# DAEMON-003: 多信号处理函数并发修改g_processExit致竞态条件

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | DAEMON-003 |
| **类型** | Race Condition in Signal Handling |
| **CWE** | CWE-364: Signal Handler Race Condition |
| **严重性** | High |
| **文件位置** | `src/server/daemon/llm_daemon.cpp` |
| **代码行** | 196-273 |
| **函数** | `SignalInterruptHandler()`, `SignalChldHandler()` |
| **置信度** | 95% |
| **状态** | CONFIRMED |

### 摘要

多个信号处理函数修改 `g_processExit` 并调用 `g_exitCv.notify_all()` 而未进行适当的同步。虽然 `g_processExit` 使用 mutex 保护，但从信号处理函数中调用 `notify_all()` 本质上是不安全的，违反了 POSIX 对异步信号安全函数的规定。当 `SignalInterruptHandler` 和 `SignalChldHandler` 同时被触发时，会产生竞态条件，可能导致条件变量内部状态损坏、死锁或未定义行为。

---

## 触发条件分析

### 1. 信号注册逻辑

```cpp
// llm_daemon.cpp:281-317
void RegisterSignal(void)
{
    signal(SIGSEGV, SignalInterruptHandler); // segmentation fault
    signal(SIGABRT, SignalInterruptHandler); // abort()
    signal(SIGINT,  SignalInterruptHandler); // Ctrl+C
    signal(SIGTERM, SignalInterruptHandler); // kill
    signal(SIGCHLD, SignalChldHandler);      // child process exit
    signal(SIGPIPE, SignalPipeHandler);
}
```

### 2. 触发场景

| 场景 | 触发条件 | 可达性 |
|------|----------|--------|
| **正常关闭** | 用户发送 SIGINT/SIGTERM | 高 - 常规操作 |
| **子进程退出** | 子进程正常/异常退出 | 高 - 常规操作 |
| **竞态窗口** | SIGCHLD 与 SIGINT/SIGTERM 同时到达 | 中 - 时序依赖 |
| **恶意触发** | 攻击者发送精心构造的信号序列 | 中 - 需要本地访问 |

### 3. 关键竞态条件

```
线程A (SignalInterruptHandler)     线程B (SignalChldHandler)
===========================     ===========================
收到 SIGINT/SIGTERM              收到 SIGCHLD (子进程退出)
    │                               │
    ▼                               ▼
lock(g_exitMtx)                  lock(g_exitMtx)  ← 竞态!
    │                               │
    ▼                               ▼
g_processExit = true             g_processExit = true
    │                               │
    ▼                               ▼
unlock(g_exitMtx)                unlock(g_exitMtx)
    │                               │
    ▼                               ▼
g_exitCv.notify_all()            g_exitCv.notify_all()  ← 危险!
    │                               │
    └─────────────────────────────────┘
                    │
                    ▼
         条件变量内部状态可能损坏
```

---

## 攻击路径图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            攻击面分析                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐                                                           │
│  │  本地用户   │                                                           │
│  │ (相同UID/   │                                                           │
│  │  root权限)  │                                                           │
│  └──────┬──────┘                                                           │
│         │ kill -SIGINT <pid>                                                │
│         │ kill -SIGCHLD <pid> (通过fork子进程退出触发)                       │
│         ▼                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    信号处理函数入口点                                │   │
│  │  ┌──────────────────┐        ┌──────────────────┐                   │   │
│  │  │SignalInterrupt   │        │SignalChld        │                   │   │
│  │  │Handler()         │        │Handler()         │                   │   │
│  │  │ - SIGINT         │        │ - SIGCHLD        │                   │   │
│  │  │ - SIGTERM        │        │                  │                   │   │
│  │  │ - SIGSEGV        │        │                  │                   │   │
│  │  │ - SIGABRT        │        │                  │                   │   │
│  │  └────────┬─────────┘        └────────┬─────────┘                   │   │
│  │           │                           │                              │   │
│  │           └───────────┬───────────────┘                              │   │
│  │                       │                                               │   │
│  │                       ▼                                               │   │
│  │           ┌───────────────────────┐                                  │   │
│  │           │ g_exitMtx.lock()      │ ← POSIX: 不安全!                  │   │
│  │           │ g_processExit = true  │                                  │   │
│  │           │ g_exitMtx.unlock()    │                                  │   │
│  │           └───────────┬───────────┘                                  │   │
│  │                       │                                               │   │
│  │                       ▼                                               │   │
│  │           ┌───────────────────────┐                                  │   │
│  │           │ g_exitCv.notify_all() │ ← POSIX: 严重不安全!             │   │
│  │           └───────────┬───────────┘                                  │   │
│  │                       │                                               │   │
│  └───────────────────────┼───────────────────────────────────────────────┘   │
│                          │                                                   │
│                          ▼                                                   │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                        潜在影响                                        │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐   │  │
│  │  │ 条件变量损坏     │  │ 死锁            │  │ 未定义行为          │   │  │
│  │  │ (内部状态不一致) │  │ (永久阻塞)      │  │ (内存损坏/crash)    │   │  │
│  │  └────────┬────────┘  └────────┬────────┘  └──────────┬──────────┘   │  │
│  │           │                    │                      │               │  │
│  │           └────────────────────┼──────────────────────┘               │  │
│  │                                │                                      │  │
│  │                                ▼                                      │  │
│  │              ┌─────────────────────────────────┐                      │  │
│  │              │         服务拒绝 (DoS)           │                      │  │
│  │              │  - 守护进程无法正常终止           │                      │  │
│  │              │  - 僵尸进程堆积                   │                      │  │
│  │              │  - 资源泄露                       │                      │  │
│  │              └─────────────────────────────────┘                      │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 源代码深度分析

### 漏洞代码片段 1: SignalInterruptHandler

```cpp
// llm_daemon.cpp:196-221
void SignalInterruptHandler(int sig)
{
    if (g_isKillingAll) {           // 检查发生在不安全操作之后
        return;
    }

    // 以下都是非异步信号安全操作:
    ULOG_WARN(...);                 // ❌ 涉及 I/O 和内存分配
    waitpid(0, &status, WNOHANG);   // ❌ waitpid 在信号处理函数中有条件安全

    {
        std::unique_lock<std::mutex> lock(g_exitMtx);  // ❌ mutex 锁操作不安全
        g_processExit = true;
    }
    HealthManager::UpdateHealth(false);  // ❌ 可能涉及原子操作和更多锁
    g_exitCv.notify_all();          // ❌❌ 条件变量操作严重不安全!
    
    ULOG_WARN(...);                 // ❌ 非信号安全
    std::this_thread::sleep_for(...); // ❌ 非信号安全
    KillProcessGroup();             // ❌ 涉及大量不安全操作
}
```

### 漏洞代码片段 2: SignalChldHandler

```cpp
// llm_daemon.cpp:223-273
void SignalChldHandler(int sig)
{
    ULOG_WARN(...);                 // ❌ 非信号安全
    waitpid(0, &status, WNOHANG);   // ✓ 有条件安全 (使用 WNOHANG)

    // ... 处理子进程退出状态 ...

    if (exitFlag) {
        {
            std::unique_lock<std::mutex> lock(g_exitMtx);  // ❌ 不安全
            g_processExit = true;
        }
        HealthManager::UpdateHealth(false);  // ❌ 不安全
        g_exitCv.notify_all();      // ❌❌ 严重不安全!

        ULOG_WARN(...);
        KillProcessGroup();
    }
}
```

### 问题根源: 条件变量的非信号安全性质

根据 POSIX 标准，`pthread_cond_signal` 和 `pthread_cond_broadcast`（C++ `notify_all()` 的底层实现）**不是异步信号安全函数**。这是因为：

1. **内部锁竞争**: 条件变量内部使用锁来保护其数据结构
2. **内存分配**: 某些实现可能在等待队列管理中分配内存
3. **与主线程冲突**: 如果主线程正在等待条件变量，信号处理函数中的操作会与其产生竞态

---

## PoC 构思

### 概念验证思路 (不提供完整 PoC)

```
攻击思路:
1. 获取目标 MindIE daemon 进程 PID
2. 启动监控线程检测进程状态
3. 快速连续发送信号:
   - SIGTERM/SIGINT (触发 SignalInterruptHandler)
   - 同时 fork 子进程立即退出 (触发 SIGCHLD → SignalChldHandler)
4. 观察结果:
   - 进程是否正常退出?
   - 是否产生僵尸进程?
   - 是否出现死锁 (strace 观察线程状态)?
```

### 预期触发条件

```python
# 伪代码 - 概念演示
import os
import signal
import subprocess
import time

def trigger_race(target_pid):
    """
    触发信号处理竞态条件
    """
    # 阶段1: 触发 SIGCHLD (通过子进程退出)
    fork_and_exit_child(target_pid)
    
    # 阶段2: 在极短时间内发送 SIGTERM
    # 与 SIGCHLD 形成竞态窗口
    os.kill(target_pid, signal.SIGTERM)
    
    # 观察目标进程状态
    # 预期: 可能出现死锁或异常终止
```

---

## 影响评估

### 1. 服务可用性影响 (High)

| 影响 | 描述 | 严重性 |
|------|------|--------|
| **守护进程死锁** | 条件变量损坏导致主线程无法被唤醒 | High |
| **僵尸进程堆积** | 子进程未被正确收割 | Medium |
| **服务无法终止** | 正常关闭流程被阻塞 | High |
| **资源泄露** | 文件描述符、内存等资源未释放 | Medium |

### 2. 数据完整性影响 (Medium)

- 非正常终止可能导致正在处理的请求丢失
- 日志可能不完整，影响审计追踪
- 共享内存状态可能不一致

### 3. 攻击面评估

| 因素 | 评估 |
|------|------|
| **本地攻击** | 需要相同用户权限或 root |
| **远程攻击** | 不直接可利用 |
| **触发难度** | 中等 - 需要精确的时序控制 |
| **利用稳定性** | 低 - 竞态条件结果不确定 |

### 4. CVSS 评分估算

```
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H
Base Score: 5.5 (Medium)
Temporal Score: 6.5 (Medium-High, 考虑实际可利用性)
```

---

## 现有缓解措施分析

### 1. g_isKillingAll 原子标志

```cpp
// llm_daemon.cpp:45
std::atomic<bool> g_isKillingAll(false);

// llm_daemon.cpp:157-160
void KillProcessGroup()
{
    bool expected = false;
    if (!g_isKillingAll.compare_exchange_strong(expected, true)) {
        return;  // 防止重复调用
    }
    // ...
}

// llm_daemon.cpp:198-200
void SignalInterruptHandler(int sig)
{
    if (g_isKillingAll) {
        return;
    }
    // ... 问题: 检查太晚!
}
```

**缓解效果**: 部分有效
- ✓ 防止 `KillProcessGroup()` 被多次调用
- ✗ **不防止** `notify_all()` 的竞态条件
- ✗ 检查发生在 `notify_all()` 调用之后

### 2. mutex 保护 g_processExit

```cpp
// llm_daemon.cpp:211-214
{
    std::unique_lock<std::mutex> lock(g_exitMtx);
    g_processExit = true;
}
```

**缓解效果**: 无效
- ✗ 在信号处理函数中获取 mutex 本身就不安全
- ✗ 不解决条件变量的竞态问题

### 3. 缺失的缓解措施

| 应有缓解 | 状态 | 说明 |
|----------|------|------|
| Self-Pipe 技术 | ❌ 未实现 | 推荐方案 |
| signalfd | ❌ 未实现 | Linux 特有方案 |
| 信号屏蔽 + 专用线程 | ❌ 未实现 | 替代方案 |
| 仅使用信号安全函数 | ❌ 未实现 | 基本要求 |

---

## 修复建议

### 方案 1: Self-Pipe Technique (推荐)

```cpp
// 推荐的修复方案
#include <unistd.h>
#include <fcntl.h>

static int g_signalPipe[2] = {-1, -1};
static std::atomic<bool> g_signalReceived{false};

void SafeSignalHandler(int sig)
{
    // 仅执行异步信号安全操作
    g_signalReceived.store(true, std::memory_order_relaxed);
    
    // 写入 pipe (async-signal-safe)
    char c = static_cast<char>(sig);
    ssize_t ret = write(g_signalPipe[1], &c, 1);
    (void)ret; // 忽略返回值
}

void SignalHandlingThread()
{
    char buf[1];
    while (true) {
        ssize_t n = read(g_signalPipe[0], buf, 1);
        if (n > 0) {
            // 在安全上下文中处理信号
            {
                std::unique_lock<std::mutex> lock(g_exitMtx);
                g_processExit = true;
            }
            g_exitCv.notify_all();
            
            if (g_signalReceived.load()) {
                KillProcessGroup();
            }
        }
    }
}

void InitSignalHandling()
{
    // 创建 non-blocking pipe
    pipe(g_signalPipe);
    fcntl(g_signalPipe[0], F_SETFL, O_NONBLOCK);
    fcntl(g_signalPipe[1], F_SETFL, O_NONBLOCK);
    
    // 注册信号处理函数
    signal(SIGINT, SafeSignalHandler);
    signal(SIGTERM, SafeSignalHandler);
    signal(SIGCHLD, SafeSignalHandler);
    
    // 启动信号处理线程
    std::thread(SignalHandlingThread).detach();
}
```

### 方案 2: signalfd (Linux 特有)

```cpp
#include <sys/signalfd.h>
#include <signal.h>
#include <poll.h>

void SignalHandlingWithSignalfd()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGCHLD);
    
    // 阻塞信号
    pthread_sigmask(SIG_BLOCK, &mask, nullptr);
    
    // 创建 signalfd
    int sfd = signalfd(-1, &mask, SFD_NONBLOCK);
    
    // 在专用线程中轮询
    struct pollfd pfd = {.fd = sfd, .events = POLLIN};
    while (poll(&pfd, 1, -1) > 0) {
        struct signalfd_siginfo fdsi;
        ssize_t s = read(sfd, &fdsi, sizeof(fdsi));
        if (s == sizeof(fdsi)) {
            // 安全地处理信号
            HandleSignalSafely(fdsi.ssi_signo);
        }
    }
}
```

### 方案 3: 最小化信号处理函数

```cpp
// 仅使用异步信号安全函数
static volatile sig_atomic_t g_signalFlag = 0;

void MinimalSignalHandler(int sig)
{
    // 仅设置标志 (async-signal-safe)
    g_signalFlag = 1;
}

// 在主循环中定期检查
void MainLoop()
{
    while (!g_processExit) {
        if (g_signalFlag) {
            // 在安全上下文中处理
            HandleShutdown();
            g_signalFlag = 0;
        }
        // ... 主循环逻辑 ...
    }
}
```

---

## 对比: 项目中的正确实现

项目中已存在正确的信号处理示例 (`tests/dlt/crash_handler.cpp`):

```cpp
// tests/dlt/crash_handler.cpp:153-162
struct sigaction sa;
memset(&sa, 0, sizeof(sa));
sa.sa_handler = SignalHandler;  // 处理函数
sigemptyset(&sa.sa_mask);
sa.sa_flags = 0;

sigaction(SIGSEGV, &sa, nullptr);
sigaction(SIGABRT, &sa, nullptr);
// ...

// SignalHandler 函数中使用 _exit() 而非 notify_all()
void SignalHandler(int sig)
{
    // ... 打印堆栈跟踪 ...
    _exit(1);  // 直接退出，不尝试通知其他线程
}
```

**差异分析**:
- crash_handler 正确使用了 `_exit()` 直接终止
- daemon 的信号处理函数尝试优雅关闭，但使用了不安全的方法
- 应该结合两者: 使用安全机制传递信号，然后在安全上下文中优雅关闭

---

## 参考资料

1. **POSIX.1-2017 - Signal Safety**
   - https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_04
   
2. **Linux man pages - signal-safety(7)**
   - 列出所有异步信号安全函数
   
3. **CERT Coding Standard - SIG00-C**
   - https://wiki.sei.cmu.edu/confluence/display/c/SIG00-C.+Mask+signals+handled+by+noninterruptible+signal+handlers

4. **CWE-364: Signal Handler Race Condition**
   - https://cwe.mitre.org/data/definitions/364.html

---

## 总结

DAEMON-003 是一个**真实存在的漏洞**，严重性为 **High**。该漏洞违反了 POSIX 对信号处理函数的规定，使用了非异步信号安全的函数（特别是 `std::condition_variable::notify_all()` 和 mutex 操作），可能导致：

1. **死锁**: 条件变量内部状态损坏，主线程永久阻塞
2. **服务拒绝**: 守护进程无法正常终止
3. **资源泄露**: 子进程未被正确收割

修复方案应采用 **Self-Pipe Technique** 或 **signalfd**，将所有非信号安全操作移至专用线程中执行。
