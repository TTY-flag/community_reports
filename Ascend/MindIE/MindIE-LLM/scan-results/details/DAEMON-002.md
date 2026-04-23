# DAEMON-002: SIGCHLD信号处理函数使用非异步安全函数致死锁内存损坏

## 漏洞概述

**漏洞ID**: DAEMON-002  
**类型**: Signal Handler Safety Issue (CWE-479)  
**严重性**: High  
**状态**: CONFIRMED  
**置信度**: 100%  

**位置**: `src/server/daemon/llm_daemon.cpp:223-273`  
**函数**: `SignalChldHandler`  
**信号**: SIGCHLD  

**描述**: SIGCHLD 信号处理函数 `SignalChldHandler` 使用多个非 POSIX 异步信号安全函数，包括 ULOG_* 日志宏（涉及互斥锁/内存分配）、std::unique_lock、condition_variable::notify_all()、以及 **strsignal()**。这些操作在异步信号上下文中可能导致死锁或内存损坏。

---

## 源代码分析

### 漏洞代码片段

```cpp
// llm_daemon.cpp:223-273
void SignalChldHandler(int sig)
{
    // 问题1: ULOG_WARN 使用 std::ostringstream 和 spdlog (非信号安全)
    ULOG_WARN(SUBMODLE_NAME_DAEMON, GenerateDaemonErrCode(WARNING, ...),
        "Received exit signal[" << sig << "], Process " << getpid() 
        << ", Thread " << std::this_thread::get_id());
    
    int status = 0;
    pid_t pid = 0;
    bool exitFlag = false;
    
    while ((pid = waitpid(0, &status, WNOHANG)) > 0) {
        // 问题1: ULOG_WARN 在循环中多次调用
        ULOG_WARN(SUBMODLE_NAME_DAEMON, ...,
                  "Process " << pid << " exited");
        
        unsigned int ustatus = static_cast<unsigned int>(status);
        if (WIFEXITED(ustatus)) {
            exitFlag = false;
            int exitCode = WEXITSTATUS(ustatus);
            // 问题1: ULOG_INFO
            ULOG_INFO(SUBMODLE_NAME_DAEMON, 
                "Process " << pid << " exited normally with status " << exitCode);
            if (exitCode != 0) {
                exitFlag = true;
            }
        } else if (WIFSIGNALED(ustatus)) {
            exitFlag = true;
            int signalNum = WTERMSIG(ustatus);
            // 问题1+2: ULOG_ERROR + strsignal() [特有于 DAEMON-002]
            ULOG_ERROR(SUBMODLE_NAME_DAEMON, ...,
                "Process " << pid << " was terminated by signal " << signalNum 
                << " (" << strsignal(signalNum) << ")");
        } else if (WIFSTOPPED(ustatus)) {
            exitFlag = true;
            int stopSignal = WSTOPSIG(ustatus);
            // 问题1+2: ULOG_ERROR + strsignal() [特有于 DAEMON-002]
            ULOG_ERROR(SUBMODLE_NAME_DAEMON, ...,
                "Process " << pid << " was stopped by signal " << stopSignal 
                << " (" << strsignal(stopSignal) << ")");
        } else {
            exitFlag = true;
            // 问题1: ULOG_ERROR
            ULOG_ERROR(SUBMODLE_NAME_DAEMON, ...,
                "Process " << pid << " terminated with unknown status " << status);
        }
    }
    
    if (exitFlag) {
        {
            // 问题3: std::unique_lock 获取互斥锁 (非信号安全)
            std::unique_lock<std::mutex> lock(g_exitMtx);
            g_processExit = true;
        }
        // 问题4: HealthManager::UpdateHealth - atomic store (信号安全)
        HealthManager::UpdateHealth(false);
        // 问题5: condition_variable::notify_all() (非信号安全)
        g_exitCv.notify_all();
        
        // 问题1: ULOG_WARN
        ULOG_WARN(SUBMODLE_NAME_DAEMON, ...,
            "Successfully handled SIGCHLD, now killing process group");
        // 问题6: KillProcessGroup() 包含多个非信号安全操作
        KillProcessGroup();
    }
}
```

### 非信号安全函数详细分析

| 问题编号 | 函数/操作 | 非安全原因 | 风险等级 | 备注 |
|---------|----------|-----------|---------|------|
| 1 | ULOG_WARN/INFO/ERROR | std::ostringstream (堆分配), spdlog (互斥锁), Log::LogMessage() | High | 多次调用 |
| **2** | **strsignal()** | **未列入 POSIX 异步信号安全函数列表** | Medium | **DAEMON-002 特有** |
| 3 | std::unique_lock<std::mutex> | 互斥锁操作在信号上下文极易死锁 | Critical | |
| 4 | HealthManager::UpdateHealth | std::atomic::store - 实际信号安全 | Safe | 安全操作 |
| 5 | g_exitCv.notify_all() | 条件变量内部使用互斥锁 | Critical | |
| 6 | KillProcessGroup() | std::cerr, ULOG_AUDIT, Log::Flush, 文件操作, 内存分配 | Critical | |

### 与 DAEMON-001 的关键区别

**DAEMON-002 特有问题**: `strsignal()` 函数调用

```cpp
// Lines 247, 253 - DAEMON-002 特有的非安全调用
ULOG_ERROR(SUBMODLE_NAME_DAEMON, ...,
    "Process " << pid << " was terminated by signal " << signalNum 
    << " (" << strsignal(signalNum) << ")");  // strsignal() NOT in POSIX safe list
```

**strsignal() 风险分析**:
- 未列入 POSIX.1-2008 Section 2.4 异步信号安全函数列表
- 可能使用静态缓冲区或进行内存分配
- 某些实现可能调用 gettext() 进行国际化翻译
- 在信号上下文中调用可能导致未定义行为

---

## 触发条件分析

### 信号触发机制

**SIGCHLD 信号触发条件**:
1. 子进程正常退出 (exit() 或 _exit())
2. 子进程被信号终止 (SIGKILL, SIGTERM 等)
3. 子进程被信号停止 (SIGSTOP, SIGTSTP)
4. 子进程继续运行 (SIGCONT, 需设置 SA_NOCLDSTOP)

**当前代码中的子进程来源**:
- RunEP 线程启动 EndPoint 服务
- 任何子进程异常终止都会触发 SIGCHLD
- 使用 `signal(SIGCHLD, SignalChldHandler)` 注册

### 触发可达性评估

| 条件 | 可能性 | 触发场景 |
|------|--------|---------|
| 子进程崩溃 | **高** | 推理服务异常、内存不足、模型加载失败 |
| 子进程主动退出 | 中 | 配置错误、服务启动失败 |
| 外部攻击导致子进程死亡 | 低-中 | 通过其他漏洞 (如 SEC-INFER-004) 导致推理进程崩溃 |

**触发复杂度**: 低 - 任何子进程终止都会触发 SIGCHLD，无需特殊攻击技巧

---

## 攻击路径图

```
┌─────────────────────────────────────────────────────────────────────┐
│                           攻击路径分析                                │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  外部攻击者   │ ──→ │ HTTP/gRPC API │ ──→ │ 推理服务进程  │
└──────────────┘     └──────────────┘     └──────────────┘
      │                     │                     │
      │  恶意推理请求        │                     │
      │  (触发其他漏洞)      │                     │
      │                     │                     │
      │                     └─────────────────────│
      │                                           │
      │                     ┌─────────────────────┘
      │                     │
      │                     ↓
      │              ┌──────────────────┐
      │              │ 子进程崩溃       │
      │              │ (SIGSEGV/SIGABRT)│
      │              └──────────────────┘
      │                     │
      │                     ↓ 内核发送 SIGCHLD
      │                     │
      │              ┌──────────────────┐
      │              │ SignalChldHandler │ ← 异步信号上下文
      │              └──────────────────┘
      │                     │
      │                     ↓
      │              ┌──────────────────┐
      │              │ ULOG_* + strsignal│ ← 堆分配 + 互斥锁 + 非安全函数
      │              └──────────────────┘
      │                     │
      │     ┌───────────────┼───────────────┐
      │     │               │               │
      │     ↓               ↓               ↓
      │ ┌─────────┐   ┌─────────┐   ┌─────────┐
      │ │ 死锁    │   │ 内存损坏 │   │ 崩溃    │
      │ │g_exitMtx│   │ostringstream│ │ SIGSEGV │
      │ └─────────┘   └─────────┘   └─────────┘
      │     │               │               │
      │     └───────────────┼───────────────┘
      │                     │
      │                     ↓
      │              ┌──────────────────┐
      │              │ 服务无法终止      │ ← 僵尸进程堆积
      │              │ 资源未清理        │
      │              │ 拒绝服务          │
      │              └──────────────────┘


      │
      │  直接触发路径（配置错误）
      │
┌─────┴──────┐     ┌──────────────┐     ┌──────────────┐
│ 配置错误    │ ──→ │ EndPoint启动失败 │ ──→ │ ep.Start()!=0 │
└──────────────┘     └──────────────┘     └──────────────┘
                                                │
                                                ↓ killpg(SIGKILL)
                                         ┌──────────────┐
                                         │ 子进程终止    │
                                         └──────────────┘
                                                │
                                                ↓ SIGCHLD
                                         ┌──────────────────┐
                                         │ SignalChldHandler │
                                         └──────────────────┘
```

---

## PoC 构思

### 直接触发场景

**场景1: 配置文件错误导致子进程启动失败**

1. 创建错误的配置文件 (如无效的模型路径)
2. 启动 MindIE-LLM 服务
3. EndPoint 启动失败，`ep.Start()` 返回非零值
4. 调用 `killpg(getpgrp(), SIGKILL)` 终止进程组
5. SIGCHLD 被 SignalChldHandler 接收
6. 在信号上下文中调用 strsignal() 和非安全函数

**场景2: 推理请求导致子进程崩溃**

1. 利用其他漏洞 (如 SEC-INFER-004 数组越界) 触发推理进程崩溃
2. 子进程收到 SIGSEGV/SIGABRT
3. 内核向父进程发送 SIGCHLD
4. SignalChldHandler 在异常上下文执行

### 死锁触发条件

```cpp
// 死锁场景构造
// 主线程持有 g_exitMtx 并等待条件变量
void RunEP(...) {
    while (!g_processExit) {
        std::unique_lock<std::mutex> lock(g_exitMtx);  // 主线程持有锁
        g_exitCv.wait(lock, []() { return g_processExit; });
    }
}

// 此时子进程退出 -> SIGCHLD -> SignalChldHandler
// SignalChldHandler 尝试获取同一锁:
// std::unique_lock<std::mutex> lock(g_exitMtx);  // 死锁!
```

---

## 影响评估

### 直接影响

| 影响类型 | 严重性 | 具体表现 |
|---------|--------|---------|
| **服务拒绝 (DoS)** | High | 进程无法正常终止，僵尸进程堆积，服务挂起 |
| **资源泄露** | High | 子进程未被正确收割，共享内存/文件描述符未释放 |
| **内存损坏** | Medium | 在堆分配期间被信号中断，可能导致内存结构损坏 |
| **日志系统损坏** | Medium | spdlog 内部状态可能不一致，后续日志丢失 |

### 连锁影响

```
SignalChldHandler 死锁/崩溃
        │
        ├──→ 主线程无法退出
        │         │
        │         ├──→ HTTP/gRPC 服务无法停止
        │         │         │
        │         │         ├──→ 客户端请求超时
        │         │         └──→ 新请求被拒绝
        │         │
        │         └──→ 僵尸进程堆积
        │                   │
        │                   ├──→ 进程表耗尽
        │                   └──→ 系统资源耗尽
        │
        ├──→ KillProcessGroup 未执行
        │         │
        │         ├──→ 子进程未被终止
        │         └──→ NPU 设备资源未释放
        │
        └──→ HealthManager 未更新
                  │
                  └──→ 健康检查错误报告服务状态
```

### CVSS 评级估算

- **CVSS 3.1 基础分数**: 6.5 (Medium)
  - AV:L (Local) - 需要触发子进程终止
  - AC:L (Low) - 无特殊条件
  - PR:L (Low) - 可能需要本地用户权限
  - UI:N (None) - 无用户交互
  - S:U (Unchanged) - 影响范围不变
  - C:N (None) - 无信息泄露
  - I:N (None) - 无完整性影响
  - A:H (High) - 高可用性影响

---

## 缓解措施分析

### 已存在的缓解

| 缓解措施 | 有效性 | 说明 |
|---------|--------|------|
| `g_isKillingAll` atomic flag | 部分 | 防止重复进入 KillProcessGroup，但不阻止日志调用 |
| `waitpid(..., WNOHANG)` | 有效 | 非阻塞等待，信号安全 |
| `exitFlag` 控制流程 | 部分 | 减少不必要的 KillProcessGroup 调用 |
| `HealthManager::UpdateHealth(false)` | 有效 | atomic 操作，信号安全 |

### 缺失的关键缓解

1. **无 self-pipe 或 signalfd 机制**: 未将信号处理移至专用线程
2. **无互斥锁保护**: 直接在信号上下文获取互斥锁
3. **无内存分配保护**: 日志系统使用堆分配
4. **无异步安全日志替代**: 未使用 async-signal-safe 日志机制
5. **strsignal() 无替代**: 使用非信号安全的信号描述函数

---

## 修复建议

### 推荐方案: Self-Pipe Technique

```cpp
// 修复方案框架

// 1. 全局管道和标志
static int g_signalPipe[2];
static volatile sig_atomic_t g_signalReceived = 0;

// 2. 信号安全处理函数 (仅 POSIX 安全函数)
void SignalChldHandler(int sig)
{
    // 仅使用 POSIX 信号安全函数
    char sigNum = static_cast<char>(sig);
    ssize_t ret = write(g_signalPipe[1], &sigNum, 1);
    // write() 是信号安全函数
    (void)ret;  // 忽略返回值
}

// 3. 专用信号处理线程
void SignalHandlerThread()
{
    char sigNum;
    while (true) {
        if (read(g_signalPipe[0], &sigNum, 1) > 0) {
            if (sigNum == SIGCHLD) {
                HandleSigchldSafe();  // 非信号上下文，可以使用任何函数
            }
        }
    }
}

// 4. 安全的 SIGCHLD 处理 (在专用线程中)
void HandleSigchldSafe()
{
    // 这里可以使用任何函数，包括 strsignal()
    ULOG_WARN(SUBMODLE_NAME_DAEMON, ...);
    
    int status;
    pid_t pid;
    bool exitFlag = false;
    
    while ((pid = waitpid(0, &status, WNOHANG)) > 0) {
        int signalNum = 0;
        
        if (WIFEXITED(status)) {
            ULOG_INFO(SUBMODLE_NAME_DAEMON, 
                "Process " << pid << " exited normally");
            if (WEXITSTATUS(status) != 0) {
                exitFlag = true;
            }
        } else if (WIFSIGNALED(status)) {
            exitFlag = true;
            signalNum = WTERMSIG(status);
            // strsignal() 在这里是安全的，因为不在信号上下文
            ULOG_ERROR(SUBMODLE_NAME_DAEMON, 
                "Process " << pid << " terminated by signal " 
                << signalNum << " (" << strsignal(signalNum) << ")");
        }
    }
    
    if (exitFlag) {
        std::unique_lock<std::mutex> lock(g_exitMtx);
        g_processExit = true;
        g_exitCv.notify_all();  // 在非信号上下文安全使用
        KillProcessGroup();
    }
}
```

### 替代方案: signalfd (Linux)

```cpp
#include <sys/signalfd.h>

// 1. 阻塞信号并创建 signalfd
sigset_t sigmask;
sigemptyset(&sigmask);
sigaddset(&sigmask, SIGCHLD);
sigprocmask(SIG_BLOCK, &sigmask, NULL);
int sigfd = signalfd(-1, &sigmask, SFD_NONBLOCK);

// 2. 专用线程轮询
void SignalHandlerThread()
{
    struct pollfd pfd = {sigfd, POLLIN, 0};
    while (poll(&pfd, 1, -1) > 0) {
        struct signalfd_siginfo siginfo;
        read(sigfd, &siginfo, sizeof(siginfo));
        
        if (siginfo.ssi_signo == SIGCHLD) {
            HandleSigchldSafe();  // 在线程上下文安全处理
        }
    }
}
```

### 最小修复方案 (不推荐，但快速)

如果无法重构信号处理架构，最小修复是移除所有非安全函数调用:

```cpp
void SignalChldHandler(int sig)
{
    // 仅设置原子标志，不做任何其他操作
    g_processExit = true;
    // 注意: notify_all() 仍然不安全
    // 完全安全的方案必须使用 self-pipe
}
```

---

## 验证结论

**判定**: ✅ 真实漏洞，需立即修复

**理由**:
1. 直接违反 POSIX.1-2008 Section 2.4 信号安全规范
2. 多个非信号安全函数调用，置信度 100%
3. **strsignal() 特有问题** - DAEMON-002 独有
4. 死锁和内存损坏风险高，影响服务可用性
5. 已有代码存在部分缓解但不足以消除风险
6. 修复方案成熟 (self-pipe/signalfd 是业界标准)

---

## 相关漏洞

| ID | 描述 | 关系 |
|----|------|------|
| DAEMON-001 | SignalInterruptHandler 信号安全问题 | 同类问题，处理 SIGINT/SIGTERM/SIGSEGV/SIGABRT |
| DAEMON-003 | 信号处理竞态条件 | DAEMON-001/002 共同导致的问题 |

**修复建议**: DAEMON-001、DAEMON-002、DAEMON-003 应一起修复，使用统一的 self-pipe 或 signalfd 架构。

---

## 参考文献

1. POSIX.1-2008, Section 2.4: Signal Concepts - Async-Signal-Safe Functions
2. CWE-479: Signal Handler Use of a Non-reentrant Function
3. "Secure Programming for Linux and Unix HOWTO" - Section 5.8: Signal Handling
4. Linux man page: signal-safety(7)
5. APUE (Advanced Programming in the UNIX Environment) - Chapter 10: Signals
6. strsignal(3) - Linux man page (not in async-signal-safe list)

---

**报告生成时间**: 2026-04-17  
**分析者**: details-analyzer (coordinator)  
**状态**: CONFIRMED - 需立即修复