# DAEMON-001: Signal Handler Safety Issue

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | DAEMON-001 |
| **类型** | Signal Handler Safety Issue (信号处理器安全性问题) |
| **CWE** | CWE-479: Signal Handler Use of a Non-reentrant Function |
| **严重性** | High (高) |
| **状态** | CONFIRMED (已确认) |
| **文件** | `src/server/daemon/llm_daemon.cpp` |
| **位置** | Lines 196-221, Function: `SignalInterruptHandler` |

### 漏洞描述

`SignalInterruptHandler` 信号处理函数处理关键信号（SIGSEGV、SIGABRT、SIGINT、SIGTERM），但在信号上下文中调用了多个非异步信号安全函数，包括：
- `ULOG_WARN/ULOG_INFO` 宏（使用堆分配、互斥锁）
- `std::unique_lock<std::mutex>`（互斥锁操作）
- `std::condition_variable::notify_all()`（条件变量）
- `std::this_thread::sleep_for()`（线程睡眠）

这些函数在信号处理器中调用可能导致死锁、内存损坏或未定义行为。

## 触发条件分析

### 信号注册情况

```cpp
// llm_daemon.cpp:281-317
void RegisterSignal(void)
{
    signal(SIGSEGV, SignalInterruptHandler); // segmentation fault
    signal(SIGABRT, SignalInterruptHandler); // abort()
    signal(SIGINT,  SignalInterruptHandler); // Ctrl+C
    signal(SIGTERM, SignalInterruptHandler); // termination
    signal(SIGCHLD, SignalChldHandler);
    signal(SIGPIPE, SignalPipeHandler);
}
```

### 触发条件

| 信号 | 触发方式 | 可达性 | 外部可控性 |
|------|----------|--------|------------|
| **SIGINT** | Ctrl+C, `kill -INT <pid>` | **高** - 用户可直接触发 | **高** - 任何有进程访问权限的用户 |
| **SIGTERM** | `kill <pid>`, 系统关闭 | **高** - 用户可直接触发 | **高** - 任何有进程访问权限的用户 |
| **SIGSEGV** | 内存访问错误, 空指针解引用 | **中** - 取决于程序状态 | **中** - 可通过输入触发内存错误 |
| **SIGABRT** | `abort()`调用, 断言失败 | **中** - 取决于程序状态 | **中** - 可通过输入触发断言 |

### 特殊条件

1. **死锁触发条件**: 
   - 信号到达时，另一线程正在持有 `g_exitMtx` 互斥锁
   - 信号到达时，另一线程正在执行 `ULOG_*` 相关的内存分配或spdlog互斥锁操作

2. **内存损坏触发条件**:
   - 信号中断堆分配操作时，`std::ostringstream` 创建新对象
   - 信号中断spdlog日志写入时

## 攻击路径图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Attack Surface Analysis                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  External Actor                                                         │
│       │                                                                 │
│       ├───────────► [Ctrl+C] ──────────────┐                           │
│       │                                      │                          │
│       ├───────────► [kill -INT <pid>] ──────┤                          │
│       │                                      │                          │
│       ├───────────► [kill -TERM <pid>] ─────┼──► SIGINT/SIGTERM        │
│       │                                      │      Signal              │
│       │                                      │         │                │
│       │                                      │         ▼                │
│       │                                      │  ┌──────────────────┐   │
│       │                                      │  │SignalInterrupt   │   │
│       │                                      │  │Handler           │   │
│       │                                      │  │(llm_daemon.cpp:  │   │
│       │                                      │  │ 196-221)         │   │
│       │                                      │  └──────────────────┘   │
│       │                                      │         │                │
│       │                                      │         ▼                │
│       │                                      │  ┌──────────────────┐   │
│       │                                      │  │ UNSAFE CALLS:    │   │
│       │                                      │  │ • ULOG_* (heap,  │   │
│       │                                      │  │   mutex)         │   │
│       │                                      │  │ • unique_lock    │   │
│       │                                      │  │   (mutex)        │   │
│       │                                      │  │ • notify_all     │   │
│       │                                      │  │   (mutex)        │   │
│       │                                      │  │ • sleep_for      │   │
│       │                                      │  └──────────────────┘   │
│       │                                      │         │                │
│       │                                      │         ▼                │
│       │                                      │  ┌──────────────────┐   │
│       │                                      │  │ IMPACT:          │   │
│       │                                      │  │ • Deadlock       │   │
│       │                                      │  │ • Memory Corrupt │   │
│       │                                      │  │ • Process Hang   │   │
│       │                                      │  └──────────────────┘   │
│       │                                      │                          │
│       │                                                                 │
│       ├───────────► [Malicious Input] ──────┤                          │
│       │                 │                    │                          │
│       │                 ▼                    │                          │
│       │          ┌──────────────┐           │                          │
│       │          │ Trigger Bug │           │                          │
│       │          │ (Null Ptr,  │           │                          │
│       │          │  Buffer Ovf)│           │                          │
│       │          └──────────────┘           │                          │
│       │                 │                    │                          │
│       │                 ▼                    │                          │
│       │          SIGSEGV/SIGABRT ────────────┤                          │
│       │                                      │                          │
└─────────────────────────────────────────────┴──────────────────────────┘
```

### 详细攻击路径

```
Phase 1: Signal Delivery
─────────────────────────
[Attacker with shell access] ──► [kill -INT <mindie_pid>]
                                      │
                                      ▼
                              [Kernel delivers SIGINT]
                                      │
                                      ▼
                              [Process interrupted at arbitrary point]
                                      │
                                      │ (Critical: may interrupt during)
                                      │  • g_exitMtx locked by main thread
                                      │  • Heap allocation in progress
                                      │  • spdlog mutex held
                                      ▼
Phase 2: Signal Handler Execution
─────────────────────────────────
SignalInterruptHandler(sig)
    │
    ├─► g_isKillingAll check (atomic - SAFE)
    │
    ├─► ULOG_WARN() ──────────────► [std::ostringstream allocation]
    │                              [spdlog mutex acquisition]
    │                              ❌ NOT SIGNAL-SAFE
    │
    ├─► waitpid() (WNOHANG) ─────► SAFE (async-signal-safe)
    │
    ├─► ULOG_INFO() ─────────────► ❌ NOT SIGNAL-SAFE (same issues)
    │
    ├─► std::unique_lock(g_exitMtx) ─► ❌ DEADLOCK RISK
    │                                   If main thread holds mutex
    │
    ├─► g_processExit = true ────► SAFE (atomic bool assignment)
    │
    ├─► HealthManager::UpdateHealth ─► SAFE (atomic store)
    │
    ├─► g_exitCv.notify_all() ───► ❌ NOT SIGNAL-SAFE (internal mutex)
    │
    ├─► ULOG_WARN() ─────────────► ❌ NOT SIGNAL-SAFE
    │
    ├─► std::this_thread::sleep_for ─► ❌ NOT SIGNAL-SAFE
    │
    ├─► KillProcessGroup() ─────► ❌ Contains:
    │                               • ULOG_AUDIT (unsafe)
    │                               • std::cerr (unsafe)
    │                               • Log::Flush() (mutex)
    ▼

Phase 3: Impact
───────────────
┌─────────────────────────────────────────────────┐
│                 Potential Outcomes               │
├─────────────────────────────────────────────────┤
│                                                 │
│  Case A: Deadlock                               │
│  ─────────────────                              │
│  Signal arrives during mutex operation          │
│  → Handler tries to acquire same mutex          │
│  → Process hangs indefinitely                   │
│  → Service unavailable (DoS)                    │
│                                                 │
│  Case B: Memory Corruption                      │
│  ───────────────────────                        │
│  Signal interrupts heap allocation              │
│  → ostringstream creates corrupted object       │
│  → Potential heap metadata corruption           │
│  → Further undefined behavior                   │
│                                                 │
│  Case C: Inconsistent State                     │
│  ────────────────────────                       │
│  Signal interrupts logging                      │
│  → spdlog internal state corrupted              │
│  → Log files may be incomplete/corrupted        │
│  → Audit trail compromised                      │
│                                                 │
└─────────────────────────────────────────────────┘
```

## PoC 构思 (Proof of Concept Concept)

### 测试场景 1: 死锁触发

```cpp
// Concept: Create race condition between main thread mutex and signal
// 
// 1. 在主线程中持续获取/释放 g_exitMtx
// 2. 同时从另一进程发送 SIGINT
// 3. 观察进程是否hang住

// 测试代码框架（概念性）:
// Thread 1: 
//   while(true) {
//     std::unique_lock<std::mutex> lock(g_exitMtx);
//     // do work
//     lock.unlock();
//   }
// 
// External: kill -INT <pid> (repeatedly)
// 
// Expected: Process deadlock when signal arrives during lock held
```

### 测试场景 2: 堆损坏触发

```cpp
// Concept: Trigger SIGSEGV during heap allocation
// 
// 1. 创建大量并发日志操作（使用 ULOG_*）
// 2. 同时触发 SIGSEGV（通过空指针解引用或恶意输入）
// 3. 观察进程行为

// 预期结果：
// - 进程在信号处理器中崩溃
// - 或产生不可预测的行为
```

### 测试场景 3: 简单DoS测试

```bash
# Simple DoS test that any user with process access can perform
# 
# 1. Start MindIE server
# 2. While server is handling requests:
#    kill -INT <pid>
# 3. Observe:
#    - Does process respond?
#    - Is shutdown graceful?
#    - Are there any hangs?
#
# Expected problematic behavior:
# - Process may hang during shutdown
# - Logs may be incomplete
# - Subprocess cleanup may fail
```

## 影响评估

### 实际影响

| 影响类型 | 严重性 | 具体危害 |
|----------|--------|----------|
| **拒绝服务 (DoS)** | High | 进程死锁导致服务完全不可用 |
| **数据完整性** | Medium | 堆损坏可能导致数据处理错误 |
| **日志完整性** | Medium | 信号中断日志写入，审计日志丢失 |
| **进程状态** | High | 不一致状态可能导致子进程处理失败 |

### CWE-479 风险分析

根据POSIX标准和CWE-479定义：

> "If a signal handler calls a non-reentrant function, it can cause unpredictable results, including memory corruption or the process hanging."

**具体风险**:
1. **互斥锁死锁**: `std::unique_lock` 和 `std::condition_variable` 在信号上下文中是明确禁止的
2. **堆损坏**: `std::ostringstream` 使用堆分配，中断分配操作可能导致堆元数据损坏
3. **spdlog互斥锁**: 日志库内部使用互斥锁保护，信号中断可能导致锁状态损坏

### 安全影响评级

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Impact Rating                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Attack Complexity: LOW                                     │
│  ─────────────────────                                      │
│  • No special conditions needed for SIGINT/SIGTERM          │
│  • Any user with shell access can trigger                   │
│  • Standard kill command sufficient                         │
│                                                             │
│  Privileges Required: LOW                                   │
│  ───────────────────────                                    │
│  • Same user as process can send SIGINT/SIGTERM             │
│  • Different user with process access can send SIGTERM      │
│                                                             │
│  User Interaction: NONE                                     │
│  ─────────────────────                                      │
│  • Signal can be sent without interaction                   │
│                                                             │
│  Scope: CHANGED                                             │
│  ─────────────────                                          │
│  • Signal affects entire process group                      │
│  • Subprocess cleanup may fail                              │
│                                                             │
│  CVSS-like Assessment:                                      │
│  ─────────────────────                                      │
│  • Attack Vector: Local/Low                                 │
│  • Attack Complexity: Low                                   │
│  • Impact: High (DoS), Medium (Data Integrity)              │
│                                                             │
│  Overall: HIGH SEVERITY                                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 修复建议

### 1. 使用自管道技术 (Self-Pipe Trick)

这是处理信号的标准安全方法：

```cpp
// 推荐的修复方案框架

// 全局变量
static int g_signalPipe[2];  // pipe file descriptors

// 安全的信号处理器
void SafeSignalHandler(int sig)
{
    // 只写入信号编号到管道 - 这是异步信号安全的
    char signalByte = static_cast<char>(sig);
    write(g_signalPipe[1], &signalByte, 1);  // write() is async-signal-safe
}

// 初始化
void InitSignalHandling()
{
    pipe(g_signalPipe);  // 创建管道
    
    // 创建专用线程读取管道
    std::thread signalThread([]() {
        char signalByte;
        while (read(g_signalPipe[0], &signalByte, 1) > 0) {
            int sig = static_cast<int>(signalByte);
            // 在这里安全地处理信号（非信号上下文）
            HandleSignalInThreadContext(sig);
        }
    });
    signalThread.detach();
    
    // 注册安全信号处理器
    signal(SIGINT,  SafeSignalHandler);
    signal(SIGTERM, SafeSignalHandler);
    // ... 其他信号
}

// 在线程上下文中安全处理信号
void HandleSignalInThreadContext(int sig)
{
    // 现在可以安全使用所有函数
    ULOG_WARN(SUBMODLE_NAME_DAEMON, ...);
    std::unique_lock<std::mutex> lock(g_exitMtx);
    // ... 原来的处理逻辑
}
```

### 2. 使用 signalfd (Linux特有)

```cpp
// Linux特有的替代方案
#include <sys/signalfd.h>

// 创建signalfd
sigset_t mask;
sigemptyset(&mask);
sigaddset(&mask, SIGINT);
sigaddset(&mask, SIGTERM);
// ...
sigprocmask(SIG_BLOCK, &mask, NULL);

int fd = signalfd(-1, &mask, SFD_NONBLOCK);

// 使用epoll/select监听fd
// 在专用线程中处理信号
```

### 3. 最小化信号处理器

如果必须保留当前架构，至少移除不安全调用：

```cpp
void SignalInterruptHandler(int sig)
{
    // 只保留异步信号安全操作
    if (g_isKillingAll) { return; }
    
    // 设置原子标志 - 安全
    g_processExit = true;
    g_isKillingAll = true;
    
    // write() 到文件描述符是安全的
    // 可以预先打开一个日志文件描述符
    
    // 不调用: ULOG_*, mutex, condition_variable, sleep_for
    // 不调用: KillProcessGroup() (因为它有不安全操作)
    
    // 使用异步信号安全函数终止进程
    _exit(128 + sig);  // 或使用 killpg() + abort()
}
```

### 异步信号安全函数列表 (POSIX定义)

以下函数是信号上下文中唯一可安全调用的：

```
_Exit()          abort()          accept()         access()
alarm()          bind()           cfgetispeed()    cfgetospeed()
cfsetispeed()    cfsetospeed()    chdir()          chmod()
chown()          clock_gettime()  close()          connect()
creat()          dup()            dup2()           execle()
execve()         fcntl()          fdatasync()      fork()
fpathconf()      fstat()          fsync()          ftruncate()
getegid()        geteuid()        getgid()         getgroups()
getpeername()    getpgrp()        getpid()         getppid()
getsockname()    getsockopt()     getuid()         kill()
link()           listen()         lseek()          lstat()
mkdir()          mkfifo()         open()           pathconf()
pause()          pipe()           poll()           posix_trace_event()
pselect()        raise()          read()           readlink()
recv()           recvfrom()       recvmsg()        rename()
rmdir()          select()         sem_post()       send()
sendmsg()        sendto()         setgid()         setpgid()
setsid()         setsockopt()     setuid()         shutdown()
sigaction()      sigaddset()      sigdelset()      sigemptyset()
sigfillset()     sigismember()    signal()         sigpause()
sigpending()     sigprocmask()    sigqueue()       sigset()
sigsuspend()     sleep()          socket()         socketpair()
stat()           symlink()        sysconf()        tcdrain()
tcflow()         tcflush()        tcgetattr()      tcgetpgrp()
tcsendbreak()    tcsetattr()      tcsetpgrp()      time()
timer_getoverrun() timer_gettime() timer_settime() times()
umask()          uname()          unlink()         utime()
wait()           waitpid()        write()          ...
```

**注意**: `std::mutex`, `std::condition_variable`, `std::ostringstream`, `malloc`, `free` 都不在列表中！

## 相关漏洞

| ID | 类型 | 文件 | 行号 | 关系 |
|----|------|------|------|------|
| DAEMON-002 | Signal Handler Safety | llm_daemon.cpp | 223-273 | 同类问题（SignalChldHandler） |
| DAEMON-003 | Race Condition | llm_daemon.cpp | 196-273 | 相关竞态条件 |

## 结论

**判定**: 真实漏洞 (TRUE POSITIVE)

**理由**:
1. 明确违反CWE-479和POSIX信号安全要求
2. 代码中存在多处非异步信号安全函数调用
3. 触发条件简单，可达性高
4. 可导致严重的DoS和数据完整性问题
5. 代码库中未发现有效的缓解措施

**建议优先级**: HIGH - 应立即修复

---

报告生成时间: 2026-04-17
分析工具: Vuln-DB Deep Analysis Worker
