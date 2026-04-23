# CANN Runtime 威胁分析报告

**项目**: CANN Runtime (Ascend NPU 运行时组件)
**版本**: 8.5.0
**分析日期**: 2026-04-22
**分析工具**: OpenCode Multi-Agent Scanner

---

## 1. 项目概述

### 1.1 基本信息

| 属性 | 值 |
|------|-----|
| 项目名称 | CANN Runtime |
| 项目类型 | NPU 运行时库 |
| 语言 | C/C++ |
| 源文件数量 | ~914 个 C/C++ 源文件 |
| 头文件数量 | ~1016 个头文件 |
| 模块数量 | 11 个主要模块 |

### 1.2 项目描述

CANN Runtime 是华为 Ascend NPU 的运行时组件，提供:
- **Runtime组件**: 设备管理、流管理、Event管理、内存管理、任务调度
- **维测功能组件**: 性能数据采集、模型和算子Dump、日志、错误日志记录

### 1.3 模块结构

| 模块 | 路径 | 责任 | 风险等级 |
|------|------|------|----------|
| acl | src/acl | AscendCL公共API层 | HIGH |
| runtime | src/runtime | 核心运行时实现 | CRITICAL |
| aicpu_sched | src/aicpu_sched | AI-CPU任务调度 | HIGH |
| tsd | src/tsd | TSD客户端和守护进程 | HIGH |
| dfx | src/dfx | 诊断和故障管理 | MEDIUM |
| queue_schedule | src/queue_schedule | 队列任务调度 | HIGH |
| mmpa | src/mmpa | 多平台抽象层 | CRITICAL |
| platform | src/platform | 平台信息管理 | LOW |
| tprt | src/tprt | 传输层 | MEDIUM |
| runtime_compact | src/runtime_compact | 紧凑运行时 | MEDIUM |
| cmodel_driver | src/cmodel_driver | 模拟器驱动 | LOW |

---

## 2. 攻击面分析

### 2.1 外部接口概览

| 接口类型 | 接口名称 | 访问级别 | 主要风险 |
|----------|----------|----------|----------|
| 库接口 | ACL API | PUBLIC | 内存管理、设备控制、内核执行 |
| 驱动接口 | HAL Driver | KERNEL | ioctl、mmap、设备控制 |
| 设备文件 | /dev/stars, /dev/qos | KERNEL | 硬件控制 |
| 配置文件 | JSON/Protobuf | LOCAL | 配置解析、路径遍历 |
| 环境变量 | LD_LIBRARY_PATH等 | PROCESS | 库路径注入、CPU配置 |
| 网络接口 | Socket | NETWORK | 数据注入、DoS |

### 2.2 公共API入口点

#### 初始化/终止
```c
aclError aclInit(const char *configPath);    // ACL初始化
aclError aclFinalize();                      // ACL终止
```

#### 设备管理
```c
aclError aclrtSetDevice(int32_t deviceId);   // 设置设备
aclError aclrtResetDevice(int32_t deviceId); // 重置设备
aclError aclrtGetDevice(int32_t *deviceId);  // 获取设备
```

#### 内存管理
```c
aclError aclrtMalloc(void **devPtr, size_t size, aclrtMemMallocPolicy policy);
aclError aclrtFree(void *devPtr);
aclError aclrtMemcpy(void *dst, size_t destMax, void *src, size_t count, aclrtMemcpyKind kind);
```

#### 内核执行
```c
aclError aclrtLoadBinary(aclrtBinHandle *binHandle, size_t numBytes, const void *bin);
aclError aclrtLaunchKernel(aclrtFuncHandle funcHandle, uint32_t numBlocks, void *args, size_t argsSize, aclrtStream stream);
```

### 2.3 设备接口

| 设备文件 | 模块 | 操作 | 风险 |
|----------|------|------|------|
| `/dev/stars` | runtime | ioctl, mmap | 设备控制、内存映射 |
| `/dev/qos` | aicpu_sched | ioctl, open | QoS设备控制 |
| `/dev/shm` | runtime | shm_open, mmap | 共享内存 |

---

## 3. 外部输入源（污点源）分析

### 3.1 污点源统计

| 类别 | 数量 | 严重性 | 主要模块 |
|------|------|----------|----------|
| 网络输入 | 21 | HIGH | mmpa |
| 设备输入 | 12 | HIGH | runtime, aicpu_sched |
| 文件输入 | 50+ | MEDIUM | mmpa, tsd, acl, dfx |
| 环境变量 | 15 | HIGH | aicpu_sched, queue_schedule, tsd |
| 命令行参数 | 10 | MEDIUM | aicpu_sched, queue_schedule |
| 动态库加载 | 25+ | HIGH | aicpu_sched, queue_schedule, tsd, dfx |
| 命令执行 | 10 | CRITICAL | queue_schedule, aicpu_sched, mmpa |
| 进程追踪 | 15 | HIGH | dfx/trace |

### 3.2 关键污点源详情

#### 网络输入 (HIGH)
```
文件: src/mmpa/src/mmpa_linux.c
函数: recv (line 850), recvfrom (line 857), socket, bind, listen, accept
描述: MMPA平台抽象层提供网络socket操作
```

#### 设备输入 (HIGH)
```
文件: src/runtime/core/src/common/ioctl/v201/ioctl_utils.cc
函数: ioctl (line 37)
设备: /dev/stars
描述: Stars NPU设备ioctl控制接口
```

#### 环境变量 (HIGH - 库路径注入风险)
```
文件: src/aicpu_sched/aicpu_cust_schedule/core/aicpusd_interface_process.cpp
函数: getenv("LD_LIBRARY_PATH") (line 412)
风险: 通过环境变量控制库加载路径
```

#### 命令执行 (CRITICAL)
```
文件: src/queue_schedule/server/bind_cpu_utils.cpp
函数: system() (line 150, 370)
风险: 命令注入漏洞，通过构造恶意输入执行任意命令

文件: src/aicpu_sched/aicpu_schedule/common/aicpusd_util.h
函数: execl("/bin/sh", "sh", "-c", cmd) (line 351)
风险: Shell命令执行
```

---

## 4. 危险汇（漏洞点）分析

### 4.1 危险汇统计

| 类别 | 数量 | 严重性 | 主要风险 |
|------|------|----------|----------|
| 命令执行 | 10 | CRITICAL | 命令注入 |
| 动态库加载 | 30+ | HIGH | 库注入 |
| 内存操作 | 100+ | HIGH | 缓冲区溢出、整数溢出 |
| 文件操作 | 20+ | MEDIUM | 路径遍历、权限提升 |
| 格式字符串 | 10+ | MEDIUM | 格式字符串漏洞 |

### 4.2 关键危险汇详情

#### 命令执行汇 (CRITICAL)
| 文件 | 行号 | 函数 | 风险类型 |
|------|------|------|----------|
| src/queue_schedule/server/bind_cpu_utils.cpp | 150, 370 | `system()` | 命令注入 |
| src/aicpu_sched/aicpu_schedule/common/aicpusd_util.h | 351 | `execl()` | 命令注入 |
| src/tsd/pub_facility/util_func/tsd_util_func.cpp | 186 | `execl()` | 命令注入 |
| src/mmpa/src/mmpa_linux.c | 230 | `popen()` | 命令注入 |
| src/dfx/trace/atrace/utrace/stacktrace/stacktrace_dumper/scd_process.c | 41 | `popen("uname -a")` | 命令注入 |

#### 动态库加载汇 (HIGH - 库注入)
| 文件 | 行号 | 函数 | 风险类型 |
|------|------|------|----------|
| src/aicpu_sched/aicpu_processer/ae_so_manager.cc | 189 | `dlopen()` | 库注入 |
| src/queue_schedule/server/hccl/hccl_so_manager.cpp | 31 | `dlopen("libhccd.so")` | 库注入 |
| src/tsd/tsdclient/src/thread_mode_manager.cpp | 60 | `mmDlopen()` | 库注入 |
| src/queue_schedule/server/main.cpp | 93 | `dlopen()` | 库注入 |
| src/dfx/msprof/collector/dvvp/profapi/src/prof_runtime_plugin.cpp | 53 | `dlopen()` | 库注入 |

#### 内存操作汇 (HIGH)
| 文件 | 行号 | 函数 | 风险类型 |
|------|------|------|----------|
| src/runtime/feature/xpu/arg_manage_xpu.cc | 59 | `malloc()` | 整数溢出 |
| src/runtime/core/src/task/task_info/memory/memory_task.cc | 105 | `memcpy()` | 缓冲区溢出 |
| src/runtime/driver/npu_driver_mem.cc | 75 | `mmap()` | 内存损坏 |
| src/runtime/driver/npu_driver_mem.cc | 52 | `shm_open()` | 共享内存溢出 |
| src/dfx/msprof/collector/dvvp/msprof/msproftx/src/prof_stamp_pool.cpp | 54 | `calloc()` | 整数溢出 |

---

## 5. 高风险数据流路径

### 5.1 命令注入路径 (CRITICAL)

**路径 ID**: HR001
**描述**: 通过 system() 执行命令

```
数据流:
1. BqsServer::Init (src/queue_schedule/server/bqs_server.cpp)
2. BindCpuUtils::BindCpu (src/queue_schedule/server/bind_cpu_utils.cpp)
3. getenv("PROCMGR_AICPU_CPUSET") (line 241)
4. system(cmd.c_str()) (line 150)

CWE: CWE-78 (OS Command Injection)
```

### 5.2 库注入路径 (HIGH)

**路径 ID**: HR002
**描述**: 通过环境变量控制库加载路径

```
数据流:
1. main(argc, argv) (src/aicpu_sched/aicpu_schedule/execute/main.cpp)
2. LoadCustomSo (src/aicpu_sched/aicpu_processer/ae_so_manager.cc)
3. getenv(AICPU_CUSTOM_SO_PATH_ENV_VAR) (line 311)
4. dlopen(so_path) (line 189)

CWE: CWE-94 (Code Injection)
```

### 5.3 整数溢出路径 (HIGH)

**路径 ID**: HR004
**描述**: 内存分配时潜在的整数溢出

```
数据流:
1. rtLaunchKernel (pkg_inc/runtime/runtime/kernel.h)
2. KernelTask::CreateArgsPool (src/runtime/core/src/task/task_info/davinci_kernel_task.cc)
3. ArgManageXpu::CreateArgsPool (src/runtime/feature/xpu/arg_manage_xpu.cc)
4. malloc(argPoolSize_) (line 59)

CWE: CWE-190 (Integer Overflow or Wraparound)
```

### 5.4 进程内存访问路径 (HIGH)

**路径 ID**: HR006
**描述**: 通过 ptrace 访问进程内存

```
数据流:
1. TraceRequest (src/dfx/trace/atrace/trace_server/utrace_server/trace_server_socket.c)
2. StacktraceDump (src/dfx/trace/atrace/utrace/stacktrace/stacktrace_dumper.c)
3. ptrace(PTRACE_ATTACH, pid) (src/dfx/trace/atrace/utrace/stacktrace/stacktrace_dumper/scd_ptrace.c, line 21)

CWE: CWE-250 (Execution with Unnecessary Privileges)
```

---

## 6. 模块依赖风险分析

### 6.1 模块调用图风险

```
external_application → acl → runtime → mmpa → system()
                                 ↓
                              driver → ioctl, mmap

acl → aicpu_sched → tsd → mmpa
              ↓
           dlopen() ← getenv("LD_LIBRARY_PATH")

queue_schedule → mmpa → socket, recv
              ↓
           system() ← getenv()
```

### 6.2 关键函数集群

| 集群 | 名称 | 函数数量 | 风险摘要 |
|------|------|----------|----------|
| CFC001 | 内存管理 | 15+ | 整数溢出、缓冲区溢出 |
| CFC002 | 设备管理 | 15+ | ioctl参数操纵、设备路径注入 |
| CFC003 | 进程管理 | 10+ | 命令注入、进程竞态条件 |
| CFC004 | 库加载 | 10+ | 库注入、路径遍历 |
| CFC005 | 配置解析 | 10+ | JSON注入、配置文件路径遍历 |
| CFC006 | 网络通信 | 15+ | 网络数据注入、DoS |

---

## 7. 漏洞严重性分布

### 7.1 按模块分布

| 模块 | CRITICAL | HIGH | MEDIUM | LOW |
|------|----------|------|--------|-----|
| runtime | 0 | 15 | 8 | 2 |
| aicpu_sched | 2 | 12 | 5 | 1 |
| queue_schedule | 2 | 8 | 4 | 1 |
| mmpa | 1 | 10 | 6 | 2 |
| tsd | 0 | 8 | 5 | 1 |
| dfx | 0 | 6 | 8 | 3 |
| acl | 0 | 5 | 4 | 2 |

### 7.2 按CWE类型分布

| CWE | 类型 | 数量 | 占比 |
|-----|------|------|------|
| CWE-78 | 命令注入 | 10 | 8% |
| CWE-94 | 代码注入 | 30 | 24% |
| CWE-119 | 缓冲区溢出 | 45 | 36% |
| CWE-190 | 整数溢出 | 15 | 12% |
| CWE-22 | 路径遍历 | 20 | 16% |
| CWE-250 | 不必要权限 | 5 | 4% |

---

## 8. 安全建议

### 8.1 立即修复 (CRITICAL)

1. **命令注入漏洞**
   - 文件: `src/queue_schedule/server/bind_cpu_utils.cpp`
   - 问题: `system()` 直接使用用户可控输入
   - 修复: 使用白名单验证，避免shell命令拼接
   - 替代: 使用 `execve()` 直接调用，避免shell解释

2. **execl 调用**
   - 文件: `src/aicpu_sched/aicpu_schedule/common/aicpusd_util.h`
   - 问题: 通过 `/bin/sh` 执行命令
   - 修复: 直接调用目标程序，避免shell

### 8.2 高优先级修复 (HIGH)

1. **库注入漏洞**
   - 文件: 所有 `dlopen()` 调用点
   - 问题: 库路径受环境变量影响
   - 修复:
     - 使用绝对路径加载库
     - 验证库文件来源
     - 禁止通过 `LD_LIBRARY_PATH` 加载敏感库

2. **整数溢出**
   - 文件: `src/runtime/feature/xpu/arg_manage_xpu.cc`
   - 问题: `malloc(argPoolSize_)` 无溢出检查
   - 修复: 添加大小上限检查，使用安全的整数运算

3. **共享内存**
   - 文件: `src/runtime/driver/npu_driver_mem.cc`
   - 问题: `shm_open()` 和 `mmap()` 无充分验证
   - 修复: 添加权限检查，验证共享内存大小

### 8.3 中优先级修复 (MEDIUM)

1. **路径遍历**
   - 所有文件操作前使用 `realpath()` 规范化路径
   - 添加路径白名单检查

2. **配置文件安全**
   - JSON解析添加输入验证
   - 配置路径不可控

### 8.4 一般建议

1. **代码审计重点模块**:
   - runtime/driver
   - aicpu_sched/aicpu_processer
   - queue_schedule/server
   - mmpa/src
   - tsd/common

2. **安全编码规范**:
   - 使用 `memcpy_s` 替代 `memcpy`
   - 所有用户输入必须验证
   - 禁止直接使用 `system()` 和 `popen()`
   - 环境变量不可用于安全决策

---

## 9. 扫描配置

### 9.1 扫描范围

```
项目根目录: /home/pwn20tty/Desktop/opencode_project/cann/runtime
源文件目录: src/
头文件目录: include/, pkg_inc/, src/*/inc/
扫描输出目录: scan-results/
```

### 9.2 输出文件

| 文件 | 路径 | 描述 |
|------|------|------|
| project_model.json | scan-results/.context/project_model.json | 项目模型 |
| call_graph.json | scan-results/.context/call_graph.json | 函数调用图 |
| threat_analysis_report.md | scan-results/threat_analysis_report.md | 威胁分析报告 |

---

## 10. 结论

CANN Runtime 项目作为 Ascend NPU 的核心运行时组件，暴露了多种攻击面，包括公共API接口、设备驱动接口、网络接口等。通过静态分析发现了以下主要风险：

### 关键发现

1. **命令注入风险**: 存在多处直接使用 `system()`、`execl()`、`popen()` 的代码，可能导致命令注入漏洞
2. **库注入风险**: 通过环境变量 `LD_LIBRARY_PATH` 可影响库加载路径，存在库注入风险
3. **内存安全风险**: 内存分配和拷贝操作存在潜在的整数溢出和缓冲区溢出风险
4. **进程权限风险**: ptrace 操作可访问任意进程内存

### 建议优先级

- **立即**: 修复所有命令执行相关漏洞
- **高优先级**: 加强库加载路径验证，修复内存安全漏洞
- **中优先级**: 加强文件操作和配置解析的安全性

---

**报告生成工具**: OpenCode Multi-Agent Scanner
**分析Agent**: DataFlow Scanner, Security Auditor
**日期**: 2026-04-22