# CANN Runtime 威胁分析报告

**生成时间**: 2026-04-24  
**项目路径**: /home/pwn20tty/Desktop/opencode_project/cann/runtime  
**项目类型**: AI NPU 运行时服务（network_service）  
**代码规模**: 3481 个源文件，150000+ 行代码  

---

## 1. 项目概述

### 1.1 项目定位

CANN Runtime 是华为 Ascend NPU 的运行时组件，提供：
- **ACL API**：用户编程接口（337 个公开函数）
- **运行时核心**：设备/流/内存/任务管理
- **TSD 客户端**：与设备守护进程通信（IPC）
- **队列调度服务**：队列绑定/查询 RPC 服务
- **驱动层**：NPU 驱动接口封装

### 1.2 部署模型

```
┌─────────────────────────────────────────────────────┐
│                   User Application                   │
│              (调用 ACL API，不受信任)                │
└────────────────────┬────────────────────────────────┘
                     │ aclInit(), aclrtMalloc(), ...
                     │ (API 参数来自用户应用)
┌────────────────────▼────────────────────────────────┐
│               ACL API Layer (libascendcl.so)         │
│   337 个公开函数 - 需验证输入参数                     │
└────────────────────┬────────────────────────────────┘
                     │
        ┌────────────┴─────────────┬──────────────────┐
        │                          │                  │
┌───────▼────────┐   ┌─────────────▼───────┐  ┌──────▼─────┐
│ Runtime Core   │   │ TSD Client         │  │ Queue Sched│
│ (内存/流/任务) │   │ (IPC通信)          │  │ (RPC服务)  │
└───────┬────────┘   └──────┬──────────────┘  └──────┬─────┘
        │                  │                        │
        │                  │ /var/tsdaemon          │ Protobuf
        │                  │ (Unix Socket)          │
┌───────▼────────┐   ┌─────▼──────┐          ┌──────▼─────┐
│ NPU Driver     │   │ tsdaemon   │          │ QS Server  │
│ (ioctl/mmap)   │   │ (守护进程) │          │ (调度服务) │
└───────┬────────┘   └────┬───────┘          └────┬───────┘
        │                 │                       │
┌───────▼────────┐   ┌────▼──────┐          ┌─────▼──────┐
│ NPU Hardware   │   │ Device OS │          │ Queue DB   │
│ (AI Core)      │   │ (MiniOS)  │          │            │
└────────────────┘   └───────────┘          └────────────┘
```

---

## 2. 攻击面识别

### 2.1 主要攻击面

| 攻击面 | 位置 | 风险等级 | 攻击向量 |
|--------|------|----------|----------|
| **ACL API Interface** | include/external/acl/acl_rt.h | **Critical** | 用户应用传入恶意参数（size, count, args, configPath） |
| **IPC Daemon** | /var/tsdaemon (Unix Socket) | **High** | 本地进程发送恶意消息到 tsdaemon |
| **Queue Schedule Service** | protobuf RPC | **High** | 客户端发送队列绑定/查询请求 |
| **NPU Driver** | ioctl/mmap | **High** | 恶意驱动命令触发内核漏洞 |
| **Configuration File** | aclInit(configPath) | **Medium** | 配置文件路径遍历/注入 |
| **HDC Communication** | hdc_client.cpp | **Medium** | IPC 消息篡改 |

### 2.2 关键入口点

**ACL API 层（337 个函数）**：

1. **aclInit(const char *configPath)** - 初始化
   - 风险：配置文件路径遍历、文件注入
   
2. **aclrtMalloc(void **devPtr, size_t size, ...)** - 内存分配
   - 风险：整数溢出、堆溢出
   
3. **aclrtMemcpy(void *dst, size_t destMax, const void *src, size_t count, ...)** - 内存拷贝
   - 风险：缓冲区溢出、越界读写
   
4. **aclrtLaunchKernel(aclrtFuncHandle funcHandle, uint32_t numBlocks, void *args, ...)** - 内核启动
   - 部门间信任：args 参数注入、代码执行
   
5. **aclrtFree(void *devPtr)** - 内存释放
   - 风险：UAF（释放后使用）、双重释放

**IPC 层**：

1. **RecvMsg(sessionId)** - hdc_client.cpp:143
   - 风险：IPC 消息解析漏洞
   
2. **SendOpenMsg(rankSize)** - process_mode_manager.cpp:119
   - 风险：消息伪造

**RPC 层**：

1. **BQSBindQueueMsg(queue_id)** - easycom_message.proto:14
   - 风险：queue_id 权限绕过

---

## 3. 信任边界分析

### 3.1 信任边界定义

| 边界 | 可信侧 | 不可信侧 | 风险 |
|------|--------|----------|------|
| **User Application** | Application logic (User controlled) | ACL API parameters | **Critical** |
| **IPC Daemon** | tsdaemon service (System controlled) | Client requests via /var/tsdaemon | **High** |
| **NPU Driver** | Runtime kernel (System controlled) | Driver commands and memory operations | **High** |
| **Queue Schedule Service** | queue_schedule server | Client queue bind/unbind requests | **Medium** |
| **Configuration File** | Admin controlled | File content could be tampered | **Medium** |

### 3.2 数据流向

```
User Application (不受信任)
    ↓ ACL API 参数 (size, count, args, configPath)
ACL API Layer
    ↓ 参数传递
Runtime Core
    ↓ 内存操作/驱动命令
NPU Driver
    ↓ ioctl/mmap
NPU Hardware Kernel (可信)
```

**关键风险**：用户控制的参数直接传递到驱动层，缺乏充分验证。

---

## 4. STRIDE 威胁建模

### 4.1 Spoofing（身份伪造）

| 威胁 | 位置 | 影响 |
|------|------|------|
| 客户端伪造队列 ID | BQSBindQueueMsg | 绕过队列访问权限 |
| 进程伪造 PID | tsdaemon IPC | 获取设备访问权限 |

### 4.2 Tampering（数据篡改）

| 娏胁 | 位置 | 影响 |
|------|------|------|
| 配置文件篡改 | aclInit(configPath) | 加载恶意配置 |
| IPC 消息篡改 | hdc_client.cpp | 破坏通信协议 |
| 内存数据篡改 | aclrtMemcpy | 越界写入 |

### 4.3 Repudiation（抵赖）

| 娏胁 | 位置 | 影响 |
|------|------|------|
| 缺乏操作审计日志 | ACL API | 无法追踪恶意操作 |
| IPC 消息无签名 | tsdaemon | 无法验证消息来源 |

### 4.4 Information Disclosure（信息泄露）

| 娏胁 | 位置 | 影响 |
|------|------|------|
| 设备内存信息泄露 | aclrtMemcpy, aclrtPointerGetAttributes | 泄露内核内存 |
| DFX 日志泄露 | dfx/log | 泄露敏感信息 |
| 错误消息泄露 | aclGetRecentErrMsg() | 泄露内部状态 |

### 4.5 Denial of Service（拒绝服务）

| 娏胁 | 位置 | 影响 |
|------|------|------|
| 内存耗尽攻击 | aclrtMalloc(size=MAX) | 消耗设备内存 |
| 流阻塞攻击 | aclrtSynchronizeDevice | 阻塞运行时 |
| IPC 连接耗尽 | tsdaemon socket | 拒绝其他客户端连接 |

### 4.6 Elevation of Privilege（权限提升）

| 娏胁 | 位置 | 影响 |
|------|------|------|
| 内核参数注入 | aclrtLaunchKernel(args) | 执行恶意内核代码 |
| 驱动命令注入 | ioctl | 提升到内核权限 |
| queue_id 权限绕过 | BQSBindQueueMsg | 访问其他用户的队列 |

---

## 5. 高风险模块分析

### 5.1 Critical 级模块

**runtime_core（核心运行时）**：
- api_impl.cc (9043 行) - API 实现层
- runtime.cc (6129 行) - 运行时核心
- 内存/流/设备/任务管理模块

**runtime_driver（驱动层）**：
- npu_driver_mem.cc (2552 行) - 驱动内存管理
- npu_driver_res.cc (2344 行) - 驱动资源管理
- npu_driver.cc (1594 行) - 驱动核心

**扫描重点**：
1. 参数验证完整性（size, count, args 边界检查）
2. 整数溢出检测（aclrtMalloc, halMemAlloc）
3. 内存操作安全性（memcpy, memset）
4. ioctl 命令验证

### 5.2 High 级模块

**tsd_client（IPC 客户端）**：
- process_mode_manager.cpp (2345 行) - 进程管理器
- hdc_client.cpp - HDC 客户端通信

**queue_schedule（队列调度）**：
- bqs_client.cpp (11919 行) - BQS 客户端
- dgw_client.cpp - DGW 客户端
- server/main.cpp - 服务入口

**cmodel_driver（模型驱动）**：
- driver_api.c (964 行) - 驱动 API
- driver_mem.c (15397 行) - 驱动内存

**扫描重点**：
1. IPC 消息解析安全性（protobuf 解析）
2. Unix socket 消息验证
3. queue_id 权限检查
4. 驱动命令验证

---

## 6. 推荐扫描策略

### 6.1 优先级排序

| 优先级 | 模块 | 扫描重点 | 预估工作量 |
|--------|------|----------|------------|
| **P1** | runtime_core | 内存操作、参数验证 | 高 |
| **P1** | runtime_driver | ioctl/mmap 安全 | 高 |
| **P1** | acl API 层 | 337 个 API 输入验证 | 高 |
| **P2** | tsd_client | IPC 消息处理 | 中 |
| **P2** | queue_schedule | RPC 消息解析 | 中 |
| **P2** | cmodel_driver | 驱动命令验证 | 中 |
| **P3** | dfx | 信息泄露风险 | 低 |
| **P4** | mmpa | 平台抽象层 | 低 |

### 6.2 漏洞类型预期

基于代码分析，预期可能发现以下漏洞类型：

| 漏洞类型 | CWE | 可能位置 | 风险等级 |
|----------|-----|----------|----------|
| **整数溢出** | CWE-190 | aclrtMalloc, halMemAlloc, drvMemAlloc | Critical |
| **缓冲区溢出** | CWE-120 | aclrtMemcpy, memcpy operations | Critical |
| **UAF** | CWE-416 | aclrtFree, memory management | High |
| **路径遍历** | CWE-22 | aclInit(configPath) | High |
| **IPC 消息注入** | CWE-912 | hdc_client, tsdaemon | High |
| **权限绕过** | CWE-269 | BQSBindQueueMsg(queue_id) | High |
| **信息泄露** | CWE-200 | aclrtPointerGetAttributes, dfx/log | Medium |
| **代码注入** | CWE-94 | aclrtLaunchKernel(args) | Critical |

### 6.3 扫描工具建议

1. **静态分析**：
   - C/C++ 内存安全扫描（整数溢出、缓冲区溢出）
   - 数据流分析（污点追踪：API 参数 → 驱动操作）
   
2. **污点分析**：
   - Source：ACL API 参数
   - Sink：memcpy, malloc, ioctl, fopen
   
3. **配置分析**：
   - 配置文件解析逻辑（路径验证）
   
4. **IPC 分析**：
   - Unix socket 消息格式验证
   - Protobuf 消息解析安全性

---

## 7. 总结

### 7.1 核心风险

CANN Runtime 是一个高风险的 NPU 运行时服务，主要风险来自：

1. **庞大的 API 接口**（337 个函数）- 用户参数直接传递到驱动层
2. **多层 IPC 通信**- Unix socket + protobuf RPC 消息处理复杂
3. **驱动层交互**- ioctl/mmap 直接与 NPU 硬件通信
4. **内存操作密集**- 大量 malloc/memcpy/free 操作

### 7.2 关键建议

1. **强化参数验证**：在 ACL API 层增加严格的边界检查
2. **IPC 安全加固**：增加消息签名和来源验证
3. **驱动命令过滤**：限制危险的 ioctl 命令
4. **内存隔离**：增加内存访问权限检查
5. **审计日志**：记录关键 API 调用和 IPC 消息

---

**报告结束**
