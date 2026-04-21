# 漏洞扫描报告 — 已确认漏洞

**项目**: MindStudio-Monitor
**扫描时间**: 2026-04-20T00:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

### 项目概述

MindStudio-Monitor 是华为 MindStudio 平台的 NPU 监控组件，包含 dynolog 守护进程和 Python C 扩展绑定模块。该系统通过 TCP RPC 服务（默认端口 1778）和 Unix Domain Socket IPC 提供远程监控能力，支持 NPU 设备的性能采集和训练作业监控。

### 关键发现

本次安全扫描共发现 **2 个已确认漏洞**，均为 Medium 严重性级别：

| 漏洞ID | 类型 | 位置 | 核心风险 |
|--------|------|------|----------|
| DF-008 | 信息泄露 (CWE-200) | RPC 服务入口 | 敏感请求内容被完整记录到日志 |
| VULN-SEC-BIND-001 | 输入验证缺失 (CWE-20) | Python 绑定层 | NPU ID 无范围验证导致 IPC 消息污染 |

### 风险评估

**业务影响**：
- **信息泄露风险**：RPC 请求中的训练配置、作业 ID、进程列表等敏感业务数据会被持久化到日志文件，可能违反数据保护合规要求，并为后续攻击提供情报支撑
- **系统稳定性风险**：无效的 NPU ID 注册可能导致 dynolog daemon 的资源管理逻辑异常，影响多租户环境下的设备分配

**攻击可达性**：
- DF-008 可通过远程网络触达（NO_CERTS 模式下无认证门槛）
- VULN-SEC-BIND-001 需要本地 Python 执行权限（多租户容器/Jupyter 环境中风险较高）

### 修复优先级

| 优先级 | 漏洞 | 建议时间 |
|--------|------|----------|
| P1 | DF-008 RPC 信息泄露 | 立即修复 |
| P2 | VULN-SEC-BIND-001 输入验证 | 短期修复（1-2 周） |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 14 | 50.0% |
| POSSIBLE | 7 | 25.0% |
| LIKELY | 5 | 17.9% |
| CONFIRMED | 2 | 7.1% |
| **总计** | **28** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Medium | 2 | 100.0% |
| **有效漏洞总计** | **2** | - |
| 误报 (FALSE_POSITIVE) | 14 | - |

### 1.3 Top 10 关键漏洞

1. **[DF-008]** information_disclosure (Medium) - `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:322` @ `processOne` | 置信度: 85
2. **[VULN-SEC-BIND-001]** Improper Input Validation (Medium) - `plugin/bindings.cpp:117` @ `init_dyno` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `initSocket@dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp` | network | untrusted_network | TCP socket绑定到IPv6任意地址(in6addr_any)，监听指定端口(默认1778)，远程客户端可通过dyno CLI连接发送RPC请求，攻击者可触达 | TCP RPC服务入口，接收JSON格式的RPC请求 |
| `accept@dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp` | network | untrusted_network | 接受TCP连接，客户端可来自任何网络位置 | 接受TCP连接 |
| `get_message@dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp` | network | untrusted_network | 通过recv()或SSL_read()读取客户端发送的消息，消息内容完全由客户端控制 | 读取RPC请求消息 |
| `processOneImpl@dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h` | rpc | untrusted_network | 处理RPC请求，解析JSON并执行getStatus、setKinetOnDemandRequest等操作，输入来自网络 | 处理RPC请求，解析并执行命令 |
| `ipc_manager_->recv@dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp` | rpc | semi_trusted | 通过Unix Domain Socket接收IPC消息，本地进程需有权限连接到socket文件 | IPC消息接收入口 |
| `data_ipc_manager_->recv@dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp` | rpc | semi_trusted | 通过Unix Domain Socket接收数据消息，本地进程需有权限连接 | IPC数据消息接收入口 |
| `processMsg@dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp` | rpc | semi_trusted | 处理IPC消息，解析消息类型并执行对应操作，输入来自本地进程 | 处理IPC消息 |
| `processDataMsg@dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp` | rpc | semi_trusted | 处理IPC数据消息，解析JSON格式数据并记录，输入来自本地进程 | 处理IPC数据消息，包含性能数据 |
| `main@dynolog_npu/dynolog/src/Main.cpp` | cmdline | untrusted_local | 命令行参数由本地用户传入，启动daemon时可通过gflags配置端口、证书目录等 | 程序入口，解析命令行参数 |
| `run@dynolog_npu/dynolog/src/ThreadManager.cpp` | cmdline | untrusted_local | 解析命令行参数(gflags)，设置端口、启用IPC监控等配置 | 线程管理器运行，解析命令行参数 |
| `Init@plugin/ipc_monitor/NpuIpcClient.cpp` | rpc | semi_trusted | IPC客户端初始化，通过Unix Domain Socket与dynolog daemon通信 | IPC客户端初始化 |
| `IpcClientNpuConfig@plugin/ipc_monitor/NpuIpcClient.cpp` | rpc | semi_trusted | 向dynolog发送配置请求并接收响应，通过IPC | IPC配置请求 |

**其他攻击面**:
- TCP RPC服务: 端口1778（可配置），接收JSON格式RPC请求
- SSL/TLS加密通道: 支持证书验证，可选NO_CERTS模式
- Unix Domain Socket IPC: 抽象socket路径'dynolog'和'dynolog_data'
- JSON解析: RPC和IPC消息均使用JSON格式
- 配置参数: 命令行参数控制端口、证书目录、监控功能启用等
- Python C扩展: bindings.cpp暴露的Python接口

---

## 3. Medium 漏洞 (2)

### [DF-008] information_disclosure - processOne

**严重性**: Medium | **CWE**: CWE-200 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:322` @ `processOne`
**模块**: dynolog_daemon

**描述**: RPC请求处理过程中将完整的请求内容记录到日志。Line 322: LOG(INFO) << "RPC message received = " << request_str; 可能导致敏感信息（如配置内容、PID列表）泄露到日志文件。

**漏洞代码** (`dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:322`)

```c
LOG(INFO) << "RPC message received = " << request_str;
```

**达成路径**

get_message() → request_str → LOG(INFO) → log file

**验证说明**: RPC请求消息被完整记录到日志文件(LOG(INFO) << "RPC message received = " << request_str)。远程攻击者发送的请求内容会被持久化到日志，可能导致敏感信息泄露(配置内容、PID列表等)。无任何缓解措施。

**深度分析**

#### 根因分析

从源代码 `SimpleJsonServer.cpp:314-330` 可见，`processOne()` 函数在接收 RPC 请求后，直接将完整的 `request_str` 字符串通过 `LOG(INFO)` 记录到日志：

```cpp
// dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:314-330
void SimpleJsonServerBase::processOne() noexcept
{
    LOG(INFO) << "Waiting for connection.";
    ClientSocketWrapper client;
    if (!client.accept(sock_fd_, ctx_)) {
        return;
    }
    std::string request_str = client.get_message();
    LOG(INFO) << "RPC message received = " << request_str;  // ← 漏洞点
    auto response_str = processOneImpl(request_str);
    ...
}
```

**根因**：开发者为了调试便利，将完整请求内容记录到 INFO 级别日志，忽略了以下安全风险：
1. INFO 级别日志在生产环境通常默认启用
2. 请求内容完全由远程客户端控制，不可信
3. 日志持久化到磁盘，可能被备份系统长期保留

#### 潜在利用场景

**场景 1 - 业务情报收集**：
攻击者发送包含训练配置的 RPC 请求（如 `setKinetOnDemandRequest`），日志将记录完整的 `config` 字段，暴露：
- 训练参数（profiler_level, activities）
- 敏感路径（log_file, trace_output）
- 业务标识（job_id, process_limit）

**场景 2 - 系统信息泄露**：
通过 `getStatus` 等请求，日志记录 PID 列表和运行状态，为后续攻击（如进程劫持）提供情报。

**场景 3 - 合规违规**：
在数据敏感环境（如金融、医疗训练任务），日志泄露可能违反 GDPR 或企业安全策略。

#### 建议修复方式

**推荐修复**：移除完整请求日志，仅记录请求长度或函数类型：

```cpp
// 修复方案: 仅记录请求长度
LOG(INFO) << "RPC message received, length = " << request_str.size() << " bytes";
```

或使用脱敏函数过滤敏感字段后记录。详见修复建议章节。

---

### [VULN-SEC-BIND-001] Improper Input Validation - init_dyno

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `plugin/bindings.cpp:117` @ `init_dyno`
**模块**: bindings
**跨模块**: bindings → ipc_monitor

**描述**: npu_id parameter lacks range validation. Python binding function init_dyno(npu_id) accepts arbitrary integer without validating NPU device ID range. Invalid NPU IDs could cause resource access errors or unexpected behavior in IPC registration.

**漏洞代码** (`plugin/bindings.cpp:117`)

```c
m.def("init_dyno", [](int npu_id) -> bool { return dynolog_npu::ipc_monitor::PyDynamicMonitorProxy::GetInstance()->InitDyno(npu_id); }, py::arg("npu_id"));
```

**达成路径**

Python caller → bindings.cpp:init_dyno(npu_id) → PyDynamicMonitorProxy.h:InitDyno(npuId) → DynoLogNpuMonitor.h:SetNpuId(id) [line 38-41: npuId_ = id] → DynoLogNpuMonitor.cpp:RegisterInstance(npuId_) [line 42] → NpuIpcClient.cpp:RegisterInstance(int32_t npu) [line 27-46: direct use without validation]

**验证说明**: Data flow confirmed: Python -> bindings.cpp -> PyDynamicMonitorProxy -> DynoLogNpuMonitor -> NpuIpcClient.RegisterInstance. No bounds validation found anywhere in the chain. npu_id passed directly to IPC registration. Impact: Invalid NPU ID could cause IPC registration failure or unexpected behavior at daemon side. While no direct security exploit path found, the lack of validation is confirmed.

**深度分析**

#### 根因分析

从源代码追踪发现，`npu_id` 参数从 Python 绑定层到 IPC 发送层全程缺失验证：

**入口点** (`plugin/bindings.cpp:116-118`)：
```cpp
m.def("init_dyno", [](int npu_id) -> bool {
    // 漏洞: npu_id 直接传递，无范围检查
    return dynolog_npu::ipc_monitor::PyDynamicMonitorProxy::GetInstance()->InitDyno(npu_id);
}, py::arg("npu_id"));
```

**使用点** (`plugin/ipc_monitor/NpuIpcClient.cpp:27-46`)：
```cpp
bool IpcClient::RegisterInstance(int32_t npu)
{
    NpuContext context{
        .npu = npu,  // 无效 ID 直接写入 IPC 消息
        .pid = getpid(),
        .jobId = JOB_ID,
    };
    std::unique_ptr<Message> message = Message::ConstructMessage<decltype(context)>(context, MSG_TYPE_CONTEXT);
    // 发送到 dynolog daemon...
}
```

**根因**：开发者假设上层调用者会提供有效 ID，未在关键入口实施防御性验证。这违反了"信任边界验证"原则——外部输入（Python 层）不应被无条件信任。

#### 潜在利用场景

**场景 1 - 多租户干扰**：
恶意用户传入 `init_dyno(-1)` 或超大 ID，导致 dynolog daemon 的 NPU 注册表污染，干扰正常租户的设备分配。

**场景 2 - Jupyter/容器滥用**：
数据科学平台用户可通过简单 Python 脑本触发：
```python
import mindstudio_monitor
mindstudio_monitor.init_dyno(-2147483648)  # INT_MIN
```

**场景 3 - 服务异常触发**：
无效 NPU ID 可能导致 dynolog daemon 在处理 IPC 消息时访问不存在设备，触发异常或崩溃。

#### 建议修复方式

**推荐修复**：在 Python 绑定层添加范围验证（最小改动，最大防护）：

```cpp
// plugin/bindings.cpp:116-118 (修复后)
constexpr int MIN_NPU_ID = 0;
constexpr int MAX_NPU_ID = 7;  // 根据实际硬件配置

m.def("init_dyno", [](int npu_id) -> bool {
    if (npu_id < MIN_NPU_ID || npu_id > MAX_NPU_ID) {
        throw std::invalid_argument(
            "Invalid npu_id: " + std::to_string(npu_id) + 
            ". Valid range is [0, 7]");
    }
    return dynolog_npu::ipc_monitor::PyDynamicMonitorProxy::GetInstance()->InitDyno(npu_id);
}, py::arg("npu_id"));
```

详见修复建议章节。

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| bindings | 0 | 0 | 1 | 0 | 1 |
| dynolog_daemon | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **0** | **2** | **0** | **2** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-200 | 1 | 50.0% |
| CWE-20 | 1 | 50.0% |

---

## 修复建议

### 优先级 1: 立即修复 (Critical/High)

当前无 Critical 或 High 级别漏洞。

### 优先级 2: 短期修复 (Medium)

#### 修复建议 1: DF-008 RPC 信息泄露漏洞

**影响组件**: `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp`

**修复方案 A (推荐): 移除完整请求日志**

```cpp
// 将第 322 行改为仅记录请求长度
// 原代码: LOG(INFO) << "RPC message received = " << request_str;
LOG(INFO) << "RPC message received, length = " << request_str.size() << " bytes";
```

**修复方案 B: 敏感字段脱敏**

```cpp
// 添加脱敏函数（需包含 JSON 解析库）
std::string sanitize_request(const std::string& request) {
    try {
        auto json = nlohmann::json::parse(request);
        if (json.contains("config")) json["config"] = "[REDACTED]";
        if (json.contains("log_file")) json["log_file"] = "[REDACTED]";
        if (json.contains("pids")) json["pids"] = "[REDACTED]";
        return json.dump();
    } catch (...) {
        return "[parse error - content redacted]";
    }
}
LOG(INFO) << "RPC message received = " << sanitize_request(request_str);
```

**验证步骤**:
1. 发送包含敏感字段的 RPC 请求
2. 检查日志文件 `/tmp/dynolog.INFO`，确认不泄露完整请求
3. 验证 RPC 功能正常（如 `dyno status` 响应正确）

---

#### 修复建议 2: VULN-SEC-BIND-001 NPU ID 输入验证缺失

**影响组件**: `plugin/bindings.cpp`, `plugin/ipc_monitor/*.cpp`

**修复方案 A (推荐): Python 绑定层验证**

在 `plugin/bindings.cpp:116-118` 添加范围检查：

```cpp
// 定义有效 NPU ID 范围（根据实际硬件配置）
constexpr int MIN_NPU_ID = 0;
constexpr int MAX_NPU_ID = 7;  // 假设最多 8 个 NPU 设备

m.def("init_dyno", [](int npu_id) -> bool {
    if (npu_id < MIN_NPU_ID || npu_id > MAX_NPU_ID) {
        throw std::invalid_argument(
            "Invalid npu_id: " + std::to_string(npu_id) + 
            ". Valid range is [" + std::to_string(MIN_NPU_ID) + 
            ", " + std::to_string(MAX_NPU_ID) + "]");
    }
    return dynolog_npu::ipc_monitor::PyDynamicMonitorProxy::GetInstance()->InitDyno(npu_id);
}, py::arg("npu_id"));
```

**修复方案 B: 多层防御**

同时在 C++ 层 (`PyDynamicMonitorProxy.h`) 和存储层 (`DynoLogNpuMonitor.h`) 添加验证，实现防御深度原则。

**验证步骤**:
1. 测试边界值：`init_dyno(0)` 和 `init_dyno(7)` 应成功
2. 测试无效值：`init_dyno(-1)` 和 `init_dyno(100)` 应抛出异常
3. 验证 IPC 消息仅包含有效 NPU ID

---

### 优先级 3: 计划修复 (Low)

当前无 Low 级别漏洞。

---

### 综合加固建议

| 类别 | 建议 |
|------|------|
| **日志安全审计** | 全面审计项目中的 `LOG(INFO)` 语句，移除或脱敏记录外部输入的日志点 |
| **输入验证规范** | 制定 API 边界验证规范，要求所有外部入口参数必须有范围检查 |
| **信任边界定义** | 明确 Python 绑定层为"不可信边界"，所有来自 Python 的参数需验证后才能进入 C++ 层 |
| **单元测试覆盖** | 为新增验证逻辑添加边界测试用例（负数、INT_MAX、INT_MIN） |
| **文档更新** | 更新 API 文档，明确 `npu_id` 有效范围，说明异常抛出行为 |

---

**报告生成**: report-generator + reporter-agent  
**生成时间**: 2026-04-20
