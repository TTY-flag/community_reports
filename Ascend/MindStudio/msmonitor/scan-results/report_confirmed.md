# 漏洞扫描报告 — 已确认漏洞

**项目**: msmonitor
**扫描时间**: 2026-04-20T10:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描对 msmonitor 项目进行了全面的漏洞分析，该项目是一个运行于 Linux 服务器上的 NPU 监控守护进程，通过 RPC 端口 1778 接受远程 dyno CLI 客户端连接，并通过 Unix Domain Socket 与本地 MSPTI 插件进程通信。

### 关键发现

扫描共发现 **10 个候选漏洞**，经验证后确认 **1 个高危漏洞**（CONFIRMED），另有 4 个中等可能性漏洞（LIKELY）和 2 个低可能性漏洞（POSSIBLE）待进一步评估。

### 最严重漏洞

**[DF-001] RPC 请求信息泄露 (CWE-532, High)** — 这是本次扫描发现的最严重漏洞。dynolog RPC 服务在处理客户端请求时，将完整的 JSON 消息内容记录到 INFO 级别日志中。由于 RPC 端口 1778 接受远程连接（信任等级为 `untrusted_network`），攻击者可通过发送包含敏感配置数据（如 PID 列表、监控参数、设备配置等）的 RPC 请求，诱导服务将这些敏感信息写入日志文件。日志文件可能被其他用户或进程读取，导致敏感信息泄露。

### 风险评估

| 风险维度 | 评估 |
|---------|------|
| **攻击复杂度** | 低 — 攻击者仅需发送正常 RPC 请求即可触发漏洞 |
| **攻击者要求** | 网络访问 — 需能连接到 RPC 端口 1778 |
| **影响范围** | 信息泄露 — 敏感配置数据可能被日志文件持久化 |
| **严重性** | High — 直接违反安全日志最佳实践 |

### 建议优先级

1. **立即修复**: DF-001（RPC 信息泄露）— 移除敏感数据日志记录或实施日志脱敏
2. **高优先级**: SEC-004（TLS 版本限制）— 强制 TLS 1.2+ 以防止协议降级攻击
3. **中优先级**: DF-002/DF-003/DF-004（IPC/RPC 日志泄露）— 对 IPC 消息日志实施脱敏处理
4. **低优先级**: DF-006/SEC-003（环境变量/路径验证）— 加强输入验证（已有部分防护）

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 4 | 40.0% |
| FALSE_POSITIVE | 3 | 30.0% |
| POSSIBLE | 2 | 20.0% |
| CONFIRMED | 1 | 10.0% |
| **总计** | **10** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 1 | 100.0% |
| **有效漏洞总计** | **1** | - |
| 误报 (FALSE_POSITIVE) | 3 | - |

### 1.3 Top 10 关键漏洞

1. **[DF-001]** Information Exposure Through Log Files (High) - `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:322` @ `processOne` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `initSocket@dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp` | network | untrusted_network | 监听TCP端口1778，接受远程dyno CLI客户端连接，使用TLS证书可选认证 | RPC服务端口初始化 |
| `accept@dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp` | network | untrusted_network | accept()接受远程客户端连接请求，解析IPv6地址 | 接受RPC客户端连接 |
| `get_message@dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp` | network | untrusted_network | 从RPC连接读取JSON消息，消息长度由客户端控制，最大8KB | 读取RPC请求消息 |
| `loop@dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp` | rpc | untrusted_local | Unix Domain Socket监听，接受本地MSPTI插件进程的IPC消息 | IPC消息循环 |
| `processMsg@dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp` | rpc | untrusted_local | 处理IPC消息，解析消息类型和内容，可能包含恶意数据 | 处理IPC消息 |
| `processDataMsg@dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp` | rpc | untrusted_local | 解析JSON数据消息，使用nlohmann::json解析，可能触发解析漏洞 | 处理IPC数据消息 |
| `readConfigFromConfigFile@dynolog_npu/dynolog/src/LibkinetoConfigManager.cpp` | file | trusted_admin | 读取/etc/libkineto.conf配置文件，由管理员控制 | 读取配置文件 |
| `NpuIpcEndPoint@plugin/ipc_monitor/NpuIpcEndPoint.h` | rpc | untrusted_local | Unix Domain Socket客户端端点，发送消息到dynolog守护进程 | IPC客户端端点 |
| `DynoLogGetOpts@plugin/ipc_monitor/InputParser.cpp` | rpc | untrusted_local | 解析来自dynolog守护进程的配置字符串，可能包含恶意数据 | 解析IPC配置 |
| `Run@plugin/ipc_monitor/mspti_monitor/MsptiMonitor.cpp` | rpc | semi_trusted | MSPTI回调函数入口，处理来自设备的活动数据 | MSPTI监控线程 |
| `BufferComplete@plugin/ipc_monitor/mspti_monitor/MsptiMonitor.cpp` | rpc | semi_trusted | MSPTI缓冲区完成回调，处理原始活动记录数据 | MSPTI缓冲区回调 |
| `PYBIND11_MODULE@plugin/bindings.cpp` | decorator | trusted_admin | Python绑定入口，通过pip安装后由用户代码调用 | Python模块绑定 |
| `init_dyno@plugin/IPCMonitor/dynamic_monitor_proxy.py` | decorator | trusted_admin | Python代理类初始化函数，调用C++模块 | Python初始化代理 |

**其他攻击面**:
- RPC TCP端口1778 (IPv6)
- Unix Domain Socket IPC通信
- JSON消息解析 (RPC和IPC)
- MSPTI活动数据缓冲区
- SQLite数据库文件写入
- JSONL日志文件写入
- 配置文件/etc/libkineto.conf读取
- TLS证书验证

---

## 3. High 漏洞 (1)

### [DF-001] Information Exposure Through Log Files - processOne

**严重性**: High | **CWE**: CWE-532 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:322` @ `processOne`
**模块**: dynolog_daemon

#### 漏洞描述

RPC请求消息内容被完整记录到INFO级别日志中，可能泄露敏感配置信息。远程攻击者通过发送包含敏感数据的请求，可能导致敏感信息（如配置字符串、PID列表等）被记录到日志文件。

#### 深度分析

**漏洞触发路径**:

```
远程客户端 → TCP端口1778 → SSL_accept() → get_message() → request_str → LOG(INFO)
```

**代码上下文分析**:

在 `SimpleJsonServer.cpp` 中，`processOne()` 函数处理每个 RPC 请求：

```cpp
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

`get_message()` 函数从 SSL 连接读取最大 8KB 的 JSON 消息：

```cpp
std::string get_message()
{
    int32_t msg_size = -1;
    if (!read_helper((uint8_t*)&msg_size, sizeof(msg_size)) || 
        msg_size <= 0 || msg_size >= MAX_MESSAGE_LEN) {
        LOG(ERROR) << "Invalid message size = " << msg_size;
        return "";
    }
    std::string message;
    message.resize(msg_size);
    // 读取消息内容...
    return message;
}
```

**攻击场景**:

1. **配置信息泄露**: dyno CLI 客户端发送包含监控配置（如 NPU 设备 ID、监控阈值、采样频率）的 RPC 请求，这些敏感配置被完整写入日志文件。

2. **进程信息泄露**: 请求中可能包含目标进程 PID 列表，攻击者可通过构造包含其他用户进程 PID 的请求，诱导服务记录其他用户的进程信息。

3. **日志持久化风险**: INFO 级别日志通常被持久化到文件（如 `/var/log/msmonitor.log`），可能被其他用户或系统组件读取。

**缓解措施缺失分析**:

- ❌ 无敏感数据过滤机制
- ❌ 无日志脱敏处理
- ❌ INFO 级别日志未区分敏感/非敏感内容
- ❌ 消息内容直接拼接输出，未进行安全审查

**漏洞代码** (`dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:322`)

```c
LOG(INFO) << "RPC message received = " << request_str;
```

**达成路径**

get_message() [line 199] → request_str [line 321] → LOG(INFO) [line 322]

**验证说明**: LOG(INFO)完整记录RPC请求内容(line322)。远程攻击者通过RPC端口1778发送包含敏感数据的请求，可能导致配置信息泄露到日志文件

**评分明细**: base: 30 | context: 0 | controllability: 25 | cross_file: 0 | mitigations: 0 | reachability: 30

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| dynolog_daemon | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **1** | **0** | **0** | **1** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-532 | 1 | 100.0% |

---

## 6. 修复建议

### 6.1 [DF-001] RPC 信息泄露 — 修复方案

**优先级**: 立即修复

**修复策略**:

1. **移除敏感数据日志** — 最安全的方案是完全移除 RPC 消息内容的日志记录：

```cpp
// 修复后代码
void SimpleJsonServerBase::processOne() noexcept
{
    LOG(INFO) << "Waiting for connection.";
    ClientSocketWrapper client;
    if (!client.accept(sock_fd_, ctx_)) {
        return;
    }
    std::string request_str = client.get_message();
    // 移除: LOG(INFO) << "RPC message received = " << request_str;
    LOG(INFO) << "RPC message received (size: " << request_str.size() << " bytes)";
    auto response_str = processOneImpl(request_str);
    ...
}
```

2. **日志脱敏** — 如果需要记录请求内容用于调试，实施字段级脱敏：

```cpp
// 脱敏方案示例
std::string sanitizeRpcMessage(const std::string& msg) {
    try {
        auto j = nlohmann::json::parse(msg);
        // 对敏感字段进行脱敏
        if (j.contains("pid_list")) {
            j["pid_list"] = "[REDACTED]";
        }
        if (j.contains("config")) {
            j["config"] = "[REDACTED]";
        }
        return j.dump();
    } catch (...) {
        return "[UNPARSEABLE - REDACTED]";
    }
}

LOG(DEBUG) << "RPC message sanitized = " << sanitizeRpcMessage(request_str);
```

3. **降低日志级别** — 将完整消息日志降级为 DEBUG，仅在调试时启用：

```cpp
LOG(DEBUG) << "RPC message received = " << request_str;
```

**验证步骤**:
- [ ] 移除或脱敏 INFO 级别的完整消息日志
- [ ] 确保 DEBUG 日志在生产环境默认禁用
- [ ] 检查其他日志点是否存在类似问题（DF-002、DF-003、DF-004）
- [ ] 验证日志文件权限配置正确（仅限管理员读取）

### 6.2 日志安全最佳实践

为防止类似问题，建议在整个项目中实施以下日志安全规范：

1. **敏感数据禁止写入日志**:
   - PID 列表、设备 ID、配置参数
   - 用户凭证、密钥、证书内容
   - 未脱敏的 JSON 消息内容

2. **日志分级**:
   - INFO: 仅记录操作摘要（如 "RPC request received"）
   - DEBUG: 可包含详细内容，但生产环境禁用
   - ERROR: 异常信息，避免包含原始输入

3. **日志文件权限**:
   - 设置 `chmod 600 /var/log/msmonitor.log`
   - 确保仅 root 或 msmonitor 用户可读取

---

**报告生成**: 由 Reporter Agent 自动生成并人工补充
**验证状态**: 所有漏洞已通过 DataFlow Scanner 和 Security Auditor 双重验证