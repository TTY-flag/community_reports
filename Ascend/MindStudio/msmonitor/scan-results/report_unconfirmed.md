# 漏洞扫描报告 — 待确认漏洞

**项目**: msmonitor
**扫描时间**: 2026-04-20T10:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本报告包含经扫描发现但尚未完全确认的漏洞，需要进一步人工评估或补充测试验证。这些漏洞基于代码分析和数据流追踪发现，具有较高的潜在风险，建议优先审查。

### 漏洞概况

| 状态 | 数量 | 说明 |
|------|------|------|
| LIKELY | 4 | 高置信度漏洞，建议优先修复 |
| POSSIBLE | 2 | 待验证漏洞，需进一步测试确认 |

### 主要风险类别

1. **日志信息泄露 (CWE-532)** — 3 个 LIKELY 漏洞，IPC/RPC 消息在解析失败或处理时被完整记录到日志
2. **TLS 配置缺陷 (CWE-326)** — 1 个 LIKELY 漏洞，未强制最低 TLS 版本限制
3. **输入验证不足 (CWE-22/CWE-15)** — 2 个 POSSIBLE 漏洞，路径/环境变量验证存在改进空间

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
| Medium | 4 | 66.7% |
| Low | 2 | 33.3% |
| **有效漏洞总计** | **6** | - |
| 误报 (FALSE_POSITIVE) | 3 | - |

### 1.3 Top 10 关键漏洞

1. **[SEC-004]** Weak TLS Protocol (Medium) - `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:351` @ `create_context` | 置信度: 75
2. **[DF-002]** Information Exposure Through Log Files (Medium) - `dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp:162` @ `processDataMsg` | 置信度: 75
3. **[DF-003]** Information Exposure Through Log Files (Medium) - `dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp:158` @ `processDataMsg` | 置信度: 75
4. **[DF-004]** Insertion of Sensitive Information Into Log File (Medium) - `dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h:67` @ `toJson` | 置信度: 75
5. **[DF-006]** Use of Potentially Dangerous Function (Low) - `plugin/ipc_monitor/utils/utils.cpp:560` @ `CreateMsmonitorLogPath` | 置信度: 50
6. **[SEC-003]** Path Traversal (Low) - `plugin/ipc_monitor/InputParser.cpp:83` @ `isValidPath` | 置信度: 45

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

## 3. Medium 漏洞 (4)

### [SEC-004] Weak TLS Protocol - create_context

**严重性**: Medium | **CWE**: CWE-326 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:351-360` @ `create_context`
**模块**: dynolog_daemon

#### 深度分析

**漏洞描述**: 在 SimpleJsonServer.cpp 的 `create_context` 函数中，使用 `TLS_server_method()` 创建 SSL 上下文，但没有设置最低 TLS 版本限制。这意味着服务器可能接受 TLS 1.0 或 TLS 1.1 连接，这些版本已被认为不安全（存在 BEAST、POODLE 等攻击）。

**攻击场景**: 
- 攻击者连接 RPC 端口 1778，协商使用 TLS 1.0/1.1
- 利用 BEAST、POODLE 等已知攻击解密通信内容
- 可能获取 RPC 消息中的配置信息

**风险评估**:
- 信任等级: `untrusted_network` — 远程客户端可连接
- 现有 TLS 证书认证可选，协议版本降级进一步削弱安全性
- OpenSSL 默认行为可能允许 TLS 1.0/1.1（取决于系统配置）

**漏洞代码** (`dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp:351-360`)

```c
SSL_CTX* SimpleJsonServerBase::create_context()
{
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Unable to create SSL context");
    }
    return ctx;
}
```

**达成路径**

TLS_server_method() → SSL_CTX_new → SSL连接(无最低版本限制)

**验证说明**: create_context使用TLS_server_method()未设置SSL_CTX_set_min_proto_version，可能接受TLS1.0/1.1连接。RPC端口1778接受远程连接，攻击者可协商弱TLS版本

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 30

---

### [DF-002] Information Exposure Through Log Files - processDataMsg

**严重性**: Medium | **CWE**: CWE-532 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp:162` @ `processDataMsg`
**模块**: dynolog_daemon

#### 深度分析

**漏洞描述**: IPC 数据消息（JSON 格式）被完整记录到 INFO 级别日志中，可能泄露监控数据内容。本地 IPC 客户端发送的数据可能包含敏感信息（如时间戳、设备 ID、操作名称等）。

**代码上下文**:

```cpp
// IPCMonitor.cpp processDataMsg
std::string message = std::string((char*)msg->buf.get(), msg->metadata.size);
try {
    if (!(nlohmann::json::accept(message) && CheckJsonDepth(message))) {
        LOG(ERROR) << "Error parsing message = " << message;
        return;
    }
    nlohmann::json result = nlohmann::json::parse(message);
    LOG(INFO) << "Received data message : " << result;  // ← 漏洞点
    LogData(result);
}
```

**攻击场景**:
- 本地进程通过 Unix Domain Socket 发送 IPC 数据消息
- 消息内容（可能包含 NPU 设备 ID、时间戳、监控数据）被完整写入日志
- 日志文件可能被其他本地用户读取

**缓解因素**: 信任等级为 `untrusted_local`，攻击者需有本地访问权限

**漏洞代码** (`dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp:162`)

```c
LOG(INFO) << "Received data message : " << result;
```

**达成路径**

parse(message) [line 161] → result [line 161] → LOG(INFO) [line 162]

**验证说明**: LOG(INFO)记录完整IPC数据消息JSON(line162)。本地IPC客户端发送的数据可能包含时间戳、设备ID等敏感信息

**评分明细**: base: 30 | context: 0 | controllability: 25 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [DF-003] Information Exposure Through Log Files - processDataMsg

**严重性**: Medium | **CWE**: CWE-532 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp:158-165` @ `processDataMsg`
**模块**: ipc_monitor_plugin

#### 深度分析

**漏洞描述**: IPC 消息解析失败时，原始消息内容被记录到 ERROR 日志中。如果消息包含敏感数据，可能在错误处理时泄露。

**攻击场景**:
- 攻击者构造恶意 JSON 消息触发解析错误
- 服务将原始恶意消息内容写入 ERROR 日志
- 如果消息中包含敏感数据片段，可能泄露

**漏洞代码** (`dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp:158-165`)

```c
LOG(ERROR) << "Error parsing message = " << message;
```

**达成路径**

msg->buf.get() [line 155] → message [line 155] → LOG(ERROR) [line 158/165]

**验证说明**: LOG(ERROR)在解析失败时记录原始IPC消息内容(line158/165)。攻击者可构造恶意JSON触发解析错误，导致消息内容泄露

**评分明细**: base: 30 | context: 0 | controllability: 25 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [DF-004] Insertion of Sensitive Information Into Log File - toJson

**严重性**: Medium | **CWE**: CWE-532 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h:67-73` @ `toJson`
**模块**: ipc_monitor_plugin

#### 深度分析

**漏洞描述**: RPC 消息解析失败时，原始消息内容被记录到 ERROR 日志中，可能泄露敏感请求内容。

**与 DF-001 的关联**: 此漏洞是 DF-001 的变体，发生在 RPC 消息解析错误处理路径中。虽然错误日志通常用于调试，但可能被攻击者利用触发敏感信息泄露。

**漏洞代码** (`dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h:67-73`)

```c
LOG(ERROR) << "Error parsing message = " << message;
```

**达成路径**

request_str [line 58] → message → LOG(ERROR) [line 67/73]

**验证说明**: LOG(ERROR)在RPC消息解析失败时记录原始消息内容(line67/73)。攻击者可构造恶意JSON触发解析错误，导致敏感请求泄露

**评分明细**: base: 30 | context: 0 | controllability: 25 | cross_file: 0 | mitigations: 0 | reachability: 20

---

## 4. Low 漏洞 (2)

### [DF-006] Use of Potentially Dangerous Function - CreateMsmonitorLogPath

**严重性**: Low | **CWE**: CWE-15 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `plugin/ipc_monitor/utils/utils.cpp:560-575` @ `CreateMsmonitorLogPath`
**模块**: ipc_monitor_plugin

#### 深度分析

**漏洞描述**: 环境变量 MSMONITOR_LOG_PATH 直接用于设置日志文件路径。环境变量可被攻击者控制，虽然后续有 DirPathCheck 验证，但仍建议对环境变量值进行更严格的白名单验证。

**缓解措施**: 
- ✅ 后续调用 `PathUtils::DirPathCheck()` 进行路径验证
- ✅ 验证包括：长度检查、软链接检查、目录权限检查
- ⚠️ 建议增加白名单路径验证

**风险评估**: 置信度较低（50），因为有防护措施存在

**漏洞代码** (`plugin/ipc_monitor/utils/utils.cpp:560-575`)

```c
const char* logPathEnvVal = getenv("MSMONITOR_LOG_PATH");\n    ...\n    logPath = logPath + "/msmonitor_log";
```

**达成路径**

getenv("MSMONITOR_LOG_PATH") [line 560] → logPath [line 563] → PathUtils::DirPathCheck() [line 577]

**验证说明**: getenv获取MSMONITOR_LOG_PATH环境变量，后续CreateMsmonitorLogPath调用DirPathCheck验证。环境变量由本地用户设置，有防护但值得关注

**评分明细**: base: 30 | context: 5 | controllability: 15 | cross_file: 0 | mitigations: -20 | reachability: 20

---

### [SEC-003] Path Traversal - isValidPath

**严重性**: Low | **CWE**: CWE-22 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `plugin/ipc_monitor/InputParser.cpp:83-86` @ `isValidPath`
**模块**: ipc_monitor_plugin

#### 深度分析

**漏洞描述**: 在 InputParser.cpp 中，`isValidPath` 函数仅检查路径长度是否超过 PATH_MAX（4096），未检查路径是否包含路径遍历字符（如 '..'）。这允许攻击者通过 IPC 配置传递包含 '../' 的路径，可能访问预期之外的文件或目录。

**缓解措施**: 
- ⚠️ 第一层验证仅检查长度，过于宽松
- ✅ 后续 `MsptiMonitor.CheckAndSetSavePath` 调用 `DirPathCheck` 进行完整验证
- ✅ 完整验证包括：长度、软链接、目录权限

**风险评估**: 置信度较低（45），因为有第二层防护存在

**漏洞代码** (`plugin/ipc_monitor/InputParser.cpp:83-86`)

```c
bool isValidPath(const std::string& s)
{
    return s.length() <= PATH_MAX;
}
```

**达成路径**

NPU_MONITOR_SAVE_PATH配置项 → isValidPath验证(仅长度) → 保存路径使用

**验证说明**: isValidPath仅检查长度，但后续MsptiMonitor.CheckAndSetSavePath调用DirPathCheck进行完整验证(长度、软链接、目录权限)。第一层验证过于宽松但非直接漏洞

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: -20 | reachability: 20

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| dynolog_daemon | 0 | 0 | 2 | 0 | 2 |
| ipc_monitor_plugin | 0 | 0 | 2 | 2 | 4 |
| **合计** | **0** | **0** | **4** | **2** | **6** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-532 | 3 | 50.0% |
| CWE-326 | 1 | 16.7% |
| CWE-22 | 1 | 16.7% |
| CWE-15 | 1 | 16.7% |

---

## 7. 修复建议

### 7.1 高优先级修复 (LIKELY 漏洞)

#### [SEC-004] TLS 版本限制

**修复方案**:

```cpp
SSL_CTX* SimpleJsonServerBase::create_context()
{
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Unable to create SSL context");
    }
    
    // 强制 TLS 1.2 或更高版本
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
        SSL_CTX_free(ctx);
        throw std::runtime_error("Failed to set minimum TLS version");
    }
    
    // 可选：禁用弱加密套件
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5:!RC4");
    
    return ctx;
}
```

**验证步骤**:
- [ ] 使用 `openssl s_client -connect localhost:1778 -tls1_1` 测试，应拒绝连接
- [ ] 确认仅接受 TLS 1.2+ 连接

#### [DF-002/DF-003/DF-004] IPC/RPC 日志脱敏

**修复方案**:

1. 移除 INFO 级别完整消息日志，改为摘要信息：
```cpp
LOG(INFO) << "Received IPC data message (type: " << msg_type << ", size: " << msg_size << ")";
```

2. ERROR 日志仅记录错误类型，不记录原始消息：
```cpp
LOG(ERROR) << "Error parsing IPC message: JSON validation failed";
```

3. 如需调试，使用 DEBUG 级别并脱敏：
```cpp
LOG(DEBUG) << "IPC message sanitized: " << sanitizeForLog(message);
```

### 7.2 中优先级修复 (POSSIBLE 漏洞)

#### [SEC-003] 加强路径验证

**修复方案**: 增强 `isValidPath` 函数：

```cpp
bool isValidPath(const std::string& s)
{
    if (s.length() > PATH_MAX || s.empty()) {
        return false;
    }
    
    // 检查路径遍历
    if (s.find("..") != std::string::npos) {
        return false;
    }
    
    // 检查绝对路径（仅允许安全目录）
    // 可选：白名单检查
    
    return true;
}
```

#### [DF-006] 环境变量白名单

**修复方案**: 增加环境变量值验证：

```cpp
std::string CreateMsmonitorLogPath()
{
    const char* logPathEnvVal = getenv("MSMONITOR_LOG_PATH");
    std::string logPath;
    
    if (logPathEnvVal && strlen(logPathEnvVal) > 0) {
        logPath = logPathEnvVal;
        
        // 白名单检查：仅允许安全目录
        if (!isAllowedLogPath(logPath)) {
            LOG(WARNING) << "Invalid MSMONITOR_LOG_PATH, using default";
            logPath = "/var/log";
        }
    } else {
        logPath = "/var/log";
    }
    
    logPath = logPath + "/msmonitor_log";
    
    // 后续 DirPathCheck 验证...
    return logPath;
}
```

---

## 8. 待确认事项

以下漏洞需要进一步人工验证：

| ID | 问题 | 验证建议 |
|-----|------|---------|
| SEC-004 | OpenSSL 系统配置是否默认禁用 TLS 1.0/1.1 | 使用 `openssl s_client` 测试实际协商版本 |
| SEC-003 | `DirPathCheck` 是否完整覆盖路径遍历检查 | 审阅 `PathUtils::DirPathCheck` 实现 |
| DF-006 | 环境变量是否可被非 root 用户设置 | 检查部署环境权限配置 |

---

**报告生成**: 由 Reporter Agent 自动生成并人工补充
**验证状态**: LIKELY 漏洞建议优先修复，POSSIBLE 漏洞需进一步确认