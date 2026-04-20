# 漏洞扫描报告 — 已确认漏洞

**项目**: MindIE-LLM
**扫描时间**: 2025-04-17T00:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## Executive Summary

MindIE-LLM 是一个大型语言模型推理服务框架，本次安全扫描覆盖了项目的核心模块，包括守护进程管理、HTTP/gRPC 接口、推理实例管理、IPC 通信以及配置管理等关键组件。扫描发现了 **25 个已确认的安全漏洞**，其中 **8 个高危漏洞** 需要立即修复。

### 关键发现

| 漏洞类别 | 数量 | 严重性 | 核心风险 |
|---------|------|--------|---------|
| Signal Handler Safety (CWE-479) | 3 | High | 进程死锁、崩溃风险 |
| Array Index Validation (CWE-129/125) | 8 | High | 内存越界读取、信息泄露 |
| Path Traversal (CWE-22) | 1 | High | 任意文件读取/加载 |
| Integer Overflow (CWE-190) | 7 | High/Medium | 内存耗尽、逻辑错误 |
| Memory Exhaustion (CWE-789) | 1 | High | 服务拒绝攻击 |
| Division by Zero (CWE-369) | 1 | High | 服务崩溃 |

### 风险评估结论

**整体风险等级**: **HIGH**

MindIE-LLM 作为网络服务部署，暴露了多个 HTTP REST API 和 gRPC 接口供外部客户端调用。扫描结果表明：

1. **守护进程模块存在严重的信号处理安全隐患**，违反 POSIX 信号安全规范，可能导致服务进程在异常终止时发生死锁或崩溃后无法正常清理资源。

2. **推理接口模块缺乏输入验证**，用户可通过 HTTP API 控制数组索引大小，触发越界读取，可能导致敏感内存内容泄露。

3. **LoRA 适配器加载接口存在路径遍历漏洞**，攻击者可尝试加载任意路径的模型文件。

4. **IPC 通信模块未对共享内存消息大小进行验证**，本地攻击者可利用此缺陷读取相邻内存区域。

### 建议优先处理的漏洞

按风险优先级排序，建议立即修复以下漏洞：

| 优先级 | 漏洞 ID | 类型 | 原因 |
|-------|---------|------|------|
| P0 | DAEMON-001, DAEMON-002 | Signal Handler Safety | 置信度 100，直接违反 POSIX 规范，可能导致死锁 |
| P0 | SEC-INFER-004 | Array Index OOB | 用户可控数组索引，直接越界读取 |
| P1 | IPC-001 | Buffer Overread | IPC 共享内存边界未验证 |
| P1 | CVE-MINDIE-001 | Path Traversal | HTTP API 路径验证不充分 |
| P1 | VULN-RH-008 | Division by Zero | 推理服务崩溃风险 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 25 | 28.1% |
| POSSIBLE | 23 | 25.8% |
| FALSE_POSITIVE | 21 | 23.6% |
| LIKELY | 20 | 22.5% |
| **总计** | **89** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 8 | 32.0% |
| Medium | 3 | 12.0% |
| **有效漏洞总计** | **25** | - |
| 误报 (FALSE_POSITIVE) | 21 | - |

### 1.3 Top 10 关键漏洞

1. **[DAEMON-001]** Signal Handler Safety Issue (High) - `src/server/daemon/llm_daemon.cpp:196` @ `SignalInterruptHandler` | 置信度: 100
2. **[DAEMON-002]** Signal Handler Safety Issue (High) - `src/server/daemon/llm_daemon.cpp:223` @ `SignalChldHandler` | 置信度: 100
3. **[DAEMON-003]** Race Condition in Signal Handling (High) - `src/server/daemon/llm_daemon.cpp:196` @ `SignalInterruptHandler,SignalChldHandler` | 置信度: 95
4. **[SEC-INFER-004]** Improper Validation of Array Index with User-Controlled Size (High) - `src/server/endpoint/single_req_infer_interface/single_req_triton_token_infer_interface.cpp:417` @ `BuildReComputeInput` | 置信度: 85
5. **[VULN-GRPC-001]** Memory Exhaustion (High) - `src/server/endpoint/grpc_wrapper/grpc_handler.cpp:85` @ `HandleDecodeRequest` | 置信度: 85
6. **[DFLOW-001]** Improper Input Validation (High) - `src/executor/grpc_communicator.cpp:627` @ `MasterServiceImpl::RegisterAndCommunicate` | 置信度: 85
7. **[CVE-MINDIE-001]** Path Traversal (High) - `src/server/endpoint/http_wrapper/http_handler.cpp:1069` @ `HandleLoadLoraAdapter` | 置信度: 80
8. **[SEC-INFER-001]** Integer Overflow/Wraparound (High) - `src/server/endpoint/single_req_infer_interface/single_req_infer_interface_base.cpp:1045` @ `GetTokensFromInput` | 置信度: 70
9. **[VULN-INF-002]** Improper Exception Handling (Medium) - `src/server/infer_instances/infer_instances.cpp:634` @ `InferInstance::InitPDNode` | 置信度: 95
10. **[SEC-INFER-002]** Unsafe Enum Type Conversion (Medium) - `src/server/endpoint/single_req_infer_interface/parse_protocol.cpp:206` @ `GetFaultRecoveryCmdType` | 置信度: 65

---

## Top 5 关键漏洞深度分析

以下对已确认的 5 个最高风险漏洞进行深度分析，包括漏洞成因、攻击路径、影响评估和修复优先级。

### 1. DAEMON-001/002: Signal Handler Safety Issue (CWE-479)

**漏洞概述**

守护进程 `llm_daemon.cpp` 中的两个信号处理函数 `SignalInterruptHandler` 和 `SignalChldHandler` 违反 POSIX 信号安全规范，在异步信号上下文中调用了多个非信号安全函数。

**源代码分析**

```cpp
// llm_daemon.cpp:196-221
void SignalInterruptHandler(int sig)
{
    if (g_isKillingAll) { return; }
    
    // 问题 1: ULOG_* 使用 std::ostringstream 和 spdlog (heap allocation + mutex)
    ULOG_WARN(SUBMODLE_NAME_DAEMON, "Received exit signal[" << sig << "]");
    
    // 问题 2: std::unique_lock 在信号上下文中获取互斥锁
    {
        std::unique_lock<std::mutex> lock(g_exitMtx);  // DEADLOCK PRONE
        g_processExit = true;
    }
    
    // 问题 3: condition_variable 操作使用内部互斥锁
    g_exitCv.notify_all();  // UNSAFE
    
    // 问题 4: sleep_for 不是异步信号安全函数
    std::this_thread::sleep_for(std::chrono::milliseconds(EP_STOP_WAIT_TIME));
    
    KillProcessGroup();  // Contains more unsafe operations
}
```

**攻击场景**

当进程正在执行以下操作时收到信号：
1. 另一个线程正在持有 `g_exitMtx` 互斥锁
2. ULOG 正在进行内存分配（`std::ostringstream` 构造）
3. spdlog 正在写入日志文件（持有内部锁）

此时信号处理函数尝试获取同一个锁或分配内存，将导致**死锁**或**内存损坏**。

**影响评估**

- **服务可用性**: 进程无法正常终止，僵尸进程堆积
- **资源清理**: 子进程未被正确收割，资源泄露
- **调试难度**: 死锁后无法获取有效日志，难以排查问题

**修复方案**

采用 **self-pipe technique** 或 **signalfd**：
1. 在信号处理函数中仅设置 `volatile sig_atomic_t` 标志
2. 创建专用线程轮询标志或使用 `signalfd` 监听信号
3. 在专用线程中执行所有非信号安全操作

---

### 2. SEC-INFER-004: Improper Validation of Array Index (CWE-129)

**漏洞概述**

推理接口 `BuildReComputeInput` 函数使用用户控制的 `oriReqTokenLen_` 值作为数组循环边界，未验证其是否小于 `reqTokens_` 数组实际大小。

**源代码分析**

```cpp
// single_req_triton_token_infer_interface.cpp:415-420
void BuildReComputeInput(std::vector<int64_t> &inputTokens)
{
    inputTokens.push_back(oriReqTokenLen_);
    // 漏洞: oriReqTokenLen_ 来自用户输入，未检查是否 <= reqTokens_.size()
    for (size_t i = 0; i < oriReqTokenLen_; i++) {
        inputTokens.push_back(reqTokens_[i]);  // OOB READ if i >= reqTokens_.size()
    }
    ...
}

// single_req_infer_interface_base.cpp:1045 - oriReqTokenLen_ 的来源
oriReqTokenLen_ = static_cast<uint64_t>(std::stoll(token));  // 来自 HTTP JSON 输入
```

**数据流分析**

```
HTTP Request Body
    ↓ JSON parse
inputParam->textInput (comma-separated string)
    ↓ GetTokensFromInput()
inputsData[0] → std::stoll() → oriReqTokenLen_ (uint64_t)
    ↓ BuildReComputeInput()
for (i < oriReqTokenLen_) { reqTokens_[i] }  ← NO bounds check
```

**攻击场景**

攻击者构造恶意推理请求：
```json
{
  "text_input": "999999999,1,2,3"  // 前两个 token 数量设为极大值
}
```

当 `isReCompute_ = true` 时，`oriReqTokenLen_` 被设为第一个逗号分隔值。如果此值大于 `reqTokens_` 实际大小，循环将读取 `reqTokens_` 之外的内存内容。

**影响评估**

- **信息泄露**: 读取相邻内存区域，可能泄露敏感数据（如其他请求的 token、密钥）
- **服务崩溃**: 访问无效内存地址导致 SIGSEGV
- **远程可触发**: 通过 HTTP REST API 直接触发，无需本地访问

**修复方案**

添加边界检查：
```cpp
void BuildReComputeInput(std::vector<int64_t> &inputTokens)
{
    // 添加边界验证
    if (oriReqTokenLen_ > reqTokens_.size()) {
        throw std::runtime_error("oriReqTokenLen_ exceeds reqTokens_ size");
    }
    inputTokens.push_back(oriReqTokenLen_);
    for (size_t i = 0; i < oriReqTokenLen_; i++) {
        inputTokens.push_back(reqTokens_[i]);
    }
    ...
}
```

---

### 3. IPC-001: Buffer Overread in IPC Communication (CWE-125)

**漏洞概述**

IPC 通信模块 `ParseResponse` 函数直接从共享内存读取消息大小，未验证其是否超出共享内存缓冲区边界。

**源代码分析**

```cpp
// ipc_communicator.cpp:247-265
bool IPCCommunicator::ParseResponse(ExecuteResponse &executeResponse, char *sharedBuf) const
{
    // 问题: messageSize 直接从共享内存读取，无边界检查
    uint32_t messageSize = *reinterpret_cast<uint32_t *>(sharedBuf);
    
    // 如果 messageSize > 共享内存大小，ParseFromArray 将越界读取
    if (!executeResponse.ParseFromArray(sharedBuf + sizeof(uint32_t), messageSize)) {
        MINDIE_LLM_LOG_ERROR("Failed to deserialize buffer.");
        return false;
    }
    ...
}
```

**攻击场景**

假设共享内存缓冲区大小为 4KB：
1. 本地攻击者通过其他进程写入共享内存
2. 将 `messageSize` 字段设置为 0xFFFFFFFF
3. `ParseFromArray` 尝试读取 4GB 数据，超出共享内存边界
4. **越界读取**相邻进程或内核内存内容

**影响评估**

- **信任边界**: 共享内存属于 semi_trusted 区域，需防范本地攻击者
- **信息泄露**: 可读取共享内存之外的敏感数据
- **服务崩溃**: 访问无效地址导致 SIGSEGV

**修复方案**

添加共享内存大小参数，并在读取前验证：
```cpp
bool ParseResponse(ExecuteResponse &executeResponse, char *sharedBuf, size_t bufSize) const
{
    if (bufSize < sizeof(uint32_t)) {
        return false;
    }
    uint32_t messageSize = *reinterpret_cast<uint32_t *>(sharedBuf);
    
    // 添加边界检查
    if (messageSize > bufSize - sizeof(uint32_t)) {
        MINDIE_LLM_LOG_ERROR("Message size exceeds buffer boundary");
        return false;
    }
    ...
}
```

---

### 4. VULN-RH-008: Division by Zero in Metrics Calculation (CWE-369)

**漏洞概述**

请求处理模块 `MetricsCallback` 函数在计算平均解码时间时，使用 `outputLen` 作为除数但未检查零值。

**源代码分析**

```cpp
// single_llm_req_handler_base.cpp:317-342
void SingleLLMReqHandlerBase::MetricsCallback(const ResponseSPtr &response)
{
    // outputLen 来自 responseContents
    outputLen = response->responseContents.at(0).speculativeTokenNum;  // 可能为 0
    
    if (!metrics.isPrefill) {
        // 问题: outputLen 未检查是否为 0
        auto avgDecodeTime = (decodeTime + outputLen / 2) / outputLen;  // DIV BY ZERO
        for (size_t i = 0; i < outputLen; ++i) {
            metrics.decodeTime.push_back(avgDecodeTime);
        }
    }
}
```

**攻击场景**

在投机解码场景下：
1. 推理引擎返回 `speculativeTokenNum = 0`（推测失败）
2. `outputLen` 被设为 0
3. 计算 `(decodeTime + 0) / 0` 时触发 SIGFPE
4. **服务进程崩溃**

**影响评估**

- **服务可用性**: 推理服务崩溃，所有进行中的请求中断
- **触发条件**: 推测解码失败时自动触发，无需恶意输入
- **连锁反应**: 崩溃可能触发信号处理函数中的其他漏洞

**修复方案**

添加零值检查：
```cpp
outputLen = response->responseContents.at(0).speculativeTokenNum;
if (outputLen == 0) {
    // 处理特殊情况：无解码 token 时跳过时间计算
    metrics.decodeTime.push_back(decodeTime);
    return;
}
auto avgDecodeTime = (decodeTime + outputLen / 2) / outputLen;
```

---

### 5. CVE-MINDIE-001: Path Traversal in LoRA Adapter Loading (CWE-22)

**漏洞概述**

`/v1/load_lora_adapter` HTTP API 接受用户提供的 LoRA 适配器路径，现有正则验证存在缺陷，允许绝对路径且路径规范化不足。

**源代码分析**

```cpp
// http_handler.cpp:1069-1110
server.Post(R"(/v1/load_lora_adapter)", [...] {
    std::string loraPath = jsonObj.value("lora_path", "");
    
    // 问题 1: 正则允许绝对路径（以 '/' 开头）
    std::regex path_pattern(R"(^(\/(?:[\w\-\.]+\/)*[\w\-\.]*\/?)?$|^(?:[\w\-\.]+\/)*[\w\-\.]*\/?$)");
    
    // 问题 2: 仅检查字面量 ".."，无法防止 URL 编码或符号链接绕过
    if (!std::regex_match(loraPath, path_pattern) || loraPath.find("..") != std::string::npos) {
        // 验证失败
        return;
    }
    
    // 问题 3: 无路径规范化，无白名单验证
    Status status = GetInferInstance()->HandleLora(LoraOperation::LORA_LOAD, lora_params);
});
```

**验证缺陷分析**

当前验证存在以下弱点：
1. **允许绝对路径**: 正则 `^\/` 允许 `/etc/passwd` 等系统文件
2. **字面量 ".." 检查不足**: URL 编码 `%2e%2e` 或符号链接可绕过
3. **无规范化**: 无 `realpath()` 或 `canonicalize_file_name()` 调用
4. **无白名单**: 未限制 LoRA 文件应位于特定目录（如模型目录）

**攻击场景**

攻击者构造请求：
```json
{
  "lora_name": "malicious",
  "lora_path": "/etc/passwd",  // 正则允许，无 ".."
  "master_model": "target-model"
}
```

服务尝试加载 `/etc/passwd` 作为 LoRA 适配器，可能：
- 泄露敏感配置信息
- 加载恶意模型代码（若文件格式可被解析）

**影响评估**

- **信息泄露**: 读取任意文件内容
- **代码执行**: 若 LoRA 文件包含可执行代码
- **远程可触发**: HTTP API 公开暴露

**修复方案**

1. 禁止绝对路径，强制相对路径
2. 使用 `canonicalize_file_name()` 规范化路径
3. 验证规范化路径位于允许的目录白名单内
4. 使用 `SafePath::Check()` 进行完整路径安全检查

```cpp
// 修复示例
std::string loraPath = jsonObj.value("lora_path", "");
if (loraPath.empty() || loraPath[0] == '/') {
    return;  // 禁止绝对路径
}

// 规范化并验证
std::string modelDir = GetModelDirectory();
std::string fullPath = modelDir + "/" + loraPath;
char *canonicalPath = canonicalize_file_name(fullPath.c_str());
if (!canonicalPath || strncmp(canonicalPath, modelDir.c_str(), modelDir.size()) != 0) {
    free(canonicalPath);
    return;  // 路径不在允许目录内
}
free(canonicalPath);
```

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `HttpServer::HttpServerInit@src/server/endpoint/http_wrapper/http_server.cpp` | network | untrusted_network | HTTP server listens on configured IP/port, accepting requests from external clients via REST API endpoints | Initializes HTTP server listening for external client requests |
| `HttpHandler::InitializeServiceStatusResource@src/server/endpoint/http_wrapper/http_handler.cpp` | http | untrusted_network | HTTP GET endpoints for health checks and service management accessible from external clients | Registers HTTP GET handlers for health check and status endpoints |
| `HttpHandler::BusinessInitialize@src/server/endpoint/http_wrapper/http_handler.cpp` | http | untrusted_network | Business HTTP endpoints for inference requests (OpenAI, TGI, vLLM, Triton APIs) accessible from external clients | Registers HTTP POST handlers for inference API endpoints |
| `GrpcHandler::InitGrpcService@src/server/endpoint/grpc_wrapper/grpc_handler.cpp` | rpc | semi_trusted | gRPC server for inter-node communication in PD disaggregation mode, accessible from prefill nodes | Initializes gRPC service for decode request handling |
| `GRPCCommunicator::InitMaster@src/executor/grpc_communicator.cpp` | network | semi_trusted | Master node gRPC server for multi-node inference, accepts connections from slave nodes | Initializes gRPC server for master-slave coordination |
| `GRPCCommunicator::InitSlave@src/executor/grpc_communicator.cpp` | network | semi_trusted | Slave node gRPC client connecting to master node for multi-node inference | Initializes gRPC client connecting to master node |
| `ConfigManager::Impl::Impl@src/config_manager/config_manager_impl.cpp` | file | trusted_admin | Configuration file parsing from config.json, typically managed by administrator | Parses and validates configuration from JSON file |
| `IPCCommunicator::SetupChannel@src/executor/ipc_communicator.cpp` | ipc | semi_trusted | Shared memory IPC setup for executor communication, local process boundary | Creates shared memory and semaphores for IPC |
| `HandleLoadLoraAdapter@src/server/endpoint/http_wrapper/http_handler.cpp` | http | untrusted_network | HTTP POST endpoint for loading LoRA adapters from specified paths, accessible from external clients | Handles LoRA adapter loading request |
| `ParseCommandLineArgs@src/server/daemon/llm_daemon.cpp` | cmdline | trusted_admin | Command line argument parsing for daemon startup, controlled by administrator | Parses command line arguments for daemon configuration |

**其他攻击面**:
- HTTP REST API (Port configured in serverConfig.port): OpenAI, TGI, vLLM, Triton inference endpoints
- HTTP Management API (Port configured in serverConfig.managementPort): Health checks, status, config query
- HTTP Metrics API (Port configured in serverConfig.metricsPort): Prometheus metrics
- gRPC Inter-node Communication (Port configured in serverConfig.interCommPort): PD disaggregation, multi-node inference
- IPC Shared Memory: Executor communication via shared memory and semaphores
- Configuration File Parsing: config.json, TLS certificates, CRL files
- LoRA Adapter Loading: Dynamic loading of LoRA adapters via API

---

## 3. High 漏洞 (8)

### [DAEMON-001] Signal Handler Safety Issue - SignalInterruptHandler

**严重性**: High | **CWE**: CWE-479 | **置信度**: 100/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `src/server/daemon/llm_daemon.cpp:196-221` @ `SignalInterruptHandler`
**模块**: daemon

**描述**: Signal handler SignalInterruptHandler uses non-async-signal-safe functions including std::cerr, ULOG_* macros (which likely use mutexes/memory allocation), std::unique_lock, std::condition_variable::notify_all(), and std::this_thread::sleep_for. These functions are not safe to call from signal handlers and can cause deadlocks, memory corruption, or undefined behavior when a signal interrupts a thread holding a lock or during memory allocation.

**漏洞代码** (`src/server/daemon/llm_daemon.cpp:196-221`)

```c
void SignalInterruptHandler(int sig)
{
    if (g_isKillingAll) { return; }
    ULOG_WARN(SUBMODLE_NAME_DAEMON, ...);  // NOT SAFE: uses mutexes/allocation
    int status = 0; pid_t pid = 0;
    while ((pid = waitpid(0, &status, WNOHANG)) > 0) {
        ULOG_INFO(SUBMODLE_NAME_DAEMON, ...);  // NOT SAFE
    }
    {
        std::unique_lock<std::mutex> lock(g_exitMtx);  // NOT SAFE: mutex in signal handler
        g_processExit = true;
    }
    HealthManager::UpdateHealth(false);  // NOT SAFE: may use I/O/locks
    g_exitCv.notify_all();  // NOT SAFE: condition variable in signal handler
    ULOG_WARN(SUBMODLE_NAME_DAEMON, ...);  // NOT SAFE
    std::this_thread::sleep_for(std::chrono::milliseconds(EP_STOP_WAIT_TIME));  // NOT SAFE
    KillProcessGroup();
}
```

**达成路径**

Signal (SIGSEGV/SIGABRT/SIGINT/SIGTERM) -> SignalInterruptHandler -> ULOG_* (mutex/allocation) -> std::unique_lock (mutex) -> notify_all() (mutex) -> sleep_for() (not signal-safe) -> KillProcessGroup()

**验证说明**: VERIFIED: SignalInterruptHandler contains confirmed non-async-signal-safe function calls. ULOG_* macros use std::ostringstream (heap allocation) and spdlog (mutexes). std::unique_lock acquires mutex. std::condition_variable::notify_all() uses internal mutexes. std::this_thread::sleep_for() is not async-signal-safe. This is a direct violation of CWE-479 and POSIX signal safety requirements.

**评分明细**: 0: D | 1: A | 2: E | 3: M | 4: O | 5: N | 6: - | 7: 0 | 8: 0 | 9: 1 | 10: : | 11:   | 12: S | 13: i | 14: g | 15: n | 16: a | 17: l | 18: I | 19: n | 20: t | 21: e | 22: r | 23: r | 24: u | 25: p | 26: t | 27: H | 28: a | 29: n | 30: d | 31: l | 32: e | 33: r | 34:   | 35: ( | 36: l | 37: i | 38: n | 39: e | 40: s | 41:   | 42: 1 | 43: 9 | 44: 6 | 45: - | 46: 2 | 47: 2 | 48: 1 | 49: ) | 50:   | 51: u | 52: s | 53: e | 54: s | 55:   | 56: m | 57: u | 58: l | 59: t | 60: i | 61: p | 62: l | 63: e | 64:   | 65: n | 66: o | 67: n | 68: - | 69: a | 70: s | 71: y | 72: n | 73: c | 74: - | 75: s | 76: i | 77: g | 78: n | 79: a | 80: l | 81: - | 82: s | 83: a | 84: f | 85: e | 86:   | 87: f | 88: u | 89: n | 90: c | 91: t | 92: i | 93: o | 94: n | 95: s | 96: : | 97: 
 | 98: - | 99:   | 100: U | 101: L | 102: O | 103: G | 104: _ | 105: W | 106: A | 107: R | 108: N | 109: ( | 110: ) | 111:   | 112: ( | 113: l | 114: i | 115: n | 116: e | 117: s | 118:   | 119: 2 | 120: 0 | 121: 2 | 122: - | 123: 2 | 124: 0 | 125: 3 | 126: , | 127:   | 128: 2 | 129: 1 | 130: 7 | 131: - | 132: 2 | 133: 1 | 134: 8 | 135: ) | 136: : | 137:   | 138: U | 139: s | 140: e | 141: s | 142:   | 143: s | 144: t | 145: d | 146: : | 147: : | 148: o | 149: s | 150: t | 151: r | 152: i | 153: n | 154: g | 155: s | 156: t | 157: r | 158: e | 159: a | 160: m | 161:   | 162: ( | 163: h | 164: e | 165: a | 166: p | 167:   | 168: a | 169: l | 170: l | 171: o | 172: c | 173: a | 174: t | 175: i | 176: o | 177: n | 178: ) | 179: , | 180:   | 181: s | 182: p | 183: d | 184: l | 185: o | 186: g | 187:   | 188: ( | 189: m | 190: u | 191: t | 192: e | 193: x | 194: e | 195: s | 196: ) | 197:   | 198: - | 199:   | 200: N | 201: O | 202: T | 203:   | 204: s | 205: i | 206: g | 207: n | 208: a | 209: l | 210: - | 211: s | 212: a | 213: f | 214: e | 215: 
 | 216: - | 217:   | 218: U | 219: L | 220: O | 221: G | 222: _ | 223: I | 224: N | 225: F | 226: O | 227: ( | 228: ) | 229:   | 230: ( | 231: l | 232: i | 233: n | 234: e | 235:   | 236: 2 | 237: 0 | 238: 8 | 239: ) | 240: : | 241:   | 242: S | 243: a | 244: m | 245: e | 246:   | 247: a | 248: s | 249:   | 250: U | 251: L | 252: O | 253: G | 254: _ | 255: W | 256: A | 257: R | 258: N | 259:   | 260: - | 261:   | 262: N | 263: O | 264: T | 265:   | 266: s | 267: i | 268: g | 269: n | 270: a | 271: l | 272: - | 273: s | 274: a | 275: f | 276: e | 277:   | 278:   | 279: 
 | 280: - | 281:   | 282: s | 283: t | 284: d | 285: : | 286: : | 287: u | 288: n | 289: i | 290: q | 291: u | 292: e | 293: _ | 294: l | 295: o | 296: c | 297: k | 298: < | 299: s | 300: t | 301: d | 302: : | 303: : | 304: m | 305: u | 306: t | 307: e | 308: x | 309: > | 310:   | 311: ( | 312: l | 313: i | 314: n | 315: e | 316:   | 317: 2 | 318: 1 | 319: 2 | 320: ) | 321: : | 322:   | 323: M | 324: u | 325: t | 326: e | 327: x | 328:   | 329: o | 330: p | 331: e | 332: r | 333: a | 334: t | 335: i | 336: o | 337: n | 338: s | 339:   | 340: d | 341: e | 342: a | 343: d | 344: l | 345: o | 346: c | 347: k | 348: - | 349: p | 350: r | 351: o | 352: n | 353: e | 354:   | 355: i | 356: n | 357:   | 358: s | 359: i | 360: g | 361: n | 362: a | 363: l | 364:   | 365: h | 366: a | 367: n | 368: d | 369: l | 370: e | 371: r | 372: s | 373:   | 374: - | 375:   | 376: N | 377: O | 378: T | 379:   | 380: s | 381: i | 382: g | 383: n | 384: a | 385: l | 386: - | 387: s | 388: a | 389: f | 390: e | 391: 
 | 392: - | 393:   | 394: g | 395: _ | 396: e | 397: x | 398: i | 399: t | 400: C | 401: v | 402: . | 403: n | 404: o | 405: t | 406: i | 407: f | 408: y | 409: _ | 410: a | 411: l | 412: l | 413: ( | 414: ) | 415:   | 416: ( | 417: l | 418: i | 419: n | 420: e | 421:   | 422: 2 | 423: 1 | 424: 6 | 425: ) | 426: : | 427:   | 428: C | 429: o | 430: n | 431: d | 432: i | 433: t | 434: i | 435: o | 436: n | 437:   | 438: v | 439: a | 440: r | 441: i | 442: a | 443: b | 444: l | 445: e | 446:   | 447: o | 448: p | 449: e | 450: r | 451: a | 452: t | 453: i | 454: o | 455: n | 456: s | 457:   | 458: u | 459: n | 460: s | 461: a | 462: f | 463: e | 464:   | 465: i | 466: n | 467:   | 468: s | 469: i | 470: g | 471: n | 472: a | 473: l | 474:   | 475: c | 476: o | 477: n | 478: t | 479: e | 480: x | 481: t | 482:   | 483: - | 484:   | 485: N | 486: O | 487: T | 488:   | 489: s | 490: i | 491: g | 492: n | 493: a | 494: l | 495: - | 496: s | 497: a | 498: f | 499: e | 500: 
 | 501: - | 502:   | 503: s | 504: t | 505: d | 506: : | 507: : | 508: t | 509: h | 510: i | 511: s | 512: _ | 513: t | 514: h | 515: r | 516: e | 517: a | 518: d | 519: : | 520: : | 521: s | 522: l | 523: e | 524: e | 525: p | 526: _ | 527: f | 528: o | 529: r | 530: ( | 531: ) | 532:   | 533: ( | 534: l | 535: i | 536: n | 537: e | 538:   | 539: 2 | 540: 1 | 541: 9 | 542: ) | 543: : | 544:   | 545: T | 546: h | 547: r | 548: e | 549: a | 550: d | 551:   | 552: s | 553: l | 554: e | 555: e | 556: p | 557:   | 558: f | 559: u | 560: n | 561: c | 562: t | 563: i | 564: o | 565: n | 566: s | 567:   | 568: u | 569: n | 570: s | 571: a | 572: f | 573: e | 574:   | 575: i | 576: n | 577:   | 578: s | 579: i | 580: g | 581: n | 582: a | 583: l | 584:   | 585: h | 586: a | 587: n | 588: d | 589: l | 590: e | 591: r | 592: s | 593:   | 594: - | 595:   | 596: N | 597: O | 598: T | 599:   | 600: s | 601: i | 602: g | 603: n | 604: a | 605: l | 606: - | 607: s | 608: a | 609: f | 610: e | 611: 
 | 612: - | 613:   | 614: K | 615: i | 616: l | 617: l | 618: P | 619: r | 620: o | 621: c | 622: e | 623: s | 624: s | 625: G | 626: r | 627: o | 628: u | 629: p | 630: ( | 631: ) | 632:   | 633: ( | 634: l | 635: i | 636: n | 637: e | 638:   | 639: 2 | 640: 2 | 641: 0 | 642: ) | 643: : | 644:   | 645: C | 646: o | 647: n | 648: t | 649: a | 650: i | 651: n | 652: s | 653:   | 654: U | 655: L | 656: O | 657: G | 658: _ | 659: A | 660: U | 661: D | 662: I | 663: T | 664: ( | 665: ) | 666: , | 667:   | 668: s | 669: t | 670: d | 671: : | 672: : | 673: c | 674: e | 675: r | 676: r | 677: , | 678:   | 679: L | 680: o | 681: g | 682: : | 683: : | 684: F | 685: l | 686: u | 687: s | 688: h | 689: ( | 690: ) | 691:   | 692: - | 693:   | 694: N | 695: O | 696: T | 697:   | 698: s | 699: i | 700: g | 701: n | 702: a | 703: l | 704: - | 705: s | 706: a | 707: f | 708: e | 709: 
 | 710: S | 711: i | 712: g | 713: n | 714: a | 715: l | 716: s | 717:   | 718: h | 719: a | 720: n | 721: d | 722: l | 723: e | 724: d | 725: : | 726:   | 727: S | 728: I | 729: G | 730: S | 731: E | 732: G | 733: V | 734: , | 735:   | 736: S | 737: I | 738: G | 739: A | 740: B | 741: R | 742: T | 743: , | 744:   | 745: S | 746: I | 747: G | 748: I | 749: N | 750: T | 751: , | 752:   | 753: S | 754: I | 755: G | 756: T | 757: E | 758: R | 759: M | 760: . | 761:   | 762: D | 763: e | 764: a | 765: d | 766: l | 767: o | 768: c | 769: k | 770:   | 771: r | 772: i | 773: s | 774: k | 775: : | 776:   | 777: I | 778: f | 779:   | 780: s | 781: i | 782: g | 783: n | 784: a | 785: l | 786:   | 787: a | 788: r | 789: r | 790: i | 791: v | 792: e | 793: s | 794:   | 795: w | 796: h | 797: i | 798: l | 799: e | 800:   | 801: a | 802: n | 803: o | 804: t | 805: h | 806: e | 807: r | 808:   | 809: t | 810: h | 811: r | 812: e | 813: a | 814: d | 815:   | 816: h | 817: o | 818: l | 819: d | 820: s | 821:   | 822: g | 823: _ | 824: e | 825: x | 826: i | 827: t | 828: M | 829: t | 830: x | 831:   | 832: o | 833: r | 834:   | 835: d | 836: u | 837: r | 838: i | 839: n | 840: g | 841:   | 842: m | 843: e | 844: m | 845: o | 846: r | 847: y | 848:   | 849: a | 850: l | 851: l | 852: o | 853: c | 854: a | 855: t | 856: i | 857: o | 858: n | 859:   | 860: i | 861: n | 862:   | 863: U | 864: L | 865: O | 866: G | 867: _ | 868: * | 869: , | 870:   | 871: d | 872: e | 873: a | 874: d | 875: l | 876: o | 877: c | 878: k | 879:   | 880: o | 881: r | 882:   | 883: c | 884: o | 885: r | 886: r | 887: u | 888: p | 889: t | 890: i | 891: o | 892: n | 893:   | 894: o | 895: c | 896: c | 897: u | 898: r | 899: s | 900: .

---

### [DAEMON-002] Signal Handler Safety Issue - SignalChldHandler

**严重性**: High | **CWE**: CWE-479 | **置信度**: 100/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `src/server/daemon/llm_daemon.cpp:223-273` @ `SignalChldHandler`
**模块**: daemon

**描述**: Signal handler SignalChldHandler uses non-async-signal-safe functions including ULOG_* macros (mutex/allocation), std::unique_lock with mutex, condition_variable::notify_all(), and strsignal(). These can cause deadlock or memory corruption.

**验证说明**: VERIFIED: SignalChldHandler contains confirmed non-async-signal-safe function calls. In addition to ULOG_* macros and mutex/condition_variable issues found in DAEMON-001, this handler also uses strsignal() which is not listed in POSIX async-signal-safe functions. Direct violation of CWE-479.

**评分明细**: 0: D | 1: A | 2: E | 3: M | 4: O | 5: N | 6: - | 7: 0 | 8: 0 | 9: 2 | 10: : | 11:   | 12: S | 13: i | 14: g | 15: n | 16: a | 17: l | 18: C | 19: h | 20: l | 21: d | 22: H | 23: a | 24: n | 25: d | 26: l | 27: e | 28: r | 29:   | 30: ( | 31: l | 32: i | 33: n | 34: e | 35: s | 36:   | 37: 2 | 38: 2 | 39: 3 | 40: - | 41: 2 | 42: 7 | 43: 3 | 44: ) | 45:   | 46: u | 47: s | 48: e | 49: s | 50:   | 51: m | 52: u | 53: l | 54: t | 55: i | 56: p | 57: l | 58: e | 59:   | 60: n | 61: o | 62: n | 63: - | 64: a | 65: s | 66: y | 67: n | 68: c | 69: - | 70: s | 71: i | 72: g | 73: n | 74: a | 75: l | 76: - | 77: s | 78: a | 79: f | 80: e | 81:   | 82: f | 83: u | 84: n | 85: c | 86: t | 87: i | 88: o | 89: n | 90: s | 91: : | 92: 
 | 93: - | 94:   | 95: U | 96: L | 97: O | 98: G | 99: _ | 100: W | 101: A | 102: R | 103: N | 104: ( | 105: ) | 106:   | 107: ( | 108: l | 109: i | 110: n | 111: e | 112: s | 113:   | 114: 2 | 115: 2 | 116: 5 | 117: - | 118: 2 | 119: 2 | 120: 6 | 121: , | 122:   | 123: 2 | 124: 3 | 125: 1 | 126: - | 127: 2 | 128: 3 | 129: 2 | 130: , | 131:   | 132: 2 | 133: 6 | 134: 9 | 135: - | 136: 2 | 137: 7 | 138: 0 | 139: ) | 140: : | 141:   | 142: U | 143: s | 144: e | 145: s | 146:   | 147: s | 148: t | 149: d | 150: : | 151: : | 152: o | 153: s | 154: t | 155: r | 156: i | 157: n | 158: g | 159: s | 160: t | 161: r | 162: e | 163: a | 164: m | 165:   | 166: ( | 167: h | 168: e | 169: a | 170: p | 171:   | 172: a | 173: l | 174: l | 175: o | 176: c | 177: a | 178: t | 179: i | 180: o | 181: n | 182: ) | 183: , | 184:   | 185: s | 186: p | 187: d | 188: l | 189: o | 190: g | 191:   | 192: ( | 193: m | 194: u | 195: t | 196: e | 197: x | 198: e | 199: s | 200: ) | 201:   | 202: - | 203:   | 204: N | 205: O | 206: T | 207:   | 208: s | 209: i | 210: g | 211: n | 212: a | 213: l | 214: - | 215: s | 216: a | 217: f | 218: e | 219: 
 | 220: - | 221:   | 222: U | 223: L | 224: O | 225: G | 226: _ | 227: I | 228: N | 229: F | 230: O | 231: ( | 232: ) | 233:   | 234: ( | 235: l | 236: i | 237: n | 238: e | 239:   | 240: 2 | 241: 3 | 242: 8 | 243: ) | 244: : | 245:   | 246: S | 247: a | 248: m | 249: e | 250:   | 251: - | 252:   | 253: N | 254: O | 255: T | 256:   | 257: s | 258: i | 259: g | 260: n | 261: a | 262: l | 263: - | 264: s | 265: a | 266: f | 267: e | 268: 
 | 269: - | 270:   | 271: U | 272: L | 273: O | 274: G | 275: _ | 276: E | 277: R | 278: R | 279: O | 280: R | 281: ( | 282: ) | 283:   | 284: ( | 285: l | 286: i | 287: n | 288: e | 289: s | 290:   | 291: 2 | 292: 4 | 293: 6 | 294: - | 295: 2 | 296: 4 | 297: 7 | 298: , | 299:   | 300: 2 | 301: 5 | 302: 2 | 303: - | 304: 2 | 305: 5 | 306: 3 | 307: , | 308:   | 309: 2 | 310: 5 | 311: 7 | 312: - | 313: 2 | 314: 5 | 315: 8 | 316: ) | 317: : | 318:   | 319: S | 320: a | 321: m | 322: e | 323:   | 324: - | 325:   | 326: N | 327: O | 328: T | 329:   | 330: s | 331: i | 332: g | 333: n | 334: a | 335: l | 336: - | 337: s | 338: a | 339: f | 340: e | 341: 
 | 342: - | 343:   | 344: s | 345: t | 346: r | 347: s | 348: i | 349: g | 350: n | 351: a | 352: l | 353: ( | 354: ) | 355:   | 356: ( | 357: l | 358: i | 359: n | 360: e | 361: s | 362:   | 363: 2 | 364: 4 | 365: 7 | 366: , | 367:   | 368: 2 | 369: 5 | 370: 3 | 371: ) | 372: : | 373:   | 374: N | 375: o | 376: t | 377:   | 378: i | 379: n | 380:   | 381: P | 382: O | 383: S | 384: I | 385: X | 386:   | 387: a | 388: s | 389: y | 390: n | 391: c | 392: - | 393: s | 394: i | 395: g | 396: n | 397: a | 398: l | 399: - | 400: s | 401: a | 402: f | 403: e | 404:   | 405: f | 406: u | 407: n | 408: c | 409: t | 410: i | 411: o | 412: n | 413:   | 414: l | 415: i | 416: s | 417: t | 418:   | 419: - | 420:   | 421: N | 422: O | 423: T | 424:   | 425: s | 426: i | 427: g | 428: n | 429: a | 430: l | 431: - | 432: s | 433: a | 434: f | 435: e | 436: 
 | 437: - | 438:   | 439: s | 440: t | 441: d | 442: : | 443: : | 444: u | 445: n | 446: i | 447: q | 448: u | 449: e | 450: _ | 451: l | 452: o | 453: c | 454: k | 455: < | 456: s | 457: t | 458: d | 459: : | 460: : | 461: m | 462: u | 463: t | 464: e | 465: x | 466: > | 467:   | 468: ( | 469: l | 470: i | 471: n | 472: e | 473:   | 474: 2 | 475: 6 | 476: 3 | 477: ) | 478: : | 479:   | 480: M | 481: u | 482: t | 483: e | 484: x | 485:   | 486: o | 487: p | 488: e | 489: r | 490: a | 491: t | 492: i | 493: o | 494: n | 495: s | 496:   | 497: d | 498: e | 499: a | 500: d | 501: l | 502: o | 503: c | 504: k | 505: - | 506: p | 507: r | 508: o | 509: n | 510: e | 511:   | 512: - | 513:   | 514: N | 515: O | 516: T | 517:   | 518: s | 519: i | 520: g | 521: n | 522: a | 523: l | 524: - | 525: s | 526: a | 527: f | 528: e | 529: 
 | 530: - | 531:   | 532: g | 533: _ | 534: e | 535: x | 536: i | 537: t | 538: C | 539: v | 540: . | 541: n | 542: o | 543: t | 544: i | 545: f | 546: y | 547: _ | 548: a | 549: l | 550: l | 551: ( | 552: ) | 553:   | 554: ( | 555: l | 556: i | 557: n | 558: e | 559:   | 560: 2 | 561: 6 | 562: 7 | 563: ) | 564: : | 565:   | 566: C | 567: o | 568: n | 569: d | 570: i | 571: t | 572: i | 573: o | 574: n | 575:   | 576: v | 577: a | 578: r | 579: i | 580: a | 581: b | 582: l | 583: e | 584:   | 585: o | 586: p | 587: e | 588: r | 589: a | 590: t | 591: i | 592: o | 593: n | 594: s | 595:   | 596: u | 597: n | 598: s | 599: a | 600: f | 601: e | 602:   | 603: - | 604:   | 605: N | 606: O | 607: T | 608:   | 609: s | 610: i | 611: g | 612: n | 613: a | 614: l | 615: - | 616: s | 617: a | 618: f | 619: e | 620: 
 | 621: - | 622:   | 623: K | 624: i | 625: l | 626: l | 627: P | 628: r | 629: o | 630: c | 631: e | 632: s | 633: s | 634: G | 635: r | 636: o | 637: u | 638: p | 639: ( | 640: ) | 641:   | 642: ( | 643: l | 644: i | 645: n | 646: e | 647:   | 648: 2 | 649: 7 | 650: 1 | 651: ) | 652: : | 653:   | 654: C | 655: o | 656: n | 657: t | 658: a | 659: i | 660: n | 661: s | 662:   | 663: u | 664: n | 665: s | 666: a | 667: f | 668: e | 669:   | 670: o | 671: p | 672: e | 673: r | 674: a | 675: t | 676: i | 677: o | 678: n | 679: s | 680:   | 681: - | 682:   | 683: N | 684: O | 685: T | 686:   | 687: s | 688: i | 689: g | 690: n | 691: a | 692: l | 693: - | 694: s | 695: a | 696: f | 697: e | 698: 
 | 699: S | 700: i | 701: g | 702: n | 703: a | 704: l | 705:   | 706: h | 707: a | 708: n | 709: d | 710: l | 711: e | 712: d | 713: : | 714:   | 715: S | 716: I | 717: G | 718: C | 719: H | 720: L | 721: D | 722: .

---

### [DAEMON-003] Race Condition in Signal Handling - SignalInterruptHandler,SignalChldHandler

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-364 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `src/server/daemon/llm_daemon.cpp:196-273` @ `SignalInterruptHandler,SignalChldHandler`
**模块**: daemon

**描述**: Multiple signal handlers modify g_processExit and call g_exitCv.notify_all() without proper synchronization. While g_processExit uses mutex protection, calling notify_all() from signal handler is unsafe and creates race between SignalInterruptHandler and SignalChldHandler.

**验证说明**: VERIFIED: Race condition confirmed. The root cause is that both signal handlers call g_exitCv.notify_all() which uses internal mutexes. POSIX explicitly prohibits condition variable operations from signal handlers. The mutex protection on g_processExit is insufficient because the condition variable itself becomes corrupted when accessed from async context. This is a race condition that violates CWE-364.

**评分明细**: 0: D | 1: A | 2: E | 3: M | 4: O | 5: N | 6: - | 7: 0 | 8: 0 | 9: 3 | 10: : | 11:   | 12: R | 13: a | 14: c | 15: e | 16:   | 17: c | 18: o | 19: n | 20: d | 21: i | 22: t | 23: i | 24: o | 25: n | 26:   | 27: b | 28: e | 29: t | 30: w | 31: e | 32: e | 33: n | 34:   | 35: s | 36: i | 37: g | 38: n | 39: a | 40: l | 41:   | 42: h | 43: a | 44: n | 45: d | 46: l | 47: e | 48: r | 49: s | 50:   | 51: ( | 52: l | 53: i | 54: n | 55: e | 56: s | 57:   | 58: 1 | 59: 9 | 60: 6 | 61: - | 62: 2 | 63: 7 | 64: 3 | 65: ) | 66: : | 67: 
 | 68: - | 69:   | 70: B | 71: o | 72: t | 73: h | 74:   | 75: S | 76: i | 77: g | 78: n | 79: a | 80: l | 81: I | 82: n | 83: t | 84: e | 85: r | 86: r | 87: u | 88: p | 89: t | 90: H | 91: a | 92: n | 93: d | 94: l | 95: e | 96: r | 97:   | 98: a | 99: n | 100: d | 101:   | 102: S | 103: i | 104: g | 105: n | 106: a | 107: l | 108: C | 109: h | 110: l | 111: d | 112: H | 113: a | 114: n | 115: d | 116: l | 117: e | 118: r | 119:   | 120: m | 121: o | 122: d | 123: i | 124: f | 125: y | 126:   | 127: g | 128: _ | 129: p | 130: r | 131: o | 132: c | 133: e | 134: s | 135: s | 136: E | 137: x | 138: i | 139: t | 140:   | 141: a | 142: n | 143: d | 144:   | 145: c | 146: a | 147: l | 148: l | 149:   | 150: g | 151: _ | 152: e | 153: x | 154: i | 155: t | 156: C | 157: v | 158: . | 159: n | 160: o | 161: t | 162: i | 163: f | 164: y | 165: _ | 166: a | 167: l | 168: l | 169: ( | 170: ) | 171: 
 | 172: - | 173:   | 174: W | 175: h | 176: i | 177: l | 178: e | 179:   | 180: g | 181: _ | 182: p | 183: r | 184: o | 185: c | 186: e | 187: s | 188: s | 189: E | 190: x | 191: i | 192: t | 193:   | 194: m | 195: o | 196: d | 197: i | 198: f | 199: i | 200: c | 201: a | 202: t | 203: i | 204: o | 205: n | 206:   | 207: i | 208: s | 209:   | 210: m | 211: u | 212: t | 213: e | 214: x | 215: - | 216: p | 217: r | 218: o | 219: t | 220: e | 221: c | 222: t | 223: e | 224: d | 225: , | 226:   | 227: c | 228: a | 229: l | 230: l | 231: i | 232: n | 233: g | 234:   | 235: n | 236: o | 237: t | 238: i | 239: f | 240: y | 241: _ | 242: a | 243: l | 244: l | 245: ( | 246: ) | 247:   | 248: f | 249: r | 250: o | 251: m | 252:   | 253: s | 254: i | 255: g | 256: n | 257: a | 258: l | 259:   | 260: h | 261: a | 262: n | 263: d | 264: l | 265: e | 266: r | 267:   | 268: i | 269: s | 270:   | 271: u | 272: n | 273: s | 274: a | 275: f | 276: e | 277: 
 | 278: - | 279:   | 280: g | 281: _ | 282: i | 283: s | 284: K | 285: i | 286: l | 287: l | 288: i | 289: n | 290: g | 291: A | 292: l | 293: l | 294:   | 295: a | 296: t | 297: o | 298: m | 299: i | 300: c | 301:   | 302: f | 303: l | 304: a | 305: g | 306:   | 307: ( | 308: l | 309: i | 310: n | 311: e | 312:   | 313: 1 | 314: 5 | 315: 8 | 316: ) | 317:   | 318: p | 319: r | 320: o | 321: v | 322: i | 323: d | 324: e | 325: s | 326:   | 327: p | 328: a | 329: r | 330: t | 331: i | 332: a | 333: l | 334:   | 335: p | 336: r | 337: o | 338: t | 339: e | 340: c | 341: t | 342: i | 343: o | 344: n | 345:   | 346: a | 347: g | 348: a | 349: i | 350: n | 351: s | 352: t | 353:   | 354: m | 355: u | 356: l | 357: t | 358: i | 359: p | 360: l | 361: e | 362:   | 363: K | 364: i | 365: l | 366: l | 367: P | 368: r | 369: o | 370: c | 371: e | 372: s | 373: s | 374: G | 375: r | 376: o | 377: u | 378: p | 379: ( | 380: ) | 381:   | 382: c | 383: a | 384: l | 385: l | 386: s | 387: 
 | 388: - | 389:   | 390: H | 391: o | 392: w | 393: e | 394: v | 395: e | 396: r | 397: , | 398:   | 399: r | 400: a | 401: c | 402: e | 403:   | 404: e | 405: x | 406: i | 407: s | 408: t | 409: s | 410:   | 411: a | 412: t | 413:   | 414: n | 415: o | 416: t | 417: i | 418: f | 419: y | 420: _ | 421: a | 422: l | 423: l | 424: ( | 425: ) | 426:   | 427: c | 428: a | 429: l | 430: l | 431:   | 432: w | 433: h | 434: i | 435: c | 436: h | 437:   | 438: c | 439: a | 440: n | 441:   | 442: c | 443: o | 444: r | 445: r | 446: u | 447: p | 448: t | 449:   | 450: c | 451: o | 452: n | 453: d | 454: i | 455: t | 456: i | 457: o | 458: n | 459:   | 460: v | 461: a | 462: r | 463: i | 464: a | 465: b | 466: l | 467: e | 468:   | 469: i | 470: n | 471: t | 472: e | 473: r | 474: n | 475: a | 476: l | 477:   | 478: s | 479: t | 480: a | 481: t | 482: e | 483: 
 | 484: - | 485:   | 486: C | 487: o | 488: n | 489: c | 490: u | 491: r | 492: r | 493: e | 494: n | 495: t | 496:   | 497: S | 498: I | 499: G | 500: C | 501: H | 502: L | 503: D | 504:   | 505: a | 506: n | 507: d | 508:   | 509: S | 510: I | 511: G | 512: I | 513: N | 514: T | 515: / | 516: S | 517: I | 518: G | 519: T | 520: E | 521: R | 522: M | 523:   | 524: c | 525: a | 526: n | 527:   | 528: c | 529: a | 530: u | 531: s | 532: e | 533: : | 534:   | 535: c | 536: o | 537: r | 538: r | 539: u | 540: p | 541: t | 542: e | 543: d | 544:   | 545: c | 546: o | 547: n | 548: d | 549: i | 550: t | 551: i | 552: o | 553: n | 554:   | 555: v | 556: a | 557: r | 558: i | 559: a | 560: b | 561: l | 562: e | 563: , | 564:   | 565: m | 566: i | 567: s | 568: s | 569: e | 570: d | 571:   | 572: n | 573: o | 574: t | 575: i | 576: f | 577: i | 578: c | 579: a | 580: t | 581: i | 582: o | 583: n | 584: s | 585: , | 586:   | 587: o | 588: r | 589:   | 590: u | 591: n | 592: d | 593: e | 594: f | 595: i | 596: n | 597: e | 598: d | 599:   | 600: b | 601: e | 602: h | 603: a | 604: v | 605: i | 606: o | 607: r | 608: 
 | 609: - | 610:   | 611: P | 612: r | 613: i | 614: m | 615: a | 616: r | 617: y | 618:   | 619: i | 620: s | 621: s | 622: u | 623: e | 624: : | 625:   | 626: U | 627: s | 628: i | 629: n | 630: g | 631:   | 632: m | 633: u | 634: t | 635: e | 636: x | 637: - | 638: p | 639: r | 640: o | 641: t | 642: e | 643: c | 644: t | 645: e | 646: d | 647:   | 648: c | 649: o | 650: n | 651: d | 652: i | 653: t | 654: i | 655: o | 656: n | 657:   | 658: v | 659: a | 660: r | 661: i | 662: a | 663: b | 664: l | 665: e | 666: s | 667:   | 668: f | 669: r | 670: o | 671: m | 672:   | 673: s | 674: i | 675: g | 676: n | 677: a | 678: l | 679:   | 680: h | 681: a | 682: n | 683: d | 684: l | 685: e | 686: r | 687: s | 688:   | 689: i | 690: s | 691:   | 692: f | 693: u | 694: n | 695: d | 696: a | 697: m | 698: e | 699: n | 700: t | 701: a | 702: l | 703: l | 704: y | 705:   | 706: u | 707: n | 708: s | 709: a | 710: f | 711: e | 712:   | 713: p | 714: e | 715: r | 716:   | 717: P | 718: O | 719: S | 720: I | 721: X

---

### [SEC-INFER-004] Improper Validation of Array Index with User-Controlled Size - BuildReComputeInput

**严重性**: High | **CWE**: CWE-129 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-infer_interface-scanner

**位置**: `src/server/endpoint/single_req_infer_interface/single_req_triton_token_infer_interface.cpp:417-419` @ `BuildReComputeInput`
**模块**: infer_interface
**跨模块**: infer_interface → single_req_triton_token_infer_interface

**描述**: Improper validation of array index in GetTokensFromInput and BuildReComputeInput. The oriReqTokenLen_ value derived from user input (first token in comma-separated string) is used to determine array bounds without proper validation. In BuildReComputeInput (single_req_triton_token_infer_interface.cpp:417-419), the code iterates for (size_t i = 0; i < oriReqTokenLen_; i++) { inputTokens.push_back(reqTokens_[i]); } without checking that oriReqTokenLen_ <= reqTokens_.size(). If oriReqTokenLen_ is larger than the actual token array size, this could cause out-of-bounds read from reqTokens_ vector, potentially exposing sensitive memory contents or causing program crash.

**漏洞代码** (`src/server/endpoint/single_req_infer_interface/single_req_triton_token_infer_interface.cpp:417-419`)

```c
inputTokens.push_back(oriReqTokenLen_);
for (size_t i = 0; i < oriReqTokenLen_; i++) {
    inputTokens.push_back(reqTokens_[i]);
}
```

**达成路径**

HTTP Request -> JSON parse -> GetTokensFromInput() -> oriReqTokenLen_ (user-controlled) -> BuildReComputeInput() -> reqTokens_[i] (array access without bounds check)

**验证说明**: VALID CRITICAL: BuildReComputeInput in triton_token_infer_interface.cpp (line 418) iterates reqTokens_[i] for i<oriReqTokenLen_ without bounds check. oriReqTokenLen_=inputsData[0] from user input when isReCompute_=true. No validation that oriReqTokenLen_<=reqTokens_.size(). Direct OOB read possible.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: : | 23: 3 | 24: 0 | 25: ( | 26: d | 27: i | 28: r | 29: e | 30: c | 31: t | 32: _ | 33: e | 34: x | 35: t | 36: e | 37: r | 38: n | 39: a | 40: l | 41: ) | 42:   | 43: + | 44:   | 45: c | 46: o | 47: n | 48: t | 49: r | 50: o | 51: l | 52: l | 53: a | 54: b | 55: i | 56: l | 57: i | 58: t | 59: y | 60: : | 61: 2 | 62: 5 | 63: ( | 64: f | 65: u | 66: l | 67: l | 68: ) | 69:   | 70: + | 71:   | 72: c | 73: r | 74: o | 75: s | 76: s | 77: _ | 78: f | 79: i | 80: l | 81: e | 82: : | 83: 0 | 84: ( | 85: c | 86: h | 87: a | 88: i | 89: n | 90: _ | 91: c | 92: o | 93: m | 94: p | 95: l | 96: e | 97: t | 98: e | 99: )

---

### [VULN-GRPC-001] Memory Exhaustion - HandleDecodeRequest

**严重性**: High | **CWE**: CWE-789 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-grpc_endpoint-scanner

**位置**: `src/server/endpoint/grpc_wrapper/grpc_handler.cpp:85-96` @ `HandleDecodeRequest`
**模块**: grpc_endpoint

**描述**: Memory Exhaustion via Unvalidated BlockTable Size. blocktable_size() and blockid_size() are used directly without upper-bound validation in HandleDecodeRequest(). An attacker can send a malformed protobuf message with extremely large values causing memory exhaustion.

**漏洞代码** (`src/server/endpoint/grpc_wrapper/grpc_handler.cpp:85-96`)

```c
kvCacheInfo.blockTable.resize(para.blocktable_size()); for (int i = 0; i < para.blocktable_size(); ++i) { ... blocktable.blockid_size() ... }
```

**达成路径**

DecodeParameters.blocktable -> HandleDecodeRequest() -> KvCacheInfo.blockTable.resize() -> unbounded memory allocation

**验证说明**: Pre-validated: blocktable_size() and blockid_size() used directly without upper-bound validation. Unbounded memory allocation from gRPC input can cause memory exhaustion.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [DFLOW-001] Improper Input Validation - MasterServiceImpl::RegisterAndCommunicate

**严重性**: High | **CWE**: CWE-20 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-grpc_communicator-scanner

**位置**: `src/executor/grpc_communicator.cpp:627-628` @ `MasterServiceImpl::RegisterAndCommunicate`
**模块**: grpc_communicator

**描述**: Network-provided slave_ip used without IP format validation. In MasterServiceImpl::RegisterAndCommunicate(), the slave_ip field from RegisterRequestMsg protobuf is directly used as a key to store stream connections without calling CheckIp() to validate IP format. An attacker controlling a slave node could inject malformed IP strings causing denial of service or potential injection attacks.

**漏洞代码** (`src/executor/grpc_communicator.cpp:627-628`)

```c
slaveIpFromStream = register_request.slave_ip(); gRPCCommunicator->SlaveIpToStream().Insert(register_request.slave_ip(), stream);
```

**达成路径**

register_request.slave_ip() (network) -> slaveIpFromStream -> SlaveIpToStream_.Insert() [NO CheckIp validation]

**验证说明**: Pre-validated: Network-provided slave_ip used without IP validation. Direct external input from gRPC protobuf, attacker-controlled slave node can inject malformed IPs. No CheckIp() validation before storing in map.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CVE-MINDIE-001] Path Traversal - HandleLoadLoraAdapter

**严重性**: High | **CWE**: CWE-22 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: dataflow-http_endpoint-scanner

**位置**: `src/server/endpoint/http_wrapper/http_handler.cpp:1069-1110` @ `HandleLoadLoraAdapter`
**模块**: http_endpoint

**描述**: The /v1/load_lora_adapter endpoint accepts user-controlled lora_path parameter. While there is regex validation, the validation has weaknesses: regex allows absolute paths starting with '/', '..' check only prevents basic traversal but doesn't prevent URL encoding or other techniques, path is passed to HandleLora without canonicalization or sandbox validation.

**漏洞代码** (`src/server/endpoint/http_wrapper/http_handler.cpp:1069-1110`)

```c
loraPath.find("..") != std::string::npos validation insufficient; regex allows absolute paths
```

**达成路径**

HTTP request body -> JSON parsing -> Regex check -> HandleLora -> LoraManager::Load -> Executor

**验证说明**: Pre-validated: /v1/load_lora_adapter endpoint has weak path validation. Regex allows absolute paths, '..' check is insufficient. Direct external input via HTTP API.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-INFER-001] Integer Overflow/Wraparound - GetTokensFromInput

**严重性**: High | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: CONFIRMED | **来源**: dataflow-infer_interface-scanner

**位置**: `src/server/endpoint/single_req_infer_interface/single_req_infer_interface_base.cpp:1045-1052` @ `GetTokensFromInput`
**模块**: infer_interface
**跨模块**: infer_interface → single_req_infer_interface_base → single_req_triton_token_infer_interface

**描述**: Integer overflow in GetTokensFromInput function. The function uses std::stoll() to convert user-controlled input string to int64_t, then casts to uint64_t without proper bounds validation. If a malicious user provides a negative value or a value exceeding INT64_MAX through the recompute input parameter, the cast to uint64_t can result in an extremely large value. This value (oriReqTokenLen_) is then used to iterate over arrays (line 418: for (size_t i = 0; i < oriReqTokenLen_; i++) in BuildReComputeInput) which could lead to memory exhaustion, out-of-bounds access, or denial of service. The tainted data flows from HTTP request body -> JSON parsing -> GetTokensFromInput -> oriReqTokenLen_ -> BuildReComputeInput loop iteration.

**漏洞代码** (`src/server/endpoint/single_req_infer_interface/single_req_infer_interface_base.cpp:1045-1052`)

```c
oriReqTokenLen_ = static_cast<uint64_t>(std::stoll(token));
if (idx <= oriReqTokenLen_) {
    requestTokens.push_back(std::stoll(token));
}
```

**达成路径**

HTTP Request Body -> JSON parse -> inputParam->textInput -> GetTokensFromInput() -> std::stoll(token) -> oriReqTokenLen_ (uint64_t) -> BuildReComputeInput() loop iteration

**验证说明**: VALID: oriReqTokenLen_ from std::stoll cast to uint64_t without bounds validation. Negative values wrap to large positives. StreamAppend uses min(source.size(),limit) mitigating downstream impact in base class, but BuildReComputeInput in triton_token_infer_interface.cpp lacks bounds check.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: : | 23: 3 | 24: 0 | 25: ( | 26: d | 27: i | 28: r | 29: e | 30: c | 31: t | 32: _ | 33: e | 34: x | 35: t | 36: e | 37: r | 38: n | 39: a | 40: l | 41: ) | 42:   | 43: + | 44:   | 45: c | 46: o | 47: n | 48: t | 49: r | 50: o | 51: l | 52: l | 53: a | 54: b | 55: i | 56: l | 57: i | 58: t | 59: y | 60: : | 61: 2 | 62: 5 | 63: ( | 64: f | 65: u | 66: l | 67: l | 68: ) | 69:   | 70: - | 71:   | 72: m | 73: i | 74: t | 75: i | 76: g | 77: a | 78: t | 79: i | 80: o | 81: n | 82: s | 83: : | 84: 1 | 85: 5 | 86: ( | 87: S | 88: t | 89: r | 90: e | 91: a | 92: m | 93: A | 94: p | 95: p | 96: e | 97: n | 98: d | 99:   | 100: b | 101: o | 102: u | 103: n | 104: d | 105: s | 106:   | 107: c | 108: h | 109: e | 110: c | 111: k | 112:   | 113: d | 114: o | 115: w | 116: n | 117: s | 118: t | 119: r | 120: e | 121: a | 122: m | 123: )

---

## 4. Medium 漏洞 (3)

### [VULN-INF-002] Improper Exception Handling - InferInstance::InitPDNode

**严重性**: Medium | **CWE**: CWE-252 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `src/server/infer_instances/infer_instances.cpp:634-636` @ `InferInstance::InitPDNode`
**模块**: infer_instances

**描述**: Unprotected stoi() call without exception handling in InitPDNode. stoi(id) lacks try-catch, unlike DeserializeSet which handles exceptions properly. Invalid input causes uncaught exception leading to crash.

**漏洞代码** (`src/server/infer_instances/infer_instances.cpp:634-636`)

```c
for (auto &id : Split(ipInfo[local_logic_device_id], ,)) { deviceIds.insert(static_cast<size_t>(stoi(id))); }
```

**达成路径**

GlobalIpInfo.localDeviceLogicalIds -> ipInfo -> Split() -> stoi(id) [NO EXCEPTION HANDLING] -> deviceIds

**验证说明**: CONFIRMED: The stoi() call at line 635 has no exception handling. If the input string contains non-numeric characters or values outside int range, it will throw std::invalid_argument or std::out_of_range, crashing the service. Compare with DeserializeSet() which has proper try-catch blocks for similar conversion operations.

**评分明细**: exception_safety: [object Object] | comparison: [object Object] | impact: Service crash on malformed input | trust_boundary: internal_api

---

### [SEC-INFER-002] Unsafe Enum Type Conversion - GetFaultRecoveryCmdType

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: CONFIRMED | **来源**: dataflow-infer_interface-scanner

**位置**: `src/server/endpoint/single_req_infer_interface/parse_protocol.cpp:206-207` @ `GetFaultRecoveryCmdType`
**模块**: infer_interface

**描述**: Unsafe conversion from int to FaultRecoveryCmd enum without bounds validation. The GetFaultRecoveryCmdType function extracts an integer value from JSON input using jsonData["cmd"].get<int>() and directly casts it to FaultRecoveryCmd enum type without verifying the value is within valid enum range (0-4 based on CMD_PAUSE_ENGINE, CMD_REINIT_NPU, CMD_START_ENGINE, CMD_PAUSE_ENGINE_ROCE). Providing an out-of-range integer value could result in undefined behavior when the enum value is used in switch statements or passed to FaultRecoveryCmdToString, potentially leading to unpredictable program behavior or security bypass.

**漏洞代码** (`src/server/endpoint/single_req_infer_interface/parse_protocol.cpp:206-207`)

```c
cmdType = static_cast<FaultRecoveryCmd>(jsonData["cmd"].get<int>());
cmdStr = FaultRecoveryCmdToString(cmdType);
```

**达成路径**

HTTP Request -> DecodeFaultRecoveryCmd() -> OrderedJson::parse() -> GetFaultRecoveryCmdType() -> jsonData["cmd"].get<int>() -> static_cast<FaultRecoveryCmd> -> switch/case usage

**验证说明**: VALID: int cast to FaultRecoveryCmd enum without range validation (valid range: 0-3). FaultRecoveryCmdToString has default case returning CMD_UNKNOWN, providing partial mitigation. Invalid values may cause logic issues but no memory safety impact.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: : | 23: 3 | 24: 0 | 25: ( | 26: d | 27: i | 28: r | 29: e | 30: c | 31: t | 32: _ | 33: e | 34: x | 35: t | 36: e | 37: r | 38: n | 39: a | 40: l | 41: ) | 42:   | 43: + | 44:   | 45: c | 46: o | 47: n | 48: t | 49: r | 50: o | 51: l | 52: l | 53: a | 54: b | 55: i | 56: l | 57: i | 58: t | 59: y | 60: : | 61: 1 | 62: 5 | 63: ( | 64: p | 65: a | 66: r | 67: t | 68: i | 69: a | 70: l | 71: ) | 72:   | 73: - | 74:   | 75: m | 76: i | 77: t | 78: i | 79: g | 80: a | 81: t | 82: i | 83: o | 84: n | 85: s | 86: : | 87: 1 | 88: 0 | 89: ( | 90: F | 91: a | 92: u | 93: l | 94: t | 95: R | 96: e | 97: c | 98: o | 99: v | 100: e | 101: r | 102: y | 103: C | 104: m | 105: d | 106: T | 107: o | 108: S | 109: t | 110: r | 111: i | 112: n | 113: g | 114:   | 115: d | 116: e | 117: f | 118: a | 119: u | 120: l | 121: t | 122:   | 123: c | 124: a | 125: s | 126: e | 127: )

---

### [SEC-INFER-003] Integer Overflow in Output Length Calculation - GenerateInferRequest

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: CONFIRMED | **来源**: dataflow-infer_interface-scanner

**位置**: `src/server/endpoint/single_req_infer_interface/single_req_infer_interface_base.cpp:466-476` @ `GenerateInferRequest`
**模块**: infer_interface
**跨模块**: infer_interface → single_req_infer_interface_base

**描述**: Integer overflow vulnerability in maxOutputLen calculation. The GenerateInferRequest function computes maxOutputLen as inputParam->maxNewTokens - static_cast<int>(inputParam->outputLenOffset). Both values are derived from user-controlled parameters. If maxNewTokens is at INT32_MAX and outputLenOffset is negative (due to the overflow in GetTokensFromInput), the subtraction could overflow. Even though there is a check for maxOutputLen < 0, the subsequent cast to uint64_t (request_->maxOutputLen = static_cast<uint64_t>(maxOutputLen)) could wrap a negative value to a large positive value, leading to excessive memory allocation or incorrect inference behavior.

**漏洞代码** (`src/server/endpoint/single_req_infer_interface/single_req_infer_interface_base.cpp:466-476`)

```c
int maxOutputLen = inputParam->maxNewTokens - static_cast<int>(inputParam->outputLenOffset);
if (maxOutputLen < 0) { ... }
request_->maxOutputLen = static_cast<uint64_t>(maxOutputLen);
```

**达成路径**

AssignMaxNewTokens() -> maxNewTokens (int32_t) -> outputLenOffset (from GetTokensFromInput) -> maxOutputLen calculation -> cast to uint64_t -> request_->maxOutputLen

**验证说明**: VALID: maxOutputLen calculation from user-controlled parameters. Check at line 467 (maxOutputLen<0) mitigates negative value case. Cast to uint64_t only happens after negative check. Remaining risk: overflow from extreme positive values.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: : | 23: 3 | 24: 0 | 25: ( | 26: i | 27: n | 28: d | 29: i | 30: r | 31: e | 32: c | 33: t | 34: _ | 35: e | 36: x | 37: t | 38: e | 39: r | 40: n | 41: a | 42: l | 43: ) | 44:   | 45: + | 46:   | 47: c | 48: o | 49: n | 50: t | 51: r | 52: o | 53: l | 54: l | 55: a | 56: b | 57: i | 58: l | 59: i | 60: t | 61: y | 62: : | 63: 1 | 64: 5 | 65: ( | 66: p | 67: a | 68: r | 69: t | 70: i | 71: a | 72: l | 73: ) | 74:   | 75: - | 76:   | 77: m | 78: i | 79: t | 80: i | 81: g | 82: a | 83: t | 84: i | 85: o | 86: n | 87: s | 88: : | 89: 1 | 90: 0 | 91: ( | 92: n | 93: e | 94: g | 95: a | 96: t | 97: i | 98: v | 99: e | 100:   | 101: v | 102: a | 103: l | 104: u | 105: e | 106:   | 107: c | 108: h | 109: e | 110: c | 111: k | 112: )

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| daemon | 0 | 3 | 0 | 0 | 3 |
| grpc_communicator | 0 | 1 | 0 | 0 | 1 |
| grpc_endpoint | 0 | 1 | 0 | 0 | 1 |
| http_endpoint | 0 | 1 | 0 | 0 | 1 |
| infer_instances | 0 | 0 | 1 | 0 | 1 |
| infer_interface | 0 | 2 | 2 | 0 | 4 |
| ipc_communicator | 0 | 0 | 0 | 0 | 0 |
| llm_manager | 0 | 0 | 0 | 0 | 0 |
| request_handler | 0 | 0 | 0 | 0 | 0 |
| **合计** | **0** | **8** | **3** | **0** | **11** |

## 7. Remediation Recommendations

以下针对各类已确认漏洞提供具体修复建议和最佳实践参考。

### 7.1 Signal Handler Safety (CWE-479) — DAEMON-001, DAEMON-002, DAEMON-003

**问题根源**: 在异步信号上下文中调用非 POSIX 信号安全函数。

**修复策略**: 采用 Self-Pipe Technique 或 signalfd 方案。

**具体实现**:

```cpp
// 推荐方案: Self-Pipe Technique
// 1. 创建专用管道
int signalPipe[2];
pipe2(signalPipe, O_NONBLOCK);

// 2. 信号处理函数仅写入管道
void SignalInterruptHandler(int sig)
{
    // 仅使用异步信号安全函数
    char sigNum = static_cast<char>(sig);
    write(signalPipe[1], &sigNum, 1);  // write() 是 POSIX 信号安全函数
}

// 3. 专用线程处理信号
void SignalHandlerThread()
{
    char sigNum;
    while (read(signalPipe[0], &sigNum, 1) > 0) {
        // 在此线程中执行所有非信号安全操作
        ULOG_WARN(...);
        std::unique_lock<std::mutex> lock(g_exitMtx);
        g_processExit = true;
        g_exitCv.notify_all();
        KillProcessGroup();
    }
}
```

**参考资料**:
- POSIX.1-2008, Section 2.4: Signal Concepts
- "Secure Programming for Linux and Unix" - Signal Handling

---

### 7.2 Array Index Validation (CWE-129/125) — SEC-INFER-004, IPC-001

**问题根源**: 使用用户控制的值作为数组边界，未验证其合法性。

**修复策略**: 强制边界检查，遵循 "先验证后使用" 原则。

**具体实现**:

```cpp
// SEC-INFER-004 修复
void BuildReComputeInput(std::vector<int64_t> &inputTokens)
{
    // 添加边界检查
    if (oriReqTokenLen_ > reqTokens_.size()) {
        ULOG_ERROR(SUBMODLE_NAME_ENDPOINT, 
                   "Invalid oriReqTokenLen_: " << oriReqTokenLen_ 
                   << " exceeds reqTokens_.size(): " << reqTokens_.size());
        throw std::runtime_error("Invalid recompute token length");
    }
    inputTokens.push_back(oriReqTokenLen_);
    for (size_t i = 0; i < oriReqTokenLen_; i++) {
        inputTokens.push_back(reqTokens_[i]);
    }
}

// IPC-001 修复
bool ParseResponse(ExecuteResponse &executeResponse, char *sharedBuf, size_t bufferSize)
{
    if (bufferSize < sizeof(uint32_t)) {
        return false;
    }
    uint32_t messageSize = *reinterpret_cast<uint32_t *>(sharedBuf);
    
    // 边界检查
    if (messageSize > bufferSize - sizeof(uint32_t)) {
        MINDIE_LLM_LOG_ERROR("Message size exceeds buffer boundary: " 
                             << messageSize << " > " << bufferSize);
        return false;
    }
    return executeResponse.ParseFromArray(sharedBuf + sizeof(uint32_t), messageSize);
}
```

---

### 7.3 Path Traversal (CWE-22) — CVE-MINDIE-001

**问题根源**: 路径验证正则表达式存在缺陷，未进行路径规范化。

**修复策略**: 多层防御：禁止绝对路径 + 路径规范化 + 目录白名单。

**具体实现**:

```cpp
// 推荐修复方案
#include <sys/stat.h>
#include <limits.h>

bool ValidateLoRAPath(const std::string &loraPath, const std::string &allowedDir)
{
    // 1. 禁止绝对路径
    if (!loraPath.empty() && loraPath[0] == '/') {
        return false;
    }
    
    // 2. 禁止路径遍历序列
    if (loraPath.find("..") != std::string::npos) {
        return false;
    }
    
    // 3. 构建完整路径并规范化
    std::string fullPath = allowedDir + "/" + loraPath;
    char resolvedPath[PATH_MAX];
    if (!realpath(fullPath.c_str(), resolvedPath)) {
        return false;  // 路径不存在或解析失败
    }
    
    // 4. 验证规范化路径位于允许目录内
    char resolvedAllowedDir[PATH_MAX];
    if (!realpath(allowedDir.c_str(), resolvedAllowedDir)) {
        return false;
    }
    
    std::string resolvedPathStr(resolvedPath);
    std::string allowedDirStr(resolvedAllowedDir);
    
    if (resolvedPathStr.find(allowedDirStr) != 0) {
        return false;  // 路径不在白名单目录内
    }
    
    return true;
}
```

**参考资料**:
- CWE-22: Improper Limitation of a Pathname
- OWASP Path Traversal Prevention Cheat Sheet

---

### 7.4 Division by Zero (CWE-369) — VULN-RH-008

**问题根源**: 使用未验证的变量作为除数。

**修复策略**: 零值检查 + 异常处理。

**具体实现**:

```cpp
// VULN-RH-008 修复
void SingleLLMReqHandlerBase::MetricsCallback(const ResponseSPtr &response)
{
    outputLen = response->responseContents.at(0).speculativeTokenNum;
    
    // 添加零值检查
    if (outputLen == 0) {
        ULOG_WARN(SUBMODLE_NAME_ENDPOINT, "Zero output length in metrics calculation");
        // 处理特殊情况：使用 decodeTime 作为单 token 时间
        metrics.decodeTime.push_back(decodeTime);
        return;
    }
    
    // 正常计算
    auto avgDecodeTime = (decodeTime + outputLen / 2) / outputLen;
    for (size_t i = 0; i < outputLen; ++i) {
        metrics.decodeTime.push_back(avgDecodeTime);
    }
}
```

---

### 7.5 Integer Overflow (CWE-190) — SEC-INFER-001, SEC-INFER-002, SEC-INFER-003

**问题根源**: 整数类型转换未检查溢出，负值转无符号类型导致数值翻转。

**修复策略**: 使用安全转换函数 + 范围检查。

**具体实现**:

```cpp
// 安全整数转换模板
template<typename T, typename S>
bool SafeCast(S source, T &target)
{
    if (source < std::numeric_limits<T>::min() || 
        source > std::numeric_limits<T>::max()) {
        return false;
    }
    target = static_cast<T>(source);
    return true;
}

// SEC-INFER-001 修复示例
int64_t tokenValue = std::stoll(token);
if (tokenValue < 0) {
    errorMsg = "Negative token value not allowed";
    return false;
}
uint64_t safeValue;
if (!SafeCast(tokenValue, safeValue)) {
    errorMsg = "Token value overflow";
    return false;
}
oriReqTokenLen_ = safeValue;
```

---

### 7.6 Memory Exhaustion (CWE-789) — VULN-GRPC-001

**问题根源**: 网络提供的数组大小直接用于内存分配，无上限约束。

**修复策略**: 设置合理上限 + 请求速率限制。

**具体实现**:

```cpp
// VULN-GRPC-001 修复
constexpr int MAX_BLOCKTABLE_SIZE = 10000;  // 合理上限

Status HandleDecodeRequest(DecodeParameters *para, KvCacheInfo &kvCacheInfo)
{
    int blockTableSize = para->blocktable_size();
    
    // 添加上限检查
    if (blockTableSize > MAX_BLOCKTABLE_SIZE) {
        return Status::InvalidArgument("BlockTable size exceeds limit");
    }
    
    kvCacheInfo.blockTable.resize(blockTableSize);
    for (int i = 0; i < blockTableSize; ++i) {
        int blockIdSize = para->blocktable()[i].blockid_size();
        if (blockIdSize > MAX_BLOCKTABLE_SIZE) {
            return Status::InvalidArgument("BlockId size exceeds limit");
        }
        // 处理逻辑...
    }
    return Status::OK;
}
```

---

### 7.7 Input Validation (CWE-20) — DFLOW-001

**问题根源**: 网络输入未进行格式验证。

**修复策略**: 使用现有验证函数 + 白名单检查。

**具体实现**:

```cpp
// DFLOW-001 修复
Status MasterServiceImpl::RegisterAndCommunicate(ServerContext *context,
    const RegisterRequestMsg *register_request, ServerWriter<MasterResponseMsg> *writer)
{
    std::string slaveIp = register_request->slave_ip();
    
    // 使用现有 CheckIp 函数验证 IP 格式
    if (!CheckIp(slaveIp)) {
        ULOG_ERROR(SUBMODLE_NAME_EXECUTOR, "Invalid slave IP format: " << slaveIp);
        return Status::InvalidArgument("Invalid IP format");
    }
    
    // 存储验证后的 IP
    gRPCCommunicator->SlaveIpToStream().Insert(slaveIp, stream);
    return Status::OK;
}
```

---

### 7.8 Improper Exception Handling (CWE-252) — VULN-INF-002

**问题根源**: 关键转换函数未捕获异常。

**修复策略**: 全面的异常捕获 + 错误传播。

**具体实现**:

```cpp
// VULN-INF-002 修复
for (auto &id : Split(ipInfo[local_logic_device_id], ',')) {
    try {
        int deviceId = std::stoi(id);
        if (deviceId < 0) {
            throw std::out_of_range("Negative device ID");
        }
        deviceIds.insert(static_cast<size_t>(deviceId));
    } catch (const std::invalid_argument &e) {
        ULOG_ERROR(SUBMODLE_NAME_INFER, "Invalid device ID format: " << id);
        return Status::InvalidArgument("Invalid device ID format");
    } catch (const std::out_of_range &e) {
        ULOG_ERROR(SUBMODLE_NAME_INFER, "Device ID out of range: " << id);
        return Status::OutOfRange("Device ID out of range");
    }
}
```

---

## 8. Security Best Practices Recommendations

### 8.1 输入验证框架

建议建立统一的输入验证框架：

```cpp
// 建议的验证器接口
class InputValidator {
public:
    static bool ValidateInteger(int64_t value, int64_t min, int64_t max);
    static bool ValidateString(const std::string &str, size_t maxLen, const std::string &pattern);
    static bool ValidatePath(const std::string &path, const std::string &allowedDir);
    static bool ValidateArraySize(size_t size, size_t maxSize);
};
```

### 8.2 安全编码规范

1. **边界检查**: 所有数组访问前必须验证索引
2. **类型转换**: 使用 `SafeCast` 等安全转换函数
3. **异常处理**: 关键转换操作必须有 try-catch
4. **路径处理**: 所有文件路径必须规范化并白名单验证
5. **信号处理**: 仅在信号处理函数中使用 POSIX 信号安全函数

### 8.3 测试建议

1. 添加单元测试覆盖所有边界条件（零值、负值、极大值）
2. 集成模糊测试（fuzz testing）验证输入处理
3. 建立安全回归测试套件，防止漏洞修复后再引入

---

## 9. Summary

本次扫描确认了 **25 个安全漏洞**，其中 **8 个高危漏洞** 需要立即修复。核心问题集中在：

| 问题类别 | 根本原因 | 修复优先级 |
|---------|---------|-----------|
| Signal Handler Safety | 违反 POSIX 规范，异步上下文调用非安全函数 | P0 |
| Input Validation | 用户输入未验证即用于关键操作 | P0 |
| Path Traversal | 路径验证正则缺陷，无规范化 | P1 |
| Arithmetic Errors | 整数溢出、除零未检查 | P1 |

建议在下一个版本发布前完成所有 P0 级别漏洞修复，并建立安全编码规范防止类似问题再次引入。
