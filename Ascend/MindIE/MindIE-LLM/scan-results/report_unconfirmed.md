# 漏洞扫描报告 — 待确认漏洞

**项目**: MindIE-LLM
**扫描时间**: 2025-04-17T00:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## Executive Overview

本报告列出了 **42 个待确认的候选漏洞**，这些漏洞需要进一步人工验证以确定其真实性和可利用性。待确认漏洞分为两个置信度等级：

- **LIKELY (20 个)**: 有较强的证据表明漏洞存在，但需要补充验证
- **POSSIBLE (22 个)**: 存在潜在风险模式，需要深入分析确认

### 待确认漏洞分布

| 严重性 | LIKELY | POSSIBLE | 主要模块 |
|--------|---------|----------|---------|
| High | 3 | 3 | config_manager, python_connector |
| Medium | 9 | 10 | grpc_endpoint, grpc_communicator, config_manager |
| Low | 2 | 8 | infer_instances, endpoint_utils |

### 常见漏洞模式分析

待确认漏洞主要集中在以下模式：

1. **Path Traversal (CWE-22)** - 6 个候选
   - 配置管理模块：`modelWeightPath` 构建文件路径后验证
   - Python connector：`shm_name_prefix` 用户可控
   - **验证重点**: 确认配置文件是否为管理员可控，以及验证顺序是否确实存在问题

2. **Integer Overflow (CWE-190)** - 10 个候选
   - 配置管理模块：`std::stoi/stoul` 转换后直接使用
   - Endpoint utils：int64 到 int32 类型截断
   - **验证重点**: 确认输入源信任等级，是否存在实际触发路径

3. **Input Validation (CWE-20)** - 7 个候选
   - gRPC 通信：枚举值、数组大小未验证
   - **验证重点**: 确认是否存在有效的输入边界检查

4. **Resource Exhaustion (CWE-400/789)** - 6 个候选
   - JSON 深度解析无限制
   - gRPC 消息大小限制不足
   - **验证重点**: 确认是否存在实际的内存耗尽触发路径

---

## Verification Priority Matrix

以下矩阵根据**可利用性**、**影响范围**和**验证难度**对待确认漏洞进行优先级排序。

### Priority 1: 立即验证 (高影响 + 易触发)

| 漏洞 ID | 类型 | 模块 | 置信度 | 验证优先级理由 |
|---------|------|------|--------|--------------|
| VULN-CFG-004/005/011 | Path Traversal | config_manager | 65% | 配置文件路径构建顺序存在明显缺陷，影响模型加载安全 |
| DFLOW-002 | Array Index OOB | grpc_communicator | 70% | 网络输入作为 map key，可能导致访问异常 |
| CVE-MINDIE-002 | Resource Exhaustion | http_endpoint | 65% | JSON 解析无深度限制，直接影响 HTTP API 稳定性 |

### Priority 2: 尽快验证 (中影响 + 存在触发路径)

| 漏洞 ID | 类型 | 模块 | 置信度 | 验证优先级理由 |
|---------|------|------|--------|--------------|
| VULN-GRPC-002 | Input Validation | grpc_endpoint | 65% | gRPC 请求验证不充分，影响 decode 请求处理 |
| VULN-GRPC-003 | Resource Exhaustion | grpc_endpoint | 65% | 线程资源无限制，可能导致服务拒绝 |
| DFLOW-004 | Input Validation | grpc_communicator | 65% | 网络枚举值未验证，可能导致逻辑错误 |
| SEC-001/002 | Info Exposure | grpc_communicator | 65% | TLS 私钥内存未清理，本地攻击者可能利用 |

### Priority 3: 按需验证 (低影响或高验证难度)

| 漏洞 ID | 类型 | 模块 | 置信度 | 验证优先级理由 |
|---------|------|------|--------|--------------|
| VULN-CFG-001/002/003 | Integer Overflow | config_manager | 45-60% | 配置文件输入，信任等级为 trusted_admin，实际风险较低 |
| VULN-PYCONN-001/002 | Path Traversal | python_connector | 65% | 共享内存名称前缀可控，但有 ownership check 保护 |
| VULN-INF-003/005/007 | Input Validation | infer_instances | 60-75% | 内部 API 调用，信任边界为 internal，影响有限 |
| VULN-EP-004 | Integer Truncation | endpoint_utils | 55% | 有显式范围检查，实际溢出可能性低 |

---

## Recommended Verification Actions

### 1. Path Traversal 验证步骤

对于 `VULN-CFG-004/005/011` 和 `VULN-PYCONN-001/002`:

```
验证清单:
[ ] 确认输入源是否为外部可控（配置文件管理员控制 vs. 用户输入）
[ ] 检查 SafePath::Check() 函数的实际验证逻辑
[ ] 尝试构造恶意路径触发漏洞（测试环境）
[ ] 确认 CheckParam() 验证时机是否确实在文件读取之后
[ ] Python connector: 确认 shm_name_prefix 的 ownership check 是否有效
```

### 2. Integer Overflow 验证步骤

对于配置管理模块的整数转换问题:

```
验证清单:
[ ] 确认配置文件是否由管理员控制（信任边界: trusted_admin）
[ ] 测试边界值（负值、INT_MAX、INT_MIN）的实际行为
[ ] 检查是否存在有效的 try-catch 或范围检查
[ ] 确认溢出后的实际影响（服务崩溃 vs. 逻辑错误）
```

### 3. Input Validation 验证步骤

对于 gRPC 输入验证问题:

```
验证清单:
[ ] 检查 protobuf 定义中是否有 IsValid() 函数
[ ] 确认是否有其他位置存在补充验证
[ ] 构造超出范围的输入测试实际行为
[ ] 确认错误处理的完整性（是否有异常捕获）
```

### 4. Resource Exhaustion 验证步骤

对于 JSON 深度解析和线程资源问题:

```
验证清单:
[ ] 确认 JSON 解析库的默认深度限制
[ ] 测试深层嵌套 JSON 的实际解析行为
[ ] 检查是否有请求速率限制机制
[ ] 测试大量并发请求的资源消耗情况
```

---

## 验证后预期处理

根据验证结果，候选漏洞将被分类处理：

| 验证结果 | 处理方式 |
|---------|---------|
| 真漏洞，可利用 | 升级为 CONFIRMED，添加修复方案 |
| 真漏洞，不可利用 | 标记为 FALSE_POSITIVE，记录原因 |
| 需要更多信息 | 保持 POSSIBLE，补充详细分析 |
| 误报 | 标记为 FALSE_POSITIVE，记录误报原因 |

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
| High | 6 | 14.3% |
| Medium | 19 | 45.2% |
| Low | 10 | 23.8% |
| **有效漏洞总计** | **42** | - |
| 误报 (FALSE_POSITIVE) | 21 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-CFG-004]** Path Traversal (High) - `src/config_manager/model_deploy_config.cpp:57` @ `GetJsonModelConfig` | 置信度: 65
2. **[VULN-CFG-005]** Path Traversal (High) - `src/config_manager/model_deploy_config.cpp:79` @ `GetJsonModelConfig` | 置信度: 65
3. **[VULN-CFG-011]** Path Traversal (High) - `src/config_manager/model_deploy_config.cpp:319` @ `InitLoraConfigFromFile` | 置信度: 65
4. **[VULN-PYCONN-001]** Path Traversal (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/mindie_llm/connector/request_listener/shared_mem_communication.py:66` @ `SharedMemoryChannel.open_channel` | 置信度: 65
5. **[VULN-PYCONN-002]** Path Traversal (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/mindie_llm/connector/request_listener/shared_mem_communication.py:108` @ `SharedMemoryChannel.open_error_response_channel` | 置信度: 65
6. **[VULN-CFG-001]** Integer Overflow (High) - `src/config_manager/config_manager_impl.cpp:314` @ `ConfigManager::Impl::CheckLayerwiseDisaggregatedParam` | 置信度: 60
7. **[DFLOW-002]** Array Index Bounds Check (Medium) - `src/executor/grpc_communicator.cpp:634` @ `MasterServiceImpl::RegisterAndCommunicate` | 置信度: 70
8. **[SEC-001]** Sensitive Information Exposure (Medium) - `src/executor/grpc_communicator.cpp:702` @ `LoadCertificates` | 置信度: 65
9. **[SEC-002]** Sensitive Information Exposure (Medium) - `src/executor/grpc_communicator.h:136` @ `GRPCCommunicator` | 置信度: 65
10. **[CVE-MINDIE-002]** Resource Exhaustion (Medium) - `src/server/endpoint/http_wrapper/http_handler.cpp:1191` @ `HandlePDWiseUpdateNpuDeviceIds` | 置信度: 65

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

## 3. High 漏洞 (6)

### [VULN-CFG-004] Path Traversal - GetJsonModelConfig

**严重性**: High | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/config_manager/model_deploy_config.cpp:57` @ `GetJsonModelConfig`
**模块**: config_manager

**描述**: User-controlled modelWeightPath from JSON config is concatenated directly to construct modelConfigPath before validation. SafePath::Check() validation happens in CheckParam() AFTER the file is already read via LoadJson().

**漏洞代码** (`src/config_manager/model_deploy_config.cpp:57`)

```c
std::string modelConfigPath = modelConfig.modelWeightPath + "/config.json";
```

**达成路径**

JSON ModelConfig -> modelWeightPath -> concatenate "/config.json" -> LoadJson(modelConfigPath) -> reads arbitrary file. Validation in CheckParam() happens later.

**验证说明**: Config file source but serious: modelWeightPath constructs file path before validation. Path traversal possible if config is compromised.

**评分明细**: base: 30 | reachability: 5 | controllability: 20 | mitigations: 0 | context: -10 | cross_file: 0

---

### [VULN-CFG-005] Path Traversal - GetJsonModelConfig

**严重性**: High | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/config_manager/model_deploy_config.cpp:79` @ `GetJsonModelConfig`
**模块**: config_manager

**描述**: Same pattern as VULN-CFG-004. User-controlled modelWeightPath constructs generation_config.json path before validation.

**漏洞代码** (`src/config_manager/model_deploy_config.cpp:79`)

```c
std::string modelGenerationConfigPath = modelConfig.modelWeightPath + "/generation_config.json";
```

**达成路径**

JSON ModelConfig -> modelWeightPath -> concatenate "/generation_config.json" -> LoadJson() -> reads file before validation

**验证说明**: Config file source but serious: Same pattern as VULN-CFG-004. Path constructed before validation.

**评分明细**: base: 30 | reachability: 5 | controllability: 20 | mitigations: 0 | context: -10 | cross_file: 0

---

### [VULN-CFG-011] Path Traversal - InitLoraConfigFromFile

**严重性**: High | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/config_manager/model_deploy_config.cpp:319` @ `InitLoraConfigFromFile`
**模块**: config_manager

**描述**: User-controlled weightPath (derived from modelWeightPath) concatenated to construct lora_adapter.json path before validation.

**漏洞代码** (`src/config_manager/model_deploy_config.cpp:319`)

```c
filepath = weightPath + "/lora_adapter.json";
```

**达成路径**

JSON ModelConfig -> modelWeightPath -> weightPath -> concatenate "/lora_adapter.json" -> GetJsonData() -> reads file

**验证说明**: Config file source but serious: weightPath constructs lora_adapter.json path before validation.

**评分明细**: base: 30 | reachability: 5 | controllability: 20 | mitigations: 0 | context: -10 | cross_file: 0

---

### [VULN-PYCONN-001] Path Traversal - SharedMemoryChannel.open_channel

**严重性**: High | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/mindie_llm/connector/request_listener/shared_mem_communication.py:66-72` @ `SharedMemoryChannel.open_channel`
**模块**: python_connector

**达成路径**

Source: config.shm_name_prefix (from main.py command line args, line 33-34) -> Sink: os.stat() in check_owner_and_permission() -> Attacker controls shm_name_prefix via CLI

**验证说明**: Path traversal via shm_name_prefix. Pre-validated: false.

**评分明细**: 0: I | 1: n | 2: i | 3: t | 4: i | 5: a | 6: l | 7: : | 8: 8 | 9: 5 | 10: - | 11: > | 12: V | 13: e | 14: r | 15: i | 16: f | 17: i | 18: e | 19: d | 20: : | 21: 7 | 22: 5 | 23: . | 24:   | 25: P | 26: a | 27: t | 28: h | 29:   | 30: t | 31: r | 32: a | 33: v | 34: e | 35: r | 36: s | 37: a | 38: l | 39:   | 40: e | 41: x | 42: i | 43: s | 44: t | 45: s | 46:   | 47: b | 48: u | 49: t | 50:   | 51: m | 52: i | 53: t | 54: i | 55: g | 56: a | 57: t | 58: e | 59: d | 60:   | 61: b | 62: y | 63:   | 64: o | 65: w | 66: n | 67: e | 68: r | 69: s | 70: h | 71: i | 72: p | 73:   | 74: c | 75: h | 76: e | 77: c | 78: k | 79: . | 80:   | 81: S | 82: e | 83: v | 84: e | 85: r | 86: i | 87: t | 88: y | 89:   | 90: d | 91: o | 92: w | 93: n | 94: g | 95: r | 96: a | 97: d | 98: e | 99: d | 100:   | 101: H | 102: I | 103: G | 104: H | 105: - | 106: > | 107: M | 108: E | 109: D | 110: I | 111: U | 112: M | 113:   | 114: d | 115: u | 116: e | 117:   | 118: t | 119: o | 120:   | 121: d | 122: e | 123: f | 124: e | 125: n | 126: s | 127: e | 128: - | 129: i | 130: n | 131: - | 132: d | 133: e | 134: p | 135: t | 136: h | 137:   | 138: m | 139: i | 140: t | 141: i | 142: g | 143: a | 144: t | 145: i | 146: o | 147: n | 148: .

---

### [VULN-PYCONN-002] Path Traversal - SharedMemoryChannel.open_error_response_channel

**严重性**: High | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/mindie_llm/connector/request_listener/shared_mem_communication.py:108-122` @ `SharedMemoryChannel.open_error_response_channel`
**模块**: python_connector

**达成路径**

Source: config.shm_name_prefix -> Sink: posix_ipc.Semaphore() and shm.SharedMemory() with unsanitized path

**验证说明**: Path traversal via shm_name_prefix in error channel. Pre-validated: false.

**评分明细**: 0: I | 1: n | 2: i | 3: t | 4: i | 5: a | 6: l | 7: : | 8: 8 | 9: 5 | 10: - | 11: > | 12: V | 13: e | 14: r | 15: i | 16: f | 17: i | 18: e | 19: d | 20: : | 21: 7 | 22: 5 | 23: . | 24:   | 25: S | 26: a | 27: m | 28: e | 29:   | 30: p | 31: a | 32: t | 33: t | 34: e | 35: r | 36: n | 37:   | 38: a | 39: s | 40:   | 41: V | 42: U | 43: L | 44: N | 45: - | 46: P | 47: Y | 48: C | 49: O | 50: N | 51: N | 52: - | 53: 0 | 54: 0 | 55: 1 | 56: . | 57:   | 58: P | 59: a | 60: t | 61: h | 62:   | 63: t | 64: r | 65: a | 66: v | 67: e | 68: r | 69: s | 70: a | 71: l | 72:   | 73: e | 74: x | 75: i | 76: s | 77: t | 78: s | 79:   | 80: b | 81: u | 82: t | 83:   | 84: m | 85: i | 86: t | 87: i | 88: g | 89: a | 90: t | 91: e | 92: d | 93:   | 94: b | 95: y | 96:   | 97: o | 98: w | 99: n | 100: e | 101: r | 102: s | 103: h | 104: i | 105: p | 106:   | 107: c | 108: h | 109: e | 110: c | 111: k | 112: . | 113:   | 114: S | 115: e | 116: v | 117: e | 118: r | 119: i | 120: t | 121: y | 122:   | 123: d | 124: o | 125: w | 126: n | 127: g | 128: r | 129: a | 130: d | 131: e | 132: d | 133:   | 134: H | 135: I | 136: G | 137: H | 138: - | 139: > | 140: M | 141: E | 142: D | 143: I | 144: U | 145: M | 146: .

---

### [VULN-CFG-001] Integer Overflow - ConfigManager::Impl::CheckLayerwiseDisaggregatedParam

**严重性**: High | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/config_manager/config_manager_impl.cpp:314` @ `ConfigManager::Impl::CheckLayerwiseDisaggregatedParam`
**模块**: config_manager

**描述**: std::stol() converts string from JSON config to long, then cast to uint32_t without bounds validation. If the value is negative (returns 0) or exceeds uint32_t max (overflow), it can cause incorrect validation logic.

**漏洞代码** (`src/config_manager/config_manager_impl.cpp:314`)

```c
uint32_t dpNum = isFindDp ? std::stol(itrFindDp->second) : 0;
```

**达成路径**

JSON config -> modelConfig["dp"] -> itrFindDp->second (string) -> std::stol() -> uint32_t dpNum -> validation logic

**验证说明**: Config file source (admin-controlled): std::stol() to uint32_t without bounds validation. Lower confidence due to trusted config source, but still exploitable if config is compromised.

**评分明细**: base: 30 | reachability: 5 | controllability: 20 | mitigations: 0 | context: -20 | cross_file: 0

---

## 4. Medium 漏洞 (19)

### [DFLOW-002] Array Index Bounds Check - MasterServiceImpl::RegisterAndCommunicate

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-grpc_communicator-scanner

**位置**: `src/executor/grpc_communicator.cpp:634-645` @ `MasterServiceImpl::RegisterAndCommunicate`
**模块**: grpc_communicator

**描述**: target_dp_rank from network not validated for bounds before map access

**漏洞代码** (`src/executor/grpc_communicator.cpp:634-645`)

```c
int targetDPRank = client_msg.target_dp_rank()
```

**达成路径**

network int32 -> map key access [no bounds check]

**验证说明**: Pre-validated: target_dp_rank from network used as map key without bounds validation. External input via gRPC, could cause out-of-bounds access or denial of service.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-001] Sensitive Information Exposure - LoadCertificates

**严重性**: Medium | **CWE**: CWE-214 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/executor/grpc_communicator.cpp:702-706` @ `LoadCertificates`
**模块**: grpc_communicator

**描述**: Private key memory not cleared in destructor. The TLS private key is loaded and stored in the member variable 'tlsCertPrivateKey_' (std::string) without proper memory sanitization when the GRPCCommunicator object is destroyed. The destructor (lines 125-135) does not explicitly zero out the private key content, potentially leaving sensitive cryptographic material in memory after object destruction. This could be exploited through memory dumps or core dumps to extract private key material.

**漏洞代码** (`src/executor/grpc_communicator.cpp:702-706`)

```c
fs::path keyPath = fs::path(interNodeTlsPk_);
std::string keyContent;
ReadFileToString(keyPath, keyContent);
tlsCertPrivateKey_.assign(keyContent.data(), keyContent.size());
```

**达成路径**

interNodeTlsPk_ (config) -> ReadFileToString() -> keyContent (string) -> tlsCertPrivateKey_ (member variable, no cleanup)

**验证说明**: Pre-validated: Private key stored in std::string without secure memory clearing. Memory dump/core dump could expose key material. Lower confidence because requires local access to exploit.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: -15 | cross_file: 0

---

### [SEC-002] Sensitive Information Exposure - GRPCCommunicator

**严重性**: Medium | **CWE**: CWE-200 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/executor/grpc_communicator.h:136` @ `GRPCCommunicator`
**模块**: grpc_communicator

**描述**: Private key content stored in std::string without secure memory handling. Unlike the grpc_communication_mng.cpp implementation which uses OPENSSL_cleanse() to sanitize private key data, grpc_communicator.cpp stores the private key directly in std::string tlsCertPrivateKey_ without any secure memory clearing. std::string memory is not guaranteed to be securely cleared and may persist in memory after deallocation.

**漏洞代码** (`src/executor/grpc_communicator.h:136`)

```c
std::string tlsCertPrivateKey_;
```

**达成路径**

TLS private key loaded from file -> stored in std::string -> no OPENSSL_cleanse or memset_s used

**验证说明**: Pre-validated: Private key stored in std::string without OPENSSL_cleanse(). Memory persistence risk after deallocation. Requires local access to exploit via memory dumps.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: -15 | cross_file: 0

---

### [CVE-MINDIE-002] Resource Exhaustion - HandlePDWiseUpdateNpuDeviceIds

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-http_endpoint-scanner

**位置**: `src/server/endpoint/http_wrapper/http_handler.cpp:1191-1195` @ `HandlePDWiseUpdateNpuDeviceIds`
**模块**: http_endpoint

**描述**: At line 1191, ordered_json::parse(msgBody) is called without the CheckOrderedJsonDepthCallback. This differs from other parsing locations that use the depth callback. A malicious deeply nested JSON could cause stack exhaustion, memory exhaustion, or denial of service.

**漏洞代码** (`src/server/endpoint/http_wrapper/http_handler.cpp:1191-1195`)

```c
body = ordered_json::parse(msgBody); // Missing depth callback
```

**达成路径**

HTTP request body -> JSON parsing without depth limit -> Recursive parsing

**验证说明**: Pre-validated: JSON parsing at line 1191 without depth callback. Deeply nested JSON could cause stack/memory exhaustion. Other locations use depth callback.

**评分明细**: base: 30 | reachability: 30 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CVE-MINDIE-003] Integer Overflow - HandlePDWiseUpdateNpuDeviceIds

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-http_endpoint-scanner

**位置**: `src/server/endpoint/http_wrapper/http_handler.cpp:1196-1200` @ `HandlePDWiseUpdateNpuDeviceIds`
**模块**: http_endpoint

**描述**: Multiple locations parse integers from user input without proper validation using std::stoi/stoul. These can cause std::out_of_range exceptions, integer overflow when casting to smaller types, or potential negative value bypass if unsigned expected.

**漏洞代码** (`src/server/endpoint/http_wrapper/http_handler.cpp:1196-1200`)

```c
std::stoi(item["device_logical_id"].get<std::string>()) // No bounds check
```

**达成路径**

HTTP request JSON -> Integer parsing -> Device ID assignment

**验证说明**: Pre-validated: std::stoi/stoul parsing without bounds check. Integer overflow or out_of_range exceptions possible from user input.

**评分明细**: base: 30 | reachability: 30 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-GRPC-002] Input Validation - isValidRequest

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-grpc_endpoint-scanner

**位置**: `src/server/endpoint/grpc_wrapper/dmi_msg_receiver.cpp:54-79` @ `isValidRequest`
**模块**: grpc_endpoint

**描述**: Insufficient Input Validation in isValidRequest(). Only validates null pointers and maxnewtoken < 0. Missing validation for tokens, firstToken, outputNames array sizes, and string fields like reqId, tools, loraId, modelName.

**漏洞代码** (`src/server/endpoint/grpc_wrapper/dmi_msg_receiver.cpp:54-79`)

```c
isValidRequest() only checks para == nullptr and para->maxnewtoken() < 0
```

**达成路径**

DecodeRequestChannel -> isValidRequest() -> HandleDecodeRequest() -> downstream processing

**验证说明**: Pre-validated: isValidRequest() only checks null pointers and negative maxnewtoken. Missing validation for array sizes and string fields.

**评分明细**: base: 30 | reachability: 30 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-GRPC-003] Resource Exhaustion - ReleaseKVCacheChannel

**严重性**: Medium | **CWE**: CWE-404 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-grpc_endpoint-scanner

**位置**: `src/server/endpoint/grpc_wrapper/dmi_msg_receiver.cpp:101-106` @ `ReleaseKVCacheChannel`
**模块**: grpc_endpoint

**描述**: Thread Resource Exhaustion via Detached Threads. Each KV release request spawns a detached thread without rate limiting. Flood of requests could cause thread exhaustion.

**漏洞代码** (`src/server/endpoint/grpc_wrapper/dmi_msg_receiver.cpp:101-106`)

```c
std::thread([this, reqId]() { ... this->kvReleaseHandler_(reqId); }).detach();
```

**达成路径**

ReleaseKVCacheChannel -> detached thread -> kvReleaseHandler_ -> HandleKvRelease()

**验证说明**: Pre-validated: Detached threads spawned per KV release request without rate limiting. Flood could cause thread exhaustion.

**评分明细**: base: 30 | reachability: 30 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-GRPC-005] Memory Exhaustion - HandleDecodeRequest

**严重性**: Medium | **CWE**: CWE-789 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-grpc_endpoint-scanner

**位置**: `src/server/endpoint/grpc_wrapper/grpc_handler.cpp:94-96` @ `HandleDecodeRequest`
**模块**: grpc_endpoint

**描述**: dpInstanceIds Memory Exhaustion. Similar to blockTable issue - dpInstanceIds array processed without size validation.

**漏洞代码** (`src/server/endpoint/grpc_wrapper/grpc_handler.cpp:94-96`)

```c
for (int i = 0; i < para.dpinstanceids_size(); ++i) { kvCacheInfo.dpInstanceIds.push_back(para.dpinstanceids()[i]); }
```

**达成路径**

DecodeParameters.dpInstanceIds -> HandleDecodeRequest() -> kvCacheInfo.dpInstanceIds

**验证说明**: Pre-validated: dpInstanceIds array processed without size validation. Similar to blockTable issue, can cause memory exhaustion.

**评分明细**: base: 30 | reachability: 30 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-GRPC-006] Resource Exhaustion - GrpcCommunicationMng::Init

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-grpc_endpoint-scanner

**位置**: `src/server/endpoint/grpc_wrapper/grpc_communication_mng.cpp:44-50` @ `GrpcCommunicationMng::Init`
**模块**: grpc_endpoint

**描述**: Large gRPC Message Size combined with missing per-field validation. 16MB message limit allows large individual fields to cause resource exhaustion.

**漏洞代码** (`src/server/endpoint/grpc_wrapper/grpc_communication_mng.cpp:44-50`)

```c
max_receive_message_size = 16 * 1024 * 1024; // 16MB
```

**达成路径**

gRPC message -> message size validation -> field processing

**验证说明**: Pre-validated: 16MB gRPC message limit allows large fields. Combined with missing per-field validation enables resource exhaustion.

**评分明细**: base: 30 | reachability: 30 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [DFLOW-004] Input Validation - HandleRequestFromMaster

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-grpc_communicator-scanner

**位置**: `src/executor/grpc_communicator.cpp:560-581` @ `HandleRequestFromMaster`
**模块**: grpc_communicator

**描述**: execute_type from network not validated against enum range before use

**漏洞代码** (`src/executor/grpc_communicator.cpp:560-581`)

```c
request.execute_type() used in if-else
```

**达成路径**

network protobuf int -> if-else branches [no ExecuteType_IsValid]

**验证说明**: Pre-validated: execute_type from network protobuf not validated against enum range. Missing ExecuteType_IsValid() check allows invalid values in if-else branches.

**评分明细**: base: 30 | reachability: 30 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [DFLOW-005] Path Traversal - LoadCertificates

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-grpc_communicator-scanner

**位置**: `src/executor/grpc_communicator.cpp:682-709` @ `LoadCertificates`
**模块**: grpc_communicator

**描述**: TLS certificate paths lack expected-directory validation after CanonicalPath

**漏洞代码** (`src/executor/grpc_communicator.cpp:682-709`)

```c
fs::path certPath = interNodeTlsCert_; ReadFileToString(certPath, tlsCert_)
```

**达成路径**

config path -> CanonicalPath -> file read [no whitelist check]

**验证说明**: Pre-validated: TLS certificate paths lack whitelist validation after CanonicalPath. Config-derived paths could potentially read arbitrary certificate files.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: -20 | cross_file: 0

---

### [VULN-EP-004-INT-OVERFLOW] integer_truncation - AssignMaxTokens,AssignTopK

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/src/server/endpoint/utils/infer_param.cpp:536-602` @ `AssignMaxTokens,AssignTopK`
**模块**: endpoint_utils

**描述**: Integer values from JSON input (int64_t) are cast to smaller types (int32_t) without overflow checking. While range validation exists before casting in some cases, the static_cast operations at lines 536 and 602 could truncate values if validation logic is bypassed.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/src/server/endpoint/utils/infer_param.cpp:536-602`)

```c
param->maxNewTokens = static_cast<int32_t>(value); tmpReq->topK = static_cast<int32_t>(value);
```

**达成路径**

JSON input -> jsonObj[key] -> int64_t value -> static_cast<int32_t> -> param field

**验证说明**: Integer truncation in int64_t to int32_t cast. Pre-validated: false.

**评分明细**: 0: R | 1: a | 2: n | 3: g | 4: e | 5:   | 6: v | 7: a | 8: l | 9: i | 10: d | 11: a | 12: t | 13: i | 14: o | 15: n | 16:   | 17: e | 18: x | 19: i | 20: s | 21: t | 22: s | 23:   | 24: b | 25: e | 26: f | 27: o | 28: r | 29: e | 30:   | 31: c | 32: a | 33: s | 34: t | 35: : | 36:   | 37: M | 38: A | 39: X | 40: _ | 41: I | 42: N | 43: T | 44: 3 | 45: 2 | 46: _ | 47: V | 48: A | 49: L | 50: U | 51: E | 52:   | 53: c | 54: h | 55: e | 56: c | 57: k | 58:   | 59: p | 60: r | 61: e | 62: v | 63: e | 64: n | 65: t | 66: s | 67:   | 68: o | 69: v | 70: e | 71: r | 72: f | 73: l | 74: o | 75: w | 76: . | 77:   | 78: L | 79: i | 80: n | 81: e | 82: s | 83:   | 84: 5 | 85: 3 | 86: 2 | 87:   | 88: a | 89: n | 90: d | 91:   | 92: 5 | 93: 9 | 94: 6 | 95:   | 96: e | 97: x | 98: p | 99: l | 100: i | 101: c | 102: i | 103: t | 104: l | 105: y | 106:   | 107: c | 108: h | 109: e | 110: c | 111: k | 112:   | 113: v | 114: a | 115: l | 116: u | 117: e | 118:   | 119: < | 120: = | 121:   | 122: M | 123: A | 124: X | 125: _ | 126: I | 127: N | 128: T | 129: 3 | 130: 2 | 131: _ | 132: V | 133: A | 134: L | 135: U | 136: E | 137:   | 138: b | 139: e | 140: f | 141: o | 142: r | 143: e | 144:   | 145: s | 146: t | 147: a | 148: t | 149: i | 150: c | 151: _ | 152: c | 153: a | 154: s | 155: t | 156: < | 157: i | 158: n | 159: t | 160: 3 | 161: 2 | 162: _ | 163: t | 164: > | 165: . | 166:   | 167: M | 168: A | 169: X | 170: _ | 171: I | 172: N | 173: T | 174: 3 | 175: 2 | 176: _ | 177: V | 178: A | 179: L | 180: U | 181: E | 182:   | 183: = | 184:   | 185: s | 186: t | 187: d | 188: : | 189: : | 190: n | 191: u | 192: m | 193: e | 194: r | 195: i | 196: c | 197: _ | 198: l | 199: i | 200: m | 201: i | 202: t | 203: s | 204: < | 205: i | 206: n | 207: t | 208: 3 | 209: 2 | 210: _ | 211: t | 212: > | 213: : | 214: : | 215: m | 216: a | 217: x | 218: ( | 219: ) | 220: .

---

### [VULN-EP-006-BIO-WRITE] unbounded_bio_write - Encode

**严重性**: Medium | **CWE**: CWE-787 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/src/server/endpoint/utils/base64_util.cpp:20-44` @ `Encode`
**模块**: endpoint_utils

**描述**: Base64 encoding writes user input to BIO without size limit validation. While MAX_BUFFER_SIZE is defined (1024), it is never used to check input size before BIO_write. Very large inputs could cause memory exhaustion or buffer issues.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/src/server/endpoint/utils/base64_util.cpp:20-44`)

```c
const uint32_t MAX_BUFFER_SIZE = 1024; // unused... BIO_write(bio, input.data(), input.size());
```

**达成路径**

User Input -> Encode function -> BIO_write(input.data(), input.size()) -> No size check

**验证说明**: BIO_write without size limit. Pre-validated: false. MAX_BUFFER_SIZE defined but unused.

**评分明细**: 0: C | 1: o | 2: d | 3: e | 4:   | 5: s | 6: m | 7: e | 8: l | 9: l | 10: : | 11:   | 12: M | 13: A | 14: X | 15: _ | 16: B | 17: U | 18: F | 19: F | 20: E | 21: R | 22: _ | 23: S | 24: I | 25: Z | 26: E | 27: = | 28: 1 | 29: 0 | 30: 2 | 31: 4 | 32:   | 33: d | 34: e | 35: f | 36: i | 37: n | 38: e | 39: d | 40:   | 41: b | 42: u | 43: t | 44:   | 45: u | 46: n | 47: u | 48: s | 49: e | 50: d | 51: . | 52:   | 53: B | 54: I | 55: O | 56: _ | 57: w | 58: r | 59: i | 60: t | 61: e | 62:   | 63: u | 64: s | 65: e | 66: s | 67:   | 68: i | 69: n | 70: p | 71: u | 72: t | 73: . | 74: s | 75: i | 76: z | 77: e | 78: ( | 79: ) | 80:   | 81: w | 82: i | 83: t | 84: h | 85: o | 86: u | 87: t | 88:   | 89: d | 90: i | 91: r | 92: e | 93: c | 94: t | 95:   | 96: s | 97: i | 98: z | 99: e | 100:   | 101: c | 102: h | 103: e | 104: c | 105: k | 106: . | 107:   | 108: H | 109: o | 110: w | 111: e | 112: v | 113: e | 114: r | 115: , | 116:   | 117: u | 118: p | 119: s | 120: t | 121: r | 122: e | 123: a | 124: m | 125:   | 126: v | 127: a | 128: l | 129: i | 130: d | 131: a | 132: t | 133: i | 134: o | 135: n | 136:   | 137: i | 138: n | 139:   | 140: A | 141: s | 142: s | 143: i | 144: g | 145: n | 146: S | 147: t | 148: o | 149: p | 150: S | 151: t | 152: r | 153: i | 154: n | 155: g | 156: L | 157: i | 158: s | 159: t | 160: / | 161: A | 162: s | 163: s | 164: i | 165: g | 166: n | 167: S | 168: t | 169: o | 170: p | 171: S | 172: i | 173: n | 174: g | 175: l | 176: e | 177: S | 178: t | 179: r | 180: i | 181: n | 182: g | 183:   | 184: l | 185: i | 186: m | 187: i | 188: t | 189: s | 190:   | 191: i | 192: n | 193: p | 194: u | 195: t | 196: : | 197:   | 198: M | 199: A | 200: X | 201: _ | 202: S | 203: T | 204: O | 205: P | 206: _ | 207: S | 208: T | 209: R | 210: I | 211: N | 212: G | 213: _ | 214: L | 215: E | 216: N | 217: = | 218: 1 | 219: 0 | 220: 2 | 221: 4 | 222:   | 223: p | 224: e | 225: r | 226:   | 227: s | 228: t | 229: r | 230: i | 231: n | 232: g | 233: , | 234:   | 235: M | 236: A | 237: X | 238: _ | 239: T | 240: O | 241: T | 242: A | 243: L | 244: _ | 245: S | 246: T | 247: O | 248: P | 249: = | 250: 3 | 251: 2 | 252: K | 253: B | 254:   | 255: t | 256: o | 257: t | 258: a | 259: l | 260: , | 261:   | 262: M | 263: A | 264: X | 265: _ | 266: S | 267: T | 268: O | 269: P | 270: _ | 271: S | 272: T | 273: R | 274: I | 275: N | 276: G | 277: _ | 278: N | 279: U | 280: M | 281: = | 282: 1 | 283: 0 | 284: 2 | 285: 4 | 286:   | 287: c | 288: o | 289: u | 290: n | 291: t | 292: .

---

### [VULN-CFG-002] Integer Overflow - BackendConfigManager::UpdateMultiNodesInfer

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/config_manager/backend_config.cpp:262` @ `BackendConfigManager::UpdateMultiNodesInfer`
**模块**: config_manager

**描述**: std::stoi() converts deviceId string from ranktable JSON to int, then cast to size_t. deviceId values outside int range cause undefined behavior or truncation.

**漏洞代码** (`src/config_manager/backend_config.cpp:262`)

```c
npuDeviceId.insert(static_cast<size_t>(std::stoi(ele.deviceId)));
```

**达成路径**

Ranktable JSON -> device[].deviceId -> std::stoi() -> static_cast<size_t> -> npuDeviceId set

**验证说明**: Config file source: std::stoi() for deviceId with cast to size_t. Overflow possible but ranktable is admin-controlled.

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: -20 | cross_file: 0

---

### [VULN-CFG-003] Integer Overflow - GammaUpdate

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/config_manager/model_deploy_config.cpp:144` @ `GammaUpdate`
**模块**: config_manager

**描述**: Direct JSON get<uint32_t>() for num_speculative_tokens without prior bounds validation. JSON library may silently truncate values outside uint32_t range.

**漏洞代码** (`src/config_manager/model_deploy_config.cpp:144`)

```c
uint32_t gammaTmp = pluginConfig["num_speculative_tokens"].get<uint32_t>();
```

**达成路径**

JSON plugin_params -> parse -> pluginConfig["num_speculative_tokens"] -> get<uint32_t>() -> gammaTmp -> speculationGamma calculation

**验证说明**: Config file source: Direct JSON get<uint32_t>() without bounds validation. Silent truncation possible.

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: -20 | cross_file: 0

---

### [VULN-CFG-006] Resource Exhaustion - ParamChecker::ReadJsonFile

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/config_manager/param_checker.cpp:54` @ `ParamChecker::ReadJsonFile`
**模块**: config_manager

**描述**: JSON parsing using file >> jsonData without depth callback. While LoadJson() uses CheckJsonDepthCallbackNoLogger, this function does not. Deeply nested JSON can cause stack overflow or excessive memory allocation.

**漏洞代码** (`src/config_manager/param_checker.cpp:54`)

```c
file >> jsonData;
```

**达成路径**

Config file path -> std::ifstream -> operator>> (unlimited depth) -> jsonData (potential memory exhaustion)

**验证说明**: Config file source: JSON parsing without depth callback. Stack overflow possible but config is admin-controlled.

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: -20 | cross_file: 0

---

### [VULN-CFG-007] Resource Exhaustion - RanktableConfigManager::ReadRanktableData

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/config_manager/ranktable_config.cpp:67` @ `RanktableConfigManager::ReadRanktableData`
**模块**: config_manager

**描述**: Same issue as VULN-CFG-006. Ranktable JSON parsed without depth limit callback.

**漏洞代码** (`src/config_manager/ranktable_config.cpp:67`)

```c
file >> jsonData;
```

**达成路径**

RANK_TABLE_FILE env -> ifstream -> operator>> (no depth limit) -> jsonData

**验证说明**: Config file source: Same JSON depth issue in ranktable parser.

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: -20 | cross_file: 0

---

### [VULN-CFG-008] Integer Overflow - RanktableConfigManager::ReadRanktableData

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/config_manager/ranktable_config.cpp:71` @ `RanktableConfigManager::ReadRanktableData`
**模块**: config_manager

**描述**: std::stoi() converts server_count string to int, then cast to uint32_t. Values outside int range cause undefined behavior.

**漏洞代码** (`src/config_manager/ranktable_config.cpp:71`)

```c
serverCount = static_cast<uint32_t>(std::stoi(jsonData["server_count"].get<std::string>()));
```

**达成路径**

Ranktable JSON -> server_count (string) -> std::stoi() -> uint32_t -> serverCount

**验证说明**: Config file source: std::stoi() for server_count with cast to uint32_t.

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: -20 | cross_file: 0

---

### [VULN-CFG-009] Integer Overflow - CheckIfParallelInfoIsValid

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/config_manager/model_deploy_config.cpp:100` @ `CheckIfParallelInfoIsValid`
**模块**: config_manager

**描述**: std::stoi() converts parallel info (dp/sp/cp) from model config without range validation before use. Large values can overflow.

**漏洞代码** (`src/config_manager/model_deploy_config.cpp:100`)

```c
parallelSize = std::stoi(it->second);
```

**达成路径**

JSON modelConfig -> find("dp"/"sp"/"cp") -> it->second -> std::stoi() -> parallelSize -> validation

**验证说明**: Config file source: std::stoi() for parallel info without range validation.

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: -20 | cross_file: 0

---

## 5. Low 漏洞 (10)

### [VULN-INF-007] Missing Input Validation - InferInstance::Process

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/server/infer_instances/infer_instances.cpp:163-164` @ `InferInstance::Process`
**模块**: infer_instances
**跨模块**: infer_instances, llm_manager_v2

**描述**: Request object fields flow directly to LlmManager without validation.

**漏洞代码** (`src/server/infer_instances/infer_instances.cpp:163-164`)

```c
callbackMap.Insert(request->requestId, request->serverResponseCallback_); auto status = llmManagers_[chosen]->AddRequest(request);
```

**达成路径**

Request [external] -> llmManagers_[chosen]->AddRequest() [NO VALIDATION]

**验证说明**: POSSIBLE: Request object flows to LlmManager with minimal validation. However, CHECK_INITIALIZATION macro validates instance state, duplicate requestId is checked at lines 138-142, and the request source is internal API. Severity reduced from Medium to Low due to trust boundary.

**评分明细**: validation_checks: [object Object] | trust_boundary: internal_api | risk: Low - internal API calls only

---

### [VULN-INF-003] Improper Input Validation - ProcessDevice

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/server/infer_instances/infer_instances.cpp:454-462` @ `ProcessDevice`
**模块**: infer_instances
**跨模块**: infer_instances, http_wrapper

**描述**: Tainted data from GlobalIpInfo flows to ProcessDevice without adequate validation. The DeviceInfo fields come from external configuration/network sources and are directly used to populate internal structures.

**漏洞代码** (`src/server/infer_instances/infer_instances.cpp:454-462`)

```c
for (const auto &device : devicesIP) { dpInstance2Devices[instanceId].push_back({deviceIpAddress, devicePhysicalId}); if (superDeviceId != -1) { dpInstance2SuperDeviceIds[instanceId].push_back(superDeviceId); } }
```

**达成路径**

GlobalIpInfo.linkIpInfo/unlinkIpInfo -> DeviceInfo fields [NO VALIDATION] -> request structures

**验证说明**: POSSIBLE: DeviceInfo fields from GlobalIpInfo are used without explicit validation. However, the code is within the internal_api trust boundary and wrapped in try-catch. Severity reduced from Medium to Low due to trust boundary. Recommend adding validation as defense-in-depth.

**评分明细**: input_validation: [object Object] | trust_boundary: internal_api | exception_handling: [object Object] | risk: Low - internal calls only

---

### [VULN-INF-005] Integer Overflow - InferInstance::GetCacheBlockNums

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/server/infer_instances/infer_instances.cpp:279-298` @ `InferInstance::GetCacheBlockNums`
**模块**: infer_instances

**描述**: Unchecked integer accumulation in GetCacheBlockNums and similar metric collection functions. Values from EngineMetric are accumulated into uint64_t variables without overflow checking. If engine metrics report extremely large values (due to bugs or malicious input), the accumulated totals could overflow, leading to incorrect metric reporting and potential downstream issues in resource allocation decisions.

**漏洞代码** (`src/server/infer_instances/infer_instances.cpp:279-298`)

```c
for (auto &llmManager : llmManagers_) {\n    EngineMetric engineMetric = llmManager->CollectEngineMetric();\n    accumulatedFreeNpuBlocks += engineMetric.schedulerInfo.blockInfo.freeNpuBlockNum_;\n    accumulatedFreeCpuBlocks += engineMetric.schedulerInfo.blockInfo.freeCpuBlockNum_;\n    accumulatedTotalNpuBlocks += engineMetric.schedulerInfo.blockInfo.totalNpuBlockNum_;\n    accumulatedTotalCpuBlocks += engineMetric.schedulerInfo.blockInfo.totalCpuBlockNum_;\n}
```

**达成路径**

llmManagers_->CollectEngineMetric() -> engineMetric.schedulerInfo.blockInfo.freeNpuBlockNum_/freeCpuBlockNum_/totalNpuBlockNum_/totalCpuBlockNum_ [NO VALIDATION] -> accumulated* [POTENTIAL OVERFLOW] -> freeNpuBlockNums/freeCpuBlockNums/totalNpuBlockNums/totalCpuBlockNums [output params]

**验证说明**: POSSIBLE: Theoretical integer overflow when accumulating uint64_t block counts. However, uint64_t max (~18 quintillion) is practically unreachable for block counts. The data source (EngineMetric) is internal and trusted. Reduced severity from Medium to Low.

**评分明细**: overflow_analysis: [object Object] | trust_boundary: internal_api | data_source: EngineMetric (internal) | mitigation: uint64_t max is astronomically large for block counts

---

### [DFLOW-003] Improper Neutralization - SendRegistration

**严重性**: Low | **CWE**: CWE-79 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-grpc_communicator-scanner

**位置**: `src/executor/grpc_communicator.cpp:331-332` @ `SendRegistration`
**模块**: grpc_communicator

**描述**: slave_ip logged without sanitization in log messages. The slave_ip value from network registration is directly concatenated into log messages without sanitization.

**漏洞代码** (`src/executor/grpc_communicator.cpp:331-332`)

```c
MINDIE_LLM_LOG_INFO log message with slaveIp_
```

**达成路径**

slaveIp_ -> log message concatenation [NO sanitization]

**验证说明**: Pre-validated: slave_ip logged without sanitization. Potential log injection but limited impact - log files typically not security-critical.

**评分明细**: base: 30 | reachability: 30 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: -10

---

### [CVE-MINDIE-004] Resource Exhaustion - HttpServerInit

**严重性**: Low | **CWE**: CWE-400 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-http_endpoint-scanner

**位置**: `src/server/endpoint/http_wrapper/http_server.cpp:51-202` @ `HttpServerInit`
**模块**: http_endpoint

**描述**: PAYLOAD_MAX_LENGTH = 512MB allows very large request sizes. maxRequestLength default is 40MB, configurable up to 100MB. Could enable denial of service via memory exhaustion with large requests.

**漏洞代码** (`src/server/endpoint/http_wrapper/http_server.cpp:51-202`)

```c
PAYLOAD_MAX_LENGTH = 512MB; server.set_payload_max_length(GetMaxInputLen())
```

**达成路径**

HTTP request -> Payload size check -> Memory allocation

**验证说明**: Pre-validated: Large payload limits (512MB max, configurable). DoS via memory exhaustion possible but requires significant resources and is configurable.

**评分明细**: base: 30 | reachability: 30 | controllability: 0 | mitigations: -10 | context: 0 | cross_file: 0

---

### [CVE-MINDIE-005] SSRF - IsDTargetValid

**严重性**: Low | **CWE**: CWE-918 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-http_endpoint-scanner

**位置**: `src/server/endpoint/http_wrapper/http_handler.cpp:1924-1940` @ `IsDTargetValid`
**模块**: http_endpoint

**描述**: The d-target header is parsed and validated for IP format using CheckIp() which checks format but not destination. Could potentially be manipulated in DMI mode for server-side request forgery.

**漏洞代码** (`src/server/endpoint/http_wrapper/http_handler.cpp:1924-1940`)

```c
d-target header validation uses CheckIp() for format only
```

**达成路径**

HTTP header d-target -> IP format validation -> Destination comparison

**验证说明**: Pre-validated: d-target header validated for IP format only, not destination. SSRF potential in DMI mode but limited impact.

**评分明细**: base: 30 | reachability: 30 | controllability: 0 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-EP-005-ENV-CONTROL] environment_control - ValidateAsyncSchedulingConstraints

**严重性**: Low | **CWE**: CWE-807 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/src/server/endpoint/utils/infer_param.cpp:176-195` @ `ValidateAsyncSchedulingConstraints`
**模块**: endpoint_utils

**描述**: Security-sensitive behavior controlled by environment variable MINDIE_ASYNC_SCHEDULING_ENABLE. Environment variables can be manipulated by attackers to bypass security restrictions like beam search and n/best_of limits.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/src/server/endpoint/utils/infer_param.cpp:176-195`)

```c
const char *env = std::getenv(\"MINDIE_ASYNC_SCHEDULING_ENABLE\"); if (env == nullptr || std::string(env) != \"1\") { return true; }
```

**达成路径**

Environment Variable -> getenv -> Control Flow Decision -> Security restrictions bypassed

**验证说明**: Environment variable controls security behavior. Pre-validated: false. Trust boundary: trusted_admin.

**评分明细**: 0: E | 1: n | 2: v | 3: i | 4: r | 5: o | 6: n | 7: m | 8: e | 9: n | 10: t | 11:   | 12: v | 13: a | 14: r | 15: i | 16: a | 17: b | 18: l | 19: e | 20:   | 21: M | 22: I | 23: N | 24: D | 25: I | 26: E | 27: _ | 28: A | 29: S | 30: Y | 31: N | 32: C | 33: _ | 34: S | 35: C | 36: H | 37: E | 38: D | 39: U | 40: L | 41: I | 42: N | 43: G | 44: _ | 45: E | 46: N | 47: A | 48: B | 49: L | 50: E | 51:   | 52: e | 53: n | 54: a | 55: b | 56: l | 57: e | 58: s | 59:   | 60: A | 61: D | 62: D | 63: I | 64: T | 65: I | 66: O | 67: N | 68: A | 69: L | 70:   | 71: s | 72: e | 73: c | 74: u | 75: r | 76: i | 77: t | 78: y | 79:   | 80: c | 81: o | 82: n | 83: s | 84: t | 85: r | 86: a | 87: i | 88: n | 89: t | 90: s | 91: , | 92:   | 93: n | 94: o | 95: t | 96:   | 97: b | 98: y | 99: p | 100: a | 101: s | 102: s | 103: e | 104: s | 105:   | 106: t | 107: h | 108: e | 109: m | 110: . | 111:   | 112: W | 113: h | 114: e | 115: n | 116:   | 117: s | 118: e | 119: t | 120:   | 121: t | 122: o | 123:   | 124: 1 | 125: , | 126:   | 127: i | 128: t | 129:   | 130: r | 131: e | 132: s | 133: t | 134: r | 135: i | 136: c | 137: t | 138: s | 139:   | 140: b | 141: e | 142: a | 143: m | 144: _ | 145: s | 146: e | 147: a | 148: r | 149: c | 150: h | 151: , | 152:   | 153: n | 154: = | 155: 1 | 156: , | 157:   | 158: a | 159: n | 160: d | 161:   | 162: b | 163: e | 164: s | 165: t | 166: _ | 167: o | 168: f | 169: = | 170: 1 | 171: . | 172:   | 173: D | 174: e | 175: f | 176: a | 177: u | 178: l | 179: t | 180:   | 181: b | 182: e | 183: h | 184: a | 185: v | 186: i | 187: o | 188: r | 189:   | 190: ( | 191: e | 192: n | 193: v | 194:   | 195: n | 196: o | 197: t | 198:   | 199: s | 200: e | 201: t | 202:   | 203: o | 204: r | 205:   | 206: n | 207: o | 208: t | 209:   | 210: 1 | 211: ) | 212:   | 213: a | 214: l | 215: l | 216: o | 217: w | 218: s | 219:   | 220: a | 221: l | 222: l | 223:   | 224: f | 225: e | 226: a | 227: t | 228: u | 229: r | 230: e | 231: s | 232: . | 233:   | 234: T | 235: h | 236: i | 237: s | 238:   | 239: i | 240: s | 241:   | 242: a | 243:   | 244: d | 245: o | 246: c | 247: u | 248: m | 249: e | 250: n | 251: t | 252: e | 253: d | 254:   | 255: p | 256: e | 257: r | 258: f | 259: o | 260: r | 261: m | 262: a | 263: n | 264: c | 265: e | 266:   | 267: o | 268: p | 269: t | 270: i | 271: m | 272: i | 273: z | 274: a | 275: t | 276: i | 277: o | 278: n | 279:   | 280: f | 281: e | 282: a | 283: t | 284: u | 285: r | 286: e | 287: .

---

### [VULN-GRPC-004] Injection - HandleKvRelease

**严重性**: Low | **CWE**: CWE-79 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-grpc_endpoint-scanner

**位置**: `src/server/endpoint/grpc_wrapper/grpc_handler.cpp:153-166` @ `HandleKvRelease`
**模块**: grpc_endpoint

**描述**: RequestId String Injection in logging. RequestId string is used in logging without sanitization. Lower severity due to limited impact.

**漏洞代码** (`src/server/endpoint/grpc_wrapper/grpc_handler.cpp:153-166`)

```c
RequestIdNew reqId(requestId); Status status = GetInferInstance()->ControlRequest(reqId, OperationV2::RELEASE_KV);
```

**达成路径**

request->reqid() -> RequestIdNew -> ControlRequest(RELEASE_KV)

**验证说明**: Pre-validated: RequestId used in logging without sanitization. Log injection possible but limited security impact.

**评分明细**: base: 30 | reachability: 30 | controllability: 0 | mitigations: -5 | context: -10 | cross_file: 0

---

### [VULN-CFG-010] Out-of-Bounds Access - ModelDeployConfigManager::SetMaxPositionEmbeddings

**严重性**: Low | **CWE**: CWE-129 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/config_manager/model_deploy_config.cpp:512` @ `ModelDeployConfigManager::SetMaxPositionEmbeddings`
**模块**: config_manager

**描述**: Direct access to modelParamVec_[0] without checking if vector is empty. If no models are configured, this causes undefined behavior.

**漏洞代码** (`src/config_manager/model_deploy_config.cpp:512`)

```c
modelParamVec_[0].maxPositionEmbeddings = maxPositionEmbeddings;
```

**达成路径**

External input -> maxPositionEmbeddings -> modelParamVec_[0] (no bounds check)

**验证说明**: Config file source: Direct modelParamVec_[0] access without empty check. Undefined behavior if no models configured.

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: -20 | cross_file: 0

---

### [VULN-CFG-012] Type Truncation - ModelDeployConfigManager::InitModelConfigImpl

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/config_manager/model_deploy_config.cpp:205` @ `ModelDeployConfigManager::InitModelConfigImpl`
**模块**: config_manager

**描述**: JSON values cast to int32_t without checking if value fits. For boolean/number JSON types, value may be truncated.

**漏洞代码** (`src/config_manager/model_deploy_config.cpp:205`)

```c
int32_t valueTemp = static_cast<int32_t>(it.value());
```

**达成路径**

JSON modelConfig items -> it.value() -> static_cast<int32_t> -> modelConfig map

**验证说明**: Config file source: JSON values cast to int32_t without checking fit. Type truncation possible.

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: -20 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| config_manager | 0 | 4 | 6 | 2 | 12 |
| endpoint_utils | 0 | 0 | 2 | 1 | 3 |
| grpc_communicator | 0 | 0 | 5 | 1 | 6 |
| grpc_endpoint | 0 | 0 | 4 | 1 | 5 |
| http_endpoint | 0 | 0 | 2 | 2 | 4 |
| infer_instances | 0 | 0 | 0 | 3 | 3 |
| ipc_communicator | 0 | 0 | 0 | 0 | 0 |
| llm_manager | 0 | 0 | 0 | 0 | 0 |
| python_connector | 0 | 2 | 0 | 0 | 2 |
| request_handler | 0 | 0 | 0 | 0 | 0 |
| **合计** | **0** | **6** | **19** | **10** | **35** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-190 | 10 | 23.8% |
| CWE-22 | 6 | 14.3% |
| CWE-400 | 5 | 11.9% |
| CWE-20 | 5 | 11.9% |
| CWE-79 | 2 | 4.8% |
| CWE-129 | 2 | 4.8% |
| CWE-119 | 2 | 4.8% |
| CWE-918 | 1 | 2.4% |
| CWE-807 | 1 | 2.4% |
| CWE-789 | 1 | 2.4% |
| CWE-787 | 1 | 2.4% |
| CWE-502 | 1 | 2.4% |
| CWE-474 | 1 | 2.4% |
| CWE-404 | 1 | 2.4% |
| CWE-367 | 1 | 2.4% |
| CWE-214 | 1 | 2.4% |
| CWE-200 | 1 | 2.4% |
