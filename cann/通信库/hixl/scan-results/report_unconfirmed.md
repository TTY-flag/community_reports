# 漏洞扫描报告 — 待确认漏洞

**项目**: hixl
**扫描时间**: 2026-04-21T22:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

**说明**: 本报告包含需要人工复核验证的候选漏洞。这些漏洞已通过自动化扫描检测，但置信度不足以直接确认。建议在资源充足时对这些漏洞进行人工代码审计和验证。部分 LIKELY 漏洞可能在后续验证中提升为 CONFIRMED 状态。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 24 | 42.9% |
| LIKELY | 17 | 30.4% |
| POSSIBLE | 11 | 19.6% |
| CONFIRMED | 4 | 7.1% |
| **总计** | **56** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 5 | 17.9% |
| High | 9 | 32.1% |
| Medium | 10 | 35.7% |
| Low | 3 | 10.7% |
| **有效漏洞总计** | **28** | - |
| 误报 (FALSE_POSITIVE) | 24 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-007]** improper_input_validation (Critical) - `src/hixl/cs/hixl_cs_server.cc:284` @ `CreateChannel` | 置信度: 75
2. **[hixl_cs-vuln-001]** Type Confusion/Pointer Injection (Critical) - `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/hixl_cs_server.cc:295` @ `CreateChannel` | 置信度: 75
3. **[hixl_cs-vuln-002]** Type Confusion/Pointer Injection (Critical) - `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/hixl_cs_server.cc:379` @ `ExportMem` | 置信度: 75
4. **[hixl_cs-vuln-003]** Arbitrary Memory Address Use (Critical) - `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/mem_msg_handler.cc:123` @ `ParseMemObject` | 置信度: 75
5. **[hixl_cs-vuln-004]** Arbitrary Memory Address Use (Critical) - `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/mem_msg_handler.cc:187` @ `ParseOneMemDesc` | 置信度: 75
6. **[VULN-ADXL-001]** Missing Input Validation (High) - `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/llm_datadist/adxl/channel_manager.cc:152` @ `ProcessReceivedData` | 置信度: 75
7. **[VULN-SEC-009]** improper_input_validation (High) - `src/llm_datadist/adxl/channel_manager.cc:140` @ `ProcessReceivedData` | 置信度: 75
8. **[VULN-CROSS-001]** TAINT_FLOW_CROSS_MODULE (High) - `跨模块数据流:0` @ `RegisterMem数据流` | 置信度: 75
9. **[VULN-CROSS-002]** TAINT_FLOW_CROSS_MODULE (High) - `跨模块数据流:0` @ `recv数据流` | 置信度: 75
10. **[VULN-SEC-001]** missing_authentication (High) - `src/llm_datadist/link_mgr/link_msg_handler.cc:367` @ `LinkCluster` | 置信度: 65

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `Listen@src/hixl/cs/hixl_cs_server.cc` | network | semi_trusted | 集群环境中的 TCP 监听端口，仅接受已建链的节点连接，需要 LinkLlmClusters 前置操作 | TCP socket 监听入口，接收远端节点的连接请求 |
| `MatchEndpointMsg@src/hixl/cs/hixl_cs_server.cc` | rpc | semi_trusted | 接收已连接客户端的端点匹配请求，来自集群内已建链节点 | 处理 MatchEndpoint 消息，匹配远端端点 |
| `CreateChannel@src/hixl/cs/hixl_cs_server.cc` | rpc | semi_trusted | 接收已连接客户端的通道创建请求，来自集群内节点 | 处理 CreateChannel 消息，创建数据传输通道 |
| `ExportMem@src/hixl/cs/hixl_cs_server.cc` | rpc | semi_trusted | 接收已连接客户端的内存导出请求，返回已注册内存描述 | 处理 GetRemoteMem 消息，导出内存描述给远端 |
| `ProClientMsg@src/hixl/cs/hixl_cs_server.cc` | network | semi_trusted | 处理 epoll 接收到的客户端消息，来自已建链的连接 | 通过 MsgReceiver 接收并处理客户端消息 |
| `HandleChannelEvent@src/llm_datadist/adxl/channel_manager.cc` | network | semi_trusted | 使用 recv() 直接接收网络数据，来自已建链的通道连接 | 从 socket 接收通道数据到 recv_buffer_ |
| `Initialize@src/hixl/engine/hixl_impl.cc` | decorator | trusted_admin | API 入口，由应用开发者调用，部署时配置 IP:port 参数 | Hixl 初始化 API，可指定监听端口 |
| `RegisterMem@src/hixl/engine/hixl_impl.cc` | decorator | trusted_admin | API 入口，由应用开发者调用注册内存地址 | 内存注册 API，接收用户提供内存地址和长度 |
| `TransferSync@src/hixl/engine/hixl_impl.cc` | decorator | trusted_admin | API 入口，由应用开发者调用执行数据传输 | 同步传输 API，接收 TransferOpDesc 数组（含地址和长度） |
| `Initialize@src/llm_datadist/api/llm_datadist_impl.cc` | decorator | trusted_admin | LLM-DataDist API 入口，由应用开发者调用 | LLM-DataDist 初始化 API |
| `LinkLlmClusters@src/llm_datadist/api/llm_datadist_impl.cc` | decorator | trusted_admin | API 入口，由应用调用建立集群间连接 | 建立与其他 LlmDataDist 实例的连接 |

**其他攻击面**:
- TCP Socket Listening (port > 0): 接收集群内节点连接，处理消息类型 MatchEndpoint/CreateChannel/GetRemoteMem
- Network Data Reception: recv() 接收已建链通道的数据，需检查缓冲区边界
- Memory Registration API: RegisterMem 接收用户提供内存地址，需验证地址有效性
- Transfer API: TransferSync/TransferAsync 接收 TransferOpDesc（含地址和长度），需验证参数合法性
- RPC Message Parsing: 处理 JSON 序列化的消息，需检查反序列化安全性
- Cluster Connection: LinkLlmClusters 建立 TCP/RDMA 连接，需验证远端身份

---

## 3. Critical 漏洞 (5)

### [VULN-SEC-007] improper_input_validation - CreateChannel

**严重性**: Critical | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/hixl/cs/hixl_cs_server.cc:284-317` @ `CreateChannel`
**模块**: hixl_cs

**描述**: RPC 请求中端点句柄验证不充分。CreateChannel 直接使用请求中的 dst_ep_handle 值，未验证该句柄是否属于合法端点或请求者是否有权限访问该端点。

**漏洞代码** (`src/hixl/cs/hixl_cs_server.cc:284-317`)

```c
EndpointHandle handle = reinterpret_cast<EndpointHandle>(static_cast<uintptr_t>(req.dst_ep_handle)); auto ep = endpoint_store_.GetEndpoint(handle);
```

**达成路径**

CreateChannelReq → reinterpret_cast dst_ep_handle → endpoint_store_.GetEndpoint → CreateChannel

**验证说明**: 与hixl_cs-vuln-001相同问题，dst_ep_handle直接cast无验证

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [hixl_cs-vuln-001] Type Confusion/Pointer Injection - CreateChannel

**严重性**: Critical | **CWE**: CWE-843 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/hixl_cs_server.cc:295-296` @ `CreateChannel`
**模块**: hixl_cs

**描述**: Network-supplied dst_ep_handle is directly cast to EndpointHandle pointer without validation. An attacker controlling a semi-trusted remote node can send arbitrary handle values that will be used as pointers to access internal objects, potentially leading to memory corruption or information disclosure.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/hixl_cs_server.cc:295-296`)

```c
EndpointHandle handle = reinterpret_cast<EndpointHandle>(static_cast<uintptr_t>(req.dst_ep_handle));
```

**达成路径**

TCP recv -> MsgReceiver::IRecv -> MsgHandler -> CreateChannel -> reinterpret_cast(req.dst_ep_handle) -> GetEndpoint(handle)

**验证说明**: GetEndpoint仅做map查找无handle来源验证，semi_trusted节点可发送任意handle值导致非法内存访问

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [hixl_cs-vuln-002] Type Confusion/Pointer Injection - ExportMem

**严重性**: Critical | **CWE**: CWE-843 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/hixl_cs_server.cc:379-380` @ `ExportMem`
**模块**: hixl_cs

**描述**: Network-supplied dst_ep_handle in ExportMem is directly cast to EndpointHandle pointer without validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/hixl_cs_server.cc:379-380`)

```c
EndpointHandle handle = reinterpret_cast<EndpointHandle>(static_cast<uintptr_t>(req->dst_ep_handle));
```

**达成路径**

TCP recv -> MsgHandler -> ExportMem -> handle cast

**验证说明**: ExportMem中同样handle cast问题，GetEndpoint无来源验证

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [hixl_cs-vuln-003] Arbitrary Memory Address Use - ParseMemObject

**严重性**: Critical | **CWE**: CWE-119 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/mem_msg_handler.cc:123-124` @ `ParseMemObject`
**模块**: hixl_cs

**描述**: Memory address parsed from JSON response from semi-trusted remote server is directly used as pointer without validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/mem_msg_handler.cc:123-124`)

```c
mem.addr = reinterpret_cast<void *>(static_cast<uintptr_t>(addr_u64));
```

**达成路径**

TCP recv -> JSON parse -> addr used directly

**验证说明**: JSON解析的addr直接用作指针，来自semi_trusted节点响应，无地址有效性验证

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [hixl_cs-vuln-004] Arbitrary Memory Address Use - ParseOneMemDesc

**严重性**: Critical | **CWE**: CWE-119 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/mem_msg_handler.cc:187-188` @ `ParseOneMemDesc`
**模块**: hixl_cs

**描述**: Device memory pointer parsed from JSON response without validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/mem_msg_handler.cc:187-188`)

```c
out.registered_dev_mem = reinterpret_cast<void *>(item["registered_dev_mem"].get<uintptr_t>());
```

**达成路径**

JSON parse -> registered_dev_mem used

**验证说明**: registered_dev_mem同样直接cast使用，无验证

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. High 漏洞 (9)

### [VULN-ADXL-001] Missing Input Validation - ProcessReceivedData

**严重性**: High | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/llm_datadist/adxl/channel_manager.cc:152` @ `ProcessReceivedData`
**模块**: llm_datadist_adxl

**描述**: ProtocolHeader.body_size (uint64_t) is used directly from network without upper bound validation. An attacker can set body_size to UINT64_MAX causing memory exhaustion DoS via unbounded string construction at line 199. The recv() path accepts arbitrary body_size values. Compare with MsgHandlerPlugin::RecvMsg which properly validates length <= 1MB (kMaxLength = 1ULL << 20).

**达成路径**

[IN] recv(fd) @line123 -> recv_buffer_ -> ProtocolHeader parsing @line147 -> header->body_size [OUT] expected_body_size_ -> std::string msg_str @line199 -> Deserialize

**验证说明**: body_size来自网络header(uint64_t)直接赋值给expected_body_size_无上限验证。Line152无检查，Line194仅检查>sizeof(ControlMsgType)。入口点HandleChannelEvent(semi_trusted)。MsgHandlerPlugin::RecvMsg有1MB限制但此路径缺失。可达性+20(间接外部),可控性+25(攻击者可设置任意值)。无缓解措施。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-009] improper_input_validation - ProcessReceivedData

**严重性**: High | **CWE**: CWE-129 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/llm_datadist/adxl/channel_manager.cc:140-191` @ `ProcessReceivedData`
**模块**: llm_datadist_adxl

**描述**: 消息体大小验证存在但可能不够严格。ProcessReceivedData 检查 header.body_size 但未设置最大限制。恶意节点发送超大 body_size 可能导致内存过度分配。

**漏洞代码** (`src/llm_datadist/adxl/channel_manager.cc:140-191`)

```c
channel->expected_body_size_ = header->body_size; // 未检查上限
```

**达成路径**

recv() → ProtocolHeader parsing → expected_body_size_ = header->body_size → buffer resize

**验证说明**: 与VULN-ADXL-001相同漏洞。body_size无上限验证，可导致内存过度分配。Line140-191整体流程分析确认缺失上限检查。security-auditor独立发现与dataflow扫描一致。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CROSS-001] TAINT_FLOW_CROSS_MODULE - RegisterMem数据流

**严重性**: High | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `跨模块数据流:0` @ `RegisterMem数据流`
**模块**: cross_module
**跨模块**: hixl_engine → hixl_cs → hixl_proxy → llm_datadist_hccl

**描述**: 用户提供内存地址从API层直接传递到硬件通信层，中间仅检查地址非空，未验证地址范围和有效性。完整攻击路径：用户调用RegisterMem注册恶意地址 → 地址传递给HIXL引擎 → CS模块Endpoint直接使用 → Proxy层无验证传递给HCCL → 硬件RDMA读写任意内存

**达成路径**

RegisterMem(hixl_engine) -> Endpoint::RegisterMem(hixl_cs) -> HcommProxy::MemReg(hixl_proxy) -> HCCL MemReg

**验证说明**: Call chain verified via call_graph.json. Null check exists (CheckTransferOpDescs) but no range/bounds validation before HCCL memory registration.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-CROSS-002] TAINT_FLOW_CROSS_MODULE - recv数据流

**严重性**: High | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `跨模块数据流:0` @ `recv数据流`
**模块**: cross_module
**跨模块**: llm_datadist_adxl → llm_datadist_cache_mgr → llm_datadist_data_transfer

**描述**: 网络数据从recv()接收，ProtocolHeader.body_size无上限验证，跨模块传递到缓存管理器进行内存操作。完整攻击路径：恶意节点发送超大body_size → channel_manager创建极大字符串 → JSON解析内存耗尽DoS → 或传递错误数据给CacheManager导致越界

**达成路径**

recv()(llm_datadist_adxl) -> ProcessReceivedData -> body_size(无验证) -> std::string msg_str(内存分配) -> HandleControlMsg -> json::parse -> CacheManager操作

**验证说明**: Call chain verified. body_size from ProtocolHeader has minimum size check (channel_manager.cc:194) but NO maximum limit check. std::string msg_str allocation (line 199) can cause memory exhaustion DoS.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-001] missing_authentication - LinkCluster

**严重性**: High | **CWE**: CWE-287 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/llm_datadist/link_mgr/link_msg_handler.cc:367-413` @ `LinkCluster`
**模块**: llm_datadist_link_mgr

**描述**: 节点连接建立过程缺乏身份认证机制。LinkMsgHandler::LinkCluster 和 HixlCSServer::Listen 在 TCP 连接建立后，仅验证消息格式和类型，未对远端节点进行身份认证。任何能够连接到 TCP 监听端口的主机都可以建立链路连接，获取内存地址信息。

**漏洞代码** (`src/llm_datadist/link_mgr/link_msg_handler.cc:367-413`)

```c
LLM_CHK_STATUS_RET(MsgHandlerPlugin::Connect(remote_ip_str, remote_port, conn_fd, timeout, ge::LLM_LINK_FAILED), ...); // 无身份验证
```

**达成路径**

[CREDENTIAL_FLOW] TCP Connect → RecvMsg → Deserialize peer_exchange_info → 直接使用远端地址

**验证说明**: LIKELY: Real authentication gap in cluster linking. Semi_trusted network entry point. Any host that can reach TCP port can establish link and exchange memory addresses. No identity verification (certificate, token, whitelist) observed. Risk: malicious node injection in cluster.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-002] improper_input_validation - ProcessConnectRequest

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/llm_datadist/link_mgr/link_msg_handler.cc:187-222` @ `ProcessConnectRequest`
**模块**: llm_datadist_link_mgr

**描述**: 远端节点提供的内存地址缺乏有效性验证。ProcessConnectRequest 直接使用从远端接收的 cache_table_addr、req_addr、resp_addr 等地址值，未验证这些地址是否在合法范围内。恶意节点可提供无效地址导致内存访问异常。

**漏洞代码** (`src/llm_datadist/link_mgr/link_msg_handler.cc:187-222`)

```c
remote_mem.addr = ValueToPtr(peer_exchange_info.cache_table_addr); // 未验证地址有效性
```

**达成路径**

RecvMsg → Deserialize LLMExchangeInfo → remote_mem.addr = ValueToPtr(cache_table_addr) → 内存访问

**验证说明**: LIKELY: Remote node-provided memory addresses (cache_table_addr, req_addr, resp_addr) used without validation. Semi_trusted entry point. Malicious node could provide invalid addresses causing memory access errors or information leak. Addresses should be validated against registered memory ranges.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-005] missing_authentication - DoWait

**严重性**: High | **CWE**: CWE-287 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/hixl/cs/hixl_cs_server.cc:443-479` @ `DoWait`
**模块**: hixl_cs

**描述**: TCP 连接接受后无身份验证。HixlCSServer::DoWait 在 accept 新连接后，直接将连接添加到 epoll 并开始处理消息，未对客户端进行身份验证。攻击者可连接并发送伪造的 RPC 消息。

**漏洞代码** (`src/hixl/cs/hixl_cs_server.cc:443-479`)

```c
HIXL_CHK_STATUS_RET(CtrlMsgPlugin::Accept(listen_fd_, connect_fd), ...); HIXL_CHK_STATUS_RET(CtrlMsgPlugin::AddFdToEpoll(epoll_fd_, connect_fd), ...); // 无认证
```

**达成路径**

Accept → AddFdToEpoll → ProClientMsg → MsgHandler::HandleMsg → RPC 处理

**验证说明**: DoWait accept后无身份验证直接处理消息，semi_trusted假设下仍存在恶意节点连接风险

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-010] missing_authentication - LinkLlmClusters

**严重性**: High | **CWE**: CWE-287 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/llm_datadist/api/llm_datadist_impl.cc:249-258` @ `LinkLlmClusters`
**模块**: llm_datadist_api
**跨模块**: llm_datadist_api → llm_datadist_link_mgr

**描述**: LinkLlmClusters API 缺乏远端身份验证。该 API 仅验证 timeout 和初始化状态，未对远端集群参数进行身份验证。应用可连接任意远端地址。

**漏洞代码** (`src/llm_datadist/api/llm_datadist_impl.cc:249-258`)

```c
LLM_CHK_BOOL_RET_STATUS(timeout > 0, LLM_PARAM_INVALID, ...); llm_data_dist_.LinkClusters(cluster_infos, rets, timeout);
```

**达成路径**

LinkLlmClusters → ConvertClusterInfos → llm_data_dist_.LinkClusters → TCP Connect

**验证说明**: LIKELY: Cross-module authentication gap. LinkLlmClusters API (trusted_admin) passes to link_mgr.LinkCluster (semi_trusted network layer). No identity verification before accepting remote node connection. Same root cause as VULN-SEC-001.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-PYWRAPPER-003] Race Condition - LLMDataDistV2Wrapper::Init

**严重性**: High | **CWE**: CWE-362 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/python/llm_wrapper/llm_datadist_v2_wrapper.cc:17-33` @ `LLMDataDistV2Wrapper::Init`
**模块**: python_llm_wrapper

**描述**: 静态全局变量llm_data_dist(std::unique_ptr<LLMDataDistV2>)没有线程同步保护。并发调用Init/Finalize可能导致竞态条件，引发内存泄漏、重复初始化或use-after-free。虽然LLMDataDistV2内部有mutex，但wrapper层无保护。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/python/llm_wrapper/llm_datadist_v2_wrapper.cc:17-33`)

```c
static std::unique_ptr<LLMDataDistV2> llm_data_dist;
```

**达成路径**

Python多线程 -> 全局静态变量

**验证说明**: 静态全局变量llm_data_dist无线程同步保护。pybind11使用call_guard<gil_scoped_release>释放GIL后，Python多线程可并发调用Init/Finalize，存在TOCTOU竞态条件，可能导致重复初始化、内存泄漏或use-after-free。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. Medium 漏洞 (10)

### [VULN-SEC-013] insufficient_access_control - ExportMem

**严重性**: Medium | **CWE**: CWE-284 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/hixl/cs/hixl_cs_server.cc:369-389` @ `ExportMem`
**模块**: cross_module
**跨模块**: hixl_cs → hixl_engine

**描述**: 跨模块权限传递缺乏验证。ExportMem RPC 将内存描述导出后，远端节点可通过 ImportMem 获取本地内存访问权。从 ExportMem（hixl_cs_server）到 MemImport（hixl_cs_client）的流程中，未验证请求者是否有权限访问该内存。

**漏洞代码** (`src/hixl/cs/hixl_cs_server.cc:369-389`)

```c
HIXL_CHK_STATUS_RET(ep->ExportMem(resp.mem_descs), ...); // 内存描述导出，无权限验证
```

**达成路径**

[CREDENTIAL_FLOW] GetRemoteMemReq → ExportMem → JSON Serialize → TCP Send → MemImport → 内存访问

**验证说明**: Call chain verified. ExportMem exports memory descriptions without verifying requester permissions. Any connected node can request memory export.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-ADXL-004] Denial of Service via Parser - Deserialize

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/llm_datadist/adxl/control_msg_handler.h:207-210` @ `Deserialize`
**模块**: llm_datadist_adxl

**描述**: nlohmann::json::parse() at control_msg_handler.h:207 on untrusted network data without depth/nesting limit. Deeply nested JSON could cause stack overflow. Combined with unvalidated body_size from VULN-ADXL-001, extremely large JSON messages could cause memory exhaustion even with exception handling.

**达成路径**

[IN] msg_str (from network, size unvalidated) -> json::parse(msg_str) [OUT] msg = j.get<T>()

**验证说明**: nlohmann::json::parse无深度/嵌套限制。依赖VULN-ADXL-001的大消息触发。异常处理Line211-214存在但无法阻止内存耗尽。可达性+20(间接),可控性+15(内容可控但大小依赖body_size)。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [hixl_cs-vuln-006] Insufficient Input Validation - CreateChannel

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/hixl_cs_server.cc:294-306` @ `CreateChannel`
**模块**: hixl_cs

**描述**: CreateChannelReq fields from network used without bounds checking.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/hixl_cs_server.cc:294-306`)

```c
channel_desc.tc = req.tc; channel_desc.sl = req.sl;
```

**达成路径**

Network fields -> direct use

**验证说明**: tc/sl/channel_index来自网络直接使用无bounds check

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-006] information_exposure - ExportMem

**严重性**: Medium | **CWE**: CWE-200 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/hixl/cs/hixl_cs_server.cc:369-389` @ `ExportMem`
**模块**: hixl_cs

**描述**: 内存地址信息暴露给远端节点。ExportMem RPC 将本地注册的内存描述（包含地址和大小）序列化为 JSON 并发送给远端节点。远端节点可获取敏感的内存布局信息。

**漏洞代码** (`src/hixl/cs/hixl_cs_server.cc:369-389`)

```c
HIXL_CHK_STATUS_RET(ep->ExportMem(resp.mem_descs), ...); Serialize(resp, msg_str); // 内存地址暴露
```

**达成路径**

GetRemoteMemReq → ExportMem → ep->ExportMem → Serialize(JSON) → SendRemoteMemResp

**验证说明**: 内存地址暴露是协议设计必要功能，但在semi_trusted环境下仍可被恶意节点利用获取内存布局信息

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-PYWRAPPER-001] Type Conversion - PyDictToVector

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-704 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/python/llm_wrapper/llm_wrapper_v2.cc:65-74` @ `PyDictToVector`
**模块**: python_llm_wrapper

**描述**: PyDictToVector函数使用cast<int64_t>()进行类型转换但缺少异常处理。当Python传入非整数类型时，pybind11会抛出未捕获的异常，可能导致程序崩溃或不可预测行为。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/python/llm_wrapper/llm_wrapper_v2.cc:65-74`)

```c
int64_t key = item.first.cast<int64_t>();\nint64_t value = item.second.cast<int64_t>();
```

**达成路径**

Python dict -> C++ vector<pair>

**验证说明**: cast<int64_t>()确实无显式异常处理，但pybind11内置异常机制会将转换失败自动转换为Python TypeError异常，不会导致C++程序崩溃。仅影响用户体验（不友好的错误消息），无安全风险。

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-PYWRAPPER-005] Improper Input Validation - UnpackClusterInfos

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/python/llm_wrapper/llm_datadist_v2_wrapper.cc:341-366` @ `UnpackClusterInfos`
**模块**: python_llm_wrapper

**描述**: UnpackClusterInfos函数直接从tuple提取IP地址和端口，没有格式验证。恶意输入可能导致网络连接到非预期地址或端口溢出。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/python/llm_wrapper/llm_datadist_v2_wrapper.cc:341-366`)

```c
IpInfo ip_info;\nip_info.ip = ip_and_port.first;\nip_info.port = ip_and_port.second;
```

**达成路径**

Python tuple -> ClusterInfo -> LLMDataDistV2

**验证说明**: UnpackClusterInfos直接从tuple提取IP/端口无格式验证，但参数来自trusted_admin应用开发者。恶意输入可能导致连接到非预期地址，但无内存破坏风险。属于信任边界问题而非安全漏洞。

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [hixl_cs-vuln-009] Uncontrolled Memory Allocation - FillExportDescFromJsonField

**严重性**: Medium | **CWE**: CWE-789 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/mem_msg_handler.cc:149-171` @ `FillExportDescFromJsonField`
**模块**: hixl_cs

**描述**: malloc(n) where n from JSON array size.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/mem_msg_handler.cc:149-171`)

```c
void *buf = std::malloc(n);
```

**达成路径**

JSON size -> malloc

**验证说明**: malloc(n)中n来自JSON数组size，元素值有范围检查但n本身无上限约束，可能导致资源耗尽

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [llm_datadist_cache_mgr-V001] Integer Overflow - SwapBlocks

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/llm_datadist/cache_mgr/swap_impl.cc:44-46` @ `SwapBlocks`
**模块**: llm_datadist_cache_mgr
**跨模块**: data_transfer

**描述**: Integer overflow in block_size calculation: block_size * ordered_block.size() can overflow uint64_t, leading to undersized allocation and subsequent out-of-bounds memory access in aclrtMemcpy

**漏洞代码** (`src/llm_datadist/cache_mgr/swap_impl.cc:44-46`)

```c
const uint64_t copy_size = block_size * ordered_block.size();\nauto src = src_addr + src_index * block_size;\nauto dst = dst_addr + dst_index * block_size;
```

**达成路径**

[IN] block_size from SwapBlocksV2 caller\n[IN] block_mapping from external\n[OUT] memory copied via aclrtMemcpy

**验证说明**: Integer overflow in block_size * ordered_block.size() without explicit overflow check. However: 1) internal API (trusted_admin), 2) block_size typically bounded by config, 3) ordered_block.size() derived from block_mapping validation

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [llm_datadist_cache_mgr-V002] Missing Boundary Validation - SwapBlocks

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/llm_datadist/cache_mgr/swap_impl.cc:42-46` @ `SwapBlocks`
**模块**: llm_datadist_cache_mgr
**跨模块**: data_transfer

**描述**: Block indices src_index and dst_index from block_mapping are used without validation against buffer boundaries, allowing out-of-bounds memory read/write

**漏洞代码** (`src/llm_datadist/cache_mgr/swap_impl.cc:42-46`)

```c
const int64_t src_index = ordered_block.front().first;\nconst int64_t dst_index = ordered_block.front().second;\nauto src = src_addr + src_index * block_size;\nauto dst = dst_addr + dst_index * block_size;
```

**达成路径**

[IN] block_mapping contains unvalidated indices\n[OUT] Memory access at computed addresses

**验证说明**: Block indices src_index/dst_index from block_mapping used without explicit bounds validation against cache buffer size. However: 1) internal API (trusted_admin), 2) block_mapping validated via FindContiguousBlockIndexPair for continuity, 3) indices derived from validated block_mapping pairs

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [hixl_cs-vuln-005] Missing Authorization - MatchEndpointMsg

**严重性**: Medium | **CWE**: CWE-862 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/hixl_cs_server.cc:266-275` @ `MatchEndpointMsg`
**模块**: hixl_cs

**描述**: MatchEndpointMsg accepts any EndpointDesc from remote client without validating authorization.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/hixl_cs_server.cc:266-275`)

```c
auto ep = endpoint_store_.MatchEndpoint(req.dst, handle);
```

**达成路径**

Network EndpointDesc -> MatchEndpoint (no auth)

**验证说明**: MatchEndpoint有EndpointDesc匹配验证(operator==)，非完全无验证，但缺少授权检查

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: 0

---

## 6. Low 漏洞 (3)

### [VULN-ADXL-005] Uncontrolled Memory Allocation - HandleReadEvent

**严重性**: Low | **CWE**: CWE-789 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/llm_datadist/adxl/channel_manager.cc:120-121` @ `HandleReadEvent`
**模块**: llm_datadist_adxl

**描述**: recv_buffer_.resize() at line 120-121 grows buffer based on bytes_received_ + kRecvChunkSize (4096) without upper bound. While individual recv() calls are bounded, cumulative growth from many small recv() chunks could lead to memory exhaustion over extended connection.

**达成路径**

[IN] recv(fd) cumulative -> bytes_received_ += n -> recv_buffer_.resize(bytes_received_ + 4096)

**验证说明**: recv_buffer_.resize每次增长4096字节。累积内存耗尽需大量recv调用和长时间连接。Line120-121按需增长。攻击者可控性低，仅能通过多次发送小数据逐步增长。+5可控性(仅长度渐进可控)。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-008] improper_input_validation - ConnectInfoProcess

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/llm_datadist/adxl/channel_msg_handler.cc:369-413` @ `ConnectInfoProcess`
**模块**: llm_datadist_adxl

**描述**: 通道连接信息地址验证不充分。ConnectInfoProcess 将远端提供的 addrs 数组直接添加到本地段表，未验证地址范围的有效性。恶意节点可提供越界地址。

**漏洞代码** (`src/llm_datadist/adxl/channel_msg_handler.cc:369-413`)

```c
for (const auto &remote_addr : peer_channel_info.addrs) { segment_table_->AddRange(..., remote_addr.start_addr, remote_addr.end_addr, ...); }
```

**达成路径**

RecvMsg → Deserialize ChannelConnectInfo → segment_table_->AddRange → 内存访问验证

**验证说明**: peer_channel_info.addrs来自网络直接添加到segment_table_。Line339-344无地址有效性验证。但后续FindSegment/Contains会检查地址范围，非法地址会被拒绝访问。主要影响功能而非安全。有Contains检查缓解-10。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [hixl_cs-vuln-008] Missing Buffer Size Check - ExportMem

**严重性**: Low | **CWE**: CWE-130 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/hixl_cs_server.cc:384-388` @ `ExportMem`
**模块**: hixl_cs

**描述**: ExportMem serializes all memory descriptors without size check.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/2/hixl/src/hixl/cs/hixl_cs_server.cc:384-388`)

```c
Serialize(resp, msg_str);
```

**达成路径**

ExportMem -> Serialize -> no size check

**验证说明**: JSON序列化由nlohmann库管理缓冲区，实际溢出风险低，但无显式size check

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

## 7. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cross_module | 0 | 2 | 1 | 0 | 3 |
| hixl_cs | 5 | 1 | 4 | 1 | 11 |
| hixl_proxy | 0 | 0 | 0 | 0 | 0 |
| llm_datadist_adxl | 0 | 2 | 1 | 2 | 5 |
| llm_datadist_api | 0 | 1 | 0 | 0 | 1 |
| llm_datadist_cache_mgr | 0 | 0 | 2 | 0 | 2 |
| llm_datadist_link_mgr | 0 | 2 | 0 | 0 | 2 |
| python_llm_wrapper | 0 | 1 | 2 | 0 | 3 |
| **合计** | **5** | **9** | **10** | **3** | **27** |

## 8. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 9 | 32.1% |
| CWE-287 | 3 | 10.7% |
| CWE-843 | 2 | 7.1% |
| CWE-789 | 2 | 7.1% |
| CWE-129 | 2 | 7.1% |
| CWE-119 | 2 | 7.1% |
| CWE-862 | 1 | 3.6% |
| CWE-704 | 1 | 3.6% |
| CWE-400 | 1 | 3.6% |
| CWE-362 | 1 | 3.6% |
| CWE-284 | 1 | 3.6% |
| CWE-200 | 1 | 3.6% |
| CWE-190 | 1 | 3.6% |
| CWE-130 | 1 | 3.6% |
