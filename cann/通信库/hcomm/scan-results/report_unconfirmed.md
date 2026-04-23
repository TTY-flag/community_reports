# 漏洞扫描报告 — 待确认漏洞

**项目**: hcomm
**扫描时间**: 2026-04-22T05:18:53Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 11 | 47.8% |
| POSSIBLE | 5 | 21.7% |
| CONFIRMED | 4 | 17.4% |
| FALSE_POSITIVE | 3 | 13.0% |
| **总计** | **23** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 5 | 31.3% |
| Medium | 11 | 68.8% |
| **有效漏洞总计** | **16** | - |
| 误报 (FALSE_POSITIVE) | 3 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-ENV-002]** path_traversal_environment (High) - `src/legacy/framework/communicator/communicator_impl.cc:3163` @ `unknown` | 置信度: 70
2. **[VULN-DF-OVERFLOW-001]** integer_overflow (High) - `src/framework/communicator/impl/independent_op/channel/channel_manager.cc:296` @ `unknown` | 置信度: 65
3. **[VULN-DF-OVERFLOW-006]** integer_overflow (High) - `src/framework/communicator/impl/hccl_communicator.cc:1687` @ `unknown` | 置信度: 65
4. **[VULN-DF-OVERFLOW-003]** integer_overflow (High) - `src/platform/resource/transport/host/transport_ibverbs.cc:1069` @ `unknown` | 置信度: 60
5. **[VULN-DF-ENV-001]** path_traversal_environment (High) - `src/platform/common/launch_aicpu.cc:200` @ `unknown` | 置信度: 60
6. **[VULN-SEC-001]** improper_input_validation (Medium) - `src/framework/hcom/hcom.cc:174` @ `HcomInitByString` | 置信度: 65
7. **[VULN-SEC-002]** improper_input_validation (Medium) - `src/legacy/framework/entrance/hcom_comm/comm_manager.cc:555` @ `HcomInitByFile` | 置信度: 65
8. **[VULN-DF-NUM-002]** improper_integer_conversion (Medium) - `src/framework/hcom/hcom.cc:174` @ `HcomInit` | 置信度: 65
9. **[VULN-DF-NUM-003]** improper_integer_conversion (Medium) - `src/platform/hccp/rdma_service/tlv/rs_adp_nslb.c:46` @ `unknown` | 置信度: 65
10. **[VULN-DF-NUM-004]** improper_integer_conversion (Medium) - `src/framework/hcom/hcom_common.cc:1473` @ `unknown` | 置信度: 65

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `GetDeviceComm@src/framework/op_base/src/op_base.cc` | network | untrusted_network | 通过HcclCommInitRootInfo初始化通信域，接收远程节点的root_info数据，该数据来自网络交换 | HCCL通信域初始化入口，接收远程节点信息 |
| `HcomInit@src/framework/hcom/hcom.cc` | file | semi_trusted | 解析rankTableM配置文件路径，该文件由训练框架或用户提供，可能被篡改 | HCOM初始化入口，解析配置文件 |
| `HcomInitByString@src/framework/hcom/hcom.cc` | file | semi_trusted | 接收字符串形式的rank table配置，数据来源可能不可信 | 通过字符串初始化HCOM |
| `HcclInitComm@src/hccd/hccd.cc` | file | semi_trusted | 解析rankTableM JSON配置文件，该文件定义集群拓扑，可能包含恶意数据 | HCCL通信初始化，解析配置文件 |
| `RsSocketInit@src/platform/hccp/rdma_service/rs_socket.c` | network | untrusted_network | 初始化VNIC IP地址列表，用于网络通信，数据来自外部配置 | Socket通信初始化 |
| `RsServerValidAsync@src/platform/hccp/rdma_service/rs_socket.c` | network | untrusted_network | 验证白名单连接，接收来自远程节点的连接请求 | 服务器端连接验证 |
| `RsEpollRecvQpHandle@src/platform/hccp/rdma_service/rs_rdma.c` | network | untrusted_network | 处理RDMA接收队列事件，数据来自远程节点通过RDMA网络传输 | RDMA接收事件处理 |
| `HcclRawConnect@src/hccd/hccl_raw.cc` | network | untrusted_network | 建立到远程地址的TCP连接，远程地址来自配置文件 | 原始连接建立 |
| `HcclRawAccept@src/hccd/hccl_raw.cc` | network | untrusted_network | 接受远程节点的连接请求 | 原始连接接受 |
| `ParseFileToJson@src/legacy/framework/misc/json_parser/json_parser.cc` | file | semi_trusted | 解析JSON配置文件，文件路径由用户提供，内容可能包含恶意数据 | JSON配置文件解析 |
| `InitEnvParam@src/framework/common/src/config/env_config.cc` | env | semi_trusted | 解析HCCL环境变量配置，环境变量可被恶意设置 | 环境变量配置解析 |
| `net_co_init@src/platform/hccp/netco/net_adapt/init/net_co.c` | network | untrusted_network | NetCo网络通信初始化，处理网络数据收发 | NetCo网络初始化 |
| `RaPeerInit@src/platform/hccp/rdma_agent/peer/ra_peer.c` | network | untrusted_network | RDMA Agent Peer初始化，管理远程节点通信 | RDMA Agent Peer初始化 |
| `HcclCommInitClusterInfo@include/hccl/hccl_comm.h` | file | semi_trusted | HCCL主要API入口，接收集群配置文件路径作为参数 | HCCL集群初始化API |
| `HcclCommInitRootInfo@include/hccl/hccl_comm.h` | network | untrusted_network | 接收root_info结构体进行初始化，该结构体内容来自网络交换 | HCCL Root Info初始化API |
| `HcommWriteOnThread@include/hcomm_primitives.h` | network | untrusted_network | 单边写操作，数据通过channel写入远程节点内存 | 通信原语写操作 |
| `HcommReadOnThread@include/hcomm_primitives.h` | network | untrusted_network | 单边读操作，从远程节点内存读取数据 | 通信原语读操作 |

**其他攻击面**:
- RDMA/RoCE网络接口: ibv_post_send/recv, QP状态管理
- TCP Socket网络接口: bind/listen/accept/connect
- 配置文件解析: JSON rank table解析, 环境变量解析
- HCCS芯片间通信: 设备内部通信
- PCIe通信: 主机与设备通信
- AICPU内核加载: 动态加载内核模块
- 白名单验证: 连接白名单校验
- Root Info交换: 集群初始化时交换的身份信息

---

## 3. High 漏洞 (5)

### [VULN-DF-ENV-002] path_traversal_environment - unknown

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/legacy/framework/communicator/communicator_impl.cc:3163-3172` @ `unknown`
**模块**: framework

**描述**: ASCEND_HOME_PATH environment variable used for path construction in communicator_impl.cc. Similar binary planting risk.

**漏洞代码** (`src/legacy/framework/communicator/communicator_impl.cc:3163-3172`)

```c
char *getPath = getenv("ASCEND_HOME_PATH");
if (getPath != nullptr) { libPath = getPath; }
```

**达成路径**

getenv("ASCEND_HOME_PATH") -> libPath [SINK]

**验证说明**: ASCEND_HOME_PATH 环境变量用于构建 DPU kernel 加载路径。有 realpath 验证 (行 3177)，可检测无效路径，但不能防止恶意路径内的合法文件加载。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-OVERFLOW-001] integer_overflow - unknown

**严重性**: High | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/framework/communicator/impl/independent_op/channel/channel_manager.cc:296-300` @ `unknown`
**模块**: framework

**描述**: Integer overflow in malloc at channel_manager.cc. channelParam.listNum from external transport response is multiplied by sizeof(HcclIndOpChannelRemoteResV2) without overflow check. Large listNum could cause multiplication overflow, resulting in small allocation followed by heap overflow during subsequent iterations.

**漏洞代码** (`src/framework/communicator/impl/independent_op/channel/channel_manager.cc:296-300`)

```c
channelParam.remoteResV2 = static_cast<HcclIndOpChannelRemoteResV2*>(malloc(channelParam.listNum * sizeof(HcclIndOpChannelRemoteResV2)));
```

**达成路径**

external transport response -> listNum -> malloc(listNum * sizeof(...)) [SINK]

**验证说明**: listNum from external transport response lacks overflow check before malloc. The consistency check (listNum == links.size()) provides partial mitigation but doesn't prevent integer overflow if both values are corrupted or if links.size() itself is from external data.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-OVERFLOW-006] integer_overflow - unknown

**严重性**: High | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/framework/communicator/impl/hccl_communicator.cc:1687-1690` @ `unknown`
**模块**: framework

**描述**: Dynamic size calculation overflow in hccl_communicator.cc. rankSize * rankSize * sizeof(u64) calculation without overflow check. Large rankSize could cause rankSize^2 overflow.

**漏洞代码** (`src/framework/communicator/impl/hccl_communicator.cc:1687-1690`)

```c
dynamicDataSize = sizeof(struct OpTilingAlltoallvcDataDes) + rankSize * rankSize * sizeof(u64);
```

**达成路径**

rankSize parameter -> rankSize * rankSize * sizeof(u64) [SINK]

**验证说明**: rankSize 来自配置/API 参数 (semi_trusted 入口点)，rankSize^2 计算可能溢出，无边界检查保护。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-OVERFLOW-003] integer_overflow - unknown

**严重性**: High | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/platform/resource/transport/host/transport_ibverbs.cc:1069-1071` @ `unknown`
**模块**: platform

**描述**: Integer overflow in malloc at transport_ibverbs.cc. memCount from remote message data is multiplied by sizeof(MemDetails) without overflow check. Malicious peer could send large memCount causing overflow.

**漏洞代码** (`src/platform/resource/transport/host/transport_ibverbs.cc:1069-1071`)

```c
MemDetails* remoteMemDetails = static_cast<MemDetails*>(malloc(memCount * sizeof(MemDetails)));
```

**达成路径**

remote message data -> memCount -> malloc(memCount * sizeof(MemDetails)) [SINK]

**验证说明**: memCount comes from remoteUserDeviceMemMsg_.size() which is populated from network data (remoteDmemNum at line 2065). No overflow validation before malloc multiplication. Vector resize provides partial mitigation by throwing on excessive sizes, but the malloc call still vulnerable.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-ENV-001] path_traversal_environment - unknown

**严重性**: High | **CWE**: CWE-22 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/platform/common/launch_aicpu.cc:200-209` @ `unknown`
**模块**: platform
**跨模块**: platform → framework

**描述**: ASCEND_HOME_PATH environment variable used for binary path construction in launch_aicpu.cc. Attacker controlling this environment variable could redirect binary loading to malicious path, leading to arbitrary code execution via binary planting.

**漏洞代码** (`src/platform/common/launch_aicpu.cc:200-209`)

```c
char *getPath = getenv("ASCEND_HOME_PATH");
if (getPath != nullptr) { libPath = getPath; }
libPath += "/opp/built-in/op_impl/aicpu/config/";
```

**达成路径**

getenv("ASCEND_HOME_PATH") -> libPath -> binary loading [SINK]

**验证说明**: ASCEND_HOME_PATH env var used to construct config directory path. Path traversal possible if attacker controls env var. Fixed suffix '/opp/built-in/op_impl/aicpu/config/' is appended, limiting direct exploitation. Requires env var control which typically needs admin access but exploitable in container/cloud scenarios.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (11)

### [VULN-SEC-001] improper_input_validation - HcomInitByString

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/framework/hcom/hcom.cc:174-175` @ `HcomInitByString`
**模块**: framework

**描述**: 使用 std::atoi() 解析 rank ID 字符串，atoi 对无效输入返回 0 而不报告错误。如果 identify 参数为无效字符串（如非数字字符），rank ID 将被错误设置为 0。rank 0 通常代表协调者节点，可能导致数据路由错误或节点身份混淆。虽然其他路径有 SalStrToULong 等安全转换函数，但此特定路径缺少错误检测。

**漏洞代码** (`src/framework/hcom/hcom.cc:174-175`)

```c
s32 myRank = std::atoi(identify);\nHccl::RankId rank = static_cast<Hccl::RankId>(myRank);
```

**达成路径**

identify [USER_INPUT via HcomInitByString API] -> std::atoi(identify) -> myRank -> Hccl::RankId rank -> HcomInitCollComm(rank)

**验证说明**: std::atoi(identify) 无错误检测，无效输入返回 0。identify 来自配置文件/API (semi_trusted)。rank 0 通常为协调者，可能导致节点身份混淆。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-002] improper_input_validation - HcomInitByFile

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/legacy/framework/entrance/hcom_comm/comm_manager.cc:555-558` @ `HcomInitByFile`
**模块**: legacy

**描述**: 使用 std::atoi() 解析 rank ID 字符串，atoi 对无效输入返回 0 而不报告错误。虽然代码使用 try-catch 包裹，但 atoi 在 C++ 标准中不会抛出异常。无效输入会导致 myRank 为 0，可能导致节点身份混淆。

**漏洞代码** (`src/legacy/framework/entrance/hcom_comm/comm_manager.cc:555-558`)

```c
try {\n    myRank = std::atoi(identify);\n} catch (...) {\n    HCCL_ERROR("atoi(identify) failed!");\n}
```

**达成路径**

identify [USER_INPUT] -> std::atoi(identify) -> myRank -> CommParams.rank

**验证说明**: std::atoi(identify) 用 try-catch 包裹，但 atoi 是 C 函数不抛异常。无效输入返回 0，可能导致 rank 身份错误。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-NUM-002] improper_integer_conversion - HcomInit

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/framework/hcom/hcom.cc:174-176` @ `HcomInit`
**模块**: framework

**描述**: atoi() without error validation in HcomInit. The identify parameter from configuration is converted to rank using std::atoi() which cannot detect conversion errors. Invalid configuration could cause unexpected rank assignment.

**漏洞代码** (`src/framework/hcom/hcom.cc:174-176`)

```c
s32 myRank = std::atoi(identify);
```

**达成路径**

rankTableFile_@src/framework/hcom/hcom.cc [SOURCE] -> identify parameter -> atoi() [SINK]

**验证说明**: std::atoi(identify) 无错误检测，identify 来自配置/API。与 VULN-SEC-001 同一漏洞点。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-NUM-003] improper_integer_conversion - unknown

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/platform/hccp/rdma_service/tlv/rs_adp_nslb.c:46-48` @ `unknown`
**模块**: platform

**描述**: strtoul() without proper error validation in rs_adp_nslb.c. Configuration value is converted to port number using strtoul() without proper error checking. Invalid configuration could cause unexpected port assignment.

**漏洞代码** (`src/platform/hccp/rdma_service/tlv/rs_adp_nslb.c:46-48`)

```c
netcoArg->listenPort = (unsigned short)strtoul(cfgVal, NULL, NETCO_PORT_NUM_BASE);
```

**达成路径**

cfgVal (configuration) -> strtoul() -> listenPort [SINK]

**验证说明**: strtoul(cfgVal, NULL, ...) 用于解析端口配置，无错误检测。无效配置可能导致意外端口值。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-NUM-004] improper_integer_conversion - unknown

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/framework/hcom/hcom_common.cc:1473-1475` @ `unknown`
**模块**: framework

**描述**: atoi() without error validation in hcom_common.cc. The identify parameter is converted using std::atoi() which returns 0 on error without distinguishing between actual zero and invalid input.

**漏洞代码** (`src/framework/hcom/hcom_common.cc:1473-1475`)

```c
s32 myRank = std::atoi(identify);
```

**达成路径**

identify parameter -> atoi() -> myRank [SINK]

**验证说明**: std::atoi(identify) 在 HcomInitByFileV2 调用链中，无错误检测。与 VULN-SEC-001 同类问题。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-NUM-005] improper_integer_conversion - unknown

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/legacy/framework/entrance/hcom_comm/comm_manager.cc:555-558` @ `unknown`
**模块**: framework

**描述**: atoi() without error validation in comm_manager.cc. Multiple instances of std::atoi() used to convert identify parameter without error checking.

**漏洞代码** (`src/legacy/framework/entrance/hcom_comm/comm_manager.cc:555-558`)

```c
myRank = std::atoi(identify);
HCCL_ERROR("atoi(identify) failed!");
```

**达成路径**

identify parameter -> atoi() -> myRank [SINK]

**验证说明**: std::atoi(identify) 在 HcomInitByFile 中，try-catch 无效。与 VULN-SEC-002 同一漏洞点。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MEM-003] memory_copy_without_bounds_check - unknown

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/platform/hccp/rdma_agent/hdc/ra_hdc.c:595-615` @ `unknown`
**模块**: platform

**描述**: memcpy_s uses rcvLen from network data in ra_hdc.c. rcvLen extracted from received HDC message is used in memcpy_s without validation against expected size limits.

**漏洞代码** (`src/platform/hccp/rdma_agent/hdc/ra_hdc.c:595-615`)

```c
ret = RA_HDC_OPS.recv(session, pMsgRcv, MAX_HDC_DATA, RA_HDC_WAIT_TIMEOUT, &recvBufCnt, ...);
ret = memcpy_s(recvBuf, *recvLen, rcvBuf, (unsigned int)rcvLen);
```

**达成路径**

RA_HDC_OPS.recv -> rcvLen -> memcpy_s(recvBuf, *recvLen, rcvBuf, rcvLen) [SINK]

**验证说明**: rcvLen 来自 HDC getMsgBuffer，用于 memcpy_s。有 rcvLen <= 0 检查，但不检查是否超过 recvLen 缓冲区大小。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-NET-001] integer_overflow - HdcAsyncAddResponse

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/platform/hccp/rdma_agent/hdc/async/ra_hdc_async.c:167-173` @ `HdcAsyncAddResponse`
**模块**: platform

**描述**: Network message data length used directly in calloc allocation in ra_hdc_async.c. The msgDataLen from received network message header is used directly to allocate memory without overflow validation. A malicious message with large msgDataLen could cause allocation failure or memory exhaustion.

**漏洞代码** (`src/platform/hccp/rdma_agent/hdc/async/ra_hdc_async.c:167-173`)

```c
reqHandleTmp->recvBuf = (void *)calloc(recvMsgHead->msgDataLen, sizeof(char));
if (reqHandleTmp->recvBuf == NULL) {
```

**达成路径**

RA_HDC_OPS.recv@ra_adp.c:1762 [SOURCE] -> recvMsgHead->msgDataLen -> calloc@ra_hdc_async.c:167 [SINK]

**验证说明**: msgDataLen 来自网络消息头，但 HdcAsyncIsMsgValid (行 142-148) 验证其需匹配预期 dataSize，限制了攻击者控制范围。

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-DF-OVERFLOW-004] integer_overflow - unknown

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/platform/hccp/rdma_agent/client/ra_host.c:1651-1653` @ `unknown`
**模块**: platform

**描述**: Integer overflow in calloc at ra_host.c. *num from HDC receive is used in calloc without overflow validation. Attacker could manipulate HDC message to set large num value causing overflow.

**漏洞代码** (`src/platform/hccp/rdma_agent/client/ra_host.c:1651-1653`)

```c
ifaddrInfos = calloc(*num, sizeof(struct IfaddrInfo));
```

**达成路径**

HDC receive -> *num -> calloc(*num, sizeof(struct IfaddrInfo)) [SINK]

**验证说明**: num 来自 HDC 接收 (RaHdcGetIfaddrs)，有 MAX_WLIST_NUM 检查限制，但检查不防止整数溢出。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-MEM-002] memory_copy_without_bounds_check - unknown

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/framework/communicator/impl/hccl_communicator_host.cc:8409-8412` @ `unknown`
**模块**: framework

**描述**: memcpy_s with unchecked nRanks in hccl_communicator_host.cc. nRanks is used in sizeof(u32) * nRanks calculation without validation against sizeof(switchRankList_) destination buffer.

**漏洞代码** (`src/framework/communicator/impl/hccl_communicator_host.cc:8409-8412`)

```c
memcpy_s(switchRankList_, sizeof(switchRankList_), ranks, sizeof(u32) * nRanks);
```

**达成路径**

nRanks parameter -> sizeof(u32) * nRanks [SINK]

**验证说明**: nRanks 来自 API 参数，用于 memcpy_s 大小计算。有 switchRankId 验证 (行 8422-8428)，但验证在 memcpy 之后进行。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-MEM-004] integer_overflow_memcpy - unknown

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/platform/hccp/rdma_agent/hdc/async/ra_hdc_async_ctx.c:411-415` @ `unknown`
**模块**: platform

**描述**: memcpy_s with num from external input in ra_hdc_async_ctx.c. asyncRsp->num from HDC response is used in memcpy_s(num * sizeof(struct HccpTpInfo)) without overflow check.

**漏洞代码** (`src/platform/hccp/rdma_agent/hdc/async/ra_hdc_async_ctx.c:411-415`)

```c
memcpy_s(asyncRsp->tpInfoList, (*asyncRsp->num) * sizeof(struct HccpTpInfo), ...);
```

**达成路径**

HDC response -> asyncRsp->num -> memcpy_s((*asyncRsp->num) * sizeof(...)) [SINK]

**验证说明**: asyncRsp->num 来自 HDC response，用于 memcpy_s 大小计算。无 overflow 检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| framework | 0 | 3 | 5 | 0 | 8 |
| legacy | 0 | 0 | 1 | 0 | 1 |
| platform | 0 | 2 | 5 | 0 | 7 |
| **合计** | **0** | **5** | **11** | **0** | **16** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-190 | 10 | 62.5% |
| CWE-22 | 2 | 12.5% |
| CWE-20 | 2 | 12.5% |
| CWE-120 | 2 | 12.5% |
