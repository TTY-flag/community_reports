# 漏洞扫描报告 — 已确认漏洞

**项目**: hcomm (华为 CANN HCOMM 通信基础库)
**扫描时间**: 2026-04-22T05:18:53Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次扫描对华为 CANN HCOMM 通信基础库进行了全面的安全审计，重点关注 RDMA/RoCE/TCP 网络接口和配置文件解析等攻击面。

### 关键发现

**发现 4 个已确认的高危漏洞**，主要涉及：

1. **网络数据接收缺少整数溢出检查** (CWE-130) - 2 个漏洞
   - `hccl_one_sided_conn.cc` 和 `transport_mem.cc` 中，接收的网络数据 `actualNumOfRemote` 直接用于缓冲区大小计算，未检查乘法溢出
   - 存在**不对称安全漏洞**：发送端有溢出检查，但接收端缺失
   - **攻击风险**：恶意节点可发送超大值导致整数溢出，引发缓冲区问题或拒绝服务

2. **strtol 无错误检测** (CWE-190/20) - 2 个漏洞（同一漏洞点）
   - `rs_socket.c:146` 中，网络接收的 tag 数据使用 `strtol(NULL, 10)` 解析
   - NULL endptr 导致无法区分错误与有效值 0
   - **攻击风险**：恶意网络数据可能导致设备 ID 解析错误

### 建议优先级

| 优先级 | 漏洞 | 风险 | 建议修复时间 |
|--------|------|------|-------------|
| P0 | VULN-DF-NET-002/003 | 整数溢出可导致 DoS 或内存问题 | 1 周内 |
| P1 | VULN-DF-NUM-001 | 输入验证缺失，可能导致错误行为 | 2 周内 |

### 安全特性确认

✓ 项目广泛使用安全函数 (`memcpy_s`, `snprintf_s`, `strncpy_s`)
✓ SSL/TLS cipher 配置正确排除弱算法
✓ 白名单验证机制存在
✓ JSON 解析使用 `realpath` 防止路径遍历

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
| High | 4 | 100.0% |
| **有效漏洞总计** | **4** | - |
| 误报 (FALSE_POSITIVE) | 3 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-003]** improper_input_validation (High) - `src/platform/hccp/rdma_service/rs_socket.c:146` @ `rs_socket_fill_wlist_by_phyID` | 置信度: 85
2. **[VULN-DF-NUM-001]** improper_integer_conversion (High) - `src/platform/hccp/rdma_service/rs_socket.c:146` @ `rs_socket_fill_wlist_by_phyID` | 置信度: 85
3. **[VULN-DF-NET-002]** network_data_size_validation (High) - `src/legacy/framework/service/one_sided_service/hccl_one_sided_conn.cc:112` @ `unknown` | 置信度: 85
4. **[VULN-DF-NET-003]** network_data_size_validation (High) - `src/platform/resource/transport/onesided/transport_mem.cc:165` @ `unknown` | 置信度: 85

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

## 3. High 漏洞 (4)

### [VULN-SEC-003] improper_input_validation - rs_socket_fill_wlist_by_phyID

**严重性**: High | **CWE**: CWE-20 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/platform/hccp/rdma_service/rs_socket.c:146-148` @ `rs_socket_fill_wlist_by_phyID`
**模块**: platform

**描述**: 使用 strtol() 解析来自网络连接 tag 的 phyId，但没有检查 strtol 的返回值和 errno。如果 tagTemp 包含无效数字字符串，strtol 返回 0 且不设置 errno（因为 NULL 作为 endptr）。后续的 DlHalGetDeviceInfo 调用会检查返回值，但无效的 phyId=0 可能导致查询错误的设备信息。

**漏洞代码** (`src/platform/hccp/rdma_service/rs_socket.c:146-148`)

```c
phyId = (unsigned int)strtol(tagTemp, NULL, 10);\nret = DlHalGetDeviceInfo(phyId, MODULE_TYPE_SYSTEM, INFO_TYPE_VNIC_IP, &deviceInfo);
```

**达成路径**

rsConn->tag [NETWORK_INPUT] -> tagTemp -> strtol(tagTemp, NULL, 10) -> phyId -> DlHalGetDeviceInfo(phyId)

**验证说明**: strtol(tagTemp, NULL, 10) 解析来自网络 recv 的数据 (行 336)。与 VULN-DF-NUM-001 同一漏洞点。NULL endptr 导致无法检测错误。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-NUM-001] improper_integer_conversion - rs_socket_fill_wlist_by_phyID

**严重性**: High | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/platform/hccp/rdma_service/rs_socket.c:146-150` @ `rs_socket_fill_wlist_by_phyID`
**模块**: platform

**描述**: strtol() without error validation in rs_socket_fill_wlist_by_phyID. Network-received tag data is converted to phyId using strtol() without checking for conversion errors or overflow. Malicious network data could cause invalid device ID lookup or unexpected behavior.

**漏洞代码** (`src/platform/hccp/rdma_service/rs_socket.c:146-150`)

```c
phyId = (unsigned int)strtol(tagTemp, NULL, 10); // Decimal(10)
ret = DlHalGetDeviceInfo(phyId, MODULE_TYPE_SYSTEM, INFO_TYPE_VNIC_IP, &deviceInfo);
```

**达成路径**

recv@src/platform/hccp/rdma_service/rs_socket.c:336 [SOURCE] -> RsTcpRecvTagInHandle@rs_socket.c:324 -> connTmp->tag -> tagTemp -> strtol@rs_socket.c:146 [SINK]

**验证说明**: strtol(tagTemp, NULL, 10) 用于解析来自网络 recv 的 tag 数据 (行 336)。无错误检测，NULL endptr 导致无法区分错误与有效值 0。攻击者可发送无效数据导致 phyId 错误。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-NET-002] network_data_size_validation - unknown

**严重性**: High | **CWE**: CWE-130 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/legacy/framework/service/one_sided_service/hccl_one_sided_conn.cc:112-115` @ `unknown`
**模块**: platform

**描述**: Network recv without overflow check in hccl_one_sided_conn.cc. actualNumOfRemote from network is used in Recv(actualNumOfRemote * sizeof(HcclMemDesc)) without overflow validation. Line 94 has check for Send but line 112 Recv lacks similar protection.

**漏洞代码** (`src/legacy/framework/service/one_sided_service/hccl_one_sided_conn.cc:112-115`)

```c
socket_->Recv((u8 *)remoteMemDescs.array, actualNumOfRemote * sizeof(HcclMemDesc));
```

**达成路径**

network receive -> actualNumOfRemote -> Recv(actualNumOfRemote * sizeof(...)) [SINK]

**验证说明**: Clear asymmetric vulnerability: SendLocalMemDesc (lines 94-96) has overflow check, but ReceiveRemoteMemDesc has NO overflow check at line 112. actualNumOfRemote is directly from network recv (line 105) and multiplied without validation. The Recv call uses unchecked multiplication that could overflow, leading to receiving less data or buffer issues.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-NET-003] network_data_size_validation - unknown

**严重性**: High | **CWE**: CWE-130 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/platform/resource/transport/onesided/transport_mem.cc:165-168` @ `unknown`
**模块**: platform

**描述**: Network Recv without overflow check in transport_mem.cc. actualNumOfRemote from network is used in Recv(actualNumOfRemote * sizeof(RmaMemDesc)) without overflow validation.

**漏洞代码** (`src/platform/resource/transport/onesided/transport_mem.cc:165-168`)

```c
Recv((u8 *)remoteMemDescs.array, actualNumOfRemote * sizeof(RmaMemDesc));
```

**达成路径**

network receive -> actualNumOfRemote -> Recv(actualNumOfRemote * sizeof(...)) [SINK]

**验证说明**: actualNumOfRemote 直接来自网络 recv (行 155)，用于 Recv 缓冲区大小计算 (行 165)。无 overflow 检查，攻击者可发送大值导致整数溢出。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| platform | 0 | 4 | 0 | 0 | 4 |
| **合计** | **0** | **4** | **0** | **0** | **4** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-130 | 2 | 50.0% |
| CWE-20 | 1 | 25.0% |
| CWE-190 | 1 | 25.0% |

---

## 6. 修复建议

### 6.1 整数溢出检查 (CWE-130)

**受影响代码**:
```c
// hccl_one_sided_conn.cc:112 - 缺少溢出检查
socket_->Recv((u8 *)remoteMemDescs.array, actualNumOfRemote * sizeof(HcclMemDesc));

// transport_mem.cc:165 - 缺少溢出检查
Recv((u8 *)remoteMemDescs.array, actualNumOfRemote * sizeof(RmaMemDesc));
```

**修复方案**:

方案 1：添加乘法溢出检查
```c
// 参考 SendLocalMemDesc 的安全模式 (line 94-96)
size_t recvSize = actualNumOfRemote * sizeof(HcclMemDesc);
if (recvSize > MAX_RECV_SIZE || recvSize / sizeof(HcclMemDesc) != actualNumOfRemote) {
    // 处理溢出错误
    return HCCL_ERROR;
}
socket_->Recv((u8 *)remoteMemDescs.array, recvSize);
```

方案 2：使用安全计算函数
```c
size_t recvSize;
if (__builtin_mul_overflow(actualNumOfRemote, sizeof(HcclMemDesc), &recvSize)) {
    return HCCL_ERROR;
}
```

### 6.2 strtol 错误检测 (CWE-190/20)

**受影响代码**:
```c
// rs_socket.c:146 - NULL endptr 导致无法检测错误
phyId = (unsigned int)strtol(tagTemp, NULL, 10);
```

**修复方案**:
```c
char *endptr;
long phyIdLong = strtol(tagTemp, &endptr, 10);

// 检查转换是否成功
if (endptr == tagTemp || *endptr != '\0') {
    // tagTemp 不是有效的数字字符串
    return HCCL_ERROR;
}

// 检查是否溢出
if (phyIdLong < 0 || phyIdLong > UINT_MAX) {
    return HCCL_ERROR;
}

phyId = (unsigned int)phyIdLong;
```

### 6.3 安全编码最佳实践

1. **统一发送/接收安全检查**：确保对称操作（Send/Recv）采用相同的溢出保护
2. **使用安全函数**：继续使用 `memcpy_s`、`snprintf_s` 等安全替代
3. **输入验证边界检查**：对所有来自网络、配置文件的数据进行范围验证
4. **整数运算安全**：使用编译器内置溢出检查（`__builtin_mul_overflow`）或手动检查

---

## 7. 附录

### 7.1 扫描范围

- **扫描目录**: `src/`（排除 `test/`）
- **语言**: C/C++（200+ 文件）
- **代码量**: 185,048 行
- **入口点**: 18 个（网络接口、配置文件、环境变量等）

### 7.2 工具链

- **架构分析**: @architecture
- **数据流扫描**: @dataflow-scanner (C/C++ 污点追踪)
- **安全审计**: @security-auditor
- **漏洞验证**: @verification-worker (置信度评分)
- **报告生成**: report-generator

---

**报告结束**
