# HCOMM 威胁分析报告

> 生成时间: 2026-04-22T05:18:53Z
> 项目路径: /home/pwn20tty/Desktop/opencode_project/cann/2/hcomm
> 项目类型: network_service (分布式训练通信基础库)

## 1. 项目概述

HCOMM（Huawei Communication）是华为CANN的HCCL通信基础库，用于昇腾AI芯片的分布式训练通信。该库提供标准化通信编程接口，支持以下关键特性：

- **通信协议**: RDMA/RoCE、TCP Socket、HCCS（芯片间）、PCIe（主机-设备）
- **通信原语**: AllReduce、AllGather、Broadcast、ReduceScatter等
- **通信域管理**: 通信域初始化、资源管理、拓扑信息查询
- **部署模式**: 部署于昇腾AI芯片服务器，作为分布式训练通信的基础库

### 项目统计

| 指标 | 数值 |
|------|------|
| 源文件总数 | 311 |
| 代码总行数 | 185,048 |
| 主要语言 | C/C++ |
| 模块数量 | 6 |

## 2. 模块架构

### 2.1 模块划分

| 模块 | 路径 | 语言 | 风险等级 | 主要功能 |
|------|------|------|----------|----------|
| algorithm | src/algorithm | C/C++ | Medium | 通信算法实现（AllReduce、ReduceScatter等） |
| framework | src/framework | C/C++ | Critical | 通信框架核心（API入口、通信域管理） |
| platform | src/platform | C/C++ | Critical | 通信平台（HCCP协议栈、RDMA、Socket） |
| hccd | src/hccd | C/C++ | High | 进程间点对点通信守护进程 |
| legacy | src/legacy | C/C++ | High | 历史版本兼容代码 |
| common | src/common | C/C++ | Low | 公共基础功能（错误码、调试、流管理） |

### 2.2 组件依赖关系

```
Application Layer (Python/Training Scripts)
    ↓
API Layer (hccl_comm.h, hcomm_primitives.h, hcom.h)
    ↓
Framework Layer (op_base, communicator, hcom)
    ↓
Platform Layer (hccp, rdma_service, rdma_agent, netco)
    ↓
Hardware Layer (RDMA NIC, HCCS, PCIe, AICPU)
```

## 3. 入口点分析

### 3.1 高风险入口点

| 入口点 | 文件 | 行号 | 类型 | 信任等级 | 风险说明 |
|--------|------|------|------|----------|----------|
| HcclCommInitClusterInfo | include/hccl/hccl_comm.h | 34 | file | semi_trusted | 接收用户提供的配置文件路径，解析集群拓扑 |
| HcomInit | src/framework/hcom/hcom.cc | 68 | file | semi_trusted | HCOM初始化，解析rank table配置 |
| HcclInitComm | src/hccd/hccd.cc | 52 | file | semi_trusted | HCCL初始化，解析JSON配置 |
| RsSocketAccept | src/platform/hccp/rdma_service/rs_socket.c | 400 | network | untrusted_network | 接收远程TCP连接请求 |
| RsEpollRecvHandle | src/platform/hccp/rdma_service/rs_epoll.c | 100 | network | untrusted_network | 处理网络接收事件 |
| RsEpollRecvQpHandle | src/platform/hccp/rdma_service/rs_rdma.c | 200 | network | untrusted_network | 处理RDMA接收队列事件 |
| HcclRawAccept | src/hccd/hccl_raw.cc | 108 | network | untrusted_network | 原始Socket连接接受 |
| HcclRawConnect | src/hccd/hccl_raw.cc | 57 | network | untrusted_network | 原始Socket连接建立 |

### 3.2 配置文件解析入口

| 入口点 | 文件 | 行号 | 输入来源 | 风险 |
|--------|------|------|----------|------|
| ParseFileToJson | src/legacy/framework/misc/json_parser/json_parser.cc | 73 | 文件系统 | JSON注入、路径遍历 |
| GetJsonProperty | src/legacy/framework/misc/json_parser/json_parser.cc | 16 | JSON对象 | 类型混淆、数值溢出 |
| InitEnvParam | src/framework/common/src/config/env_config.cc | 112 | 环境变量 | 环境变量篡改 |
| CfgGetClusterInfo | src/framework/common/src/topo/topoinfo_ranktableParser.cc | 100 | 配置文件 | 拓扑信息伪造 |

### 3.3 网络通信入口

| 入口点 | 文件 | 协议 | 风险 |
|--------|------|------|------|
| RsSocketInit | src/platform/hccp/rdma_service/rs_socket.c | TCP | 端口绑定、IP欺骗 |
| RsSocketRecv | src/platform/hccp/rdma_service/rs_socket.c | TCP | 数据篡改、DoS |
| RsRdmaRecv | src/platform/hccp/rdma_service/rs_rdma.c | RDMA/RoCE | 内存破坏、QP状态篡改 |
| ibv_post_recv | src/platform/hccp/rdma_service/rs_rdma.c | RDMA | 缓冲区溢出 |
| ibv_post_send | src/platform/hccp/rdma_service/rs_rdma.c | RDMA | 远程内存写入 |

## 4. 信任边界分析

### 4.1 网络边界 (Critical)

**边界**: RDMA/RoCE/TCP网络接口

| 属性 | 说明 |
|------|------|
| 可信侧 | HCCL Library / Application Logic |
| 不可信侧 | Remote Training Nodes / Network |
| 风险等级 | Critical |

**威胁场景**:
- **Spoofing**: 恶意节点伪造身份加入训练集群
- **Tampering**: 网络数据包篡改、RDMA内存写入篡改
- **Repudiation**: 日志记录不足导致无法追踪恶意行为
- **Information Disclosure**: 通信数据泄露训练模型参数
- **Denial of Service**: 网络DoS攻击导致训练中断
- **Elevation of Privilege**: 通过RDMA漏洞获取远程内存访问权限

### 4.2 配置边界 (High)

**边界**: 配置文件输入（Rank Table JSON、环境变量）

| 属性 | 说明 |
|------|------|
| 可信侧 | HCCL Library |
| 不可信侧 | Rank Table JSON File / Environment Variables |
| 飱险等级 | High |

**威胁场景**:
- **Spoofing**: 配置文件伪造集群拓扑，引入恶意节点
- **Tampering**: 配置文件篡改，修改IP地址、端口号
- **Injection**: JSON注入攻击，通过恶意JSON内容触发代码执行
- **Path Traversal**: 通过配置文件路径访问非授权文件

### 4.3 设备边界 (Medium)

**边界**: HCCS/PCIe接口

| 属性 | 说明 |
|------|------|
| 可信侧 | HCCL Library |
| 不可信侧 | Other NPU Devices on Same Server |
| 飱险等级 | Medium |

**威胁场景**:
- 设备间通信数据泄露
- 恶意设备驱动干扰通信

## 5. STRIDE威胁建模

### 5.1 Spoofing (身份伪造)

| 威胁 | 入口点 | 影响 | 缓解措施 |
|------|--------|------|----------|
| 恶意节点伪造身份 | HcclCommInitClusterInfo | 集群被恶意节点入侵 | Root Info验证、白名单校验 |
| 配置文件伪造 | ParseFileToJson | 拓扑信息被篡改 | 文件校验、签名验证 |
| 网络连接伪造 | RsSocketAccept | 未授权连接 | 白名单验证、SSL/TLS |

**现有缓解措施**:
- `RsServerValidAsync` 函数实现白名单验证
- `RsFindWhiteList` 函数检查连接是否在白名单中
- SSL/TLS支持（通过 `ssl_adp_write/ssl_adp_read`）

### 5.2 Tampering (数据篡改)

| 威胁 | 入口点 | 影响 | 缓解措施 |
|------|--------|------|----------|
| 网络数据篡改 | RsSocketRecv | 通信数据损坏 | SSL/TLS加密 |
| RDMA内存篡改 | ibv_post_send | 远程内存被恶意写入 | MR权限控制、QP状态验证 |
| 配置篡改 | ParseFileToJson | 集群拓扑被篡改 | 文件权限控制 |

**现有缓解措施**:
- `memcpy_s` 使用安全函数进行内存操作
- `RsQpStateModify` 管理QP状态防止状态篡改
- SSL加密传输支持

### 5.3 Repudiation (抵赖)

| 威虑 | 入口点 | 影响 | 缓解措施 |
|------|--------|------|----------|
| 无法追踪连接来源 | RsSocketAccept | 恶意行为无法追踪 | 日志记录 |
| 无法追踪配置修改 | ParseFileToJson | 配置篡改无法检测 | 文件完整性校验 |

**现有缓解措施**:
- HCCL_INFO/HCCL_ERROR日志宏记录关键操作
- Rank Table CRC校验（`TransportHeterog::RecordRankTableCrc`）

### 5.4 Information Disclosure (信息泄露)

| 威胁 | 入口点 | 影响 | 缓解措施 |
|------|--------|------|----------|
| 通信数据泄露 | HcommWriteOnThread | 训练参数泄露 | SSL/TLS加密 |
| 配置信息泄露 | HcclCommInitClusterInfo | 集群拓扑泄露 | 文件权限控制 |
| 内存内容泄露 | ibv_post_recv | RDMA缓冲区泄露 | MR权限控制 |

### 5.5 Denial of Service (拒绝服务)

| 威胁 | 入口点 | 影响 | 缓解措施 |
|------|--------|------|----------|
| 网络DoS | RsSocketAccept | 连接资源耗尽 | 连接数限制（MAX_CONN_LINK_NUM） |
| 配置解析DoS | ParseFileToJson | 资源耗尽 | 文件大小限制 |
| RDMA资源耗尽 | RsQpStateModify | QP资源耗尽 | 资源配额管理 |

**现有缓解措施**:
- `IsExceedMaxLinkNum` 检查连接数是否超过限制
- 超时配置支持（`hcclExecTimeOut`）

### 5.6 Elevation of Privilege (权限提升)

| 威胁 | 入口点 | 影响 | 缓解措施 |
|------|--------|------|----------|
| RDMA远程内存访问 | ibv_post_send | 获取远程节点内存访问权限 | MR权限、QP权限控制 |
| 配置注入 | ParseFileToJson | 通过配置注入执行恶意代码 | 输入验证 |

## 6. 高风险文件列表

### 6.1 Critical级别文件

| 文件 | 行数 | 模块 | 风险原因 |
|------|------|------|----------|
| src/platform/hccp/rdma_service/rs_rdma.c | 3092 | platform | RDMA核心实现，QP管理、内存操作 |
| src/platform/hccp/rdma_service/rs_socket.c | 2411 | platform | Socket网络通信，连接验证 |
| src/framework/op_base/src/op_base.cc | 5271 | framework | API入口点，通信域初始化 |
| src/framework/hcom/hcom.cc | 4247 | framework | HCOM初始化，配置解析 |

### 6.2 High级别文件

| 文件 | 行数 | 模块 | 风险原因 |
|------|------|------|----------|
| src/legacy/framework/misc/json_parser/json_parser.cc | 96 | legacy | JSON配置解析 |
| src/framework/common/src/config/env_config.cc | 856 | framework | 环境变量解析 |
| src/framework/common/src/topo/topoinfo_ranktableParser.cc | 400 | framework | Rank Table解析 |
| src/platform/resource/socket/hccl_socket.cc | 500 | platform | Socket管理 |
| src/hccd/hccd.cc | 418 | hccd | 通信守护进程 |
| src/hccd/hccl_comm_conn.cc | 500 | hccd | 连接管理 |

## 7. 攻击面总结

### 7.1 外部攻击面

1. **RDMA/RoCE网络接口** (Critical)
   - QP状态管理漏洞
   - 内存注册/注销漏洞
   - 远程内存读写漏洞

2. **TCP Socket网络接口** (Critical)
   - 连接伪造/劫持
   - 数据包篡改
   - DoS攻击

3. **配置文件解析** (High)
   - JSON注入
   - 路径遍历
   - 类型混淆/数值溢出

4. **环境变量解析** (High)
   - HCCL_*环境变量篡改
   - 端口范围配置篡改

### 7.2 内部攻击面

1. **HCCS芯片间通信** (Medium)
   - 设备间数据泄露
   - 芯片资源竞争

2. **PCIe通信** (Medium)
   - 主机-设备通信干扰

3. **AICPU内核加载** (Medium)
   - 动态内核加载安全

## 8. 安全建议

### 8.1 网络通信安全

1. **强化连接验证**
   - 完善白名单验证机制
   - 添加节点身份认证
   - 实现双向SSL/TLS验证

2. **RDMA安全增强**
   - 严格MR权限控制
   - QP状态变更审计
   - 远程内存访问权限验证

### 8.2 配置解析安全

1. **JSON解析安全**
   - 输入验证和类型检查
   - 数值范围校验
   - 防止JSON注入

2. **配置文件安全**
   - 文件完整性校验（签名验证）
   - 路径规范化检查
   - 权限控制

### 8.3 环境变量安全

1. **环境变量验证**
   - 数值范围校验
   - 格式验证
   - 防止注入

### 8.4 内存安全

1. **安全内存操作**
   - 使用安全函数（memcpy_s等）
   - 边界检查
   - 内存权限控制

## 9. 结论

HCOMM作为分布式训练通信基础库，面临多种安全威胁：

- **最高风险**: RDMA/RoCE网络接口，涉及远程内存操作和QP状态管理
- **高风险**: 配置文件解析和TCP Socket通信
- **中风险**: HCCS/PCIe设备间通信

建议后续漏洞扫描重点关注：
1. RDMA内存操作相关的缓冲区溢出和内存破坏漏洞
2. Socket网络通信相关的注入和DoS漏洞
3. JSON配置解析相关的注入和路径遍历漏洞
4. 环境变量解析相关的注入漏洞

---

*本报告由 Architecture Agent 生成，用于指导后续漏洞扫描工作。*