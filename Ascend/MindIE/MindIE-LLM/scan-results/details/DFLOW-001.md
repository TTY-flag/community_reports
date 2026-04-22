# DFLOW-001: gRPC 通信中 slave_ip 的输入验证不当

## 漏洞概述

| 属性 | 值 |
|-----------|-------|
| **ID** | DFLOW-001 |
| **类型** | 输入验证不当 |
| **CWE** | CWE-20 (输入验证不当) |
| **严重程度** | 高 |
| **状态** | 已确认 |
| **文件** | `src/executor/grpc_communicator.cpp` |
| **行号** | 627-628 |
| **函数** | `MasterServiceImpl::RegisterAndCommunicate` |

### 描述
来自 gRPC protobuf 消息的网络输入 `slave_ip` 字段被直接用作键来存储流连接，而未调用 `CheckIp()` 验证 IP 格式。控制从节点的攻击者可以注入格式错误的 IP 字符串，导致拒绝服务或潜在的注入攻击。

---

## 触发条件分析

### 攻击面
```
┌─────────────────────────────────────────────────────────────────┐
│                        攻击面                                   │
├─────────────────────────────────────────────────────────────────┤
│  网络攻击向量:                                                  │
│  - 主节点暴露的 gRPC 端口 (multiNodesInferPort)                 │
│  - Protobuf 消息: RegisterRequestMsg.slave_ip (字符串)          │
│  - 如果禁用 TLS 则无需认证                                      │
│                                                                 │
│  入口点:                                                        │
│  - MasterServiceImpl::RegisterAndCommunicate()                  │
│  - 可通过双向流式 RPC 访问                                       │
└─────────────────────────────────────────────────────────────────┘
```

### 可达性评估
**状态: 可达**

该漏洞可直接触发：
1. 从节点通过 `RegisterAndCommunicate` RPC 发起与主节点的连接
2. 流中的第一条消息必须是 `register_request`
3. `slave_ip` 字段在第 627 行被提取并在第 628 行被使用

### 必要条件
| 条件 | 要求 | 评估 |
|-----------|-------------|------------|
| 网络访问 | 可访问主节点的 gRPC 端口 | 必需 - 通常是内部网络 |
| 认证 | 有效从节点证书（如果启用 TLS） | 可选 - TLS 可配置 |
| 授权 | 无 - 任何连接的客户端都可以注册 | **无授权检查** |
| 特定状态 | 主节点等待从节点连接 | 正常运行状态 |

### 触发分析
```cpp
// grpc_communicator.cpp:620-628
grpc::Status MasterServiceImpl::RegisterAndCommunicate(ServerContext *context, SlaveStreamPtr stream)
{
    SlaveToMasterMsg client_msg;
    std::string slaveIpFromStream;
    while (stream->Read(&client_msg)) {
        if (client_msg.has_register_request()) {
            auto &register_request = client_msg.register_request();
            slaveIpFromStream = register_request.slave_ip();  // 第 627 行: 无验证
            gRPCCommunicator_->SlaveIpToStream().Insert(register_request.slave_ip(), stream); // 第 628 行: 已存储
            // ...
        }
    }
}
```

---

## 攻击路径图

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           攻击路径                                            │
└──────────────────────────────────────────────────────────────────────────────┘

     ┌───────────────┐
     │  攻击者       │
     │  (从节点)     │
     └───────┬───────┘
             │
             │ 1. 建立 gRPC 连接
             │    (TLS 根据配置可选)
             ▼
     ┌───────────────────────────────────────┐
     │  主节点                                │
     │  ┌─────────────────────────────────┐  │
     │  │ MasterServiceImpl::             │  │
     │  │ RegisterAndCommunicate()        │  │
     │  │                                 │  │
     │  │  2. 读取 RegisterRequestMsg    │  │
     │  │     slave_ip = <攻击者输入>     │  │
     │  │                                 │  │
     │  │  3. 无验证 ⚠️                   │  │
     │  │     (缺少 CheckIp() 调用)       │  │
     │  │                                 │  │
     │  │  4. 存储到 MAP                  │  │
     │  │     slaveIpToStream_[ip] = str  │  │
     │  └─────────────────────────────────┘  │
     └───────────────────────────────────────┘
             │
             │ 5. 下游影响
             ▼
     ┌───────────────────────────────────────┐
     │  影响向量:                            │
     │                                       │
     │  a) Map 污染                          │
     │     - 内部 map 中出现任意键           │
     │     - 可能导致内存耗尽                │
     │                                       │
     │  b) NPU 利用率追踪                    │
     │     - RecordSlaveNpuUtil() 使用 ip    │
     │     - 数据结构污染                    │
     │                                       │
     │  c) 日志注入                          │
     │     - "Sent registration: slave_ip=..."│
     │     - 攻击者控制的日志内容            │
     │                                       │
     │  d) 请求路由中断                      │
     │     - SendRequest() 使用 ip 进行查找 │
     │     - 格式错误的键导致失败            │
     └───────────────────────────────────────┘
```

---

## PoC 概念大纲

### 攻击场景
1. **前置条件**: 攻击者拥有主节点 gRPC 端口的网络访问权限
2. **利用步骤**:
   - 建立与主节点的 gRPC 连接
   - 发送带有格式错误 `slave_ip` 值的 `RegisterRequestMsg`
   - 恶意值示例:
     - 空字符串（导致空键）
     - 超长字符串（内存消耗）
     - 包含特殊字符的字符串（潜在日志注入）
     - SQL 类模式（如果后续用于数据库查询）
     - 路径遍历模式（`../../etc/passwd`）

### 不提供完整 PoC
遵循负责任披露原则，不提供详细的利用代码。该漏洞已通过代码分析确认。

---

## 影响评估

### 严重程度: 高

| 影响类别 | 评级 | 理由 |
|-----------------|--------|---------------|
| **机密性** | 低 | 无直接数据泄露 |
| **完整性** | 中 | Map 污染影响内部状态 |
| **可用性** | 高 | 通过格式错误数据处理导致 DoS |
| **可利用性** | 中 | 需要访问 gRPC 端口的网络权限 |

### 具体影响

#### 1. 拒绝服务（高影响）
- **Map 键污染**: 攻击者可以注入任意字符串作为 map 键
- **内存耗尽**: 大量或超大的格式错误 IP 消耗内存
- **服务中断**: 后续使用该 IP 的操作可能失败

#### 2. 日志注入（中影响）
```cpp
// grpc_communicator.cpp:331
MINDIE_LLM_LOG_INFO("Sent registration to master: slave_ip=" + slaveIp_);
```
攻击者控制的日志内容可能:
- 破坏日志解析/分析工具
- 在日志中隐藏恶意活动
- 可能利用日志处理漏洞

#### 3. 数据结构损坏（中影响）
```cpp
// grpc_communicator.cpp:444
void GRPCCommunicator::RecordSlaveNpuUtil(const std::string &slaveIp, uint32_t maxAicoreUtilizationPercent)
{
    slaveIpToMaxNpuUtil_[slaveIp] = {...};
}
```
NPU 利用率追踪使用未验证的 IP 作为键。

#### 4. 请求路由中断（中影响）
```cpp
// grpc_communicator.cpp:393
std::optional<SlaveStreamPtr> stream = slaveIpToStream_.Get(slaveIp);
```
主节点通过 IP 查找将请求路由到从节点；格式错误的 IP 会导致路由失败。

---

## 现有缓解措施

### 1. TLS/mTLS 认证（部分缓解）
```cpp
// grpc_communicator.cpp:74-87
auto it = modelConfig.find("interNodeTLSEnabled");
interNodeTLSEnabled_ = (it != modelConfig.end() && it->second == "1");
if (interNodeTLSEnabled_) {
    // 加载证书进行双向认证
}
```
**有效性**: 如果启用 TLS，攻击者需要有效证书才能连接。
**局限性**: TLS 是**可选的**，在许多部署中默认禁用。

### 2. 网络隔离（取决于部署）
gRPC 端口通常在内部网络，限制了外部攻击面。

### 3. CheckIp 函数已存在（未应用）
```cpp
// common_util.cpp:699-715
bool CheckIp(const std::string &ipAddress, const std::string &inputName, bool enableZeroIp)
{
    if (ipAddress.empty()) { return false; }
    if (IsIPv6(ipAddress)) { return CheckIPV6(...); }
    else if (IsIPv4(ipAddress)) { return CheckIPV4(...); }
    else { return false; }  // 不是有效的 IP 格式
}
```
验证函数已存在并在其他地方使用，但**未应用于此输入**。

---

## 漏洞证据

### 与已验证代码路径对比

**已验证输入 (server_config.cpp:554)**:
```cpp
for (auto &slaveIp: serverConfig_.layerwiseDisaggregatedSlaveIpAddress) {
    CheckIp(slaveIp, "layerwiseDisaggregatedSlaveIpAddress", false);
}
```

**已验证输入 (http_handler.cpp:1932)**:
```cpp
if (!mindie_llm::CheckIp(dTargetIp, "d-target", false)) {
    // 拒绝无效 IP
}
```

**未验证输入 (grpc_communicator.cpp:627-628)**:
```cpp
slaveIpFromStream = register_request.slave_ip();  // 无检查
gRPCCommunicator_->SlaveIpToStream().Insert(register_request.slave_ip(), stream);
```

### 单元测试证据
```cpp
// grpc_communicator_test.cpp
comm.SlaveIpToStream().Insert("1.1.1.1", nullptr);  // 测试中使用有效 IP
comm.SlaveIpToStream().Insert("2.2.2.2", nullptr);  // 测试中使用有效 IP
```
测试使用有效 IP，但不存在验证来拒绝无效 IP。

---

## 修复建议

### 推荐修复
在存储 `slave_ip` 之前应用 `CheckIp()` 验证:

```cpp
grpc::Status MasterServiceImpl::RegisterAndCommunicate(ServerContext *context, SlaveStreamPtr stream)
{
    SlaveToMasterMsg client_msg;
    std::string slaveIpFromStream;
    while (stream->Read(&client_msg)) {
        if (client_msg.has_register_request()) {
            auto &register_request = client_msg.register_request();
            std::string slaveIp = register_request.slave_ip();
            
            // 添加验证
            if (!CheckIp(slaveIp, "slave_ip", false)) {
                MINDIE_LLM_LOG_ERROR("Invalid slave IP format rejected: " << slaveIp);
                return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, 
                                   "Invalid slave_ip format");
            }
            
            slaveIpFromStream = slaveIp;
            gRPCCommunicator_->SlaveIpToStream().Insert(slaveIp, stream);
            // ...
        }
    }
}
```

### 额外建议
1. **输入长度限制**: 为 IP 字符串添加最大长度检查
2. **日志净化**: 在记录日志前净化 IP 以防止日志注入
3. **默认启用 TLS**: 考虑为节点间通信默认启用 TLS
4. **认证**: 实现超出证书验证的节点认证机制

---

## 结论

**DFLOW-001 是已确认的真实漏洞**

该漏洞由于缺少对网络输入数据的验证而存在。虽然影响主要是拒绝服务和数据完整性（而非远程代码执行），但当攻击者拥有 gRPC 端口的网络访问权限时，该漏洞很容易被利用。修复方案很简单——应用代码库中其他代码路径已使用的 `CheckIp()` 验证函数。

**风险评估**: 高
- 网络输入直接进入内部数据结构
- 缺少代码库其他地方已存在的验证
- DoS 和日志注入影响已确认
- 缓解措施（TLS）是可选的，非强制