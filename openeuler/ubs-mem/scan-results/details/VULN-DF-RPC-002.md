# VULN-DF-RPC-002: DLockClientReinit 信任远端 serverIp_ 可劫持锁服务重连

## 漏洞概述

**漏洞ID**: VULN-DF-RPC-002  
**类型**: improper_input_validation (输入验证不当)  
**CWE**: CWE-20 (Improper Input Validation)  
**严重等级**: Medium → High (验证后升级)  
**置信度**: 85%  
**跨模块影响**: 是 (mxm_shm → dlock_utils)

### 简要描述

`DLockClientReinit` 函数接收来自 RPC 远程节点的 `serverIp_` 参数，**直接赋值**给配置并调用 `Reinit`。攻击者可以通过发送伪造的 RPC 重初始化请求，强制目标节点的分布式锁客户端连接到恶意服务器，实现**锁劫持**或**服务中断**攻击。

---

## Codex 二次确认补充

- 结论：属实，`DLockClientReinit` 直接信任 RPC 请求里的 `serverIp_` 并触发 reinit。
- 场景：不是默认任意互联网远程漏洞；TLS 开启时通常要求恶意/失陷集群节点或有效证书，TLS 关闭时风险扩大。
- 本段为二次确认补充，原报告其他内容保留不变。
## 漏洞原理分析

### 1. 漏洞代码位置

**文件**: `src/mxm_shm/rpc_handler.cpp`  
**函数**: `MxmServerMsgHandle::DLockClientReinit`  
**行号**: 45-71

```cpp
int MxmServerMsgHandle::DLockClientReinit(const MsgBase* req, MsgBase* rsp)
{
    // 仅检查指针非空，未验证请求来源
    if (req == nullptr || rsp == nullptr) {
        DBG_LOGERROR("RPC_DLockClientReinit: invalid param.");
        return MXM_ERR_NULLPTR;
    }
    auto request = dynamic_cast<const DLockClientReinitRequest*>(req);
    auto response = dynamic_cast<DLockClientReinitResponse*>(rsp);
    if (request == nullptr || response == nullptr) {
        DBG_LOGERROR("RPC_DLockClientReinit: invalid param.");
        return MXM_ERR_NULLPTR;
    }
    
    // === 关键漏洞点 ===
    // 直接从RPC请求获取serverIp_，无任何验证
    auto& cfg = dlock_utils::DLockContext::Instance().GetConfig();
    cfg.serverIp = request->serverIp_;  // ← 直接赋值，无验证！
    
    // 使用未验证的IP执行重新初始化
    auto ret = dlock_utils::UbsmLock::Instance().Reinit();
    ...
}
```

### 2. 数据流追踪

```
RPC Request (DLockClientReinitRequest)
    └── serverIp_ (攻击者可控字符串)
            ↓
    rpc_handler.cpp:58
    cfg.serverIp = request->serverIp_  [直接赋值，无验证]
            ↓
    ubsm_lock.cpp:709-761 (Reinit 函数)
    使用 cfg.serverIp 初始化/重连 DLock 客户端
            ↓
    ubsm_lock.cpp:750
    DlockClientReinit(clientId, ctx.GetConfig().serverIp)
            ↓
    ubsm_lock.cpp:854-899 (DlockClientReinit)
    ClientReInitStagesClientReInit(clientId, serverIp.c_str(), ...)
            ↓
    dlock_executor.cpp:265
    DLockClientReinitFunc(clientId, serverIp)  [连接到指定IP]
            ↓
    dlock 库底层连接到攻击者指定的服务器
```

### 3. 关键代码分析

#### 3.1 RPC 消息定义 (mxm_msg.h:1289-1312)

```cpp
struct DLockClientReinitRequest : MsgBase {
    std::string serverIp_;  // ← 攻击者可控字段
    
    explicit DLockClientReinitRequest(const std::string &serverIp) 
        : MsgBase{0, MXM_MSG_BUTT, 0}, serverIp_(serverIp){};
    
    // 序列化/反序列化直接传递字符串，无验证逻辑
    int32_t Deserialize(NetMsgUnpacker& unpacker) override {
        unpacker.Deserialize(serverIp_);
        return UBSM_OK;
    }
};
```

#### 3.2 Reinit 函数使用未验证 IP (ubsm_lock.cpp:709-761)

```cpp
int32_t UbsmLock::Reinit()
{
    ...
    auto& ctx = DLockContext::Instance();
    // 直接使用配置中的 serverIp（已被攻击者篡改）
    DBG_LOGINFO("UbsmLock reinit, serverIp: " << ctx.GetConfig().serverIp);
    
    if (ctx.GetConfig().isDlockServer) {
        // Server端使用攻击者IP
        auto result = DlockServerReinit(ctx.GetConfig().serverIp, sslConfig);
    }
    if (ctx.GetConfig().isDlockClient) {
        for (uint32_t i = 0; i < clients.size(); i++) {
            // Client端连接到攻击者IP
            auto result = DlockClientReinit(clientId, ctx.GetConfig().serverIp);
        }
    }
    return MXM_OK;
}
```

#### 3.3 客户端实际连接 (ubsm_lock.cpp:854-899)

```cpp
int32_t UbsmLock::DlockClientReinit(int32_t clientId, const std::string& serverIp)
{
    // 无IP验证，直接使用
    ret = ClientReInitStagesClientReInit(clientId, serverIp.c_str(), retryCount);
    // 这会调用底层dlock库连接到攻击者指定的地址
}
```

### 4. 缺失的验证检查

| 验证类型 | 是否存在 | 预期行为 |
|---------|---------|---------|
| IP 格式验证 | ❌ 否 | 应使用 `inet_pton` 验证 IPv4/IPv6 格式 |
| IP 白名单检查 | ❌ 否 | 应验证 IP 属于集群已知节点 |
| 来源节点验证 | ❌ 否 | 应验证请求来自合法的 Master 节点 |
| 空值检查 | ❌ 否 | 未检查 serverIp_ 是否为空字符串 |
| 端口范围检查 | ❌ 否 | 未验证配套端口是否合理 |

**对比正常流程中的 IP 设置**：

在 `ubsm_lock_event.cpp` 的 `OnDLockClientInit` (line 102-132) 中，正常的客户端初始化流程：

```cpp
void UbsmLockEvent::OnDLockClientInit(const std::string& masterId)
{
    rpc::RpcNode masterNode;
    // 从已注册的节点配置获取IP（有来源验证）
    if (rpc::NetRpcConfig::GetInstance().ParseRpcNodeFromId(masterId, masterNode) != UBSM_OK) {
        DBG_LOGERROR("Invalid master Id: " << masterId);  // ← 有验证
        return;
    }
    cfg.serverIp = masterNode.ip;  // ← IP来源于已验证的节点配置
}
```

**对比 RPC 处理流程**：

```cpp
// RPC处理中直接使用请求中的字符串，无任何来源验证
cfg.serverIp = request->serverIp_;  // ← 完全信任RPC请求
```

---

## 攻击路径分析

### 攻击场景一：恶意节点伪装 Master

```
步骤1: 攻击者节点加入集群或通过网络可达
       └── 前提条件：能够发送 RPC 消息到目标节点

步骤2: 攻击者构造恶意 RPC_DLOCK_CLIENT_REINIT 请求
       ├── DLockClientReinitRequest 结构
       └── serverIp_ = "攻击者控制的IP地址"

步骤3: 攻击者发送请求到目标节点
       └── RPC_DLOCK_CLIENT_REINIT opcode 消息

步骤4: 目标节点执行 DLockClientReinit
       ├── cfg.serverIp = request->serverIp_ (攻击者IP)
       └── UbsmLock::Instance().Reinit()

步骤5: 目标节点 DLock 客户端重连到攻击者服务器
       ├── 所有锁操作请求发送到攻击者
       └── 攻击者可以拒绝服务或返回伪造响应

步骤6: 攻击后果
       ├── 锁劫持：攻击者控制所有分布式锁
       ├── 服务中断：锁操作失败导致业务崩溃
       ├── 数据竞争：错误的锁状态导致数据不一致
```

### 攻击场景二：服务降级攻击

攻击者可以发送无效 IP 地址，导致：

```
攻击者发送: serverIp_ = "invalid-ip-address" 或空字符串
结果:
    ├── DlockClientReinit 连接失败
    ├── UbsmLock 状态变为不可用
    ├── 所有后续 Lock/Unlock 操作失败
    └── 整个分布式锁服务崩溃
```

### 攻击前置条件

| 条件 | 要求 | 备注 |
|-----|------|------|
| 网络可达 | 攻击者能发送 RPC 消息到目标节点 | 可能是集群内恶意节点或网络入侵 |
| RPC 协议知识 | 了解 RPC_DLOCK_CLIENT_REINIT 消息格式 | 可通过代码分析或协议逆向获得 |
| 无认证机制 | 当前 RPC 无节点身份认证 | 漏洞存在的根本原因 |

---

## 影响范围评估

### 受影响组件

| 模块 | 文件 | 影响程度 |
|-----|------|---------|
| mxm_shm | rpc_handler.cpp | 直接漏洞点 |
| dlock_utils | ubsm_lock.cpp | IP 被滥用执行重连 |
| dlock_utils | dlock_context.cpp | 配置被篡改 |
| mxm_message | mxm_msg.h | 消息结构定义 |

### 受影响场景

1. **分布式锁客户端节点**
   - 任何作为 DLock Client 的节点都可能被攻击
   - 包括 Worker 节点、计算节点等

2. **故障恢复流程**
   - `DoRecovery` 函数 (`ubsm_lock_event.cpp:173-218`) 通过 RPC 发送重初始化请求
   - 该流程中 Master 发送合法请求，但攻击者可以伪造

3. **选举完成后客户端初始化**
   - `OnDLockClientInit` 流程依赖 Master 选举结果
   - 攻击者可以在选举期间或之后发送伪造请求

### 安全影响矩阵

| 影响类型 | 严重程度 | 具体后果 |
|---------|---------|---------|
| 锁劫持 | High | 攻击者完全控制分布式锁逻辑 |
| 服务拒绝 | High | 锁服务不可用导致业务中断 |
| 数据完整性 | Medium | 锁状态异常导致数据竞争 |
| 信息泄露 | Low | 攻击者可观察所有锁请求内容 |

---

## 修复建议

### 方案一：添加来源节点验证（推荐）

在 `DLockClientReinit` 函数中添加请求来源验证：

```cpp
int MxmServerMsgHandle::DLockClientReinit(const MsgBase* req, MsgBase* rsp)
{
    // 现有参数检查...
    
    auto request = dynamic_cast<const DLockClientReinitRequest*>(req);
    
    // === 新增：来源节点验证 ===
    // 获取当前集群 Master 节点信息
    auto localNode = rpc::NetRpcConfig::GetInstance().GetLocalNode();
    auto zenDiscovery = ock::zendiscovery::ZenDiscovery::GetInstance();
    
    std::string expectedMasterId;
    if (zenDiscovery->GetMasterNode(expectedMasterId) != UBSM_OK) {
        DBG_LOGERROR("Cannot verify request source: no master elected");
        response->errCode_ = MXM_ERR_LOCK_NOT_READY;
        return MXM_ERR_LOCK_NOT_READY;
    }
    
    // 验证请求来源节点是否为合法 Master
    rpc::RpcNode expectedMaster;
    if (rpc::NetRpcConfig::GetInstance().ParseRpcNodeFromId(expectedMasterId, expectedMaster) != UBSM_OK) {
        DBG_LOGERROR("Invalid master node ID: " << expectedMasterId);
        response->errCode_ = MXM_ERR_PARAM_INVALID;
        return MXM_ERR_PARAM_INVALID;
    }
    
    // === 新增：IP 格式验证 ===
    if (!IsValidIpAddress(request->serverIp_)) {
        DBG_LOGERROR("Invalid server IP format: " << request->serverIp_);
        response->errCode_ = MXM_ERR_PARAM_INVALID;
        return MXM_ERR_PARAM_INVALID;
    }
    
    // === 新增：IP 白名单检查 ===
    if (!IsIpInClusterWhitelist(request->serverIp_)) {
        DBG_LOGERROR("Server IP not in cluster whitelist: " << request->serverIp_);
        response->errCode_ = MXM_ERR_PARAM_INVALID;
        return MXM_ERR_PARAM_INVALID;
    }
    
    // 验证请求的 serverIp 与 Master IP 一致
    if (request->serverIp_ != expectedMaster.ip) {
        DBG_LOGERROR("Server IP mismatch: expected=" << expectedMaster.ip 
                     << ", received=" << request->serverIp_);
        response->errCode_ = MXM_ERR_PARAM_INVALID;
        return MXM_ERR_PARAM_INVALID;
    }
    
    // 验证通过后才执行重初始化
    auto& cfg = dlock_utils::DLockContext::Instance().GetConfig();
    cfg.serverIp = request->serverIp_;
    auto ret = dlock_utils::UbsmLock::Instance().Reinit();
    ...
}
```

### 方案二：添加 IP 验证辅助函数

新增验证函数：

```cpp
// 在 dlock_common.h 中添加
bool IsValidIpAddress(const std::string& ip) {
    if (ip.empty()) return false;
    
    // IPv4 验证
    struct in_addr ipv4_addr;
    if (inet_pton(AF_INET, ip.c_str(), &ipv4_addr) == 1) {
        return true;
    }
    
    // IPv6 验证
    struct in6_addr ipv6_addr;
    if (inet_pton(AF_INET6, ip.c_str(), &ipv6_addr) == 1) {
        return true;
    }
    
    return false;
}

bool IsIpInClusterWhitelist(const std::string& ip) {
    auto nodes = rpc::NetRpcConfig::GetInstance().GetAllNodes();
    for (const auto& node : nodes) {
        if (node.ip == ip) {
            return true;
        }
    }
    return false;
}
```

### 方案三：RPC 请求认证机制（长期方案）

建议在 RPC 协议层添加节点身份认证：

1. **消息签名验证**
   ```cpp
   struct DLockClientReinitRequest : MsgBase {
       std::string serverIp_;
       std::string senderNodeId_;    // 发送者节点ID
       std::string signature_;       // 消息签名
       uint64_t timestamp_;          // 时间戳防重放
   };
   ```

2. **集群信任节点列表**
   - 维护已认证节点列表
   - 只接受来自信任节点的敏感操作请求

### 方案四：配置不可变设计

防止配置被外部请求直接修改：

```cpp
// 在 dlock_context.h 中修改 GetConfig 返回类型
const DLockConfig& GetConfig() const { return cfg; };  // 只读访问

// 新增专门的更新函数，带验证
bool SetServerIp(const std::string& newIp, const std::string& sourceNodeId) {
    // 验证来源
    // 验证IP格式
    // 验证白名单
    cfg.serverIp = newIp;
    return true;
}
```

---

## 测试验证建议

### 安全测试用例

```cpp
TEST(DLockClientReinitSecurityTest, InvalidIpAddress) {
    auto request = std::make_shared<DLockClientReinitRequest>("invalid-ip");
    auto response = std::make_shared<DLockClientReinitResponse>();
    auto ret = MxmServerMsgHandle::DLockClientReinit(request.get(), response.get());
    EXPECT_NE(ret, UBSM_OK);  // 应拒绝无效IP
}

TEST(DLockClientReinitSecurityTest, EmptyIpAddress) {
    auto request = std::make_shared<DLockClientReinitRequest>("");
    auto response = std::make_shared<DLockClientReinitResponse>();
    auto ret = MxmServerMsgHandle::DLockClientReinit(request.get(), response.get());
    EXPECT_NE(ret, UBSM_OK);  // 应拒绝空IP
}

TEST(DLockClientReinitSecurityTest, NonWhitelistedIp) {
    auto request = std::make_shared<DLockClientReinitRequest>("192.168.999.999");
    auto response = std::make_shared<DLockClientReinitResponse>();
    auto ret = MxmServerMsgHandle::DLockClientReinit(request.get(), response.get());
    EXPECT_NE(ret, UBSM_OK);  // 应拒绝非白名单IP
}

TEST(DLockClientReinitSecurityTest, SpoofedMasterRequest) {
    // 模拟攻击者伪造Master请求
    auto request = std::make_shared<DLockClientReinitRequest>("attacker-ip");
    // ... 设置伪造的来源信息
    auto ret = MxmServerMsgHandle::DLockClientReinit(request.get(), response.get());
    EXPECT_NE(ret, UBSM_OK);  // 应拒绝伪造请求
}
```

---

## 参考信息

- **CWE-20**: Improper Input Validation - https://cwe.mitre.org/data/definitions/20.html
- **CWE-346**: Origin Validation Error - 相关的来源验证问题
- **CVE 参考**: 分布式系统 RPC 安全漏洞案例

---

## 总结

该漏洞是一个典型的**远程输入验证不当**问题，攻击者可以通过伪造 RPC 请求控制分布式锁客户端的服务器连接地址。修复需要在以下层面加强：

1. **输入验证**: IP 格式、空值检查
2. **来源验证**: 确认请求来自合法 Master 节点
3. **白名单机制**: 只允许集群已知节点 IP
4. **配置保护**: 防止配置被外部请求直接篡改

建议优先实施**方案一（来源节点验证）**，该方案与现有的选举机制紧密配合，且能最大程度防止锁劫持攻击。
