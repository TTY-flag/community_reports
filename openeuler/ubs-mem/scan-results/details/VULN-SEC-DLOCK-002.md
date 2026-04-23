# VULN-SEC-DLOCK-002：分布式锁凭证伪造授权绕过

## 漏洞概要

| 属性 | 值 |
|-----------|-------|
| **漏洞编号** | VULN-SEC-DLOCK-002 |
| **类型** | 授权绕过（凭证伪造） |
| **CWE** | CWE-639: 通过用户控制键绕过授权 |
| **严重级别** | **严重 (Critical)** |
| **位置** | `src/mxm_shm/rpc_handler.cpp:110-115` |
| **函数** | `HandleMemUnLock` |
| **受影响组件** | 分布式锁RPC处理器 |

## 漏洞描述

RPC解锁操作（`HandleMemUnLock`）接受来自远程RPC请求的自声明进程身份凭证（`pid`、`uid`、`gid`），而没有任何验证机制。这些凭证直接从请求消息中提取并用于验证锁所有权。

`IsLockUdsValid` 执行的"验证"根本上有缺陷——它只将解锁请求声称的凭证与存储的锁元数据进行比较，而这些元数据在锁获取阶段（`HandleMemLock`）也**是自声明的**。这创建了一个循环验证，即未验证的凭证与未验证的凭证进行比较。

### 漏洞代码分析

**位置：`src/mxm_shm/rpc_handler.cpp:110-115`**
```cpp
int MxmServerMsgHandle::HandleMemUnLock(const MsgBase* req, MsgBase* rsp)
{
    // ... 类型验证 ...
    
    dlock_utils::LockUdsInfo udsInfo;
    udsInfo.pid = request->pid_;    // 漏洞：来自RPC请求的自声明
    udsInfo.uid = request->uid_;    // 漏洞：来自RPC请求的自声明  
    udsInfo.gid = request->gid_;    // 漏洞：来自RPC请求的自声明
    udsInfo.validTime = 0;
    response->dLockCode_ = dlock_utils::UbsmLock::Instance().Unlock(request->memName_, udsInfo);
    // ...
}
```

**`HandleMemLock` 中相同漏洞（第88-93行）：**
```cpp
dlock_utils::LockUdsInfo udsInfo;
udsInfo.pid = request->pid_;    // 自声明 - 无验证
udsInfo.uid = request->uid_;    // 自声明 - 无验证
udsInfo.gid = request->gid_;    // 自声明 - 无验证
udsInfo.validTime = 0;
response->dLockCode_ = dlock_utils::UbsmLock::Instance().Lock(request->memName_, request->isExclusive_, udsInfo);
```

**`IsLockUdsValid` 中有缺陷的"验证"（`src/dlock_utils/client_desc.h:137-153`）：**
```cpp
inline bool IsLockUdsValid(const std::string &name, const LockUdsInfo &udsInfo)
{
    // 仅检查声称的凭证是否匹配存储的（同样是自声明的）值
    auto found = it->second.find(udsInfo);  // 循环验证！
    return found != it->second.end();
}
```

## 攻击场景

### 前置条件
1. 攻击者已攻陷或有权限访问分布式集群中的任何节点
2. 攻击者可以发送RPC消息到锁服务节点
3. TLS认证仅验证节点间通信，不验证进程身份

### 攻击流程（与VULN-SEC-DLOCK-001组合）

**步骤1：收集情报**
- 通过名称识别目标锁（例如 `critical_resource_lock`）
- 通过以下方式获取锁持有者声称的凭证：
  - 日志分析
  - 内存检查
  - 被攻陷节点上的进程枚举

**步骤2：伪造凭证**
- 构造 `UnLockRequest` 消息：
  - `memName_` = 目标锁名称
  - `pid_` = 受害者声称的PID
  - `uid_` = 受害者声称的UID
  - `gid_` = 受害者声称的GID

**步骤3：释放锁**
- 发送伪造的RPC解锁请求到锁服务节点
- 验证成功，因为声称的凭证匹配存储的（自声明的）值
- 锁被释放，允许攻击者获取它

**步骤4：锁劫持**
- 攻击者现在持有关键资源的独占锁
- 可以对受保护资源执行任意操作
- 原进程的操作失败或被阻塞

## 利用步骤

### PoC概念
```cpp
// 攻击者构造伪造的解锁请求
auto forgedRequest = UnLockRequest(
    "target_resource_lock",  // 要劫持的锁名称
    VICTIM_PID,              // 伪造 - 从侦察获取
    VICTIM_UID,              // 伪造 - 从侦察获取  
    VICTIM_GID               // 伪造 - 从侦察获取
);

// 通过RPC发送到锁服务
RpcServer::GetInstance().SendMsg(RPC_UNLOCK, &forgedRequest, &response, targetNodeId);

// 验证成功（循环：未验证 vs 未验证）
// 锁被释放

// 攻击者现在用自己的（同样伪造的）凭证获取锁
auto attackRequest = LockRequest(
    "target_resource_lock",
    true,  // 独占
    ATTACKER_PID,
    ATTACKER_UID,
    ATTACKER_GID
);
RpcServer::GetInstance().SendMsg(RPC_LOCK, &attackRequest, &response, targetNodeId);
```

## 影响评估

### 直接影响
- **锁劫持**：未授权释放和获取分布式锁
- **资源损坏**：并发访问独占资源
- **数据完整性破坏**：受保护数据可被未授权方修改
- **服务中断**：依赖锁的关键服务可被阻塞或损坏

### 组合影响（与VULN-SEC-DLOCK-001）
- **完全锁接管**：对集群中任何分布式锁的完全控制
- **集群范围攻击**：攻击可传播到所有节点
- **持久性**：攻击者可无限期保持锁控制
- **隐蔽性**：不记录实际攻击者身份（仅记录伪造凭证）

### 业务影响
- 关键分布式操作可被破坏
- 多节点共识机制可被扰乱
- 数据库/内存完整性可被损害
- 高可用服务可被渲染为不可用

## 受影响代码文件

| 文件 | 行号 | 角色 |
|------|-------|------|
| `src/mxm_shm/rpc_handler.cpp` | 98-118, 73-96 | RPC入口点 - 接受未验证凭证 |
| `src/dlock_utils/client_desc.h` | 137-153 | 有缺陷验证 - 循环凭证检查 |
| `src/dlock_utils/ubsm_lock.cpp` | 592-634 | HandleUnlock - 传播未验证凭证 |
| `src/mxm_message/mxm_msg.h` | 1349-1426 | 消息结构 - 无认证字段 |

## 根因分析

### 主要根因
**缺少凭证验证**：`HandleMemLock` 和 `HandleMemUnLock` 都未实现任何机制来验证声称的进程凭证实际属于请求实体。

### 促成因素
1. **信任RPC层**：系统假设TLS提供足够认证，但TLS仅认证节点，不认证进程
2. **循环验证设计**：`IsLockUdsValid` 将自声明凭证与自声明存储值比较
3. **无进程存在验证**：系统不验证声称的PID在源节点上存在
4. **无凭证绑定**：凭证未与请求实体进行加密绑定

## 修复建议

### 立即修复

**1. 在RPC处理器中实现凭证验证**
```cpp
int MxmServerMsgHandle::HandleMemUnLock(const MsgBase* req, MsgBase* rsp)
{
    auto request = dynamic_cast<const UnLockRequest*>(req);
    
    // 修复：使用源节点实际进程信息验证凭证
    if (!VerifyRpcCredentials(request)) {
        DBG_LOGERROR("解锁请求凭证验证失败");
        response->dLockCode_ = MXM_ERR_AUTH_FAILED;
        return UBSM_OK;
    }
    
    // 使用已验证的凭证，而非自声明的
    dlock_utils::LockUdsInfo verifiedUdsInfo = GetVerifiedCredentials(request);
    response->dLockCode_ = dlock_utils::UbsmLock::Instance().Unlock(request->memName_, verifiedUdsInfo);
}
```

**2. 添加凭证验证函数**
```cpp
bool VerifyRpcCredentials(const UnLockRequest* request) {
    // 方案A：查询源节点获取实际进程凭证
    // 方案B：使用绑定进程身份的加密令牌
    // 方案C：实现内核级凭证证明
    
    // 验证PID存在并匹配声称的UID/GID
    return QuerySourceNodeProcessInfo(request->sourceNodeId, request->pid_) 
           && ValidateProcessCredentials(request->pid_, request->uid_, request->gid_);
}
```

### 架构修复

**1. 进程身份证明**
- 实现节点级证明服务，提供进程身份的加密证明
- 每个进程应被颁发无法被其他进程伪造的令牌
- 锁操作应要求此证明令牌

**2. 加密锁令牌**
```cpp
struct LockRequest : MsgBase {
    std::string memName_;
    bool isExclusive_;
    uint32_t pid_;
    uint32_t uid_;
    uint32_t gid_;
    std::vector<uint8_t> attestationToken_;  // 新增：加密证明
    uint64_t tokenTimestamp_;                 // 新增：新鲜性保证
};
```

**3. 内核级验证**
- 实现提供可验证进程凭证证明的内核模块
- 证明应包含：PID、UID、GID、启动时间和加密签名
- RPC处理器应在接受锁操作前验证证明

### 缓解措施（修复部署前）

1. **网络分段**：仅限制RPC对信任节点的访问
2. **速率限制**：实现每节点锁/解锁操作的速率限制
3. **审计日志**：增强所有锁操作的日志记录，包含源节点归属
4. **锁监控**：实现异常检测以发现意外的锁释放

## 测试建议

### 安全测试用例
1. 测试来自不同节点的伪造凭证锁释放
2. 测试跨不同UID/GID组合的凭证伪造
3. 测试锁劫持攻击链（VULN-001 + VULN-002组合）
4. 测试凭证伪造攻击期间的竞态条件

### 回归测试
- 确保修复后合法锁/解锁操作仍成功
- 验证凭证验证不引入不可接受的延迟
- 测试高负载条件下的凭证验证

## 参考资料

- CWE-639: 通过用户控制键绕过授权
- CWE-287: 不当认证
- OWASP: 认证失效
- 相关：VULN-SEC-DLOCK-001（锁操作凭证伪造）

---

**报告生成日期**: 2026-04-22  
**置信度**: 高（源码分析确认）  
**验证方法**: 静态代码分析、数据流追踪