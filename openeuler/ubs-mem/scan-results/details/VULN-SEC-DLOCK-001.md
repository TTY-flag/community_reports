# VULN-SEC-DLOCK-001：分布式锁凭证伪造授权绕过

## 概要

| 属性 | 值 |
|-----------|-------|
| **漏洞编号** | VULN-SEC-DLOCK-001 |
| **类型** | 授权绕过（凭证伪造） |
| **CWE** | CWE-639: 通过用户控制键绕过授权 |
| **严重级别** | 严重 (Critical) |
| **CVSS评分** | 9.1 (网络型，低复杂度，高影响) |
| **受影响文件** | `src/mxm_shm/rpc_handler.cpp:88-93` |
| **受影响函数** | `HandleMemLock`, `HandleMemUnLock` |
| **信任级别** | 半信任（TLS认证的RPC客户端） |
| **攻击面** | TCP RPC（远程节点通信） |

---

## 漏洞描述

`HandleMemLock` 和 `HandleMemUnLock` 中的 RPC 分布式锁操作直接从请求负载中接受自声明的进程身份凭证（`pid`、`uid`、`gid`），而未对实际源进程进行任何验证。这允许远程集群节点上的攻击者伪造这些值以冒充其他节点上的进程，实现未经授权的锁获取或释放操作。

### 源码证据

**漏洞代码 - RPC处理器 (`rpc_handler.cpp:88-93`)：**
```cpp
int MxmServerMsgHandle::HandleMemLock(const MsgBase* req, MsgBase* rsp)
{
    auto request = dynamic_cast<const LockRequest*>(req);
    ...
    dlock_utils::LockUdsInfo udsInfo;
    udsInfo.pid = request->pid_;    // 直接信任请求中的值！
    udsInfo.uid = request->uid_;    // 直接信任请求中的值！
    udsInfo.gid = request->gid_;    // 直接信任请求中的值！
    udsInfo.validTime = 0;
    response->dLockCode_ = dlock_utils::UbsmLock::Instance().Lock(request->memName_, request->isExclusive_, udsInfo);
    ...
}
```

**`HandleMemUnLock` 中类似漏洞 (`rpc_handler.cpp:110-115`)：**
```cpp
int MxmServerMsgHandle::HandleMemUnLock(const MsgBase* req, MsgBase* rsp)
{
    auto request = dynamic_cast<const UnLockRequest*>(req);
    ...
    dlock_utils::LockUdsInfo udsInfo;
    udsInfo.pid = request->pid_;    // 直接信任请求中的值！
    udsInfo.uid = request->uid_;
    udsInfo.gid = request->gid_;
    udsInfo.validTime = 0;
    response->dLockCode_ = dlock_utils::UbsmLock::Instance().Unlock(request->memName_, udsInfo);
    ...
}
```

**数据流分析：**
1. 远程节点发送带有任意 `pid`、`uid`、`gid` 值的 RPC 锁请求
2. `HandleMemLock` 从 `LockRequest` 消息中提取这些值（第88-91行）
3. 值被传递给 `UbsmLock::Instance().Lock()` 而未进行验证
4. 在 `ubsm_lock.cpp` 中，这些值被存储在 `ClientDesc::name2UdsInfo` map（第479行）
5. 锁所有权被归因于伪造的身份

---

## 对比：IPC vs RPC 凭证处理

### IPC接口（安全实现）

IPC接口正确使用 Unix Domain Socket 的 `SO_PEERCRED` 机制从内核获取凭证：

**`mxm_message_handler.h:38-44`：**
```cpp
HRESULT Handle(const MsgBase* req, MsgBase* rsp, MxmComBaseMessageHandlerCtxPtr handlerCtx) override
{
    if (isIpc) {
        MxmComUdsInfo udsInfo;
        if (handlerCtx != nullptr) {
            auto info = handlerCtx->GetUdsIdInfo();  // 内核提供的凭证！
            udsInfo.pid = info.pid;
            udsInfo.uid = info.uid;
            udsInfo.gid = info.gid;
        }
        ipcHandler(udsInfo, req, rsp);
    }
}
```

IPC处理器从 `handlerCtx->GetUdsIdInfo()` 获取 `udsInfo`，该函数通过 `SO_PEERCRED` socket 选项返回内核提供的凭证。这是一种安全的机制，无法被客户端伪造。

### RPC接口（漏洞实现）

RPC接口绕过此保护，直接从序列化消息负载中提取凭证：

```cpp
udsInfo.pid = request->pid_;  // 远程客户端自声明！
```

RPC客户端可以在 `LockRequest` 消息中为 `pid`、`uid`、`gid` 设置任意值，服务器接受这些值而未进行验证。

---

## 攻击场景

### 场景1：未授权锁获取（锁劫持）

**攻击步骤：**
1. 攻击者获得集群中被攻陷节点的访问权限（通过TLS认证的RPC）
2. 攻击者识别目标共享内存区域（如关键数据库区域）
3. 攻击者发送带有伪造凭证的 RPC_LOCK 请求：
   - `memName_`：目标共享内存名称
   - `isExclusive_`：true（独占/写锁）
   - `pid_`：合法持有者的PID
   - `uid_`：合法持有者的UID
   - `gid_`：合法持有者的GID
4. 服务器接受伪造身份并授予独占锁
5. 合法持有者被阻塞或锁被错误归属

**影响：** 拒绝服务、数据损坏、竞态条件利用

### 场景2：未授权锁释放（锁窃取）

**攻击步骤：**
1. 攻击者识别其他进程持有的活跃锁
2. 攻击者发送凭证与锁持有者匹配的 RPC_UNLOCK 请求
3. 服务器根据存储的 `udsInfo` 验证身份（该信息也可被伪造）
4. 锁被释放，允许攻击者或其他进程获取它

**影响：** 破坏互斥、数据损坏、权限提升

### 场景3：跨节点身份冒充

**攻击步骤：**
1. 节点A上的攻击者观察节点B上的锁活动（通过监控）
2. 攻击者发送冒充节点B上高权限进程的RPC请求
3. 攻击者获取用于特权操作的锁
4. 攻击者获得对共享内存区域的未授权访问

**影响：** 权限提升、未授权数据访问

---

## 利用条件

| 条件 | 描述 |
|-------------|-------------|
| **网络访问** | 访问集群网络，能够连接到RPC端口 |
| **TLS凭证** | 用于集群认证的有效TLS证书（半信任） |
| **目标知识** | 了解共享内存名称和目标进程身份 |
| **复杂度** | 低 - 不需要特殊技术，只需构造恶意RPC消息 |

---

## 受影响组件

| 组件 | 文件 | 行号 | 影响 |
|-----------|------|-------|--------|
| `HandleMemLock` | `src/mxm_shm/rpc_handler.cpp` | 73-96 | 锁获取绕过 |
| `HandleMemUnLock` | `src/mxm_shm/rpc_handler.cpp` | 98-118 | 锁释放绕过 |
| `LockRequest` | `src/mxm_message/mxm_msg.h` | 1349-1387 | 携带可伪造凭证的消息 |
| `UnLockRequest` | `src/mxm_message/mxm_msg.h` | 1389-1426 | 携带可伪造凭证的消息 |
| `LockUdsInfo` | `src/dlock_utils/client_desc.h` | 29-46 | 未验证存储 |
| `UbsmLock::Lock` | `src/dlock_utils/ubsm_lock.cpp` | 264-316 | 处理未验证凭证 |
| `HandleUnlock` | `src/dlock_utils/ubsm_lock.cpp` | 592-634 | 与未验证存储值比对 |

---

## 根因分析

漏洞源于根本性的架构不一致：

1. **IPC路径（本地）：** 使用内核提供的 `SO_PEERCRED` 凭证 - **安全**
2. **RPC路径（远程）：** 使用消息负载中的自声明凭证 - **漏洞**

RPC路径的设计假设TLS认证提供足够的信任，但这是不正确的：
- TLS认证的是**节点**身份，而非该节点上的**进程**身份
- 一个节点可能托管具有不同权限级别的多个进程
- 被攻陷的节点或恶意进程可以冒充该节点上的任何进程

---

## 影响评估

### 业务影响
- **数据完整性：** 共享内存区域可能因未授权访问而损坏
- **服务可用性：** 关键进程可能被阻塞无法获取锁
- **安全性：** 特权操作可能被非特权攻击者执行

### 技术影响
- **锁完整性：** 分布式锁机制变得不可靠
- **授权：** 进程级授权完全被绕过
- **信任链：** 攻击者可以冒充任何进程身份

---

## 概念验证（概念性）

```python
# 概念性利用 - 构造恶意RPC锁请求
import socket
import struct

# 假设已建立到RPC服务器的TLS连接
def craft_lock_request(mem_name, target_pid, target_uid, target_gid, exclusive=True):
    """
    构造带有伪造凭证的 LockRequest 消息
    """
    request = {
        'memName': mem_name,           # 目标共享内存
        'isExclusive': exclusive,       # 请求独占锁
        'pid': target_pid,              # 伪造的PID
        'uid': target_uid,              # 伪造的UID
        'gid': target_gid               # 伪造的GID
    }
    # 序列化并通过RPC连接发送
    return serialize_and_send(request)

# 示例：冒充root进程（PID=1, UID=0, GID=0）
craft_lock_request("critical_db_region", 1, 0, 0, True)
# 服务器将授予归属为 PID=1, UID=0, GID=0 的独占锁
```

---

## 修复建议

### 主要修复：为RPC实现凭证验证

**方案A：节点级映射（推荐）**

```cpp
int MxmServerMsgHandle::HandleMemLock(const MsgBase* req, MsgBase* rsp)
{
    auto request = dynamic_cast<const LockRequest*>(req);
    
    // 验证：将RPC源节点映射到允许的凭证范围
    auto sourceNode = GetRpcSourceNode();  // 从TLS证书获取
    auto allowedCredentials = GetNodeCredentials(sourceNode);
    
    // 验证：请求的凭证必须匹配源节点的允许范围
    if (!ValidateCredentials(request->pid_, request->uid_, request->gid_, allowedCredentials)) {
        DBG_LOGERROR("检测到来自节点的凭证伪造: " << sourceNode);
        response->dLockCode_ = MXM_ERR_CREDENTIAL_INVALID;
        return MXM_ERR_CREDENTIAL_INVALID;
    }
    
    // 使用已验证的凭证继续
    dlock_utils::LockUdsInfo udsInfo;
    udsInfo.pid = request->pid_;
    udsInfo.uid = request->uid_;
    udsInfo.gid = request->gid_;
    ...
}
```

**方案B：使用节点范围身份**

使用节点范围身份而非进程身份进行RPC锁操作：

```cpp
// 用节点身份替换RPC的进程身份
dlock_utils::LockUdsInfo udsInfo;
udsInfo.nodeId = GetRpcSourceNodeId();  // 从TLS证书获取
udsInfo.processId = request->pid_;       // 仅用于本地跟踪，不用于授权
```

### 次要修复：添加审计日志

```cpp
DBG_AUDITWARN("RPC锁请求 - 源节点=%s, 声称PID=%u, 声称UID=%u, 声称GID=%u, 内存名=%s",
              sourceNode.c_str(), request->pid_, request->uid_, request->gid_, request->memName_.c_str());
```

### 长期修复：统一凭证架构

重新设计分布式锁系统以使用统一凭证模型：
- IPC：继续使用 `SO_PEERCRED`
- RPC：使用节点级身份并设置显式信任映射
- 永不信任RPC路径中的自声明凭证

---

## 测试建议

### 安全测试用例

1. **凭证伪造测试：**
   - 发送带有不匹配pid/uid/gid的RPC_LOCK
   - 验证服务器拒绝请求

2. **跨节点冒充测试：**
   - 节点A发送声称是节点B上进程的请求
   - 验证服务器检测并拒绝

3. **权限提升测试：**
   - 非特权节点发送声称root凭证的请求
   - 验证服务器拒绝

### 回归测试用例

1. 验证合法IPC锁操作仍然正常工作
2. 验证合法RPC锁操作在验证凭证后正常工作
3. 验证锁过期和清理仍然正确运行

---

## 参考资料

- **CWE-639:** 通过用户控制键绕过授权
  https://cwe.mitre.org/data/definitions/639.html

- **SO_PEERCRED:** Linux socket选项用于获取对端凭证
  https://man7.org/linux/man-pages/man7/unix.7.html

- **CWE-287:** 不当认证
  https://cwe.mitre.org/data/definitions/287.html

---

## 时间线

| 日期 | 事件 |
|------|-------|
| 2026-04-22 | 安全扫描期间发现漏洞 |
| 2026-04-22 | 完成详细分析 |
| TBD | 修复实现 |
| TBD | 安全测试验证 |
| TBD | 部署 |

---

## 附录：相关代码位置

### IPC安全凭证获取
- `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/communication/adapter/mxm_message_handler.h:38-44`
- `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/communication/adapter/mxm_com_base.cpp:253`

### RPC漏洞凭证接受
- `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/rpc_handler.cpp:88-93` (Lock)
- `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/rpc_handler.cpp:110-115` (Unlock)

### 凭证存储和验证
- `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/dlock_utils/client_desc.h:29-46` (LockUdsInfo)
- `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/dlock_utils/client_desc.h:137-153` (IsLockUdsValid)