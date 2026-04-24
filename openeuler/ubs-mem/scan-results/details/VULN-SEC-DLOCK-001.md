# VULN-SEC-DLOCK-001: DLock RPC 信任请求体 pid/uid/gid 可伪造锁身份

## Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-SEC-DLOCK-001 |
| **Type** | Authorization Bypass (Credential Forgery) |
| **CWE** | CWE-639: Authorization Bypass Through User-Controlled Key |
| **Severity** | Critical |
| **CVSS Score** | 9.1 (Network-based, Low complexity, High impact) |
| **Affected File** | `src/mxm_shm/rpc_handler.cpp:88-93` |
| **Affected Function** | `HandleMemLock`, `HandleMemUnLock` |
| **Trust Level** | Semi-trusted (TLS-authenticated RPC client) |
| **Attack Surface** | TCP RPC (Remote Node Communication) |

---

## Codex 二次确认补充

- 结论：属实，DLock RPC 路径信任请求体中的 `pid_/uid_/gid_`，无法证明真实远端进程身份。
- 场景：攻击者通常需要处在 RPC 信任域内，例如恶意/失陷集群节点；TLS 只能证明节点/通道，不能证明远端进程 uid/gid/pid。
- 去重：覆盖 `VULN-SEC-DLOCK-002`、`VULN-SEC-LOCK-001`、`VULN-SEC-AUTH-003` 同根因重复报告。
- 本段为二次确认补充，原报告其他内容保留不变。
## Vulnerability Description

The RPC distributed lock operations in `HandleMemLock` and `HandleMemUnLock` accept self-declared process identity credentials (`pid`, `uid`, `gid`) directly from the request payload without any verification against the actual source process. This allows an attacker on a remote cluster node to spoof these values to impersonate processes on other nodes, enabling unauthorized lock acquisition or release operations.

### Evidence from Source Code

**Vulnerable Code - RPC Handler (`rpc_handler.cpp:88-93`):**
```cpp
int MxmServerMsgHandle::HandleMemLock(const MsgBase* req, MsgBase* rsp)
{
    auto request = dynamic_cast<const LockRequest*>(req);
    ...
    dlock_utils::LockUdsInfo udsInfo;
    udsInfo.pid = request->pid_;    // DIRECTLY TRUSTED FROM REQUEST!
    udsInfo.uid = request->uid_;    // DIRECTLY TRUSTED FROM REQUEST!
    udsInfo.gid = request->gid_;    // DIRECTLY TRUSTED FROM REQUEST!
    udsInfo.validTime = 0;
    response->dLockCode_ = dlock_utils::UbsmLock::Instance().Lock(request->memName_, request->isExclusive_, udsInfo);
    ...
}
```

**Similar vulnerability in `HandleMemUnLock` (`rpc_handler.cpp:110-115`):**
```cpp
int MxmServerMsgHandle::HandleMemUnLock(const MsgBase* req, MsgBase* rsp)
{
    auto request = dynamic_cast<const UnLockRequest*>(req);
    ...
    dlock_utils::LockUdsInfo udsInfo;
    udsInfo.pid = request->pid_;    // DIRECTLY TRUSTED FROM REQUEST!
    udsInfo.uid = request->uid_;
    udsInfo.gid = request->gid_;
    udsInfo.validTime = 0;
    response->dLockCode_ = dlock_utils::UbsmLock::Instance().Unlock(request->memName_, udsInfo);
    ...
}
```

**Data Flow Analysis:**
1. Remote node sends RPC lock request with arbitrary `pid`, `uid`, `gid` values
2. `HandleMemLock` extracts these values from `LockRequest` message (lines 88-91)
3. Values are passed to `UbsmLock::Instance().Lock()` without verification
4. In `ubsm_lock.cpp`, these values are stored in `ClientDesc::name2UdsInfo` map (line 479)
5. Lock ownership is attributed to the spoofed identity

---

## Comparison: IPC vs RPC Credential Handling

### IPC Interface (Secure Implementation)

The IPC interface correctly obtains credentials from the kernel using the Unix Domain Socket `SO_PEERCRED` mechanism:

**`mxm_message_handler.h:38-44`:**
```cpp
HRESULT Handle(const MsgBase* req, MsgBase* rsp, MxmComBaseMessageHandlerCtxPtr handlerCtx) override
{
    if (isIpc) {
        MxmComUdsInfo udsInfo;
        if (handlerCtx != nullptr) {
            auto info = handlerCtx->GetUdsIdInfo();  // KERNEL-PROVIDED CREDENTIALS!
            udsInfo.pid = info.pid;
            udsInfo.uid = info.uid;
            udsInfo.gid = info.gid;
        }
        ipcHandler(udsInfo, req, rsp);
    }
}
```

The IPC handler obtains `udsInfo` from `handlerCtx->GetUdsIdInfo()`, which returns kernel-provided credentials via `SO_PEERCRED` socket option. This is a secure mechanism that cannot be spoofed by the client.

### RPC Interface (Vulnerable Implementation)

The RPC interface bypasses this protection by directly extracting credentials from the serialized message payload:

```cpp
udsInfo.pid = request->pid_;  // SELF-DECLARED BY REMOTE CLIENT!
```

The RPC client can set arbitrary values for `pid`, `uid`, `gid` in the `LockRequest` message, and the server accepts them without verification.

---

## Attack Scenarios

### Scenario 1: Unauthorized Lock Acquisition (Lock Hijacking)

**Attack Steps:**
1. Attacker gains access to a compromised node in the cluster (via TLS-authenticated RPC)
2. Attacker identifies target shared memory region (e.g., critical database region)
3. Attacker sends RPC_LOCK request with spoofed credentials:
   - `memName_`: target shared memory name
   - `isExclusive_`: true (exclusive/write lock)
   - `pid_`: legitimate owner's PID
   - `uid_`: legitimate owner's UID
   - `gid_`: legitimate owner's GID
4. Server accepts spoofed identity and grants exclusive lock
5. Legitimate owner is blocked or lock is incorrectly attributed

**Impact:** Denial of service, data corruption, race condition exploitation

### Scenario 2: Unauthorized Lock Release (Lock Theft)

**Attack Steps:**
1. Attacker identifies active lock held by another process
2. Attacker sends RPC_UNLOCK request with spoofed credentials matching the lock holder
3. Server validates identity against stored `udsInfo` (which was also spoofable)
4. Lock is released, allowing attacker or other processes to acquire it

**Impact:** Breaking mutual exclusion, data corruption, privilege escalation

### Scenario 3: Cross-Node Identity Impersonation

**Attack Steps:**
1. Attacker on Node A observes lock activity on Node B (via monitoring)
2. Attacker sends RPC request impersonating a high-privilege process on Node B
3. Attacker acquires locks meant for privileged operations
4. Attacker gains unauthorized access to shared memory regions

**Impact:** Privilege escalation, unauthorized data access

---

## Exploit Requirements

| Requirement | Description |
|-------------|-------------|
| **Network Access** | Access to cluster network, ability to connect to RPC port |
| **TLS Credentials** | Valid TLS certificate for cluster authentication (semi-trusted) |
| **Target Knowledge** | Knowledge of shared memory names and target process identities |
| **Complexity** | Low - No special techniques required, just craft malicious RPC message |

---

## Affected Components

| Component | File | Lines | Impact |
|-----------|------|-------|--------|
| `HandleMemLock` | `src/mxm_shm/rpc_handler.cpp` | 73-96 | Lock acquisition bypass |
| `HandleMemUnLock` | `src/mxm_shm/rpc_handler.cpp` | 98-118 | Lock release bypass |
| `LockRequest` | `src/mxm_message/mxm_msg.h` | 1349-1387 | Message carrying spoofable credentials |
| `UnLockRequest` | `src/mxm_message/mxm_msg.h` | 1389-1426 | Message carrying spoofable credentials |
| `LockUdsInfo` | `src/dlock_utils/client_desc.h` | 29-46 | Stored without verification |
| `UbsmLock::Lock` | `src/dlock_utils/ubsm_lock.cpp` | 264-316 | Processes unverified credentials |
| `HandleUnlock` | `src/dlock_utils/ubsm_lock.cpp` | 592-634 | Validates against unverified stored values |

---

## Root Cause Analysis

The vulnerability stems from a fundamental architectural inconsistency:

1. **IPC Path (Local):** Uses kernel-provided `SO_PEERCRED` credentials - **SECURE**
2. **RPC Path (Remote):** Uses self-declared credentials from message payload - **VULNERABLE**

The RPC path was designed assuming that TLS authentication provides sufficient trust, but this is incorrect:
- TLS authenticates the **node** identity, not the **process** identity on that node
- A node may host multiple processes with different privilege levels
- A compromised node or malicious process can impersonate any process on that node

---

## Impact Assessment

### Business Impact
- **Data Integrity:** Shared memory regions may be corrupted due to unauthorized access
- **Service Availability:** Critical processes may be blocked from acquiring locks
- **Security:** Privileged operations may be executed by unprivileged attackers

### Technical Impact
- **Lock Integrity:** Distributed lock mechanism becomes unreliable
- **Authorization:** Process-level authorization completely bypassed
- **Trust Chain:** Attackers can impersonate any process identity

---

## Proof of Concept (Conceptual)

```python
# Conceptual exploit - Craft malicious RPC lock request
import socket
import struct

# Assume TLS connection to RPC server is established
def craft_lock_request(mem_name, target_pid, target_uid, target_gid, exclusive=True):
    """
    Craft LockRequest message with spoofed credentials
    """
    request = {
        'memName': mem_name,           # Target shared memory
        'isExclusive': exclusive,       # Request exclusive lock
        'pid': target_pid,              # Spoofed PID
        'uid': target_uid,              # Spoofed UID
        'gid': target_gid               # Spoofed GID
    }
    # Serialize and send via RPC connection
    return serialize_and_send(request)

# Example: Impersonate root process (PID=1, UID=0, GID=0)
craft_lock_request("critical_db_region", 1, 0, 0, True)
# Server will grant exclusive lock attributed to PID=1, UID=0, GID=0
```

---

## Remediation Recommendations

### Primary Fix: Implement Credential Verification for RPC

**Option A: Node-Level Mapping (Recommended)**

```cpp
int MxmServerMsgHandle::HandleMemLock(const MsgBase* req, MsgBase* rsp)
{
    auto request = dynamic_cast<const LockRequest*>(req);
    
    // VERIFY: Map RPC source node to allowed credential range
    auto sourceNode = GetRpcSourceNode();  // From TLS certificate
    auto allowedCredentials = GetNodeCredentials(sourceNode);
    
    // VALIDATE: Requested credentials must match allowed range for source node
    if (!ValidateCredentials(request->pid_, request->uid_, request->gid_, allowedCredentials)) {
        DBG_LOGERROR("Credential spoofing detected from node: " << sourceNode);
        response->dLockCode_ = MXM_ERR_CREDENTIAL_INVALID;
        return MXM_ERR_CREDENTIAL_INVALID;
    }
    
    // Proceed with verified credentials
    dlock_utils::LockUdsInfo udsInfo;
    udsInfo.pid = request->pid_;
    udsInfo.uid = request->uid_;
    udsInfo.gid = request->gid_;
    ...
}
```

**Option B: Use Node-Scoped Identity**

Instead of per-process identity, use node-scoped identity for RPC locks:

```cpp
// Replace process identity with node identity for RPC
dlock_utils::LockUdsInfo udsInfo;
udsInfo.nodeId = GetRpcSourceNodeId();  // From TLS certificate
udsInfo.processId = request->pid_;       // Local tracking only, not for authorization
```

### Secondary Fix: Add Audit Logging

```cpp
DBG_AUDITWARN("RPC Lock request - SourceNode=%s, ClaimedPID=%u, ClaimedUID=%u, ClaimedGID=%u, MemName=%s",
              sourceNode.c_str(), request->pid_, request->uid_, request->gid_, request->memName_.c_str());
```

### Long-Term Fix: Unified Credential Architecture

Redesign the distributed lock system to use a unified credential model:
- IPC: Continue using `SO_PEERCRED`
- RPC: Use node-level identity with explicit trust mappings
- Never trust self-declared credentials in RPC path

---

## Testing Recommendations

### Security Test Cases

1. **Credential Spoofing Test:**
   - Send RPC_LOCK with mismatched pid/uid/gid
   - Verify server rejects request

2. **Cross-Node Impersonation Test:**
   - Node A sends request claiming to be process on Node B
   - Verify server detects and rejects

3. **Privilege Escalation Test:**
   - Unprivileged node sends request claiming root credentials
   - Verify server rejects

### Regression Test Cases

1. Verify legitimate IPC lock operations still work
2. Verify legitimate RPC lock operations work with verified credentials
3. Verify lock expiration and cleanup still function correctly

---

## References

- **CWE-639:** Authorization Bypass Through User-Controlled Key
  https://cwe.mitre.org/data/definitions/639.html

- **SO_PEERCRED:** Linux socket option for obtaining peer credentials
  https://man7.org/linux/man-pages/man7/unix.7.html

- **CWE-287:** Improper Authentication
  https://cwe.mitre.org/data/definitions/287.html

---

## Timeline

| Date | Event |
|------|-------|
| 2026-04-22 | Vulnerability discovered during security scan |
| 2026-04-22 | Detailed analysis completed |
| TBD | Fix implementation |
| TBD | Security test verification |
| TBD | Deployment |

---

## Appendix: Related Code Locations

### IPC Secure Credential Retrieval
- `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/communication/adapter/mxm_message_handler.h:38-44`
- `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/communication/adapter/mxm_com_base.cpp:253`

### RPC Vulnerable Credential Acceptance
- `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/rpc_handler.cpp:88-93` (Lock)
- `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/rpc_handler.cpp:110-115` (Unlock)

### Credential Storage and Validation
- `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/dlock_utils/client_desc.h:29-46` (LockUdsInfo)
- `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/dlock_utils/client_desc.h:137-153` (IsLockUdsValid)
