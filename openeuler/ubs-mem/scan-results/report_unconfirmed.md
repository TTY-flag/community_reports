# 漏洞扫描报告 — 待确认漏洞

**项目**: ubs-mem
**扫描时间**: 2026-04-22T21:43:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 15 | 48.4% |
| POSSIBLE | 9 | 29.0% |
| CONFIRMED | 4 | 12.9% |
| FALSE_POSITIVE | 3 | 9.7% |
| **总计** | **31** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 5 | 20.8% |
| Medium | 18 | 75.0% |
| Low | 1 | 4.2% |
| **有效漏洞总计** | **24** | - |
| 误报 (FALSE_POSITIVE) | 3 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-MXM-SHM-001]** Missing Input Validation - Size Parameter (High) - `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:118` @ `ShmCreate` | 置信度: 75
2. **[VULN-DF-MXM-SHM-002]** Missing Input Validation - Name Parameter (High) - `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:118` @ `ShmCreate` | 置信度: 70
3. **[VUL-UNDER-API-004]** Improper Input Validation (High) - `src/under_api/ubse/ubse_mem_adapter.cpp:1075` @ `ShmCreate` | 置信度: 65
4. **[VULN-COM-003]** missing_input_validation (High) - `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/communication/adapter/mxm_com_engine.cpp:305` @ `MxmComEngine::CreateChannel` | 置信度: 65
5. **[VULN-SEC-PROC-001]** insecure_temporary_file (High) - `src/process/daemon/main.cpp:19` @ `CheckIsRunning` | 置信度: 60
6. **[VULN-DF-MXM-SHM-003]** Missing Input Validation - Size Parameter in ShmMap (Medium) - `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:584` @ `ShmMap` | 置信度: 65
7. **[VULN-DF-MXM-SHM-005]** Missing Input Validation - RPC Lock Name Parameter (Medium) - `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/rpc_handler.cpp:73` @ `HandleMemLock` | 置信度: 65
8. **[VULN-COM-006]** missing_input_validation (Medium) - `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:584` @ `MxmServerMsgHandle::ShmMap` | 置信度: 65
9. **[VULN-COM-007]** missing_input_validation (Medium) - `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/rpc_handler.cpp:73` @ `MxmServerMsgHandle::HandleMemLock` | 置信度: 65
10. **[VUL-DLOCK-001]** Improper Input Validation (Medium) - `src/dlock_utils/ubsm_lock.cpp:510` @ `GetLock` | 置信度: 65

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `ShmCreate@src/mxm_shm/ipc_handler.cpp` | ipc | semi_trusted | Unix Domain Socket IPC接口，本地进程通过UDS发送共享内存创建请求，请求包含name/size等参数，socket路径由管理员配置 | 处理共享内存创建IPC请求 |
| `ShmMap@src/mxm_shm/ipc_handler.cpp` | ipc | semi_trusted | Unix Domain Socket IPC接口，本地进程请求映射共享内存，请求包含name/size/prot参数 | 处理共享内存映射IPC请求 |
| `ShmDelete@src/mxm_shm/ipc_handler.cpp` | ipc | semi_trusted | Unix Domain Socket IPC接口，本地进程请求删除共享内存 | 处理共享内存删除IPC请求 |
| `ShmUnmap@src/mxm_shm/ipc_handler.cpp` | ipc | semi_trusted | Unix Domain Socket IPC接口，本地进程请求取消映射 | 处理共享内存取消映射IPC请求 |
| `ShmWriteLock@src/mxm_shm/ipc_handler.cpp` | ipc | semi_trusted | Unix Domain Socket IPC接口，本地进程请求写锁 | 处理共享内存写锁IPC请求 |
| `AppMallocMemory@src/mxm_lease/ipc_handler.cpp` | ipc | semi_trusted | Unix Domain Socket IPC接口，本地进程请求借用内存 | 处理内存借用IPC请求 |
| `AppFreeMemory@src/mxm_lease/ipc_handler.cpp` | ipc | semi_trusted | Unix Domain Socket IPC接口，本地进程请求释放借用内存 | 处理内存释放IPC请求 |
| `HandleMemLock@src/mxm_shm/rpc_handler.cpp` | rpc | semi_trusted | RPC接口，远程节点请求分布式锁操作，需TLS认证 | 处理RPC分布式锁请求 |
| `PingRequestInfo@src/mxm_shm/rpc_handler.cpp` | rpc | semi_trusted | RPC接口，节点发现Ping请求，需TLS认证 | 处理节点发现Ping请求 |
| `CreateChannel@src/communication/adapter/mxm_com_engine.cpp` | network | semi_trusted | 网络连接创建，TCP/UDS协议，RPC通信使用TLS保护 | 创建网络通信通道 |
| `Initialize@src/process/daemon/ock_daemon.cpp` | cmdline | trusted_admin | 守护进程初始化入口，由systemd启动，参数来自配置文件 | 守护进程初始化 |
| `LoadDecryptFunction@src/security/cryptor/ubs_cryptor_handler.cpp` | file | trusted_admin | 动态加载解密库/usr/local/ubs_mem/lib/libdecrypt.so，路径硬编码 | 加载解密动态库 |
| `Initialize@src/under_api/ubse/ubse_mem_adapter.cpp` | file | trusted_admin | 动态加载UBSE库/usr/lib64/libubse-client.so.1，路径硬编码 | 加载UBSE底层库 |

**其他攻击面**:
- Unix Domain Socket IPC: /var/run/ubsmd.sock (本地进程通信)
- TCP RPC: 配置文件指定的IP和端口 (远程节点通信，TLS可选)
- 配置文件: /opt/ubs_mem/config/ubsmd.conf (管理员控制)
- 动态库加载: dlopen libubse-client.so.1, libdecrypt.so
- 共享内存: shm_open /ubsm_records (内部数据存储)

---

## 3. High 漏洞 (5)

### [VULN-DF-MXM-SHM-001] Missing Input Validation - Size Parameter - ShmCreate

**严重性**: High | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:118-230` @ `ShmCreate`
**模块**: mxm_shm
**跨模块**: mxm_shm,under_api

**描述**: ShmCreate IPC handler accepts size parameter from untrusted IPC source without upper bound validation. Large size values could lead to integer overflow in memory allocation or resource exhaustion. The size is directly passed to UbseMemAdapter::ShmCreate without validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:118-230`)

```c
createParam.size = request->size_; // Line 204 - No validation\nauto hr = mxm::UbseMemAdapter::ShmCreate(createParam); // Line 214
```

**达成路径**

IPC Request(ShmCreateRequest::size_) -> ipc_handler.cpp:ShmCreate() -> createParam.size -> under_api::UbseMemAdapter::ShmCreate() -> pUbseMemShmCreate()

**验证说明**: ShmCreate IPC handler accepts size parameter from IPC request without upper bound validation (line 204). Large size could cause memory exhaustion or integer overflow in downstream UBSE API.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MXM-SHM-002] Missing Input Validation - Name Parameter - ShmCreate

**严重性**: High | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:118-230` @ `ShmCreate`
**模块**: mxm_shm
**跨模块**: mxm_shm,under_api

**描述**: ShmCreate IPC handler accepts name parameter from untrusted IPC source without length/format validation. While under_api has UBS_MEM_MAX_NAME_LENGTH (48) limit, the IPC handler does not enforce this constraint before passing the name to UbseMemAdapter::ShmCreate.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:118-230`)

```c
createParam.name = request->name_; auto hr = mxm::UbseMemAdapter::ShmCreate(createParam);
```

**达成路径**

IPC Request(name_) -> ShmCreate() -> createParam.name -> under_api::UbseMemAdapter::ShmCreate()

**验证说明**: ShmCreate IPC handler accepts name parameter without length validation (line 203). UBSE API has UBS_MEM_MAX_NAME_LENGTH=48 but IPC handler does not enforce this before passing.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VUL-UNDER-API-004] Improper Input Validation - ShmCreate

**严重性**: High | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/under_api/ubse/ubse_mem_adapter.cpp:1075-1128` @ `ShmCreate`
**模块**: under_api
**跨模块**: mxm_shm,under_api

**描述**: ShmCreate receives param.name/size from mxm_shm IPC without proper validation before passing to UBSE API.

**漏洞代码** (`src/under_api/ubse/ubse_mem_adapter.cpp:1075-1128`)

```c
pUbseMemShmCreate(param.name.c_str(), param.size, ...)
```

**达成路径**

[IN] mxm_shm::ShmCreate -> ShmCreate -> pUbseMemShmCreate

**验证说明**: ShmCreate receives param.name/size from IPC without validation before passing to UBSE API. Name length and size upper bound not checked in under_api layer.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-COM-003] missing_input_validation - MxmComEngine::CreateChannel

**严重性**: High | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/communication/adapter/mxm_com_engine.cpp:305-328` @ `MxmComEngine::CreateChannel`
**模块**: communication

**描述**: CreateChannel uses connection parameters (ip, remoteNodeId) without validation. For UDS protocol, info.GetIp() is used as UDS path without path traversal checks. For TCP, info.GetRemoteNodeId() is used in connection string without format validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/communication/adapter/mxm_com_engine.cpp:305-328`)

```c
hcomNetService->Connect(uds:// + info.GetIp(), channelPtr, options);
```

**达成路径**

MxmComChannelConnectInfo.ip -> UDS path construction -> hcomNetService->Connect

**验证说明**: CreateChannel uses info.GetIp() as UDS path without path traversal check (line 325). For UDS protocol, IP field is used as socket path.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PROC-001] insecure_temporary_file - CheckIsRunning

**严重性**: High | **CWE**: CWE-377 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `src/process/daemon/main.cpp:19-21` @ `CheckIsRunning`
**模块**: process

**描述**: Lock file '/tmp/matrix_mem_daemon.lock' created with predictable path in shared directory. An attacker could pre-create this file as a symlink pointing to a sensitive file (e.g., /etc/passwd), causing the daemon to overwrite it or fail to start. While permissions are set to 0600, the TOCTOU race between file existence check and creation is not mitigated.

**漏洞代码** (`src/process/daemon/main.cpp:19-21`)

```c
std::string filePath = "/tmp/matrix_mem_daemon";
std::string fileName = filePath + ".lock";
int fd = open(fileName.c_str(), O_WRONLY | O_CREAT, 0600);
```

**达成路径**

/tmp/matrix_mem_daemon.lock [SOURCE: predictable path]
main.cpp:21 open(O_CREAT, 0600) [SINK: file creation without O_EXCL]

**验证说明**: Lock file /tmp/matrix_mem_daemon.lock created with O_CREAT but without O_EXCL (line 21). Symlink attack possible. Permissions 0600 set but TOCTOU race not mitigated.

**评分明细**: base: 30 | reachability: 5 | controllability: 20 | mitigations: -5 | context: 5 | cross_file: 0

---

## 4. Medium 漏洞 (18)

### [VULN-DF-MXM-SHM-003] Missing Input Validation - Size Parameter in ShmMap - ShmMap

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:584-659` @ `ShmMap`
**模块**: mxm_shm
**跨模块**: mxm_shm,under_api

**描述**: ShmMap IPC handler accepts size parameter without validation before passing to ShmMmapInner and UbseMemAdapter::ShmAttach.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:584-659`)

```c
importParam.length = request->size_; ret = ShmMmapInner(importParam, result);
```

**达成路径**

IPC Request(size_) -> ShmMap() -> importParam.length -> ShmMmapInner() -> under_api::UbseMemAdapter::ShmAttach()

**验证说明**: ShmMap IPC handler accepts size parameter without validation before passing to ShmMmapInner.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-MXM-SHM-005] Missing Input Validation - RPC Lock Name Parameter - HandleMemLock

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/rpc_handler.cpp:73-96` @ `HandleMemLock`
**模块**: mxm_shm
**跨模块**: mxm_shm,dlock_utils

**描述**: HandleMemLock RPC handler accepts memName without validation before passing to dlock_utils::UbsmLock::Lock().

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/rpc_handler.cpp:73-96`)

```c
response->dLockCode_ = dlock_utils::UbsmLock::Instance().Lock(request->memName_, request->isExclusive_, udsInfo);
```

**达成路径**

RPC Request(memName_) -> HandleMemLock() -> dlock_utils::UbsmLock::Lock()

**验证说明**: HandleMemLock RPC handler accepts memName without validation (line 93). Cross-module to dlock_utils.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-COM-006] missing_input_validation - MxmServerMsgHandle::ShmMap

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:584-659` @ `MxmServerMsgHandle::ShmMap`
**模块**: communication
**跨模块**: communication,mxm_shm

**描述**: IPC handler ShmMap uses request->size_ and request->prot_ from IPC message without validation. size_ is used as importParam.length and prot_ as importParam.prot, both from IPC client without bounds checking.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:584-659`)

```c
importParam.length = request->size_; importParam.prot = request->prot_;
```

**达成路径**

IPC message -> ShmMapRequest.size_/prot_ -> importParam -> ShmMmapInner -> UbseMemAdapter::ShmAttach

**验证说明**: IPC handler ShmMap uses request->size_ and request->prot_ without validation. Both from IPC client.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-COM-007] missing_input_validation - MxmServerMsgHandle::HandleMemLock

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/rpc_handler.cpp:73-96` @ `MxmServerMsgHandle::HandleMemLock`
**模块**: communication
**跨模块**: communication,mxm_lease

**描述**: RPC handler HandleMemLock uses request->memName_ and pid/uid/gid from RPC message without validation. memName_ from RPC client is passed to UbsmLock::Instance().Lock without sanitization, potentially allowing lock manipulation on arbitrary resources.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/rpc_handler.cpp:73-96`)

```c
dlock_utils::UbsmLock::Instance().Lock(request->memName_, request->isExclusive_, udsInfo);
```

**达成路径**

RPC message -> LockRequest.memName_/pid_/uid_/gid_ -> UbsmLock::Instance().Lock

**验证说明**: RPC handler HandleMemLock uses request->memName_ from RPC without validation (line 93).

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VUL-DLOCK-001] Improper Input Validation - GetLock

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/dlock_utils/ubsm_lock.cpp:510-511` @ `GetLock`
**模块**: dlock_utils
**跨模块**: mxm_shm,dlock_utils

**描述**: Lock name (memName) passed without length validation from RPC/IPC handlers. The name parameter flows directly to dlock library without bounds checking. Excessive length names could cause buffer overflow or memory exhaustion in downstream dlock library. No maximum length constraint enforced on memName_ string.

**漏洞代码** (`src/dlock_utils/ubsm_lock.cpp:510-511`)

```c
desc.p_desc = const_cast<char *>(name.c_str());
desc.len = name.size();
```

**达成路径**

[IN] mxm_shm::HandleMemLock/ShmWriteLock/ShmReadLock (memName) -> UbsmLock::Lock(ubsm_lock.cpp:264) -> GetLock(ubsm_lock.cpp:490) -> DLockClientGetLockFunc [SINK - no length bounds]

**验证说明**: Lock name (memName) passed without length validation to dlock library (lines 510-511). desc.len = name.size() without bounds check.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VUL-UNDER-API-007] Improper Input Validation - ShmAttach

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/under_api/ubse/ubse_mem_adapter.cpp:1422-1441` @ `ShmAttach`
**模块**: under_api
**跨模块**: mxm_shm,under_api

**描述**: ShmAttach receives name from mxm_shm IPC and passes directly to UBSE API without validation.

**漏洞代码** (`src/under_api/ubse/ubse_mem_adapter.cpp:1422-1441`)

```c
pUbseMemShmAttach(name.c_str(), ...)
```

**达成路径**

[IN] mxm_shm::ShmAttach -> ShmAttach -> pUbseMemShmAttach

**验证说明**: ShmAttach receives name from IPC and passes directly to UBSE API. No length validation observed.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MXM-SHM-004] Missing Input Validation - Name Parameter in ShmMap - ShmMap

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:584-659` @ `ShmMap`
**模块**: mxm_shm
**跨模块**: mxm_shm,under_api

**描述**: ShmMap IPC handler accepts name parameter without length validation before passing to ShmMmapInner.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:584-659`)

```c
importParam.name = request->name_; ret = ShmMmapInner(importParam, result);
```

**达成路径**

IPC Request(name_) -> ShmMap() -> importParam.name -> ShmMmapInner() -> under_api::UbseMemAdapter::ShmAttach()

**验证说明**: ShmMap IPC handler accepts name parameter without length validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MXM-SHM-006] Missing Input Validation - IPC Lock Name Parameter - ShmWriteLock

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:1044-1072` @ `ShmWriteLock`
**模块**: mxm_shm
**跨模块**: mxm_shm,dlock_utils

**描述**: ShmWriteLock IPC handler accepts name without validation before passing to dlock_utils::UbsmLock::Lock().

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:1044-1072`)

```c
auto ret = ock::dlock_utils::UbsmLock::Instance().Lock(request->name_, true, info);
```

**达成路径**

IPC Request(name_) -> ShmWriteLock() -> dlock_utils::UbsmLock::Lock()

**验证说明**: ShmWriteLock IPC handler accepts name without validation before passing to UbsmLock::Lock.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-COM-002] missing_input_validation - SplitPayload

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/communication/adapter/mxm_com_def.cpp:344-355` @ `SplitPayload`
**模块**: communication

**描述**: SplitPayload does not validate nodeId string length or content from network payload. Payload from ch->GetPeerConnectPayload() is split by delimiter but payloadPair[0] (nodeId) is used directly without sanitization, potentially allowing injection of malformed node identifiers.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/communication/adapter/mxm_com_def.cpp:344-355`)

```c
return std::make_pair(payloadPair[0], StringToChannelType(payloadPair[1]));
```

**达成路径**

Network payload string -> SplitPayload -> payloadPair[0] -> NewChannel as remoteNodeId -> channel info storage

**验证说明**: SplitPayload does not validate nodeId string (line 354). payloadPair[0] used as nodeId without sanitization.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-COM-004] buffer_overread - MxmComEngine::ReceivedRequest

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/communication/adapter/mxm_com_engine.cpp:791` @ `MxmComEngine::ReceivedRequest`
**模块**: communication

**描述**: CRC calculation uses attacker-controlled bodyLen value. msg->GetMessageBodyLen() from message header is passed to CrcUtil::SoftCrc32 without verifying it matches actual data length. If bodyLen is larger than actual data, this causes buffer overread.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/communication/adapter/mxm_com_engine.cpp:791`)

```c
auto crcNew = CrcUtil::SoftCrc32(msg->GetMessageBody(), msg->GetMessageBodyLen(), SHIFT_1);
```

**达成路径**

Network message -> msg.GetMessageBody() + msg.GetMessageBodyLen() -> CrcUtil::SoftCrc32

**验证说明**: CRC calculation uses msg->GetMessageBodyLen() without verifying actual data length (line 791). If bodyLen > actual data, buffer overread occurs.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VUL-UNDER-API-005] Improper Input Validation - LeaseMalloc

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/under_api/ubse/ubse_mem_adapter.cpp:410-508` @ `LeaseMalloc`
**模块**: under_api
**跨模块**: mxm_lease,under_api

**描述**: LeaseMalloc receives name/size/regionName from mxm_lease IPC without bounds validation before UBSE API calls.

**漏洞代码** (`src/under_api/ubse/ubse_mem_adapter.cpp:410-508`)

```c
pUbseMemNumaCreateWithCandidate(param.name.c_str(), param.size, ...)
```

**达成路径**

[IN] mxm_lease::AppMallocMemory -> LeaseMalloc -> UBSE API

**验证说明**: LeaseMalloc receives name/size/regionName from IPC. slotCnt comes from GetRegionInfo (internal), not direct external input. Name and size passed to UBSE API without bounds check.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-MXM-SHM-007] Missing Input Validation - ShmDelete Name Parameter - ShmDelete

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:308-378` @ `ShmDelete`
**模块**: mxm_shm
**跨模块**: mxm_shm,under_api

**描述**: ShmDelete IPC handler name is not validated for length before GetMemoryUsersCountByName and UbseMemAdapter::ShmDelete.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:308-378`)

```c
auto ret = SHMManager::GetInstance().GetMemoryUsersCountByName(request->name_, usrNum); auto hr = mxm::UbseMemAdapter::ShmDelete(request->name_, appContext);
```

**达成路径**

IPC Request(name_) -> ShmDelete() -> SHMManager -> UbseMemAdapter::ShmDelete()

**验证说明**: ShmDelete IPC handler name is checked for busy status before deletion, but no length validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 5 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VUL-UNDER-API-008] Improper Input Validation - ShmDelete

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/under_api/ubse/ubse_mem_adapter.cpp:1273-1287` @ `ShmDelete`
**模块**: under_api
**跨模块**: mxm_shm,under_api

**描述**: ShmDelete receives name from mxm_shm IPC and passes directly to pUbseMemShmDelete without validation. Could potentially delete unintended shared memory if name contains path traversal or special characters.

**漏洞代码** (`src/under_api/ubse/ubse_mem_adapter.cpp:1273-1287`)

```c
ret = pUbseMemShmDelete(name.c_str());
```

**达成路径**

[IN] mxm_shm::ShmDelete -> name -> UbseMemAdapter::ShmDelete -> pUbseMemShmDelete

**验证说明**: ShmDelete receives name from IPC and passes to pUbseMemShmDelete. Could delete unintended shared memory. Limited impact as name validation exists upstream.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-003] resource_exhaustion - Decrypt

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/security/cryptor/ubs_cryptor_handler.cpp:117-122` @ `Decrypt`
**模块**: security

**描述**: decryptLength由外部库decryptLibHandlePtr返回，未设置上限检查直接用于内存分配。若库返回异常大值(如恶意库或内存损坏)，可导致内存耗尽。

**漏洞代码** (`src/security/cryptor/ubs_cryptor_handler.cpp:117-122`)

```c
auto decryptRes = decryptLibHandlePtr(encryptedText.c_str(), oldLength, &decryptLength);
...
auto buffer = new (std::nothrow) char[decryptLength + 1];
```

**达成路径**

encryptedText(外部输入) → decryptLibHandlePtr(外部库) → decryptLength输出 → new char[decryptLength+1]分配

**验证说明**: decryptLength from external decrypt library used for memory allocation without upper bound (line 122). Malicious library could cause memory exhaustion.

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MXM-SHM-008] Missing Input Validation - RegionDesc Array - ShmCreate

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:154-201` @ `ShmCreate`
**模块**: mxm_shm

**描述**: ShmCreate processes regionDesc array without validating individual array elements bounds.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-mem/src/mxm_shm/ipc_handler.cpp:154-201`)

```c
for (int i = 0; i < regionInfo.num; i++) { createParam.privider.slot_ids[count] = nodeId; }
```

**达成路径**

IPC Request(regionDesc_) -> ShmCreate() -> regionInfo.num loop -> createParam.privider.slot_ids

**验证说明**: ShmCreate processes regionDesc array. MEM_TOPOLOGY_MAX_HOSTS check exists (line 139), but individual nodeId validation via StrToUint exists.

**评分明细**: base: 30 | reachability: 30 | controllability: 5 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VUL-UNDER-API-002] Dynamic Library Hijacking - Initialize

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/under_api/ubse/ubse_mem_adapter.cpp:74-94` @ `Initialize`
**模块**: under_api

**描述**: dlopen of /usr/lib64/libubse-client.so.1 without integrity verification (no signature check, no hash verification). An attacker with filesystem access could replace/mount over this path to inject malicious code.

**漏洞代码** (`src/under_api/ubse/ubse_mem_adapter.cpp:74-94`)

```c
auto soPath = "/usr/lib64/libubse-client.so.1"; auto ret = DlopenLibUbse(soPath);
```

**达成路径**

Initialize -> DlopenLibUbse -> SystemAdapter::DlOpen -> dlopen

**验证说明**: dlopen of hardcoded path /usr/lib64/libubse-client.so.1 without integrity verification. Attack requires root filesystem access to replace library. Trust boundary: trusted_admin.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: 5 | cross_file: 0

---

### [VUL-UNDER-API-003] Dynamic Library Hijacking - InitOpensslDl

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/under_api/openssl/openssl_dl.cpp:232-242` @ `InitOpensslDl`
**模块**: under_api

**描述**: OpenSSL libraries loaded via dlopen without integrity verification. Attackers could replace these libraries to intercept certificate verification.

**漏洞代码** (`src/under_api/openssl/openssl_dl.cpp:232-242`)

```c
dlopen("/usr/lib64/libcrypto.so.3", RTLD_NOW); dlopen("/usr/lib64/libssl.so.3", RTLD_NOW);
```

**达成路径**

InitOpensslDl -> dlopen

**验证说明**: OpenSSL libraries loaded via dlopen with hardcoded paths without integrity verification. Attack requires root filesystem access.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: 5 | cross_file: 0

---

### [VULN-SEC-002] toctou - LoadDecryptFunction

**严重性**: Medium | **CWE**: CWE-367 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/security/cryptor/ubs_cryptor_handler.cpp:237-240` @ `LoadDecryptFunction`
**模块**: security

**描述**: validate_real_so检查(软链接验证)与dlopen之间存在TOCTOU窗口。攻击者可在验证通过后、dlopen执行前将普通文件替换为软链接，绕过安全检查加载恶意库。

**漏洞代码** (`src/security/cryptor/ubs_cryptor_handler.cpp:237-240`)

```c
if (!validate_real_so(path)) { return -1; }
auto decryLibHandler = SystemAdapter::DlOpen(path, RTLD_NOW);
```

**达成路径**

is_symlink检查(T1) → [竞态窗口] → dlopen(T2)，攻击者可在窗口内替换文件

**验证说明**: TOCTOU window between validate_real_so and DlOpen (lines 237-240). Attacker with root access could replace file in race window. Limited by root requirement.

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: -10 | context: 5 | cross_file: 0

---

## 5. Low 漏洞 (1)

### [VULN-SEC-PROC-002] insecure_file_permission - StartServices

**严重性**: Low | **CWE**: CWE-269 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/process/daemon/ock_daemon.cpp:584-589` @ `StartServices`
**模块**: process

**描述**: PID file created without explicit permission control. std::ofstream creates files with default permissions (typically 0644), potentially exposing the daemon's PID to other users. While the directory path is validated, the file permissions are not explicitly restricted to owner-only.

**漏洞代码** (`src/process/daemon/ock_daemon.cpp:584-589`)

```c
std::string pidFilePath = mHomePath;
pidFilePath += "/work/pids/ockd.pid";
std::ofstream fout(pidFilePath.c_str());
fout << getpid() << std::endl;
```

**达成路径**

mHomePath [validated via realpath]
ock_daemon.cpp:586 ofstream(fout) [SINK: default permissions]

**验证说明**: PID file created with std::ofstream using default permissions (typically 0644). No explicit chmod to restrict to owner-only.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: 5 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| communication | 0 | 1 | 4 | 0 | 5 |
| dlock_utils | 0 | 0 | 1 | 0 | 1 |
| mxm_shm | 0 | 2 | 6 | 0 | 8 |
| process | 0 | 1 | 0 | 1 | 2 |
| security | 0 | 0 | 2 | 0 | 2 |
| under_api | 0 | 1 | 5 | 0 | 6 |
| **合计** | **0** | **5** | **18** | **1** | **24** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 14 | 58.3% |
| CWE-426 | 2 | 8.3% |
| CWE-190 | 2 | 8.3% |
| CWE-400 | 1 | 4.2% |
| CWE-377 | 1 | 4.2% |
| CWE-367 | 1 | 4.2% |
| CWE-269 | 1 | 4.2% |
| CWE-129 | 1 | 4.2% |
| CWE-125 | 1 | 4.2% |
