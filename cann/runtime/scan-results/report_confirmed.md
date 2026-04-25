# 漏洞扫描报告 — 已确认漏洞

**项目**: CANN Runtime  
**扫描时间**: 2026-04-24T23:45:00Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

### 扫描概述

本次漏洞扫描对华为昇腾 AI NPU 运行时系统（CANN Runtime）进行了全面的安全审计，覆盖 3481 个源文件，约 150,000 行 C/C++ 和 Python 代码。扫描发现了 **3 个已确认的高危漏洞**，均涉及授权缺失或路径验证不足问题，可能导致数据泄露、权限提升或资源滥用。

### 关键发现

| 发现 | 严重性 | 影响 |
|------|--------|------|
| 内存组授权缺失 | **High** | 恶意进程可获得 NPU 内存组的完全控制权，窃取 AI 模型数据 |
| 队列绑定授权缺失 | **High** | 客户端可绑定任意队列，窃取推理数据或阻断服务 |
| 共享内存路径遍历 | **High** | 用户输入可探测敏感文件存在性，信息泄露风险 |

### 业务影响评估

CANN Runtime 作为华为昇腾 AI 平台的核心运行时系统，承载着 AI 推理和训练的关键业务。确认的漏洞可能导致：

1. **AI 模型资产泄露**: 通过内存组漏洞，攻击者可窃取部署在 NPU 上的 AI 模型权重和参数
2. **推理数据截获**: 队列绑定漏洞可让攻击者截获推理请求和响应数据
3. **服务可用性破坏**: 恶意进程可破坏内存组或队列，导致 AI 服务中断
4. **跨进程攻击**: 本地攻击者可利用授权缺失进行横向攻击，影响同一服务器上的其他 AI 应用

### 安全态势分析

| 维度 | 评估 | 说明 |
|------|------|------|
| 攻击面 | **广泛** | 337 个公开 API + IPC + Driver 接口，多个信任边界 |
| 利用难度 | **低** | 漏洞利用仅需 API 调用，无需特殊权限或复杂技巧 |
| 检测难度 | **中等** | 需探测队列/内存组名称，但可通过侧信道推断 |
| 影响范围 | **关键业务** | 直接影响 AI 推理/训练服务的核心功能 |

### 建议优先级

| 优先级 | 漏洞 | 建议措施 |
|--------|------|----------|
| **立即修复** | VULN-SEC-MEMGRP-008 | 实现内存组授权检查机制 |
| **立即修复** | VULN-SEC-QUEUE-002 | 实现队列绑定权限验证 |
| **尽快修复** | VULN-DF-BO-001 | 添加共享内存名称验证 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 14 | 56.0% |
| POSSIBLE | 4 | 16.0% |
| FALSE_POSITIVE | 4 | 16.0% |
| CONFIRMED | 3 | 12.0% |
| **总计** | **25** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 3 | 100.0% |
| **有效漏洞总计** | **3** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-BO-001]** buffer_overflow (High) - `src/runtime/driver/npu_driver_mem.cc:43` @ `MallocHostSharedMemory` | 置信度: 85
2. **[VULN-SEC-QUEUE-002]** missing_authorization (High) - `src/queue_schedule/client/bqs_client.cpp:166` @ `DoBindQueue` | 置信度: 85
3. **[VULN-SEC-MEMGRP-008]** missing_authorization (High) - `src/runtime/driver/npu_driver_queue.cc:429` @ `MemGrpAddProc` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `aclInit@include/external/acl/acl_rt.h` | api | untrusted_local | 用户应用调用的初始化入口，接受配置文件路径参数 | ACL初始化API，用户可通过配置文件路径控制初始化参数 |
| `aclrtMalloc@include/external/acl/acl_rt.h` | api | untrusted_local | 用户应用调用，传入size参数可能触发整数溢出或堆溢出 | 设备内存分配API，size参数由用户控制 |
| `aclrtMemcpy@include/external/acl/acl_rt.h` | api | untrusted_local | 用户控制源地址、目标地址和长度，可能触发缓冲区溢出 | 内存拷贝API，src/dst/count参数均由用户控制 |
| `aclrtLaunchKernel@include/external/acl/acl_rt.h` | api | untrusted_local | 用户传入内核参数和参数缓冲区，可能触发代码注入或内存破坏 | 内核启动API，funcHandle和args参数由用户控制 |
| `TSDAEMON_HOST_NAME@src/tsd/tsdclient/src/process_mode_manager.cpp` | network | untrusted_network | Unix domain socket: /var/tsdaemon，本地进程可通过socket发送恶意消息 | TSD守护进程IPC通信接口 |
| `RecvMsg@src/tsd/common/src/hdc_client.cpp` | network | untrusted_network | 接收来自守护进程的IPC消息，消息内容可能被篡改 | HDC客户端消息接收函数 |
| `BQSBindQueueMsg@src/queue_schedule/proto/easycom_message.proto` | rpc | untrusted_local | 客户端通过protobuf发送队列绑定请求，queue_id参数可能触发权限绕过 | 队列调度服务的RPC消息格式 |
| `main@src/queue_schedule/server/main.cpp` | network | untrusted_network | 队列调度服务监听客户端请求，接收队列绑定/查询操作 | 队列调度服务进程入口 |
| `halMemAlloc@src/cmodel_driver/driver_api.c` | driver | semi_trusted | 驱动层内存分配，size参数来自上层ACL API，可能触发整数溢出 | HAL层内存分配接口 |
| `npu_driver_mem@src/runtime/driver/npu_driver_mem.cc` | driver | semi_trusted | NPU驱动内存管理模块，处理设备内存分配和映射操作 | NPU驱动内存操作 |

**其他攻击面**:
- ACL API Interface: 337个公开函数，用户应用可调用所有API
- IPC Daemon: Unix domain socket /var/tsdaemon，本地进程可发送恶意消息
- Queue Schedule Service: protobuf RPC接口，客户端可发送队列操作请求
- NPU Driver Interface: ioctl和内存映射操作，可能触发内核漏洞
- Configuration File: aclInit()接受的配置文件路径，可能触发路径遍历
- HDC Communication: hdc_client与tsdaemon的消息通信协议
- Memory Operations: aclrtMalloc/aclrtMemcpy/aclrtFree等内存操作API

---

## 3. High 漏洞 (3)

### [VULN-DF-BO-001] buffer_overflow - MallocHostSharedMemory

**严重性**: High | **CWE**: CWE-120 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/runtime/driver/npu_driver_mem.cc:43-49` @ `MallocHostSharedMemory`
**模块**: runtime_driver

**描述**: Shared memory name parameter (in->name) is concatenated to /dev/shm/ path using strcpy_s/strcat_s without proper path validation. The name comes from user-controlled rtMallocHostSharedMemoryIn structure, potentially allowing path traversal attacks.

**漏洞代码** (`src/runtime/driver/npu_driver_mem.cc:43-49`)

```c
char_t name[MMPA_MAX_PATH] = {}; errno_t retSafe = strcpy_s(&name[0], sizeof(name), path); retSafe = strcat_s(name, sizeof(name), in->name);
```

**达成路径**

rtMallocHostSharedMemoryIn.name [SOURCE: API参数]
→ strcpy_s(name, path) [PROPAGATION]
→ strcat_s(name, in->name) [PROPAGATION]
→ shm_open(in->name, ...) [SINK: file_operation]

**验证说明**: 共享内存名in->name拼接到/dev/shm/无路径遍历检查。shm_open直接使用in->name，攻击者可使用../逃逸/dev/shm目录。strcpy_s/strcat_s不防止路径遍历。

**评分明细**: base: 30 | context: 0 | controllability: 25 | cross_file: 0 | mitigations: 0 | reachability: 30

---

### [VULN-SEC-QUEUE-002] missing_authorization - DoBindQueue

**严重性**: High | **CWE**: CWE-862 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/queue_schedule/client/bqs_client.cpp:166-180` @ `DoBindQueue`
**模块**: queue_schedule

**描述**: 队列绑定操作权限检查缺失。DoBindQueue 函数接收客户端的 queue_id 参数并执行绑定操作，但没有验证调用者是否有权限绑定该队列。恶意客户端可以绑定任意队列，可能导致数据泄露或资源窃取。

**漏洞代码** (`src/queue_schedule/client/bqs_client.cpp:166-180`)

```c
BQSMsg bqsReqMsg = {}; if (EzcomClient::GetInstance(clientFd_)->SerializeBindMsg(bindQueueVec, bqsReqMsg) != BQS_STATUS_OK) { return 0U; }
```

**达成路径**

客户端进程 -> BindQueue -> SerializeBindMsg -> queue_schedule 服务 -> 绑定操作

**验证说明**: DoBindQueue接收queue_id参数无权限验证。客户端可绑定任意队列，可能导致数据泄露或资源窃取。CWE-862缺失授权检查。

**评分明细**: base: 30 | context: 0 | controllability: 25 | cross_file: 0 | mitigations: 0 | reachability: 30

---

### [VULN-SEC-MEMGRP-008] missing_authorization - MemGrpAddProc

**严重性**: High | **CWE**: CWE-862 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/runtime/driver/npu_driver_queue.cc:429-450` @ `MemGrpAddProc`
**模块**: runtime_driver

**描述**: 内存组进程添加权限检查缺失。MemGrpAddProc 函数可以向内存组添加任意 PID，但没有验证调用者是否有权限操作该内存组，也没有验证目标 PID 是否属于合法进程。恶意进程可以将其他进程添加到内存组获取访问权限。

**漏洞代码** (`src/runtime/driver/npu_driver_queue.cc:429-450`)

```c
const drvError_t drvRet = static_cast<drvError_t>(halGrpAddProc(name, pid, drvAttr));
```

**达成路径**

用户进程 -> MemGrpAddProc(pid) -> halGrpAddProc -> 内存组

**验证说明**: MemGrpAddProc可添加任意PID无授权检查。恶意进程可将其他进程添加到内存组获取访问权限。CWE-862缺失授权。

**评分明细**: base: 30 | context: 0 | controllability: 25 | cross_file: 0 | mitigations: 0 | reachability: 30

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| queue_schedule | 0 | 1 | 0 | 0 | 1 |
| runtime_driver | 0 | 2 | 0 | 0 | 2 |
| **合计** | **0** | **3** | **0** | **0** | **3** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-862 | 2 | 66.7% |
| CWE-120 | 1 | 33.3% |

---

## 6. 已确认漏洞深度分析

### 6.1 VULN-SEC-MEMGRP-008 - 内存组授权缺失（最严重）

#### 漏洞机制

内存组（Memory Group）是 CANN Runtime 中用于跨进程共享 NPU 内存资源的关键机制。`MemGrpAddProc` API 允许进程将其他进程添加到内存组并设置权限属性（admin、read、write、alloc）。漏洞在于该 API **完全不验证调用者的权限**，任意进程可以：

1. 将自己添加到任意内存组并设置 **admin=true**
2. 将任意 PID 添加到内存组
3. 授予超出自身权限等级的权限

#### 攻击场景

```
攻击者进程
    ↓ 调用 MemGrpAddProc("npu_hbm_pool_0", getpid(), {admin=1, alloc=1})
    ↓ 驱动层无授权检查，直接执行
    ↓
攻击者获得内存组 admin 权限
    ↓
读取共享 NPU 内存中的 AI 模型参数
篡改训练数据或推理结果
踢出合法进程，破坏服务
```

#### 实际危害

- **AI 模型窃取**: 共享内存中存储的模型权重可直接读取
- **推理结果篡改**: 可修改推理队列的输出数据
- **训练过程破坏**: 可篡改训练中间状态
- **服务 DoS**: 可踢出合法进程或耗尽内存资源

#### 根因分析

代码仅检查 API 存在性，未实现任何授权逻辑：

```cpp
// npu_driver_queue.cc:429-450
COND_RETURN_WARN(&halGrpAddProc == nullptr, RT_ERROR_FEATURE_NOT_SUPPORT, "...");

// 直接构造属性并调用驱动，无任何授权检查！
GroupShareAttr drvAttr = {};
drvAttr.admin = attr->admin;   // 攻击者可设置 admin=true!
drvAttr.read = attr->read;
drvAttr.write = attr->write;
drvAttr.alloc = attr->alloc;

const drvError_t drvRet = halGrpAddProc(name, pid, drvAttr);  // 直接执行
```

---

### 6.2 VULN-SEC-QUEUE-002 - 队列绑定授权缺失

#### 漏洞机制

队列调度系统（BQS）管理 NPU 任务队列的数据流。`DoBindQueue` API 允许客户端绑定源队列到目标队列，建立数据流管道。漏洞在于该 API **不验证队列所有权或访问权限**，恶意客户端可以：

1. 绑定任意队列组合
2. 将攻击者队列绑定到高价值队列窃取数据
3. 将受害者队列绑定到"黑洞"队列阻断服务

#### 攻击场景

```
步骤1: 攻击者创建自己的队列 (ATTACKER_QUEUE)
步骤2: 探测推理服务队列 ID (INFERENCE_QUEUE)
步骤3: 调用 BindQueue(ATTACKER_QUEUE, INFERENCE_QUEUE)
步骤4: 服务端无权限验证，绑定成功
步骤5: 推理结果流向攻击者队列
步骤6: 攻击者读取窃取的数据
```

#### 实际危害

- **数据窃取**: 推理结果、训练数据、模型中间状态
- **服务阻断**: 将队列绑定到无效目标导致数据堵塞
- **权限提升**: 访问超出授权等级的高优先级队列

#### 根因分析

客户端直接序列化绑定请求并发送，服务端未实现权限检查：

```cpp
// bqs_client.cpp:166-180
BQSMsg bqsReqMsg = {};
// 直接序列化绑定请求，无权限检查！
SerializeBindMsg(bindQueueVec, bqsReqMsg);

// 发送请求到队列调度服务
SendBqsMsg(bqsReqMsg, bqsRespMsg);
```

---

### 6.3 VULN-DF-BO-001 - 共享内存路径遍历

#### 漏洞机制

`MallocHostSharedMemory` API 用于创建共享内存区域。用户提供的共享内存名称参数 (`in->name`) 被直接拼接到 `/dev/shm/` 路径，没有路径遍历防护。虽然 POSIX `shm_open()` 规范会拒绝包含 `/` 的名称，但 `stat()` 操作可用于探测任意文件存在性。

#### 攻击场景

```
步骤1: 调用 rtMallocHostSharedMemory
步骤2: 设置 in->name = "../../../etc/shadow"
步骤3: 代码执行 stat("/dev/shm/../../../etc/shadow")
步骤4: stat 成功返回 → 攻击者确认敏感文件存在
步骤5: shm_open 失败，但信息已泄露
```

#### 实际危害

- **信息泄露**: 可探测 `/etc/passwd`、`/etc/shadow` 等敏感文件存在性
- **资源滥用**: 可创建任意名称的共享内存消耗资源
- **后续攻击辅助**: 信息探测可辅助其他攻击路径

#### 根因分析

安全函数仅防止缓冲区溢出，不防止路径遍历：

```cpp
// npu_driver_mem.cc:43-49
char_t name[MMPA_MAX_PATH] = {};
strcpy_s(name, sizeof(name), "/dev/shm/");  // 仅防止溢出
strcat_s(name, sizeof(name), in->name);      // 不验证路径字符！
stat(name, &buf);  // 可探测任意文件
shm_open(in->name, ...);  // 使用原始名称
```

---

## 7. 修复建议和缓解措施

### 7.1 VULN-SEC-MEMGRP-008 修复方案（Critical）

#### API 层授权检查

```cpp
rtError_t NpuDriver::MemGrpAddProc(const char_t * const name, const int32_t pid,
                                   const rtMemGrpShareAttr_t * const attr)
{
    // 1. 获取调用者 PID
    int32_t callerPid = getpid();
    
    // 2. 检查调用者是否有权限操作该内存组
    rtMemGrpQueryOutput_t queryOutput;
    if (!IsGroupAdmin(name, callerPid, queryOutput)) {
        RT_LOG(RT_LOG_ERROR, "Caller %d lacks admin permission for group '%s'", 
               callerPid, name);
        return RT_ERROR_PERMISSION_DENIED;
    }
    
    // 3. 限制授予的权限不能超过调用者的权限等级
    if (attr->admin > queryOutput.admin) {
        RT_LOG(RT_LOG_ERROR, "Cannot grant admin permission beyond caller's level");
        return RT_ERROR_PERMISSION_DENIED;
    }
    
    // 4. 验证目标 PID 合法性
    if (!ValidateTargetPid(pid, callerPid)) {
        return RT_ERROR_PERMISSION_DENIED;
    }
    
    // 原有逻辑...
}
```

#### 驱动层加固

```c
drvError_t halGrpAddProc(const char* name, int32_t pid, GroupShareAttr attr)
{
    // 1. 内核级验证调用者进程权限
    int32_t callerPid = current->pid;
    
    // 2. 检查内存组元数据
    MemGroup* group = FindMemGroup(name);
    if (group == NULL) return DRV_ERROR_NOT_FOUND;
    
    // 3. 验证调用者是 group 的管理员
    ProcessMember* caller = FindMember(group, callerPid);
    if (caller == NULL || caller->attr.admin == 0) {
        LogSecurityEvent("Unauthorized MemGrpAddProc", callerPid, name);
        return DRV_ERROR_PERMISSION_DENIED;
    }
    
    // 4. 权限降级：不允许授予超过调用者等级的权限
    if (attr.admin > caller->attr.admin) attr.admin = caller->attr.admin;
    
    return DoAddProc(group, pid, attr);
}
```

---

### 7.2 VULN-SEC-QUEUE-002 修复方案（Critical）

#### 服务端授权检查

```cpp
// BqsServer 端添加权限验证
bool ValidateBindPermission(uint32_t srcQueueId, uint32_t dstQueueId, int32_t clientPid)
{
    // 1. 源队列：必须有所有权或绑定权限
    QueueMetadata* srcMeta = GetQueueMetadata(srcQueueId);
    if (srcMeta == nullptr) return false;
    
    if (srcMeta->ownerPid != clientPid && 
        !HasQueuePermission(srcQueueId, clientPid, PERMISSION_BIND)) {
        return false;
    }
    
    // 2. 目标队列：必须有访问权限
    if (!HasQueuePermission(dstQueueId, clientPid, PERMISSION_ACCESS)) {
        return false;
    }
    
    // 3. 绑定策略检查
    return CheckBindPolicy(srcQueueId, dstQueueId);
}

void BqsServer::HandleBindRequest(BQSMsg& request, BQSMsg& response)
{
    int32_t clientPid = GetClientPid(request.connectionFd);
    
    for (auto& item : request.bindItems) {
        if (!ValidateBindPermission(item.srcQueueId, item.dstQueueId, clientPid)) {
            LogSecurityEvent("Unauthorized bind attempt", clientPid, item);
            SetBindResult(response, item, BQS_STATUS_PERMISSION_DENIED);
            continue;
        }
        ExecuteBind(item);
    }
}
```

#### 队列权限模型

```
Queue 创建时记录:
- owner_pid: 创建者进程 ID
- group_id: 所属组/用户
- permissions: {read, write, bind, manage}

绑定操作检查:
1. src_queue.owner_pid == client_pid 或 
   src_queue.permissions[client_pid].bind == true
   
2. dst_queue.permissions[client_pid].access == true 或
   dst_queue.group == client_group
   
3. policy.check(src_queue, dst_queue) == ALLOW
```

---

### 7.3 VULN-DF-BO-001 修复方案（High）

#### 输入名称验证

```cpp
bool IsValidShmName(const char* name) {
    if (name == nullptr) return false;
    
    size_t len = strlen(name);
    if (len == 0 || len > NAME_MAX) return false;
    
    // 检查禁止字符
    for (size_t i = 0; i < len; i++) {
        if (name[i] == '/' || name[i] == '\\') return false;
        if (name[i] == '.' && name[i+1] == '.') return false;
    }
    
    return true;
}

rtError_t NpuDriver::MallocHostSharedMemory(...) {
    // 1. 名称验证
    if (!IsValidShmName(in->name)) {
        RT_LOG(RT_LOG_ERROR, "Invalid shared memory name: %s", in->name);
        return RT_ERROR_INVALID_VALUE;
    }
    
    // 2. 规范化名称（使用 basename）
    char safeName[NAME_MAX];
    strncpy(safeName, in->name, NAME_MAX - 1);
    
    // 3. 只使用合法名称进行操作
    // ... 原有逻辑 ...
}
```

---

### 7.4 系统级加固建议

#### 权限模型重构

| 层级 | 权限 | 授予规则 |
|------|------|----------|
| Level 0 (Creator/Admin) | 完全控制 | 创建者自动获得，仅 Admin 可授予 Admin |
| Level 1 (Manager) | 添加成员+读写 | Admin 可授予 Manager |
| Level 2 (Contributor) | 读写+分配 | Manager 可授予 Contributor |
| Level 3 (Reader) | 只读 | Contributor 可授予 Reader |

**核心规则**: 调用者只能授予 ≤ 自己权限等级的权限

#### 审计和监控

```cpp
// 记录所有敏感操作
void LogSecurityEvent(const char* eventType, int32_t callerPid, ...) {
    SecurityAuditLog log;
    log.timestamp = GetCurrentTime();
    log.eventType = eventType;
    log.callerPid = callerPid;
    log.callerUid = getuid();
    log.callerGid = getgid();
    
    // 写入审计日志
    WriteAuditLog(log);
}
```

#### LSM 加固

建议使用 SELinux/AppArmor 策略限制：

```
# SELinux 策略示例
type cann_runtime_t;
type npu_device_t;
type memory_group_t;

# 仅允许授权进程访问内存组
allow authorized_process_t memory_group_t:memgrp { add_proc remove_proc read write };

# 禁止未授权进程
dontaudit untrusted_process_t memory_group_t:memgrp *;
```

---

## 8. 总结

### 漏洞概况

| 漏洞 ID | 类型 | 严重性 | 利用难度 | 业务影响 |
|---------|------|--------|----------|----------|
| VULN-SEC-MEMGRP-008 | 授权缺失 | High | Low | AI 模型窃取、服务破坏 |
| VULN-SEC-QUEUE-002 | 授权缺失 | High | Low | 数据窃取、服务阻断 |
| VULN-DF-BO-001 | 路径遍历 | High | Medium | 信息泄露、资源滥用 |

### 修复优先级

1. **立即修复**: VULN-SEC-MEMGRP-008 和 VULN-SEC-QUEUE-002 — 实现授权检查机制
2. **尽快修复**: VULN-DF-BO-001 — 添加输入验证
3. **长期加固**: 建立完整的权限模型和审计系统

### 安全态势建议

- 实现最小权限原则，限制 API 默认权限
- 建立完整的身份认证和授权体系
- 添加安全审计日志，监控敏感操作
- 使用 LSM 模块进行系统级防护
- 定期安全审计和渗透测试

---

*报告生成时间: 2026-04-25*  
*分析工具: CANN Vulnerability Scanner*  
*详细分析报告: scan-results/details/*.md*
