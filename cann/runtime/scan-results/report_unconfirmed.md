# 漏洞扫描报告 — 待确认漏洞

**项目**: CANN Runtime
**扫描时间**: 2026-04-24T23:45:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| High | 7 | 38.9% |
| Medium | 11 | 61.1% |
| **有效漏洞总计** | **18** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-API-001]** buffer_overflow (High) - `src/runtime/core/src/api_impl/api_impl.cc:726` @ `CalcLaunchArgsSize/CreateLaunchArgs` | 置信度: 75
2. **[VULN-DF-API-002]** buffer_overflow (High) - `src/runtime/core/src/api_impl/api_impl.cc:553` @ `KernelLaunchEx` | 置信度: 75
3. **[VULN-DF-API-003]** buffer_overflow (High) - `src/runtime/driver/npu_driver_mem.cc:702` @ `MemSetSync` | 置信度: 75
4. **[VULN-SEC-IPC-001]** missing_authentication (High) - `src/tsd/common/src/hdc_client.cpp:193` @ `CreateHdcSession` | 置信度: 75
5. **[VULN-SEC-DEV-003]** improper_resource_access (High) - `src/runtime/driver/npu_driver.cc:407` @ `DeviceOpen` | 置信度: 75
6. **[VULN-SEC-KERNEL-005]** code_injection (High) - `src/runtime/core/src/api_impl/api_impl.cc:498` @ `KernelLaunch` | 置信度: 75
7. **[VULN-DF-BO-002]** buffer_overflow (High) - `src/runtime/driver/npu_driver_mem.cc:75` @ `MallocHostSharedMemory` | 置信度: 60
8. **[VULN-DF-IPC-001]** path_traversal (Medium) - `src/tsd/tsdclient/src/process_mode_manager.cpp:357` @ `SendAICPUPackageSimple` | 置信度: 65
9. **[VULN-DF-API-004]** buffer_overflow (Medium) - `src/runtime/driver/npu_driver_mem.cc:668` @ `MemPrefetchToDevice` | 置信度: 65
10. **[VULN-SEC-PATH-004]** path_traversal (Medium) - `src/acl/aclrt_c/common/acl_rt.c:24` @ `PathIsLegal` | 置信度: 65

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

## 3. High 漏洞 (7)

### [VULN-DF-API-001] buffer_overflow - CalcLaunchArgsSize/CreateLaunchArgs

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-120 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/runtime/core/src/api_impl/api_impl.cc:726-765` @ `CalcLaunchArgsSize/CreateLaunchArgs`
**模块**: runtime_core

**描述**: Launch arguments size calculation involves user-controlled argsSize and hostInfoTotalSize parameters. The sum could overflow at line 731 (argsSize + hostInfoTotalSize), and the result is used for memory allocation at line 746.

**漏洞代码** (`src/runtime/core/src/api_impl/api_impl.cc:726-765`)

```c
*launchArgsSize = argsSize + hostInfoTotalSize; auto *hdlHostInputInfo = new (std::nothrow) rtHostInputInfo_t[hostInfoNum];
```

**达成路径**

rtLaunchKernel(args, argsSize) [SOURCE: API参数]
→ CalcLaunchArgsSize(argsSize, hostInfoTotalSize) [PROPAGATION]
→ argsSize + hostInfoTotalSize [PROPAGATION: arithmetic]
→ CreateLaunchArgs(argsSize, ...) [SINK: memory_allocation]

**验证说明**: argsSize+hostInfoTotalSize可能在731行溢出。无溢出检查，但argsSize被cast为uint16_t限制。内存分配可能不足。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-API-002] buffer_overflow - KernelLaunchEx

**严重性**: High | **CWE**: CWE-120 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/runtime/core/src/api_impl/api_impl.cc:553-577` @ `KernelLaunchEx`
**模块**: runtime_core

**描述**: Extended kernel launch accepts user-controlled args and argsSize parameters. The args buffer flows to StreamLaunchKernelEx without size validation against actual kernel requirements.

**漏洞代码** (`src/runtime/core/src/api_impl/api_impl.cc:553-577`)

```c
return StreamLaunchKernelEx(args, argsSize, flags, curStm);
```

**达成路径**

aclrtLaunchKernel(args, argsSize) [SOURCE: API参数]
→ KernelLaunchEx(args, argsSize, flags, stm) [PROPAGATION]
→ StreamLaunchKernelEx(args, argsSize, flags, curStm) [SINK: kernel_launch]

**验证说明**: KernelLaunchEx的args/argsSize传递给StreamLaunchKernelEx无大小验证。类似VULN-SEC-KERNEL-005，参数来自API用户。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 30

---

### [VULN-DF-API-003] buffer_overflow - MemSetSync

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-120 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/runtime/driver/npu_driver_mem.cc:702-718` @ `MemSetSync`
**模块**: runtime_driver
**跨模块**: acl → runtime_driver

**描述**: Memory set function accepts user-controlled devPtr, destMax, and cnt parameters. The cnt parameter flows directly to drvMemsetD8 without validation against destMax bounds.

**漏洞代码** (`src/runtime/driver/npu_driver_mem.cc:702-718`)

```c
const drvError_t drvRet = drvMemsetD8(RtPtrToPtr<DVdeviceptr>(devPtr), static_cast<size_t>(destMax), static_cast<UINT8>(val), static_cast<size_t>(cnt));
```

**达成路径**

aclrtMemset(devPtr, destMax, val, count) [SOURCE: ACL API]
→ MemSetSync(devPtr, destMax, val, cnt) [PROPAGATION]
→ drvMemsetD8(devPtr, destMax, val, cnt) [SINK: memory_write]

**验证说明**: drvMemsetD8参数devPtr/destMax/cnt来自API，无边界检查。运行时层不做验证，依赖驱动层。攻击者可控制参数。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-IPC-001] missing_authentication - CreateHdcSession

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-287 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/tsd/common/src/hdc_client.cpp:193-202` @ `CreateHdcSession`
**模块**: tsd_client

**描述**: IPC 客户端身份验证缺失。drvHdcSessionConnect 函数连接设备守护进程时，没有验证客户端进程的身份（PID、UID等）。恶意本地进程可以连接到 Unix domain socket (/var/tsdaemon) 并发送伪造的消息，可能导致权限提升或设备资源滥用。

**漏洞代码** (`src/tsd/common/src/hdc_client.cpp:193-202`)

```c
retVal = drvHdcSessionConnect(0, static_cast<int32_t>(deviceId_), hdcClient_, &session);
```

**达成路径**

用户进程 -> drvHdcSessionConnect -> Unix socket /var/tsdaemon -> tsdaemon 服务

**验证说明**: drvHdcSessionConnect连接守护进程无客户端身份验证（PID/UID）。恶意本地进程可连接Unix socket发送伪造消息。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-DEV-003] improper_resource_access - DeviceOpen

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-732 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/runtime/driver/npu_driver.cc:407-474` @ `DeviceOpen`
**模块**: runtime_driver

**描述**: 设备打开操作权限控制不当。DeviceOpen 函数接受 deviceId 参数但没有验证调用者是否有权限访问该设备。任何可以调用 API 的进程都可以打开任意 NPU 设备，可能导致资源滥用或跨进程攻击。

**漏洞代码** (`src/runtime/driver/npu_driver.cc:407-474`)

```c
drvRet = drvDeviceOpen(RtPtrToPtr<void **>(&devInfo), deviceId);
```

**达成路径**

用户进程 -> DeviceOpen -> drvDeviceOpen -> NPU 设备

**验证说明**: DeviceOpen接受deviceId参数但无权限验证。任意进程可打开任意NPU设备，可能导致资源滥用或跨进程攻击。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-KERNEL-005] code_injection - KernelLaunch

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/runtime/core/src/api_impl/api_impl.cc:498-527` @ `KernelLaunch`
**模块**: runtime_core

**描述**: 内核启动参数验证不足。KernelLaunch 函数的 args 参数来自用户应用，没有验证参数内容是否安全。恶意构造的参数可能导致 NPU 内核执行未授权操作、内存破坏或代码注入。

**漏洞代码** (`src/runtime/core/src/api_impl/api_impl.cc:498-527`)

```c
return curCtx->LaunchKernel(stubFunc, coreDim, argsInfo, curStm, flag, &taskCfg, isLaunchVec);
```

**达成路径**

用户进程 -> KernelLaunch(args) -> LaunchKernel -> NPU 内核执行

**验证说明**: KernelLaunch的args参数来自用户应用无验证。恶意参数可能导致NPU内核执行未授权操作或内存破坏。stubFunc控制执行。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-BO-002] buffer_overflow - MallocHostSharedMemory

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/runtime/driver/npu_driver_mem.cc:75-79` @ `MallocHostSharedMemory`
**模块**: runtime_driver

**描述**: mmap() is called with user-controlled size parameter (in->size) from rtMallocHostSharedMemoryIn structure. While size validation exists at line 65-71, the mmap could still fail if size is too large, and no upper bound check prevents excessive memory mapping.

**漏洞代码** (`src/runtime/driver/npu_driver_mem.cc:75-79`)

```c
out->ptr = mmap(nullptr, in->size, static_cast<int32_t>(PROT_READ) | static_cast<int32_t>(PROT_WRITE), static_cast<int32_t>(MAP_SHARED), out->fd, 0);
```

**达成路径**

rtMallocHostSharedMemoryIn.size [SOURCE: API参数]
→ ftruncate(out->fd, in->size) [PROPAGATION]
→ mmap(nullptr, in->size, ...) [SINK: memory_operation]

**验证说明**: mmap使用用户控制的size参数。存在大小不匹配验证（65-71行）但无上限检查防止过量映射。攻击者可控制大小但受验证限制。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (11)

### [VULN-DF-IPC-001] path_traversal - SendAICPUPackageSimple

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/tsd/tsdclient/src/process_mode_manager.cpp:357-383` @ `SendAICPUPackageSimple`
**模块**: tsd_client

**描述**: File transfer functions drvHdcSendFile and drvHdcSendFileV2 accept user-provided file paths (orgFile, dstFile). While some path validation exists elsewhere, the direct file transfer API could allow unauthorized file access if paths are not properly sanitized.

**漏洞代码** (`src/tsd/tsdclient/src/process_mode_manager.cpp:357-383`)

```c
const auto ret = drvHdcSendFileV2(peerNode, static_cast<int32_t>(logicDeviceId_), orgFile.c_str(), dstFile.c_str(), nullptr);
```

**达成路径**

orgFile/dstFile [SOURCE: 配置参数]
→ drvHdcSendFileV2(peerNode, deviceId, orgFile, dstFile) [SINK: file_transfer]

**验证说明**: drvHdcSendFileV2的orgFile/dstFile来自配置参数，无路径验证。本地攻击者可通过配置文件注入路径遍历。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-API-004] buffer_overflow - MemPrefetchToDevice

**严重性**: Medium（原评估: Critical → 验证后: Medium） | **CWE**: CWE-120 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/runtime/driver/npu_driver_mem.cc:668-687` @ `MemPrefetchToDevice`
**模块**: runtime_driver
**跨模块**: acl → runtime_driver

**描述**: Memory prefetch function accepts user-controlled devPtr and len parameters. The len parameter flows directly to drvMemPrefetchToDevice without bounds validation against device memory limits.

**漏洞代码** (`src/runtime/driver/npu_driver_mem.cc:668-687`)

```c
drvRet = drvMemPrefetchToDevice(RtPtrToPtr<DVdeviceptr>(devPtr), static_cast<size_t>(len), static_cast<DVdevice>(logicDevId));
```

**达成路径**

aclrtMemPrefetchToDevice(devPtr, len, deviceId) [SOURCE: ACL API]
→ MemPrefetchToDevice(devPtr, len, deviceId) [PROPAGATION]
→ drvMemPrefetchToDevice(devPtr, len, logicDevId) [SINK: memory_operation]

**验证说明**: len参数直接传递给drvMemPrefetchToDevice无验证。预取提示而非实际内存操作，风险较低。设备端有内存限制。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PATH-004] path_traversal - PathIsLegal

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/acl/aclrt_c/common/acl_rt.c:24-34` @ `PathIsLegal`
**模块**: acl

**描述**: 配置文件路径验证不足。aclInit 的 configPath 参数虽然有 PathIsLegal 函数检查文件是否存在，但没有进行路径遍历防护（使用 realpath 规范化路径）。攻击者可以使用符号链接或相对路径绕过检查，加载恶意配置文件。

**漏洞代码** (`src/acl/aclrt_c/common/acl_rt.c:24-34`)

```c
mmFileHandle* fd = mmOpenFile(cfg, FILE_READ); if (fd == NULL) { return false; }
```

**达成路径**

用户进程 -> aclInit(configPath) -> PathIsLegal -> mmOpenFile -> 配置文件

**验证说明**: PathIsLegal仅检查文件存在和非空，无realpath规范化或路径遍历防护。aclInit配置路径通常由管理员控制，但本地攻击者可篡改。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-SEC-FILE-007] path_traversal - SendAICPUPackageSimple

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/tsd/tsdclient/src/process_mode_manager.cpp:363-378` @ `SendAICPUPackageSimple`
**模块**: tsd_client

**描述**: 文件传输路径验证缺失。drvHdcSendFile 传输文件到设备时，orgFile 参数来自上层配置，没有验证源文件路径是否在允许的范围内。恶意进程可以发送任意路径的文件到设备，可能导致设备端加载恶意代码。

**漏洞代码** (`src/tsd/tsdclient/src/process_mode_manager.cpp:363-378`)

```c
const auto ret = drvHdcSendFile(peerNode, static_cast<int32_t>(logicDeviceId_), orgFile.c_str(), dstFile.c_str(), nullptr);
```

**达成路径**

配置路径 -> drvHdcSendFile(orgFile) -> HDC 通道 -> 设备端

**验证说明**: drvHdcSendFile的orgFile来自配置无路径验证。类似VULN-DF-IPC-001，本地攻击者可通过配置注入路径。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-SEC-CONFIG-009] path_traversal - LoadConfigFile

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/platform/platform_info.cpp:168-212` @ `LoadConfigFile`
**模块**: platform

**描述**: 平台配置目录遍历风险。LoadConfigFile 使用 opendir/readdir 遍历配置目录，但没有验证目录路径是否规范化。如果 real_path 包含符号链接或 .. 路径，可能加载非预期的配置文件。

**漏洞代码** (`src/platform/platform_info.cpp:168-212`)

```c
dir = opendir(real_path.c_str()); ini_cfg_files.push_back(real_path + "/" + dirp->d_name);
```

**达成路径**

配置路径 -> opendir -> readdir -> LoadIniFile

**验证说明**: opendir/readdir遍历real_path无规范化检查。配置路径可能包含符号链接或..路径，但通常由管理员控制。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-SEC-OMFILE-010] improper_input_validation - LoadOmFileToDevice

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/tsd/tsdclient/src/process_mode_manager.cpp:1143-1181` @ `LoadOmFileToDevice`
**模块**: tsd_client

**描述**: OM 文件加载路径验证不足。LoadOmFileToDevice 函数接收 filePath 和 fileName 参数，虽然有长度检查但没有验证路径是否在可信范围内。攻击者可以加载任意位置的 OM 文件到设备，可能导致设备执行恶意算子。

**漏洞代码** (`src/tsd/tsdclient/src/process_mode_manager.cpp:1143-1181`)

```c
std::string filePathStr(filePath, pathLen); auto ret = SendFileToDevice(filePath, pathLen, fileName, fileNameLen, true);
```

**达成路径**

filePath -> SendFileToDevice -> drvHdcSendFile -> 设备端 OM 文件

**验证说明**: LoadOmFileToDevice的filePath无可信路径验证。OM文件包含算子代码，加载恶意OM可能导致设备执行恶意算子。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-IPC-003] integer_overflow - BindQueue

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/queue_schedule/client/bqs_client.cpp:141-164` @ `BindQueue`
**模块**: queue_schedule

**描述**: Queue binding function accepts vector of BQSBindQueueItem. The pagination logic at line 150-152 uses MAX_PAGED_QUEUE_RELATION (300) for chunking. If the vector size is very large, multiple iterations could cause resource exhaustion.

**漏洞代码** (`src/queue_schedule/client/bqs_client.cpp:141-164`)

```c
if (bindQueueVec.size() > MAX_PAGED_QUEUE_RELATION) { auto tempBindQueEndIter = bindQueueIter + MAX_PAGED_QUEUE_RELATION; if (tempBindQueEndIter > bindQueEndIter) { tempBindQueEndIter = bindQueEndIter; }
```

**达成路径**

BQSBindQueueItem vector [SOURCE: client_input]
→ BindQueue(bindQueueVec) [PROPAGATION]
→ DoBindQueue(bindQueue, bindResult) [SINK: queue_bind]

**验证说明**: bindQueueVec.size()>MAX_PAGED_QUEUE_RELATION导致多次迭代。MAX_PAGED_QUEUE_RELATION=300限制存在。资源消耗问题，非严重漏洞。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: -15 | reachability: 30

---

### [VULN-DF-IO-001] integer_overflow - drvMemAlloc

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/cmodel_driver/driver_mem.c:267-269` @ `drvMemAlloc`
**模块**: cmodel_driver

**描述**: Size alignment calculation ((tSize >> 9) + 1) << 9 could overflow if tSize is near MAX_ALLOC (0x1FFFFFFF00). The result could be smaller than expected, leading to insufficient memory allocation.

**漏洞代码** (`src/cmodel_driver/driver_mem.c:267-269`)

```c
if ((tSize & 0x1ff) != 0) { tSize = ((tSize >> 9) + 1) << 9; }
```

**达成路径**

drvMemAlloc(size) [SOURCE: API参数]
→ tSize = size [PROPAGATION]
→ tSize = ((tSize >> 9) + 1) << 9 [PROPAGATION: arithmetic]
→ drvMemAllocDeviceHBM(dptr, tSize, ...) [SINK: memory_allocation]

**验证说明**: 大小对齐((tSize>>9)+1)<<9可能溢出，但MAX_ALLOC检查（261行）在对齐前执行，限制了size范围。实际溢出风险低。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: -15 | reachability: 20

---

### [VULN-DF-BO-003] buffer_overflow - drvModelMemcpy

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-120 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/cmodel_driver/driver_mem.c:305-344` @ `drvModelMemcpy`
**模块**: cmodel_driver

**描述**: Memory copy function accepts user-controlled dst, src, and size parameters. While destMax < size check exists at line 312, the busDirectWrite/busDirectRead calls use the raw size without additional bounds checking against actual buffer sizes.

**漏洞代码** (`src/cmodel_driver/driver_mem.c:305-344`)

```c
ret = busDirectWrite(address, size, (void *)src, 0); ret = busDirectRead(dst, size, address, 0);
```

**达成路径**

drvModelMemcpy(dst, src, size) [SOURCE: API参数]
→ busDirectWrite(address, size, src, 0) [SINK: memory_write]
→ busDirectRead(dst, size, address, 0) [SINK: memory_read]

**验证说明**: drvModelMemcpy有destMax<size检查（312行）和MAX_ALLOC检查。memcpy_s使用destMax参数提供边界保护。风险缓解。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: -15 | reachability: 20

---

### [VULN-DF-BO-004] buffer_overflow - halMemAlloc

**严重性**: Medium（原评估: Critical → 验证后: Medium） | **CWE**: CWE-120 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/cmodel_driver/driver_api.c:111-122` @ `halMemAlloc`
**模块**: cmodel_driver
**跨模块**: acl → cmodel_driver

**描述**: malloc() is called with user-controlled size parameter from upper layer API (aclrtMalloc). The size is passed directly without integer overflow validation before the malloc call, potentially leading to insufficient memory allocation if size is manipulated.

**漏洞代码** (`src/cmodel_driver/driver_api.c:111-122`)

```c
*pp = malloc(size);
```

**达成路径**

aclrtMalloc(size) [SOURCE: ACL API]
→ halMemAlloc(pp, size, flag) [PROPAGATION]
→ malloc(size) [SINK: memory_allocation]

**验证说明**: malloc使用上层API传入的size。drvMemAlloc中存在MAX_ALLOC上限检查（261行），缓解了整数溢出风险。攻击者控制受限制。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-BO-005] buffer_overflow - drvMemcpy

**严重性**: Medium（原评估: Critical → 验证后: Medium） | **CWE**: CWE-120 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/cmodel_driver/driver_api.c:660-676` @ `drvMemcpy`
**模块**: cmodel_driver
**跨模块**: acl → cmodel_driver

**描述**: Memory copy function accepts user-controlled dst, src, and ByteCount parameters. The function routes to drvModelMemcpy based on address ranges, but the ByteCount parameter flows directly to memory operations without validation against actual buffer allocation sizes.

**漏洞代码** (`src/cmodel_driver/driver_api.c:660-676`)

```c
return drvModelMemcpy((void *)((uintptr_t)dst), destMax, (void *)((uintptr_t) src), ByteCount, DRV_MEMCPY_HOST_TO_HOST);
```

**达成路径**

aclrtMemcpy(dst, src, count) [SOURCE: ACL API]
→ drvMemcpy(dst, destMax, src, ByteCount) [PROPAGATION]
→ drvModelMemcpy(dst, destMax, src, size, kind) [SINK: memory_copy]

**验证说明**: drvModelMemcpy有destMax<size检查（312行）和MAX_ALLOC检查（311行）。memcpy_s使用destMax参数，有基本边界保护。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| acl | 0 | 0 | 1 | 0 | 1 |
| cmodel_driver | 0 | 0 | 4 | 0 | 4 |
| platform | 0 | 0 | 1 | 0 | 1 |
| queue_schedule | 0 | 0 | 1 | 0 | 1 |
| runtime_core | 0 | 3 | 0 | 0 | 3 |
| runtime_driver | 0 | 3 | 1 | 0 | 4 |
| tsd_client | 0 | 1 | 3 | 0 | 4 |
| **合计** | **0** | **7** | **11** | **0** | **18** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-120 | 8 | 44.4% |
| CWE-22 | 4 | 22.2% |
| CWE-190 | 2 | 11.1% |
| CWE-94 | 1 | 5.6% |
| CWE-732 | 1 | 5.6% |
| CWE-287 | 1 | 5.6% |
| CWE-20 | 1 | 5.6% |
