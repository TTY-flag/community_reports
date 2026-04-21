# 漏洞扫描报告 — 待确认漏洞

**项目**: msPTI (MindStudio Profiling Tools Interface)
**扫描时间**: 2026-04-20T00:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 概述

本报告列出 6 个待确认的候选漏洞，包括 1 个 LIKELY 级别和 5 个 POSSIBLE 级别。这些漏洞经过初步验证，置信度在 45-65 之间，需要进一步人工审核和验证。

**处理建议**:

- **LIKELY (SEC-002)**: 建议优先审核，置信度较高 (65)，涉及域名管理逻辑缺陷
- **POSSIBLE (SEC-003~SEC-007)**: 建议根据业务场景评估是否需要修复，置信度在 45-55 之间

**漏洞类型分布**:

| CWE 类型 | 数量 | 说明 |
|----------|------|------|
| CWE-170 | 1 | 字符串处理缺陷 |
| CWE-119 | 2 | 内存边界问题 |
| CWE-822 | 2 | 不可信指针解引用 |
| CWE-367 | 1 | TOCTOU 竞态条件 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 5 | 62.5% |
| LIKELY | 1 | 12.5% |
| FALSE_POSITIVE | 1 | 12.5% |
| CONFIRMED | 1 | 12.5% |
| **总计** | **8** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Medium | 5 | 83.3% |
| Low | 1 | 16.7% |
| **有效漏洞总计** | **6** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[SEC-002]** Improper Null Termination (Medium) - `csrc/common/inject/mstx_inject.cpp:79` @ `MstxDomainMgr::CreateDomainHandle` | 置信度: 65
2. **[SEC-003]** Improper Restriction of Operations within Bounds of Memory Buffer (Medium) - `csrc/activity/ascend/channel/channel_reader.cpp:126` @ `ChannelReader::TransTsFwData` | 置信度: 55
3. **[SEC-004]** Improper Restriction of Operations within Bounds of Memory Buffer (Medium) - `csrc/common/inject/profapi_inject.cpp:164` @ `MsptiCompactInfoReporterCallbackImpl` | 置信度: 55
4. **[SEC-005]** Untrusted Pointer Dereference (Medium) - `csrc/common/inject/driver_inject.cpp:55` @ `ProfDrvGetChannels` | 置信度: 55
5. **[SEC-007]** Time-of-check Time-of-use (TOCTOU) Race Condition (Medium) - `csrc/common/function_loader.cpp:62` @ `CanonicalSoPath` | 置信度: 50
6. **[SEC-006]** Untrusted Pointer Dereference (Low) - `csrc/callback/callback_manager.cpp:94` @ `CallbackManager::Init` | 置信度: 45

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `msptiSubscribe@csrc/callback/callback_manager.cpp` | decorator | semi_trusted | 公共API入口点，用户通过此函数订阅回调，传入自定义回调函数和用户数据，用户数据直接传递到回调中 | 注册性能分析回调订阅者 |
| `msptiActivityRegisterCallbacks@csrc/activity/activity_manager.cpp` | decorator | semi_trusted | 公共API入口点，用户注册缓冲区回调函数，回调函数由用户实现并可能处理来自驱动的数据 | 注册活动记录缓冲区回调 |
| `dlopen@csrc/common/function_loader.cpp` | env | untrusted_local | 使用dlopen动态加载外部库，库路径由ASCEND_HOME_PATH环境变量决定，可能被恶意用户篡改导致加载恶意库 | 动态加载libascendcl.so/libhccl.so/libprofapi.so等外部库 |
| `ProfChannelRead@csrc/common/inject/driver_inject.cpp` | file | semi_trusted | 从驱动通道读取原始性能数据，数据来自设备驱动层，可能被篡改或包含异常数据结构 | 从驱动读取通道数据 |
| `ChannelReader::Execute@csrc/activity/ascend/channel/channel_reader.cpp` | file | semi_trusted | 从驱动读取数据后直接进行类型转换和解析，数据未经过验证直接reinterpret_cast | 读取并解析通道数据 |
| `MstxMarkAFunc@csrc/common/inject/mstx_inject.cpp` | stdin | semi_trusted | 用户提供的msg字符串直接传递到内部处理，仅做长度检查，未对内容进行完整验证 | 处理用户标记消息 |
| `CanonicalSoPath@csrc/common/utils.cpp` | env | untrusted_local | 从ASCEND_HOME_PATH环境变量获取库路径，路径拼接后使用realpath规范化但未做充分验证 | 从环境变量解析动态库路径 |
| `KernelParser::ReportRtTaskTrack@csrc/activity/ascend/parser/kernel_parser.cpp` | rpc | semi_trusted | 从MsprofCompactInfo结构解析数据，数据来自profapi回调，结构体内容可能包含异常值 | 解析内核任务追踪数据 |

**其他攻击面**:
- 动态库加载机制: dlopen/dlsym 加载 libascendcl.so, libhccl.so, libprofapi.so, libascend_hal.so
- 环境变量依赖: ASCEND_HOME_PATH 控制动态库搜索路径
- 驱动数据通道: ProfChannelRead 从设备驱动读取原始二进制数据
- 用户回调机制: msptiSubscribe/msptiActivityRegisterCallbacks 注册用户回调函数
- 字符串输入: mstx标记函数的消息字符串(msg)、域名(domain)
- 结构体转换: reinterpret_cast 直接转换驱动数据为内部结构体
- 缓冲区操作: memcpy_s 复制活动记录数据到用户提供的缓冲区

---

## 3. Medium 漏洞 (5)

### [SEC-002] Improper Null Termination - MstxDomainMgr::CreateDomainHandle

**严重性**: Medium | **CWE**: CWE-170 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/common/inject/mstx_inject.cpp:79-82` @ `MstxDomainMgr::CreateDomainHandle`
**模块**: common_inject

**描述**: Domain name comparison uses strncmp with the stored name's length rather than comparing full strings. This could cause domain name collisions when a new domain name is a prefix of an existing domain name. For example, if 'domain1' exists, a request to create 'domain1extended' would incorrectly return the existing 'domain1' handle instead of creating a new one.

**漏洞代码** (`csrc/common/inject/mstx_inject.cpp:79-82`)

```c
for (const auto &iter : domainHandleMap_) {
    if (strncmp(iter.second->name->c_str(), name, iter.second->name->size()) == 0) {
        iter.second->isDestroyed = false;
        return iter.first;  // Returns existing handle incorrectly
    }
}
```

**达成路径**

name (user input) -> strncmp() comparison with stored name length -> incorrect domain handle returned

**验证说明**: strncmp compares using stored name length, causing domain collision when new domain name is a prefix of existing domain. User-provided domain name reaches vulnerable comparison directly.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-003] Improper Restriction of Operations within Bounds of Memory Buffer - ChannelReader::TransTsFwData

**严重性**: Medium | **CWE**: CWE-119 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/activity/ascend/channel/channel_reader.cpp:126-130` @ `ChannelReader::TransTsFwData`
**模块**: activity_ascend_channel
**跨模块**: activity_ascend_channel → common_inject

**描述**: Driver channel data is directly reinterpret_cast to internal structures without validation beyond size checks. The ProfChannelRead function reads raw binary data from the device driver, which is then cast to TsTrackHead and other structures. If driver data is corrupted or malicious, this could lead to memory corruption, out-of-bounds access, or unexpected behavior.

**漏洞代码** (`csrc/activity/ascend/channel/channel_reader.cpp:126-130`)

```c
TsTrackHead* tsHead = reinterpret_cast<TsTrackHead*>(buffer + pos);
switch (tsHead->rptType) {
    case RPT_TYPE_STEP_TRACE:
        Mspti::Parser::ParserManager::GetInstance()->ReportStepTrace(deviceId,
            reinterpret_cast<StepTrace*>(buffer + pos));
```

**达成路径**

ProfChannelRead() -> buffer -> reinterpret_cast<TsTrackHead*> -> tsHead->rptType dereference

**验证说明**: Driver data from ProfChannelRead is reinterpret_cast without field validation. While driver is semi-trusted, corrupted or malicious driver data could cause memory corruption. Risk is lower due to driver trust boundary.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-004] Improper Restriction of Operations within Bounds of Memory Buffer - MsptiCompactInfoReporterCallbackImpl

**严重性**: Medium | **CWE**: CWE-119 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/common/inject/profapi_inject.cpp:164-195` @ `MsptiCompactInfoReporterCallbackImpl`
**模块**: common_inject
**跨模块**: common_inject → activity_ascend_parser

**描述**: Callback data from profapi is reinterpret_cast to MsprofCompactInfo structure with only a length validation. The callback receives data from libprofapi.so external library. While length check verifies data size matches structure size, the structure's internal fields are not validated. Malformed data could cause unexpected behavior when accessing compact->level, compact->type, and compact->data fields.

**漏洞代码** (`csrc/common/inject/profapi_inject.cpp:164-195`)

```c
if (data == nullptr || length != sizeof(struct MsprofCompactInfo)) {
    return PROFAPI_ERROR;
}
const auto* compact = reinterpret_cast<const MsprofCompactInfo*>(data);
if (compact->level == MSPROF_REPORT_RUNTIME_LEVEL && compact->type == RT_PROFILE_TYPE_TASK_TRACK) {
```

**达成路径**

MsprofApi callback -> data pointer -> length check -> reinterpret_cast<MsprofCompactInfo*> -> field dereference

**验证说明**: Profapi callback data is reinterpret_cast after length check. Length validation ensures size match but internal fields are not validated. Mitigated by size check but field values remain untrusted.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -10 | context: 0 | cross_file: 0

---

### [SEC-005] Untrusted Pointer Dereference - ProfDrvGetChannels

**严重性**: Medium | **CWE**: CWE-822 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/common/inject/driver_inject.cpp:55-65` @ `ProfDrvGetChannels`
**模块**: common_inject
**跨模块**: common_inject → common_utils

**描述**: Function pointers loaded via dlsym are cast using ReinterpretConvert template from void* to function pointer types. While this is common practice for dynamic loading, casting from void* to function pointer is technically undefined behavior in C++ (allowed in POSIX but not standard C++). If dlsym returns a corrupted or incorrect function pointer, invoking it could lead to arbitrary code execution or crashes.

**漏洞代码** (`csrc/common/inject/driver_inject.cpp:55-65`)

```c
void *voidFunc = g_driverFuncArray[FUNC_PROF_DRV_GET_CHANNELS];
using ProfDrvGetChannelsFunc = std::function<decltype(ProfDrvGetChannels)>;
ProfDrvGetChannelsFunc func = Mspti::Common::ReinterpretConvert<decltype(&ProfDrvGetChannels)>(voidFunc);
if (func == nullptr) {
    Mspti::Common::GetFunction("libascend_hal", "prof_drv_get_channels", func);
}
return func(deviceId, channelList);
```

**达成路径**

dlopen() -> dlsym() -> void* -> ReinterpretConvert -> function pointer -> func() invocation

**验证说明**: Function pointers from dlsym are cast via ReinterpretConvert. While technically UB in C++, this is common POSIX practice. Null check provides some mitigation. Exploit requires library injection (SEC-001) first.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -10 | context: 0 | cross_file: 0

---

### [SEC-007] Time-of-check Time-of-use (TOCTOU) Race Condition - CanonicalSoPath

**严重性**: Medium | **CWE**: CWE-367 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/common/function_loader.cpp:62-74` @ `CanonicalSoPath`
**模块**: common_utils

**描述**: CanonicalSoPath performs realpath() on the constructed library path, then checks file existence and readability. Between the realpath() call and the dlopen() call in FunctionLoader::Get(), an attacker could potentially replace the library file (symbolic link attack). The realpath() resolves symbolic links, but the resolved path is then validated for existence/readability before being passed to dlopen(). While realpath() helps mitigate symlink attacks, the file could still be replaced between validation and loading.

**漏洞代码** (`csrc/common/function_loader.cpp:62-74`)

```c
auto canonicalPath = Utils::RealPath(Utils::RelativeToAbsPath(soPath));
return Utils::FileExist(canonicalPath) && Utils::FileReadable(canonicalPath) ? canonicalPath : soName_;
// In FunctionLoader::Get():
auto handle = dlopen(soPath.c_str(), RTLD_LAZY);
```

**达成路径**

Utils::RealPath() -> Utils::FileExist() + Utils::FileReadable() -> canonicalPath returned -> dlopen(canonicalPath) with potential race window

**验证说明**: Potential TOCTOU between realpath() validation and dlopen(). realpath() resolves symlinks reducing symlink attack risk, but file could be replaced between check and load. Race window is small.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -5 | context: 0 | cross_file: 0

---

## 4. Low 漏洞 (1)

### [SEC-006] Untrusted Pointer Dereference - CallbackManager::Init

**严重性**: Low | **CWE**: CWE-822 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/callback/callback_manager.cpp:94-209` @ `CallbackManager::Init`
**模块**: callback

**描述**: User-provided callback function is stored and invoked directly without validation or sandboxing. In msptiSubscribe API, users provide a callback function pointer and userdata that are stored and later invoked during profiling events. While this is an intentional design for the profiling API, a malicious or buggy callback could execute arbitrary code or cause crashes within the profiling infrastructure.

**漏洞代码** (`csrc/callback/callback_manager.cpp:94-209`)

```c
subscriber_ptr_->handle = callback;
subscriber_ptr_->userdata = userdata;
// Later in ExecuteCallback:
subscriber_ptr_->handle(subscriber_ptr_->userdata, domain, cbid, &callbackData);
```

**达成路径**

msptiSubscribe(user callback, userdata) -> subscriber_ptr_->handle stored -> ExecuteCallback() -> handle(userdata, ...) invoked

**验证说明**: User callback is stored and invoked directly without sandboxing. This is intentional API design (profiling requires user callbacks). Downgraded to POSSIBLE as this is expected behavior, but should be documented as security consideration.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -20 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| activity_ascend_channel | 0 | 0 | 1 | 0 | 1 |
| callback | 0 | 0 | 0 | 1 | 1 |
| common_inject | 0 | 0 | 3 | 0 | 3 |
| common_utils | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **0** | **5** | **1** | **6** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-822 | 2 | 33.3% |
| CWE-119 | 2 | 33.3% |
| CWE-367 | 1 | 16.7% |
| CWE-170 | 1 | 16.7% |

---

## 7. 处理建议

### 7.1 LIKELY 级别漏洞 (SEC-002)

**SEC-002 - Improper Null Termination** (置信度: 65)

该漏洞涉及域名字符串比较逻辑缺陷。建议:

1. **审核优先级**: 高 - 应优先进行人工验证
2. **修复方案**: 修改 strncmp 比较逻辑，使用完整的字符串比较而非长度比较
3. **影响评估**: 可能导致域名管理混乱，但安全风险相对可控

### 7.2 POSSIBLE 级别漏洞 (SEC-003~SEC-007)

这些漏洞置信度较低 (45-55)，建议根据业务场景评估:

| 漏洞 ID | 类型 | 处理建议 |
|---------|------|----------|
| SEC-003 | 内存边界 | 驱动数据验证增强，但驱动属于半信任边界，风险有限 |
| SEC-004 | 内存边界 | 已有长度检查缓解，风险降低，可作为中长期改进项 |
| SEC-005 | 指针解引用 | POSIX 常见实践，风险依赖 SEC-001，修复 SEC-001 后可降低 |
| SEC-006 | 指针解引用 | API 设计预期行为，建议文档化而非修复 |
| SEC-007 | TOCTOU | 竞态窗口极小，realpath 提供部分缓解，低优先级 |

### 7.3 综合建议

1. **优先修复 SEC-001** (已确认漏洞) 后，SEC-005 的风险将显著降低
2. **SEC-002** 应进行人工代码审核，确认是否为真实漏洞
3. **SEC-003~SEC-007** 可作为中长期安全加固项目，根据实际部署环境评估必要性

---

## 附录

### A. CWE 参考链接

- [CWE-170: Improper Null Termination](https://cwe.mitre.org/data/definitions/170.html)
- [CWE-119: Improper Restriction of Operations within Bounds of Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
- [CWE-822: Untrusted Pointer Dereference](https://cwe.mitre.org/data/definitions/822.html)
- [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)

---

**报告生成时间**: 2026-04-20
**扫描工具**: Multi-Agent C/C++ Vulnerability Scanner
