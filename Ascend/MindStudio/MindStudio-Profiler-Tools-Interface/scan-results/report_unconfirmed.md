# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-Profiler-Tools-Interface
**扫描时间**: 2026-04-21T09:21:42.727Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 31 | 58.5% |
| LIKELY | 18 | 34.0% |
| CONFIRMED | 3 | 5.7% |
| FALSE_POSITIVE | 1 | 1.9% |
| **总计** | **53** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 4 | 8.2% |
| Medium | 14 | 28.6% |
| Low | 31 | 63.3% |
| **有效漏洞总计** | **49** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-CB-001]** untrusted_callback_execution (High) - `csrc/callback/callback_manager.cpp:213` @ `ExecuteCallback` | 置信度: 75
2. **[VULN-SEC-PYCB-001]** untrusted_callback_execution (High) - `mspti/csrc/mspti_adapter.cpp:48` @ `CallKernelCallback` | 置信度: 75
3. **[MSPTI-VULN-001]** User Callback Execution (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/activity_manager.cpp:59` @ `ActivityBuffer::Init` | 置信度: 75
4. **[VULN-INJECT-001]** library_injection (High) - `csrc/common/inject/acl_inject.cpp:52` @ `LoadAclFunction` | 置信度: 75
5. **[VULN-CALLBACK-002]** Missing Function Pointer Validation (Medium) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/callback/callback_manager.cpp:213` @ `CallbackManager::ExecuteCallback` | 置信度: 80
6. **[VULN-CALLBACK-003]** API Hooking via CallbackScope (Medium) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/callback/callback_manager.h:72` @ `CallbackScope` | 置信度: 75
7. **[VULN-DF-LIB-003]** missing_input_validation (Medium) - `csrc/common/function_loader.cpp:58` @ `CanonicalSoPath` | 置信度: 65
8. **[VULN-DF-LIB-002]** insecure_library_loading_fallback (Medium) - `csrc/common/function_loader.cpp:45` @ `CanonicalSoPath` | 置信度: 65
9. **[MSPTI-001]** Missing Callable Validation (Medium) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/init.cpp:79` @ `Mspti::Adapter::Mstx::RegisterCB` | 置信度: 65
10. **[MSPTI-002]** Missing Callable Validation (Medium) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/init.cpp:132` @ `Mspti::Adapter::Kernel::RegisterCB` | 置信度: 65

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `undefined@csrc/callback/callback_manager.cpp` | API_ENTRY | - | - | Register callback subscriber for profiling events |
| `undefined@csrc/activity/activity_manager.cpp` | API_ENTRY | - | - | Register buffer request/completion callbacks |
| `undefined@csrc/common/inject/acl_inject.cpp` | HOOKED_API | - | - | Hooked ACL device setting function |
| `undefined@csrc/common/inject/acl_inject.cpp` | HOOKED_API | - | - | Hooked ACL kernel launch function |
| `undefined@csrc/activity/ascend/channel/channel_reader.cpp` | DATA_INPUT | - | - | Read profiling data from driver channel |
| `undefined@csrc/common/inject/driver_inject.cpp` | DRIVER_INTERFACE | - | - | Direct driver channel read interface |
| `undefined@mspti/csrc/init.cpp` | PYTHON_MODULE | - | - | Python module initialization |
| `undefined@mspti/csrc/init.cpp` | PYTHON_CALLBACK | - | - | Python callback registration for Mstx/Kernel/Hccl |


---

## 3. High 漏洞 (4)

### [VULN-SEC-CB-001] untrusted_callback_execution - ExecuteCallback

**严重性**: High | **CWE**: CWE-829 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/callback/callback_manager.cpp:213-229` @ `ExecuteCallback`
**模块**: csrc/callback

**描述**: Untrusted callback execution without validation. The CallbackManager::ExecuteCallback() function directly invokes user-provided callback functions (subscriber_ptr_->handle) without any validation or sanitization. A malicious callback could access sensitive profiling data, modify application behavior, or execute arbitrary code during API operations. The callback is registered via msptiSubscribe() which accepts arbitrary function pointers.

**漏洞代码** (`csrc/callback/callback_manager.cpp:213-229`)

```c
void CallbackManager::ExecuteCallback(msptiCallbackDomain domain,
    msptiCallbackId cbid, msptiApiCallbackSite site, const char* funcName)
{
    if (!init_.load()) { return; }
    if (!IsCallbackIdEnable(domain, cbid)) { return; }
    if (subscriber_ptr_->handle) {
        subscriber_ptr_->handle(subscriber_ptr_->userdata, domain, cbid, &callbackData);
    }
}
```

**达成路径**

msptiSubscribe(callback) → subscriber_ptr_->handle → ExecuteCallback() → arbitrary code execution

**验证说明**: msptiSubscribe()接收用户回调函数指针，直接存储并执行。仅检查指针是否为null，无地址验证、签名验证或白名单验证。攻击者可执行任意代码地址。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PYCB-001] untrusted_callback_execution - CallKernelCallback

**严重性**: High | **CWE**: CWE-829 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `mspti/csrc/mspti_adapter.cpp:48-81` @ `CallKernelCallback`
**模块**: mspti/csrc

**描述**: Python callback execution without validation in C extension. The mspti_adapter registers Python callback objects (PyObject*) via RegisterMstxCallback, RegisterKernelCallback, RegisterHcclCallback and executes them via PyObject_CallFunction during buffer processing. A malicious Python callback could execute arbitrary Python code during profiling operations, potentially accessing sensitive data or modifying application state.

**漏洞代码** (`mspti/csrc/mspti_adapter.cpp:48-81`)

```c
void CallKernelCallback(PyObject *kernelCallback, const msptiActivityKernel *kernel)
{
    PyObject *kernelData = Py_BuildValue("{sIsKsKsIsIsKssss}", ...);
    Py_INCREF(kernelCallback);
    auto ret = PyObject_CallFunction(kernelCallback, "O", kernelData);
    Py_DECREF(kernelCallback);
}
```

**达成路径**

RegisterKernelCallback(PyObject) → stored in kernelCallback_ → CallKernelCallback() → PyObject_CallFunction() → arbitrary Python code

**验证说明**: RegisterMstxCallback/RegisterKernelCallback/RegisterHcclCallback接收Python回调对象，通过PyObject_CallFunction执行。攻击者可执行任意Python代码。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [MSPTI-VULN-001] User Callback Execution - ActivityBuffer::Init

**严重性**: High | **CWE**: CWE-829 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: c-cpp-taint-tracking

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/activity_manager.cpp:59-70` @ `ActivityBuffer::Init`
**模块**: csrc/activity/activity_manager.cpp

**描述**: User-provided callback function is executed without sufficient validation. The msptiBuffersCallbackRequestFunc callback is invoked directly to allocate buffer space, allowing user to control buf_, buf_size_, and records_num_ pointers. Malicious callback could return invalid pointers leading to memory corruption.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/activity_manager.cpp:59-70`)

```c
void ActivityBuffer::Init(msptiBuffersCallbackRequestFunc func){ if (func == nullptr) { MSPTI_LOGE("The request callback is nullptr."); return; } func(&buf_, &buf_size_, &records_num_); ... }
```

**达成路径**

msptiActivityRegisterCallbacks() -> RegisterCallbacks() -> ActivityBuffer::Init() -> func(&buf_, &buf_size_, &records_num_) [TAINT SINK: user callback execution]

**验证说明**: ActivityBuffer::Init()调用用户回调函数控制buf_, buf_size_, records_num_指针。恶意回调可返回无效指针导致内存损坏。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-INJECT-001] library_injection - LoadAclFunction

**严重性**: High | **CWE**: CWE-426 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/common/inject/acl_inject.cpp:52-92` @ `LoadAclFunction`
**模块**: csrc/common/inject

**描述**: RegisterFunction in inject modules loads dynamic libraries without validating library paths. Libraries loaded include libascendcl.so, libhccl.so, libprofapi.so, libascend_hal. The library path is controlled by ASCEND_HOME_PATH environment variable in function_loader.cpp.

**漏洞代码** (`csrc/common/inject/acl_inject.cpp:52-92`)

```c
Mspti::Common::RegisterFunction(SO_NAME, "aclrtSetDevice"); ...
```

**达成路径**

RegisterFunction -> FunctionLoader -> CanonicalSoPath -> getenv(ASCEND_HOME_PATH) -> dlopen

**验证说明**: RegisterFunction加载动态库(libascendcl.so等)，路径由ASCEND_HOME_PATH控制。攻击者可通过环境变量劫持库加载。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (14)

### [VULN-CALLBACK-002] Missing Function Pointer Validation - CallbackManager::ExecuteCallback

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-829 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/callback/callback_manager.cpp:213-229` @ `CallbackManager::ExecuteCallback`
**模块**: csrc/callback

**描述**: The callback function pointer validation is insufficient. While ExecuteCallback() checks if the handle is non-null (line 222), there is no validation that the function pointer points to a valid code region, no signature verification, and no check against an allowlist of permitted callbacks. This could allow execution of arbitrary code addresses if memory corruption occurs.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/callback/callback_manager.cpp:213-229`)

```c
void CallbackManager::ExecuteCallback(msptiCallbackDomain domain,
    msptiCallbackId cbid, msptiApiCallbackSite site, const char* funcName)
{
    if (!init_.load()) {
        return;
    }
    if (!IsCallbackIdEnable(domain, cbid)) {
        return;
    }
    if (subscriber_ptr_->handle) {  // Only null check, no address validation
        MSPTI_LOGD("CallbackManager execute Callbackfunc, funcName is %s", funcName);
        msptiCallbackData callbackData;
        callbackData.callbackSite = site;
        callbackData.functionName = funcName;
        subscriber_ptr_->handle(subscriber_ptr_->userdata, domain, cbid, &callbackData);
    }
}
```

**达成路径**

[{"source": "subscriber_ptr_->handle", "line": 104, "type": "taint_source", "description": "Previously stored untrusted callback"}, {"flow": "if (subscriber_ptr_->handle)", "line": 222, "type": "check", "description": "Only null pointer check performed"}, {"sink": "subscriber_ptr_->handle(...)", "line": 227, "type": "taint_sink", "description": "Function pointer invoked without address/signature validation"}]

**验证说明**: 回调函数指针验证不足。仅检查null，无地址验证签名验证白名单验证。若内存损坏可执行任意地址。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-CALLBACK-003] API Hooking via CallbackScope - CallbackScope

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-829 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/callback/callback_manager.h:72-93` @ `CallbackScope`
**模块**: csrc/callback

**描述**: The CallbackScope RAII class provides an automatic hooking mechanism into ACL/HCCL API calls. When any ACL or HCCL API is called, CallbackScope constructor/destructor automatically triggers user callback execution. This creates a comprehensive API hooking surface where user-provided code runs before and after every instrumented API call.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/callback/callback_manager.h:72-93`)

```c
class CallbackScope {
public:
    CallbackScope(msptiCallbackDomain domain, msptiCallbackId cbid, const char* funcName)
        : domain_(domain), cbid_(cbid), func_name_(funcName)
    {
        CallbackManager::GetInstance()->ExecuteCallback(domain, cbid, MSPTI_API_ENTER, func_name_);
    }

    ~CallbackScope()
    {
        try {
            CallbackManager::GetInstance()->ExecuteCallback(domain_, cbid_, MSPTI_API_EXIT, func_name_);
        } catch(...) {
            // Exception occurred during destruction of CallbackScope
        }
    }

private:
    msptiCallbackDomain domain_;
    msptiCallbackId cbid_;
    const char* func_name_;
};
```

**达成路径**

[{"source": "ACL/HCCL API call (e.g., aclrtSetDevice)", "type": "entry_point", "description": "API function entry triggers CallbackScope construction"}, {"flow": "CallbackScope constructor", "line": 74, "type": "propagation", "description": "MSPTI_API_ENTER callback triggered"}, {"flow": "ExecuteCallback(domain, cbid, MSPTI_API_ENTER, func_name_)", "line": 77, "type": "taint_sink", "description": "User callback executed at API entry"}, {"flow": "~CallbackScope destructor", "line": 80, "type": "propagation", "description": "MSPTI_API_EXIT callback triggered"}, {"sink": "ExecuteCallback(domain_, cbid_, MSPTI_API_EXIT, func_name_)", "line": 83, "type": "taint_sink", "description": "User callback executed at API exit"}]

**验证说明**: CallbackScope RAII类自动hook ACL/HCCL API调用，用户回调在API entry/exit时执行。

**评分明细**: base: 30 | context: 0 | controllability: 25 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-LIB-003] missing_input_validation - CanonicalSoPath

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `csrc/common/function_loader.cpp:58-64` @ `CanonicalSoPath`
**模块**: csrc/common

**描述**: Missing input validation in library path construction. The FunctionLoader::CanonicalSoPath() function constructs the library path by concatenating ASCEND_HOME_PATH environment variable with /lib64/ and the library name WITHOUT calling Utils::CheckCharValid() to validate for dangerous characters. The CheckCharValid function exists to filter shell metacharacters but is never invoked in this security-critical path. This allows injection of special characters like .., $, backticks, etc. in the path.

**漏洞代码** (`csrc/common/function_loader.cpp:58-64`)

```c
char *ascendHomePath = std::getenv(ASCEND_HOME_PATH);
if (ascendHomePath == nullptr || ascendHomePath[0] == 0) {
    return soName_;
}
auto soPath = std::string(ascendHomePath) + /lib64/ + soName_;
// NOTE: CheckCharValid() is NEVER called here!
auto canonicalPath = Utils::RealPath(Utils::RelativeToAbsPath(soPath));
return Utils::FileExist(canonicalPath) && Utils::FileReadable(canonicalPath) ? canonicalPath : soName_;
```

**达成路径**

getenv(ASCEND_HOME_PATH) -> path construction -> NO CheckCharValid() -> RealPath() -> dlopen() -> unvalidated path used

**验证说明**: CanonicalSoPath构建库路径时未调用CheckCharValid验证危险字符。CheckCharValid存在但从未调用，允许..等字符在路径中。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-LIB-002] insecure_library_loading_fallback - CanonicalSoPath

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-427 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `csrc/common/function_loader.cpp:45-65` @ `CanonicalSoPath`
**模块**: csrc/common

**描述**: Insecure library loading fallback mechanism. In FunctionLoader::CanonicalSoPath(), when the canonical path verification fails (file does not exist or is not readable), the function falls back to returning just the library name (soName_). This fallback relies on system library search paths (LD_LIBRARY_PATH, /etc/ld.so.conf) which can be controlled by an attacker. Combined with environment variable control, this creates multiple vectors for library hijacking.

**漏洞代码** (`csrc/common/function_loader.cpp:45-65`)

```c
When ASCEND_HOME_PATH is not set or path invalid, returns soName_ directly. dlopen(soName_) then searches LD_LIBRARY_PATH.
```

**达成路径**

ASCEND_HOME_PATH not set OR path invalid -> fallback to soName_ -> dlopen(soName_) -> LD_LIBRARY_PATH search -> library hijacking

**验证说明**: 当ASCEND_HOME_PATH未设置或路径无效时，CanonicalSoPath回退到soName_，dlopen使用LD_LIBRARY_PATH搜索。攻击者可通过控制环境变量劫持库加载。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [MSPTI-001] Missing Callable Validation - Mspti::Adapter::Mstx::RegisterCB

**严重性**: Medium（原评估: high → 验证后: Medium） | **CWE**: CWE-829 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/init.cpp:79-88` @ `Mspti::Adapter::Mstx::RegisterCB`
**模块**: mspti/csrc

**描述**: PyArg_ParseTuple with format 'O' accepts any Python object without validating it is callable. Non-callable objects can be registered as callbacks, causing undefined behavior or crash when PyObject_CallFunction is invoked.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/init.cpp:79-88`)

```c
PyObject *RegisterCB(PyObject *self, PyObject *args)\n{\n    PyObject *callback = nullptr;\n    if (!PyArg_ParseTuple(args, "O", &callback)) {\n        PyErr_SetString(PyExc_TypeError, "Mstx register callback args parse failed!");\n        return nullptr;\n    }\n    auto ret = MsptiAdapter::GetInstance()->RegisterMstxCallback(callback);\n    return Py_BuildValue("i", ret);\n}
```

**达成路径**

PyArg_ParseTuple(args, "O", &callback) [TAINT SOURCE] -> RegisterMstxCallback(callback) -> mstxCallback_ stored -> PyObject_CallFunction(mstxCallback, "O", markerData) [TAINT SINK]

**验证说明**: PyArg_ParseTuple格式'O'接受任意Python对象作为回调。非可调用对象注册为回调会在PyObject_CallFunction调用时崩溃。但Python层会抛出TypeError异常，不会直接内存损坏。依赖用户代码不传递非可调用对象。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-002] Missing Callable Validation - Mspti::Adapter::Kernel::RegisterCB

**严重性**: Medium（原评估: high → 验证后: Medium） | **CWE**: CWE-829 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/init.cpp:132-141` @ `Mspti::Adapter::Kernel::RegisterCB`
**模块**: mspti/csrc

**描述**: PyArg_ParseTuple with format O accepts any Python object without validating it is callable. Non-callable objects can be registered as callbacks, causing undefined behavior or crash when PyObject_CallFunction is invoked.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/init.cpp:132-141`)

```c
PyObject RegisterCB(PyObject self, PyObject args) - PyArg_ParseTuple O format without PyCallable_Check
```

**达成路径**

PyArg_ParseTuple(args, O, callback) -> RegisterKernelCallback(callback) -> kernelCallback_ stored -> PyObject_CallFunction(kernelCallback, O, kernelData) [TAINT SINK]

**验证说明**: 与MSPTI-001相同。PyArg_ParseTuple未验证Kernel回调对象是否可调用。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-003] Missing Callable Validation - Mspti::Adapter::Hccl::RegisterCB

**严重性**: Medium（原评估: high → 验证后: Medium） | **CWE**: CWE-829 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/init.cpp:161-170` @ `Mspti::Adapter::Hccl::RegisterCB`
**模块**: mspti/csrc

**描述**: PyArg_ParseTuple with format O accepts any Python object without validating it is callable. Non-callable objects can be registered as callbacks, causing undefined behavior or crash when PyObject_CallFunction is invoked.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/init.cpp:161-170`)

```c
PyObject RegisterCB(PyObject self, PyObject args) - PyArg_ParseTuple O format without PyCallable_Check
```

**达成路径**

PyArg_ParseTuple(args, O, callback) -> RegisterHcclCallback(callback) -> hcclCallback_ stored -> PyObject_CallFunction(hcclCallback, O, hcclData) [TAINT SINK]

**验证说明**: 与MSPTI-001相同。PyArg_ParseTuple未验证Hccl回调对象是否可调用。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-VULN-002] User Callback Execution - ActivityBuffer::UnInit

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-829 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: c-cpp-taint-tracking

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/activity_manager.cpp:72-81` @ `ActivityBuffer::UnInit`
**模块**: csrc/activity/activity_manager.cpp

**描述**: User-provided completion callback is executed with buffer data that may have been manipulated. The msptiBuffersCallbackCompleteFunc callback receives buffer pointer and size information that originated from user-controlled request callback.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/activity_manager.cpp:72-81`)

```c
void ActivityBuffer::UnInit(msptiBuffersCallbackCompleteFunc func){ if (func == nullptr) { MSPTI_LOGE("The complete callback is nullptr."); return; } func(buf_, buf_size_, valid_size_); }
```

**达成路径**

buf_ (from user callback) -> UnInit() -> func(buf_, buf_size_, valid_size_) [TAINT SINK: tainted data passed to user callback]

**验证说明**: ActivityBuffer::UnInit()调用用户回调函数，传入buf_, buf_size_, valid_size_。这些值来自用户请求回调，可能被操控。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [MSPTI-VULN-007] Memory Corruption - CalculateAll2AllVBandWidth

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-120 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: c-cpp-taint-tracking

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/parser/hccl_calculator.cpp:59-87` @ `CalculateAll2AllVBandWidth`
**模块**: csrc/activity/ascend/parser/hccl_calculator.cpp

**描述**: CalculateAll2AllVBandWidth accesses sendCounts and recvCounts arrays using rankSize as loop bound without validating that the arrays have sufficient elements. If rankSize exceeds actual array size, out-of-bounds memory access occurs.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/parser/hccl_calculator.cpp:59-87`)

```c
msptiResult CalculateAll2AllVBandWidth(HcclOpDesc* hcclOpDesc){ auto all2AllVOpDesc = static_cast<All2AllVOpDesc*>(hcclOpDesc); const auto* sendCounts = reinterpret_cast<const uint64_t*>(all2AllVOpDesc->sendCounts); for (uint32_t i = 0; i < all2AllVOpDesc->rankSize; i++) { sendDataSize += sendCounts[i] * sendType->second; recvDataSize += recvCounts[i] * recvType->second; } }
```

**达成路径**

All2AllVOpDesc->sendCounts/recvCounts (external pointers) + rankSize -> for loop i < rankSize -> sendCounts[i], recvCounts[i] [TAINT SINK: array access with unvalidated bounds]

**验证说明**: CalculateAll2AllVBandWidth()使用rankSize作为循环边界访问sendCounts和recvCounts数组，无数组大小验证。若rankSize超过数组大小会导致越界访问。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CHANNEL-001] Buffer Over-read - ChannelReader::TransTsFwData

**严重性**: Medium（原评估: high → 验证后: Medium） | **CWE**: CWE-125 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: c-cpp-taint-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/channel_reader.cpp:127-141` @ `ChannelReader::TransTsFwData`
**模块**: csrc/activity/ascend/channel

**描述**: TsTrackHead structure fields are read from external driver data without validating buffer bounds. At line 129, buffer + pos is cast to TsTrackHead without verifying sufficient remaining bytes. The rptType field from untrusted source controls switch branching, potentially leading to out-of-bounds reads if buffer contains malicious data.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/channel_reader.cpp:127-141`)

```c
while (valid_size - pos >= logStructSize) {
    StepTraceBasic stepTrace;
    TsTrackHead* tsHead = reinterpret_cast<TsTrackHead*>(buffer + pos);
    MSPTI_LOGD("ts track data type is %d", tsHead->rptType);
    switch (tsHead->rptType) {
        case RPT_TYPE_STEP_TRACE:
            Convert::TsfwConvert::GetInstance().TransData(buffer, valid_size, deviceId, pos, stepTrace);
            Mspti::Parser::ParserManager::GetInstance()->ReportStepTrace(deviceId, &stepTrace);
            break;
        default:
            pos += logStructSize;
            break;
    }
}
```

**达成路径**

ProfChannelRead(deviceId_, channelId_, buf + cur_pos, MAX_BUFFER_SIZE - cur_pos) -> buf (external, tainted) -> TransDataToActivityBuffer(buf, cur_pos + uint_currLen, deviceId_, channelId_) -> TransTsFwData(buffer, valid_size, deviceId) -> reinterpret_cast<TsTrackHead*>(buffer + pos) -> tsHead->rptType (untrusted control flow)

**验证说明**: TransTsFwData将外部驱动数据重新解释为TsTrackHead结构，rptType控制switch分支。无缓冲区边界验证，可能导致越界读取。数据来自NPU驱动，通常可信但恶意驱动可能利用。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-CHANNEL-002] Type Confusion - Trans910BSocLog

**严重性**: Medium（原评估: high → 验证后: Medium） | **CWE**: CWE-843 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: c-cpp-taint-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/soclog_convert.cpp:28-56` @ `Trans910BSocLog`
**模块**: csrc/activity/ascend/channel

**描述**: funcType field from external driver data (6-bit field) controls type casting decisions without comprehensive validation. Malicious funcType values could cause the buffer to be interpreted as wrong struct types (StarsSocLog vs FftsPlusLog vs StarsSocLogV6), leading to out-of-bounds reads and data corruption.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/soclog_convert.cpp:28-56`)

```c
bool Trans910BSocLog(const void *const buffer, HalLogData &halLogData)
{
    const auto *originHeader = reinterpret_cast<const StarsSocHeader *>(buffer);
    if (originHeader->funcType == STARS_FUNC_TYPE_BEGIN || originHeader->funcType == STARS_FUNC_TYPE_END) {
        const auto *originData = reinterpret_cast<const StarsSocLog *>(buffer);
        // ... process as StarsSocLog
    } else if (originHeader->funcType == FFTS_PLUS_TYPE_START || originHeader->funcType == FFTS_PLUS_TYPE_END) {
        const auto *originData = reinterpret_cast<const FftsPlusLog *>(buffer);
        // ... process as FftsPlusLog (different struct layout)
    } else {
        MSPTI_LOGW("unkonw funcType, funcType is %u", static_cast<uint32_t>(originHeader->funcType));
        return false;
    }
}
```

**达成路径**

ProfChannelRead -> buf -> TransStarsLog -> SocLogConvert::TransData -> Trans910BSocLog(buffer) -> reinterpret_cast<StarsSocHeader*>(buffer)->funcType (untrusted) -> type confusion between StarsSocLog and FftsPlusLog

**验证说明**: Trans910BSocLog根据funcType字段决定类型转换(StarsSocLog vs FftsPlusLog)，恶意funcType可能导致类型混淆。funcType为6位字段，值范围0-63，但仅处理已知值，其他值返回false。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-CALLBACK-004] Untrusted Userdata Propagation - CallbackManager::Init

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/callback/callback_manager.cpp:104-107` @ `CallbackManager::Init`
**模块**: csrc/callback

**描述**: User-provided userdata pointer is stored and passed to callback without validation. The userdata pointer provided at subscription time is stored and later passed to the user callback without any validation of its contents or integrity. This could be exploited to inject malicious data structures or pointers that the callback function might process.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/callback/callback_manager.cpp:104-107`)

```c
subscriber_ptr_->handle = callback;
subscriber_ptr_->userdata = userdata;  // Untrusted userdata stored
*subscriber = subscriber_ptr_.get();
init_.store(true);
```

**达成路径**

[{"source": "msptiSubscribe(subscriber, callback, userdata)", "line": 244, "type": "taint_source", "description": "User-provided userdata enters system"}, {"flow": "Init(subscriber, callback, userdata)", "line": 86, "type": "propagation", "description": "userdata passed to Init"}, {"flow": "subscriber_ptr_->userdata = userdata", "line": 105, "type": "taint_store", "description": "userdata stored without validation"}, {"sink": "subscriber_ptr_->handle(subscriber_ptr_->userdata, ...)", "line": 227, "type": "taint_sink", "description": "userdata passed to user callback"}]

**验证说明**: userdata作为void*传入回调函数，回调可直接访问。攻击者可控制userdata内容。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-INJECT-002] api_hooking - LoadHcclFunction

**严重性**: Medium | **CWE**: CWE-829 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/common/inject/hccl_inject.cpp:53-66` @ `LoadHcclFunction`
**模块**: csrc/common/inject

**描述**: API hooking mechanism in inject modules hooks into ACL/HCCL/MSTX API calls. If an attacker can inject a malicious library via ASCEND_HOME_PATH, all hooked API calls would be intercepted including aclrtLaunchKernel, HcclAllReduce, etc.

**漏洞代码** (`csrc/common/inject/hccl_inject.cpp:53-66`)

```c
g_hcclFuncArray[FUNC_HCCL_ALL_REDUCE] = Mspti::Common::RegisterFunction("libhccl", "HcclAllReduce");
```

**达成路径**

RegisterFunction -> GetFunction -> hooked API call execution

**验证说明**: API hooking机制hook ACL/HCCL API调用。若库被注入，攻击者可拦截API调用。依赖ASCEND_HOME_PATH漏洞。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-INJECT-003] function_interposition - LoadDriverFunction

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/common/inject/driver_inject.cpp:43-51` @ `LoadDriverFunction`
**模块**: csrc/common/inject

**描述**: Driver inject module loads libascend_hal for ProfChannelRead, ProfChannelPoll, ProfDrvGetChannels. If library path is hijacked, attacker can intercept all profiling data from NPU driver.

**漏洞代码** (`csrc/common/inject/driver_inject.cpp:43-51`)

```c
g_driverFuncArray[FUNC_PROF_CHANNEL_READ] = Mspti::Common::RegisterFunction("libascend_hal", "prof_channel_read");
```

**达成路径**

RegisterFunction -> ProfChannelRead -> ChannelReader::Execute -> driver data

**验证说明**: Driver inject模块加载libascend_hal用于ProfChannelRead等。攻击者可通过ASCEND_HOME_PATH劫持库路径拦截驱动数据。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

## 5. Low 漏洞 (31)

### [VULN-SEC-ENV-001] environment_variable_manipulation - GetEnv

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/common/utils.cpp:148-151` @ `GetEnv`
**模块**: csrc/common

**描述**: Environment variable used in security-sensitive context without validation. Multiple locations use std::getenv() to read environment variables that influence security-sensitive operations. ASCEND_HOME_PATH controls library loading paths, and LD_PRELOAD is checked for presence without integrity verification. An attacker with access to the environment can manipulate these variables to affect application behavior.

**漏洞代码** (`csrc/common/utils.cpp:148-151`)

```c
std::string Utils::GetEnv(const std::string& name) {
    const char* value = std::getenv(name.c_str());
    return value ? std::string(value) : std::string();
}
```

**达成路径**

Environment variables → GetEnv() → security-sensitive operations (library loading, callback checks)

**验证说明**: GetEnv读取环境变量用于敏感操作。但环境变量通常由管理员或部署脚本控制，攻击者难以直接操控。依赖部署环境安全。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-PATH-001] path_traversal - RealPath

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `csrc/common/utils.cpp:94-104` @ `RealPath`
**模块**: csrc/common

**描述**: Path traversal vulnerability in Utils::RealPath. The function calls realpath() on user-supplied paths without validating against directory traversal sequences (../). While realpath() resolves symlinks and relative paths, it can be used to access files outside intended directories if an attacker can control the input path. The function only checks for empty paths and PATH_MAX size limits but does not restrict the resolved path to a safe directory.

**漏洞代码** (`csrc/common/utils.cpp:94-104`)

```c
std::string Utils::RealPath(const std::string& path)
{
    if (path.empty() || path.size() > PATH_MAX) {
        return "";
    }
    char realPath[PATH_MAX] = {0};
    if (realpath(path.c_str(), realPath) == nullptr) {
        return "";
    }
    return std::string(realPath);
}
```

**达成路径**

User input → RealPath(path) → realpath() → resolved absolute path → potentially unintended file access

**验证说明**: RealPath调用realpath处理路径。路径来自ASCEND_HOME_PATH，已被第一个漏洞覆盖。单独看路径处理无边界验证，但依赖环境变量控制。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-LINK-001] symlink_following - RealPath

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-59 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `csrc/common/utils.cpp:94-104` @ `RealPath`
**模块**: csrc/common

**描述**: Symlink following vulnerability in library loading path. The Utils::RealPath() function uses realpath() which follows symbolic links. In the context of FunctionLoader::CanonicalSoPath(), an attacker who can create symlinks in the ASCEND_HOME_PATH directory (or any parent directory) could redirect library loading to arbitrary files. The path resolution through realpath() does not verify that the resolved path stays within expected boundaries.

**漏洞代码** (`csrc/common/utils.cpp:94-104`)

```c
std::string Utils::RealPath(const std::string& path)
{
    if (path.empty() || path.size() > PATH_MAX) {
        return "";
    }
    char realPath[PATH_MAX] = {0};
    if (realpath(path.c_str(), realPath) == nullptr) {  // Follows symlinks!
        return "";
    }
    return std::string(realPath);
}
// Called from function_loader.cpp:
auto canonicalPath = Utils::RealPath(Utils::RelativeToAbsPath(soPath));
// soPath = ASCEND_HOME_PATH + "/lib64/" + soName_
// If attacker creates symlink: ASCEND_HOME_PATH/lib64/libascendcl.so → /malicious/lib.so
```

**达成路径**

Symlink in controlled path → realpath() follows symlink → dlopen() loads malicious library

**验证说明**: RealPath调用realpath跟随符号链接。攻击者需在控制目录下创建符号链接。依赖ASCEND_HOME_PATH漏洞。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-PATH-002] path_traversal - RelativeToAbsPath

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `csrc/common/utils.cpp:106-119` @ `RelativeToAbsPath`
**模块**: csrc/common

**描述**: Path traversal vulnerability in Utils::RelativeToAbsPath. The function converts relative paths to absolute without validating against directory traversal sequences (../). An attacker-controlled relative path like ../../../etc/passwd would be converted to an absolute path without any sanitization. Only checks if path starts with / to determine if already absolute.

**漏洞代码** (`csrc/common/utils.cpp:106-119`)

```c
std::string Utils::RelativeToAbsPath(const std::string& path)
{
    if (path.empty() || path.size() > PATH_MAX) {
        return ;
    }
    if (path[0] != '/''') {
        char pwd_path[PATH_MAX] = {0};
        if (getcwd(pwd_path, PATH_MAX) != nullptr) {
            return std::string(pwd_path) + / + path;
        }
        return ;
    }
    return std::string(path);
}
```

**达成路径**

User input -> RelativeToAbsPath(path) -> getcwd() + path -> absolute path with traversal -> unintended file access

**验证说明**: RelativeToAbsPath将相对路径转为绝对路径，无目录遍历验证。路径来自ASCEND_HOME_PATH，已被第一个漏洞覆盖。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-004] Memory Leak - Missing DECREF on Callback Replacement - MsptiAdapter::RegisterMstxCallback

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-829 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/mspti_adapter.cpp:303-309` @ `MsptiAdapter::RegisterMstxCallback`
**模块**: mspti/csrc

**描述**: When registering a new callback, the previous callback is not properly DECREFd before being replaced, causing a reference count leak. This can lead to memory exhaustion if callbacks are repeatedly registered.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/mspti_adapter.cpp:303-309`)

```c
msptiResult MsptiAdapter::RegisterMstxCallback(PyObject *mstxCallback)\n{\n    std::lock_guard<std::mutex> lk(mtx_);\n    Py_XINCREF(mstxCallback);\n    mstxCallback_ = mstxCallback;  // Old mstxCallback_ reference leaked\n    return msptiActivityEnable(MSPTI_ACTIVITY_KIND_MARKER);\n}
```

**达成路径**

RegisterMstxCallback(mstxCallback) -> Py_XINCREF(mstxCallback) -> mstxCallback_ = mstxCallback [OLD mstxCallback_ NOT DECREFd - MEMORY LEAK]

**验证说明**: RegisterMstxCallback替换回调时未对旧回调执行DECREF。内存泄漏而非安全问题，但可能导致内存耗尽。依赖回调注册频率。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-005] Memory Leak - Missing DECREF on Callback Replacement - MsptiAdapter::RegisterKernelCallback

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-829 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/mspti_adapter.cpp:324-330` @ `MsptiAdapter::RegisterKernelCallback`
**模块**: mspti/csrc

**描述**: When registering a new callback, the previous callback is not properly DECREFd before being replaced, causing a reference count leak.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/mspti_adapter.cpp:324-330`)

```c
Old kernelCallback_ reference leaked when new callback assigned
```

**达成路径**

RegisterKernelCallback(kernelCallback) -> Py_XINCREF(kernelCallback) -> kernelCallback_ = kernelCallback [OLD kernelCallback_ NOT DECREFd]

**验证说明**: 与MSPTI-004相同。RegisterKernelCallback替换回调时未对旧回调执行DECREF。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-006] Memory Leak - Missing DECREF on Callback Replacement - MsptiAdapter::RegisterHcclCallback

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-829 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/mspti_adapter.cpp:345-351` @ `MsptiAdapter::RegisterHcclCallback`
**模块**: mspti/csrc

**描述**: When registering a new callback, the previous callback is not properly DECREFd before being replaced, causing a reference count leak.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/mspti_adapter.cpp:345-351`)

```c
Old hcclCallback_ reference leaked when new callback assigned
```

**达成路径**

RegisterHcclCallback(hcclCallback) -> Py_XINCREF(hcclCallback) -> hcclCallback_ = hcclCallback [OLD hcclCallback_ NOT DECREFd]

**验证说明**: 与MSPTI-004相同。RegisterHcclCallback替换回调时未对旧回调执行DECREF。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-007] Integer Overflow in Buffer Size Calculation - MsptiAdapter::SetBufferSize

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-120 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/mspti_adapter.cpp:289-301` @ `MsptiAdapter::SetBufferSize`
**模块**: mspti/csrc

**描述**: Integer overflow vulnerability in SetBufferSize. The calculation bufferSize = size * MB where MB = 1024*1024 can overflow when size is a large uint32_t.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/mspti_adapter.cpp:289-301`)

```c
if (size * MB > MAX_BUFFER_SIZE) overflow check can itself overflow
```

**达成路径**

PyArg_ParseTuple(args, I, size) -> SetBufferSize(size) -> size * MB [OVERFLOW RISK] -> bufferSize

**验证说明**: SetBufferSize中size * MB计算可能溢出。虽有MAX_BUFFER_SIZE检查，但size为uint32_t时溢出检查本身可能溢出。依赖输入范围限制。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-009] Callback Execution Without Exception Handling - CallKernelCallback

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-829 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/mspti_adapter.cpp:48-81` @ `CallKernelCallback`
**模块**: mspti/csrc

**描述**: PyObject_CallFunction is called without proper exception handling. If callback raises exception, no PyErr_Clear is called.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/mspti_adapter.cpp:48-81`)

```c
No PyErr_Clear after PyObject_CallFunction fails
```

**达成路径**

kernelCallback -> PyObject_CallFunction -> ret == nullptr -> MSPTI_LOGE [NO PyErr_Clear]

**验证说明**: CallKernelCallback调用PyObject_CallFunction后无PyErr_Clear。异常未清理可能导致后续Python调用失败。非直接安全问题，但可能导致程序不稳定。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-010] Callback Execution Without Exception Handling - CallMstxCallback

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-829 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/mspti_adapter.cpp:83-121` @ `CallMstxCallback`
**模块**: mspti/csrc

**描述**: PyObject_CallFunction is called without proper exception handling. If callback raises exception, no PyErr_Clear is called.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/mspti_adapter.cpp:83-121`)

```c
No PyErr_Clear after PyObject_CallFunction fails
```

**达成路径**

mstxCallback -> PyObject_CallFunction -> ret == nullptr -> MSPTI_LOGE [NO PyErr_Clear]

**验证说明**: CallMstxCallback调用PyObject_CallFunction后无PyErr_Clear。异常未清理可能导致程序不稳定。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-011] Callback Execution Without Exception Handling - CallHcclCallback

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-829 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/mspti_adapter.cpp:123-156` @ `CallHcclCallback`
**模块**: mspti/csrc

**描述**: PyObject_CallFunction is called without proper exception handling. If callback raises exception, no PyErr_Clear is called.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/mspti_adapter.cpp:123-156`)

```c
No PyErr_Clear after PyObject_CallFunction fails
```

**达成路径**

hcclCallback -> PyObject_CallFunction -> ret == nullptr -> MSPTI_LOGE [NO PyErr_Clear]

**验证说明**: CallHcclCallback调用PyObject_CallFunction后无PyErr_Clear。异常未清理可能导致程序不稳定。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-VULN-003] Buffer Overflow - ActivityManager::GetNextRecord

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-120 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: c-cpp-taint-tracking

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/activity_manager.cpp:227-263` @ `ActivityManager::GetNextRecord`
**模块**: csrc/activity/activity_manager.cpp

**描述**: GetNextRecord reads activity kind from buffer without comprehensive validation. The activity kind value is read directly from buffer position and used to determine data size. Malformed buffer could contain invalid activity kind values leading to incorrect memory access.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/activity_manager.cpp:227-263`)

```c
msptiActivityKind *pKind = Common::ReinterpretConvert<msptiActivityKind*>(buffer + pos); auto iter = activityKindDataSize.find(*pKind); if (iter == activityKindDataSize.end()) { MSPTI_LOGE("GetNextRecord failed, invalid kind: %d", *pKind); return MSPTI_ERROR_INNER; } *record = Common::ReinterpretConvert<msptiActivity*>(buffer + pos); pos += iter->second;
```

**达成路径**

buffer (user-provided) -> pKind = reinterpret_cast(buffer + pos) -> activityKindDataSize.find(*pKind) [TAINT SINK: unvalidated enum value]

**验证说明**: GetNextRecord读取activity kind值确定数据大小。值来自用户回调提供的缓冲区，可能被操控。但有activityKindDataSize映射检查，无效值会返回错误。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-VULN-004] Data Parsing Vulnerability - ParserManager::ReportStepTrace

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-119 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: c-cpp-taint-tracking

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/parser/parser_manager.cpp:66-78` @ `ParserManager::ReportStepTrace`
**模块**: csrc/activity/ascend/parser/parser_manager.cpp
**跨模块**: csrc/activity/ascend/parser/parser_manager.cpp → csrc/activity/ascend/channel/channel_reader.cpp

**描述**: ReportStepTrace processes external StepTraceBasic data from device channel without comprehensive field validation. The stepTrace data is directly used to determine processing flow via tagId switch.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/parser/parser_manager.cpp:66-78`)

```c
void ParserManager::ReportStepTrace(uint32_t deviceId, const StepTraceBasic* stepTrace){ if (!stepTrace) { return; } switch (stepTrace->tagId) { case STEP_TRACE_TAG_MARKEX: MstxParser::GetInstance()->ReportMarkDataToActivity(deviceId, stepTrace); break; default: break; } }
```

**达成路径**

ChannelReader::TransTsFwData() -> stepTrace (from device buffer) -> ReportStepTrace() -> stepTrace->tagId [TAINT SOURCE: external device data]

**验证说明**: ReportStepTrace处理外部StepTraceBasic数据，字段直接使用无范围验证。数据来自设备通道，通常可信。依赖驱动安全。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-VULN-005] Data Parsing Vulnerability - MstxParser::ReportMarkDataToActivity

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-119 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: c-cpp-taint-tracking

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/parser/mstx_parser.cpp:202-240` @ `MstxParser::ReportMarkDataToActivity`
**模块**: csrc/activity/ascend/parser/mstx_parser.cpp
**跨模块**: csrc/activity/ascend/parser/mstx_parser.cpp → csrc/activity/ascend/parser/parser_manager.cpp

**描述**: ReportMarkDataToActivity processes StepTraceBasic data fields (indexId, modelId, streamId, timestamp) from device channel and creates msptiActivityMarker without validating field ranges.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/parser/mstx_parser.cpp:202-240`)

```c
void MstxParser::ReportMarkDataToActivity(uint32_t deviceId, const StepTraceBasic* stepTrace){ ... mark.timestamp = Common::ContextManager::GetInstance()->CalculateRealTime(stepTrace->timestamp, devTimeInfo); mark.id = stepTrace->indexId; mark.flag = static_cast<msptiActivityFlag>(stepTrace->modelId); mark.objectId.ds.streamId = static_cast<uint32_t>(stepTrace->streamId); }
```

**达成路径**

ChannelReader::TransTsFwData() -> StepTraceBasic (device data) -> ReportMarkDataToActivity() -> stepTrace fields [TAINT SINK: external data used in activity structure]

**验证说明**: ReportMarkDataToActivity处理StepTraceBasic数据字段，无范围验证。数据来自设备通道，通常可信。依赖驱动安全。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-VULN-006] Data Parsing Vulnerability - KernelParser::KernelParserImpl::ReportRtTaskTrack

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-119 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: c-cpp-taint-tracking

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/parser/kernel_parser.cpp:93-114` @ `KernelParser::KernelParserImpl::ReportRtTaskTrack`
**模块**: csrc/activity/ascend/parser/kernel_parser.cpp

**描述**: ReportRtTaskTrack processes MsprofCompactInfo data containing runtime track information (deviceId, streamId, taskType, kernelName hash) from external profiling API. The data fields are cached and later used for kernel activity creation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/parser/kernel_parser.cpp:93-114`)

```c
msptiResult KernelParser::KernelParserImpl::ReportRtTaskTrack(uint32_t agingFlag, const MsprofCompactInfo *data){ auto taskType = static_cast<TsTaskType>(data->data.runtimeTrack.taskType); hostTasks_.emplace_back(data->threadId, data->data.runtimeTrack.deviceId, data->data.runtimeTrack.streamId, data->data.runtimeTrack.taskType, data->data.runtimeTrack.kernelName, ...); }
```

**达成路径**

MsptiCompactInfoReporterCallbackImpl() -> MsprofCompactInfo (external profiling data) -> ReportRtTaskTrack() -> data->data.runtimeTrack fields [TAINT SOURCE: external API callback data]

**验证说明**: ReportRtTaskTrack处理MsprofCompactInfo数据，字段直接使用。数据来自外部profiling API回调，通常可信。依赖API调用者安全。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-VULN-008] Data Parsing Vulnerability - ChannelReader::TransTsFwData

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-119 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: c-cpp-taint-tracking

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/channel_reader.cpp:123-142` @ `ChannelReader::TransTsFwData`
**模块**: csrc/activity/ascend/channel/channel_reader.cpp
**跨模块**: csrc/activity/ascend/channel/channel_reader.cpp → csrc/activity/ascend/parser/parser_manager.cpp

**描述**: TransTsFwData processes raw buffer data from driver channel. The buffer content is reinterpreted as TsTrackHead structure and rptType field is used to determine processing. Malformed buffer could contain invalid rptType or corrupted structure data.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/channel_reader.cpp:123-142`)

```c
size_t ChannelReader::TransTsFwData(char buffer[], size_t valid_size, uint32_t deviceId){ TsTrackHead* tsHead = reinterpret_cast<TsTrackHead*>(buffer + pos); switch (tsHead->rptType) { case RPT_TYPE_STEP_TRACE: Convert::TsfwConvert::GetInstance().TransData(buffer, valid_size, deviceId, pos, stepTrace); Mspti::Parser::ParserManager::GetInstance()->ReportStepTrace(deviceId, &stepTrace); break; } }
```

**达成路径**

ProfChannelRead() -> buffer (driver channel data) -> TsTrackHead* tsHead = reinterpret_cast(buffer + pos) -> tsHead->rptType [TAINT SOURCE: external driver data]

**验证说明**: TransTsFwData处理驱动通道数据，buffer内容被重新解释。数据来自NPU驱动，通常可信。依赖驱动安全。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-VULN-009] Data Parsing Vulnerability - ChannelReader::TransStarsLog

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-119 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: c-cpp-taint-tracking

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/channel_reader.cpp:144-159` @ `ChannelReader::TransStarsLog`
**模块**: csrc/activity/ascend/channel/channel_reader.cpp
**跨模块**: csrc/activity/ascend/channel/channel_reader.cpp → csrc/activity/ascend/parser/kernel_parser.cpp

**描述**: TransStarsLog processes raw buffer data from STARS_SOC_LOG channel. The buffer is passed to SocLogConvert for conversion and resulting HalLogData is processed by KernelParser and DeviceTaskCalculator. No validation of buffer content integrity.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/channel_reader.cpp:144-159`)

```c
size_t ChannelReader::TransStarsLog(char buffer[], size_t valid_size, uint32_t deviceId){ HalLogData logData; Convert::SocLogConvert::GetInstance().TransData(buffer, valid_size, deviceId, pos, logData); Mspti::Parser::DeviceTaskCalculator::GetInstance().ReportStarsSocLog(deviceId, logData); Mspti::Parser::KernelParser::GetInstance()->ReportStarsSocLog(deviceId, logData); }
```

**达成路径**

ProfChannelRead() -> buffer (driver channel) -> SocLogConvert::TransData() -> HalLogData -> ReportStarsSocLog() [TAINT SINK: external data propagated to parsers]

**验证说明**: TransStarsLog处理STARS_SOC_LOG通道数据。数据来自驱动通道，通常可信。依赖驱动安全。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-VULN-010] Data Parsing Vulnerability - CannApiParser::CannApiParserImpl::ReportRtApi

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-119 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: c-cpp-taint-tracking

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/parser/cann_api_parser.cpp:52-80` @ `CannApiParser::CannApiParserImpl::ReportRtApi`
**模块**: csrc/activity/ascend/parser/cann_api_parser.cpp

**描述**: ReportRtApi processes MsprofApi data from external profiling callback. The data contains level, type, threadId, beginTime, endTime, itemId fields that are used to construct activity records.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/parser/cann_api_parser.cpp:52-80`)

```c
msptiResult ReportRtApi(uint32_t agingFlag, const MsprofApi* data){ auto kind = level2ApiKind(data->level); const auto& name = CannHashCache::GetTypeHashInfo(data->level, data->type); api.start = Common::ContextManager::GetInstance()->GetRealTimeFromSysCnt(data->beginTime); api.end = Common::ContextManager::GetInstance()->GetRealTimeFromSysCnt(data->endTime); }
```

**达成路径**

MsptiApiReporterCallbackImpl() -> MsprofApi (external profiling data) -> ReportRtApi() -> data->level/type/itemId/beginTime/endTime [TAINT SOURCE: external API callback]

**验证说明**: ReportRtApi处理MsprofApi数据，字段直接使用。数据来自外部profiling API回调，通常可信。依赖API调用者安全。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-DF-001] Path Traversal - <module>

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/monitor/_mspti_c.py:23-26` @ `<module>`
**模块**: mspti.monitor._mspti_c

**描述**: Dynamic sys.path manipulation with relative path resolution. The module constructs a path using os.path.dirname(__file__) and adds it to sys.path without validation. In certain deployment scenarios (zip imports, frozen executables, symlink attacks), this could lead to module hijacking where a malicious mspti_C module could be loaded.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/monitor/_mspti_c.py:23-26`)

```c
so_path = os.path.join(os.path.dirname(__file__), "..", "lib64")
sys.path.append(os.path.realpath(so_path))

mspti_C_module = importlib.import_module("mspti_C")
```

**达成路径**

[{"source": "os.path.dirname(__file__)", "line": 23, "type": "path_source"}, {"sink": "os.path.join()", "line": 23, "type": "path_construction"}, {"sink": "os.path.realpath()", "line": 24, "type": "path_resolution"}, {"sink": "sys.path.append()", "line": 24, "type": "path_injection_sink"}, {"sink": "importlib.import_module()", "line": 26, "type": "module_load_sink"}]

**验证说明**: _mspti_c.py动态修改sys.path导入mspti_C模块。路径来自os.path.dirname(__file__)，在某些部署场景(zip import, frozen, symlink)下可能被劫持。依赖部署环境安全。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-DF-003] Type Confusion - start

**严重性**: Low（原评估: low → 验证后: Low） | **CWE**: CWE-843 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/monitor/mstx_monitor.py:47-58` @ `start`
**模块**: mspti.monitor.mstx_monitor

**描述**: Logic flaw in callback validation allows storing non-callable objects. The start() method checks if BOTH mark_cb AND range_cb are non-callable before rejecting, but this allows one to be non-callable while the other is callable. The non-callable callback is stored and could cause AttributeError when invoked later.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/monitor/mstx_monitor.py:47-58`)

```c
def start(self,
          mark_cb: Callable[[MarkerData], None] = empty_callback,
          range_cb: Callable[[RangeMarkerData], None] = empty_callback) -> MsptiResult:
    if not callable(mark_cb) and not callable(range_cb):
        print_error_msg(\"Mstx callback is invalid\")
        return MsptiResult.MSPTI_ERROR_INVALID_PARAMETER
    ret = BaseMonitor.start_monitor()
    if ret == MsptiResult.MSPTI_SUCCESS:
        self.mark_user_cb = mark_cb
        self.range_user_cb = range_cb
        return MsptiResult(_mstx_register_cb(self.callback))
    return ret
```

**达成路径**

[{"source": "mark_cb (user input)", "line": 48, "type": "callback_input"}, {"source": "range_cb (user input)", "line": 49, "type": "callback_input"}, {"validation": "not callable(mark_cb) and not callable(range_cb)", "line": 50, "type": "flawed_validation_logic"}, {"sink": "self.mark_user_cb = mark_cb", "line": 55, "type": "storage_without_validation"}, {"sink": "self.range_user_cb = range_cb", "line": 56, "type": "storage_without_validation"}, {"sink": "self.mark_user_cb(mark_data)", "line": 103, "type": "potential_type_error"}, {"sink": "self.range_user_cb(range_mark_data)", "line": 115, "type": "potential_type_error"}]

**验证说明**: start()方法回调验证逻辑有缺陷：检查两个回调都不可调用才拒绝，允许一个不可调用一个可调用。不可调用回调存储后调用时抛出AttributeError。

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-CHANNEL-003] Integer Overflow - ChannelReader::Execute

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: c-cpp-taint-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/channel_reader.cpp:85-105` @ `ChannelReader::Execute`
**模块**: csrc/activity/ascend/channel

**描述**: currLen returned from ProfChannelRead is int type. The check at line 93 casts to size_t and validates against buffer size, but the arithmetic cur_pos + uint_currLen could overflow if currLen approaches INT_MAX. Additionally, the memcpy_s size calculation cur_pos + uint_currLen - last_pos has potential for underflow if last_pos > cur_pos + uint_currLen.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/channel_reader.cpp:85-105`)

```c
currLen = ProfChannelRead(deviceId_, channelId_, buf + cur_pos, MAX_BUFFER_SIZE - cur_pos);
if (currLen <= 0) {
    // error handling
}
auto uint_currLen = static_cast<size_t>(currLen);
if (uint_currLen > (MAX_BUFFER_SIZE - cur_pos)) {
    MSPTI_LOGE("Read invalid data len [%zu] from driver", uint_currLen);
    break;
}
size_t last_pos = TransDataToActivityBuffer(buf, cur_pos + uint_currLen, deviceId_, channelId_);
if (last_pos < cur_pos + uint_currLen) {
    if (memcpy_s(buf, MAX_BUFFER_SIZE, buf + last_pos, cur_pos + uint_currLen - last_pos) != EOK) {
        // ...
    }
}
```

**达成路径**

ProfChannelRead -> currLen (int, tainted) -> uint_currLen (size_t) -> cur_pos + uint_currLen (potential overflow) -> memcpy_s(..., cur_pos + uint_currLen - last_pos) (potential underflow)

**验证说明**: currLen为int类型，cur_pos + uint_currLen可能溢出。但已有边界检查uint_currLen > (MAX_BUFFER_SIZE - cur_pos)防止溢出。依赖驱动返回值合理。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-CHANNEL-004] Memory Corruption - ChannelReader::TransStarsLog

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-119 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: c-cpp-taint-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/channel_reader.cpp:144-158` @ `ChannelReader::TransStarsLog`
**模块**: csrc/activity/ascend/channel

**描述**: TransStarsLog has a potential infinite loop or unbounded memory access. The while loop condition checks valid_size - pos >= logStructSize, but inside SocLogConvert::TransData (basic_convert.h:71), pos is incremented by structSize regardless of parse success. If parsing fails (returns false), the loop in TransStarsLog continues without proper handling, and the inner TransData increments pos anyway, potentially skipping over malformed data or causing uncontrolled buffer advancement.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/channel_reader.cpp:144-158`)

```c
size_t ChannelReader::TransStarsLog(char buffer[], size_t valid_size, uint32_t deviceId)
{
    size_t pos = 0;
    HalLogData logData;
    static size_t logStructSize = Convert::SocLogConvert::GetInstance().GetStructSize(deviceId, Common::ContextManager::GetInstance()->GetChipType(deviceId));
    while (valid_size - pos >= logStructSize) {
        Convert::SocLogConvert::GetInstance().TransData(buffer, valid_size, deviceId, pos, logData);
        if (Mspti::Parser::DeviceTaskCalculator::GetInstance().ReportStarsSocLog(deviceId, logData) != MSPTI_SUCCESS) {
            MSPTI_LOGE("DeviceTaskCalculator parse SocLog failed");
        }
        // No pos increment here - relies on TransData to increment
    }
    return pos;
}
```

**达成路径**

ProfChannelRead -> buffer -> TransStarsLog -> SocLogConvert::TransData (basic_convert.h:62-73) -> pos += structSize (unconditionally) -> potential skip/over-read of malicious data

**验证说明**: TransStarsLog循环处理外部驱动数据，SocLogConvert::TransData无条件增加pos。解析失败时pos仍增加，可能跳过恶意数据或导致处理问题。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-CHANNEL-005] Buffer Over-read - ChannelPool::Run

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-125 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: c-cpp-taint-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/channel_pool.cpp:107-127` @ `ChannelPool::Run`
**模块**: csrc/activity/ascend/channel

**描述**: ProfChannelPoll returns device/channel info from driver into channels array. While ret is bounds-checked against CHANNEL_POOL_NUM, the channels[ii].deviceId and channels[ii].channelId values are used directly without validation. Malicious driver could provide invalid device IDs leading to unauthorized access or out-of-bounds map lookups.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/channel_pool.cpp:107-127`)

```c
int ret = ProfChannelPoll(channels, CHANNEL_POOL_NUM, DEFAULT_TIMEOUT_SEC);
if (ret == CHANNEL_PROF_ERROR || ret == CHANNEL_PROF_STOPPED_ALREADY) {
    // error handling
}
if (ret < 0 || ret > CHANNEL_POOL_NUM) {
    MSPTI_LOGE("Ret is out of range, CHANNEL_POOL_NUM=%d, ret=%d", CHANNEL_POOL_NUM, ret);
    break;
}
for (int ii = 0; ii < ret; ++ii) {
    DispatchChannel(channels[ii].deviceId, static_cast<AI_DRV_CHANNEL>(channels[ii].channelId));
}
```

**达成路径**

ProfChannelPoll(channels, CHANNEL_POOL_NUM, DEFAULT_TIMEOUT_SEC) -> channels[ii].deviceId, channels[ii].channelId (tainted from driver) -> DispatchChannel(devId, channelId) -> GetChannelIndex -> readers_map_[channel_index] (potential invalid access)

**验证说明**: ProfChannelPoll返回的设备/通道信息直接使用无验证。恶意驱动可能提供无效设备ID导致map查找失败。依赖驱动可信。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-CHANNEL-007] Memory Corruption - BasicConvert::TransData

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-119 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: c-cpp-taint-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/basic_convert.h:62-73` @ `BasicConvert::TransData`
**模块**: csrc/activity/ascend/channel

**描述**: In basic_convert.h TransData, the structSize used for buffer pointer arithmetic is obtained from GetStructSize which depends on chipType. If chipType is determined incorrectly (potentially from external context), wrong struct sizes could cause buffer over-read when parsing. The function at line 70 casts buffer + pos to struct without checking remaining buffer size before the cast.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/basic_convert.h:62-73`)

```c
bool TransData(const char buffer[], size_t valid_size, uint32_t deviceId, size_t& pos, T& t)
{
    auto chipType = Common::ContextManager::GetInstance()->GetChipType(deviceId);
    auto parseFunc = this->GetTransFunc(deviceId, chipType);
    size_t structSize = this->GetStructSize(deviceId, chipType);
    if (parseFunc == nullptr || structSize == INVALID_STRUCT_SIZE) {
        return false;
    }
    auto ans = parseFunc(buffer + pos, t);  // No check if buffer + pos + structSize <= buffer + valid_size
    pos += structSize;
    return ans;
}
```

**达成路径**

GetChipType(deviceId) -> chipType -> GetStructSize(chipType) -> structSize -> parseFunc(buffer + pos, t) where buffer + pos may not have structSize bytes remaining

**验证说明**: BasicConvert::TransData使用structSize处理缓冲区，structSize依赖chipType。chipType错误可能导致越界读取。但chipType来自ContextManager，非攻击者可控。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-CHANNEL-008] Buffer Overflow - ChannelReader::Execute

**严重性**: Low（原评估: high → 验证后: Low） | **CWE**: CWE-120 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: c-cpp-taint-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/channel_reader.cpp:97-103` @ `ChannelReader::Execute`
**模块**: csrc/activity/ascend/channel

**描述**: memcpy_s at line 99 copies remaining buffer data. While memcpy_s is a safe function, the source and destination overlap (buf and buf + last_pos). The size calculation cur_pos + uint_currLen - last_pos could underflow if TransDataToActivityBuffer returns a position larger than the current data end, causing large memory copies. The check last_pos < cur_pos + uint_currLen prevents some cases but not all edge cases.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/activity/ascend/channel/channel_reader.cpp:97-103`)

```c
size_t last_pos = TransDataToActivityBuffer(buf, cur_pos + uint_currLen, deviceId_, channelId_);
if (last_pos < cur_pos + uint_currLen) {
    if (memcpy_s(buf, MAX_BUFFER_SIZE, buf + last_pos, cur_pos + uint_currLen - last_pos) != EOK) {
        MSPTI_LOGE("memcpy channel buff data failed, deviceId=%u, channelId=%d, totalSize=%lu", deviceId_, channelId_, totalSize_);
        break;
    }
}
totalSize_ += static_cast<uint64_t>(currLen);
```

**达成路径**

TransDataToActivityBuffer returns last_pos -> memcpy_s(buf, MAX_BUFFER_SIZE, buf + last_pos, cur_pos + uint_currLen - last_pos) -> overlapping copy with size from tainted arithmetic

**验证说明**: memcpy_s复制缓冲区数据，源和目的重叠。size计算cur_pos + uint_currLen - last_pos可能下溢。但已有检查last_pos < cur_pos + uint_currLen防止下溢。memcpy_s是安全函数。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: -10 | reachability: 20

---

### [MSPTI-008] Unbounded String Pass-Through - Mspti::Adapter::Mstx::EnableDomain

**严重性**: Low（原评估: low → 验证后: Low） | **CWE**: CWE-120 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/init.cpp:96-105` @ `Mspti::Adapter::Mstx::EnableDomain`
**模块**: mspti/csrc

**描述**: Domain name string from Python is passed directly to msptiActivityEnableMarkerDomain without length validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/csrc/init.cpp:96-105`)

```c
const char* domainName passed without length check
```

**达成路径**

PyArg_ParseTuple(args, s, domainName) -> EnableDomain(domainName) -> msptiActivityEnableMarkerDomain(domain)

**验证说明**: domain_name字符串直接传递给C模块无长度验证。但domain_name用于内部标记域查找，非关键安全参数。依赖用户输入可信。

**评分明细**: base: 30 | context: -5 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-DF-002] Input Validation - enable_domain, disable_domain

**严重性**: Low（原评估: low → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/monitor/mstx_monitor.py:68-78` @ `enable_domain, disable_domain`
**模块**: mspti.monitor.mstx_monitor

**描述**: Insufficient input validation for domain_name parameter. The enable_domain and disable_domain methods only validate that domain_name is a non-empty string, but do not validate character set, length limits, or potential injection patterns. This data flows directly to the C module which parses it as a C string.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/monitor/mstx_monitor.py:68-78`)

```c
def enable_domain(self, domain_name: str):
    if isinstance(domain_name, str) and len(domain_name) != 0:
        return _mstx_enable_domain(domain_name)
    print_error_msg(f\"domain_name must be a string\")
    return MsptiResult.MSPTI_ERROR_INVALID_PARAMETER

def disable_domain(self, domain_name: str):
    if isinstance(domain_name, str) and len(domain_name) != 0:
        return _mstx_disable_domain(domain_name)
```

**达成路径**

[{"source": "domain_name (user input)", "line": 68, "type": "user_input"}, {"validation": "isinstance(domain_name, str) and len(domain_name) != 0", "line": 69, "type": "insufficient_validation"}, {"sink": "_mstx_enable_domain(domain_name)", "line": 70, "type": "c_module_sink"}, {"source": "domain_name (user input)", "line": 74, "type": "user_input"}, {"validation": "isinstance(domain_name, str) and len(domain_name) != 0", "line": 75, "type": "insufficient_validation"}, {"sink": "_mstx_disable_domain(domain_name)", "line": 76, "type": "c_module_sink"}]

**验证说明**: enable_domain/disable_domain仅验证domain_name非空字符串，无字符集或长度限制。但domain_name用于内部标记域查找，非关键安全参数。

**评分明细**: base: 30 | context: -5 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-DF-004] Data Injection - KernelData.__init__

**严重性**: Low（原评估: low → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/activity_data.py:36-52` @ `KernelData.__init__`
**模块**: mspti.activity_data

**描述**: Unvalidated data from C callbacks flows directly into data objects without type checking or sanitization. The origin_data dict comes from the C profiling layer and is used with .get() methods but without validating types or constraints. Malformed data could propagate to user callbacks.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/activity_data.py:36-52`)

```c
def __init__(self, origin_data: dict):
    self.kind: MsptiActivityKind = MsptiActivityKind(origin_data.get(self.KIND, 0))
    self.start: int = origin_data.get(self.START, 0)
    self.end: int = origin_data.get(self.END, 0)
    self.device_id: int = origin_data.get(self.DEVICE_ID, 0)
    self.stream_id: int = origin_data.get(self.STREAM_ID, 0)
    self.correlation_id: int = origin_data.get(self.CORRELATION_ID, 0)
    self.type: str = origin_data.get(self.TYPE, "")
    self.name: str = origin_data.get(self.NAME, "")
```

**达成路径**

[{"source": "origin_data (C callback)", "line": 36, "type": "external_data_source"}, {"sink": "MsptiActivityKind(origin_data.get(...))", "line": 38, "type": "enum_conversion_without_validation"}, {"sink": "origin_data.get(self.START, 0)", "line": 40, "type": "direct_use_without_type_check"}, {"sink": "origin_data.get(self.NAME, "")", "line": 52, "type": "string_without_sanitization"}]

**验证说明**: KernelData从C回调数据构造，无类型检查。但数据来自可信的profiling层，非攻击者可控。

**评分明细**: base: 30 | context: -5 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-DF-005] Data Injection - callback

**严重性**: Low（原评估: low → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/monitor/kernel_monitor.py:53-58` @ `callback`
**模块**: mspti.monitor.kernel_monitor

**描述**: Data from C profiling callbacks flows through to user callbacks without validation. The origin_data dict from the C layer is passed directly to KernelData constructor and then to user callbacks. While Python type hints suggest structure, no runtime validation exists.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/monitor/kernel_monitor.py:53-58`)

```c
def callback(self, origin_data: dict):
    try:
        if callable(self.user_cb):
            self.user_cb(KernelData(origin_data))
    except Exception as ex:
        print_error_msg(f\"Call kernel callback failed. Exception: {str(ex)}\")
```

**达成路径**

[{"source": "origin_data (C module callback)", "line": 53, "type": "external_data"}, {"transform": "KernelData(origin_data)", "line": 56, "type": "data_transformation"}, {"sink": "self.user_cb(KernelData(origin_data))", "line": 56, "type": "user_callback_sink"}]

**验证说明**: kernel_monitor.py将C回调数据传递给用户回调无验证。数据来自可信profiling层。

**评分明细**: base: 30 | context: -5 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-DF-006] Data Injection - callback

**严重性**: Low（原评估: low → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/monitor/hccl_monitor.py:53-58` @ `callback`
**模块**: mspti.monitor.hccl_monitor

**描述**: Data from C profiling callbacks flows through to user callbacks without validation. The origin_data dict from the C layer is passed directly to HcclData constructor and then to user callbacks. Similar to kernel_monitor, no runtime validation exists.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/monitor/hccl_monitor.py:53-58`)

```c
def callback(self, origin_data: dict):
    try:
        if callable(self.user_cb):
            self.user_cb(HcclData(origin_data))
    except Exception as ex:
        print_error_msg(f\"Call hccl callback failed. Exception: {str(ex)}\")
```

**达成路径**

[{"source": "origin_data (C module callback)", "line": 53, "type": "external_data"}, {"transform": "HcclData(origin_data)", "line": 56, "type": "data_transformation"}, {"sink": "self.user_cb(HcclData(origin_data))", "line": 56, "type": "user_callback_sink"}]

**验证说明**: hccl_monitor.py将C回调数据传递给用户回调无验证。数据来自可信profiling层。

**评分明细**: base: 30 | context: -5 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [MSPTI-DF-007] Data Injection - callback

**严重性**: Low（原评估: low → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/monitor/mstx_monitor.py:80-84` @ `callback`
**模块**: mspti.monitor.mstx_monitor

**描述**: Data from C profiling callbacks flows through to user callbacks without validation. The origin_data dict is used to construct MarkerData objects and passed to user callbacks. No sanitization of name, domain, or other string fields.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/mspti/monitor/mstx_monitor.py:80-84`)

```c
def callback(self, origin_data: dict):
    try:
        self._append_data(MarkerData(origin_data))
    except Exception as ex:
        print_error_msg(f\"Call mstx callback failed. Exception: {str(ex)}\")
```

**达成路径**

[{"source": "origin_data (C module callback)", "line": 80, "type": "external_data"}, {"transform": "MarkerData(origin_data)", "line": 82, "type": "data_transformation"}, {"transform": "_append_data(MarkerData)", "line": 82, "type": "internal_processing"}, {"sink": "self.mark_user_cb(mark_data)", "line": 103, "type": "user_callback_sink"}, {"sink": "self.range_user_cb(range_mark_data)", "line": 115, "type": "user_callback_sink"}]

**验证说明**: mstx_monitor.py将C回调数据传递给用户回调无验证。数据来自可信profiling层。

**评分明细**: base: 30 | context: -5 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| csrc/activity/activity_manager.cpp | 0 | 1 | 1 | 1 | 3 |
| csrc/activity/ascend/channel | 0 | 0 | 2 | 5 | 7 |
| csrc/activity/ascend/channel/channel_reader.cpp | 0 | 0 | 0 | 2 | 2 |
| csrc/activity/ascend/parser/cann_api_parser.cpp | 0 | 0 | 0 | 1 | 1 |
| csrc/activity/ascend/parser/hccl_calculator.cpp | 0 | 0 | 1 | 0 | 1 |
| csrc/activity/ascend/parser/kernel_parser.cpp | 0 | 0 | 0 | 1 | 1 |
| csrc/activity/ascend/parser/mstx_parser.cpp | 0 | 0 | 0 | 1 | 1 |
| csrc/activity/ascend/parser/parser_manager.cpp | 0 | 0 | 0 | 1 | 1 |
| csrc/callback | 0 | 1 | 3 | 0 | 4 |
| csrc/common | 0 | 0 | 2 | 4 | 6 |
| csrc/common/inject | 0 | 1 | 2 | 0 | 3 |
| mspti.activity_data | 0 | 0 | 0 | 1 | 1 |
| mspti.monitor._mspti_c | 0 | 0 | 0 | 1 | 1 |
| mspti.monitor.hccl_monitor | 0 | 0 | 0 | 1 | 1 |
| mspti.monitor.kernel_monitor | 0 | 0 | 0 | 1 | 1 |
| mspti.monitor.mstx_monitor | 0 | 0 | 0 | 3 | 3 |
| mspti/csrc | 0 | 1 | 3 | 8 | 12 |
| **合计** | **0** | **4** | **14** | **31** | **49** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-829 | 16 | 32.7% |
| CWE-119 | 8 | 16.3% |
| CWE-20 | 6 | 12.2% |
| CWE-120 | 5 | 10.2% |
| CWE-22 | 3 | 6.1% |
| CWE-843 | 2 | 4.1% |
| CWE-426 | 2 | 4.1% |
| CWE-125 | 2 | 4.1% |
| CWE-94 | 1 | 2.0% |
| CWE-78 | 1 | 2.0% |
| CWE-59 | 1 | 2.0% |
| CWE-427 | 1 | 2.0% |
| CWE-190 | 1 | 2.0% |
