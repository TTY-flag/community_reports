# 漏洞扫描报告 — 已确认漏洞

**项目**: MindStudio-Profiler-Tools-Interface  
**扫描时间**: 2026-04-21T09:21:42.727Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描针对 MindStudio-Profiler-Tools-Interface 项目（华为昇腾 NPU 性能分析工具接口）进行了全面的漏洞检测。项目包含 C++ 核心库和 Python 绑定，涉及动态库加载、回调机制、驱动数据读取等多个安全敏感模块。

### 关键发现

扫描共发现 **53 个候选漏洞**，经验证后确认 **3 个高危漏洞**（全部为 CONFIRMED 状态）：

| 严重性 | 数量 | 核心风险 |
|--------|------|----------|
| **Critical** | 2 | 库注入攻击 → 任意代码执行 |
| **High** | 1 | 未验证回调 → 代码执行 |

### 攻击路径分析

三个已确认漏洞形成**完整的攻击链**：

1. **入口点**: `ASCEND_HOME_PATH` 环境变量由用户/部署脚本控制
2. **攻击向量**: 攻击者设置 `ASCEND_HOME_PATH=/malicious/path`
3. **执行链**: `CanonicalSoPath()` → 构造恶意路径 → `dlopen()` 加载恶意 `.so` → **任意代码执行**
4. **横向渗透**: 恶意库加载后，所有 API Hook（aclrtSetDevice、HcclAllReduce 等）被劫持
5. **回调劫持**: `msptiSubscribe()` 接收未验证回调指针 → 直接执行

### 影响评估

- **资产风险**: 高危 — 攻击者可获取宿主机完整控制权
- **攻击复杂度**: 低 — 仅需控制环境变量（常见于容器/K8s 部署）
- **前置条件**: 攻击者需有环境变量控制能力（如容器配置权限、部署脚本注入）
- **影响范围**: 所有使用 MSPTI 的昇腾 NPU 应用

### 建议优先级

| 优先级 | 漏洞 ID | 修复难度 | 建议措施 |
|--------|---------|----------|----------|
| **P0** | VULN-SEC-LIB-001 | 中 | 硬编码库路径 + 环境变量白名单 |
| **P0** | VULN-DF-DATAFLOW-001 | 中 | 同上（同一根本原因） |
| **P1** | VULN-CALLBACK-001 | 低 | 添加回调签名验证 |

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
| Critical | 2 | 66.7% |
| High | 1 | 33.3% |
| **有效漏洞总计** | **3** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-LIB-001]** library_injection (Critical) - `csrc/common/function_loader.cpp:58` @ `CanonicalSoPath` | 置信度: 85
2. **[VULN-DF-DATAFLOW-001]** tainted_data_to_sensitive_sink (Critical) - `csrc/common/function_loader.cpp:58` @ `CanonicalSoPath,Get` | 置信度: 85
3. **[VULN-CALLBACK-001]** Untrusted Callback Execution (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/callback/callback_manager.cpp:104` @ `CallbackManager::Init, CallbackManager::ExecuteCallback` | 置信度: 85

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

## 3. Critical 漏洞 (2)

### [VULN-SEC-LIB-001] library_injection - CanonicalSoPath

**严重性**: Critical | **CWE**: CWE-426 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `csrc/common/function_loader.cpp:58-74` @ `CanonicalSoPath`
**模块**: csrc/common

**描述**: Library injection via environment variable. The FunctionLoader::CanonicalSoPath() function uses std::getenv("ASCEND_HOME_PATH") to determine the library loading path. An attacker who can control this environment variable can redirect library loading to a malicious path, potentially executing arbitrary code when dlopen() is called. The whitelist check for library names is insufficient because the path itself is attacker-controlled.

**漏洞代码** (`csrc/common/function_loader.cpp:58-74`)

```c
char *ascendHomePath = std::getenv("ASCEND_HOME_PATH");
if (ascendHomePath == nullptr || ascendHomePath[0] == '\0') {
    return soName_;
}
auto soPath = std::string(ascendHomePath) + "/lib64/" + soName_;
auto canonicalPath = Utils::RealPath(Utils::RelativeToAbsPath(soPath));
return Utils::FileExist(canonicalPath) && Utils::FileReadable(canonicalPath) ? canonicalPath : soName_;
...
auto handle = dlopen(soPath.c_str(), RTLD_LAZY);
```

**达成路径**

ASCEND_HOME_PATH (environment) → CanonicalSoPath() → soPath → dlopen() → code execution

**验证说明**: ASCEND_HOME_PATH环境变量直接控制dlopen加载路径。库名称白名单限制库文件名但不阻止路径注入。RealPath跟随符号链接。CheckCharValid从未被调用无法过滤危险字符。攻击者可完全控制库加载路径执行任意代码。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-DATAFLOW-001] tainted_data_to_sensitive_sink - CanonicalSoPath,Get

**严重性**: Critical | **CWE**: CWE-99 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `csrc/common/function_loader.cpp:58-74` @ `CanonicalSoPath,Get`
**模块**: csrc/common

**描述**: Complete data flow from tainted source to sensitive sink. Environment variable ASCEND_HOME_PATH flows through multiple functions to dlopen() without sufficient validation. Data flow: 1) getenv(ASCEND_HOME_PATH) reads tainted environment variable [function_loader.cpp:58], 2) String concatenation creates path [line 62], 3) RelativeToAbsPath() adds current directory [utils.cpp:106-119], 4) RealPath() resolves the path [utils.cpp:94-104], 5) FileExist() and FileReadable() check access [utils.cpp:121-135], 6) dlopen() loads the library [function_loader.cpp:74]. The only validation is a library name whitelist which does NOT validate the path. CheckCharValid() exists but is NEVER called.

**漏洞代码** (`csrc/common/function_loader.cpp:58-74`)

```c
// SOURCE: Tainted environment variable
char *ascendHomePath = std::getenv(ASCEND_HOME_PATH);  // LINE 58

// PROPAGATION: String concatenation without validation
auto soPath = std::string(ascendHomePath) + /lib64/ + soName_;  // LINE 62

// PROPAGATION: Path manipulation functions (no validation)
auto canonicalPath = Utils::RealPath(Utils::RelativeToAbsPath(soPath));  // LINE 63

// SINK: Library loading
auto handle = dlopen(soPath.c_str(), RTLD_LAZY);  // LINE 74
```

**达成路径**

getenv(ASCEND_HOME_PATH) -> std::string concatenation -> RelativeToAbsPath() -> RealPath() -> FileExist()/FileReadable() -> dlopen() -> ARBITRARY CODE EXECUTION

**验证说明**: 完整数据流从getenv(ASCEND_HOME_PATH)到dlopen()。唯一验证是库名称白名单，不验证路径。CheckCharValid存在但从未调用。路径完全可控。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. High 漏洞 (1)

### [VULN-CALLBACK-001] Untrusted Callback Execution - CallbackManager::Init, CallbackManager::ExecuteCallback

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-829 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/callback/callback_manager.cpp:104-227` @ `CallbackManager::Init, CallbackManager::ExecuteCallback`
**模块**: csrc/callback

**描述**: User-provided callback function pointer is stored and executed without validation. The msptiSubscribe() API accepts a callback function pointer that is stored directly in subscriber_ptr_->handle without any address validation, signature verification, or integrity checks. This callback is later invoked directly in ExecuteCallback(), allowing potential arbitrary code execution if an attacker can control the callback pointer.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/csrc/callback/callback_manager.cpp:104-227`)

```c
// Line 104 - Untrusted callback stored without validation
subscriber_ptr_->handle = callback;

// Lines 222-228 - Direct invocation of user callback
if (subscriber_ptr_->handle) {
    MSPTI_LOGD("CallbackManager execute Callbackfunc, funcName is %s", funcName);
    msptiCallbackData callbackData;
    callbackData.callbackSite = site;
    callbackData.functionName = funcName;
    subscriber_ptr_->handle(subscriber_ptr_->userdata, domain, cbid, &callbackData);
}
```

**达成路径**

[{"source": "msptiSubscribe(msptiSubscriberHandle *subscriber, msptiCallbackFunc callback, void *userdata)", "line": 244, "type": "taint_source", "description": "User-provided callback enters system"}, {"flow": "CallbackManager::Init(subscriber, callback, userdata)", "line": 86, "type": "propagation", "description": "Callback passed to Init function"}, {"flow": "subscriber_ptr_->handle = callback", "line": 104, "type": "taint_store", "description": "Callback stored without validation"}, {"flow": "ExecuteCallback(domain, cbid, site, funcName)", "line": 213, "type": "propagation", "description": "Callback execution triggered"}, {"sink": "subscriber_ptr_->handle(subscriber_ptr_->userdata, domain, cbid, &callbackData)", "line": 227, "type": "taint_sink", "description": "User callback invoked directly without pre-validation"}]

**验证说明**: msptiSubscribe()接收用户回调函数指针，直接存储并执行。仅检查null，无地址验证签名验证白名单验证。攻击者可执行任意代码地址。

**评分明细**: base: 30 | context: 0 | controllability: 25 | cross_file: 0 | mitigations: 0 | reachability: 20

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| csrc/callback | 0 | 1 | 0 | 0 | 1 |
| csrc/common | 2 | 0 | 0 | 0 | 2 |
| **合计** | **2** | **1** | **0** | **0** | **3** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-99 | 1 | 33.3% |
| CWE-829 | 1 | 33.3% |
| CWE-426 | 1 | 33.3% |

---

## 7. 漏洞深度分析

### 7.1 [VULN-SEC-LIB-001] 库注入漏洞深度分析

#### 根本原因

`FunctionLoader::CanonicalSoPath()` 函数的设计缺陷：

```cpp
// function_loader.cpp:58-64
char *ascendHomePath = std::getenv("ASCEND_HOME_PATH");  // 直接读取环境变量
if (ascendHomePath == nullptr || ascendHomePath[0] == '\0') {
    return soName_;  // 回退到系统搜索路径（LD_LIBRARY_PATH）
}
auto soPath = std::string(ascendHomePath) + "/lib64/" + soName_;  // 拼接路径
auto canonicalPath = Utils::RealPath(Utils::RelativeToAbsPath(soPath));
return Utils::FileExist(canonicalPath) && Utils::FileReadable(canonicalPath) ? canonicalPath : soName_;
```

**问题点分析**:

1. **无输入验证**: `CheckCharValid()` 函数存在于 `utils.cpp` 但从未被调用
2. **白名单失效**: `soNameList` 白名单仅限制库名（如 `libascendcl.so`），不限制路径
3. **符号链接跟随**: `RealPath()` 调用 `realpath()` 会跟随符号链接
4. **回退机制危险**: 环境变量无效时回退到 `soName_`，依赖 `LD_LIBRARY_PATH`

#### 实际攻击场景

**场景一: 容器部署环境**

```bash
# 攻击者在容器配置中注入
export ASCEND_HOME_PATH=/tmp/malicious
# 创建恶意库
mkdir -p /tmp/malicious/lib64
cp malicious_libascendcl.so /tmp/malicious/lib64/libascendcl.so
# 当应用调用 aclrtSetDevice() 时
# → RegisterFunction("libascendcl", "aclrtSetDevice")
# → CanonicalSoPath() 返回 /tmp/malicious/lib64/libascendcl.so
# → dlopen() 加载恶意库 → 任意代码执行
```

**场景二: 符号链接攻击**

```bash
# 假设攻击者有 ASCEND_HOME_PATH 目录写入权限
export ASCEND_HOME_PATH=/usr/local/Ascend
ln -s /tmp/malicious/lib.so /usr/local/Ascend/lib64/libascendcl.so
# RealPath() 解析符号链接但不会阻止加载
```

#### 影响范围分析

从 `function_loader.cpp` 可见，以下关键库均通过此机制加载：

| 库名 | 加载函数 | 安全影响 |
|------|----------|----------|
| `libascendcl.so` | ACL API（aclrtSetDevice, aclrtLaunchKernel） | NPU 计算劫持 |
| `libhccl.so` | HCCL API（HcclAllReduce, HcclBroadcast） | 集合通信劫持 |
| `libascend_hal.so` | 驱动接口（ProfChannelRead） | 性能数据泄露 |
| `libprofapi.so` | 性能分析接口 | 分析数据篡改 |

---

### 7.2 [VULN-DF-DATAFLOW-001] 数据流漏洞深度分析

此漏洞与 VULN-SEC-LIB-001 共享同一根本原因，但提供了完整的数据流追踪证据。

#### 数据流追踪

```
┌─────────────────────────────────────────────────────────────────┐
│                     污点源 (Taint Source)                        │
│  getenv("ASCEND_HOME_PATH") @ function_loader.cpp:58            │
│  → 返回外部可控的环境变量值                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     传播节点 (Propagation)                       │
│  std::string(ascendHomePath) + "/lib64/" + soName_              │
│  @ function_loader.cpp:62                                        │
│  → 无验证的字符串拼接                                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     传播节点 (Propagation)                       │
│  Utils::RelativeToAbsPath(soPath) @ utils.cpp:106-119           │
│  → 将相对路径转为绝对路径，无路径遍历检查                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     传播节点 (Propagation)                       │
│  Utils::RealPath() @ utils.cpp:94-104                           │
│  → realpath() 调用，跟随符号链接                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     弱验证 (Weak Check)                          │
│  Utils::FileExist() && Utils::FileReadable()                    │
│  @ utils.cpp:121-135                                             │
│  → 仅检查文件存在性和可读性，不检查路径合法性                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     敏感汇点 (Sensitive Sink)                    │
│  dlopen(soPath.c_str(), RTLD_LAZY) @ function_loader.cpp:74     │
│  → 加载动态库，执行任意代码                                       │
└─────────────────────────────────────────────────────────────────┘
```

#### 未使用的安全函数

代码中存在 `CheckCharValid()` 函数（定义于 `utils.cpp`）用于过滤危险字符，但在库加载路径中从未被调用：

```cpp
// utils.cpp 中存在但未使用的安全函数
bool Utils::CheckCharValid(const std::string& str) {
    // 定义了过滤 shell 元字符的逻辑
    // 但 CanonicalSoPath() 中从未调用此函数
}
```

---

### 7.3 [VULN-CALLBACK-001] 回调验证缺失深度分析

#### 代码分析

从 `callback_manager.cpp` 可见完整的回调注册和执行流程：

```cpp
// callback_manager.cpp:86-114 - Init 函数
msptiResult CallbackManager::Init(msptiSubscriberHandle *subscriber, 
                                   msptiCallbackFunc callback, void* userdata) {
    // ... 参数检查
    subscriber_ptr_->handle = callback;      // Line 104: 直接存储，无验证
    subscriber_ptr_->userdata = userdata;    // Line 105: 同样无验证
    *subscriber = subscriber_ptr_.get();
    init_.store(true);
    // ...
}

// callback_manager.cpp:213-228 - ExecuteCallback 函数
void CallbackManager::ExecuteCallback(msptiCallbackDomain domain,
    msptiCallbackId cbid, msptiApiCallbackSite site, const char* funcName) {
    if (!init_.load()) { return; }
    if (!IsCallbackIdEnable(domain, cbid)) { return; }
    if (subscriber_ptr_->handle) {           // Line 222: 仅检查非空
        MSPTI_LOGD("CallbackManager execute Callbackfunc, funcName is %s", funcName);
        msptiCallbackData callbackData;
        callbackData.callbackSite = site;
        callbackData.functionName = funcName;
        subscriber_ptr_->handle(subscriber_ptr_->userdata, domain, cbid, &callbackData);
        // Line 227: 直接调用，无地址验证、签名验证
    }
}
```

#### API 入口点分析

```cpp
// callback_manager.cpp:244-247
msptiResult msptiSubscribe(msptiSubscriberHandle *subscriber, 
                           msptiCallbackFunc callback, void *userdata) {
    return Mspti::Callback::CallbackManager::GetInstance()->Init(subscriber, callback, userdata);
}
```

`msptiSubscribe()` 作为公共 API，接受任意函数指针：

```cpp
typedef void (*msptiCallbackFunc)(void *userdata, 
                                   msptiCallbackDomain domain, 
                                   msptiCallbackId cbid, 
                                   const msptiCallbackData *callbackData);
```

#### 攻击场景

**场景一: 恶意回调注入**

```cpp
// 恶意代码
void malicious_callback(void *userdata, msptiCallbackDomain domain, 
                        msptiCallbackId cbid, const msptiCallbackData *data) {
    // 在每次 ACL API 调用时执行恶意代码
    // 可窃取性能数据、修改计算结果、注入攻击代码
}

msptiSubscriberHandle subscriber;
msptiSubscribe(&subscriber, malicious_callback, nullptr);
msptiEnableDomain(1, subscriber, MSPTI_CB_DOMAIN_RUNTIME);
// 之后每次 aclrtSetDevice、aclrtLaunchKernel 都会触发恶意回调
```

**场景二: CallbackScope 自动触发**

```cpp
// callback_manager.h:72-93
class CallbackScope {
    // 在构造/析构时自动调用 ExecuteCallback
    // 所有 ACL/HCCL API 使用此 RAII 包装
};
```

攻击者注册恶意回调后，**所有 API 调用自动被劫持**。

#### 与库注入漏洞的关联

两个漏洞形成组合攻击：

1. 通过库注入替换 `libascendcl.so`
2. 替换库内部修改回调逻辑
3. 或直接通过回调机制注入恶意代码

---

## 8. 修复建议

### 8.1 库注入漏洞修复 (VULN-SEC-LIB-001, VULN-DF-DATAFLOW-001)

#### 推荐方案: 硬编码路径 + 白名单验证

```cpp
// 修复后的 CanonicalSoPath 实现
std::string FunctionLoader::CanonicalSoPath() {
    // 1. 硬编码允许的安装路径列表
    static const std::vector<std::string> allowedPaths = {
        "/usr/local/Ascend",
        "/opt/Ascend",
        "/home/ascend"  // 可配置但固定
    };
    
    // 2. 白名单验证库名
    static const std::set<std::string> soNameList = {
        "libascend_hal.so", "libascendalog.so", 
        "libascendcl.so", "libhccl.so", "libprofapi.so"
    };
    
    if (soNameList.find(soName_) == soNameList.end()) {
        return "";  // 拒绝未知库
    }
    
    // 3. 优先使用硬编码路径
    for (const auto& basePath : allowedPaths) {
        std::string soPath = basePath + "/lib64/" + soName_;
        if (Utils::FileExist(soPath)) {
            // 4. 调用 CheckCharValid 验证路径字符
            if (!Utils::CheckCharValid(soPath)) {
                continue;
            }
            // 5. 使用 lstat 而非 realpath 避免跟随符号链接
            struct stat st;
            if (lstat(soPath.c_str(), &st) == 0 && !S_ISLNK(st.st_mode)) {
                return soPath;
            }
        }
    }
    
    // 6. 禁止回退到系统路径
    return "";  // 找不到则失败，不回退
}
```

#### 配置文件方案

创建 `/etc/mspti/config.json`：

```json
{
    "allowed_library_paths": [
        "/usr/local/Ascend/lib64",
        "/opt/Ascend/lib64"
    ],
    "allowed_libraries": [
        "libascendcl.so",
        "libhccl.so",
        "libascend_hal.so",
        "libprofapi.so"
    ],
    "checksum_verification": true
}
```

#### 部署建议

- 移除对 `ASCEND_HOME_PATH` 环境变量的依赖
- 使用配置文件或硬编码路径
- 对关键库文件进行 SHA256 校验
- 禁止 `LD_LIBRARY_PATH` 回退机制

---

### 8.2 回调验证漏洞修复 (VULN-CALLBACK-001)

#### 推荐方案: 回调签名验证 + 地址范围检查

```cpp
// callback_manager.cpp 修复
msptiResult CallbackManager::Init(msptiSubscriberHandle *subscriber, 
                                   msptiCallbackFunc callback, void* userdata) {
    if (subscriber == nullptr || callback == nullptr) {
        return MSPTI_ERROR_INVALID_PARAMETER;
    }
    
    // 1. 检查回调地址是否在合法代码段
    if (!IsValidCodeAddress(callback)) {
        MSPTI_LOGE("Callback address validation failed.");
        return MSPTI_ERROR_INVALID_CALLBACK;
    }
    
    // 2. 检查回调签名（通过函数指针类型）
    // 使用 ABI 检查或注册机制
    
    subscriber_ptr_->handle = callback;
    subscriber_ptr_->userdata = userdata;
    *subscriber = subscriber_ptr_.get();
    init_.store(true);
    return MSPTI_SUCCESS;
}

// 新增地址验证函数
bool IsValidCodeAddress(void* addr) {
    // 检查地址是否在可执行内存区域
    // 可通过 /proc/self/maps 解析
    Dl_info info;
    if (dladdr(addr, &info) == 0) {
        return false;  // 无法解析地址信息
    }
    
    // 检查是否来自可信库
    static const std::set<std::string> trustedLibs = {
        "libmspti.so", "libascendcl.so", "libc.so"
    };
    
    std::string libPath = info.dli_fname;
    // 检查是否在可信库列表或应用主程序
    for (const auto& trusted : trustedLibs) {
        if (libPath.find(trusted) != std::string::npos) {
            return true;
        }
    }
    
    // 检查是否在主程序地址范围
    // ...
    return false;
}
```

#### 回调注册表方案

```cpp
// 使用回调注册表而非直接接收函数指针
class CallbackRegistry {
public:
    // 应用必须先注册回调类型
    template<typename Func>
    msptiResult RegisterCallbackType(const std::string& name, Func func) {
        // 验证函数签名
        // 存储到白名单
    }
    
    // msptiSubscribe 只接受已注册的回调名称
    msptiResult Subscribe(msptiSubscriberHandle *subscriber, 
                          const std::string& callbackName, 
                          void* userdata);
};
```

---

### 8.3 通用安全加固建议

#### 环境变量安全

1. 移除所有环境变量对安全敏感路径的控制
2. 使用配置文件替代环境变量
3. 对剩余的环境变量读取添加 `CheckCharValid()` 验证

#### 符号链接保护

```cpp
// 修改 RealPath 使用 lstat 检查符号链接
std::string Utils::SecureRealPath(const std::string& path) {
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) {
        return "";
    }
    if (S_ISLNK(st.st_mode)) {
        // 拒绝符号链接
        return "";
    }
    // 正常处理
    char realPath[PATH_MAX] = {0};
    if (realpath(path.c_str(), realPath) == nullptr) {
        return "";
    }
    return std::string(realPath);
}
```

#### 库完整性校验

```cpp
// 加载库前校验 SHA256
bool VerifyLibraryChecksum(const std::string& path) {
    static const std::map<std::string, std::string> expectedChecksums = {
        {"libascendcl.so", "sha256:abc123..."},
        {"libhccl.so", "sha256:def456..."},
        // ...
    };
    
    std::string checksum = ComputeSHA256(path);
    auto expected = expectedChecksums.find(GetBasename(path));
    if (expected == expectedChecksums.end()) {
        return false;
    }
    return checksum == expected->second;
}
```

---

## 9. 验证清单

修复完成后请执行以下验证：

### 库注入验证

```bash
# 测试环境变量注入是否被阻止
export ASCEND_HOME_PATH=/tmp/malicious
./test_app  # 应失败或使用默认路径

# 测试符号链接是否被阻止
ln -sf /tmp/malicious/lib.so /usr/local/Ascend/lib64/libascendcl.so
./test_app  # 应拒绝加载符号链接
```

### 回调验证测试

```cpp
// 测试恶意地址是否被拒绝
void* malicious_addr = (void*)0xdeadbeef;
msptiSubscriberHandle subscriber;
msptiResult ret = msptiSubscribe(&subscriber, (msptiCallbackFunc)malicious_addr, nullptr);
assert(ret == MSPTI_ERROR_INVALID_CALLBACK);
```

### 集成测试

```bash
# 运行完整测试套件
./run_security_tests.sh

# 检查 LSP 诊断无警告
clang-tidy --checks='security-*' csrc/**/*.cpp
```

---

**报告结束**

**生成时间**: 2026-04-21  
**扫描引擎**: Multi-Agent Vulnerability Scanner  
**报告版本**: v1.0
