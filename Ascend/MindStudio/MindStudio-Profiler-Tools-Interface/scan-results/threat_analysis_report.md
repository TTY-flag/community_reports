# MindStudio Profiler Tools Interface (MSPTI) 威胁分析报告

## 执行摘要

MSPTI 是华为昇腾平台的性能分析工具接口，用于采集 NPU 应用性能数据。本项目包含 C/C++ 核心实现和 Python 封装，通过 API Hooking、回调机制和驱动数据通道实现性能数据采集。

**关键发现：**
- **5个高风险攻击面**：动态库加载、用户回调执行、驱动数据输入、Python回调注册、环境变量控制
- **2个关键安全模块**：inject（API Hooking）和 channel（驱动数据读取）
- **主要威胁类型**：库注入、代码执行、数据篡改、环境变量操纵

---

## 1. 项目概述

| 属性 | 值 |
|------|-----|
| 项目名称 | MindStudio Profiler Tools Interface (MSPTI) |
| 语言组成 | C/C++ (82 cpp + 62 h) + Python (24 py) |
| 生产代码文件 | 108 个 |
| 排除目录 | test/, samples/ |
| 许可证 | Mulan PSL v2 |
| 功能 | NPU 性能分析数据采集 |

### 核心功能模块

| 模块 | 功能 | 风险等级 |
|------|------|----------|
| `inject` | API Hooking / 函数替换 | **Critical** |
| `channel` | 驱动数据读取与转换 | **Critical** |
| `callback` | 用户回调订阅与执行 | **High** |
| `activity` | 活动数据缓冲区管理 | **High** |
| `function_loader` | 动态库加载 (dlopen/dlsym) | **High** |
| `parser` | 性能数据解析 | **Medium** |
| `python_binding` | Python C 扩展 | **Medium** |
| `utils` | 通用工具函数 | **Low** |

---

## 2. 攻击面分析

### 2.1 外部输入攻击面

#### 2.1.1 驱动数据输入 (Critical)

**位置：** `csrc/activity/ascend/channel/channel_reader.cpp`

**入口函数：** `ChannelReader::Execute()`

**数据流：**
```
驱动 (ProfChannelRead) → ChannelReader → memcpy_s → TransDataToActivityBuffer → Parser
```

**威胁描述：**
- 驱动返回的 profiling 数据可能被恶意篡改
- `memcpy_s` 操作在 `Execute()` 函数中进行缓冲区数据复制
- 数据解析涉及复杂的结构体转换 (`TsTrackHead`, `HalLogData`)

**潜在漏洞：**
- 缓冲区溢出：驱动数据长度可能超过 `MAX_BUFFER_SIZE` (2MB)
- 数据解析错误：恶意构造的结构体数据可能导致解析器崩溃
- 内存越界访问：`reinterpret_cast` 强制类型转换可能访问无效内存

**相关代码：**
```cpp
// channel_reader.cpp:85
currLen = ProfChannelRead(deviceId_, channelId_, buf + cur_pos, MAX_BUFFER_SIZE - cur_pos);
// channel_reader.cpp:99
if (memcpy_s(buf, MAX_BUFFER_SIZE, buf + last_pos, cur_pos + uint_currLen - last_pos) != EOK) {
```

---

#### 2.1.2 动态库加载 (Critical)

**位置：** `csrc/common/function_loader.cpp`

**入口函数：** `FunctionLoader::Get()`, `CanonicalSoPath()`

**数据流：**
```
ASCEND_HOME_PATH (env) → CanonicalSoPath → dlopen → dlsym → Inject Functions
```

**威胁描述：**
- 环境变量 `ASCEND_HOME_PATH` 决定库加载路径
- 加载的库包括：`libascendcl.so`, `libhccl.so`, `libprofapi.so`, `libascend_hal.so`
- 攻击者可通过控制环境变量劫持库加载路径

**潜在漏洞：**
- **库注入**：恶意库替换原库，劫持所有 NPU API 调用
- **符号劫持**：`dlsym` 返回的函数指针可能被替换
- **路径遍历**：`CanonicalSoPath` 使用 `realpath` 但仍可能被符号链接攻击

**相关代码：**
```cpp
// function_loader.cpp:58-62
char *ascendHomePath = std::getenv("ASCEND_HOME_PATH");
if (ascendHomePath == nullptr || ascendHomePath[0] == '\0') {
    return soName_;
}
auto soPath = std::string(ascendHomePath) + "/lib64/" + soName_;
```

---

#### 2.1.3 环境变量控制 (High)

**位置：** `csrc/common/utils.cpp`

**函数：** `Utils::GetEnv()`

**威胁描述：**
- 多处使用 `std::getenv()` 获取环境变量
- 环境变量可被攻击者控制，影响程序行为

**潜在漏洞：**
- 环境变量注入可能导致库加载路径篡改
- 特殊字符注入可能导致日志注入或命令注入

---

### 2.2 用户交互攻击面

#### 2.2.1 用户回调执行 (Critical)

**位置：** `csrc/callback/callback_manager.cpp`, `csrc/activity/activity_manager.cpp`

**入口函数：**
- `msptiSubscribe()` - 注册回调
- `CallbackManager::ExecuteCallback()` - 执行回调
- `bufferRequested_handle_()` / `bufferCompleted_handle_()` - Activity缓冲区回调

**数据流：**
```
User Callback Registration → CallbackManager → subscriber_ptr_->handle() → Arbitrary Code Execution
```

**威胁描述：**
- 用户注册的回调函数在 API 调用前后执行
- 回调接收敏感数据：`msptiCallbackData` 包含 API 参数、返回值、correlationId
- Activity 缓冲区回调接收 profiling 数据

**潜在漏洞：**
- **任意代码执行**：恶意回调可在 profiling 上下文执行任意代码
- **数据泄露**：回调可访问所有 profiling 数据，包括内核参数、内存地址
- **权限提升**：回调在 NPU 应用进程内执行，可能提升攻击者权限

**相关代码：**
```cpp
// callback_manager.h:76-78
CallbackScope(msptiCallbackDomain domain, msptiCallbackId cbid, const char* funcName) {
    CallbackManager::GetInstance()->ExecuteCallback(domain, cbid, MSPTI_API_ENTER, func_name_);
}
// callback_manager.cpp (ExecuteCallback)
subscriber_ptr_->handle(subscriber_ptr_->userdata, domain, cbid, cbdata);
```

---

#### 2.2.2 Python 回调注册 (High)

**位置：** `mspti/csrc/init.cpp`, `mspti/csrc/mspti_adapter.cpp`

**入口函数：** `RegisterCB()`, `MsptiAdapter::RegisterMstxCallback()`

**数据流：**
```
Python Callback → PyArg_ParseTuple → Py_INCREF → Storage → Later Invocation
```

**威胁描述：**
- Python 用户可注册回调函数处理 profiling 数据
- 回调在 C++ 层存储，后续通过 Python C API 调用
- 支持三种回调类型：Mstx, Kernel, Hccl

**潜在漏洞：**
- **Python 代码注入**：恶意 Python 回调可执行任意 Python 代码
- **类型混淆**：`PyArg_ParseTuple` 参数解析可能存在类型检查漏洞
- **引用计数问题**：错误的 `Py_INCREF/Py_DECREF` 可能导致内存泄漏或崩溃

---

### 2.3 API Hooking 攻击面

#### 2.3.1 ACL API Hooking (Critical)

**位置：** `csrc/common/inject/acl_inject.cpp`

**Hooked 函数：**
- `aclrtSetDevice` / `aclrtResetDevice`
- `aclrtCreateContext` / `aclrtDestroyContext`
- `aclrtCreateStream` / `aclrtDestroyStream`
- `aclrtLaunchKernel` / `aclrtLaunchKernelV2` / `aclrtLaunchKernelWithConfig`
- `aclrtSynchronizeStream`

**威胁描述：**
- 所有 ACL API 调用被拦截并注入 profiling 逻辑
- Hook 使用 `dlsym` 获取原函数地址
- 每个调用触发 `CallbackScope` 执行用户回调

**潜在漏洞：**
- **API 参数篡改**：Hook 可修改 API 参数
- **返回值篡改**：Hook 可修改 API 返回值
- **函数指针劫持**：`dlsym` 失败时的 `THROW_FUNC_NOTFOUND` 可能导致异常

---

#### 2.3.2 HCCL API Hooking (Critical)

**位置：** `csrc/common/inject/hccl_inject.cpp`

**Hooked 函数：**
- `HcclAllReduce`, `HcclAllGather`, `HcclReduceScatter`
- `HcclBroadcast`, `HcclSend`, `HcclRecv`
- `HcclGroupStart`, `HcclGroupEnd`

**威胁描述：**
- HCCL 通信 API 被拦截，可能泄露通信数据
- 通信参数包含敏感信息：数据地址、大小、通信组

**潜在漏洞：**
- **通信数据泄露**：Hook 可访问所有 HCCL 通信参数
- **通信篡改**：恶意 Hook 可修改通信数据或参数

---

#### 2.3.3 MSTX Marker Hooking (High)

**位置：** `csrc/common/inject/mstx_inject.cpp`

**Hooked 函数：**
- `MstxMarkA` / `MstxRangeStartA` / `MstxRangeEnd`
- Domain 相关函数

**威胁描述：**
- MSTX 用于用户标记性能事件
- 包含用户提供的字符串消息

**潜在漏洞：**
- **字符串注入**：用户提供的消息字符串可能包含恶意内容
- **日志注入**：消息字符串直接记录到日志

---

---

## 3. 高风险模块详细分析

### 3.1 Inject 模块 (Critical)

**文件列表：**
- `acl_inject.cpp/h` - ACL API Hooking
- `hccl_inject.cpp/h` - HCCL API Hooking
- `mstx_inject.cpp/h` - MSTX Marker Hooking
- `driver_inject.cpp/h` - 驱动接口 Hooking
- `profapi_inject.cpp/h` - Profiling API Hooking
- `inject_base.h` - 共享数据结构

**风险因素：**
| 因素 | 描述 | 风险等级 |
|------|------|----------|
| 函数替换 | dlopen/dlsym 动态加载替换原函数 | Critical |
| 环境变量依赖 | ASCEND_HOME_PATH 控制库路径 | High |
| 回调触发 | 每次 API 调用触发用户回调 | High |
| 异常处理 | THROW_FUNC_NOTFOUND 可能抛出异常 | Medium |

**关键代码路径：**
```cpp
// acl_inject.cpp:52-87 - 函数加载
void LoadAclFunction() {
    g_aclrtFuncArray[FUNC_ACL_RT_SET_DEVICE] =
        Mspti::Common::RegisterFunction(SO_NAME, "aclrtSetDevice");
    // ... 其他函数
}

// acl_inject.cpp:90-102 - Hooked 函数
AclError aclrtSetDevice(int32_t deviceId) {
    pthread_once(&g_once, LoadAclFunction);
    // 获取原函数
    aclrtSetDeviceFunc func = Mspti::Common::ReinterpretConvert<decltype(&aclrtSetDevice)>(voidFunc);
    THROW_FUNC_NOTFOUND(func, __FUNCTION__, SO_FILE_NAME);
    // 触发回调
    Mspti::Callback::CallbackScope scope(MSPTI_CB_DOMAIN_RUNTIME, MSPTI_CBID_RUNTIME_DEVICE_SET, __FUNCTION__);
    return func(deviceId);
}
```

---

### 3.2 Channel 模块 (Critical)

**文件列表：**
- `channel_reader.cpp/h` - 驱动数据读取
- `channel_pool.cpp/h` - 管道池管理
- `channel_pool_manager.cpp/h` - 管道池管理器
- `tsfw_convert.cpp/h` - TS Firmware 数据转换
- `soclog_convert.cpp/h` - SOC 日志转换
- `stars_common.cpp/h` - STARS 共享代码

**风险因素：**
| 因素 | 描述 | 风险等级 |
|------|------|----------|
| 外部数据输入 | ProfChannelRead 从驱动读取数据 | Critical |
| 缓冲区操作 | memcpy_s 复制数据到缓冲区 | High |
| 结构体解析 | reinterpret_cast 强制转换结构体 | High |
| 大缓冲区 | MAX_BUFFER_SIZE = 2MB | Medium |

**关键代码路径：**
```cpp
// channel_reader.cpp:78-108 - 数据读取循环
msptiResult ChannelReader::Execute() {
    char buf[MAX_BUFFER_SIZE] = {0};
    while (isInited_ && !isChannelStopped_) {
        currLen = ProfChannelRead(deviceId_, channelId_, buf + cur_pos, MAX_BUFFER_SIZE - cur_pos);
        if (currLen <= 0) break;
        // memcpy_s 复制剩余数据
        if (memcpy_s(buf, MAX_BUFFER_SIZE, buf + last_pos, cur_pos + uint_currLen - last_pos) != EOK) {
            MSPTI_LOGE("memcpy channel buff data failed");
            break;
        }
    }
}

// channel_reader.cpp:129 - 结构体转换
TsTrackHead* tsHead = reinterpret_cast<TsTrackHead*>(buffer + pos);
```

---

### 3.3 Function Loader 模块 (High)

**文件列表：**
- `function_loader.cpp/h` - 动态库加载
- `utils.cpp/h` - 路径处理工具

**风险因素：**
| 因素 | 描述 | 风险等级 |
|------|------|----------|
| 环境变量 | ASCEND_HOME_PATH 控制库路径 | High |
| dlopen | 动态加载外部库 | Critical |
| dlsym | 动态获取函数地址 | High |
| 路径验证 | realpath, FileExist, FileReadable | Medium |

**关键代码路径：**
```cpp
// function_loader.cpp:45-65 - 库路径解析
std::string FunctionLoader::CanonicalSoPath() {
    static const std::set<std::string> soNameList = {
        "libascend_hal.so", "libascendalog.so", "libascendcl.so", "libhccl.so", "libprofapi.so"
    };
    if (soNameList.find(soName_) == soNameList.end()) {
        return "";  // 白名单检查
    }
    char *ascendHomePath = std::getenv("ASCEND_HOME_PATH");
    auto soPath = std::string(ascendHomePath) + "/lib64/" + soName_;
    auto canonicalPath = Utils::RealPath(Utils::RelativeToAbsPath(soPath));
    return Utils::FileExist(canonicalPath) && Utils::FileReadable(canonicalPath) ? canonicalPath : soName_;
}
```

---

## 4. 数据流分析

### 4.1 关键数据流路径

```
┌─────────────────────────────────────────────────────────────────┐
│                        数据流架构图                               │
└─────────────────────────────────────────────────────────────────┘

用户应用
    │
    ├──► ACL API 调用 (aclrtSetDevice, aclrtLaunchKernel)
    │       │
    │       └─► Inject Wrapper [acl_inject.cpp]
    │               │
    │               ├─► CallbackScope [callback_manager.cpp]
    │               │       │
    │               │       └─► 用户回调执行 ★ HIGH RISK
    │               │
    │               ├─► ContextManager::UpdateAndReportCorrelationId
    │               │
    │               └─► 原函数 (dlsym)
    │
    ├──► HCCL API 调用
    │       │
    │       └─► Inject Wrapper [hccl_inject.cpp]
    │               │
    │               └─► CallbackScope → 用户回调 ★ HIGH RISK
    │
    └─► MSTX Marker API
            │
            └─► Inject Wrapper [mstx_inject.cpp]
                    │
                    └─► ActivityManager::Record

驱动层
    │
    └─► ProfChannelRead [driver_inject.cpp]
            │
            └─► ChannelReader::Execute [channel_reader.cpp] ★ CRITICAL
                    │
                    ├─► memcpy_s (缓冲区复制)
                    │
                    ├─► TransTsFwData → TsfwConvert → ParserManager
                    │
                    └─► TransStarsLog → SocLogConvert → KernelParser
                            │
                            └─► ActivityManager::Record

ActivityManager [activity_manager.cpp]
    │
    ├─► ActivityBuffer::Record
    │
    └─► bufferCompleted_handle_ 回调 ★ HIGH RISK
            │
            └─► 用户回调接收 profiling 数据

动态库加载 [function_loader.cpp]
    │
    ├─► ASCEND_HOME_PATH (环境变量) ★ HIGH RISK
    │
    ├─► CanonicalSoPath → realpath
    │
    └─► dlopen/dlsym ★ CRITICAL
            │
            └─► 所有 Inject 模块依赖

Python 层
    │
    ├─► PyInit_mspti_C [init.cpp]
    │
    ├─► RegisterCB → MsptiAdapter::RegisterCallback ★ HIGH RISK
    │       │
    │       └─► Python 回调存储与后续调用
    │
    └─► start/stop → MsptiAdapter::Start/Stop
```

---

## 5. 安全建议

### 5.1 高优先级建议

| 序号 | 建议 | 模块 | 风险降低 |
|------|------|------|----------|
| 1 | **验证环境变量**：对 ASCEND_HOME_PATH 进行白名单校验 | function_loader | High |
| 2 | **签名验证**：对加载的动态库进行签名验证 | function_loader | Critical |
| 3 | **回调隔离**：用户回调应在沙箱或受限环境执行 | callback, activity | Critical |
| 4 | **驱动数据校验**：对 ProfChannelRead 返回数据进行完整性检查 | channel | High |
| 5 | **缓冲区边界检查**：强化 memcpy_s 前的边界验证 | channel | Medium |

### 5.2 中优先级建议

| 序号 | 建议 | 模块 | 风险降低 |
|------|------|------|----------|
| 6 | **Python 回调验证**：验证回调函数签名和来源 | python_binding | High |
| 7 | **日志净化**：对用户提供的字符串进行净化处理 | mstx_inject | Medium |
| 8 | **异常安全**：完善 THROW_FUNC_NOTFOUND 的异常处理 | inject | Medium |
| 9 | **权限限制**：限制 profiling 上下文的权限 | 全局 | Medium |

### 5.3 低优先级建议

| 序号 | 建议 | 模块 | 风险降低 |
|------|------|------|----------|
| 10 | **输入字符检查**：扩展 CheckCharValid 的检查范围 | utils | Low |

---

## 6. CWE 映射

| CWE ID | 描述 | 相关代码 | 风险等级 |
|--------|------|----------|----------|
| CWE-426 | Untrusted Search Path | function_loader.cpp:58 | High |
| CWE-114 | Process Control | inject modules | Critical |
| CWE-120 | Buffer Copy without Size Check | channel_reader.cpp:99 | Medium |
| CWE-78 | Improper Neutralization of Special Elements | utils.cpp | Low |
| CWE-22 | Path Traversal | utils.cpp:94-104 | Medium |
| CWE-829 | Inclusion of Function from Untrusted Control Sphere | callback_manager.cpp | Critical |
| CWE-94 | Improper Control of Generation of Code ('Code Injection') | init.cpp, mspti_adapter.cpp | High |

---

## 7. 扫描范围

### 7.1 已覆盖文件

| 模块 | 文件数 | 覆盖率 |
|------|--------|--------|
| csrc/include | 5 | 100% |
| csrc/callback | 2 | 100% |
| csrc/activity | 28 | 100% |
| csrc/common | 24 | 100% |
| mspti/csrc | 5 | 100% |
| mspti/monitor | 6 | 100% |
| mspti (Python) | 4 | 100% |

### 7.2 排除文件

| 目录 | 原因 |
|------|------|
| test/ | 测试代码，非生产代码 |
| samples/ | 示例代码，非生产代码 |

---

## 8. 附录

### 8.1 关键文件路径

```
/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Profiler-Tools-Interface/
├── csrc/
│   ├── include/
│   │   ├── mspti.h
│   │   ├── mspti_activity.h
│   │   ├── mspti_callback.h
│   │   ├── mspti_cbid.h
│   │   └── mspti_result.h
│   ├── activity/
│   │   ├── activity_manager.cpp/h
│   │   └── ascend/
│   │       ├── channel/ [CRITICAL]
│   │       ├── parser/
│   │       ├── reporter/
│   │       └── entity/
│   ├── callback/
│   │   └ callback_manager.cpp/h [HIGH]
│   └── common/
│       ├── inject/ [CRITICAL]
│       │   ├── acl_inject.cpp/h
│       │   ├── hccl_inject.cpp/h
│       │   ├── mstx_inject.cpp/h
│       │   ├── driver_inject.cpp/h
│       │   └ function_loader.cpp/h [HIGH]
│       └ utils.cpp/h
├── mspti/
│   ├── csrc/
│   │   ├── init.cpp [HIGH]
│   │   ├── mspti_adapter.cpp/h
│   │   └ stub/
│   └ monitor/
│       ├── base_monitor.py
│       ├── kernel_monitor.py
│       ├── hccl_monitor.py
│       └ mstx_monitor.py
```

### 8.2 参考文档

- 华为昇腾 CANN 软件栈文档
- MSPTI API 参考文档 (docs/zh/c_api/)
- Python API 参考文档 (docs/zh/python_api/)
- 安全声明文档 (docs/zh/security_statement.md)

---

**报告生成时间：** 2026-04-21
**分析工具版本：** Architecture Analyzer v1.0
**项目版本：** 26.0.0-alpha.1