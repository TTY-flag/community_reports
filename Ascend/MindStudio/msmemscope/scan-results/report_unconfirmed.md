# 漏洞扫描报告 — 待确认漏洞

**项目**: msMemScope
**扫描时间**: 2026-04-20T06:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 8 | 47.1% |
| POSSIBLE | 4 | 23.5% |
| CONFIRMED | 3 | 17.6% |
| FALSE_POSITIVE | 2 | 11.8% |
| **总计** | **17** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 7 | 58.3% |
| Medium | 5 | 41.7% |
| **有效漏洞总计** | **12** | - |
| 误报 (FALSE_POSITIVE) | 2 | - |

### 1.3 Top 10 关键漏洞

1. **[SEC-001]** Untrusted_Search_Path (High) - `csrc/framework/process.cpp:172` @ `Process::SetPreloadEnv` | 置信度: 65
2. **[SEC-002]** Uncontrolled_Search_Path (High) - `csrc/event_trace/vallina_symbol.cpp:26` @ `LibLoad` | 置信度: 65
3. **[SEC-003]** Uncontrolled_Search_Path (High) - `python/msmemscope/__init__.py:21` @ `模块初始化` | 置信度: 65
4. **[SEC-008]** External_Control_System_Configuration (High) - `csrc/framework/process.cpp:172` @ `Process::SetPreloadEnv` | 置信度: 65
5. **[VULN-DF-LIB-001]** library_injection (High) - `csrc/event_trace/vallina_symbol.cpp:26` @ `LibLoad` | 置信度: 65
6. **[VULN-DF-PYLIB-001]** library_injection (High) - `python/msmemscope/__init__.py:21` @ `module initialization` | 置信度: 65
7. **[VULN-DF-CROSS-001]** cross_module_data_flow (High) - `跨模块:0` @ `Environment Variable Chain` | 置信度: 65
8. **[SEC-005]** External_Control_File_Name (Medium) - `csrc/utility/json_manager.cpp:267` @ `JsonConfig::ReadJsonConfig` | 置信度: 65
9. **[SEC-004]** Improper_Input_Validation (Medium) - `csrc/python_itf/watcherobject.cpp:79` @ `ParseInputArgs, ParseTensorPtrAndSize` | 置信度: 55
10. **[SEC-010]** Improper_Input_Validation (Medium) - `python/msmemscope/analyzer/leaks.py:71` @ `LeaksAnalyzer.read_file` | 置信度: 55

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@csrc/main.cpp` | cmdline | untrusted_local | CLI工具的主入口，接收用户命令行参数(argc, argv)，用户可以控制所有参数内容 | 程序主入口，解析命令行参数并执行命令 |
| `ClientParser::Interpretor@csrc/framework/client_parser.cpp` | cmdline | untrusted_local | 命令行参数解析入口，接收argc/argv并解析大量用户可控参数（路径、步骤、分析类型等） | 解析命令行参数并配置工具行为 |
| `ParseInputPaths@csrc/framework/client_parser.cpp` | file | untrusted_local | 解析用户指定的输入文件路径（--input参数），路径内容完全由用户控制 | 解析内存对比分析所需的输入文件路径 |
| `ParseOutputPath@csrc/framework/client_parser.cpp` | file | untrusted_local | 解析用户指定的输出目录路径（--output参数），路径内容完全由用户控制 | 解析分析结果输出目录路径 |
| `PyInit__msmemscope@csrc/python_itf/msleaksmodule.cpp` | decorator | untrusted_local | Python C扩展模块入口，被Python解释器调用，配置参数由Python调用者传入 | Python模块初始化，注册start/stop/config/step等接口 |
| `MsmemscopeConfig@csrc/python_itf/msleaksmodule.cpp` | decorator | untrusted_local | Python config()接口，接收用户传入的kwargs配置参数，包括路径、分析类型等 | Python接口配置工具参数 |
| `PyMemScopeWatcherWatch@csrc/python_itf/watcherobject.cpp` | decorator | untrusted_local | Python watcher.watch()接口，接收用户传入的tensor或addr+length参数进行内存监测 | Python接口添加内存监测对象 |
| `ExecuteCommand@csrc/event_trace/vallina_symbol.cpp` | cmdline | semi_trusted | 通过popen执行外部命令(which sqlite3)，命令参数来自硬编码字符串，但popen本身存在风险 | 执行外部shell命令查找sqlite3库路径 |
| `Process::SetPreloadEnv@csrc/framework/process.cpp` | env | trusted_admin | 设置LD_PRELOAD环境变量，Hook库路径来自工具安装目录和ATB_HOME_PATH环境变量，由管理员/部署者控制 | 设置进程预加载的Hook库环境变量 |
| `Process::Launch@csrc/framework/process.cpp` | cmdline | untrusted_local | 启动目标进程执行内存采集，目标程序路径和参数由用户命令行指定 | 启动被检测的目标进程 |
| `ctypes.CDLL@python/msmemscope/__init__.py` | file | semi_trusted | 动态加载libascend_leaks.so，路径来自ASCEND_HOME_PATH环境变量拼接，环境变量由部署者控制 | Python模块初始化时加载C扩展库 |
| `LeaksAnalyzer.read_file@python/msmemscope/analyzer/leaks.py` | file | untrusted_local | 读取用户指定的CSV文件进行分析，文件路径由Python调用者传入 | 读取CSV内存事件数据文件 |

**其他攻击面**:
- 命令行参数接口: msmemscope <options> <prog-and-args>
- Python API接口: msmemscope.config(), msmemscope.start(), msmemscope.stop(), msmemscope.watcher.watch()
- 文件输入接口: --input=path1,path2 (CSV/DB文件)
- 文件输出接口: --output=path (输出目录)
- 动态库加载: dlopen(libsqlite3.so), dlopen(libascend_leaks.so)
- Hook注入机制: LD_PRELOAD设置，Hook库注入目标进程
- Shell命令执行: popen("which sqlite3")
- 进程执行: execvpe()执行用户指定的目标程序

---

## 3. High 漏洞 (7)

### [SEC-001] Untrusted_Search_Path - Process::SetPreloadEnv

**严重性**: High | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/framework/process.cpp:172-222` @ `Process::SetPreloadEnv`
**模块**: framework

**描述**: SetPreloadEnv() 函数设置 LD_PRELOAD 环境变量加载 Hook 库文件时，只检查库文件是否存在(Exists())，没有验证库文件的属主和权限安全性。与 vallina_symbol.cpp 中的 ValidateLibrary() 不同，Hook 库加载缺少对库文件属主(root或当前用户)以及 group/others 写权限的检查，攻击者可能通过控制 LD_PRELOAD_PATH 环境变量提供恶意 Hook 库。

**漏洞代码** (`csrc/framework/process.cpp:172-222`)

```c
for (string &hookLib : hookLibNames) {
    Path hookLibPath = (Path(hookLibDir) / Path(hookLib)).Resolved();
    if (hookLibPath.ErrorOccured()) { return; }
    if (hookLibPath.Exists()) {
        hookLib = hookLibPath.ToString();
        // 缺少 ValidateLibrary() 类似的属主/权限验证
    }
}
```

**达成路径**

LD_PRELOAD_PATH环境变量 -> hookLibDir -> Path::Resolved() -> hookLibPath -> setenv(LD_PRELOAD)

**验证说明**: LD_PRELOAD_PATH环境变量控制Hook库路径，缺少ValidateLibrary()安全验证。攻击者可控制环境变量注入恶意库。属部署者控制而非普通用户，风险中等。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-002] Uncontrolled_Search_Path - LibLoad

**严重性**: High | **CWE**: CWE-427 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/event_trace/vallina_symbol.cpp:26-44` @ `LibLoad`
**模块**: event_trace

**描述**: LibLoad() 函数通过 ASCEND_HOME_PATH 环境变量加载动态库时，直接使用 dlopen 加载库文件，没有调用 ValidateLibrary() 进行安全验证。只有 Sqlite3LibLoader 使用了 ValidateLibrary()，其他 LibLoad 用法缺少对库文件属主和权限的检查，攻击者可能通过控制 ASCEND_HOME_PATH 环境变量加载恶意动态库。

**漏洞代码** (`csrc/event_trace/vallina_symbol.cpp:26-44`)

```c
void *LibLoad(std::string libName) {
    const char *pathEnv = std::getenv("ASCEND_HOME_PATH");
    if (pathEnv && !std::string(pathEnv).empty()) {
        libPath = pathEnv;
        libPath += "/lib64/" + libName;
        return dlopen(libPath.c_str(), RTLD_NOW | RTLD_GLOBAL); // 缺少 ValidateLibrary() 验证
    }
    return dlopen(libPath.c_str(), RTLD_NOW | RTLD_GLOBAL);
}
```

**达成路径**

ASCEND_HOME_PATH环境变量 -> libPath拼接 -> dlopen()

**验证说明**: ASCEND_HOME_PATH环境变量控制dlopen库路径，无ValidateLibrary()验证。与SEC-001同类问题，属部署者控制的环境变量风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-003] Uncontrolled_Search_Path - 模块初始化

**严重性**: High | **CWE**: CWE-427 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `python/msmemscope/__init__.py:21-32` @ `模块初始化`
**模块**: python_core
**跨模块**: python_core → event_trace

**描述**: Python __init__.py 通过 ASCEND_HOME_PATH 环境变量构建动态库路径并使用 ctypes.CDLL 加载 libascend_leaks.so，没有验证库文件的属主和权限安全性。与 C++ 代码的 ValidateLibrary() 不同，Python 侧缺少对动态库文件的安全验证。

**漏洞代码** (`python/msmemscope/__init__.py:21-32`)

```c
ASCEND_HOME_PATH = os.getenv('ASCEND_HOME_PATH')
if ASCEND_HOME_PATH:
    LEAKS_LIB_PATH = os.path.join(ASCEND_HOME_PATH, "tools", "msmemscope", "lib64")
if LEAKS_LIB_PATH:
    LEAKS_SO_PATH = os.path.join(LEAKS_LIB_PATH, "libascend_leaks.so")
    ctypes.CDLL(LEAKS_SO_PATH, mode=ctypes.RTLD_GLOBAL)  # 缺少库文件安全验证
```

**达成路径**

ASCEND_HOME_PATH环境变量 -> LEAKS_LIB_PATH -> ctypes.CDLL()

**验证说明**: Python侧ctypes.CDLL加载库文件，路径来自ASCEND_HOME_PATH，无安全验证。与C++侧SEC-002同类风险，跨模块一致性问题。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-008] External_Control_System_Configuration - Process::SetPreloadEnv

**严重性**: High | **CWE**: CWE-15 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/framework/process.cpp:172-222` @ `Process::SetPreloadEnv`
**模块**: framework
**跨模块**: framework → event_trace → utility → python_core

**描述**: 跨模块安全问题：多个关键环境变量(ASCEND_HOME_PATH, ATB_HOME_PATH, LD_PRELOAD_PATH, MSMEMSCOPE_CONFIG_ENV)在模块间传递控制关键路径，但缺少统一的安全验证机制。这些环境变量的值直接用于动态库加载、Hook库路径设置和配置文件读取，攻击者可能通过控制这些环境变量实现供应链攻击。

**漏洞代码** (`csrc/framework/process.cpp:172-222`)

```c
const char* preloadPath = getenv("LD_PRELOAD_PATH");
const char* atbHomePath = std::getenv("ATB_HOME_PATH");
// 环境变量控制关键路径，缺少安全验证
```

**达成路径**

[跨模块] LD_PRELOAD_PATH -> Hook库路径 | ASCEND_HOME_PATH -> 动态库路径 | MSMEMSCOPE_CONFIG_ENV -> 配置文件路径

**验证说明**: 跨模块环境变量安全问题汇总。ASCEND_HOME_PATH、ATB_HOME_PATH、LD_PRELOAD_PATH、MSMEMSCOPE_CONFIG_ENV需统一验证机制。属架构层面安全问题。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-LIB-001] library_injection - LibLoad

**严重性**: High | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/event_trace/vallina_symbol.cpp:26-44` @ `LibLoad`
**模块**: event_trace

**描述**: dlopen 动态加载库，库路径来自 ASCEND_HOME_PATH 环境变量。如果恶意用户能控制该环境变量，可以注入任意动态库并执行代码。数据流: getenv(ASCEND_HOME_PATH) → libPath → dlopen

**漏洞代码** (`csrc/event_trace/vallina_symbol.cpp:26-44`)

```c
void *LibLoad(std::string libName)
{
    const char *pathEnv = std::getenv("ASCEND_HOME_PATH");
    if (pathEnv && !std::string(pathEnv).empty()) {
        libPath = pathEnv;
        libPath += "/lib64/" + libName;
        return dlopen(libPath.c_str(), RTLD_NOW | RTLD_GLOBAL);
    }
    return dlopen(libPath.c_str(), RTLD_NOW | RTLD_GLOBAL);
}
```

**达成路径**

getenv(ASCEND_HOME_PATH)@csrc/event_trace/vallina_symbol.cpp:33 [SOURCE]
→ libPath@csrc/event_trace/vallina_symbol.cpp:35
→ dlopen@csrc/event_trace/vallina_symbol.cpp:37 [SINK]

**验证说明**: ASCEND_HOME_PATH环境变量控制dlopen路径，无ValidateLibrary()验证。与SEC-002重复发现，属于同一安全问题。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-PYLIB-001] library_injection - module initialization

**严重性**: High | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `python/msmemscope/__init__.py:21-30` @ `module initialization`
**模块**: python_core

**描述**: Python 模块初始化时使用 ctypes.CDLL 动态加载 libascend_leaks.so，库路径来自 ASCEND_HOME_PATH 环境变量。如果恶意用户能控制该环境变量，可以注入任意动态库。数据流: os.getenv(ASCEND_HOME_PATH) → LEAKS_LIB_PATH → LEAKS_SO_PATH → ctypes.CDLL

**漏洞代码** (`python/msmemscope/__init__.py:21-30`)

```c
ASCEND_HOME_PATH = os.getenv('ASCEND_HOME_PATH')
if ASCEND_HOME_PATH:
    LEAKS_LIB_PATH = os.path.join(ASCEND_HOME_PATH, "tools", "msmemscope", "lib64")
if LEAKS_LIB_PATH:
    LEAKS_SO_PATH = os.path.join(LEAKS_LIB_PATH, "libascend_leaks.so")
    ctypes.CDLL(LEAKS_SO_PATH, mode=ctypes.RTLD_GLOBAL)
```

**达成路径**

os.getenv('ASCEND_HOME_PATH')@python/msmemscope/__init__.py:21 [SOURCE]
→ LEAKS_LIB_PATH@python/msmemscope/__init__.py:24
→ LEAKS_SO_PATH@python/msmemscope/__init__.py:28
→ ctypes.CDLL@python/msmemscope/__init__.py:30 [SINK]

**验证说明**: Python侧ctypes.CDLL库加载，路径来自ASCEND_HOME_PATH。与SEC-03/VULN-DF-LIB-001同类问题，跨模块一致性风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CROSS-001] cross_module_data_flow - Environment Variable Chain

**严重性**: High | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `跨模块:0` @ `Environment Variable Chain`
**模块**: cross_module
**跨模块**: event_trace → python_core

**描述**: 跨模块环境变量传播链：ASCEND_HOME_PATH 环境变量同时影响 C++ 模块（vallina_symbol.cpp 的 dlopen）和 Python 模块（__init__.py 的 ctypes.CDLL）。如果恶意用户能控制该环境变量，可以在两个入口点同时注入恶意库。数据流路径：environ → getenv(ASCEND_HOME_PATH) → [dlopen, ctypes.CDLL]

**漏洞代码** (`跨模块:0`)

```c
跨模块传播，涉及 csrc/event_trace/vallina_symbol.cpp 和 python/msmemscope/__init__.py
```

**达成路径**

environ [SOURCE]
→ getenv(ASCEND_HOME_PATH)@csrc/event_trace/vallina_symbol.cpp:33
→ dlopen@csrc/event_trace/vallina_symbol.cpp:37 [SINK-CPP]
→ os.getenv('ASCEND_HOME_PATH')@python/msmemscope/__init__.py:21
→ ctypes.CDLL@python/msmemscope/__init__.py:30 [SINK-Python]

**验证说明**: 跨模块环境变量传播链。ASCEND_HOME_PATH同时影响C++模块(dlopen)和Python模块(ctypes.CDLL)。属架构层面问题，与SEC-008相关。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (5)

### [SEC-005] External_Control_File_Name - JsonConfig::ReadJsonConfig

**严重性**: Medium | **CWE**: CWE-73 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/utility/json_manager.cpp:267-277` @ `JsonConfig::ReadJsonConfig`
**模块**: utility

**描述**: ReadJsonConfig() 从 MSMEMSCOPE_CONFIG_ENV 环境变量读取配置文件路径并加载配置，但没有验证路径的安全性(属主、权限)。攻击者可能通过控制 MSMEMSCOPE_CONFIG_ENV 环境变量指向恶意配置文件，导致工具加载恶意配置。

**漏洞代码** (`csrc/utility/json_manager.cpp:267-277`)

```c
bool JsonConfig::ReadJsonConfig(MemScope::Config& config) {
    const char* path = std::getenv(MSMEMSCOPE_CONFIG_ENV);
    if (!path) { return false; }
    if (!Utility::JsonManager::GetInstance().LoadFromFile(path)) {  // 缺少路径安全验证
        return false;
    }
}
```

**达成路径**

MSMEMSCOPE_CONFIG_ENV环境变量 -> path -> LoadFromFile()

**验证说明**: MSMEMSCOPE_CONFIG_ENV环境变量控制配置文件路径，缺少路径安全验证。攻击者控制环境变量可加载恶意配置。属部署者控制风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-004] Improper_Input_Validation - ParseInputArgs, ParseTensorPtrAndSize

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/python_itf/watcherobject.cpp:79-144` @ `ParseInputArgs, ParseTensorPtrAndSize`
**模块**: python_itf

**描述**: Python watcher.watch() API 接受用户传入的内存地址(addr)和长度(length)参数进行内存监测，但缺少边界验证：1)没有验证内存地址是否在有效范围内；2)没有验证长度是否合理(可能导致DoS)。用户可以通过Python API传入任意内存地址进行监测，可能导致监测非法内存区域或传入超大长度值导致资源耗尽。

**漏洞代码** (`csrc/python_itf/watcherobject.cpp:79-144`)

```c
bool ParseTensorPtrAndSize(PyObject *tensor, void** ptr, uint64_t& length) {
    *ptr = reinterpret_cast<void*>((std::uintptr_t)PyLong_AsUnsignedLongLong(ptrObj));
    length = static_cast<uint64_t>(PyLong_AsUnsignedLongLong(lengthObj));
    // 缺少对内存地址有效性、长度合理性的验证
}
```

**达成路径**

Python kwargs(addr,length) -> PyLong_AsUnsignedLongLong -> tensorInfo.data/tensorInfo.dataSize -> TensorMonitor::AddWatchTensor

**验证说明**: Python API接受任意内存地址参数，缺少边界验证。有类型检查(PyLong_AsUnsignedLongLong)但无地址有效性验证。设计意图功能，但需加强边界检查。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [SEC-010] Improper_Input_Validation - LeaksAnalyzer.read_file

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `python/msmemscope/analyzer/leaks.py:71-92` @ `LeaksAnalyzer.read_file`
**模块**: python_analyzer
**跨模块**: python_analyzer → utility

**描述**: Python LeaksAnalyzer.read_file() 读取用户指定的CSV文件进行分析，虽然使用了try-except捕获异常，但缺少对文件路径的更严格安全验证（如检查文件大小限制、检查文件属主/权限）。与 C++ 的 CheckIsValidInputPath() 不同，Python侧缺少完整的安全验证。

**漏洞代码** (`python/msmemscope/analyzer/leaks.py:71-92`)

```c
def read_file(self):
    try:
        with open(self.config.input_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)  # 缺少对文件大小、属主/权限的安全验证
    except FileNotFoundError: ...
    except PermissionError: ...
```

**达成路径**

input_path参数 -> open() -> csv.DictReader()

**验证说明**: Python文件读取有异常捕获(FileNotFoundError/PermissionError/csv.Error)，但缺少文件大小限制和属主验证。与C++侧CheckIsValidInputPath()不一致。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-LIB-002] library_injection - FindAndLoadSqliteInDir

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/event_trace/vallina_symbol.cpp:146-189` @ `FindAndLoadSqliteInDir`
**模块**: event_trace

**描述**: 递归搜索目录并使用 dlopen 加载 libsqlite3.so。虽然有 ValidateLibrary 函数检查文件权限（root/当前用户拥有，无 group/other 写权限），但搜索起点来自 popen("which sqlite3") 的输出，该输出可能被篡改。数据流: popen output → FindLibParentDir → FindAndLoadSqliteInDir → dlopen

**漏洞代码** (`csrc/event_trace/vallina_symbol.cpp:146-189`)

```c
void* FindAndLoadSqliteInDir(const std::string& dirPath, int depth, int maxDepth)
{
    void* handle = dlopen(candidatePath.c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (handle) { return handle; }
}
```

**达成路径**

ExecuteCommand("which sqlite3")@csrc/event_trace/vallina_symbol.cpp:52
→ popen@csrc/event_trace/vallina_symbol.cpp:55
→ FindLibParentDir@csrc/event_trace/vallina_symbol.cpp:99
→ FindAndLoadSqliteInDir@csrc/event_trace/vallina_symbol.cpp:146
→ dlopen@csrc/event_trace/vallina_symbol.cpp:161 [SINK]

**验证说明**: dlopen加载SQLite库，虽有ValidateLibrary()权限检查，但搜索起点来自popen('which sqlite3')输出，可能被篡改。缓解措施有效但存在路径篡改风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -20 | context: 0 | cross_file: 0

---

### [SEC-009] Function_Pointer_Manipulation - MstxTableCoreInject

**严重性**: Medium | **CWE**: CWE-822 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/event_trace/mstx_hooks/mstx_inject.cpp:69-95` @ `MstxTableCoreInject`
**模块**: event_trace_mstx_hooks

**描述**: MstxTableCoreInject() 函数通过函数指针表替换替换原始函数实现。虽然这是Hook机制的正常实现，但函数指针替换操作本身存在安全风险：1)如果 getFuncTable 返回的函数表被篡改，可能导致执行恶意代码；2)缺少对 getFuncTable 函数来源的验证。

**漏洞代码** (`csrc/event_trace/mstx_hooks/mstx_inject.cpp:69-95`)

```c
bool MstxTableCoreInject(MstxGetModuleFuncTableFunc getFuncTable) {
    MstxFuncTable outTable;
    if (getFuncTable(...) != MSTX_SUCCESS || outTable == nullptr) { return false; }
    *(outTable[...]) = reinterpret_cast<MstxFuncPointer>(MstxMarkAFunc);  // 函数指针替换
}
```

**达成路径**

外部模块 -> getFuncTable() -> outTable函数指针表 -> 函数指针替换

**验证说明**: 函数指针表替换是Hook机制的设计意图。有nullptr检查但缺少getFuncTable来源验证。设计合理性较高，安全性风险可控。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: -5 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cross_module | 0 | 1 | 0 | 0 | 1 |
| event_trace | 0 | 2 | 1 | 0 | 3 |
| event_trace_mstx_hooks | 0 | 0 | 1 | 0 | 1 |
| framework | 0 | 2 | 0 | 0 | 2 |
| python_analyzer | 0 | 0 | 1 | 0 | 1 |
| python_core | 0 | 2 | 0 | 0 | 2 |
| python_itf | 0 | 0 | 1 | 0 | 1 |
| utility | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **7** | **5** | **0** | **12** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-426 | 5 | 41.7% |
| CWE-427 | 2 | 16.7% |
| CWE-20 | 2 | 16.7% |
| CWE-822 | 1 | 8.3% |
| CWE-73 | 1 | 8.3% |
| CWE-15 | 1 | 8.3% |
