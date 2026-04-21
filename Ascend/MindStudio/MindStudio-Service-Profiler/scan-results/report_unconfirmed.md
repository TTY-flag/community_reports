# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-Service-Profiler
**扫描时间**: 2026-04-20T23:50:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 33 | 42.9% |
| LIKELY | 24 | 31.2% |
| CONFIRMED | 12 | 15.6% |
| FALSE_POSITIVE | 8 | 10.4% |
| **总计** | **77** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 13 | 22.8% |
| Medium | 33 | 57.9% |
| Low | 11 | 19.3% |
| **有效漏洞总计** | **57** | - |
| 误报 (FALSE_POSITIVE) | 8 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-CPP-001]** Missing Security Validation (High) - `cpp/src/Config.cpp:76` @ `ReadConfigFile` | 置信度: 95
2. **[VULN-CPP-002]** Path Injection (High) - `cpp/src/Config.cpp:435` @ `ParseProfPath` | 置信度: 90
3. **[VULN-CPP-007]** Path Construction from Untrusted Source (High) - `cpp/src/ServiceProfilerDbWriter.cpp:88` @ `StartDump` | 置信度: 90
4. **[VULN-001-SOCKET-UNBOUNDED-FRAME]** Memory Exhaustion (High) - `ms_service_profiler/tracer/socket_server.py:157` @ `_process_data_frame` | 置信度: 90
5. **[VULN-UTILS-001]** Path Traversal (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/ms_service_profiler/utils/file_open_check.py:320` @ `ms_open` | 置信度: 85
6. **[VULN-002-TOCTOU-SAFE-PARENT]** TOCTOU (High) - `ms_service_profiler/utils/check/path_checker.py:234` @ `is_safe_parent_dir` | 置信度: 85
7. **[XM-VULN-003]** path_traversal (High) - `cpp/src/Config.cpp:435` @ `ParseProfPath` | 置信度: 80
8. **[VULN-b04e92c9]** dynamic_import (High) - `ms_service_profiler/patcher/core/config_loader.py:82` @ `_resolve_handler_func` | 置信度: 75
9. **[VULN-201c6934]** dynamic_import (High) - `ms_service_profiler/patcher/core/config_loader.py:118` @ `_resolve_metrics_handler_func` | 置信度: 75
10. **[VULN-b6a35737]** dynamic_import (High) - `ms_service_profiler/patcher/core/dynamic_hook.py:603` @ `HandlerResolver._try_import` | 置信度: 75

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@__main__.py` | cmdline | untrusted_local | CLI 入口点，用户通过命令行参数传入输入路径、输出路径、配置等。argparse 解析的参数可能包含恶意路径或异常值。 | 主 CLI 入口函数，解析命令行参数并执行子命令 |
| `ReadConfigPath@cpp/src/Config.cpp` | env | semi_trusted | 从环境变量 SERVICE_PROF_CONFIG_PATH 读取配置文件路径，环境变量由进程 owner 设置，但可被攻击者通过修改环境变量指向恶意配置文件。 | 读取配置路径环境变量 |
| `ReadConfigFile@cpp/src/Config.cpp` | file | semi_trusted | 从环境变量指定的路径读取 JSON 配置文件。文件内容由管理员控制，但 realpath 和 stat 检查存在路径遍历风险。 | 读取并解析 JSON 配置文件 |
| `load_yaml_config@ms_service_profiler/patcher/core/utils.py` | file | semi_trusted | 加载 YAML 配置文件，文件路径来自用户传入或环境变量。YAML 解析可能存在 YAML 反序列化风险。 | 加载 YAML 配置文件 |
| `AbstractSocketServer@ms_service_profiler/tracer/socket_server.py` | network | semi_trusted | Unix Domain Socket 服务器，监听 abstract namespace socket。虽然有 peer cred 验证（uid/gid/pid 检查和 namespace 检查），但接收的外部数据可能包含恶意内容。 | Unix Domain Socket 服务器，接收 traced 进程数据 |
| `send_control_command@ms_service_metric/ms_service_metric/control/cli.py` | rpc | semi_trusted | 通过共享内存和 SIGUSR1 信号控制目标进程。进程间通信需要相同用户权限，但控制命令可影响目标进程行为。 | 通过共享内存发送控制命令 |
| `load@ms_service_metric/ms_service_metric/core/config/symbol_config.py` | file | semi_trusted | 从 MS_SERVICE_METRIC_CONFIG_PATH 环境变量或传入路径加载 YAML 配置。配置中可指定 handler 函数路径，可能导致恶意代码执行。 | 加载 YAML 配置并解析 handler 函数路径 |
| `_resolve_handler_func@ms_service_profiler/patcher/core/config_loader.py` | decorator | semi_trusted | 从配置中导入自定义 handler 函数（importlib.import_module + getattr），配置文件可指定任意模块路径，存在代码注入风险。 | 根据配置导入自定义 handler 函数 |
| `parse@ms_service_profiler/parse.py` | cmdline | untrusted_local | 解析用户指定的输入路径，可能包含恶意路径或超大文件。check_input_dir_valid 有路径检查，但解析过程涉及 SQLite 和文件读写。 | 解析性能分析数据 |
| `ms_open@ms_service_profiler/utils/file_open_check.py` | file | semi_trusted | 安全文件打开函数，有路径检查、软链接检查、权限检查、大小限制。但依赖 FileStat 和 Rule.path() 检查，需要验证检查逻辑完整性。 | 安全文件打开函数，用于读取配置和数据文件 |
| `LibServiceProfiler@ms_service_profiler/mstx.py` | rpc | semi_trusted | 通过 ctypes 加载 C++ 动态库 libms_service_profiler.so。库路径来自 ASCEND_HOME_PATH 环境变量或系统默认路径，有白名单检查。 | Python ctypes 绑定，加载 C++ 性能分析库 |

**其他攻击面**:
- CLI 参数解析: argparse 解析用户传入的路径、配置文件路径
- JSON 配置文件解析: Config.cpp 读取 JSON 配置（环境变量 SERVICE_PROF_CONFIG_PATH）
- YAML 配置文件解析: config_loader.py、symbol_config.py 加载 YAML 配置
- 动态 Handler 导入: _resolve_handler_func 通过 importlib.import_module 加载配置指定的 handler 函数
- Unix Domain Socket: socket_server.py 接收 traced 进程数据（有 peer cred 验证）
- 共享内存 IPC: shm_manager.py 通过 posix_ipc 和 SIGUSR1 进行进程间控制
- 动态库加载: mstx.py 通过 ctypes 加载 libms_service_profiler.so
- 文件路径检查: SecurityUtils.cpp、file_open_check.py 的路径验证函数
- 模块导入监听: symbol_watcher.py 监听 Python 模块导入并执行 hook
- 字节码注入: inject.py 在函数入口和返回点注入 hook 代码

---

## 3. High 漏洞 (13)

### [VULN-CPP-001] Missing Security Validation - ReadConfigFile

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-73 | **置信度**: 95/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp/src/Config.cpp:76-126` @ `ReadConfigFile`
**模块**: cpp_profiler

**描述**: ReadConfigFile() reads configuration file from path derived from SERVICE_PROF_CONFIG_PATH environment variable without calling SecurityUtils::CheckFileBeforeRead(). The function only uses realpath() and basic file existence checks, but skips critical security validations: symlink detection, ownership verification, and group/world write permission checks. An attacker controlling the environment variable could point to a symlink or world-writable file, leading to config injection or information disclosure.

**漏洞代码** (`cpp/src/Config.cpp:76-126`)

```c
configPath_ = MsUtils::GetEnvAsString("SERVICE_PROF_CONFIG_PATH");\n// ... No CheckFileBeforeRead() call ...\nstd::ifstream configFile;\nconfigFile.open(configPath_);
```

**达成路径**

[IN] env(SERVICE_PROF_CONFIG_PATH) -> configPath_ -> realpath() -> ifstream::open() [OUT] JSON config parsed

**验证说明**: ReadConfigFile 从环境变量路径读取配置，缺少 CheckFileBeforeRead 安全检查。有 realpath 但缺少所有权和权限验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 10

---

### [VULN-CPP-002] Path Injection - ParseProfPath

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-22 | **置信度**: 90/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp/src/Config.cpp:435-447` @ `ParseProfPath`
**模块**: cpp_profiler

**描述**: ParseProfPath() directly assigns profPath_ from JSON config value "prof_dir" without path traversal validation. The value is taken from config["prof_dir"] and directly used to construct output paths. No validation for symlink containment, absolute path restrictions, or path depth limits. Attacker-controlled config could redirect profiler output to arbitrary directories.

**漏洞代码** (`cpp/src/Config.cpp:435-447`)

```c
profPath_ = config["prof_dir"];
```

**达成路径**

[IN] JSON config(prof_dir) -> profPath_ -> GetProfPath() [OUT] used in StartDump(), aclprofInit()

**验证说明**: prof_dir 配置值直接赋值给 profPath_，无路径遍历验证。可重定向输出到任意目录。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-CPP-007] Path Construction from Untrusted Source - StartDump

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-22 | **置信度**: 90/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp/src/ServiceProfilerDbWriter.cpp:88-103` @ `StartDump`
**模块**: cpp_profiler

**描述**: StartDump() constructs database file path from outputPath parameter without path traversal validation. The outputPath comes from config_->GetProfPath() which is derived from JSON "prof_dir" value. Path is constructed via simple concatenation: dir + dbFileName_ + hostName + pid. Attacker could inject path traversal sequences or absolute paths.

**漏洞代码** (`cpp/src/ServiceProfilerDbWriter.cpp:88-103`)

```c
std::string dbPath = dir + dbFileName_ + "_" + hostName + "-" + std::to_string(getpid()) + ".db";
```

**达成路径**

[IN] outputPath (from config) -> dir -> dbPath [OUT] sqlite3_open()

**验证说明**: StartDump 从 config 配置构造数据库路径，无路径遍历验证。可注入绝对路径或路径遍历序列。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-001-SOCKET-UNBOUNDED-FRAME] Memory Exhaustion - _process_data_frame

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-789 | **置信度**: 90/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ms_service_profiler/tracer/socket_server.py:157-165` @ `_process_data_frame`
**模块**: ms_service_profiler_tracer

**描述**: Uncontrolled memory allocation via unbounded frame length field. The _process_data_frame function reads a 4-byte length field (max ~4GB) without any validation or upper limit check. An authenticated peer (valid uid/gid/pid/namespace) can send a frame header claiming a massive payload size (e.g., 0xFFFFFFFF), causing the server to accumulate data in memory until it reaches the claimed size or runs out of memory. This can lead to OOM (Out of Memory) denial of service affecting the entire host system.

**漏洞代码** (`ms_service_profiler/tracer/socket_server.py:157-165`)

```c
length = int.from_bytes(buffer[:length_field_size], byteorder='big')
if len(buffer) >= length_field_size + length:
    data = buffer[length_field_size:length_field_size + length]
```

**达成路径**

socket.recv@socket_server.py:142 → _handle_recv@socket_server.py:139 → _process_data_frame@socket_server.py:157 → _handle_data@socket_server.py:167 → data_queue.put@socket_server.py:171

**验证说明**: Socket 服务器接收无限制帧长度，可导致内存耗尽 DoS。peer cred 验证后仍可发送大帧。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 5 | cross_file: 0

---

### [VULN-UTILS-001] Path Traversal - ms_open

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/ms_service_profiler/utils/file_open_check.py:320-358` @ `ms_open`
**模块**: utils_security

**描述**: ms_open function has TOCTOU (Time-of-Check-Time-of-Use) vulnerability. FileStat is created at line 322 using os.stat() which follows symlinks, but the actual os.open() at line 358 operates on the original path. An attacker could replace the file with a symlink between the check and the open, bypassing the symlink check.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/ms_service_profiler/utils/file_open_check.py:320-358`)

```c
file_stat = FileStat(file)  # Line 322\n...\nif not softlink and file_stat.is_softlink:  # Line 335\n...\nreturn os.fdopen(os.open(file, flags, mode=write_permission), mode, **kwargs)  # Line 358
```

**达成路径**

[IN] user input file path -> FileStat.__init__ (line 322) -> os.stat(file) (line 150) -> os.open(file) (line 358) [OUT] file descriptor

**验证说明**: ms_open TOCTOU 漏洞：FileStat 缓存和 os.open 之间存在时间窗口，可替换软链接绕过检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-002-TOCTOU-SAFE-PARENT] TOCTOU - is_safe_parent_dir

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-367 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ms_service_profiler/utils/check/path_checker.py:234-244` @ `is_safe_parent_dir`
**模块**: utils_security

**描述**: is_safe_parent_dir函数存在TOCTOU漏洞。函数内部对父目录进行多次stat操作(line 237, 240-242)，这些检查与调用方的文件操作之间存在竞态条件。攻击者可在检查期间移动或替换父目录，绕过安全限制。

**漏洞代码** (`ms_service_profiler/utils/check/path_checker.py:234-244`)

```c
path = os.path.realpath(self.instance); dirpath = os.path.dirname(path); if os.getuid() == 0: return True; dir_checker = PathChecker().any(...); return dir_checker.check(dirpath)
```

**验证说明**: is_safe_parent_dir TOCTOU 漏洞：多次 stat 操作与调用方文件操作之间存在竞态。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [XM-VULN-003] path_traversal - ParseProfPath

**严重性**: High（原评估: high → 验证后: High） | **CWE**: CWE-22 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/src/Config.cpp:435-446` @ `ParseProfPath`
**模块**: cross_module
**跨模块**: cpp_profiler → cpp_headers

**描述**: 跨模块配置路径注入: Config.cpp从JSON配置读取profPath_字段，该路径直接流向ServiceProfilerDbWriter.cpp用于数据库文件写入。路径未经安全验证，存在路径遍历风险。

**达成路径**

[IN] JSON config prof_dir → Config.cpp:ParseProfPath → profPath_ → [OUT] ServiceProfilerDbWriter.cpp:103 dbPath构造

**验证说明**: 跨模块配置路径注入：prof_dir 从 JSON 配置流向 ServiceProfilerDbWriter 用于数据库写入，无路径安全验证。

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 15 | mitigations: 0 | reachability: 25

---

### [VULN-b04e92c9] dynamic_import - _resolve_handler_func

**严重性**: High | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: python-security-module-scanner

**位置**: `ms_service_profiler/patcher/core/config_loader.py:82-110` @ `_resolve_handler_func`
**模块**: ms_service_profiler_patcher
**跨模块**: config_loader,dynamic_hook,utils

**描述**: Arbitrary code execution via unrestricted dynamic import. The function _resolve_handler_func uses importlib.import_module() to import modules specified in the configuration file without any validation or whitelist. An attacker who can control the configuration file (handler_path field) can import arbitrary modules and execute arbitrary code. Example attack: handler: 'os:system' would import os module and execute system calls.

**漏洞代码** (`ms_service_profiler/patcher/core/config_loader.py:82-110`)

```c
mod_obj = importlib.import_module(mod_str)
func = getattr(mod_obj, func_name, None)
if callable(func):
    return func
```

**达成路径**

handler_path(config YAML) -> _resolve_handler_func -> importlib.import_module(mod_str) -> getattr(mod_obj, func_name) -> handler_func execution

**验证说明**: 配置文件中的 handler_path 可被攻击者控制（若能修改配置文件或环境变量），实现任意模块导入和代码执行。无验证或白名单保护。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-201c6934] dynamic_import - _resolve_metrics_handler_func

**严重性**: High | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: python-security-module-scanner

**位置**: `ms_service_profiler/patcher/core/config_loader.py:118-135` @ `_resolve_metrics_handler_func`
**模块**: ms_service_profiler_patcher
**跨模块**: config_loader,metric_hook

**描述**: Arbitrary code execution via unrestricted dynamic import in metrics handler resolution. The function _resolve_metrics_handler_func uses importlib.import_module() without validation to import modules specified in the metrics configuration file. This allows an attacker to import arbitrary modules and execute arbitrary code via the metrics handler configuration.

**漏洞代码** (`ms_service_profiler/patcher/core/config_loader.py:118-135`)

```c
mod_obj = importlib.import_module(mod_str)
func = getattr(mod_obj, func_name, None)
if callable(func):
    return func
```

**达成路径**

handler_path(metrics config YAML) -> _resolve_metrics_handler_func -> importlib.import_module -> getattr -> handler_func

**验证说明**: metrics handler 配置同样可被攻击者控制，实现任意模块导入。无验证或白名单。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-b6a35737] dynamic_import - HandlerResolver._try_import

**严重性**: High | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: python-security-module-scanner

**位置**: `ms_service_profiler/patcher/core/dynamic_hook.py:603-620` @ `HandlerResolver._try_import`
**模块**: ms_service_profiler_patcher
**跨模块**: config_loader,dynamic_hook

**描述**: Arbitrary code execution via HandlerResolver._try_import. This static method uses importlib.import_module() without any validation to import modules based on handler_val string from configuration. The handler_val format 'pkg.mod:func' allows importing any Python module accessible in the environment.

**漏洞代码** (`ms_service_profiler/patcher/core/dynamic_hook.py:603-620`)

```c
mod, func_name = handler_val.split(':', 1)
mod_obj = importlib.import_module(mod)
value = getattr(mod_obj, '__dict__', {}).get(func_name, None)
```

**达成路径**

handler_val(config) -> HandlerResolver._try_import -> importlib.import_module(mod) -> getattr -> callable check

**验证说明**: HandlerResolver._try_import 通过配置中的 handler_val 导入任意模块，无验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-c9f7a958] dynamic_import - import_object_from_string

**严重性**: High | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: python-security-module-scanner

**位置**: `ms_service_profiler/patcher/core/module_hook.py:73-102` @ `import_object_from_string`
**模块**: ms_service_profiler_patcher
**跨模块**: module_hook,dynamic_hook

**描述**: Arbitrary module import via import_object_from_string. This function uses importlib.import_module() without any validation to import arbitrary modules based on configuration-provided import_path. Combined with getattr traversal, this allows importing and accessing any module and attribute in the Python environment. Used by DynamicHooker.init() and patcher decorator.

**漏洞代码** (`ms_service_profiler/patcher/core/module_hook.py:73-102`)

```c
module = importlib.import_module(import_path)
for part in module_path.split('.'): 
    current = getattr(current, part, None)
```

**达成路径**

import_path(config) -> import_object_from_string -> importlib.import_module -> getattr traversal

**验证说明**: import_object_from_string 从配置导入任意模块，无验证或白名单。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CROSS-003] Cross-Module TOCTOU Propagation - cross_module_toctou

**严重性**: High（原评估: high → 验证后: High） | **CWE**: CWE-367 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `cross_module:1-30` @ `cross_module_toctou`
**模块**: cross_module
**跨模块**: utils_security → cpp_profiler → ms_service_profiler

**描述**: TOCTOU vulnerabilities in security checking functions propagate across Python and C++ layers. Python's ms_open() calls FileStat (caches stat) then os.open(), while C++'s SecurityUtils::CheckFileBeforeRead uses stat before ifstream::open. Both have race condition windows. When Python calls C++ via ctypes for file operations, the TOCTOU window is extended, increasing attack success probability.

**漏洞代码** (`cross_module:1-30`)

```c
Python: FileStat → check → os.open
C++: stat → check → ifstream::open
Cross: ctypes → C++ SecurityUtils → extended TOCTOU window
```

**达成路径**

[PYTHON] file_open_check.py:ms_open → FileStat(cache) → Rule.path() → os.open (TOCTOU)
[C++] SecurityUtils.cpp:CheckFileBeforeRead → stat() → ifstream::open (TOCTOU)
[CROSS] mstx.py → ctypes → C++ checks → TOCTOU window extended

**验证说明**: 跨模块TOCTOU传播：Python ms_open 和 C++ SecurityUtils CheckFileBeforeRead 都有竞态窗口。ctypes调用扩展了TOCTOU窗口。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 15 | mitigations: 0 | reachability: 25

---

### [VULN-CPP-HEADERS-003] Untrusted Search Path - ServiceProfilerInterface::OpenLib

**严重性**: High | **CWE**: CWE-426 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/cpp/include/msServiceProfiler/ServiceProfilerInterface.h:473-517` @ `ServiceProfilerInterface::OpenLib`
**模块**: cpp_headers
**跨模块**: cpp_headers → cpp_src

**描述**: OpenLib() function constructs shared library path using ASCEND_HOME_PATH environment variable and loads it via dlopen(). Although realpath() is used for canonicalization, a manipulated environment variable could lead to loading a malicious library, resulting in arbitrary code execution.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/cpp/include/msServiceProfiler/ServiceProfilerInterface.h:473-517`)

```c
char *ascendHomePathPtr = getenv("ASCEND_HOME_PATH"); ... handle = dlopen(soName.c_str(), RTLD_LAZY);
```

**达成路径**

[IN] ASCEND_HOME_PATH env var -> getenv() -> realpath() -> dlopen() -> [OUT] library loaded

**验证说明**: ASCEND_HOME_PATH 环境变量控制 dlopen 加载路径。攻击者若控制环境变量可加载恶意库实现任意代码执行。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (33)

### [VULN-ms_service_metric-002] Configuration File Path from Environment Variable - _load_user_config

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-15 | **置信度**: 90/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ms_service_metric/ms_service_metric/core/config/symbol_config.py:182-186` @ `_load_user_config`
**模块**: ms_service_metric

**描述**: Configuration file path is read from MS_SERVICE_METRIC_CONFIG_PATH environment variable without validation. An attacker who can control this environment variable can force the application to load an arbitrary configuration file, potentially containing malicious handler paths.

**漏洞代码** (`ms_service_metric/ms_service_metric/core/config/symbol_config.py:182-186`)

```c
env_path = os.environ.get(self.ENV_CONFIG_PATH)\nif env_path and os.path.exists(env_path):\n    return self._load_yaml(env_path)
```

**达成路径**

[IN] MS_SERVICE_METRIC_CONFIG_PATH env -> _load_user_config() -> _load_yaml() -> [OUT] Arbitrary config loaded

**验证说明**: 环境变量 MS_SERVICE_METRIC_CONFIG_PATH 指向任意配置文件，可加载恶意配置导致代码执行。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-ms_service_metric-003] Unauthenticated Shared Memory IPC - connect

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-287 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ms_service_metric/ms_service_metric/utils/shm_manager.py:194-248` @ `connect`
**模块**: ms_service_metric
**跨模块**: shm_manager.py,cli.py,metric_control_watch.py

**描述**: Shared memory IPC mechanism lacks authentication. Any process knowing the shared memory prefix (controlled by MS_SERVICE_METRIC_SHM_PREFIX env var) can connect and send control commands. No verification of sender identity or authorization.

**漏洞代码** (`ms_service_metric/ms_service_metric/utils/shm_manager.py:194-248`)

```c
self._shm = posix_ipc.SharedMemory(self._shm_name)\nself._mmap = mmap.mmap(self._shm.fd, actual_size)
```

**达成路径**

[IN] Any process -> SharedMemoryManager.connect() -> posix_ipc.SharedMemory -> [OUT] Unauthenticated access to shared control state

**验证说明**: 共享内存 IPC 无身份验证，任何知道 shm prefix 的进程可连接发送控制命令。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-CPP-003] TOCTOU Race Condition - CheckFileBeforeRead

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-367 | **置信度**: 85/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/src/SecurityUtils.cpp:268-299` @ `CheckFileBeforeRead`
**模块**: cpp_profiler

**描述**: CheckFileBeforeRead() has a Time-of-Check-Time-of-Use race condition. IsSoftLink() is called first to check if path is symlink, then GetRealPath() resolves the path. An attacker could replace the symlink with a regular file or vice versa between these checks, bypassing the symlink detection.

**漏洞代码** (`cpp/src/SecurityUtils.cpp:268-299`)

```c
if (IsSoftLink(path)) { return false; }\nconst auto absPath = GetRealPath(path);
```

**达成路径**

[IN] path -> IsSoftLink() [TOCTOU WINDOW] -> GetRealPath() [OUT] absPath

**验证说明**: CheckFileBeforeRead TOCTOU 漏洞：IsSoftLink 和 GetRealPath 之间可替换文件。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CPP-004] Shared Memory Race Condition - MarkFirstProcessAsMain

**严重性**: Medium（原评估: HIGH → 验证后: Medium） | **CWE**: CWE-362 | **置信度**: 85/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/src/ServiceProfilerManager.cpp:562-622` @ `MarkFirstProcessAsMain`
**模块**: cpp_profiler

**描述**: MarkFirstProcessAsMain() uses POSIX shared memory (shm_open/mmap) for inter-process coordination without proper synchronization. The shared memory region stores PID and path info that multiple processes read/write. Race conditions could allow: 1) Process impersonation via PID manipulation, 2) Path redirection to attacker-controlled directories, 3) Data corruption leading to unpredictable behavior.

**漏洞代码** (`cpp/src/ServiceProfilerManager.cpp:562-622`)

```c
shm_open(..., O_CREAT | O_RDWR, 0640);\nmmap(..., PROT_READ | PROT_WRITE, MAP_SHARED, ...);\n// No mutex/semaphore protection between processes
```

**达成路径**

[IN] shared memory -> pInfoStr -> SplitStr() -> Str2Uint() [OUT] isMaster_, profPathDateTail_

**验证说明**: 共享内存进程协调无同步机制，可导致 PID 伪造或路径重定向。利用难度较高。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN-002-SOCKET-UNBOUNDED-BUFFER] Resource Exhaustion - _handle_recv

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-400 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ms_service_profiler/tracer/socket_server.py:139-154` @ `_handle_recv`
**模块**: ms_service_profiler_tracer

**描述**: Unbounded buffer accumulation during data reception. The _handle_recv function continuously extends a bytearray buffer with received data without any size limit or timeout on individual recv operations. An authenticated peer can slowly stream data at a minimal rate to keep the connection alive while accumulating memory, or send multiple large frames concurrently. Combined with the unbounded frame length issue, this creates a compound memory exhaustion attack vector.

**漏洞代码** (`ms_service_profiler/tracer/socket_server.py:139-154`)

```c
buffer = bytearray()\nwhile True:\n    chunk = client_sock.recv(self.buffer_size)\n    if not chunk:\n        break\n    buffer.extend(chunk)
```

**达成路径**

socket.recv@socket_server.py:142 → _handle_recv@socket_server.py:139 → buffer.extend(chunk)@socket_server.py:145

**验证说明**: Socket 接收无限制缓冲区积累，可导致内存耗尽。与帧长度漏洞结合形成复合攻击。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 5 | cross_file: 0

---

### [VULN-004-UNSAFE-EVAL] unsafe_eval - _execute_direct_expression

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: N/A | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `dynamic_hook.py:392-478` @ `_execute_direct_expression`
**模块**: ms_service_profiler_patcher

**描述**: Expression evaluation using eval() with blocklist-based filtering. _validate_expression_safety() uses incomplete keyword blocklist. Blocklist approach is bypassable - attacker may use encoding tricks or alternative dangerous constructs not in blocklist.

**达成路径**

config_attributes_expr->_validate_expression_safety->_execute_direct_expression->eval

**验证说明**: eval() 使用 blocklist 过滤不完整，可能被绕过。safe_globals/locals 有部分保护但不完美。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 5 | cross_file: 0

---

### [VULN-CPP-005] Unbounded Resource Consumption - ReadConfigFile

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-400 | **置信度**: 80/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/src/Config.cpp:111-125` @ `ReadConfigFile`
**模块**: cpp_profiler

**描述**: ReadConfigFile() parses JSON configuration without file size validation before parsing. The JSON parsing via nlohmann::json uses operator>> which could consume excessive memory if the config file is maliciously large. Combined with missing CheckFileBeforeRead() call, attacker could craft large JSON causing DoS through memory exhaustion.

**漏洞代码** (`cpp/src/Config.cpp:111-125`)

```c
configFile >> jsonData; // No size limit check before parsing
```

**达成路径**

[IN] configFile -> jsonData (nlohmann::json::parse) [OUT] ParseConfig()

**验证说明**: ReadConfigFile JSON 解析无大小限制，可能导致内存耗尽 DoS。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-003-SOCKET-CONNECTION-LIMIT] Resource Exhaustion - _server_loop

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-772 | **置信度**: 80/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ms_service_profiler/tracer/socket_server.py:192-209` @ `_server_loop`
**模块**: ms_service_profiler_tracer

**描述**: Missing concurrent connection limit enforcement. While max_listen_num is set on the listening socket (backlog), each accepted connection spawns a new unbounded thread via threading.Thread without tracking or limiting concurrent connections. Combined with the memory accumulation per connection, an authenticated peer can open multiple concurrent connections (up to system limits) to amplify memory consumption and thread pool exhaustion.

**漏洞代码** (`ms_service_profiler/tracer/socket_server.py:192-209`)

```c
client_sock, client_addr = self.server_socket.accept()\nclient_thread = threading.Thread(\n    target=self._handle_client,\n    args=(client_sock, client_addr),\n    daemon=True\n)\nclient_thread.start()
```

**达成路径**

_server_loop@socket_server.py:192 → threading.Thread@socket_server.py:198 → _handle_client@socket_server.py:124

**验证说明**: 缺少并发连接限制，每个连接创建新线程无跟踪，可导致线程池耗尽。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-005-ENV-PATH-INJECTION] Environment Variable Path Injection - get_valid_lib_path

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-80 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ms_service_profiler/utils/file_open_check.py:377-397` @ `get_valid_lib_path`
**模块**: utils_security

**描述**: get_valid_lib_path函数使用环境变量ASCEND_HOME_PATH构造动态库路径。虽然库名有白名单限制，但攻击者若能控制环境变量，可指向包含恶意同名库的目录。返回路径用于ctypes.cdll.LoadLibrary。

**漏洞代码** (`ms_service_profiler/utils/file_open_check.py:377-397`)

```c
os.getenv ASCEND_HOME_PATH + os.path.join + ctypes.cdll.LoadLibrary
```

**验证说明**: ASCEND_HOME_PATH 环境变量构造动态库路径，库名有白名单但路径可控。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

---

### [ms_service_metric-CWE73-config_path] PATH_TRAVERSAL - _load_user_config

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-73 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ms_service_metric/ms_service_metric/core/config/symbol_config.py:171-193` @ `_load_user_config`
**模块**: ms_service_metric

**描述**: _load_user_config loads YAML config from MS_SERVICE_METRIC_CONFIG_PATH environment variable without path validation. While yaml.safe_load prevents YAML deserialization attacks (no yaml.load used), the config content (handler paths) leads to arbitrary code execution via _import_handler. Config file can be placed anywhere including /tmp, world-writable directories.

**达成路径**

MS_SERVICE_METRIC_CONFIG_PATH (env) -> _load_user_config -> _load_yaml -> MetricHandler.from_config

**验证说明**: MS_SERVICE_METRIC_CONFIG_PATH 环境变量指向任意配置文件，可放置在世界可写目录。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-ms_service_metric-004] Signal Injection via Process List Manipulation - _send_signals_and_cleanup

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-74 | **置信度**: 75/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ms_service_metric/ms_service_metric/utils/shm_manager.py:683-715` @ `_send_signals_and_cleanup`
**模块**: ms_service_metric
**跨模块**: shm_manager.py,cli.py

**描述**: SIGUSR1 signals are sent to PIDs stored in shared memory. An attacker with access to shared memory could potentially inject malicious PIDs, causing SIGUSR1 signals to be sent to arbitrary processes when control commands are issued.

**漏洞代码** (`ms_service_metric/ms_service_metric/utils/shm_manager.py:683-715`)

```c
for i in range(proc_len):\n    pid = self.get_proc_at(i)\n    os.kill(pid, signal.SIGUSR1)
```

**达成路径**

[IN] SharedMemoryManager -> _send_signals_and_cleanup() -> os.kill(pid, SIGUSR1) -> [OUT] Signal sent to stored PIDs

**验证说明**: SIGUSR1 信号发送到共享内存中的 PID，若攻击者能访问共享内存可注入恶意 PID。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-CPP-008] Library Loading Without Path Validation - RegisterSetDeviceCallback

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-426 | **置信度**: 75/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/src/ServiceProfilerManager.cpp:474-516` @ `RegisterSetDeviceCallback`
**模块**: cpp_profiler

**描述**: RegisterSetDeviceCallback() calls dlopen("libprofapi.so", ...) without validating the library path. While RTLD_LOCAL is used, the library search uses system paths. If attacker can place malicious libprofapi.so in library search path before legitimate one, could achieve code execution. Consider using absolute path with CheckFileBeforeRead.

**漏洞代码** (`cpp/src/ServiceProfilerManager.cpp:474-516`)

```c
void *handle = dlopen("libprofapi.so", RTLD_LAZY | RTLD_LOCAL);
```

**达成路径**

[IN] "libprofapi.so" -> dlopen() [OUT] dlsym() for callback registration

**验证说明**: dlopen libprofapi.so 无路径验证，攻击者可在库搜索路径放置恶意库。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-005-SOCKET-QUEUE-AMPLIFICATION] Denial of Service - _handle_data

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-770 | **置信度**: 75/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ms_service_profiler/tracer/socket_server.py:167-190` @ `_handle_data`
**模块**: ms_service_profiler_tracer

**描述**: Missing data rate limiting enabling queue flooding. The socket server has a large queue (max_queue_size=1000000) but no rate limiting on incoming data. Combined with unbounded frame sizes, an authenticated peer can rapidly fill the queue with large frames, causing legitimate data to be dropped (oldest discarded in _handle_queue_full). The warning_queue_size of 100000 only triggers logging without actual throttling.

**漏洞代码** (`ms_service_profiler/tracer/socket_server.py:167-190`)

```c
def _handle_data(self, data):\n    try:\n        self._check_queue_size()\n        self.data_queue.put(data, block=False)\n    except queue.Full:\n        self._handle_queue_full(data)
```

**达成路径**

_handle_data@socket_server.py:167 → data_queue.put@socket_server.py:171 → [OUT] export_binary_data@binary_otlp_exporter.py:46

**验证说明**: 大队列无速率限制，认证 peer 可快速填满队列导致数据丢失。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-UTILS-002] Improper Privilege Management - is_safe_parent_dir

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-269 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/ms_service_profiler/utils/check/path_checker.py:233-244` @ `is_safe_parent_dir`
**模块**: utils_security

**描述**: is_safe_parent_dir() bypasses all parent directory safety checks when running as root (os.getuid() == 0). This allows files in world-writable directories to be used without validation, which could lead to unauthorized file access in privileged contexts.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/ms_service_profiler/utils/check/path_checker.py:233-244`)

```c
def is_safe_parent_dir(self):\n    path = os.path.realpath(self.instance)\n    dirpath = os.path.dirname(path)\n    if os.getuid() == 0:\n        return True  # Bypasses all checks for root!
```

**达成路径**

[IN] file path -> os.path.realpath() -> os.getuid() == 0 check -> returns True without validation

**验证说明**: is_safe_parent_dir 当 root 用户运行时绕过所有检查，世界可写目录文件无验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 5 | cross_file: 0

---

### [VULN-003-WRITE-RACE] Incomplete Permission Check - ms_open

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-264 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ms_service_profiler/utils/file_open_check.py:331-358` @ `ms_open`
**模块**: utils_security

**描述**: ms_open函数在写模式下存在权限竞态问题。当文件存在时先检查所有者，然后删除文件，再创建新文件。新创建的文件可能由不同用户所有，且在删除和创建之间存在竞态窗口。

**漏洞代码** (`ms_service_profiler/utils/file_open_check.py:331-358`)

```c
check_file_owner then os.remove then os.open
```

**验证说明**: ms_open 写模式存在权限竞态：删除和创建之间存在时间窗口，新文件可能不同用户所有。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-UTILS-005] Improper Control of Environment Variable - check_basic_permission

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-15 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/ms_service_profiler/utils/file_open_check.py:209-242` @ `check_basic_permission`
**模块**: utils_security

**描述**: check_basic_permission() uses RAW_INPUT_PATH environment variable to whitelist symlink targets without validation. An attacker controlling this environment variable can allow arbitrary symlink targets to pass the symlink check.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/ms_service_profiler/utils/file_open_check.py:209-242`)

```c
whitelist_path = os.environ.get(RAW_INPUT_PATH, "")\nif whitelist_path == "":\n    ...\nsub_paths = whitelist_path.split("|")\nfor sub_path in sub_paths:\n    if common_path_target == sub_path_abs and common_path_file == sub_path_abs:\n        illegal_softlink = False
```

**达成路径**

[IN] RAW_INPUT_PATH env var -> os.environ.get() -> split("|") -> os.path.commonpath() comparison -> bypasses symlink check

**验证说明**: RAW_INPUT_PATH 环境变量白名单软链接目标无验证，可绕过软链接检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-UTILS-004] Improper Link Resolution - ms_open

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-59 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/ms_service_profiler/utils/file_open_check.py:335-336` @ `ms_open`
**模块**: utils_security

**描述**: ms_open softlink parameter allows bypassing symlink security checks. When softlink=True is passed, symlink files are opened without validation of their targets. This could be exploited if callers pass softlink=True with untrusted paths.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/ms_service_profiler/utils/file_open_check.py:335-336`)

```c
if not softlink and file_stat.is_softlink:\n    raise OpenException(f"Softlink is not allowed to be opened. {file}")
```

**达成路径**

[IN] softlink parameter -> bypasses is_softlink check -> os.fdopen() opens symlink target

**验证说明**: 软链接链接解析可能允许攻击者将链接目标重定向到非预期路径。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp_profiler_VULN_001] TOCTOU - Config::ReadConfigFile

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-367 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `cpp/src/Config.cpp:91-100` @ `Config::ReadConfigFile`
**模块**: cpp_profiler

**描述**: Time-of-Check-Time-of-Use vulnerability in Config::ReadConfigFile(). The function uses realpath() to canonicalize the path at line 91, but then opens the file with ifstream::open() at line 100 without atomic operations. An attacker could replace the file with a symlink between the realpath check and the open operation, potentially reading arbitrary files.

**漏洞代码** (`cpp/src/Config.cpp:91-100`)

```c
char realConfigPath[PATH_MAX] = {0};
if (realpath(configPath_.c_str(), realConfigPath) == nullptr) {...}
configPath_ = realConfigPath;
...
configFile.open(configPath_);
```

**达成路径**

SERVICE_PROF_CONFIG_PATH env var -> ReadConfigPath() -> configPath_ -> realpath() -> ifstream::open()

**验证说明**: TOCTOU 竞态条件：realpath() 和 ifstream::open() 之间存在时间窗口。利用难度高，需精确时间控制。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp_profiler_VULN_004] TOCTOU - Profiler::OpenLib

**严重性**: Medium | **CWE**: CWE-367 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `cpp/include/msServiceProfiler/ServiceProfilerInterface.h:478-500` @ `Profiler::OpenLib`
**模块**: cpp_profiler
**跨模块**: python_wrapper

**描述**: Time-of-Check-Time-of-Use vulnerability in ServiceProfilerInterface.h::OpenLib(). After canonicalizing ASCEND_HOME_PATH with realpath() at line 490, it checks file readability with stat() at line 496, then calls dlopen() at line 500. An attacker could replace the .so file between the stat check and dlopen, potentially loading malicious code.

**漏洞代码** (`cpp/include/msServiceProfiler/ServiceProfilerInterface.h:478-500`)

```c
char ascendHomeRealPath[PATH_MAX + 1] = {0};
if (realpath(ascendHomePath.c_str(), ascendHomeRealPath) == nullptr) {...}
std::string soName = std::string(ascendHomeRealPath) + "/lib64/libms_service_profiler.so";
struct stat fileStat;
if ((stat(soName.c_str(), &fileStat) != 0) || (fileStat.st_mode & S_IRUSR) == 0) {...}
handle = dlopen(soName.c_str(), RTLD_LAZY);
```

**达成路径**

ASCEND_HOME_PATH env var -> realpath() -> stat() [TOCTOU window] -> dlopen()

**验证说明**: dlopen 前的 TOCTOU 竞态：stat() 和 dlopen() 之间可替换 .so 文件。利用难度高。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-004-SYMLINK-BYPASS] Configuration Weakness - ms_open

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-59 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ms_service_profiler/utils/file_open_check.py:320-336` @ `ms_open`
**模块**: utils_security

**描述**: ms_open函数的softlink参数默认为False，允许调用方传入softlink=True绕过软链接安全检查。这可能导致攻击者通过软链接访问非预期文件，尤其在文件写入场景下风险更高。

**漏洞代码** (`ms_service_profiler/utils/file_open_check.py:320-336`)

```c
def ms_open(file, mode="r", max_size=CONFIG_FILE_MAX_SIZE, softlink=False, ...):
    ...
    if not softlink and file_stat.is_softlink:  # softlink=True时可绕过检查
        raise OpenException(...)
```

**验证说明**: ms_open softlink 参数默认为 False，调用方可传入 True 绕过软链接检查。文件写入场景风险更高。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [msservice_advisor_path_traversal_001] Path Traversal - arg_parse

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: python-dataflow-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/msservice_advisor/msservice_advisor/advisor.py:184-131` @ `arg_parse`
**模块**: msservice_advisor
**跨模块**: msservice_advisor → msguard

**描述**: The service_config_path CLI argument is not validated at input point (uses type=str) while instance_path uses Rule.input_dir_traverse. Validation via Rule.input_file_read occurs AFTER path manipulation with os.path.join.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/msservice_advisor/msservice_advisor/advisor.py:184-131`)

```c
parser.add_argument("-s", "--service_config_path", type=str, required=False, default=None, ...)
```

**达成路径**

[IN] CLI arg --service_config_path (line 184, type=str, no validation) -> get_mindie_server_config_path (line 124) -> os.path.join for path construction (line 118) -> Rule.input_file_read.is_satisfied_by AFTER path manipulation (line 126) -> read_csv_or_json (line 131) -> [OUT] file content to mindie_service_config

**验证说明**: CLI 参数 service_config_path 无即时验证，路径操作后才检查。可能存在路径遍历绕过。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-ms_serviceparam_optimizer-001] arbitrary_code_execution - unknown

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `plugins/__init__.py:49-55` @ `?`
**模块**: ms_serviceparam_optimizer

**描述**: Dynamic plugin loading via entry_points without validation. ep.load() loads arbitrary callable code from external packages registered under ms_serviceparam_optimizer.plugins group. Malicious packages can register plugins that execute automatically. Attack vector: supply malicious Python package with entry_points registration.

**达成路径**

[IN] Python package entry_points -> load_plugins_by_group() -> ep.load() -> func() execution

**验证说明**: 供应链攻击场景：攻击者需创建并让用户安装恶意 Python 包。entry_points 自动加载插件，无验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-ms_serviceparam_optimizer-006] configuration_injection - prepare_plugin

**严重性**: Medium | **CWE**: CWE-15 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `optimizer/optimizer.py:349-350` @ `prepare_plugin`
**模块**: ms_serviceparam_optimizer

**描述**: Config field value read from JSON without validation. get_required_field_from_json reads nested values that could be manipulated.

**达成路径**

[IN] config.json -> get_required_field_from_json -> scheduler.run

**验证说明**: 配置文件字段值无验证读取，攻击者若能控制配置文件可注入恶意值。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-UTILS-006] Race Condition - ms_open

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-367 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/ms_service_profiler/utils/file_open_check.py:320-358` @ `ms_open`
**模块**: utils_security

**描述**: ms_open performs multiple non-atomic file operations. FileStat checks (exists, type, size, owner) are performed before os.open(). Between these checks and the actual open, file state can change (symlink replacement, file content modification), leading to race condition attacks.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/ms_service_profiler/utils/file_open_check.py:320-358`)

```c
file_stat = FileStat(file)  # Line 322: stat check\ncheck_file_exists_and_type(file_stat, file)  # Line 324\ncheck_file_size(file_stat, file, max_size)  # Line 329\ncheck_file_owner(file_stat, file)  # Line 332/339\n...\nreturn os.fdopen(os.open(file, flags, mode=write_permission), mode, **kwargs)  # Line 358
```

**达成路径**

[IN] file path -> FileStat (stat) -> check_file_size -> check_file_owner -> os.open() [OUT] - Gap between check and use allows file modification

**验证说明**: ms_open 多次非原子文件操作，stat检查和os.open之间存在TOCTOU竞态。文件状态可在此窗口内改变。

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-ms_serviceparam_optimizer-004] path_traversal - fetch_rids_from_db

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `train/source_to_train.py:37` @ `fetch_rids_from_db`
**模块**: ms_serviceparam_optimizer

**描述**: Database path from user-controlled input. sqlite3.connect uses path from user input_path. Rule.input_file_read check exists but path is user-controlled before validation.

**达成路径**

[IN] CLI args.input -> input_path -> sqlite3.connect

**验证说明**: CLI 参数控制数据库路径，虽有 Rule.input_file_read 检查但路径在检查前已使用。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [XM-VULN-004] ipc_manipulation - send_signal_to_processes

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: CWE-342 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `ms_service_metric/ms_service_metric/utils/shm_manager.py:683-715` @ `send_signal_to_processes`
**模块**: cross_module
**跨模块**: ms_service_metric → ms_service_profiler_tracer

**描述**: 跨模块IPC信号注入: ms_service_metric/shm_manager.py通过共享内存接收控制命令，使用os.kill(pid, SIGUSR1)向注册进程发送信号。攻击者可注册恶意PID或操纵共享内存数据。

**达成路径**

[IN] CLI control command → shm_manager.py:SharedMemoryManager → [OUT] os.kill(pid, SIGUSR1) → 目标进程

**验证说明**: IPC信号注入：共享内存接收控制命令，os.kill 发送 SIGUSR1 到注册PID。攻击者可注册恶意PID或操纵共享内存。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 5 | mitigations: 0 | reachability: 20

---

### [cpp_profiler_VULN_002] Missing Security Check - Config::SetFileEnable

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-264 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `cpp/src/Config.cpp:807-820` @ `Config::SetFileEnable`
**模块**: cpp_profiler
**跨模块**: python_wrapper

**描述**: Config::SetFileEnable() writes to a configuration file without performing comprehensive security checks. It only checks IsPathLenLegal and IsPathDepthLegal (lines 807-813), but does NOT call CheckFileBeforeWrite() to verify: 1) file is not a symlink, 2) file ownership, 3) write permissions, 4) path characters validity. This could allow writing to attacker-controlled files.

**漏洞代码** (`cpp/src/Config.cpp:807-820`)

```c
if (!SecurityUtils::IsPathLenLegal(configPath)) {...return;}
if (!SecurityUtils::IsPathDepthLegal(configPath)) {...return;}
std::ofstream outputFile(configPath.c_str());
outputFile << configJson.dump(jsonIndentSize);
```

**达成路径**

configPath -> IsPathLenLegal/IsPathDepthLegal (partial check) -> ofstream::open() -> write JSON

**验证说明**: 写入配置文件缺少完整安全检查（无 CheckFileBeforeWrite），但有部分长度和深度检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-17e1e3dc] eval_injection - _execute_direct_expression

**严重性**: Medium | **CWE**: CWE-94 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: python-security-module-scanner

**位置**: `ms_service_profiler/patcher/core/dynamic_hook.py:418-439` @ `_execute_direct_expression`
**模块**: ms_service_profiler_patcher

**描述**: Potential code injection via eval() with weak expression validation. The _execute_direct_expression function uses eval() to evaluate expressions from configuration. The _validate_expression_safety function attempts to block dangerous operations but has weaknesses: (1) it checks for dangerous keywords but attribute access like 'this.__class__' could bypass, (2) dangerous operators check is incomplete, (3) function call whitelist may not cover all dangerous patterns. Although safe_globals restricts builtins, the safe_locals dict contains runtime objects that could be exploited.

**漏洞代码** (`ms_service_profiler/patcher/core/dynamic_hook.py:418-439`)

```c
safe_globals = {'__builtins__': {'len': len, 'str': str, 'int': int, 'float': float, 'bool': bool}}
return eval(expr_str, safe_globals, safe_locals)
```

**达成路径**

expr(attributes config) -> _validate_expression_safety -> eval(expr_str, safe_globals, safe_locals)

**验证说明**: eval() 使用受限制的 globals/locals，_validate_expression_safety 有部分缓解但不完整。攻击者需要控制配置中的表达式字段，但受限格式和部分验证降低了风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-ms_serviceparam_optimizer-002] unsafe_deserialization - process_execution_data_vllm

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-502 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `train/source_to_train.py:206` @ `process_execution_data_vllm`
**模块**: ms_serviceparam_optimizer

**描述**: ast.literal_eval used to parse untrusted database content in process_execution_data_vllm. While literal_eval is safer than eval, it can still parse complex literals. If database is crafted maliciously, could lead to resource exhaustion. Data from external profiler.db under user-controlled path.

**达成路径**

[IN] User input_path -> profiler.db -> fetch_rids_from_db() -> rids_ori -> ast.literal_eval

**验证说明**: ast.literal_eval 有一定安全性，但仍可解析复杂字面量导致资源消耗。攻击者需控制数据库内容。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-ms_serviceparam_optimizer-003] unsafe_deserialization - process_execution_data_mindie

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-502 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `train/source_to_train.py:272` @ `process_execution_data_mindie`
**模块**: ms_serviceparam_optimizer

**描述**: Second occurrence of ast.literal_eval parsing database content in process_execution_data_mindie. Same vulnerability pattern. Parses rids_ori from external database without validation.

**达成路径**

[IN] profiler.db -> rids_ori -> ast.literal_eval

**验证说明**: 与 VULN-ms_serviceparam_optimizer-002 相同模式，mindie 版本的 ast.literal_eval 使用。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-CROSS-004] Cross-Module IPC Credential Bypass - cross_module_ipc_flow

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: CWE-287 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `cross_module:1-20` @ `cross_module_ipc_flow`
**模块**: cross_module
**跨模块**: ms_service_profiler_tracer → ms_service_profiler

**描述**: Unix Domain Socket peer cred validation is correct but downstream modules (binary_otlp_exporter, scheduler) do not independently validate data integrity. Data flows from traced process → socket_server (validated) → data_queue → scheduler → OTLP receiver without additional integrity checks. A compromised traced process (after peer cred validation) can inject malicious data into downstream systems.

**漏洞代码** (`cross_module:1-20`)

```c
traced_process → socket_server (peer_cred OK) → data_queue → scheduler → OTLP export
```

**达成路径**

[TRUST BOUNDARY] traced process (peer cred validated) → socket_server.py
[DATA FLOW] socket_server → data_queue → scheduler.py → binary_otlp_exporter.py
[RISK] Peer cred validates identity but not data integrity. Compromised traced process can inject malformed OTLP data

**验证说明**: Unix Socket peer cred验证正确但下游模块无数据完整性检查。被入侵的 traced process 可注入恶意数据。

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 5 | mitigations: 0 | reachability: 15

---

### [ms_service_profiler-unsafe_lib-001] unsafe_library_loading - LibServiceProfiler.init

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: N/A | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ms_service_profiler/mstx.py:123` @ `LibServiceProfiler.init`
**模块**: ms_service_profiler

**描述**: Unsafe dynamic library loading via ctypes.cdll.LoadLibrary without integrity verification. The library path is validated through get_valid_lib_path with whitelist and environment variable checks, but no cryptographic signature verification is performed on the loaded library.

**达成路径**

[IN] ASCEND_HOME_PATH env → get_valid_lib_path → [OUT] ctypes.cdll.LoadLibrary → libms_service_profiler.so

**验证说明**: ctypes.CDLL 加载库无完整性验证，虽有路径白名单但无签名验证。攻击者可替换库文件。

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 5 | mitigations: 0 | reachability: 15

---

### [ms_service_profiler-toctou-001] toctou_race_condition - get_valid_lib_path

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: N/A | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ms_service_profiler/utils/file_open_check.py:392-395` @ `get_valid_lib_path`
**模块**: ms_service_profiler

**描述**: Time-of-check to time-of-use race condition in get_valid_lib_path. Path is resolved with os.path.realpath(), checked with os.path.exists() and os.access(), then loaded with ctypes.CDLL(). An attacker with filesystem access could replace the library file between the check and the load operation.

**达成路径**

[IN] ASCEND_HOME_PATH env → get_valid_lib_path → [OUT] mstx.py:123 ctypes.cdll.LoadLibrary(fp)

**验证说明**: get_valid_lib_path TOCTOU：realpath/exist/access检查和CDLL加载之间存在时间窗口，可替换库文件。

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 5 | mitigations: 0 | reachability: 10

---

## 5. Low 漏洞 (11)

### [VULN-ms_service_metric-006] Shared Memory Name Prefix from Environment Variable - __init__

**严重性**: Low（原评估: LOW → 验证后: Low） | **CWE**: CWE-15 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ms_service_metric/ms_service_metric/utils/shm_manager.py:177-182` @ `__init__`
**模块**: ms_service_metric

**描述**: Shared memory and semaphore names are derived from MS_SERVICE_METRIC_SHM_PREFIX environment variable. An attacker controlling this variable could potentially cause collision with other processes shared memory or redirect IPC to unintended targets.

**漏洞代码** (`ms_service_metric/ms_service_metric/utils/shm_manager.py:177-182`)

```c
self._shm_prefix = shm_prefix or os.environ.get(ENV_SHM_PREFIX, DEFAULT_SHM_PREFIX)\nself._shm_name = SharedMemoryLayout.get_shm_name(self._shm_prefix)
```

**达成路径**

[IN] MS_SERVICE_METRIC_SHM_PREFIX env -> SharedMemoryManager.__init__() -> shm/sem names derived -> [OUT] Potential IPC collision or redirection

**验证说明**: 共享内存名称前缀来自环境变量，可能导致 IPC 冲突或重定向。风险较低。

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CPP-006] Incomplete Regex Pattern - FILE_VALID_PATTERN

**严重性**: Low（原评估: LOW → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/include/msServiceProfiler/SecurityConstants.h:26` @ `FILE_VALID_PATTERN`
**模块**: cpp_profiler

**描述**: FILE_VALID_PATTERN regex "(\\.|\\\\|/|:|_|-|[~0-9a-zA-Z])+" allows individual characters including dot (.) but does not explicitly prevent path traversal sequences like "..". The pattern validates character set but not semantic path safety. Combined with other vulnerabilities, this provides weak path validation.

**漏洞代码** (`cpp/include/msServiceProfiler/SecurityConstants.h:26`)

```c
constexpr const char* FILE_VALID_PATTERN = "(\\.|\\\\|/|:|_|-|[~0-9a-zA-Z])+";
```

**达成路径**

[IN] path string -> regex_match(FILE_VALID_PATTERN) [OUT] IsPathCharactersValid()

**验证说明**: FILE_VALID_PATTERN 正则不阻止路径遍历序列，仅验证字符集。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-004-SOCKET-TOCTOU-RACE] Race Condition - _validate_peer_cred

**严重性**: Low（原评估: LOW → 验证后: Low） | **CWE**: CWE-367 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ms_service_profiler/tracer/socket_server.py:113-122` @ `_validate_peer_cred`
**模块**: ms_service_profiler_tracer

**描述**: Time-of-Check-Time-of-Use (TOCTOU) race condition in peer credential validation. After validating peer credentials (uid/gid/pid), the code checks namespace inodes by reading /proc/{peer_pid}/ns/pid and /proc/{peer_pid}/ns/user. If the peer process terminates between credential extraction and namespace validation, the _get_namespace_inode call will fail with FileNotFoundError. Although currently caught and returns False (safe fail), this creates an opportunity for race exploitation where a malicious process could potentially exit and be replaced.

**漏洞代码** (`ms_service_profiler/tracer/socket_server.py:113-122`)

```c
try:
    if (self._get_namespace_inode(self_pid, "pid") != self._get_namespace_inode(peer_pid, "pid") or
            self._get_namespace_inode(self_pid, "user") != self._get_namespace_inode(peer_pid, "user")):
        logger.debug(f"Connect with unexpected pid {peer_pid}.")
        return False
except Exception as e:
    logger.debug(f"Validate peer cred failed: {e}")
    return False
```

**达成路径**

_validate_peer_cred@socket_server.py:89 → _get_namespace_inode@socket_server.py:84 → os.stat(/proc/{pid}/ns/{ns_type})@socket_server.py:87

**验证说明**: peer cred 验证 TOCTOU 竞态：进程终止后 namespace 验证失败。目前 safe fail 处理。

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-006-ACL-BYPASS] Incomplete Permission Check - check_linux_permission

**严重性**: Low（原评估: LOW → 验证后: Low） | **CWE**: CWE-264 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ms_service_profiler/utils/file_open_check.py:244-273` @ `check_linux_permission`
**模块**: utils_security

**描述**: check_linux_permission函数仅检查基本Unix权限位，未考虑POSIX ACL、Linux Capabilities等复杂权限机制。文件可能通过ACL授予其他用户权限，但此检查无法检测，导致权限判断不完整。

**漏洞代码** (`ms_service_profiler/utils/file_open_check.py:244-273`)

```c
def check_linux_permission(perm=none, strict_permission=True): if perm == read: if self.permission & READ_FILE_NOT_PERMITTED_STAT > 0: ... # 仅检查基本权限位，未检查ACL和capabilities
```

**验证说明**: check_linux_permission 仅检查基本Unix权限位，未考虑 POSIX ACL 和 Linux Capabilities。权限判断不完整。

**评分明细**: base: 30 | controllability: 5 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-CPP-HEADERS-001] Format String Vulnerability - PROF_LOG* macros

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-134 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/cpp/include/msServiceProfiler/Log.h:47-82` @ `PROF_LOG* macros`
**模块**: cpp_headers

**描述**: PROF_LOGD, PROF_LOGI, PROF_LOGW, PROF_LOGE macros use printf(__VA_ARGS__) without format specifier protection. If user-controlled data is passed as the first argument, it could lead to format string vulnerabilities allowing memory read/write.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/cpp/include/msServiceProfiler/Log.h:47-82`)

```c
#define PROF_LOGD(...) printf(__VA_ARGS__);
```

**达成路径**

[IN] User input via __VA_ARGS__ -> printf() -> stdout

**验证说明**: printf(__VA_ARGS__) 无格式保护，但日志内容多为内部生成，用户可控输入有限。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -10 | cross_file: 0

---

### [msservice_advisor_model_weight_path_taint_001] Path Traversal via Configuration - extract_model_config_params

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: python-dataflow-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/msservice_advisor/msservice_advisor/profiling_analyze/npu_memory_analyze.py:77-126` @ `extract_model_config_params`
**模块**: msservice_advisor
**跨模块**: msservice_advisor → msguard

**描述**: model_weight_path is read from user-controlled JSON config file and used for directory traversal and file reads. While Rule.input_dir_traverse validation is applied, the source is still user-provided config.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/msservice_advisor/msservice_advisor/profiling_analyze/npu_memory_analyze.py:77-126`)

```c
model_weight_path = model_configs.get("modelWeightPath")
```

**达成路径**

[IN] service_config_path -> read_csv_or_json -> modelWeightPath from JSON (line 77) -> extract_model_config_params (line 424) -> Rule.input_dir_traverse validation (line 118) -> get_directory_size and read_csv_or_json (lines 129, 126) [OUT]

**验证说明**: 配置文件中的 modelWeightPath 有 Rule.input_dir_traverse 验证，降低风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [ms_service_metric-CWE453-env_ipc] INSUFFICIENT_INPUT_VALIDATION - __init__

**严重性**: Low（原评估: LOW → 验证后: Low） | **CWE**: CWE-453 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ms_service_metric/ms_service_metric/utils/shm_manager.py:177-178` @ `__init__`
**模块**: ms_service_metric

**描述**: shm_prefix and max_procs come from environment variables MS_SERVICE_METRIC_SHM_PREFIX and MS_SERVICE_METRIC_MAX_PROCS without validation (lines 177-178). Malicious prefix (e.g. /existing_ipc_name) could potentially interfere with other processes IPC objects. max_procs unbounded could cause memory exhaustion in shared memory allocation.

**达成路径**

MS_SERVICE_METRIC_SHM_PREFIX/MS_SERVICE_METRIC_MAX_PROCS (env) -> SharedMemoryManager.__init__ -> SharedMemoryLayout.calc_memory_size

**验证说明**: shm_prefix 和 max_procs 来自环境变量无验证。恶意prefix可干扰其他进程IPC，max_procs无限制可内存耗尽。

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 10

---

### [VULN-CPP-HEADERS-002] Buffer Overflow - ResID::ResID(const char*)

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-120 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/cpp/include/msServiceProfiler/Profiler.h:56-63` @ `ResID::ResID(const char*)`
**模块**: cpp_headers

**描述**: ResID constructor for string type performs manual character copy into fixed buffer strRid[MAX_RES_STR_IZE=128] without explicit bounds validation. While it stops at MAX_RES_STR_IZE-1, the input string length is not checked before the loop, potentially causing issues with very long strings.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/cpp/include/msServiceProfiler/Profiler.h:56-63`)

```c
ResID(const char *strRid) noexcept : type(ResType::STRING) { ... manual copy loop ... }
```

**达成路径**

[IN] strRid parameter -> manual loop copy -> resValue.strRid[128]

**验证说明**: ResID 构造函数有边界检查（截断而非溢出），但超长输入被截断可能导致数据完整性问题。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [cpp_profiler_VULN_005] Insecure Environment Variable Access - MsUtils::GetEnvAsString

**严重性**: Low | **CWE**: CWE-264 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `cpp/include/msServiceProfiler/Utils.h:72-76` @ `MsUtils::GetEnvAsString`
**模块**: cpp_profiler

**描述**: Utils.h::GetEnvAsString() uses unsafe getenv() instead of secure_getenv(). While SecurityUtilsLog.cpp correctly uses secure_getenv() for SECURITY_UTILS_LOG_LEVEL, the critical SERVICE_PROF_CONFIG_PATH environment variable is read via the insecure getenv() through MsUtils::GetEnvAsString(). This could allow environment variable manipulation in setuid/setgid contexts.

**漏洞代码** (`cpp/include/msServiceProfiler/Utils.h:72-76`)

```c
inline std::string GetEnvAsString(const std::string &envName)
{
    const char *value = getenv(envName.c_str());
    return std::string((value != nullptr) ? value : "");
};
```

**达成路径**

envName -> getenv() [insecure] -> returned string value

**验证说明**: 使用 getenv() 替代 secure_getenv()，仅在 setuid/setgid 上下文有风险。当前部署模型不涉及特权上下文。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: -15 | cross_file: 0

---

### [msservice_advisor_env_var_trust_001] Improper Input Validation - get_mindie_server_config_path

**严重性**: Low | **CWE**: CWE-807 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: python-dataflow-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/msservice_advisor/msservice_advisor/advisor.py:114-131` @ `get_mindie_server_config_path`
**模块**: msservice_advisor

**描述**: Environment variable MIES_INSTALL_PATH is trusted without validation and used to construct file paths. If attacker controls env var, they can redirect file reads.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/msservice_advisor/msservice_advisor/advisor.py:114-131`)

```c
service_config_path = os.getenv(MIES_INSTALL_PATH, MINDIE_SERVICE_DEFAULT_PATH)
```

**达成路径**

[IN] Environment variable MIES_INSTALL_PATH (line 114) -> fallback path construction -> os.path.join (line 118) -> read_csv_or_json (line 131) -> [OUT] mindie_service_config data

**验证说明**: 环境变量 MIES_INSTALL_PATH 无验证用于路径构造。攻击者需已有访问权限才能修改环境变量。

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp_profiler_VULN_003] Incomplete Symlink Check - SecurityUtils::CheckFileBeforeRead

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-264 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `cpp/src/SecurityUtils.cpp:268-300` @ `SecurityUtils::CheckFileBeforeRead`
**模块**: cpp_profiler

**描述**: SecurityUtils::CheckFileBeforeRead() only checks if the final path component is a symlink (line 270) using IsSoftLink(), but does NOT check intermediate path components using CheckPathContainSoftLink(). An attacker could create a symlink in a parent directory to bypass the check and read arbitrary files.

**漏洞代码** (`cpp/src/SecurityUtils.cpp:268-300`)

```c
bool CheckFileBeforeRead(const std::string &path, long long maxSize)
{
    if (IsSoftLink(path)) {
        return false;
    }
    const auto absPath = GetRealPath(path);
    if (!IsPathLenLegal(absPath) || !IsPathCharactersValid(absPath) || !IsFile(absPath)) {...
```

**达成路径**

path -> IsSoftLink(path) [only checks final component] -> GetRealPath -> stat checks

**验证说明**: CheckFileBeforeRead 只检查最终路径组件软链接，攻击者可在父目录创建软链接绕过。静态函数降低攻击面。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: -15 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cpp_headers | 0 | 1 | 0 | 2 | 3 |
| cpp_profiler | 0 | 3 | 7 | 3 | 13 |
| cross_module | 0 | 2 | 2 | 0 | 4 |
| ms_service_metric | 0 | 0 | 4 | 2 | 6 |
| ms_service_profiler | 0 | 0 | 2 | 0 | 2 |
| ms_service_profiler_patcher | 0 | 4 | 2 | 0 | 6 |
| ms_service_profiler_tracer | 0 | 1 | 3 | 1 | 5 |
| ms_serviceparam_optimizer | 0 | 0 | 5 | 0 | 5 |
| msservice_advisor | 0 | 0 | 1 | 2 | 3 |
| utils_security | 0 | 2 | 7 | 1 | 10 |
| **合计** | **0** | **13** | **33** | **11** | **57** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-367 | 7 | 12.3% |
| CWE-22 | 7 | 12.3% |
| CWE-94 | 5 | 8.8% |
| CWE-264 | 5 | 8.8% |
| CWE-15 | 4 | 7.0% |
| CWE-426 | 3 | 5.3% |
| N/A | 3 | 5.3% |
| CWE-73 | 2 | 3.5% |
| CWE-59 | 2 | 3.5% |
| CWE-502 | 2 | 3.5% |
| CWE-400 | 2 | 3.5% |
| CWE-287 | 2 | 3.5% |
| CWE-807 | 1 | 1.8% |
| CWE-80 | 1 | 1.8% |
| CWE-789 | 1 | 1.8% |
| CWE-772 | 1 | 1.8% |
| CWE-770 | 1 | 1.8% |
| CWE-74 | 1 | 1.8% |
| CWE-453 | 1 | 1.8% |
| CWE-362 | 1 | 1.8% |
| CWE-342 | 1 | 1.8% |
| CWE-269 | 1 | 1.8% |
| CWE-20 | 1 | 1.8% |
| CWE-134 | 1 | 1.8% |
| CWE-120 | 1 | 1.8% |
