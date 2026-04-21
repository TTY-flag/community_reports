# 漏洞扫描报告 — 已确认漏洞

**项目**: MindStudio-Service-Profiler
**扫描时间**: 2026-04-20T23:50:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

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
| Critical | 8 | 66.7% |
| High | 4 | 33.3% |
| **有效漏洞总计** | **12** | - |
| 误报 (FALSE_POSITIVE) | 8 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-001-CONFIG-IMPORT]** arbitrary_code_execution (Critical) - `config_loader.py:82` @ `_resolve_handler_func` | 置信度: 95
2. **[VULN-002-METRICS-IMPORT]** arbitrary_code_execution (Critical) - `config_loader.py:118` @ `_resolve_metrics_handler_func` | 置信度: 95
3. **[VULN-ms_service_metric-001]** Code Injection via Configuration Handler Import (Critical) - `ms_service_metric/ms_service_metric/core/handler.py:466` @ `_import_handler` | 置信度: 95
4. **[VULN-003-RESOLVER-IMPORT]** arbitrary_code_execution (Critical) - `dynamic_hook.py:571` @ `HandlerResolver._try_import` | 置信度: 90
5. **[VULN-005-MODULE-IMPORT]** arbitrary_code_execution (Critical) - `module_hook.py:73` @ `import_object_from_string` | 置信度: 90
6. **[VULN-CROSS-001]** Cross-Module Credential Flow Attack (Critical) - `cross_module:1` @ `cross_module_handler_flow` | 置信度: 90
7. **[XM-VULN-001]** arbitrary_code_execution (Critical) - `ms_service_profiler/mstx.py:116` @ `LibServiceProfiler.init` | 置信度: 90
8. **[XM-VULN-002]** arbitrary_code_execution (Critical) - `ms_service_profiler/patcher/core/config_loader.py:96` @ `_resolve_handler_func` | 置信度: 90
9. **[VULN-UTILS-003]** Improper Control of Environment Variable (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/ms_service_profiler/utils/file_open_check.py:377` @ `get_valid_lib_path` | 置信度: 90
10. **[VULN-001-TOCTOU-MSOPEN]** TOCTOU (High) - `ms_service_profiler/utils/file_open_check.py:320` @ `ms_open` | 置信度: 90

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

## 3. Critical 漏洞 (8)

### [VULN-001-CONFIG-IMPORT] arbitrary_code_execution - _resolve_handler_func

**严重性**: Critical（原评估: critical → 验证后: Critical） | **CWE**: N/A | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `config_loader.py:82-110` @ `_resolve_handler_func`
**模块**: ms_service_profiler_patcher

**描述**: Dynamic import of arbitrary modules from YAML configuration. The _resolve_handler_func() function uses importlib.import_module() with module paths specified in YAML config files without validation. If config file is attacker-controlled, arbitrary code execution is possible via malicious handler paths like os:system or subprocess:call.

**达成路径**

yaml_config->load_yaml_config->ConfigLoader.load_profiling->_resolve_handler_func->importlib.import_module->getattr->handler_execution

**验证说明**: 配置文件中的 handler_path 可被攻击者完全控制，实现任意模块导入和代码执行。无任何验证或白名单保护。高风险漏洞。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 10 | cross_file: 0

---

### [VULN-002-METRICS-IMPORT] arbitrary_code_execution - _resolve_metrics_handler_func

**严重性**: Critical（原评估: critical → 验证后: Critical） | **CWE**: N/A | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `config_loader.py:118-135` @ `_resolve_metrics_handler_func`
**模块**: ms_service_profiler_patcher

**描述**: Dynamic import of arbitrary modules for metrics handlers. _resolve_metrics_handler_func() uses importlib.import_module() with unvalidated module paths from YAML config, enabling arbitrary code execution.

**达成路径**

yaml_config->load_yaml_config->ConfigLoader.load_metrics->_resolve_metrics_handler_func->importlib.import_module->getattr

**验证说明**: metrics handler 配置同样可被攻击者完全控制，实现任意模块导入和代码执行。与 VULN-001 相同风险。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 10 | cross_file: 0

---

### [VULN-ms_service_metric-001] Code Injection via Configuration Handler Import - _import_handler

**严重性**: Critical（原评估: HIGH → 验证后: Critical） | **CWE**: CWE-94 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `ms_service_metric/ms_service_metric/core/handler.py:466-489` @ `_import_handler`
**模块**: ms_service_metric
**跨模块**: symbol_config.py,handler.py,symbol_handler_manager.py

**描述**: Arbitrary code execution via malicious YAML configuration. The handler field in YAML config specifies a module:function path that is dynamically imported using importlib.import_module. If MS_SERVICE_METRIC_CONFIG_PATH environment variable points to a malicious config, arbitrary code can be executed when the handler module is imported.

**漏洞代码** (`ms_service_metric/ms_service_metric/core/handler.py:466-489`)

```c
module = importlib.import_module(module_path)\nfunc = getattr(module, func_name, None)
```

**达成路径**

[IN] MS_SERVICE_METRIC_CONFIG_PATH env -> SymbolConfig.load() -> yaml.safe_load() -> MetricHandler.from_config() -> _import_handler() -> importlib.import_module() -> [OUT] ARBITRARY CODE EXECUTION

**验证说明**: MS_SERVICE_METRIC_CONFIG_PATH 环境变量指向恶意配置，handler 字段指定任意模块导入执行代码。无验证保护。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 10 | cross_file: 0

---

### [VULN-003-RESOLVER-IMPORT] arbitrary_code_execution - HandlerResolver._try_import

**严重性**: Critical（原评估: high → 验证后: Critical） | **CWE**: N/A | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `dynamic_hook.py:571-620` @ `HandlerResolver._try_import`
**模块**: ms_service_profiler_patcher

**描述**: HandlerResolver uses importlib.import_module() with user-controlled handler paths. HandlerResolver._try_import() imports arbitrary modules specified in configuration, enabling code execution if config is attacker-controlled.

**达成路径**

config->HandlerResolver.resolve->HandlerResolver._try_import->importlib.import_module

**验证说明**: HandlerResolver._try_import 通过配置中的 handler_val 导入任意模块，无验证。高风险代码注入。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 10 | cross_file: 0

---

### [VULN-005-MODULE-IMPORT] arbitrary_code_execution - import_object_from_string

**严重性**: Critical（原评估: high → 验证后: Critical） | **CWE**: N/A | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `module_hook.py:73-102` @ `import_object_from_string`
**模块**: ms_service_profiler_patcher

**描述**: import_object_from_string() uses importlib.import_module() with arbitrary import_path parameter. When called from DynamicHooker.init(), the import_path comes from YAML configuration hook_list.

**达成路径**

[IN]config_hook_list->DynamicHooker.init->import_object_from_string->importlib.import_module

**验证说明**: import_object_from_string 从配置导入任意模块，无验证或白名单。高风险漏洞。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 10 | cross_file: 0

---

### [VULN-CROSS-001] Cross-Module Credential Flow Attack - cross_module_handler_flow

**严重性**: Critical（原评估: critical → 验证后: Critical） | **CWE**: CWE-94 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `cross_module:1-100` @ `cross_module_handler_flow`
**模块**: cross_module
**跨模块**: ms_service_profiler_patcher → ms_service_metric → cpp_profiler → utils_security

**描述**: Cross-module dynamic import attack chain: Environment variables control config file paths across multiple modules. MS_SERVICE_METRIC_CONFIG_PATH → symbol_config.py → handler.py:_import_handler → arbitrary module import. SERVICE_PROF_CONFIG_PATH → Config.cpp → C++ library initialization. The attack chain allows arbitrary code execution through either Python or C++ entry points.

**漏洞代码** (`cross_module:1-100`)

```c
ENV_VARS → config_loader.py/symbol_config.py → importlib.import_module → arbitrary execution
```

**达成路径**

[PYTHON] MS_SERVICE_METRIC_CONFIG_PATH → symbol_config.py → handler.py → importlib.import_module → arbitrary code
[C++] SERVICE_PROF_CONFIG_PATH → Config.cpp → JSON config parsed → dlopen initialization
[CROSS] Python ctypes → C++ SecurityUtils → TOCTOU vulnerabilities propagate

**验证说明**: 跨模块动态导入攻击链：环境变量控制配置文件路径，通过 handler 字段实现任意代码执行。Python 和 C++ 入口点均可被利用。

**评分明细**: base: 30 | controllability: 30 | context: 10 | cross_file: 20 | mitigations: 0 | reachability: 30

---

### [XM-VULN-001] arbitrary_code_execution - LibServiceProfiler.init

**严重性**: Critical（原评估: critical → 验证后: Critical） | **CWE**: CWE-426 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `ms_service_profiler/mstx.py:116-123` @ `LibServiceProfiler.init`
**模块**: cross_module
**跨模块**: utils_security → ms_service_profiler → cpp_headers

**描述**: 跨模块动态库加载路径污染: ASCEND_HOME_PATH环境变量在utils_security/file_open_check.py中被读取，路径传递至ms_service_profiler/mstx.py通过ctypes.CDLL加载。攻击者控制ASCEND_HOME_PATH可加载恶意动态库，实现任意代码执行。

**达成路径**

[IN] ASCEND_HOME_PATH env → get_valid_lib_path@file_open_check.py:386 → realpath → [OUT] ctypes.cdll.LoadLibrary@mstx.py:123

**验证说明**: ASCEND_HOME_PATH 跨模块库路径污染：环境变量控制 get_valid_lib_path 和 ctypes.CDLL 加载路径，可加载恶意库。

**评分明细**: base: 30 | controllability: 30 | context: 0 | cross_file: 20 | mitigations: 0 | reachability: 30

---

### [XM-VULN-002] arbitrary_code_execution - _resolve_handler_func

**严重性**: Critical（原评估: critical → 验证后: Critical） | **CWE**: CWE-94 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `ms_service_profiler/patcher/core/config_loader.py:96-102` @ `_resolve_handler_func`
**模块**: cross_module
**跨模块**: ms_service_profiler_patcher → ms_service_metric

**描述**: 跨模块配置驱动代码执行: YAML配置文件中的handler字段(格式module.path:func_name)在ms_service_profiler_patcher/config_loader.py中被解析，通过importlib.import_module动态导入任意模块。该机制在ms_service_metric中同样存在(handler.py)。攻击者控制配置文件可执行任意代码。

**达成路径**

[IN] YAML config handler字段 → config_loader.py:87 → importlib.import_module(mod_str) → getattr → [OUT] handler_func执行

**验证说明**: 跨模块配置驱动代码执行：YAML handler 字段通过 importlib.import_module 导入任意模块，实现任意代码执行。

**评分明细**: base: 30 | controllability: 30 | context: 10 | cross_file: 10 | mitigations: 0 | reachability: 30

---

## 4. High 漏洞 (4)

### [VULN-UTILS-003] Improper Control of Environment Variable - get_valid_lib_path

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-15 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/ms_service_profiler/utils/file_open_check.py:377-397` @ `get_valid_lib_path`
**模块**: utils_security

**描述**: get_valid_lib_path() reads ASCEND_HOME_PATH environment variable without validation and uses it directly to construct library path. An attacker controlling the environment can inject arbitrary paths, potentially loading malicious libraries.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Service-Profiler/ms_service_profiler/utils/file_open_check.py:377-397`)

```c
ascend_home = os.getenv(ASCEND_HOME_PATH); candidate_path = os.path.join(ascend_home, ...)
```

**达成路径**

[IN] ASCEND_HOME_PATH env -> os.getenv() -> os.path.join() -> ctypes.cdll.LoadLibrary() [OUT] mstx.py

**验证说明**: ASCEND_HOME_PATH 环境变量控制动态库加载路径，可加载恶意库实现任意代码执行。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-001-TOCTOU-MSOPEN] TOCTOU - ms_open

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-367 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `ms_service_profiler/utils/file_open_check.py:320-358` @ `ms_open`
**模块**: utils_security

**描述**: ms_open函数存在Time-of-Check to Time-of-Use漏洞。FileStat在构造时缓存文件状态信息(os.stat)，后续的软链接检查(line 335)和父目录安全检查(line 343)与最终的os.open(line 358)之间存在时间窗口。攻击者可在此窗口内替换文件为软链接，绕过安全检查访问非预期文件。

**漏洞代码** (`ms_service_profiler/utils/file_open_check.py:320-358`)

```c
file_stat = FileStat(file)  # line 322 - 缓存stat
if not softlink and file_stat.is_softlink:  # line 335
    raise OpenException(...)
safe_parent_msg = Rule.path().is_safe_parent_dir().check(file)  # line 343
return os.fdopen(os.open(file, flags, mode=write_permission), mode, **kwargs)  # line 358
```

**验证说明**: ms_open 函数 TOCTOU 漏洞：FileStat 缓存后与 os.open 之间存在时间窗口，可替换文件绕过检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CROSS-002] Cross-Language Library Loading Chain - cross_module_lib_loading

**严重性**: High（原评估: high → 验证后: High） | **CWE**: CWE-426 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `cross_module:1-50` @ `cross_module_lib_loading`
**模块**: cross_module
**跨模块**: ms_service_profiler → cpp_headers → utils_security

**描述**: Cross-language library loading vulnerability chain: ASCEND_HOME_PATH environment variable controls library path for both Python (mstx.py:ctypes.CDLL) and C++ (ServiceProfilerInterface.h:dlopen). If attacker controls ASCEND_HOME_PATH, they can redirect library loading to malicious .so files in both language layers. The Python get_valid_lib_path() has weak validation (only checks library name whitelist, not full path).

**漏洞代码** (`cross_module:1-50`)

```c
ASCEND_HOME_PATH → Python mstx.py → get_valid_lib_path → ctypes.CDLL
ASCEND_HOME_PATH → C++ ServiceProfilerInterface.h → realpath → dlopen
```

**达成路径**

[PYTHON] ASCEND_HOME_PATH → get_valid_lib_path() → ctypes.cdll.LoadLibrary → libms_service_profiler.so
[C++] ASCEND_HOME_PATH → realpath() → dlopen() → same library
[ATTACK] Control ASCEND_HOME_PATH → malicious libms_service_profiler.so → arbitrary code in both Python and C++

**验证说明**: 跨语言库加载链：ASCEND_HOME_PATH 控制Python和C++库加载路径，可加载恶意.so文件实现代码执行。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 20 | mitigations: 0 | reachability: 30

---

### [VULN-ms_service_metric-005] Bytecode Injection with Untrusted Handler - inject_function

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-94 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `ms_service_metric/ms_service_metric/core/hook/inject.py:55-234` @ `inject_function`
**模块**: ms_service_metric
**跨模块**: inject.py,handler.py,symbol_handler_manager.py

**描述**: Bytecode injection mechanism allows arbitrary code execution within hooked function context. If malicious handlers are loaded via configuration, they are injected into target functions using bytecode manipulation and types.FunctionType, allowing execution of arbitrary code with access to function locals.

**漏洞代码** (`ms_service_metric/ms_service_metric/core/hook/inject.py:55-234`)

```c
return types.FunctionType(\n    new_code,\n    new_globals,\n    ori_func.__name__,\n    ori_func.__defaults__,\n    ori_func.__closure__\n)
```

**达成路径**

[IN] Handler from config -> inject_function() -> bytecode manipulation -> types.FunctionType() -> [OUT] Code execution in hooked function context

**验证说明**: 字节码注入机制允许在 hooked 函数上下文中执行任意代码。若加载恶意 handler 可完全控制。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cross_module | 3 | 1 | 0 | 0 | 4 |
| ms_service_metric | 1 | 1 | 0 | 0 | 2 |
| ms_service_profiler_patcher | 4 | 0 | 0 | 0 | 4 |
| utils_security | 0 | 2 | 0 | 0 | 2 |
| **合计** | **8** | **4** | **0** | **0** | **12** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-94 | 4 | 33.3% |
| N/A | 4 | 33.3% |
| CWE-426 | 2 | 16.7% |
| CWE-367 | 1 | 8.3% |
| CWE-15 | 1 | 8.3% |
