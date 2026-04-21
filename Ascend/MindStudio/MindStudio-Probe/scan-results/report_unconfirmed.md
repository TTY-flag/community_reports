# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-Probe
**扫描时间**: 2025-04-20T20:39:00+08:00
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 16 | 47.1% |
| CONFIRMED | 7 | 20.6% |
| FALSE_POSITIVE | 6 | 17.6% |
| POSSIBLE | 5 | 14.7% |
| **总计** | **34** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 13 | 61.9% |
| Medium | 6 | 28.6% |
| Low | 2 | 9.5% |
| **有效漏洞总计** | **21** | - |
| 误报 (FALSE_POSITIVE) | 6 | - |

### 1.3 Top 10 关键漏洞

1. **[MSACCUCMP-DESER-001]** unsafe_deserialization (High) - `python/msprobe/msaccucmp/dump_parse/big_dump_data.py:245` @ `read_numpy_file` | 置信度: 80
2. **[MSACCUCMP-DESER-002]** unsafe_deserialization (High) - `python/msprobe/msaccucmp/overflow/overflow_analyse.py:84` @ `npy_data_summary` | 置信度: 80
3. **[INFER-DESER-001]** unsafe_deserialization (High) - `python/msprobe/infer/offline/compare/msquickcmp/common/convert.py:64` @ `convert` | 置信度: 80
4. **[INFER-DESER-002]** unsafe_deserialization (High) - `python/msprobe/infer/offline/compare/msquickcmp/net_compare/net_compare.py:189` @ `compare_net_output` | 置信度: 80
5. **[SEC-DESERIALIZATION-CHAIN-001]** unsafe_deserialization_chain (High) - `python/msprobe/msaccucmp/dump_parse/big_dump_data.py:245` @ `read_numpy_file` | 置信度: 80
6. **[atb_probe_cwe73_config_injection_001]** external_control_file_path (High) - `ccsrc/atb_probe/atb_probe.cpp:998` @ `IsTensorNeedSave/UpdateConfig` | 置信度: 75
7. **[PYTORCH-DESERIALIZATION-001]** unsafe_deserialization (High) - `python/msprobe/pytorch/common/utils.py:335` @ `load_pt` | 置信度: 75
8. **[MSACCUCMP-CODEEXEC-001]** code_execution (High) - `python/msprobe/msaccucmp/algorithm_manager/algorithm_manager.py:290` @ `load_custom_algorithm` | 置信度: 75
9. **[SEC-CROSS-CONFIG-001]** cross_boundary_security (High) - `ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:44` @ `InitPrecisionDebugger` | 置信度: 75
10. **[SEC-CUSTOM-CODE-EXEC-001]** arbitrary_code_execution (High) - `python/msprobe/msaccucmp/algorithm_manager/algorithm_manager.py:290` @ `load_custom_algorithm` | 置信度: 75

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main()@python/msprobe/msprobe.py` | cmdline | - | - | - |
| `InitPrecisionDebugger@ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp` | decorator | - | - | - |

**其他攻击面**:
- [object Object]
- [object Object]
- [object Object]

---

## 3. High 漏洞 (13)

### [MSACCUCMP-DESER-001] unsafe_deserialization - read_numpy_file

**严重性**: High | **CWE**: CWE-502 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `python/msprobe/msaccucmp/dump_parse/big_dump_data.py:245` @ `read_numpy_file`
**模块**: msaccucmp

**描述**: np.load() without allow_pickle=False in big_dump_data.py - can execute arbitrary code via malicious .npy files

**漏洞代码** (`python/msprobe/msaccucmp/dump_parse/big_dump_data.py:245`)

```c
numpy_data = np.load(self.dump_file_path) - missing allow_pickle=False
```

**达成路径**

dump_file_path -> np.load() -> arbitrary code execution

**验证说明**: np.load() without allow_pickle=False is standard deserialization vulnerability. Part of SEC-DESERIALIZATION-CHAIN-001.

---

### [MSACCUCMP-DESER-002] unsafe_deserialization - npy_data_summary

**严重性**: High | **CWE**: CWE-502 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `python/msprobe/msaccucmp/overflow/overflow_analyse.py:84` @ `npy_data_summary`
**模块**: msaccucmp

**描述**: np.load() without allow_pickle=False in overflow_analyse.py

**漏洞代码** (`python/msprobe/msaccucmp/overflow/overflow_analyse.py:84`)

```c
data = np.load(source_data) - missing allow_pickle=False
```

**达成路径**

source_data -> np.load() -> arbitrary code execution

**验证说明**: Same pattern as MSACCUCMP-DESER-001. np.load() deserialization risk.

---

### [INFER-DESER-001] unsafe_deserialization - convert

**严重性**: High | **CWE**: CWE-502 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `python/msprobe/infer/offline/compare/msquickcmp/common/convert.py:64` @ `convert`
**模块**: infer

**描述**: np.load() without allow_pickle=False in convert.py

**漏洞代码** (`python/msprobe/infer/offline/compare/msquickcmp/common/convert.py:64`)

```c
npy_data = np.load(input_item_path)
```

**达成路径**

input_item_path -> np.load() -> arbitrary code execution

**验证说明**: np.load() without allow_pickle=False. Part of SEC-DESERIALIZATION-CHAIN-001.

---

### [INFER-DESER-002] unsafe_deserialization - compare_net_output

**严重性**: High | **CWE**: CWE-502 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `python/msprobe/infer/offline/compare/msquickcmp/net_compare/net_compare.py:189-192` @ `compare_net_output`
**模块**: infer

**描述**: Multiple np.load() calls without allow_pickle=False in net_compare.py

**漏洞代码** (`python/msprobe/infer/offline/compare/msquickcmp/net_compare/net_compare.py:189-192`)

```c
npu_data = np.load(...); golden_data = np.load(...)
```

**达成路径**

CLI args -> np.load() -> code execution

**验证说明**: Same as INFER-DESER-001. Multiple np.load() calls in net_compare.py.

---

### [SEC-DESERIALIZATION-CHAIN-001] unsafe_deserialization_chain - read_numpy_file

**严重性**: High | **CWE**: CWE-502 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `python/msprobe/msaccucmp/dump_parse/big_dump_data.py:245` @ `read_numpy_file`
**模块**: cross_module
**跨模块**: core → pytorch → msaccucmp → infer

**描述**: Multiple modules use np.load() and torch.load() without safe deserialization settings, forming a chain of deserialization vulnerabilities across core, pytorch, msaccucmp, and infer modules. Malicious pickle data can execute arbitrary code.

**漏洞代码** (`python/msprobe/msaccucmp/dump_parse/big_dump_data.py:245`)

```c
np.load() calls across multiple modules without allow_pickle=False
```

**达成路径**

[core/pytorch/msaccucmp/infer] np.load/torch.load -> pickle deserialization -> arbitrary code execution

**验证说明**: Multiple np.load() and torch.load() calls without allow_pickle=False. Standard Python deserialization vulnerability pattern. Malicious pickle can execute arbitrary code.

---

### [atb_probe_cwe73_config_injection_001] external_control_file_path - IsTensorNeedSave/UpdateConfig

**严重性**: High | **CWE**: CWE-73 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `ccsrc/atb_probe/atb_probe.cpp:998-1073` @ `IsTensorNeedSave/UpdateConfig`
**模块**: atb_probe

**描述**: ATB_DUMP_CONFIG environment variable controls config file path and content parsing

**漏洞代码** (`ccsrc/atb_probe/atb_probe.cpp:998-1073`)

```c
config parsing from ATB_DUMP_CONFIG env
```

**达成路径**

ATB_DUMP_CONFIG (env) -> ifstream -> config parsing -> program behavior

**验证说明**: ATB_DUMP_CONFIG env controls config file path. Local attacker can inject malicious config.

---

### [PYTORCH-DESERIALIZATION-001] unsafe_deserialization - load_pt

**严重性**: High | **CWE**: CWE-502 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `python/msprobe/pytorch/common/utils.py:335-340` @ `load_pt`
**模块**: pytorch

**描述**: torch.load() in load_pt() can execute arbitrary code if weights_only=False

**漏洞代码** (`python/msprobe/pytorch/common/utils.py:335-340`)

```c
torch.load(pt_path, weights_only=weights_only) - potential unsafe fallback
```

**达成路径**

pt_path -> torch.load -> arbitrary code execution

**验证说明**: torch.load() without weights_only=True can execute arbitrary code. Part of SEC-DESERIALIZATION-CHAIN-001.

---

### [MSACCUCMP-CODEEXEC-001] code_execution - load_custom_algorithm

**严重性**: High | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `python/msprobe/msaccucmp/algorithm_manager/algorithm_manager.py:290-294` @ `load_custom_algorithm`
**模块**: msaccucmp

**描述**: Dynamic import of user-provided custom algorithm scripts via importlib

**漏洞代码** (`python/msprobe/msaccucmp/algorithm_manager/algorithm_manager.py:290-294`)

```c
importlib.import_module(custom_script) - code execution
```

**达成路径**

custom_script_path -> importlib.import_module -> code execution

**验证说明**: importlib.import_module() with user-provided path allows arbitrary code execution. Duplicate of SEC-CUSTOM-CODE-EXEC-001.

---

### [SEC-CROSS-CONFIG-001] cross_boundary_security - InitPrecisionDebugger

**严重性**: High | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:44-58` @ `InitPrecisionDebugger`
**模块**: cross_module
**跨模块**: pytorch → core → adump

**描述**: Python-to-C++ config_path boundary lacks unified security validation. Python layer validation may be incomplete; C++ LoadConfig does not perform additional path security checks before file operations. If Python validation fails or is bypassed, arbitrary path operations can occur in C++ layer.

**漏洞代码** (`ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:44-58`)

```c
std::string cfgFile = kwArgs.GetItem("config_path"); Initialize(framework, cfgFile) -> no path validation
```

**达成路径**

[PYTHON:pytorch/core] config_path -> [CPP:adump] InitPrecisionDebugger -> Initialize -> LoadConfig -> GetOutputPath

**验证说明**: Python config_path flows to C++ without unified validation. C++ LoadConfig uses GetAbsPath which resolves .. but may not prevent all attacks. Need deeper analysis of Python-side validation.

---

### [SEC-CUSTOM-CODE-EXEC-001] arbitrary_code_execution - load_custom_algorithm

**严重性**: High | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `python/msprobe/msaccucmp/algorithm_manager/algorithm_manager.py:290-294` @ `load_custom_algorithm`
**模块**: msaccucmp

**描述**: Dynamic import of user-provided custom algorithm scripts via importlib.import_module(). This allows execution of arbitrary Python code by specifying malicious script paths.

**漏洞代码** (`python/msprobe/msaccucmp/algorithm_manager/algorithm_manager.py:290-294`)

```c
importlib.import_module(custom_script) - arbitrary code execution
```

**达成路径**

custom_script_path -> importlib.import_module -> code execution

**验证说明**: importlib.import_module() with user-provided script path allows arbitrary code execution. Need to verify if script path is validated/sandboxed.

---

### [atb_probe_cwe22_path_traversal_001] path_traversal - GetRealPath

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `ccsrc/atb_probe/utils/utils.cpp:26-31` @ `GetRealPath`
**模块**: atb_probe

**描述**: GetRealPath() does NOT use realpath() - only handles symlinks but does not resolve .. sequences

**漏洞代码** (`ccsrc/atb_probe/utils/utils.cpp:26-31`)

```c
std::experimental::filesystem::path - no realpath() call
```

**达成路径**

ATB_OUTPUT_DIR -> GetRealPath (flawed) -> directory creation

**验证说明**: GetRealPath doesn't use realpath() - incomplete path resolution. Symlink handling exists but .. not resolved.

---

### [CROSS-MODULE-001] cross_module_data_flow - InitPrecisionDebugger

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:44` @ `InitPrecisionDebugger`
**模块**: cross_module
**跨模块**: pytorch → adump

**描述**: Cross-language boundary: Python config_path flows to C++ adump module for file operations. If Python validation bypasses, C++ may write to arbitrary paths.

**漏洞代码** (`ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:44`)

```c
config_path Python -> C++ InitPrecisionDebugger -> LoadConfig -> GetOutputPath
```

**达成路径**

[PYTHON:pytorch] config_path -> [CPP:adump] InitPrecisionDebugger -> LoadConfig -> GetOutputPath -> file_write

**验证说明**: Python config_path to C++ config loader. GetAbsPath sanitizes path traversal but absolute paths remain controllable. Chain complete with partial mitigation.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -20 | context: 0 | cross_file: 0

---

### [SEC-ENV-CONTROL-001] environment_control - GetOutDir/UpdateConfig/GetCurrentDeviceId

**严重性**: High | **CWE**: CWE-15 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `ccsrc/atb_probe/atb_probe.cpp:215` @ `GetOutDir/UpdateConfig/GetCurrentDeviceId`
**模块**: atb_probe

**描述**: Multiple critical behaviors controlled by environment variables without sufficient validation. ATB_OUTPUT_DIR controls output directory, ATB_DUMP_CONFIG controls config file path, ASCEND_TOOLKIT_HOME controls library loading path. All can be manipulated by local attacker.

**漏洞代码** (`ccsrc/atb_probe/atb_probe.cpp:215`)

```c
std::getenv("ATB_OUTPUT_DIR") / std::getenv("ATB_DUMP_CONFIG") / std::getenv("ASCEND_TOOLKIT_HOME")
```

**达成路径**

Environment variables -> critical behavior control (file write, config parse, library load)

**验证说明**: Multiple env vars control critical behavior. Local attacker can manipulate ATB_OUTPUT_DIR, ATB_DUMP_CONFIG, ASCEND_TOOLKIT_HOME. Partial mitigations exist but environment control is security-sensitive.

---

## 4. Medium 漏洞 (6)

### [PYTORCH-CONFIG-PATH-001] path_traversal - PrecisionDebugger.__init__

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `python/msprobe/pytorch/dump/debugger/precision_debugger.py:39-45` @ `PrecisionDebugger.__init__`
**模块**: pytorch
**跨模块**: pytorch → adump

**描述**: config_path parameter flows to C++ layer for configuration loading

**漏洞代码** (`python/msprobe/pytorch/dump/debugger/precision_debugger.py:39-45`)

```c
config_path -> load_json -> C++ LoadConfig
```

**达成路径**

config_path (Python) -> C++ adump module

**验证说明**: config_path flows to C++. Partial validation may exist in Python layer. Part of SEC-CROSS-CONFIG-001.

---

### [INFER-DESER-003] unsafe_deserialization - load_tensor

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `python/msprobe/infer/utils/util.py:87-89` @ `load_tensor`
**模块**: infer

**描述**: torch.load() with potential fallback to unsafe weights_only=False

**漏洞代码** (`python/msprobe/infer/utils/util.py:87-89`)

```c
torch.load(path, **kwargs) except pickle.UnpicklingError
```

**达成路径**

path -> torch.load() -> fallback to unsafe mode

**验证说明**: torch.load() with potential unsafe fallback. Part of SEC-DESERIALIZATION-CHAIN-001.

---

### [atb_probe_getrealpath_flawed_001] flawed_path_resolution - GetRealPath

**严重性**: Medium | **CWE**: CWE-59 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `ccsrc/atb_probe/utils/utils.cpp:26-31` @ `GetRealPath`
**模块**: atb_probe

**描述**: GetRealPath function name suggests realpath but implementation doesn't resolve .. components

**漏洞代码** (`ccsrc/atb_probe/utils/utils.cpp:26-31`)

```c
is_symlink ? read_symlink : path - missing realpath()
```

**达成路径**

Path input -> GetRealPath -> incomplete resolution

**验证说明**: GetRealPath name misleading - doesn't fully canonicalize path. Security implication depends on usage context.

---

### [SEC-ZIP-SLIP-CORE-001] zip_slip - extract_zip

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `python/msprobe/core/common/file_utils.py:943-966` @ `extract_zip`
**模块**: core

**描述**: extract_zip uses zipfile.extractall() without path validation. Archive entries containing ../ sequences can escape the target directory, potentially writing to arbitrary locations.

**漏洞代码** (`python/msprobe/core/common/file_utils.py:943-966`)

```c
zipfile.extractall(extract_dir) - no path validation for archive entries
```

**达成路径**

zip file entries with ../ -> extractall -> path traversal escape

**验证说明**: extractall() without member path validation is vulnerable to zip slip. Need to verify if extract_zip is called with user-provided zip files.

---

### [PYTORCH-SUBPROCESS-001] command_injection - run_parallel_ut

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `python/msprobe/pytorch/api_accuracy_checker/acc_check/multi_acc_check.py:145-146` @ `run_parallel_ut`
**模块**: pytorch

**描述**: subprocess.Popen in run_parallel_ut() executes Python scripts with user-controlled arguments

**漏洞代码** (`python/msprobe/pytorch/api_accuracy_checker/acc_check/multi_acc_check.py:145-146`)

```c
subprocess.Popen(cmd, shell=False) - arguments not sanitized
```

**达成路径**

ParallelUTConfig.api_files -> create_cmd -> subprocess.Popen

**验证说明**: subprocess.Popen with shell=False mitigates shell injection. But api_files argument could be manipulated. Need usage context.

---

### [VULN-ADUMP-004] path_traversal - OnAclDumpCallBack

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `ccsrc/adump/core/AclDumper.cpp:391` @ `OnAclDumpCallBack`
**模块**: adump

**描述**: ACL callback chunk->fileName used without full validation against base output directory

**漏洞代码** (`ccsrc/adump/core/AclDumper.cpp:391`)

```c
chunk->fileName used in path operations
```

**达成路径**

ACL callback fileName -> file operations

**验证说明**: ACL callback fileName may come from trusted kernel. Need to verify source of chunk->fileName.

---

## 5. Low 漏洞 (2)

### [VULN-ADUMP-003] thread_safety - GenDumpPath

**严重性**: Low | **CWE**: CWE-362 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `ccsrc/adump/core/AclDumper.cpp:120-122` @ `GenDumpPath`
**模块**: adump

**描述**: localtime() returns pointer to static buffer - not thread-safe

**漏洞代码** (`ccsrc/adump/core/AclDumper.cpp:120-122`)

```c
strftime(cTime, sizeof(cTime), "%Y%m%d%H%M%S", localtime(&pTime))
```

**达成路径**

Internal time handling -> non-thread-safe localtime

**验证说明**: localtime() is not thread-safe but this is a data race bug, not a security vulnerability. Low impact.

---

### [VULN-ADUMP-005] improper_input_validation - ParseJson

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `ccsrc/adump/base/DebuggerConfig.cpp:36` @ `ParseJson`
**模块**: adump

**描述**: JSON config field validation may be incomplete

**漏洞代码** (`ccsrc/adump/base/DebuggerConfig.cpp:36`)

```c
Config field parsing without schema validation
```

**达成路径**

config.json -> ParseJson -> internal config

**验证说明**: JSON config parsing may have incomplete validation but specific attack path unclear.

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| adump | 0 | 0 | 1 | 2 | 3 |
| atb_probe | 0 | 3 | 1 | 0 | 4 |
| core | 0 | 0 | 1 | 0 | 1 |
| cross_module | 0 | 3 | 0 | 0 | 3 |
| infer | 0 | 2 | 1 | 0 | 3 |
| msaccucmp | 0 | 4 | 0 | 0 | 4 |
| pytorch | 0 | 1 | 2 | 0 | 3 |
| **合计** | **0** | **13** | **6** | **2** | **21** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-502 | 7 | 33.3% |
| CWE-22 | 5 | 23.8% |
| CWE-94 | 2 | 9.5% |
| CWE-20 | 2 | 9.5% |
| CWE-78 | 1 | 4.8% |
| CWE-73 | 1 | 4.8% |
| CWE-59 | 1 | 4.8% |
| CWE-362 | 1 | 4.8% |
| CWE-15 | 1 | 4.8% |
