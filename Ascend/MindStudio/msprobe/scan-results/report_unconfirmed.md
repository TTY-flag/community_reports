# 漏洞扫描报告 — 待确认漏洞

**项目**: msprobe
**扫描时间**: 2026-04-20T10:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 62 | 64.6% |
| LIKELY | 25 | 26.0% |
| CONFIRMED | 6 | 6.3% |
| FALSE_POSITIVE | 3 | 3.1% |
| **总计** | **96** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 13 | 14.9% |
| Medium | 49 | 56.3% |
| Low | 25 | 28.7% |
| **有效漏洞总计** | **87** | - |
| 误报 (FALSE_POSITIVE) | 3 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-001-adump_if_python]** memory (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:73` @ `PrecisionDebuggerGetAttr` | 置信度: 90
2. **[VULN-core_config_check-001]** Path Traversal (High) - `python/msprobe/core/config_check/config_checker.py:50` @ `compare` | 置信度: 90
3. **[VULN-ADUMP-001]** TOCTOU (High) - `ccsrc/adump/utils/FileUtils.cpp:141` @ `IsFileSymbolLink` | 置信度: 85
4. **[VULN-002-adump_if_python]** api (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/if/python/CPythonAgent.cpp:44` @ `CPythonAgentRegister` | 置信度: 85
5. **[VULN-004-adump_if_python]** error_handling (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:28` @ `NewPrecisionDebugger` | 置信度: 85
6. **[adump-core-001]** Buffer Overflow (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumpDataProcessor.cpp:401` @ `ConcatenateData` | 置信度: 80
7. **[adump-core-006]** Improper Input Validation (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumpDataProcessor.cpp:896` @ `DumpToDisk` | 置信度: 80
8. **[VULN-ADUMP-002]** Path Traversal (High) - `ccsrc/adump/utils/FileUtils.cpp:88` @ `GetAbsPath` | 置信度: 80
9. **[VULN-ADUMP-006]** Permission Bypass (High) - `ccsrc/adump/utils/FileUtils.cpp:586` @ `CheckFileBeforeCreateOrWrite` | 置信度: 80
10. **[VULN-ADUMP-008]** TOCTOU (High) - `ccsrc/adump/utils/FileUtils.cpp:268` @ `DeleteFile` | 置信度: 80

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@python/msprobe/msprobe.py` | cmdline | untrusted_local | CLI 工具入口，本地用户通过命令行参数控制工具行为，参数值可被攻击者（本地非特权用户）控制 | 解析命令行参数并调用对应子命令 |
| `load_json@python/msprobe/core/common/file_utils.py` | file | untrusted_local | 读取 JSON 配置文件，文件路径由用户通过 CLI 参数传入，文件内容由用户控制 | 加载 JSON 配置文件内容 |
| `load_yaml@python/msprobe/core/common/file_utils.py` | file | untrusted_local | 读取 YAML 配置文件，文件路径由用户通过 CLI 参数传入，文件内容由用户控制 | 加载 YAML 配置文件内容 |
| `load_npy@python/msprobe/core/common/file_utils.py` | file | untrusted_local | 读取 numpy 数据文件，文件路径由用户通过 CLI 参数传入，文件内容可能包含恶意构造的数组 | 加载 numpy 数据文件 |
| `_process_dump_file@python/msprobe/core/dump/dump2db/dump2db.py` | file | untrusted_local | 处理 dump.json 文件，文件路径和数据内容由用户控制，包含大量 tensor 统计数据 | 解析 dump.json 文件并导入数据库 |
| `LoadConfig@ccsrc/adump/base/DebuggerConfig.cpp` | file | untrusted_local | C++ 层加载配置文件，配置路径由 Python 传入（来自用户 CLI 参数），配置内容由用户控制 | 加载并解析 JSON 配置文件 |
| `DumpToDisk@ccsrc/adump/core/AclDumpDataProcessor.cpp` | file | semi_trusted | 处理 ACL dump 数据并写入磁盘，数据来源为 ACL API（硬件层），但路径配置来自用户 | 处理并写入 dump 数据到磁盘 |
| `InitPrecisionDebugger@ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp` | rpc | semi_trusted | Python C API 接口，从 Python 层接收 framework 和 config_path 参数，参数来自用户 CLI | 初始化 PrecisionDebugger C++ 对象 |

**其他攻击面**:
- CLI 参数解析: argparse 解析命令行参数
- JSON 配置文件解析: nlohmann::json (C++), json.load() (Python)
- YAML 配置文件解析: yaml.safe_load()
- Numpy 文件解析: np.load() with allow_pickle=False
- Protobuf 数据解析: AclDumpMsg::DumpData.ParseFromArray()
- CSV 文件读写: pd.read_csv(), csv.writer
- Excel 文件读写: pd.read_excel(), pd.ExcelWriter
- ZIP 文件处理: zipfile.ZipFile
- 文件路径处理: os.path, FileUtils::GetAbsPath
- Python C API 边界: PyObject_Call, PyDict_GetItemString

---

## 3. High 漏洞 (13)

### [VULN-001-adump_if_python] memory - PrecisionDebuggerGetAttr

**严重性**: High | **CWE**: CWE-416 | **置信度**: 90/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:73-75` @ `PrecisionDebuggerGetAttr`
**模块**: adump_if_python

**描述**: Use After Free - Dangling pointer from temporary string. attr.ToString() creates a temporary std::string that is destroyed at end of expression, but c_str() pointer is stored and used in strcmp(). This can cause crashes or memory corruption when the temporary is destroyed before the comparison completes.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:73-75`)

```c
const char* s = attr.ToString().c_str();
```

**达成路径**

attr(name) -> ToString() -> temporary std::string -> c_str() -> const char* s -> strcmp(s, ...)

**验证说明**: Use After Free confirmed: attr.ToString().c_str() creates dangling pointer. Temporary string destroyed before strcmp completes.

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 30

---

### [VULN-core_config_check-001] Path Traversal - compare

**严重性**: High | **CWE**: CWE-22 | **置信度**: 90/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `python/msprobe/core/config_check/config_checker.py:50-53` @ `compare`
**模块**: core_config_check
**跨模块**: core_config_check,common

**描述**: Zip Slip vulnerability in extract_zip: The check_zip_file function only validates file size/count but does NOT validate file paths within the archive. An attacker can craft a malicious ZIP containing paths like ../../../etc/crontab to write files outside the intended extraction directory. This is called from compare() method when extracting user-provided zip files.

**漏洞代码** (`python/msprobe/core/config_check/config_checker.py:50-53`)

```c
extract_zip(bench_zip_path, bench_dir)\nextract_zip(cmp_zip_path, cmp_dir)
```

**达成路径**

_run_config_checking_command:args.compare -> compare:bench_zip_path,cmp_zip_path -> extract_zip -> zip_file.extractall (no path sanitization)

**验证说明**: Zip Slip confirmed: zipfile.extractall without path validation allows arbitrary file write.

**评分明细**: base: 30 | controllability: 15 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [VULN-ADUMP-001] TOCTOU - IsFileSymbolLink

**严重性**: High | **CWE**: CWE-367 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ccsrc/adump/utils/FileUtils.cpp:141-150` @ `IsFileSymbolLink`
**模块**: adump_utils
**跨模块**: FileUtils,DeleteFile,DeleteDir,Chmod

**描述**: Time-of-check to time-of-use race condition in symlink handling. IsFileSymbolLink uses lstat() to check for symlinks, but subsequent file operations use the path directly without re-validation. An attacker could replace the checked file with a symlink between the check and operation.

**漏洞代码** (`ccsrc/adump/utils/FileUtils.cpp:141-150`)

```c
lstat(path.c_str(), &buffer) followed by operations on unchecked path
```

**验证说明**: TOCTOU confirmed: lstat() check followed by operations on unchecked path. Symlink race possible.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 5 | mitigations: 0 | reachability: 30

---

### [VULN-002-adump_if_python] api - CPythonAgentRegister

**严重性**: High | **CWE**: CWE-667 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/if/python/CPythonAgent.cpp:44-49` @ `CPythonAgentRegister`
**模块**: adump_if_python

**描述**: Improper Reference Management - PyArg_ParseTuple "s" format returns a borrowed reference to internal string buffer. This pointer is stored in global map without copying. If Python GC collects the original string object or modifies it, the stored pointer becomes invalid, leading to use-after-free or data corruption.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/if/python/CPythonAgent.cpp:44-49`)

```c
const char* name = nullptr; PyArg_ParseTuple(args, "sO", &name, &obj); RegisterPythonObject(name, obj);
```

**达成路径**

args -> PyArg_ParseTuple -> name (borrowed ref) -> RegisterPythonObject -> PyObjMap[name] = obj

**验证说明**: Improper Reference Management: PyArg_ParseTuple returns borrowed reference stored in global map without copying.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -5 | reachability: 25

---

### [VULN-004-adump_if_python] error_handling - NewPrecisionDebugger

**严重性**: High | **CWE**: CWE-754 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:28-30` @ `NewPrecisionDebugger`
**模块**: adump_if_python

**描述**: Improper Exception Handling in Python C API - C++ exception thrown without setting Python exception state. When std::runtime_error is thrown in NewPrecisionDebugger, Python interpreter state is not properly set, which can cause undefined behavior or crashes when exception propagates across Python-C boundary.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:28-30`)

```c
throw std::runtime_error("PrecisionDebugger: type or alloc is nullptr.")
```

**达成路径**

type/alloc check -> throw exception without PyErr_SetString

**验证说明**: Improper Exception Handling: C++ exception without PyErr_SetString across Python-C boundary.

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [adump-core-001] Buffer Overflow - ConcatenateData

**严重性**: High | **CWE**: CWE-119 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumpDataProcessor.cpp:401-409` @ `ConcatenateData`
**模块**: adump_core

**描述**: headerSegLen is read directly from buffer without bounds validation. The value at buffer.front()->data() is interpreted as uint64_t and used directly as Protobuf message length. A malicious chunk could specify an extremely large headerSegLen causing ParseFromArray to read beyond allocated buffer.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumpDataProcessor.cpp:401-409`)

```c
headerSegLen = *(reinterpret_cast<const uint64_t *>(buffer.front()->data()));
```

**达成路径**

chunk->dataBuf -> buffer -> headerSegLen -> ParseFromArray

**验证说明**: Buffer overflow potential: headerSegLen read from buffer without bounds check. Could cause ParseFromArray to read beyond buffer. Semi-trusted ACL data source.

**评分明细**: base: 30 | reachability: 25 | controllability: 15 | mitigations: 0 | context: -10 | cross_file: 0

---

### [adump-core-006] Improper Input Validation - DumpToDisk

**严重性**: High | **CWE**: CWE-20 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumpDataProcessor.cpp:896-901` @ `DumpToDisk`
**模块**: adump_core
**跨模块**: adump_core → Protobuf_library

**描述**: ParseFromArray called with headerSegLen from buffer. While total size validated against MAX_DATA_LEN (4GB), Protobuf parser vulnerable to crafted messages.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumpDataProcessor.cpp:896-901`)

```c
dumpData.ParseFromArray(msg + headerSegOffset, headerSegLen)
```

**达成路径**

buffer -> headerSegLen -> ParseFromArray

**验证说明**: Improper input validation: ParseFromArray with headerSegLen from buffer. MAX_DATA_LEN check exists but Protobuf parser may still be vulnerable to crafted messages.

**评分明细**: base: 30 | reachability: 25 | controllability: 15 | mitigations: -5 | context: -10 | cross_file: 5

---

### [VULN-ADUMP-002] Path Traversal - GetAbsPath

**严重性**: High | **CWE**: CWE-22 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ccsrc/adump/utils/FileUtils.cpp:88-121` @ `GetAbsPath`
**模块**: adump_utils
**跨模块**: FileUtils,OpenFile,CheckFileBeforeRead

**描述**: Path traversal bypass via symlink. GetAbsPath performs lexical path canonicalization handling . and .. but does NOT resolve symlinks. A symlink could point outside the intended directory even after lexical normalization.

**漏洞代码** (`ccsrc/adump/utils/FileUtils.cpp:88-121`)

```c
Lexical normalization of .. without symlink resolution
```

**验证说明**: Path Traversal via symlink: GetAbsPath lexical normalization without symlink resolution.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 5 | mitigations: -5 | reachability: 25

---

### [VULN-ADUMP-006] Permission Bypass - CheckFileBeforeCreateOrWrite

**严重性**: High | **CWE**: CWE-269 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ccsrc/adump/utils/FileUtils.cpp:586-612` @ `CheckFileBeforeCreateOrWrite`
**模块**: adump_utils
**跨模块**: FileUtils,OpenFile

**描述**: Owner permission check bypass. CheckFileBeforeCreateOrWrite checks IsFileOwner after canonicalization, but actual file may differ via symlink race. Permission check on original path does not guarantee ownership of target.

**漏洞代码** (`ccsrc/adump/utils/FileUtils.cpp:586-612`)

```c
IsFileWritable(realPath) && IsFileOwner(realPath) check before write
```

**验证说明**: Permission Bypass: CheckFileBeforeCreateOrWrite owner check vulnerable to symlink race.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 5 | mitigations: -5 | reachability: 25

---

### [VULN-ADUMP-008] TOCTOU - DeleteFile

**严重性**: High | **CWE**: CWE-59 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ccsrc/adump/utils/FileUtils.cpp:268-282` @ `DeleteFile`
**模块**: adump_utils
**跨模块**: FileUtils,AclDumper

**描述**: TOCTOU in DeleteFile. Symlink check with IsFileSymbolLink followed by remove() on original path. Attacker can swap file to symlink after check, potentially deleting arbitrary files.

**漏洞代码** (`ccsrc/adump/utils/FileUtils.cpp:268-282`)

```c
IsFileSymbolLink check then remove() on unchecked path
```

**验证说明**: TOCTOU in DeleteFile: Symlink check then remove() on unchecked path.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 5 | mitigations: 0 | reachability: 25

---

### [VULN-ADUMP-009] TOCTOU - DeleteDir

**严重性**: High | **CWE**: CWE-59 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ccsrc/adump/utils/FileUtils.cpp:331-349` @ `DeleteDir`
**模块**: adump_utils
**跨模块**: FileUtils,AclDumper

**描述**: TOCTOU in DeleteDir. Same pattern as DeleteFile - symlink check followed by rmdir() on unchecked path.

**漏洞代码** (`ccsrc/adump/utils/FileUtils.cpp:331-349`)

```c
IsFileSymbolLink check then rmdir() on unchecked path
```

**验证说明**: TOCTOU in DeleteDir: Same pattern as DeleteFile.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 5 | mitigations: 0 | reachability: 25

---

### [adump-core-007] Deserialization Untrusted Data - DumpToDisk

**严重性**: High | **CWE**: CWE-502 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumpDataProcessor.cpp:897-900` @ `DumpToDisk`
**模块**: adump_core
**跨模块**: adump_core → ACL_external

**描述**: Protobuf deserialization on data from ACL dump callback. Semi-trusted source could send malformed messages exploiting parsing vulnerabilities.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumpDataProcessor.cpp:897-900`)

```c
dumpData.ParseFromArray(msg + headerSegOffset, headerSegLen)
```

**达成路径**

ACL device -> AclDumpChunk -> buffer -> ParseFromArray

**验证说明**: Deserialization of semi-trusted data: Protobuf from ACL callback. Parsing vulnerabilities possible if ACL library compromised.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: -10 | cross_file: 5

---

### [PYTORCH_DUMP_PATH_TRAVERSAL_001] Path Traversal - get_save_file_path

**严重性**: High | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: python-security-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/dump/data_dump/data_processor/base.py:456-465` @ `get_save_file_path`
**模块**: pytorch_dump
**跨模块**: pytorch_dump → core_dump → torch_npu

**描述**: get_save_file_path方法在base.py中使用用户可控的current_api_or_module_name和api_data_category构造文件路径。FILE_PATTERN正则表达式允许'..'和'/'字符，可能导致路径遍历攻击。攻击者可通过构造包含'../'的API名称来写入任意位置文件。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/dump/data_dump/data_processor/base.py:456-465`)

```c
def get_save_file_path(self, suffix):
    file_path = os.path.join(self.data_writer.dump_tensor_data_dir, dump_data_name)
    return dump_data_name, file_path
```

**达成路径**

用户配置JSON -> CommonConfig.dump_path -> service.py:create_dirs -> base.py:get_save_file_path -> torch.save

**验证说明**: Path Traversal: FILE_PATTERN allows '..' and '/' in get_save_file_path. User-controlled API names could traverse directories.

**评分明细**: base: 30 | controllability: 15 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 25

---

## 4. Medium 漏洞 (49)

### [63c6b4c9-be11-45fd-ade0-164c751d725c] Configuration Size Limit Mismatch - MAX_JSON_SIZE

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/utils/FileUtils.h:38` @ `MAX_JSON_SIZE`
**模块**: adump_base
**跨模块**: adump_base,msprobe_python_core

**描述**: JSON file size limit inconsistency between Python and C++ modules. Python side defines MAX_JSON_SIZE = 10737418240 (10GB), while C++ side defines MAX_JSON_SIZE = 1024ULL * 1024 * 1024 (1GB). This inconsistency could allow malicious JSON files up to 10GB to be accepted by Python frontend but rejected by C++ backend, or vice versa, potentially causing resource exhaustion.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/utils/FileUtils.h:38`)

```c
constexpr size_t MAX_JSON_SIZE = 1024ULL * 1024 * 1024;
```

**达成路径**

Python FileChecker -> C++ CheckFileBeforeRead -> Parse

**验证说明**: Configuration Size Limit Mismatch: Python 10GB vs C++ 1GB. Resource exhaustion risk.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: -10 | cross_file: 0

---

### [a57dcbc7-e5f8-4976-a7dd-49320b528eaf] Path Traversal - GetAbsPath

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/utils/FileUtils.cpp:88-121` @ `GetAbsPath`
**模块**: adump_base
**跨模块**: adump_base,adump_utils

**描述**: GetAbsPath function handles path traversal sequences (..) but returns empty string when tokensRefined is empty and .. is encountered. For paths like /../../../etc/passwd, the function would return / (root), potentially allowing access to unintended files. Combined with configuration parsing that uses this path, attacker could potentially access sensitive system files.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/utils/FileUtils.cpp:88-121`)

```c
if (token == ..) { if (tokensRefined.empty()) { return ; } tokensRefined.pop_back(); }
```

**达成路径**

LoadConfig -> GetAbsPath -> CheckFileBeforeRead -> Parse -> JSON parsing

**验证说明**: Path Traversal edge case in GetAbsPath: empty string when .. with empty tokensRefined.

**评分明细**: base: 30 | reachability: 25 | controllability: 10 | mitigations: -5 | context: -10 | cross_file: 5

---

### [core_compare-001] Path Traversal - extract_json

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/compare/utils.py:40-58` @ `extract_json`
**模块**: core_compare

**描述**: extract_json uses os.listdir without validating filenames contain path traversal chars

**验证说明**: Path Traversal risk: extract_json uses os.listdir without validating filenames for traversal chars like ../

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 25

---

### [VULN-003-adump_if_python] concurrency - RegisterPythonObject

**严重性**: Medium | **CWE**: CWE-362 | **置信度**: 80/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/utils/CPythonUtils.cpp:26-60` @ `RegisterPythonObject`
**模块**: adump_if_python

**描述**: Race Condition - Global static map PyObjMap accessed without synchronization. RegisterPythonObject, UnRegisterPythonObject, and GetRegisteredPyObj all access this map without locks. In multi-threaded Python environments, concurrent access can cause data races, corruption, or crashes.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/utils/CPythonUtils.cpp:26-60`)

```c
static std::map<std::string, PythonObject> PyObjMap = {};
```

**达成路径**

Multiple functions access PyObjMap without synchronization

**验证说明**: Race Condition: PyObjMap global map accessed without synchronization.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 15

---

### [MSDUMP-CWE22-002] Path Traversal - process_step

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `python/msprobe/mindspore/dump/dump_processor/cell_dump_process.py:616-624` @ `process_step`
**模块**: mindspore_dump

**描述**: The RANK_ID environment variable is read and used directly in path construction without validation. An attacker could manipulate this environment variable to cause files to be written to unexpected locations.

**漏洞代码** (`python/msprobe/mindspore/dump/dump_processor/cell_dump_process.py:616-624`)

```c
rank_id = os.environ.get("RANK_ID")\n    rank_dir = DEFAULT_RANK_DIR\n    if rank_id is not None:\n        rank_dir = CoreConst.RANK + str(rank_id)\n    step_dir = CoreConst.STEP + str(step)\n    step_path = os.path.join(dump_path, step_dir)\n    rank_path = os.path.join(step_path, rank_dir)
```

**达成路径**

RANK_ID env -> os.environ.get() -> rank_dir -> os.path.join() -> file system

**验证说明**: Path Traversal: RANK_ID env var used directly in path construction.

**评分明细**: base: 30 | controllability: 15 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 25

---

### [MSDUMP-XMOD-001] Cross-Module Security Boundary - handle

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: CWE-114 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `python/msprobe/mindspore/dump/dump_processor/kernel_graph_dump.py:59-65` @ `handle`
**模块**: mindspore_dump
**跨模块**: mindspore_dump, _msprobe_c (C++), MindSpore runtime

**描述**: Python module passes configuration to C++ _msprobe_c module via environment variable. The security of file operations then depends entirely on the C++ implementation. The Python side validates paths but the C++ module receives paths through environment variables without guaranteed validation.

**漏洞代码** (`python/msprobe/mindspore/dump/dump_processor/kernel_graph_dump.py:59-65`)

```c
try:\n    from msprobe.lib import _msprobe_c\n    return\nexcept ImportError:\n    logger.info("Module _msprobe_c has not been installed...")\n...json_path = os.path.join(json_path, "kernel_graph_dump.json")\nsave_json(json_path, self.dump_json, indent=4)\nos.environ["MINDSPORE_DUMP_CONFIG"] = json_path
```

**达成路径**

Python config -> save_json() -> os.environ -> C++ _msprobe_c reads env -> C++ file operations

**验证说明**: Cross-Module Boundary: Python passes config via env to C++ _msprobe_c.

**评分明细**: base: 30 | controllability: 15 | context: -10 | cross_file: 10 | mitigations: -5 | reachability: 25

---

### [adump-core-005] Race Condition - WriteOneTensorStatToDisk

**严重性**: Medium | **CWE**: CWE-362 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumpDataProcessor.cpp:712-758` @ `WriteOneTensorStatToDisk`
**模块**: adump_core

**描述**: TOCTOU race in WriteOneTensorStatToDisk. File checked then opened, flock acquired after. Between check and flock another process could modify file.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumpDataProcessor.cpp:712-758`)

```c
CheckFileBeforeCreateOrWrite -> open() -> flock(LOCK_EX)
```

**达成路径**

CheckFileBeforeCreateOrWrite -> open -> flock -> lseek -> write

**验证说明**: TOCTOU Race: CheckFileBeforeCreateOrWrite then open/flock gap.

**评分明细**: base: 30 | reachability: 25 | controllability: 15 | mitigations: -5 | context: -10 | cross_file: 0

---

### [VULN-ADUMP-004] Race Condition - RegisterPythonObject

**严重性**: Medium | **CWE**: CWE-362 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ccsrc/adump/utils/CPythonUtils.cpp:26-60` @ `RegisterPythonObject`
**模块**: adump_utils
**跨模块**: CPythonUtils,CPythonAgent

**描述**: Thread safety issue with global Python object registry. PyObjMap is a static global std::map accessed without synchronization. In multi-threaded Python environments, concurrent access could cause data corruption.

**漏洞代码** (`ccsrc/adump/utils/CPythonUtils.cpp:26-60`)

```c
static std::map<std::string, PythonObject> PyObjMap accessed without mutex
```

**验证说明**: Race Condition: Global static map PyObjMap accessed without synchronization in multi-threaded Python.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 20

---

### [DF-006] json_injection - _process_dump_file

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `python/msprobe/core/dump/dump2db/dump2db.py:322-360` @ `_process_dump_file`
**模块**: core_dump
**跨模块**: core_file_utils → core_dump

**描述**: _process_dump_file 函数处理用户控制的 dump.json 文件，通过 load_json 读取后直接使用数据。JSON 数据可能包含恶意构造的内容，需要验证数据结构。

**漏洞代码** (`python/msprobe/core/dump/dump2db/dump2db.py:322-360`)

```c
def _process_dump_file(self, dump_file_path, metric_type):
    dump_data = load_json(dump_file_path)
```

**达成路径**

用户 CLI 参数 → dump_file_path → load_json → JSON 解析 → 数据直接使用

**验证说明**: JSON Injection Risk: _process_dump_file processes user-controlled dump.json, data used directly without structure validation. User CLI input flows to JSON parsing.

**评分明细**: base: 30 | controllability: 15 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 25

---

### [core_compare-002] Path Traversal - get_paired_dirs

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/compare/utils.py:657-660` @ `get_paired_dirs`
**模块**: core_compare

**描述**: get_paired_dirs uses os.listdir without validating directory names

**验证说明**: Path Traversal risk: get_paired_dirs uses os.listdir without validating directory names.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [core_compare-006] Improper Input Validation - mix_compare

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/compare/auto_compare.py:108-131` @ `mix_compare`
**模块**: core_compare

**描述**: mix_compare builds paths from unvalidated directory names

**验证说明**: Improper Input Validation: mix_compare builds paths from unvalidated directory names.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [adump-third-party-003] External Control of File Name or Path - OnAclDumpCallBack

**严重性**: Medium | **CWE**: CWE-73 | **置信度**: 75/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumper.cpp:389` @ `OnAclDumpCallBack`
**模块**: adump_third_party
**跨模块**: adump_third_party,adump_core

**描述**: The AclDumpChunk.fileName field from external ACL callback is used directly with GetAbsPath() for file operations. While path traversal is sanitized, the file path comes from an untrusted external source (ACL library callback) and could write to arbitrary locations if the ACL library is compromised.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumper.cpp:389`)

```c
std::string dumpPath = FileUtils::GetAbsPath(chunk->fileName);
```

**验证说明**: External Control of File Path: AclDumpChunk.fileName from ACL callback used directly. Path sanitized but source untrusted.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 20

---

### [VULN-006-adump_if_python] input_validation - InitPrecisionDebugger

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:42-59` @ `InitPrecisionDebugger`
**模块**: adump_if_python
**跨模块**: adump_if_python → adump_core → adump_base

**描述**: Missing Parameter Validation - InitPrecisionDebugger receives config_path from Python kwargs without comprehensive validation at Python C API boundary before passing to DebuggerConfig::LoadConfig. While path is validated in DebuggerConfig, the framework parameter lacks enum validation at this layer.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:42-59`)

```c
std::string framework = kwArgs.GetItem("framework"); std::string cfgFile = kwArgs.GetItem("config_path");
```

**达成路径**

[CREDENTIAL_FLOW] kws -> GetItem -> framework/cfgFile -> PrecisionDebugger::Initialize -> DebuggerConfig::LoadConfig -> FileUtils::GetAbsPath

**验证说明**: Missing Parameter Validation: InitPrecisionDebugger receives unvalidated config_path. Downstream validation exists.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 20

---

### [CLI-001-argv-direct-pass] argument_injection - main

**严重性**: Medium | **CWE**: CWE-88 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `python/msprobe/msprobe.py:70-75` @ `main`
**模块**: cli_entry
**跨模块**: cli_entry → acc_check_cli → core_file_utils

**描述**: CLI入口函数main()直接将sys.argv[2:]传递给acc_check_cli/multi_acc_check_cli，绕过argparse验证。攻击者可注入恶意参数，影响子模块的安全校验逻辑。这违反了"所有外部输入必须经过统一校验入口"的原则。

**漏洞代码** (`python/msprobe/msprobe.py:70-75`)

```c
if len(sys.argv) >= 2 and sys.argv[1] == "acc_check":\n    acc_check_cli(sys.argv[2:])\n    return\nelif len(sys.argv) >= 2 and sys.argv[1] == "multi_acc_check":\n    multi_acc_check_cli(sys.argv[2:])\n    return
```

**达成路径**

sys.argv -> main() -> acc_check_cli(sys.argv[2:]) -> _detect_framework_from_api_info -> FileChecker.common_check

**验证说明**: Argument Injection: sys.argv[2:] passed directly bypassing argparse validation.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 25

---

### [MSDUMP-CWE73-001] External Control of File Name or Path - step

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: CWE-73 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `python/msprobe/mindspore/dump/dump_processor/graph_mode_cell_dump.py:68-74` @ `step`
**模块**: mindspore_dump

**描述**: The RANK_ID environment variable controls the directory name used for dump file storage. This allows external control over where dump files are written, potentially leading to unauthorized file access or data corruption.

**漏洞代码** (`python/msprobe/mindspore/dump/dump_processor/graph_mode_cell_dump.py:68-74`)

```c
rank_id = os.environ.get("RANK_ID")\n    rank_dir = DEFAULT_RANK_DIR\n    if rank_id is not None:\n        rank_dir = CoreConst.RANK + str(rank_id)\n    with tempfile.TemporaryDirectory(dir=dump_path, prefix=rank_dir) as temp_dir:
```

**达成路径**

RANK_ID env -> rank_dir -> tempfile.TemporaryDirectory prefix -> file system

**验证说明**: External Control: RANK_ID env controls directory name for dump storage.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 25

---

### [overflow_check-002] Time-of-check Time-of-use (TOCTOU) - OverFlowCheck._resolve_input_path

**严重性**: Medium | **CWE**: CWE-367 | **置信度**: 75/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/overflow_check/analyzer.py:51-65` @ `OverFlowCheck._resolve_input_path`
**模块**: overflow_check

**描述**: 文件路径检查和实际使用之间存在TOCTOU竞态条件。check_file_or_directory_path验证后到实际os.listdir使用前，路径可能被恶意修改（如符号链接替换）。影响：可能导致访问非预期文件或目录。

**漏洞代码** (`python/msprobe/overflow_check/analyzer.py:51-65`)

```c
contents = os.listdir(self._input_path)\nfor path in contents:\n    if not path.startswith('rank'):\n        continue
```

**验证说明**: TOCTOU Race: check_file_or_directory_path then os.listdir gap.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 25

---

### [VULN-002-pickle-scanner-flaw] insecure_deserialization_detection - DeserializationScanner.scan_pickle_content

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/core/common/file_utils.py:1142-1166` @ `DeserializationScanner.scan_pickle_content`
**模块**: core_file_utils

**描述**: DeserializationScanner.scan_pickle_content()的检测逻辑存在缺陷：使用re.fullmatch()在latin-1解码的二进制数据上匹配危险方法名，无法准确检测pickle文件中的实际危险操作。攻击者可构造不包含匹配字符串但仍危险的pickle payload。

**漏洞代码** (`python/msprobe/core/common/file_utils.py:1142-1166`)

```c
def scan_pickle_content(cls, filepath: str) -> bool:\n    content = f.read()\n    text_content = content.decode("latin-1")  # 二进制解码\n    for method in cls.DANGEROUS_METHODS:\n        if re.fullmatch(method, text_content):  # fullmatch检测不准确
```

**达成路径**

file_utils.py:scan_pickle_content() -> FileOpen -> content.decode -> re.fullmatch

**验证说明**: Pickle Scanner Flaw: scan_pickle_content uses fullmatch on latin-1 decoded data, cannot accurately detect dangerous pickle operations.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [d805ae2e-1436-4031-9c4d-629ed2129485] Cross-Module Validation Inconsistency - LoadConfig

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/base/DebuggerConfig.cpp:462-502` @ `LoadConfig`
**模块**: adump_base
**跨模块**: adump_base,msprobe_python_core

**描述**: Configuration validation differs between Python and C++ layers. Python FileChecker validates path characters, soft links, owner consistency, and path patterns. C++ CheckFileBeforeRead has similar checks but uses different character validation (IsPathCharactersValid allows : char which Python may restrict). This inconsistency creates potential attack surface.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/base/DebuggerConfig.cpp:462-502`)

```c
cfgFilePath_ = FileUtils::GetAbsPath(cfgFilePath); DebuggerErrno ret = FileUtils::CheckFileBeforeRead(cfgFilePath_, "r", FileType::JSON);
```

**达成路径**

Python precision_debugger.py -> C++ PrecisionDebugger::Initialize -> DebuggerConfig::LoadConfig

**验证说明**: Cross-Module Validation Inconsistency: Python/C++ different char validation.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: -10 | cross_file: 5

---

### [adump-core-002] Path Traversal - OnAclDumpCallBack

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumper.cpp:389-396` @ `OnAclDumpCallBack`
**模块**: adump_core
**跨模块**: adump_core → ACL_external

**描述**: chunk->fileName from ACL callback used to construct dump path. GetAbsPath handles .. traversal but path originates from external ACL infrastructure.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumper.cpp:389-396`)

```c
std::string dumpPath = FileUtils::GetAbsPath(chunk->fileName);
```

**达成路径**

ACL callback -> chunk->fileName -> GetAbsPath -> dumpPath

**验证说明**: Path Traversal via ACL callback: chunk->fileName from untrusted source.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: -10 | cross_file: 5

---

### [VULN-ADUMP-003] Integer Overflow - PythonObject::To

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ccsrc/adump/utils/CPythonUtils.cpp:96-112` @ `PythonObject::To`
**模块**: adump_utils
**跨模块**: CPythonUtils,Environment

**描述**: Integer overflow in Python C API conversion. PyLong_AsLong and PyLong_AsUnsignedLong can overflow when cast to int32_t/uint32_t. Python integers can be arbitrarily large and error detection is unreliable.

**漏洞代码** (`ccsrc/adump/utils/CPythonUtils.cpp:96-112`)

```c
PyLong_AsLong(ptr) cast to int32_t without overflow check
```

**验证说明**: Integer Overflow: PyLong_AsLong cast to int32_t without overflow check. Python integers can be arbitrarily large.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 20

---

### [VULN-ADUMP-010] Missing Validation - DumpNpy

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ccsrc/adump/utils/FileOperation.cpp:156-179` @ `DumpNpy`
**模块**: adump_utils
**跨模块**: FileOperation,AclDumpDataProcessor

**描述**: Missing data size validation in DumpNpy. Writes arbitrary data buffer without validating size matches declared shape and dtype. Could lead to buffer over-read if data is smaller than expected.

**漏洞代码** (`ccsrc/adump/utils/FileOperation.cpp:156-179`)

```c
fd.write(data, len) without shape/dtype consistency check
```

**验证说明**: Missing Validation: DumpNpy writes data without validating size matches declared shape and dtype.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 20

---

### [DF-009] command_execution - install_offline_deps_cli

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-78 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `python/msprobe/infer/offline/compare/msquickcmp/main.py:191-197` @ `install_offline_deps_cli`
**模块**: infer_offline

**描述**: install_offline_deps_cli 函数使用 subprocess.run() 执行 shell 脚本，虽然使用列表形式传参避免 shell 注入，但脚本路径来自 os.path.abspath() 与 __file__ 拼接，可能存在路径篡改风险。

**漏洞代码** (`python/msprobe/infer/offline/compare/msquickcmp/main.py:191-197`)

```c
offline_extra_install_cmd = ['/bin/bash', os.path.abspath(os.path.join(os.path.dirname(__file__), 'install_aclruntime_aisbench.sh')), str(args.no_check)]
subprocess.run(offline_extra_install_cmd, shell=False)
```

**达成路径**

__file__ → os.path.dirname → os.path.join → install_aclruntime_aisbench.sh → subprocess.run

**验证说明**: Command Execution Risk: install_offline_deps_cli uses subprocess.run with script path from __file__. Path derived from module location, lower attackability.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [DF-011] python_c_api - PythonObject::Get

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `ccsrc/adump/utils/CPythonUtils.cpp:146-150` @ `PythonObject::Get`
**模块**: adump_utils
**跨模块**: adump_if_python → adump_utils

**描述**: CPythonUtils 模块处理 Python C API 调用，PythonDictObject::GetItem 从 Python 字典获取值，输入来自 Python 层可能被用户控制。需要验证返回值类型。

**漏洞代码** (`ccsrc/adump/utils/CPythonUtils.cpp:146-150`)

```c
PyObject* o = PyObject_GetAttrString(ptr, name.c_str());
if (o == nullptr && ignore) {
    PyErr_Clear();
```

**达成路径**

Python 字典 → PyObject_GetAttrString → 返回 PythonObject → 类型转换

**验证说明**: Python C API: PythonObject::Get uses PyObject_GetAttrString with potential null return handling issues.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [XF-002] cross_module_data_flow - 跨模块调用链

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `跨模块: core_file_utils → core_dump:0` @ `跨模块调用链`
**模块**: cross_module
**跨模块**: core_file_utils → core_dump

**描述**: 跨模块数据流: 用户 JSON 数据 → 数据库存储。dump.json 文件内容从 CLI 参数指定的路径加载，经过 load_json 解析后直接用于数据库插入。数据结构验证依赖下游检查。

**漏洞代码** (`跨模块: core_file_utils → core_dump:0`)

```c
Python: load_json(json_path) → _process_dump_file → db.batch_insert_data
```

**达成路径**

[OUT] core_file_utils.load_json → JSON data
[IN] core_dump._process_dump_file ← dump_data
[OUT] core_dump → tensor_data
[IN] db_utils ← 批量插入

**验证说明**: Cross-module data flow: User JSON data flows to database. Structure validation depends on downstream checks.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 20

---

### [adump-third-party-001] Untrusted Search Path - LoadAclApi

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/third_party/ACL/AclApi.cpp:70-71` @ `LoadAclApi`
**模块**: adump_third_party

**描述**: Dynamic library loading uses library name without full path verification. While RTLD_NOLOAD flag mitigates by only searching already-loaded libraries, the approach relies on proper library preloading order and could be exploited if LD_LIBRARY_PATH is manipulated before the target library is loaded.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/third_party/ACL/AclApi.cpp:70-71`)

```c
hLibAscendcl = dlopen(LIB_ASCEND_CL_NAME, RTLD_LAZY | RTLD_NOLOAD);
```

**验证说明**: Untrusted Search Path: dlopen with library name without full path. RTLD_NOLOAD mitigates but LD_LIBRARY_PATH manipulation possible.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [core_compare-005] Improper Input Validation - get_stats_map

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/compare/atb_data_compare.py:178-185` @ `get_stats_map`
**模块**: core_compare

**描述**: get_stats_map constructs paths from CSV without traversal validation

**验证说明**: Improper Input Validation: get_stats_map constructs paths from CSV without traversal validation.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [core_compare-008] Argument Injection - compare_offline_data_mode

**严重性**: Medium | **CWE**: CWE-88 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/compare/offline_data_compare.py:32-55` @ `compare_offline_data_mode`
**模块**: core_compare

**描述**: compare_offline_data_mode passes user paths as command arguments without validation

**验证说明**: Argument Injection risk: compare_offline_data_mode passes user paths as command arguments.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 20

---

### [VULN-005-adump_if_python] error_handling - CPythonKernelSetDump

**严重性**: Medium | **CWE**: CWE-252 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/if/python/ACLDump.cpp:38-47` @ `CPythonKernelSetDump`
**模块**: adump_if_python

**描述**: Unchecked Return Value - PyArg_ParseTuple return value not properly handled before proceeding. While LOG_ERROR is called, the function returns nullptr, but the error handling could be improved with consistent state management.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/if/python/ACLDump.cpp:38-47`)

```c
if (!PyArg_ParseTuple(args, "s", &path)) { LOG_ERROR(...); return nullptr; }
```

**达成路径**

args -> PyArg_ParseTuple -> path (borrowed) -> KernelSetDump(std::string(path))

**验证说明**: Unchecked Return Value: PyArg_ParseTuple error handling could be improved.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 15

---

### [MSDUMP-CWE22-001] Path Traversal - gen_file_path

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/mindspore/dump/dump_processor/cell_dump_process.py:117-126` @ `gen_file_path`
**模块**: mindspore_dump
**跨模块**: mindspore_dump, core.file_utils

**描述**: The dump_path from DebuggerConfig is used directly in path construction without explicit validation against path traversal characters. While file_utils.py provides validation through check_path_pattern_valid, the cell_prefix parameter in gen_file_path() is derived from user-controlled cell names which could potentially contain path traversal sequences.

**漏洞代码** (`python/msprobe/mindspore/dump/dump_processor/cell_dump_process.py:117-126`)

```c
def gen_file_path(dump_path, cell_prefix, suffix, io_type, index):\n    step_path = os.path.join(dump_path, "{step}")\n    rank_path = os.path.join(step_path, "{rank}")\n    data_path = os.path.join(rank_path, CoreConst.DUMP_TENSOR_DATA)\n    file_name = ""\n    if dump_task == CoreConst.TENSOR:\n        file_name = cell_prefix + CoreConst.SEP + suffix + CoreConst.SEP + io_type + CoreConst.SEP + str(index)
```

**达成路径**

dump_path -> DebuggerConfig.dump_path -> cell_dump_process.gen_file_path() -> os.path.join() -> file system

**验证说明**: Path Traversal: dump_path from config used directly, cell_prefix from user cell names.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 20

---

### [PYTORCH_DUMP_CONFIG_PATH_INJECTION_001] External Control of File Name or Path - CommonConfig.__init__

**严重性**: Medium | **CWE**: CWE-73 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: python-security-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/dump/common_config.py:27-33` @ `CommonConfig.__init__`
**模块**: pytorch_dump

**描述**: CommonConfig类直接从JSON配置文件读取dump_path，仅验证是否为字符串类型，未进行路径安全验证。攻击者可通过配置文件指定任意路径。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/dump/common_config.py:27-33`)

```c
self.dump_path = json_config.get('dump_path')
```

**达成路径**

JSON配置文件 -> CommonConfig.dump_path -> create_directory -> os.makedirs

**验证说明**: External Control: CommonConfig reads dump_path without validation from JSON.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [infer_offline_np_load_003] Unsafe Deserialization - _get_file_size

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: CWE-502 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/infer/offline/compare/msquickcmp/npu/npu_dump_data.py:525-526` @ `_get_file_size`
**模块**: infer_offline
**跨模块**: msprobe.infer.utils.check.rule,msprobe.infer.utils.util

**描述**: np.load used without explicit allow_pickle=False in npu_dump_data.py. While file validation is performed, numpy files can contain malicious pickle payloads.

**漏洞代码** (`python/msprobe/infer/offline/compare/msquickcmp/npu/npu_dump_data.py:525-526`)

```c
file_size.append(np.load(item).size)
```

**验证说明**: Unsafe Deserialization: np.load without explicit allow_pickle=False.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 20

---

### [overflow_check-001] Race Condition - FileCache.__new__

**严重性**: Medium | **CWE**: CWE-362 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `python/msprobe/overflow_check/utils.py:49-57` @ `FileCache.__new__`
**模块**: overflow_check

**描述**: FileCache单例模式实现存在线程安全问题。__new__方法中的单例检查和创建不是原子操作，在多线程环境下可能导致创建多个实例或竞态条件。影响缓存数据一致性。

**漏洞代码** (`python/msprobe/overflow_check/utils.py:49-57`)

```c
def __new__(cls, *args, **kwargs):\n    if not cls._instance:\n        cls._instance = super().__new__(cls, *args, **kwargs)\n    return cls._instance
```

**验证说明**: Race Condition: FileCache singleton not thread-safe in __new__.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [a64db995-e73d-4715-8650-b6c1402ed42d] Integer Overflow in Range Parsing - DebuggerCfgParseUIntRangeGetBorder

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/base/DebuggerConfig.cpp:99-178` @ `DebuggerCfgParseUIntRangeGetBorder`
**模块**: adump_base

**描述**: DebuggerCfgParseUIntRangeGetBorder parses range expressions like a-b from JSON configuration. The function uses std::istringstream to parse uint32_t values without proper bounds checking before arithmetic operations. Line 152 calculates rangeSize = end - begin, and line 153 checks overflow but only against UINT32_MAX. If malformed JSON contains extremely large values, could cause unexpected behavior.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/base/DebuggerConfig.cpp:99-178`)

```c
uint32_t rangeSize = end - begin; if (realLen > UINT32_MAX - (rangeSize + 1))
```

**达成路径**

LoadConfig -> Parse -> CommonCfg::Parse -> DebuggerCfgParseUIntRange

**验证说明**: Integer Overflow in Range Parsing: uint32_t arithmetic before overflow check.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: -10 | cross_file: 0

---

### [adump-core-004] Integer Overflow - FRAC_Z_TO_NCHW_WITH_GROUPS

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclTensor.cpp:424-434` @ `FRAC_Z_TO_NCHW_WITH_GROUPS`
**模块**: adump_core

**描述**: Format conversion functions perform index calculations using values from Protobuf shapes. Intermediate calculations could overflow before bounds check.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclTensor.cpp:424-434`)

```c
int64_t devIdx = (g/eMult)*c1Dim*hDim*wDim*coutOpt*cubeK + ...;
```

**达成路径**

tensor.hostShape/deviceShape -> index calculation -> buffer access

**验证说明**: Integer Overflow in format conversion index calculations.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: -10 | cross_file: 0

---

### [adump-core-008] Path Manipulation - GenDataPath

**严重性**: Medium | **CWE**: CWE-73 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumpDataProcessor.cpp:586-622` @ `GenDataPath`
**模块**: adump_core

**描述**: GenDataPath constructs paths by splitting and reassembling components without validating segment contents. Path segments extracted by index and concatenated.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/core/AclDumpDataProcessor.cpp:586-622`)

```c
dataPath.append(items[rankIdPos] + "/");
```

**达成路径**

dumpPath -> GenDataPath -> SplitPath -> path reconstruction

**验证说明**: Path Manipulation: GenDataPath segments by index without validation.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: -10 | cross_file: 0

---

### [VULN-ADUMP-007] NULL Pointer Dereference - PythonDictObject::GetItem

**严重性**: Medium | **CWE**: CWE-476 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ccsrc/adump/utils/CPythonUtils.h:424-440` @ `PythonDictObject::GetItem`
**模块**: adump_utils
**跨模块**: CPythonUtils,PrecisionDebuggerIfPython

**描述**: Missing NULL check in PythonDictObject::GetItem. PyDict_GetItem returns NULL when key not found with no exception set, but PyErr_Clear called unconditionally. Error semantics are incorrect.

**漏洞代码** (`ccsrc/adump/utils/CPythonUtils.h:424-440`)

```c
PyDict_GetItem returns borrowed ref, PyErr_Clear on no-error
```

**验证说明**: NULL Pointer Dereference: PyDict_GetItem returns NULL with no exception, PyErr_Clear called on no-error.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 20

---

### [DF-003] input_validation - InitPrecisionDebugger

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:42-62` @ `InitPrecisionDebugger`
**模块**: adump_if_python
**跨模块**: cli_entry → adump_if_python → adump_base

**描述**: InitPrecisionDebugger 函数从 Python C API 接收 framework 和 config_path 参数，这些参数来自用户 CLI 输入。虽然下游 LoadConfig 有验证，但 Python-C++ 边界缺乏显式输入验证。

**漏洞代码** (`ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp:42-62`)

```c
std::string framework = kwArgs.GetItem("framework");
std::string cfgFile = kwArgs.GetItem("config_path");
if (PrecisionDebugger::GetInstance().Initialize(framework, cfgFile) != 0)
```

**达成路径**

Python CLI 参数 → InitPrecisionDebugger → framework/config_path → PrecisionDebugger::Initialize → DebuggerConfig::LoadConfig → 文件验证

**验证说明**: Input Validation: InitPrecisionDebugger receives parameters without validation at Python-C boundary.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 20

---

### [DF-004] integer_overflow - DebuggerCfgParseUIntRange

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `ccsrc/adump/base/DebuggerConfig.cpp:122-178` @ `DebuggerCfgParseUIntRange`
**模块**: adump_base

**描述**: DebuggerCfgParseUIntRange 函数解析范围表达式时存在整数溢出风险。虽然代码检查了 realLen > UINT32_MAX - (rangeSize + 1)，但使用 uint32_t 计算可能导致溢出。

**漏洞代码** (`ccsrc/adump/base/DebuggerConfig.cpp:122-178`)

```c
uint32_t rangeSize = end - begin;
if (realLen > UINT32_MAX - (rangeSize + 1)) { ... }
```

**达成路径**

JSON 配置范围表达式 → 解析为 begin/end → 计算 rangeSize → 检查溢出 → 添加到 range 列表

**验证说明**: Integer Overflow: DebuggerCfgParseUIntRange uses uint32_t arithmetic. Overflow check exists but may overflow before check.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [DF-010] environment_variable - CANN_PATH

**严重性**: Medium | **CWE**: CWE-807 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `python/msprobe/infer/offline/compare/msquickcmp/main.py:37` @ `CANN_PATH`
**模块**: infer_offline

**描述**: CANN_PATH 从环境变量 ASCEND_TOOLKIT_HOME 获取，如果未设置则使用硬编码路径。环境变量可被外部设置，需要验证路径合法性。

**漏洞代码** (`python/msprobe/infer/offline/compare/msquickcmp/main.py:37`)

```c
CANN_PATH = os.environ.get('ASCEND_TOOLKIT_HOME', '/usr/local/Ascend/ascend-toolkit/latest')
```

**达成路径**

环境变量 ASCEND_TOOLKIT_HOME → CANN_PATH → DumpArgsAdapter → dump_process

**验证说明**: Environment Variable: CANN_PATH from ASCEND_TOOLKIT_HOME environment. Environment can be manipulated by attacker.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [XF-001] cross_module_data_flow - 跨模块调用链

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `跨模块: cli_entry → adump_if_python → adump_base:0` @ `跨模块调用链`
**模块**: cross_module
**跨模块**: cli_entry → adump_if_python → adump_base

**描述**: 跨模块数据流: Python CLI → C++ 配置加载。用户通过 CLI 参数 config_path 传入配置文件路径，Python 层传递到 C++ PrecisionDebugger::Initialize，最终在 DebuggerConfig::LoadConfig 加载和解析。跨语言边界缺乏统一验证框架。

**漏洞代码** (`跨模块: cli_entry → adump_if_python → adump_base:0`)

```c
Python: InitPrecisionDebugger(framework, config_path)
C++: PrecisionDebugger::Initialize → DebuggerConfig::LoadConfig
```

**达成路径**

[OUT] cli_entry.main → config_path
[IN] adump_if_python.InitPrecisionDebugger ← framework, config_path
[OUT] adump_if_python → cfgFile
[IN] adump_base.DebuggerConfig.LoadConfig ← cfgFilePath

**验证说明**: Cross-module data flow: Python CLI to C++ config loading. Framework validation exists but inconsistent at boundary.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 10 | mitigations: -5 | reachability: 15

---

### [adump-third-party-002] Untrusted Pointer Dereference - LoadAclApi

**严重性**: Medium | **CWE**: CWE-822 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/third_party/ACL/AclApi.cpp:79-87` @ `LoadAclApi`
**模块**: adump_third_party

**描述**: Function pointers obtained from dlsym() are stored in global variables and called without validation. If dlopen/dlsym succeeded but the library was compromised, arbitrary code execution could occur through manipulated function pointers.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/third_party/ACL/AclApi.cpp:79-87`)

```c
*(iter.second) = dlsym(hLibAscendcl, iter.first);
```

**验证说明**: Untrusted Pointer Dereference: Function pointers from dlsym called without validation. If library compromised, arbitrary code execution.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [core_compare-007] Path Traversal - get_torchair_ge_graph_path

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/compare/torchair_acc_cmp.py:44-69` @ `get_torchair_ge_graph_path`
**模块**: core_compare

**描述**: os.walk in torchair without bounds validation after initial check

**验证说明**: Path Traversal: os.walk in torchair without bounds validation after initial check.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [MSDUMP-CWE73-002] External Control of File Name or Path - start

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: CWE-73 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/mindspore/dump/dump_processor/cell_dump_process.py:930-934` @ `start`
**模块**: mindspore_dump

**描述**: Cell names from model structure are used directly in file name construction without explicit validation. Cell names derived from user-defined classes could contain special characters that affect file system behavior.

**漏洞代码** (`python/msprobe/mindspore/dump/dump_processor/cell_dump_process.py:930-934`)

```c
cell.cell_prefix = CoreConst.SEP.join([CoreConst.CELL, name, cell.__class__.__name__])\n    if dump_task == CoreConst.STATISTICS:\n        cell.cell_prefix = cell.cell_prefix.replace(CoreConst.SEP, CoreConst.HYPHEN)
```

**达成路径**

model.cells_and_names() -> name -> cell.cell_prefix -> file name

**验证说明**: External Control: Cell names used in file name without validation.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [PYTORCH_DUMP_KERNEL_CONFIG_CPP_001] Cross-Module Interface Risk - start_kernel_dump

**严重性**: Medium | **CWE**: CWE-749 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: python-security-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/dump/data_dump/data_processor/pytorch_processor.py:857-861` @ `start_kernel_dump`
**模块**: pytorch_dump
**跨模块**: pytorch_dump → torch_npu → adump_cxx

**描述**: start_kernel_dump调用torch_npu.npu.set_dump(config_path)，是Python到C++的跨语言接口调用。config_path传递给底层C++模块，需验证C++路径处理安全性。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/dump/data_dump/data_processor/pytorch_processor.py:857-861`)

```c
torch_npu.npu.set_dump(config_path)
```

**达成路径**

kernel_config.py -> JSON文件 -> torch_npu.npu.set_dump(C++接口)

**验证说明**: Cross-Module Interface: torch_npu.npu.set_dump passes path to C++.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 10 | mitigations: -5 | reachability: 15

---

### [infer_offline_onnx_load_001] Unsafe Model Loading - _load_onnx

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/infer/offline/compare/msquickcmp/onnx_model/onnx_dump_data.py:170` @ `_load_onnx`
**模块**: infer_offline

**描述**: onnx.load_model used without security options. ONNX model files could potentially contain malicious payloads. While file validation exists, the model loading process should be reviewed for security.

**漏洞代码** (`python/msprobe/infer/offline/compare/msquickcmp/onnx_model/onnx_dump_data.py:170`)

```c
onnx_model = onnx.load_model(model_path)
```

**验证说明**: Unsafe Model Loading: onnx.load_model without security options.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [VULN-ADUMP-005] Improper Input Validation - IsPathCharactersValid

**严重性**: Medium | **CWE**: CWE-74 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ccsrc/adump/utils/FileUtils.cpp:152-160` @ `IsPathCharactersValid`
**模块**: adump_utils

**描述**: Insufficient path character validation. IsPathCharactersValid only checks for alphanumeric and limited special chars.

**漏洞代码** (`ccsrc/adump/utils/FileUtils.cpp:152-160`)

```c
isalnum check plus limited whitelist
```

**验证说明**: Improper Input Validation: IsPathCharactersValid has insufficient character whitelist.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [DF-007] regex_injection - KernelListMatcher::Parse

**严重性**: Medium | **CWE**: CWE-1333 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `ccsrc/adump/base/DebuggerConfig.cpp:218-264` @ `KernelListMatcher::Parse`
**模块**: adump_base

**描述**: KernelListMatcher::Parse 函数接收用户配置的 kernel 表达式列表，直接构造正则表达式用于匹配。恶意正则表达式可能导致 ReDoS。

**漏洞代码** (`ccsrc/adump/base/DebuggerConfig.cpp:218-264`)

```c
regexList.emplace_back(expression.substr(REGEX_INDEX, len - REGEX_INDEX));
...
re2::RE2 reg(pattern, re2::RE2::Quiet);
```

**达成路径**

JSON 配置 list 字段 → KernelListMatcher::Parse → 提取正则表达式 → re2::RE2 构造 → 匹配 kernel 名称

**验证说明**: Regex Injection Risk: KernelListMatcher::Parse uses user regex. RE2 library provides ReDoS protection.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [core_compare-009] Improper Link Resolution - compare_torchair_mode

**严重性**: Medium | **CWE**: CWE-59 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/compare/torchair_acc_cmp.py:672-679` @ `compare_torchair_mode`
**模块**: core_compare

**描述**: os.path.realpath used before symlink validation in compare_torchair_mode

**验证说明**: Improper Link Resolution: os.path.realpath used before symlink validation in compare_torchair_mode.

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [infer_offline_env_var_001] Environment Variable Injection - global

**严重性**: Medium（原评估: medium → 验证后: Medium） | **CWE**: CWE-78 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/infer/offline/compare/msquickcmp/main.py:37` @ `global`
**模块**: infer_offline
**跨模块**: msprobe.infer.offline.compare.msquickcmp.atc.atc_utils,msprobe.infer.utils.util

**描述**: ASCEND_TOOLKIT_HOME environment variable used without validation. While the path is later validated via realpath and directory checks, an attacker controlling the environment could potentially influence the CANN path used for external tool execution.

**漏洞代码** (`python/msprobe/infer/offline/compare/msquickcmp/main.py:37`)

```c
CANN_PATH = os.environ.get(ASCEND_TOOLKIT_HOME, /usr/local/Ascend/ascend-toolkit/latest)
```

**验证说明**: Environment Variable: ASCEND_TOOLKIT_HOME used without validation.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 5 | mitigations: -10 | reachability: 20

---

## 5. Low 漏洞 (25)

### [MSDUMP-CWE453-001] Insecure Insertion of Sensitive Information - handle

**严重性**: Low（原评估: low → 验证后: Low） | **CWE**: CWE-453 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/mindspore/dump/dump_processor/kernel_graph_dump.py:73-80` @ `handle`
**模块**: mindspore_dump
**跨模块**: mindspore_dump, C++_adump_module

**描述**: Dump configuration file paths are exposed through environment variables MINDSPORE_DUMP_CONFIG and MS_ACL_DUMP_CFG_PATH. These paths could contain sensitive information about the system layout and are visible to child processes.

**漏洞代码** (`python/msprobe/mindspore/dump/dump_processor/kernel_graph_dump.py:73-80`)

```c
os.environ["MINDSPORE_DUMP_CONFIG"] = json_path\n        if self.dump_json["common_dump_settings"]["dump_mode"] == 0:\n            if self.dump_json["common_dump_settings"]["iteration"] != "all" or ...\n                os.environ["MS_ACL_DUMP_CFG_PATH"] = json_path
```

**达成路径**

json_path -> os.environ["MINDSPORE_DUMP_CONFIG"] -> child processes

**验证说明**: Sensitive Info Exposure: Dump config paths exposed via environment variables.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 20

---

### [MSDUMP-CWE453-002] Insecure Insertion of Sensitive Information - handle

**严重性**: Low（原评估: low → 验证后: Low） | **CWE**: CWE-453 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/mindspore/dump/dump_processor/kernel_kbyk_dump.py:109-111` @ `handle`
**模块**: mindspore_dump
**跨模块**: mindspore_dump, C++_adump_module

**描述**: Dump configuration file path is set in MINDSPORE_DUMP_CONFIG environment variable, exposing the dump directory path to all child processes and potentially other applications.

**漏洞代码** (`python/msprobe/mindspore/dump/dump_processor/kernel_kbyk_dump.py:109-111`)

```c
os.environ["MINDSPORE_DUMP_CONFIG"] = json_path\n        if "MS_ACL_DUMP_CFG_PATH" in os.environ:\n            del os.environ["MS_ACL_DUMP_CFG_PATH"]
```

**达成路径**

json_path -> os.environ["MINDSPORE_DUMP_CONFIG"] -> visible to child processes

**验证说明**: Sensitive Info Exposure: MINDSPORE_DUMP_CONFIG environment variable.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 20

---

### [CLI-002-dual-arg-pass] improper_input_validation - main

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/msprobe.py:82` @ `main`
**模块**: cli_entry
**跨模块**: cli_entry → compare_cli

**描述**: compare_cli同时接收args对象和sys.argv[1:]原始参数，造成参数处理不一致。check_valid_args()函数使用原始sys_argv验证，而实际功能使用args对象。这种双重参数传递模式可能导致验证绕过。

**漏洞代码** (`python/msprobe/msprobe.py:82`)

```c
compare_cli(args, sys.argv[1:])
```

**达成路径**

sys.argv -> argparse.parse_args -> args + sys.argv[1:] -> compare_cli -> check_valid_args(sys_argv) vs compare_func(args)

**验证说明**: Dual arg pass: compare_cli receives args and sys.argv - validation inconsistency.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 20

---

### [XF-003] cross_module_data_flow - 跨模块调用链

**严重性**: Low | **CWE**: CWE-22 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `跨模块: cli_entry → visualization → core_file_utils:0` @ `跨模块调用链`
**模块**: cross_module
**跨模块**: cli_entry → visualization → core_file_utils

**描述**: 跨模块数据流: CLI 路径 → 可视化服务。target_path 从 CLI 传入，通过 check_file_or_directory_path 验证后用于图构建。路径验证在 core_file_utils 模块完成。

**漏洞代码** (`跨模块: cli_entry → visualization → core_file_utils:0`)

```c
Python: args.target_path → _graph_service_command → check_file_or_directory_path
```

**达成路径**

[OUT] cli_entry.main → target_path
[IN] visualization._graph_service_command ← args
[OUT] visualization → npu_path
[IN] core_file_utils.check_file_or_directory_path ← path

**验证说明**: Cross-module path flow: CLI path to visualization, validated by check_file_or_directory_path. Lower risk - mitigated.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 15

---

### [adump-third-party-004] Execution with Unnecessary Privileges - AclApiAcldumpRegCallback

**严重性**: Low | **CWE**: CWE-250 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/third_party/ACL/AclApi.cpp:137-154` @ `AclApiAcldumpRegCallback`
**模块**: adump_third_party
**跨模块**: adump_third_party,adump_core

**描述**: Callback registration mechanism allows external code to register functions that will be invoked during dump operations. The callback AclDumpCallBack is passed directly to the external ACL library without any sandboxing or privilege restrictions.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/third_party/ACL/AclApi.cpp:137-154`)

```c
staticAclRet = g_acldumpRegCallbackFunc(messageCallback, flag);
```

**验证说明**: Execution with Unnecessary Privileges: Callback registration to ACL without sandboxing. Lower risk - ACL is trusted infrastructure.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 5 | mitigations: -5 | reachability: 15

---

### [MSDUMP-CWE362-001] Race Condition - is_download_finished

**严重性**: Low（原评估: low → 验证后: Low） | **CWE**: CWE-362 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/mindspore/dump/dump_processor/cell_dump_process.py:581-601` @ `is_download_finished`
**模块**: mindspore_dump

**描述**: The is_download_finished function checks for directory existence and then lists directory contents without atomic operations. Between the check and the listing, the directory state could change, leading to TOCTOU race condition.

**漏洞代码** (`python/msprobe/mindspore/dump/dump_processor/cell_dump_process.py:581-601`)

```c
def is_download_finished(directory, save_flag):\n    time.sleep(0.5)\n    if not os.path.exists(directory):\n        return False\n    for entry_path in os.listdir(directory):...
```

**达成路径**

directory check -> os.path.exists() -> os.listdir() -> race window

**验证说明**: Race Condition: is_download_finished TOCTOU in directory operations.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [PYTORCH_DUMP_PATH_PATTERN_WEAK_001] Incomplete Path Validation - check_path_before_create

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: python-security-module-scanner

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/common/file_utils.py:334-343` @ `check_path_before_create`
**模块**: pytorch_dump
**跨模块**: pytorch_dump → core_common

**描述**: FILE_PATTERN正则(r'^[a-zA-Z0-9_./-]+$')允许'..'字符，路径遍历检查应在realpath之前进行而非之后。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/common/file_utils.py:334-343`)

```c
if not re.match(FileCheckConst.FILE_PATTERN, path):
```

**达成路径**

check_path_before_create -> realpath -> FILE_PATTERN匹配

**验证说明**: Incomplete Path Validation: FILE_PATTERN allows '..' but realpath mitigates.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 5 | mitigations: -10 | reachability: 20

---

### [overflow_check-003] Improper Validation of Array Index - CommunicationNode._resolve_type

**严重性**: Low | **CWE**: CWE-129 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/overflow_check/graph.py:94-99` @ `CommunicationNode._resolve_type`
**模块**: overflow_check

**描述**: op_name分割后检查长度小于4时抛出异常，但后续代码直接访问op_name_split[1]和op_name_split[2]没有进一步验证内容有效性。虽然已有基本检查，但错误处理不完整。

**漏洞代码** (`python/msprobe/overflow_check/graph.py:94-99`)

```c
op_name_split = self.data.op_name.split(Const.SEP)\nif len(op_name_split) < 4:\n    raise RuntimeError(...)\nself.api = op_name_split[1]\nself.call_cnt = op_name_split[2]
```

**验证说明**: Array Index Validation: op_name split has basic checks but incomplete.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [VULN-core_config_check-002] Improper Input Validation - _run_config_checking_command

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/core/config_check/config_check_cli.py:40-46` @ `_run_config_checking_command`
**模块**: core_config_check

**描述**: File extension check bypass risk: Using str.endswith(chr(39)+chr(122)+chr(105)+chr(112)+chr(39)) allows bypass via files like malicious.zip.txt. While downstream check_file_suffix provides additional validation, this initial check is weak.

**漏洞代码** (`python/msprobe/core/config_check/config_check_cli.py:40-46`)

```c
if args.compare[0].endswith(chr(39)+chr(122)+chr(105)+chr(112)+chr(39)):
```

**验证说明**: Input Validation: Weak extension check but downstream validation exists.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -10 | reachability: 20

---

### [ee0fd92d-623a-4cc5-9f16-5eee037d95ca] Regex Injection - KernelListMatcher::Parse

**严重性**: Low | **CWE**: CWE-1333 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/base/DebuggerConfig.cpp:218-264` @ `KernelListMatcher::Parse`
**模块**: adump_base

**描述**: KernelListMatcher::Parse accepts user-controlled regular expressions from configuration file. While re2 library provides some protection against ReDoS, complex regex patterns with large kernel lists could still cause performance degradation. The regex is matched against fullKernelList which could contain many entries.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/ccsrc/adump/base/DebuggerConfig.cpp:218-264`)

```c
regexList.emplace_back(expression.substr(REGEX_INDEX, len - REGEX_INDEX));
```

**达成路径**

LoadConfig -> Parse -> StatisticsCfg::Parse/DumpTensorCfg::Parse -> matcher.Parse

**验证说明**: Regex Injection: User regex in config parsed by RE2. RE2 protects against ReDoS. Lower risk.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -10 | reachability: 15

---

### [DF-001] path_traversal - FileCheckConst.FILE_VALID_PATTERN

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `python/msprobe/core/common/const.py:747` @ `FileCheckConst.FILE_VALID_PATTERN`
**模块**: core_file_utils

**描述**: FILE_VALID_PATTERN 正则表达式 (r'^[a-zA-Z0-9_.:/-]+$') 允许 '..' 字符组合，虽然后续有 os.path.realpath() 处理，但正则验证本身存在潜在路径遍历风险。需确认所有路径处理都经过了 realpath 标准化。

**漏洞代码** (`python/msprobe/core/common/const.py:747`)

```c
FILE_VALID_PATTERN = r"^[a-zA-Z0-9_.:/-]+$"
```

**达成路径**

用户输入路径 → check_path_pattern_valid → FILE_VALID_PATTERN 验证 → 允许 '..' 字符 → os.path.realpath() 处理

**验证说明**: Path Validation: FILE_VALID_PATTERN allows '..' but realpath handles traversal. Mitigated - lower risk.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -10 | reachability: 15

---

### [DF-008] csv_injection - FileCheckConst.CSV_BLACK_LIST

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-123 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `python/msprobe/core/common/const.py:802` @ `FileCheckConst.CSV_BLACK_LIST`
**模块**: core_file_utils

**描述**: CSV_BLACK_LIST 正则表达式用于检测 CSV 公式注入，但正则表达式可能不完整。检查以危险字符开头的值，但不检查嵌入式公式。

**漏洞代码** (`python/msprobe/core/common/const.py:802`)

```c
CSV_BLACK_LIST = r'^[＋－＝％＠\+\-=%@]|;[＋－＝％＠\+\-=%@]'
```

**达成路径**

用户数据 → CSV 写入 → csv_value_is_valid 检查 → CSV_BLACK_LIST 验证 → 允许或拒绝

**验证说明**: CSV Injection: CSV_BLACK_LIST regex may miss embedded formulas. Mitigated by output handling.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -10 | reachability: 15

---

### [CLI-003-manual-dispatch] improper_subcommand_handling - main

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/msprobe.py:81-103` @ `main`
**模块**: cli_entry

**描述**: main()使用手动if-elif字符串匹配(sys.argv[1]=="compare")分发子命令，而非依赖argparse的subparser机制。这种模式容易出错，且无法利用argparse的内置验证功能。添加新命令时需手动维护两处逻辑(subparsers.add_parser和if-elif链)。

**漏洞代码** (`python/msprobe/msprobe.py:81-103`)

```c
if sys.argv[1] == "compare":\n    compare_cli(args, sys.argv[1:])\nelif sys.argv[1] == "merge_result":\n    merge_result_cli(args)\n...
```

**达成路径**

sys.argv[1] -> manual string comparison -> subcommand dispatch

**验证说明**: Manual Dispatch: if-elif string matching instead of subparser.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -10 | reachability: 20

---

### [infer_offline_resource_001] Resource Exhaustion - parse_dym_shape_range

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-400 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/infer/offline/compare/msquickcmp/common/utils.py:521-582` @ `parse_dym_shape_range`
**模块**: infer_offline

**描述**: parse_dym_shape_range can generate excessive shape combinations if user provides large dynamic shape ranges. While there is a DYM_SHAPE_END_MAX limit and user confirmation prompt, the itertools.product operation could still cause memory/performance issues.

**漏洞代码** (`python/msprobe/infer/offline/compare/msquickcmp/common/utils.py:521-582`)

```c
itertools.product generates all combinations
```

**验证说明**: Resource Exhaustion: parse_dym_shape_range generates combinations.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -10 | reachability: 15

---

### [overflow_check-004] Improper Input Validation - OverFlowCheck._resolve_input_path

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/overflow_check/analyzer.py:51-65` @ `OverFlowCheck._resolve_input_path`
**模块**: overflow_check

**描述**: parse输入路径时仅检查rank目录名称的startswith和isdigit，没有对完整的路径进行更严格校验。攻击者可能通过构造特殊目录名绕过检查。入口点有check_file_or_directory_path但子目录处理较宽松。

**漏洞代码** (`python/msprobe/overflow_check/analyzer.py:51-65`)

```c
for path in contents:\n    if not path.startswith('rank'):\n        continue\n    rank_str = path[len('rank'):]\n    if not rank_str:\n        rank = 0\n    elif not rank_str.isdigit():\n        continue
```

**验证说明**: Input Validation: rank directory validation is loose.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [DF-002] input_validation - IsPathCharactersValid

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `ccsrc/adump/utils/FileUtils.cpp:152-160` @ `IsPathCharactersValid`
**模块**: adump_utils

**描述**: IsPathCharactersValid() 函数允许 '..' 字符组合通过验证。虽然 GetAbsPath() 后续会处理路径遍历，但验证函数本身不够严格。建议增强字符验证或明确依赖后续处理。

**漏洞代码** (`ccsrc/adump/utils/FileUtils.cpp:152-160`)

```c
for (const char& ch : path) { if (!std::isalnum(ch) && ch != '_' && ch != '.' && ch != ':' && ch != '/' && ch != '-') { return false; } } return true;
```

**达成路径**

用户输入路径 → IsPathCharactersValid → 允许 '.' → GetAbsPath → 处理 '..' → 返回标准化路径

**验证说明**: Input Validation: IsPathCharactersValid allows '..' but GetAbsPath handles traversal. Low risk - mitigated downstream.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 15

---

### [DF-012] json_parsing - load_mapping

**严重性**: Low | **CWE**: CWE-502 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `python/msprobe/core/dump/dump2db/dump2db.py:47-51` @ `load_mapping`
**模块**: core_dump
**跨模块**: core_file_utils → core_dump

**描述**: load_mapping 函数直接调用 load_json 加载映射文件，JSON 内容直接返回使用，未验证数据结构。虽然是安全解析方式，但需验证数据完整性。

**漏洞代码** (`python/msprobe/core/dump/dump2db/dump2db.py:47-51`)

```c
def load_mapping(mapping_path):
    if mapping_path and isinstance(mapping_path, str):
        return load_json(mapping_path)
    else:
        return {}
```

**达成路径**

CLI args.mapping → load_mapping → load_json → JSON 数据 → 直接使用

**验证说明**: JSON Parsing: load_mapping directly loads JSON without structure validation. Lower risk - simple mapping data.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 5 | mitigations: -10 | reachability: 15

---

### [core_compare-010] Improper Input Validation - process_output_file

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/core/compare/acc_compare.py:63-77` @ `process_output_file`
**模块**: core_compare

**描述**: process_output_file deletes file without explicit bounds validation

**验证说明**: Improper Input Validation: process_output_file deletes file without explicit bounds validation. Lower risk due to downstream checks.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 15

---

### [infer_offline_csv_write_001] CSV Injection - _write_csv

**严重性**: Low（原评估: low → 验证后: Low） | **CWE**: CWE-1236 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/msprobe/infer/offline/compare/msquickcmp/cmp_process.py:118-124` @ `_write_csv`
**模块**: infer_offline
**跨模块**: msprobe.infer.utils.file_open_check

**描述**: sanitize_csv_value is called but result not used in cmp_process.py _write_csv function. The sanitized values are computed but not stored before writing to CSV, potentially allowing formula injection.

**漏洞代码** (`python/msprobe/infer/offline/compare/msquickcmp/cmp_process.py:118-124`)

```c
for ele in line:\n    _ = sanitize_csv_value(ele)\nwriter.writerows(rows)
```

**验证说明**: CSV Injection: sanitize_csv_value called but result not used.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 5 | mitigations: -10 | reachability: 15

---

### [DF-005] deserialization - SafeUnpickler.find_class

**严重性**: Low | **CWE**: CWE-502 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `python/msprobe/core/common/file_utils.py:1116-1122` @ `SafeUnpickler.find_class`
**模块**: core_file_utils

**描述**: SafeUnpickler 实现了白名单机制限制反序列化类型，但白名单可能不够完善。WHITELIST 仅包含基本类型，这是安全的实现。标记为低风险作为安全审计参考。

**漏洞代码** (`python/msprobe/core/common/file_utils.py:1116-1122`)

```c
WHITELIST = {'builtins': {'str', 'bool', 'int', 'float', 'list', 'set', 'dict'}}
def find_class(self, module, name):
    if module in self.WHITELIST and name in self.WHITELIST[module]:
        return super().find_class(module, name)
    raise pickle.PicklingError(f'Unpickling {module}.{name} is illegal!')
```

**达成路径**

共享内存数据 → pickle.loads → SafeUnpickler.find_class → 白名单检查 → 仅允许基本类型

**验证说明**: SafeUnpickler Whitelist: Implements whitelist for basic types - secure. Reference audit item.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -15 | reachability: 10

---

### [DF-013] path_traversal - _graph_service_command

**严重性**: Low | **CWE**: CWE-22 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `python/msprobe/visualization/graph_service.py:523-567` @ `_graph_service_command`
**模块**: visualization
**跨模块**: cli_entry → visualization → core_file_utils

**描述**: _graph_service_command 函数接收用户提供的 target_path 和 golden_path，通过 check_file_or_directory_path 验证。验证函数已实现路径规范化，风险较低。

**漏洞代码** (`python/msprobe/visualization/graph_service.py:523-567`)

```c
check_file_or_directory_path(npu_path, isdir=True)
if bench_path:
    check_file_or_directory_path(bench_path, isdir=True)
```

**达成路径**

CLI args → target_path/golden_path → check_file_or_directory_path → os.path.realpath → 验证通过

**验证说明**: Path Traversal: _graph_service_command validates paths via check_file_or_directory_path. Mitigated.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 5 | mitigations: -15 | reachability: 10

---

### [DF-014] numpy_deserialization - load_npy

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-502 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `python/msprobe/core/common/file_utils.py:515-522` @ `load_npy`
**模块**: core_file_utils

**描述**: load_npy 函数使用 np.load 加载 numpy 文件，已设置 allow_pickle=False 防止反序列化攻击。这是安全的实现方式，标记为参考审计项。

**漏洞代码** (`python/msprobe/core/common/file_utils.py:515-522`)

```c
npy = np.load(filepath, allow_pickle=False)
```

**达成路径**

CLI filepath → check_file_or_directory_path → np.load(allow_pickle=False) → numpy 数组

**验证说明**: Numpy Deserialization: load_npy uses allow_pickle=False - safe implementation. Reference audit item.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -15 | reachability: 10

---

### [DF-015] yaml_deserialization - load_yaml

**严重性**: Low | **CWE**: CWE-502 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `python/msprobe/core/common/file_utils.py:503-512` @ `load_yaml`
**模块**: core_file_utils

**描述**: load_yaml 函数使用 yaml.safe_load 安全加载 YAML 文件，避免反序列化攻击。这是安全实现，标记为参考审计项。

**漏洞代码** (`python/msprobe/core/common/file_utils.py:503-512`)

```c
yaml_data = yaml.safe_load(f)
```

**达成路径**

CLI yaml_path → FileChecker → FileOpen → yaml.safe_load → YAML 数据

**验证说明**: YAML Deserialization: yaml.safe_load used - secure. Reference audit item.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -15 | reachability: 10

---

### [VIS-001] unknown - unknown

**严重性**: Low（原评估: low → 验证后: Low） | **CWE**: CWE-376 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprobe/python/msprobe/visualization/graph_service.py:43-45` @ `?`
**模块**: visualization

**描述**: Predictable filename generation using time.strftime() for database output files. Race condition potential mitigated by file locks and path validation.

**验证说明**: Predictable Filename: time.strftime() for database output.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: -15 | reachability: 15

---

### [DF-016] input_validation - main

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `python/msprobe/msprobe.py:34-104` @ `main`
**模块**: cli_entry
**跨模块**: cli_entry → core_compare → core_dump → visualization

**描述**: main 函数是 CLI 入口点，使用 argparse 解析命令行参数。参数分发到各子命令处理函数，下游模块有验证机制。入口点设计合理。

**漏洞代码** (`python/msprobe/msprobe.py:34-104`)

```c
args = parser.parse_args(sys.argv[1:])
if sys.argv[1] == 'compare':
    compare_cli(args, sys.argv[1:])
```

**达成路径**

sys.argv → argparse → args → 子命令处理函数 → 下游验证

**验证说明**: CLI Entry: main uses argparse with downstream validation. Well-designed entry point.

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 5 | mitigations: -20 | reachability: 10

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| adump_base | 0 | 0 | 6 | 1 | 7 |
| adump_core | 0 | 3 | 4 | 0 | 7 |
| adump_if_python | 0 | 3 | 4 | 0 | 7 |
| adump_third_party | 0 | 0 | 3 | 1 | 4 |
| adump_utils | 0 | 5 | 6 | 1 | 12 |
| cli_entry | 0 | 0 | 1 | 3 | 4 |
| core_compare | 0 | 0 | 7 | 1 | 8 |
| core_config_check | 0 | 1 | 0 | 1 | 2 |
| core_dump | 0 | 0 | 1 | 1 | 2 |
| core_file_utils | 0 | 0 | 1 | 5 | 6 |
| cross_module | 0 | 0 | 2 | 1 | 3 |
| infer_offline | 0 | 0 | 5 | 2 | 7 |
| mindspore_dump | 0 | 0 | 5 | 3 | 8 |
| overflow_check | 0 | 0 | 2 | 2 | 4 |
| pytorch_dump | 0 | 1 | 2 | 1 | 4 |
| visualization | 0 | 0 | 0 | 2 | 2 |
| **合计** | **0** | **13** | **49** | **25** | **87** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 17 | 19.5% |
| CWE-22 | 14 | 16.1% |
| CWE-502 | 8 | 9.2% |
| CWE-73 | 5 | 5.7% |
| CWE-362 | 5 | 5.7% |
| CWE-190 | 4 | 4.6% |
| CWE-59 | 3 | 3.4% |
| CWE-88 | 2 | 2.3% |
| CWE-78 | 2 | 2.3% |
| CWE-453 | 2 | 2.3% |
| CWE-400 | 2 | 2.3% |
| CWE-367 | 2 | 2.3% |
| CWE-1333 | 2 | 2.3% |
| CWE-94 | 1 | 1.1% |
| CWE-822 | 1 | 1.1% |
| CWE-807 | 1 | 1.1% |
| CWE-754 | 1 | 1.1% |
| CWE-749 | 1 | 1.1% |
| CWE-74 | 1 | 1.1% |
| CWE-667 | 1 | 1.1% |
| CWE-476 | 1 | 1.1% |
| CWE-426 | 1 | 1.1% |
| CWE-416 | 1 | 1.1% |
| CWE-376 | 1 | 1.1% |
| CWE-269 | 1 | 1.1% |
| CWE-252 | 1 | 1.1% |
| CWE-250 | 1 | 1.1% |
| CWE-129 | 1 | 1.1% |
| CWE-1236 | 1 | 1.1% |
| CWE-123 | 1 | 1.1% |
| CWE-119 | 1 | 1.1% |
| CWE-114 | 1 | 1.1% |
