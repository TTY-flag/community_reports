# Threat Analysis Report

## MindStudio Kernel Performance Prediction (msKPP)

**Project Type:** Python Library with C++ Extension  
**Version:** 0.0.0.dev0  
**Analysis Date:** 2026-04-21  
**Analyzer:** Architecture Agent

---

## Executive Summary

MindStudio Kernel Performance Prediction (msKPP) is a performance simulation tool for Ascend AI operators. It provides a Python API backed by C++ extensions for predicting operator performance without actual computation execution. The project is primarily a **library** that users import and use in their own code, rather than a network service or standalone CLI tool.

**Overall Risk Level:** **MEDIUM**

The primary attack vectors are:
1. **Python-C++ Binding vulnerabilities** - Type confusion, null pointer dereference, integer overflow
2. **Supply chain attacks** - External dependency download mechanism
3. **File I/O operations** - Path traversal and permission issues
4. **User input validation gaps** - Tensor parameter handling

---

## 1. Project Architecture

### 1.1 Project Type Classification

| Aspect | Classification |
|--------|----------------|
| Primary Type | **Python Library** |
| Secondary Type | **Native Extension Module** |
| Deployment Model | User-installed Python package |
| Network Exposure | **None** - No network interfaces |
| CLI Entry Points | Build scripts only (build.py, download_dependencies.py) |

### 1.2 Component Overview

```
msKPP Architecture
==================

┌─────────────────────────────────────────────────────────────┐
│                    User Python Code                          │
│                  (imports mskpp module)                      │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    mskpp Python Package                      │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────────┐  │
│  │   __init__.py │  │    apis.py    │  │     core/       │  │
│  │   (exports)   │──│ (InstrAPI)    │──│  (Tensor,Chip)  │  │
│  └───────────────┘  └───────────────┘  └─────────────────┘  │
│         │                  │                   │            │
│         │                  │                   │            │
│         │                  │                   │            │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────────┐  │
│  │ intrisic_api/ │  │   prof_data/  │  │     utils/      │  │
│  │ (inference)   │  │  (perf data)  │  │  (safe_check)   │  │
│  └───────────────┘  └───────────────┘  └─────────────────┘  │
│         │                  │                   │            │
└─────────┼──────────────────┼───────────────────┼────────────┘
          │                  │                   │
          ▼                  ▼                   ▼
┌─────────────────────────────────────────────────────────────┐
│               mskpp._C (C Extension Module)                  │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────────┐  │
│  │   arch        │  │  prof_data    │  │  task_schedule  │  │
│  │ (arch info)   │  │(data adapter) │  │    (pipeline)   │  │
│  └───────────────┘  └───────────────┘  └─────────────────┘  │
│         │                  │                   │            │
└─────────┼──────────────────┼───────────────────┼────────────┘
          │                  │                   │
          ▼                  ▼                   ▼
┌─────────────────────────────────────────────────────────────┐
│                  C++ Native Implementation                   │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────────┐  │
│  │   csrc/core   │  │ csrc/prof_data│  │csrc/interface   │  │
│  │ (arch_info)   │  │(data_adapter) │  │(Python bindings)│  │
│  └───────────────┘  └───────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Attack Surface Analysis

### 2.1 Entry Points

| Entry Point | Type | Description | Risk Level | Attack Vector |
|-------------|------|-------------|------------|---------------|
| **Python API** | Library | User imports mskpp and creates Tensor/Chip objects | Medium | Malformed input parameters, type confusion |
| **C++ Extension** | Native | Python calls C++ via `_C.so` | High | PyObject manipulation errors, memory safety |
| **Build Scripts** | CLI | `build.py` and `download_dependencies.py` | High | Supply chain attack, command injection |
| **File Output** | I/O | `trace.json`, CSV, HTML output | Low | Path traversal, permission issues |

### 2.2 Data Flow Analysis

#### 2.2.1 User API to Task Schedule Flow

```
User Python Code
    │
    ▼
InstrApiRegister.get("VADD") ─────────────────────────────────
    │                                                         │
    ▼                                                         │
InstrRegister.register(name, ...)                             │
    │                                                         │
    ▼                                                         │
ComputationInstruction.__init__(inputs, outputs)              │
    │                                                         │
    ├──► Tensor.param_check() ─► checker.is_mem_type_valid()  │
    ├──► Tensor.param_check() ─► checker.is_dtype_valid()     │
    └──► Tensor.param_check() ─► checker.is_shape_valid()     │
    │                                                         │
    ▼                                                         │
InstrTask(pipe_name, instruction)                             │
    │                                                         │
    ▼                                                         │
task_schedule.Schedule().add_task(task)                       │
    │                                                         │
    ▼ [Python-C Boundary]                                     │
MSKPP_SCHEDULE_AddTask(PyObject *task)                        │
    │                                                         │
    ├──► RawTask::CheckPyObj(task)                            │
    ├──► RawTask::Run() ─► PyObject_CallObject                │
    │                                                         │
    ▼                                                         │
TaskSchedule::AddTask(RawTask)                                │
```

#### 2.2.2 Tensor Creation and Memory Instruction Flow

```
Tensor("UB", "FP16", [32, 48], "ND")
    │
    ▼
Tensor.__init__(mem_type, dtype, size, format)
    │
    ├──► self.param_check(self)
    │       │
    │       ├──► checker.is_mem_type_valid() ─► "UB" in valid_mem_type?
    │       ├──► checker.is_dtype_valid() ─► "FP16" in valid_dtype?
    │       ├──► checker.is_shape_valid() ─► [32, 48] validation
    │       └──► checker.is_format_valid() ─► "ND" in valid_format?
    │
    ▼
Tensor.load(other_tensor)
    │
    ├──► MemoryInstruction(src, dst, trans_enable)
    │
    ▼ [Python-C Boundary]
prof_data.MOV.get(src, dst, dataSize, transEnable)
    │
    ▼
MSKPP_PROFDATA_MOVRegister(PyObject *args)
    │
    ├──► PyArg_ParseTuple(args, "ssli", &src, &dst, &dataSize, &transEnable)
    │
    ▼
MovClass::Get(src, dst, dataSize, transEnable)
    │
    ├──► GetMovTypeData(movPath) ─► Lookup performance table
    │
    ▼
LinearInterpolate(curves, dataSize) ─► Return estimated cycles
```

#### 2.2.3 Dependency Download Flow

```
build.py / download_dependencies.py
    │
    ▼
DependencyManager(args)
    │
    ├──► self.config = json.loads(dependencies.json)
    │
    ▼
DependencyManager.proc_artifact(artifacts, spec)
    │
    ├──► subprocess.run(["curl", "-Lfk", "--retry", "5", url])
    │       │
    │       ▼ [HTTP Download]
    │       External Server (mirrors.aliyun.com, gitee.com)
    │
    ├──► hashlib.sha256(archive_path.read_bytes()).hexdigest()
    │       │
    │       ▼ [SHA256 Verification]
    │       Compare with expected hash
    │
    ├──► subprocess.run(["tar", "-xf", archive_path])
    │       │
    │       ▼ [Archive Extraction]
    │       Extract files to temporary directory
    │
    ▼
shutil.move(source, target)
```

---

## 3. Vulnerability Categories

### 3.1 Python-C++ Binding Vulnerabilities (HIGH RISK)

**Location:** `csrc/interface/*.cpp`

#### 3.1.1 PyArg_ParseTuple Usage

**Files Affected:**
- `csrc/interface/init_profdata_module.cpp` (lines 44, 56, 67, etc.)

**Potential Issues:**
- **Type Confusion:** If argument format string doesn't match actual Python objects
- **Argument Count Mismatch:** If nargs check is incorrect
- **Integer Overflow:** Using `long` for dataSize, which can overflow for large tensor sizes

**Example from code:**
```cpp
// Line 44 in init_profdata_module.cpp
if (!PyArg_ParseTuple(pstArgs, "ssli", &src, &dst, &dataSize, &transEnable)) { Py_RETURN_NONE; }
```

**Risk:** dataSize is parsed as `long`, which can be negative or overflow when passed to MovClass::Get

#### 3.1.2 PyUnicode_AsUTF8AndSize Usage

**Files Affected:**
- `csrc/interface/init_arch_module.cpp` (lines 35, 84, etc.)
- `csrc/core/task_schedule/raw_task.cpp`

**Potential Issues:**
- **Null Pointer Dereference:** If PyObject is not a Unicode object, returns NULL
- **Buffer Pointer Lifetime:** Pointer only valid while PyObject exists
- **No Length Bounds Check:** Extracted string can be arbitrary length

**Example from code:**
```cpp
// Lines 35-41 in init_arch_module.cpp
s = PyUnicode_AsUTF8AndSize(args[0], &len);
if (!s) {
    PyErr_SetString(PyExc_TypeError, "ChipType except a string value.");
    Py_RETURN_NONE;
}
ArchInfo::instance()->SetChipType(std::string(s));
```

**Risk:** No validation of chip type string against valid chip types before setting

#### 3.1.3 PyLong_AsLongLong Usage

**Files Affected:**
- `csrc/interface/init_arch_module.cpp` (lines 52, 110)
- `csrc/core/task_schedule/raw_task.cpp`

**Potential Issues:**
- **Overflow:** Values larger than LLONG_MAX cause overflow (-1 returned)
- **Error Detection:** -1 is also returned on error, causing ambiguity

**Example from code:**
```cpp
// Lines 51-57 in init_arch_module.cpp
if (PyLong_CheckExact(args[0])) {
    long long value = PyLong_AsLongLong(args[0]);
    if (value == -1 && PyErr_Occurred()) {
        PyErr_SetString(PyExc_OverflowError, "...");
        Py_RETURN_NONE;
    }
    cycle = static_cast<double>(value);
}
```

#### 3.1.4 PyObject_CallObject Usage

**Files Affected:**
- `csrc/core/task_schedule/raw_task.cpp`

**Potential Issues:**
- **Arbitrary Code Execution:** Calls Python methods from C++, which could execute arbitrary code if PyObject is crafted maliciously
- **Null Pointer:** If PyObject is NULL or not callable

---

### 3.2 Supply Chain Attack (HIGH RISK)

**Location:** `download_dependencies.py`

#### 3.2.1 External Dependency Download

**Attack Vector:**
1. **Man-in-the-Middle Attack:** HTTP downloads without TLS certificate verification
2. **Malicious Package Injection:** Downloaded archives could be replaced with malicious versions
3. **Hash Collision:** SHA256 verification provides some protection, but hash collisions are theoretically possible

**Code Analysis:**
```python
# Lines 104-107 in download_dependencies.py
self._exec_shell_cmd(["curl", "-Lfk", "--retry", "5", "--retry-delay", "2",
                      "-o", str(archive_path), url], msg=f"Download {name} ...")
if sha and hashlib.sha256(archive_path.read_bytes()).hexdigest() != sha:
    sys.exit(f"SHA256 mismatch for {name}")
```

**Mitigations Present:**
- SHA256 hash verification ✓
- Retry mechanism ✓

**Weaknesses:**
- `-k` flag disables SSL certificate verification ✗
- No signature verification ✗
- URLs point to external mirrors ✗

---

### 3.3 File I/O Operations (MEDIUM RISK)

**Location:** `mskpp/core/trace.py`, `mskpp/core/metric/`

#### 3.3.1 File Output Operations

**Files Affected:**
- `mskpp/core/trace.py` (lines 157-161)
- `mskpp/core/metric/output_tool.py` (lines 38-39)

**Potential Issues:**
- **Path Traversal:** If `output_dir` is user-controlled and not validated
- **Permission Issues:** Files created with `S_IWUSR | S_IRUSR` (user-only permissions)

**Code Analysis:**
```python
# Lines 150-161 in trace.py
trace_file = os.path.join(output_dir, "trace.json")
if checker.check_path_exists(trace_file):
    raise Exception("The file {} already exists, cannot generate, please remove it first".format(trace_file))
trace_obj = {...}
with os.fdopen(os.open(trace_file, OPEN_FLAGS, SAVE_DATA_FILE_AUTHORITY), 'w') as f:
    data = json.dumps(trace_obj)
    f.truncate()
    f.write(data)
```

**Mitigations Present:**
- Secure file permissions (`S_IWUSR | S_IRUSR`) ✓
- File existence check ✓
- Uses `os.fdopen` with explicit flags ✓

**Weaknesses:**
- No path traversal validation ✗
- No validation of `output_dir` parameter ✗

#### 3.3.2 File Input Validation

**Files Affected:**
- `mskpp/utils/safe_check.py`
- `mskpp/core/metric/file_system.py`

**Security Features:**
- Symbolic link detection ✓
- File owner consistency check ✓
- Group/others write permission check ✓
- File size limit ✓
- Path length limit ✓
- Invalid character detection ✓

---

### 3.4 User Input Validation (MEDIUM RISK)

**Location:** `mskpp/core/tensor.py`, `mskpp/core/common/checker.py`

#### 3.4.1 Tensor Parameter Validation

**Parameters Validated:**
- `mem_type`: Must be in ["GM", "UB", "L1", "L0A", "L0B", "L0C", "FB", "BT", "VEC"]
- `dtype`: Must be in ["BOOL", "UINT1", ..., "FP32"]
- `format`: Must be in ["NCHW", "NHWC", "ND", "NZ", "NC1HWC0", "FRACTAL", "FRACTAL_NZ"]
- `size`: Must be list of positive integers

**Potential Issues:**
- **Integer Overflow:** `LARGE_LONG_SIZE_THRESHOLD = 2^31 - 1` limits tensor size, but individual dimensions not limited
- **Empty String Handling:** No explicit check for empty strings in dtype/format

**Code Analysis:**
```python
# Lines 53-63 in checker.py
def is_shape_valid(param_shape_list):
    if not is_required_type(param_shape_list, list):
        return False
    if not param_shape_list:
        return False
    size = 1
    for dim in param_shape_list:
        if not is_int_type(dim) or dim < 0:
            return False
        size *= dim
    return check_convert_long_size(size)
```

**Risk:** Product of dimensions can overflow `size` variable during validation

---

### 3.5 Command Execution (MEDIUM RISK)

**Location:** `build.py`, `download_dependencies.py`

#### 3.5.1 subprocess.run Usage

**Files Affected:**
- `build.py` (lines 65, 72, 73, etc.)
- `download_dependencies.py` (lines 55, 83, etc.)

**Potential Issues:**
- **Command Injection:** If arguments contain shell metacharacters
- **Privilege Escalation:** Commands executed with user privileges

**Mitigations Present:**
- Arguments passed as list (not shell string) ✓
- `check=True` raises exception on failure ✓

**Weaknesses:**
- No input sanitization for revision/tag arguments ✗
- Git commands could execute hooks ✗

---

## 4. High-Risk Files Summary

| File | Risk Level | Primary Vulnerabilities |
|------|------------|------------------------|
| `csrc/interface/init_profdata_module.cpp` | **HIGH** | PyArg_ParseTuple, integer overflow, string handling |
| `csrc/interface/init_arch_module.cpp` | **HIGH** | PyUnicode_AsUTF8AndSize, chip type validation |
| `csrc/core/task_schedule/raw_task.cpp` | **HIGH** | PyObject_CallObject, arbitrary code execution |
| `download_dependencies.py` | **HIGH** | Supply chain attack, SSL bypass |
| `build.py` | **MEDIUM** | subprocess.run, git command execution |
| `mskpp/core/trace.py` | **MEDIUM** | File output, path validation |
| `mskpp/core/tensor.py` | **MEDIUM** | Parameter validation, integer overflow |

---

## 5. Security Features Inventory

### 5.1 Implemented Security Features

| Feature | Location | Effectiveness |
|---------|----------|---------------|
| **File Permission Checks** | `mskpp/utils/safe_check.py` | Good - comprehensive validation |
| **Secure File Open** | `mskpp/core/trace.py` | Good - uses `os.fdopen` with explicit permissions |
| **Input Validation** | `mskpp/core/common/checker.py` | Moderate - some gaps in overflow handling |
| **Compiler Security Flags** | `CMakeLists.txt` | Good - stack protection, fortify source, RELRO |
| **SHA256 Verification** | `download_dependencies.py` | Moderate - but SSL bypass present |

### 5.2 Compiler Security Flags

From `CMakeLists.txt`:
```cmake
target_compile_options(mskpp_c PRIVATE
    -std=c++11
    -Wall
    -fPIC
    -fstack-protector-all      # Stack overflow protection
    -D_FORTIFY_SOURCE=2        # Buffer overflow detection
    -fvisibility=hidden        # Symbol visibility
    -ftrapv                    # Signed integer overflow trap
    -fstack-check              # Stack checking
)

target_link_options(mskpp_c PRIVATE
    -Wl,-z,relro               # Read-only relocation
    -Wl,-z,now                 # Immediate binding
    -Wl,-z,noexecstack         # Non-executable stack
)
```

---

## 6. Recommendations

### 6.1 Critical Remediation

1. **Remove SSL Certificate Bypass**
   - Remove `-k` flag from curl command in `download_dependencies.py`
   - Add certificate verification

2. **Add Chip Type Validation**
   - Validate chip type string against enum values before setting
   - Add whitelist validation in `ArchInfo::SetChipType`

3. **Integer Overflow Prevention**
   - Use `size_t` or `uint64_t` for dataSize instead of `long`
   - Add explicit overflow checks in tensor size validation

### 6.2 High Priority Remediation

4. **Path Validation**
   - Add path traversal detection in trace dump
   - Validate output_dir parameter against base directory

5. **String Bounds Checking**
   - Add maximum length check for chip type strings
   - Add maximum length check for dtype/format strings

6. **PyObject Error Handling**
   - Add explicit NULL checks after all PyObject operations
   - Use PyErr_Occurred() consistently

### 6.3 Medium Priority Remediation

7. **Dependency Security**
   - Add package signature verification
   - Use HTTPS-only URLs
   - Pin dependency versions

8. **Input Sanitization**
   - Sanitize git revision/tag arguments
   - Add regex validation for string parameters

---

## 7. Appendix

### 7.1 File Statistics

| Category | Count | Lines |
|----------|-------|-------|
| Python Core Files | 52 | ~2000 |
| C++ Core Files | 24 | ~1500 |
| Python Interface Files | 4 | ~800 |
| Build Scripts | 3 | ~300 |

### 7.2 Excluded from Analysis

- `test/` - Testing code, not production
- `thirdparty/` - External dependencies
- `example/` - Usage examples
- `docs/` - Documentation

### 7.3 References

- Python C API Reference: https://docs.python.org/3/c-api/
- OWASP Supply Chain Security: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html
- CWE-190: Integer Overflow or Wraparound
- CWE-476: NULL Pointer Dereference
- CWE-22: Path Traversal

---

*Report Generated by Architecture Analysis Agent*
*Scan Session: architecture_analysis*