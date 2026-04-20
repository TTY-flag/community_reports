# 漏洞扫描报告 — 待确认漏洞

**项目**: DrivingSDK
**扫描时间**: 2026-04-20T00:18:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 44 | 53.7% |
| FALSE_POSITIVE | 33 | 40.2% |
| LIKELY | 3 | 3.7% |
| CONFIRMED | 2 | 2.4% |
| **总计** | **82** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 1 | 2.1% |
| Medium | 7 | 14.9% |
| Low | 39 | 83.0% |
| **有效漏洞总计** | **47** | - |
| 误报 (FALSE_POSITIVE) | 33 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SA-PY-003]** deserialization (High) - `model_examples/DriverAgent/evaluate.py:60` @ `model_evaluate` | 置信度: 75
2. **[scripts-003]** path_traversal (Medium) - `scripts/install_kernel.sh:50` @ `main` | 置信度: 65
3. **[scripts-004]** path_traversal (Medium) - `scripts/upgrade_kernel.sh:14` @ `main` | 置信度: 65
4. **[mx_driving_csrc_library_injection_001]** Library Injection (Medium) - `mx_driving/csrc/pybind.cpp:25` @ `init_op_api_so_path` | 置信度: 65
5. **[onnx_plugin_roi_align_negative_value_conversion]** Integer Overflow / Type Conversion (Medium) - `onnx_plugin/onnx_roi_align_rotated.cpp:34` @ `ParseParamsRoiAlignRotatedV2` | 置信度: 60
6. **[VULN-SA-CROSS-001]** untrusted_binding (Medium) - `mx_driving/__init__.py:179` @ `_set_env` | 置信度: 55
7. **[VULN-DF-001]** Shared Library Injection (Medium) - `mx_driving/get_chip_info.py:9` @ `find_library_in_ld_path / Dsmi_dc_Func.__init__` | 置信度: 55
8. **[mx_driving_csrc_nms3d_int_overflow_001]** Integer Overflow (Medium) - `mx_driving/csrc/Nms3d.cpp:24` @ `nms3d` | 置信度: 55
9. **[VULN-SA-PY-006]** command_injection (Low) - `ci/access_control_test.py:66` @ `find_ut_by_regex` | 置信度: 55
10. **[PY-DF-tests-001]** unsafe_deserialization (Low) - `tests/torch/data_cache.py:98` @ `load_data` | 置信度: 55

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `with_imports@mx_driving/patcher/patch.py` | decorator | semi_trusted | eval() used for decorator expression resolution within patcher framework. Decorator expressions come from predefined patch definitions (developer-controlled), not user input. Risk is limited to developers creating custom patches with malicious decorator strings. | Decorator expression evaluation in patcher framework |
| `load_data@tests/torch/data_cache.py` | file | untrusted_local | torch.load() used without weights_only=True to load cached test data from file paths. File paths come from test cache directory (developer-controlled environment) but could be manipulated if cache directory is writable by other users. | Loading cached test data via torch.load() |
| `__init__@model_examples/DriverAgent/data.py` | file | untrusted_local | torch.load() used without weights_only=True to load .pt data files from user-provided path. Path is constructor argument, attacker can provide malicious .pt file if they control data source. | Loading training data from .pt files via torch.load() |
| `main@model_examples/DriverAgent/train.py` | file | untrusted_local | torch.load() used without weights_only=True to load pretrained model weights from args.continue_path. Path is CLI argument, attacker controlling command line can provide malicious checkpoint. | Loading model checkpoint via torch.load() |
| `__init__@mx_driving/get_chip_info.py` | env | semi_trusted | Loads libdrvdsmi_host.so from LD_LIBRARY_PATH. Library search path can be manipulated by local user via environment variable, but requires the attacker to place malicious library in accessible location. | Loading system library from LD_LIBRARY_PATH |
| `_set_env@mx_driving/__init__.py` | env | semi_trusted | Modifies ASCEND_CUSTOM_OPP_PATH environment variable, combining with existing value. Existing env value can be set by local user before importing mx_driving. | Modifying ASCEND_CUSTOM_OPP_PATH environment variable |
| `get_sha@setup.py` | env | trusted_admin | git rev-parse executed in project root directory during build. Command is hardcoded, cwd is BASE_DIR (project root). Only executed during pip install/build, attacker cannot trigger this at runtime. | Git command execution during build |

**其他攻击面**:
- Python API Input Validation: Tensor shape/type validation in ops modules (sparse_functional.py, voxelization.py)
- File Loading: torch.load() in model examples and test data cache (DriverAgent/data.py, data_cache.py)
- Environment Variable: LD_LIBRARY_PATH for library loading (get_chip_info.py), ASCEND_CUSTOM_OPP_PATH (__init__.py)
- Monkey Patching: Dynamic module replacement via patcher framework (patcher.py, patch.py)
- Decorator Evaluation: eval() in patch.py for decorator expression resolution
- C Extension Bindings: pybind.cpp exposes C++ operators to Python without validation
- Model Checkpoint Loading: torch.load() in DriverAgent/train.py for pretrained weights

---

## 3. High 漏洞 (1)

### [VULN-SA-PY-003] deserialization - model_evaluate

**严重性**: High | **CWE**: CWE-502 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `model_examples/DriverAgent/evaluate.py:60` @ `model_evaluate`
**模块**: model_examples

**描述**: Unsafe deserialization via torch.load() without weights_only=True. The model path is constructed from CLI argument args.name, which could enable path traversal if the name contains directory separators (e.g., '../../../malicious_model'), leading to loading of malicious checkpoint files with arbitrary code execution capability.

**漏洞代码** (`model_examples/DriverAgent/evaluate.py:60`)

```c
PiP.load_state_dict(torch.load('./trained_models/{}/{}.tar'.format(args.name, args.name)))
```

**达成路径**

args.name [CLI argument] -> path construction -> torch.load() -> PiP.load_state_dict()

**验证说明**: CLI argument args.name used in path construction './trained_models/{}/{}.tar'. Path traversal possible via directory separators in args.name (e.g., '../../../malicious'). torch.load() without weights_only=True enables code execution. Partial controllability due to expected directory structure.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (7)

### [scripts-003] path_traversal - main

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: python-dataflow-module-scanner

**位置**: `scripts/install_kernel.sh:50-64` @ `main`
**模块**: scripts
**跨模块**: scripts → mx_driving

**描述**: install_kernel.sh uses ASCEND_OPP_PATH and ASCEND_CUSTOM_OPP_PATH environment variables to determine installation paths without path normalization or sandboxing.

**漏洞代码** (`scripts/install_kernel.sh:50-64`)

```c
targetdir=${ASCEND_CUSTOM_OPP_PATH}
```

**达成路径**

env ASCEND_CUSTOM_OPP_PATH → targetdir → mkdir/cp operations

**验证说明**: install_kernel.sh uses ASCEND_OPP_PATH/ASCEND_CUSTOM_OPP_PATH env vars without path validation. However: (1) script not called by build system, (2) env vars normally set by trusted CANN installation, (3) attacker would need pre-existing access to set env vars. Installation-time risk, not runtime.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: i | 23: n | 24: d | 25: i | 26: r | 27: e | 28: c | 29: t | 30: _ | 31: e | 32: x | 33: t | 34: e | 35: r | 36: n | 37: a | 38: l | 39: ( | 40: + | 41: 2 | 42: 0 | 43: ) | 44: , | 45:   | 46: c | 47: o | 48: n | 49: t | 50: r | 51: o | 52: l | 53: l | 54: a | 55: b | 56: i | 57: l | 58: i | 59: t | 60: y | 61: = | 62: p | 63: a | 64: r | 65: t | 66: i | 67: a | 68: l | 69: ( | 70: + | 71: 1 | 72: 5 | 73: ) | 74: , | 75:   | 76: m | 77: i | 78: t | 79: i | 80: g | 81: a | 82: t | 83: i | 84: o | 85: n | 86: s | 87: = | 88: 0 | 89:   | 90: ( | 91: e | 92: n | 93: v | 94:   | 95: v | 96: a | 97: r | 98: s | 99: ) | 100: , | 101:   | 102: p | 103: a | 104: r | 105: t | 106: i | 107: a | 108: l | 109: _ | 110: m | 111: i | 112: t | 113: i | 114: g | 115: a | 116: t | 117: i | 118: o | 119: n | 120:   | 121: f | 122: o | 123: r | 124:   | 125: - | 126: - | 127: i | 128: n | 129: s | 130: t | 131: a | 132: l | 133: l | 134: - | 135: p | 136: a | 137: t | 138: h | 139:   | 140: C | 141: L | 142: I | 143:   | 144: a | 145: r | 146: g | 147: . | 148:   | 149: T | 150: o | 151: t | 152: a | 153: l | 154: = | 155: 6 | 156: 5 | 157: .

---

### [scripts-004] path_traversal - main

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: python-dataflow-module-scanner

**位置**: `scripts/upgrade_kernel.sh:14-19` @ `main`
**模块**: scripts
**跨模块**: scripts → mx_driving

**描述**: upgrade_kernel.sh uses ASCEND_OPP_PATH environment variable to determine target directory without validation.

**漏洞代码** (`scripts/upgrade_kernel.sh:14-19`)

```c
targetdir=${ASCEND_OPP_PATH}
```

**达成路径**

env ASCEND_OPP_PATH → targetdir → mkdir/cp operations

**验证说明**: upgrade_kernel.sh uses ASCEND_OPP_PATH env var without any path validation. Same constraints as scripts-003: (1) not called by build system, (2) env var normally trusted source, (3) requires attacker to pre-set environment. Installation-time risk.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: i | 23: n | 24: d | 25: i | 26: r | 27: e | 28: c | 29: t | 30: _ | 31: e | 32: x | 33: t | 34: e | 35: r | 36: n | 37: a | 38: l | 39: ( | 40: + | 41: 2 | 42: 0 | 43: ) | 44: , | 45:   | 46: c | 47: o | 48: n | 49: t | 50: r | 51: o | 52: l | 53: l | 54: a | 55: b | 56: i | 57: l | 58: i | 59: t | 60: y | 61: = | 62: p | 63: a | 64: r | 65: t | 66: i | 67: a | 68: l | 69: ( | 70: + | 71: 1 | 72: 5 | 73: ) | 74: , | 75:   | 76: m | 77: i | 78: t | 79: i | 80: g | 81: a | 82: t | 83: i | 84: o | 85: n | 86: s | 87: = | 88: 0 | 89: . | 90:   | 91: T | 92: o | 93: t | 94: a | 95: l | 96: = | 97: 6 | 98: 5 | 99: .

---

### [mx_driving_csrc_library_injection_001] Library Injection - init_op_api_so_path

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-module-scanner

**位置**: `mx_driving/csrc/pybind.cpp:25-32` @ `init_op_api_so_path`
**模块**: mx_driving_csrc
**跨模块**: mx_driving_csrc → mx_driving_ops → mx_driving

**描述**: Dynamic library loading from configurable path. _init_op_api_so_path is exposed via pybind11, allowing Python code to set g_opApiSoPath. This path is then used in dlopen() to load libopapi.so. An attacker could call _init_op_api_so_path with a malicious library path to inject arbitrary code.

**漏洞代码** (`mx_driving/csrc/pybind.cpp:25-32`)

```c
void init_op_api_so_path(const std::string& path) {
    std::call_once(init_flag, [&]() { g_opApiSoPath = path; });
}
PYBIND11_MODULE(...) { m.def("_init_op_api_so_path", &init_op_api_so_path); }
```

**达成路径**

Python string (path) -> init_op_api_so_path -> g_opApiSoPath -> dlopen in GetOpApiFuncAddr -> arbitrary code execution

**验证说明**: _init_op_api_so_path exposed via pybind11 allows setting library path. Path stored in g_opApiSoPath for later dlopen(). Attack requires Python code execution to call this API. If attacker has Python execution capability, they could load arbitrary library. Semi-trusted: requires prior code execution foothold.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [onnx_plugin_roi_align_negative_value_conversion] Integer Overflow / Type Conversion - ParseParamsRoiAlignRotatedV2

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `onnx_plugin/onnx_roi_align_rotated.cpp:34-69` @ `ParseParamsRoiAlignRotatedV2`
**模块**: onnx_plugin
**跨模块**: onnx_plugin → kernels

**描述**: ParseParamsRoiAlignRotatedV2 reads pooled_height and pooled_width from ONNX model attributes as int32, but kernel layer uses uint32_t. Negative values (e.g., -1) from malicious ONNX models become extremely large positive values (4294967295), causing memory allocation overflow or DoS. No range validation in ONNX plugin layer.

**漏洞代码** (`onnx_plugin/onnx_roi_align_rotated.cpp:34-69`)

```c
int pooled_height = 1; int pooled_width = 1; ... pooled_height = attr.i(); pooled_width = attr.i(); ... op_dest.SetAttr("pooled_h", pooled_height); op_dest.SetAttr("pooled_w", pooled_width);
```

**达成路径**

ONNX model file (attr.i()) → pooled_height/pooled_width (int) → op_dest.SetAttr → kernel GetAttrPointer<uint32_t>() → memory allocation calc

**验证说明**: ONNX model attributes (pooled_height/pooled_width) read as int32 but used as uint32_t. Negative values become large positive causing memory allocation overflow. Attack path: malicious ONNX model file loaded by user. Trust_level: untrusted_local (file input).

**评分明细**: base: 30 | reachability: 30 | controllability: 5 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SA-CROSS-001] untrusted_binding - _set_env

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-1327 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `mx_driving/__init__.py:179` @ `_set_env`
**模块**: mx_driving
**跨模块**: mx_driving → mx_driving/__init__.py → mx_driving/get_chip_info.py

**描述**: Untrusted library binding on module import. When mx_driving is imported, _set_env() automatically executes and calls Dsmi_dc_Func() which loads libdrvdsmi_host.so from LD_LIBRARY_PATH. If an attacker controls the environment variable before import (e.g., in a shared environment or CI pipeline), a malicious library can be loaded and executed without user awareness. This is a cross-module security issue involving mx_driving/__init__.py and mx_driving/get_chip_info.py.

**漏洞代码** (`mx_driving/__init__.py:179`)

```c
_set_env()  # Called automatically on import, triggers library loading from LD_LIBRARY_PATH
```

**达成路径**

LD_LIBRARY_PATH [environment] -> find_library_in_ld_path() (get_chip_info.py) -> cdll.LoadLibrary() -> malicious library execution

**验证说明**: LD_LIBRARY_PATH used for library loading on module import. Attack requires shared environment/CI pipeline where attacker can set environment variables before import. Not a direct exploit - attacker must already have environment control. Downgraded severity: requires local foothold first. Trust_level: semi_trusted confirms limited attack surface.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-DF-001] Shared Library Injection - find_library_in_ld_path / Dsmi_dc_Func.__init__

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-427 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/get_chip_info.py:9-28` @ `find_library_in_ld_path / Dsmi_dc_Func.__init__`
**模块**: mx_driving_root

**描述**: Dynamic library loaded from LD_LIBRARY_PATH without validation. An attacker who can control the LD_LIBRARY_PATH environment variable can place a malicious libdrvdsmi_host.so in a directory under their control, leading to arbitrary code execution when the library is loaded via cdll.LoadLibrary().

**漏洞代码** (`mx_driving/get_chip_info.py:9-28`)

```c
def find_library_in_ld_path(lib_name):
    ld_paths = os.environ.get("LD_LIBRARY_PATH", "").split(":")
    for path in ld_paths:
        if not path.strip():
            continue
        full_path = os.path.join(path.strip(), lib_name)
        if os.path.isfile(full_path):
            return full_path
    return None

class Dsmi_dc_Func:
    def __init__(self, cur=None):
        if cur is None:
            lib_path = find_library_in_ld_path("libdrvdsmi_host.so")
            if lib_path is None:
                raise FileNotFoundError(...)
            cur = cdll.LoadLibrary(lib_path)  # SINK
```

**达成路径**

os.environ.get('LD_LIBRARY_PATH') [line 9] → find_library_in_ld_path() [line 21] → os.path.join() [line 13] → cdll.LoadLibrary() [line 28]

**验证说明**: Same vulnerability as VULN-SA-CROSS-001 - same code path via find_library_in_ld_path() -> cdll.LoadLibrary(). LD_LIBRARY_PATH library injection requires attacker to have local environment control. Not a standalone vulnerability but a design risk in shared environments.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: -15 | cross_file: 0

---

### [mx_driving_csrc_nms3d_int_overflow_001] Integer Overflow - nms3d

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `mx_driving/csrc/Nms3d.cpp:24-25` @ `nms3d`
**模块**: mx_driving_csrc
**跨模块**: mx_driving_csrc → mx_driving_ops

**描述**: Integer overflow in mask_num calculation. box_num comes from tensor size (external Python input). The calculation ((box_num - 1) / 16 + 1) * 16 can overflow if box_num is near INT32_MAX, leading to undersized memory allocation and potential heap overflow.

**漏洞代码** (`mx_driving/csrc/Nms3d.cpp:24-25`)

```c
int32_t mask_num = ((box_num - 1) / data_align + 1) * data_align;
at::Tensor mask = at::empty({box_num, mask_num}, boxes.options().dtype(at::kShort));
```

**达成路径**

Python tensor (boxes.size(0)) -> box_num -> arithmetic overflow -> mask_num -> at::empty allocation

**验证说明**: Integer overflow in mask_num calculation ((box_num-1)/16+1)*16. box_num from Python tensor size. Overflow leads to undersized allocation and potential heap overflow. Requires malicious tensor with size near INT32_MAX - possible if attacker controls model input tensors.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -10 | context: -15 | cross_file: 0

---

## 5. Low 漏洞 (39)

### [VULN-SA-PY-006] command_injection - find_ut_by_regex

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `ci/access_control_test.py:66-67` @ `find_ut_by_regex`
**模块**: ci

**描述**: Potential command injection in subprocess.getstatusoutput(). The 'regex' parameter is derived from file names in modify_files.txt and used directly in shell command construction without sanitization. If modify_files.txt contains malicious file names with shell metacharacters (e.g., 'test_; rm -rf /'), it could lead to arbitrary command execution.

**漏洞代码** (`ci/access_control_test.py:66-67`)

```c
cmd = "find {} -name {}".format(str(TEST_DIR), regex)
status, output = subprocess.getstatusoutput(cmd)
```

**达成路径**

modify_files.txt -> modify_file -> OpStrategy.identify() -> regex construction -> subprocess.getstatusoutput(cmd)

**验证说明**: subprocess.getstatusoutput with regex from modify_files.txt. CI test script - regex from git diff. Shell metacharacters in file names could cause injection if modify_files.txt malicious.

---

### [PY-DF-tests-001] unsafe_deserialization - load_data

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-502 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: python-dataflow-module-scanner

**位置**: `tests/torch/data_cache.py:98-99` @ `load_data`
**模块**: tests-py

**描述**: torch.load() called without weights_only=True parameter, allowing arbitrary pickle deserialization. This can lead to Remote Code Execution (RCE) if an attacker controls the .pth file content or cache directory. Affects 61 test files with 129 decorator usage points.

**漏洞代码** (`tests/torch/data_cache.py:98-99`)

```c
elif file_name.endswith(".pth"):
    result = torch.load(file_path)  # No weights_only=True
```

**达成路径**

os.getenv('MXDRIVING_CACHE_PATH') [Source] → save_path_ → golden_data_cache() wrapper → load_data(save_path, file_names) → torch.load(file_path) [Sink]

**验证说明**: torch.load() in test data_cache.py without weights_only=True. Test code loading cached test data. Risk limited to test environment. Potential RCE if cache path controlled.

---

### [VULN-SA-PY-004] code_injection - with_imports

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-95 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `mx_driving/patcher/patch.py:790-791` @ `with_imports`
**模块**: mx_driving_patcher

**描述**: Use of eval() for decorator expression resolution. While decorator_exprs come from predefined patch definitions (developer-controlled), eval() can execute arbitrary Python code. If patch definitions are modified (e.g., through compromised git repository or malicious dependency), this could lead to code injection. The code is annotated with '# noqa: S307' indicating awareness of the security risk.

**漏洞代码** (`mx_driving/patcher/patch.py:790-791`)

```c
dec = eval(expr, new_globals)  # noqa: S307
resolved_func[0] = dec(resolved_func[0])
```

**达成路径**

decorator_exprs [from patch definition] -> eval(expr, new_globals) -> decorator application

**验证说明**: eval() used for decorator expression resolution in patcher. Decorator expressions from predefined patch definitions (developer-controlled). Risk limited to malicious patch definitions. Requires compromised git repository or dependency. noqa: S307 indicates known risk.

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -10 | context: 0 | cross_file: 0

---

### [mx_driving_csrc_sparse_conv3d_int_overflow_001] Integer Overflow - npu_sparse_conv3d

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `mx_driving/csrc/SparseConv3d.cpp:32-46` @ `npu_sparse_conv3d`
**模块**: mx_driving_csrc
**跨模块**: mx_driving_csrc → mx_driving_ops

**描述**: Integer overflow in kernelsum and outputsum calculations. kernel_size array comes from Python (IntArrayRef). Multiplying kernel_size values can overflow kernelsum, then multiplying with indices_size[0] can overflow outputsum, leading to undersized tensor allocation.

**漏洞代码** (`mx_driving/csrc/SparseConv3d.cpp:32-46`)

```c
int64_t kernelsum = 1;
for (int32_t i = 0; i < kernel_size.size(); i++) { kernelsum *= kernel_size[i]; }
int64_t outputsum = indices_size[0] * kernelsum;
at::Tensor indices_out = at::empty(indices_out_size, ...);
at::Tensor indices_pairs = at::empty(indices_pairs_size, ...);
```

**达成路径**

Python IntArrayRef (kernel_size) -> kernelsum multiplication -> outputsum -> indices_out_size, indices_pairs_size -> at::empty allocation

**验证说明**: kernel_size array multiplication overflow. Python-controlled input. Library API quality defect.

---

### [mx_driving_ops_deform_conv2d_offset_validation] Missing Input Validation - DeformConv2dFunction.forward

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/ops/deform_conv2d.py:46-56` @ `DeformConv2dFunction.forward`
**模块**: mx_driving_ops

**描述**: deform_conv2d() passes offset tensor to C++ binding without validating offset values. Deformable convolution offsets can cause out-of-bounds memory sampling if values exceed input spatial dimensions. No bounds check before C++ kernel invocation.

**漏洞代码** (`mx_driving/ops/deform_conv2d.py:46-56`)

```c
out, offset_output = mx_driving._C.deformable_conv2d(nhwc_x, nhwc_offset, nhwc_weight, ctx.kernel_size, ctx.stride, ctx.padding, ctx.dilation, ctx.groups, ctx.deformable_groups)
```

**达成路径**

offset (user input) → mx_driving._C.deformable_conv2d (C++ sink)

**验证说明**: Deformable convolution offset tensor passed to C++ kernel without bounds validation. However, this is a library API - input comes from developer's model code, not external attacker. Out-of-bounds offsets would cause incorrect sampling or runtime errors, not security compromise. Trust_level: internal (developer-controlled) limits attack surface. Quality defect, not security vulnerability.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-DF-KERNEL-001] integer_overflow - furthestPointSamplingKernel::Process

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `kernels/furthest_point_sampling/op_kernel/furthest_point_sampling.cpp:115-116` @ `furthestPointSamplingKernel::Process`
**模块**: kernels

**描述**: Batch offset calculation uses multiplication of core_batch, N, and 3 without overflow validation. If N is large (e.g., >2^31), the multiplication could overflow uint32_t, leading to incorrect buffer offsets.

**漏洞代码** (`kernels/furthest_point_sampling/op_kernel/furthest_point_sampling.cpp:115-116`)

```c
this->batchOffsetPoint = this->core_batch * this->TA->N * 3;
this->batchOffsetNearest = this->core_batch * this->TA->N;
```

**达成路径**

tiling_data.N (Source) -> batchOffsetPoint/batchOffsetNearest (multiplication) -> pointGm/nearestDistGm SetGlobalBuffer offset (Sink)

**验证说明**: Integer overflow in batch offset calculation for furthest point sampling. Large N values could overflow uint32_t. N comes from tiling_data (model parameters), not external attacker. Quality defect in kernel.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-DF-KERNEL-002] integer_overflow - KernelSparseConv3d::Init

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `kernels/sparse_conv3d/op_kernel/sparse_conv3d.cpp:22-37` @ `KernelSparseConv3d::Init`
**模块**: kernels

**描述**: Multiple offset calculations use beginOffset multiplied by kernelSize or 4 without overflow checks. beginOffset = curBlockIdx * coreTask could overflow for large coreTask values.

**漏洞代码** (`kernels/sparse_conv3d/op_kernel/sparse_conv3d.cpp:22-37`)

```c
uint64_t beginOffset = curBlockIdx * coreTask;
indicesGm.SetGlobalBuffer(reinterpret_cast<__gm__ DTYPE_INDICES *>(indices) + beginOffset * 4);
```

**达成路径**

tiling_data.coreTask, curBlockIdx (Source) -> beginOffset (multiplication) -> GlobalBuffer offset (Sink)

**验证说明**: Integer overflow in beginOffset calculation for sparse_conv3d. Same assessment as VULN-DF-KERNEL-001 - kernel quality defect.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [onnx_plugin_roi_align_zero_value_missing_check] Missing Input Validation - ParseParamsRoiAlignRotatedV2

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `onnx_plugin/onnx_roi_align_rotated.cpp:34-69` @ `ParseParamsRoiAlignRotatedV2`
**模块**: onnx_plugin
**跨模块**: onnx_plugin → kernels

**描述**: ParseParamsRoiAlignRotatedV2 does not validate pooled_height and pooled_width for zero values. Zero pooled dimensions result in zero-size output tensor shape calculation (output_shape = pooled_height * pooled_width = 0), potentially causing subsequent out-of-bounds memory access or division by zero in downstream operations.

**漏洞代码** (`onnx_plugin/onnx_roi_align_rotated.cpp:34-69`)

```c
int pooled_height = 1; int pooled_width = 1; ... pooled_height = attr.i(); pooled_width = attr.i(); // No zero check
```

**达成路径**

ONNX model → pooled_height/pooled_width (int) → kernel output_shape calc → SetGlobalBuffer size = 0

**验证说明**: Zero pooled dimensions cause zero-size output tensor. Malicious ONNX model could trigger this. Quality defect with potential DoS.

---

### [onnx_plugin_roi_align_sampling_ratio_unvalidated] Missing Input Validation - ParseParamsRoiAlignRotatedV2

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `onnx_plugin/onnx_roi_align_rotated.cpp:36-67` @ `ParseParamsRoiAlignRotatedV2`
**模块**: onnx_plugin
**跨模块**: onnx_plugin → kernels

**描述**: sampling_ratio read from ONNX model attributes without validation. Documentation states it should be non-negative integer, but code accepts negative values. Negative sampling_ratio causes undefined behavior in kernel bin_grid calculations (sampling_ratio > 0 condition false for negatives).

**漏洞代码** (`onnx_plugin/onnx_roi_align_rotated.cpp:36-67`)

```c
int sampling_ratio = 0; ... sampling_ratio = attr.i(); ... op_dest.SetAttr("sampling_ratio", sampling_ratio);
```

**达成路径**

ONNX model → sampling_ratio (int) → kernel → bin_grid_h/bin_grid_w calc

**验证说明**: Negative sampling_ratio causes undefined behavior. Malicious ONNX model input. Quality defect.

---

### [PY-DF-tests-002] env_variable_injection - golden_data_cache

**严重性**: Low | **CWE**: CWE-94 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: python-dataflow-module-scanner

**位置**: `tests/torch/data_cache.py:121-122` @ `golden_data_cache`
**模块**: tests-py

**描述**: Environment variable MXDRIVING_CACHE_PATH controls cache directory path without validation. If attacker can set this env var, they can redirect cache loading to malicious .pth files.

**漏洞代码** (`tests/torch/data_cache.py:121-122`)

```c
if os.getenv('MXDRIVING_CACHE_PATH', None) is not None:
    save_path_ = os.getenv('MXDRIVING_CACHE_PATH', None)
```

**达成路径**

os.getenv('MXDRIVING_CACHE_PATH') [Source] → save_path_ → load_data() → torch.load() [Sink]

**验证说明**: MXDRIVING_CACHE_PATH controls cache directory. Test environment only. Similar to tests-py issues.

---

### [PY-DF-001] Arbitrary Code Execution via Dynamic Library Loading - load_dso

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-94 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: python-dataflow-module-scanner

**位置**: `cmake/util/ascendc_impl_build.py:89-96` @ `load_dso`
**模块**: cmake-py
**跨模块**: cmake-py → tbe.common.platform

**描述**: The load_dso function at line 91 uses ctypes.CDLL(so_path) to load shared libraries without validating the path. The so_path is constructed from get_soc_spec() output (soc_version, soc_short) which comes from an external module 'tbe.common.platform'. If these values can be controlled through environment variables or configuration, arbitrary code execution is possible.

**漏洞代码** (`cmake/util/ascendc_impl_build.py:89-96`)

```c
def load_dso(so_path):
    try:
        ctypes.CDLL(so_path)
    except OSError as error :
        print(error)
        raise RuntimeError("cannot open %s" %(so_path))
```

**达成路径**

get_soc_spec("SOC_VERSION") → soc_version → tikreplay_stub_path → replaystub_so_path → load_dso(so_path) → ctypes.CDLL(so_path)

**验证说明**: ctypes.CDLL loads library from get_soc_spec output. SOC_VERSION from external module tbe.common.platform. Build-time script for operator compilation. Requires controlling external module output. Limited attack surface.

**评分明细**: base: 30 | reachability: 15 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [PY-DF-002] Generated Code Propagation of Dynamic Library Loading Vulnerability - _write_impl (generated code)

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-94 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: python-dataflow-module-scanner

**位置**: `cmake/util/ascendc_impl_build.py:163-177` @ `_write_impl (generated code)`
**模块**: cmake-py
**跨模块**: cmake-py → tbe.common.platform → generated operators

**描述**: The REPLAY_OP_API template (lines 163-187) generates code that calls load_dso() with paths constructed from get_soc_spec() output. This pattern is replicated across all generated operator files, amplifying the impact of PY-DF-001.

**漏洞代码** (`cmake/util/ascendc_impl_build.py:163-177`)

```c
    tikreplay_codegen_path = tikcpp_path + "/tikreplaylib/lib"
    tikreplay_stub_path = tikcpp_path + "/tikreplaylib/lib/" + soc_version
    codegen_so_path = tikreplay_codegen_path + "/libtikreplaylib_codegen.so"
    replaystub_so_path = tikreplay_stub_path + "/libtikreplaylib_stub.so"
    replayapi_so_path = os.path.join(op_replay_path, "libreplay_{}_" + soc_short + ".so")
    load_dso(codegen_so_path)
    load_dso(replaystub_so_path)
    load_dso(replayapi_so_path)
```

**达成路径**

get_soc_spec("SOC_VERSION") → soc_version → path → load_dso → ctypes.CDLL

**验证说明**: Generated code calls load_dso with paths from get_soc_spec. Same as PY-DF-001 - propagated through generated operator files. Build-time code generation.

**评分明细**: base: 30 | reachability: 15 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-DF-PY-MOD-001] improper_input_validation - scatter_nd

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/modules/sparse_structure.py:7-20` @ `scatter_nd`
**模块**: mx_driving_modules

**描述**: scatter_nd function in sparse_structure.py does not validate that indices tensor values are within the bounds of the output shape before writing. This could lead to out-of-bounds memory access if indices contain values exceeding shape boundaries.

**漏洞代码** (`mx_driving/modules/sparse_structure.py:7-20`)

```c
ret = torch.zeros(*shape, dtype=updates.dtype, device=updates.device)
flatted_indices = indices.view(-1, ndim)
slices = [flatted_indices[:, i] for i in range(ndim)]
ret[slices] = updates.view(*output_shape)
```

**达成路径**

scatter_nd(indices, updates, shape) → indices tensor from external SparseConvTensor → tensor indexing ret[slices] = updates

**验证说明**: scatter_nd passes indices tensor without bounds validation. Indices could cause OOB if exceeding shape boundaries. Library API input - developer-controlled. Quality defect.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-DF-PY-MOD-002] improper_input_validation - Voxelization.forward

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/modules/voxelization.py:21-25` @ `Voxelization.forward`
**模块**: mx_driving_modules
**跨模块**: mx_driving_modules → mx_driving_ops

**描述**: Voxelization.forward() method passes points tensor directly to C++ ops layer voxelization function without validating tensor shape, dtype, or value ranges. Malicious or malformed input could trigger vulnerabilities in the underlying C++ implementation.

**漏洞代码** (`mx_driving/modules/voxelization.py:21-25`)

```c
def forward(self, points: torch.Tensor):
    max_voxels = self.max_voxels[0] if self.training else self.max_voxels[1]
    return voxelization(points, self.voxel_size, self.point_cloud_range, ...)
```

**达成路径**

Voxelization.forward(points) → voxelization@mx_driving/ops/voxelization.py [C++ ops layer]

**验证说明**: Voxelization.forward passes points tensor to C++ ops without validation. Library API quality defect - same pattern as mx_driving_ops issues.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-DF-PY-MOD-003] improper_input_validation - RoIPointPool3d.forward

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/modules/roi_point_pool_3d.py:11-12` @ `RoIPointPool3d.forward`
**模块**: mx_driving_modules
**跨模块**: mx_driving_modules → mx_driving_ops

**描述**: RoIPointPool3d.forward() passes points, point_features, and boxes3d tensors directly to roipoint_pool3d C++ ops without validation. No checks for tensor shapes, dtypes, or value ranges before passing to potentially unsafe C++ implementation.

**漏洞代码** (`mx_driving/modules/roi_point_pool_3d.py:11-12`)

```c
def forward(self, points, point_features, boxes3d):
    return roipoint_pool3d(self.num_sampled_points, points, point_features, boxes3d)
```

**达成路径**

RoIPointPool3d.forward(points, point_features, boxes3d) → roipoint_pool3d@mx_driving/ops/roipoint_pool3d.py [C++ ops layer]

**验证说明**: RoIPointPool3d.forward passes tensors to C++ ops without validation. Same library API quality defect pattern.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [mx_driving_ops_bev_pool_missing_validation] Missing Input Validation - BEVPool.forward

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/ops/bev_pool.py:18-27` @ `BEVPool.forward`
**模块**: mx_driving_ops

**描述**: bev_pool() passes tensors feat and geom_feat to C++ binding mx_driving._C.npu_bev_pool without validation of tensor bounds, dtype consistency, or device placement. Only validates feat.shape[0] == geom_feat.shape[0]. Invalid tensor data could cause memory corruption or crashes in C++ layer.

**漏洞代码** (`mx_driving/ops/bev_pool.py:18-27`)

```c
out = mx_driving._C.npu_bev_pool(feat, geom_feat, interval_lengths, interval_starts, B, D, H, W)
```

**达成路径**

feat, geom_feat (user input) → mx_driving._C.npu_bev_pool (C++ sink)

**验证说明**: BEV pool tensors passed to C++ without comprehensive validation. Basic shape validation present (feat.shape[0] == geom_feat.shape[0]). Invalid tensors cause runtime errors or incorrect results in NPU kernel, not security exploits. Library API input validation issue - quality defect.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [mx_driving_ops_bev_pool_v2_missing_validation] Missing Input Validation - BEVPoolV2.forward

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/ops/bev_pool_v2.py:36-38` @ `BEVPoolV2.forward`
**模块**: mx_driving_ops

**描述**: bev_pool_v2() passes tensors depth, feat, ranks_* directly to C++ binding without validation of tensor shapes, value bounds, or dtype. Missing validation could lead to undefined behavior in C++ kernel.

**漏洞代码** (`mx_driving/ops/bev_pool_v2.py:36-38`)

```c
out = mx_driving._C.npu_bev_pool_v2(depth, feat, ranks_depth, ranks_feat, ranks_bev, interval_lengths, interval_starts, B, D, H, W)
```

**达成路径**

depth, feat, ranks_* (user input) → mx_driving._C.npu_bev_pool_v2 (C++ sink)

**验证说明**: Same pattern as bev_pool - library API input validation. Invalid tensor shapes/values cause undefined behavior in C++ kernel but no security path to exploitation. Developer-controlled input.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: -15 | cross_file: 0

---

### [mx_driving_ops_bev_pool_v3_missing_validation] Missing Input Validation - BEVPoolV3.forward

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/ops/bev_pool_v3.py:40-44` @ `BEVPoolV3.forward`
**模块**: mx_driving_ops

**描述**: bev_pool_v3() when depth=None only checks ranks_bev.dim() == 2 but does not validate value bounds. Tensors passed to C++ binding without comprehensive validation could cause out-of-bounds memory access.

**漏洞代码** (`mx_driving/ops/bev_pool_v3.py:40-44`)

```c
ranks_bev = ranks_bev[:, 3] * D * H * W + ranks_bev[:, 2] * H * W + ranks_bev[:, 0] * W + ranks_bev[:, 1]
out = mx_driving._C.npu_bev_pool_v3(depth, feat, ranks_depth, ranks_feat, ranks_bev, B, D, H, W)
```

**达成路径**

depth, feat, ranks_bev (user input) → mx_driving._C.npu_bev_pool_v3 (C++ sink)

**验证说明**: ranks_bev.dim() == 2 check present but value bounds not validated. Same assessment as bev_pool variants - library API quality issue.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -5 | context: -15 | cross_file: 0

---

### [mx_driving_ops_nms3d_missing_bounds] Missing Input Validation - Nms3dFunction.forward

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/ops/nms3d.py:18-25` @ `Nms3dFunction.forward`
**模块**: mx_driving_ops

**描述**: nms3d() only validates boxes.shape[1] == 7. Missing validation for iou_threshold bounds (should be 0-1), scores tensor values, and boxes coordinate bounds. Invalid values could cause undefined behavior in C++ NMS kernel.

**漏洞代码** (`mx_driving/ops/nms3d.py:18-25`)

```c
keep, num_out = mx_driving._C.nms3d(boxes, iou_threshold)
```

**达成路径**

boxes, scores, iou_threshold (user input) → mx_driving._C.nms3d (C++ sink)

**验证说明**: NMS 3D validates boxes.shape[1] == 7. Invalid iou_threshold (outside 0-1) causes undefined behavior but not exploitable. Library API quality issue.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -5 | context: -15 | cross_file: 0

---

### [mx_driving_ops_scatter_add_index_validation] Missing Input Validation - ScatterAddFunction.forward

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/ops/scatter_add.py:9-14` @ `ScatterAddFunction.forward`
**模块**: mx_driving_ops

**描述**: scatter_add() passes index tensor to C++ binding without bounds validation. Invalid index values exceeding output dimensions could cause out-of-bounds writes in C++ scatter operation.

**漏洞代码** (`mx_driving/ops/scatter_add.py:9-14`)

```c
res = mx_driving._C.npu_scatter_add(src.float(), index, out, dim, dim_size).to(src_dtype)
```

**达成路径**

index (user input) → mx_driving._C.npu_scatter_add (C++ sink)

**验证说明**: scatter_add passes index tensor without bounds validation. Library API quality defect.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [mx_driving_ops_scatter_max_index_validation] Missing Input Validation - ScatterMaxFunction.forward

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/ops/scatter_max.py:19-23` @ `ScatterMaxFunction.forward`
**模块**: mx_driving_ops

**描述**: scatter_max() passes indices tensor to C++ binding without bounds validation. Out-of-range indices could cause memory corruption in scatter_max_v3 C++ kernel.

**漏洞代码** (`mx_driving/ops/scatter_max.py:19-23`)

```c
out, argmax = func(updates, indices, out)
```

**达成路径**

indices (user input) → mx_driving._C.scatter_max_v3 (C++ sink)

**验证说明**: scatter_max passes indices without bounds validation. Library API quality defect.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [mx_driving_ops_scatter_mean_index_validation] Missing Input Validation - ScatterMeanFunction.forward

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/ops/scatter_mean.py:11-16` @ `ScatterMeanFunction.forward`
**模块**: mx_driving_ops

**描述**: scatter_mean() passes index tensor to C++ binding without validation. Invalid indices could cause out-of-bounds memory access in C++ scatter mean operation.

**漏洞代码** (`mx_driving/ops/scatter_mean.py:11-16`)

```c
res, count = func(src, index, out, dim, dim_size)
```

**达成路径**

index (user input) → mx_driving._C.npu_scatter_mean (C++ sink)

**验证说明**: scatter_mean passes index without validation. Library API quality defect.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [mx_driving_ops_furthest_point_sampling_bounds] Missing Input Validation - AdsFurthestPointSampling.forward

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/ops/furthest_point_sampling.py:21-36` @ `AdsFurthestPointSampling.forward`
**模块**: mx_driving_ops

**描述**: furthest_point_sampling() checks num_points == 0 but missing upper bounds validation. num_points exceeding point_xyz.shape[1] could cause undefined behavior in C++ sampling kernel.

**漏洞代码** (`mx_driving/ops/furthest_point_sampling.py:21-36`)

```c
output = mx_driving._C.npu_furthest_point_sampling(point_xyz, nearest_dist, num_points)
```

**达成路径**

num_points (user input) → mx_driving._C.npu_furthest_point_sampling (C++ sink)

**验证说明**: furthest_point_sampling checks num_points==0 but missing upper bounds. Library API quality defect.

---

### [mx_driving_ops_roiaware_pool3d_missing_validation] Missing Input Validation - RoIAwarePool3dFunction.forward

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/ops/roiaware_pool3d.py:59-61` @ `RoIAwarePool3dFunction.forward`
**模块**: mx_driving_ops

**描述**: roiaware_pool3d() checks out_size and max_pts_per_voxel but missing validation for pts, rois tensor shapes and coordinate bounds. Invalid coordinates in pts could cause out-of-bounds voxel indexing in C++.

**漏洞代码** (`mx_driving/ops/roiaware_pool3d.py:59-61`)

```c
mx_driving._C.npu_roiaware_pool3d_forward(rois, pts, pts_feature, argmax, pts_idx_of_voxels, pooled_features, mode)
```

**达成路径**

rois, pts, pts_feature (user input) → mx_driving._C.npu_roiaware_pool3d_forward (C++ sink)

**验证说明**: roiaware_pool3d checks out_size but missing pts/rois validation. Library API quality defect.

---

### [mx_driving_ops_dynamic_scatter_missing_validation] Missing Input Validation - DynamicScatterFunction.forward

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/ops/npu_dynamic_scatter.py:33-40` @ `DynamicScatterFunction.forward`
**模块**: mx_driving_ops

**描述**: dynamic_scatter() passes feats and coors tensors to C++ binding without shape validation or coordinate bounds check. Invalid coordinates could cause memory corruption in voxel operations.

**漏洞代码** (`mx_driving/ops/npu_dynamic_scatter.py:33-40`)

```c
voxel_idx = mx_driving._C.point_to_voxel(coors, [], [], "XYZ")
voxel_feats, compare_mask = mx_driving._C.npu_dynamic_scatter(feats, coors, prefix_sum_point_per_voxel, argsort_coor, num_voxels, reduce_type)
```

**达成路径**

feats, coors (user input) → mx_driving._C.point_to_voxel/npu_dynamic_scatter (C++ sink)

**验证说明**: dynamic_scatter passes feats/coors without validation. Library API quality defect.

---

### [mx_driving_ops_deformable_aggregation_location_validation] Missing Input Validation - AdsDeformableAggregation.forward

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mx_driving/ops/npu_deformable_aggregation.py:30-36` @ `AdsDeformableAggregation.forward`
**模块**: mx_driving_ops

**描述**: npu_deformable_aggregation() passes sampling_location tensor to C++ without bounds validation. Sampling locations exceeding spatial dimensions could cause out-of-bounds memory access in deformable aggregation kernel.

**漏洞代码** (`mx_driving/ops/npu_deformable_aggregation.py:30-36`)

```c
output = mx_driving._C.npu_deformable_aggregation(mc_ms_feat, spatial_shape, scale_start_index, sampling_location, weights)
```

**达成路径**

sampling_location (user input) → mx_driving._C.npu_deformable_aggregation (C++ sink)

**验证说明**: npu_deformable_aggregation passes sampling_location without bounds. Library API quality defect.

---

### [VULN-DF-KERNEL-003] out_of_bounds_write - KernelSparseConv3d::Compute

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-787 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `kernels/sparse_conv3d/op_kernel/sparse_conv3d.cpp:119-123` @ `KernelSparseConv3d::Compute`
**模块**: kernels

**描述**: Values read from indicesLocal (featureB, featureD, featureH, featureW) are used to calculate bOffset without bounds validation. Negative values from indices could cause out-of-bounds buffer access.

**漏洞代码** (`kernels/sparse_conv3d/op_kernel/sparse_conv3d.cpp:119-123`)

```c
int32_t featureB = indicesLocal.GetValue(idxOffset);
int32_t bOffset = featureB * outputDepth * outputHeight * outputWidth;
```

**达成路径**

indices tensor via GetValue() (Source - tainted input) -> bOffset (multiplication) -> gmOutValueOffset (Sink - memory access)

**验证说明**: Out-of-bounds write via indices tensor values. Indices from Python tensor (developer-controlled). Quality defect.

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-DF-KERNEL-004] out_of_bounds_write - BEVPoolV3Kernel::CopyIn

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-787 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `kernels/bev_pool_v3/op_kernel/bev_pool_v3.cpp:144-174` @ `BEVPoolV3Kernel::CopyIn`
**模块**: kernels

**描述**: Values from ranksFeat_ and ranksDepth_ tensors obtained via GetValue() are used directly as offsets for DataCopy without validation. Malicious or corrupted tensor values could cause out-of-bounds memory access.

**漏洞代码** (`kernels/bev_pool_v3/op_kernel/bev_pool_v3.cpp:144-174`)

```c
uint64_t rf = ranksFeat_.GetValue(off + j);
DataCopy(featLocal_[featOff + j * channel_], featGm_[rf], channel_);
```

**达成路径**

ranksFeat/ranksDepth tensor (Source) -> rf/rd via GetValue() -> featGm_[rf] (Sink - memory read)

**验证说明**: Out-of-bounds access via ranksFeat/ranksDepth tensor values. Developer-controlled input - quality defect.

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-DF-KERNEL-005] out_of_bounds_write - BEVPoolV3Kernel::CopyOut

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-787 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `kernels/bev_pool_v3/op_kernel/bev_pool_v3.cpp:172-174` @ `BEVPoolV3Kernel::CopyOut`
**模块**: kernels

**描述**: ranksBev_ value obtained via GetValue() is used directly as output buffer offset without validation, potentially causing out-of-bounds write to outGm_.

**漏洞代码** (`kernels/bev_pool_v3/op_kernel/bev_pool_v3.cpp:172-174`)

```c
uint64_t rb = ranksBev_.GetValue(off + j);
DataCopy(outGm_[rb], out_[featOff + j * channel_], channel_);
```

**达成路径**

ranksBev tensor (Source) -> rb via GetValue() -> outGm_[rb] (Sink - memory write)

**验证说明**: ranksBev_ value used as output buffer offset without validation. Same kernel quality defect pattern as other KERNEL issues.

---

### [VULN-DF-KERNEL-006] integer_overflow - Compute

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `kernels/roiaware_pool3d/op_kernel/roiaware_pool3d.cpp:146-162` @ `Compute`
**模块**: kernels

**描述**: Large offset calculation chain involving boxIdx, outx, outy, outz, maxPtsPerVoxel without overflow validation. If input dimensions are large, uint64_t overflow could occur.

**漏洞代码** (`kernels/roiaware_pool3d/op_kernel/roiaware_pool3d.cpp:146-162`)

```c
uint64_t idOffset = (boxIdx + startOffset) * outx * outy * outz * maxPtsPerVoxel + xIdx * outy * outz * maxPtsPerVoxel + ...
```

**达成路径**

tiling_data dimensions (Source) -> idOffset calculation (multiplication chain) -> ptsIdxOfVoxelGM buffer access (Sink)

**验证说明**: Large offset calculation chain in roiaware_pool3d without overflow validation. Input dimensions from tiling_data. Same kernel quality defect pattern as other KERNEL vulnerabilities.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-DF-KERNEL-007] out_of_bounds_write - Process

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-787 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `kernels/group_points/op_kernel/group_points.cpp:81-84` @ `Process`
**模块**: kernels

**描述**: Index value from indices_local via GetValue() is used directly for input buffer access without bounds check. Negative or out-of-range indices could cause out-of-bounds read.

**漏洞代码** (`kernels/group_points/op_kernel/group_points.cpp:81-84`)

```c
uint32_t idx = indices_local.GetValue(i);
DataCopy(input_local[i * cAligned], inputGm[src_idx], cAligned);
```

**达成路径**

indices tensor (Source) -> idx via GetValue() -> inputGm[src_idx] (Sink - memory read)

**验证说明**: Index value from indices tensor used for buffer access without bounds check in group_points. Developer-controlled tensor - quality defect.

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-DF-KERNEL-008] integer_overflow - furthestPointSamplingKernel::updateDist

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `kernels/furthest_point_sampling/op_kernel/furthest_point_sampling.cpp:563` @ `furthestPointSamplingKernel::updateDist`
**模块**: kernels

**描述**: maxDistIdx calculation uses formerNum * (i / 2) + tempValue without validation. If formerNum is large, multiplication could overflow.

**漏洞代码** (`kernels/furthest_point_sampling/op_kernel/furthest_point_sampling.cpp:563`)

```c
this->maxDistIdx = (this->TA->formerNum * (i / 2)) + (*reinterpret_cast<idxType*>(&tempValue));
```

**达成路径**

tiling_data.formerNum, idxTempLocal GetValue (Source) -> maxDistIdx calculation (Sink)

**验证说明**: maxDistIdx calculation with formerNum multiplication. Same kernel quality defect pattern.

---

### [VULN-DF-KERNEL-009] out_of_bounds_write - Process

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-787 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `kernels/scatter_max/op_kernel/scatter_max_with_argmax_v2.cpp:251` @ `Process`
**模块**: kernels

**描述**: indices value from indicesLocal via GetValue() used directly for localSetNote offset without bounds validation.

**漏洞代码** (`kernels/scatter_max/op_kernel/scatter_max_with_argmax_v2.cpp:251`)

```c
DTYPE_INDICES dataInIndices = indicesLocal.GetValue(idx);
int32_t localSetNoteOffset = dataInIndices / INDICES_EACH_BLOCK;
```

**达成路径**

indices tensor (Source) -> dataInIndices via GetValue() -> localSetNoteOffset (Sink - array index)

**验证说明**: Index value from indices tensor used for localSetNote offset without bounds check in scatter_max. Same quality defect pattern.

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-DF-KERNEL-010] out_of_bounds_write - Process

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-787 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `kernels/subm_sparse_conv3d/op_kernel/subm_sparse_conv3d_v2.cpp:208-225` @ `Process`
**模块**: kernels

**描述**: Values from batchIdxLocal, spatial0Local via GetValue() used to calculate mapOffset for map1GM_ access without bounds validation.

**漏洞代码** (`kernels/subm_sparse_conv3d/op_kernel/subm_sparse_conv3d_v2.cpp:208-225`)

```c
int16_t batchIdx = batchIdxLocal_.GetValue(i);
int16_t spatial0BaseIdx = spatial0Local_.GetValue(i);
DataCopyPad(mapValLocal_[(k0Idx - spatial0BaseIdx) * k1_ * k2Aligned_], map1GM_[mapOffset], ...);
```

**达成路径**

indices tensor via GetValue() (Source) -> mapOffset calculation -> map1GM_[mapOffset] (Sink - memory access)

**验证说明**: Values from batchIdx/spatial0 tensors used for mapOffset calculation without validation in subm_sparse_conv3d. Quality defect.

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-DF-KERNEL-011] missing_input_validation - Process

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `kernels/nms3d/op_kernel/nms3d.cpp:119-120` @ `Process`
**模块**: kernels

**描述**: cur_box and com_box values derived from loop calculations are used directly for boxGm access without validation against boxNum bounds.

**漏洞代码** (`kernels/nms3d/op_kernel/nms3d.cpp:119-120`)

```c
DataCopy(curLocal, boxGm[static_cast<uint64_t>(cur_box) * 7], dataAlign);
DataCopy(boxLocal, boxGm[static_cast<uint64_t>(com_box) * 7], dataAlign * 7);
```

**达成路径**

loop counter (Source) -> cur_box/com_box -> boxGm[offset] (Sink)

**验证说明**: cur_box/com_box used for boxGm access without bounds check. Same kernel quality defect pattern.

---

### [VULN-DF-KERNEL-012] integer_overflow - Init

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `kernels/nms3d/op_kernel/nms3d.cpp:32-33` @ `Init`
**模块**: kernels

**描述**: boxNum and maskNum from tiling_data are multiplied by 7 and boxNum respectively for buffer size without overflow validation.

**漏洞代码** (`kernels/nms3d/op_kernel/nms3d.cpp:32-33`)

```c
boxGm.SetGlobalBuffer(reinterpret_cast<__gm__ T*>(boxes), static_cast<uint64_t>(boxNum) * 7);
maskGm.SetGlobalBuffer(reinterpret_cast<__gm__ int16_t*>(mask), static_cast<uint64_t>(maskNum) * boxNum);
```

**达成路径**

tiling_data (Source) -> boxNum * 7, maskNum * boxNum -> buffer size (Sink)

**验证说明**: boxNum/maskNum multiplication for buffer size. Same kernel quality defect pattern.

---

### [mx_driving_csrc_pybind_exposed_api_001] Exposed Dangerous API - PYBIND11_MODULE

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-749 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `mx_driving/csrc/pybind.cpp:30-260` @ `PYBIND11_MODULE`
**模块**: mx_driving_csrc
**跨模块**: mx_driving_csrc → mx_driving_ops → mx_driving

**描述**: All C++ operator functions exposed via pybind11 without input sanitization. 70+ functions are directly bound to Python without intermediate validation layer. Tensor dimensions and values from Python are used directly for memory calculations, creating multiple attack surfaces for integer overflow and buffer issues.

**漏洞代码** (`mx_driving/csrc/pybind.cpp:30-260`)

```c
PYBIND11_MODULE(TORCH_EXTENSION_NAME, m) {
    m.def("knn", &knn);
    m.def("nms3d", &nms3d);
    m.def("deformable_conv2d", &deformable_conv2d);
    ... // 70+ exposed functions
```

**达成路径**

Python tensors/arrays -> pybind11 bindings -> C++ operators -> memory allocations with external dimensions

**验证说明**: 70+ pybind11 exposed functions without input sanitization. Same pattern as mx_driving_ops - library API quality issues.

---

### [DF-PY-001] Path Traversal - get_agents_num

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: python-dataflow-module-scanner

**位置**: `mx_driving/dataset/agent_dataset.py:80-83` @ `get_agents_num`
**模块**: mx_driving_dataset
**跨模块**: mx_driving_dataset → model_examples/QCNet

**描述**: AgentDynamicDataset.get_agents_num() 使用 self.processed_dir 构建文件路径进行 json.load() 操作。processed_dir 基于 root 参数构建，root 是外部可控的构造函数参数，仅经过 expanduser/normpath 处理，无法防止路径遍历攻击。

**漏洞代码** (`mx_driving/dataset/agent_dataset.py:80-83`)

```c
agents_num_file_path = os.path.join(self.processed_dir, agents_num_file_name)
if os.path.exists(agents_num_file_path):
    with open(agents_num_file_path, "r") as handle:
        self.agents_num = json.load(handle)
```

**达成路径**

root (constructor arg) → os.path.expanduser(os.path.normpath(root)) → os.path.join(root, split, 'processed') → self._processed_dir → os.path.join(self.processed_dir, 'train_agents_num.json') → open() → json.load()

**验证说明**: Path traversal in dataset processed_dir. root parameter from constructor. Developer-controlled input.

---

### [DF-PY-002] Path Traversal - get_agents_num

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: python-dataflow-module-scanner

**位置**: `mx_driving/dataset/agent_dataset.py:90-91` @ `get_agents_num`
**模块**: mx_driving_dataset
**跨模块**: mx_driving_dataset → model_examples/QCNet

**描述**: AgentDynamicDataset.get_agents_num() 使用 self.processed_dir 构建文件路径进行 json.dump() 写入操作。processed_dir 基于 root 参数构建，root 是外部可控的构造函数参数，可写入任意路径的文件。

**漏洞代码** (`mx_driving/dataset/agent_dataset.py:90-91`)

```c
with open(agents_num_file_path, 'w') as handle:
    json.dump(self.agents_num, handle)
```

**达成路径**

root (constructor arg) → processed_dir → agents_num_file_path → open('w') → json.dump()

**验证说明**: Same as DF-PY-001 - path traversal in dataset file writing. Developer-controlled input.

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| ci | 0 | 0 | 0 | 1 | 1 |
| cmake-py | 0 | 0 | 0 | 2 | 2 |
| kernels | 0 | 0 | 0 | 12 | 12 |
| model_examples | 0 | 1 | 0 | 0 | 1 |
| mx_driving | 0 | 0 | 1 | 0 | 1 |
| mx_driving_csrc | 0 | 0 | 2 | 2 | 4 |
| mx_driving_dataset | 0 | 0 | 0 | 2 | 2 |
| mx_driving_modules | 0 | 0 | 0 | 3 | 3 |
| mx_driving_ops | 0 | 0 | 0 | 12 | 12 |
| mx_driving_patcher | 0 | 0 | 0 | 1 | 1 |
| mx_driving_root | 0 | 0 | 1 | 0 | 1 |
| onnx_plugin | 0 | 0 | 1 | 2 | 3 |
| scripts | 0 | 0 | 2 | 0 | 2 |
| tests-py | 0 | 0 | 0 | 2 | 2 |
| **合计** | **0** | **1** | **7** | **39** | **47** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 18 | 38.3% |
| CWE-190 | 8 | 17.0% |
| CWE-787 | 6 | 12.8% |
| CWE-22 | 4 | 8.5% |
| CWE-94 | 3 | 6.4% |
| CWE-502 | 2 | 4.3% |
| CWE-95 | 1 | 2.1% |
| CWE-78 | 1 | 2.1% |
| CWE-749 | 1 | 2.1% |
| CWE-427 | 1 | 2.1% |
| CWE-426 | 1 | 2.1% |
| CWE-1327 | 1 | 2.1% |
