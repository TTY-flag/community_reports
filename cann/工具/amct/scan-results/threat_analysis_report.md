# Threat Analysis Report - AMCT PyTorch

**Project:** amct_pytorch  
**Version:** 6.0  
**Analysis Date:** 2026-04-22  
**Analyst:** Architecture Agent

---

## Executive Summary

AMCT PyTorch (Ascend Model Compression Toolkit) is a Python library for quantizing PyTorch models for deployment on Huawei Ascend NPUs. The project contains **532 source files** with approximately **83,741 lines of code** in both Python and C++.

The threat analysis identified **9 primary attack surfaces** and **16 entry points** that process external input. Key concerns include:

- **Configuration Parsing:** User-provided config dicts and JSON files flow through multiple validation layers without comprehensive sanitization
- **File Path Handling:** Multiple APIs accept user-specified file paths with `os.path.realpath()` resolution but limited path traversal validation
- **C++ Extension Functions:** Pybind11 and extern C functions process tensor/array data without bounds validation
- **Fuzzy Pattern Matching:** `fnmatch` wildcard matching on user-provided layer names

**Overall Risk Assessment: HIGH**

---

## 1. Project Profile

### 1.1 Project Type

| Attribute | Value |
|-----------|-------|
| Type | Library (Python + C++ extension) |
| Deployment | Installed via pip, used in Python scripts by ML engineers |
| Primary Language | Python (524 files, 81,854 lines) + C++ (8 files, 1,887 lines) |
| Dependencies | torch, torch_npu, numpy, pybind11 |

### 1.2 Trust Boundaries

| Boundary | Trusted Side | Untrusted Side | Risk |
|----------|--------------|----------------|------|
| User Input (Configuration) | Library Logic | User-provided config dict/JSON files | **High** |
| User Input (Model) | Library Logic | User-provided PyTorch models | Medium |
| File System | Library Logic | User-specified file paths | **High** |
| Tensor Data | Quantization Algorithms | User-provided tensor data | Medium |
| C++ Extension | Python Wrapper | Raw tensor data in C++ | **High** |

---

## 2. Attack Surface Analysis

### 2.1 Configuration Dictionary Input

**Location:** `amct_pytorch/config/`

**Entry Points:**
- `quantize(model, config)` - Main API takes user config dict
- `parse_config(model, config, registed_alg)` - Parses config dict
- `QuantConfig.__init__(config, registed_alg)` - Processes nested fields

**Data Flow:**
```
User Config Dict → quantize() → parse_config() → QuantConfig.__init__()
                  → QuantCfgField.__init__() → WeightsCfgField.check()
                  → InputsCfgField.check() → AlgorithmField.__init__()
```

**Potential Vulnerabilities:**
1. **Type Confusion:** Config fields are extracted via `.get()` without strict type checking before validation
2. **Nested Dict Injection:** Complex nested structure (`quant_cfg.weights_cfg`, `quant_cfg.inputs_cfg`) allows injection of malicious values
3. **Algorithm Name Injection:** `algorithm` field names are validated against registry but custom algorithm registration could bypass checks

**Risk: HIGH** - User-controlled data flows to multiple validation functions

### 2.2 File Path Input

**Location:** `amct_pytorch/graph_based_compression/amct_pytorch/`

**Entry Points:**
| Function | File | Line | File Parameters |
|----------|------|------|-----------------|
| `create_quant_config` | quantize_tool.py | 51 | config_file |
| `quantize_preprocess` | quantize_tool.py | 96 | config_file, record_file |
| `quantize_model` | quantize_tool.py | 155 | config_file, modified_onnx_file, record_file |
| `save_model` | quantize_tool.py | 309 | modified_onnx_file, record_file, save_path |
| `create_quant_cali_config` | quant_calibration_interface.py | 39 | config_file |
| `create_quant_cali_model` | quant_calibration_interface.py | 62 | config_file, record_file |

**Path Handling Pattern:**
```python
config_file = os.path.realpath(config_file)
if not os.path.exists(config_file):
    raise OSError(f'file ({config_file}) does not exist!')
```

**Potential Vulnerabilities:**
1. **Path Traversal:** `os.path.realpath()` resolves symlinks but doesn't prevent traversal outside intended directories
2. **Symbolic Link Attack:** Symlink resolution could redirect to sensitive files
3. **No Directory Validation:** No check that resolved path is within expected project/workspace directory
4. **File Existence Bypass:** `check_exist=True` creates empty files at user-specified paths

**Risk: HIGH** - Multiple APIs accept arbitrary file paths

### 2.3 C++ Extension Functions (Pybind11)

**Location:** `amct_pytorch/experimental/hifloat8/hifloat8_cast.cpp`

**Exported Functions:**
| Function | Line | Input | Description |
|----------|------|-------|-------------|
| `FloatToHifloat8` | 285 | `torch::Tensor& input` | Cast float to hifloat8 |
| `Hifloat8ToFloat32` | 301 | `torch::Tensor& input` | Convert hifloat8 to float32 |
| `Hifloat8ToFloat16` | 312 | `torch::Tensor& input` | Convert hifloat8 to float16 |
| `Hifloat8ToBFloat16` | 324 | `torch::Tensor& input` | Convert hifloat8 to bfloat16 |

**Code Pattern:**
```cpp
torch::Tensor FloatToHifloat8(torch::Tensor& input)
{
    input = input.contiguous();
    torch::Tensor output = torch::zeros_like(input).to(torch::kUInt8);
    auto outputPtr = reinterpret_cast<uint8_t*>(output.data_ptr());
    auto inputPtr = reinterpret_cast<uint32_t*>(input.data_ptr());
    DataCastToHiF8Functor<uint32_t>()(inputPtr, outputPtr, input.numel(), FP32);
    return output;
}
```

**Potential Vulnerabilities:**
1. **Buffer Overflow:** `input.numel()` determines loop bounds, but malformed tensor could have inconsistent size
2. **Type Confusion:** `reinterpret_cast` assumes specific data types; if Python passes wrong dtype, memory corruption possible
3. **No Bounds Check:** Loop in `DataCastToHiF8Functor::operator()` iterates `length` times without validation
4. **Parallel Execution:** `#pragma omp parallel for` with unchecked bounds could cause race conditions

**Risk: HIGH** - Raw pointer manipulation with user-controlled tensor data

### 2.4 extern C Functions (Tensor Decomposition)

**Location:** `amct_pytorch/graph_based_compression/amct_tensor_decompose/src/tensor_decomposition_api.cpp`

**Exported Functions:**
| Function | Line | Parameters |
|----------|------|------------|
| `GetRank` | 31 | `ConvInfo info, const double *s, unsigned int length` |
| `FastFilterConv` | 47 | `ConvInfo info` |

**Code Pattern:**
```cpp
extern "C" {
int GetRank(ConvInfo info, const double *s, unsigned int length)
{
    if (length == 0) {
        return 0;
    }
    Vector vecS;
    TdError vecRet = vecS.Create(s, length);
    if (vecRet !=TdError::TD_SUCCESS) {
        return length;
    }
    int res = TensorDecomposition::Estimation(info, vecS, length);
    return res;
}
```

**Potential Vulnerabilities:**
1. **Buffer Overflow:** `length` parameter controls array access; if `length` exceeds actual array size, out-of-bounds read
2. **Null Pointer:** No check for `s == NULL`
3. **ConvInfo Validation:** `ConvInfo` struct fields are used directly without validation

**Risk: MEDIUM** - extern C interface with array pointer + length pattern

### 2.5 Fuzzy Pattern Matching

**Location:** `amct_pytorch/config/utils.py`

**Function:** `match_fuzzy_pattern(layer_name, pattern)` (line 32)

**Code Pattern:**
```python
def match_fuzzy_pattern(layer_name, pattern):
    if '*' not in pattern:
        return layer_name == pattern
    
    if fnmatch.fnmatch(layer_name, pattern):
        return True
    
    for suffix in ['.weights', '.inputs']:
        if fnmatch.fnmatch(layer_name + suffix, pattern):
            return True
    
    return False
```

**Potential Vulnerabilities:**
1. **Pattern Injection:** User-provided `pattern` with `*` wildcards passed directly to `fnmatch`
2. **Layer Name Injection:** `layer_name` comes from model `named_modules()` - could contain special characters
3. **Suffix Concatenation:** `layer_name + suffix` could create unexpected patterns

**Risk: MEDIUM** - fnmatch is generally safe but pattern construction needs review

### 2.6 JSON Configuration File Parsing

**Location:** `amct_pytorch/graph_based_compression/amct_pytorch/configuration/configuration.py`

**Entry Points:** Configuration file is read and parsed as JSON

**Potential Vulnerabilities:**
1. **JSON Deserialization:** Standard `json.load()` is safe but doesn't validate schema
2. **Large File DoS:** No size limit on config file
3. **Malformed Structure:** Invalid structure could cause unexpected behavior

**Risk: LOW** - Standard JSON parsing is relatively safe

---

## 3. STRIDE Threat Modeling

### 3.1 Spoofing

| Threat | Location | Description |
|--------|----------|-------------|
| **Custom Algorithm Spoofing** | `algorithm_register()` | User can register malicious algorithm modules that appear legitimate |
| **Config File Spoofing** | File APIs | User could provide config file that mimics legitimate structure |

**Mitigation:** None implemented - custom algorithms are fully user-controlled

### 3.2 Tampering

| Threat | Location | Description |
|--------|----------|-------------|
| **Config Dict Tampering** | `parse_config()` | User can inject malicious values into config fields |
| **Model Parameter Tampering** | `quantize()` | User model parameters are directly processed |
| **File Path Tampering** | File APIs | User can specify arbitrary file paths |

**Mitigation:** Partial - `check_params` decorator validates types, but values are not sanitized

### 3.3 Repudiation

| Threat | Location | Description |
|--------|----------|-------------|
| **No Audit Trail** | All APIs | No logging of user inputs or file operations |

**Mitigation:** Minimal - `LOGGER` provides some debug logging but not security audit trail

### 3.4 Information Disclosure

| Threat | Location | Description |
|--------|----------|-------------|
| **Error Message Leakage** | `OSError` exceptions | File paths exposed in error messages |
| **Config Structure Exposure** | Validation errors | Detailed field requirements exposed via `ValueError` |

**Mitigation:** None - error messages include sensitive information (file paths, config structure)

### 3.5 Denial of Service

| Threat | Location | Description |
|--------|----------|-------------|
| **Large Config Processing** | `parse_config()` | Large nested config could consume significant memory |
| **Tensor Size Attack** | C++ extensions | Large tensor input could cause memory exhaustion |
| **File Read DoS** | Configuration parsing | No file size limits |

**Mitigation:** Minimal - some tensor size checks in algorithms (e.g., `check_linear_input_dim`)

### 3.6 Elevation of Privilege

| Threat | Location | Description |
|--------|----------|-------------|
| **Path Traversal** | File APIs | User can potentially write to arbitrary locations |
| **Arbitrary Code Execution** | `algorithm_register()` | User-provided modules are loaded and executed |

**Mitigation:** Partial - `@check_params` decorator enforces type checks

---

## 4. High-Risk Modules Summary

### 4.1 Critical Risk Modules

| Module | Path | Risk Factors |
|--------|------|--------------|
| **config** | `amct_pytorch/config/` | Config dict parsing, field validation, fuzzy pattern matching |
| **graph_based_compression** | `amct_pytorch/graph_based_compression/amct_pytorch/` | File path handling, config file parsing, ONNX export |
| **experimental_hifloat8** | `amct_pytorch/experimental/hifloat8/` | C++ tensor manipulation, pybind11 interface |

### 4.2 High Risk Modules

| Module | Path | Risk Factors |
|--------|------|--------------|
| **quantize** | `amct_pytorch/quantize.py` | Main API entry point, model processing |
| **quantize_op** | `amct_pytorch/quantize_op/` | Tensor processing, forward passes |
| **deploy_op** | `amct_pytorch/deploy_op/` | NPU operations, tensor conversion |

### 4.3 Medium Risk Modules

| Module | Path | Risk Factors |
|--------|------|--------------|
| **algorithm** | `amct_pytorch/algorithm/` | Algorithm implementations, scale search |
| **optimizer** | `amct_pytorch/optimizer/` | Model modification passes |
| **utils** | `amct_pytorch/utils/` | Utility functions, parameter checking |
| **tensor_decompose** | `amct_pytorch/graph_based_compression/amct_tensor_decompose/` | extern C interface |
| **experimental_quantization** | `amct_pytorch/experimental/quantization/DeepSeekV3.2/` | CLI script with file operations |

### 4.4 Low Risk Modules

| Module | Path | Risk Factors |
|--------|------|--------------|
| **examples** | `examples/` | Demonstration code (not production) |
| **tests** | `tests/` | Test code (not production) |

---

## 5. Recommended Security Controls

### 5.1 Input Validation

1. **Config Dict Schema Validation:** Implement strict JSON schema validation for config dicts
2. **Path Whitelisting:** Validate file paths against allowed directories
3. **Tensor Size Limits:** Implement maximum tensor size checks in C++ extensions
4. **Pattern Sanitization:** Escape special characters in fuzzy pattern matching

### 5.2 File Operations

1. **Directory Restriction:** Restrict file operations to user-specified workspace directory
2. **Symlink Resolution:** Check resolved path doesn't escape intended directory
3. **File Size Limits:** Implement maximum file size for config and record files

### 5.3 C++ Extensions

1. **Bounds Validation:** Add explicit bounds checks before array iteration
2. **Type Validation:** Validate tensor dtype matches expected type
3. **Null Checks:** Add null pointer checks in extern C functions

### 5.4 Error Handling

1. **Sanitized Error Messages:** Remove sensitive information from error messages
2. **Audit Logging:** Implement security audit trail for file operations and config parsing

---

## 6. Summary Statistics

| Metric | Value |
|--------|-------|
| Total Files | 532 |
| Total Lines of Code | 83,741 |
| Entry Points Identified | 16 |
| Attack Surfaces | 9 |
| High-Risk Modules | 3 |
| Critical Risk Functions | 6 |
| STRIDE Categories Affected | 6 (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation) |

---

## 7. Files for Further Analysis

Priority files for vulnerability scanning:

1. `amct_pytorch/config/parser.py` - Config parsing logic
2. `amct_pytorch/config/fields.py` - Field validation
3. `amct_pytorch/graph_based_compression/amct_pytorch/quantize_tool.py` - File path handling
4. `amct_pytorch/experimental/hifloat8/hifloat8_cast.cpp` - C++ tensor casting
5. `amct_pytorch/graph_based_compression/amct_tensor_decompose/src/tensor_decomposition_api.cpp` - extern C interface
6. `amct_pytorch/config/utils.py` - Pattern matching
7. `amct_pytorch/quantize.py` - Main API entry point

---

**Report Generated by:** Architecture Agent  
**Next Phase:** Data Flow Scanner → Security Auditor → Verification → Reporter