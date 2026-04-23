# Threat Analysis Report - CANN ops-cv

**Project**: CANN Computer Vision Operators Library  
**Scan Time**: 2026-04-21  
**Project Root**: /home/pwn20tty/Desktop/opencode_project/cann/1/ops-cv

---

## Executive Summary

This threat analysis examines the CANN ops-cv library, which provides computer vision operators for Huawei Ascend NPU. The library processes tensor data from machine learning models during inference, making it a critical component in the AI inference pipeline.

### Key Findings

1. **Primary Attack Surface**: All `aclnn*GetWorkspaceSize` API functions receive user-controlled tensor data through the CANN runtime interface
2. **Critical Risk Areas**: AICPU kernels that perform complex processing on raw tensor data with potential for integer overflow and improper bounds checking
3. **Trust Boundary**: The operator library sits between untrusted user applications (ML frameworks) and trusted NPU execution

---

## Project Profile

| Attribute | Value |
|-----------|-------|
| **Type** | Library (shared library for NPU operators) |
| **Languages** | C/C++ (680 files, 53278 lines), Python (117 files) |
| **Deployment** | Loaded by PyTorch/TensorFlow via CANN runtime on Ascend NPU servers |
| **Modules** | 44 image operators, 13 object detection operators, common utilities |

---

## Attack Surface Analysis

### 1. API Layer Entry Points (High Risk)

The `aclnn*GetWorkspaceSize` functions are the primary attack surface. These functions:

- Receive `aclTensor*` pointers from user applications
- Process tensor metadata (shape, dtype, format)
- Perform parameter validation
- Dispatch to kernel execution

**Example Attack Vector**: A malicious model could craft tensors with:
- Invalid shapes causing integer overflow in size calculations
- Mismatched dtypes bypassing type checks
- Extreme values causing buffer over-allocation

### 2. AICPU Kernel Layer (Critical Risk)

AICPU kernels run on a dedicated CPU core and perform complex operations:

| Kernel | Risk Level | Concern |
|--------|------------|---------|
| `non_max_suppression_v3_aicpu.cpp` | Critical | Dynamic allocation based on `max_output_size` from user input |
| `crop_and_resize_aicpu.cpp` | Critical | Processes crop box coordinates from user tensor |
| `spatial_transformer_aicpu.cpp` | Critical | Transformation matrix from user input |
| `scale_and_translate_aicpu.cpp` | High | Scale factors from user input |
| `image_warp_offsets_aicpu.cpp` | High | Warp parameters from user tensor |

**Potential Vulnerabilities**:
- Integer overflow in `max_output_size` validation (line 78-81 in NMS)
- Dynamic memory allocation `new int32_t[max_output_size_]` without upper bounds check
- Array index calculations based on user tensor dimensions

### 3. AI Core Kernel Layer (High Risk)

AI Core kernels (`op_kernel/*.cpp`) receive GM_ADDR pointers directly:

```cpp
extern "C" __global__ __aicore__ void grid_sample(GM_ADDR x, GM_ADDR grid, GM_ADDR y, ...)
```

**Concerns**:
- Direct memory access without intermediate validation
- Tiling key dispatch based on input characteristics
- Workspace allocation based on tensor dimensions

### 4. Parameter Validation Layer (Medium Risk)

The `CheckParams` functions in `op_api/*.cpp` files perform validation:

**Observed Patterns**:
- Null pointer checks via `OP_CHECK_NULL`
- Dtype validation via `OP_CHECK_DTYPE_NOT_SUPPORT`
- Shape dimension checks via `OP_CHECK_WRONG_DIMENSION`

**Potential Gaps**:
- Missing upper bounds checks for tensor dimensions
- Limited validation for scalar parameters (thresholds, ratios)
- Format-specific validation may be incomplete

---

## STRIDE Threat Modeling

### Spoofing

| Threat | Entry Point | Risk |
|--------|-------------|------|
| Malicious tensor metadata | aclnn API functions | High |
| Fake ROI boxes | roi_align, roi_pooling | Medium |

**Mitigation Status**: Partial - dtype/format validation exists but dimension bounds checking is limited.

### Tampering

| Threat | Entry Point | Risk |
|--------|-------------|------|
| Buffer overflow via tensor dimensions | AICPU kernels | Critical |
| Integer overflow in size calculations | CheckArray functions | High |
| Memory corruption via workspace allocation | GetWorkspaceSize | High |

**Mitigation Status**: Weak - minimal bounds checking on allocation sizes.

### Repudiation

| Threat | Entry Point | Risk |
|--------|-------------|------|
| No audit trail for operator execution | All operators | Low |

**Mitigation Status**: Not applicable for inference operators.

### Information Disclosure

| Threat | Entry Point | Risk |
|--------|-------------|------|
| Tensor data exposure via log messages | KERNEL_LOG_* macros | Low |

**Mitigation Status**: Good - logs use structured macros with limited data exposure.

### Denial of Service

| Threat | Entry Point | Risk |
|--------|-------------|------|
| Memory exhaustion via large tensors | workspace allocation | High |
| Infinite loops via invalid grid coordinates | grid_sample kernel | Medium |
| Priority queue exhaustion | NMS implementation | Medium |

**Mitigation Status**: Weak - no maximum tensor size enforcement.

### Elevation of Privilege

| Threat | Entry Point | Risk |
|--------|-------------|------|
| NPU memory access via crafted tensors | AI Core kernels | Critical |
| Host memory access via AICPU | AICPU kernels | High |

**Mitigation Status**: Weak - depends on CANN runtime sandboxing.

---

## High-Risk Modules Summary

### Critical Risk (Priority 1)

| Module | Files | Rationale |
|--------|-------|-----------|
| image_grid_sample | grid_sample.cpp | Direct GM_ADDR access, complex interpolation |
| image_transform (AICPU) | crop_and_resize_aicpu.cpp, spatial_transformer_aicpu.cpp | Dynamic allocation, coordinate processing |
| image_other (NMS) | non_max_suppression_v3_aicpu.cpp | User-controlled max_output_size, dynamic allocation |

### High Risk (Priority 2)

| Module | Files | Rationale |
|--------|-------|-----------|
| objdetect_roi | aclnn_roi_align_v2.cpp, roi_pooling_with_arg_max.cpp | Box coordinate processing, format conversion |
| objdetect_nms | aclnn_non_max_suppression.cpp, aclnn_iou.cpp | Box/score tensor processing |
| image_grid_sample (API) | aclnn_grid_sampler*.cpp | Grid coordinate validation |
| image_transform (API) | aclnn_im2col_backward.cpp | Complex parameter validation |

### Medium Risk (Priority 3)

| Module | Files | Rationale |
|--------|-------|-----------|
| common | tiling_util.cpp, op_error_check.h | Shared validation utilities |
| common/framework | *_onnx_plugin.cpp | ONNX model conversion |

---

## Recommended Security Controls

### 1. Input Validation Enhancement

- Add upper bounds checks for tensor dimensions (max_dim_size)
- Add validation for scalar parameters (iou_threshold, spatial_scale bounds)
- Validate workspace size against maximum limits

### 2. Memory Safety

- Replace `new int32_t[max_output_size_]` with bounded allocation
- Add overflow checks for size calculations (size_t vs int64_t)
- Implement safe memory copy operations in AICPU kernels

### 3. Bounds Checking

- Validate array indices before access in kernels
- Check grid coordinates are within valid range [-1, 1]
- Validate ROI box indices against input tensor dimensions

### 4. Logging Audit

- Ensure no tensor data is logged in error messages
- Add execution tracing for security monitoring

---

## Conclusion

The CANN ops-cv library presents significant attack surface through its tensor processing APIs. The primary risks are:

1. **Integer overflow vulnerabilities** in size calculations and allocation
2. **Improper bounds checking** in AICPU kernel implementations
3. **Direct memory access** in AI Core kernels without intermediate validation

Recommendation: Prioritize scanning of AICPU kernels (`op_kernel_aicpu/*.cpp`) and API validation functions (`op_api/*.cpp`) for integer overflow, buffer overflow, and improper input validation vulnerabilities.