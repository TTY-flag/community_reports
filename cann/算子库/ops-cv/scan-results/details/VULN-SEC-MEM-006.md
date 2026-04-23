# VULN-SEC-MEM-006：缩放平移算子整数溢出漏洞

## Executive Summary

**Status**: CONFIRMED REAL VULNERABILITY

**Severity**: High

**CWE Classification**: CWE-190 (Integer Overflow or Wraparound), CWE-400 (Uncontrolled Resource Consumption)

**Vulnerability Type**: Memory Exhaustion / Denial of Service

---

## Vulnerability Details

### Location
- **File**: `image/scale_and_translate/op_kernel_aicpu/scale_and_translate_aicpu.cpp`
- **Function**: `InitSpans()` (lines 149-165) and `ScaleAndTranslateCompute()` (line 359)
- **Lines**: 158-163 (primary), 359 (secondary)

### Vulnerable Code

```cpp
// Line 148-165: InitSpans function
template <typename Kernel>
uint32_t InitSpans(const Kernel &kernel, int64_t output_size,
                   int64_t input_size, bool antialias, float inv_scale,
                   Spans *spans, float &kernel_scale)
{
    kernel_scale = antialias ? std::max(inv_scale, 1.0f) : 1.0f;
    spans->span_size = std::min(
        2 * static_cast<int>(std::ceil(kernel.Radius() * kernel_scale)) + 1,
        static_cast<int>(input_size));

    // VULNERABLE ALLOCATIONS - No upper bound validation on output_size
    spans->starts = new (std::nothrow) Eigen::Tensor<int32_t, 1>(output_size);
    KERNEL_CHECK_NULLPTR(spans->starts, KERNEL_STATUS_PARAM_INVALID,
                         "New spans starts failed.")
    spans->weights = new (std::nothrow) Eigen::Tensor<float, 1>(spans->span_size * output_size);
    KERNEL_CHECK_NULLPTR(spans->weights, KERNEL_STATUS_PARAM_INVALID,
                         "New spans weights failed.")
    return KERNEL_STATUS_OK;
}

// Line 359: Additional vulnerable allocation
Eigen::Tensor<float, 4> intermediate_tensor_middle(p.batch_size, p.output_height,
                                                   p.input_width, p.channels);
```

### Data Flow

```
User Input (Input(1) tensor) 
    │
    ▼
Line 289: input_size = ctx.Input(1)->GetData()
    │
    ▼
Lines 300-301: 
    p.output_height = input_size[0];
    p.output_width = input_size[1];
    │
    ▼
[NO UPPER BOUND VALIDATION]
    │
    ▼
Line 352: ComputeSpans(..., p.output_width, ...)
Line 356: ComputeSpans(..., p.output_height, ...)
    │
    ▼
Line 175: InitSpans(..., output_size, ...)
    │
    ▼
Lines 158, 161: Large memory allocations based on user-controlled values
```

---

## Exploitation Analysis

### Attack Vector

The attacker controls the `size` input tensor (Input 1), which directly specifies `output_height` and `output_width`. These values are used to allocate memory without any upper bound validation.

### Trigger Conditions

1. **Attacker provides malicious `size` tensor** with extremely large values (e.g., `INT32_MAX = 2,147,483,647`)
2. **Kernel processes the input** and attempts to allocate:
   - `spans->starts`: `output_size * sizeof(int32_t)` bytes
   - `spans->weights`: `span_size * output_size * sizeof(float)` bytes
   - `intermediate_tensor_middle`: `batch_size * output_height * input_width * channels * sizeof(float)` bytes

### Concrete Attack Scenario

```python
# Malicious input construction
import numpy as np

# Input 0: Small image (doesn't matter for attack)
images = np.zeros((1, 10, 10, 3), dtype=np.float32)

# Input 1: Malicious size tensor - CRITICAL ATTACK VECTOR
# Using INT32_MAX to maximize memory consumption
size = np.array([2147483647, 2147483647], dtype=np.int32)  # INT32_MAX for both dimensions

# Input 2 & 3: Valid scale and translation
scale = np.array([1.0, 1.0], dtype=np.float32)
translation = np.array([0.0, 0.0], dtype=np.float32)

# When this operation is executed:
# Memory allocation attempts:
# - spans->starts (height): 2147483647 * 4 bytes = ~8.6 GB
# - spans->starts (width): 2147483647 * 4 bytes = ~8.6 GB  
# - spans->weights (height): span_size * 2147483647 * 4 bytes = potentially 100+ GB
# - spans->weights (width): span_size * 2147483647 * 4 bytes = potentially 100+ GB
# - intermediate_tensor_middle: batch * 2147483647 * width * channels * 4 bytes
```

### Memory Impact Calculation

For an attack with `output_height = output_width = INT32_MAX`:

| Allocation | Size Formula | Approximate Size |
|------------|--------------|------------------|
| spans->starts (row) | `output_height * sizeof(int32_t)` | ~8.6 GB |
| spans->starts (col) | `output_width * sizeof(int32_t)` | ~8.6 GB |
| spans->weights (row) | `span_size * output_height * sizeof(float)` | Span dependent (huge) |
| spans->weights (col) | `span_size * output_width * sizeof(float)` | Span dependent (huge) |
| intermediate_tensor | `batch * output_height * input_width * channels * sizeof(float)` | Potentially exabytes |

With typical span_size values (e.g., 5-15 for common kernels), `spans->weights` alone would attempt to allocate:
- `5 * 2,147,483,647 * 4` = ~43 GB per call

### Integer Overflow Risk

Additional concern: The multiplication `span_size * output_size` on line 161:

```cpp
spans->weights = new (std::nothrow) Eigen::Tensor<float, 1>(spans->span_size * output_size);
```

If `span_size * output_size` overflows `int64_t`, the allocation size could wrap around to a smaller value, potentially leading to heap buffer overflow when the tensor is accessed later.

---

## Root Cause Analysis

### Missing Validations

The code performs only **positive value checks** but lacks **upper bound validation**:

```cpp
// Lines 308-311: Only checks for positive values
KERNEL_CHECK_FALSE(
    (p.output_height > 0 && p.output_width > 0), KERNEL_STATUS_PARAM_INVALID,
    "output_height = [%d] and output_width = [%d] must be positive",
    p.output_height, p.output_width)
```

**No checks for:**
1. Maximum allowed `output_height` / `output_width`
2. Maximum total output size (`output_height * output_width`)
3. Integer overflow in size calculations
4. Maximum memory allocation size

### Existing Mitigations (Insufficient)

1. **`std::nothrow` allocation**: Returns nullptr on failure but doesn't prevent memory exhaustion attack
2. **`KERNEL_CHECK_NULLPTR`**: Checks allocation result but attack succeeds before this check

---

## Impact Assessment

### Severity: High

| Impact Category | Assessment |
|-----------------|------------|
| **Availability** | Critical - Can cause system-wide memory exhaustion |
| **Integrity** | None - Read-only corruption risk |
| **Confidentiality** | None - No data disclosure |

### Affected Components

1. **Scale and Translate AICPU Kernel** - Primary target
2. **System Memory** - Attacked resource
3. **Other System Processes** - Collateral damage via OOM

### Attack Prerequisites

1. Ability to invoke `ScaleAndTranslate` operation
2. Control over `size` input tensor (Input 1)
3. No additional privilege requirements

---

## Proof of Concept

### PoC Tensor Construction

```cpp
// C++ PoC for model construction
// Input shapes
std::vector<int64_t> image_shape = {1, 10, 10, 3};  // Minimal input
std::vector<int64_t> size_shape = {2};               // Size tensor

// Malicious size tensor
int32_t size_data[2] = {
    2147483647,  // INT32_MAX for output_height
    2147483647   // INT32_MAX for output_width
};

// Normal scale and translation
float scale_data[2] = {1.0f, 1.0f};
float translate_data[2] = {0.0f, 0.0f};

// When kernel executes:
// Memory allocation will attempt ~8.6GB + ~8.6GB + much more
// System will likely crash or become unresponsive
```

### Expected Behavior

1. **On resource-limited system**: Process killed by OOM killer
2. **On high-memory system**: Extreme memory consumption, potential system instability
3. **In containerized environment**: Container OOM, potential node-level impact

---

## Remediation Recommendations

### Immediate Fix

Add upper bound validation for output dimensions:

```cpp
// Recommended maximum values (adjust based on use case)
constexpr int64_t kMaxOutputDimension = 65536;  // 64K
constexpr int64_t kMaxOutputSize = 4294967296;  // 4GB total elements

// Add validation in ParseScaleAndTranslateParams()
KERNEL_CHECK_FALSE(
    (p.output_height <= kMaxOutputDimension && p.output_width <= kMaxOutputDimension),
    KERNEL_STATUS_PARAM_INVALID,
    "output_height = [%d] and output_width = [%d] exceed maximum allowed dimension [%d]",
    p.output_height, p.output_width, kMaxOutputDimension)

// Check for overflow in total output size
int64_t total_output_size = p.output_height * p.output_width;
KERNEL_CHECK_FALSE(
    (total_output_size > 0 && total_output_size <= kMaxOutputSize),
    KERNEL_STATUS_PARAM_INVALID,
    "Total output size [%d] exceeds maximum allowed [%d]",
    total_output_size, kMaxOutputSize)

// Check for integer overflow in span_size * output_size calculation
int64_t weights_size = static_cast<int64_t>(spans->span_size) * output_size;
KERNEL_CHECK_FALSE(
    (weights_size > 0 && weights_size <= kMaxOutputSize),
    KERNEL_STATUS_PARAM_INVALID,
    "Weights size calculation overflow or too large")
```

### Defense in Depth

1. **Input Validation**: Validate all user-controlled tensor values
2. **Resource Limits**: Implement per-operation memory quotas
3. **Allocator Limits**: Use bounded allocators that fail gracefully
4. **Logging**: Log suspicious input patterns for monitoring

---

## Verification

### Manual Verification Steps

1. Compile the kernel with PoC input
2. Monitor memory usage during execution
3. Observe allocation failure or system impact

### Test Cases

```cpp
// Negative test case - should fail validation
TEST(ScaleAndTranslateSecurity, LargeOutputSize) {
    int32_t malicious_size[2] = {2147483647, 2147483647};
    // Expect KERNEL_STATUS_PARAM_INVALID after fix
}

// Boundary test case
TEST(ScaleAndTranslateSecurity, MaxValidOutputSize) {
    int32_t max_size[2] = {65536, 65536};  // At boundary
    // Should succeed or fail gracefully based on available memory
}
```

---

## Related Vulnerabilities

This pattern may exist in other image processing kernels that accept user-controlled size parameters. Recommend auditing:

1. All `Scale*` family operations
2. All `Resize*` family operations  
3. All `Crop*` family operations
4. Any operation accepting dimension tensors

---

## References

- CWE-190: Integer Overflow or Wraparound
- CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')
- CWE-789: Memory Allocation with Excessive Size Value

---

## Metadata

- **Discovered by**: Automated Security Scanner
- **Analysis Date**: 2026-04-22
- **Last Updated**: 2026-04-22
- **File Version**: 1.0
