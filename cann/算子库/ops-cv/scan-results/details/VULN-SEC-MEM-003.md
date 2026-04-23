# VULN-SEC-MEM-003：NMS算子内存分配失控漏洞

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **ID** | VULN-SEC-MEM-003 |
| **Type** | Integer Overflow / Resource Exhaustion |
| **CWE** | CWE-190 (Integer Overflow or Wraparound), CWE-787 (Out-of-bounds Write) |
| **Severity** | High |
| **Affected File** | `image/non_max_suppression_v3/op_kernel_aicpu/non_max_suppression_v3_aicpu.cpp` |
| **Affected Lines** | 52, 154-157 |
| **Affected Functions** | `NonMaxSuppressionV3CpuKernel::GetInputAndCheck`, `NonMaxSuppressionV3CpuKernel::DoCompute` |

## Vulnerability Description

The Non-Max Suppression V3 AICPU kernel accepts user-controlled tensor shapes without upper bound validation. The `num_boxes_` value derived from `boxes_shape->GetDimSize(0)` is directly used in multiple memory-intensive operations without size limits, creating a resource exhaustion attack vector.

### Data Flow Analysis

```
User Input Tensor Shape (boxes)
    ↓
boxes_shape->GetDimSize(0)  [Line 39, 52]
    ↓
num_boxes_ (int64_t)  [Line 52, Header Line 42]
    ↓
┌─────────────────────────────────────────────────────────────┐
│ Path 1: Eigen::TensorMap Construction (Line 154-155)        │
│   Eigen::TensorMap<T, 2>(boxes_->GetData(), num_boxes_, 4) │
│   → Creates view mapping num_boxes_ * 4 elements            │
│   → No allocation, but creates incorrect dimension mapping  │
│   → Potential buffer over-read if boxes_ has insufficient data│
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ Path 2: std::vector Allocation (Line 156)                   │
│   std::vector<T> scores_data(num_boxes_);                   │
│   → Allocates num_boxes_ * sizeof(T) bytes                  │
│   → sizeof(float) = 4 bytes, sizeof(float16) = 2 bytes      │
│   → Memory exhaustion for large num_boxes_ values           │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ Path 3: std::copy_n Operation (Line 157-158)               │
│   std::copy_n(scores_->GetData(), num_boxes_, ...)         │
│   → Reads num_boxes_ elements from scores tensor            │
│   → Buffer over-read if scores tensor is undersized         │
└─────────────────────────────────────────────────────────────┘
```

### Code Evidence

**Line 52 - No bounds check on num_boxes_:**
```cpp
num_boxes_ = boxes_shape->GetDimSize(0);
// No validation: num_boxes_ can be any int64_t value from user input
```

**Lines 154-157 - Direct use in memory operations:**
```cpp
template <typename T, typename T_threshold>
uint32_t NonMaxSuppressionV3CpuKernel::DoCompute() {
  Eigen::TensorMap<Eigen::Tensor<T, Two, Eigen::RowMajor>> boxes_map(
      reinterpret_cast<T *>(boxes_->GetData()), num_boxes_, 4);  // num_boxes_ * 4 mapping
  std::vector<T> scores_data(num_boxes_);  // Allocation without size limit
  std::copy_n(reinterpret_cast<T *>(scores_->GetData()), num_boxes_,
              scores_data.begin());  // Copy without bounds check
```

## Attack Scenario Analysis

### Scenario 1: Memory Exhaustion Attack

**Attack Vector:** Malicious user provides a boxes tensor with extremely large first dimension.

**Trigger Conditions:**
```python
# Example malicious input construction
import numpy as np

# Create boxes tensor with dimension that causes memory exhaustion
num_boxes_malicious = 2**30  # 1073741824 boxes
boxes_shape = (num_boxes_malicious, 4)  # Shape: [1073741824, 4]

# This triggers:
# 1. scores_data allocation: 1073741824 * 4 bytes = 4 GB for float
# 2. For larger values like 2**31: 8 GB allocation
# 3. Maximum theoretical: 2**62 * 4 = astronomical (will throw bad_alloc)
```

**Attack Steps:**
1. User constructs model with NonMaxSuppressionV3 node
2. User provides boxes tensor with shape `[HUGE_NUMBER, 4]`
3. Kernel extracts `num_boxes_ = HUGE_NUMBER` without validation
4. `std::vector<T> scores_data(num_boxes_)` attempts to allocate enormous memory
5. System memory exhausted → OOM → Kernel crash → Potential Denial of Service

### Scenario 2: Integer Overflow in Eigen TensorMap Dimensions

**Attack Vector:** The multiplication `num_boxes_ * 4` for tensor dimensions.

**Trigger Conditions:**
```cpp
// If num_boxes_ = SIZE_MAX/4 + 1 (on 64-bit: 2^62 + 1)
// num_boxes_ * 4 wraps around or exceeds maximum
// This creates invalid tensor mapping
```

**Note:** Eigen::TensorMap doesn't allocate memory itself, but incorrect dimensions combined with subsequent tensor access (like `boxes_map(next_candidate.box_index, 0)` at line 212) could lead to out-of-bounds memory access.

### Scenario 3: Buffer Over-read via std::copy_n

**Attack Vector:** Mismatch between declared shape and actual tensor data size.

**Trigger Conditions:**
```python
# Create undersized scores tensor
# Declare shape as [1000000] but only allocate minimal data
scores_shape = (1000000,)  # Declared shape
scores_data_actual_size = 100  # Actual data size mismatch

# std::copy_n will read 1000000 elements from undersized buffer
# → Out-of-bounds read → Information leak or crash
```

## Exploitability Assessment

### Feasibility: HIGH

1. **User-Controlled Input:** Tensor shapes are directly provided by user code in ML model inference
2. **No Validation:** Code has zero upper-bound checks for `num_boxes_`
3. **Direct Impact:** Memory allocation happens immediately in kernel execution
4. **AI Chip Context:** NPU/AICPU kernels run in device memory context; exhaustion can affect entire device

### Barriers to Exploitation

| Barrier | Status | Analysis |
|---------|--------|----------|
| Size validation in framework layer | **NOT PRESENT** | No validation in infershape.cpp (file is minimal/empty) |
| Memory allocation limits in AICPU | **UNKNOWN** | No explicit limits found in codebase for this pattern |
| std::vector overflow protection | **PARTIAL** | std::vector throws std::bad_alloc for impossible sizes, but in kernel context may cause crash |
| Input tensor size validation | **NOT PRESENT** | No check that actual tensor data size matches declared shape |

### Proof of Concept Construction Approach

```python
# PoC structure for memory exhaustion
import torch
import torch_npu  # Assuming CANN integration

def create_nms_exhaustion_attack():
    # Maximum safe value: depends on available device memory
    # For 4GB device memory, num_boxes ~ 500M for float
    # For larger devices, values can be higher
    
    # Create tensors with suspicious large shape
    num_boxes_exploit = 10**9  # 1 billion - likely exceeds available memory
    
    boxes = torch.randn(num_boxes_exploit, 4, dtype=torch.float32)
    scores = torch.randn(num_boxes_exploit, dtype=torch.float32)
    max_output_size = torch.tensor(100, dtype=torch.int32)
    iou_threshold = torch.tensor(0.5, dtype=torch.float32)
    score_threshold = torch.tensor(0.1, dtype=torch.float32)
    
    # Call NonMaxSuppressionV3
    # This triggers memory exhaustion in scores_data vector allocation
    result = torch.ops.npu.non_max_suppression_v3(
        boxes, scores, max_output_size, iou_threshold, score_threshold
    )
    # Expected: OOM error, kernel crash, or device reset

# Alternative PoC: shape-data mismatch for buffer over-read
def create_nms_buffer_overread():
    # This requires manipulating tensor metadata vs actual allocation
    # May require low-level tensor manipulation or custom graph construction
    pass
```

## Impact Assessment

### Primary Impact: Resource Exhaustion / Denial of Service

- **Memory Exhaustion:** Large `num_boxes_` values cause massive memory allocation
- **NPU Device Crash:** AICPU kernel failure can affect entire NPU device
- **Service Disruption:** Model inference pipeline crashes

### Secondary Impact: Out-of-Bounds Read

- **Information Leak:** Buffer over-read in `std::copy_n` or `boxes_map` access could expose memory contents
- **Kernel Instability:** Invalid tensor dimensions cause undefined behavior

### Affected Scope

- All users of NonMaxSuppressionV3 operator
- Models using object detection pipelines
- Production inference services on NPU hardware

## Comparison with Similar Operators

| Operator | Size Limit | Location |
|----------|------------|----------|
| NonMaxSuppressionV6 | `MAX_VALID_OUTPUT = 700` | `aclnn_non_max_suppression.cpp:35` |
| RoiPoolingWithArgMax | `BATCH_SIZE_MAX_LIMIT = 1024` | `roi_pooling_with_arg_max_infershape.cpp:43` |
| RoiPoolingGradWithArgMax | `BATCH_SIZE_MAX_LIMIT = 1024` | `roi_pooling_grad_with_arg_max_infershape.cpp:30` |
| **NonMaxSuppressionV3** | **NO LIMIT** | **VULNERABLE** |

This demonstrates that size limits are standard practice in this codebase, but NMS v3 lacks them.

## Security Mechanisms Evaluation

### Existing Checks (NMS V3)

| Check | Present | Location |
|-------|---------|----------|
| Input null pointer check | ✓ | Lines 36-38, 57-59, etc. |
| Tensor shape null check | ✓ | Lines 39-41, 60-62 |
| Rank validation (boxes must be 2D) | ✓ | Line 45 |
| Column validation (boxes must have 4 columns) | ✓ | Line 45 |
| Scores-boxes length match | ✓ | Lines 68-70 |
| max_output_size >= 0 | ✓ | Lines 79-81 |
| iou_threshold range [0, 1] | ✓ | Lines 171-177 |
| dtype validation | ✓ | Lines 104-115 |
| **num_boxes_ upper bound** | ✗ **MISSING** | **VULNERABILITY** |

### What Would Block This Attack?

1. **Framework-level shape validation** - Not present in infershape.cpp
2. **Tensor size vs declared shape verification** - Not found in codebase
3. **Memory allocation limits in AICPU runtime** - Unknown; may exist but not documented
4. **Device memory limits** - Would cause allocation failure, but crash is still impact

## Remediation Recommendations

### Fix 1: Add Upper Bound Validation in GetInputAndCheck

```cpp
// Add to non_max_suppression_v3_aicpu.cpp after line 52
constexpr int64_t kMaxNumBoxes = 1000000;  // 1 million reasonable limit

num_boxes_ = boxes_shape->GetDimSize(0);
KERNEL_CHECK_FALSE((num_boxes_ > 0), KERNEL_STATUS_PARAM_INVALID,
                   "num_boxes must be positive, but got [%ld].", num_boxes_);
KERNEL_CHECK_FALSE((num_boxes_ <= kMaxNumBoxes), KERNEL_STATUS_PARAM_INVALID,
                   "num_boxes [%ld] exceeds maximum limit [%ld].",
                   num_boxes_, kMaxNumBoxes);
```

### Fix 2: Add Memory Size Validation

```cpp
// In DoCompute, before vector allocation
constexpr size_t kMaxVectorSizeBytes = 256 * 1024 * 1024;  // 256 MB limit
size_t required_memory = static_cast<size_t>(num_boxes_) * sizeof(T);
KERNEL_CHECK_FALSE((required_memory <= kMaxVectorSizeBytes),
                   KERNEL_STATUS_PARAM_INVALID,
                   "scores_data allocation size [%zu] exceeds limit [%zu].",
                   required_memory, kMaxVectorSizeBytes);
```

### Fix 3: Add infershape Validation

```cpp
// Add to non_max_suppression_v3_infershape.cpp
static constexpr int64_t kMaxNumBoxes = 1000000;

// Validate boxes shape at infer shape stage
if (boxes_shape->GetDim(0) > kMaxNumBoxes) {
    OP_LOGE("NonMaxSuppressionV3", "boxes shape dim0 [%ld] exceeds limit [%ld].",
            boxes_shape->GetDim(0), kMaxNumBoxes);
    return ge::GRAPH_FAILED;
}
```

## Fix Priority: HIGH

This vulnerability allows:
1. Unprivileged users to cause NPU device crashes
2. Denial of service in production inference services
3. Potential information leak via buffer over-read

**Recommended Action:** Implement upper bound validation for `num_boxes_` before next release.

## References

- CWE-190: Integer Overflow or Wraparound
- CWE-787: Out-of-bounds Write
- CWE-400: Uncontrolled Resource Consumption
- TensorFlow NonMaxSuppressionV3 implementation (has similar validation patterns)
