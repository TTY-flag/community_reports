# VULN-DF-INT-005：AllGather算子整数溢出漏洞

## Vulnerability Metadata

| Field | Value |
|-------|-------|
| **ID** | VULN-DF-INT-005 |
| **Type** | integer_overflow (CWE-190) |
| **Severity** | HIGH |
| **Confidence** | 85% |
| **Location** | mc2/common/op_host/mc2_common_infershape.cpp:95 |
| **Function** | AllGatherMatmulInferYShape |
| **Code Snippet** | `yShape->SetDim(0, commParas.dimM * commParas.rankSize);` |

## Executive Summary

**VERDICT: TRUE VULNERABILITY**

A confirmed integer overflow vulnerability exists in the shape inference code for AllGatherMatmul operations. The multiplication of `dimM` (user-controlled tensor dimension) and `rankSize` (communication group size) occurs without overflow protection, potentially leading to incorrect output shape calculation and downstream memory safety issues.

## Detailed Analysis

### 1. Source Code Context

**File: `/mc2/common/op_host/mc2_common_infershape.cpp`**

```cpp
// Lines 77-98: AllGatherMatmulInferYShape function
ge::graphStatus AllGatherMatmulInferYShape(gert::InferShapeContext* context, CommParas& commParas)
{
    OP_LOGE_IF(
        CommonParamCheck(context, AG_IS_TRANS_A, AG_IS_TRANS_B, commParas) != GRAPH_SUCCESS, GRAPH_FAILED,
        context->GetNodeName(), "CommonParamCheck excute failed.");
    // 动态shape入图时 m轴-1时，不再进行(dimM * rankSize)的处理
    if (commParas.dimM == -1) {
        commParas.rankSize = 1;
    }
    // 不支持k = 0
    if (commParas.dimKX1 == 0) {
        commParas.dimM = commParas.dimN = 0;
        OP_LOGE(context->GetNodeName(), "X1/X2 are empty tensors with zero dimK.");
        return ge::GRAPH_FAILED;
    }
    gert::Shape* yShape = context->GetOutputShape(0);
    OPS_CHECK_NULL_WITH_CONTEXT(context, yShape);
    yShape->SetDimNum(SUPPORT_DIM_SIZE);
    yShape->SetDim(0, commParas.dimM * commParas.rankSize);  // <-- VULNERABLE LINE 95
    yShape->SetDim(1, commParas.dimN);
    return ge::GRAPH_SUCCESS;
}
```

**File: `/mc2/common/op_host/mc2_common_infershape.cpp` - CommonParamCheck**

```cpp
// Lines 22-75: Parameter checking function
ge::graphStatus CommonParamCheck(
    const gert::InferShapeContext* context, const size_t isTransAIndex, const size_t isTransBIndex, CommParas& commParas)
{
    commParas.x1MatrixShape = context->GetInputShape(0);
    // ... dimension validation (only checks == 2 dims)
    
    const int64_t* rankSizeAttr = attrs->GetAttrPointer<int64_t>(RANK_SIZE);  // Line 38
    // ...
    if (*rankSizeAttr <= 0) {
        // Query from HCCL
        commParas.rankSize = rankNum;  // uint32_t, limited
    } else {
        commParas.rankSize = *rankSizeAttr;  // USER-PROVIDED, NO VALIDATION
    }
    
    commParas.dimM = !(*isTransA) ? commParas.x1MatrixShape->GetDim(0) : commParas.x1MatrixShape->GetDim(1);  // Line 57
    // NO UPPER BOUND CHECK on dimM
}
```

### 2. Data Flow Analysis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DATA FLOW DIAGRAM                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ACLNN API Layer                                                            │
│  ├─ aclnnAllGatherMatmulGetWorkspaceSize()                                  │
│  │   └─ User provides:                                                      │
│  │       • x1 tensor with shape (m, k)     ← dimM SOURCE                    │
│  │       • group string for HCCL           ← rankSize SOURCE (via HCCL)     │
│  │       • rankSize attribute (optional)   ← rankSize SOURCE (direct)       │
│  │                                                                          │
│  Validation Layer                                                           │
│  ├─ CheckShape() in aclnn_all_gather_matmul.cpp                             │
│  │   └─ Validates k-axis: [256, 65535)                                      │
│  │   └─ NO validation on m-axis (dimM) upper bound                          │
│  │   └─ NO validation on rankSize upper bound                               │
│  │                                                                          │
│  InferShape Layer                                                           │
│  ├─ InferShapeAllGatherMatmul()                                             │
│  │   └─ Calls AllGatherMatmulCommonInferShape()                             │
│  │       └─ Calls AllGatherMatmulInferYShape()                              │
│  │           └─ Calls CommonParamCheck()                                    │
│  │               ├─ dimM = x1MatrixShape->GetDim(0) [PROPAGATION]            │
│  │               ├─ rankSize = HCCL query OR user attribute [PROPAGATION]    │
│  │               └─ NO overflow check                                       │
│  │           └─ yShape->SetDim(0, dimM * rankSize)  [SINK - OVERFLOW]       │
│  │                                                                          │
│  Downstream Impact                                                          │
│  ├─ Incorrect output shape stored                                           │
│  ├─ Memory allocation based on wrong size                                   │
│  ├─ Buffer overflow/underallocation                                         │
│  └─ Potential memory corruption                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3. Source Variables Analysis

| Variable | Source | Type | Control | Validation |
|----------|--------|------|---------|------------|
| **dimM** | x1 tensor shape (user input) | int64_t | User-controlled via aclCreateTensor() | NO upper bound check |
| **rankSize** | HCCL query OR user attribute | int64_t | HCCL: limited (2-64); Attr: unvalidated | Only >0 check for HCCL fallback |

**Key Finding**: When user provides `rankSizeAttr > 0` at attribute index 5, the value is used directly without any upper bound validation.

### 4. Cross-Module Call Analysis

**Callers of vulnerable function:**

| Module | File | Line | Context |
|--------|------|------|---------|
| AllGatherMatmul | all_gather_matmul_infershape.cpp | 26 | InferShapeAllGatherMatmul → AllGatherMatmulCommonInferShape |
| AllGatherMatmulV2 | all_gather_matmul_v2_infershape.cpp | 28 | InferShapeAllGatherMatmulV2 → AllGatherMatmulCommonInferShape |

**Additional vulnerable multiplication at line 113:**
```cpp
gatherOutShape->SetDim(0, commParas.dimM * commParas.rankSize);  // Also vulnerable
```

### 5. Attack Scenario Construction

**Scenario 1: Extreme dimM with Hardware rankSize**

```cpp
// Attack parameters
int64_t malicious_dimM = 144115188075855873;  // INT64_MAX/64 + 1
// rankSize = 64 (max hardware support for Ascend 950PR)

// Calculation:
// dimM * rankSize = 144115188075855873 * 64 
// = 9223372036854775872 (overflows INT64_MAX = 9223372036854775807)
// Result wraps to negative or small positive value

// Attack code:
aclTensor* x1 = aclCreateTensor({malicious_dimM, 256}, ACL_FLOAT16, ...);
aclTensor* x2 = aclCreateTensor({256, 512}, ACL_FLOAT16, ...);

// When InferShape runs:
// - dimM = 144115188075855873 from x1 shape
// - rankSize = 64 from HCCL
// - yShape->SetDim(0, overflow_value)
// - Output shape becomes incorrect
```

**Scenario 2: User-provided rankSize Attribute**

```cpp
// User provides malicious rankSize via graph attribute
// At RANK_SIZE index (5), set value to cause overflow

int64_t malicious_dimM = 3037000500;  // sqrt(INT64_MAX) + 1
int64_t malicious_rankSize = 3037000500;  // Same value

// dimM * rankSize = 3037000500^2 = overflow
// Both dimM and rankSize come from user-controlled sources
```

**Scenario 3: Practical Exploit via Dynamic Shape**

```cpp
// In graph compilation phase, shape inference happens before memory allocation
// User constructs graph with symbolic/dynamic shapes
// At runtime, shapes resolve to overflow-triggering values

// This bypasses practical memory allocation checks during graph construction
```

### 6. Overflow Impact Analysis

**Mathematical Analysis:**

```
INT64_MAX = 9,223,372,036,854,775,807 (9.22 × 10^18)

Overflow threshold:
- dimM > INT64_MAX / rankSize
- For rankSize = 64: dimM > 144,115,188,075,855,872
- For rankSize = 8:  dimM > 1,152,921,504,606,846,976

Overflow examples:
1. dimM = 144,115,188,075,855,873, rankSize = 64
   → Result: -63 (wrapped around)
   
2. dimM = 2,147,483,648 (2^31), rankSize = 4,294,967,296 (2^32)
   → Result: 0 (exact overflow)
```

**Downstream Effects:**

| Phase | Impact |
|-------|--------|
| Shape Inference | Incorrect output shape stored |
| Memory Allocation | Buffer size calculated from wrong shape |
| Kernel Execution | Writing to undersized buffer → overflow |
| Data Integrity | Silent corruption, potential crash |

### 7. Constraint Analysis

**Hardware Constraints:**
- Ascend 950PR: rankSize limited to 2, 4, 8, 16, 32, 64 cards
- Atlas A2/A3: rankSize limited to 2, 4, 8 cards
- Communication data limit: 16 × 256MB for Ascend 950PR

**However, these constraints are NOT enforced at the shape inference layer:**
- Shape inference happens in graph compilation phase
- Communication limits checked AFTER shape inference
- User-provided rankSize attribute bypasses hardware limit

### 8. Related Vulnerabilities

Similar overflow patterns found in:
- VULN-DF-INT-002: quant_all_reduce_infershape.cpp (bs * rankSize overflow)
- VULN-DF-INT-004: batch_matmul_reduce_scatter_infershape.cpp

### 9. Verification Evidence

**Evidence 1: No overflow check found in codebase**
```bash
# grep search for overflow protection
grep -r "SetDim.*overflow|overflow.*check" → No relevant results
grep -r "__builtin_mul_overflow" → Only found in unrelated test file
```

**Evidence 2: Validation gaps**
- CheckShape() validates k-axis [256, 65535) but NOT m-axis
- CommonParamCheck() only checks dimKX1 == dimKX2, NOT upper bounds

**Evidence 3: User attribute path**
- Line 54: `commParas.rankSize = *rankSizeAttr;` - Direct assignment, no validation

### 10. Remediation Recommendations

**Recommended Fix:**

```cpp
ge::graphStatus AllGatherMatmulInferYShape(gert::InferShapeContext* context, CommParas& commParas)
{
    // ... existing checks ...
    
    // ADD: Overflow protection before multiplication
    if (commParas.dimM > 0 && commParas.rankSize > 0) {
        if (commParas.dimM > INT64_MAX / commParas.rankSize) {
            OP_LOGE(context->GetNodeName(), 
                "Integer overflow: dimM=%ld * rankSize=%ld exceeds INT64_MAX",
                commParas.dimM, commParas.rankSize);
            return ge::GRAPH_FAILED;
        }
    }
    
    int64_t outputDim0 = commParas.dimM * commParas.rankSize;  // Now safe
    yShape->SetDim(0, outputDim0);
    // ...
}
```

**Additional Recommendations:**

1. **Validate rankSize upper bound**: Limit to hardware max (64)
2. **Validate dimM upper bound**: Based on communication data limit
3. **Add bounds checking in CommonParamCheck**: Validate all dimensions
4. **Use safe multiplication helpers**: `__builtin_mul_overflow` or custom safe_mul

### 11. Severity Assessment

| Factor | Rating | Justification |
|--------|--------|---------------|
| **Exploitability** | Medium | Requires extreme dimM values; constrained by hardware |
| **Impact** | High | Memory corruption, buffer overflow potential |
| **Scope** | Medium | Affects AllGatherMatmul and AllGatherMatmulV2 |
| **Detection** | Hard | Overflow happens silently, shape inference phase |
| **Overall** | HIGH | Real vulnerability with practical constraints |

### 12. Conclusion

**TRUE VULNERABILITY CONFIRMED**

The integer overflow in `AllGatherMatmulInferYShape` at line 95 is a real security vulnerability. While practical exploitation is constrained by hardware limits on rankSize (max 64), the vulnerability exists in the code path and can be triggered:

1. Through user-provided rankSize attribute (bypasses hardware limits)
2. In graph compilation phase before memory allocation checks
3. Via dynamic shape scenarios where bounds are resolved late

**Recommended Action**: Implement overflow protection before multiplication and validate all dimension upper bounds.

---

## References

- CWE-190: Integer Overflow or Wraparound
- File: /mc2/common/op_host/mc2_common_infershape.cpp
- API Documentation: aclnnAllGatherMatmul.md, aclnnAllGatherMatmulV2.md
