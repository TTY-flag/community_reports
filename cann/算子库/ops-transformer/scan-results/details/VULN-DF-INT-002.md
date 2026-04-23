# VULN-DF-INT-002：量化AllReduce算子整数溢出漏洞

## Summary
| Field | Value |
|-------|-------|
| **Vulnerability ID** | VULN-DF-INT-002 |
| **Type** | Integer Overflow (CWE-190) |
| **Severity** | Medium |
| **Confidence** | 85% |
| **File** | mc2/quant_all_reduce/op_host/quant_all_reduce_infershape.cpp |
| **Line** | 73 |
| **Function** | GetShapeInfo |
| **Affected Operator** | QuantAllReduce |

## Vulnerability Details

### Location
```cpp
// File: quant_all_reduce_infershape.cpp:73
shapeInfo.bs = x_shape->GetDim(0) * x_shape->GetDim(1);
```

### Context
当输入张量是3维形状 `[b, s, h]` 时，函数计算 `bs = batch_size * seq_len`。这个乘法操作没有溢出检查，可能导致 `int64_t` 溢出。

### Data Flow Analysis

```
Source: ACLNN API Input Tensor Shape
    ↓
InferShapeQuantAllReduce() [Line 108]
    ↓
GetShapeInfo() [Line 57]
    ↓
x_shape->GetDim(0) * x_shape->GetDim(1) [Line 73] ← OVERFLOW POINT
    ↓
shapeInfo.bs (int64_t) [Potential Overflow]
    ↓
output_shape->SetDim(0, shapeInfo.bs) [Line 128] ← Incorrect Output Shape
```

### Related Structures

```cpp
struct QuantAllReduceShapeInfo {
    int64_t b;      // batch size
    int64_t s;      // sequence length
    int64_t bs;     // batch_size * seq_len ← OVERFLOW TARGET
    int64_t hiddenSize;
    uint64_t xDim;
    int64_t rankNum;
};
```

## Impact Analysis

### 1. Shape Inference Impact
- 溢出的 `bs` 值被用于设置输出tensor形状
- 输出形状 `output_shape->SetDim(0, shapeInfo.bs)` 会设置为错误值
- 可能导致后续算子处理错误的tensor大小

### 2. Tiling vs InferShape
| Component | Variable Type | Risk Level |
|-----------|--------------|------------|
| InferShape | `int64_t` | **HIGH** - Potential overflow |
| Tiling | `uint64_t` | **LOW** - Proper type used |
| Kernel | `uint64_t` | **LOW** - Uses tiling data |

Tiling代码（quant_all_reduce_tiling.cpp:78-87）使用 `uint64_t`，更安全：
```cpp
uint64_t xValueBS = context->GetInputShape(X_INDEX)->GetStorageShape().GetDim(DIM_ZERO);
...
xValueBS = xValueBS * context->GetInputShape(X_INDEX)->GetStorageShape().GetDim(DIM_ONE);
```

### 3. Real-world Trigger Condition

在正常深度学习场景中难以触发：
- INT64_MAX = 9,223,372,036,854,775,807
- 典型值：batch_size=128, seq_len=4096 → bs = 524,288
- 即使极端情况：batch_size=65536, seq_len=65536 → bs ≈ 4.3×10^9 (仍安全)

**但是**：
- 对于超长上下文模型（如 1M token），可能接近边界
- 恶意构造的输入形状可以触发溢出
- 缺乏防护措施违反安全编码规范

### 4. Security Assessment

| Aspect | Assessment |
|--------|------------|
| Memory Corruption | **NO** - Shape inference only |
| Code Execution | **NO** |
| Data Leak | **NO** |
| Denial of Service | **POSSIBLE** - Invalid shape may crash pipeline |
| Correctness Issue | **YES** - Output shape will be incorrect |

## Comparison with VULN-DF-INT-001

| Attribute | VULN-DF-INT-001 | VULN-DF-INT-002 |
|-----------|----------------|----------------|
| **File** | quant_reduce_scatter_infershape.cpp | quant_all_reduce_infershape.cpp |
| **Line** | 76 | 73 |
| **Operator** | QuantReduceScatter | QuantAllReduce |
| **Pattern** | `GetDim(0) * GetDim(1)` | `GetDim(0) * GetDim(1)` |
| **Same Pattern** | Yes | Yes |

**结论**：两个漏洞是独立的，位于不同算子，但模式相同。需要分别修复。

## Proof of Concept

### Trigger Scenario
```python
# 构造触发溢出的输入形状（假设场景）
# 注意：实际NPU内存限制可能阻止这种极端输入
import torch

# 如果 batch_size * seq_len > INT64_MAX
# 例如：batch_size = 2^31, seq_len = 2^31
# 这需要约 4TB 内存，实际场景难以实现
```

### Practical Limitation
由于NPU内存限制，实际触发此溢出需要：
- 假设 hidden_size = 1024, dtype = float16 (2 bytes)
- 触发溢出需要 b * s > INT64_MAX
- 这意味着 tensor 大小需要 > INT64_MAX * 1024 * 2 bytes ≈ 18 EB

**结论**：虽然代码存在漏洞，但实际触发条件极端困难。

## Recommended Fix

### Option 1: Add Overflow Check
```cpp
// Line 73 replacement
if (x_dim == DIM_THREE) {
    shapeInfo.b = x_shape->GetDim(0);
    shapeInfo.s = x_shape->GetDim(1);
    
    // 添加溢出检查
    int64_t dim0 = x_shape->GetDim(0);
    int64_t dim1 = x_shape->GetDim(1);
    if (dim0 > 0 && dim1 > 0 && dim0 > INT64_MAX / dim1) {
        OP_LOGE(context->GetNodeName(), 
                "Integer overflow in bs calculation: %ld * %ld exceeds INT64_MAX", 
                dim0, dim1);
        return ge::GRAPH_FAILED;
    }
    shapeInfo.bs = dim0 * dim1;
    shapeInfo.hiddenSize = x_shape->GetDim(AXIS_TWO);
}
```

### Option 2: Use Safe Multiplication Helper
```cpp
// 使用安全乘法函数（如果项目有）
shapeInfo.bs = SafeMultiply(x_shape->GetDim(0), x_shape->GetDim(1));
if (shapeInfo.bs == OVERFLOW_ERROR) {
    return ge::GRAPH_FAILED;
}
```

### Option 3: Use uint64_t Consistently
```cpp
// 修改结构体使用 uint64_t
struct QuantAllReduceShapeInfo {
    uint64_t bs;  // 改为 uint64_t
    ...
};
```

## Files to Fix

| Priority | File | Line | Change Required |
|----------|------|------|-----------------|
| **HIGH** | quant_all_reduce_infershape.cpp | 73 | Add overflow check |
| **MEDIUM** | quant_all_reduce_infershape.cpp | 43-50 | Consider uint64_t for bs |

## Additional Affected Patterns

在项目中发现相同模式的其他位置：
- `mc2/quant_reduce_scatter/op_host/quant_reduce_scatter_infershape.cpp:76` (VULN-DF-INT-001)
- `mc2/common/utils/context_transfer.cpp:166`

建议统一修复所有类似模式。

## References

- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [Secure Coding in C++ - Integer Operations](https://isocpp.org/wiki/faq/misc-technical-issues#int-overflow)

## Conclusion

**漏洞判定**：✅ 真实漏洞（但风险较低）

这是一个代码质量问题，主要影响正确性而非安全性。建议添加溢出检查以符合安全编码规范。虽然实际触发条件极端困难，但缺乏防护措施违反安全编码最佳实践。

---
*Report generated: 2026-04-21*
*Scanner: Detail Analysis Module*
