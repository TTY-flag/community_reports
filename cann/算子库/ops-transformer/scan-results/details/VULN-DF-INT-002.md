# VULN-DF-INT-002：量化AllReduce算子整数溢出漏洞

## 概要
| 字段 | 值 |
|-------|-------|
| **漏洞编号** | VULN-DF-INT-002 |
| **类型** | 整数溢出 (CWE-190) |
| **严重级别** | 中 (Medium) |
| **置信度** | 85% |
| **文件** | mc2/quant_all_reduce/op_host/quant_all_reduce_infershape.cpp |
| **行号** | 73 |
| **函数** | GetShapeInfo |
| **受影响算子** | QuantAllReduce |

## 漏洞详情

### 位置
```cpp
// 文件：quant_all_reduce_infershape.cpp:73
shapeInfo.bs = x_shape->GetDim(0) * x_shape->GetDim(1);
```

### 上下文
当输入张量是3维形状 `[b, s, h]` 时，函数计算 `bs = batch_size * seq_len`。这个乘法操作没有溢出检查，可能导致 `int64_t` 溢出。

### 数据流分析

```
源：ACLNN API输入张量形状
    ↓
InferShapeQuantAllReduce() [第108行]
    ↓
GetShapeInfo() [第57行]
    ↓
x_shape->GetDim(0) * x_shape->GetDim(1) [第73行] ← 溢出点
    ↓
shapeInfo.bs (int64_t) [潜在溢出]
    ↓
output_shape->SetDim(0, shapeInfo.bs) [第128行] ← 输出形状错误
```

### 相关结构

```cpp
struct QuantAllReduceShapeInfo {
    int64_t b;      // batch size
    int64_t s;      // sequence length
    int64_t bs;     // batch_size * seq_len ← 溢出目标
    int64_t hiddenSize;
    uint64_t xDim;
    int64_t rankNum;
};
```

## 影响分析

### 1. 形状推导影响
- 溢出的 `bs` 值被用于设置输出tensor形状
- 输出形状 `output_shape->SetDim(0, shapeInfo.bs)` 会设置为错误值
- 可能导致后续算子处理错误的tensor大小

### 2. Tiling vs InferShape
| 组件 | 变量类型 | 风险级别 |
|-----------|--------------|------------|
| InferShape | `int64_t` | **高** - 潜在溢出 |
| Tiling | `uint64_t` | **低** - 使用正确类型 |
| Kernel | `uint64_t` | **低** - 使用tiling数据 |

Tiling代码（quant_all_reduce_tiling.cpp:78-87）使用 `uint64_t`，更安全：
```cpp
uint64_t xValueBS = context->GetInputShape(X_INDEX)->GetStorageShape().GetDim(DIM_ZERO);
...
xValueBS = xValueBS * context->GetInputShape(X_INDEX)->GetStorageShape().GetDim(DIM_ONE);
```

### 3. 现实触发条件

在正常深度学习场景中难以触发：
- INT64_MAX = 9,223,372,036,854,775,807
- 典型值：batch_size=128, seq_len=4096 → bs = 524,288
- 即使极端情况：batch_size=65536, seq_len=65536 → bs ≈ 4.3×10^9 (仍安全)

**但是**：
- 对于超长上下文模型（如 1M token），可能接近边界
- 恶意构造的输入形状可以触发溢出
- 缺乏防护措施违反安全编码规范

### 4. 安全评估

| 方面 | 评估 |
|--------|------------|
| 内存损坏 | **否** - 仅形状推导 |
| 代码执行 | **否** |
| 数据泄露 | **否** |
| 拒绝服务 | **可能** - 无效形状可能导致管道崩溃 |
| 正确性问题 | **是** - 输出形状将不正确 |

## 与VULN-DF-INT-001比较

| 属性 | VULN-DF-INT-001 | VULN-DF-INT-002 |
|-----------|----------------|----------------|
| **文件** | quant_reduce_scatter_infershape.cpp | quant_all_reduce_infershape.cpp |
| **行号** | 76 | 73 |
| **算子** | QuantReduceScatter | QuantAllReduce |
| **模式** | `GetDim(0) * GetDim(1)` | `GetDim(0) * GetDim(1)` |
| **相同模式** | 是 | 是 |

**结论**：两个漏洞是独立的，位于不同算子，但模式相同。需要分别修复。

## 概念验证

### 触发场景
```python
# 构造触发溢出的输入形状（假设场景）
# 注意：实际NPU内存限制可能阻止这种极端输入
import torch

# 如果 batch_size * seq_len > INT64_MAX
# 例如：batch_size = 2^31, seq_len = 2^31
# 这需要约 4TB 内存，实际场景难以实现
```

### 实际限制
由于NPU内存限制，实际触发此溢出需要：
- 假设 hidden_size = 1024, dtype = float16 (2 bytes)
- 触发溢出需要 b * s > INT64_MAX
- 这意味着 tensor 大小需要 > INT64_MAX * 1024 * 2 bytes ≈ 18 EB

**结论**：虽然代码存在漏洞，但实际触发条件极端困难。

## 推荐修复

### 方案1：添加溢出检查
```cpp
// 第73行替换
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

### 方案2：使用安全乘法辅助函数
```cpp
// 使用安全乘法函数（如果项目有）
shapeInfo.bs = SafeMultiply(x_shape->GetDim(0), x_shape->GetDim(1));
if (shapeInfo.bs == OVERFLOW_ERROR) {
    return ge::GRAPH_FAILED;
}
```

### 方案3：一致使用uint64_t
```cpp
// 修改结构体使用 uint64_t
struct QuantAllReduceShapeInfo {
    uint64_t bs;  // 改为 uint64_t
    ...
};
```

## 需修复文件

| 优先级 | 文件 | 行号 | 所需更改 |
|----------|------|------|-----------------|
| **高** | quant_all_reduce_infershape.cpp | 73 | 添加溢出检查 |
| **中** | quant_all_reduce_infershape.cpp | 43-50 | 考虑为bs使用uint64_t |

## 其他受影响模式

项目中发现相同模式的其它位置：
- `mc2/quant_reduce_scatter/op_host/quant_reduce_scatter_infershape.cpp:76` (VULN-DF-INT-001)
- `mc2/common/utils/context_transfer.cpp:166`

建议统一修复所有类似模式。

## 参考资料

- [CWE-190: 整数溢出或回绕](https://cwe.mitre.org/data/definitions/190.html)
- [C++安全编码 - 整数操作](https://isocpp.org/wiki/faq/misc-technical-issues#int-overflow)

## 结论

**漏洞判定**：✅ 真实漏洞（但风险较低）

这是一个代码质量问题，主要影响正确性而非安全性。建议添加溢出检查以符合安全编码规范。虽然实际触发条件极端困难，但缺乏防护措施违反安全编码最佳实践。

---
*报告生成日期：2026-04-21*
*扫描器：详细分析模块*