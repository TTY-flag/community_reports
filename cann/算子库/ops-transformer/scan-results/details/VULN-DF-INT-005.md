# VULN-DF-INT-005：AllGather算子整数溢出漏洞

## 漏洞元数据

| 字段 | 值 |
|------|-----|
| **ID** | VULN-DF-INT-005 |
| **类型** | integer_overflow (CWE-190) |
| **严重性** | HIGH |
| **置信度** | 85% |
| **位置** | mc2/common/op_host/mc2_common_infershape.cpp:95 |
| **函数** | AllGatherMatmulInferYShape |
| **代码片段** | `yShape->SetDim(0, commParas.dimM * commParas.rankSize);` |

## 漏洞摘要

**判定: 真实漏洞**

AllGatherMatmul操作的shape推导代码中存在已确认的整数溢出漏洞。`dimM`（用户控制张量维度）与 `rankSize`（通信组大小）的乘法没有溢出保护，可能导致错误的输出shape计算和下游内存安全问题。

## 详细分析

### 1. 源代码上下文

**文件: `/mc2/common/op_host/mc2_common_infershape.cpp`**

```cpp
// 第77-98行: AllGatherMatmulInferYShape函数
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
    yShape->SetDim(0, commParas.dimM * commParas.rankSize);  // <-- 漏洞行95
    yShape->SetDim(1, commParas.dimN);
    return ge::GRAPH_SUCCESS;
}
```

**文件: `/mc2/common/op_host/mc2_common_infershape.cpp` - CommonParamCheck**

```cpp
// 第22-75行: 参数检查函数
ge::graphStatus CommonParamCheck(
    const gert::InferShapeContext* context, const size_t isTransAIndex, const size_t isTransBIndex, CommParas& commParas)
{
    commParas.x1MatrixShape = context->GetInputShape(0);
    // ... 维度验证（仅检查 == 2维）
    
    const int64_t* rankSizeAttr = attrs->GetAttrPointer<int64_t>(RANK_SIZE);  // 第38行
    // ...
    if (*rankSizeAttr <= 0) {
        // 从HCCL查询
        commParas.rankSize = rankNum;  // uint32_t，有限制
    } else {
        commParas.rankSize = *rankSizeAttr;  // 用户提供，无验证
    }
    
    commParas.dimM = !(*isTransA) ? commParas.x1MatrixShape->GetDim(0) : commParas.x1MatrixShape->GetDim(1);  // 第57行
    // dimM无上限检查
}
```

### 2. 数据流分析

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           数据流图                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ACLNN API层                                                                │
│  ├─ aclnnAllGatherMatmulGetWorkspaceSize()                                  │
│  │   └─ 用户提供：                                                          │
│  │       • x1张量shape (m, k)     ← dimM源                                  │
│  │       • group字符串for HCCL     ← rankSize源(via HCCL)                   │
│  │       • rankSize属性(optional) ← rankSize源(直接)                        │
│  │                                                                          │
│  验证层                                                                      │
│  ├─ aclnn_all_gather_matmul.cpp中CheckShape()                               │
│  │   └─ 验证k-axis: [256, 65535)                                            │
│  │   └─ m-axis (dimM)无上限验证                                             │
│  │   └─ rankSize无上限验证                                                  │
│  │                                                                          │
│  InferShape层                                                               │
│  ├─ InferShapeAllGatherMatmul()                                             │
│  │   └─ 调用AllGatherMatmulCommonInferShape()                                │
│  │       └─ 调用AllGatherMatmulInferYShape()                                 │
│  │           └─ 调用CommonParamCheck()                                       │
│  │               ├─ dimM = x1MatrixShape->GetDim(0) [传播]                   │
│  │               ├─ rankSize = HCCL查询或用户属性 [传播]                      │
│  │               └─ 无溢出检查                                               │
│  │           └─ yShape->SetDim(0, dimM * rankSize)  [漏洞点 - 溢出]         │
│  │                                                                          │
│  下游影响                                                                    │
│  ├─ 错误输出shape存储                                                        │
│  ├─ 基于错误大小的内存分配                                                   │
│  ├─ 缓冲区溢出/欠分配                                                        │
│  └─ 潜在内存损坏                                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3. 源变量分析

| 变量 | 来源 | 类型 | 控制 | 验证 |
|------|------|------|------|------|
| **dimM** | x1张量shape（用户输入） | int64_t | 用户通过aclCreateTensor()控制 | 无上限检查 |
| **rankSize** | HCCL查询或用户属性 | int64_t | HCCL: 有限(2-64); Attr: 无验证 | 仅HCCL回退时>0检查 |

**关键发现**: 当用户在属性索引5提供 `rankSizeAttr > 0`，值被直接使用，无任何上限验证。

### 4. 跨模块调用分析

**漏洞函数调用者：**

| 模块 | 文件 | 行 | 上下文 |
|------|------|-----|--------|
| AllGatherMatmul | all_gather_matmul_infershape.cpp | 26 | InferShapeAllGatherMatmul → AllGatherMatmulCommonInferShape |
| AllGatherMatmulV2 | all_gather_matmul_v2_infershape.cpp | 28 | InferShapeAllGatherMatmulV2 → AllGatherMatmulCommonInferShape |

**第113行额外漏洞乘法：**
```cpp
gatherOutShape->SetDim(0, commParas.dimM * commParas.rankSize);  // 也漏洞
```

### 5. 攻击场景构造

**场景1：极端dimM配合硬件rankSize**

```cpp
// 攻击参数
int64_t malicious_dimM = 144115188075855873;  // INT64_MAX/64 + 1
// rankSize = 64 (Ascend 950PR最大硬件支持)

// 计算：
// dimM * rankSize = 144115188075855873 * 64 
// = 9223372036854775872（超过INT64_MAX = 9223372036854775807）
// 结果回绕为负值或小正值

// 攻击代码：
aclTensor* x1 = aclCreateTensor({malicious_dimM, 256}, ACL_FLOAT16, ...);
aclTensor* x2 = aclCreateTensor({256, 512}, ACL_FLOAT16, ...);

// InferShape运行时：
// - dimM = 144115188075855873 来自x1 shape
// - rankSize = 64 来自HCCL
// - yShape->SetDim(0, overflow_value)
// - 输出shape变得错误
```

**场景2：用户提供rankSize属性**

```cpp
// 用户通过图属性提供恶意rankSize
// 在RANK_SIZE索引(5)设置值以触发溢出

int64_t malicious_dimM = 3037000500;  // sqrt(INT64_MAX) + 1
int64_t malicious_rankSize = 3037000500;  // 相同值

// dimM * rankSize = 3037000500^2 = 溢出
// dimM和rankSize都来自用户控制源
```

**场景3：通过动态shape实际利用**

```cpp
// 图编译阶段，shape推导在内存分配前发生
// 用户用符号/动态shape构造图
// 运行时，shape解析为触发溢出的值

// 这绕过了图构造期间的内存分配检查
```

### 6. 溢出影响分析

**数学分析：**

```
INT64_MAX = 9,223,372,036,854,775,807 (9.22 × 10^18)

溢出阈值：
- dimM > INT64_MAX / rankSize
- 对于rankSize = 64: dimM > 144,115,188,075,855,872
- 对于rankSize = 8:  dimM > 1,152,921,504,606,846,976

溢出示例：
1. dimM = 144,115,188,075,855,873, rankSize = 64
   → 结果：-63（回绕）
   
2. dimM = 2,147,483,648 (2^31), rankSize = 4,294,967,296 (2^32)
   → 结果：0（精确溢出）
```

**下游影响：**

| 阶段 | 影响 |
|------|------|
| Shape推导 | 错误输出shape存储 |
| 内存分配 | 基于错误shape计算缓冲区大小 |
| 内核执行 | 写入欠大小缓冲区 → 溢出 |
| 数据完整性 | 静默损坏，潜在崩溃 |

### 7. 约束分析

**硬件约束：**
- Ascend 950PR: rankSize限制为2, 4, 8, 16, 32, 64卡
- Atlas A2/A3: rankSize限制为2, 4, 8卡
- 通信数据限制: Ascend 950PR为16 × 256MB

**但这些约束不在shape推导层强制执行：**
- shape推导发生在图编译阶段
- 通信限制在shape推导之后检查
- 用户提供的rankSize属性绕过硬件限制

### 8. 相关漏洞

类似溢出模式还存在于：
- VULN-DF-INT-002: quant_all_reduce_infershape.cpp (bs * rankSize溢出)
- VULN-DF-INT-004: batch_matmul_reduce_scatter_infershape.cpp

### 9. 验证证据

**证据1：代码库中无溢出检查**
```bash
# grep搜索溢出保护
grep -r "SetDim.*overflow|overflow.*check" → 无相关结果
grep -r "__builtin_mul_overflow" → 仅在不相关测试文件中找到
```

**证据2：验证缺口**
- CheckShape()验证k-axis [256, 65535)但不验证m-axis
- CommonParamCheck()仅检查dimKX1 == dimKX2，不检查上限

**证据3：用户属性路径**
- 第54行：`commParas.rankSize = *rankSizeAttr;` - 直接赋值，无验证

### 10. 修复建议

**推荐修复：**

```cpp
ge::graphStatus AllGatherMatmulInferYShape(gert::InferShapeContext* context, CommParas& commParas)
{
    // ... 现有检查 ...
    
    // 新增：乘法前溢出保护
    if (commParas.dimM > 0 && commParas.rankSize > 0) {
        if (commParas.dimM > INT64_MAX / commParas.rankSize) {
            OP_LOGE(context->GetNodeName(), 
                "Integer overflow: dimM=%ld * rankSize=%ld exceeds INT64_MAX",
                commParas.dimM, commParas.rankSize);
            return ge::GRAPH_FAILED;
        }
    }
    
    int64_t outputDim0 = commParas.dimM * commParas.rankSize;  // 现安全
    yShape->SetDim(0, outputDim0);
    // ...
}
```

**额外建议：**

1. **验证rankSize上限**: 限制为硬件最大(64)
2. **验证dimM上限**: 基于通信数据限制
3. **CommonParamCheck中添加边界检查**: 验证所有维度
4. **使用安全乘法辅助函数**: `__builtin_mul_overflow` 或自定义safe_mul

### 11. 严重性评估

| 因素 | 评级 | 论证 |
|------|------|------|
| **可利用性** | Medium | 需要极端dimM值；受硬件约束 |
| **影响** | High | 内存损坏，缓冲区溢出潜在 |
| **范围** | Medium | 影响AllGatherMatmul和AllGatherMatmulV2 |
| **检测** | Hard | 溢出静默发生，shape推导阶段 |
| **总体** | HIGH | 有实际约束的真实漏洞 |

### 12. 结论

**已确认真实漏洞**

`AllGatherMatmulInferYShape` 第95行的整数溢出是真实安全漏洞。虽然实际利用受rankSize硬件限制（最大64）约束，但漏洞存在于代码路径中，可通过以下方式触发：

1. 通过用户提供的rankSize属性（绕过硬件限制）
2. 在内存分配检查前的图编译阶段
3. 通过bounds延迟解析的动态shape场景

**推荐行动**: 乘法前实现溢出保护并验证所有维度上限。

---

## 参考文献

- CWE-190: Integer Overflow or Wraparound
- 文件: /mc2/common/op_host/mc2_common_infershape.cpp
- API文档: aclnnAllGatherMatmul.md, aclnnAllGatherMatmulV2.md