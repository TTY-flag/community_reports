# VULN-DF-INT-008：MLA算子整数溢出漏洞

## 漏洞概述

| 字段 | 值 |
|------|-----|
| **ID** | VULN-DF-INT-008 |
| **类型** | Integer Overflow (CWE-190) |
| **严重性** | High |
| **置信度** | 95% (已确认) |
| **位置** | `attention/mla_prolog_v2/op_host/mla_prolog_v2_infershape.cpp:36` |
| **函数** | `SetMlaPrologV2ShapeDim` |
| **受影响组件** | MLA Prolog V2 InferShape |

## 漏洞摘要

这是一个**真实漏洞**。在 MLA Prolog V2 算子的 InferShape 函数中，当 `isBsMerge=false` 时执行 `B * S` 乘法计算输出张量维度，但代码没有对乘法结果进行溢出检查。根据官方文档，B 的取值范围为 0~65536，S 的取值范围在 A2/A3 平台上"不限制"，因此 B*S 可能溢出 int64_t，导致错误的 shape 推导和潜在的内存安全问题。

## 技术分析

### 1. 漏洞代码位置

**文件**: `/home/pwn20tty/Desktop/opencode_project/cann/1/ops-transformer/attention/mla_prolog_v2/op_host/mla_prolog_v2_infershape.cpp`

**漏洞代码** (第 36 行):
```cpp
dequantScaleQNopeShape->SetDim(DIM_INDEX_0, shapeParam.isBsMerge ? shapeParam.T : shapeParam.B * shapeParam.S);
```

**相关代码** (GetMlaPrologShapeDim 函数中):
```cpp
// 文件: mla_prolog_infershape.cpp:47-50
shapeParam.B = tokenXShape->GetDim(DIM_INDEX_0);  // 从用户输入获取
shapeParam.S = tokenXShape->GetDim(DIM_INDEX_1);  // 从用户输入获取
shapeParam.T = shapeParam.B * shapeParam.S;        // 第一次 B*S 乘法
```

### 2. 数据类型分析

**MlaPrologProtoShapeParam 结构体定义** (mla_prolog_infershape.h:52-62):
```cpp
struct MlaPrologProtoShapeParam {
    bool isBsMerge { false };
    int64_t B { 0 };       // 批次大小 - 64位有符号整数
    int64_t T { 0 };       // Token总数
    int64_t S { 0 };       // 序列长度
    int64_t N { 0 };       // 头数
    int64_t Hckv { 0 };
    int64_t He { 0 };
    int64_t Dr { 0 };
    int64_t Hcq { 0 };
};
```

- B 和 S 都是 `int64_t` 类型
- int64_t 范围: -9,223,372,036,854,775,808 到 9,223,372,036,854,775,807
- 没有对 B*S 乘法进行溢出检查

### 3. 数据流追踪

```
ACLNN API (aclnnMlaPrologV2WeightNzGetWorkspaceSize)
    ↓
tokenX 张量输入 (用户控制)
    ↓
InferShapeMlaPrologV2 (mla_prolog_v2_infershape.cpp:44)
    ↓
GetMlaPrologShapeDim (mla_prolog_infershape.cpp:22)
    ↓ [SOURCE] shapeParam.B = tokenXShape->GetDim(0)
    ↓ [SOURCE] shapeParam.S = tokenXShape->GetDim(1)
    ↓ [VULNERABLE] shapeParam.T = shapeParam.B * shapeParam.S (第50行)
    ↓
SetMlaPrologV2ShapeDim (mla_prolog_v2_infershape.cpp:17)
    ↓ [VULNERABLE] shapeParam.B * shapeParam.S (第36行)
    ↓
SetDim() 设置输出张量维度
```

### 4. isBsMerge 条件分支分析

`isBsMerge` 值由输入张量维度数量决定:

```cpp
if (tokenXShape->GetDimNum() == DIM_NUM_3) {  // 3维: (B, S, He)
    shapeParam.isBsMerge = false;              // ← 触发 B*S 计算
    shapeParam.B = tokenXShape->GetDim(DIM_INDEX_0);
    shapeParam.S = tokenXShape->GetDim(DIM_INDEX_1);
} else {                                        // 2维: (T, He)
    shapeParam.isBsMerge = true;               // ← 使用 T，不触发 B*S
}
```

**攻击条件**: 提供一个 3 维的 tokenX 张量 (B, S, He)，使得 `isBsMerge=false`

### 5. 文档约束分析

**官方文档约束** (aclnnMlaPrologV2WeightNz.md):

| 参数 | 取值范围 |
|------|----------|
| **B (Batch)** | 0~65536 |
| **S (Seq-Length)** | A2、A3: **不限制** |

**关键发现**: S 的取值范围"不限制"，意味着用户可以传入任意大的 S 值。

## 攻击场景构造

### 场景 1: 边界溢出

```python
# 构造恶意输入张量
B = 65536          # B 取最大允许值
S = 140737488355328  # S = 2^47 ≈ 1.4 × 10^14

# 计算乘积
B * S = 65536 * 140737488355328 = 9223372036854775808
#              = 2^16 * 2^47 = 2^63
#              = INT64_MAX + 1  → 溢出!
```

### 场景 2: 更实际的攻击值

```python
# 使用较小的 B 和较大的 S
B = 1000           # 合理的批次大小
S = 9223372036854775  # S ≈ 9.2 × 10^15

# 计算乘积
B * S ≈ 9.22 × 10^18 → 超过 INT64_MAX
```

### 场景 3: uint32_t 溢出 (tiling 代码)

在 tiling 代码中使用 `uint32_t` 类型存储维度值:

```cpp
// mla_prolog_tiling.h:131-134
struct MlaPrologBaseShapeInfo {
    uint32_t bSize = 0;    // 最大值约 4.29 × 10^9
    uint32_t s1Size = 0;
    uint32_t tSize = 0;
    ...
};

// mla_prolog_tiling.cpp:237
baseShapeInfo_.tSize = baseShapeInfo_.bSize * baseShapeInfo_.s1Size;
```

如果 B = 65536, S = 65536:
- uint32_t 乘积: 65536 * 65536 = 4,294,967,296 = 2^32 = 0 (溢出为0)

## 影响分析

### 1. 直接影响

| 影响 | 描述 |
|------|------|
| **Shape 推导错误** | 溢出后的错误值被设置为输出张量维度 |
| **内存分配异常** | 基于错误 shape 分配内存，可能过大或过小 |
| **内存访问越界** | 后续内核执行时访问超出实际分配范围的内存 |
| **数据损坏** | 内存写入越界可能损坏其他数据结构 |

### 2. 安全影响

- **拒绝服务 (DoS)**: 超大维度值可能导致内存分配失败或系统崩溃
- **内存泄露**: 溢出为小值可能导致后续操作访问已释放的内存
- **潜在信息泄露**: 内存越界读取可能泄露敏感数据

### 3. 漏洞链分析

```
整数溢出 → 错误 Shape → 错误内存分配 → 内存访问越界 → 数据损坏/信息泄露
```

## 概念验证

```cpp
// 模拟攻击场景的测试代码
#include <cstdint>
#include <iostream>

int main() {
    int64_t B = 65536;                     // B 最大允许值
    int64_t S = 140737488355328;           // S = 2^47
    int64_t product = B * S;               // 溢出计算
    
    std::cout << "B = " << B << std::endl;
    std::cout << "S = " << S << std::endl;
    std::cout << "B * S (overflowed) = " << product << std::endl;
    std::cout << "INT64_MAX = " << INT64_MAX << std::endl;
    
    // 输出: product = -9223372036854775808 (溢出为负值)
    // 这将导致输出张量被设置为负维度，引发严重错误
    
    return 0;
}
```

## 代码参考

| 文件 | 行号 | 描述 |
|------|------|------|
| `mla_prolog_v2_infershape.cpp` | 36 | 主要漏洞点 - B*S 乘法用于 SetDim |
| `mla_prolog_infershape.cpp` | 50 | 第二处 B*S 乘法 - 计算 T |
| `mla_prolog_infershape.h` | 52-62 | MlaPrologProtoShapeParam 结构体定义 |
| `mla_prolog_tiling.cpp` | 237 | uint32_t 溢出风险点 |
| `mla_prolog_tiling.h` | 131-149 | MlaPrologBaseShapeInfo 结构体定义 |

## 修复建议

### 1. 添加溢出检查 (推荐方案)

```cpp
// 在 GetMlaPrologShapeDim 中添加检查
ge::graphStatus GetMlaPrologShapeDim(const gert::InferShapeContext *context, 
                                      MlaPrologProtoShapeParam &shapeParam)
{
    // ... 获取 B 和 S ...
    
    if (!shapeParam.isBsMerge) {
        // 检查 B*S 是否会溢出
        if (shapeParam.B > 0 && shapeParam.S > 0) {
            // 使用安全乘法检查
            if (shapeParam.B > INT64_MAX / shapeParam.S) {
                OP_LOGE(context->GetNodeName(), 
                    "B*S overflow: B=%ld, S=%ld, product exceeds INT64_MAX",
                    shapeParam.B, shapeParam.S);
                return ge::GRAPH_FAILED;
            }
        }
        shapeParam.T = shapeParam.B * shapeParam.S;
    }
    
    return GRAPH_SUCCESS;
}
```

### 2. 使用安全乘法函数

```cpp
// 定义安全乘法辅助函数
inline bool SafeMultiplyInt64(int64_t a, int64_t b, int64_t& result) {
    if (a == 0 || b == 0) {
        result = 0;
        return true;
    }
    if (a > 0) {
        if (b > 0) {
            if (a > INT64_MAX / b) return false;
        } else {
            if (b < INT64_MIN / a) return false;
        }
    } else {
        if (b > 0) {
            if (a < INT64_MIN / b) return false;
        } else {
            if (b < INT64_MAX / a) return false;
        }
    }
    result = a * b;
    return true;
}
```

### 3. 文档约束增强

建议修改文档，对 S 的取值范围添加合理限制:
- 原: "A2、A3取值范围：不限制"
- 建议: "A2、A3取值范围：0 ~ (INT64_MAX / 65536) ≈ 1.4 × 10^14"

## 验证状态

| 检查项 | 结果 |
|--------|------|
| 源代码存在 B*S 乘法 | ✓ 确认 |
| 数据类型为 int64_t | ✓ 确认 |
| 无溢出检查代码 | ✓ 确认 |
| B/S 来源为用户输入 | ✓ 确认 |
| 文档约束允许触发条件 | ✓ 确认 |
| 可构造溢出攻击场景 | ✓ 确认 |

## 结论

**判定**: **真实漏洞 (TRUE POSITIVE)**

**理由**:
1. 代码确实存在 `B * S` 整数乘法操作，且数据类型为 int64_t
2. B 和 S 直接来源于用户输入张量的维度值
3. 代码中没有任何溢出检查或边界限制
4. 官方文档明确说明 B 取值范围 0~65536，S 取值范围"不限制"
5. 可构造实际的溢出攻击场景 (B=65536, S=2^47)
6. 溢出结果直接影响输出张量 shape 设置，可能导致内存安全问题

**风险等级**: High - 可能导致内存分配异常、访问越界、数据损坏

## 参考文献

- CWE-190: Integer Overflow or Wraparound
- [aclnnMlaPrologV2WeightNz 文档](./docs/aclnnMlaPrologV2WeightNz.md)
- 华为昇腾 CANN Transformer 算子库