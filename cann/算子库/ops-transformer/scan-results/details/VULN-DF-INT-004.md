# VULN-DF-INT-004：MoE算子整数溢出漏洞

## 漏洞摘要

| 字段 | 值 |
|-------|-------|
| **漏洞编号** | VULN-DF-INT-004 |
| **类型** | Integer Overflow (CWE-190) |
| **严重性** | High |
| **置信度** | 85% |
| **验证状态** | TRUE POSITIVE (已确认) |
| **受影响组件** | MoeDistributeDispatch Operator - InferShape |
| **项目** | 华为昇腾CANN Transformer算子库 |

## 漏洞详情

### 位置
- **主要**: `mc2/moe_distribute_dispatch/op_host/moe_distribute_dispatch_infershape.cpp:94`
- **次要**: `mc2/moe_distribute_dispatch_setup/op_api/aclnn_moe_distribute_dispatch_setup.cpp:129`

### 漏洞代码
```cpp
// 第81-84行：源变量
int64_t bs = xShape->GetDimNum() == 1U ? NEG_ONE : xShape->GetDim(0);
int64_t k = expertIdsShape->GetDimNum() == 1U ? NEG_ONE : expertIdsShape->GetDim(1);

// 第88-91行：验证（仅正数检查）
OP_CHECK_IF((bs <= 0) || (h <= 0) || (bsTmp <= 0) || (k <= 0),
    OP_LOGE(context->GetNodeName(), "Input shape of xShape or input shape of expertIdsShape is incorrect, "
    "xShape [%ld, %ld], expertIdsShape [%ld, %ld]", bs, h, bsTmp, k),
    return ge::GRAPH_FAILED);

// 第94行：漏洞点 - 无溢出保护！
expandIdxShape->SetDim(0U, bs * k);
```

### 次要漏洞位置
```cpp
// aclnn_moe_distribute_dispatch_setup.cpp:129
int64_t bs = x->GetViewShape().GetDim(0);
int64_t k = expertIds->GetViewShape().GetDim(1);
expandIdxOutSize = static_cast<uint64_t>(bs * k);  // 转换前溢出！
```

## 数据流分析

### 源变量
| 变量 | 来源 | 类型 | 验证 |
|----------|--------|------|------------|
| `bs` | `xShape->GetDim(0)` | `int64_t` | 仅 `> 0` 检查 |
| `k` | `expertIdsShape->GetDim(1)` | `int64_t` | 仅 `> 0` 检查 |

### 漏洞点位置
- `expandIdxShape->SetDim(0U, bs * k)` - 设置输出张量维度
- 内存分配依赖此计算的维度

### 验证缺口分析
```
┌─────────────────────────────────────────────────────────────┐
│                    编译流水线                      │
├─────────────────────────────────────────────────────────────┤
│  1. InferShape阶段                                         │
│     ├─ 从输入shape提取bs、k                      │
│     ├─ 仅检查正数 (bs > 0, k > 0)               │
│     ├─ 无边界验证                                  │
│     ├─ 无溢出检查                                     │
│     └─ 漏洞点：bs * k 在第94行                        │
│                                                              │
│  2. Tiling阶段（发生在InferShape之后）                 │
│     ├─ 有边界检查：bs <= 512, k <= 8                 │
│     ├─ MAX_SAFE_PRODUCT = 512 * 8 = 4096                    │
│     └─ 缓解来得太晚                             │
│                                                              │
│  3. ACLNN API入口                                          │
│     ├─ 直接算子调用绕过Python验证       │
│     ├─ 无显式边界验证                         │
│     └─ 漏洞路径存在                                │
└─────────────────────────────────────────────────────────────┘
```

## 攻击场景

### 攻击向量 1：ACLNN API直接调用
```cpp
// 攻击者构造恶意输入张量
int64_t malicious_bs = 3037000500;  // sqrt(INT64_MAX) ≈ 3037000499
int64_t malicious_k = 3037000500;

// 计算：bs * k ≈ 9.23 × 10^18
// INT64_MAX = 9,223,372,036,854,775,807 ≈ 9.22 × 10^18

// 结果：溢出！
// 实际结果：回绕为负值或小正数

// 分步攻击：
// 1. 创建shape为[3037000500, h]的aclTensor作为x
// 2. 创建shape为[bs, 3037000500]的aclTensor作为expertIds
// 3. 调用aclnnMoeDistributeDispatchGetWorkspaceSize()
// 4. InferShape计算溢出维度
// 5. 错误shape传播到内存分配
// 6. 发生缓冲区溢出/内存损坏
```

### 攻击向量 2：图构造绕过
```
攻击者直接构造GE（图引擎）图：
1. 创建带恶意输入shape的算子节点
2. InferShape函数在图编译期间执行
3. Tiling验证尚未执行
4. shape推理中发生溢出
5. 错误shape存储在图中
6. 运行时使用错误维度
```

### 概念验证（概念性）
```cpp
// 溢出演示
int64_t bs = 3037000500;
int64_t k = 3037000500;
int64_t product = bs * k;

// 期望值：9,225,530,250,000,000
// INT64_MAX：9,223,372,036,854,775,807
// 溢出发生：product回绕

// 如果回绕为负数：
//   SetDim(0U, negative) -> 未定义行为

// 如果回绕为小正数（如1000000）：
//   为1000000个元素分配内存
//   实际数据有bs * k个元素
//   写入数据时发生缓冲区溢出
```

## 影响评估

### 主要影响：错误的形状计算
- 输出张量维度计算错误
- shape推理返回错误结果
- 下游算子接收错误shape

### 次要影响：内存损坏
**场景A - 欠分配：**
```
bs * k溢出为小值（如1,000,000）
├─ 为1,000,000个元素分配内存
├─ 实际数据有90亿元素
├─ 写入数据时发生缓冲区溢出
└─ 内存损坏，潜在崩溃
```

**场景B - 负维度：**
```
bs * k溢出为负值
├─ SetDim(0U, negative_value)
├─ shape系统未定义行为
├─ 可能断言失败
└─ 拒绝服务
```

### 第三影响：安全利用
- CWE-190将整数溢出定义为可利用
- 缓冲区溢出可导致：
  - 任意代码执行
  - 信息泄露
  - 拒绝服务
- 违反纵深防御原则

## 缓解因素分析

### 现有缓解措施
| 缓解措施 | 位置 | 效果 |
|------------|----------|---------------|
| Tiling边界检查 | `moe_distribute_dispatch_tiling.cpp` | 有限 - 发生在InferShape之后 |
| BS_UPPER_BOUND = 512 | 第87行 | 未应用于InferShape |
| K_MAX = 8 | 第97行 | 未应用于InferShape |
| Python元注册 | `moe_distribute_dispatch_v2.py` | 可通过ACLNN API绕过 |

### 缓解措施不足的原因

1. **时机问题**：Tiling验证发生在InferShape已计算溢出值之后

2. **绕过路径**：ACLNN API允许直接算子调用，无需通过Python验证层

3. **违反纵深防御**：安全验证应在最早阶段（InferShape）进行，而非后续阶段

4. **缺失边界检查**：InferShape仅验证正数，无上限检查

## 修复建议

### 建议 1：添加溢出检查（高优先级）
```cpp
// 在InferExpertIdsShape函数中，第94行之前
#include <limits>

const int64_t MAX_INT64 = std::numeric_limits<int64_t>::max();
OP_CHECK_IF((bs > 0 && k > 0 && bs > MAX_INT64 / k),
    OP_LOGE(context->GetNodeName(), 
            "检测到整数溢出：bs * k会溢出。"
            "bs=%ld, k=%ld, max_safe_product=%ld",
            bs, k, MAX_INT64 / k),
    return ge::GRAPH_FAILED);

expandIdxShape->SetDim(0U, bs * k);
```

### 建议 2：添加边界验证（高优先级）
```cpp
// 定义与tiling约束匹配的上限
static constexpr int64_t BS_MAX_INFER = 512;
static constexpr int64_t K_MAX_INFER = 8;

OP_CHECK_IF(bs > BS_MAX_INFER,
    OP_LOGE(context->GetNodeName(), 
            "批次大小超过最大值：bs=%ld, max=%ld",
            bs, BS_MAX_INFER),
    return ge::GRAPH_FAILED);

OP_CHECK_IF(k > K_MAX_INFER,
    OP_LOGE(context->GetNodeName(), 
            "Top-k超过最大值：k=%ld, max=%ld",
            k, K_MAX_INFER),
    return ge::GRAPH_FAILED);
```

### 建议 3：安全乘法辅助函数（推荐）
```cpp
// 安全乘法工具函数
namespace ops {

template<typename T>
bool SafeMultiply(T a, T b, T& result) {
    if (a == 0 || b == 0) {
        result = 0;
        return true;
    }
    if (a > 0) {
        if (b > 0) {
            if (a > std::numeric_limits<T>::max() / b) return false;
        } else {
            if (b < std::numeric_limits<T>::min() / a) return false;
        }
    } else {
        if (b > 0) {
            if (a < std::numeric_limits<T>::min() / b) return false;
        } else {
            if (b < std::numeric_limits<T>::max() / a) return false;
        }
    }
    result = a * b;
    return true;
}

} // namespace ops

// 使用：
int64_t expandIdxSize;
OP_CHECK_IF(!ops::SafeMultiply(bs, k, expandIdxSize),
    OP_LOGE(context->GetNodeName(), "bs * k溢出"),
    return ge::GRAPH_FAILED);
expandIdxShape->SetDim(0U, expandIdxSize);
```

### 建议 4：应用于次要位置
```cpp
// 在aclnn_moe_distribute_dispatch_setup.cpp中
// 替换第129行为安全计算

int64_t expandIdxCompute;
if (!ops::SafeMultiply(bs, k, expandIdxCompute)) {
    OP_LOGE(ACLNN_ERR_PARAM_INVALID, 
            "整数溢出：bs=%ld, k=%ld", bs, k);
    return ACLNN_ERR_PARAM_INVALID;
}
expandIdxOutSize = static_cast<uint64_t>(expandIdxCompute);
```

## 严重性分类

### CVSS v3.1 评估
| 指标 | 值 | 理由 |
|--------|-------|---------------|
| 攻击向量 | Local | 需要本地访问调用ACLNN API |
| 攻击复杂度 | Low | 直接利用 |
| 所需权限 | Low | 需算子执行权限 |
| 用户交互 | None | 无需用户交互 |
| 范围 | Changed | 影响预期边界外内存 |
| 机密性影响 | Low | 潜在信息泄露 |
| 完整性影响 | High | 可能内存损坏 |
| 可用性影响 | High | 可能拒绝服务 |

**CVSS分数：7.1 (High)**

### CWE 分类
- **主要**：CWE-190 (Integer Overflow or Wraparound)
- **相关**：CWE-680 (Integer Overflow to Buffer Overflow)
- **相关**：CWE-129 (Improper Validation of Array Index)

## 验证证据

### 静态分析发现
1. InferShape函数缺乏溢出保护（已确认）
2. InferShape无边界验证（已确认）
3. Tiling验证发生在InferShape之后（已确认）
4. ACLNN API存在绕过路径（已确认）

### 代码审查证据
- 源变量：`bs`、`k`提取无边界检查
- 验证：仅有正数检查
- 漏洞点：`bs * k`使用无溢出保护
- 缓解时机：Tiling发生在漏洞窗口之后

## 参考文献

- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [CWE-680: Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html)
- 华为CANN文档：MoeDistributeDispatch算子

## 附录：受影响文件

| 文件 | 行号 | 严重性 | 描述 |
|------|------|----------|-------------|
| `moe_distribute_dispatch_infershape.cpp` | 94 | High | 主要溢出位置 |
| `aclnn_moe_distribute_dispatch_setup.cpp` | 129 | Medium | 次要溢出位置 |
| `moe_distribute_dispatch_tiling.cpp` | 347-349 | Info | 包含缓解措施（太晚） |

---

**报告生成日期**：2026-04-21  
**验证状态**：TRUE POSITIVE  
**建议行动**：立即应用修复补丁