# VULN-DF-INT-003：MoE分发算子整数溢出漏洞

## 基本信息
- 漏洞ID: VULN-DF-INT-003
- 类型: 整数溢出 (CWE-190)
- 严重性: Critical (扫描工具判定) → **实际评估: Medium**
- 置信度: 85
- 位置: mc2/moe_distribute_dispatch_v3/op_host/moe_distribute_dispatch_v3_infershape.cpp:274
- 函数: InferShapeMoeDistributeDispatchV3

## 漏洞描述

该漏洞位于 MoE（Mixture of Experts）分发算子的形状推理函数中。第274行存在潜在的整数溢出风险：

```cpp
epRecvCountShape->SetDim(0U, *epWorldSize * localExpertNum + globalBsReal * 2 * k * ((*epWorldSize) / RANK_NUM_PER_NODE));
```

该计算涉及多个大数值的乘法运算，理论上可能导致 int64_t 溢出。溢出后的值将用于设置 tensor 形状维度，可能导致：
1. 形状推理错误（负数维度）
2. 内存分配不足（小正数维度）
3. 后续计算中的数据损坏

## 数据流分析

### 污点源追踪

| 参数 | 来源 | 类型 | 约束条件 | 漏洞风险 |
|------|------|------|----------|----------|
| `epWorldSize` | 属性 (DISPATCH_INPUT_ATTR_EP_WORLD_SIZE_INDEX) | int64_t | [2, 768] | 有上限，风险低 |
| `moeExpertNum` | 属性 (DISPATCH_INPUT_ATTR_MOE_EXPERT_NUM_INDEX) | int64_t | (0, 1024] | 有上限，风险低 |
| `globalBs` | 属性 (DISPATCH_INPUT_ATTR_GLOBAL_BS_INDEX) | int64_t | **无上限约束** | **高风险源** |
| `bs` | xShape->GetDim(0) | int64_t | **无上限约束** | **高风险源** |
| `k` | expertIdsShape->GetDim(1) | int64_t | **无上限约束** | **高风险源** |

### 传播路径

```
ACLNN API 入口 (aclnnMoeDistributeDispatchV5GetWorkspaceSize)
    ↓
属性获取 (attrs->GetAttrPointer<int64_t>)
    ↓
[第179-180行] globalBs 获取（无验证）
    ↓
[第152-153行] epWorldSize 获取（有范围验证）
    ↓
[第202-205行] bs, k 从 shape 获取（只检查负值）
    ↓
[第215行] globalBsReal 计算:
    globalBsReal = (globalBs == 0) ? (bs * epWorldSize) : globalBs
    ↓
[第214行] localMoeExpertNum 计算:
    localMoeExpertNum = moeExpertNum / moeRankNum
    ↓
[第220-228行] localExpertNum 赋值（取决于 epRankId）
    ↓
[第274行] 汇点 - 溢出点:
    epRecvCountShape->SetDim(0U, ...)
```

### 现有防护机制

1. **第182-184行**: 检查 epRankId 在 [0, epWorldSize) 范围内 ✓
2. **第185-187行**: 检查 sharedExpertRankNum 在 [0, epWorldSize) 范围内 ✓
3. **第207-210行**: 检查 bs, h, bsTmp, k > 0（只检查负值，**不检查上界**）⚠️
4. **无**: 对 globalBsReal, bs, k 的上界检查 ❌

### 触发条件分析

根据计算分析：

```python
# int64_t 最大值: 9.22 × 10^18

# 第274行计算公式:
value = epWorldSize * localExpertNum + globalBsReal * 2 * k * (epWorldSize / 8)

# 使用最大参数值:
epWorldSize = 768          # 最大值
localExpertNum = 1024      # 假设最大
k = 8                      # 典型 top-k 值
RANK_NUM_PER_NODE = 8

# 计算:
part1 = 768 * 1024 = 786,432
part2_factor = 2 * 8 * (768 / 8) = 1536

# 溢出阈值:
overflow_threshold = (9.22e18 - 786432) / 1536 ≈ 6.00 × 10^15

# 如果 globalBs = 0:
bs_threshold = 6.00e15 / 768 ≈ 7.82 × 10^12
```

**溢出阈值总结**:
- `globalBsReal` 需超过 **6万亿** (6 × 10^15)
- `bs` 需超过 **78万亿** (7.8 × 10^12)（如果 globalBs = 0）

## 攻击场景

### 场景1: 极大 Batch Size 攻击

**攻击者能力**: 
- 可以控制 ACLNN API 的输入参数（通过 PyTorch 接口）
- 可以构造异常大的 tensor shape 或属性值

**攻击路径**:
```
PyTorch 模型调用
    ↓
torch_npu 扩展
    ↓
aclnnMoeDistributeDispatchV5GetWorkspaceSize
    ↓
传入异常参数:
    - globalBs = 10^16 (10万亿)
    - 或 bs = 10^13 (构造超大 tensor)
    - k = 8 (正常值)
    - epWorldSize = 768
    ↓
InferShapeMoeDistributeDispatchV3 执行
    ↓
第274行计算溢出
    ↓
epRecvCountShape 维度设置为错误值（负数或小正数）
    ↓
后续内存分配错误 → NPU 崩溃或数据损坏
```

**触发条件**（具体参数值）:
```cpp
// 示例攻击参数:
int64_t globalBs = 7000000000000000;  // 7万亿
int64_t epWorldSize = 768;
int64_t moeExpertNum = 1024;
int64_t k = 8;  // expertIds shape: {bs, 8}

// 计算结果:
// value = 768*1024 + 7e15*2*8*96 ≈ 10.75e18 > INT64_MAX (溢出)
// 溢出后 value ≈ -1.75e18 (负数)
```

### 场景2: 通过 globalBs 参数直接攻击

**攻击者能力**: 
- 直接调用 ACLNN API，传入恶意 globalBs 值

**触发条件**:
```cpp
// 攻击参数:
globalBs = 10000000000000000;  // 10万亿
epWorldSize = 768;
expertScalesShape != nullptr;  // 触发溢出路径
IsTargetSocVersionInfershape(nodeName, PLATFORM_A2);  // Ascend910B 平台
```

### 场景限制

该漏洞触发条件极其苛刻：
1. 需要目标平台为 **Ascend910B** (特定硬件)
2. 需要 `expertScalesShape != nullptr`（必须提供 expert_scales 输入）
3. 需要异常大的参数值（万亿级别）

## 影响评估

### 直接影响

如果溢出发生：

| 溢出结果 | 形状维度 | 影响 |
|----------|----------|------|
| 负数 | 负数维度 | SetDim 可能失败，返回 GRAPH_FAILED |
| 小正数 | 错误的小值 | 内存分配不足 → 数据损坏、越界访问 |
| 大负数 | 负数维度 | 编译图阶段错误 |

**关键影响点**:
- `epRecvCountShape` 用于记录从各卡接收的 token 数量
- 该 tensor 的形状错误会直接影响后续的通信和计算
- 可能导致 NPU 设备异常、模型训练中断

### 间接影响

1. **资源浪费**: 如果 SetDim 失败，算子会提前返回错误，浪费计算资源
2. **稳定性风险**: 极端情况下可能导致 NPU 设备异常
3. **数据完整性**: 如果内存分配不足，可能导致数据损坏

### CVSS 评分估算

根据实际触发难度评估：

```
CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L

- Attack Vector (AV): Local - 需要本地调用 API
- Attack Complexity (AC): High - 需要构造异常大参数值（万亿级别）
- Privileges Required (PR): Low - 只需调用算子权限
- User Interaction (UI): None
- Scope (S): Unchanged
- Confidentiality (C): None
- Integrity (I): None - 数据完整性影响有限
- Availability (A): Low - 可能导致算子失败，但影响范围有限

CVSS Base Score: 2.8 (Low)
```

**修正严重性**: 从 Critical → **Medium/Low**

## 修复建议

### 代码修复方案

#### 方案1: 添加参数上界检查

```cpp
// 在 InferShapeMoeDistributeDispatchV3 函数中添加：

// 第210行后添加:
static constexpr int64_t MAX_BATCH_SIZE = 1000000000;  // 10亿上限
static constexpr int64_t MAX_K_VALUE = 128;             // top-k 上限
static constexpr int64_t MAX_GLOBAL_BS = 100000000000;  // globalBs 上限

OP_CHECK_IF(bs > MAX_BATCH_SIZE,
    OP_LOGE(context->GetNodeName(), "Batch size %ld exceeds maximum allowed value %ld.", 
            bs, MAX_BATCH_SIZE), return ge::GRAPH_FAILED);

OP_CHECK_IF(k > MAX_K_VALUE,
    OP_LOGE(context->GetNodeName(), "K value %ld exceeds maximum allowed value %ld.", 
            k, MAX_K_VALUE), return ge::GRAPH_FAILED);

OP_CHECK_IF(*globalBs > MAX_GLOBAL_BS,
    OP_LOGE(context->GetNodeName(), "Global batch size %ld exceeds maximum allowed value %ld.", 
            *globalBs, MAX_GLOBAL_BS), return ge::GRAPH_FAILED);

OP_CHECK_IF(bs * *epWorldSize > MAX_GLOBAL_BS,
    OP_LOGE(context->GetNodeName(), "Calculated globalBsReal %ld exceeds maximum allowed value %ld.", 
            bs * *epWorldSize, MAX_GLOBAL_BS), return ge::GRAPH_FAILED);
```

#### 方案2: 计算前检查溢出

```cpp
// 在第274行前添加溢出检查:

int64_t epWorldSizeDiv = (*epWorldSize) / RANK_NUM_PER_NODE;
int64_t overflowThreshold = std::numeric_limits<int64_t>::max();

// 检查乘法是否会导致溢出
if (globalBsReal > 0 && k > 0 && epWorldSizeDiv > 0) {
    // globalBsReal * 2 * k * epWorldSizeDiv 检查
    int64_t product1 = globalBsReal * 2;
    if (product1 < 0 || product1 > overflowThreshold) {
        OP_LOGE(context->GetNodeName(), "Integer overflow detected in epRecvCountShape calculation.");
        return ge::GRAPH_FAILED;
    }
    
    int64_t product2 = product1 * k;
    if (product2 < 0 || product2 > overflowThreshold) {
        OP_LOGE(context->GetNodeName(), "Integer overflow detected in epRecvCountShape calculation.");
        return ge::GRAPH_FAILED;
    }
    
    int64_t product3 = product2 * epWorldSizeDiv;
    if (product3 < 0 || product3 > overflowThreshold) {
        OP_LOGE(context->GetNodeName(), "Integer overflow detected in epRecvCountShape calculation.");
        return ge::GRAPH_FAILED;
    }
}

// 安全计算
int64_t epRecvCountDim = *epWorldSize * localExpertNum + globalBsReal * 2 * k * epWorldSizeDiv;
epRecvCountShape->SetDim(0U, epRecvCountDim);
```

#### 方案3: 使用安全计算函数

```cpp
// 添加辅助函数:
namespace {
    bool SafeMultiply(int64_t a, int64_t b, int64_t& result) {
        if (a == 0 || b == 0) {
            result = 0;
            return true;
        }
        if (a > std::numeric_limits<int64_t>::max() / b ||
            a < std::numeric_limits<int64_t>::min() / b) {
            return false;  // 溢出
        }
        result = a * b;
        return true;
    }
}

// 在计算前使用:
int64_t temp1, temp2, temp3, temp4;
if (!SafeMultiply(globalBsReal, 2, temp1) ||
    !SafeMultiply(temp1, k, temp2) ||
    !SafeMultiply(temp2, (*epWorldSize) / RANK_NUM_PER_NODE, temp3) ||
    !SafeMultiply(*epWorldSize, localExpertNum, temp4)) {
    OP_LOGE(context->GetNodeName(), "Integer overflow in epRecvCountShape dimension calculation.");
    return ge::GRAPH_FAILED;
}
int64_t finalDim = temp4 + temp3;
epRecvCountShape->SetDim(0U, finalDim);
```

### 属性定义修复

在 `moe_distribute_dispatch_v3_proto.h` 中添加约束说明：

```cpp
// 第35行修改:
* @li ep_world_size: Required. Input ep comm world size, Support Range: [2, 768], dtype: int64.
* @li global_bs: Input global batch size, Support Range: [0, 10^11], dtype: int64. **新增上限**
```

## 验证结果

### 测试验证

通过数值计算验证溢出阈值：

```python
# 测试场景
epWorldSize = 768
k = 8
RANK_NUM_PER_NODE = 8

# 正常场景 - 不溢出
bs = 1000000000  # 10亿
globalBsReal = bs * epWorldSize = 7.68e11
value = 768*1024 + 7.68e11 * 2 * 8 * 96 ≈ 1.18e15  # 远小于 INT64_MAX

# 攻击场景 - 溢出
globalBs = 10000000000000000  # 10万亿
value = 768*1024 + 1e16 * 2 * 8 * 96 ≈ 1.54e19 > INT64_MAX  # 溢出!
```

### 判定结论

- **判定**: **真实漏洞，但严重性应调整为 Medium**
- **原因**: 
  1. ✓ 代码确实缺少对 globalBsReal、bs、k 的上界检查
  2. ✓ 理论上存在整数溢出风险
  3. ⚠️ 但触发条件极其苛刻（需要万亿级别的参数值）
  4. ⚠️ 正常 MoE 模型场景下不会触发（batch size 通常 < 10万）
  5. ✓ 建议添加边界检查以增强代码健壮性和防御性编程

### 与扫描工具评估的差异

| 维度 | 扫描工具 | 实际分析 |
|------|----------|----------|
| 严重性 | Critical | Medium |
| 触发难度 | 未评估 | 极高（需万亿级参数） |
| 影响范围 | 广泛 | 有限（特定平台+特定条件） |
| 实际风险 | 高 | 低 |

**调整理由**: 
- 溢出阈值远超实际使用场景（6万亿 vs 正常 < 1亿）
- 需要恶意构造异常参数
- 缺少实际的攻击路径（攻击者难以获得如此大的计算资源）

### 建议

1. **优先级**: Medium - 应修复但非紧急
2. **修复方式**: 添加参数上界检查（方案1 最简单有效）
3. **测试**: 在单元测试中添加边界值测试用例

---

**报告生成时间**: 2026-04-21
**分析工具**: 人工深度分析 + 数值验证
**参考文献**: CWE-190 (Integer Overflow or Wraparound)
