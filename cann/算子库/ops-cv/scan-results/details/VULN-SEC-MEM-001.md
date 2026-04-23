# VULN-SEC-MEM-001：NMS算子整数溢出漏洞

## 漏洞摘要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-MEM-001 |
| **类型** | integer_overflow_resource_exhaustion |
| **CWE** | CWE-190 (Integer Overflow or Wraparound) |
| **严重性** | High |
| **CVSS评分** | 7.5 (High) |
| **文件** | image/non_max_suppression_v3/op_kernel_aicpu/non_max_suppression_v3_aicpu.cpp |
| **行号** | 78, 165 |
| **函数** | NonMaxSuppressionV3CpuKernel::DoCompute |
| **状态** | 已确认 (真实漏洞) |

---

## 1. 漏洞详情

### 1.1 漏洞代码位置

```cpp
// 文件: non_max_suppression_v3_aicpu.cpp
// 行号: 78-81 (输入验证)
Tensor *max_output_size_tensor = ctx.Input(kThirdInputIndex);
KERNEL_CHECK_FALSE((max_output_size_tensor != nullptr),
                   KERNEL_STATUS_PARAM_INVALID,
                   "GetInputAndCheck: get input:2 max_output_size failed.");
max_output_size_ = *static_cast<int32_t *>(max_output_size_tensor->GetData());
KERNEL_CHECK_FALSE((max_output_size_ >= 0), KERNEL_STATUS_PARAM_INVALID,
                   "max_output_size must be non-negative, but are [%d]",
                   max_output_size_);
// 问题: 仅检查 >= 0，缺少上限验证!

// 行号: 165 (危险内存分配)
std::unique_ptr<int32_t[]> indices_data(new (std::nothrow) int32_t[max_output_size_]);
if (indices_data == nullptr) {
    KERNEL_LOG_ERROR("DoCompute: new indices_data failed");
    return KERNEL_STATUS_INNER_ERROR;
}
// 问题: max_output_size_ 直接用于动态内存分配，无上限约束!
```

### 1.2 数据流分析

```
用户输入 Tensor (max_output_size)
    ↓
ctx.Input(kThirdInputIndex) 
    ↓
max_output_size_tensor->GetData()
    ↓
*static_cast<int32_t *>(...) → max_output_size_
    ↓
仅检查 >= 0 (无上限!)
    ↓
new int32_t[max_output_size_] → 动态内存分配
    ↓
可能导致内存耗尽或分配失败
```

---

## 2. 深度利用分析

### 2.1 攻击向量

攻击者可以通过控制 `max_output_size` 输入 Tensor 的值来触发漏洞：

1. **输入来源**: `max_output_size` 是一个 scalar Tensor (DT_INT32)，由用户在调用 NMS v3 算子时提供
2. **验证缺陷**: 代码仅验证 `max_output_size_ >= 0`，允许任意大的正整数
3. **危险操作**: 该值直接作为数组大小传递给 `new int32_t[max_output_size_]`

### 2.2 具体攻击场景

#### 场景 A: 内存耗尽攻击

```python
# 攻击者构造恶意输入
import numpy as np
import acl  # Huawei Ascend Compute Library

# 构造正常 boxes 和 scores
boxes = np.random.rand(5, 4).astype(np.float32)  # 正常数据
scores = np.random.rand(5).astype(np.float32)     # 正常数据

# 构造恶意 max_output_size
max_output_size = np.array([2147483647], dtype=np.int32)  # INT32_MAX

# 调用 NMS v3 算子
# 将触发约 8GB 内存分配请求: 2147483647 * 4 bytes = ~8GB
result = acl.op.non_max_suppression_v3(
    boxes, scores, max_output_size, 
    iou_threshold, score_threshold
)
```

**攻击效果**:
- 单次调用请求分配约 **8GB 内存**
- 多次并发调用可导致系统内存耗尽
- 其他进程无法分配内存，导致系统拒绝服务

#### 场景 B: 内存分配失败

```python
# 在内存受限环境中
max_output_size = np.array([1073741824], dtype=np.int32)  # 1GB entries = 4GB memory
# 在 4GB 内存设备上，可能导致:
# - 算子执行失败
# - 返回 KERNEL_STATUS_INNER_ERROR
# - 应用程序崩溃或功能降级
```

### 2.3 触发条件

| 条件 | 说明 |
|------|------|
| **输入类型** | DT_INT32 scalar Tensor |
| **有效范围** | 仅检查 >= 0，任何 >= 0 的值都被接受 |
| **危险阈值** | max_output_size > 可用内存 / 4 bytes |
| **典型攻击值** | INT32_MAX (2147483647), 1000000000, 500000000 |

---

## 3. 对比分析: v3 vs v6

### 3.1 v3 版本 (存在漏洞)

```cpp
// non_max_suppression_v3_aicpu.cpp
// 无上限验证!
max_output_size_ = *static_cast<int32_t *>(max_output_size_tensor->GetData());
KERNEL_CHECK_FALSE((max_output_size_ >= 0), KERNEL_STATUS_PARAM_INVALID, ...);
// 直接用于内存分配
std::unique_ptr<int32_t[]> indices_data(new (std::nothrow) int32_t[max_output_size_]);
```

### 3.2 v6 版本 (安全实现)

```cpp
// aclnn_non_max_suppression.cpp (v6)
static constexpr int32_t MAX_VALID_OUTPUT = 700;  // 安全上限!

int64_t maxOutputSize = 0;
if (maxOutputBoxesPerClass->Size() > 0) {
    maxOutputSize = maxOutputBoxesPerClass->operator[](0);
}
if (maxOutputSize > MAX_VALID_OUTPUT) {
    OP_LOGE(ACLNN_ERR_PARAM_INVALID, "maxOutputBoxesPerClass[%ld] should < 700 ", maxOutputSize);
    return ACLNN_ERR_PARAM_INVALID;  // 拒绝危险输入!
}
```

**关键差异**:
- v6 定义了 `MAX_VALID_OUTPUT = 700` 上限
- v6 在分配前验证输入不超过上限
- v3 缺少此类保护，存在资源耗尽风险

---

## 4. 安全机制评估

### 4.1 现有防护措施

| 防护 | 实现位置 | 效果 |
|------|---------|------|
| **nullptr 检查** | 行 74-77 | 防止空指针访问，但无助于限制大小 |
| **负值检查** | 行 79-81 | 仅检查 >= 0，允许任意大的正整数 |
| **std::nothrow** | 行 165 | 防止异常抛出，分配失败返回 nullptr |
| **nullptr 返回检查** | 行 166-170 | 检测分配失败，返回错误码 |

### 4.2 缺失的防护

| 缺失防护 | 风险 |
|---------|------|
| **上限验证** | 允许任意大的分配请求 |
| **内存容量检查** | 不检查系统可用内存 |
| **合理值约束** | 无业务逻辑相关的合理性检查 |
| **资源限制** | 无算子级别的资源配额限制 |

### 4.3 安全机制无法阻止攻击的原因

虽然存在 `std::nothrow` 和 nullptr 检查，但这些机制：
1. **仅处理失败后的恢复**，而非预防攻击
2. **无法阻止资源耗尽** - 大量分配请求仍会消耗内存
3. **不提供早期拒绝** - 恶意请求仍会进入分配阶段
4. **依赖系统内存管理** - 系统层面可能已经受损

---

## 5. PoC 构造思路

### 5.1 PoC 设计

```cpp
// PoC 概念代码
void PoC_ResourceExhaustion_NMS_V3() {
    // 1. 准备正常 boxes 和 scores (绕过 shape 验证)
    float boxes[5 * 4] = {...};  // [5, 4] shape, 正常数据
    float scores[5] = {...};     // [5] shape, 正常数据
    
    // 2. 构造恶意 max_output_size
    int32_t malicious_size = 2147483647;  // INT32_MAX
    
    // 3. 构造正常 threshold (绕过 threshold 验证)
    float iou_threshold = 0.5f;   // 在 [0, 1] 范围内
    float score_threshold = 0.1f; // 正常值
    
    // 4. 调用 NMS v3 kernel
    // 将触发约 8GB 内存分配请求
    CpuKernelContext ctx;
    ctx.SetInput(0, boxes, {5, 4}, DT_FLOAT);
    ctx.SetInput(1, scores, {5}, DT_FLOAT);
    ctx.SetInput(2, &malicious_size, {1}, DT_INT32);  // 恶意输入!
    ctx.SetInput(3, &iou_threshold, {1}, DT_FLOAT);
    ctx.SetInput(4, &score_threshold, {1}, DT_FLOAT);
    
    NonMaxSuppressionV3CpuKernel kernel;
    kernel.Compute(ctx);  // 触发内存分配失败或耗尽
}
```

### 5.2 验证步骤

1. **构造恶意输入**: 设置 `max_output_size = INT32_MAX`
2. **观察内存使用**: 使用系统监控工具观察内存消耗
3. **验证失败响应**: 期望返回 `KERNEL_STATUS_INNER_ERROR`
4. **测试并发场景**: 多线程并发调用，观察系统稳定性

---

## 6. 影响范围评估

### 6.1 直接影响

| 影响对象 | 影响 |
|---------|------|
| **系统稳定性** | 内存耗尽导致系统不稳定 |
| **服务可用性** | AI 服务拒绝服务 |
| **并发进程** | 其他进程无法分配内存 |
| **用户体验** | 应用崩溃或功能降级 |

### 6.2 间接影响

- **资源竞争**: 导致其他算子执行失败
- **系统性能**: 内存分配失败增加系统负载
- **安全边界**: 可作为其他攻击的前置条件

### 6.3 受影响场景

| 场景 | 风险等级 |
|------|---------|
| **嵌入式/边缘设备** | Critical - 内存有限，极易耗尽 |
| **多租户云环境** | High - 影响其他租户 |
| **生产推理服务** | High - 影响服务可用性 |
| **开发测试环境** | Medium - 影响有限 |

---

## 7. 修复建议

### 7.1 立即修复方案

```cpp
// 在 non_max_suppression_v3_aicpu.cpp 中添加上限验证
// 参考 v6 版本的 MAX_VALID_OUTPUT 实现

// 添加常量定义 (建议放在头文件或文件开头)
static constexpr int32_t MAX_VALID_OUTPUT_SIZE = 700;  // 或根据业务需求调整

// 在 GetInputAndCheck 函数中添加上限验证 (行 78-81 之后)
max_output_size_ = *static_cast<int32_t *>(max_output_size_tensor->GetData());
KERNEL_CHECK_FALSE((max_output_size_ >= 0), KERNEL_STATUS_PARAM_INVALID,
                   "max_output_size must be non-negative, but are [%d]",
                   max_output_size_);
// 新增上限验证!
KERNEL_CHECK_FALSE((max_output_size_ <= MAX_VALID_OUTPUT_SIZE), KERNEL_STATUS_PARAM_INVALID,
                   "max_output_size must be <= %d, but are [%d]",
                   MAX_VALID_OUTPUT_SIZE, max_output_size_);
```

### 7.2 增强修复方案

```cpp
// 更全面的修复: 考虑 num_boxes_ 约束
// max_output_size 应合理限制在 num_boxes_ 范围内

// 在 DoCompute 中使用实际需要的分配大小
int32_t actual_max_output = std::min(max_output_size_, 
                                     static_cast<int32_t>(num_boxes_));
actual_max_output = std::min(actual_max_output, MAX_VALID_OUTPUT_SIZE);

std::unique_ptr<int32_t[]> indices_data(new (std::nothrow) int32_t[actual_max_output]);
```

### 7.3 配套措施

1. **文档更新**: 在 README.md 中说明 max_output_size 的有效范围
2. **测试补充**: 添加边界值测试 (INT32_MAX, 负值, 上限+1)
3. **日志增强**: 记录接近上限的输入值，便于审计
4. **资源监控**: 在算子级别添加资源配额限制

---

## 8. 修复优先级

| 维度 | 评估 |
|------|------|
| **安全风险** | High - DoS 攻击可影响系统稳定性 |
| **修复难度** | Low - 单一位置添加上限验证 |
| **影响范围** | Medium - 仅影响 NMS v3 算子 |
| **现有参考** | High - v6 版本已有安全实现可参考 |

**推荐优先级**: **P1 (高优先级)**

理由:
- 漏洞可直接利用，无需复杂前置条件
- 修复简单，可快速实施
- v6 版本提供了成熟的参考实现
- 可能影响生产环境服务可用性

---

## 9. 结论

### 9.1 漏洞判定

**这是一个真实的安全漏洞**

依据:
1. **用户可控输入**: `max_output_size` 来自用户提供的 Tensor
2. **验证不足**: 仅检查 `>= 0`，缺少上限约束
3. **危险操作**: 直接用于动态内存分配
4. **对比证据**: v6 版本有明确的 `MAX_VALID_OUTPUT = 700` 保护
5. **攻击可行**: 可构造恶意输入触发内存耗尽

### 9.2 漏洞分类

- **类型**: CWE-190 (Integer Overflow or Wraparound) → 资源耗尽
- **严重性**: High
- **可利用性**: 高 - 无需特殊权限或复杂条件
- **修复难度**: 低 - 参考现有安全实现

---

## 10. 参考资料

- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- v6 安全实现: `objdetect/non_max_suppression_v6/op_host/op_api/aclnn_non_max_suppression.cpp`
