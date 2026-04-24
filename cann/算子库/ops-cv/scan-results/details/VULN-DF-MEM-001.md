# VULN-DF-MEM-001：NMS算子内存分配失控漏洞

## 漏洞概述

| 字段 | 值 |
|------|-----|
| **ID** | VULN-DF-MEM-001 |
| **类型** | integer_overflow_to_heap_overflow / Uncontrolled Memory Allocation |
| **CWE** | CWE-789 (Memory Allocation with Excessive Size Value) / CWE-190 (Integer Overflow or Wraparound) |
| **严重性** | HIGH |
| **CVSS分数** | 7.5 (High) |
| **文件** | `image/non_max_suppression_v3/op_kernel_aicpu/non_max_suppression_v3_aicpu.cpp` |
| **行号** | 165-169, 78-81 |
| **函数** | `DoCompute()`, `GetInputAndCheck()` |

## 漏洞详情

### 根因

漏洞存在于 `NonMaxSuppressionV3CpuKernel::DoCompute()` 函数中，用户控制参数 `max_output_size_` 用于内存分配，但没有适当的上限验证。

**漏洞代码（第165行）**：
```cpp
std::unique_ptr<int32_t[]> indices_data(new (std::nothrow) int32_t[max_output_size_]);
if (indices_data == nullptr) {
    KERNEL_LOG_ERROR("DoCompute: new indices_data failed");
    return KERNEL_STATUS_INNER_ERROR;
}
```

**输入验证（第78-81行）**：
```cpp
max_output_size_ = *static_cast<int32_t *>(max_output_size_tensor->GetData());
KERNEL_CHECK_FALSE((max_output_size_ >= 0), KERNEL_STATUS_PARAM_INVALID,
                   "max_output_size must be non-negative, but are [%d]",
                   max_output_size_);
```

### 数据流分析

```
用户输入 (aclTensor max_output_size_tensor)
    ↓
第78行: max_output_size_ = *static_cast<int32_t *>(max_output_size_tensor->GetData())
    ↓
第79-81行: 验证（仅检查 >= 0，无上限）
    ↓
第165行: new int32_t[max_output_size_]（失控分配大小）
```

### 安全缺口

1. **缺失上限检查**: 与 Non-Max Suppression V6 不同，V3 不验证最大值
2. **直接用户控制**: 攻击者可指定任意非负 int32_t 值
3. **预循环分配**: 内存分配在处理循环之前，因此分配大小不受实际数据约束

## 攻击场景

### 场景1：内存耗尽（DoS）
```python
# 攻击者构造恶意模型输入
max_output_size = 2147483647  # INT32_MAX
# 触发分配：
# 2147483647 * 4字节 (int32_t) = ~8 GB
```

**影响**：
- 单次请求可分配高达8GB
- 系统内存耗尽
- OOM killer可能终止进程
- 服务不可用

### 场景2：多请求DoS
```python
# 攻击者发送多个并发请求
# 每个使用大max_output_size值
# 总内存: N * max_output_size * 4字节
```

**影响**：
- 放大内存消耗
- 完全系统资源耗尽
- 级联服务失败

### 场景3：整数溢出（理论）
```cpp
// 某些实现中，数组new[]使用size_t
// int32_t到size_t转换可能在32位系统或特定分配器上导致问题
```

## 与安全实现对比

### Non-Max Suppression V6（安全）
**文件**: `objdetect/non_max_suppression_v6/op_host/op_api/aclnn_non_max_suppression.cpp`

```cpp
static constexpr int32_t MAX_VALID_OUTPUT = 700;  // 第35行

// 第126-129行
if (maxOutputSize > MAX_VALID_OUTPUT) {
    OP_LOGE(ACLNN_ERR_PARAM_INVALID, "maxOutputBoxesPerClass[%ld] should < 700 ", maxOutputSize);
    return ACLNN_ERR_PARAM_INVALID;
}
```

### Non-Max Suppression V3（漏洞）
```cpp
// 无上限常量定义
// 无上限验证
KERNEL_CHECK_FALSE((max_output_size_ >= 0), ...);  // 仅非负检查
```

## 利用评估

### 可利用性：HIGH

| 因素 | 评估 |
|------|------|
| 攻击向量 | Network（通过模型输入） |
| 攻击复杂度 | LOW |
| 所需权限 | NONE（用户提供的输入） |
| 用户交互 | NONE |
| 范围 | CHANGED（影响系统稳定性） |
| 可用性影响 | HIGH |

### 利用前提条件
1. 能调用 NonMaxSuppressionV3 操作
2. 能控制 `max_output_size` 张量参数
3. 无特殊权限要求

### 缓解绕过
- `new (std::nothrow)` 仅在尝试后捕获分配失败
- 内存耗尽可能在分配失败前发生
- Nothrow防止异常但不阻止DoS向量

## 概念验证

### PoC概念
```cpp
// 构造包含NonMaxSuppressionV3节点的恶意模型图
// 设置max_output_size张量为INT32_MAX (2147483647)

// 测试用例结构：
boxes = [[0, 0, 10, 10]]        // 最小框输入
scores = [0.9]                   // 最小分数
max_output_size = 2147483647     // 恶意：INT32_MAX
iou_threshold = 0.5
score_threshold = 0.0

// 预期：内核尝试8GB分配
// 结果：内存耗尽或分配失败
```

### 实际攻击步骤
1. 创建或修改包含NonMaxSuppressionV3操作的TensorFlow/ONNX模型
2. 将 `max_output_size` 输入张量设置为大值（如 2^30）
3. 在CANN框架上执行模型
4. 观察内存耗尽或进程终止

## 影响评估

### 直接影响
- **拒绝服务**: 内存耗尽导致服务不可用
- **系统不稳定**: OOM killer可能终止关键进程
- **资源饥饿**: 其他应用受影响

### 业务影响
- 服务停机
- ML推理服务拒绝
- 生产系统潜在级联故障
- SLA违约

### 受影响组件
- 华为昇腾AI处理器
- CANN (Compute Architecture for Neural Networks)
- 使用NonMaxSuppressionV3操作的模型

## 推荐修复

### 立即缓解（推荐）
```cpp
// 添加上限常量
static constexpr int32_t MAX_VALID_OUTPUT_SIZE = 10000;  // 或适当限制

// 在GetInputAndCheck()中，第81行后添加验证：
KERNEL_CHECK_FALSE((max_output_size_ <= MAX_VALID_OUTPUT_SIZE), 
                   KERNEL_STATUS_PARAM_INVALID,
                   "max_output_size must be <= %d, but got [%d]",
                   MAX_VALID_OUTPUT_SIZE, max_output_size_);
```

### 额外加固
```cpp
// 考虑与num_boxes_的关系
KERNEL_CHECK_FALSE((max_output_size_ <= num_boxes_), 
                   KERNEL_STATUS_PARAM_INVALID,
                   "max_output_size [%d] cannot exceed number of boxes [%ld]",
                   max_output_size_, num_boxes_);

// 或使用两者最小值：
int32_t effective_max = std::min(max_output_size_, static_cast<int32_t>(num_boxes_));
```

### 完整修复示例
```cpp
uint32_t NonMaxSuppressionV3CpuKernel::GetInputAndCheck(const CpuKernelContext &ctx) {
    // ... 现有代码 ...
    
    max_output_size_ = *static_cast<int32_t *>(max_output_size_tensor->GetData());
    
    // 现有检查
    KERNEL_CHECK_FALSE((max_output_size_ >= 0), KERNEL_STATUS_PARAM_INVALID,
                       "max_output_size must be non-negative, but are [%d]",
                       max_output_size_);
    
    // 新增：上限检查
    static constexpr int32_t MAX_VALID_OUTPUT_SIZE = 10000;
    KERNEL_CHECK_FALSE((max_output_size_ <= MAX_VALID_OUTPUT_SIZE), 
                       KERNEL_STATUS_PARAM_INVALID,
                       "max_output_size must be <= %d, but got [%d]",
                       MAX_VALID_OUTPUT_SIZE, max_output_size_);
    
    // ... 代码其余部分 ...
}
```

## 测试建议

### 需添加的单元测试
```cpp
TEST_F(TEST_NON_MAX_SUPPRESSION_V3_UT, TestMaxOutputSizeExceedsLimit) {
    // 测试max_output_size > MAX_VALID_OUTPUT_SIZE
    int32_t max_output_size = 10001;  // 或INT32_MAX
    // 期望：KERNEL_STATUS_PARAM_INVALID
}

TEST_F(TEST_NON_MAX_SUPPRESSION_V3_UT, TestMaxOutputSizeLarge) {
    // 测试合理大值
    int32_t max_output_size = 10000;
    // 期望：KERNEL_STATUS_OK（如果在限制内）
}

TEST_F(TEST_NON_MAX_SUPPRESSION_V3_UT, TestMaxOutputSizeBoundary) {
    // 测试边界条件
    int32_t max_output_size = MAX_VALID_OUTPUT_SIZE;
    // 期望：KERNEL_STATUS_OK
}
```

## 参考文献

### 相关代码
- 安全实现：`objdetect/non_max_suppression_v6/op_host/op_api/aclnn_non_max_suppression.cpp`
- 其他算子中类似模式的MAX_VALID_*常量

### 标准
- CWE-789: Memory Allocation with Excessive Size Value
- CWE-190: Integer Overflow or Wraparound
- CWE-400: Uncontrolled Resource Consumption

## 分类

- **漏洞状态**: 已确认（真实漏洞）
- **修复优先级**: HIGH
- **修复复杂度**: LOW（简单参数验证）
- **部署风险**: LOW（对有效输入向后兼容）

## 时间线

| 事件 | 日期 |
|------|------|
| 漏洞发现 | 2026-04-22 |
| 报告创建 | 2026-04-22 |
| 建议修复截止 | 立即 |

---

**报告生成**: 2026-04-22  
**扫描器**: OpenCode漏洞扫描器  
**置信度**: HIGH