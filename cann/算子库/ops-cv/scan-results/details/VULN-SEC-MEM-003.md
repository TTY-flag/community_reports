# VULN-SEC-MEM-003：NMS算子内存分配失控漏洞

## 漏洞概要

| 字段 | 值 |
|-------|-------|
| **ID** | VULN-SEC-MEM-003 |
| **类型** | 整数溢出 / 资源耗尽 |
| **CWE** | CWE-190 (整数溢出或回绕), CWE-787 (越界写入) |
| **严重级别** | 高 (High) |
| **受影响文件** | `image/non_max_suppression_v3/op_kernel_aicpu/non_max_suppression_v3_aicpu.cpp` |
| **受影响行号** | 52, 154-157 |
| **受影响函数** | `NonMaxSuppressionV3CpuKernel::GetInputAndCheck`, `NonMaxSuppressionV3CpuKernel::DoCompute` |

## 漏洞描述

Non-Max Suppression V3 AICPU内核接受用户可控的tensor形状而无上限验证。从 `boxes_shape->GetDimSize(0)` 获取的 `num_boxes_` 值直接用于多个内存密集型操作而无大小限制，创建了资源耗尽攻击向量。

### 数据流分析

```
用户输入Tensor形状 (boxes)
    ↓
boxes_shape->GetDimSize(0)  [第39, 52行]
    ↓
num_boxes_ (int64_t)  [第52行, 头文件第42行]
    ↓
┌─────────────────────────────────────────────────────────────┐
│ 路径1：Eigen::TensorMap构造（第154-155行）                    │
│   Eigen::TensorMap<T, 2>(boxes_->GetData(), num_boxes_, 4) │
│   → 创建映射 num_boxes_ * 4 元素的视图                        │
│   → 无分配，但创建错误维度映射                                 │
│   → 如果boxes_数据不足可能缓冲区越界读取                        │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ 路径2：std::vector分配（第156行）                             │
│   std::vector<T> scores_data(num_boxes_);                   │
│   → 分配 num_boxes_ * sizeof(T) bytes                        │
│   → sizeof(float) = 4 bytes, sizeof(float16) = 2 bytes      │
│   → 大num_boxes_值导致内存耗尽                                 │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ 路径3：std::copy_n操作（第157-158行）                         │
│   std::copy_n(scores_->GetData(), num_boxes_, ...)         │
│   → 从scores tensor读取num_boxes_个元素                      │
│   → 如果scores tensor大小不足则缓冲区越界读取                  │
└─────────────────────────────────────────────────────────────┘
```

### 代码证据

**第52行 - num_boxes_无边界检查：**
```cpp
num_boxes_ = boxes_shape->GetDimSize(0);
// 无验证：num_boxes_ 可以是来自用户输入的任意 int64_t 值
```

**第154-157行 - 内存操作直接使用：**
```cpp
template <typename T, typename T_threshold>
uint32_t NonMaxSuppressionV3CpuKernel::DoCompute() {
  Eigen::TensorMap<Eigen::Tensor<T, Two, Eigen::RowMajor>> boxes_map(
      reinterpret_cast<T *>(boxes_->GetData()), num_boxes_, 4);  // num_boxes_ * 4 映射
  std::vector<T> scores_data(num_boxes_);  // 无大小限制分配
  std::copy_n(reinterpret_cast<T *>(scores_->GetData()), num_boxes_,
              scores_data.begin());  // 无边界检查复制
```

## 攻击场景分析

### 场景1：内存耗尽攻击

**攻击向量：** 恶意用户提供具有极大第一维度的boxes tensor。

**触发条件：**
```python
# 恶意输入构造示例
import numpy as np

# 创建导致内存耗尽的boxes tensor维度
num_boxes_malicious = 2**30  # 1073741824 boxes
boxes_shape = (num_boxes_malicious, 4)  # 形状：[1073741824, 4]

# 这触发：
# 1. scores_data分配：1073741824 * 4 bytes = 4 GB 对于float
# 2. 对于更大值如 2**31：8 GB 分配
# 3. 理论最大：2**62 * 4 = 天文数字（会抛出bad_alloc）
```

**攻击步骤：**
1. 用户构造包含NonMaxSuppressionV3节点的模型
2. 用户提供形状为 `[HUGE_NUMBER, 4]` 的boxes tensor
3. 内核提取 `num_boxes_ = HUGE_NUMBER` 而无验证
4. `std::vector<T> scores_data(num_boxes_)` 尝试分配巨大内存
5. 系统内存耗尽 → OOM → 内核崩溃 → 潜在拒绝服务

### 场景2：Eigen TensorMap维度整数溢出

**攻击向量：** tensor维度的乘法 `num_boxes_ * 4`。

**触发条件：**
```cpp
// 如果 num_boxes_ = SIZE_MAX/4 + 1 (64位: 2^62 + 1)
// num_boxes_ * 4 回绕或超出最大值
// 这创建无效tensor映射
```

**注意：** Eigen::TensorMap本身不分配内存，但错误维度结合后续tensor访问（如第212行的 `boxes_map(next_candidate.box_index, 0)`）可能导致越界内存访问。

### 场景3：通过std::copy_n缓冲区越界读取

**攻击向量：** 声明形状与实际tensor数据大小不匹配。

**触发条件：**
```python
# 创建大小不足的scores tensor
# 声明形状为 [1000000] 但只分配最小数据
scores_shape = (1000000,)  # 声明形状
scores_data_actual_size = 100  # 实际数据大小不匹配

# std::copy_n 将从大小不足的缓冲区读取1000000个元素
# → 越界读取 → 信息泄露或崩溃
```

## 可利用性评估

### 可行性：高

1. **用户可控输入：** Tensor形状在ML模型推理中直接由用户代码提供
2. **无验证：** 代码对 `num_boxes_` 无上限检查
3. **直接影响：** 内存分配在内核执行中立即发生
4. **AI芯片上下文：** NPU/AICPU内核在设备内存上下文中运行；耗尽可影响整个设备

### 利用障碍

| 障碍 | 状态 | 分析 |
|---------|--------|----------|
| 框架层大小验证 | **不存在** | infershape.cpp无验证（文件最小/空） |
| AICPU内存分配限制 | **未知** | 代码库中未发现此模式的显式限制 |
| std::vector溢出保护 | **部分** | std::vector对不可能大小抛出std::bad_alloc，但内核上下文可能导致崩溃 |
| 输入tensor大小验证 | **不存在** | 无检查实际tensor数据大小与声明形状匹配 |

### 概念验证构造方法

```python
# 内存耗尽PoC结构
import torch
import torch_npu  # 假设CANN集成

def create_nms_exhaustion_attack():
    # 最大安全值：取决于可用设备内存
    # 对于4GB设备内存，num_boxes ~ 500M 对于float
    # 对于更大设备，值可以更高
    
    # 创建可疑大形状的tensors
    num_boxes_exploit = 10**9  # 10亿 - 可能超出可用内存
    
    boxes = torch.randn(num_boxes_exploit, 4, dtype=torch.float32)
    scores = torch.randn(num_boxes_exploit, dtype=torch.float32)
    max_output_size = torch.tensor(100, dtype=torch.int32)
    iou_threshold = torch.tensor(0.5, dtype=torch.float32)
    score_threshold = torch.tensor(0.1, dtype=torch.float32)
    
    # 调用NonMaxSuppressionV3
    # 这触发scores_data vector分配中的内存耗尽
    result = torch.ops.npu.non_max_suppression_v3(
        boxes, scores, max_output_size, iou_threshold, score_threshold
    )
    # 预期：OOM错误，内核崩溃，或设备重置

# 替代PoC：形状-数据不匹配导致缓冲区越界读取
def create_nms_buffer_overread():
    # 这需要操纵tensor元数据与实际分配
    # 可能需要低级tensor操作或自定义图构造
    pass
```

## 影响评估

### 主要影响：资源耗尽 / 拒绝服务

- **内存耗尽：** 大 `num_boxes_` 值导致大量内存分配
- **NPU设备崩溃：** AICPU内核失败可影响整个NPU设备
- **服务中断：** 模型推理管道崩溃

### 次要影响：越界读取

- **信息泄露：** `std::copy_n` 或 `boxes_map` 访问中的缓冲区越界读取可能暴露内存内容
- **内核不稳定：** 无效tensor维度导致未定义行为

### 受影响范围

- 所有使用NonMaxSuppressionV3算子的用户
- 使用目标检测管道的模型
- NPU硬件上的生产推理服务

## 与类似算子比较

| 算子 | 大小限制 | 位置 |
|----------|------------|----------|
| NonMaxSuppressionV6 | `MAX_VALID_OUTPUT = 700` | `aclnn_non_max_suppression.cpp:35` |
| RoiPoolingWithArgMax | `BATCH_SIZE_MAX_LIMIT = 1024` | `roi_pooling_with_arg_max_infershape.cpp:43` |
| RoiPoolingGradWithArgMax | `BATCH_SIZE_MAX_LIMIT = 1024` | `roi_pooling_grad_with_arg_max_infershape.cpp:30` |
| **NonMaxSuppressionV3** | **无限制** | **漏洞** |

这表明大小限制在此代码库中是标准做法，但NMS v3缺乏它们。

## 安全机制评估

### 现有检查（NMS V3）

| 检查 | 存在 | 位置 |
|-------|---------|----------|
| 输入空指针检查 | ✓ | 第36-38, 57-59行等 |
| Tensor形状空检查 | ✓ | 第39-41, 60-62行 |
| 秩验证（boxes必须是2D） | ✓ | 第45行 |
| 列验证（boxes必须有4列） | ✓ | 第45行 |
| Scores-boxes长度匹配 | ✓ | 第68-70行 |
| max_output_size >= 0 | ✓ | 第79-81行 |
| iou_threshold范围 [0, 1] | ✓ | 第171-177行 |
| dtype验证 | ✓ | 第104-115行 |
| **num_boxes_上限** | ✗ **缺失** | **漏洞** |

### 什么会阻止此攻击？

1. **框架层形状验证** - infershape.cpp中不存在
2. **Tensor大小与声明形状验证** - 代码库中未发现
3. **AICPU运行时内存分配限制** - 未知；可能存在但未文档化
4. **设备内存限制** - 会导致分配失败，但崩溃仍是影响

## 修复建议

### 修复1：在GetInputAndCheck中添加上限验证

```cpp
// 添加到 non_max_suppression_v3_aicpu.cpp 第52行后
constexpr int64_t kMaxNumBoxes = 1000000;  // 100万合理限制

num_boxes_ = boxes_shape->GetDimSize(0);
KERNEL_CHECK_FALSE((num_boxes_ > 0), KERNEL_STATUS_PARAM_INVALID,
                   "num_boxes must be positive, but got [%ld].", num_boxes_);
KERNEL_CHECK_FALSE((num_boxes_ <= kMaxNumBoxes), KERNEL_STATUS_PARAM_INVALID,
                   "num_boxes [%ld] exceeds maximum limit [%ld].",
                   num_boxes_, kMaxNumBoxes);
```

### 修复2：添加内存大小验证

```cpp
// 在DoCompute中，vector分配前
constexpr size_t kMaxVectorSizeBytes = 256 * 1024 * 1024;  // 256 MB限制
size_t required_memory = static_cast<size_t>(num_boxes_) * sizeof(T);
KERNEL_CHECK_FALSE((required_memory <= kMaxVectorSizeBytes),
                   KERNEL_STATUS_PARAM_INVALID,
                   "scores_data allocation size [%zu] exceeds limit [%zu].",
                   required_memory, kMaxVectorSizeBytes);
```

### 修复3：添加infershape验证

```cpp
// 添加到 non_max_suppression_v3_infershape.cpp
static constexpr int64_t kMaxNumBoxes = 1000000;

// 在推导形状阶段验证boxes形状
if (boxes_shape->GetDim(0) > kMaxNumBoxes) {
    OP_LOGE("NonMaxSuppressionV3", "boxes shape dim0 [%ld] exceeds limit [%ld].",
            boxes_shape->GetDim(0), kMaxNumBoxes);
    return ge::GRAPH_FAILED;
}
```

## 修复优先级：高

此漏洞允许：
1. 无特权用户导致NPU设备崩溃
2. 生产推理服务中的拒绝服务
3. 通过缓冲区越界读取潜在信息泄露

**建议行动：** 在下次发布前实现 `num_boxes_` 上限验证。

## 参考资料

- CWE-190: 整数溢出或回绕
- CWE-787: 越界写入
- CWE-400: 未控制资源消耗
- TensorFlow NonMaxSuppressionV3实现（有类似验证模式）