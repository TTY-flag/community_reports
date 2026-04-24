# VULN-SEC-MEM-006：缩放平移算子整数溢出漏洞

## 漏洞摘要

**状态**: 已确认真实漏洞

**严重性**: High

**CWE分类**: CWE-190 (Integer Overflow or Wraparound), CWE-400 (Uncontrolled Resource Consumption)

**漏洞类型**: 内存耗尽 / 拒绝服务

---

## 漏洞详情

### 位置
- **文件**: `image/scale_and_translate/op_kernel_aicpu/scale_and_translate_aicpu.cpp`
- **函数**: `InitSpans()` (第149-165行) 和 `ScaleAndTranslateCompute()` (第359行)
- **行号**: 158-163 (主要), 359 (次要)

### 漏洞代码

```cpp
// 第148-165行: InitSpans函数
template <typename Kernel>
uint32_t InitSpans(const Kernel &kernel, int64_t output_size,
                   int64_t input_size, bool antialias, float inv_scale,
                   Spans *spans, float &kernel_scale)
{
    kernel_scale = antialias ? std::max(inv_scale, 1.0f) : 1.0f;
    spans->span_size = std::min(
        2 * static_cast<int>(std::ceil(kernel.Radius() * kernel_scale)) + 1,
        static_cast<int>(input_size));

    // 漏洞点: 对output_size无上限验证的内存分配
    spans->starts = new (std::nothrow) Eigen::Tensor<int32_t, 1>(output_size);
    KERNEL_CHECK_NULLPTR(spans->starts, KERNEL_STATUS_PARAM_INVALID,
                         "New spans starts failed.")
    spans->weights = new (std::nothrow) Eigen::Tensor<float, 1>(spans->span_size * output_size);
    KERNEL_CHECK_NULLPTR(spans->weights, KERNEL_STATUS_PARAM_INVALID,
                         "New spans weights failed.")
    return KERNEL_STATUS_OK;
}

// 第359行: 额外的漏洞分配点
Eigen::Tensor<float, 4> intermediate_tensor_middle(p.batch_size, p.output_height,
                                                   p.input_width, p.channels);
```

### 数据流

```
用户输入 (Input(1)张量) 
    │
    ▼
第289行: input_size = ctx.Input(1)->GetData()
    │
    ▼
第300-301行: 
    p.output_height = input_size[0];
    p.output_width = input_size[1];
    │
    ▼
[无上限验证]
    │
    ▼
第352行: ComputeSpans(..., p.output_width, ...)
第356行: ComputeSpans(..., p.output_height, ...)
    │
    ▼
第175行: InitSpans(..., output_size, ...)
    │
    ▼
第158、161行: 基于用户控制值的大内存分配
```

---

## 利用分析

### 攻击向量

攻击者控制 `size` 输入张量 (Input 1)，它直接指定 `output_height` 和 `output_width`。这些值用于内存分配，没有任何上限验证。

### 触发条件

1. **攻击者提供恶意 `size` 张量**，包含极大值（如 `INT32_MAX = 2,147,483,647`）
2. **内核处理输入**并尝试分配：
   - `spans->starts`: `output_size * sizeof(int32_t)` 字节
   - `spans->weights`: `span_size * output_size * sizeof(float)` 字节
   - `intermediate_tensor_middle`: `batch_size * output_height * input_width * channels * sizeof(float)` 字节

### 具体攻击场景

```python
# 恶意输入构造
import numpy as np

# Input 0: 小图像（对攻击不重要）
images = np.zeros((1, 10, 10, 3), dtype=np.float32)

# Input 1: 恶意size张量 - 关键攻击向量
# 使用INT32_MAX最大化内存消耗
size = np.array([2147483647, 2147483647], dtype=np.int32)  # 两个维度都用INT32_MAX

# Input 2 & 3: 有效scale和translation
scale = np.array([1.0, 1.0], dtype=np.float32)
translation = np.array([0.0, 0.0], dtype=np.float32)

# 当此操作执行时:
# 内存分配尝试:
# - spans->starts (height): 2147483647 * 4字节 = ~8.6 GB
# - spans->starts (width): 2147483647 * 4字节 = ~8.6 GB  
# - spans->weights (height): span_size * 2147483647 * 4字节 = 可能100+ GB
# - spans->weights (width): span_size * 2147483647 * 4字节 = 可能100+ GB
# - intermediate_tensor_middle: batch * 2147483647 * width * channels * 4字节
```

### 内存影响计算

对于 `output_height = output_width = INT32_MAX` 的攻击：

| 分配 | 大小公式 | 约大小 |
|------|----------|--------|
| spans->starts (行) | `output_height * sizeof(int32_t)` | ~8.6 GB |
| spans->starts (列) | `output_width * sizeof(int32_t)` | ~8.6 GB |
| spans->weights (行) | `span_size * output_height * sizeof(float)` | 取决于span（巨大） |
| spans->weights (列) | `span_size * output_width * sizeof(float)` | 取决于span（巨大） |
| intermediate_tensor | `batch * output_height * input_width * channels * sizeof(float)` | 可能达到EB级别 |

典型 span_size 值（如常见内核为5-15），仅 `spans->weights` 就会尝试分配：
- `5 * 2,147,483,647 * 4` = ~43 GB 每次调用

### 整数溢出风险

额外关注：第161行的乘法 `span_size * output_size`：

```cpp
spans->weights = new (std::nothrow) Eigen::Tensor<float, 1>(spans->span_size * output_size);
```

如果 `span_size * output_size` 溢出 `int64_t`，分配大小可能回绕到较小值，后续访问张量时可能导致堆缓冲区溢出。

---

## 根因分析

### 缺失的验证

代码仅执行**正值检查**但缺少**上限验证**：

```cpp
// 第308-311行: 仅检查正值
KERNEL_CHECK_FALSE(
    (p.output_height > 0 && p.output_width > 0), KERNEL_STATUS_PARAM_INVALID,
    "output_height = [%d] and output_width = [%d] must be positive",
    p.output_height, p.output_width)
```

**无检查项：**
1. `output_height` / `output_width` 最大允许值
2. 最大总输出大小 (`output_height * output_width`)
3. 大小计算中的整数溢出
4. 最大内存分配大小

### 现有缓解措施（不足）

1. **`std::nothrow` 分配**: 失败时返回 nullptr 但无法阻止内存耗尽攻击
2. **`KERNEL_CHECK_NULLPTR`**: 检查分配结果但攻击在此检查前已成功

---

## 影响评估

### 严重性: High

| 影响类别 | 评估 |
|----------|------|
| **可用性** | Critical - 可导致系统级内存耗尽 |
| **完整性** | None - 只读损坏风险 |
| **机密性** | None - 无数据泄露 |

### 受影响组件

1. **Scale and Translate AICPU Kernel** - 主要目标
2. **系统内存** - 受攻击资源
3. **其他系统进程** - 通过OOM造成连带损害

### 攻击前提条件

1. 能调用 `ScaleAndTranslate` 操作
2. 能控制 `size` 输入张量 (Input 1)
3. 无额外权限要求

---

## 概念验证

### PoC张量构造

```cpp
// 用于模型构造的C++ PoC
// 输入形状
std::vector<int64_t> image_shape = {1, 10, 10, 3};  // 最小输入
std::vector<int64_t> size_shape = {2};               // Size张量

// 恶意size张量
int32_t size_data[2] = {
    2147483647,  // INT32_MAX用于output_height
    2147483647   // INT32_MAX用于output_width
};

// 正常scale和translation
float scale_data[2] = {1.0f, 1.0f};
float translate_data[2] = {0.0f, 0.0f};

// 当内核执行时:
// 内存分配将尝试 ~8.6GB + ~8.6GB + 更多
// 系统可能崩溃或变得无响应
```

### 预期行为

1. **资源受限系统**: 进程被OOM killer终止
2. **高内存系统**: 极端内存消耗，潜在系统不稳定
3. **容器化环境**: 容器OOM，可能的节点级影响

---

## 修复建议

### 立即修复

为输出维度添加上限验证：

```cpp
// 推荐最大值（根据用例调整）
constexpr int64_t kMaxOutputDimension = 65536;  // 64K
constexpr int64_t kMaxOutputSize = 4294967296;  // 4GB总元素

// 在ParseScaleAndTranslateParams()中添加验证
KERNEL_CHECK_FALSE(
    (p.output_height <= kMaxOutputDimension && p.output_width <= kMaxOutputDimension),
    KERNEL_STATUS_PARAM_INVALID,
    "output_height = [%d] and output_width = [%d] exceed maximum allowed dimension [%d]",
    p.output_height, p.output_width, kMaxOutputDimension)

// 检查总输出大小的溢出
int64_t total_output_size = p.output_height * p.output_width;
KERNEL_CHECK_FALSE(
    (total_output_size > 0 && total_output_size <= kMaxOutputSize),
    KERNEL_STATUS_PARAM_INVALID,
    "Total output size [%d] exceeds maximum allowed [%d]",
    total_output_size, kMaxOutputSize)

// 检查span_size * output_size计算的整数溢出
int64_t weights_size = static_cast<int64_t>(spans->span_size) * output_size;
KERNEL_CHECK_FALSE(
    (weights_size > 0 && weights_size <= kMaxOutputSize),
    KERNEL_STATUS_PARAM_INVALID,
    "Weights size calculation overflow or too large")
```

### 深度防御

1. **输入验证**: 验证所有用户控制的张量值
2. **资源限制**: 实现每操作内存配额
3. **分配器限制**: 使用能优雅失败的有限分配器
4. **日志记录**: 记录可疑输入模式用于监控

---

## 验证

### 手动验证步骤

1. 用PoC输入编译内核
2. 执行期间监控内存使用
3. 观察分配失败或系统影响

### 测试用例

```cpp
// 负面测试用例 - 应验证失败
TEST(ScaleAndTranslateSecurity, LargeOutputSize) {
    int32_t malicious_size[2] = {2147483647, 2147483647};
    // 修复后预期KERNEL_STATUS_PARAM_INVALID
}

// 边界测试用例
TEST(ScaleAndTranslateSecurity, MaxValidOutputSize) {
    int32_t max_size[2] = {65536, 65536};  // 在边界
    // 根据可用内存应成功或优雅失败
}
```

---

## 相关漏洞

此模式可能存在于接受用户控制大小参数的其他图像处理内核中。建议审计：

1. 所有 `Scale*` 系列操作
2. 所有 `Resize*` 系列操作  
3. 所有 `Crop*` 系列操作
4. 任何接受维度张量的操作

---

## 参考文献

- CWE-190: Integer Overflow or Wraparound
- CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')
- CWE-789: Memory Allocation with Excessive Size Value

---

## 元数据

- **发现者**: Automated Security Scanner
- **分析日期**: 2026-04-22
- **最后更新**: 2026-04-22
- **文件版本**: 1.0