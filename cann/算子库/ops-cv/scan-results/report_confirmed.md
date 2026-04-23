# 漏洞扫描报告 — 已确认漏洞

**项目**: ops-cv  
**扫描时间**: 2026-04-21T23:18:00Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞  

---

## 执行摘要 (Executive Summary)

本次安全扫描针对华为 CANN (Compute Architecture for Neural Networks) 框架中的 ops-cv 图像处理算子库进行了深度漏洞分析。扫描发现 **8 个已确认的高危漏洞**，全部涉及 **整数溢出导致的内存安全问题**。

### 关键发现

| 维度 | 结果 |
|------|------|
| **已确认漏洞** | 8 个（全部 High 级别） |
| **漏洞类型** | 100% 为 CWE-190 整数溢出相关 |
| **攻击向量** | 用户可控的 Tensor Shape / API 参数 |
| **影响范围** | 华为 Ascend NPU 推理服务 |
| **潜在后果** | 内存耗尽 (DoS) / 堆溢出 / 系统崩溃 |

### 核心风险分析

所有漏洞共享相同的根本原因：**AICPU Kernel 接收用户控制的 Tensor 尺寸参数，仅进行非负检查 (>=0)，缺少上限验证和乘法溢出检测**。这种缺陷模式在不同算子中反复出现：

- **Non-Max Suppression v3**: max_output_size_ 无上限，可请求 8GB 内存
- **Spatial Transformer**: output_h_ * output_w_ * 2 可溢出，导致堆溢出
- **Scale and Translate**: span_size * output_size 溢出，分配小内存后写入越界

### 与安全版本的对比

关键发现：**Non-Max Suppression v6 版本已实现安全保护** (`MAX_VALID_OUTPUT = 700`)，而 v3 版本完全缺失此保护。这表明安全编码实践已存在于代码库中，但未被系统性推广。

### 业务影响

1. **生产推理服务**: 恶意模型可导致 NPU 服务崩溃
2. **多租户云环境**: 单租户攻击可影响其他租户
3. **边缘设备**: 内存有限的嵌入式设备极易耗尽
4. **ONNX 模型导入**: 恶意构造的模型文件可触发漏洞

### 修复优先级

**推荐立即修复**。修复难度低（添加参数上限检查），已有安全实现可参考（NMS v6），且漏洞可被远程触发无需特殊权限。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 8 | 38.1% |
| LIKELY | 5 | 23.8% |
| POSSIBLE | 4 | 19.0% |
| FALSE_POSITIVE | 4 | 19.0% |
| **总计** | **21** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 8 | 100.0% |
| **有效漏洞总计** | **8** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-MEM-001]** integer_overflow_to_heap_overflow (High) - `image/non_max_suppression_v3/op_kernel_aicpu/non_max_suppression_v3_aicpu.cpp:165` @ `DoCompute` | 置信度: 90
2. **[VULN-DF-MEM-002]** integer_overflow_to_memory_allocation (High) - `image/spatial_transformer/op_kernel_aicpu/spatial_transformer_aicpu.cpp:274` @ `DoCompute4D` | 置信度: 90
3. **[VULN-DF-MEM-003]** integer_overflow_to_memory_allocation (High) - `image/spatial_transformer/op_kernel_aicpu/spatial_transformer_aicpu.cpp:319` @ `DoCompute5D` | 置信度: 90
4. **[VULN-SEC-MEM-001]** integer_overflow_resource_exhaustion (High) - `image/non_max_suppression_v3/op_kernel_aicpu/non_max_suppression_v3_aicpu.cpp:78` @ `NonMaxSuppressionV3CpuKernel::DoCompute` | 置信度: 90
5. **[VULN-SEC-MEM-003]** integer_overflow_resource_exhaustion (High) - `image/non_max_suppression_v3/op_kernel_aicpu/non_max_suppression_v3_aicpu.cpp:52` @ `NonMaxSuppressionV3CpuKernel::GetInputAndCheck/DoCompute` | 置信度: 85
6. **[VULN-SEC-MEM-005]** integer_overflow_resource_exhaustion (High) - `image/spatial_transformer/op_kernel_aicpu/spatial_transformer_aicpu.cpp:274` @ `SpatialTransformerCpuKernel::DoCompute4D/DoCompute5D/DoCompute5D_C1` | 置信度: 85
7. **[VULN-SEC-MEM-006]** integer_overflow_resource_exhaustion (High) - `image/scale_and_translate/op_kernel_aicpu/scale_and_translate_aicpu.cpp:158` @ `InitSpans` | 置信度: 85
8. **[VULN-DF-MEM-004]** integer_overflow_to_memory_allocation (High) - `image/scale_and_translate/op_kernel_aicpu/scale_and_translate_aicpu.cpp:158` @ `InitSpans` | 置信度: 85

---

## 2. Top 5 漏洞深入分析

### 2.1 VULN-DF-MEM-001: Non-Max Suppression V3 内存耗尽

**CVSS 评分**: 7.5 (High) | **CWE**: CWE-190, CWE-789

#### 漏洞机理

NMS v3 AICPU Kernel 接收用户提供的 `max_output_size` Tensor（int32_t scalar），仅验证 `>= 0`，然后直接用于动态内存分配：

```cpp
// Line 78: 获取用户输入
max_output_size_ = *static_cast<int32_t *>(max_output_size_tensor->GetData());
// Line 79-81: 仅检查非负
KERNEL_CHECK_FALSE((max_output_size_ >= 0), KERNEL_STATUS_PARAM_INVALID, ...);
// Line 165: 危险分配
std::unique_ptr<int32_t[]> indices_data(new (std::nothrow) int32_t[max_output_size_]);
```

#### 攻击场景

**内存耗尽攻击**:
```python
max_output_size = np.array([2147483647], dtype=np.int32)  # INT32_MAX
# 触发分配: 2147483647 * 4 bytes ≈ 8.6 GB
# 结果: 系统内存耗尽，OOM Killer 触发
```

#### 安全版本对比

**NMS v6 (安全实现)**:
```cpp
static constexpr int32_t MAX_VALID_OUTPUT = 700;  // 明确上限
if (maxOutputSize > MAX_VALID_OUTPUT) {
    OP_LOGE(ACLNN_ERR_PARAM_INVALID, "maxOutputBoxesPerClass[%ld] should < 700", ...);
    return ACLNN_ERR_PARAM_INVALID;  // 拒绝危险输入
}
```

#### 修复方案

```cpp
static constexpr int32_t MAX_VALID_OUTPUT_SIZE = 10000;
KERNEL_CHECK_FALSE((max_output_size_ <= MAX_VALID_OUTPUT_SIZE), 
                   KERNEL_STATUS_PARAM_INVALID,
                   "max_output_size must be <= %d, but got [%d]",
                   MAX_VALID_OUTPUT_SIZE, max_output_size_);
```

---

### 2.2 VULN-DF-MEM-002: Spatial Transformer 整数溢出导致堆溢出

**CVSS 评分**: 8.1 (High) | **CWE**: CWE-190, CWE-122

#### 漏洞机理

DoCompute4D 函数使用用户控制的 `output_h_` 和 `output_w_` 计算分配大小：

```cpp
// Line 82-83: 从 Tensor Shape 获取
output_h_ = static_cast<int32_t>(output_tensor_->GetTensorShape()->GetDimSize(2));
output_w_ = static_cast<int32_t>(output_tensor_->GetTensorShape()->GetDimSize(3));
// Line 99-100: 仅检查 != 0
bool dims_error_flag = (output_h_ == 0 || output_w_ == 0);
// Line 274: 危险分配
float* input_grid = (float *)malloc(sizeof(float) * output_h_ * output_w_ * 2);
```

#### 溢出分析

```
假设: output_h_ = 46341, output_w_ = 46341
计算: 46341 * 46341 * 2 * 4 = 17,180,069,256 bytes

32位系统: 溢出为小值 → 分配小内存 → 堆溢出
64位系统: 尝试分配 17GB → 内存耗尽
```

#### 攻击路径

```
用户模型定义 output tensor shape
    ↓
output_tensor_->GetTensorShape()->GetDimSize(2/3)
    ↓
output_h_, output_w_ (int32_t)
    ↓
malloc(sizeof(float) * output_h_ * output_w_ * 2)
    ↓
ComputeGrid() 写入 → 堆溢出
```

#### 修复方案

```cpp
constexpr int64_t MAX_DIM_SIZE = 65536;
constexpr size_t MAX_ALLOCATION_SIZE = 1024 * 1024 * 1024;  // 1GB

if (output_h_ > MAX_DIM_SIZE || output_w_ > MAX_DIM_SIZE) {
    KERNEL_LOG_ERROR("Output dimensions too large");
    return KERNEL_STATUS_PARAM_INVALID;
}

size_t allocation_size = sizeof(float) * output_h_ * output_w_ * 2;
if (allocation_size > MAX_ALLOCATION_SIZE) {
    KERNEL_LOG_ERROR("Allocation exceeds limit");
    return KERNEL_STATUS_PARAM_INVALID;
}
```

---

### 2.3 VULN-DF-MEM-003: Spatial Transformer input_c0_ 漏洞

**CVSS 评分**: 7.5 (High) | **CWE**: CWE-190

#### 漏洞机理

DoCompute5D 函数中 `input_c0_` 来自 5D Tensor 的第四维度：

```cpp
// Line 89: 从 NC1HWC0 格式获取
input_c0_ = static_cast<int32_t>(input_tensor_->GetTensorShape()->GetDimSize(4));
// Line 90: 潜在溢出
input_c_ = input_c1_ * input_c0_;
// Line 99-104: input_c0_ 未单独检查
// Line 319: 危险分配
float *res = (float *)malloc(sizeof(float) * input_c0_);
```

#### 特殊风险

当 `input_c0_` 为负数时（通过特定 uint64 → int32 转换）：

```
GetDimSize(4) = 4294967295 (UINT32_MAX)
static_cast<int32_t>(4294967295) = -1
malloc(sizeof(float) * (-1)) → 巨大分配请求
```

#### 修复方案

```cpp
constexpr int32_t MAX_C0_SIZE = 1024;  // 典型 C0 block size
if (input_c0_ <= 0 || input_c0_ > MAX_C0_SIZE) {
    KERNEL_LOG_ERROR("input_c0_ invalid: [%d]", input_c0_);
    return KERNEL_STATUS_PARAM_INVALID;
}
```

---

### 2.4 VULN-SEC-MEM-005: Spatial Transformer 多处资源耗尽

**CVSS 评分**: 7.5 (High) | **CWE**: CWE-190, CWE-400

#### 漏洞分布

同一文件存在多处相同问题：

| 函数 | 行号 | 分配表达式 |
|------|------|-----------|
| DoCompute4D | 274 | `malloc(sizeof(float) * output_h_ * output_w_ * 2)` |
| DoCompute5D | 316 | `malloc(sizeof(float) * output_w_ * output_h_ * 2)` |
| DoCompute5D | 319 | `malloc(sizeof(float) * input_c0_)` |
| DoCompute5D_C1 | 371 | `malloc(sizeof(float) * output_h_ * output_w_ * 2)` |

#### 攻击场景

```python
output_h = 100000
output_w = 100000
# 单次分配: 100000 * 100000 * 2 * 4 = 80 GB
# 系统内存完全耗尽
```

#### 参考安全实现

UpsampleNearest3D 有完善的边界检查：
```cpp
if (inputShape.GetDim(0) > INT32_MAX) {
    OP_LOGE_FOR_INVALID_SHAPE_WITH_REASON(...);
    return false;
}
```

---

### 2.5 VULN-DF-MEM-004 & VULN-SEC-MEM-006: Scale and Translate 漏洞组

**CVSS 评分**: 7.5 (High) | **CWE**: CWE-190

#### 漏洞机理

InitSpans 函数使用用户 `input_size` tensor 分配 Eigen::Tensor：

```cpp
// Line 289-301: 获取用户输入
auto input_size = reinterpret_cast<int32_t *>(ctx.Input(1)->GetData());
p.output_height = input_size[0];
p.output_width = input_size[1];
// Line 308-311: 仅检查 > 0
KERNEL_CHECK_FALSE((p.output_height > 0 && p.output_width > 0), ...);
// Line 158-163: 双重漏洞
spans->starts = new Eigen::Tensor<int32_t, 1>(output_size);
spans->weights = new Eigen::Tensor<float, 1>(span_size * output_size);  // 溢出点
```

#### 溢出触发

```
span_size ≈ 10 (lanczos3 kernel)
output_size = INT32_MAX / 10 + 1 = 214,748,365

span_size * output_size 溢出:
  10 * 214,748,365 > INT32_MAX
  → 分配小内存
  → ComputeSpansCore() 写入时堆溢出
```

#### 双漏洞关联

| ID | 类型 | 触发条件 |
|----|------|---------|
| VULN-DF-MEM-004 | 整数溢出→缓冲区溢出 | span_size * output_size 溢出 |
| VULN-SEC-MEM-006 | 资源耗尽 | output_size 过大导致 OOM |

两者是同一代码缺陷的不同表现形式，需同时修复。

---

## 3. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `aclnnGridSampler2DGetWorkspaceSize@image/grid_sample/op_api/aclnn_grid_sampler2d.cpp` | rpc | untrusted_network | aclnn API entry point, receives aclTensor pointers from user application via CANN runtime | Grid sample 2D operator API entry - processes input tensor and grid coordinates from user |
| `aclnnGridSampler3DGetWorkspaceSize@image/grid_sample/op_api/aclnn_grid_sampler3d.cpp` | rpc | untrusted_network | aclnn API entry point, receives aclTensor pointers from user application via CANN runtime | Grid sample 3D operator API entry - processes input tensor and grid coordinates from user |
| `aclnnIm2colBackwardGetWorkspaceSize@image/col2im/op_api/aclnn_im2col_backward.cpp` | rpc | untrusted_network | aclnn API entry point, receives gradOutput tensor and kernel/stride/padding parameters from user | Col2im backward operator - receives gradient tensor and convolution parameters |
| `aclnnRoiAlignV2GetWorkspaceSize@objdetect/roi_align/op_host/op_api/aclnn_roi_align_v2.cpp` | rpc | untrusted_network | aclnn API entry point, receives input tensor and ROI boxes from user detection model | ROI align V2 operator - processes feature map and region proposals from detection model |
| `aclnnRoiPoolingWithArgMaxGetWorkspaceSize@objdetect/roi_pooling_with_arg_max/op_api/aclnn_roi_pooling_with_arg_max.cpp` | rpc | untrusted_network | aclnn API entry point, receives input tensor and ROI boxes from user | ROI pooling operator - processes feature map and region proposals |
| `aclnnNonMaxSuppressionGetWorkspaceSize@objdetect/non_max_suppression_v6/op_host/op_api/aclnn_non_max_suppression.cpp` | rpc | untrusted_network | aclnn API entry point, receives boxes and scores tensors from detection model output | Non-maximum suppression operator - processes detection boxes and scores |
| `aclnnIouGetWorkspaceSize@objdetect/iou_v2/op_api/aclnn_iou.cpp` | rpc | untrusted_network | aclnn API entry point, receives bboxes tensors from detection model | IoU calculation operator - processes bounding box tensors |
| `aclnnCIoUGetWorkspaceSize@objdetect/ciou/op_api/aclnn_ciou.cpp` | rpc | untrusted_network | aclnn API entry point, receives bboxes tensors from detection model | CIoU calculation operator - processes bounding box tensors |
| `aclnnResizeGetWorkspaceSize@image/resize_bilinear_v2/op_api/aclnn_resize.cpp` | rpc | untrusted_network | aclnn API entry point, receives input tensor and size parameters from user | Resize bilinear operator - processes input image tensor |
| `NonMaxSuppressionV3CpuKernel::Compute@image/non_max_suppression_v3/op_kernel_aicpu/non_max_suppression_v3_aicpu.cpp` | rpc | untrusted_network | AICPU kernel entry point, called via kernel dispatch from host code | AICPU NMS implementation - directly processes tensor data |
| `CropAndResizeCpuKernel::Compute@image/crop_and_resize/op_kernel_aicpu/crop_and_resize_aicpu.cpp` | rpc | untrusted_network | AICPU kernel entry point, processes image tensor and crop boxes | AICPU crop and resize implementation |
| `SpatialTransformerCpuKernel::Compute@image/spatial_transformer/op_kernel_aicpu/spatial_transformer_aicpu.cpp` | rpc | untrusted_network | AICPU kernel entry point, processes input tensor and transformation parameters | AICPU spatial transformer implementation |
| `grid_sample@image/grid_sample/op_kernel/grid_sample.cpp` | rpc | untrusted_network | AI Core kernel entry point, receives GM_ADDR pointers to tensor data | AI Core grid sample kernel - processes tensor data directly on NPU |

**其他攻击面**:
- aclnn API Interface: All aclnn*GetWorkspaceSize functions receive user-controlled tensor data
- AICPU Kernel Dispatch: AICPU kernels process raw tensor data from model inference
- AI Core Kernel Execution: op_kernel/*.cpp files receive GM_ADDR pointers to user tensor data
- ONNX Plugin Interface: common/src/framework/*.cpp files handle ONNX model conversion
- Python Scripts: scripts/ directory contains build/package scripts that may process model files

---

## 4. High 漏洞详情列表

### [VULN-DF-MEM-001] integer_overflow_to_heap_overflow - DoCompute

**严重性**: High | **CWE**: CWE-190 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `image/non_max_suppression_v3/op_kernel_aicpu/non_max_suppression_v3_aicpu.cpp:165-169` @ `DoCompute`
**模块**: image_other

**描述**: 用户控制的 max_output_size_ 参数用于内存分配 new int32_t[max_output_size_]，只检查了非负 (>=0) 但没有上限检查。攻击者可以通过提供极大的 max_output_size_ 值导致大量内存分配或整数溢出。对比 non_max_suppression_v6 版本有 MAX_VALID_OUTPUT=700 的上限检查，而 v3 版本缺少此安全保护。

**漏洞代码**

```c
std::unique_ptr<int32_t[]> indices_data(new (std::nothrow) int32_t[max_output_size_]);
if (indices_data == nullptr) {
  KERNEL_LOG_ERROR("DoCompute: new indices_data failed");
  return KERNEL_STATUS_INNER_ERROR;
}
```

**达成路径**

aclTensor max_output_size_tensor (用户输入) [SOURCE] -> max_output_size_ = *static_cast<int32_t*>(max_output_size_tensor->GetData()) [line 78] -> new int32_t[max_output_size_] [SINK, line 165]

---

### [VULN-DF-MEM-002] integer_overflow_to_memory_allocation - DoCompute4D

**严重性**: High | **CWE**: CWE-190 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `image/spatial_transformer/op_kernel_aicpu/spatial_transformer_aicpu.cpp:274-276` @ `DoCompute4D`
**模块**: image_transform

**描述**: malloc 分配大小由用户控制的 output_h_, output_w_ 和 input_c0_ 计算，缺少整数溢出检查。计算 sizeof(float) * output_h_ * output_w_ * 2 可能溢出，导致分配的内存比预期小，后续写入时可能造成堆溢出。output_h_, output_w_ 来自 output_tensor_->GetTensorShape()->GetDimSize()，这些值由用户应用通过 API 传入。

**漏洞代码**

```c
float* input_grid = (float *)malloc(sizeof(float) * output_h_ * output_w_ * 2);
KERNEL_CHECK_NULLPTR(input_grid, KERNEL_STATUS_INNER_ERROR, "Can't malloc input_grid.");
```

**达成路径**

output_tensor_->GetTensorShape()->GetDimSize() (用户tensor shape) [SOURCE] -> output_h_, output_w_ [lines 82-83] -> malloc(sizeof(float) * output_h_ * output_w_ * 2) [SINK, line 274]

---

### [VULN-DF-MEM-003] integer_overflow_to_memory_allocation - DoCompute5D

**严重性**: High | **CWE**: CWE-190 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `image/spatial_transformer/op_kernel_aicpu/spatial_transformer_aicpu.cpp:319-324` @ `DoCompute5D`
**模块**: image_transform

**描述**: malloc 分配大小 sizeof(float) * input_c0_ 来自用户控制的 tensor shape。input_c0_ 来自 input_tensor_->GetTensorShape()->GetDimSize(kDimSizeIndex4)，用户可控制此值。缺少整数溢出检查和上限验证。

**漏洞代码**

```c
float *res = (float *)malloc(sizeof(float) * input_c0_);
if (res == nullptr) {
  KERNEL_LOG_ERROR("Can't malloc res.");
  free(input_grid);
  return KERNEL_STATUS_INNER_ERROR;
}
```

**达成路径**

input_tensor_->GetTensorShape()->GetDimSize(kDimSizeIndex4) [SOURCE, line 89] -> input_c0_ -> malloc(sizeof(float) * input_c0_) [SINK, line 319]

---

### [VULN-SEC-MEM-001] integer_overflow_resource_exhaustion - NonMaxSuppressionV3CpuKernel::DoCompute

**严重性**: High | **CWE**: CWE-190 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `image/non_max_suppression_v3/op_kernel_aicpu/non_max_suppression_v3_aicpu.cpp:78-165` @ `NonMaxSuppressionV3CpuKernel::DoCompute`
**模块**: image_other

**描述**: NMS v3 AICPU kernel 中 max_output_size_ 来自用户输入 tensor，仅检查 >= 0 但无上限验证。该值直接用于 new int32_t[max_output_size_] 动态内存分配。用户传入超大值（如 INT32_MAX 或接近 2^30）可能导致内存耗尽或分配失败，造成拒绝服务。

**漏洞代码**

```c
max_output_size_ = *static_cast<int32_t *>(max_output_size_tensor->GetData());
KERNEL_CHECK_FALSE((max_output_size_ >= 0), KERNEL_STATUS_PARAM_INVALID, ...);
...
std::unique_ptr<int32_t[]> indices_data(new (std::nothrow) int32_t[max_output_size_]);
```

**达成路径**

ctx.Input(kThirdInputIndex) -> max_output_size_tensor->GetData() -> max_output_size_ -> new int32_t[max_output_size_]

---

### [VULN-SEC-MEM-003] integer_overflow_resource_exhaustion - NonMaxSuppressionV3CpuKernel::GetInputAndCheck/DoCompute

**严重性**: High | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `image/non_max_suppression_v3/op_kernel_aicpu/non_max_suppression_v3_aicpu.cpp:52-157` @ `NonMaxSuppressionV3CpuKernel::GetInputAndCheck/DoCompute`
**模块**: image_other

**描述**: NMS v3 AICPU kernel 中 num_boxes_ 来自用户 tensor shape (boxes_shape->GetDimSize(0))，用于分配 std::vector<T> scores_data(num_boxes_)。无上限检查，超大 num_boxes 值可能导致内存耗尽。结合 num_boxes_ * 4 用于 Eigen::TensorMap，同样存在整数溢出风险。

**漏洞代码**

```c
num_boxes_ = boxes_shape->GetDimSize(0);
...
Eigen::TensorMap<Eigen::Tensor<T, Two, Eigen::RowMajor>> boxes_map(reinterpret_cast<T *>(boxes_->GetData()), num_boxes_, 4);
std::vector<T> scores_data(num_boxes_);
```

**达成路径**

boxes_->GetTensorShape()->GetDimSize(0) -> num_boxes_ -> Eigen::TensorMap(num_boxes_, 4), vector(num_boxes_)

---

### [VULN-SEC-MEM-005] integer_overflow_resource_exhaustion - SpatialTransformerCpuKernel::DoCompute4D/DoCompute5D/DoCompute5D_C1

**严重性**: High | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `image/spatial_transformer/op_kernel_aicpu/spatial_transformer_aicpu.cpp:274-371` @ `SpatialTransformerCpuKernel::DoCompute4D/DoCompute5D/DoCompute5D_C1`
**模块**: image_transform

**描述**: Spatial Transformer AICPU kernel 使用 malloc 分配 output_h_ * output_w_ * 2 * sizeof(float) 内存。output_h_ 和 output_w_ 来自用户 tensor output shape，无上限检查。超大输出尺寸可能导致内存耗尽。存在多处相同问题（DoCompute4D/5D/5D_C1）。

**漏洞代码**

```c
float* input_grid = (float *)malloc(sizeof(float) * output_h_ * output_w_ * 2);
KERNEL_CHECK_NULLPTR(input_grid, KERNEL_STATUS_INNER_ERROR, "Can't malloc input_grid.");
// DoCompute5D 还分配: float *res = (float *)malloc(sizeof(float) * input_c0_);
```

**达成路径**

output_tensor_->GetTensorShape()->GetDimSize(kDimSizeIndex2/3) -> output_h_/output_w_ -> malloc()

---

### [VULN-SEC-MEM-006] integer_overflow_resource_exhaustion - InitSpans

**严重性**: High | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `image/scale_and_translate/op_kernel_aicpu/scale_and_translate_aicpu.cpp:158-163` @ `InitSpans`
**模块**: image_transform

**描述**: Scale and Translate AICPU kernel 在 InitSpans 中使用 new 分配 Eigen::Tensor，大小为 output_size (来自用户 input_size tensor)。无上限验证，超大 output_size 可能导致内存耗尽。同时 spans->weights 分配 span_size * output_size 也存在风险。

**漏洞代码**

```c
spans->starts = new (std::nothrow) Eigen::Tensor<int32_t, 1>(output_size);
KERNEL_CHECK_NULLPTR(spans->starts, ...);
spans->weights = new (std::nothrow) Eigen::Tensor<float, 1>(spans->span_size * output_size);
```

**达成路径**

ctx.Input(1)->GetData() -> input_size[0/1] -> output_height/width -> InitSpans(output_size) -> new Eigen::Tensor(output_size)

---

### [VULN-DF-MEM-004] integer_overflow_to_memory_allocation - InitSpans

**严重性**: High | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `image/scale_and_translate/op_kernel_aicpu/scale_and_translate_aicpu.cpp:158-163` @ `InitSpans`
**模块**: image_transform

**描述**: InitSpans 函数中使用用户控制的 output_size 参数进行内存分配。output_size 来自用户提供的 input_size tensor (ctx.Input(1)->GetData())，只检查了 output_height > 0 和 output_width > 0，但没有上限检查。spans->span_size * output_size 的乘法可能发生整数溢出，导致分配的内存比预期小。

**漏洞代码**

```c
spans->starts = new (std::nothrow) Eigen::Tensor<int32_t, 1>(output_size);
KERNEL_CHECK_NULLPTR(spans->starts, KERNEL_STATUS_PARAM_INVALID, "New spans starts failed.")
spans->weights = new (std::nothrow) Eigen::Tensor<float, 1>(spans->span_size * output_size);
```

**达成路径**

input_size tensor (用户输入) [SOURCE] -> input_size[0], input_size[1] [lines 289-291] -> output_height, output_width [lines 300-301] -> InitSpans(... output_size ...) [line 175] -> new Eigen::Tensor<int32_t, 1>(output_size) [SINK, line 158]

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| image_other | 0 | 3 | 0 | 0 | 3 |
| image_transform | 0 | 5 | 0 | 0 | 5 |
| **合计** | **0** | **8** | **0** | **0** | **8** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-190 | 8 | 100.0% |

---

## 7. 修复建议

### 7.1 统一修复模式

所有漏洞共享相同的根本原因，可采用统一的修复模式：

```cpp
// 1. 定义模块级常量
static constexpr int32_t MAX_DIM_SIZE = 65536;          // 单维度上限
static constexpr int64_t MAX_ALLOCATION_SIZE = 1024LL * 1024 * 1024;  // 1GB 分配上限

// 2. 参数验证模板
template<typename T>
bool ValidateDimension(T value, const char* name, T max_value) {
    if (value <= 0) {
        KERNEL_LOG_ERROR("%s must be positive, got [%d]", name, value);
        return false;
    }
    if (value > max_value) {
        KERNEL_LOG_ERROR("%s exceeds maximum [%d], got [%d]", name, max_value, value);
        return false;
    }
    return true;
}

// 3. 安全乘法函数
template<typename T>
bool SafeMultiply(T a, T b, T& result, T max_value) {
    if (a == 0 || b == 0) {
        result = 0;
        return true;
    }
    if (a > max_value / b) {
        return false;  // 溢出
    }
    result = a * b;
    return true;
}
```

### 7.2 各漏洞具体修复

#### Non-Max Suppression V3

```cpp
// 参考 NMS v6 的安全实现
static constexpr int32_t MAX_VALID_OUTPUT = 700;

KERNEL_CHECK_FALSE((max_output_size_ <= MAX_VALID_OUTPUT),
                   KERNEL_STATUS_PARAM_INVALID,
                   "max_output_size must be <= %d, got [%d]",
                   MAX_VALID_OUTPUT, max_output_size_);
```

#### Spatial Transformer

```cpp
// 在 GetInputAndCheckValid 中添加
if (output_h_ > MAX_DIM_SIZE || output_w_ > MAX_DIM_SIZE) {
    KERNEL_LOG_ERROR("Output dimensions too large: h=[%d], w=[%d]", output_h_, output_w_);
    return KERNEL_STATUS_PARAM_INVALID;
}

// 检查分配大小溢出
int64_t grid_size = static_cast<int64_t>(output_h_) * output_w_ * 2 * sizeof(float);
if (grid_size > MAX_ALLOCATION_SIZE) {
    KERNEL_LOG_ERROR("Grid allocation size exceeds limit");
    return KERNEL_STATUS_PARAM_INVALID;
}

// 检查 input_c0_ (5D 格式)
if (input_c0_ <= 0 || input_c0_ > 1024) {
    KERNEL_LOG_ERROR("input_c0_ invalid: [%d]", input_c0_);
    return KERNEL_STATUS_PARAM_INVALID;
}
```

#### Scale and Translate

```cpp
// 在 ParseScaleAndTranslateParams 中添加
if (p.output_height > MAX_DIM_SIZE || p.output_width > MAX_DIM_SIZE) {
    KERNEL_LOG_ERROR("Output size exceeds limit");
    return KERNEL_STATUS_PARAM_INVALID;
}

// 在 InitSpans 中检查乘法溢出
int64_t weights_size = spans->span_size * output_size;
if (weights_size > MAX_ALLOCATION_SIZE / sizeof(float)) {
    KERNEL_LOG_ERROR("Weights allocation overflow");
    return KERNEL_STATUS_PARAM_INVALID;
}
```

### 7.3 代码库级别改进

1. **创建公共验证头文件**
   - 文件: `common/inc/external/aclnn_kernels/common/dimension_validation.h`
   - 包含统一的验证宏和函数

2. **infershape 验证补充**
   - 在算子 infershape.cpp 中添加 shape 上限验证
   - 提前拦截危险输入，避免 kernel 执行

3. **单元测试补充**
   ```cpp
   // 边界测试模板
   TEST(SecurityTest, LargeDimensionRejection) {
       EXPECT_EQ(KERNEL_STATUS_PARAM_INVALID, kernel(dim=MAX+1));
   }
   TEST(SecurityTest, OverflowDetection) {
       EXPECT_EQ(KERNEL_STATUS_PARAM_INVALID, kernel(dim=overflow_boundary));
   }
   ```

4. **文档更新**
   - API 文档中说明参数有效范围
   - 安全编码指南中添加验证模式

### 7.4 修复优先级矩阵

| 优先级 | 漏洞 | 修复难度 | 业务风险 |
|--------|------|---------|---------|
| P1 (立即) | VULN-DF-MEM-001, VULN-SEC-MEM-001 | 低（参考 v6） | 高（NMS 常用） |
| P1 (立即) | VULN-DF-MEM-002, VULN-SEC-MEM-005 | 中（多处） | 高（图像处理） |
| P2 (本周) | VULN-DF-MEM-003 | 低 | 中 |
| P2 (本周) | VULN-DF-MEM-004, VULN-SEC-MEM-006 | 中 | 高 |
| P3 (下版本) | 公共验证框架 | 中 | 长期收益 |

---

## 8. 总结

本次扫描揭示了 ops-cv 算子库中系统性的安全缺陷模式。所有 8 个已确认漏洞源于同一根本原因：**用户控制的 Tensor 尺寸参数缺少上限验证和整数溢出检测**。

关键发现：
- 安全实现已存在于代码库（NMS v6 的 MAX_VALID_OUTPUT=700）
- 漏洞可通过简单的参数上限检查修复
- 攻击向量远程可达，无需特殊权限
- 影响华为 Ascend NPU 生产推理服务

建议采取行动：
1. 立即修复 P1 级别漏洞（NMS v3, Spatial Transformer）
2. 建立统一的维度验证机制
3. 在 infershape 阶段添加预验证
4. 补充安全测试用例

---

**报告生成**: 2026-04-22  
**扫描工具**: OpenCode Vulnerability Scanner  
**置信度**: HIGH (85-90%)  
**深度分析报告**: 详见 `scan-results/details/` 目录