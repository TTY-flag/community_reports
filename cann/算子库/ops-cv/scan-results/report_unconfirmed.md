# 漏洞扫描报告 — 待确认漏洞

**项目**: ops-cv
**扫描时间**: 2026-04-21T23:18:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| Medium | 4 | 100.0% |
| **有效漏洞总计** | **4** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-INT-001]** integer_overflow_to_buffer_overflow (Medium) - `image/col2im/op_api/aclnn_im2col_backward.cpp:170` @ `CheckArray` | 置信度: 65
2. **[VULN-SEC-ONNX-001]** missing_input_validation (Medium) - `common/src/framework/npu_nms_v4_onnx_plugin.cpp:44` @ `ParseParamsNmsV4` | 置信度: 55
3. **[VULN-SEC-INPUT-001]** missing_input_validation (Medium) - `objdetect/roi_align/op_host/op_api/aclnn_roi_align_v2.cpp:100` @ `aclnnRoiAlignV2GetWorkspaceSize/CheckShape/CheckAttr` | 置信度: 50
4. **[VULN-SEC-MEM-004]** integer_overflow (Medium) - `objdetect/non_max_suppression_v6/op_host/op_api/aclnn_non_max_suppression.cpp:140` @ `aclnnNonMaxSuppressionGetWorkspaceSize` | 置信度: 45

---

## 2. 攻击面分析

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

## 3. Medium 漏洞 (4)

### [VULN-DF-INT-001] integer_overflow_to_buffer_overflow - CheckArray

**严重性**: Medium | **CWE**: CWE-680 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `image/col2im/op_api/aclnn_im2col_backward.cpp:170-178` @ `CheckArray`
**模块**: image_transform

**描述**: CheckArray 函数中计算 numL0 * numL1 时可能发生整数溢出。numL0 和 numL1 通过用户提供的参数 (inputSize, padding, dilation, kernelSize, stride) 计算得出，这些值都来自用户输入。当用户提供极大的参数值时，乘法可能溢出，导致 numL != numL0L1 检查通过但实际上 shape 不匹配。

**漏洞代码** (`image/col2im/op_api/aclnn_im2col_backward.cpp:170-178`)

```c
size_t numL0 = ((*inputSize)[0] + (*padding)[0] * 2 - (*dilation)[0] * ((*kernelSize)[0] - 1) - 1 + (*stride)[0]) / (*stride)[0];
size_t numL1 = ((*inputSize)[1] + (*padding)[1] * 2 - (*dilation)[1] * ((*kernelSize)[1] - 1) - 1 + (*stride)[1]) / (*stride)[1];
size_t numL0L1 = numL0 * numL1;
```

**达成路径**

inputSize, padding, dilation, kernelSize, stride (用户IntArray参数) [SOURCE] -> numL0, numL1 计算 [lines 170-173] -> numL0 * numL1 [溢出风险, line 174] -> shape 验证 [SINK]

**验证说明**: Integer overflow in CheckArray validation logic. User input (inputSize, padding, dilation, kernelSize, stride) flows directly to numL0*numL1 calculation. However, this is parameter validation only - overflow affects validation result but does NOT lead to memory allocation or buffer overflow. CheckArrayValue provides basic sanity checks (>0, >=0). Severity reduced due to limited impact.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 4 | 6: 0 | 7: ( | 8: r | 9: e | 10: a | 11: c | 12: h | 13: a | 14: b | 15: l | 16: e | 17: , | 18: C | 19: W | 20: E | 21: - | 22: 6 | 23: 8 | 24: 0 | 25: ) | 26:   | 27: + | 28:   | 29: r | 30: e | 31: a | 32: c | 33: h | 34: a | 35: b | 36: i | 37: l | 38: i | 39: t | 40: y | 41: : | 42: + | 43: 1 | 44: 5 | 45: ( | 46: d | 47: i | 48: r | 49: e | 50: c | 51: t | 52:   | 53: A | 54: P | 55: I | 56:   | 57: p | 58: a | 59: r | 60: a | 61: m | 62: s | 63: ) | 64:   | 65: + | 66:   | 67: c | 68: o | 69: n | 70: t | 71: r | 72: o | 73: l | 74: l | 75: a | 76: b | 77: i | 78: l | 79: i | 80: t | 81: y | 82: : | 83: + | 84: 2 | 85: 0 | 86: ( | 87: u | 88: s | 89: e | 90: r | 91:   | 92: c | 93: o | 94: n | 95: t | 96: r | 97: o | 98: l | 99: s | 100:   | 101: a | 102: l | 103: l | 104: ) | 105:   | 106: + | 107:   | 108: m | 109: i | 110: t | 111: i | 112: g | 113: a | 114: t | 115: i | 116: o | 117: n | 118: s | 119: : | 120: - | 121: 1 | 122: 0 | 123: ( | 124: C | 125: h | 126: e | 127: c | 128: k | 129: A | 130: r | 131: r | 132: a | 133: y | 134: V | 135: a | 136: l | 137: u | 138: e | 139:   | 140: b | 141: a | 142: s | 143: i | 144: c | 145:   | 146: c | 147: h | 148: e | 149: c | 150: k | 151: s | 152: ) | 153:   | 154: + | 155:   | 156: c | 157: o | 158: n | 159: t | 160: e | 161: x | 162: t | 163: : | 164: + | 165: 0 | 166: ( | 167: i | 168: n | 169: t | 170: e | 171: r | 172: n | 173: a | 174: l | 175:   | 176: v | 177: a | 178: l | 179: i | 180: d | 181: a | 182: t | 183: i | 184: o | 185: n | 186: )

---

### [VULN-SEC-ONNX-001] missing_input_validation - ParseParamsNmsV4

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `common/src/framework/npu_nms_v4_onnx_plugin.cpp:44-49` @ `ParseParamsNmsV4`
**模块**: common

**描述**: ONNX NMS v4 Plugin 从 ONNX node attribute 读取 max_output_size，未验证值的合理性。负数、零值或超大整数值可能导致后续 NonMaxSuppressionV4 算子执行异常或内存分配失败。ONNX 模型文件可被用户修改，存在恶意构造风险。

**漏洞代码** (`common/src/framework/npu_nms_v4_onnx_plugin.cpp:44-49`)

```c
if (attr.name() == "max_output_size" && attr.type() == ge::onnx::AttributeProto::INT) {
    max_output_size = attr.i();  // 无验证
}
ge::Tensor scalar_const_value = CreateScalar(max_output_size, ge::DT_INT32);
```

**达成路径**

node->attribute() -> attr.i() -> max_output_size -> CreateScalar() -> NonMaxSuppressionV4

**验证说明**: ONNX plugin ParseParamsNmsV4 reads max_output_size from node attributes without validation. User-provided model files can contain malicious attributes. However, this occurs during offline graph compilation phase, not runtime execution. The max_output_size value becomes a constant in compiled graph. Risk is elevated if untrusted model files are processed, but context is trusted development environment.

**评分明细**: base: 60 | additive: [object Object] | veto: [object Object] | reachability: model_parsing | exploitability: medium

---

### [VULN-SEC-INPUT-001] missing_input_validation - aclnnRoiAlignV2GetWorkspaceSize/CheckShape/CheckAttr

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `objdetect/roi_align/op_host/op_api/aclnn_roi_align_v2.cpp:100-124` @ `aclnnRoiAlignV2GetWorkspaceSize/CheckShape/CheckAttr`
**模块**: objdetect_roi

**描述**: ROI Align V2 API 中 pooledHeight 和 pooledWidth 参数来自 API 调用参数，仅验证与 out tensor shape 的匹配关系，但未检查参数本身的合理上限。超大值可能导致 kernel 执行时内存耗尽或计算溢出。samplingRatio 也存在类似问题，仅检查 >= 0 但无上限。

**漏洞代码** (`objdetect/roi_align/op_host/op_api/aclnn_roi_align_v2.cpp:100-124`)

```c
if (outShape.GetDim(DIM_TWO) != pooledHeight) {
    OP_LOGE(..., "out shape dim2 [%ld] and pooledHeight [%ld] should be equal", ...);
    return false;
}
if (outShape.GetDim(DIM_THREE) != pooledWidth) { ... }
```

**达成路径**

aclnnRoiAlignV2GetWorkspaceSize 参数 pooledHeight/pooledWidth -> CheckShape() -> 仅验证与 out shape 匹配

**验证说明**: ROI Align V2 API accepts pooledHeight, pooledWidth, samplingRatio parameters with limited validation. Only checks shape matching and samplingRatio >= 0. No upper bounds prevent extremely large values. Large parameters could cause memory exhaustion or computational overflow in kernel. However, framework memory allocation limits provide protection - allocation failures return graceful errors rather than crashes.

**评分明细**: base: 55 | additive: [object Object] | veto: [object Object] | reachability: direct_api | exploitability: medium

---

### [VULN-SEC-MEM-004] integer_overflow - aclnnNonMaxSuppressionGetWorkspaceSize

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `objdetect/non_max_suppression_v6/op_host/op_api/aclnn_non_max_suppression.cpp:140` @ `aclnnNonMaxSuppressionGetWorkspaceSize`
**模块**: objdetect_nms

**描述**: NMS v6 API 中 maxBoxesSize 计算涉及三个乘数相乘：maxOutputSize (最大700) * scores->GetDim(0) * scores->GetDim(1)。虽然 maxOutputSize 有上限700，但 scores shape 来自用户输入，大模型可能产生极大的 batch_size 和 num_classes，乘积可能超过 int64_t 范围导致整数溢出。

**漏洞代码** (`objdetect/non_max_suppression_v6/op_host/op_api/aclnn_non_max_suppression.cpp:140`)

```c
maxBoxesSize = maxOutputSize * scores->GetViewShape().GetDim(0) * scores->GetViewShape().GetDim(1);
```

**达成路径**

maxOutputBoxesPerClass -> maxOutputSize (<=700) -> scores shape dim0 * dim1 -> maxBoxesSize

**验证说明**: Integer overflow in maxBoxesSize calculation: maxOutputSize (capped at 700) * scores.GetDim(0) * scores.GetDim(1). Overflow requires scores dimensions ~13M each to exceed int64_t max. Typical model sizes are orders of magnitude smaller. While no upper bound check exists for scores shape, practical exploitation is highly unlikely. Validates shape dimension count (must be 3D) but not size limits.

**评分明细**: base: 50 | additive: [object Object] | veto: [object Object] | reachability: direct_api | exploitability: low_practical

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| common | 0 | 0 | 1 | 0 | 1 |
| image_transform | 0 | 0 | 1 | 0 | 1 |
| objdetect_nms | 0 | 0 | 1 | 0 | 1 |
| objdetect_roi | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **0** | **4** | **0** | **4** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 2 | 50.0% |
| CWE-680 | 1 | 25.0% |
| CWE-190 | 1 | 25.0% |
