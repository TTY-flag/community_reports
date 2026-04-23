# VULN-SEC-TENSOR-001: Tensor 构造函数用户 Shape 与实际 Buffer 不匹配致越界读取

## 漏洞摘要

| 属性 | 值 |
|-----------|-------|
| **CWE ID** | CWE-125: 越界读取 |
| **严重程度** | High |
| **信任等级** | untrusted_external |
| **受影响模块** | tensor |
| **主要位置** | `AccSDK/source/tensor/Tensor.cpp:83` |
| **次要位置** | `AccSDK/source/tensor/Tensor.cpp:121`, `AccSDK/source/py/module/PyTensor.cpp:102`, `AccSDK/source/py/module/PyUtil.cpp:84` |

## 漏洞描述

`Tensor` 构造函数接受用户提供的 buffer 指针 (`void* data`) 和 shape 向量，但未验证实际 buffer 大小是否与从 shape 计算的预期大小匹配。当随后调用 `Clone()` 方法时，它会从 buffer 读取 `totalBytes` 字节，如果用户提供的 shape 大于实际数据，则可能读取超出实际分配的内存。

这是一个 **CWE-125: 越界读取** 漏洞，可能导致：
1. **信息泄露**：从相邻内存读取敏感数据
2. **拒绝服务**：读取未映射内存时导致应用程序崩溃
3. **内存破坏**：根据读取的数据类型可能被利用

## 调用链分析

```
Python 层                         C++ 绑定层                         核心 C++ 层
─────────────────────────────────────────────────────────────────────────────────────────
PyTensor.from_numpy()     →     PyUtil.cpp: GetNumpyData()      →    Tensor.cpp:83 Tensor()
     │                               │                                    │
     │ PyObject* numpy array         │ Extract dataPtr, shape             │ CheckTensorParams()
     │                               │ from __array_interface__            │ (仅 null 检查)
     │                               │ 无大小验证                          │
     │                               │                                    ▼
     │                               │                          FillAuxInfo()
     │                               │                          (计算 totalBytes)
     │                               │                                    │
     └───────────────────────────────┴────────────────────────────────────┘
                                                                          │
                                          Clone() 被调用 ──────────────────┘
                                               │
                                               ▼
                                    memcpy_s(..., totalBytes)  [SINK - 过度读取]
```

### 第 1 层：Python 入口点 (`PyTensor.cpp:99-106`)

```cpp
Tensor Tensor::from_numpy(PyObject* pyObj)
{
    NumpyData numpyData = GetNumpyData(pyObj);
    // 漏洞：numpyData.dataPtr 和 numpyData.shape 来自用户输入
    // 未验证实际 buffer 大小是否与 shape 匹配
    Acc::Tensor accTensor(numpyData.dataPtr, numpyData.shape, numpyData.dataType, Acc::TensorFormat::ND, "cpu");
    Tensor tensor;
    tensor.SetTensor(accTensor);
    return tensor;
}
```

**安全控制**：无 - 用户控制的 numpy 数组被直接传递。

### 第 2 层：Numpy 数据提取 (`PyUtil.cpp:47-137`)

```cpp
NumpyData GetNumpyData(PyObject* pyObj)
{
    // ...
    // 从 __array_interface__ 获取 data pointer
    PyObject *dataPtrObj = PyTuple_GetItem(dataTuple, 0);
    numpyData.dataPtr = reinterpret_cast<void*>(PyLong_AsVoidPtr(dataPtrObj));
    if (PyErr_Occurred() || !numpyData.dataPtr) {
        throw std::runtime_error("Failed to get valid data pointer...");
    }
    // 漏洞：仅检查指针非 null，不验证 buffer 是否足够大
    
    // 从 __array_interface__ 获取 shape
    for (Py_ssize_t i = 0; i < PyTuple_Size(shapeTuple); i++) {
        PyObject *dim = PyTuple_GetItem(shapeTuple, i);
        size_t dimSize = PyLong_AsSize_t(dim);  // 用户控制的值
        numpyData.shape.push_back(dimSize);
    }
    // 漏洞：shape 是用户控制的，未针对实际 buffer 大小进行验证
    // ...
}
```

**安全控制**：仅验证非 null 指针，未针对 shape 验证 buffer 大小。

### 第 3 层：Tensor 构造函数 (`Tensor.cpp:83-93`)

```cpp
Tensor::Tensor(void* data, const std::vector<size_t>& shape, DataType dataType, TensorFormat format, const char* device)
    : deviceId_(DEVICE_CPU),
      shape_(shape),
      dataType_(dataType),
      format_(format),
      dataPtr_(std::shared_ptr<void>(data, [](void*) {})),  // 获取所有权但无大小信息
      device_(device ? device : "")
{
    CheckTensorParams();  // 仅验证：dataPtr != nullptr, shape.size() > 0, format 约束
    FillAuxInfo();        // 计算：totalBytes = product(shape) * elementSize
}
```

**关键漏洞**：
- `dataPtr_` 存储指针但无任何大小信息
- `CheckTensorParams()` 不验证 buffer 大小
- `FillAuxInfo()` 仅根据用户提供的 `shape` 计算 `totalBytes`

### 第 4 层：AuxInfo 计算 (`Tensor.cpp:37-60`)

```cpp
void Tensor::FillAuxInfo()
{
    // 计算缓存
    auxInfo_.elementNums =
        std::accumulate(shape_.begin(), shape_.end(), static_cast<size_t>(1), std::multiplies<size_t>());
    auxInfo_.perElementBytes = GetByteSize(dataType_);
    auxInfo_.totalBytes = auxInfo_.elementNums * auxInfo_.perElementBytes;  // 基于用户提供的 shape！
    // ...
}
```

**漏洞**：`totalBytes` 从用户控制的 `shape_` 计算，未针对实际 buffer 大小进行验证。

### 第 5 层：Clone 方法 - SINK (`Tensor.cpp:108-129`)

```cpp
ErrorCode Tensor::Clone(Tensor& tensor) const
{
    if (dataPtr_ == nullptr || auxInfo_.totalBytes == 0) {
        LogWarn << "Current tensor is empty, the clone operation is invalid.";
        return SUCCESS;
    }
    // 基于从用户提供的 shape 计算的 totalBytes 分配
    char* data = new(std::nothrow) char[auxInfo_.totalBytes];
    if (data == nullptr) {
        LogError << "Failed to malloc for tensor." << GetErrorInfo(ERR_BAD_ALLOC);
        return ERR_BAD_ALLOC;
    }
    std::shared_ptr<void> dstPtr(static_cast<void*>(data), [](void* ptr) { delete[] static_cast<char*>(ptr); });
    // 漏洞：从用户 buffer 读取 totalBytes 但不知道实际大小
    auto ret = memcpy_s(dstPtr.get(), auxInfo_.totalBytes, dataPtr_.get(), auxInfo_.totalBytes);
    // 如果实际 buffer < totalBytes → 越界读取
    if (ret != SUCCESS) {
        LogError << "Tensor clone failed..." << GetErrorInfo(ERR_BAD_COPY);
        return ERR_BAD_COPY;
    }
    tensor = Tensor(dstPtr, shape_, dataType_, format_, this->Device().get());
    return SUCCESS;
}
```

**漏洞 SINK**：`memcpy_s()` 从 `dataPtr_` 读取 `totalBytes` 字节，但不知道 buffer 的实际分配大小。

## 概念验证

### 攻击向量 1：Python API 直接利用

```python
import numpy as np
from mm.acc.wrapper.tensor_wrapper import Tensor

# 创建一个小 buffer (100 字节)
small_array = np.zeros((100,), dtype=np.uint8)
tensor = Tensor.from_numpy(small_array)

# 恶意修改内部 shape（模拟构造的输入）
# 在实际攻击中，这可以通过构造具有被操纵的 __array_interface__ 元数据的恶意 numpy 数组来完成

# 替代攻击向量：直接 C++ 操作
# 攻击者创建一个具有 __array_interface__ 的恶意对象：
class MaliciousArray:
    @property
    def __array_interface__(self):
        return {
            'version': 3,
            'data': (actual_buffer_address, False),  # 小 buffer
            'shape': (1000000, 1000000),  # 巨大 shape
            'typestr': '<f4'  # float32 = 每元素 4 字节
        }

# 这将导致 Tensor 计算 totalBytes = 1000000 * 1000000 * 4 = 4TB
# 而 Clone() 将尝试从小 buffer 读取 4TB
```

### 攻击向量 2：图像处理流水线

```python
# 图像数据流经流水线：
# 图像文件 → 解码 → Tensor → 模型推理
# 
# 如果图像解码产生的 buffer 小于预期 shape：
# （例如：截断的图像文件、损坏的 header）
#
# Tensor 构造函数无法验证实际 buffer 大小
# 后续的 Clone() 或 tensor 操作将越界读取
```

## 影响评估

| 因素 | 评估 |
|--------|-------------|
| **攻击复杂度** | Low - 通过 Python API 直接利用 |
| **所需权限** | None - 任何有 SDK 访问权限的用户 |
| **用户交互** | None - 可编程触发 |
| **范围** | Unchanged - 仅影响漏洞进程 |
| **机密性影响** | High - 可读取任意进程内存 |
| **完整性影响** | None - 只读漏洞 |
| **可用性影响** | High - 可通过 SIGSEGV 导致崩溃 |

**CVSS v3.1 评分**: 8.6 (High) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H

## 根本原因分析

该漏洞源于一个基本的设计问题：

1. **缺少大小参数**：`Tensor` 构造函数接受 `void* data` 但没有 `size_t bufferSize` 参数来针对计算的 `totalBytes` 进行验证。

2. **无验证的信任**：代码信任调用者提供正确大小的 buffer，但无法验证这一点。

3. **信息流不一致**：shape 信息从用户输入流经整个流水线，但实际 buffer 大小信息在 Python-C++ 边界丢失。

**漏洞设计模式**：
```
用户输入 (shape) → 信任 → 计算 totalBytes → 读取那么多字节
                                        ↑
                                   无针对实际 buffer 的验证
```

## 建议

### 立即修复（高优先级）

1. **向构造函数添加 Buffer 大小参数**：

```cpp
// 修改 Tensor 构造函数签名
Tensor::Tensor(void* data, size_t bufferSize, const std::vector<size_t>& shape, 
               DataType dataType, TensorFormat format, const char* device)
{
    CheckTensorParams();
    FillAuxInfo();
    // 验证 buffer 大小
    if (auxInfo_.totalBytes > bufferSize) {
        LogError << "Buffer size mismatch: shape requires " << auxInfo_.totalBytes 
                 << " bytes but only " << bufferSize << " provided.";
        throw std::runtime_error("Buffer size mismatch");
    }
}
```

2. **在 Python 绑定层验证**：

```cpp
// 在 PyUtil.cpp: GetNumpyData()
NumpyData GetNumpyData(PyObject* pyObj)
{
    // ... 现有代码 ...
    
    // 添加：获取 strides 信息以验证 buffer
    PyObject *stridesTuple = PyDict_GetItemString(arrayInterface, "strides");
    // 从 shape 和 strides 计算实际 buffer 大小
    
    // 添加：验证 buffer 是否足够大
    size_t requiredSize = CalculateRequiredSize(numpyData.shape, numpyData.dataType);
    // 注意：这仍然不能完全解决问题，因为仅从 __array_interface__ 无法知道实际 buffer 大小
    // 需要添加显式的大小参数
}
```

### 短期修复（中优先级）

3. **添加具有边界检查的安全 Clone 方法**：

```cpp
ErrorCode Tensor::CloneWithValidation(Tensor& tensor, size_t knownBufferSize) const
{
    if (auxInfo_.totalBytes > knownBufferSize) {
        LogError << "Clone rejected: buffer undersized";
        return ERR_INVALID_PARAM;
    }
    return Clone(tensor);
}
```

4. **添加 Python 级验证**：

```python
# 在 tensor_wrapper.py
@staticmethod
def from_numpy(array: np.ndarray) -> "Tensor":
    # 验证 array 是否连续并拥有其数据
    if not array.flags['C_CONTIGUOUS']:
        array = np.ascontiguousarray(array)
    
    # 计算预期大小
    expected_size = array.nbytes
    
    # 传递大小到 C++ 进行验证
    return _acc.Tensor.from_numpy_with_size(array, expected_size)
```

### 长期修复（低优先级）

5. **重新设计内存所有权模型**：

考虑使用包含大小信息的 RAII-based buffer 包装器：

```cpp
class TensorBuffer {
    void* data_;
    size_t size_;
public:
    TensorBuffer(size_t size) : size_(size) {
        data_ = new char[size];
    }
    size_t size() const { return size_; }
    // ...
};

// Tensor 获取 TensorBuffer 的所有权，而不是原始 void*
Tensor::Tensor(TensorBuffer&& buffer, const std::vector<size_t>& shape, ...);
```

## 相关漏洞

在此代码库中无直接相关的漏洞，但类似模式可能存在于：
- Image 模块 (`Image::Image` 使用 buffer 指针)
- Video 模块 (video frame buffers)

## 参考文献

- CWE-125: 越界读取
- [OWASP Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
- [NIST CWE-125](https://cwe.mitre.org/data/definitions/125.html)

## 附录：文件引用

| 文件 | 行号 | 目的 |
|------|-------|---------|
| `AccSDK/source/tensor/Tensor.cpp` | 83-93 | Tensor 构造函数 (漏洞点) |
| `AccSDK/source/tensor/Tensor.cpp` | 108-129 | Clone 方法 (sink) |
| `AccSDK/source/tensor/Tensor.cpp` | 37-60 | FillAuxInfo (大小计算) |
| `AccSDK/source/tensor/Tensor.cpp` | 62-81 | CheckTensorParams (缺少大小检查) |
| `AccSDK/source/py/module/PyTensor.cpp` | 99-106 | Python 绑定入口点 |
| `AccSDK/source/py/module/PyUtil.cpp` | 47-137 | Numpy 数据提取 |
| `AccSDK/source/py/module/PyImage.cpp` | 158-203 | Image::from_numpy (类似模式) |
| `AccSDK/include/acc/tensor/Tensor.h` | 96-97 | 构造函数声明

(文件结束 - 共 350 行)