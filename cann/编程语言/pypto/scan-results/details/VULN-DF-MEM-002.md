# VULN-DF-MEM-002: DeviceTensorData pybind11 Arbitrary Address Entry Point

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-MEM-002 |
| **类型** | 内存损坏 (Memory Corruption) |
| **CWE** | CWE-125: Out-of-bounds Read |
| **严重性** | Critical |
| **置信度** | 85 |
| **状态** | CONFIRMED |
| **发现者** | dataflow-scanner |

## 漏洞位置

| 文件 | 行号 | 函数 |
|------|------|------|
| python/src/bindings/runtime.cpp | 1042-1048 | BindRuntime |

## 漏洞性质

此漏洞是 **VULN-DF-MEM-001 攻击链的入口点**。它允许 Python 用户直接创建包含任意内存地址的 DeviceTensorData 对象，该地址随后被用于设备执行时的内存操作。

## 关联漏洞

- **VULN-DF-MEM-001**: 攻击链的主要 Sink 点
- **VULN-SEC-BIND-001**: 同类型漏洞的另一发现
- **VULN-SEC-PYAPI-001**: Python 层入口点
- **VULN-DF-MEM-005**: 最终的内存操作点

## 漏洞代码

```cpp
// runtime.cpp:1042-1048
py::class_<DeviceTensorData>(m, "DeviceTensorData")
    .def(
        py::init<DataType, uintptr_t, const std::vector<int64_t>&>(), 
        py::arg("dtype"), 
        py::arg("addr"),   // ← uintptr_t 直接从 Python 传入
        py::arg("shape")
    )
    .def("GetDataPtr", &DeviceTensorData::GetAddr)
    .def("GetShape", &DeviceTensorData::GetShape)
    .def("GetDataType", &DeviceTensorData::GetDataType);
```

## 问题分析

### 1. 类型转换无验证

`uintptr_t addr` 是一个整数类型，可以表示任意地址值。pybind11 自动将 Python `int` 转换为 `uintptr_t`，无需任何验证：

```python
# Python 端可以传入任意整数
data = pypto_impl.DeviceTensorData(
    pypto.DT_FP16,
    0xdeadbeef,     # ← 任意地址值，无需是有效指针
    [1024, 1024]
)
```

### 2. 构造函数直接赋值

```cpp
// device_launcher_binding.h:41-44
DeviceTensorData(DataType dtype, uintptr_t addr, const std::vector<int64_t>& shape)
    : dtype_(dtype), addr_((void*)addr), shape_(shape)  // ← 直接转换
{}
```

没有任何验证：
- 地址是否在有效内存范围
- 地址是否属于已知 Tensor 对象
- 地址是否对齐
- 地址是否有读写权限

### 3. 跨语言边界安全缺失

从 Python (动态类型) 到 C++ (静态类型) 的转换中，pybind11 默认信任用户提供的数据。对于指针类型，这是极其危险的。

## 利用方式

### 直接调用

```python
import pypto_impl

# 直接传入任意地址
malicious_addr = 0x7fff12340000
fake_tensor = pypto_impl.DeviceTensorData(
    pypto_impl.DT_FP16,
    malicious_addr,
    [1024, 1024]
)

# 地址被存储，后续使用时触发内存操作
addr = fake_tensor.GetDataPtr()  # 返回 0x7fff12340000
```

### 结合 DeviceRunOnceDataFromHost

```python
# 构造恶意输入向量
inputs = [
    pypto_impl.DeviceTensorData(pypto_impl.DT_UINT8, 0xsecret_address, [4096])
]

# 调用会触发内存读取
pypto_impl.DeviceRunOnceDataFromHost(inputs, [])
# 内部执行: RawTensorData::CreateTensor(dtype, shape, (uint8_t*)0xsecret_address)
```

## 安全影响

| 影响类型 | 说明 |
|----------|------|
| **攻击入口** | 这是整个攻击链的起点 |
| **信任边界突破** | Python 用户突破到 C++ 内存空间 |
| **直接危害** | 单独使用也可导致问题，但主要作为攻击链组件 |

## 修复建议

### 方案1: 取消裸指针接口

完全移除 `uintptr_t` 构造函数，改为接受 Tensor 对象：

```cpp
// 不再暴露 uintptr_t 构造函数
py::class_<DeviceTensorData>(m, "DeviceTensorData")
    .def(py::init([](py::object tensor_obj) {
        // 从 torch.Tensor 或其他验证过的对象提取地址
        return ExtractValidatedDeviceTensorData(tensor_obj);
    }))
```

### 方案2: 添加地址验证钩子

```cpp
py::class_<DeviceTensorData>(m, "DeviceTensorData")
    .def(py::init([](DataType dtype, uintptr_t addr, const std::vector<int64_t>& shape) {
        // 验证函数
        if (!ValidateAddress(addr, dtype, shape)) {
            throw py::value_error("Invalid memory address for DeviceTensorData");
        }
        return std::make_unique<DeviceTensorData>(dtype, addr, shape);
    }),
    py::arg("dtype"), py::arg("addr"), py::arg("shape"));
```

### 方案3: 限制地址范围

```cpp
bool ValidateAddress(uintptr_t addr, DataType dtype, const std::vector<int64_t>& shape) {
    // 检查地址在已知内存池范围内
    auto pool_start = TensorMemoryPool::GetBaseAddress();
    auto pool_end = pool_start + TensorMemoryPool::GetSize();
    
    size_t required_size = ComputeTensorSize(dtype, shape);
    
    if (addr < pool_start || addr + required_size > pool_end) {
        return false;  // 地址不在有效范围
    }
    
    return true;
}
```

## 修复优先级

| 优先级 | 建议 |
|--------|------|
| **P0** | 取消裸指针接口，只接受验证过的 Tensor 对象 |
| **P1** | 添加地址白名单验证 |
| **P2** | 在文档中明确标记此接口的危险性 |

## 验证测试

修复后应通过以下测试：

```python
# 测试1: 任意地址应被拒绝
try:
    data = pypto_impl.DeviceTensorData(DT_FP16, 0xdeadbeef, [1024])
    assert False, "Should have raised exception"
except ValueError:
    pass  # 正确抛出异常

# 测试2: 有效地址应通过
valid_tensor = torch.randn(1024, dtype=torch.float16)
data = pypto_impl.DeviceTensorData(DT_FP16, valid_tensor.data_ptr(), [1024])
assert data.GetDataPtr() == valid_tensor.data_ptr()
```

## 参考链接

- CWE-125: Out-of-bounds Read
- pybind11 安全最佳实践