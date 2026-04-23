# VULN-DF-MEM-004：Tensor构造函数未验证data_ptr指针

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-DF-MEM-004 |
| **类型** | 内存损坏 (Memory Corruption) |
| **CWE** | CWE-125: Out-of-bounds Read |
| **严重性** | High |
| **置信度** | 80 |
| **状态** | CONFIRMED |
| **发现者** | dataflow-scanner |

## 漏洞位置

| 文件 | 行号 | 函数 |
|------|------|------|
| python/src/bindings/tensor.cpp | 51-66 | BindTensor |

## 漏洞性质

此漏洞是一个**独立的内存读取漏洞**。Python 用户可以通过 Tensor 的 pybind11 构造函数传入任意 `uint8_t* data_ptr`，该指针后续被用于 Tensor 的数据操作。

## 漏洞代码

```cpp
// tensor.cpp:51-66
py::class_<Tensor>(m, "Tensor")
    // ...
    .def(
        py::init<DataType, std::vector<int64_t>, uint8_t*, std::string, TileOpFormat>(),
        py::arg("dtype"),
        py::arg("shape"),
        py::arg("data_ptr"),  // ← uint8_t* 来自 Python
        py::arg("name"),
        py::arg("format") = TileOpFormat::TILEOP_ND
    )
    .def(
        py::init<DataType, std::vector<int64_t>, uint8_t*, std::string, TileOpFormat>(),
        py::arg("dtype"),
        py::arg("shape"),
        py::arg("data_ptr"),  // ← 重复定义，同样危险
        py::arg("name"),
        py::arg("format") = TileOpFormat::TILEOP_ND
    )
```

## 问题分析

### 1. uint8_t* 指针直接接受

pybind11 支持从 Python 传递指针到 C++：
- Python 整数 → `uint8_t*`
- 无地址验证
- 无所有权检查

```python
# Python 端
import pypto

# 传入任意地址作为 data_ptr
tensor = pypto.Tensor(
    pypto.DT_UINT8,
    [1024],
    0xdeadbeef,  # ← 整数被解释为指针
    "malicious_tensor"
)

# tensor 内部存储了 0xdeadbeef 作为数据指针
```

### 2. 与其他构造函数对比

```cpp
// tensor.cpp:25-49 - 安全的构造函数
py::class_<Tensor>(m, "Tensor")
    .def(py::init<>())  // 默认构造，无指针
    .def(
        py::init([](DataType dtype, const py::sequence& shape, ...) {
            // 从 shape 创建，不接受 data_ptr
            return std::make_unique<Tensor>(dtype, int_shape, name, format);
        }),
        // ...
    )

// tensor.cpp:51-66 - 危险的构造函数
    .def(
        py::init<DataType, std::vector<int64_t>, uint8_t*, std::string, TileOpFormat>(),
        // 直接接受 uint8_t*，无验证
    )
```

### 3. 重复定义

注意代码中**两次定义了相同的危险构造函数**（第 51-53 行和第 64-66 行）。这可能是复制粘贴错误，但增加了暴露面。

### 4. Tensor 内部使用

虽然 Tensor 类主要用于编译阶段，但如果内部代码使用 `data_ptr`：
- 读取数据：信息泄露
- 写入数据：内存破坏

## 与攻击链漏洞的区别

| 特征 | MEM-004 | MEM-001 攻击链 |
|------|---------|---------------|
| **漏洞位置** | Tensor.cpp | Runtime.cpp |
| **类** | Tensor | DeviceTensorData |
| **数据流阶段** | 编译阶段 | 执行阶段 |
| **直接危害** | 有限（编译阶段） | 直接（执行阶段） |
| **利用复杂度** | 中 | 低 |
| **组合价值** | 可组合成更大攻击 | 独立严重 |

## 利用场景

### 场景 1: 编译阶段信息泄露

```python
import pypto

# 创建指向敏感地址的 Tensor
secret_addr = find_sensitive_data_address()
leak_tensor = pypto.Tensor(
    pypto.DT_UINT8,
    [1024],
    secret_addr,
    "leak"
)

# 如果编译过程读取 Tensor 数据
# 可能泄露 secret_addr 处的内容
```

### 场景 2: 组合攻击

```python
# MEM-004 提供创建恶意 Tensor 的能力
# MEM-001/002 提供执行 Tensor 的能力

# 步骤 1: 使用 MEM-004 创建恶意 Tensor
malicious_tensor = pypto.Tensor(
    pypto.DT_UINT8,
    [4096],
    target_memory_address,
    "combined_attack"
)

# 步骤 2: 将 Tensor 转换为 DeviceTensorData
# 通过 MEM-001 的攻击链执行
```

### 场景 3: 通过 pypto.from_torch 绑定

```python
import pypto

class FakeTorchTensor:
    """伪装 torch.Tensor"""
    dtype = None
    shape = [1024]
    data_ptr = lambda self: 0xdeadbeef  # 返回恶意地址
    
fake_tensor = FakeTorchTensor()
pto_tensor = pypto.from_torch(fake_tensor)

# 如果 from_torch 使用 data_ptr()
# pto_tensor 内部存储了恶意指针
```

## Tensor 类用途分析

根据代码，Tensor 类主要用于：
1. **编译阶段**：表示计算图中的张量
2. **符号计算**：可能不需要实际数据
3. **形状推断**：主要关注 shape

但如果某些操作确实访问 `data_ptr`：
- `GetTensorData()` 函数
- `SetTensorData()` 函数
- 其他内部操作

## 代码中的 Tensor 数据访问

```cpp
// tensor.cpp:194-201
m.def(
    "GetTensorData",
    [](const Tensor& t, std::vector<SymbolicScalar> offset) {
        if (t.IsEmpty()) {
            throw py::value_error("Empty tensor.");
        }
        return npu::tile_fwk::GetTensorData(t, offset);  // ← 可能访问数据
    },
    // ...
)
```

如果 `GetTensorData` 内部访问 `data_ptr`，则 MEM-004 可被直接利用。

## 影响范围

| 影响 | 说明 |
|------|------|
| **编译阶段泄露** | 如果编译器读取 Tensor 数据 |
| **组合攻击能力** | 可与 MEM-001 组合 |
| **API 暴露** | 构造函数直接暴露给 Python |
| **信任边界突破** | Python → C++ 指针传递 |

## 修复建议

### 方案 1: 移除危险的构造函数

```cpp
// 只保留安全的构造函数
py::class_<Tensor>(m, "Tensor")
    .def(py::init<>())
    .def(
        py::init([](DataType dtype, const py::sequence& shape, 
                   const std::string& name, TileOpFormat format) {
            // 从 shape 创建，不接受外部指针
            return std::make_unique<Tensor>(dtype, shape, name, format);
        }),
        py::arg("dtype"), py::arg("shape"), py::arg("name") = "", 
        py::arg("format") = TileOpFormat::TILEOP_ND
    )
    // 移除所有 uint8_t* data_ptr 构造函数
```

### 方案 2: 使用 torch.Tensor 包装

```cpp
// 只接受 torch.Tensor，使用其验证过的 data_ptr
py::class_<Tensor>(m, "Tensor")
    .def(
        py::init([](py::object torch_tensor, const std::string& name) {
            // 从 torch.Tensor 创建，确保数据有效性
            if (!py::hasattr(torch_tensor, "data_ptr")) {
                throw py::value_error("Invalid tensor object");
            }
            auto dtype = ConvertTorchDtype(torch_tensor.attr("dtype"));
            auto shape = torch_tensor.attr("shape").cast<std::vector<int64_t>>();
            auto data_ptr = torch_tensor.attr("data_ptr").cast<uintptr_t>();
            
            // 验证 torch_tensor 的有效性
            ValidateTorchTensor(torch_tensor);
            
            return std::make_unique<Tensor>(dtype, shape, (uint8_t*)data_ptr, name);
        }),
        py::arg("torch_tensor"), py::arg("name") = ""
    )
```

### 方案 3: 添加指针验证

```cpp
py::class_<Tensor>(m, "Tensor")
    .def(
        py::init([](DataType dtype, std::vector<int64_t> shape, 
                   uintptr_t addr, std::string name, TileOpFormat format) {
            // 验证地址
            if (addr != 0 && !ValidateMemoryAddress(addr, shape, dtype)) {
                throw py::value_error("Invalid data_ptr address");
            }
            return std::make_unique<Tensor>(dtype, shape, (uint8_t*)addr, name, format);
        }),
        py::arg("dtype"), py::arg("shape"), py::arg("data_ptr"),
        py::arg("name") = "", py::arg("format") = TileOpFormat::TILEOP_ND
    )

bool ValidateMemoryAddress(uintptr_t addr, const std::vector<int64_t>& shape, DataType dtype) {
    size_t required_size = ComputeSize(shape, dtype);
    // 检查地址是否在有效的内存区域
    auto regions = GetValidMemoryRegions();
    for (const auto& region : regions) {
        if (addr >= region.start && addr + required_size <= region.end) {
            return true;
        }
    }
    return false;
}
```

### 方案 4: 标记为内部 API

```cpp
// 使用 py::kw_only 和内部标记
py::class_<Tensor>(m, "Tensor")
    .def(
        py::init<DataType, std::vector<int64_t>, uint8_t*, std::string, TileOpFormat>(),
        py::arg("dtype"), py::arg("shape"), py::arg("_internal_data_ptr"),
        py::arg("name") = "", py::arg("format") = TileOpFormat::TILEOP_ND
    )
    // 在文档中明确标记为内部 API，不应由用户直接调用
```

## 修复优先级

| 优先级 | 建议 |
|--------|------|
| **P0** | 移除重复的危险构造函数定义 |
| **P1** | 添加指针验证逻辑 |
| **P2** | 改为只接受 torch.Tensor |
| **P3** | 标记为内部 API，添加文档警告 |

## 验证测试

```python
# 测试 1: 任意地址应被拒绝
try:
    tensor = pypto.Tensor(pypto.DT_UINT8, [1024], 0xdeadbeef, "test")
    # 如果修复后，应该抛出异常
    assert False, "Should reject invalid address"
except (ValueError, RuntimeError):
    pass  # 正确拒绝

# 测试 2: 有效地址应被接受
import torch
valid_tensor = torch.randn(1024, dtype=torch.uint8)
addr = valid_tensor.data_ptr()
pto_tensor = pypto.Tensor(pypto.DT_UINT8, [1024], addr, "valid")
assert pto_tensor is not None

# 测试 3: null 指针应被允许或明确处理
null_tensor = pypto.Tensor(pypto.DT_UINT8, [1024], 0, "null")
# 代码应该明确处理 null 情况
```

## 参考链接

- CWE-125: Out-of-bounds Read
- pybind11 安全指针处理
- VULN-DF-MEM-001 主攻击链漏洞
- Python-C++ 指针传递安全指南