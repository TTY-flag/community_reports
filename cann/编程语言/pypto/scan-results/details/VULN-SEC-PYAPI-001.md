# VULN-SEC-PYAPI-001: Python API Passes Arbitrary Pointer to C++ Backend

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-PYAPI-001 |
| **类型** | 内存损坏 (Memory Corruption) |
| **CWE** | CWE-119: Improper Restriction of Operations within Bounds |
| **严重性** | Critical |
| **置信度** | 85 |
| **状态** | CONFIRMED |
| **发现者** | security-auditor |

## 漏洞位置

| 文件 | 行号 | 函数 |
|------|------|------|
| python/pypto/runtime.py | 70-81 | _pto_to_tensor_data |

## 漏洞性质

此漏洞是 **VULN-DF-MEM-001 攻击链的 Python 层入口点**。它负责将用户提供的 Tensor 对象转换为 C++ 可接受的 DeviceTensorData，但没有验证 data_ptr 的有效性。

## 关联漏洞

- **VULN-DF-MEM-001**: 攻击链主漏洞
- **VULN-DF-MEM-002**: pybind11 绑定入口
- **VULN-SEC-BIND-001**: C++ 层漏洞
- **VULN-DF-MEM-005**: Sink 点

## 漏洞代码

```python
# runtime.py:70-81
def _pto_to_tensor_data(tensors: List[pypto.Tensor]) -> List[pypto_impl.DeviceTensorData]:
    datas = []
    for t in tensors:
        if t.ori_shape is None:
            raise PyptoRtError(RuntimeError("The ori_shape of the tensor is not specified."))
        data = pypto_impl.DeviceTensorData(
            t.dtype,
            t.data_ptr,       # ← 直接传递，无验证
            list(t.ori_shape),
        )
        datas.append(data)
    return datas
```

## 问题分析

### 1. 输入类型不限制

函数接受 `List[pypto.Tensor]`，但没有验证：
- Tensor 是否来自有效的来源
- data_ptr 是否是真实的数据指针
- Tensor 对象是否被恶意构造

### 2. 无验证直接传递

`t.data_ptr` 直接传递给 C++，没有任何验证步骤：

```python
# 攻击者可以构造虚假的 Tensor
class FakeTensor:
    dtype = pypto.DT_FP16
    data_ptr = 0xdeadbeef  # 任意地址
    ori_shape = [1024, 1024]

# _pto_to_tensor_data 会接受这个假 Tensor
fake = FakeTensor()
datas = _pto_to_tensor_data([fake])  # 通过！
# datas[0].GetDataPtr() == 0xdeadbeef
```

### 3. 类型检查薄弱

代码只检查 `ori_shape` 是否为 None，不检查 data_ptr：

```python
if t.ori_shape is None:
    raise PyptoRtError(...)  # 只检查 shape
# 没有检查 data_ptr 的有效性！
```

## 利用场景

### 场景1: 恶意 Tensor 类

```python
import pypto
import pypto_impl

# 构造恶意 Tensor 类，模拟 pypto.Tensor 接口
class MaliciousTensor:
    """伪装成 pypto.Tensor 的恶意对象"""
    dtype = pypto.DT_UINT8
    data_ptr = 0xsecret_kernel_address  # 目标地址
    ori_shape = [4096]

# 调用 verify 或其他使用 _pto_to_tensor_data 的函数
malicious_input = MaliciousTensor()
pypto.verify(
    func=my_func,
    inputs=[malicious_input],
    outputs=[valid_output],
    goldens=[valid_golden]
)
# C++ 层将使用 0xsecret_kernel_address 进行内存操作
```

### 场景2: 覆盖 pypto.Tensor 属性

```python
import pypto

# 创建正常 Tensor
tensor = pypto.Tensor(pypto.DT_FP16, [1024])

# Python 动态语言，可以修改属性
tensor.data_ptr = 0xattacker_address  # 替换为恶意地址

# 调用 API
pypto_impl.DeviceRunOnceDataFromHost(
    _pto_to_tensor_data([tensor]), []
)
# 现在 tensor.data_ptr 是攻击者指定的地址
```

### 场景3: 通过 verify 函数利用

```python
def verify(func, inputs, outputs, goldens, *args, ...):
    # ...
    pypto_impl.SetVerifyData(
        _pto_to_tensor_data(inputs),   # ← inputs 通过这里
        _pto_to_tensor_data(outputs),
        _pto_to_tensor_data(goldens),
    )
    # ...

# 所有三个参数都可以传入恶意 Tensor
malicious_tensors = [MaliciousTensor() for _ in range(3)]
pypto.verify(func, malicious_tensors, malicious_tensors, malicious_tensors)
```

## 完整调用路径

```
pypto.verify()
    ↓
SetVerifyData(inputs, outputs, goldens)
    ↓
_pto_to_tensor_data(inputs)   [此漏洞]
    ↓
DeviceTensorData(dtype, data_ptr, shape)
    ↓
RawTensorData::CreateTensor(addr)
    ↓
StringUtils::DataCopy(..., addr, ...)  ← 任意内存访问
```

## 安全影响

| 影响层面 | 说明 |
|----------|------|
| **Python 层** | 攻击者在 Python 层即可构造攻击 |
| **类型系统** | Python 动态类型绕过静态检查 |
| **信任传递** | Python → C++ 信任链无中断 |
| **API 广泛使用** | verify、DeviceRunOnceDataFromHost 等多个 API 使用此函数 |

## 修复建议

### 方案1: 类型白名单

```python
def _pto_to_tensor_data(tensors: List[pypto.Tensor]) -> List[pypto_impl.DeviceTensorData]:
    datas = []
    for t in tensors:
        # 严格类型检查
        if not isinstance(t, (torch.Tensor, pypto.Tensor)):
            raise PyptoRtError(TypeError(f"Expected torch.Tensor or pypto.Tensor, got {type(t)}"))
        
        # 验证 ori_shape
        if t.ori_shape is None:
            raise PyptoRtError(RuntimeError("The ori_shape is not specified."))
        
        # 新增: 验证 data_ptr 来自有效 Tensor
        validated_ptr = validate_and_get_data_ptr(t)
        
        data = pypto_impl.DeviceTensorData(
            t.dtype,
            validated_ptr,  # 验证后的指针
            list(t.ori_shape),
        )
        datas.append(data)
    return datas
```

### 方案2: 只接受 torch.Tensor

```python
def _pto_to_tensor_data(tensors: List[torch.Tensor]) -> List[pypto_impl.DeviceTensorData]:
    """只接受 torch.Tensor，使用其内置的 data_ptr"""
    datas = []
    for t in tensors:
        if not isinstance(t, torch.Tensor):
            raise PyptoRtError(TypeError(f"Only torch.Tensor is accepted"))
        
        # torch.Tensor.data_ptr() 是可信的
        data = pypto_impl.DeviceTensorData(
            dtype_from_torch(t.dtype),
            t.data_ptr(),  # torch.Tensor 提供验证过的指针
            list(t.shape),
        )
        datas.append(data)
    return datas
```

### 方案3: 注册机制

```python
# 建立 Tensor 注册表
_valid_tensors = WeakSet()

def register_valid_tensor(tensor):
    """注册验证过的 Tensor"""
    _valid_tensors.add(tensor)

def _pto_to_tensor_data(tensors):
    datas = []
    for t in tensors:
        # 检查 Tensor 是否在注册表中
        if t not in _valid_tensors:
            raise PyptoRtError(ValueError("Tensor not registered as valid"))
        
        data = pypto_impl.DeviceTensorData(t.dtype, t.data_ptr, list(t.ori_shape))
        datas.append(data)
    return datas
```

## 修复验证

```python
# 测试1: 假 Tensor 应被拒绝
class FakeTensor:
    dtype = pypto.DT_FP16
    data_ptr = 0xdeadbeef
    ori_shape = [1024]

try:
    _pto_to_tensor_data([FakeTensor()])
    assert False, "Should reject fake tensor"
except TypeError:
    pass  # 正确

# 测试2: torch.Tensor 应通过
import torch
t = torch.randn(1024, dtype=torch.float16)
datas = _pto_to_tensor_data([t])
assert len(datas) == 1
```

## 参考链接

- CWE-119: Buffer Bounds Violation
- Python 类型安全最佳实践
- VULN-DF-MEM-001 主漏洞分析