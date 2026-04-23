# VULN-DF-MEM-005: RawTensorData::CreateTensor Unvalidated Pointer Sink

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-MEM-005 |
| **类型** | 内存损坏 (Memory Corruption) |
| **CWE** | CWE-125: Out-of-bounds Read |
| **严重性** | Critical |
| **置信度** | 85 |
| **状态** | CONFIRMED |
| **发现者** | dataflow-scanner |

## 漏洞位置

| 文件 | 行号 | 函数 |
|------|------|------|
| framework/src/interface/interpreter/raw_tensor_data.h | 317-322 | RawTensorData::CreateTensor |

## 漏洞性质

此漏洞是 **VULN-DF-MEM-001 攻击链的最终 Sink 点**。所有从 Python 传入的恶意地址最终汇聚于此，执行实际的内存拷贝操作。

## 关联漏洞

- **VULN-DF-MEM-001**: 攻击链主漏洞 (同一数据流终点)
- **VULN-DF-MEM-002**: 入口点
- **VULN-SEC-PYAPI-001**: Python API 入口
- **VULN-SEC-BIND-001**: C++ 绑定层

## 漏洞代码

```cpp
// raw_tensor_data.h:317-322
static std::shared_ptr<RawTensorData> CreateTensor(
    DataType dtype, 
    const std::vector<int64_t>& shape, 
    uint8_t* data)  // ← 来自 Python 的任意指针
{
    auto tensorData = std::make_shared<RawTensorData>(dtype, shape);
    StringUtils::DataCopy(
        tensorData->data(),        // 目标: 新创建的缓冲区
        tensorData->GetDataSize(), // 拷贝大小
        data,                      // 源: 用户提供的任意地址 ← 危险！
        tensorData->GetDataSize()
    );
    return tensorData;
}
```

## 问题分析

### 1. 指针来源不可信

`data` 参数来自调用链：

```
Python data_ptr → DeviceTensorData → InitializeInputOutputData → CreateTensor
```

整个链条中没有任何验证，最终指针是 Python 用户提供的任意值。

### 2. 直接 memcpy 调用

`StringUtils::DataCopy` 内部调用 `memcpy`:

```cpp
void StringUtils::DataCopy(void* dst, size_t dst_size, const void* src, size_t src_size) {
    // 无边界检查
    memcpy(dst, src, std::min(dst_size, src_size));
}
```

如果 `src` (来自 Python) 是无效地址：
- 读访问违规 → 进程崩溃
- 读到敏感数据 → 信息泄露
- 读到内核地址 → 权限提升尝试

### 3. 大小由用户控制

`tensorData->GetDataSize()` 由 `shape` 参数计算：

```cpp
size_t GetDataSize() const {
    return static_cast<size_t>(nelem) * static_cast<size_t>(elemSize_);
}
```

`nelem` 是 shape 各维度乘积，`elemSize_` 是 dtype 的字节大小。两者都由 Python 用户控制，可指定任意大的读取量。

### 4. 跨模块调用

此函数位于 `interface` 模块，被 `bindings` 模块调用，跨越模块边界时无安全检查。

## 实际执行路径

### 输入处理

```cpp
// runtime.cpp:126-130 (SetVerifyData)
for (size_t i = 0; i < inputs.size(); i++) {
    auto logicalShape = ToLogicalShape(inputs[i].GetDataType(), inputs[i].GetShape());
    auto rawData = RawTensorData::CreateTensor(
        inputs[i].GetDataType(), 
        logicalShape, 
        (uint8_t*)inputs[i].GetAddr()  // ← 恶意地址传入
    );
    ProgramData::GetInstance().AppendInput(rawData);
}
```

### 数据拷贝发生

调用 `CreateTensor` 时立即执行拷贝：

```
CreateTensor(addr)
    → make_shared<RawTensorData>(dtype, shape)  // 分配目标缓冲区
    → DataCopy(dst, size, addr, size)           // 从 addr 读取 size 字节
        → memcpy(dst, addr, size)               // 实际内存拷贝
```

如果 `addr = 0xdeadbeef`，进程尝试从该地址读取 `size` 字节。

## 利用分析

### 读任意地址

```python
# Python 端
data_ptr = 0x7fff12340000  # 目标地址
shape = [1024 * 1024]      # 读取 1MB
dtype = pypto.DT_UINT8     # 每元素 1 字节

# C++ 执行
# RawTensorData::CreateTensor(DT_UINT8, [1048576], (uint8_t*)0x7fff12340000)
# → DataCopy(dst, 1048576, 0x7fff12340000, 1048576)
# → memcpy(dst, 0x7fff12340000, 1048576)
```

### 读内核地址 (如果可访问)

```python
# 尝试读取内核空间
kernel_addr = 0xffff800000000000  # Linux 内核地址范围
shape = [4096]

# 触发读取
# 可能崩溃，或读取内核数据（取决于权限）
```

### 读敏感数据

```python
# 目标: 读取进程中存储的密钥
secret_addr = FindSecretKeyAddress()  # 通过其他漏洞获取地址
shape = [256]  # 密钥通常较小

# 执行后，输入 Tensor 包含密钥内容
```

## 系统级影响

| 影响 | 说明 |
|------|------|
| **进程崩溃** | 无效地址导致 SIGSEGV |
| **信息泄露** | 读取进程内存中的任意数据 |
| **跨进程读取** | 如果地址指向共享内存 |
| **内核交互** | 尝试读取内核地址可能触发安全机制 |

## 修复建议

### 方案1: 地址验证

```cpp
static std::shared_ptr<RawTensorData> CreateTensor(
    DataType dtype, const std::vector<int64_t>& shape, uint8_t* data)
{
    // 新增: 验证地址有效性
    size_t size = ComputeSize(dtype, shape);
    if (!ValidateMemoryAddress(data, size)) {
        throw std::invalid_argument("Invalid source address for CreateTensor");
    }
    
    auto tensorData = std::make_shared<RawTensorData>(dtype, shape);
    StringUtils::DataCopy(tensorData->data(), tensorData->GetDataSize(), data, tensorData->GetDataSize());
    return tensorData;
}
```

### 方案2: 安全 DataCopy

```cpp
void StringUtils::SafeDataCopy(void* dst, size_t dst_size, const void* src, size_t src_size) {
    // 使用 safe_memcpy 或 read() syscall
    // 验证 src 可读
    if (src == nullptr || !IsReadable(src, src_size)) {
        throw MemoryAccessException("Source memory not accessible");
    }
    memcpy(dst, src, std::min(dst_size, src_size));
}
```

### 方案3: 传递 Tensor 对象而非指针

修改接口，不接受裸指针：

```cpp
template<typename TensorType>
static std::shared_ptr<RawTensorData> CreateTensorFromValidated(TensorType& tensor) {
    // tensor 对象提供验证过的数据访问
    return CreateTensor(tensor.GetDataType(), tensor.GetShape(), tensor.GetValidatedData());
}
```

## 边界检查实现示例

```cpp
bool ValidateMemoryAddress(const void* addr, size_t size) {
    // 检查地址是否在已知内存区域
    auto regions = GetKnownMemoryRegions();
    uintptr_t addr_val = reinterpret_cast<uintptr_t>(addr);
    
    for (const auto& region : regions) {
        if (addr_val >= region.start && addr_val + size <= region.end) {
            return true;  // 地址在有效范围内
        }
    }
    return false;  // 地址不在任何已知区域
}
```

## 参考链接

- CWE-125: Out-of-bounds Read
- VULN-DF-MEM-001 主漏洞分析
- memcpy 安全使用指南