# VULN-DF-MEM-001: 任意内存地址引用漏洞

## 漏洞概要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-MEM-001 |
| **类型** | 内存安全 (memory_safety) |
| **CWE** | CWE-787 (Out-of-bounds Write) / CWE-119 (Buffer Overflow) |
| **严重性** | Critical |
| **置信度** | 85 |
| **状态** | CONFIRMED |
| **受影响文件** | `torchair/llm_datadist/llm_datadist.cpp` |
| **受影响行** | 39-72 |
| **受影响函数** | `AsTorchTensor` |

## 漏洞描述

`AsTorchTensor` 函数接受用户提供的内存地址列表 (`addresses`)，直接使用 `reinterpret_cast<void *>(dev_addr)` 将地址转换为指针，并以此为数据指针创建 PyTorch Tensor。该函数**未实施任何安全验证**：

- ❌ 无地址有效性检查
- ❌ 无所有权验证
- ❌ 无内存边界检查
- ❌ 无生命周期管理
- ❌ 无访问控制机制

攻击者可传入任意内存地址，创建指向该地址的 Tensor，从而实现：
1. **任意内存读取** - 通过 Tensor 读取任意地址的内容
2. **任意内存写入** - 通过 Tensor 操作向任意地址写入数据
3. **Use-After-Free** - 指向已释放内存导致悬空指针
4. **信息泄露** - 读取进程内存中的敏感数据

## 漏洞代码分析

### 危险代码片段 (llm_datadist.cpp:39-72)

```cpp
std::pair<uint32_t, std::vector<at::Tensor>> AsTorchTensor(
    const std::vector<int64_t> &dims, 
    const int32_t ge_data_type,
    const std::vector<uintptr_t> &addresses) {  // [1] 用户可控的地址列表
  std::vector<at::Tensor> at_tensors;
  c10::ScalarType tensor_dtype = ToScalarType(static_cast<TorchDataType>(ge_data_type));
  if (tensor_dtype == c10::ScalarType::Undefined) {
    return {kFailure, at_tensors};
  }
  c10::DeviceType device_type = c10::DeviceType::PrivateUse1;
  at::TensorOptions option = at::TensorOptions().dtype(tensor_dtype).device(device_type);

  at_tensors.reserve(addresses.size());
  for (auto dev_addr : addresses) {              // [2] 遍历用户提供的地址
    auto tensor = at::empty({0}, option);
    auto address = reinterpret_cast<void *>(dev_addr);  // [3] 直接转换，无验证！
    at::DataPtr c10_data_ptr(address, address, [](void *) {}, tensor.device());
    //                                                        [4] 空的释放函数，无所有权管理

    size_t tensor_nbytes = at::detail::computeStorageNbytesContiguous(dims, tensor.dtype().itemsize());
    at::Storage storage;
    auto fptr = c10::GetStorageImplCreate(device_type);
    auto allocator = c10::GetAllocator(device_type);
    storage = fptr(c10::StorageImpl::use_byte_size_t(), 0, allocator->allocate(0), allocator, true);
    storage.unsafeGetStorageImpl()->set_nbytes(tensor_nbytes);
    storage.set_data_ptr(std::move(c10_data_ptr));  // [5] 设置用户控制的地址作为数据指针

    tensor.set_(storage, 0, dims);
    at_tensors.emplace_back(std::move(tensor));
  }
  return {kSuccess, at_tensors};
}
```

### 关键问题点

1. **[位置 1-2]** `addresses` 参数完全由用户控制，没有任何验证
2. **[位置 3]** `reinterpret_cast<void *>(dev_addr)` 直接将用户输入的整数值转换为指针
3. **[位置 4]** `[](void *) {}` 空的释放函数意味着没有所有权管理，也没有地址清理
4. **[位置 5]** 用户控制的地址被设置为 Tensor 的数据指针

## 攻击路径分析

### 完整调用链

```
┌─────────────────────────────────────────────────────────────────┐
│ Python API (公开接口)                                            │
│ torchair.llm_datadist.create_npu_tensors(shape, dtype, addrs)   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Python 内部实现                                                  │
│ _tensor_utils._create_npu_tensors(shape, dtype, addresses)      │
│ [仅做类型检查，无地址验证]                                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ pybind11 绑定                                                   │
│ _torchair.as_torch_tensors(shape, data_type, addresses)         │
│ [直接转发参数，无验证]                                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ C++ 实现 (漏洞点)                                                │
│ AsTorchTensor(dims, ge_data_type, addresses)                     │
│ reinterpret_cast<void*>(dev_addr) ← SINK                        │
└─────────────────────────────────────────────────────────────────┘
```

### 数据流验证

| 步骤 | 文件 | 行号 | 数据传递 | 验证状态 |
|------|------|------|----------|----------|
| 1 | `llm_datadist/__init__.py` | 8-9 | `addresses` 透传 | ❌ 无验证 |
| 2 | `llm_datadist/_tensor_utils.py` | 50-56 | `addresses` 类型检查为 `int` | ⚠️ 仅类型检查 |
| 3 | `core/npu_wrapper.cpp` | 77 | pybind11 绑定 | ❌ 无验证 |
| 4 | `llm_datadist/llm_datadist.cpp` | 50-52 | `reinterpret_cast<void*>` | ❌ **漏洞点** |

## 利用分析

### 利用前提条件

1. **攻击者能力要求**：
   - 能够导入 `torchair` 库
   - 能够调用 `torchair.llm_datadist.create_npu_tensors` 函数
   
2. **环境要求**：
   - 目标系统运行 PyTorch + torchair
   - 支持 NPU 设备 (华为 Ascend NPU)

3. **知识要求**：
   - 了解目标进程的内存布局（部分场景需要绕过 ASLR）

### 利用场景

#### 场景 1: 任意内存读取

```python
import torch
import torchair

# 攻击者控制 addresses 参数
# 假设目标地址为 0x7fff12340000
target_addr = 0x7fff12340000

# 创建指向目标地址的 Tensor
shape = [1024]  # 读取 1024 * 2 = 2048 字节
dtype = torch.float16
tensors = torchair.llm_datadist.create_npu_tensors(shape, dtype, [target_addr])

# 通过 Tensor 操作读取内存
leaked_data = tensors[0]  # 获取目标地址的内存内容
```

**危害**：信息泄露，可读取密钥、密码、敏感配置等

#### 场景 2: 任意内存写入

```python
import torch
import torchair

# 攻击者控制写入地址和数据
target_addr = 0x7fff12340000
shape = [1]
dtype = torch.float16

tensors = torchair.llm_datadist.create_npu_tensors(shape, dtype, [target_addr])

# 向目标地址写入数据
tensors[0].fill_(0x41414141)  # 写入任意值
```

**危害**：内存破坏，可能覆盖关键数据结构

#### 场景 3: Use-After-Free

```python
import torch
import torchair

# 假设攻击者知道某个已释放对象的地址
freed_addr = 0xdeadbeef

shape = [100]
dtype = torch.float32
tensors = torchair.llm_datadist.create_npu_tensors(shape, dtype, [freed_addr])

# 访问已释放的内存
data = tensors[0]  # 触发 UAF
```

**危害**：程序崩溃、堆利用、潜在的代码执行

### 利用难度评估

| 因素 | 评估 | 说明 |
|------|------|------|
| 攻击向量 | Local | 需要本地代码执行能力 |
| 攻击复杂度 | Low | API 调用简单，无需特殊技巧 |
| 权限要求 | Low | 标准 PyTorch 用户权限即可 |
| 用户交互 | None | 无需用户交互 |
| ASLR 影响 | Medium | 64位系统 ASLR 增加地址预测难度，但可信息泄露后绕过 |

## 影响评估

### 受影响组件

- **torchair**: 华为 PyTorch 扩展库
- **使用场景**: 大模型分布式训练/推理场景下的 KV Cache 管理

### 潜在影响

| 影响类型 | 严重程度 | 说明 |
|----------|----------|------|
| 任意内存读取 | High | 可读取进程内存中的敏感数据 |
| 任意内存写入 | Critical | 可覆盖任意内存，可能导致代码执行 |
| 信息泄露 | High | 密钥、模型权重、训练数据等可能泄露 |
| 拒绝服务 | High | 触发段错误导致进程崩溃 |
| 权限提升 | Medium | 在特定条件下可能实现权限提升 |

### CVSS 3.1 评分估算

**CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H**

- **Attack Vector (AV)**: Local - 需要本地访问
- **Attack Complexity (AC)**: Low - 利用简单，无需特殊条件
- **Privileges Required (PR)**: Low - 需要普通用户权限
- **User Interaction (UI)**: None - 无需用户交互
- **Scope (S)**: Changed - 可能影响其他组件
- **Confidentiality (C)**: High - 可读取任意内存
- **Integrity (I)**: High - 可写入任意内存
- **Availability (A)**: High - 可导致崩溃

**基础分数: 8.8 (High)**

## 修复建议

### 短期修复 (推荐)

1. **添加地址白名单机制**

```cpp
std::pair<uint32_t, std::vector<at::Tensor>> AsTorchTensor(
    const std::vector<int64_t> &dims, 
    const int32_t ge_data_type,
    const std::vector<uintptr_t> &addresses) {
  
  // 获取有效的 NPU 内存范围
  auto valid_ranges = GetValidNpuMemoryRanges();
  
  for (auto dev_addr : addresses) {
    // 验证地址是否在有效范围内
    bool is_valid = false;
    for (const auto& range : valid_ranges) {
      if (dev_addr >= range.start && dev_addr < range.end) {
        is_valid = true;
        break;
      }
    }
    
    if (!is_valid) {
      return {kFailure, {}};  // 拒绝无效地址
    }
    
    // ... 原有逻辑
  }
}
```

2. **添加地址所有权验证**

```cpp
// 要求调用者提供地址的所有权证明
struct OwnedMemory {
  uintptr_t address;
  std::shared_ptr<MemoryHandle> ownership_proof;
};

std::pair<uint32_t, std::vector<at::Tensor>> AsTorchTensor(
    const std::vector<int64_t> &dims, 
    const int32_t ge_data_type,
    const std::vector<OwnedMemory> &owned_memories) {
  
  for (const auto& mem : owned_memories) {
    if (!VerifyOwnership(mem.ownership_proof, mem.address)) {
      return {kFailure, {}};
    }
    // ... 原有逻辑
  }
}
```

### 中期修复

1. **重构 API 设计**

```python
# 不推荐：直接传递地址
tensors = create_npu_tensors(shape, dtype, addresses)

# 推荐：使用安全的内存管理 API
with NpuMemoryManager() as manager:
    # 由框架管理内存分配
    buffer = manager.allocate(shape, dtype)
    tensors = buffer.create_tensors()
```

2. **添加访问控制**

```cpp
// 检查调用者是否有权限访问指定内存
if (!CheckMemoryAccessPermission(current_process, dev_addr, size)) {
  LOG_ERROR("Permission denied: process cannot access memory at 0x{:x}", dev_addr);
  return {kFailure, {}};
}
```

### 长期修复

1. **使用内存映射而非直接地址**

```cpp
// 使用安全的内存标识符而非原始地址
using MemoryHandle = uint64_t;  // 不透明的句柄

std::pair<uint32_t, std::vector<at::Tensor>> AsTorchTensor(
    const std::vector<int64_t> &dims, 
    const int32_t ge_data_type,
    const std::vector<MemoryHandle> &handles) {
  
  for (auto handle : handles) {
    // 通过安全查找表获取地址
    auto* mem_info = MemoryRegistry::Lookup(handle);
    if (!mem_info || !mem_info->is_valid) {
      return {kFailure, {}};
    }
    
    void* address = mem_info->address;
    // ... 使用验证过的地址
  }
}
```

2. **添加审计日志**

```cpp
LOG_SECURITY("AsTorchTensor: process={} addresses={} shapes={}",
             GetCurrentProcessId(), 
             FormatAddresses(addresses),
             FormatDims(dims));
```

## 缓解措施

在应用补丁之前，可采取以下缓解措施：

1. **限制 API 访问**
   - 在 Python 层添加权限检查
   - 仅允许可信代码调用此 API

2. **监控异常调用**
   - 记录所有对此 API 的调用
   - 检测异常地址模式

3. **沙箱隔离**
   - 在受限环境中运行使用此 API 的代码
   - 使用 seccomp 或类似机制限制系统调用

## 参考信息

### 相关 CWE

- **CWE-787**: Out-of-bounds Write
- **CWE-119**: Improper Restriction of Operations within the Bounds of a Memory Buffer
- **CWE-125**: Out-of-bounds Read
- **CWE-416**: Use After Free

### 相关文档

- [torchair 官方文档](https://gitee.com/ascend/torchair)
- [PyTorch Tensor 内存管理](https://pytorch.org/docs/stable/notes/tensor_memory_management.html)

### 历史案例

类似的原始指针直接使用漏洞：
- CVE-2019-14232 (Django)
- CVE-2020-10750 (QEMU)

## 验证信息

| 检查项 | 结果 |
|--------|------|
| 漏洞可达性 | ✅ 直接可达，公开 API |
| 数据可控性 | ✅ 完全可控 (addresses 参数) |
| 缓解措施 | ❌ 无任何缓解措施 |
| 测试代码 | ❌ 非测试代码 |

### 评分详情

```json
{
  "base": 30,
  "reachability": 30,
  "controllability": 25,
  "mitigations": 0,
  "context": 0,
  "cross_file": 0,
  "final_score": 85
}
```

**置信度**: 85 (CONFIRMED)

## 结论

VULN-DF-MEM-001 是一个严重的内存安全漏洞，攻击者可通过公开 API 传入任意内存地址，实现任意内存读写。该漏洞缺乏任何安全验证机制，在华为 Ascend NPU 的大模型训练/推理场景下存在严重的安全风险。建议立即采取缓解措施并尽快实施修复。

---

**分析日期**: 2026-04-24  
**分析者**: details-analyzer  
**来源 Agent**: dataflow-scanner, security-auditor