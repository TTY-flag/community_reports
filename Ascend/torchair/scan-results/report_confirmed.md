# 漏洞扫描报告 — 已确认漏洞

**项目**: torchair  
**扫描时间**: 2026-04-24T06:38:54.193Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

### 项目背景

TorchAir (Torch Ascend Intermediate Representation) 是华为昇腾 NPU 的 PyTorch 扩展库，用于在华为 NPU 设备上进行图模式推理和训练。该项目采用 C++/Python 混合架构，通过 pybind11 实现跨语言绑定，核心功能包括：

- **图编译**: 通过 `torch.compile()` 将 PyTorch FX 图转换为 GE 图
- **模型导出**: 将编译后的模型导出为 `.air` 格式文件
- **分布式训练**: 支持 HCOM 分布式通信算子
- **KV Cache 管理**: LLM 场景下的张量数据分布 (llm_datadist)

### 关键发现

本次安全扫描发现 **1 个已确认的严重内存安全漏洞**：

| 漏洞ID | 类型 | 严重性 | CWE | 受影响组件 |
|--------|------|--------|-----|------------|
| VULN-DF-MEM-001 | 内存安全 | **Critical** | CWE-787 | `AsTorchTensor` 函数 |

该漏洞位于 `torchair/llm_datadist/llm_datadist.cpp` 的 `AsTorchTensor` 函数，允许攻击者通过公开 API 传入任意内存地址，创建指向该地址的 PyTorch Tensor，从而实现：

- **任意内存读取**: 读取进程内存中的敏感数据（密钥、模型权重、训练数据）
- **任意内存写入**: 向任意地址写入数据，可能导致内存破坏或代码执行
- **Use-After-Free**: 指向已释放内存导致悬空指针利用

### 风险评估

| 维度 | 评估 | 说明 |
|------|------|------|
| **攻击向量** | Local | 需要本地代码执行能力，可通过 Python API 触发 |
| **攻击复杂度** | Low | API 调用简单，无需特殊技巧或知识 |
| **权限要求** | Low | 标准 PyTorch 用户权限即可调用 |
| **用户交互** | None | 无需用户交互 |
| **影响范围** | Changed | 可能影响整个进程内存空间 |
| **CVSS 评分** | **8.8 (High)** | CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H |

### 安全状态

- ✅ **已确认漏洞**: 1 个 (Critical)
- ⚠️ **待确认漏洞**: 9 个 (LIKELY: 4, POSSIBLE: 5)
- ❌ **误报排除**: 4 个

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 5 | 35.7% |
| LIKELY | 4 | 28.6% |
| FALSE_POSITIVE | 4 | 28.6% |
| CONFIRMED | 1 | 7.1% |
| **总计** | **14** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 1 | 100.0% |
| **有效漏洞总计** | **1** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-MEM-001]** memory_safety (Critical) - `torchair/llm_datadist/llm_datadist.cpp:39` @ `AsTorchTensor` | 置信度: 85

---

## 2. 攻击面分析

### 主要攻击入口

| 入口点 | 类型 | 风险等级 | 描述 |
|--------|------|----------|------|
| `torch.compile()` | Python API | HIGH | NPU 图编译入口，接受用户模型 |
| `dynamo_export()` | Python API | HIGH | 模型导出入口，生成 .air 文件 |
| `TorchNpuGraphBase::Load` | C++ API | HIGH | 加载序列化的 Proto 图 |
| `TorchNpuGraphBase::Run` | C++ API | HIGH | 执行图推理，接受用户张量 |
| `AsTorchTensor` | C++ API | **Critical** | **从内存地址创建张量（漏洞点）** |

### 高风险攻击面类别

1. **Model Loading / Serialization (HIGH)**: Proto 反序列化、.air 文件加载
2. **Python-C++ Boundary (HIGH)**: pybind11 绑定、张量解析
3. **Tensor Memory Handling (HIGH)**: 内存地址处理、张量数据指针
4. **Dynamic Code Generation (HIGH)**: Python exec() 动态代码生成
5. **Dynamic Library Loading (MEDIUM)**: dlopen/dlsym 动态库加载

---

## 3. Critical 漏洞深度分析

### [VULN-DF-MEM-001] 任意内存地址引用漏洞

**严重性**: Critical | **CWE**: CWE-787 | **置信度**: 85/100 | **状态**: CONFIRMED  
**位置**: `torchair/llm_datadist/llm_datadist.cpp:39-72` @ `AsTorchTensor`  
**模块**: torchair/llm_datadist

---

#### 3.1 漏洞描述

`AsTorchTensor` 函数接受用户提供的内存地址列表 (`addresses`)，直接使用 `reinterpret_cast<void *>(dev_addr)` 将地址转换为指针，并以此为数据指针创建 PyTorch Tensor。该函数**未实施任何安全验证**：

| 安全检查 | 状态 | 说明 |
|----------|------|------|
| 地址有效性检查 | ❌ 缺失 | 未验证地址是否在有效内存范围内 |
| 所有权验证 | ❌ 缺失 | 未验证调用者是否拥有该内存 |
| 内存边界检查 | ❌ 缺失 | 未验证 dims 与地址范围的匹配 |
| 生命周期管理 | ❌ 缺失 | 空 lambda 释放函数，无所有权管理 |
| 访问控制 | ❌ 缺失 | 无权限验证机制 |

---

#### 3.2 漏洞代码分析

**危险代码片段** (`torchair/llm_datadist/llm_datadist.cpp:39-72`)

```cpp
std::pair<uint32_t, std::vector<at::Tensor>> AsTorchTensor(
    const std::vector<int64_t> &dims, 
    const int32_t ge_data_type,
    const std::vector<uintptr_t> &addresses) {  // [1] 用户完全可控
    
  std::vector<at::Tensor> at_tensors;
  c10::ScalarType tensor_dtype = ToScalarType(static_cast<TorchDataType>(ge_data_type));
  if (tensor_dtype == c10::ScalarType::Undefined) {
    return {kFailure, at_tensors};
  }
  
  c10::DeviceType device_type = c10::DeviceType::PrivateUse1;
  at::TensorOptions option = at::TensorOptions().dtype(tensor_dtype).device(device_type);

  at_tensors.reserve(addresses.size());
  for (auto dev_addr : addresses) {              // [2] 遍历用户地址
    auto tensor = at::empty({0}, option);
    auto address = reinterpret_cast<void *>(dev_addr);  // [3] 直接转换！无验证
    at::DataPtr c10_data_ptr(address, address, [](void *) {}, tensor.device());
    //                                                        [4] 空释放函数
    
    size_t tensor_nbytes = at::detail::computeStorageNbytesContiguous(dims, tensor.dtype().itemsize());
    at::Storage storage;
    auto fptr = c10::GetStorageImplCreate(device_type);
    auto allocator = c10::GetAllocator(device_type);
    storage = fptr(c10::StorageImpl::use_byte_size_t(), 0, allocator->allocate(0), allocator, true);
    storage.unsafeGetStorageImpl()->set_nbytes(tensor_nbytes);
    storage.set_data_ptr(std::move(c10_data_ptr));  // [5] 用户地址作为数据指针

    tensor.set_(storage, 0, dims);
    at_tensors.emplace_back(std::move(tensor));
  }
  return {kSuccess, at_tensors};
}
```

**关键问题点详解**：

| 标记 | 代码位置 | 问题描述 |
|------|----------|----------|
| [1] | 参数 `addresses` | 用户完全可控的地址列表，无任何验证 |
| [2] | `for (auto dev_addr : addresses)` | 直接遍历用户输入，无过滤 |
| [3] | `reinterpret_cast<void *>(dev_addr)` | **核心漏洞**：将任意整数直接转换为指针 |
| [4] | `[](void *) {}` | 空释放函数意味着无所有权管理，不释放内存 |
| [5] | `storage.set_data_ptr(...)` | 用户地址被设置为 Tensor 的数据指针 |

---

#### 3.3 数据流路径

```
Python API 层
├─ torchair.llm_datadist.create_npu_tensors(shape, dtype, addrs)
│  └─ _tensor_utils._create_npu_tensors(shape, dtype, addresses)
│     └─ 仅做类型检查 (int)，无地址验证
│
pybind11 绑定层
├─ _torchair.as_torch_tensors(shape, data_type, addresses)
│  └─ core/npu_wrapper.cpp:77
│     └─ 直接转发参数，无验证
│
C++ 实现层 (漏洞点)
├─ AsTorchTensor(dims, ge_data_type, addresses)
│  └─ reinterpret_cast<void*>(dev_addr) ← SINK
│     └─ at::DataPtr 创建
│        └─ Tensor 数据指针设置
```

---

#### 3.4 利用场景分析

##### 场景 1: 任意内存读取

```python
import torch
import torchair

# 攻击者控制 addresses 参数
target_addr = 0x7fff12340000  # 目标地址

# 创建指向目标地址的 Tensor
shape = [1024]  # 读取 1024 * 2 = 2048 字节
dtype = torch.float16
tensors = torchair.llm_datadist.create_npu_tensors(shape, dtype, [target_addr])

# 通过 Tensor 操作读取内存
leaked_data = tensors[0]  # 获取目标地址的内存内容
```

**危害**: 信息泄露，可读取密钥、密码、模型权重、训练数据等敏感信息。

##### 场景 2: 任意内存写入

```python
import torch
import torchair

target_addr = 0x7fff12340000
shape = [1]
dtype = torch.float16

tensors = torchair.llm_datadist.create_npu_tensors(shape, dtype, [target_addr])

# 向目标地址写入数据
tensors[0].fill_(0x41414141)  # 写入任意值
```

**危害**: 内存破坏，可覆盖关键数据结构，可能导致代码执行。

##### 场景 3: Use-After-Free

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

**危害**: 程序崩溃、堆利用、潜在的代码执行。

---

#### 3.5 利用难度评估

| 因素 | 评估 | 说明 |
|------|------|------|
| 攻击向量 | Local | 需要本地代码执行能力 |
| 攻击复杂度 | **Low** | API 调用简单，无需特殊技巧 |
| 权限要求 | **Low** | 标准 PyTorch 用户权限即可 |
| 用户交互 | None | 无需用户交互 |
| ASLR 影响 | Medium | 64位系统增加地址预测难度，但可通过信息泄露绕过 |

---

#### 3.6 影响评估

| 影响类型 | 严重程度 | 说明 |
|----------|----------|------|
| **任意内存读取** | High | 可读取进程内存中的敏感数据 |
| **任意内存写入** | **Critical** | 可覆盖任意内存，可能导致代码执行 |
| **信息泄露** | High | 密钥、模型权重、训练数据等可能泄露 |
| **拒绝服务** | High | 触发段错误导致进程崩溃 |
| **权限提升** | Medium | 特定条件下可能实现权限提升 |

**CVSS 3.1 评分**: **CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H**  
**基础分数: 8.8 (High)**

---

#### 3.7 评分明细

| 维度 | 分数 | 说明 |
|------|------|------|
| Base (漏洞类型基础分) | 30 | 内存安全漏洞基础分 |
| Reachability (可达性) | 30 | 公开 API，直接可达 |
| Controllability (可控性) | 25 | addresses 参数完全用户可控 |
| Mitigations (缓解措施) | 0 | 无任何缓解措施 |
| Context (上下文风险) | 0 | 无特殊上下文风险 |
| Cross-file (跨文件) | 0 | 单文件漏洞 |
| **总分** | **85** | CONFIRMED 状态 |

---

## 4. 修复建议

### 4.1 短期修复 (推荐立即实施)

#### 方案 A: 地址白名单机制

```cpp
std::pair<uint32_t, std::vector<at::Tensor>> AsTorchTensor(
    const std::vector<int64_t> &dims, 
    const int32_t ge_data_type,
    const std::vector<uintptr_t> &addresses) {
  
  // 获取有效的 NPU 内存范围
  auto valid_ranges = GetValidNpuMemoryRanges();  // 新增函数
  
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
      TNG_LOG(ERROR) << "Invalid memory address: 0x" << std::hex << dev_addr;
      return {kFailure, {}};
    }
    
    // 原有逻辑...
  }
}
```

#### 方案 B: 所有权验证机制

```cpp
// 引入所有权证明结构
struct OwnedMemory {
  uintptr_t address;
  std::shared_ptr<MemoryHandle> ownership_proof;  // 必须提供所有权证明
};

std::pair<uint32_t, std::vector<at::Tensor>> AsTorchTensor(
    const std::vector<int64_t> &dims, 
    const int32_t ge_data_type,
    const std::vector<OwnedMemory> &owned_memories) {
  
  for (const auto& mem : owned_memories) {
    // 验证所有权证明
    if (!VerifyOwnership(mem.ownership_proof, mem.address)) {
      TNG_LOG(ERROR) << "Ownership verification failed for address 0x" 
                     << std::hex << mem.address;
      return {kFailure, {}};
    }
    // 原有逻辑...
  }
}
```

### 4.2 中期修复

#### API 重设计

**不推荐** (当前设计):
```python
tensors = create_npu_tensors(shape, dtype, addresses)  # 直接传递地址
```

**推荐** (安全设计):
```python
with NpuMemoryManager() as manager:
    # 由框架管理内存分配，不暴露原始地址
    buffer = manager.allocate(shape, dtype)
    tensors = buffer.create_tensors()
```

#### 添加访问控制

```cpp
// 检查调用者是否有权限访问指定内存
if (!CheckMemoryAccessPermission(current_process, dev_addr, size)) {
  LOG_SECURITY("Permission denied: process {} cannot access memory at 0x{:x}", 
               GetCurrentProcessId(), dev_addr);
  return {kFailure, {}};
}
```

### 4.3 长期修复

#### 使用安全内存句柄

```cpp
// 使用不透明的内存句柄而非原始地址
using MemoryHandle = uint64_t;

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
    
    void* address = mem_info->address;  // 验证过的地址
    // 原有逻辑...
  }
}
```

#### 添加审计日志

```cpp
LOG_SECURITY("AsTorchTensor: process={} addresses_count={} shapes={} sizes={}",
             GetCurrentProcessId(), 
             addresses.size(),
             FormatDims(dims),
             FormatSizes(dims, tensor_dtype));
```

### 4.4 缓解措施 (补丁前)

在应用正式补丁之前，可采取以下临时缓解措施：

| 缓解措施 | 实施方式 | 效果 |
|----------|----------|------|
| **限制 API 访问** | Python 层添加权限检查，仅允许可信代码调用 | 减少攻击面 |
| **监控异常调用** | 记录所有 API 调用，检测异常地址模式 | 早期发现攻击 |
| **沙箱隔离** | 在受限环境中运行使用此 API 的代码 | 降低影响范围 |
| **seccomp 过滤** | 使用 seccomp 限制系统调用 | 防止代码执行 |

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| torchair/llm_datadist | 1 | 0 | 0 | 0 | 1 |
| **合计** | **1** | **0** | **0** | **0** | **1** |

---

## 6. CWE 分布

| CWE | 数量 | 占比 | 描述 |
|-----|------|------|------|
| CWE-787 | 1 | 100.0% | Out-of-bounds Write |

---

## 7. 参考信息

### 相关 CWE

- **CWE-787**: Out-of-bounds Write
- **CWE-119**: Improper Restriction of Operations within the Bounds of a Memory Buffer
- **CWE-125**: Out-of-bounds Read
- **CWE-416**: Use After Free

### 相关文档

- [torchair 官方文档](https://gitee.com/ascend/torchair)
- [PyTorch Tensor 内存管理](https://pytorch.org/docs/stable/notes/tensor_memory_management.html)
- [CWE-787 详细说明](https://cwe.mitre.org/data/definitions/787.html)

---

**报告生成时间**: 2026-04-24T06:38:54.193Z  
**分析者**: vulnerability-reporter  
**深度分析报告**: `scan-results/details/VULN-DF-MEM-001.md`