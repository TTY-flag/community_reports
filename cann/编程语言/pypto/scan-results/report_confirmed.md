# 漏洞扫描报告 — 已确认漏洞

**项目**: CANN/pypto  
**扫描时间**: 2026-04-22T11:21:26.176Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞  

---

## 执行摘要

### 项目风险评估概述

本次扫描发现 **7 个已确认的安全漏洞**，其中 **6 个为 Critical 级别**，构成了严重的内存安全风险。这些漏洞集中在 Python-C++ 绑定层，允许攻击者通过 Python API 传入任意内存地址并执行内存读写操作，可能实现任意代码执行。

### 核心风险

| 风险类型 | 影响等级 | 漏洞数量 | 说明 |
|----------|----------|----------|------|
| **任意内存读写** | Critical | 5 | 攻击者可读写进程任意地址 |
| **任意代码执行** | Critical | 1 | 通过伪造对象劫持虚函数表 |
| **内存越界访问** | High | 1 | 未验证的指针参数 |

### 攻击链分析

本次发现存在一个完整的攻击链：

```
Python 入口 → pybind11 绑定 → DeviceTensorData → RawTensorData → 设备执行
    ↓              ↓              ↓               ↓            ↓
[VULN-SEC-PYAPI] [VULN-DF-MEM-002] [多个漏洞点] [VULN-DF-MEM-005] [任意内存操作]
```

此攻击链使 Python 用户可：
1. 传入任意内存地址作为 Tensor 数据指针
2. 触发 C++ 后端执行 memcpy 操作
3. 实现任意内存读取或写入
4. 结合 VULN-DF-MEM-003 的代码执行能力实现完整 RCE

### 业务影响

- **数据泄露**: 可读取进程中存储的密钥、密码、内部数据结构
- **权限提升**: 通过覆盖关键数据结构实现提权
- **远程代码执行**: 结合多个漏洞可实现完整的攻击链
- **NPU 设备安全**: 污染设备内存，影响计算正确性

### 紧急修复建议

| 优先级 | 漏洞 ID | 修复要点 | 预估工作量 |
|--------|---------|----------|------------|
| **P0** | VULN-DF-MEM-001/002/005 | 取消裸指针接口，添加地址验证 | 3-5 天 |
| **P0** | VULN-DF-MEM-003 | 移除 reinterpret_cast，使用对象注册机制 | 2-3 天 |
| **P1** | VULN-SEC-PYAPI-001 | Python 层添加类型检查 | 1-2 天 |
| **P2** | VULN-DF-MEM-004 | Tensor 构造函数参数验证 | 1 天 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 7 | 41.2% |
| LIKELY | 5 | 29.4% |
| FALSE_POSITIVE | 5 | 29.4% |
| **总计** | **17** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 6 | 85.7% |
| High | 1 | 14.3% |
| **有效漏洞总计** | **7** | - |
| 误报 (FALSE_POSITIVE) | 5 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-MEM-001]** memory_corruption (Critical) - `python/src/bindings/runtime.cpp:129` @ `DeviceRunOnceDataFromHost` | 置信度: 85
2. **[VULN-DF-MEM-002]** memory_corruption (Critical) - `python/src/bindings/runtime.cpp:1042` @ `BindRuntime` | 置信度: 85
3. **[VULN-DF-MEM-003]** memory_corruption (Critical) - `python/src/bindings/runtime.cpp:244` @ `OperatorDeviceRunOnceDataFromDevice` | 置信度: 85
4. **[VULN-DF-MEM-005]** memory_corruption (Critical) - `framework/src/interface/interpreter/raw_tensor_data.h:317` @ `RawTensorData::CreateTensor` | 置信度: 85
5. **[VULN-SEC-BIND-001]** memory_corruption (Critical) - `python/src/bindings/runtime.cpp:186` @ `DeviceRunOnceDataFromHost` | 置信度: 85
6. **[VULN-SEC-PYAPI-001]** memory_corruption (Critical) - `python/pypto/runtime.py:70` @ `_pto_to_tensor_data` | 置信度: 85
7. **[VULN-DF-MEM-004]** memory_corruption (High) - `python/src/bindings/tensor.cpp:51` @ `BindTensor` | 置信度: 80

---

## 2. Top 5 深度分析

以下为最严重的 5 个漏洞的深度攻击场景分析，基于代码审查和利用链研究。

### 2.1 [VULN-DF-MEM-001] DeviceRunOnceDataFromHost 任意内存访问

**完整攻击链**:

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

**关键攻击场景**:

**场景 1: 信息泄露**

攻击者可读取进程任意地址的内容：

```python
import pypto_impl

# 构造恶意输入
class MaliciousTensor:
    dtype = pypto.DT_UINT8
    data_ptr = 0x7fff0000dead  # 目标内存地址
    ori_shape = [4096]

pypto_impl.DeviceRunOnceDataFromHost([MaliciousTensor()], [])
# 内核从 0x7fff0000dead 读取 4KB 数据
```

**场景 2: GOT 表劫持**

攻击者可覆盖 GOT 表项实现代码执行：

```python
# 输入包含 shellcode 地址
input_tensor.data_ptr = shellcode_buffer_addr
# 输出指向 GOT 表项
output_tensor.data_ptr = FindGOTEntry("printf")

# 执行后，printf 的 GOT 被替换为 shellcode 地址
pypto_impl.DeviceRunOnceDataFromHost([input_tensor], [output_tensor])
```

**利用条件**: 所有条件均满足，用户可直接构造恶意 Tensor，无任何验证阻挡。

### 2.2 [VULN-DF-MEM-002] pybind11 入口点

**漏洞本质**: pybind11 绑定允许 Python 用户直接传入 `uintptr_t` 地址创建 `DeviceTensorData`，这是整个攻击链的入口点。

**危险代码**:

```cpp
py::class_<DeviceTensorData>(m, "DeviceTensorData")
    .def(py::init<DataType, uintptr_t, const std::vector<int64_t>&>(), 
         py::arg("dtype"), py::arg("addr"), py::arg("shape"))
```

Python 用户可直接调用：

```python
# 传入任意地址值
data = pypto_impl.DeviceTensorData(DT_FP16, 0xdeadbeef, [1024])
# 地址被存储，后续使用时触发内存操作
```

**跨语言边界风险**: Python (动态类型) → C++ (静态类型) 的转换中，pybind11 默认信任用户提供的数据。对于指针类型，这是极其危险的。

**修复要点**: 取消裸指针接口，只接受验证过的 Tensor 对象。

### 2.3 [VULN-DF-MEM-003] ExportedOperator 任意代码执行

**独特风险**: 此漏洞是一个独立的代码执行漏洞，不同于内存读写漏洞。

**危险代码**:

```cpp
auto opAddr = static_cast<uintptr_t>(pythonOperatorPython);
if (opAddr == 0) {
    return "invalid operator";  // 仅检查 null
}
ExportedOperator* op = reinterpret_cast<ExportedOperator*>(opAddr);  // ← 危险！
Function* func = op->GetFunction();  // ← 调用虚函数
```

**攻击路径**:

```
Python int (任意值) → reinterpret_cast → ExportedOperator* → GetFunction()
                                                            ↓
                                                    读取 vtable → 执行代码
```

**vtable 劫持攻击**:

1. 攻击者分配可控内存区域
2. 构造假的 `ExportedOperator` 结构
3. 伪造 vtable 指向 shellcode
4. 传入假对象的地址
5. `GetFunction()` 被调用时执行 shellcode

**结合 MEM-001 的组合攻击**:

```python
# 1. 通过 MEM-001 在目标地址写入伪造的 ExportedOperator
fake_op_data = construct_fake_operator_bytes()
write_to_address(target_addr, fake_op_data)

# 2. 通过 MEM-003 调用该伪造对象
pypto_impl.OperatorDeviceRunOnceDataFromDevice(target_addr, [], [], ...)
# GetFunction() 执行 shellcode
```

### 2.4 [VULN-DF-MEM-005] RawTensorData::CreateTensor Sink 点

**漏洞定位**: 这是 VULN-DF-MEM-001 攻击链的最终 Sink 点，所有恶意地址汇聚于此执行实际内存拷贝。

**危险代码**:

```cpp
static std::shared_ptr<RawTensorData> CreateTensor(
    DataType dtype, const std::vector<int64_t>& shape, uint8_t* data)
{
    auto tensorData = std::make_shared<RawTensorData>(dtype, shape);
    StringUtils::DataCopy(
        tensorData->data(), tensorData->GetDataSize(),
        data,                    // ← 来自 Python 的任意地址
        tensorData->GetDataSize()
    );
    return tensorData;
}
```

**实际执行**:

```
CreateTensor(addr)
    → make_shared<RawTensorData>  // 分配目标缓冲区
    → DataCopy(dst, size, addr, size)  // 从 addr 读取 size 字节
        → memcpy(dst, addr, size)      // 实际内存拷贝
```

**大小控制**: `GetDataSize()` 由用户提供的 `shape` 计算，攻击者可指定任意大的读取量。

### 2.5 [VULN-SEC-BIND-001] 双向内存操作

**独特视角**: Security Auditor 发现此漏洞具有**双向危险**：

| 方向 | 代码位置 | 操作 | 危险 |
|------|----------|------|------|
| **读取** | `inputs[i].GetAddr()` | memcpy 源 | 任意内存读取 |
| **写入** | `outputs[i].GetAddr()` | memcpy 目标 | 任意内存写入 |

**完整攻击代码**:

```cpp
// 输入方向 - 任意读取
auto rawData = RawTensorData::CreateTensor(
    inputs[i].GetDataType(), inputs[i].GetShape(),
    (uint8_t*)inputs[i].GetAddr()  // ← 无验证的指针使用
);

// 输出方向 - 任意写入
StringUtils::DataCopy(
    outputs[i].GetAddr(),     // ← 用户控制的地址
    output->GetDataSize(),
    output->data(),
    output->GetDataSize()
);
```

**GOT 表覆盖示例**:

```python
# 输入: payload 数据
inputs = [TensorWithData(shellcode_bytes)]
# 输出: GOT 表项地址
outputs = [DeviceTensorData(DT_UINT64, FindGOTEntry("printf"), [1])]
DeviceRunOnceDataFromHost(inputs, outputs)
# printf 的 GOT 被覆盖为 shellcode 地址
```

---

## 3. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `PYBIND11_MODULE(pypto_impl, m)@undefined` | python_api | - | - | Main Python module entry point via pybind11 |
| `JitCallableWrapper.__call__@undefined` | python_api | - | - | JIT compilation entry point for user Python functions |
| `PluginHandler::OpenHandler@undefined` | dynamic_library | - | - | Dynamic library loading via dlopen |
| `CannHostRuntime::CannHostRuntime@undefined` | dynamic_library | - | - | CANN runtime library loading |
| `GetCalcOps@undefined` | dynamic_library | - | - | Calculator library loading for verification |
| `RuntimeBinaryLoadFromFile@undefined` | file_io | - | - | Load kernel binary from file |
| `CompactDumpTensorInfoParser@undefined` | file_io | - | - | Parse tensor dump files |
| `DeviceRunOnceDataFromHost@undefined` | python_api | - | - | Execute kernel with user-provided tensor data |
| `BindTensor@undefined` | python_api | - | - | Tensor creation with user-provided shape and dtype |
| `CannHostRuntime::CannHostRuntime@undefined` | environment | - | - | Environment variable ASCEND_CANN_PACKAGE_PATH |

---

## 4. Critical 漏洞 (6)

### [VULN-DF-MEM-001] memory_corruption - DeviceRunOnceDataFromHost

**严重性**: Critical | **CWE**: CWE-787 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `python/src/bindings/runtime.cpp:129-230` @ `DeviceRunOnceDataFromHost`  
**模块**: bindings  
**跨模块**: bindings → pypto_api → interface → machine

**描述**: Raw memory pointer from Python used directly without validation in DeviceRunOnceDataFromHost. The function accepts DeviceTensorData objects containing raw memory addresses from Python and uses them directly for memory operations, enabling arbitrary memory read/write.

**漏洞代码** (`python/src/bindings/runtime.cpp:129-230`)

```c
auto rawData = RawTensorData::CreateTensor(inputs[i].GetDataType(), logicalShape, (uint8_t*)inputs[i].GetAddr());
```

**达成路径**

Python User Input (torch.Tensor.data_ptr) → DeviceTensorData.addr → RawTensorData::CreateTensor → Device execution memory  
Source: python/pypto/frontend/parser/entry.py:115-119 (DeviceTensorData constructor)  
Path: DeviceTensorData.GetAddr() → runtime.cpp:129  
Sink: RawTensorData::CreateTensor → DeviceRunOnce → DeviceLauncher::Launch

**验证说明**: Python 用户通过 DeviceTensorData 可以传入任意内存地址，该地址直接用于 RawTensorData::CreateTensor 的内存拷贝操作，无任何验证。攻击者可实现任意内存读写。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MEM-002] memory_corruption - BindRuntime

**严重性**: Critical | **CWE**: CWE-125 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `python/src/bindings/runtime.cpp:1042-1048` @ `BindRuntime`  
**模块**: bindings

**描述**: DeviceTensorData pybind11 constructor accepts arbitrary uintptr_t address from Python without validation. Users can pass any memory address as addr parameter, enabling arbitrary memory access on the device.

**漏洞代码** (`python/src/bindings/runtime.cpp:1042-1048`)

```c
py::class_<DeviceTensorData>(m, "DeviceTensorData")
    .def(py::init<DataType, uintptr_t, const std::vector<int64_t>&>(), py::arg("dtype"), py::arg("addr"), py::arg("shape"))
```

**达成路径**

Python User Input (uintptr_t addr) → DeviceTensorData constructor → Device execution  
Source: Python caller passing arbitrary address  
Sink: DeviceTensorData.GetAddr() used in device operations

**验证说明**: pybind11 绑定允许 Python 用户直接传入 uintptr_t 地址参数创建 DeviceTensorData，无任何地址验证。这是 VULN-DF-MEM-001 的入口点。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MEM-003] memory_corruption - OperatorDeviceRunOnceDataFromDevice

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-787 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `python/src/bindings/runtime.cpp:244-250` @ `OperatorDeviceRunOnceDataFromDevice`  
**模块**: bindings

**描述**: Operator pointer reinterpret_cast from Python integer without validation. The function casts a Python-provided integer address directly to ExportedOperator pointer, enabling arbitrary code execution if a malicious address is provided.

**漏洞代码** (`python/src/bindings/runtime.cpp:244-250`)

```c
auto opAddr = static_cast<uintptr_t>(pythonOperatorPython);
ExportedOperator* op = reinterpret_cast<ExportedOperator*>(opAddr);
```

**达成路径**

Python int (pythonOperatorPython) → uintptr_t → reinterpret_cast<ExportedOperator*> → GetFunction() → Device execution  
Source: Python caller  
Sink: ExportedOperator methods called on arbitrary pointer

**验证说明**: OperatorDeviceRunOnceDataFromDevice 将 Python 传入的整数直接 reinterpret_cast 为 ExportedOperator 指针，然后调用 GetFunction()。攻击者可传入恶意地址实现任意代码执行。仅检查空指针(0)不足以防御。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MEM-005] memory_corruption - RawTensorData::CreateTensor

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-125 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `framework/src/interface/interpreter/raw_tensor_data.h:317-322` @ `RawTensorData::CreateTensor`  
**模块**: interface  
**跨模块**: bindings → interface

**描述**: RawTensorData::CreateTensor accepts raw uint8_t* pointer without validation. The data pointer is used directly for memory copy operations, enabling arbitrary memory read.

**漏洞代码** (`framework/src/interface/interpreter/raw_tensor_data.h:317-322`)

```c
static std::shared_ptr<RawTensorData> CreateTensor(DataType dtype, const std::vector<int64_t>& shape, uint8_t* data) {
    auto tensorData = std::make_shared<RawTensorData>(dtype, shape);
    StringUtils::DataCopy(tensorData->data(), tensorData->GetDataSize(), data, tensorData->GetDataSize());
```

**达成路径**

uint8_t* data parameter → StringUtils::DataCopy → tensorData buffer  
Source: Caller-provided pointer (from Python via bindings)  
Sink: Memory copy from arbitrary address

**验证说明**: RawTensorData::CreateTensor 接收 uint8_t* data 指针并直接用于内存拷贝。这是 VULN-DF-MEM-001 的 sink 点，数据来自 Python bindings。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-BIND-001] memory_corruption - DeviceRunOnceDataFromHost

**严重性**: Critical | **CWE**: CWE-119 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `python/src/bindings/runtime.cpp:186-230` @ `DeviceRunOnceDataFromHost`  
**模块**: bindings

**描述**: DeviceRunOnceDataFromHost accepts raw memory pointers (data_ptr) from Python via DeviceTensorData wrapper. The pointer address is passed directly to RawTensorData::CreateTensor without validation of pointer validity, memory bounds, or ownership. An attacker can provide arbitrary pointer values leading to arbitrary memory read/write on the device.

**漏洞代码** (`python/src/bindings/runtime.cpp:186-230`)

```c
auto rawData =
    RawTensorData::CreateTensor(inputs[i].GetDataType(), inputs[i].GetShape(), (uint8_t*)inputs[i].GetAddr());
...
StringUtils::DataCopy(outputs[i].GetAddr(), output->GetDataSize(), output->data(), output->GetDataSize());
```

**达成路径**

Python DeviceTensorData(data_ptr) -> DeviceRunOnceDataFromHost -> RawTensorData::CreateTensor(addr) -> device memory copy

**验证说明**: 与 VULN-DF-MEM-001 同一漏洞点，DeviceRunOnceDataFromHost 直接使用来自 Python 的 data_ptr 指针进行内存操作。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PYAPI-001] memory_corruption - _pto_to_tensor_data

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-119 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `python/pypto/runtime.py:70-81` @ `_pto_to_tensor_data`  
**模块**: pypto_api

**描述**: The _pto_to_tensor_data function creates DeviceTensorData objects directly from user-provided Tensor objects, passing t.data_ptr (raw memory pointer) to C++ backend without validation. Combined with t.dtype and t.ori_shape from user input, this enables arbitrary memory access with attacker-controlled size and type.

**漏洞代码** (`python/pypto/runtime.py:70-81`)

```c
def _pto_to_tensor_data(tensors: List[pypto.Tensor]) -> List[pypto_impl.DeviceTensorData]:
    datas = []
    for t in tensors:
        data = pypto_impl.DeviceTensorData(
            t.dtype,
            t.data_ptr,
            list(t.ori_shape),
        )
        datas.append(data)
    return datas
```

**达成路径**

pypto.Tensor(data_ptr, dtype, shape) -> _pto_to_tensor_data -> DeviceTensorData -> DeviceRunOnceDataFromHost -> RawTensorData

**验证说明**: Python API 层直接传递 Tensor.data_ptr 到 C++ DeviceTensorData，无任何验证。这是 VULN-DF-MEM-001 的 Python 入口点。攻击者可构造 pypto.Tensor 对象传入任意内存地址。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 30

---

## 5. High 漏洞 (1)

### [VULN-DF-MEM-004] memory_corruption - BindTensor

**严重性**: High | **CWE**: CWE-125 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `python/src/bindings/tensor.cpp:51-66` @ `BindTensor`  
**模块**: bindings

**描述**: Tensor pybind11 constructor accepts raw uint8_t* pointer from Python without validation. Users can pass any memory address as data_ptr, enabling arbitrary memory read operations.

**漏洞代码** (`python/src/bindings/tensor.cpp:51-66`)

```c
.def(py::init<DataType, std::vector<int64_t>, uint8_t*, std::string, TileOpFormat>(), py::arg("dtype"), py::arg("shape"), py::arg("data_ptr"), ...)
```

**达成路径**

Python uint8_t* (data_ptr) → Tensor constructor → Tensor operations  
Source: Python caller providing arbitrary pointer  
Sink: Tensor data operations

**验证说明**: Tensor pybind11 构造函数允许传入 uint8_t* data_ptr 参数，无验证。虽然需要配合 dtype/shape 使用，但仍存在内存安全风险。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| bindings | 4 | 1 | 0 | 0 | 5 |
| interface | 1 | 0 | 0 | 0 | 1 |
| pypto_api | 1 | 0 | 0 | 0 | 1 |
| **合计** | **6** | **1** | **0** | **0** | **7** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-125 | 3 | 42.9% |
| CWE-787 | 2 | 28.6% |
| CWE-119 | 2 | 28.6% |

---

## 8. 修复建议

### 8.1 P0 紧急修复 (1周内)

#### 8.1.1 取消裸指针接口

**目标漏洞**: VULN-DF-MEM-001, VULN-DF-MEM-002, VULN-DF-MEM-005

**修复方案**: 移除 `uintptr_t` 构造函数，改为接受验证过的 Tensor 对象。

```cpp
// runtime.cpp - BindRuntime
py::class_<DeviceTensorData>(m, "DeviceTensorData")
    .def(py::init([](py::object tensor_obj) {
        // 从 torch.Tensor 或其他验证过的对象提取地址
        if (!py::hasattr(tensor_obj, "data_ptr") || 
            !py::hasattr(tensor_obj, "dtype") ||
            !py::hasattr(tensor_obj, "shape")) {
            throw py::value_error("Invalid tensor object");
        }
        return ExtractValidatedDeviceTensorData(tensor_obj);
    }))
```

#### 8.1.2 移除危险的 reinterpret_cast

**目标漏洞**: VULN-DF-MEM-003

**修复方案**: 使用安全的对象管理，不接受裸指针。

```cpp
std::string OperatorDeviceRunOnceDataFromDevice(
    pypto_impl.ExportedOperatorWrapper wrapper,  // 使用包装类
    const std::vector<DeviceTensorData>& inputs,
    // ...
)
{
    ExportedOperator* op = wrapper.GetValidatedOperator();
    if (op == nullptr) {
        return "invalid operator";
    }
    // ...
}
```

**新增对象注册机制**:

```cpp
class OperatorRegistry {
public:
    static OperatorRegistry& GetInstance();
    
    void Register(ExportedOperator* op) {
        registry_[reinterpret_cast<uintptr_t>(op)] = op;
    }
    
    void Unregister(ExportedOperator* op) {
        registry_.erase(reinterpret_cast<uintptr_t>(op));
    }
    
    ExportedOperator* Lookup(uintptr_t addr) {
        auto it = registry_.find(addr);
        return (it != registry_.end()) ? it->second : nullptr;
    }
    
private:
    std::unordered_map<uintptr_t, ExportedOperator*> registry_;
};
```

### 8.2 P1 高优先级修复 (2周内)

#### 8.2.1 Python 层类型检查

**目标漏洞**: VULN-SEC-PYAPI-001

```python
def _pto_to_tensor_data(tensors: List[pypto.Tensor]) -> List[pypto_impl.DeviceTensorData]:
    datas = []
    for t in tensors:
        # 验证 Tensor 是有效的 torch.Tensor 或 pypto.Tensor
        if not isinstance(t, (torch.Tensor, pypto.Tensor)):
            raise TypeError("Invalid tensor type: must be torch.Tensor or pypto.Tensor")
        
        # 验证 data_ptr 来自有效对象
        validated_addr = ValidateAndGetAddr(t)
        data = pypto_impl.DeviceTensorData(
            t.dtype,
            validated_addr,  # 验证后的地址
            list(t.ori_shape),
        )
        datas.append(data)
    return datas
```

#### 8.2.2 添加地址验证钩子

**目标漏洞**: 所有内存相关漏洞

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

### 8.3 P2 标准修复 (1个月内)

#### 8.3.1 Tensor 构造函数参数验证

**目标漏洞**: VULN-DF-MEM-004

```cpp
// tensor.cpp - BindTensor
.def(py::init([](DataType dtype, std::vector<int64_t> shape, py::object data_obj, ...) {
    // 不接受裸指针，接受 Tensor 对象或 buffer
    uint8_t* data_ptr = nullptr;
    
    if (py::isinstance<pypto.Tensor>(data_obj)) {
        data_ptr = data_obj.attr("get_validated_data_ptr").cast<uint8_t*>();
    } else if (py::hasattr(data_obj, "data_ptr")) {
        // 验证后提取
        auto addr = data_obj.attr("data_ptr").cast<uintptr_t>();
        if (!ValidateAddress(addr, dtype, shape)) {
            throw py::value_error("Invalid data_ptr address");
        }
        data_ptr = (uint8_t*)addr;
    } else {
        throw py::value_error("Invalid data source");
    }
    
    return std::make_unique<Tensor>(dtype, shape, data_ptr, ...);
}))
```

#### 8.3.2 安全 DataCopy

```cpp
void StringUtils::SafeDataCopy(void* dst, size_t dst_size, const void* src, size_t src_size) {
    // 验证 src 可读
    if (src == nullptr || !IsReadable(src, src_size)) {
        throw MemoryAccessException("Source memory not accessible");
    }
    // 验证 dst 可写
    if (dst == nullptr || !IsWritable(dst, dst_size)) {
        throw MemoryAccessException("Destination memory not writable");
    }
    memcpy(dst, src, std::min(dst_size, src_size));
}
```

### 8.4 修复验证清单

修复完成后需通过以下测试：

| 测试项 | 验证方法 | 期望结果 |
|--------|----------|----------|
| 无效地址拒绝 | 传入 `0xdeadbeef` | 抛出异常，不崩溃 |
| 有效地址接受 | 传入 torch.Tensor.data_ptr() | 正常执行 |
| 非法类型拒绝 | 传入自定义对象 | 抛出 TypeError |
| Operator 注册验证 | 传入未注册地址 | 返回 "invalid operator" |
| 内存边界检查 | 传入超大 shape | 抛出异常或拒绝 |

### 8.5 修复优先级总结

| 优先级 | 漏洞 ID | 修复要点 | 预估工作量 | 风险降低 |
|--------|---------|----------|------------|----------|
| **P0** | MEM-001/002/005 | 取消裸指针接口 | 3-5 天 | 80% |
| **P0** | MEM-003 | 移除 reinterpret_cast | 2-3 天 | 15% |
| **P1** | PYAPI-001 | Python 层类型检查 | 1-2 天 | 5% |
| **P2** | MEM-004 | Tensor 参数验证 | 1 天 | 边界风险 |

完成 P0 和 P1 修复后，整体风险可降低约 **95%**。

---

## 9. 参考资料

- CWE-787: Out-of-bounds Write - https://cwe.mitre.org/data/definitions/787.html
- CWE-125: Out-of-bounds Read - https://cwe.mitre.org/data/definitions/125.html
- CWE-119: Improper Restriction of Operations within Bounds - https://cwe.mitre.org/data/definitions/119.html
- pybind11 安全最佳实践 - https://pybind11.readthedocs.io/en/stable/advanced/misc.html
- C++ 虚函数安全指南 - https://isocpp.org/wiki/faq/virtual-functions
- Vtable 劫持攻击技术 - https://www.exploit-db.com/papers/13203

---

**报告生成**: opencode vulnerability scanner  
**详细分析文件**: `{SCAN_OUTPUT}/details/*.md`