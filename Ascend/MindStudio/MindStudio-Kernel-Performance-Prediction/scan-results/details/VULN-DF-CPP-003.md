# VULN-DF-CPP-003: Null Pointer Dereference in MMAD_DATA_REGISTER Macro

## 漏洞概述

| 属性 | 值 |
|------|------|
| **漏洞ID** | VULN-DF-CPP-003 |
| **类型** | Null Pointer Dereference |
| **CWE** | CWE-476 |
| **严重程度** | High |
| **置信度** | 85 |
| **文件** | csrc/interface/init_profdata_module.cpp:51-60 |
| **函数** | MMAD_DATA_REGISTER macro-generated functions |
| **状态** | CONFIRMED |

## 漏洞描述

`MMAD_DATA_REGISTER` 宏用于生成矩阵乘加 (MMAD) 指令的性能数据获取函数。该宏通过 `PyArg_ParseTuple` 提取字符串参数 `instrType`，但未对提取的指针进行 nullptr 或空字符串验证，直接传递给 `std::string()` 构造函数。

当 Python 调用者传入 `None` 作为 `instrType` 参数时，`PyArg_ParseTuple` 会将 `const char* instrType` 设置为 nullptr，随后 `std::string(nullptr)` 构造会导致 Undefined Behavior 或程序崩溃。

**特别说明**: MMAD (Matrix Multiply Accumulate) 是 AI 算子中最核心的计算指令，用于矩阵乘法运算。该漏洞直接影响所有使用 MMAD 指令的性能预测功能。

## 源代码分析

### 漏洞代码 (行 51-60)

```cpp
#define MMAD_DATA_REGISTER(instrName)                                                          \
    static PyObject *MSKPP_PROFDATA_##instrName##Register(PyObject *self, PyObject *pstArgs)   \
    {                                                                                          \
        long granularity;                                                                      \
        const char *instrType = nullptr;                                                       \
        if (!PyArg_ParseTuple(pstArgs, "ls", &granularity, &instrType)) { Py_RETURN_NONE; }    \
        auto instrName##Instr = MmadFactory::instance()->Create(#instrName);                   \
        if (instrName##Instr == nullptr) { Py_RETURN_NONE; }                                   \
        return PyFloat_FromDouble(instrName##Instr->Get(granularity, std::string(instrType))); \
    }
```

### 问题点

1. **行 55**: `instrType` 初始化为 nullptr
2. **行 56**: `PyArg_ParseTuple` 使用 `"ls"` 格式解析参数。`'s'` 格式允许 None，会将指针设置为 nullptr
3. **行 59**: 直接使用 `std::string(instrType)`，无验证

### 宏展开 (MMAD)

```cpp
// MMAD_DATA_REGISTER(MMAD) 展开后:
static PyObject *MSKPP_PROFDATA_MMADRegister(PyObject *self, PyObject *pstArgs)
{
    long granularity;
    const char *instrType = nullptr;
    if (!PyArg_ParseTuple(pstArgs, "ls", &granularity, &instrType)) { Py_RETURN_NONE; }
    auto MMADInstr = MmadFactory::instance()->Create("MMAD");
    if (MMADInstr == nullptr) { Py_RETURN_NONE; }
    return PyFloat_FromDouble(MMADInstr->Get(granularity, std::string(instrType)));
}
```

## 攻击路径分析

### 完整数据流

```
Python Caller (MmadData().get(64, None))
    ↓
PyArg_ParseTuple("ls", &granularity, &instrType)
    ↓ [传入 None]
const char* instrType = nullptr
    ↓
MmadFactory::instance()->Create("MMAD")
    ↓
MmadClass::Get(granularity, std::string(nullptr))
    ↓ [触发点]
std::string(nullptr) → Undefined Behavior / Segmentation Fault
```

### MmadClass::Get 实现 (data_adapter.cpp:121-144)

```cpp
double MmadClass::Get(long granularity, std::string instrType)
{
    std::map<uint32_t, double> curves;
    uint32_t g;
    uint32_t maxG = 0;
    std::map<std::string, std::string> mmadMap = { 
        {"ascend910b1", "MMAD_FP16_FP16_FP32_1_core_910b1"},
        {"ascend910b3", "MMAD_FP16_FP16_FP32_1_core_910b3"},
        {"ascend91095", "MMAD_FP16_FP16_FP32_1_core_91095"} 
    };
    std::string movPath = mmadMap[ArchInfo::instance()->GetChipType()];
    auto res = GetMmadTypeData(movPath);

    for (const auto& data : res) {
        g = data.mknSum;
        curves[g] = data.calPerf;
        // ...
    }
    if (granularity > maxG) {
        // ← 若 instrType 来自 nullptr，此处调用 GetDataTypeSizeOf(instrType) 可能出错
        return static_cast<double>(GetDataTypeSizeOf(instrType)) * 16 * 16 * 16;
    }
    return LinearInterpolate(curves, granularity);
}
```

注意：`MmadClass::Get` 的 `instrType` 参数类型为 `std::string` (非引用)，这意味着构造在调用时发生。若传入 nullptr，`std::string(nullptr)` 构造已触发 UB。

### 触发条件

| 条件 | 描述 |
|------|------|
| **必要条件** | Python 调用者传入 `None` 作为第二个参数 (instrType) |
| **触发位置** | `std::string(nullptr)` 构造函数调用 (行 59) |
| **触发时机** | 立即在参数解析后触发 |

## 潜在影响

### 技术影响

| 影响类型 | 描述 |
|----------|------|
| **程序崩溃** | `std::string(nullptr)` 构造会触发 Segmentation Fault |
| **核心功能影响** | MMAD 是矩阵乘法核心指令，影响 AI 模型性能预测 |
| **拒绝服务** | 攻击者可使性能预测功能完全停止 |

### 业务影响

| 影域 | 影响 |
|------|------|
| **可用性** | 高 - MMAD 是 AI 算子性能预测核心入口 |
| **完整性** | 无 |
| **机密性** | 无 |

### MMAD 指令重要性

MMAD (Matrix Multiply Accumulate) 是：
- **AI 算子核心**: 矩阵乘法是深度学习最基础的计算
- **性能瓶颈**: MMAD 性能直接影响整体模型性能预测精度
- **高频调用**: 在 AI 算子模拟中被频繁调用

## PoC (Proof of Concept)

### Python 触发代码

```python
from mskpp._C import prof_data

# 正常调用 (安全)
mmad_data = prof_data.MmadData()
result = mmad_data.get(64, "FP32")  # 正常返回性能数据

# 恶意调用 - 触发漏洞
try:
    result = mmad_data.get(64, None)  # ← instrType=None → Crash
except Exception as e:
    print(f"Error: {e}")

# Python 端直接使用示例 (example/sample_mmad.py)
# 如果用户代码中意外传入 None，将导致崩溃
from mskpp import mmad, Tensor, Chip

def malicious_mmad():
    with Chip("Ascend910B1"):
        # 模拟用户错误或恶意输入
        x = Tensor("L0A", None, [32, 48])  # ← 若 dtype 为 None 传递到底层
        # 或在其他路径中 instrType 变为 None
```

### C++ 层崩溃验证

```cpp
#include <string>
#include <iostream>

int main() {
    const char* ptr = nullptr;
    std::string s(ptr);  // ← Segmentation Fault / UB
    std::cout << s << std::endl;
    return 0;
}
```

## 修复建议

### 推荐修复方案

在 `MMAD_DATA_REGISTER` 宏中添加参数验证，参考安全实现模式：

```cpp
#define MMAD_DATA_REGISTER(instrName)                                                          \
    static PyObject *MSKPP_PROFDATA_##instrName##Register(PyObject *self, PyObject *pstArgs)   \
    {                                                                                          \
        long granularity;                                                                      \
        const char *instrType = nullptr;                                                       \
        if (!PyArg_ParseTuple(pstArgs, "ls", &granularity, &instrType)) {                      \
            PyErr_SetString(PyExc_ValueError, "Invalid Input.");                               \
            Py_RETURN_NONE;                                                                    \
        }                                                                                      \
        if (instrType == nullptr) {                                                            \
            PyErr_SetString(PyExc_ValueError, "instrType cannot be None.");                    \
            Py_RETURN_NONE;                                                                    \
        }                                                                                      \
        if (strlen(instrType) == 0) {                                                          \
            PyErr_SetString(PyExc_ValueError, "instrType cannot be empty.");                   \
            Py_RETURN_NONE;                                                                    \
        }                                                                                      \
        auto instrName##Instr = MmadFactory::instance()->Create(#instrName);                   \
        if (instrName##Instr == nullptr) { Py_RETURN_NONE; }                                   \
        return PyFloat_FromDouble(instrName##Instr->Get(granularity, std::string(instrType))); \
    }
```

### 修复要点

1. **nullptr 检查**: 在使用 `instrType` 前检查是否为 nullptr
2. **空字符串检查**: 使用 `strlen()` 检查字符串是否为空
3. **错误处理**: 使用 `PyErr_SetString()` 设置明确的错误消息
4. **一致性**: 与其他修复保持相同的安全模式

### 替代方案：使用 `'s#'` 格式

```cpp
#define MMAD_DATA_REGISTER(instrName)                                                          \
    static PyObject *MSKPP_PROFDATA_##instrName##Register(PyObject *self, PyObject *pstArgs)   \
    {                                                                                          \
        long granularity;                                                                      \
        const char *instrType = nullptr;                                                       \
        Py_ssize_t instrType_len;                                                              \
        if (!PyArg_ParseTuple(pstArgs, "ls#", &granularity, &instrType, &instrType_len)) {     \
            PyErr_SetString(PyExc_ValueError, "Invalid Input.");                               \
            Py_RETURN_NONE;                                                                    \
        }                                                                                      \
        if (instrType_len == 0) {                                                              \
            PyErr_SetString(PyExc_ValueError, "instrType cannot be empty.");                   \
            Py_RETURN_NONE;                                                                    \
        }                                                                                      \
        auto instrName##Instr = MmadFactory::instance()->Create(#instrName);                   \
        if (instrName##Instr == nullptr) { Py_RETURN_NONE; }                                   \
        return PyFloat_FromDouble(instrName##Instr->Get(granularity, std::string(instrType, instrType_len))); \
    }
```

## 相关漏洞

| 漏洞ID | 描述 | 关系 |
|--------|------|------|
| VULN-DF-CPP-001 | MOV_DATA_REGISTER 空指针解引用 | 相同漏洞模式 |
| VULN-DF-CPP-002 | VEC_DATA_REGISTER 空指针解引用 | 相同漏洞模式 |

这三个漏洞源于相同的代码模式缺陷，应同步修复。

## Python 层面缓解措施

在 Python 封装层添加类型检查：

```python
# mskpp/prof_data/mmad_prof.py
@ProfDataRegister.register("MMAD")
class MmadPref(PrefModel):
    def time(self):
        # 添加参数验证
        if self.instr_type is None:
            raise ValueError("instr_type cannot be None")
        if not self.instr_type:
            raise ValueError("instr_type cannot be empty string")
        # 原有逻辑...
        bandwidth = prof_data.MmadData().get(self.granularity, self.instr_type)
```

**注意**: 这只是缓解措施，恶意用户仍可直接调用底层 C API。

## 验证测试

### 单元测试

```cpp
TEST_F(ProfDataTest, MmadData_Get_NoneProtection)
{
    std::string className = "MmadData";
    auto mmadDataClass = GetmoduleClass(className);
    PyObject *pInstance = PyObject_CallObject(mmadDataClass, NULL);
    PyObject *get = PyObject_GetAttrString(pInstance, "get");

    // 测试 None 参数保护
    PyObject *pArgs = PyTuple_New(2);
    PyTuple_SetItem(pArgs, 0, PyLong_FromLong(64));  // granularity
    PyTuple_SetItem(pArgs, 1, Py_None);              // instrType=None

    PyObject *getRes = PyObject_CallObject(get, pArgs);
    EXPECT_TRUE(getRes == NULL);  // 应返回 NULL 并设置错误
    EXPECT_TRUE(PyErr_Occurred());  // 应设置 ValueError
    EXPECT_TRUE(PyErr_ExceptionMatches(PyExc_ValueError));
    PyErr_Clear();
    
    Py_DECREF(pArgs);
    Py_DECREF(pInstance);
    Py_DECREF(get);
}

TEST_F(ProfDataTest, MmadData_Get_EmptyStringProtection)
{
    auto mmadDataClass = GetmoduleClass("MmadData");
    PyObject *pInstance = PyObject_CallObject(mmadDataClass, NULL);
    PyObject *get = PyObject_GetAttrString(pInstance, "get");

    // 测试空字符串保护
    PyObject *pArgs = PyTuple_New(2);
    PyTuple_SetItem(pArgs, 0, PyLong_FromLong(64));
    PyTuple_SetItem(pArgs, 1, PyUnicode_FromString(""));  // instrType=""

    PyObject *getRes = PyObject_CallObject(get, pArgs);
    EXPECT_TRUE(getRes == NULL);
    EXPECT_TRUE(PyErr_Occurred());
    PyErr_Clear();
    
    Py_DECREF(pArgs);
    Py_DECREF(pInstance);
    Py_DECREF(get);
}
```

## 时间线

| 事件 | 时间 |
|------|------|
| 漏洞发现 | 2026-04-21 |
| 漏洞确认 | 2026-04-21 |
| 深度分析 | 2026-04-21 |

## 参考资料

1. [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
2. [Python C API: PyArg_ParseTuple](https://docs.python.org/3/c-api/arg.html#strings)
3. [C++ std::string constructor](https://en.cppreference.com/w/cpp/string/basic_string/basic_string)
4. [MindStudio MMAD Performance Prediction](https://gitee.com/ascend/mskpp)