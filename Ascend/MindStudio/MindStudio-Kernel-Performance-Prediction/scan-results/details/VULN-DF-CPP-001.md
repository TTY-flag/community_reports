# VULN-DF-CPP-001: Null Pointer Dereference in MOV_DATA_REGISTER Macro

## 漏洞概述

| 属性 | 值 |
|------|------|
| **漏洞ID** | VULN-DF-CPP-001 |
| **类型** | Null Pointer Dereference |
| **CWE** | CWE-476 |
| **严重程度** | High |
| **置信度** | 85 |
| **文件** | csrc/interface/init_profdata_module.cpp:39-49 |
| **函数** | MOV_DATA_REGISTER macro-generated functions |
| **状态** | CONFIRMED |

## 漏洞描述

`MOV_DATA_REGISTER` 宏用于生成 MOV 类指令的性能数据获取函数。该宏通过 `PyArg_ParseTuple` 提取字符串参数 `src` 和 `dst`，但未对提取的指针进行 nullptr 或空字符串验证，直接传递给 `std::string()` 构造函数。

当 Python 调用者传入 `None` 作为字符串参数时，`PyArg_ParseTuple` 会将对应的 `const char*` 指针设置为 nullptr，随后 `std::string(nullptr)` 构造会导致 Undefined Behavior 或程序崩溃。

## 源代码分析

### 漏洞代码 (行 39-49)

```cpp
#define MOV_DATA_REGISTER(instrName)                                                                                  \
    static PyObject *MSKPP_PROFDATA_##instrName##Register(PyObject *self, PyObject *pstArgs) {                        \
        const char *src = nullptr; const char *dst = nullptr;                                                         \
        long dataSize; int transEnable;                                                                               \
        /* 这里需要使用long接收dataSize */                                                                               \
        if (!PyArg_ParseTuple(pstArgs, "ssli", &src, &dst, &dataSize, &transEnable)) { Py_RETURN_NONE; }              \
        auto instrName##Instr = MovFactory::instance()->Create(#instrName);                                           \
        if (instrName##Instr == nullptr) { Py_RETURN_NONE; }                                                          \
        return PyFloat_FromDouble(instrName##Instr->Get(std::string(src), std::string(dst), dataSize,                 \
            (bool)transEnable));                                                                                      \
    }
```

### 问题点

1. **行 41**: `src` 和 `dst` 初始化为 nullptr
2. **行 44**: `PyArg_ParseTuple` 使用 `"ssli"` 格式解析参数。`'s'` 格式允许 None，会将指针设置为 nullptr
3. **行 47-48**: 直接使用 `std::string(src)` 和 `std::string(dst)`，无验证

### 安全参考实现 (行 74-95)

```cpp
static PyObject *MSKPP_PROFDATA_MovDataGetPeak(PyObject *self, PyObject *pstArgs)
{
    const char *src = nullptr;
    const char *dst = nullptr;
    if (!PyArg_ParseTuple(pstArgs, "ss", &src, &dst)) {
        PyErr_SetString(PyExc_ValueError, "Invalid Input.");
        Py_RETURN_NONE;
    }
    if (src == nullptr || dst == nullptr) {
        PyErr_SetString(PyExc_ValueError, "src/dst cannot be None.");
        Py_RETURN_NONE;
    }
    if (std::string(src).empty() || std::string(dst).empty()) {
        PyErr_SetString(PyExc_ValueError, "src/dst cannot be empty strings");
        Py_RETURN_NONE;
    }
    // ... safe usage
}
```

该安全实现验证了：
- nullptr 检查
- 空字符串检查
- 适当的错误消息设置

## 攻击路径分析

### 完整数据流

```
Python Caller
    ↓
PyArg_ParseTuple("ssli", &src, &dst, &dataSize, &transEnable)
    ↓ [传入 None]
const char* src = nullptr, const char* dst = nullptr
    ↓
MovFactory::instance()->Create("MOV")
    ↓
MovClass::Get(std::string(nullptr), std::string(nullptr), dataSize, transEnable)
    ↓ [触发点]
std::string(nullptr) → Undefined Behavior / Segmentation Fault
```

### MovClass::Get 实现 (data_adapter.cpp:21-52)

```cpp
double MovClass::Get(std::string src, std::string dst, long dataSize, bool transEnable)
{
    std::string movPath = src + "_TO_" + dst;  // ← 若 src/dst 来自 nullptr，此处已触发 UB
    if (transEnable) {
        movPath = movPath + "_TRANS";
    }
    movPath = movPath + "_" + ArchInfo::instance()->GetChipType().substr(6, 5);
    // ...
}
```

### 触发条件

| 条件 | 描述 |
|------|------|
| **必要条件** | Python 调用者传入 `None` 作为第一个或第二个字符串参数 |
| **触发位置** | `std::string(nullptr)` 构造函数调用 |
| **触发时机** | 立即在参数解析后触发 |

## 潜在影响

### 技术影响

| 影响类型 | 描述 |
|----------|------|
| **程序崩溃** | `std::string(nullptr)` 构造会触发 Segmentation Fault，导致 Python 解释器崩溃 |
| **未定义行为** | C++ 标准规定 `std::string(nullptr)` 为 UB，可能导致数据损坏或不可预测行为 |
| **拒绝服务** | 攻击者可通过简单调用使服务不可用 |

### 业务影响

| 影域 | 影响 |
|------|------|
| **可用性** | 高 - 用户可通过恶意输入导致服务完全停止 |
| **完整性** | 无 - 无数据修改风险 |
| **机密性** | 无 - 无信息泄露风险 |

### 影响范围

- **直接影响**: `MovData.get()` Python API
- **受影响用户**: 所有使用 MSKPP 性能预测框架的开发者
- **攻击复杂度**: 低 - 仅需构造简单 Python 调用

## PoC (Proof of Concept)

### Python 触发代码

```python
from mskpp._C import prof_data

# 正常调用 (安全)
mov_data = prof_data.MovData()
result = mov_data.get("GM", "UB", 128, 0)  # 正常返回

# 恶意调用 - 触发漏洞
try:
    result = mov_data.get(None, "UB", 128, 0)  # src=None → Crash
except:
    pass

# 恶意调用 - 触发漏洞 (dst)
try:
    result = mov_data.get("GM", None, 128, 0)  # dst=None → Crash
except:
    pass

# 恶意调用 - 触发漏洞 (两者)
try:
    result = mov_data.get(None, None, 128, 0)  # src=None, dst=None → Crash
except:
    pass
```

### C++ 层崩溃验证

```cpp
// 编译并运行以下代码验证 std::string(nullptr) 的行为
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

在 `MOV_DATA_REGISTER` 宏中添加参数验证，参考 `MSKPP_PROFDATA_MovDataGetPeak` 的安全实现：

```cpp
#define MOV_DATA_REGISTER(instrName)                                                                                  \
    static PyObject *MSKPP_PROFDATA_##instrName##Register(PyObject *self, PyObject *pstArgs) {                        \
        const char *src = nullptr; const char *dst = nullptr;                                                         \
        long dataSize; int transEnable;                                                                               \
        if (!PyArg_ParseTuple(pstArgs, "ssli", &src, &dst, &dataSize, &transEnable)) {                                \
            PyErr_SetString(PyExc_ValueError, "Invalid Input.");                                                      \
            Py_RETURN_NONE;                                                                                           \
        }                                                                                                             \
        if (src == nullptr || dst == nullptr) {                                                                       \
            PyErr_SetString(PyExc_ValueError, "src/dst cannot be None.");                                             \
            Py_RETURN_NONE;                                                                                           \
        }                                                                                                             \
        if (strlen(src) == 0 || strlen(dst) == 0) {                                                                   \
            PyErr_SetString(PyExc_ValueError, "src/dst cannot be empty strings.");                                    \
            Py_RETURN_NONE;                                                                                           \
        }                                                                                                             \
        auto instrName##Instr = MovFactory::instance()->Create(#instrName);                                           \
        if (instrName##Instr == nullptr) { Py_RETURN_NONE; }                                                          \
        return PyFloat_FromDouble(instrName##Instr->Get(std::string(src), std::string(dst), dataSize,                 \
            (bool)transEnable));                                                                                      \
    }
```

### 修复要点

1. **nullptr 检查**: 在使用指针前检查是否为 nullptr
2. **空字符串检查**: 使用 `strlen()` 或 `std::string().empty()` 检查
3. **错误处理**: 使用 `PyErr_SetString()` 设置明确的错误消息
4. **一致性**: 与 `MSKPP_PROFDATA_MovDataGetPeak` 保持相同的安全模式

### 替代方案

使用 Python 的 `'s#'` 或 `'z#'` 格式代替 `'s'`，这些格式更安全：

```cpp
// 使用 's#' 格式：返回字符串和长度，长度为 0 时可用于检查空字符串
const char *src = nullptr;
Py_ssize_t src_len;
if (!PyArg_ParseTuple(pstArgs, "s#s#li", &src, &src_len, &dst, &dst_len, &dataSize, &transEnable)) {
    PyErr_SetString(PyExc_ValueError, "Invalid Input.");
    Py_RETURN_NONE;
}
if (src_len == 0 || dst_len == 0) {
    PyErr_SetString(PyExc_ValueError, "src/dst cannot be empty.");
    Py_RETURN_NONE;
}
```

## 相关漏洞

| 漏洞ID | 描述 | 关系 |
|--------|------|------|
| VULN-DF-CPP-003 | MMAD_DATA_REGISTER 空指针解引用 | 相同漏洞模式 |
| VULN-DF-CPP-002 | VEC_DATA_REGISTER 空指针解引用 | 相同漏洞模式 |

这三个漏洞源于相同的代码模式缺陷，应同步修复。

## 验证测试

### 单元测试修复验证

```cpp
TEST_F(ProfDataTest, MovData_Get_NoneProtection)
{
    auto movDataClass = GetmoduleClass("MovData");
    PyObject *pInstance = PyObject_CallObject(movDataClass, NULL);
    PyObject *get = PyObject_GetAttrString(pInstance, "get");

    // 测试 None 参数保护
    PyObject *pArgs = PyTuple_New(4);
    PyTuple_SetItem(pArgs, 0, Py_None);  // src=None
    PyTuple_SetItem(pArgs, 1, PyUnicode_FromString("UB"));
    PyTuple_SetItem(pArgs, 2, PyLong_FromLong(128));
    PyTuple_SetItem(pArgs, 3, PyLong_FromLong(0));

    PyObject *getRes = PyObject_CallObject(get, pArgs);
    EXPECT_TRUE(getRes == NULL);  // 应返回 NULL 并设置错误
    EXPECT_TRUE(PyErr_Occurred());  // 应设置 ValueError
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