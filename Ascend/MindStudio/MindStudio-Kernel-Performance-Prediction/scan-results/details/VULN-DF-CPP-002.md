# VULN-DF-CPP-002: Null Pointer Dereference in VEC_DATA_REGISTER Macro

## 漏洞概述

| 属性 | 值 |
|------|------|
| **漏洞ID** | VULN-DF-CPP-002 |
| **类型** | Null Pointer Dereference |
| **CWE** | CWE-476 |
| **严重程度** | High |
| **置信度** | 85 |
| **文件** | csrc/interface/init_profdata_module.cpp:62-71 |
| **函数** | VEC_DATA_REGISTER macro-generated functions |
| **状态** | CONFIRMED |

## 漏洞描述

`VEC_DATA_REGISTER` 宏用于生成向量类指令的性能数据获取函数。该宏通过 `PyArg_ParseTuple` 提取字符串参数 `instrType`，但未对提取的指针进行 nullptr 或空字符串验证，直接传递给 `std::string()` 构造函数。

**影响范围极大**：该宏被用于生成 **50+ 个向量指令** 的 Python API，包括 VABS、VADD、VAND、VCONV、VMUL、VSUB 等所有向量操作指令。

当 Python 调用者传入 `None` 作为 `instrType` 参数时，`PyArg_ParseTuple` 会将 `const char* instrType` 设置为 nullptr，随后 `std::string(nullptr)` 构造会导致 Undefined Behavior 或程序崩溃。

## 受影响指令列表

以下所有指令的 `get()` 方法均受此漏洞影响：

| 指令类型 | 数量 |
|----------|------|
| 算术运算 | VADD, VADDS, VSUB, VMUL, VMULS, VDIV, VEXP, VLN, VSQRT, VRSQRT, VREC |
| 逻辑运算 | VAND, VOR, VNOT |
| 比较运算 | VCMP, VCMPV, VCMPVS, VCMAX, VCMIN, VCGMAX, VCGMIN |
| 数据转换 | VCONV, VCONVDEQ, VCONVVDEQ |
| 数据移动 | VCOPY, VECTORDUP, VGATHER, VGATHERB |
| 激活函数 | VRELU, VLRELU, VADDRELU, VSUBRELU |
| 其他运算 | VAXPY, VBRCB, VCADD, VCPADD, VSEL, VSHL, VSHR, VMADD, VMLA, VREDUCE, VREDUCEV2, VMULCONV, VMRGSORT |

**总计**: 约 50+ 个向量指令 API

## 源代码分析

### 漏洞代码 (行 62-71)

```cpp
#define VEC_DATA_REGISTER(instrName)                                                           \
    static PyObject *MSKPP_PROFDATA_##instrName##Register(PyObject *self, PyObject *pstArgs)   \
    {                                                                                          \
        long granularity;                                                                      \
        const char *instrType = nullptr;                                                       \
        if (!PyArg_ParseTuple(pstArgs, "ls", &granularity, &instrType)) { Py_RETURN_NONE; }    \
        auto instrName##Instr = VecFactory::instance()->Create(#instrName, #instrName);        \
        if (instrName##Instr == nullptr) { Py_RETURN_NONE; }                                   \
        return PyFloat_FromDouble(instrName##Instr->Get(granularity, std::string(instrType))); \
    }
```

### 问题点

1. **行 66**: `instrType` 初始化为 nullptr
2. **行 67**: `PyArg_ParseTuple` 使用 `"ls"` 格式解析参数。`'s'` 格式允许 None，会将指针设置为 nullptr
3. **行 70**: 直接使用 `std::string(instrType)`，无验证

### 宏展开示例 (VADD)

```cpp
// VEC_DATA_REGISTER(VADD) 展开后:
static PyObject *MSKPP_PROFDATA_VADDRegister(PyObject *self, PyObject *pstArgs)
{
    long granularity;
    const char *instrType = nullptr;
    if (!PyArg_ParseTuple(pstArgs, "ls", &granularity, &instrType)) { Py_RETURN_NONE; }
    auto VADDInstr = VecFactory::instance()->Create("VADD", "VADD");
    if (VADDInstr == nullptr) { Py_RETURN_NONE; }
    return PyFloat_FromDouble(VADDInstr->Get(granularity, std::string(instrType)));
}
```

## 攻击路径分析

### 完整数据流

```
Python Caller (e.g., VaddData().get(16, None))
    ↓
PyArg_ParseTuple("ls", &granularity, &instrType)
    ↓ [传入 None]
const char* instrType = nullptr
    ↓
VecFactory::instance()->Create("VADD", "VADD")
    ↓
VecClass::Get(granularity, std::string(nullptr))
    ↓ [触发点]
std::string(nullptr) → Undefined Behavior / Segmentation Fault
```

### VecClass::Get 实现 (data_adapter.cpp:146-167)

```cpp
double VecClass::Get(long granularity, const std::string& instrType)
{
    std::string fullOpName = instrName + "_" + instrType + "_1_core_" +
        ArchInfo::instance()->GetChipType().substr(6, 5);  // ← 若 instrType 来自 nullptr，此处已触发 UB
    auto res = GetVecTypeData(fullOpName);
    // ...
}
```

注意：虽然参数类型为 `const std::string&`，但在调用之前 `std::string(nullptr)` 构造已触发 UB。

### 触发条件

| 条件 | 描述 |
|------|------|
| **必要条件** | Python 调用者传入 `None` 作为第二个参数 (instrType) |
| **触发位置** | `std::string(nullptr)` 构造函数调用 (行 70) |
| **触发时机** | 立即在参数解析后触发 |

## 潜在影响

### 技术影响

| 影响类型 | 描述 |
|----------|------|
| **程序崩溃** | `std::string(nullptr)` 构造会触发 Segmentation Fault |
| **攻击面扩大** | 50+ 个向量指令 API 均可被利用 |
| **拒绝服务** | 任意向量指令 API 均可导致服务崩溃 |

### 业务影响

| 影域 | 影响 |
|------|------|
| **可用性** | 高 - 50+ API 入口点均可触发崩溃 |
| **完整性** | 无 |
| **机密性** | 无 |

### 影响范围评估

```
受影响 API 数量: 50+ 个向量指令
每个 API 的调用频率: 高 (向量指令是 AI 算子核心操作)
攻击复杂度: 低 (仅需传入 None)
利用价值: 高 (影响所有使用向量指令的性能预测)
```

## PoC (Proof of Concept)

### Python 触发代码

```python
from mskpp._C import prof_data

# 受影响的向量指令列表 (部分示例)
vec_classes = [
    'VaddData', 'VmulData', 'VsubData', 'VconvData', 
    'VabsData', 'VexpData', 'VsqrtData', 'VreluData',
    'VcmpData', 'VandData', 'VorData', 'VcopyData',
    # ... 还有约 40+ 个其他向量指令
]

# 恶意调用 - 针对所有向量指令
for vec_name in vec_classes:
    try:
        vec_data = getattr(prof_data, vec_name)()
        # 传入 None 作为 instrType
        result = vec_data.get(16, None)  # ← 触发漏洞，导致崩溃
    except Exception as e:
        print(f"{vec_name}: {e}")

# 单个指令 PoC
vadd_data = prof_data.VaddData()
try:
    result = vadd_data.get(16, None)  # ← Crash
except:
    pass
```

### 验证代码

```cpp
// 编译并运行验证 std::string(nullptr) 行为
#include <string>

int main() {
    const char* ptr = nullptr;
    std::string s(ptr);  // ← Segmentation Fault
    return 0;
}
```

## 修复建议

### 推荐修复方案

在 `VEC_DATA_REGISTER` 宏中添加参数验证：

```cpp
#define VEC_DATA_REGISTER(instrName)                                                           \
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
        auto instrName##Instr = VecFactory::instance()->Create(#instrName, #instrName);        \
        if (instrName##Instr == nullptr) { Py_RETURN_NONE; }                                   \
        return PyFloat_FromDouble(instrName##Instr->Get(granularity, std::string(instrType))); \
    }
```

### 批量修复策略

由于该宏影响 50+ 个指令，修复该宏即可同时修复所有向量指令的漏洞：

1. **单点修复**: 只需修改宏定义一处
2. **自动覆盖**: 所有使用该宏的指令自动获得修复
3. **测试覆盖**: 为每个受影响指令添加 None 参数测试

### 替代方案

使用 `'s#'` 格式获取字符串长度：

```cpp
#define VEC_DATA_REGISTER(instrName)                                                           \
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
        auto instrName##Instr = VecFactory::instance()->Create(#instrName, #instrName);        \
        if (instrName##Instr == nullptr) { Py_RETURN_NONE; }                                   \
        return PyFloat_FromDouble(instrName##Instr->Get(granularity, std::string(instrType, instrType_len))); \
    }
```

## 相关漏洞

| 漏洞ID | 描述 | 关系 |
|--------|------|------|
| VULN-DF-CPP-001 | MOV_DATA_REGISTER 空指针解引用 | 相同漏洞模式 |
| VULN-DF-CPP-003 | MMAD_DATA_REGISTER 空指针解引用 | 相同漏洞模式 |

这三个漏洞源于相同的代码模式缺陷，应同步修复。

## Python 层面缓解措施

在 Python 封装层添加类型检查（临时缓解）：

```python
# mskpp/prof_data/vector_unary_instr_prof.py
class VectorInstrProf(PrefModel):
    def time(self):
        # 添加参数验证
        if self.instr_type is None:
            raise ValueError("instr_type cannot be None")
        if not self.instr_type:
            raise ValueError("instr_type cannot be empty")
        # 原有逻辑...
```

**注意**: 这只是缓解措施，不能完全阻止恶意用户直接调用底层 C API。

## 验证测试

### 批量测试所有向量指令

```cpp
TEST_F(ProfDataTest, Vec_Get_All_NoneProtection)
{
    std::vector<std::string> vecClasses = {
        "VaddData", "VmulData", "VsubData", "VconvData", 
        "VabsData", "VexpData", "VsqrtData", "VreluData",
        // ... 所有受影响的向量指令
    };
    
    for (const auto& className : vecClasses) {
        PyObject *vecClass = GetmoduleClass(className);
        PyObject *pInstance = PyObject_CallObject(vecClass, NULL);
        PyObject *get = PyObject_GetAttrString(pInstance, "get");

        // 测试 None 参数保护
        PyObject *pArgs = PyTuple_New(2);
        PyTuple_SetItem(pArgs, 0, PyLong_FromLong(16));
        PyTuple_SetItem(pArgs, 1, Py_None);  // instrType=None

        PyObject *getRes = PyObject_CallObject(get, pArgs);
        EXPECT_TRUE(getRes == NULL) << className << " should reject None";
        EXPECT_TRUE(PyErr_Occurred());
        PyErr_Clear();
        
        Py_DECREF(pArgs);
        Py_DECREF(pInstance);
        Py_DECREF(get);
    }
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