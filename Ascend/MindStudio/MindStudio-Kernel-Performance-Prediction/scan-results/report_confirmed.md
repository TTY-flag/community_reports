# 漏洞扫描报告 — 已确认漏洞

**项目**: MindStudio-Kernel-Performance-Prediction
**扫描时间**: 2026-04-21T12:02:18.654Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

### 项目背景

MindStudio Kernel Performance Prediction (msKPP) 是华为 Ascend AI 处理器的算子性能预测工具。该项目采用 Python + C++ 混合架构，通过 Python API 接口调用底层 C++ 扩展模块，实现对矩阵乘法 (MMAD)、向量运算 (VEC)、数据搬运 (MOV) 等 AI 算子指令的性能上限预测。

项目核心功能：
- 基于 Tensor 参数模拟 AI 算子执行时间
- 支持 Ascend910B 系列芯片性能建模
- 提供 70+ 种向量/矩阵指令的性能预测 API
- 输出性能追踪数据 (trace.json) 和可视化分析报告

### 扫描范围

本次扫描覆盖项目核心代码：

| 类别 | 文件数 | 重点关注 |
|------|--------|----------|
| C/C++ 源文件 | 30 | Python-C++ 绑定接口、性能数据处理 |
| Python 源文件 | 52 | API 封装层、参数验证、文件操作 |
| 总计 | 82 | 高风险区域：Python-C 绑定、字符串处理 |

扫描重点聚焦于：
1. **Python-C++ 绑定接口** (`csrc/interface/`)：PyObject 参数解析、字符串提取
2. **用户输入验证**：Tensor 参数、指令类型参数
3. **文件操作安全**：路径验证、权限控制

### 关键发现

本次扫描共发现 **3 个已确认 (CONFIRMED) 漏洞**，均为 **High 严重级别**：

| 漏洞类型 | 数量 | CWE | 影响 |
|----------|------|-----|------|
| 空指针解引用 | 3 | CWE-476 | Python 解释器崩溃、拒绝服务 |

**核心问题**：三个漏洞均源于 `init_profdata_module.cpp` 中的宏定义缺陷。这些宏（`MOV_DATA_REGISTER`、`VEC_DATA_REGISTER`、`MMAD_DATA_REGISTER`）在通过 `PyArg_ParseTuple` 提取字符串参数后，未进行 nullptr 验证，直接传递给 `std::string()` 构造函数。当 Python 调用者传入 `None` 时，触发 Undefined Behavior 或 Segmentation Fault。

**影响范围评估**：
- `VEC_DATA_REGISTER` 宏影响 **50+ 个向量指令 API**
- `MMAD_DATA_REGISTER` 宏影响 AI 算子核心计算指令
- `MOV_DATA_REGISTER` 宏影响数据搬运性能预测

**风险等级**：高 - 所有使用 msKPP 进行性能预测的开发者均可能受影响，攻击复杂度低（仅需传入 None 参数）。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 3 | 33.3% |
| FALSE_POSITIVE | 3 | 33.3% |
| CONFIRMED | 3 | 33.3% |
| **总计** | **9** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 3 | 100.0% |
| **有效漏洞总计** | **3** | - |
| 误报 (FALSE_POSITIVE) | 3 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-CPP-001]** null_pointer_dereference (High) - `csrc/interface/init_profdata_module.cpp:39` @ `MOV_DATA_REGISTER macro-generated functions` | 置信度: 85
2. **[VULN-DF-CPP-002]** null_pointer_dereference (High) - `csrc/interface/init_profdata_module.cpp:62` @ `VEC_DATA_REGISTER macro-generated functions` | 置信度: 85
3. **[VULN-DF-CPP-003]** null_pointer_dereference (High) - `csrc/interface/init_profdata_module.cpp:51` @ `MMAD_DATA_REGISTER macro-generated functions` | 置信度: 85

---

## 2. 攻击面分析

### 2.1 入口点分析

根据 project_model.json 分析，项目主要攻击面如下：

| 入口类型 | 位置 | 风险等级 | 说明 |
|----------|------|----------|------|
| Python API | `mskpp/__init__.py`, `mskpp/apis.py` | Medium | 用户代码导入 mskpp 并调用指令 API |
| Python-C 绑定 | `csrc/interface/*.cpp` | High | PyObject 参数解析，字符串处理 |
| 文件输出 | `mskpp/core/trace.py`, `output_tool.py` | Low | Trace/CVS 文件写入 |
| 外部下载 | `download_dependencies.py` | High | HTTP 下载依赖包 |

### 2.2 数据流分析

```
用户 Python 代码
    ↓ 导入 mskpp
mskpp/apis.py (Python 封装)
    ↓ 调用 prof_data.*Data().get()
csrc/interface/init_profdata_module.cpp (C++ 扩展)
    ↓ PyArg_ParseTuple 提取参数
    ↓ [漏洞触发点] std::string(nullptr)
程序崩溃 (Segmentation Fault)
```

---

## 3. High 漏洞深度分析 (3)

### [VULN-DF-CPP-001] Null Pointer Dereference - MOV_DATA_REGISTER

**严重性**: High | **CWE**: CWE-476 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `csrc/interface/init_profdata_module.cpp:39-49` @ `MOV_DATA_REGISTER macro-generated functions`

#### 漏洞详情

`MOV_DATA_REGISTER` 宏通过 `PyArg_ParseTuple` 使用 `"ssli"` 格式提取 `src` 和 `dst` 字符串参数。Python 的 `'s'` 格式允许传入 `None`，此时对应的 `const char*` 指针被设置为 nullptr。

**漏洞代码**：
```cpp
#define MOV_DATA_REGISTER(instrName)
static PyObject *MSKPP_PROFDATA_##instrName##Register(PyObject *self, PyObject *pstArgs) {
  const char *src = nullptr; const char *dst = nullptr;
  long dataSize; int transEnable;
  if (!PyArg_ParseTuple(pstArgs, "ssli", &src, &dst, &dataSize, &transEnable)) { Py_RETURN_NONE; }
  // 未验证 src/dst 是否为 nullptr
  MovClass::Get(std::string(src), std::string(dst), dataSize, transEnable);  // ← UB 触发点
}
```

#### 触发条件

| 条件 | 说明 |
|------|------|
| 必要条件 | Python 调用者传入 `None` 作为 src 或 dst 参数 |
| 触发位置 | `std::string(nullptr)` 构造函数调用 |
| 触发时机 | 参数解析后立即触发 |

#### PoC 代码

```python
from mskpp._C import prof_data

mov_data = prof_data.MovData()
# 触发漏洞 - src=None 导致 std::string(nullptr)
result = mov_data.get(None, "UB", 128, 0)  # ← Segmentation Fault
```

#### 安全参考实现

项目中存在安全实现参考 `MSKPP_PROFDATA_MovDataGetPeak` (行 74-95)，正确验证了：
- nullptr 检查：`if (src == nullptr || dst == nullptr)`
- 空字符串检查：`if (strlen(src) == 0 || strlen(dst) == 0)`
- 错误消息：`PyErr_SetString(PyExc_ValueError, "...")`

---

### [VULN-DF-CPP-002] Null Pointer Dereference - VEC_DATA_REGISTER

**严重性**: High | **CWE**: CWE-476 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `csrc/interface/init_profdata_module.cpp:62-71` @ `VEC_DATA_REGISTER macro-generated functions`

#### 漏洞详情

`VEC_DATA_REGISTER` 宏用于生成 **50+ 个向量指令** 的 Python API，包括 VADD、VMUL、VCONV、VRELU 等所有向量操作指令。漏洞模式与 VULN-DF-CPP-001 相同：`instrType` 参数未验证 nullptr。

**受影响指令列表**：
| 类型 | 指令示例 |
|------|----------|
| 算术运算 | VADD, VSUB, VMUL, VDIV, VEXP, VSQRT |
| 逻辑运算 | VAND, VOR, VNOT |
| 激活函数 | VRELU, VLRELU, VADDRELU |
| 数据转换 | VCONV, VCONVDEQ |

**漏洞代码**：
```cpp
#define VEC_DATA_REGISTER(instrName)
static PyObject *MSKPP_PROFDATA_##instrName##Register(PyObject *self, PyObject *pstArgs) {
  const char *instrType = nullptr;
  long granularity;
  if (!PyArg_ParseTuple(pstArgs, "ls", &granularity, &instrType)) { Py_RETURN_NONE; }
  VecClass::Get(granularity, std::string(instrType));  // ← UB 触发点
}
```

#### 影响范围

- **50+ API 入口点**：所有向量指令均可被利用
- **高频调用**：向量指令是 AI 算子核心操作，调用频率高
- **攻击复杂度低**：仅需传入 None 参数

#### PoC 代码

```python
from mskpp._C import prof_data

# 影响所有向量指令
vadd_data = prof_data.VaddData()
result = vadd_data.get(16, None)  # ← instrType=None, Crash

vmul_data = prof_data.VmulData()
result = vmul_data.get(32, None)  # ← 同样触发漏洞
```

---

### [VULN-DF-CPP-003] Null Pointer Dereference - MMAD_DATA_REGISTER

**严重性**: High | **CWE**: CWE-476 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `csrc/interface/init_profdata_module.cpp:51-60` @ `MMAD_DATA_REGISTER macro-generated functions`

#### 漏洞详情

MMAD (Matrix Multiply Accumulate) 是 AI 算子中**最核心的计算指令**，用于矩阵乘法运算。该漏洞直接影响所有使用 MMAD 指令的性能预测功能。

**漏洞代码**：
```cpp
#define MMAD_DATA_REGISTER(instrName)
static PyObject *MSKPP_PROFDATA_##instrName##Register(PyObject *self, PyObject *pstArgs) {
  const char *instrType = nullptr;
  long granularity;
  if (!PyArg_ParseTuple(pstArgs, "ls", &granularity, &instrType)) { Py_RETURN_NONE; }
  MmadClass::Get(granularity, std::string(instrType));  // ← UB 触发点
}
```

#### 业务影响

| 影域 | 影响说明 |
|------|----------|
| AI 算子核心 | MMAD 是深度学习最基础的计算操作 |
| 性能预测精度 | MMAD 性能直接影响整体模型预测 |
| 高频调用 | 在 AI 算子模拟中频繁使用 |

#### PoC 代码

```python
from mskpp._C import prof_data

mmad_data = prof_data.MmadData()
result = mmad_data.get(64, None)  # ← instrType=None, Crash
```

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| csrc.interface | 0 | 3 | 0 | 0 | 3 |
| **合计** | **0** | **3** | **0** | **0** | **3** |

---

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-476 | 3 | 100.0% |

---

## 6. 修复建议

### 6.1 推荐修复方案

三个漏洞源于相同的代码模式缺陷，可通过修改三个宏定义**一次性修复所有受影响 API**：

#### MOV_DATA_REGISTER 修复

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

#### VEC_DATA_REGISTER / MMAD_DATA_REGISTER 修复

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

### 6.2 修复要点

| 修复项 | 说明 |
|--------|------|
| nullptr 检查 | 在使用指针前检查是否为 nullptr |
| 空字符串检查 | 使用 `strlen()` 或检查字符串长度 |
| 错误处理 | 使用 `PyErr_SetString()` 设置明确的错误消息 |
| 一致性 | 与 `MSKPP_PROFDATA_MovDataGetPeak` 安全实现保持一致 |

### 6.3 替代方案

使用 Python `'s#'` 格式获取字符串长度，避免 nullptr 问题：

```cpp
// 's#' 格式：返回字符串指针和长度，长度为 -1 时表示 None
const char *instrType = nullptr;
Py_ssize_t instrType_len;
if (!PyArg_ParseTuple(pstArgs, "ls#", &granularity, &instrType, &instrType_len)) {
    PyErr_SetString(PyExc_ValueError, "Invalid Input.");
    Py_RETURN_NONE;
}
if (instrType_len <= 0) {  // 长度为 0 或 -1 (None)
    PyErr_SetString(PyExc_ValueError, "instrType cannot be None or empty.");
    Py_RETURN_NONE;
}
```

### 6.4 测试验证建议

修复后应添加单元测试验证：

```cpp
TEST_F(ProfDataTest, MovData_Get_NoneProtection)
{
    auto movDataClass = GetmoduleClass("MovData");
    PyObject *pInstance = PyObject_CallObject(movDataClass, NULL);
    PyObject *get = PyObject_GetAttrString(pInstance, "get");

    PyObject *pArgs = PyTuple_New(4);
    PyTuple_SetItem(pArgs, 0, Py_None);  // src=None
    PyTuple_SetItem(pArgs, 1, PyUnicode_FromString("UB"));
    PyTuple_SetItem(pArgs, 2, PyLong_FromLong(128));
    PyTuple_SetItem(pArgs, 3, PyLong_FromLong(0));

    PyObject *getRes = PyObject_CallObject(get, pArgs);
    EXPECT_TRUE(getRes == NULL);  // 应返回 NULL 并设置错误
    EXPECT_TRUE(PyErr_Occurred());
    EXPECT_TRUE(PyErr_ExceptionMatches(PyExc_ValueError));
    PyErr_Clear();
}
```

### 6.5 修复优先级

| 漏洞 | 优先级 | 原因 |
|------|--------|------|
| VULN-DF-CPP-002 | **最高** | 影响 50+ API 入口点，向量指令高频调用 |
| VULN-DF-CPP-003 | **高** | MMAD 是 AI 算子核心指令，业务影响大 |
| VULN-DF-CPP-001 | **高** | MOV 指令影响数据搬运性能预测 |

**建议**：三个漏洞可**同步修复**，修改三个宏定义即可覆盖所有受影响 API。

---

## 7. 参考资料

1. [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
2. [Python C API: PyArg_ParseTuple](https://docs.python.org/3/c-api/arg.html#strings)
3. [C++ std::string constructor](https://en.cppreference.com/w/cpp/string/basic_string/basic_string)
4. [MindStudio msKPP Documentation](https://gitee.com/ascend/mskpp)

---

## 附录：深度分析报告

详细 PoC 代码、攻击路径分析、验证测试请参考：

- `{SCAN_OUTPUT}/details/VULN-DF-CPP-001.md` - MOV_DATA_REGISTER 完整分析
- `{SCAN_OUTPUT}/details/VULN-DF-CPP-002.md` - VEC_DATA_REGISTER 完整分析 (50+ API)
- `{SCAN_OUTPUT}/details/VULN-DF-CPP-003.md` - MMAD_DATA_REGISTER 完整分析