# VULN-SEC-PYBIND-001：VerbatimOp pybind绑定漏洞

## 漏洞概述

**漏洞类型**: 代码注入  
**CWE**: CWE-94 (Improper Control of Generation of Code)  
**严重程度**: High  
**置信度**: 80%

### 影响文件

- **文件**: `python/src/OpBuilder.cpp`
- **行号**: 765-766
- **函数**: `bind_create_emitc_operations`

### 漏洞描述

VerbatimOp pybind 绑定直接将用户提供的字符串插入到生成的代码中，无任何验证或过滤。恶意用户可通过 Python API 注入任意 C++ 代码片段。

---

## 完整攻击链分析

### 数据流追踪

```
[污点源: Python 用户输入]
用户调用 builder.create_emitc_VerbatimOp(恶意字符串)
    ↓
[OpBuilder.cpp:765-766]
.def("create_emitc_VerbatimOp",
     [](PyOpBuilder &self, const std::string &str) {
         self.create<emitc::VerbatimOp>(StringRef(str));
     })
    ↓
[无验证: 直接传递字符串]
    ↓
[MLIR: emitc.verbatim "恶意代码"]
    ↓
[CodeEmitter]
Emitc.cpp:49-52 → emitter.ostream() << op.getValue()
    ↓
[污点汇: 生成的 C++ 代码]
    ↓
[恶意 C++ 代码编译执行]
```

### 关键代码片段

```cpp
// python/src/OpBuilder.cpp:765-766
.def("create_emitc_VerbatimOp",
     [](PyOpBuilder &self, const std::string &str) {
         self.create<emitc::VerbatimOp>(StringRef(str));
     })
```

绑定直接接受用户字符串，没有任何验证。

---

## PoC 构造思路

### 通过 Python API 注入

```python
import asc
from asc._C import ir

# 创建恶意 VerbatimOp
builder = ir.OpBuilder()
builder.create_emitc_VerbatimOp("system(\"id > /tmp/pwned\");")

# 生成的 C++ 代码包含恶意代码
# 编译执行后，恶意代码在 NPU 上运行
```

---

## 修复建议

### 优先级 1: pybind 绑定添加验证

```cpp
// 修改 OpBuilder.cpp
.def("create_emitc_VerbatimOp",
     [](PyOpBuilder &self, const std::string &str) {
         // 添加验证
         if (str.find("system") != std::string::npos ||
             str.find("exec") != std::string::npos ||
             str.find("fork") != std::string::npos) {
             throw py::value_error("VerbatimOp contains forbidden keywords");
         }
         
         self.create<emitc::VerbatimOp>(StringRef(str));
     })
```

---

## 相关漏洞

- **VULN-SEC-PYBIND-002**: emitasc::VerbatimOp 绑定
- **VULN-SEC-CI-001**: emitc::VerbatimOp 代码发射
- **VULN-CROSS-002**: 跨模块代码注入链