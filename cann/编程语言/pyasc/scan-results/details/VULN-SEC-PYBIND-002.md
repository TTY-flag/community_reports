# VULN-SEC-PYBIND-002: emitasc::VerbatimOp pybind 绑定漏洞

## 漏洞概述

**漏洞类型**: 代码注入  
**CWE**: CWE-94 (Improper Control of Generation of Code)  
**严重程度**: High  
**置信度**: 80%

### 影响文件

- **文件**: `python/src/OpBuilder.cpp`
- **行号**: 791-794
- **函数**: `bind_create_emitasc_operations`

### 漏洞描述

emitasc::VerbatimOp pybind 绑定直接将用户提供的字符串和参数插入到生成的代码中，无验证。恶意用户可注入任意代码片段。

---

## 关键代码片段

```cpp
// python/src/OpBuilder.cpp:791-794
.def(
    "create_emitasc_VerbatimOp",
    [](PyOpBuilder &self, const std::string &value, const std::optional<std::vector<Value>> &args) {
        self.create<emitasc::VerbatimOp>(self->getStringAttr(value), args.value_or(noValues));
    },
    "value"_a, "args"_a = py::none());
```

绑定直接接受 `value` 字符串，没有任何内容验证。

---

## 攻击链分析

与 VULN-SEC-PYBIND-001 类似，但针对 `emitasc` dialect：

```
[Python 用户输入]
builder.create_emitasc_VerbatimOp("恶意代码", args)
    ↓
[OpBuilder.cpp:791-794]
直接传递到 emitasc::VerbatimOp
    ↓
[EmitAsc.cpp]
emitter.ostream() << result (模板替换后)
    ↓
[生成的 Ascend C 代码]
    ↓
[编译执行恶意代码]
```

---

## 修复建议

与 VULN-SEC-PYBIND-001 相同的修复方案：添加内容验证。

---

## 相关漏洞

- **VULN-SEC-PYBIND-001**: emitc::VerbatimOp 绑定
- **VULN-SEC-CI-002**: emitasc::VerbatimOp 代码发射
- **VULN-CROSS-002**: 跨模块代码注入链