# VULN-SEC-CI-001：emitc VerbatimOp代码发射漏洞

## 漏洞概述

**漏洞类型**: 代码注入  
**CWE**: CWE-94 (Improper Control of Generation of Code)  
**严重程度**: High  
**置信度**: 80%

### 影响文件

- **文件**: `lib/Target/AscendC/External/Emitc.cpp`
- **行号**: 49-52
- **函数**: `printOperation`

### 漏洞描述

emitc::VerbatimOp 直接输出用户提供的代码字符串到生成的 C++ 代码中，无任何验证或过滤。用户可通过 Python DSL 的 `asc.inline()` API 或 CLI 工具处理的 MLIR 文件注入任意 C++ 代码片段。

---

## 关键代码片段

```cpp
// lib/Target/AscendC/External/Emitc.cpp:49-52
LogicalResult mlir::printOperation(CodeEmitter &emitter, emitc::VerbatimOp verbatimOp) {
    emitter.ostream() << verbatimOp.getValue();  // 直接输出，无验证
    return success();
}
```

代码发射器直接将 VerbatimOp 的 value 字符串输出到生成的 C++ 代码中。

---

## 攻击链分析

```
[输入源]
Python DSL: asc.inline("恶意代码")
或 MLIR 文件: emitc.verbatim "恶意代码"
    ↓
[MLIR IR]
emitc::VerbatimOp value="恶意代码"
    ↓
[Emitc.cpp:49-52]
emitter.ostream() << verbatimOp.getValue()
    ↓
[生成的 C++ 文件]
包含 "恶意代码"
    ↓
[bisheng 编译]
编译恶意代码
    ↓
[NPU 执行]
恶意代码在 NPU 上执行
```

---

## 修复建议

### 在代码发射前添加验证

```cpp
LogicalResult mlir::printOperation(CodeEmitter &emitter, emitc::VerbatimOp verbatimOp) {
    auto value = verbatimOp.getValue();
    
    // 验证代码内容
    if (value.contains("system") || value.contains("exec") ||
        value.contains("fork") || value.contains("while(true)") ||
        value.contains("while (true)")) {
        return verbatimOp.emitError() << "VerbatimOp contains forbidden keywords";
    }
    
    emitter.ostream() << value;
    return success();
}
```

---

## 相关漏洞

- **VULN-SEC-CI-002**: emitasc::VerbatimOp 代码发射
- **VULN-SEC-PYBIND-001**: emitc::VerbatimOp pybind 绑定
- **VULN-CROSS-002**: 跨模块代码注入链