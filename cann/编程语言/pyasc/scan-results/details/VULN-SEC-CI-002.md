# VULN-SEC-CI-002: emitasc::VerbatimOp 代码发射漏洞

## 漏洞概述

**漏洞类型**: 代码注入  
**CWE**: CWE-94 (Improper Control of Generation of Code)  
**严重程度**: High  
**置信度**: 80%

### 影响文件

- **文件**: `lib/Target/AscendC/EmitAsc.cpp`
- **行号**: 189-227
- **函数**: `printOperation`

### 漏洞描述

emitasc::VerbatimOp 直接输出用户提供的代码字符串到生成的 C++ 代码中。支持模板替换 ($1, $2 等) 但不对代码内容进行验证。用户可通过 `asc.inline()` API 或 MLIR 文件注入任意 C++ 代码。

---

## 关键代码片段

```cpp
// lib/Target/AscendC/EmitAsc.cpp:189-227
LogicalResult mlir::emitasc::printOperation(CodeEmitter &emitter, emitasc::VerbatimOp op) {
    auto code = op.getValue();
    auto args = op.getArgs();
    
    if (args.empty()) {
        os << code;  // 直接输出代码字符串
        return success();
    }
    
    // 模板替换：将 $1, $2, ... 替换为参数
    std::string result = code.str();
    for (size_t i = 0; i < args.size(); ++i) {
        std::string placeholder = "$" + std::to_string(i + 1);
        // 替换操作...
    }
    
    os << result;  // 输出替换后的代码
    return success();
}
```

代码发射器直接输出 VerbatimOp 的 value 字符串（或替换后的结果），没有任何内容验证。

---

## 攻击链分析

```
[输入源]
Python DSL: asc.inline("恶意代码", [args])
或 MLIR 文件: emitasc.verbatim "恶意代码"
    ↓
[MLIR IR]
emitasc::VerbatimOp value="恶意代码" args=[...]
    ↓
[EmitAsc.cpp:189-227]
模板替换（如果有参数）
os << result
    ↓
[生成的 Ascend C 文件]
包含 "恶意代码" 或替换后的恶意代码
    ↓
[bisheng 编译]
    ↓
[NPU 执行]
恶意代码在 NPU 上执行
```

---

## 修复建议

### 在代码发射前添加验证

```cpp
LogicalResult mlir::emitasc::printOperation(CodeEmitter &emitter, emitasc::VerbatimOp op) {
    auto code = op.getValue();
    
    // 验证代码内容（替换前后都需要验证）
    auto verifyCode = [](StringRef code) -> bool {
        return !code.contains("system") && 
               !code.contains("exec") &&
               !code.contains("fork") &&
               !code.contains("while(true)");
    };
    
    if (!verifyCode(code)) {
        return op.emitError() << "VerbatimOp contains forbidden keywords";
    }
    
    // 模板替换后再次验证
    std::string result = code.str();
    // 替换操作...
    
    if (!verifyCode(result)) {
        return op.emitError() << "VerbatimOp after substitution contains forbidden keywords";
    }
    
    os << result;
    return success();
}
```

---

## 相关漏洞

- **VULN-SEC-CI-001**: emitc::VerbatimOp 代码发射
- **VULN-SEC-PYBIND-002**: emitasc::VerbatimOp pybind 绑定
- **VULN-CROSS-002**: 跨模块代码注入链