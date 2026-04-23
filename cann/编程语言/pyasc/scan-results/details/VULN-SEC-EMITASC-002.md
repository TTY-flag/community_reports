# VULN-SEC-EMITASC-002: EmitAsc CallOpaqueOp 定义漏洞

## 漏洞概述

**漏洞类型**: 代码注入  
**CWE**: CWE-94 (Improper Control of Generation of Code)  
**严重程度**: High  
**置信度**: 75%

### 影响文件

- **文件**: `lib/Dialect/EmitAsc/IR/Ops.td`
- **行号**: 27-39
- **函数**: `EmitAsc_CallOpaqueOp`

### 漏洞描述

CallOpaqueOp 操作允许通过字符串名称（StrAttr:$callee）调用任意 C++ 函数。如果 callee 字符串来源于外部输入或可被用户控制，可能导致执行危险函数或代码注入。

---

## 关键代码片段

```tablegen
// lib/Dialect/EmitAsc/IR/Ops.td:27-39
def EmitAsc_CallOpaqueOp : EmitAsc_Op<"call_opaque"> {
  let arguments = (ins StrAttr:$callee, Variadic<AnyType>:$callee_operands);
  let results = (outs Optional<AnyType>:$result);
}
```

CallOpaqueOp 接受任意函数名（StrAttr），没有验证函数是否在允许列表中。

---

## 攻击链分析

与 VULN-SEC-INC-002 相同，这是 EmitAsc dialect 的 CallOpaqueOp 定义（位于 `lib/Dialect/` 目录）。

---

## 修复建议

添加 CallOpaqueOp verifier：

```tablegen
def EmitAsc_CallOpaqueOp : EmitAsc_Op<"call_opaque"> {
  let arguments = (ins StrAttr:$callee, Variadic<AnyType>:$callee_operands);
  let results = (outs Optional<AnyType>:$result);
  
  // 添加验证器
  let hasVerifier = 1;
}
```

```cpp
LogicalResult EmitAscCallOpaqueOp::verify() {
  auto callee = getCallee();
  
  // 定义允许的函数列表
  static const std::set<std::string> ALLOWED_CALLEES = {
    // Ascend C API 函数
    // 安全的标准库函数
  };
  
  // 定义禁止的函数列表
  static const std::set<std::string> FORBIDDEN_CALLEES = {
    "system", "exec", "fork", "pipe", "popen",
    "unlink", "rmdir", "chmod", "chown",
  };
  
  if (FORBIDDEN_CALLEES.count(callee.str())) {
    return emitError() << "CallOpaqueOp callee '" << callee << "' is forbidden";
  }
  
  if (!ALLOWED_CALLEES.count(callee.str())) {
    return emitWarning() << "CallOpaqueOp callee '" << callee << "' not in allowed list";
  }
  
  return success();
}
```

---

## 相关漏洞

- **VULN-SEC-INC-002**: include/ EmitAsc CallOpaqueOp
- **VULN-SEC-EMITASC-003**: VerbatimOp 定义
- **VULN-CROSS-002**: 跨模块代码注入链