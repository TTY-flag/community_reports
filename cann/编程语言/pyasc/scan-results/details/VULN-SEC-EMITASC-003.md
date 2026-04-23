# VULN-SEC-EMITASC-003：EmitAsc VerbatimOp定义漏洞

## 漏洞概述

**漏洞类型**: 代码注入  
**CWE**: CWE-94 (Improper Control of Generation of Code)  
**严重程度**: High  
**置信度**: 80%

### 影响文件

- **文件**: `lib/Dialect/EmitAsc/IR/Ops.td`
- **行号**: 167-170
- **函数**: `EmitAsc_VerbatimOp`

### 漏洞描述

VerbatimOp 操作允许直接嵌入原始代码字符串（StrAttr:$value）。如果 value 字符串来源于外部输入或可被用户控制，可能导致代码注入或执行恶意代码片段。

---

## 关键代码片段

```tablegen
// lib/Dialect/EmitAsc/IR/Ops.td:167-170
def EmitAsc_VerbatimOp : EmitAsc_Op<"verbatim"> {
  let arguments = (ins StrAttr:$value, Variadic<AnyType>:$args);
  let assemblyFormat = "$value ($args^ `:` type($args))?  attr-dict";
}
```

VerbatimOp 接受任意字符串（StrAttr），没有内容验证或约束。

---

## 攻击链分析

与 VULN-SEC-INC-001 相同，这是 EmitAsc dialect 的 VerbatimOp 定义（位于 `lib/Dialect/` 目录而非 `include/`）。

---

## 修复建议

添加 VerbatimOp verifier：

```tablegen
def EmitAsc_VerbatimOp : EmitAsc_Op<"verbatim"> {
  let arguments = (ins StrAttr:$value, Variadic<AnyType>:$args);
  let assemblyFormat = "$value ($args^ `:` type($args))?  attr-dict";
  
  // 添加验证器
  let hasVerifier = 1;
}
```

```cpp
LogicalResult EmitAscVerbatimOp::verify() {
  auto value = getValue();
  
  // 检查危险关键字
  if (value.contains("system") || value.contains("exec") ||
      value.contains("fork") || value.contains("pipe")) {
    return emitError() << "VerbatimOp contains forbidden keywords: " << value;
  }
  
  return success();
}
```

---

## 相关漏洞

- **VULN-SEC-INC-001**: include/ EmitAsc VerbatimOp
- **VULN-SEC-EMITASC-002**: CallOpaqueOp 定义
- **VULN-CROSS-002**: 跨模块代码注入链