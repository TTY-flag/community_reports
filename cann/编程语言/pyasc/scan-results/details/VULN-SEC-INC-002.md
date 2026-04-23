# VULN-SEC-INC-002: CallOpaqueOp 任意函数调用

## 漏洞概述

**漏洞类型**: 代码注入  
**CWE**: CWE-94 (Improper Control of Generation of Code)  
**严重程度**: Critical  
**置信度**: 80%

### 影响文件

- **文件**: `include/ascir/Dialect/EmitAsc/IR/Ops.td`
- **行号**: 27-39
- **函数**: `EmitAsc_CallOpaqueOp`

### 漏洞描述

CallOpaqueOp 定义允许通过函数名调用任意 C++ 函数。如果 MLIR 输入中的 `callee` 字段被攻击者控制，可调用任意函数，包括危险的系统调用。

---

## 完整攻击链分析

### 数据流追踪

```
[污点源: MLIR 文件输入]
cli_tools/ascir-translate 处理 MLIR 文件
    ↓
[解析 MLIR: EmitAsc::CallOpaqueOp]
Ops.td:27-39 → CallOpaqueOp callee: StrAttr
    ↓
[无验证: 任意函数名]
    ↓
[CodeEmitter 处理]
生成 C++ 代码调用指定函数
    ↓
[污点汇: 函数调用执行]
    ↓
[恶意函数调用执行]
```

### 关键代码片段

```tablegen
// include/ascir/Dialect/EmitAsc/IR/Ops.td:27-39
def EmitAsc_CallOpaqueOp : EmitAsc_Op<"call_opaque"> {
  let arguments = (ins StrAttr:$callee, Variadic<AnyType>:$callee_operands);
  let results = (outs Optional<AnyType>:$result);
}
```

CallOpaqueOp 接受任意函数名 (`StrAttr:$callee`)，没有任何验证。

---

## PoC 构造思路

### 步骤 1: 创建恶意 MLIR 文件

```mlir
// malicious.mlir
module {
  func.func @attack(%arg0: tensor<f32>) -> tensor<f32> {
    // CallOpaqueOp 调用危险函数
    %0 = emitasc.call_opaque "system"(%arg0) : (tensor<f32>) -> tensor<f32>
    
    // 或调用自定义恶意函数（如果已编译）
    %1 = emitasc.call_opaque "malicious_function"(%arg0) : (tensor<f32>) -> tensor<f32>
    
    return %1 : tensor<f32>
  }
}
```

### 步骤 2: 使用 CLI 工具翻译

```bash
ascir-translate malicious.mlir -o output.cpp

# output.cpp 包含:
# ...
# system(arg0);  // 调用 system 函数
# malicious_function(arg0);  // 调用恶意函数
# ...
```

---

## 利用条件分析

| 条件 | 要求 | 说明 |
|------|------|------|
| 攻击者位置 | 本地 | 提供 MLIR 文件 |
| 权限要求 | 无 | 只需能提供 MLIR 输入 |
| 函数可用性 | 需要 | 目标函数需要在编译环境中可用 |
| 用户交互 | 无 | CLI 工具自动处理 |

---

## 影响分析

### 安全影响

1. **任意函数调用**: 可调用任何编译时可用的函数
2. **系统调用执行**: 可调用 `system()`、`exec()` 等危险函数
3. **数据泄露**: 可调用窃取数据的函数

---

## 修复建议

### 优先级 1: CallOpaqueOp 函数名白名单

```cpp
// 定义允许调用的函数
static const std::set<std::string> ALLOWED_CALLEES = {
  "memcpy",  // 安全限制版本
  "memset",  // 安全限制版本
  "printf",  // 日志函数
  // Ascend C API 函数
};

LogicalResult EmitAscCallOpaqueOp::verify() {
  auto callee = getCallee();
  
  if (!ALLOWED_CALLEES.count(callee.str())) {
    return emitError() << "CallOpaqueOp callee '" << callee 
                       << "' not in allowed function list";
  }
  
  return success();
}
```

### 优先级 2: 禁用危险函数

```cpp
static const std::set<std::string> FORBIDDEN_CALLEES = {
  "system", "exec", "fork", "pipe", "popen",
  "unlink", "rmdir", "chmod", "chown",
  // 其他危险函数
};

LogicalResult EmitAscCallOpaqueOp::verify() {
  auto callee = getCallee();
  
  if (FORBIDDEN_CALLEES.count(callee.str())) {
    return emitError() << "CallOpaqueOp callee '" << callee 
                       << "' is forbidden";
  }
  
  return success();
}
```

---

## 相关漏洞

- **VULN-CROSS-002**: 跨模块代码注入链
- **VULN-SEC-INC-001**: VerbatimOp 代码注入
- **VULN-SEC-EMITASC-002**: EmitAsc CallOpaqueOp 定义