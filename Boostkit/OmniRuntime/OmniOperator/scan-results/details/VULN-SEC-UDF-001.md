# VULN-SEC-UDF-001 / udf-001: UDF 任意代码执行漏洞

## 漏洞概述

**漏洞类型**: 任意代码执行 (CWE-94/CWE-470)  
**严重级别**: Critical  
**置信度**: 95%  
**影响模块**: util, codegen, udf

UDF 类名参数从用户 SQL 查询传递到 JNI 执行层，无任何验证。Java 端使用 `Class.forName` 加载任意类，静态初始化器在 UDF 检查前执行。

## 分析说明

此漏洞与 **VULN-XMOD-001** 和 **udf-005** 属于同一攻击链的不同报告。

完整攻击路径分析请参考：
- `VULN-XMOD-001.md` - 跨模块攻击链完整分析
- `VULN-SEC-UDF-004.md` - DLLEXPORT 绕过白名单分析
- `udf-005.md` - Java 端不安全类加载分析

## 漏洞本质

```
SQL 查询 (用户输入)
    ↓
JSONParser::ParseJSONFunc
    ↓
FuncExpr.funcName = udfClassName
    ↓
expression_codegen.cpp → 编译为 LLVM IR
    ↓
EvaluateHiveUdfSingle [DLLEXPORT]
    ↓
ExecuteHiveUdfSingle → JNI 调用
    ↓
HiveUdfExecutor.java → Class.forName(udfClassName, true, loader)
    ↓
⚠️ 静态初始化器执行 → 任意代码执行
```

## 关键缺陷

1. **无类名验证**: `udfClass` 参数从 SQL 传递到 JNI，无验证
2. **DLLEXPORT 绕过**: 导出函数可被直接调用，绕过属性文件白名单
3. **静态初始化器先执行**: `Class.forName(..., true, ...)` 的 `true` 参数导致类初始化
4. **检查太晚**: `UDF.class.isAssignableFrom` 在类加载后检查

## 修复建议

参考 VULN-XMOD-001.md 和 udf-005.md 中的详细修复方案。

## 相关漏洞

| ID | 描述 | 关系 |
|----|------|------|
| VULN-XMOD-001 | UDF 链任意代码执行 | 完整攻击链分析 |
| VULN-SEC-UDF-004 | 安全控制绕过 | DLLEXPORT 绕过 |
| udf-001 | 信任边界违规 | C++ 端问题 |
| udf-005 | 不安全类加载 | Java 端问题 |
| VULN-SEC-UDF-001 | 任意代码执行 | 相同漏洞 |