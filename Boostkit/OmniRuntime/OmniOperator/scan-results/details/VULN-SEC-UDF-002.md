# VULN-SEC-UDF-002：UDF批量执行任意代码漏洞

> **注意**: 此漏洞与 VULN-DF-UDF-002 是同一安全问题，由 security-auditor 和 dataflow-scanner 分别发现。详情请参考 [VULN-DF-UDF-002 报告](./VULN-DF-UDF-002.md)。

## 漏洞摘要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-UDF-002 |
| **发现者** | security-auditor |
| **类型** | 任意代码执行 |
| **CWE** | CWE-94 (Improper Control of Generation of Code) |
| **严重程度** | Critical |
| **置信度** | 85/100 |
| **文件位置** | `core/src/udf/cplusplus/java_udf_functions.cpp:166-177` |
| **函数名** | `ExecuteHiveUdfBatch` |

## 核心问题

`ExecuteHiveUdfBatch` 函数同样接收 `udfClass` 参数（用户提供的 UDF 类名），直接传递给 JVM 执行批量 UDF。与 `ExecuteHiveUdfSingle` 存在相同的无验证问题。批量执行模式增加了攻击效率。

## 受影响代码片段

```cpp
void ExecuteHiveUdfBatch(int64_t contextPtr, const char *udfClass, ...) {
    if (TypeUtil::IsStringType(static_cast<type::DataTypeId>(retType))) {
        ExecHiveUdfOutputString(contextPtr, udfClass, ...);  // 无验证传递
    } else {
        ExecHiveUdfOutputNonString(contextPtr, udfClass, ...);  // 无验证传递
    }
}
```

## 修复状态

请参见 [VULN-DF-UDF-002](./VULN-DF-UDF-002.md) 的修复建议。建议与 `ExecuteHiveUdfSingle` 使用统一的验证逻辑。