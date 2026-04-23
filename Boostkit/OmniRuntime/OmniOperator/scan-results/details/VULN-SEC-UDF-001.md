# VULN-SEC-UDF-001：UDF类名注入导致任意代码执行

> **注意**: 此漏洞与 VULN-DF-UDF-001 是同一安全问题，由 security-auditor 和 dataflow-scanner 分别发现。详情请参考 [VULN-DF-UDF-001 报告](./VULN-DF-UDF-001.md)。

## 漏洞摘要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-UDF-001 |
| **发现者** | security-auditor |
| **类型** | 任意代码执行 |
| **CWE** | CWE-94 (Improper Control of Generation of Code) |
| **严重程度** | Critical |
| **置信度** | 85/100 |
| **文件位置** | `core/src/udf/cplusplus/java_udf_functions.cpp:42-73` |
| **函数名** | `ExecuteHiveUdfSingle` |

## 核心问题

`ExecuteHiveUdfSingle` 函数接收 `udfClass` 参数（用户提供的 UDF 类名），直接通过 JNI 传递给 JVM 执行，没有任何验证机制（如白名单、黑名单、包名前缀检查）。攻击者可以执行任意 Java 类，实现完全的远程代码执行。

## 受影响代码片段

```cpp
jstring jUdfClassName = env->NewStringUTF(udfClass);  // 无验证
env->CallStaticVoidMethod(executorCls, executeSingleMethod, jUdfClassName, ...);  // 执行任意类
```

## 攻击示例

```sql
-- 直接执行系统命令
CREATE TEMPORARY FUNCTION exploit AS 'java.lang.Runtime';
SELECT exploit('exec', 'id') FROM table;
```

## 修复状态

请参见 [VULN-DF-UDF-001](./VULN-DF-UDF-001.md) 的修复建议。核心修复方案是实施 UDF 类名白名单验证和注册机制。