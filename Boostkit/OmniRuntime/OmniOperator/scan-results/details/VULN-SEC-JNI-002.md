# VULN-SEC-JNI-002：JNI getOutput指针验证缺失

> **注意**: 此漏洞与 VULN-DF-JNI-002 是同一安全问题，由 security-auditor 和 dataflow-scanner 分别发现。详情请参考 [VULN-DF-JNI-002 报告](./VULN-DF-JNI-002.md)。

## 漏洞摘要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-JNI-002 |
| **发现者** | security-auditor |
| **类型** | 指针验证缺失 |
| **CWE** | CWE-787 (Out-of-bounds Write) |
| **严重程度** | Critical |
| **置信度** | 85/100 |
| **文件位置** | `bindings/java/src/main/cpp/src/jni_operator.cpp:178-198` |
| **函数名** | `Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative` |

## 核心问题

JNI入口点 `getOutputNative` 直接将 `jlong` 类型参数转换为 `Operator*` 指针，没有任何验证机制。攻击者可以注入任意指针值，导致内存泄露或代码执行。

## 受影响代码片段

```cpp
auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddr);
// 无任何验证，直接调用虚函数
nativeOperator->GetOutput(&outputVecBatch);
```

## 修复状态

请参见 [VULN-DF-JNI-002](./VULN-DF-JNI-002.md) 的修复建议。