# VULN-SEC-JNI-003：JNI close指针验证缺失漏洞

> **注意**: 此漏洞与 VULN-DF-JNI-003 是同一安全问题，由 security-auditor 和 dataflow-scanner 分别发现。详情请参考 [VULN-DF-JNI-003 报告](./VULN-DF-JNI-003.md)。

## 漏洞摘要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-JNI-003 |
| **发现者** | security-auditor |
| **类型** | 指针验证缺失 / Use-After-Free |
| **CWE** | CWE-787 (Out-of-bounds Write) |
| **严重程度** | Critical |
| **置信度** | 85/100 |
| **文件位置** | `bindings/java/src/main/cpp/src/jni_operator.cpp:205-214` |
| **函数名** | `Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative` |

## 核心问题

JNI入口点 `closeNative` 直接将 `jlong` 类型参数转换为 `Operator*` 指针并调用 `DeleteOperator`，没有任何验证机制。攻击者可以：

1. 传入任意地址导致非法内存释放
2. 多次调用同一地址导致 double-free
3. 释放其他对象导致 use-after-free

## 受影响代码片段

```cpp
auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddr);
op::Operator::DeleteOperator(nativeOperator);  // 无验证释放
```

## 修复状态

请参见 [VULN-DF-JNI-003](./VULN-DF-JNI-003.md) 的修复建议。核心修复方案是使用注册表机制防止 double-free 和任意释放。