# VULN-SEC-HELPER-001：JNI Helper指针验证缺失

> **注意**: 此漏洞与 VULN-DF-JNI-005 是同一安全问题，由 security-auditor 和 dataflow-scanner 分别发现。详情请参考 [VULN-DF-JNI-005 报告](./VULN-DF-JNI-005.md)。

## 漏洞摘要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-HELPER-001 |
| **发现者** | security-auditor |
| **类型** | 指针验证缺失 |
| **CWE** | CWE-787 (Out-of-bounds Write) |
| **严重程度** | High |
| **置信度** | 85/100 |
| **文件位置** | `bindings/java/src/main/cpp/src/jni_helper.cpp:8-25` |
| **函数名** | `Java_nova_hetu_omniruntime_utils_ShuffleHashHelper_computePartitionIds` |

## 核心问题

`jni_helper.cpp` 中 `computePartitionIds` 函数直接将 `jlongArray` 数组元素转换为 `BaseVector*` 指针数组，没有验证每个指针的有效性。攻击者可以通过构造包含恶意地址的数组触发内存访问问题或潜在的代码执行。

## 受影响代码片段

```cpp
jlong *addrs = (*env).GetLongArrayElements(vecAddrArray, nullptr);
std::vector<omniruntime::vec::BaseVector *> vecs;
for (int i = 0; i < length; ++i) {
    auto vec = reinterpret_cast<omniruntime::vec::BaseVector *>(addrs[i]); // 直接转换指针
    vecs.push_back(vec);
}
```

## 安全风险

1. **数组批量注入**: 一次性注入多个恶意指针
2. **缺少魔术字验证**: 无法确认指针指向真实 BaseVector 对象
3. **缺少 NULL 检查**: 数组元素可能为 0
4. **缺少地址范围检查**: 未验证地址在合法内存范围

## 修复状态

请参见 [VULN-DF-JNI-005](./VULN-DF-JNI-005.md) 的修复建议。核心修复方案是在循环中对每个数组元素执行 NULL 检查和魔术字验证。