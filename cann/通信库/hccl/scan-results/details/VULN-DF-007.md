# VULN-DF-007: 动态库加载相对路径注入漏洞

> **合并说明**: 此漏洞与 VULN-SEC-DL-002 为同一安全问题的不同发现点。
> 
> 详细分析请参考: **[VULN-SEC-DL-002.md](./VULN-SEC-DL-002.md)**

## 漏洞概要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-007 |
| **关联漏洞** | VULN-SEC-DL-002 |
| **CWE** | CWE-426: Untrusted Search Path |
| **严重性** | High |
| **置信度** | 85 |

## 代码位置

**文件**: `src/common/hcomm_dlsym/hcomm_dlsym.cc`
**行号**: 60-64
**函数**: `HcommDlInit()`

```cpp
gLibHandle = dlopen("libhcomm.so", RTLD_NOW);
if (!gLibHandle) {
    fprintf(stderr, "[HcclWrapper] Failed to open libhcomm: %s\n", dlerror());
    return;
}
```

## 关键发现

此漏洞点通过 `__attribute__((constructor))` 在库加载时自动触发，是攻击链的**最早入口点**:

```
应用程序加载 libhccl.so
→ InitCompat() (constructor)
→ HcommDlInit()  ← 此漏洞点
→ dlopen("libhcomm.so")
```

完整利用分析和修复建议请参阅主报告。