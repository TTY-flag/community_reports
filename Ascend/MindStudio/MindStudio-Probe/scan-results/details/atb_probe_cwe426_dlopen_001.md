# atb_probe_cwe426_dlopen_001 - dlopen 不可信搜索路径漏洞

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| 漏洞 ID | atb_probe_cwe426_dlopen_001 |
| CWE | CWE-426 (Untrusted Search Path) |
| 严重性 | Critical |
| 置信度 | 95% |
| 文件 | ccsrc/atb_probe/atb_probe.cpp |
| 行号 | 171-195 |

## 漏洞判定

**此漏洞是 [SEC-DLOPEN-ROOT-BYPASS-001](./SEC-DLOPEN-ROOT-BYPASS-001.md) 的重复报告。**

两个漏洞描述同一代码缺陷的不同视角：
- SEC-DLOPEN-ROOT-BYPASS-001：强调 root 用户权限绕过问题
- atb_probe_cwe426_dlopen_001：强调不可信搜索路径问题

## 详细分析

请参阅核心报告：**[SEC-DLOPEN-ROOT-BYPASS-001 深度分析](./SEC-DLOPEN-ROOT-BYPASS-001.md)**

---

**报告生成时间**: 2026-04-21  
**判定**: 重复漏洞，详见核心报告