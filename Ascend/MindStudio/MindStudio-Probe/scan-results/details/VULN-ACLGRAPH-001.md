# VULN-ACLGRAPH-001 - acl_save_impl 路径遍历漏洞

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| 漏洞 ID | VULN-ACLGRAPH-001 |
| CWE | CWE-22 (Path Traversal) |
| 严重性 | High |
| 置信度 | 90% |
| 文件 | ccsrc/aclgraph_dump/aclgraph_dump.cpp |
| 行号 | 341-346 |

## 漏洞判定

**此漏洞是 [SEC-ACL-SAVE-BYPASS-001](./SEC-ACL-SAVE-BYPASS-001.md) 的重复报告。**

两个漏洞描述同一代码缺陷：
- SEC-ACL-SAVE-BYPASS-001：强调 API 绕过和跨语言安全问题
- VULN-ACLGRAPH-001：强调路径遍历数据流

## 详细分析

请参阅核心报告：**[SEC-ACL-SAVE-BYPASS-001 深度分析](./SEC-ACL-SAVE-BYPASS-001.md)**

---

**报告生成时间**: 2026-04-21  
**判定**: 重复漏洞，详见核心报告