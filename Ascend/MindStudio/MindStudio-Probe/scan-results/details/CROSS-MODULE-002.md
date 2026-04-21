# CROSS-MODULE-002 - 跨语言数据流漏洞

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| 漏洞 ID | CROSS-MODULE-002 |
| CWE | CWE-22 (Path Traversal) |
| 严重性 | Critical |
| 置信度 | 92% |
| 模块 | cross_module (pytorch → aclgraph_dump) |
| 文件 | ccsrc/aclgraph_dump/aclgraph_dump.cpp |
| 行号 | 341-346 |

## 漏洞判定

**此漏洞是 [SEC-ACL-SAVE-BYPASS-001](./SEC-ACL-SAVE-BYPASS-001.md) 的重复报告。**

两个漏洞描述同一跨语言安全问题：
- SEC-ACL-SAVE-BYPASS-001：强调 API 绕过和路径验证缺失
- CROSS-MODULE-002：强调 Python-C++ 跨语言数据流问题

## 跨语言数据流图

```
┌─────────────────────┐
│ Python: pytorch     │
│ acl_save(path)      │ ← 用户可控输入
└─────────┬───────────┘
          │ pybind11 绑定
          ↓
┌─────────────────────┐
│ C++: aclgraph_dump  │
│ acl_save_impl()     │ ← 🔴 无验证接收
└─────────┬───────────┘
          │
          ↓
┌─────────────────────┐
│ build_final_path()  │ ← 🔴 保留原始路径
└─────────┬───────────┘
          │
          ↓
┌─────────────────────┐
│ write_pt_or_throw() │ ← 写入任意位置
└─────────────────────┘
```

## 详细分析

请参阅核心报告：**[SEC-ACL-SAVE-BYPASS-001 深度分析](./SEC-ACL-SAVE-BYPASS-001.md)**

---

**报告生成时间**: 2026-04-21  
**判定**: 重复漏洞，详见核心报告