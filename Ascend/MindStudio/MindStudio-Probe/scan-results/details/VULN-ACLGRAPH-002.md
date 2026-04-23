# VULN-ACLGRAPH-002：build_final_path缺失路径验证致任意文件写入

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| 漏洞 ID | VULN-ACLGRAPH-002 |
| CWE | CWE-73 (External Control of File Name or Path) |
| 严重性 | High |
| 置信度 | 90% |
| 文件 | ccsrc/aclgraph_dump/aclgraph_dump.cpp |
| 行号 | 92-104 |
| 函数 | build_final_path() |

## 漏洞判定

**此漏洞是 [SEC-ACL-SAVE-BYPASS-001](./SEC-ACL-SAVE-BYPASS-001.md) 的辅助分析。**

`build_final_path` 函数是 `acl_save_impl` 调用的辅助函数，其路径验证缺失是 SEC-ACL-SAVE-BYPASS-001 的根因之一。

## 关键代码分析

```cpp
static std::string build_final_path(const std::string& path) {
    size_t last_slash = path.find_last_of("/\\");
    std::string filename = (last_slash == std::string::npos) ? path : path.substr(last_slash + 1);
    // ... 处理文件名 ...
    
    // 🔴 问题：直接拼接原始目录路径，无验证
    return path.substr(0, last_slash + 1) + oss_name.str();
}
```

**问题：**
- 只处理文件名部分，忽略目录路径验证
- 无 `realpath` 解析
- 无路径遍历检测 (`../`)
- 无绝对路径白名单

## 详细分析

请参阅核心报告：**[SEC-ACL-SAVE-BYPASS-001 深度分析](./SEC-ACL-SAVE-BYPASS-001.md)**

---

**报告生成时间**: 2026-04-21  
**判定**: 辅助漏洞，详见核心报告