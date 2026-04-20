# VULN-SEC-OOB-001: UTF-8 越界读取漏洞

## 漏洞概述

**漏洞类型**: 越界读取 (CWE-125)  
**严重级别**: High (原 Medium)  
**置信度**: 50%  
**影响模块**: codegen

OmniOperator 的 `RegexpExtractRetNull` 函数在处理多字节 UTF-8 字符时存在越界读取风险。函数将输入字符串转换为宽字符串进行正则匹配，但将宽字符串的匹配位置（startIdx）直接用于字节字符串的偏移计算，导致索引不一致。

## 漏洞触发条件

1. 输入字符串包含多字节 UTF-8 字符
2. 正则表达式匹配位于多字节字符序列中
3. 计算的字节偏移超出实际字符串长度

## 关键代码分析

### stringfunctions.cpp:155-162

```cpp
extern "C" DLLEXPORT const char *RegexpExtractRetNull(...)
{
    std::string s(str, strLen);
    std::wstring ws = StringUtil::ToWideString(s);  // 转换为宽字符串
    
    std::wregex re(StringUtil::ToWideString(r));
    std::wsmatch match;
    
    if (std::regex_search(ws, match, re) && match.size() > group) {
        int startIdx = match.position(group);  // ⚠️ 宽字符串索引
        std::wstring matchedWstr = match[group].str();
        std::wstring_convert<std::codecvt_utf8<wchar_t>> convert;
        std::string matchedNstr = convert.to_bytes(matchedWstr);
        *outLen = matchedNstr.size();
        auto ret = ArenaAllocatorMalloc(contextPtr, *outLen + 1);
        // ⚠️ 关键缺陷: startIdx 是宽字符索引，但用于字节字符串偏移
        memcpy_s(ret, *outLen + 1, str + startIdx, *outLen + 1);  // 错误偏移！
        return ret;
    }
    ...
}
```

**安全缺陷分析**:
- `ws` 是宽字符串，每个字符可能对应多个字节
- `match.position(group)` 返回宽字符串中的字符位置
- `str + startIdx` 使用字节偏移，但 `startIdx` 是字符位置
- 对于多字节 UTF-8 字符，字符位置 ≠ 字节位置

## 问题示例

```
输入字符串 (UTF-8): "你好世界"  (每个汉字 3 bytes)
字节表示: "\xe4\xbd\xa0\xe5\xa5\xbd\xe4\xb8\x96\xe7\x95\x8c" (12 bytes)
宽字符串: 4 个宽字符

假设正则匹配 "好" (第 2 个字符):
- 宽字符串位置: startIdx = 1 (第 2 个字符)
- 正确字节偏移: 3 bytes (第一个汉字占 3 bytes)
- 错误代码使用: str + 1 (偏移 1 byte)
- 结果: 从第 1 个字节开始读取，而不是第 4 个字节
- 可能越界读取或读取错误数据
```

## 利用步骤 (PoC)

### 构造恶意输入

```sql
-- 使用包含多字节 UTF-8 字符的字符串
SELECT regexp_extract('你好世界测试数据', '好', 0) FROM table;
-- 或更极端的例子
SELECT regexp_extract('𠮷𠮷𠮷𠮷', '𠮷', 0) FROM table;  -- 4-byte UTF-8 字符
```

### 构造越界读取场景

```sql
-- 构造长字符串，正则匹配位于末尾的多字节字符
SELECT regexp_extract(
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA你好',
    '好',
    0
) FROM table;
-- 宽字符串索引计算可能超出字节字符串边界
```

## 危害评估

### 攻击影响
- **越界读取**: 可能读取超出字符串边界的数据
- **信息泄露**: 可能泄露相邻内存内容
- **数据处理错误**: 返回错误的匹配结果

### CVSS 评分预估
- **攻击向量**: Network (通过 SQL 输入)
- **攻击复杂度**: Medium (需要构造特定 UTF-8 输入)
- **权限要求**: Low
- **影响**: Medium (信息泄露) / Low (正确性问题)

**预估 CVSS 评分**: 5.5 (Medium)

## 修复建议

### 1. 正确计算字节偏移（优先级：高）

```cpp
extern "C" DLLEXPORT const char *RegexpExtractRetNull(...)
{
    std::string s(str, strLen);
    std::wstring ws = StringUtil::ToWideString(s);
    
    std::wregex re(StringUtil::ToWideString(r));
    std::wsmatch match;
    
    if (std::regex_search(ws, match, re) && match.size() > group) {
        int wideStartIdx = match.position(group);
        
        // 关键修复: 计算宽字符索引对应的字节偏移
        int byteStartIdx = 0;
        for (int i = 0; i < wideStartIdx && byteStartIdx < strLen; i++) {
            // 跳过 UTF-8 多字节字符
            byteStartIdx += GetUtf8CharLength(str + byteStartIdx);
        }
        
        std::wstring matchedWstr = match[group].str();
        std::wstring_convert<std::codecvt_utf8<wchar_t>> convert;
        std::string matchedNstr = convert.to_bytes(matchedWstr);
        *outLen = matchedNstr.size();
        
        auto ret = ArenaAllocatorMalloc(contextPtr, *outLen + 1);
        // 添加边界检查
        if (byteStartIdx + *outLen <= strLen) {
            memcpy_s(ret, *outLen + 1, str + byteStartIdx, *outLen + 1);
        } else {
            // 处理越界情况
            *outIsNull = true;
            return nullptr;
        }
        return ret;
    }
    ...
}
```

### 2. 使用字节字符串正则（优先级：中）

```cpp
// 使用 std::regex 和字节字符串，避免宽字符串转换问题
std::regex re(r);
std::smatch match;
if (std::regex_search(s, match, re) && match.size() > group) {
    int startIdx = match.position(group);  // 正确的字节索引
    ...
}
```

### 3. 添加边界验证（优先级：中）

```cpp
// 在 memcpy 前添加边界检查
if (startIdx < 0 || startIdx >= strLen || startIdx + *outLen > strLen) {
    *outIsNull = true;
    return nullptr;
}
memcpy_s(ret, *outLen + 1, str + startIdx, *outLen + 1);
```

## 参考信息

- CWE-125: Out-of-bounds Read
- UTF-8 Encoding Considerations
- std::regex vs std::wregex in C++