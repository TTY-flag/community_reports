# VULN-COMMON-006: EndWith字符串比较函数缺少边界检查致缓冲区越界访问

## 1. 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-COMMON-006 |
| **类型** | 缓冲区错误 (buffer_error) |
| **CWE** | CWE-170: Improper Null Termination / CWE-129: Improper Validation of Array Index |
| **严重性** | MEDIUM |
| **文件** | `ubsio-boostio/src/common/bio_str_util.h` |
| **行号** | 44-47 |
| **函数** | `EndWith` |
| **置信度** | 85% → **确认 (100%)** |

## 2. 漏洞代码分析

### 2.1 漏洞代码

```cpp
// File: ubsio-boostio/src/common/bio_str_util.h:44-47
inline bool StrUtil::EndWith(const std::string &src, const std::string &end)
{
    return src.compare(src.size() - end.size(), end.size(), end) == 0;
}
```

### 2.2 问题根因

当 `src.size() < end.size()` 时:
1. `src.size() - end.size()` 会发生**无符号整数下溢** (因为 `size_t` 是无符号类型)
2. 下溢后得到一个非常大的正整数 (接近 `SIZE_MAX`)
3. `std::string::compare(pos, count, str)` 在 `pos > src.size()` 时会抛出 `std::out_of_range` 异常

### 2.3 对比 StartWith 函数

```cpp
// 正常工作的 StartWith 函数
inline bool StrUtil::StartWith(const std::string &src, const std::string &start)
{
    return src.compare(0, start.size(), start) == 0;
}
```
- `StartWith` 使用固定位置 `0`，不会发生下溢
- 但 `EndWith` 使用 `src.size() - end.size()`，当 `end` 比 `src` 长时会产生问题

## 3. 触发条件与攻击场景

### 3.1 触发条件

```cpp
// 触发条件: end.length() > src.length()
StrUtil::EndWith("ab", "abc");      // src.size()=2, end.size()=3
StrUtil::EndWith("", "anything");   // src.size()=0, end.size()>0
StrUtil::EndWith("x", "xyz");       // src.size()=1, end.size()=3
```

### 3.2 攻击场景

**场景 1: 文件扩展名检查绕过**
```cpp
// 假设用于检查文件扩展名
std::string filename = getUserInput();  // 用户可控
if (StrUtil::EndWith(filename, ".txt")) {
    // 安全处理文本文件
} else if (StrUtil::EndWith(filename, ".exe")) {
    // 处理可执行文件
}
// 攻击者输入空字符串 "" 或比 ".txt" 短的字符串
// 导致异常崩溃 (DoS)
```

**场景 2: URL/路径处理**
```cpp
// 检查 URL 是否以特定后缀结尾
std::string url = request.getPath();
if (StrUtil::EndWith(url, ".php")) {
    // 处理 PHP 请求
}
// 攻击者发送空路径或极短路径触发异常
```

**场景 3: 配置文件解析**
```cpp
// 解析配置项
std::string line = readConfigLine();
if (StrUtil::EndWith(line, "=true")) {
    // 解析布尔配置
}
// 空行或格式错误的行触发异常
```

## 4. PoC 构造思路

### 4.1 简单 PoC

```cpp
#include <iostream>
#include <string>
#include "bio_str_util.h"

int main() {
    using namespace ock::bio;
    
    // 正常情况
    bool ret1 = StrUtil::EndWith("hello.txt", ".txt");  // 正常: true
    
    // 触发漏洞情况
    try {
        bool ret2 = StrUtil::EndWith("ab", "abc");  // 抛出 std::out_of_range
        std::cout << "ret2 = " << ret2 << std::endl;
    } catch (const std::out_of_range& e) {
        std::cout << "Exception caught: " << e.what() << std::endl;
        // 输出: basic_string::compare: __pos (which is 18446744073709551615) > this->size() (which is 2)
    }
    
    // 空字符串情况
    try {
        bool ret3 = StrUtil::EndWith("", ".txt");  // 同样抛出异常
    } catch (const std::out_of_range& e) {
        std::cout << "Empty string exception: " << e.what() << std::endl;
    }
    
    return 0;
}
```

### 4.2 编译运行验证

```bash
g++ -std=c++17 -I./ubsio-boostio/src poc.cpp -o poc && ./poc
```

### 4.3 预期输出

```
Exception caught: basic_string::compare: __pos (which is 18446744073709551615) > this->size() (which is 2)
Empty string exception: basic_string::compare: __pos (which is 18446744073709551615) > this->size() (which is 0)
```

**注意**: `18446744073709551615` = `SIZE_MAX` (64位系统)，这是无符号整数下溢的结果。

## 5. 可利用性评估

### 5.1 利用难度: **低**

- 漏洞触发条件简单明确
- 不需要特殊权限
- 只需提供特定输入即可触发

### 5.2 影响范围评估

| 维度 | 评估 | 说明 |
|------|------|------|
| **可利用性** | 中等 | `EndWith` 函数目前未在代码库中发现实际调用点 |
| **影响程度** | 中等 | 导致 DoS (拒绝服务)，不影响数据完整性或机密性 |
| **攻击向量** | 网络/本地 | 取决于输入来源 |
| **用户交互** | 需要 | 需要触发特定代码路径 |

### 5.3 实际风险评级: **中等**

虽然当前代码库中未发现 `EndWith` 的实际调用，但作为公共工具函数:
1. 未来可能被其他模块使用
2. 属于基础库代码，可靠性要求高
3. 应当修复以防止潜在风险

## 6. 修复建议

### 6.1 推荐修复代码

```cpp
inline bool StrUtil::EndWith(const std::string &src, const std::string &end)
{
    // 添加边界检查
    if (end.size() > src.size()) {
        return false;
    }
    return src.compare(src.size() - end.size(), end.size(), end) == 0;
}
```

### 6.2 替代修复方案 (使用 std::string::rfind)

```cpp
inline bool StrUtil::EndWith(const std::string &src, const std::string &end)
{
    if (end.empty()) {
        return true;  // 空后缀总是匹配
    }
    if (end.size() > src.size()) {
        return false;
    }
    return src.rfind(end) == src.size() - end.size();
}
```

### 6.3 更健壮的修复 (处理空字符串边界情况)

```cpp
inline bool StrUtil::EndWith(const std::string &src, const std::string &end)
{
    // 边界检查
    const size_t srcLen = src.size();
    const size_t endLen = end.size();
    
    // 如果 end 为空，任何字符串都以空字符串结尾
    if (endLen == 0) {
        return true;
    }
    
    // 如果 src 比 end 短，不可能匹配
    if (endLen > srcLen) {
        return false;
    }
    
    // 安全的比较
    return src.compare(srcLen - endLen, endLen, end) == 0;
}
```

### 6.4 同时建议修复 StartWith

虽然 `StartWith` 当前不会崩溃，但为了一致性和健壮性:

```cpp
inline bool StrUtil::StartWith(const std::string &src, const std::string &start)
{
    if (start.size() > src.size()) {
        return false;
    }
    return src.compare(0, start.size(), start) == 0;
}
```

## 7. 测试用例建议

```cpp
// 单元测试用例
TEST(StrUtilTest, EndWith_BasicCases) {
    EXPECT_TRUE(StrUtil::EndWith("hello.txt", ".txt"));
    EXPECT_TRUE(StrUtil::EndWith("test", "t"));
    EXPECT_TRUE(StrUtil::EndWith("test", "test"));
    EXPECT_FALSE(StrUtil::EndWith("hello.txt", ".json"));
    EXPECT_FALSE(StrUtil::EndWith("test", "xyz"));
}

TEST(StrUtilTest, EndWith_EdgeCases) {
    // 空 end - 应该返回 true (任何字符串都以空字符串结尾)
    EXPECT_TRUE(StrUtil::EndWith("anything", ""));
    EXPECT_TRUE(StrUtil::EndWith("", ""));
    
    // 空 src, 非空 end - 应该返回 false (不崩溃)
    EXPECT_FALSE(StrUtil::EndWith("", ".txt"));
    
    // end 比 src 长 - 应该返回 false (不崩溃)
    EXPECT_FALSE(StrUtil::EndWith("ab", "abc"));
    EXPECT_FALSE(StrUtil::EndWith("x", "xyz"));
}
```

## 8. 总结

| 项目 | 结论 |
|------|------|
| **是否真实漏洞** | ✅ **确认** - 缺少边界检查导致整数下溢和异常抛出 |
| **漏洞类型** | 整数下溢 → 越界访问 → 未处理异常 |
| **实际风险** | 中等 - 当前无实际调用，但作为基础库需要修复 |
| **修复难度** | 低 - 添加一行边界检查即可 |
| **修复优先级** | 中等 - 建议尽快修复 |

## 9. 参考资料

- [CWE-129: Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html)
- [CWE-170: Improper Null Termination](https://cwe.mitre.org/data/definitions/170.html)
- [C++ Reference: std::string::compare](https://en.cppreference.com/w/cpp/string/basic_string/compare)
- [C++ Reference: std::out_of_range](https://en.cppreference.com/w/cpp/error/out_of_range)

