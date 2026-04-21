# 漏洞深度分析报告

## VULN-SEC-SERVER-002: CORS 配置过于宽松 - POST 端点 (CWE-942)

**严重性**: Medium  
**置信度**: 85%  
**CVSS 3.1 评分**: 6.5 (Medium)

---

## 1. 执行摘要

HTTP POST API 端点同样返回 `Access-Control-Allow-Origin: *` 通配符响应头。与 GET 端点相比，POST 端点的风险更高：
- **允许跨域数据提交**: 恶意网站可以向 API POST 数据
- **可能触发数据处理**: POST 请求可能触发文件解析、分析任务等操作
- **数据注入风险**: 恶意数据可能被注入到分析流程

---

## 2. 与 VULN-SEC-SERVER-001 的关系

### 2.1 相同根因

两个漏洞共享相同的根本原因：
- 同一文件 `WsServer.cpp`
- 同样的 CORS 通配符配置
- 同样的缺失认证机制

### 2.2 额外风险

POST 端点相比 GET 端点的额外风险：

| 方面 | GET 端点 | POST 端点 |
|------|----------|-----------|
| 数据流向 | 读取数据 | 提交数据 |
| 操作类型 | 查询 | 可能触发处理 |
| 影响范围 | 信息泄露 | 数据注入 + 信息泄露 |

---

## 3. 根因分析

### 3.1 漏洞代码位置

**文件**: `server/src/server/WsServer.cpp`  
**行号**: 216-218  
**函数**: `WsServer::AddPostHandler`

```cpp
void WsServer::AddPostHandler(const std::string& key, std::shared_ptr<Core::ApiHandler> handler)
{
    wsApp->post(key.data(), [handler](uWS::HttpResponse<false> *res, auto *req) {
        res->onAborted([]() { ... });
        res->onData([res, handler, bodyBuffer = std::string()](std::string_view data, bool isEnd) mutable {
            bodyBuffer.append(data);
            if (isEnd) {
                // add coc - CORS 配置 (漏洞点)
                res->writeHeader("Access-Control-Allow-Origin", "*");
                res->writeHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                res->writeHeader("Access-Control-Allow-Headers", "Content-Type");
                
                std::string result;
                handler->run(bodyBuffer, result);  // bodyBuffer 可包含恶意数据
                res->end(result);
            }
        });
    });
}
```

### 3.2 POST 请求处理流程

```
[恶意网站] evil.com
    ↓ POST 请求
[MindStudio API] localhost:8080/api/some-endpoint
    ↓ CORS: Access-Control-Allow-Origin: * (允许)
[Handler] handler->run(bodyBuffer, result)
    ↓ bodyBuffer 包含恶意构造的数据
[数据处理] 可能触发文件解析、分析任务等
    ↓
[影响] 恶意数据进入分析流程
```

---

## 4. 攻击场景分析

### 4.1 数据注入攻击

恶意网站可 POST 构造的数据：

```javascript
// evil.com 的恶意代码
fetch("http://localhost:8080/api/parse", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    filePath: "/malicious/path",
    params: { "injection": "payload" }
  })
});
```

潜在影响：
- 触发文件解析操作
- 注入恶意参数到分析流程
- 可能结合其他漏洞（如路径遍历）扩大攻击

### 4.2 CSRF-like 攻击

```javascript
// 用户正在使用 MindStudio
// evil.com 在后台发起请求
fetch("http://localhost:8080/api/delete-project", {
  method: "POST",
  body: JSON.stringify({ projectId: "important-data" })
});
// 由于 CORS 允许，请求成功执行
```

---

## 5. CVSS 3.1 评分

### 5.1 评分向量

```
CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N
```

### 5.2 评分详解

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Network (N) | 网络跨域请求 |
| Attack Complexity (AC) | High (H) | 需用户访问恶意网站 |
| Privileges Required (PR) | None (N) | 无认证 |
| User Interaction (UI) | Required (R) | 用户需访问恶意页面 |
| Scope (S) | Unchanged (U) | 同一资源 |
| Confidentiality (C) | Low (L) | 数据泄露风险 |
| Integrity (I) | Low (L) | POST 可修改数据 |
| Availability (A) | None (N) | 不影响可用性 |

**基础评分**: 6.5 (Medium)

**相比 VULN-SEC-SERVER-001**: Integrity 影响从 None 升为 Low

---

## 6. 缓解建议

### 6.1 与 VULN-SEC-SERVER-001 相同的修复方案

参见 VULN-SEC-SERVER-001.md 的修复方案：

- 限制 CORS 来源为 localhost
- 动态 CORS 验证
- 添加认证机制

### 6.2 POST 端点额外建议

**请求内容验证**:
```cpp
// 在 handler->run 之前验证请求内容
if (!ValidateRequestBody(bodyBuffer)) {
    res->writeStatus("400 Bad Request");
    res->end("Invalid request body");
    return;
}
```

**关键操作保护**:
- 对删除、修改等操作添加 CSRF Token
- 对文件路径参数使用白名单验证

---

## 7. 漏洞关联

| 漏洞 ID | 类型 | 关系 |
|----------|------|------|
| VULN-SEC-SERVER-001 | CORS GET | 同根因，GET 端点 |
| server-vuln-005 | CORS | 不同 Scanner 发现 |
| VULN-SEC-PROX-001 | 输入验证 | 组合利用可能 |

---

## 8. 参考资料

- [CWE-942: Permissive Cross-domain Policy](https://cwe.mitre.org/data/definitions/942.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

**报告生成时间**: 2026-04-20  
**分析者**: Security Scanner  
**状态**: CONFIRMED  
**关联报告**: VULN-SEC-SERVER-001.md