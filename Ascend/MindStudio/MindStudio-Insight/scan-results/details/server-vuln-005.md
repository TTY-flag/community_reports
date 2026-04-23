# server-vuln-005：CORS通配符配置（同VULN-SEC-SERVER-001重复发现）

## server-vuln-005: CORS 配置过于宽松 (重复发现)

**严重性**: Medium  
**置信度**: 85%  
**CVSS 3.1 评分**: 5.3 (Medium)

---

## 1. 重要说明：这是重复发现

### 1.1 与主报告的关系

本漏洞 **server-vuln-005** 与 **VULN-SEC-SERVER-001** 完全相同：
- **相同代码位置**: `server/src/server/WsServer.cpp:196-198`
- **相同漏洞类型**: CORS 通配符配置
- **相同根因**: `Access-Control-Allow-Origin: *`

### 1.2 为什么单独追踪

| Scanner | 发现编号 | 发现时间 |
|----------|----------|----------|
| Security Module Scanner | VULN-SEC-SERVER-001 | 首次发现 |
| DataFlow Module Scanner | server-vuln-005 | 后续发现 |

**原因**: 多个 Scanner 独立分析同一代码，产生重复报告。为保证完整性，两个发现都被保留。

---

## 2. 主报告摘要

请参阅 **VULN-SEC-SERVER-001.md** 的完整分析。以下是关键摘要：

### 2.1 漏洞描述

HTTP GET API 端点返回 CORS 通配符 `*`，允许任何网站跨域访问 API。

### 2.2 代码片段

```cpp
res->writeHeader("Access-Control-Allow-Origin", "*");
res->writeHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
res->writeHeader("Access-Control-Allow-Headers", "Content-Type");
```

### 2.3 风险评估

| 风险 | 严重程度 |
|------|----------|
| 数据泄露 | Medium |
| CSRF-like 攻击 | Medium |
| 供应链攻击风险 | Medium-High |

---

## 3. CVSS 评分

与 VULN-SEC-SERVER-001 相同：

```
CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N
基础评分: 5.3 (Medium)
```

---

## 4. 缓解建议

与 VULN-SEC-SERVER-001 相同：

1. **限制 CORS 来源**: 仅允许 localhost
2. **动态 CORS**: 根据请求来源动态设置
3. **添加认证**: WebSocket/HTTP API token 验证

---

## 5. 参考链接

- **主报告**: [VULN-SEC-SERVER-001.md](./VULN-SEC-SERVER-001.md)
- **关联报告**: [VULN-SEC-SERVER-002.md](./VULN-SEC-SERVER-002.md) (POST 端点)

---

**报告生成时间**: 2026-04-20  
**状态**: CONFIRMED (Duplicate of VULN-SEC-SERVER-001)