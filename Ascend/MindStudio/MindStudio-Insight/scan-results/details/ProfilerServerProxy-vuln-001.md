# 漏洞深度分析报告

## ProfilerServerProxy-vuln-001: WebSocket 代理输入验证缺失 (重复发现)

**严重性**: Critical  
**置信度**: 85%  
**CVSS 3.1 评分**: 8.8 (High)

---

## 1. 重要说明：这是重复发现

### 1.1 与主报告的关系

本漏洞 **ProfilerServerProxy-vuln-001** 与 **VULN-SEC-PROX-001** 完全相同：
- **相同代码位置**: `plugins/ProfilerServerProxy/core/proxy/multi_aio_proxy_server.py:41-55`
- **相同漏洞类型**: WebSocket 消息无验证转发
- **相同根因**: `forward_to_backend` 函数直接转发所有消息

### 1.2 为什么单独追踪

| Scanner | 发现编号 | 发现时间 |
|----------|----------|----------|
| Security Module Scanner | VULN-SEC-PROX-001 | 首次发现 |
| DataFlow Module Scanner | ProfilerServerProxy-vuln-001 | 后续发现 |

**原因**: 多个 Scanner 独立分析同一代码路径，产生重复报告。

---

## 2. 主报告摘要

请参阅 **VULN-SEC-PROX-001.md** 的完整分析（已存在）。以下是关键摘要：

### 2.1 漏洞描述

Python WebSocket 代理 (`ProfilerServerProxy`) 完全透传前端消息到后端 C++ 服务器：
- 无 JSON 格式验证
- 无消息大小限制
- 无 moduleName/command 白名单
- 无频率控制

### 2.2 代码片段

```python
async def forward_to_backend(self, client_ws, backend_ws, backend_ws_uri):
    async for msg in client_ws:
        if msg.type == WSMsgType.TEXT:
            await backend_ws.send_str(msg.data)  # 直接转发，无验证
        elif msg.type == WSMsgType.BINARY:
            await backend_ws.send_bytes(msg.data)  # 直接转发，无验证
```

### 2.3 攻击路径

```
[恶意前端] WebSocket 连接
    ↓ 发送任意 JSON 消息
[Python Proxy] forward_to_backend
    ↓ 无验证直接转发
[C++ Backend] WsServer::OnMessageCb
    ↓ 解析并处理恶意请求
[各模块 Handler] 可能触发各种漏洞
```

---

## 3. CVSS 评分

与 VULN-SEC-PROX-001 相同：

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N
基础评分: 8.8 (High)
```

---

## 4. 缓解建议

与 VULN-SEC-PROX-001 相同：

### 4.1 立即修复 (P0)

1. **添加消息验证层**:
```python
async def forward_to_backend(self, client_ws, backend_ws, backend_ws_uri):
    async for msg in client_ws:
        if msg.type == WSMsgType.TEXT:
            # 新增: 验证 JSON 格式
            try:
                data = json.loads(msg.data)
                # 新增: moduleName 白名单
                if data.get("moduleName") not in ALLOWED_MODULES:
                    continue  # 拒绝非法模块
                # 新增: 大小限制
                if len(msg.data) > MAX_MESSAGE_SIZE:
                    continue  # 拒绝超大消息
            except json.JSONDecodeError:
                continue  # 拒绝非 JSON
            await backend_ws.send_str(msg.data)
```

2. **频率限制**: 添加消息速率控制防止 DoS

---

## 5. 参考链接

- **主报告**: [VULN-SEC-PROX-001.md](./VULN-SEC-PROX-001.md)
- **关联报告**: [cross-module-vuln-003.md](./cross-module-vuln-003.md)

---

**报告生成时间**: 2026-04-20  
**状态**: CONFIRMED (Duplicate of VULN-SEC-PROX-001)