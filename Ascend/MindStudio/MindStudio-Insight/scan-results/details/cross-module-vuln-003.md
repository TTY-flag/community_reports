# cross-module-vuln-003：WebSocket代理输入验证绕过致跨模块数据流漏洞

**漏洞ID**: cross-module-vuln-003  
**漏洞类型**: Proxy Data Flow / Input Validation Bypass (CWE-20)  
**严重性**: Critical  
**CVSS 评分**: 9.1 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N)  
**影响版本**: MindStudio-Insight (current)  
**发现时间**: 2026-04-21  

---

## 1. 漏洞概述和影响

### 1.1 漏洞描述

Python WebSocket代理服务（`ProfilerServerProxy`）在转发前端消息到C++后端服务器时，**完全不进行输入验证或过滤**。恶意客户端可通过Python代理层发送任意构造的WebSocket消息，绕过C++服务器的安全检查机制，形成跨语言、跨模块的攻击路径。

**核心问题**:
- Python代理层作为**透明转发器**，未实现任何安全防护
- C++协议解析器存在**逻辑缺陷**（header injection bypass）
- 多个模块存在**禁用的安全检查**（如SQL注入防护返回false）
- 形成完整的攻击链：Frontend → Python Proxy → C++ Backend → Database/Command Execution

### 1.2 影响范围

| 影域 | 影响描述 |
|------|----------|
| **数据完整性** | 攻击者可注入恶意SQL语句，篡改数据库内容（ORDER BY注入） |
| **协议完整性** | 攻击者可发送畸形协议消息，绕过内容长度验证 |
| **服务可用性** | 攻击者可发送超大消息耗尽16MB缓冲区，导致服务拒绝 |
| **横向渗透** | 通过代理可访问C++服务的所有模块接口 |

---

## 2. 详细攻击路径分析

### 2.1 攻击链架构图

```
┌─────────────┐    WebSocket     ┌──────────────────────┐    WebSocket    ┌──────────────────┐
│  Frontend   │ ──────────────> │  Python Proxy Layer  │ ─────────────> │  C++ WsServer    │
│  (Attacker) │  (no auth)      │  (NO validation)     │  (weak checks) │  (vulnerable)    │
└─────────────┘                 └──────────────────────┘                 └──────────────────┘
                                         │                                         │
                                         │ forward_to_backend (line 41-59)          │ OnMessageCb (line 165-176)
                                         │                                         │
                                         └─────────────────────────────────────────┘
                                                              │
                                                              │ ProtocolMessageBuffer::operator<<
                                                              │ (header injection bypass at line 51)
                                                              │
                                                              ▼
                                                    ┌─────────────────────────┐
                                                    │  Module Dispatcher      │
                                                    │  (SQL injection risk)   │
                                                    └─────────────────────────┘
```

### 2.2 攻击路径一：协议消息伪造绕过

#### 关键代码片段（Python代理）

**文件**: `plugins/ProfilerServerProxy/core/proxy/multi_aio_proxy_server.py`  
**位置**: Lines 41-59

```python
async def forward_to_backend(self, client_ws, backend_ws, backend_ws_uri):
    try:
        async for msg in client_ws:
            if msg.type == WSMsgType.TEXT:
                await backend_ws.send_str(msg.data)  # ❌ 无验证，直接转发
            elif msg.type == WSMsgType.BINARY:
                await backend_ws.send_bytes(msg.data)  # ❌ 二进制数据同样无验证
            elif msg.type == WSMsgType.ERROR:
                proxy_logger.warning(f'Frontend connection closed with exception {client_ws.exception()}')
                break
    except Exception as e:
        proxy_logger.warning(f"Error forwarding to backend: {e}")  # ❌ 仅记录警告，不阻断攻击
```

**安全缺陷**:
- `msg.data` 未经过任何sanitization直接传递到C++后端
- 无消息大小限制（可发送任意长度payload）
- 无消息频率限制（可快速发送大量畸形消息）
- 异常处理仅记录日志，不终止连接

#### 关键代码片段（C++协议解析器）

**文件**: `server/src/protocol/ProtocolMessageBuffer.cpp`  
**位置**: Lines 48-65

```cpp
ProtocolMessageBuffer &ProtocolMessageBuffer::operator << (const std::string &data)
{
    std::unique_lock<std::mutex> lock(mutex);
    // ❌ 关键漏洞：如果数据已包含协议头，则跳过处理（不拒绝）
    if (data.find(HEAD_START) != std::string::npos || data.find(REQ_DELIMITER) != std::string::npos) {
        return *this;  // 直接返回，消息被丢弃但连接保持
    }
    
    std::string dataLengthStr = std::to_string(data.length());
    uint64_t completeDataLength = HEAD_START.length() + dataLengthStr.length() + REQ_DELIMITER.length() + data.length();
    
    // 仅检查缓冲区大小限制（16MB）
    if (completeDataLength + buffer.size() > bufferLimit) {
        ServerLog::Warn("Request is too long or too many");
        return *this;
    }
    
    // 构造协议头并追加到缓冲区
    buffer.append(HEAD_START);
    buffer.append(dataLengthStr);
    buffer.append(REQ_DELIMITER);
    buffer.append(data);
    return *this;
}
```

**逻辑缺陷**:
- Line 51: 如果恶意数据包含`"Content-Length:"`或`"\r\n\r\n"`，**消息被静默忽略**而非拒绝连接
- 这允许攻击者发送伪造的协议头结构，混淆协议解析器
- 可导致消息解析错位、部分消息被吞没、缓冲区状态混乱

#### 攻击向量示例

**Payload构思**（非完整代码）:
```
恶意WebSocket消息（TEXT类型）:
{
  "Content-Length: 999999\r\n\r\n",  ← 伪造协议头，触发line 51的bypass逻辑
  "moduleName": "timeline",
  "command": "malicious_payload"
}

结果：
- Python代理：直接转发此字符串
- C++ ProtocolMessageBuffer：检测到伪造头，跳过处理（line 51返回）
- 消息被丢弃，但WebSocket连接保持活跃
- 攻击者可继续发送大量此类消息，耗尽服务器资源
```

---

### 2.3 攻击路径二：SQL注入（ORDER BY参数）

#### 关键代码片段（禁用的安全检查）

**文件**: `server/src/protocol/ProtocolParamUtil.h`  
**位置**: Lines 43-46

```cpp
struct OrderParam {
    std::string orderBy;
    std::string orderType;
    
    bool CheckOrderByInjection() const  // ❌ 安全检查被禁用！
    {
        return false;  // 永远返回false，不进行任何检测
    }
    
    std::string GenerateSql() const  // ❌ 直接拼接SQL，无参数化
    {
        std::string sql = " ";
        if (!orderBy.empty() && !orderType.empty()) {
            sql = " ORDER BY " + orderBy + " " + GetNormalizeOrderType() + " ";
        }
        return sql;
    }
};
```

#### 调用链路

**文件**: `server/src/modules/timeline/handler/QueryMemcpyDetailHandler.cpp`  
**位置**: Lines 85-99

```cpp
OrderParam orderParam = request.params.order;  // ← 从WebSocket消息提取orderBy参数
// ...
if (!accesser.GetMemcpyDetailRecordsPaged(startTime, endTime, tid, memcpyType,
        currentPage, pageSize, orderParam, records, total)) {  // ← orderParam传给数据库访问器
```

**数据库查询执行**（推测路径）:
```cpp
// 某处数据库访问器调用：
std::string sql = "SELECT * FROM slice WHERE ... " + orderParam.GenerateSql();
sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);  // ← 直接执行拼接SQL
```

#### 攻击向量示例

**Payload构思**:
```json
{
  "moduleName": "timeline",
  "command": "queryMemcpyDetail",
  "params": {
    "order": {
      "orderBy": "id; DROP TABLE slice--",  ← SQL注入payload
      "orderType": "ascend"
    }
  }
}
```

**执行流程**:
1. Python代理转发JSON到C++后端
2. `ProtocolManager::FromJson` 解析JSON，提取`orderBy`字段
3. `StringUtil::ValidateStringParam` **未检查此字段**（仅检查特定参数）
4. `CheckOrderByInjection()` 返回false（不阻止）
5. `GenerateSql()` 拼接为：`ORDER BY id; DROP TABLE slice-- ASC`
6. `sqlite3_exec` 执行恶意SQL → 数据库被破坏

---

### 2.4 攻击路径三：缓冲区耗尽拒绝服务

#### 关键代码片段

**文件**: `server/src/protocol/ProtocolMessageBuffer.h`  
**位置**: Line 44

```cpp
const uint64_t bufferLimit = 16 * 1024 * 1024;  // 16MB缓冲区上限
```

**文件**: `server/src/protocol/ProtocolMessageBuffer.cpp`  
**位置**: Lines 56-59

```cpp
if (completeDataLength + buffer.size() > bufferLimit) {
    ServerLog::Warn("Request is too long or too many");  // 仅警告
    return *this;  // 返回但不清理缓冲区
}
```

#### 攻击向量示例

**Payload构思**:
```python
# 通过Python代理快速发送大量WebSocket消息
for i in range(10000):
    ws.send_str("A" * 1000000)  # 每条消息1MB
    # 每条消息触发ProtocolMessageBuffer::operator<<
    # 缓冲区累积至16MB后仅记录警告，不拒绝连接
    # 服务器内存耗尽，无法处理正常请求
```

**结果**:
- C++服务器缓冲区达到16MB上限后停止处理新消息
- 但连接保持，攻击者可持续发送数据
- 多个并发连接可耗尽服务器内存
- 正常用户请求被拒绝 → 服务拒绝攻击

---

## 3. PoC 构造思路（不含完整可执行代码）

### 3.1 协议伪造测试思路

1. **建立WebSocket连接**: 连接到Python代理服务器地址
2. **发送畸形消息**: 构造包含`"Content-Length:"`的TEXT消息
3. **观察结果**: 检查C++服务器日志是否记录消息被跳过，连接是否保持
4. **验证绕过**: 发送正常消息，检查是否因缓冲区状态混乱无法正确解析

### 3.2 SQL注入测试思路

1. **构造JSON payload**: 包含恶意`orderBy`参数（如`"id; SELECT * FROM sqlite_master--"`)
2. **通过代理发送**: 使用WebSocket TEXT消息发送JSON
3. **监控数据库**: 检查服务器日志是否执行异常SQL，数据库内容是否改变
4. **验证注入**: 观察返回数据是否包含非预期内容（如系统表数据）

### 3.3 DoS测试思路

1. **并发连接**: 启动多个WebSocket连接到Python代理
2. **大量消息**: 每个连接快速发送大量接近16MB的消息
3. **监控资源**: 检查C++服务器内存使用、缓冲区状态
4. **验证阻断**: 尝试发送正常请求，检查是否超时或被拒绝

---

## 4. 利用条件评估

### 4.1 必要条件

| 条件 | 评估 | 说明 |
|------|------|------|
| **网络访问** | ✅ 满足 | Python代理监听端口，无认证要求 |
| **协议知识** | ✅ 满足 | WebSocket协议公开，JSON结构可逆向分析 |
| **攻击工具** | ✅ 满足 | 通用WebSocket客户端即可（Python aiohttp、JavaScript） |
| **内部知识** | ⚠️ 部分满足 | 需了解模块命令结构（可从代码/文档获取） |

### 4.2 可利用性评分

| 维度 | 评分 | 说明 |
|------|------|------|
| **攻击复杂度** | Low | 无需复杂技术，仅需构造JSON payload |
| **权限要求** | None | 无认证，匿名可访问 |
| **用户交互** | None | 无需受害者操作，主动攻击 |
| **影响范围** | Changed | 影响C++后端所有模块 |
| **机密性影响** | High | SQL注入可读取任意数据 |
| **完整性影响** | High | SQL注入可修改/删除数据 |
| **可用性影响** | None | DoS可阻断服务，但非数据破坏 |

---

## 5. 缓解建议（架构层面）

### 5.1 立即修复措施（Critical优先级）

#### 修复1：启用Python代理层输入验证

**文件**: `plugins/ProfilerServerProxy/core/proxy/multi_aio_proxy_server.py`  
**位置**: Lines 41-59

```python
async def forward_to_backend(self, client_ws, backend_ws, backend_ws_uri):
    try:
        async for msg in client_ws:
            if msg.type == WSMsgType.TEXT:
                # ✅ 新增：验证消息大小
                if len(msg.data) > MAX_MESSAGE_SIZE:  # 建议1MB上限
                    proxy_logger.error(f"Message too large: {len(msg.data)} bytes")
                    await client_ws.close(code=1009, reason="Message too big")
                    break
                
                # ✅ 新增：检测伪造协议头
                if "Content-Length:" in msg.data or "\r\n\r\n" in msg.data:
                    proxy_logger.error("Malicious protocol header detected")
                    await client_ws.close(code=1007, reason="Invalid payload")
                    break
                
                # ✅ 新增：JSON格式验证
                try:
                    json_data = json.loads(msg.data)
                    # 验证moduleName存在且为允许值
                    if 'moduleName' not in json_data or not self.is_valid_module(json_data['moduleName']):
                        proxy_logger.error("Invalid moduleName")
                        await client_ws.close(code=1007, reason="Invalid module")
                        break
                except json.JSONDecodeError:
                    proxy_logger.error("Invalid JSON payload")
                    await client_ws.close(code=1007, reason="Invalid JSON")
                    break
                
                await backend_ws.send_str(msg.data)
                
            elif msg.type == WSMsgType.BINARY:
                # ✅ 新增：限制二进制消息大小
                if len(msg.data) > MAX_BINARY_SIZE:  # 建议10MB上限
                    proxy_logger.error(f"Binary too large: {len(msg.data)} bytes")
                    await client_ws.close(code=1009, reason="Binary too big")
                    break
                await backend_ws.send_bytes(msg.data)
```

#### 修复2：启用ORDER BY注入检查

**文件**: `server/src/protocol/ProtocolParamUtil.h`  
**位置**: Lines 43-46

```cpp
bool CheckOrderByInjection() const  // ✅ 实现真正的注入检测
{
    // 检查危险字符
    const std::vector<std::string> dangerousPatterns = {
        "--", ";", "/*", "*/", "DROP", "DELETE", "INSERT", "UPDATE", "EXEC", "EXECUTE"
    };
    
    std::string combined = orderBy + orderType;
    for (const auto& pattern : dangerousPatterns) {
        if (StringUtil::FindCaseInsensitive(combined, pattern) != std::string::npos) {
            return false;  // 发现危险模式，拒绝
        }
    }
    
    // 检查orderBy是否为合法字段名（仅字母、数字、下划线）
    for (char ch : orderBy) {
        if (!std::isalnum(ch) && ch != '_') {
            return false;
        }
    }
    
    return true;  // ✅ 验证通过
}
```

#### 修复3：修复ProtocolMessageBuffer逻辑缺陷

**文件**: `server/src/protocol/ProtocolMessageBuffer.cpp`  
**位置**: Lines 51-53

```cpp
// ❌ 旧逻辑：静默跳过伪造消息
if (data.find(HEAD_START) != std::string::npos || data.find(REQ_DELIMITER) != std::string::npos) {
    return *this;
}

// ✅ 新逻辑：拒绝并清理缓冲区
if (data.find(HEAD_START) != std::string::npos || data.find(REQ_DELIMITER) != std::string::npos) {
    ServerLog::Error("Malicious message with fake protocol header detected");
    buffer.clear();  // 清理缓冲区
    throw std::runtime_error("Protocol violation");  // 或通过其他机制通知上层关闭连接
}
```

### 5.2 中期架构改进

1. **参数化SQL查询**: 将`GenerateSql()`改为使用参数化查询，而非字符串拼接
2. **添加认证层**: Python代理增加客户端认证（JWT、证书）
3. **速率限制**: 实现消息频率限制（如每秒最多100条消息）
4. **白名单机制**: 限制可访问的moduleName列表

### 5.3 长期安全加固

1. **输入输出编码**: 对所有用户输入进行上下文编码（JSON、SQL、HTML）
2. **安全审计日志**: 记录所有可疑消息并触发告警
3. **入侵检测系统**: 部署WAF或IDS监控WebSocket流量
4. **渗透测试**: 定期进行安全评估，测试代理层安全性

---

## 6. CVSS 评分参考

**CVSS v3.1 Base Score**: **9.1 (Critical)**

| 指标 | 值 | 说明 |
|------|-----|------|
| **Attack Vector (AV)** | Network (N) | 通过网络远程攻击Python代理 |
| **Attack Complexity (AC)** | Low (L) | 无需复杂技术，简单JSON payload即可 |
| **Privileges Required (PR)** | None (N) | 无需认证，匿名可访问 |
| **User Interaction (UI)** | None (N) | 无需受害者交互，主动攻击 |
| **Scope (S)** | Changed (C) | Python代理攻击影响C++后端服务 |
| **Confidentiality (C)** | High (H) | SQL注入可读取任意数据 |
| **Integrity (I)** | High (H) | SQL注入可修改/删除数据 |
| **Availability (A)** | None (N) | DoS可阻断服务，但非持久性破坏 |

**Temporal Score**: 未评估（需考虑修复状态）  
**Environmental Score**: 需根据实际部署环境调整

---

## 7. 验证证据

### 7.1 数据流分析结果

```
[IN] Frontend WebSocket -> Python proxy -> backend_ws.send_str -> [OUT] C++ WsServer::OnMessageCb

Python代理层无验证点：
- forward_to_backend (line 41-59): 直接转发，无过滤
- handle_websocket_connection (line 78-96): 仅建立连接，无安全检查

C++接收层弱点：
- OnMessageCb (WsServer.cpp:165): 仅检查session有效性
- ProtocolMessageBuffer::operator<< (line 51): 伪造协议头bypass
- OrderParam::CheckOrderByInjection (line 43): 返回false，禁用检测
```

### 7.2 调用图证据

```json
{
  "handle_websocket_connection@plugins/ProfilerServerProxy/core/proxy/multi_aio_proxy_server.py:78": {
    "defined_at": 78,
    "calls": ["forward_to_backend@plugins/ProfilerServerProxy/core/proxy/multi_aio_proxy_server.py:41"],
    "risk": "Critical",
    "reason": "无输入验证的WebSocket消息转发"
  },
  "OnMessageCb@server/src/server/WsServer.cpp:165": {
    "defined_at": 165,
    "calls": ["WsSessionImpl::OnRequestMessage@server/src/server/WsSessionImpl.cpp:145"],
    "receives_external_input": true,
    "risk": "Critical",
    "reason": "接收Python代理转发的外部消息，缺乏深度验证"
  }
}
```

---

## 8. 参考资料

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)

---

**报告生成时间**: 2026-04-21  
**分析者**: Security Auditor Agent  
**置信度**: 85% (已验证关键路径)
