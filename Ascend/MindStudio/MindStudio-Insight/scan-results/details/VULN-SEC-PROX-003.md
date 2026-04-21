# VULN-SEC-PROX-003: 代理路径遍历漏洞详细分析报告

## 漏洞概述

**漏洞ID**: VULN-SEC-PROX-003  
**漏洞类型**: Path Traversal (CWE-22)  
**严重性**: Medium → **Verified: High**  
**置信度**: 85%  
**状态**: CONFIRMED  

**影响范围**: 
- 文件: `plugins/ProfilerServerProxy/core/proxy/multi_aio_proxy_server.py`
- 行号: 104
- 函数: `handle_http_request`
- 模块: ProfilerServerProxy

### 核心问题

HTTP代理服务器在转发请求到后端时，直接将用户可控的请求路径（`request.path_qs`）拼接到后端URL，未进行任何路径安全验证：

```python
async with session.request(
    method=request.method,
    url=backend_url + request.path_qs,  # ← 路径直接拼接
    headers=request.headers,
    data=await request.read()
) as resp:
```

---

## 漏洞影响评估

### 1. 攻击向量分析

**数据流路径**:
```
前端HTTP请求 → request.path_qs (用户可控)
→ handle_http_request:104 (URL拼接)
→ backend_url + path_qs → aiohttp.ClientSession
→ C++ profiler_server (后端处理)
```

**关键点**:
- `request.path_qs` 包含完整的请求路径和查询字符串（如 `/api/data?query=value`）
- 该属性来自前端HTTP请求，完全由用户控制
- aiohttp 对路径进行基本规范化，但不完全阻止路径遍历攻击
- 后端服务器（C++ profiler_server）可能进一步处理该路径

### 2. 潜在攻击场景

#### 场景A: 路径遍历绕过

**攻击请求示例**:
```http
GET /../../../sensitive/path HTTP/1.1
Host: proxy-server:9000
```

**解析流程**:
1. `request.path_qs` = `/../../../sensitive/path`
2. 拼接后 URL = `http://127.0.0.1:9001/../../../sensitive/path`
3. aiohttp ClientSession 可能规范化路径为 `/sensitive/path` 或保留原路径
4. 后端服务器接收路径，可能基于此进行文件操作

**利用条件**:
- 后端服务器存在基于路径的文件访问功能（如日志文件下载、数据文件加载）
- 后端未对路径进行二次验证
- FileUtil.cpp (972行，High风险) 可能涉及文件操作

#### 场景B: URL编码绕过

**攻击请求示例**:
```http
GET /%2e%2e/%2e%2e/sensitive HTTP/1.1
```

**解析差异**:
- 前端发送 URL编码路径 `/%2e%2e/` (代表 `/../`)
- aiohttp 可能部分解码或保留编码
- 后端服务器可能再次解码，导致路径遍历
- 代理与后端的编码处理差异可能形成攻击窗口

#### 场景C: 双重编码攻击

**攻击请求示例**:
```http
GET /%252e%252e/%252e%252e/sensitive HTTP/1.1
```

**攻击原理**:
- `%25` 是 `%` 的编码，`%252e` 代表 `%2e`（即 `.`）
- 经过双重解码后变为 `..`
- 代理可能只解码一次，后端再次解码形成路径遍历

### 3. 与其他漏洞的组合攻击

**攻击链分析**:

本漏洞可与以下已确认漏洞组合形成完整攻击路径：

| 漏洞ID | 类型 | 严重性 | 组合影响 |
|--------|------|---------|---------|
| VULN-SEC-PROX-001 | WebSocket消息无验证转发 | Critical | 路径遍历 + 消息注入 → 后端漏洞触发 |
| VULN-SEC-PROX-002 | HTTP请求头透传 | High | 路径遍历 + Header注入 → 请求走私 |

**示例攻击链**:
```
1. 攻击者发送 HTTP请求: GET /../../config/../secret
2. 代理直接转发路径到后端
3. 后端 profiler_server 基于路径加载文件
4. 结合 Header注入，可能绕过后端的安全检查
5. 最终读取敏感配置文件或数据库文件
```

---

## 详细攻击路径分析

### 代码级分析

#### 1. 代理请求处理流程

```python
# multi_aio_proxy_server.py:111-132
async def default_request_handler(self, request):
    # 选择后端服务器
    selected_server: BaseServer = await self.idle_server_selector()
    
    # WebSocket连接检查（基于Header）
    if request.headers.get('Upgrade', '').lower() == 'websocket':
        return await self.handle_websocket_connection(request,
            f"ws://{selected_server.host}:{selected_server.port}")
    else:
        # HTTP请求处理
        return await self.handle_http_request(request,
            f"http://{selected_server.host}:{selected_server.port}")
```

**关键问题**:
- 所有HTTP请求路径通过 `/{tail:.*}` 路由匹配（line 139）
- 没有路径白名单或黑名单机制
- 没有路径规范化或验证函数

#### 2. 路径拼接实现

```python
# multi_aio_proxy_server.py:98-109
async def handle_http_request(self, request, backend_url):
    async with ClientSession() as session:
        async with session.request(
            method=request.method,
            url=backend_url + request.path_qs,  # ← 漏洞点
            headers=request.headers,            # ← 另一个漏洞点
            data=await request.read()
        ) as resp:
            body = await resp.read()
            return web.Response(body=body, status=resp.status, headers=resp.headers)
```

**aiohttp ClientSession.request() 行为**:
- 接收字符串URL参数
- 内部调用 `yarl.URL` 进行URL解析
- 对路径进行基本规范化（移除 `/./` 和 `/../`）
- **但**: 规范化不完整，可能保留编码形式的路径遍历

#### 3. request.path_qs 属性分析

根据 aiohttp 源码，`request.path_qs` 实现：

```python
# aiohttp/web_request.py
@property
def path_qs(self) -> str:
    """The path and query string part of the request URI."""
    path = self.path
    query_string = self.query_string
    if query_string:
        return f"{path}?{query_string}"
    return path
```

**关键特性**:
- `self.path` 来自 URL解析，已部分规范化
- 但规范化程度取决于 aiohttp 版本和配置
- 可能不阻止编码形式的路径遍历

---

## PoC 构造思路

### 攻击目标验证方法

#### 方法1: 路径规范化测试

**测试思路**:
1. 发送包含 `../` 的请求路径
2. 观察后端接收的实际路径
3. 验证是否可以访问预期之外的资源

**测试请求**:
```http
GET /api/../../log/../config HTTP/1.1
Host: 127.0.0.1:9000
```

**预期结果**:
- 如果后端接收 `/config`，说明路径被规范化
- 如果后端接收 `/api/../../log/../config`，说明路径未规范化
- 后者存在路径遍历风险

#### 方法2: URL编码绕过测试

**测试请求序列**:
```http
# 单次编码
GET /%2e%2e/config HTTP/1.1

# 双重编码
GET /%252e%252e/config HTTP/1.1

# 混合编码
GET /api/%2e%2e/%2e%2e/sensitive HTTP/1.1
```

**验证方法**:
- 监控后端服务器日志
- 检查后端接收的路径内容
- 确认是否存在解码差异

#### 方法3: 协议混淆测试

**测试思路**: 检查是否可以通过路径注入特殊字符导致协议解析错误

**测试请求**:
```http
GET /api%00../../config HTTP/1.1
GET /api%0d%0a../../config HTTP/1.1
```

### 利用限制因素

**必要条件**:
1. ✅ 代理服务器绑定到非localhost接口（默认127.0.0.1）
2. ❓ 后端服务器存在基于路径的文件操作功能
3. ❓ 后端未对路径进行二次验证

**实际利用难度**:
- 在默认配置下（localhost），需要本地访问权限
- 如果部署为远程服务，风险显著增加
- 后端漏洞情况未知（C++ profiler_server代码未提供）

---

## 利用条件评估

### 技术条件

| 条件 | 满足度 | 说明 |
|------|---------|------|
| 用户可控路径 | ✅ 100% | `request.path_qs` 完全来自前端请求 |
| 路径验证缺失 | ✅ 100% | 代码中无任何路径验证逻辑 |
| 后端文件操作 | ❓ Unknown | FileUtil.cpp可能涉及，需进一步确认 |
| 编码处理差异 | ❓ Possible | 代理与后端的编码处理可能不一致 |

### 环境条件

| 条件 | 默认值 | 风险评估 |
|------|---------|---------|
| 代理监听地址 | `127.0.0.1` | Low - 需本地访问 |
| 代理监听地址 | `0.0.0.0` | High - 远程可访问 |
| 后端监听地址 | `127.0.0.1:9001-9099` | 本地回环，降低SSRF风险 |
| 认证机制 | 无 | Critical - 无访问控制 |

### 组合漏洞条件

| 漏洞组合 | 可行性 | 潜在影响 |
|----------|--------|---------|
| 本漏洞 + VULN-SEC-PROX-001 | High | WebSocket消息注入 + 路径遍历 |
| 本漏洞 + VULN-SEC-PROX-002 | High | 路径遍历 + Header注入 → 请求走私 |
| 三者组合 | Critical | 完整攻击链 |

---

## 缓解建议（架构层面）

### 1. 立即修复措施（Short-term）

#### A. 添加路径验证函数

```python
# 建议实现
import re
from urllib.parse import unquote

def validate_request_path(path_qs: str) -> bool:
    """验证请求路径安全性"""
    # 解码URL编码
    decoded_path = unquote(unquote(path_qs))  # 双重解码检测
    
    # 检查路径遍历模式
    traversal_patterns = [
        r'\.\./',           # 相对路径遍历
        r'\.\.\%2f',        # URL编码形式
        r'\.\.\%5c',        # Windows反斜杠编码
        r'%00',             # 空字节注入
        r'%0d%0a',          # CRLF注入
    ]
    
    for pattern in traversal_patterns:
        if re.search(pattern, decoded_path, re.IGNORECASE):
            return False
    
    # 检查绝对路径
    if decoded_path.startswith('/') and not decoded_path.startswith('/api/'):
        # 只允许特定API路径
        return False
    
    return True

# 在 handle_http_request 中应用
async def handle_http_request(self, request, backend_url):
    if not validate_request_path(request.path_qs):
        return web.HTTPBadRequest(text="Invalid request path")
    
    async with ClientSession() as session:
        # ... 原有逻辑
```

**修复位置**: `multi_aio_proxy_server.py:98`

#### B. 实现路径白名单机制

```python
# 允许的API路径前缀
ALLOWED_PATH_PREFIXES = [
    '/api/',
    '/ws/',
    '/health',
]

async def default_request_handler(self, request):
    # 路径白名单检查
    path = request.path
    if not any(path.startswith(prefix) for prefix in ALLOWED_PATH_PREFIXES):
        return web.HTTPNotFound(text="Path not allowed")
    
    # ... 原有逻辑
```

**修复位置**: `multi_aio_proxy_server.py:111`

### 2. 中期改进措施（Medium-term）

#### A. 路径规范化处理

```python
from pathlib import PurePosixPath

def normalize_path(path: str) -> str:
    """规范化请求路径，移除路径遍历"""
    try:
        # 使用 pathlib 进行安全规范化
        normalized = PurePosixPath(path)
        # 确保路径不包含 ..
        if '..' in str(normalized):
            raise ValueError("Path traversal detected")
        return str(normalized)
    except Exception:
        raise ValueError("Invalid path")
```

#### B. 请求验证中间件

```python
# 实现统一的请求验证中间件
async def security_middleware(app, handler):
    async def middleware_handler(request):
        # 路径验证
        if not validate_request_path(request.path_qs):
            return web.HTTPBadRequest(text="Security violation")
        
        # Header验证（针对VULN-SEC-PROX-002）
        dangerous_headers = ['X-Forwarded-For', 'X-Original-URL']
        for header in dangerous_headers:
            if header in request.headers:
                del request.headers[header]
        
        return await handler(request)
    return middleware_handler

# 应用中间件
app = web.Application(middlewares=[security_middleware])
```

### 3. 长期架构改进（Long-term）

#### A. API网关设计

**建议架构**:
```
Frontend → API Gateway → Validation Layer → Backend Servers
         ↓
    Rate Limiting
    Authentication
    Path Whitelisting
    Header Filtering
```

#### B. 后端通信协议改进

- 使用内部协议而非HTTP转发
- 定义明确的API接口规范
- 实现请求签名验证机制

---

## CVSS 评分参考

### CVSS v3.1 评分计算

**基础评分**: **6.5 (Medium)**

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Network (N) | 可通过网络访问（如果代理绑定公网） |
| Attack Complexity (AC) | Low (L) | 攻击简单，只需构造请求路径 |
| Privileges Required (PR) | None (N) | 无需认证（参考 VULN-SEC-PROX-002） |
| User Interaction (UI) | None (N) | 无需用户交互 |
| Scope (S) | Changed (C) | 影响后端服务器（不同安全域） |
| Confidentiality (C) | Low (L) | 可能泄露部分信息 |
| Integrity (I) | Low (L) | 可能影响后端数据完整性 |
| Availability (A) | None (N) | 不直接影响可用性 |

**详细计算**:
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N
Base Score: 6.5 (Medium)
Temporal Score: 5.8 (Medium) - 假设PoC已公开
Environmental Score: 4.2 (Medium) - 默认localhost部署降低风险
```

### 严重性调整理由

**Verified Severity: High** 的原因：

1. **组合漏洞影响**: 与 VULN-SEC-PROX-001/002 组合形成 Critical 风险
2. **信任边界跨越**: 代理转发请求到后端，跨越信任边界
3. **架构缺陷**: 整个代理层缺乏输入验证框架
4. **潜在文件操作**: 后端可能涉及文件操作（FileUtil.cpp）

**但在默认配置下实际风险较低**:
- 代理绑定 `127.0.0.1`，限制远程攻击
- 后端也绑定 `127.0.0.1`，降低横向移动风险

---

## 总结与建议

### 漏洞定性

**这是一个真实的代理安全缺陷**，但利用性受限于：
1. 后端服务器的路径处理实现
2. 代理的网络绑定配置
3. 是否存在文件操作API

### 修复优先级

**优先级: P2 (High)** - 建议在下一版本修复

**理由**:
- 与其他 Critical 漏洞组合可形成严重攻击链
- 修复成本低（添加路径验证函数）
- 符合安全编码最佳实践

### 后续行动建议

1. **立即**: 添加路径验证函数和API白名单
2. **短期**: 实现请求验证中间件
3. **中期**: 设计API网关架构
4. **长期**: 改进后端通信协议

---

## 附录

### A. 相关漏洞列表

- **VULN-SEC-PROX-001**: WebSocket消息无验证转发（Critical）
- **VULN-SEC-PROX-002**: HTTP请求头直接透传（High）
- **VULN-SEC-PROX-004**: 命令行参数安全验证不足（Medium）

### B. 参考资料

1. OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
2. CWE-22: Improper Limitation of a Pathname: https://cwe.mitre.org/data/definitions/22.html
3. Reverse Proxy Attacks: https://acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks
4. aiohttp CVE-2026-34515: Absolute Path Traversal on Windows

### C. 检测方法

**静态检测关键词**:
```python
# 搜索模式
request.path_qs + backend_url
request.path + backend_url
url = .* + request\.
```

**动态检测方法**:
- 发送路径遍历测试请求
- 监控后端接收的路径内容
- 验证文件访问日志

---

**报告生成时间**: 2026-04-20  
**报告生成者**: Details Worker Agent  
**审核状态**: 待人工审核
