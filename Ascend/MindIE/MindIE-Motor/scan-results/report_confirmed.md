# 漏洞扫描报告 — 已确认漏洞

**项目**: MindIE-Motor
**扫描时间**: 2026-04-17T00:30:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

### 项目背景

MindIE-Motor 是一个分布式 AI 推理引擎管理系统，由华为技术有限公司开发。该系统部署在 Linux 服务器集群上，包含三个核心服务组件：

- **Controller**: 集群控制器，负责节点调度、故障管理、进程监控
- **Coordinator**: 协调器，负责请求管理、调度分发、集群监控
- **Node Manager**: 节点管理器，负责 daemon 进程管理、心跳监控、硬件故障处理

项目采用 C/C++ 和 Python 混合开发模式：
- C++ 实现核心服务（Controller、Coordinator、HTTP Server、IPC）
- Python 实现 Node Manager 及 OM Adapter 监控组件

### 扫描范围

本次扫描覆盖了以下攻击面：

| 攻击面类型 | 组件 | 风险等级 |
|-----------|------|---------|
| HTTP Server | HttpServer.cpp (C++) | Critical |
| FastAPI Routes | server_api.py (Python) | Critical |
| Shared Memory IPC | SharedMemoryUtils.cpp + circular_memory.py | High |
| gRPC Cluster | GrpcClusterClient.cpp | High |
| Process Execution | daemon_manager (Python) | High |
| Configuration Files | JsonFileLoader.cpp + config.py | Medium |

扫描共分析了 **334 个源文件**，总计 **56,790 行代码**，覆盖 8 个功能模块。

### 主要发现

本次扫描发现 **20 个候选漏洞**，经验证后：

| 状态 | 数量 | 占比 |
|------|------|------|
| **CONFIRMED** | **1** | 5.0% |
| LIKELY | 2 | 10.0% |
| POSSIBLE | 4 | 20.0% |
| FALSE_POSITIVE | 13 | 65.0% |
| **总计** | **20** | 100% |

**关键发现**:
- 发现 1 个已确认的 **High 级别 XSS 漏洞**，位于 HTTP 请求处理函数
- 发现 2 个高可信度的漏洞待进一步验证（Buffer Overflow、Path Traversal）
- 13 个误报已被正确过滤（包括多个不存在风险的配置文件解析点）

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 13 | 65.0% |
| POSSIBLE | 4 | 20.0% |
| LIKELY | 2 | 10.0% |
| CONFIRMED | 1 | 5.0% |
| **总计** | **20** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 1 | 100.0% |
| **有效漏洞总计** | **1** | - |
| 误报 (FALSE_POSITIVE) | 13 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-CPP-001]** XSS (High) - `mindie_motor/src/common/http_server/HttpServer.cpp:27` @ `ResourceNotFound` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `HandleRequest@mindie_motor/src/common/http_server/HttpServer.cpp` | network | untrusted_network | HTTP请求处理函数，接收来自外部客户端的HTTP请求，包括body和header数据，可能来自不可信的网络来源 | 处理HTTP GET/POST/DELETE请求，解析请求body和target路径 |
| `Listener::Run@mindie_motor/src/common/http_server/HttpServer.cpp` | network | untrusted_network | HTTP服务器监听端口，接受外部网络连接 | 在指定端口监听TCP连接，接受来自任何IP的HTTP请求 |
| `Read@mindie_motor/src/common/ipc/shared_memory/SharedMemoryUtils.cpp` | ipc | semi_trusted | 从共享内存读取数据，数据可能来自其他本地进程（包括可能被攻击者控制的进程） | 从共享内存环形缓冲区读取消息 |
| `CreateHeartbeatMessage@mindie_motor/src/common/ipc/heartbeat/HeartbeatProducer.cpp` | ipc | semi_trusted | 心跳消息写入共享内存，可能被其他进程读取 | 创建并写入心跳消息到共享内存 |
| `FileToJsonObj@mindie_motor/src/controller/json_file_loader/JsonFileLoader.cpp` | file | trusted_admin | 从文件加载JSON配置，文件由管理员控制但需验证权限 | 读取JSON配置文件并解析为JSON对象 |
| `running_status@mindie_motor/python/mindie_motor/node_manager/routes/server_api.py` | web_route | untrusted_network | FastAPI HTTP GET路由，接收外部HTTP请求查询节点状态 | 处理/v1/node-manager/running-status GET请求 |
| `fault_handling_command@mindie_motor/python/mindie_motor/node_manager/routes/server_api.py` | web_route | semi_trusted | FastAPI HTTP POST路由，接收故障处理命令，可能影响进程执行 | 处理/v1/node-manager/fault-handling-command POST请求，解析并执行命令 |
| `hardware_fault_info@mindie_motor/python/mindie_motor/node_manager/routes/server_api.py` | web_route | semi_trusted | FastAPI HTTP POST路由，接收硬件故障信息 | 处理/v1/node-manager/hardware-fault-info POST请求 |
| `start_daemon_process@mindie_motor/python/mindie_motor/node_manager/daemon_manager/base_daemon_manager.py` | cmdline | trusted_admin | 启动子进程执行mindie_llm_server，命令参数来自配置文件 | 使用subprocess.Popen启动daemon进程，包含命令验证 |
| `build_daemon_command@mindie_motor/python/mindie_motor/node_manager/daemon_manager/llm_daemon_starter.py` | cmdline | trusted_admin | 构建daemon进程命令，包含taskset CPU绑定和配置文件路径 | 构建mindie_llm_server启动命令，支持taskset和config-file参数 |
| `parse_daemon_arguments@mindie_motor/python/mindie_motor/node_manager/daemon_manager/llm_daemon_starter.py` | cmdline | trusted_admin | 解析命令行参数决定启动模式 | 解析sys.argv参数，支持single和distributed模式 |
| `_update_info@mindie_motor/python/mindie_motor/node_manager/core/config.py` | env | semi_trusted | 从环境变量MIES_INSTALL_PATH和POD_IP读取配置路径和IP地址 | 从环境变量和配置文件加载系统配置 |
| `_query_engine_server_status@mindie_motor/python/mindie_motor/node_manager/core/heartbeat_mng.py` | network | semi_trusted | 向engine server发送HTTP请求查询状态，接收响应数据 | 使用Client发送HTTP请求查询engine server状态 |
| `read_data@mindie_motor/python/mindie_motor/om_adapter/share_memory_utils/circular_memory.py` | ipc | semi_trusted | 从共享内存环形缓冲区读取数据 | 读取Python共享内存环形缓冲区数据 |
| `write_data@mindie_motor/python/mindie_motor/om_adapter/share_memory_utils/circular_memory.py` | ipc | semi_trusted | 写入数据到共享内存环形缓冲区 | 写入数据到Python共享内存环形缓冲区 |
| `send@mindie_motor/python/mindie_motor/om_adapter/monitors/kafka_client/kafka_produce.py` | network | semi_trusted | 向Kafka集群发送消息，Kafka配置包含SSL认证 | 使用confluent_kafka发送消息到Kafka主题 |
| `SendRequest@mindie_motor/src/http_client_ctl/http_client/HttpClient.cpp` | network | semi_trusted | 发送HTTP请求到外部服务，接收响应数据 | 使用Boost.Beast发送HTTP请求，支持TLS和非TLS模式 |
| `CreateGrpcChannel@mindie_motor/src/common/cluster_grpc/GrpcClusterClient.cpp` | network | semi_trusted | 创建gRPC通道用于集群通信 | 创建gRPC客户端通道，支持TLS认证 |

**其他攻击面**:
- HTTP Server: 监听端口接受外部HTTP请求（mindie_motor/src/common/http_server/HttpServer.cpp）
- FastAPI Routes: Python HTTP API endpoints（mindie_motor/python/mindie_motor/node_manager/routes/server_api.py）
- Shared Memory IPC: C++和Python共享内存通信（mindie_motor/src/common/ipc/ 和 mindie_motor/python/mindie_motor/om_adapter/share_memory_utils/）
- gRPC Cluster Communication: 集群节点间gRPC通信（mindie_motor/src/common/cluster_grpc/）
- Kafka Client: 向Kafka集群发送消息（mindie_motor/python/mindie_motor/om_adapter/monitors/kafka_client/）
- Process Execution: subprocess.Popen启动mindie_llm_server进程（mindie_motor/python/mindie_motor/node_manager/daemon_manager/）
- JSON Configuration Parsing: 解析配置文件（mindie_motor/src/controller/json_file_loader/ 和 mindie_motor/python/mindie_motor/node_manager/core/config.py）
- Environment Variables: 读取MIES_INSTALL_PATH、POD_IP、RANK_TABLE_FILE等环境变量
- Heartbeat IPC: 本地进程心跳监控机制
- HTTP Client: 向外部服务发送HTTP请求

---

## 3. High 漏洞 (1)

### [VULN-DF-CPP-001] XSS - ResourceNotFound

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-79 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `mindie_motor/src/common/http_server/HttpServer.cpp:27-40` @ `ResourceNotFound`
**模块**: common

**描述**: HTTP request target path is directly embedded into error response body without HTML escaping. The 'target' parameter from HTTP request (req.target()) is user-controlled network input that flows to response.body() without sanitization, allowing potential XSS attacks.

#### 漏洞代码分析

**漏洞代码** (`mindie_motor/src/common/http_server/HttpServer.cpp:27-40`)

```cpp
static Http::message_generator ResourceNotFound(const Http::request<Http::string_body> &req, const std::string &ip,
    Beast::string_view target)
{
    LOG_M("[Handle] Handle request, IP %s, method %s, target %s, code %d.",
        ip.c_str(), std::string(req.method_string()).c_str(),
        std::string(req.target()).c_str(), static_cast<int>(Http::status::not_found));
    Http::response<Http::string_body> response{Http::status::not_found, req.version()};
    response.body() = "Cannot find the resource " + std::string(target);  // 漏洞点：直接拼接
    std::string contentType = "text/html";  // 危险：设置为 HTML Content-Type
    response.set(Http::field::content_type, contentType);
    response.keep_alive(req.keep_alive());
    response.prepare_payload();
    return response;
}
```

**调用链分析** (`HttpServer.cpp:115-139`)

```cpp
Http::message_generator HttpServer::HandleRequest(Http::request<Http::string_body> &&req, const std::string &ip)
{
    // ...方法验证...
    
    // 路径遍历检查（不完整的检查）
    if (req.target().empty() || req.target()[0] != '/' || req.target().find("..") != Beast::string_view::npos) {
        return BadRequest(req, ip, "Illegal request-target");
    }
    
    // ...URL 处理...
    for (auto iter : std::as_const(handler)) {
        if (!req.target().starts_with(iter.first)) {
            continue;
        }
        auto ret = iter.second(req);
        if (ret.first == ErrorCode::NOT_FOUND) {
            return ResourceNotFound(req, ip, req.target());  // 漏洞触发点
        }
    }
    return ResourceNotFound(req, ip, req.target());  // 默认处理
}
```

#### 漏洞成因深度分析

**问题根源**:

1. **Content-Type 设置错误**: 代码将 Content-Type 设置为 `text/html`（第35行），这使得浏览器会解析响应内容为 HTML，从而执行嵌入的脚本。

2. **缺少 HTML 转义**: 第34行直接将用户输入的 `target` 字符串拼接到响应体中，没有任何 HTML 实体编码或转义处理。

3. **输入来源**: `req.target()` 是 HTTP 请求的 URL 路径部分，完全由外部客户端控制，属于 **untrusted_network** 级别的输入。

**数据流路径**:

```
HTTP Request (外部网络) 
    ↓ req.target()
HandleRequest() [Line 115]
    ↓ 路径检查 (只检查 ".."，不检查 HTML 特殊字符)
ResourceNotFound() [Line 135/139]
    ↓ std::string(target)
response.body() = "Cannot find the resource " + target [Line 34]
    ↓
HTTP Response (Content-Type: text/html) → 浏览器执行
```

#### 攻击场景示例

**攻击向量**:

攻击者可以构造以下恶意 URL 来触发 XSS：

```
GET /<script>alert('XSS')</script> HTTP/1.1
Host: target-server:port
```

**响应内容**:

```html
HTTP/1.1 404 Not Found
Content-Type: text/html

Cannot find the resource <script>alert('XSS')</script>
```

浏览器将执行嵌入的 JavaScript 代码。

**实际影响**:

- 在管理界面场景下，攻击者可窃取管理员 session
- 可植入恶意代码进行钓鱼攻击
- 可能绕过 CSRF 防护机制
- 如果服务器部署在集群内部，攻击者可能通过 XSS 横向移动

#### 验证说明

Confirmed XSS vulnerability. HTTP request target (req.target()) is directly embedded into HTML response body without escaping at line 34: `response.body() = 'Cannot find the resource ' + std::string(target)`. Content-Type set to `text/html`. Attackers can inject arbitrary HTML/JavaScript via URL path.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| common | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **1** | **0** | **0** | **1** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-79 | 1 | 100.0% |

---

## 6. 修复建议

### 6.1 [VULN-DF-CPP-001] XSS 漏洞修复方案

**优先级**: 立即修复 (P0)

**方案一：修改 Content-Type**

将 Content-Type 从 `text/html` 改为 `text/plain`，这是最简单的修复方式：

```cpp
std::string contentType = "text/plain";  // 修改为纯文本类型
response.set(Http::field::content_type, contentType);
```

**方案二：HTML 实体编码**

添加 HTML 转义函数，对用户输入进行编码：

```cpp
// 建议添加转义函数（可参考 SecurityUtils.cpp 中已有的 SanitizeStringForJson）
static std::string HtmlEscape(const std::string& input) {
    std::string result;
    for (char c : input) {
        switch (c) {
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '&': result += "&amp;"; break;
            case '"': result += "&quot;"; break;
            case '\'': result += "&apos;"; break;
            default: result += c;
        }
    }
    return result;
}

// 在 ResourceNotFound 中使用
response.body() = "Cannot find the resource " + HtmlEscape(std::string(target));
```

**方案三：统一使用 JSON 格式响应**

将错误响应改为 JSON 格式，与项目其他接口保持一致：

```cpp
Http::response<Http::string_body> response{Http::status::not_found, req.version()};
nlohmann::json errorResp;
errorResp["error"] = "resource_not_found";
errorResp["target"] = std::string(target);  // JSON 自动处理字符串转义
errorResp["message"] = "Cannot find the requested resource";
response.body() = errorResp.dump();
response.set(Http::field::content_type, "application/json");
```

### 6.2 其他待验证漏洞的预防性修复建议

虽然这些漏洞尚未确认，但建议进行预防性修复以提高安全性：

#### Buffer Overflow (VULN-DF-PY-001) 预防建议

在 `circular_memory.py` 的 `write_data()` 方法中添加边界检查：

```python
def write_data(self, chunk: str):
    byte_chunk = chunk.encode()
    if len(byte_chunk) > self.shm_size:
        self.logger.warning(f"Data size {len(byte_chunk)} exceeds buffer capacity {self.shm_size}")
        return  # 或抛出异常
    write_idx = self.cb.write_idx
    for i, byte in enumerate(byte_chunk):
        self.cb.data[(write_idx + i) % self.shm_size] = byte
    self.cb.write_idx = (write_idx + len(byte_chunk)) % self.shm_size
```

#### Path Traversal (VULN-SEC-PATH-001) 预防建议

增强路径检查，处理 URL 编码变体：

```cpp
// 在 HandleRequest 中增强路径检查
std::string decodedTarget = UrlDecode(req.target());  // 需要实现 URL 解码
if (decodedTarget.empty() || decodedTarget[0] != '/' || 
    decodedTarget.find("..") != std::string::npos) {
    return BadRequest(req, ip, "Illegal request-target");
}
```

或使用更严格的白名单验证：

```cpp
// 只允许字母、数字、下划线、斜杠和点
static bool IsPathSafe(const std::string& path) {
    for (char c : path) {
        if (!std::isalnum(c) && c != '/' && c != '_' && c != '.' && c != '-') {
            return false;
        }
    }
    return path.find("..") == std::string::npos;
}
```

---

## 7. 总结

本次漏洞扫描针对 MindIE-Motor 分布式 AI 推理引擎管理系统进行了全面的安全评估。扫描发现了一个已确认的 XSS 漏洞，该漏洞可能导致：

1. **管理界面安全风险**: 如果 HTTP Server 提供管理接口，攻击者可通过 XSS 窃取管理员凭据
2. **集群内部横向移动**: 攻击者可能利用 XSS 在集群环境中进一步渗透
3. **数据泄露风险**: 可能泄露系统状态、配置信息等敏感数据

**建议措施**:

- **立即修复**: VULN-DF-CPP-001 XSS 漏洞
- **进一步验证**: VULN-DF-PY-001 Buffer Overflow 和 VULN-SEC-PATH-001 Path Traversal
- **安全加固**: 完善输入验证机制，统一错误响应格式

扫描结果表明项目的整体安全状况良好，65% 的候选漏洞被正确识别为误报，验证机制有效运行。建议持续进行安全扫描和代码审查，确保新增代码符合安全规范。