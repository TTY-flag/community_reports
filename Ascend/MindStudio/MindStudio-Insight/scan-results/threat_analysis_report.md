# MindStudio-Insight 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析未受 threat.md 约束，AI 自主识别了所有潜在攻击面和威胁场景。

**生成时间：** 2026-04-20T20:15:00Z  
**项目路径：** /home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Insight  
**项目类型：** 网络服务（WebSocket 守护进程）  
**文件统计：** 366 个 C++ 文件，70 个 Python 文件（非测试目录）

---

## 1. 项目架构概览

### 1.1 项目定位

MindStudio-Insight 是华为昇腾 AI 平台的性能可视化调优工具，通过 WebSocket 服务器接收前端客户端（浏览器、JupyterLab 插件）的请求，解析用户上传的性能分析数据文件，提供系统调优、算子调优、通信分析、内存分析等功能。

**部署模型：** Linux/Windows/macOS 服务器上的 WebSocket 守护进程，监听 `host:wsPort` 端口。典型部署为本地工具（localhost），但配置文件允许监听任意网络接口。

**主要组件：**
- **C++ WebSocket 服务器**（server/src/server/）：处理 WebSocket 连接和消息
- **协议解析层**（server/src/protocol/）：解析 JSON 请求并分发到模块
- **业务模块层**（server/src/modules/）：timeline、communication、memory、advisor、operator 等
- **文件解析层**：解析 JSON、CSV、SQLite 数据文件
- **Python 辅助脚本**：集群分析、CPU 绑定、内存快照处理
- **Python WebSocket 代理**（plugins/ProfilerServerProxy/）：前端到 C++ 服务器的代理

### 1.2 信任边界模型

| 边界 | 可信一侧 | 不可信一侧 | 风险等级 |
|------|----------|-----------|---------|
| WebSocket Network Interface | Application logic (C++ server) | Remote WebSocket clients | Critical |
| HTTP API Interface | ApiHandler implementations | HTTP POST requests from frontend | High |
| File System Interface | Database (SQLite) | User-provided profiler data files | High |
| Process Execution Interface | Python scripts (cluster_analysis.py) | Arguments from user requests | High |
| Python WebSocket Proxy Interface | ProfilerServerProxy backend | Frontend WebSocket clients | Critical |

---

## 2. 模块风险评估

### 2.1 Critical 风险模块

| 模块 | 文件 | 主要功能 | STRIDE 威胁 |
|------|------|----------|------------|
| **server** | WsServer.cpp, WsSessionImpl.cpp | WebSocket 服务器监听、消息接收 | S, T, D, E |
| **protocol** | ProtocolMessageBuffer.cpp | JSON 消息解析、请求分发 | T, D |
| **ProfilerServerProxy** | multi_aio_proxy_server.py | Python WebSocket 代理 | S, T, D |

### 2.2 High 风险模块

| 模块 | 文件 | 主要功能 | STRIDE 威胁 |
|------|------|----------|------------|
| **communication** | ClusterFileParser.cpp | 文件解析、集群分析 | T, I, D |
| **utils** | FileUtil.cpp, PythonUtil.cpp | 文件操作、进程执行 | T, I, E |
| **timeline** | EventParser.cpp | 事件数据解析 | T, D |
| **memory** | MemoryParse.cpp | 内存数据解析 | T, D |
| **global** | ProjectExplorerManager.cpp | 项目管理、文件路径处理 | T, I |

### 2.3 Medium 风险模块

| 模块 | 文件 | 主要功能 | STRIDE 威胁 |
|------|------|----------|------------|
| **advisor** | AdvisorModule.cpp | 性能建议生成 | I, D |
| **operator** | KernelParse.cpp | 算子数据解析 | T, D |
| **source** | SourceInstructionParser.cpp | 指令数据解析 | T |
| **triton** | TritonParser.cpp | Triton 模块数据解析 | T |

---

## 3. 攻击面分析

### 3.1 主要攻击入口

#### 3.1.1 WebSocket Network Interface（Critical）

**入口点：** `WsServer::OnMessageCb`（WsServer.cpp:165）

**攻击者可达性：** WebSocket 服务器监听配置的 `host:wsPort` 端口。如果配置为 `0.0.0.0` 或非 localhost，则任意网络客户端可连接。典型部署为 localhost，但攻击者可通过本地用户权限或浏览器漏洞触达。

**数据可控性：** WebSocket 消息内容完全由客户端控制。消息包含 JSON 格式的请求，字段包括 `moduleName`、`command`、`params` 等。

**攻击向量：**
- 恶意 JSON 请求导致解析器崩溃或内存耗尽
- 恶意 `moduleName` 导致分发到不存在或错误的模块
- 恶意 `params` 字段导致后续模块处理异常

**现有防护：**
- 消息缓冲区长度限制（`bufferLimit`）
- JSON 解析异常捕获
- 模块名存在性检查

**绕过可能性：** 高。防护机制不完善，缺少速率限制、认证授权、输入白名单。

---

#### 3.1.2 HTTP POST API Interface（High）

**入口点：** `WsServer::AddPostHandler`（WsServer.cpp:205）

**攻击者可达性：** HTTP POST 处理器通过 uWS::App 的 `.post()` 方法注册，监听相同端口。

**数据可控性：** HTTP 请求 body 完全由客户端控制。`bodyBuffer.append(data)` 直接追加未过滤的数据。

**攻击向量：**
- 超大 HTTP body 导致内存耗尽
- 恶意 JSON body 导致 Handler 处理异常
- CORS 配置宽松（`Access-Control-Allow-Origin: *`）

**现有防护：**
- uWS 框架默认的请求大小限制
- Handler 内部的异常捕获

**绕过可能性：** 中。缺少请求速率限制、输入验证、认证授权。

---

#### 3.1.3 File Parsing Interface（High）

**入口点：** `ClusterFileParser::ParseCommunication`（ClusterFileParser.cpp:41）

**攻击者可达性：** 文件路径来自用户请求的 `params.filePathList`。用户可通过 WebSocket 请求指定要解析的文件。

**数据可控性：** 文件内容由用户提供。文件路径受 `CheckPathSecurity` 验证。

**攻击向量：**
- 路径遍历绕过 `CheckPathSecurity` 检查
- 恶意文件内容导致 rapidjson SAX 解析器崩溃或内存耗尽
- 超大文件导致内存耗尽（虽然有 20GB 限制）

**现有防护：**
- `CheckPathSecurity`：路径长度检查、非法字符过滤、软链接检测、owner 检查、权限检查
- `CheckFileSize`：文件大小限制（20GB）
- rapidjson SAX 解析器的错误处理

**绕过可能性：** 中低。防护较完善，但 TOCTOU（Time-of-Check-Time-of-Use）漏洞可能存在。

---

#### 3.1.4 Process Execution Interface（High）

**入口点：** `PythonUtil::ExecuteScript`（PythonUtil.cpp:44）

**攻击者可达性：** 当 `ClusterFileParser::AttAnalyze` 执行集群分析时，调用 Python 脚本。

**数据可控性：** 脚本参数 `selectedPath` 和 `mode` 来自用户请求。脚本路径硬编码为 `msprof_analyze/cluster_analyse/cluster_analysis.py`。

**攻击向量：**
- 参数注入（`selectedPath` 包含特殊字符或命令分隔符）
- 脚本路径被替换（如果安装目录权限不当）
- Python 解释器路径被劫持（Linux 使用 PATH 中的 `python3`）

**现有防护：**
- `StringUtil::ValidateCommandFilePathParam`：参数验证
- 脚本路径硬编码
- Linux 使用 `posix_spawnp` 而非 `system()`

**绕过可能性：** 中。参数验证可能不完善，PATH 劫持风险存在。

---

#### 3.1.5 Python WebSocket Proxy Interface（Critical）

**入口点：** `MultiplexAIOProxyServer::handle_websocket_connection`（multi_aio_proxy_server.py:78）

**攻击者可达性：** Python 实现的 WebSocket 代理服务器，监听独立端口。前端通过代理连接到 C++ WebSocket 服务器。

**数据可控性：** WebSocket 消息通过代理转发，内容完全由前端客户端控制。

**攻击向量：**
- 代理转发绕过 C++ 服务器的安全检查
- 代理服务器自身漏洞（Python aiohttp 框架）
- 后端连接劫持

**现有防护：**
- aiohttp 框架的默认 WebSocket 安全措施
- 异步错误处理

**绕过可能性：** 高。Python 代理增加攻击面，缺少认证授权。

---

### 3.2 辅助攻击入口

| 入口类型 | 文件 | 函数 | 信任等级 | 说明 |
|---------|------|------|---------|------|
| 命令行参数 | main.cpp | main | trusted_admin | 服务器启动参数，非运行时入口 |
| 预加载目录 | WsServer.cpp | PreLoadEventDir | trusted_admin | 服务器启动时预加载，非运行时入口 |
| SQLite 数据库 | TextClusterDatabase.cpp | Insert/Query | trusted_admin | 数据库文件由解析模块生成，非外部输入 |

---

## 4. STRIDE 威胁建模

### 4.1 Spoofing（身份伪造）

**威胁场景：**
- WebSocket 客户端伪造身份。服务器未实施认证机制，任意客户端可连接。
- Python WebSocket 代理伪造后端连接。攻击者可创建恶意后端服务器，诱骗代理转发消息。

**风险等级：** High

**影响：** 未授权访问敏感数据、恶意请求处理。

---

### 4.2 Tampering（数据篡改）

**威胁场景：**
- WebSocket 消息篡改。攻击者修改 JSON 请求字段（moduleName、command、params），影响请求分发和处理逻辑。
- 文件内容篡改。用户上传的性能分析数据文件包含恶意构造的数据，导致解析器异常或数据库污染。
- 数据库文件篡改。SQLite 数据库文件由用户提供的目录路径生成，可能被其他进程篡改。

**风险等级：** Critical

**影响：** 数据完整性破坏、逻辑绕过、注入攻击。

---

### 4.3 Repudiation（抵赖）

**威胁场景：**
- 无操作日志追溯。服务器虽有 ServerLog 日志，但缺少请求来源追溯（如客户端 IP、用户 ID）。
- 无请求签名验证。客户端请求未签名，无法证明请求来源。

**风险等级：** Medium

**影响：** 无法追溯恶意请求来源，安全事件调查困难。

---

### 4.4 Information Disclosure（信息泄露）

**威胁场景：**
- 性能数据泄露。用户上传的性能分析数据可能包含敏感信息（模型结构、算子名称、内存布局）。
- 日志信息泄露。ServerLog 日志可能包含敏感路径、参数内容。
- 错误消息泄露。JSON 解析失败时返回的错误消息可能暴露内部结构。

**风险等级：** High

**影响：** 敏感数据泄露、攻击者获取系统信息。

---

### 4.5 Denial of Service（拒绝服务）

**威胁场景：**
- WebSocket 消息泛洪。发送大量或超大消息导致缓冲区耗尽或处理线程阻塞。
- 文件解析资源耗尽。上传超大 JSON 文件（接近 20GB 限制）导致 SAX 解析器内存耗尽或 CPU 过载。
- HTTP POST 泛洪。发送大量 HTTP 请求导致服务器资源耗尽。

**风险等级：** Critical

**影响：** 服务不可用、处理线程崩溃。

---

### 4.6 Elevation of Privilege（权限提升）

**威胁场景：**
- Python 脚本执行权限提升。`ExecuteScript` 执行外部脚本，如果脚本或参数被劫持，可能执行恶意代码。
- 文件操作权限提升。如果 `CheckPathSecurity` 被绕过，可能读写敏感文件。
- SQLite 数据库权限提升。数据库文件存储在用户目录，可能被其他用户进程访问。

**风险等级：** High

**影响：** 执行任意代码、读写敏感文件、获取更高权限。

---

## 5. 安全加固建议（架构层面）

### 5.1 网络接口加固

1. **WebSocket 认证机制：** 实施基于 Token 或 Session 的认证机制，拒绝未认证客户端连接。
2. **速率限制：** 实施消息速率限制和连接速率限制，防止泛洪攻击。
3. **输入验证：** 对 JSON 请求字段实施白名单验证，拒绝未知 moduleName 或 command。
4. **CORS 配置：** 将 `Access-Control-Allow-Origin` 改为具体域名，避免宽松配置。
5. **网络隔离：** 默认监听 localhost，配置选项限制为非公网接口。

---

### 5.2 文件操作加固

1. **路径安全增强：** 在 `CheckPathSecurity` 后立即使用 `realpath()` 获取绝对路径，防止 TOCTOU 漏洞。
2. **文件内容验证：** 对上传文件实施格式验证和签名检查，拒绝恶意构造文件。
3. **文件大小限制降低：** 将 20GB 限制降低为更合理的值（如 2GB），并实施渐进式解析。
4. **数据库隔离：** 将数据库文件存储在受保护目录，限制其他进程访问。

---

### 5.3 进程执行加固

1. **参数严格验证：** 对 `ExecuteScript` 参数实施严格字符过滤，拒绝所有 shell 元字符。
2. **Python 解释器路径固定：** 使用绝对路径调用 Python 解释器，避免 PATH 劫持。
3. **脚本完整性检查：** 执行脚本前校验脚本文件完整性（签名或哈希）。
4. **执行环境隔离：** 使用 `posix_spawn_file_actions_addclose` 关闭不必要的文件描述符。

---

### 5.4 日志与追溯加固

1. **请求来源记录：** 在 ServerLog 中记录客户端 IP、WebSocket 连接 ID、请求时间戳。
2. **敏感数据脱敏：** 日志中脱敏文件路径、参数内容等敏感信息。
3. **请求签名：** 实施请求签名机制（HMAC），验证请求来源和完整性。

---

### 5.5 Python 代理加固

1. **认证机制：** Python WebSocket 代理实施与 C++ 服务器相同的认证机制。
2. **转发验证：** 代理转发前验证消息格式和来源。
3. **后端连接验证：** 代理验证后端服务器证书或 Token，防止连接劫持。

---

## 6. 高风险文件清单（按优先级）

| 优先级 | 文件 | 模块 | 风险等级 | 主要威胁 |
|--------|------|------|---------|---------|
| 1 | server/src/server/WsServer.cpp | server | Critical | WebSocket 消息接收、HTTP POST 处理 |
| 2 | server/src/server/WsSessionImpl.cpp | server | Critical | WebSocket Session 管理、消息处理线程 |
| 3 | server/src/protocol/ProtocolMessageBuffer.cpp | protocol | Critical | JSON 消息解析、缓冲区管理 |
| 4 | server/src/modules/communication/parser/ClusterFileParser.cpp | communication | High | 文件解析、Python 脚本执行 |
| 5 | server/msinsight/src/utils/FileUtil.cpp | utils | High | 文件路径处理、安全检查 |
| 6 | server/msinsight/src/utils/PythonUtil.cpp | utils | High | 外部 Python 脚本执行 |
| 7 | server/src/modules/ModuleManager.cpp | modules | High | 请求分发逻辑 |
| 8 | plugins/ProfilerServerProxy/core/proxy/multi_aio_proxy_server.py | ProfilerServerProxy | Critical | Python WebSocket 代理 |
| 9 | server/src/modules/timeline/core/parser/EventParser.cpp | timeline | High | 事件数据解析 |
| 10 | server/src/modules/memory/parser/MemoryParse.cpp | memory | High | 内存数据解析 |

---

## 7. 数据流关键路径

### 7.1 WebSocket 消息处理路径

```
WebSocket Client -> OnMessageCb (WsServer.cpp:165)
  -> OnRequestMessage (WsSessionImpl.cpp:145)
  -> operator<< (ProtocolMessageBuffer.cpp:48)
  -> Pop (ProtocolMessageBuffer.cpp:67)
  -> FromJson (ProtocolManager.cpp:55)
  -> OnDispatchModuleRequest (ModuleManager.cpp:62)
  -> BaseModule::OnRequest -> Handler::run
```

**关键验证点：**
- ProtocolMessageBuffer::Pop：JSON 解析异常捕获
- ProtocolManager::FromJson：moduleName 存在性检查
- ModuleManager::OnDispatchModuleRequest：Session 状态检查

---

### 7.2 文件解析路径

```
User Request (params.filePathList)
  -> ParseCommunication (ClusterFileParser.cpp:41)
  -> PathPreprocess (FileUtil.cpp)
  -> SaxParseJsonFile (ClusterFileParser.cpp:63)
  -> CheckPathSecurity (FileUtil.cpp:205)
  -> fopen -> rapidjson::Reader::Parse
  -> CommunicationRapidSaxHandler::Default
```

**关键验证点：**
- FileUtil::CheckPathSecurity：路径安全性检查（长度、字符、owner、权限）
- FileUtil::CheckFileSize：文件大小限制（20GB）
- rapidjson SAX 解析错误处理

---

### 7.3 Python 执行路径

```
User Request (params.selectedPath)
  -> AttAnalyze (ClusterFileParser.cpp:428)
  -> ValidateCommandFilePathParam (StringUtil.h)
  -> ExecuteScript (PythonUtil.cpp:44)
  -> ExecuteCommand (PythonUtil.cpp:77)
  -> posix_spawnp -> waitpid
```

**关键验证点：**
- StringUtil::ValidateCommandFilePathParam：参数字符验证
- 硬编码脚本路径
- posix_spawnp 使用而非 system()

---

## 8. 后续扫描建议

基于本次威胁分析，建议后续漏洞扫描重点关注：

1. **WebSocket 消息处理模块：** 搜索 JSON 解析漏洞、缓冲区溢出、整数溢出
2. **文件解析模块：** 搜索路径遍历、文件描述符泄漏、解析器崩溃
3. **Python 执行模块：** 搜索命令注入、参数验证漏洞
4. **数据库模块：** 搜索 SQL 注入（虽然使用参数化查询）、数据库文件权限漏洞
5. **内存操作模块：** 搜索缓冲区溢出、内存泄漏、整数溢出

---

**报告结束**