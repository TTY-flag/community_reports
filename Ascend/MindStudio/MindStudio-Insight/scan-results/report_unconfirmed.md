# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-Insight
**扫描时间**: 2026-04-20T20:15:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 12 | 40.0% |
| CONFIRMED | 9 | 30.0% |
| POSSIBLE | 5 | 16.7% |
| LIKELY | 4 | 13.3% |
| **总计** | **30** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 2 | 22.2% |
| Medium | 4 | 44.4% |
| Low | 3 | 33.3% |
| **有效漏洞总计** | **9** | - |
| 误报 (FALSE_POSITIVE) | 12 | - |

### 1.3 Top 10 关键漏洞

1. **[server-vuln-001]** Path Traversal (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Insight/server/src/modules/global/handler/FilesGetHandler.cpp:35` @ `FilesGetHandler::HandleRequest` | 置信度: 65
2. **[cross-module-vuln-001]** Cross-Module Data Flow (High) - `server/src/server/WsServer.cpp:165` @ `OnMessageCb` | 置信度: 60
3. **[timeline-vuln-001]** JSON Parsing (Medium) - `server/src/modules/timeline/core/parser/EventParser.cpp:60` @ `EventParser::Parse` | 置信度: 65
4. **[VULN-SEC-PROX-004]** command_injection (Medium) - `plugins/ProfilerServerProxy/core/server/profiler_server.py:89` @ `_initialize` | 置信度: 55
5. **[server-vuln-006]** Insufficient Path Security (Medium) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Insight/server/src/modules/global/core/FileSelector.cpp:51` @ `FileSelector::GetFoldersAndFiles` | 置信度: 55
6. **[communication-vuln-002]** File Parsing (Medium) - `server/src/modules/communication/parser/ClusterFileParser.cpp:63` @ `ClusterFileParser::SaxParseJsonFile` | 置信度: 50
7. **[VULN-SEC-SERVER-004]** improper_input_validation (Low) - `server/src/server/WsServer.cpp:165` @ `OnMessageCb` | 置信度: 60
8. **[VULN-SEC-SERVER-003]** improper_input_validation (Low) - `server/src/server/WsSessionImpl.cpp:145` @ `OnRequestMessage` | 置信度: 45
9. **[server-vuln-002]** Input Validation Bypass (Low) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Insight/server/msinsight/src/utils/JsonUtil.h:256` @ `JsonUtil::GetString` | 置信度: 40

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `OnMessageCb@server/src/server/WsServer.cpp` | network | untrusted_network | WebSocket 服务器监听配置的 host:wsPort 端口，接收任意客户端的 WebSocket 消息。消息直接传递给 OnRequestMessage 进行解析，攻击者可通过 WebSocket 连接发送恶意 JSON 请求。 | 接收 WebSocket 客户端消息 |
| `AddPostHandler@server/src/server/WsServer.cpp` | network | untrusted_network | HTTP POST 处理器接收前端发送的 HTTP 请求，请求 body 来自网络客户端，未经过认证或授权检查。bodyBuffer 直接传递给 handler->run() 处理。 | 处理 HTTP POST API 请求 |
| `AddGetHandler@server/src/server/WsServer.cpp` | network | untrusted_network | HTTP GET 处理器接收前端发送的 HTTP 请求，query 参数来自 URL，攻击者可控制查询参数内容。 | 处理 HTTP GET API 请求 |
| `operator<<@server/src/protocol/ProtocolMessageBuffer.cpp` | network | untrusted_network | 接收来自 WebSocket 的原始消息数据，数据内容完全由客户端控制。消息被追加到 buffer 中等待解析，可能包含恶意构造的 JSON。 | 接收 WebSocket 消息数据流 |
| `Pop@server/src/protocol/ProtocolMessageBuffer.cpp` | network | untrusted_network | 从 buffer 中提取 JSON 字符串并调用 ProtocolManager::FromJson 解析为 Request 对象。JSON 内容来自 WebSocket 客户端，可能包含恶意构造的 moduleName、command、params 等字段。 | 解析 WebSocket JSON 请求 |
| `ParseCommunication@server/src/modules/communication/parser/ClusterFileParser.cpp` | file | untrusted_local | 解析用户指定的性能分析数据文件（filePathList[0]），文件路径来自用户请求的 params。虽然有 CheckPathSecurity 检查，但攻击者可尝试路径遍历或恶意文件内容注入。 | 解析用户上传的通信分析 JSON 文件 |
| `SaxParseJsonFile@server/src/modules/communication/parser/ClusterFileParser.cpp` | file | untrusted_local | 使用 fopen 打开用户指定的文件路径，然后使用 rapidjson SAX 解析器处理。文件内容由用户控制，可能包含超大 JSON 或恶意构造的数据导致解析器崩溃或内存耗尽。 | SAX 解析用户上传的 JSON 文件 |
| `AttAnalyze@server/src/modules/communication/parser/ClusterFileParser.cpp` | rpc | semi_trusted | 执行外部 Python 脚本 cluster_analysis.py，参数 selectedPath 来自用户请求。虽然有 ValidateCommandFilePathParam 检查，但参数传递到命令行可能存在注入风险。脚本路径硬编码为 msprof_analyze/cluster_analyse/cluster_analysis.py。 | 执行 Python 集群分析脚本 |
| `ExecuteScript@server/msinsight/src/utils/PythonUtil.cpp` | rpc | semi_trusted | 使用 posix_spawnp 执行 Python 命令，脚本路径和 arguments 由调用者传入。arguments 内容来自用户请求参数，如果未正确过滤可能导致命令注入。Linux 上使用 python3 命令从 PATH 查找。 | 执行外部 Python 脚本 |
| `CheckPathSecurity@server/msinsight/src/utils/FileUtil.cpp` | file | trusted_admin | 路径安全检查函数，验证路径长度、非法字符、软链接、owner、权限等。路径由调用者传入，通常来自用户请求参数。虽然有检查，但绕过方式可能存在（如 TOCTOU）。 | 验证文件路径安全性 |
| `OnDispatchModuleRequest@server/src/modules/ModuleManager.cpp` | rpc | untrusted_network | 根据 Request 的 moduleName 分发请求到对应模块处理。moduleName 和 request 内容来自 WebSocket 客户端的 JSON 解析结果，攻击者可控制分发目标。 | 分发 WebSocket 请求到模块处理器 |
| `handle_websocket_connection@plugins/ProfilerServerProxy/core/proxy/multi_aio_proxy_server.py` | network | untrusted_network | Python 实现的 WebSocket 代理服务器，接收前端客户端 WebSocket 连接并转发到后端 C++ WsServer。前端消息完全由攻击者控制，通过 proxy 转发可能绕过 C++ 服务器的安全检查。 | Python WebSocket 代理接收前端连接 |
| `_initialize@plugins/ProfilerServerProxy/core/server/profiler_server.py` | rpc | trusted_admin | 启动 profiler_server C++ 子进程，参数包括 wsPort、host、logPath、eventDir 等。参数由 ProfilerServerProxy 配置决定，不由用户直接控制。 | 启动 C++ WebSocket 服务器子进程 |
| `main@server/src/entry/server/bin/main.cpp` | cmdline | trusted_admin | 命令行入口，解析 argc/argv 参数启动服务器。参数包括 host、wsPort、logPath、eventDir 等。由用户在启动服务器时指定，非运行时攻击入口。 | 服务器启动命令行入口 |
| `PreLoadEventDir@server/src/server/WsServer.cpp` | file | trusted_admin | 预加载 eventDir 目录，目录路径由命令行参数 eventDir 指定。由管理员在启动服务器时配置，非运行时攻击入口。 | 预加载服务器启动时指定的 eventDir |

**其他攻击面**:
- WebSocket Network Interface: host:wsPort 端口监听，接收前端 WebSocket 连接和消息
- HTTP API Interface: POST/GET 处理器接收前端 HTTP 请求
- File Parsing Interface: 解析用户上传的 JSON/CSV/.db 性能分析数据文件
- Process Execution Interface: 执行外部 Python 脚本（cluster_analysis.py）处理集群分析
- Python WebSocket Proxy: ProfilerServerProxy 作为前端和 C++ 服务器之间的代理
- SQLite Database Interface: cluster.db、trace.db 等数据库文件读写
- JupyterLab Plugin Interface: 通过 JupyterLab 扩展访问 WebSocket 服务器

---

## 3. High 漏洞 (2)

### [server-vuln-001] Path Traversal - FilesGetHandler::HandleRequest

**严重性**: High | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Insight/server/src/modules/global/handler/FilesGetHandler.cpp:35-38` @ `FilesGetHandler::HandleRequest`
**模块**: server

**描述**: FilesGetHandler中request.params.path直接传递给FileSelector::GetFoldersAndFiles，虽然FileSelector.cpp中有realpath检查，但缺少完整的CheckPathSecurity验证，可能允许访问敏感目录

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Insight/server/src/modules/global/handler/FilesGetHandler.cpp:35-38`)

```c
FileSelector::GetFoldersAndFiles(request.params.path, ...)
```

**达成路径**

OnMessageCb -> OnRequestMessage -> ProtocolManager::FromJson -> FilesGetRequest.params.path -> FileSelector::GetFoldersAndFiles

**验证说明**: Path traversal partially mitigated by GetRealPath symlink resolution, but FindFolders called with strict=false bypasses CheckPathSecurity. Only symlink check applies, not full path security validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [cross-module-vuln-001] Cross-Module Data Flow - OnMessageCb

**严重性**: High | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `server/src/server/WsServer.cpp:165-175` @ `OnMessageCb`
**模块**: cross_module
**跨模块**: server → protocol → timeline → communication → global → utils

**描述**: 完整污点链: WebSocket(untrusted_network) → ProtocolMessageBuffer → ProtocolManager::FromJson → ModuleManager::OnDispatchModuleRequest → BaseModule::OnRequest → 各模块Handler。Request对象的params字段直接传递给各Handler，部分Handler缺少完整验证

**漏洞代码** (`server/src/server/WsServer.cpp:165-175`)

```c
session->OnRequestMessage(std::string(message))
```

**达成路径**

[IN] WebSocket message -> ProtocolMessageBuffer::operator<< -> Pop -> FromJson -> [OUT] Request -> ModuleManager -> Handlers

**验证说明**: 跨模块调用链完整验证：OnMessageCb→OnRequestMessage→ProtocolMessageBuffer→Pop→FromJson→OnDispatchModuleRequest。ModuleManager::OnDispatchModuleRequest存在WsSessionManager::CheckSession()会话检查（has_safety_check），但Request.params字段直接传递给各Handler，部分Handler可能缺少完整输入验证。攻击者可通过WebSocket发送恶意JSON请求，params内容部分可控。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: -15

---

## 4. Medium 漏洞 (4)

### [timeline-vuln-001] JSON Parsing - EventParser::Parse

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-module-scanner

**位置**: `server/src/modules/timeline/core/parser/EventParser.cpp:60-96` @ `EventParser::Parse`
**模块**: timeline

**描述**: EventParser::Parse使用rapidjson解析JSON文件内容，无深度限制(kParseDepthLimitFlag未设置)，深层嵌套JSON可能导致栈溢出或内存耗尽

**漏洞代码** (`server/src/modules/timeline/core/parser/EventParser.cpp:60-96`)

```c
document_t doc(allocator.get()); doc.Parse<kParseNumbersAsStringsFlag>(buffer.data());
```

**达成路径**

WebSocket request -> filePath -> FileReader::ReadJsonArray -> rapidjson Parse

**验证说明**: EventParser::Parse使用rapidjson DOM解析无深度限制。filePath通过WebSocket传入，经过OpenReadFileSafely→CheckPathSecurity路径验证，但JSON文件内容本身未限制深度。用户可构造深层嵌套JSON导致栈溢出。相比SaxParseJsonFile，EventParser使用DOM解析(doc.Parse)对内存/栈压力更大。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-SEC-PROX-004] command_injection - _initialize

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `plugins/ProfilerServerProxy/core/server/profiler_server.py:89-95` @ `_initialize`
**模块**: ProfilerServerProxy

**描述**: 子进程启动参数值来自命令行输入，缺乏严格的字符安全验证。虽然使用列表形式传参避免了shell=True的风险，但--logPath、--eventDir等参数值来自run.py的命令行参数，仅检查目录权限不检查字符安全性。特殊字符可能导致profiler_server二进制解析异常或意外行为。

**漏洞代码** (`plugins/ProfilerServerProxy/core/server/profiler_server.py:89-95`)

```c
for k, v in args.items():
    if v:
        start_args_list.append(f"{k}={v}")
self._start_cmd_list = [abs_server_bin] + start_args_list
```

**达成路径**

run.py命令行参数(--logPath,--eventDir) → common.py配置 → ProfilerServer.__init__参数 → _initialize:89-95 → subprocess.Popen:121

**验证说明**: Command-line arguments (--logPath, --eventDir) passed to subprocess without character safety validation. Permission checks exist in run.py but do not prevent special characters that could cause C++ backend parsing issues. Shell injection is avoided via list form.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [server-vuln-006] Insufficient Path Security - FileSelector::GetFoldersAndFiles

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Insight/server/src/modules/global/core/FileSelector.cpp:51-60` @ `FileSelector::GetFoldersAndFiles`
**模块**: server

**描述**: FileSelector::GetFoldersAndFiles中使用realpath检查但未调用CheckPathSecurity完整验证，可能遗漏软链接、权限等检查

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Insight/server/src/modules/global/core/FileSelector.cpp:51-60`)

```c
filepath = FileUtil::GetRealPath(tempPath); if (tempPath != filepath) { exist = false; return; }
```

**达成路径**

request.params.path -> tempPath -> GetRealPath -> FindFolders

**验证说明**: Same root cause as server-vuln-001. GetRealPath used but CheckPathSecurity not invoked due to strict=false. Consider merging with server-vuln-001.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [communication-vuln-002] File Parsing - ClusterFileParser::SaxParseJsonFile

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-module-scanner

**位置**: `server/src/modules/communication/parser/ClusterFileParser.cpp:63-95` @ `ClusterFileParser::SaxParseJsonFile`
**模块**: communication

**描述**: SaxParseJsonFile使用rapidjson SAX解析用户上传的JSON文件，CheckPathSecurity验证后打开文件，但rapidjson默认无深度限制，深层嵌套JSON可能导致内存耗尽

**漏洞代码** (`server/src/modules/communication/parser/ClusterFileParser.cpp:63-95`)

```c
FILE* fp = fopen(filePath.c_str(), "rb"); rapidjson::Reader reader; reader.Parse<kParseNumbersAsStringsFlag>(is, rapidSaxHandler)
```

**达成路径**

WebSocket request -> filePathList[0] -> PathPreprocess -> CheckPathSecurity -> fopen -> rapidjson Parse

**验证说明**: SaxParseJsonFile确实使用rapidjson::Reader无深度限制（仅设置kParseNumbersAsStringsFlag）。用户上传的JSON文件内容可控，深层嵌套可能导致栈溢出或内存耗尽。但存在多重缓解：CheckPathSecurity验证路径、IsRegularFile验证文件类型、CheckFileSize限制20GB、CheckPathOwner验证所有权。实际利用需构造满足所有安全检查的恶意JSON文件。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -35 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (3)

### [VULN-SEC-SERVER-004] improper_input_validation - OnMessageCb

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `server/src/server/WsServer.cpp:165-175` @ `OnMessageCb`
**模块**: server

**描述**: WebSocket message callback receives data from untrusted network source and creates a full copy via std::string(message) without size validation beyond the 16MB maxPayloadLength limit. Large messages could cause memory exhaustion before reaching the per-message processing stage.

**漏洞代码** (`server/src/server/WsServer.cpp:165-175`)

```c
void WsServer::OnMessageCb(WsChannel *ws, std::string_view message, uWS::OpCode opCode)
{
    if (ws == nullptr) { return; }
    WsSessionImpl *session = dynamic_cast<WsSessionImpl *>(WsSessionManager::Instance().GetSession());
    if (session == nullptr) { return; }
    session->OnRequestMessage(std::string(message)); // copies entire message
}
```

**达成路径**

WebSocket network input [SOURCE: untrusted_network] → OnMessageCb → std::string(message) copy → OnRequestMessage

**验证说明**: 16MB maxPayloadLength exists but std::string(message) creates full copy. Memory exhaustion possible with concurrent large messages before validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-SERVER-003] improper_input_validation - OnRequestMessage

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `server/src/server/WsSessionImpl.cpp:145-153` @ `OnRequestMessage`
**模块**: server
**跨模块**: server → module_manager

**描述**: WebSocket messages received from untrusted network source are queued for processing without format validation, structural verification, or sanity checks. Messages are passed directly to internal module dispatch (ModuleManager::OnDispatchModuleRequest) without intermediate validation. Malformed or maliciously crafted messages could cause downstream processing errors, crashes, or unexpected behavior.

**漏洞代码** (`server/src/server/WsSessionImpl.cpp:145-153`)

```c
void WsSessionImpl::OnRequestMessage(const std::string &data)
{
    if (msgBuffer == nullptr) {
        return;
    }
    if (data.empty()) {
        return;
    }
    (*msgBuffer.get()) << data;
}
```

**达成路径**

WsServer.cpp:165 OnMessageCb [SOURCE: untrusted_network] → WsSessionImpl.cpp:145 OnRequestMessage → msgBuffer queue → BatchHandleMsg → ModuleManager::OnDispatchModuleRequest [SINK: unknown downstream processing]

**验证说明**: Mitigations exist: ProtocolMessageBuffer checks for HEAD_START/REQ_DELIMITER injection (line 51-53), size limit bufferLimit (line 56-58), moduleName validation in ProtocolManager. Original report overstated 'no validation'.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -35 | context: 0 | cross_file: -15

---

### [server-vuln-002] Input Validation Bypass - JsonUtil::GetString

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Insight/server/msinsight/src/utils/JsonUtil.h:256-265` @ `JsonUtil::GetString`
**模块**: server

**描述**: JsonUtil::GetString从JSON中提取字符串时未进行长度限制和特殊字符验证，可能导致后续处理中的注入问题

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Insight/server/msinsight/src/utils/JsonUtil.h:256-265`)

```c
return value.GetString();
```

**达成路径**

WebSocket message -> ProtocolMessageBuffer::Pop -> ProtocolManager::FromJson -> JsonUtil::GetString -> request params

**验证说明**: GetString is a JSON helper without validation, but downstream callers (e.g., JsonUtil::ReadJsonFromFile) invoke CheckPathSecurity. Vulnerability depends on specific handler implementations.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: -15 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| ProfilerServerProxy | 0 | 0 | 1 | 0 | 1 |
| communication | 0 | 0 | 1 | 0 | 1 |
| cross_module | 0 | 1 | 0 | 0 | 1 |
| server | 0 | 1 | 1 | 3 | 5 |
| timeline | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **2** | **4** | **3** | **9** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 4 | 44.4% |
| CWE-502 | 2 | 22.2% |
| CWE-22 | 2 | 22.2% |
| CWE-78 | 1 | 11.1% |
