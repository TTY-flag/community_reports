# 漏洞扫描报告 — 待确认漏洞

**项目**: mindstudio-agent (msagent)
**扫描时间**: 2026-04-21T00:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本报告包含 **37 个待确认漏洞**，其中 **8 个为 High 级别**，16 个为 Medium 级别，13 个为 Low 级别。这些漏洞经自动化扫描检测，但需人工验证确认风险程度和可利用性。

### 待确认漏洞风险说明

待确认漏洞（LIKELY/POSSIBLE）代表以下情况：

| 状态 | 含义 | 处理建议 |
|------|------|----------|
| LIKELY (20个) | 漏洞模式存在，可利用性需验证 | 优先人工审查，可能升级为 CONFIRMED |
| POSSIBLE (17个) | 代码模式可疑，实际风险较低 | 低优先级审查，可能标记为 FALSE_POSITIVE |

### 关键待确认漏洞类别

1. **SSRF (5个)**: LLM base_url 和 MCP URL 配置可能允许连接内部服务，需验证网络隔离策略
2. **环境变量注入 (2个)**: MCP STDIO 环境变量可能注入危险变量，需验证配置访问控制
3. **路径遍历 (6个)**: 多处文件路径拼接可能超出边界，需验证实际触发条件
4. **模板注入 (1个)**: `str.format(**context)` 可能访问对象属性，需验证 context 来源

### 与已确认漏洞的关联

部分待确认漏洞与已确认漏洞存在关联：
- **SSRF 待确认** → 与 VULN-DF-LLMS-002 (Cleartext Transmission) 相关
- **环境变量注入** → 与 VULN-CROSS-001 (Credential Flow Chain) 相关
- **工具加载风险** → 与 VULN-DF-SANDBOXES-001 (Sandbox Missing) 相关

### 验证优先级建议

| 优先级 | 漏洞类型 | 数量 | 验证方式 |
|--------|----------|------|----------|
| 高 | SSRF (CWE-918) | 5 | 检查网络策略和 URL 验证 |
| 中 | 环境变量注入 (CWE-78) | 2 | 检查 MCP 配置访问控制 |
| 中 | 路径遍历 (CWE-22) | 6 | 构造测试路径验证边界 |
| 低 | 模板注入 (CWE-94) | 1 | 检查 context 数据来源 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 20 | 32.3% |
| POSSIBLE | 17 | 27.4% |
| CONFIRMED | 13 | 21.0% |
| FALSE_POSITIVE | 12 | 19.4% |
| **总计** | **62** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 8 | 21.6% |
| Medium | 16 | 43.2% |
| Low | 13 | 35.1% |
| **有效漏洞总计** | **37** | - |
| 误报 (FALSE_POSITIVE) | 12 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-MCP-003]** SSRF (High) - `src/msagent/mcp/client.py:143` @ `_build_connection` | 置信度: 75
2. **[VULN-MCP-002]** SSRF via HTTP/SSE/Websocket URLs (High) - `src/msagent/mcp/client.py:143` @ `_build_connection` | 置信度: 75
3. **[VULN-MCP-005]** Environment Variable Injection via STDIO (High) - `src/msagent/mcp/client.py:139` @ `_build_connection` | 置信度: 75
4. **[VULN-CLI-003]** MCP Command Execution (High) - `src/msagent/configs/mcp.py:50` @ `MCPServerConfig` | 置信度: 75
5. **[VULN-DF-LLMS-003]** Server-Side Request Forgery (High) - `src/msagent/llms/factory.py:183` @ `_normalize_base_url` | 置信度: 75
6. **[VULN-CFG-LLM-001]** SSRF (High) - `src/msagent/configs/llm.py:64` @ `LLMConfig.base_url` | 置信度: 75
7. **[VULN-CROSS-003]** ssrf_credential_leak (High) - `src/msagent/llms/factory.py:104` @ `create` | 置信度: 75
8. **[VULN-DF-MCP-004]** Injection (High) - `src/msagent/mcp/client.py:139` @ `_build_connection` | 置信度: 70
9. **[VULN-DF-CONFIGS-001]** Template Injection (Medium) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/utils/render.py:44` @ `render_templates` | 置信度: 80
10. **[VULN-CLI-001]** Credential Exposure (Medium) - `src/msagent/cli/bootstrap/legacy.py:287` @ `_handle_config` | 置信度: 80

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `cli@run.py` | cmdline | untrusted_local | CLI 主入口点，用户通过命令行参数和交互式输入控制程序行为 | CLI 入口，解析命令行参数并启动会话 |
| `launch_langgraph_dev_server@src/msagent/web/launcher.py` | network | semi_trusted | Web API 服务器入口，绑定 127.0.0.1:2024，仅本地可达但 HTTP 客户端可发送任意请求 | 启动 LangGraph API 服务器，提供 HTTP 接口 |
| `dispatch@src/msagent/cli/handlers/bash.py` | stdin | untrusted_local | 直接执行用户输入的 bash 命令，命令内容完全由用户控制 | Bash 命令执行处理，用户可执行任意 shell 命令 |
| `tools@src/msagent/mcp/client.py` | rpc | untrusted_network | MCP 客户端从外部服务器加载工具，外部服务器可能是不可信来源 | 从 MCP 服务器加载工具列表，支持 stdio/sse/http/websocket 传输 |
| `web_search@src/msagent/tools/web_search.py` | web_route | semi_trusted | 发送 HTTP 请求到外部搜索 API (DuckDuckGo/Tavily)，用户可控制搜索关键词 | Web 搜索工具，向外部 API 发送请求 |
| `create_legacy_parser@src/msagent/cli/bootstrap/legacy.py` | cmdline | untrusted_local | argparse 参数解析，用户可控制命令行参数 | CLI 参数解析器，处理 config/chat/web 子命令 |
| `from_json@src/msagent/configs/mcp.py` | file | trusted_admin | 从配置文件加载 MCP 服务器配置，配置文件由管理员/用户编辑 | 从 JSON 文件加载 MCP 配置 |
| `load_all@src/msagent/configs/registry.py` | file | trusted_admin | 加载所有配置文件，配置由用户/管理员控制 | 配置注册表，加载 LLM/Agent/MCP/Sandbox 配置 |
| `load_skills@src/msagent/skills/factory.py` | file | trusted_admin | 从目录加载 Skills 定义文件 (SKILL.md)，文件内容由用户/管理员控制 | Skills 加载器，读取 SKILL.md 文件 |
| `get_skill@src/msagent/tools/catalog/skills.py` | file | trusted_admin | 读取 Skill 文件内容，文件路径来自已加载的 Skills 目录 | 读取指定 Skill 的 SKILL.md 内容 |
| `_get_files@src/msagent/cli/resolvers/file.py` | cmdline | semi_trusted | 执行 shell 命令列出文件，使用 shlex.quote 处理 pattern 参数 | 文件补全解析器，执行 git/fd 命令 |
| `create@src/msagent/llms/factory.py` | network | untrusted_network | 创建 LLM 客户端连接外部 API 服务器 | LLM 工厂，创建 OpenAI/Anthropic/Google LLM 客户端 |

**其他攻击面**:
- CLI 命令行参数: 用户可控制所有子命令和参数
- 交互式会话输入: 用户在 CLI 会话中输入文本和命令
- Bash 模式: 用户可直接执行任意 shell 命令
- Web API HTTP 请求: 127.0.0.1:2024 接收 HTTP 请求
- MCP 工具服务器连接: stdio/sse/http/websocket 连接外部工具服务器
- 配置文件解析: YAML/JSON 配置文件加载
- LLM API 调用: 发送请求到外部 LLM 服务
- Web 搜索请求: 发送 HTTP 请求到 DuckDuckGo/Tavily
- Skills 文件加载: 从目录读取 SKILL.md 文件

---

## 3. High 漏洞 (8)

### [VULN-DF-MCP-003] SSRF - _build_connection

**严重性**: High | **CWE**: CWE-918 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/msagent/mcp/client.py:143-170` @ `_build_connection`
**模块**: mcp

**描述**: SSRF via URL configuration in _build_connection()

**达成路径**

[TAINT] MCPServerConfig.url -> _build_connection()

**验证说明**: Same as VULN-MCP-002 - SSRF via unvalidated URL.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-MCP-002] SSRF via HTTP/SSE/Websocket URLs - _build_connection

**严重性**: High | **CWE**: CWE-918 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/msagent/mcp/client.py:143-170` @ `_build_connection`
**模块**: mcp
**跨模块**: configs/mcp.py, mcp/client.py

**描述**: The _build_connection method in client.py accepts arbitrary URLs from server.url without validation. There is no SSRF protection, no whitelist for allowed hosts, and no check for localhost/internal IP ranges. An attacker who can modify the MCP configuration can cause the application to connect to internal services, potentially accessing sensitive internal APIs or services.

**漏洞代码** (`src/msagent/mcp/client.py:143-170`)

```c
connection = {"transport": "sse", "url": server.url}
```

**达成路径**

config.mcp.json -> MCPConfig.from_json -> MCPServerConfig.url -> MCPClient._build_connection -> MultiServerMCPClient (http/sse/websocket)

**验证说明**: SSRF via server.url - no URL validation or whitelist. Attacker with config access can connect to internal services.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-MCP-005] Environment Variable Injection via STDIO - _build_connection

**严重性**: High | **CWE**: CWE-78 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/msagent/mcp/client.py:139-140` @ `_build_connection`
**模块**: mcp
**跨模块**: configs/mcp.py, mcp/client.py

**描述**: The _build_connection method passes server.env directly to the subprocess connection without validation. Environment variables like PATH, LD_PRELOAD, PYTHONPATH or other security-sensitive variables could be manipulated by an attacker who can modify the MCP configuration, potentially leading to code injection or privilege escalation.

**漏洞代码** (`src/msagent/mcp/client.py:139-140`)

```c
if server.env:\n    connection["env"] = dict(server.env)
```

**达成路径**

config.mcp.json -> MCPConfig.from_json -> MCPServerConfig.env -> MCPClient._build_connection -> subprocess environment

**验证说明**: Environment variable injection via server.env - can inject LD_PRELOAD, PATH etc for code execution.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-CLI-003] MCP Command Execution - MCPServerConfig

**严重性**: High | **CWE**: CWE-78 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/msagent/configs/mcp.py:50-63` @ `MCPServerConfig`
**模块**: cli
**跨模块**: mcp/factory.py

**描述**: MCP server configuration allows arbitrary command execution via command and args fields. Malicious MCP config modification could enable unauthorized command execution. repair_command field also allows command execution on server failure.

**漏洞代码** (`src/msagent/configs/mcp.py:50-63`)

```c
command: str | None, args: list[str], repair_command: list[str] | None
```

**达成路径**

mcp_config.command/args -> subprocess execution via MCP factory

**验证说明**: MCP configuration allows arbitrary command execution via command/args fields. Risk depends on who can modify MCP config files.

**评分明细**: base: 30 | reachability: 25 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-LLMS-003] Server-Side Request Forgery - _normalize_base_url

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-918 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/msagent/llms/factory.py:183-204` @ `_normalize_base_url`
**模块**: llms

**描述**: base_url parameter accepts arbitrary URLs without validation or allowlist. This enables SSRF attacks where LLM API requests can be redirected to internal services, potentially leaking API keys or accessing internal endpoints.

**达成路径**

LLMConfig.base_url -> urlparse() -> httpx.Client(base_url=...) -> internal network access

**验证说明**: base_url accepts arbitrary URLs without validation. Only DeepSeek has special handling. SSRF risk.

**评分明细**: base: 30 | reachability: 25 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-CFG-LLM-001] SSRF - LLMConfig.base_url

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-918 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/msagent/configs/llm.py:64-67` @ `LLMConfig.base_url`
**模块**: configs
**跨模块**: configs, llms

**描述**: User-configurable base_url allows redirecting LLM API calls to arbitrary endpoints. The base_url field in LLMConfig (llm.py:64) is passed directly to init_chat_model in factory.py:104-109 without full URL validation. While there is partial mitigation for DeepSeek URLs (factory.py:200-202), arbitrary base_url values could redirect API calls and credentials to attacker-controlled servers.

**漏洞代码** (`src/msagent/configs/llm.py:64-67`)

```c
base_url: str | None = Field(default=None, description="Optional base URL override")
```

**达成路径**

[CREDENTIAL_FLOW] LLMConfig.base_url -> LLMFactory.create() -> _normalize_base_url() -> init_chat_model(base_url=...) -> HTTP requests with API keys

**验证说明**: Same as VULN-DF-LLMS-003 - SSRF via base_url.

**评分明细**: base: 30 | reachability: 25 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-CROSS-003] ssrf_credential_leak - create

**严重性**: High | **CWE**: CWE-918 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/msagent/llms/factory.py:104-109` @ `create`
**模块**: cross-module
**跨模块**: configs → llms

**描述**: 跨模块SSRF凭证泄露：base_url重定向导致API密钥发送到攻击者服务器
1. configs/llm.py定义base_url字段
2. llms/factory.py使用base_url创建HTTP客户端
3. API密钥随请求发送到base_url指定的endpoint

仅对DeepSeek有特殊验证，其他provider无白名单

**达成路径**

configs/llm.py:base_url → llms/factory.py:104 → init_chat_model(base_url=...) → HTTP POST携带api_key

**验证说明**: Cross-module SSRF credential leak: base_url sends API keys to arbitrary endpoints. Only DeepSeek has special validation.

**评分明细**: base: 30 | reachability: 25 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-DF-MCP-004] Injection - _build_connection

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-74 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/msagent/mcp/client.py:139-140` @ `_build_connection`
**模块**: mcp

**描述**: Environment variable injection: server.env dictionary is passed directly to spawned processes via STDIO transport (line 139-140). An attacker who controls MCPConfig could inject malicious environment variables (e.g., LD_PRELOAD, PATH manipulation) to achieve code execution or leak secrets.

**达成路径**

[TAINT] MCPConfig.from_json() → MCPServerConfig.env → _build_connection() → process environment

**验证说明**: Same as VULN-MCP-005 - env injection via MCP config.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

---

## 4. Medium 漏洞 (16)

### [VULN-DF-CONFIGS-001] Template Injection - render_templates

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-94 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/utils/render.py:44-47` @ `render_templates`
**模块**: configs

**描述**: Template injection vulnerability in render_templates function. The function uses Python str.format(**context) which can access object attributes and methods if context contains malicious objects. Called from mcp.py:from_json with externally-loaded JSON config.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/utils/render.py:44-47`)

```c
return data.format(**context)
```

**达成路径**

from_json@mcp.py:92 -> render_templates@render.py:36 -> str.format(**context)

**验证说明**: Template injection via str.format(**context) - called from mcp.py with JSON config.

**评分明细**: base: 30 | reachability: 25 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-CLI-001] Credential Exposure - _handle_config

**严重性**: Medium | **CWE**: CWE-214 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/msagent/cli/bootstrap/legacy.py:287-291` @ `_handle_config`
**模块**: cli

**描述**: API Key passed via command-line argument is visible in process listing. The --llm-api-key parameter sets environment variable directly, making the key visible to other users via ps/top commands.

**漏洞代码** (`src/msagent/cli/bootstrap/legacy.py:287-291`)

```c
os.environ[str(env_name)] = args.llm_api_key
```

**达成路径**

args.llm_api_key (cmdline) -> os.environ[api_key_env]

**验证说明**: API key passed via --llm-api-key CLI argument is visible in process listings (ps/top). This is a valid concern but requires local access to the system.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-LLMS-001] CREDENTIAL_EXPOSURE - _handle_config

**严重性**: Medium | **CWE**: CWE-214 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/cli/bootstrap/legacy.py:287-291` @ `_handle_config`
**模块**: llms
**跨模块**: cli/bootstrap/legacy.py,llms/factory.py

**描述**: API key set directly from CLI argument to environment variable without masking. Visible in process listings, shell history, and potentially in logs.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/cli/bootstrap/legacy.py:287-291`)

```c
if args.llm_api_key:\n    env_name = llm_data.get("api_key_env") or DEFAULT_API_ENV_MAP.get(provider or current_llm.provider)\n    if env_name:\n        os.environ[str(env_name)] = args.llm_api_key
```

**达成路径**

[CREDENTIAL_FLOW] CLI argument -> os.environ -> LLMFactory._resolve_api_key() -> kwargs["api_key"] -> init_chat_model

**验证说明**: Same as VULN-CLI-001 - API key via cmdline visible in process listings.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-DF-LLMS-004] Certificate Validation Bypass - _resolve_openai_trust_env

**严重性**: Medium | **CWE**: CWE-295 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/msagent/llms/factory.py:122-137` @ `_resolve_openai_trust_env`
**模块**: llms

**描述**: trust_env parameter allows disabling certificate validation via environment variables. When trust_env=True, SSL_CERT_FILE and proxy environment variables can bypass certificate verification, enabling MITM attacks on LLM API connections.

**达成路径**

LLMConfig.trust_env -> _resolve_openai_trust_env() -> httpx.Client(trust_env=True) -> SSL_CERT_FILE bypass

**验证说明**: trust_env allows disabling certificate validation via SSL_CERT_FILE env var. MITM risk.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-LLMS-002] CREDENTIAL_FLOW - _resolve_api_key

**严重性**: Medium | **CWE**: CWE-522 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/llms/factory.py:169-180` @ `_resolve_api_key`
**模块**: llms
**跨模块**: core/settings.py,llms/factory.py

**描述**: API key extracted from SecretStr via get_secret_value() and passed as plain string to init_chat_model. While necessary for LangChain, the key could be logged by library internals or leaked in debug output.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/llms/factory.py:169-180`)

```c
if isinstance(value, SecretStr):\n    raw = value.get_secret_value().strip()\nelif isinstance(value, str):\n    raw = value.strip()\n...\nreturn raw
```

**达成路径**

[CREDENTIAL_FLOW] LLMSettings.SecretStr -> get_secret_value() -> plain string -> kwargs["api_key"] -> init_chat_model

**验证说明**: API key extracted from SecretStr - necessary for LangChain but could be logged.

**评分明细**: base: 30 | reachability: 25 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-DF-MCP-002] Code Injection - tools

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-94 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/msagent/mcp/client.py:60-107` @ `tools`
**模块**: mcp
**跨模块**: mcp,agents

**描述**: Untrusted tool definitions loaded from external MCP servers: tools() method at line 74 calls MultiServerMCPClient.get_tools() which fetches tool definitions from external servers. These tool definitions (including tool names, descriptions, parameter schemas) come from untrusted network sources and are returned to caller without validation or signature verification. An attacker-controlled MCP server could inject malicious tool definitions.

**达成路径**

[TAINT] External MCP server -> MultiServerMCPClient.get_tools() -> loaded_tools -> filtered_tools -> [OUT] to agents/factory.py

**验证说明**: Tool definitions from external MCP servers without signature verification - attacker-controlled MCP server could inject malicious tools.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-MCP-003] Credential Exposure in Configuration - MCPServerConfig

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-522 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/msagent/configs/mcp.py:52-55` @ `MCPServerConfig`
**模块**: mcp
**跨模块**: configs/mcp.py, mcp/client.py, llms/factory.py

**描述**: [CREDENTIAL_FLOW] The MCPServerConfig class stores sensitive headers and environment variables as plain dict[str, str] without using SecretStr for protection. Unlike LLMConfig which uses SecretStr for API keys, these credentials can be exposed in logs, debug output, or when the configuration is serialized. Headers may contain authentication tokens, API keys, or other secrets that should be protected.

**漏洞代码** (`src/msagent/configs/mcp.py:52-55`)

```c
headers: dict[str, str] | None = Field(default=None)\nenv: dict[str, str] = Field(default_factory=dict)
```

**达成路径**

config.mcp.json -> MCPConfig -> MCPServerConfig.headers/env -> MCPClient._build_connection -> external process/network connection

**验证说明**: Headers/env stored as plain dict - credential exposure risk in logs/serialization. Lower impact than command execution.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 15

---

### [VULN-004] Path Traversal - resolve_path

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: python-security-module-scanner

**位置**: `src/msagent/utils/path.py:73-78` @ `resolve_path`
**模块**: utils

**描述**: Symlink escape detection bypassed for absolute paths. The is_symlink_escape check only triggers when is_absolute is False (line 73-76). Absolute symlinks bypass escape detection, allowing access to sensitive files like /etc/passwd.

**漏洞代码** (`src/msagent/utils/path.py:73-78`)

```c
if not is_absolute:
    original = working_path / path
    if original.exists() and is_symlink_escape(original, [working_path]):
        raise SymlinkEscapeError(...)
```

**达成路径**

path -> is_absolute check -> bypass symlink escape for absolute symlinks

**验证说明**: Symlink escape check only applies to non-absolute paths (line 73-76 in path.py). Absolute symlinks bypass detection, but require symlink creation capability.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-DF-CONFIGS-003] Command Injection via Config - MCPServerConfig

**严重性**: Medium | **CWE**: CWE-77 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/configs/mcp.py:50-56` @ `MCPServerConfig`
**模块**: configs

**描述**: MCP server configuration contains command/args fields that could execute arbitrary commands.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/configs/mcp.py:50-56`)

```c
command: str | None, args: list[str]
```

**达成路径**

from_json@mcp.py:92 -> MCPServerConfig(**server_config)

**验证说明**: Same as VULN-MCP-001 - command via MCP config.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-CLI-005] Default Approval Configuration - _default_decision_rules

**严重性**: Medium | **CWE**: CWE-693 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/msagent/configs/approval.py:166-172` @ `_default_decision_rules`
**模块**: cli
**跨模块**: cli/dispatchers/messages.py

**描述**: Default approval configuration has execute tool with always_approve decision as fallback. This means all shell commands are auto-approved by default after specific dangerous pattern checks.

**漏洞代码** (`src/msagent/configs/approval.py:166-172`)

```c
ToolDecisionRule(name="execute", args={"command": r".*"}, decision="always_approve")
```

**达成路径**

execute tool call -> decision_rules match -> always_approve

**验证说明**: Default decision_rules includes fallback that auto-approves all execute commands. Dangerous commands (rm -rf, sudo, git push/reset) require ask, but all other commands auto-approved.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MIDDLEWARES-001] Approval Bypass - _default_decision_rules

**严重性**: Medium | **CWE**: CWE-693 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/msagent/configs/approval.py:169-172` @ `_default_decision_rules`
**模块**: middlewares
**跨模块**: configs,interrupts,agents

**描述**: Default decision_rules includes fallback rule that auto-approves all execute commands (pattern r".*" with decision "always_approve"). If no explicit deny rules are set, dangerous commands like rm -rf can bypass approval.

**漏洞代码** (`src/msagent/configs/approval.py:169-172`)

```c
ToolDecisionRule(name="execute", args={"command": r".*"}, decision="always_approve")
```

**达成路径**

configs/approval.py -> interrupt_handler.py -> deepagents

**验证说明**: Same as VULN-CLI-005 - default approval fallback.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-LOW-APPROVAL-001] Security Control Misconfiguration - _default_decision_rules

**严重性**: Medium（原评估: Low → 验证后: Medium） | **CWE**: CWE-16 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/msagent/configs/approval.py:166-172` @ `_default_decision_rules`
**模块**: core

**描述**: ToolApprovalConfig default decision_rules includes a fallback rule that automatically approves all execute commands (command: ".*" -> always_approve). This could lead to unintended command execution if more specific rules fail to match.

**漏洞代码** (`src/msagent/configs/approval.py:166-172`)

```c
ToolDecisionRule(\n    name="execute",\n    args={"command": r".*"},\n    decision="always_approve",\n),
```

**验证说明**: Same as VULN-DF-MIDDLEWARES-001.

---

### [VULN-MCP-004] Untrusted Tool Loading Without Verification - tools

**严重性**: Medium | **CWE**: CWE-436 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/msagent/mcp/client.py:60-107` @ `tools`
**模块**: mcp

**描述**: The tools() method loads tools from external MCP servers without any verification of tool source authenticity, code signing, or permission controls. The _is_tool_enabled method only performs basic name-based filtering (include/exclude lists) but does not verify tool integrity or trustworthiness. Tools from untrusted MCP servers could execute malicious operations on the host system.

**漏洞代码** (`src/msagent/mcp/client.py:60-107`)

```c
loaded_tools = await client.get_tools()
```

**达成路径**

External MCP Server -> MultiServerMCPClient.get_tools -> MCPClient.tools() -> Agent runtime (tool execution)

**验证说明**: Untrusted tool loading without verification - depends on trust model for MCP servers.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-AGENTS-003] Path Traversal - AgentContext

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/msagent/agents/context.py:54-55` @ `AgentContext`
**模块**: agents
**跨模块**: agents,cli

**描述**: [CREDENTIAL_FLOW] Unvalidated working directory via environment variable: AgentContext uses MSAGENT_WEB_WORKING_DIR environment variable to determine working directory without validation. If attacker can set this environment variable (e.g., via web request or compromised process), they can control the directory where shell commands execute via LocalShellBackend.

**漏洞代码** (`src/msagent/agents/context.py:54-55`)

```c
working_dir: Path = Field(default_factory=lambda: Path(os.getenv("MSAGENT_WEB_WORKING_DIR", "").strip() or Path.cwd()).resolve())
```

**达成路径**

[TAINT] MSAGENT_WEB_WORKING_DIR env -> AgentContext.working_dir -> LocalShellBackend.root_dir

**验证说明**: MSAGENT_WEB_WORKING_DIR controls execution directory - requires env var control, limited attack surface.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-AGENTS-002] Code Injection - _resolve_retry_on_exceptions

**严重性**: Medium | **CWE**: CWE-94 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: python-security-module-scanner, dataflow-scanner

**位置**: `src/msagent/agents/factory.py:561-597` @ `_resolve_retry_on_exceptions`
**模块**: agents
**跨模块**: agents,configs

**描述**: [CREDENTIAL_FLOW] Dynamic import of exception classes from configurable strings: _resolve_retry_on_exceptions() uses import_module() and getattr() to dynamically load exception classes based on user-configurable names in retry.tool.retry_on config. If an attacker can modify agent configuration, they could potentially import arbitrary modules or classes.

**漏洞代码** (`src/msagent/agents/factory.py:561-597`)

```c
module = import_module(module_name); candidate = getattr(module, attr_name, None)
```

**达成路径**

[TAINT] AgentConfig.retry.tool.retry_on -> _resolve_retry_on_exceptions() -> import_module() -> getattr()

**验证说明**: Dynamic import of exception classes - limited to Exception subclasses only, provides some protection.

**评分明细**: base: 30 | reachability: 15 | controllability: 5 | mitigations: -5 | context: 0 | cross_file: 5

---

### [VULN-DF-CLI-005] path_injection - _create_checkpointer

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/msagent/cli/bootstrap/initializer.py:280-289` @ `_create_checkpointer`
**模块**: cli
**跨模块**: cli,configs

**描述**: SQLite checkpointer uses config.connection_string which could potentially be a file path from configuration. If configuration is user-controlled, this could lead to arbitrary file access.

**漏洞代码** (`src/msagent/cli/bootstrap/initializer.py:280-289`)

```c
sqlite_path = config.connection_string or db_path; conn = await aiosqlite.connect(sqlite_path)
```

**达成路径**

config.connection_string -> sqlite_path @ initializer.py:280 -> aiosqlite.connect(sqlite_path) @ initializer.py:284

**验证说明**: connection_string comes from config file, not user input. Configuration is typically admin-controlled. Low risk unless config file is compromised.

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (13)

### [VULN-LLMS-004] INPUT_VALIDATION - create

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/llms/factory.py:104-109` @ `create`
**模块**: llms

**描述**: User-provided base_url passed to HTTP client without URL validation. Could redirect API requests to malicious endpoints, enabling credential theft.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/llms/factory.py:104-109`)

```c
normalized_base_url = self._normalize_base_url(provider, cfg.base_url)\nif normalized_base_url:\n    kwargs["base_url"] = normalized_base_url\n    provider_base_url_key = _PROVIDER_BASE_URL_KWARG.get(provider)\n    if provider_base_url_key:\n        kwargs[provider_base_url_key] = normalized_base_url
```

**达成路径**

[CREDENTIAL_FLOW] LLMConfig.base_url -> kwargs["base_url"] -> init_chat_model -> HTTP client

**验证说明**: Same as VULN-DF-LLMS-003 - base_url SSRF.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CONFIGS-002] Path Traversal - load_prompt_content

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/configs/utils.py:177-188` @ `load_prompt_content`
**模块**: configs

**描述**: Path traversal risk in load_prompt_content. Paths are concatenated without validation (base_path / prompt). No check that resolved path stays within expected directory bounds.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/configs/utils.py:177-188`)

```c
prompt_path = base_path / prompt
```

**达成路径**

from_yaml@agent.py:550 -> load_prompt_content@utils.py:163

**验证说明**: Path traversal in load_prompt_content - config-based.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-LLMS-003] INSECURE_CONFIGURATION - _resolve_api_key

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-15 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/llms/factory.py:149-153` @ `_resolve_api_key`
**模块**: llms

**描述**: Arbitrary environment variable name allowed for API key retrieval via api_key_env config field. Misconfiguration could expose unintended credentials.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/llms/factory.py:149-153`)

```c
if cfg.api_key_env:\n    from_env = os.getenv(cfg.api_key_env, "").strip()\n    if from_env:\n        return from_env
```

**达成路径**

[CREDENTIAL_FLOW] LLMConfig.api_key_env (user-configurable) -> os.getenv() -> API key returned

**验证说明**: api_key_env allows arbitrary env var names - misconfiguration risk.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CFG-MCP-002] Injection - MCPServerConfig.headers

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-74 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/msagent/configs/mcp.py:52-53` @ `MCPServerConfig.headers`
**模块**: configs
**跨模块**: configs, mcp

**描述**: Headers injection via MCP HTTP/WebSocket transports: server.headers dictionary is passed directly to MCP client connections (mcp/client.py:148, 160). User-provided headers could contain malicious values or credential exfiltration headers. No header validation or sanitization is performed.

**漏洞代码** (`src/msagent/configs/mcp.py:52-53`)

```c
headers: dict[str, str] | None = Field(default=None, description="Headers for the server connection")
```

**达成路径**

[TAINT] MCPConfig.from_json() -> MCPServerConfig.headers -> _build_connection() -> connection["headers"] -> HTTP requests

**验证说明**: Headers injection via MCP config - config-based.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-LLMS-005] Injection - create

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/msagent/llms/factory.py:91` @ `create`
**模块**: llms

**描述**: params dict from LLMConfig is directly passed to init_chat_model without validation. This allows arbitrary parameter injection which could affect LangChain behavior or introduce unexpected configurations.

**达成路径**

LLMConfig.params -> kwargs.update() -> init_chat_model(**kwargs) -> untrusted parameter injection

**验证说明**: params dict injection - config-based, limited attack surface.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-LLMS-005] CREDENTIAL_STORAGE - LLMSettings

**严重性**: Low | **CWE**: CWE-256 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/core/settings.py:38-44` @ `LLMSettings`
**模块**: llms
**跨模块**: core/settings.py,llms/factory.py

**描述**: Proxy URLs stored as SecretStr but default values sourced directly from os.getenv() at module load time. Proxy URLs may contain embedded credentials (user:pass@host).

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/core/settings.py:38-44`)

```c
http_proxy: SecretStr = Field(\n    default=SecretStr(os.getenv("HTTP_PROXY", os.getenv("http_proxy", ""))),\n    description="HTTP proxy URL",\n)\nhttps_proxy: SecretStr = Field(\n    default=SecretStr(os.getenv("HTTPS_PROXY", os.getenv("https_proxy", ""))),\n    description="HTTPS proxy URL",\n)
```

**达成路径**

[CREDENTIAL_FLOW] os.getenv(HTTP_PROXY/HTTPS_PROXY) -> SecretStr default -> LLMSettings

**验证说明**: Proxy URLs sourced from env at module load - embedded credential risk.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-LOW-MIDDLEWARE-001] Security Control Bypass - ApprovalMiddleware.__init__

**严重性**: Low | **CWE**: CWE-693 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/msagent/middlewares/approval.py:40-46` @ `ApprovalMiddleware.__init__`
**模块**: middlewares

**描述**: ApprovalMiddleware can be disabled via enabled=False parameter, potentially allowing tool calls to bypass approval workflow. However, actual approval logic is implemented in ToolApprovalConfig class which provides secondary control.

**漏洞代码** (`src/msagent/middlewares/approval.py:40-46`)

```c
def __init__(self, enabled: bool = True):\n    self.enabled = enabled
```

**验证说明**: ApprovalMiddleware can be disabled - secondary control in ToolApprovalConfig.

---

### [VULN-LOW-CORE-002] Sensitive Data Exposure - LLMSettings/ToolSettings.model_dump

**严重性**: Low | **CWE**: CWE-312 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/msagent/core/settings.py:35-59` @ `LLMSettings/ToolSettings.model_dump`
**模块**: core

**描述**: Settings uses SecretStr for API keys (good practice), but model_dump(hide_secret_str=False) method can expose secret values. Default dummy values may mislead users about actual configuration state.

**漏洞代码** (`src/msagent/core/settings.py:35-59`)

```c
def model_dump(self, hide_secret_str: bool = True, *args, **kwargs):\n    dump = super().model_dump(*args, **kwargs)\n    if hide_secret_str:\n        return dump\n    else:\n        return dump | {key: value.get_secret_value() for key, value in dump.items() if isinstance(value, SecretStr)}
```

**验证说明**: model_dump(hide_secret_str=False) exposes secrets - requires explicit call.

---

### [VULN-DF-CONFIGS-004] Missing Input Validation - from_json

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/configs/mcp.py:92-116` @ `from_json`
**模块**: configs

**描述**: Configuration loading functions do not validate that input paths are within expected working directory.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/msagent/src/msagent/configs/mcp.py:92-116`)

```c
async def from_json(cls, path: Path, context: dict)
```

**达成路径**

from_json@mcp.py:92 -> aiofiles.open(path)

**验证说明**: Missing path validation in config loading - low risk.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-TESTING-001] Configuration Bypass Risk - create_graph

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-15 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/msagent/cli/bootstrap/initializer.py:124-138` @ `create_graph`
**模块**: testing
**跨模块**: testing,cli.bootstrap.initializer,web.runtime

**描述**: FakeGraph test mock is conditionally instantiated in production code path via MSAGENT_FAKE_BACKEND environment variable. If this variable is set in production, all agent requests bypass real processing. Environment variable control without authentication or secure defaults poses a security risk.

**漏洞代码** (`src/msagent/cli/bootstrap/initializer.py:124-138`)

```c
fake_graph = FakeGraph() when MSAGENT_FAKE_BACKEND=true
```

**达成路径**

Environment Variable (MSAGENT_FAKE_BACKEND) -> initializer.create_graph() [line 124] -> FakeGraph() instantiation [line 129] -> Returns mock instead of real graph

**验证说明**: FakeGraph bypass via env var - testing feature, requires env control.

---

### [VULN-CFG-SBX-001] Path Traversal - FilesystemConfig

**严重性**: Low | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/msagent/configs/sandbox.py:50-61` @ `FilesystemConfig`
**模块**: configs

**描述**: Sandbox filesystem paths configured via user input: filesystem.read/write paths in SandboxConfig (sandbox.py:50-57) accept arbitrary path strings without validation. While sandbox execution enforces these rules, malicious path configurations could grant unintended filesystem access or hide sensitive files via hidden patterns.

**漏洞代码** (`src/msagent/configs/sandbox.py:50-61`)

```c
read/write/hidden lists of path strings
```

**达成路径**

SandboxConfig.filesystem -> Sandbox execution layer -> Filesystem access rules

**验证说明**: Sandbox path traversal - sandbox is disabled anyway (VULN-DF-SANDBOXES-001).

---

### [VULN-LOW-CORE-001] Information Exposure - FILE_LOG_FORMAT

**严重性**: Low | **CWE**: CWE-532 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/msagent/core/logging.py:30-31` @ `FILE_LOG_FORMAT`
**模块**: core

**描述**: Logging configuration does not filter sensitive information. FILE_LOG_FORMAT includes full context (filename, line number, message) which could log sensitive data if API keys or credentials are included in logged objects.

**漏洞代码** (`src/msagent/core/logging.py:30-31`)

```c
FILE_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
```

**验证说明**: Logging format could leak secrets - requires sensitive data in logged objects.

---

### [VULN-005] Path Traversal - offload_messages_to_backend

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: python-security-module-scanner

**位置**: `src/msagent/utils/offload.py:64` @ `offload_messages_to_backend`
**模块**: utils

**描述**: Thread_id used in path without sanitization. Path constructed from thread_id without validation, allowing ../ or other path traversal characters to write outside intended location.

**漏洞代码** (`src/msagent/utils/offload.py:64`)

```c
path = f"/conversation_history/{thread_id}.md"
```

**达成路径**

thread_id -> path construction -> backend.aedit/awrite

**验证说明**: thread_id in path - requires control over thread_id generation.

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| agents | 0 | 0 | 2 | 0 | 2 |
| cli | 0 | 1 | 3 | 0 | 4 |
| configs | 0 | 1 | 2 | 4 | 7 |
| core | 0 | 0 | 1 | 2 | 3 |
| cross-module | 0 | 1 | 0 | 0 | 1 |
| llms | 0 | 1 | 3 | 4 | 8 |
| mcp | 0 | 4 | 3 | 0 | 7 |
| middlewares | 0 | 0 | 1 | 1 | 2 |
| testing | 0 | 0 | 0 | 1 | 1 |
| utils | 0 | 0 | 1 | 1 | 2 |
| **合计** | **0** | **8** | **16** | **13** | **37** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 6 | 16.2% |
| CWE-918 | 5 | 13.5% |
| CWE-94 | 3 | 8.1% |
| CWE-693 | 3 | 8.1% |
| CWE-20 | 3 | 8.1% |
| CWE-78 | 2 | 5.4% |
| CWE-74 | 2 | 5.4% |
| CWE-522 | 2 | 5.4% |
| CWE-214 | 2 | 5.4% |
| CWE-15 | 2 | 5.4% |
| CWE-77 | 1 | 2.7% |
| CWE-532 | 1 | 2.7% |
| CWE-436 | 1 | 2.7% |
| CWE-312 | 1 | 2.7% |
| CWE-295 | 1 | 2.7% |
| CWE-256 | 1 | 2.7% |
| CWE-16 | 1 | 2.7% |

---

## 8. 分类统计补充

### 8.1 漏洞状态分析

| 状态 | 数量 | 典型特征 | 建议处理 |
|------|------|----------|----------|
| LIKELY | 20 | 漏洞模式明确，触发条件需验证 | 人工审查代码上下文，确认可达性 |
| POSSIBLE | 17 | 代码模式可疑，实际风险可能较低 | 简单验证后可标记为 FALSE_POSITIVE |

### 8.2 漏洞可达性分析

| 可达性等级 | 数量 | 示例漏洞 | 说明 |
|------------|------|----------|------|
| 配置控制 (trusted_admin) | 12 | SSRF via base_url | 需配置文件写入权限才能触发 |
| 环境变量控制 | 3 | Path traversal via env | 需环境变量控制权限 |
| 网络输入 (untrusted_network) | 5 | MCP tool injection | 外部 MCP server 可触发 |
| 本地输入 (untrusted_local) | 2 | Template injection | CLI 输入可触发 |

### 8.3 模块风险矩阵

| 模块 | High | Medium | Low | 主要风险类型 |
|------|------|--------|-----|--------------|
| mcp | 4 | 3 | 0 | SSRF, 环境注入, 工具加载 |
| llms | 1 | 3 | 4 | SSRF, 证书绕过, 凭证存储 |
| configs | 1 | 2 | 4 | 路径遍历, 配置注入 |
| cli | 1 | 3 | 0 | 凭证暴露, 命令执行 |
| agents | 0 | 2 | 0 | 动态导入, 路径控制 |

### 8.4 依赖关系分析

待确认漏洞与已确认漏洞的依赖关系：

```
已确认: VULN-DF-SANDBOXES-001 (Sandbox Missing)
    ↓ 影响
待确认: VULN-MCP-003 (工具加载无验证) - 无沙箱时风险更高

已确认: VULN-CROSS-001 (Credential Flow Chain)
    ↓ 关联
待确认: VULN-MCP-005 (环境变量注入) - 相同根因

已确认: VULN-DF-LLMS-002 (Cleartext Transmission)
    ↓ 相关
待确认: VULN-DF-LLMS-003 (SSRF via base_url) - 相同攻击向量
```

---

## 9. 验证建议

### 9.1 高优先级验证 (LIKELY High)

#### SSRF 验证 (VULN-DF-MCP-003, VULN-MCP-002, VULN-DF-LLMS-003)

**验证步骤**:
1. 检查网络策略：是否允许连接 127.0.0.1 或 169.254.x.x (AWS metadata)
2. 测试 base_url：设置 `base_url=http://169.254.169.254/latest/meta-data/`
3. 检查 URL 验证：是否存在 host 白名单或 scheme 验证

**预期结果**: 如果有网络隔离或 URL 验证，标记为 FALSE_POSITIVE

#### 环境变量注入验证 (VULN-MCP-005, VULN-DF-MCP-004)

**验证步骤**:
1. 检查配置文件访问控制：config.mcp.json 是否可被非管理员修改
2. 测试环境注入：设置 `env={"LD_PRELOAD": "/tmp/test.so"}` 并执行工具
3. 检查是否有环境变量过滤机制

**预期结果**: 如果配置文件有访问控制，风险降低

### 9.2 中优先级验证 (LIKELY Medium)

#### 模板注入验证 (VULN-DF-CONFIGS-001)

**验证步骤**:
1. 检查 context 来源：`from_json()` 中 context 参数来源
2. 测试模板注入：构造 context 包含恶意对象属性访问
3. 检查是否使用 Jinja2 安全模板替代 str.format

**预期结果**: 如果 context 仅来自可信配置，风险较低

#### 路径遍历验证 (VULN-004, VULN-AGENTS-003)

**验证步骤**:
1. 构造测试路径：`../../../etc/passwd`, `/etc/shadow`
2. 检查路径解析：是否有 realpath 边界检查
3. 测试 symlink 场景：创建指向外部的符号链接

**预期结果**: 如果有路径边界检查，标记为 FALSE_POSITIVE

### 9.3 低优先级验证 (POSSIBLE)

大多数 POSSIBLE 漏洞可通过代码审查快速确认是否为误报：
- 检查触发条件是否在实际使用中可达
- 检查是否有隐式的安全检查
- 评估攻击者获取触发条件的成本
