# msAgent (mindstudio-agent) 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析未使用 `threat.md` 约束文件，AI 自主识别所有潜在攻击面和高风险模块。

## 1. 项目架构概览

### 1.1 项目定位

**msAgent (mindstudio-agent)** 是一个面向 Ascend NPU 场景的一站式调试调优 AI Agent 框架，类似于 LangChain/LangGraph 的应用框架。

- **项目类型**: Python CLI 工具 + Web 应用
- **主要功能**: 
  - CLI 交互式会话（支持 `/` 命令和快捷键）
  - Web UI 模式（通过 LangGraph API 服务器）
  - MCP (Model Context Protocol) 工具服务器集成
  - 内置 Agent（Hermes/Minos/Accuracy/Zephyr）用于不同场景
  - Skills 扩展机制
- **源文件数**: 114 个 Python 文件（src/msagent）
- **代码行数**: 约 8,749 行

### 1.2 核心架构组件

| 层级 | 模块 | 功能 | 风险等级 |
|------|------|------|----------|
| 入口层 | cli/bootstrap | CLI 参数解析和会话启动 | Medium |
| 入口层 | web/launcher | Web API 服务器启动 | High |
| 工具层 | mcp/client | MCP 工具服务器客户端 | Critical |
| 工具层 | tools/web_search | Web 搜索工具 | High |
| 工具层 | tools/factory | 工具创建和包装 | Medium |
| 执行层 | utils/bash | Bash 命令执行 | Critical |
| 执行层 | sandboxes | 沙箱后端（deepagents） | Low |
| 配置层 | configs/ | 配置文件加载（LLM/MCP/Agent/Sandbox） | Medium |
| Agent层 | agents/factory | Agent 图创建 | High |
| LLM层 | llms/factory | LLM 客户端创建 | High |

### 1.3 信任边界模型

```
┌─────────────────────────────────────────────────────────────────────┐
│                          msAgent Application                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │   CLI/UI    │  │   Agent     │  │   Tools     │  │   Configs   │ │
│  │   Layer     │  │   Factory   │  │   Layer     │  │   Layer     │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
│         │                │                │                │         │
│         ▼                ▼                ▼                ▼         │
├─────────────────────────────────────────────────────────────────────┤
│                        Trust Boundaries                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  [1] CLI User Input ────────────► Local user (untrusted_local)      │
│  [2] Web API (127.0.0.1:2024) ──► HTTP clients (semi_trusted)       │
│  [3] MCP Tool Servers ─────────► External servers (untrusted_net)   │
│  [4] LLM API Providers ────────► OpenAI/Anthropic/Google (net)      │
│  [5] Web Search APIs ──────────► DuckDuckGo/Tavily (untrusted_net)  │
│  [6] Config Files ─────────────► User-provided YAML/JSON (trusted)  │
│  [7] Skills Files ─────────────► SKILL.md files (trusted_admin)     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## 2. 模块风险评估

### 2.1 Critical 风险模块

| 模块 | 文件 | 风险因素 | STRIDE 威胁 |
|------|------|----------|-------------|
| MCP Client | mcp/client.py | 从外部服务器加载工具，支持多种传输协议（stdio/sse/http/websocket） | S, T, E |
| MCP Factory | mcp/factory.py | 创建 MCP 客户端，配置外部服务器连接 | S, T, E |
| Bash Executor | utils/bash.py | 使用 subprocess 执行任意 shell 命令 | T, D, E |
| Bash Handler | cli/handlers/bash.py | 接收用户命令并调用 bash executor | T, D, E |

### 2.2 High 风险模块

| 模块 | 文件 | 风险因素 | STRIDE 威胁 |
|------|------|----------|-------------|
| Web Launcher | web/launcher.py | 启动 LangGraph API 和 UI 服务器，使用 subprocess | T, D |
| Web Search | tools/web_search.py | 发送 HTTP 请求到外部搜索 API | T, I |
| Agent Factory | agents/factory.py | 创建 Agent 图，集成 MCP 工具和 LLM | S, T, E |
| Initializer | cli/bootstrap/initializer.py | 加载所有配置，创建 Agent 运行环境 | T, E |
| MCP Config | configs/mcp.py | 定义外部 MCP 服务器连接配置 | S, T |
| LLM Factory | llms/factory.py | 创建 LLM 客户端，发送 API 请求 | T, I |

### 2.3 Medium 风险模块

| 模块 | 文件 | 风险因素 | STRIDE 威胁 |
|------|------|----------|-------------|
| Skills Factory | skills/factory.py | 加载 SKILL.md 文件，解析 YAML frontmatter | T |
| Tools Factory | tools/factory.py | 包装工具调用，添加超时控制 | T |
| File Resolver | cli/resolvers/file.py | 执行 shell 命令列出文件 | T |
| Config Registry | configs/registry.py | 加载所有配置文件 | T |
| Agent Config | configs/agent.py | Agent 配置定义 | T |
| LLM Config | configs/llm.py | LLM 配置定义 | T |
| Approval Config | configs/approval.py | 工具审批规则定义 | T |
| Sandbox Config | configs/sandbox.py | 沙箱配置定义 | T |
| Skills Catalog | tools/catalog/skills.py | Skills 列表和读取 | T, I |

## 3. 攻击面分析

### 3.1 CLI 入口攻击面

| 入口点 | 文件位置 | 数据流 | 攻击向量 |
|--------|----------|--------|----------|
| 命令行参数 | run.py:30 → legacy.py:47 | sys.argv → argparse | 参数注入、路径遍历 |
| Bash 模式 | handlers/bash.py:17 | stdin → subprocess | 命令注入（有意设计） |
| 交互式输入 | dispatchers/messages.py | stdin → LLM | Prompt injection |

**防护措施**:
- Bash 命令执行有审批机制（middlewares/approval.py）
- 文件补全使用 shlex.quote 处理用户输入

### 3.2 Web API 攻击面

| 入口点 | 文件位置 | 数据流 | 攻击向量 |
|--------|----------|--------|----------|
| LangGraph API | launcher.py:172 | HTTP request → LangGraph server | SSRF、API abuse |
| Web UI | launcher.py:300 | HTTP request → Next.js frontend | XSS、CSRF |

**防护措施**:
- 默认绑定 127.0.0.1（仅本地可达）
- 使用 LangGraph 官方服务器实现

### 3.3 MCP 工具攻击面

| 入口点 | 文件位置 | 传输类型 | 攻击向量 |
|--------|----------|----------|----------|
| STDIO MCP | mcp/client.py:131 | stdin/stdout | 命令注入、工具滥用 |
| SSE MCP | mcp/client.py:143 | HTTP SSE | SSRF、数据泄露 |
| HTTP MCP | mcp/client.py:155 | HTTP streaming | SSRF、MITM |
| WebSocket MCP | mcp/client.py:167 | WebSocket | SSRF、协议注入 |

**风险分析**:
- MCP 配置允许执行任意命令（`command` 字段）
- HTTP/WebSocket 传输无法沙箱化
- 工具返回数据直接传递给 LLM（可能触发 Prompt injection）

### 3.4 配置文件攻击面

| 入口点 | 文件位置 | 文件类型 | 攻击向量 |
|--------|----------|----------|----------|
| MCP 配置 | configs/mcp.py:92 | JSON | YAML/JSON 注入 |
| LLM 配置 | configs/llm.py:131 | YAML | YAML 注入 |
| Agent 配置 | configs/agent.py:510 | YAML | YAML 注入 |
| Sandbox 配置 | configs/sandbox.py:143 | YAML | YAML 注入 |

**防护措施**:
- 使用 yaml.safe_load（安全解析）
- Pydantic 模型验证

### 3.5 Skills 文件攻击面

| 入口点 | 文件位置 | 文件类型 | 攻击向量 |
|--------|----------|----------|----------|
| SKILL.md 加载 | skills/factory.py:113 | Markdown + YAML | YAML frontmatter 注入 |
| Skills 脚本执行 | skills/*/scripts/*.py | Python | 代码执行 |

**风险分析**:
- Skills 目录中的 Python 脚本可被 Agent 执行
- SKILL.md 文件包含指导内容，可能影响 Agent 行为

### 3.6 外部 API 攻击面

| 入口点 | 文件位置 | API 目标 | 攻击向量 |
|--------|----------|----------|----------|
| Web Search | tools/web_search.py:122 | DuckDuckGo/Tavily | SSRF、数据泄露 |
| LLM API | llms/factory.py:20 | OpenAI/Anthropic/Google | API key 泄露、数据泄露 |

## 4. STRIDE 威胁建模

### 4.1 Spoofing (欺骗)

| 威胁 | 模块 | 描述 | 风险等级 |
|------|------|------|----------|
| MCP 服务器伪造 | mcp/client.py | 恶意 MCP 服务器可能伪装为合法工具提供者 | High |
| LLM API 响应伪造 | llms/factory.py | MITM 攻击可能篡改 LLM API 响应 | Medium |
| Skills 内容伪造 | skills/factory.py | 恶意 SKILL.md 可能注入虚假指导内容 | Low |

### 4.2 Tampering (篡改)

| 威胁 | 模块 | 描述 | 风险等级 |
|------|------|------|----------|
| 配置文件篡改 | configs/ | 本地攻击者可能修改配置文件 | Medium |
| MCP 工具输出篡改 | mcp/client.py | 外部 MCP 服务器可能返回篡改的数据 | High |
| Bash 命令注入 | utils/bash.py | 用户输入直接传递给 bash -c（有意设计） | High |

### 4.3 Repudiation (抵赖)

| 威胁 | 模块 | 描述 | 风险等级 |
|------|------|------|----------|
| 工具调用无审计日志 | tools/factory.py | 工具调用可能缺乏详细的审计日志 | Low |
| MCP 工具调用追踪 | mcp/client.py | MCP 工具调用来源难以追溯 | Medium |

### 4.4 Information Disclosure (信息泄露)

| 威胁 | 模块 | 描述 | 风险等级 |
|------|------|------|----------|
| API Key 泄露 | core/settings.py | LLM API Key 存储在环境变量/.env | High |
| 配置内容泄露 | configs/ | 配置文件可能包含敏感信息 | Medium |
| Web 搜索查询泄露 | tools/web_search.py | 搜索关键词发送到外部服务 | Medium |
| MCP 工具数据泄露 | mcp/client.py | MCP 服务器可能泄露用户数据 | High |

### 4.5 Denial of Service (拒绝服务)

| 娃胁 | 模块 | 描述 | 风险等级 |
|------|------|------|----------|
| LLM API 超时 | configs/llm.py:71 | LLM 请求超时可能导致阻塞 | Medium |
| MCP 工具超时 | configs/mcp.py:70 | MCP 工具超时可能影响 Agent 执行 | Medium |
| Bash 命令无限循环 | utils/bash.py | 恶意命令可能耗尽资源 | Medium |
| Web 服务器资源耗尽 | web/launcher.py | 大量 HTTP 请求可能耗尽服务器资源 | Low |

### 4.6 Elevation of Privilege (权限提升)

| 威胁 | 模块 | 描述 | 风险等级 |
|------|------|------|----------|
| MCP STDIO 命令执行 | mcp/client.py:131 | MCP 配置允许执行任意命令 | Critical |
| Bash 模式命令执行 | handlers/bash.py | 用户可直接执行任意 shell 命令 | High |
| Skills 脚本执行 | skills/*/scripts/ | Skills Python 脚本可被执行 | Medium |
| Sandbox 绕过 | sandboxes/__init__.py | HTTP MCP 传输无法沙箱化 | High |

## 5. 安全加固建议（架构层面）

### 5.1 MCP 工具安全加固

1. **强制审批机制**: 所有 MCP 工具调用应经过 HIL（Human-in-the-loop）审批
   - 当前实现: configs/approval.py 提供审批规则配置
   - 建议: 默认启用 MCP 工具审批，而非仅在配置中指定

2. **传输协议限制**: 限制 STDIO 传输为唯一可信传输方式
   - HTTP/WebSocket/SSE 传输无法沙箱化，应作为可选而非默认

3. **工具白名单**: 默认启用工具白名单模式
   - 当前实现: configs/mcp.py 的 `include`/`exclude` 字段
   - 建议: 默认 `include` 为空，必须显式配置允许的工具

### 5.2 Bash 执行安全加固

1. **命令审批**: 已有实现（approval.py），建议默认启用
2. **命令沙箱**: 建议在 Linux 上使用 bubblewrap 沙箱化 bash 执行
   - 当前实现: configs/sandbox.py 定义沙箱配置
   - 建议: 默认启用沙箱，限制文件系统和网络访问

### 5.3 配置文件安全加固

1. **配置签名**: 对配置文件进行签名验证
2. **敏感数据加密**: API Key 应加密存储而非明文环境变量
3. **配置审计**: 记录配置文件变更日志

### 5.4 Web API 安全加固

1. **认证机制**: Web API 应添加认证（当前无认证）
2. **速率限制**: 添加 API 调用速率限制
3. **HTTPS 支持**: 默认启用 HTTPS（当前仅 HTTP）

### 5.5 Skills 安全加固

1. **Skills 签名**: 对 Skills 目录进行签名验证
2. **脚本审查**: Skills Python 脚本应经过安全审查
3. **执行沙箱**: Skills 脚本应在沙箱中执行

## 6. 漏洞扫描优先级

根据风险评级和攻击面分析，建议漏洞扫描按以下优先级执行：

### 优先级 1 (Critical)
- mcp/client.py: MCP 工具加载和连接建立
- utils/bash.py: Bash 命令执行
- cli/handlers/bash.py: Bash 命令处理入口

### 优先级 2 (High)
- web/launcher.py: Web 服务器启动和进程管理
- tools/web_search.py: Web 搜索 HTTP 请求
- agents/factory.py: Agent 创建和工具集成
- configs/mcp.py: MCP 配置解析

### 优先级 3 (Medium)
- skills/factory.py: Skills 加载
- cli/resolvers/file.py: 文件补全命令执行
- configs/registry.py: 配置加载聚合
- tools/catalog/skills.py: Skills 内容读取

---

**报告生成时间**: 2026-04-21
**分析工具**: Architecture Agent (Python taint tracking mode)