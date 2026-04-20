# 漏洞扫描报告 — 已确认漏洞

**项目**: MindInferenceService
**扫描时间**: 2026-04-20T00:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 12 | 46.2% |
| POSSIBLE | 10 | 38.5% |
| LIKELY | 4 | 15.4% |
| **总计** | **26** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 12 | - |

### 1.3 Top 10 关键漏洞


---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `create_chat_completions@mis/llm/entrypoints/openai/api_server.py` | web_route | untrusted_network | POST /openai/v1/chat/completions 是公开的 HTTP API 入口，接收外部客户端的聊天请求，请求体包含用户可控的 messages、model、temperature 等参数。 | OpenAI 兼容的聊天补全 API 入口 |
| `show_available_models@mis/llm/entrypoints/openai/api_server.py` | web_route | untrusted_network | GET /openai/v1/models 是公开的 HTTP API 入口，允许外部客户端查询可用模型列表，无需认证即可访问。 | 模型列表查询 API 入口 |
| `_config_yaml_file_loading@mis/llm/engines/config_parser.py` | file | trusted_admin | YAML 配置文件由管理员通过 MIS_CONFIG 环境变量指定，配置路径和内容受管理员控制，需确保路径权限验证（已实现 640 权限检查）。 | 引擎配置 YAML 文件加载入口 |
| `environment_variables@mis/envs.py` | env | trusted_admin | 环境变量由部署脚本或 systemd 注入，包括 MIS_MODEL、MIS_CONFIG、MIS_PORT 等关键配置，管理员负责设置正确值。 | 环境变量配置入口 |
| `restrict_host_middleware@mis/llm/entrypoints/launcher.py` | web_route | semi_trusted | Host 头验证中间件，限制请求只能来自 MIS_HOST 配置的主机，默认 127.0.0.1，可被管理员配置为其他地址。 | Host 头验证中间件 |

**其他攻击面**:
- HTTP API: POST /openai/v1/chat/completions - 接收聊天请求，messages 字段完全可控
- HTTP API: GET /openai/v1/models - 模型列表查询
- YAML Configuration Loading: configs/llm/*.yaml - 配置文件解析
- Environment Variables: MIS_* 系列环境变量
- Request Body Size: max 50MB 限制
- Request Headers: max 8KB 限制
- Rate Limiting: 60 requests/minute 默认限制
- Concurrent Requests: max 512 并发限制

---

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
