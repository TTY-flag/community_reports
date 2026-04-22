# VULN-DF-LLMS-001 深度利用分析报告

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞类型** | 敏感数据暴露 (Sensitive Data Exposure) |
| **CWE** | CWE-312: Cleartext Storage of Sensitive Information |
| **严重性** | High |
| **置信度** | 85% |
| **影响范围** | 所有使用 LLM API 的场景 |
| **漏洞文件** | `src/msagent/llms/factory.py:111-115` |

## 漏洞详情

### 技术分析

该漏洞存在于 `LLMFactory.create()` 方法中。API 密钥从 `SecretStr` 类型提取后，以明文字符串形式传递给 `init_chat_model()` 函数的 kwargs 参数，导致原本的保护机制失效。

**漏洞代码位置**:

```python
# src/msagent/llms/factory.py:111-115
if api_key := self._resolve_api_key(cfg, provider):
    kwargs["api_key"] = api_key  # 明文存储在 kwargs dict 中
    provider_api_key = _PROVIDER_API_KEY_KWARG.get(provider)
    if provider_api_key:
        kwargs[provider_api_key] = api_key  # 同样明文存储
```

**API 密钥解析函数** (`src/msagent/llms/factory.py:149-180`):

```python
def _resolve_api_key(self, cfg: LLMConfig, provider: str) -> str | None:
    if cfg.api_key_env:
        from_env = os.getenv(cfg.api_key_env, "").strip()
        if from_env:
            return from_env  # 返回明文字符串

    # ...
    
    value = getattr(self.settings, attr, None)
    if isinstance(value, SecretStr):
        raw = value.get_secret_value().strip()  # 从 SecretStr 提取明文
    elif isinstance(value, str):
        raw = value.strip()
    # ...
    return raw  # 返回明文字符串
```

### 数据流分析

```
LLMConfig.api_key_env (环境变量名)
    ↓
os.getenv() 获取环境变量值
    ↓
_resolve_api_key() 提取 API 密钥
    ↓
SecretStr.get_secret_value() (如果有) → 明文字符串
    ↓
kwargs["api_key"] = api_key (明文存储在 dict)
    ↓
init_chat_model(model_name, **kwargs)
    ↓
langchain ChatModel (可能被记录到日志)
```

### 漏洞原因分析

1. **SecretStr 保护失效**: Pydantic 的 `SecretStr` 类型设计用于隐藏敏感值（在日志、打印、序列化时显示为 `**********`），但通过 `get_secret_value()` 提取后，明文值暴露在 kwargs dict 中

2. **kwargs 可能被记录**: LangChain 的 `init_chat_model()` 函数可能在调试模式下记录 kwargs 参数，导致 API 密钥出现在日志中

3. **异常栈可能泄露**: 如果 `init_chat_model()` 抛出异常，包含 kwargs 的栈信息可能被记录，泄露 API 密钥

## 攻击场景

### 场景 1: 日志文件泄露

**前提条件**:
1. LangChain 库开启了调试日志
2. 或应用本身开启了详细日志
3. 日志文件可被攻击者访问

**攻击路径**:
```python
# 调用链中的日志记录可能导致泄露
import logging
logging.basicConfig(level=logging.DEBUG)

# LLMFactory.create() 调用
factory = LLMFactory(settings=LLMSettings(openai_api_key=SecretStr("sk-xxx")))
model = factory.create(config)

# 日志可能记录：
# DEBUG: init_chat_model called with kwargs: {'api_key': 'sk-xxx', ...}
```

### 场景 2: 异常栈泄露

**前提条件**:
1. `init_chat_model()` 执行失败
2. 异被捕获并记录到日志
3. 或异常信息在 UI 中显示

**攻击路径**:
```python
# 模拟异常场景
try:
    model = factory.create(config)
except Exception as e:
    # 异常栈可能包含 kwargs 参数
    logger.error(f"LLM creation failed: {e}", exc_info=True)
    # 泄露：TypeError: init_chat_model() got unexpected kwargs: {'api_key': 'sk-xxx'}
```

### 场景 3: 调试输出泄露

**前提条件**:
1. 开发者在调试模式下运行
2. 使用 print/pprint 输出 kwargs
3. 或使用调试器查看变量

**攻击路径**:
```python
# 开发调试时可能泄露
kwargs = {..., "api_key": "sk-xxx"}
print(f"Creating model with params: {kwargs}")  # 直接泄露
# 或
import pprint
pprint.pprint(kwargs)  # 泄露
```

## PoC 构造

### 模拟日志泄露场景

```python
# 漏洞演示代码
import logging
from pydantic import SecretStr
from msagent.llms.factory import LLMFactory
from msagent.configs.llm import LLMConfig

# 设置详细日志
logging.basicConfig(level=logging.DEBUG, format='%(message)s')

# 添加日志拦截器来捕获泄露
class SecretInterceptor:
    def __init__(self):
        self.captured_logs = []
    
    def write(self, message):
        if 'sk-' in message or 'api_key' in message.lower():
            self.captured_logs.append(message)
        return len(message)

# 模拟敏感值泄露
config = LLMConfig(
    provider="openai",
    model="gpt-4",
    api_key_env="OPENAI_API_KEY"
)

factory = LLMFactory()
# 当 create() 调用时，kwargs["api_key"] 可能被记录到日志
model = factory.create(config)

# 如果日志记录了 kwargs，API 密钥将被暴露
```

### 模拟异常栈泄露

```python
# 触发异常并观察栈信息
from msagent.llms.factory import LLMFactory
from msagent.configs.llm import LLMConfig

config = LLMConfig(
    provider="invalid_provider",  # 触发异常
    model="test"
)

try:
    factory = LLMFactory()
    model = factory.create(config)
except ValueError as e:
    print(f"Exception: {e}")
    # 异常信息可能包含敏感参数
```

### 检查 kwargs 泄露点

```python
# 检查 LangChain init_chat_model 的日志行为
import langchain
print(f"LangChain debug mode: {langchain.debug}")

# 如果 debug=True，kwargs 可能被记录
langchain.debug = True

from langchain.chat_models import init_chat_model
# init_chat_model 可能记录 kwargs
```

## 影响评估

### 可能后果

| 风险类型 | 描述 | 严重程度 |
|----------|------|----------|
| **API 密钥泄露** | OpenAI/Anthropic API 密钥出现在日志中 | 高 |
| **费用损失** | 泄露的密钥被滥用，导致 API 费用损失 | 高 |
| **服务滥用** | 泄露密钥用于恶意请求 | 高 |
| **数据泄露** | 使用泄露密钥访问历史对话数据 | 中 |
| **凭证暴露** | 多个服务商密钥同时泄露 | 高 |

### 受影响资产

- OpenAI API 密钥
- Anthropic API 密钥
- Google/Gemini API 密钥
- 其他 LLM 服务商凭证
- 可能包含密钥的日志文件
- 异常栈信息
- 调试输出

### 风险场景对比

| 场景 | 泄露途径 | 风险等级 |
|------|----------|----------|
| 生产环境日志 | 应用日志文件 | 中（需有日志访问权限） |
| 调试环境 | 开发者屏幕/终端 | 高（直接可见） |
| CI/CD 日志 | 构建日志文件 | 中 |
| 异常报告 | Sentry/错误追踪服务 | 高（可能上传到第三方） |
| 云日志服务 | AWS CloudWatch/GCP Logging | 高（集中存储） |

## 修复建议

### 1. 保持 SecretStr 保护

```python
# 建议实现：不提取 SecretStr，直接传递
def create(self, config: LLMConfig, ...) -> Any:
    # 不要从 SecretStr 提取明文
    api_key_secret = self._resolve_api_key_secret(cfg, provider)
    
    # 直接传递 SecretStr 对象（如果 langchain 支持）
    if api_key_secret:
        kwargs["api_key"] = api_key_secret  # 保持 SecretStr 类型
    
    # 或者使用闭包保护
    kwargs["api_key"] = lambda: api_key_secret.get_secret_value()
    
    return init_chat_model(model_name, **kwargs)
```

### 2. kwargs 过滤日志

```python
# 匇导实现：在传递 kwargs 前过滤敏感字段
SENSITIVE_KEYS = {'api_key', 'openai_api_key', 'anthropic_api_key', 'google_api_key'}

def _sanitize_kwargs_for_logging(kwargs: dict) -> dict:
    sanitized = {}
    for key, value in kwargs.items():
        if key in SENSITIVE_KEYS:
            sanitized[key] = "**********"
        else:
            sanitized[key] = value
    return sanitized

def create(self, config: LLMConfig, ...) -> Any:
    kwargs = {...}
    
    # 记录过滤后的 kwargs
    logger.debug(f"Creating LLM with params: {_sanitize_kwargs_for_logging(kwargs)}")
    
    return init_chat_model(model_name, **kwargs)
```

### 3. 使用环境变量传递

```python
# 建议实现：不通过 kwargs 传递，使用环境变量
def create(self, config: LLMConfig, ...) -> Any:
    # API 密钥通过环境变量传递，langchain 会自动读取
    # 不需要在 kwargs 中显式设置
    
    # 仅设置非敏感参数
    kwargs = {
        "temperature": cfg.temperature,
        "timeout": ...,
        # 不包含 api_key
    }
    
    # langchain 会从 OPENAI_API_KEY 等环境变量自动读取
    return init_chat_model(model_name, **kwargs)
```

### 4. 异常处理保护

```python
# 建议实现：自定义异常消息，不包含敏感信息
def create(self, config: LLMConfig, ...) -> Any:
    try:
        kwargs = {...}
        return init_chat_model(model_name, **kwargs)
    except Exception as e:
        # 不记录包含敏感信息的异常
        sanitized_error = self._sanitize_exception_message(str(e))
        logger.error(f"LLM creation failed: {sanitized_error}")
        raise ValueError(sanitized_error) from None  # 隐藏原始异常栈
```

### 5. 使用安全的日志库

```python
# 建议实现：使用支持敏感值过滤的日志库
from msagent.core.logging import SecureLogger

logger = SecureLogger(__name__, sensitive_keys=['api_key', 'token', 'secret'])

def create(self, config: LLMConfig, ...) -> Any:
    kwargs = {...}
    # SecureLogger 自动过滤敏感值
    logger.debug("Creating LLM", extra={"kwargs": kwargs})
```

## 相关代码

### LLM 工厂完整创建逻辑

```python
# src/msagent/llms/factory.py:76-139 (核心函数)
def create(
    self,
    config: LLMConfig | None = None,
    *,
    max_retries: int | None = None,
    timeout_seconds: float | None = None,
) -> Any:
    """Create an LLM model from config."""
    cfg = config or self.default_llm
    if cfg is None:
        raise ValueError("No LLM config provided")

    provider = self._normalize_provider(cfg.provider.value)
    model_name = f"{provider}:{cfg.model}"

    kwargs: dict[str, Any] = dict(cfg.params or {})
    kwargs.update(
        {
            "temperature": cfg.temperature,
            "timeout": float(cfg.request_timeout_seconds if timeout_seconds is None else timeout_seconds),
        }
    )
    # ... 其他参数设置

    # 漏洞点：API 密钥以明文存储在 kwargs
    if api_key := self._resolve_api_key(cfg, provider):
        kwargs["api_key"] = api_key
        provider_api_key = _PROVIDER_API_KEY_KWARG.get(provider)
        if provider_api_key:
            kwargs[provider_api_key] = api_key

    # ... OpenAI 特殊处理

    return init_chat_model(model_name, **kwargs)
```

### API 密钥解析函数

```python
# src/msagent/llms/factory.py:149-180
def _resolve_api_key(self, cfg: LLMConfig, provider: str) -> str | None:
    if cfg.api_key_env:
        from_env = os.getenv(cfg.api_key_env, "").strip()
        if from_env:
            return from_env  # 返回明文

    default_env = _DEFAULT_PROVIDER_API_KEY_ENV.get(provider)
    if default_env:
        from_env = os.getenv(default_env, "").strip()
        if from_env:
            return from_env  # 返回明文

    if self.settings is None:
        return None

    attr = _SETTINGS_API_KEY_ATTR.get(provider)
    if not attr:
        return None

    value = getattr(self.settings, attr, None)
    if isinstance(value, SecretStr):
        raw = value.get_secret_value().strip()  # SecretStr 保护失效
    elif isinstance(value, str):
        raw = value.strip()
    else:
        return None

    if not raw:
        return None
    if raw.lower() == "dummy":
        return None
    return raw  # 返回明文
```

## 参考资料

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [Pydantic SecretStr Documentation](https://docs.pydantic.dev/latest/api/types/#pydantic.types.SecretStr)
- [LangChain Security Best Practices](https://python.langchain.com/docs/security)

## 结论

该漏洞导致 API 密钥的保护机制失效。虽然使用了 `SecretStr` 类型存储密钥，但在传递给 LangChain 时，明文值被暴露在 kwargs dict 中，可能被记录到日志或出现在异常栈中。

**严重性评估**: High

**关键风险点**:
1. SecretStr 的 `get_secret_value()` 破坏了保护机制
2. kwargs dict 可能被日志库记录
3. 异常栈可能包含 kwargs 参数

**建议优先级**: 高优先级修复

**修复方向**:
- 避免在 kwargs 中直接存储明文密钥
- 使用环境变量机制让 LangChain 自动读取
- 实现日志敏感值过滤