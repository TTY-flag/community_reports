# 漏洞扫描报告 — MindIE-SD 已确认漏洞

**项目**: MindIE-SD (Mind Inference Engine for Stable Diffusion)
**项目描述**: 针对华为 Ascend 硬件优化的 Stable Diffusion 模型推理引擎
**版本**: 2.3.0
**厂商**: Huawei Technologies Co., Ltd.
**扫描时间**: 2026-04-17T08:33:48.809Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞（置信度 ≥ 80）

---

## 执行摘要

本次安全扫描在 MindIE-SD 项目的 HTTP 服务示例代码中发现了 **2 个已确认的高危漏洞**，均为路径遍历漏洞（CWE-22）。这些漏洞存在于 `examples/service` 模块中，该模块提供了一个基于 FastAPI 和 Ray 的分布式视频生成推理服务。

### 核心风险

**攻击向量**：服务绑定在 `0.0.0.0:6000`，无任何身份认证机制。攻击者可直接访问服务，通过 HTTP POST 请求控制文件读写路径。

**漏洞组合效应**：两个漏洞可组合利用形成完整攻击链：
1. **任意文件读取 (VULN-DF-PY-001)**：通过 `image` 参数读取敏感文件（如 `/etc/passwd`、SSH 密钥、环境变量）
2. **任意文件写入 (VULN-DF-PY-002)**：通过 `save_disk_path` 参数写入任意位置（可部署后门、覆盖系统文件）

### 潜在影响

| 影响类型 | 严重性 | 说明 |
|---------|--------|------|
| **信息泄露** | 高 | 读取凭证、密钥、配置文件等敏感数据 |
| **权限提升** | 高 | 写入 cron 任务、SSH authorized_keys 实现持久化 |
| **远程代码执行** | 中 | 通过写入脚本/配置文件间接执行代码 |
| **拒绝服务** | 高 | 覆盖关键系统文件、磁盘填充攻击 |
| **数据完整性破坏** | 高 | 模型文件、配置文件篡改 |

### 建议措施（优先级 P0）

1. **立即修复路径验证**：在 `worker.py` 中添加路径白名单验证，禁止路径遍历
2. **添加认证机制**：为 HTTP 服务添加 API Token 或其他身份认证
3. **限制网络绑定**：生产环境绑定 `127.0.0.1` 而非 `0.0.0.0`
4. **使用现有安全工具**：项目已有 `mindiesd/utils/file_utils.py` 安全工具但未被使用

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 5 | 55.6% |
| POSSIBLE | 2 | 22.2% |
| CONFIRMED | 2 | 22.2% |
| **总计** | **9** | 100% |

### 1.2 严重性分布（已确认漏洞）

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 2 | 100.0% |
| **有效漏洞总计** | **2** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 关键漏洞列表

| ID | 类型 | 严重性 | 文件 | 函数 | 置信度 |
|-----|------|--------|------|------|--------|
| VULN-DF-PY-001 | path_traversal | High | `examples/service/worker.py:140` | `generate` | 85 |
| VULN-DF-PY-002 | path_traversal | High | `examples/service/worker.py:195` | `generate` | 85 |

---

## 2. 攻击面分析

### 主要攻击入口

| 类型 | 位置 | 绑定/暴露 | 风险 | 说明 |
|------|------|----------|------|------|
| **HTTP API** | `examples/service/server.py` | `0.0.0.0:6000` | Critical | 无认证，用户控制文件路径 |
| **IPC 网络** | `mindiesd/share_memory.py` | ZMQ TCP | High | 可配置网络绑定，无认证 |
| **动态库加载** | `csrc/plugin/find_op_path.cpp` | 环境变量 | Medium | dlopen 加载可配置路径 |

### HTTP 服务攻击面详情

```
入口: HTTP POST /generate
绑定: 0.0.0.0:6000（公网可达）
认证: 无
请求模型: GeneratorRequest (Pydantic)
用户可控字段:
  - prompt: 文本生成提示词（可能用于日志注入）
  - image: 输入图片路径（任意文件读取）
  - save_disk_path: 输出视频路径（任意文件写入）
  - ckpt_dir: 模型加载路径（可能加载恶意模型）
```

### 信任边界

| 边界 | 可信侧 | 不可信侧 | 风险 |
|------|--------|---------|------|
| Network Interface | 应用逻辑 | 远程 HTTP 客户端 | Critical |
| IPC Socket | 本地进程 | 网络可达客户端（配置后） | High |
| Environment | 系统配置 | 环境变量（部署环境决定） | Medium |

---

## 3. High 漏洞详情

### [VULN-DF-PY-001] 任意文件读取漏洞

**基本信息**

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-PY-001 |
| **类型** | Path Traversal (Read) |
| **CWE** | CWE-22: Improper Limitation of a Pathname |
| **严重性** | High |
| **置信度** | 85/100 |
| **状态** | CONFIRMED |
| **位置** | `examples/service/worker.py:140-141` |
| **函数** | `generate()` |
| **模块** | examples/service |

#### 漏洞描述

HTTP 请求中的 `image` 字段直接传入 `Image.open()` 函数，无任何路径验证或清洗。攻击者可使用路径遍历序列（`../`）或绝对路径读取服务器上的任意文件。

#### 漏洞代码

```python
# examples/service/worker.py:139-141
if request.image is not None:
    img = Image.open(request.image).convert("RGB")
    logging.info(f"Input image: {request.image}")
```

#### 数据流路径

```
HTTP POST /generate
  → GeneratorRequest.image (Pydantic Optional[str])
  → worker.py:generate()
  → Image.open(request.image) [SINK]
```

#### 攻击场景

**场景 1: 敏感文件读取**

```bash
curl -X POST http://target:6000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt":"test","sample_steps":40,"task":"i2v-A14B","image":"../../../etc/passwd"}'
```

**场景 2: SSH 密钥提取**

```json
{"image": "/root/.ssh/id_rsa"}
```

**场景 3: 环境变量泄露**

```json
{"image": "/proc/self/environ"}
```

#### 影响评估

| 影响类型 | 严重性 | 说明 |
|---------|--------|------|
| 信息泄露 | High | 读取凭证、密钥、配置等敏感数据 |
| 权限提升 | Medium | SSH 密钥泄露可导致后续入侵 |
| 系统枚举 | High | `/proc/*` 文件系统可进行详细侦察 |

#### 根本原因分析

1. **缺失输入验证**：Pydantic 模型仅验证类型（Optional[str]），未验证内容
2. **直接使用文件 API**：`Image.open()` 未经过安全封装
3. **已有安全工具未使用**：项目有 `mindiesd/utils/file_utils.py` 的安全工具但未被调用

#### 验证说明

HTTP请求中的 image 字段直接传入 Image.open()，无路径验证。攻击者可通过路径遍历读取任意文件（如 ../../../etc/passwd）。调用链完整：HTTP request → GeneratorRequest.image → Image.open()。这是完整的 Ray 分布式视频生成服务，非示例代码。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0 = **85**

---

### [VULN-DF-PY-002] 任意文件写入漏洞

**基本信息**

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-PY-002 |
| **类型** | Path Traversal (Write) |
| **CWE** | CWE-22: Improper Limitation of a Pathname |
| **严重性** | High |
| **置信度** | 85/100 |
| **状态** | CONFIRMED |
| **位置** | `examples/service/worker.py:195-201` |
| **函数** | `generate()` |
| **模块** | examples/service |

#### 漏洞描述

HTTP 请求中的 `save_disk_path` 字段直接传入 `save_video()` 函数，无任何路径验证或清洗。攻击者可写入任意位置文件，可能覆盖关键系统文件或部署后门。

#### 漏洞代码

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

#### 数据流路径

```
HTTP POST /generate
  → GeneratorRequest.save_disk_path (Pydantic Optional[str])
  → worker.py:generate()
  → save_video(save_file=request.save_disk_path) [SINK]
```

#### 攻击场景

**场景 1: Cron 任务注入（持久化后门）**

```json
{
  "prompt": "malicious",
  "sample_steps": 40,
  "save_disk_path": "/etc/cron.d/malicious_job"
}
```

影响：写入 cron 任务，实现命令执行的持久化后门。

**场景 2: SSH Authorized Keys 写入**

```json
{
  "save_disk_path": "/root/.ssh/authorized_keys.mp4"
}
```

影响：虽然扩展名为 .mp4，但可配合其他漏洞或配置缺陷实现利用。

**场景 3: 磁盘填充攻击（拒绝服务）**

攻击者可利用 Ray 分布式执行特性，同时触发 8 个 worker 写入大文件，快速耗尽磁盘空间。

#### 影响评估

| 影响类型 | 严重性 | 说明 |
|---------|--------|------|
| 文件系统破坏 | Critical | 覆盖系统文件、后门部署 |
| 权限提升 | High | Cron/SSH 配置可导致 root 访问 |
| 拒绝服务 | High | 磁盘耗尽、关键文件损坏 |
| 数据完整性 | High | 模型/配置文件篡改 |
| 远程代码执行 | Medium | 通过 cron/web shell 间接实现 |

#### Ray 分布式攻击放大效应

服务使用 Ray 进行分布式视频生成：

```python
# 默认 8 个 worker
self.workers = [
    GeneratorWorker.remote(args, rank=rank, world_size=world_size)
    for rank in range(num_workers)
]
```

单次请求可触发多 worker 并行写入，攻击放大效应显著。

#### 根本原因分析

1. **缺失路径验证**：无白名单、无路径遍历检测
2. **用户控制输出路径**：攻击者决定文件写入位置和内容
3. **Ray 放大效应**：分布式执行增加攻击效率
4. **已有安全工具未使用**：`mindiesd/utils/file_utils.py` 未被调用

#### 验证说明

HTTP请求中的 save_disk_path 字段直接传入 save_video()，无路径验证。攻击者可通过路径遍历写入任意位置文件，可能导致覆盖关键系统文件或写入恶意内容。调用链完整且无缓解措施。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0 = **85**

---

## 4. 组合攻击链分析

### 攻击链: 信息窃取 → 持久化后门

```
Step 1: 利用 VULN-DF-PY-001 读取敏感信息
  → 读取 /proc/self/environ 获取环境变量中的凭证
  → 读取 /etc/passwd 枚举系统用户
  → 读取应用配置文件获取内部信息

Step 2: 利用 VULN-DF-PY-002 部署后门
  → 写入 /etc/cron.d/persistence 实现持久化
  → 或写入 web 目录实现远程命令执行

结果: 完整的系统入侵链
```

### 组合利用示例

```bash
# 单次请求组合利用
curl -X POST http://target:6000/generate \
  -H "Content-Type: application/json" \
  -d '{
    "image": "/proc/self/environ",
    "save_disk_path": "/tmp/backdoor.mp4",
    "prompt": "exploit"
  }'
```

---

## 5. 修复建议

### 优先级 P0: 立即修复

#### 5.1 路径白名单验证

```python
# worker.py - 添加路径验证函数
import os
from pathlib import Path

ALLOWED_IMAGE_DIR = "/data/images"
ALLOWED_OUTPUT_DIR = "/data/output"

def validate_image_path(image_path: str) -> str:
    """验证图片路径在允许目录内"""
    if not image_path:
        raise ValueError("Image path cannot be empty")
    
    abs_path = os.path.realpath(image_path)
    allowed_dir = os.path.realpath(ALLOWED_IMAGE_DIR)
    
    if not abs_path.startswith(allowed_dir + "/"):
        raise ValueError(f"Image path must be within {ALLOWED_IMAGE_DIR}")
    
    if os.path.islink(image_path):
        raise ValueError("Symbolic links are not allowed")
    
    allowed_extensions = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}
    if Path(abs_path).suffix.lower() not in allowed_extensions:
        raise ValueError(f"Invalid image extension")
    
    return abs_path

def validate_output_path(output_path: str) -> str:
    """验证输出路径在允许目录内"""
    if output_path is None:
        return None
    
    abs_path = os.path.realpath(output_path)
    allowed_dir = os.path.realpath(ALLOWED_OUTPUT_DIR)
    
    if not abs_path.startswith(allowed_dir + "/"):
        raise ValueError(f"Output path must be within {ALLOWED_OUTPUT_DIR}")
    
    if os.path.islink(output_path):
        raise ValueError("Symbolic links are not allowed")
    
    if Path(abs_path).suffix.lower() != ".mp4":
        raise ValueError("Output must be .mp4 file")
    
    return abs_path

# 使用验证函数
if request.image is not None:
    safe_path = validate_image_path(request.image)
    img = Image.open(safe_path).convert("RGB")

if request.save_disk_path is not None:
    request.save_disk_path = validate_output_path(request.save_disk_path)
```

#### 5.2 使用项目已有安全工具

```python
from mindiesd.utils.file_utils import standardize_path, check_file_safety

# 验证图片路径
safe_path = standardize_path(request.image, check_link=True)
check_file_safety(safe_path, permission_mode=0o640)
img = Image.open(safe_path).convert("RGB")
```

#### 5.3 添加 HTTP 认证

```python
# server.py - 添加认证中间件
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os

security = HTTPBearer()

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """验证 API Token"""
    valid_tokens = os.environ.get("API_TOKENS", "").split(",")
    if credentials.credentials not in valid_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    return credentials

@app.post("/generate")
async def generate_video(
    request: GeneratorRequest,
    _: HTTPAuthorizationCredentials = Depends(verify_token)
):
    # ... 业务逻辑
```

#### 5.4 限制网络绑定

```python
# server.py - 修改绑定地址
# 生产环境绑定 localhost
uvicorn.run(app, host="127.0.0.1", port=6000)

# 或通过环境变量控制
host = os.environ.get("SERVICE_HOST", "127.0.0.1")
uvicorn.run(app, host=host, port=6000)
```

#### 5.5 速率限制（防止磁盘填充）

```python
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter

@app.post("/generate", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def generate_video(request: GeneratorRequest):
    # 限制: 每个 IP 每分钟最多 5 次请求
```

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| examples/service | 0 | 2 | 0 | 0 | 2 |
| **合计** | **0** | **2** | **0** | **0** | **2** |

---

## 7. CWE 分布

| CWE | 数量 | 占比 | 说明 |
|-----|------|------|------|
| CWE-22 | 2 | 100.0% | 路径遍历漏洞 |

---

## 8. 参考资料

- [CWE-22: Improper Limitation of a Pathname](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

## 9. 深度分析报告

已为两个已确认漏洞生成详细的深度分析报告：

- **VULN-DF-PY-001 深度分析**: `details/VULN-DF-PY-001.md`
  - 包含完整的利用分析、PoC 代码、根本原因分析和修复方案

- **VULN-DF-PY-002 深度分析**: `details/VULN-DF-PY-002.md`
  - 包含完整的利用分析、组合攻击链分析、修复方案和测试建议

---

**报告生成时间**: 2026-04-17T08:33:48.809Z
**扫描系统**: OpenCode 多 Agent 漏洞扫描系统