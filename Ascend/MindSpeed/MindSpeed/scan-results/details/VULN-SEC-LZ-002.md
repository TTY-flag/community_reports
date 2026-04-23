# VULN-SEC-LZ-002：LayerZero ShardStateDict torch.load无保护致Pickle RCE

## 概要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-LZ-002 |
| **CWE** | CWE-502：不可信数据反序列化 |
| **严重性** | High |
| **CVSS评分** | 7.8 (High) |
| **状态** | 已确认 |
| **文件** | `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py` |
| **行号** | 55 |
| **函数** | `ShardStateDict._init_metadata` |

## 漏洞描述

`ShardStateDict._init_metadata` 方法使用 `torch.load()` 反序列化 checkpoint 文件而无适当的安全验证。`filename` 参数来源于仅验证文件名前缀的文件系统遍历，允许恶意文件被加载和反序列化。

### 漏洞代码

```python
# 第 50-55 行
class ShardStateDict:
    def __init__(self, filename) -> None:
        self.filename = filename
        self._init_metadata()

    def _init_metadata(self):
        state_dict = torch.load(self.filename, map_location='cpu')  # 漏洞点
```

### 不充分的缓解措施（文件前缀过滤）

```python
# 第 141-147 行
def _get_files_by_key(self, ckpt_dir, key):
    file_list = []
    for root, _, files in os.walk(ckpt_dir):
        for file in files:
            if file.startswith(key):  # 仅检查文件名前缀！
                file_list.append(os.path.join(root, file))
    return file_list
```

## 攻击向量分析

### 数据流

```
用户输入 (ckpt_dir)
    ↓
LayerzeroCheckpoint.__init__(ckpt_dir)
    ↓
_get_files_by_key(ckpt_dir, 'model_')  ← 前缀过滤（不充分）
    ↓
file_list = [以 "model_" 开头的文件]
    ↓
ShardStateDict(filename)
    ↓
torch.load(self.filename, map_location='cpu')  ← 任意反序列化
```

### 攻击场景

1. **初始访问**：攻击者通过以下方式获得 checkpoint 目录写入权限：
   - 被入侵的共享文件系统
   - 内部威胁
   - checkpoint 分发的供应链攻击
   - 其他组件的路径遍历

2. **Payload 放置**：攻击者创建恶意 pickle 文件：
   ```python
   import torch
   import pickle
   import os
   
   class Exploit:
       def __reduce__(self):
           return (os.system, ('id > /tmp/pwned',))
   
   # 保存为 model_malicious.pt
   torch.save({'exploit': Exploit()}, 'model_malicious.pt')
   ```

3. **触发**：应用加载 checkpoint：
   ```python
   checkpoint = LayerzeroCheckpoint("/path/to/compromised/dir")
   # torch.load 时执行任意代码
   ```

## 风险证据

### 1. 官方安全确认

来自 `docs/zh/SECURITYNOTE.md` (第 54 行)：
> MindSpeed在运行中可能会调用torch.load函数，torch.load在2.6以下版本默认参数weight_only=False，存在潜在安全风险（CVE-2025-32434）。建议使用2.6.0版本的pytorch。

### 2. 同文件中多处漏洞 torch.load 调用

| 行号 | 函数 | 风险等级 |
|------|------|----------|
| 55 | `ShardStateDict._init_metadata` | Critical |
| 110 | `LayerzeroCheckpoint._build_global_state` | Critical |
| 127 | `LayerzeroCheckpoint.get_iteration` | Critical |
| 135 | `LayerzeroCheckpoint.get_args` | Critical |

### 3. 无完整性验证

代码未做：
- 验证文件 checksum 或签名
- 验证文件所有权/权限
- 加载前验证 checkpoint 结构
- 使用 `weights_only=True` 参数（PyTorch 2.0+ 安全特性）

## 影响评估

| 影响类别 | 严重性 | 描述 |
|----------|--------|------|
| **机密性** | High | 攻击者可通过 pickle payload 读取任意文件 |
| **完整性** | High | 攻击者可修改数据或系统状态 |
| **可用性** | High | 攻击者可导致拒绝服务 |
| **执行** | Critical | 以应用权限执行任意代码 |

## 受影响组件

### 入口点
```python
# convert_to_megatron.py, 第 97 行
lz_checkpoint = LayerzeroCheckpoint(args.input_folder)
```

此脚本用于 checkpoint 转换，通过命令行参数 `--input_folder` 接收用户提供的 checkpoint 目录。

### 信任边界
- **输入**：用户控制的 checkpoint 目录路径
- **信任级别**：半可信（仅对文件名做前缀检查）
- **问题**：前缀检查不验证文件内容或来源

## 修复建议

### 1. 使用 `weights_only=True`（主要修复）

```python
# PyTorch 2.0+ 提供 weights_only 参数
state_dict = torch.load(self.filename, map_location='cpu', weights_only=True)
```

### 2. 添加 Checkpoint 完整性验证

```python
import hashlib

def validate_checkpoint_integrity(filepath, expected_hash=None):
    """加载前验证 checkpoint 文件完整性。"""
    if expected_hash:
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        if file_hash != expected_hash:
            raise SecurityError(f"Checkpoint 完整性检查失败: {filepath}")
    return True

def safe_load_checkpoint(filepath, expected_hash=None):
    """带完整性验证的安全加载 checkpoint。"""
    validate_checkpoint_integrity(filepath, expected_hash)
    return torch.load(filepath, map_location='cpu', weights_only=True)
```

### 3. 限制文件权限

确保 checkpoint 目录有受限权限：
- 仅所有者写入权限
- 验证文件所有权匹配预期用户

### 4. 验证 Checkpoint 结构

```python
def _init_metadata(self):
    # 首先用 weights_only 加载验证结构
    state_dict = torch.load(self.filename, map_location='cpu', weights_only=True)
    
    # 验证必需键存在
    required_keys = [PARALLE_STATE_KAY, LOCAL_NAME_TO_FQN_KEY, MODEL_SD_KEY]
    for key in required_keys:
        if key not in state_dict:
            raise ValueError(f"无效 checkpoint: 缺少必需键 '{key}'")
    
    # 然后安全访问数据
    self.parallel_info = state_dict[PARALLE_STATE_KAY]
    # ...
```

## 参考资料

- **CWE-502**：不可信数据反序列化 - https://cwe.mitre.org/data/definitions/502.html
- **CVE-2025-32434**：PyTorch torch.load 安全问题
- **PyTorch 安全**：https://pytorch.org/docs/stable/generated/torch.load.html

## 时间线

- **发现**：静态分析扫描
- **分析日期**：2026-04-20
- **状态**：已确认 - 需修复的真实漏洞

## 相关漏洞

- **VULN-DF-PY-CHKPT-001**：`mindspeed/checkpointing.py` 中类似问题
- **layerzero-mga_checkpoint-torch_load-188**：`mindspeed/core/distributed/layerzero/state/mga_checkpoint.py` 中类似问题