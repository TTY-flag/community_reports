# VULN-CHECKPOINT-004：torch.load设置weights_only=False致Pickle反序列化RCE

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞类型** | Unsafe Deserialization (CWE-502) |
| **严重性** | Critical |
| **置信度** | 95% -> **100% (已确认)** |
| **影响版本** | 当前版本 |

## 漏洞详情

### 核心问题

项目中多处使用 `torch.load()` 加载模型权重时设置 `weights_only=False`，这会导致使用 Python 的 `pickle` 模块进行反序列化。`pickle` 是已知的不安全序列化格式，攻击者可以通过构造恶意的 `.pt` 文件来执行任意代码。

### 受影响的代码位置

#### 1. 主要漏洞点 (报告中指出)
**文件**: `/checkpoint/sora_model/convert_utils/save_load_utils.py`
**行号**: 36
```python
def load_from_mm(load_dir):
    # ... 
    state_dict_path = os.path.join(load_dir, directory, sub_dir, MEGATRON_CKPT_NAME)
    state_dict = torch.load(state_dict_path, map_location='cpu', weights_only=False)  # 不安全!
```

#### 2. 同文件其他漏洞点
**行号**: 152
```python
def load_pt(source_path, module_name=None):
    state_dict = torch.load(source_path, map_location='cpu')  # 默认 weights_only=False
```

#### 3. VLM 模块中的漏洞点
**文件**: `/checkpoint/vlm_model/mm_to_hf.py`
**行号**: 92, 107
```python
for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=False)['model'].items():
```

#### 4. LoRA 合并模块中的漏洞点
**文件**: `/checkpoint/common/merge_base_lora_weight.py`
**行号**: 88-92
```python
base_state_dict = torch.load(base_pt_path, map_location='npu')['model']
lora_state_dict = torch.load(lora_pt_path, map_location='npu')['model']
# 或
base_state_dict = torch.load(base_pt_path, map_location='cpu')['model']
lora_state_dict = torch.load(lora_pt_path, map_location='cpu')['model']
```

## 数据流追踪

```
CLI 入口 (convert_cli.py)
    │
    ▼
jsonargparse.auto_cli(Commandable.subclasses)
    │
    ▼
ConvertConfig.source_path (用户提供的路径)
    │
    ▼
SoraModelConverter 方法 (mm_to_hf, mm_to_dcp, resplit, merge_lora_to_base)
    │
    ▼
load_from_mm(cfg.source_path)
    │
    ▼
state_dict_path = os.path.join(load_dir, ...)
    │
    ▼
torch.load(state_dict_path, weights_only=False)  ← 不安全的反序列化!
```

### 关键文件链

1. **入口点**: `/checkpoint/convert_cli.py`
   - 使用 `jsonargparse` 解析 CLI 参数
   - 自动发现并调用 `Commandable.subclasses` 中的转换器

2. **配置定义**: `/checkpoint/sora_model/convert_utils/cfg.py`
   ```python
   class ConvertConfig(BaseModel):
       source_path: str  # 用户可控
       lora_path: str = ""  # 用户可控
       target_path: str
       target_parallel_config: ParallelConfig
   ```

3. **转换器实现**: `/checkpoint/sora_model/sora_model_converter.py`
   - 多个方法调用 `load_from_mm(cfg.source_path)`:
     - `mm_to_hf()` - 第88行
     - `mm_to_dcp()` - 第99行
     - `resplit()` - 第116行
     - `merge_lora_to_base()` - 第147, 149行

## 安全影响

### 攻击向量

1. **供应链攻击**: 攻击者在模型仓库中发布包含恶意 payload 的 checkpoint 文件
2. **社会工程攻击**: 诱骗用户下载并转换"预训练模型"
3. **本地文件利用**: 如果攻击者能控制用户加载的文件路径

### 攻击示例

攻击者可以创建一个恶意的 `.pt` 文件：
```python
import torch
import os

class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

# 创建恶意 checkpoint
malicious_state_dict = {'model': MaliciousPayload()}
torch.save(malicious_state_dict, 'malicious_model.pt')

# 当用户运行转换命令时，会执行恶意代码
# python convert_cli.py mm_to_hf --source_path ./malicious_model.pt ...
```

### 影响范围

该漏洞影响所有使用以下功能的用户：
- 模型权重格式转换 (HF <-> MM)
- 权重重新分片 (resplit)
- LoRA 权重合并
- LayerZero 模型转换

## 修复建议

### 短期修复 (推荐)

1. **使用 weights_only=True**:
   ```python
   # 修复前
   state_dict = torch.load(path, weights_only=False)
   
   # 修复后
   state_dict = torch.load(path, weights_only=True)
   ```

   注意：`weights_only=True` 仅支持加载张量数据，如果 checkpoint 包含其他 Python 对象，可能需要额外处理。

2. **使用 safetensors 格式** (项目已部分采用):
   ```python
   from safetensors.torch import load_file
   state_dict = load_file(path)  # 安全，不使用 pickle
   ```

### 中期修复

1. **添加路径验证**:
   ```python
   import os
   
   def validate_path(path):
       """验证路径是否在允许的目录范围内"""
       abs_path = os.path.realpath(path)
       allowed_dirs = [...]  # 定义允许的目录
       return any(abs_path.startswith(d) for d in allowed_dirs)
   ```

2. **添加文件哈希校验**:
   - 为可信模型提供校验和
   - 在加载前验证文件完整性

3. **添加安全警告**:
   ```python
   import warnings
   warnings.warn(
       "Loading untrusted checkpoint files can execute arbitrary code. "
       "Only load checkpoints from trusted sources.",
       UserWarning
   )
   ```

### 长期修复

1. 迁移所有 checkpoint 格式到 `safetensors`
2. 实现安全的 checkpoint 加载框架
3. 添加模型来源验证机制

## 补充发现

在审查过程中，还发现以下安全问题：

1. **`merge_base_lora_weight.py`** 中的 `use_npu` 变量未定义但在第87行被使用
2. 缺少输入验证和错误处理
3. 文件路径直接拼接到 `os.path.join`，可能存在路径遍历风险

## 验证状态

- [x] 数据流已验证
- [x] 入口点已确认
- [x] 无现有防护措施
- [x] 漏洞可复现

## 参考

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [PyTorch Security: torch.load() and pickle](https://pytorch.org/docs/stable/generated/torch.load.html)
- [Safetensors: A safer alternative](https://huggingface.co/docs/safetensors/index)
