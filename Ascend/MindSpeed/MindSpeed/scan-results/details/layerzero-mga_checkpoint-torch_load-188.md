# layerzero-mga_checkpoint-torch_load-188：LayerZero Checkpoint加载torch.load无保护致RCE

## 概要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | layerzero-mga_checkpoint-torch_load-188 |
| **CWE** | CWE-502 (不可信数据反序列化) |
| **严重性** | Critical |
| **文件** | mindspeed/core/distributed/layerzero/state/mga_checkpoint.py |
| **行号** | 188 |
| **函数** | `load_layerzero_checkpoint` |

## 漏洞描述

`load_layerzero_checkpoint` 函数使用 `torch.load()` 时未设置 `weights_only=True` 参数，允许通过嵌入在 checkpoint 文件中的恶意 pickle payload 执行任意代码。

### 漏洞代码

```python
# 第 177-188 行
def load_layerzero_checkpoint(models, ckpt_dir, optimizer=None, opt_param_scheduler=None):
    if ckpt_dir is None:
        raise AssertionError(f"Got {ckpt_dir} filename")
    if len(models) != 1:
        raise ValueError(f"VPP is not supported by layerzero currently")
    rank = dist.get_rank()
    sd_file = os.path.join(ckpt_dir, f"model_{rank}.pt")
    if not os.path.exists(sd_file):
        raise FileNotFoundError(
            f"No checkpoint found in load directory or pretrained directory: no such file {sd_file}")
    args = get_args()
    state_dict = torch.load(sd_file)  # 漏洞点：无 weights_only=True
```

### 数据流

```
数据源：config.ckpt_load_path (YAML 配置文件或直接参数)
   ↓
LayerzeroConfig.ckpt_load_path (dataclass 字段，config.py 第 64 行)
   ↓
验证：仅 os.path.isabs() 检查 (第 267-269 行)
   ↓
load_layerzero_checkpoint(models, config.ckpt_load_path, ...) (第 271-272 行)
   ↓
sd_file = os.path.join(ckpt_dir, f"model_{rank}.pt") (第 183 行)
   ↓
torch.load(sd_file)  ← 危险点：任意 pickle 反序列化
```

## 技术细节

### 为什么无法直接应用 `weights_only=True`

Checkpoint state dictionary 包含复杂对象而非简单张量：

```python
# 来自 generate_state_dict() 函数 (第 112-153 行)
state_dict = {}
state_dict['args'] = args                    # Python 对象，非仅张量
state_dict['checkpoint_version'] = 3.0
state_dict['iteration'] = iteration
state_dict[MODEL_KEY] = model.state_dict()  # 张量权重
state_dict[OPTIM_STATE_KEY] = optimizer.state_dict()  # 复杂优化器状态
state_dict[RNG_STATE_KEY] = rng_state       # Python 状态对象
state_dict[PARALLE_STATE_KAY] = generate_3D_parallel_state()  # 并行状态
```

使用 `weights_only=True` 将导致加载失败，因为：
1. `args` 是 Python argparse Namespace 对象
2. 优化器状态包含复杂嵌套对象
3. RNG 状态包含 Python 随机状态对象

### 现有缓解措施（不充分）

1. **绝对路径验证** (config.py 第 267-269 行)：
   ```python
   if not os.path.isabs(config.ckpt_load_path):
       raise ValueError(...)
   ```
   - 仅验证路径格式，不验证文件内容或来源
   - 不阻止从绝对路径加载恶意文件

2. **文件存在检查** (mga_checkpoint.py 第 184-186 行)：
   - 仅检查文件是否存在，不检查完整性或真实性

## 攻击场景

可控制以下内容的攻击者：
1. YAML 配置文件中的 `ckpt_load_path` 路径
2. 或向预期目录注入恶意 checkpoint 文件

可通过构造恶意 `.pt` 文件实现 **任意代码执行**：
```python
import torch
import os

class Malicious:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

# 创建恶意 checkpoint
malicious_ckpt = {'model': Malicious(), 'iteration': 0}
torch.save(malicious_ckpt, 'model_0.pt')
```

当调用 `torch.load('model_0.pt')` 时，恶意代码被执行。

## 相关漏洞位置

代码库中存在类似模式：

| 文件 | 行号 | 函数 |
|------|------|------|
| mindspeed/checkpointing.py | 277 | `load_checkpoint` |
| mindspeed/checkpointing.py | 284 | `load_checkpoint` |
| mindspeed/checkpointing.py | 310 | `load_checkpoint` |
| mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py | 55 | `ShardStateDict._init_metadata` |
| mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py | 110 | `LayerzeroCheckpoint._build_global_state` |
| mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py | 127, 135 | `LayerzeroCheckpoint.get_iteration`/`get_args` |

## 修复建议

### 短期（立即）

1. **在文档中添加安全警告**，说明仅从可信来源加载 checkpoint

2. **添加 checkpoint 完整性验证**，使用哈希检查：
   ```python
   import hashlib
   def verify_checkpoint_hash(filepath, expected_hash):
       with open(filepath, 'rb') as f:
           file_hash = hashlib.sha256(f.read()).hexdigest()
       return file_hash == expected_hash
   ```

3. **记录 checkpoint 加载并带安全警告**：
   ```python
   import logging
   logging.warning(f"从 {sd_file} 加载 checkpoint。仅从可信来源加载 checkpoint。")
   ```

### 中期

1. **分离权重与状态元数据**：
   - 使用 `weights_only=True` 安全格式单独存储权重
   - 将元数据（args、iteration 等）存储在 JSON/YAML 格式
   - 安全加载两部分后重建 state_dict

2. **实现 checkpoint 签名**：
   - 使用私钥签名保存的 checkpoint
   - 加载前验证签名

### 长期

1. **迁移到更安全的序列化格式**：
   - 使用 `torch.save(..., _use_new_zipfile_serialization=True)`
   - 考虑 safetensors 格式存储模型权重
   - 将非张量数据存储在 JSON

2. **为不可信 checkpoint 添加沙箱反序列化**

## 风险评估

| 因素 | 评估 |
|------|------|
| **可能性** | Low-Medium（需配置/文件访问） |
| **影响** | Critical（任意代码执行） |
| **当前缓解措施** | 不充分 |
| **框架上下文** | 内部训练框架（预期可信配置） |

## 参考资料

- [PyTorch 安全公告：torch.load weights_only 默认值变更](https://github.com/pytorch/pytorch/pull/101837)
- [CWE-502：不可信数据反序列化](https://cwe.mitre.org/data/definitions/502.html)
- [PyTorch 安全加载文档](https://pytorch.org/docs/stable/generated/torch.load.html)

## 验证步骤

1. 识别所有无 `weights_only=True` 的 `torch.load()` 调用
2. 追踪数据流确定路径是否可被外部控制
3. 用构造的恶意 checkpoint 文件测试确认可利用性
4. 验证是否存在完整性检查或签名验证

---

*报告由 OpenCode 漏洞扫描器生成*
*日期：2026-04-20*