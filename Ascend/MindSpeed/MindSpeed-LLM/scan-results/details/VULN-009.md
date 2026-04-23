# VULN-009：PP/VPP微调Checkpoint转换torch.load存在反序列化RCE风险

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-009 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/tasks/posttrain/ldt_sft/convert_ckpt_pp_vpp.py:130` |
| **函数** | `load_ckpt` |
| **模块** | mindspeed_llm/tasks/posttrain/ldt_sft |
| **场景** | PP/VPP 微调训练 checkpoint 转换 |

---

## 漏洞代码

```python
# mindspeed_llm/tasks/posttrain/ldt_sft/convert_ckpt_pp_vpp.py:130

def load_ckpt(checkpoint_path):
    """加载 PP/VPP checkpoint"""
    return torch.load(
        checkpoint_path,
        map_location='cpu',
        weights_only=False  # 危险！
    )
```

---

## 数据流分析

```
CLI --load-dir → checkpoint_path
  ↓
load_ckpt(checkpoint_path)
  ↓
torch.load(checkpoint_path, weights_only=False)
  ↓ [SINK]
恶意 checkpoint → RCE
```

---

## 特殊场景: Pipeline Parallel

**PP/VPP 模型特点**:
- Pipeline Parallel: 多 GPU 并行处理不同层
- Virtual Pipeline Parallel: 优化内存的虚拟流水线
- 微调训练 (LDT SFT) 场景

**攻击场景**:
微调训练的 checkpoint 转换过程中加载恶意文件。

---

## 修复建议

```python
def load_ckpt_secure(checkpoint_path):
    """安全的 PP/VPP checkpoint 加载"""
    return torch.load(
        checkpoint_path,
        map_location='cpu',
        weights_only=True  # 安全
    )
```

---

**报告生成时间**: 2026-04-20