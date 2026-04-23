# VULN-007：Longcat模型Checkpoint转换torch.load无保护致反序列化RCE

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-007 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/tasks/checkpoint/convert_ckpt_longcat.py:312` |
| **函数** | `generate_mg_weights` |
| **模块** | mindspeed_llm/tasks/checkpoint |
| **模型类型** | Longcat (长上下文模型) |

---

## 漏洞代码

```python
# mindspeed_llm/tasks/checkpoint/convert_ckpt_longcat.py:312

def generate_mg_weights(self, save_dir):
    """生成 Megatron 格式的 weights"""
    save_file_name = os.path.join(save_dir, "layer_weights.bin")
    
    # 加载临时保存的 checkpoint
    model_dict = torch.load(
        save_file_name,
        map_location='cpu',
        weights_only=False  # 危险！
    )
    
    # 处理权重...
    return model_dict
```

---

## 数据流分析

```
CLI 参数 → save_dir
  ↓
os.path.join(save_dir, "layer_weights.bin")
  ↓
torch.load(save_file_name, weights_only=False)
  ↓ [SINK]
恶意 layer_weights.bin → RCE
```

---

## 特殊场景: Longcat 模型转换

**Longcat 模型特点**: 
- 支持超长上下文的 LLM 模型
- 特殊的 checkpoint 转换流程
- 可能涉及中间临时文件

**攻击场景**: 
攻击者篡改转换过程中保存的临时 checkpoint 文件。

---

## 修复建议

```python
def generate_mg_weights_secure(self, save_dir):
    save_file_name = os.path.join(save_dir, "layer_weights.bin")
    
    # 安全加载
    model_dict = torch.load(
        save_file_name,
        map_location='cpu',
        weights_only=True  # 安全
    )
    
    return model_dict
```

---

**报告生成时间**: 2026-04-20