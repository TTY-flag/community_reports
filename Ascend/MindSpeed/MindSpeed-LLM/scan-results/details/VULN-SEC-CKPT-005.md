# VULN-SEC-CKPT-005：HF格式转换函数torch.load无保护致Pickle RCE风险

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-CKPT-005 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/tasks/checkpoint/convert_param.py:581-582` |
| **函数** | `_set_dense_hf_model` |
| **模块** | checkpoint_conversion |

---

## 漏洞代码

```python
# mindspeed_llm/tasks/checkpoint/convert_param.py:581-582

def _set_dense_hf_model(self):
    """设置密集 HF 模型"""
    mg_save_dir = get_mg_model_save_dir(self.args_cmd.mg_dir)
    
    # 加载 MG checkpoint 用于 HF 转换
    mg_tp_model = torch.load(
        os.path.join(mg_save_dir, self.mg_model_file_name),
        map_location='cpu',
        weights_only=False  # 危险！
    )
    return mg_tp_model
```

---

## 数据流分析

```
CLI --mg-dir → args_cmd.mg_dir
  ↓
get_mg_model_save_dir(mg_dir) → mg_save_dir
  ↓
os.path.join(mg_save_dir, self.mg_model_file_name)
  ↓
torch.load(..., weights_only=False)
  ↓ [SINK]
恶意 MG checkpoint → RCE
```

---

## 攻击场景: MG → HF 转换攻击

反向转换场景：
1. 用户有 Megatron 格式的 checkpoint
2. 需要转换为 HuggingFace 格式
3. 加载 MG checkpoint 时触发恶意 payload

---

## 修复建议

同其他 torch.load 漏洞，强制使用 `weights_only=True`。

---

**报告生成时间**: 2026-04-20