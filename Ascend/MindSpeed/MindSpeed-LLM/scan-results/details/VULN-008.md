# VULN-008：Longcat最后一层Checkpoint加载存在Pickle反序列化RCE漏洞

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-008 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/tasks/checkpoint/convert_ckpt_longcat.py:336` |
| **函数** | `generate_mg_weights` |
| **模块** | mindspeed_llm/tasks/checkpoint |
| **特征** | 与 VULN-007 同函数，最后一层加载 |

---

## 漏洞代码

```python
# mindspeed_llm/tasks/checkpoint/convert_ckpt_longcat.py:336

# 在 generate_mg_weights 函数中，第二次加载
model_dict = torch.load(
    save_file_name,  # 最后一层的 checkpoint
    map_location='cpu',
    weights_only=False  # 危险！
)
```

---

## 与 VULN-007 关系

- **同函数**: 两个漏洞点在同一个 `generate_mg_weights` 函数中
- **不同加载**: 分别加载中间层和最后一层的 checkpoint
- **需同时修复**: 函数中所有 torch.load 调用都需要安全化

---

## 修复建议

同 VULN-007，强制使用 `weights_only=True`。

---

**报告生成时间**: 2026-04-20