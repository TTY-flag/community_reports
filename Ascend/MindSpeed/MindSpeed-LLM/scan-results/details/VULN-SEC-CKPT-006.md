# 深度利用分析报告: VULN-SEC-CKPT-006

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-CKPT-006 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:24` |
| **函数** | `distrib_optimizer_load_parameter_state_patch` |
| **模块** | checkpoint_conversion |
| **风险点** | 缺少 weights_only 参数 (默认 False) |

---

## 漏洞代码

```python
# mindspeed_llm/core/high_availability/tft_acp_compatibility.py:24

def distrib_optimizer_load_parameter_state_patch(filename):
    """分布式优化器状态加载补丁"""
    # 缺少 weights_only 参数，默认为 False
    state_dict = torch.load(filename)  # 危险！
    return state_dict
```

---

## 数据流分析

```
args.load → filename
  ↓
torch.load(filename)  # 无 weights_only
  ↓ [默认 weights_only=False]
pickle 反序列化 → RCE
```

---

## 风险: 默认值陷阱

**问题**: PyTorch 2.5 及之前版本，`torch.load()` 默认 `weights_only=False`
- 开发者可能不知道需要显式设置 `weights_only=True`
- 缺少参数比显式 `False` 更隐蔽

---

## 修复建议

```python
# 必须显式设置 weights_only=True
def distrib_optimizer_load_parameter_state_patch_secure(filename):
    state_dict = torch.load(
        filename,
        weights_only=True  # 必须显式设置
    )
    return state_dict
```

---

**报告生成时间**: 2026-04-20