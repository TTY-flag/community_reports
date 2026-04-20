# 深度利用分析报告: VULN-SEC-HA-002

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-HA-002 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:129-130` |
| **函数** | `checkpointing_load_base_checkpoint_patch` |
| **模块** | high_availability |
| **场景** | 向后兼容处理 - 异常分支 |

---

## 漏洞代码

```python
# mindspeed_llm/core/high_availability/tft_acp_compatibility.py:129-130

def checkpointing_load_base_checkpoint_patch():
    try:
        # 主加载逻辑...
        state_dict = torch.load(checkpoint_name, ...)
    except Exception:
        # 向后兼容处理
        state_dict = torch.load(
            checkpoint_name,
            map_location='cpu',
            weights_only=False  # 异常处理中的危险加载
        )
    return state_dict
```

---

## 特殊风险: 异常处理路径

**风险**: 
- 异常处理中的备用加载路径同样危险
- 主路径可能被修复，但备用路径仍存在漏洞
- 攻击者可构造特殊 checkpoint 触发异常进入备用路径

---

## 修复建议

**必须同时修复主路径和备用路径**：

```python
def checkpointing_load_base_checkpoint_patch_secure():
    try:
        state_dict = torch.load(
            checkpoint_name,
            map_location='cpu',
            weights_only=True  # 主路径安全
        )
    except Exception as e:
        # 备用路径也要安全
        state_dict = torch.load(
            checkpoint_name,
            map_location='cpu',
            weights_only=True  # 备用路径安全
        )
    return state_dict
```

---

**报告生成时间**: 2026-04-20