# VULN-SEC-CKPT-007：链式优化器加载函数torch.load无保护致Pickle RCE

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-CKPT-007 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:50` |
| **函数** | `chained_optimizer_load_parameter_state_patch` |
| **模块** | high_availability |
| **风险点** | 缺少 weights_only 参数 (默认 False) |

---

## 漏洞代码

```python
# mindspeed_llm/core/high_availability/tft_acp_compatibility.py:50

def chained_optimizer_load_parameter_state_patch(filename):
    """链式优化器状态加载补丁"""
    states = torch.load(filename)  # 危险！无 weights_only
    return states
```

---

## 与 VULN-SEC-CKPT-006 关系

同类型漏洞，位于同一文件的不同位置（第24行和第50行）。

---

## 修复建议

同 VULN-SEC-CKPT-006，必须显式设置 `weights_only=True`。

---

**报告生成时间**: 2026-04-20