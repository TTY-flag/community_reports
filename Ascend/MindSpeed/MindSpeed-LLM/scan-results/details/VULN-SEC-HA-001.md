# VULN-SEC-HA-001：高可用模块故障恢复时加载Checkpoint存在Pickle RCE风险

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-HA-001 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:117-118` |
| **函数** | `checkpointing_load_base_checkpoint_patch` |
| **模块** | high_availability |
| **场景** | 高可用训练 - 故障恢复 |

---

## 漏洞代码

```python
# mindspeed_llm/core/high_availability/tft_acp_compatibility.py:117-118

def checkpointing_load_base_checkpoint_patch():
    """高可用模块的 checkpoint 加载补丁"""
    checkpoint_name = get_checkpoint_name(args.load, args.ckpt_step)
    
    # 加载 base checkpoint
    state_dict = torch.load(
        checkpoint_name,
        map_location='cpu',
        weights_only=False  # 危险！高可用场景
    )
    return state_dict
```

---

## 数据流分析

```
训练参数 args.load + args.ckpt_step
  ↓
get_checkpoint_name() → checkpoint_name
  ↓
torch.load(checkpoint_name, weights_only=False)
  ↓ [SINK]
恶意 checkpoint → 高可用节点 RCE
```

---

## 特殊风险: 高可用训练环境

**场景**: 分布式训练故障恢复时自动加载 checkpoint：
- 故障节点重启后自动加载 checkpoint
- 如果 checkpoint 被篡改，故障恢复时触发 RCE
- **自动化执行**，用户无感知

---

## 攻击场景

```
┌─────────────────────────────────────────────────────────────────┐
│                    高可用训练集群                                 │
│                                                                  │
│  正常运行 → Rank 2 故障 → 自动恢复 → 加载 checkpoint             │
│                                     ↓                            │
│                            恶意 checkpoint → RCE                 │
│                                     ↓                            │
│                            Rank 2 被攻陷                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 修复建议

```python
# 高可用场景必须使用安全加载
def checkpointing_load_base_checkpoint_patch_secure():
    checkpoint_name = get_checkpoint_name(args.load, args.ckpt_step)
    
    # 高可用场景必须验证完整性
    verify_checkpoint_signature(checkpoint_name)
    
    # 安全加载
    state_dict = torch.load(
        checkpoint_name,
        map_location='cpu',
        weights_only=True  # 必须！
    )
    return state_dict
```

---

**报告生成时间**: 2026-04-20