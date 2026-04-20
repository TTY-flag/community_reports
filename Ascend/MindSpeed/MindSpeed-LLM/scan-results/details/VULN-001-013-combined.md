# 深度利用分析报告: VULN-001 至 VULN-013 (数据流扫描系列)

## 概述

VULN-001 到 VULN-013 是数据流扫描 Agent 发现的 13 个 CWE-502 漏洞，与 security-auditor 发现的 VULN-SEC-CKPT 系列漏洞位置重叠。

---

## 漏洞列表与对应关系

| 数据流ID | 安全审计ID | 位置文件 | 行号 | 函数 |
|---------|-----------|---------|------|------|
| VULN-001 | VULN-SEC-CKPT-001 | convert_ckpt_mamba2.py | 87 | load_hf_files_to_dict |
| VULN-002 | VULN-SEC-CKPT-002 | convert_ckpt_mamba2.py | 372 | convert_hf2mg |
| VULN-003 | VULN-SEC-CKPT-003 | convert_ckpt_mamba2.py | 404 | merge_checkpoints |
| VULN-004 | VULN-SEC-CKPT-004 | convert_param.py | 221 | convert_to_mg |
| VULN-005 | VULN-SEC-CKPT-005 | convert_param.py | 581 | convert_to_hf |
| VULN-006 | VULN-SEC-CKPT-008 | convert_param.py | 755 | _update_hf_model_file |
| VULN-007 | (独立) | convert_ckpt_longcat.py | 312 | generate_mg_weights |
| VULN-008 | (独立) | convert_ckpt_longcat.py | 336 | generate_mg_weights |
| VULN-009 | (独立) | convert_ckpt_pp_vpp.py | 130 | load_ckpt |
| VULN-010 | VULN-SEC-CKPT-006 | tft_acp_compatibility.py | 24 | distrib_optimizer_load |
| VULN-011 | VULN-SEC-CKPT-007 | tft_acp_compatibility.py | 50 | chained_optimizer_load |
| VULN-012 | VULN-SEC-HA-001 | tft_acp_compatibility.py | 115-117 | load_checkpoint_for_ha |
| VULN-013 | VULN-SEC-HA-002 | tft_acp_compatibility.py | 129 | load_checkpoint_for_ha |
| VULN-014 | (已单独报告) | tft_optimizer_data_repair.py | 204 | recv_ckpt_from_peer |

---

## 独立漏洞详细报告

### VULN-007: convert_ckpt_longcat.py:312

```python
# mindspeed_llm/tasks/checkpoint/convert_ckpt_longcat.py:312

def generate_mg_weights(self, save_dir):
    """生成 Megatron weights (longcat 模型)"""
    save_file_name = os.path.join(save_dir, "layer_weights.bin")
    
    # 加载临时 checkpoint
    model_dict = torch.load(
        save_file_name,
        map_location='cpu',
        weights_only=False  # 危险！
    )
    return model_dict
```

**数据流**: `argparse → args.save_dir → torch.load()`

---

### VULN-008: convert_ckpt_longcat.py:336

与 VULN-007 同函数，第二处加载点（最后一层权重）。

---

### VULN-009: convert_ckpt_pp_vpp.py:130

```python
# mindspeed_llm/tasks/posttrain/ldt_sft/convert_ckpt_pp_vpp.py:130

def load_ckpt(checkpoint_path):
    """PP/VPP checkpoint 加载函数"""
    return torch.load(
        checkpoint_path,
        map_location='cpu',
        weights_only=False  # 危险！
    )
```

**场景**: Pipeline Parallel / Virtual Pipeline Parallel 模型转换。

---

## 通用修复方案

所有漏洞均使用相同修复策略：

```python
# 强制使用 weights_only=True
state_dict = torch.load(
    file_path,
    map_location='cpu',
    weights_only=True  # 关键修复
)
```

---

## 报告合并说明

| VULN-ID | 合并到 |
|---------|--------|
| VULN-001 | VULN-SEC-CKPT-001.md |
| VULN-002 | VULN-SEC-CKPT-002.md |
| VULN-003 | VULN-SEC-CKPT-003.md |
| VULN-004 | VULN-SEC-CKPT-004.md |
| VULN-005 | VULN-SEC-CKPT-005.md |
| VULN-006 | VULN-SEC-CKPT-008.md |
| VULN-010 | VULN-SEC-CKPT-006.md |
| VULN-011 | VULN-SEC-CKPT-007.md |
| VULN-012 | VULN-SEC-HA-001.md |
| VULN-013 | VULN-SEC-HA-002.md |

---

**报告生成时间**: 2026-04-20  
**说明**: 数据流扫描与安全审计发现的同位置漏洞已合并报告