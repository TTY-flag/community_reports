# 深度利用分析报告: VULN-SEC-HA-003

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-HA-003 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical (验证后升级) |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/core/high_availability/tft_optimizer_data_repair.py:204-205` |
| **函数** | `recv_ckpt_from_peer` |
| **模块** | high_availability |

---

## 与 VULN-014 关系

**合并说明**: 此漏洞与 VULN-014 位置完全相同（同一代码位置），是 security-auditor 和 dataflow_scanner 分别发现的同一漏洞点。

**完整分析**: 请参考 `VULN-014.md` 中的详细分析报告。

---

## 关键特征

- **攻击向量**: 分布式训练网络传输
- **最危险漏洞**: 单节点攻陷 → 全集群渗透
- **CVSS**: 9.3 (Critical)
- **跨模块**: ✓ (rank间通信)

---

**报告生成时间**: 2026-04-20  
**合并说明**: 此漏洞与 VULN-014 同位置，完整分析见 VULN-014.md