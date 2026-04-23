# VULN-018：评估模块Tokenizer加载启用trust_remote_code致远程代码执行

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-018 |
| **CWE** | CWE-940 (Improper Verification of Source of a Communication Channel) |
| **严重性** | High |
| **置信度** | 80/100 |
| **位置** | `evaluation.py:383` |
| **函数** | `main` |
| **模块** | mindspeed_llm/tasks/evaluation |

---

## 与 VULN-SEC-TRUST-001 关系

**合并报告**: 此漏洞与 VULN-SEC-TRUST-001 位置完全相同，详细分析请参考 `VULN-SEC-TRUST-001.md`。

---

## 数据流来源

```
argparse --tokenizer-name-or-path → args.tokenizer_name_or_path
  ↓
AutoTokenizer.from_pretrained(trust_remote_code=True)
  ↓ [SINK]
执行模型自定义代码
```

---

## 漏洞代码

```python
# evaluation.py:383
tokenizer = AutoTokenizer.from_pretrained(
    args.tokenizer_name_or_path, 
    trust_remote_code=True, 
    local_files_only=True
)
```

---

## 修复建议

参考 `VULN-SEC-TRUST-001.md` 中的安全加载方案。

---

**报告生成时间**: 2026-04-20  
**合并说明**: 此漏洞与 VULN-SEC-TRUST-001 同位置，完整分析见 VULN-SEC-TRUST-001.md