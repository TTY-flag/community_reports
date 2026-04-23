# VULN-SEC-CKPT-008：HF模型文件更新函数torch.load无保护致反序列化RCE

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-CKPT-008 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/tasks/checkpoint/convert_param.py:755-756` |
| **函数** | `_update_hf_model_file` |
| **模块** | checkpoint_conversion |
| **特殊点** | 条件加载 + 文件存在检查 |

---

## 漏洞代码

```python
# mindspeed_llm/tasks/checkpoint/convert_param.py:755-756

def _update_hf_model_file(self, file_path):
    """更新 HF 模型文件"""
    # 条件加载：文件存在时加载，否则返回空字典
    exist_model = torch.load(
        file_path,
        map_location='cpu',
        weights_only=False  # 危险！
    ) if os.path.exists(file_path) else {}
    
    return exist_model
```

---

## 数据流分析

```
CLI --hf-dir → file_path
  ↓
os.path.exists(file_path) 检查
  ↓ [文件存在]
torch.load(file_path, weights_only=False)
  ↓ [SINK]
恶意文件 → RCE
```

---

## 特殊风险: 条件加载

**风险**: 条件表达式中的加载：
- `os.path.exists()` 检查不提供安全保证
- 文件存在 ≠ 文件安全
- 条件加载更隐蔽，可能被忽略

---

## 攻击场景

```bash
# 攻击者确保恶意文件存在
touch /shared/models/pytorch_model.bin  # 创建恶意文件

# 用户执行转换，文件存在检查通过
python convert_param.py --hf-dir /shared/models

# 条件加载触发 → RCE
```

---

## 修复建议

```python
def _update_hf_model_file_secure(self, file_path):
    if os.path.exists(file_path):
        # 验证完整性
        verify_file_hash(file_path)
        
        # 安全加载
        exist_model = torch.load(
            file_path,
            map_location='cpu',
            weights_only=True  # 安全
        )
    else:
        exist_model = {}
    return exist_model
```

---

**报告生成时间**: 2026-04-20