# 深度利用分析报告: VULN-SEC-CKPT-004

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-CKPT-004 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/tasks/checkpoint/convert_param.py:221-222` |
| **函数** | `get_hf_model_based_files` |
| **模块** | checkpoint_conversion |

---

## 漏洞代码

```python
# mindspeed_llm/tasks/checkpoint/convert_param.py:221-222

def get_hf_model_based_files(self, hf_dir):
    """从 HF 目录加载模型文件"""
    for filename in os.listdir(hf_dir):
        file_path = os.path.join(hf_dir, filename)
        
        if filename.endswith(".bin"):
            # 明确 weights_only=False
            hf_model = torch.load(
                file_path, 
                map_location='cpu', 
                weights_only=False  # 危险！
            )
            return hf_model
```

---

## 数据流分析

```
CLI --hf-dir → args_cmd.hf_dir
  ↓
get_hf_model_based_files(hf_dir)
  ↓
os.listdir(hf_dir) → 找到 pytorch_model.bin
  ↓
file_path = os.path.join(hf_dir, filename)
  ↓
torch.load(file_path, weights_only=False)
  ↓ [SINK]
恶意 pytorch_model.bin → RCE
```

---

## 攻击场景

**场景: HF 模型转换攻击**

1. 用户从 HuggingFace 下载模型到本地
2. 攻击者篡改本地模型的 `pytorch_model.bin`
3. 用户执行 HF → MG 转换
4. `torch.load()` 加载恶意文件 → RCE

---

## 修复建议

```python
# 修复代码
def get_hf_model_based_files_secure(self, hf_dir):
    # 优先使用 safetensors 格式
    for filename in os.listdir(hf_dir):
        if filename.endswith(".safetensors"):
            from safetensors.torch import load_file
            return load_file(os.path.join(hf_dir, filename))
    
    # 如果必须用 .bin，强制 weights_only=True
    for filename in os.listdir(hf_dir):
        if filename.endswith(".bin"):
            return torch.load(
                os.path.join(hf_dir, filename),
                map_location='cpu',
                weights_only=True  # 安全
            )
```

---

**报告生成时间**: 2026-04-20