# 深度利用分析报告: VULN-SEC-CKPT-003

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-CKPT-003 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:404-405` |
| **函数** | `merge_checkpoints` |
| **模块** | checkpoint_conversion |
| **特殊风险** | TP分片合并 - 需加载多个文件 |

---

## 漏洞代码

```python
# mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:404-405

def merge_checkpoints(self, input_model_dir):
    """合并 TP 分片的 checkpoint"""
    tp_models = []
    
    for tp_rank in range(self.args.target_tensor_parallel_size):
        model_file = get_model_file_path(input_model_dir, tp_rank)
        
        # 每个分片都用 weights_only=False 加载
        tp_models.append(torch.load(
            model_file, 
            map_location='cpu', 
            weights_only=False  # 危险！多个文件暴露
        ))
    
    return merge_tp_shards(tp_models)
```

---

## 数据流分析

```
CLI --load-dir → input_model_dir
  ↓
遍历 TP ranks: 0, 1, 2, ...
  ↓
get_model_file_path() → model_file_tp0.bin, model_file_tp1.bin, ...
  ↓ [多个文件路径]
torch.load(model_file, weights_only=False) [×N]
  ↓ [SINK ×N - 多次 pickle 反序列化]
任意一个恶意分片 → RCE
```

---

## 特殊风险: 多文件暴露

**风险**: 需要加载多个 TP 分片文件，攻击面更大：
- 任何一个分片被篡改都可以触发 RCE
- 攻击者只需污染其中一个 `.bin` 文件

---

## 攻击场景

```bash
# 攻击者篡改其中一个分片
/shared/models/llama_tp0.bin  ← 正常
/shared/models/llama_tp1.bin  ← 正常
/shared/models/llama_tp2.bin  ← 恶意 (被篡改)
/shared/models/llama_tp3.bin  ← 正常

# 用户执行转换
python convert_ckpt.py --load-dir /shared/models

# tp2.bin 加载时 → RCE
```

---

## 修复建议

```python
# 修复代码 - 批量安全加载
def merge_checkpoints_secure(self, input_model_dir):
    tp_models = []
    
    for tp_rank in range(self.args.target_tensor_parallel_size):
        model_file = get_model_file_path(input_model_dir, tp_rank)
        
        # 验证文件完整性
        verify_checkpoint_hash(model_file)
        
        # 安全加载
        tp_models.append(torch.load(
            model_file,
            map_location='cpu',
            weights_only=True  # 安全
        ))
    
    return merge_tp_shards(tp_models)
```

---

**报告生成时间**: 2026-04-20