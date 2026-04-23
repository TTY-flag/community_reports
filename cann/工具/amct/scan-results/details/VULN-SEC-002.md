# VULN-SEC-002 深度利用分析报告

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-SEC-002 |
| **类型** | 不安全反序列化 (Unsafe Deserialization) |
| **CWE** | CWE-502: Deserialization of Untrusted Data |
| **严重性** | Critical (代码层面) / Low (实际风险) |
| **置信度** | 85 |
| **状态** | **低风险 - 未使用代码 (Dead Code)** |
| **最终判定** | **不可直接利用，建议删除代码** |

## 漏洞位置

**文件**: `amct_pytorch/graph_based_compression/amct_pytorch/parser/module_based_record_parser.py`
**行号**: 38-43
**函数**: `get_layer_quant_params`

### 漏洞代码

```python
def get_layer_quant_params(records, layer_name):
    """
    Function: get single layer quant params from quant_result_path in records
    """
    if records.get('quant_result_path') is None:
        raise RuntimeError("quant_result_path not exists in record!")

    quant_result_path = records.get('quant_result_path')
    if not os.path.exists(quant_result_path):
        raise RuntimeError("quant_result_path {} not exists.".format(quant_result_path))
    
    # ⚠️ 漏洞点: weights_only=False 显式禁用安全模式
    if version_higher_than(torch.__version__, '2.1.0'):
        load_kwargs = {'mmap': True, 'weights_only': False}
    else:
        load_kwargs = {}
    quant_params = torch.load(quant_result_path, **load_kwargs)
    return quant_params.get(layer_name)
```

## 关键发现：未使用代码分析

### 1. 调用链追踪结果

| 检查项 | 结果 |
|--------|------|
| 函数定义位置 | `module_based_record_parser.py:24` |
| 导入位置 | 仅在 `custom_op/utils.py:24` 导入 |
| **实际调用** | **无 - 搜索整个项目未发现任何调用** |
| 公共 API 导出 | **否 - 不在 __all__ 列表中** |
| 测试覆盖 | **无 - 无相关测试文件** |

### 2. 数据结构不匹配

**Proto 文件分析**:

```protobuf
// scale_offset_record_pytorch.proto - 无 quant_result_path 字段
message SingleLayerRecord {
    optional float scale_d = 1;
    optional int32 offset_d = 2;
    repeated float scale_w = 3;
    repeated int32 offset_w = 4;
    // ... 其他字段
    // ❌ 无 quant_result_path 字段定义
}
```

**结论**: `records['quant_result_path']` 的数据来源不存在于标准 record 文件结构中。

### 3. 入口点可达性分析

```
┌─────────────────────────────────────────────────────────────┐
│                    入口点可达性分析                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  公共 API (__all__)                                         │
│  ├── create_quant_config                                   │
│  ├── quantize_model                                        │
│  ├── save_model                                            │
│  ├── restore_quant_retrain_model  ←── VULN-SEC-001 在此处   │
│  ├── ...                                                   │
│  └── ❌ get_layer_quant_params 未导出                       │
│                                                             │
│  调用路径搜索:                                              │
│  quantize_tool.py ──────────────→ 无调用                   │
│  quant_calibration_interface.py → 无调用                   │
│  prune_interface.py ────────────→ 无调用                   │
│  distillation_interface.py ─────→ 无调用                   │
│  custom_op/utils.py ────────────→ 仅导入，无使用           │
│                                                             │
│  结论: 无可达入口点                                         │
└─────────────────────────────────────────────────────────────┘
```

## 攻击路径分析

### 理论攻击路径 (不存在)

```
理论攻击链 (假设存在调用):
用户输入 (record 文件)
    ↓
parse_record_file() [不存在 quant_result_path 字段]
    ↓
records['quant_result_path'] [字段不存在]
    ↓
get_layer_quant_params() [从未被调用]
    ↓
torch.load(weights_only=False)
    ↓
pickle 反序列化 [SINK]
    ↓
RCE
```

### 实际可达性: **不可达**

| 步骤 | 状态 | 说明 |
|------|------|------|
| 用户提供 record 文件 | 可能 | 用户可提供 record 文件 |
| record 包含 quant_result_path | **不可能** | proto 无此字段定义 |
| 调用 get_layer_quant_params | **不可能** | 无任何代码调用 |
| torch.load 触发 | **不可能** | 前序步骤均不可达 |

## PoC 构建分析

### 结论: 无法构建有效 PoC

**原因**:

1. **无调用入口**: 没有任何公共 API 或内部代码调用 `get_layer_quant_params`
2. **数据结构缺失**: 标准 record 文件格式不包含 `quant_result_path` 字段
3. **仅导入未使用**: `custom_op/utils.py` 导入后未实际使用

### 如果假设存在调用 (仅理论分析)

```python
# 理论攻击思路 (实际无法执行)
# 1. 需要 records 字典包含 quant_result_path 键
# 2. 需要有人调用 get_layer_quant_params(records, layer_name)
# 3. 需要恶意 .pth 文件

records = {
    'quant_result_path': '/path/to/malicious.pth',
    'layer_name': {...}
}
# 由于无调用代码，此攻击无法触发
```

## 影响评估

### 实际风险评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **代码安全性** | Critical | torch.load(weights_only=False) 存在 RCE 风险 |
| **可达性** | None | 无任何调用路径 |
| **可控性** | N/A | 无入口点无法评估 |
| **实际风险** | **Low** | 未使用代码，无法被触发 |

### 与 VULN-SEC-001 的对比

| 漏洞 | VULN-SEC-001 | VULN-SEC-002 |
|------|--------------|--------------|
| 位置 | model_util.py | module_based_record_parser.py |
| 入口 API | restore_quant_retrain_model | **无入口** |
| 调用路径 | 存在完整调用链 | **无调用** |
| 实际风险 | **Critical** | **Low (Dead Code)** |
| 可利用性 | 可利用 | **不可利用** |

## 最终判定

### 漏洞状态: **低风险 - 未使用代码**

**判定依据**:

1. ✅ 代码存在安全缺陷 (torch.load weights_only=False)
2. ❌ 无任何调用路径
3. ❌ 不在公共 API 中导出
4. ❌ Proto 数据结构不支持所需字段
5. ❌ 仅导入未使用

### 建议: 删除未使用代码

```python
# 建议删除整个文件或移除未使用的导入:
# amct_pytorch/graph_based_compression/amct_pytorch/parser/module_based_record_parser.py

# 以及移除 custom_op/utils.py 中的导入:
# from ...amct_pytorch.parser.module_based_record_parser import get_layer_quant_params
```

## 修复建议

### 1. 立即行动: 删除未使用代码

```bash
# 删除未使用的解析器文件
rm amct_pytorch/graph_based_compression/amct_pytorch/parser/module_based_record_parser.py

# 移除 utils.py 中的导入
# 删除第 24 行的导入语句
```

### 2. 代码审计建议

建议审计以下内容:

- 检查所有 `parser/` 目录下的文件使用情况
- 清理所有未使用的导入
- 确保 `custom_op/utils.py` 导入的函数都被实际使用

### 3. 预防性修复 (如果保留代码)

如果该函数在未来可能被使用，应修复为:

```python
def get_layer_quant_params(records, layer_name):
    quant_result_path = records.get('quant_result_path')
    
    # 强制安全加载
    load_kwargs = {'weights_only': True}
    quant_params = torch.load(quant_result_path, **load_kwargs)
    return quant_params.get(layer_name)
```

## 参考链接

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [PyTorch Security: weights_only Parameter](https://pytorch.org/docs/stable/generated/torch.load.html)
- [Dead Code Analysis Best Practices](https://owasp.org/www-community/vulnerabilities/Use_of_obsolete_code)

## 验证日期

2026-04-23

## 验证者

Automated Vulnerability Scanner + Deep Analysis
