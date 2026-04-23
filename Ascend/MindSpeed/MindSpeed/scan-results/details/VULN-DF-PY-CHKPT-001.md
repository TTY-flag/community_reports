# VULN-DF-PY-CHKPT-001：Checkpoint加载Pickle反序列化漏洞致远程代码执行

## 概要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-PY-CHKPT-001 |
| **类型** | 反序列化 (CWE-502) |
| **严重性** | Critical |
| **CVSS评分** | 9.8 (Critical) |
| **文件** | `mindspeed/checkpointing.py` |
| **函数** | `_load_base_checkpoint` |
| **行号** | 277, 284, 310 |

## 漏洞描述

`mindspeed/checkpointing.py` 中的 `_load_base_checkpoint` 函数使用 `torch.load()` 反序列化 checkpoint 文件，但未设置 `weights_only=True` 参数。PyTorch 的 `torch.load()` 函数内部使用 Python 的 `pickle` 模块，在反序列化过程中可执行任意代码。这导致加载不可信 checkpoint 文件时存在严重的远程代码执行漏洞。

## 漏洞代码

### 位置 1：第 277 行
```python
state_dict = torch.load(checkpoint_name, map_location='cpu')
```

### 位置 2：第 284 行
```python
ema_state_dict = torch.load(checkpoint_name + ".ema", map_location='cpu')
```

### 位置 3：第 310 行
```python
state_dict = torch.load(checkpoint_name, map_location='cpu')
```

## 数据流分析

```
数据源: load_dir (函数参数，半可信)
    |
    v
get_checkpoint_name(load_dir, iteration, release, ...)
    |
    v
checkpoint_name (构造的文件路径)
    |
    v
torch.load(checkpoint_name, map_location='cpu')  <-- 危险点：不安全反序列化
```

### 入口点追踪

1. **CLI 参数**：用户提供 `--load <path>` 或 `--save <path>` 参数
2. **load_checkpoint()**：调用时传入 `load_dir = args.load`
3. **_load_base_checkpoint(load_dir, ...)**：接收 `load_dir` 作为参数
4. **get_checkpoint_name()**：从 `load_dir` 构造 checkpoint 文件路径
5. **torch.load()**：无安全保护反序列化 checkpoint 文件

## 攻击向量

1. **外部 Checkpoint**：用户从不可信来源下载 checkpoint 文件（如 HuggingFace Hub、模型仓库、第三方分享）
2. **恶意 Payload**：checkpoint 文件包含恶意 pickle payload
3. **代码执行**：当 `torch.load()` 反序列化文件时，任意代码被执行

### 概念验证

攻击者可构造恶意 checkpoint 文件：

```python
import torch
import pickle
import os

class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

# 创建恶意 checkpoint
checkpoint = {
    'model': MaliciousPayload(),
    'args': None,
    'iteration': 1
}
torch.save(checkpoint, 'malicious_checkpoint.pt')
```

加载此 checkpoint 时：
```bash
python -m mindspeed.run --load ./malicious_checkpoint.pt
```
`id > /tmp/pwned` 命令将被执行。

## 影响

| 影响类别 | 严重性 | 描述 |
|----------|--------|------|
| **远程代码执行** | Critical | 以加载 checkpoint 进程的权限执行任意代码 |
| **系统入侵** | Critical | 若以高权限运行，可完全控制系统 |
| **数据泄露** | High | 可访问训练数据、模型权重和凭证 |
| **模型完整性** | High | 模型权重可被篡改以植入后门 |

## 代码库证据

### 未使用安全替代方案
漏洞文件未使用 `weights_only=True`：
```bash
# 在 checkpointing.py 中搜索 weights_only 返回无匹配
```

### 存在安全实现示例
同一代码库中存在安全实现模式，位于 `mindspeed/mindspore/third_party/transformers/modeling_utils.py`：
```python
weights_only: bool = True,
...
weights_only=weights_only,
```

## 根因分析

1. **缺少安全参数**：未使用 `weights_only=True` 参数，该参数可限制反序列化仅处理张量数据
2. **无完整性验证**：无 checksum 或签名验证 checkpoint 文件
3. **无来源验证**：无 checkpoint 来源的白名单或允许列表
4. **默认不安全行为**：PyTorch 默认行为不安全，需显式启用安全选项

## 修复建议

### 主要修复：添加 weights_only=True

```python
# 第 277 行 - 修复前
state_dict = torch.load(checkpoint_name, map_location='cpu')

# 第 277 行 - 修复后
state_dict = torch.load(checkpoint_name, map_location='cpu', weights_only=True)
```

同样修复第 284 和 310 行。

### 次要修复

1. **添加文件完整性验证**：
```python
import hashlib

def verify_checkpoint_integrity(checkpoint_path, expected_hash=None):
    if expected_hash is None:
        return True  # 无哈希时跳过验证
    with open(checkpoint_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    return file_hash == expected_hash
```

2. **添加来源验证**：
```python
ALLOWED_CHECKPOINT_SOURCES = [
    "https://huggingface.co/",
    "https://modelscope.cn/",
    # 添加可信来源
]

def validate_checkpoint_source(path):
    # 检查路径是否来自可信来源
    pass
```

3. **添加安全加载包装器**：
```python
def safe_torch_load(path, **kwargs):
    """带安全检查的安全加载 checkpoint。"""
    kwargs.setdefault('weights_only', True)
    kwargs.setdefault('map_location', 'cpu')
    return torch.load(path, **kwargs)
```

## 受影响组件

| 组件 | 文件 | 函数 | 严重性 |
|------|------|------|--------|
| Checkpoint 加载 | mindspeed/checkpointing.py | _load_base_checkpoint | Critical |
| EMA Checkpoint 加载 | mindspeed/checkpointing.py | _load_base_checkpoint | Critical |
| 旧版 Checkpoint 加载 | mindspeed/checkpointing.py | _load_base_checkpoint | Critical |

## 相关漏洞

- **CWE-502**：不可信数据反序列化
- **CWE-915**：动态确定对象属性的不当控制修改

## 参考资料

- [PyTorch 安全公告：torch.load weights_only](https://pytorch.org/docs/stable/generated/torch.load.html)
- [CWE-502：不可信数据反序列化](https://cwe.mitre.org/data/definitions/502.html)
- [PyTorch pickle 安全风险](https://github.com/pytorch/pytorch/security/advisories)

## 验证步骤

1. 应用 `weights_only=True` 修复
2. 运行现有测试确保兼容性
3. 用 checkpoint 文件测试验证加载仍正常工作
4. 用恶意 checkpoint 测试验证代码执行被阻止

## 状态

- [ ] 漏洞已确认
- [ ] 修复已实施
- [ ] 测试通过
- [ ] 代码审查完成
- [ ] 安全审查完成

---
*由安全扫描器于 2026-04-20 生成*