# VULN-SEC-001 深度利用分析报告

## 漏洞概述

**CWE-502**: Deserialization of Untrusted Data（不可信数据的反序列化）

**漏洞类型**: Unsafe Pickle Deserialization（不安全的 Pickle 反序列化）

**严重性**: High → Critical

**状态**: CONFIRMED（真实漏洞）

**描述**: `torch.load()` 在 PyTorch 2.1.0+ 版本中被显式设置为 `weights_only=False`，允许任意 pickle 反序列化。用户通过 API 提供 `pth_file` 参数，恶意 `.pth` 文件可导致远程代码执行（RCE）。

---

## 漏洞位置

- **文件**: `amct_pytorch/graph_based_compression/amct_pytorch/utils/model_util.py`
- **行号**: 139-143
- **函数**: `load_pth_file()`

**漏洞代码片段**:
```python
def load_pth_file(model, pth_file, state_dict_name):
    """
    Function: load pth file to model
    """
    load_kwargs = {'map_location': torch.device('cpu')}
    if version_higher_than(torch.__version__, '2.1.0'):
        load_kwargs['weights_only'] = False  # <-- 危险：显式禁用安全加载模式
    checkpoint = torch.load(pth_file, **load_kwargs)  # <-- SINK：pickle 反序列化
    ...
```

---

## 攻击路径分析

### 入口点

漏洞通过以下 3 个公开 API 入口点可达：

| API 函数 | 文件位置 | 行号 | pth_file 参数来源 |
|---------|---------|------|------------------|
| `restore_quant_retrain_model()` | `quantize_tool.py` | 431 | 用户直接输入 |
| `restore_prune_retrain_model()` | `prune_interface.py` | 101 | 用户直接输入 |
| `restore_compressed_retrain_model()` | `prune_interface.py` | 292 | 用户直接输入 |

### 数据流追踪

**完整攻击路径**:

```
用户输入 (pth_file 字符串)
    │
    ▼
[入口点 API 函数]
    │ restore_quant_retrain_model(config_file, model, record_file, input_data, pth_file, ...)
    │ restore_prune_retrain_model(model, input_data, record_file, config_defination, pth_file, ...)
    │ restore_compressed_retrain_model(model, input_data, config_defination, record_file, pth_file, ...)
    │
    ▼
os.path.realpath(pth_file)  -- 仅做路径规范化，无安全验证
    │
    ▼
load_pth_file(model, pth_file, state_dict_name)
    │
    ▼
version_higher_than(torch.__version__, '2.1.0') 检查
    │ 条件为 True (PyTorch 2.1.0+)
    ▼
load_kwargs['weights_only'] = False  -- 显式禁用安全模式
    │
    ▼
torch.load(pth_file, **load_kwargs)  -- [SINK]
    │
    ▼
pickle.loads()  -- 内部调用，反序列化任意 Python 对象
    │
    ▼
任意代码执行 (RCE)
```

### 攻击向量

**攻击前提条件**:
1. 用户使用 PyTorch 2.1.0+ 版本
2. 用户调用任一受影响的 API 函数
3. 攻击者能够提供或控制 `pth_file` 参数指向的文件路径

**攻击者如何利用此漏洞**:

1. **恶意 .pth 文件构造**: 
   - PyTorch `.pth` 文件本质是使用 pickle 序列化的 Python 对象
   - pickle 模块允许在序列化数据中嵌入任意 Python 代码
   - 通过 `__reduce__` 方法可以在反序列化时执行任意命令

2. **攻击场景**:
   - **场景 A**: 攻击者提供"预训练模型"下载链接，受害者使用该模型文件调用 API
   - **场景 B**: 攻击者入侵模型仓库/共享平台，替换合法模型文件为恶意版本
   - **场景 C**: 内部威胁，恶意员工将恶意代码注入训练流程
   - **场景 D**: 模型文件传输被中间人攻击篡改

3. **PyTorch 安全机制被绕过**:
   - PyTorch 2.1.0+ 引入 `weights_only=True` 作为安全加载模式
   - 该模式仅加载张量数据，禁止 arbitrary pickle 反序列化
   - 本代码显式设置 `weights_only=False`，完全绕过此安全机制

---

## PoC 构建思路

**警告**: 此部分仅描述攻击思路，不提供完整可执行代码。

### 攻击思路概述

1. **构造恶意 .pth 文件**:
   - 创建一个包含 `__reduce__` 方法的恶意类
   - `__reduce__` 返回 `(os.system, ('命令'))` 形式的 tuple
   - 使用 `torch.save()` 或 `pickle.dump()` 保存该对象

2. **触发反序列化**:
   - 将恶意文件路径作为 `pth_file` 参数
   - 调用 `restore_quant_retrain_model()` 或其他受影响 API
   - 当 `torch.load()` 执行时，恶意代码自动运行

3. **攻击效果示例**:
   - 反弹 shell 获取系统访问权限
   - 读取敏感文件（密钥、配置、数据）
   - 植入后门或持久化恶意软件
   - 窃取训练数据或模型参数

### 关键技术点

- PyTorch `.pth` 文件格式允许嵌入任意可序列化 Python 对象
- `pickle` 的 `__reduce__` 协议是执行任意代码的标准方法
- 代码在 `torch.load()` 调用时立即执行，无需额外触发
- 攻击代码运行在调用进程的权限上下文中

---

## 影响评估

### 受影响组件

**直接受影响的 API**:

```python
# quantize_tool.py
restore_quant_retrain_model(config_file, model, record_file, input_data, pth_file, state_dict_name=None)

# prune_interface.py  
restore_prune_retrain_model(model, input_data, record_file, config_defination, pth_file, state_dict_name=None)
restore_compressed_retrain_model(model, input_data, config_defination, record_file, pth_file, state_dict_name=None)
```

**导出位置**: `amct_pytorch/graph_based_compression/amct_pytorch/__init__.py`

```python
'restore_quant_retrain_model', 'restore_prune_retrain_model', 'restore_compressed_retrain_model'
```

**受影响的模块**: `graph_based_compression` 模块（高风险模块）

### 攻击后果

| 影响级别 | 具体后果 |
|---------|---------|
| **Critical** | 远程代码执行 (RCE) - 完全控制受害者系统 |
| **High** | 权限提升 - 以受害者进程权限执行任意命令 |
| **High** | 数据窃取 - 读取训练数据、模型参数、系统文件 |
| **High** | 供应链攻击 - 污染共享模型仓库影响下游用户 |
| **Medium** | 横向移动 - 以受害者身份访问其他系统资源 |

### 攻击场景分析

1. **ML 研究员/工程师**: 使用公开模型文件调用 API，被植入恶意代码
2. **企业环境**: 内部模型共享平台被污染，所有使用者面临风险
3. **生产部署**: 模型加载服务使用恶意文件，导致服务器被入侵
4. **CI/CD 管道**: 自动化训练流程加载恶意模型，导致构建环境被控制

---

## 修复建议

### 方案 1: 使用 weights_only=True（推荐）

**修改位置**: `model_util.py` 第 139-142 行

**修改前**:
```python
load_kwargs = {'map_location': torch.device('cpu')}
if version_higher_than(torch.__version__, '2.1.0'):
    load_kwargs['weights_only'] = False
checkpoint = torch.load(pth_file, **load_kwargs)
```

**修改后**:
```python
load_kwargs = {'map_location': torch.device('cpu')}
if version_higher_than(torch.__version__, '2.1.0'):
    load_kwargs['weights_only'] = True  # 安全加载模式
checkpoint = torch.load(pth_file, **load_kwargs)
```

**注意事项**:
- `weights_only=True` 仅加载张量和必要元数据
- 如果 `.pth` 文件包含自定义对象，需要额外处理
- 需要测试确保现有模型文件兼容性

### 方案 2: 添加文件来源验证

在调用 `load_pth_file()` 前验证 `pth_file` 来源：

```python
def load_pth_file(model, pth_file, state_dict_name):
    # 添加安全检查
    if not is_path_in_trusted_directory(pth_file):
        raise SecurityError("pth_file must be from trusted source")
    
    # 可选：验证文件签名/哈希
    if not verify_file_integrity(pth_file):
        raise SecurityError("pth_file integrity check failed")
    
    # 使用安全加载
    load_kwargs = {'map_location': torch.device('cpu'), 'weights_only': True}
    ...
```

### 方案 3: 使用 safetensors 格式替代

推荐使用 HuggingFace 的 `safetensors` 格式，该格式不使用 pickle：

```python
from safetensors.torch import load_file

def load_pth_file_safe(model, pth_file, state_dict_name):
    if pth_file.endswith('.safetensors'):
        state_dict = load_file(pth_file)
    else:
        # 对旧格式使用 weights_only=True
        load_kwargs = {'map_location': torch.device('cpu'), 'weights_only': True}
        state_dict = torch.load(pth_file, **load_kwargs)
    ...
```

### 方案 4: 迁移指南

对于用户和开发者：

1. **短期**: 立即将 `weights_only=False` 改为 `weights_only=True`
2. **中期**: 添加文件来源验证机制
3. **长期**: 迁移到 `safetensors` 格式，完全消除 pickle 风险

---

## 参考链接

- **CWE-502**: https://cwe.mitre.org/data/definitions/502.html
- **PyTorch Security**: https://pytorch.org/docs/stable/generated/torch.load.html
- **weights_only 参数文档**: https://pytorch.org/docs/stable/notes/serialization.html#weights-only-loading
- **safetensors 格式**: https://github.com/huggingface/safetensors
- **PyTorch Pickle RCE 历史**: CVE-2023-39309, 相关安全公告
- **ML Model Security**: https://github.com/usnistgov/ML-Model-Security

---

## 结论

**VULN-SEC-001 是一个真实的严重安全漏洞**，攻击者可以通过恶意 `.pth` 文件实现远程代码执行。该漏洞的根源是代码显式禁用了 PyTorch 2.1.0+ 引入的安全加载机制 (`weights_only=True`)。

建议立即修复，优先采用方案 1（启用 `weights_only=True`），并考虑长期迁移到 `safetensors` 格式以彻底消除 pickle 反序列化风险。
