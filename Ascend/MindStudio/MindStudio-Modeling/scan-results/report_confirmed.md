# 漏洞扫描报告 — 已确认漏洞

**项目**: MindStudio-Modeling  
**扫描时间**: 2026-04-21T04:10:56.724Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

MindStudio-Modeling 是一个 AI 模型推理框架，本次扫描发现了 **8 个已确认的严重漏洞**，全部属于 **CWE-94 (代码注入)** 类别。这些漏洞形成了一个完整的攻击链，允许攻击者通过恶意 HuggingFace/ModelScope 模型仓库实现 **远程代码执行 (RCE)**。

### 核心风险

所有 8 个漏洞都源于同一个根本原因：**`trust_remote_code` 参数的不安全使用**。该参数在以下三个层面被自动启用：

1. **默认值层 (SEC-011)**: `ModelConfig.trust_remote_code = True` 作为默认值，用户无需任何操作就会启用远程代码执行
2. **配置层 (SEC-012)**: `ConfigResolver` 自动为非原生支持的模型设置 `trust_remote_code=True`
3. **回退层 (SEC-001/DF-001)**: 当原生模型加载失败时，代码自动回退到 `trust_remote_code=True`

### 攻击路径

```
CLI args.model_id (用户输入)
    ↓
UserInputConfig.model_id
    ↓
ConfigResolver.__init__
    ↓ (自动设置 trust_remote_code=True)
AutoModelConfigLoader.load_config(model_id)
    ↓ (失败时自动回退)
AutoConfig.from_pretrained(model_id, trust_remote_code=True)
    ↓
下载恶意模型仓库的 configuration_xxx.py
    ↓
执行任意 Python 代码 → RCE
```

### 影响范围

- **攻击者**: 任何能控制 `model_id` 参数的用户（CLI 用户、API 调用者）
- **攻击条件**: 提供指向恶意 HuggingFace/ModelScope 仓库的 model_id
- **攻击后果**: 完全控制运行 MindStudio-Modeling 的服务器，可窃取数据、植入后门、破坏系统
- **CVSS 评分**: 9.8 (Critical) - AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

### 修复优先级

| 优先级 | 漏洞 | 修复建议 | 工作量 |
|--------|------|----------|--------|
| **P0** | SEC-011 | 将 `ModelConfig.trust_remote_code` 默认值改为 `False` | 1 行代码 |
| **P0** | SEC-001 | 移除自动回退机制，要求用户显式确认 | 5-10 行代码 |
| **P1** | SEC-012 | 移除 ConfigResolver 自动设置逻辑 | 3-5 行代码 |
| **P2** | SEC-002, SEC-003, DF-002, DF-012 | 添加用户确认和安全验证 | 10-20 行代码 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 8 | 36.4% |
| CONFIRMED | 8 | 36.4% |
| POSSIBLE | 3 | 13.6% |
| LIKELY | 3 | 13.6% |
| **总计** | **22** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 8 | 100.0% |
| **有效漏洞总计** | **8** | - |
| 误报 (FALSE_POSITIVE) | 8 | - |

### 1.3 Top 10 关键漏洞

1. **[SEC-011]** Remote Code Execution (Critical) - `tensor_cast/model_config.py:448` @ `ModelConfig` | 置信度: 90
2. **[SEC-001]** Remote Code Execution (Critical) - `tensor_cast/transformers/utils.py:258` @ `AutoModelConfigLoader.load_config` | 置信度: 85
3. **[DF-001]** Code Injection (Critical) - `tensor_cast/transformers/utils.py:255` @ `AutoModelConfigLoader.load_config` | 置信度: 85
4. **[SEC-012]** Remote Code Execution (Critical) - `tensor_cast/core/config_resolver.py:83` @ `ConfigResolver.__init__` | 置信度: 85
5. **[SEC-002]** Remote Code Execution (Critical) - `tensor_cast/transformers/model.py:185` @ `TransformerModel.__init__` | 置信度: 82
6. **[SEC-003]** Remote Code Execution (Critical) - `tensor_cast/transformers/utils.py:334` @ `AutoModelConfigLoader.try_to_load_model` | 置信度: 80
7. **[DF-002]** Code Injection (Critical) - `tensor_cast/transformers/utils.py:287` @ `AutoModelConfigLoader.try_to_load_model` | 置信度: 80
8. **[DF-012]** Code Injection (Critical) - `tensor_cast/transformers/model.py:185` @ `TransformerModel.__init__` | 置信度: 80

---

## 2. 攻击面分析

**入口点**: CLI 命令行参数 `--model_id`  
**数据流**: `args.model_id → UserInputConfig → ConfigResolver → AutoModelConfigLoader → AutoConfig.from_pretrained`  
**污点源**: 用户提供的 model_id（可以是本地路径或远程仓库 ID）  
**污点汇**: `AutoConfig.from_pretrained(model_id, trust_remote_code=True)`

---

## 3. Critical 漏洞 (8)

### [SEC-011] Remote Code Execution - ModelConfig (根本原因)

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 90/100 | **状态**: CONFIRMED

**位置**: `tensor_cast/model_config.py:448` @ `ModelConfig`

这是所有漏洞的根本原因。`ModelConfig` dataclass 的 `trust_remote_code` 默认值为 `True`，意味着用户无需任何操作就会启用远程代码执行。

**漏洞代码**:
```python
@dataclass
class ModelConfig:
    ...
    trust_remote_code: bool = True  # ← 危险的默认值
```

**修复建议**:
```python
trust_remote_code: bool = False  # 安全默认值
```

---

### [SEC-001] Remote Code Execution - AutoModelConfigLoader.load_config (触发点)

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `tensor_cast/transformers/utils.py:258-260`

这是主要的触发点。当原生模型加载失败时，代码自动回退到 `trust_remote_code=True`。

**漏洞代码**:
```python
try:
    hf_config = AutoConfig.from_pretrained(model_id)
except Exception:
    hf_config = AutoConfig.from_pretrained(model_id, trust_remote_code=True)
```

**修复建议**:
```python
try:
    hf_config = AutoConfig.from_pretrained(model_id)
except Exception:
    # 不要自动启用 trust_remote_code，要求用户显式确认
    raise SecurityError(
        "Model not natively supported. To load custom models, "
        "explicitly set trust_remote_code=True after verifying "
        "the model repository is trusted."
    )
```

---

### [SEC-012] Remote Code Execution - ConfigResolver.__init__

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `tensor_cast/core/config_resolver.py:83-85`

ConfigResolver 自动为非原生支持的模型设置 `trust_remote_code=True`。

**漏洞代码**:
```python
self.model_config.trust_remote_code = (
    not auto_loader.is_transformers_natively_supported
)
```

**修复建议**:
```python
# 移除自动设置逻辑，保留用户显式设置的值
# 或者添加安全警告
if not auto_loader.is_transformers_natively_supported:
    logger.warning(
        "Model is not natively supported. "
        "trust_remote_code must be explicitly enabled by user."
    )
```

---

### [SEC-002] Remote Code Execution - TransformerModel.__init__

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 82/100 | **状态**: CONFIRMED

**位置**: `tensor_cast/transformers/model.py:185-189`

模型加载时将 `trust_remote_code` 参数传递给 HuggingFace API。

**漏洞代码**:
```python
self._inner = auto_loader.load_model(
    self.hf_config,
    self.model_config.dtype,
    trust_remote_code=self.model_config.trust_remote_code,
)
```

---

### [SEC-003] Remote Code Execution - AutoModelConfigLoader.try_to_load_model

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 80/100 | **状态**: CONFIRMED

**位置**: `tensor_cast/transformers/utils.py:334-338`

`trust_remote_code` 通过 kwargs 传递到 AutoModel API。

**漏洞代码**:
```python
try:
    hf_model = AutoModel.from_config(*args, **kwarg)
except Exception:
    hf_model = AutoModelForCausalLM.from_config(*args, **kwarg)
```

---

### [DF-001] Code Injection - AutoModelConfigLoader.load_config

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED

与 SEC-001 相同的漏洞，从数据流分析视角确认。

---

### [DF-002] Code Injection - AutoModelConfigLoader.try_to_load_model

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 80/100 | **状态**: CONFIRMED

与 SEC-003 相同的漏洞，从数据流分析视角确认。

---

### [DF-012] Code Injection - TransformerModel.__init__

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 80/100 | **状态**: CONFIRMED

与 SEC-002 相同的漏洞，从数据流分析视角确认。

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| tensor_cast.core | 3 | 0 | 0 | 0 | 3 |
| tensor_cast.transformers | 5 | 0 | 0 | 0 | 5 |
| **合计** | **8** | **0** | **0** | **0** | **8** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-94 | 8 | 100.0% |

---

## 6. 修复建议

### 6.1 立即修复 (P0)

**SEC-011 - ModelConfig 默认值**

修改 `tensor_cast/model_config.py:448`:
```python
# 当前代码 (危险)
trust_remote_code: bool = True

# 修复后 (安全)
trust_remote_code: bool = False
```

**SEC-001 - 移除自动回退机制**

修改 `tensor_cast/transformers/utils.py:258-260`:
```python
# 当前代码 (危险)
try:
    hf_config = AutoConfig.from_pretrained(model_id)
except Exception:
    hf_config = AutoConfig.from_pretrained(model_id, trust_remote_code=True)

# 修复后 (安全)
try:
    hf_config = AutoConfig.from_pretrained(model_id)
except Exception as e:
    # 记录失败原因，不自动启用 trust_remote_code
    logger.error(f"Failed to load model config: {e}")
    raise ValueError(
        f"Model '{model_id}' is not natively supported. "
        "If you trust this model repository, explicitly set "
        "trust_remote_code=True in your configuration."
    )
```

### 6.2 高优先级修复 (P1)

**SEC-012 - 移除 ConfigResolver 自动设置**

修改 `tensor_cast/core/config_resolver.py:83-85`:
```python
# 当前代码 (危险)
self.model_config.trust_remote_code = (
    not auto_loader.is_transformers_natively_supported
)

# 修复后 (安全)
if not auto_loader.is_transformers_natively_supported:
    logger.warning(
        f"Model '{model_id}' is not natively supported by transformers. "
        "Remote code execution is disabled by default. "
        "Enable trust_remote_code explicitly only if you verify the repository."
    )
# 不自动修改 trust_remote_code，保留用户设置或默认值
```

### 6.3 增强安全 (P2)

**添加 model_id 验证**

修改 `cli/utils.py`:
```python
# 当前代码 (弱验证)
def check_string_valid(string: str, max_len=256):
    if not re.match(r"^[a-zA-Z0-9_/.-]+$", string):
        raise ValueError(...)

# 修复后 (增强验证)
def check_model_id_valid(model_id: str, max_len=256):
    # 检查长度
    if len(model_id) > max_len:
        raise ValueError(f"model_id too long (max {max_len})")
    
    # 如果是本地路径，检查是否在允许的目录内
    if os.path.exists(model_id):
        allowed_dirs = get_allowed_model_dirs()
        abs_path = os.path.abspath(model_id)
        if not any(abs_path.startswith(d) for d in allowed_dirs):
            raise ValueError("model_id path outside allowed directories")
    
    # 如果是远程 ID，验证格式
    else:
        if not re.match(r"^[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+$", model_id):
            raise ValueError("Invalid remote model_id format")
```

### 6.4 安全最佳实践

1. **信任模型白名单**: 维护一个已验证的可信模型仓库列表
2. **审计日志**: 记录所有 `trust_remote_code=True` 的使用情况
3. **沙箱执行**: 在隔离环境中执行非原生模型
4. **用户确认**: 在启用 `trust_remote_code` 前要求用户明确确认

---

## 7. 详细分析报告

每个已确认漏洞的详细分析报告位于：
- `scan-results/details/SEC-011.md` (主报告，包含完整漏洞链分析)
- `scan-results/details/SEC-001.md`
- `scan-results/details/SEC-012.md`
- `scan-results/details/SEC-002.md`
- `scan-results/details/SEC-003.md`
- `scan-results/details/DF-001.md`
- `scan-results/details/DF-002.md`
- `scan-results/details/DF-012.md`

---

**报告生成工具**: OpenCode Vulnerability Scanner  
**扫描完成时间**: 2026-04-21T04:15:00+08:00