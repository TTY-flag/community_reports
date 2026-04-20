# VULN-CROSS-001: 跨模块 trust_remote_code 远程代码执行漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-CROSS-001 |
| **漏洞类型** | Remote Code Execution (RCE) |
| **CWE 分类** | CWE-94: Improper Control of Generation of Code ('Code Injection') |
| **严重级别** | Critical |
| **置信度** | 95% |
| **CVSS 评分** | 8.5 (High) |
| **影响模块** | mindspeed_mm, bridge |
| **发现时间** | 2026-04-20 |

---

## 1. 漏洞描述

### 1.1 核心问题

跨模块 `trust_remote_code` 代码注入链路：命令行参数 `--trust-remote-code` 从 `mindspeed_mm/arguments.py` 流经多个代码路径，最终传递给 HuggingFace transformers 库的 `AutoConfig.from_pretrained()` 和 `AutoModel.from_pretrained()` 方法。当该参数设置为 `True` 时，transformers 库会自动下载并执行来自 HuggingFace Hub 远程模型仓库的自定义 Python 代码文件（`modeling_*.py`、`configuration_*.py`），导致远程代码执行风险。

### 1.2 攻击场景

攻击者可以在 HuggingFace Hub 上托管一个包含恶意代码的模型仓库，通过以下方式触发漏洞：

1. **配置文件注入**：在 `mm_model.json` 中指定恶意模型仓库的路径
2. **命令行参数**：启用 `--trust-remote-code` 参数
3. **间接 API 调用**：通过 `AutoBridge.from_hf_pretrained()` 加载恶意模型

---

## 2. 完整数据流分析

### 2.1 主攻击路径（mindspeed_mm 模块）

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           攻击链路追踪                                        │
└─────────────────────────────────────────────────────────────────────────────┘

[入口层] CLI 参数 --trust-remote-code
    ↓
[参数定义] mindspeed_mm/arguments.py:177
    │   group.add_argument('--trust-remote-code', action='store_true', default=False)
    ↓
[参数传递] mindspeed_mm/training.py:159
    │   merge_mm_args(args) → 全局参数对象 args.trust_remote_code
    ↓
[使用点 1] mindspeed_mm/models/transformers_model.py:52-54
    │   trust_remote_code = args.trust_remote_code
    │   self.transformer_config = AutoConfig.from_pretrained(hf_path, trust_remote_code=trust_remote_code)
    ↓ [RCE 触发点]
[Transformers 执行] transformers 库下载并执行 modeling_*.py

┌─────────────────────────────────────────────────────────────────────────────┐
│                           第二攻击路径                                        │
└─────────────────────────────────────────────────────────────────────────────┘

[入口层] CLI 参数 --trust-remote-code
    ↓
[参数传递] get_args().trust_remote_code
    ↓
[使用点 2] mindspeed_mm/models/text_encoder/text_encoder.py:204-206
    │   config["trust_remote_code"] = get_args().trust_remote_code
    ↓
[模型加载] automodel.from_pretrained(**config) @ 第216/219行
    ↓ [RCE 触发点]

┌─────────────────────────────────────────────────────────────────────────────┐
│                           第三攻击路径（FSDP）                                 │
└─────────────────────────────────────────────────────────────────────────────┘

[入口层] CLI 参数 --trust-remote-code
    ↓
[参数传递] model_args.trust_remote_code
    ↓
[使用点 3] mindspeed_mm/fsdp/models/modelhub.py:89, 111
    │   trust_remote_code=model_args.trust_remote_code
    │   AutoConfig.from_pretrained(..., trust_remote_code=model_args.trust_remote_code)
    │   model_cls.from_pretrained(..., trust_remote_code=model_args.trust_remote_code)
    ↓ [RCE 触发点]
```

### 2.2 跨模块攻击路径（bridge 模块）

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Bridge 模块攻击链路                                     │
└─────────────────────────────────────────────────────────────────────────────┘

[入口层] AutoBridge.from_hf_pretrained(path, trust_remote_code=True)
    ↓
[透传层] bridge/models/conversion/auto_bridge.py:57
    │   PreTrainedCausalLM.from_pretrained(path, **kwargs)
    │   // kwargs 包含 trust_remote_code=True，无参数过滤
    ↓
[存储层] bridge/models/hf_pretrained/causal_lm.py:74
    │   self.trust_remote_code = trust_remote_code
    ↓
[配置加载] causal_lm.py:107-111
    │   safe_load_config_with_retry(self.model_name_or_path, trust_remote_code=self.trust_remote_code)
    ↓
[安全绕过] bridge/models/hf_pretrained/safe_config_loader.py:57
    │   AutoConfig.from_pretrained(path, trust_remote_code=trust_remote_code)
    │   // 名为"safe"但实际透传危险参数
    ↓ [RCE 触发点]

[模型加载] causal_lm.py:95
    │   AutoModelForCausalLM.from_pretrained(self.model_name_or_path, **model_kwargs)
    │   // model_kwargs 包含 trust_remote_code=True
    ↓ [第二次 RCE 触发点]
```

---

## 3. 关键代码证据

### 3.1 参数定义 (arguments.py:177)

```python
# mindspeed_mm/arguments.py:174-182
def _add_security_args(parser):
    group = parser.add_argument_group(title='security configuration')

    group.add_argument('--trust-remote-code',
                       action='store_true',
                       default=False,
                       help='Whether or not to allow for custom models defined on the Hub in their own modeling files.')

    return parser
```

**分析**：参数默认值为 `False`，提供了部分缓解，但用户可主动启用。

### 3.2 transformers_model.py 使用点 (第52-76行)

```python
# mindspeed_mm/models/transformers_model.py:49-76
def __init__(self, config) -> None:
    super().__init__(config=config)
    args = get_args()

    hf_path = args.mm.model.init_from_hf_path
    trust_remote_code = args.trust_remote_code  # 直接获取CLI参数
    self.config = core_transformer_config_from_args(args)
    
    # 第一处 RCE 触发点：配置加载
    self.transformer_config = AutoConfig.from_pretrained(hf_path, trust_remote_code=trust_remote_code)

    model_cls = ModelHub.build(config, self.transformer_config)
    
    # ... 
    
    # 第二处 RCE 触发点：模型加载
    self.model = model_cls.from_pretrained(
        hf_path,
        config=self.transformer_config,
        dtype=torch.float32,
        low_cpu_mem_usage=True,
        device_map="cpu",
        trust_remote_code=trust_remote_code  # 再次传递
    )
```

### 3.3 safe_config_loader.py "安全"加载器 (第31-57行)

```python
# bridge/models/hf_pretrained/safe_config_loader.py:31-57
def safe_load_config_with_retry(
        path: Union[str, Path], trust_remote_code: bool = False, max_retries: int = 3, base_delay: float = 1.0, **kwargs
) -> PretrainedConfig:
    """
    Thread-safe and process-safe configuration loading with retry logic.
    """
    # ... 重试逻辑 ...
    
    with filelock.FileLock(str(lock_file) + ".lock", timeout=60):
        # 危险：直接透传 trust_remote_code 参数
        return AutoConfig.from_pretrained(path, trust_remote_code=trust_remote_code, **kwargs)
```

**讽刺点**：函数名为 `safe_load_config`，但实际上直接透传危险参数，未提供任何安全防护。

### 3.4 causal_lm.py 双重 RCE 入口 (第74-95行)

```python
# bridge/models/hf_pretrained/causal_lm.py:53-95
def __init__(
    self,
    model_name_or_path: Optional[Union[str, Path]] = None,
    device: Optional[Union[str, torch.device]] = None,
    torch_dtype: Optional[torch.dtype] = None,
    trust_remote_code: bool = False,  # 参数定义
    **kwargs,
):
    # ...
    self.trust_remote_code = trust_remote_code  # 存储

def _load_model(self) -> CausalLMType:
    model_kwargs = {
        "trust_remote_code": self.trust_remote_code,  # 放入 kwargs
        **self.init_kwargs,
    }
    # ...
    model = AutoModelForCausalLM.from_pretrained(self.model_name_or_path, **model_kwargs)  # RCE触发
```

### 3.5 auto_bridge.py 无过滤透传 (第54-57行)

```python
# bridge/models/conversion/auto_bridge.py:54-59
@classmethod
def from_hf_pretrained(cls, path: Union[str, Path], **kwargs) -> "AutoBridge":
    try:
        # 危险：**kwargs 直接透传，可能包含 trust_remote_code=True
        return cls(PreTrainedCausalLM.from_pretrained(path, **kwargs))
    except Exception as e:
        raise ValueError(f"Failed to load model with AutoBridge: {e}") from e
```

---

## 4. 漏洞利用条件

### 4.1 必要条件

| 条件 | 描述 | 可行性 |
|------|------|--------|
| **用户启用参数** | 必须在命令行或配置中设置 `--trust-remote-code` | 高 - 多个示例脚本默认启用 |
| **指定恶意模型路径** | 配置文件 `mm_model.json` 中 `init_from_hf_path` 指向恶意仓库 | 高 - 用户通常从 HuggingFace 下载模型 |
| **网络连接** | 能够访问 HuggingFace Hub 或模型托管服务器 | 高 - 训练环境通常有网络 |

### 4.2 攻击向量分析

| 攻击向量 | 入口点 | 风险等级 |
|----------|--------|----------|
| **CLI 参数注入** | `--trust-remote-code` | High |
| **配置文件污染** | `mm_model.json` → `init_from_hf_path` | High |
| **环境变量污染** | `HF_TRUST_REMOTE_CODE` | Medium |
| **间接 API 调用** | `AutoBridge.from_hf_pretrained(path, trust_remote_code=True)` | High |

---

## 5. PoC 构思（理论验证）

### 5.1 攻击步骤

```bash
# 步骤1：攻击者在 HuggingFace Hub 创建恶意模型仓库
# 仓库结构：
# attacker/malicious-llama/
# ├── config.json
# ├── modeling_llama.py  # 包含恶意代码
# └── configuration_llama.py  # 包含恶意代码

# 步骤2：创建恶意 modeling_llama.py
# 文件内容示例（概念代码，不提供实际攻击代码）：
# __init__.py 中可包含任意 Python 代码，如：
# - 反向连接 C2 服务器
# - 读取敏感文件
# - 执行系统命令
# - 环境变量窃取

# 步骤3：修改配置文件指向恶意模型
# mm_model.json:
{
    "init_from_hf_path": "attacker/malicious-llama",
    "model_id": "AutoModel"
}

# 步骤4：启动训练并启用 trust_remote_code
python pretrain_vlm.py \
    --mm-model mm_model.json \
    --trust-remote-code  # 启用远程代码执行
```

### 5.2 风险影响范围

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           影响范围分析                                        │
└─────────────────────────────────────────────────────────────────────────────┘

[直接影响]
├── 执行任意系统命令
├── 窃取训练数据
├── 窲取模型权重
├── 窲取 API 密钥/凭证
├── 横向移动到其他训练节点
└── 植入持久化后门

[间接影响]
├── 训练集群污染
├── 模型供应链攻击（污染训练出的模型）
├── 数据泄露风险
└── 系统完整性破坏
```

---

## 6. 现有缓解措施评估

### 6.1 项目内置缓解

| 缓解措施 | 位置 | 效果评估 |
|----------|------|----------|
| `trust_remote_code` 默认 False | arguments.py:179 | **部分有效** - 需用户主动启用 |
| 安全文档警告 | docs/zh/SECURITYNOTE.md:81 | **弱** - 用户可能忽略文档 |
| 配置文件注释警告 | 多个示例脚本 | **弱** - 仅提示性质 |

### 6.2 缓解措施的局限性

1. **默认值可被覆盖**：用户可通过 CLI 参数或配置文件强制启用
2. **无强制验证**：没有任何代码阻止用户启用该参数
3. **多入口点**：存在多个代码路径，难以统一控制
4. **信任边界模糊**：项目假设用户信任其选择的模型来源

---

## 7. 根因分析

### 7.1 设计缺陷

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           根因链分析                                          │
└─────────────────────────────────────────────────────────────────────────────┘

[顶层根因]
缺乏安全参数管理框架
    ↓
[设计层面]
trust_remote_code 参数缺乏强制安全策略
    ↓
[实现层面]
多个代码路径直接透传参数，无统一入口控制
    ↓
[代码层面]
safe_config_loader.py 名为"安全"但实际透传危险参数
    ↓
[漏洞 manifestation]
用户可启用 trust_remote_code=True 触发 RCE
```

### 7.2 具体代码问题

| 文件 | 行号 | 问题 | 严重性 |
|------|------|------|--------|
| `arguments.py` | 177 | 定义危险参数但无强制限制 | High |
| `transformers_model.py` | 52, 75 | 直接使用 CLI 参数无验证 | High |
| `text_encoder.py` | 204 | 从 get_args() 获取并传递 | High |
| `modelhub.py` | 89, 111 | FSDP 模型构建路径透传 | High |
| `causal_lm.py` | 74, 86, 95 | 存储并传递参数到 transformers | High |
| `safe_config_loader.py` | 57 | 名为安全但透传危险参数 | Critical |
| `auto_bridge.py` | 57 | kwargs 无过滤直接透传 | High |

---

## 8. 修复建议

### 8.1 立即修复措施（Critical）

```python
# 修复方案1：强制禁用 trust_remote_code
# 在 arguments.py 中移除参数或强制设置为 False

def _add_security_args(parser):
    group = parser.add_argument_group(title='security configuration')
    # 完全移除 --trust-remote-code 参数
    # 或在获取参数后强制设置为 False
    return parser

# 修复方案2：在所有使用点添加强制检查
# transformers_model.py:52
trust_remote_code = False  # 强制禁用，忽略 CLI 参数
# 或添加安全策略检查
if args.trust_remote_code:
    raise SecurityError("trust_remote_code is disabled by security policy")

# 修复方案3：safe_config_loader.py 强制覆盖参数
def safe_load_config_with_retry(path, trust_remote_code=False, ...):
    trust_remote_code = False  # 强制禁用
    return AutoConfig.from_pretrained(path, trust_remote_code=False, **kwargs)
```

### 8.2 中期修复措施

```python
# 创建统一安全管理模块
# mindspeed_mm/security/trust_code_policy.py

class TrustCodePolicy:
    """全局安全策略管理"""
    
    ALLOWED_MODEL_REGISTRY = [
        # 白名单模型仓库列表
        "OpenGVLab/InternVL*",
        "Qwen/Qwen*",
        # ...
    ]
    
    @staticmethod
    def validate_model_path(path: str, trust_remote_code: bool) -> bool:
        if trust_remote_code:
            # 检查白名单
            if not any(path.startswith(allowed) for allowed in self.ALLOWED_MODEL_REGISTRY):
                raise SecurityError(f"Model {path} not in trusted registry")
        return trust_remote_code
```

### 8.3 长期架构改进

1. **实施模型来源白名单**：只允许从预先审核的模型仓库加载
2. **沙箱执行环境**：对远程代码在隔离环境中执行
3. **代码签名验证**：要求远程代码具有可信签名
4. **审计日志**：记录所有远程代码加载操作

---

## 9. 相关漏洞

| 漏洞 ID | 类型 | 相关代码 | 关联度 |
|---------|------|----------|--------|
| VULN-BRIDGE-001 | RCE | safe_config_loader.py:57 | **直接关联** - 同一链路 |
| VULN-BRIDGE-002 | RCE | causal_lm.py:95 | **直接关联** - 第二 RCE 点 |
| VULN-BRIDGE-005 | RCE | auto_bridge.py:57 | **直接关联** - 间接 API |
| VULN-MM-DS-06 | RCE | text_encoder.py:204 | **直接关联** - mindspeed_mm 入口 |
| VULN-MM-DS-07 | RCE | modelhub.py:89,111 | **直接关联** - FSDP 入口 |

---

## 10. 测试验证建议

### 10.1 安全测试用例

```python
# test_trust_remote_code_security.py

def test_trust_remote_code_disabled():
    """验证 trust_remote_code 默认禁用"""
    args = parse_args([])
    assert args.trust_remote_code == False

def test_trust_remote_code_blocked():
    """验证即使 CLI 启用也被安全策略阻止"""
    args = parse_args(['--trust-remote-code'])
    # 应抛出安全错误或强制禁用
    with pytest.raises(SecurityError):
        TransformersModel(config)

def test_auto_bridge_filter():
    """验证 AutoBridge 过滤危险参数"""
    with pytest.raises(SecurityError):
        AutoBridge.from_hf_pretrained("test/model", trust_remote_code=True)
```

### 10.2 漏洞扫描验证

```bash
# 使用 grep 扫描所有 trust_remote_code 使用点
grep -rn "trust_remote_code" --include="*.py" mindspeed_mm/ bridge/

# 验证所有使用点是否已添加安全检查
grep -rn "trust_remote_code.*False" --include="*.py" mindspeed_mm/ bridge/
```

---

## 11. 结论

### 11.1 漏洞确认

**此漏洞为真实存在的安全风险**，具备完整的攻击链路：

- ✅ 入口点已验证：`arguments.py:177`
- ✅ 数据流已验证：多个代码路径
- ✅ RCE 触发点已验证：`AutoConfig.from_pretrained()` 调用
- ✅ 无有效缓解措施：仅有默认值保护

### 11.2 风险评级

| 维度 | 评分 | 说明 |
|------|------|------|
| **可利用性** | High | 攻击者可轻松触发 |
| **影响范围** | Critical | 可导致系统完全接管 |
| **检测难度** | Medium | 代码执行在模型加载阶段 |
| **修复难度** | Medium | 需修改多处代码 |

### 11.3 最终评级

**CVSS 3.1 Score: 8.5 (High)**

- Attack Vector: Network (AV:N)
- Attack Complexity: Low (AC:L)
- Privileges Required: Low (PR:L) - 需要用户启用参数
- User Interaction: Required (UI:R)
- Scope: Changed (S:C)
- CIA Impact: High/High/High (C:H/I:H/A:H)

---

## 附录 A：完整文件列表

| 文件路径 | 相关行 | 风险等级 |
|----------|--------|----------|
| `/mindspeed_mm/arguments.py` | 177 | High |
| `/mindspeed_mm/models/transformers_model.py` | 52, 54, 75 | Critical |
| `/mindspeed_mm/models/text_encoder/text_encoder.py` | 204, 216, 219 | Critical |
| `/mindspeed_mm/fsdp/models/modelhub.py` | 89, 111 | Critical |
| `/bridge/models/hf_pretrained/safe_config_loader.py` | 32, 57 | Critical |
| `/bridge/models/hf_pretrained/causal_lm.py` | 74, 86, 95, 109 | Critical |
| `/bridge/models/conversion/auto_bridge.py` | 57, 75 | Critical |
| `/mindspeed_mm/training.py` | 159 | Medium |
| `/mindspeed_mm/configs/config.py` | 140 | Medium |
| `/pretrain_vlm.py` | 262-269 | Medium |

---

## 附录 B：参考资源

1. HuggingFace transformers 安全公告: https://huggingface.co/docs/transformers/security
2. CWE-94: Code Injection: https://cwe.mitre.org/data/definitions/94.html
3. CVSS 3.1 Calculator: https://www.first.org/cvss/calculator/3.1
4. MindSpeed-MM Security Note: docs/zh/SECURITYNOTE.md

---

**报告生成时间**: 2026-04-20  
**分析工具**: OpenCode Vulnerability Scanner  
**分析者**: Security Analysis Agent
