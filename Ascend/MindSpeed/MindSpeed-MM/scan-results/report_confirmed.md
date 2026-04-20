# 漏洞扫描报告 — 已确认漏洞

**项目**: MindSpeed-MM
**扫描时间**: 2026-04-20T01:17:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描针对 MindSpeed-MM 项目（672 个 Python 文件）进行了全面漏洞检测，共发现 **25 个已确认漏洞**，其中 **14 个 Critical 级别**、**11 个 High 级别**。漏洞主要集中在 checkpoint 模块（11 个）和 mindspeed_mm 模块（9 个），涉及两类核心安全风险：

**核心风险分析**：
1. **远程代码执行（RCE）风险**：8 个漏洞（CWE-94）涉及 `trust_remote_code` 参数链路，当用户启用 `--trust-remote-code` 命令行参数时，HuggingFace transformers 库会自动下载并执行来自远程模型仓库的 Python 代码文件（`modeling_*.py`、`configuration_*.py`），攻击者可通过托管恶意模型实现任意代码执行。完整攻击链路从 CLI 参数 → arguments.py → transformers_model.py/text_encoder.py/modelhub.py → AutoConfig.from_pretrained/AutoModel.from_pretrained → 远程代码执行。

2. **不安全反序列化风险**：15 个漏洞（CWE-502）涉及 `torch.load()` 调用时未设置 `weights_only=True`，默认使用 pickle 反序列化机制，攻击者可构造恶意 `.pt` checkpoint 文件，在加载时触发任意代码执行。主要分布在 checkpoint 转换工具（mm_to_hf.py、hf_to_mm.py、save_load_utils.py）和 mindspeed_mm 的模型加载路径（vision encoder、feature dataset、VAE 等）。

**业务影响**：
- 在模型训练/推理场景中，用户加载第三方模型权重或使用公开模型仓库时存在被攻击风险
- checkpoint 转换工具被攻击者利用可影响整个模型转换流程的安全
- 攻击可导致训练环境被完全控制、敏感数据泄露、模型权重被篡改

**优先修复建议**：
1. 立即移除或严格限制 `--trust-remote-code` 参数的使用，添加显式安全警告
2. 所有 `torch.load()` 调用强制使用 `weights_only=True`，拒绝 pickle 反序列化
3. 对 checkpoint 转换工具添加来源验证和完整性检查机制

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 25 | 62.5% |
| POSSIBLE | 9 | 22.5% |
| LIKELY | 6 | 15.0% |
| **总计** | **40** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 14 | 56.0% |
| High | 11 | 44.0% |
| **有效漏洞总计** | **25** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-BRIDGE-001]** Remote Code Execution (Critical) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/hf_pretrained/safe_config_loader.py:57` @ `safe_load_config_with_retry` | 置信度: 95
2. **[VULN-BRIDGE-002]** Remote Code Execution (Critical) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/hf_pretrained/causal_lm.py:95` @ `_load_model` | 置信度: 95
3. **[VULN-BRIDGE-005]** Remote Code Execution (Critical) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/conversion/auto_bridge.py:54` @ `from_hf_pretrained` | 置信度: 95
4. **[VULN-DF-MM-CI-01]** code_injection (Critical) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/models/text_encoder/text_encoder.py:204` @ `_init_text_encoder` | 置信度: 95
5. **[VULN-DF-MM-CI-09]** code_injection (Critical) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/fsdp/models/modelhub.py:109` @ `build` | 置信度: 95
6. **[MM-CWE94-001]** Code Injection (Critical) - `mindspeed_mm/models/transformers_model.py:52` @ `__init__` | 置信度: 95
7. **[VULN-CHECKPOINT-001]** Unsafe Deserialization (Critical) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/vlm_model/mm_to_hf.py:92` @ `load_from_mm` | 置信度: 95
8. **[VULN-CHECKPOINT-002]** Unsafe Deserialization (Critical) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/vlm_model/mm_to_hf.py:107` @ `load_from_mm` | 置信度: 95
9. **[VULN-CHECKPOINT-004]** Unsafe Deserialization (Critical) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/sora_model/convert_utils/save_load_utils.py:36` @ `load_from_mm` | 置信度: 95
10. **[VULN-CROSS-001]** Remote Code Execution (Critical) - `mindspeed_mm/arguments.py:177` @ `_add_security_args` | 置信度: 95

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `load_model@bridge/models/hf_pretrained/causal_lm.py` | file | semi_trusted | 加载来自 HuggingFace 的模型权重，路径由用户通过配置文件或命令行指定，使用 safetensors 格式而非 pickle | AutoModelForCausalLM.from_pretrained 调用 |
| `safe_load_config_with_retry@bridge/models/hf_pretrained/safe_config_loader.py` | file | semi_trusted | 加载模型配置文件，路径由用户指定，信任等级取决于 trust_remote_code 参数 | AutoConfig.from_pretrained 调用 |
| `__init__@mindspeed_mm/configs/config.py` | file | untrusted_local | 用户通过命令行指定配置文件路径，文件内容由用户控制 | MMConfig 配置文件加载入口 |
| `get_sys_args_from_yaml@mindspeed_mm/configs/read_yaml_config.py` | file | untrusted_local | YAML 配置文件路径来自 sys.argv[1]，文件内容完全由用户控制，使用 yaml.safe_load 加载 | YAML 配置文件解析入口 |
| `get_datasamples@mindspeed_mm/data/data_utils/utils.py` | file | untrusted_local | 数据集文件路径来自用户配置，CSV/JSON/Parquet 文件内容由用户提供 | 数据集文件加载入口 |
| `_add_security_args@mindspeed_mm/arguments.py` | cmdline | semi_trusted | trust-remote-code 参数控制是否允许加载远程代码，默认为 False | 命令行参数定义 trust-remote-code |
| `file_legality_checker@mindspeed_mm/configs/config.py` | file | internal | 内部安全检查函数，验证路径合法性 | 文件路径安全验证 |
| `main@pretrain_vlm.py` | cmdline | semi_trusted | 训练脚本入口，由有权限的开发者/研究人员执行，配置文件和数据路径通过命令行参数传入 | 预训练脚本主入口 |
| `main@checkpoint/convert_cli.py` | cmdline | semi_trusted | 权重转换工具入口，由用户执行转换本地模型权重 | 权重转换命令行入口 |
| `test_audio_encoder@tests/ut/models/audio_encoder/test_audio_encoder_processor.py` | file | internal | 测试代码中使用 torch.load 加载预置的测试数据文件，非生产代码路径 | 测试中使用 torch.load |
| `import@examples/diffsynth/qwen_image_edit/qwen_image_edit_patch.py` | file | semi_trusted | 示例代码导入 pickle 模块，但未见直接 pickle.load 调用，属于潜在风险点 | pickle 模块导入（潜在风险） |
| `acquire_exitcode@verl_plugin/setup.py` | cmdline | trusted_admin | 插件安装脚本中的 subprocess.Popen，仅用于安装阶段，非运行时入口 | 安装脚本 subprocess 调用 |
| `acquire_exitcode@ci/access_control_test.py` | cmdline | trusted_admin | CI 测试脚本，仅用于自动化测试，非生产运行时入口 | CI 测试 subprocess 调用 |

**其他攻击面**:
- HuggingFace from_pretrained: 加载外部模型权重和配置
- Safetensors 文件加载: 模型权重存储格式
- YAML/JSON 配置文件解析: 用户训练配置
- CSV/JSON/Parquet 数据集文件: 训练数据加载
- trust_remote_code 参数: 控制远程代码加载
- 命令行参数: 训练脚本启动参数
- torch.load: 测试代码中使用（非生产路径）

---

## 3. Critical 漏洞 (14)

### [VULN-BRIDGE-001] Remote Code Execution - safe_load_config_with_retry

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/hf_pretrained/safe_config_loader.py:57` @ `safe_load_config_with_retry`
**模块**: bridge
**跨模块**: bridge,mindspeed_mm

**描述**: trust_remote_code parameter passed to AutoConfig.from_pretrained enables execution of arbitrary code from HuggingFace Hub repositories. When trust_remote_code=True, transformers library downloads and executes modeling_*.py and configuration_*.py files from remote model repositories without validation or sandboxing.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/hf_pretrained/safe_config_loader.py:57`)

```c
return AutoConfig.from_pretrained(path, trust_remote_code=trust_remote_code, **kwargs)
```

**达成路径**

User Input (model_name_or_path, trust_remote_code=True) -> PreTrainedCausalLM.__init__ -> safe_load_config_with_retry() -> AutoConfig.from_pretrained(path, trust_remote_code=True) -> RCE via downloaded modeling_*.py/configuration_*.py

**验证说明**: trust_remote_code参数直接传递给AutoConfig.from_pretrained，当启用时执行HuggingFace Hub远程代码。数据流完整：CLI --trust-remote-code -> PreTrainedCausalLM.__init__ -> safe_load_config_with_retry -> AutoConfig.from_pretrained(trust_remote_code=True) -> RCE。无任何验证或限制。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

**深度分析**

根因分析：`safe_config_loader.py:31-57` 定义的 `safe_load_config_with_retry()` 函数被设计为线程安全的配置加载工具，但第 57 行直接将 `trust_remote_code` 参数透传给 `AutoConfig.from_pretrained()`，未进行任何安全校验或限制。该函数被 `causal_lm.py:107-111` 的 `_load_config()` 方法调用，形成完整的 RCE 链路。

潜在利用场景：
1. 攻击者在 HuggingFace Hub 上托管一个包含恶意 `configuration_xxx.py` 的模型仓库
2. 用户运行训练脚本时指定 `--trust-remote-code` 参数和恶意模型名称
3. transformers 库下载并执行恶意配置代码，攻击者获得训练环境的完全控制权

修复建议：
- 移除 `trust_remote_code` 参数的透传逻辑，强制设为 `False`
- 或添加白名单机制，仅允许已验证的模型仓库启用远程代码加载
- 在 CLI 参数处理层添加显式安全警告，告知用户启用该参数的风险

---

### [VULN-BRIDGE-002] Remote Code Execution - _load_model

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/hf_pretrained/causal_lm.py:95` @ `_load_model`
**模块**: bridge
**跨模块**: bridge,mindspeed_mm

**描述**: trust_remote_code parameter passed to AutoModelForCausalLM.from_pretrained enables execution of arbitrary code from HuggingFace Hub repositories. This is the second RCE point in the model loading chain, triggered when the model weights are loaded.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/hf_pretrained/causal_lm.py:95`)

```c
model = AutoModelForCausalLM.from_pretrained(self.model_name_or_path, **model_kwargs)
```

**达成路径**

User Input -> PreTrainedCausalLM.__init__ -> trust_remote_code stored -> _load_model() -> AutoModelForCausalLM.from_pretrained(..., trust_remote_code=True) -> RCE

**验证说明**: trust_remote_code参数存储在self.trust_remote_code，传入model_kwargs，最终传递给AutoModelForCausalLM.from_pretrained。第二处RCE点，加载模型权重时触发。调用链完整。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

**深度分析**

根因分析：`causal_lm.py:80-101` 的 `_load_model()` 方法在第 85-88 行将 `self.trust_remote_code` 存储到 `model_kwargs` 字典中，然后第 95 行将其传递给 `AutoModelForCausalLM.from_pretrained()`。这是模型权重加载阶段的第二处 RCE 点，与配置加载阶段的 VULN-BRIDGE-001 形成双重攻击路径。

潜在利用场景：
1. 用户使用 `PreTrainedCausalLM.from_pretrained("malicious-model", trust_remote_code=True)` 加载模型
2. 第 74 行将 `trust_remote_code=True` 存储为实例属性
3. 当模型首次被访问时，`_load_model()` 触发，下载并执行恶意的 `modeling_xxx.py` 文件
4. 恶意代码可以窃取模型权重、注入后门、或直接执行任意系统命令

修复建议：
- 在 `causal_lm.py:58` 的 `__init__` 方法中，强制将 `trust_remote_code` 参数设为 `False`，忽略用户传入值
- 或在 `model_kwargs` 构建时（第 86 行）显式排除 `trust_remote_code` 参数

---

### [VULN-BRIDGE-005] Remote Code Execution - from_hf_pretrained

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/conversion/auto_bridge.py:54-59` @ `from_hf_pretrained`
**模块**: bridge
**跨模块**: bridge,mindspeed_mm

**描述**: AutoBridge.from_hf_pretrained passes **kwargs directly to PreTrainedCausalLM.from_pretrained, which can include trust_remote_code=True. This provides an indirect API for enabling RCE without explicit parameter validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/conversion/auto_bridge.py:54-59`)

```c
return cls(PreTrainedCausalLM.from_pretrained(path, **kwargs))
```

**达成路径**

User Input (path, kwargs with trust_remote_code=True) -> AutoBridge.from_hf_pretrained -> PreTrainedCausalLM.from_pretrained(path, trust_remote_code=True) -> RCE

**验证说明**: AutoBridge.from_hf_pretrained直接将**kwargs传递给PreTrainedCausalLM.from_pretrained，可包含trust_remote_code=True。提供间接API启用RCE，无参数验证。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

**深度分析**

根因分析：`auto_bridge.py:54-59` 的 `from_hf_pretrained()` 方法是一个间接 API 入口，直接将 `**kwargs` 透传给 `PreTrainedCausalLM.from_pretrained()`，没有任何参数过滤或安全检查。第 74-75 行的 `load_hf_weights()` 方法也存在类似问题，虽然读取了 `trust_remote_code` 属性，但仍传递给下游调用。

潜在利用场景：
1. 开发者使用 `AutoBridge.from_hf_pretrained("model", trust_remote_code=True)` 转换模型
2. 第 57 行调用 `PreTrainedCausalLM.from_pretrained()` 时 `trust_remote_code=True` 被包含在 kwargs 中
3. 这绕过了直接使用 `PreTrainedCausalLM` 的显式参数传递，更容易被忽略
4. 攻击者可通过恶意模型仓库实现 RCE

修复建议：
- 在 `from_hf_pretrained()` 方法中添加显式参数检查，拒绝 `trust_remote_code=True`
- 或在 kwargs 处理时强制移除 `trust_remote_code` 键
- 为 `AutoBridge` 类添加文档警告，说明该方法的潜在安全风险

---

### [VULN-DF-MM-CI-01] code_injection - _init_text_encoder

**严重性**: Critical（原评估: critical → 验证后: Critical） | **CWE**: CWE-94 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/models/text_encoder/text_encoder.py:204-216` @ `_init_text_encoder`
**模块**: mindspeed_mm

**描述**: trust_remote_code enables arbitrary code execution from HuggingFace Hub. When trust_remote_code=True, AutoConfig.from_pretrained and model.from_pretrained can load and execute arbitrary Python code from remote model repositories. The code path flows from CLI argument --trust-remote-code through get_args() to transformers.from_pretrained calls.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/models/text_encoder/text_encoder.py:204-216`)

```c
config["trust_remote_code"] = get_args().trust_remote_code\n...\nautomodel.from_pretrained(**config)
```

**达成路径**

[IN] CLI args --trust-remote-code -> arguments.py:177 -> get_args() -> text_encoder.py:204 -> transformers.AutoModel.from_pretrained(trust_remote_code=True) -> EXECUTES REMOTE CODE

**验证说明**: text_encoder.py:204-216 trust_remote_code从get_args()传入config字典，然后传递给automodel.from_pretrained。完整RCE链路。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

**深度分析**

根因分析：`text_encoder.py:188-231` 的 `_init_text_encoder()` 方法在第 202-206 行尝试从 Megatron 的 `get_args()` 获取 `trust_remote_code` 参数。第 204 行直接将 `get_args().trust_remote_code` 写入 `config` 字典，然后在第 216 行和 219 行分别传递给 `automodel.from_pretrained(**config)`。这是 mindspeed_mm 模块中 trust_remote_code 风险传播的核心节点之一。

潜在利用场景：
1. 用户在训练配置中指定 text_encoder 的 `from_pretrained` 为恶意模型仓库
2. 启用 `--trust-remote-code` 参数运行训练脚本
3. `TextEncoder.__init__()` 初始化时调用 `_init_text_encoder()`
4. 第 216/219 行加载恶意模型，执行远程代码注入

修复建议：
- 在第 204 行强制设置 `config["trust_remote_code"] = False`，忽略 CLI 参数
- 或添加模型仓库白名单验证，仅允许官方/已验证的模型仓库
- 在 `TextEncoder` 类文档中添加安全警告，说明不应从未知来源加载模型

---

### [VULN-DF-MM-CI-09] code_injection - build

**严重性**: Critical（原评估: critical → 验证后: Critical） | **CWE**: CWE-94 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/fsdp/models/modelhub.py:109-112` @ `build`
**模块**: mindspeed_mm
**跨模块**: mindspeed_mm,transformers

**描述**: trust_remote_code enables arbitrary code execution via AutoConfig.from_pretrained. The transformers library executes custom modeling code when trust_remote_code=True. This flows from CLI args through fsdp/modelhub.py to transformers.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/fsdp/models/modelhub.py:109-112`)

```c
transformer_config = AutoConfig.from_pretrained(model_args.model_name_or_path, trust_remote_code=model_args.trust_remote_code)
```

**达成路径**

[IN] CLI --trust-remote-code -> model_args.trust_remote_code -> ModelHub.build() -> AutoConfig.from_pretrained(trust_remote_code=True) -> EXECUTES CODE

**验证说明**: modelhub.py:109-112 AutoConfig.from_pretrained(model_args.model_name_or_path, trust_remote_code=model_args.trust_remote_code)。trust_remote_code直接来自CLI参数。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

**深度分析**

根因分析：`modelhub.py:94-138` 的 `ModelHub.build()` 静态方法是 FSDP 模型构建的核心入口。第 109-113 行加载 HuggingFace 配置时，直接将 `model_args.trust_remote_code` 传递给 `AutoConfig.from_pretrained()`。此外，第 83-90 行的 `_build_transformers_model()` 方法也在第 89 行传递 `trust_remote_code=model_args.trust_remote_code`，形成双重攻击路径。

潜在利用场景：
1. 用户配置 `model_args.model_name_or_path` 为恶意模型仓库
2. 启用 `--trust-remote-code` 参数运行 FSDP 分布式训练
3. `ModelHub.build()` 被调用时，第 109 行加载恶意配置文件
4. 或第 89 行加载模型权重时执行恶意代码
5. 分布式训练环境中的所有节点都会被攻击

修复建议：
- 在 `ModelHub.build()` 方法中添加参数验证，强制拒绝 `trust_remote_code=True`
- 或在 `model_args` 类中添加安全检查，默认禁止远程代码加载
- 为 FSDP 训练流程添加模型来源验证机制

---

### [MM-CWE94-001] Code Injection - __init__

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-94 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: python-security-module-scanner

**位置**: `mindspeed_mm/models/transformers_model.py:52-76` @ `__init__`
**模块**: mindspeed_mm
**跨模块**: mindspeed_mm → transformers → bridge

**描述**: trust_remote_code参数可导致执行任意远程代码。当启用--trust-remote-code时，AutoConfig.from_pretrained和AutoModel.from_pretrained会加载并执行来自HuggingFace Hub的自定义Python代码，存在代码注入风险。

**漏洞代码** (`mindspeed_mm/models/transformers_model.py:52-76`)

```c
trust_remote_code = args.trust_remote_code\nself.transformer_config = AutoConfig.from_pretrained(hf_path, trust_remote_code=trust_remote_code)\nself.model = model_cls.from_pretrained(hf_path, ..., trust_remote_code=trust_remote_code)
```

**达成路径**

sys.argv -> arguments.py --trust-remote-code -> get_args().trust_remote_code -> AutoConfig.from_pretrained -> HF Hub remote code execution

**验证说明**: transformers_model.py:52-76 trust_remote_code从args传入AutoConfig.from_pretrained和model_cls.from_pretrained。与VULN-CROSS-001相同的trust_remote_code链路起点。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-CHECKPOINT-001] Unsafe Deserialization - load_from_mm

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/vlm_model/mm_to_hf.py:92` @ `load_from_mm`
**模块**: checkpoint
**跨模块**: checkpoint

**描述**: torch.load() called with weights_only=False on user-provided .pt checkpoint file. When weights_only=False (the default), torch.load uses pickle deserialization which can execute arbitrary code. The pt_path is derived from command-line arguments through ConvertConfig.mm_dir, allowing attackers to load malicious checkpoint files.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/vlm_model/mm_to_hf.py:92`)

```c
torch.load(pt_path, map_location="cpu", weights_only=False)["model"]
```

**达成路径**

CLI args -> ConvertConfig.mm_dir -> load_from_mm -> pt_path construction -> torch.load(weights_only=False) -> pickle deserialization

**验证说明**: torch.load(weights_only=False)明确允许pickle反序列化。pt_path来自CLI参数ConvertConfig.mm_dir，攻击者可提供恶意checkpoint文件执行任意代码。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-CHECKPOINT-002] Unsafe Deserialization - load_from_mm

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/vlm_model/mm_to_hf.py:107` @ `load_from_mm`
**模块**: checkpoint
**跨模块**: checkpoint

**描述**: torch.load() called with weights_only=False on user-provided .pt checkpoint file. Second instance in load_from_mm function with same vulnerability pattern.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/vlm_model/mm_to_hf.py:107`)

```c
torch.load(pt_path, map_location="cpu", weights_only=False)["model"]
```

**达成路径**

CLI args -> ConvertConfig.mm_dir -> load_from_mm -> pt_path construction -> torch.load(weights_only=False) -> pickle deserialization

**验证说明**: 同VULN-CHECKPOINT-001，同一函数内第二处torch.load(weights_only=False)调用，相同漏洞模式。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-CHECKPOINT-004] Unsafe Deserialization - load_from_mm

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/sora_model/convert_utils/save_load_utils.py:36` @ `load_from_mm`
**模块**: checkpoint
**跨模块**: checkpoint

**描述**: torch.load() called with weights_only=False on state_dict_path. The path is constructed from load_dir parameter which comes from user input through ConvertConfig.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/sora_model/convert_utils/save_load_utils.py:36`)

```c
state_dict = torch.load(state_dict_path, map_location="cpu", weights_only=False)
```

**达成路径**

CLI args -> ConvertConfig.source_path -> load_from_mm -> state_dict_path -> torch.load(weights_only=False) -> pickle deserialization

**验证说明**: torch.load(weights_only=False)在save_load_utils.py:36。state_dict_path来自load_dir (CLI参数)，可加载恶意checkpoint。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-CROSS-001] Remote Code Execution - _add_security_args

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `mindspeed_mm/arguments.py:177` @ `_add_security_args`
**模块**: cross_module
**跨模块**: mindspeed_mm → bridge → checkpoint

**描述**: 跨模块 trust_remote_code 代码注入链路：命令行参数 --trust-remote-code 从 mindspeed_mm/arguments.py 流经 bridge/models/hf_pretrained/safe_config_loader.py 到 transformers.AutoConfig.from_pretrained，最终执行来自 HuggingFace Hub 的远程代码。完整数据流：CLI args -> mindspeed_mm/training.py -> merge_mm_args -> bridge_patch.py -> AutoBridge.from_hf_pretrained -> safe_load_config_with_retry(trust_remote_code=True) -> AutoConfig.from_pretrained -> RCE

**漏洞代码** (`mindspeed_mm/arguments.py:177`)

```c
group.add_argument('--trust-remote-code', action='store_true', default=False, ...)
```

**达成路径**

[IN] CLI --trust-remote-code -> mindspeed_mm/arguments.py:177 -> get_args().trust_remote_code -> mindspeed_mm/models/transformers_model.py:52 -> bridge/models/hf_pretrained/safe_config_loader.py:57 -> AutoConfig.from_pretrained(trust_remote_code=True) -> [OUT] EXECUTES REMOTE CODE FROM HF HUB

**验证说明**: 跨模块trust_remote_code完整链路已验证：CLI --trust-remote-code -> arguments.py:177 -> get_args().trust_remote_code -> transformers_model.py:52 -> safe_config_loader.py:57 -> AutoConfig.from_pretrained(trust_remote_code=True) -> RCE。调用链完整，每一步都存在。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-CHECKPOINT-003] Unsafe Deserialization - load_from_hf

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/vlm_model/hf_to_mm.py:316` @ `load_from_hf`
**模块**: checkpoint
**跨模块**: checkpoint

**描述**: torch.load() called without weights_only parameter on user-provided .pt file. Default behavior allows pickle deserialization which can execute arbitrary code. pt_path comes from ConvertConfig.pt_path which is a CLI argument.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/vlm_model/hf_to_mm.py:316`)

```c
weight = torch.load(pt_path)
```

**达成路径**

CLI args -> ConvertConfig.pt_path -> load_from_hf -> torch.load() -> pickle deserialization (default weights_only=False)

**验证说明**: torch.load(pt_path)无weights_only参数，默认False允许pickle。pt_path来自ConvertConfig.pt_path (CLI参数)。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-CHECKPOINT-005] Unsafe Deserialization - load_pt

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/sora_model/convert_utils/save_load_utils.py:152` @ `load_pt`
**模块**: checkpoint
**跨模块**: checkpoint

**描述**: torch.load() called without weights_only parameter. Default allows pickle deserialization. source_path is a CLI argument from ConvertConfig.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/sora_model/convert_utils/save_load_utils.py:152`)

```c
state_dict = torch.load(source_path, map_location="cpu")
```

**达成路径**

CLI args -> ConvertConfig.source_path -> load_pt -> torch.load() -> pickle deserialization

**验证说明**: torch.load(source_path)无weights_only参数。source_path来自CLI ConvertConfig.source_path。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-CHECKPOINT-006] Unsafe Deserialization - merge_model

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/common/merge_base_lora_weight.py:88-92` @ `merge_model`
**模块**: checkpoint

**描述**: torch.load() called without weights_only parameter in merge_base_lora_weight.py. base_pt_path and lora_pt_path are CLI arguments (--base_save_dir, --lora_save_dir). Default pickle deserialization allows arbitrary code execution.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/common/merge_base_lora_weight.py:88-92`)

```c
base_state_dict = torch.load(base_pt_path, map_location="npu/cpu")["model"]
```

**达成路径**

CLI args (--base_save_dir, --lora_save_dir) -> merge_model -> base_pt_path/lora_pt_path -> torch.load() -> pickle deserialization

**验证说明**: merge_base_lora_weight.py中torch.load(base_pt_path/lora_pt_path)无weights_only。路径来自CLI参数--base_save_dir/--lora_save_dir。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-CROSS-002] Unsafe Deserialization - main

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `checkpoint/convert_cli.py:13-23` @ `main`
**模块**: cross_module
**跨模块**: checkpoint → bridge

**描述**: 跨模块反序列化链路：checkpoint 模块的 convert_cli.py 调用 bridge 模块的 AutoBridge，最终使用 torch.load 加载用户提供的 .pt 文件。当 weights_only=False 时，torch.load 使用 pickle 反序列化，可执行任意代码。完整数据流：checkpoint/convert_cli.py -> AutoBridge.from_hf_pretrained -> PreTrainedCausalLM.load -> checkpoint/vlm_model/mm_to_hf.py:92 -> torch.load(weights_only=False)

**漏洞代码** (`checkpoint/convert_cli.py:13-23`)

```c
jsonargparse.auto_cli(Commandable.subclasses)
```

**达成路径**

[IN] CLI args (mm_dir, source_path) -> checkpoint/convert_cli.py -> ConvertConfig -> checkpoint/vlm_model/mm_to_hf.py -> torch.load(weights_only=False) -> [OUT] pickle deserialization RCE

**验证说明**: 跨模块反序列化链路已验证：checkpoint/convert_cli.py -> ConvertConfig -> mm_to_hf.py:92 -> torch.load(weights_only=False)。CLI参数直接控制checkpoint路径。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

---

## 4. High 漏洞 (11)

### [checkpoint-vuln-001] Unsafe Deserialization - load_from_mm

**严重性**: High | **CWE**: CWE-502 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `checkpoint/vlm_model/mm_to_hf.py:92-107` @ `load_from_mm`
**模块**: checkpoint

**描述**: torch.load() used without weights_only=True, allowing arbitrary code execution via malicious checkpoint files.

**漏洞代码** (`checkpoint/vlm_model/mm_to_hf.py:92-107`)

```c
torch.load(pt_path, map_location="cpu", weights_only=False)["model"]
```

**达成路径**

User checkpoint path -> torch.load() without weights_only=True -> arbitrary code execution

**验证说明**: torch.load(weights_only=False)在同一文件mm_to_hf.py:92-107，与VULN-CHECKPOINT-001/002相同的漏洞点。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

---

### [checkpoint-vuln-003] Unsafe Deserialization - merge_model

**严重性**: High | **CWE**: CWE-502 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `checkpoint/common/merge_base_lora_weight.py:88-92` @ `merge_model`
**模块**: checkpoint

**描述**: torch.load() without weights_only=True in LoRA merge script.

**漏洞代码** (`checkpoint/common/merge_base_lora_weight.py:88-92`)

```c
torch.load(base_pt_path, map_location="npu")["model"]
```

**达成路径**

CLI paths -> torch.load() without weights_only=True -> arbitrary code execution

**验证说明**: merge_base_lora_weight.py中torch.load无weights_only，路径来自CLI。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

---

### [checkpoint-vuln-004] Unsafe Deserialization - load_from_mm

**严重性**: High | **CWE**: CWE-502 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `checkpoint/sora_model/convert_utils/save_load_utils.py:36` @ `load_from_mm`
**模块**: checkpoint

**描述**: torch.load() with weights_only=False in save_load_utils.

**漏洞代码** (`checkpoint/sora_model/convert_utils/save_load_utils.py:36`)

```c
torch.load(state_dict_path, map_location="cpu", weights_only=False)
```

**达成路径**

load_dir -> torch.load() weights_only=False -> arbitrary code execution

**验证说明**: save_load_utils.py:36 torch.load(weights_only=False)。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

---

### [MM-CWE94-002] Code Injection - _init_tokenizer

**严重性**: High | **CWE**: CWE-94 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mindspeed_mm/models/text_encoder/tokenizer.py:64-73` @ `_init_tokenizer`
**模块**: mindspeed_mm
**跨模块**: mindspeed_mm,transformers

**描述**: tokenizer trust_remote_code传递

**验证说明**: tokenizer.py:64-73 tokenizer初始化中trust_remote_code传递给AutoTokenizer.from_pretrained。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-DF-MM-SSRF-04] ssrf - load_audio

**严重性**: High（原评估: high → 验证后: High） | **CWE**: CWE-918 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/fsdp/models/qwen3tts/inference/qwen3_tts_tokenizer.py:140-142` @ `load_audio`
**模块**: mindspeed_mm

**描述**: urllib.request.urlopen fetches URLs from user input without validation. The load_audio function accepts URL strings and fetches remote content without any URL whitelist or validation, enabling SSRF attacks.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/fsdp/models/qwen3tts/inference/qwen3_tts_tokenizer.py:140-142`)

```c
if self._is_url(x):\n    with urllib.request.urlopen(x) as resp:
```

**达成路径**

[IN] User audio URL input -> Qwen3TTSTokenizer.load_audio() -> urllib.request.urlopen(x) -> SSRF to internal services

**验证说明**: qwen3_tts_tokenizer.py:140-142 urllib.request.urlopen(x)直接打开用户提供的URL，无URL白名单或验证。SSRF攻击可访问内部服务。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-DF-MM-DS-03] deserialization - _load_extra_state

**严重性**: High（原评估: high → 验证后: High） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/fsdp/checkpoint/dcp_checkpointer.py:311` @ `_load_extra_state`
**模块**: mindspeed_mm

**描述**: torch.load in dcp_checkpointer.py loads extra_state without weights_only=True, allowing pickle-based code execution. The checkpoint path comes from distributed checkpoint directory which can be manipulated.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/fsdp/checkpoint/dcp_checkpointer.py:311`)

```c
state["extra_state"] = torch.load(extra_state_path, weights_only=False)
```

**达成路径**

[IN] Checkpoint path from config -> DistributedCheckpointer.load() -> _load_extra_state() -> torch.load(weights_only=False)

**验证说明**: dcp_checkpointer.py:311 torch.load(extra_state_path, weights_only=False)。checkpoint路径来自分布式checkpoint配置。

**评分明细**: base: 30 | reachability: 25 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-DF-MM-DS-07] deserialization - from_pretrained

**严重性**: High（原评估: high → 验证后: High） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/models/vision/vision_encoders/siglip_vit_model.py:818` @ `from_pretrained`
**模块**: mindspeed_mm

**描述**: torch.load in vision_encoders loads checkpoint without weights_only. The ckpt_path comes from user config mm_model.json image_encoder.vision_encoder.ckpt_path.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/models/vision/vision_encoders/siglip_vit_model.py:818`)

```c
state_dict = torch.load(ckpt_path, map_location="cpu")
```

**达成路径**

[IN] mm_model.json vision_encoder.ckpt_path -> SiglipVisionModel -> torch.load() -> pickle deserialization

**验证说明**: siglip_vit_model.py:818 torch.load(ckpt_path)无weights_only。ckpt_path来自mm_model.json vision_encoder配置。

**评分明细**: base: 30 | reachability: 25 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-DF-MM-DS-08] deserialization - _load_feature

**严重性**: High（原评估: high → 验证后: High） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/data/datasets/feature_dataset.py:96` @ `_load_feature`
**模块**: mindspeed_mm

**描述**: torch.load in feature_dataset.py loads features without weights_only. The feature_path comes from dataset config data_path which is user-controlled.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/data/datasets/feature_dataset.py:96`)

```c
return torch.load(feature_path, map_location=torch.device("cpu"))
```

**达成路径**

[IN] mm_data.json dataset data_path -> FeatureDataset -> _load_feature -> torch.load() -> pickle

**验证说明**: feature_dataset.py:96 torch.load(feature_path)无weights_only。feature_path来自数据集配置data_path。

**评分明细**: base: 30 | reachability: 25 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-DF-MM-DS-11] deserialization - load_checkpoint

**严重性**: High（原评估: high → 验证后: High） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/models/ae/contextparallel_causalvae.py:521` @ `load_checkpoint`
**模块**: mindspeed_mm

**描述**: torch.load in ae/contextparallel_causalvae.py loads checkpoints without weights_only. The ckpt_path comes from mm_model.json ae.from_pretrained.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/models/ae/contextparallel_causalvae.py:521`)

```c
ckpt_dict = torch.load(ckpt_path, map_location=lambda storage, loc: storage)
```

**达成路径**

[IN] mm_model.json ae.from_pretrained -> ContextParallelCausalVAE.load_checkpoint -> torch.load()

**验证说明**: contextparallel_causalvae.py:521 torch.load(ckpt_path)无weights_only。ckpt_path来自ae配置。

**评分明细**: base: 30 | reachability: 25 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

---

### [checkpoint-vuln-002] Unsafe Deserialization - load_from_hf

**严重性**: High | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `checkpoint/vlm_model/hf_to_mm.py:316-317` @ `load_from_hf`
**模块**: checkpoint

**描述**: torch.load() called without weights_only parameter in load_from_hf.

**漏洞代码** (`checkpoint/vlm_model/hf_to_mm.py:316-317`)

```c
weight = torch.load(pt_path)
```

**达成路径**

Optional pt_path -> torch.load() without weights_only -> arbitrary code execution

**验证说明**: torch.load(pt_path)无weights_only参数。hf_to_mm.py:316处，pt_path可选但来自CLI。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

### [checkpoint-vuln-006] Improper Neutralization of Directives - merge_dcp_to_hf

**严重性**: High | **CWE**: CWE-95 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `checkpoint/common/merge_dcp_to_hf.py:94` @ `merge_dcp_to_hf`
**模块**: checkpoint
**跨模块**: checkpoint,bridge

**描述**: trust_remote_code=True hardcoded in AutoProcessor.from_pretrained.

**漏洞代码** (`checkpoint/common/merge_dcp_to_hf.py:94`)

```c
AutoProcessor.from_pretrained(str(model_assets_dir), trust_remote_code=True)
```

**达成路径**

[CREDENTIAL_FLOW] model_assets_dir -> AutoProcessor with trust_remote_code=True -> remote code execution

**验证说明**: merge_dcp_to_hf.py:94 trust_remote_code=True硬编码，AutoProcessor.from_pretrained会执行远程代码。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| bridge | 3 | 0 | 0 | 0 | 3 |
| checkpoint | 6 | 5 | 0 | 0 | 11 |
| cross_module | 2 | 0 | 0 | 0 | 2 |
| mindspeed_mm | 3 | 6 | 0 | 0 | 9 |
| **合计** | **14** | **11** | **0** | **0** | **25** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-502 | 15 | 60.0% |
| CWE-94 | 8 | 32.0% |
| CWE-95 | 1 | 4.0% |
| CWE-918 | 1 | 4.0% |

---

## 7. 修复建议

### 优先级 1: 立即修复（Critical 漏洞）

#### 7.1.1 远程代码执行（CWE-94）漏洞修复

**影响范围**: 8 个漏洞涉及 `trust_remote_code` 参数链路

**修复措施**:

| 文件 | 修复方案 |
|------|----------|
| `mindspeed_mm/arguments.py:177` | 移除 `--trust-remote-code` CLI 参数，或添加强制性安全警告和二次确认机制 |
| `bridge/models/hf_pretrained/safe_config_loader.py:57` | 强制设置 `trust_remote_code=False`，移除参数透传 |
| `bridge/models/hf_pretrained/causal_lm.py:86-95` | 在 `model_kwargs` 构建时排除 `trust_remote_code` 参数 |
| `bridge/models/conversion/auto_bridge.py:57` | 添加 kwargs 过滤，拒绝 `trust_remote_code=True` |
| `mindspeed_mm/models/text_encoder/text_encoder.py:204` | 强制设置 `config["trust_remote_code"] = False` |
| `mindspeed_mm/fsdp/models/modelhub.py:109-111,89` | 强制设置 `trust_remote_code=False` |
| `checkpoint/common/merge_dcp_to_hf.py:94` | 移除硬编码的 `trust_remote_code=True` |

**通用加固建议**:
- 实现模型仓库白名单机制，仅允许已验证的官方模型仓库
- 在加载远程模型前添加完整性校验（如 SHA256 验证）
- 为训练环境添加网络隔离，限制对未知 HuggingFace Hub 仓库的访问

#### 7.1.2 不安全反序列化（CWE-502）漏洞修复

**影响范围**: 15 个漏洞涉及 `torch.load()` 调用

**修复措施**:

| 文件 | 修复方案 |
|------|----------|
| `checkpoint/vlm_model/mm_to_hf.py:92,107` | 设置 `weights_only=True`，添加异常处理 |
| `checkpoint/vlm_model/hf_to_mm.py:316` | 设置 `weights_only=True` |
| `checkpoint/sora_model/convert_utils/save_load_utils.py:36,152` | 设置 `weights_only=True` |
| `checkpoint/common/merge_base_lora_weight.py:88,92` | 设置 `weights_only=True` |
| `mindspeed_mm/fsdp/checkpoint/dcp_checkpointer.py:311` | 设置 `weights_only=True` |
| `mindspeed_mm/models/vision/vision_encoders/siglip_vit_model.py:818` | 设置 `weights_only=True` |
| `mindspeed_mm/data/datasets/feature_dataset.py:96` | 设置 `weights_only=True` |
| `mindspeed_mm/models/ae/contextparallel_causalvae.py:521` | 设置 `weights_only=True` |

**通用加固建议**:
- 所有 checkpoint 文件加载前进行完整性校验
- 实现模型权重签名验证机制
- 添加 checkpoint 来源审计日志

---

### 优先级 2: 短期修复（High 漏洞）

#### 7.2.1 SSRF 漏洞修复

**漏洞位置**: `mindspeed_mm/fsdp/models/qwen3tts/inference/qwen3_tts_tokenizer.py:140-142`

**修复措施**:
- 实现 URL 白名单验证机制，仅允许安全的 URL 协议和域名
- 添加请求超时限制和重试次数限制
- 禁止访问内网 IP 地址和本地文件路径

#### 7.2.2 代码注入（CWE-95）漏洞修复

**漏洞位置**: `checkpoint/common/merge_dcp_to_hf.py:94`

**修复措施**:
- 移除 `AutoProcessor.from_pretrained()` 的 `trust_remote_code=True` 硬编码
- 添加 processor 来源验证机制

---

### 优先级 3: 计划修复（架构层面加固）

1. **统一安全配置管理**: 创建全局安全配置模块，集中管理 `trust_remote_code`、checkpoint 加载策略等安全参数

2. **添加安全审计层**: 为所有模型加载、checkpoint 加载操作添加审计日志，记录来源、时间、操作者等信息

3. **实现安全测试覆盖**: 为关键安全路径添加单元测试，验证 `weights_only=True` 和 `trust_remote_code=False` 的强制执行

4. **更新依赖版本**: 检查 transformers、torch 等依赖库的最新安全补丁，及时更新到安全版本

5. **添加安全文档**: 为项目添加安全最佳实践文档，指导用户正确使用模型加载和 checkpoint 转换功能
