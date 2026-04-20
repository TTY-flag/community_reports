# 漏洞扫描报告 — 待确认漏洞

**项目**: MindSpeed-MM
**扫描时间**: 2026-04-20T01:17:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| High | 2 | 13.3% |
| Medium | 8 | 53.3% |
| Low | 5 | 33.3% |
| **有效漏洞总计** | **15** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-MM-DS-06]** deserialization (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/models/transformers_model.py:69` @ `__init__` | 置信度: 80
2. **[VULN-BRIDGE-003]** Improper Input Validation (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/hf_pretrained/causal_lm.py:55` @ `PreTrainedCausalLM.__init__/_load_model` | 置信度: 65
3. **[checkpoint-vuln-005]** Unsafe Deserialization (Medium) - `checkpoint/sora_model/convert_utils/save_load_utils.py:152` @ `load_pt` | 置信度: 80
4. **[checkpoint-vuln-007]** Improper Neutralization of Directives (Medium) - `checkpoint/common/merge_dcp_to_hf.py:114` @ `merge_dcp_to_hf_sharded` | 置信度: 80
5. **[checkpoint-vuln-008]** Improper Neutralization of Directives (Medium) - `checkpoint/vlm_model/converters/moe_expert.py:46` @ `save_hf_with_experts` | 置信度: 75
6. **[checkpoint-vuln-009]** Improper Neutralization of Directives (Medium) - `checkpoint/vlm_model/converters/mistral3.py:205` @ `convert_hf_to_mm` | 置信度: 75
7. **[VULN-CHECKPOINT-007]** Improper Input Validation (Medium) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/sora_model/convert_utils/cfg.py:11` @ `ConvertConfig` | 置信度: 60
8. **[VULN-CROSS-003]** Model Path Injection (Medium) - `mindspeed_mm/configs/config.py:143` @ `merge_mm_args` | 置信度: 60
9. **[VULN-BRIDGE-004]** Improper Input Validation (Medium) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/hf_pretrained/state.py:89` @ `_model_architecture/SafeTensorsStateSource` | 置信度: 55
10. **[VULN-BRIDGE-006]** Code Injection (Medium) - `bridge/models/conversion/auto_bridge.py:147` @ `_resolve_generation_model_architecture` | 置信度: 50

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

## 3. High 漏洞 (2)

### [VULN-DF-MM-DS-06] deserialization - __init__

**严重性**: High（原评估: high → 验证后: High） | **CWE**: CWE-502 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/models/transformers_model.py:69-76` @ `__init__`
**模块**: mindspeed_mm

**描述**: torch.load in transformers_model.py loads from_pretrained without weights_only parameter. The hf_path comes from config mm.model.init_from_hf_path which is user-controlled.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/models/transformers_model.py:69-76`)

```c
self.model = model_cls.from_pretrained(hf_path, ...)
```

**达成路径**

[IN] mm_model.json init_from_hf_path -> TransformersModel.__init__ -> model_cls.from_pretrained() -> internal torch.load

**验证说明**: transformers_model.py:69-76 model_cls.from_pretrained(hf_path)间接调用torch.load。hf_path来自配置mm.model.init_from_hf_path。

**评分明细**: base: 30 | reachability: 25 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-BRIDGE-003] Improper Input Validation - PreTrainedCausalLM.__init__/_load_model

**严重性**: High | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/hf_pretrained/causal_lm.py:55-95` @ `PreTrainedCausalLM.__init__/_load_model`
**模块**: bridge
**跨模块**: bridge,mindspeed_mm

**描述**: model_name_or_path parameter lacks validation before being passed to from_pretrained methods. While HuggingFace snapshot_download has protections, a malicious local path could be used to load crafted model files. No sanitization of path input to prevent path traversal or malicious file references.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/hf_pretrained/causal_lm.py:55-95`)

```c
model_name_or_path: Optional[Union[str, Path]] = None, ... model = AutoModelForCausalLM.from_pretrained(self.model_name_or_path, **model_kwargs)
```

**达成路径**

User Input (model_name_or_path) -> PreTrainedCausalLM.__init__ -> _load_model/_load_config -> AutoModelForCausalLM.from_pretrained/AutoConfig.from_pretrained -> unvalidated path used

**验证说明**: model_name_or_path参数缺乏验证，但HuggingFace的snapshot_download有内置保护机制。攻击者可尝试使用恶意本地路径，但风险相对较低。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (8)

### [checkpoint-vuln-005] Unsafe Deserialization - load_pt

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `checkpoint/sora_model/convert_utils/save_load_utils.py:152` @ `load_pt`
**模块**: checkpoint

**描述**: torch.load() without weights_only in load_pt function.

**漏洞代码** (`checkpoint/sora_model/convert_utils/save_load_utils.py:152`)

```c
torch.load(source_path, map_location="cpu")
```

**达成路径**

source_path -> torch.load() without weights_only -> arbitrary code execution

**验证说明**: save_load_utils.py:152 load_pt函数torch.load无weights_only。

**评分明细**: base: 30 | reachability: 25 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

### [checkpoint-vuln-007] Improper Neutralization of Directives - merge_dcp_to_hf_sharded

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-95 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `checkpoint/common/merge_dcp_to_hf.py:114-121` @ `merge_dcp_to_hf_sharded`
**模块**: checkpoint
**跨模块**: checkpoint,bridge

**描述**: trust_remote_code defaults to True in merge_dcp_to_hf_sharded.

**漏洞代码** (`checkpoint/common/merge_dcp_to_hf.py:114-121`)

```c
AutoProcessor.from_pretrained(model_assets_dir, trust_remote_code=trust_remote_code)
```

**达成路径**

[CREDENTIAL_FLOW] trust_remote_code defaults True -> remote code execution

**验证说明**: merge_dcp_to_hf_sharded中trust_remote_code默认True传递给AutoProcessor。

**评分明细**: base: 30 | reachability: 25 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

### [checkpoint-vuln-008] Improper Neutralization of Directives - save_hf_with_experts

**严重性**: Medium | **CWE**: CWE-95 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `checkpoint/vlm_model/converters/moe_expert.py:46` @ `save_hf_with_experts`
**模块**: checkpoint

**描述**: trust_remote_code=True hardcoded in AutoConfig.from_pretrained for expert config.

**漏洞代码** (`checkpoint/vlm_model/converters/moe_expert.py:46`)

```c
AutoConfig.from_pretrained(save_dir, trust_remote_code=True)
```

**达成路径**

save_dir -> AutoConfig trust_remote_code=True -> remote code execution

**验证说明**: moe_expert.py:46 AutoConfig.from_pretrained(trust_remote_code=True)硬编码。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

### [checkpoint-vuln-009] Improper Neutralization of Directives - convert_hf_to_mm

**严重性**: Medium | **CWE**: CWE-95 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `checkpoint/vlm_model/converters/mistral3.py:205` @ `convert_hf_to_mm`
**模块**: checkpoint

**描述**: trust_remote_code=True hardcoded in AutoProcessor.from_pretrained.

**漏洞代码** (`checkpoint/vlm_model/converters/mistral3.py:205`)

```c
AutoProcessor.from_pretrained(str(base_hf_dir), trust_remote_code=True)
```

**达成路径**

base_hf_dir -> AutoProcessor trust_remote_code=True -> remote code execution

**验证说明**: mistral3.py:205 AutoProcessor.from_pretrained(trust_remote_code=True)硬编码。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-CHECKPOINT-007] Improper Input Validation - ConvertConfig

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/sora_model/convert_utils/cfg.py:11-16` @ `ConvertConfig`
**模块**: checkpoint

**描述**: Path parameters from CLI (source_path, target_path, hf_dir, mm_dir) lack proper validation. While Pydantic DirectoryPath checks existence, there is no path traversal protection. An attacker could use paths containing ../ sequences or absolute paths outside expected directories.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/sora_model/convert_utils/cfg.py:11-16`)

```c
source_path: str, target_path: str, hf_dir: str
```

**达成路径**

CLI args (jsonargparse) -> ConvertConfig.source_path/target_path -> used directly in file operations without path traversal validation

**验证说明**: ConvertConfig路径参数虽有Pydantic DirectoryPath检查存在性，但无路径遍历防护。攻击者可尝试../序列，但实际利用难度较高。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CROSS-003] Model Path Injection - merge_mm_args

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mindspeed_mm/configs/config.py:143-147` @ `merge_mm_args`
**模块**: cross_module
**跨模块**: mindspeed_mm → bridge

**描述**: 跨模块模型路径注入链路：用户通过 mindspeed_mm/configs/config.py 传入模型路径参数，流经 mindspeed_mm/patchs/bridge_patch.py 到 bridge 模块的 AutoBridge.from_hf_pretrained，最终加载外部模型。路径缺乏跨模块统一验证，可能导致加载恶意模型文件。

**漏洞代码** (`mindspeed_mm/configs/config.py:143-147`)

```c
args.mm_model -> MMConfig -> args_external_path_checker
```

**达成路径**

[IN] mm_model.json model_path -> mindspeed_mm/configs/config.py:143 -> mindspeed_mm/patchs/bridge_patch.py:254 -> AutoBridge.from_hf_pretrained(load_dir) -> bridge/models/hf_pretrained/causal_lm.py -> [OUT] from_pretrained with unvalidated path

**验证说明**: 跨模块模型路径注入：mm_model.json -> config.py:143 -> bridge_patch.py:254 -> AutoBridge.from_hf_pretrained。路径验证在file_legality_checker中，但使用os.getcwd()作为base_dir，可能被绕过。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-BRIDGE-004] Improper Input Validation - _model_architecture/SafeTensorsStateSource

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/hf_pretrained/state.py:89-107` @ `_model_architecture/SafeTensorsStateSource`
**模块**: bridge

**描述**: model_name_or_path used directly in path construction without sanitization in SafeTensorsStateSource. Path concatenation with os.path.join and Path() operations could potentially be exploited if attacker controls the input.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/bridge/models/hf_pretrained/state.py:89-107`)

```c
config_path = os.path.join(self.hf_pretrained.model_name_or_path, 'config.json')
```

**达成路径**

User Input (model_name_or_path) -> SafeTensorsStateSource.__init__ -> path resolution -> os.path.join(model_name_or_path, config.json) -> direct path usage

**验证说明**: model_name_or_path在SafeTensorsStateSource中用于路径构建，但主要加载safetensors文件而非pickle。_resolve_path使用HuggingFace的snapshot_download，有一定保护。路径遍历风险有限。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-BRIDGE-006] Code Injection - _resolve_generation_model_architecture

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-094 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `bridge/models/conversion/auto_bridge.py:147-150` @ `_resolve_generation_model_architecture`
**模块**: bridge

**描述**: Dynamic module import via importlib.import_module based on config.json _class_name field in CLASS_MODULE_MAPPING. The _resolve_generation_model_architecture method imports modules determined by external config data without validation, enabling code injection if model path contains malicious config.json with crafted _class_name value that maps to attacker-controlled module.

**达成路径**

[CREDENTIAL_FLOW] model_name_or_path -> config.json direct read (line 91-92) -> config._class_name -> CLASS_MODULE_MAPPING[class_name] -> (module_name, actual_class_name) -> importlib.import_module(module_name) -> getattr(module, actual_class_name)

**验证说明**: importlib.import_module基于config.json的_class_name字段，但CLASS_MODULE_MAPPING白名单限制了可导入的类。攻击者需要class_name在白名单中才能利用，降低了实际风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (5)

### [VULN-DF-MM-PATH-05] path_traversal - file_legality_checker

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/configs/config.py:218-256` @ `file_legality_checker`
**模块**: mindspeed_mm

**描述**: Path validation in file_legality_checker uses os.getcwd() as base_dir default, which may not properly restrict paths in all contexts. The validation occurs after paths are already read from config, and some code paths may bypass validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/configs/config.py:218-256`)

```c
base_dir = os.getcwd() if not base_dir; if not norm_path.startswith(base_directory):
```

**达成路径**

[IN] User config paths -> MMConfig -> args_external_path_checker -> file_legality_checker(os.getcwd()) -> partial path validation

**验证说明**: file_legality_checker路径验证使用os.getcwd()，与MM-CWE22-001相同的弱点。

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: 0 | context: 5 | cross_file: 0

---

### [MM-CWE22-001] Path Traversal - file_legality_checker

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: python-security-module-scanner

**位置**: `mindspeed_mm/configs/config.py:218-256` @ `file_legality_checker`
**模块**: mindspeed_mm

**描述**: file_legality_checker函数的base_dir默认为os.getcwd()，可能被攻击者操纵。

**漏洞代码** (`mindspeed_mm/configs/config.py:218-256`)

```c
base_dir = os.getcwd()
```

**达成路径**

os.getcwd() -> base_dir

**验证说明**: file_legality_checker使用os.getcwd()作为base_dir默认值。攻击者可能通过控制工作目录绕过验证，但实际利用场景有限。

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: 0 | context: 5 | cross_file: 0

---

### [MM-CWE22-002] Path Traversal - get_datasamples

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindspeed_mm/data/data_utils/utils.py:90-110` @ `get_datasamples`
**模块**: mindspeed_mm

**描述**: get_datasamples未验证data_path

**验证说明**: get_datasamples未验证data_path，但数据集路径通常由配置文件指定，攻击者需先控制配置文件。风险较低。

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MM-EVAL-10] code_injection - select_best_resolution

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-95 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/tasks/inference/pipeline/utils/llava_utils.py:92` @ `select_best_resolution`
**模块**: mindspeed_mm

**描述**: ast.literal_eval used to parse user-provided grid_pinpoints in llava_utils.py. While ast.literal_eval is safer than eval(), it still parses arbitrary Python literals which could be manipulated.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/mindspeed_mm/tasks/inference/pipeline/utils/llava_utils.py:92`)

```c
possible_resolutions = ast.literal_eval(grid_pinpoints)
```

**达成路径**

[IN] config grid_pinpoints -> llava_utils.select_best_resolution -> ast.literal_eval()

**验证说明**: llava_utils.py:92 ast.literal_eval(grid_pinpoints)。虽比eval()安全，但仍解析任意Python字面量。风险有限。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CHECKPOINT-008] Improper Input Validation - HfConfig.config

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/vlm_model/config.py:130-131` @ `HfConfig.config`
**模块**: checkpoint

**描述**: trust_remote_code parameter passed to AutoConfig.from_pretrained enables execution of arbitrary code from remote model repositories. When trust_remote_code=True, transformers downloads and executes modeling_*.py files.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed-MM/checkpoint/vlm_model/config.py:130-131`)

```c
AutoConfig.from_pretrained(self.hf_dir, local_files_only=True)
```

**达成路径**

Note: local_files_only=True mitigates remote code execution, but if trust_remote_code is later enabled, risk exists

**验证说明**: AutoConfig.from_pretrained使用local_files_only=True，缓解了远程代码执行风险。但trust_remote_code若后续启用则风险存在。

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| bridge | 0 | 1 | 2 | 0 | 3 |
| checkpoint | 0 | 0 | 5 | 1 | 6 |
| cross_module | 0 | 0 | 1 | 0 | 1 |
| mindspeed_mm | 0 | 1 | 0 | 4 | 5 |
| **合计** | **0** | **2** | **8** | **5** | **15** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-95 | 4 | 26.7% |
| CWE-22 | 4 | 26.7% |
| CWE-20 | 4 | 26.7% |
| CWE-502 | 2 | 13.3% |
| CWE-094 | 1 | 6.7% |
