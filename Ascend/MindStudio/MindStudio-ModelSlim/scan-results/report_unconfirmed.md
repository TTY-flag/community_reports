# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-ModelSlim
**扫描时间**: 2026-04-21T12:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 22 | 31.0% |
| LIKELY | 18 | 25.4% |
| FALSE_POSITIVE | 17 | 23.9% |
| CONFIRMED | 14 | 19.7% |
| **总计** | **71** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 13 | 32.5% |
| Medium | 18 | 45.0% |
| Low | 9 | 22.5% |
| **有效漏洞总计** | **40** | - |
| 误报 (FALSE_POSITIVE) | 17 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SHELL-003]** Environment Variable Injection (High) - `msmodelslim/utils/security/shell.py:279` @ `AsyncProcess.__init__` | 置信度: 75
2. **[VULN-MODEL-010]** Insecure from_pretrained without local_files_only (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen3_vl/model_adapter.py:223` @ `init_model` | 置信度: 75
3. **[VULN-MODEL-013]** Insecure Image Pipeline Loading (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen_image_edit/model_adapter.py:271` @ `init_model` | 置信度: 75
4. **[VULN-MODEL-017]** Insecure Qwen2_5_VL Loading (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen2_5_vl/model_adapter.py:216` @ `init_model` | 置信度: 75
5. **[VULN-MODEL-018]** Insecure Qwen2_5_Omni Loading (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen2_5_omni_thinker/model_adapter.py:235` @ `init_model` | 置信度: 75
6. **[VULN-ASCEND-001]** Insecure Deserialization Bypass (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/ascend_utils/common/security/pytorch.py:85` @ `safe_torch_load` | 置信度: 75
7. **[VULN-PYTORCH-WEIGHT-001]** Pickle Deserialization (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/pytorch/weight_compression/compress_tools.py:302` @ `load_from_file` | 置信度: 75
8. **[VULN-XMOD-001]** path_traversal (High) - `msmodelslim/cli/__main__.py:34` @ `main` | 置信度: 75
9. **[VULN-MODEL-001]** Code Injection via trust_remote_code (High) - `msmodelslim/utils/security/model.py:49` @ `get_model_from_pretrained` | 置信度: 70
10. **[VULN-DF-PY-002]** path_traversal (High) - `msmodelslim/model/qwen2_5_vl/model_adapter.py:97` @ `handle_dataset` | 置信度: 70

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@msmodelslim/cli/__main__.py` | cmdline | untrusted_local | CLI入口点，接收用户命令行参数（model_path, save_path, config_path等），参数可完全由用户控制 | 命令行工具主入口，支持quant/analyze/tune三个子命令 |
| `quant_parser.add_argument@msmodelslim/cli/__main__.py` | cmdline | untrusted_local | 量化命令参数解析，model_path、save_path、config_path等参数来自用户命令行输入 | 解析量化命令参数 |
| `NaiveQuantizationApplication.quant@msmodelslim/app/naive_quantization/application.py` | decorator | untrusted_local | 公开API入口点，接收model_path、save_path、config_path等用户输入参数 | 量化应用主入口函数 |
| `SafeGenerator.get_config_from_pretrained@msmodelslim/utils/security/model.py` | file | untrusted_local | 加载用户提供的模型配置文件，通过AutoConfig.from_pretrained解析 | 安全加载模型配置 |
| `SafeGenerator.get_model_from_pretrained@msmodelslim/utils/security/model.py` | file | untrusted_local | 加载用户提供的模型权重文件，通过AutoModelForCausalLM.from_pretrained解析，可能涉及safetensors或pickle文件 | 安全加载模型权重 |
| `yaml_safe_load@msmodelslim/utils/security/path.py` | file | untrusted_local | 加载用户提供的YAML配置文件，使用yaml.safe_load解析 | 安全加载YAML文件 |
| `json_safe_load@msmodelslim/utils/security/path.py` | file | untrusted_local | 加载用户提供的JSON配置文件，使用json.load解析 | 安全加载JSON文件 |
| `ShellRunner.run_safe_cmd@msmodelslim/utils/security/shell.py` | cmdline | semi_trusted | 执行外部命令，参数经过安全验证（validate_safe_identifier）后使用subprocess.run(shell=False) | 安全执行外部命令 |
| `AsyncProcess@msmodelslim/utils/security/shell.py` | cmdline | semi_trusted | 管理长期运行的进程（如vllm服务），参数经过安全验证后使用subprocess.Popen(shell=False) | 异步进程管理器 |
| `AutoProcessor.from_pretrained@msmodelslim/model/qwen2_5_vl/model_adapter.py` | file | untrusted_local | 加载模型处理器，model_path来自用户输入 | 加载Qwen2.5-VL模型处理器 |
| `safe_open@msmodelslim/model/qwen2_5_vl/model_adapter.py` | file | untrusted_local | 使用safetensors.safe_open加载模型权重文件，file_path来自用户输入的model_path | 从safetensors加载权重 |
| `safe_open@msmodelslim/model/qwen3_5_moe/model_adapter.py` | file | untrusted_local | 使用safetensors.safe_open加载MoE模型权重文件 | 从safetensors加载MoE权重 |
| `subprocess.Popen@msmodelslim/pytorch/weight_compression/compress_utils.py` | cmdline | semi_trusted | 调用compress_excutor执行权重压缩，参数经过数值验证（shape_k, shape_n等）后以列表形式传递，shell=False | 调用压缩执行器 |
| `main@msmodelslim/pytorch/weight_compression/compress_graph/src/main.cpp` | cmdline | semi_trusted | C++ CLI入口，接收压缩参数（dimK, dimN, inputWeightPath等）并调用File::CheckFileBeforeCreateOrWrite验证路径 | 压缩图执行器主入口 |
| `fopen@msmodelslim/pytorch/weight_compression/compress_graph/src/main.cpp` | file | semi_trusted | 打开文件写入压缩输出，路径经过File::CheckFileBeforeCreateOrWrite安全检查 | 打开文件写入 |
| `GetDataFromBin@msmodelslim/pytorch/weight_compression/compress_graph/src/graph_utils.cpp` | file | untrusted_local | 读取二进制输入权重文件，input_path来自命令行参数，未经过显式安全检查 | 读取二进制输入文件 |
| `File::CheckFileBeforeCreateOrWrite@msmodelslim/pytorch/weight_compression/security/src/File.cpp` | file | trusted_admin | 安全检查函数，验证路径长度、字符、软链接、权限等，被其他函数调用作为安全边界 | 文件写入前安全检查 |
| `get_valid_path@security/path.py` | file | trusted_admin | 路径安全检查函数，验证特殊字符、软链接、长度等，被其他函数调用作为安全边界 | 路径安全检查 |
| `json_safe_load@security/path.py` | file | untrusted_local | 加载JSON文件，路径经过get_valid_read_path验证 | 安全加载JSON |

**其他攻击面**:
- 命令行接口: msmodelslim quant/analyze/tune 命令参数（model_path, save_path, config_path）
- Python API接口: NaiveQuantizationApplication.quant() 函数参数
- 模型文件加载: safetensors文件、pickle文件、配置文件（AutoConfig/AutoModel/AutoTokenizer.from_pretrained）
- 配置文件解析: YAML/JSON配置文件（yaml_safe_load, json_safe_load）
- 数据集文件加载: JSONL/JSON校准数据集文件
- 外部命令执行: compress_excutor二进制执行（subprocess.Popen, shell=False）
- C++ CLI接口: compress_excutor命令行参数（inputWeightPath, outputWeightPath等）

---

## 3. High 漏洞 (13)

### [VULN-SHELL-003] Environment Variable Injection - AsyncProcess.__init__

**严重性**: High | **CWE**: CWE-15 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `msmodelslim/utils/security/shell.py:279-296` @ `AsyncProcess.__init__`
**模块**: msmodelslim.utils.security.shell

**描述**: AsyncProcess accepts arbitrary environment variables without validation. Attacker can inject LD_PRELOAD for DLL injection, PATH for binary substitution, or other security-sensitive environment variables leading to code execution.

**漏洞代码** (`msmodelslim/utils/security/shell.py:279-296`)

```c
if env:\n    self.env = {**os.environ, **env}  # No validation of env keys/values\n# ...\npopen_kwargs['env'] = {k: str(v) for k, v in self.env.items()}  # Passed to subprocess
```

**达成路径**

User env dict -> merged with os.environ -> subprocess.Popen(env=...) -> LD_PRELOAD/PATH injection -> code execution

**验证说明**: AsyncProcess accepts arbitrary environment variables. LD_PRELOAD, PATH injection possible. shell=False mitigates command injection but env injection enables DLL/binary substitution. Requires attacker to have process control.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-MODEL-010] Insecure from_pretrained without local_files_only - init_model

**严重性**: High | **CWE**: CWE-829 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen3_vl/model_adapter.py:223-227` @ `init_model`
**模块**: msmodelslim/model
**跨模块**: msmodelslim/model,msmodelslim/utils/security

**描述**: Direct from_pretrained call missing local_files_only=True security constraint. Qwen3VLForConditionalGeneration.from_pretrained is called without local_files_only=True, potentially allowing remote model loading and code execution.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen3_vl/model_adapter.py:223-227`)

```c
model = Qwen3VLForConditionalGeneration.from_pretrained(self.model_path, config=self.config, trust_remote_code=self.trust_remote_code, torch_dtype=auto, device_map=cpu)
```

**达成路径**

model_path -> from_pretrained (no local_files_only) -> model

**验证说明**: Qwen3VLForConditionalGeneration.from_pretrained without local_files_only=True. Trust boundary: untrusted_local to model loading. Missing SafeGenerator wrapper. Could allow remote model loading if network access available.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-MODEL-013] Insecure Image Pipeline Loading - init_model

**严重性**: High | **CWE**: CWE-829 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen_image_edit/model_adapter.py:271-275` @ `init_model`
**模块**: msmodelslim/model

**描述**: qwen_image_edit/model_adapter.py uses QwenImageEditPlusPipeline.from_pretrained without SafeGenerator wrapper, potentially allowing remote code execution.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen_image_edit/model_adapter.py:271-275`)

```c
self.model = QwenImageEditPlusPipeline.from_pretrained(self.model_path)
```

**达成路径**

model_path -> Pipeline.from_pretrained -> model

**验证说明**: qwen_image_edit/model_adapter.py uses QwenImageEditPlusPipeline.from_pretrained without SafeGenerator. Missing local_files_only=True. Similar to VULN-MODEL-011 pattern.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-MODEL-017] Insecure Qwen2_5_VL Loading - init_model

**严重性**: High | **CWE**: CWE-829 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen2_5_vl/model_adapter.py:216-220` @ `init_model`
**模块**: msmodelslim/model
**跨模块**: msmodelslim/model

**描述**: Qwen2_5_VLForConditionalGeneration.from_pretrained in qwen2_5_vl/model_adapter.py lacks SafeGenerator wrapper.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen2_5_vl/model_adapter.py:216-220`)

```c
model = Qwen2_5_VLForConditionalGeneration.from_pretrained(self.model_path)
```

**达成路径**

model_path -> from_pretrained -> model

**验证说明**: Qwen2_5_VLForConditionalGeneration.from_pretrained in model_adapter.py:216. Missing SafeGenerator wrapper. But line 211 has get_valid_read_path validation. Partial mitigation via path check.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-MODEL-018] Insecure Qwen2_5_Omni Loading - init_model

**严重性**: High | **CWE**: CWE-829 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen2_5_omni_thinker/model_adapter.py:235-240` @ `init_model`
**模块**: msmodelslim/model
**跨模块**: msmodelslim/model

**描述**: Qwen2_5OmniThinkerForConditionalGeneration.from_pretrained in qwen2_5_omni_thinker/model_adapter.py lacks SafeGenerator wrapper.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen2_5_omni_thinker/model_adapter.py:235-240`)

```c
Qwen2_5OmniThinkerForConditionalGeneration.from_pretrained(self.model_path)
```

**达成路径**

model_path -> from_pretrained -> model

**验证说明**: Qwen2_5OmniThinkerForConditionalGeneration.from_pretrained lacks SafeGenerator wrapper. Similar pattern to VULN-MODEL-017. Trust boundary: untrusted_local CLI input to model loading.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-ASCEND-001] Insecure Deserialization Bypass - safe_torch_load

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-502 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/ascend_utils/common/security/pytorch.py:85-103` @ `safe_torch_load`
**模块**: ascend_utils.common.security.pytorch

**描述**: safe_torch_load function allows bypassing weights_only protection through user confirmation. The function initially uses weights_only=True for safe loading, but when pickle.UnpicklingError occurs, it prompts user for confirmation and then sets weights_only=False. This allows arbitrary code execution via malicious pickle payloads in model files. Attack scenario: attacker crafts a malicious model file that triggers UnpicklingError, user is prompted to confirm, and upon confirmation, the malicious payload executes.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/ascend_utils/common/security/pytorch.py:85-103`)

```c
def safe_torch_load(path, **kwargs):\n    kwargs['weights_only'] = True\n    tensor = None\n    while True:\n        try:\n            tensor = torch.load(path, **kwargs)\n        except pickle.UnpicklingError:\n            confirmation_prompt = "Weights only load failed..."\n            if not confirmation_interaction(confirmation_prompt):\n                raise\n            kwargs['weights_only'] = False  # DANGEROUS: bypasses security\n        else:\n            break\n    return tensor
```

**达成路径**

User input -> safe_torch_load -> weights_only=True (initial) -> pickle.UnpicklingError -> confirmation_interaction -> weights_only=False -> torch.load -> pickle deserialization -> RCE

**验证说明**: safe_torch_load bypasses weights_only after user confirmation. Initial weights_only=True is secure, but UnpicklingError triggers confirmation and sets weights_only=False. Social engineering attack possible, but requires user interaction.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-PYTORCH-WEIGHT-001] Pickle Deserialization - load_from_file

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-502 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/pytorch/weight_compression/compress_tools.py:302-309` @ `load_from_file`
**模块**: model

**描述**: CRITICAL: Unsafe pickle deserialization - np.load() falls back to allow_pickle=True when allow_pickle=False fails. Pickle deserialization can execute arbitrary code when loading malicious .npy files. Attack vector: attacker crafts malicious .npy file containing pickle payload with __reduce__ method that executes arbitrary code. When np.load is called with allow_pickle=True, the payload executes. The warning message acknowledges risk but still proceeds.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/pytorch/weight_compression/compress_tools.py:302-309`)

```c
self.weights = np.load(weight_path, allow_pickle=True).item()
```

**达成路径**

User-provided weight_path -> get_valid_read_path(path validation) -> np.load(allow_pickle=False) fails -> np.load(allow_pickle=True) -> pickle.loads() -> arbitrary code execution

**验证说明**: np.load falls back to allow_pickle=True after user confirmation. get_valid_read_path() validates path. Social engineering required - user must confirm pickle load.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-XMOD-001] path_traversal - main

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `msmodelslim/cli/__main__.py:34-141` @ `main`
**模块**: cross_module_analysis
**跨模块**: cli → app_naive_quantization → model

**描述**: Cross-module path traversal: model_path flows from CLI (cli/__main__.py) through Application layer (app/naive_quantization/application.py) to Model Adapter (model/qwen2_5_vl/model_adapter.py:97) where AutoProcessor.from_pretrained is called WITHOUT get_valid_read_path validation. The validation only happens later in init_model() (line 211), but handle_dataset() can be called independently.

**达成路径**

CLI args.model_path → quant_main() → NaiveQuantizationApplication.quant() → model_factory.create() → Qwen25VLModelAdapter.handle_dataset() → AutoProcessor.from_pretrained(self.model_path) [Python validation gap]

**验证说明**: Cross-module path traversal: model_path flows from CLI through Application to Model Adapter. AutoProcessor.from_pretrained() called before full get_valid_read_path validation. Partial validation via convert_to_readable_dir() reduces risk.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-MODEL-001] Code Injection via trust_remote_code - get_model_from_pretrained

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-94 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `msmodelslim/utils/security/model.py:49-75` @ `get_model_from_pretrained`
**模块**: msmodelslim.utils.security.model

**描述**: SafeGenerator methods do not explicitly enforce trust_remote_code=False. When trust_remote_code=True is passed via kwargs (which happens in transformers.py line 73 and model adapters), arbitrary code from model files can be executed. Model files contain Python code that gets executed during loading.

**漏洞代码** (`msmodelslim/utils/security/model.py:49-75`)

```c
config = AutoConfig.from_pretrained(model_path, local_files_only=True, **kwargs)  # trust_remote_code not enforced\nmodel = AutoModelForCausalLM.from_pretrained(model_path, local_files_only=True, **kwargs)  # trust_remote_code not enforced
```

**达成路径**

User model_path -> SafeGenerator.get_model_from_pretrained(**kwargs) -> kwargs includes trust_remote_code=True -> AutoModel.from_pretrained executes arbitrary code

**验证说明**: SafeGenerator passes kwargs including potential trust_remote_code=True to AutoModel.from_pretrained. local_files_only=True mitigates remote risk. User must explicitly enable trust_remote_code. auto_map in config can still execute code.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-PY-002] path_traversal - handle_dataset

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `msmodelslim/model/qwen2_5_vl/model_adapter.py:97` @ `handle_dataset`
**模块**: model

**描述**: AutoProcessor.from_pretrained(self.model_path) is called at line 97 BEFORE get_valid_read_path() validation at line 211. This allows path traversal to arbitrary directories before security checks are applied. The model_path comes from user input through CLI/API.

**漏洞代码** (`msmodelslim/model/qwen2_5_vl/model_adapter.py:97`)

```c
def handle_dataset(self, dataset: Any, device: DeviceType = DeviceType.NPU) -> List[Any]:
    ...
    self._processor = AutoProcessor.from_pretrained(self.model_path)
```

**达成路径**

model_path (CLI arg) -> NaiveQuantizationApplication.quant() -> model_factory.create() -> Qwen25VLModelAdapter.__init__() -> handle_dataset() -> AutoProcessor.from_pretrained(self.model_path) [SINK - NO VALIDATION]

**验证说明**: AutoProcessor.from_pretrained() called at line 97 BEFORE get_valid_read_path() validation at line 211. However, convert_to_readable_dir() in application.py:369 provides partial validation. Trust boundary: untrusted_local CLI input to model adapter.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-QWEN2_5_VL-001] Path Traversal - handle_dataset

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen2_5_vl/model_adapter.py:97` @ `handle_dataset`
**模块**: model

**描述**: AutoProcessor.from_pretrained called without path validation in handle_dataset(). model_path flows from constructor to sink without validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen2_5_vl/model_adapter.py:97`)

```c
self._processor = AutoProcessor.from_pretrained(self.model_path)
```

**达成路径**

Entry: __init__(model_path) -> self.model_path -> Sink: AutoProcessor.from_pretrained [NO VALIDATION]

**验证说明**: AutoProcessor.from_pretrained without validation. Same as VULN-DF-PY-002. Path validated later in init_model.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-QWEN3_5_MOE-001] Path Traversal - handle_dataset

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen3_5_moe/model_adapter.py:148-151` @ `handle_dataset`
**模块**: model

**描述**: AutoProcessor.from_pretrained called without path validation in handle_dataset(). get_valid_read_path only in init_model.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen3_5_moe/model_adapter.py:148-151`)

```c
AutoProcessor.from_pretrained(self.model_path)
```

**达成路径**

Entry: __init__(model_path) -> self.model_path -> Sink: AutoProcessor.from_pretrained [NO VALIDATION]

**验证说明**: AutoProcessor.from_pretrained without validation in handle_dataset. Same pattern as VULN-QWEN2_5_VL-001.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-QWEN3_OMNI_MOE-001] Path Traversal - handle_dataset

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen3_omni_moe/model_adapter.py:92-96` @ `handle_dataset`
**模块**: model

**描述**: Qwen3OmniMoeProcessor.from_pretrained without path validation in handle_dataset().

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen3_omni_moe/model_adapter.py:92-96`)

```c
Qwen3OmniMoeProcessor.from_pretrained(self.model_path)
```

**达成路径**

Entry: __init__(model_path) -> self.model_path -> Sink: Processor.from_pretrained [NO VALIDATION]

**验证说明**: Qwen3OmniMoeProcessor.from_pretrained without validation. Same pattern as VULN-QWEN2_5_VL-001.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (18)

### [infra-safe-generator-load-jsonl-bypass] Missing Security Validation - SafeGenerator.load_jsonl

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/utils/security/model.py:79-90` @ `SafeGenerator.load_jsonl`
**模块**: infra
**跨模块**: infra,file_dataset_loader.py

**描述**: SafeGenerator.load_jsonl() bypasses path security validation. Unlike json_safe_load and yaml_safe_load which call get_valid_read_path() for security checks (path traversal prevention, symlink detection, permission validation), this function directly opens files using os.open() without any validation. This creates an inconsistent security pattern where direct calls to load_jsonl could bypass all security controls.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/utils/security/model.py:79-90`)

```c
def load_jsonl(dataset_path, key_name='inputs_pretokenized'):
    dataset = []
    if dataset_path == humaneval_x.jsonl:
        key_name = 'prompt'
    with os.fdopen(os.open(dataset_path, os.O_RDONLY, 0o600),
                   'r', encoding='utf-8') as file:
        lines = file.readlines()
        for line in lines:
            data = json.loads(line)
            text = data.get(key_name, line)
            dataset.append(text)
    return dataset
```

**达成路径**

Caller in file_dataset_loader.py:66-68 validates path first with get_valid_read_path(), then passes to load_jsonl. However, as a public static method, any code can call load_jsonl directly bypassing validation.

**验证说明**: Same as VULN-DF-PY-001/VULN-MODEL-003. load_jsonl bypasses path validation. Caller file_dataset_loader.py validates path first, but public method can be called directly. Inconsistent security pattern.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-ASCEND-003] Incomplete Symlink Protection - get_valid_path

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-59 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/ascend_utils/common/security/path.py:63-64` @ `get_valid_path`
**模块**: ascend_utils.common.security.path

**描述**: Symlink check only verifies if the final path component is a symlink, not intermediate directory components. An attacker can create a directory structure where an intermediate directory is a symlink, bypassing the protection. Example: create /tmp/evil/links -> /etc, then access /tmp/evil/links/passwd. The abspath check passes because /tmp/evil/links/passwd is not a symlink itself.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/ascend_utils/common/security/path.py:63-64`)

```c
if os.path.islink(os.path.abspath(path)):\n    raise ValueError("The value of the path cannot be soft link: {}".format(path))\n# Only checks final component, not intermediate directories
```

**达成路径**

Attacker creates symlink dir: ln -s /etc /tmp/evil/links -> Access /tmp/evil/links/passwd -> islink check passes (file not symlink) -> realpath resolves to /etc/passwd

**验证说明**: Same incomplete symlink protection as VULN-PATH-002. islink only checks final component. Intermediate directory symlinks bypass protection. Cross-package vulnerability in ascend_utils.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-002-UTILS-SECURITY] Path Traversal - AsyncProcess.__init__

**严重性**: Medium | **CWE**: CWE-22, CWE-73 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `msmodelslim/utils/security/shell.py:258-277` @ `AsyncProcess.__init__`
**模块**: utils_security

**描述**: AsyncProcess.__init__ 中 self.log_file = open(log_file, 'w') 直接打开日志文件，没有验证路径。攻击者可以通过路径穿越写入任意路径，或覆盖敏感系统文件。

**漏洞代码** (`msmodelslim/utils/security/shell.py:258-277`)

```c
self.log_file = open(log_file, 'w')
```

**达成路径**

log_file (user input) -> open() -> file write (NO VALIDATION)

**验证说明**: AsyncProcess.__init__ opens log_file without validation. Same as VULN-SHELL-002. Arbitrary file write via path traversal. Should use get_valid_write_path().

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-PATH-004] Privilege Escalation via Root Bypass - get_valid_read_path

**严重性**: Medium | **CWE**: CWE-269 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `msmodelslim/utils/security/path.py:138-144` @ `get_valid_read_path`
**模块**: msmodelslim.utils.security.path

**描述**: Root user bypasses ownership validation with only a warning. When running as root, ownership checks are silently skipped after logging a warning, allowing access to files owned by other users.

**漏洞代码** (`msmodelslim/utils/security/path.py:138-144`)

```c
if check_user_stat and not sys.platform.startswith("win") and not is_belong_to_user_or_group(file_stat):\n    if os.geteuid() == 0:\n        get_logger().warning(...)  # Only warning, no error\n    else:\n        raise SecurityError(...)
```

**达成路径**

Root process -> ownership check fails -> only warning logged -> access granted to unowned file

**验证说明**: Root user bypasses ownership validation with only warning. os.geteuid()==0 allows access to files owned by others. Intended behavior for root, but reduces security in multi-user environments. Low severity as root is trusted.

**评分明细**: base: 30 | reachability: 10 | controllability: 15 | mitigations: 0 | context: 10 | cross_file: 0

---

### [VULN-MODEL-002] Insecure Deserialization - get_model_from_pretrained

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `msmodelslim/utils/security/model.py:62-63` @ `get_model_from_pretrained`
**模块**: msmodelslim.utils.security.model

**描述**: Model loading via AutoModelForCausalLM.from_pretrained internally uses torch.load which can deserialize pickle files. No explicit use of weights_only=True or safetensors enforcement. Pickle deserialization of untrusted model files can lead to arbitrary code execution.

**漏洞代码** (`msmodelslim/utils/security/model.py:62-63`)

```c
model = AutoModelForCausalLM.from_pretrained(model_path, local_files_only=True, **kwargs)  # Internally uses torch.load without weights_only=True
```

**达成路径**

User provides malicious .bin or .pt file -> from_pretrained -> torch.load -> pickle.loads -> arbitrary code execution

**验证说明**: AutoModel.from_pretrained internally uses torch.load which can deserialize pickle. Mitigations: get_valid_read_path(), local_files_only=True, check_user_stat=True. Residual risk: malicious pickle in validated path.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-MODEL-012] Insecure Model Loading Qwen3Omni - init_model

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-829 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen3_omni_moe/model_adapter.py:223-228` @ `init_model`
**模块**: msmodelslim/model
**跨模块**: msmodelslim/model

**描述**: Qwen3OmniMoeThinkerForConditionalGeneration.from_pretrained in qwen3_omni_moe lacks local_files_only=True in some calls, potentially allowing remote model loading.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/model/qwen3_omni_moe/model_adapter.py:223-228`)

```c
Qwen3OmniMoeThinkerForConditionalGeneration.from_pretrained(self.model_path, config=thinker_config, trust_remote_code=self.trust_remote_code, torch_dtype=auto, local_files_only=True, device_map=cpu)
```

**达成路径**

model_path -> from_pretrained -> model

**验证说明**: Qwen3OmniMoeThinkerForConditionalGeneration.from_pretrained has local_files_only=True per code snippet. Scanner description suggests missing it, but actual code includes it. May be FALSE_POSITIVE or different call path.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-CLI-001] Arbitrary Code Execution via trust_remote_code - main

**严重性**: Medium（原评估: HIGH → 验证后: Medium） | **CWE**: CWE-95 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/cli/__main__.py:65-67` @ `main`
**模块**: cli_and_app
**跨模块**: cli,app/naive_quantization,model,utils/security

**描述**: The trust_remote_code parameter flows from CLI argument to AutoModel.from_pretrained. While local_files_only=True prevents remote code fetching, trust_remote_code=True enables execution of custom Python code files (modeling_*.py) in the local model_path directory. A malicious model can contain arbitrary code that executes during model loading.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/cli/__main__.py:65-67`)

```c
quant_parser.add_argument('--trust_remote_code', type=convert_to_bool, default=False)
```

**达成路径**

args.trust_remote_code -> quant_main(args) [cli/naive_quantization/__main__.py:91-99] -> app.quant(trust_remote_code) -> model_factory.create(trust_remote_code) -> ModelAdapter.__init__(trust_remote_code) -> SafeGenerator.get_model_from_pretrained(**kwargs) -> AutoModelForCausalLM.from_pretrained(trust_remote_code=trust_remote_code)

**验证说明**: trust_remote_code flows to AutoModel.from_pretrained. local_files_only mitigates. User must enable explicitly. Related to VULN-XMOD-003.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-XMOD-003] code_injection - main

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-95 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `msmodelslim/cli/__main__.py:65-67` @ `main`
**模块**: cross_module_analysis
**跨模块**: cli → app_naive_quantization → model → utils_security

**描述**: Cross-module trust_remote_code risk: When user sets --trust_remote_code=True, the parameter flows through CLI → Application → Model Factory → Model Adapter → SafeGenerator → AutoModel.from_pretrained. Even with local_files_only=True, a malicious model config can contain 'auto_map' pointing to custom Python code files in the model directory. These files are executed during model loading, enabling arbitrary code execution.

**达成路径**

CLI args.trust_remote_code → quant_main() → ModelAdapter.__init__(trust_remote_code=True) → SafeGenerator.get_model_from_pretrained(**kwargs) → AutoModel.from_pretrained(trust_remote_code=True) [Config auto_map → Python code execution]

**验证说明**: trust_remote_code risk flows through CLI to model loading. local_files_only=True mitigates remote code. User must explicitly set --trust_remote_code=True to enable risk. Attack requires malicious auto_map in model config.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [infra-yaml-export-disable-user-check] Insecure Permission Check - export_quant_config

**严重性**: Medium | **CWE**: CWE-732 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/infra/yaml_quant_config_exporter.py:51-55` @ `export_quant_config`
**模块**: infra
**跨模块**: infra,utils/security/path.py

**描述**: yaml_safe_dump is called with check_user_stat=False when exporting quantization config, bypassing critical security checks: 1) File ownership validation - allows writing to files owned by other users, 2) Permission validation - allows writing to files with insecure permissions (group-writable or others-writable). This could enable privilege escalation or data tampering in multi-user environments.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/infra/yaml_quant_config_exporter.py:51-55`)

```c
yaml_safe_dump(quant_config.model_dump(mode='json'), str(file_path), check_user_stat=False)
```

**达成路径**

quant_config -> model_dump() -> yaml_safe_dump() with check_user_stat=False

**验证说明**: yaml_safe_dump called with check_user_stat=False bypasses ownership validation. Allows writing to files owned by others. Privilege escalation risk in multi-user environments. Intentional but reduces security.

**评分明细**: base: 30 | reachability: 10 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [CLI-001] Arbitrary Code Execution - argparse

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-95 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/cli/__main__.py:65-67` @ `argparse`
**模块**: msmodelslim/cli

**描述**: trust_remote_code allows arbitrary code execution from model files

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/cli/__main__.py:65-67`)

```c
trust_remote_code param
```

**达成路径**

CLI to model load

**验证说明**: trust_remote_code CLI parameter allows arbitrary code execution from model files. User must explicitly set True. Mitigation: default=False, warning message. Related to VULN-XMOD-003.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-PWC-003-2026] Uncontrolled Memory Allocation - GetDataFromBin

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-789 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/pytorch/weight_compression/compress_graph/src/graph_utils.cpp:61-65` @ `GetDataFromBin`
**模块**: pytorch_weight_compression_cpp

**描述**: Memory allocation new uint8_t[dataLen] has no upper bound limit. While File.h defines MAX_FILE_SIZE_DEFAULT=10GB, GetDataFromBin() does not enforce any size limit before allocation, potentially allowing DoS via memory exhaustion.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/pytorch/weight_compression/compress_graph/src/graph_utils.cpp:61-65`)

```c
uint8_t* heapData = new (std::nothrow) uint8_t[dataLen];
```

**达成路径**

graph_utils.cpp:51-53 (dataLen calculated from user-controlled shape) -> graph_utils.cpp:61 (unbounded allocation)

**验证说明**: Unbounded memory allocation. CheckShape limits but no max size. fileSize check provides partial mitigation.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SHELL-001] Command Injection via Permissive Regex - validate_safe_identifier

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `msmodelslim/utils/security/shell.py:33-62` @ `validate_safe_identifier`
**模块**: msmodelslim.utils.security.shell

**描述**: SAFE_IDENTIFIER_REGEX is too permissive, allowing dangerous characters: curly braces for brace expansion, colon for scheme/path injection, quotes for injection, comma as argument separator. These characters could enable command injection in certain contexts.

**漏洞代码** (`msmodelslim/utils/security/shell.py:33-62`)

```c
SAFE_IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z0-9_\-./{}:"\,]+$") allows dangerous chars
```

**达成路径**

User input -> validate_safe_identifier() -> SAFE_IDENTIFIER_REGEX allows {} : "" , -> command argument injection

**验证说明**: SAFE_IDENTIFIER_REGEX allows {}, :, quotes, comma - potentially dangerous chars. But shell=False prevents command injection. Characters could enable argument injection in specific contexts. Low confidence due to shell=False mitigation.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-ASCEND-005] Ineffective Security Warning - check_others_not_writable

**严重性**: Medium | **CWE**: CWE-693 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/ascend_utils/common/security/path.py:86-93` @ `check_others_not_writable`
**模块**: ascend_utils.common.security.path

**描述**: check_others_not_writable only logs warning, does not block operation. Allows attacker to place malicious files.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/ascend_utils/common/security/path.py:86-93`)

```c
logger.warning only, no exception raised
```

**达成路径**

Writable directory warning -> operation continues -> malicious file placed

**验证说明**: check_others_not_writable only logs warning, doesn't block. Attacker can place files in writable directories. Ineffective security check.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-WC-002] Race Condition - CheckDir, CheckFileBeforeCreateOrWrite

**严重性**: Medium（原评估: HIGH → 验证后: Medium） | **CWE**: CWE-367 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `msmodelslim/pytorch/weight_compression/security/src/File.cpp:188-254` @ `CheckDir, CheckFileBeforeCreateOrWrite`
**模块**: pytorch_weight_compression

**描述**: TOCTOU Race Condition in Directory/File Validation: Security checks (IsSoftLink, CheckOwner, IsDir, etc.) are performed sequentially before file operations, creating a Time-Of-Check-To-Time-Of-Use race condition. An attacker could replace a valid file with a symlink between validation and actual use. In CheckDir() and CheckFileBeforeCreateOrWrite(), path is validated then later used by fopen(), leaving exploitation window.

**漏洞代码** (`msmodelslim/pytorch/weight_compression/security/src/File.cpp:188-254`)

```c
// In CheckDir():
if (IsSoftLink(absPath)) { ERROR_LOG("path is soft link"); return false; }
// ... more checks ...
return true;  // Validation complete
// In WriteDataToFile (main.cpp:55):
FILE *fp = fopen(filePath, "w+");  // TOCTOU window - symlink could be placed here!
```

**验证说明**: TOCTOU race in File.cpp. Symlink check before fopen. Window exists but exploitation requires precise timing.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -15 | context: -10 | cross_file: 0

---

### [VULN-DF-PY-003] deserialization - get_model_from_pretrained

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `msmodelslim/utils/security/model.py:62` @ `get_model_from_pretrained`
**模块**: model

**描述**: AutoModelForCausalLM.from_pretrained() may internally use pickle to load model weights if the model uses pickle format (e.g., .bin files). Although get_valid_read_path() is called before loading, pickle deserialization of untrusted model files could lead to arbitrary code execution.

**漏洞代码** (`msmodelslim/utils/security/model.py:62`)

```c
model = AutoModelForCausalLM.from_pretrained(model_path, local_files_only=True, **kwargs)
```

**达成路径**

model_path (user input) -> get_valid_read_path() -> AutoModelForCausalLM.from_pretrained() [potential pickle deserialization]

**验证说明**: Pickle deserialization risk in AutoModel.from_pretrained. Mitigations: get_valid_read_path() validates path, local_files_only=True, check_user_stat=True. Residual risk: malicious model config with auto_map or malicious pickle in trusted directory.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-003-UTILS-SECURITY] Unsafe Deserialization - SafeGenerator.get_config_from_pretrained, get_model_from_pretrained

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `msmodelslim/utils/security/model.py:49-62` @ `SafeGenerator.get_config_from_pretrained, get_model_from_pretrained`
**模块**: utils_security

**描述**: AutoConfig.from_pretrained 和 AutoModelForCausalLM.from_pretrained 加载模型时存在 pickle 反序列化风险。已有缓解措施：local_files_only=True、路径验证 get_valid_read_path()、用户权限检查 check_user_stat=True。残留风险：如果用户提供的模型目录被恶意替换（包含恶意 pickle），仍可触发代码执行。配置文件中的 auto_map 字段可能被篡改。

**漏洞代码** (`msmodelslim/utils/security/model.py:49-62`)

```c
config = AutoConfig.from_pretrained(model_path, local_files_only=True, **kwargs)\nmodel = AutoModelForCausalLM.from_pretrained(model_path, local_files_only=True, **kwargs)
```

**达成路径**

model_path -> get_valid_read_path() (VALIDATED) -> Auto*.from_pretrained() (PICKLE RISK)

**验证说明**: Pickle deserialization in SafeGenerator methods. Mitigations: local_files_only=True, get_valid_read_path(), check_user_stat=True. Residual risk from auto_map or trusted directory attack.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-PYTORCH-WEIGHT-002] Improper Authentication - load_from_file

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-287 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/pytorch/weight_compression/compress_tools.py:297-299` @ `load_from_file`
**模块**: pytorch_weight_compression

**描述**: Interactive input() confirmation can be bypassed in automated/non-interactive environments. The check provides only a UI warning, not a true security boundary.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/pytorch/weight_compression/compress_tools.py:297-299`)

```c
input() confirmation bypass
```

**达成路径**

load_from_file -> input prompt bypassed

**验证说明**: input() confirmation can be bypassed. Same pattern as VULN-CLI-002.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-WC-005] File Handling - WriteDataToFile

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-59 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `msmodelslim/pytorch/weight_compression/compress_graph/src/main.cpp:30-73` @ `WriteDataToFile`
**模块**: pytorch_weight_compression

**描述**: WriteDataToFile Uses fopen Without O_NOFOLLOW: WriteDataToFile() uses fopen(filePath, "w+") which follows symbolic links. Even though CheckFileBeforeCreateOrWrite() checks for symlinks, the TOCTOU window exists. If an attacker replaces a file with a symlink between the check and fopen(), data could be written to arbitrary locations.

**漏洞代码** (`msmodelslim/pytorch/weight_compression/compress_graph/src/main.cpp:30-73`)

```c
if (!File::CheckFileBeforeCreateOrWrite(filePath, true)) { return FAILED; }
// TOCTOU window - attacker could replace file with symlink
FILE *fp = fopen(filePath, "w+");  // fopen follows symlinks!
```

**验证说明**: fopen follows symlinks. TOCTOU window between check and use. Related to VULN-WC-002.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (9)

### [VULN-PATH-003] TOCTOU Race Condition - get_valid_path

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-367 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `msmodelslim/utils/security/path.py:69-73` @ `get_valid_path`
**模块**: msmodelslim.utils.security.path

**描述**: Time-of-check to time-of-use race condition in symlink validation. The symlink status is checked before realpath resolution, creating a window for symlink swapping attacks.

**漏洞代码** (`msmodelslim/utils/security/path.py:69-73`)

```c
if os.path.islink(os.path.abspath(path)):  # TOCTOU: check\n    raise SecurityError(...)\nreal_path = os.path.realpath(path)  # TOCTOU: use
```

**达成路径**

Attacker creates symlink -> check passes -> attacker swaps symlink -> realpath resolves to malicious file

**验证说明**: TOCTOU race condition between islink check and realpath. Symlink swap attack possible but requires precise timing. realpath() resolution mitigates some risk. Static analysis pattern, practical exploitation difficult.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -15 | context: -10 | cross_file: 0

---

### [CLI-003] Information Exposure - quant

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-532 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/app/naive_quantization/application.py:398-418` @ `quant`
**模块**: msmodelslim/cli

**描述**: Sensitive parameters logged without sanitization. Model paths, save paths, and other potentially sensitive information are logged directly to INFO level logs. In production environments, this could expose sensitive directory structures or model locations.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/app/naive_quantization/application.py:398-418`)

```c
get_logger().info(f"model_type: {model_type}")\nget_logger().info(f"model_path: {model_path}")\nget_logger().info(f"save_path: {save_path}")
```

**达成路径**

Parameters -> get_logger().info() -> log file/output

**验证说明**: Sensitive parameters logged to INFO level. Model paths, save paths could expose directory structures. Information disclosure risk. Low severity - depends on log handling.

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: -5 | context: 10 | cross_file: 0

---

### [CLI-007] Path Traversal - argparse.add_argument

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/cli/__main__.py:61-62` @ `argparse.add_argument`
**模块**: msmodelslim/cli

**描述**: config_path parameter passed to yaml_safe_load without immediate CLI validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/cli/__main__.py:61-62`)

```c
quant_parser.add_argument --config_path type=str
```

**达成路径**

CLI args -> get_best_practice config_path -> yaml_safe_load

**验证说明**: config_path passed to yaml_safe_load. yaml_safe_load internally uses get_valid_read_path. So validation exists downstream. Low confidence - mitigated by yaml_safe_load.

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-ASCEND-004] TOCTOU Race Condition - get_valid_read_path

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-367 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/ascend_utils/common/security/path.py:117-130` @ `get_valid_read_path`
**模块**: ascend_utils.common.security.path

**描述**: Multiple os.stat calls create race condition windows

**验证说明**: TOCTOU in get_valid_read_path. Multiple os.stat calls create race windows. Same pattern as VULN-PATH-003. Practical exploitation difficult.

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: -15 | context: -10 | cross_file: 0

---

### [CLI-002] Improper Input Validation - argparse

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/cli/__main__.py:92-94` @ `argparse`
**模块**: msmodelslim/cli

**描述**: calib_dataset accepts arbitrary path without whitelist

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/cli/__main__.py:92-94`)

```c
calib_dataset param
```

**达成路径**

CLI to analysis

**验证说明**: calib_dataset parameter accepts arbitrary path. Downstream validation may exist. Path traversal to calibration data files. Needs further call chain analysis.

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CLI-004] Sensitive Data Exposure - main

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-226 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/cli/naive_quantization/__main__.py:68-71` @ `main`
**模块**: msmodelslim/cli

**描述**: Debug mode persists sensitive info without filtering

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/cli/naive_quantization/__main__.py:68-71`)

```c
debug persistence
```

**达成路径**

Debug files written

**验证说明**: Debug mode persists sensitive info. Debug files may contain model paths, parameters. Information disclosure in debug output. Depends on debug mode usage.

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-ASCEND-007] Dynamic Import Code Injection - check_type

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-94 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/ascend_utils/common/security/type.py:36-44` @ `check_type`
**模块**: ascend_utils.common.security.type

**描述**: check_type function uses importlib.import_module with module names derived from value_type.__module__ which could potentially be controlled by an attacker. If value_type can be influenced by user input, this could lead to arbitrary module import. The redirect_module_name is constructed by string replacement from user-provided data.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/ascend_utils/common/security/type.py:36-44`)

```c
def check_type(value, value_type, ...):\n    is_modelslim_import = (value.__class__.__module__.startswith(OLD_PACKAGE_NAME) and\n                           value_type.__module__.startswith(NEW_PACKAGE_NAME))\n    if is_modelslim_import:\n        original_module_name = value_type.__module__\n        redirect_module_name = original_module_name.replace(NEW_PACKAGE_NAME, OLD_PACKAGE_NAME)\n        module = importlib.import_module(redirect_module_name)\n        value_type = getattr(module, value_type.__qualname__)
```

**达成路径**

User-controlled value_type -> value_type.__module__ -> redirect_module_name -> importlib.import_module -> arbitrary module import

**验证说明**: Dynamic import via importlib.import_module with value_type.__module__. Module name derived from type, user control unclear. Indirect attack vector. Low confidence.

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CLI-002] Interactive Confirmation Bypass - get_best_practice

**严重性**: Low（原评估: MEDIUM → 验证后: Low） | **CWE**: CWE-352 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/app/naive_quantization/application.py:241-243` @ `get_best_practice`
**模块**: cli_and_app

**描述**: The get_best_practice() method uses input() for user confirmation before proceeding. Automated tools can pipe responses (e.g. echo y | python script.py) to bypass this check. While intended as user guidance, it provides no security guarantee and can be trivially bypassed.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/app/naive_quantization/application.py:241-243`)

```c
user_input = input(tips + "(Enter y to continue, otherwise it will exit): ").strip().lower()[:3]
```

**达成路径**

tips message -> input() call -> stdin can be piped -> execution continues

**验证说明**: input() confirmation bypass. Automated tools can pipe responses. UI warning, not security boundary.

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: -5 | context: 0 | cross_file: 0

---

### [infra-plugin-exception-swallow] Exception Swallowing - __init__

**严重性**: Low | **CWE**: CWE-392 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/infra/yaml_practice_manager.py:75-76` @ `__init__`
**模块**: infra

**描述**: Broad exception handling swallows all exceptions when processing third-party plugin directories, potentially hiding security-relevant failures. Missing logging prevents detection and investigation of malicious plugin directories, path traversal attempts, permission issues, or other attacks.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-ModelSlim/msmodelslim/infra/yaml_practice_manager.py:75-76`)

```c
except Exception: continue
```

**达成路径**

Third-party plugin directory processing -> exception swallowed

**验证说明**: Broad exception handling swallows all errors when processing plugin directories. Missing logging hides security-relevant failures. Detection difficulty for malicious plugins. Low severity - affects debugging, not direct attack.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -5 | context: 10 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| ascend_utils.common.security.path | 0 | 0 | 2 | 1 | 3 |
| ascend_utils.common.security.pytorch | 0 | 1 | 0 | 0 | 1 |
| ascend_utils.common.security.type | 0 | 0 | 0 | 1 | 1 |
| cli_and_app | 0 | 0 | 1 | 1 | 2 |
| cross_module_analysis | 0 | 1 | 1 | 0 | 2 |
| infra | 0 | 0 | 2 | 1 | 3 |
| model | 0 | 5 | 1 | 0 | 6 |
| msmodelslim.utils.security.model | 0 | 1 | 1 | 0 | 2 |
| msmodelslim.utils.security.path | 0 | 0 | 1 | 1 | 2 |
| msmodelslim.utils.security.shell | 0 | 1 | 1 | 0 | 2 |
| msmodelslim/cli | 0 | 0 | 1 | 4 | 5 |
| msmodelslim/model | 0 | 4 | 1 | 0 | 5 |
| pytorch_weight_compression | 0 | 0 | 3 | 0 | 3 |
| pytorch_weight_compression_cpp | 0 | 0 | 1 | 0 | 1 |
| utils_security | 0 | 0 | 2 | 0 | 2 |
| **合计** | **0** | **13** | **18** | **9** | **40** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 7 | 17.5% |
| CWE-829 | 5 | 12.5% |
| CWE-502 | 5 | 12.5% |
| CWE-95 | 3 | 7.5% |
| CWE-367 | 3 | 7.5% |
| CWE-94 | 2 | 5.0% |
| CWE-59 | 2 | 5.0% |
| CWE-789 | 1 | 2.5% |
| CWE-78 | 1 | 2.5% |
| CWE-732 | 1 | 2.5% |
| CWE-693 | 1 | 2.5% |
| CWE-532 | 1 | 2.5% |
| CWE-392 | 1 | 2.5% |
| CWE-352 | 1 | 2.5% |
| CWE-287 | 1 | 2.5% |
| CWE-269 | 1 | 2.5% |
| CWE-226 | 1 | 2.5% |
| CWE-22, CWE-73 | 1 | 2.5% |
| CWE-20 | 1 | 2.5% |
| CWE-15 | 1 | 2.5% |
