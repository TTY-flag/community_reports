# 漏洞扫描报告 — 已确认漏洞

**项目**: MindSpeed-LLM
**扫描时间**: 2026-04-20T09:37:58.850Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 31 | 81.6% |
| LIKELY | 7 | 18.4% |
| **总计** | **38** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 25 | 80.6% |
| High | 6 | 19.4% |
| **有效漏洞总计** | **31** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-CKPT-001]** unsafe_deserialization (Critical) - `mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:87` @ `load_hf_files_to_dict` | 置信度: 85
2. **[VULN-SEC-CKPT-002]** unsafe_deserialization (Critical) - `mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:372` @ `load_mg_model` | 置信度: 85
3. **[VULN-SEC-CKPT-003]** unsafe_deserialization (Critical) - `mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:404` @ `merge_checkpoints` | 置信度: 85
4. **[VULN-SEC-CKPT-004]** unsafe_deserialization (Critical) - `mindspeed_llm/tasks/checkpoint/convert_param.py:221` @ `get_hf_model_based_files` | 置信度: 85
5. **[VULN-SEC-CKPT-005]** unsafe_deserialization (Critical) - `mindspeed_llm/tasks/checkpoint/convert_param.py:581` @ `_set_dense_hf_model` | 置信度: 85
6. **[VULN-SEC-HA-001]** unsafe_deserialization (Critical) - `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:117` @ `checkpointing_load_base_checkpoint_patch` | 置信度: 85
7. **[VULN-SEC-HA-002]** unsafe_deserialization (Critical) - `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:129` @ `checkpointing_load_base_checkpoint_patch` | 置信度: 85
8. **[VULN-SEC-HA-003]** unsafe_deserialization (Critical) - `mindspeed_llm/core/high_availability/tft_optimizer_data_repair.py:204` @ `recv_ckpt_from_peer` | 置信度: 85
9. **[VULN-SEC-CKPT-006]** unsafe_deserialization (Critical) - `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:24` @ `distrib_optimizer_load_parameter_state_patch` | 置信度: 85
10. **[VULN-SEC-CKPT-007]** unsafe_deserialization (Critical) - `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:50` @ `chained_optimizer_load_parameter_state_patch` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `undefined@undefined` | training | - | - | GPT model pretraining entry point |
| `undefined@undefined` | evaluation | - | - | Model evaluation entry point for various benchmarks |
| `undefined@undefined` | inference | - | - | Model inference entry point |
| `undefined@undefined` | data_preprocessing | - | - | Data preprocessing for training |
| `undefined@undefined` | checkpoint_conversion | - | - | Checkpoint format conversion |
| `undefined@undefined` | rlhf_training | - | - | RLHF (Reinforcement Learning from Human Feedback) training |


---

## 3. Critical 漏洞 (25)

### [VULN-SEC-CKPT-001] unsafe_deserialization - load_hf_files_to_dict

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:87-88` @ `load_hf_files_to_dict`
**模块**: checkpoint_conversion

**描述**: torch.load() 使用 weights_only=False 加载 checkpoint 文件，存在 pickle 反序列化漏洞。攻击者可以通过篡改 checkpoint 文件注入恶意 pickle payload，实现任意代码执行。文件路径来自命令行参数，无路径验证。

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:87-88`)

```c
cur_weights = torch.load(file_path, map_location=torch.device('cpu'))
```

**达成路径**

命令行参数(args.load_dir) -> load_hf_files_to_dict(directory_path) -> os.listdir(directory_path) -> file_path -> torch.load(file_path) [SINK]

**验证说明**: Direct external input from CLI args (args.load_dir), fully controllable file path, no input validation. torch.load() with weights_only=False enables pickle RCE.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CKPT-002] unsafe_deserialization - load_mg_model

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:372-373` @ `load_mg_model`
**模块**: checkpoint_conversion

**描述**: torch.load() 使用 weights_only=False 加载 Megatron checkpoint 文件。checkpoint 文件路径来自命令行参数 load_dir，无验证，存在 pickle 反序列化 RCE 风险。

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:372-373`)

```c
src_model = torch.load(src_model_file, map_location='cpu', weights_only=False)
```

**达成路径**

args.load_dir -> get_latest_checkpoint_model_file(load_dir) -> src_model_file -> torch.load(src_model_file, weights_only=False) [SINK]

**验证说明**: Direct external input from CLI args, explicit weights_only=False, pickle RCE confirmed.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CKPT-003] unsafe_deserialization - merge_checkpoints

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:404-405` @ `merge_checkpoints`
**模块**: checkpoint_conversion

**描述**: torch.load() 使用 weights_only=False 加载 TP 分片的 checkpoint 文件。文件路径来自命令行参数，无路径验证，存在 pickle 反序列化漏洞。

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:404-405`)

```c
tp_models.append(torch.load(model_file, map_location='cpu', weights_only=False))
```

**达成路径**

args.load_dir -> input_model_dir -> get_model_file_path() -> model_file -> torch.load(model_file, weights_only=False) [SINK]

**验证说明**: Direct external input, TP checkpoint merge with weights_only=False, pickle RCE.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CKPT-004] unsafe_deserialization - get_hf_model_based_files

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mindspeed_llm/tasks/checkpoint/convert_param.py:221-222` @ `get_hf_model_based_files`
**模块**: checkpoint_conversion

**描述**: torch.load() 使用 weights_only=False 加载 HF 模型 .bin 文件。文件路径来自命令行参数 hf_dir，无路径验证，存在 pickle 反序列化漏洞。

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/convert_param.py:221-222`)

```c
hf_model = torch.load(file_path, map_location='cpu', weights_only=False)
```

**达成路径**

args_cmd.hf_dir -> file_path -> torch.load(file_path, weights_only=False) [SINK]

**验证说明**: torch.load weights_only=False with CLI hf_dir, pickle RCE

---

### [VULN-SEC-CKPT-005] unsafe_deserialization - _set_dense_hf_model

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mindspeed_llm/tasks/checkpoint/convert_param.py:581-582` @ `_set_dense_hf_model`
**模块**: checkpoint_conversion

**描述**: torch.load() 使用 weights_only=False 加载 Megatron checkpoint 文件用于转换到 HF 格式。文件路径来自命令行参数 mg_dir，无路径验证。

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/convert_param.py:581-582`)

```c
mg_tp_model = torch.load(os.path.join(mg_save_dir, self.mg_model_file_name), map_location='cpu', weights_only=False)
```

**达成路径**

args_cmd.mg_dir -> mg_save_dir -> torch.load(mg_save_dir/mg_model_file_name, weights_only=False) [SINK]

**验证说明**: torch.load weights_only=False with CLI mg_dir, pickle RCE

---

### [VULN-SEC-HA-001] unsafe_deserialization - checkpointing_load_base_checkpoint_patch

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:117-118` @ `checkpointing_load_base_checkpoint_patch`
**模块**: high_availability

**描述**: torch.load() 无 weights_only 参数加载 checkpoint 文件，默认为 False，存在 pickle 反序列化漏洞。checkpoint_name 来自 args.load 路径。

**漏洞代码** (`mindspeed_llm/core/high_availability/tft_acp_compatibility.py:117-118`)

```c
state_dict = torch.load(checkpoint_name, map_location='cpu', weights_only=False)
```

**达成路径**

args.load -> load_dir -> get_checkpoint_name() -> checkpoint_name -> torch.load(checkpoint_name, weights_only=False) [SINK]

**验证说明**: High availability checkpoint loading with weights_only=False, path from args.load, pickle RCE.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-HA-002] unsafe_deserialization - checkpointing_load_base_checkpoint_patch

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:129-130` @ `checkpointing_load_base_checkpoint_patch`
**模块**: high_availability

**描述**: torch.load() 在 backward compatibility 处理中无 weights_only 参数加载 checkpoint，存在 pickle 反序列化漏洞。

**漏洞代码** (`mindspeed_llm/core/high_availability/tft_acp_compatibility.py:129-130`)

```c
state_dict = torch.load(checkpoint_name, map_location='cpu', weights_only=False)
```

**达成路径**

checkpoint_name -> torch.load(checkpoint_name, weights_only=False) [SINK]

**验证说明**: torch.load weights_only=False backward compat, pickle RCE

---

### [VULN-SEC-HA-003] unsafe_deserialization - recv_ckpt_from_peer

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mindspeed_llm/core/high_availability/tft_optimizer_data_repair.py:204-205` @ `recv_ckpt_from_peer`
**模块**: high_availability

**描述**: torch.load() 使用 weights_only=False 反序列化从其他 rank 接收的 checkpoint 数据。数据来自分布式传输，虽然来源是可信 rank，但仍存在被篡改风险。

**漏洞代码** (`mindspeed_llm/core/high_availability/tft_optimizer_data_repair.py:204-205`)

```c
loaded_state_dict = torch.load(buffer, map_location=map_location, weights_only=False)
```

**达成路径**

torch.distributed.recv() -> state_dict_tensor -> state_dict_bytes -> buffer -> torch.load(buffer, weights_only=False) [SINK]

**验证说明**: torch.load from distributed recv, pickle RCE from malicious peer

---

### [VULN-SEC-CKPT-006] unsafe_deserialization - distrib_optimizer_load_parameter_state_patch

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:24` @ `distrib_optimizer_load_parameter_state_patch`
**模块**: checkpoint_conversion

**描述**: torch.load() 在向后兼容代码中无 weights_only 参数加载 checkpoint，默认为 False，存在 pickle 反序列化漏洞。checkpoint_name 来自 args.load 路径。

**漏洞代码** (`mindspeed_llm/core/high_availability/tft_acp_compatibility.py:24`)

```c
state_dict = torch.load(filename)
```

**达成路径**

args.load -> filename -> torch.load(filename) [SINK]

**验证说明**: torch.load missing weights_only defaults to unsafe pickle

---

### [VULN-SEC-CKPT-007] unsafe_deserialization - chained_optimizer_load_parameter_state_patch

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:50` @ `chained_optimizer_load_parameter_state_patch`
**模块**: high_availability

**描述**: torch.load() 无 weights_only 参数加载 checkpoint，默认为 False，存在 pickle 反序列化漏洞。

**漏洞代码** (`mindspeed_llm/core/high_availability/tft_acp_compatibility.py:50`)

```c
states = torch.load(filename)
```

**达成路径**

filename -> torch.load(filename) [SINK]

**验证说明**: torch.load missing weights_only defaults to unsafe pickle

---

### [VULN-SEC-CKPT-008] unsafe_deserialization - _update_hf_model_file

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mindspeed_llm/tasks/checkpoint/convert_param.py:755-756` @ `_update_hf_model_file`
**模块**: checkpoint_conversion

**描述**: torch.load() 使用 weights_only=False 加载已存在的 HF 模型文件。文件路径来自命令行参数 hf_dir。

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/convert_param.py:755-756`)

```c
exist_model = torch.load(file_path, map_location='cpu', weights_only=False) if os.path.exists(file_path) else {}
```

**达成路径**

args_cmd.hf_dir -> file_path -> torch.load(file_path, weights_only=False) [SINK]

**验证说明**: torch.load weights_only=False with hf_dir path

---

### [VULN-001] Deserialization of Untrusted Data - load_hf_files_to_dict

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:87` @ `load_hf_files_to_dict`
**模块**: mindspeed_llm/tasks/checkpoint

**描述**: Unsafe pickle deserialization via torch.load() with weights_only=False. Attacker-controlled checkpoint file paths from CLI arguments can lead to arbitrary code execution.

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:87`)

```c
cur_weights = torch.load(file_path, map_location=torch.device('cpu'))
```

**达成路径**

argparse --load → args.load_dir → load_hf_files_to_dict(directory_path) → torch.load(file_path)

**验证说明**: torch.load CLI path, pickle RCE

---

### [VULN-002] Deserialization of Untrusted Data - convert_hf2mg

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:372` @ `convert_hf2mg`
**模块**: mindspeed_llm/tasks/checkpoint

**描述**: Explicit weights_only=False in torch.load() enables pickle-based RCE from attacker-controlled checkpoint paths.

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:372`)

```c
src_model = torch.load(src_model_file, map_location='cpu', weights_only=False)
```

**达成路径**

argparse --load → args.load_dir → get_latest_checkpoint_model_file() → torch.load()

**验证说明**: torch.load weights_only=False, pickle RCE

---

### [VULN-003] Deserialization of Untrusted Data - merge_checkpoints

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:404` @ `merge_checkpoints`
**模块**: mindspeed_llm/tasks/checkpoint

**描述**: Explicit weights_only=False enables pickle-based RCE from attacker-controlled checkpoint paths.

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/convert_ckpt_mamba2.py:404`)

```c
tp_models.append(torch.load(model_file, map_location='cpu', weights_only=False))
```

**达成路径**

argparse --load → args.load_dir → get_model_file_path() → torch.load()

**验证说明**: torch.load weights_only=False, pickle RCE

---

### [VULN-004] Deserialization of Untrusted Data - convert_to_mg

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/tasks/checkpoint/convert_param.py:221` @ `convert_to_mg`
**模块**: mindspeed_llm/tasks/checkpoint

**描述**: Unsafe torch.load with explicit weights_only=False from CLI-controlled HF model directory.

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/convert_param.py:221`)

```c
hf_model = torch.load(file_path, map_location='cpu', weights_only=False)
```

**达成路径**

argparse --hf-dir → self.args_cmd.hf_dir → torch.load()

**验证说明**: torch.load weights_only=False HF model, pickle RCE

---

### [VULN-005] Deserialization of Untrusted Data - convert_to_hf

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/tasks/checkpoint/convert_param.py:581` @ `convert_to_hf`
**模块**: mindspeed_llm/tasks/checkpoint

**描述**: Unsafe torch.load with explicit weights_only=False from CLI-controlled MG model directory.

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/convert_param.py:581`)

```c
mg_tp_model = torch.load(os.path.join(mg_save_dir, self.mg_model_file_name), map_location='cpu', weights_only=False)
```

**达成路径**

argparse --mg-dir → self.args_cmd.mg_dir → get_mg_model_save_dir() → torch.load()

**验证说明**: torch.load weights_only=False MG model, pickle RCE

---

### [VULN-006] Deserialization of Untrusted Data - _update_hf_model_file

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/tasks/checkpoint/convert_param.py:755` @ `_update_hf_model_file`
**模块**: mindspeed_llm/tasks/checkpoint

**描述**: Conditional unsafe deserialization from CLI-controlled directory.

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/convert_param.py:755`)

```c
exist_model = torch.load(file_path, map_location='cpu', weights_only=False) if os.path.exists(file_path) else {}
```

**达成路径**

argparse --hf-dir → self.args_cmd.hf_dir → torch.load()

**验证说明**: torch.load weights_only=False conditional, pickle RCE

---

### [VULN-007] Deserialization of Untrusted Data - generate_mg_weights

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/tasks/checkpoint/convert_ckpt_longcat.py:312` @ `generate_mg_weights`
**模块**: mindspeed_llm/tasks/checkpoint

**描述**: Unsafe checkpoint loading in longcat conversion.

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/convert_ckpt_longcat.py:312`)

```c
model_dict = torch.load(save_file_name, map_location='cpu', weights_only=False)
```

**达成路径**

argparse → args → save_dir → torch.load()

**验证说明**: torch.load weights_only=False longcat, pickle RCE

---

### [VULN-008] Deserialization of Untrusted Data - generate_mg_weights

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/tasks/checkpoint/convert_ckpt_longcat.py:336` @ `generate_mg_weights`
**模块**: mindspeed_llm/tasks/checkpoint

**描述**: Unsafe checkpoint loading in longcat conversion (final layer).

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/convert_ckpt_longcat.py:336`)

```c
model_dict = torch.load(save_file_name, map_location='cpu', weights_only=False)
```

**达成路径**

argparse → args → save_dir → torch.load()

**验证说明**: torch.load weights_only=False longcat final, pickle RCE

---

### [VULN-009] Deserialization of Untrusted Data - load_ckpt

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/tasks/posttrain/ldt_sft/convert_ckpt_pp_vpp.py:130` @ `load_ckpt`
**模块**: mindspeed_llm/tasks/posttrain/ldt_sft

**描述**: Central unsafe deserialization function in PP/VPP checkpoint conversion.

**漏洞代码** (`mindspeed_llm/tasks/posttrain/ldt_sft/convert_ckpt_pp_vpp.py:130`)

```c
return torch.load(checkpoint_path, map_location='cpu', weights_only=False)
```

**达成路径**

argparse --load-dir → get_checkpoint_name() → torch.load()

**验证说明**: torch.load weights_only=False PP/VPP, pickle RCE

---

### [VULN-010] Deserialization of Untrusted Data - distrib_optimizer_load_parameter_state_patch

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:24` @ `distrib_optimizer_load_parameter_state_patch`
**模块**: mindspeed_llm/core/high_availability

**描述**: Missing weights_only parameter in torch.load() defaults to unsafe pickle deserialization.

**漏洞代码** (`mindspeed_llm/core/high_availability/tft_acp_compatibility.py:24`)

```c
state_dict = torch.load(filename)
```

**达成路径**

args.load → load_dir → get_checkpoint_name() → filename → torch.load()

**验证说明**: torch.load missing weights_only, pickle RCE

---

### [VULN-011] Deserialization of Untrusted Data - chained_optimizer_load_parameter_state_patch

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:50` @ `chained_optimizer_load_parameter_state_patch`
**模块**: mindspeed_llm/core/high_availability

**描述**: Missing weights_only parameter in torch.load().

**漏洞代码** (`mindspeed_llm/core/high_availability/tft_acp_compatibility.py:50`)

```c
states = torch.load(filename)
```

**达成路径**

args.load → filename → torch.load()

**验证说明**: torch.load missing weights_only, pickle RCE

---

### [VULN-012] Deserialization of Untrusted Data - load_checkpoint_for_high_availability

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:115-117` @ `load_checkpoint_for_high_availability`
**模块**: mindspeed_llm/core/high_availability

**描述**: Explicit weights_only=False enables pickle-based RCE from checkpoint paths.

**漏洞代码** (`mindspeed_llm/core/high_availability/tft_acp_compatibility.py:115-117`)

```c
state_dict = torch.load(checkpoint_name, map_location='cpu', weights_only=False)
```

**达成路径**

args.load + args.ckpt_step → checkpoint_name → torch.load()

**验证说明**: torch.load weights_only=False HA, pickle RCE

---

### [VULN-013] Deserialization of Untrusted Data - load_checkpoint_for_high_availability

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/core/high_availability/tft_acp_compatibility.py:129` @ `load_checkpoint_for_high_availability`
**模块**: mindspeed_llm/core/high_availability

**描述**: Explicit weights_only=False in exception handler.

**漏洞代码** (`mindspeed_llm/core/high_availability/tft_acp_compatibility.py:129`)

```c
state_dict = torch.load(checkpoint_name, map_location='cpu', weights_only=False)
```

**达成路径**

args.load → checkpoint_name → torch.load()

**验证说明**: torch.load weights_only=False exception handler, pickle RCE

---

### [VULN-014] Deserialization of Untrusted Data - recv_ckpt_from_peer

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/core/high_availability/tft_optimizer_data_repair.py:204` @ `recv_ckpt_from_peer`
**模块**: mindspeed_llm/core/high_availability

**描述**: Unsafe deserialization of checkpoint received from distributed peer rank. Malicious peer can send pickle payload.

**漏洞代码** (`mindspeed_llm/core/high_availability/tft_optimizer_data_repair.py:204`)

```c
loaded_state_dict = torch.load(buffer, map_location=map_location, weights_only=False)
```

**达成路径**

distributed.recv() from peer rank → buffer → torch.load()

**验证说明**: Distributed recv from peer rank, pickle deserialization without validation. Malicious peer can send RCE payload.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

---

## 4. High 漏洞 (6)

### [VULN-SEC-DYN-001] dynamic_module_loading - load_plugin

**严重性**: High | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `convert_ckpt.py:22-23` @ `load_plugin`
**模块**: checkpoint_conversion

**描述**: importlib.import_module() 动态加载转换器插件模块。模块名来自命令行参数 --loader 和 --saver，通过字符串拼接构造模块名，可能导致加载任意模块。

**漏洞代码** (`convert_ckpt.py:22-23`)

```c
plugin = importlib.import_module(module_name)
```

**达成路径**

命令行参数 known_args.loader -> module_name = f'{MODULE_ROOT}.{plugin_type}_{name}' -> importlib.import_module(module_name) [SINK]

**验证说明**: importlib.import_module() with user-controlled module name from CLI args --loader/--saver, arbitrary module loading.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-015] Improper Control of Generation of Code - load_plugin

**严重性**: High | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `convert_ckpt.py:22-26` @ `load_plugin`
**模块**: root

**描述**: Dynamic module loading via importlib.import_module() with user-controlled module name from CLI arguments allows arbitrary module loading.

**漏洞代码** (`convert_ckpt.py:22-26`)

```c
plugin = importlib.import_module(module_name)
```

**达成路径**

argparse --loader/--saver → load_plugin() → importlib.import_module()

**验证说明**: importlib.import_module with CLI args

---

### [VULN-016] Improper Control of Generation of Code - load_plugin

**严重性**: High | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `mindspeed_llm/mindspore/convert_ckpt.py:27-31` @ `load_plugin`
**模块**: mindspeed_llm/mindspore

**描述**: Dynamic module loading with user-controlled module name (mirror of convert_ckpt.py).

**漏洞代码** (`mindspeed_llm/mindspore/convert_ckpt.py:27-31`)

```c
plugin = importlib.import_module(module_name)
```

**达成路径**

argparse --loader/--saver → load_plugin() → importlib.import_module()

**验证说明**: importlib.import_module mirror of convert_ckpt.py

---

### [VULN-SEC-TRUST-001] unsafe_code_execution - main

**严重性**: High | **CWE**: CWE-940 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `evaluation.py:383` @ `main`
**模块**: evaluation

**描述**: AutoTokenizer.from_pretrained() 使用 trust_remote_code=True。即使有 local_files_only=True，如果本地模型仓库被篡改或用户下载了被污染的模型，trust_remote_code=True 允许执行模型中的自定义代码。tokenizer_name_or_path 来自命令行参数。

**漏洞代码** (`evaluation.py:383`)

```c
tokenizer = AutoTokenizer.from_pretrained(args.tokenizer_name_or_path, trust_remote_code=True, local_files_only=True)
```

**达成路径**

命令行参数(args.tokenizer_name_or_path) -> AutoTokenizer.from_pretrained(trust_remote_code=True) [SINK]

**验证说明**: trust_remote_code=True with local_files_only=True. Path from CLI args. Local tampered model can execute arbitrary code.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-TRUST-002] unsafe_code_execution - get_modules_from_config

**严重性**: High | **CWE**: CWE-940 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mindspeed_llm/tasks/checkpoint/models.py:514-516` @ `get_modules_from_config`
**模块**: checkpoint_conversion

**描述**: AutoModelForCausalLM.from_config() 使用 trust_remote_code=True 加载模型配置。config 来自 load_dir 目录，如果目录被篡改，可执行恶意代码。

**漏洞代码** (`mindspeed_llm/tasks/checkpoint/models.py:514-516`)

```c
config = AutoConfig.from_pretrained(load_dir, trust_remote_code=trust_remote_code)
hf_model = AutoModelForCausalLM.from_config(config, trust_remote_code=trust_remote_code)
```

**达成路径**

load_dir -> AutoConfig.from_pretrained(trust_remote_code=True) -> AutoModelForCausalLM.from_config(trust_remote_code=True) [SINK]

**验证说明**: trust_remote_code=True with AutoModelForCausalLM.from_config

---

### [VULN-018] Improper Verification of Source of Communication Channel - main

**严重性**: High | **CWE**: CWE-940 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: dataflow_scanner

**位置**: `evaluation.py:383` @ `main`
**模块**: mindspeed_llm/tasks/evaluation

**描述**: trust_remote_code=True in AutoTokenizer.from_pretrained allows arbitrary code execution from model repository.

**漏洞代码** (`evaluation.py:383`)

```c
tokenizer = AutoTokenizer.from_pretrained(args.tokenizer_name_or_path, trust_remote_code=True, local_files_only=True)
```

**达成路径**

argparse → args.tokenizer_name_or_path → AutoTokenizer.from_pretrained(trust_remote_code=True)

**验证说明**: trust_remote_code=True with local_files_only, local tampering risk

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| checkpoint_conversion | 7 | 2 | 0 | 0 | 9 |
| evaluation | 0 | 1 | 0 | 0 | 1 |
| high_availability | 4 | 0 | 0 | 0 | 4 |
| mindspeed_llm/core/high_availability | 5 | 0 | 0 | 0 | 5 |
| mindspeed_llm/mindspore | 0 | 1 | 0 | 0 | 1 |
| mindspeed_llm/tasks/checkpoint | 8 | 0 | 0 | 0 | 8 |
| mindspeed_llm/tasks/evaluation | 0 | 1 | 0 | 0 | 1 |
| mindspeed_llm/tasks/posttrain/ldt_sft | 1 | 0 | 0 | 0 | 1 |
| root | 0 | 1 | 0 | 0 | 1 |
| **合计** | **25** | **6** | **0** | **0** | **31** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-502 | 25 | 80.6% |
| CWE-940 | 3 | 9.7% |
| CWE-94 | 3 | 9.7% |
