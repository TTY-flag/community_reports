# 漏洞扫描报告 — 待确认漏洞

**项目**: amct_pytorch
**扫描时间**: 2026-04-22T18:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 8 | 66.7% |
| CONFIRMED | 3 | 25.0% |
| FALSE_POSITIVE | 1 | 8.3% |
| **总计** | **12** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Medium | 7 | 87.5% |
| Low | 1 | 12.5% |
| **有效漏洞总计** | **8** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-PT-002]** path_traversal (Medium) - `amct_pytorch/graph_based_compression/amct_pytorch/common/utils/files.py:52` @ `create_empty_file` | 置信度: 70
2. **[VULN-DF-PT-003]** path_traversal (Medium) - `amct_pytorch/graph_based_compression/amct_pytorch/common/utils/files.py:34` @ `create_path` | 置信度: 70
3. **[VULN-DF-PT-004]** path_traversal (Medium) - `amct_pytorch/graph_based_compression/amct_pytorch/common/utils/files.py:191` @ `parse_dump_data` | 置信度: 70
4. **[VULN-SEC-003]** unsafe_deserialization (Medium) - `amct_pytorch/experimental/quantization/DeepSeekV3.2/deploy.py:280` @ `load_clip_params` | 置信度: 65
5. **[VULN-SEC-004]** unsafe_deserialization (Medium) - `amct_pytorch/experimental/quantization/DeepSeekV3.2/extract_calib_data.py:150` @ `get_layers_input` | 置信度: 65
6. **[VULN-SEC-005]** unsafe_deserialization (Medium) - `amct_pytorch/experimental/quantization/DeepSeekV3.2/pp/forward/infer.py:132` @ `load_layer_inputs` | 置信度: 65
7. **[VULN-DF-PT-006]** path_traversal (Medium) - `amct_pytorch/experimental/quantization/DeepSeekV3.2/deploy.py:280` @ `load_quant_params` | 置信度: 65
8. **[VULN-DF-PT-005]** path_traversal (Low) - `amct_pytorch/graph_based_compression/amct_pytorch/common/utils/files.py:165` @ `find_dump_file` | 置信度: 60

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `quantize@amct_pytorch/quantize.py` | decorator | semi_trusted | Main public API entry point - user provides PyTorch model and config dict directly | Quantize a PyTorch model according to config dict |
| `convert@amct_pytorch/quantize.py` | decorator | semi_trusted | Public API entry point - user provides quantized model | Convert quantized calibration model to deployment model |
| `algorithm_register@amct_pytorch/quantize.py` | decorator | semi_trusted | Public API entry point - user provides custom algorithm modules | Register custom quantization algorithm |
| `parse_config@amct_pytorch/config/parser.py` | internal | untrusted_local | Called from quantize(), processes user-provided config dict with potential malicious input | Parse user config dict into layer-specific quant configs |
| `QuantConfig.__init__@amct_pytorch/config/fields.py` | internal | untrusted_local | Processes user-provided config dict with various fields that need validation | Initialize QuantConfig from user config dict |
| `match_fuzzy_pattern@amct_pytorch/config/utils.py` | internal | untrusted_local | Pattern matching with fnmatch - potential wildcard injection if layer_name contains malicious patterns | Match layer names with fuzzy patterns containing wildcards |
| `create_quant_config@amct_pytorch/graph_based_compression/amct_pytorch/quantize_tool.py` | file | untrusted_local | User-provided file path (config_file) - potential path traversal | Create quantization config file from user-specified path |
| `quantize_preprocess@amct_pytorch/graph_based_compression/amct_pytorch/quantize_tool.py` | file | untrusted_local | User-provided file paths (config_file, record_file) - potential path traversal | Quantize preprocessing with user-specified file paths |
| `quantize_model@amct_pytorch/graph_based_compression/amct_pytorch/quantize_tool.py` | file | untrusted_local | User-provided file paths (config_file, modified_onnx_file, record_file) - potential path traversal | Quantize model with user-specified file paths |
| `save_model@amct_pytorch/graph_based_compression/amct_pytorch/quantize_tool.py` | file | untrusted_local | User-provided file paths (modified_onnx_file, record_file, save_path) - potential path traversal | Save quantized model to user-specified paths |
| `create_quant_cali_config@amct_pytorch/graph_based_compression/amct_pytorch/quant_calibration_interface.py` | file | untrusted_local | User-provided file path (config_file) - potential path traversal | Create quant calibration config file |
| `create_quant_cali_model@amct_pytorch/graph_based_compression/amct_pytorch/quant_calibration_interface.py` | file | untrusted_local | User-provided file paths (config_file, record_file) - potential path traversal | Create quant calibration model |
| `FloatToHifloat8@amct_pytorch/experimental/hifloat8/hifloat8_cast.cpp` | rpc | semi_trusted | Pybind11 exported C++ function - processes tensor data directly from Python, potential buffer overflow if tensor is malformed | Cast float tensor to hifloat8 tensor |
| `Hifloat8ToFloat32@amct_pytorch/experimental/hifloat8/hifloat8_cast.cpp` | rpc | semi_trusted | Pybind11 exported C++ function - processes tensor data, potential buffer overflow if input is malformed | Convert hifloat8 tensor to float32 tensor |
| `GetRank@amct_pytorch/graph_based_compression/amct_tensor_decompose/src/tensor_decomposition_api.cpp` | rpc | semi_trusted | extern C exported function - takes ConvInfo struct and double array, potential buffer overflow if length is invalid | Estimate rank for tensor decomposition |
| `main@amct_pytorch/experimental/quantization/DeepSeekV3.2/main.py` | cmdline | semi_trusted | CLI script entry point - takes command line args including file paths | DeepSeekV3.2 quantization CLI script |

**其他攻击面**:
- Configuration Dictionary Input: User-provided config dicts in quantize() and parse_config() with nested fields (batch_num, quant_cfg, algorithm, skip_layers)
- File Path Input: User-specified file paths in graph_based_compression APIs (config_file, record_file, save_path, onnx_file) with os.path.realpath processing
- Pybind11 C++ Extension: hifloat8_cast.cpp tensor conversion functions (FloatToHifloat8, Hifloat8ToFloat32) processing raw tensor data
- extern C Function: tensor_decomposition_api.cpp GetRank() taking array pointer and length
- Fuzzy Pattern Matching: config/utils.py match_fuzzy_pattern() using fnmatch with wildcard patterns
- JSON Configuration Files: Configuration class parsing JSON config files
- ONNX Model Export: Parser.export_onnx() exporting models to user-specified paths
- Model Loading: load_pth_file() loading PyTorch checkpoint files from user-specified paths
- DeepSeekV3.2 CLI: experimental/quantization/DeepSeekV3.2/main.py taking command line arguments for model paths and data directories

---

## 3. Medium 漏洞 (7)

### [VULN-DF-PT-002] path_traversal - create_empty_file

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `amct_pytorch/graph_based_compression/amct_pytorch/common/utils/files.py:52-62` @ `create_empty_file`
**模块**: graph_based_compression

**描述**: Arbitrary file creation via path traversal. The function uses os.path.realpath() to normalize path but lacks directory whitelist validation. User can create empty files at arbitrary locations, potentially overwriting critical system files.

**漏洞代码** (`amct_pytorch/graph_based_compression/amct_pytorch/common/utils/files.py:52-62`)

```c
def create_empty_file(file_name, check_exist=False):
    file_realpath = os.path.realpath(file_name)
    create_file_path(file_realpath, check_exist=check_exist)
    with open(file_realpath, 'w') as record_file:
        record_file.write('')
```

**达成路径**

quantize_tool.py:119 quantize_preprocess() [SOURCE: user-provided record_file] -> files.py:54 create_empty_file() -> files.py:58 open(file_realpath) [SINK]

**验证说明**: 真实漏洞：create_empty_file 使用 os.path.realpath 规范化路径但无目录白名单验证。用户通过 quantize_preprocess API 提供 record_file 参数，可在任意位置创建文件。作为库的使用场景，用户通常控制自己的文件系统，但在共享环境或库被不信任用户调用时可被利用。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-PT-003] path_traversal - create_path

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `amct_pytorch/graph_based_compression/amct_pytorch/common/utils/files.py:34-40` @ `create_path`
**模块**: graph_based_compression

**描述**: Arbitrary directory creation via path traversal. The function uses os.path.realpath() but lacks directory whitelist. User can create directories at arbitrary filesystem locations.

**漏洞代码** (`amct_pytorch/graph_based_compression/amct_pytorch/common/utils/files.py:34-40`)

```c
def create_path(file_path, mode=DIR_MODE):
    file_dir = os.path.realpath(file_path)
    os.makedirs(file_dir, mode, exist_ok=True)
```

**达成路径**

quantize_tool.py:696 _generate_model() [SOURCE: user-provided save_path] -> files.py:36 create_path() [SINK: os.makedirs]

**验证说明**: 真实漏洞：create_path 使用 os.path.realpath 规范化路径但无目录白名单验证。用户通过 _generate_model 的 save_path 参数提供路径，可在任意位置创建目录。作为库的使用场景，风险取决于调用环境。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-PT-004] path_traversal - parse_dump_data

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `amct_pytorch/graph_based_compression/amct_pytorch/common/utils/files.py:191-223` @ `parse_dump_data`
**模块**: graph_based_compression

**描述**: Arbitrary file read via path traversal. User-provided file_path is normalized with realpath but lacks whitelist validation. Allows reading arbitrary files including sensitive system files.

**漏洞代码** (`amct_pytorch/graph_based_compression/amct_pytorch/common/utils/files.py:191-223`)

```c
def parse_dump_data(file_path, with_type=False):
    real_file_path = os.path.realpath(file_path)
    dump_data = np.fromfile(real_file_path, np.byte)
```

**达成路径**

User API call [SOURCE: file_path param] -> files.py:203 np.fromfile(real_file_path) [SINK]

**验证说明**: 真实漏洞：parse_dump_data 使用 os.path.realpath 规范化路径但无白名单验证。用户通过 API 提供 file_path，可读取任意文件内容。影响：敏感信息泄露或读取配置文件。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-003] unsafe_deserialization - load_clip_params

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `amct_pytorch/experimental/quantization/DeepSeekV3.2/deploy.py:280-288` @ `load_clip_params`
**模块**: experimental_quantization

**描述**: Unsafe pickle deserialization via torch.load() without weights_only=True. The function loads quantization parameters from user-provided .pth files without the safe loading option.

**漏洞代码** (`amct_pytorch/experimental/quantization/DeepSeekV3.2/deploy.py:280-288`)

```c
old_quant_params = torch.load(expected_file)
old_quant_params.update(torch.load(expected_file.replace(mla_param_path, moe_param_path)))
quant_params = torch.load(expected_file)
quant_params.update(torch.load(expected_file.replace(mla_param_path, moe_param_path)))
```

**达成路径**

User input (mla_param_path, moe_param_path) → torch.load() without weights_only=True [SINK]

**验证说明**: 与 VULN-DF-PT-006 相同漏洞点：deploy.py CLI 工具中的 torch.load 存在 pickle 反序列化风险。用户通过 --mla_param_path/--moe_param_path CLI 参数提供路径。实验性代码，但仍存在恶意模型文件 RCE 风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: -10 | cross_file: 0

---

### [VULN-SEC-004] unsafe_deserialization - get_layers_input

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `amct_pytorch/experimental/quantization/DeepSeekV3.2/extract_calib_data.py:150-155` @ `get_layers_input`
**模块**: experimental_quantization

**描述**: Unsafe pickle deserialization via torch.load() with weights_only=False. Loading calibration data from .pkl files with unsafe pickle deserialization.

**漏洞代码** (`amct_pytorch/experimental/quantization/DeepSeekV3.2/extract_calib_data.py:150-155`)

```c
inps = torch.load(os.path.join(output_dir, f'layer_{layer_idx - 1}_out.pkl'),
    weights_only=False, map_location=device)
attention_mask = torch.load(
    os.path.join(output_dir, 'attention_mask.pkl'), weights_only=False, map_location=device)
```

**达成路径**

User input (output_dir) → torch.load(weights_only=False) [SINK]

**验证说明**: 实验性代码漏洞：extract_calib_data.py 中 torch.load(weights_only=False) 加载 output_dir 中的 .pkl 文件。用户通过 CLI 参数提供 output_dir。存在恶意校准数据文件 RCE 风险，但作为实验脚本，使用范围有限。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: -10 | cross_file: 0

---

### [VULN-SEC-005] unsafe_deserialization - load_layer_inputs

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `amct_pytorch/experimental/quantization/DeepSeekV3.2/pp/forward/infer.py:132-137` @ `load_layer_inputs`
**模块**: experimental_quantization

**描述**: Unsafe pickle deserialization via torch.load() with weights_only=False. Loading inference inputs from .pkl files with unsafe deserialization.

**漏洞代码** (`amct_pytorch/experimental/quantization/DeepSeekV3.2/pp/forward/infer.py:132-137`)

```c
inps = torch.load(os.path.join(output_dir, f'layer_{layer_idxes[0] - 1}_out.pkl'),
    weights_only=False, map_location=device)
attention_mask = torch.load(
    os.path.join(output_dir, 'attention_mask.pkl'), weights_only=False, map_location=device)
```

**达成路径**

User input (output_dir) → torch.load(weights_only=False) [SINK]

**验证说明**: 实验性代码漏洞：infer.py 中 torch.load(weights_only=False) 加载推理输入数据。用户通过 CLI 参数提供 output_dir。存在恶意 .pkl 文件 RCE 风险，但作为实验脚本，使用范围有限。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: -10 | cross_file: 0

---

### [VULN-DF-PT-006] path_traversal - load_quant_params

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `amct_pytorch/experimental/quantization/DeepSeekV3.2/deploy.py:280-288` @ `load_quant_params`
**模块**: experimental_quantization

**描述**: Arbitrary file read via torch.load without path validation. User-provided file paths (expected_file) are loaded without whitelist validation, allowing reading arbitrary files including sensitive system files.

**漏洞代码** (`amct_pytorch/experimental/quantization/DeepSeekV3.2/deploy.py:280-288`)

```c
old_quant_params = torch.load(expected_file)
old_quant_params.update(torch.load(expected_file.replace(mla_param_path, moe_param_path)))
quant_params = torch.load(expected_file)
```

**达成路径**

CLI args [SOURCE: user-provided paths] -> deploy.py:280 torch.load(expected_file) [SINK]

**验证说明**: 真实漏洞但场景受限：deploy.py 是 CLI 工具而非库 API，用户通过 CLI 参数提供模型路径。torch.load 无 weights_only 参数，存在 pickle 反序列化风险。作为实验性代码（experimental/目录），使用范围有限，但仍需警惕恶意模型文件导致的 RCE。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: -10 | cross_file: 0

---

## 4. Low 漏洞 (1)

### [VULN-DF-PT-005] path_traversal - find_dump_file

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `amct_pytorch/graph_based_compression/amct_pytorch/common/utils/files.py:165-188` @ `find_dump_file`
**模块**: graph_based_compression

**描述**: Directory enumeration via path traversal. User-provided data_dir is normalized but allows listing arbitrary directory contents, potentially exposing sensitive file information.

**漏洞代码** (`amct_pytorch/graph_based_compression/amct_pytorch/common/utils/files.py:165-188`)

```c
def find_dump_file(data_dir, name_prefix):
    data_dir = os.path.realpath(data_dir)
    file_list = os.listdir(data_dir)
```

**达成路径**

User API call [SOURCE: data_dir param] -> files.py:180 os.listdir(data_dir) [SINK]

**验证说明**: 真实漏洞但影响有限：find_dump_file 使用 os.path.realpath 规范化路径但无白名单验证。用户可枚举任意目录内容。影响：信息泄露（目录内容列表）。严重性降级为 Low。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: -10 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| experimental_quantization | 0 | 0 | 4 | 0 | 4 |
| graph_based_compression | 0 | 0 | 3 | 1 | 4 |
| **合计** | **0** | **0** | **7** | **1** | **8** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 5 | 62.5% |
| CWE-502 | 3 | 37.5% |
