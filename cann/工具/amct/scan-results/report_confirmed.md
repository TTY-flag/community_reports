# 漏洞扫描报告 — 已确认漏洞

**项目**: amct_pytorch
**扫描时间**: 2026-04-22T18:30:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## Executive Summary

本次扫描在 **amct_pytorch** 项目中发现 **3 个已确认的严重漏洞**，全部为 **Pickle 反序列化导致的远程代码执行 (RCE)** 风险。

### 关键发现

- **严重程度**: 所有确认漏洞均为 **Critical** 级别
- **漏洞类型**: CWE-502 (Deserialization of Untrusted Data)
- **根本原因**: `torch.load()` 显式设置 `weights_only=False`，允许任意 pickle 反序列化
- **攻击影响**: 恶意模型文件可导致 **完全系统控制**

### 风险评估

这些漏洞存在于核心库代码中，用户通过 API 参数提供模型文件路径即可触发。在以下场景中风险极高：
- 加载不信任来源的模型文件
- 共享环境或云平台中运行量化任务
- 供应链攻击（污染共享模型文件）

### 紧急行动建议

1. **立即修复**: 将所有 `torch.load()` 调用的 `weights_only` 参数改为 `True`
2. **迁移到 safetensors**: 使用无反序列化风险的模型存储格式
3. **安全警告**: 在文档中明确警告用户不要加载不信任来源的模型文件

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
| Critical | 3 | 100.0% |
| **有效漏洞总计** | **3** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-001]** unsafe_deserialization (Critical) - `amct_pytorch/graph_based_compression/amct_pytorch/utils/model_util.py:139` @ `load_pth_file` | 置信度: 85
2. **[VULN-SEC-002]** unsafe_deserialization (Critical) - `amct_pytorch/graph_based_compression/amct_pytorch/parser/module_based_record_parser.py:38` @ `get_layer_quant_params` | 置信度: 85
3. **[VULN-DF-DS-001]** deserialization (Critical) - `amct_pytorch/graph_based_compression/amct_pytorch/utils/model_util.py:129` @ `load_pth_file` | 置信度: 85

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

## 3. Critical 漏洞 (3)

### [VULN-SEC-001] unsafe_deserialization - load_pth_file

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `amct_pytorch/graph_based_compression/amct_pytorch/utils/model_util.py:139-143` @ `load_pth_file`
**模块**: graph_based_compression

**描述**: Unsafe pickle deserialization via torch.load() with weights_only=False. The function accepts user-provided pth_file path and loads it using torch.load() which internally uses pickle when weights_only=False. This allows arbitrary code execution if a malicious .pth file is provided.

**漏洞代码** (`amct_pytorch/graph_based_compression/amct_pytorch/utils/model_util.py:139-143`)

```c
load_kwargs = {'map_location': torch.device('cpu')}
if version_higher_than(torch.__version__, '2.1.0'):
    load_kwargs['weights_only'] = False
checkpoint = torch.load(pth_file, **load_kwargs)
```

**达成路径**

User input (pth_file) → load_pth_file() → torch.load(weights_only=False) → pickle deserialization [SINK]

**验证说明**: 严重漏洞：torch.load(weights_only=False) 显式禁用安全加载模式，允许任意 pickle 反序列化。用户通过 restore_quant_retrain_model API 提供 pth_file 参数，恶意 .pth 文件可导致 RCE。这是一个真实的严重安全威胁，恶意模型文件可能导致完全的系统控制。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 10 | cross_file: 0

---

### [VULN-SEC-002] unsafe_deserialization - get_layer_quant_params

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `amct_pytorch/graph_based_compression/amct_pytorch/parser/module_based_record_parser.py:38-43` @ `get_layer_quant_params`
**模块**: graph_based_compression

**描述**: Unsafe pickle deserialization via torch.load() with weights_only=False. The quant_result_path is read from records (user-provided record file) and loaded using torch.load() with weights_only=False, enabling arbitrary code execution.

**漏洞代码** (`amct_pytorch/graph_based_compression/amct_pytorch/parser/module_based_record_parser.py:38-43`)

```c
if version_higher_than(torch.__version__, '2.1.0'):
    load_kwargs = {'mmap': True, 'weights_only': False}
else:
    load_kwargs = {}
quant_params = torch.load(quant_result_path, **load_kwargs)
```

**达成路径**

User input (record file) → records['quant_result_path'] → torch.load(weights_only=False) [SINK]

**验证说明**: 严重漏洞：torch.load(weights_only=False) 加载用户 record 文件中指定的 quant_result_path。攻击向量：用户可提供恶意 record 文件，其中 quant_result_path 指向恶意 .pth 文件，导致 RCE。调用链完整：用户提供 record 文件 -> get_layer_quant_params -> torch.load。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 10 | cross_file: 0

---

### [VULN-DF-DS-001] deserialization - load_pth_file

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `amct_pytorch/graph_based_compression/amct_pytorch/utils/model_util.py:129-164` @ `load_pth_file`
**模块**: graph_based_compression

**描述**: Unsafe deserialization via torch.load with weights_only=False. The function explicitly disables safe loading mode, allowing arbitrary pickle deserialization. User-provided pth_file path in restore_quant_retrain_model API could load malicious checkpoint files leading to RCE.

**漏洞代码** (`amct_pytorch/graph_based_compression/amct_pytorch/utils/model_util.py:129-164`)

```c
load_kwargs = {'map_location': torch.device('cpu')}
if version_higher_than(torch.__version__, '2.1.0'):
    load_kwargs['weights_only'] = False
checkpoint = torch.load(pth_file, **load_kwargs)
```

**达成路径**

quantize_tool.py:436 restore_quant_retrain_model() [SOURCE: user-provided pth_file] -> model_util.py:142 torch.load(pth_file) [SINK: pickle deserialization]

**验证说明**: 与 VULN-SEC-001 相同漏洞点：load_pth_file 中的 torch.load(weights_only=False)。这是明确的 RCE 漏洞，恶意模型文件可导致任意代码执行。建议合并为单一漏洞报告。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 10 | cross_file: 0

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| graph_based_compression | 3 | 0 | 0 | 0 | 3 |
| **合计** | **3** | **0** | **0** | **0** | **3** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-502 | 3 | 100.0% |

---

## 6. Remediation Recommendations

### 6.1 紧急修复方案

#### 方案 A: 强制启用 `weights_only=True`

修改以下文件中的 `torch.load()` 调用：

**文件 1**: `amct_pytorch/graph_based_compression/amct_pytorch/utils/model_util.py`

```python
# 原代码 (第 139-143 行)
def load_pth_file(model, pth_file, state_dict_name):
    load_kwargs = {'map_location': torch.device('cpu')}
    if version_higher_than(torch.__version__, '2.1.0'):
        load_kwargs['weights_only'] = False  # ❌ 危险
    checkpoint = torch.load(pth_file, **load_kwargs)

# 修复代码
def load_pth_file(model, pth_file, state_dict_name):
    load_kwargs = {
        'map_location': torch.device('cpu'),
        'weights_only': True  # ✅ 安全
    }
    checkpoint = torch.load(pth_file, **load_kwargs)
```

**文件 2**: `amct_pytorch/graph_based_compression/amct_pytorch/parser/module_based_record_parser.py`

```python
# 原代码 (第 38-43 行)
if version_higher_than(torch.__version__, '2.1.0'):
    load_kwargs = {'mmap': True, 'weights_only': False}  # ❌ 危险
else:
    load_kwargs = {}
quant_params = torch.load(quant_result_path, **load_kwargs)

# 修复代码
load_kwargs = {'mmap': True, 'weights_only': True}  # ✅ 安全
quant_params = torch.load(quant_result_path, **load_kwargs)
```

#### 方案 B: 使用 safetensors 格式

```python
from safetensors.torch import load_file, save_file

# 加载模型 (无 pickle 反序列化风险)
checkpoint = load_file(pth_file)

# 保存模型
save_file(checkpoint, output_path)
```

### 6.2 长期安全改进

| 改进项 | 优先级 | 描述 |
|--------|--------|------|
| 模型文件签名校验 | High | 使用 HMAC 或数字签名验证模型文件完整性 |
| 路径白名单 | Medium | 限制可加载文件的目录范围 |
| 安全文档 | Medium | 在 README 和 API 文档中添加安全警告 |
| 输入验证 | Medium | 验证文件扩展名和路径格式 |
| 安全审计 | Low | 定期进行安全代码审计 |

### 6.3 依赖安全

- PyTorch 2.1.0+ 提供 `weights_only` 参数
- 建议使用最新稳定版本
- 关注 PyTorch 安全公告

### 6.4 安全最佳实践

```markdown
## 安全警告 ⚠️

**不要加载不信任来源的模型文件！**

恶意 .pth 文件可能包含 pickle payload，导致：
- 远程代码执行 (RCE)
- 数据泄露
- 系统控制

建议：
- 仅加载来源可信的模型文件
- 使用 safetensors 格式存储模型
- 对模型文件进行签名校验
```

---

## 7. References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [PyTorch Serialization Security](https://pytorch.org/docs/stable/notes/serialization.html)
- [Safetensors Format](https://github.com/huggingface/safetensors)
- [MITRE ATT&CK: T1059.006 - Python](https://attack.mitre.org/techniques/T1059/006/)
- [NIST SP 800-53: SI-10 Information Input Validation](https://csrc.nist.gov/projects/risk-management/sp800-53-controls)
