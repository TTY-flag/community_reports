# 漏洞扫描报告 — 待确认漏洞

**项目**: mindspore-lite
**扫描时间**: 2026-04-24T03:09:09.860Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 5 | 83.3% |
| POSSIBLE | 1 | 16.7% |
| **总计** | **6** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 1 | 16.7% |
| High | 2 | 33.3% |
| **有效漏洞总计** | **6** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[vuln-hw-002]** Buffer Overflow (Critical) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/providers/triton/backend/src/mslite_model_state.cc:214` @ `ModelInstanceState::ProcessInputs` | 置信度: 85
2. **[VULN-SEC-MP-001]** path_traversal (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/converter/parser/onnx/onnx_node_parser.cc:64` @ `ExternalDataInfo::Create / LoadOnnxRawData` | 置信度: 85
3. **[vuln-hw-004]** Memory Safety (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/providers/nnie/src/nnie_manager.h:53` @ `NNIEManager::Init` | 置信度: 75
4. **[VULN-ONNX-001]** Buffer Overflow (critical) - `mindspore-lite/tools/converter/parser/onnx/onnx_node_parser.cc:416` @ `OnnxNodeParser::LoadOnnxRawData` | 置信度: 85
5. **[VULN-ONNX-003]** Buffer Overflow (critical) - `mindspore-lite/tools/converter/parser/onnx/onnx_node_parser.cc:293` @ `OnnxNodeParser::LoadOnnxExternalTensorData` | 置信度: 85
6. **[VULN-COMMON-001]** Buffer Overflow (high) - `mindspore-lite/tools/common/tensor_util.cc:66` @ `CreateTensorInfo` | 置信度: 80

---

## 2. 攻击面分析

未找到入口点数据。


---

## 3. Critical 漏洞 (1)

### [vuln-hw-002] Buffer Overflow - ModelInstanceState::ProcessInputs

**严重性**: Critical | **CWE**: CWE-120 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/providers/triton/backend/src/mslite_model_state.cc:214-218` @ `ModelInstanceState::ProcessInputs`
**模块**: hardware_providers
**跨模块**: hardware_providers,runtime_engine

**描述**: memcpy from untrusted network input_buffer to input_data with size input_buffer_byte_size. The input_buffer comes from ProcessTensor (network request) and input_buffer_byte_size is provided by Triton backend. There IS a size check at line 214 (input_buffer_byte_size > data_size returns error), but the check uses RETURN_ERROR_IF_TRUE which only returns error - it does NOT prevent the memcpy from executing if input_buffer_byte_size <= data_size. The memcpy at line 218 copies input_buffer_byte_size bytes from network-controlled buffer to model input tensor.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/providers/triton/backend/src/mslite_model_state.cc:214-218`)

```c
RETURN_ERROR_IF_TRUE(input_data == nullptr || input_buffer_byte_size > data_size, TRITONSERVER_ERROR_INTERNAL, ...); std::memset(input_data, 0, input_tensor.DataSize()); std::memcpy(input_data, input_buffer, input_buffer_byte_size);
```

**达成路径**

TRITONBACKEND_RequestInputByIndex -> collector.ProcessTensor(input_name, nullptr, 0, allowed_input_types, &input_buffer, &input_buffer_byte_size, ...) -> std::memcpy(input_data, input_buffer, input_buffer_byte_size)

---

## 4. High 漏洞 (2)

### [VULN-SEC-MP-001] path_traversal - ExternalDataInfo::Create / LoadOnnxRawData

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/converter/parser/onnx/onnx_node_parser.cc:64-441` @ `ExternalDataInfo::Create / LoadOnnxRawData`
**模块**: model_parser
**跨模块**: model_parser,micro_coder

**描述**: ONNX external data loading uses unsanitized path from model file. The relative_path_ field from external_data is directly concatenated with external_tensor_dir without path traversal validation. An attacker could craft a malicious ONNX model with location field containing ../../../etc/passwd to read arbitrary files.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/converter/parser/onnx/onnx_node_parser.cc:64-441`)

```c
external_data_info->relative_path_ = string_map.value(); ... std::string external_data_file = external_tensor_dir + "/" + data_path; external_data = reinterpret_cast<uint8_t *>(ReadFile(external_data_file.c_str(), &external_data_size));
```

**达成路径**

ONNX model file -> external_data field -> relative_path_ -> string concatenation -> ReadFile()

---

### [vuln-hw-004] Memory Safety - NNIEManager::Init

**严重性**: High | **CWE**: CWE-119 | **置信度**: 75/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/providers/nnie/src/nnie_manager.h:53` @ `NNIEManager::Init`
**模块**: hardware_providers
**跨模块**: hardware_providers,runtime_engine

**描述**: NNIEManager::Init accepts model_buf (char pointer) and size from external caller. The model_buf could come from untrusted model file loaded from disk. The size parameter is not validated against actual buffer size before use. If size is incorrect (larger than actual buffer), operations within Init could read beyond buffer bounds. Need to check implementation file for specific dangerous operations.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/providers/nnie/src/nnie_manager.h:53`)

```c
int Init(char *model_buf, int size, const std::vector<mindspore::MSTensor> &inputs);
```

**达成路径**

Model loading -> NNIEManager::GetInstance(model_buf) -> NNIEManager::Init(model_buf, size, inputs)

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| hardware_providers | 1 | 1 | 0 | 0 | 2 |
| model_parser | 0 | 1 | 0 | 0 | 1 |
| **合计** | **1** | **2** | **0** | **0** | **3** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-787 | 3 | 50.0% |
| CWE-22 | 1 | 16.7% |
| CWE-120 | 1 | 16.7% |
| CWE-119 | 1 | 16.7% |
