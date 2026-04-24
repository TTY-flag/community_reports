# 漏洞扫描报告 — 待确认漏洞

**项目**: mindspore-lite
**扫描时间**: 2026-04-24T03:27:42.281Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 30 | 54.5% |
| POSSIBLE | 21 | 38.2% |
| CONFIRMED | 4 | 7.3% |
| **总计** | **55** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 1 | 2.0% |
| High | 12 | 23.5% |
| Medium | 20 | 39.2% |
| Low | 15 | 29.4% |
| **有效漏洞总计** | **51** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[vuln-hw-002]** Buffer Overflow (Critical) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/providers/triton/backend/src/mslite_model_state.cc:214` @ `ModelInstanceState::ProcessInputs` | 置信度: 85
2. **[VULN-SEC-MP-001]** path_traversal (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/converter/parser/onnx/onnx_node_parser.cc:64` @ `ExternalDataInfo::Create / LoadOnnxRawData` | 置信度: 85
3. **[vuln-hw-004]** Memory Safety (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/providers/nnie/src/nnie_manager.h:53` @ `NNIEManager::Init` | 置信度: 75
4. **[VULN-SEC-003]** command_injection (High) - `tools/cropper/cropper.cc:244` @ `Cropper::CutPackage` | 置信度: 75
5. **[VULN-003]** Memory Corruption (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/src/tensor.cc:579` @ `CreateTensorByDeepCopy` | 置信度: 70
6. **[VULN-CONVERT-DL-001]** Arbitrary Code Execution (High) - `mindspore-lite/tools/converter/converter.cc:1107` @ `ConverterImpl::LoadPluginLib` | 置信度: 70
7. **[VULN-SEC-001]** command_injection (High) - `tools/cropper/cropper.cc:38` @ `Cropper::ReadPackage` | 置信度: 70
8. **[VULN-SEC-002]** command_injection (High) - `tools/cropper/cropper.cc:152` @ `Cropper::GetModelFiles` | 置信度: 70
9. **[VULN-001]** Buffer Overflow (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/src/litert/lite_model.cc:458` @ `InitModelBuffer` | 置信度: 65
10. **[VULN-002]** Buffer Overflow (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/src/extendrt/mindir_loader/model_loader.cc:40` @ `InitModelBuffer` | 置信度: 65

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

## 4. High 漏洞 (12)

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

### [VULN-SEC-003] command_injection - Cropper::CutPackage

**严重性**: High | **CWE**: CWE-78 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `tools/cropper/cropper.cc:244-282` @ `Cropper::CutPackage`
**模块**: converter_core

**描述**: 命令注入风险：多处 system() 调用，参数来自用户输入的文件路径。package_file_ 和 output_file_ 可能包含 shell 特殊字符导致命令注入。

**漏洞代码** (`tools/cropper/cropper.cc:244-282`)

```c
std::string copy_bak_cmd = "cp " + this->flags_->package_file_ + " " + this->flags_->package_file_ + ".bak";
status = system(copy_bak_cmd.c_str());
```

**验证说明**: system() calls with package_file_ and output_file_ concatenated. Multiple injection points. cp, ar, mv commands. Pre-validated. Limited mitigation - direct path concatenation.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: -5 | reachability: 30

---

### [VULN-003] Memory Corruption - CreateTensorByDeepCopy

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-122 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/src/tensor.cc:579-586` @ `CreateTensorByDeepCopy`
**模块**: runtime_engine

**描述**: Tensor creation with deep copy uses user-provided data_len for malloc and memcpy. If data_len exceeds actual buffer size, overflow occurs. Validation only checks data_len > MAX_MALLOC_SIZE.

**达成路径**

MSTensorCreate(name, shape, data, data_len) -> Tensor::CreateTensorByDeepCopy -> malloc(data_len) -> memcpy(new_data, data, data_len)

**验证说明**: CreateTensorByDeepCopy uses malloc(data_len) and memcpy(new_data, data, data_len). User controls data_len via MSTensorCreate. Shape validation at line 601 truncates shape if mismatched, allowing partial bypass. Attacker can provide large data_len with small actual data buffer, causing heap overflow. Mitigation is lenient - doesn't reject mismatched sizes.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 5

---

### [VULN-CONVERT-DL-001] Arbitrary Code Execution - ConverterImpl::LoadPluginLib

**严重性**: High（原评估: high → 验证后: High） | **CWE**: CWE-94 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/converter.cc:1107-1120` @ `ConverterImpl::LoadPluginLib`
**模块**: converter_core

**描述**: ConverterImpl::LoadPluginLib loads dynamic libraries specified via plugin_path config parameter. The path is processed through lite::RealPath() but then directly loaded via DynamicLibraryLoader::Open() which uses dlopen(). A malicious config file could specify plugin_path pointing to a crafted shared library that executes arbitrary code when loaded. The limit on plugin paths (kPluginPathMaxNum=10) is checked but not sufficient security.

**漏洞代码** (`mindspore-lite/tools/converter/converter.cc:1107-1120`)

```c
for (auto &path : param->plugins_path) {\n  auto status = dl_loader->Open(path);
```

**达成路径**

config_file [registry] -> plugin_path -> lite::SplitStringToVector() -> lite::RealPath() -> plugins_path -> DynamicLibraryLoader::Open() -> dlopen()

**验证说明**: LoadPluginLib calls dl_loader->Open(path) directly on plugins_path from config. dlopen() loads arbitrary library. RealPath may validate but library content unchecked. Attacker with config write access can execute arbitrary code.

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: -10 | reachability: 30

---

### [VULN-SEC-001] command_injection - Cropper::ReadPackage

**严重性**: High | **CWE**: CWE-78 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `tools/cropper/cropper.cc:38-50` @ `Cropper::ReadPackage`
**模块**: converter_core

**描述**: 命令注入风险：使用 popen() 执行用户输入的路径。real_path 来自 flags_->package_file_，用户可通过传入包含 shell 特殊字符的路径（如 '; rm -rf /'）执行任意命令。

**漏洞代码** (`tools/cropper/cropper.cc:38-50`)

```c
std::string cmd = "ar -t " + real_path;
FILE *p_file = popen(cmd.c_str(), "r");
```

**验证说明**: popen('ar -t ' + real_path) with real_path from flags_->package_file_. Shell special chars (; rm -rf /) could inject commands. Pre-validated. Mitigation: RealPath validates path existence, reduces direct injection.

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: -10 | reachability: 30

---

### [VULN-SEC-002] command_injection - Cropper::GetModelFiles

**严重性**: High | **CWE**: CWE-78 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `tools/cropper/cropper.cc:152-170` @ `Cropper::GetModelFiles`
**模块**: converter_core

**描述**: 命令注入风险：使用 popen() 执行用户输入的目录路径。model_folder_path_ 来自用户输入，可通过目录名注入 shell 命令。

**漏洞代码** (`tools/cropper/cropper.cc:152-170`)

```c
std::string cmd = "find " + this->flags_->model_folder_path_ + " -name '*.ms'";
FILE *p_file = popen(cmd.c_str(), "r");
```

**验证说明**: popen('find ' + model_folder_path_ + ' -name *.ms') with user-supplied directory path. Directory name could contain shell chars. Pre-validated. Mitigation: Limited to find command context.

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: -10 | reachability: 30

---

### [VULN-001] Buffer Overflow - InitModelBuffer

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-125 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/src/litert/lite_model.cc:458` @ `InitModelBuffer`
**模块**: runtime_engine

**描述**: Untrusted model buffer copied directly to internal buffer via memcpy without size validation. User-controlled model_buf and size parameters flow to memcpy without verifying the actual buffer contents.

**达成路径**

MSModelBuild(model_data, data_size) -> Model::Build -> LoadModelAndCompileByBuf -> ImportFromBuffer -> ConstructModel -> InitModelBuffer -> memcpy(model->buf, model_buf, size)

**验证说明**: memcpy(model->buf, model_buf, size) copies user-supplied buffer. Size validation exists (kMaxModelBufferSize check at line 450, max 2GB). However, the library doesn't verify that model_buf actually contains size bytes - if caller provides mismatched pointer/size, heap overflow occurs. Mitigation exists but is incomplete - only validates size upper bound, not buffer content.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 5

---

### [VULN-002] Buffer Overflow - InitModelBuffer

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-125 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/src/extendrt/mindir_loader/model_loader.cc:40` @ `InitModelBuffer`
**模块**: runtime_engine

**描述**: Model loader copies untrusted model buffer via memcpy. Same vulnerability pattern as lite_model.cc, in extendrt model loader.

**达成路径**

MSModelBuild(model_data, data_size) -> Model::Build -> LoadModelAndCompileByBuf -> ImportFromBuffer -> ModelLoader::InitModelBuffer -> memcpy(model->buf, model_buf, size)

**验证说明**: Same vulnerability pattern as VULN-001. model_loader.cc InitModelBuffer has size validation (kMaxModelBufferSize at line 31) but doesn't verify buffer content matches size. memcpy at line 40. Partial mitigation reduces severity to High.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 5

---

### [VULN-CONVERT-CMD-001] Command Injection - AclCustomOppInstaller::InstallCustomOpp

**严重性**: High（原评估: critical → 验证后: High） | **CWE**: CWE-78 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/adapter/acl/src/acl_custom_opp_installer.cc:44-62` @ `AclCustomOppInstaller::InstallCustomOpp`
**模块**: converter_core
**跨模块**: converter_core,hardware_providers

**描述**: AclCustomOppInstaller::InstallCustomOpp executes bash script via popen() with path from config file parameter custom_opp_path. Although lite::RealPath() is used to resolve the path, the script content itself is not validated. A malicious config file could specify a custom_opp_path pointing to a crafted install.sh script containing arbitrary commands. The command bash {resolved_path} is directly executed via popen().

**漏洞代码** (`mindspore-lite/tools/converter/adapter/acl/src/acl_custom_opp_installer.cc:44-62`)

```c
std::string cmd = "bash " + install_path_real_path;\nif ((fp = popen(cmd.c_str(), "r")) == NULL) {
```

**达成路径**

config_file [acl_option_cfg_param] -> custom_opp_path -> install_path = custom_opp_path + /install.sh -> lite::RealPath() -> popen("bash " + path)

**验证说明**: Command injection via popen("bash " + install_path_real_path). custom_opp_path from config file (semi_trusted). RealPath validates path existence but NOT script content. Attacker who can modify config can point to malicious install.sh for arbitrary code execution. Requires config file write access - reduces severity to High.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-004] command_injection - AclCustomOppInstaller::InstallCustomOpp

**严重性**: High | **CWE**: CWE-78 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `tools/converter/adapter/acl/src/acl_custom_opp_installer.cc:46-62` @ `AclCustomOppInstaller::InstallCustomOpp`
**模块**: converter_core

**描述**: 命令注入风险：使用 popen() 执行 bash 脚本。虽然使用了 RealPath 验证路径，但 install_path_real_path 可能指向恶意脚本文件。

**漏洞代码** (`tools/converter/adapter/acl/src/acl_custom_opp_installer.cc:46-62`)

```c
std::string cmd = "bash " + install_path_real_path;
if ((fp = popen(cmd.c_str(), "r")) == NULL) {
```

**验证说明**: Duplicate of VULN-CONVERT-CMD-001. popen('bash ' + install_path_real_path). Same vulnerability pattern. RealPath validates but script content unchecked.

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: -10 | reachability: 30

---

### [VULN-TFLITE-001] Memory Corruption - TfliteModelParser::ReadTfliteModel

**严重性**: High（原评估: critical → 验证后: High） | **CWE**: CWE-787 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/parser/tflite/tflite_model_parser.cc:56-69` @ `TfliteModelParser::ReadTfliteModel`
**模块**: model_parser

**描述**: ReadTfliteModel in tflite_model_parser.cc reads the entire model file into memory and uses flatbuffers::Verifier to validate the buffer. However, flatbuffers verification may not catch all malformed inputs, and subsequent UnPackModel operation could still trigger memory corruption if the buffer contains carefully crafted malicious data.

**达成路径**

ReadFile(model_path) -> tflite_model_buf_ -> flatbuffers::Verifier verify -> tflite::VerifyModelBuffer(verify) -> tflite::UnPackModel(tflite_model_buf_)

**验证说明**: flatbuffers::Verifier and VerifyModelBuffer provide validation (lines 63-64) before UnPackModel. Theoretical vulnerability - verification may miss crafted malicious inputs. Strong mitigation reduces confidence. Requires proof of specific bypass to upgrade to CONFIRMED.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: -20 | context: 0 | cross_file: 0

---

## 5. Medium 漏洞 (20)

### [vuln-hw-006] Stack Buffer Overflow - GetCustomShape

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-121 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/providers/nnie/src/custom_infer.cc:43-57` @ `GetCustomShape`
**模块**: hardware_providers

**描述**: GetCustomShape uses fixed-size stack buffer buf[kMaxSize] to copy attribute data from model. Although line 50 checks attr_size >= kMaxSize, the check returns error for oversized attributes. However, if kMaxSize is defined too large, this could still cause stack overflow. The buffer is then parsed with strtok_r which modifies it in-place.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/providers/nnie/src/custom_infer.cc:43-57`)

```c
char buf[kMaxSize]; ... for (int j = 0; j < attr_size; j++) { buf[j] = static_cast<char>(output_info->Get(j)); } buf[attr_size] = 0;
```

**达成路径**

Custom op attribute parsing -> GetCustomShape(op, attr, &shapes) -> output_info = op->attr()->Get(i)->data() -> buf[attr_size] = 0

**验证说明**: GetCustomShape uses stack buffer buf[kMaxSize]. attr_size check at line 50 prevents oversized attributes. But if kMaxSize too large, stack overflow. strtok_r modifies buffer. Pre-validated with size check.

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: -10 | reachability: 30

---

### [micro_coder_pt_005] Path Traversal - Coder::InitPath

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/micro/coder/coder.cc:115-146` @ `Coder::InitPath`
**模块**: micro_coder

**描述**: model_name extracted from output_path without path traversal character filtering. While RealPath validates save_path, the model_name component (used in directory/file creation) is not sanitized. Path like /valid/path/../malicious.ms would extract ../malicious as model_name.

**漏洞代码** (`mindspore-lite/tools/converter/micro/coder/coder.cc:115-146`)

```c
this->model_name_ = output_path.substr(pos + 1);
```

**达成路径**

output_path[API] -> find_last_of[/\\] -> substr[model_name] -> model_name_[member] -> CreateStaticDir/CreateDynamicDir[path_construct]

**验证说明**: model_name extracted via substr from output_path. RealPath validates save_path but model_name component not sanitized. Path like /valid/../malicious.ms extracts ../malicious. Partial mitigation via RealPath on parent path.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -10 | reachability: 30

---

### [VULN-005] Buffer Overflow - CreateTensor

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-125 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/src/litert/cxx_api/types.cc:179-185` @ `CreateTensor`
**模块**: runtime_engine

**描述**: MSTensor::CreateTensor copies user data via memcpy without validating that data buffer actually contains data_len bytes. Only MAX_MALLOC_SIZE check exists.

**达成路径**

MSTensor::CreateTensor -> malloc(data_len) -> memcpy(new_data, data, data_len)

**验证说明**: Same pattern as VULN-003. CreateTensor uses malloc/memcpy with user data_len. MAX_MALLOC_SIZE check exists. Shape mismatch allowed (truncates). Partial mitigation reduces severity.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -15 | reachability: 30

---

### [micro_coder_pt_006] Path Traversal - DirectoryGenerator::CreateStaticDir

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/micro/coder/utils/dir_utils.cc:84-130` @ `DirectoryGenerator::CreateStaticDir`
**模块**: micro_coder

**描述**: Directory creation uses project_name directly in path concatenation without validation. While work_dir is validated via RealPath, project_name (derived from model_name) could contain path traversal characters. Used in mkdir() calls.

**漏洞代码** (`mindspore-lite/tools/converter/micro/coder/utils/dir_utils.cc:84-130`)

```c
std::string project_dir = work_dir_ + project_name_;
```

**达成路径**

project_name[model_name_derived] -> project_dir[path_concat] -> MkMicroDir[mkdir]

**验证说明**: project_dir = work_dir_ + project_name_ concatenation. work_dir validated via RealPath but project_name not sanitized. mkdir() could create directories outside intended location. Partial mitigation.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -10 | reachability: 30

---

### [VULN-TFLITE-002] Buffer Overflow - TfliteModelParser::ConvertConstTensor

**严重性**: Medium（原评估: high → 验证后: Medium） | **CWE**: CWE-787 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/parser/tflite/tflite_model_parser.cc:704-775` @ `TfliteModelParser::ConvertConstTensor`
**模块**: model_parser

**描述**: ConvertConstTensor in tflite_model_parser.cc copies tensor data from model buffers using memcpy_s. The size check at line 750 (MS_CHECK_TRUE_MSG(tensor_info->Size() == data.size()) only logs an error but returns RET_ERROR, which may not properly halt processing in all code paths. String tensor handling at lines 741-746 performs memcpy without verifying that shape_str.size() + data.size() fits in the allocated buffer.

**达成路径**

tflite_model_buffers.at(tensor->buffer)->data -> tensor_info->data_c() -> memcpy_s(tensor_data, tensor_info->Size(), data.data(), data.size())

**验证说明**: ConvertConstTensor memcpy_s with size check (tensor_info->Size() == data.size()). Returns RET_ERROR on mismatch. String tensor handling at 741-746 may have buffer issues. Partial mitigation.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [VULN-TF-001] Buffer Overflow - SetFloatTensorInfo/SetInt32TensorInfo

**严重性**: Medium（原评估: high → 验证后: Medium） | **CWE**: CWE-787 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/parser/tf/tf_model_parser.cc:126-247` @ `SetFloatTensorInfo/SetInt32TensorInfo`
**模块**: model_parser

**描述**: SetFloatTensorInfo/SetInt32TensorInfo in tf_model_parser.cc copies tensor content from TensorFlow protobuf using memcpy_s. The size is calculated as shape_size * sizeof(type) but the tensor_content.size() validation only checks equality, not if it exceeds the destination buffer. Additionally, INT_MUL_OVERFLOW_THRESHOLD checks exist but error handling may not prevent subsequent operations.

**达成路径**

tensor_proto.tensor_content() -> shape_size * sizeof(float) -> memcpy_s(tensor_data, (*tensor_info)->Size(), addr, shape_size * sizeof(float))

**验证说明**: SetFloatTensorInfo/SetInt32TensorInfo memcpy_s with shape_size validation. tensor_content.size() equality check. INT_MUL_OVERFLOW_THRESHOLD exists. Partial mitigation.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [VULN-CAFFE-001] Buffer Overflow - CaffeModelParser::ConvertBlobs

**严重性**: Medium（原评估: high → 验证后: Medium） | **CWE**: CWE-787 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/parser/caffe/caffe_model_parser.cc:530-613` @ `CaffeModelParser::ConvertBlobs`
**模块**: model_parser

**描述**: ConvertBlobs in caffe_model_parser.cc processes blob data from Caffe model files. The count is obtained from layer.blobs(i).data_size() or other size fields directly from the model file without validation. CreateTensorInfo is called with data_size = count * sizeof(float) without overflow checking. A malicious model with extremely large data_size values could trigger integer overflow.

**达成路径**

layer.blobs(i).data_size() -> count -> CreateTensorInfo(data_ptr, count * sizeof(float), shape_vector) -> memcpy_s

**验证说明**: ConvertBlobs CreateTensorInfo with count * sizeof(float). data_size from layer.blobs(i).data_size(). Integer overflow risk. Partial mitigation: protobuf parsing validation.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [VULN-004] Buffer Overflow - Predict

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-125 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/src/litert/cxx_api/model/model_impl.cc:644` @ `Predict`
**模块**: runtime_engine

**描述**: Predict function uses memcpy with input->Size() which is derived from user-provided tensor shapes. Potential overflow if Size() calculation overflows or mismatches actual buffer.

**达成路径**

MSModelPredict(inputs) -> ModelImpl::Predict -> memcpy(dst_data, src_data, input->Size())

**验证说明**: Predict memcpy with input->Size(). Size derived from tensor shapes (user-controlled via MSTensorCreate). Overflow risk if Size() calculation overflows or mismatches. Mitigation: shape validation in tensor creation reduces risk.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [vuln-hw-001] Buffer Overflow - ModelInstanceState::ProcessInputs

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/providers/triton/backend/src/mslite_model_state.cc:182-183` @ `ModelInstanceState::ProcessInputs`
**模块**: hardware_providers

**描述**: memcpy from untrusted network input_shape to batched_shape without sufficient validation. The input_dims_count comes from TRITONBACKEND_InputProperties which provides network-controlled dimension count. If input_dims_count is excessively large, memcpy could overflow batched_shape.data() which is a vector with size input_dims_count (line 182). However, line 182 creates vector with input_dims_count size, making overflow unlikely unless integer overflow occurs.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/providers/triton/backend/src/mslite_model_state.cc:182-183`)

```c
std::vector<int64_t> batched_shape(input_dims_count); std::memcpy(batched_shape.data(), input_shape, input_dims_count * sizeof(int64_t));
```

**达成路径**

TRITONBACKEND_RequestInputByIndex -> TRITONBACKEND_InputProperties(input, &input_name, &input_datatype, &input_shape, &input_dims_count) -> std::memcpy(batched_shape.data(), input_shape, input_dims_count * sizeof(int64_t))

**验证说明**: memcpy(batched_shape.data(), input_shape, input_dims_count*sizeof(int64_t)). Vector allocation protects against direct overflow. input_dims_count from untrusted_network. Batch size validation exists (line 175-177). Mitigation: vector handles allocation, partial validation.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [VULN-ONNX-002] Integer Overflow - OnnxNodeParser::GetOnnxElementNum

**严重性**: Medium（原评估: high → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/parser/onnx/onnx_node_parser.cc:268-291` @ `OnnxNodeParser::GetOnnxElementNum`
**模块**: model_parser

**描述**: GetOnnxElementNum in onnx_node_parser.cc calculates data_count by multiplying tensor dimensions from the model file. While overflow checking exists (INT_MUL_OVERFLOW_THRESHOLD), the function returns 0 on overflow which may lead to incorrect tensor creation with zero-size data. The overflow handling may not prevent subsequent operations from proceeding incorrectly.

**达成路径**

onnx_tensor.dims() -> data_count *= dim -> INT_MUL_OVERFLOW_THRESHOLD check -> returns 0 on overflow

**验证说明**: GetOnnxElementNum data_count *= dim from ONNX tensor dims. INT_MUL_OVERFLOW_THRESHOLD check exists, returns 0 on overflow. Error handling may not halt subsequent operations. Strong mitigation.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [VULN-PYTORCH-001] Integer Overflow / Memory Corruption - PytorchModelParser::ConvertTorchTensor

**严重性**: Medium（原评估: high → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/parser/pytorch/pytorch_model_parser.cc:524-545` @ `PytorchModelParser::ConvertTorchTensor`
**模块**: model_parser

**描述**: ConvertTorchTensor in pytorch_model_parser.cc calculates data_size as torch_tensor.numel() * abstract::TypeIdSize(data_type) and passes it to malloc. While numel() and TypeIdSize are relatively safe, a malicious PyTorch model could potentially trigger integer overflow through carefully crafted tensor dimensions. No overflow check is performed before malloc.

**达成路径**

torch_tensor.numel() -> data_size = numel() * TypeIdSize(data_type) -> malloc(data_size) -> CopyDataFromTorchTensor -> CreateTensorInfo

**验证说明**: ConvertTorchTensor data_size = numel() * TypeIdSize(). malloc(data_size) without overflow check. PyTorch model dimensions could overflow. Internal calculation mitigations.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [VULN-006] Integer Overflow - ElementsNum

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/src/tensor.cc:280-298` @ `ElementsNum`
**模块**: runtime_engine

**描述**: ElementsNum() multiplies shape dimensions without overflow checks in high-performance mode (ENABLE_HIGH_PERFORMANCE). Overflow can lead to undersized allocations.

**达成路径**

tensor shape dimensions -> ElementsNum() -> Size() -> malloc()

**验证说明**: ElementsNum() multiplies shape dimensions. In ENABLE_HIGH_PERFORMANCE mode, overflow checks may be disabled. Could lead to undersized allocations. Mitigation: overflow checks exist in normal mode.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [VULN-CONVERT-CMD-002] Command Injection - ExecuteAoe

**严重性**: Medium（原评估: high → 验证后: Medium） | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/adapter/acl/cxx_api_lite/cxx_api/model/aoe/auto_tune_process.cc:95-121` @ `ExecuteAoe`
**模块**: converter_core
**跨模块**: converter_core,hardware_providers

**描述**: ExecuteAoe in auto_tune_process.cc constructs shell command from multiple config parameters and executes via popen(). The command includes aoe_options, dynamic_option, and input_shape which are parsed from config files without proper sanitization. These values are concatenated directly into the command string: aoe + --model= + real_path + --job_type= + mode + dynamic_option + input_shape + aoe_options. Special characters in these parameters could enable command injection.

**漏洞代码** (`mindspore-lite/tools/converter/adapter/acl/cxx_api_lite/cxx_api/model/aoe/auto_tune_process.cc:95-121`)

```c
std::string cmd = aoe_path + " --framework=1" + " --model=" + real_path + " --job_type=" + mode + dynamic_option + input_shape + aoe_options;\nauto fp = popen(cmd.c_str(), "r");
```

**达成路径**

build_options [ge::ir_option::DYNAMIC_BATCH_SIZE/DYNAMIC_IMAGE_SIZE/DYNAMIC_DIMS] -> dynamic_option -> aoe_options -> popen(cmd)

**验证说明**: ExecuteAoe popen(cmd) with concatenated params from config. aoe_options, dynamic_option, input_shape from config files. Special chars could enable injection. Multiple mitigations: aoe_path hardcoded, partial parameter validation.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [QUANT-001] Integer Overflow - QuantMax

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/common/quant_utils.h:50-56` @ `QuantMax`
**模块**: quantizer

**描述**: Bit shift operation in QuantMax() can overflow for large bit values. The expression (1 << (bits - 1)) - 1 uses signed integer arithmetic which can overflow when bits >= 32, causing undefined behavior.

**漏洞代码** (`src/common/quant_utils.h:50-56`)

```c
return (1 << static_cast<unsigned int>(bits - 1)) - 1;
```

**达成路径**

QuantMax(bits) -> quant_max -> CalQuantizationParams -> QuantizeData

**验证说明**: QuantMax bit shift (1 << (bits - 1)) - 1. Overflow when bits >= 32 with signed int. Undefined behavior. Internal module, bits from quantization config.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -15 | reachability: 5

---

### [QUANT-002] Integer Overflow - QuantMin

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/common/quant_utils.h:58-64` @ `QuantMin`
**模块**: quantizer

**描述**: Bit shift operation in QuantMin() can overflow. Similar to QuantMax, the expression -(1 << (bits - 1)) uses signed integer arithmetic which can overflow when bits >= 32.

**漏洞代码** (`src/common/quant_utils.h:58-64`)

```c
return -(1 << static_cast<unsigned int>(bits - 1)) + (is_narrow ? 1 : 0);
```

**达成路径**

QuantMin(bits) -> quant_min -> CalQuantizationParams -> QuantizeData

**验证说明**: QuantMin bit shift -(1 << (bits - 1)). Same overflow risk as QUANT-001. bits >= 32 causes undefined behavior.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -15 | reachability: 5

---

### [QUANT-004] Integer Overflow - QuantizeData

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/common/quant_utils.h:77-93` @ `QuantizeData`
**模块**: quantizer

**描述**: QuantizeData() function performs float to integer conversion without bounds checking. The expression std::round(origin_data / scale + zero_point) is cast to type T without verifying the result fits within the target type range.

**漏洞代码** (`src/common/quant_utils.h:77-93`)

```c
auto quant_data = std::round(origin_data / scale + zero_point); return static_cast<T>(quant_data);
```

**达成路径**

raw_datas[i] -> QuantizeData -> quant_datas[i]

**验证说明**: QuantizeData static_cast<T> without bounds check. std::round result cast to type T. Could overflow if result exceeds T range. Internal module, data from model weights. Partial mitigation in upstream validation.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -15 | reachability: 5

---

### [QUANT-005] Integer Overflow - ComputeBiasDataAndQuantParam

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `tools/converter/quantizer/fixed_bit_weight_quantization.cc:159-160` @ `ComputeBiasDataAndQuantParam`
**模块**: quantizer

**描述**: Bias quantization in ComputeBiasDataAndQuantParam() casts float division result to int32_t without bounds checking. Large bias values combined with small scales can produce results exceeding INT32_MAX.

**漏洞代码** (`tools/converter/quantizer/fixed_bit_weight_quantization.cc:159-160`)

```c
auto quant_data = static_cast<int32_t>(std::round(raw_datas[i] / bias_scale_tmp));
```

**达成路径**

raw_datas -> bias_scale_tmp -> quant_data -> quant_datas

**验证说明**: ComputeBiasDataAndQuantParam static_cast<int32_t> for bias quantization. Large bias/small scale could exceed INT32_MAX. Internal module. Partial mitigation.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -15 | reachability: 5

---

### [QUANT-009] Integer Overflow - GetElementNumFromShape

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `tools/converter/quantizer/quantize_util.cc:645-653` @ `GetElementNumFromShape`
**模块**: quantizer

**描述**: GetElementNumFromShape() multiplies dimensions without overflow protection for very large tensors. While INT_MUL_OVERFLOW is checked, the function uses int type which may be insufficient for large models.

**漏洞代码** (`tools/converter/quantizer/quantize_util.cc:645-653`)

```c
MS_CHECK_FALSE_MSG(INT_MUL_OVERFLOW(*total_size, dim), RET_ERROR, "Int mul overflow."); *total_size *= dim;
```

**达成路径**

dims -> total_size -> elem_count -> quant_datas

**验证说明**: GetElementNumFromShape INT_MUL_OVERFLOW check exists. Uses int type which may overflow for large tensors. Overflow check provides mitigation.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -15 | reachability: 5

---

### [VULN-SEC-005] command_injection - ExecuteAoe

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `tools/converter/adapter/acl/cxx_api_lite/cxx_api/model/aoe/auto_tune_process.cc:103-113` @ `ExecuteAoe`
**模块**: converter_core

**描述**: 命令注入风险：使用 popen() 执行 aoe 命令。aoe_options、dynamic_option、input_shape 等参数来自用户配置，可能包含 shell 特殊字符导致命令注入。

**漏洞代码** (`tools/converter/adapter/acl/cxx_api_lite/cxx_api/model/aoe/auto_tune_process.cc:103-113`)

```c
std::string cmd = aoe_path + " --framework=1" + " --model=" + real_path + " --job_type=" + mode + dynamic_option + input_shape + aoe_options;
auto fp = popen(cmd.c_str(), "r");
```

**验证说明**: Duplicate of VULN-CONVERT-CMD-002. popen() with aoe_options, dynamic_option, input_shape from config. Multiple params reduce injection risk per param. Partial mitigations.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [QUANT-003] Division by Zero - CalQuantizationParams

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-369 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/common/quant_utils.cc:75-87` @ `CalQuantizationParams`
**模块**: quantizer

**描述**: Scale calculation in CalQuantizationParams() can result in division by zero if q_range equals zero. The expression double scale = (encode_max - encode_min) / q_range; does not check if q_range could be zero.

**漏洞代码** (`src/common/quant_utils.cc:75-87`)

```c
auto q_range = quant_max - quant_min; double scale = (encode_max - encode_min) / q_range;
```

**达成路径**

encode_min/encode_max -> scale -> CalQuantizationParams -> QuantizeData

**验证说明**: CalQuantizationParams division by q_range. q_range = quant_max - quant_min. If quant_max == quant_min, q_range = 0 -> division by zero. Internal module, no direct external input. Mitigation: quantization parameters validated upstream.

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 5

---

## 6. Low 漏洞 (15)

### [VULN-007] Path Traversal - ReadFileByMmap

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/src/common/mmap_utils.cc:27-49` @ `ReadFileByMmap`
**模块**: runtime_engine

**描述**: MSModelBuildFromFile accepts user-provided model_path. RealPath() sanitizes but mmap operation directly maps file contents. Symlink attacks possible.

**达成路径**

MSModelBuildFromFile(model_path) -> LoadModelAndCompileByPath -> LoadModelByPath -> ReadFileByMmap -> mmap()

**验证说明**: MSModelBuildFromFile uses RealPath to sanitize path. mmap() maps file contents. Symlink attacks possible if attacker controls symlinks. Strong mitigation (RealPath) reduces confidence.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [vuln-hw-003] Integer Overflow - ModelInstanceState::ProcessInputs

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/providers/triton/backend/src/mslite_model_state.cc:169-174` @ `ModelInstanceState::ProcessInputs`
**模块**: hardware_providers

**描述**: Network-controlled request_count could cause integer overflow when computing batched_size_. The loop at lines 170-174 accumulates *input_shape into batched_size_ for each request. If a malicious client sends many requests with large batch sizes, batched_size_ could overflow int64_t, causing unexpected behavior in subsequent shape calculations.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/providers/triton/backend/src/mslite_model_state.cc:169-174`)

```c
batched_size_ = 0; for (uint32_t r = 0; r < request_count; r++) { ... batched_size_ += *input_shape; }
```

**达成路径**

TRITONBACKEND_ModelInstanceExecute(requests, request_count) -> ProcessInputs -> batched_size_ += *input_shape (accumulated over request_count)

**验证说明**: batched_size_ accumulates *input_shape over request_count loop. request_count from network (untrusted_network). Integer overflow risk for int64_t. MaxBatchSize check provides partial mitigation.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [vuln-hw-005] Configuration Injection - AclModelManager::Init

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-15 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/providers/dpico/manager/acl_model_manager.h:41-44` @ `AclModelManager::Init`
**模块**: hardware_providers

**描述**: AclModelManager::Init accepts dpico_config and model_share_config as map of strings from external configuration. These configs are passed directly from model parsing without validation. Malicious configs could cause unexpected behavior in ACL operations. The primitive and input/output tensors also come from untrusted sources.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/providers/dpico/manager/acl_model_manager.h:41-44`)

```c
int Init(const std::map<std::string, std::string> &dpico_config, const std::map<std::string, std::string> &model_share_config, const schema::Primitive *primitive, const std::vector<mindspore::MSTensor> &input_tensors, const std::vector<mindspore::MSTensor> &output_tensors);
```

**达成路径**

Model parsing -> CustomCPUKernel::Prepare -> acl_model_manager_->Init(config_info, this->GetConfig(kModelSharingSection), primitive_, inputs_, outputs_)

**验证说明**: AclModelManager::Init accepts dpico_config map from model parsing. Config values passed to ACL operations without validation. Could cause unexpected behavior. Mitigation: config comes from semi-trusted sources.

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: -15 | reachability: 30

---

### [VULN-SEC-MP-002] improper_error_handling - ExternalDataInfo::Create

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-754 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/converter/parser/onnx/onnx_node_parser.cc:66-74` @ `ExternalDataInfo::Create`
**模块**: model_parser

**描述**: strtol is used to parse offset and length values from ONNX external_data without checking errno for overflow/underflow conditions. Only length validation is performed which may miss edge cases like LONG_MIN/LONG_MAX.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/converter/parser/onnx/onnx_node_parser.cc:66-74`)

```c
external_data_info->offset_ = strtol(string_map.value().c_str(), nullptr, kMaxValidCharacters); external_data_info->length_ = static_cast<size_t>(strtol(string_map.value().c_str(), nullptr, kMaxValidCharacters));
```

**达成路径**

ONNX external_data -> strtol -> offset_/length_

**验证说明**: strtol for offset/length from ONNX external_data without errno check. LONG_MIN/LONG_MAX edge cases missed. Pre-validated but incomplete. Mitigation: length validation exists.

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [VULN-PROTOBUF-001] Memory Exhaustion / Parsing Vulnerability - ReadProtoFromBinaryFile

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-400 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindspore-lite/tools/common/protobuf_utils.cc:75-104` @ `ReadProtoFromBinaryFile`
**模块**: model_parser

**描述**: ReadProtoFromBinaryFile in protobuf_utils.cc reads protobuf binary files using ParseFromCodedStream. While ReadProtoFromCodedInputStream sets TotalBytesLimit to INT_MAX, a malicious model file with extreme recursion or nested structures could still cause memory exhaustion during parsing. The function does not implement additional validation for the parsed protobuf structure.

**达成路径**

model_file path -> ReadFile -> google::protobuf::io::CodedInputStream -> message->ParseFromCodedStream

**验证说明**: ReadProtoFromBinaryFile ParseFromCodedStream with TotalBytesLimit INT_MAX. Malicious nested structures could cause memory exhaustion. Strong mitigation: protobuf has built-in protections.

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [VULN-008] Buffer Overflow - CopyTensor/CopyTensorData

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-125 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/src/tensor.cc:78-88` @ `CopyTensor/CopyTensorData`
**模块**: runtime_engine

**描述**: Session constructor memcpy with tensor Sizes that may overflow. Uses tensor_c_ struct copy.

**达成路径**

Tensor operations -> memcpy(dst_tensor->tensor_c_.data_, src_tensor.tensor_c_.data_, data_size)

**验证说明**: CopyTensorData memcpy with data_size derived from tensor Sizes(). Internal tensor operation, not direct external input. Overflow risk if Size() overflows. Strong mitigations in tensor management.

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [VULN-CONVERT-PATH-001] Path Traversal - ConverterImpl::GetStrFromConfigFile

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/converter.cc:656-706` @ `ConverterImpl::GetStrFromConfigFile`
**模块**: converter_core

**描述**: GetStrFromConfigFile in converter.cc uses realpath() to resolve config file path but does not validate that the resolved path is within expected boundaries. The function reads arbitrary key-value pairs from the config file and returns values that are later used for various operations including plugin loading and parallel computation configuration.

**漏洞代码** (`mindspore-lite/tools/converter/converter.cc:656-706`)

```c
char *real_path = realpath(file.c_str(), resolved_path.get());\nstd::ifstream ifs(resolved_path.get());
```

**达成路径**

config_file path -> realpath() -> ifstream read -> key-value parsing -> value used in subsequent operations

**验证说明**: GetStrFromConfigFile uses realpath() for config path. Reads arbitrary key-value pairs. Cannot prevent reading malicious config files if path user-controlled. Strong mitigation (realpath) but limited impact.

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [VULN-CONVERT-INT-001] Integer Overflow - InitModelInputShape

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/converter.cc:178-225` @ `InitModelInputShape`
**模块**: converter_core

**描述**: InitModelInputShape in converter.cc parses dimension values from command-line inputShape argument using std::stoi() without bounds checking. The parsed dimensions are stored in param->input_shape map and used for tensor shape calculations. Negative or extremely large values could lead to integer overflow in subsequent memory allocation calculations.

**漏洞代码** (`mindspore-lite/tools/converter/converter.cc:178-225`)

```c
dim_value = std::stoi(dim);\nshape.push_back(dim_value);
```

**达成路径**

inputShape CLI argument -> StrSplit -> std::stoi(dim) -> shape.push_back() -> param->input_shape[name] = shape

**验证说明**: InitModelInputShape std::stoi() for dimension parsing. CLI input (semi_trusted). No bounds check after parsing. Exception handling exists for stoi overflow. Shape used in tensor calculations.

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [VULN-CONVERT-INT-002] Integer Overflow - ParseDynamicDimTemplate

**严重性**: Low（原评估: medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/config_parser/config_file_parser.cc:272-291` @ `ParseDynamicDimTemplate`
**模块**: converter_core

**描述**: ParseDynamicDimTemplate in config_file_parser.cc parses dimension ranges from config file using std::stoi() and uses them directly in loops. The function at lines 285-289 iterates from start to end where start and end are parsed integers. If malicious values are provided, this could lead to excessive iterations or memory issues. The check for >0 is insufficient for overflow prevention.

**漏洞代码** (`mindspore-lite/tools/converter/config_parser/config_file_parser.cc:272-291`)

```c
auto start = std::stoi(continuous_dim[0]);\nauto end = std::stoi(continuous_dim[1]);\nfor (auto i = start; i <= end; ++i) {
```

**达成路径**

dynamic_dim_params config -> SplitStringToVector -> std::stoi() -> loop iteration -> emplace_back to vector

**验证说明**: ParseDynamicDimTemplate std::stoi() for dimension ranges. Loop from start to end. Positive check exists but no upper bound. Could exhaust memory with large range. Internal operation with mitigations.

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 30

---

### [QUANT-006] Division by Zero - CalWeightQuantBias

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-369 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/common/quant_utils.cc:198-199` @ `CalWeightQuantBias`
**模块**: quantizer

**描述**: Bucket volume calculation in CalWeightQuantBias() divides by bucket_volume without checking for zero. If dims[preferred_dim] equals elem_count, bucket_volume becomes zero causing division by zero.

**漏洞代码** (`src/common/quant_utils.cc:198-199`)

```c
average_raws[bucket_index] = total_raws[bucket_index] / bucket_volume;
```

**达成路径**

total_raws -> bucket_volume -> average_raws -> quant_params

**验证说明**: CalWeightQuantBias division by bucket_volume. bucket_volume could be 0 if dims[preferred_dim] == elem_count. Internal module.

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 5

---

### [QUANT-008] Division by Zero - GetBucketIndex

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-369 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/common/quant_utils.cc:107-118` @ `GetBucketIndex`
**模块**: quantizer

**描述**: GetBucketIndex() function divides by stride without proper zero check. While there is a check for stride == 0 || bucket_count == 0, the return statement can still produce invalid index if conditions pass but values are invalid.

**漏洞代码** (`src/common/quant_utils.cc:107-118`)

```c
stride *= dims[i]; return (data_index / stride) % bucket_count;
```

**达成路径**

dims[i] -> stride -> bucket_index -> per_channel_min_max

**验证说明**: GetBucketIndex division by stride. Check for stride == 0 || bucket_count == 0 exists. Internal module.

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 5

---

### [QUANT-010] Division by Zero - CalQuantizationParams

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-369 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/common/quant_utils.cc:87` @ `CalQuantizationParams`
**模块**: quantizer

**描述**: Per-channel quantization scale zero-point calculation can overflow. The zero_point calculation std::round(quant_min - encode_min / scale) can produce values outside quantized range if scale is very small.

**漏洞代码** (`src/common/quant_utils.cc:87`)

```c
int zero_point = static_cast<int32_t>(std::round(quant_min - encode_min / scale));
```

**达成路径**

encode_min -> scale -> zero_point -> quant_param

**验证说明**: zero_point = static_cast<int32_t>(round(quant_min - encode_min/scale)). Overflow if scale very small. Internal module. Mitigation: upstream scale validation.

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 5

---

### [VULN-SEC-MP-003] information_disclosure - InitOriginModel

**严重性**: Low | **CWE**: CWE-532 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/converter/parser/onnx/onnx_model_parser.cc:751` @ `InitOriginModel`
**模块**: model_parser

**描述**: Sensitive file paths are logged in error messages across multiple parser files. This could reveal information about the system filesystem structure to attackers who can observe logs.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/mindspore-lite/mindspore-lite/tools/converter/parser/onnx/onnx_model_parser.cc:751`)

```c
MS_LOG(ERROR) << "Read onnx model file failed, model path: " << model_file;
```

**达成路径**

Error condition -> MS_LOG -> file path exposure

**验证说明**: Sensitive file paths logged in error messages. MS_LOG(ERROR) exposes model_file path. Information disclosure risk if attacker observes logs. Low security impact.

**评分明细**: base: 30 | controllability: 5 | context: 0 | cross_file: 0 | mitigations: -25 | reachability: 30

---

### [QUANT-007] Memory Safety - ConvertParameterFp16TensorToFp32

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-125 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `tools/converter/quantizer/weight_quantizer.cc:67-73` @ `ConvertParameterFp16TensorToFp32`
**模块**: quantizer

**描述**: FP16 to FP32 conversion in ConvertParameterFp16TensorToFp32() allocates vector without checking tensor size. Large tensor sizes could cause memory allocation failure or excessive memory consumption.

**漏洞代码** (`tools/converter/quantizer/weight_quantizer.cc:67-73`)

```c
auto data = static_cast<float16 *>(tensor_info->data_c()); std::vector<float> fp32_data(tensor_info->DataSize());
```

**达成路径**

tensor_info -> DataSize() -> fp32_data -> tensor_ptr

**验证说明**: FP16 to FP32 conversion allocates vector without size check. Large tensors could cause allocation failure. Internal module, controlled data source.

**评分明细**: base: 30 | controllability: 5 | context: 0 | cross_file: 0 | mitigations: -25 | reachability: 5

---

### [VULN-CONVERT-MEM-001] Memory Safety - PreInference

**严重性**: Low（原评估: low → 验证后: Low） | **CWE**: CWE-119 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindspore-lite/tools/converter/converter.cc:354-416` @ `PreInference`
**模块**: converter_core

**描述**: PreInference in converter.cc builds a temporary model from meta_graph for pre-inference testing. The flatbuffers::FlatBufferBuilder is used to pack the meta_graph and the buffer pointer is passed to model.Build(). While this is an internal operation, improper handling of the FlatBufferBuilder buffer could lead to use-after-free if the builder is cleared or destroyed before the model Build operation completes.

**漏洞代码** (`mindspore-lite/tools/converter/converter.cc:354-416`)

```c
flatbuffers::FlatBufferBuilder builder(kMaxNum1024);\nauto content = builder.GetBufferPointer();\nauto ret = model.Build(content, size, kMindIR_Lite, context);
```

**达成路径**

meta_graph -> FlatBufferBuilder::Pack() -> builder.GetBufferPointer() -> model.Build() -> model.Predict()

**验证说明**: PreInference FlatBufferBuilder buffer used in model.Build(). Internal operation, controlled data. Lifecycle management concern but limited security impact. Strong mitigations for internal flow.

**评分明细**: base: 30 | controllability: 5 | context: 0 | cross_file: 0 | mitigations: -25 | reachability: 30

---

## 7. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| converter_core | 0 | 6 | 2 | 4 | 12 |
| hardware_providers | 1 | 1 | 2 | 2 | 6 |
| micro_coder | 0 | 0 | 2 | 0 | 2 |
| model_parser | 0 | 2 | 5 | 3 | 10 |
| quantizer | 0 | 0 | 6 | 4 | 10 |
| runtime_engine | 0 | 3 | 3 | 2 | 8 |
| **合计** | **1** | **12** | **20** | **15** | **48** |

## 8. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-190 | 11 | 21.6% |
| CWE-787 | 7 | 13.7% |
| CWE-78 | 7 | 13.7% |
| CWE-125 | 6 | 11.8% |
| CWE-22 | 5 | 9.8% |
| CWE-369 | 4 | 7.8% |
| CWE-120 | 2 | 3.9% |
| CWE-119 | 2 | 3.9% |
| CWE-94 | 1 | 2.0% |
| CWE-754 | 1 | 2.0% |
| CWE-532 | 1 | 2.0% |
| CWE-400 | 1 | 2.0% |
| CWE-15 | 1 | 2.0% |
| CWE-122 | 1 | 2.0% |
| CWE-121 | 1 | 2.0% |
