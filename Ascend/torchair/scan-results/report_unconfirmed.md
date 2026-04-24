# 漏洞扫描报告 — 待确认漏洞

**项目**: torchair
**扫描时间**: 2026-04-24T06:38:54.193Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 5 | 35.7% |
| LIKELY | 4 | 28.6% |
| FALSE_POSITIVE | 4 | 28.6% |
| CONFIRMED | 1 | 7.1% |
| **总计** | **14** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 3 | 33.3% |
| Medium | 6 | 66.7% |
| **有效漏洞总计** | **9** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-INJ-001]** code_injection (High) - `python/torchair/npu_fx_compiler.py:1027` @ `_compile_py_code` | 置信度: 65
2. **[VULN-DF-INJ-002]** code_injection (High) - `python/torchair/_ge_concrete_graph/fx2ge_converter.py:666` @ `get_or_auto_gen_converter` | 置信度: 65
3. **[VULN-DF-PROTO-001]** deserialization (High) - `torchair/abi_compat_ge_apis/compat_apis.cpp:129` @ `ParseGraphFromArray` | 置信度: 60
4. **[VULN-SEC-PATH-001]** path_traversal (Medium) - `torchair/core/torchair.cpp:168` @ `AclopStartDumpArgs` | 置信度: 65
5. **[VULN-DF-INPUT-001]** input_validation (Medium) - `torchair/core/torchair.cpp:24` @ `ParseListTensors/ParseListOptionalTensors` | 置信度: 55
6. **[VULN-SEC-CONF-001]** improper_input_validation (Medium) - `torchair/concrete_graph/session.cpp:42` @ `Session::Initialize` | 置信度: 50
7. **[VULN-DF-PATH-001]** path_traversal (Medium) - `torchair/concrete_graph/export.cpp:19` @ `ep::Export` | 置信度: 50
8. **[VULN-SEC-DYNLIB-002]** insecure_library_loading (Medium) - `torchair/utils_tools/utils_tools.cpp:42` @ `GetOpApiLibHandler` | 置信度: 40
9. **[VULN-DF-DYN-002]** library_injection (Medium) - `torchair/utils_tools/utils_tools.cpp:55` @ `NpuOpUtilsTools::CheckAclnnAvaliable` | 置信度: 40

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `get_npu_backend@undefined` | Python API | - | - | Main entry point for NPU graph compilation via torch.compile |
| `dynamo_export@undefined` | Python API | - | - | Export model to offline .air format |
| `Load@undefined` | C++ API | - | - | Load serialized graph from proto buffer |
| `Run@undefined` | C++ API | - | - | Execute graph with user-provided tensors |
| `Initialize@undefined` | C++ API | - | - | Initialize GE session with configuration options |
| `ep::Export@undefined` | C++ API | - | - | Export graph to .air file |
| `AsTorchTensor@undefined` | C++ API | - | - | Create tensors from raw memory addresses |
| `patch_for_hcom@undefined` | Python API | - | - | Patch torch.distributed for HCOM operations |
| `__call__@undefined` | Python API | - | - | Execute GE graph with runtime inputs |
| `AclopStartDumpArgs@undefined` | C++ API | - | - | Start ACL dump with user-provided path |

**其他攻击面**:
- [object Object]
- [object Object]
- [object Object]
- [object Object]
- [object Object]
- [object Object]
- [object Object]
- [object Object]
- [object Object]
- [object Object]

---

## 3. High 漏洞 (3)

### [VULN-DF-INJ-001] code_injection - _compile_py_code

**严重性**: High | **CWE**: CWE-95 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner, security-auditor

**位置**: `python/torchair/npu_fx_compiler.py:1027-1029` @ `_compile_py_code`
**模块**: python/torchair

**描述**: exec() with dynamically generated code. The _compile_py_code function uses exec() to execute code generated from graph codegen. While the code is generated internally from FX graph compilation, if a malicious FX graph with crafted node operations is provided, the generated code could contain dangerous constructs. The exec() call has no sandboxing or code validation.

**漏洞代码** (`python/torchair/npu_fx_compiler.py:1027-1029`)

```c
def _compile_py_code(py_code: str):
    ge_mod = ModuleType('ge_mod')
    exec(compile(py_code, '<string>', 'exec'), ge_mod.__dict__, ge_mod.__dict__)
    return ge_mod
```

**达成路径**

GeConcreteGraph.codegen() -> py_code string -> _compile_py_code (npu_fx_compiler.py:1027) -> exec() [SINK]

**验证说明**: exec()执行动态生成的代码存在风险。py_code来自FX graph内部codegen，不是直接用户输入，但通过自定义算子可能间接控制生成内容。缺乏沙箱隔离或代码验证。实际利用难度较高但路径可达。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-INJ-002] code_injection - get_or_auto_gen_converter

**严重性**: High | **CWE**: CWE-95 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner, security-auditor

**位置**: `python/torchair/_ge_concrete_graph/fx2ge_converter.py:666-679` @ `get_or_auto_gen_converter`
**模块**: python/torchair/_ge_concrete_graph

**描述**: exec() with auto-generated converter code. The get_or_auto_gen_converter function dynamically generates converter code based on user-provided operator metadata and executes it via exec(). The converter_code is built from operator schema information including ge_name, ge_inputs, ge_outputs which come from external GE API. If malicious custom operator metadata is registered, dangerous code could be generated and executed.

**漏洞代码** (`python/torchair/_ge_concrete_graph/fx2ge_converter.py:666-679`)

```c
def get_or_auto_gen_converter(target):
    ...
    converter_code = _generate_converter_code(target)
    logger.info(f"The converter for the Ascend operator {target} has been automatically converted: {converter_code}")
    exec(converter_code)
    converter = target._ge_converter
    return converter
```

**达成路径**

User FX graph -> target (OpOverload) -> _generate_converter_code (fx2ge_converter.py:867) -> converter_code string -> exec() [SINK]

**验证说明**: exec()执行自动生成的转换器代码。converter_code基于OpOverload的schema信息生成，schema来自用户的FX graph。缺乏代码验证和沙箱。实际利用需要注册恶意算子元数据。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-PROTO-001] deserialization - ParseGraphFromArray

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-502 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `torchair/abi_compat_ge_apis/compat_apis.cpp:129-136` @ `ParseGraphFromArray`
**模块**: torchair/abi_compat_ge_apis

**描述**: Proto buffer deserialization without comprehensive validation. ParseGraphFromArray takes serialized_proto and proto_size from user and directly calls graph->LoadFromSerializedModelArray() without version compatibility check, content validation, or malicious structure detection. While a 2G size limit exists in concrete_graph.cpp:182, no other security validation is performed.

**漏洞代码** (`torchair/abi_compat_ge_apis/compat_apis.cpp:129-136`)

```c
Status ParseGraphFromArray(const void *serialized_proto, size_t proto_size, ge::GraphPtr &graph) {
  TNG_ASSERT_NOTNULL(serialized_proto, "Given serialized proto is nullptr.");
  if (graph == nullptr) {
    graph = std::make_shared<ge::Graph>();
  }
  TNG_ASSERT(graph->LoadFromSerializedModelArray(serialized_proto, proto_size) == ge::GRAPH_SUCCESS);
  return Status::Success();
}
```

**达成路径**

TorchNpuGraphBase::Load (torchair.cpp:182) -> NpuConcreteGraph::Create (concrete_graph.cpp:176) -> ParseGraphFromArray (compat_apis.cpp:129) -> graph->LoadFromSerializedModelArray() [SINK]

**验证说明**: Proto反序列化存在风险，但有2G大小限制和空指针检查缓解。用户通过Python API Load()可直接传入序列化proto数据，完全控制内容和大小。缺乏版本兼容检查和内容验证，但实际风险取决于GE库内部LoadFromSerializedModelArray的实现。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -25 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (6)

### [VULN-SEC-PATH-001] path_traversal - AclopStartDumpArgs

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `torchair/core/torchair.cpp:168-172` @ `AclopStartDumpArgs`
**模块**: torchair/core

**描述**: ACL dump 路径未验证。AclopStartDumpArgs 函数接收用户提供的路径参数并直接传递给 aclopStartDumpArgs，未进行路径规范化、符号链接检查或路径遍历验证。攻击者可使用相对路径(../)访问非预期目录。

**漏洞代码** (`torchair/core/torchair.cpp:168-172`)

```c
void AclopStartDumpArgs(uint32_t dumpType, const char *path) {
    RECORD_FUNCTION("torchair::AclopStartDumpArgs", {});
    auto ret = aclopStartDumpArgs(dumpType, path);
    TNG_RAISE_ASSERT(ret == 0, "AclopStartDumpArgs execute failed");
}
```

**达成路径**

用户路径参数 -> AclopStartDumpArgs -> aclopStartDumpArgs -> ACL dump配置

**验证说明**: ACL dump路径直接传递给aclopStartDumpArgs，无路径规范化或遍历验证。用户可通过相对路径(../)访问非预期目录。实际攻击价值取决于ACL库内部处理。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-INPUT-001] input_validation - ParseListTensors/ParseListOptionalTensors

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `torchair/core/torchair.cpp:24-95` @ `ParseListTensors/ParseListOptionalTensors`
**模块**: torchair/core

**描述**: Python-C++ boundary tensor parsing with limited validation. ParseListTensors and ParseListOptionalTensors parse Python objects (PyList/PyTuple) into C++ tensors. While basic type checking exists (THPVariable_CheckExact), there is no validation of tensor shape bounds, dtype consistency, or device placement. Large tensor lists could cause memory pressure without size limits.

**漏洞代码** (`torchair/core/torchair.cpp:24-95`)

```c
tng::Status ParseListTensors(PyObject *obj, std::vector<at::Tensor> &tensors) {
  auto tuple = six::isTuple(obj);
  if (!(tuple || PyList_Check(obj))) {
    return tng::Status::Error("not a list or tuple");
  }
  const auto size = tuple ? PyTuple_GET_SIZE(obj) : PyList_GET_SIZE(obj);
  for (long idx = 0; idx < size; idx++) {
    PyObject *iobj = tuple ? PyTuple_GET_ITEM(obj, idx) : PyList_GET_ITEM(obj, idx);
    ...
    tensors.emplace_back(THPVariable_Unpack(iobj));
  }
  return tng::Status::Success();
}
```

**达成路径**

Python Run() call -> TorchNpuGraphBase::Run (torchair.cpp:233) -> ParseListTensors (torchair.cpp:58) -> THPVariable_Unpack -> at::Tensor [Sink]

**验证说明**: Python-C++ tensor解析使用PyTorch标准机制(THPVariable_CheckExact)。存在类型检查但无形状/设备验证。实际风险较低：这是PyTorch的标准tensor传递方式，漏洞描述夸大了风险。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-CONF-001] improper_input_validation - Session::Initialize

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `torchair/concrete_graph/session.cpp:42-64` @ `Session::Initialize`
**模块**: torchair/concrete_graph

**描述**: GE Session 初始化配置选项未进行全面验证。Session::Initialize 接收用户提供的配置选项并直接传递给 GEInitialize，仅对 device_id 进行基本范围检查。配置键值未进行白名单验证或内容清洗，可能影响 GE引擎行为或日志输出。

**漏洞代码** (`torchair/concrete_graph/session.cpp:42-64`)

```c
Status Session::Initialize(const std::map<std::string, std::string> &options) {
    ...
    for (const auto &option : options) {
        TNG_LOG(INFO) << "  " << option.first << ": " << option.second;
        ...
        ge_options[option.first.c_str()] = option.second.c_str();
    }
    auto iter = ge_options.find(ge::AscendString(ge::OPTION_EXEC_DEVICE_ID));
    TNG_ASSERT(iter != ge_options.end(), "Device id is not specified...");
    device_index_ = static_cast<int32_t>(std::atoi(iter->second.GetString()));
}
```

**达成路径**

用户配置选项 -> Session::Initialize -> GEInitialize -> GE引擎配置

**验证说明**: 配置选项字符串直接传递给GEInitialize，无白名单验证。实际风险较低：配置只是字符串参数传递，不涉及代码执行。GE引擎内部应有参数校验。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-PATH-001] path_traversal - ep::Export

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `torchair/concrete_graph/export.cpp:19-48` @ `ep::Export`
**模块**: torchair/concrete_graph

**描述**: Export path handling with partial mitigation. The Export function constructs a file path from user-provided export_path_dir and export_name. While symlink protection exists (line 39 checks is_symlink), the path components could still contain '..' sequences that might escape the intended directory. Uses std::filesystem::absolute after symlink check but before file write.

**漏洞代码** (`torchair/concrete_graph/export.cpp:19-48`)

```c
Status Export(const void *serialized_proto, size_t proto_size,
                 const std::map<ge::AscendString, ge::AscendString> &options) {
    ...
    save_air_path += iter_path->second.GetString();
    save_air_path += "/";
    save_air_path += iter_name->second.GetString();
    ...
    std::filesystem::path file_path(save_air_path);
    TNG_ASSERT(!std::filesystem::is_symlink(file_path), "Target file path should not be an symbolic link");
    save_air_path = std::filesystem::absolute(file_path).string();
    ...
    TNG_ASSERT(graph->SaveToFile(save_air_path.c_str()) == ge::GRAPH_SUCCESS);
}
```

**达成路径**

Python dynamo_export (npu_export.py:46) -> Export (torchair.cpp:122) -> ep::Export (export.cpp:19) -> graph->SaveToFile() [SINK]

**验证说明**: Export路径有符号链接检查缓解措施(is_symlink)，但仍可能存在路径遍历风险。使用std::filesystem::absolute进行路径处理，但未完全验证路径是否指向预期目录。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-DYNLIB-002] insecure_library_loading - GetOpApiLibHandler

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `torchair/utils_tools/utils_tools.cpp:42-50` @ `GetOpApiLibHandler`
**模块**: torchair/utils_tools

**描述**: 动态库加载使用相对路径而非绝对路径。GetOpApiLibHandler 函数使用 dlopen(lib_name, RTLD_LAZY) 仅传入库名("libopapi.so")而非绝对路径，同样依赖系统库搜索路径。若攻击者控制搜索路径，可实现库注入。

**漏洞代码** (`torchair/utils_tools/utils_tools.cpp:42-50`)

```c
inline void *GetOpApiLibHandler(const char *lib_name) {
    auto handler = dlopen(lib_name, RTLD_LAZY);
    if (handler == nullptr) {
        TNG_LOG(ERROR) << "dlopen "<< lib_name << " failed, error: " << dlerror() << ".";
    }
    return handler;
}
```

**达成路径**

系统环境(LD_LIBRARY_PATH) -> dlopen -> 加载恶意库 -> 代码执行

**验证说明**: dlsym查找用户提供的aclnn_name符号名。攻击价值有限：dlsym只查找符号地址不执行代码。库名硬编码libopapi.so，攻击者只能控制符号名查找。实际利用场景不明确。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-DYN-002] library_injection - NpuOpUtilsTools::CheckAclnnAvaliable

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `torchair/utils_tools/utils_tools.cpp:55-64` @ `NpuOpUtilsTools::CheckAclnnAvaliable`
**模块**: torchair/utils_tools

**描述**: dlopen/dlsym with user-influenced symbol lookup. CheckAclnnAvaliable takes aclnn_name (operator name) as input and uses dlsym to lookup that symbol in libopapi.so. While the library name is hardcoded, the symbol name comes from user input (CheckAclnnAvaliable is called from Python with user-provided aclnn_name). Symbol name validation is minimal.

**漏洞代码** (`torchair/utils_tools/utils_tools.cpp:55-64`)

```c
bool NpuOpUtilsTools::CheckAclnnAvaliable(const std::string &aclnn_name) {
    static auto opapi_handler = GetOpApiLibHandler(GetOpApiLibName());
    if (opapi_handler != nullptr) {
        auto func_addr = GetOpApiFuncAddrInLib(opapi_handler, GetOpApiLibName(), aclnn_name.c_str());
        if (func_addr != nullptr) {
            return true;
        }
    }
    return false;
}
```

**达成路径**

TorchNpuGraphBase::CheckAclnnAvaliable (torchair.cpp:283) -> NpuOpUtilsTools::CheckAclnnAvaliable (utils_tools.cpp:55) -> dlsym(handler, aclnn_name.c_str()) [SINK]

**验证说明**: 与VULN-SEC-DYNLIB-002相同，dlsym查找aclnn_name符号。库名硬编码，攻击者只能控制符号名，实际利用价值有限。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| python/torchair | 0 | 1 | 0 | 0 | 1 |
| python/torchair/_ge_concrete_graph | 0 | 1 | 0 | 0 | 1 |
| torchair/abi_compat_ge_apis | 0 | 1 | 0 | 0 | 1 |
| torchair/concrete_graph | 0 | 0 | 2 | 0 | 2 |
| torchair/core | 0 | 0 | 2 | 0 | 2 |
| torchair/utils_tools | 0 | 0 | 2 | 0 | 2 |
| **合计** | **0** | **3** | **6** | **0** | **9** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-95 | 2 | 22.2% |
| CWE-426 | 2 | 22.2% |
| CWE-22 | 2 | 22.2% |
| CWE-20 | 2 | 22.2% |
| CWE-502 | 1 | 11.1% |
