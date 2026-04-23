# 漏洞扫描报告 — 待确认漏洞

**项目**: GE (Graph Engine)
**扫描时间**: 2026-04-22T10:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 7 | 46.7% |
| FALSE_POSITIVE | 4 | 26.7% |
| LIKELY | 3 | 20.0% |
| POSSIBLE | 1 | 6.7% |
| **总计** | **15** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 2 | 50.0% |
| Medium | 2 | 50.0% |
| **有效漏洞总计** | **4** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DFLOW-002]** Missing IP Validation (High) - `dflow/deployer/daemon/daemon_service.cc:48` @ `VerifyIpaddr` | 置信度: 75
2. **[dflow-pkl-cpp-load-006]** Insecure Deserialization via C++ (High) - `/home/pwn20tty/Desktop/opencode_project/cann/4/ge/dflow/pydflow/python/dataflow/tools/tpl/tpl_wrapper_code.py:242` @ `InitPyObjFromPkl` | 置信度: 70
3. **[dflow-cpp-sys-path-005]** Code Injection via Generated C++ (Medium) - `/home/pwn20tty/Desktop/opencode_project/cann/4/ge/dflow/pydflow/python/dataflow/tools/tpl/tpl_wrapper_code.py:88` @ `Init` | 置信度: 65
4. **[VULN-DF-CMD-001]** command_injection (Medium) - `parser/parser/tensorflow/tensorflow_custom_op_parser.cc:437` @ `CompileCustomOpFiles` | 置信度: 55

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `aclgrphParseONNX@parser/parser/onnx/onnx_parser.cc` | file | untrusted_local | 解析外部ONNX模型文件，用户可控制的模型文件路径 | ONNX模型文件解析入口，读取并解析ONNX protobuf文件 |
| `aclgrphParseONNXFromMem@parser/parser/onnx/onnx_parser.cc` | file | untrusted_local | 从内存缓冲区解析ONNX模型，用户控制缓冲区内容 | ONNX内存缓冲区解析入口 |
| `OnnxModelParser::Parse@parser/parser/onnx/onnx_parser.cc` | file | untrusted_local | ONNX模型文件解析核心函数 | ONNX模型解析核心实现 |
| `OnnxModelParser::ParseFromMemory@parser/parser/onnx/onnx_parser.cc` | file | untrusted_local | ONNX内存解析核心函数 | ONNX内存解析核心实现 |
| `aclgrphParseTensorFlow@parser/parser/tensorflow/tensorflow_parser.cc` | file | untrusted_local | 解析外部TensorFlow PB模型文件 | TensorFlow PB模型文件解析入口 |
| `aclgrphParseCaffe@parser/parser/caffe/caffe_parser.cc` | file | untrusted_local | 解析外部Caffe模型文件 | Caffe模型文件解析入口 |
| `aclmdlLoadFromFile@api/acl/acl_model/model/acl_model.cpp` | file | untrusted_local | ACL API模型文件加载入口 | ACL模型文件加载，加载编译后的OM模型 |
| `aclmdlLoadFromMem@api/acl/acl_model/model/acl_model.cpp` | file | untrusted_local | ACL API内存模型加载入口 | ACL内存模型加载，从用户缓冲区加载OM模型 |
| `aclmdlGetDescFromFile@api/acl/acl_model/model/acl_model.cpp` | file | untrusted_local | 从文件获取模型描述信息 | 模型描述文件读取 |
| `aclmdlGetDescFromMem@api/acl/acl_model/model/acl_model.cpp` | file | untrusted_local | 从内存获取模型描述信息 | 模型描述内存读取 |
| `Session::AddGraph@api/session/session/session.cc` | rpc | semi_trusted | Session图添加接口，用户构建的Graph | 添加计算图到Session |
| `Session::RunGraph@api/session/session/session.cc` | rpc | semi_trusted | Session图执行接口，用户提供的输入数据 | 执行计算图推理 |
| `DaemonService::Process@dflow/deployer/daemon/daemon_service.cc` | network | untrusted_network | 分布式部署守护进程网络请求处理入口，接收远程节点请求 | Daemon服务请求处理入口 |
| `DaemonService::ProcessInitRequest@dflow/deployer/daemon/daemon_service.cc` | network | untrusted_network | 处理远程节点初始化请求 | Daemon初始化请求处理 |
| `DaemonService::ProcessDisconnectRequest@dflow/deployer/daemon/daemon_service.cc` | network | untrusted_network | 处理远程节点断连请求 | Daemon断连请求处理 |
| `LlmWorker::Initialize@dflow/llm_datadist/v1/common/llm_flow_service.cc` | rpc | semi_trusted | LLM分布式Worker初始化 | LLM Worker初始化 |
| `LlmWorker::LoadFlowFuncs@dflow/llm_datadist/v1/common/llm_flow_service.cc` | rpc | semi_trusted | LLM分布式Flow函数加载 | LLM Flow函数加载 |
| `TbePluginLoader::LoadSo@parser/parser/common/tbe_plugin_loader.cc` | file | untrusted_local | 动态加载外部SO插件文件 | TBE插件SO动态加载 |
| `CustomOpSoLoader::LoadSo@base/common/helper/custom_op_so_loader.cc` | file | untrusted_local | 动态加载自定义算子SO文件 | 自定义算子SO动态加载 |
| `ModelSerialize::UnserializeModel@graph_metadef/graph/serialization/model_serialize.cc` | file | untrusted_local | 模型反序列化，从protobuf数据恢复模型 | 模型protobuf反序列化 |
| `main@api/atc/main.cc` | cmdline | trusted_admin | ATC命令行工具入口，管理员控制 | ATC模型转换工具主入口 |
| `pygraph_create@api/python/ge/ge/_capi/pygraph_wrapper.py` | decorator | semi_trusted | Python Graph创建API，绑定到C++实现 | Python Graph wrapper入口 |
| `pysession_create@api/python/ge/ge/_capi/pysession_wrapper.py` | decorator | semi_trusted | Python Session创建API | Python Session wrapper入口 |
| `create_flow_graph@dflow/pydflow/python/dataflow/pyflow.py` | decorator | semi_trusted | Dataflow Python流图创建 | Python Dataflow入口 |

**其他攻击面**:
- ONNX模型文件解析: parser/parser/onnx/onnx_parser.cc
- TensorFlow PB模型文件解析: parser/parser/tensorflow/tensorflow_parser.cc
- Caffe模型文件解析: parser/parser/caffe/caffe_parser.cc
- 内存缓冲区模型解析: ParseFromMemory函数族
- ACL模型文件加载: api/acl/acl_model/model/acl_model.cpp
- Session图执行: api/session/session/session.cc
- 分布式守护进程网络服务: dflow/deployer/daemon/daemon_service.cc
- LLM分布式流服务: dflow/llm_datadist/v1/common/llm_flow_service.cc
- 模型序列化/反序列化: graph_metadef/graph/serialization/model_serialize.cc
- TBE插件动态加载: parser/parser/common/tbe_plugin_loader.cc
- 自定义算子SO加载: base/common/helper/custom_op_so_loader.cc
- Python C API绑定: api/python/ge/ge/_capi/
- ATC命令行工具: api/atc/main.cc
- 外部权重文件加载: FileConstant算子外部权重

---

## 3. High 漏洞 (2)

### [VULN-DFLOW-002] Missing IP Validation - VerifyIpaddr

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-287 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `dflow/deployer/daemon/daemon_service.cc:48-51` @ `VerifyIpaddr`
**模块**: dflow

**描述**: IP地址验证完全可选。当 remote_configs.empty() 时，VerifyIpaddr 直接返回 SUCCESS，任何IP地址都可以连接守护进程服务。

**漏洞代码** (`dflow/deployer/daemon/daemon_service.cc:48-51`)

```c
if (remote_configs.empty()) { GELOGI("Without remote config, no need to verify ipaddr."); return SUCCESS; }
```

**验证说明**: IP validation optional when remote_configs.empty(). Any IP can connect to daemon service. trust_level=untrusted_network confirms network attack surface. Mitigated only when remote_configs configured.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [dflow-pkl-cpp-load-006] Insecure Deserialization via C++ - InitPyObjFromPkl

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-502 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/4/ge/dflow/pydflow/python/dataflow/tools/tpl/tpl_wrapper_code.py:242-296` @ `InitPyObjFromPkl`
**模块**: dflow-python

**描述**: Generated C++ code loads pickle files from work_path and deserializes using cloudpickle. The InitPyObjFromPkl function reads .pkl files and deserializes them without integrity checks. Attackers could replace pickle files with malicious payloads.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/4/ge/dflow/pydflow/python/dataflow/tools/tpl/tpl_wrapper_code.py:242-296`)

```c
py_obj_ = deserialize_func(py::memoryview::from_memory(&buffer[0], buffer.size(), false))
```

**验证说明**: Generated C++ code loads .pkl files from work_path and deserializes via cloudpickle. File read from work_path + py_clz_name.pkl. Attacker with file write access to work_path can inject malicious pickle payload.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (2)

### [dflow-cpp-sys-path-005] Code Injection via Generated C++ - Init

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/4/ge/dflow/pydflow/python/dataflow/tools/tpl/tpl_wrapper_code.py:88-89` @ `Init`
**模块**: dflow-python

**描述**: Generated C++ wrapper code uses PyRun_SimpleString to append work_path to sys.path without sanitization. If params->GetWorkPath() contains malicious Python code, it could be executed. Generated code template injects path directly into Python interpreter.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/4/ge/dflow/pydflow/python/dataflow/tools/tpl/tpl_wrapper_code.py:88-89`)

```c
PyRun_SimpleString("import sys"); std::string append = std::string("sys.path.append(\'") + params->GetWorkPath() + "\')"; PyRun_SimpleString(append.c_str())
```

**验证说明**: PyRun_SimpleString with sys.path.append(work_path) without quote sanitization. If work_path contains single quotes or Python code injection, arbitrary Python execution possible. Generated C++ template injects path directly.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CMD-001] command_injection - CompileCustomOpFiles

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `parser/parser/tensorflow/tensorflow_custom_op_parser.cc:437-441` @ `CompileCustomOpFiles`
**模块**: parser

**描述**: system() call with constructed command string. The command is constructed from compile paths and includes g++ compilation. Although paths are validated with kSafePathRegex, the system() call itself is risky. The regex blocks '..' but shell metacharacters could potentially bypass validation if edge cases exist.

**漏洞代码** (`parser/parser/tensorflow/tensorflow_custom_op_parser.cc:437-441`)

```c
std::string command = "g++ -O2 -fstack-protector-all -shared -fPIC -Wl,-z,now -Wl,-z,noexecstack -s -o " + output_so_path + " -D_GLIBCXX_USE_CXX11_ABI=0 ... " + custom_op_cc_path;
GE_ASSERT_TRUE(CheckPathInCmdIsValid(output_so_path, incloud_path, register_path), ...);
int rc = system(command.c_str());
```

**达成路径**

custom_op_cc_path [SOURCE - from model file]
→ GetCompilePath@parser/parser/tensorflow/tensorflow_custom_op_parser.cc:409
→ CheckPathInCmdIsValid@parser/parser/tensorflow/tensorflow_custom_op_parser.cc:426 [PARTIAL SANITIZATION]
→ system()@parser/parser/tensorflow/tensorflow_custom_op_parser.cc:441 [SINK]

**验证说明**: system() call for g++ compilation. Paths validated with kSafePathRegex blocking '..' and shell metacharacters not in [A-Za-z0-9./+-_]. However, regex may not cover all edge cases. custom_op_cc_path origin needs further tracing to confirm if from untrusted model file.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| dflow | 0 | 1 | 0 | 0 | 1 |
| dflow-python | 0 | 1 | 1 | 0 | 2 |
| parser | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **2** | **2** | **0** | **4** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-94 | 1 | 25.0% |
| CWE-78 | 1 | 25.0% |
| CWE-502 | 1 | 25.0% |
| CWE-287 | 1 | 25.0% |
