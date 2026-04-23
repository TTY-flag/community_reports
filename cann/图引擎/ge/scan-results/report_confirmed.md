# 漏洞扫描报告 — 已确认漏洞

**项目**: GE (Graph Engine)  
**扫描时间**: 2026-04-22T10:00:00Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次漏洞扫描针对华为 CANN (Compute Architecture for Neural Networks) GE (Graph Engine) 项目进行了深度安全分析。该项目是一个 AI 推理框架，支持 ONNX/TensorFlow/Caffe 模型解析与编译，在昇腾 AI 处理器上执行推理。

### 关键发现

扫描发现 **7 个已确认漏洞**，其中 **4 个 Critical 级别**，**3 个 High 级别**。最严重的漏洞涉及：

1. **任意代码执行风险** - OM 模型文件中的自定义算子 SO 二进制通过 memfd+dlopen 加载，无签名验证。攻击者可通过恶意模型文件执行任意代码。这是本项目最严重的安全漏洞。

2. **远程代码执行风险** - dflow 分布式模块使用 cloudpickle 反序列化未信任数据，pickle 反序列化可执行任意代码。在分布式系统环境下，攻击者可通过注入恶意消息实现远程代码执行。

3. **路径遍历漏洞** - ONNX 模型的 external_data 字段和 protobuf ATTR_NAME_LOCATION 属性中的文件路径未进行遍历检查，攻击者可读取任意文件。

4. **通信安全缺失** - gRPC 分布式服务完全未加密（服务端和客户端均使用 InsecureCredentials），所有网络流量可被窃听/篡改。

5. **IDOR 资源越权** - GetClient 函数仅根据 client_id 查找客户端，不验证请求来源所有权，攻击者可操作其他客户端资源。

### 建议优先修复

| 优先级 | 漏洞ID | 问题 | 建议 |
|--------|--------|------|------|
| P0 | VULN-DF-DYN-001 | OM模型SO无签名加载 | 实现SO签名验证机制，拒绝未签名二进制 |
| P0 | dflow-pickle-deser-001 | cloudpickle反序列化RCE | 替换为安全序列化格式（JSON/MessagePack）或添加签名验证 |
| P1 | VULN-DF-PATH-001/002 | 路径遍历 | 添加路径规范化验证，禁止".."/绝对路径 |
| P1 | VULN-DFLOW-003/007 | gRPC无TLS | 强制TLS加密通信 |
| P2 | VULN-DFLOW-004 | IDOR | 添加资源所有权验证 |

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
| Critical | 4 | 57.1% |
| High | 3 | 42.9% |
| **有效漏洞总计** | **7** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-DYN-001]** untrusted_library_loading (Critical) - `base/common/helper/custom_op_so_loader.cc:136` @ `DlopenSoByFd` | 置信度: 90
2. **[VULN-DF-PATH-001]** path_traversal (Critical) - `parser/parser/onnx/onnx_parser.cc:813` @ `SetExternalPath` | 置信度: 85
3. **[VULN-DF-PATH-002]** path_traversal (Critical) - `graph_metadef/graph/serialization/model_serialize.cc:1174` @ `SetWeightForModel` | 置信度: 85
4. **[dflow-pickle-deser-001]** Insecure Deserialization (Critical) - `/home/pwn20tty/Desktop/opencode_project/cann/4/ge/dflow/pydflow/python/dataflow/utils/msg_type_register.py:81` @ `_deserialize_with_cloudpickle` | 置信度: 85
5. **[VULN-DFLOW-003]** Missing Transport Layer Protection (High) - `dflow/deployer/deploy/rpc/deployer_server.cc:63` @ `DeployerServer::Impl::Run` | 置信度: 85
6. **[VULN-DFLOW-004]** Missing Authorization (High) - `dflow/deployer/daemon/daemon_service.cc:178` @ `GetClient` | 置信度: 85
7. **[VULN-DFLOW-007]** Missing Transport Layer Protection (High) - `dflow/deployer/deploy/rpc/deployer_client.cc:46` @ `DeployerClient::Connect` | 置信度: 85

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

## 3. Critical 漏洞 (4)

### [VULN-DF-DYN-001] untrusted_library_loading - DlopenSoByFd

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-427 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `base/common/helper/custom_op_so_loader.cc:136-145` @ `DlopenSoByFd`
**模块**: base
**跨模块**: base → runtime

**描述**: Custom operator SO binary loaded from OM model file. The SO binary data comes from the model file (op_so_bin->GetBinData()), which could be crafted by an attacker. The binary is loaded via memfd_create and dlopen, which executes arbitrary code from the untrusted binary. No signature verification of the SO binary is performed.

**漏洞代码** (`base/common/helper/custom_op_so_loader.cc:136-145`)

```c
const std::string so_path = std::string(kProcFdPrefix) + std::to_string(mem_fd);
const int32_t open_flag = static_cast<int32_t>(static_cast<uint32_t>(MMPA_RTLD_NOW) | static_cast<uint32_t>(MMPA_RTLD_GLOBAL));
handle = mmDlopen(so_path.c_str(), open_flag);
```

**达成路径**

OpSoBinPtr->GetBinData() [SOURCE - from OM model file]
→ LoadCustomOpSoBins@base/common/helper/custom_op_so_loader.cc:147
→ WriteSoBinToFd@base/common/helper/custom_op_so_loader.cc:115
→ DlopenSoByFd@base/common/helper/custom_op_so_loader.cc:136 [SINK - arbitrary code execution]

**验证说明**: Arbitrary code execution via OM model file. Binary data from OpSoBinPtr->GetBinData() written to memfd and loaded via dlopen without signature verification. Critical vulnerability - attacker-controlled binary executes arbitrary code.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 5 | cross_file: 0

---

### [VULN-DF-PATH-001] path_traversal - SetExternalPath

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `parser/parser/onnx/onnx_parser.cc:813-816` @ `SetExternalPath`
**模块**: parser

**描述**: ONNX external weight file path concatenation without validation. The file_name from ONNX model's external_data field is directly concatenated with the model's directory to form a file path, without checking for path traversal sequences like '..' or absolute paths. An attacker-controlled ONNX model could specify external weight files outside the intended directory.

**漏洞代码** (`parser/parser/onnx/onnx_parser.cc:813-816`)

```c
const std::string &file_name = string_proto.value();
const std::string new_file = std::string(dir) + MMPA_PATH_SEPARATOR_STR + file_name;
string_proto.set_value(new_file);
```

**达成路径**

aclgrphParseONNX@parser/parser/onnx/onnx_parser.cc:111 [SOURCE]
→ Parse@parser/parser/onnx/onnx_parser.cc:1134
→ GetModelFromFile@parser/parser/onnx/onnx_parser.cc:765
→ SetExternalPath@parser/parser/onnx/onnx_parser.cc:783
→ initializer_tensor.external_data(j).value() [EXTERNAL DATA]
→ new_file path construction [SINK]

**验证说明**: Direct path traversal from ONNX model external_data field. file_name directly concatenated without validation for '..' or absolute paths. trust_level=untrusted_local confirms external model file input. No mitigations found.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-PATH-002] path_traversal - SetWeightForModel

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `graph_metadef/graph/serialization/model_serialize.cc:1174-1181` @ `SetWeightForModel`
**模块**: graph_metadef

**描述**: Model weight file path loaded from untrusted protobuf attribute. The file_path comes from ATTR_NAME_LOCATION attribute in the model protobuf, which could contain path traversal sequences. The weight file is loaded from this potentially untrusted path without proper validation against allowed directories.

**漏洞代码** (`graph_metadef/graph/serialization/model_serialize.cc:1174-1181`)

```c
const std::string file_path = iter->second.s();
...
if (!LoadWeightFromFile(file_path, length, weight)) {
  GELOGE(GRAPH_FAILED, "Load weight from path %s failed.", file_path.c_str());
```

**达成路径**

UnserializeModel@graph_metadef/graph/serialization/model_serialize.cc [SOURCE]
→ op_def_proto.attr() (ATTR_NAME_LOCATION) [EXTERNAL DATA]
→ SetWeightForModel@graph_metadef/graph/serialization/model_serialize.cc:1168
→ LoadWeightFromFile@graph_metadef/graph/serialization/model_serialize.cc:1138 [SINK]

**验证说明**: Model weight file path from protobuf ATTR_NAME_LOCATION attribute loaded without path traversal validation. Direct file read via LoadWeightFromFile. trust_level=untrusted_local confirms external model input.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [dflow-pickle-deser-001] Insecure Deserialization - _deserialize_with_cloudpickle

**严重性**: Critical（原评估: HIGH → 验证后: Critical） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/4/ge/dflow/pydflow/python/dataflow/utils/msg_type_register.py:81-84` @ `_deserialize_with_cloudpickle`
**模块**: dflow-python

**描述**: cloudpickle.loads() used for deserialization of untrusted data in distributed message handling. Pickle deserialization can execute arbitrary code when loading malicious serialized objects. In a distributed system context, this could allow remote code execution if an attacker can inject malicious messages into the dataflow.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/4/ge/dflow/pydflow/python/dataflow/utils/msg_type_register.py:81-84`)

```c
def _deserialize_with_cloudpickle(self, buffer):\n    import cloudpickle\n    return cloudpickle.loads(buffer)
```

**验证说明**: cloudpickle.loads() on untrusted buffer in distributed message handling. Pickle deserialization executes arbitrary code. No integrity/signature check. Critical remote code execution risk.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. High 漏洞 (3)

### [VULN-DFLOW-003] Missing Transport Layer Protection - DeployerServer::Impl::Run

**严重性**: High | **CWE**: CWE-319 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `dflow/deployer/deploy/rpc/deployer_server.cc:63` @ `DeployerServer::Impl::Run`
**模块**: dflow

**描述**: gRPC服务器使用 InsecureServerCredentials，通信完全不加密。所有网络流量可能被窃听或篡改，包括认证数据和敏感的部署请求。

**漏洞代码** (`dflow/deployer/deploy/rpc/deployer_server.cc:63`)

```c
server_builder.AddListeningPort(server_addr, grpc::InsecureServerCredentials());
```

**验证说明**: gRPC server uses InsecureServerCredentials() - no TLS encryption. All network traffic including authentication data can be intercepted. trust_level=untrusted_network confirms attack surface.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DFLOW-004] Missing Authorization - GetClient

**严重性**: High | **CWE**: CWE-862 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `dflow/deployer/daemon/daemon_service.cc:178-188` @ `GetClient`
**模块**: dflow

**描述**: GetClient函数只根据client_id查找客户端，不验证请求来源是否匹配。攻击者只要知道有效的client_id就可以操作其他客户端的资源（如部署请求、缓存操作等）。存在IDOR风险。

**漏洞代码** (`dflow/deployer/daemon/daemon_service.cc:178-188`)

```c
*client = client_manager_->GetClient(client_id); if (*client != nullptr) { return true; }
```

**验证说明**: IDOR vulnerability. GetClient(client_id) returns client without verifying request source matches client_id owner. Attacker with known client_id can operate other clients' resources. trust_level=untrusted_network confirms attack surface.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DFLOW-007] Missing Transport Layer Protection - DeployerClient::Connect

**严重性**: High | **CWE**: CWE-319 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `dflow/deployer/deploy/rpc/deployer_client.cc:46` @ `DeployerClient::Connect`
**模块**: dflow

**描述**: gRPC客户端使用 InsecureChannelCredentials，通信完全不加密。客户端到服务器的所有数据可能被窃听或篡改。

**漏洞代码** (`dflow/deployer/deploy/rpc/deployer_client.cc:46`)

```c
auto channel = grpc::CreateCustomChannel(address, grpc::InsecureChannelCredentials(), channel_arguments);
```

**验证说明**: gRPC client uses InsecureChannelCredentials() - no TLS encryption. Client-to-server traffic unencrypted. Data interception possible on network path.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| base | 1 | 0 | 0 | 0 | 1 |
| dflow | 0 | 3 | 0 | 0 | 3 |
| dflow-python | 1 | 0 | 0 | 0 | 1 |
| graph_metadef | 1 | 0 | 0 | 0 | 1 |
| parser | 1 | 0 | 0 | 0 | 1 |
| **合计** | **4** | **3** | **0** | **0** | **7** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-319 | 2 | 28.6% |
| CWE-22 | 2 | 28.6% |
| CWE-862 | 1 | 14.3% |
| CWE-502 | 1 | 14.3% |
| CWE-427 | 1 | 14.3% |
