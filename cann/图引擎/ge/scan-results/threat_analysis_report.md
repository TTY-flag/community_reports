# GE (Graph Engine) 威胁分析报告

> 扫描时间: 2026-04-22T10:00:00Z
> 项目路径: /home/pwn20tty/Desktop/opencode_project/cann/4/ge
> 项目类型: Library (AI推理框架组件)

## 1. 项目概述

GE (Graph Engine) 是华为 CANN (Compute Architecture for Neural Networks) 的图引擎，面向昇腾 AI 处理器的高性能图编译器和执行器。项目规模：

- **C/C++ 文件**: 5279 个 (约129003行代码)
- **Python 文件**: 201 个
- **主要模块**: compiler (2454文件), runtime (835文件), parser (143文件), dflow (449文件)

### 项目定位

GE 作为 AI 推理框架的核心组件，主要功能包括：
1. 模型格式解析（ONNX、TensorFlow PB、Caffe）
2. 图编译与优化
3. 模型执行（静态/动态执行器）
4. 分布式推理（dflow 模块）

## 2. 信任边界分析

| 边界 | 可信侧 | 不可信侧 | 风险等级 | 说明 |
|------|--------|----------|----------|------|
| Model File Input | Application logic | External model files | **Critical** | 用户提供的模型文件可能包含恶意构造的 protobuf 数据 |
| Model Memory Buffer | Application logic | User-provided buffers | **High** | 内存缓冲区可能包含恶意数据 |
| Distributed Network | Local GE daemon | Remote deployer nodes | **High** | RDMA/TCP 网络接口接收远程请求 |
| Plugin/Custom Op Loading | GE runtime | External SO files | **High** | 动态加载的 SO 文件可能包含恶意代码 |
| Python Binding | Python runtime | C++ implementation | **Medium** | 跨语言调用边界 |
| ACL API | User application | GE session/execution | **Medium** | 用户输入数据通过 API 传递 |

## 3. STRIDE 威胁建模

### 3.1 Spoofing (身份伪造)

| 威胁 | 位置 | 风险 | 说明 |
|------|------|------|------|
| 远程节点身份伪造 | dflow/deployer/daemon | High | Daemon 服务接收远程节点请求，存在身份验证绕过风险 |
| 签名数据验证绕过 | daemon_service.cc:63 | High | VerifySignData 使用 auth_lib_path，验证逻辑可能被绕过 |

**缓解措施**:
- VerifyIpaddr 检查 IP 地址白名单
- VerifySignData 使用外部认证库验证签名
- 建议：加强身份验证机制，使用更强的加密认证

### 3.2 Tampering (数据篡改)

| 威胁 | 位置 | 风险 | 说明 |
|------|------|------|------|
| 模型文件篡改 | parser/parser/onnx | **Critical** | ONNX/TensorFlow 模型文件可能被篡改 |
| protobuf 数据篡改 | ReadProtoFromBinaryFile | **Critical** | 解析过程中缺乏完整性校验 |
| 网络数据篡改 | dflow/deployer | High | RDMA/TCP 传输可能被篡改 |
| 外部权重文件篡改 | FileConstant 算子 | High | 外置权重文件路径可被用户控制 |

**缓解措施**:
- 建议：添加模型文件签名验证
- 建议：protobuf 解析后进行数据校验
- 建议：网络传输使用加密通道

### 3.3 Repudiation (抵赖)

| 威略 | 风险 | 说明 |
|------|------|------|
| 操作日志不完整 | Medium | 缺乏详细的审计日志记录模型加载/执行操作 |
| 分布式请求来源追踪 | Medium | Daemon 服务日志可能不足以追踪请求来源 |

**缓解措施**:
- 建议：增强日志记录，记录关键操作来源
- 建议：添加审计追踪机制

### 3.4 Information Disclosure (信息泄露)

| 威胁 | 位置 | 风险 | 说明 |
|------|------|------|------|
| 模型结构泄露 | parser 模块 | Medium | 解析错误信息可能泄露模型内部结构 |
| 内存数据泄露 | runtime 执行 | Medium | 执行过程中的内存可能泄露敏感数据 |
| 配置信息泄露 | base/common | Low | 错误信息可能包含路径等敏感信息 |

**缓解措施**:
- GE_LOG 使用分级日志
- 建议：敏感操作使用脱敏日志

### 3.5 Denial of Service (拒绝服务)

| 威胁 | 位置 | 风险 | 说明 |
|------|------|------|------|
| 恶意模型导致解析崩溃 | parser 模块 | **Critical** | 构造的 protobuf 数据可能导致解析崩溃 |
| 大文件耗尽内存 | ReadProtoFromBinaryFile | **Critical** | 大模型文件可能耗尽系统内存 |
| 无限循环图结构 | compiler 模块 | High | 恶意构造的图结构可能导致编译卡死 |
| 网络请求洪水 | dflow daemon | High | 大量网络请求可能耗尽 Daemon 资源 |

**缓解措施**:
- 建议：添加文件大小限制
- 建议：protobuf 解析添加递归深度限制
- 建议：网络请求添加速率限制

### 3.6 Elevation of Privilege (权限提升)

| 娱胁 | 位置 | 风险 | 说明 |
|------|------|------|------|
| 恶意 SO 加载 | custom_op_so_loader.cc | **Critical** | 动态加载的 SO 可执行任意代码 |
| TBE 插件加载 | tbe_plugin_loader.cc | **Critical** | 插件 SO 可能提升权限 |
| protobuf 反序列化漏洞 | model_serialize.cc | **Critical** | protobuf 反序列化可能导致代码执行 |
| 模型注入攻击 | parser 模块 | **Critical** | 恶意模型可能触发代码执行漏洞 |

**缓解措施**:
- 建议：SO 文件签名验证
- 建议：限制 SO 加载路径
- 建议：protobuf 解析使用安全限制

## 4. 关键攻击面详细分析

### 4.1 模型文件解析 (Critical)

**位置**: parser/parser/onnx/onnx_parser.cc, parser/parser/tensorflow/tensorflow_parser.cc

**攻击向量**:
1. **恶意 ONNX 文件**: 通过构造的 ONNX protobuf 数据触发解析漏洞
   - 入口: `aclgrphParseONNX` (line 111)
   - 数据流: `GetModelFromFile` → `ReadProtoFromBinaryFile` → protobuf 解析
   
2. **恶意 TensorFlow PB 文件**: 通过构造的 PB 数据触发漏洞
   - 入口: `aclgrphParseTensorFlow` (line 100)
   
3. **内存缓冲区攻击**: 通过内存中的恶意数据触发漏洞
   - 入口: `aclgrphParseONNXFromMem` (line 144), `ParseFromMemory`

**潜在漏洞类型**:
- CWE-20: 输入验证不当
- CWE-502: 反序列化不可信数据
- CWE-400: 未控制的资源消耗

### 4.2 分布式守护进程服务 (High)

**位置**: dflow/deployer/daemon/daemon_service.cc

**攻击向量**:
1. **网络请求伪造**: 通过构造的网络请求绕过认证
   - 入口: `DaemonService::Process` (line 31)
   - 数据流: `ProcessInitRequest` → `VerifyInitRequest` → `VerifySignData`
   
2. **IP 地址绕过**: `VerifyIpaddr` (line 47) 仅检查字符串匹配
   
3. **签名验证绕过**: `VerifySignData` 依赖外部认证库

**潜在漏洞类型**:
- CWE-287: 认证不当
- CWE-311: 缺少加密保护

### 4.3 动态 SO 加载 (Critical)

**位置**: base/common/helper/custom_op_so_loader.cc, parser/parser/common/tbe_plugin_loader.cc

**攻击向量**:
1. **恶意 SO 文件**: 通过构造的 SO 文件执行任意代码
   - 入口: `CustomOpSoLoader::LoadSo` (line 30)
   - Sink: `dlopen` 系统调用
   
2. **路径注入**: SO 文件路径可被用户控制

**潜在漏洞类型**:
- CWE-426: 不受信任的搜索路径
- CWE-114: 进程控制

### 4.4 模型序列化/反序列化 (Critical)

**位置**: graph_metadef/graph/serialization/model_serialize.cc

**攻击向量**:
1. **protobuf 反序列化漏洞**: 构造的 protobuf 数据可能触发漏洞
   - 入口: `ModelSerialize::UnserializeModel`
   - Sink: `ParseFromArray`, `ParseFromMemory`

**潜在漏洞类型**:
- CWE-502: 反序列化不可信数据

## 5. 数据流分析

### 5.1 ONNX 解析数据流

```
[用户输入] model_file path
    ↓
aclgrphParseONNX@onnx_parser.cc:111
    ↓
PrepareBeforeParse@onnx_parser.cc:58
    ↓
Parse@onnx_parser.cc:1134
    ↓
GetModelFromFile@onnx_parser.cc:765
    ↓
ReadProtoFromBinaryFile ← [危险Sink: 文件操作]
    ↓
ModelParseToGraph → [图结构传递]
```

### 5.2 分布式请求数据流

```
[远程节点] network request
    ↓
DaemonService::Process@daemon_service.cc:31
    ↓
ProcessInitRequest@daemon_service.cc:111
    ↓
VerifyInitRequest@daemon_service.cc:74
    ↓
VerifyIpaddr@daemon_service.cc:47 ← [IP白名单检查]
    ↓
VerifySignData@daemon_service.cc:63 ← [签名验证]
    ↓
CreateAndInitClient@daemon_client_manager.cc
```

### 5.3 SO 加载数据流

```
[用户输入] so_path
    ↓
CustomOpSoLoader::LoadSo@custom_op_so_loader.cc:30
    ↓
mmDlopen@base/common
    ↓
dlopen ← [危险Sink: 动态加载]
```

## 6. 高风险文件清单

| 文件 | 风险等级 | 漏洞类型 | 优先级 |
|------|----------|----------|--------|
| parser/parser/onnx/onnx_parser.cc | Critical | 文件解析、反序列化 | 1 |
| parser/parser/tensorflow/tensorflow_parser.cc | Critical | 文件解析、反序列化 | 1 |
| graph_metadef/graph/serialization/model_serialize.cc | Critical | 反序列化 | 1 |
| dflow/deployer/daemon/daemon_service.cc | High | 网络认证 | 2 |
| dflow/llm_datadist/v1/common/llm_flow_service.cc | High | 分布式通信 | 2 |
| api/acl/acl_model/model/acl_model.cpp | High | 模型加载 | 2 |
| base/common/helper/custom_op_so_loader.cc | High | 动态加载 | 3 |
| parser/parser/common/tbe_plugin_loader.cc | High | 动态加载 | 3 |
| api/session/session/session.cc | Medium | API边界 | 4 |
| api/python/ge/ge/_capi/*.py | Medium | 跨语言边界 | 4 |

## 7. 安全建议

### 7.1 紧急修复建议 (Critical)

1. **模型文件验证**: 在 `ReadProtoFromBinaryFile` 之前添加文件签名验证
2. **protobuf 解析限制**: 添加递归深度限制、内存限制、字段数量限制
3. **SO 加载验证**: 添加 SO 文件签名验证，限制加载路径
4. **输入大小限制**: 对模型文件和内存缓冲区添加大小上限

### 7.2 高优先级修复建议 (High)

1. **网络认证增强**: 使用更强的加密认证机制
2. **IP 白名单验证**: 改为精确匹配而非字符串搜索
3. **外部权重验证**: FileConstant 算子添加权重文件验证
4. **错误信息脱敏**: 避免在错误信息中泄露敏感路径

### 7.3 中优先级修复建议 (Medium)

1. **日志审计增强**: 记录关键操作来源
2. **API 输入验证**: Session API 添加输入验证
3. **Python 绑定安全**: 添加参数类型检查

## 8. 扫描范围排除

以下目录已被排除在本次扫描范围之外：
- `tests/` - 测试代码
- `Third_Party/` - 第三方库
- `examples/` - 示例代码（非生产代码）

## 9. 附录

### 9.1 相关 CWE 参考

- CWE-20: Improper Input Validation
- CWE-502: Deserialization of Untrusted Data
- CWE-400: Uncontrolled Resource Consumption
- CWE-287: Improper Authentication
- CWE-426: Untrusted Search Path
- CWE-114: Process Control

### 9.2 输出文件

本次扫描生成以下文件：
- `scan-results/.context/project_model.json` - 项目模型
- `scan-results/.context/call_graph.json` - 调用关系图
- `scan-results/.context/scan.db` - 漏洞数据库（SQLite）
- `scan-results/threat_analysis_report.md` - 本报告