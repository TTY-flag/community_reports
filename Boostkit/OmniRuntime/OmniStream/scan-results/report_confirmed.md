# 漏洞扫描报告 — 已确认漏洞

**项目**: OmniStream  
**扫描时间**: 2026-04-19T21:52:00+08:00  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

### 扫描概述

本次安全扫描针对 **OmniStream** 项目进行了全面的漏洞分析。OmniStream 是一个分布式流处理框架，作为 Apache Flink 的 C++ 本地执行引擎，通过 JNI 桥接 Java Flink Runtime 和 C++ Native TaskManager，处理来自 Kafka 等外部数据源的数据流。

扫描共发现 **30 个漏洞**，其中 **9 个已确认 (CONFIRMED)**，**12 个高疑似 (LIKELY)**，**3 个可能 (POSSIBLE)**，**6 个已排除为误报 (FALSE_POSITIVE)**。

### 关键发现

| 严重程度 | 数量 | 关键问题 |
|----------|------|----------|
| **Critical** | 3 | 远程代码执行、跨模块数据流漏洞 |
| **High** | 6 | JNI 异常安全缺失、内存泄漏、反序列化漏洞 |

#### 最严重漏洞（需立即修复）

1. **[VULN-DF-XMOD-002] Kafka 数据反序列化路径** (Critical, CWE-502)  
   - **攻击路径**: Kafka Broker → RdKafkaConsumer::poll → JsonRowDataDeserializationSchema::deserialize → nlohmann::json::parse  
   - **风险**: 来自不可信网络源的 Kafka 消息直接流向 JSON 反序列化，攻击者可发送恶意消息触发解析异常或注入恶意数据。

2. **[SEC-004] UDF 动态库加载代码执行** (Critical, CWE-94)  
   - **攻击路径**: Java TaskDeploymentDescriptor JSON → config["udf_so"] → UDFLoader::LoadMapFunction → dlopen  
   - **风险**: UDF 共享库路径来自配置 JSON，若 JobManager 或 TDD JSON 被篡改，可实现任意代码执行。

3. **[SEC-009] 配置注入导致代码执行** (Critical, CWE-15)  
   - **攻击路径**: Java JobManager → Operator Config → config["udf_so"] → dlopen  
   - **风险**: 与 SEC-004 同源，多个算子（StreamMap、StreamCalc 等）均从配置加载 UDF 库。

### 高危漏洞（需优先修复）

- **JNI 异常安全缺失**: 4 个 High 级别漏洞涉及 JSON 解析无 try-catch 保护，且 GetStringUTFChars 资源未正确释放，可能导致 JVM 崩溃和内存泄漏。
- **网络缓冲区长度未验证**: VULN-DF-NET-001 中 readInt() 从网络缓冲区读取 32 位整数作为记录长度，恶意远程 TaskManager 可发送超大值导致内存分配问题。

### 建议措施

| 优先级 | 建议措施 |
|--------|----------|
| **P0 (立即)** | 修复 SEC-004/SEC-009，在 dlopen 前验证 UDF 库路径白名单 |
| **P0 (立即)** | 修复 VULN-DF-XMOD-002，在 Kafka 消息反序列化前添加数据校验 |
| **P1 (本周)** | 修复所有 JNI 异常安全问题，采用 Copy+Release+Parse 模式 |
| **P1 (本周)** | 为网络缓冲区读取添加长度上限验证 |
| **P2 (本月)** | 建立统一的安全编码规范和 RAII 包装类 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 12 | 40.0% |
| CONFIRMED | 9 | 30.0% |
| FALSE_POSITIVE | 6 | 20.0% |
| POSSIBLE | 3 | 10.0% |
| **总计** | **30** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 3 | 33.3% |
| High | 6 | 66.7% |
| **有效漏洞总计** | **9** | - |
| 误报 (FALSE_POSITIVE) | 6 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-XMOD-002]** cross_module_data_flow_kafka_to_deserialization (Critical) - `cpp/connector/kafka/source/reader/RdKafkaConsumer.cpp:55` @ `Kafka_to_JSON_Deserialization` | 置信度: 85
2. **[SEC-004]** Arbitrary Code Execution (Critical) - `cpp/core/udf/UDFLoader.h:131` @ `LoadUDFFunction` | 置信度: 75
3. **[SEC-009]** Configuration Injection (Critical) - `cpp/streaming/api/operators/StreamMap.h:42` @ `StreamMap::loadUdf` | 置信度: 75
4. **[VULN-DF-JNI-001]** deserialization_exception_unsafe (High) - `cpp/jni/init.cpp:50` @ `Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration` | 置信度: 85
5. **[VULN-DF-JNI-002]** deserialization_exception_unsafe (High) - `cpp/jni/tasks/jni_OmniStreamTask.cpp:18` @ `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask` | 置信度: 85
6. **[VULN-DF-JNI-003]** deserialization_exception_unsafe (High) - `cpp/jni/tasks/jni_OmniStreamTask.cpp:42` @ `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeOmniInputProcessor` | 置信度: 85
7. **[SEC-001]** Memory Leak + Exception Safety (High) - `cpp/jni/init.cpp:52` @ `Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration` | 置信度: 85
8. **[SEC-002]** Exception Safety (High) - `cpp/jni/tasks/jni_OmniStreamTask.cpp:27` @ `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask` | 置信度: 85
9. **[VULN-DF-NET-001]** buffer_read_unvalidated_length (High) - `cpp/runtime/io/network/api/serialization/NonSpanningWrapper.h:131` @ `NonSpanningWrapper::readInt` | 置信度: 80

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `Java_com_huawei_omniruntime_flink_TNELLibrary_initialize@cpp/jni/init.cpp` | rpc | semi_trusted | JNI 初始化入口，由 Java Flink Runtime 调用，初始化共享内存 Metric Manager | JNI 初始化函数，设置共享内存监控 |
| `Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration@cpp/jni/init.cpp` | rpc | semi_trusted | JNI 配置入口，由 Java TaskManagerRunner 调用，接收 JSON 配置字符串 | 初始化 TaskManager 配置，解析 JSON 配置字符串 |
| `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask@cpp/jni/tasks/jni_OmniStreamTask.cpp` | rpc | semi_trusted | JNI 任务创建入口，由 Java 调用，接收 TDD JSON 字符串创建 C++ StreamTask | 创建原生 StreamTask 对象，解析任务部署描述符 JSON |
| `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeOmniInputProcessor@cpp/jni/tasks/jni_OmniStreamTask.cpp` | rpc | semi_trusted | JNI 输入处理器创建入口，接收通道信息 JSON | 创建 OmniInputProcessor，处理输入通道配置 |
| `OmniTaskBridgeImpl2::CallMaterializeMetaData@cpp/jni/bridge/OmniTaskBridgeImpl2.cpp` | rpc | semi_trusted | JNI 回调，将状态元数据序列化为 JSON 并上传到 Java 端 | 序列化状态元数据并调用 Java 方法 |
| `OmniTaskBridgeImpl2::readMetaData@cpp/jni/bridge/OmniTaskBridgeImpl2.cpp` | rpc | semi_trusted | JNI 回调，从 Java 端读取状态元数据并反序列化 | 读取状态元数据 JSON 并解析 |
| `OmniTaskBridgeImpl2::getKeyGroupEntries@cpp/jni/bridge/OmniTaskBridgeImpl2.cpp` | rpc | semi_trusted | JNI 回调，从 Java 端获取 KeyGroup 数据，处理字节数组数据 | 从 Java 流中读取 KeyGroup 数据 |
| `KafkaSource::createReader@cpp/connector/kafka/source/KafkaSource.cpp` | network | untrusted_network | Kafka 数据源入口，创建 KafkaSourceReader 从 Kafka Broker 读取数据 | 创建 Kafka Source Reader，配置反序列化 Schema |
| `RdKafkaConsumer::poll@cpp/connector/kafka/source/reader/RdKafkaConsumer.cpp` | network | untrusted_network | Kafka 数据接收入口，从 Kafka Broker 消费消息数据 | 从 Kafka 消费批量消息数据 |
| `SpillingAdaptiveSpanningRecordDeserializer::setNextBuffer@cpp/runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp` | network | untrusted_network | 网络数据反序列化入口，接收来自远程 TaskManager 的网络缓冲区数据 | 设置网络缓冲区并反序列化记录 |
| `SpillingAdaptiveSpanningRecordDeserializer::SetNextBuffer@cpp/runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp` | network | untrusted_network | 网络数据反序列化入口（V2），接收 ReadOnlySlicedNetworkBuffer | 设置网络缓冲区并反序列化记录（V2 版本） |
| `StreamTaskNetworkInput::processInput@cpp/streaming/runtime/io/StreamTaskNetworkInput.cpp` | network | untrusted_network | 流处理网络输入入口，处理来自远程 TaskManager 的数据 | 处理网络输入数据 |
| `JsonRowDataDeserializationSchema::deserialize@cpp/core/api/common/serialization/JsonRowDataDeserializationSchema.cpp` | network | untrusted_network | JSON 反序列化入口，解析来自 Kafka 或网络的数据 | 反序列化 JSON 数据为 RowData |
| `MemorySegment::put@cpp/core/memory/MemorySegment.cpp` | internal | internal | 内存写入操作，接收外部数据写入堆外内存 | 向内存段写入数据 |
| `MemorySegment::get@cpp/core/memory/MemorySegment.cpp` | internal | internal | 内存读取操作，从堆外内存读取数据 | 从内存段读取数据 |
| `RocksDBStateDownloader::download@cpp/runtime/state/rocksdb/RocksDBStateDownloader.cpp` | file | semi_trusted | 状态恢复入口，从外部存储下载 RocksDB 状态快照 | 从外部存储下载状态数据 |
| `RocksDBStateUploader::upload@cpp/runtime/state/rocksdb/RocksDBStateUploader.cpp` | file | semi_trusted | 状态快照入口，将 RocksDB 状态上传到外部存储 | 上传状态数据到外部存储 |

**其他攻击面**:
- JNI Interface: Java Flink Runtime ↔ C++ TaskManager 数据传递边界
- Kafka Consumer: 从 Kafka Broker 接收消息数据
- Netty Shuffle Network: TaskManager 间数据交换（远程网络连接）
- State Snapshot Storage: 从/向外部分布式存储读写状态快照
- Checkpoint Storage: 从/向外部存储读写 Checkpoint 数据
- JSON Deserialization: 解析来自网络/Kafka 的 JSON 数据
- Memory Segment Operations: 堆外内存读写操作

---

## 3. Critical 漏洞 (3)

### [VULN-DF-XMOD-002] cross_module_data_flow_kafka_to_deserialization - Kafka_to_JSON_Deserialization

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `cpp/connector/kafka/source/reader/RdKafkaConsumer.cpp:55-62` @ `Kafka_to_JSON_Deserialization`
**模块**: cross_module
**跨模块**: connector_kafka → core_serialization

**描述**: Cross-module data flow: Kafka messages → Deserialization → JSON parsing. Kafka message data from untrusted network source flows through multiple modules and eventually to JSON deserialization.

**漏洞代码** (`cpp/connector/kafka/source/reader/RdKafkaConsumer.cpp:55-62`)

```c
// See call_graph.json data_flows entry for Kafka data flow
ConsumerRecords* RdKafkaConsumer::poll(int timeoutMs) → KafkaRecordEmitter::emitRecord → JsonRowDataDeserializationSchema::deserialize → nlohmann::json::parse
```

**达成路径**

Kafka Broker (RdKafkaConsumer.cpp:55-62) [SOURCE untrusted_network] → KafkaPartitionSplitReader → KafkaSourceReader → KafkaRecordEmitter → JsonRowDataDeserializationSchema → nlohmann::json::parse [SINK]
This is a complete attack path from untrusted network input to JSON deserialization.

**验证说明**: Kafka Broker -> RdKafkaConsumer::poll -> JsonRowDataDeserializationSchema::deserialize -> json::parse. Complete attack path from untrusted Kafka.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-004] Arbitrary Code Execution - LoadUDFFunction

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `cpp/core/udf/UDFLoader.h:131-137` @ `LoadUDFFunction`
**模块**: core_udf
**跨模块**: jni → streaming_runtime_tasks → core_udf

**描述**: UDFLoader uses dlopen() to load shared libraries based on file path parameters that can be derived from JSON configuration. If an attacker can inject malicious UDF library paths into the task deployment descriptor JSON, arbitrary code execution is possible. The filePath parameter comes from config["udf_so"] which is parsed from operator descriptions received from Java JobManager.

**漏洞代码** (`cpp/core/udf/UDFLoader.h:131-137`)

```c
void* handle = dlopen(filePath.c_str(), RTLD_LAZY);
FuncType *funcPointer = (FuncType *)dlsym(handle, funcSignature.c_str());
```

**达成路径**

Java TaskDeploymentDescriptor JSON → operator["udf_so"] → UDFLoader.LoadMapFunction(filePath) → dlopen → arbitrary code execution

**验证说明**: CRITICAL: dlopen(filePath) at line 131 loads shared library from config['udf_so']. If TDD JSON is compromised, arbitrary code execution possible.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-009] Configuration Injection - StreamMap::loadUdf

**严重性**: Critical | **CWE**: CWE-15 | **置信度**: 75/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `cpp/streaming/api/operators/StreamMap.h:42-45` @ `StreamMap::loadUdf`
**模块**: streaming_runtime_tasks
**跨模块**: jni → streaming_runtime_tasks → core_udf

**描述**: Operator configurations are parsed from JSON descriptions that come from Java JobManager. Multiple operators (StreamCalc, KeyedProcessOperator, etc.) load UDF shared libraries based on config["udf_so"] paths. If JobManager is compromised or configuration is manipulated, malicious library paths could be injected.

**漏洞代码** (`cpp/streaming/api/operators/StreamMap.h:42-45`)

```c
std::string soPath = config["udf_so"]; std::string udfObj = config["udf_obj"];
```

**达成路径**

Java JobManager → TaskDeploymentDescriptor JSON → Operator Config → config["udf_so"] → dlopen

**验证说明**: StreamMap::loadUdf at lines 44-49 uses config['udf_so'] for dlopen. Part of SEC-004 attack chain.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. High 漏洞 (6)

### [VULN-DF-JNI-001] deserialization_exception_unsafe - Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration

**严重性**: High | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `cpp/jni/init.cpp:50-55` @ `Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration`
**模块**: jni

**描述**: JSON parsing from JNI input without exception safety. GetStringUTFChars returns Java string data which is passed to nlohmann::json::parse. If parse() throws an exception, ReleaseStringUTFChars is never called causing memory leak. Malformed JSON from Java side could cause parsing exceptions.

**漏洞代码** (`cpp/jni/init.cpp:50-55`)

```c
const char *cStrCon = (env)->GetStringUTFChars(configStr, 0);
nlohmann::json config = nlohmann::json::parse(cStrCon);
Configuration::TM_CONFIG->setConfiguration(config);
```

**达成路径**

Java jstring configStr → GetStringUTFChars → const char* cStrCon → nlohmann::json::parse → Configuration object
[SOURCE] Line 52: GetStringUTFChars (JNI input)
[SINK] Line 53: json::parse (deserialization)

**验证说明**: Code confirmed: GetStringUTFChars at line 52 without ReleaseStringUTFChars, json::parse at line 53 without try-catch. If parse throws, memory leaks and JVM crashes.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-JNI-002] deserialization_exception_unsafe - Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask

**严重性**: High | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `cpp/jni/tasks/jni_OmniStreamTask.cpp:18-40` @ `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask`
**模块**: jni
**跨模块**: jni → streaming_runtime_tasks

**描述**: JSON parsing from JNI input without exception safety. TDD (Task Deployment Descriptor) JSON string from Java is parsed without proper exception handling. If json::parse throws, ReleaseStringUTFChars is skipped.

**漏洞代码** (`cpp/jni/tasks/jni_OmniStreamTask.cpp:18-40`)

```c
const char *cStrTDD = (env)->GetStringUTFChars(TDDString, 0);
nlohmann::json tdd = nlohmann::json::parse(cStrTDD);
auto *streamTask = new omnistream::datastream::StreamTask(tdd, bufferStatus, task->getRuntimeEnv());
```

**达成路径**

Java jstring TDDString → GetStringUTFChars → const char* cStrTDD → nlohmann::json::parse → StreamTask constructor
[SOURCE] Line 21: GetStringUTFChars (JNI input)
[SINK] Line 27: json::parse (deserialization)

**验证说明**: Code confirmed: GetStringUTFChars at line 21, json::parse at line 27, ReleaseStringUTFChars at line 37. If parse throws exception before line 37, memory leak occurs.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-JNI-003] deserialization_exception_unsafe - Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeOmniInputProcessor

**严重性**: High | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `cpp/jni/tasks/jni_OmniStreamTask.cpp:42-57` @ `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeOmniInputProcessor`
**模块**: jni
**跨模块**: jni → streaming_runtime_io

**描述**: JSON parsing from JNI input without exception safety. Channel info JSON string from Java is parsed without proper exception handling.

**漏洞代码** (`cpp/jni/tasks/jni_OmniStreamTask.cpp:42-57`)

```c
const char *channelInfos = (env)->GetStringUTFChars(inputChannelInfo, 0);
nlohmann::json channelJson = nlohmann::json::parse(channelInfos);
```

**达成路径**

Java jstring inputChannelInfo → GetStringUTFChars → const char* channelInfos → nlohmann::json::parse → channelJson
[SOURCE] Line 45: GetStringUTFChars (JNI input)
[SINK] Line 49: json::parse (deserialization)

**验证说明**: Code confirmed: GetStringUTFChars at line 45, json::parse at line 49, ReleaseStringUTFChars at line 50. If parse throws, ReleaseStringUTFChars skipped causing memory leak.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-001] Memory Leak + Exception Safety - Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration

**严重性**: High | **CWE**: CWE-401 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `cpp/jni/init.cpp:52-54` @ `Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration`
**模块**: jni

**描述**: JNI function initTMConfiguration fails to release GetStringUTFChars and lacks exception handling for JSON parsing. The const char* pointer obtained from GetStringUTFChars is never released with ReleaseStringUTFChars, causing memory leak. Additionally, nlohmann::json::parse() is called without try-catch block, which could crash the JVM if malformed JSON is passed from Java side.

**漏洞代码** (`cpp/jni/init.cpp:52-54`)

```c
const char *cStrCon = (env)->GetStringUTFChars(configStr, 0);
nlohmann::json config = nlohmann::json::parse(cStrCon);
Configuration::TM_CONFIG->setConfiguration(config);
```

**达成路径**

Java JString → GetStringUTFChars → JSON Parse → Configuration

**验证说明**: Duplicate of VULN-DF-JNI-001. Code confirmed: line 52 GetStringUTFChars without release, line 53 json::parse without exception handling.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-002] Exception Safety - Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask

**严重性**: High | **CWE**: CWE-755 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `cpp/jni/tasks/jni_OmniStreamTask.cpp:27-29` @ `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask`
**模块**: jni

**描述**: JNI function createNativeStreamTask calls nlohmann::json::parse() without exception handling. If malformed TDD JSON string is passed from Java, the parse exception will propagate and crash the native code, potentially causing JVM instability.

**漏洞代码** (`cpp/jni/tasks/jni_OmniStreamTask.cpp:27-29`)

```c
nlohmann::json tdd = nlohmann::json::parse(cStrTDD);
LOG("Calling  StreamTask with json " + tdd.dump(2))
```

**达成路径**

Java TDDString → GetStringUTFChars → JSON Parse → StreamTask Creation

**验证说明**: Duplicate of VULN-DF-JNI-002. Code confirmed: line 27 json::parse without try-catch, exception propagation to JVM.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-NET-001] buffer_read_unvalidated_length - NonSpanningWrapper::readInt

**严重性**: High | **CWE**: CWE-190 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `cpp/runtime/io/network/api/serialization/NonSpanningWrapper.h:131-147` @ `NonSpanningWrapper::readInt`
**模块**: runtime_io_network

**描述**: Record length read from network buffer without upper bound validation. readInt() reads a 32-bit integer from network buffer representing record length. This value could be manipulated by malicious remote TaskManager to cause integer overflow or excessive memory allocation.

**漏洞代码** (`cpp/runtime/io/network/api/serialization/NonSpanningWrapper.h:131-147`)

```c
uint32_t value = (static_cast<uint32_t>(data_[position_]) << 24) |
                 (static_cast<uint32_t>(data_[position_ + 1]) << 16) |
                 (static_cast<uint32_t>(data_[position_ + 2]) << 8) |
                 static_cast<uint32_t>(data_[position_ + 3]);
position_ += sizeof(uint32_t);
return static_cast<int>(value);
```

**达成路径**

Remote TaskManager network buffer → data_ pointer → readInt() → int recordLen → canReadRecord(recordLen) → SpanningWrapper buffer expansion
[SOURCE] Network buffer from remote TaskManager (untrusted_network)
[SINK] recordLength used in SpanningWrapper::ensureBufferCapacity

**验证说明**: readInt() reads 32-bit int from network buffer. No upper bound validation - malicious remote TaskManager could send extremely large recordLength.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| core_udf | 1 | 0 | 0 | 0 | 1 |
| cross_module | 1 | 0 | 0 | 0 | 1 |
| jni | 0 | 5 | 0 | 0 | 5 |
| runtime_io_network | 0 | 1 | 0 | 0 | 1 |
| streaming_runtime_tasks | 1 | 0 | 0 | 0 | 1 |
| **合计** | **3** | **6** | **0** | **0** | **9** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-502 | 4 | 44.4% |
| CWE-94 | 1 | 11.1% |
| CWE-755 | 1 | 11.1% |
| CWE-401 | 1 | 11.1% |
| CWE-190 | 1 | 11.1% |
| CWE-15 | 1 | 11.1% |

---

## 7. Top 5 关键漏洞深度分析

### 7.1 [VULN-DF-XMOD-002] Kafka → JSON 反序列化跨模块漏洞

#### 漏洞定位

**源文件**: `cpp/connector/kafka/source/reader/RdKafkaConsumer.cpp`  
**关键函数**: `RdKafkaConsumer::poll()` (第 55-62 行)

```cpp
ConsumerRecords* RdKafkaConsumer::poll(int timeoutMs)
{
    std::unordered_map<RdKafka::TopicPartition *, std::vector<RdKafka::Message *>> records =
        consumer_->consumeBatch(timeoutMs, batch_size_);
    ConsumerRecords* consumerRecords = new ConsumerRecords(std::move(records));
    return consumerRecords;
}
```

#### 数据流追踪

完整攻击路径：
```
Kafka Broker (外部不可信网络源)
    │
    ▼ RdKafkaConsumer::poll() — 获取消息批次
    │
    ▼ KafkaPartitionSplitReader — 分区读取
    │
    ▼ KafkaSourceReader — 源读取器
    │
    ▼ KafkaRecordEmitter::emitRecord() — 发射记录
    │
    ▼ DeserializationSchema::deserialize() — 反序列化入口
    │
    ▼ JsonRowDataDeserializationSchema::deserialize()
    │
    ▼ nlohmann::json::parse() — JSON 解析 [SINK]
```

#### 安全风险

1. **外部数据源**: Kafka Broker 位于不可信网络边界，消息数据可被攻击者控制
2. **无数据校验**: 消息直接传递给反序列化器，未进行格式或大小验证
3. **异常传播**: JSON 解析异常可能跨模块传播，影响流处理任务稳定性
4. **内存问题**: 恶意消息可能触发内存耗尽或解析异常导致任务失败

#### 影响范围

- **模块**: connector_kafka → core_serialization
- **组件**: RdKafkaConsumer, KafkaSourceReader, JsonRowDataDeserializationSchema
- **信任边界**: Network Interface (Kafka) — Critical Risk

---

### 7.2 [SEC-004] UDF 动态库加载代码执行漏洞

#### 漏洞定位

**源文件**: `cpp/core/udf/UDFLoader.h`  
**关键函数**: `LoadUDFFunction()` 模板函数 (第 129-157 行)

```cpp
template<typename FuncType>
FuncType* LoadUDFFunction(const std::string &filePath, const std::string &funcSignature)
{
    void* handle = dlopen(filePath.c_str(), RTLD_LAZY);  // 直接加载外部库
    if (not handle) {
        std::cerr << "Error loading library: " << dlerror() << std::endl;
        return nullptr;
    }
    FuncType *funcPointer = (FuncType *)dlsym(handle, funcSignature.c_str());
    // ...
    return funcPointer;
}
```

#### 数据流追踪

```
Java JobManager
    │
    ▼ TaskDeploymentDescriptor JSON
    │
    ▼ operator["udf_so"] 配置项
    │
    ▼ StreamMap::loadUdf() / StreamCalc::loadUdf() 等
    │
    ▼ config["udf_so"] 字符串提取
    │
    ▼ UDFLoader::LoadMapFunction(filePath)
    │
    ▼ dlopen(filePath.c_str(), RTLD_LAZY) [SINK - 代码执行]
```

#### 安全风险

1. **路径可控**: `filePath` 来自 JSON 配置 `config["udf_so"]`
2. **无路径验证**: dlopen 直接加载，无白名单或路径校验
3. **任意代码执行**: 恶意 .so 库可在 TaskManager 进程中执行任意代码
4. **权限继承**: 加载的库继承 TaskManager 进程权限

#### 影响范围

- **模块**: jni → streaming_runtime_tasks → core_udf
- **攻击面**: JNI Interface — Critical Risk
- **前置条件**: JobManager 被入侵 或 TDD JSON 在传输中被篡改

---

### 7.3 [SEC-009] 配置注入漏洞

#### 漏洞定位

**源文件**: `cpp/streaming/api/operators/StreamMap.h`  
**关键函数**: `StreamMap::loadUdf()` (第 42-55 行)

```cpp
void loadUdf(const nlohmann::json &config)
{
    std::string soPath = config["udf_so"];       // 直接从配置提取路径
    std::string udfObj = config["udf_obj"];
    nlohmann::json udfObjJson = nlohmann::json::parse(udfObj);
    
    auto *symbol = udfLoader.LoadMapFunction(soPath);  // 调用 dlopen
    if (symbol == nullptr) {
        throw std::out_of_range("null pointer when load " + soPath);
    }
    function = symbol(udfObjJson);
    this->userFunction = function.release();
}
```

#### 安全风险

此漏洞与 SEC-004 共享同一攻击链，但发生在算子层面：
- 多个算子 (StreamMap, StreamCalc, KeyedProcessOperator 等) 均使用相同模式
- 配置 JSON 来自 Java JobManager 的 TaskDeploymentDescriptor
- 若 TDD JSON 被篡改，所有算子均可能加载恶意库

---

### 7.4 [VULN-DF-JNI-001/002/003] JNI 异常安全缺失

#### 漏洞定位

**源文件**: 
- `cpp/jni/init.cpp` (VULN-DF-JNI-001)
- `cpp/jni/tasks/jni_OmniStreamTask.cpp` (VULN-DF-JNI-002/003)

#### 漏洞模式分析

**错误模式** (jni/init.cpp):
```cpp
const char *cStrCon = (env)->GetStringUTFChars(configStr, 0);  // 分配 JNI 资源
nlohmann::json config = nlohmann::json::parse(cStrCon);         // 可抛出异常
Configuration::TM_CONFIG->setConfiguration(config);
// 缺少: env->ReleaseStringUTFChars(configStr, cStrCon);
```

**错误模式** (jni_OmniStreamTask.cpp):
```cpp
const char *cStrTDD = (env)->GetStringUTFChars(TDDString, 0);
nlohmann::json tdd = nlohmann::json::parse(cStrTDD);  // 若抛出异常
// ...
env->ReleaseStringUTFChars(TDDString, cStrTDD);  // 此行不会执行
```

#### 安全风险

1. **内存泄漏**: GetStringUTFChars 分配的内存永不释放
2. **JVM 崩溃**: C++ 异常跨 JNI 边界导致未定义行为
3. **资源耗尽**: 重复调用可耗尽 JVM 堆内存
4. **任务失败**: 流任务初始化失败导致集群不稳定

#### 正确模式对比

**正确实现** (jni_OmniTaskExecutor.cpp):
```cpp
const char* jobString = jniEnv->GetStringUTFChars(jobjson, nullptr);
std::string jobInfoString(jobString);  // 复制到安全内存
jniEnv->ReleaseStringUTFChars(jobjson, jobString);  // 立即释放
nlohmann::json job = nlohmann::json::parse(jobInfoString);  // 解析安全副本
```

---

### 7.5 [VULN-DF-NET-001] 网络缓冲区长度未验证

#### 漏洞定位

**源文件**: `cpp/runtime/io/network/api/serialization/NonSpanningWrapper.h`  
**关键函数**: `NonSpanningWrapper::readInt()` (第 131-147 行)

```cpp
inline int NonSpanningWrapper::readInt()
{
    if (unlikely(position_ + sizeof(uint32_t) > length_)) {
        THROW_LOGIC_EXCEPTION("EOFException");
    }
    uint32_t value = (static_cast<uint32_t>(data_[position_]) << 24) |
                     (static_cast<uint32_t>(data_[position_ + 1]) << 16) |
                     (static_cast<uint32_t>(data_[position_ + 2]) << 8) |
                     static_cast<uint32_t>(data_[position_ + 3]);
    position_ += sizeof(uint32_t);
    return static_cast<int>(value);  // 返回 32 位整数作为记录长度
}
```

#### 数据流追踪

```
远程 TaskManager (Netty Shuffle Network)
    │
    ▼ NetworkBuffer 数据包
    │
    ▼ SpillingAdaptiveSpanningRecordDeserializer::setNextBuffer()
    │
    ▼ NonSpanningWrapper::initializeFromMemoryBuffer()
    │
    ▼ NonSpanningWrapper::readInt() — 读取记录长度
    │
    ▼ SpanningWrapper::ensureBufferCapacity(recordLength) [SINK]
    │
    ▼ buffer_.reserve(newCapacity) — 内存分配
```

#### 安全风险

1. **长度可控**: 记录长度来自远程 TaskManager 网络数据
2. **无上限验证**: 32 位整数可达 2^31-1，无最大值限制
3. **内存耗尽**: 恶意远程 TaskManager 可发送超大长度值
4. **整数溢出**: 在后续计算中可能触发整数溢出

---

## 8. 修复建议

### 8.1 P0 优先级（立即修复）

#### 修复 SEC-004/SEC-009: UDF 库路径验证

```cpp
// 在 UDFLoader.h 中添加路径白名单验证
class UDFLoader {
private:
    static const std::vector<std::string> ALLOWED_UDF_PATHS = {
        "/opt/omnistream/udf/",
        "/usr/local/lib/omnistream/"
    };
    
    bool isPathAllowed(const std::string& filePath) {
        // 解析真实路径防止符号链接攻击
        char resolved[PATH_MAX];
        if (realpath(filePath.c_str(), resolved) == nullptr) {
            return false;
        }
        for (const auto& allowed : ALLOWED_UDF_PATHS) {
            if (strncmp(resolved, allowed.c_str(), allowed.length()) == 0) {
                return true;
            }
        }
        return false;
    }
    
    template<typename FuncType>
    FuncType* LoadUDFFunction(const std::string &filePath, const std::string &funcSignature)
    {
        if (!isPathAllowed(filePath)) {
            std::cerr << "SECURITY: UDF path not in whitelist: " << filePath << std::endl;
            return nullptr;
        }
        void* handle = dlopen(filePath.c_str(), RTLD_LAZY);
        // ... 原有逻辑
    }
};
```

#### 修复 VULN-DF-XMOD-002: Kafka 消息校验

```cpp
// 在 KafkaRecordEmitter::emitRecord 中添加数据校验
void KafkaRecordEmitter::emitRecord(ConsumerRecord* record, SourceOutputWrapper* output) {
    // 添加消息大小限制
    const size_t MAX_MESSAGE_SIZE = 10 * 1024 * 1024;  // 10MB
    if (record->value().size() > MAX_MESSAGE_SIZE) {
        LOG_WARN("Kafka message exceeds size limit: " << record->value().size());
        return;  // 跳过超大消息
    }
    
    // 添加 JSON 格式预校验（可选）
    if (requiresJsonValidation) {
        // 快速检查 JSON 结构
        const auto& data = record->value();
        if (data.empty() || data[0] != '{') {
            LOG_WARN("Invalid JSON format in Kafka message");
            return;
        }
    }
    
    try {
        deserializationSchema->deserialize(record, output);
    } catch (const nlohmann::json::parse_error& e) {
        LOG_ERROR("JSON parse error in Kafka message: " << e.what());
        // 可选：将错误消息发送到侧输出流
    }
}
```

---

### 8.2 P1 优先级（本周修复）

#### 修复 JNI 异常安全问题

**方案 A: Copy + Release + Parse 模式**

```cpp
// 通用修复模板
JNIEXPORT void JNICALL Java_..._initTMConfiguration(JNIEnv *env, jclass, jstring configStr)
{
    // 1. 获取并复制
    const char *cStrCon = env->GetStringUTFChars(configStr, nullptr);
    if (cStrCon == nullptr) {
        return;  // JVM 已抛出 OutOfMemoryError
    }
    std::string configCopy(cStrCon);
    
    // 2. 立即释放 (在 parse 之前)
    env->ReleaseStringUTFChars(configStr, cStrCon);
    
    // 3. 解析安全副本，添加异常处理
    try {
        nlohmann::json config = nlohmann::json::parse(configCopy);
        Configuration::TM_CONFIG->setConfiguration(config);
    } catch (const nlohmann::json::parse_error& e) {
        env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"),
                      ("Invalid JSON: " + std::string(e.what())).c_str());
    } catch (const std::exception& e) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), e.what());
    }
}
```

**方案 B: RAII 包装类 (推荐)**

```cpp
// 创建 cpp/jni/utils/JniStringHolder.h
class JniStringHolder {
public:
    JniStringHolder(JNIEnv* env, jstring jstr) 
        : env_(env), jstr_(jstr), cstr_(nullptr) {
        if (jstr != nullptr) {
            cstr_ = env->GetStringUTFChars(jstr, nullptr);
        }
    }
    
    ~JniStringHolder() {
        if (cstr_ != nullptr && jstr_ != nullptr) {
            env_->ReleaseStringUTFChars(jstr_, cstr_);
        }
    }
    
    std::string str() const { return cstr_ ? std::string(cstr_) : ""; }
    bool valid() const { return cstr_ != nullptr; }
    
    // 禁止拷贝和移动
    JniStringHolder(const JniStringHolder&) = delete;
    JniStringHolder& operator=(const JniStringHolder&) = delete;

private:
    JNIEnv* env_;
    jstring jstr_;
    const char* cstr_;
};
```

#### 修复网络缓冲区长度验证

```cpp
// 在 NonSpanningWrapper.h 中添加上限验证
inline int NonSpanningWrapper::readInt()
{
    if (unlikely(position_ + sizeof(uint32_t) > length_)) {
        THROW_LOGIC_EXCEPTION("EOFException");
    }
    uint32_t value = ...;  // 原有读取逻辑
    
    // 新增: 验证长度上限
    const int32_t MAX_RECORD_LENGTH = 100 * 1024 * 1024;  // 100MB
    int32_t intValue = static_cast<int>(value);
    if (intValue < 0 || intValue > MAX_RECORD_LENGTH) {
        THROW_LOGIC_EXCEPTION("Invalid record length: " + std::to_string(intValue));
    }
    
    position_ += sizeof(uint32_t);
    return intValue;
}
```

---

### 8.3 P2 优先级（本月完成）

1. **建立安全编码规范**
   - 强制使用 RAII 包装类管理 JNI 资源
   - 所有外部数据解析必须包含 try-catch
   - 所有网络数据必须进行长度/格式验证

2. **代码审计清单**
   - 扫描所有 dlopen 调用点，验证路径来源
   - 扫描所有 GetStringUTFChars 调用点，验证释放逻辑
   - 扫描所有 json::parse 调用点，验证异常处理

3. **安全测试**
   - 添加 JNI 接口模糊测试
   - 添加 Kafka 消息格式测试用例
   - 添加 UDF 路径注入测试用例

---

## 9. 参考链接

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [JNI Specification - Exception Handling](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/design.html)
- [nlohmann::json Documentation](https://json.nlohmann.me/)

---

**报告生成时间**: 2026-04-19  
**扫描工具**: OpenCode Multi-Agent Vulnerability Scanner  
**深度分析报告**: 见 `{SCAN_OUTPUT}/details/` 目录
