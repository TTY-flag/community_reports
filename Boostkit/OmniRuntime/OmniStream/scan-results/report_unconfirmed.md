# 漏洞扫描报告 — 待确认漏洞

**项目**: OmniStream  
**扫描时间**: 2026-04-19T21:52:00+08:00  
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

### 扫描概述

本报告包含扫描发现的 **15 个待确认漏洞**（LIKELY: 12 个，POSSIBLE: 3 个）。这些漏洞需要进一步人工验证以确认其可利用性和实际风险等级。

### 关键发现

| 严重程度 | 数量 | 主要类型 |
|----------|------|----------|
| **High** | 5 | JSON 解析异常安全、反序列化风险 |
| **Medium** | 8 | 内存分配控制、环境变量注入 |
| **Low** | 2 | 整数溢出潜在风险 |

### 重点关注漏洞

1. **[VULN-DF-JNI-006/007] JNI TaskExecutor JSON 解析**  
   - 与已确认漏洞 VULN-DF-JNI-001-003 同类模式
   - 需验证：异常处理和内存释放是否完善

2. **[SEC-007] Kafka 消息反序列化**  
   - 与 VULN-DF-XMOD-002 相关
   - 需验证：KafkaRecordEmitter 的异常处理是否足够

3. **[SEC-003] OMNI_HOME 环境变量注入**  
   - 潜在路径注入风险
   - 需验证：环境变量控制是否可被攻击者利用

### 建议措施

- **验证优先级**: 先验证 High 级别漏洞，确认与已确认漏洞的关系
- **联动修复**: 与已确认报告中的同类漏洞一并修复
- **人工审计**: 对配置加载和环境变量使用进行安全审计

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
| High | 5 | 33.3% |
| Medium | 8 | 53.3% |
| Low | 2 | 13.3% |
| **有效漏洞总计** | **15** | - |
| 误报 (FALSE_POSITIVE) | 6 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-JNI-006]** json_parse_exception_unsafe (High) - `cpp/jni/taskexecutor/jni_OmniTaskExecutor.cpp:47` @ `Java_com_huawei_omniruntime_flink_runtime_taskexecutor_OmniTaskExecutor_submitTaskNative` | 置信度: 75
2. **[VULN-DF-JNI-007]** json_parse_exception_unsafe (High) - `cpp/jni/taskexecutor/jni_OmniTaskExecutor.cpp:85` @ `Java_com_huawei_omniruntime_flink_runtime_taskexecutor_OmniTaskExecutor_submitTaskNativeWithCheckpointing` | 置信度: 75
3. **[SEC-007]** Deserialization Safety (High) - `cpp/connector/kafka/source/reader/KafkaRecordEmitter.cpp:33` @ `KafkaRecordEmitter::emitRecord` | 置信度: 75
4. **[SEC-006]** Deserialization Safety (High) - `cpp/runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp:68` @ `SpillingAdaptiveSpanningRecordDeserializer::setNextBuffer` | 置信度: 70
5. **[VULN-DF-XMOD-001]** cross_module_data_flow_jni_to_network (High) - `cpp/jni/tasks/jni_OmniStreamTask.cpp:18` @ `JNI_to_StreamTask_NetworkInput` | 置信度: 65
6. **[VULN-DF-NET-002]** memory_allocation_external_control (Medium) - `cpp/runtime/io/network/api/serialization/SpanningWrapper.h:186` @ `SpanningWrapper::ensureBufferCapacity` | 置信度: 70
7. **[VULN-DF-JNI-004]** deserialization_exception_unsafe (Medium) - `cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:518` @ `convertResult` | 置信度: 65
8. **[VULN-DF-OPS-001]** json_parse_from_config (Medium) - `cpp/streaming/runtime/tasks/OperatorChain.cpp:214` @ `OperatorChainV2::getChainOutputType` | 置信度: 65
9. **[VULN-DF-OPS-002]** json_parse_from_config (Medium) - `cpp/streaming/runtime/tasks/omni/OmniStreamTask.cpp:111` @ `OmniStreamTask::postConstruct` | 置信度: 65
10. **[VULN-DF-OPS-003]** json_parse_from_config (Medium) - `cpp/streaming/runtime/tasks/StreamTask.cpp:138` @ `StreamTask::createDataInput` | 置信度: 65

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

## 3. High 漏洞 (5)

### [VULN-DF-JNI-006] json_parse_exception_unsafe - Java_com_huawei_omniruntime_flink_runtime_taskexecutor_OmniTaskExecutor_submitTaskNative

**严重性**: High | **CWE**: CWE-502 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/jni/taskexecutor/jni_OmniTaskExecutor.cpp:47-78` @ `Java_com_huawei_omniruntime_flink_runtime_taskexecutor_OmniTaskExecutor_submitTaskNative`
**模块**: jni
**跨模块**: jni → runtime_execution → streaming_runtime_tasks

**描述**: JSON parsing from JNI strings without exception handling. Multiple JSON strings (jobjson, taskjson, tddjson) are converted to C++ strings and parsed. If any json::parse throws an exception, the function exits without proper cleanup.

**漏洞代码** (`cpp/jni/taskexecutor/jni_OmniTaskExecutor.cpp:47-78`)

```c
const char* jobString = jniEnv->GetStringUTFChars(jobjson, nullptr);
std::string jobInfoString(jobString);
jniEnv->ReleaseStringUTFChars(jobjson, jobString);
nlohmann::json job = nlohmann::json::parse(jobInfoString);
```

**达成路径**

Java jstring jobjson/taskjson/tddjson → GetStringUTFChars → std::string → nlohmann::json::parse → JobInformationPOD/TaskInformationPOD/TaskDeploymentDescriptorPOD
[SOURCE] Lines 50, 54, 58: JNI string input
[SINK] Lines 66, 68, 70: json::parse

**验证说明**: Code pattern safer: GetStringUTFChars → std::string → ReleaseStringUTFChars → parse(std::string). Memory released before parse, but no try-catch so exception still crashes JVM.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-JNI-007] json_parse_exception_unsafe - Java_com_huawei_omniruntime_flink_runtime_taskexecutor_OmniTaskExecutor_submitTaskNativeWithCheckpointing

**严重性**: High | **CWE**: CWE-502 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/jni/taskexecutor/jni_OmniTaskExecutor.cpp:85-142` @ `Java_com_huawei_omniruntime_flink_runtime_taskexecutor_OmniTaskExecutor_submitTaskNativeWithCheckpointing`
**模块**: jni
**跨模块**: jni → runtime_execution → streaming_runtime_tasks

**描述**: JSON parsing from JNI strings without exception handling. Same pattern as submitTaskNative - multiple JSON strings parsed without exception safety.

**漏洞代码** (`cpp/jni/taskexecutor/jni_OmniTaskExecutor.cpp:85-142`)

```c
const char* jobString = jniEnv->GetStringUTFChars(jobjson, nullptr);
std::string jobInfoString(jobString);
nlohmann::json job = nlohmann::json::parse(jobInfoString);
```

**达成路径**

Java jstring → GetStringUTFChars → std::string → nlohmann::json::parse → POD objects
[SOURCE] Lines 92, 96, 100: JNI string input
[SINK] Lines 108, 110, 112: json::parse

**验证说明**: Same pattern as VULN-DF-JNI-006: safer memory handling but no exception safety for json::parse.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [SEC-007] Deserialization Safety - KafkaRecordEmitter::emitRecord

**严重性**: High | **CWE**: CWE-502 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `cpp/connector/kafka/source/reader/KafkaRecordEmitter.cpp:33-36` @ `KafkaRecordEmitter::emitRecord`
**模块**: connector_kafka
**跨模块**: connector_kafka → core_serialization

**描述**: KafkaSource receives messages from external Kafka brokers and deserializes them using user-defined deserialization schemas. The KafkaRecordEmitter::emitRecord() calls deserializationSchema->deserialize() on data from untrusted external Kafka sources. Malformed Kafka messages could trigger exceptions in deserializers.

**漏洞代码** (`cpp/connector/kafka/source/reader/KafkaRecordEmitter.cpp:33-36`)

```c
deserializationSchema->deserialize(consumerRecord, sourceOutputWrapper);
} catch (const std::exception& e) {
throw std::runtime_error("Failed to deserialize consumer record due to: " + std::string(e.what()));
```

**达成路径**

Kafka Broker → RdKafkaConsumer::poll() → KafkaRecordEmitter → DeserializationSchema → Application

**验证说明**: emitRecord calls deserialize on Kafka message data. Untrusted network input with exception handling.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [SEC-006] Deserialization Safety - SpillingAdaptiveSpanningRecordDeserializer::setNextBuffer

**严重性**: High | **CWE**: CWE-502 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `cpp/runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp:68-86` @ `SpillingAdaptiveSpanningRecordDeserializer::setNextBuffer`
**模块**: runtime_io_network
**跨模块**: runtime_io_network → streaming_runtime_io

**描述**: SpillingAdaptiveSpanningRecordDeserializer receives network buffers from remote TaskManagers and deserializes records without explicit validation. The setNextBuffer() function processes data from untrusted network sources (remote TaskManagers via Netty shuffle). Malformed or malicious network data could potentially cause issues during deserialization.

**漏洞代码** (`cpp/runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp:68-86`)

```c
void SpillingAdaptiveSpanningRecordDeserializer::setNextBuffer(const uint8_t *buffer, int size)
{ if (spanningWrapper->getNumGatheredBytes() > 0) { spanningWrapper->addNextChunkFromMemoryBuffer(buffer, size); } else { nonSpanningWrapper->initializeFromMemoryBuffer(buffer, size); } }
```

**达成路径**

Remote TaskManager → Netty Network → NetworkBuffer → SpillingAdaptiveSpanningRecordDeserializer → Record Deserialization

**验证说明**: setNextBuffer processes network data from remote TaskManager. Partial boundary checks but potential deserialization issues.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-XMOD-001] cross_module_data_flow_jni_to_network - JNI_to_StreamTask_NetworkInput

**严重性**: High | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/jni/tasks/jni_OmniStreamTask.cpp:18-52` @ `JNI_to_StreamTask_NetworkInput`
**模块**: cross_module
**跨模块**: jni → streaming_runtime_tasks → streaming_runtime_io → runtime_io_network

**描述**: Cross-module data flow: JNI JSON input → StreamTask creation → Network input processor. Malformed JSON from Java could propagate through the entire pipeline, affecting network data processing.

**漏洞代码** (`cpp/jni/tasks/jni_OmniStreamTask.cpp:18-52`)

```c
// See VULN-DF-JNI-002 and VULN-DF-JNI-003 for detailed code
// Data flows: JNI → StreamTask → StreamOneInputProcessor → StreamTaskNetworkInput → SpillingAdaptiveSpanningRecordDeserializer
```

**达成路径**

JNI (jni_OmniStreamTask.cpp:21-27) → StreamTask (StreamTask.cpp:36-40) → StreamOneInputProcessor → StreamTaskNetworkInput → SpillingAdaptiveSpanningRecordDeserializer (NonSpanningWrapper.h:131-147)
[SOURCE] JNI input (semi_trusted)
[PATH] StreamTask → InputProcessor → Network Deserializer
[SINK] Network buffer processing (untrusted_network)

**验证说明**: JNI -> StreamTask -> StreamOneInputProcessor -> StreamTaskNetworkInput -> SpillingAdaptiveSpanningRecordDeserializer. Cross-module data flow verified.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (8)

### [VULN-DF-NET-002] memory_allocation_external_control - SpanningWrapper::ensureBufferCapacity

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/runtime/io/network/api/serialization/SpanningWrapper.h:186-192` @ `SpanningWrapper::ensureBufferCapacity`
**模块**: runtime_io_network

**描述**: Buffer capacity expansion based on externally controlled record length. The recordLength_ value comes from network buffer and is used to expand internal buffer capacity. A malicious remote TaskManager could send extremely large record length values.

**漏洞代码** (`cpp/runtime/io/network/api/serialization/SpanningWrapper.h:186-192`)

```c
if (static_cast<size_t>(minLength) > buffer_.capacity()) {
    int newCapacity_ = std::max(minLength, static_cast<int>(buffer_.capacity() * 2));
    buffer_.reserve(newCapacity_);
}
```

**达成路径**

Network buffer → readInt() → recordLength_ → updateLength() → ensureBufferCapacity(recordLength_) → buffer_.reserve()
[SOURCE] recordLength_ from network
[SINK] buffer_.reserve(newCapacity_) (memory allocation)

**验证说明**: ensureBufferCapacity uses minLength from network data to reserve buffer. No explicit upper bound limit.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-JNI-004] deserialization_exception_unsafe - convertResult

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:518-566` @ `convertResult`
**模块**: jni

**描述**: JSON parsing from JNI returned data. The convertResult function parses JSON data returned from Java JNI call. Malformed JSON could cause parsing exceptions.

**漏洞代码** (`cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:518-566`)

```c
nlohmann::json parsed = nlohmann::json::parse(cppResult);
for (const auto& oneSnapshot : parsed) {
```

**达成路径**

Java jstring result → GetStringUTFChars → std::string cppResult → nlohmann::json::parse → StateMetaInfoSnapshot vector
[SOURCE] Line 602: GetStringUTFChars (JNI input)
[SINK] Line 522: json::parse (deserialization)

**验证说明**: Code at line 522: json::parse on Java bridge returned data. Indirect external input, partial controllability.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-OPS-001] json_parse_from_config - OperatorChainV2::getChainOutputType

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/streaming/runtime/tasks/OperatorChain.cpp:214-240` @ `OperatorChainV2::getChainOutputType`
**模块**: streaming_runtime_tasks

**描述**: JSON parsing from operator configuration without exception handling. Operator output type strings from configuration are parsed as JSON. Malformed configuration could cause exceptions.

**漏洞代码** (`cpp/streaming/runtime/tasks/OperatorChain.cpp:214-240`)

```c
nlohmann::json outputRowType = nlohmann::json::parse(lastOperatorOutput.type);
// ...
auto description = nlohmann::json::parse(operatorPod.getDescription());
```

**达成路径**

OperatorPOD configuration → lastOperatorOutput.type/operatorPod.getDescription() → nlohmann::json::parse → TypeInfo
[SOURCE] Configuration strings (from TDD JSON)
[SINK] Lines 214, 217, 222, 233, 239: json::parse

**验证说明**: OperatorChain.cpp lines 214, 217, 222, 239: json::parse on operator configuration from TDD JSON. Indirect external input.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-OPS-002] json_parse_from_config - OmniStreamTask::postConstruct

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/streaming/runtime/tasks/omni/OmniStreamTask.cpp:111-124` @ `OmniStreamTask::postConstruct`
**模块**: streaming_runtime_tasks
**跨模块**: streaming_runtime_tasks → runtime_state

**描述**: JSON parsing from local recovery configuration string. The configuration string is parsed without exception handling. Malformed recovery config could cause parsing exceptions.

**漏洞代码** (`cpp/streaming/runtime/tasks/omni/OmniStreamTask.cpp:111-124`)

```c
std::string localRecoveryProviderStr = taskConfiguration_.getLocalRecoveryConfig();
nlohmann::json localJson = nlohmann::json::parse(localRecoveryProviderStr);
```

**达成路径**

TaskConfiguration → getLocalRecoveryConfig() → std::string → nlohmann::json::parse → LocalRecoveryDirectoryProviderImpl
[SOURCE] Line 111: Configuration string
[SINK] Line 112: json::parse

**验证说明**: OmniStreamTask.cpp line 112: json::parse on localRecoveryProviderStr from taskConfiguration.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-OPS-003] json_parse_from_config - StreamTask::createDataInput

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/streaming/runtime/tasks/StreamTask.cpp:138-148` @ `StreamTask::createDataInput`
**模块**: streaming_runtime_tasks

**描述**: JSON parsing from operator description string. The operatorPod description is parsed as JSON without exception handling.

**漏洞代码** (`cpp/streaming/runtime/tasks/StreamTask.cpp:138-148`)

```c
auto operatorPod = env_->taskConfiguration().getStreamConfigPOD().getOperatorDescription();
auto description = nlohmann::json::parse(operatorPod.getDescription());
```

**达成路径**

TaskConfiguration → getOperatorDescription() → getDescription() → nlohmann::json::parse → inputTypes
[SOURCE] Line 137: Configuration
[SINK] Line 138: json::parse

**验证说明**: StreamTask.cpp line 138: json::parse on operatorPod.getDescription() from TDD JSON.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-JNI-009] jni_string_unsafe - Java_com_huawei_omniruntime_flink_runtime_taskmanager_OmniTask_notifyCheckpointComplete

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/jni/taskmanager/jni_OmniTask.cpp:126-128` @ `Java_com_huawei_omniruntime_flink_runtime_taskmanager_OmniTask_notifyCheckpointComplete`
**模块**: jni

**描述**: JNI string handling and potential JSON parsing. GetStringUTFChars returns checkpoint option JSON string. No explicit exception handling.

**漏洞代码** (`cpp/jni/taskmanager/jni_OmniTask.cpp:126-128`)

```c
const char* checkpointStr = jniEnv->GetStringUTFChars(checkpointoptionJson, nullptr);
```

**达成路径**

Java jstring checkpointoptionJson → GetStringUTFChars → const char* checkpointStr → potential JSON parsing
[SOURCE] Line 126: JNI string
[SINK] GetStringUTFChars

**验证说明**: Code at lines 126-128: GetStringUTFChars → json::parse → ReleaseStringUTFChars. Same exception safety issue.

**评分明细**: base: 30 | reachability: 30 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-003] Environment Variable Path Injection - GetOmniHome

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `cpp/connector/kafka/utils/ConfigLoader.cpp:23-30` @ `GetOmniHome`
**模块**: connector_kafka
**跨模块**: connector_kafka → runtime_state

**描述**: Kafka configuration loader uses OMNI_HOME environment variable to construct file paths without proper validation. An attacker who can control the OMNI_HOME environment variable could redirect configuration loading to arbitrary files, potentially loading malicious Kafka configurations including security settings (sasl.mechanism, security.protocol). The default fallback to /opt also has potential for symlink attacks.

**漏洞代码** (`cpp/connector/kafka/utils/ConfigLoader.cpp:23-30`)

```c
auto omniHome = std::getenv("OMNI_HOME");
if (omniHome != nullptr && omniHome[0] != '\0') {
    std::string confDir { omniHome }; Trim(confDir); return confDir;
} else { return "/opt"; }
```

**达成路径**

OMNI_HOME env → GetOmniHome() → GetConfigFilePath() → LoadKafkaConfig() → Kafka Consumer Configuration

**验证说明**: GetOmniHome at lines 23-30 uses OMNI_HOME env var for config path. realpath() provides partial mitigation against symlink attacks.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [SEC-008] Deserialization Safety - TaskLocalStateStore::restore

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `cpp/runtime/state/TaskLocalStateStore.cpp:227-228` @ `TaskLocalStateStore::restore`
**模块**: runtime_state
**跨模块**: runtime_state → jni

**描述**: State restoration reads serialized state data from external storage (HDFS/S3) via Java bridge and deserializes it. The TaskLocalStateStore reads state snapshots from external storage and deserializes them using TaskStateSnapshotDeserializer. Malicious state data in checkpoint storage could compromise the restoration process.

**漏洞代码** (`cpp/runtime/state/TaskLocalStateStore.cpp:227-228`)

```c
TaskStateSnapshotDeserializer::Deserialize(std::string(buffer.data(), buffer.size()));
```

**达成路径**

External Storage (HDFS/S3) → Java FSDataInputStream → JNI Bridge → C++ Buffer → TaskStateSnapshotDeserializer → State Restoration

**验证说明**: restore deserializes state from external storage (HDFS/S3). Partially controlled input.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (2)

### [VULN-DF-JNI-005] integer_overflow_potential - CreateByteStreamStateHandle

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:227-278` @ `CreateByteStreamStateHandle`
**模块**: jni
**跨模块**: jni → runtime_state

**描述**: Byte array copy from JNI without explicit size limit validation. GetByteArrayElements returns raw bytes from Java. While GetArrayLength returns jsize (int), for extremely large arrays there could be integer overflow issues when used with size_t operations.

**漏洞代码** (`cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:227-278`)

```c
jsize dataLen = env->GetArrayLength(jData);
jbyte* dataBytes = env->GetByteArrayElements(jData, nullptr);
data.assign(reinterpret_cast<uint8_t*>(dataBytes), reinterpret_cast<uint8_t*>(dataBytes + dataLen));
```

**达成路径**

Java jbyteArray jData → GetArrayLength → jsize dataLen → GetByteArrayElements → jbyte* dataBytes → std::vector::assign
[SOURCE] Line 248: Java byte array (JNI input)
[SINK] Line 267: vector::assign (memory allocation/copy)

**验证说明**: Code at lines 263-269: GetArrayLength checks size, GetByteArrayElements with ReleaseByteArrayElements. Potential integer overflow for extremely large arrays.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-JNI-008] jni_bytearray_no_limit - uploadRocksDBStateToJava

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `cpp/runtime/state/rocksdb/RocksDBStateUploader.cpp:374-380` @ `uploadRocksDBStateToJava`
**模块**: jni
**跨模块**: jni → runtime_state

**描述**: JNI byte array handling without size limit validation. GetByteArrayElements is called on potentially large state data. No explicit size limit check before memory operations.

**漏洞代码** (`cpp/runtime/state/rocksdb/RocksDBStateUploader.cpp:374-380`)

```c
jbyte* dataBytes = env->GetByteArrayElements(jData, nullptr);
```

**达成路径**

Java jbyteArray → GetByteArrayElements → jbyte* dataBytes → state data processing
[SOURCE] JNI byte array from Java
[SINK] GetByteArrayElements (memory access)

**验证说明**: Code at lines 375-381: GetByteArrayElements on state data with ReleaseByteArrayElements. Same pattern as VULN-DF-JNI-005.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| connector_kafka | 0 | 1 | 1 | 0 | 2 |
| cross_module | 0 | 1 | 0 | 0 | 1 |
| jni | 0 | 2 | 2 | 2 | 6 |
| runtime_io_network | 0 | 1 | 1 | 0 | 2 |
| runtime_state | 0 | 0 | 1 | 0 | 1 |
| streaming_runtime_tasks | 0 | 0 | 3 | 0 | 3 |
| **合计** | **0** | **5** | **8** | **2** | **15** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-502 | 11 | 73.3% |
| CWE-190 | 3 | 20.0% |
| CWE-78 | 1 | 6.7% |
