# 漏洞扫描报告 — 待确认漏洞

**项目**: OmniStream
**扫描时间**: 2025-04-22T23:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本报告包含 **32 个待确认漏洞** (18 LIKELY + 14 POSSIBLE)，其中 **18 个为 High 级别，11 个为 Medium 级别，3 个为 Low 级别**。这些漏洞需要进一步验证和测试，部分可能与已确认漏洞存在关联。

**重点关注的待确认漏洞**：

1. **JNI 层输入验证** — 多个 JNI 接口缺少 JSON 解析异常处理，可能导致内存泄露或崩溃
2. **NULL 指针解引用** — 网络数据对象转换缺少 NULL 检查，可能导致崩溃
3. **文件路径处理** — CSV 文件路径可能存在路径遍历风险

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 18 | 47.4% |
| POSSIBLE | 14 | 36.8% |
| CONFIRMED | 6 | 15.8% |
| **总计** | **38** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 18 | 56.3% |
| Medium | 11 | 34.4% |
| Low | 3 | 9.4% |
| **有效漏洞总计** | **32** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-STREAM-002]** NULL Pointer Dereference (High) - `cpp/streaming/runtime/io/OmniAbstractStreamTaskNetworkInput.h:175` @ `OmniAbstractStreamTaskNetworkInput::processBufferOrEventOptForSQL` | 置信度: 75
2. **[VULN-CROSS-002]** Cross-Module Memory Corruption (High) - `cpp/jni/io/jni_OmniLocalInputChannel.cpp:42` @ `Java_org_apache_flink_runtime_io_network_partition_consumer_OmniLocalInputChannel_sendMemorySegmentToNative` | 置信度: 75
3. **[SEC-009]** NULL Pointer Dereference (High) - `cpp/streaming/runtime/io/OmniAbstractStreamTaskNetworkInput.h:177` @ `OmniAbstractStreamTaskNetworkInput::processBufferOrEventOptForSQL` | 置信度: 75
4. **[VULN-JNI-003]** Deserialization of Untrusted Data (High) - `cpp/jni/tasks/jni_OmniStreamTask.cpp:27` @ `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask` | 置信度: 70
5. **[VULN-JNI-007]** Deserialization of Untrusted Data (High) - `cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:772` @ `convertResult` | 置信度: 70
6. **[VULN-NET-001]** Out-of-bounds Read (High) - `cpp/runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp:57` @ `SpillingAdaptiveSpanningRecordDeserializer::readNonSpanningRecord` | 信度: 70
7. **[VULN-KAFKA-001]** Improper Input Validation (High) - `cpp/connector/kafka/source/KafkaSource.cpp:31` @ `KafkaSource::KafkaSource` | 置信度: 70
8. **[VULN-CROSS-003]** Cross-Module State Restoration (High) - `cpp/jni/bridge/OmniTaskBridgeImpl2.cpp -> cpp/runtime/state/RocksdbKeyedStateBackend.h:730` @ `OmniTaskBridgeImpl2::CallDownloadFileToLocal -> RocksdbKeyedStateBackend::restore` | 置信度: 70
9. **[SEC-003]** Improper Input Validation (High) - `cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:768` @ `convertResult` | 置信度: 70
10. **[SEC-006]** Improper Input Validation (High) - `cpp/runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp:53` @ `SpillingAdaptiveSpanningRecordDeserializer::readNonSpanningRecord` | 置信度: 70

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration@cpp/jni/init.cpp` | rpc | semi_trusted | JNI 调用入口，接收 Java 侧传递的配置 JSON 字符串，Java Flink Runtime 为半信任方（部署在集群环境） | 初始化 TaskManager 配置，接收并解析 JSON 配置字符串 |
| `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask@cpp/jni/tasks/jni_OmniStreamTask.cpp` | rpc | semi_trusted | JNI 调用入口，接收 Java 传递的 TDD（TaskDeploymentDescriptor）JSON 字符串 | 创建原生 StreamTask 对象，解析任务描述 JSON |
| `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeOmniInputProcessor@cpp/jni/tasks/jni_OmniStreamTask.cpp` | rpc | semi_trusted | JNI 调用入口，接收输入通道信息 JSON 字符串 | 创建输入处理器，解析通道配置 JSON |
| `Java_org_apache_flink_runtime_io_network_partition_consumer_OmniLocalInputChannel_sendMemorySegmentToNative@cpp/jni/io/jni_OmniLocalInputChannel.cpp` | rpc | semi_trusted | JNI 调用入口，接收 Java 传递的内存段地址和数据长度，直接操作共享内存 | 发送内存段数据到原生侧，传递内存地址和数据参数 |
| `OmniTaskBridgeImpl2::CallMaterializeMetaData@cpp/jni/bridge/OmniTaskBridgeImpl2.cpp` | rpc | semi_trusted | 通过 JNI 回调 Java 方法，涉及 checkpoint 元数据和文件路径传递 | 调用 Java 端 checkpoint 元数据持久化 |
| `RdKafkaConsumer::poll@cpp/connector/kafka/source/reader/RdKafkaConsumer.h` | network | untrusted_network | 从 Kafka Broker 消费消息，数据来源为外部网络集群 | Kafka 消息消费，接收外部 Kafka 数据 |
| `KafkaSource::KafkaSource@cpp/connector/kafka/source/KafkaSource.cpp` | network | untrusted_network | 解析 Kafka 配置属性，配置来源于 JSON opDescription | Kafka 源初始化，解析配置并创建消费者 |
| `OmniAbstractStreamTaskNetworkInput::emitNext@cpp/streaming/runtime/io/OmniAbstractStreamTaskNetworkInput.h` | network | untrusted_network | 处理来自其他 TaskManager 的网络数据，数据通过网络传输接收 | 网络输入数据处理，反序列化并分发数据 |
| `SpillingAdaptiveSpanningRecordDeserializer::deserialize@cpp/runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp` | network | untrusted_network | 反序列化网络数据缓冲区，数据来源为远程 TaskManager | 记录反序列化，处理网络数据缓冲区 |
| `CsvLookupFunction::open@cpp/table/sources/CsvTableSource.h` | file | semi_trusted | 读取 CSV 文件，文件路径来自配置，数据内容可被外部修改 | CSV 文件读取和哈希表构建 |
| `JsonRowDataDeserializationSchema::deserialize@cpp/core/api/common/serialization/JsonRowDataDeserializationSchema.h` | network | untrusted_network | 解析 JSON 数据，数据来源为 Kafka 消息或网络数据 | JSON 数据反序列化，将字节流转换为 VectorBatch |

**其他攻击面**:
- JNI Interface: Java Flink Runtime -> C++ Native Runtime (配置注入、任务描述、内存地址传递)
- Kafka Consumer: External Kafka Cluster -> KafkaSource Reader (消息数据、配置)
- Network I/O: Remote TaskManager -> NetworkInput/Deserializer (网络数据缓冲区)
- File System: Checkpoint/Savepoint Files -> State Backend (文件路径、状态数据)
- CSV Source: External Files -> CsvTableSource (文件路径、文件内容)

---

## 3. High 漏洞 (18)

### [VULN-STREAM-002] NULL Pointer Dereference - OmniAbstractStreamTaskNetworkInput::processBufferOrEventOptForSQL

**严重性**: High | **CWE**: CWE-476 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/streaming/runtime/io/OmniAbstractStreamTaskNetworkInput.h:175-184` @ `OmniAbstractStreamTaskNetworkInput::processBufferOrEventOptForSQL`
**模块**: streaming_runtime_io

**描述**: Object retrieved from network data (objSegment->getObject(index)) is cast to StreamRecord/VectorBatch without null checking. Malformed network data could result in null pointers being dereferenced.

**漏洞代码** (`cpp/streaming/runtime/io/OmniAbstractStreamTaskNetworkInput.h:175-184`)

```c
StreamElement *object = objSegment->getObject(index);
if (object->getTag() == StreamElementTag::TAG_REC_WITH_TIMESTAMP ||...) {
    auto record = static_cast<StreamRecord *>(object);
    auto vectorBatch = static_cast<VectorBatch *>(record->getValue());
```

**达成路径**

ObjectSegment::getObject (Network Source) -> static_cast (no null check) -> getValue dereference

**验证说明**: 源代码确认object指针未检查null(line175)。但getTag()访问在static_cast之后，实际崩溃风险取决于ObjectSegment::getObject实现。

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: -5 | reachability: 30

---

### [VULN-CROSS-002] Cross-Module Memory Corruption - Java_org_apache_flink_runtime_io_network_partition_consumer_OmniLocalInputChannel_sendMemorySegmentToNative

**严重性**: High | **CWE**: CWE-119 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/jni/io/jni_OmniLocalInputChannel.cpp:42-43` @ `Java_org_apache_flink_runtime_io_network_partition_consumer_OmniLocalInputChannel_sendMemorySegmentToNative`
**模块**: cross_module
**跨模块**: jni → runtime_partition → streaming_runtime_io

**描述**: Cross-module memory address chain: segmentAddress from JNI is passed through OmniLocalInputChannel to memory operations. Invalid addresses could corrupt memory across multiple modules.

**漏洞代码** (`cpp/jni/io/jni_OmniLocalInputChannel.cpp:42-43`)

```c
jni_OmniLocalInputChannel.cpp:43 -> OmniLocalInputChannel::notifyOriginalDataAvailable
```

**达成路径**

jni_OmniLocalInputChannel.cpp (jni) segmentAddress -> OmniLocalInputChannel (runtime_partition) -> MemorySegment operations -> Network buffer processing (streaming_runtime_io)

**验证说明**: 跨模块链确认: JNI segmentAddress -> OmniLocalInputChannel -> memory操作。缺少地址验证。但需要控制Java侧传值，实际攻击难度较高。

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 25

---

### [SEC-009] NULL Pointer Dereference - OmniAbstractStreamTaskNetworkInput::processBufferOrEventOptForSQL

**严重性**: High | **CWE**: CWE-476 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `cpp/streaming/runtime/io/OmniAbstractStreamTaskNetworkInput.h:177-186` @ `OmniAbstractStreamTaskNetworkInput::processBufferOrEventOptForSQL`
**模块**: streaming_runtime_io

**描述**: StreamElement类型转换无NULL检查。OmniAbstractStreamTaskNetworkInput.h中static_cast<StreamRecord*>和static_cast<VectorBatch*>转换前未检查指针有效性，若object为nullptr会导致崩溃。

**漏洞代码** (`cpp/streaming/runtime/io/OmniAbstractStreamTaskNetworkInput.h:177-186`)

```c
auto record = static_cast<StreamRecord *>(object);
auto vectorBatch = static_cast<VectorBatch *>(record->getValue());
```

**达成路径**

objSegment.getObject -> StreamElement -> static_cast -> getValue

**验证说明**: 源代码确认object指针未检查null。与VULN-STREAM-002重复发现。

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: -5 | reachability: 30

---

### [VULN-JNI-003] Deserialization of Untrusted Data - Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask

**严重性**: High | **CWE**: CWE-502 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/jni/tasks/jni_OmniStreamTask.cpp:27-34` @ `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask`
**模块**: jni

**描述**: nlohmann::json::parse() parses TDD (TaskDeploymentDescriptor) JSON string from Java without validation. Malicious JSON could cause exceptions, memory exhaustion, or injection of malicious task configurations.

**漏洞代码** (`cpp/jni/tasks/jni_OmniStreamTask.cpp:27-34`)

```c
nlohmann::json tdd = nlohmann::json::parse(cStrTDD);
LOG("Calling  StreamTask with json " + tdd.dump(2))
auto *streamTask = new omnistream::datastream::StreamTask(tdd, bufferStatus, task->getRuntimeEnv());
```

**达成路径**

JNIEnv::GetStringUTFChars (JNI Source) -> nlohmann::json::parse (no validation) -> StreamTask constructor

**验证说明**: 源代码确认缺少try-catch。parse异常时ReleaseStringUTFChars不执行，存在内存泄露。但trust_level为semi_trusted，攻击者需控制Java传递的TDD字符串。

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-JNI-007] Deserialization of Untrusted Data - convertResult

**严重性**: High | **CWE**: CWE-502 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:772-773` @ `convertResult`
**模块**: jni

**描述**: nlohmann::json::parse() parses checkpoint metadata JSON from Java in convertResult() without validation. Malformed metadata could cause state restoration failures or injection attacks.

**漏洞代码** (`cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:772-773`)

```c
nlohmann::json parsed = nlohmann::json::parse(cppResult);
for (const auto& oneSnapshot : parsed) {
```

**达成路径**

Java metadata string (JNI Source) -> nlohmann::json::parse (no validation) -> StateMetaInfoSnapshot reconstruction

**验证说明**: 源代码确认checkpoint元数据JSON解析缺少异常处理(line772)。虽有部分字段验证(line775-781)，但parse调用本身无try-catch包裹。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -5 | reachability: 30

---

### [VULN-NET-001] Out-of-bounds Read - SpillingAdaptiveSpanningRecordDeserializer::readNonSpanningRecord

**严重性**: High | **CWE**: CWE-125 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp:57-66` @ `SpillingAdaptiveSpanningRecordDeserializer::readNonSpanningRecord`
**模块**: runtime_io_network

**描述**: recordLen is read from network buffer via nonSpanningWrapper->readInt() without validation. A maliciously crafted length value could lead to buffer overflows when used in subsequent read operations.

**漏洞代码** (`cpp/runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp:57-66`)

```c
int recordLen = nonSpanningWrapper->readInt();
if (nonSpanningWrapper->canReadRecord(recordLen)) {
    return nonSpanningWrapper->readInto(target);
} else {
    spanningWrapper->transferFrom(*nonSpanningWrapper, recordLen);
```

**达成路径**

Network buffer (Source) -> readInt (tainted length) -> readInto/transferFrom

**验证说明**: 源代码确认recordLen从网络读取，但有canReadRecord检查(line61)作为部分缓解。trust_level为untrusted_network，但仍需验证canReadRecord是否充分。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: -15 | reachability: 30

---

### [VULN-KAFKA-001] Improper Input Validation - KafkaSource::KafkaSource

**严重性**: High | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/connector/kafka/source/KafkaSource.cpp:31-33` @ `KafkaSource::KafkaSource`
**模块**: connector_kafka

**描述**: Deserialization schema is created from opDescriptionJSON without validation. JSON configuration from Java/Kafka setup could inject malicious deserialization settings.

**漏洞代码** (`cpp/connector/kafka/source/KafkaSource.cpp:31-33`)

```c
auto innerDeserializationSchema = DeserializationFactory::getDeserializationSchema(
    opDescriptionJSON);
deserializationSchema = KafkaRecordDeserializationSchema::valueOnly(innerDeserializationSchema);
```

**达成路径**

opDescriptionJSON (Java config Source) -> DeserializationFactory::getDeserializationSchema (no validation)

**验证说明**: 源代码确认opDescriptionJSON直接用于创建deserializer(line31)。缺少schema验证。但信任边界为Java->C++，实际攻击需控制Java配置。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 25

---

### [VULN-CROSS-003] Cross-Module State Restoration - OmniTaskBridgeImpl2::CallDownloadFileToLocal -> RocksdbKeyedStateBackend::restore

**严重性**: High | **CWE**: CWE-125 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/jni/bridge/OmniTaskBridgeImpl2.cpp -> cpp/runtime/state/RocksdbKeyedStateBackend.h:730-765` @ `OmniTaskBridgeImpl2::CallDownloadFileToLocal -> RocksdbKeyedStateBackend::restore`
**模块**: cross_module
**跨模块**: jni → runtime_state

**描述**: Cross-module file path chain: File paths from Java checkpoint metadata are passed through JNI bridge to RocksDB state backend for restoration. Malicious checkpoint files could lead to arbitrary file access or state corruption.

**漏洞代码** (`cpp/jni/bridge/OmniTaskBridgeImpl2.cpp -> cpp/runtime/state/RocksdbKeyedStateBackend.h:730-765`)

```c
OmniTaskBridgeImpl2.cpp:730 -> RocksdbKeyedStateBackend.h
```

**达成路径**

OmniTaskBridgeImpl2.cpp (jni) CallDownloadFileToLocal -> RocksdbKeyedStateBackend.h (runtime_state) restore -> RocksDB::Open (potential arbitrary file access)

**验证说明**: 跨模块链确认checkpoint文件路径传递。但文件操作受Java安全机制约束，实际攻击难度较高。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -5 | reachability: 30

---

### [SEC-003] Improper Input Validation - convertResult

**严重性**: High | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:768-817` @ `convertResult`
**模块**: jni
**跨模块**: jni → runtime_state

**描述**: Checkpoint元数据JSON解析缺少异常处理。OmniTaskBridgeImpl2.cpp中convertResult函数直接调用nlohmann::json::parse解析从Java端获取的元数据字符串，无异常捕获。恶意元数据可能导致解析崩溃。

**漏洞代码** (`cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:768-817`)

```c
nlohmann::json parsed = nlohmann::json::parse(cppResult);
```

**达成路径**

Java metadata JNI -> readMetaData -> convertResult -> json::parse

**验证说明**: 源代码确认checkpoint元数据JSON解析缺少异常处理。与VULN-JNI-007重复发现，合并评分。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -5 | reachability: 30

---

### [SEC-006] Improper Input Validation - SpillingAdaptiveSpanningRecordDeserializer::readNonSpanningRecord

**严重性**: High | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `cpp/runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp:53-67` @ `SpillingAdaptiveSpanningRecordDeserializer::readNonSpanningRecord`
**模块**: runtime_io_network
**跨模块**: runtime_io_network → streaming_runtime_io

**描述**: 网络数据反序列化缺少长度校验。SpillingAdaptiveSpanningRecordDeserializer.cpp中recordLen从网络缓冲区读取后直接使用，未验证是否超出缓冲区大小。可能导致读取越界。

**漏洞代码** (`cpp/runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp:53-67`)

```c
int recordLen = nonSpanningWrapper->readInt();
if (nonSpanningWrapper->canReadRecord(recordLen)) {...}
```

**达成路径**

NetworkBuffer -> readInt(recordLen) -> readInto/spanningWrapper

**验证说明**: 源代码确认recordLen缺少充分验证。虽有canReadRecord检查，但需验证其完整性。与VULN-NET-001重复发现。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: -15 | reachability: 30

---

### [VULN-JNI-002] Improper Input Validation - Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration

**严重性**: High | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/jni/init.cpp:53-54` @ `Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration`
**模块**: jni

**描述**: nlohmann::json::parse() parses external JSON configuration from Java without exception handling or input validation. Malformed JSON could cause exceptions, denial of service, or potential memory corruption.

**漏洞代码** (`cpp/jni/init.cpp:53-54`)

```c
nlohmann::json config = nlohmann::json::parse(cStrCon);
Configuration::TM_CONFIG->setConfiguration(config);
```

**达成路径**

JNIEnv::GetStringUTFChars (JNI Source) -> nlohmann::json::parse (no validation) -> Configuration::setConfiguration

**验证说明**: 源代码确认缺少try-catch异常处理。JSON解析可能抛出parse_error异常导致进程崩溃。但trust_level为semi_trusted(JNI来自Java Flink Runtime)，攻击者需控制Java侧配置。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-JNI-005] Deserialization of Untrusted Data - Java_org_apache_flink_runtime_io_network_partition_consumer_OmniLocalInputChannel_doChangeNativeLocalInputChannel

**严重性**: High | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/jni/io/jni_OmniLocalInputChannel.cpp:31-32` @ `Java_org_apache_flink_runtime_io_network_partition_consumer_OmniLocalInputChannel_doChangeNativeLocalInputChannel`
**模块**: jni

**描述**: nlohmann::json::parse() parses partition ID JSON from Java without validation in doChangeNativeLocalInputChannel.

**漏洞代码** (`cpp/jni/io/jni_OmniLocalInputChannel.cpp:31-32`)

```c
nlohmann::json partitionId = nlohmann::json::parse(paritionIdStr);
omnistream::ResultPartitionIDPOD partitionIdPOD = partitionId;
```

**达成路径**

JNIEnv::GetStringUTFChars (JNI Source) -> nlohmann::json::parse (no validation) -> ResultPartitionIDPOD

**验证说明**: 源代码确认JSON解析缺少异常处理。但trust_level为semi_trusted，实际攻击需控制Java侧传值。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-BUF-001] Improper Validation of Array Index - LocalMemoryBufferPool::toMemoryBufferBuilder

**严重性**: High | **CWE**: CWE-129 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/runtime/buffer/LocalMemoryBufferPool.cpp:202-203` @ `LocalMemoryBufferPool::toMemoryBufferBuilder`
**模块**: runtime_buffer

**描述**: targetChannel is used as an index into subpartitionBufferRecyclers_ array without bounds checking. If targetChannel exceeds the array size, this causes out-of-bounds array access.

**漏洞代码** (`cpp/runtime/buffer/LocalMemoryBufferPool.cpp:202-203`)

```c
return new MemoryBufferBuilder(memorySegment, subpartitionBufferRecyclers_[targetChannel]);
```

**达成路径**

targetChannel parameter (JNI/config) -> subpartitionBufferRecyclers_ array access (no bounds check)

**验证说明**: 源代码确认targetChannel数组访问无边界检查(line202)。但targetChannel来源需进一步追踪，可能是内部配置而非外部可控。

**评分明细**: base: 30 | controllability: 10 | context: -5 | cross_file: 0 | mitigations: 0 | reachability: 30

---

### [VULN-JNI-009] Deserialization of Untrusted Data - Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeOmniInputProcessor

**严重性**: High | **CWE**: CWE-502 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/jni/tasks/jni_OmniStreamTask.cpp:49-52` @ `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeOmniInputProcessor`
**模块**: jni

**描述**: JSON parsing of input channel info from Java without validation in createNativeOmniInputProcessor.

**漏洞代码** (`cpp/jni/tasks/jni_OmniStreamTask.cpp:49-52`)

```c
nlohmann::json tdd = nlohmann::json::parse(cStrTDD);
```

**达成路径**

JNI inputChannelInfo string -> nlohmann::json::parse

**验证说明**: 源代码确认JSON解析缺少异常处理(line49)。trust_level为semi_trusted JNI接口。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [SEC-001] Improper Input Validation - Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration

**严重性**: High | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `cpp/jni/init.cpp:50-55` @ `Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration`
**模块**: jni

**描述**: JNI配置JSON解析缺少异常处理。init.cpp中nlohmann::json::parse()直接解析Java传递的配置字符串，无try-catch包裹。恶意JSON可能导致解析异常崩溃，且缺少ReleaseStringUTFChars调用存在内存泄露风险。

**漏洞代码** (`cpp/jni/init.cpp:50-55`)

```c
const char *cStrCon = (env)->GetStringUTFChars(configStr, 0);
nlohmann::json config = nlohmann::json::parse(cStrCon);
```

**达成路径**

Java configStr JNI -> GetStringUTFChars -> json::parse -> setConfiguration

**验证说明**: 源代码确认JSON解析缺少异常处理(init.cpp:53)。与VULN-JNI-002重复发现，合并评分。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-JNI-004] Buffer Errors - Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask

**严重性**: High | **CWE**: CWE-119 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/jni/tasks/jni_OmniStreamTask.cpp:25-34` @ `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask`
**模块**: jni

**描述**: statusAddress and nativeTask are jlong values passed from Java and directly cast to pointers using reinterpret_cast without validation. Invalid addresses could cause memory corruption, crashes, or potential exploitation.

**漏洞代码** (`cpp/jni/tasks/jni_OmniStreamTask.cpp:25-34`)

```c
void *bufferStatus = reinterpret_cast<void *>(statusAddress);
...
auto task = reinterpret_cast<omnistream::OmniTask *>(nativeTask);
auto *streamTask = new omnistream::datastream::StreamTask(tdd, bufferStatus, task->getRuntimeEnv());
```

**达成路径**

jlong statusAddress/nativeTask (JNI Source) -> reinterpret_cast (no validation) -> pointer usage

**验证说明**: 源代码确认jlong直接reinterpret_cast为指针。这是JNI标准做法，但缺少地址有效性验证。攻击者可传递非法地址导致崩溃。实际攻击需控制Java侧传值。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 15

---

### [VULN-JNI-006] Buffer Errors - Java_org_apache_flink_runtime_io_network_partition_consumer_OmniLocalInputChannel_sendMemorySegmentToNative

**严重性**: High | **CWE**: CWE-119 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cpp/jni/io/jni_OmniLocalInputChannel.cpp:42-43` @ `Java_org_apache_flink_runtime_io_network_partition_consumer_OmniLocalInputChannel_sendMemorySegmentToNative`
**模块**: jni

**描述**: segmentAddress (jlong) is passed directly from Java to notifyOriginalDataAvailable without validation. Invalid memory addresses could cause memory corruption or out-of-bounds writes when accessing shared memory segments.

**漏洞代码** (`cpp/jni/io/jni_OmniLocalInputChannel.cpp:42-43`)

```c
auto omniInputChannel = reinterpret_cast<omnistream::OmniLocalInputChannel*>(omniLocalInputChannelRef);
omniInputChannel->notifyOriginalDataAvailable(segmentAddress, length, readIndex, sequenceNum, memorySegmentOffset, bufferType);
```

**达成路径**

jlong segmentAddress (JNI Source) -> notifyOriginalDataAvailable (direct memory access)

**验证说明**: 源代码确认jlong segmentAddress直接传递给notifyOriginalDataAvailable，缺少验证。但这是JNI接口，实际攻击需控制Java侧传值。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 15

---

### [SEC-011] Improper Input Validation - JsonRowDataDeserializationSchema::setColValue

**严重性**: High | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `cpp/core/api/common/serialization/JsonRowDataDeserializationSchema.h:49-85` @ `JsonRowDataDeserializationSchema::setColValue`
**模块**: core_serialization

**描述**: JSON字段类型不匹配处理不当。JsonRowDataDeserializationSchema.h中node[name].get<T>()直接调用类型转换，若JSON字段类型与预期不符会抛出异常。缺少类型检查和错误处理。

**漏洞代码** (`cpp/core/api/common/serialization/JsonRowDataDeserializationSchema.h:49-85`)

```c
vectorBatch->SetValueAt(colIndex, rowIndex, node[name].get<int32_t>());
```

**达成路径**

JSON node -> node[name].get<T>() -> SetValueAt

**验证说明**: JSON字段类型转换缺少异常处理(line55-79)。node[name].get<T>()可能抛出type_error。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 15

---

## 4. Medium 漏洞 (11)

### [VULN-MEM-001] Out-of-bounds Read - MemorySegment::equalTo

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `cpp/core/memory/MemorySegment.cpp:171` @ `MemorySegment::equalTo`
**模块**: core_memory

**描述**: equalTo() method uses memcmp with offset parameters without bounds checking. If offsets exceed buffer sizes, this causes out-of-bounds memory reads.

**漏洞代码** (`cpp/core/memory/MemorySegment.cpp:171`)

```c
return (memcmp((offHeapBuffer_ + offset1), (seg2.offHeapBuffer_ + offset2), length) == 0);
```

**达成路径**

offset1/offset2/length parameters -> memcmp (no bounds check)

**验证说明**: memcmp使用offset参数，需验证调用方是否有边界检查。内部函数，攻击面较小。

**评分明细**: base: 30 | controllability: 10 | context: -15 | cross_file: 0 | mitigations: 0 | reachability: 30

---

### [SEC-004] Improper Input Validation - KafkaSource::KafkaSource

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `cpp/connector/kafka/source/KafkaSource.cpp:15-34` @ `KafkaSource::KafkaSource`
**模块**: connector_kafka

**描述**: Kafka配置属性直接注入。KafkaSource.cpp中从opDescriptionJSON直接读取properties并用于创建Kafka消费者，未对配置值进行验证。恶意配置可能导致Kafka连接异常或安全问题。

**漏洞代码** (`cpp/connector/kafka/source/KafkaSource.cpp:15-34`)

```c
nlohmann::json properties = opDescriptionJSON["properties"];
for (auto &[key, value] : properties.items()) {
    props.emplace(iter->second, value);
}
```

**达成路径**

opDescriptionJSON -> properties extraction -> Kafka config props

**验证说明**: Kafka配置属性直接使用，缺少验证。但配置来源为Java opDescription，非直接外部网络数据。

**评分明细**: base: 30 | controllability: 10 | context: -5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-JNI-008] Buffer Copy without Checking Size - OmniTaskBridgeImpl2::WriteSavepointOutputStream

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:1220-1221` @ `OmniTaskBridgeImpl2::WriteSavepointOutputStream`
**模块**: jni

**描述**: SetByteArrayRegion is called with offset and len parameters without bounds checking. If offset + len exceeds the byte array bounds, this could cause buffer overflow.

**漏洞代码** (`cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:1220-1221`)

```c
jbyteArray data = env->NewByteArray(len);
env->SetByteArrayRegion(data, offset, len, chunk);
```

**达成路径**

offset/len parameters (potentially tainted) -> SetByteArrayRegion (no bounds check)

**验证说明**: SetByteArrayRegion offset/len参数需进一步验证是否有边界检查。但JNIEnv API本身有一定安全机制。

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: -10 | reachability: 20

---

### [VULN-TABLE-001] Integer Overflow or Wraparound - CsvStrConverterFunc<int64_t>

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `cpp/table/sources/CsvTableSource.h:49` @ `CsvStrConverterFunc<int64_t>`
**模块**: table_sources

**描述**: std::stol() is called on CSV file content without exception handling or bounds validation. Malicious CSV content with very large numbers could cause integer overflow or exceptions.

**漏洞代码** (`cpp/table/sources/CsvTableSource.h:49`)

```c
static_cast<omniruntime::vec::Vector<int64_t>* >(vec)->SetValue(rowIndex, std::stol(inStr));
```

**达成路径**

CSV file content (File Source) -> std::stol (no validation) -> Vector SetValue

**验证说明**: std::stol转换CSV数据缺少异常处理。但CSV文件来源通常为可信配置，实际攻击需控制文件内容。

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-TABLE-003] Path Traversal - CsvLookupFunction::open

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `cpp/table/sources/CsvTableSource.h:134` @ `CsvLookupFunction::open`
**模块**: table_sources

**描述**: CSV file path from configuration could contain path traversal sequences if not validated. Malicious paths like '../../../etc/passwd' could be used to read arbitrary files.

**漏洞代码** (`cpp/table/sources/CsvTableSource.h:134`)

```c
std::ifstream file(src->getFilePath());
```

**达成路径**

filepath from config -> std::ifstream open

**验证说明**: CSV文件路径来自配置，存在path traversal风险。但文件路径通常由管理员配置而非攻击者可控。

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [SEC-007] Improper Input Validation - EventSerializer::fromSerializedEvent

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `cpp/runtime/io/network/api/serialization/EventSerializer.cpp:148-213` @ `EventSerializer::fromSerializedEvent`
**模块**: runtime_io_network

**描述**: 事件类型未完全验证。EventSerializer.cpp中eventType从缓冲区读取后直接用于switch判断，缺少对未知事件类型的完整处理，可能返回nullptr或抛出异常导致崩溃。

**漏洞代码** (`cpp/runtime/io/network/api/serialization/EventSerializer.cpp:148-213`)

```c
int eventType = byteBuffer.getIntFromValue();
if (eventType == END_OF_PARTITION_EVENT) {...} else {... return nullptr;}
```

**达成路径**

Buffer rawData -> getIntFromValue(eventType) -> switch processing

**验证说明**: eventType未完全验证，可能返回nullptr。但影响为异常处理而非安全漏洞。

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [SEC-012] Improper Input Validation - CsvLookupFunction::open

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `cpp/table/sources/CsvTableSource.h:156-158` @ `CsvLookupFunction::open`
**模块**: table_sources

**描述**: CSV数值转换缺少异常处理。CsvTableSource.h中std::stol(keyStr)直接转换CSV读取的字符串，若数据格式错误会抛出invalid_argument异常。缺少错误处理机制。

**漏洞代码** (`cpp/table/sources/CsvTableSource.h:156-158`)

```c
K key = std::stol(keyStr);
dataMap[key].push_back(irow);
```

**达成路径**

CSV file getline -> keyStr -> std::stol -> dataMap insert

**验证说明**: std::stol转换缺少异常处理。与VULN-TABLE-001重复发现。

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [SEC-014] Use of Potentially Dangerous Function - Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask

**严重性**: Medium | **CWE**: CWE-710 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `cpp/jni/tasks/jni_OmniStreamTask.cpp:25-34` @ `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask`
**模块**: jni

**描述**: 裸指针reinterpret_cast使用。jni_OmniStreamTask.cpp中statusAddress和nativeTask参数直接reinterpret_cast为指针，若Java传递无效地址可能导致非法内存访问。缺少地址有效性验证。

**漏洞代码** (`cpp/jni/tasks/jni_OmniStreamTask.cpp:25-34`)

```c
void *bufferStatus = reinterpret_cast<void *>(statusAddress);
auto task = reinterpret_cast<omnistream::OmniTask *>(nativeTask);
```

**达成路径**

JNI jlong params -> reinterpret_cast -> pointer use

**验证说明**: 与VULN-JNI-004重复发现。jlong reinterpret_cast缺少验证。JNI标准做法，实际攻击需控制Java传值。

**评分明细**: base: 30 | controllability: 10 | context: -10 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-TABLE-002] Improper Input Validation - CsvLookupFunction::CsvLookupFunction

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `cpp/table/sources/CsvTableSource.h:75-103` @ `CsvLookupFunction::CsvLookupFunction`
**模块**: table_sources

**描述**: JSON field access and parsing without validation. Missing fields or malformed JSON could cause exceptions.

**漏洞代码** (`cpp/table/sources/CsvTableSource.h:75-103`)

```c
auto lookupTypeStrs = description["lookupInputTypes"].get<std::vector<std::string>>();
```

**达成路径**

JSON description (config) -> operator[] access -> get<std::vector<std::string>> (no validation)

**验证说明**: JSON字段访问缺少验证。但description来源为配置文件而非外部网络数据。

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [SEC-005] Uncontrolled Resource Consumption - RdKafkaConsumer

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `cpp/connector/kafka/source/reader/RdKafkaConsumer.h:237-238` @ `RdKafkaConsumer`
**模块**: connector_kafka

**描述**: Kafka批量消息大小过大。RdKafkaConsumer.h中batch_size_默认值为100000，大量恶意消息可能导致内存耗尽。缺少消息大小限制和流量控制机制。

**漏洞代码** (`cpp/connector/kafka/source/reader/RdKafkaConsumer.h:237-238`)

```c
int batch_size_ = 100000; // 默认批量大小
```

**达成路径**

Kafka poll -> ConsumerRecords collection -> batch_size_ limit

**验证说明**: batch_size_默认值较大。但该参数可配置，且Kafka消费有流量控制机制。实际DoS风险需评估。

**评分明细**: base: 30 | controllability: 5 | context: -10 | cross_file: 0 | mitigations: 0 | reachability: 30

---

### [SEC-013] Race Condition - OmniAbstractStreamTaskNetworkInput::timerThread

**严重性**: Medium | **CWE**: CWE-362 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `cpp/streaming/runtime/io/OmniAbstractStreamTaskNetworkInput.h:104-120` @ `OmniAbstractStreamTaskNetworkInput::timerThread`
**模块**: streaming_runtime_io

**描述**: 定时器线程与主线程竞态条件。OmniAbstractStreamTaskNetworkInput.h中timerThread与主线程共享rowList和rowCount，存在潜在的竞态条件。mutex保护不够全面，batchStartTime在锁外更新。

**漏洞代码** (`cpp/streaming/runtime/io/OmniAbstractStreamTaskNetworkInput.h:104-120`)

```c
while (running_) {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait_for(lock, std::chrono::seconds(1), ...);
    emitCurrentBatch(output_);
}
```

**达成路径**

timerThread -> rowList/rowCount access -> emitCurrentBatch -> main thread

**验证说明**: 定时器线程竞态条件需进一步分析。mutex保护范围需验证是否充分。实际安全影响取决于共享数据的使用方式。

**评分明细**: base: 30 | controllability: 0 | context: -10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

## 5. Low 漏洞 (3)

### [VULN-JNI-001] Memory Leak - Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration

**严重性**: Low | **CWE**: CWE-401 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `cpp/jni/init.cpp:52-55` @ `Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration`
**模块**: jni

**描述**: GetStringUTFChars returns a pointer to the Java string in initTMConfiguration, but it's never released with ReleaseStringUTFChars. This causes a memory leak as the JNI memory is not freed.

**漏洞代码** (`cpp/jni/init.cpp:52-55`)

```c
const char *cStrCon = (env)->GetStringUTFChars(configStr, 0);
nlohmann::json config = nlohmann::json::parse(cStrCon);
Configuration::TM_CONFIG->setConfiguration(config);
```

**达成路径**

JNIEnv::GetStringUTFChars -> nlohmann::json::parse -> Configuration::setConfiguration (memory never released)

**验证说明**: 源代码确认缺少ReleaseStringUTFChars调用。但该函数很短且配置解析后进程继续运行，内存泄露影响有限。

**评分明细**: base: 30 | controllability: 0 | context: -10 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [SEC-002] Memory Leak - Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask

**严重性**: Low | **CWE**: CWE-401 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `cpp/jni/tasks/jni_OmniStreamTask.cpp:18-40` @ `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask`
**模块**: jni

**描述**: JNI内存释放顺序不当。jni_OmniStreamTask.cpp中ReleaseStringUTFChars在JSON解析之后调用，若解析抛出异常则字符串资源无法释放。存在异常路径下的内存泄露风险。

**漏洞代码** (`cpp/jni/tasks/jni_OmniStreamTask.cpp:18-40`)

```c
const char *cStrTDD = (env)->GetStringUTFChars(TDDString, 0);
nlohmann::json tdd = nlohmann::json::parse(cStrTDD);
...
env->ReleaseStringUTFChars(TDDString, cStrTDD);
```

**达成路径**

TDDString JNI -> GetStringUTFChars -> parse (may throw) -> ReleaseStringUTFChars (not reached on exception)

**验证说明**: 内存释放顺序不当，异常路径下可能泄露。但影响有限，仅为单个JNI字符串资源。

**评分明细**: base: 30 | controllability: 0 | context: -10 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [SEC-015] Improper Check for Unusual or Exceptional Conditions - OmniTaskBridgeImpl2::readMetaData

**严重性**: Low | **CWE**: CWE-754 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:847-850` @ `OmniTaskBridgeImpl2::readMetaData`
**模块**: jni

**描述**: JNI异常处理后继续执行。OmniTaskBridgeImpl2.cpp多处JNI调用后检查ExceptionCheck并清除异常，但函数继续执行返回空值或默认值，可能导致后续逻辑异常。缺少正确错误传播机制。

**漏洞代码** (`cpp/jni/bridge/OmniTaskBridgeImpl2.cpp:847-850`)

```c
if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
}
```

**达成路径**

JNI CallObjectMethod -> ExceptionCheck -> ExceptionClear -> continue execution

**验证说明**: JNI异常处理后继续执行存在风险。但函数有返回值处理，实际影响需评估后续逻辑是否能正确处理空值。

**评分明细**: base: 30 | controllability: 0 | context: -10 | cross_file: 0 | mitigations: 0 | reachability: 20

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| connector_kafka | 0 | 1 | 2 | 0 | 3 |
| core_memory | 0 | 0 | 1 | 0 | 1 |
| core_serialization | 0 | 1 | 0 | 0 | 1 |
| cross_module | 0 | 2 | 0 | 0 | 2 |
| jni | 0 | 9 | 2 | 3 | 14 |
| runtime_buffer | 0 | 1 | 0 | 0 | 1 |
| runtime_io_network | 0 | 2 | 1 | 0 | 3 |
| streaming_runtime_io | 0 | 2 | 1 | 0 | 3 |
| table_sources | 0 | 0 | 4 | 0 | 4 |
| **合计** | **0** | **18** | **11** | **3** | **32** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 10 | 31.3% |
| CWE-502 | 4 | 12.5% |
| CWE-125 | 3 | 9.4% |
| CWE-119 | 3 | 9.4% |
| CWE-476 | 2 | 6.3% |
| CWE-401 | 2 | 6.3% |
| CWE-754 | 1 | 3.1% |
| CWE-710 | 1 | 3.1% |
| CWE-400 | 1 | 3.1% |
| CWE-362 | 1 | 3.1% |
| CWE-22 | 1 | 3.1% |
| CWE-190 | 1 | 3.1% |
| CWE-129 | 1 | 3.1% |
| CWE-120 | 1 | 3.1% |

---

## 8. 后续验证建议

### 优先验证的漏洞

以下 LIKELY 状态漏洞建议优先进行人工验证：

1. **VULN-STREAM-002 / SEC-009** — NULL 指针解引用，需验证 ObjectSegment::getObject 返回值
2. **VULN-JNI-003** — TDD JSON 解析异常处理，需验证异常场景下的内存管理
3. **VULN-NET-001** — 网络数据长度验证，需评估 canReadRecord 检查的完整性

### 验证方法建议

| 漏洞类型 | 验证方法 |
|----------|----------|
| JSON 解析异常处理 | 构造畸形 JSON payload 进行 fuzz 测试 |
| 越界访问 | 构造超大 size/offset 值的网络数据包进行测试 |
| NULL 指针解引用 | 源代码审查 + 动态测试验证指针检查逻辑 |
| 内存泄露 | 长期运行测试 + 内存分析工具检测 |
| 竞态条件 | 多线程并发测试 + 静态分析工具检测 |

---

## 附录：与已确认漏洞的关联

以下待确认漏洞与已确认漏洞存在关联：

| 待确认漏洞 | 关联的已确认漏洞 | 关联类型 |
|------------|------------------|----------|
| VULN-STREAM-002 | VULN-STREAM-001 | 同一文件，不同风险点 (NULL vs OOB) |
| VULN-NET-001 | VULN-CROSS-004 | 同一模块，不同验证缺口 |
| SEC-003 | VULN-JNI-007 | 同一漏洞，不同发现者 |
| SEC-006 | VULN-NET-001 | 同一漏洞，不同发现者 |