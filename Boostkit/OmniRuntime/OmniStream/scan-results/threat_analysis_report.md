# OmniStream 威胁分析报告

## 项目概述

**项目名称**: OmniStream  
**项目类型**: 网络服务（Flink 流处理框架 C++ 原生运行时）  
**扫描时间**: 2025-04-22  
**总文件数**: 1587  
**总代码行数**: 84104  
**LSP 可用**: 是

### 项目定位

OmniStream 是 Apache Flink 流处理框架的 C++ 原生运行时移植版本，作为 Flink TaskManager 的本地扩展，通过 JNI 与 Java Flink Runtime 交互。项目部署在分布式集群环境中，处理来自 Kafka 集群、远程 TaskManager 和文件系统的数据。

---

## 信任边界分析

### 边界 1: JNI Interface (Critical)

| 属性 | 值 |
|------|-----|
| 边界名称 | JNI Interface |
| 可信一侧 | C++ Native Runtime |
| 不可信一侧 | Java Flink Runtime |
| 风险等级 | Critical |

**分析**: JNI 是 Java 与 C++ 之间的主要通信通道。Java 侧传递配置 JSON、任务描述、内存地址等关键数据到 C++ 原生运行时。虽然 Java Flink Runtime 在同一集群部署，但作为外部进程，仍存在配置注入、内存地址伪造等风险。

### 边界 2: Network Interface (Critical)

| 属性 | 值 |
|------|-----|
| 边界名称 | Network Interface |
| 可信一侧 | TaskExecutor |
| 不可信一侧 | Remote TaskManagers / JobManager |
| 风险等级 | Critical |

**分析**: TaskManager 之间通过网络传输数据缓冲区，数据可能来自恶意节点或被网络篡改。网络数据反序列化是主要的攻击入口。

### 边界 3: Kafka Broker (Critical)

| 属性 | 值 |
|------|-----|
| 边界名称 | Kafka Broker |
| 可信一侧 | KafkaSource Reader |
| 不可信一侧 | Kafka Cluster |
| 风险等级 | Critical |

**分析**: Kafka 消息数据完全来自外部网络集群，数据内容可被 Kafka 生产者控制或被网络攻击者篡改。消息反序列化过程可能存在注入漏洞。

### 边界 4: File System (Medium)

| 属性 | 值 |
|------|-----|
| 边界名称 | File System |
| 可信一侧 | State Backend |
| 不可信一侧 | Checkpoint Files / Savepoints |
| 风险等级 | Medium |

**分析**: Checkpoint 和 Savepoint 文件存储在分布式文件系统（如 HDFS）中，文件内容可能被其他租户或攻击者篡改。文件路径来自配置，可能存在路径遍历风险。

### 边界 5: Configuration Input (High)

| 属性 | 值 |
|------|-----|
| 边界名称 | Configuration Input |
| 可信一侧 | TaskManager Configuration |
| 不可信一侧 | Configuration JSON from Java |
| 风险等级 | High |

**分析**: 配置数据通过 JNI 从 Java 侧传递，包含 JSON 格式的配置字符串。恶意配置可能导致异常行为或安全漏洞。

---

## STRIDE 威胁建模

### Spoofing (身份伪造)

| 威胁 | 风险等级 | 受影响组件 | 缓解建议 |
|------|----------|------------|----------|
| 恶意 TaskManager 节点伪造网络数据 | High | Network I/O, RecordDeserializer | 实施节点身份认证和数据签名验证 |
| Kafka 生产者伪造消息内容 | Critical | KafkaSource, DeserializationSchema | Kafka 消息验证和来源认证 |
| Checkpoint 文件被篡改伪造 | Medium | State Backend, RocksdbKeyedStateBackend | 文件完整性校验 |

### Tampering (数据篡改)

| 威胁 | 风险等级 | 受影响组件 | 缓解建议 |
|------|----------|------------|----------|
| 网络数据缓冲区被篡改 | Critical | NetworkBuffer, SpillingAdaptiveSpanningRecordDeserializer | 数据校验和完整性验证 |
| JNI 传递的配置 JSON 被篡改 | High | init.cpp, Configuration | 配置参数验证和类型检查 |
| Kafka 消息被篡改注入恶意数据 | Critical | RdKafkaConsumer, JsonRowDataDeserializationSchema | 消息内容验证和边界检查 |

### Repudiation (抵赖)

| 威胁 | 风险等级 | 受影响组件 | 缓解建议 |
|------|----------|------------|----------|
| 无法追踪恶意数据来源 | Medium | All network input paths | 实施审计日志和数据来源追踪 |
| Checkpoint 操作无审计记录 | Low | TaskStateManager | 记录关键操作日志 |

### Information Disclosure (信息泄露)

| 威胁 | 风险等级 | 受影响组件 | 缓解建议 |
|------|----------|------------|----------|
| 网络数据缓冲区内容泄露 | High | NetworkBuffer, MemorySegment | 内存加密和安全释放 |
| 配置信息泄露 | Medium | Configuration, TM_CONFIG | 配置参数脱敏 |
| 状态数据泄露 | High | RocksdbKeyedStateBackend | 状态数据加密存储 |

### Denial of Service (拒绝服务)

| 威胁 | 风险等级 | 受影响组件 | 缓解建议 |
|------|----------|------------|----------|
| 恶意 Kafka 消息导致解析失败 | High | JsonRowDataDeserializationSchema | 异常处理和资源限制 |
| 大量网络数据耗尽内存 | Critical | LocalMemoryBufferPool, NetworkBuffer | 内存配额和流量控制 |
| 无效配置导致服务崩溃 | High | init.cpp, StreamTask creation | 配置验证和容错机制 |

### Elevation of Privilege (权限提升)

| 威胁 | 风险等级 | 受影响组件 | 缓解建议 |
|------|----------|------------|----------|
| 恶意 Checkpoint 文件导致代码执行 | Critical | RocksdbKeyedStateBackend, OmniTaskBridgeImpl2 | 文件来源验证和安全加载 |
| JNI 调用绕过安全检查 | High | All JNI entry points | JNI 参数验证和访问控制 |

---

## 关键攻击面分析

### 攻击面 1: JNI 配置注入 (Critical)

**入口文件**: `cpp/jni/init.cpp`  
**入口函数**: `Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration`  
**行号**: 50-55

**攻击路径**:
```
Java 配置 JSON 字符串 -> GetStringUTFChars -> nlohmann::json::parse -> Configuration::setConfiguration
```

**潜在漏洞**:
- **JSON 解析异常**: 无校验的 `nlohmann::json::parse` 可能因恶意 JSON 导致异常或内存问题
- **配置注入**: 恶意配置值可能导致系统异常行为
- **字符串释放遗漏**: `GetStringUTFChars` 后未及时 `ReleaseStringUTFChars` 可能导致内存泄露

**风险**: CWE-20 (Improper Input Validation), CWE-74 (Injection)

### 攻击面 2: JNI 任务描述解析 (Critical)

**入口文件**: `cpp/jni/tasks/jni_OmniStreamTask.cpp`  
**入口函数**: `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask`  
**行号**: 18-40

**攻击路径**:
```
Java TDD JSON 字符串 -> GetStringUTFChars -> nlohmann::json::parse -> StreamTask 构造函数
```

**潜在漏洞**:
- **JSON 解析异常**: TDD 字符串可能包含恶意 JSON 结构
- **内存地址伪造**: `statusAddress` 和 `nativeTask` 参数为裸指针，可能被伪造导致非法内存访问
- **资源泄露**: `ReleaseStringUTFChars` 后异常可能导致 `StreamTask` 创建失败但资源未释放

**风险**: CWE-20, CWE-119 (Buffer Errors), CWE-787 (Out-of-bounds Write)

### 攻击面 3: Kafka 消息消费 (Critical)

**入口文件**: `cpp/connector/kafka/source/reader/RdKafkaConsumer.cpp`  
**入口函数**: `RdKafkaConsumer::poll`  
**行号**: 209

**攻击路径**:
```
Kafka Broker -> RdKafka::KafkaConsumer::consume -> ConsumerRecords::addRecord -> KafkaRecordEmitter::emitRecord -> DeserializationSchema::deserialize
```

**潜在漏洞**:
- **消息反序列化异常**: 恶意 Kafka 消息可能导致反序列化失败或内存问题
- **消息内容注入**: JSON 消息可能包含恶意数据结构
- **批量消息攻击**: 大量消息可能耗尽内存资源

**风险**: CWE-20, CWE-502 (Deserialization of Untrusted Data), CWE-400 (Uncontrolled Resource Consumption)

### 攻击面 4: 网络数据反序列化 (Critical)

**入口文件**: `cpp/runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp`  
**入口函数**: `SpillingAdaptiveSpanningRecordDeserializer::deserialize`  
**行号**: 1

**攻击路径**:
```
Remote TaskManager -> NetworkBuffer -> MemorySegment::get -> NonSpanningWrapper::deserialize / SpanningWrapper::add
```

**潜在漏洞**:
- **缓冲区溢出**: 网络数据长度字段可能被伪造导致读取越界
- **内存段非法访问**: MemorySegment 的 index 参数来自网络数据，可能越界
- **反序列化异常**: 恶意数据结构可能导致解析异常

**风险**: CWE-119, CWE-120 (Buffer Copy without Checking Size), CWE-125 (Out-of-bounds Read)

### 攻击面 5: 网络输入处理 (Critical)

**入口文件**: `cpp/streaming/runtime/io/OmniAbstractStreamTaskNetworkInput.h`  
**入口函数**: `OmniAbstractStreamTaskNetworkInput::emitNext`  
**行号**: 79-200

**攻击路径**:
```
CheckpointedInputGate::pollNext -> BufferOrEvent -> processBufferOrEventOptForSQL -> ObjectBuffer::GetSize -> ObjectSegment::getObject
```

**潜在漏洞**:
- **ObjectBuffer 大小伪造**: `GetSize()` 返回值来自网络，可能伪造导致内存越界
- **StreamElement 类型伪造**: `getTag()` 返回值来自网络数据，可能导致非法类型转换
- **内存回收异常**: `RecycleBuffer()` 在异常路径可能遗漏

**风险**: CWE-119, CWE-476 (NULL Pointer Dereference), CWE-416 (Use After Free)

### 攻击面 6: JSON 数据反序列化 (High)

**入口文件**: `cpp/core/api/common/serialization/JsonRowDataDeserializationSchema.h`  
**入口函数**: `JsonRowDataDeserializationSchema::deserialize`  
**行号**: 33-47

**攻击路径**:
```
Kafka/Network bytes -> nlohmann::json::parse -> node[name].get<T>() -> VectorBatch::SetValueAt
```

**潜在漏洞**:
- **JSON 解析异常**: 恶意 JSON 字节数据可能导致解析失败或内存问题
- **类型不匹配**: JSON 字段类型与预期类型不匹配可能导致异常
- **字段名注入**: 恶意字段名可能导致非法操作

**风险**: CWE-20, CWE-502

### 攻击面 7: Checkpoint 状态恢复 (High)

**入口文件**: `cpp/runtime/state/RocksdbKeyedStateBackend.h`  
**入口函数**: `RocksdbKeyedStateBackend::restore`  
**行号**: 1

**攻击路径**:
```
OmniTaskBridgeImpl2::readMetaData -> convertResult -> OmniTaskBridgeImpl2::CallDownloadFileToLocal -> RocksDB::Open
```

**潜在漏洞**:
- **文件路径注入**: Checkpoint 文件路径来自 Java 端，可能包含恶意路径
- **元数据解析异常**: JSON 元数据可能包含恶意结构
- **文件内容篡改**: Checkpoint 文件内容可能被篡改导致状态异常

**风险**: CWE-22 (Path Traversal), CWE-20, CWE-502

---

## 高风险模块分析

### 模块 1: JNI Bridge (Critical)

**路径**: `cpp/jni`  
**代码行数**: 2669  
**主要风险**: JNI 参数验证不足、内存地址传递、JSON 解析异常

**关键文件**:
| 文件 | 行数 | 风险 | 主要漏洞类型 |
|------|------|------|--------------|
| init.cpp | 55 | Critical | 配置注入、JSON 解析 |
| jni_OmniStreamTask.cpp | 71 | Critical | 任务描述注入、内存地址伪造 |
| OmniTaskBridgeImpl2.cpp | 1236 | Critical | 文件路径操作、状态恢复 |

### 模块 2: Kafka Connector (Critical)

**路径**: `cpp/connector/kafka`  
**代码行数**: 5774  
**主要风险**: 外部消息消费、反序列化异常、批量消息攻击

**关键文件**:
| 文件 | 行数 | 风险 | 主要漏洞类型 |
|------|------|------|--------------|
| KafkaSource.cpp | 56 | Critical | 配置解析、反序列化器创建 |
| RdKafkaConsumer.h | 242 | Critical | Kafka poll、消息消费 |
| KafkaPartitionSplitReader.cpp | 9548 | Critical | 分区读取、消息处理 |

### 模块 3: Network I/O (Critical)

**路径**: `cpp/runtime/io/network`  
**代码行数**: 38727  
**主要风险**: 网络数据反序列化、缓冲区溢出、内存段非法访问

**关键文件**:
| 文件 | 行数 | 风险 | 主要漏洞类型 |
|------|------|------|--------------|
| SpillingAdaptiveSpanningRecordDeserializer.cpp | 1565 | Critical | 记录反序列化、内存访问 |
| EventSerializer.cpp | 3561 | High | 事件序列化、内存操作 |

### 模块 4: Streaming I/O (Critical)

**路径**: `cpp/streaming/runtime/io`  
**代码行数**: 14709  
**主要风险**: 网络输入处理、ObjectBuffer 解析、内存回收

**关键文件**:
| 文件 | 行数 | 风险 | 主要漏洞类型 |
|------|------|------|--------------|
| OmniAbstractStreamTaskNetworkInput.h | 668 | Critical | 网络输入处理、ObjectBuffer 解析 |

### 模块 5: Buffer Management (High)

**路径**: `cpp/runtime/buffer`  
**代码行数**: 约 10000  
**主要风险**: 内存段操作、缓冲区分配、引用计数管理

**关键文件**:
| 文件 | 行数 | 风险 | 主要漏洞类型 |
|------|------|------|--------------|
| NetworkBuffer.h | 237 | High | 内存回收、引用计数 |
| LocalMemoryBufferPool.cpp | 16932 | High | 内存分配、缓冲池管理 |

### 模块 6: State Backend (High)

**路径**: `cpp/runtime/state`  
**代码行数**: 约 15000  
**主要风险**: Checkpoint 文件操作、状态恢复、RocksDB 操作

**关键文件**:
| 文件 | 行数 | 风险 | 主要漏洞类型 |
|------|------|------|--------------|
| RocksdbKeyedStateBackend.h | 34750 | High | 状态恢复、文件操作 |
| TaskStateManager.cpp | 5589 | High | checkpoint 管理 |

---

## 数据流风险分析

### 数据流 1: JNI 配置注入流 (Critical)

```
Source: JNIEnv::GetStringUTFChars (init.cpp:52)
  ↓
Process: nlohmann::json::parse (init.cpp:53)
  ↓
Sink: Configuration::setConfiguration
```

**风险点**: 
- `GetStringUTFChars` 返回的字符串未验证长度
- `json::parse` 对恶意 JSON 无防护
- 配置值未进行类型和范围验证

### 数据流 2: Kafka 消息流 (Critical)

```
Source: RdKafka::KafkaConsumer::consume
  ↓
Process: ConsumerRecords::addRecord
  ↓
Process: KafkaRecordEmitter::emitRecord
  ↓
Process: DeserializationSchema::deserialize
  ↓
Sink: VectorBatch creation
```

**风险点**:
- Kafka 消息长度未验证
- 反序列化过程对恶意数据无防护
- VectorBatch 创建可能因数据异常导致内存问题

### 数据流 3: 网络数据流 (Critical)

```
Source: CheckpointedInputGate::pollNext
  ↓
Process: OmniAbstractStreamTaskNetworkInput::emitNext
  ↓
Process: processBufferOrEventOptForSQL
  ↓
Process: ObjectSegment::getObject
  ↓
Sink: StreamRecord::getValue
```

**风险点**:
- NetworkBuffer 大小来自网络，可能伪造
- ObjectSegment 索引来自网络数据
- StreamRecord 类型转换可能非法

---

## 建议的缓解措施

### 高优先级 (Critical)

1. **JNI 参数验证**: 在所有 JNI 入口函数中添加参数验证，检查字符串长度、指针有效性、JSON 结构完整性
2. **网络数据校验**: 在反序列化前添加数据长度校验、魔术字验证、完整性校验
3. **Kafka 消息验证**: 在消息反序列化前添加消息大小限制、内容类型验证
4. **内存段边界检查**: 在所有 MemorySegment::get/put 操作中添加边界检查

### 中优先级 (High)

5. **配置值验证**: 在 Configuration::setConfiguration 中添加配置值类型和范围验证
6. **异常处理加固**: 在所有数据解析路径添加 try-catch 异常处理和资源释放
7. **Checkpoint 文件验证**: 在状态恢复前添加文件完整性校验和来源验证
8. **缓冲区配额**: 实施内存缓冲池配额限制，防止资源耗尽

### 低优先级 (Medium)

9. **审计日志**: 在关键操作点添加审计日志，记录数据来源和操作内容
10. **配置脱敏**: 对敏感配置参数进行脱敏处理

---

## 总结

OmniStream 项目作为 Flink 流处理框架的 C++ 原生运行时，具有以下关键安全特征：

1. **外部数据入口多**: JNI 配置、Kafka 消息、网络数据、Checkpoint 文件等多通道接收外部数据
2. **反序列化密集**: JSON、网络缓冲区、Kafka 消息等多处涉及数据反序列化
3. **内存操作频繁**: MemorySegment、NetworkBuffer、ObjectBuffer 等底层内存操作类较多
4. **信任边界复杂**: JNI、网络、文件系统等多信任边界交织

建议在后续漏洞扫描中重点关注：
- JNI 入口的参数验证和异常处理
- 网络数据反序列化的边界检查
- Kafka 消息反序列化的内容验证
- 内存段操作的安全性
- Checkpoint 文件恢复的安全性

---

*报告生成时间: 2025-04-22*  
*Architecture Agent 版本: 1.0*