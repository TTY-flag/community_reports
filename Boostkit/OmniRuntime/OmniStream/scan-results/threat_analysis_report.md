# OmniStream 威胁分析报告

> 项目路径: /home/pwn20tty/Desktop/opencode_project/kunpeng/OmniStream
> 项目类型: 分布式流处理框架（华为 OmniStream）
> 分析时间: 2026-04-19
> 语言: 纯 C/C++ (1716 个源文件，约 75000 行代码)

## 1. 项目概述

OmniStream 是华为开发的分布式流处理框架，类似于 Apache Flink，作为 Flink 的 C++ 本地执行引擎运行。项目采用 Java + C++ 混合架构：

- **Java 端**: Flink JobManager（任务调度、资源管理）
- **C++ 端**: Native TaskManager（数据流处理执行）
- **通信方式**: JNI（Java 调用 C++）
- **数据源**: Kafka、网络 Shuffle（TaskManager 间数据交换）
- **状态存储**: RocksDB + 外部分布式存储（HDFS/S3）

## 2. 攻击面分析

### 2.1 JNI 边界（Critical）

**信任边界**: Java Flink Runtime ↔ C++ Native TaskManager

**风险描述**: JNI 是 Java 和 C++ 之间的核心通信桥梁，所有数据传递都经过此边界。

**攻击入口点**:

| 入口函数 | 文件位置 | 数据来源 | 潜在威胁 |
|----------|----------|----------|----------|
| `Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration` | jni/init.cpp:50 | Java 配置 JSON | JSON 解析异常、配置注入 |
| `Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask` | jni/tasks/jni_OmniStreamTask.cpp:18 | Java TDD JSON | JSON 解析异常、内存分配失败 |
| `OmniTaskBridgeImpl2::CallMaterializeMetaData` | jni/bridge/OmniTaskBridgeImpl2.cpp:391 | C++ 状态元数据 | JSON 序列化异常、JNI 调用失败 |
| `OmniTaskBridgeImpl2::readMetaData` | jni/bridge/OmniTaskBridgeImpl2.cpp:568 | Java 状态 JSON | JSON 反序列化异常、类型转换错误 |
| `OmniTaskBridgeImpl2::getKeyGroupEntries` | jni/bridge/OmniTaskBridgeImpl2.cpp:635 | Java 字节数组 | 大量数据拷贝、内存溢出 |

**STRIDE 分析**:

| 威胁类型 | 分析 |
|----------|------|
| Spoofing | 恶意 Java 代码可伪造配置信息，导致 C++ 端行为异常 |
| Tampering | JNI 数据传递过程中可能被篡改（配置、状态、任务描述符） |
| Repudiation | JNI 调用日志不完整，难以追踪跨语言边界操作 |
| Information Disclosure | JNI 字符串/字节数组转换可能泄露敏感数据 |
| Denial of Service | JNI 调用失败可能导致 TaskManager 崩溃或挂起 |
| Elevation of Privilege | JNI 层绕过 Java 安全检查，直接操作 C++ 堆外内存 |

### 2.2 Kafka 数据源（Critical）

**信任边界**: C++ TaskManager ↔ External Kafka Brokers / Remote Data Producers

**风险描述**: Kafka 是主要的外部数据输入源，所有流数据都来自 Kafka。

**攻击入口点**:

| 入口函数 | 文件位置 | 数据来源 | 潜在威胁 |
|----------|----------|----------|----------|
| `RdKafkaConsumer::poll` | connector/kafka/source/reader/RdKafkaConsumer.cpp:55 | Kafka Broker | 完全可控的远程数据 |
| `KafkaRecordEmitter::emitRecord` | connector/kafka/source/reader/KafkaRecordEmitter.cpp:1 | Kafka 消息 | 消息反序列化、数据注入 |
| `JsonRowDataDeserializationSchema::deserialize` | core/api/common/serialization/JsonRowDataDeserializationSchema.cpp:1 | Kafka JSON | JSON 解析异常、数据污染 |

**STRIDE 分析**:

| 威胁类型 | 分析 |
|----------|------|
| Spoofing | 恶意 Kafka Producer 可发送伪造数据 |
| Tampering | Kafka 数据可能被篡改（网络攻击、Broker 被攻陷） |
| Repudiation | 缺乏数据来源审计，难以追溯恶意数据源 |
| Information Disclosure | Kafka 消息可能包含敏感信息泄露 |
| Denial of Service | 大量恶意数据可耗尽 TaskManager 内存资源 |
| Elevation of Privilege | 恶意数据可通过反序列化漏洞执行任意代码 |

### 2.3 网络 Shuffle（High）

**信任边界**: C++ TaskManager ↔ Remote TaskManagers (Netty Data Exchange)

**风险描述**: TaskManager 之间通过网络交换数据流（Shuffle），接收来自其他 TaskManager 的处理结果。

**攻击入口点**:

| 入口函数 | 文件位置 | 数据来源 | 潜在威胁 |
|----------|----------|----------|----------|
| `OmniCreditBasedSequenceNumberingViewReader::onBuffer` | runtime/io/network/netty/OmniCreditBasedSequenceNumberingViewReader.cpp:1 | 远程 TaskManager | 网络数据缓冲区 |
| `SpillingAdaptiveSpanningRecordDeserializer::setNextBuffer` | runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp:68 | Netty 缓冲区 | 缓冲区反序列化 |
| `SpillingAdaptiveSpanningRecordDeserializer::getNextRecord` | runtime/io/network/api/serialization/SpillingAdaptiveSpanningRecordDeserializer.cpp:15 | 网络数据 | 记录反序列化 |

**STRIDE 分析**:

| 威胁类型 | 分析 |
|----------|------|
| Spoofing | 恶意 TaskManager 可发送伪造数据 |
| Tampering | 网络传输中数据可能被篡改 |
| Repudiation | 缺乏数据来源验证 |
| Information Disclosure | Shuffle 数据可能泄露中间处理结果 |
| Denial of Service | 大量网络数据可耗尽缓冲区资源 |
| Elevation of Privilege | 网络反序列化漏洞可能导致远程代码执行 |

### 2.4 状态存储（Medium）

**信任边界**: C++ State Backend ↔ External Filesystem / RocksDB Storage

**风险描述**: 流处理状态存储在外部存储系统（HDFS、S3）和本地 RocksDB。

**攻击入口点**:

| 入口函数 | 文件位置 | 数据来源 | 潜在威胁 |
|----------|----------|----------|----------|
| `RocksDBStateDownloader::download` | runtime/state/rocksdb/RocksDBStateDownloader.cpp:1 | 外部存储 | 状态快照下载 |
| `RocksDBStateUploader::upload` | runtime/state/rocksdb/RocksDBStateUploader.cpp:1 | 本地状态 | 状态快照上传 |
| `FullSnapshotAsyncWriter::write` | runtime/state/FullSnapshotAsyncWriter.cpp:1 | RocksDB 状态 | 全量快照写入 |

**STRIDE 分析**:

| 威胁类型 | 分析 |
|----------|------|
| Spoofing | 状态快照可能被伪造或替换 |
| Tampering | 外部存储中的状态数据可能被篡改 |
| Repudiation | 状态恢复缺乏来源审计 |
| Information Disclosure | 状态快照可能包含敏感业务数据 |
| Denial of Service | 状态恢复失败可能导致任务无法启动 |
| Elevation of Privilege | 恶意状态快照可能导致反序列化漏洞 |

### 2.5 内存管理（Medium）

**信任边界**: C++ Internal Memory Operations ↔ Heap/Off-Heap Memory

**风险描述**: 项目使用大量堆外内存（MemorySegment）进行数据处理。

**关键函数**:

| 函数 | 文件位置 | 操作类型 | 潜在威胁 |
|------|----------|----------|----------|
| `MemorySegment::put` | core/memory/MemorySegment.cpp:73 | 内存写入 | 缓冲区溢出 |
| `MemorySegment::get` | core/memory/MemorySegment.cpp:96 | 内存读取 | 越界读取 |
| `LocalBufferPool::requestBuffer` | runtime/buffer/LocalBufferPool.cpp:1 | 缓冲区分配 | 内存耗尽 |

## 3. 关键数据流分析

### 3.1 Kafka → 算子链数据流

```
[Source: Kafka Broker]
  → RdKafkaConsumer::poll() [connector/kafka]
    → KafkaSourceReader::pollNext()
      → KafkaRecordEmitter::emitRecord()
        → JsonRowDataDeserializationSchema::deserialize() [core]
          → RowData::setField() [Sink: 内存对象]
```

**风险点**: JSON 反序列化过程中，外部可控数据直接写入 C++ 对象，可能导致：
- JSON 解析异常（格式错误、超大 JSON）
- 类型转换错误（字段类型不匹配）
- 内存分配失败（超大数据）

### 3.2 JNI 状态恢复数据流

```
[Source: Java 状态快照]
  → OmniTaskBridgeImpl2::getKeyGroupEntries() [jni]
    → JNIEnv::GetByteArrayElements() [JNI 拷贝]
      → KeyGroupEntry::KeyGroupEntry() [C++ 对象]
        → StateRestoreOperation::restoreKeyGroup() [Sink: 状态恢复]
```

**风险点**: JNI 字节数组拷贝过程中：
- 大量数据拷贝可能导致内存溢出
- 字节数组数据可能包含恶意序列化数据
- KeyGroup 反序列化可能导致对象注入

### 3.3 网络 Shuffle 数据流

```
[Source: 远程 TaskManager]
  → OmniCreditBasedSequenceNumberingViewReader::onBuffer() [netty]
    → BufferConsumer::create() [buffer]
      → SpillingAdaptiveSpanningRecordDeserializer::setNextBuffer()
        → NonSpanningWrapper::readInt() [读取长度]
          → NonSpanningWrapper::readInto() [反序列化]
            → IOReadableWritable::read() [Sink: 记录对象]
```

**风险点**: 网络反序列化过程中：
- 记录长度由网络数据指定，可能导致整数溢出
- 跨段反序列化逻辑复杂，存在边界处理风险
- 网络数据直接写入内存缓冲区

## 4. 高风险模块汇总

| 模块 | 路径 | 风险等级 | 关键威胁 |
|------|------|----------|----------|
| jni | cpp/jni | Critical | JNI 数据传递、JSON 解析、字节数组拷贝 |
| connector_kafka | cpp/connector/kafka | Critical | Kafka 数据接收、消息反序列化 |
| runtime_io_network | cpp/runtime/io/network | High | 网络 Shuffle、缓冲区反序列化 |
| runtime_buffer | cpp/runtime/buffer | High | 内存缓冲区管理、溢出风险 |
| runtime_state | cpp/runtime/state | Medium | 状态快照上传/下载、反序列化 |
| core_memory | cpp/core/memory | Medium | 堆外内存操作、边界检查 |
| streaming_runtime_io | cpp/streaming/runtime/io | High | 网络输入处理、数据流控制 |

## 5. 建议扫描重点

### 5.1 高优先级扫描方向

1. **JNI 层 JSON 解析**:
   - 搜索所有 `nlohmann::json::parse` 调用点
   - 检查是否有异常处理和数据验证
   - 关注超大 JSON 字符串处理

2. **JNI 字节数组操作**:
   - 搜索 `GetByteArrayElements` / `GetPrimitiveArrayCritical` 调用
   - 检查数组长度限制和内存分配
   - 关注拷贝后的数据使用

3. **Kafka 反序列化**:
   - 搜索 `KafkaRecordDeserializationSchema::deserialize` 实现
   - 检查 JSON 反序列化安全性
   - 关注数据注入风险

4. **网络反序列化**:
   - 搜索 `NonSpanningWrapper::readInt` / `SpanningWrapper::addNextChunk`
   - 检查长度字段处理和边界检查
   - 关注整数溢出风险

### 5.2 中优先级扫描方向

1. **内存段操作**:
   - 搜索 `MemorySegment::put` / `MemorySegment::get`
   - 检查边界检查是否完整
   - 关注 `memcpy_s` 调用参数

2. **状态上传/下载**:
   - 搜索 `RocksDBStateUploader::upload` / `RocksDBStateDownloader::download`
   - 检查文件路径处理和外部存储访问
   - 关注状态数据反序列化

## 6. CWE 威胁映射

| CWE ID | 威胁类型 | 涉及模块 |
|--------|----------|----------|
| CWE-120 | 缓冲区溢出 | runtime_buffer, core_memory |
| CWE-190 | 整数溢出 | runtime_io_network, connector_kafka |
| CWE-502 | 反序列化漏洞 | connector_kafka, runtime_state, runtime_io_network |
| CWE-78 | 命令注入 | (暂未发现) |
| CWE-22 | 路径遍历 | runtime_state (状态存储路径) |
| CWE-134 | 格式化字符串 | (暂未发现) |
| CWE-20 | 输入验证不足 | jni, connector_kafka, runtime_io_network |
| CWE-400 | 资源耗尽 | runtime_buffer, jni (大数据处理) |
| CWE-776 | XML/JSON 注入 | jni, connector_kafka, core_serialization |

## 7. 总结

OmniStream 作为分布式流处理框架，面临以下主要安全威胁：

1. **JNI 边界安全**: Java ↔ C++ 数据传递缺乏充分验证，JSON 解析和字节数组操作存在风险
2. **外部数据源安全**: Kafka 数据完全可控，反序列化过程可能被利用
3. **网络 Shuffle 安全**: 远程 TaskManager 数据缺乏来源验证，反序列化存在边界风险
4. **内存安全**: 堆外内存操作需要严格边界检查

建议后续漏洞扫描重点关注：
- JNI 层的 JSON 解析和字节数组处理
- Kafka connector 的消息反序列化
- 网络 Shuffle 的缓冲区处理和长度字段解析
- 状态快照的文件路径处理和反序列化