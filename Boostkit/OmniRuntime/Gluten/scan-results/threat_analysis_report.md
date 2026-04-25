# Apache Gluten 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析由 AI 自主进行，未使用 threat.md 约束文件。

## 项目架构概览

### 项目简介

Apache Gluten 是一个用于加速 Spark SQL 的原生向量化执行引擎插件。项目通过 JNI 将 Spark 的执行计划转换为原生 C++ 执行，显著提升数据处理性能。本项目基于开源 Gluten 1.3.0 版本，接入鲲鹏自研向量化执行引擎 OmniOperator。

### 技术架构

- **主要语言**: C/C++ (727 个文件，约 119,000 行代码)
- **辅助语言**: Python (2 个工具脚本)
- **部署模式**: 编译为 `libspark_columnar_plugin.so` 动态库，部署在 Spark Executor 节点
- **通信方式**: JNI (Java Native Interface)

### 模块划分

| 模块 | 文件数 | 语言 | 风险等级 | 描述 |
|------|--------|------|----------|------|
| cpp-omni-jni | 4 | C/C++ | Critical | OmniOperator 后端 JNI 入口点 |
| cpp-omni-substrait | 4 | C/C++ | High | Substrait Plan 解析转换 |
| cpp-omni-shuffle | 4 | C/C++ | High | Shuffle 数据分割 |
| cpp-omni-io | 6 | C/C++ | Medium | 文件 I/O 和压缩 |
| cpp-ch-main | 1 | C/C++ | Critical | ClickHouse 后端主入口 |
| cpp-ch-parser | 6 | C/C++ | High | ClickHouse Plan 解析 |
| cpp-ch-shuffle | 6 | C/C++ | High | ClickHouse Shuffle |
| cpp-ch-storages | 20+ | C/C++ | High | 存储层实现 |
| cpp-core-jni | 3 | C/C++ | Critical | 核心 JNI 接口 |
| cpp-core-shuffle | 15 | C/C++ | High | 核心 Shuffle 实现 |

## 攻击面分析

### 信任边界模型

项目作为 JNI 库，主要与以下外部实体交互：

| 信任边界 | 可信侧 | 不可信侧 | 风险等级 | 说明 |
|----------|--------|----------|----------|------|
| JNI Interface | Native C++ 库 | Spark JVM 进程 | High | Spark 传入数据和配置，需要 Spark Executor 权限才能调用 |
| File System | Native 库 | HDFS/S3/本地文件系统 | Medium | 文件路径由 Spark 配置指定，属于管理员控制 |
| Protobuf Parser | 执行引擎 | 序列化 Plan 数据 | Medium | Substrait Plan 来自 Spark 序列化 |
| Shuffle Data | Shuffle 处理 | 序列化 VectorBatch | High | 大量数据传输和内存拷贝 |

### 入口点分析

项目主要入口点均为 JNI 函数，共发现 **101 个 JNI 函数入口**：

| 入口类型 | 数量 | 风险等级 | 说明 |
|----------|------|----------|------|
| Plan 解析/验证 | 15 | Critical | 接收 Substrait Plan 字节数组，进行 Protobuf 解析 |
| Shuffle 操作 | 30 | High | Shuffle Split/Write/Read 操作 |
| Runtime/内存管理 | 10 | High | Runtime 创建和内存分配 |
| 数据序列化 | 12 | Critical | Protobuf 数据反序列化 |
| 其他操作 | 44 | Medium | 配置、迭代器、结果转换等 |

### 高风险入口点

1. **Substrait Plan 解析** (Critical)
   - 入口函数: `nativeValidateWithFailureReason`, `nativeCreateKernelWithIterator`
   - 风险: 接收 Protobuf 序列化的执行计划，解析过程中可能存在整数溢出、内存越界
   - 数据来源: Spark JVM (semi_trusted)

2. **Shuffle 数据反序列化** (Critical)
   - 入口函数: `columnarShuffleParseInit`, `rowShuffleParseInit`
   - 风险: 接收 Protobuf 序列化的 VectorBatch 数据，包含大量 memcpy 操作
   - 数据来源: Shuffle 序列化数据 (semi_trusted)

3. **Shuffle Writer/Reader 创建** (High)
   - 入口函数: `nativeMake`, `make`
   - 风险: 接收文件路径、压缩配置等参数
   - 数据来源: Spark 配置 (trusted_admin)

## 模块风险评估

### STRIDE 威胁建模

| 模块 | Spoofing | Tampering | Repudiation | Info Disclosure | Denial of Service | Elevation of Privilege | 总风险 |
|------|----------|-----------|-------------|-----------------|-------------------|------------------------|--------|
| JNI 入口 | L | L | L | M | H | L | Medium |
| Substrait 解析 | L | H | L | M | H | M | High |
| Shuffle 处理 | L | H | L | M | H | L | High |
| 文件 I/O | L | M | L | M | M | L | Medium |
| 内存管理 | L | H | L | H | H | M | High |

### 关键威胁分析

#### 1. 数据篡改 (Tampering) - High

**威胁场景**: 恶意构造的 Substrait Plan 或 VectorBatch 数据可能导致：
- 解析过程中的整数溢出
- 内存分配大小计算错误
- memcpy 目标缓冲区越界

**影响模块**:
- `cpp-omni/src/substrait/SubstraitParser.cpp`
- `cpp-omni/src/jni/deserializer.cpp`
- `cpp-omni/src/shuffle/splitter.cpp`

**缓解措施**: 项目使用 `memcpy_s` (安全版本) 代替 `memcpy`，但仍有部分代码使用不安全的 `memcpy`

#### 2. 信息泄露 (Information Disclosure) - Medium

**威胁场景**: 
- 内存错误可能导致敏感数据泄露
- Shuffle 数据可能暴露查询结果

**影响模块**:
- `cpp-omni/src/jni/SparkJniWrapper.cpp`
- `cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp`

#### 3. 拒绝服务 (Denial of Service) - High

**威胁场景**:
- 恶意构造的大数据量 Plan 可耗尽内存
- 无限递归的 Plan 结构可导致栈溢出
- Protobuf 递归深度限制设置为 100000，可能过大

**影响模块**:
- `cpp-omni/src/jni/SparkJniWrapper.cpp:245` (codedStream.SetRecursionLimit(100000))

## 高风险文件列表

| 优先级 | 文件路径 | 风险等级 | 主要风险点 |
|--------|----------|----------|------------|
| 1 | cpp-omni/src/jni/SparkJniWrapper.cpp | Critical | JNI 入口点，Plan 解析，递归限制设置 |
| 2 | cpp-omni/src/jni/deserializer.cpp | Critical | Protobuf 反序列化，memcpy 操作 |
| 3 | cpp-ch/local-engine/local_engine_jni.cpp | Critical | ClickHouse JNI 主入口，大量入口函数 |
| 4 | cpp/core/jni/JniWrapper.cc | Critical | 核心 JNI 入口，Runtime/Shuffle 创建 |
| 5 | cpp-omni/src/shuffle/splitter.cpp | High | 大量 memcpy_s 操作，内存分配 |
| 6 | cpp-omni/src/substrait/SubstraitParser.cpp | High | memcpy 操作处理 decimal |
| 7 | cpp-omni/src/io/SparkFile.cc | High | 文件 open/read/write 操作 |
| 8 | cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp | High | 列数据转换，memcpy 操作 |
| 9 | cpp-ch/local-engine/Shuffle/ShuffleReader.cpp | High | Shuffle 数据读取 |
| 10 | cpp/core/shuffle/LocalPartitionWriter.cc | High | 本地分区写入，文件操作 |

## 数据流分析

### 关键数据流路径

```
Spark JVM (JNI Call)
    ↓
nativeValidateWithFailureReason() [SparkJniWrapper.cpp:237]
    ↓
CodedInputStream.ParseFromCodedStream() [Protobuf]
    ↓
SubstraitToOmniPlanValidator.Validate() [SubstraitToOmniPlanValidator.cpp]
    ↓
SubstraitParser.ParseType() [SubstraitParser.cpp:218]
    ↓
memcpy() [潜在 SINK - decimal 处理]
```

```
Spark JVM (JNI Call)
    ↓
columnarShuffleParseInit() [deserializer.cpp:26]
    ↓
VecBatch.ParseFromArray() [Protobuf]
    ↓
columnarShuffleParseBatch() [deserializer.cpp:69]
    ↓
memcpy_s() [潜在 SINK - values/offsets 拷贝]
```

```
Spark JVM (JNI Call)
    ↓
nativeMake() [SparkJniWrapper.cpp:37]
    ↓
Splitter::Make() [splitter.cpp]
    ↓
Splitter::Split() [splitter.cpp:147]
    ↓
memcpy_s() [潜在 SINK - fixed-width value buffer]
```

### 内存操作热点

| 文件 | 函数 | 操作类型 | 数据来源 |
|------|------|----------|----------|
| splitter.cpp:829 | SplitFixedWidthValueBuffer | memcpy_s | VectorBatch |
| splitter.cpp:835 | SplitFixedWidthValueBuffer | memcpy_s | VectorBatch |
| SubstraitParser.cpp:219 | GetLiteralValue<int64_t> | memcpy | Protobuf decimal |
| SubstraitParser.cpp:230 | GetLiteralValue<int128_t> | memcpy | Protobuf decimal |
| deserializer.cpp:106 | columnarShuffleParseBatch | memcpy_s | Protobuf VecBatch |
| deserializer.cpp:107 | columnarShuffleParseBatch | memcpy_s | Protobuf VecBatch |
| CHColumnToSparkRow.cpp:70 | bitmap操作 | memcpy | Column data |

## 安全加固建议

### 架构层面

1. **输入验证增强**
   - 在 Protobuf 解析前添加大小限制检查
   - 对 Substrait Plan 的递归深度设置更严格的限制（建议 < 1000）
   - 验证 VectorBatch 的行数和列数是否在合理范围内

2. **内存安全加固**
   - 将所有 `memcpy` 替换为 `memcpy_s` 或使用带边界检查的容器
   - 添加内存分配失败的统一处理路径
   - 实现内存使用的监控和限制机制

3. **错误处理改进**
   - 统一 JNI 异常处理机制
   - 添加详细的错误日志记录
   - 确保所有异常路径都正确释放资源

4. **配置安全**
   - 对文件路径进行合法性验证
   - 限制可访问的目录范围
   - 验证压缩类型和级别参数

### 代码层面

1. **SubstraitParser.cpp**
   - 第 219、230 行的 memcpy 操作应替换为 memcpy_s
   - 添加 decimal 精度和 scale 的范围验证

2. **SparkJniWrapper.cpp**
   - 第 245 行的递归限制 (100000) 应降低到更安全的值
   - 添加 planSize 的上限检查

3. **deserializer.cpp**
   - 添加 VecBatch/ProtoRowBatch 大小的合理性检查
   - 验证 typeId、precision、scale 参数范围

4. **splitter.cpp**
   - 验证 num_rows 参数的合理性
   - 添加 partition_id 范围检查 (已存在，但可增强)

## 总结

Apache Gluten 作为 Spark 的原生加速插件，主要风险来源于：

1. **JNI 数据传递**: 来自 Spark JVM 的数据和配置需要严格验证
2. **Protobuf 解析**: 序列化数据的解析存在潜在的内存安全风险
3. **Shuffle 数据处理**: 大量内存拷贝操作需要边界检查

整体风险评级：**High**（由于内存操作密集且数据来源为半信任状态）

建议后续漏洞扫描重点关注：
- JNI 入口点的输入验证
- memcpy/memcpy_s 操作的边界检查
- Protobuf 解析过程中的整数溢出
- 内存分配和释放的完整性

---

**报告生成时间**: 2026-04-22T20:55:00Z
**分析工具**: Architecture Agent
**LSP 可用性**: 不可用（使用 grep 回退分析）