# 漏洞扫描报告 — 已确认漏洞

**项目**: Apache Gluten
**扫描时间**: 2026-04-22T20:55:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描针对 Apache Gluten 项目（华为 BoostKit Spark 加速引擎）的 C/C++ Native 模块进行了深度漏洞分析，共发现 **28 个已确认漏洞**，其中 **6 个 Critical 级别**，**17 个 High 级别**。这些漏洞主要集中在 JNI 边界处理、指针注入、缓冲区溢出和输入验证缺失等关键安全问题。

**最严重的风险领域**：
1. **JNI 指针注入**（VULN-CPP-CH-001, VULN_CPP_CH_MAIN_001）：Java 侧传入的 jlong 地址直接被 reinterpret_cast 为原生指针，攻击者可控制任意内存地址，导致 use-after-free 或任意内存读写。
2. **Bzip2 解码溢出**（VULN-002）：Huffman 解码过程中 nextSym 参数可超过固定数组 yy[256] 的大小，导致堆缓冲区溢出，影响从 HDFS/S3 读取的压缩数据流。
3. **Protobuf 解析攻击**（VULN-CPP-JNI-002, VULN-CPP-JNI-003）：JNI 入口的 length 参数无验证，负数或超大值可导致内存破坏或 DoS。

**业务影响**：Apache Gluten 作为 Spark SQL 加速引擎，其 JNI 模块直接处理 Spark Executor 传递的数据。攻击者若能控制 Shuffle 数据流或 Substrait Plan，可触发上述漏洞导致 Spark Executor 崩溃、内存破坏或信息泄露，影响大数据处理任务的安全性。

**优先修复方向**：
1. 对所有 JNI 入口的 jlong 指针参数添加指针验证机制（注册表 + 魔数校验）
2. 对所有 JNI 长度参数添加边界检查（负数、最大值）
3. 对 Bzip2 解码的 nextSym 参数添加上限检查

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 64 | 41.8% |
| POSSIBLE | 35 | 22.9% |
| CONFIRMED | 28 | 18.3% |
| FALSE_POSITIVE | 26 | 17.0% |
| **总计** | **153** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 6 | 21.4% |
| High | 17 | 60.7% |
| Medium | 5 | 17.9% |
| **有效漏洞总计** | **28** | - |
| 误报 (FALSE_POSITIVE) | 26 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-002]** Buffer Overflow (Critical) - `cpp-ch/local-engine/IO/SplittableBzip2ReadBuffer.cpp:738` @ `?` | 置信度: 90
2. **[VULN-CPP-JNI-002]** Input Validation (Critical) - `cpp-omni/src/jni/deserializer.cpp:26` @ `columnarShuffleParseInit` | 置信度: 85
3. **[VULN-CPP-JNI-003]** Input Validation (Critical) - `cpp-omni/src/jni/deserializer.cpp:127` @ `rowShuffleParseInit` | 置信度: 85
4. **[VULN_CPP_CH_MAIN_001]** Improper Pointer Validation (Critical) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:280` @ `Java_org_apache_gluten_vectorized_BatchIterator_nativeHasNext` | 置信度: 85
5. **[VULN-CPP-CH-001]** Pointer Injection (Critical) - `cpp-ch/local-engine/local_engine_jni.cpp:73` @ `getColumnFromColumnVector` | 置信度: 85
6. **[JNI-003]** Missing Input Validation (Critical) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:127` @ `Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_rowShuffleParseInit` | 置信度: 85
7. **[CPP-CH-PARSER-002]** buffer_overflow (High) - `cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp:852` @ `writeUnalignedBytes` | 置信度: 90
8. **[cpp-core-jni-VULN-001]** Buffer Overflow (High) - `cpp/core/jni/JniWrapper.cc:1060` @ `Java_org_apache_gluten_vectorized_OnHeapJniByteInputStream_memCopyFromHeap` | 置信度: 85
9. **[cpp-core-jni-VULN-006]** Improper Input Validation (High) - `cpp/core/jni/JniWrapper.cc:680` @ `Java_org_apache_gluten_vectorized_NativeRowToColumnarJniWrapper_nativeConvertRowToColumnar` | 置信度: 85
10. **[cpp-core-jni-VULN-010]** Improper Input Validation (High) - `cpp/core/compute/ProtobufUtils.cc:31` @ `parseProtobuf` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_nativeMake@cpp-omni/src/jni/SparkJniWrapper.cpp` | rpc | semi_trusted | JNI 入口点，由 Spark JVM 进程调用，需要 Spark Executor 进程权限。参数来自 Spark 配置，包括分区数、压缩类型、文件路径等。 | 创建 Shuffle Splitter |
| `Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_split@cpp-omni/src/jni/SparkJniWrapper.cpp` | rpc | semi_trusted | JNI 入口点，处理 VectorBatch 数据分割，数据来自 Spark Executor | 执行 Shuffle Split 操作 |
| `Java_org_apache_gluten_vectorized_OmniPlanEvaluatorJniWrapper_nativeValidateWithFailureReason@cpp-omni/src/jni/SparkJniWrapper.cpp` | rpc | semi_trusted | JNI 入口点，接收并解析来自 Spark 的 Substrait Plan (Protobuf 序列化数据) | 验证 Substrait 执行计划 |
| `Java_org_apache_gluten_vectorized_OmniPlanEvaluatorJniWrapper_nativeCreateKernelWithIterator@cpp-omni/src/jni/SparkJniWrapper.cpp` | rpc | semi_trusted | JNI 入口点，接收 Plan 字节数组并创建执行内核 | 创建执行内核 |
| `Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_columnarShuffleParseInit@cpp-omni/src/jni/deserializer.cpp` | rpc | semi_trusted | JNI 入口点，接收 Protobuf 字节数组并解析为 VecBatch，数据来自 Shuffle 序列化 | 初始化列 Shuffle 数据解析 |
| `Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_rowShuffleParseInit@cpp-omni/src/jni/deserializer.cpp` | rpc | semi_trusted | JNI 入口点，接收 Protobuf 字节数组并解析为 ProtoRowBatch | 初始化行 Shuffle 数据解析 |
| `JNI_OnLoad@cpp-ch/local-engine/local_engine_jni.cpp` | rpc | semi_trusted | JNI 库加载入口，初始化全局状态和类引用 | JNI 库初始化 |
| `Java_org_apache_gluten_vectorized_ExpressionEvaluatorJniWrapper_nativeInitNative@cpp-ch/local-engine/local_engine_jni.cpp` | rpc | semi_trusted | JNI 入口点，接收配置 Plan 字节数组并初始化后端 | 初始化 ClickHouse 后端 |
| `JNI_OnLoad@cpp/core/jni/JniWrapper.cc` | rpc | semi_trusted | 核心 JNI 库加载入口，注册 MemoryManager 和 Runtime 工厂 | 核心 JNI 库初始化 |
| `Java_org_apache_gluten_runtime_RuntimeJniWrapper_createRuntime@cpp/core/jni/JniWrapper.cc` | rpc | semi_trusted | JNI 入口点，创建 Runtime 实例，配置来自 Spark sessionConf | 创建 Runtime |
| `Java_org_apache_gluten_memory_NativeMemoryManagerJniWrapper_create@cpp/core/jni/JniWrapper.cc` | rpc | semi_trusted | JNI 入口点，创建内存管理器 | 创建 NativeMemoryManager |
| `Java_org_apache_gluten_vectorized_PlanEvaluatorJniWrapper_nativeCreateKernelWithIterator@cpp/core/jni/JniWrapper.cc` | rpc | semi_trusted | JNI 入口点，解析 Plan 并创建结果迭代器，接收大量外部数据 | 创建执行内核和迭代器 |
| `Java_org_apache_gluten_vectorized_ShuffleWriterJniWrapper_nativeMake@cpp/core/jni/JniWrapper.cc` | rpc | semi_trusted | JNI 入口点，创建 ShuffleWriter，接收分区配置、压缩类型、文件路径等参数 | 创建 ShuffleWriter |
| `Java_org_apache_gluten_vectorized_ShuffleReaderJniWrapper_make@cpp/core/jni/JniWrapper.cc` | rpc | semi_trusted | JNI 入口点，创建 ShuffleReader | 创建 ShuffleReader |
| `FileInputStream::FileInputStream@cpp-omni/src/io/SparkFile.cc` | file | trusted_admin | 文件打开操作，路径由 Spark 配置或 Shuffle 逻辑指定，属于管理员控制的路径 | 打开文件进行读取 |
| `FileOutputStream::FileOutputStream@cpp-omni/src/io/SparkFile.cc` | file | trusted_admin | 文件创建和写入操作，路径由 Spark Shuffle 配置指定 | 创建文件进行写入 |
| `GetLiteralValue<int64_t>@cpp-omni/src/substrait/SubstraitParser.cpp` | rpc | semi_trusted | 处理 decimal 数据的 memcpy 操作，数据来自解析后的 Substrait Plan | 解析 decimal 常量值 |
| `Splitter::SplitFixedWidthValueBuffer@cpp-omni/src/shuffle/splitter.cpp` | internal | internal | 内部数据拷贝操作，数据来自已经解析的 VectorBatch | 分割固定宽度值缓冲区 |

**其他攻击面**:
- JNI Interface: 所有 JNI 函数入口点，接收来自 Spark JVM 的数据和配置
- Protobuf/Substrait Deserialization: Substrait Plan 和 VectorBatch 数据解析
- Shuffle Data Processing: Shuffle 数据的序列化/反序列化和分区处理
- File I/O: Shuffle 文件和数据文件的读写
- Memory Management: Native 内存分配和释放

---

## 3. Critical 漏洞 (6)

### [VULN-002] Buffer Overflow - unknown

**严重性**: Critical | **CWE**: CWE-787 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp-ch/local-engine/IO/SplittableBzip2ReadBuffer.cpp:738-739` @ `?`
**模块**: cpp-ch-storages
**跨模块**: cpp-ch-storages,cpp-ch-io

**描述**: memmove with size (nextSym-1)*sizeof(yy[0]) where nextSym comes from decompressed bzip2 data. If nextSym > 256, overflow of yy array (fixed size 256) occurs. nextSym is derived from Huffman decoding of potentially malformed compressed input.

**漏洞代码** (`cpp-ch/local-engine/IO/SplittableBzip2ReadBuffer.cpp:738-739`)

```c
memmove(&yy[1], &yy[0], (nextSym - 1) * sizeof(yy[0]))
```

**达成路径**

[IN] Compressed data from HDFS/S3/Local -> ReadBufferBuilder -> getAndMoveToFrontDecode()

**验证说明**: Bzip2 Huffman解码nextSym > 256可溢出yy数组(固定256大小)

**深度分析**

**根因分析**：该漏洞位于 Bzip2 解压缩的 Huffman 解码阶段（MTF - Move To Front 解码）。yy 数组是固定大小的 256 元素数组，用于存储 MTF 序列。当 nextSym（来自 Huffman 解码的符号索引）超过 16 时，代码使用 `memmove(&yy[1], &yy[0], (nextSym - 1) * sizeof(yy[0]))` 将数组元素向右移动。由于 yy 数组大小为 256，若 nextSym > 256，则 `(nextSym - 1) * sizeof(yy[0])` 会超过数组边界，导致堆溢出。

**关键代码路径**（`SplittableBzip2ReadBuffer.cpp:734-738`）：
```c
if (nextSym <= 16)
    for (Int32 j = nextSym - 1; j > 0; --j)
        yy[j] = yy[j - 1];    // 安全：编译器可能检查边界
else
    memmove(&yy[1], &yy[0], (nextSym - 1) * sizeof(yy[0]));  // 危险：无边界检查
```

**潜在利用场景**：
1. 攻击者通过控制 HDFS/S3/本地文件系统上的压缩数据文件，构造恶意 Bzip2 流
2. Huffman 解码阶段生成 nextSym > 256 的值
3. memmove 操作溢出 yy 数组边界，覆盖相邻堆内存
4. 可导致代码执行（若覆盖关键数据结构）或 DoS（崩溃）

**修复建议**：在 memmove 操作前添加边界检查：
```c
if (nextSym > 256) {
    throw Exception(ErrorCodes::LOGICAL_ERROR, "Invalid nextSym value");
}
```

---

### [VULN-CPP-JNI-002] Input Validation - columnarShuffleParseInit

**严重性**: Critical | **CWE**: CWE-20 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp-omni/src/jni/deserializer.cpp:26-36` @ `columnarShuffleParseInit`
**模块**: cpp-omni-jni

**描述**: Missing validation of JNI jint length parameter in columnarShuffleParseInit. Negative or excessively large length values passed to ParseFromArray could cause memory corruption or DoS.

**漏洞代码** (`cpp-omni/src/jni/deserializer.cpp:26-36`)

```c
vecBatch->ParseFromArray(reinterpret_cast<char*>(address), length);
```

**达成路径**

[IN] JNI:jint length -> [SINK] ParseFromArray(address, length) - no bounds check

**验证说明**: columnarShuffleParseInit中jint length参数直接传给ParseFromArray，无负数或超限验证。可导致非法内存访问或崩溃。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：该漏洞位于 columnarShuffleParseInit JNI 函数入口。Java 侧通过 JNI 调用传递两个参数：`address`（指向内存缓冲区的 jlong）和 `length`（数据长度 jint）。这两个参数直接传递给 `ParseFromArray`，没有任何验证：
- **length 参数风险**：jint 是有符号 32 位整数，若传入负数，ParseFromArray 会将其解释为巨大的正数（符号扩展）或导致解析失败。若传入超大值，可能导致非法内存访问。
- **address 参数风险**：address 直接 reinterpret_cast 为 char*，无指针有效性验证。

**关键代码路径**（`deserializer.cpp:26-34`）：
```c
JNIEXPORT jlong JNICALL
Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_columnarShuffleParseInit(
    JNIEnv *env, jobject obj, jlong address, jint length)
{
    auto *vecBatch = new spark::VecBatch();
    vecBatch->ParseFromArray(reinterpret_cast<char*>(address), length);  // 无边界检查
    return (jlong)(vecBatch);
}
```

**潜在利用场景**：
1. 攻击者通过 Shuffle 数据流注入恶意 Protobuf 数据
2. 控制 length 参数为负数或超限值
3. ParseFromArray 尝试读取非法内存地址，导致崩溃或信息泄露
4. 若解析部分成功但数据不完整，返回的 VecBatch 对象处于 undefined 状态

**修复建议**：
```c
// 添加边界验证
if (length < 0 || length > MAX_PROTOBUF_SIZE) {
    env->ThrowNew(runtimeExceptionClass, "Invalid length parameter");
    return 0;
}
if (address == 0) {
    env->ThrowNew(runtimeExceptionClass, "Invalid address parameter");
    return 0;
}
if (!vecBatch->ParseFromArray(reinterpret_cast<char*>(address), length)) {
    delete vecBatch;
    env->ThrowNew(runtimeExceptionClass, "Protobuf parse failed");
    return 0;
}
```

---

### [VULN-CPP-JNI-003] Input Validation - rowShuffleParseInit

**严重性**: Critical | **CWE**: CWE-20 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp-omni/src/jni/deserializer.cpp:127-136` @ `rowShuffleParseInit`
**模块**: cpp-omni-jni

**描述**: Missing validation of JNI jint length parameter in rowShuffleParseInit. Negative or excessively large length values passed to ParseFromArray could cause memory corruption or DoS.

**漏洞代码** (`cpp-omni/src/jni/deserializer.cpp:127-136`)

```c
protoRowBatch->ParseFromArray(reinterpret_cast<char*>(address), length);
```

**达成路径**

[IN] JNI:jint length -> [SINK] ParseFromArray(address, length) - no bounds check

**验证说明**: rowShuffleParseInit中jint length参数无验证，与VULN-CPP-JNI-002相同问题。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：该漏洞与 VULN-CPP-JNI-002 是同一模式的不同入口点。rowShuffleParseInit 用于解析行格式的 Shuffle 数据（ProtoRowBatch），同样缺少对 length 和 address 参数的验证。关键风险点：
- ParseFromArray 返回值未检查，若解析失败，ProtoRowBatch 对象处于 undefined 状态但仍被返回给 Java 侧
- 后续访问该无效对象（如 rowShuffleParseVecCount）会导致 undefined behavior

**关键代码路径**（`deserializer.cpp:127-136`）：
```c
JNIEXPORT jlong JNICALL
Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_rowShuffleParseInit(
    JNIEnv *env, jobject obj, jlong address, jint length)
{
    auto *protoRowBatch = new spark::ProtoRowBatch();
    protoRowBatch->ParseFromArray(reinterpret_cast<char*>(address), length);  // 返回值未检查
    return (jlong)(protoRowBatch);  // 无解析结果验证
}
```

**潜在利用场景**：
1. 攻击者构造格式错误的 ProtoRowBatch 数据
2. ParseFromArray 解析失败但返回 false，代码未检查该返回值
3. protoRowBatch 对象内部状态不可预测
4. 后续调用 rowShuffleParseVecCount、rowShuffleParseBatch 等函数时，访问无效对象导致崩溃或内存读取

**修复建议**：与 VULN-CPP-JNI-002 相同，需添加：
1. length 参数边界检查（负数、最大值）
2. ParseFromArray 返回值检查
3. 解析失败时的对象清理和错误抛出

---

### [VULN_CPP_CH_MAIN_001] Improper Pointer Validation - Java_org_apache_gluten_vectorized_BatchIterator_nativeHasNext

**严重性**: Critical | **CWE**: CWE-787 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:280-288` @ `Java_org_apache_gluten_vectorized_BatchIterator_nativeHasNext`
**模块**: cpp-ch-main

**描述**: JNI functions use reinterpret_cast to convert jlong addresses to object pointers (Block*, LocalExecutor*, ShuffleReader*, etc.) without validating the pointer is valid or within expected bounds. This can lead to use-after-free, invalid memory access, or memory corruption if a malicious or corrupted address is passed from Java side.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:280-288`)

```c
local_engine::LocalExecutor * executor = reinterpret_cast<local_engine::LocalExecutor *>(executor_address);
```

**达成路径**

Java jlong executor_address -> reinterpret_cast -> LocalExecutor* -> dereference

**验证说明**: Same pattern as VULN-CPP-CH-001. jlong executor_address from Java is reinterpret_cast to LocalExecutor* without validation. Direct external input with full attacker control allows arbitrary memory operations.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：该漏洞是 JNI 指针注入的典型案例。Java 侧通过 BatchIterator.nativeHasNext 传递 executor_address（jlong 类型），该地址在 C++ 侧被直接 reinterpret_cast 为 LocalExecutor* 指针，没有任何验证。这意味着：
- 攻击者可传入任意 64 位地址值
- C++ 侧将该地址当作 LocalExecutor 对象进行访问
- 若地址指向无效内存，导致崩溃（DoS）
- 若地址指向有效但非 LocalExecutor 的内存，导致内存破坏
- 若地址指向已释放的 LocalExecutor 对象，导致 use-after-free

**关键代码路径**（`local_engine_jni.cpp:277-282`）：
```c
JNIEXPORT jboolean Java_org_apache_gluten_vectorized_BatchIterator_nativeHasNext(
    JNIEnv * env, jobject /*obj*/, jlong executor_address)
{
    LOCAL_ENGINE_JNI_METHOD_START
    local_engine::LocalExecutor * executor = reinterpret_cast<local_engine::LocalExecutor *>(executor_address);
    return executor->hasNext();  // 直接解引用未验证的指针
}
```

**潜在利用场景**：
1. 攻击者通过 Java 侧的 BatchIterator 对象传入伪造的 executor_address
2. 若攻击者能控制 JNI 调用参数（通过反序列化攻击或 Spark 任务注入）
3. 传入指向已释放内存的地址 → use-after-free
4. 传入指向攻击者可控内存区域的地址 → 伪造 LocalExecutor 对象
5. executor->hasNext() 调用伪造对象的虚函数表 → 代码执行

**修复建议**：建立指针注册表机制：
```c
// 在创建 executor 时注册
static std::unordered_set<uintptr_t> valid_executors;
valid_executors.insert(reinterpret_cast<uintptr_t>(executor));

// 在使用时验证
if (!valid_executors.count(executor_address)) {
    throw Exception(ErrorCodes::LOGICAL_ERROR, "Invalid executor address");
}
// 或使用魔数校验：LocalExecutor 对象内嵌固定魔数字段
```

---

### [VULN-CPP-CH-001] Pointer Injection - getColumnFromColumnVector

**严重性**: Critical | **CWE**: CWE-20 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp-ch/local-engine/local_engine_jni.cpp:73-75` @ `getColumnFromColumnVector`
**模块**: cpp-ch-main

**描述**: Pointer injection: jlong values from Java are reinterpret_cast to native pointers without validation. Attackers could pass arbitrary jlong values causing use-after-free or arbitrary memory access.

**漏洞代码** (`cpp-ch/local-engine/local_engine_jni.cpp:73-75`)

```c
reinterpret_cast<DB::Block *>(block_address)
```

**达成路径**

[IN] jlong block_address (from Java) -> reinterpret_cast -> DB::Block*

**验证说明**: jlong block_address from Java is reinterpret_cast to DB::Block* without any validation. Attacker can pass arbitrary pointer values causing use-after-free or arbitrary memory access. Direct external input (JNI) with full attacker control.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：该漏洞是 VULN_CPP_CH_MAIN_001 的变体，同样属于 JNI 指针注入类漏洞。getColumnFromColumnVector 是一个静态辅助函数，接收 block_address（jlong）并直接 cast 为 DB::Block* 指针。该函数被多个 JNI 入口点调用，处理 ClickHouse Block 数据结构。

**关键代码路径**（`local_engine_jni.cpp:71-75`）：
```c
static DB::ColumnWithTypeAndName getColumnFromColumnVector(
    JNIEnv * /*env*/, jobject /*obj*/, jlong block_address, jint column_position)
{
    DB::Block * block = reinterpret_cast<DB::Block *>(block_address);
    return block->getByPosition(column_position);  // 直接访问未验证的指针
}
```

**风险放大因素**：
1. **静态函数**：该函数是内部辅助函数，被多处 JNI 入口调用，影响范围广
2. **column_position 参数**：jint 类型的 column_position 也未验证，若传入超限值，block->getByPosition 可能越界访问
3. **数据结构复杂性**：DB::Block 是 ClickHouse 核心数据结构，包含复杂的内存布局，伪造该对象难度高但影响严重

**潜在利用场景**：
1. 攻击者通过 JNI 调用传递伪造的 block_address
2. 若 block_address 指向攻击者可控内存区域，可伪造 DB::Block 对象
3. block->getByPosition(column_position) 尧访问伪造对象的内部数据
4. 若伪造成功，可控制返回的 ColumnWithTypeAndName 结构，进一步影响数据处理流程

**修复建议**：
1. 建立 Block 指针注册表（类似 LocalExecutor）
2. 验证 column_position 在 Block 的有效列范围内
3. 添加 Block 对象完整性校验（魔数、版本号）

---

### [JNI-003] Missing Input Validation - Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_rowShuffleParseInit

**严重性**: Critical | **CWE**: CWE-20 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:127-136` @ `Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_rowShuffleParseInit`
**模块**: cpp-omni-jni

**描述**: ParseFromArray return value is not checked in rowShuffleParseInit. If protobuf parsing fails, the ProtoRowBatch object is in an undefined state but is still returned. Subsequent functions access this invalid object, potentially causing undefined behavior.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:127-136`)

```c
auto *protoRowBatch = new spark::ProtoRowBatch();
protoRowBatch->ParseFromArray(reinterpret_cast<char*>(address), length);
// No check: if (!protoRowBatch->ParseFromArray(...)) { ... }
return (jlong)(protoRowBatch);
```

**验证说明**: ParseFromArray返回值未检查，解析失败后对象处于undefined状态，后续访问导致UB。直接JNI入口+完全可控数据源+无缓解措施。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. High 漏洞 (17)

### [CPP-CH-PARSER-002] buffer_overflow - writeUnalignedBytes

**严重性**: High | **CWE**: CWE-787 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp:852-858` @ `writeUnalignedBytes`
**模块**: cpp-ch-parser
**跨模块**: cpp-ch-parser,local-executor

**描述**: writeUnalignedBytes memcpy uses externally-controlled size parameter without buffer bounds validation. offsets[row_idx]+buffer_cursor[row_idx]+size can exceed allocated buffer causing heap overflow.

**达成路径**

[IN] src/size from column data → memcpy(buffer_address+offsets+cursor, src, size) → [OUT] heap overflow

**验证说明**: Same as cpp-ch-parser-001. Verified confirmed buffer overflow via writeUnalignedBytes.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

---

### [cpp-core-jni-VULN-001] Buffer Overflow - Java_org_apache_gluten_vectorized_OnHeapJniByteInputStream_memCopyFromHeap

**严重性**: High | **CWE**: CWE-787 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp/core/jni/JniWrapper.cc:1060-1070` @ `Java_org_apache_gluten_vectorized_OnHeapJniByteInputStream_memCopyFromHeap`
**模块**: cpp-core-jni

**描述**: Unsafe memcpy operation in memCopyFromHeap. The size parameter from JVM is used directly without bounds validation. If size is negative or exceeds source array length, this causes buffer overflow. The destAddress is also from JVM and could point to arbitrary memory.

**漏洞代码** (`cpp/core/jni/JniWrapper.cc:1060-1070`)

```c
std::memcpy(reinterpret_cast<void*>(destAddress), safeArray.elems(), size);
```

**达成路径**

JVM(size, destAddress) -> JNI(memcpy dest, source, size) -> Native Memory

**验证说明**: CONFIRMED: Direct JNI parameters (destAddress, size) used in memcpy without any validation. Attacker can pass arbitrary memory address and size, causing buffer overflow. No bounds check between size and source array length. Full control of destination address and copy size.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp-core-jni-VULN-006] Improper Input Validation - Java_org_apache_gluten_vectorized_NativeRowToColumnarJniWrapper_nativeConvertRowToColumnar

**严重性**: High | **CWE**: CWE-20 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp/core/jni/JniWrapper.cc:680-705` @ `Java_org_apache_gluten_vectorized_NativeRowToColumnarJniWrapper_nativeConvertRowToColumnar`
**模块**: cpp-core-jni

**描述**: Unsafe pointer casting in nativeCreateKernelWithIterator. Memory addresses (memoryAddress, cSchema) from JVM are directly cast to pointers without validation. Arbitrary memory addresses could lead to memory corruption.

**漏洞代码** (`cpp/core/jni/JniWrapper.cc:680-705`)

```c
reinterpret_cast<struct ArrowSchema*>(cSchema); uint8_t* address = reinterpret_cast<uint8_t*>(memoryAddress);
```

**达成路径**

JVM(cSchema, memoryAddress) -> reinterpret_cast -> Pointer Access -> ArrowSchema/Memory

**验证说明**: CONFIRMED: cSchema and memoryAddress from JVM directly cast to pointers without validation. Attacker can pass arbitrary memory addresses causing memory corruption. Full control of pointer values.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp-core-jni-VULN-010] Improper Input Validation - parseProtobuf

**严重性**: High | **CWE**: CWE-20 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp/core/compute/ProtobufUtils.cc:31-37` @ `parseProtobuf`
**模块**: cpp-core-jni
**跨模块**: cpp-core-compute

**描述**: Deep recursion limit in protobuf parsing allows DoS. The recursion limit is set to 100000 in parseProtobuf which could cause stack overflow with maliciously crafted deep protobuf messages.

**漏洞代码** (`cpp/core/compute/ProtobufUtils.cc:31-37`)

```c
codedStream.SetRecursionLimit(100000); return msg->ParseFromCodedStream(&codedStream);
```

**达成路径**

JVM(planArr) -> parseProtobuf -> SetRecursionLimit(100000) -> Stack Overflow

**验证说明**: CONFIRMED: Protobuf recursion limit set to 100000 (default is 100). Deeply nested malicious protobuf can cause stack overflow DoS. Attacker has full control over protobuf structure depth.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [JNI-007] Stack-based Buffer Overflow - Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_columnarShuffleParseBatch

**严重性**: High | **CWE**: CWE-121 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:74-77` @ `Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_columnarShuffleParseBatch`
**模块**: cpp-omni-jni

**描述**: columnarShuffleParseBatch creates VLA vecs[vecCount] based on untrusted protobuf data without validation. Large vecCount from malicious protobuf can cause stack overflow.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:74-77`)

```c
int32_t vecCount = vecBatch->veccnt(); omniruntime::vec::BaseVector* vecs[vecCount]{};
```

**验证说明**: VLA vecs[vecCount]基于protobuf数据，无上限检查。恶意protobuf指定超大vecCount导致栈溢出。直接JNI入口+完全可控。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [JNI-008] Stack-based Buffer Overflow - Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_rowShuffleParseBatch

**严重性**: High | **CWE**: CWE-121 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:174-178` @ `Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_rowShuffleParseBatch`
**模块**: cpp-omni-jni

**描述**: rowShuffleParseBatch creates VLA vecs[vecCount] based on untrusted protobuf data without validation. Additionally, omniDataTypeIds vector is sized with vecCount without bounds checking.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:174-178`)

```c
int32_t vecCount = protoRowBatch->veccnt(); omniruntime::vec::BaseVector* vecs[vecCount];
```

**验证说明**: 与JNI-007相同，rowShuffleParseBatch中VLA vecCount来自protobuf，无上限验证。栈溢出风险。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [JNI-013] Use After Free - Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_close

**严重性**: High | **CWE**: CWE-416 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:218-229` @ `Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_close`
**模块**: cpp-omni-jni

**描述**: close function deletes the splitter pointer but does not set the pointer to NULL. If close is called multiple times with the same handle, this causes use-after-free vulnerability.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:218-229`)

```c
auto splitter = reinterpret_cast<Splitter*>(splitter_addr); delete splitter; // UAF risk on repeated calls - no NULL after delete
```

**验证说明**: close函数delete splitter后未置NULL，多次调用同一handle导致use-after-free。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp-core-jni-VULN-014] Path Traversal - Java_org_apache_gluten_vectorized_PlanEvaluatorJniWrapper_injectWriteFilesTempPath

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp/core/jni/JniWrapper.cc:399-408` @ `Java_org_apache_gluten_vectorized_PlanEvaluatorJniWrapper_injectWriteFilesTempPath`
**模块**: cpp-core-jni
**跨模块**: cpp-core-compute

**描述**: Unsafe temp path injection in injectWriteFilesTempPath. The path byte array from JVM is converted to string and used as temp path without validation. Path traversal characters could escape intended directories.

**漏洞代码** (`cpp/core/jni/JniWrapper.cc:399-408`)

```c
std::string pathStr(reinterpret_cast<char*>(safeArray.elems()), len); *Runtime::localWriteFilesTempPath() = pathStr;
```

**达成路径**

JVM(path) -> ByteArray -> String -> Runtime::localWriteFilesTempPath()

**验证说明**: CONFIRMED: Path byte array from JVM used as temp path without validation. Attacker has full control over path content including traversal characters '../'. Direct assignment to Runtime::localWriteFilesTempPath().

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp-core-jni-VULN-015] Improper Input Validation - Java_org_apache_gluten_vectorized_ColumnarBatchSerializerJniWrapper_deserializeDirect

**严重性**: High | **CWE**: CWE-20 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp/core/jni/JniWrapper.cc:1203-1217` @ `Java_org_apache_gluten_vectorized_ColumnarBatchSerializerJniWrapper_deserializeDirect`
**模块**: cpp-core-jni

**描述**: Unsafe memory address in deserializeDirect. The address parameter from JVM is used as raw memory pointer without validation. This allows arbitrary memory read/write operations.

**漏洞代码** (`cpp/core/jni/JniWrapper.cc:1203-1217`)

```c
auto batch = serializer->deserialize((uint8_t*)address, size);
```

**达成路径**

JVM(address, size) -> reinterpret_cast -> deserialize -> Memory Access

**验证说明**: CONFIRMED: address from JVM cast to uint8_t* without validation in deserializeDirect. Arbitrary memory address allows memory read from any location. Full control of address parameter.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CPP-CH-PARSER-004] buffer_overflow - readDecimal

**严重性**: High | **CWE**: CWE-787 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp-ch/local-engine/Parser/SparkRowToCHColumn.cpp:172-174` @ `readDecimal`
**模块**: cpp-ch-parser
**跨模块**: cpp-ch-parser,spark-row

**描述**: readDecimal memcpy: length parameter from external buffer can exceed sizeof(Decimal128) causing stack buffer overflow in decimal128_fix_data array.

**达成路径**

[IN] length from SparkRow buffer → memcpy(decimal128_fix_data+sizeof(Decimal128)-length, buffer, length) [OUT] stack overflow

**验证说明**: readDecimal assert (line 163) only active in debug builds. In release, length > sizeof(Decimal128) causes stack buffer overflow via memcpy at line 172.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SHUFFLE-001] Buffer Overflow - ReadBufferFromJavaInputStream::nextImpl

**严重性**: High | **CWE**: CWE-120 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp-ch/local-engine/Shuffle/ShuffleReader.cpp:68-74` @ `ReadBufferFromJavaInputStream::nextImpl`
**模块**: cpp-ch-shuffle

**描述**: JNI read buffer overflow risk: safeCallIntMethod returns count from Java without validating against internal_buffer size. If count > internal_buffer.size(), working_buffer.resize(count) at line 72 may exceed allocated buffer capacity.

**漏洞代码** (`cpp-ch/local-engine/Shuffle/ShuffleReader.cpp:68-74`)

```c
int count = readFromJava();\nif (count > 0)\n    working_buffer.resize(count);
```

**达成路径**

[IN] JNI Java InputStream -> [BUFFER] internal_buffer -> [OUT] working_buffer

**验证说明**: Duplicate/near-duplicate of SHUFFLE-006. JNI read returns count without validation against buffer capacity. If count > internal_buffer.size(), working_buffer.resize(count) exceeds allocated memory.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-001] Buffer Overflow - unknown

**严重性**: High | **CWE**: CWE-120 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp-ch/local-engine/IO/SplittableBzip2ReadBuffer.cpp:234-236` @ `?`
**模块**: cpp-ch-storages
**跨模块**: cpp-ch-storages,cpp-ch-io

**描述**: memcpy copies last_incomplete_line to dest buffer without verifying dest capacity. If last_incomplete_line.size() exceeds dest_size (internal_buffer.size()), buffer overflow occurs during bzip2 decompression.

**漏洞代码** (`cpp-ch/local-engine/IO/SplittableBzip2ReadBuffer.cpp:234-236`)

```c
memcpy(dest, last_incomplete_line.data(), last_incomplete_line.size())
```

**达成路径**

[IN] ReadBufferBuilder.cpp:wrapWithBzip2() -> SplittableBzip2ReadBuffer::nextImpl()

**验证说明**: Bzip2解压缩memcpy无缓冲区大小验证，恶意压缩数据可触发溢出

---

### [SHUFFLE-006] JNI Buffer Pointer Exposure - ReadBufferFromJavaInputStream::readFromJava

**严重性**: High | **CWE**: CWE-125 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp-ch/local-engine/Shuffle/ShuffleReader.cpp:76-82` @ `ReadBufferFromJavaInputStream::readFromJava`
**模块**: cpp-ch-shuffle
**跨模块**: cpp-ch-jni,cpp-core-jni

**描述**: In ShuffleReader::readFromJava(), internal_buffer.begin() pointer is passed to JNI via reinterpret_cast<jlong>. If Java side writes beyond the returned count or returns corrupted count value, this could lead to out-of-bounds memory access or information disclosure.

**漏洞代码** (`cpp-ch/local-engine/Shuffle/ShuffleReader.cpp:76-82`)

```c
safeCallIntMethod(env, java_in, ShuffleReader::input_stream_read, reinterpret_cast<jlong>(internal_buffer.begin()), internal_buffer.size())
```

**达成路径**

JNI buffer pointer -> Java InputStream -> read result -> buffer resize

**验证说明**: JNI buffer pointer passed to Java without return value validation. Java InputStream receives buffer pointer and size, but can (1) write beyond buffer size causing memory corruption, or (2) return count > internal_buffer.size() causing working_buffer.resize(count) overflow.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CPP-OMNI-COMPUTE-002] Resource Exhaustion - ParseProtobuf

**严重性**: High | **CWE**: CWE-400 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp-omni/src/compute/ProtobufUtils.h:15-16` @ `ParseProtobuf`
**模块**: cpp-omni-compute
**跨模块**: cpp-omni-jni,cpp-omni-compute,cpp-omni-substrait

**描述**: Protobuf recursion limit set to 100000 (default is 100). Malicious deeply nested Substrait Plan could cause stack exhaustion or DoS

**漏洞代码** (`cpp-omni/src/compute/ProtobufUtils.h:15-16`)

```c
codedStream.SetRecursionLimit(100000); return msg->ParseFromCodedStream(&codedStream);
```

**达成路径**

JNI planArray -> ParseProtobuf -> SetRecursionLimit(100000) -> stack exhaustion

**验证说明**: CONFIRMED: Protobuf recursion limit set to 100000 (1000x default) in ProtobufUtils.h:15 and SparkJniWrapper.cpp:245. JNI receives planArray from untrusted Spark JVM (High risk boundary per project_model). Deeply nested Substrait plans can exhaust stack. No mitigations - recursion limit is raised, not lowered. Direct external input via JNI with full attacker control over protobuf content.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp-ch-parser-001] Buffer Overflow - VariableLengthDataWriter::writeUnalignedBytes

**严重性**: High | **CWE**: CWE-787 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp:852-857` @ `VariableLengthDataWriter::writeUnalignedBytes`
**模块**: cpp-ch-parser
**跨模块**: cpp-ch-parser → jni-interface

**描述**: memcpy in writeUnalignedBytes writes data to buffer_address + offsets[row_idx] + buffer_cursor[row_idx] without validating that the target address is within allocated buffer bounds. The offsets and buffer_cursor values come from calculated sizes which could be manipulated by malicious input data in SparkRow format.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp:852-857`)

```c
memcpy(buffer_address + offsets[row_idx] + buffer_cursor[row_idx], src, size);
```

**达成路径**

Spark Row data -> VariableLengthDataWriter::write -> writeUnalignedBytes -> memcpy to unvalidated buffer offset

**验证说明**: memcpy in writeUnalignedBytes writes to buffer_address+offsets[row_idx]+buffer_cursor[row_idx] without bounds validation. offsets and buffer_cursor derived from external column data sizes. Size parameter fully controlled by attacker via column content. No bounds check between calculated offset+size and allocated total_bytes.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp-ch-parser-003] Out-of-bounds Read - VariableLengthDataReader::readArray

**严重性**: High | **CWE**: CWE-125 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/SparkRowToCHColumn.cpp:187-248` @ `VariableLengthDataReader::readArray`
**模块**: cpp-ch-parser
**跨模块**: cpp-ch-parser → jni-interface

**描述**: readArray reads num_elems from buffer without validating bounds. Maliciously large num_elems could cause out-of-bounds reads.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/SparkRowToCHColumn.cpp:187-248`)

```c
memcpy(&num_elems, buffer, 8); calculateBitSetWidthInBytes(num_elems);
```

**达成路径**

Spark Row buffer -> num_elems -> out-of-bounds risk

**验证说明**: readArray reads num_elems directly from buffer (line 192) without validating against length parameter. If num_elems * element_size > length, out-of-bounds reads occur in the loop. Also num_elems used for array.reserve() can cause memory exhaustion.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [cpp-ch-parser-007] Out-of-bounds Read - VariableLengthDataReader::readArray

**严重性**: High | **CWE**: CWE-125 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/SparkRowToCHColumn.cpp:234-241` @ `VariableLengthDataReader::readArray`
**模块**: cpp-ch-parser
**跨模块**: cpp-ch-parser → jni-interface

**描述**: readArray uses buffer+offset without validating offset+size within buffer bounds.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/SparkRowToCHColumn.cpp:234-241`)

```c
reader.read(buffer + offset, size);
```

**达成路径**

Spark Row -> offset_and_size -> unvalidated buffer access

**验证说明**: readArray extracts offset_and_size from buffer (line 235) and uses offset directly for buffer access (line 239). No validation that offset+size <= length parameter. Attacker-controlled offset can cause out-of-bounds read.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. Medium 漏洞 (5)

### [VULN-CPP-JNI-008] Buffer Overflow - rowShuffleParseBatch

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp-omni/src/jni/deserializer.cpp:201-206` @ `rowShuffleParseBatch`
**模块**: cpp-omni-jni

**描述**: Potential buffer overflow in rowShuffleParseBatch: offsets[i] from protobuf used to calculate rowPtr without bounds validation. Could read beyond rows buffer if offsets contain malicious values.

**漏洞代码** (`cpp-omni/src/jni/deserializer.cpp:201-206`)

```c
char *rowPtr = rows + offsets[i]; parser->ParseOneRow(reinterpret_cast<uint8_t*>(rowPtr), vecs, i);
```

**达成路径**

[IN] ProtoRowBatch.rows + offsets[i] -> [SINK] ParseOneRow - no bounds check on offsets

**验证说明**: Buffer overread confirmed: same vulnerability as JNI-015. offsets[i] from protobuf used without bounds validation in rowShuffleParseBatch.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CPP-JNI-009] Input Validation - columnarShuffleParseBatch

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `cpp-omni/src/jni/deserializer.cpp:76-77` @ `columnarShuffleParseBatch`
**模块**: cpp-omni-jni

**描述**: VLA array vecs[vecCount] created using protobuf vecCount without validation. Negative or excessively large vecCount could cause stack overflow or memory corruption.

**漏洞代码** (`cpp-omni/src/jni/deserializer.cpp:76-77`)

```c
omniruntime::vec::BaseVector* vecs[vecCount]{};
```

**达成路径**

[IN] protobuf:vecCount -> [SINK] VLA vecs[vecCount] - no bounds validation

**验证说明**: Stack overflow confirmed: vecCount from protobuf used in VLA vecs[vecCount] without validation. Negative or huge vecCount causes stack overflow or memory corruption.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [JNI-015] Integer Overflow or Wraparound - Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_rowShuffleParseBatch

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:200-206` @ `Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_rowShuffleParseBatch`
**模块**: cpp-omni-jni

**描述**: Integer multiplication rowCount * columnType could overflow when rowCount comes from untrusted protobuf data. The offsets array is used with offsets[i] to access row data without bounds validation, potentially causing buffer overread.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:200-206`)

```c
char *rows = const_cast<char*>(protoRowBatch->rows().data());
const int32_t *offsets = reinterpret_cast<const int32_t*>(protoRowBatch->offsets().data());
for (auto i = 0; i < rowCount; ++i) {
    char *rowPtr = rows + offsets[i];  // No bounds validation on offsets[i]
    parser->ParseOneRow(reinterpret_cast<uint8_t*>(rowPtr), vecs, i);
}
```

**验证说明**: Buffer overread confirmed: offsets[i] from protobuf used directly without bounds validation. Attacker can craft malicious protobuf with offsets exceeding rows buffer size.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [JNI-009] Memory Leak - Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_nativeMake

**严重性**: Medium | **CWE**: CWE-401 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:53-67` @ `Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_nativeMake`
**模块**: cpp-omni-jni

**描述**: GetStringUTFChars is called for jInputType but ReleaseStringUTFChars is never called, causing a memory leak of JNI string resources. This can lead to resource exhaustion in long-running Spark executor processes.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:53-67`)

```c
const char *inputTypeCharPtr = env->GetStringUTFChars(jInputType, JNI_FALSE); // Missing: env->ReleaseStringUTFChars(jInputType, inputTypeCharPtr);
```

**验证说明**: GetStringUTFChars获取inputTypeCharPtr后无ReleaseStringUTFChars。长期运行的Spark executor会累积JNI内存泄漏。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [JNI-010] Injection - Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_nativeMake

**严重性**: Medium | **CWE**: CWE-74 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:103-105` @ `Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_nativeMake`
**模块**: cpp-omni-jni

**描述**: setenv is called with local_dirs from JVM without validation. This allows manipulation of NATIVESQL_SPARK_LOCAL_DIRS environment variable, potentially redirecting file operations to attacker-controlled paths.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:103-105`)

```c
auto local_dirs = env->GetStringUTFChars(local_dirs_jstr, JNI_FALSE); setenv("NATIVESQL_SPARK_LOCAL_DIRS", local_dirs, 1);
```

**验证说明**: setenv直接使用Java传入的local_dirs设置NATIVESQL_SPARK_LOCAL_DIRS环境变量，无验证。可影响后续文件操作路径。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cpp-ch-main | 2 | 0 | 0 | 0 | 2 |
| cpp-ch-parser | 0 | 5 | 0 | 0 | 5 |
| cpp-ch-shuffle | 0 | 2 | 0 | 0 | 2 |
| cpp-ch-storages | 1 | 1 | 0 | 0 | 2 |
| cpp-core-jni | 0 | 5 | 0 | 0 | 5 |
| cpp-omni-compute | 0 | 1 | 0 | 0 | 1 |
| cpp-omni-jni | 3 | 3 | 5 | 0 | 11 |
| **合计** | **6** | **17** | **5** | **0** | **28** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 8 | 28.6% |
| CWE-787 | 6 | 21.4% |
| CWE-125 | 3 | 10.7% |
| CWE-120 | 3 | 10.7% |
| CWE-121 | 2 | 7.1% |
| CWE-74 | 1 | 3.6% |
| CWE-416 | 1 | 3.6% |
| CWE-401 | 1 | 3.6% |
| CWE-400 | 1 | 3.6% |
| CWE-22 | 1 | 3.6% |
| CWE-190 | 1 | 3.6% |

## 8. 修复建议

### 优先级 1: 立即修复（Critical 漏洞）

**JNI 指针注入漏洞（VULN-CPP-CH-001, VULN_CPP_CH_MAIN_001）**

1. **建立指针注册表机制**：
   - 在创建 Native 对象（LocalExecutor、Block、Splitter 等）时，将指针地址注册到全局安全的哈希表
   - 在 JNI 入口函数中，先验证传入的 jlong 地址是否在注册表中
   - 对象销毁时从注册表移除

2. **添加对象完整性校验**：
   - 在关键 Native 对象结构中嵌入魔数字段（如 `magic = 0xDEADBEEF`）
   - JNI 入口函数在 reinterpret_cast 后立即检查魔数
   - 若魔数不匹配，抛出异常并拒绝访问

3. **使用智能指针封装**：
   - 将裸指针替换为 std::shared_ptr 或 std::unique_ptr
   - JNI 侧传递的是智能指针的控制块地址，而非直接内存地址

**Protobuf 解析输入验证（VULN-CPP-JNI-002, VULN-CPP-JNI-003, JNI-003）**

1. **添加 length 参数边界检查**：
   ```c
   const int MAX_PROTOBUF_SIZE = 100 * 1024 * 1024; // 100MB 上限
   if (length < 0 || length > MAX_PROTOBUF_SIZE) {
       env->ThrowNew(runtimeExceptionClass, "Invalid protobuf length");
       return 0;
   }
   ```

2. **检查 ParseFromArray 返回值**：
   ```c
   if (!vecBatch->ParseFromArray(reinterpret_cast<char*>(address), length)) {
       delete vecBatch;
       env->ThrowNew(runtimeExceptionClass, "Protobuf parse failed");
       return 0;
   }
   ```

**Bzip2 解码溢出（VULN-002）**

1. **添加 nextSym 上限检查**：
   ```c
   const int YY_ARRAY_SIZE = 256;
   if (nextSym > YY_ARRAY_SIZE) {
       throw Exception(ErrorCodes::LOGICAL_ERROR, 
           "Invalid Huffman symbol index: {}", nextSym);
   }
   ```

2. **添加解压缩数据大小限制**：对从 HDFS/S3 读取的压缩数据添加最大解压大小限制，防止恶意超大压缩流耗尽内存。

---

### 优先级 2: 短期修复（High 漏洞）

**缓冲区溢出漏洞（CWE-787, CWE-120）**

| 漏洞类型 | 修复方案 |
|---------|---------|
| memcpy/memmove 边界溢出 | 所有 memcpy 操作前添加 `dest_size >= src_size` 检查 |
| VLA 栈溢出（JNI-007, JNI-008） | 替换 VLA 为 std::vector，添加 vecCount 上限检查（如 `vecCount <= 10000`）|
| SparkRow 解析溢出（CPP-CH-PARSER 系列） | 对 offset/size 参数添加边界验证，确保 `offset + size <= buffer_length` |

**路径遍历漏洞（cpp-core-jni-VULN-014）**

1. **路径规范化**：使用 `canonicalize()` 或 `realpath()` 规范化路径
2. **路径验证**：检查规范化后的路径是否在预期的基目录内
   ```c
   std::string canonical_path = std::filesystem::canonical(pathStr);
   std::string base_dir = "/tmp/gluten_write";
   if (!canonical_path.starts_with(base_dir)) {
       throw Exception("Path traversal detected");
   }
   ```

**资源耗尽漏洞（CWE-400）**

| 漏洞位置 | 当前值 | 建议值 |
|---------|--------|--------|
| ProtobufUtils.h:15 | 100000 | 100（默认值）或 1000 |
| ProtobufUtils.cc:31 | 100000 | 同上 |

修复：将递归限制降低到合理范围（100-1000），防止深度嵌套的 Protobuf 消息导致栈溢出。

---

### 优先级 3: 计划修复（Medium 漏洞）

**内存泄漏（JNI-009）**

对所有 JNI 函数中的 GetStringUTFChars 调用，确保在函数结束前调用 ReleaseStringUTFChars：
```c
const char *inputTypeCharPtr = env->GetStringUTFChars(jInputType, JNI_FALSE);
// ... 使用 inputTypeCharPtr ...
env->ReleaseStringUTFChars(jInputType, inputTypeCharPtr); // 必须添加
```

**环境变量注入（JNI-010）**

对 setenv 调用的参数进行验证：
```c
// 验证 local_dirs 不包含危险字符
if (local_dirs.find("..") != std::string::npos || 
    local_dirs.find("/") != 0) {
    throw Exception("Invalid local_dirs path");
}
setenv("NATIVESQL_SPARK_LOCAL_DIRS", local_dirs, 1);
```

---

### 通用安全加固建议

1. **JNI 边界安全框架**：建立统一的 JNI 参数验证框架，包括：
   - 指针地址验证（注册表机制）
   - 整数参数范围验证（负数、最大值）
   - 数组/缓冲区边界验证
   - 字符串参数规范化

2. **模糊测试**：对 JNI 入口点进行模糊测试，验证：
   - Shuffle 数据解析（VecBatch、ProtoRowBatch）
   - Substrait Plan 解析
   - SparkRow 格式解析

3. **安全编码培训**：对开发团队进行 C/C++ 安全编码培训，重点关注：
   - CWE-20（输入验证）
   - CWE-787（缓冲区溢出）
   - CWE-416（Use-After-Free）
