# 漏洞扫描报告 — 待确认漏洞

**项目**: Apache Gluten
**扫描时间**: 2026-04-22T20:55:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| Critical | 2 | 2.1% |
| High | 26 | 26.8% |
| Medium | 50 | 51.5% |
| Low | 19 | 19.6% |
| **有效漏洞总计** | **97** | - |
| 误报 (FALSE_POSITIVE) | 26 | - |

### 1.3 Top 10 关键漏洞

1. **[JNI-001]** Out-of-bounds Write (Critical) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:69` @ `Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_columnarShuffleParseBatch` | 置信度: 75
2. **[JNI-004]** Out-of-bounds Write (Critical) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:169` @ `Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_rowShuffleParseBatch` | 置信度: 75
3. **[VULN-CH-STORAGE-001]** Path Traversal (High) - `cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:232` @ `LocalFileReadBufferBuilder::build` | 置信度: 85
4. **[CPP-SHUFFLE-010]** Integer Overflow (High) - `cpp/core/shuffle/LocalPartitionWriter.cc:407` @ `init` | 置信度: 85
5. **[VULN-CPP-JNI-001]** Buffer Overflow (High) - `cpp-omni/src/jni/deserializer.cpp:106` @ `columnarShuffleParseBatch` | 置信度: 80
6. **[VULN-CH-STORAGE-004]** SSRF (High) - `cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:522` @ `S3FileReadBufferBuilder::getClient` | 置信度: 80
7. **[VULN-SHUFFLE-008]** Unvalidated Index (High) - `cpp-ch/local-engine/Shuffle/NativeSplitter.cpp:199` @ `HashNativeSplitter::HashNativeSplitter` | 置信度: 75
8. **[VULN-SHUFFLE-009]** Memory Safety (High) - `cpp-ch/local-engine/Shuffle/NativeSplitter.cpp:113` @ `NativeSplitter::hasNext` | 置信度: 75
9. **[VULN-004]** Buffer Overflow (High) - `cpp-ch/local-engine/IO/SplittableBzip2ReadBuffer.cpp:720` @ `?` | 置信度: 75
10. **[SHUFFLE-001]** Improper Array Index Validation (High) - `cpp-ch/local-engine/Shuffle/NativeSplitter.cpp:199` @ `HashNativeSplitter::HashNativeSplitter` | 置信度: 75

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

## 3. Critical 漏洞 (2)

### [JNI-001] Out-of-bounds Write - Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_columnarShuffleParseBatch

**严重性**: Critical | **CWE**: CWE-787 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:69-123` @ `Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_columnarShuffleParseBatch`
**模块**: cpp-omni-jni

**描述**: columnarShuffleParseBatch does not validate that Java arrays (typeIdArray, precisionArray, scaleArray, vecNativeIdArray) have sufficient length for vecCount elements from protobuf. The vecCount value comes from untrusted protobuf data parsed earlier without validation, allowing out-of-bounds array writes if Java arrays are smaller than vecCount.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:69-123`)

```c
jint *typeIdArrayElements = env->GetIntArrayElements(typeIdArray, NULL);
// No validation: env->GetArrayLength(typeIdArray) >= vecCount
for (auto i = 0; i < vecCount; ++i) {
    typeIdArrayElements[i] = ...; // OOB write possible
}
```

**验证说明**: vecCount来自protobuf数据，Java数组长度未验证。若vecCount>数组长度导致OOB写。需恶意protobuf配合Java端预分配数组大小不匹配。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [JNI-004] Out-of-bounds Write - Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_rowShuffleParseBatch

**严重性**: Critical | **CWE**: CWE-787 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:169-219` @ `Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_rowShuffleParseBatch`
**模块**: cpp-omni-jni

**描述**: rowShuffleParseBatch does not validate that Java arrays have sufficient length for vecCount elements. The vecCount comes from untrusted protobuf data without bounds validation against Java array sizes, allowing out-of-bounds array writes.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:169-219`)

```c
jint *typeIdArrayElements = env->GetIntArrayElements(typeIdArray, NULL); for (; pos < vecCount; ++pos) { typeIdArrayElements[pos] = ...; }
```

**验证说明**: 与JNI-001相同模式，rowShuffleParseBatch中vecCount来自protobuf，Java数组边界未验证。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. High 漏洞 (26)

### [VULN-CH-STORAGE-001] Path Traversal - LocalFileReadBufferBuilder::build

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:232-248` @ `LocalFileReadBufferBuilder::build`
**模块**: cpp-ch-storages

**描述**: LocalFileReadBufferBuilder::build() directly uses URI path without validation. Attacker can construct malicious file:// URIs to read arbitrary files or use path traversal sequences to escape intended directories.

**漏洞代码** (`cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:232-248`)

```c
const String & file_path = file_uri.getPath();
if (stat(file_path.c_str(), &file_stat))
    throw DB::Exception(DB::ErrorCodes::BAD_ARGUMENTS, "file stat failed for {}", file_path);
if (S_ISREG(file_stat.st_mode))
    read_buffer = std::make_unique<DB::ReadBufferFromFilePRead>(file_path);
```

**验证说明**: LocalFileReadBufferBuilder直接使用URI路径，无路径遍历验证（../检查缺失）

---

### [CPP-SHUFFLE-010] Integer Overflow - init

**严重性**: High | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp/core/shuffle/LocalPartitionWriter.cc:407-408` @ `init`
**模块**: cpp-core-shuffle

**描述**: numPartitions_ resize without validation. Extremely large numPartitions could cause vector allocation failure or integer overflow in partition indexing.

**漏洞代码** (`cpp/core/shuffle/LocalPartitionWriter.cc:407-408`)

```c
partitionLengths_.resize(numPartitions_, 0)
```

**达成路径**

[IN] numPartitions (from Java) -> init -> resize [OUT]

**验证说明**: numPartitions from JNI parameter without validation. resize(numPartitions_) can cause memory exhaustion if extremely large value passed. Attack path exists if attacker controls Spark shuffle partition count config.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CPP-JNI-001] Buffer Overflow - columnarShuffleParseBatch

**严重性**: High | **CWE**: CWE-120 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-omni/src/jni/deserializer.cpp:106-110` @ `columnarShuffleParseBatch`
**模块**: cpp-omni-jni

**描述**: Unvalidated memcpy_s using protobuf sizes as destination size. The destination buffer from UnsafeGetValues/ExpandStringBuffer may not match the source size from protobuf, leading to potential buffer overflow.

**漏洞代码** (`cpp-omni/src/jni/deserializer.cpp:106-110`)

```c
memcpy_s(valuesAddress, protoVec.values().size(), values, protoVec.values().size());
```

**达成路径**

[IN] JNI:jbyteArray -> Protobuf:VecBatch -> [SINK] memcpy_s(dest, proto_size, src, proto_size)

**验证说明**: memcpy_s使用protobuf size作为dest参数，ExpandStringBuffer已按该size分配。但UnsafeGetValues返回buffer大小未验证，仍需确认。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-CH-STORAGE-004] SSRF - S3FileReadBufferBuilder::getClient

**严重性**: High | **CWE**: CWE-918 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:522-531` @ `S3FileReadBufferBuilder::getClient`
**模块**: cpp-ch-storages

**描述**: S3 endpoint URL is taken from configuration and only validated for https:// prefix. No validation against allowlisted domains, potentially enabling SSRF attacks to internal services.

**漏洞代码** (`cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:522-531`)

```c
auto endpoint = getSetting(settings, bucket_name, BackendInitializerUtil::HADOOP_S3_ENDPOINT, "https://s3.us-west-2.amazonaws.com");
if (!endpoint.starts_with("https://")) {
    if (endpoint.starts_with("s3"))
        endpoint = "https://" + endpoint;
    else
        throw DB::Exception(DB::ErrorCodes::BAD_ARGUMENTS, "S3 Endpoint format not right: {}", endpoint);
}
```

**验证说明**: S3 endpoint仅验证https://前缀，无域名白名单，SSRF风险存在

---

### [VULN-SHUFFLE-008] Unvalidated Index - HashNativeSplitter::HashNativeSplitter

**严重性**: High | **CWE**: CWE-129 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Shuffle/NativeSplitter.cpp:199-206` @ `HashNativeSplitter::HashNativeSplitter`
**模块**: cpp-ch-shuffle

**描述**: Unvalidated string-to-int conversion: std::stoi(*iter) parses column indices from string without bounds checking. Could result in out-of-bounds block column access.

**漏洞代码** (`cpp-ch/local-engine/Shuffle/NativeSplitter.cpp:199-206`)

```c
hash_fields.push_back(std::stoi(*iter));\noutput_columns_indicies.push_back(std::stoi(*iter));
```

**达成路径**

[IN] config string -> [PARSE] std::stoi -> [OUT] column index access

**验证说明**: Duplicate of SHUFFLE-001. Column indices from exprs_buffer/schema_buffer via std::stoi without bounds check against block.columns().

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SHUFFLE-009] Memory Safety - NativeSplitter::hasNext

**严重性**: High | **CWE**: CWE-416 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Shuffle/NativeSplitter.cpp:113` @ `NativeSplitter::hasNext`
**模块**: cpp-ch-shuffle

**描述**: Use-after-free potential: reinterpret_cast<DB::Block *>(inputNext()) casts JNI long return value to Block pointer without validation. Invalid pointer could cause use-after-free or crash.

**漏洞代码** (`cpp-ch/local-engine/Shuffle/NativeSplitter.cpp:113`)

```c
split(*reinterpret_cast<DB::Block *>(inputNext()));
```

**达成路径**

[IN] JNI long -> [CAST] Block* -> [OUT] split() dereference

**验证说明**: JNI pointer cast without validation: reinterpret_cast<DB::Block*>(inputNext()) casts JNI long to Block pointer. If Java returns invalid/freed pointer, use-after-free or crash occurs. Trusted JNI context reduces risk but design is unsafe.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-004] Buffer Overflow - unknown

**严重性**: High | **CWE**: CWE-787 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/IO/SplittableBzip2ReadBuffer.cpp:720-724` @ `?`
**模块**: cpp-ch-storages
**跨模块**: cpp-ch-storages,cpp-ch-io

**描述**: ll8[++lastShadow] writes to ll8 vector without bounds check during run-length decoding. lastShadow increments potentially beyond ll8 capacity causing out-of-bounds write.

**漏洞代码** (`cpp-ch/local-engine/IO/SplittableBzip2ReadBuffer.cpp:720-724`)

```c
ll8[++lastShadow] = ch; if (lastShadow >= limitLast) throw...
```

**达成路径**

[IN] Compressed block data -> getAndMoveToFrontDecode()

**验证说明**: ll8[++lastShadow]写操作有limitLast检查，但检查后于写入

---

### [SHUFFLE-001] Improper Array Index Validation - HashNativeSplitter::HashNativeSplitter

**严重性**: High | **CWE**: CWE-129 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Shuffle/NativeSplitter.cpp:199-206` @ `HashNativeSplitter::HashNativeSplitter`
**模块**: cpp-ch-shuffle
**跨模块**: cpp-ch-parser,cpp-ch-main

**描述**: std::stoi parses column indices from comma-separated strings without bounds validation against actual block column count. If malicious or corrupted input provides indices exceeding block.columns(), subsequent block.getByPosition() calls will cause out-of-bounds access.

**漏洞代码** (`cpp-ch/local-engine/Shuffle/NativeSplitter.cpp:199-206`)

```c
hash_fields.push_back(std::stoi(*iter)); output_columns_indicies.push_back(std::stoi(*iter));
```

**达成路径**

External string input -> std::stoi -> vector push -> block.getByPosition()

**验证说明**: Column indices parsed from JNI-provided strings (exprs_buffer, schema_buffer) without bounds validation against block.columns(). If index >= block.columns(), block.getByPosition(index) causes out-of-bounds access. Attack path: Java provides malicious config -> std::stoi -> vector -> block.getByPosition -> OOB.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CPP-SHUFFLE-007] Unvalidated Input - deserialize

**严重性**: High | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp/core/shuffle/Payload.cc:311-312` @ `deserialize`
**模块**: cpp-core-shuffle

**描述**: numBuffers read from input stream without validation. Malicious shuffle data could specify extremely large numBuffers causing memory exhaustion or integer overflow in loop iteration.

**漏洞代码** (`cpp/core/shuffle/Payload.cc:311-312`)

```c
RETURN_NOT_OK(inputStream->Read(sizeof(uint32_t), &numBuffers))
```

**达成路径**

[IN] inputStream (from network/disk) -> deserialize -> buffers.reserve [OUT]

**验证说明**: numBuffers read from inputStream without bounds check. Malicious shuffle data can cause memory exhaustion or integer overflow in loop iteration.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-MOD-SCAN-004] Deserialization of Untrusted Data - readUncompressedBuffer

**严重性**: High | **CWE**: CWE-502 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp/core/shuffle/Payload.cc:122-165` @ `readUncompressedBuffer`
**模块**: cpp-core-shuffle
**跨模块**: cpp-core-jni,cpp-core-shuffle

**描述**: readUncompressedBuffer() reads bufferLength from input stream and allocates memory without upper bound validation. Malicious shuffle data from compromised upstream executor could specify extremely large bufferLength, causing memory exhaustion. Combined with JNI boundary from Spark JVM, creates DoS attack path.

**漏洞代码** (`cpp/core/shuffle/Payload.cc:122-165`)

```c
AllocateResizableBuffer(bufferLength, pool) without bounds check
```

**达成路径**

Shuffle stream (JVM) -> inputStream->Read(&bufferLength) -> AllocateResizableBuffer(bufferLength)

**验证说明**: bufferLength read from inputStream without upper bound validation. Malicious shuffle data (from compromised upstream executor or tampered disk file) can specify huge bufferLength causing memory exhaustion (DoS).

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [JNI-016] Missing Input Validation - getByteArrayElementsSafe

**严重性**: High | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:231-235` @ `getByteArrayElementsSafe`
**模块**: cpp-omni-jni

**描述**: getByteArrayElementsSafe does not validate that array is non-NULL or check for JNI exceptions. The returned pointer could be NULL if array is invalid, leading to NULL pointer dereference when used in protobuf parsing.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:231-235`)

```c
inline uint8_t *getByteArrayElementsSafe(JNIEnv *env, jbyteArray array)
{
    auto nativeArray = env->GetByteArrayElements(array, nullptr);
    return reinterpret_cast<uint8_t*>(nativeArray);  // No NULL check, no exception check
}
```

**验证说明**: getByteArrayElementsSafe无NULL检查，调用者也未检查array参数。若Java传入null导致空指针解引用。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN-CPP-CH-008] Path Traversal - createFilerWriter

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/local_engine_jni.cpp:889-911` @ `createFilerWriter`
**模块**: cpp-ch-main

**描述**: File URI injection: jstring file_uri_ passed to NormalFileWriter::create without sanitization. Path traversal patterns like ../ could lead to arbitrary file access outside expected directories.

**漏洞代码** (`cpp-ch/local-engine/local_engine_jni.cpp:889-911`)

```c
jstring2string(env, file_uri_) -> NormalFileWriter::create
```

**达成路径**

[IN] jstring file_uri_ -> jstring2string -> NormalFileWriter::create [OUT]

**验证说明**: jstring file_uri_ passed to NormalFileWriter::create without path sanitization. Poco::URI::encode only encodes spaces and %, does NOT prevent path traversal (../ patterns). validatePartitionKey is only called for partition paths, not main file_uri.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [CPP-SHUFFLE-001] Path Traversal - getShuffleSpillDir

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp/core/shuffle/Utils.cc:329-333` @ `getShuffleSpillDir`
**模块**: cpp-core-shuffle

**描述**: No validation of configuredDir parameter in getShuffleSpillDir. Path is constructed using std::filesystem::path without checking for path traversal characters (../) or absolute paths. Attacker-controlled localDirs from Java side could write to arbitrary locations.

**漏洞代码** (`cpp/core/shuffle/Utils.cc:329-333`)

```c
std::filesystem::path(configuredDir) / ss.str()
```

**达成路径**

[IN] localDirs (from Java) -> getShuffleSpillDir -> createTempShuffleFile [OUT]

**验证说明**: Same vulnerability as SEC-MOD-SCAN-001 (getShuffleSpillDir is upstream of createTempShuffleFile). No path traversal validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: -5

---

### [SEC-MOD-SCAN-002] External Control of File Path - LocalPartitionWriter::LocalPartitionWriter

**严重性**: High | **CWE**: CWE-73 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp/core/shuffle/LocalPartitionWriter.cc:371-379` @ `LocalPartitionWriter::LocalPartitionWriter`
**模块**: cpp-core-shuffle
**跨模块**: cpp-core-jni,cpp-core-shuffle

**描述**: LocalPartitionWriter constructor accepts dataFile and localDirs parameters from external Spark configuration without validation. These paths control where shuffle data is written. If compromised configuration injects malicious paths, data could be written to unauthorized locations or overwrite critical files.

**漏洞代码** (`cpp/core/shuffle/LocalPartitionWriter.cc:371-379`)

```c
LocalPartitionWriter(numPartitions, options, pool, dataFile, localDirs)
```

**达成路径**

Spark config (JVM) -> JNI boundary -> LocalPartitionWriter constructor -> dataFile_ / localDirs_ stored

**验证说明**: Entry point of path traversal chain. dataFile/localDirs from Spark config via JNI stored without validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: -5

---

### [SEC-MOD-SCAN-006] Improper Path Neutralization - getShuffleSpillDir

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp/core/shuffle/Utils.cc:329-333` @ `getShuffleSpillDir`
**模块**: cpp-core-shuffle
**跨模块**: cpp-core-jni,cpp-core-shuffle

**描述**: getShuffleSpillDir() constructs paths by concatenating configuredDir with subDirId using std::filesystem::path without validation. configuredDir originates from Spark localDirs config through JNI. If config contains path traversal sequences (../) or absolute paths, spill files written outside intended locations.

**漏洞代码** (`cpp/core/shuffle/Utils.cc:329-333`)

```c
std::filesystem::path(configuredDir) / ss.str()
```

**达成路径**

Spark localDirs -> JNI -> LocalPartitionWriter::localDirs_ -> getShuffleSpillDir -> path concatenation

**验证说明**: Same vulnerability as CPP-SHUFFLE-001 (getShuffleSpillDir path concatenation).

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: -5

---

### [VULN-CPP-CH-002] Configuration Injection - nativeInitNative

**严重性**: High | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/local_engine_jni.cpp:192-202` @ `nativeInitNative`
**模块**: cpp-ch-main

**描述**: Configuration injection via nativeInitNative: jbyteArray conf_plan is parsed as protobuf configuration without validation. Malicious configuration could modify ClickHouse settings, paths, or credentials.

**漏洞代码** (`cpp-ch/local-engine/local_engine_jni.cpp:192-202`)

```c
SparkConfigs::update({reinterpret_cast<const char *>(conf_plan_a.elems()), plan_buf_size}, ...)
```

**达成路径**

[IN] jbyteArray conf_plan -> getByteArrayElementsSafe -> reinterpret_cast -> SparkConfigs::update -> [OUT] BackendInitializerUtil::initBackend

**验证说明**: jbyteArray conf_plan from Java parsed as protobuf configuration. Protobuf provides syntactic validation but no semantic validation. Malicious config could modify ClickHouse settings, paths, or credentials.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [cpp-core-jni-VULN-008] Improper Input Validation - Java_org_apache_gluten_vectorized_ShuffleWriterJniWrapper_nativeMake

**严重性**: High | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp/core/jni/JniWrapper.cc:906-926` @ `Java_org_apache_gluten_vectorized_ShuffleWriterJniWrapper_nativeMake`
**模块**: cpp-core-jni

**描述**: Unsafe file path handling in ShuffleWriterJniWrapper_nativeMake. The dataFile and localDirs paths from JVM are used directly for file operations without path validation. Path traversal or arbitrary file access possible.

**漏洞代码** (`cpp/core/jni/JniWrapper.cc:906-926`)

```c
auto dataFile = std::string(dataFileC); partitionWriter = std::make_unique<LocalPartitionWriter>(..., dataFile, configuredDirs);
```

**达成路径**

JVM(dataFileJstr, localDirsJstr) -> String conversion -> LocalPartitionWriter -> File Operations

**验证说明**: LIKELY: dataFile and localDirs from JVM used in LocalPartitionWriter without path traversal validation. Null check exists but no sanitization for '../' or absolute paths. Direct file operations.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN_CPP_CH_MAIN_003] Improper Input Validation - Java_org_apache_gluten_vectorized_ExpressionEvaluatorJniWrapper_nativeInitNative

**严重性**: High | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:192-203` @ `Java_org_apache_gluten_vectorized_ExpressionEvaluatorJniWrapper_nativeInitNative`
**模块**: cpp-ch-main
**跨模块**: SparkConfigs, BackendInitializerUtil, QueryContext

**描述**: nativeInitNative receives a byte array (conf_plan) from Java without validating its size limits. Large or malformed configuration data could cause buffer overflow or excessive memory consumption. The configuration is parsed via protobuf BinaryToMessage which may throw exceptions but size limits are not checked before processing.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:192-203`)

```c
const auto conf_plan_a = local_engine::getByteArrayElementsSafe(env, conf_plan); local_engine::SparkConfigs::update(...)
```

**达成路径**

Java byte[] conf_plan -> getByteArrayElementsSafe -> SparkConfigs::update -> BackendInitializerUtil::initBackend

**验证说明**: Duplicate of VULN-CPP-CH-002. nativeInitNative receives byte array without size limits. Large/malformed config could cause buffer overflow or excessive memory consumption.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-CPP-SHUFFLE-002] Buffer Overflow - ComputeAndCountPartitionId

**严重性**: High | **CWE**: CWE-787 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/shuffle/splitter.cpp:65-72` @ `ComputeAndCountPartitionId`
**模块**: cpp-omni-shuffle

**描述**: Negative partition ID array access: hash_vct->GetValue(i) returns int32_t which could be negative. Validation only checks upper bound, missing negative check.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/shuffle/splitter.cpp:65-72`)

```c
int32_t pid = hash_vct->GetValue(i); partition_id_cnt_cur_[pid]++;
```

**达成路径**

[IN] VectorBatch hash column -> pid [OUT] partition_id_cnt_cur_ array

**验证说明**: Negative pid validation missing confirmed: int32_t pid = hash_vct->GetValue(i) only checks upper bound (pid >= num_partitions_), missing negative check. Negative pid causes out-of-bounds access: partition_id_cnt_cur_[pid]++ (int32_t* array). Hash function returns int32_t which can be negative.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: -15 | cross_file: 0

---

### [cpp-omni-shuffle-003] Improper Input Validation - ComputeAndCountPartitionId

**严重性**: High | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-omni/src/shuffle/splitter.cpp:65-72` @ `ComputeAndCountPartitionId`
**模块**: cpp-omni-shuffle

**描述**: Incomplete partition ID validation: hash_vct GetValue returns int32_t but only checks upper bound, missing negative check. Negative pid causes out-of-bounds array access.

**漏洞代码** (`cpp-omni/src/shuffle/splitter.cpp:65-72`)

```c
pid validation missing negative check
```

**验证说明**: Same location as VULN-CPP-SHUFFLE-002: CWE-20 Improper Input Validation - incomplete partition ID validation missing negative check.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: -15 | cross_file: 0

---

### [SEC-MOD-SCAN-001] Path Traversal - createTempShuffleFile

**严重性**: High | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-module-scanner, dataflow_scanner

**位置**: `cpp/core/shuffle/Utils.cc:335-367` @ `createTempShuffleFile`
**模块**: cpp-core-shuffle
**跨模块**: cpp-core-jni,cpp-core-shuffle

**描述**: createTempShuffleFile() creates files in directories from external configuration without path canonicalization or symlink validation. The configuredDir parameter from getShuffleSpillDir() is concatenated directly into file paths, allowing potential path traversal if localDirs contains malicious values like ../../ sequences or symlinks to sensitive locations.

**漏洞代码** (`cpp/core/shuffle/Utils.cc:335-367`)

```c
filePath = parentPath / (temp-shuffle- + generateUuid())
```

**达成路径**

localDirs (external config) -> LocalPartitionWriter -> getShuffleSpillDir -> createTempShuffleFile -> std::filesystem::path concatenation

**验证说明**: Code lacks path canonicalization and ../ validation. O_CREAT|O_EXCL only protects file-level TOCTOU. Attack path exists if attacker controls Spark localDirs config.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-CPP-SHUFFLE-001] Integer Overflow - AllocatePartitionBuffers

**严重性**: High | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/shuffle/splitter.cpp:101-106` @ `AllocatePartitionBuffers`
**模块**: cpp-omni-shuffle

**描述**: Integer overflow in buffer allocation: new_size * (1 << column_type_id_[i]) can overflow when new_size is large (int32_t) and type size multiplier (1-16 bytes). This could lead to undersized buffer allocation followed by buffer overflow during memcpy operations.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/shuffle/splitter.cpp:101-106`)

```c
void *ptr_tmp = static_cast<void *>(options_.allocator->Alloc(new_size * (1 << column_type_id_[i])));
```

**达成路径**

[IN] VectorBatch::GetRowCount -> num_rows -> partition_id_cnt_cur_[pid] -> new_size [OUT] Buffer allocation undersized -> memcpy overflow

**验证说明**: Integer overflow confirmed: new_size (int32_t) multiplied by (1 << column_type_id_[i]) (1-16 bytes) can overflow when new_size > INT_MAX/16 (~134M). Undersized buffer allocation followed by memcpy overflow. Code snippet: options_.allocator->Alloc(new_size * (1 << column_type_id_[i])). No bounds check present.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: -15 | cross_file: 0

---

### [cpp-omni-shuffle-001] Integer Overflow - AllocatePartitionBuffers

**严重性**: High | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-module-scanner, dataflow-scanner

**位置**: `cpp-omni/src/shuffle/splitter.cpp:101-102` @ `AllocatePartitionBuffers`
**模块**: cpp-omni-shuffle

**描述**: Integer overflow in AllocatePartitionBuffers: new_size * (1 << column_type_id_[i]) can overflow when new_size is large and column_type_id_[i] represents byte width. This overflow can lead to undersized buffer allocation, followed by memcpy operations that write beyond buffer bounds causing heap corruption.

**漏洞代码** (`cpp-omni/src/shuffle/splitter.cpp:101-102`)

```c
void *ptr_tmp = static_cast<void *>(options_.allocator->Alloc(new_size * (1 << column_type_id_[i])));
```

**验证说明**: Duplicate of VULN-CPP-SHUFFLE-001: same integer overflow at line 101 in AllocatePartitionBuffers. new_size * (1 << column_type_id_[i]) overflow leads to undersized buffer.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: -15 | cross_file: 0

---

### [cpp-omni-shuffle-002] Integer Overflow - SerializingFixedColumns

**严重性**: High | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-omni/src/shuffle/splitter.cpp:795-798` @ `SerializingFixedColumns`
**模块**: cpp-omni-shuffle

**描述**: Integer overflow in SerializingFixedColumns: onceCopyRow * (1 << column_type_id_[colIndexTmpSchema]) can overflow. Overflowed value used to resize string buffer, leading to undersized buffer followed by memcpy operations causing heap corruption.

**漏洞代码** (`cpp-omni/src/shuffle/splitter.cpp:795-798`)

```c
auto onceCopyLen = splitRowInfoTmp->onceCopyRow * (1 << column_type_id_[colIndexTmpSchema]); valueStr.resize(onceCopyLen);
```

**验证说明**: Integer overflow confirmed at line 795: onceCopyRow * (1 << column_type_id_[colIndexTmpSchema]). Result used in valueStr.resize(onceCopyLen) leading to undersized buffer. memcpy_s at lines 829-862 writes beyond resized buffer.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: -15 | cross_file: 0

---

### [cpp-omni-shuffle-009] Uncontrolled Memory Allocation - AllocatePartitionBuffers

**严重性**: High | **CWE**: CWE-789 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-omni/src/shuffle/splitter.cpp:101-106` @ `AllocatePartitionBuffers`
**模块**: cpp-omni-shuffle

**描述**: Large memory allocation without bounds: Alloc allocates based on new_size and column_type_id_[i] from external input. Large values cause excessive memory consumption leading to DoS or heap corruption.

**漏洞代码** (`cpp-omni/src/shuffle/splitter.cpp:101-106`)

```c
Alloc without bounds check
```

**验证说明**: Variant of VULN-CPP-SHUFFLE-001: CWE-789 Uncontrolled Memory Allocation at same location. Large new_size causes excessive memory consumption or undersized allocation due to overflow.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: -15 | cross_file: 0

---

### [JNI-006] Stack-based Buffer Overflow - Transform

**严重性**: High | **CWE**: CWE-121 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:319-368` @ `Transform`
**模块**: cpp-omni-jni

**描述**: Transform function creates multiple VLAs with size vecCount from VectorBatch without validation. Large vecCount from untrusted source can cause stack overflow.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:319-368`)

```c
int32_t vecCount = result.GetVectorCount(); int64_t vecAddresses[vecCount]; int32_t encodings[vecCount];
```

**验证说明**: Transform函数中VLA vecCount来自VectorBatch.GetVectorCount()，需追踪数据源可信度。static函数降低攻击面。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -15 | cross_file: 0

---

## 5. Medium 漏洞 (50)

### [CPP-CH-PARSER-006] buffer_overflow - writeVariableLengthNonNullableValue

**严重性**: Medium | **CWE**: CWE-787 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp:176-264` @ `writeVariableLengthNonNullableValue`
**模块**: cpp-ch-parser
**跨模块**: cpp-ch-parser,spark-row-info

**描述**: writeVariableLengthNonNullableValue/NullableValue memcpy writes offset_and_size to buffer_address+offsets[i]+field_offset without verifying destination bounds match allocated total_bytes.

**达成路径**

[IN] offsets/field_offset from SparkRowInfo → memcpy(buffer_address+offsets+field_offset) [OUT] heap write overflow

**验证说明**: writeVariableLengthNonNullableValue/NullableValue memcpy writes offset_and_size to buffer+offsets+field_offset without destination bounds check.

**评分明细**: base: 30 | reachability: 25 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

### [VULN-CPP-JNI-006] Input Validation - nativeMake

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-omni/src/jni/SparkJniWrapper.cpp:37-131` @ `nativeMake`
**模块**: cpp-omni-jni

**描述**: No validation for negative or zero values of num_partitions, jNumCols, buffer_size in nativeMake. These values are used directly for memory allocation and array sizing.

**漏洞代码** (`cpp-omni/src/jni/SparkJniWrapper.cpp:37-131`)

```c
auto splitter = Splitter::Make(partitioning_name, inputDataTypesTmp, jNumCols, num_partitions, std::move(splitOptions));
```

**达成路径**

[IN] JNI:jint num_partitions, jint jNumCols -> [SINK] Splitter::Make - no negative/zero check

**验证说明**: num_partitions and jNumCols not validated for negative/zero values. buffer_size has >0 check but other parameters don't. Could cause issues in Splitter::Make.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-CPP-JNI-010] Input Validation - columnarShuffleParseBatch

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-omni/src/jni/deserializer.cpp:79-122` @ `columnarShuffleParseBatch`
**模块**: cpp-omni-jni

**描述**: JNI array element count mismatch risk: GetIntArrayElements used without checking if the array size matches the protobuf vecCount. Mismatch could cause out-of-bounds writes.

**漏洞代码** (`cpp-omni/src/jni/deserializer.cpp:79-122`)

```c
jint *typeIdArrayElements = env->GetIntArrayElements(typeIdArray, NULL); ... typeIdArrayElements[i] = ...
```

**达成路径**

[IN] JNI:GetIntArrayElements + protobuf:vecCount -> [SINK] array[i] - no size match check

**验证说明**: Potential out-of-bounds write: vecCount from protobuf used to index Java array elements without checking if array size matches. Mismatch could cause buffer overflow.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN_CPP_CH_MAIN_005] Improper Array Index Validation - getColumnFromColumnVector

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:71-75` @ `getColumnFromColumnVector`
**模块**: cpp-ch-main

**描述**: JNI functions like getColumnFromColumnVector and various nativeGet* functions receive column_position (jint) parameters without validating against block->columns() bounds. Invalid column_position values could cause out-of-bounds access in Block::getByPosition().

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:71-75`)

```c
DB::Block * block = reinterpret_cast<DB::Block *>(block_address); return block->getByPosition(column_position);
```

**达成路径**

jint column_position -> Block::getByPosition() without bounds check

**验证说明**: jint column_position passed to Block::getByPosition() without bounds validation. Invalid column_position >= block->columns() causes out-of-bounds access.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN_CPP_CH_MAIN_007] Integer Overflow - Java_org_apache_gluten_vectorized_CHShuffleSplitterJniWrapper_nativeMake

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:651-667` @ `Java_org_apache_gluten_vectorized_CHShuffleSplitterJniWrapper_nativeMake`
**模块**: cpp-ch-main

**描述**: In ShuffleSplitterJniWrapper_nativeMake, multiple integer parameters (split_size, spill_threshold, max_sort_buffer_size, etc.) from Java are cast to size_t without overflow checks. Large jlong values could overflow when cast to size_t, causing unexpected behavior or memory allocation issues.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:651-667`)

```c
.split_size = static_cast<size_t>(split_size), .spill_threshold = static_cast<size_t>(spill_threshold)
```

**达成路径**

Java jlong -> static_cast<size_t> without overflow validation

**验证说明**: jint/jlong parameters (split_size, spill_threshold, max_sort_buffer_size) cast to size_t without overflow validation. Negative jint values become large positive values via static_cast<size_t>. Could cause memory allocation issues.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp-core-jni-VULN-009] Improper Input Validation - parseConfMap

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp/core/config/GlutenConfig.cc:38-48` @ `parseConfMap`
**模块**: cpp-core-jni
**跨模块**: cpp-core-config

**描述**: Protobuf parsing without size validation in parseConfMap. The planDataLength from JVM is passed directly to parseProtobuf without bounds checking. Large or malformed data could cause DoS or parsing errors.

**漏洞代码** (`cpp/core/config/GlutenConfig.cc:38-48`)

```c
gluten::parseProtobuf(planData, planDataLength, &pConfigMap);
```

**达成路径**

JVM(sessionConf bytes) -> getByteArrayElementsSafe -> parseProtobuf(planData, planDataLength) -> ConfigMap

**验证说明**: LIKELY: planDataLength from JVM passed to parseProtobuf without upper bound check. Large or malformed protobuf data could cause DoS or parsing errors. No size validation before parsing.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CPP-CH-PARSER-003] integer_overflow - calculateBitSetWidthInBytes

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp:48-56` @ `calculateBitSetWidthInBytes`
**模块**: cpp-ch-parser
**跨模块**: cpp-ch-parser,serialized-plan

**描述**: calculateBitSetWidthInBytes and calculatedFixeSizePerRow use num_cols/num_fields without upper bound validation. Integer overflow can cause undersized allocation in SparkRowInfo constructor.

**达成路径**

[IN] num_cols from Substrait Plan → calculateBitSetWidthInBytes → total_bytes allocation [OUT] undersized buffer

**验证说明**: Integer overflow in calculateBitSetWidthInBytes (line 50) and calculatedFixeSizePerRow (line 55) when num_cols is maliciously large. Can cause undersized allocation.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 5

---

### [CPP-CH-PARSER-005] buffer_overflow - readArray

**严重性**: Medium | **CWE**: CWE-787 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Parser/SparkRowToCHColumn.cpp:192-248` @ `readArray`
**模块**: cpp-ch-parser
**跨模块**: cpp-ch-parser,spark-row

**描述**: readArray/readMap multiple memcpy calls read from buffer using externally-controlled num_elems and offsets without validating buffer bounds against actual length parameter.

**达成路径**

[IN] num_elems/offsets from buffer → memcpy(buffer+calculated_offset) [OUT] out-of-bounds read

**验证说明**: readArray/readMap use externally-controlled num_elems and offsets without bounds validation against actual buffer length.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 0

---

### [CPP-CH-PARSER-007] out_of_bounds_read - parse

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Parser/ExpressionParser.cpp:127-141` @ `parse`
**模块**: cpp-ch-parser
**跨模块**: cpp-ch-parser,substrait

**描述**: ExpressionParser decimal parsing uses reinterpret_cast on protobuf bytes without size validation. If bytes.size() less than sizeof(type), reads garbage memory.

**达成路径**

[IN] literal.decimal().value() from protobuf → reinterpret_cast [OUT] uninitialized memory read

**验证说明**: Same as cpp-ch-parser-006. ExpressionParser decimal parsing reinterpret_cast without bytes.size() validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CH-STORAGE-006] Improper Input Validation - HDFSFileReadBufferBuilder::build

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:270-274` @ `HDFSFileReadBufferBuilder::build`
**模块**: cpp-ch-storages

**描述**: User info for HDFS URI is set from BackendInitializerUtil::spark_user without validation. Malicious user info could lead to privilege escalation or authentication bypass.

**漏洞代码** (`cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:270-274`)

```c
if (uri.getUserInfo().empty() && BackendInitializerUtil::spark_user.has_value()) {
    uri.setUserInfo(*BackendInitializerUtil::spark_user);
    new_file_uri = uri.toString();
}
```

**验证说明**: HDFS URI userInfo来自BackendInitializerUtil::spark_user，无输入验证

---

### [cpp-ch-parser-006] Type Confusion - LiteralParser::parse

**严重性**: Medium | **CWE**: CWE-704 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/ExpressionParser.cpp:119-145` @ `LiteralParser::parse`
**模块**: cpp-ch-parser
**跨模块**: cpp-ch-parser → substrait

**描述**: Decimal parsing uses reinterpret_cast without validating bytes.size() matches expected type size.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/ExpressionParser.cpp:119-145`)

```c
auto value = *reinterpret_cast<const Int32*>(bytes.data());
```

**达成路径**

Substrait decimal -> bytes -> reinterpret_cast unchecked

**验证说明**: ExpressionParser decimal parsing uses reinterpret_cast on bytes.data() without checking bytes.size() matches expected type size (lines 127,133,140). If protobuf decimal value has fewer bytes than sizeof(Int32/Int64/Decimal128), reads uninitialized/garbage memory.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp-ch-parser-008] Improper Array Index - ExpressionParser::parseExpression

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/ExpressionParser.cpp:295-301` @ `ExpressionParser::parseExpression`
**模块**: cpp-ch-parser
**跨模块**: cpp-ch-parser → substrait

**描述**: Selection parsing accesses getInputs()[field] without bounds validation on field index.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/ExpressionParser.cpp:295-301`)

```c
actions_dag.getInputs()[rel.selection().struct_field().field()];
```

**达成路径**

Substrait field index -> getInputs[] unvalidated

**验证说明**: ExpressionParser::parseExpression accesses getInputs()[field] without bounds validation (line 299). field index comes from Substrait selection struct_field. If field >= getInputs().size(), causes array out-of-bounds access.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp-ch-parser-010] Improper Input Validation - SerializedPlanParser::parseOp

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/SerializedPlanParser.cpp:248-251` @ `SerializedPlanParser::parseOp`
**模块**: cpp-ch-parser
**跨模块**: cpp-ch-parser → jni-interface

**描述**: std::stoi parses iterator index without exception handling, could cause crash or invalid indices.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/SerializedPlanParser.cpp:248-251`)

```c
auto iter_index = std::stoi(iter.substr(pos + 1));
```

**达成路径**

URI string -> std::stoi -> potential exception

**验证说明**: std::stoi parses URI substring (line 250) without exception handling. Malformed URI string can cause std::invalid_argument or std::out_of_range exception, crashing the process. Denial-of-service vulnerability.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CPP-CH-010] Input Validation - nativeMake

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/local_engine_jni.cpp:647-650` @ `nativeMake`
**模块**: cpp-ch-main

**描述**: Local directories injection: jstring local_dirs parsed without validation.

**漏洞代码** (`cpp-ch/local-engine/local_engine_jni.cpp:647-650`)

```c
Poco::StringTokenizer(jstring2string(env, local_dirs), ,)
```

**达成路径**

[IN] jstring local_dirs

**验证说明**: jstring local_dirs parsed by Poco::StringTokenizer without path validation. Could contain path traversal patterns to access directories outside expected locations.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp-core-jni-VULN-016] Improper Input Validation - Java_org_apache_gluten_runtime_RuntimeJniWrapper_createRuntime

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp/core/jni/JniWrapper.cc:273-288` @ `Java_org_apache_gluten_runtime_RuntimeJniWrapper_createRuntime`
**模块**: cpp-core-jni
**跨模块**: cpp-core-config

**描述**: Unchecked array length in createRuntime. The sessionConf byte array length is used without upper bound check. Maliciously large arrays could cause memory exhaustion.

**漏洞代码** (`cpp/core/jni/JniWrapper.cc:273-288`)

```c
auto safeArray = getByteArrayElementsSafe(env, sessionConf); auto sparkConf = parseConfMap(env, safeArray.elems(), safeArray.length());
```

**达成路径**

JVM(sessionConf) -> getByteArrayElementsSafe -> parseConfMap -> ConfigMap

**验证说明**: LIKELY: sessionConf byte array from JVM used without upper bound check. Large arrays could cause memory exhaustion in parseConfMap. Length-only control, content format is protobuf.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CPP-OMNI-COMPUTE-003] Improper Input Validation - ParsePlan

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-omni/src/compute/Runtime.cpp:17-20` @ `ParsePlan`
**模块**: cpp-omni-compute
**跨模块**: cpp-omni-jni,cpp-omni-compute

**描述**: ParsePlan accepts raw byte array without size bounds validation. Negative or extremely large size values could cause undefined behavior

**漏洞代码** (`cpp-omni/src/compute/Runtime.cpp:17-20`)

```c
OMNI_CHECK(ParseProtobuf(data, size, &substraitPlan_) == true, "Parse substrait plan failed");
```

**达成路径**

JNI planArr -> GetArrayLength -> ParsePlan(data, size) -> ParseProtobuf

**验证说明**: LIKELY: ParsePlan accepts raw pointer with int32_t size from JNI. JNI GetArrayLength provides valid length. Combined with high recursion limit (100000), deeply nested malformed protobuf can cause stack exhaustion. Protobuf parser has internal validation but recursion limit override undermines it. Related to CPP-OMNI-COMPUTE-002.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [cpp-ch-parser-005] Integer Overflow - SparkRowInfo::SparkRowInfo

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp:297-368` @ `SparkRowInfo::SparkRowInfo`
**模块**: cpp-ch-parser

**描述**: SparkRowInfo accumulates total_bytes without overflow checks, leading to undersized buffer allocation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp:297-368`)

```c
total_bytes += lengths[i]; alloc(total_bytes, 64);
```

**达成路径**

lengths accumulation -> overflow -> undersized alloc

**验证说明**: SparkRowInfo constructor accumulates total_bytes from lengths (line 367) without overflow check. Malicious column data with large lengths can cause integer overflow, resulting in undersized buffer allocation and subsequent buffer overflow in write operations.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-cpp-omni-compute-001] Buffer Overread - Runtime::ParsePlan

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/compute/Runtime.cpp:17-20` @ `Runtime::ParsePlan`
**模块**: cpp-omni-compute
**跨模块**: jni,substrait

**描述**: ParsePlan accepts raw pointer data with int32_t size without validation. The size parameter is passed to ParseProtobuf which uses it directly without bounds checking. Malformed or truncated protobuf data could cause buffer overread.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/compute/Runtime.cpp:17-20`)

```c
void Runtime::ParsePlan(const uint8_t *data, int32_t size, std::optional<std::string> dumpFile)\n{\n    OMNI_CHECK(ParseProtobuf(data, size, &substraitPlan_) == true, "Parse substrait plan failed");\n}
```

**达成路径**

[IN] External protobuf data (JNI/native) -> ParsePlan -> ParseProtobuf -> CodedInputStream (no size validation)

**验证说明**: LIKELY: Duplicate/related to CPP-OMNI-COMPUTE-003. Buffer overread concern mitigated by JNI GetArrayLength returning valid array bounds. Main risk is high recursion limit (100000) combined with malformed deeply nested protobuf.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-CPP-CH-006] Input Validation - nativeMake

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/local_engine_jni.cpp:609-672` @ `nativeMake`
**模块**: cpp-ch-main

**描述**: Unvalidated split_size/partition_num: jint/jlong parameters used to construct SplitOptions without validation. Malicious values could cause memory allocation failures or DoS.

**漏洞代码** (`cpp-ch/local-engine/local_engine_jni.cpp:609-672`)

```c
.split_size = static_cast<size_t>(split_size), .partition_num = static_cast<size_t>(num_partitions)
```

**达成路径**

[IN] jint/jlong split_size, num_partitions -> static_cast<size_t> -> SplitOptions

**验证说明**: jint/jlong split_size and num_partitions used to construct SplitOptions without validation. Malicious values could cause memory allocation failures or DoS.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CPP-JNI-004] Integer Overflow - nativeMake

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-omni/src/jni/SparkJniWrapper.cpp:58-66` @ `nativeMake`
**模块**: cpp-omni-jni

**描述**: Potential integer overflow in buffer size calculation. size from protobuf is used directly in new uint32_t[size] allocation without overflow validation.

**漏洞代码** (`cpp-omni/src/jni/SparkJniWrapper.cpp:58-66`)

```c
uint32_t *inputDataPrecisions = new uint32_t[size]; uint32_t *inputDataScales = new uint32_t[size];
```

**达成路径**

[IN] JNI:jInputType -> Deserialize -> inputVecTypes.Get() -> size -> [SINK] new uint32_t[size]

**验证说明**: Potential DoS through huge allocation. size from Deserialize() could be very large causing allocation failure or memory exhaustion. Not classic integer overflow.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN_CPP_CH_MAIN_009] Out-of-bounds Read - Java_org_apache_gluten_vectorized_CHBlockConverterJniWrapper_convertSparkRowsToCHColumn

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:808-835` @ `Java_org_apache_gluten_vectorized_CHBlockConverterJniWrapper_convertSparkRowsToCHColumn`
**模块**: cpp-ch-main

**描述**: In convertSparkRowsToCHColumn, GetArrayLength is called on names array but the loop iterates through both names and types without checking their sizes match. If types array is smaller than names, it could cause out-of-bounds read when accessing env->GetObjectArrayElement(types, i).

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:808-835`)

```c
int num_columns = env->GetArrayLength(names); for (int i = 0; i < num_columns; i++) { auto* type = static_cast<jbyteArray>(env->GetObjectArrayElement(types, i)); }
```

**达成路径**

Java ObjectArray names,types -> GetArrayLength(names) -> loop without checking types length

**验证说明**: convertSparkRowsToCHColumn uses GetArrayLength(names) for loop but also accesses types array. If types is smaller, GetObjectArrayElement throws ArrayIndexOutOfBoundsException. JNI exception handling provides partial mitigation.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN_CPP_CH_MAIN_010] Allocation of Resources Without Limits - Java_org_apache_gluten_vectorized_ExpressionEvaluatorJniWrapper_nativeCreateKernelWithIterator

**严重性**: Medium | **CWE**: CWE-770 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:267-273` @ `Java_org_apache_gluten_vectorized_ExpressionEvaluatorJniWrapper_nativeCreateKernelWithIterator`
**模块**: cpp-ch-main
**跨模块**: SerializedPlanParser, LocalExecutor, QueryPipeline

**描述**: Multiple JNI functions allocate native objects (LocalExecutor, ShuffleReader, ShuffleWriter, NativeWriterInMemory, etc.) without size limits based on input data. Large query plans or data streams could exhaust memory. The executor is allocated via parser.createExecutor().release() without memory limits.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:267-273`)

```c
local_engine::LocalExecutor * executor = parser.createExecutor(plan_pb).release();
```

**达成路径**

Java byte[] plan -> protobuf parsing -> LocalExecutor allocation without limits

**验证说明**: LocalExecutor allocated via parser.createExecutor(plan_pb).release() without explicit memory limits. Large query plans could exhaust memory. ClickHouse has internal memory limits at various levels.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-CPP-CH-009] Input Validation - nativeMake

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/local_engine_jni.cpp:626-667` @ `nativeMake`
**模块**: cpp-ch-main

**描述**: Hash algorithm string injection: jstring hash_algorithm passed without validation to SplitOptions. Malicious algorithm name could bypass expected security properties or cause unexpected behavior.

**漏洞代码** (`cpp-ch/local-engine/local_engine_jni.cpp:626-667`)

```c
jstring2string(env, hash_algorithm) -> SplitOptions
```

**达成路径**

[IN] jstring hash_algorithm -> jstring2string -> SplitOptions.hash_algorithm

**验证说明**: jstring hash_algorithm passed to SplitOptions without validation. Malicious algorithm name could bypass expected security properties or cause unexpected behavior.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CPP-CH-011] Input Validation - nativeMake

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/local_engine_jni.cpp:621-663` @ `nativeMake`
**模块**: cpp-ch-main

**描述**: Codec name injection: jstring codec passed without validation to compression methods. Malicious codec name could cause unexpected behavior.

**漏洞代码** (`cpp-ch/local-engine/local_engine_jni.cpp:621-663`)

```c
jstring2string(env, codec) -> compress_method
```

**达成路径**

[IN] jstring codec -> jstring2string -> compress_method

**验证说明**: jstring codec passed to compress_method without validation. Malicious codec name could cause unexpected behavior.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SHUFFLE-002] Integer Overflow - SparkExchangeManager::SparkExchangeManager

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Shuffle/SparkExchangeSink.cpp:126-127` @ `SparkExchangeManager::SparkExchangeManager`
**模块**: cpp-ch-shuffle

**描述**: Integer overflow in overhead memory calculation: multiplication of header.columns() * 16 * split_size * partition_num can overflow size_t when partition_num is large, leading to incorrect memory allocation decisions.

**漏洞代码** (`cpp-ch/local-engine/Shuffle/SparkExchangeSink.cpp:126-127`)

```c
auto overhead_memory = header.columns() * 16 * options.split_size * options.partition_num;
```

**达成路径**

[IN] config parameters -> [CALC] overhead_memory -> [OUT] use_sort_shuffle decision

**验证说明**: Integer overflow in overhead_memory = header.columns() * 16 * split_size * partition_num. With extreme partition_num (>10^13), size_t overflow causes incorrect use_sort_shuffle decision. Practical impact limited but exploitable with malicious config.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SHUFFLE-003] Integer Underflow - PartitionWriter::PartitionWriter

**严重性**: Medium | **CWE**: CWE-191 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Shuffle/PartitionWriter.cpp:240` @ `PartitionWriter::PartitionWriter`
**模块**: cpp-ch-shuffle

**描述**: Integer underflow when partition_num is zero: last_partition_id is initialized as (options.partition_num - 1), causing wraparound to SIZE_MAX if partition_num is 0.

**漏洞代码** (`cpp-ch/local-engine/Shuffle/PartitionWriter.cpp:240`)

```c
last_partition_id(options.partition_num - 1)
```

**达成路径**

[IN] partition_num config -> [CALC] last_partition_id -> [OUT] array indexing

**验证说明**: Integer underflow when partition_num=0: last_partition_id = partition_num - 1 = SIZE_MAX. Then (last_partition_id + 1) % partition_num = division by zero at lines 100-101.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SHUFFLE-006] Division by Zero - Spillable::getNextSpillFile

**严重性**: Medium | **CWE**: CWE-369 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Shuffle/PartitionWriter.cpp:195-196` @ `Spillable::getNextSpillFile`
**模块**: cpp-ch-shuffle

**描述**: Division by zero risk: hash % spill_options.local_dirs_list.size() will cause division by zero if local_dirs_list is empty.

**漏洞代码** (`cpp-ch/local-engine/Shuffle/PartitionWriter.cpp:195-196`)

```c
auto dir_id = hash % spill_options.local_dirs_list.size();
```

**达成路径**

[IN] file hash -> [CALC] dir_id -> [OUT] file path

**验证说明**: Division by zero if local_dirs_list is empty: hash % local_dirs_list.size() = hash % 0. Config validation should prevent empty list, but no runtime check.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SHUFFLE-003] Improper Input Validation in JSON Parsing - RangeSelectorBuilder::RangeSelectorBuilder

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Shuffle/SelectorBuilder.cpp:169-175` @ `RangeSelectorBuilder::RangeSelectorBuilder`
**模块**: cpp-ch-shuffle
**跨模块**: cpp-ch-parser

**描述**: RangeSelectorBuilder parses JSON configuration from external input without schema validation. Poco::JSON::Parser.parse() and subsequent convert<T>() calls can throw exceptions or cause undefined behavior with malformed JSON. Multiple field_value.convert<T>() calls lack error handling.

**漏洞代码** (`cpp-ch/local-engine/Shuffle/SelectorBuilder.cpp:169-175`)

```c
auto info = parser.parse(option).extract<Poco::JSON::Object::Ptr>();
```

**达成路径**

External JSON string -> Poco parser -> Object::Ptr -> convert<T> -> internal structures

**验证说明**: JSON parsing from external config without schema validation or exception handling. Poco::JSON::Parser.parse() and convert<T>() calls can throw exceptions with malformed JSON, causing crash or unexpected behavior.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SHUFFLE-004] Improper Pathname Limitation - Spillable::getNextSpillFile

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Shuffle/PartitionWriter.cpp:195-201` @ `Spillable::getNextSpillFile`
**模块**: cpp-ch-shuffle
**跨模块**: cpp-ch-main

**描述**: Spill files are created in directories from spill_options.local_dirs_list which comes from external configuration. Hash-based directory selection uses modulo operation but does not validate path components. std::filesystem::create_directories() could create directories in unintended locations if local_dirs_list contains malicious paths.

**漏洞代码** (`cpp-ch/local-engine/Shuffle/PartitionWriter.cpp:195-201`)

```c
auto dir_id = hash % spill_options.local_dirs_list.size(); std::filesystem::path(spill_options.local_dirs_list[dir_id])
```

**达成路径**

External config -> local_dirs_list -> hash selection -> filesystem::create_directories

**验证说明**: Spill file directories from external config (local_dirs_list) without path validation. If config contains malicious paths (e.g., system directories), std::filesystem::create_directories() could create files in unintended locations.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp-ch-parser-004] Improper Input Validation - BinaryToMessage

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/SubstraitParserUtils.h:56-69` @ `BinaryToMessage`
**模块**: cpp-ch-parser
**跨模块**: cpp-ch-parser → jni-interface

**描述**: BinaryToMessage parses protobuf without size limits, allowing memory exhaustion or stack overflow.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/SubstraitParserUtils.h:56-69`)

```c
CodedInputStream coded_in(binary.data(), binary.size()); SetRecursionLimit(100000);
```

**达成路径**

JNI bytes -> BinaryToMessage -> no size validation

**验证说明**: BinaryToMessage parses protobuf without size limit on binary input. SetRecursionLimit(100000) mitigates deep recursion stack overflow but not memory exhaustion from large protobuf messages. Attacker can craft malformed/large protobuf to consume resources.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [cpp-core-jni-VULN-013] Integer Overflow - Java_org_apache_gluten_columnarbatch_ColumnarBatchJniWrapper_select

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp/core/jni/JniWrapper.cc:819-826` @ `Java_org_apache_gluten_columnarbatch_ColumnarBatchJniWrapper_select`
**模块**: cpp-core-jni

**描述**: Potential integer overflow in array size operations. jint parameters are used for array indices and sizes without bounds checking. Large values could overflow when converted to int32_t or size_t.

**漏洞代码** (`cpp/core/jni/JniWrapper.cc:819-826`)

```c
int size = env->GetArrayLength(jcolumnIndices); for (int32_t i = 0; i < size; i++) { columnIndices.push_back(safeArray.elems()[i]); }
```

**达成路径**

JVM(jcolumnIndices) -> GetArrayLength -> Loop -> Vector push_back

**验证说明**: LIKELY: jint size from GetArrayLength used in loop. Java arrays max ~2B elements, overflow unlikely but negative size (unlikely) could skip loop. Weak vulnerability with limited practical impact.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [CPP-OMNI-COMPUTE-001] Information Disclosure - GetQueryContextConf

**严重性**: Medium | **CWE**: CWE-209 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-omni/src/compute/WholeStageResultIterator.cpp:120-123` @ `GetQueryContextConf`
**模块**: cpp-omni-compute
**跨模块**: cpp-omni-jni,cpp-omni-compute

**描述**: Exception error message includes err.what() which may expose internal details or sensitive configuration values to callers

**漏洞代码** (`cpp-omni/src/compute/WholeStageResultIterator.cpp:120-123`)

```c
const std::string errDetails = err.what(); throw std::runtime_error("Invalid conf arg: " + errDetails);
```

**达成路径**

std::invalid_argument -> err.what() -> error message -> exception propagation to JNI

**验证说明**: LIKELY: Exception error message includes err.what() which exposes internal details. Data flows from confMap (JNI sessionConf) to config parsing. Error messages may contain sensitive configuration values. Indirect external input with partial controllability.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-cpp-omni-compute-002] Use After Free Risk - WholeStageResultIterator::Next

**严重性**: Medium | **CWE**: CWE-416 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/compute/WholeStageResultIterator.cpp:45-68` @ `WholeStageResultIterator::Next`
**模块**: cpp-omni-compute
**跨模块**: jni,task

**描述**: WholeStageResultIterator::Next() returns raw VectorBatch* pointer with unclear ownership semantics. Caller may not know if they own the returned memory. Memory leaks or use-after-free could occur.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/compute/WholeStageResultIterator.cpp:45-68`)

```c
VectorBatch *WholeStageResultIterator::Next() { VectorBatch *vectorBatch = nullptr; return vectorBatch; }
```

**达成路径**

[OUT] task_->Next() -> VectorBatch* (raw pointer) -> Returned to caller (ownership unclear)

**验证说明**: LIKELY: Next() returns raw VectorBatch* pointer with unclear ownership semantics. JNI layer receives pointer and passes to Java without ownership transfer. Risk of use-after-free or memory leaks if caller assumes ownership incorrectly. Indirect external caller via JNI.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cpp-core-jni-VULN-002] Improper Input Validation - jniCastOrThrow

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp/core/jni/JniCommon.h:125-130` @ `jniCastOrThrow`
**模块**: cpp-core-jni

**描述**: Unsafe handle validation in jniCastOrThrow. The jlong handle is directly reinterpret_casted to a pointer without bounds checking or validation. An attacker could pass arbitrary handle values leading to memory access violations.

**漏洞代码** (`cpp/core/jni/JniCommon.h:125-130`)

```c
auto instance = reinterpret_cast<T*>(handle); GLUTEN_CHECK(instance != nullptr, ...)
```

**达成路径**

JVM(handle) -> reinterpret_cast(handle) -> Memory Access

**验证说明**: LIKELY: jniCastOrThrow directly casts jlong handle to pointer with only null check. GLUTEN_CHECK catches null but not arbitrary invalid handles. Used for handles bypassing ObjectStore validation. Partial risk as handles must be previously stored.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [cpp-core-jni-VULN-005] Buffer Underread - JavaInputStreamAdaptor::Read

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/core/jni/JniWrapper.cc:121-127` @ `JavaInputStreamAdaptor::Read`
**模块**: cpp-core-jni

**描述**: Unsafe array element access in JavaInputStreamAdaptor::Read. The nbytes parameter from JVM is used directly without validation against actual available data. Negative or oversized nbytes could cause buffer issues.

**漏洞代码** (`cpp/core/jni/JniWrapper.cc:121-127`)

```c
jlong read = env->CallLongMethod(jniIn_, jniByteInputStreamRead, reinterpret_cast<jlong>(out), nbytes);
```

**达成路径**

JVM(nbytes) -> Read(out, nbytes) -> Buffer Access

**验证说明**: POSSIBLE: nbytes from JVM passed to Java read method. The actual buffer allocation is handled by Arrow. Risk is limited as buffer is managed and the vulnerable code path is primarily on Java side.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [cpp-core-jni-VULN-007] NULL Pointer Dereference - ObjectStore::retrieveInternal

**严重性**: Medium | **CWE**: CWE-476 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/core/jni/JniCommon.h:84-91` @ `ObjectStore::retrieveInternal`
**模块**: cpp-core-jni

**描述**: Potential NULL pointer dereference in ObjectStore::retrieve. The retrieved object is static_pointer_cast without NULL check after lookup. Invalid handle could result in NULL pointer being used.

**漏洞代码** (`cpp/core/jni/JniCommon.h:84-91`)

```c
std::shared_ptr<void> object = store_.lookup(handle); auto casted = std::static_pointer_cast<T>(object);
```

**达成路径**

Invalid Handle -> lookup() -> NULL shared_ptr -> static_pointer_cast -> UB

**验证说明**: POSSIBLE: Type confusion risk in static_pointer_cast. ResourceMap::lookup validates handle existence, but wrong template parameter T causes UB. Not NULL deref as described - mischaracterized vulnerability.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-CPP-SHUFFLE-004] Integer Overflow - AllocatePartitionBuffers

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/shuffle/splitter.cpp:102` @ `AllocatePartitionBuffers`
**模块**: cpp-omni-shuffle

**描述**: Accumulated buffer size overflow in fixed_valueBuffer_size_ uint32_t.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/shuffle/splitter.cpp:102`)

```c
fixed_valueBuffer_size_[partition_id] += new_size * ...
```

**达成路径**

[IN] allocations [OUT] size corruption

**验证说明**: Accumulated buffer size overflow: fixed_valueBuffer_size_[partition_id] (uint32_t*) accumulates new_size * type_multiplier. Multiple accumulations can overflow uint32_t, affecting subsequent buffer calculations. Impact is limited as it affects size tracking rather than direct memory corruption.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: -15 | cross_file: 0

---

### [CPP-CH-PARSER-001] buffer_overflow - bitSet

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp:70-73` @ `bitSet`
**模块**: cpp-ch-parser
**跨模块**: cpp-ch-parser,spark-row

**描述**: memcpy in bitSet function lacks bounds validation. word_offset=(index>>6)*8 can overflow or access out-of-bounds memory if index is maliciously large from external input.

**达成路径**

[IN] index from column data → memcpy(bitmap + word_offset) [OUT] memory corruption

**验证说明**: Same analysis as cpp-ch-parser-002. bitSet word_offset risk exists primarily via integer overflow in num_cols calculation rather than direct bounds violation.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: -5

---

### [VULN-005] Buffer Overflow - unknown

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp-ch/local-engine/Storages/IO/AggregateSerializationUtils.cpp:118-120` @ `?`
**模块**: cpp-ch-storages
**跨模块**: cpp-ch-storages,cpp-ch-parser

**描述**: memcpy copies value.data to place using value.size in aggregate state conversion. If value.size exceeds size_of_state allocated memory (from agg_function->sizeOfData()), overflow occurs.

**漏洞代码** (`cpp-ch/local-engine/Storages/IO/AggregateSerializationUtils.cpp:118-120`)

```c
memcpy(place, value.data, value.size)
```

**达成路径**

[OUT] Aggregate state serialization -> CHColumnToSparkRow conversion

**验证说明**: Aggregate状态序列化memcpy依赖agg_function->sizeOfData()验证

---

### [VULN-CPP-SHUFFLE-006] Buffer Overflow - BuildPartition2Row

**严重性**: Medium | **CWE**: CWE-787 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/shuffle/splitter.cpp:27-47` @ `BuildPartition2Row`
**模块**: cpp-omni-shuffle

**描述**: Row offset array overflow: row_offset_row_id_[pos] accessed with pos derived from partition_row_offset_base_[pid+1]. If BuildPartition2Row produces incorrect offsets (due to overflow in partition_id_cnt_cur_), accessing row_offset_row_id_ beyond its resize(num_rows) size could cause buffer overflow.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/shuffle/splitter.cpp:27-47`)

```c
row_offset_row_id_[partition_row_offset_base_[pid]++] = row;
```

**达成路径**

[IN] partition_id_cnt_cur_ counts [OUT] row_offset_row_id_ vector overflow

**验证说明**: Indirect overflow: row_offset_row_id_[partition_row_offset_base_[pid]++] depends on partition_id_cnt_cur_ counts. If partition_id_cnt_cur_ overflow occurs, partition_row_offset_base_ calculation becomes incorrect, causing row_offset_row_id_ array out-of-bounds. This is a cascade effect from primary overflow vulnerabilities.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -15 | cross_file: 0

---

### [VULN-006] Integer Underflow - unknown

**严重性**: Medium | **CWE**: CWE-191 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:276-278` @ `?`
**模块**: cpp-ch-storages
**跨模块**: cpp-ch-storages,cpp-ch-substrait

**描述**: HDFS URI parsing: new_file_uri.find("//") returns npos (-1) if pattern not found. Adding 2 creates invalid offset causing potential memory access issues in subsequent find operation.

**漏洞代码** (`cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:276-278`)

```c
auto begin_of_path = new_file_uri.find("/", new_file_uri.find("//") + 2)
```

**达成路径**

[IN] Substrait plan URI parsing -> HDFSFileReadBufferBuilder

**验证说明**: HDFS URI解析find('//')缺失时返回npos+2造成无效偏移

---

### [cpp-ch-parser-002] Buffer Overflow - bitSet

**严重性**: Medium | **CWE**: CWE-787 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp:65-73` @ `bitSet`
**模块**: cpp-ch-parser

**描述**: bitSet function performs memcpy operations on bitmap at word_offset without validating that the offset is within the bitmap bounds.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp:65-73`)

```c
void bitSet(char* bitmap, size_t index) { memcpy(bitmap + word_offset, &value, sizeof(int64_t)); }
```

**达成路径**

col_index -> bitSet -> memcpy unvalidated

**验证说明**: bitSet calculates word_offset=(index>>6)*8 without bounds check against bitmap size. However, bitmap is allocated based on num_cols from calculateBitSetWidthInBytes, providing implicit bounds. Vulnerability exists if num_cols causes integer overflow leading to undersized bitmap allocation.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: -5

---

### [cpp-core-jni-VULN-003] Path Traversal - Java_org_apache_gluten_vectorized_PlanEvaluatorJniWrapper_nativeCreateKernelWithIterator

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/core/jni/JniWrapper.cc:433-449` @ `Java_org_apache_gluten_vectorized_PlanEvaluatorJniWrapper_nativeCreateKernelWithIterator`
**模块**: cpp-core-jni

**描述**: Unsafe path handling in nativeCreateKernelWithIterator. The saveDir path from Spark configuration is used directly for filesystem operations (create_directory) without path traversal validation. An attacker could inject paths like ../ to escape intended directories.

**漏洞代码** (`cpp/core/jni/JniWrapper.cc:433-449`)

```c
std::filesystem::path f{saveDir}; std::filesystem::create_directory(f, ec);
```

**达成路径**

JVM(sessionConf) -> parseConfMap() -> saveDir -> filesystem::create_directory

**验证说明**: POSSIBLE: Path from Spark config used in create_directory without traversal validation. Could inject '../' to escape directories. Limited by admin-controlled configuration - not direct user input.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -20 | cross_file: 0

---

### [VULN-CPP-SHUFFLE-005] Buffer Overflow - SplitFixedWidthValueBuffer

**严重性**: Medium | **CWE**: CWE-787 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/shuffle/splitter.cpp:159-170` @ `SplitFixedWidthValueBuffer`
**模块**: cpp-omni-shuffle

**描述**: Partition buffer array access with pid from partition_used_.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/shuffle/splitter.cpp:159-170`)

```c
dstPidBase = dst_addrs[pid] + partition_buffer_idx_base_[pid]
```

**达成路径**

[IN] partition_used_ [OUT] value_addrs_

**验证说明**: Indirect vulnerability: dstPidBase access uses pid from partition_used_ which only contains positive pids (filtered by partition_id_cnt_cur_[pid] > 0). However, overflow in partition_id_cnt_cur_ could affect partition_used_ indirectly. Lower confidence due to filtering protection.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: -15 | cross_file: 0

---

### [CPP-SHUFFLE-003] Integer Overflow - merge

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/core/shuffle/Payload.cc:357` @ `merge`
**模块**: cpp-core-shuffle

**描述**: mergedRows = source->numRows() + append->numRows() without overflow check. Large row counts from partition buffers can overflow uint32_t numRows_ field causing memory corruption.

**漏洞代码** (`cpp/core/shuffle/Payload.cc:357`)

```c
auto mergedRows = source->numRows() + append->numRows()
```

**达成路径**

[IN] numRows (from partition) -> merge -> Resize [OUT]

**验证说明**: mergedRows = source->numRows() + append->numRows() without overflow check. uint32_t overflow possible if numRows > 2^31. Requires extremely large row counts (rare in Spark shuffle).

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CPP-SHUFFLE-004] Integer Overflow - merge

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/core/shuffle/Payload.cc:409` @ `merge`
**模块**: cpp-core-shuffle

**描述**: mergedSize = sourceBufferSize + appendBuffer->size() without overflow check. Large buffer sizes can overflow int64_t leading to buffer underallocation during resize.

**漏洞代码** (`cpp/core/shuffle/Payload.cc:409`)

```c
auto mergedSize = sourceBufferSize + appendBuffer->size()
```

**达成路径**

[IN] buffer sizes -> merge -> memcpy [OUT]

**验证说明**: Same as CPP-SHUFFLE-005: mergedSize integer overflow in merge function. Triggering requires large buffer sizes.

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CPP-SHUFFLE-005] Buffer Overflow - merge

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/core/shuffle/Payload.cc:420` @ `merge`
**模块**: cpp-core-shuffle

**描述**: memcpy in buffer merge without bounds validation. resizable->mutable_data() + sourceBufferSize could write past allocated buffer if mergedSize calculation overflowed or allocation failed.

**漏洞代码** (`cpp/core/shuffle/Payload.cc:420`)

```c
memcpy(resizable->mutable_data() + sourceBufferSize, appendBuffer->data(), appendBuffer->size())
```

**达成路径**

[IN] appendBuffer -> merge -> memcpy [OUT]

**验证说明**: Integer overflow in mergedSize = sourceBufferSize + appendBuffer->size(). If both are large (>2^31), Resize allocates undersized buffer and memcpy overflows. Triggering requires extremely large partitions (rare in Spark shuffle).

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CPP-SHUFFLE-008] Integer Overflow - merge

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/core/shuffle/LocalPartitionWriter.cc:151` @ `merge`
**模块**: cpp-core-shuffle

**描述**: mergedRows calculation in PayloadMerger::merge without overflow check. Large partition row counts can overflow.

**漏洞代码** (`cpp/core/shuffle/LocalPartitionWriter.cc:151`)

```c
auto mergedRows = append->numRows() + lastPayload->numRows()
```

**达成路径**

[IN] numRows -> merge -> partitionMergePayload [OUT]

**验证说明**: Same integer overflow pattern as CPP-SHUFFLE-003: mergedRows in PayloadMerger::merge.

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-MOD-SCAN-007] Improper Input Validation - MmapFileStream::open

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/core/shuffle/Utils.cc:230-243` @ `MmapFileStream::open`
**模块**: cpp-core-shuffle
**跨模块**: cpp-core-jni,cpp-core-shuffle

**描述**: MmapFileStream::open() accepts path parameter from Spill::openForRead() which uses spillFile_ set from external sources. The path is used for mmap() without validation. If spill file was manipulated or replaced with symlink, mmap could map attacker-controlled file content into process memory.

**漏洞代码** (`cpp/core/shuffle/Utils.cc:230-243`)

```c
mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd.fd(), 0)
```

**达成路径**

spillFile_ (from createTempShuffleFile) -> Spill::openForRead -> MmapFileStream::open -> mmap()

**验证说明**: mmap() uses path from spillFile_ (created by createTempShuffleFile). If spill file replaced by symlink, mmap could map attacker-controlled content. Requires local attacker and TOCTOU window.

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-MOD-SCAN-003] TOCTOU Race Condition - createTempShuffleFile

**严重性**: Medium | **CWE**: CWE-367 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/core/shuffle/Utils.cc:340-365` @ `createTempShuffleFile`
**模块**: cpp-core-shuffle

**描述**: createTempShuffleFile() has TOCTOU race between checking directory existence (line 340) and creating directories (line 345). Attacker with local access could replace directory with symlink, causing files in unintended locations. O_CREAT|O_EXCL mitigates file-level races but directory-level race remains.

**漏洞代码** (`cpp/core/shuffle/Utils.cc:340-365`)

```c
exists() check -> create_directories()
```

**达成路径**

exists() check -> attacker symlink swap -> create_directories() follows symlink

**验证说明**: TOCTOU between exists() check (line 340) and create_directories() (line 345). Attacker with local access can swap directory with symlink. O_CREAT|O_EXCL mitigates file-level race but not directory-level.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

## 6. Low 漏洞 (19)

### [JNI-014] Information Exposure - Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_split

**严重性**: Low | **CWE**: CWE-200 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:139-141` @ `Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_split`
**模块**: cpp-omni-jni

**描述**: Error messages include memory addresses (splitter_addr) which can leak ASLR bypass information. This information could help attackers understand memory layout for exploitation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:139-141`)

```c
std::string error_message = "Invalid splitter id " + std::to_string(splitter_addr); env->ThrowNew(runtimeExceptionClass, error_message.c_str());
```

**验证说明**: Memory address leak in error message could assist ASLR bypass. splitter_addr is directly exposed via std::to_string().

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [JNI-011] NULL Pointer Dereference - Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_split

**严重性**: Low | **CWE**: CWE-476 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:134-149` @ `Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_split`
**模块**: cpp-omni-jni

**描述**: In split function, the splitter pointer check and error handling occurs before JNI_FUNC_START macro. The error message includes splitter_addr value in exception which could leak memory layout information.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:134-149`)

```c
auto splitter = reinterpret_cast<Splitter*>(splitter_addr); if (!splitter) { std::string error_message = "Invalid splitter id " + std::to_string(splitter_addr); env->ThrowNew(runtimeExceptionClass, error_message.c_str()); }
```

**验证说明**: split函数在JNI_FUNC_START前检查splitter，异常消息包含splitter_addr内存地址值，导致信息泄露而非NULL指针解引用。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -5 | context: 5 | cross_file: 0

---

### [VULN-SHUFFLE-007] Integer Truncation - WriteBufferFromJavaOutputStream::nextImpl

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `cpp-ch/local-engine/Shuffle/WriteBufferFromJavaOutputStream.cpp:33-34` @ `WriteBufferFromJavaOutputStream::nextImpl`
**模块**: cpp-ch-shuffle

**描述**: Integer truncation when casting size_t to jint: static_cast<jint>(...) may truncate large buffer sizes (>2GB) leading to incomplete data transfer to Java.

**漏洞代码** (`cpp-ch/local-engine/Shuffle/WriteBufferFromJavaOutputStream.cpp:33-34`)

```c
jint copy_num = static_cast<jint>(std::min(offset() - bytes_write, buffer_size));
```

**达成路径**

[IN] C++ buffer -> [JNI] jint truncation -> [OUT] Java array

**验证说明**: Integer truncation: static_cast<jint>(buffer_size) truncates values > 2GB (INT_MAX). Large buffer_size config causes incomplete data transfer to Java. Rare in practice but possible with malicious config.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [JNI-012] Improper Validation of Array Index - Java_org_apache_gluten_vectorized_OmniPlanEvaluatorJniWrapper_nativeCreateKernelWithIterator

**严重性**: Low | **CWE**: CWE-129 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:280-287` @ `Java_org_apache_gluten_vectorized_OmniPlanEvaluatorJniWrapper_nativeCreateKernelWithIterator`
**模块**: cpp-omni-jni

**描述**: nativeCreateKernelWithIterator gets iterArr length from JVM without validation. A malicious caller could provide inconsistent array sizes or extremely large values, potentially causing integer overflow in loop iteration or resource exhaustion.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/SparkJniWrapper.cpp:280-287`)

```c
jsize itersLen = env->GetArrayLength(iterArr);
std::vector<std::shared_ptr<omniruntime::ResultIterator>> inputIters;
for (int idx = 0; idx < itersLen; idx++) {
    jobject iter = env->GetObjectArrayElement(iterArr, idx);
    // No validation of itersLen bounds or array consistency
}
```

**验证说明**: iterArr长度来自GetArrayLength，Java数组有大小限制，GetObjectArrayElement有边界检查。实际风险较低。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN_CPP_CH_MAIN_008] Passing Sensitive Data to External Method - BackendInitializerUtil::initEnvs

**严重性**: Low | **CWE**: CWE-374 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Common/CHUtil.cpp:561-614` @ `BackendInitializerUtil::initEnvs`
**模块**: cpp-ch-main
**跨模块**: libhdfs3, HDFS client

**描述**: Environment variables (CLICKHOUSE_BACKEND_CONFIG, SPARK_USER, LIBHDFS3_CONF) are read in initEnvs and used to configure backend. These environment variables could be manipulated by attackers to change configuration paths or impersonate users.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Common/CHUtil.cpp:561-614`)

```c
if (const char * config_path = std::getenv("CLICKHOUSE_BACKEND_CONFIG")) return config_path; if (const char * spark_user_c_str = std::getenv("SPARK_USER")) spark_user = spark_user_c_str;
```

**达成路径**

Environment variables -> configuration paths / user identity

**验证说明**: Environment variables (CLICKHOUSE_BACKEND_CONFIG, SPARK_USER, LIBHDFS3_CONF) read for configuration. Requires local access to manipulate environment. More of a deployment security concern than code vulnerability.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -10 | cross_file: 0

---

### [VULN-CH-STORAGE-002] Information Exposure in Logs - adjustReadRangeIfNeeded

**严重性**: Low | **CWE**: CWE-532 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:203-209` @ `adjustReadRangeIfNeeded`
**模块**: cpp-ch-storages

**描述**: File paths and read positions are logged in debug messages, potentially exposing sensitive file locations and access patterns to unauthorized viewers of logs.

**漏洞代码** (`cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:203-209`)

```c
LOG_DEBUG(&Poco::Logger::get("ReadBufferBuilder"),
    "File read start and end position adjusted from {},{} to {},{}",
    file_info.start(), file_info.start() + file_info.length(),
    start_end.first, start_end.second);
```

**验证说明**: LOG_DEBUG日志泄露文件路径和读位置，仅DEBUG模式生效

---

### [cpp-ch-parser-009] Buffer Overflow - FixedLengthDataWriter::write

**严重性**: Low | **CWE**: CWE-787 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp:868-948` @ `FixedLengthDataWriter::write`
**模块**: cpp-ch-parser

**描述**: FixedLengthDataWriter::write uses memcpy without validating buffer bounds relative to allocated SparkRow size.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/CHColumnToSparkRow.cpp:868-948`)

```c
memcpy(buffer, &value, size);
```

**达成路径**

Column data -> write -> memcpy unvalidated

**验证说明**: FixedLengthDataWriter::write uses memcpy with size determined by type (1/2/4/8 bytes), not attacker controlled. However buffer pointer comes from offsets+field_offset calculation which could be influenced by malicious column data. Less severe as size is fixed.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-CH-STORAGE-003] Credential Handling - S3FileReadBufferBuilder::getClient

**严重性**: Low | **CWE**: CWE-522 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:480-512` @ `S3FileReadBufferBuilder::getClient`
**模块**: cpp-ch-storages

**描述**: S3 client credentials (access key, secret key) are cached without expiration or refresh mechanism. Long-lived cached credentials increase exposure window if memory is compromised.

**漏洞代码** (`cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:480-512`)

```c
void cacheClient(const std::string & bucket_name, const bool is_per_bucket, std::shared_ptr<DB::S3::Client> client) {
    if (is_per_bucket) {
        per_bucket_clients.insert(bucket_name, client);
    } else {
        per_bucket_clients.insert(SHARED_CLIENT_KEY, client);
    }
}
```

**验证说明**: S3凭证缓存无过期机制，内存泄露风险有限

---

### [VULN-CH-STORAGE-005] Information Exposure Through Error - LocalFileReadBufferBuilder::build

**严重性**: Low | **CWE**: CWE-209 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:239-240` @ `LocalFileReadBufferBuilder::build`
**模块**: cpp-ch-storages

**描述**: Error messages include full file paths and detailed error information, potentially exposing internal file system structure to attackers.

**漏洞代码** (`cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:239-240`)

```c
if (stat(file_path.c_str(), &file_stat))
    throw DB::Exception(DB::ErrorCodes::BAD_ARGUMENTS, "file stat failed for {}", file_path);
```

**验证说明**: 错误消息泄露文件路径，信息泄露风险有限

---

### [cpp-core-jni-VULN-011] Information Exposure - Java_org_apache_gluten_vectorized_PlanEvaluatorJniWrapper_nativeCreateKernelWithIterator

**严重性**: Low | **CWE**: CWE-200 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/core/jni/JniWrapper.cc:449-450` @ `Java_org_apache_gluten_vectorized_PlanEvaluatorJniWrapper_nativeCreateKernelWithIterator`
**模块**: cpp-core-jni
**跨模块**: cpp-core-compute

**描述**: Sensitive configuration dump to file in dumpConf. Configuration values including potential secrets are written to files without sanitization. The saveDir and file paths could expose sensitive data.

**漏洞代码** (`cpp/core/jni/JniWrapper.cc:449-450`)

```c
ctx->dumpConf(saveDir + "/conf" + fileIdentifier + ".ini");
```

**达成路径**

JVM(sessionConf) -> parseConfMap() -> Runtime.dumpConf() -> File Write

**验证说明**: POSSIBLE: Configuration dumped to file potentially exposing secrets. saveDir path from config, not direct user input. Information exposure risk, limited by admin-controlled configuration.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -20 | cross_file: 0

---

### [VULN-007] Path Traversal - unknown

**严重性**: Low | **CWE**: CWE-22 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:239-240` @ `?`
**模块**: cpp-ch-storages

**描述**: stat() called on file_path from Poco::URI.getPath() without sanitization. Malicious URI could contain path traversal sequences (../) allowing access to unintended files.

**漏洞代码** (`cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:239-240`)

```c
stat(file_path.c_str(), &file_stat)
```

**达成路径**

[IN] Substrait file URI -> LocalFileReadBufferBuilder

**验证说明**: 与VULN-CH-STORAGE-001重复，路径遍历风险

---

### [VULN-008] Memory Allocation Issue - unknown

**严重性**: Low | **CWE**: CWE-787 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:768-771` @ `?`
**模块**: cpp-ch-storages

**描述**: buffer_size from context settings passed to SplittableBzip2ReadBuffer without explicit upper bounds validation. Large settings could cause excessive memory allocation.

**漏洞代码** (`cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:768-771`)

```c
size_t buffer_size = context->getSettingsRef()[DB::Setting::max_read_buffer_size]
```

**达成路径**

[IN] Context settings -> wrapWithBzip2 buffer allocation

**验证说明**: buffer_size来自context设置，ClickHouse有内部上限

---

### [VULN-CH-STORAGE-007] Race Condition - S3FileReadBufferBuilder::S3FileReadBufferBuilder

**严重性**: Low | **CWE**: CWE-367 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:377-378` @ `S3FileReadBufferBuilder::S3FileReadBufferBuilder`
**模块**: cpp-ch-storages

**描述**: Cache directories are created without proper permission checks or ownership verification. Time-of-check-to-time-of-use race condition possible between exists() and create_directories().

**漏洞代码** (`cpp-ch/local-engine/Storages/SubstraitSource/ReadBufferBuilder.cpp:377-378`)

```c
if (!std::filesystem::exists(cache_base_path))
    std::filesystem::create_directories(cache_base_path);
```

**验证说明**: exists/create_directories TOCTOU竞态，需本地攻击者

---

### [VULN-CH-STORAGE-008] Information Exposure Through Error - CacheManager::cachePart lambda

**严重性**: Low | **CWE**: CWE-209 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp-ch/local-engine/Storages/Cache/CacheManager.cpp:147-150` @ `CacheManager::cachePart lambda`
**模块**: cpp-ch-storages

**描述**: Exception messages are logged with full table names, database names, and part names. This information exposure could aid attackers in reconnaissance.

**漏洞代码** (`cpp-ch/local-engine/Storages/Cache/CacheManager.cpp:147-150`)

```c
LOG_ERROR(getLogger("CacheManager"), "Load cache of table {}.{} part {} failed.\n {}",
    job_detail.table.database, job_detail.table.table, job_detail.table.parts.front().name, e.what());
```

**验证说明**: LOG_ERROR泄露表名和数据库名，信息泄露风险有限

---

### [VULN-CH-STORAGE-009] Path Traversal - CacheManager::removeFiles

**严重性**: Low | **CWE**: CWE-22 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp-ch/local-engine/Storages/Cache/CacheManager.cpp:249-259` @ `CacheManager::removeFiles`
**模块**: cpp-ch-storages

**描述**: removeFiles() accepts arbitrary file path without validation. Could be exploited to delete files outside the cache directory if the file parameter is attacker-controlled.

**漏洞代码** (`cpp-ch/local-engine/Storages/Cache/CacheManager.cpp:249-259`)

```c
void CacheManager::removeFiles(String file, String cache_name) {
    for (const auto & [name, file_cache] : FileCacheFactory::instance().getAll()) {
        if (const auto cache = file_cache->cache)
            cache->removePathIfExists(file, DB::FileCache::getCommonUser().user_id);
    }
}
```

**验证说明**: removeFiles路径参数需验证，但调用上下文受限

---

### [VULN_CPP_CH_MAIN_006] NULL Pointer Dereference - jstring2string

**严重性**: Low | **CWE**: CWE-476 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:77-85` @ `jstring2string`
**模块**: cpp-ch-main

**描述**: jstring2string function checks for null jstring but returns empty string. However, GetStringUTFChars is called without checking if string is valid UTF-8. Malformed UTF-8 strings could cause issues. More critically, some JNI functions call jstring2string without first validating the jobject is of correct type.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/local_engine_jni.cpp:77-85`)

```c
const char * chars = env->GetStringUTFChars(string, nullptr); std::string ret(chars);
```

**达成路径**

Java jstring -> GetStringUTFChars -> std::string construction

**验证说明**: jstring2string has null check for jstring. GetStringUTFChars called without UTF-8 validation but JNI handles most cases. Minor issue - malformed UTF-8 unlikely to cause security impact.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: -10 | cross_file: 0

---

### [VULN-CH-STORAGE-010] Improper Exception Handling - setCurrentTaskWriteInfo

**严重性**: Low | **CWE**: CWE-754 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp-ch/local-engine/Storages/MergeTree/SparkMergeTreeWriter.cpp:70-77` @ `setCurrentTaskWriteInfo`
**模块**: cpp-ch-storages

**描述**: JNI calls in setCurrentTaskWriteInfo() lack exception checking. JNI exceptions could cause undefined behavior if not properly detected and handled.

**漏洞代码** (`cpp-ch/local-engine/Storages/MergeTree/SparkMergeTreeWriter.cpp:70-77`)

```c
void setCurrentTaskWriteInfo(const std::string & jobTaskTempID, const std::string & commitInfos) {
    GET_JNIENV(env)
    const jstring Java_jobTaskTempID = charTojstring(env, jobTaskTempID.c_str());
    const jstring Java_commitInfos = charTojstring(env, commitInfos.c_str());
    safeCallVoidMethod(env, Java_MergeTreeCommiterHelper, Java_set, Java_jobTaskTempID, Java_commitInfos);
    CLEAN_JNIENV
}
```

**验证说明**: JNI异常处理缺失，但safeCallVoidMethod有封装

---

### [CPP-SHUFFLE-002] Integer Overflow - maxCompressedLength

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/core/shuffle/Payload.cc:342-350` @ `maxCompressedLength`
**模块**: cpp-core-shuffle

**描述**: Integer overflow in maxCompressedLength when calculating metadataLength = sizeof(int64_t) * 2 * buffers.size(). If buffers.size() is large (e.g., > 2^30), multiplication can overflow int64_t leading to buffer underallocation.

**漏洞代码** (`cpp/core/shuffle/Payload.cc:342-350`)

```c
const auto metadataLength = sizeof(int64_t) * 2 * buffers.size()
```

**达成路径**

[IN] numBuffers (from serialization) -> maxCompressedLength -> AllocateResizableBuffer [OUT]

**验证说明**: Integer overflow in metadataLength = sizeof(int64_t) * 2 * buffers.size(). Requires buffers.size() > 2^30, unrealistic in normal shuffle operations. Vector size is typically hundreds, not billions.

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CPP-SHUFFLE-006] Buffer Overflow - compressBuffer

**严重性**: Low | **CWE**: CWE-120 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `cpp/core/shuffle/Payload.cc:84` @ `compressBuffer`
**模块**: cpp-core-shuffle

**描述**: memcpy in compressAndFlush writes compressed data without validating output buffer bounds after compression. Available length calculation may be incorrect.

**漏洞代码** (`cpp/core/shuffle/Payload.cc:84`)

```c
memcpy(*outputPtr, buffer->data(), buffer->size())
```

**达成路径**

[IN] buffer -> compressBuffer -> outputStream [OUT]

**验证说明**: memcpy in compressBuffer writes uncompressed data when compression fails to shrink. Allocated buffer size is sizeof(int64_t)*2 + maxCompressedLength. Vulnerable if codec.MaxCompressedLen() returns value smaller than buffer->size() (depends on codec implementation).

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

## 7. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cpp-ch-main | 0 | 3 | 8 | 2 | 13 |
| cpp-ch-parser | 0 | 0 | 11 | 1 | 12 |
| cpp-ch-shuffle | 0 | 3 | 5 | 1 | 9 |
| cpp-ch-storages | 0 | 3 | 3 | 9 | 15 |
| cpp-core-jni | 0 | 1 | 7 | 1 | 9 |
| cpp-core-shuffle | 0 | 7 | 6 | 2 | 15 |
| cpp-omni-compute | 0 | 0 | 4 | 0 | 4 |
| cpp-omni-jni | 2 | 3 | 3 | 3 | 11 |
| cpp-omni-shuffle | 0 | 6 | 3 | 0 | 9 |
| **合计** | **2** | **26** | **50** | **19** | **97** |

## 8. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 21 | 21.6% |
| CWE-190 | 16 | 16.5% |
| CWE-787 | 11 | 11.3% |
| CWE-22 | 9 | 9.3% |
| CWE-129 | 5 | 5.2% |
| CWE-120 | 5 | 5.2% |
| CWE-125 | 4 | 4.1% |
| CWE-476 | 3 | 3.1% |
| CWE-209 | 3 | 3.1% |
| CWE-416 | 2 | 2.1% |
| CWE-367 | 2 | 2.1% |
| CWE-200 | 2 | 2.1% |
| CWE-191 | 2 | 2.1% |
| CWE-918 | 1 | 1.0% |
| CWE-789 | 1 | 1.0% |
| CWE-770 | 1 | 1.0% |
| CWE-754 | 1 | 1.0% |
| CWE-73 | 1 | 1.0% |
| CWE-704 | 1 | 1.0% |
| CWE-532 | 1 | 1.0% |
| CWE-522 | 1 | 1.0% |
| CWE-502 | 1 | 1.0% |
| CWE-374 | 1 | 1.0% |
| CWE-369 | 1 | 1.0% |
| CWE-121 | 1 | 1.0% |
