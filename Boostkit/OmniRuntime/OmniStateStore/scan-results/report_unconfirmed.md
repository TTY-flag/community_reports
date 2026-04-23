# 漏洞扫描报告 — 待确认漏洞

**项目**: OmniStateStore  
**扫描时间**: 2026-04-22T15:30:00Z  
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞  

---

## 执行摘要

### 扫描概述

OmniStateStore 是华为 Kunpeng BoostKit 项目中的 Apache Flink 状态存储引擎，采用 C/C++ 实现，通过 JNI 接口与 Java Flink TaskManager 进程交互。本次安全扫描覆盖 380 个源文件、57,205 行代码，重点关注 checkpoint 恢复流程中的二进制解析漏洞。

### 发现统计

- **总漏洞数**: 21 个 (LIKELY: 16, POSSIBLE: 5)
- **严重性分布**: Critical (2) | High (9) | Medium (9) | Low (1)
- **误报率**: 0% (无 FALSE_POSITIVE)
- **平均置信度**: 64.5/100

### 主要风险分析

本次扫描发现的漏洞集中于 **Checkpoint 恢复路径**，这是 OmniStateStore 最关键的安全边界：

1. **攻击向量**: 攻击者可通过篡改 HDFS/S3/本地磁盘上的 checkpoint 文件，注入恶意构造的二进制数据
2. **攻击场景**: Flink 任务故障恢复、增量 checkpoint 合并、并行度变更时的 rescale 操作
3. **潜在影响**: 
   - 内存破坏/堆溢出导致进程崩溃或代码执行
   - 整数溢出导致内存分配异常
   - 路径遍历导致敏感文件泄露

### 关键漏洞类型

| CWE 类型 | 数量 | 核心风险 |
|---------|------|---------|
| CWE-120 (Buffer Overflow) | 9 | 二进制解析时未验证数组大小边界 |
| CWE-190 (Integer Overflow) | 8 | 文件头字段用于内存分配前未做上限检查 |
| CWE-191 (Integer Underflow) | 1 | 无符号整数减法可能产生极大值 |
| CWE-22 (Path Traversal) | 1 | JNI 路径验证缺乏白名单机制 |
| CWE-843 (Type Confusion) | 1 | JNI handle 无类型校验 |

### 建议优先级

| 优先级 | 漏洞 ID | 修复时间建议 |
|--------|---------|-------------|
| P0 (立即) | VULN-SEC-SLICE-001, VULN-SEC-SNAPSHOT-001 | 2-3 天 |
| P1 (高) | VULN-DF-001, VULN-SEC-SNAPSHOT-002, VULN-SEC-LSM-001 | 1 周 |
| P2 (中) | 其他 High/Medium 漏洞 | 2 周 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 16 | 76.2% |
| POSSIBLE | 5 | 23.8% |
| **总计** | **21** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 2 | 9.5% |
| High | 9 | 42.9% |
| Medium | 9 | 42.9% |
| Low | 1 | 4.8% |
| **有效漏洞总计** | **21** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-SLICE-001]** memory_corruption (Critical) - `src/core/snapshot/slice_table_restore_operation.cpp:214` @ `SliceTableRestoreOperation::LoadSlicesIntoLogicalSliceChain` | 置信度: 75
2. **[VULN-SEC-SNAPSHOT-001]** integer_overflow (Critical) - `src/core/lsm_store/file/file_reader.cpp:141` @ `FileReaderBase::ReadBlock` | 置信度: 65
3. **[VULN-DF-001]** buffer_overflow (High) - `src/core/slice_table/slice/slice.cpp:615` @ `Slice::RestoreSliceUseByteBuffer` | 置信度: 75
4. **[VULN-SEC-JNI-001]** integer_overflow (High) - `src/core/slice_table/slice/slice.cpp:615` @ `Slice::RestoreSliceUseByteBuffer` | 置信度: 75
5. **[VULN-SEC-SNAPSHOT-002]** buffer_overflow (High) - `src/core/snapshot/snapshot_restore_utils.cpp:156` @ `SnapshotRestoreUtils::ReadSnapshotMetaTail` | 置信度: 75
6. **[VULN-SEC-LSM-001]** integer_overflow (High) - `src/core/lsm_store/block/index_reader.cpp:75` @ `IndexReader::GetBlockAt` | 置信度: 75
7. **[VULN-SEC-SLICE-002]** buffer_overflow (High) - `src/core/binary/slice_binary.h:303` @ `SliceHeadSpace::Init` | 置信度: 75
8. **[VULN-DF-011]** buffer_overflow (High) - `src/core/binary/slice_binary.h:39` @ `SliceKey::Unpack` | 置信度: 75
9. **[VULN-DF-009]** integer_overflow (High) - `src/core/blob_store/blob_file_reader.cpp:64` @ `BlobFileReader::ReadBlock` | 置信度: 65
10. **[VULN-DF-004]** buffer_overflow (High) - `src/core/binary/lsm_binary.h:107` @ `LsmKeyValueInfo::Unpack` | 置信度: 60

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `Java_com_huawei_ock_bss_common_BoostStateDB_open@src/core/jni/com_huawei_ock_bss_common_BoostStateDB.cpp` | jni | semi_trusted | JNI entry point - receives BoostConfig object from Java Flink TaskManager. Config contains paths, sizes, and settings from Flink configuration. | Opens BoostStateDB with configuration from Java layer |
| `Java_com_huawei_ock_bss_common_BoostStateDB_restore@src/core/jni/com_huawei_ock_bss_common_BoostStateDB.cpp` | jni | untrusted_local | JNI entry point - receives file paths from Java for restore. Paths come from checkpoint locations which may be on HDFS or local disk controlled by Flink. | Restores state database from checkpoint paths |
| `Java_com_huawei_ock_bss_table_KVTableImpl_put@src/core/jni/com_huawei_ock_bss_table_KVTableImpl.cpp` | jni | semi_trusted | JNI entry point - receives key/value data from Java Flink operators. Data comes from streaming job processing. | Puts key-value pair into KV table |
| `Java_com_huawei_ock_bss_table_AbstractTable_open@src/core/jni/com_huawei_ock_bss_table_AbstractTable.cpp` | jni | semi_trusted | JNI entry point - receives table name, state type from Java | Opens state table with given name |
| `SnapshotRestoreUtils::Deserialize@src/core/snapshot/snapshot_restore_utils.cpp` | file | untrusted_local | Reads binary data from checkpoint meta files. Files come from external checkpoint storage (HDFS/S3/local disk). | Deserializes snapshot operator info from file input view |
| `SnapshotRestoreUtils::ReadSnapshotOperatorInfo@src/core/snapshot/snapshot_restore_utils.cpp` | file | untrusted_local | Reads snapshot operator metadata from checkpoint file | Reads snapshot operator info array from file |
| `Slice::RestoreSliceUseByteBuffer@src/core/slice_table/slice/slice.cpp` | file | untrusted_local | Restores slice structure from ByteBuffer containing checkpoint data. Buffer filled from file read. | Restores slice from binary buffer data |
| `FileReader::ReadBlock@src/core/lsm_store/file/file_reader.cpp` | file | untrusted_local | Reads compressed block data from SST files. Files are checkpoint/snapshot data from external storage. | Reads and decompresses block from SST file |
| `DataBlock::InitIndexReader@src/core/lsm_store/block/data_block.cpp` | file | untrusted_local | Parses data block header from file buffer | Initializes data block index reader |
| `IndexReader::GetBlockIndex@src/core/lsm_store/block/index_reader.cpp` | file | untrusted_local | Parses index block entries from file buffer using variable-length encoding | Gets block index from index block buffer |
| `FullKeyUtil::ReadInternalKey@src/core/lsm_store/key/full_key_util.cpp` | file | untrusted_local | Parses full key structure (stateId, key, seqId, valueType) from file buffer | Reads internal key structure from file |
| `LsmKeyValueInfo::Unpack@src/core/binary/lsm_binary.h` | file | untrusted_local | Unpacks LSM key-value info from binary buffer - reads length fields, key data, value data | Unpacks key-value info from buffer |
| `HadoopFileSystem::Read@src/core/common/fs/hdfs/hadoop_file_system.h` | file | untrusted_network | Reads data from HDFS via JNI. Data comes from remote Hadoop cluster. | Reads bytes from HDFS file |
| `LocalFileSystem::Read@src/core/fs/local/local_file_system.h` | file | untrusted_local | Reads data from local file using pread/read syscalls. Files may be checkpoint data. | Reads from local file |
| `Lz4Interface::Decompress@src/core/compress/lz4_interface.cpp` | file | untrusted_local | Decompresses data with srcSize/dstCapacity from file. Size parameters come from file headers. | Decompresses LZ4 compressed data |
| `FileInputView::ReadUTF@src/core/common/io/file_input_view.h` | file | untrusted_local | Reads UTF string length and data from file. Length field read from file (limited to 128KB). | Reads UTF string from file |
| `LazyDownloadStrategy::Download@src/core/lsm_store/lazy/lazy_download_strategy.cpp` | file | untrusted_network | Downloads file from remote HDFS storage for lazy restore | Downloads file from remote storage |
| `JNI_OnLoad@src/core/jni/jni_common.cpp` | jni | semi_trusted | JNI library initialization - called when library is loaded by JVM | JNI library initialization hook |
| `AbstractBoostIncrementalRestoreOperation::restoreMeta@src/plugin/state_store_plugin/flink-1.17.1/com/huawei/ock/bss/restore/AbstractBoostIncrementalRestoreOperation.java` | file | untrusted_local | Deserializes checkpoint metadata from input stream - reads version, jobID, state descriptors | Restores checkpoint metadata from stream |

**其他攻击面**:
- JNI Interface: 25+ JNI entry points receiving data from Java Flink TaskManager
- Checkpoint Restore: Binary parsing of snapshot/slice/meta files from external storage
- HDFS I/O: File reads from remote Hadoop cluster via JNI bridge
- Local File I/O: Reading checkpoint files from local disk
- LZ4 Decompression: Decompression of blocks with size parameters from file
- Binary Parsing: LsmKeyValueInfo, SliceKey, DataBlock, IndexBlock parsing from file buffers
- Variable-length Encoding: VarEncodingUtil::DecodeUnsignedInt reads without strict bounds
- ByteBuffer Operations: memcpy_s with buffer data from files

---

## 3. Top 5 关键漏洞深度分析

### [VULN-SEC-SLICE-001] Memory Corruption — SliceTableRestoreOperation::LoadSlicesIntoLogicalSliceChain

**严重性**: Critical | **CWE**: CWE-119 | **置信度**: 75/100 | **状态**: LIKELY

#### 漏洞位置
`src/core/snapshot/slice_table_restore_operation.cpp:214-255`

#### 深度分析

**漏洞根源**: 该函数从 checkpoint 文件读取 SliceAddress 结构，直接使用 `GetDataLen()` 和 `GetStartOffset()` 字段进行内存分配和文件定位，未实施任何边界验证。

**源代码验证** (lines 214-255):

```cpp
BResult SliceTableRestoreOperation::LoadSlicesIntoLogicalSliceChain(const LogicalSliceChainRef &sliceChain,
                                                                    uint32_t snapshotVersion)
{
    // ...
    while (sliceIterator->HasNext()) {
        SliceAddressRef sliceAddress = sliceIterator->Next();
        // ...
        
        // 关键漏洞点: sliceAddress 来自 checkpoint，字段未验证
        auto buffer = MakeRef<ByteBuffer>(sliceAddress->GetDataLen(), MemoryType::SLICE_TABLE, mMemManager);
        RETURN_ALLOC_FAIL_AS_NULLPTR(buffer);
        
        auto restoreFilePath = std::make_shared<Path>(sliceAddress->GetLocalAddress());
        FileInputViewRef inputView = std::make_shared<FileInputView>();
        inputView->Init(FileSystemType::LOCAL, restoreFilePath);
        
        // GetStartOffset 用于 Seek，GetDataLen 用于读取长度 — 均未验证
        auto ret = inputView->ReadByteBuffer(0, buffer, sliceAddress->GetStartOffset(), sliceAddress->GetDataLen());
        // ...
    }
}
```

**攻击路径**:
1. 攻击者篡改 checkpoint 文件中的 SliceAddress 结构
2. 将 `DataLen` 设为极大值 (如 0xFFFFFFFF)，触发内存耗尽或分配失败
3. 将 `StartOffset` 设为负值或超出文件边界，导致 Seek 异常或读取无效数据
4. 结合其他漏洞，可实现堆溢出后的代码执行

**影响范围**: 
- 该函数是 Flink 任务故障恢复的核心路径，在每次恢复时都会调用
- 影响所有使用 slice_table 状态存储的 Flink 流式任务
- 可导致 TaskManager 进程崩溃，影响整个 Flink 集群稳定性

**修复建议**:
```cpp
// 建议添加的验证逻辑
uint32_t maxSliceSize = mConfig->GetMaxSliceSize();  // 从配置获取上限
uint32_t dataLen = sliceAddress->GetDataLen();
if (UNLIKELY(dataLen == 0 || dataLen > maxSliceSize || dataLen > MAX_REASONABLE_SLICE_SIZE)) {
    LOG_ERROR("Invalid slice data length: " << dataLen);
    return BSS_INVALID_PARAM;
}

uint64_t startOffset = sliceAddress->GetStartOffset();
uint64_t fileSize = restoreFilePath->GetFileSize();
if (UNLIKELY(startOffset >= fileSize || startOffset + dataLen > fileSize)) {
    LOG_ERROR("Invalid slice offset: " << startOffset << ", fileSize: " << fileSize);
    return BSS_INVALID_PARAM;
}
```

---

### [VULN-SEC-SNAPSHOT-001] Integer Overflow — FileReaderBase::ReadBlock

**严重性**: Critical | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY

#### 漏洞位置
`src/core/lsm_store/file/file_reader.cpp:141-182`

#### 深度分析

**漏洞根源**: SST 文件块头部的 `originLength` 字段直接从文件读取，用于内存分配，仅有 CRC 校验而无长度上限验证。

**源代码验证** (lines 141-182):

```cpp
BResult FileReaderBase::ReadBlock(const BlockHandle &blockHandle, ByteBufferRef &byteBuffer)
{
    // ...
    // originLength 直接从文件头部读取，未经验证
    uint32_t originLength = *reinterpret_cast<uint32_t *>(byteBuffer->Data() + NO_1);
    uint32_t crc = *reinterpret_cast<uint32_t *>(byteBuffer->Data() + NO_5);
    
    // CRC 校验仅验证 checksum，不验证长度合理性
    if (UNLIKELY(crc != NO_1024)) {
        LOG_ERROR("Data crc check failed, crc:" << crc << ", except crc:" << NO_1024);
        return BSS_INNER_ERR;
    }
    
    // 关键漏洞点: originLength 用于内存分配，无上限检查
    auto addrOrigin = FileMemAllocator::Alloc(mMemManager, mHolder, originLength, __FUNCTION__);
    // ...
}
```

**攻击路径**:
1. SST 文件来自 HDFS 或本地 checkpoint 存储
2. 攻击者修改 SST 文件块头部，将 `originLength` 设为极大值
3. `FileMemAllocator::Alloc` 根据该值分配内存
4. 整数溢出: 若 `originLength` 约等于系统可用内存，可能导致 OOM
5. 若攻击者能控制后续的 Decompress 操作，可能触发堆溢出

**缓解措施分析**:
- CRC 校验 (line 171-174) 仅检查数据完整性，攻击者可同时修改数据和 CRC
- INT32_MAX 检查存在于 `Lz4Interface::Decompress`，但分配已发生
- 缺少对 `originLength` 与压缩后数据大小的合理性比对

**修复建议**:
```cpp
// 建议添加的验证逻辑
const uint32_t MAX_BLOCK_SIZE = 64 * 1024 * 1024;  // 64MB 上限
if (UNLIKELY(originLength == 0 || originLength > MAX_BLOCK_SIZE)) {
    LOG_ERROR("Invalid originLength from block header: " << originLength);
    return BSS_INVALID_PARAM;
}

// 验证 originLength 与压缩后数据的合理性关系
uint32_t compressedSize = rawSize;
if (originLength > compressedSize * 100) {  // 100倍压缩率异常
    LOG_ERROR("Suspicious decompression ratio, originLength: " << originLength 
              << ", compressedSize: " << compressedSize);
    return BSS_INVALID_PARAM;
}
```

---

### [VULN-DF-001] Buffer Overflow — Slice::RestoreSliceUseByteBuffer

**严重性**: High | **CWE**: CWE-120 | **置信度**: 75/100 | **状态**: LIKELY

#### 漏洞位置
`src/core/slice_table/slice/slice.cpp:615-668`

#### 深度分析

**漏洞根源**: SliceHead 结构的 `keyCount` 和 `indexCount` 字段直接从 ByteBuffer 读取，用于计算后续数据空间大小，缺少上限验证。

**源代码验证** (lines 615-668):

```cpp
void Slice::RestoreSliceUseByteBuffer(ByteBufferRef byteBuffer, MemManagerRef memManager)
{
    mInit = true;
    mBuffer = byteBuffer;
    mMemManager = memManager;

    uint8_t *data = mBuffer->Data();
    // SliceHead 直接从 buffer reinterpret，字段来自 checkpoint 文件
    mHeader = reinterpret_cast<SliceHead *>(data);

    // 关键漏洞点: kvCount 和 indexCount 未验证
    uint32_t kvCount = mHeader->keyCount;
    uint32_t indexCount = mHeader->indexCount;
    
    uint32_t indexWidth = NO_4;
    if (indexCount > BYTE4_MAX_SLOT_SIZE) {
        indexWidth = NO_8;
    }

    uint32_t bufferSize = 0;
    bufferSize += sizeof(SliceHead);
    uint32_t indexBase = bufferSize;
    bufferSize += indexCount * indexWidth;  // 整数溢出风险
    
    // ...
    bufferSize += kvCount * sizeof(uint32_t);  // 整数溢出风险
    // ...
    
    // 使用未验证的 kvCount 初始化空间
    mHashCodeSpace = std::make_shared<HashCodeSpace>(mBuffer, hashCodeBase);
    mSeqIdSpace = std::make_shared<SeqIdSpace>(mBuffer, seqIdBase);
    mIndexSpace = std::make_shared<IndexSpace>(mBuffer, indexBase, indexCount, indexWidth, true);
    mKeySpace = std::make_shared<KeySpace>(mBuffer, keyOffsetBase, kvCount);
    mValueSpace = std::make_shared<ValueSpace>(mBuffer, valueOffsetBase, kvCount);
}
```

**攻击路径**:
1. ByteBuffer 内容来自 checkpoint 文件的 Slice 数据
2. 攻击者构造恶意 SliceHead:
   - `keyCount` = 0xFFFFFFFF
   - `indexCount` = 0xFFFFFFFF
3. `bufferSize += indexCount * indexWidth` 计算时发生整数溢出
4. 溢出后的 bufferSize 可能是极小值，导致后续空间初始化超出 buffer 边界
5. `HashCodeSpace`, `KeySpace`, `ValueSpace` 的初始化可能访问非法内存

**整数溢出分析**:
```
indexCount = 0xFFFFFFFF, indexWidth = 4
bufferSize += 0xFFFFFFFF * 4 = 0xFFFFFFFC (溢出为 -4，实际为极大值或极小值取决于类型)
```

**修复建议**:
```cpp
// 建议添加的验证逻辑
const uint32_t MAX_KEY_COUNT = 10 * 1024 * 1024;  // 10M 上限
const uint32_t MAX_INDEX_COUNT = 10 * 1024 * 1024;

uint32_t kvCount = mHeader->keyCount;
uint32_t indexCount = mHeader->indexCount;

if (UNLIKELY(kvCount == 0 || kvCount > MAX_KEY_COUNT)) {
    LOG_ERROR("Invalid keyCount from SliceHead: " << kvCount);
    return;  // 或抛出异常
}

if (UNLIKELY(indexCount == 0 || indexCount > MAX_INDEX_COUNT)) {
    LOG_ERROR("Invalid indexCount from SliceHead: " << indexCount);
    return;
}

// 验证 bufferSize 不会溢出
uint64_t estimatedSize = sizeof(SliceHead) + (uint64_t)indexCount * indexWidth 
                        + (uint64_t)kvCount * sizeof(uint32_t) * 4;
if (UNLIKELY(estimatedSize > mBuffer->Capacity())) {
    LOG_ERROR("SliceHead declares size exceeds buffer capacity");
    return;
}
```

---

### [VULN-SEC-SNAPSHOT-002] Buffer Overflow — SnapshotRestoreUtils::ReadSnapshotMetaTail

**严重性**: High | **CWE**: CWE-120 | **置信度**: 75/100 | **状态**: LIKELY

#### 漏洞位置
`src/core/snapshot/snapshot_restore_utils.cpp:156-207`

#### 深度分析

**漏洞根源**: checkpoint meta 文件尾部的 `numberOfSnapshotOperators` 字段用于循环迭代，缺少上限验证。

**源代码验证** (lines 156-207):

```cpp
SnapshotMetaTailRef SnapshotRestoreUtils::ReadSnapshotMetaTail(const PathRef &snapshotMetaPath,
                                                               const FileInputViewRef &snapshotMetaInputView)
{
    // 仅验证文件大小 >= 64 bytes
    if (restoredMetaSize < NO_64) {
        LOG_ERROR("Read restore meta tail fail, meta size:" << restoredMetaSize);
        return nullptr;
    }
    
    // ...
    // numberOfSnapshotOperators 直接从文件读取
    uint32_t numberOfSnapshotOperators;
    RETURN_NULLPTR_AS_READ_ERROR(snapshotMetaInputView->Read(numberOfSnapshotOperators));
    
    // 关键漏洞点: numberOfSnapshotOperators 用于后续循环和 Deserialize 调用
    // 但在此处无验证，传递给 ReadSnapshotOperatorInfo
    return std::make_shared<SnapshotMetaTail>(snapshotVersion, snapshotId, startKeyGroup, endKeyGroup, seqId,
                                              snapshotOperatorInfoOffset, numberOfSnapshotOperators,
                                              localFileMappingOffset, remoteFileMappingOffset, stateIdOffset);
}
```

**攻击路径**:
1. checkpoint meta 文件来自 HDFS/本地存储
2. 攻击者修改 `numberOfSnapshotOperators` 为极大值 (如 0xFFFFFFFF)
3. `ReadSnapshotOperatorInfo` 函数中的 for 循环将迭代该次数:
```cpp
for (uint32_t i = 0; i < numberOfSnapshotOperators; i++) {
    SnapshotOperatorType operatorType;
    inputView->Read(operatorType);
    // ...
    SnapshotOperatorInfoRef snapshotOperatorInfo = Deserialize(inputView, operatorType);
    // ...
}
```
4. 每次迭代调用 `Deserialize`，可能导致:
   - 内存耗尽 (大量 SnapshotOperatorInfo 对象创建)
   - 文件读取超出边界
   - DoS 攻击

**修复建议**:
```cpp
const uint32_t MAX_SNAPSHOT_OPERATORS = 1000;  // 合理上限，实际 Flink 任务很少超过几十个

uint32_t numberOfSnapshotOperators;
RETURN_NULLPTR_AS_READ_ERROR(snapshotMetaInputView->Read(numberOfSnapshotOperators));

if (UNLIKELY(numberOfSnapshotOperators > MAX_SNAPSHOT_OPERATORS)) {
    LOG_ERROR("Invalid numberOfSnapshotOperators: " << numberOfSnapshotOperators 
              << ", max allowed: " << MAX_SNAPSHOT_OPERATORS);
    return nullptr;
}
```

---

### [VULN-SEC-LSM-001] Integer Overflow — IndexReader::GetBlockAt

**严重性**: High | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY

#### 漏洞位置
`src/core/lsm_store/block/index_reader.cpp:75-86`

#### 深度分析

**漏洞根源**: SST 文件索引块中的 block offset 和 size 通过变长编码读取，解码后的值用于 Seek 和 buffer 分配，缺少与文件大小的比对验证。

**源代码验证** (lines 75-86):

```cpp
// IndexReader::GetBlockAt 核心逻辑
uint64_t blockOffsetDecode = VarEncodingUtil::DecodeUnsignedInt(buffer, handleOffset);
uint64_t blockSizeDecode = VarEncodingUtil::DecodeUnsignedInt(buffer, 
    handleOffset + static_cast<uint32_t>(blockOffsetDecode >> NO_32));

// 解码值直接用于 BlockHandle，无文件大小验证
blockHandle.Fill(VarEncodingUtil::GetDecodedValue(blockOffsetDecode), 
                 VarEncodingUtil::GetDecodedValue(blockSizeDecode));
```

**攻击路径**:
1. SST 文件索引块来自 checkpoint
2. 攻击者修改索引块的变长编码数据
3. 解码后的 `blockOffset` 超出文件范围
4. `FileReader::ReadBlock` 在 Seek 时读取无效位置:
   - 可能读取文件外的内存
   - 可能触发 SIGBUS/SIGSEGV
5. `blockSize` 为极大值时，导致内存分配异常

**修复建议**:
```cpp
uint64_t blockOffset = VarEncodingUtil::GetDecodedValue(blockOffsetDecode);
uint64_t blockSize = VarEncodingUtil::GetDecodedValue(blockSizeDecode);

// 验证 offset 和 size 与文件大小的关系
uint64_t fileSize = mFileReader->GetFileSize();
if (UNLIKELY(blockOffset >= fileSize || blockOffset + blockSize > fileSize)) {
    LOG_ERROR("Invalid blockHandle: offset=" << blockOffset << ", size=" << blockSize 
              << ", fileSize=" << fileSize);
    return BSS_INVALID_PARAM;
}

const uint64_t MAX_BLOCK_SIZE = 64 * 1024 * 1024;
if (UNLIKELY(blockSize > MAX_BLOCK_SIZE)) {
    LOG_ERROR("Block size exceeds limit: " << blockSize);
    return BSS_INVALID_PARAM;
}
```

---

## 4. Critical 漏洞 (2)

### [VULN-SEC-SLICE-001] memory_corruption - SliceTableRestoreOperation::LoadSlicesIntoLogicalSliceChain

**严重性**: Critical | **CWE**: CWE-119 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/core/snapshot/slice_table_restore_operation.cpp:214-255` @ `SliceTableRestoreOperation::LoadSlicesIntoLogicalSliceChain`
**模块**: slice_table
**跨模块**: slice_table → snapshot

**描述**: SliceTableRestoreOperation::LoadSlicesIntoLogicalSliceChain reads sliceAddress->GetDataLen() from checkpoint and uses it to allocate ByteBuffer and read file data. If DataLen is tampered to a large value, it could cause excessive memory allocation. Additionally, sliceAddress->GetStartOffset() is used without validation for Seek position.

**漏洞代码** (`src/core/snapshot/slice_table_restore_operation.cpp:214-255`)

```c
auto buffer = MakeRef<ByteBuffer>(sliceAddress->GetDataLen(), ...); ... auto ret = inputView->ReadByteBuffer(0, buffer, sliceAddress->GetStartOffset(), sliceAddress->GetDataLen());
```

**达成路径**

Checkpoint -> SliceAddress (from checkpoint) -> GetDataLen/GetStartOffset -> ByteBuffer allocation -> file read

**验证说明**: GetDataLen/GetStartOffset from SliceAddress checkpoint used for ByteBuffer allocation and file Seek without validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-SNAPSHOT-001] integer_overflow - FileReaderBase::ReadBlock

**严重性**: Critical | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor, dataflow-scanner

**位置**: `src/core/lsm_store/file/file_reader.cpp:141-182` @ `FileReaderBase::ReadBlock`
**模块**: snapshot
**跨模块**: snapshot → lsm_store → compress

**描述**: FileReader::ReadBlock reads originLength directly from block header without validation. This value is then used for memory allocation (FileMemAllocator::Alloc). If originLength is tampered to an extremely large value in the checkpoint file, integer overflow during size calculation could lead to heap overflow or allocation failure.

**漏洞代码** (`src/core/lsm_store/file/file_reader.cpp:141-182`)

```c
uint32_t originLength = *reinterpret_cast<uint32_t *>(byteBuffer->Data() + NO_1); ... auto addrOrigin = FileMemAllocator::Alloc(mMemManager, mHolder, originLength, __FUNCTION__);
```

**达成路径**

SST file -> FileInputView::ReadByteBuffer -> byteBuffer -> originLength (from header) -> FileMemAllocator::Alloc -> Decompress

**验证说明**: originLength read from file header without proper validation, used for memory allocation. CRC check exists but doesn't validate length bounds.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

## 5. High 漏洞 (9)

### [VULN-DF-001] buffer_overflow - Slice::RestoreSliceUseByteBuffer

**严重性**: High | **CWE**: CWE-120 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/slice_table/slice/slice.cpp:615-668` @ `Slice::RestoreSliceUseByteBuffer`
**模块**: slice_table

**描述**: RestoreSliceUseByteBuffer reads header fields (keyCount, indexCount, sortedKeyCount) directly from ByteBuffer without bounds validation. These fields come from checkpoint files which may be corrupted or tampered. The keyCount and indexCount are used to calculate offsets and sizes without upper bound checks, potentially leading to buffer overflow or out-of-bounds memory access.

**漏洞代码** (`src/core/slice_table/slice/slice.cpp:615-668`)

```c
mHeader = reinterpret_cast<SliceHead *>(data);
uint32_t kvCount = mHeader->keyCount;
uint32_t indexCount = mHeader->indexCount;
// No validation of kvCount or indexCount bounds
bufferSize += indexCount * indexWidth;
bufferSize += kvCount * sizeof(uint32_t);
```

**达成路径**

[SOURCE] ByteBuffer from checkpoint file (RestoreSliceUseByteBuffer:615)
[PROPAGATION] mHeader->keyCount, mHeader->indexCount read from buffer:623-626
[SINK] bufferSize calculation with unvalidated counts:633-646
[POTENTIAL] IndexSpace, HashCodeSpace allocations with kvCount

**验证说明**: keyCount/indexCount from SliceHead used for bufferSize calculations without upper bound validation. Integer overflow possible in multiplication.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-JNI-001] integer_overflow - Slice::RestoreSliceUseByteBuffer

**严重性**: High | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/core/slice_table/slice/slice.cpp:615-669` @ `Slice::RestoreSliceUseByteBuffer`
**模块**: jni
**跨模块**: jni → snapshot → slice_table

**描述**: Slice::RestoreSliceUseByteBuffer reads keyCount and indexCount from untrusted checkpoint file without upper bound validation. These values are used to calculate buffer sizes (bufferSize += indexCount * indexWidth). If indexCount is tampered to a large value, integer overflow may occur leading to insufficient buffer allocation.

**漏洞代码** (`src/core/slice_table/slice/slice.cpp:615-669`)

```c
uint32_t kvCount = mHeader->keyCount; uint32_t indexCount = mHeader->indexCount; ... bufferSize += indexCount * indexWidth;
```

**达成路径**

Checkpoint file -> FileInputView::ReadByteBuffer -> ByteBuffer -> Slice::RestoreSliceUseByteBuffer -> mHeader->keyCount/indexCount -> bufferSize calculation

**验证说明**: Same as VULN-DF-001 - keyCount/indexCount from checkpoint without validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-SNAPSHOT-002] buffer_overflow - SnapshotRestoreUtils::ReadSnapshotMetaTail

**严重性**: High | **CWE**: CWE-120 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/core/snapshot/snapshot_restore_utils.cpp:156-207` @ `SnapshotRestoreUtils::ReadSnapshotMetaTail`
**模块**: snapshot

**描述**: SnapshotRestoreUtils::ReadSnapshotMetaTail reads multiple fields from checkpoint meta file after seeking to tailOffset. While it validates restoredMetaSize >= 64 bytes, the subsequent reads do not validate that each field value (snapshotVersion, numberOfSnapshotOperators) is within reasonable bounds. numberOfSnapshotOperators is used to iterate without upper bound check.

**漏洞代码** (`src/core/snapshot/snapshot_restore_utils.cpp:156-207`)

```c
uint32_t numberOfSnapshotOperators; RETURN_NULLPTR_AS_READ_ERROR(snapshotMetaInputView->Read(numberOfSnapshotOperators)); ... for (uint32_t i = 0; i < numberOfSnapshotOperators; i++)
```

**达成路径**

Checkpoint meta file -> FileInputView -> ReadSnapshotMetaTail -> numberOfSnapshotOperators -> iteration

**验证说明**: numberOfSnapshotOperators read from file without upper bound check, used in for loop iteration.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-LSM-001] integer_overflow - IndexReader::GetBlockAt

**严重性**: High | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/core/lsm_store/block/index_reader.cpp:75-86` @ `IndexReader::GetBlockAt`
**模块**: lsm_store

**描述**: IndexReader::GetBlockAt uses VarEncodingUtil::DecodeUnsignedInt to read block offset and size from buffer. These decoded values come directly from SST file index blocks without validation. If tampered, they could cause Seek to invalid file positions or allocate incorrect buffer sizes.

**漏洞代码** (`src/core/lsm_store/block/index_reader.cpp:75-86`)

```c
uint64_t blockOffsetDecode = VarEncodingUtil::DecodeUnsignedInt(buffer, handleOffset); uint64_t blockSizeDecode = VarEncodingUtil::DecodeUnsignedInt(buffer, ...);
```

**达成路径**

SST index block -> ByteBuffer -> VarEncodingUtil::DecodeUnsignedInt -> blockHandle offset/size

**验证说明**: blockOffset/blockSize decoded from SST index block without validation against file size.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-SLICE-002] buffer_overflow - SliceHeadSpace::Init

**严重性**: High | **CWE**: CWE-120 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/core/binary/slice_binary.h:303-337` @ `SliceHeadSpace::Init`
**模块**: slice_table

**描述**: SliceHeadSpace::Init uses keyCount from header to initialize index arrays. In restore mode (isRestore=true), memset_s is called with buffer->Capacity() - originOffset - bufferOffset as size. If keyCount or indexCount are tampered, the calculated mIndex.TotalSize() may exceed remaining buffer capacity.

**漏洞代码** (`src/core/binary/slice_binary.h:303-337`)

```c
mIndex.Init(data + bufferOffset, buffer->Capacity() - originOffset - bufferOffset, indexCount, indexWidth, isRestore); bufferOffset += mIndex.TotalSize();
```

**达成路径**

Checkpoint file -> ByteBuffer -> SliceHeadSpace::Init -> keyCount/indexCount -> array initialization

**验证说明**: keyCount/indexCount from SliceHead used in SliceHeadSpace::Init for array initialization without validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-011] buffer_overflow - SliceKey::Unpack

**严重性**: High | **CWE**: CWE-120 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/binary/slice_binary.h:39-69` @ `SliceKey::Unpack`
**模块**: binary

**描述**: SliceKey::Unpack reads priKey->mKeyLen directly from buffer (line 54) and uses it to calculate secondary key length and data offsets. The mKeyLen comes from checkpoint/slice file buffer without bounds validation. An attacker could craft a checkpoint with large mKeyLen causing the secondary key offset calculation (line 59-60) to reference out-of-bounds memory.

**漏洞代码** (`src/core/binary/slice_binary.h:39-69`)

```c
mPriKey.KeyLen(priKey->mKeyLen);
mPriKey.KeyData(priKey->mKeyData);
mSecKey.KeyLen(bufferLen - (mPriKey.KeyLen() + sizeof(SlicePriKey)));
mSecKey.KeyData(data + sizeof(SlicePriKey) + mPriKey.KeyLen());
```

**达成路径**

[SOURCE] ByteBuffer from checkpoint/slice file (slice_binary.h:46)
[PROPAGATION] priKey->mKeyLen from buffer:54
[SINK] mSecKey.KeyLen/KeyData offset calculation:59-60

**验证说明**: priKey->mKeyLen from buffer used for secondary key offset calculation without bounds check.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-009] integer_overflow - BlobFileReader::ReadBlock

**严重性**: High | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/blob_store/blob_file_reader.cpp:64-128` @ `BlobFileReader::ReadBlock`
**模块**: blob_store

**描述**: BlobFileReader::ReadBlock reads originLength from block header (line 91) and uses it for buffer allocation (line 113). The originLength comes from blob file which could be from HDFS or local checkpoint storage. Similar to FileReaderBase::ReadBlock, an attacker modifying blob files could inject malicious originLength values causing heap overflow during decompression.

**漏洞代码** (`src/core/blob_store/blob_file_reader.cpp:64-128`)

```c
uint32_t originLength = *reinterpret_cast<uint32_t *>(byteBuffer->Data() + sizeof(CompressAlgo));
// ...
ByteBufferRef originBuffer = CreateBuffer(originLength);
```

**达成路径**

[SOURCE] Blob file block header (blob_file_reader.cpp:91) - originLength read from file
[PROPAGATION] originLength used directly without upper bound validation
[SINK] CreateBuffer(originLength) allocation:113
[SINK] compressor->Decompress with originLength:119

**验证说明**: originLength from blob file header used for CreateBuffer allocation. CRC check exists but not length validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-004] buffer_overflow - LsmKeyValueInfo::Unpack

**严重性**: High | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner, security-auditor

**位置**: `src/core/binary/lsm_binary.h:107-131` @ `LsmKeyValueInfo::Unpack`
**模块**: binary

**描述**: Unpack reads mPriKey->mKeyLen directly from buffer (line 115) and uses it for offset calculations. While there are buffer overflow checks via RETURN_INNER_ERR_AS_BUFFER_OVER_FLOW, the mKeyLen is read from potentially corrupted checkpoint data. An attacker could craft a file with large mKeyLen values to cause out-of-bounds reads or trigger the overflow checks repeatedly.

**漏洞代码** (`src/core/binary/lsm_binary.h:107-131`)

```c
mPriKey = reinterpret_cast<LsmPriKeyNode *>(data);
offset += sizeof(LsmPriKeyNode) + mPriKey->mKeyLen;
```

**达成路径**

[SOURCE] ByteBuffer from SST/checkpoint file (lsm_binary.h:110)
[PROPAGATION] mPriKey->mKeyLen from buffer:115
[SINK] offset += mPriKey->mKeyLen:115
[POTENTIAL] mSecKey->mKeyLen usage in mSgl.Unpack:342

**验证说明**: mKeyLen read from buffer for offset calculation, but RETURN_INNER_ERR_AS_BUFFER_OVER_FLOW provides bounds checking.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-JNI-002] path_traversal - CheckPathValid

**严重性**: High | **CWE**: CWE-22 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor, dataflow-scanner

**位置**: `src/core/jni/kv_helper.h:327-381` @ `CheckPathValid`
**模块**: jni

**描述**: CheckPathValid function in kv_helper.h uses realpath to resolve paths from Java JNI layer but lacks whitelist validation or prefix checking. While it validates path length (PATH_MAX) and readability, it does not prevent path traversal attacks (e.g., '../../../etc/passwd') or symlink-based attacks that could redirect to unintended locations.

**漏洞代码** (`src/core/jni/kv_helper.h:327-381`)

```c
auto realPath = realpath(path.c_str(), nullptr); if (UNLIKELY(std::string(realPath).size() > PATH_MAX)) { ... } if (access(realPath, R_OK) != 0) { ... }
```

**达成路径**

JNI Java layer -> ConstructPath -> CheckPathValid -> realpath -> filesystem access

**验证说明**: realpath resolves path but lacks whitelist/prefix validation. Multiple checks exist (length, readability, null) but path traversal not prevented.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: 0

---

## 6. Medium 漏洞 (9)

### [VULN-SEC-BINARY-002] integer_underflow - SliceKey::Unpack

**严重性**: Medium | **CWE**: CWE-191 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/core/binary/slice_binary.h:39-69` @ `SliceKey::Unpack`
**模块**: binary
**跨模块**: binary → slice_table

**描述**: SliceKey::Unpack calculates secondary key length as bufferLen - (mPriKey.KeyLen() + sizeof(SlicePriKey)). If bufferLen or priKey->mKeyLen are tampered in checkpoint data, this subtraction could result in negative value being interpreted as large unsigned value, causing out-of-bounds memory access.

**漏洞代码** (`src/core/binary/slice_binary.h:39-69`)

```c
mSecKey.KeyLen(bufferLen - (mPriKey.KeyLen() + sizeof(SlicePriKey)));
```

**达成路径**

Checkpoint file -> ByteBuffer -> SliceKey::Unpack -> bufferLen/mPriKey.KeyLen() -> secondary key length

**验证说明**: Integer underflow risk: bufferLen - (mPriKey.KeyLen() + sizeof(SlicePriKey)) could produce negative value interpreted as large unsigned.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-010] buffer_overflow - IndexReader::GetBlockAt

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/lsm_store/block/index_reader.cpp:75-86` @ `IndexReader::GetBlockAt`
**模块**: lsm_store

**描述**: GetBlockAt uses VarEncodingUtil::DecodeUnsignedInt to read block offset and size from index block buffer (lines 79-81). These decoded values (blockOffset, blockSize) come from SST file index blocks. The decoded values are used directly to fill BlockHandle without validation against file size limits. A corrupted index block could provide invalid offsets causing out-of-bounds file reads.

**漏洞代码** (`src/core/lsm_store/block/index_reader.cpp:75-86`)

```c
uint64_t blockOffsetDecode = VarEncodingUtil::DecodeUnsignedInt(buffer, handleOffset);
uint64_t blockSizeDecode = VarEncodingUtil::DecodeUnsignedInt(buffer, handleOffset + static_cast<uint32_t>(blockOffsetDecode >> NO_32));
blockHandle.Fill(VarEncodingUtil::GetDecodedValue(blockOffsetDecode), VarEncodingUtil::GetDecodedValue(blockSizeDecode));
```

**达成路径**

[SOURCE] Index block buffer from SST file (index_reader.cpp:79)
[PROPAGATION] VarEncodingUtil::DecodeUnsignedInt reads offset/size:79-81
[SINK] blockHandle.Fill with decoded values:82-83

**验证说明**: Same as VULN-SEC-LSM-001 - VarEncodingUtil decoded values used without file size validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-005] buffer_overflow - SnapshotRestoreUtils::ReadSnapshotOperatorInfo

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/snapshot/snapshot_restore_utils.cpp:62-83` @ `SnapshotRestoreUtils::ReadSnapshotOperatorInfo`
**模块**: snapshot

**描述**: ReadSnapshotOperatorInfo reads numberOfSnapshotOperators from file metadata (passed as parameter from snapshotMetaTail). While numberOfSnapshotOperators comes from snapshotMetaTail which has validation, the for loop iterates numberOfSnapshotOperators times without upper bound validation visible in this function. Large values could cause excessive memory allocation or iteration.

**漏洞代码** (`src/core/snapshot/snapshot_restore_utils.cpp:62-83`)

```c
for (uint32_t i = 0; i < numberOfSnapshotOperators; i++) {
    SnapshotOperatorType operatorType;
    inputView->Read(operatorType);
    // ...
    SnapshotOperatorInfoRef snapshotOperatorInfo = Deserialize(inputView, operatorType);
```

**达成路径**

[SOURCE] numberOfSnapshotOperators from SnapshotMetaTail (from file:196)
[PROPAGATION] Loop iteration count:68
[SINK] Multiple Deserialize calls per iteration:75

**验证说明**: numberOfSnapshotOperators passed as parameter from ReadSnapshotMetaTail, used in loop without validation.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-JNI-003] type_confusion - Java_com_huawei_ock_bss_common_BoostStateDB_restore

**严重性**: Medium | **CWE**: CWE-843 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/core/jni/com_huawei_ock_bss_common_BoostStateDB.cpp:76-80` @ `Java_com_huawei_ock_bss_common_BoostStateDB_restore`
**模块**: jni

**描述**: BoostStateDB restore JNI function uses reinterpret_cast to convert jlong jDBHandle to BoostStateDB pointer without type verification. If an invalid handle is passed from Java layer, this could lead to use of invalid pointer causing memory corruption or crash.

**漏洞代码** (`src/core/jni/com_huawei_ock_bss_common_BoostStateDB.cpp:76-80`)

```c
auto *boostStateDB = reinterpret_cast<BoostStateDB *>(jDBHandle); if (UNLIKELY(boostStateDB == nullptr)) { LOG_ERROR(...); return JNI_FALSE; }
```

**达成路径**

Java JNI layer -> jlong jDBHandle -> reinterpret_cast<BoostStateDB *> -> BoostStateDB operations

**验证说明**: reinterpret_cast jlong to BoostStateDB* without type verification. Null check exists but arbitrary pointer value accepted.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-007] buffer_overflow - DataBlock::InitIndexReader

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/lsm_store/block/data_block.cpp:16-32` @ `DataBlock::InitIndexReader`
**模块**: lsm_store

**描述**: InitIndexReader reads data block from buffer with minimum size check (NO_10 bytes) but the actual index reader initialization at line 29 uses buffer capacity - NO_10 as the index offset position. The buffer content and structure come from SST files. Malformed SST files with crafted block structure could cause unexpected parsing behavior.

**漏洞代码** (`src/core/lsm_store/block/data_block.cpp:16-32`)

```c
if (UNLIKELY(mBuffer->Capacity() < NO_10)) {...}
auto ret = mBuffer->ReadUint8(blockType, mBuffer->Capacity() - 1);
// ...
ret = reader->Init(mBuffer, mBuffer->Capacity() - NO_10);
```

**达成路径**

[SOURCE] ByteBuffer from SST file block (data_block.cpp:16)
[PROPAGATION] mBuffer->Capacity() from file:18
[SINK] reader->Init with offset from capacity:29

**验证说明**: mBuffer->Capacity() used for index reader initialization. Minimum size check (10 bytes) exists.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-012] buffer_overflow - ByteBuffer::Write/WriteAt

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/slice_table/binary/byte_buffer.h:142-167` @ `ByteBuffer::Write/WriteAt`
**模块**: slice_table

**描述**: ByteBuffer::Write and WriteAt use memcpy_s with positions calculated from mOffset or external pos parameter. While CheckParam validates pos+len <= mCapacity, the pos value could come from checkpoint data. In restore scenarios, positions like keyOffsetBase and valueOffsetBase are read from SliceHead which comes from file buffer. If corrupted offset bases are used, memcpy_s operations could fail or cause issues.

**漏洞代码** (`src/core/slice_table/binary/byte_buffer.h:142-167`)

```c
BResult WriteAt(const uint8_t *buf, uint32_t len, uint32_t pos) noexcept {
    if (UNLIKELY(!CheckParam(buf, len, pos))) { return BSS_INVALID_PARAM; }
    auto ret = memcpy_s(mData + pos, mCapacity - pos, buf, len);
```

**达成路径**

[SOURCE] SliceHead fields from checkpoint (keyOffsetBase, valueOffsetBase)
[PROPAGATION] pos parameter from mHeader->keyOffsetBase/valueOffsetBase
[SINK] memcpy_s with pos from file data:162

**验证说明**: WriteAt uses pos parameter from SliceHead offsets. CheckParam validates pos+len <= mCapacity.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-003] integer_overflow - FileInputView::ReadUTF

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/core/common/io/file_input_view.h:64-88` @ `FileInputView::ReadUTF`
**模块**: io

**描述**: ReadUTF reads utfLen from file (uint64_t at line 67) and allocates buffer based on it. While there is a 128KB limit check (line 73), the allocation uses new uint8_t[utfLen] which could still allocate up to 128KB based on untrusted file data. The limit is good but 128KB allocation from corrupted checkpoint could still cause memory exhaustion in repeated calls.

**漏洞代码** (`src/core/common/io/file_input_view.h:64-88`)

```c
uint64_t utfLen = 0;
if (UNLIKELY(Read(utfLen) != BSS_OK)) {...}
if (UNLIKELY(utfLen > IO_SIZE_128K)) {...}
auto *tempBuf = new (std::nothrow)uint8_t[utfLen];
```

**达成路径**

[SOURCE] FileInputView::Read(utfLen) - reads length from file:68
[SANITIZATION] Upper bound check utfLen > IO_SIZE_128K:73 - partial mitigation
[SINK] new uint8_t[utfLen] allocation:78

**验证说明**: utfLen read from file with 128KB upper bound limit. Allocation uses nothrow but size limited.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-IO-001] integer_overflow - FileInputView::ReadByteBuffer

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/core/common/io/file_input_view.h:108-117` @ `FileInputView::ReadByteBuffer`
**模块**: io
**跨模块**: io → snapshot → lsm_store

**描述**: FileInputView::ReadByteBuffer validates position and length against buffer capacity, but the offset and length parameters originate from checkpoint metadata. If offset/length are tampered to cause integer overflow in position+offset calculation, the validation check position >= buffer->Capacity() || length > buffer->Capacity() - position could be bypassed.

**漏洞代码** (`src/core/common/io/file_input_view.h:108-117`)

```c
if (UNLIKELY(position >= buffer->Capacity() || length > buffer->Capacity() - position)) { ... } return fileSystem->Read(buffer->Data() + position, length, offset);
```

**达成路径**

Checkpoint metadata -> offset/length -> FileInputView::ReadByteBuffer -> validation -> file read

**验证说明**: position/length validation exists but integer overflow in position+offset could bypass check. Check: position >= capacity || length > capacity-position

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-008] integer_overflow - Lz4Interface::Decompress

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner, security-auditor

**位置**: `src/core/compress/lz4_interface.cpp:39-57` @ `Lz4Interface::Decompress`
**模块**: compress
**跨模块**: compress → lsm_store

**描述**: Decompress uses dstCapacity and srcSize parameters which ultimately come from file headers in the SST/checkpoint context. While there are bounds checks against INT32_MAX, the decompression operation uses these sizes directly. If the sizes are crafted based on compressed data that doesn't match the declared sizes, LZ4_decompress_safe will return error but the allocation already happened.

**漏洞代码** (`src/core/compress/lz4_interface.cpp:39-57`)

```c
if (UNLIKELY(src == nullptr || srcSize == 0 || srcSize > INT32_MAX)) {...}
if (UNLIKELY(dst == nullptr || dstCapacity == 0 || dstCapacity > INT32_MAX)) {...}
int result = LZ4_decompress_safe((const char *)src, (char *)dst, (int)srcSize, (int)dstCapacity);
```

**达成路径**

[SOURCE] File headers (originLength from file_reader.cpp:169)
[PROPAGATION] dstCapacity from originLength via FileMemAllocator::Alloc
[SINK] LZ4_decompress_safe with sizes from file:50

**验证说明**: dstCapacity/srcSize from file headers with INT32_MAX validation. LZ4_decompress_safe handles mismatch gracefully.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

## 7. Low 漏洞 (1)

### [VULN-DF-013] integer_overflow - Java_com_huawei_ock_bss_common_BoostStateDB_restore

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/core/jni/com_huawei_ock_bss_common_BoostStateDB.cpp:84-105` @ `Java_com_huawei_ock_bss_common_BoostStateDB_restore`
**模块**: jni

**描述**: The restore JNI function reads metaSize and size from Java List objects and compares against NO_1000000. While this provides a maximum limit, the loop iterations use jint which is 32-bit signed integer. The comparison metaSize > NO_1000000 prevents integer overflow attacks, but the loop could still iterate up to 1 million times causing potential performance issues.

**漏洞代码** (`src/core/jni/com_huawei_ock_bss_common_BoostStateDB.cpp:84-105`)

```c
jint metaSize = env->CallIntMethod(jRestorePaths, sizeMid);
if (UNLIKELY(metaSize > static_cast<jint>(NO_1000000))) {...}
for (jint i = 0; i < metaSize; i++) {...
```

**达成路径**

[SOURCE] Java List.size() via JNI:84,101
[SANITIZATION] Upper bound check against NO_1000000:85,102
[POTENTIAL] Loop iteration with metaSize:90

**验证说明**: metaSize from Java List with 1000000 upper bound. Loop iteration limited but could cause performance issues.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

## 8. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| binary | 0 | 2 | 1 | 0 | 3 |
| blob_store | 0 | 1 | 0 | 0 | 1 |
| compress | 0 | 0 | 1 | 0 | 1 |
| io | 0 | 0 | 2 | 0 | 2 |
| jni | 0 | 2 | 1 | 1 | 4 |
| lsm_store | 0 | 1 | 2 | 0 | 3 |
| slice_table | 1 | 2 | 1 | 0 | 4 |
| snapshot | 1 | 1 | 1 | 0 | 3 |
| **合计** | **2** | **9** | **9** | **1** | **21** |

## 9. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-120 | 9 | 42.9% |
| CWE-190 | 8 | 38.1% |
| CWE-843 | 1 | 4.8% |
| CWE-22 | 1 | 4.8% |
| CWE-191 | 1 | 4.8% |
| CWE-119 | 1 | 4.8% |

---

## 10. 修复建议总结

### 10.1 核心修复原则

所有从 checkpoint 文件读取的数值字段（长度、偏移、计数器）必须经过以下三层验证：

1. **范围验证**: 检查是否在合理范围内（如 0 < value < MAX_LIMIT）
2. **一致性验证**: 检查与已知约束的关系（如 offset + length <= fileSize）
3. **溢出验证**: 使用 64 位中间变量计算，避免整数溢出/下溢

### 10.2 优先修复项 (P0)

| 漏洞 ID | 修复要点 | 预估工作量 |
|---------|---------|-----------|
| VULN-SEC-SLICE-001 | SliceAddress 字段验证 + 文件边界检查 | 2 天 |
| VULN-SEC-SNAPSHOT-001 | originLength 上限 + 压缩比合理性检查 | 2 天 |

### 10.3 高优先级修复项 (P1)

| 漏洞 ID | 修复要点 |
|---------|---------|
| VULN-DF-001, VULN-SEC-JNI-001 | SliceHead 字段上限 + bufferSize 溢出检查 |
| VULN-SEC-SNAPSHOT-002 | numberOfSnapshotOperators 上限验证 |
| VULN-SEC-LSM-001 | blockHandle 与 fileSize 关系验证 |

### 10.4 通用防御措施

1. **Checkpoint 文件签名**: 对 checkpoint 文件添加 HMAC 或数字签名，验证完整性
2. **魔法数字校验**: 在文件头部添加固定魔法数字，快速识别篡改
3. **内存分配上限**: 配置全局内存分配上限，防止恶意文件导致 OOM
4. **白名单路径**: JNI 路径验证使用白名单前缀，而非 realpath

### 10.5 测试建议

1. **模糊测试**: 对 checkpoint 恢复流程实施 fuzz testing，验证边界条件处理
2. **恶意文件测试**: 构造包含极端值的 checkpoint 文件，验证系统稳定性
3. **回归测试**: 修复后确保现有正常 checkpoint 恢复流程不受影响

---

## 附录

### A. 扫描配置

- **扫描工具**: OpenCode Multi-Agent Vulnerability Scanner
- **扫描模式**: DataFlow Scanner + Security Auditor
- **置信度阈值**: 40 (LIKELY ≥ 60, POSSIBLE 40-60)
- **语言支持**: C/C++
- **LSP 支持**: 是

### B. 参考文档

- CWE-120: Buffer Copy without Checking Size of Input
- CWE-190: Integer Overflow or Wraparound
- CWE-191: Integer Underflow
- CWE-22: Path Traversal
- CWE-843: Type Confusion
- CWE-119: Improper Restriction of Operations within Bounds of Memory Buffer

### C. 联系方式

如有疑问或需要进一步分析，请联系安全扫描团队。