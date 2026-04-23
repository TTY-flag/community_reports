# 漏洞扫描报告 — 已确认漏洞

**项目**: OmniStateStore
**扫描时间**: 2026-04-22T15:30:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

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
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞


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
| `LocalFileSystem::Read@src/core/common/fs/local/local_file_system.h` | file | untrusted_local | Reads data from local file using pread/read syscalls. Files may be checkpoint data. | Reads from local file |
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

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
