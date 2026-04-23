# OmniStateStore Threat Analysis Report

**Project**: OmniStateStore - Huawei Flink State Storage Engine  
**Scan Date**: 2026-04-22  
**Total Files**: 380 (C/C++ source files)  
**Total Lines**: 57,205  
**Language**: C++ (core) + Java (plugin layer)

---

## 1. Executive Summary

OmniStateStore is a high-performance state storage engine for Apache Flink streaming applications. It uses a hybrid architecture with a C++ native engine accessed via JNI from Java Flink TaskManagers. The system stores state data locally and supports checkpointing to HDFS/S3.

**Key Attack Surfaces Identified**:
- **25+ JNI Entry Points** - Primary attack surface receiving data from Java Flink operators
- **Checkpoint Restore Pipeline** - Parses binary data from potentially untrusted checkpoint files
- **HDFS I/O Layer** - Receives data from remote Hadoop clusters via JNI bridge
- **Binary Parsing Layer** - LSM blocks, slices, keys parsed from file buffers
- **Memory Management** - Complex allocator/pool system with potential injection points

**Overall Risk Assessment**: **HIGH**  
The system has multiple critical attack vectors where untrusted data from checkpoint files, HDFS storage, or JNI interfaces flows into binary parsing functions without comprehensive validation.

---

## 2. Attack Surface Analysis

### 2.1 JNI Interface Layer (Critical Risk)

**Location**: `src/core/jni/`

| Entry Point | Risk | Data Source | Attack Vector |
|-------------|------|-------------|---------------|
| `Java_com_huawei_ock_bss_common_BoostStateDB_open` | Critical | Java BoostConfig | Config injection - paths, sizes, flags |
| `Java_com_huawei_ock_bss_common_BoostStateDB_restore` | Critical | Java restorePaths | Path traversal via checkpoint locations |
| `Java_com_huawei_ock_bss_table_KVTableImpl_put` | High | Java key/value | Data injection into state tables |
| `Java_com_huawei_ock_bss_table_iterator_PQKeyIterator_open` | Critical | Java groupId array | Memory allocation with untrusted size |

**Key Findings**:
- `CheckPathValid()` in `kv_helper.h:327` validates paths but uses `realpath()` which may resolve symlinks to unexpected locations
- `GetStringFromJava()` reads strings from Java without length limits (except hardcoded checks)
- `CreateConfig()` trusts Java-provided parallelism values, key group ranges
- `PQKeyIterator::open()` allocates memory with size from `env->GetArrayLength()` - potential integer overflow

### 2.2 Checkpoint Restore Pipeline (Critical Risk)

**Location**: `src/core/snapshot/`

| Entry Point | Risk | Data Source | Attack Vector |
|-------------|------|-------------|---------------|
| `SnapshotRestoreUtils::ReadDbMeta` | Critical | Checkpoint meta file | Metadata parsing - version, snapshotId, operator info |
| `SnapshotRestoreUtils::Deserialize` | Critical | Checkpoint file | Binary deserialization of operator info |
| `Slice::RestoreSliceUseByteBuffer` | Critical | Checkpoint slice file | Slice structure parsing - header, index, offsets |
| `LogicalSliceChainImpl::Restore` | High | Checkpoint file | Chain restoration with slice addresses |

**Key Findings**:
- `FileInputView::ReadUTF()` reads length from file (limited to 128KB) but still allows large allocations
- No magic number validation in snapshot meta parsing (only footer has magic check)
- `Slice::RestoreSliceUseByteBuffer()` reads multiple length/count fields without upper bounds
- CRC validation only in `FileReader::ReadBlock()` - snapshot files lack CRC

### 2.3 LSM Store Block Parsing (High Risk)

**Location**: `src/core/lsm_store/block/`

| Entry Point | Risk | Data Source | Attack Vector |
|-------------|------|-------------|---------------|
| `FileReader::ReadBlock` | High | SST file | Block reading + LZ4 decompression |
| `DataBlock::InitIndexReader` | High | Block buffer | Header parsing - offset, size, count |
| `IndexReader::GetBlockIndex` | High | Index buffer | Variable-length encoding decode |
| `FullKeyUtil::ReadInternalKey` | High | File buffer | Key structure parsing |

**Key Findings**:
- `Lz4Interface::Decompress()` uses `srcSize` and `dstCapacity` from file headers
- `VarEncodingUtil::DecodeUnsignedInt()` reads variable-length integers without strict bounds
- Block parsing uses `reinterpret_cast` for struct overlaying (alignment issues)
- `DataBlock::InitIndexReader()` reads count/offset from buffer tail without validation

### 2.4 Binary Parsing Utilities (High Risk)

**Location**: `src/core/binary/`

| Function | Risk | Input Source | Vulnerability Type |
|----------|------|--------------|-------------------|
| `LsmKeyValueInfo::Unpack` | High | Buffer | Length field parsing, key/value read |
| `SliceKey::Unpack` | High | Buffer | Key length from buffer |
| `BinaryReader::ReadBytes` | Medium | Buffer | Raw byte reading (limited to 8 bytes) |

**Key Findings**:
- `Unpack` functions read length fields and use `ByteBuffer::Read()` without validation
- Multiple `ByteBuffer::memcpy_s` operations with lengths from buffer data
- Buffer overflow checks use macros but may miss edge cases in offset calculations

### 2.5 File System Layer (High Risk)

**Location**: `src/core/common/fs/`

| Component | Risk | Data Source | Attack Vector |
|-----------|------|-------------|---------------|
| `HadoopFileSystem::Read` | High | HDFS remote | Network data via JNI |
| `HadoopFileSystem::Download` | High | HDFS remote | File download to local path |
| `LocalFileSystem::Read` | Medium | Local disk | File content read |
| `FileInputView::ReadByteBuffer` | High | File system | Buffer read with position/length |

**Key Findings**:
- `HadoopFileSystem::Read()` receives data from Java Hadoop client - potentially malicious HDFS cluster
- `Download()` writes to local path from JNI - path handling from Java
- No content validation on downloaded files

### 2.6 Memory Management (Medium-High Risk)

**Location**: `src/core/memory/`

| Component | Risk | Issue |
|-----------|------|-------|
| `SegmentHeads metadata hack` | Critical | Metadata written BEFORE returned pointer - potential underrun |
| `DirectAllocator::Allocate` | High | malloc with size from caller - no validation |
| `ByteBuffer dual-free paths` | High | `mMemManagerFree` and `mDataFree` flags - potential double-free |
| `FreshTable::NewActiveSegment` | Medium | Bypasses MemManager limits |

**Key Findings**:
- Memory metadata pattern: `SegmentHeads` struct at `address - sizeof(SegmentHeads)` creates buffer underrun risk
- JNI memory allocation: `PQKeyIterator::open()` and `DirectBuffer` allocate with sizes from Java
- ByteBuffer destruction has dual free paths that could lead to double-free if flags set incorrectly

---

## 3. Data Flow Analysis

### Critical Data Flow: JNI -> Checkpoint Restore

```
Java restorePaths (JNI)
  └── Java_com_huawei_ock_bss_common_BoostStateDB_restore()
      └── CheckPathValid() - realpath(), access(), lstat()
      └── BoostStateDB::Restore()
          └── SnapshotRestoreUtils::ReadDbMeta()
              └── FileInputView::Init() - opens checkpoint file
              └── ReadSnapshotMetaTail() - reads version, snapshotId
              └── ReadSnapshotOperatorInfo() - binary parsing
              └── SliceTableRestoreOperation::Restore()
                  └── Slice::RestoreSliceUseByteBuffer()
                      └── ByteBuffer::ReadUint32/64 - reads lengths
                      └── SliceKey::Unpack() - parses key data
```

**Risk Points**:
1. Path validation uses `realpath()` - may resolve symlinks to attacker-controlled paths
2. Length fields read from file without comprehensive bounds checking
3. No magic number validation in early parsing stages

### Critical Data Flow: SST File -> Block Parsing

```
SST file on disk/HDFS
  └── FileReader::ReadBlock()
      └── FileInputView::ReadByteBuffer() - reads compressed data
      └── CheckCRC() - validates CRC (1024 magic)
      └── Lz4Interface::Decompress() - srcSize/dstCapacity from file
      └── DataBlock::InitIndexReader()
          └── ByteBuffer::ReadUint32() - reads offset, count
      └── DataBlock::GetKey()
          └── FullKeyUtil::ReadInternalKey()
              └── VarEncodingUtil::DecodeUnsignedInt() - variable-length
```

**Risk Points**:
1. LZ4 decompression size parameters from file - could cause buffer overflow
2. Variable-length encoding reads without bounds
3. Count/offset from buffer tail - may overflow capacity

---

## 4. STRIDE Threat Modeling

### Spoofing
- **Risk**: Medium
- **Vectors**: 
  - HDFS cluster impersonation - attacker controls remote storage
  - Checkpoint file tampering - modify checkpoint files on shared storage
- **Mitigation Needed**: Signature verification for checkpoint files

### Tampering
- **Risk**: High
- **Vectors**:
  - Checkpoint metadata tampering - inject malicious operator info
  - SST file block tampering - modify compressed blocks
  - Config injection via JNI - malicious BoostConfig from Java
- **Mitigation Needed**: Cryptographic integrity checks for all checkpoint files

### Repudiation
- **Risk**: Low
- **Vectors**: Operations not logged sufficiently
- **Mitigation**: Add audit logging for restore operations

### Information Disclosure
- **Risk**: Medium
- **Vectors**:
  - Path leakage via logging (`PathTransform::ExtractFileName`)
  - State data exposure through iterator APIs
- **Mitigation**: Review logging for sensitive data exposure

### Denial of Service
- **Risk**: High
- **Vectors**:
  - Memory exhaustion - large allocations from file lengths
  - LZ4 decompression bomb - crafted compressed data
  - Infinite loops in variable-length decoding
- **Mitigation**: Strict size limits on all parsed fields

### Elevation of Privilege
- **Risk**: Critical
- **Vectors**:
  - Path traversal via checkpoint restore - escape from allowed directories
  - Memory corruption - buffer overflow leading to code execution
  - JNI boundary exploitation - Java native bridge vulnerabilities
- **Mitigation**: Comprehensive input validation, sandboxing

---

## 5. High-Risk Vulnerability Candidates

### 5.1 Path Traversal in Checkpoint Restore
**Severity**: Critical  
**Location**: `kv_helper.h:327`, `com_huawei_ock_bss_common_BoostStateDB.cpp:64`  
**Description**: `CheckPathValid()` uses `realpath()` which resolves symlinks. An attacker controlling checkpoint storage could create symlinks pointing to sensitive files outside intended directories.  
**Attack Scenario**: Malicious HDFS/S3 admin creates checkpoint symlink → restore reads unintended file.

### 5.2 Unchecked Length Fields in Binary Parsing
**Severity**: Critical  
**Location**: `slice.cpp:615`, `lsm_binary.h:107`, `snapshot_restore_utils.cpp`  
**Description**: Multiple `ReadUint32`, `ReadUint64` calls read length/count fields from checkpoint buffers without upper bounds validation.  
**Attack Scenario**: Malicious checkpoint with large length field → buffer overflow in `memcpy_s`.

### 5.3 LZ4 Decompression with File Parameters
**Severity**: High  
**Location**: `lz4_interface.cpp:39`, `file_reader.cpp:184`  
**Description**: `LZ4_decompress_safe()` is called with `srcSize` and `dstCapacity` from file headers. Malicious SST file could specify incorrect sizes.  
**Attack Scenario**: Crafted SST with mismatched sizes → decompression failure or memory corruption.

### 5.4 Variable-Length Integer Decoding
**Severity**: High  
**Location**: `var_encoding_util.h:71`, `full_key_util.cpp:91`  
**Description**: `DecodeUnsignedInt()` reads bytes from buffer until continuation bit cleared - no explicit bounds.  
**Attack Scenario**: Malicious buffer with infinite continuation bytes → infinite loop or integer overflow.

### 5.5 JNI Memory Allocation with Java Size
**Severity**: Critical  
**Location**: `PQKeyIterator.cpp:34`, `DirectBuffer.cpp:70`  
**Description**: `malloc(len)` where `len = env->GetArrayLength()` - untrusted size from Java environment.  
**Attack Scenario**: Java provides huge array length → integer overflow or excessive allocation.

### 5.6 SegmentHeads Buffer Underrun
**Severity**: High  
**Location**: `mem_manager.cpp:129-133`  
**Description**: Memory metadata written BEFORE returned pointer at `address - sizeof(SegmentHeads)`.  
**Attack Scenario**: Caller writes to negative offset → metadata corruption, allocator crash.

---

## 6. Recommendations

### Critical (Immediate Action Required)
1. **Add magic number validation** to all checkpoint/snapshot file parsing before processing
2. **Add upper bounds validation** for all length/count fields read from binary files (limit to reasonable max sizes)
3. **Add integrity verification** (HMAC/signature) for checkpoint files to prevent tampering
4. **Validate JNI array lengths** before malloc - reject values exceeding MAX_PARALLELISM or reasonable limits

### High (Near-Term Action)
1. **Audit realpath() usage** - consider canonical path validation without symlink resolution
2. **Add explicit bounds** to `VarEncodingUtil::DecodeUnsignedInt()` - limit iterations
3. **Validate LZ4 sizes** - verify compressed size matches block header before decompression
4. **Review SegmentHeads pattern** - move metadata after pointer or add guard pages

### Medium (Long-Term Improvements)
1. Add comprehensive logging for all restore operations
2. Implement rate limiting on JNI operations
3. Add fuzz testing for checkpoint file parsing
4. Consider sandboxing file system operations

---

## 7. Attack Surfaces Summary

| Category | Entry Points | Risk Level | Priority |
|----------|--------------|------------|----------|
| JNI Interface | 25+ | Critical | 1 |
| Checkpoint Restore | 15+ | Critical | 1 |
| LSM Block Parsing | 10+ | High | 2 |
| Binary Parsing | 8+ | High | 2 |
| File System I/O | 6+ | High | 2 |
| Memory Management | 5+ | Medium | 3 |

---

## 8. Next Steps

1. **Scanner Agents**: Run dataflow scanner and security auditor on identified high-risk files
2. **Verification**: Validate each vulnerability candidate with confidence scoring
3. **Detailed Analysis**: For confirmed vulnerabilities, generate exploitation details
4. **Report**: Produce final vulnerability report with remediation guidance

---

**Generated by**: Architecture Analysis Agent  
**Confidence**: High (based on comprehensive code exploration)