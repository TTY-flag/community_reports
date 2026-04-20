# 漏洞扫描报告 — 待确认漏洞

**项目**: Unknown Project
**扫描时间**: 2026-04-20T07:33:14.934Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 15 | 41.7% |
| LIKELY | 14 | 38.9% |
| FALSE_POSITIVE | 7 | 19.4% |
| **总计** | **36** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 14 | 50.0% |
| Medium | 14 | 50.0% |
| **有效漏洞总计** | **28** | - |
| 误报 (FALSE_POSITIVE) | 7 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-RESTORE-001]** path_traversal (High) - `src/core/snapshot/restore_operator.cpp:142` @ `CreateHardLinkForRestoredLocalFile` | 置信度: 75
2. **[VULN-DF-SNAPSHOT-001]** path_traversal (High) - `src/core/snapshot/restore_operator.cpp:143` @ `CreateHardLinkForRestoredLocalFile` | 置信度: 75
3. **[VULN-DF-SNAPSHOT-002]** path_traversal (High) - `src/core/snapshot/snapshot_restore_utils.cpp:108` @ `ReadFileMapping` | 置信度: 75
4. **[VULN-DF-SNAPSHOT-004]** path_traversal (High) - `src/core/slice_table/slice/slice_address.cpp:67` @ `SliceAddress::Restore` | 置信度: 75
5. **[VULN-DF-SNAPSHOT-005]** path_traversal (High) - `src/core/snapshot/slice_table_restore_operation.cpp:229` @ `LoadSlicesIntoLogicalSliceChain` | 置信度: 75
6. **[VULN-DF-SNAPSHOT-007]** path_traversal (High) - `src/core/snapshot/pending_snapshot_operator_coordinator.cpp:137` @ `CreateHardLinkForLocalFiles` | 置信度: 75
7. **[VULN-DF-SNAPSHOT-008]** path_traversal (High) - `src/core/snapshot/slice_table_snapshot_operator.h:64` @ `createHardlinks` | 置信度: 75
8. **[VULN-DF-SNAPSHOT-009]** path_traversal (High) - `src/core/fresh_table/fresh_table.cpp:309` @ `FreshTable::Restore` | 置信度: 75
9. **[VULN-SEC-MEM-001]** resource_exhaustion (High) - `src/core/lsm_store/key/full_key_util.cpp:193` @ `ReadPrimary` | 置信度: 65
10. **[VULN-SEC-MEM-002]** resource_exhaustion (High) - `src/core/lsm_store/key/full_key_util.cpp:224` @ `ReadSecondaryKey` | 置信度: 65

---

## 2. 攻击面分析

未找到入口点数据。


---

## 3. High 漏洞 (14)

### [VULN-SEC-RESTORE-001] path_traversal - CreateHardLinkForRestoredLocalFile

**严重性**: High | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/core/snapshot/restore_operator.cpp:142-166` @ `CreateHardLinkForRestoredLocalFile`
**模块**: snapshot

**描述**: 硬链接创建使用来自checkpoint元数据的文件名(fileName)，通过PathTransform::ExtractFileName提取但未验证是否包含路径遍历字符。恶意checkpoint可构造包含路径遍历的文件名，导致在意外位置创建硬链接。

**漏洞代码** (`src/core/snapshot/restore_operator.cpp:142-166`)

```c
std::string fileName = PathTransform::ExtractFileName(restoredFileIno->GetFileName());
PathRef srcFile = std::make_shared<Path>(restoredBasePath, fileName);
if (link(srcFile->Name().c_str(), targetFile->Name().c_str()) != 0)
```

**达成路径**

恶意checkpoint元数据 -> SnapshotFileInfo.FileName -> ExtractFileName [无路径遍历检查] -> link() -> 路径遍历

**验证说明**: PathTransform::ExtractFileName只提取最后路径部分，不过滤../字符。fileName来自checkpoint元数据，直接拼接进Path构造，可实现路径遍历。例如fileName='../../../etc/passwd'会构造出restoredBasePath/../../../etc/passwd路径。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-SNAPSHOT-001] path_traversal - CreateHardLinkForRestoredLocalFile

**严重性**: High | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/snapshot/restore_operator.cpp:143-162` @ `CreateHardLinkForRestoredLocalFile`
**模块**: snapshot

**描述**: Hard link creation uses fileName from checkpoint metadata without path traversal validation. PathTransform::ExtractFileName only extracts the last path component but does not validate '../' sequences. The fileName is read from external checkpoint file via SnapshotRestoreUtils::ReadFileMapping, making it a potential path traversal vector.

**漏洞代码** (`src/core/snapshot/restore_operator.cpp:143-162`)

```c
std::string fileName = PathTransform::ExtractFileName(restoredFileIno->GetFileName());
...
PathRef srcFile = std::make_shared<Path>(restoredBasePath, fileName);
PathRef targetFile = std::make_shared<Path>(targetPath, fileName);
if (link(srcFile->Name().c_str(), targetFile->Name().c_str()) != 0)
```

**达成路径**

checkpoint metadata file [SOURCE] -> ReadFileMapping(fileName) -> CreateHardLinkForRestoredLocalFile(fileName) -> Path(restoredBasePath, fileName) -> link() [SINK]

**验证说明**: 与SEC-RESTORE-001相同漏洞，数据流分析确认fileName来自checkpoint元数据，通过ReadFileMapping读取，无路径遍历验证。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-SNAPSHOT-002] path_traversal - ReadFileMapping

**严重性**: High | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/snapshot/snapshot_restore_utils.cpp:108-134` @ `ReadFileMapping`
**模块**: snapshot

**描述**: basePath and fileName read from checkpoint metadata via ReadUTF without path validation. These values flow to CreateHardLinkForRestoredLocalFile for file operations. No sanitization of '../' sequences.

**漏洞代码** (`src/core/snapshot/snapshot_restore_utils.cpp:108-134`)

```c
std::string fileName;
inputView->ReadUTF(fileName);
SnapshotFileInfoRef restoredFileIno = std::make_shared<SnapshotFileInfo>(fileName, lsmFileId, 0);
```

**达成路径**

Checkpoint metadata [SOURCE] -> ReadUTF(fileName) -> SnapshotFileInfo -> CreateHardLinkForRestoredLocalFile [SINK]

**验证说明**: fileName通过ReadUTF从checkpoint元数据读取，直接用于SnapshotFileInfo。后续CreateHardLinkForRestoredLocalFile中Path(restoredBasePath, fileName)直接拼接，无路径遍历验证。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-SNAPSHOT-004] path_traversal - SliceAddress::Restore

**严重性**: High | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/slice_table/slice/slice_address.cpp:67-85` @ `SliceAddress::Restore`
**模块**: snapshot

**描述**: localAddress read from checkpoint metadata and stored without validation. Used later in LoadSlicesIntoLogicalSliceChain to construct file paths for reading slice data.

**漏洞代码** (`src/core/slice_table/slice/slice_address.cpp:67-85`)

```c
std::string localAddress;
RETURN_NOT_OK_AS_READ_ERROR(reader->ReadUTF(localAddress));
sliceAddress->SetLocalAddress(localAddress);
```

**达成路径**

Checkpoint [SOURCE] -> ReadUTF(localAddress) -> SetLocalAddress -> LoadSlicesIntoLogicalSliceChain -> FileInputView::Init [SINK]

**验证说明**: localAddress从checkpoint通过ReadUTF读取(行67)，直接SetLocalAddress存储。后续LoadSlicesIntoLogicalSliceChain用于构造Path打开文件，无路径遍历验证。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-SNAPSHOT-005] path_traversal - LoadSlicesIntoLogicalSliceChain

**严重性**: High | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/snapshot/slice_table_restore_operation.cpp:229-232` @ `LoadSlicesIntoLogicalSliceChain`
**模块**: snapshot

**描述**: localAddress from sliceAddress (deserialized from checkpoint) directly used to construct Path and open file. Combined with VULN-004 enables arbitrary file read.

**漏洞代码** (`src/core/snapshot/slice_table_restore_operation.cpp:229-232`)

```c
auto restoreFilePath = std::make_shared<Path>(sliceAddress->GetLocalAddress());
FileInputViewRef inputView = std::make_shared<FileInputView>();
inputView->Init(FileSystemType::LOCAL, restoreFilePath);
```

**达成路径**

sliceAddress->GetLocalAddress() [SOURCE] -> Path construction -> FileInputView::Init [SINK]

**验证说明**: sliceAddress->GetLocalAddress()直接用于构造Path(行229)，FileInputView::Init打开文件，无路径验证。攻击者可读取任意文件。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-SNAPSHOT-007] path_traversal - CreateHardLinkForLocalFiles

**严重性**: High | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/snapshot/pending_snapshot_operator_coordinator.cpp:137-162` @ `CreateHardLinkForLocalFiles`
**模块**: snapshot

**描述**: File paths from FileInfo used to create hard links. ExtractFileName does not sanitize '../' sequences. Hard link could be created outside intended directory.

**漏洞代码** (`src/core/snapshot/pending_snapshot_operator_coordinator.cpp:137-162`)

```c
PathRef srcFile = fileInfo->GetFilePath();
PathRef targetFile = std::make_shared<Path>(basePath, srcFile->ExtractFileName());
link(srcFile->Name().c_str(), targetFile->Name().c_str());
```

**达成路径**

FileInfo->GetFilePath() [SOURCE] -> Path construction -> link() [SINK]

**验证说明**: srcFile->ExtractFileName()从FileInfo获取，直接用于Path(basePath, fileName)构造，无路径遍历验证。link()可能在意外位置创建硬链接。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-SNAPSHOT-008] path_traversal - createHardlinks

**严重性**: High | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/snapshot/slice_table_snapshot_operator.h:64-83` @ `createHardlinks`
**模块**: snapshot

**描述**: sliceFile parameter used directly to construct paths for hard link creation without validation. Called from AsyncSnapshot with file names derived from potentially manipulated sliceAddress.

**漏洞代码** (`src/core/snapshot/slice_table_snapshot_operator.h:64-83`)

```c
PathRef sourcePath = std::make_shared<Path>(backupPath, sliceFile);
PathRef destPath = std::make_shared<Path>(snapshotPath, sliceFile);
link(sourcePath->Name().c_str(), destPath->Name().c_str());
```

**达成路径**

sliceFile [SOURCE] -> Path construction -> link() [SINK]

**验证说明**: sliceFile参数直接用于Path(backupPath, sliceFile)和Path(snapshotPath, sliceFile)构造，link()创建硬链接，无路径验证。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-SNAPSHOT-009] path_traversal - FreshTable::Restore

**严重性**: High | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/fresh_table/fresh_table.cpp:309-327` @ `FreshTable::Restore`
**模块**: snapshot

**描述**: address (file path) read from checkpoint metadata via ReadUTF and directly used to open file for reading. No path traversal validation.

**漏洞代码** (`src/core/fresh_table/fresh_table.cpp:309-327`)

```c
std::string address;
metaFileInputView->ReadUTF(address);
fileInputView->Init(FileSystemType::LOCAL, std::make_shared<Path>(Uri(address)));
```

**达成路径**

Checkpoint metadata [SOURCE] -> ReadUTF(address) -> Path construction -> FileInputView::Init [SINK]

**验证说明**: address通过ReadUTF从checkpoint元数据读取，直接用于Uri和Path构造，FileInputView::Init打开文件，无路径验证。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-SEC-MEM-001] resource_exhaustion - ReadPrimary

**严重性**: High | **CWE**: CWE-400 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/core/lsm_store/key/full_key_util.cpp:193-205` @ `ReadPrimary`
**模块**: lsm_store

**描述**: ReadPrimary从文件读取keyLen并直接分配内存，没有上限检查。恶意checkpoint文件可包含超大keyLen值(如UINT32_MAX)，导致内存耗尽DoS攻击。

**漏洞代码** (`src/core/lsm_store/key/full_key_util.cpp:193-205`)

```c
uint32_t keyLen = 0;
RETURN_AS_NOT_OK_NO_LOG(inputView->Read(keyLen));
auto addr = FileMemAllocator::Alloc(memManager, holder, keyLen, __FUNCTION__);
```

**达成路径**

恶意checkpoint文件 -> FileInputView.Read(keyLen) [无上限检查] -> FileMemAllocator::Alloc(keyLen) -> 内存耗尽

**验证说明**: keyLen从checkpoint文件直接读取，无上限检查。恶意checkpoint可构造超大keyLen(UINT32_MAX)导致内存耗尽DoS攻击。FileMemAllocator::Alloc会尝试分配但无大小限制。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-MEM-002] resource_exhaustion - ReadSecondaryKey

**严重性**: High | **CWE**: CWE-400 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/core/lsm_store/key/full_key_util.cpp:224-236` @ `ReadSecondaryKey`
**模块**: lsm_store

**描述**: ReadSecondaryKey从文件读取keyLen并直接分配内存，没有上限检查。与ReadPrimary相同漏洞模式，恶意checkpoint可导致内存耗尽。

**漏洞代码** (`src/core/lsm_store/key/full_key_util.cpp:224-236`)

```c
uint32_t keyLen = 0;
RETURN_AS_NOT_OK_NO_LOG(inputView->Read(keyLen));
secBuffer = MakeRef<ByteBuffer>(reinterpret_cast<uint8_t *>(addr), keyLen, memManager);
```

**达成路径**

恶意checkpoint文件 -> inputView->Read(keyLen) [无上限检查] -> 内存分配 -> 内存耗尽

**验证说明**: 与SEC-MEM-001相同漏洞模式，ReadSecondaryKey同样从文件读取keyLen无上限检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-MEM-001] unbounded_memory_allocation - ReadPrimary

**严重性**: High | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/lsm_store/key/full_key_util.cpp:184-213` @ `ReadPrimary`
**模块**: lsm_store/key

**描述**: keyLen is read from SST file and used directly for memory allocation without upper bound validation. While ByteBuffer has capacity checks, the keyLen value itself has no maximum limit, potentially leading to memory exhaustion if malicious SST file contains large keyLen values.

**漏洞代码** (`src/core/lsm_store/key/full_key_util.cpp:184-213`)

```c
uint32_t keyLen = 0;
RETURN_AS_NOT_OK_NO_LOG(inputView->Read(keyLen));
auto addr = FileMemAllocator::Alloc(memManager, holder, keyLen, __FUNCTION__);
```

**达成路径**

SST file [SOURCE] -> FileInputView::Read(keyLen) -> FileMemAllocator::Alloc(keyLen) [SINK]

**验证说明**: 与SEC-MEM-001相同漏洞，数据流分析确认路径可达。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-MEM-002] unbounded_memory_allocation - ReadSecondaryKey

**严重性**: High | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/lsm_store/key/full_key_util.cpp:215-242` @ `ReadSecondaryKey`
**模块**: lsm_store/key

**描述**: keyLen is read from SST file and used directly for memory allocation without upper bound validation. Same issue as ReadPrimary - no maximum limit on secondary key length.

**漏洞代码** (`src/core/lsm_store/key/full_key_util.cpp:215-242`)

```c
uint32_t keyLen = 0;
RETURN_AS_NOT_OK_NO_LOG(inputView->Read(keyLen));
auto addr = FileMemAllocator::Alloc(memManager, holder, keyLen, __FUNCTION__);
```

**达成路径**

SST file [SOURCE] -> FileInputView::Read(keyLen) -> FileMemAllocator::Alloc(keyLen) [SINK]

**验证说明**: 与SEC-MEM-002相同漏洞，数据流分析确认路径可达。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-FILE-001] heap_buffer_overflow - ReadBlock

**严重性**: High | **CWE**: CWE-122 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/lsm_store/file/file_reader.cpp:145-153` @ `ReadBlock`
**模块**: lsm_store/file

**描述**: Memory allocation with rawSize from blockHandle.GetSize() which originates from SST file footer/index block. No validation that rawSize is within reasonable bounds before FileMemAllocator::Alloc(). Malicious SST file can specify arbitrary large size causing heap overflow or memory exhaustion.

**漏洞代码** (`src/core/lsm_store/file/file_reader.cpp:145-153`)

```c
uint32_t rawSize = blockHandle.GetSize();
uint32_t totalBufferSize = HEAD_BLOCK_SIZE + rawSize;
auto addr = FileMemAllocator::Alloc(mMemManager, mHolder, totalBufferSize, __FUNCTION__);
```

**达成路径**

SST file footer [SOURCE] -> FooterStructure.metaIndexBlockHandleSize -> BlockHandle.mSize -> blockHandle.GetSize() -> FileMemAllocator::Alloc(totalBufferSize) [SINK]

**验证说明**: rawSize从SST文件footer读取，blockHandle.GetSize()无上限检查。恶意SST文件可构造超大rawSize导致内存耗尽DoS。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: -10 | reachability: 20

---

### [VULN-DF-FILE-002] heap_buffer_overflow - DecompressBlock

**严重性**: High | **CWE**: CWE-122 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/core/lsm_store/file/file_reader.cpp:169-191` @ `DecompressBlock`
**模块**: lsm_store/file

**描述**: originLength read directly from compressed block header without validation. This value controls decompression buffer allocation. Malicious SST file can specify originLength to cause heap overflow or memory exhaustion.

**漏洞代码** (`src/core/lsm_store/file/file_reader.cpp:169-191`)

```c
uint32_t originLength = *reinterpret_cast<uint32_t *>(byteBuffer->Data() + NO_1);
...
auto addrOrigin = FileMemAllocator::Alloc(mMemManager, mHolder, originLength, __FUNCTION__);
```

**达成路径**

SST compressed block header [SOURCE] -> reinterpret_cast(originLength) -> FileMemAllocator::Alloc(originLength) [SINK]

**验证说明**: originLength直接从压缩块头部读取(行169)，无验证。恶意SST文件可构造超大originLength导致内存耗尽。虽然有CRC检查，但不验证长度上限。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: -15 | reachability: 20

---

## 4. Medium 漏洞 (14)

### [VULN-DF-BINARY-001] out_of_bounds_read - SliceKey::Unpack

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/core/binary/slice_binary.h:39-69` @ `SliceKey::Unpack`
**模块**: binary

**描述**: SliceKey::Unpack uses direct pointer arithmetic with reinterpret_cast, bypassing ByteBuffer's boundary checks. The bufferOffset parameter is not validated against buffer capacity before dereferencing. If bufferOffset exceeds buffer capacity, this leads to out-of-bounds read.

**漏洞代码** (`src/core/binary/slice_binary.h:39-69`)

```c
uint8_t *data = buffer->Data() + bufferOffset;
uint16_t stateId = *reinterpret_cast<const uint16_t *>(data);
auto priKey = const_cast<SlicePriKey *>(reinterpret_cast<const SlicePriKey *>(data));
mPriKey.KeyLen(priKey->mKeyLen);
```

**达成路径**

ByteBuffer [SOURCE] -> buffer->Data() + bufferOffset -> reinterpret_cast -> memory read [SINK]

**验证说明**: bufferOffset参数未验证是否超过buffer容量。SliceKey::Unpack直接用buffer->Data()+bufferOffset访问内存，可能导致越界读取。但需要攻击者知道正确的bufferOffset值。

**评分明细**: base: 30 | controllability: 25 | context: -15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-FILE-003] integer_overflow - ReadBlock

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/core/lsm_store/file/file_reader.cpp:148-149` @ `ReadBlock`
**模块**: lsm_store/file

**描述**: totalBufferSize = HEAD_BLOCK_SIZE + rawSize can overflow uint32_t if rawSize is close to UINT32_MAX (e.g., 0xFFFFFFFF), resulting in small allocation followed by large file read.

**漏洞代码** (`src/core/lsm_store/file/file_reader.cpp:148-149`)

```c
uint32_t totalBufferSize = HEAD_BLOCK_SIZE + rawSize;
```

**达成路径**

blockHandle.GetSize() -> rawSize -> HEAD_BLOCK_SIZE + rawSize [OVERFLOW POTENTIAL]

**验证说明**: HEAD_BLOCK_SIZE + rawSize可能发生整数溢出(行148)。如果rawSize接近UINT32_MAX(如OxFFFFFFFF)，totalBufferSize会溢出为很小的值，导致缓冲区溢出。但实际攻击需要精确构造，难度较高。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-JNI-003] path_traversal - Java_com_huawei_ock_bss_common_BoostStateDB_restore

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/core/jni/com_huawei_ock_bss_common_BoostStateDB.cpp:64-131` @ `Java_com_huawei_ock_bss_common_BoostStateDB_restore`
**模块**: jni

**描述**: Restore paths from Java JNI passed through ConstructPath/GetStringUTFChars. While CheckPathValid uses realpath(), there's TOCTOU window between validation and actual Restore() call. allowPathNotExist=true allows paths that don't exist yet.

**漏洞代码** (`src/core/jni/com_huawei_ock_bss_common_BoostStateDB.cpp:64-131`)

```c
jstring restorePath = (jstring)env->CallObjectMethod(jRestorePaths, getMid, i);
std::string path = ConstructPath(env, restorePath);
if (UNLIKELY(!CheckPathValid(path))) { return JNI_FALSE; }
metaPaths.emplace_back(path);
```

**达成路径**

JNI jRestorePaths [SOURCE] -> ConstructPath -> GetStringUTFChars -> CheckPathValid -> Restore() [SINK]

**验证说明**: CheckPathValid使用realpath，在验证和Restore调用之间存在TOCTOU时间窗口。但realpath已解析路径，攻击难度高。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [VULN-DF-SNAPSHOT-003] integer_overflow - ReadFileMapping

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/core/snapshot/snapshot_restore_utils.cpp:121-122` @ `ReadFileMapping`
**模块**: snapshot

**描述**: numberLsmFiles read from checkpoint as uint32_t without upper bound validation. Large value causes excessive memory allocation and potential denial of service.

**漏洞代码** (`src/core/snapshot/snapshot_restore_utils.cpp:121-122`)

```c
uint32_t numberLsmFiles = NO_0;
RETURN_NULLPTR_AS_READ_ERROR(inputView->Read(numberLsmFiles));
for (uint32_t i = 0; i < numberLsmFiles; i++)
```

**达成路径**

Checkpoint [SOURCE] -> Read(numberLsmFiles) -> vector push_back [SINK]

**验证说明**: numberLsmFiles从checkpoint读取，无上限验证。大值会导致vector循环操作过多，可能导致DoS。但单个循环项处理较轻量。

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-SNAPSHOT-006] integer_overflow - RestoreSliceBucketIndex

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/core/snapshot/slice_table_restore_operation.cpp:94-104` @ `RestoreSliceBucketIndex`
**模块**: snapshot

**描述**: oldBucketNum read from checkpoint without upper bound validation. Large value causes massive vector allocation leading to memory exhaustion.

**漏洞代码** (`src/core/snapshot/slice_table_restore_operation.cpp:94-104`)

```c
uint32_t oldBucketNum = 0;
RETURN_NOT_OK_AS_READ_ERROR(reader->Read(oldBucketNum));
std::vector<LogicalSliceChainRef> logicalSliceChainTable(oldBucketNum);
```

**达成路径**

Checkpoint [SOURCE] -> Read(oldBucketNum) -> vector allocation [SINK]

**验证说明**: oldBucketNum从checkpoint读取，直接用于vector logicalSliceChainTable(oldBucketNum)分配。大值会导致内存耗尽。有zero检查但无上限。

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [VULN-DF-SNAPSHOT-010] integer_overflow - ReadSnapshotOperatorInfo

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/core/snapshot/snapshot_restore_utils.cpp:62-83` @ `ReadSnapshotOperatorInfo`
**模块**: snapshot

**描述**: numberOfSnapshotOperators from checkpoint metadata without upper bound validation. Large value causes excessive deserialization operations.

**漏洞代码** (`src/core/snapshot/snapshot_restore_utils.cpp:62-83`)

```c
for (uint32_t i = 0; i < numberOfSnapshotOperators; i++)
```

**达成路径**

Checkpoint [SOURCE] -> numberOfSnapshotOperators -> loop iteration [SINK]

**验证说明**: numberOfSnapshotOperators从checkpoint读取，无上限验证。大值会导致过多反序列化操作，可能导致DoS。

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-SEC-JNI-001] use_after_free - nativeGetDirectBufferData

**严重性**: Medium | **CWE**: CWE-416 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/core/jni/com_huawei_ock_bss_common_memory_DirectBuffer.cpp:25-27` @ `nativeGetDirectBufferData`
**模块**: jni

**描述**: DirectBuffer暴露原生指针给Java层，指针生命周期由native管理但Java端可能继续引用已释放内存。nativeGetDirectBufferData()直接返回buffer->Data()指针，当nativeReleaseDirectBuffer()释放后，Java端持有的指针变为悬空指针，可能导致UAF。

**漏洞代码** (`src/core/jni/com_huawei_ock_bss_common_memory_DirectBuffer.cpp:25-27`)

```c
SerializedDataWrapper *buffer = reinterpret_cast<SerializedDataWrapper *>(jBuffer);
return reinterpret_cast<jlong>(buffer->Data());
```

**达成路径**

Java DirectBuffer.nativeGetDirectBufferData() -> reinterpret_cast<SerializedDataWrapper*>(jBuffer) -> buffer->Data() [返回原生指针]
Java可能继续引用 -> nativeReleaseDirectBuffer() delete对象 -> UAF

**验证说明**: DirectBuffer API确实暴露原生指针给Java，但属于API设计问题而非直接安全漏洞。需要Java端正确配合使用，如果Java端在native释放后继续使用指针会导致UAF。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PTR-001] unsafe_pointer_exposure - SetKey/SetNamespace/SetMapKey/SetValue

**严重性**: Medium | **CWE**: CWE-767 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/core/jni/kv_helper.h:687-728` @ `SetKey/SetNamespace/SetMapKey/SetValue`
**模块**: jni

**描述**: 多处将原生内存指针(reinterpret_cast<jlong>(cppItem->mKey/mNs/mMapKey/mValue))直接设置到Java字段。这些指针指向native内存，Java端无法验证生命周期，可能导致非法内存访问或UAF。

**漏洞代码** (`src/core/jni/kv_helper.h:687-728`)

```c
env->SetLongField(javaItem, keyFiled, reinterpret_cast<jlong>(cppItem->mKey));
env->SetLongField(javaItem, namespaceFiled, reinterpret_cast<jlong>(cppItem->mNs));
env->SetLongField(javaItem, mapKeyFiled, reinterpret_cast<jlong>(cppItem->mMapKey));
env->SetLongField(javaItem, valueFiled, reinterpret_cast<jlong>(cppItem->mValue));
```

**达成路径**

BinaryKeyValueItem原生指针 -> SetLongField设置到Java对象 -> Java端直接引用native内存 -> native释放后UAF

**验证说明**: kv_helper.h中SetKey/SetNamespace/SetMapKey/SetValue直接将原生指针设置到Java字段。属于API设计问题，需要Java端正确配合使用。Java端持有指针但生命周期由native管理，可能导致UAF。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 30

---

### [VULN-DF-JNI-005] out_of_bounds_read - nativeGetDirectBufferData

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/core/jni/com_huawei_ock_bss_common_memory_DirectBuffer.cpp:18-27` @ `nativeGetDirectBufferData`
**模块**: jni

**描述**: Only validates null pointer. Java can pass arbitrary jlong values that are cast to pointers and dereferenced. No validation that pointer points to valid SerializedDataWrapper object.

**漏洞代码** (`src/core/jni/com_huawei_ock_bss_common_memory_DirectBuffer.cpp:18-27`)

```c
if (jBuffer == 0) { return 0; }
SerializedDataWrapper *buffer = reinterpret_cast<SerializedDataWrapper *>(jBuffer);
return reinterpret_cast<jlong>(buffer->Data());
```

**达成路径**

JNI jBuffer (arbitrary pointer) [SOURCE] -> reinterpret_cast -> buffer->Data() dereference [SINK]

**验证说明**: nativeGetDirectBufferData只检查jBuffer==0(行22)，Java可传入任意jlong指针值。reinterpret_cast后直接访问buffer->Data()可能导致非法内存访问。但攻击者需要知道有效的内存地址。

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: -10 | reachability: 30

---

### [VULN-SEC-VERSION-001] version_validation - ReadSnapshotMetaTail

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/core/snapshot/snapshot_restore_utils.cpp:178-184` @ `ReadSnapshotMetaTail`
**模块**: snapshot

**描述**: snapshot版本验证只检查snapshotVersion > NO_5返回错误，但没有检查过旧版本(如version=0)是否兼容。这可能导致处理不支持的老版本数据格式，产生解析错误。

**漏洞代码** (`src/core/snapshot/snapshot_restore_utils.cpp:178-184`)

```c
uint32_t snapshotVersion = UINT32_MAX;
RETURN_NULLPTR_AS_READ_ERROR(snapshotMetaInputView->Read(snapshotVersion));
if (UNLIKELY(snapshotVersion > NO_5)) {...}
```

**达成路径**

checkpoint文件 -> Read(snapshotVersion) -> 只检查 > NO_5 -> 可能接受过老版本

**验证说明**: snapshot版本只检查>NO_5，不检查过旧版本是否兼容。可能导致解析错误但非直接安全漏洞。

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-PATH-001] path_traversal - Path constructor

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/core/common/path.h:51-64` @ `Path constructor`
**模块**: common

**描述**: Path class constructor directly concatenates parent path with child without validating '../' path traversal sequences. This can allow construction of paths that escape intended directories.

**漏洞代码** (`src/core/common/path.h:51-64`)

```c
std::string netPath = parentStr + "/" + child->GetUri().GetPath();
mUri = Uri(netPath);
```

**达成路径**

parent path + child path [SOURCE] -> string concatenation -> Uri construction -> file operations [SINK]

**验证说明**: Path构造函数直接拼接parentStr + '/' + child，无 '../' 过滤。但实际使用中child通常来自内部生成而非外部输入。

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-FILE-004] improper_input_validation - InitializeFooterAndMetaBlock

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/core/lsm_store/file/file_reader.cpp:305-307` @ `InitializeFooterAndMetaBlock`
**模块**: lsm_store/file

**描述**: FooterStructure values read from SST file used directly to create BlockHandle without validation. metaIndexBlockHandleOffset and metaIndexBlockHandleSize from potentially corrupted footer lead to untrusted block reads.

**漏洞代码** (`src/core/lsm_store/file/file_reader.cpp:305-307`)

```c
BlockHandle metaIndexBlockHandle(footer.metaIndexBlockHandleOffset, footer.metaIndexBlockHandleSize);
ret = ReadBlock(metaIndexBlockHandle, metaIndexBlockBuffer);
```

**达成路径**

SST file footer [SOURCE] -> footer.metaIndexBlockHandleOffset/Size -> BlockHandle -> ReadBlock() [SINK]

**验证说明**: FooterStructure值直接从SST文件读取创建BlockHandle，无验证。但需要进一步分析是否有offset/size范围检查。

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-FILE-005] improper_input_validation - CreateFileMetaIndex

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/core/lsm_store/file/file_meta_index_block_writer.cpp:42-48` @ `CreateFileMetaIndex`
**模块**: lsm_store/file

**描述**: metaBlockOffset and metaBlockSize read directly from file buffer without validation. BlockHandle created with untrusted offset/size values used for subsequent reads.

**漏洞代码** (`src/core/lsm_store/file/file_meta_index_block_writer.cpp:42-48`)

```c
uint32_t metaBlockOffset = 0;
byteBuffer->ReadUint32(metaBlockOffset, position);
uint32_t metaBlockSize = 0;
byteBuffer->ReadUint32(metaBlockSize, position);
BlockHandleRef metaBlockMeta = std::make_shared<BlockHandle>(metaBlockOffset, metaBlockSize);
```

**达成路径**

SST meta index block [SOURCE] -> ReadUint32 -> BlockHandle construction [SINK]

**验证说明**: metaBlockOffset和metaBlockSize从文件缓冲区直接读取创建BlockHandle，无验证。

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-FILE-006] improper_input_validation - GetBlockAt

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/core/lsm_store/block/index_reader.cpp:79-83` @ `GetBlockAt`
**模块**: lsm_store/block

**描述**: blockOffsetDecode and blockSizeDecode are var-encoded values read from index block buffer. These values directly populate BlockHandle without validation against file bounds.

**漏洞代码** (`src/core/lsm_store/block/index_reader.cpp:79-83`)

```c
uint64_t blockOffsetDecode = VarEncodingUtil::DecodeUnsignedInt(buffer, handleOffset);
uint64_t blockSizeDecode = VarEncodingUtil::DecodeUnsignedInt(buffer, handleOffset + ...);
blockHandle.Fill(VarEncodingUtil::GetDecodedValue(blockOffsetDecode), VarEncodingUtil::GetDecodedValue(blockSizeDecode));
```

**达成路径**

Index block [SOURCE] -> VarEncodingUtil::Decode -> BlockHandle.Fill() [SINK]

**验证说明**: blockOffsetDecode和blockSizeDecode从index block直接var-decode读取，无文件边界验证。

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| binary | 0 | 0 | 1 | 0 | 1 |
| common | 0 | 0 | 1 | 0 | 1 |
| jni | 0 | 0 | 4 | 0 | 4 |
| lsm_store | 0 | 2 | 0 | 0 | 2 |
| lsm_store/block | 0 | 0 | 1 | 0 | 1 |
| lsm_store/file | 0 | 2 | 3 | 0 | 5 |
| lsm_store/key | 0 | 2 | 0 | 0 | 2 |
| snapshot | 0 | 8 | 4 | 0 | 12 |
| **合计** | **0** | **14** | **14** | **0** | **28** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 10 | 35.7% |
| CWE-190 | 6 | 21.4% |
| CWE-20 | 4 | 14.3% |
| CWE-400 | 2 | 7.1% |
| CWE-125 | 2 | 7.1% |
| CWE-122 | 2 | 7.1% |
| CWE-767 | 1 | 3.6% |
| CWE-416 | 1 | 3.6% |
