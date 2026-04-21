# 漏洞扫描报告 — 待确认漏洞

**项目**: IndexSDK
**扫描时间**: 2026-04-20T00:20:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 24 | 54.5% |
| LIKELY | 11 | 25.0% |
| FALSE_POSITIVE | 8 | 18.2% |
| CONFIRMED | 1 | 2.3% |
| **总计** | **44** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 4 | 11.4% |
| Medium | 15 | 42.9% |
| Low | 16 | 45.7% |
| **有效漏洞总计** | **35** | - |
| 误报 (FALSE_POSITIVE) | 8 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-001-VSTAR-READER]** Path Traversal (High) - `vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp:138` @ `VstarIOReader::VstarIOReader` | 置信度: 70
2. **[VULN-IVFSP-CBT-001]** Integer Overflow (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:158` @ `ReadFile` | 置信度: 70
3. **[VULN-IVFSP-CBT-002]** Integer Overflow (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:173` @ `ReadMemLearnData` | 置信度: 70
4. **[SEC-IVFSP-001]** Security Measure Bypass (High) - `ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:131` @ `FSPIOReader::FSPIOReader` | 置信度: 65
5. **[VULN-IVFSP-003]** File Handling (Medium) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:131` @ `FSPIOReader::FSPIOReader` | 置信度: 85
6. **[VULN-FR-004]** Path Traversal (Medium) - `feature_retrieval/src/ascendfaiss/ascend/ivfsp/AscendIndexIVFSPImpl.cpp:102` @ `addCodeBook` | 置信度: 70
7. **[VULN-FR-007]** path_traversal (Medium) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/feature_retrieval/src/ascendfaiss/ascend/ivfsp/AscendIndexIVFSPImpl.cpp:177` @ `loadAllData, saveAllData` | 置信度: 70
8. **[VULN-VGI-003]** Environment Variable Injection (Medium) - `vstar_great_impl/mix-index/src/npu/common/utils/AscendUtils.cpp:82` @ `AscendOperatorManager::init` | 置信度: 65
9. **[VULN-002-TOCTOU]** TOCTOU Race Condition (Medium) - `vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp:53` @ `initializeFileDescription` | 置信度: 65
10. **[VULN-CROSS-001]** Environment Variable Trust Chain (Medium) - `multiple modules:1` @ `multiple functions` | 置信度: 60

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `add@feature_retrieval/src/ascendfaiss/ascend/AscendIndex.h` | api | untrusted_local | 用户应用程序调用此API传入向量数据，数据内容完全由调用方控制 | 向索引中添加向量数据 |
| `search@feature_retrieval/src/ascendfaiss/ascend/AscendIndex.h` | api | untrusted_local | 用户应用程序调用此API传入查询向量，数据内容完全由调用方控制 | 执行向量检索搜索 |
| `addCodeBook@feature_retrieval/src/ascendfaiss/ascend/ivfsp/AscendIndexIVFSP.h` | file | untrusted_local | 用户指定码本文件路径，文件路径完全由调用方控制，可能被用于路径遍历攻击 | 从指定路径加载码本文件 |
| `initializeFileDescription@ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp` | file | untrusted_local | 用户指定文件路径进行读写操作，虽有安全检查但路径仍由用户控制 | 初始化文件描述符并校验路径安全性 |
| `initializeFileDescription@vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp` | file | untrusted_local | 用户指定文件路径进行读写操作，路径由用户控制 | 初始化文件描述符并校验路径安全性 |
| `AscendIndex@feature_retrieval/src/ascendfaiss/ascend/AscendIndex.h` | api | semi_trusted | 构造函数接收设备列表和资源配置，需要一定权限才能正确配置 | SDK索引对象构造函数 |

**其他攻击面**:
- API接口: add(), search(), add_with_ids() 等向量数据输入
- 文件I/O: 码本加载、索引保存/加载等用户可控文件路径
- 配置参数: 设备列表、资源大小等初始化配置

---

## 3. High 漏洞 (4)

### [VULN-001-VSTAR-READER] Path Traversal - VstarIOReader::VstarIOReader

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp:138-143` @ `VstarIOReader::VstarIOReader`
**模块**: vstar_great_impl

**描述**: VstarIOReader构造函数直接调用open()打开文件，未进行路径安全检查（路径长度、字符有效性、符号链接等），与VstarIOWriter/VstarIOWriter使用的initializeFileDescription()相比缺少完整的防护措施。攻击者可通过构造恶意路径（如../）或符号链接实现路径遍历攻击。

**达成路径**

用户输入(fname) -> open(name.c_str(), O_NOFOLLOW | O_RDONLY) [缺少路径规范化、长度检查、字符白名单验证]

**验证说明**: VstarIOReader直接调用open()，仅有O_NOFOLLOW和部分调用点的checkSoftLink()防护。对比VstarIOWriter使用initializeFileDescription()有完整路径验证(长度/字符/规范化/属主)，Reader缺失关键防护。可通过../实现路径遍历。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-IVFSP-CBT-001] Integer Overflow - ReadFile

**严重性**: High | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:158-159` @ `ReadFile`
**模块**: ivfsp_impl

**描述**: Integer overflow in ReadFile when computing nb and allocating memory. nb is int type (32-bit) while fileSize is size_t. Division result could overflow when cast to int. Later nb*dim multiplication in vector resize could overflow causing insufficient memory allocation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:158-159`)

```c
nb = fileSize / (dim * sizeof(float));\nlearnDataFp32.resize(static_cast<size_t>(nb) * dim);
```

**达成路径**

fileSize -> nb (int truncation) -> nb*dim (overflow) -> resize()

**验证说明**: Integer overflow confirmed: nb(int32) = fileSize(size_t)/divisor truncates. With MAX_LEARN_DATA_SIZE=100GB and typical dim=128-256, overflow threshold (~8GB for dim=128) is reachable. Negative nb causes resize(size_t(nb)*dim) to allocate huge memory. Positive truncation allocates insufficient memory for actual data.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-IVFSP-CBT-002] Integer Overflow - ReadMemLearnData

**严重性**: High | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:173-174` @ `ReadMemLearnData`
**模块**: ivfsp_impl

**描述**: Integer overflow in ReadMemLearnData. nb is int type while memLearnDataSize is size_t. Truncation occurs when assigning memLearnDataSize/dim to int nb, potentially causing incorrect calculations in subsequent operations.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:173-174`)

```c
nb = memLearnDataSize / dim;\nlearnDataFp32.resize(memLearnDataSize);
```

**达成路径**

memLearnDataSize -> nb (int truncation) -> subsequent nb usage

**验证说明**: Integer overflow confirmed: nb(int32) = memLearnDataSize(size_t)/dim truncates. Similar mechanics to VULN-001. memLearnDataSize is element count (not bytes), max ~25B elements allowed by 100GB limit. Overflow occurs when memLearnDataSize > INT_MAX*dim.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [SEC-IVFSP-001] Security Measure Bypass - FSPIOReader::FSPIOReader

**严重性**: High | **CWE**: CWE-73 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:131-136` @ `FSPIOReader::FSPIOReader`
**模块**: ivfsp_utils

**描述**: FSPIOReader constructor (line 131-136) bypasses multiple security checks that are present in FSPIOWriter/initializeFileDescription. The reader path is opened with O_NOFOLLOW but lacks: 1) parent directory symlink check (checkLinkRec), 2) file ownership verification (st.st_uid != geteuid()), 3) file size limit check (MAX_DATAFILE_SIZE), 4) regular file type check. This creates an asymmetric security posture where read operations have fewer protections than write operations.

**漏洞代码** (`ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:131-136`)

```c
fd = open(name.c_str(), O_NOFOLLOW | O_RDONLY);
```

**达成路径**

User input (fname) -> FSPIOReader constructor -> open() -> read operations

**验证说明**: FSPIOReader确实缺少FSPIOWriter中的多项安全检查（父目录symlink检查、文件大小/属主检查）。O_NOFOLLOW仅防护最终路径symlink，不防护父目录symlink绕过。攻击者可构造路径读取其他用户的文件。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (15)

### [VULN-IVFSP-003] File Handling - FSPIOReader::FSPIOReader

**严重性**: Medium | **CWE**: CWE-73 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:131-136` @ `FSPIOReader::FSPIOReader`
**模块**: ivfsp_impl

**描述**: Incomplete path validation in FSPIOReader. Unlike FSPIOWriter which performs comprehensive validation (path length 255 chars, encoding whitelist, owner check, file size limit 56GB), FSPIOReader only uses O_NOFOLLOW flag for symlink protection.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:131-136`)

```c
fd = open(name.c_str(), O_NOFOLLOW | O_RDONLY);
```

**验证说明**: CONFIRMED discrepancy: FSPIOWriter has comprehensive validation (255 chars path limit, encoding whitelist check, parent dir symlink check, owner check, 56GB file size limit). FSPIOReader only uses O_NOFOLLOW flag - lacks path length, encoding, owner, and size validation.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-FR-004] Path Traversal - addCodeBook

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `feature_retrieval/src/ascendfaiss/ascend/ivfsp/AscendIndexIVFSPImpl.cpp:102-111` @ `addCodeBook`
**模块**: feature_retrieval
**跨模块**: feature_retrieval-cpp, ascendSearch-module

**描述**: addCodeBook() API中的路径遍历风险：用户传入的codeBookPath直接传递给底层实现，虽然有RealPath处理和CheckPathValid限制(/home/或/root/)，但限制范围较广，可能允许访问用户目录下的敏感文件。

**漏洞代码** (`feature_retrieval/src/ascendfaiss/ascend/ivfsp/AscendIndexIVFSPImpl.cpp:102-111`)

```c
FAISS_THROW_IF_NOT_MSG((codeBookPath != nullptr), "codeBookPath can not be nullptr"); std::string cdbkFilePath(codeBookPath); pIVFSPSQ->addCodeBook(cdbkFilePath);
```

**达成路径**

User input: codeBookPath -> std::string cdbkFilePath -> pIVFSPSQ->addCodeBook() [CROSS_MODULE to ascendSearch namespace]

**验证说明**: Path traversal vulnerability confirmed. addCodeBook() accepts arbitrary file path with only null check, no path validation. RealPath() and CheckSymLink() utilities exist but are NOT applied. Cross-module call to pIVFSPSQ->addCodeBook() passes unvalidated path.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: -15

---

### [VULN-FR-007] path_traversal - loadAllData, saveAllData

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/feature_retrieval/src/ascendfaiss/ascend/ivfsp/AscendIndexIVFSPImpl.cpp:177-192` @ `loadAllData, saveAllData`
**模块**: feature_retrieval-cpp
**跨模块**: feature_retrieval-cpp, ascendSearch-module

**描述**: The loadAllData and saveAllData functions accept file paths from user input without proper validation. Similar to addCodeBook, these functions pass arbitrary paths to the underlying pIVFSPSQ component without canonicalization, symlink checks, or path traversal prevention. A malicious user could read from arbitrary locations or write data to sensitive system files.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/feature_retrieval/src/ascendfaiss/ascend/ivfsp/AscendIndexIVFSPImpl.cpp:177-192`)

```c
void AscendIndexIVFSPImpl::loadAllData(const char *dataPath)\n{\n    auto lock = ::ascend::AscendMultiThreadManager::GetWriteLock(mtxVec[ivfspConfig.deviceList.front()]);\n    pIVFSPSQ->loadAllData(dataPath);\n    ...\n}\n\nvoid AscendIndexIVFSPImpl::saveAllData(const char *dataPath)\n{\n    pIVFSPSQ->saveAllData(dataPath);\n}
```

**达成路径**

User input: dataPath -> pIVFSPSQ->loadAllData/saveAllData() [CROSS_MODULE to ascendSearch namespace]

**验证说明**: Path traversal vulnerability confirmed in both loadAllData and saveAllData. No path validation before cross-module calls. User-controlled path directly passed to pIVFSPSQ->loadAllData()/saveAllData(). Same pattern as VULN-FR-004.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: -15

---

### [VULN-VGI-003] Environment Variable Injection - AscendOperatorManager::init

**严重性**: Medium | **CWE**: CWE-453 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `vstar_great_impl/mix-index/src/npu/common/utils/AscendUtils.cpp:82-89` @ `AscendOperatorManager::init`
**模块**: vstar_great_impl
**跨模块**: vstar_great_impl,mix-index

**描述**: [CREDENTIAL_FLOW] MX_INDEX_MODELPATH controls model loading path.

**漏洞代码** (`vstar_great_impl/mix-index/src/npu/common/utils/AscendUtils.cpp:82-89`)

```c
getenv MX_INDEX_MODELPATH
```

**达成路径**

env->aclopSetModelDir

**验证说明**: 有缓解措施(RealPath+CheckPathValid)，但CheckPathValid仅检查/home/或/root/前缀，攻击者仍可访问这些目录下可读文件。攻击面受限但漏洞有效。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-002-TOCTOU] TOCTOU Race Condition - initializeFileDescription

**严重性**: Medium | **CWE**: CWE-367 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp:53-56` @ `initializeFileDescription`
**模块**: vstar_great_impl

**描述**: initializeFileDescription()中存在TOCTOU(Time-of-Check-Time-of-Use)竞争条件。realpath()在第53行解析路径后，lstat()在第54行检查文件状态，之间存在时间窗口。攻击者可在此期间替换文件系统对象，绕过安全检查。

**达成路径**

realpath(realPath.c_str(), resolvedPath) -> [竞争窗口] -> lstat(realPath.c_str(), &st) -> open(resolvedPath, ...)

**验证说明**: Classic TOCTOU exists: realpath() at line 53 resolves path, then lstat() at line 54 checks status, then open() at line 56. Window between lstat and open allows file replacement. However, O_NOFOLLOW prevents symlink replacement attacks. Attacker could still swap regular file with another regular file owned by same user. Mitigated by owner check and O_NOFOLLOW.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: -15 | reachability: 30

---

### [VULN-CROSS-001] Environment Variable Trust Chain - multiple functions

**严重性**: Medium | **CWE**: CWE-453 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `multiple modules:1` @ `multiple functions`
**模块**: cross_module
**跨模块**: vstar_great_impl → ivfsp_utils → vsa_hpp → feature_retrieval

**描述**: [CREDENTIAL_FLOW] 多模块共享环境变量信任链：MX_INDEX_MODELPATH、MX_INDEX_HOME、MX_INDEX_FINALIZE 环境变量在多个模块（vstar_great_impl、ivfsp_utils、vsa_hpp、feature_retrieval）中被使用控制关键路径和行为。攻击者若能控制这些环境变量，可同时影响：1) 模型加载路径(aclopSetModelDir)，2) 版本文件路径，3) 最终化行为。这是一个跨模块的安全信任链问题。

**漏洞代码** (`multiple modules:1`)

```c
getenv(MX_INDEX_MODELPATH), getenv(MX_INDEX_HOME), getenv(MX_INDEX_FINALIZE)
```

**达成路径**

环境变量 → vstar_great_impl(AscendUtils.cpp:82) → aclopSetModelDir; ivfsp_utils(Version.cpp:49) → filePath; ivfsp_utils(AscendUtils.cpp) → modelpath; vstar_great_impl(SocUtils.h:181) → aclFinalize

**验证说明**: 跨模块环境变量信任链验证确认。MX_INDEX_MODELPATH有RealPath+CheckPathValid验证(-15缓解)，MX_INDEX_HOME仅有realpath和后缀检查，MX_INDEX_FINALIZE仅有长度验证。攻击者控制环境变量可影响模型加载路径、版本文件路径和最终化行为。评分：base30+reachability30+controllability15+mitigations(-15)+context0+cross_file0=60

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-FR-001] Integer Overflow - searchImpl

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `feature_retrieval/src/ascendfaiss/ascend/impl/AscendIndexImpl.cpp:315-316` @ `searchImpl`
**模块**: feature_retrieval

**描述**: add() API中的整数溢出风险：用户传入的向量数量n在内存分配计算中可能导致整数溢出。当用户传入超大n值时，n * dims * sizeof(float)的计算可能溢出，导致分配不足的内存或缓冲区溢出。

**漏洞代码** (`feature_retrieval/src/ascendfaiss/ascend/impl/AscendIndexImpl.cpp:315-316`)

```c
std::vector<uint16_t> query(n * this->intf_->d, 0);
```

**达成路径**

add(idx_t n, const float* x) [AscendIndex.h:70] -> impl_->add() -> addPaged() -> addImpl() -> aclrtMemcpy [size=n*dims*sizeof]

**验证说明**: Integer overflow risk in searchImpl vector allocation mitigated by pagination logic. searchPaged() limits n via SEARCH_PAGE_SIZE constraints, preventing exploitation of n*d multiplication overflow.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-FR-002] Integer Overflow - indexSearch

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `feature_retrieval/src/ascendfaiss/ascend/impl/AscendIndexImpl.cpp:662-663` @ `indexSearch`
**模块**: feature_retrieval

**描述**: search() API中的整数溢出风险：查询向量数量n和维度dims的乘积在aclrtMemcpy调用时可能导致整数溢出。param.n * param.dim * sizeof(uint16_t)的计算可能溢出，导致内存操作异常。

**漏洞代码** (`feature_retrieval/src/ascendfaiss/ascend/impl/AscendIndexImpl.cpp:662-663`)

```c
aclrtMemcpy(tensorDevQueries.data(), tensorDevQueries.getSizeInBytes(), param.query, param.n * param.dim * sizeof(uint16_t), ACL_MEMCPY_HOST_TO_DEVICE);
```

**达成路径**

search(idx_t n, const float* x, idx_t k, ...) [AscendIndex.h:81] -> impl_->search() -> searchPaged() -> searchImpl() -> indexSearch() -> aclrtMemcpy

**验证说明**: Integer overflow in indexSearch aclrtMemcpy size calculation mitigated by upstream pagination. param.n and param.dim are bounded by SEARCH_PAGE_SIZE before reaching this function.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-VGI-004] External Control of File Path - initializeFileDescription

**严重性**: Medium | **CWE**: CWE-73 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp:29-87` @ `initializeFileDescription`
**模块**: vstar_great_impl
**跨模块**: vstar_great_impl,mix-index

**描述**: [CREDENTIAL_FLOW] User-Controlled File Path in File Operations: initializeFileDescription takes user-provided file path. Has security measures: path length (255), character whitelist, O_NOFOLLOW, owner check, size limits. Concern: realpath() called at line 53 before lstat checks, potentially resolving symlinks before detection.

**漏洞代码** (`vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp:29-87`)

```c
void initializeFileDescription(int &fd, const std::string &fname) { ... char *resolvedPathPtr = realpath(realPath.c_str(), resolvedPath); if (lstat(realPath.c_str(), &st) == 0) { ... fd = open(resolvedPath, O_NOFOLLOW | O_WRONLY); ... parentDirCheckAndRemove(realPath, fd, false); } }
```

**达成路径**

fname(user) -> getcwd/realpath -> lstat -> open(O_NOFOLLOW) -> fstat -> parentDirCheckAndRemove

**验证说明**: User-provided file path has comprehensive security measures: length check (255), character whitelist, O_NOFOLLOW, owner check (geteuid), file size check (56GB limit), regular file check (S_ISREG), parent directory symlink check. Concern: realpath() called before lstat() could resolve symlinks before detection, but O_NOFOLLOW on open() mitigates symlink attacks on target file.

**评分明细**: base: 30 | controllability: 15 | context: -5 | cross_file: 0 | mitigations: -25 | reachability: 30

---

### [SEC-IVFSP-005] External Control of Path - GetVersionInfo

**严重性**: Medium | **CWE**: CWE-73 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ivfsp_utils/src/ascend/utils/Version.cpp:49-68` @ `GetVersionInfo`
**模块**: ivfsp_utils

**描述**: Environment variable MX_INDEX_HOME controls version.info file path without full security validation. While realpath() is used to canonicalize the path, the security checks in GetVersionInfo are less comprehensive than those in initializeFileDescription - no symlink checks for parent directories, no file ownership check, no file size limit. An attacker controlling MX_INDEX_HOME could potentially read arbitrary version.info files.

**漏洞代码** (`ivfsp_utils/src/ascend/utils/Version.cpp:49-68`)

```c
const char* mxIndexEnv = std::getenv("MX_INDEX_HOME"); if (mxIndexEnv) { mxIndexHome = mxIndexEnv; } std::string filePath = mxIndexHome + std::string(versionInfo);
```

**达成路径**

getenv(MX_INDEX_HOME) -> filePath construction -> realpath -> ifstream open

**验证说明**: MX_INDEX_HOME环境变量控制版本文件路径，缺少CheckPathValid中的路径前缀白名单和父目录symlink检查。但需要攻击者控制环境变量+程序读取敏感文件+程序运行权限，利用条件苛刻。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-IVFSP-CBT-003] Off-by-one Error - PutDataInNList

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:358-365` @ `PutDataInNList`
**模块**: ivfsp_impl

**描述**: Off-by-one bounds check in PutDataInNList. The condition nlistId <= nlist should be nlistId < nlist. This allows accessing learnDataByNList[nlist] which is out of bounds since valid indices are 0 to nlist-1.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:358-365`)

```c
ASCEND_THROW_IF_NOT_FMT(nlistId <= nlist, ...);\nlearnDataByNList[nlistId].insert(...);
```

**达成路径**

labels[i] -> nlistId -> bounds check (<= instead of <) -> learnDataByNList[nlistId]

**验证说明**: Off-by-one bounds check confirmed: condition 'nlistId <= nlist' should be 'nlistId < nlist'. learnDataByNList.resize(nlist) creates indices 0..nlist-1, so nlistId==nlist is OOB. Practical exploitability limited as labels from ArgMaxAlongNList/faiss are normally in [0, nlist-1]. Bug causes potential crash in edge cases.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -15 | cross_file: 0

---

### [SEC-IVFSP-002] Race Condition - initializeFileDescription

**严重性**: Medium | **CWE**: CWE-367 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:50-79` @ `initializeFileDescription`
**模块**: ivfsp_utils

**描述**: Potential TOCTOU (Time-of-check Time-of-use) race condition in initializeFileDescription. The sequence: 1) lstat(realPath) to check symlinks, 2) open(realPath) to get file descriptor is not atomic. An attacker could replace the path between lstat and open (e.g., replace regular file with symlink). While O_NOFOLLOW helps mitigate symlink-to-file attacks, the parent directory check (checkLinkRec) is performed before open, leaving a race window.

**漏洞代码** (`ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:50-79`)

```c
if (lstat(realPath.c_str(), &st) == 0) { fd = open(realPath.c_str(), O_NOFOLLOW | O_WRONLY); ... parentDirCheckAndRemove(realPath, fd, false); }
```

**达成路径**

User input fname -> lstat check -> race window -> open -> parentDirCheckAndRemove

**验证说明**: TOCTOU竞态存在于lstat和open之间，但O_NOFOLLOW防止最终路径是symlink的攻击。文件属主检查(需geteuid匹配)进一步限制攻击收益。实际利用需要精确时机控制和本地文件系统访问。

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-IVFSP-004] TOCTOU Race Condition - checkLinkRec/parentDirCheckAndRemove

**严重性**: Medium | **CWE**: CWE-367 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:83-119` @ `checkLinkRec/parentDirCheckAndRemove`
**模块**: ivfsp_utils

**描述**: checkLinkRec()函数与后续文件操作之间存在TOCTOU(Time-of-check to time-of-use)竞态条件。攻击者可在检查与操作之间的时间窗口内将目录替换为符号链接。

**漏洞代码** (`ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:83-119`)

```c
bool checkLinkRec(const std::string &realPathFunc)
{
    // 检查符号链接
}
// 竞态窗口：检查后、操作前，攻击者可修改文件系统
void parentDirCheckAndRemove(...)
{
    if (checkLinkRec(realPathParent)) { ... }
    // 此处存在竞态窗口
}
```

**达成路径**

检查 -> 竞态窗口 -> 文件操作

**验证说明**: checkLinkRec与后续文件操作之间存在TOCTOU窗口。攻击者可在检查后、操作前将父目录替换为symlink。但需要本地文件系统访问和精确时机控制，实际利用难度高。与SEC-IVFSP-002是同一TOCTOU问题的不同方面。

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-004-INTOVERFLOW-PIVOT] Integer Overflow to Buffer Overflow - GeneratePQPivots

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `vstar_great_impl/DiskIndex/src/Adapter/OpenGaussAdapter.cpp:150-151` @ `GeneratePQPivots`
**模块**: vstar_great_impl

**描述**: GeneratePQPivots()第150行分配trainDataVec时使用sample->length * sample->dim计算大小，无溢出检查。虽然length被限制在1e8，但dim可达2000，乘积最大约200GB，可能导致内存分配失败或拒绝服务。

**达成路径**

sample->length * sample->dim -> vector<float>分配 [无溢出检查，极端值可达200GB]

**验证说明**: 原CWE-680不准确，修正为CWE-400(Resource Exhaustion)。length*dim最大2e11(200GB)，64位系统无溢出但可能导致内存分配失败/DoS。风险类型应为资源耗尽而非整数溢出到缓冲区溢出。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-005-INTOVERFLOW-PQDATA] Integer Overflow to Heap Overflow - GeneratePQDataFromPivots

**严重性**: Medium | **CWE**: CWE-680 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `vstar_great_impl/DiskIndex/src/Adapter/OpenGaussAdapter.cpp:202-203` @ `GeneratePQDataFromPivots`
**模块**: vstar_great_impl

**描述**: GeneratePQDataFromPivots()第202行分配blockCompressedBase时使用input.numTrain * input.numPQChunks计算大小，两者均为size_t/uint32_t类型，乘积可能溢出导致缓冲区分配不足，后续写入越界。

**达成路径**

numTrain * numPQChunks -> make_unique<uint32_t[]> [无溢出检查，溢出后分配缓冲区过小]

**验证说明**: CheckVectorArray验证限制length≤1e8, pqChunks≤dim≤2000。64位系统size_t可容纳2e11(无溢出)。实际风险为资源耗尽/DoS而非整数溢出。32位系统可能溢出但项目可能不支持。降低置信度。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -20 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (16)

### [VULN-IVFSP-001] Information Exposure - LogInfo

**严重性**: Low | **CWE**: CWE-200 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.h:220` @ `LogInfo`
**模块**: ivfsp_impl

**描述**: Sensitive path information disclosure in verbose output. The codebook output path is printed to console via printf, which may leak sensitive filesystem information to unauthorized observers.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.h:220`)

```c
printf("Output codebook dir = %s;\n", codeBookOutputPath.c_str());
```

**验证说明**: printf outputs codeBookOutputPath only when verbose=true. Path information disclosure requires verbose mode enabled and console access. Controlled by configuration parameter.

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: -5 | context: -10 | cross_file: 0

---

### [VULN-IVFSP-002] Information Exposure - RpcIndexIVFSPSQRemoveIds

**严重性**: Low | **CWE**: CWE-200 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascendhost/src/rpc-local/AscendRpcLocalIndexIVFSPSQ.cpp:389-405` @ `RpcIndexIVFSPSQRemoveIds`
**模块**: ivfsp_impl

**描述**: Index ID information disclosure in log messages. The RPC operations log index IDs and removal ranges which could aid attackers in understanding internal system structure.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascendhost/src/rpc-local/AscendRpcLocalIndexIVFSPSQ.cpp:389-405`)

```c
APP_LOG_INFO("remove %d vector(s) of index %d\n", n, indexId);
```

**验证说明**: APP_LOG_INFO logs index IDs and removal ranges. Information exposure requires log file access. Internal RPC operations logging, not user-controlled input.

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: -10 | context: -5 | cross_file: 0

---

### [VULN-IVFSP-CBT-007] Integer Overflow - SplitLearnDataByBatch

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:521-528` @ `SplitLearnDataByBatch`
**模块**: ivfsp_impl

**描述**: Integer overflow in SplitLearnDataByBatch. Calculation i*batchSize and actualBatchSize*dim could overflow when processing large datasets, causing incorrect batch splitting.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:521-528`)

```c
size_t actualBatchSize = std::min(...) - i * batchSize;\nlearnDataByBatch[i].resize(actualBatchSize * dim);
```

**达成路径**

i*batchSize -> subtraction; actualBatchSize*dim -> resize

**验证说明**: i*batchSize uses int arithmetic. actualBatchSize*dim uses size_t. Typical batchSize=32768, nb bounded by training data size. Loop bounds derived from vector resize.

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-FR-006] Missing Input Validation - CheckFilterTime

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `feature_retrieval/src/ascendfaiss/ascend/impl/AscendIndexImpl.cpp:528-537` @ `CheckFilterTime`
**模块**: feature_retrieval

**描述**: add_with_ids() API中缺少对ids数组的有效性验证：用户传入的ids数组直接传递给底层，在CheckFilterTime中仅检查时间戳符号位，但未验证ids是否在有效范围内或是否为null（ids可为null但需明确处理）。

**漏洞代码** (`feature_retrieval/src/ascendfaiss/ascend/impl/AscendIndexImpl.cpp:528-537`)

```c
if (indexConfig.filterable && ids != nullptr) { for (idx_t i = 0; i < n; i++) { FAISS_THROW_IF_NOT_FMT(((static_cast<uint64_t>(ids[i]) >> 41) & 0x1) == 0, ...); } }
```

**达成路径**

add_with_ids(idx_t n, const float* x, const idx_t* ids) -> impl_->add_with_ids() -> CheckFilterTime()

**验证说明**: Missing input validation for ids array. CheckFilterTime validates timestamp bit only, not id range validity. ids nullptr check exists but semantic validation is incomplete. Impact depends on downstream pIVFSPSQ->add() behavior with invalid ids.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-IVFSP-CBT-005] Integer Overflow - ZzFormatReshape

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:563-572` @ `ZzFormatReshape`
**模块**: ivfsp_impl

**描述**: Integer overflow in ZzFormatReshape memcpy offset calculation. Multiple multiplications in offset calculations (i*CUBE_ALIGN*col, k*CUBE_ALIGN, j*CUBE_ALIGN*CUBE_ALIGN) could overflow causing incorrect memory access.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:563-572`)

```c
dst.resize(static_cast<size_t>(rowMovCnt) * colMovCnt * CUBE_ALIGN * CUBE_ALIGN, 0);\nmemcpy_s(dst.data() + i * CUBE_ALIGN * col + ...)
```

**达成路径**

rowMovCnt*colMovCnt*CUBE_ALIGN*CUBE_ALIGN -> resize; i*CUBE_ALIGN*col -> memcpy offset

**验证说明**: Resize protected by static_cast<size_t>. Offset i*CUBE_ALIGN*col in memcpy could overflow but CUBE_ALIGN=16 constant limits impact. Pre-validation ASCEND_THROW_IF_NOT_FMT checks src.size() bounds.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -15 | context: -15 | cross_file: 0

---

### [VULN-IVFSP-CBT-006] Integer Overflow - NzFormatReshape

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:587-595` @ `NzFormatReshape`
**模块**: ivfsp_impl

**描述**: Integer overflow in NzFormatReshape memcpy offset calculation. Multiple multiplications in offset calculations could overflow causing incorrect memory access during data reshaping.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:587-595`)

```c
dst.resize(static_cast<size_t>(rowMovCnt) * CUBE_ALIGN * col, 0);\nmemcpy_s(dst.data() + i * CUBE_ALIGN * col + ...)
```

**达成路径**

rowMovCnt*CUBE_ALIGN*col -> resize; i*CUBE_ALIGN*col -> memcpy offset

**验证说明**: Similar to CBT-005. ASCEND_THROW_IF_NOT_FMT validates src.size(). CUBE_ALIGN=16 limits multiplication overflow potential.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -15 | context: -15 | cross_file: 0

---

### [VULN-IVFSP-CBT-008] Integer Overflow - MergeCodeBookByNList

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:332-339` @ `MergeCodeBookByNList`
**模块**: ivfsp_impl

**描述**: Integer overflow in MergeCodeBookByNList array indexing. Multiple multiplications (i*nonzeroNum, i*nlist*nonzeroNum+j*nonzeroNum) in offset calculations could overflow.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:332-339`)

```c
codeBookFp32.resize(static_cast<size_t>(dim) * nlist * nonzeroNum);\nstd::copy(..., codeBookFp32.begin() + i * nlist * nonzeroNum + j * nonzeroNum);
```

**达成路径**

dim*nlist*nonzeroNum -> resize; i*nlist*nonzeroNum+j*nonzeroNum -> array offset

**验证说明**: Resize protected. Loop uses size_t from vector sizing. Offset i*nlist*nonzeroNum+j*nonzeroNum uses size_t loop vars. Mitigation: loop bounds derived from validated resize.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-IVFSP-CBT-010] Integer Overflow - SplitCodeBookByNList

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:319-327` @ `SplitCodeBookByNList`
**模块**: ivfsp_impl

**描述**: Integer overflow in SplitCodeBookByNList array indexing. Multiple multiplications in offset calculations could overflow causing incorrect memory access.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:319-327`)

```c
codeBookByNList[i].resize(static_cast<size_t>(dim) * nonzeroNum);\nstd::copy(codeBookFp32.begin() + j * nlist * nonzeroNum + i * nonzeroNum, ...);
```

**达成路径**

dim*nonzeroNum -> resize; j*nlist*nonzeroNum+i*nonzeroNum -> offset

**验证说明**: Similar to CBT-008. Loop vars are size_t. Resize protected by static_cast<size_t>. j*nlist*nonzeroNum+i*nonzeroNum uses size_t arithmetic.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-VGI-001] Information Exposure - Finalize

**严重性**: Low | **CWE**: CWE-200 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `vstar_great_impl/mix-index/include/npu/common/utils/SocUtils.h:193` @ `Finalize`
**模块**: vstar_great_impl

**描述**: Sensitive Information Exposure in Logs: Environment variable MX_INDEX_FINALIZE value is logged in debug logs. SocUtils.h Finalize() function logs env var content which could contain sensitive configuration.

**漏洞代码** (`vstar_great_impl/mix-index/include/npu/common/utils/SocUtils.h:193`)

```c
APP_LOG_DEBUG("set env -------------%s \n", finalizeEnv);
```

**达成路径**

getenv(MX_INDEX_FINALIZE) -> validate -> APP_LOG_DEBUG

**验证说明**: Environment variable MX_INDEX_FINALIZE is logged at DEBUG level, but value is strictly validated to be exactly 1 character ('0' or '1') before logging (lines 180-183). The logged content is essentially a boolean flag, not sensitive configuration. Impact is minimal - only DEBUG level logging, not INFO/WARN/ERROR.

**评分明细**: base: 30 | controllability: 5 | context: -5 | cross_file: 0 | mitigations: -15 | reachability: 20

---

### [VULN-VGI-006] Information Exposure - initializeFileDescription

**严重性**: Low | **CWE**: CWE-200 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp:57-58` @ `initializeFileDescription`
**模块**: vstar_great_impl

**描述**: Error messages expose internal state.

**漏洞代码** (`vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp:57-58`)

```c
ASCEND_THROW_IF_NOT_MSG fname
```

**达成路径**

open->throw

**验证说明**: Error message includes filename in exception: 'fname or one of its parent directory is a softlink...'. Path information disclosure in error messages. Path is validated before reaching this point, so disclosure is limited to validated paths.

**评分明细**: base: 30 | controllability: 10 | context: 0 | cross_file: 0 | mitigations: -15 | reachability: 20

---

### [SEC-IVFSP-003] Information Exposure - AscendOperatorManager::init

**严重性**: Low | **CWE**: CWE-200 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ivfsp_utils/src/ascenddaemon/utils/AscendUtils.cpp:88` @ `AscendOperatorManager::init`
**模块**: ivfsp_utils

**描述**: Sensitive path information logged to application log. The model path derived from MX_INDEX_MODELPATH environment variable is logged via APP_LOG_INFO. In production environments, this could expose file system structure information to unauthorized viewers of log files. The path could contain sensitive directory names, usernames, or internal infrastructure details.

**漏洞代码** (`ivfsp_utils/src/ascenddaemon/utils/AscendUtils.cpp:88`)

```c
APP_LOG_INFO("Use env %s as modelpath", path.c_str());
```

**达成路径**

getenv(MX_INDEX_MODELPATH) -> RealPath validation -> APP_LOG_INFO logging

**验证说明**: 日志确实记录了路径信息，但路径已通过RealPath规范化且CheckPathValid限制在/home或/root下。实际泄露的敏感信息有限（文件系统结构片段）。风险较低。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-CROSS-003] Sensitive Information Logging Chain - APP_LOG_INFO, APP_LOG_DEBUG, printf

**严重性**: Low | **CWE**: CWE-538 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `multiple files:1` @ `APP_LOG_INFO, APP_LOG_DEBUG, printf`
**模块**: cross_module
**跨模块**: vstar_great_impl → ivfsp_utils → feature_retrieval → ivfsp_impl

**描述**: [CREDENTIAL_FLOW] 多模块共享日志系统泄露敏感信息：多个模块使用 APP_LOG_* 宏记录路径、环境变量值、设备ID。日志信息流：vstar_great_impl 记录 MX_INDEX_MODELPATH 路径和 MX_INDEX_FINALIZE 值；ivfsp_utils 记录 modelpath 和 finalizeEnv；feature_retrieval 记录 codeBookOutputPath。生产环境日志文件可能暴露敏感配置信息。

**漏洞代码** (`multiple files:1`)

```c
APP_LOG_INFO("Use env %s as modelpath", path.c_str()); APP_LOG_DEBUG("set env ---%s", finalizeEnv); printf("Output codebook dir = %s;", path)
```

**达成路径**

环境变量 → vstar_great_impl(AscendUtils.cpp:88, SocUtils.h:193) → 日志; ivfsp_utils(AscendUtils.cpp:88, SocUtils.h:202) → 日志; feature_retrieval(IVFSPCodeBookTrainer.h:220) → printf

**验证说明**: 跨模块敏感信息日志链验证确认。多模块使用APP_LOG_INFO/APP_LOG_DEBUG/printf记录路径和环境变量值。但日志记录是被动行为，攻击者不能直接控制日志输出，只能通过环境变量间接影响内容。严重性取决于生产环境日志文件保护措施。评分：base30+reachability5+controllability0+mitigations0+context10+cross_file0=45。建议：确认生产环境日志级别配置后决定是否报告

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: 10 | cross_file: 0

---

### [VULN-IVFSP-CBT-004] Integer Overflow - InitCodeBook

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:298-303` @ `InitCodeBook`
**模块**: ivfsp_impl

**描述**: Integer overflow in InitCodeBook array indexing. Multiple multiplications nlist*nonzeroNum, chooseFrom[i]*dim, i*dim could overflow causing incorrect memory access during codebook initialization.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:298-303`)

```c
codeBookBeforeTranspose.resize(static_cast<size_t>(nlist) * nonzeroNum * dim);\nfor (int i = 0; i < nlist * nonzeroNum; ++i) {...}
```

**达成路径**

nlist*nonzeroNum*dim -> resize; chooseFrom[i]*dim -> array access

**验证说明**: Resize protected by static_cast<size_t>. Loop bound nlist*nonzeroNum uses int but typical values (nlist=256, nonzeroNum=64) stay within int range. chooseFrom[i] is size_t from vector sized to nb. Mitigation: vector sizing provides implicit bounds.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

---

### [VULN-VGI-002] Information Exposure - AscendOperatorManager::init

**严重性**: Low | **CWE**: CWE-200 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `vstar_great_impl/mix-index/src/npu/common/utils/AscendUtils.cpp:88` @ `AscendOperatorManager::init`
**模块**: vstar_great_impl

**描述**: Sensitive Path Information Logged: Model path from MX_INDEX_MODELPATH logged at info level.

**漏洞代码** (`vstar_great_impl/mix-index/src/npu/common/utils/AscendUtils.cpp:88`)

```c
APP_LOG_INFO path.c_str()
```

**达成路径**

getenv->APP_LOG_INFO

**验证说明**: Model path is logged at INFO level after validation. CheckPathValid() ensures path is in home directory and readable. Path exposure is limited to validated, user-controlled paths within expected directories. Not a high-risk disclosure.

**评分明细**: base: 30 | controllability: 5 | context: -5 | cross_file: 0 | mitigations: -20 | reachability: 20

---

### [VULN-003-INTOVERFLOW-RAW] Integer Overflow - GetRawDataFromItems

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `vstar_great_impl/DiskIndex/src/Adapter/OpenGaussAdapter.cpp:124-132` @ `GetRawDataFromItems`
**模块**: vstar_great_impl

**描述**: GetRawDataFromItems()函数中第126行计算structSize和指针偏移时存在整数溢出风险。structSize = VECTOR_META_SIZE + sizeof(T) * dim，当dim值较大时可能溢出；循环中items + i * structSize的指针运算可能因溢出导致越界访问。

**达成路径**

dim参数 -> structSize计算 -> items指针偏移 [无溢出检查]

**验证说明**: structSize = VECTOR_META_SIZE + sizeof(T)*dim，dim≤2000，float时structSize最大约8KB。指针偏移items+i*structSize中i≤length≤1e8，乘积约8e11。64位系统无溢出风险。实际风险极低，可能仅DoS。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-IVFSP-CBT-009] Integer Overflow - Transpose

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:539-543` @ `Transpose`
**模块**: ivfsp_impl

**描述**: Integer overflow in Transpose array indexing. Calculations j*srcRow and i*srcCol in array indexing could overflow with large dimensions.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSeriesSDK/IndexSDK/ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:539-543`)

```c
dst[j * srcRow + i] = src[i * srcCol + j];
```

**达成路径**

j*srcRow -> dst offset; i*srcCol -> src offset

**验证说明**: ASCEND_THROW_IF_NOT_FMT validates src.size() == srcRow*srcCol before transpose. This size check prevents overflow for actual data. Offset calculations bounded by validated dimensions.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -20 | context: -15 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cross_module | 0 | 0 | 1 | 1 | 2 |
| feature_retrieval | 0 | 0 | 3 | 1 | 4 |
| feature_retrieval-cpp | 0 | 0 | 1 | 0 | 1 |
| ivfsp_impl | 0 | 2 | 2 | 9 | 13 |
| ivfsp_utils | 0 | 1 | 3 | 1 | 5 |
| vstar_great_impl | 0 | 1 | 5 | 4 | 10 |
| **合计** | **0** | **4** | **15** | **16** | **35** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-190 | 12 | 34.3% |
| CWE-200 | 6 | 17.1% |
| CWE-73 | 4 | 11.4% |
| CWE-367 | 3 | 8.6% |
| CWE-22 | 3 | 8.6% |
| CWE-453 | 2 | 5.7% |
| CWE-680 | 1 | 2.9% |
| CWE-538 | 1 | 2.9% |
| CWE-400 | 1 | 2.9% |
| CWE-20 | 1 | 2.9% |
| CWE-129 | 1 | 2.9% |
