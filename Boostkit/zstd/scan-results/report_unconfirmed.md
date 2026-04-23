# 漏洞扫描报告 — 待确认漏洞

**项目**: zstd
**扫描时间**: 2026-04-21T10:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 27 | 39.7% |
| POSSIBLE | 17 | 25.0% |
| LIKELY | 13 | 19.1% |
| CONFIRMED | 11 | 16.2% |
| **总计** | **68** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 7 | 25.9% |
| Medium | 15 | 55.6% |
| Low | 5 | 18.5% |
| **有效漏洞总计** | **27** | - |
| 误报 (FALSE_POSITIVE) | 27 | - |

### 1.3 Top 10 关键漏洞

1. **[lib_common_entropy_fse_ncount_boundary_001]** Buffer Over-read (High) - `lib/common/entropy_common.c:42` @ `FSE_readNCount_body` | 置信度: 75
2. **[VULN-DF-DECOMP-MEM-001]** Memory Corruption (High) - `lib/decompress/zstd_decompress_block.c:1059` @ `ZSTD_execSequence` | 置信度: 70
3. **[VULN-DF-KERNEL-NV-01]** kernel_memory_corruption (High) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/contrib/linux-kernel/zstd_decompress_module.c:74` @ `zstd_init_dctx` | 置信度: 70
4. **[VULN-DF-KERNEL-NV-02]** kernel_memory_corruption (High) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/contrib/linux-kernel/zstd_compress_module.c:154` @ `zstd_init_cctx` | 置信度: 70
5. **[VULN-DF-KERNEL-NV-03]** kernel_memory_corruption (High) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/contrib/linux-kernel/zstd_decompress_module.c:104` @ `zstd_init_dstream` | 置信度: 70
6. **[VULN-DF-CROSS-001]** memory_corruption (High) - `cross_module/zlib_wrapper_to_lib_decompress:1` @ `gzread_to_ZSTD_decompress` | 置信度: 70
7. **[VULN-zlib_wrapper-001]** Buffer Overflow (High) - `zlibWrapper/gzwrite.c:396` @ `gzvprintf` | 置信度: 65
8. **[VULN-DF-SEEK-MEMDOS-002]** memory_exhaustion (Medium) - `contrib/seekable_format/zstdseek_decompress.c:415` @ `ZSTD_seekable_loadSeekTable` | 置信度: 75
9. **[VULN-DF-COMMON-OOB-002]** out_of_bounds (Medium) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/lib/common/fse.h:540` @ `FSE_decodeSymbol` | 置信度: 70
10. **[VULN-DF-DECOMP-LIT-001]** Memory Corruption (Medium) - `lib/decompress/zstd_decompress_block.c:111` @ `ZSTD_allocateLiteralsBuffer` | 置信度: 65

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@programs/zstdcli.c` | cmdline | untrusted_local | CLI 工具入口，用户可通过命令行参数指定文件路径，本地用户可控制输入文件内容和路径 | 处理命令行参数，读取用户指定的文件进行压缩/解压缩 |
| `ZSTD_decompress@lib/zstd.h` | file | untrusted_network | 核心库 API，接收压缩数据缓冲区。应用场景包括解压缩网络传输数据、文件数据等不可信来源 | 解压缩单个压缩帧，处理用户提供的数据 |
| `ZSTD_decompressStream@lib/decompress/zstd_decompress.c` | file | untrusted_network | 流式解压缩 API，持续接收输入数据。典型场景：网络数据流解压缩、管道输入处理 | 流式解压缩，处理连续输入数据 |
| `ZSTD_isLegacy@lib/legacy/zstd_legacy.h` | file | untrusted_network | 检测并处理旧版本格式的压缩数据。旧格式可能存在未修复的安全问题 | 识别并路由到 legacy 解压缩器 |
| `ZSTDv01_decompress@lib/legacy/zstd_v01.c` | file | untrusted_network | v0.1 版本格式解压缩，处理早期格式数据。旧格式代码可能缺乏现代安全检查 | 解压缩 v0.1 版本格式的数据 |
| `gzread@zlibWrapper/gzread.c` | file | untrusted_local | zlib 兼容层 API，处理 gzip 格式文件。应用可能使用此接口处理用户提供的外部文件 | 读取 gzip 格式文件 |
| `ZSTD_seekable_decompress@contrib/seekable_format/zstdseek_decompress.c` | file | untrusted_network | 可寻址格式解压缩，处理索引帧数据。索引数据可能被恶意构造 | 解压缩可寻址格式的数据帧 |
| `zstd_decompress_module_init@contrib/linux-kernel/zstd_decompress_module.c` | rpc | semi_trusted | 内核模块入口，通过系统调用接口接收数据。需要内核权限触发，但数据来源可能来自用户空间 | Linux 内核模块解压缩接口 |
| `FIO_decompressFilename@programs/fileio.c` | file | untrusted_local | CLI 文件解压缩入口，处理用户指定的文件路径和文件内容 | 解压缩指定文件名 |
| `ZDICT_trainFromBuffer@lib/dictBuilder/zdict.c` | file | untrusted_local | 字典训练 API，从样本数据构建压缩字典。恶意样本可能触发缓冲区问题 | 从缓冲区训练压缩字典 |

**其他攻击面**:
- 压缩数据解析：解压缩模块处理用户/网络提供的压缩数据，可能触发缓冲区溢出、整数溢出、内存破坏
- Legacy 格式支持：旧版本格式（v0.1-v0.7）解压缩可能缺乏现代安全检查
- Huffman/FSE 熵解码：熵解码表可能被恶意构造触发越界访问
- 字典加载：外部字典文件可能被恶意构造
- 文件路径处理：CLI 模式下用户可指定任意文件路径
- 流式解压缩：长时间运行的解压缩流可能触发资源耗尽
- 内核模块接口：Linux 内核模块接收用户空间数据的解压缩请求
- zlib 兼容层：gzread/gzwrite 处理外部文件数据

---

## 3. High 漏洞 (7)

### [lib_common_entropy_fse_ncount_boundary_001] Buffer Over-read - FSE_readNCount_body

**严重性**: High | **CWE**: CWE-125 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `lib/common/entropy_common.c:42-187` @ `FSE_readNCount_body`
**模块**: lib_common

**描述**: FSE_readNCount_body 函数处理 FSE NCount 头解码，边界检查逻辑极其复杂。循环中 ip 指针的移动条件涉及多个不等式判断（ip <= iend-7, ip + bitCount>>3 <= iend-4）。恶意构造的 NCount 头可能触发边界条件组合，导致 MEM_readLE32(ip) 读取超出 hbSize 范围的内存。

**漏洞代码** (`lib/common/entropy_common.c:42-187`)

```c
if (LIKELY(ip <= iend-7) || (ip + (bitCount>>3) <= iend-4)) { ... } bitStream = MEM_readLE32(ip) >> bitCount;
```

**达成路径**

headerBuffer(hbSize) -> ip指针移动(复杂条件) -> MEM_readLE32(可能越界)

**验证说明**: Complex boundary conditions with multiple checks. Line 120: ip<=iend-7 || ip+(bitCount>>3)<=iend-4 ensures MEM_readLE32 reads within bounds. Line 181: charnum>maxSV1 check. Line 182: bitCount>32 check. Edge cases may exist but main protections present. Confidence reduced due to complexity.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-DECOMP-MEM-001] Memory Corruption - ZSTD_execSequence

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-119 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `lib/decompress/zstd_decompress_block.c:1059-1074` @ `ZSTD_execSequence`
**模块**: lib_decompress

**描述**: Match offset beyond prefix/dict validation insufficient. The check sequence.offset > (size_t)(oLitEnd - prefixStart) and subsequent match pointer recalculation (match = dictEnd + (match - prefixStart)) can result in invalid pointer if offset exceeds virtualStart bounds.

**漏洞代码** (`lib/decompress/zstd_decompress_block.c:1059-1074`)

```c
match = dictEnd + (match - prefixStart);
```

**达成路径**

compressed_data→sequence.offset→match pointer calculation→ZSTD_memmove

**验证说明**: Match offset validation exists (RETURN_ERROR_IF at line 1061) but may have edge cases with pointer recalculation. Direct external input reachable, offset fully controllable.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-KERNEL-NV-01] kernel_memory_corruption - zstd_init_dctx

**严重性**: High | **CWE**: CWE-129 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/contrib/linux-kernel/zstd_decompress_module.c:74-79` @ `zstd_init_dctx`
**模块**: contrib_linux_kernel
**跨模块**: contrib_linux_kernel,lib_decompress

**描述**: Missing workspace_size validation in zstd_init_dctx. Function only checks workspace==NULL but does not validate workspace_size bounds before passing to ZSTD_initStaticDCtx. Malicious caller could provide invalid size leading to memory corruption.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/contrib/linux-kernel/zstd_decompress_module.c:74-79`)

```c
if (workspace == NULL) return NULL; return ZSTD_initStaticDCtx(workspace, workspace_size);
```

**达成路径**

[IN] workspace/workspace_size from kernel caller → zstd_init_dctx → ZSTD_initStaticDCtx

**验证说明**: LIKELY: workspace_size验证缺失存在，但有部分内部缓解。lib/decompress/zstd_decompress.c:281-292行显示ZSTD_initStaticDCtx有基本验证: 8字节对齐检查(line 285)，最小大小检查sizeof(ZSTD_DCtx)(line 286)。但无上限验证或完整性检查。内核模块只检查workspace==NULL(line 76-77)，无大小验证。若调用者提供不合理的workspace_size(如超出物理内存或导致内部计算溢出)，可能导致问题。降级到LIKELY因内部有部分缓解。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-KERNEL-NV-02] kernel_memory_corruption - zstd_init_cctx

**严重性**: High | **CWE**: CWE-129 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/contrib/linux-kernel/zstd_compress_module.c:154-160` @ `zstd_init_cctx`
**模块**: contrib_linux_kernel
**跨模块**: contrib_linux_kernel,lib_compress

**描述**: Missing workspace_size validation in zstd_init_cstream. Function only checks workspace==NULL but does not validate workspace_size. Attacker could trigger kernel memory corruption via invalid size.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/contrib/linux-kernel/zstd_compress_module.c:154-160`)

```c
if (workspace == NULL) return NULL; return ZSTD_initStaticCCtx(workspace, workspace_size);
```

**达成路径**

[IN] workspace/workspace_size from kernel caller → zstd_init_cctx → ZSTD_initStaticCCtx

**验证说明**: LIKELY: Compression context workspace_size验证缺失，同NV-01。lib/compress/zstd_compress.c:134-157行显示ZSTD_initStaticCCtx有验证: min size(line 138)，alignment(line 139)，workspace check(line 150)。但内核模块zstd_init_cctx(line 154-159)只检查workspace==NULL。风险相似：不合理size可能导致内部问题。降级到LIKELY因内部有缓解。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-KERNEL-NV-03] kernel_memory_corruption - zstd_init_dstream

**严重性**: High | **CWE**: CWE-129 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/contrib/linux-kernel/zstd_decompress_module.c:104-111` @ `zstd_init_dstream`
**模块**: contrib_linux_kernel
**跨模块**: contrib_linux_kernel,lib_decompress

**描述**: Missing workspace_size validation in zstd_init_dstream. Only checks workspace==NULL, workspace_size flows directly to ZSTD_initStaticDStream without bounds validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/contrib/linux-kernel/zstd_decompress_module.c:104-111`)

```c
if (workspace == NULL) return NULL; return ZSTD_initStaticDStream(workspace, workspace_size);
```

**达成路径**

[IN] workspace/workspace_size → zstd_init_dstream → ZSTD_initStaticDStream

**验证说明**: LIKELY: DStream workspace_size验证缺失。lib/decompress/zstd_decompress.c:1678-1681行显示ZSTD_initStaticDStream仅调用ZSTD_initStaticDCtx，依赖其验证。内核模块zstd_init_dstream(line 104-111)只检查workspace==NULL。风险与NV-01相同。降级到LIKELY因最终调用的ZSTD_initStaticDCtx有部分缓解。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-CROSS-001] memory_corruption - gzread_to_ZSTD_decompress

**严重性**: High | **CWE**: CWE-787 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cross_module/zlib_wrapper_to_lib_decompress:1` @ `gzread_to_ZSTD_decompress`
**模块**: cross_module
**跨模块**: zlib_wrapper → lib_decompress

**描述**: 跨模块数据流攻击链：zlib_wrapper → lib_decompress。用户通过 gzread API 调用 ZSTD_decompress，恶意压缩数据流经 gz_decomp → inflate → ZSTD_decompressStream → ZSTD_execSequence。match 指针计算依赖外部数据，在 zlib 兼容层缺乏额外验证的情况下，可能触发 lib_decompress 中的缓冲区溢出（VULN-DF-DECOMP-MEM-001）。完整攻击路径：用户 gzip 文件 → gzread → ZSTD_decompress → match pointer corruption → 内存破坏。

**达成路径**

[SOURCE] gzread.c:gz_load (read fd) → gz_decomp → ZSTD_decompressStream → ZSTD_execSequence → [SINK] match pointer calculation (VULN-DF-DECOMP-MEM-001)

**验证说明**: 调用链验证通过: gzread → ZSTD_decompressStream → ZSTD_execSequence。zlibWrapper兼容层确实将外部gzip数据路由到lib_decompress。VULN-DF-DECOMP-MEM-001的match pointer漏洞通过跨模块路径可达。cross_file评分: chain_complete=0, has_safety_check=-15 (lib_decompress有部分边界检查)。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-zlib_wrapper-001] Buffer Overflow - gzvprintf

**严重性**: High | **CWE**: CWE-120 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `zlibWrapper/gzwrite.c:396-402` @ `gzvprintf`
**模块**: zlib_wrapper

**描述**: Unbounded sprintf/vsprintf in gzprintf fallback path - when NO_vsnprintf is defined, uses vsprintf/sprintf without buffer size limits, leading to stack buffer overflow.

**漏洞代码** (`zlibWrapper/gzwrite.c:396-402`)

```c
vsprintf(next, format, va); // Line 397 - no bounds check
```

**达成路径**

format string -> vsprintf -> stack buffer overflow

**验证说明**: gzvprintf在NO_vsnprintf编译条件下使用vsprintf，无缓冲区大小限制。溢出发生在vsprintf调用时（行397/401），而行413的检查是溢出后检测而非预防。依赖条件编译配置，仅在缺少vsnprintf的平台触发。gzguts.h定义了多种触发条件（C89、WinCE等）。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: -10 | cross_file: 0

---

## 4. Medium 漏洞 (15)

### [VULN-DF-SEEK-MEMDOS-002] memory_exhaustion - ZSTD_seekable_loadSeekTable

**严重性**: Medium | **CWE**: CWE-789 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `contrib/seekable_format/zstdseek_decompress.c:415-416` @ `ZSTD_seekable_loadSeekTable`
**模块**: contrib_seekable_format

**描述**: Uncontrolled memory allocation based on untrusted numFrames value. No upper bound validation before malloc. Can cause DoS through excessive memory allocation. ZSTD_SEEKABLE_MAXFRAMES (0x8000000U) is defined but not enforced in decompression path.

**漏洞代码** (`contrib/seekable_format/zstdseek_decompress.c:415-416`)

```c
seekEntry_t* const entries = (seekEntry_t*)malloc(sizeof(seekEntry_t) * (numFrames + 1));
```

**达成路径**

TAINT_FLOW: MEM_readLE32@numFrames -> malloc(sizeof(seekEntry_t) * (numFrames + 1))

**验证说明**: Memory exhaustion verified: malloc(sizeof(seekEntry_t)*(numFrames+1)) at line 415. ZSTD_SEEKABLE_MAXFRAMES=0x8000000U (134M frames) not enforced. At numFrames=0x8000000U, allocates ~3GB (24 bytes * 134M). Combined with overflow, may allocate less but still cause DoS. Secondary to primary integer overflow vulnerability.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN-DF-COMMON-OOB-002] out_of_bounds - FSE_decodeSymbol

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/lib/common/fse.h:540-548` @ `FSE_decodeSymbol`
**模块**: lib_common
**跨模块**: lib_common,zstd_decompress

**描述**: Out-of-bounds read in FSE_decodeSymbol: DStatePtr->state used as table index without bounds validation. Corrupted entropy table can cause OOB read.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/lib/common/fse.h:540-548`)

```c
FSE_decode_t const DInfo = ((const FSE_decode_t*)(DStatePtr->table))[DStatePtr->state];
```

**达成路径**

cSrc -> BIT_initDStream -> BIT_readBits -> state -> DStatePtr->table[state]

**验证说明**: Potential OOB read in FSE_decodeSymbol. Line 542: tableDecode[state] where state from BIT_readBits(DTableH.tableLog). If DTable header is corrupted with larger tableLog, state could exceed table bounds. Requires DTable memory corruption prior to decode. Less likely in normal flow where FSE_buildDTable validates tableLog.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: -15 | cross_file: 5

---

### [VULN-DF-DECOMP-LIT-001] Memory Corruption - ZSTD_allocateLiteralsBuffer

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-787 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `lib/decompress/zstd_decompress_block.c:111-122` @ `ZSTD_allocateLiteralsBuffer`
**模块**: lib_decompress

**描述**: Literal buffer split calculation could write beyond dst bounds. The calculation dctx->litBuffer = (BYTE*)dst + expectedWriteSize - litSize + ZSTD_LITBUFFEREXTRASIZE - WILDCOPY_OVERLENGTH could result in pointer outside valid buffer if litSize is malformed.

**漏洞代码** (`lib/decompress/zstd_decompress_block.c:111-122`)

```c
dctx->litBuffer = (BYTE*)dst + expectedWriteSize - litSize + ZSTD_LITBUFFEREXTRASIZE - WILDCOPY_OVERLENGTH;
```

**达成路径**

compressed_header→litSize→litBuffer pointer calculation→ZSTD_memcpy

**验证说明**: Literal buffer split uses complex pointer arithmetic. Only assert-based validation at line 121 which may be disabled in production. ExpectedWriteSize validation upstream.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-DECOMP-FSE-001] Memory Corruption - ZSTD_buildFSETable_body

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-787 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `lib/decompress/zstd_decompress_block.c:484-602` @ `ZSTD_buildFSETable_body`
**模块**: lib_decompress

**描述**: FSE decoding table construction without full validation: ZSTD_buildFSETable builds tables from normalizedCounter read from compressed data. Assertion checks exist but are not runtime validation. Malicious FSE NCount could construct invalid table leading to out-of-bounds decode operations.

**漏洞代码** (`lib/decompress/zstd_decompress_block.c:484-602`)

```c
assert(maxSymbolValue <= MaxSeq); assert(tableLog <= MaxFSELog);
```

**达成路径**

compressed_data→FSE_readNCount→normalizedCounter→ZSTD_buildFSETable

**验证说明**: FSE table construction uses assert-only validation (lines 499-500). Upstream FSE_readNCount has RETURN_ERROR_IF but this function lacks runtime checks.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-DECOMP-BUF-001] Buffer Overflow - ZSTD_execSequence

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `lib/decompress/zstd_decompress_block.c:1015-1022` @ `ZSTD_execSequence`
**模块**: lib_decompress

**描述**: 32-bit pointer overflow in match calculation: match = oLitEnd - sequence.offset. The code comment explicitly notes "risk: address space overflow (32-bits)". Maliciously crafted compressed data with large offset values can cause pointer wraparound, leading to out-of-bounds memory access.

**漏洞代码** (`lib/decompress/zstd_decompress_block.c:1015-1022`)

```c
BYTE* const oMatchEnd = op + sequenceLength;   /* risk : address space overflow (32-bits) */
```

**达成路径**

ZSTD_decompress→ZSTD_decompressBlock→ZSTD_execSequence→match calculation (TAINTED)

**验证说明**: 32-bit overflow explicitly documented in code comment. Complete mitigation exists with MEM_32bits() check at line 1035. Known design limitation with proper protection.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -25 | context: 0 | cross_file: 0

---

### [VULN-zlib_wrapper-002] Buffer Overflow - gzprintf

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `zlibWrapper/gzwrite.c:486-504` @ `gzprintf`
**模块**: zlib_wrapper

**描述**: Unbounded sprintf in gzprintf legacy (non-STDC) path - sprintf with 20 arguments without bounds checking.

**漏洞代码** (`zlibWrapper/gzwrite.c:486-504`)

```c
sprintf(next, format, a1, a2, ..., a20); // Line 493 - 20 args, no bounds
```

**达成路径**

format + 20 args -> sprintf -> overflow

**验证说明**: gzprintf非STDC遗留路径在NO_snprintf条件下使用sprintf，传递20个int参数无大小限制。溢出发生在sprintf调用时（行487/493），行507-509检查是溢出后检测。仅影响缺少snprintf且非STDC的极端遗留环境（行441-526，非STDC非Z_HAVE_STDARG_H）。可控性较低：参数为固定int类型，非指针。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: -10 | cross_file: 0

---

### [VULN-SEEKABLE-004] Integer Overflow - ZSTD_seekable_loadSeekTable

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `contrib/seekable_format/zstdseek_decompress.c:438-441` @ `ZSTD_seekable_loadSeekTable`
**模块**: contrib_seekable_format
**跨模块**: seekable_format,lib_decompress

**描述**: ZSTD_seekable_loadSeekTable() 中累积偏移量可能整数溢出。cOffset 和 dOffset 在循环中累加 MEM_readLE32() 值（第438-441行）。恶意构造的帧大小可导致累积值超过 U64 最大值发生回绕，造成错误的帧定位。入口函数 ZSTD_seekable_decompress 使用这些偏移量进行文件定位和解压缩。

**漏洞代码** (`contrib/seekable_format/zstdseek_decompress.c:438-441`)

```c
cOffset += MEM_readLE32(zs->inBuff + pos); dOffset += MEM_readLE32(zs->inBuff + pos);
```

**达成路径**

frame sizes (from file) -> cumulative sum -> offset wraparound -> wrong seek position

**验证说明**: U64 overflow theoretical but low practical exploitability: cOffset/dOffset accumulate U32 frame sizes as U64. Overflow requires total sizes >2^64 bytes (impossible for real files). May cause incorrect seek positions but no direct memory corruption. Exploit requires crafted frames summing to astronomical total.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-DECOMP-HUF-001] Memory Corruption - HUF_readDTableX1_wksp

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-787 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `lib/decompress/huf_decompress.c:386-520` @ `HUF_readDTableX1_wksp`
**模块**: lib_decompress

**描述**: Huffman DTable construction from untrusted input: HUF_readDTableX1_wksp/HUF_readDTableX2_wksp build decoding tables from compressed data. Maliciously crafted Huffman weights could lead to out-of-bounds table filling. Validation checks exist but edge cases with maxTableLog manipulation may bypass bounds.

**漏洞代码** (`lib/decompress/huf_decompress.c:386-520`)

```c
ZSTD_memcpy(DTable, &dtd, sizeof(dtd)); ... dt[uStart] = D;
```

**达成路径**

compressed_data→HUF_readStats→huffWeight→DTable construction

**验证说明**: Huffman DTable construction has tableLog validation at line 410. HUF_readStats_wksp provides input validation. Multiple bounds checks in table construction loop.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -30 | context: 0 | cross_file: 0

---

### [VULN-SEC-DECOMP-HUF4X-001] Integer Overflow - HUF_DecompressFastArgs_init

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `lib/decompress/huf_decompress.c:224-240` @ `HUF_DecompressFastArgs_init`
**模块**: lib_decompress

**描述**: Jump table length overflow in 4X Huffman decompression: MEM_readLE16 reads stream lengths from jump table. Length4 computed as srcSize - (length1 + length2 + length3 + 6). Malicious stream lengths could cause negative length4 wraparound to large positive bypassing overflow check.

**漏洞代码** (`lib/decompress/huf_decompress.c:224-240`)

```c
size_t const length4 = srcSize - (length1 + length2 + length3 + 6);
```

**达成路径**

compressed_data→jump_table→length1/2/3→length4 calculation

**验证说明**: Jump table overflow check at line 239 (length4 > srcSize) correctly detects overflow. Additional minimum length checks (length < 8) provide comprehensive protection.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -30 | context: 0 | cross_file: 0

---

### [VULN-DF-COMMON-OOB-001] out_of_bounds - FSE_buildDTable_internal

**严重性**: Medium | **CWE**: CWE-119 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/lib/common/fse_decompress.c:67-82` @ `FSE_buildDTable_internal`
**模块**: lib_common
**跨模块**: lib_common,zstd_decompress

**描述**: Out-of-bounds write in FSE_buildDTable_internal: highThreshold decrements without validation that highThreshold stays >= 0. Maliciously crafted normalizedCounter values (-1 entries) can cause highThreshold to become negative.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/lib/common/fse_decompress.c:67-82`)

```c
tableDecode[highThreshold--].symbol = (FSE_FUNCTION_TYPE)s;
```

**达成路径**

cSrc -> FSE_readNCount -> normalizedCounter[s]==-1 -> highThreshold-- -> tableDecode[highThreshold]

**验证说明**: highThreshold decrement at line 82 when normalizedCounter[s]==-1. highThreshold is U32 starting at tableSize-1. If many -1 entries, decrement wraps to large value causing OOB access at tableDecode[highThreshold]. However, FSE_readNCount constrains -1 entries via remaining validation. Edge case possible but constrained.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -10 | context: -5 | cross_file: 5

---

### [VULN-DF-DECOMP-BUF-003] Buffer Overflow - HUF_readDTableX1_wksp

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-120 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `lib/decompress/huf_decompress.c:459-516` @ `HUF_readDTableX1_wksp`
**模块**: lib_decompress

**描述**: Huffman DTable construction with insufficient bounds validation. tableLog derived from compressed header (tainted). While maxTableLog check exists, the table construction loop uses (1 << w) for length calculation which could overflow if w is maliciously large.

**漏洞代码** (`lib/decompress/huf_decompress.c:459-516`)

```c
int const length = (1 << w) >> 1;
```

**达成路径**

compressed_header→tableLog→HUF_readDTableX1_wksp→DTable construction

**验证说明**: DTable construction length calculation (1 << w) >> 1 depends on tableLog which is validated upstream. Edge cases with maxTableLog manipulation may exist.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -25 | context: 0 | cross_file: 0

---

### [VULN-DF-KERNEL-IO-01] integer_overflow - zstd_decompress_dctx

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/contrib/linux-kernel/zstd_decompress_module.c:82-87` @ `zstd_decompress_dctx`
**模块**: contrib_linux_kernel
**跨模块**: contrib_linux_kernel,lib_decompress

**描述**: Potential integer overflow in decompression buffer parameters. src_size and dst_capacity passed directly to ZSTD functions without overflow validation. Large values from user space could cause arithmetic overflow in internal size calculations.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/contrib/linux-kernel/zstd_decompress_module.c:82-87`)

```c
return ZSTD_decompressDCtx(dctx, dst, dst_capacity, src, src_size);
```

**达成路径**

[IN] dst_capacity/src_size from kernel caller → zstd_decompress_dctx → ZSTD_decompressDCtx → internal size calculations

**验证说明**: POSSIBLE: 整数溢出风险理论上存在，但实际触发难度高。size_t在64位内核为64位，溢出需要极端值(接近2^64)。ZSTD内部未发现明确的溢出检查代码，但极端size值会触发其他错误(内存分配失败)。内核模块直接传递参数，无额外验证。降级到POSSIBLE因触发条件苛刻且可能有间接保护(内存限制)。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: -5

---

### [VULN-DF-KERNEL-IO-02] integer_overflow - zstd_decompress_stream

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/contrib/linux-kernel/zstd_decompress_module.c:120-125` @ `zstd_decompress_stream`
**模块**: contrib_linux_kernel
**跨模块**: contrib_linux_kernel,lib_decompress

**描述**: Potential integer overflow in streaming decompression input/output buffer sizes. zstd_decompress_stream receives zstd_in_buffer/zstd_out_buffer with size fields that flow to internal functions without overflow checks.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/zstd/contrib/linux-kernel/zstd_decompress_module.c:120-125`)

```c
return ZSTD_decompressStream(dstream, output, input);
```

**达成路径**

[IN] input.size/output.size from kernel caller → zstd_decompress_stream → ZSTD_decompressStream

**验证说明**: POSSIBLE: Streaming decompression整数溢出风险，同IO-01。zstd_in_buffer/zstd_out_buffer结构体包含size字段，传递给ZSTD_decompressStream。size_t溢出风险相同：需要极端值触发。未发现明确溢出检查。降级到POSSIBLE因触发难度高且有间接保护。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: -5

---

### [VULN-DF-CROSS-005] buffer_overflow - legacy_decompress_chain

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `cross_module/legacy_to_decompress:1` @ `legacy_decompress_chain`
**模块**: cross_module
**跨模块**: lib_legacy → lib_decompress

**描述**: 跨模块数据流攻击链：lib_legacy → lib_decompress。旧版本格式数据通过 ZSTD_isLegacy 被路由到 legacy 解压缩器。v01-v07 版本的 ZSTD_wildcopy 函数可额外复制 7-8 字节（明确标注风险）。旧格式解压后数据可能流入主解压流程。完整路径：旧格式压缩数据 → ZSTD_isLegacy → ZSTDv01-v07_decompress → ZSTD_wildcopy (7-8 byte overflow) → lib_decompress。

**达成路径**

[SOURCE] legacy compressed data → ZSTD_isLegacy → ZSTDv01-v07_decompress → ZSTD_wildcopy → [SINK] 7-8 byte buffer overflow

**验证说明**: wildcopy溢出风险有限: zstd_v01.c:1785使用(oend-8)-op作为长度参数，预留8字节缓冲。代码注释标注address space overflow风险，但实际溢出被部分缓解。legacy格式数据流经ZSTD_isLegacy路由到v01-v07解压器。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: -15 | cross_file: 0

---

### [VULN-DF-DECOMP-DICT-001] Memory Corruption - ZSTD_initDDict_internal

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `lib/decompress/zstd_ddict.c:120-143` @ `ZSTD_initDDict_internal`
**模块**: lib_decompress
**跨模块**: lib_decompress,lib_common

**描述**: External dictionary data processed without complete validation. ZSTD_createDDict accepts arbitrary dictionary buffer which is parsed for entropy tables. Malicious dictionary could corrupt internal state via crafted Huffman/FSE tables.

**漏洞代码** (`lib/decompress/zstd_ddict.c:120-143`)

```c
ZSTD_memcpy(internalBuffer, dict, dictSize);
```

**达成路径**

external_dict→ZSTD_createDDict→ZSTD_memcpy→ZSTD_loadEntropy_intoDDict

**验证说明**: Dictionary loading path has extensive validation in ZSTD_loadDEntropy. Cross-module path verified complete with RETURN_ERROR_IF checks for each entropy table.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -20 | context: 0 | cross_file: -15

---

## 5. Low 漏洞 (5)

### [VULN-DF-DECOMP-INT-001] Integer Overflow - ZSTD_execSequence

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `lib/decompress/zstd_decompress_block.c:1014-1015` @ `ZSTD_execSequence`
**模块**: lib_decompress

**描述**: Integer overflow in sequenceLength calculation: sequence.litLength + sequence.matchLength. Both values derived from compressed data (tainted). While size_t is used, on 32-bit systems overflow can occur leading to undersized buffer allocation.

**漏洞代码** (`lib/decompress/zstd_decompress_block.c:1014-1015`)

```c
size_t const sequenceLength = sequence.litLength + sequence.matchLength;
```

**达成路径**

compressed_data→ZSTD_decodeSequence→sequence.litLength/matchLength→sequenceLength calculation

**验证说明**: Integer overflow in sequenceLength addition. 64-bit systems unlikely to overflow. 32-bit has explicit MEM_32bits() check at line 1035. Mitigated.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -30 | context: 0 | cross_file: 0

---

### [VULN-SEC-DECOMP-BITSTREAM-001] Memory Corruption - HUF_decompress1X1_usingDTable_internal_body

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-125 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `lib/decompress/huf_decompress.c:589-650` @ `HUF_decompress1X1_usingDTable_internal_body`
**模块**: lib_decompress

**描述**: Bitstream read beyond buffer in Huffman decoding: BIT_initDStream and BIT_readBits operations in Huffman and FSE decoding. While bitD.limitPtr tracks buffer end, the bit container refill mechanism may read 8 bytes beyond the nominal end. Maliciously crafted bitstream could exploit this read-ahead behavior.

**漏洞代码** (`lib/decompress/huf_decompress.c:589-650`)

```c
CHECK_F( BIT_initDStream(&bitD, cSrc, cSrcSize) );
```

**达成路径**

compressed_bitstream→BIT_initDStream→read-ahead refill

**验证说明**: Bitstream read-ahead documented. BIT_initDStream provides validation. Read-ahead is limited and within buffer reservation.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -25 | context: 0 | cross_file: 0

---

### [VULN-DF-DECOMP-BUF-002] Buffer Overflow - ZSTD_copyRawBlock

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-120 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `lib/decompress/zstd_decompress.c:896-907` @ `ZSTD_copyRawBlock`
**模块**: lib_decompress

**描述**: Raw block copy without proper bounds validation. srcSize is derived from compressed block header (tainted). While RETURN_ERROR_IF checks srcSize > dstCapacity, the ZSTD_memmove operation could still overflow if srcSize is maliciously large.

**漏洞代码** (`lib/decompress/zstd_decompress.c:896-907`)

```c
ZSTD_memmove(dst, src, srcSize);
```

**达成路径**

compressed_block_header→cBlockSize→srcSize→ZSTD_memmove

**验证说明**: Complete bounds validation: RETURN_ERROR_IF(srcSize > dstCapacity) at line 900 prevents overflow. NULL pointer check at line 901-904. Vulnerability appears mitigated.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -40 | context: 0 | cross_file: 0

---

### [VULN-SEC-DECOMP-REPCODE-001] Memory Corruption - ZSTD_loadDEntropy

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-787 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `lib/decompress/zstd_decompress.c:1526-1534` @ `ZSTD_loadDEntropy`
**模块**: lib_decompress

**描述**: Repcodes validation in dictionary decompression: ZSTD_loadDEntropy reads 3 repcodes from dictionary. Validation checks rep > dictContentSize but rep==0 check may be bypassed. Repcodes used in sequence offset calculation - invalid repcodes could cause negative offsets or out-of-bounds match references.

**漏洞代码** (`lib/decompress/zstd_decompress.c:1526-1534`)

```c
U32 const rep = MEM_readLE32(dictPtr); RETURN_ERROR_IF(rep==0 || rep > dictContentSize, dictionary_corrupted, );
```

**达成路径**

dict_file→repcodes→sequence.offset→match reference

**验证说明**: Repcodes validation complete at lines 1531-1532: RETURN_ERROR_IF(rep==0 || rep > dictContentSize). dictContentSize bounds enforced.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -25 | context: 0 | cross_file: 0

---

### [VULN-SEC-DECOMP-DICT-001] Memory Corruption - ZSTD_loadDEntropy

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-787 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `lib/decompress/zstd_decompress.c:1452-1537` @ `ZSTD_loadDEntropy`
**模块**: lib_decompress
**跨模块**: lib_decompress,zstd_ddict

**描述**: Dictionary entropy table loading from untrusted dictionary file: ZSTD_loadDEntropy reads Huffman and FSE tables from dictionary content. A malicious dictionary could inject corrupted entropy tables that are used during decompression, bypassing frame-level validation. Cross-module: dictionary loaded via zstd_ddict.c affects decompression.

**漏洞代码** (`lib/decompress/zstd_decompress.c:1452-1537`)

```c
HUF_readDTableX2_wksp(entropy->hufTable, dictPtr, dictEnd - dictPtr...)
```

**达成路径**

dict_file→ZSTD_createDDict→ZSTD_loadDEntropy→entropy tables

**验证说明**: Dictionary entropy loading has comprehensive RETURN_ERROR_IF validation chain. Cross-module path verified. Low risk due to multiple validation layers.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -25 | context: 0 | cross_file: -10

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| contrib_linux_kernel | 0 | 3 | 2 | 0 | 5 |
| contrib_seekable_format | 0 | 0 | 2 | 0 | 2 |
| cross_module | 0 | 1 | 1 | 0 | 2 |
| lib_common | 0 | 1 | 2 | 0 | 3 |
| lib_decompress | 0 | 1 | 7 | 5 | 13 |
| zlib_wrapper | 0 | 1 | 1 | 0 | 2 |
| **合计** | **0** | **7** | **15** | **5** | **27** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-787 | 6 | 22.2% |
| CWE-120 | 6 | 22.2% |
| CWE-190 | 5 | 18.5% |
| CWE-129 | 3 | 11.1% |
| CWE-125 | 3 | 11.1% |
| CWE-119 | 2 | 7.4% |
| CWE-789 | 1 | 3.7% |
| CWE-20 | 1 | 3.7% |
