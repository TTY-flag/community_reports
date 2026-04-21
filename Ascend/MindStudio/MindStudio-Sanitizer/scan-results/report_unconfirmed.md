# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-Sanitizer
**扫描时间**: 2026-04-21T10:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

MindStudio-Sanitizer 是华为 Ascend AI 处理器平台的内存安全检测工具，采用 LD_PRELOAD 钩子机制劫持用户算子程序的 Ascend Runtime/ACL/HAL API 调用，通过 Unix Domain Socket 与主进程通信进行内存安全和竞态条件检测。本次扫描覆盖了 150 个源文件，共计约 45000 行代码，重点关注钩子层、核心框架和检测器模块的安全风险。

扫描结果显示共发现 24 个潜在漏洞，经验证后 19 个为有效候选漏洞（排除 5 个误报）。其中 9 个判定为 LIKELY（高置信度），10 个判定为 POSSIBLE（需进一步确认）。所有漏洞均分布在 hooks 模块（11 个）、core_framework 模块（4 个）、race_sanitizer 模块（2 个）等核心组件，主要集中在整数溢出（CWE-190，8 个）和缓冲区溢出（CWE-120，10 个）两类问题。

值得注意的是，本次扫描未发现已确认（CONFIRMED）漏洞。主要原因包括：
1. 部分漏洞存在缓解措施（如底层库的边界检查），降低了实际风险
2. Sanitizer 作为检测工具，其钩子函数主要记录操作而非执行实际内存访问
3. 多数漏洞的攻击路径受信任边界限制（Unix Domain Socket 的 UID/GID 验证）

尽管如此，hooks 模块中多个高置信度漏洞仍需重点关注，特别是用户可控参数缺乏边界验证的场景。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 10 | 41.7% |
| LIKELY | 9 | 37.5% |
| FALSE_POSITIVE | 5 | 20.8% |
| **总计** | **24** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 8 | 42.1% |
| Medium | 11 | 57.9% |
| **有效漏洞总计** | **19** | - |
| 误报 (FALSE_POSITIVE) | 5 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-HOOK-003]** integer_overflow (High) - `csrc/hooks/runtime_hooks.cpp:317` @ `ExtractOpMemInfo` | 置信度: 75
2. **[VULN-DF-ASC-001]** buffer_overflow (High) - `csrc/hooks/ascendc_hooks/ascendc_hooks.cpp:268` @ `ReportSanitizerRecords` | 置信度: 75
3. **[VULN-DF-HOOK-002]** integer_overflow (High) - `csrc/hooks/runtime_hooks.cpp:260` @ `ProduceRtArgsEx` | 置信度: 70
4. **[VULN-DF-HOOK-006]** integer_overflow (High) - `csrc/hooks/hal_hooks/hal_hooks.cpp:133` @ `halMemcpy2D` | 置信度: 70
5. **[VULN-DF-HOOK-008]** integer_overflow (High) - `csrc/hooks/acl_hooks/acl_hooks.cpp:307` @ `sanitizerRtMemcpy2d` | 置信度: 70
6. **[VULN-DF-HOOK-004]** buffer_overflow (High) - `csrc/hooks/runtime_hooks.cpp:805` @ `rtKernelLaunch` | 置信度: 65
7. **[VULN-DF-HOOK-001]** buffer_overflow (High) - `csrc/hooks/runtime_hooks.cpp:646` @ `rtMemcpy` | 置信度: 60
8. **[VULN-DF-HOOK-005]** buffer_overflow (High) - `csrc/hooks/hal_hooks/hal_hooks.cpp:90` @ `drvMemcpy` | 置信度: 60
9. **[VULN-DF-HOOK-007]** buffer_overflow (Medium) - `csrc/hooks/acl_hooks/acl_hooks.cpp:245` @ `sanitizerRtMemcpy` | 置信度: 60
10. **[VULN-DF-CMD-002]** buffer_overflow (Medium) - `csrc/core/framework/command.cpp:237` @ `HandleKernelBlock` | 置信度: 50

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `rtMalloc@csrc/hooks/runtime_hooks.cpp` | rpc | semi_trusted | 用户算子程序通过 LD_PRELOAD 劫持调用此函数，传入 devPtr 和 size 参数，来自用户程序的内存分配请求 | Ascend Runtime 内存分配钩子，接收用户程序的内存分配请求 |
| `rtFree@csrc/hooks/runtime_hooks.cpp` | rpc | semi_trusted | 用户程序传入 devPtr 参数，可能包含恶意或异常地址 | Ascend Runtime 内存释放钩子 |
| `rtMemcpy@csrc/hooks/runtime_hooks.cpp` | rpc | semi_trusted | 用户程序传入 dst、src、cnt 参数，存在缓冲区溢出风险 | Ascend Runtime 内存拷贝钩子，接收源地址、目标地址和大小 |
| `rtKernelLaunch@csrc/hooks/runtime_hooks.cpp` | rpc | semi_trusted | 用户程序传入 stubFunc、args、argsSize 参数，args 缓冲区可能包含恶意数据 | Ascend Runtime 内核启动钩子，接收内核参数 |
| `halMemAlloc@csrc/hooks/hal_hooks/hal_hooks.cpp` | rpc | semi_trusted | HAL 层内存分配，用户程序传入 size 和 flag 参数 | HAL 层内存分配钩子 |
| `drvMemcpy@csrc/hooks/hal_hooks/hal_hooks.cpp` | rpc | semi_trusted | HAL 层内存拷贝，接收 dst、src、byteCount 参数 | HAL 层内存拷贝钩子 |
| `aclrtMalloc@csrc/hooks/acl_hooks/acl_hooks.cpp` | rpc | semi_trusted | ACL API 内存分配，用户程序传入 devPtr 和 size 参数 | ACL 内存分配钩子 |
| `aclrtMemcpy@csrc/hooks/acl_hooks/acl_hooks.cpp` | rpc | semi_trusted | ACL API 内存拷贝，接收 dst、src、count 参数 | ACL 内存拷贝钩子 |
| `KERNEL_LAUNCH_INIT@csrc/hooks/ascendc_hooks/ascendc_hooks.cpp` | rpc | semi_trusted | AscendC 内核初始化，接收 blockDim 参数 | AscendC 内核初始化钩子 |
| `KERNEL_LAUNCH_FINALIZE@csrc/hooks/ascendc_hooks/ascendc_hooks.cpp` | rpc | semi_trusted | AscendC 内核结束，接收 memInfo 和 blockDim 参数，memInfo 来自 Device 内存 | AscendC 内核结束钩子，处理内核执行记录 |
| `main@csrc/core/cli_parser.cpp` | cmdline | trusted_admin | 命令行入口，由管理员/开发者直接执行，参数已做白名单校验 | CLI 工具入口，解析命令行参数 |
| `DomainSocketServer::ListenAndBind@csrc/core/framework/utility/domain_socket.cpp` | rpc | semi_trusted | Unix Domain Socket 服务端，通过 SO_PEERCRED 验证连接进程 UID/GID，仅允许相同用户连接 | Unix Domain Socket 服务端监听 |
| `DomainSocketServer::Read@csrc/core/framework/utility/domain_socket.cpp` | rpc | semi_trusted | 从 Unix Domain Socket 读取数据，数据来自相同用户的子进程 | Unix Domain Socket 数据读取 |
| `MemCheckProtocol::GetPayLoad@csrc/core/framework/protocol.cpp` | rpc | internal | 协议解析内部函数，处理来自钩子进程的数据包 | 协议数据包解析，根据包头类型解包 |

**其他攻击面**:
- LD_PRELOAD 钩子机制: 劫持 Ascend Runtime/ACL/HAL API 调用
- 用户程序传入的内存参数: 地址、大小、拷贝参数
- 内核参数缓冲区: args、argsSize、tilingData
- Unix Domain Socket IPC: 与钩子进程通信（已做 UID/GID 验证）
- 命令行参数: --tool, --log-file, --cache-size 等（已做白名单校验）
- ELF 二进制解析: 用户算子内核二进制加载

---

## 3. Top 5 高置信度漏洞深度分析

### 3.1 [VULN-DF-HOOK-003] ExtractOpMemInfo 输入参数越界 (置信度: 75)

**位置**: `csrc/hooks/runtime_hooks.cpp:317-359`

**漏洞本质**: 该漏洞是典型的"信任外部数据"问题。`sizeInfo->infoAddr` 指针和 `inputNum` 都来自用户程序，代码在循环中直接使用 `inputNum` 进行指针算术运算 `*(buff + 2U + i + inputOffset)`，没有验证 `inputNum` 是否在 `buff` 有效范围内。

**数据流分析**:
```
用户程序 → rtKernelLaunch(args, argsSize) → ExtractOpMemInfo(sizeInfo)
→ inputNum = *(buff + 1) [外部读取]
→ 循环: *(buff + 2 + i + inputOffset) [越界风险]
```

**攻击场景**: 恶意算子程序可构造 `sizeInfo` 结构，将 `inputNum` 设置为超大值（如 UINT64_MAX），导致循环中指针算术运算产生越界读取，可能泄露 Sanitizer 进程内存内容或触发崩溃。

**缓解措施现状**: 无。代码未对 `inputNum` 进行任何上限检查，也未验证 `infoAddr` 指针的有效范围。

**建议修复**:
1. 在循环前添加 `inputNum` 上限检查：`if (inputNum > MAX_INPUT_NUM || inputNum * sizeof(uint64_t) > bufferSize) return error`
2. 验证 `infoAddr` 指针范围：检查其是否属于用户程序的合法地址空间
3. 使用安全的指针访问方式：添加 `if ((buff + offset) >= bufferEnd) break` 边界检查

---

### 3.2 [VULN-DF-ASC-001] ReportSanitizerRecords TOCTOU 越界读取 (置信度: 75)

**位置**: `csrc/hooks/ascendc_hooks/ascendc_hooks.cpp:268-323`

**漏洞本质**: 这是一个经典的 TOCTOU（Time-of-Check to Time-of-Use）漏洞。循环中 `recordOffset` 先增加，然后才执行 `curSize > size` 检查。这意味着在 `ParseRecord(memInfoBlockRecord + recordOffset)` 执行时，`recordOffset` 已经超出安全范围，但检查尚未生效。

**数据流分析**:
```
Device 内存 → memInfoHost → ReportSanitizerRecords(size, recordWriteCount)
→ recordOffset += ParseRecord(...)
→ curSize = sizeof(RecordBlockHead) + recordOffset [此时已越界]
→ if (curSize > size) break [检查延迟]
```

**攻击场景**: Device 内存中的 `recordWriteCount` 和记录数据可被恶意内核程序操控。通过构造大量小记录或单条超大记录，可使得 `recordOffset` 在检查生效前已超出 `size` 边界，读取 Sanitizer 主进程的堆内存内容。

**缓解措施现状**: 存在延迟的边界检查 `curSize > size`，但检查时机在 `ParseRecord` 执行后，无法防止越界读取。

**建议修复**:
1. 在 `ParseRecord` 调用前检查边界：`if (recordOffset + expectedRecordSize > size - sizeof(RecordBlockHead)) break`
2. 添加 `recordWriteCount` 上限检查：与 Device 内存报告的记录数做一致性验证
3. 使用安全的缓冲区读取函数：封装带边界检查的 `SafeParseRecord` 接口

---

### 3.3 [VULN-DF-HOOK-002] ProduceRtArgsEx 整数溢出 (置信度: 70)

**位置**: `csrc/hooks/runtime_hooks.cpp:260-314`

**漏洞本质**: `argsInfo.argsSize` 来自用户程序，代码使用 `argsSize + memInfoS.size()` 计算 vector 大小。当 `argsSize` 被设置为接近 `UINT64_MAX` 的值时，加法溢出导致 vector 分配极小的缓冲区，后续 `std::copy_n` 将读取远超 vector 容量的数据。

**数据流分析**:
```
用户程序 → rtKernelLaunch(args, argsSize) → ProduceRtArgsEx(argsInfo)
→ argsSize (用户可控，可达 UINT64_MAX)
→ vector(argsSize + memInfoS.size()) [溢出，实际分配很小]
→ std::copy_n(args, argsSize, ...) [越界读取]
```

**攻击场景**: 恶意程序将 `argsSize` 设置为 `0xFFFFFFFFFFFFFF00`，加上 `memInfoS.size()`（假设为 256）后溢出为 0，vector 分配 0 字节缓冲区，`copy_n` 尝试读取 `argsSize` 字节导致越界。

**缓解措施现状**: `VerifyArginfo` 检查 `headSize` 但不检查 `argsSize` 上限。C++ vector 在分配失败时会抛出 `std::bad_alloc`，但仍可能导致拒绝服务。

**建议修复**:
1. 添加 `argsSize` 上限检查：`if (argsSize > MAX_ARGS_SIZE || argsSize + memInfoS.size() > MAX_TOTAL_SIZE) return error`
2. 使用安全的加法函数：`SafeAdd(argsSize, memInfoS.size(), &totalSize)` 检测溢出
3. 添加 `args` 指针有效性验证：检查 args 缓冲区是否在用户程序地址空间内

---

### 3.4 [VULN-DF-HOOK-006] halMemcpy2D 地址计算溢出 (置信度: 70)

**位置**: `csrc/hooks/hal_hooks/hal_hooks.cpp:133-172`

**漏洞本质**: 循环中地址计算 `dst + r * dpitch` 使用用户传入的 `height`、`dpitch` 参数。虽然 `height` 有 `MAX_MEMORY_RECORD_HEIGHT` (60GB) 上限检查，但该值过大几乎无实际限制。`r * dpitch` 乘法可能溢出，产生错误的地址偏移。

**数据流分析**:
```
用户程序 → halMemcpy2D(pCopy) → height = pCopy->copy2d.height (用户可控)
→ 循环: dst + r * dpitch [r 最大可达 60GB，dpitch 用户可控]
→ 地址溢出 → ReportStore(错误地址)
```

**攻击场景**: 用户设置 `height = 1000000`，`dpitch = 0xFFFFFFFF`，乘法溢出导致地址计算错误。Sanitizer 可能报告错误的内存地址或访问非法地址。

**缓解措施现状**: `MAX_MEMORY_RECORD_HEIGHT` 检查存在但值过大。底层 `drvMemcpyInner` 执行实际拷贝时有边界检查，但 Sanitizer 的记录操作不受保护。

**建议修复**:
1. 降低 `MAX_MEMORY_RECORD_HEIGHT` 上限：根据实际 NPU 内存容量设置合理值（如 16MB）
2. 添加乘法溢出检查：`if (r * dpitch > UINT64_MAX / 2) break` 或使用 `SafeMul`
3. 验证 `dpitch` 和 `width` 的合理性：`dpitch >= width` 检查

---

### 3.5 [VULN-DF-HOOK-008] sanitizerRtMemcpy2d 地址计算溢出 (置信度: 70)

**位置**: `csrc/hooks/acl_hooks/acl_hooks.cpp:307-344`

**漏洞本质**: 与 VULN-DF-HOOK-006 相同的模式。循环地址计算 `dstAddr + r * dpitch` 和 `srcAddr + r * spitch` 可能因 `height` 和 pitch 参数过大而溢出。

**数据流分析**:
```
用户程序 → sanitizerRtMemcpy2d(height, dpitch, spitch)
→ 循环: dstAddr + r * dpitch [溢出风险]
→ ReportAddrInfo(错误地址)
```

**攻击场景**: 同 VULN-DF-HOOK-006，ACL 层的 2D 内存拷贝钩子同样受用户参数控制。

**缓解措施现状**: `MAX_MEMORY_RECORD_HEIGHT` 检查存在。底层 ACL 库有边界检查，但 Sanitizer 的记录逻辑独立执行。

**建议修复**: 同 VULN-DF-HOOK-006，统一添加 pitch 参数验证和乘法溢出检查。

---

## 4. High 漏洞 (8)

### [VULN-DF-HOOK-003] integer_overflow - ExtractOpMemInfo

**严重性**: High | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/hooks/runtime_hooks.cpp:317-359` @ `ExtractOpMemInfo`
**模块**: hooks

**描述**: sizeInfo->infoAddr 来自用户程序，用于解析内存信息。循环中使用用户控制的 inputNum 进行迭代，可能存在整数溢出或无限循环风险。buff 指针算术运算可能导致越界访问。

**漏洞代码** (`csrc/hooks/runtime_hooks.cpp:317-359`)

```c
uint64_t *buff = static_cast<uint64_t *>(sizeInfo->infoAddr);
for (uint64_t i = 0U; i < opMemInfo.inputNum; ++i) {
    uint64_t primaryPtrNum = *(buff + 2U + i + inputOffset) & 0xffffffffffffff;
}
```

**达成路径**

用户程序 sizeInfo [SOURCE] → ExtractOpMemInfo(infoAddr, inputNum) → buff 指针算术运算 [SINK]

**验证说明**: 真实漏洞：inputNum来自外部数据(buff+1)，没有验证是否在buff有效范围内。循环中使用inputNum进行指针算术运算可能导致越界。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-ASC-001] buffer_overflow - ReportSanitizerRecords

**严重性**: High | **CWE**: CWE-120 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/hooks/ascendc_hooks/ascendc_hooks.cpp:268-323` @ `ReportSanitizerRecords`
**模块**: hooks

**描述**: memInfoHost 来自 Device 内存，size 参数指定缓冲区大小。在循环中 recordOffset 增加后才检查 curSize > size，可能导致在检查之前已经越界读取 memInfoBlockRecord 内容。ParseRecord 操作可能读取超出 size 范围的数据。

**漏洞代码** (`csrc/hooks/ascendc_hooks/ascendc_hooks.cpp:268-323`)

```c
uint8_t *memInfoBlockRecord = memInfoHost + sizeof(RecordBlockHead);
for (uint64_t recordIdx = 0; recordIdx < recordWriteCount; ++recordIdx) {
    RecordType *recordTypePtr = reinterpret_cast<RecordType *>(memInfoBlockRecord + recordOffset);
    uint64_t curSize = sizeof(RecordBlockHead) + recordOffset;
    if (curSize > size) { break; }
}
```

**达成路径**

Device 内存 memInfoHost [SOURCE] → ReportSanitizerRecords(size, recordWriteCount) → memInfoBlockRecord + recordOffset [SINK]

**验证说明**: 真实漏洞：ParseRecord在curSize边界检查之前执行，可能读取超出size范围的memInfoBlockRecord数据。recordOffset增加后才检查边界，存在TOCTOU风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-HOOK-002] integer_overflow - ProduceRtArgsEx

**严重性**: High | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/hooks/runtime_hooks.cpp:260-314` @ `ProduceRtArgsEx`
**模块**: hooks

**描述**: argsInfo.argsSize 参数来自用户程序，用于创建 argsWithMemInfo 缓冲区。argsSize + memInfoS.size() 计算可能溢出，导致缓冲区分配不足。后续 std::copy_n 操作使用溢出后的大小进行拷贝，可能导致内存越界。

**漏洞代码** (`csrc/hooks/runtime_hooks.cpp:260-314`)

```c
argsWithMemInfo = std::vector<uint8_t>(argsInfo.argsSize + memInfoS.size());
std::copy_n(static_cast<uint8_t const*>(args), argsSize, argsWithMemInfo.begin());
```

**达成路径**

用户程序 argsInfo [SOURCE] → ProduceRtArgsEx(argsSize) → argsWithMemInfo vector 创建 → std::copy_n [SINK]

**验证说明**: argsSize+memInfoS.size()可能整数溢出导致vector分配不足。VerifyArginfo检查headSize但不检查argsSize上限。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-HOOK-006] integer_overflow - halMemcpy2D

**严重性**: High | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/hooks/hal_hooks/hal_hooks.cpp:133-172` @ `halMemcpy2D`
**模块**: hooks

**描述**: 用户传入的 pCopy->copy2d.height 用于循环迭代。虽然有 MAX_MEMORY_RECORD_HEIGHT (60*1024^3) 检查，但循环中地址计算 r * dpitch 和 r * spitch 可能存在整数溢出，导致越界地址访问。

**漏洞代码** (`csrc/hooks/hal_hooks/hal_hooks.cpp:133-172`)

```c
for (uint64_t r = 0; r < pCopy->copy2d.height; ++r) {
    ReportAddrInfo addrInfo{dst + r * dpitch, pCopy->copy2d.width, MemInfoSrc::HAL};
}
```

**达成路径**

用户程序 pCopy [SOURCE] → halMemcpy2D(height, dpitch, spitch) → 循环地址计算 dst + r * dpitch [SINK]

**验证说明**: height参数有MAX_MEMORY_RECORD_HEIGHT(60GB)检查但值过大几乎无实际限制。dst+r*dpitch地址计算可能整数溢出导致越界报告。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-HOOK-008] integer_overflow - sanitizerRtMemcpy2d

**严重性**: High | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/hooks/acl_hooks/acl_hooks.cpp:307-344` @ `sanitizerRtMemcpy2d`
**模块**: hooks

**描述**: 用户传入的 height 参数用于循环迭代，循环中地址计算 r * dpitch 和 r * spitch 可能整数溢出。虽然有 MAX_MEMORY_RECORD_HEIGHT 检查，但地址偏移计算仍可能溢出导致越界。

**漏洞代码** (`csrc/hooks/acl_hooks/acl_hooks.cpp:307-344`)

```c
for (uint64_t r = 0; r < height; ++r) {
    ReportAddrInfo addrInfo{dstAddr + r * dpitch, width, ...};
}
```

**达成路径**

用户程序 [SOURCE] → sanitizerRtMemcpy2d(height, dpitch, spitch) → 循环地址计算 [SINK]

**验证说明**: 类似halMemcpy2D，height参数限制过大。dstAddr+r*dpitch地址计算可能溢出。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-HOOK-004] buffer_overflow - rtKernelLaunch

**严重性**: High | **CWE**: CWE-120 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/hooks/runtime_hooks.cpp:805-845` @ `rtKernelLaunch`
**模块**: hooks

**描述**: 用户传入的 args 和 argsSize 参数直接用于创建 argsWithMemInfo 缓冲区并进行拷贝。argsSize 可能被恶意设置为超出实际 args 大小的值，导致 std::copy_n 越界读取。

**漏洞代码** (`csrc/hooks/runtime_hooks.cpp:805-845`)

```c
std::vector<uint8_t> argsWithMemInfo(argsSize + memInfoS.size());
if (args != nullptr) {
    std::copy_n(static_cast<uint8_t const*>(args), argsSize, argsWithMemInfo.begin());
}
```

**达成路径**

用户程序 [SOURCE] → rtKernelLaunch(args, argsSize) → argsWithMemInfo 创建 → std::copy_n [SINK]

**验证说明**: argsSize参数可被设置为极大值(uint32_t最大4GB)，导致vector内存分配问题。C++ vector会抛出异常但仍可能导致拒绝服务。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-HOOK-001] buffer_overflow - rtMemcpy

**严重性**: High | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/hooks/runtime_hooks.cpp:646-668` @ `rtMemcpy`
**模块**: hooks

**描述**: 用户传入的 cnt 参数直接用于内存拷贝操作，没有验证 cnt 是否超过 destMax 缓冲区大小。用户程序通过 LD_PRELOAD 钩子调用此函数，可传入恶意参数导致缓冲区溢出。

**漏洞代码** (`csrc/hooks/runtime_hooks.cpp:646-668`)

```c
RTS_API rtError_t rtMemcpy(void *dst, uint64_t destMax, const void *src, uint64_t cnt, rtMemcpyKind_t kind)
{
    ...
    rtError_t ret = vallina(dst, destMax, src, cnt, kind);
    uint64_t dstAddr = reinterpret_cast<uint64_t>(dst);
    uint64_t srcAddr = reinterpret_cast<uint64_t>(src);
    HookReport::Instance().ReportStore(dstAddr, cnt, MemInfoSrc::RT);
}
```

**达成路径**

用户程序 [SOURCE] → rtMemcpy(cnt参数) → vallina(dst, destMax, src, cnt) [SINK]

**验证说明**: vallina函数执行实际内存拷贝并有内部边界检查(cnt vs destMax)。Sanitizer仅记录操作，不执行实际内存访问。虽然cnt参数可由用户控制，但原始库函数会检查边界。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-HOOK-005] buffer_overflow - drvMemcpy

**严重性**: High | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/hooks/hal_hooks/hal_hooks.cpp:90-109` @ `drvMemcpy`
**模块**: hooks

**描述**: 用户传入的 dst、src、byteCount 参数直接用于内存拷贝操作，没有验证 byteCount 是否超过有效范围。HAL 层钩子接收来自用户算子程序的内存拷贝请求，byteCount 可被恶意设置为超出缓冲区大小的值。

**漏洞代码** (`csrc/hooks/hal_hooks/hal_hooks.cpp:90-109`)

```c
drvError_t drvMemcpy(DVdeviceptr dst, size_t destMax, DVdeviceptr src, size_t byteCount)
{
    drvError_t ret = drvMemcpyInner(dst, destMax, src, byteCount);
    HookReport::Instance().ReportStore(addrInfo); // byteCount 直接使用
}
```

**达成路径**

用户算子程序 [SOURCE] → drvMemcpy(byteCount) → drvMemcpyInner [SINK] → HookReport.ReportStore(byteCount)

**验证说明**: drvMemcpyInner执行实际内存拷贝，有内部边界检查。byteCount参数可控制但HAL库会验证。Sanitizer仅记录操作。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

## 5. Medium 漏洞 (11)

### [VULN-DF-HOOK-007] buffer_overflow - sanitizerRtMemcpy

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/hooks/acl_hooks/acl_hooks.cpp:245-274` @ `sanitizerRtMemcpy`
**模块**: hooks

**描述**: 用户传入的 count 参数直接用于内存拷贝和上报操作。count 可被恶意设置为超出 dst/src 缓冲区大小的值，导致缓冲区溢出或越界访问。

**漏洞代码** (`csrc/hooks/acl_hooks/acl_hooks.cpp:245-274`)

```c
aclError ret = vallina(dst, destMax, src, count, kind);
ReportAddrInfo addrInfo{dstAddr, count, ...};
result &= report.ReportStore(addrInfo);
```

**达成路径**

用户程序 [SOURCE] → sanitizerRtMemcpy(count) → vallina(dst, destMax, src, count) [SINK] → ReportStore(count)

**验证说明**: 类似rtMemcpy，vallina执行实际拷贝有边界检查。count参数用于记录不执行实际内存操作。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-CMD-002] buffer_overflow - HandleKernelBlock

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/core/framework/command.cpp:237-291` @ `HandleKernelBlock`
**模块**: core_framework

**描述**: memInfo 来自 payload.buf，size 来自 payload.len。KernelBlock::CreateKernelBlock 使用这些参数解析内核记录。NextSimd 和 ParseSimtRecord 可能读取超出 size 范围的数据。

**漏洞代码** (`csrc/core/framework/command.cpp:237-291`)

```c
void HandleKernelBlock(Checker &checker, Packet::BinaryPayload const &payload)
{
    auto memInfo = static_cast<uint8_t const *>(static_cast<void const *>(payload.buf));
    auto kernelBlock = KernelBlock::CreateKernelBlock(memInfo, runtimeContext.currentBlockIdx_);
    while (kernelBlock->NextSimd(sanitizerRecord.payload.kernelRecord)) { }
}
```

**达成路径**

钩子进程 payload [SOURCE] → HandleKernelBlock(memInfo) → KernelBlock::CreateKernelBlock → NextSimd [SINK]

**验证说明**: memInfo来自payload，KernelBlock::CreateKernelBlock内部应有边界检查。需进一步验证NextSimd实现。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-RACE-001] integer_overflow - RaceAlgImpl::RaceAlgImpl

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/race_sanitizer/alg_framework/race_alg_impl.cpp:21-32` @ `RaceAlgImpl::RaceAlgImpl`
**模块**: race_sanitizer

**描述**: blockDim 参数来自用户程序的内核启动请求，用于计算 totalBlockNum。totalBlockNum * static_cast<uint8_t>(PipeType::SIZE) 计算可能整数溢出，导致 vc_ 和 eventContainer_ 分配不足。

**漏洞代码** (`csrc/race_sanitizer/alg_framework/race_alg_impl.cpp:21-32`)

```c
uint32_t totalBlockNum = NeedExpandBlockDim(kernelType, deviceType) ? blockDim * C220_MIX_SUB_BLOCKDIM : 1;
vc_.resize(totalBlockNum * static_cast<uint8_t>(PipeType::SIZE));
for (auto &it : vc_) {
    it.resize(totalBlockNum * static_cast<uint8_t>(PipeType::SIZE), 1);
}
```

**达成路径**

用户程序 blockDim [SOURCE] → RaceAlgImpl → totalBlockNum 计算 → vc_.resize [SINK]

**验证说明**: blockDim用于计算totalBlockNum，其他模块有MAX_BLOCKDIM_NUMS(100)检查但此文件未显式检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-ASC-002] integer_overflow - KERNEL_LAUNCH_FINALIZE

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/hooks/ascendc_hooks/ascendc_hooks.cpp:374-427` @ `KERNEL_LAUNCH_FINALIZE`
**模块**: hooks

**描述**: 用户传入的 blockDim 参数用于计算 g_totalBlockDim，进而计算 singleBlockByteSize * g_totalBlockDim。totalByteSize 计算可能整数溢出，导致内存分配不足。后续循环中 memInfo + i * singleBlockByteSize 计算也可能溢出。

**漏洞代码** (`csrc/hooks/ascendc_hooks/ascendc_hooks.cpp:374-427`)

```c
uint64_t singleBlockByteSize = recordGlobalHead.checkParms.cacheSize * MB_TO_BYTES + sizeof(RecordBlockHead);
uint64_t totalByteSize = sizeof(RecordGlobalHead) + singleBlockByteSize * g_totalBlockDim;
memInfo + sizeof(RecordGlobalHead) + i * singleBlockByteSize
```

**达成路径**

用户程序 blockDim [SOURCE] → AssignTotalBlockDim → totalByteSize 计算 [SINK] → rtMemcpy 地址计算

**验证说明**: blockDim有CheckBlockDimValid检查(上限100)和MAX_RECORD_BUF_SIZE限制。i*singleBlockByteSize溢出风险因检查而降低。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-ASC-003] integer_overflow - KERNEL_LAUNCH_INIT

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/hooks/ascendc_hooks/ascendc_hooks.cpp:437-484` @ `KERNEL_LAUNCH_INIT`
**模块**: hooks

**描述**: 用户传入的 blockDim 参数用于计算 g_totalBlockDim 和 totalByteSize。singleBlockByteSize * g_totalBlockDim 可能整数溢出。cacheSize 来自配置但与 blockDim 结合可能导致溢出。

**漏洞代码** (`csrc/hooks/ascendc_hooks/ascendc_hooks.cpp:437-484`)

```c
uint64_t singleBlockByteSize = recordGlobalHead.checkParms.cacheSize * MB_TO_BYTES + sizeof(RecordBlockHead);
uint64_t totalByteSize = sizeof(RecordGlobalHead) + singleBlockByteSize * g_totalBlockDim;
rtError_t error = devMemManager.MallocMemory(memPtr, totalByteSize);
```

**达成路径**

用户程序 blockDim [SOURCE] → CheckBlockDimValid → AssignTotalBlockDim → totalByteSize [SINK] → MallocMemory

**验证说明**: 类似KERNEL_LAUNCH_FINALIZE，有完整的blockDim和size检查。溢出风险因缓解措施降低。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-PROT-001] integer_overflow - MemCheckProtocol::Extractor::Read

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/core/framework/protocol.cpp:78-91` @ `MemCheckProtocol::Extractor::Read`
**模块**: core_framework

**描述**: size 参数来自 Unix Domain Socket 数据包，用于从 bytes_ 中读取数据。offset_ + size 检查存在，但 size 来自外部数据可能被设置为极大值，导致内存分配问题。

**漏洞代码** (`csrc/core/framework/protocol.cpp:78-91`)

```c
bool MemCheckProtocol::Extractor::Read(uint64_t size, std::string &buffer)
{
    if (offset_ + size > bytes_.size()) { return false; }
    buffer = bytes_.substr(offset_, size);
}
```

**达成路径**

Unix Domain Socket 数据 [SOURCE] → Extractor::Read(size) → bytes_.substr(offset_, size) [SINK]

**验证说明**: 有完整的边界检查：offset_+size>bytes_.size()和MAX_STREAM_LEN限制。size来自外部但被验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-DF-PROT-002] buffer_overflow - MemCheckProtocol::GetPayLoad

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/core/framework/protocol.cpp:161-187` @ `MemCheckProtocol::GetPayLoad`
**模块**: core_framework

**描述**: GetPayLoad 处理来自钩子进程的数据包。head.type 来自外部数据，用于 switch 语句选择解包方式。GetBinaryDataPacket 从外部数据读取 size 并创建缓冲区，size 可能被恶意设置。

**漏洞代码** (`csrc/core/framework/protocol.cpp:161-187`)

```c
Packet MemCheckProtocol::GetPayLoad(PacketHead head)
{
    switch (head.type) {
        case PacketType::KERNEL_BINARY:
            return GetBinaryDataPacket<Packet::KernelBinary>();
    }
}
```

**达成路径**

钩子进程数据包 [SOURCE] → GetPayLoad(head.type) → GetBinaryDataPacket(size) [SINK]

**验证说明**: GetBinaryDataPacket读取size创建缓冲区，有MAX_FILE_MAPPING_BUFF_SIZE(1GB)检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-DF-CMD-001] buffer_overflow - HandleKernelBinary

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/core/framework/command.cpp:293-321` @ `HandleKernelBinary`
**模块**: core_framework

**描述**: payload.buf 和 payload.len 来自钩子进程的内核二进制数据。payload.len 直接用于创建 vector<char> 缓冲区。虽然有 MAX_FILE_MAPPING_BUFF_SIZE (1GB) 检查，但 ElfLoader.FromBuffer 可能解析超出范围的数据。

**漏洞代码** (`csrc/core/framework/command.cpp:293-321`)

```c
inline void HandleKernelBinary(Packet::BinaryPayload const &payload)
{
    std::vector<char> buffer(payload.buf, payload.buf + payload.len);
    if (fileMapping.size() >= MAX_FILE_MAPPING_BUFF_SIZE) { return; }
    FileMapping::Instance().Load(fileMapping);
}
```

**达成路径**

钩子进程 payload [SOURCE] → HandleKernelBinary(payload.len) → vector<char> 创建 [SINK] → ElfLoader.Load

**验证说明**: payload.len用于创建vector，有MAX_FILE_MAPPING_BUFF_SIZE(1GB)检查限制。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-DF-SOCK-001] buffer_overflow - DomainSocketServer::Read

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/core/framework/utility/domain_socket.cpp:168-190` @ `DomainSocketServer::Read`
**模块**: utility

**描述**: maxBytes 参数用于创建缓冲区，但实际读取大小由对端控制。read() 返回值 ret 可能小于、等于或大于预期。虽然有 SO_PEERCRED 验证连接进程 UID/GID，但数据内容仍来自外部进程。

**漏洞代码** (`csrc/core/framework/utility/domain_socket.cpp:168-190`)

```c
Result DomainSocketServer::Read(ClientId id, std::string &message, size_t maxBytes, size_t &receivedBytes)
{
    std::vector<char> buffer(maxBytes);
    ssize_t ret = read(cfd, buffer.data(), maxBytes);
    receivedBytes = static_cast<size_t>(ret);
}
```

**达成路径**

Unix Domain Socket [SOURCE] → DomainSocketServer::Read(maxBytes) → read(cfd, buffer, maxBytes) [SINK]

**验证说明**: maxBytes由内部控制，有SO_PEERCRED UID/GID验证连接进程。数据来自相同用户的子进程。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-HEAP-001] use_after_free - HeapBlockManager::FreeHeapBlock

**严重性**: Medium | **CWE**: CWE-416 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/address_sanitizer/heap_block_manager.cpp:173-232` @ `HeapBlockManager::FreeHeapBlock`
**模块**: address_sanitizer

**描述**: FreeHeapBlock 删除 heapBlocks_ 中的条目，但 DeleteMstxInfo 可能遍历已删除条目的关联信息。heapBlocks.erase(it) 后，DeleteMstxInfo 中可能访问已删除的块信息。

**漏洞代码** (`csrc/address_sanitizer/heap_block_manager.cpp:173-232`)

```c
ErrorMsg HeapBlockManager::FreeRtDfxBlock(const MemOpRecord &record, uint64_t &size)
{
    auto it = heapBlocks.find(addr);
    size = it->second.len;
    DeleteMstxInfo(record, size);
    heapBlocks.erase(it);
}
```

**达成路径**

内存释放请求 [SOURCE] → FreeHeapBlock → heapBlocks.find → DeleteMstxInfo → heapBlocks.erase [SINK]

**验证说明**: DeleteMstxInfo在heapBlocks.erase(it)之前调用，使用的是size变量而非heapBlocks迭代器。需进一步验证DeleteMstxInfo实现。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-VECTOR-001] buffer_overflow - VectorClock::UpdateLogicTime

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/race_sanitizer/alg_framework/vector_clock.cpp:22-46` @ `VectorClock::UpdateLogicTime`
**模块**: race_sanitizer

**描述**: VectorTime t 来自事件记录，pipe 参数用于索引 t[pipe]。如果 pipe 参数超出 VectorTime 的实际大小，会导致越界访问。std::min(in.size(), out.size()) 部分缓解了风险。

**漏洞代码** (`csrc/race_sanitizer/alg_framework/vector_clock.cpp:22-46`)

```c
void VectorClock::UpdateLogicTime(VectorTime &t, uint32_t pipe)
{
    t[pipe++];
}
void VectorClock::UpdateVectorTime(const VectorTime &in, VectorTime &out)
{
    auto count = std::min(in.size(), out.size());
    for (uint32_t i = 0; i < count; i++) {
        out[i] = std::max(in[i], out[i]);
    }
}
```

**达成路径**

事件记录 VectorTime [SOURCE] → VectorClock(pipe) → t[pipe++] [SINK]

**验证说明**: pipe参数用于索引t[pipe]，有std::min(in.size(),out.size())检查。UpdateLogicTime中t[pipe++]需验证VectorTime大小。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -15 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| address_sanitizer | 0 | 0 | 1 | 0 | 1 |
| core_framework | 0 | 0 | 4 | 0 | 4 |
| hooks | 0 | 8 | 3 | 0 | 11 |
| race_sanitizer | 0 | 0 | 2 | 0 | 2 |
| utility | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **8** | **11** | **0** | **19** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-120 | 10 | 52.6% |
| CWE-190 | 8 | 42.1% |
| CWE-416 | 1 | 5.3% |

---

## 8. 综合修复建议

### 8.1 高优先级修复项（针对 LIKELY 漏洞）

#### 8.1.1 用户参数边界验证

所有 hooks 模块的钩子函数在处理用户传入参数时，应统一添加边界验证机制：

```c
// 建议：创建参数验证辅助函数
inline bool ValidateUserSize(uint64_t size, uint64_t maxSize) {
    return size > 0 && size <= maxSize && size < UINT64_MAX / 2;
}

// 应用示例：ExtractOpMemInfo
if (!ValidateUserSize(opMemInfo.inputNum, MAX_INPUT_NUM)) {
    return RTS_ERROR_INVALID_PARAM;
}
```

**涉及漏洞**: VULN-DF-HOOK-003, VULN-DF-HOOK-002, VULN-DF-HOOK-004, VULN-DF-HOOK-006, VULN-DF-HOOK-008

#### 8.1.2 安全算术运算

引入安全的整数运算函数，防止溢出：

```c
// 安全加法
inline bool SafeAdd(uint64_t a, uint64_t b, uint64_t *result) {
    if (a > UINT64_MAX - b) return false;
    *result = a + b;
    return true;
}

// 安全乘法
inline bool SafeMul(uint64_t a, uint64_t b, uint64_t *result) {
    if (a > UINT64_MAX / b) return false;
    *result = a * b;
    return true;
}

// 应用示例：ProduceRtArgsEx
uint64_t totalSize;
if (!SafeAdd(argsSize, memInfoS.size(), &totalSize)) {
    return RTS_ERROR_SIZE_OVERFLOW;
}
```

#### 8.1.3 TOCTOU 修复

修复 ReportSanitizerRecords 中的 TOCTOU 问题，将边界检查移至操作前：

```c
// 修复：先检查再操作
for (uint64_t recordIdx = 0; recordIdx < recordWriteCount; ++recordIdx) {
    // 先预估下一条记录大小
    uint64_t nextRecordSize = EstimateRecordSize(memInfoBlockRecord + recordOffset);
    if (sizeof(RecordBlockHead) + recordOffset + nextRecordSize > size) {
        break;  // 检查在 ParseRecord 之前
    }
    recordOffset += ParseRecord(memInfoBlockRecord + recordOffset);
}
```

### 8.2 中优先级修复项（针对 POSSIBLE 漏洞）

#### 8.2.1 强化现有缓解措施

- 将 `MAX_MEMORY_RECORD_HEIGHT` 从 60GB 降低到合理值（建议 16MB）
- 将 `MAX_BLOCKDIM_NUMS` 检查扩展到 race_sanitizer 模块
- 为 `VectorClock::UpdateLogicTime` 添加 `pipe < t.size()` 检查

#### 8.2.2 协议层加固

- 统一所有协议解析函数的边界检查逻辑
- 为 `ElfLoader.FromBuffer` 添加 ELF 头校验和段表边界检查

### 8.3 误报分析（5 个 FALSE_POSITIVE 漏洞）

本次扫描中 5 个漏洞被判定为误报，原因如下：

| 漏洞类型 | 误报原因 |
|---------|---------|
| rtMemcpy 类缓冲区溢出 | Sanitizer 仅记录操作，底层库（vallina）执行实际内存拷贝并有边界检查 |
| drvMemcpy 类缓冲区溢出 | HAL 库 drvMemcpyInner 有内部边界验证，Sanitizer 不执行实际内存访问 |
| DomainSocket 信任问题 | SO_PEERCRED 验证连接进程 UID/GID，仅接受相同用户连接，信任边界合理 |

这些"误报"实际上反映了 Sanitizer 的安全设计：钩子层仅做记录，不执行危险操作。但建议在代码注释中明确说明这一安全模型，避免后续开发者误修改。

### 8.4 长期改进建议

1. **建立安全编码规范**: 为 hooks 模块制定参数验证标准，明确所有用户可控参数的上限
2. **引入静态分析工具**: 将本次发现的漏洞模式集成到 CI/CD 流程中的静态分析规则
3. **安全审计机制**: 每次新增钩子函数前，需通过安全审查确认参数验证完整性
4. **模糊测试**: 对 hooks 模块的入口点开展模糊测试，验证边界检查的有效性

---

## 附录：扫描配置

- **扫描工具**: Multi-Agent C/C++ Vulnerability Scanner
- **扫描模式**: DataFlow Scanner + Security Auditor
- **置信度阈值**: 40/100
- **语言**: C/C++
- **文件范围**: 150 个源文件
- **代码行数**: 约 45000 行