# VULN-SEEKABLE-001：整数溢出漏洞分析

## Executive Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-SEEKABLE-001 |
| **Type** | Integer Overflow (CWE-190) |
| **Severity** | High |
| **Source Module** | contrib_seekable_format |
| **Affected File** | contrib/seekable_format/zstdseek_decompress.c |
| **Affected Lines** | 394-416 |
| **Function** | ZSTD_seekable_loadSeekTable |

---

## 1. Vulnerability Details

### 1.1 Source Code Analysis

**Vulnerable Code (Lines 394-416):**
```c
{   U32 const numFrames = MEM_readLE32(zs->inBuff);           // ← 从文件读取，无验证
    U32 const sizePerEntry = 8 + (checksumFlag?4:0);
    U32 const tableSize = sizePerEntry * numFrames;            // ← U32乘法可能溢出
    
    // ...
    
    seekEntry_t* const entries = (seekEntry_t*)malloc(
        sizeof(seekEntry_t) * (numFrames + 1));                // ← malloc溢出风险
```

### 1.2 Vulnerability Mechanism

**Integer Overflow Path:**
```
sizeof(seekEntry_t) = 24 bytes (U64 cOffset + U64 dOffset + U32 checksum + padding)

当 numFrames = 0xFFFFFFFF 时：
  (numFrames + 1) = 0 (U32 overflow)
  malloc(sizeof(seekEntry_t) * 0) = malloc(0) → 返回最小缓冲区

后续 entries[] 数组访问将越界
```

**Compression Side Has Check (zstdseek_compress.c:172):**
```c
#define ZSTD_SEEKABLE_MAXFRAMES 0x8000000U  // 134M frames limit
if (numFrames > ZSTD_SEEKABLE_MAXFRAMES) return ERROR(...);  // ← 压缩端有检查
```

**Decompression Side Lacks Check:**
```c
// zstdseek_decompress.c:394
U32 const numFrames = MEM_readLE32(zs->inBuff);  // ← 直接读取，无上限验证！
```

---

## 2. Attack Chain Analysis

### Complete Data Flow

```
Phase 1: Malicious File Preparation
────────────────────────────────────
[Attacker creates seekable format file]
   → numFrames = 0xFFFFFFFF (恶意值)
   → 构造 seek table footer
   
Phase 2: Decompression Trigger
──────────────────────────────
[ZSTD_seekable_loadSeekTable called]
   → MEM_readLE32 reads numFrames = 0xFFFFFFFF
   → sizeof(seekEntry_t) * (numFrames + 1)
     = 24 * 0 = 0 (U32 overflow)
   → malloc(0) 返回最小分配
   
Phase 3: Buffer Overflow
────────────────────────
[Loop iterates over entries]
   → for (idx < numFrames; idx++)
   → entries[idx] write at idx = 0xFFFFFFFF 越界访问
   → 内存破坏，程序崩溃，或任意写
```

### Attack Vector

| Vector | Risk |
|--------|------|
| Malicious seekable file | High - attacker controls numFrames |
| Network transferred file | Critical - untrusted source |
| File corruption | Medium - accidental trigger |

---

## 3. Exploitability Assessment

### Exploit Conditions

1. Attacker provides malicious seekable format file
2. Application calls ZSTD_seekable_loadSeekTable
3. numFrames value triggers malloc overflow
4. Loop accesses entries[] out-of-bounds

### Attack Scenarios

| Scenario | Impact |
|----------|--------|
| numFrames = 0xFFFFFFFF | malloc(0), heap corruption |
| numFrames = 0x10000000 (268M) | Large allocation, OOM |
| Crafted entries data | Memory corruption, info leak |

---

## 4. Security Impact

### Immediate Consequences

| Consequence | Severity |
|-------------|----------|
| Heap Corruption | Critical |
| Out-of-Bounds Write | Critical |
| Program Crash | High |
| Memory Leak | Medium |
| DoS | High |

---

## 5. Recommendations

### Immediate Fix

**Add MAXFRAMES Validation:**
```c
// zstdseek_decompress.c:394
U32 const numFrames = MEM_readLE32(zs->inBuff);
if (numFrames > ZSTD_SEEKABLE_MAXFRAMES) {
    return ERROR(frameIndex_tooLarge);  // ← 添加上限检查
}
```

### Alternative Fixes

1. Use size_t for allocation calculation
2. Check multiplication overflow before malloc
3. Validate against file size bounds

---

## 6. Related Vulnerabilities

| Vulnerability | Relationship |
|---------------|--------------|
| VULN-SEEKABLE-003 | Same missing validation |
| VULN-DF-SEEK-INTOVF-001 | Different overflow point (tableSize) |
| VULN-DF-CROSS-003 | Cross-module variant |

---

*Analysis Date: 2026-04-21*