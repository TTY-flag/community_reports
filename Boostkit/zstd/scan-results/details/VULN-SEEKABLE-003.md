# VULN-SEEKABLE-003: Missing Validation Vulnerability Analysis

## Executive Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-SEEKABLE-003 |
| **Type** | Missing Validation (CWE-129) |
| **Severity** | Medium |
| **Source Module** | contrib_seekable_format |
| **Affected File** | contrib/seekable_format/zstdseek_decompress.c |
| **Affected Lines** | 394-395 |
| **Function** | ZSTD_seekable_loadSeekTable |

---

## 1. Vulnerability Details

### 1.1 Source Code Analysis

**Vulnerable Code (Lines 394-395):**
```c
U32 const numFrames = MEM_readLE32(zs->inBuff);  // ← 直接读取，无上限验证
```

**Expected Validation (Missing):**
```c
// Should check against ZSTD_SEEKABLE_MAXFRAMES
if (numFrames > ZSTD_SEEKABLE_MAXFRAMES) {
    return ERROR(frameIndex_tooLarge);
}
```

### 1.2 MAXFRAMES Definition

**Compression Side Has Check (zstd_seekable.h:16):**
```c
#define ZSTD_SEEKABLE_MAXFRAMES 0x8000000U  // 134,217,728 frames (128M)
```

**Compression Implementation (zstdseek_compress.c:172):**
```c
if (s->numFrames > ZSTD_SEEKABLE_MAXFRAMES) {
    return ERROR(frameIndex_tooLarge);
}
```

**Decompression Missing Check:**
```c
// zstdseek_decompress.c - NO validation of numFrames against MAXFRAMES
```

---

## 2. Relationship to VULN-SEEKABLE-001

### Common Root Cause

Both vulnerabilities stem from the same missing validation:

| Aspect | VULN-SEEKABLE-001 | VULN-SEEKABLE-003 |
|--------|-------------------|-------------------|
| Location | malloc overflow | numFrames untrusted |
| Root Cause | No MAXFRAMES check | No MAXFRAMES check |
| Impact | malloc(0) heap corruption | Enables overflow attacks |

### Attack Chain Enablement

```
VULN-SEEKABLE-003 (Missing Validation)
       ↓ Enables
VULN-SEEKABLE-001 (malloc Overflow)
       ↓ Enables
VULN-DF-SEEK-TAINT-005 (Tainted Data Flow)
```

---

## 3. Security Impact

### Direct Consequences

| Consequence | Severity |
|-------------|----------|
| Large Allocation | Medium - OOM |
| Memory Exhaustion | Medium |
| Enables Overflow Attacks | High |

### Indirect Consequences

This missing validation **enables** other vulnerabilities:
- VULN-SEEKABLE-001: malloc integer overflow
- VULN-DF-SEEK-INTOVF-001: tableSize overflow
- VULN-DF-SEEK-TAINT-005: tainted offset accumulation

---

## 4. Recommendations

### Immediate Fix

**Add MAXFRAMES Validation:**
```c
// zstdseek_decompress.c:394
U32 const numFrames = MEM_readLE32(zs->inBuff);
if (numFrames > ZSTD_SEEKABLE_MAXFRAMES) {
    return ERROR(frameIndex_tooLarge);  // ← 添加上限检查
}
```

### Comprehensive Fix

This fix addresses ALL related vulnerabilities:
- Prevents malloc overflow (VULN-SEEKABLE-001)
- Prevents tableSize overflow (VULN-DF-SEEK-INTOVF-001)
- Validates input before processing

---

## 5. Exploitability

### Exploit Conditions

1. Attacker crafts file with numFrames > MAXFRAMES
2. Application calls ZSTD_seekable_loadSeekTable
3. No validation → overflow attacks enabled

### Attack Value

| numFrames | Effect |
|-----------|--------|
| 0xFFFFFFFF | malloc(0) via overflow |
| 0x20000000 | tableSize U32 overflow |
| > 0x8000000 | Exceeds MAXFRAMES |

---

*Analysis Date: 2026-04-21*
*Related: VULN-SEEKABLE-001, VULN-DF-SEEK-INTOVF-001*