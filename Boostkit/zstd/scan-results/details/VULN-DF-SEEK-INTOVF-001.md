# VULN-DF-SEEK-INTOVF-001：Seek表整数溢出漏洞

## Executive Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-DF-SEEK-INTOVF-001 |
| **Type** | Integer Overflow (CWE-190) |
| **Severity** | High |
| **Source Module** | contrib_seekable_format |
| **Affected File** | contrib/seekable_format/zstdseek_decompress.c |
| **Affected Lines** | 394-398 |
| **Function** | ZSTD_seekable_loadSeekTable |

---

## 1. Vulnerability Details

### 1.1 Source Code Analysis

**Vulnerable Code (Lines 394-398):**
```c
U32 const numFrames = MEM_readLE32(zs->inBuff);     // ← From file, untrusted
U32 const sizePerEntry = 8 + (checksumFlag?4:0);    // ← 8 or 12
U32 const tableSize = sizePerEntry * numFrames;     // ← U32 overflow!
U32 const frameSize = tableSize + ZSTD_seekTableFooterSize + ZSTD_SKIPPABLEHEADERSIZE;
```

### 1.2 Integer Overflow Mechanism

**U32 Multiplication Overflow:**
```
sizePerEntry = 12 (with checksum)
numFrames = 0x20000000 (512M)

tableSize = 12 * 0x20000000 = 0x180000000
  → U32 truncates to 0x80000000 (wraps)
  → Incorrect tableSize used for calculations

frameSize = truncated tableSize + constants
  → Invalid seek position calculated
  → File seeked to wrong location
```

---

## 2. Difference from VULN-SEEKABLE-001

### Comparison

| Aspect | VULN-SEEKABLE-001 | VULN-DF-SEEK-INTOVF-001 |
|--------|-------------------|-------------------------|
| Overflow Point | malloc(sizeof * numFrames) | tableSize = sizePerEntry * numFrames |
| Data Type | size_t multiplication | U32 multiplication |
| Impact | malloc(0), heap corruption | Wrong file seek position |
| Trigger Value | numFrames ≈ 0xFFFFFFFF | numFrames ≈ 0x20000000 |

### Both Share Root Cause

Both stem from missing numFrames validation against MAXFRAMES.

---

## 3. Attack Chain Analysis

### Complete Data Flow

```
Phase 1: Malicious numFrames
────────────────────────────
[Attacker sets numFrames = 0x20000000]
   → sizePerEntry = 12
   → tableSize = 12 * 0x20000000
   → U32 overflow: 0x180000000 → 0x80000000

Phase 2: Incorrect Calculation
───────────────────────────────
[frameSize uses truncated tableSize]
   → frameSize = 0x80000000 + constants
   → Incorrect seek position

Phase 3: Wrong File Position
────────────────────────────
[src.seek with wrong frameSize]
   → Seek to truncated position
   → Read wrong data
   → Decompression corruption
```

---

## 4. Exploitability Assessment

### Overflow Values

| numFrames | sizePerEntry | tableSize (U32) | Effect |
|-----------|--------------|-----------------|--------|
| 0x20000000 | 12 | 0x80000000 | Wraps, wrong seek |
| 0x15555556 | 12 | 0x66666678 | Partial wrap |
| 0xFFFFFFFF | 12 | 0xFFFFFFF4 | Near-max wrap |

### Attack Vector

```
Craft seekable file:
1. numFrames = 0x20000000 (512M)
2. Actual data much smaller
3. Overflow causes wrong frameSize
4. Seek position incorrect
5. Read from wrong file location
```

---

## 5. Security Impact

### Immediate Consequences

| Consequence | Severity |
|-------------|----------|
| Incorrect Seek Position | High |
| File Position Corruption | High |
| Decompression Failure | Medium |
| Data Corruption | Medium |

---

## 6. Recommendations

### Immediate Fix

**Validate numFrames + Use 64-bit:**
```c
if (numFrames > ZSTD_SEEKABLE_MAXFRAMES) {
    return ERROR(frameIndex_tooLarge);
}
U64 const tableSize = (U64)sizePerEntry * numFrames;  // ← Use U64
```

### Alternative: Overflow Detection

```c
U32 const tableSize = sizePerEntry * numFrames;
if (tableSize / sizePerEntry != numFrames) {
    return ERROR(corruption_detected);  // ← Overflow detected
}
```

---

## 7. Related Vulnerabilities

| Vulnerability | Relationship |
|---------------|--------------|
| VULN-SEEKABLE-001 | malloc overflow variant |
| VULN-SEEKABLE-003 | Missing MAXFRAMES validation |

---

*Analysis Date: 2026-04-21*