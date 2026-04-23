# VULN-DF-SEEK-TAINT-005：污点数据流漏洞分析

## Executive Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-DF-SEEK-TAINT-005 |
| **Type** | Buffer Overflow (CWE-120) |
| **Severity** | High |
| **Source Module** | contrib_seekable_format |
| **Affected File** | contrib/seekable_format/zstdseek_decompress.c |
| **Affected Lines** | 426-448 |
| **Function** | ZSTD_seekable_loadSeekTable |

---

## 1. Vulnerability Details

### 1.1 Source Code Analysis

**Vulnerable Code (Lines 426-448):**
```c
/* compute cumulative positions */
for (; idx < numFrames; idx++) {
    // ...
    entries[idx].cOffset = cOffset;
    entries[idx].dOffset = dOffset;
    
    cOffset += MEM_readLE32(zs->inBuff + pos);  // ← Untrusted 32-bit value
    pos += 4;
    dOffset += MEM_readLE32(zs->inBuff + pos);  // ← Untrusted 32-bit value
    pos += 4;
    // ...
}
entries[numFrames].cOffset = cOffset;
entries[numFrames].dOffset = dOffset;
```

### 1.2 Taint Flow Analysis

**TAINT_SOURCE → TAINT_SINK:**
```
MEM_readLE32(zs->inBuff + pos)
    → cOffset, dOffset accumulation (U64)
    → entries[idx].cOffset, entries[idx].dOffset
    → Used for decompression positioning
    → No sanitization between read and use
```

**Taint Source:**
- Data from seekable format file (untrusted)
- MEM_readLE32 reads U32 frame sizes
- Accumulated into cOffset/dOffset

**Taint Sink:**
- entries[].cOffset used for file seek (line 506-508)
- entries[].dOffset used for decompression boundary
- Direct use without validation

---

## 2. Attack Chain Analysis

### Complete Taint Flow

```
Phase 1: Tainted Input
──────────────────────
[Attacker crafts seekable file]
   → Frame sizes in seek table = malicious values
   → MEM_readLE32 reads attacker-controlled data
   
Phase 2: Accumulation Without Validation
────────────────────────────────────────
[ZSTD_seekable_loadSeekTable loop]
   → cOffset += MEM_readLE32(...)  ← Accumulate tainted values
   → dOffset += MEM_readLE32(...)  ← Accumulate tainted values
   → No overflow check on U64 accumulation
   → entries[idx] populated with tainted offsets
   
Phase 3: Tainted Offsets Used
─────────────────────────────
[Decompression operations]
   → entries[].cOffset → src.seek(position)
   → entries[].dOffset → decompression boundary
   → Attacker controls file position and output size
   → Arbitrary file access, decompression corruption
```

---

## 3. Exploitability Assessment

### Attack Scenarios

| Scenario | Attack Value | Effect |
|----------|--------------|--------|
| Large frame sizes | cOffset/dOffset overflow | Seek beyond file |
| Negative-like values | Accumulation wraps | Invalid boundaries |
| Crafted frame sizes | Specific cOffset/dOffset | Control decompression |

### Manipulation Options

```
Attacker can manipulate:
1. File seek position (via cOffset)
2. Decompression boundaries (via dOffset)
3. Frame checksums (if checksumFlag enabled)

Impact:
- Read from unintended file positions
- Decompression with invalid boundaries
- Output corruption or info leak
```

---

## 4. Security Impact

### Immediate Consequences

| Consequence | Severity |
|-------------|----------|
| Tainted File Seek | High |
| Invalid Decompression Boundary | High |
| Arbitrary Position Access | Medium |
| Decompression Corruption | Medium |

---

## 5. Recommendations

### Immediate Fix

**Validate Accumulated Offsets:**
```c
// During accumulation loop
cOffset += MEM_readLE32(zs->inBuff + pos);
if (cOffset > zs->fileSize) {
    return ERROR(corruption_detected);  // ← Validate cOffset
}
dOffset += MEM_readLE32(zs->inBuff + pos);
// Validate dOffset against expected output size
```

### Alternative: Post-Loop Validation

```c
// After accumulation
for (idx = 0; idx < numFrames; idx++) {
    if (entries[idx].cOffset > totalFileSize) {
        return ERROR(corruption_detected);
    }
}
```

---

## 6. Related Vulnerabilities

| Vulnerability | Relationship |
|---------------|--------------|
| VULN-DF-SEEK-IDXMAN-003 | Same tainted cOffset → seek |
| VULN-SEEKABLE-001 | Enables via malloc overflow |

---

*Analysis Date: 2026-04-21*