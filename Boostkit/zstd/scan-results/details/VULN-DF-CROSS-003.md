# VULN-DF-CROSS-003：跨模块整数溢出攻击链分析

## Executive Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-DF-CROSS-003 |
| **Type** | Integer Overflow (CWE-190) |
| **Severity** | High |
| **Source Module** | cross_module |
| **Attack Chain** | contrib_seekable_format → lib_decompress |
| **Affected Function** | ZSTD_seekable_loadSeekTable_chain |

---

## 1. Vulnerability Details

### 1.1 Cross-Module Attack Chain

**Data Flow Path:**
```
[SOURCE] seekable index file
    → numFrames (untrusted U32)
    → malloc overflow
    → entries[] array (undersized)
    
[SINK] lib_decompress
    → ZSTD_decompress calls
    → Uses malformed index for frame positioning
    → Potential boundary violations
```

### 1.2 Module Interaction

| Module | Role | Vulnerability |
|--------|------|---------------|
| contrib_seekable_format | SOURCE | numFrames unvalidated |
| lib_decompress | SINK | Uses malformed seek table |

**Attack Chain Flow:**
```
Phase 1: Seekable Format Processing
───────────────────────────────────
[ZSTD_seekable_loadSeekTable]
   → numFrames = MEM_readLE32(file)  ← No MAXFRAMES check
   → malloc overflow when numFrames ≈ 0xFFFFFFFF
   → entries[] undersized buffer

Phase 2: Decompression Triggered
────────────────────────────────
[ZSTD_seekable_decompress(frameIndex)]
   → Uses entries[frameIndex] for positioning
   → Malformed entries from undersized buffer
   → ZSTD_decompress with invalid offsets
   
Phase 3: lib_decompress Boundary Issue
───────────────────────────────────────
[ZSTD_decompress or ZSTD_decompressStream]
   → Invalid frame boundaries from seek table
   → Potential buffer over-read
   → Memory corruption in decompression path
```

---

## 2. Attack Chain Analysis

### Complete Cross-Module Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│              CROSS-MODULE ATTACK CHAIN: seekable → decompress        │
└─────────────────────────────────────────────────────────────────────┘

[contrib/seekable_format/zstdseek_decompress.c]
     │
     │ ZSTD_seekable_loadSeekTable()
     │   → numFrames from file (U32, unvalidated)
     │   → malloc(sizeof(seekEntry_t) * (numFrames + 1))
     │   → Overflow when numFrames ≈ 0xFFFFFFFF
     │   → entries[] undersized
     ↓
[Malformed seekTable]
     │ entries[].cOffset = garbage
     │ entries[].dOffset = garbage
     ↓
[ZSTD_seekable_decompress()]
     │ → lookup entries[frameIndex]
     │ → Calculate file position from cOffset
     │ → Invalid seek position
     ↓
[lib/decompress/zstd_decompress.c]
     │
     │ ZSTD_decompress()
     │   → Invalid input buffer boundaries
     │   → Potential over-read
     │   → Memory corruption
     ↓
┌─────────────────────────────────────────────────────────────────────┐
│                       CROSS-MODULE EXPLOITATION                       │
│  • lib_decompress receives malformed input                           │
│  • Boundary checks in decompress may fail                           │
│  • Memory corruption across module boundary                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Exploitability Assessment

### Exploit Conditions

1. Attacker crafts malicious seekable format file
2. numFrames triggers malloc overflow in seekable module
3. entries[] populated with garbage from undersized buffer
4. Decompression module receives invalid frame boundaries

### Cross-Module Attack Scenarios

| Scenario | Effect |
|----------|--------|
| malloc(0) + entries corruption | lib_decompress receives garbage offsets |
| cOffset overflow | Invalid file seek position |
| dOffset overflow | Invalid decompression boundary |

---

## 4. Security Impact

### Cross-Module Consequences

| Module | Impact |
|--------|--------|
| seekable_format | Heap corruption, malformed entries |
| lib_decompress | Invalid boundaries, over-read |

### Attack Propagation

```
seekable_format vulnerability
       ↓ Propagates via entries[]
lib_decompress receives corrupted data
       ↓ Uses corrupted offsets
Memory over-read in decompression
```

---

## 5. Recommendations

### Root Cause Fix

**Add MAXFRAMES Validation in seekable_format:**
```c
// Fixes both this vulnerability and VULN-SEEKABLE-001
if (numFrames > ZSTD_SEEKABLE_MAXFRAMES) {
    return ERROR(frameIndex_tooLarge);
}
```

### Cross-Module Defense

**Validate seek table entries in decompress:**
```c
// lib/decompress should validate frame boundaries
if (cOffset > file_size || dOffset > expected_output_size) {
    return ERROR(corruption_detected);
}
```

---

## 6. Related Vulnerabilities

| Vulnerability | Relationship |
|---------------|--------------|
| VULN-SEEKABLE-001 | Same root cause in seekable_format |
| VULN-SEEKABLE-003 | Missing MAXFRAMES validation |
| VULN-DF-SEEK-TAINT-005 | Tainted data flow |

---

*Analysis Date: 2026-04-21*