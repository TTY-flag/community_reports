# VULN-DF-SEEK-IDXMAN-003: Index Manipulation Vulnerability Analysis

## Executive Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-DF-SEEK-IDXMAN-003 |
| **Type** | Index Manipulation (CWE-822) |
| **Severity** | High |
| **Source Module** | contrib_seekable_format |
| **Affected File** | contrib/seekable_format/zstdseek_decompress.c |
| **Affected Lines** | 502-508 |
| **Function** | ZSTD_seekable_decompress |

---

## 1. Vulnerability Details

### 1.1 Source Code Analysis

**Vulnerable Code (Lines 502-508):**
```c
// From database description:
zs->decompressedOffset = zs->seekTable.entries[targetFrame].dOffset;
...
CHECK_IO(zs->src.seek(zs->src.opaque,
                      (long long)zs->seekTable.entries[targetFrame].cOffset,
                      SEEK_SET));  // ← Untrusted cOffset directly used for seek
```

### 1.2 Vulnerability Mechanism

**Untrusted Seek Position:**
- cOffset accumulated from MEM_readLE32 (U32 frame sizes)
- No validation against file bounds
- Attacker can craft arbitrary cOffset values

**Data Flow:**
```
TAINT_SOURCE: MEM_readLE32@cOffset accumulation
    → seekTable.entries[].cOffset
    → src.seek(cOffset) without validation
    → Arbitrary file position access
```

---

## 2. Attack Chain Analysis

### Complete Data Flow

```
Phase 1: Malicious Seek Table
─────────────────────────────
[Attacker crafts seekable file]
   → entries[].cOffset = arbitrary values
   → cOffset > file_size or negative
   → cOffset points to malicious data

Phase 2: Seek Without Validation
────────────────────────────────
[ZSTD_seekable_decompress(frameIndex)]
   → targetFrame = frameIndex
   → cOffset = entries[targetFrame].cOffset
   → src.seek(cOffset) ← No bounds check!
   
Phase 3: Arbitrary File Access
───────────────────────────────
[File seeked to attacker-controlled position]
   → Read from unintended file location
   → May access data outside seekable format
   → Potential information disclosure
```

---

## 3. Exploitability Assessment

### Attack Scenarios

| Scenario | Attack Value | Effect |
|----------|--------------|--------|
| cOffset > file_size | Seek beyond file | Read from memory/hardware |
| Negative cOffset | Seek to start | Access header data |
| Crafted cOffset | Point to malicious data | Trigger decompression bugs |

### Attack Vector

```
Example Attack:
1. Create seekable file with normal frames
2. Craft seek table entry with cOffset = 0x100000000 (large)
3. Application calls ZSTD_seekable_decompress(frameIndex)
4. Seek to position 0x100000000 (beyond file)
5. Read returns garbage or crashes
```

---

## 4. Security Impact

### Immediate Consequences

| Consequence | Severity |
|-------------|----------|
| Arbitrary File Position | High |
| Out-of-Bounds Read | High |
| Information Disclosure | Medium |
| Decompression Corruption | Medium |

---

## 5. Recommendations

### Immediate Fix

**Validate cOffset Against File Size:**
```c
// Before seek operation
if (entries[targetFrame].cOffset > zs->fileSize) {
    return ERROR(corruption_detected);
}
CHECK_IO(zs->src.seek(zs->src.opaque, entries[targetFrame].cOffset, SEEK_SET));
```

### Alternative Fixes

**Validate Frame Boundaries:**
```c
// Ensure cOffset is within valid frame range
U64 totalCompressedSize = entries[tableLen].cOffset;
if (cOffset >= totalCompressedSize) {
    return ERROR(frameIndex_tooLarge);
}
```

---

## 6. Related Vulnerabilities

| Vulnerability | Relationship |
|---------------|--------------|
| VULN-DF-SEEK-TAINT-005 | Same tainted cOffset/dOffset flow |
| VULN-SEEKABLE-001 | Enables via malloc overflow |

---

*Analysis Date: 2026-04-21*