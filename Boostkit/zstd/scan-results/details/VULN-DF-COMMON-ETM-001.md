# VULN-DF-COMMON-ETM-001: Entropy Table Manipulation Vulnerability Analysis

## Executive Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-DF-COMMON-ETM-001 |
| **Type** | Buffer Overflow (CWE-119) |
| **Severity** | High |
| **Source Module** | lib_common |
| **Affected File** | lib/common/entropy_common.c |
| **Affected Lines** | 88-154 |
| **Function** | FSE_readNCount_body |

---

## 1. Vulnerability Details

### 1.1 Source Code Analysis

**Vulnerable Code (Lines 88-154):**
```c
// Repeat code parsing - charnum can increment rapidly
int repeats = ZSTD_countTrailingZeros32(~bitStream | 0x80000000) >> 1;
while (repeats >= 12) {
    charnum += 3 * 12;  // ← Rapid increment
    // ...
}
charnum += 3 * repeats;

// Main loop - write BEFORE check
normalizedCounter[charnum++] = (short)count;  // ← Line 154: Write BEFORE bounds check

// Bounds check AFTER write
if (charnum >= maxSV1) break;  // ← Line 167: Check AFTER write
```

### 1.2 Vulnerability Mechanism

**Write-Before-Check Pattern:**
```
Line 154: normalizedCounter[charnum++] = count  ← WRITE
Line 167: if (charnum >= maxSV1) break          ← CHECK (after write)

如果 charnum == maxSV1:
  → Write at normalizedCounter[maxSV1] ← OOB (one past boundary)
  → Then check catches it, but damage done
```

**Previous0 Branch Has Check Before:**
```c
// Line 114 - Check BEFORE returning to main loop
if (charnum >= maxSV1) break;  // ← Previous0 branch is safe
```

**Main Loop Writes Before Checking:**
```c
// Main loop lacks pre-write check
normalizedCounter[charnum++] = count;  // ← Write
// ...
if (charnum >= maxSV1) break;         // ← Check AFTER
```

---

## 2. Attack Chain Analysis

### Complete Data Flow

```
Phase 1: Malicious FSE Header
─────────────────────────────
[Attacker crafts compressed data]
   → FSE NCount header with repeat codes
   → Trigger rapid charnum increment
   → charnum reaches maxSV1 before check

Phase 2: OOB Write
──────────────────
[FSE_readNCount_body processes header]
   → Repeat parsing: charnum += 3 * repeats
   → Main loop iteration
   → normalizedCounter[charnum++] = count  ← Write at maxSV1
   → OOB access before check catches it
   
Phase 3: Memory Corruption
──────────────────────────
[One-off OOB write]
   → Write past normalizedCounter[maxSVPtr] boundary
   → Heap corruption
   → May corrupt adjacent allocation
```

---

## 3. Exploitability Assessment

### Exploit Conditions

1. Attacker provides malicious compressed data
2. FSE NCount header crafted with specific repeat codes
3. charnum reaches maxSV1 at exact iteration
4. Write occurs at index maxSV1 (OOB)

### Attack Vector

```
Crafted NCount Header:
1. Set maxSV1 = 256 (normalizedCounter size)
2. Use repeat codes to increment charnum to 255
3. Next iteration: charnum = 256
4. Write at normalizedCounter[256] ← OOB!
5. Heap memory corrupted
```

---

## 4. Security Impact

### Immediate Consequences

| Consequence | Severity |
|-------------|----------|
| Buffer Overflow | High |
| Heap Corruption | High |
| Memory Write OOB | High |
| Decompression Failure | Medium |

### Cross-Module Impact

```
lib_common (entropy_common.c)
       ↓ Overflow
normalizedCounter[maxSV1] OOB write
       ↓ Affects
lib_decompress (uses FSE tables)
       ↓ Corruption
Decompression may use corrupted tables
```

---

## 5. Recommendations

### Immediate Fix

**Move Check Before Write:**
```c
// Line 154 area - check BEFORE write
if (charnum >= maxSV1) break;  // ← Move check here
normalizedCounter[charnum++] = (short)count;
```

### Alternative Fix

**Add Pre-Loop Check:**
```c
// Before entering main loop after previous0 branch
if (charnum >= maxSV1) {
    return ERROR(corruption_detected);
}
normalizedCounter[charnum++] = count;
```

---

## 6. Technical Evidence

**Inconsistent Check Pattern:**
- Previous0 branch (line 114): Check BEFORE break
- Main loop (line 167): Check AFTER write
- Bug: Main loop should have check before write

---

*Analysis Date: 2026-04-21*