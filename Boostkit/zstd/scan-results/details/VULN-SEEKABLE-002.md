# VULN-SEEKABLE-002: Out-of-Bounds Read Vulnerability Analysis

## Executive Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-SEEKABLE-002 |
| **Type** | Out-of-Bounds Read (CWE-125) |
| **Severity** | High |
| **Source Module** | contrib_seekable_format |
| **Affected File** | contrib/seekable_format/zstdseek_decompress.c |
| **Affected Lines** | 369-371 |
| **Function** | ZSTD_seekTable_getFrameDecompressedSize |

---

## 1. Vulnerability Details

### 1.1 Source Code Analysis

**Vulnerable Code (Lines 369-371):**
```c
size_t ZSTD_seekTable_getFrameDecompressedSize(const ZSTD_seekTable* st, unsigned frameIndex)
{
    if (frameIndex > st->tableLen) return ERROR(frameIndex_tooLarge);  // ← 使用 > 而非 >=
    return st->entries[frameIndex + 1].dOffset -                       // ← entries[frameIndex+1]
           st->entries[frameIndex].dOffset;
}
```

### 1.2 Boundary Check Inconsistency

**Pattern Analysis - Other Functions Use >=:**
```c
// Line 335: ZSTD_seekTable_getFrameCompressedSize
if (frameIndex >= st->tableLen) return ERROR(...);

// Line 346: ZSTD_seekTable_getFrameCompressedOffset
if (frameIndex >= st->tableLen) return ERROR(...);

// Line 357: ZSTD_seekTable_getFrameDecompressedOffset
if (frameIndex >= st->tableLen) return ERROR(...);

// Line 586: ZSTD_seekable_decompress
if (frameIndex >= zs->seekTable.tableLen) return ERROR(...);
```

**Inconsistent Check at Line 369:**
```c
if (frameIndex > st->tableLen)  // ← 使用 > (允许 frameIndex == tableLen)
```

### 1.3 OOB Access Trigger

```
当 frameIndex == tableLen 时：
  
  检查: frameIndex > tableLen → false (检查通过)
  
  访问: entries[frameIndex + 1]
       = entries[tableLen + 1]  ← 越界访问！
       
  entries 数组大小 = numFrames + 1 = tableLen + 1
  有效索引范围: [0, tableLen]
  tableLen + 1 越界！
```

---

## 2. Attack Chain Analysis

### Complete Data Flow

```
Phase 1: Normal Operation
─────────────────────────
[ZSTD_seekable_loadSeekTable completes]
   → entries allocated: malloc(sizeof(seekEntry_t) * (numFrames + 1))
   → tableLen = numFrames
   → 有效 entries: [0..tableLen]

Phase 2: Trigger OOB
────────────────────
[Caller requests last frame size]
   → frameIndex = tableLen (合法值，因为 entries 有 tableLen+1 个)
   
[ZSTD_seekTable_getFrameDecompressedSize]
   → Check: frameIndex > tableLen → false (通过)
   → Access: entries[tableLen + 1].dOffset ← OOB!
   
Phase 3: Memory Corruption
──────────────────────────
[OOB read occurs]
   → Read from heap memory beyond entries[]
   → 可能读取到其他分配的内存内容
   → Info leak, crash, or corruption
```

---

## 3. Exploitability Assessment

### Exploit Conditions

1. Application queries frame size for frameIndex == tableLen
2. entries[] array allocated adjacent to other memory
3. OOB read accesses neighboring heap objects

### Attack Scenarios

| Scenario | Impact |
|----------|--------|
| Query last frame info | OOB read occurs silently |
| Heap layout manipulation | Info leak via OOB read |
| Adjacent object corruption | Memory read corruption |

---

## 4. Security Impact

### Immediate Consequences

| Consequence | Severity |
|-------------|----------|
| Out-of-Bounds Read | High |
| Information Leak | Medium |
| Memory Corruption | Medium |
| Heap Corruption | Medium |

---

## 5. Recommendations

### Immediate Fix

**Change > to >=:**
```c
// zstdseek_decompress.c:369
size_t ZSTD_seekTable_getFrameDecompressedSize(const ZSTD_seekTable* st, unsigned frameIndex)
{
    if (frameIndex >= st->tableLen) return ERROR(frameIndex_tooLarge);  // ← 使用 >=
    return st->entries[frameIndex + 1].dOffset - 
           st->entries[frameIndex].dOffset;
}
```

### Alternative: Special Case Handling

```c
// Handle last frame specially
if (frameIndex >= st->tableLen) return ERROR(frameIndex_tooLarge);
if (frameIndex == st->tableLen - 1) {
    // Last frame: use total size instead of entries[frameIndex+1]
    return st->entries[st->tableLen].dOffset - st->entries[frameIndex].dOffset;
}
```

---

## 6. Pattern Evidence

**Consistent >= Usage in Same File:**

| Line | Function | Check |
|------|----------|-------|
| 335 | getFrameCompressedSize | >= |
| 346 | getFrameCompressedOffset | >= |
| 357 | getFrameDecompressedOffset | >= |
| 369 | getFrameDecompressedSize | > (BUG) |
| 586 | ZSTD_seekable_decompress | >= |

**Conclusion**: Line 369 is an inconsistent boundary check bug.

---

*Analysis Date: 2026-04-21*