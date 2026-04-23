# VULN-DF-KERNEL-UAF-01: Use After Free Vulnerability Analysis

## Executive Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-DF-KERNEL-UAF-01 |
| **Type** | Use After Free (CWE-416) |
| **Severity** | Critical |
| **Source Module** | contrib_linux_kernel |
| **Affected File** | contrib/linux-kernel/zstd_decompress_module.c |
| **Affected Lines** | 59-66 |
| **Function** | zstd_create_ddict_byreference() |
| **Kernel Impact** | Memory corruption, kernel panic, privilege escalation |

---

## 1. Vulnerability Verification

### 1.1 Source Code Analysis

**Vulnerable Function:**
```c
// contrib/linux-kernel/zstd_decompress_module.c:59-66
zstd_ddict *zstd_create_ddict_byreference(const void *dict, size_t dict_size,
                          zstd_custom_mem custom_mem)
{
    return ZSTD_createDDict_advanced(dict, dict_size, ZSTD_dlm_byRef,
                     ZSTD_dct_auto, custom_mem);
}
EXPORT_SYMBOL(zstd_create_ddict_byreference);
```

**Critical Observations:**
- Uses `ZSTD_dlm_byRef` mode which stores only a pointer reference
- Dictionary content is NOT copied into DDict structure
- Function exported via `EXPORT_SYMBOL` to all kernel modules
- No lifetime validation or ownership tracking

### 1.2 Internal Implementation

**DDict Structure (lib/decompress/zstd_ddict.c):**
```c
struct ZSTD_DDict_s {
    void* dictBuffer;           // NULL in byRef mode (no ownership)
    const void* dictContent;    // Direct pointer to external dict
    size_t dictContentSize;
    ZSTD_entropyTables_t entropy;
    ...
};
```

**Initialization Logic (lib/decompress/zstd_ddict.c:125-136):**
```c
if (dictLoadMethod == ZSTD_dlm_byRef) {
    ddict->dictBuffer = NULL;            // ← No ownership
    ddict->dictContent = dict;           // ← Direct pointer reference!
} else {
    ddict->dictBuffer = ZSTD_malloc(dictSize);
    ddict->dictContent = ddict->dictBuffer;
    ZSTD_memcpy(ddict->dictBuffer, dict, dictSize);  // ← Copy mode
}
```

**Vendor Warning (lib/decompress/zstd_ddict.c:179):**
```
Warning: dictBuffer must outlive DDict (DDict must be freed before dictBuffer)
```

---

## 2. Attack Chain Analysis

### Complete Data Flow

```
Phase 1: Setup
─────────────
[Kernel Caller] allocates dict_buffer (kmalloc)
   → dict_buffer = kzalloc(dict_size, GFP_KERNEL);

[Caller creates DDict by reference]
   → ddict = zstd_create_ddict_byreference(dict_buffer, dict_size, ...);
   → DDict->dictContent = dict_buffer (pointer stored, NO copy)
   → DDict does NOT own dict_buffer memory

Phase 2: Trigger (Premature Free)
─────────────────────────────────
[Caller frees dictionary buffer - MISTAKE!]
   → kfree(dict_buffer);
   → Memory returned to slab allocator
   → DDict still holds stale pointer!

Phase 3: Exploitation
─────────────────────
[Decompression request]
   → ZSTD_decompress_usingDDict(dctx, dst, cap, src, size, ddict);
   → ZSTD_copyDDictParameters(dctx, ddict):
      → dctx->prefixStart = ddict->dictContent;  // ← STALE POINTER
      → dctx->virtualStart = ddict->dictContent;
      → dctx->dictEnd = dictContent + dictSize;

[Block decompression]
   → ZSTD_execSequence():
      → match = dictEnd - (prefixStart - match);  // ← Calculate position
      → ZSTD_memmove(oLitEnd, match, matchLength);  // ← UAF READ!
      → Reads from freed kernel memory
```

### UAF Trigger Points

| Location | Code | Action |
|----------|------|--------|
| zstd_ddict.c:125-136 | dictContent = dict | Store stale pointer |
| zstd_ddict.c:50-60 | ZSTD_copyDDictParameters | Copy stale ptr to DCtx |
| zstd_decompress_block.c:937-951 | ZSTD_execSequence | Read from freed memory |

---

## 3. Exploitability Assessment

### Attack Scenarios

| Scenario | Feasibility | Impact |
|----------|-------------|--------|
| Accidental caller bug | High | Kernel panic, memory corruption |
| Malicious kernel module | Medium | Privilege escalation |
| Slab spray attack | Low-Medium | Info leak, controlled corruption |
| Race condition | Medium | DoS, instability |

### Required Conditions

1. Caller uses `zstd_create_ddict_byreference()` (not copy variant)
2. Caller frees dictionary buffer before decompression completes
3. Decompression initiated after buffer is freed
4. Timing window exists between free and decompress

### Exploitation Techniques

**Technique 1: Slab Object Replacement**
- Free dictionary buffer (specific size)
- Spray slab with controlled objects
- Trigger decompression → reads from replaced objects
- Potential: info leak, address disclosure

**Technique 2: Dictionary Poisoning**
- Create DDict with known content
- Free and reallocate with attacker-controlled data
- Decompression uses poisoned dictionary
- Potential: corrupt match finding, create malformed output

---

## 4. Security Impact

### Immediate Consequences

| Consequence | Severity | Description |
|-------------|----------|-------------|
| Kernel Panic | Critical | Invalid memory access crashes kernel |
| Memory Corruption | High | Hash tables/match state corrupted |
| Info Leak | Medium | Slab object contents read during decompression |
| DoS | High | System crash prevents operation |

### Potential Privilege Escalation Path

1. Load malicious kernel module or exploit vulnerable module
2. Allocate dictionary buffer from specific slab cache
3. Create DDict by reference, then free buffer
4. Spray slab with target kernel objects (struct cred, file_operations)
5. Trigger decompression → reads from sprayed objects
6. Analyze corrupted hash tables for leaked addresses
7. Bypass KASLR, construct ROP chain
8. Achieve root privileges

---

## 5. Recommendations

### Immediate Remediation

**Option A: Remove Export (Recommended)**
```c
// Remove EXPORT_SYMBOL for byRef variant
// Only export safe byCopy variant
zstd_ddict *zstd_create_ddict(const void *dict, size_t dict_size,
                               zstd_custom_mem custom_mem)
{
    return ZSTD_createDDict_advanced(dict, dict_size, 
                                      ZSTD_dlm_byCopy,  // ← Force copy
                                      ZSTD_dct_auto, custom_mem);
}
EXPORT_SYMBOL(zstd_create_ddict);
```

**Option B: Add Lifetime Validation**
```c
// Require callers to provide refcount
zstd_ddict *zstd_create_ddict_byreference_safe(
    const void *dict, size_t dict_size,
    struct kref *dict_refcount,  // NEW: caller refcount
    zstd_custom_mem custom_mem);
```

**Option C: Enhanced Documentation**
```c
/**
 * WARNING: This function creates a dictionary that REFERENCES the provided
 * buffer WITHOUT copying it. The caller MUST ensure:
 * 1. Dictionary buffer remains valid and unchanged
 * 2. Buffer NOT freed until after zstd_free_ddict() is called
 * 3. No concurrent modifications during any decompression
 *
 * FAILURE TO OBSERVE THESE REQUIREMENTS WILL CAUSE KERNEL MEMORY CORRUPTION.
 * Prefer zstd_create_ddict() for safer usage.
 */
```

### Long-Term Improvements

1. Audit all kernel callers of zstd dictionary APIs
2. Add memory ownership tracking in module
3. Implement automatic copying for kernel API
4. Add KASAN assertions in debug builds
5. Deprecate byRef mode for kernel exports

---

## 6. Related Vulnerability

**VULN-DF-KERNEL-UAF-02** (Compression Dictionary byRef) shares the same design flaw pattern. Both should be remediated together:

| Aspect | UAF-01 (Decompression) | UAF-02 (Compression) |
|--------|------------------------|----------------------|
| Function | zstd_create_ddict_byreference | zstd_create_cdict_byreference |
| UAF Trigger | Decompression block processing | Compression hash table building |
| Root Cause | Same - byRef mode without lifetime enforcement | Same |

---

## 7. Conclusion

**Status: CONFIRMED**

The `zstd_create_ddict_byreference()` function creates a Use After Free vulnerability:

1. **Design Flaw**: byRef mode avoids copying for performance, creates lifetime dependency
2. **No Validation**: No tracking of dictionary buffer ownership
3. **Direct Export**: Available to potentially untrusted kernel callers
4. **Active Usage**: Dictionary pointer directly accessed during decompression

**Recommended Action**: Remove EXPORT_SYMBOL or add comprehensive lifetime validation.

---

*Analysis Date: 2026-04-21*
*Related: VULN-DF-KERNEL-UAF-02*