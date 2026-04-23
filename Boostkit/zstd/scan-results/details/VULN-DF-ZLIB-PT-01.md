# VULN-DF-ZLIB-PT-01：路径遍历漏洞分析

## Executive Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-DF-ZLIB-PT-01 |
| **Type** | Path Traversal (CWE-22) |
| **Severity** | High |
| **Source Module** | zlib_wrapper |
| **Affected File** | zlibWrapper/gzlib.c |
| **Affected Lines** | 240 |
| **Function** | gz_open |

---

## 1. Vulnerability Details

### 1.1 Source Code Analysis

**Vulnerable Code (Line 240):**
```c
state.state->fd = fd > -1 ? fd : (
#ifdef WIDECHAR
    fd == -2 ? _wopen(path, oflag, 0666) :
#endif
    open((const char *)path, oflag, 0666));  // ← 直接使用用户提供的 path
```

### 1.2 Vulnerability Mechanism

**No Path Validation:**
- No `realpath()` normalization
- No `O_NOFOLLOW` to prevent symlink following
- No `../` sequence filtering
- Only checks `path == NULL`

**API Entry Points:**
```c
gzFile ZEXPORT gzopen(const char *path, const char *mode) {
    return gz_open(path, -1, mode);  // ← User path passed directly
}

gzFile ZEXPORT gzopen64(const char *path, const char *mode) {
    return gz_open(path, -1, mode);
}
```

---

## 2. Attack Chain Analysis

### Complete Data Flow

```
Phase 1: Malicious Path Input
─────────────────────────────
[Attacker provides path]
   → path = "../../../etc/passwd"
   → 或 path = "/proc/self/root/../etc/shadow"

Phase 2: Path Passed to gzopen
──────────────────────────────
[Application calls gzopen]
   → gzopen(path, "rb")
   → gz_open(path, -1, mode)
   
Phase 3: Direct open() Call
───────────────────────────
[gz_open calls open]
   → open(path, O_RDONLY, 0666)
   → No validation, direct file access
   
Phase 4: Arbitrary File Access
───────────────────────────────
[File opened outside intended directory]
   → Read/write arbitrary files
   → Information disclosure
   → File corruption
```

---

## 3. Exploitability Assessment

### Attack Scenarios

| Scenario | Attack Path | Impact |
|----------|-------------|--------|
| Directory Escape | `../../etc/passwd` | Read sensitive files |
| Absolute Path | `/etc/shadow` | Direct file access |
| Symlink Attack | Symlink to target | Follow symlink, access target |
| Proc Filesystem | `/proc/self/...` | Process info disclosure |

### Real-World Attack Examples

**Example 1: Read Sensitive Files**
```bash
# Application expects files in /data/compressed/
gzopen("../../etc/passwd", "rb")  # Accesses /etc/passwd
```

**Example 2: Symlink Following**
```bash
# Create symlink in allowed directory
ln -s /etc/shadow /data/compressed/link
gzopen("link", "rb")  # Reads /etc/shadow via symlink
```

**Example 3: Absolute Path Bypass**
```bash
# Application restricts to /data/
gzopen("/etc/passwd", "rb")  # Direct absolute path access
```

---

## 4. Security Impact

### Immediate Consequences

| Consequence | Severity |
|-------------|----------|
| Arbitrary File Read | Critical |
| Information Disclosure | High |
| File Corruption | Medium |
| Privilege Escalation | Medium |

### Attack Surface

**Entry Points from project_model.json:**
- `gzread` - trust_level: untrusted_local
- CLI mode or application layer can pass malicious paths

---

## 5. Recommendations

### Immediate Fix

**Add Path Validation:**
```c
// Before calling open()
if (contains_path_traversal(path)) {
    return NULL;  // Reject malicious paths
}

// Or use realpath() + prefix check
char resolved[PATH_MAX];
if (realpath(path, resolved) == NULL) return NULL;
if (!starts_with_prefix(resolved, allowed_prefix)) return NULL;
```

### Alternative Fixes

**Option A: O_NOFOLLOW Flag**
```c
open(path, oflag | O_NOFOLLOW, 0666);  // Prevent symlink following
```

**Option B: Sandbox Path**
```c
// Require paths within allowed directory
if (!path_is_safe(path, allowed_dir)) return NULL;
```

**Option C: Documentation Warning**
```c
/**
 * WARNING: gzopen() accepts any path without validation.
 * Applications MUST validate paths before calling.
 * Reject paths containing "..", absolute paths, or symlinks.
 */
```

---

## 6. Trust Boundary Analysis

**From project_model.json:**
```
Trust Boundary: File System Interface
- Trusted: Application-controlled file paths
- Untrusted: User-provided file paths (CLI mode)
- Risk: Medium
```

**gzread Entry Point:**
``- trust_level: untrusted_local
- Justification: Application may use this interface for user-provided external files

---

*Analysis Date: 2026-04-21*