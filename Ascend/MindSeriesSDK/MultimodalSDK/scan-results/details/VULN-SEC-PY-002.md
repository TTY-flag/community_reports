# VULN-SEC-PY-002: Path Traversal Vulnerability in Image.open()

## Vulnerability Summary

| Attribute | Value |
|-----------|-------|
| **CWE ID** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| **Severity** | Medium (mitigated) |
| **Trust Level** | untrusted_local |
| **Affected Module** | py_bindings (Python-C++ bindings) |
| **Primary Location** | `AccSDK/source/py/module/PyImage.cpp:153` |
| **Secondary Locations** | `AccSDK/source/image/Image.cpp:180`, `AccSDK/source/utils/ImageUtils.cpp:61` |

## Vulnerability Description

The `Image.open()` static method accepts a user-provided file path and passes it through the Python-C++ binding layer to the underlying C++ image loading code without proper path canonicalization. While the implementation includes several security checks (symlink blocking, file ownership verification, permission checks), the lack of full path canonicalization using `realpath()` or `std::filesystem::canonical()` leaves potential attack vectors open.

## Call Chain Analysis

```
Python Layer                      C++ Binding Layer                    Core C++ Layer
─────────────────────────────────────────────────────────────────────────────────────────
image_wrapper.py:35               PyImage.cpp:153                      Image.cpp:180
Image.open(path)            →     Image::open(path)              →    Image::Image(path)
     │                                  │                                 │
     │ _ensure_bytes(path)              │ PyAcc::Image(path)               │ ReadJpegData()
     │ (NULL check only)                │ (direct passthrough)             │     │
     │                                  │                                  │     ▼
     └──────────────────────────────────┴──────────────────────────────────┴─→ FileUtils.cpp
                                                                          IsFileValid()
```

### Layer 1: Python Wrapper (`image_wrapper.py:35-51`)

```python
@classmethod
def open(cls, path: str | bytes, device: str | bytes = b"cpu") -> "Image":
    path_bytes = _ensure_bytes(path, "path")  # Only converts to bytes, checks NULL
    device_bytes = _ensure_bytes(device, "device")
    acc_img = _acc.Image.open(path_bytes, device_bytes)  # Directly passes to C++
```

**Security Control**: `_ensure_bytes()` only:
- Converts string to bytes
- Rejects NULL bytes (`\x00`)
- Does NOT sanitize `../` sequences or validate path structure

### Layer 2: PyBind C++ Binding (`PyImage.cpp:153-156`)

```cpp
Image Image::open(const std::string& path, const std::string& device)
{
    return PyAcc::Image(path.c_str(), device.c_str());  // Direct passthrough, no validation
}
```

**Security Control**: None - path passed directly to constructor.

### Layer 3: C++ Image Constructor (`Image.cpp:180-201`)

```cpp
Image::Image(const char* path, const char* device)
{
    CheckDeviceFromConstructor(device);
    auto decodeRet = ReadJpegData(path, imData, imWidth, imHeight, ptr);  // File read
    // ...
}
```

**Security Control**: Device validation only; path is passed to file reading function.

### Layer 4: JPEG Data Reader (`ImageUtils.cpp:61-75`)

```cpp
ErrorCode ReadJpegData(const char* path, ...) {
    if (!IsFileValid(path)) {  // Validation happens here
        return ERR_INVALID_PARAM;
    }
    // Extension check
    if (!CheckFileExtension(path, "jpg") && !CheckFileExtension(path, "jpeg")) {
        return ERR_INVALID_PARAM;
    }
    ErrorCode ret = ReadFile(path, rawData, IMAGE_MAX_FILE_SIZE);
    // ...
}
```

### Layer 5: File Validation (`FileUtils.cpp:203-223`)

```cpp
bool IsFileValid(const char* path) {
    std::string pathStr(path);
    if (!CheckFilePath(pathStr)) return false;    // Symlink & existence check
    if (!CheckFileOwner(pathStr)) return false;   // Owner must match process UID
    if (!CheckFilePermission(pathStr, FILE_MODE)) return false;  // Permission <= 0640
    return true;
}
```

## Security Controls Present

The code implements several security checks that partially mitigate the vulnerability:

### 1. Symlink Detection (`FileUtils.cpp:148-151`)

```cpp
bool CheckFilePath(const std::string& path) {
    fs::path pathObj = fs::absolute(path);
    // ...
    if (fs::is_symlink(pathObj)) {  // Blocks if final path component is symlink
        LogError << "Check file path failed. The file is a symlink.";
        return false;
    }
    // ...
}
```

**Effectiveness**: Blocks direct symlinks, but does not detect symlinks in parent directories.

### 2. File Ownership Verification (`FileUtils.cpp:160-176`)

```cpp
bool CheckFileOwner(const std::string& path) {
    struct stat fileStat;
    stat(path.c_str(), &fileStat);
    uid_t currentUid = getuid();
    if (fileStat.st_uid != currentUid) {  // Only owner can access
        return false;
    }
    return true;
}
```

**Effectiveness**: Strong mitigation - limits access to files owned by the process user.

### 3. Permission Verification (`FileUtils.cpp:178-201`)

```cpp
bool CheckFilePermission(const std::string& path, const mode_t mode) {
    // Ensures file permissions don't exceed 0640
    // ...
}
```

**Effectiveness**: Prevents access to overly permissive files.

## Remaining Vulnerabilities

Despite the mitigations, the following attack vectors remain:

### 1. Missing Path Canonicalization

The code uses `fs::absolute(path)` which does NOT:
- Resolve `..` path components against the actual filesystem
- Follow and resolve symlinks in intermediate path components
- Call `realpath()` or `canonical()` for full path resolution

**Vulnerable Code** (`FileUtils.cpp:141`):
```cpp
fs::path pathObj = fs::absolute(path);  // Should be fs::canonical(path)
```

**Impact**: Path traversal sequences may not be properly resolved in all scenarios.

### 2. TOCTOU Race Condition

The checks are performed sequentially without atomicity:
1. Check if symlink
2. Check file owner
3. Check permissions
4. Open file

A race condition could allow an attacker to replace a valid file with a symlink between checks.

### 3. Intermediate Symlink Bypass

```cpp
// Only checks final component
if (fs::is_symlink(pathObj)) { ... }
```

An attacker could create a path like:
- `/home/user/attacker_dir/image.jpg` where `attacker_dir` is a symlink to another directory

The final file `image.jpg` would pass the symlink check even though a parent directory is a symlink.

## Proof of Concept

### Scenario 1: Path Traversal (Limited by ownership check)

```python
from mm.acc.wrapper.image_wrapper import Image

# Attempt to read system file - BLOCKED by CheckFileOwner
# (file must be owned by current user)
img = Image.open("../../../etc/passwd")  # Will fail - not owned by user
```

### Scenario 2: Intermediate Symlink (Potentially exploitable)

```bash
# Attacker creates directory structure
mkdir -p /home/user/images
ln -s /home/user/other_location /home/user/images/link_dir
# Place an image owned by user in other_location
cp my_image.jpg /home/user/other_location/
```

```python
# This may bypass symlink detection if only final component is checked
img = Image.open("/home/user/images/link_dir/my_image.jpg")
```

## Impact Assessment

| Factor | Assessment |
|--------|-------------|
| **Attack Complexity** | Medium - requires understanding of filesystem and race conditions |
| **Privileges Required** | Low - local access to Python runtime |
| **User Interaction** | None |
| **Scope** | Limited by ownership checks - can only access user-owned files |
| **Confidentiality Impact** | Low to Medium - limited to user-owned files |
| **Integrity Impact** | None - read-only operation |
| **Availability Impact** | Low - could cause DoS with malformed paths |

**Overall Severity**: Medium (reduced from High due to mitigating controls)

## Recommendations

### Immediate (High Priority)

1. **Use `fs::canonical()` for path resolution**:

```cpp
// In FileUtils.cpp
bool CheckFilePath(const std::string& path) {
    std::error_code ec;
    fs::path canonicalPath = fs::canonical(path, ec);  // Fully resolves path
    if (ec) {
        LogError << "Path canonicalization failed";
        return false;
    }
    // Use canonicalPath for all subsequent checks
    // ...
}
```

2. **Implement base directory whitelist**:

```cpp
bool IsPathWithinAllowedDirectory(const fs::path& path) {
    static const std::vector<fs::path> allowedDirs = {
        fs::canonical("/home/user/images"),
        fs::canonical("/var/data/images"),
        // ...
    };
    fs::path canonicalPath = fs::canonical(path);
    for (const auto& allowedDir : allowedDirs) {
        if (canonicalPath.string().find(allowedDir.string()) == 0) {
            return true;
        }
    }
    return false;
}
```

### Short-term (Medium Priority)

3. **Add TOCTOU protection** using file descriptor-based operations:

```cpp
// Open file first, then validate using the file descriptor
int fd = open(path, O_RDONLY | O_NOFOLLOW);
if (fd < 0) return false;
struct stat st;
fstat(fd, &st);  // Use fd to prevent race condition
// Validate using st
```

4. **Check all path components for symlinks**:

```cpp
bool HasSymlinkInPath(const fs::path& path) {
    fs::path current;
    for (const auto& component : path) {
        current /= component;
        if (fs::is_symlink(current)) {
            return true;
        }
    }
    return false;
}
```

### Long-term (Low Priority)

5. **Add Python-level path validation**:

```python
# In image_wrapper.py
import os
from pathlib import Path

@classmethod
def open(cls, path: str | bytes, device: str | bytes = b"cpu") -> "Image":
    path_str = path if isinstance(path, str) else path.decode('utf-8')
    
    # Resolve and validate path
    try:
        resolved_path = Path(path_str).resolve(strict=True)
        # Optionally check against allowed base directories
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid or unsafe path: {e}")
    
    # Continue with resolved_path
```

## Related Vulnerabilities

- **VULN-SEC-PY-001**: Path traversal in `Image::Image` constructor (PyImage.cpp:54) - same vulnerability in different function
- **VULN-SEC-PY-003**: Path traversal in `video_decode` (PyVideo.cpp:30) - similar pattern in video module

## References

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [C++ std::filesystem::canonical](https://en.cppreference.com/w/cpp/filesystem/canonical)

## Appendix: File References

| File | Lines | Purpose |
|------|-------|---------|
| `AccSDK/source/py/module/PyImage.cpp` | 153-156 | PyBind binding layer |
| `AccSDK/source/py/module/PyImage.cpp` | 54-65 | PyBind constructor |
| `AccSDK/source/image/Image.cpp` | 180-201 | Core image loading |
| `AccSDK/source/utils/ImageUtils.cpp` | 61-119 | JPEG file reading |
| `AccSDK/source/utils/FileUtils.cpp` | 203-223 | File validation |
| `AccSDK/source/utils/FileUtils.cpp` | 128-158 | Path checking |
| `AccSDK/source/utils/FileUtils.cpp` | 160-176 | Ownership checking |
| `MultimodalSDK/source/mm/acc/wrapper/image_wrapper.py` | 35-51 | Python entry point |
| `MultimodalSDK/source/mm/acc/wrapper/util.py` | 20-31 | Bytes conversion |
