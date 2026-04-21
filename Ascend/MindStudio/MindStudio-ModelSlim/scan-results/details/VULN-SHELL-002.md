# VULN-SHELL-002: Arbitrary File Write via log_file Parameter

## Executive Summary

**Status**: CONFIRMED (Limited Exploitability)  
**Severity**: High (Technical Impact) / Medium (Practical Exploitability)  
**CWE**: CWE-22 (Path Traversal)  
**Confidence**: 80/100  

AsyncProcess.__init__ 直接打开 `log_file` 参数写入文件，没有路径验证。虽然上游调用链对 `save_path` 有字符白名单和权限检查，但**未显式阻止写入系统敏感文件**。攻击可行性受限于严格的权限验证机制。

---

## 1. Attack Chain Analysis

### Complete Data Flow Path

```
User Input (save_path)
    ↓
AutoTuningApplication.run() [application.py:88]
    ↓ convert_to_writable_dir()
get_write_directory() [path.py:177]
    ↓ get_valid_path()
Path Validation [path.py:60-92]
    ↓ Returns realpath
EvaluateContext.working_dir [application.py:211]
    ↓
service_oriented_evaluate_service.py:83
    ↓ context.working_dir / "vllm_server.log"
VllmAscendServer.__init__ [vllm_ascend_server.py:114]
    ↓ log_file=str(self.log_file)
AsyncProcess.__init__ [shell.py:277]
    ↓ NO VALIDATION
open(log_file, 'w')  ← VULNERABLE POINT
```

### Critical Code Snippets

**Vulnerable Code (shell.py:277)**:
```python
def __init__(self, binary: str, log_file: str, ...):
    self.log_file = open(log_file, 'w')  # No path validation!
```

**User-Controlled Input (application.py:88)**:
```python
save_path = convert_to_writable_dir(save_path, param_name="save_path")
```

**Fixed Path Concatenation (service_oriented_evaluate_service.py:83)**:
```python
log_file_path=context.working_dir / "vllm_server.log"
```

---

## 2. Path Validation Mechanism Analysis

### get_valid_path() Implementation (path.py:60-92)

**Security Controls Present**:
1. **Character whitelist**: `[_A-Za-z0-9/.-]` (Line 65)
   - Allows `/`, `.`, `-` (including `..` sequence!)
2. **Soft link prohibition**: Rejects symbolic links (Line 69)
3. **Realpath resolution**: `os.path.realpath()` resolves `..` (Line 73)
4. **Permission checks** (in get_valid_write_path(), Line 196-204):
   - File must belong to current user (`st_uid == os.getuid()`)
   - Others must not be writable (`stat.S_IWOTH` prohibited)
   - Current user must have write permission (`os.W_OK`)

**Gaps in Validation**:
- ❌ **No explicit path traversal check**: Allows `/etc/passwd`, `/root/.ssh/authorized_keys`
- ❌ **No directory confinement**: User can write to any location meeting permission criteria
- ❌ **No sensitive file blacklist**: Can overwrite system configuration files
- ⚠️ **Character whitelist allows `/`**: Enables absolute paths

### Attack Vector Example

```python
# User-provided save_path = "/etc/cron.d/"
# get_valid_path() validation:
# 1. Character check: PASS (only /, -, letters)
# 2. Soft link check: PASS (not a symlink)
# 3. Permission check: FAIL if not root (st_uid != os.getuid())

# If run as root:
# final log_file = "/etc/cron.d/vllm_server.log"
# AsyncProcess.__init__ → open("/etc/cron.d/vllm_server.log", 'w')
# Result: Arbitrary file write to cron directory!
```

---

## 3. PoC Feasibility Assessment

### Attack Requirements

| Condition | Required | Practical Difficulty |
|-----------|----------|---------------------|
| Root/high privilege execution | HIGH risk scenarios | Medium |
| Target file exists | Yes (for overwrite) | Easy |
| File owned by current user | Yes (st_uid check) | Context-dependent |
| Others not writable permission | Yes (st_mode check) | Easy (most system files) |
| Current user has write permission | Yes (os.W_OK check) | Easy for owned files |

### Realistic Attack Scenarios

#### Scenario A: Root Execution (HIGH Severity)

**Attack Steps**:
1. Attacker controls `save_path` parameter (via CLI/API)
2. Set `save_path = "/etc/cron.d/"`
3. Application creates `EvaluateContext.working_dir = "/etc/cron.d"`
4. Log file: `/etc/cron.d/vllm_server.log`
5. **AsyncProcess opens file in 'w' mode** → Creates/overwrites file
6. vLLM server logs written to cron file → Contains attacker-controlled content

**PoC Code**:
```python
# Malicious invocation
AutoTuningApplication.run(
    model_type="llama",
    model_path="/models/llama",
    save_path="/etc/cron.d/",  # Attack vector
    plan_id="default"
)

# Result: Logs written to /etc/cron.d/vllm_server.log
# Cron daemon reads *.log files? → Need cron.d/*.conf naming
# But attacker can use: save_path="/var/spool/cron/crontabs/"
```

**Limitation**: Cron requires specific filename patterns. More viable targets:
- `/root/.ssh/authorized_keys` → SSH key injection
- `/etc/sudoers.d/user` → Sudo privilege escalation
- `/home/user/.bashrc` → Shell command injection

#### Scenario B: Normal User Execution (MEDIUM Severity)

**Attack Steps**:
1. User runs application with normal privileges
2. Attacker controls `save_path = "/home/user/.ssh/"`
3. Log file: `/home/user/.ssh/vllm_server.log`
4. Overwrites SSH configuration (if file exists)
5. Less severe than root case, but still enables user-level persistence

**Feasibility**: **MEDIUM** - Requires file to exist, belong to user, meet permission criteria

#### Scenario C: Web Service/API Exposure (HIGH Severity if exists)

**Attack Steps**:
1. If application exposes tuning API endpoint
2. Attacker sends request with malicious `save_path`
3. Backend validates characters/permissions
4. If running as privileged service → writes to system files

**Feasibility**: **DEPENDS ON DEPLOYMENT** - Unknown without architecture review

---

## 4. Impact Range Analysis

### Critical Target Files (Root Execution)

| File | Impact | Feasibility |
|------|--------|-------------|
| `/etc/cron.d/vllm_server.log` | Arbitrary cron job execution | Medium (cron naming restrictions) |
| `/root/.ssh/authorized_keys` | SSH persistence | High (standard SSH config) |
| `/etc/sudoers.d/vllm` | Sudo privilege escalation | High (sudoers.d mechanism) |
| `/var/spool/cron/crontabs/root` | Root cron execution | High (direct crontab) |
| `/etc/systemd/system/vllm.service` | systemd service creation | High (if directory writable) |

### User-Level Target Files

| File | Impact | Feasibility |
|------|--------|-------------|
| `/home/user/.bashrc` | Shell persistence | High (user-owned) |
| `/home/user/.ssh/authorized_keys` | User SSH access | High |
| `/home/user/.config/autostart/script.desktop` | GUI autostart | High |

---

## 5. Mitigation Measures Effectiveness

### Existing Mitigation: shell=False

**Analysis** (shell.py:289):
```python
popen_kwargs = {
    'args': self.cmd,
    'shell': False,  # Mitigation for command injection
    'stdout': self.log_file,
    ...
}
```

**Effectiveness**:
- ✅ **Effective against CWE-78 (Command Injection)**: Prevents shell metacharacter interpretation
- ❌ **NOT effective against CWE-22 (Path Traversal)**: `shell=False` only affects command execution, not file path validation
- ❌ **Does not protect log_file parameter**: File write vulnerability remains

**Conclusion**: shell=False is a **different mitigation** for a different vulnerability class. It does not address arbitrary file write.

### Path Validation Mitigation

**Analysis** (path.py:196-204):
```python
# Permission checks in get_valid_write_path()
if check_user_stat and os.stat(real_path).st_uid != os.getuid():
    raise SecurityError("The file {} doesn't belong to the current user.")
if check_user_stat and os.stat(real_path).st_mode & WRITE_FILE_NOT_PERMITTED_STAT > 0:
    raise SecurityError("The file permission for others is not 0.")
if not os.access(real_path, os.W_OK):
    raise SecurityError("The file {} exist and not writable.")
```

**Effectiveness**:
- ✅ **Prevents writing to unowned files**: Stops `/etc/passwd` write by normal user
- ⚠️ **Allows writing to owned sensitive files**: Can still write `/root/.ssh/authorized_keys` if running as root
- ❌ **Missing downstream validation**: AsyncProcess.__init__ bypasses these checks entirely
- ❌ **No directory confinement**: User can specify any valid directory

---

## 6. Vulnerability Classification

| Dimension | Assessment |
|-----------|------------|
| **Type** | Arbitrary File Write (CWE-22) |
| **Attack Vector** | Local (save_path parameter) / Network (if API exposed) |
| **Attack Complexity** | Low (direct parameter control) |
| **Privileges Required** | None (user execution) / High (root for system files) |
| **User Interaction** | None |
| **Scope** | Changed (can affect other files beyond intended log) |
| **Impact** | High (file integrity), Medium (depends on deployment) |

### CVSS 3.1 Estimate

**Base Score**: 5.5-7.5 (depending on deployment context)

- **AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N** → 5.5 (Local attack, user privileges)
- **AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N** → 7.5 (Network attack, requires high privileges)

---

## 7. Remediation Recommendations

### Primary Fix (AsyncProcess.__init__)

```python
# Current vulnerable code:
def __init__(self, binary: str, log_file: str, ...):
    self.log_file = open(log_file, 'w')  # No validation!

# Recommended fix:
from msmodelslim.utils.security.path import get_valid_write_path

def __init__(self, binary: str, log_file: str, ...):
    # Validate log_file path with security checks
    validated_log_file = get_valid_write_path(
        log_file, 
        extensions="log",
        check_user_stat=True,
        warn_exists=True
    )
    self.log_file = open(validated_log_file, 'w')
```

### Secondary Fix (Directory Confinement)

```python
# Restrict logs to safe directory
import os
from pathlib import Path

def __init__(self, binary: str, log_file: str, ...):
    # Extract only filename, force safe base directory
    filename = os.path.basename(log_file)
    safe_log_dir = Path("/var/log/msmodelslim/")  # Or configurable safe dir
    safe_log_file = safe_log_dir / filename
    
    # Ensure filename doesn't contain traversal
    if ".." in filename or filename.startswith("/"):
        raise SecurityError("Invalid log filename")
    
    self.log_file = open(safe_log_file, 'w')
```

### Alternative Fix (Upstream Validation)

Modify `VllmAscendServer.__init__` to validate log_file:

```python
# vllm_ascend_server.py
from msmodelslim.utils.security.path import get_valid_write_path

def __init__(self, context, server_config, model_path, log_file_path):
    # Validate log file path before passing to AsyncProcess
    validated_log = get_valid_write_path(str(log_file_path), extensions="log")
    self.log_file = Path(validated_log)
```

---

## 8. Testing Recommendations

### Security Test Cases

1. **Path traversal test**:
   ```python
   save_path = "/etc/passwd/../root/.ssh/authorized_keys"
   # Should fail or sanitize to safe path
   ```

2. **Absolute path test**:
   ```python
   save_path = "/etc/cron.d/"
   # Should validate permissions and reject root-owned directories (for non-root)
   ```

3. **Character injection test**:
   ```python
   save_path = "/tmp/logs/../../../etc/passwd"
   # Should fail character whitelist check
   ```

4. **Permission boundary test**:
   ```python
   save_path = "/home/other_user/.ssh/"
   # Should fail st_uid != os.getuid() check
   ```

### Integration Test

```python
# Automated test in test suite
def test_log_file_path_validation():
    app = AutoTuningApplication(...)
    
    # Test 1: Valid path
    with tempfile.TemporaryDirectory() as tmpdir:
        app.run(save_path=tmpdir)  # Should succeed
    
    # Test 2: Sensitive system file
    try:
        app.run(save_path="/etc/cron.d/")
        assert False, "Should reject system directory"
    except SecurityError:
        pass  # Expected
    
    # Test 3: Path traversal
    try:
        app.run(save_path="/tmp/../../etc/passwd")
        assert False, "Should reject traversal"
    except SecurityError:
        pass  # Expected
```

---

## 9. Conclusion

### Summary

- **Vulnerability is REAL**: AsyncProcess.__init__ opens log_file without validation
- **Exploitability is LIMITED**: Permission checks provide partial protection
- **Risk level depends on deployment**: Root execution → HIGH risk; User execution → MEDIUM risk
- **Mitigation is incomplete**: shell=False doesn't protect file write vulnerability

### Recommended Priority

**Medium-High Priority** for fix:
- Not immediately critical (permission checks provide defense)
- Violates security design principle (all file paths should be validated)
- Could be exploited in privileged deployment scenarios

### References

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- Secure File Handling: Always validate paths, use safe directories, check permissions
