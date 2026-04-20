# Vulnerability Report: VULN-SEC-LZ-002

## Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-SEC-LZ-002 |
| **CWE** | CWE-502: Deserialization of Untrusted Data |
| **Severity** | High |
| **CVSS Score** | 7.8 (High) |
| **Status** | Confirmed |
| **File** | `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py` |
| **Line** | 55 |
| **Function** | `ShardStateDict._init_metadata` |

## Vulnerability Description

The `ShardStateDict._init_metadata` method uses `torch.load()` to deserialize checkpoint files without proper security validation. The `filename` parameter originates from file system traversal that only validates the filename prefix, allowing malicious files to be loaded and deserialized.

### Vulnerable Code

```python
# Line 50-55
class ShardStateDict:
    def __init__(self, filename) -> None:
        self.filename = filename
        self._init_metadata()

    def _init_metadata(self):
        state_dict = torch.load(self.filename, map_location='cpu')  # VULNERABLE
```

### Inadequate Mitigation (File Prefix Filter)

```python
# Lines 141-147
def _get_files_by_key(self, ckpt_dir, key):
    file_list = []
    for root, _, files in os.walk(ckpt_dir):
        for file in files:
            if file.startswith(key):  # Only checks filename prefix!
                file_list.append(os.path.join(root, file))
    return file_list
```

## Attack Vector Analysis

### Data Flow

```
User Input (ckpt_dir)
    ↓
LayerzeroCheckpoint.__init__(ckpt_dir)
    ↓
_get_files_by_key(ckpt_dir, 'model_')  ← Prefix filter (insufficient)
    ↓
file_list = [files starting with "model_"]
    ↓
ShardStateDict(filename)
    ↓
torch.load(self.filename, map_location='cpu')  ← Arbitrary deserialization
```

### Attack Scenario

1. **Initial Access**: Attacker gains write access to checkpoint directory through:
   - Compromised shared filesystem
   - Insider threat
   - Supply chain attack on checkpoint distribution
   - Path traversal in another component

2. **Payload Placement**: Attacker creates a malicious pickle file:
   ```python
   import torch
   import pickle
   import os
   
   class Exploit:
       def __reduce__(self):
           return (os.system, ('id > /tmp/pwned',))
   
   # Save as model_malicious.pt
   torch.save({'exploit': Exploit()}, 'model_malicious.pt')
   ```

3. **Trigger**: Application loads checkpoint:
   ```python
   checkpoint = LayerzeroCheckpoint("/path/to/compromised/dir")
   # Arbitrary code executes during torch.load
   ```

## Evidence of Risk

### 1. Official Security Acknowledgment

From `docs/zh/SECURITYNOTE.md` (line 54):
> MindSpeed在运行中可能会调用torch.load函数，torch.load在2.6以下版本默认参数weight_only=False，存在潜在安全风险（CVE-2025-32434）。建议使用2.6.0版本的pytorch。

### 2. Multiple Vulnerable torch.load Calls in Same File

| Line | Function | Risk Level |
|------|----------|------------|
| 55 | `ShardStateDict._init_metadata` | Critical |
| 110 | `LayerzeroCheckpoint._build_global_state` | Critical |
| 127 | `LayerzeroCheckpoint.get_iteration` | Critical |
| 135 | `LayerzeroCheckpoint.get_args` | Critical |

### 3. No Integrity Validation

The code does NOT:
- Validate file checksums or signatures
- Verify file ownership/permissions
- Validate checkpoint structure before loading
- Use `weights_only=True` parameter (PyTorch 2.0+ security feature)

## Impact Assessment

| Impact Category | Severity | Description |
|-----------------|----------|-------------|
| **Confidentiality** | High | Attacker can read arbitrary files via pickle payload |
| **Integrity** | High | Attacker can modify data or system state |
| **Availability** | High | Attacker can cause denial of service |
| **Execution** | Critical | Arbitrary code execution with application privileges |

## Affected Components

### Entry Point
```python
# convert_to_megatron.py, line 97
lz_checkpoint = LayerzeroCheckpoint(args.input_folder)
```

This script is designed for checkpoint conversion, accepting user-supplied checkpoint directories via command-line argument `--input_folder`.

### Trust Boundary
- **Input**: User-controlled checkpoint directory path
- **Trust Level**: Semi-trusted (only prefix check on filename)
- **Problem**: Prefix check does not validate file contents or source

## Remediation Recommendations

### 1. Use `weights_only=True` (Primary Fix)

```python
# PyTorch 2.0+ provides weights_only parameter
state_dict = torch.load(self.filename, map_location='cpu', weights_only=True)
```

### 2. Add Checkpoint Integrity Verification

```python
import hashlib

def validate_checkpoint_integrity(filepath, expected_hash=None):
    """Validate checkpoint file integrity before loading."""
    if expected_hash:
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        if file_hash != expected_hash:
            raise SecurityError(f"Checkpoint integrity check failed for {filepath}")
    return True

def safe_load_checkpoint(filepath, expected_hash=None):
    """Safely load checkpoint with integrity verification."""
    validate_checkpoint_integrity(filepath, expected_hash)
    return torch.load(filepath, map_location='cpu', weights_only=True)
```

### 3. Restrict File Permissions

Ensure checkpoint directories have restricted permissions:
- Owner-only write access
- Verify file ownership matches expected user

### 4. Validate Checkpoint Structure

```python
def _init_metadata(self):
    # First load with weights_only to validate structure
    state_dict = torch.load(self.filename, map_location='cpu', weights_only=True)
    
    # Validate required keys exist
    required_keys = [PARALLE_STATE_KAY, LOCAL_NAME_TO_FQN_KEY, MODEL_SD_KEY]
    for key in required_keys:
        if key not in state_dict:
            raise ValueError(f"Invalid checkpoint: missing required key '{key}'")
    
    # Then safely access the data
    self.parallel_info = state_dict[PARALLE_STATE_KAY]
    # ...
```

## References

- **CWE-502**: Deserialization of Untrusted Data - https://cwe.mitre.org/data/definitions/502.html
- **CVE-2025-32434**: PyTorch torch.load security issue
- **PyTorch Security**: https://pytorch.org/docs/stable/generated/torch.load.html

## Timeline

- **Discovery**: Static analysis scan
- **Analysis Date**: 2026-04-20
- **Status**: Confirmed - Real vulnerability requiring remediation

## Related Vulnerabilities

- **VULN-DF-PY-CHKPT-001**: Similar issue in `mindspeed/checkpointing.py`
- **layerzero-mga_checkpoint-torch_load-188**: Similar issue in `mindspeed/core/distributed/layerzero/state/mga_checkpoint.py`
