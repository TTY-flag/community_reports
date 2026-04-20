# VULN-DF-PY-CHKPT-001: Unsafe Pickle Deserialization in Checkpoint Loading

## Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-DF-PY-CHKPT-001 |
| **Type** | Deserialization (CWE-502) |
| **Severity** | Critical |
| **CVSS Score** | 9.8 (Critical) |
| **File** | `mindspeed/checkpointing.py` |
| **Function** | `_load_base_checkpoint` |
| **Lines** | 277, 284, 310 |

## Description

The `_load_base_checkpoint` function in `mindspeed/checkpointing.py` uses `torch.load()` to deserialize checkpoint files without the `weights_only=True` parameter. PyTorch's `torch.load()` function uses Python's `pickle` module internally, which can execute arbitrary code during deserialization. This creates a critical remote code execution vulnerability when loading untrusted checkpoint files.

## Vulnerable Code

### Location 1: Line 277
```python
state_dict = torch.load(checkpoint_name, map_location='cpu')
```

### Location 2: Line 284
```python
ema_state_dict = torch.load(checkpoint_name + ".ema", map_location='cpu')
```

### Location 3: Line 310
```python
state_dict = torch.load(checkpoint_name, map_location='cpu')
```

## Data Flow Analysis

```
Source: load_dir (function parameter, semi_trusted)
    |
    v
get_checkpoint_name(load_dir, iteration, release, ...)
    |
    v
checkpoint_name (constructed file path)
    |
    v
torch.load(checkpoint_name, map_location='cpu')  <-- SINK: Unsafe deserialization
```

### Entry Point Trace

1. **CLI Arguments**: User provides `--load <path>` or `--save <path>` argument
2. **load_checkpoint()**: Called with `load_dir = args.load`
3. **_load_base_checkpoint(load_dir, ...)**: Receives `load_dir` as parameter
4. **get_checkpoint_name()**: Constructs checkpoint file path from `load_dir`
5. **torch.load()**: Deserializes checkpoint file without safe guards

## Attack Vector

1. **External Checkpoint**: User downloads a checkpoint file from an untrusted source (e.g., HuggingFace Hub, model zoo, shared by third party)
2. **Malicious Payload**: The checkpoint file contains a malicious pickle payload
3. **Code Execution**: When `torch.load()` deserializes the file, arbitrary code is executed

### Proof of Concept

An attacker can craft a malicious checkpoint file:

```python
import torch
import pickle
import os

class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

# Create malicious checkpoint
checkpoint = {
    'model': MaliciousPayload(),
    'args': None,
    'iteration': 1
}
torch.save(checkpoint, 'malicious_checkpoint.pt')
```

When this checkpoint is loaded:
```bash
python -m mindspeed.run --load ./malicious_checkpoint.pt
```
The `id > /tmp/pwned` command will be executed.

## Impact

| Impact Category | Severity | Description |
|-----------------|----------|-------------|
| **Remote Code Execution** | Critical | Arbitrary code execution with the privileges of the process loading the checkpoint |
| **System Compromise** | Critical | Full system compromise if running with elevated privileges |
| **Data Exfiltration** | High | Access to training data, model weights, and credentials |
| **Model Integrity** | High | Model weights can be tampered with to introduce backdoors |

## Evidence from Codebase

### No Safe Alternative Used
The vulnerable file does not use `weights_only=True`:
```bash
# grep for weights_only in checkpointing.py returns NO matches
```

### Safe Implementation Example Exists
A safe implementation pattern exists in the same codebase at `mindspeed/mindspore/third_party/transformers/modeling_utils.py`:
```python
weights_only: bool = True,
...
weights_only=weights_only,
```

## Root Cause Analysis

1. **Missing Security Parameter**: The `weights_only=True` parameter is not used, which would restrict deserialization to tensor data only
2. **No Integrity Verification**: No checksum or signature verification of checkpoint files
3. **No Source Validation**: No whitelist or allowlist for checkpoint sources
4. **Default Unsafe Behavior**: PyTorch's default behavior is unsafe; explicit opt-in required for safety

## Recommended Remediation

### Primary Fix: Add weights_only=True

```python
# Line 277 - BEFORE
state_dict = torch.load(checkpoint_name, map_location='cpu')

# Line 277 - AFTER
state_dict = torch.load(checkpoint_name, map_location='cpu', weights_only=True)
```

Apply the same fix to lines 284 and 310.

### Secondary Fixes

1. **Add File Integrity Verification**:
```python
import hashlib

def verify_checkpoint_integrity(checkpoint_path, expected_hash=None):
    if expected_hash is None:
        return True  # Skip verification if no hash provided
    with open(checkpoint_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    return file_hash == expected_hash
```

2. **Add Source Validation**:
```python
ALLOWED_CHECKPOINT_SOURCES = [
    "https://huggingface.co/",
    "https://modelscope.cn/",
    # Add trusted sources
]

def validate_checkpoint_source(path):
    # Check if path is from trusted source
    pass
```

3. **Add Safe Load Wrapper**:
```python
def safe_torch_load(path, **kwargs):
    """Safely load checkpoint with security checks."""
    kwargs.setdefault('weights_only', True)
    kwargs.setdefault('map_location', 'cpu')
    return torch.load(path, **kwargs)
```

## Affected Components

| Component | File | Function | Severity |
|-----------|------|----------|----------|
| Checkpoint Loading | mindspeed/checkpointing.py | _load_base_checkpoint | Critical |
| EMA Checkpoint Loading | mindspeed/checkpointing.py | _load_base_checkpoint | Critical |
| Legacy Checkpoint Loading | mindspeed/checkpointing.py | _load_base_checkpoint | Critical |

## Related Vulnerabilities

- **CWE-502**: Deserialization of Untrusted Data
- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object Attributes

## References

- [PyTorch Security Advisory: torch.load weights_only](https://pytorch.org/docs/stable/generated/torch.load.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [PyTorch pickle security risks](https://github.com/pytorch/pytorch/security/advisories)

## Verification Steps

1. Apply the `weights_only=True` fix
2. Run existing tests to ensure compatibility
3. Test with checkpoint files to verify loading still works
4. Test with malicious checkpoint to verify code execution is blocked

## Status

- [ ] Vulnerability Confirmed
- [ ] Fix Implemented
- [ ] Tests Passing
- [ ] Code Review Complete
- [ ] Security Review Complete

---
*Generated by security scanner on 2026-04-20*
