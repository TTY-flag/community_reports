# Deserialization Vulnerability: Unsafe torch.load in LayerZero Checkpoint

## Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | layerzero-mga_checkpoint-torch_load-188 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **Severity** | Critical |
| **File** | mindspeed/core/distributed/layerzero/state/mga_checkpoint.py |
| **Line** | 188 |
| **Function** | `load_layerzero_checkpoint` |

## Vulnerability Description

The function `load_layerzero_checkpoint` uses `torch.load()` without the `weights_only=True` parameter, allowing arbitrary code execution through malicious pickle payloads embedded in checkpoint files.

### Vulnerable Code

```python
# Line 177-188
def load_layerzero_checkpoint(models, ckpt_dir, optimizer=None, opt_param_scheduler=None):
    if ckpt_dir is None:
        raise AssertionError(f"Got {ckpt_dir} filename")
    if len(models) != 1:
        raise ValueError(f"VPP is not supported by layerzero currently")
    rank = dist.get_rank()
    sd_file = os.path.join(ckpt_dir, f"model_{rank}.pt")
    if not os.path.exists(sd_file):
        raise FileNotFoundError(
            f"No checkpoint found in load directory or pretrained directory: no such file {sd_file}")
    args = get_args()
    state_dict = torch.load(sd_file)  # VULNERABLE: No weights_only=True
```

### Data Flow

```
Source: config.ckpt_load_path (YAML config file or direct parameter)
   ↓
LayerzeroConfig.ckpt_load_path (dataclass field, line 64 in config.py)
   ↓
Validation: os.path.isabs() check only (lines 267-269)
   ↓
load_layerzero_checkpoint(models, config.ckpt_load_path, ...) (line 271-272)
   ↓
sd_file = os.path.join(ckpt_dir, f"model_{rank}.pt") (line 183)
   ↓
torch.load(sd_file)  ← SINK: Arbitrary pickle deserialization
```

## Technical Details

### Why `weights_only=True` Cannot Be Directly Applied

The checkpoint state dictionary contains complex objects beyond simple tensors:

```python
# From generate_state_dict() function (lines 112-153)
state_dict = {}
state_dict['args'] = args                    # Python object, not just tensors
state_dict['checkpoint_version'] = 3.0
state_dict['iteration'] = iteration
state_dict[MODEL_KEY] = model.state_dict()  # Tensor weights
state_dict[OPTIM_STATE_KEY] = optimizer.state_dict()  # Complex optimizer state
state_dict[RNG_STATE_KEY] = rng_state       # Python state objects
state_dict[PARALLE_STATE_KAY] = generate_3D_parallel_state()  # Parallel state
```

Using `weights_only=True` would cause loading failures because:
1. `args` is a Python argparse Namespace object
2. Optimizer state contains complex nested objects
3. RNG states contain Python random state objects

### Existing Mitigations (Insufficient)

1. **Absolute path validation** (config.py lines 267-269):
   ```python
   if not os.path.isabs(config.ckpt_load_path):
       raise ValueError(...)
   ```
   - Only validates path format, not file content or origin
   - Does not prevent loading malicious files from absolute paths

2. **File existence check** (mga_checkpoint.py line 184-186):
   - Only checks if file exists, not its integrity or authenticity

## Attack Scenario

An attacker who can:
1. Control the YAML configuration file path for `ckpt_load_path`
2. OR inject a malicious checkpoint file into an expected directory

Can achieve **arbitrary code execution** by crafting a malicious `.pt` file:
```python
import torch
import os

class Malicious:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

# Create malicious checkpoint
malicious_ckpt = {'model': Malicious(), 'iteration': 0}
torch.save(malicious_ckpt, 'model_0.pt')
```

When `torch.load('model_0.pt')` is called, the malicious code executes.

## Related Vulnerable Locations

Similar patterns exist elsewhere in the codebase:

| File | Line | Function |
|------|------|----------|
| mindspeed/checkpointing.py | 277 | `load_checkpoint` |
| mindspeed/checkpointing.py | 284 | `load_checkpoint` |
| mindspeed/checkpointing.py | 310 | `load_checkpoint` |
| mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py | 55 | `ShardStateDict._init_metadata` |
| mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py | 110 | `LayerzeroCheckpoint._build_global_state` |
| mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py | 127, 135 | `LayerzeroCheckpoint.get_iteration`/`get_args` |

## Recommendations

### Short-term (Immediate)

1. **Add security warning in documentation** about only loading checkpoints from trusted sources

2. **Add checkpoint integrity verification** using hash checking:
   ```python
   import hashlib
   def verify_checkpoint_hash(filepath, expected_hash):
       with open(filepath, 'rb') as f:
           file_hash = hashlib.sha256(f.read()).hexdigest()
       return file_hash == expected_hash
   ```

3. **Log checkpoint loading with security warnings**:
   ```python
   import logging
   logging.warning(f"Loading checkpoint from {sd_file}. Only load checkpoints from trusted sources.")
   ```

### Medium-term

1. **Separate weights from state metadata**:
   - Store weights separately using `weights_only=True` safe format
   - Store metadata (args, iteration, etc.) in JSON/YAML format
   - Reconstruct state_dict after loading both parts safely

2. **Implement checkpoint signing**:
   - Sign checkpoints during save with a private key
   - Verify signature before loading

### Long-term

1. **Migrate to safer serialization formats**:
   - Use `torch.save(..., _use_new_zipfile_serialization=True)`
   - Consider safetensors format for model weights
   - Store non-tensor data in JSON

2. **Add sandboxed deserialization** for untrusted checkpoints

## Risk Assessment

| Factor | Assessment |
|--------|------------|
| **Likelihood** | Low-Medium (requires config/file access) |
| **Impact** | Critical (arbitrary code execution) |
| **Current mitigations** | Insufficient |
| **Framework context** | Internal training framework (trusted config expected) |

## References

- [PyTorch Security Advisory: torch.load weights_only default change](https://github.com/pytorch/pytorch/pull/101837)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [PyTorch Safe Loading Documentation](https://pytorch.org/docs/stable/generated/torch.load.html)

## Verification Steps

1. Identify all `torch.load()` calls without `weights_only=True`
2. Trace data flow to determine if paths can be controlled externally
3. Test with crafted malicious checkpoint file to confirm exploitability
4. Verify any existing integrity checks or signature verification

---

*Report generated by OpenCode Vulnerability Scanner*
*Date: 2026-04-20*
