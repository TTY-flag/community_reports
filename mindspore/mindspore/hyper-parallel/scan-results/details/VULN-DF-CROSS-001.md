# VULN-DF-CROSS-001: Cross-Module Insecure Deserialization via torch.load

## Vulnerability Overview

| Attribute | Value |
|-----------|-------|
| **ID** | VULN-DF-CROSS-001 |
| **CWE** | CWE-502: Deserialization of Untrusted Data |
| **Severity** | Critical |
| **Confidence** | 80 |
| **Type** | insecure_deserialization |
| **File** | `hyper_parallel/core/distributed_checkpoint/filesystem_storage.py` |
| **Lines** | 385-413 |
| **Function** | `_load_tensor_file` |
| **Cross-Module** | Yes (distributed_checkpoint → platform) |

### CWE-502 Description

CWE-502 covers deserialization of untrusted data. This is a **cross-module vulnerability** where the dangerous deserialization occurs in a different module (`platform`) than the entry point (`distributed_checkpoint`).

### Cross-Module Vulnerability Characteristics

| Module | Role | Function |
|--------|------|----------|
| `distributed_checkpoint` | Entry point | `_load_tensor_file(path)` |
| `platform` | Sink (vulnerability) | `TorchPlatform.load_checkpoint()` |

---

## Root Cause Analysis

### Vulnerable Code Location (Entry Point)

```python
# filesystem_storage.py:385-413 (_load_tensor_file)
param_dict = platform.load_checkpoint(path)
for req in reqs:
    fqn = req.storage_index.fqn
    if fqn not in param_dict:
        raise KeyError(f"Key {fqn} not found in checkpoint file {path}")
    full_tensor = param_dict[fqn]
    # ... tensor processing
```

### Vulnerable Code Location (Sink - Platform Module)

```python
# platform.py:615-618 (TorchPlatform.load_checkpoint)
def load_checkpoint(file_path: str, ckpt_format: str = "safetensors") -> dict:
    if ckpt_format == "safetensors":
        return load_file(filename=file_path)  # Safe
    return torch.load(f=file_path)  # VULNERABLE - no weights_only=True
```

### Code Logic Flaw

The cross-module vulnerability exists because:

1. **Format Override**: Default `ckpt_format='safetensors'` is safe, but can be overridden to `'pickle'`
2. **Missing `weights_only=True`**: `torch.load()` is called without the safety parameter
3. **Cross-Module Call**: `_load_tensor_file()` calls `platform.load_checkpoint()` without format validation
4. **User-Controlled Path**: Checkpoint path flows from user input through distributed_checkpoint to platform

### Complete Cross-Module Data Flow

```
[Module: distributed_checkpoint]
User Input (checkpoint_id)
    │
    ▼
distributed_checkpoint.load(state_dict, checkpoint_id)
    │  [SOURCE: User-controlled]
    ▼
FileSystemReader(checkpoint_dir)
    │
    ▼
FileSystemReader.load_metadata()
    │
    ▼
_load_tensor_file(path, reqs, planner, storage_data)
    │  [Cross-module boundary]
    │  path = user-controlled checkpoint path
    ▼
platform.load_checkpoint(path)
    │  [Module boundary crossed]
    │
[Module: platform]
    ▼
TorchPlatform.load_checkpoint(file_path, ckpt_format)
    │  ckpt_format may be 'pickle' (dangerous)
    ▼
torch.load(f=file_path)
    │  [SINK: CWE-502 - No weights_only=True]
    │  Arbitrary code execution via pickle
    ▼
param_dict (potentially malicious tensors)
    │
[Return to distributed_checkpoint]
    ▼
full_tensor = param_dict[fqn]
    │
    ▼
target_tensor = planner.acquire_tensor(req)
    │  [Malicious data injected into application]
```

---

## Attack Path Analysis

### Step-by-Step Attack Scenario

**Step 1: Identify Format Override Mechanism**

```python
# Attacker needs to trigger non-safetensors format
# Options:
# 1. Checkpoint saved with pickle format
# 2. Format parameter override in load call
```

**Step 2: Create Malicious PyTorch Checkpoint**

```
Create malicious checkpoint file:
/malicious_checkpoint/model.pkl
Content: torch.save() format containing pickle payload
```

**Step 3: Trigger Vulnerability**

```python
# Scenario A: Direct checkpoint with pickle format
checkpoint = "/malicious_checkpoint/model.pkl"
distributed_checkpoint.load(state_dict, checkpoint)
# If metadata indicates pickle format or format is inferred
```

**Step 4: Exploitation Chain**

```
1. _load_tensor_file(path) called
2. platform.load_checkpoint(path) invoked
3. torch.load(file_path) reads malicious checkpoint
4. Pickle payload executes during torch.load()
5. Arbitrary code runs in training process
6. Malicious tensors returned to distributed_checkpoint
```

### Format-Based Attack Vector

| Format | Security | Attack Feasibility |
|--------|----------|-------------------|
| `safetensors` | Safe | No exploit possible |
| `pickle` | Vulnerable | Direct exploit via pickle payload |
| Default inference | Varies | Depends on checkpoint metadata |

### Entry Point Identification

| Entry Point | Module | Cross-Module Call |
|-------------|--------|-------------------|
| `distributed_checkpoint.load()` | distributed_checkpoint | Calls platform module |
| `platform.load_checkpoint()` | platform | Sink location |

### Required Conditions

| Condition | Required? | Notes |
|-----------|-----------|-------|
| Non-safetensors format | Yes | Default is safetensors (safe) |
| User controls checkpoint path | Yes | Primary vector |
| torch.load without weights_only | Yes | Current implementation |
| Pickle format checkpoint file | Yes | Crafted by attacker |

---

## PoC Construction Concept (Attack Idea Only)

### Attack Vector Description

1. **Format Manipulation**: Create checkpoint in pickle format instead of safetensors
2. **torch.load Exploit**: PyTorch's `torch.load()` uses pickle by default
3. **Payload Injection**: Embed malicious pickle payload in model file

### What a Malicious torch.load Payload Could Do

| Capability | Impact |
|------------|--------|
| **RCE** | Execute arbitrary commands during tensor loading |
| **Tensor Tampering** | Inject malicious weights that cause incorrect model outputs |
| **Backdoor in Model** | Embed hidden functionality in model weights |
| **Environment Access** | Read secrets, credentials from process environment |

### Prerequisites for Attack

1. **Format Override Capability**:
   - Checkpoint saved with pickle format
   - Format parameter explicitly set to non-safetensors
   
2. **Checkpoint Distribution**:
   - Shared storage (NFS, S3)
   - Model hub/repository (supply chain)
   - Direct file transfer

---

## Impact Assessment

### What an Attacker Can Achieve

| Attack Outcome | Severity | Description |
|----------------|----------|-------------|
| **Remote Code Execution** | Critical | Full process control via torch.load() |
| **Model Poisoning** | High | Inject backdoored weights |
| **Cross-Module Impact** | Critical | Affects both distributed_checkpoint and platform |
| **Supply Chain Attack** | High | Poisoned model in repository |

### Mitigation Assessment

| Mitigation | Status | Effectiveness |
|------------|--------|---------------|
| Default safetensors format | Present | Partial - can be overridden |
| File existence check | Present | Minimal - no content validation |
| Format validation | Missing | Vulnerability remains |

### Confidence Reduction Factors

| Factor | Impact on Confidence |
|--------|---------------------|
| Default safe format | -5 points |
| Cross-module complexity | -0 points (verified flow) |
| Format override possible | +20 points (attackable) |

**Final Confidence: 80** (Critical threshold maintained)

---

## Remediation Recommendations

### Option 1: Force weights_only=True (Recommended for torch.load)

```python
# platform.py - load_checkpoint()

@staticmethod
def load_checkpoint(file_path: str, ckpt_format: str = "safetensors") -> dict:
    if ckpt_format == "safetensors":
        return load_file(filename=file_path)
    
    # CRITICAL FIX: Add weights_only=True
    return torch.load(f=file_path, weights_only=True)
```

**Note**: `weights_only=True` restricts torch.load to only deserialize tensor weights, blocking arbitrary code execution. This is the recommended fix by PyTorch security team.

### Option 2: Disable Non-Safetensors Formats

```python
# platform.py - load_checkpoint()

SAFE_FORMATS = {"safetensors"}

@staticmethod
def load_checkpoint(file_path: str, ckpt_format: str = "safetensors") -> dict:
    if ckpt_format not in SAFE_FORMATS:
        raise SecurityError(
            f"Unsafe checkpoint format: {ckpt_format}. "
            f"Only {SAFE_FORMATS} formats are allowed."
        )
    
    if ckpt_format == "safetensors":
        return load_file(filename=file_path)
    
    # This branch should never be reached with SAFE_FORMATS restriction
    return torch.load(f=file_path, weights_only=True)
```

### Option 3: Format Validation in Entry Module

```python
# filesystem_storage.py - _load_tensor_file()

def _load_tensor_file(path: Path, reqs: list, planner, storage_data):
    """Load tensor file with format validation."""
    # Validate checkpoint format is safe
    metadata = storage_data.get("metadata")
    if metadata and metadata.format not in SAFE_FORMATS:
        raise SecurityError(
            f"Checkpoint format {metadata.format} not allowed. "
            "Use safetensors format for security."
        )
    
    param_dict = platform.load_checkpoint(path, ckpt_format="safetensors")
    # ... rest of implementation
```

### Option 4: Add Hash Verification

```python
# During save
def save_checkpoint_with_hash(model, path, format="safetensors"):
    platform.save_checkpoint(model, path, format)
    # Record hash in metadata
    hash = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return hash

# During load
def load_checkpoint_with_verification(path, expected_hash):
    actual_hash = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        raise SecurityError("Checkpoint hash verification failed")
    return platform.load_checkpoint(path, weights_only=True)
```

### Comprehensive Cross-Module Fix

```python
# platform.py - Secure load_checkpoint implementation

import hashlib
from pathlib import Path

class TorchPlatform:
    SAFE_FORMATS = frozenset({"safetensors"})
    
    @staticmethod
    def load_checkpoint(
        file_path: str,
        ckpt_format: str = "safetensors",
        expected_hash: str = None,
        strict_format: bool = True
    ) -> dict:
        """
        Load checkpoint with security validation.
        
        Args:
            file_path: Path to checkpoint file
            ckpt_format: Format of checkpoint
            expected_hash: Optional SHA256 hash for verification
            strict_format: If True, reject non-safe formats
        """
        # 1. Format validation
        if strict_format and ckpt_format not in TorchPlatform.SAFE_FORMATS:
            raise SecurityError(
                f"Checkpoint format '{ckpt_format}' rejected. "
                f"Allowed formats: {TorchPlatform.SAFE_FORMATS}"
            )
        
        # 2. Path validation (prevent traversal)
        resolved_path = Path(file_path).resolve()
        if not resolved_path.exists():
            raise FileNotFoundError(f"Checkpoint not found: {file_path}")
        
        # 3. Hash verification
        if expected_hash:
            content = resolved_path.read_bytes()
            actual_hash = hashlib.sha256(content).hexdigest()
            if actual_hash != expected_hash:
                raise SecurityError(
                    f"Checkpoint hash mismatch. Expected: {expected_hash}"
                )
        
        # 4. Safe loading
        if ckpt_format == "safetensors":
            return load_file(filename=file_path)
        
        # 5. For legacy pickle format (if allowed), use weights_only=True
        return torch.load(f=file_path, weights_only=True)
```

```python
# filesystem_storage.py - _load_tensor_file with verification

def _load_tensor_file(path: Path, reqs: list, planner, storage_data):
    """Load tensor file with cross-module security."""
    # Retrieve expected format and hash from metadata
    metadata = storage_data.get("metadata")
    ckpt_format = getattr(metadata, "format", "safetensors")
    expected_hash = getattr(metadata, "tensor_hash", None)
    
    # Call platform with security parameters
    param_dict = platform.load_checkpoint(
        str(path),
        ckpt_format=ckpt_format,
        expected_hash=expected_hash,
        strict_format=True  # Force safe format
    )
    
    # Process tensors...
    for req in reqs:
        fqn = req.storage_index.fqn
        full_tensor = param_dict[fqn]
        # ... rest of implementation
```

---

## Cross-Module Security Implications

### Why Cross-Module Vulnerabilities Are Dangerous

| Aspect | Impact |
|--------|--------|
| **Complexity** | Data flows across boundaries, harder to trace |
| **Entry-Sink Separation** | Vulnerability not at entry point |
| **Module Dependencies** | Changes in platform affect distributed_checkpoint |
| **Remediation Coordination** | Fix required in both modules |

### Recommendations for Cross-Module Security

1. **Interface Contracts**: Define security requirements at module boundaries
2. **Parameter Validation**: Validate all cross-module parameters
3. **Sink Protection**: Secure sinks even if entry seems safe
4. **Default Safety**: Default to safe formats/options at sinks

---

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [PyTorch torch.load weights_only Parameter](https://pytorch.org/docs/stable/generated/torch.load.html)
- [PyTorch Security Best Practices](https://pytorch.org/docs/stable/notes/serialization.html)
- [safetensors Format Documentation](https://huggingface.co/docs/safetensors)