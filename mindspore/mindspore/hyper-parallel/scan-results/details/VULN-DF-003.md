# VULN-DF-003: Insecure Deserialization in torch.load Without weights_only

## Vulnerability Overview

| Attribute | Value |
|-----------|-------|
| **ID** | VULN-DF-003 |
| **CWE** | CWE-502: Deserialization of Untrusted Data |
| **Severity** | High |
| **Confidence** | 78 |
| **Type** | insecure_deserialization |
| **File** | `hyper_parallel/platform/torch/platform.py` |
| **Lines** | 615-618 |
| **Function** | `TorchPlatform.load_checkpoint` |

### CWE-502 Description

CWE-502 describes deserialization of untrusted data. PyTorch's `torch.load()` function uses Python's pickle module by default, which can execute arbitrary code during deserialization.

---

## Root Cause Analysis

### Vulnerable Code Location

```python
# platform.py:614-618
@staticmethod
def load_checkpoint(file_path: str, ckpt_format: str = "safetensors") -> dict:
    if ckpt_format == "safetensors":
        return load_file(filename=file_path)
    return torch.load(f=file_path)
```

### Code Logic Flaw

The vulnerability exists due to:

1. **Missing `weights_only=True`**: `torch.load()` is called without the safety parameter
2. **Format-Based Conditional**: Pickle format branch is vulnerable
3. **Default Safety Incomplete**: While default is safetensors, format can be overridden
4. **No File Content Validation**: Path checked for existence, but content unvalidated

### Data Flow

```
distributed_checkpoint._load_tensor_file(path)
    │  [SOURCE: User-controlled checkpoint path]
    ▼
platform.load_checkpoint(path)
    │
    ▼
TorchPlatform.load_checkpoint(file_path, ckpt_format='pickle')
    │  [Format can be non-safetensors]
    ▼
torch.load(f=file_path)
    │  [SINK: CWE-502 - No weights_only=True]
    ▼
param_dict (potentially malicious)
```

### Mitigations Present

| Mitigation | Location | Effectiveness |
|------------|----------|---------------|
| Default safetensors format | Parameter default | Partial - can be overridden |
| File existence check | offline_transform.py | Minimal - no content validation |
| Safe format option | Conditional | Requires explicit safe choice |

---

## Attack Path Analysis

### Step-by-Step Attack Scenario

**Step 1: Format Override Analysis**

```python
# Attack requires non-safetensors format
# Format can be:
# - Explicitly passed as parameter
# - Inferred from file extension
# - Set in checkpoint metadata
```

**Step 2: Create Malicious Torch Checkpoint**

```
Create: /malicious_checkpoint/model.pt
Content: torch.save format with embedded pickle payload
```

**Step 3: Trigger Vulnerability**

```python
# Direct call with pickle format
platform.load_checkpoint("/malicious_checkpoint/model.pt", ckpt_format="pickle")

# Or via distributed_checkpoint (if metadata indicates pickle format)
distributed_checkpoint.load(state_dict, checkpoint_id)
```

**Step 4: Exploitation**

```
1. torch.load(file_path) reads checkpoint
2. Pickle deserialization occurs
3. Arbitrary code executes
4. Malicious content returned
```

### Required Conditions

| Condition | Required? | Current State |
|-----------|-----------|---------------|
| Non-safetensors format | Yes | Can be overridden |
| User-controlled checkpoint | Yes | Entry point allows |
| torch.load without weights_only | Yes | Current implementation |
| Malicious checkpoint file | Yes | Attack vector |

---

## PoC Construction Concept (Attack Idea Only)

### Attack Vector: Format Override + Malicious Checkpoint

1. **Create torch checkpoint** in pickle format (`.pt` or `.pth`)
2. **Embed pickle payload** in checkpoint structure
3. **Trigger load** with non-safetensors format

### torch.load Exploit Mechanism

PyTorch `torch.load()` deserialization flow:
```
torch.load(file)
    │
    ▼
pickle.Unpickler
    │
    ▼
__reduce__ / GLOBAL opcode
    │
    ▼
Arbitrary function call
    │
    ▼
RCE
```

### What Payloads Can Achieve

| Capability | Example Impact |
|------------|----------------|
| **RCE** | Shell command execution |
| **Environment Access** | Steal API keys, secrets |
| **Tensor Manipulation** | Poison model weights |
| **Process Control** | Install malware, backdoors |

### Attack Prerequisites

1. **Format Control**:
   - Saved checkpoint uses pickle format
   - Format parameter set to 'pickle'
   - Metadata indicates pickle format

2. **Checkpoint Source**:
   - Shared storage access
   - Downloaded from untrusted source
   - Supply chain compromise

---

## Impact Assessment

### Severity Analysis

| Factor | Impact | Score |
|--------|--------|-------|
| RCE Capability | Critical | +30 |
| Default safe format | Mitigation | -5 |
| Format override possible | Attackable | +20 |
| File existence check | Minimal mitigation | -0 |
| Reachability | High | +33 |

**Severity: High** (reduced from Critical due to default safetensors)

### What Attacker Can Achieve

| Outcome | Impact Level |
|---------|--------------|
| Remote Code Execution | High (requires format override) |
| Model Poisoning | High |
| Credential Theft | Medium |
| System Compromise | High |

### Affected Components

| Component | Impact |
|-----------|--------|
| Platform module | Direct vulnerability location |
| Distributed checkpoint | Caller module |
| Training pipelines | Consumer |
| Model weights | Target of manipulation |

---

## Remediation Recommendations

### Option 1: Add weights_only=True (CRITICAL FIX)

```python
# platform.py - load_checkpoint()

@staticmethod
def load_checkpoint(file_path: str, ckpt_format: str = "safetensors") -> dict:
    if ckpt_format == "safetensors":
        return load_file(filename=file_path)
    
    # CRITICAL: Add weights_only=True to prevent code execution
    return torch.load(f=file_path, weights_only=True)
```

**Why weights_only=True**:
- Restricts unpickling to only tensor data types
- Blocks arbitrary class/function imports
- Prevents RCE via pickle payloads
- Recommended by PyTorch since version 2.0

### Option 2: Enforce Safe Format

```python
# platform.py - load_checkpoint()

ALLOWED_FORMATS = {"safetensors"}

@staticmethod
def load_checkpoint(file_path: str, ckpt_format: str = "safetensors") -> dict:
    # Security: Reject dangerous formats
    if ckpt_format not in ALLOWED_FORMATS:
        raise SecurityError(
            f"Checkpoint format '{ckpt_format}' is not allowed. "
            f"Supported formats: {ALLOWED_FORMATS}"
        )
    
    return load_file(filename=file_path)
```

### Option 3: Add File Hash Verification

```python
import hashlib
from pathlib import Path

@staticmethod
def load_checkpoint(
    file_path: str,
    ckpt_format: str = "safetensors",
    expected_hash: str = None
) -> dict:
    """Load checkpoint with optional hash verification."""
    
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Checkpoint not found: {file_path}")
    
    # Hash verification for security
    if expected_hash:
        content = path.read_bytes()
        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash != expected_hash:
            raise SecurityError(
                f"Checkpoint integrity check failed. "
                f"Expected: {expected_hash}, Got: {actual_hash}"
            )
    
    if ckpt_format == "safetensors":
        return load_file(filename=file_path)
    
    # Safe loading with weights_only
    return torch.load(f=file_path, weights_only=True)
```

### Option 4: Comprehensive Secure Implementation

```python
class TorchPlatform:
    """PyTorch platform with security-hardened checkpoint loading."""
    
    # Whitelist of safe checkpoint formats
    SAFE_FORMATS = frozenset({"safetensors"})
    
    # Legacy formats allowed only with weights_only=True
    LEGACY_FORMATS = frozenset({"pickle", "pt", "pth"})
    
    @staticmethod
    def load_checkpoint(
        file_path: str,
        ckpt_format: str = "safetensors",
        expected_hash: Optional[str] = None,
        allow_legacy: bool = False
    ) -> dict:
        """
        Secure checkpoint loading.
        
        Args:
            file_path: Path to checkpoint file
            ckpt_format: Checkpoint format (default: safetensors)
            expected_hash: Optional SHA256 hash for integrity verification
            allow_legacy: If True, allow legacy pickle formats with weights_only
            
        Returns:
            dict: Loaded checkpoint parameters
            
        Raises:
            SecurityError: If format not allowed or hash mismatch
            FileNotFoundError: If checkpoint file not found
        """
        # 1. Resolve and validate path
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Checkpoint not found: {file_path}")
        
        # 2. Format validation
        if ckpt_format in TorchPlatform.SAFE_FORMATS:
            # Safe format - proceed
            pass
        elif ckpt_format in TorchPlatform.LEGACY_FORMATS:
            if not allow_legacy:
                raise SecurityError(
                    f"Legacy format '{ckpt_format}' requires allow_legacy=True. "
                    f"Recommended: use safetensors format."
                )
        else:
            raise SecurityError(
                f"Unknown checkpoint format: '{ckpt_format}'. "
                f"Safe formats: {TorchPlatform.SAFE_FORMATS}, "
                f"Legacy formats: {TorchPlatform.LEGACY_FORMATS}"
            )
        
        # 3. Hash verification (if provided)
        if expected_hash:
            content = path.read_bytes()
            actual_hash = hashlib.sha256(content).hexdigest()
            if actual_hash != expected_hash:
                raise SecurityError(
                    f"Checkpoint hash verification failed. "
                    f"Expected: {expected_hash[:16]}..., "
                    f"Got: {actual_hash[:16]}..."
                )
        
        # 4. Load with appropriate safety measures
        if ckpt_format == "safetensors":
            return load_file(filename=str(path))
        
        # Legacy formats always use weights_only=True
        return torch.load(f=str(path), weights_only=True)
    
    @staticmethod
    def save_checkpoint(
        cell: Module,
        file_path: str,
        ckpt_format: str = "safetensors"
    ) -> str:
        """
        Save checkpoint and return hash for verification.
        
        Returns:
            str: SHA256 hash of saved checkpoint
        """
        path = Path(file_path)
        
        if ckpt_format == "safetensors":
            save_file(tensors=cell, filename=file_path)
        else:
            torch.save(obj=cell, f=file_path)
        
        # Return hash for verification during load
        content = path.read_bytes()
        return hashlib.sha256(content).hexdigest()
```

### Integration with distributed_checkpoint

```python
# filesystem_storage.py - _load_tensor_file()

def _load_tensor_file(path: Path, reqs: list, planner, storage_data):
    """Load tensor file with security parameters."""
    
    # Get metadata for hash verification
    metadata = storage_data.get("metadata")
    expected_hash = getattr(metadata, "tensor_hashes", {}).get(str(path))
    
    # Get format from metadata or use safe default
    ckpt_format = getattr(metadata, "tensor_format", "safetensors")
    
    # Load with security
    param_dict = platform.load_checkpoint(
        str(path),
        ckpt_format=ckpt_format,
        expected_hash=expected_hash,
        allow_legacy=False  # Reject legacy formats
    )
    
    # Process tensors...
```

---

## Best Practices for torch.load Security

| Practice | Implementation |
|----------|----------------|
| **Always use weights_only=True** | `torch.load(f=path, weights_only=True)` |
| **Prefer safetensors format** | Use `safetensors` for new checkpoints |
| **Add hash verification** | Verify checkpoint integrity before loading |
| **Validate file paths** | Prevent path traversal attacks |
| **Document format expectations** | Specify format in checkpoint metadata |

---

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [PyTorch torch.load Documentation](https://pytorch.org/docs/stable/generated/torch.load.html)
- [PyTorch weights_only Security Notice](https://github.com/pytorch/pytorch/issues/32475)
- [safetensors: Safe Tensor Serialization](https://huggingface.co/docs/safetensors)
- [OWASP Deserialization Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)