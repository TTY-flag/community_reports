# VULN-DF-001: Insecure Pickle Deserialization in Metadata Loading

## Vulnerability Overview

| Attribute | Value |
|-----------|-------|
| **ID** | VULN-DF-001 |
| **CWE** | CWE-502: Deserialization of Untrusted Data |
| **Severity** | Critical |
| **Confidence** | 85 |
| **Type** | insecure_deserialization |
| **File** | `hyper_parallel/core/distributed_checkpoint/filesystem_storage.py` |
| **Lines** | 462-464 |
| **Function** | `FileSystemReader.load_metadata` |

### CWE-502 Description

CWE-502 describes the deserialization of untrusted data. When an application deserializes data from an untrusted source without adequate verification, attackers can inject malicious payloads that execute arbitrary code during the deserialization process.

Python's `pickle` module is particularly dangerous because:
- It can serialize and deserialize arbitrary Python objects
- During deserialization, `pickle.load()` and `pickle.loads()` can execute arbitrary code by invoking `__reduce__`, `__reduce_ex__`, or custom unpickling methods
- The pickle format includes opcode instructions that can trigger arbitrary function calls

---

## Root Cause Analysis

### Vulnerable Code Location

```python
# filesystem_storage.py:462-464
with open(metadata_file, 'rb') as f:
    metadata = pickle.load(f)
```

### Code Logic Flaw

The vulnerability exists because:

1. **Direct User Input**: `checkpoint_dir` parameter is passed directly from user input through the API call chain
2. **No Validation**: The metadata file is opened and deserialized without any integrity checks
3. **No File Content Verification**: No hash/signature validation to ensure file authenticity
4. **Pickle's Dangerous Nature**: `pickle.load()` inherently executes code during deserialization

### Complete Data Flow Trace

```
User Input (checkpoint_id)
    │
    ▼
distributed_checkpoint.load(state_dict, checkpoint_id)
    │  [SOURCE: User-controlled parameter]
    ▼
FileSystemReader(checkpoint_dir)
    │  checkpoint_dir = Path(checkpoint_id)  [User path directly used]
    ▼
FileSystemReader.load_metadata()
    │  metadata_file = self.checkpoint_dir / METADATA_FILE_NAME
    │  [User-controlled directory + predictable filename]
    ▼
open(metadata_file, 'rb')
    │  [File from user-controlled path]
    ▼
pickle.load(f)
    │  [SINK: CWE-502 - Arbitrary code execution]
    ▼
metadata (potentially malicious object)
```

### Attacker Control Points

| Control Point | Attacker Capability |
|---------------|---------------------|
| `checkpoint_id` parameter | Full control of checkpoint directory path |
| Directory contents | Can place malicious `.metadata` file |
| `.metadata` file content | Can craft pickle payload with arbitrary code |

---

## Attack Path Analysis

### Step-by-Step Attack Scenario

**Step 1: Create Malicious Checkpoint Directory**
```
Attacker creates: /malicious_checkpoint/
```

**Step 2: Craft Poisoned Metadata File**
```
Create: /malicious_checkpoint/.metadata
Content: Malicious pickle payload containing exploit code
```

**Step 3: Trigger Vulnerability**
```python
# Victim code
distributed_checkpoint.load(state_dict, "/malicious_checkpoint")
```

**Step 4: Exploitation**
- When `load_metadata()` is called, the malicious `.metadata` file is deserialized
- Pickle payload executes arbitrary Python code on the victim's system
- Code execution occurs before any validation can happen

### Entry Point Identification

| Entry Point | Location | Parameter |
|-------------|----------|-----------|
| `distributed_checkpoint.load()` | API function | `checkpoint_id` |
| Direct `FileSystemReader` instantiation | Class constructor | `checkpoint_dir` |

### Required Conditions for Exploitation

| Condition | Required? | Notes |
|-----------|-----------|-------|
| User can specify checkpoint path | Yes | Primary attack vector |
| User can modify checkpoint files | Yes | Need file write access |
| No signature verification | Yes | Current state - no protection |
| Python environment executes pickle | Yes | Built-in behavior |

---

## PoC Construction Concept (Attack Idea Only)

### Attack Vector Description

The attack exploits Python's pickle deserialization behavior:

1. **Pickle Opcodes**: Pickle format supports `GLOBAL` opcode to import arbitrary modules
2. **`__reduce__` Method**: Objects can define `__reduce__` that returns `(callable, args)` - executed during unpickling
3. **Built-in Functions**: `os.system`, `subprocess.call`, `eval`, `exec` are commonly exploited

### What a Malicious Pickle Payload Could Do

| Payload Capability | Impact |
|--------------------|--------|
| Execute shell commands | Remote Code Execution (RCE) |
| Read sensitive files | Data Exfiltration |
| Modify system files | Persistence, sabotage |
| Install malware | System compromise |
| Exfiltrate credentials | Credential theft |
| Establish reverse shell | Full remote control |

### Prerequisites for the Attack

1. **Write Access**: Attacker must be able to write to the checkpoint directory
   - Could be achieved via:
     - Shared filesystem access
     - Compromised storage server
     - Malicious checkpoint distribution (supply chain)
     - Path traversal vulnerabilities in upstream systems

2. **Trigger Mechanism**: Victim must load the checkpoint
   - Normal usage scenario for distributed training
   - Could be triggered automatically in training pipelines

---

## Impact Assessment

### What an Attacker Can Achieve

| Attack Outcome | Severity | Description |
|----------------|----------|-------------|
| **Remote Code Execution** | Critical | Full control of the Python process |
| **Data Theft** | High | Access to training data, model weights, credentials |
| **Model Poisoning** | High | Inject malicious model weights |
| **System Compromise** | Critical | Pivot to other systems via RCE |
| **Supply Chain Attack** | High | Distribute poisoned checkpoints to other users |

### Affected Components and Users

| Affected Entity | Impact |
|-----------------|--------|
| Training pipelines | Complete compromise |
| Distributed training nodes | All nodes loading checkpoint are affected |
| Model weights | Can be tampered or stolen |
| Training data | Can be exfiltrated |
| Cloud environments | Container/process compromise |

### Severity Justification

- **Critical Severity** assigned due to:
  - Direct RCE capability (no privilege escalation needed)
  - No mitigations detected in code path
  - High confidence (85) - verified data flow from user input to sink
  - Common attack vector in ML/distributed systems

---

## Remediation Recommendations

### Option 1: Replace Pickle with Safe Format (Recommended)

**Replace `.metadata` pickle file with JSON or YAML:**

```python
# BEFORE (Vulnerable)
with open(metadata_file, 'rb') as f:
    metadata = pickle.load(f)

# AFTER (Safe - JSON)
import json
with open(metadata_file, 'r') as f:
    metadata_dict = json.load(f)
    metadata = Metadata.from_dict(metadata_dict)
```

**Add Metadata class serialization method:**

```python
class Metadata:
    def to_dict(self) -> dict:
        """Convert metadata to JSON-safe dictionary."""
        return {
            "state_dict_metadata": {k: v.to_dict() for k, v in self.state_dict_metadata.items()},
            "storage_data": self.storage_data,
            "planner_data": self.planner_data,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> Metadata:
        """Reconstruct metadata from dictionary."""
        return cls(**data)
```

### Option 2: Add Signature Verification

**Implement HMAC or cryptographic signature verification:**

```python
import hashlib
import hmac

# During save
def save_metadata_with_signature(metadata, metadata_file, secret_key):
    serialized = pickle.dumps(metadata)
    signature = hmac.new(secret_key, serialized, hashlib.sha256).hexdigest()
    with open(metadata_file, 'wb') as f:
        f.write(signature.encode() + '\n'.encode())
        f.write(serialized)

# During load (Verification)
def load_metadata_with_verification(metadata_file, secret_key):
    with open(metadata_file, 'rb') as f:
        signature_line = f.readline().strip()
        serialized = f.read()
    
    expected_sig = hmac.new(secret_key, serialized, hashlib.sha256).hexdigest()
    if signature_line.decode() != expected_sig:
        raise SecurityError("Metadata signature verification failed")
    
    return pickle.loads(serialized)
```

### Option 3: Use Restricted Unpickler (Defense-in-Depth)

**Implement a whitelist-based unpickler:**

```python
import pickle

class SafeUnpickler(pickle.Unpickler):
    """Whitelist-based unpickler that only allows safe classes."""
    
    SAFE_CLASSES = {
        ('builtins', 'dict'),
        ('builtins', 'list'),
        ('builtins', 'tuple'),
        ('builtins', 'str'),
        ('builtins', 'int'),
        ('builtins', 'float'),
        ('hyper_parallel.core.distributed_checkpoint.metadata', 'Metadata'),
        ('hyper_parallel.core.distributed_checkpoint.metadata', 'TensorStorageMetadata'),
    }
    
    def find_class(self, module, name):
        if (module, name) not in self.SAFE_CLASSES:
            raise pickle.UnpicklingError(
                f"Forbidden class: {module}.{name}. "
                "Only whitelisted classes are allowed for security."
            )
        return super().find_class(module, name)

# Usage
with open(metadata_file, 'rb') as f:
    unpickler = SafeUnpickler(f)
    metadata = unpickler.load()
```

### Option 4: Path Validation (Partial Mitigation)

**Add path sanitization to prevent arbitrary path access:**

```python
import os

def validate_checkpoint_path(checkpoint_dir: Path) -> Path:
    """Validate and sanitize checkpoint directory path."""
    # Resolve to absolute path
    abs_path = checkpoint_dir.resolve()
    
    # Check if path is within allowed checkpoint directories
    allowed_dirs = [Path("/trusted_checkpoints"), Path("/model_checkpoints")]
    
    for allowed in allowed_dirs:
        try:
            abs_path.relative_to(allowed.resolve())
            return abs_path
        except ValueError:
            continue
    
    raise SecurityError(f"Checkpoint path not in allowed directories: {checkpoint_dir}")
```

### Comprehensive Fix (Recommended)

Combine multiple approaches for defense-in-depth:

```python
# filesystem_storage.py - load_metadata()

def load_metadata(self, **kwargs) -> Metadata:
    """Load metadata with security verification."""
    # 1. Validate checkpoint directory path
    validated_dir = validate_checkpoint_path(self.checkpoint_dir)
    
    rank = kwargs.get("rank")
    if rank is not None:
        metadata_file = validated_dir / f".rank{rank}_metadata"
    else:
        metadata_file = validated_dir / METADATA_FILE_NAME
    
    if not metadata_file.exists():
        raise FileNotFoundError(f"Metadata file not found: {metadata_file}")
    
    # 2. Use JSON format instead of pickle (preferred)
    try:
        with open(metadata_file.with_suffix('.json'), 'r') as f:
            metadata_dict = json.load(f)
            return Metadata.from_dict(metadata_dict)
    except FileNotFoundError:
        # 3. Fallback to safe unpickler for legacy checkpoints
        with open(metadata_file, 'rb') as f:
            unpickler = SafeUnpickler(f)
            metadata = unpickler.load()
        
        # 4. Verify signature if present
        if hasattr(metadata, '_signature'):
            verify_metadata_signature(metadata)
        
        return metadata
```

---

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Python pickle Module Documentation](https://docs.python.org/3/library/pickle.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [NIST SP 800-53: SI-14 Non-persistence](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)