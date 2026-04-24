# VULN-DF-002: Insecure Pickle Deserialization in Bytes Data Loading

## Vulnerability Overview

| Attribute | Value |
|-----------|-------|
| **ID** | VULN-DF-002 |
| **CWE** | CWE-502: Deserialization of Untrusted Data |
| **Severity** | Critical |
| **Confidence** | 82 |
| **Type** | insecure_deserialization |
| **File** | `hyper_parallel/core/distributed_checkpoint/standard_planner.py` |
| **Lines** | 575-577 |
| **Function** | `StandardLoadPlanner.apply_bytes` |

### CWE-502 Description

CWE-502 describes the deserialization of untrusted data. Python's `pickle.loads()` function can execute arbitrary code during deserialization when processing malicious payloads, enabling Remote Code Execution (RCE) attacks.

---

## Root Cause Analysis

### Vulnerable Code Location

```python
# standard_planner.py:574-577
fqn = read_item.dest_index.fqn
# Deserialize bytes
obj = pickle.loads(value)
self.state_dict[fqn] = obj
```

### Code Logic Flaw

The vulnerability exists because:

1. **Unchecked Deserialization**: `pickle.loads(value)` is called directly on bytes data
2. **User-Controlled Data Source**: `value` originates from checkpoint files in user-controlled directory
3. **No Content Validation**: No integrity checks on the bytes content before deserialization
4. **Direct State Dict Modification**: Deserialized object is directly stored in application state

### Complete Data Flow Trace

```
User Input (checkpoint_id)
    │
    ▼
distributed_checkpoint.load()
    │  [SOURCE: Entry point]
    ▼
_load_bytes_file(path, reqs, planner, storage_data)
    │  path = user-controlled checkpoint directory
    │  [filesystem_storage.py:294]
    ▼
Read bytes from checkpoint file
    │  bytes_file = path / f"{fqn}.bytes"
    │  value = bytes_file.read_bytes()  [User-controlled content]
    │
    ▼
planner.apply_bytes(req, value)
    │  [filesystem_storage.py:317]
    ▼
pickle.loads(value)
    │  [SINK: CWE-502 - Arbitrary code execution]
    ▼
obj (potentially malicious object)
    │
    ▼
self.state_dict[fqn] = obj
    │  [Malicious object injected into application state]
```

### Attacker Control Points

| Control Point | Location | Attacker Capability |
|---------------|----------|---------------------|
| `checkpoint_id` | API entry | Full control of checkpoint path |
| Bytes file path | `_load_bytes_file` | Can place malicious `.bytes` files |
| Bytes file content | File system | Can craft pickle payload with arbitrary code |

---

## Attack Path Analysis

### Step-by-Step Attack Scenario

**Step 1: Identify Target Bytes Files**
```
Attacker analyzes checkpoint structure:
/malicious_checkpoint/
├── .metadata
├── layer1.weight.bytes    <- Target for exploitation
├── layer2.weight.bytes
└── ...
```

**Step 2: Craft Poisoned Bytes File**
```
Replace: layer1.weight.bytes
Content: Malicious pickle payload
```

**Step 3: Trigger Vulnerability**
```python
# Victim code - normal distributed checkpoint loading
distributed_checkpoint.load(state_dict, "/malicious_checkpoint")
```

**Step 4: Exploitation Chain**
```
1. _load_bytes_file() reads poisoned bytes file
2. planner.apply_bytes(req, malicious_value) called
3. pickle.loads(malicious_value) executes payload
4. Arbitrary code runs in training process
5. Malicious object stored in state_dict[fqn]
```

### Entry Point Identification

| Entry Point | Module | Parameter |
|-------------|--------|-----------|
| `distributed_checkpoint.load()` | API | `checkpoint_id` |
| `_load_bytes_file()` | filesystem_storage | `path` (derived from checkpoint_id) |

### Required Conditions for Exploitation

| Condition | Required? | Notes |
|-----------|-----------|-------|
| Bytes files in checkpoint | Yes | Part of standard checkpoint format |
| Pickle serialization in bytes files | Yes | Current implementation |
| File write access to checkpoint | Yes | Attack vector |
| Training process loads checkpoint | Yes | Trigger condition |

---

## PoC Construction Concept (Attack Idea Only)

### Attack Vector Description

The bytes file exploitation approach:

1. **File Format**: `.bytes` files are raw pickle-serialized objects
2. **Direct Deserialization**: `pickle.loads()` directly processes file contents
3. **No Intermediate Validation**: Bytes are deserialized immediately after reading

### What a Malicious Pickle Payload Could Do

| Payload Type | Capability |
|--------------|------------|
| **RCE Payload** | Execute arbitrary shell commands via `os.system`, `subprocess.Popen` |
| **Backdoor Installation** | Create persistent access mechanism |
| **Data Exfiltration** | Read and transmit sensitive data |
| **Model Poisoning** | Inject malicious weights that cause incorrect outputs |
| **Crypto Mining** | Install cryptocurrency miner |

### Prerequisites for the Attack

1. **Checkpoint File Access**:
   - Shared NFS/distributed filesystem
   - Cloud storage bucket (S3, GCS, Azure Blob)
   - Downloaded checkpoint from untrusted source
   - Supply chain compromise (pre-trained model repository)

2. **Execution Trigger**:
   - Distributed training job loading checkpoint
   - Model fine-tuning pipeline
   - Resume training from checkpoint

---

## Impact Assessment

### What an Attacker Can Achieve

| Attack Outcome | Impact Level | Description |
|----------------|--------------|-------------|
| **Remote Code Execution** | Critical | Full control of training node |
| **State Dict Manipulation** | High | Inject malicious objects into model state |
| **Training Pipeline Compromise** | Critical | All subsequent training steps affected |
| **Credential Theft** | High | Access to API keys, secrets in environment |
| **Data Breach** | High | Exfiltrate training data, proprietary models |

### Affected Components and Users

| Affected Entity | Scope |
|-----------------|-------|
| Training nodes | All nodes in distributed cluster |
| Model state | Potentially all state dict entries loaded from bytes |
| Training data | Accessible via RCE |
| Cloud credentials | Environment variables, mounted secrets |
| Downstream consumers | Poisoned models propagated to inference |

### Severity Justification

**Critical** severity justified by:
- Verified data flow: User input → bytes file → `pickle.loads()` → state dict
- No mitigations detected in code path
- High confidence (82) from cross-file verification
- RCE capability without privilege escalation

---

## Remediation Recommendations

### Option 1: Use Safe Serialization Format (Recommended)

**Replace pickle bytes with safe alternatives:**

```python
# BEFORE (Vulnerable)
obj = pickle.loads(value)
self.state_dict[fqn] = obj

# AFTER (Safe - JSON for simple types, safetensors for tensors)
import json

def apply_bytes(self, read_item: ReadItem, value: bytes) -> None:
    fqn = read_item.dest_index.fqn
    
    # Use JSON for bytes data instead of pickle
    try:
        obj = json.loads(value.decode('utf-8'))
        # Convert JSON representation back to appropriate type
        if obj.get('_type') == 'tensor_metadata':
            obj = TensorMetadata.from_dict(obj)
        self.state_dict[fqn] = obj
    except json.JSONDecodeError:
        raise ValueError(f"Invalid bytes format for {fqn}")
```

### Option 2: Implement Safe Unpickler with Whitelist

```python
import pickle

class BytesSafeUnpickler(pickle.Unpickler):
    """Whitelist unpickler for bytes data - only allows basic types."""
    
    ALLOWED_TYPES = {
        # Basic built-in types only
        ('builtins', 'dict'),
        ('builtins', 'list'),
        ('builtins', 'tuple'),
        ('builtins', 'set'),
        ('builtins', 'frozenset'),
        ('builtins', 'str'),
        ('builtins', 'int'),
        ('builtins', 'float'),
        ('builtins', 'bool'),
        ('builtins', 'bytes'),
        ('builtins', 'NoneType'),
        # Framework types (add as needed)
        ('hyper_parallel.core.distributed_checkpoint.metadata', 'TensorStorageMetadata'),
    }
    
    def find_class(self, module: str, name: str):
        key = (module, name)
        if key not in self.ALLOWED_TYPES:
            raise pickle.UnpicklingError(
                f"Blocked dangerous type: {module}.{name}. "
                "Bytes files can only contain basic types."
            )
        return super().find_class(module, name)

# In apply_bytes
def apply_bytes(self, read_item: ReadItem, value: bytes) -> None:
    fqn = read_item.dest_index.fqn
    unpickler = BytesSafeUnpickler(value)
    obj = unpickler.load()
    self.state_dict[fqn] = obj
```

### Option 3: Add Integrity Verification

```python
import hashlib

def apply_bytes(self, read_item: ReadItem, value: bytes, expected_hash: str = None) -> None:
    """Apply bytes with hash verification."""
    fqn = read_item.dest_index.fqn
    
    # Verify hash if provided (from metadata)
    if expected_hash:
        actual_hash = hashlib.sha256(value).hexdigest()
        if actual_hash != expected_hash:
            raise SecurityError(
                f"Bytes content hash mismatch for {fqn}. "
                f"Expected: {expected_hash}, Got: {actual_hash}"
            )
    
    # Safe unpickler after verification
    unpickler = BytesSafeUnpickler(value)
    obj = unpickler.load()
    self.state_dict[fqn] = obj
```

### Option 4: Content-Type Validation

```python
def apply_bytes(self, read_item: ReadItem, value: bytes) -> None:
    """Apply bytes with content validation."""
    fqn = read_item.dest_index.fqn
    
    # Check for pickle magic bytes and reject
    PICKLE_MAGIC = [
        b'\x80\x01',  # Protocol 1
        b'\x80\x02',  # Protocol 2
        b'\x80\x03',  # Protocol 3
        b'\x80\x04',  # Protocol 4
        b'\x80\x05',  # Protocol 5
    ]
    
    if value[:2] in PICKLE_MAGIC:
        # Use safe unpickler only
        unpickler = BytesSafeUnpickler(value)
        obj = unpickler.load()
    else:
        # Try JSON fallback
        obj = json.loads(value.decode('utf-8'))
    
    self.state_dict[fqn] = obj
```

### Comprehensive Fix

```python
# standard_planner.py - apply_bytes()

def apply_bytes(self, read_item: ReadItem, value: bytes, metadata: Metadata = None) -> None:
    """
    Load bytes data into state_dict with security validation.
    
    Args:
        read_item: The read item specifying destination
        value: Bytes data to load
        metadata: Metadata containing expected hashes
    """
    if self.state_dict is None:
        raise RuntimeError("Planner not set up")
    
    fqn = read_item.dest_index.fqn
    
    # 1. Verify content hash if metadata provides it
    if metadata and hasattr(metadata, 'bytes_hashes'):
        expected_hash = metadata.bytes_hashes.get(fqn)
        if expected_hash:
            actual_hash = hashlib.sha256(value).hexdigest()
            if actual_hash != expected_hash:
                raise SecurityError(f"Hash mismatch for {fqn}")
    
    # 2. Detect format and use appropriate safe loader
    if value[:2] in (b'\x80\x01', b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05'):
        # Pickle format - use whitelist unpickler
        unpickler = BytesSafeUnpickler(value)
        obj = unpickler.load()
    else:
        # JSON format (preferred)
        obj = json.loads(value.decode('utf-8'))
    
    # 3. Type validation
    if not isinstance(obj, (dict, list, tuple, str, int, float, bool, bytes, type(None))):
        raise SecurityError(f"Unsafe object type for {fqn}: {type(obj)}")
    
    self.state_dict[fqn] = obj
    
    if self.flatten_state_dict:
        set_element(self.original_state_dict, self.name_mapping[fqn], obj)
```

---

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Python pickle Security Considerations](https://docs.python.org/3/library/pickle.html#security-considerations)
- [OWASP Unsafe Deserialization Prevention](https://owasp.org/www-community/vulnerabilities/Unsafe_deserialization)
- [PyTorch Load Weights Safely](https://pytorch.org/docs/stable/generated/torch.load.html)