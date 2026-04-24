# VULN-SEC-DES-002: Insecure Pickle Deserialization in Bytes Data Loading

## Vulnerability Overview

| Attribute | Value |
|-----------|-------|
| **ID** | VULN-SEC-DES-002 |
| **CWE** | CWE-502: Deserialization of Untrusted Data |
| **Severity** | Critical |
| **Confidence** | 82 |
| **Type** | insecure_deserialization |
| **File** | `hyper_parallel/core/distributed_checkpoint/standard_planner.py` |
| **Lines** | 574-577 |
| **Function** | `StandardLoadPlanner.apply_bytes` |

### Relationship to VULN-DF-002

This vulnerability is a **duplicate detection** of VULN-DF-002, identified by a different scanner agent:
- **VULN-DF-002**: Detected by `dataflow-scanner` agent
- **VULN-SEC-DES-002**: Detected by `security-auditor` agent

Both reports describe the same vulnerable code location and attack vector. The independent detection by multiple agents increases confidence in the vulnerability's validity.

---

## Root Cause Analysis

### Vulnerable Code Location

```python
# standard_planner.py:574-577
fqn = read_item.dest_index.fqn
obj = pickle.loads(value)
self.state_dict[fqn] = obj
```

### Code Logic Flaw

The same vulnerability as VULN-DF-002:

1. **`pickle.loads(value)`** directly deserializes bytes from checkpoint files
2. **No validation** of bytes content before deserialization
3. **User-controlled checkpoint path** enables arbitrary file access
4. **Arbitrary code execution** during pickle unpickling

### Data Flow (Security Auditor Trace)

```
distributed_checkpoint.load() [ENTRY]
    │
    ▼
_load_bytes_file(path, reqs, planner, storage_data)
    │  [filesystem_storage.py:294]
    │  Reads bytes from user-controlled path
    ▼
planner.apply_bytes(req, value)
    │  [filesystem_storage.py:317]
    ▼
pickle.loads(value)
    │  [SINK, line 576 - CWE-502]
    ▼
obj (arbitrary Python object)
    │
    ▼
self.state_dict[fqn] = obj
```

---

## Attack Path Analysis

### Attack Scenario (Same as VULN-DF-002)

1. **Attacker crafts malicious bytes file** in checkpoint directory
2. **Victim loads checkpoint** via `distributed_checkpoint.load()`
3. **Bytes file deserialized** via `pickle.loads()`
4. **Arbitrary code executes** in training process

### Multi-Detector Confidence Boost

| Agent | Detection Method | Confidence |
|-------|-----------------|------------|
| dataflow-scanner | Data flow tracking | 82 |
| security-auditor | Security pattern matching | 82 |
| **Combined** | Cross-validation | **High confidence** |

---

## PoC Construction Concept

Same attack vector as VULN-DF-002. See VULN-DF-002.md for detailed attack concept.

### Attack Idea Summary

- Craft malicious `.bytes` file with pickle payload
- Payload executes during `pickle.loads(value)` call
- Can achieve RCE, data theft, model poisoning

---

## Impact Assessment

Same impact as VULN-DF-002:
- **Remote Code Execution** on training nodes
- **State dict manipulation** via malicious objects
- **Credential theft** and **data exfiltration**
- **Supply chain attack** via poisoned checkpoints

---

## Remediation Recommendations

Same fixes apply as VULN-DF-002:

### Recommended Fix: Safe Unpickler with Whitelist

```python
import pickle

class BytesSafeUnpickler(pickle.Unpickler):
    ALLOWED_TYPES = {
        ('builtins', 'dict'),
        ('builtins', 'list'),
        ('builtins', 'tuple'),
        ('builtins', 'str'),
        ('builtins', 'int'),
        ('builtins', 'float'),
        ('builtins', 'bool'),
        ('builtins', 'bytes'),
        ('builtins', 'NoneType'),
    }
    
    def find_class(self, module: str, name: str):
        if (module, name) not in self.ALLOWED_TYPES:
            raise pickle.UnpicklingError(f"Blocked: {module}.{name}")
        return super().find_class(module, name)

# Apply in apply_bytes()
def apply_bytes(self, read_item: ReadItem, value: bytes) -> None:
    fqn = read_item.dest_index.fqn
    unpickler = BytesSafeUnpickler(value)
    obj = unpickler.load()
    self.state_dict[fqn] = obj
```

### Additional: Hash Verification

```python
# Store hashes in metadata during checkpoint save
# Verify hashes during load before deserialization
```

---

## Deduplication Notes

| Field | VULN-DF-002 | VULN-SEC-DES-002 |
|-------|-------------|------------------|
| Source Agent | dataflow-scanner | security-auditor |
| Line Range | 575-577 | 574-577 |
| Detection Method | Data flow analysis | Security pattern |

**Recommendation**: Merge reports in final vulnerability summary. Both identify the same root cause and remediation.

---

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- See VULN-DF-002.md for complete technical analysis