# Vulnerability Report: Type Confusion in QoS Environment Variable Handling

## Vulnerability Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | core-qos-env-type-confusion-20 |
| **Type** | Type Confusion (CWE-704) |
| **Severity** | Medium |
| **Confidence** | 85% → **Confirmed 100%** |
| **CWE** | CWE-704: Incorrect Type Conversion or Cast |
| **File** | `mindspeed/core/qos/qos.py` |
| **Lines** | 20-26 |

## Description

Environment variables `QOS_SDMA_*` and `QOS_ROCE_*` are read using `os.environ.get()` with integer default values. However, `os.environ.get()` returns a **STRING** when the environment variable exists, regardless of the default value type. This creates type confusion:

```python
# If QOS_SDMA_LOW="abc" is set, returns string "abc"
# If QOS_SDMA_LOW is not set, returns integer 2
_DEFAULT_QOS_SDMA_LOW = os.environ.get('QOS_SDMA_LOW', 2)  # BUG!
```

This leads to:
1. **TypeError** when comparing strings with integers
2. **Silent comparison failures** with lexicographic ordering
3. **Application crash** during QoS initialization

## Vulnerable Code

### Primary Vulnerability (qos.py:20-26)
```python
_DEFAULT_QOS_SDMA_LOW = os.environ.get('QOS_SDMA_LOW', 2)
_DEFAULT_QOS_SDMA_MIDDLE = os.environ.get('QOS_SDMA_MIDDLE', 4)
_DEFAULT_QOS_SDMA_HIGH = os.environ.get('QOS_SDMA_HIGH', 6)

_DEFAULT_QOS_ROCE_LOW = os.environ.get('QOS_ROCE_LOW', 3)
_DEFAULT_QOS_ROCE_MIDDLE = os.environ.get('QOS_ROCE_MIDDLE', 4)
_DEFAULT_QOS_ROCE_HIGH = os.environ.get('QOS_ROCE_HIGH', 5)
```

### Critical Impact Points

#### 1. TypeError in Validation (adaptor.py:72)
```python
if not (0 <= roce_qos <= 7) or not (0 <= sdma_qos <= 7):
    # If qos is string "abc", raises: TypeError: '<=' not supported between 'str' and 'int'
```

#### 2. TypeError in max() Operation (qos.py:269, 280)
```python
# Line 269
self.sdma_aiqos_schedule['tp-ep-mp'] = max(self.sdma_aiqos_schedule['pp'], self.sdma_aiqos_schedule['tp'])

# Line 280
self.roce_aiqos_schedule['tp-ep-mp'] = max(self.roce_aiqos_schedule['pp'],
                                           self.roce_aiqos_schedule['tp'])
# If one is string and one is int: TypeError
# If both are strings: wrong lexicographic comparison (e.g., max("5", "10") = "5")
```

## Attack Scenario

### Scenario 1: Denial of Service via Invalid String
```bash
# Attacker sets environment variable to non-numeric string
export QOS_SDMA_LOW="abc"
export QOS_SDMA_HIGH="xyz"

# Application crashes during initialization
# TypeError: '<=' not supported between instances of 'str' and 'int'
```

### Scenario 2: Silent Logic Error via String Numbers
```bash
# Attacker sets environment variable (intended as number but read as string)
export QOS_SDMA_LOW="10"
export QOS_SDMA_MIDDLE="4"
export QOS_SDMA_HIGH="6"

# Comparison fails silently
# max("10", "4") returns "4" (lexicographic), not "10"
# Line 269: self.sdma_aiqos_schedule['tp-ep-mp'] gets wrong value
```

### Scenario 3: Boundary Bypass
```bash
# Attacker sets out-of-range value that passes string comparison
export QOS_ROCE_LOW="100"

# Passes boundary check: 0 <= "100" <= 7 is False (string comparison)
# But then used as integer elsewhere causing issues
```

## Proof of Concept

```python
#!/usr/bin/env python3
"""PoC demonstrating the type confusion vulnerability"""

import os

# Simulate the vulnerable code
os.environ['QOS_SDMA_LOW'] = 'abc'
os.environ['QOS_SDMA_HIGH'] = '10'

# This is the actual vulnerable pattern
_DEFAULT_QOS_SDMA_LOW = os.environ.get('QOS_SDMA_LOW', 2)
_DEFAULT_QOS_SDMA_HIGH = os.environ.get('QOS_SDMA_HIGH', 6)

print(f"QOS_SDMA_LOW type: {type(_DEFAULT_QOS_SDMA_LOW)}, value: {_DEFAULT_QOS_SDMA_LOW}")
print(f"QOS_SDMA_HIGH type: {type(_DEFAULT_QOS_SDMA_HIGH)}, value: {_DEFAULT_QOS_SDMA_HIGH}")

# This will crash with TypeError
try:
    if not (0 <= _DEFAULT_QOS_SDMA_LOW <= 7):
        print("Out of range")
except TypeError as e:
    print(f"TypeError caught: {e}")

# This will give wrong result
print(f"max('10', '4') = {max(_DEFAULT_QOS_SDMA_HIGH, '4')}")  # Returns '4', not '10'
```

**Output:**
```
QOS_SDMA_LOW type: <class 'str'>, value: abc
QOS_SDMA_HIGH type: <class 'str'>, value: 10
TypeError caught: '<=' not supported between instances of 'str' and 'int'
max('10', '4') = 4  # Wrong! Should be 10
```

## Data Flow Analysis

```
Environment Variables (QOS_SDMA_*, QOS_ROCE_*)
    ↓
os.environ.get() [NO TYPE CONVERSION]
    ↓
_DEFAULT_QOS_* variables (str or int, unpredictable)
    ↓
sdma_qos_str_to_value / roce_qos_str_to_value dictionaries
    ↓
Qos.__init__ → self.sdma_queue_list / self.roce_queue_list
    ↓
init_qos() → self.*_aiqos_schedule dictionaries
    ↓
[CRASH POINT 1] adaptor.py:72 - Range validation with <= operator
[CRASH POINT 2] qos.py:269,280 - max() function with mixed types
[CRASH POINT 3] Passed to torch_npu HCCL config as QoS priority
```

## Impact Assessment

| Impact Area | Severity | Description |
|-------------|----------|-------------|
| **Availability** | High | Application crash on startup with invalid env vars |
| **Integrity** | Medium | Incorrect QoS priority assignment affecting network scheduling |
| **Confidentiality** | Low | No direct data exposure |
| **Attack Complexity** | Low | Simple environment variable manipulation |
| **Privileges Required** | Medium | Requires access to deployment environment |

### Affected Components
- QoS (Quality of Service) configuration system
- Network communication priority scheduling
- HCCL (Huawei Collective Communication Library) configuration
- All parallel processing groups (tensor, pipeline, data, expert parallel)

## Exploitation Prerequisites

1. **Access to environment variables** - Typically requires:
   - Deployment configuration access
   - Container orchestration access (Kubernetes ConfigMaps, etc.)
   - Shell access to the runtime environment

2. **Trigger conditions**:
   - Application using QoS features (`aiqos_mode` enabled)
   - Running with expert model parallel or specific parallel configurations

## Fix Recommendations

### Immediate Fix
```python
# Add int() conversion with validation
def get_qos_env_int(var_name: str, default: int, min_val: int = 0, max_val: int = 7) -> int:
    """Safely read integer QoS value from environment variable."""
    value = os.environ.get(var_name, str(default))
    try:
        int_value = int(value)
        if not (min_val <= int_value <= max_val):
            raise ValueError(f"{var_name}={int_value} out of range [{min_val}, {max_val}]")
        return int_value
    except ValueError as e:
        raise ValueError(f"Invalid {var_name}='{value}': must be integer in range [{min_val}, {max_val}]") from e

_DEFAULT_QOS_SDMA_LOW = get_qos_env_int('QOS_SDMA_LOW', 2, 0, 7)
_DEFAULT_QOS_SDMA_MIDDLE = get_qos_env_int('QOS_SDMA_MIDDLE', 4, 0, 7)
_DEFAULT_QOS_SDMA_HIGH = get_qos_env_int('QOS_SDMA_HIGH', 6, 0, 7)
_DEFAULT_QOS_ROCE_LOW = get_qos_env_int('QOS_ROCE_LOW', 3, 0, 7)
_DEFAULT_QOS_ROCE_MIDDLE = get_qos_env_int('QOS_ROCE_MIDDLE', 4, 0, 7)
_DEFAULT_QOS_ROCE_HIGH = get_qos_env_int('QOS_ROCE_HIGH', 5, 0, 7)
```

### Alternative Minimal Fix
```python
_DEFAULT_QOS_SDMA_LOW = int(os.environ.get('QOS_SDMA_LOW', '2'))
_DEFAULT_QOS_SDMA_MIDDLE = int(os.environ.get('QOS_SDMA_MIDDLE', '4'))
_DEFAULT_QOS_SDMA_HIGH = int(os.environ.get('QOS_SDMA_HIGH', '6'))
_DEFAULT_QOS_ROCE_LOW = int(os.environ.get('QOS_ROCE_LOW', '3'))
_DEFAULT_QOS_ROCE_MIDDLE = int(os.environ.get('QOS_ROCE_MIDDLE', '4'))
_DEFAULT_QOS_ROCE_HIGH = int(os.environ.get('QOS_ROCE_HIGH', '5'))
```

## Verification Status

| Check | Status |
|-------|--------|
| Vulnerability Confirmed | ✅ YES |
| Exploitable | ✅ YES |
| Production Impact | ✅ YES (DoS, Logic Errors) |
| Fix Verified | ⬜ Not yet applied |

## References

- [CWE-704: Incorrect Type Conversion or Cast](https://cwe.mitre.org/data/definitions/704.html)
- [Python os.environ.get() Documentation](https://docs.python.org/3/library/os.html#os.environ)
- [Python Type Conversion Best Practices](https://docs.python.org/3/library/functions.html#int)

## Conclusion

This is a **genuine type confusion vulnerability** that can lead to:
1. **Application crashes** (DoS) when non-numeric strings are provided
2. **Incorrect QoS scheduling** when numeric strings bypass validation
3. **Silent logic errors** from lexicographic string comparisons

The vulnerability is confirmed through code analysis of the data flow from environment variables through to HCCL configuration. The fix is straightforward and should be applied to ensure robust type handling of configuration inputs.
