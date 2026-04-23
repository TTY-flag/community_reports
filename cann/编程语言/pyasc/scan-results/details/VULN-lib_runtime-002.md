# VULN-lib_runtime-002: Unsafe Dynamic Module Loading

## 漏洞概述

**漏洞类型**: Unsafe Dynamic Module Loading  
**CWE**: CWE-427 (Use of Uncontrolled Search Path Element)  
**严重程度**: Critical  
**置信度**: 85%

### 影响文件

- **文件**: `python/asc/lib/runtime/state.py`
- **行号**: 110-114
- **函数**: `NPUUtils.__init__`

### 漏洞描述

Arbitrary code execution via `importlib.util.spec_from_file_location()`. The `utils_lib` path is retrieved from an environment-controlled cache and loaded as a Python module without integrity verification. An attacker can place a malicious .so file in the cache to achieve arbitrary code execution.

---

## 数据流

```
PYASC_HOME/PYASC_CACHE_DIR env vars → cache_manager.get_file() → utils_lib → importlib.util.spec_from_file_location() → exec_module()
```

---

## 详细分析

此漏洞与 **VULN-SEC-RT-003** 完全相同，只是由不同的扫描 Agent 报告。详见 VULN-SEC-RT-003 的完整分析报告。

---

## 相关漏洞

- **VULN-SEC-RT-003**: 相同漏洞（详细分析）
- **VULN-lib_runtime-001**: ctypes.CDLL 加载
- **VULN-lib_runtime-006**: 缓存污染
- **VULN-CROSS-001**: 环境变量攻击链