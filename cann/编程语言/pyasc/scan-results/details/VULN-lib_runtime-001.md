# VULN-lib_runtime-001: Unsafe Dynamic Library Loading

## 漏洞概述

**漏洞类型**: Unsafe Dynamic Library Loading  
**CWE**: CWE-427 (Use of Uncontrolled Search Path Element)  
**严重程度**: Critical  
**置信度**: 85%

### 影响文件

- **文件**: `python/asc/lib/runtime/state.py`
- **行号**: 50
- **函数**: `RuntimeInterface.__init__`

### 漏洞描述

Uncontrolled search path element leads to arbitrary code execution. The `ctypes.CDLL()` loads a shared library from a cache path that is controlled by environment variables (`PYASC_HOME`, `PYASC_CACHE_DIR`). An attacker who can set these environment variables can place a malicious library in the cache directory, which will be loaded and executed with the privileges of the Python process.

---

## 数据流

```
PYASC_HOME/PYASC_CACHE_DIR env vars → CacheOptions.dir → FileCacheManager.cache_dir → cache_manager.get_file() → rt_lib → ctypes.CDLL(rt_lib)
```

---

## 详细分析

此漏洞与 **VULN-SEC-RT-001** 完全相同，只是由不同的扫描 Agent 报告。详见 VULN-SEC-RT-001 的完整分析报告。

---

## 相关漏洞

- **VULN-SEC-RT-001**: 相同漏洞（详细分析）
- **VULN-lib_runtime-002**: importlib 模块加载
- **VULN-lib_runtime-003**: PrintInterface 加载
- **VULN-lib_runtime-006**: 缓存污染
- **VULN-CROSS-001**: 环境变量攻击链
- **VULN-CROSS-004**: 缓存完整性攻击链