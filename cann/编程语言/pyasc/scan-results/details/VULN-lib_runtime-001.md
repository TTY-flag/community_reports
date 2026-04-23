# VULN-lib_runtime-001：不安全动态库加载漏洞

## 漏洞概述

**漏洞类型**: 不安全动态库加载  
**CWE**: CWE-427 (Use of Uncontrolled Search Path Element)  
**严重程度**: Critical  
**置信度**: 85%

### 影响文件

- **文件**: `python/asc/lib/runtime/state.py`
- **行号**: 50
- **函数**: `RuntimeInterface.__init__`

### 漏洞描述

不可控搜索路径元素导致任意代码执行。`ctypes.CDLL()` 从由环境变量（`PYASC_HOME`、`PYASC_CACHE_DIR`）控制的缓存路径加载共享库。攻击者若能设置这些环境变量，可在缓存目录中放置恶意库，该库将以 Python 进程权限加载并执行。

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