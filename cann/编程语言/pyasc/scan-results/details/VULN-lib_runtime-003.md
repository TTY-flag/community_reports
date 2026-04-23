# VULN-lib_runtime-003: PrintInterface Unsafe Loading

## 漏洞概述

**漏洞类型**: Unsafe Dynamic Library Loading  
**CWE**: CWE-427 (Use of Uncontrolled Search Path Element)  
**严重程度**: Critical  
**置信度**: 85%

### 影响文件

- **文件**: `python/asc/lib/runtime/print_utils.py`
- **行号**: 70
- **函数**: `PrintInterface.__init__`

### 漏洞描述

Uncontrolled search path element in `PrintInterface.__init__`. Similar to `RuntimeInterface`, this loads a shared library from an environment-controlled cache using `ctypes.cdll.LoadLibrary()`. An attacker can exploit the same cache pollution vector.

---

## 关键代码片段

```python
# python/asc/lib/runtime/print_utils.py:70
self.lib: ctypes.CDLL = ctypes.cdll.LoadLibrary(rt_lib)
```

---

## 数据流

```
PYASC_HOME/PYASC_CACHE_DIR env vars → cache_manager.get_file() → rt_lib → ctypes.cdll.LoadLibrary(rt_lib)
```

---

## 攻击分析

与 RuntimeInterface (VULN-SEC-RT-001) 类似的攻击向量：

1. 设置 `PYASC_CACHE_DIR=/tmp/attacker_cache`
2. 创建恶意 `print_interface.so` 文件
3. 放置到正确的缓存位置
4. PrintInterface 初始化时加载恶意库
5. 恶意库的 constructor 自动执行

---

## 修复建议

与 VULN-SEC-RT-001 相同的修复方案：
1. 库签名验证
2. 固定缓存目录
3. 内容 hash 验证

---

## 相关漏洞

- **VULN-SEC-RT-001**: RuntimeInterface 加载（相同攻击向量）
- **VULN-lib_runtime-001**: 相同漏洞类型
- **VULN-lib_runtime-006**: 缓存污染（根源）
- **VULN-CROSS-001**: 环境变量攻击链