# VULN-lib_runtime-006: Cache Pollution

## 漏洞概述

**漏洞类型**: Improper Control of Dynamically-Managed Code Resources  
**CWE**: CWE-913 (Improper Control of Dynamically-Managed Code Resources)  
**严重程度**: Critical  
**置信度**: 85%

### 影响文件

- **文件**: `python/asc/runtime/cache.py`
- **行号**: 22-23
- **函数**: `CacheOptions.__init__`

### 漏洞描述

Cache pollution leading to arbitrary code execution. The cache directory location is entirely controlled by environment variables (`PYASC_HOME`, `PYASC_CACHE_DIR`) without integrity verification. An attacker who can set these variables can pre-populate the cache with malicious shared libraries that will be loaded during runtime.

---

## 关键代码片段

```python
# python/asc/runtime/cache.py:22-23
@dataclass(frozen=True)
class CacheOptions:
    home_dir: str = os.getenv("PYASC_HOME", os.path.expanduser("~/"))
    dir: str = os.getenv("PYASC_CACHE_DIR", os.path.join(home_dir, ".pyasc", "cache"))
```

缓存目录完全由环境变量控制，没有验证或安全检查。

---

## 数据流

```
PYASC_HOME/PYASC_CACHE_DIR env vars → CacheOptions.dir → FileCacheManager.cache_dir → get_file() returns attacker-controlled path
```

---

## 攻击分析

### 缓存污染步骤

1. 设置 `PYASC_CACHE_DIR=/tmp/attacker_cache`
2. 创建恶意缓存文件（pickle payload、恶意 .so 文件）
3. 计算正确的缓存 key（基于源代码 hash）
4. 放置恶意文件到对应缓存目录
5. pyasc 运行时自动加载恶意缓存

### 缓存目录结构

```
<cache_base>/<base32_hash>/kernel.o          # pickle 缓存
<cache_base>/<base32_hash>/librt_wrapper.so  # 运行时库
<cache_base>/<base32_hash>/libnpu_utils.so   # NPU 工具库
<cache_base>/<base32_hash>/print_interface.so # 打印接口库
```

---

## 影响分析

缓存污染是以下漏洞的根本原因：
- VULN-SEC-RUN-001: pickle 反序列化
- VULN-SEC-RT-001: ctypes.CDLL 加载
- VULN-SEC-RT-003: importlib 模块加载
- VULN-lib_runtime-001/002/003: 各种加载点

---

## 修复建议

### 优先级 1: 禁止环境变量控制缓存目录

```python
# 强制使用固定缓存目录
SECURE_CACHE_BASE = os.path.expanduser("~/.pyasc")

@dataclass(frozen=True)
class CacheOptions:
    home_dir: str = SECURE_CACHE_BASE
    dir: str = os.path.join(home_dir, "cache")
    
    # 不从环境变量读取，发出警告
    @classmethod
    def create(cls):
        env_cache = os.getenv('PYASC_CACHE_DIR')
        if env_cache:
            warnings.warn("PYASC_CACHE_DIR is ignored for security. Using fixed cache directory.")
        return cls()
```

### 优先级 2: 缓存完整性验证

```python
class SecureCacheManager:
    def __init__(self, key: str):
        self.cache_dir = SECURE_CACHE_DIR
        self.key = key
        
    def verify_file(self, filepath: str) -> bool:
        # 验证文件签名或 hash
        ...
```

---

## 相关漏洞

- **VULN-SEC-RUN-001**: pickle 反序列化（攻击下游）
- **VULN-SEC-RT-001**: ctypes.CDLL 加载（攻击下游）
- **VULN-SEC-RT-003**: importlib 模块加载（攻击下游）
- **VULN-CROSS-001**: 环境变量攻击链
- **VULN-CROSS-004**: 缓存完整性攻击链