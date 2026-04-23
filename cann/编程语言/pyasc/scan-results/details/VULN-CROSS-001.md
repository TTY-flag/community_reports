# VULN-CROSS-001：跨模块环境变量攻击链漏洞

## 漏洞概述

| 属性 | 值 |
|------|------|
| **漏洞ID** | VULN-CROSS-001 |
| **漏洞类型** | 环境变量注入攻击链 (Environment Variable Chain Attack) |
| **CWE** | CWE-78 (OS Command Injection) |
| **严重程度** | Critical |
| **置信度** | 95% (已通过源代码验证) |
| **攻击复杂度** | Low |
| **攻击向量** | Local |

### 影响模块和文件

| 文件路径 | 环境变量 | 危险函数 |
|----------|----------|----------|
| `python/asc/runtime/compiler.py:106-113` | `PYASC_COMPILER`, `PYASC_LINKER` | `shutil.which()` → `subprocess.Popen()` |
| `python/asc/runtime/compiler.py:98-103` | `PYASC_DUMP_PATH` | 文件写入路径控制 |
| `python/asc/runtime/cache.py:22-23` | `PYASC_HOME`, `PYASC_CACHE_DIR` | 缓存目录控制 |
| `python/asc/lib/utils.py:18-21` | `ASCEND_HOME_PATH` | SDK路径控制 |
| `python/asc/lib/utils.py:26-35` | `CXX`, `CC` | 编译器路径控制 |
| `python/asc/lib/runtime/build_utils.py:24-27` | `ASCEND_HOME_PATH` | SDK路径控制 |
| `python/asc/lib/runtime/build_utils.py:34-40` | `CC` | 编译器路径控制 |
| `python/asc/lib/runtime/print_utils.py:29-35` | `CC` | 编译器路径控制 |
| `python/asc/lib/host/loader.py:28-50` | 间接依赖上述变量 | `subprocess.check_call()` |

---

## 漏洞详情分析

### 1. 编译器/链接器劫持 (compiler.py)

**危险代码位置: 第106-113行**
```python
# Line 106-109: 编译器路径由环境变量控制
compiler = shutil.which(os.environ.get("PYASC_COMPILER", "bisheng"))
if compiler is None:
    raise RuntimeError("Compiler executable is not found, check PYASC_COMPILER environment variable")
self.compiler = compiler

# Line 110-113: 链接器路径由环境变量控制  
linker = shutil.which(os.environ.get("PYASC_LINKER", "ld.lld"))
if linker is None:
    raise RuntimeError("Linker executable is not found, check PYASC_LINKER environment variable")
self.linker = linker
```

**危险调用位置: 第146行, 第155行**
```python
# Line 145-147: 执行编译命令
@staticmethod
def _run_cmd(cmd: List[str], cmd_type: str) -> None:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
    # ...
    # Line 155: 失败后重试，再次执行
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
```

**链接器调用位置: 第298-304行, 第314-328行**
```python
# Line 298-304: 混合kernel链接
link_cmd = [
    self.linker, "-m", "aicorelinux", "-Ttext=0",
    "%s" % str(dst_cube_file),
    "%s" % str(dst_vec_file), "-static", "-o",
    "%s" % str(dst)
]
self._run_cmd(link_cmd, "link")
```

**问题分析**:
- `shutil.which()` 查找的可执行文件来自 PATH 环境变量
- 如果攻击者能在 PATH 中放置恶意 `bisheng` 或 `ld.lld`，即可劫持
- 或者攻击者直接设置 `PYASC_COMPILER=/tmp/malicious_bisheng`
- `shutil.which()` 会返回攻击者控制的路径
- `subprocess.Popen()` 无任何验证即执行该路径的二进制文件

### 2. 缓存目录控制 (cache.py)

**危险代码位置: 第22-23行**
```python
@dataclass(frozen=True)
class CacheOptions:
    home_dir: str = os.getenv("PYASC_HOME", os.path.expanduser("~/"))
    dir: str = os.getenv("PYASC_CACHE_DIR", os.path.join(home_dir, ".pyasc", "cache"))
```

**全局实例: 第26行**
```python
cache_options = CacheOptions()  # 模块加载时立即实例化
```

**缓存使用点: FileCacheManager**
```python
# Line 47-51: 缓存目录直接使用环境变量值
self.cache_dir = cache_options.dir
if self.cache_dir:
    self.cache_dir = os.path.join(self.cache_dir, self.key)
    self.lock_path = os.path.join(self.cache_dir, "lock")
    os.makedirs(self.cache_dir, exist_ok=True)
```

**问题分析**:
- `PYASC_CACHE_DIR` 完全由用户控制，无任何验证
- 缓存目录可能指向攻击者控制的位置
- 后续加载的 `.so` 文件和 `pickle` 文件来自该目录

### 3. Ascend SDK路径控制 (lib/utils.py, build_utils.py)

**危险代码位置: lib/utils.py 第17-21行**
```python
@functools.lru_cache()
def get_ascend_path() -> str:
    path = os.getenv("ASCEND_HOME_PATH", "")
    if path == "":
        raise EnvironmentError("ASCEND_HOME_PATH is not set...")
    return Path(path)  # 直接返回用户控制的路径
```

**build_utils.py 第24-27行**: 完全相同的实现

**使用点分析**:
- `build_utils.py:55-73`: 使用该路径拼接 include 和 lib 目录
- `loader.py:39-42`: 使用该路径加载动态库
- `state.py:33-35`: 使用该路径读取 version.cfg

**问题分析**:
- 如果 `ASCEND_HOME_PATH` 指向攻击者控制的目录
- 攻击者可放置恶意 `lib64/libascendcl.so` 等库文件
- 编译链接时会链接恶意库，运行时加载恶意库

### 4. C++编译器控制 (lib/utils.py, build_utils.py, print_utils.py)

**lib/utils.py 第25-35行**:
```python
@functools.lru_cache()
def get_cxx_compiler():
    cxx = os.environ.get("CXX")  # 优先检查 CXX
    if cxx is None:
        cxx = os.environ.get("CC")  # 其次检查 CC
    if cxx is None:
        clangxx = shutil.which("clang++")
        gxx = shutil.which("g++")
        cxx = gxx if gxx is not None else clangxx
        if cxx is None:
            raise RuntimeError("Failed to find C++ compiler")
    return cxx  # 直接返回，无验证
```

**build_utils.py 第34-40行**:
```python
cxx = os.environ.get("CC")  # 注意: 这里用的是 CC，不是 CXX
if cxx is None:
    clangxx = shutil.which("clang++")
    gxx = shutil.which("g++")
    cxx = gxx if gxx is not None else clangxx
```

**print_utils.py 第29-35行**:
```python
cxx = os.getenv("CC")
if cxx is None:
    cpp = shutil.which("c++")
    gxx = shutil.which("g++")
    cxx = cpp if cpp is not None else gxx
```

**执行点: build_utils.py 第83行, print_utils.py 第44行, loader.py 第50行**
```python
ret = subprocess.check_call(cc_cmd)  # 直接执行编译器命令
```

**问题分析**:
- 三个文件对 CC/CXX 的处理方式不一致
- `lib/utils.py`: 优先 CXX，其次 CC
- `build_utils.py/print_utils.py`: 只检查 CC
- 所有路径最终通过 `shutil.which()` 或直接使用环境变量值
- `subprocess.check_call()` 无验证执行

---

## 完整攻击链

### 攻击链 A: 编译器劫持 → 恶意代码注入

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: 环境变量控制                                         │
│ ─────────────────────────────────────────────────────────────│
│ 攻击者设置: PYASC_COMPILER=/tmp/evil/bisheng                 │
│ 或: PATH=/tmp/evil:$PATH (放置恶意 bisheng)                   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 2: 路径解析                                             │
│ ─────────────────────────────────────────────────────────────│
│ compiler.py:106                                              │
│ shutil.which(os.environ.get("PYASC_COMPILER", "bisheng"))    │
│ → 返回 "/tmp/evil/bisheng"                                   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 3: 命令构造                                             │
│ ─────────────────────────────────────────────────────────────│
│ compiler.py:330-351 (_get_compiler_cmd)                      │
│ compile_cmds = [self.compiler, "-c", "-x", "cce", ...]       │
│ → [" /tmp/evil/bisheng", "-c", ...]                          │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 4: 恶意执行                                             │
│ ─────────────────────────────────────────────────────────────│
│ compiler.py:146                                              │
│ subprocess.Popen(cmd, stdout=PIPE, stderr=STDOUT)            │
│ → 执行 /tmp/evil/bisheng                                     │
│ → 恶意编译器可:                                              │
│   - 在编译产物中注入恶意代码                                  │
│   - 执行任意系统命令                                          │
│   - 窃取源代码                                                │
└─────────────────────────────────────────────────────────────┘
```

### 攻击链 B: 缓存污染 → Pickle RCE

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: 缓存目录控制                                         │
│ ─────────────────────────────────────────────────────────────│
│ 攻击者设置: PYASC_CACHE_DIR=/tmp/attacker_cache              │
│ 或预先写入: ~/.pyasc/cache/<hash>/kernel_name.o              │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 2: 恶意文件准备                                         │
│ ─────────────────────────────────────────────────────────────│
│ 攻击者在缓存目录放置:                                         │
│ - 恶意 pickle 文件 (利用 __reduce__)                         │
│ - 恶意 .so 文件 (constructor attribute)                      │
│ 文件名需匹配: base32(sha256(key))/*.o 或 *.so                 │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 3: 缓存加载                                             │
│ ─────────────────────────────────────────────────────────────│
│ jit.py:164-167                                               │
│ file_cache_key = get_file_cache_key(self.cache_key, ...)     │
│ file_cache_manager = get_cache_manager(file_cache_key)       │
│ cached_kernel_file = file_cache_manager.get_file(...)        │
│ → 返回攻击者的恶意文件                                        │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 4: RCE触发                                              │
│ ─────────────────────────────────────────────────────────────│
│ jit.py:170-172                                               │
│ with open(dst, 'rb') as file:                                │
│     kernel = pickle.load(file)                               │
│ → 恶意 pickle payload 执行                                   │
│ → 任意代码执行                                                │
└─────────────────────────────────────────────────────────────┘
```

### 攻击链 C: SDK路径劫持 → 动态库加载

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: SDK路径控制                                          │
│ ─────────────────────────────────────────────────────────────│
│ 攻击者设置: ASCEND_HOME_PATH=/tmp/fake_ascend                │
│ 攻击者在 /tmp/fake_ascend/lib64/ 放置恶意库:                 │
│ - libascendcl.so                                             │
│ - libruntime.so                                              │
│ - libtiling_api.so                                           │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 2: 库路径构造                                           │
│ ─────────────────────────────────────────────────────────────│
│ build_utils.py:55-73                                         │
│ asc_path = get_ascend_path()  # → /tmp/fake_ascend           │
│ cc_cmd += [f"-L{os.path.join(asc_path, 'lib64')}"]           │
│ → 链接恶意库                                                  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 3: 动态库加载                                           │
│ ─────────────────────────────────────────────────────────────│
│ state.py:50                                                  │
│ self.lib: ctypes.CDLL = ctypes.CDLL(rt_lib, RTLD_GLOBAL)     │
│ 或 loader.py: 加载 libtiling_api.so, libplatform.so          │
│ → 恶意库 __attribute__((constructor)) 自动执行               │
└─────────────────────────────────────────────────────────────┘
```

### 攻击链 D: C++编译器劫持 → 编译时注入

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: 编译器控制                                           │
│ ─────────────────────────────────────────────────────────────│
│ 攻击者设置: CC=/tmp/evil/g++                                  │
│ 或: CXX=/tmp/evil/clang++                                     │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 2: 编译器选择                                           │
│ ─────────────────────────────────────────────────────────────│
│ lib/utils.py:26-35 (get_cxx_compiler)                        │
│ 或 build_utils.py:34-40                                      │
│ 或 print_utils.py:29-35                                      │
│ → 返回攻击者控制的编译器路径                                  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 3: 编译执行                                             │
│ ─────────────────────────────────────────────────────────────│
│ build_utils.py:51-83                                         │
│ cc_cmd = [cxx, src_path, "-w", ...]                          │
│ subprocess.check_call(cc_cmd)                                │
│ → 执行恶意编译器                                              │
│ → 可在 .so 编译产物中注入恶意代码                             │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 4: 恶意库加载                                           │
│ ─────────────────────────────────────────────────────────────│
│ state.py:50 或 print_utils.py:70                             │
│ ctypes.CDLL(rt_lib) 或 ctypes.cdll.LoadLibrary(rt_lib)       │
│ → 加载被污染的 .so 文件                                       │
│ → 执行注入的恶意代码                                          │
└─────────────────────────────────────────────────────────────┘
```

---

## PoC 构造思路 (概念性描述，不提供完整代码)

### 思路 1: 编译器劫持 PoC

**攻击步骤**:
1. 创建一个伪装的编译器脚本，在执行真实编译前/后插入恶意操作
2. 该脚本需模拟真实编译器的参数处理
3. 设置 `PYASC_COMPILER` 环境变量指向恶意脚本
4. 触发 pyasc JIT 编译 (如运行示例代码)
5. 恶意编译器被执行，可植入后门或执行任意命令

**关键技术点**:
- 需正确处理 `-c`, `-x cce`, `-o` 等参数以避免编译失败
- 可在编译产物中注入恶意二进制代码

### 思路 2: Pickle 反序列化 PoC

**攻击步骤**:
1. 构造恶意 pickle payload，使用 `__reduce__` 方法
2. 计算 pyasc 缓存文件名的 hash 格式
3. 将恶意 pickle 文件放入缓存目录
4. 设置 `PYASC_CACHE_DIR` 或直接写入用户缓存目录
5. 运行 pyasc，触发缓存加载
6. `pickle.load()` 执行 payload

**关键技术点**:
- 缓存文件名格式: `base32(sha256(pyasc_key + cache_factors))`
- 需要分析 `pyasc_key()` 函数计算正确的 hash

### 思路 3: 动态库劫持 PoC

**攻击步骤**:
1. 创建恶意 C 共享库，包含 `__attribute__((constructor))` 函数
2. 构造函数中放置恶意代码
3. 计算 pyasc 缓存 hash 并将恶意 .so 放入对应目录
4. 或设置 `ASCEND_HOME_PATH` 指向伪造 SDK
5. 运行 pyasc，触发库加载
6. 构造函数自动执行恶意代码

**关键技术点**:
- constructor 函数在 `dlopen` 时自动执行
- 不需要显式调用即可触发

---

## 利用条件评估

| 条件 | 难度 | 说明 |
|------|------|------|
| 本地访问 | 必需 | 需设置环境变量或写入文件 |
| 环境变量控制 | Low | 用户级权限即可设置 |
| 文件写入权限 | Medium | 需写入缓存目录或 PATH 目录 |
| 缓存文件名计算 | Medium-High | 分析 pyasc_key 函数逻辑 |
| 用户触发 | 自动 | 用户正常使用 pyasc 即触发 |

**攻击场景**:
- 共享服务器环境，攻击者为普通用户
- CI/CD 环境中的恶意依赖注入
- 恶意管理员设置全局环境变量

---

## 修复建议

### 高优先级 (P0)

#### 1. 编译器路径白名单验证

```python
# 建议: compiler.py 中添加白名单机制
ALLOWED_COMPILERS = frozenset([
    "/usr/bin/bisheng",
    "/opt/ascend/bin/bisheng",
    # 其他官方路径
])

ALLOWED_LINKERS = frozenset([
    "/usr/bin/ld.lld",
    "/opt/ascend/bin/ld.lld",
])

def _validate_executable(path: str, allowed: frozenset) -> str:
    resolved = os.path.realpath(path)
    if resolved not in allowed:
        raise RuntimeError(f"Executable {resolved} not in allowed list")
    return resolved

# 在 Compiler.__init__ 中:
compiler = shutil.which(os.environ.get("PYASC_COMPILER", "bisheng"))
if compiler:
    compiler = _validate_executable(compiler, ALLOWED_COMPILERS)
```

#### 2. 缓存完整性签名

```python
# 建议: cache.py 中添加签名机制
import hmac
import hashlib

SECRET_KEY = ...  # 从安全配置获取

def sign_cache_data(data: bytes) -> str:
    return hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()

def verify_cache_signature(filepath: str, expected_sig: str) -> bool:
    with open(filepath, 'rb') as f:
        data = f.read()
    actual_sig = sign_cache_data(data)
    return hmac.compare_digest(actual_sig, expected_sig)

# 在 FileCacheManager.put() 中保存签名
# 在 get_file() 中验证签名
```

#### 3. 禁止从环境变量直接加载编译器

```python
# 建议: 完全移除或限制 PYASC_COMPILER 等环境变量的影响
# 改为从配置文件读取，配置文件需有权限控制

def get_compiler_path() -> str:
    # 从受保护的配置文件读取
    config_path = "/etc/pyasc/compiler.conf"
    if os.path.exists(config_path):
        # 验证配置文件权限 (应仅 root 可写)
        if os.stat(config_path).st_mode & 0o002:
            raise RuntimeError("Config file has insecure permissions")
        with open(config_path) as f:
            return f.read().strip()
    return shutil.which("bisheng")  # 默认查找系统路径
```

### 中优先级 (P1)

#### 4. 替换 Pickle 序列化

```python
# 建议: jit.py 中使用更安全的序列化格式
# 选项:
# - JSON (仅数据，需要手动处理 bytes)
# - Protocol Buffers (结构化，需要 schema)
# - 自定义格式 + HMAC 签名

import json
import base64

def serialize_kernel(kernel) -> str:
    data = {
        'binary': base64.b64encode(kernel.binary).decode(),
        'core_type': kernel.core_type.value,
        'enable_debug': kernel.enable_debug,
        # ...
    }
    return json.dumps(data)

def deserialize_kernel(data_str) -> CompiledKernel:
    data = json.loads(data_str)
    return CompiledKernel(
        binary=base64.b64decode(data['binary']),
        # ...
    )
```

#### 5. Ascend SDK 路径验证

```python
# 建议: lib/utils.py 中添加路径验证
def get_ascend_path() -> str:
    path = os.getenv("ASCEND_HOME_PATH", "")
    if not path:
        raise EnvironmentError("ASCEND_HOME_PATH not set")
    
    # 验证路径安全性
    resolved = os.path.realpath(path)
    
    # 检查关键文件是否存在
    required_files = [
        "version.cfg",
        "lib64/libascendcl.so",
    ]
    for f in required_files:
        if not os.path.exists(os.path.join(resolved, f)):
            raise RuntimeError(f"Invalid ASCEND_HOME_PATH: missing {f}")
    
    return Path(resolved)
```

### 低优先级 (P2)

#### 6. 安全文档和警告

- 在文档中明确列出安全敏感的环境变量
- 在启动时检测并警告潜在风险配置
- 添加安全最佳实践指南

#### 7. 统一 C++ 编译器获取逻辑

- 当前三个文件处理 CC/CXX 的方式不一致
- 统一为一个函数，添加白名单验证

---

## 相关漏洞关联

| 漏洞ID | 关系 | 说明 |
|--------|------|------|
| VULN-SEC-RUN-001 | 子漏洞 | Pickle 反序列化具体实现点 |
| VULN-SEC-RUN-002 | 子漏洞 | subprocess 命令注入具体点 |
| VULN-SEC-RT-001 | 子漏洞 | ctypes.CDLL 加载点 |
| VULN-SEC-RT-003 | 子漏洞 | importlib 模块加载点 |

---

## 验证结论

**漏洞确认**: 已通过源代码详细分析确认漏洞真实存在

**验证方法**:
- 阅读了 7 个相关源代码文件
- 分析了 15 处环境变量使用点
- 确认了数据流: 环境变量 → shutil.which() → subprocess.Popen/check_call()

**判定**: 非误报，漏洞真实存在且风险高
