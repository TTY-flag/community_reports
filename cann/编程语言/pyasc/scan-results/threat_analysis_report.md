# pyasc 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析由 AI 自主识别，未使用 threat.md 约束文件。

## 1. 项目架构概览

### 1.1 项目定位

**pyasc** 是华为昇腾 AI 处理器的编译器框架，提供 Python DSL 到 Ascend C 的编译能力。项目类型为 **库/SDK**，主要作为 Python 包通过 pip 安装使用。

**主要功能**：
- Python DSL 代码 → MLIR IR → Ascend C 代码 → NPU 二进制
- JIT 编译机制（@asc.jit 装饰器）
- 缓存机制（避免重复编译）
- NPU 运行时调度

**语言组成**：
- C/C++: 151 文件（后端 MLIR Dialect 和代码生成）
- Python: 164 文件（前端 DSL API 和运行时）

### 1.2 核心模块架构

```
┌─────────────────────────────────────────────────────────────────┐
│                    用户层 (Python DSL)                           │
│  @asc.jit 装饰器 → user kernel function                         │
├─────────────────────────────────────────────────────────────────┤
│                    前端编译模块                                   │
│  python/asc/codegen/function_visitor.py                         │
│  Python AST → MLIR IR (ASC Dialect)                             │
├─────────────────────────────────────────────────────────────────┤
│                    后端编译模块                                   │
│  lib/Dialect/Asc/IR → lib/Target/AscendC                        │
│  MLIR Passes → Ascend C 代码生成                                 │
├─────────────────────────────────────────────────────────────────┤
│                    外部编译器                                     │
│  subprocess → bisheng compiler → ld.lld linker                  │
│  Ascend C → NPU ELF binary                                      │
├─────────────────────────────────────────────────────────────────┤
│                    运行时模块                                     │
│  python/asc/runtime/launcher.py → ctypes → CANN runtime         │
│  kernel binary → NPU execution                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 数据流概览

```
用户 Python 函数
    ↓ @asc.jit 装饰器
JITFunction._run()
    ↓
FunctionVisitor (AST 解析)
    ↓
MLIR Module (ASC-IR)
    ↓
Ascend C 代码 (Translation.cpp)
    ↓
subprocess → bisheng compiler
    ↓
NPU Kernel Binary (.o)
    ↓
pickle 序列化 → 缓存文件
    ↓
Launcher.run() → NPU 执行
```

## 2. 模块风险评估

### 2.1 高风险模块列表

| 模块 | 路径 | 语言 | 风险等级 | STRIDE 威胁 | 说明 |
|------|------|------|----------|-------------|------|
| runtime | python/asc/runtime/ | python | Critical | T, D, E | subprocess 编译器调用 + pickle 反序列化 |
| codegen | python/asc/codegen/ | python | High | T, D | AST 解析用户代码 |
| lib_runtime | python/asc/lib/runtime/ | python | High | T, D, E | ctypes 动态库加载 + NPU 内存操作 |
| ascendc_target | lib/Target/AscendC/ | c_cpp | Medium | T | MLIR → Ascend C 代码生成 |
| pybind_bindings | python/src/ | c_cpp | Medium | T | Python ↔ C++ 数据传递 |
| cli_tools | bin/ | c_cpp | Medium | T | MLIR 文件处理 |

### 2.2 关键风险点分析

#### 2.2.1 subprocess 编译器调用 (Critical)

**位置**: `python/asc/runtime/compiler.py:146`

**风险描述**:
- 编译器路径由环境变量 `PYASC_COMPILER` 控制
- 链接器路径由环境变量 `PYASC_LINKER` 控制
- 本地攻击者可设置恶意程序路径，导致任意代码执行

**攻击场景**:
```bash
# 本地攻击者设置恶意编译器
export PYASC_COMPILER=/tmp/malicious_compiler
python user_script.py  # 触发 JIT 编译，执行恶意程序
```

#### 2.2.2 pickle 反序列化 (Critical)

**位置**: `python/asc/runtime/jit.py:172`

**风险描述**:
- 缓存文件使用 pickle 存储 CompiledKernel 对象
- 缓存目录由环境变量 `PYASC_CACHE_DIR` 控制
- 本地攻击者可篡改缓存文件，植入恶意 pickle 数据

**攻击场景**:
```python
# 缓存文件路径可被本地攻击者控制
export PYASC_CACHE_DIR=/tmp/malicious_cache
# 攻击者植入恶意 pickle 文件
# 用户执行 JIT 函数时触发反序列化 → 恶意代码执行
```

#### 2.2.3 环境变量注入 (High)

**位置**: 多处环境变量读取

**受影响的环境变量**:
| 环境变量 | 位置 | 影响 |
|----------|------|------|
| `PYASC_COMPILER` | compiler.py:106 | 控制编译器路径 |
| `PYASC_LINKER` | compiler.py:110 | 控制链接器路径 |
| `PYASC_HOME` | cache.py:22 | 控制缓存根目录 |
| `PYASC_CACHE_DIR` | cache.py:23 | 控制缓存目录 |
| `PYASC_DUMP_PATH` | compiler.py:98 | 控制 dump 输出路径 |
| `ASCENDC_DUMP` | compiler.py:191 | 控制调试 dump |

**风险**: 所有环境变量可被本地用户控制，影响编译流程安全。

#### 2.2.4 MLIR 文件解析 (Medium)

**位置**: `bin/ascir-opt.cpp`, `bin/ascir-translate.cpp`

**风险描述**:
- CLI 工具处理用户提供的 MLIR 文件
- 恡意 MLIR 文件可能导致解析异常或内存问题

## 3. 攻击面分析

### 3.1 入口点列表

| 入口类型 | 文件 | 函数 | 信任等级 | 风险 | 描述 |
|----------|------|------|----------|------|------|
| decorator | python/asc/__init__.py | jit() | untrusted_local | Critical | 用户 Python DSL 代码入口 |
| env | python/asc/runtime/compiler.py | Compiler.__init__ | untrusted_local | Critical | 编译器路径环境变量 |
| env | python/asc/runtime/cache.py | CacheOptions | untrusted_local | High | 缓存目录环境变量 |
| file | python/asc/runtime/jit.py | _cache_kernel | semi_trusted | Critical | pickle 缓存文件 |
| rpc | python/asc/runtime/compiler.py | _run_cmd | untrusted_local | Critical | subprocess 执行 |
| cmdline | bin/ascir-opt.cpp | main | untrusted_local | Medium | CLI 工具入口 |
| cmdline | bin/ascir-translate.cpp | main | untrusted_local | Medium | CLI 工具入口 |
| file | python/asc/lib/runtime/state.py | RuntimeInterface.__init__ | semi_trusted | High | 动态库加载 |

### 3.2 信任边界

```
┌──────────────────────────────────────────────────────────────────┐
│  Untrusted Zone (本地用户可控)                                    │
│  ├── 用户 Python DSL 代码                                        │
│  ├── 环境变量 (PYASC_COMPILER, PYASC_LINKER, PYASC_CACHE_DIR)    │
│  ├── MLIR 文件输入                                               │
│  └── 缓存文件 (pickle 反序列化数据)                               │
├──────────────────────────────────────────────────────────────────┤
│  Trust Boundary                                                  │
├──────────────────────────────────────────────────────────────────┤
│  Semi-Trusted Zone                                               │
│  ├── 缓存目录 (由环境变量指向，可能被篡改)                        │
│  ├── 临时文件 (编译过程生成)                                      │
├──────────────────────────────────────────────────────────────────┤
│  Trusted Zone (框架内部控制)                                     │
│  ├── MLIR IR 生成和变换                                          │
│  ├── Ascend C 代码生成                                           │
│  ├── NPU 运行时调度                                              │
│  ├── bisheng 编译器 (假设可信)                                   │
└──────────────────────────────────────────────────────────────────┘
```

## 4. STRIDE 威胁建模

### 4.1 Spoofing (欺骗) - Low

**威胁场景**:
- 无明显身份验证需求，框架作为本地编译器使用
- NPU 设备访问需要系统级权限

### 4.2 Tampering (篡改) - Critical

**主要威胁**:
1. **编译器路径篡改**: 环境变量控制编译器路径 → 恶意程序执行
2. **缓存文件篡改**: pickle 缓存文件 → 恶意代码注入
3. **MLIR 文件篡改**: CLI 工具输入 → 解析异常或代码注入

**风险等级**: Critical

### 4.3 Repudiation (抵赖) - Low

**威胁场景**:
- 无日志审计机制
- 编译过程无持久化记录

### 4.4 Information Disclosure (信息泄露) - Medium

**主要威胁**:
1. **调试 dump 泄露**: `PYASC_DUMP_PATH` 可导致中间代码泄露
2. **缓存目录泄露**: 缓存包含编译后的 kernel 二进制
3. **错误信息泄露**: 编译错误可能包含路径信息

### 4.5 Denial of Service (拒绝服务) - Medium

**主要威胁**:
1. **编译器阻塞**: 恶意编译器可无限阻塞编译流程
2. **缓存损坏**: 恶意缓存文件可导致解析失败
3. **NPU 资源耗尽**: kernel 执行可消耗 NPU 资源

### 4.6 Elevation of Privilege (权限提升) - Critical

**主要威胁**:
1. **编译器执行**: 恶意编译器以用户权限执行任意代码
2. **pickle 反序列化**: 恶意 pickle 数据执行任意 Python 代码
3. **动态库加载**: 恶意 .so 文件执行任意 native 代码

## 5. 安全加固建议 (架构层面)

### 5.1 编译器执行安全

**建议**:
1. 禁止通过环境变量控制编译器路径，使用硬编码或配置文件
2. 编译器路径验证：检查文件权限和签名
3. 使用白名单机制限制可执行的编译器命令

```python
# 建议：编译器路径硬编码或安全验证
ALLOWED_COMPILERS = ["/usr/bin/bisheng", "/opt/cann/compiler/bisheng"]
if compiler not in ALLOWED_COMPILERS:
    raise RuntimeError("Unauthorized compiler path")
```

### 5.2 缓存安全

**建议**:
1. 使用安全的序列化格式（如 JSON + 校验签名）
2. 缓存文件完整性校验（SHA256 hash）
3. 缓存目录使用固定安全路径，不接受环境变量控制

```python
# 建议：使用安全的缓存机制
# 1. 使用 JSON 而不是 pickle
# 2. 添加完整性校验
cache_hash = hashlib.sha256(data).hexdigest()
if cache_hash != expected_hash:
    raise RuntimeError("Cache integrity check failed")
```

### 5.3 环境变量安全

**建议**:
1. 减少环境变量对关键路径的控制
2. 使用配置文件替代环境变量
3. 对敏感配置进行签名验证

### 5.4 CLI 工具安全

**建议**:
1. MLIR 文件大小限制
2. 输入文件格式验证
3. 错误信息脱敏（不暴露路径）

## 6. 总结

pyasc 作为编译器框架，主要安全风险集中在：
1. **subprocess 编译器调用** - 环境变量控制导致的命令注入风险
2. **pickle 反序列化** - 缓存机制导致的恶意代码执行风险
3. **环境变量注入** - 多个关键路径可被本地攻击者控制

**建议优先级**：
1. Critical: 修复编译器执行和 pickle 反序列化安全问题
2. High: 减少环境变量对关键路径的控制
3. Medium: 加强 MLIR 文件解析安全

---

*报告生成时间: 2026-04-22*
*分析工具: Architecture Agent (自主分析模式)*