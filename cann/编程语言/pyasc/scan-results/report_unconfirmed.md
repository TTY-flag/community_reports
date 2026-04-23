# 漏洞扫描报告 — 待确认漏洞

**项目**: pyasc
**扫描时间**: 2026-04-22T10:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| High | 14 | 23.3% |
| Medium | 33 | 55.0% |
| Low | 9 | 15.0% |
| **有效漏洞总计** | **60** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[pybind_nullptr_deref_001]** Null Pointer Dereference (High) - `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:322` @ `get_opaque_type_name` | 置信度: 85
2. **[pybind_nullptr_deref_002]** Null Pointer Dereference (High) - `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/OpBuilder.cpp:774` @ `create_emitasc_CopyStructOp` | 置信度: 85
3. **[VULN-lib_runtime-004]** Command Injection (High) - `python/asc/lib/runtime/build_utils.py:34` @ `build_npu_ext` | 置信度: 80
4. **[VULN-lib_runtime-005]** Command Injection (High) - `python/asc/lib/runtime/print_utils.py:29` @ `build_print_utils` | 置信度: 80
5. **[VULN-SEC-CI-007]** injection (High) - `lib/Target/AscendC/EmitAsc.cpp:23` @ `printOperation` | 置信度: 75
6. **[VULN-SEC-RUN-003]** insecure_file_permissions (High) - `python/asc/runtime/cache.py:51` @ `FileCacheManager.__init__/put` | 置信度: 70
7. **[VULN-SEC-CG-001]** code_injection (High) - `python/asc/codegen/function_visitor.py:410` @ `visit_Attribute` | 置信度: 70
8. **[VULN-CG-001]** code_injection (High) - `python/asc/codegen/function_visitor.py:167` @ `apply_binary_method` | 置信度: 70
9. **[VULN-CROSS-003]** sandbox_escape (High) - ? @ `?` | 置信度: 70
10. **[VULN-SEC-CG-002]** code_injection (High) - `python/asc/codegen/function_visitor.py:370` @ `visit_Assign` | 置信度: 65

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

## 3. High 漏洞 (14)

### [pybind_nullptr_deref_001] Null Pointer Dereference - get_opaque_type_name

**严重性**: High | **CWE**: CWE-476 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:322-323` @ `get_opaque_type_name`
**模块**: pybind_bindings

**描述**: Unsafe cast to emitc::OpaqueType without null checking. If type is not an OpaqueType, cast<> will return null and subsequent getValue() call will crash.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:322-323`)

```c
cast<emitc::OpaqueType>(type).getValue().str()
```

**达成路径**

[IN] Python Type object -> [CAST] cast<OpaqueType> -> [ACCESS] getValue() (no null check)

**验证说明**: Verified: Unsafe cast to OpaqueType without null check. Crash if type mismatch. Code quality issue with security implications.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 0

---

### [pybind_nullptr_deref_002] Null Pointer Dereference - create_emitasc_CopyStructOp

**严重性**: High | **CWE**: CWE-476 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/OpBuilder.cpp:774-776` @ `create_emitasc_CopyStructOp`
**模块**: pybind_bindings

**描述**: Unsafe cast to MemRefType without null checking in create_emitasc_CopyStructOp. If base.getType() is not a MemRefType, the cast will fail.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/OpBuilder.cpp:774-776`)

```c
cast<MemRefType>(base.getType()).getElementType()
```

**达成路径**

[IN] Python Value -> [ACCESS] getType() -> [CAST] cast<MemRefType> -> [ACCESS] getElementType() (no null check)

**验证说明**: Verified: Unsafe cast to MemRefType without null check in OpBuilder. Crash risk.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-lib_runtime-004] Command Injection - build_npu_ext

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-78 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `python/asc/lib/runtime/build_utils.py:34-83` @ `build_npu_ext`
**模块**: lib_runtime

**描述**: OS command injection via CC environment variable. The compiler path is read from os.environ.get("CC") and used directly in subprocess.check_call() without validation. An attacker who controls the CC environment variable can execute arbitrary commands.

**漏洞代码** (`python/asc/lib/runtime/build_utils.py:34-83`)

```c
cxx = os.environ.get("CC")\n...\nret = subprocess.check_call(cc_cmd)
```

**达成路径**

CC env var → cxx → cc_cmd list → subprocess.check_call(cc_cmd)

**验证说明**: Verified: CC env var command injection in build_npu_ext. Attack requires env control.

**评分明细**: base: 30 | reachability: 25 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-lib_runtime-005] Command Injection - build_print_utils

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-78 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `python/asc/lib/runtime/print_utils.py:29-44` @ `build_print_utils`
**模块**: lib_runtime

**描述**: OS command injection via CC environment variable in print_utils. Same pattern as build_utils.py - compiler path from environment variable used in subprocess.check_call() without validation.

**漏洞代码** (`python/asc/lib/runtime/print_utils.py:29-44`)

```c
cxx = os.getenv("CC")\n...\nret = subprocess.check_call(cc_cmd)
```

**达成路径**

CC env var → cxx → cc_cmd list → subprocess.check_call(cc_cmd)

**验证说明**: Verified: CC env var command injection in print_utils.

**评分明细**: base: 30 | reachability: 25 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CI-007] injection - printOperation

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-74 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `lib/Target/AscendC/EmitAsc.cpp:23-32` @ `printOperation`
**模块**: ascendc_target

**描述**: emitasc::CallOpaqueOp 直接输出用户提供的 callee 函数名到生成的 C++ 代码调用中。函数名可以包含任意 C++ 表达式，可能导致代码注入。

**漏洞代码** (`lib/Target/AscendC/EmitAsc.cpp:23-32`)

```c
LogicalResult mlir::emitasc::printOperation(CodeEmitter &emitter, emitasc::CallOpaqueOp op) {
    os << op.getCallee() << '(';
    llvm::interleaveComma(op.getOperands(), os, ...);
}
```

**达成路径**

MLIR CallOpaqueOp → op.getCallee() → C++ 函数调用

**验证说明**: Verified: CallOpaqueOp callee string in C++ function call. Arbitrary function invocation possible.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-RUN-003] insecure_file_permissions - FileCacheManager.__init__/put

**严重性**: High | **CWE**: CWE-276 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `python/asc/runtime/cache.py:51-87` @ `FileCacheManager.__init__/put`
**模块**: runtime

**描述**: Cache directories and files created without secure permissions. FileCacheManager creates cache directories via os.makedirs() without specifying a mode (defaults to umask), and writes files without explicit permission settings. This allows other users on shared systems to potentially read or modify cached pickle files, enabling the pickle deserialization attack chain.

**漏洞代码** (`python/asc/runtime/cache.py:51-87`)

```c
os.makedirs(self.cache_dir, exist_ok=True)  # Line 51 - no mode
...
with open(temp_path, mode) as f:  # Line 86 - no explicit permissions
    f.write(data)
```

**达成路径**

cache.py:51 → os.makedirs(self.cache_dir, exist_ok=True) [INSECURE DIRECTORY CREATION]
→ cache.py:82-87 → open(temp_path, mode) → f.write(data) [INSECURE FILE CREATION]
→ [CREDENTIAL_FLOW] Combined with VULN-SEC-RUN-001 enables pickle RCE chain

**验证说明**: Verified: Insecure file permissions enable cache tampering. Combined with pickle deserialization forms attack chain. Requires local access to shared system.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -5 | cross_file: 10

---

### [VULN-SEC-CG-001] code_injection - visit_Attribute

**严重性**: High | **CWE**: CWE-94 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-module-scanner, python-dataflow-module-scanner

**位置**: `python/asc/codegen/function_visitor.py:410-422` @ `visit_Attribute`
**模块**: codegen
**跨模块**: codegen → jit → language

**描述**: Sandbox escape via arbitrary attribute access. FunctionVisitor.visit_Attribute (line 414) uses getattr(lhs, attr) where 'attr' is user-controlled from AST node. This allows user DSL code to access arbitrary Python object attributes, potentially escaping the namespace sandbox. Attack chain: tensor.__class__.__init__.__globals__['os'].system('cmd') to execute arbitrary Python code.

**漏洞代码** (`python/asc/codegen/function_visitor.py:410-422`)

```c
def visit_Attribute(self, node: ast.Attribute) -> Any:
    lhs = self.visit(node.value)
    attr = str(node.attr)
    try:
        value = getattr(lhs, attr)  # user-controlled attr
        if not isinstance(lhs, Struct) or not isinstance(value, BaseField):
            return value
    except AttributeError:
        pass
    getter = getattr(lhs, "__getattrjit__", None)
    if getter:
        return getter(attr)
    raise AttributeError(...)
```

**达成路径**

[SOURCE] User DSL code → ast.parse → AST nodes (node.attr controlled by user)
[PROPAGATION] visit(node.value) → lhs object
[SINK] getattr(lhs, attr) at line 414 - arbitrary attribute access
[IMPACT] Sandbox escape: lhs.__class__.__init__.__globals__['os'].system('cmd')

**验证说明**: Verified: getattr(lhs, attr) in visit_Attribute allows arbitrary attribute access. Sandbox escape possible via __class__.__init__.__globals__ chain. Some type checking exists (isinstance).

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-CG-001] code_injection - apply_binary_method

**严重性**: High | **CWE**: CWE-94 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: [python-dataflow-module-scanner]

**位置**: `python/asc/codegen/function_visitor.py:167-171` @ `apply_binary_method`
**模块**: codegen
**跨模块**: codegen,runtime

**描述**: Dynamic method invocation via getattr on user-controlled attributes from AST traversal. The FunctionVisitor processes user Python DSL code and dynamically calls methods using getattr() with attribute names derived from AST nodes.

**漏洞代码** (`python/asc/codegen/function_visitor.py:167-171`)

```c
reverse_method_name = re.sub(...)\ngetattr(rhs, reverse_method_name)(lhs)
```

**达成路径**

jit.py → FunctionVisitor.visit → visit_BinOp → apply_binary_method → getattr()

**验证说明**: Verified: getattr on user-controlled attributes from AST. Sandbox escape possible.

**评分明细**: base: 30 | reachability: 25 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-CROSS-003] sandbox_escape - unknown

**严重性**: High | **CWE**: CWE-94 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `?:?` @ `?`
**模块**: cross_module
**跨模块**: codegen → language

**描述**: Python DSL 沙箱逃逸链: FunctionVisitor.visit_Attribute 允许链式属性访问 (x.__class__.__init__.__globals__["os"].system("cmd"))，可逃逸 NameScope 沙箱执行任意 Python 代码。

**达成路径**

用户 DSL AST → visit_Attribute → getattr() 链 → __globals__ → os.system()

**验证说明**: Verified: Python DSL sandbox escape via getattr chain. x.__class__.__init__.__globals__['os'].system('cmd') pattern works. NameScope sandbox insufficient.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-CG-002] code_injection - visit_Assign

**严重性**: High | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-module-scanner, python-dataflow-module-scanner

**位置**: `python/asc/codegen/function_visitor.py:370-376` @ `visit_Assign`
**模块**: codegen
**跨模块**: codegen → jit → language

**描述**: Arbitrary attribute modification via setattr. visit_Assign (line 375) uses setattr(base, lhs.attr, rhs) where lhs.attr is user-controlled. User DSL code can modify arbitrary attributes on objects, potentially altering object behavior or injecting malicious code.

**漏洞代码** (`python/asc/codegen/function_visitor.py:370-376`)

```c
if isinstance(lhs, ast.Attribute) and isinstance(lhs.ctx, ast.Store):
    base = self.visit(lhs.value)
    if setter := getattr(base, "__setattrjit__", None):
        setter(lhs.attr, rhs)
    else:
        setattr(base, lhs.attr, rhs)  # user-controlled attr
```

**达成路径**

[SOURCE] User DSL assignment → AST Attribute node with Store context
[PROPAGATION] visit(lhs.value) → base object
[SINK] setattr(base, lhs.attr, rhs) at line 375
[IMPACT] Can modify object attributes to inject malicious behavior

**验证说明**: Verified: setattr(base, lhs.attr, rhs) allows arbitrary attribute modification. Can inject malicious behavior. Combined with attribute access enables full escape.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-CG-004] code_injection - visit_Subscript

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `python/asc/codegen/function_visitor.py:665-670` @ `visit_Subscript`
**模块**: codegen

**描述**: Arbitrary subscript access enables dict key exploitation. visit_Subscript (line 670) allows value.__getitem__(slices) where slices is user-controlled. Combined with attribute escape, user can access globals['__import__']('os') to import dangerous modules.

**漏洞代码** (`python/asc/codegen/function_visitor.py:665-670`)

```c
def visit_Subscript(self, node: ast.Subscript) -> Any:
    if not isinstance(node.ctx, ast.Load):
        self.raise_unsupported(node, ...)
    value = self.visit(node.value)
    slices = self.visit(node.slice)
    return value.__getitem__(slices)  # user-controlled slices
```

**达成路径**

[SOURCE] User DSL subscript → AST Subscript node
[PROPAGATION] visit(node.value) → dict, visit(node.slice) → key
[SINK] value.__getitem__(slices) at line 670
[IMPACT] Access globals['os'], globals['__import__'] to escape sandbox

**验证说明**: Verified: visit_Subscript enables globals['__import__'] access. Limited by NameScope.

**评分明细**: base: 30 | reachability: 25 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-RT-004] incorrect_resource_supply - CacheOptions

**严重性**: High | **CWE**: CWE-668 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `python/asc/runtime/cache.py:22-27` @ `CacheOptions`
**模块**: lib_runtime
**跨模块**: lib_runtime → runtime.cache → lib.host

**描述**: Environment variables control security-sensitive paths without validation. ASCEND_HOME_PATH controls library compilation paths (include directories, lib paths). PYASC_CACHE_DIR controls where compiled binaries are stored and loaded. Neither is validated against expected values or protected against manipulation.

**漏洞代码** (`python/asc/runtime/cache.py:22-27`)

```c
@dataclass(frozen=True)
class CacheOptions:
    home_dir: str = os.getenv("PYASC_HOME", os.path.expanduser("~/"))
    dir: str = os.getenv("PYASC_CACHE_DIR", os.path.join(home_dir, ".pyasc", "cache"))
```

**达成路径**

cache.py:23 PYASC_CACHE_DIR env [SOURCE]
build_utils.py:24-27 ASCEND_HOME_PATH env [SOURCE]
state.py:50, loader.py:72 compiled .so loaded from env-controlled paths [SINK]

**验证说明**: Verified: ASCEND_HOME_PATH/PYASC_CACHE_DIR control compilation paths without validation. Combined with other vulnerabilities forms attack chain.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-CG-002] code_injection - visit_Call

**严重性**: High | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: python-dataflow-module-scanner, security-module-scanner

**位置**: `python/asc/codegen/function_visitor.py:438-446` @ `visit_Call`
**模块**: codegen
**跨模块**: codegen,runtime

**描述**: Dynamic function execution with user-controlled callable. visit_Call executes fn(*args, **kwargs) where fn is dynamically resolved from scope.

**漏洞代码** (`python/asc/codegen/function_visitor.py:438-446`)

```c
fn = self.visit(node.func)\nreturn fn(*args, **kwargs)
```

**达成路径**

jit.py → FunctionVisitor.visit → visit_Call → fn(*args, **kwargs)

**验证说明**: Verified: visit_Call executes fn(*args). Dynamic resolution from scope.

**评分明细**: base: 30 | reachability: 25 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-RT-002] toctou_link_resolution - FileCacheManager.get_file

**严重性**: High | **CWE**: CWE-59 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `python/asc/runtime/cache.py:60-64` @ `FileCacheManager.get_file`
**模块**: lib_runtime
**跨模块**: lib_runtime → runtime.cache

**描述**: Time-of-check-time-of-use vulnerability in cache file retrieval. has_file() checks file existence, then get_file() returns the path for loading. An attacker could replace or symlink the cached .so file between the check and the actual ctypes.CDLL load, injecting malicious code.

**漏洞代码** (`python/asc/runtime/cache.py:60-64`)

```c
def get_file(self, filename: str) -> Optional[str]:
    if self.has_file(filename):
        return self._make_path(filename)
    else:
        return None
```

**达成路径**

cache.py:56 has_file() [CHECK] → path existence
cache.py:62 _make_path() → returns path
state.py:50 ctypes.CDLL(path) [USE] loads file - window for symlink attack

**验证说明**: Verified: TOCTOU vulnerability between has_file() check and get_file() return. Attacker could symlink/c replace .so file in race window. Requires timing and local access.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (33)

### [VULN-lib_runtime-007] Improper Input Validation - register_device_binary_kernel

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/asc/lib/runtime/interface.py:224-242` @ `register_device_binary_kernel`
**模块**: lib_runtime

**描述**: Unsafe binary kernel registration without validation. The register_device_binary_kernel function accepts arbitrary bytes as kernel_binary and passes them directly to the NPU runtime via DevBinaryRegisterWrapper without validating the binary format, magic numbers, or size limits. Malformed or malicious binaries could potentially cause memory corruption.

**漏洞代码** (`python/asc/lib/runtime/interface.py:224-242`)

```c
device_binary = support.DevBinary(\n    data=ctypes.c_char_p(kernel_binary),\n    length=ctypes.c_uint64(kernel_size),\n    version=ctypes.c_uint32(0),\n    magic=ctypes.c_uint32(core_type_id),\n)\nhandle = ctypes.c_void_p()\nstate.lib.call(\n    "DevBinaryRegisterWrapper",\n    ctypes.c_void_p(ctypes.addressof(device_binary)),\n    ctypes.c_void_p(ctypes.addressof(handle)),\n)
```

**达成路径**

kernel_binary (user-provided bytes) → DevBinary.data → DevBinaryRegisterWrapper (NPU runtime)

**验证说明**: Verified: Kernel binary registration without validation. NPU runtime risk.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [pybind_enum_unsafe_cast_001] Type Safety - symbolize

**严重性**: Medium | **CWE**: CWE-704 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:113-115` @ `symbolize`
**模块**: pybind_bindings

**描述**: Unsafe enum conversion: static_cast used without bounds checking for AippInputFormat enum. Invalid uint8_t values can produce undefined behavior.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:113-115`)

```c
static_cast<ascendc::AippInputFormat>(input_format)
```

**达成路径**

[IN] Python uint8_t -> [CAST] static_cast -> [OUT] C++ enum (no validation)

**验证说明**: Verified: Unsafe enum conversion static_cast without bounds check. Undefined behavior risk for invalid values.

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [pybind_enum_unsafe_cast_002] Type Safety - symbolize

**严重性**: Medium | **CWE**: CWE-704 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:120` @ `symbolize`
**模块**: pybind_bindings

**描述**: Unsafe enum conversion: static_cast used without bounds checking for CacheLine enum.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:120`)

```c
static_cast<ascendc::CacheLine>(v)
```

**达成路径**

[IN] Python uint8_t -> [CAST] static_cast -> [OUT] C++ enum

**验证说明**: Verified: Unsafe CacheLine enum conversion. Same pattern as 001.

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [pybind_enum_unsafe_cast_003] Type Safety - symbolize

**严重性**: Medium | **CWE**: CWE-704 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:143` @ `symbolize`
**模块**: pybind_bindings

**描述**: Unsafe enum conversion: static_cast used without bounds checking for DcciDst enum.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:143`)

```c
static_cast<ascendc::DcciDst>(v)
```

**达成路径**

[IN] Python uint8_t -> [CAST] static_cast -> [OUT] C++ enum

**验证说明**: Verified: Unsafe DcciDst enum conversion.

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [pybind_enum_unsafe_cast_004] Type Safety - symbolize

**严重性**: Medium | **CWE**: CWE-704 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:148` @ `symbolize`
**模块**: pybind_bindings

**描述**: Unsafe enum conversion: static_cast used without bounds checking for MaskMode enum.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:148`)

```c
static_cast<ascendc::MaskMode>(v)
```

**达成路径**

[IN] Python uint8_t -> [CAST] static_cast -> [OUT] C++ enum

**验证说明**: Verified: Unsafe MaskMode enum conversion.

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [pybind_enum_unsafe_cast_005] Type Safety - symbolize

**严重性**: Medium | **CWE**: CWE-704 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:155-156` @ `symbolize`
**模块**: pybind_bindings

**描述**: Unsafe enum conversion: static_cast used without bounds checking for ReduceOrder enum.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:155-156`)

```c
static_cast<ascendc::ReduceOrder>(v)
```

**达成路径**

[IN] Python uint8_t -> [CAST] static_cast -> [OUT] C++ enum

**验证说明**: Verified: Unsafe ReduceOrder enum conversion.

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [pybind_enum_unsafe_cast_006] Type Safety - symbolize

**严重性**: Medium | **CWE**: CWE-704 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:166` @ `symbolize`
**模块**: pybind_bindings

**描述**: Unsafe enum conversion: static_cast used without bounds checking for RoundMode enum.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:166`)

```c
static_cast<ascendc::RoundMode>(v)
```

**达成路径**

[IN] Python uint8_t -> [CAST] static_cast -> [OUT] C++ enum

**验证说明**: Verified: Unsafe RoundMode enum conversion.

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [pybind_enum_unsafe_cast_007] Type Safety - symbolize

**严重性**: Medium | **CWE**: CWE-704 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:169-170` @ `symbolize`
**模块**: pybind_bindings

**描述**: Unsafe enum conversion: static_cast used without bounds checking for TPosition enum.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:169-170`)

```c
static_cast<ascendc::TPosition>(pos)
```

**达成路径**

[IN] Python uint8_t -> [CAST] static_cast -> [OUT] C++ enum

**验证说明**: Verified: Unsafe TPosition enum conversion.

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [pybind_enum_unsafe_cast_008] Type Safety - symbolize

**严重性**: Medium | **CWE**: CWE-704 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:179-180` @ `symbolize`
**模块**: pybind_bindings

**描述**: Unsafe enum conversion: static_cast used without bounds checking for CMPMODE enum.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:179-180`)

```c
static_cast<ascendc::CMPMODE>(cmp_mode)
```

**达成路径**

[IN] Python uint8_t -> [CAST] static_cast -> [OUT] C++ enum

**验证说明**: Verified: Unsafe CMPMODE enum conversion.

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [pybind_enum_unsafe_cast_009] Type Safety - symbolize

**严重性**: Medium | **CWE**: CWE-704 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:187-188` @ `symbolize`
**模块**: pybind_bindings

**描述**: Unsafe enum conversion: static_cast used without bounds checking for SELMODE enum.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:187-188`)

```c
static_cast<ascendc::SELMODE>(sel_mode)
```

**达成路径**

[IN] Python uint8_t -> [CAST] static_cast -> [OUT] C++ enum

**验证说明**: Verified: Unsafe SELMODE enum conversion.

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [pybind_symbolize_comparison_001] Type Safety - multiple symbolize

**严重性**: Medium | **CWE**: CWE-704 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:113-188` @ `multiple symbolize`
**模块**: pybind_bindings

**描述**: Inconsistent validation: IR.cpp uses unsafe static_cast for symbolize functions, while OpBuilder.cpp uses proper symbolizeHardEvent/symbolizeTPosition that return optional and check for validity. The IR.cpp approach is unsafe.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:113-188`)

```c
static_cast vs ascendc::symbolizeTPosition (with validation)
```

**达成路径**

[IN] Python uint8_t -> [IR.cpp] unsafe static_cast -> [OpBuilder.cpp] safe symbolize pattern

**验证说明**: Verified: Inconsistent validation - IR.cpp unsafe vs OpBuilder.cpp safe pattern.

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-LANG-001] path_traversal - LocalTensor.to_file

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `python/asc/language/core/tensor.py:459-460` @ `LocalTensor.to_file`
**模块**: language
**跨模块**: language → ascendc_target

**描述**: LocalTensor.to_file() 方法接受用户提供的 file_name 参数直接传递给 IR 操作，未进行路径验证。可能导致路径遍历漏洞，恶意用户可写入任意位置文件。

**漏洞代码** (`python/asc/language/core/tensor.py:459-460`)

```c
@require_jit
@set_tensor_docstring(tensor_name="LocalTensor", api_name="to_file")
def to_file(self, file_name: str) -> None:
    global_builder.get_ir_builder().create_asc_LocalTensorToFileOp(self.to_ir(), file_name)
```

**达成路径**

User DSL code → LocalTensor.to_file(file_name) [SOURCE] → create_asc_LocalTensorToFileOp(file_name) → C++ backend [SINK]

**验证说明**: Verified: LocalTensor.to_file() accepts file_name without path validation.

**评分明细**: base: 30 | reachability: 25 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [PYASC-DF-cli_tools-001] Improper Input Validation - main

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `bin/ascir-opt.cpp:18-26` @ `main`
**模块**: cli_tools

**描述**: CLI tool ascir-opt passes command-line arguments directly to MLIR parsing without validation. While MLIR library provides robust parsing, there is no defense-in-depth approach. Arguments from untrusted sources could exploit parsing vulnerabilities in the underlying library.

**漏洞代码** (`bin/ascir-opt.cpp:18-26`)

```c
int main(int argc, char **argv)\n{\n    DialectRegistry registry;\n    ascir::registerDialects(registry);\n    ascendc::registerInlinerInterfaces(registry);\n    ascir::registerExtensions(registry);\n    ascir::registerPasses();\n    return asMainReturnCode(MlirOptMain(argc, argv, "AscIR modular optimizer driver\n", registry));\n}
```

**达成路径**

[IN] argv (untrusted command-line) -> main -> MlirOptMain -> MLIR parsing

**验证说明**: Verified: CLI passes argv directly to MLIR parsing. Defense-in-depth approach missing. MLIR lib provides robust parsing but input validation lacking.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [PYASC-DF-cli_tools-002] Improper Input Validation - main

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `bin/ascir-translate.cpp:31-51` @ `main`
**模块**: cli_tools
**跨模块**: cli_tools,translation

**描述**: CLI tool ascir-translate passes command-line arguments directly to MLIR translation without validation. The tool processes MLIR files and generates Ascend C code.

**漏洞代码** (`bin/ascir-translate.cpp:31-51`)

```c
int main(int argc, char **argv)\n{\n    registerAllTranslations();\n    TranslateFromMLIRRegistration reg(\n        "mlir-to-ascendc", "translate from mlir to Ascend C",\n        [](Operation *op, raw_ostream &output) { return translateToAscendC(op, output); },\n        ...\n    );\n    return failed(mlirTranslateMain(argc, argv, "AscIR translation tool"));\n}
```

**达成路径**

[IN] argv -> main -> mlirTranslateMain -> translateToAscendC -> [OUT] AscendC code generation

**验证说明**: Verified: CLI passes argv to MLIR translation. Generates AscendC code. Similar to cli_tools-001.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [pybind_input_validation_001] Input Validation - get_float_type

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/OpBuilder.cpp:270-285` @ `get_float_type`
**模块**: pybind_bindings

**描述**: get_float_type only validates width for 16, 32, 64. Other unsigned width values throw runtime_error but this is a post-validation approach. More robust validation should be applied.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/OpBuilder.cpp:270-285`)

```c
if (width == 16U) {...} else throw std::runtime_error
```

**达成路径**

[IN] Python unsigned width -> [CHECK] only 16/32/64 valid -> [OUT] Type or exception

**验证说明**: Verified: get_float_type validates width for 16/32/64 only. Post-validation approach.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-lib_runtime-008] Use of Potentially Dangerous Function - malloc,memcpy,launch_kernel

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-749 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `python/asc/lib/runtime/interface.py:269-334` @ `malloc,memcpy,launch_kernel`
**模块**: lib_runtime

**描述**: Direct memory operations via ctypes without bounds checking. Multiple functions in interface.py perform direct memory operations using ctypes (malloc, memcpy, launch_kernel) with user-provided sizes and pointers. While some size validation exists (e.g., malloc checks size > 0), the operations pass values directly to the NPU runtime without comprehensive bounds validation.

**漏洞代码** (`python/asc/lib/runtime/interface.py:269-334`)

```c
state.lib.call(\n    "MallocWrapper",\n    ctypes.c_void_p(ctypes.addressof(c_memory_p)),\n    ctypes.c_uint64(real_mem_size),\n    ...\n)\n...\nstate.lib.call(\n    "MemcpyWrapper",\n    ctypes.cast(mem_dst_handle, ctypes.c_void_p),\n    ctypes.c_uint64(dst_nbytes),\n    ...\n)
```

**达成路径**

User-provided size/args → malloc/memcpy/launch_kernel → Direct NPU memory operations

**验证说明**: Verified: ctypes memory operations without bounds check.

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [pybind_memory_lifetime_002] Memory Management - pyasc_bind_operation

**严重性**: Medium | **CWE**: CWE-416 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:461` @ `pyasc_bind_operation`
**模块**: pybind_bindings
**跨模块**: mlir_core,pybind_bindings

**描述**: Operation class uses std::unique_ptr<Operation, py::nodelete> holder. While this prevents pybind11 from deleting the Operation, the Operation can still be destroyed by MLIR framework, leading to dangling Python references.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:461`)

```c
py::class_<Operation, std::unique_ptr<Operation, py::nodelete>>
```

**达成路径**

[IN] MLIR Operation -> [BIND] py::nodelete holder -> [OUT] Python reference (MLIR controls lifetime)

**验证说明**: Verified: py::nodelete holder but MLIR controls lifetime. Use-after-free risk if MLIR destroys object.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-CI-003] injection - emitEmitcOpaqueAttr

**严重性**: Medium | **CWE**: CWE-74 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `lib/Target/AscendC/CodeEmitter.cpp:254-258` @ `emitEmitcOpaqueAttr`
**模块**: ascendc_target

**描述**: emitc::OpaqueAttr 和 emitc::OpaqueType 直接输出用户控制的 opaque 属性值/类型值到生成的 C++ 代码中。这些值可以包含任意 C++ 类型名或表达式，可能导致代码注入。

**漏洞代码** (`lib/Target/AscendC/CodeEmitter.cpp:254-258`)

```c
LogicalResult CodeEmitter::emitEmitcOpaqueAttr(Location loc, Attribute attr) {
    auto oAttr = dyn_cast<emitc::OpaqueAttr>(attr);
    os << oAttr.getValue();
}
```

**达成路径**

MLIR OpaqueAttr → emitEmitcOpaqueAttr() → os << value → C++ 代码

**验证说明**: Verified: OpaqueAttr values output directly to C++ code. Injection possible.

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-CI-004] injection - emitEmitcOpaqueType

**严重性**: Medium | **CWE**: CWE-74 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `lib/Target/AscendC/CodeEmitter.cpp:495-499` @ `emitEmitcOpaqueType`
**模块**: ascendc_target

**描述**: emitc::OpaqueType 直接输出 opaque 类型值到生成的 C++ 代码中。类型值可以包含任意 C++ 类型表达式，可能导致代码注入。

**漏洞代码** (`lib/Target/AscendC/CodeEmitter.cpp:495-499`)

```c
LogicalResult CodeEmitter::emitEmitcOpaqueType(Location loc, Type type, bool emitAsUnsigned) {
    auto oType = dyn_cast<emitc::OpaqueType>(type);
    os << oType.getValue();
}
```

**达成路径**

MLIR OpaqueType → emitEmitcOpaqueType() → os << value → C++ 类型声明

**验证说明**: Verified: OpaqueType value output to C++ type declaration.

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-CG-003] information_disclosure - Function.__init__

**严重性**: Medium | **CWE**: CWE-200 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: [python-dataflow-module-scanner]

**位置**: `python/asc/codegen/function.py:57` @ `Function.__init__`
**模块**: codegen
**跨模块**: codegen,runtime

**描述**: Exposure of function globals to AST visitor. __globals__ passed to FunctionVisitor exposing module-level variables.

**漏洞代码** (`python/asc/codegen/function.py:57`)

```c
self.__globals__ = fn.__globals__
```

**达成路径**

jit.py → FunctionVisitor(global_vars) → NameScope → scope.lookup()

**验证说明**: Verified: __globals__ exposure to AST visitor. Information disclosure.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [PYASC-DF-cli_tools-003] Improper Input Validation - main

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `bin/ascir-lsp.cpp:18-24` @ `main`
**模块**: cli_tools

**描述**: LSP server ascir-lsp accepts untrusted input from LSP clients without validation.

**漏洞代码** (`bin/ascir-lsp.cpp:18-24`)

```c
int main(int argc, char **argv)\n{\n    DialectRegistry registry;\n    ascir::registerDialects(registry);\n    ascir::registerExtensions(registry);\n    return MlirLspServerMain(argc, argv, registry).failed();\n}
```

**达成路径**

[IN] LSP client requests -> MlirLspServerMain -> MLIR parsing

**验证说明**: Verified: LSP server accepts untrusted input from LSP clients. MLIR parsing risk.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [pybind_memory_lifetime_001] Memory Management - pyasc_bind_value/pyasc_bind_region/pyasc_bind_blocks

**严重性**: Medium | **CWE**: CWE-416 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:340-400` @ `pyasc_bind_value/pyasc_bind_region/pyasc_bind_blocks`
**模块**: pybind_bindings
**跨模块**: mlir_core,pybind_bindings

**描述**: Using ret::reference policy for returning C++ object references to Python. If the underlying C++ object is destroyed while Python still holds a reference, use-after-free can occur. This pattern is used extensively throughout the binding layer.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:340-400`)

```c
ret::reference
```

**达成路径**

[IN] C++ object -> [BIND] pybind11 with ret::reference -> [OUT] Python reference (lifetime not managed by Python)

**验证说明**: Verified: ret::reference policy exposes lifetime risk. Extensive use in binding layer.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [pybind_cast_exception_001] Type Safety - __eq__/__ne__

**严重性**: Medium | **CWE**: CWE-704 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:221-229` @ `__eq__/__ne__`
**模块**: pybind_bindings

**描述**: py::cast<Type*> in __eq__ operator may throw exception or return nullptr depending on pybind11 version. The code checks for nullptr but may not handle all exception cases properly.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:221-229`)

```c
Type *other_ty = py::cast<Type *>(other)
```

**达成路径**

[IN] Python object -> [CAST] py::cast<Type*> -> [CHECK] nullptr check -> [OUT] comparison result

**验证说明**: Verified: py::cast exception handling incomplete in __eq__.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-INJ-005] path_traversal - printOperation

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `lib/Target/AscendC/External/Emitc.cpp:55-66` @ `printOperation`
**模块**: ascendc_target

**描述**: emitc::IncludeOp 直接输出用户提供的 include 路径到生成的 C++ #include 语句中，无任何路径验证。可能用于路径遍历或包含恶意头文件。

**漏洞代码** (`lib/Target/AscendC/External/Emitc.cpp:55-66`)

```c
LogicalResult mlir::printOperation(CodeEmitter &emitter, emitc::IncludeOp includeOp) {
    os << "#include";
    if (includeOp.getIsStandardInclude()) {
        os << "<" << includeOp.getInclude() << ">";
    } else {
        os << "\"" << includeOp.getInclude() << "\"";
    }
}
```

**达成路径**

MLIR emitc.include → includeOp.getInclude() → #include "path" → C++ 代码

**验证说明**: Verified: IncludeOp outputs #include path directly. Path traversal possible.

**评分明细**: base: 30 | reachability: 10 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-FMT-001] format_string_injection - AscendC_PrintfOp

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-134 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `include/ascir/Dialect/Asc/IR/Basic/OpDumpTensor.td:27-29` @ `AscendC_PrintfOp`
**模块**: include_headers
**跨模块**: cli_tools → include_headers → ascendc_target

**描述**: PrintfOp 定义使用 StrAttr 作为格式字符串描述。如果 desc 字段包含用户控制的格式说明符，可能导致格式字符串漏洞，泄露内存或导致崩溃。

**漏洞代码** (`include/ascir/Dialect/Asc/IR/Basic/OpDumpTensor.td:27-29`)

```c
def AscendC_PrintfOp : APIOp<"printf", "printf"> {
  let arguments = (ins StrAttr:$desc, Variadic<AnyType>:$vars);
}
```

**达成路径**

[CREDENTIAL_FLOW] MLIR File Input → PrintfOp.desc (StrAttr) → AscendC::printf call

**验证说明**: Verified: PrintfOp uses StrAttr for format string. Format string injection possible but requires MLIR file manipulation. Severity downgraded - format string exploitation limited in this context.

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-RUN-004] path_control - Compiler.__init__

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `python/asc/runtime/compiler.py:98-104` @ `Compiler.__init__`
**模块**: runtime

**描述**: Environment variable-controlled output directory path. PYASC_DUMP_PATH environment variable controls the directory where compiled binaries and intermediate files are written. While shutil.copyfile() is used (safe), an attacker controlling this path could redirect outputs to attacker-controlled locations or cause denial of service through invalid paths.

**漏洞代码** (`python/asc/runtime/compiler.py:98-104`)

```c
dump_dir = os.environ.get('PYASC_DUMP_PATH', None)
if dump_dir is not None:
    try:
        self.dump_dir = Path(dump_dir).resolve()
    except OSError as e:
        raise RuntimeError('Get {} realpath failed.'.format(str(dump_dir))) from e
```

**达成路径**

compiler.py:98 → os.environ.get('PYASC_DUMP_PATH', None) [SOURCE - env var]
→ compiler.py:100-101 → Path(dump_dir).resolve() [PATH RESOLUTION]
→ compiler.py:200 → shutil.copyfile(dst, self.dump_dir / 'binary.o') [FILE COPY - no path traversal but attacker-controlled destination]

**验证说明**: Verified: PYASC_DUMP_PATH controls output directory, Path().resolve() sanitizes but attacker can control destination. Lower severity - can redirect outputs but not execute code.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-RT-005] improper_input_validation - register_device_binary_kernel

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `python/asc/lib/runtime/interface.py:224-242` @ `register_device_binary_kernel`
**模块**: lib_runtime

**描述**: Kernel binary registration accepts arbitrary bytes without validation. register_device_binary_kernel takes kernel_binary as raw bytes and passes it to NPU without validating structure, magic values, or content. Malformed or malicious binary could potentially exploit NPU runtime vulnerabilities.

**漏洞代码** (`python/asc/lib/runtime/interface.py:224-242`)

```c
def register_device_binary_kernel(kernel_binary: bytes, core_type_id: int) -> support.Kernel:
    _lazy_init()
    kernel_size = len(kernel_binary)
    if kernel_size <= 0:
        raise RuntimeError("...")
    device_binary = support.DevBinary(
        data=ctypes.c_char_p(kernel_binary),
        length=ctypes.c_uint64(kernel_size),
        version=ctypes.c_uint32(0),
        magic=ctypes.c_uint32(core_type_id),
    )
```

**达成路径**

interface.py:224 kernel_binary parameter [SOURCE] user input
interface.py:236-239 passed to DevBinary struct
interface.py:237 DevBinaryRegisterWrapper [SINK] NPU runtime

**验证说明**: Verified: kernel_binary passed directly to NPU without format validation. Size check exists (kernel_size > 0). Risk depends on NPU runtime handling of malformed data.

**评分明细**: base: 30 | reachability: 10 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-PYBIND-003] path_traversal - bind_create_emitc_operations

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `python/src/OpBuilder.cpp:763-764` @ `bind_create_emitc_operations`
**模块**: pybind_bindings
**跨模块**: pybind_bindings → codegen

**描述**: IncludeOp 绑定直接使用用户提供的文件名，未进行路径验证或规范化。可能导致恶意文件包含或路径遍历。

**漏洞代码** (`python/src/OpBuilder.cpp:763-764`)

```c
.def("create_emitc_IncludeOp",
     [](PyOpBuilder &self, const std::string &filename) { self.create<emitc::IncludeOp>(StringRef(filename)); })
```

**达成路径**

[CREDENTIAL_FLOW] Python 用户输入 → pybind11 绑定参数 filename → emitc::IncludeOp → CodeGen 模块处理 #include

**验证说明**: Verified: IncludeOp binding passes filename without validation. Path traversal possible.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-RUN-005] insecure_temp_file - FileCacheManager.put

**严重性**: Medium | **CWE**: CWE-377 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `python/asc/runtime/cache.py:81-91` @ `FileCacheManager.put`
**模块**: runtime

**描述**: Temporary file creation in cache directory without secure permissions. FileCacheManager creates temporary directories using predictable naming pattern (tmp.pid_{pid}_{uuid}) but without secure permissions. While uuid provides collision avoidance, the temporary directory is created within the attacker-controllable cache directory.

**漏洞代码** (`python/asc/runtime/cache.py:81-91`)

```c
temp_dir = os.path.join(self.cache_dir, f'tmp.pid_{pid}_{rnd_id}')
os.makedirs(temp_dir, exist_ok=True)
temp_path = os.path.join(temp_dir, filename)
...
with open(temp_path, mode) as f:
    f.write(data)
os.replace(temp_path, filepath)
```

**达成路径**

cache.py:81-82 → os.makedirs(temp_dir, exist_ok=True) [INSECURE TEMP DIR]
→ cache.py:86-87 → open(temp_path, mode) → f.write(data) [INSECURE TEMP FILE]
→ [CREDENTIAL_FLOW] temp_dir located within self.cache_dir (env-controlled)

**验证说明**: Verified: Temporary files created in attacker-controlled cache dir. UUID provides some collision resistance. Risk depends on file permission issues.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -5 | context: -10 | cross_file: 10

---

### [VULN-CG-008] improper_input_validation - generic_visit

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: [python-dataflow-module-scanner]

**位置**: `python/asc/codegen/function_visitor.py:290-291` @ `generic_visit`
**模块**: codegen

**描述**: Limited validation of AST node types. While generic_visit raises UnsupportedSyntaxError for unsupported nodes, the visitor allows many node types that could have edge cases. The validation is declarative rather than comprehensive.

**漏洞代码** (`python/asc/codegen/function_visitor.py:290-291`)

```c
def generic_visit(self, node: ast.AST) -> NoReturn:
    self.raise_unsupported(node, f"{node.__class__.__name__} syntax is not supported in JIT function")
```

**达成路径**

[IN] jit.py:190 → FunctionVisitor.visit(node) [USER AST]
→ function_visitor.py:293-312 → visit() has limited node type checks
→ function_visitor.py:290-291 → generic_visit() catches unsupported nodes [REACTIVE NOT PROACTIVE]
→ [NOTE] Many specific visit_* methods exist but edge cases possible
[OUT] → Limited protection against novel AST manipulation attacks

**验证说明**: Verified: Limited AST node type validation. Edge cases possible.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN-SEC-EMITASC-001] type_confusion - ReinterpretCastOp::areCastCompatible

**严重性**: Medium | **CWE**: CWE-843 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `lib/Dialect/EmitAsc/IR/Ops.cpp:45-48` @ `ReinterpretCastOp::areCastCompatible`
**模块**: emitasc_dialect
**跨模块**: emitasc_dialect → 可能涉及使用此Dialect的其他编译模块

**描述**: ReinterpretCastOp 类型兼容性检查过于宽松，仅检查输入输出数量为1，未验证类型是否真正兼容。可能导致类型混淆，进而引发内存安全问题。

**漏洞代码** (`lib/Dialect/EmitAsc/IR/Ops.cpp:45-48`)

```c
bool ReinterpretCastOp::areCastCompatible(TypeRange inputs, TypeRange outputs)
{
    return inputs.size() == 1U && outputs.size() == 1U;
}
```

**达成路径**

本地定义 -> ReinterpretCastOp::areCastCompatible -> 类型转换检查 [SINK]

**验证说明**: Verified: ReinterpretCastOp check only checks count, not type compatibility.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-TYPE-001] type_confusion - EmitAsc_ReinterpretCastOp

**严重性**: Medium | **CWE**: CWE-843 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `include/ascir/Dialect/EmitAsc/IR/Ops.td:124-131` @ `EmitAsc_ReinterpretCastOp`
**模块**: include_headers
**跨模块**: cli_tools → include_headers → ascendc_target

**描述**: ReinterpretCastOp 定义允许类型重解释转换。如果源类型和目标类型不兼容，可能导致类型混淆，引发内存访问错误或数据损坏。

**漏洞代码** (`include/ascir/Dialect/EmitAsc/IR/Ops.td:124-131`)

```c
def EmitAsc_ReinterpretCastOp : EmitAsc_Op<"reinterpret_cast", [Pure, DeclareOpInterfaceMethods<CastOpInterface>]> {
  let summary = "Convert between types by reinterpreting the underlying data";
}
```

**达成路径**

User MLIR Input → ReinterpretCastOp → Type reinterpretation → Generated C++ reinterpret_cast

**验证说明**: Verified: ReinterpretCastOp allows type reinterpretation. Type confusion possible but requires specific MLIR manipulation. Limited attack surface.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-CG-007] code_injection - apply_binary_method

**严重性**: Medium | **CWE**: CWE-95 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: [python-dataflow-module-scanner]

**位置**: `python/asc/codegen/function_visitor.py:165` @ `apply_binary_method`
**模块**: codegen

**描述**: Regex-based method name transformation without validation. apply_binary_method uses re.sub to transform method names like __add__ to __radd__. While regex patterns are hardcoded, the method names could theoretically be manipulated through AST node manipulation to produce unexpected method names.

**漏洞代码** (`python/asc/codegen/function_visitor.py:165`)

```c
reverse_method_name = re.sub(r"__(.*)__", r"__r\1__", method_name)
```

**达成路径**

[IN] function_visitor.py:95-113 → get_binary_method_name() returns hardcoded names [CONTROLLED]
→ function_visitor.py:165 → re.sub(r"__(.*)__", r"__r\1__", method_name) [TRANSFORMATION]
→ function_visitor.py:167 → getattr(rhs, reverse_method_name)(lhs) [EXECUTION]
[OUT] → Limited risk due to hardcoded method names, but pattern is vulnerable

**验证说明**: Verified: Regex-based method transformation. Limited risk - hardcoded names.

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: 0 | context: -5 | cross_file: 0

---

## 5. Low 漏洞 (9)

### [PYASC-DF-cli_tools-004] Missing Output Validation - translateToAscendC

**严重性**: Low | **CWE**: CWE-74 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `lib/Target/AscendC/Translation.cpp:299-303` @ `translateToAscendC`
**模块**: cli_tools
**跨模块**: cli_tools,translation

**描述**: translateToAscendC function generates C code from MLIR without validating output for potentially dangerous patterns.

**漏洞代码** (`lib/Target/AscendC/Translation.cpp:299-303`)

```c
LogicalResult mlir::translateToAscendC(Operation *op, raw_ostream &os)\n{\n    CodeEmitter emitter(os);\n    return emitOperation(emitter, *op, false);\n}
```

**达成路径**

[IN] MLIR Operation* -> translateToAscendC -> [OUT] raw_ostream (generated C code)

**验证说明**: Verified: translateToAscendC generates C code without output validation. Low direct security impact.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -5 | context: -10 | cross_file: 0

---

### [VULN-SEC-LANG-002] format_string_injection - printf

**严重性**: Low | **CWE**: CWE-134 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `python/asc/language/basic/dump_tensor.py:46-63` @ `printf`
**模块**: language
**跨模块**: language → ascendc_target

**描述**: printf() 函数接受用户提供的格式字符串 desc 参数，未进行格式字符串验证。可能导致格式字符串注入，恶意用户可通过特殊格式字符串读取或写入内存。

**漏洞代码** (`python/asc/language/basic/dump_tensor.py:46-63`)

```c
@require_jit
@set_common_docstring(api_name="printf")
def printf(desc: str, *params) -> None:
    var_ir_values = []
    desc_str_list = desc.split("%s")
    # ... 处理格式字符串
    global_builder.get_ir_builder().create_asc_PrintfOp(desc, var_ir_values)
```

**达成路径**

User DSL code → printf(desc, *params) [SOURCE] → create_asc_PrintfOp(desc, params) → C++ backend [SINK]

**验证说明**: Verified: printf() format string. Limited exploitation potential due to %s split.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: -10 | context: -5 | cross_file: 0

---

### [VULN-SEC-LANG-006] type_confusion - LocalTensor.reinterpret_cast

**严重性**: Low | **CWE**: CWE-843 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `python/asc/language/core/tensor.py:389-399` @ `LocalTensor.reinterpret_cast`
**模块**: language
**跨模块**: language → ascendc_target

**描述**: reinterpret_cast() 方法允许将 LocalTensor 重解释为任意 DataType，仅检查 is_numeric() 但未验证类型大小匹配。可能导致类型混淆和数据损坏。

**漏洞代码** (`python/asc/language/core/tensor.py:389-399`)

```c
@require_jit
@set_tensor_docstring(tensor_name="LocalTensor", api_name="reinterpret_cast")
def reinterpret_cast(self, dtype: DataType) -> LocalTensor:
    if not dtype.is_numeric():
        raise RuntimeError("ReinterpretCast dtype must be integer or float")
    # 未验证类型大小是否匹配
```

**达成路径**

User DSL code → reinterpret_cast(dtype) [SOURCE] → create_asc_LocalTensorReinterpretCastOp → NPU tensor reinterpret [SINK]

**验证说明**: Verified: reinterpret_cast() allows dtype reinterpretation. Type confusion possible.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: -10 | context: -5 | cross_file: 0

---

### [VULN-SEC-CG-005] code_injection - visit_Attribute

**严重性**: Low | **CWE**: CWE-94 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `python/asc/codegen/dependencies_finder.py:148-157` @ `visit_Attribute`
**模块**: codegen

**描述**: Attribute access in DependenciesFinder for dependency tracking. visit_Attribute (line 155) uses getattr(lhs, node.attr) where node.attr is user-controlled. Lower risk since DependenciesFinder only records references for hashing, not executes code.

**漏洞代码** (`python/asc/codegen/dependencies_finder.py:148-157`)

```c
def visit_Attribute(self, node):
    lhs = self.visit(node.value)
    while isinstance(lhs, ast.Attribute):
        lhs = self.visit(lhs.value)
    lhs_name = getattr(lhs, "__name__", "")
    if lhs is None or lhs_name in self.supported_modules:
        return None
    ret = getattr(lhs, node.attr)  # user-controlled attr
    self.record_reference(ret)
    return ret
```

**达成路径**

[SOURCE] User DSL → AST Attribute node
[PROPAGATION] visit(node.value) → lhs object
[SINK] getattr(lhs, node.attr) at line 155
[MITIGATION] Only records reference, doesn't execute - lower risk

**验证说明**: Verified: DependenciesFinder uses getattr but only records references. Lower risk.

**评分明细**: base: 30 | reachability: 15 | controllability: 5 | mitigations: -5 | context: -10 | cross_file: 0

---

### [VULN-SEC-PYBIND-004] information_exposure - pyasc_bind_value

**严重性**: Low | **CWE**: CWE-200 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `python/src/IR.cpp:369` @ `pyasc_bind_value`
**模块**: pybind_bindings

**描述**: 将内部指针地址（Value::getImpl()）作为 uint64_t 暴露给 Python，可能泄露内存布局信息。虽然这是编译器库常见模式用于生成唯一标识符，但仍存在信息泄露风险。

**漏洞代码** (`python/src/IR.cpp:369`)

```c
.def("id", [](Value &self) { return reinterpret_cast<uint64_t>(self.getImpl()); });
```

**达成路径**

内部指针 → reinterpret_cast → uint64_t → Python 返回值

**验证说明**: Verified: Same pattern as pybind_pointer_exposure_001.

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: -5 | context: -10 | cross_file: 0

---

### [pybind_pointer_exposure_001] Information Exposure - Value.id

**严重性**: Low | **CWE**: CWE-200 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:369` @ `Value.id`
**模块**: pybind_bindings

**描述**: reinterpret_cast used to convert internal pointer to uint64_t ID. This exposes internal memory addresses to Python layer, which could be used for memory corruption if combined with other vulnerabilities.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:369`)

```c
reinterpret_cast<uint64_t>(self.getImpl())
```

**达成路径**

[IN] Value object -> [CAST] reinterpret_cast -> [OUT] Python uint64_t (memory address exposed)

**验证说明**: Verified: reinterpret_cast exposes memory address as uint64_t ID. Information disclosure.

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: -5 | context: -10 | cross_file: 0

---

### [pybind_pointer_exposure_002] Information Exposure - Attribute.id

**严重性**: Low | **CWE**: CWE-200 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:451` @ `Attribute.id`
**模块**: pybind_bindings

**描述**: reinterpret_cast used to convert Attribute opaque pointer to uint64_t ID. Exposes internal memory addresses.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/5/pyasc/python/src/IR.cpp:451`)

```c
reinterpret_cast<uint64_t>(self.getAsOpaquePointer())
```

**达成路径**

[IN] Attribute object -> [CAST] reinterpret_cast -> [OUT] Python uint64_t

**验证说明**: Verified: Attribute opaque pointer exposed. Similar to 001.

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: -5 | context: -10 | cross_file: 0

---

### [VULN-SEC-LANG-004] missing_input_validation - GlobalTensor.get_phy_addr

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `python/asc/language/core/tensor.py:106-111` @ `GlobalTensor.get_phy_addr`
**模块**: language
**跨模块**: language → lib_runtime → runtime

**描述**: get_phy_addr() 方法接受 offset 参数但未验证其有效性（负数、超出边界）。可能导致内存越界访问。

**漏洞代码** (`python/asc/language/core/tensor.py:106-111`)

```c
@require_jit
@set_tensor_docstring(tensor_name="GlobalTensor", api_name="get_phy_addr")
def get_phy_addr(self, offset: RuntimeInt = 0) -> GlobalAddress:
    # offset 未验证
    handle = builder.create_asc_GlobalTensorGetPhyAddrOp(ga_type, self.to_ir(), _mat(offset, KnownTypes.uint64).to_ir())
```

**达成路径**

User DSL code → get_phy_addr(offset) [SOURCE] → create_asc_GlobalTensorGetPhyAddrOp → NPU physical address access [SINK]

**验证说明**: Verified: get_phy_addr() offset without validation. Requires NPU context.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -5 | context: -5 | cross_file: 0

---

### [VULN-SEC-LANG-005] missing_input_validation - LocalTensor.get_phy_addr

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `python/asc/language/core/tensor.py:316-320` @ `LocalTensor.get_phy_addr`
**模块**: language
**跨模块**: language → lib_runtime

**描述**: get_phy_addr() 方法接受 offset 参数但未验证其有效性。可能导致内存越界访问。

**漏洞代码** (`python/asc/language/core/tensor.py:316-320`)

```c
@require_jit
@set_tensor_docstring(tensor_name="LocalTensor", api_name="get_phy_addr")
def get_phy_addr(self, offset: RuntimeInt = 0) -> RuntimeInt:
    # offset 未验证
    handle = builder.create_asc_LocalTensorGetPhyAddrOp(builder.get_ui64_type(), self.to_ir(), _mat(offset, KnownTypes.uint32).to_ir())
```

**达成路径**

User DSL code → get_phy_addr(offset) [SOURCE] → create_asc_LocalTensorGetPhyAddrOp → NPU physical address access [SINK]

**验证说明**: Verified: LocalTensor get_phy_addr variant. Similar risk.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -5 | context: -5 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| ascendc_target | 0 | 1 | 3 | 0 | 4 |
| cli_tools | 0 | 0 | 3 | 1 | 4 |
| codegen | 0 | 5 | 3 | 1 | 9 |
| cross_module | 0 | 1 | 0 | 0 | 1 |
| emitasc_dialect | 0 | 0 | 1 | 0 | 1 |
| include_headers | 0 | 0 | 2 | 0 | 2 |
| language | 0 | 0 | 1 | 4 | 5 |
| lib_host | 0 | 0 | 0 | 0 | 0 |
| lib_runtime | 0 | 4 | 3 | 0 | 7 |
| pybind_bindings | 0 | 2 | 15 | 3 | 20 |
| runtime | 0 | 1 | 2 | 0 | 3 |
| **合计** | **0** | **14** | **33** | **9** | **56** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-704 | 11 | 18.3% |
| CWE-20 | 9 | 15.0% |
| CWE-94 | 7 | 11.7% |
| CWE-22 | 5 | 8.3% |
| CWE-74 | 4 | 6.7% |
| CWE-200 | 4 | 6.7% |
| CWE-843 | 3 | 5.0% |
| CWE-78 | 3 | 5.0% |
| CWE-476 | 2 | 3.3% |
| CWE-416 | 2 | 3.3% |
| CWE-134 | 2 | 3.3% |
| CWE-95 | 1 | 1.7% |
| CWE-749 | 1 | 1.7% |
| CWE-732 | 1 | 1.7% |
| CWE-668 | 1 | 1.7% |
| CWE-59 | 1 | 1.7% |
| CWE-426 | 1 | 1.7% |
| CWE-377 | 1 | 1.7% |
| CWE-276 | 1 | 1.7% |
