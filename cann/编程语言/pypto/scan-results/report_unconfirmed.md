# 漏洞扫描报告 — 待确认漏洞

**项目**: CANN/pypto
**扫描时间**: 2026-04-22T11:21:26.176Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 7 | 41.2% |
| LIKELY | 5 | 29.4% |
| FALSE_POSITIVE | 5 | 29.4% |
| **总计** | **17** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 4 | 80.0% |
| Medium | 1 | 20.0% |
| **有效漏洞总计** | **5** | - |
| 误报 (FALSE_POSITIVE) | 5 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-DYN-001]** library_injection (High) - `framework/src/cann_host_runtime/cann_host_runtime.cpp:37` @ `CannHostRuntime::CannHostRuntime` | 置信度: 65
2. **[VULN-DF-CODE-001]** code_injection (High) - `python/pypto/frontend/parser/parser.py:290` @ `Parser.parse` | 置信度: 65
3. **[VULN-DF-CODE-002]** code_injection (High) - `python/pypto/frontend/parser/entry.py:444` @ `JitCallableWrapper.compile` | 置信度: 65
4. **[VULN-SEC-CANN-001]** library_injection (High) - `framework/src/cann_host_runtime/cann_host_runtime.cpp:40` @ `CannHostRuntime::CannHostRuntime` | 置信度: 65
5. **[VULN-SEC-EVAL-001]** code_injection (Medium) - `python/pypto/frontend/parser/evaluator.py:132` @ `ExprEvaluator._eval_by_python` | 置信度: 55

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `PYBIND11_MODULE(pypto_impl, m)@undefined` | python_api | - | - | Main Python module entry point via pybind11 |
| `JitCallableWrapper.__call__@undefined` | python_api | - | - | JIT compilation entry point for user Python functions |
| `PluginHandler::OpenHandler@undefined` | dynamic_library | - | - | Dynamic library loading via dlopen |
| `CannHostRuntime::CannHostRuntime@undefined` | dynamic_library | - | - | CANN runtime library loading |
| `GetCalcOps@undefined` | dynamic_library | - | - | Calculator library loading for verification |
| `RuntimeBinaryLoadFromFile@undefined` | file_io | - | - | Load kernel binary from file |
| `CompactDumpTensorInfoParser@undefined` | file_io | - | - | Parse tensor dump files |
| `DeviceRunOnceDataFromHost@undefined` | python_api | - | - | Execute kernel with user-provided tensor data |
| `BindTensor@undefined` | python_api | - | - | Tensor creation with user-provided shape and dtype |
| `CannHostRuntime::CannHostRuntime@undefined` | environment | - | - | Environment variable ASCEND_CANN_PACKAGE_PATH |


---

## 3. High 漏洞 (4)

### [VULN-DF-DYN-001] library_injection - CannHostRuntime::CannHostRuntime

**严重性**: High | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `framework/src/cann_host_runtime/cann_host_runtime.cpp:37-56` @ `CannHostRuntime::CannHostRuntime`
**模块**: cann_host_runtime

**描述**: Environment variable ASCEND_CANN_PACKAGE_PATH controls library loading path without validation. The constructor uses this environment variable directly to construct paths for dlopen, enabling library injection if a malicious path is set.

**漏洞代码** (`framework/src/cann_host_runtime/cann_host_runtime.cpp:37-56`)

```c
std::string LibPathDir = std::string(ASCEND_CANN_PACKAGE_PATH) + "/lib64/";
handleDep_ = dlopen(soDepPath.c_str(), RTLD_LAZY | RTLD_GLOBAL);
handle_ = dlopen(soPath.c_str(), RTLD_LAZY);
```

**达成路径**

Environment Variable (ASCEND_CANN_PACKAGE_PATH) → Library path construction → RealPath() → dlopen → Function pointers loaded
Source: Environment variable
Sink: dlopen loads arbitrary library

**验证说明**: 环境变量 ASCEND_CANN_PACKAGE_PATH 控制 dlopen 加载路径。攻击者可设置恶意路径加载木马库。RealPath() 提供了一定的路径规范化，但不阻止路径替换攻击。环境变量通常由管理员控制，但在容器/云环境可能被攻击者利用。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -10 | reachability: 20

---

### [VULN-DF-CODE-001] code_injection - Parser.parse

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `python/pypto/frontend/parser/parser.py:290-308` @ `Parser.parse`
**模块**: frontend_parser
**跨模块**: frontend_parser → bindings → interface

**描述**: Parser.parse() parses user Python code AST without sandboxing. The as_ast() method converts user-provided Python source to AST without any security restrictions, enabling arbitrary code execution through malicious Python constructs.

**漏洞代码** (`python/pypto/frontend/parser/parser.py:290-308`)

```c
def parse(self) -> "Parser":
    node = self.diag.source.as_ast()
    analyzer = LivenessAnalyzer()
    self.delete_after = analyzer.analyze(node, exempt_vars)
```

**达成路径**

User Python Function → Source(func) → as_ast() → AST traversal → PTO IR → Compilation → Device execution
Source: User-provided Python function
Sink: Compiled and executed on NPU

**验证说明**: Parser.parse() 解析用户 Python AST，但 AST 解析本身不执行代码。风险在于 IR 转换和编译过程可能被恶意代码影响。需要进一步确认 IR 编译器是否对危险 AST节点有处理限制。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-CODE-002] code_injection - JitCallableWrapper.compile

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `python/pypto/frontend/parser/entry.py:444-486` @ `JitCallableWrapper.compile`
**模块**: frontend_parser
**跨模块**: frontend_parser → pypto_api → bindings

**描述**: JitCallableWrapper.compile() compiles user Python function without validation. The function parses user code, binds dynamic dimensions, and compiles to device-executable IR without sandboxing the input.

**漏洞代码** (`python/pypto/frontend/parser/entry.py:444-486`)

```c
def compile(self, tensors, tensor_defs=None):
    self._parser = self._create_parser()
    self._parser.parse()
    self._parser.bind_dynamic_dims_to_input_tensors()
    self._pto_function = self._parser.execute()
```

**达成路径**

User Python Function → _create_parser() → Parser.parse() → bind_dynamic_dims → execute() → pypto.Function → Device execution
Source: User-provided @jit decorated function
Sink: Compiled and executed on NPU

**验证说明**: JIT 编译入口点，与 VULN-DF-CODE-001 同一攻击路径。用户提供的 Python 函数被解析、编译为 PTO IR 并在 NPU 上执行。风险在于编译过程的安全性。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-SEC-CANN-001] library_injection - CannHostRuntime::CannHostRuntime

**严重性**: High | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `framework/src/cann_host_runtime/cann_host_runtime.cpp:40-46` @ `CannHostRuntime::CannHostRuntime`
**模块**: cann_host_runtime

**描述**: Environment variable ASCEND_CANN_PACKAGE_PATH controls library loading path. The path is directly used to construct dlopen arguments without whitelist validation or path sanitization. An attacker can set ASCEND_CANN_PACKAGE_PATH to a malicious directory containing trojaned libruntime.so/libprofapi.so libraries, leading to arbitrary code execution.

**漏洞代码** (`framework/src/cann_host_runtime/cann_host_runtime.cpp:40-46`)

```c
std::string LibPathDir = std::string(ASCEND_CANN_PACKAGE_PATH) + "/lib64/";
std::string soDepPath = RealPath(LibPathDir + "libprofapi.so");
handleDep_ = dlopen(soDepPath.c_str(), RTLD_LAZY | RTLD_GLOBAL);
std::string soPath = RealPath(LibPathDir + "libruntime.so");
handle_ = dlopen(soPath.c_str(), RTLD_LAZY);
```

**达成路径**

ASCEND_CANN_PACKAGE_PATH env -> LibPathDir -> RealPath() -> dlopen(libprofapi.so) -> dlopen(libruntime.so) -> dlsym() -> function pointers

**验证说明**: 与 VULN-DF-DYN-001 同一漏洞点，环境变量控制库加载路径，存在库注入风险。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -10 | reachability: 20

---

## 4. Medium 漏洞 (1)

### [VULN-SEC-EVAL-001] code_injection - ExprEvaluator._eval_by_python

**严重性**: Medium | **CWE**: CWE-94 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `python/pypto/frontend/parser/evaluator.py:132-152` @ `ExprEvaluator._eval_by_python`
**模块**: frontend_parser

**描述**: The expression evaluator uses Python's eval() and exec() to execute user-provided AST expressions during JIT compilation. While _is_safe_expression() checks for dangerous attributes (__class__, __bases__, __globals__, etc.) and dangerous functions (eval, exec, open, etc.), the sandbox is incomplete - it may miss novel escape techniques like nested attribute access, __getattribute__ tricks, or subclass instantiation chains. The empty globals dict {} limits exposure but dict_locals may contain dangerous objects.

**漏洞代码** (`python/pypto/frontend/parser/evaluator.py:132-152`)

```c
mod = ast.fix_missing_locations(ast.Expression(body=node))
exe = compile(mod, filename=self.diag.source.source_name, mode="eval")
...
return eval(exe, {}, dict_locals)
...
exe = compile(mod, filename=self.diag.source.source_name, mode="exec")
...
return exec(exe, {}, dict_locals)
```

**达成路径**

User Python function -> AST parsing -> ExprEvaluator.eval() -> compile() -> eval/exec with dict_locals

**验证说明**: 使用 eval/exec 执行用户 AST 表达式，有 _is_safe_expression 黑名单检查。但沙箱不完整：未覆盖 getattr/setattr、嵌套属性访问、子类实例化等逃逸技术。globals={} 限制了危险函数，但 locals 可能包含危险对象。

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: -20 | reachability: 20

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cann_host_runtime | 0 | 2 | 0 | 0 | 2 |
| frontend_parser | 0 | 2 | 1 | 0 | 3 |
| **合计** | **0** | **4** | **1** | **0** | **5** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-94 | 3 | 60.0% |
| CWE-426 | 2 | 40.0% |
