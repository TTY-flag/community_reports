# 漏洞扫描报告 — 已确认漏洞

**项目**: AscendNPU-IR
**扫描时间**: 2026-04-23T23:10:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 12 | 57.1% |
| LIKELY | 6 | 28.6% |
| POSSIBLE | 2 | 9.5% |
| null | 1 | 4.8% |
| **总计** | **21** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 12 | 100.0% |
| **有效漏洞总计** | **12** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[SEC-001]** Untrusted Search Path (High) - `bishengir/lib/Tools/Utils/Utils.cpp:285` @ `getBiShengInstallPath` | 置信度: 80
2. **[SEC-002]** Untrusted Search Path - Binary Execution (High) - `bishengir/lib/Tools/Utils/Utils.cpp:175` @ `execute` | 置信度: 80
3. **[SEC-003]** Untrusted Search Path - hivmc Execution (High) - `bishengir/lib/Tools/bishengir-compile/BiShengIRCompileMain.cpp:215` @ `runExternalHIVMC` | 置信度: 80
4. **[SEC-004]** Untrusted Search Path - CLI Delegate (High) - `bishengir/tools/bishengir-compile/bishengir-compile.cpp:66` @ `runBishengirCompile91095` | 置信度: 80
5. **[SEC-005]** Untrusted Search Path - opt Delegate (High) - `bishengir/tools/bishengir-opt/bishengir-opt.cpp:76` @ `runBishengirOptA5` | 置信度: 80
6. **[DF-002]** Untrusted Search Path (High) - `bishengir/lib/Tools/Utils/Utils.cpp:175` @ `execute` | 置信度: 80
7. **[DF-003]** Untrusted Search Path (High) - `bishengir/tools/bishengir-compile/bishengir-compile.cpp:66` @ `runBishengirCompile91095` | 置信度: 80
8. **[DF-004]** Untrusted Search Path (High) - `bishengir/tools/bishengir-opt/bishengir-opt.cpp:76` @ `runBishengirOptA5` | 置信度: 80
9. **[DF-005]** Untrusted Search Path (High) - `bishengir/lib/Tools/bishengir-compile/BiShengIRCompileMain.cpp:176` @ `runExternalHIVMC` | 置信度: 80
10. **[VULN-DF-ENV-001]** environment_variable_injection (High) - `bishengir/lib/Tools/Utils/Utils.cpp:285` @ `getBiShengInstallPath` | 置信度: 80

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@bishengir/tools/bishengir-compile/bishengir-compile.cpp` | cmdline | untrusted_local | CLI 工具入口，用户通过命令行参数传入输入文件路径和编译选项 | 主函数：解析 argv 参数，读取 MLIR 文件，执行编译管线 |
| `main@bishengir/tools/bishengir-opt/bishengir-opt.cpp` | cmdline | untrusted_local | CLI 工具入口，用户通过命令行参数传入 MLIR 文件和优化选项 | 主函数：解析 argv 参数，执行 MLIR 优化 Pass |
| `compile@bishengir/python/wheel/ascendnpuir/compiler.py` | decorator | untrusted_local | Python API 入口，用户传入 MLIR 字符串和编译选项 | Python compile() 函数：接收 MLIR 字符串，通过 subprocess 调用 bishengir-compile |
| `bishengirRegisterAllDialects@bishengir/lib/CAPI/RegisterEverything/RegisterEverything.cpp` | rpc | semi_trusted | C API 入口，外部 C/C++ 程序调用注册 Dialect | C API 函数：注册所有 Dialect 到 MLIR Context |
| `execute@bishengir/lib/Tools/Utils/Utils.cpp` | rpc | semi_trusted | 执行外部二进制，参数来自内部配置或用户输入 | 执行外部二进制：通过 llvm::sys::ExecuteAndWait 执行 hivmc 等外部工具 |
| `parseSourceFile@bishengir/tools/bishengir-compile/bishengir-compile.cpp` | file | untrusted_local | 解析 MLIR 源文件，文件内容来自用户输入 | MLIR 解析器：解析 MLIR 文件内容为 ModuleOp |
| `getBiShengInstallPath@bishengir/lib/Tools/Utils/Utils.cpp` | env | semi_trusted | 读取环境变量 BISHENG_INSTALL_PATH | 环境变量读取：获取安装路径，影响外部二进制查找 |
| `parseAttribute@bishengir/tools/bishengir-hfusion-ods-gen/bishengir-hfusion-ods-yaml-gen.cpp` | file | untrusted_local | 解析 YAML 配置文件中的属性 | YAML 解析器：解析 YAML 配置生成 C++ 代码 |

**其他攻击面**:
- CLI Tool Interface: bishengir-compile 和 bishengir-opt 命令行参数和输入文件
- Python Binding Interface: ascendnpuir.compile() 函数接收的 MLIR 字符串
- CAPI Interface: bishengirRegisterAllDialects 等 C API 函数
- MLIR Parser: parseSourceFile() 解析用户提供的 MLIR 文件内容
- External Binary Execution: execute() 函数调用 hivmc 等外部工具
- Environment Variable: getenv(BISHENG_INSTALL_PATH) 影响二进制路径查找
- YAML Configuration: bishengir-hfusion-ods-gen 解析 YAML 配置文件

---

## 3. High 漏洞 (12)

### [SEC-001] Untrusted Search Path - getBiShengInstallPath

**严重性**: High | **CWE**: CWE-426 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-auditor, dataflow-scanner

**位置**: `bishengir/lib/Tools/Utils/Utils.cpp:285-300` @ `getBiShengInstallPath`
**模块**: ToolsLib
**跨模块**: ToolsLib → Tools → PythonWheel

**描述**: Environment variable BISHENG_INSTALL_PATH is read via getenv() without validation and used to locate external binary executables (hivmc, bishengir-compile-a5, bishengir-opt-a5). An attacker can set BISHENG_INSTALL_PATH to a malicious directory containing fake binaries, which will be executed when the compiler runs.

**漏洞代码** (`bishengir/lib/Tools/Utils/Utils.cpp:285-300`)

```c
const char *kBiShengInstallPath = getenv(kBiShengInstallPathEnv);
if (!kBiShengInstallPath) {
  LLVM_DEBUG(llvm::dbgs() << "[DEBUG] BISHENG_INSTALL_PATH is not set.\n");
  return "";
}
llvm::SmallString<128> path;
path.append(kBiShengInstallPath);
```

**达成路径**

getenv("BISHENG_INSTALL_PATH") -> getBiShengInstallPath() -> execute(binName, installPath, ...) -> findProgramByName(binName, {installPath}) -> ExecuteAndWait(maliciousBinary)

**验证说明**: BISHENG_INSTALL_PATH 环境变量无验证直接用于外部二进制查找路径。攻击者在共享环境/CI/CD中可设置恶意路径，放置伪造的 hivmc/bishengir-compile-a5 二进制，导致任意代码执行。调用链完整：main → getBiShengInstallPath → execute → findProgramByName → ExecuteAndWait。部署场景包含服务器环境，环境变量可能被攻击者控制。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-002] Untrusted Search Path - Binary Execution - execute

**严重性**: High | **CWE**: CWE-426 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `bishengir/lib/Tools/Utils/Utils.cpp:175-221` @ `execute`
**模块**: ToolsLib
**跨模块**: ToolsLib → Tools

**描述**: execute() function uses findProgramByName() with user-controlled installPath from BISHENG_INSTALL_PATH to locate and execute external binaries. If installPath contains malicious binaries, they will be executed with user's privileges. Calls: execute("hivmc", getBiShengInstallPath(), args) in runExternalHIVMC(); execute("bishengir-compile-a5", getBiShengInstallPath(), args) in runBishengirCompile91095(); execute("bishengir-opt-a5", getBiShengInstallPath(), args) in runBishengirOptA5().

**漏洞代码** (`bishengir/lib/Tools/Utils/Utils.cpp:175-221`)

```c
if (!installPath.empty()) {
  if (auto binPathOrErr = llvm::sys::findProgramByName(binName, {installPath})) {
    binPath = binPathOrErr.get();
  }
}
...
if (llvm::sys::ExecuteAndWait(binPath, arguments, ...) != 0)
```

**达成路径**

installPath (from BISHENG_INSTALL_PATH) -> findProgramByName(binName, {installPath}) -> binPath -> ExecuteAndWait(binPath)

**验证说明**: execute() 函数使用 findProgramByName() 在攻击者控制的 installPath 中搜索二进制，直接 ExecuteAndWait 执行。核心漏洞源头，所有委托执行路径都依赖此函数。风险为任意代码执行。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-003] Untrusted Search Path - hivmc Execution - runExternalHIVMC

**严重性**: High | **CWE**: CWE-426 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `bishengir/lib/Tools/bishengir-compile/BiShengIRCompileMain.cpp:215-217` @ `runExternalHIVMC`
**模块**: Tools
**跨模块**: ToolsLib → Tools

**描述**: runExternalHIVMC() calls execute() with getBiShengInstallPath() to locate and execute the hivmc binary. If BISHENG_INSTALL_PATH is set to a malicious directory containing a fake hivmc, arbitrary code execution is possible.

**漏洞代码** (`bishengir/lib/Tools/bishengir-compile/BiShengIRCompileMain.cpp:215-217`)

```c
if (failed(execute(getHIVMCName(), getBiShengInstallPath(), argumentsRef))) {
  return failure();
}
```

**达成路径**

getBiShengInstallPath() -> execute("hivmc", installPath, args) -> ExecuteAndWait(malicious_hivmc)

**验证说明**: runExternalHIVMC() 是主要编译管线路径，调用 execute('hivmc', getBiShengInstallPath())。攻击者通过设置 BISHENG_INSTALL_PATH 可在编译过程中执行伪造的 hivmc 二进制。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-004] Untrusted Search Path - CLI Delegate - runBishengirCompile91095

**严重性**: High | **CWE**: CWE-426 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `bishengir/tools/bishengir-compile/bishengir-compile.cpp:66-75` @ `runBishengirCompile91095`
**模块**: Tools
**跨模块**: Tools → ToolsLib

**描述**: runBishengirCompile91095() delegates execution to bishengir-compile-a5 binary located via BISHENG_INSTALL_PATH. Malicious binary injection possible.

**漏洞代码** (`bishengir/tools/bishengir-compile/bishengir-compile.cpp:66-75`)

```c
if (failed(bishengir::execute("bishengir-compile-a5",
                          bishengir::getBiShengInstallPath(), arguments)))
  return EXIT_FAILURE;
```

**达成路径**

getBiShengInstallPath() -> execute("bishengir-compile-a5", installPath, argv) -> malicious binary execution

**验证说明**: bishengir-compile 工具在检测到 Ascend910_95 目标时委托给 bishengir-compile-a5。攻击者通过 BISHENG_INSTALL_PATH 可劫持此委托，执行恶意 bishengir-compile-a5。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-005] Untrusted Search Path - opt Delegate - runBishengirOptA5

**严重性**: High | **CWE**: CWE-426 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `bishengir/tools/bishengir-opt/bishengir-opt.cpp:76-89` @ `runBishengirOptA5`
**模块**: Tools
**跨模块**: Tools → ToolsLib

**描述**: runBishengirOptA5() delegates execution to bishengir-opt-a5 binary located via BISHENG_INSTALL_PATH. Malicious binary injection possible.

**漏洞代码** (`bishengir/tools/bishengir-opt/bishengir-opt.cpp:76-89`)

```c
if (failed(bishengir::execute("bishengir-opt-a5",
                          bishengir::getBiShengInstallPath(), arguments)))
  return EXIT_FAILURE;
```

**达成路径**

getBiShengInstallPath() -> execute("bishengir-opt-a5", installPath, argv) -> malicious binary execution

**验证说明**: bishengir-opt 工具在检测到 Ascend910_95 目标时委托给 bishengir-opt-a5。同样存在 BISHENG_INSTALL_PATH 劫持风险。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [DF-002] Untrusted Search Path - execute

**严重性**: High | **CWE**: CWE-426 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `bishengir/lib/Tools/Utils/Utils.cpp:175-221` @ `execute`
**模块**: ToolsLib
**跨模块**: ToolsLib → Tools → ExecutionEngine

**描述**: execute() 函数通过 findProgramByName() 在 installPath 中搜索外部二进制。installPath 来自 getBiShengInstallPath()，可被环境变量 BISHENG_INSTALL_PATH 控制。如果攻击者在恶意目录放置伪造的 hivmc 或 bishengir-compile-a5 二进制，将被以当前进程权限执行。

**漏洞代码** (`bishengir/lib/Tools/Utils/Utils.cpp:175-221`)

```c
if (!installPath.empty()) {
  if (auto binPathOrErr = llvm::sys::findProgramByName(binName, {installPath})) {
    binPath = binPathOrErr.get();
  }
}
llvm::sys::ExecuteAndWait(binPath, arguments, ...);
```

**达成路径**

getBiShengInstallPath() → execute() → findProgramByName(hivmc, malicious_path) → ExecuteAndWait(malicious_binary)

**验证说明**: 与 SEC-002 相同漏洞，数据流分析确认调用链完整。execute() 的 findProgramByName 使用攻击者控制的 installPath。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [DF-003] Untrusted Search Path - runBishengirCompile91095

**严重性**: High | **CWE**: CWE-426 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `bishengir/tools/bishengir-compile/bishengir-compile.cpp:66-75` @ `runBishengirCompile91095`
**模块**: Tools
**跨模块**: Tools → ToolsLib

**描述**: bishengir-compile 工具在检测到 Ascend910_95 目标时，通过 runBishengirCompile91095() 调用 execute()，传递来自环境变量的安装路径。攻击者可通过 BISHENG_INSTALL_PATH 环境变量注入恶意二进制路径。

**漏洞代码** (`bishengir/tools/bishengir-compile/bishengir-compile.cpp:66-75`)

```c
if (failed(bishengir::execute("bishengir-compile-a5",
                                bishengir::getBiShengInstallPath(), arguments)))
```

**达成路径**

argv → runBishengirCompile91095 → execute("bishengir-compile-a5", getBiShengInstallPath())

**验证说明**: 与 SEC-004 相同漏洞，bishengir-compile 的 Ascend910_95 委托路径。数据流确认 argv → runBishengirCompile91095 → execute。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [DF-004] Untrusted Search Path - runBishengirOptA5

**严重性**: High | **CWE**: CWE-426 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `bishengir/tools/bishengir-opt/bishengir-opt.cpp:76-89` @ `runBishengirOptA5`
**模块**: Tools
**跨模块**: Tools → ToolsLib

**描述**: bishengir-opt 工具在检测到 Ascend910_95 目标时，通过 runBishengirOptA5() 调用 execute()，传递来自环境变量的安装路径。攻击者可通过 BISHENG_INSTALL_PATH 环境变量注入恶意二进制路径。

**漏洞代码** (`bishengir/tools/bishengir-opt/bishengir-opt.cpp:76-89`)

```c
if (failed(bishengir::execute("bishengir-opt-a5",
                                bishengir::getBiShengInstallPath(), arguments)))
```

**达成路径**

argv → runBishengirOptA5 → execute("bishengir-opt-a5", getBiShengInstallPath())

**验证说明**: 与 SEC-005 相同漏洞，bishengir-opt 的 Ascend910_95 委托路径。数据流确认 argv → runBishengirOptA5 → execute。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [DF-005] Untrusted Search Path - runExternalHIVMC

**严重性**: High | **CWE**: CWE-426 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `bishengir/lib/Tools/bishengir-compile/BiShengIRCompileMain.cpp:176-220` @ `runExternalHIVMC`
**模块**: ToolsLib
**跨模块**: ToolsLib → Tools

**描述**: runExternalHIVMC() 在编译管线中调用 execute() 执行外部 hivmc 二进制，传递来自环境变量的安装路径。这是主要的编译路径，直接影响生产环境。

**漏洞代码** (`bishengir/lib/Tools/bishengir-compile/BiShengIRCompileMain.cpp:176-220`)

```c
if (failed(execute(getHIVMCName(), getBiShengInstallPath(), argumentsRef))) {
  return failure();
}
```

**达成路径**

config → runExternalHIVMC → execute("hivmc", getBiShengInstallPath()) → ExecuteAndWait

**验证说明**: 与 SEC-003 相同漏洞，runExternalHIVMC() 调用链。主编译管线的核心路径，影响所有编译操作。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-ENV-001] environment_variable_injection - getBiShengInstallPath

**严重性**: High | **CWE**: CWE-78 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `bishengir/lib/Tools/Utils/Utils.cpp:285-300` @ `getBiShengInstallPath`
**模块**: ToolsLib
**跨模块**: ToolsLib → Tools → PythonWheel

**描述**: getBiShengInstallPath() 使用 getenv() 读取 BISHENG_INSTALL_PATH 环境变量，该路径用于查找外部二进制（如 bishengir-compile-a5, hivmc）。攻击者可以通过设置恶意环境变量，使系统执行攻击者控制路径下的恶意二进制文件。

**漏洞代码** (`bishengir/lib/Tools/Utils/Utils.cpp:285-300`)

```c
std::string bishengir::getBiShengInstallPath() {
  const char *kBiShengInstallPathEnv = "BISHENG_INSTALL_PATH";
  const char *kBiShengInstallPath = getenv(kBiShengInstallPathEnv);
  if (!kBiShengInstallPath) {
    return "";
  }
  llvm::SmallString<128> path;
  path.append(kBiShengInstallPath);
  std::error_code errorCode = llvm::sys::fs::make_absolute(path);
```

**达成路径**

getenv(BISHENG_INSTALL_PATH) (SOURCE) → path → execute() → findProgramByName → binPath [SINK - 二进制查找路径]

**验证说明**: 与 SEC-001 完全相同漏洞，getBiShengInstallPath() 直接读取 BISHENG_INSTALL_PATH 环境变量无验证。所有依赖此函数的执行路径都存在二进制劫持风险。

**评分明细**: base: 30 | context: 0 | controllability: 20 | cross_file: 0 | mitigations: 0 | reachability: 30

---

### [DF-006] Untrusted Search Path - detectHIVMCVersion

**严重性**: High | **CWE**: CWE-426 | **置信度**: 75/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `bishengir/lib/Tools/Utils/Utils.cpp:254-283` @ `detectHIVMCVersion`
**模块**: ToolsLib

**描述**: detectHIVMCVersion() 调用 execute() 执行 hivmc --version 以检测版本，传递来自环境变量的安装路径。攻击者可通过伪造 hivmc 二进制注入恶意代码。

**漏洞代码** (`bishengir/lib/Tools/Utils/Utils.cpp:254-283`)

```c
if (failed(execute(hivmcName, getBiShengInstallPath(), args, outputFile))) {
  llvm::dbgs() << "[ERROR] Failed to run `hivmc --version`.\n";
  return std::nullopt;
}
```

**达成路径**

detectHIVMCVersion → execute("hivmc", getBiShengInstallPath()) → run fake hivmc

**验证说明**: detectHIVMCVersion() 执行 hivmc --version 检测版本。虽然版本检测触发条件有限，但仍存在 BISHENG_INSTALL_PATH 劫持风险。攻击者可通过伪造 hivmc 返回任意版本信息或执行恶意代码。

**评分明细**: base: 30 | reachability: 25 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-006] Untrusted Search Path via PATH - _get_compiler_path

**严重性**: High | **CWE**: CWE-426 | **置信度**: 70/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `bishengir/python/wheel/ascendnpuir/compiler.py:68-76` @ `_get_compiler_path`
**模块**: PythonWheel

**描述**: _get_compiler_path() uses subprocess.run(['which', 'bishengir-compile']) to locate the compiler binary via PATH environment variable. If PATH is manipulated by an attacker with sufficient privileges, a malicious bishengir-compile could be substituted.

**漏洞代码** (`bishengir/python/wheel/ascendnpuir/compiler.py:68-76`)

```c
result = subprocess.run(
    ["which", "bishengir-compile"],
    capture_output=True,
    text=True,
    check=False
)
if result.returncode == 0:
    return Path(result.stdout.strip().split('\n')[0])
```

**达成路径**

PATH env -> which bishengir-compile -> malicious binary path

**验证说明**: _get_compiler_path() 使用 which bishengir-compile 通过 PATH 查找编译器。如果 PATH 环境变量被攻击者控制，which 会返回恶意路径，后续 subprocess.run 将执行伪造的编译器。这与 BISHENG_INSTALL_PATH 劫持类似，攻击向量为 PATH 环境变量污染。

**评分明细**: base: 30 | context: 0 | controllability: 20 | cross_file: 0 | mitigations: 0 | reachability: 20

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| PythonWheel | 0 | 1 | 0 | 0 | 1 |
| Tools | 0 | 5 | 0 | 0 | 5 |
| ToolsLib | 0 | 6 | 0 | 0 | 6 |
| **合计** | **0** | **12** | **0** | **0** | **12** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-426 | 11 | 91.7% |
| CWE-78 | 1 | 8.3% |
