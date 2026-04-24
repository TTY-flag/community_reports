# 漏洞扫描报告 — 待确认漏洞

**项目**: AscendNPU-IR
**扫描时间**: 2026-04-23T23:10:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| Medium | 6 | 75.0% |
| Low | 2 | 25.0% |
| **有效漏洞总计** | **8** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[SEC-007]** Untrusted Search Path via PATH (Medium) - `bishengir/python/wheel/ascendnpuir/compiler.py:94` @ `_check_hivmc_available` | 置信度: 60
2. **[VULN-DF-CMD-001]** command_injection (Medium) - `bishengir/lib/Tools/Utils/Utils.cpp:175` @ `execute` | 置信度: 55
3. **[VULN-DF-CMD-002]** command_injection (Medium) - `bishengir/tools/bishengir-compile/bishengir-compile.cpp:66` @ `runBishengirCompile91095` | 置信度: 55
4. **[VULN-DF-CMD-003]** command_injection (Medium) - `bishengir/tools/bishengir-opt/bishengir-opt.cpp:76` @ `runBishengirOptA5` | 置信度: 55
5. **[VULN-DF-PY-001]** command_injection (Medium) - `bishengir/python/wheel/ascendnpuir/compiler.py:186` @ `compile` | 置信度: 55
6. **[VULN-DF-PY-002]** path_traversal (Medium) - `bishengir/python/wheel/ascendnpuir/compiler.py:182` @ `compile` | 置信度: 50
7. **[VULN-DF-FILE-001]** path_traversal (Low) - `bishengir/lib/ExecutionEngine/BiShengIRRunnerUtils.cpp:35` @ `getFileHandle` | 置信度: 45
8. **[VULN-DF-PARSE-001]** input_validation (Low) - `bishengir/tools/bishengir-hfusion-ods-gen/bishengir-hfusion-ods-yaml-gen.cpp:342` @ `ScalarTraits<SerializedAffineMap>::input` | 置信度: 40

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

## 3. Medium 漏洞 (6)

### [SEC-007] Untrusted Search Path via PATH - _check_hivmc_available

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `bishengir/python/wheel/ascendnpuir/compiler.py:94-104` @ `_check_hivmc_available`
**模块**: PythonWheel

**描述**: _check_hivmc_available() uses subprocess.run(['which', 'hivmc']) to check if hivmc is available via PATH. If PATH is manipulated, malicious hivmc could be located.

**漏洞代码** (`bishengir/python/wheel/ascendnpuir/compiler.py:94-104`)

```c
result = subprocess.run(
    ["which", "hivmc"],
    capture_output=True,
    text=True,
    check=False
)
return result.returncode == 0
```

**达成路径**

PATH env -> which hivmc -> malicious binary detection

**验证说明**: _check_hivmc_available() 使用 which hivmc 检查可用性。如果 PATH 被污染，会检测到恶意二进制存在。但这只是可用性检查，不直接执行。实际执行风险来自后续的 bishengir-compile 调用 hivmc（通过 BISHENG_INSTALL_PATH 或 PATH）。此检查可能误导用户或影响程序行为。

**评分明细**: base: 30 | context: 0 | controllability: 10 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-CMD-001] command_injection - execute

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `bishengir/lib/Tools/Utils/Utils.cpp:175-221` @ `execute`
**模块**: ToolsLib
**跨模块**: ToolsLib → Tools

**描述**: execute() 函数执行外部二进制时，arguments 参数直接传递给 llvm::sys::ExecuteAndWait，未进行充分验证。如果 arguments 来自用户可控的命令行参数，攻击者可能注入恶意参数或执行路径操纵。

**漏洞代码** (`bishengir/lib/Tools/Utils/Utils.cpp:175-221`)

```c
LogicalResult bishengir::execute(StringRef binName, StringRef installPath,
                                  SmallVectorImpl<StringRef> &arguments,
                                  std::optional<llvm::StringRef> outputFile,
                                  unsigned timeoutSeconds) {
  // ... binPath lookup logic ...
  arguments[0] = binPath;
  // ...
  if (llvm::sys::ExecuteAndWait(binPath, arguments, /*Env=*/std::nullopt,
                                 /*Redirects=*/redirects) != 0) {
    // ...
```

**达成路径**

argv (CLI) → registerAndParseCLIOptions → config → runBiShengIRPipeline → execute → llvm::sys::ExecuteAndWait [SINK]

**验证说明**: 重新评估: 不是 CWE-78 命令注入。execute() 使用 llvm::sys::ExecuteAndWait 数组形式，无 shell 解析。但参数直接传递给子二进制，存在参数注入风险。如果 bishengir-compile-a5/hivmc 有敏感参数处理（如文件路径、配置选项），可能存在风险。实际风险取决于目标二进制的参数处理逻辑。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-CMD-002] command_injection - runBishengirCompile91095

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `bishengir/tools/bishengir-compile/bishengir-compile.cpp:66-75` @ `runBishengirCompile91095`
**模块**: Tools
**跨模块**: Tools → ToolsLib

**描述**: runBishengirCompile91095() 函数将 argv 原始参数直接传递给 execute() 函数，未进行过滤或验证。当检测到 Ascend910_95 或 Ascend950 目标时，所有 argv 参数（除第一个）被直接添加到 arguments 列表中执行。

**漏洞代码** (`bishengir/tools/bishengir-compile/bishengir-compile.cpp:66-75`)

```c
static int runBishengirCompile91095(int argc, char **argv) {
  llvm::SmallVector<llvm::StringRef> arguments;
  arguments.push_back(""); // placeholder
  for (int i = 1; i < argc; ++i)
    arguments.push_back(argv[i]);
  if (failed(bishengir::execute("bishengir-compile-a5",
                                bishengir::getBiShengInstallPath(), arguments)))
    return EXIT_FAILURE;
```

**达成路径**

argv[1..argc] (SOURCE) → arguments → execute() → llvm::sys::ExecuteAndWait [SINK]

**验证说明**: 重新评估: 不是传统命令注入。argv 直接传递给 bishengir-compile-a5 的 arguments 数组。存在参数传递风险，但取决于目标二进制如何处理参数。可能影响编译行为，但不是 shell 命令执行。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-CMD-003] command_injection - runBishengirOptA5

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `bishengir/tools/bishengir-opt/bishengir-opt.cpp:76-89` @ `runBishengirOptA5`
**模块**: Tools
**跨模块**: Tools → ToolsLib

**描述**: runBishengirOptA5() 函数将 argv 参数直接传递给 execute() 函数，仅过滤了 --target/-target 参数，其他参数未验证。攻击者可以通过其他命令行参数注入恶意选项。

**漏洞代码** (`bishengir/tools/bishengir-opt/bishengir-opt.cpp:76-89`)

```c
static int runBishengirOptA5(int argc, char **argv) {
  llvm::SmallVector<llvm::StringRef> arguments;
  arguments.push_back("");
  for (int i = 1; i < argc; ++i) {
    llvm::StringRef arg(argv[i]);
    if (isAscend910_95TargetArg(arg))
      continue; // skip --target options
    arguments.push_back(arg);
  }
  if (failed(bishengir::execute("bishengir-opt-a5",
                                bishengir::getBiShengInstallPath(), arguments)))
```

**达成路径**

argv[1..argc] (SOURCE) → arguments (filtered for target) → execute() → llvm::sys::ExecuteAndWait [SINK]

**验证说明**: 重新评估: 不是命令注入。runBishengirOptA5() 仅过滤 --target 参数，其他 argv 直接传递。存在参数注入风险，取决于 bishengir-opt-a5 的参数处理。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-PY-001] command_injection - compile

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `bishengir/python/wheel/ascendnpuir/compiler.py:186-196` @ `compile`
**模块**: PythonWheel
**跨模块**: PythonWheel → Tools

**描述**: Python compile() 函数的 option 参数是用户可控的列表，直接通过 cmd.extend(option) 扩展到命令列表中传递给 subprocess.run()。虽然使用了列表形式（隐含 shell=False），但用户可以通过注入恶意选项参数（如 --output=/恶意路径 或其他编译器选项）来操纵编译行为。

**漏洞代码** (`bishengir/python/wheel/ascendnpuir/compiler.py:186-196`)

```c
    # Add compilation options
    if option:
        cmd.extend(option)
    
    # Run the compiler with MLIR text as stdin
    result = subprocess.run(
        cmd,
        input=input,
        capture_output=True,
        text=True,
        check=False
    )
```

**达成路径**

option (user input) (SOURCE) → cmd.extend(option) → subprocess.run(cmd) [SINK]

**验证说明**: 重新评估: 不是 CWE-78 shell 命令注入。subprocess.run(cmd) 使用列表形式，无 shell 解析。但 option 参数直接 cmd.extend() 添加，存在参数注入风险。用户可传入任意编译选项，可能影响 bishengir-compile 行为。实际风险取决于编译器如何处理这些选项。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-PY-002] path_traversal - compile

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `bishengir/python/wheel/ascendnpuir/compiler.py:182-184` @ `compile`
**模块**: PythonWheel
**跨模块**: PythonWheel → Tools

**描述**: compile() 函数的 output_path 参数直接传递给 bishengir-compile 编译器，未进行路径规范化或验证。用户可以通过传入包含路径遍历序列（如 ../ 或绝对路径）的 output_path，导致文件写入到非预期位置。

**漏洞代码** (`bishengir/python/wheel/ascendnpuir/compiler.py:182-184`)

```c
    # Add output file
    if output_path:
        cmd.extend(["-o", str(output_path)])
```

**达成路径**

output_path (user input) (SOURCE) → cmd.extend(["-o", str(output_path)]) → subprocess.run → bishengir-compile → 文件写入 [SINK]

**验证说明**: 重新评估: 不是典型路径遍历。output_path 通过 -o 参数传递给 bishengir-compile，编译器内部 checkInOutOptionsValidity() 会规范化路径（make_absolute + remove_dots）。但规范化后路径仍可指向任意位置。攻击者可通过绝对路径或 symlink 攻击绕过预期输出目录。风险为输出文件控制，而非路径遍历写入。

**评分明细**: base: 30 | context: 0 | controllability: 5 | cross_file: 0 | mitigations: -10 | reachability: 25

---

## 4. Low 漏洞 (2)

### [VULN-DF-FILE-001] path_traversal - getFileHandle

**严重性**: Low | **CWE**: CWE-22 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `bishengir/lib/ExecutionEngine/BiShengIRRunnerUtils.cpp:35-51` @ `getFileHandle`
**模块**: ExecutionEngine

**描述**: getFileHandle() 函数接收 filePath 参数并直接调用 mlir::openOutputFile()，未进行路径验证。虽然这是运行时执行代码，但如果 filePath 来自编译生成的 IR 中的用户可控数据，可能导致文件写入到非预期位置。

**漏洞代码** (`bishengir/lib/ExecutionEngine/BiShengIRRunnerUtils.cpp:35-51`)

```c
extern "C" llvm::ToolOutputFile *MLIR_RUNNERUTILS_EXPORT
getFileHandle(const char *filePath) {
  if (const auto parentPath = llvm::sys::path::parent_path(filePath);
      !parentPath.empty() &&
      llvm::sys::fs::create_directories(parentPath).value() != 0) {
    llvm_unreachable("Couldn't create directories!");
    return nullptr;
  }
  auto output = mlir::openOutputFile(filePath);
```

**达成路径**

filePath (IR generated parameter) → getFileHandle → mlir::openOutputFile(filePath) [SINK]

**验证说明**: getFileHandle() 是运行时执行函数，filePath 来自 IR 生成的参数。这是 JIT 执行引擎的输出函数，filePath 通常由编译器内部控制而非用户直接输入。如果 IR 中包含硬编码路径，风险较低。需要分析 IR 生成逻辑确认 filePath 来源是否可控。

**评分明细**: base: 30 | reachability: 15 | controllability: 5 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-PARSE-001] input_validation - ScalarTraits<SerializedAffineMap>::input

**严重性**: Low | **CWE**: CWE-94 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `bishengir/tools/bishengir-hfusion-ods-gen/bishengir-hfusion-ods-yaml-gen.cpp:342-352` @ `ScalarTraits<SerializedAffineMap>::input`
**模块**: Tools

**描述**: bishengir-hfusion-ods-yaml-gen 工具解析 YAML 文件中的 MLIR 属性，使用 mlir::parseAttribute() 直接解析用户提供的 YAML 内容。如果 YAML 文件包含恶意构造的 MLIR 属性字符串，可能导致解析器异常或代码注入风险（取决于 MLIR 解析器的实现）。

**漏洞代码** (`bishengir/tools/bishengir-hfusion-ods-gen/bishengir-hfusion-ods-yaml-gen.cpp:342-352`)

```c
  static StringRef input(StringRef scalar, void *rawYamlContext,
                         SerializedAffineMap &value) {
    assert(rawYamlContext);
    auto *yamlContext = static_cast<HFusionYAMLContext *>(rawYamlContext);
    if (auto attr = dyn_cast_or_null<AffineMapAttr>(
            mlir::parseAttribute(scalar, yamlContext->mlirContext)))
      value.affineMapAttr = attr;
```

**达成路径**

YAML file content (SOURCE) → YAML parser → scalar → mlir::parseAttribute() [SINK]

**验证说明**: 重新评估: 不是典型代码注入。mlir::parseAttribute() 解析 YAML 配置中的 MLIR 属性字符串。这是 ODS 生成工具，输入来自配置文件。风险取决于 MLIR 解析器的实现，可能存在解析错误导致崩溃，但不太可能直接执行恶意代码。需要进一步分析 MLIR 解析器安全性。

**评分明细**: base: 30 | context: -5 | controllability: 5 | cross_file: 0 | mitigations: 0 | reachability: 10

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| ExecutionEngine | 0 | 0 | 0 | 1 | 1 |
| PythonWheel | 0 | 0 | 3 | 0 | 3 |
| Tools | 0 | 0 | 2 | 1 | 3 |
| ToolsLib | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **0** | **6** | **2** | **8** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 4 | 50.0% |
| CWE-22 | 2 | 25.0% |
| CWE-94 | 1 | 12.5% |
| CWE-426 | 1 | 12.5% |
