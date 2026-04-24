# 漏洞扫描报告 — 待确认漏洞

**项目**: akg
**扫描时间**: 2026-04-24T03:12:51.692Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本报告包含 10 个待确认漏洞（9 个 High、1 个 Medium），这些漏洞经过初步验证但因攻击面限制或控制路径间接性而被标记为 LIKELY 或 POSSIBLE。尽管这些漏洞的即时风险低于已确认漏洞，但一旦前置条件满足，同样可能导致严重安全后果。

**主要发现**：
- **CLI 工具命令注入**（SA-010, VULN-AKG-003）：ascend-linker 使用 `popen()` 执行 shell 命令，若在自动化 CI/CD 管道中使用受控输入文件名，可能触发命令注入
- **任意文件读写**（VULN-AKG-004, VULN-AKG-006）：ptx-replace 和 IOHelper.hpp 直接使用 CLI 参数作为文件路径，无路径验证
- **AI 代码执行风险**（SA-002, SA-003）：AI 生成的 AscendC 代码或 Torch 验证代码通过 `exec()` 执行，若攻击者能操纵 LLM 提示词，可能注入恶意代码

**建议**：这些漏洞应纳入中期修复计划，特别是 CLI 工具的安全加固和 AI 代码生成流程的输入验证。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 12 | 50.0% |
| LIKELY | 9 | 37.5% |
| FALSE_POSITIVE | 2 | 8.3% |
| POSSIBLE | 1 | 4.2% |
| **总计** | **24** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 9 | 90.0% |
| Medium | 1 | 10.0% |
| **有效漏洞总计** | **10** | - |
| 误报 (FALSE_POSITIVE) | 2 | - |

### 1.3 Top 10 关键漏洞

1. **[SA-010]** command_injection (High) - `akg-mlir/compiler/tools/ascend-linker/ascend-linker.cpp:44` @ `RunCmd` | 置信度: 70
2. **[VULN-AKG-003]** OS Command Injection (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/tools/ascend-linker/ascend-linker.cpp:34` @ `RunCmd` | 置信度: 70
3. **[VULN-AKG-004]** Arbitrary File Read/Write (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/tools/ptx-tools/ptx-replace.cpp:511` @ `main` | 置信度: 70
4. **[VULN-AKG-006]** Path Traversal via JSON File Input (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/include/akg/Utils/IOHelper.hpp:46` @ `checkAndReadJson` | 置信度: 70
5. **[SA-003]** code_injection (High) - `aikg/python/ai_kernel_generator/resources/skills/kernel-workflow/scripts/check_torch_code.py:90` @ `check_runtime` | 置信度: 65
6. **[VULN-AKG-005]** Untrusted Path from Environment Variable (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/ProfileMgr.cpp:61` @ `StartupProfiling` | 置信度: 65
7. **[VULN-PY-004]** Arbitrary Code Execution (High) - `aikg/python/ai_kernel_generator/resources/skills/kernel-workflow/scripts/check_torch_code.py:106` @ `check_runtime` | 置信度: 65
8. **[SA-002]** code_injection (High) - `aikg/python/ai_kernel_generator/core/verifier/kernel_verifier.py:722` @ `generate_ascendc_project` | 置信度: 55
9. **[VULN-PY-002]** Arbitrary Code Execution (High) - `aikg/python/ai_kernel_generator/core/verifier/kernel_verifier.py:723` @ `generate_ascendc_project` | 置信度: 55
10. **[SA-006]** command_injection (Medium) - `aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:260` @ `analyze_nsys_data` | 置信度: 45

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `undefined@aikg/python/ai_kernel_generator/worker/server.py` | web_api | - | - | Worker服务API - 接收验证包执行代码 |
| `undefined@aikg/python/ai_kernel_generator/server/app.py` | web_api | - | - | 主服务器API - 作业提交和Worker注册 |
| `undefined@akg-mlir/compiler/tools/ascend-linker/ascend-linker.cpp` | cli_tool | - | - | Ascend内核链接器 - 使用popen执行shell命令 |
| `undefined@akg-mlir/compiler/tools/ptx-tools/ptx-replace.cpp` | cli_tool | - | - | PTX文件处理器 - 文件读写和正则解析 |
| `undefined@akg-mlir/compiler/tools/akg-opt/akg-opt.cpp` | cli_tool | - | - | MLIR优化器CLI - 处理MLIR文件 |
| `undefined@akg-mlir/compiler/tools/akg-translate/akg-translate.cpp` | cli_tool | - | - | MLIR翻译工具 - 转换MLIR到PTX |
| `undefined@akg-mlir/compiler/tools/mindspore-translate/mindspore-translate.cpp` | cli_tool | - | - | MindSpore翻译工具 - JSON到MLIR转换 |
| `undefined@akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/AKGAscendLaunch.cpp` | python_binding | - | - | Python绑定 - dlopen加载用户提供的.so |
| `undefined@aikg/python/ai_kernel_generator/cli/cli.py` | python_cli | - | - | AIKG CLI入口 - Typer框架 |
| `undefined@aikg/python/ai_kernel_generator/resources/skills/kernel-workflow/scripts/check_torch_code.py` | script | - | - | Torch代码验证脚本 - exec执行用户代码 |


---

## 3. High 漏洞 (9)

### [SA-010] command_injection - RunCmd

**严重性**: High | **CWE**: CWE-78 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `akg-mlir/compiler/tools/ascend-linker/ascend-linker.cpp:44-53` @ `RunCmd`
**模块**: akg-mlir-compiler

**描述**: popen() executes shell command constructed from CLI arguments. The ascend-linker.cpp uses popen() to execute shell commands. The command is constructed from file path arguments passed via CLI (argv). While this is a CLI tool, if used in automated pipelines with untrusted input, command injection could occur via path traversal or special characters in filenames.

**漏洞代码** (`akg-mlir/compiler/tools/ascend-linker/ascend-linker.cpp:44-53`)

```c
FILE *fp;
fp = popen(cmd.c_str(), "r");
if (fp == nullptr) {
  std::cerr << cmd << " error, errno: " << errno << std::endl;
  return;
}
```

**达成路径**

argv[1], argv[2] → LinkSharedObject(src_file, dst_file) → link_cmd = "ccec --cce-fatobj-link -fPIC -shared -o " + dst_file + " " + src_file → RunCmd(link_cmd) → popen(cmd)

**验证说明**: popen() in ascend-linker CLI tool executes shell command from argv. Command injection possible if filenames contain shell metacharacters. If used in CI/CD pipeline with untrusted input, exploitable. CLI tool context reduces direct attack surface.

**评分明细**: base: 30 | reachability: 5 | controllability: 20 | mitigations: -5 | context: -15 | cross_file: 25

---

### [VULN-AKG-003] OS Command Injection - RunCmd

**严重性**: High | **CWE**: CWE-78 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/tools/ascend-linker/ascend-linker.cpp:34-58` @ `RunCmd`
**模块**: akg-mlir/compiler/tools/ascend-linker

**描述**: The ascend-linker CLI tool constructs shell commands from argv parameters and executes them via popen without proper sanitization. Shell metacharacters in input file names can lead to arbitrary command execution.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/tools/ascend-linker/ascend-linker.cpp:34-58`)

```c
fp = popen(cmd.c_str(), "r");
```

**达成路径**

[{"step":1,"source":"CLI EP-003","node":"main(argc, argv)","taint":"argv[1] path, argv[2] kernelSoFileName"},{"step":2,"node":"LinkSharedObject","operation":"link_cmd = "ccec --cce-fatobj-link -fPIC -shared -o " + dst_file + " " + src_file"},{"step":3,"node":"RunCmd","sink":"popen(cmd.c_str(), "r")","line":45,"type":"Command Injection"}]

**验证说明**: Duplicate of SA-010 - popen() command injection in CLI tool. See SA-010 for full analysis.

**评分明细**: base: 30 | reachability: 5 | controllability: 20 | mitigations: -5 | context: -15 | cross_file: 25

---

### [VULN-AKG-004] Arbitrary File Read/Write - main

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/tools/ptx-tools/ptx-replace.cpp:511-545` @ `main`
**模块**: akg-mlir/compiler/tools/ptx-tools

**描述**: The ptx-replace CLI tool reads and writes files based on command-line arguments without path validation. An attacker can use path traversal sequences to read sensitive files or write to arbitrary locations.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/tools/ptx-tools/ptx-replace.cpp:511-545`)

```c
std::ifstream inFile(inputFilename); std::ofstream outFile(outputFilename);
```

**达成路径**

[{"step":1,"source":"CLI EP-004","node":"main(argc, argv)","taint":"argv[1] inputFilename, argv[3] outputFilename"},{"step":2,"operation":"File path from argv","code":"inputFilename(argv[1]); outputFilename(argv[3])"},{"step":3,"sink":"ifstream/ofstream","lines":"368,374","type":"Arbitrary File Read/Write"}]

**验证说明**: Path traversal via ptx-replace CLI file arguments. ifstream/ofstream used without path validation. If called with attacker-controlled filenames in automated pipeline, arbitrary file read/write possible. CLI context reduces direct attack surface.

**评分明细**: base: 30 | reachability: 5 | controllability: 20 | mitigations: -5 | context: -15 | cross_file: 25

---

### [VULN-AKG-006] Path Traversal via JSON File Input - checkAndReadJson

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/include/akg/Utils/IOHelper.hpp:46-54` @ `checkAndReadJson`
**模块**: akg-mlir/compiler/include/akg/Utils
**跨模块**: akg-mlir/compiler/lib/Target/MindsporeDialect,akg-mlir/compiler/include/akg/Utils

**描述**: checkAndReadJson opens a file based on input_file_name parameter without path validation. Called from TranslateToMindsporeDialect, this allows reading arbitrary JSON files if the input path is not validated.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/include/akg/Utils/IOHelper.hpp:46-54`)

```c
std::ifstream jfile(input_file_name); jfile >> j;
```

**达成路径**

[{"step":1,"source":"TranslateToMindsporeDialect EP-007","node":"MindConverter(inputFileName)","taint":"inputFileName parameter"},{"step":2,"node":"parseJson","operation":"rawJson = DirUtils::checkAndReadJson(inputFileName)"},{"step":3,"node":"checkAndReadJson","sink":"ifstream jfile(input_file_name)","line":48,"type":"Arbitrary File Read"}]

**验证说明**: checkAndReadJson opens file from input_file_name parameter without path validation. Called from TranslateToMindsporeDialect with input path. Path traversal possible if input file name contains ../ sequences.

**评分明细**: base: 30 | reachability: 10 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 10

---

### [SA-003] code_injection - check_runtime

**严重性**: High | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `aikg/python/ai_kernel_generator/resources/skills/kernel-workflow/scripts/check_torch_code.py:90-107` @ `check_runtime`
**模块**: aikg-python

**描述**: exec() in check_torch_code.py executes arbitrary code from stdin/file input. The script reads Python code from stdin or file and executes it directly using exec(code, namespace). This script is designed to validate KernelBench format but allows arbitrary code execution if malicious code is passed.

**漏洞代码** (`aikg/python/ai_kernel_generator/resources/skills/kernel-workflow/scripts/check_torch_code.py:90-107`)

```c
def check_runtime(code: str) -> tuple[bool, str]:
    namespace = {}
    try:
        exec(code, namespace)
    except Exception as e:
        return False, f"exec error: {type(e).__name__}: {e}"
```

**达成路径**

stdin/file → code string → exec(code, namespace) → arbitrary code execution

**验证说明**: exec() in check_torch_code.py executes arbitrary code from stdin/file. If invoked from worker verification workflow with user-provided package code, exploitable. The script is marked as critical entry point EP-010 in project model.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-AKG-005] Untrusted Path from Environment Variable - StartupProfiling

**严重性**: High | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/ProfileMgr.cpp:61-71` @ `StartupProfiling`
**模块**: akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime

**描述**: The ProfileMgr reads PROFILING_DIR environment variable and passes it directly to aclprofInit without validation. An attacker controlling the environment can redirect profiling output to arbitrary paths.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/mindspore/mindspore/akg/akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime/ProfileMgr.cpp:61-71`)

```c
char *profile_dir = std::getenv("PROFILING_DIR"); ret = aclprofInit(profile_dir, strlen(profile_dir));
```

**达成路径**

[{"step":1,"source":"Environment Variable","node":"std::getenv("PROFILING_DIR")","taint":"PROFILING_DIR env var"},{"step":2,"operation":"Direct use without validation","code":"profile_dir = getenv"},{"step":3,"sink":"aclprofInit(profile_dir, strlen(profile_dir))","line":67,"type":"Path Injection"}]

**验证说明**: PROFILING_DIR environment variable used without validation in ProfileMgr. Attacker with environment control can redirect profiling output to arbitrary paths. Requires environment variable control.

**评分明细**: base: 30 | reachability: 5 | controllability: 20 | mitigations: 0 | context: -15 | cross_file: 20

---

### [VULN-PY-004] Arbitrary Code Execution - check_runtime

**严重性**: High | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: python-dataflow-module-scanner

**位置**: `aikg/python/ai_kernel_generator/resources/skills/kernel-workflow/scripts/check_torch_code.py:106-109` @ `check_runtime`
**模块**: aikg-python/resources/skills

**描述**: The check_torch_code.py script uses exec() to execute code read from stdin or file without any sandboxing. An attacker can provide malicious Python code that will be executed directly.

**漏洞代码** (`aikg/python/ai_kernel_generator/resources/skills/kernel-workflow/scripts/check_torch_code.py:106-109`)

```c
namespace = {}
try:
    exec(code, namespace)
except Exception as e:
    return False, f"exec error: {type(e).__name__}: {e}"
```

**达成路径**

[{"step":1,"node":"stdin/file input","taint_source":"sys.stdin.read() or file.read()"},{"step":2,"node":"check_runtime","operation":"执行代码"},{"step":3,"node":"Code Execution","taint_sink":"exec(code, namespace)"}]

**验证说明**: Duplicate of SA-003 - exec() in check_torch_code.py executes arbitrary code. See SA-003 for full analysis.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SA-002] code_injection - generate_ascendc_project

**严重性**: High | **CWE**: CWE-94 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `aikg/python/ai_kernel_generator/core/verifier/kernel_verifier.py:722-726` @ `generate_ascendc_project`
**模块**: aikg-python

**描述**: exec() executes AI-generated AscendC code without validation. The kernel_verifier.py uses exec(impl_code, self.context) to execute generated AscendC code. The impl_code comes from AI-generated output which could contain malicious code. If an attacker can influence the AI model output or if the generation process is compromised, arbitrary code execution is possible.

**漏洞代码** (`aikg/python/ai_kernel_generator/core/verifier/kernel_verifier.py:722-726`)

```c
try: 
    compile(impl_code, "<string>", "exec")
    exec(impl_code, self.context)
except Exception as e:
    raise Exception(f"Error in generated code: {e}")
```

**达成路径**

impl_code (AI-generated) → compile() → exec() → arbitrary code execution

**验证说明**: exec() executes AI-generated impl_code. The code comes from LLM response, not directly from attacker. Indirect external input via LLM prompts - attacker could potentially influence prompts through job submission but control is limited. The LLM may sanitize or reject malicious code.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-PY-002] Arbitrary Code Execution - generate_ascendc_project

**严重性**: High | **CWE**: CWE-94 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: python-dataflow-module-scanner

**位置**: `aikg/python/ai_kernel_generator/core/verifier/kernel_verifier.py:723-726` @ `generate_ascendc_project`
**模块**: aikg-python/core/verifier

**描述**: AI-generated AscendC code is executed directly via exec() without proper sandboxing. An attacker could manipulate LLM prompts to generate malicious code that gets executed.

**漏洞代码** (`aikg/python/ai_kernel_generator/core/verifier/kernel_verifier.py:723-726`)

```c
try: 
    compile(impl_code, "<string>", "exec")
    exec(impl_code, self.context)
  except Exception as e:
    raise Exception(f"Error in generated code: {e}")
```

**达成路径**

[{"step":1,"node":"LLM生成内核代码","taint_source":"LLM API响应"},{"step":2,"node":"KernelVerifier.generate_ascendc_project","operation":"编译并执行内核代码"},{"step":3,"node":"Code Compilation","code_snippet":"compile(impl_code, '<string', 'exec')"},{"step":4,"node":"Code Execution","taint_sink":"exec(impl_code, self.context)"}]

**验证说明**: Duplicate of SA-002 - exec() executes AI-generated AscendC code. See SA-002 for full analysis.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (1)

### [SA-006] command_injection - analyze_nsys_data

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:260-262` @ `analyze_nsys_data`
**模块**: aikg-python

**描述**: Command Injection via shell=True in nsys stats execution. The profiler_utils.py uses subprocess.run with shell=True and check=True to execute nsys stats commands. The rep_path and csv_path are passed directly to shell.

**漏洞代码** (`aikg/python/ai_kernel_generator/core/verifier/profiler_utils.py:260-262`)

```c
cmd = f'nsys stats --report gputrace --timeunit us --format csv --output {csv_path} {rep_path}'
subprocess.run(cmd, shell=True, check=True)
```

**达成路径**

rep_path → f-string interpolation → subprocess.run(shell=True) → shell command execution

**验证说明**: subprocess.run shell=True in analyze_nsys_data(). rep_path and csv_path are internally constructed from previous profiling outputs. Indirect control - attacker would need to manipulate earlier pipeline steps. Less direct attack vector.

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: -5 | context: 0 | cross_file: 10

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| aikg-python | 0 | 2 | 1 | 0 | 3 |
| aikg-python/core/verifier | 0 | 1 | 0 | 0 | 1 |
| aikg-python/resources/skills | 0 | 1 | 0 | 0 | 1 |
| akg-mlir-compiler | 0 | 1 | 0 | 0 | 1 |
| akg-mlir/compiler/include/akg/Utils | 0 | 1 | 0 | 0 | 1 |
| akg-mlir/compiler/lib/ExecutionEngine/AscendLaunchRuntime | 0 | 1 | 0 | 0 | 1 |
| akg-mlir/compiler/tools/ascend-linker | 0 | 1 | 0 | 0 | 1 |
| akg-mlir/compiler/tools/ptx-tools | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **9** | **1** | **0** | **10** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-94 | 4 | 40.0% |
| CWE-78 | 3 | 30.0% |
| CWE-22 | 2 | 20.0% |
| CWE-426 | 1 | 10.0% |
