# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-Kernel-Launcher
**扫描时间**: 2026-04-21T02:33:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| Medium | 8 | 88.9% |
| Low | 1 | 11.1% |
| **有效漏洞总计** | **9** | - |
| 误报 (FALSE_POSITIVE) | 5 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-OPT-002]** insecure_temp_file (Medium) - `mskl/optune/tuner.py:409` @ `_create_temp_dir` | 置信度: 75
2. **[VULN-UTILS-003]** SafeCheckBypass (Medium) - `mskl/utils/safe_check.py:77` @ `FileChecker.check_input_file` | 置信度: 60
3. **[VULN-UTILS-004]** SafeCheckBypass (Medium) - `mskl/utils/safe_check.py:32` @ `check_input_file` | 置信度: 55
4. **[8869c6a012d3]** arbitrary_library_load (Medium) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Kernel-Launcher/mskl/launcher/compiler.py:234` @ `compile_tiling` | 置信度: 55
5. **[VULN-UTILS-007]** OwnerCheckBypass (Medium) - `mskl/utils/safe_check.py:145` @ `check_path_permission` | 置信度: 50
6. **[VULN-SEC-LAU-002]** code_injection (Medium) - `mskl/launcher/code_generator.py:247` @ `KernelLauncher.code_gen` | 置信度: 50
7. **[VULN-SEC-LAU-004]** process_control (Medium) - `mskl/launcher/driver.py:103` @ `NPULauncher.__call__` | 置信度: 50
8. **[VULN-SEC-LAU-003]** untrusted_search_path (Medium) - `mskl/launcher/driver.py:30` @ `load_mspti_so` | 置信度: 45
9. **[VULN-SEC-UTL-001]** sensitive_info_log (Low) - `mskl/launcher/compiler.py:211` @ `compile` | 置信度: 45

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

## 3. Medium 漏洞 (8)

### [VULN-SEC-OPT-002] insecure_temp_file - _create_temp_dir

**严重性**: Medium | **CWE**: CWE-377 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `mskl/optune/tuner.py:409-418` @ `_create_temp_dir`
**模块**: optune

**描述**: 临时目录名称使用可预测的时间戳。AutotunerV2._create_temp_dir() 在第 410-411 行使用 datetime.now() 生成时间戳作为临时目录名称（./.mskl_temp_{timestamp}）。时间戳格式为 %Y%m%d%H%M%S，精度仅为秒级，可被预测。虽然目录权限设置为 0o750，但在多用户环境中仍存在竞态条件风险。

**漏洞代码** (`mskl/optune/tuner.py:409-418`)

```c
local_time = datetime.now(tz=timezone.utc) + timedelta(hours=8)
timestamp = local_time.strftime('%Y%m%d%H%M%S')
temp_dir = f'./.mskl_temp_{timestamp}'
if not os.path.exists(temp_dir):
    os.makedirs(temp_dir)
    os.chmod(temp_dir, safe_check.DATA_DIRECTORY_AUTHORITY)
```

**达成路径**

AutotunerV2 → _create_temp_dir() → Predictable timestamp → mkdir → chmod

**验证说明**: Race condition vulnerability exists: _create_temp_dir() uses predictable timestamp (%Y%m%d%H%M%S) with second-level precision. However, directory is created with 0o750 permissions (owner rwx, group rx), mitigating direct exploitation. Attack requires: 1) Predict timing, 2) Create directory before tool does, 3) Local access. Impact is lower than initially assessed.

---

### [VULN-UTILS-003] SafeCheckBypass - FileChecker.check_input_file

**严重性**: Medium | **CWE**: CWE-59 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mskl/utils/safe_check.py:77-102` @ `FileChecker.check_input_file`
**模块**: utils

**描述**: FileChecker.is_soft_link_recusively() only logs warning for symlink detection but returns True, allowing symlinked paths to pass validation

**漏洞代码** (`mskl/utils/safe_check.py:77-102`)

```c
if self.is_soft_link_recusively():\n    logger.warning(...)\nreturn True
```

**达成路径**

path -> is_soft_link_recusively() -> logger.warning -> return True

**验证说明**: FileChecker.is_soft_link_recusively()检测软链接后只警告不阻止(check_input_file:86-88)。这是设计决策，但攻击者可利用软链接绕过路径验证。需评估实际攻击场景：调用方包括KernelInvokeConfig、compile、AutotunerV2.launch。在某些场景下软链接攻击可行。

**评分明细**: 0: 可 | 1: 达 | 2: 性 | 3: : | 4: 高 | 5: , | 6: 攻 | 7: 击 | 8: 复 | 9: 杂 | 10: 度 | 11: : | 12: 中 | 13: ( | 14: 需 | 15: 创 | 16: 建 | 17: 软 | 18: 链 | 19: 接 | 20: ) | 21: , | 22: 影 | 23: 响 | 24: : | 25: 路 | 26: 径 | 27: 验 | 28: 证 | 29: 绕 | 30: 过

---

### [VULN-UTILS-004] SafeCheckBypass - check_input_file

**严重性**: Medium | **CWE**: CWE-59 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mskl/utils/safe_check.py:32-44` @ `check_input_file`
**模块**: utils

**描述**: check_input_file() function logs warning for symlinks but does not prevent their use. Symlink attacks possible

**漏洞代码** (`mskl/utils/safe_check.py:32-44`)

```c
if os.path.islink(path):\n    logger.warning(...)\n# continues execution
```

**达成路径**

path -> os.path.islink -> logger.warning -> no exception

**验证说明**: check_input_file()函数对软链接只警告不阻止(line 36-37)。被autotune_utils.get_file_lines()调用(line 95)。软链接攻击可行，但实际风险取决于调用场景。

**评分明细**: 0: 可 | 1: 达 | 2: 性 | 3: : | 4: 中 | 5: ( | 6: 被 | 7: g | 8: e | 9: t | 10: _ | 11: f | 12: i | 13: l | 14: e | 15: _ | 16: l | 17: i | 18: n | 19: e | 20: s | 21: 调 | 22: 用 | 23: ) | 24: , | 25: 攻 | 26: 击 | 27: 复 | 28: 杂 | 29: 度 | 30: : | 31: 中 | 32: , | 33: 影 | 34: 响 | 35: : | 36: 路 | 37: 径 | 38: 验 | 39: 证 | 40: 绕 | 41: 过

---

### [8869c6a012d3] arbitrary_library_load - compile_tiling

**严重性**: Medium | **CWE**: CWE-114 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Kernel-Launcher/mskl/launcher/compiler.py:234-236` @ `compile_tiling`
**模块**: launcher

**描述**: Generated tiling library loaded via importlib. While so_path is from compiled C++, user-controlled template variables (op_type, lib_path) influence generated code.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Kernel-Launcher/mskl/launcher/compiler.py:234-236`)

```c
spec = importlib.util.spec_from_file_location('_mskl_tiling_launcher', so_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
```

**达成路径**

op_type(user)[IN] -> TilingConfig -> Launcher.code_gen() -> compile_tiling() -> importlib[SINK]

**验证说明**: POSSIBLE: importlib dynamic loading of compiled tiling library. so_path comes from compile_tiling() which compiles generated code. The generated code includes user-provided lib_path in TilingConfig which loads external tiling library. lib_path passed to runtime for validation.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -5 | context: 5 | cross_file: 5

---

### [VULN-UTILS-007] OwnerCheckBypass - check_path_permission

**严重性**: Medium | **CWE**: CWE-59 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mskl/utils/safe_check.py:145-178` @ `check_path_permission`
**模块**: utils

**描述**: check_path_permission() only logs warning when file owner differs from current user but returns True, allowing untrusted files to pass

**漏洞代码** (`mskl/utils/safe_check.py:145-178`)

```c
if uid != 0 and uid != file_stat.st_uid:\n    logger.warning(...)\nreturn True
```

**达成路径**

path -> os.stat -> uid comparison -> logger.warning -> return True

**验证说明**: check_path_permission()对所有者不一致只警告不阻止(line 176-177)。攻击者可利用此绕过所有权检查。但实际风险取决于具体攻击场景和部署环境。

**评分明细**: 0: 可 | 1: 达 | 2: 性 | 3: : | 4: 中 | 5: , | 6: 攻 | 7: 击 | 8: 复 | 9: 杂 | 10: 度 | 11: : | 12: 中 | 13: , | 14: 影 | 15: 响 | 16: : | 17: 所 | 18: 有 | 19: 权 | 20: 检 | 21: 查 | 22: 绕 | 23: 过

---

### [VULN-SEC-LAU-002] code_injection - KernelLauncher.code_gen

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-94 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `mskl/launcher/code_generator.py:247-253` @ `KernelLauncher.code_gen`
**模块**: launcher

**描述**: 用户提供的参数直接嵌入 C++ 代码模板。KERNEL_TEMPLATE.format() 在第 247-253 行嵌入 kernel_src_file 和 kernel_name，OPGEN_TILING_TEMPLATE.format() 在第 274-280 行嵌入 op_type、lib_path 和 attrs。如果参数包含特殊字符（如 C++ 预处理指令），可能导致生成的代码被篡改。kernel_name 有正则验证（^[A-Za-z0-9_]+$），但 kernel_src_file 仅做路径验证，attrs 值的类型验证不足以防止 C++ 代码注入。

**漏洞代码** (`mskl/launcher/code_generator.py:247-253`)

```c
src = KERNEL_TEMPLATE.format(kernel_src_file=self.kernel_src_file,
      kernel_name=self.kernel_name,
      args_decl=new_line.join(e for e in args_decl if e is not None),
      ...)
```

**达成路径**

User Config → KernelInvokeConfig(kernel_src_file, kernel_name) → KernelLauncher.code_gen() → KERNEL_TEMPLATE.format() → Generated C++ Code

**验证说明**: POSSIBLE: kernel_src_file embedded into C++ #include directive. Partial mitigations: kernel_name regex validation (^[A-Za-z0-9_]+$), FileChecker validation, os.path.abspath normalization. However, kernel_src_file lacks C++ escaping. Practical exploitability limited by abspath normalization.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -10 | context: 5 | cross_file: 5

---

### [VULN-SEC-LAU-004] process_control - NPULauncher.__call__

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-114 | **置信度**: 50/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `mskl/launcher/driver.py:103-105` @ `NPULauncher.__call__`
**模块**: launcher

**描述**: 动态加载用户提供的 .so 模块。NPULauncher.__call__() 在第 103-105 行使用 importlib.util.spec_from_file_location 加载 self._module（用户提供的 .so 文件路径），然后 spec.loader.exec_module(module) 执行模块代码。虽然路径经过 FileChecker 验证，但恶意用户可能在验证后替换文件（TOCTOU 风险），或通过编译流程植入恶意代码。

**漏洞代码** (`mskl/launcher/driver.py:103-105`)

```c
module_name = f'_mskl_launcher'
spec = importlib.util.spec_from_file_location(module_name, self._module)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
```

**达成路径**

CompiledKernel(output_bin_path) → NPULauncher._module → importlib.util.spec_from_file_location() → spec.loader.exec_module() → Dynamic Code Execution

**验证说明**: LIKELY: Dynamic .so module loading via importlib.util.spec_from_file_location. FileChecker validation applied in CompiledKernel.__init__. TOCTOU risk exists but low probability. The .so file comes from user-controlled compilation process, creating a trust chain issue.

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: -5 | context: 5 | cross_file: 5

---

### [VULN-SEC-LAU-003] untrusted_search_path - load_mspti_so

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-426 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `mskl/launcher/driver.py:30-36` @ `load_mspti_so`
**模块**: launcher
**跨模块**: launcher → utils

**描述**: ASCEND_HOME_PATH 环境变量控制动态库加载路径。load_mspti_so() 在 driver.py:30-36 使用 os.getenv('ASCEND_HOME_PATH') 获取路径，然后用 ctypes.CDLL 加载 libmspti.so。launcher_utils.py:34 同样使用 ASCEND_HOME_PATH 加载 libruntime.so。如果环境变量被恶意设置，可加载恶意库实现任意代码执行。这是信任部署环境的设计决策，但缺少对路径的严格白名单验证。

**漏洞代码** (`mskl/launcher/driver.py:30-36`)

```c
cann_path = os.getenv('ASCEND_HOME_PATH')
if cann_path:
    mspti_path = os.path.join(cann_path, 'lib64/libmspti.so')
    mspti_real_path = os.path.realpath(mspti_path)
    if mspti_real_path and os.path.exists(mspti_real_path):
        lib = ctypes.CDLL(mspti_real_path, mode=ctypes.RTLD_GLOBAL)
```

**达成路径**

Environment Variable ASCEND_HOME_PATH → os.getenv() → ctypes.CDLL(libmspti.so) → Arbitrary Code Execution

**验证说明**: POSSIBLE: ASCEND_HOME_PATH env var controls dynamic library loading path. os.path.realpath() and existence check applied. No whitelist validation. Deployment environment trust issue - env var typically set by system admin, reducing practical attack surface.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

## 4. Low 漏洞 (1)

### [VULN-SEC-UTL-001] sensitive_info_log - compile

**严重性**: Low | **CWE**: CWE-532 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `mskl/launcher/compiler.py:211` @ `compile`
**模块**: utils
**跨模块**: launcher → utils

**描述**: 敏感信息可能泄露到日志。compiler.py:211 使用 logger.info(f'Compilation output: {result.stdout}') 记录编译输出，tuner.py:304 使用 logger.debug(f'The cmd = {cmd}') 记录完整命令。这些日志可能包含文件路径、编译参数等敏感信息。MSKL_LOG_LEVEL 环境变量控制日志级别，设置为 '0' 时输出 DEBUG 级别日志，可能导致更多信息泄露。

**漏洞代码** (`mskl/launcher/compiler.py:211`)

```c
logger.info(f'Compilation output: {result.stdout}')
```

**达成路径**

Compile Process → stdout → logger.info() → Log File/Sys.stdout

**验证说明**: 日志可能包含敏感信息：compiler.py:211记录编译输出(result.stdout)，tuner.py:304记录完整命令。当MSKL_LOG_LEVEL="0"时输出DEBUG日志。这些日志可能包含文件路径、编译参数等。但实际风险取决于日志存储位置和访问控制。

**评分明细**: 0: 可 | 1: 达 | 2: 性 | 3: : | 4: 高 | 5: , | 6: 攻 | 7: 击 | 8: 复 | 9: 杂 | 10: 度 | 11: : | 12: 高 | 13: ( | 14: 需 | 15: 访 | 16: 问 | 17: 日 | 18: 志 | 19: ) | 20: , | 21: 影 | 22: 响 | 23: : | 24: 信 | 25: 息 | 26: 泄 | 27: 露

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| launcher | 0 | 0 | 4 | 0 | 4 |
| optune | 0 | 0 | 1 | 0 | 1 |
| utils | 0 | 0 | 3 | 1 | 4 |
| **合计** | **0** | **0** | **8** | **1** | **9** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-59 | 3 | 33.3% |
| CWE-114 | 2 | 22.2% |
| CWE-94 | 1 | 11.1% |
| CWE-532 | 1 | 11.1% |
| CWE-426 | 1 | 11.1% |
| CWE-377 | 1 | 11.1% |
