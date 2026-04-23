# 漏洞扫描报告 — 待确认漏洞

**项目**: oam-tools
**扫描时间**: 2026-04-22T18:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 13 | 65.0% |
| POSSIBLE | 5 | 25.0% |
| FALSE_POSITIVE | 1 | 5.0% |
| CONFIRMED | 1 | 5.0% |
| **总计** | **20** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 12 | 66.7% |
| Medium | 4 | 22.2% |
| Low | 2 | 11.1% |
| **有效漏洞总计** | **18** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-CMD-001]** command_injection (High) - `src/asys/launch/asys_launch.py:80` @ `execute_task` | 置信度: 75
2. **[VULN-DF-CMD-002]** command_injection (High) - `src/asys/common/cmd_run.py:42` @ `check_command, run_linux_cmd, run_command, run_cmd_output, real_time_output, popen_run_cmd` | 置信度: 75
3. **[VULN-SEC-CMD-002]** command_injection (High) - `src/asys/common/cmd_run.py:42` @ `check_command` | 置信度: 75
4. **[VULN-SEC-CMD-003]** command_injection (High) - `src/asys/common/cmd_run.py:49` @ `run_linux_cmd` | 置信度: 75
5. **[VULN-SEC-CMD-004]** command_injection (High) - `src/asys/common/cmd_run.py:57` @ `run_command` | 置信度: 75
6. **[VULN-SEC-CMD-005]** command_injection (High) - `src/asys/common/cmd_run.py:72` @ `run_cmd_output` | 置信度: 75
7. **[VULN-SEC-CMD-006]** command_injection (High) - `src/asys/common/cmd_run.py:83` @ `real_time_output` | 置信度: 75
8. **[VULN-SEC-CMD-007]** command_injection (High) - `src/asys/common/cmd_run.py:111` @ `popen_run_cmd` | 置信度: 75
9. **[VULN-DF-CMD-005]** command_injection (High) - `src/asys/analyze/coredump_analyze.py:46` @ `thread_stacks_reg_info, _get_reg_info_level_thread, start_gdb` | 置信度: 70
10. **[VULN-SEC-CMD-010]** command_injection (High) - `src/asys/analyze/coredump_analyze.py:46` @ `thread_stacks_reg_info` | 置信度: 70

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@src/asys/asys.py` | cmdline | untrusted_local | 用户通过命令行执行 asys 工具，参数来自 sys.argv | asys CLI 主入口，解析命令行参数并执行相应命令 |
| `execute_task@src/asys/launch/asys_launch.py` | cmdline | untrusted_local | 接收用户命令参数并使用 subprocess.Popen 执行 | 执行用户指定的任务命令 |
| `parse@src/asys/cmdline/cmd_parser.py` | cmdline | untrusted_local | 使用 argparse 解析 sys.argv 参数 | 命令行参数解析器 |
| `main@src/msaicerr/msaicerr.py` | cmdline | untrusted_local | 用户通过命令行执行 msaicerr 工具，参数来自 sys.argv | msaicerr CLI 主入口 |
| `MsprofGetOpts@src/msprof/collector/dvvp/msprofbin/src/input_parser.cpp` | cmdline | untrusted_local | 接收 argc/argv 参数解析 msprof 命令行 | msprof 命令行参数解析入口 |
| `main@src/msprof/collector/dvvp/msprofbin/src/msprof_bin.cpp` | cmdline | untrusted_local | msprof 二进制工具的 main 函数入口 | msprof CLI 主入口 |
| `Create@src/msprof/collector/dvvp/common/socket/local_socket.cpp` | rpc | semi_trusted | 创建 Unix Domain Socket 监听外部进程连接 | Unix Socket 服务端创建，接收外部进程连接请求 |
| `Accept@src/msprof/collector/dvvp/common/socket/local_socket.cpp` | rpc | semi_trusted | 接受 Unix Socket 连接 | Unix Socket accept 函数 |
| `Recv@src/msprof/collector/dvvp/common/socket/local_socket.cpp` | rpc | semi_trusted | 从 Unix Socket 接收数据 | Unix Socket 数据接收 |
| `Run@src/msprof/collector/dvvp/transport/receiver.cpp` | rpc | semi_trusted | 接收并处理来自设备端的数据包 | 设备数据接收循环 |
| `run_command@src/asys/common/cmd_run.py` | cmdline | untrusted_local | 执行外部命令，命令参数可能来自用户输入 | 命令执行封装函数 |
| `execute_command@src/msaicerr/ms_interface/utils.py` | cmdline | untrusted_local | 执行外部命令，命令参数可能来自用户输入 | 命令执行封装函数 |
| `analyze_coredump@src/asys/analyze/coredump_analyze.py` | file | untrusted_local | 分析用户指定的 coredump 文件路径 | coredump 文件分析入口 |
| `run@src/asys/analyze/asys_analyze.py` | file | untrusted_local | 分析用户指定的文件路径 | 分析入口函数 |
| `extract_tar@src/msaicerr/msaicerr.py` | file | untrusted_local | 解压用户指定的 tar 文件到指定路径 | tar 文件解压功能 |
| `run@src/asys/diagnose/asys_diagnose.py` | cmdline | untrusted_local | 执行硬件诊断命令 | 诊断入口函数 |

**其他攻击面**:
- 命令行参数 (sys.argv): asys, msaicerr, msprof CLI 工具
- 用户命令执行 (subprocess.Popen/shell=True): asys launch 命令
- 文件路径输入 (--output, --file, --path): 所有工具的文件操作
- 环境变量 (ASCEND_OPP_PATH, HOME): 配置和路径依赖
- Unix Domain Socket: msprof 进程间通信
- Tar 文件解压: msaicerr 的 tar 文件处理

---

## 3. High 漏洞 (12)

### [VULN-DF-CMD-001] command_injection - execute_task

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-78 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner, security-auditor

**位置**: `src/asys/launch/asys_launch.py:80-81` @ `execute_task`
**模块**: asys

**描述**: 用户通过 --task 参数提供的命令字符串直接使用 shell=True 执行，无输入清洗。攻击者可注入任意shell命令执行恶意操作。

**漏洞代码** (`src/asys/launch/asys_launch.py:80-81`)

```c
pro = subprocess.Popen(self.user_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               encoding='utf-8', preexec_fn=os.setsid, env=os.environ, errors='ignore')
```

**达成路径**

sys.argv → parse() → ParamDict.set_args → get_arg('task') → self.user_cmd → subprocess.Popen(shell=True)

**验证说明**: 用户通过 --task 参数提供的命令经 check_arg_executable() 检查后使用 shell=True 执行。检查仅验证命令格式（以 sh/bash/python 开头且有 .sh/.py 扩展名），未验证命令内容。例如 'python -c "import os; os.system(\"rm -rf /\")"' 可通过检查。漏洞路径真实可达，建议使用 shell=False 或 shlex.quote() 进行参数清洗。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-CMD-002] command_injection - check_command, run_linux_cmd, run_command, run_cmd_output, real_time_output, popen_run_cmd

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-78 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/asys/common/cmd_run.py:42-112` @ `check_command, run_linux_cmd, run_command, run_cmd_output, real_time_output, popen_run_cmd`
**模块**: asys

**描述**: cmd_run.py 中多个函数使用 shell=True 执行外部命令，包括 check_command、run_linux_cmd、run_command、run_cmd_output、real_time_output、popen_run_cmd。接收任意字符串作为命令参数，可被利用执行任意shell命令。

**漏洞代码** (`src/asys/common/cmd_run.py:42-112`)

```c
subprocess.run(cmd, shell=True, ...) # Lines 42, 49, 58, 73
subprocess.Popen(command, shell=True, ...) # Line 84
os.popen(command) # Line 112
```

**达成路径**

command参数 → subprocess.run(shell=True) / subprocess.Popen(shell=True) / os.popen()

**验证说明**: cmd_run.py 中多个函数（check_command, run_linux_cmd, run_command, run_cmd_output, real_time_output, popen_run_cmd）使用 shell=True 执行命令。这些函数作为工具库被其他模块调用，若调用方传入外部输入则存在命令注入风险。建议所有调用方使用 shlex.quote() 清洗参数，或改用 shell=False 加参数列表方式。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CMD-002] command_injection - check_command

**严重性**: High | **CWE**: CWE-78 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/asys/common/cmd_run.py:42-43` @ `check_command`
**模块**: asys

**描述**: check_command 函数使用 subprocess.run 执行 shell 命令，command 参数通过 f-string 构造 shell 命令字符串，存在命令注入风险。

**漏洞代码** (`src/asys/common/cmd_run.py:42-43`)

```c
cmd = f"which {command}"  # 或 "where {command}"
ret = subprocess.run(cmd, shell=True, capture_output=True, text=True)
```

**达成路径**

command 参数 → f-string 构造 → subprocess.run(shell=True)

**验证说明**: check_command() 使用 f"which {command}" 或 f"where {command}" 构造命令，shell=True 执行。command 参数来自调用方，若为外部输入则可注入。建议使用 shell=False 加参数列表：subprocess.run(['which', command], shell=False)。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CMD-003] command_injection - run_linux_cmd

**严重性**: High | **CWE**: CWE-78 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/asys/common/cmd_run.py:49` @ `run_linux_cmd`
**模块**: asys

**描述**: run_linux_cmd 函数使用 subprocess.run 执行 shell 命令，cmd 参数直接传递给 shell=True 执行。

**漏洞代码** (`src/asys/common/cmd_run.py:49`)

```c
ret = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
```

**达成路径**

cmd 参数 → subprocess.run(shell=True)

**验证说明**: run_linux_cmd() 直接将 cmd 参数传给 subprocess.run(shell=True)。作为工具函数，若被调用方传入外部输入则存在命令注入。建议审查调用链并清洗参数。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CMD-004] command_injection - run_command

**严重性**: High | **CWE**: CWE-78 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/asys/common/cmd_run.py:57-59` @ `run_command`
**模块**: asys

**描述**: run_command 函数使用 subprocess.run 执行 shell 命令，command 参数直接传递给 shell=True 执行。

**漏洞代码** (`src/asys/common/cmd_run.py:57-59`)

```c
ret = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8',
                         env=os.environ)
```

**达成路径**

command 参数 → subprocess.run(shell=True)

**验证说明**: run_command() 与 run_linux_cmd() 模式相同，直接使用 shell=True 执行外部传入的命令。建议审查所有调用点。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CMD-005] command_injection - run_cmd_output

**严重性**: High | **CWE**: CWE-78 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/asys/common/cmd_run.py:72-74` @ `run_cmd_output`
**模块**: asys

**描述**: run_cmd_output 函数使用 subprocess.run 执行 shell 命令，command 参数直接传递给 shell=True 执行。

**漏洞代码** (`src/asys/common/cmd_run.py:72-74`)

```c
ret = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8',
                         env=os.environ)
```

**达成路径**

command 参数 → subprocess.run(shell=True)

**验证说明**: run_cmd_output() 与其他 cmd_run.py 函数模式相同，存在命令注入风险。建议统一改用 shell=False 方式。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CMD-006] command_injection - real_time_output

**严重性**: High | **CWE**: CWE-78 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/asys/common/cmd_run.py:83-85` @ `real_time_output`
**模块**: asys

**描述**: real_time_output 函数使用 subprocess.Popen 执行 shell 命令，command 参数直接传递给 shell=True 执行。

**漏洞代码** (`src/asys/common/cmd_run.py:83-85`)

```c
process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1,
                               universal_newlines=True, env=os.environ)
```

**达成路径**

command 参数 → subprocess.Popen(shell=True)

**验证说明**: real_time_output() 使用 subprocess.Popen(shell=True) 执行命令。与其他 cmd_run.py 函数风险相同，建议统一修复。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CMD-007] command_injection - popen_run_cmd

**严重性**: High | **CWE**: CWE-78 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/asys/common/cmd_run.py:111-113` @ `popen_run_cmd`
**模块**: asys

**描述**: popen_run_cmd 函数使用 os.popen 执行 shell 命令，command 参数直接传递给 os.popen 执行。

**漏洞代码** (`src/asys/common/cmd_run.py:111-113`)

```c
cmd = os.popen(command)
ret = cmd.read()
cmd.close()
```

**达成路径**

command 参数 → os.popen() → shell 执行

**验证说明**: popen_run_cmd() 使用 os.popen() 执行命令，本质上是 shell=True 的变体。风险与其他 cmd_run.py 函数相同。建议改用 subprocess.run(shell=False)。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CMD-005] command_injection - thread_stacks_reg_info, _get_reg_info_level_thread, start_gdb

**严重性**: High | **CWE**: CWE-78 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/asys/analyze/coredump_analyze.py:46-261` @ `thread_stacks_reg_info, _get_reg_info_level_thread, start_gdb`
**模块**: asys

**描述**: coredump 分析功能使用 shell=True 执行 gdb 命令。exe_file 和 core_file 参数来自用户输入，通过路径拼接形成命令字符串，可能通过特殊文件名注入命令。

**漏洞代码** (`src/asys/analyze/coredump_analyze.py:46-261`)

```c
subprocess.Popen(cmd, shell=True, ...) # f'gdb {exe_file} {core_file}'
```

**达成路径**

exe_file/core_file参数 → f'gdb {exe_file} {core_file}' → subprocess.Popen(shell=True)

**验证说明**: coredump_analyze.py 使用 f'gdb {exe_file} {core_file}' 拼接命令，shell=True 执行。exe_file 和 core_file 来自命令行参数，仅检查文件是否存在，未禁止文件名中的 shell 元字符（; | $ 等）。攻击者可通过精心构造的文件名（如 'test;rm -rf /'）注入命令。建议使用 shlex.quote() 包装文件名。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-CMD-010] command_injection - thread_stacks_reg_info

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-78 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/asys/analyze/coredump_analyze.py:46-47` @ `thread_stacks_reg_info`
**模块**: asys

**描述**: thread_stacks_reg_info 函数使用 subprocess.Popen 执行 gdb 命令，cmd 参数由 exe_file 和 core_file 构造，这两个参数来自用户命令行输入。

**漏洞代码** (`src/asys/analyze/coredump_analyze.py:46-47`)

```c
gdb_process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               bufsize=1, encoding='utf-8', errors='ignore', text=True, shell=True)
```

**达成路径**

sys.argv → exe_file, core_file → cmd = f'gdb {exe_file} {core_file}' → subprocess.Popen(shell=True)

**验证说明**: thread_stacks_reg_info() 使用 f'gdb {exe_file} {core_file}' 拼接命令，shell=True 执行。exe_file 和 core_file 来自命令行，仅检查文件存在性。文件名可包含 shell 元字符导致命令注入。建议使用 subprocess.Popen(['gdb', exe_file, core_file], shell=False) 或 shlex.quote()。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-CMD-011] command_injection - _get_reg_info_level_thread

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-78 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/asys/analyze/coredump_analyze.py:213-216` @ `_get_reg_info_level_thread`
**模块**: asys

**描述**: _get_reg_info_level_thread 函数使用 subprocess.Popen 执行 gdb 命令，exe_file 和 core_file 来自用户输入，存在命令注入风险。

**漏洞代码** (`src/asys/analyze/coredump_analyze.py:213-216`)

```c
gdb_process = subprocess.Popen(f'gdb {self.exe_file} {self.core_file}',
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               encoding='utf-8', errors='ignore', text=True, bufsize=1, shell=True)
```

**达成路径**

sys.argv → exe_file, core_file → subprocess.Popen(shell=True)

**验证说明**: _get_reg_info_level_thread() 使用相同的 GDB 命令拼接模式，存在同样的命令注入风险。建议与 VULN-SEC-CMD-010 同时修复，改用参数列表方式。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-CMD-012] command_injection - start_gdb

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-78 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/asys/analyze/coredump_analyze.py:258-261` @ `start_gdb`
**模块**: asys

**描述**: start_gdb 函数使用 subprocess.Popen 执行 gdb 命令，exe_file 和 core_file 来自用户输入，存在命令注入风险。

**漏洞代码** (`src/asys/analyze/coredump_analyze.py:258-261`)

```c
gdb_process = subprocess.Popen(f'gdb {self.exe_file} {self.core_file}',
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               encoding='utf-8', errors='ignore', text=True, shell=True)
```

**达成路径**

sys.argv → exe_file, core_file → subprocess.Popen(shell=True)

**验证说明**: start_gdb() 使用相同的 GDB 命令拼接模式，存在同样的命令注入风险。建议与 VULN-SEC-CMD-010/011 同时修复。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (4)

### [VULN-DF-CMD-006] command_injection - check_arg_executable

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/asys/cmdline/arg_checker.py:84-114` @ `check_arg_executable`
**模块**: asys

**描述**: arg_checker.py 的 check_arg_executable 函数仅检查命令是否以 sh/bash/python 开头并匹配 .sh/.py 扩展名，但无法阻止注入。例如 'python -c "import os; os.system(\"rm -rf /\")"' 会通过检查但执行恶意代码。

**漏洞代码** (`src/asys/cmdline/arg_checker.py:84-114`)

```c
check_exe = re.compile(r"sh|.*/sh|bash|.*/bash|python[0-9.]*|.*/python[0-9.]*")
check_script = re.compile(r"sh .*?.sh|...|python .*?.py")
```

**达成路径**

task参数 → check_arg_executable → 通过检查 → subprocess.Popen(shell=True)

**验证说明**: arg_checker.py check_arg_executable() 仅检查命令格式（以 sh/bash/python 开头且有 .sh/.py/.bash 扩展名），未检查命令内容。例如 'python -c "import os; os.system(\"rm -rf /\")"' 可通过检查，在 asys_launch.py 中被 shell=True 执行。此检查不足以防止命令注入，建议增加参数白名单或使用 shlex.quote()。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-CMD-003] command_injection - _run_cmd

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/asys/profiling/asys_profiling.py:138` @ `_run_cmd`
**模块**: asys

**描述**: asys profiling 功能拼接 msprof 命令后使用 shell=True 执行。output_path 和 device_id 参数来自用户输入，虽然经过部分校验但仍可能通过特殊字符注入。

**漏洞代码** (`src/asys/profiling/asys_profiling.py:138`)

```c
ret = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, encoding='utf-8', env=os.environ)
```

**达成路径**

output_path/device_id 参数 → cmd拼接 → subprocess.run(shell=True)

**验证说明**: asys_profiling.py 使用 f-string 拼接 msprof 命令，output_path 和 device_id 来自命令行。device_id 经 int() 转换和范围验证（0-N），无法注入。output_path 经 path_str_check() 验证（禁止空值、空格、特殊字符），注入受限。但 f-string 拼接仍有潜在风险，建议使用参数列表形式 subprocess.run([...], shell=False)。

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-CMD-013] command_injection - run

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/asys/profiling/asys_profiling.py:88-138` @ `run`
**模块**: asys

**描述**: _run_cmd 函数使用 subprocess.run 执行 msprof 命令，cmd 由用户参数 output_path, device_id, run_mode, aic_metrics 等构造，存在命令注入风险。

**漏洞代码** (`src/asys/profiling/asys_profiling.py:88-138`)

```c
cmd = (f"msprof --output={self.output_path} --sys-period={str(self.period)} "
        f"--sys-devices={self.device_id} ")
...
ret = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, encoding='utf-8', env=os.environ)
```

**达成路径**

sys.argv → output_path, device_id, run_mode → cmd 构造 → subprocess.run(shell=True)

**验证说明**: asys_profiling.py run() 方法使用 f-string 拼接 msprof 命令参数。device_id 经 int() 和范围验证，无法注入。output_path 经 path_str_check() 禁止特殊字符。aic_metrics 有默认值且未验证。漏洞风险有限，但建议改用参数列表方式。

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-CMD-004] command_injection - run_cmd_output

**严重性**: Medium（原评估: Critical → 验证后: Medium） | **CWE**: CWE-78 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner, security-auditor

**位置**: `src/msaicerr/ms_interface/utils.py:251-252` @ `run_cmd_output`
**模块**: msaicerr

**描述**: run_cmd_output 函数接收任意字符串作为 command 参数，直接使用 shell=True 执行。可能被调用者传入恶意命令。

**漏洞代码** (`src/msaicerr/ms_interface/utils.py:251-252`)

```c
ret = subprocess.run(command, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         encoding='utf-8', env=env)
```

**达成路径**

command参数 → subprocess.run(shell=True)

**验证说明**: msaicerr/utils.py run_cmd_output() 使用 shell=True 执行任意命令字符串。command 参数来源需追踪调用链确认。若仅被内部调用（如 execute_command 使用 shell=False），风险较低。建议审查所有调用点，确保无外部输入路径，否则需清洗参数。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -15 | cross_file: 0

---

## 5. Low 漏洞 (2)

### [VULN-SEC-CMD-009] command_injection - add_objdump_to_path

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-78 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/msaicerr/ms_interface/aicore_error_parser.py:1251` @ `add_objdump_to_path`
**模块**: msaicerr

**描述**: 使用 os.system 执行 chmod 命令，obj_dump_file 虽然是固定路径但通过字符串拼接构造命令，存在潜在命令注入风险。

**漏洞代码** (`src/msaicerr/ms_interface/aicore_error_parser.py:1251`)

```c
os.system("chmod 755 " + obj_dump_file)
```

**达成路径**

os.getcwd() → obj_dump_file 构造 → os.system()

**验证说明**: aicore_error_parser.py:1251 使用 os.system("chmod 755 " + obj_dump_file)。obj_dump_file 来自 os.getcwd() 加固定路径 "tools/cce-objdump_aarch64"，非外部输入，无法注入。风险较低，但字符串拼接模式不安全，建议改用 subprocess.run(['chmod', '755', obj_dump_file])。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN-SEC-AUTH-001] missing_authentication - Accept

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-306 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/msprof/collector/dvvp/common/socket/local_socket.cpp:96-111` @ `Accept`
**模块**: msprof

**描述**: Unix Socket 接受外部进程连接但没有对连接方进行身份验证或授权检查，任何能访问 socket 文件的进程都可以连接并发送数据。

**漏洞代码** (`src/msprof/collector/dvvp/common/socket/local_socket.cpp:96-111`)

```c
int32_t LocalSocket::Accept(int32_t fd) {
  ...
  auto clientFd = OsalAccept(fd, nullptr, nullptr);  // 不获取客户端地址信息
  ...
}
```

**达成路径**

外部进程 → socket 连接 → Accept() → 无身份验证 → 接收数据

**验证说明**: Unix Socket Accept() 未验证连接方身份。但攻击者需要：1) 获得 socket 文件访问权限（S_IRUSR|S_IWUSR 仅允许 owner）；2) 在同一机器上执行。属于本地权限提升场景而非远程攻击。根据 pre-validation-rules，CWE-306（缺少认证）不在扫描范围内，但此漏洞涉及 IPC 而非网络端点，保留为 POSSIBLE 待进一步调查。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -10 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| asys | 0 | 12 | 3 | 0 | 15 |
| msaicerr | 0 | 0 | 1 | 1 | 2 |
| msprof | 0 | 0 | 0 | 1 | 1 |
| **合计** | **0** | **12** | **4** | **2** | **18** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 17 | 94.4% |
| CWE-306 | 1 | 5.6% |
