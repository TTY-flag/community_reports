# 漏洞扫描报告 — 已确认漏洞

**项目**: oam-tools  
**扫描时间**: 2026-04-22T18:30:00Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞  

---

## Executive Summary

### 项目概况

oam-tools 是华为 Ascend NPU 服务器的运维工具套件，包含三个主要组件：

- **asys**: 系统诊断和性能分析工具，用于收集和分析系统信息
- **msaicerr**: AI Core 错误分析工具，用于解析 AI Core 错误信息
- **msprof**: 性能数据采集器，通过 Unix Socket 接收设备端数据

该项目采用混合语言开发，主要模块为 Python（asys、msaicerr）和 C/C++（msprof），总计 575 个源文件，约 59,000 行代码。

### 扫描结果摘要

本次扫描共发现 **20 个候选漏洞**，经验证后：

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 1 | 5% |
| LIKELY | 13 | 65% |
| POSSIBLE | 5 | 25% |
| FALSE_POSITIVE | 1 | 5% |

**关键发现**：

- **1 个已确认漏洞**（CWE-22 路径遍历）位于 msaicerr 的 tar 文件解压功能
- **13 个高置信度漏洞**（置信度 ≥70）全部为命令注入类型（CWE-78），集中在 asys 模块
- 所有高置信度漏洞均可通过命令行参数直接触发，攻击路径清晰可达
- 命令注入漏洞分布在三个核心文件：`asys_launch.py`、`cmd_run.py`、`coredump_analyze.py`

### 风险评估

该项目作为 CLI 工具套件，在本地环境执行。主要攻击场景为：

1. **恶意用户输入**：通过构造特殊命令行参数或文件名，触发命令注入
2. **恶意 tar 文件**：通过构造包含路径遍历序列的 tar 文件，实现任意位置文件写入
3. **权限提升**：若工具以高权限（root）执行，攻击者可获得系统级权限

**修复优先级建议**：

- **立即修复**：CONFIRMED 漏洞（路径遍历）和 execute_task 命令注入
- **短期修复**：cmd_run.py 工具库和 coredump_analyze.py 的命令注入
- **中期修复**：其余 LIKELY 和 POSSIBLE 漏洞

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
| High | 1 | 100.0% |
| **有效漏洞总计** | **1** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞（含高置信度 LIKELY）

| 排名 | 漏洞 ID | 类型 | 严重性 | 状态 | 置信度 |
|------|---------|------|--------|------|--------|
| 1 | VULN-DF-PATH-001 | path_traversal | High | CONFIRMED | 85 |
| 2 | VULN-DF-CMD-001 | command_injection | High | LIKELY | 75 |
| 3 | VULN-DF-CMD-002 | command_injection | High | LIKELY | 75 |
| 4 | VULN-SEC-CMD-010 | command_injection | High | LIKELY | 70 |
| 5 | VULN-SEC-CMD-011 | command_injection | High | LIKELY | 70 |
| 6 | VULN-SEC-CMD-012 | command_injection | High | LIKELY | 70 |
| 7 | VULN-DF-CMD-005 | command_injection | High | LIKELY | 70 |
| 8 | VULN-SEC-CMD-002 | command_injection | High | LIKELY | 75 |
| 9 | VULN-SEC-CMD-003 | command_injection | High | LIKELY | 75 |
| 10 | VULN-SEC-CMD-004 | command_injection | High | LIKELY | 75 |

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

## 3. High 漏洞 (1)

### [VULN-DF-PATH-001] path_traversal - extract_tar

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/msaicerr/msaicerr.py:53-56` @ `extract_tar`  
**模块**: msaicerr

**描述**: extract_tar 函数直接解压用户提供的 tar 文件，未检查文件内部路径是否包含 ../ 等路径遍历序列。恶意 tar 文件可将文件写入任意位置（Zip Slip）。

**漏洞代码** (`src/msaicerr/msaicerr.py:53-56`)

```python
def extract_tar(tar_file, path):
    tar = tarfile.open(tar_file, "r")
    tar.extractall(path)
    tar.close()
```

**达成路径**

```
args.tar_file → extract_tar(args.tar_file, extract_path) → tarfile.open → tar.extractall(path)
```

**验证说明**: msaicerr.py extract_tar() 使用 tar.extractall() 解压用户提供的 tar 文件，未检查文件内部路径是否包含 ../ 路径遍历序列。攻击者可构造恶意 tar 文件（如包含 '../../../etc/cron.d/malicious'），实现任意位置文件写入（Zip Slip）。这是典型的 CWE-22 漏洞，建议在解压前验证每个成员路径，拒绝包含 ../ 或绝对路径的成员。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Top 5 漏洞深度分析

以下对置信度最高的 5 个漏洞进行深入分析，包括触发条件、影响范围和修复优先级。

### 4.1 [VULN-DF-PATH-001] 路径遍历漏洞深度分析

**触发条件分析**：

从源代码分析，漏洞触发路径如下：

```python
# msaicerr.py:96-100
if not args.report_path and args.tar_file:
    utils.print_info_log("Start to unzip tar.gz package.")
    extract_path = "extract_" + cur_time_str
    extract_tar(args.tar_file, extract_path)
    args.report_path = get_select_dir(extract_path)
```

用户通过 `-p` 参数指定 tar 文件路径（`args.tar_file`），工具在当前工作目录创建解压目录并调用 `extract_tar()`。由于 `extract_tar()` 未验证 tar 文件内部路径，攻击者可构造如下恶意 tar 文件：

```
malicious.tar
├── ../../../etc/cron.d/backdoor  → 写入系统 cron 目录
├── ../../../root/.ssh/authorized_keys → 写入 SSH 密钥
└── normal_file.txt → 正常文件（伪装）
```

**影响范围**：

- **文件覆盖**：覆盖系统关键配置文件（如 `/etc/passwd`、`/etc/shadow`）
- **权限提升**：写入 `/etc/cron.d/` 或 `/etc/sudoers.d/` 实现权限提升
- **持久化攻击**：写入 `.bashrc`、`.ssh/authorized_keys` 实现持久化

**攻击可行性**：

| 条件 | 状态 |
|------|------|
| 用户可指定 tar 文件路径 | ✅ 通过 `-p` 参数 |
| tar 文件内容不受控制 | ✅ 外部提供的文件 |
| 解压位置在当前目录 | ✅ `extract_YYYYMMDDHHMMSS` |
| 无路径验证 | ✅ 直接调用 `extractall()` |

**修复优先级**: **立即修复**（最高优先级）

---

### 4.2 [VULN-DF-CMD-001] 命令注入漏洞深度分析

**触发条件分析**：

从源代码分析，漏洞触发路径如下：

```python
# asys_launch.py:39
self.user_cmd = ParamDict().get_arg("task")

# asys_launch.py:80-81
pro = subprocess.Popen(self.user_cmd, shell=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, encoding='utf-8',
                       preexec_fn=os.setsid, env=os.environ, errors='ignore')
```

用户通过 `--task` 参数指定要执行的命令，该命令直接通过 `shell=True` 执行。虽然存在 `check_arg_executable()` 检查，但该检查仅验证命令格式：

```python
# arg_checker.py (从报告可知)
check_exe = re.compile(r"sh|.*/sh|bash|.*/bash|python[0-9.]*|.*/python[0-9.]*")
check_script = re.compile(r"sh .*?.sh|...|python .*?.py")
```

此检查无法阻止以下攻击载荷：

```bash
python -c "import os; os.system('rm -rf /')"
bash -c "cat /etc/passwd > /tmp/leaked"
sh script.sh; rm -rf /home
```

**影响范围**：

- **任意命令执行**：攻击者可执行任意 shell 命令
- **数据泄露**：读取敏感文件（`/etc/passwd`、环境变量）
- **系统破坏**：删除文件、修改配置
- **权限提升**：若工具以 root 执行，可获得系统级权限

**攻击可行性**：

| 条件 | 状态 |
|------|------|
| 用户可指定命令 | ✅ 通过 `--task` 参数 |
| 命令直接执行 | ✅ `shell=True` |
| 检查不足 | ✅ 仅检查格式，不检查内容 |

**修复优先级**: **立即修复**（最高优先级）

---

### 4.3 [VULN-DF-CMD-002] 命令注入工具库深度分析

**触发条件分析**：

从源代码分析，`cmd_run.py` 包含多个使用 `shell=True` 的函数：

```python
# cmd_run.py:42
ret = subprocess.run(cmd, shell=True, capture_output=True, text=True)

# cmd_run.py:49
ret = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# cmd_run.py:58
ret = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')

# cmd_run.py:84
process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, ...)

# cmd_run.py:112
cmd = os.popen(command)
```

这些函数作为工具库被其他模块调用，若调用方传入外部输入则存在命令注入风险。

**影响范围**：

- **工具库广泛使用**：作为核心工具库，被多个模块调用
- **调用链复杂**：需要追踪所有调用点确认风险
- **潜在注入点**：任何使用外部输入调用这些函数的地方

**攻击可行性**：

风险取决于调用链。若调用方传入用户可控参数（如文件路径、命令参数），则存在注入风险。需要审计所有调用点。

**修复优先级**: **短期修复**（高优先级）

---

### 4.4 [VULN-SEC-CMD-010/011/012] GDB 命令注入深度分析

**触发条件分析**：

从源代码分析，三个函数使用相同的 GDB 命令拼接模式：

```python
# coredump_analyze.py:46-47
gdb_process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, bufsize=1, encoding='utf-8',
                               errors='ignore', text=True, shell=True)

# coredump_analyze.py:214-216
gdb_process = subprocess.Popen(f'gdb {self.exe_file} {self.core_file}',
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, encoding='utf-8', errors='ignore',
                               text=True, bufsize=1, shell=True)

# coredump_analyze.py:259-261
gdb_process = subprocess.Popen(f'gdb {self.exe_file} {self.core_file}',
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, encoding='utf-8', errors='ignore',
                               text=True, shell=True)
```

`exe_file` 和 `core_file` 来自命令行参数，仅检查文件存在性：

```python
# 从 ParamDict 获取参数
self.exe_file = exe_file  # 用户通过 --exe 参数指定
self.core_file = core_file  # 用户通过 --core 参数指定
```

攻击者可通过构造特殊文件名注入命令：

```bash
# 创建恶意文件名
touch "/tmp/test;rm -rf /"

# 使用该文件名调用工具
asys analyze --exe "/tmp/test;rm -rf /" --core normal.core
# 实际执行的命令: gdb /tmp/test;rm -rf / normal.core
```

**影响范围**：

- **任意命令执行**：通过文件名注入 shell 命令
- **数据泄露**：读取敏感文件
- **系统破坏**：删除文件、修改配置

**攻击可行性**：

| 条件 | 状态 |
|------|------|
| 用户可指定文件名 | ✅ 通过 `--exe`、`--core` 参数 |
| 文件名未过滤 shell 元字符 | ✅ 仅检查文件存在性 |
| shell=True 执行 | ✅ 直接拼接命令 |

**修复优先级**: **短期修复**（高优先级）

---

### 4.5 [VULN-DF-CMD-005] Coredump 分析命令注入深度分析

**触发条件分析**：

与 VULN-SEC-CMD-010/011/012 相同，该漏洞覆盖 coredump_analyze.py 中所有使用 GDB 命令拼接的位置。

从源代码分析，`thread_stacks_reg_info` 函数使用外部传入的 `cmd` 参数：

```python
# coredump_analyze.py:41-47
def thread_stacks_reg_info(cmd, thread, stacks, queue_reg_info):
    gdb_process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=1, encoding='utf-8',
                                   errors='ignore', text=True, shell=True)
```

`cmd` 在 `_get_reg_info_level_stack()` 中构造：

```python
# coredump_analyze.py:200
cmd = f'gdb {self.exe_file} {self.core_file}'
```

**影响范围**：与 VULN-SEC-CMD-010/011/012 相同。

**修复优先级**: **短期修复**（高优先级）

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| msaicerr | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **1** | **0** | **0** | **1** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 1 | 100.0% |

---

## 7. Remediation Recommendations

### 7.1 [VULN-DF-PATH-001] 路径遍历漏洞修复方案

**修复策略**：在解压前验证每个 tar 成员的路径，拒绝包含路径遍历序列或绝对路径的成员。

**修复代码示例**：

```python
import os
import tarfile

def extract_tar_safe(tar_file, path):
    """安全解压 tar 文件，防止路径遍历攻击"""
    path = os.path.realpath(path)
    tar = tarfile.open(tar_file, "r")
    
    for member in tar.getmembers():
        # 检查路径遍历序列
        if ".." in member.name:
            raise ValueError(f"Path traversal detected: {member.name}")
        
        # 检查绝对路径
        if os.path.isabs(member.name):
            raise ValueError(f"Absolute path not allowed: {member.name}")
        
        # 检查解压后的实际路径是否在目标目录内
        member_path = os.path.realpath(os.path.join(path, member.name))
        if not member_path.startswith(path):
            raise ValueError(f"Path escapes target directory: {member.name}")
    
    tar.extractall(path)
    tar.close()
```

**替代方案**：使用 Python 3.12+ 的 `tarfile.data_filter`：

```python
import tarfile

def extract_tar_safe(tar_file, path):
    tar = tarfile.open(tar_file, "r")
    tar.extractall(path, filter='data')  # Python 3.12+ 内置安全过滤器
    tar.close()
```

---

### 7.2 [VULN-DF-CMD-001] 命令注入漏洞修复方案

**修复策略**：使用 `shell=False` 和参数列表方式执行命令，避免 shell 解释。

**修复代码示例**：

```python
import subprocess
import shlex

def execute_task_safe(user_cmd):
    """安全执行用户命令，防止命令注入"""
    # 方案 1：使用参数列表 + shell=False
    cmd_list = shlex.split(user_cmd)
    pro = subprocess.Popen(cmd_list, shell=False, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, encoding='utf-8',
                           preexec_fn=os.setsid, env=os.environ, errors='ignore')
    return pro

# 方案 2：若必须使用 shell，则限制可执行的命令类型
def execute_task_restricted(user_cmd):
    """限制可执行命令类型"""
    # 仅允许执行预定义的脚本文件
    allowed_commands = {
        'python': lambda x: x.endswith('.py'),
        'bash': lambda x: x.endswith('.sh'),
        'sh': lambda x: x.endswith('.sh'),
    }
    
    parts = shlex.split(user_cmd)
    if len(parts) < 2:
        raise ValueError("Invalid command format")
    
    interpreter = parts[0]
    script_file = parts[1]
    
    if interpreter not in allowed_commands:
        raise ValueError(f"Interpreter not allowed: {interpreter}")
    
    if not allowed_commands[interpreter](script_file):
        raise ValueError(f"Script file extension not allowed: {script_file}")
    
    # 使用参数列表执行
    pro = subprocess.Popen(parts, shell=False, ...)
    return pro
```

---

### 7.3 [VULN-DF-CMD-002] 命令注入工具库修复方案

**修复策略**：将所有 `shell=True` 改为 `shell=False`，使用参数列表。

**修复代码示例**：

```python
import subprocess

def check_command(command):
    """安全检查命令是否存在"""
    import shutil
    return shutil.which(command) is not None

def run_linux_cmd(cmd_list):
    """安全执行命令"""
    if isinstance(cmd_list, str):
        cmd_list = shlex.split(cmd_list)
    ret = subprocess.run(cmd_list, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return ret.returncode == 0

def run_command(cmd_list):
    """安全执行命令并返回输出"""
    if isinstance(cmd_list, str):
        cmd_list = shlex.split(cmd_list)
    ret = subprocess.run(cmd_list, shell=False, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, encoding='utf-8', env=os.environ)
    if ret.returncode == 0:
        return ret.stdout.strip()
    return ret.stderr.strip()

def real_time_output(cmd_list, output=True):
    """安全执行命令并实时输出"""
    if isinstance(cmd_list, str):
        cmd_list = shlex.split(cmd_list)
    process = subprocess.Popen(cmd_list, shell=False, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, bufsize=1,
                               universal_newlines=True, env=os.environ)
    if output:
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
    process.wait()
    return process.returncode == 0

def popen_run_cmd(cmd_list):
    """安全执行命令（替代 os.popen）"""
    if isinstance(cmd_list, str):
        cmd_list = shlex.split(cmd_list)
    ret = subprocess.run(cmd_list, shell=False, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, encoding='utf-8')
    return ret.stdout
```

---

### 7.4 [VULN-SEC-CMD-010/011/012] GDB 命令注入修复方案

**修复策略**：使用 `shell=False` 和参数列表方式调用 GDB，或使用 `shlex.quote()` 包装文件名。

**修复代码示例**：

```python
import subprocess
import shlex

def thread_stacks_reg_info_safe(exe_file, core_file, thread, stacks, queue_reg_info):
    """安全的 GDB 调用"""
    # 方案 1：使用参数列表 + shell=False
    gdb_process = subprocess.Popen(['gdb', exe_file, core_file],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=1, encoding='utf-8',
                                   errors='ignore', text=True, shell=False)
    
    # 方案 2：若必须使用 shell=True，则使用 shlex.quote() 包装文件名
    cmd = f'gdb {shlex.quote(exe_file)} {shlex.quote(core_file)}'
    gdb_process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=1, encoding='utf-8',
                                   errors='ignore', text=True, shell=True)
    
    # ... 后续 GDB 交互代码 ...
```

---

### 7.5 修复优先级和实施建议

| 优先级 | 漏洞 ID | 修复难度 | 建议时间 |
|--------|---------|----------|----------|
| 立即修复 | VULN-DF-PATH-001 | 低（约 30 行代码） | 1 天内 |
| 立即修复 | VULN-DF-CMD-001 | 中（需修改调用链） | 1 天内 |
| 短期修复 | VULN-DF-CMD-002 | 中（需审计所有调用点） | 1 周内 |
| 短期修复 | VULN-SEC-CMD-010/011/012 | 低（统一修改） | 1 周内 |

**实施建议**：

1. **路径遍历漏洞**：优先修复，影响范围明确，修复代码简单
2. **命令注入漏洞**：统一修复 `cmd_run.py` 工具库，影响所有调用方
3. **GDB 命令注入**：修改 `coredump_analyze.py` 中所有 GDB 调用点
4. **全局安全审计**：检查所有使用 `shell=True` 或 `os.popen()` 的位置
5. **安全编码培训**：培训开发团队关于安全命令执行的最佳实践

---

## 8. 附录：安全编码最佳实践

### 8.1 命令执行安全原则

1. **避免使用 shell=True**：除非绝对必要，使用参数列表 + shell=False
2. **使用 shlex.split()**：将命令字符串转换为参数列表
3. **使用 shlex.quote()**：当必须拼接命令时，包装所有外部输入
4. **使用 shutil.which()**：替代 `which` 命令检查可执行文件

### 8.2 文件操作安全原则

1. **使用 os.path.realpath()**：获取真实路径，避免符号链接绕过
2. **验证路径边界**：确保操作路径在预期目录内
3. **拒绝路径遍历序列**：检查路径中的 ".."
4. **拒绝绝对路径**：限制相对路径输入

### 8.3 输入验证原则

1. **白名单优于黑名单**：定义允许的输入范围而非禁止的危险字符
2. **类型验证**：验证输入类型（如设备 ID 必须为整数）
3. **长度限制**：限制输入长度防止缓冲区问题
4. **路径规范化**：使用 `os.path.normpath()` 规范化路径输入