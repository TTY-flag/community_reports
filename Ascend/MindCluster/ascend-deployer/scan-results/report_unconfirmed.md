# 漏洞扫描报告 — 待确认漏洞

**项目**: ascend-deployer
**扫描时间**: 2025-04-21T06:15:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 9 | 50.0% |
| POSSIBLE | 5 | 27.8% |
| FALSE_POSITIVE | 4 | 22.2% |
| **总计** | **18** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 7 | 50.0% |
| Medium | 7 | 50.0% |
| **有效漏洞总计** | **14** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-CRED-001]** credential_exposure (High) - `ascend_deployer/library/scp.py:52` @ `run_scp` | 置信度: 75
2. **[VULN-SEC-CRED-002]** credential_exposure (High) - `ascend_deployer/large_scale_deploy/tools/spread_tool.py:131` @ `ConnHostInfo` | 置信度: 70
3. **[VULN-DF-CROSS-001]** command_injection (High) - `ascend_deployer/large_scale_deploy/process/remote_deploy_task.py:59` @ `_start_deploy` | 置信度: 65
4. **[VULN-DF-PY-002]** command_injection (High) - `ascend_deployer/large_scale_deploy/tools/spread_tool.py:162` @ `run_ssh_cmd` | 置信度: 60
5. **[VULN-DF-PY-003]** command_injection (High) - `ascend_deployer/large_scale_deploy/tools/spread_tool.py:174` @ `scp` | 置信度: 60
6. **[VULN-SEC-CMD-001]** command_injection (High) - `ascend_deployer/large_scale_deploy/tools/spread_tool.py:162` @ `run_ssh_cmd` | 置信度: 60
7. **[VULN-SEC-CMD-002]** command_injection (High) - `ascend_deployer/large_scale_deploy/tools/spread_tool.py:174` @ `scp` | 置信度: 60
8. **[VULN-SEC-CRED-003]** credential_exposure (Medium) - `ascend_deployer/trans_excel_to_inventory.py:121` @ `get_host_info` | 置信度: 70
9. **[VULN-SEC-LOG-001]** information_disclosure (Medium) - `ascend_deployer/utils.py:297` @ `run_cmd` | 置信度: 65
10. **[VULN-SEC-ZIP-001]** path_traversal (Medium) - `ascend_deployer/jobs.py:594` @ `extract_zip, extract_tar` | 置信度: 50

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@ascend_deployer/start_deploy.py` | cmdline | untrusted_local | CLI入口，接收用户命令行参数，包括--install、--upgrade、--check等参数，用户可控制安装包选择和部署行为 | CLI主入口，解析命令行参数并执行部署任务 |
| `_process_args@ascend_deployer/start_deploy.py` | cmdline | untrusted_local | 处理用户输入的命令行参数，直接用于控制Ansible执行 | 解析并处理CLI参数 |
| `run_playbook@ascend_deployer/jobs.py` | cmdline | semi_trusted | 通过Ansible playbook执行部署任务，tags参数来自用户CLI输入 | Ansible playbook执行入口 |
| `run@ascend_deployer/trans_excel_to_inventory.py` | file | untrusted_local | 解析用户提供的CSV/Excel文件，生成inventory配置，文件内容可包含IP地址、SSH凭证等敏感数据 | CSV/Excel转inventory配置入口 |
| `get_table_info@ascend_deployer/trans_excel_to_inventory.py` | file | untrusted_local | 读取用户CSV文件，解析为inventory配置数据 | CSV文件读取解析 |
| `parse@ascend_deployer/module_utils/inventory_file.py` | file | untrusted_local | 解析inventory_file配置文件，包含主机IP、SSH用户名密码等敏感信息 | Inventory配置文件解析入口 |
| `safe_eval@ascend_deployer/module_utils/inventory_file.py` | file | untrusted_local | 使用eval()执行表达式解析配置参数，虽有正则过滤但仍有潜在风险 | 配置参数表达式解析（含eval） |
| `download@ascend_deployer/downloader/download_util.py` | network | untrusted_network | 从远程HTTP/HTTPS服务器下载软件包，URL来自配置文件或用户输入 | 远程文件下载入口 |
| `urlopen@ascend_deployer/downloader/download_util.py` | network | untrusted_network | 打开远程URL获取内容，用于下载元数据和软件包信息 | HTTP请求入口 |
| `run_scp@ascend_deployer/library/scp.py` | network | semi_trusted | 执行SCP命令复制文件到远程主机，主机IP、用户名、密码来自Ansible模块参数 | SCP文件传输入口 |
| `run_ssh_cmd@ascend_deployer/large_scale_deploy/tools/spread_tool.py` | network | semi_trusted | 通过SSH在远程主机执行命令，包含主机IP和密码信息 | SSH命令执行入口 |
| `scp@ascend_deployer/large_scale_deploy/tools/spread_tool.py` | network | semi_trusted | 执行SCP命令传输文件，包含主机认证信息 | SCP传输入口 |
| `run_cmd@ascend_deployer/utils.py` | cmdline | semi_trusted | 执行shell命令的核心函数，参数可来自用户输入或配置，支持shell=True模式 | 通用命令执行函数（Popen） |
| `extract_zip@ascend_deployer/jobs.py` | file | untrusted_local | 解压ZIP文件，文件来自下载的软件包或用户提供的资源包 | ZIP文件解压入口 |
| `extract_tar@ascend_deployer/jobs.py` | file | untrusted_local | 解压TAR文件，文件来自下载的软件包 | TAR文件解压入口 |
| `run@ascend_deployer/library/uncompress_resources.py` | file | untrusted_local | 解压资源包tar文件到目标目录，文件路径来自Ansible模块参数 | 资源包解压入口 |
| `_run_cmd@ascend_deployer/library/install_cann.py` | cmdline | semi_trusted | 执行安装脚本的命令函数，脚本路径来自glob查找结果 | CANN安装命令执行入口 |
| `_run_cmd@ascend_deployer/library/install_sys_pkg.py` | cmdline | semi_trusted | 执行系统包安装命令（yum/apt），命令参数来自配置文件解析 | 系统包安装命令执行入口 |
| `_run_command@ascend_deployer/library/process_npu.py` | cmdline | semi_trusted | 执行NPU驱动/固件安装命令，脚本路径来自glob查找 | NPU安装命令执行入口 |
| `safe_read@ascend_deployer/module_utils/safe_file_handler.py` | file | untrusted_local | 安全文件读取函数，读取用户配置文件或下载的文件 | 文件读取入口 |
| `safe_write@ascend_deployer/module_utils/safe_file_handler.py` | file | trusted_admin | 安全文件写入函数，用于写入配置和日志文件 | 文件写入入口 |
| `main@ascend_deployer/large_scale_deployer.py` | cmdline | untrusted_local | 大规模部署CLI入口，处理大量主机的并行部署 | 大规模部署主入口 |

**其他攻击面**:
- CLI Arguments: 用户通过命令行参数控制安装包选择、场景配置、升级操作等
- Configuration Files: inventory_file, CSV/Excel模板文件包含主机IP、SSH凭证等敏感信息
- Download URLs: 从远程服务器下载软件包，URL来自配置文件
- Package Archives: ZIP/TAR软件包文件，包含安装脚本和二进制文件
- SSH Connections: 通过Ansible SSH连接远程主机执行部署任务
- Environment Variables: ASCEND_DEPLOYER_HOME, SSH_CLIENT等环境变量影响程序行为
- Ansible Playbooks: 通过YAML playbook定义部署流程，可能包含用户定制内容
- Excel/CSV Input Files: 用户提供的CSV模板文件，解析后生成inventory配置

---

## 3. High 漏洞 (7)

### [VULN-SEC-CRED-001] credential_exposure - run_scp

**严重性**: High | **CWE**: CWE-522 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `ascend_deployer/library/scp.py:52-53` @ `run_scp`
**模块**: library

**描述**: scp.py 通过环境变量 SSHPASS 传递密码，环境变量可被其他进程读取，且在进程列表（ps命令）中可见，导致密码泄露风险。

**漏洞代码** (`ascend_deployer/library/scp.py:52-53`)

```c
if self.passwd:
    os.environ["SSHPASS"] = self.passwd
```

**达成路径**

AnsibleModule.params['passwd'] -> os.environ['SSHPASS'] -> sshpass -e 命令

**验证说明**: Password set as environment variable SSHPASS. Visible in /proc/[pid]/environ and ps eww output. Other processes can read password. Credential exposure vulnerability confirmed.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CRED-002] credential_exposure - ConnHostInfo

**严重性**: High | **CWE**: CWE-522 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `ascend_deployer/large_scale_deploy/tools/spread_tool.py:131-151` @ `ConnHostInfo`
**模块**: large_scale_deploy

**描述**: spread_tool.py ConnHostInfo 类将密码以明文形式存储在对象中，并通过 to_json() 方法写入 JSON 文件，导致密码在文件系统和日志中泄露。

**漏洞代码** (`ascend_deployer/large_scale_deploy/tools/spread_tool.py:131-151`)

```c
def __init__(self, ip, account="", password=""):
    self.ip = ip
    self.account = account
    self.password = password
```

**达成路径**

Ansible inventory 配置 -> ConnHostInfo -> to_json() -> JSON 文件

**验证说明**: ConnHostInfo stores password in plaintext and to_json() method writes it to JSON files. Password visible in filesystem and logs.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CROSS-001] command_injection - _start_deploy

**严重性**: High | **CWE**: CWE-78 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `ascend_deployer/large_scale_deploy/process/remote_deploy_task.py:59-62` @ `_start_deploy`
**模块**: cross_module
**跨模块**: module_utils → large_scale_deploy → config_model

**描述**: Cross-module command injection chain: SSH commands flow from inventory configuration parsing (ConnHostInfo.from_ansible_host_info) through spread_tool.run_ssh_cmd() to remote_deploy_task.py._start_deploy(). Attackers who control inventory file content can execute arbitrary commands on remote hosts.

**漏洞代码** (`ascend_deployer/large_scale_deploy/process/remote_deploy_task.py:59-62`)

```c
@spread_tool.validate_cmd_result()
def _start_deploy(self, start_cmd):
    cmd = f"echo y | nohup  {start_cmd} > " ...
    return spread_tool.run_ssh_cmd(self._remote_conn_info, cmd)
```

**达成路径**

[MODULE: module_utils] inventory_file.py:224 config.read(OLD_FILE_PATH) [SOURCE]
  → [MODULE: large_scale_deploy/config_model] inventory.py parses hosts
    → [MODULE: large_scale_deploy] ConnHostInfo.from_ansible_host_info()
      → [MODULE: large_scale_deploy] spread_tool.run_ssh_cmd()
        → [MODULE: large_scale_deploy] remote_deploy_task._start_deploy() [SINK]

**验证说明**: Cross-module command injection chain. Inventory file parsed -> ConnHostInfo created -> SSH command executed. Same vulnerability as VULN-DF-PY-002 but demonstrates complete attack path across modules.

**评分明细**: base: 30 | reachability: 25 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-PY-002] command_injection - run_ssh_cmd

**严重性**: High | **CWE**: CWE-78 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `ascend_deployer/large_scale_deploy/tools/spread_tool.py:162-166` @ `run_ssh_cmd`
**模块**: large_scale_deploy

**描述**: Potential command injection via SSH command construction in run_ssh_cmd(). Password, account, IP, and command are directly concatenated into SSH command string using f-string without proper sanitization. If inventory file contains malicious values, arbitrary commands could be executed.

**漏洞代码** (`ascend_deployer/large_scale_deploy/tools/spread_tool.py:162-166`)

```c
def run_ssh_cmd(host_info: ConnHostInfo, cmd, timeout=100):
    sshpass_cmd = f"sshpass -p {host_info.password} " if host_info.password else ""
    account_ = host_info.account and f"{host_info.account}@"
    ssh_cmd = f"{sshpass_cmd}ssh -o StrictHostKeyChecking=no {account_}{host_info.ip} '{cmd}'"
    return run_cmd(ssh_cmd, timeout=timeout)
```

**达成路径**

spread_tool.py:144-146 ConnHostInfo.from_ansible_host_info() parses inventory [SOURCE]
  → spread_tool.py:162-166 run_ssh_cmd(host_info, cmd)
    → spread_tool.py:165 ssh_cmd = f"...{host_info.password}...{cmd}" [PROPAGATION - f-string]
      → spread_tool.py:166 run_cmd(ssh_cmd) [SINK - subprocess.Popen]

**验证说明**: Password directly concatenated into SSH command via f-string. run_cmd uses shell=False and shlex.split(), preventing full command injection. However, argument injection possible if password contains spaces - shlex.split would incorrectly split arguments causing sshpass to receive wrong password. Exploitable if inventory file is compromised.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-PY-003] command_injection - scp

**严重性**: High | **CWE**: CWE-78 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `ascend_deployer/large_scale_deploy/tools/spread_tool.py:174-177` @ `scp`
**模块**: large_scale_deploy

**描述**: Potential command injection via SCP command construction in scp(). Password, source path, and destination path are directly concatenated into SCP command string using f-string without proper sanitization. If inventory file or paths contain malicious values, arbitrary commands could be executed.

**漏洞代码** (`ascend_deployer/large_scale_deploy/tools/spread_tool.py:174-177`)

```c
def scp(remote_host_info: ConnHostInfo, src_path, dest_path, timeout=100):
    sshpass_cmd = f"sshpass -p {remote_host_info.password} " if remote_host_info.password else ""
    scp_cmd = f"{sshpass_cmd}scp -o StrictHostKeyChecking=no {src_path} {dest_path}"
    return run_cmd(scp_cmd, timeout=timeout)
```

**达成路径**

spread_tool.py:144-146 ConnHostInfo.from_ansible_host_info() [SOURCE - Inventory]
  → spread_tool.py:174-177 scp(remote_host_info, src_path, dest_path)
    → spread_tool.py:176 scp_cmd = f"...{remote_host_info.password}...{src_path}...{dest_path}" [PROPAGATION]
      → spread_tool.py:177 run_cmd(scp_cmd) [SINK]

**验证说明**: Same as VULN-DF-PY-002. Password and paths concatenated into SCP command. shell=False mitigates full command injection, but argument injection possible if password/paths contain spaces.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-CMD-001] command_injection - run_ssh_cmd

**严重性**: High | **CWE**: CWE-78 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `ascend_deployer/large_scale_deploy/tools/spread_tool.py:162-166` @ `run_ssh_cmd`
**模块**: large_scale_deploy

**描述**: spread_tool.py run_ssh_cmd() 函数直接拼接密码到 shell 命令中，密码包含特殊字符（如分号、反引号等）时可导致命令注入。攻击者可以通过构造恶意密码执行任意命令。

**漏洞代码** (`ascend_deployer/large_scale_deploy/tools/spread_tool.py:162-166`)

```c
sshpass_cmd = f"sshpass -p {host_info.password} " if host_info.password else ""
ssh_cmd = f"{sshpass_cmd}ssh -o StrictHostKeyChecking=no {account_}{host_info.ip} '{cmd}'"
return run_cmd(ssh_cmd, timeout=timeout)
```

**达成路径**

ConnHostInfo.password (来自 Ansible 模块参数) -> f-string 拼接 -> run_cmd(shell=False 但命令已拼接完成)

**验证说明**: Duplicate of VULN-DF-PY-002. Command injection via SSH command construction with shell=False mitigating full injection but argument injection possible.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-CMD-002] command_injection - scp

**严重性**: High | **CWE**: CWE-78 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `ascend_deployer/large_scale_deploy/tools/spread_tool.py:174-177` @ `scp`
**模块**: large_scale_deploy

**描述**: spread_tool.py scp() 函数直接拼接密码到 shell 命令中，存在命令注入风险。

**漏洞代码** (`ascend_deployer/large_scale_deploy/tools/spread_tool.py:174-177`)

```c
sshpass_cmd = f"sshpass -p {remote_host_info.password} " if remote_host_info.password else ""
scp_cmd = f"{sshpass_cmd}scp -o StrictHostKeyChecking=no {src_path} {dest_path}"
return run_cmd(scp_cmd, timeout=timeout)
```

**达成路径**

ConnHostInfo.password -> f-string 拼接 -> run_cmd

**验证说明**: Duplicate of VULN-DF-PY-003. Command injection via SCP command construction.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (7)

### [VULN-SEC-CRED-003] credential_exposure - get_host_info

**严重性**: Medium | **CWE**: CWE-256 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `ascend_deployer/trans_excel_to_inventory.py:121-124` @ `get_host_info`
**模块**: entry_points

**描述**: trans_excel_to_inventory.py 将 CSV 文件中的 SSH 密码直接写入 inventory_file 配置文件，密码以明文形式存储。

**漏洞代码** (`ascend_deployer/trans_excel_to_inventory.py:121-124`)

```c
host_info = f'{self.ip} ansible_ssh_user="{self.ansible_ssh_user}" '
if self.ansible_ssh_pass:
    host_info += f'ansible_ssh_pass="{self.ansible_ssh_pass}" '
```

**达成路径**

CSV 文件 -> HostInfo.ansible_ssh_pass -> inventory_file

**验证说明**: SSH password from CSV file written directly to inventory_file without encryption. Password stored plaintext in configuration.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-LOG-001] information_disclosure - run_cmd

**严重性**: Medium | **CWE**: CWE-532 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `ascend_deployer/utils.py:297-332` @ `run_cmd`
**模块**: entry_points

**描述**: utils.py run_cmd() 函数将执行的命令和所有输出写入日志文件，如果命令包含密码或敏感信息，会导致日志泄露。

**漏洞代码** (`ascend_deployer/utils.py:297-332`)

```c
LOG.info(cmd.center(MAX_LEN, '-'))
for line in output:
    LOG.info(line)
```

**达成路径**

命令执行 -> stdout/stderr -> LOG.info -> install.log

**验证说明**: run_cmd logs command and all output to install.log. If command contains SSH password (from spread_tool SSH commands), password will be logged. Information disclosure vulnerability.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-ZIP-001] path_traversal - extract_zip, extract_tar

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `ascend_deployer/jobs.py:594-621` @ `extract_zip, extract_tar`
**模块**: entry_points

**描述**: jobs.py ResourcePkg.extract_zip() 和 extract_tar() 函数解压文件时，虽然有 CompressedFileCheckUtils 检查，但白名单机制可能允许绕过路径遍历检查。

**漏洞代码** (`ascend_deployer/jobs.py:594-621`)

```c
with ZipFile(file) as z:
    members = z.namelist()
    if filter_rule:
        members = filter_rule(file, members)
    z.extractall(path, members)
```

**达成路径**

下载的 ZIP/TAR 文件 -> CompressedFileCheckUtils.check_compressed_file_valid() -> extract_zip/extract_tar -> extractall

**验证说明**: Zip Slip path traversal potential. extract_zip/extract_tar use extractall() with CompressedFileCheckUtils filter_rule. The filter may prevent path traversal but depends on implementation correctness. Need to verify filter_rule prevents ../ traversal.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-PY-001] code_injection - safe_eval

**严重性**: Medium | **CWE**: CWE-94 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `ascend_deployer/module_utils/inventory_file.py:50-56` @ `safe_eval`
**模块**: module_utils

**描述**: Potential code injection via eval() in StrTool.safe_eval(). User-provided expressions from inventory configuration file are evaluated using eval() with a restricted scope. While regex filtering is applied, the combination of allowed characters (parentheses filtered separately) and available functions (int, str) in scope may still allow expression injection.

**漏洞代码** (`ascend_deployer/module_utils/inventory_file.py:50-56`)

```c
@classmethod
def safe_eval(cls, expr):
    if not re.fullmatch(cls._FURMULA_PATTERN, expr):
        raise ValueError("unsafe expression: {}".format(expr))
    for k in cls._EXCEPTION:
        if k in expr:
            raise ValueError("unsafe expression: {}".format(expr))
    return str(eval(expr, cls._SAFE_EVAL_SCOPE))
```

**达成路径**

inventory_file.py:224 config.read(OLD_FILE_PATH) [SOURCE - File input]
  → inventory_file.py:241 host_item[1] (params from config)
    → inventory_file.py:243 HostParams(params)
      → inventory_file.py:172 StrTool.safe_eval(replaced_str[1:-1])
        → inventory_file.py:56 eval(expr, cls._SAFE_EVAL_SCOPE) [SINK - Code execution]

**验证说明**: eval() with restricted scope and regex filtering. Regex allows quotes but blocks '()' (empty parentheses). Scope has only int/str with __builtins__=None. Mitigations are strong but imperfect - theoretical sandbox escape risk via str.__class__.__bases__ but requires [] which is blocked. Actual exploitability uncertain.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-SEC-EVAL-001] code_injection - safe_eval

**严重性**: Medium | **CWE**: CWE-94 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `ascend_deployer/module_utils/inventory_file.py:50-56` @ `safe_eval`
**模块**: module_utils

**描述**: inventory_file.py safe_eval() 函数使用 eval() 执行表达式，正则过滤允许单引号和双引号，存在潜在的沙箱逃逸风险。虽然限制了 __builtins__，但通过 str.__class__.__mro__ 可能访问底层对象。

**漏洞代码** (`ascend_deployer/module_utils/inventory_file.py:50-56`)

```c
if not re.fullmatch(cls._FURMULA_PATTERN, expr):
    raise ValueError("unsafe expression: {}".format(expr))
return str(eval(expr, cls._SAFE_EVAL_SCOPE))
```

**达成路径**

用户配置文件 -> HostParams.generate_new_params_str_list() -> safe_eval() -> eval()

**验证说明**: Duplicate of VULN-DF-PY-001. safe_eval with regex filtering and scope restriction.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-DF-CROSS-003] code_injection - parse

**严重性**: Medium | **CWE**: CWE-94 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `ascend_deployer/module_utils/inventory_file.py:276-289` @ `parse`
**模块**: cross_module
**跨模块**: module_utils → entry_points

**描述**: Cross-module code injection chain: User expressions from inventory configuration file flow through InventoryFile parsing to HostParams.generate_new_params_str_list() which calls StrTool.safe_eval(). Attackers who control inventory file content can potentially execute arbitrary Python expressions.

**漏洞代码** (`ascend_deployer/module_utils/inventory_file.py:276-289`)

```c
def parse(self):...
    sec_dict = self._parse_hosts()
    self._generate_parsed_inventory_file(sec_dict)
```

**达成路径**

[MODULE: module_utils] inventory_file.py:224 config.read(OLD_FILE_PATH) [SOURCE]
  → [MODULE: module_utils] inventory_file.py:241 host_item[1] params
    → [MODULE: module_utils] HostParams.generate_new_params_str_list()
      → [MODULE: module_utils] StrTool.safe_eval()
        → [MODULE: module_utils] eval(expr, cls._SAFE_EVAL_SCOPE) [SINK]
          → [MODULE: entry_points] jobs.py:155 inventory_file.parse() [CALLER]

**验证说明**: Duplicate of VULN-DF-PY-001. Cross-module eval() chain.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-DF-PY-005] command_injection - install_basic_deps

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `ascend_deployer/library/uncompress_resources.py:69-73` @ `install_basic_deps`
**模块**: library

**描述**: Potential command injection via Ansible run_command with use_unsafe_shell=True. Package path from glob.glob search is concatenated with hardcoded prefix command and executed with shell=True. While pkg_path is derived from glob search, if glob matches a file with shell metacharacters in the name, command injection could occur.

**漏洞代码** (`ascend_deployer/library/uncompress_resources.py:69-73`)

```c
cmd = "{} {}".format(prefix_cmd, pkg_path)
if getpass.getuser() != 'root':
    self.module.fail_json(...)
self.module.run_command(cmd, use_unsafe_shell=True, check_rc=True)
```

**达成路径**

uncompress_resources.py:63 pkg_list = glob.glob(pkg_path) [SOURCE - glob search]
  → uncompress_resources.py:69 cmd = "{} {}".format(prefix_cmd, pkg_path) [PROPAGATION - format]
    → uncompress_resources.py:73 self.module.run_command(cmd, use_unsafe_shell=True) [SINK - shell=True]

**验证说明**: use_unsafe_shell=True (shell=True) in Ansible run_command. Package path from glob.glob. If resources directory compromised with malicious filenames containing shell metacharacters (e.g., 'foo;rm -rf /;.deb'), command injection possible. Requires write access to resources directory first.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: -10 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cross_module | 0 | 1 | 1 | 0 | 2 |
| entry_points | 0 | 0 | 3 | 0 | 3 |
| large_scale_deploy | 0 | 5 | 0 | 0 | 5 |
| library | 0 | 1 | 1 | 0 | 2 |
| module_utils | 0 | 0 | 2 | 0 | 2 |
| **合计** | **0** | **7** | **7** | **0** | **14** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 6 | 42.9% |
| CWE-94 | 3 | 21.4% |
| CWE-522 | 2 | 14.3% |
| CWE-532 | 1 | 7.1% |
| CWE-256 | 1 | 7.1% |
| CWE-22 | 1 | 7.1% |
