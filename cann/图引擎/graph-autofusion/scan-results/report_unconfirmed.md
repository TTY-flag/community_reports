# 漏洞扫描报告 — 待确认漏洞

**项目**: graph-autofusion
**扫描时间**: 2026-04-22T00:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本次扫描共识别出 **8 个待确认漏洞**（LIKELY + POSSIBLE），其中 **3 个为高置信度漏洞 (LIKELY)**，需要重点关注。

### 核心风险分析

所有 3 个 LIKELY 漏洞均位于 **软件包安装脚本** (`scripts/package/common/sh/`)，属于同一攻击面：
- **攻击入口**: 用户通过命令行执行安装/升级/卸载操作
- **攻击向量**: 安装命令参数中注入 shell 元字符
- **攻击后果**: 可能实现任意命令执行，获取系统权限

**风险等级**: 中-高风险（取决于脚本执行权限）

### 关键发现

| 漏洞ID | 类型 | 严重性 | 置信度 | 核心问题 |
|--------|------|--------|--------|----------|
| VULN-SEC-EVAL-003 | 命令注入 | High | 75 | eval 直接处理用户提供的 custom_options |
| VULN-SEC-EVAL-001 | 命令注入 | High | 65 | eval 处理日志消息，消息来源于命令行参数 |
| VULN-SEC-EXEC-001 | 代码注入 | Medium | 65 | 动态执行函数名参数，缺乏白名单验证 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 7 | 46.7% |
| POSSIBLE | 5 | 33.3% |
| LIKELY | 3 | 20.0% |
| **总计** | **15** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 2 | 25.0% |
| Medium | 4 | 50.0% |
| Low | 2 | 25.0% |
| **有效漏洞总计** | **8** | - |
| 误报 (FALSE_POSITIVE) | 7 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-EVAL-003]** command_injection (High) - `scripts/package/common/sh/install_common_parser.sh:1312` @ `expand_custom_options` | 置信度: 75
2. **[VULN-SEC-EVAL-001]** command_injection (High) - `scripts/package/common/sh/common_func.inc:49` @ `_comm_compose_log_msg` | 置信度: 65
3. **[VULN-SEC-EXEC-001]** code_injection (Medium) - `scripts/package/common/sh/common_func.inc:717` @ `process_pre_check` | 置信度: 65
4. **[VULN-PY-PATH-001]** path_traversal (Medium) - `super_kernel/src/jit/superkernel/super_kernel_op_infos.py:123` @ `__init__` | 置信度: 55
5. **[VULN-SEC-ELF-001]** buffer_over-read (Medium) - `super_kernel/src/aot/sk_common.cpp:43` @ `BuildFuncSymbolTable` | 置信度: 50
6. **[VULN-SEC-EVAL-002]** command_injection (Medium) - `scripts/package/common/sh/common_func.inc:265` @ `comm_get_install_param` | 置信度: 50
7. **[VULN-CPP-ENV-001]** input_validation (Low) - `super_kernel/src/aot/sk_task_builder.cpp:1551` @ `GenEntryInfo` | 置信度: 50
8. **[VULN-CPP-OPT-001]** input_validation (Low) - `super_kernel/src/aot/sk_options_manager.cpp:74` @ `ParseAndValidateExtendOptionValue` | 置信度: 45

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `aclskOptimize@super_kernel/src/aot/super_kernel.cpp` | rpc | semi_trusted | C API 入口，接收 aclmdlRI 模型句柄和 aclskOptions 配置选项，来自上层 AI 框架调用 | 执行 Super Kernel 图优化，处理模型图并生成融合内核 |
| `aclskScopeBegin@super_kernel/src/aot/super_kernel.cpp` | rpc | semi_trusted | C API 入口，接收 scopeName 字符串参数和 stream 句柄 | 开始一个 Super Kernel scope 区域 |
| `aclskScopeEnd@super_kernel/src/aot/super_kernel.cpp` | rpc | semi_trusted | C API 入口，接收 scopeName 字符串参数和 stream 句柄 | 结束一个 Super Kernel scope 区域 |
| `GenEntryInfo@super_kernel/src/aot/sk_task_builder.cpp` | env | semi_trusted | 读取环境变量 ASCEND_PROF_SK_ON 和 ASCEND_SK_OP_TRACE_ON 配置 profiling 功能 | 生成 Super Kernel 入口信息，读取环境变量决定功能模式 |
| `InitSkLogger@super_kernel/src/aot/sk_log.h` | env | semi_trusted | 读取环境变量 ASCEND_OP_COMPILE_SAVE_KERNEL_META 控制日志输出 | 初始化日志系统，由环境变量控制 |
| `TryGenerateConstantFuncHandle@super_kernel/src/aot/sk_constant_codegen.cpp` | env | semi_trusted | 读取环境变量 SK_CONSTANT 控制常量代码生成 | 尝试生成常量化代码，由环境变量控制 |
| `SkEventRecorder::Init@super_kernel/src/aot/sk_event_recorder.cpp` | env | semi_trusted | 读取环境变量 ENV_SK_EVENT_RECORD 控制 profiling | 初始化事件记录器，由环境变量控制 |
| `gen_super_kernel_file@super_kernel/src/jit/superkernel/super_kernel.py` | decorator | semi_trusted | Python JIT 编译入口，接收 super_operator 配置对象，生成内核源文件 | 生成 Super Kernel 源代码文件 |
| `parse_super_kernel_options@super_kernel/src/jit/superkernel/super_kernel_option_parse.py` | cmdline | semi_trusted | 解析用户提供的编译选项字符串 | 解析 Super Kernel 编译选项 |
| `compile_sub_kernel@super_kernel/src/jit/superkernel/super_kernel_op_infos.py` | rpc | semi_trusted | 调用 subprocess.run 执行编译命令 | 编译子内核，调用外部编译工具 |
| `execute_packaging@scripts/package/package.py` | cmdline | semi_trusted | 打包脚本入口，接收命令行参数 | 执行软件包打包流程 |

**其他攻击面**:
- ACL C API: aclskOptimize/aclskScopeBegin/aclskScopeEnd - 接收模型句柄和配置选项
- 环境变量: ASCEND_PROF_SK_ON, ASCEND_SK_OP_TRACE_ON, ASCEND_OP_COMPILE_SAVE_KERNEL_META, SK_CONSTANT
- 配置选项结构体: aclskOptions (包含字符串列表和扩展选项)
- Python 编译选项: 通过 parse_super_kernel_options 解析的选项字符串
- 编译工具链调用: subprocess.run 执行的 ar/编译命令
- Shell 脚本 eval: 多处使用 eval 执行命令和赋值
- ELF 二进制解析: sk_common.cpp 直接解析内核二进制文件
- 文件写入: 内核源文件、日志文件、JSON dump 文件

---

## 3. High 漏洞 (2)

### [VULN-SEC-EVAL-003] command_injection - expand_custom_options

**严重性**: High | **CWE**: CWE-78 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `scripts/package/common/sh/install_common_parser.sh:1312-1317` @ `expand_custom_options`
**模块**: Package Scripts

**描述**: eval usage with custom_options that could be user-controlled. The expand_custom_options function uses eval to assign transformed custom_options to an output variable. Custom options passed during package installation could potentially contain shell metacharacters that would be interpreted by eval.

**漏洞代码** (`scripts/package/common/sh/install_common_parser.sh:1312-1317`)

```c
expand_custom_options() {
    local _outvar="$1"
    local _custom_options="$2"
    eval "${_outvar}=\"$(echo "${_custom_options}" | tr "," " ")\""
}
```

**达成路径**

custom_options parameter (user input) -> tr transformation -> eval assignment -> potential command injection

**验证说明**: eval usage with custom_options from user installation command. custom_options parameter passes through tr but shell metacharacters like $(), backticks, semicolons are not filtered. Attacker controlling installation options could inject commands.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

#### 深度分析

**调用链追踪**:

```
用户安装命令 → package_custom_script() (第1320行) → expand_custom_options() (第1337行调用)
                                    ↓
                         custom_options参数直接来自用户命令行
```

在 `package_custom_script()` 函数（第1320-1344行）中：
- `custom_options` 参数（第1324行）直接传递给 `expand_custom_options`
- 第1337行调用：`expand_custom_options "custom_options" "${custom_options}"`
- 第1340行执行：`${curpath}/${script_name} ${install_options} ${custom_options}`

**漏洞触发条件**:

1. 用户执行安装命令时传入恶意选项，例如：
   ```bash
   ./install.sh --custom-options="option1,option2,$(malicious_cmd)"
   ./install.sh --custom-options="test;rm -rf /"
   ./install.sh --custom-options="a\`whoami\`b"
   ```

2. `tr "," " "` 仅替换逗号，不过滤 shell 元字符：
   - `$()` - 命令替换
   - 反引号 `` ` `` - 命令替换
   - `;` - 命令分隔符
   - `|` - 管道
   - `&` - 后台执行

**实际风险评估**:

- **攻击门槛**: 中等 - 需要能够执行安装脚本
- **影响范围**: 高 - 若脚本以 root 权限执行，可完全控制系统
- **置信度**: 75/100 - 高，因为无任何输入验证

**POC 示例**:

```bash
# 假设攻击者可控制安装命令参数
./install.sh --custom-options="opt1,$(id > /tmp/pwned)"
# eval 执行时，$(id > /tmp/pwned) 将被执行
```

---

### [VULN-SEC-EVAL-001] command_injection - _comm_compose_log_msg

**严重性**: High | **CWE**: CWE-78 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor, dataflow-scanner

**位置**: `scripts/package/common/sh/common_func.inc:49-62` @ `_comm_compose_log_msg`
**模块**: Package Scripts

**描述**: eval command injection vulnerability in log message composition. The function _comm_compose_log_msg uses eval to assign the composed log message to an output variable. The _msg parameter contains log message content that could potentially contain shell metacharacters (backticks, $(), etc.) that would be interpreted by eval. If an attacker can control the log message content, they could execute arbitrary commands.

**漏洞代码** (`scripts/package/common/sh/common_func.inc:49-62`)

```c
_comm_compose_log_msg() {
    local _outvar="$1"
    local _log_type="$2"
    local _msg="$3"
    local _result
    _result="[${LOG_PKG_NAME}] [${_cur_date}] [${_log_type}]: ${_msg}"
    eval "${_outvar}=\"${_result}\""
}
```

**达成路径**

User-controlled log message -> _msg parameter -> string concatenation to _result -> eval execution -> potential command injection

**验证说明**: eval usage in log composition. _msg parameter flows from user installation parameters via comm_log_operation(all_parma). Shell metacharacters could be executed if attacker controls installation command arguments. Mitigation: None found. Attack path exists but requires specific call chain.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

#### 深度分析

**调用链追踪**:

```
用户安装命令 → comm_start_log(all_parma) (第342-349行)
                    ↓
              comm_log "INFO" "InputParams:$all_parma" (第347行)
                    ↓
              _comm_compose_log_msg "log_msg" "$log_type" "$msg" (第86行)
                    ↓
              eval "${_outvar}=\"${_result}\"" (第61行)
```

**关键数据流**:

1. `comm_start_log()` 函数（第342行）接收所有命令行参数 `$@`
2. 第347行调用 `comm_log "INFO" "InputParams:$all_parma"`，将完整参数传递给日志
3. `comm_echo()` 函数（第81-88行）调用 `_comm_compose_log_msg`
4. `_comm_compose_log_msg` 第61行使用 `eval` 将 `_result` 赋值给输出变量

**漏洞触发条件**:

用户执行安装命令时，命令行参数被直接记录到日志：
```bash
./install.sh --param1="value" --param2="$(malicious_cmd)"
./install.sh --param1="test`whoami`test"
./install.sh --install-path="/path;rm -rf /"
```

**实际风险评估**:

- **攻击门槛**: 中等 - 需要执行安装脚本的权限
- **影响范围**: 中等 - 日志函数广泛使用，但攻击路径较长
- **置信度**: 65/100 - 中高，调用链存在但需要特定场景

**缓解因素**:

- 日志消息通常来自内部函数调用，而非直接用户输入
- `comm_log_operation()` (第136行) 直接写入文件，不使用 eval
- 需要追踪具体哪些调用点会将用户参数传入 `_msg`

**相关代码模式**:

同一文件中存在类似的 eval 使用模式（第152行 `comm_set_install_for_all_mod`），表明这是代码库的通用模式，需要系统性修复。

---

## 4. Medium 漏洞 (4)

### [VULN-SEC-EXEC-001] code_injection - process_pre_check

**严重性**: Medium | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `scripts/package/common/sh/common_func.inc:717-740` @ `process_pre_check`
**模块**: Package Scripts

**描述**: Dynamic function execution via variable. The function process_pre_check executes a function name passed as parameter (pre_check_func) using variable expansion. If the function name parameter is controlled by an attacker, they could execute arbitrary shell functions. While this appears to be used for legitimate package pre-check functions, the lack of validation on the function name is a security concern.

**漏洞代码** (`scripts/package/common/sh/common_func.inc:717-740`)

```c
process_pre_check() {
    local pkg_name="$1"
    local pre_check_func="$2"
    ${pre_check_func}
    ret=$?
}
```

**达成路径**

pre_check_func parameter -> variable expansion execution -> arbitrary function execution potential

**验证说明**: Dynamic function execution via ${pre_check_func}. Function name passed as parameter could execute arbitrary function if caller provides malicious name. Requires tracing call chain to determine if function names are predefined or user-controlled.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

#### 深度分析

**代码模式分析**:

```bash
# 第721-740行完整代码
process_pre_check() {
    local pkg_name="$1"
    local pre_check_func="$2"
    local standalone="$3"

    log "INFO" "${pkg_name} do pre_check started."
    ${pre_check_func}    # ← 直接执行函数名变量
    ret=$?
    # ...
}
```

**漏洞本质**:

- 第727行 `${pre_check_func}` 直接展开并执行函数名
- 无任何验证机制检查函数名是否在允许列表中
- 若攻击者控制 `pre_check_func` 参数，可执行任意已定义函数

**潜在攻击场景**:

1. **直接攻击**: 若调用者来自用户可控路径
   ```bash
   process_pre_check "pkg" "malicious_func; rm -rf /"
   # 或者
   process_pre_check "pkg" "$(cat /etc/passwd)"
   ```

2. **间接攻击**: 函数名包含特殊字符
   ```bash
   process_pre_check "pkg" "ls -la; id"
   # 执行: ls -la; id（两条命令）
   ```

**缓解因素分析**:

- **调用链追溯**: 需要确认 `process_pre_check` 的所有调用点
- **预期用途**: 设计意图是执行包特定的预检查函数（如 `pre_check_npu`）
- **攻击门槛**: 较高 - 需要控制函数名参数的来源

**风险评估**:

- **置信度**: 65/100 - 中高，漏洞存在但调用链不明确
- **建议**: 添加函数名白名单验证，或追踪所有调用点确认参数来源

---

### [VULN-PY-PATH-001] path_traversal - __init__

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `super_kernel/src/jit/superkernel/super_kernel_op_infos.py:123-125` @ `__init__`
**模块**: JIT Compiler

**描述**: Potential path traversal in file path construction. kernel_file uses os.path.join with kernel_name which could contain path traversal sequences if not validated.

**漏洞代码** (`super_kernel/src/jit/superkernel/super_kernel_op_infos.py:123-125`)

```c
self.kernel_file = os.path.realpath(os.path.join(kernel_meta_dir, self.kernel_name + file_name_tag))
```

**达成路径**

super_kernel_name (constructor param) → self.kernel_name → os.path.join → os.path.realpath

**验证说明**: os.path.join with kernel_name could allow path traversal if kernel_name contains ../ sequences. os.path.realpath provides partial mitigation by normalizing path. Needs explicit validation for ../ sequences.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-ELF-001] buffer_over-read - BuildFuncSymbolTable

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `super_kernel/src/aot/sk_common.cpp:43-63` @ `BuildFuncSymbolTable`
**模块**: AOT Core Engine

**描述**: ELF binary parsing lacks bounds checking. The function BuildFuncSymbolTable reads ELF header offsets (e_shoff, sh_offset) directly from memory without validating that these offsets are within the provided binSize boundary. A malformed or malicious ELF binary could specify arbitrary offsets, causing the function to read outside the allocated buffer boundary. This could lead to information disclosure or memory corruption.

**漏洞代码** (`super_kernel/src/aot/sk_common.cpp:43-63`)

```c
const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(binAddr);
uint64_t shCnt = ehdr->e_shnum;
const Elf64_Shdr* shHdr = reinterpret_cast<const Elf64_Shdr*>(binAddr + ehdr->e_shoff);
const char* shStrTbl = binAddr + shHdr[ehdr->e_shstrndx].sh_offset;
```

**达成路径**

binAddr (external input from kernel binaries) -> Elf64_Ehdr reinterpret_cast -> e_shoff offset read without bounds check -> potential out-of-bounds memory access

**验证说明**: ELF header parsing reads e_shoff, sh_offset directly without binSize boundary validation. Malformed ELF could cause out-of-bounds read. Data source is compiled binaries - attacker needs to control compile process or binary content.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -15 | cross_file: 0

---

### [VULN-SEC-EVAL-002] command_injection - comm_get_install_param

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `scripts/package/common/sh/common_func.inc:265-277` @ `comm_get_install_param`
**模块**: Package Scripts

**描述**: eval usage with content from install.info file. The function reads values from install.info file using grep and assigns them via eval. If the install.info file is tampered or contains malicious content with shell metacharacters, this could lead to command injection when the content is evaluated.

**漏洞代码** (`scripts/package/common/sh/common_func.inc:265-277`)

```c
comm_get_install_param() {
    local _outvar="$1"
    local _file="$2"
    local _key="$3"
    _result="$(grep -i "^${_key}=" "${_file}" | cut -d"=" -f2-)"
    eval "${_outvar}=\"${_result}\""
}
```

**达成路径**

install.info file content -> grep extraction -> _result -> eval assignment -> potential injection

**验证说明**: eval reads values from install.info file. Attack requires attacker to write malicious content to install.info file. Lower risk as file is typically created by installation scripts. Attack surface is limited.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -15 | cross_file: 0

---

## 5. Low 漏洞 (2)

### [VULN-CPP-ENV-001] input_validation - GenEntryInfo

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `super_kernel/src/aot/sk_task_builder.cpp:1551-1556` @ `GenEntryInfo`
**模块**: AOT Core Engine

**描述**: Environment variable ASCEND_PROF_SK_ON and ASCEND_SK_OP_TRACE_ON read without validation. getenv() reads env vars that could be manipulated by attacker. No length validation.

**漏洞代码** (`super_kernel/src/aot/sk_task_builder.cpp:1551-1556`)

```c
const char* profilingEnv = std::getenv("ASCEND_PROF_SK_ON");
bool enableProfiling = (profilingEnv != nullptr && std::string(profilingEnv) != "0");
```

**达成路径**

std::getenv("ASCEND_PROF_SK_ON") [SOURCE] → profilingEnv → std::string(profilingEnv) != "0"

**验证说明**: getenv reads ASCEND_PROF_SK_ON and ASCEND_SK_OP_TRACE_ON for profiling switches. Values only checked for 0/1 comparison. No sensitive operation. Low risk - environment variable only controls feature toggle, no security impact.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: -20 | cross_file: 0

---

### [VULN-CPP-OPT-001] input_validation - ParseAndValidateExtendOptionValue

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `super_kernel/src/aot/sk_options_manager.cpp:74-136` @ `ParseAndValidateExtendOptionValue`
**模块**: AOT Core Engine

**描述**: Extended option value parsing with length limit of 1024 bytes. The ParseAndValidateExtendOptionValue function parses raw option values with a length check, but the validation of individual tokens (IsValidExtendOptionToken) only checks alphanumeric characters, underscore, dash, dot, and slash. While there's validation, complex injection patterns could potentially bypass the checks.

**漏洞代码** (`super_kernel/src/aot/sk_options_manager.cpp:74-136`)

```c
bool ParseAndValidateExtendOptionValue(const char* rawValue, const std::string& optionName,
    std::unordered_map<std::string, std::vector<std::string>>& parsedValue)
{
    if (rawValue == nullptr) {
        SK_LOGW("OptionName:%s, raw extend value is nullptr", optionName.c_str());
        return false;
    }

    const std::string input(rawValue);
    if (input.size() > kMaxExtendOptionLength) {
        SK_LOGW("OptionName:%s, raw extend value is too long: %zu", optionName.c_str(), input.size());
        return false;
    }
```

**达成路径**

option->optExtend.value (from aclskOptions struct, external input) [SOURCE] → ParseAndValidateExtendOptionValue [validation]

**验证说明**: ParseAndValidateExtendOptionValue has COMPREHENSIVE input validation: 1024 byte length limit, IsValidExtendOptionToken only allows alnum/_/-/./slash. This effectively blocks injection characters. Vulnerability is mitigated by validation.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| AOT Core Engine | 0 | 0 | 1 | 2 | 3 |
| JIT Compiler | 0 | 0 | 1 | 0 | 1 |
| Package Scripts | 0 | 2 | 2 | 0 | 4 |
| **合计** | **0** | **2** | **4** | **2** | **8** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 3 | 37.5% |
| CWE-20 | 2 | 25.0% |
| CWE-94 | 1 | 12.5% |
| CWE-22 | 1 | 12.5% |
| CWE-125 | 1 | 12.5% |

---

## 8. 修复建议

### 8.1 高优先级修复 (LIKELY 漏洞)

#### VULN-SEC-EVAL-003: expand_custom_options 命令注入

**修复方案**: 替换 `eval` 为安全的变量赋值方式

```bash
# 当前代码（不安全）
expand_custom_options() {
    local _outvar="$1"
    local _custom_options="$2"
    eval "${_outvar}=\"$(echo "${_custom_options}" | tr "," " ")\""
}

# 修复方案 1: 使用 printf 替代 eval
expand_custom_options() {
    local _outvar="$1"
    local _custom_options="$2"
    local _result
    _result=$(printf '%s' "${_custom_options}" | tr "," " ")
    printf -v "${_outvar}" '%s' "${_result}"
}

# 修复方案 2: 直接赋值（若调用方式允许）
# 修改调用方 package_custom_script，直接处理
custom_options=$(printf '%s' "${custom_options}" | tr "," " ")
```

**验证建议**: 使用 shell 静态分析工具（如 shellcheck）扫描所有 eval 使用点

---

#### VULN-SEC-EVAL-001: _comm_compose_log_msg 命令注入

**修复方案**: 移除 eval，使用直接赋值

```bash
# 当前代码（不安全）
_comm_compose_log_msg() {
    local _outvar="$1"
    local _log_type="$2"
    local _msg="$3"
    local _result
    _result="[${LOG_PKG_NAME}] [${_cur_date}] [${_log_type}]: ${_msg}"
    eval "${_outvar}=\"${_result}\""
}

# 修复方案: 使用 printf -v 或改变调用方式
_comm_compose_log_msg() {
    local _outvar="$1"
    local _log_type="$2"
    local _msg="$3"
    local _result
    _result="[${LOG_PKG_NAME}] [${_cur_date}] [${_log_type}]: ${_msg}"
    # 方案 1: printf -v (bash 4.0+)
    printf -v "${_outvar}" '%s' "${_result}"
    
    # 方案 2: 直接返回字符串（修改调用方式）
    # return via echo, caller uses result=$(...)
}

# 方案 3: 修改调用方式 - 更安全的重构
comm_echo() {
    local log_type="$1"
    local msg="$2"
    local log_msg
    log_msg="[${LOG_PKG_NAME}] [$(date +'%Y-%m-%d %H:%M:%S')] [${log_type}]: ${msg}"
    _comm_echo_log_msg "$log_type" "$log_msg"
}
```

**额外建议**: 对日志消息中的特殊字符进行转义处理

---

#### VULN-SEC-EXEC-001: process_pre_check 动态函数执行

**修复方案**: 添加函数名白名单验证

```bash
# 当前代码（不安全）
process_pre_check() {
    local pkg_name="$1"
    local pre_check_func="$2"
    ${pre_check_func}
}

# 修复方案: 添加白名单验证
process_pre_check() {
    local pkg_name="$1"
    local pre_check_func="$2"
    local standalone="$3"
    
    # 定义允许的预检查函数白名单
    local allowed_funcs="pre_check_npu pre_check_cuda pre_check_common pre_check_driver"
    
    # 验证函数名是否在白名单中
    if ! echo "${allowed_funcs}" | grep -qw "${pre_check_func}"; then
        log "ERROR" "Invalid pre_check function: ${pre_check_func}"
        return 1
    fi
    
    log "INFO" "${pkg_name} do pre_check started."
    "${pre_check_func}"
    ret=$?
    # ...
}

# 方案 2: 使用 case 语句验证
case "${pre_check_func}" in
    pre_check_npu|pre_check_cuda|pre_check_common|pre_check_driver)
        "${pre_check_func}"
        ;;
    *)
        log "ERROR" "Invalid pre_check function: ${pre_check_func}"
        return 1
        ;;
esac
```

---

### 8.2 中优先级修复 (POSSIBLE 漏洞)

#### VULN-PY-PATH-001: 路径遍历

**修复方案**: 添加路径规范化验证

```python
# 当前代码
self.kernel_file = os.path.realpath(os.path.join(kernel_meta_dir, self.kernel_name + file_name_tag))

# 修复方案: 显式检查路径遍历
import os

kernel_file = os.path.join(kernel_meta_dir, self.kernel_name + file_name_tag)
kernel_file_real = os.path.realpath(kernel_file)

# 验证最终路径仍在预期目录内
if not kernel_file_real.startswith(os.path.realpath(kernel_meta_dir)):
    raise ValueError(f"Path traversal detected in kernel_name: {self.kernel_name}")

self.kernel_file = kernel_file_real
```

---

#### VULN-SEC-ELF-001: ELF 解析边界检查

**修复方案**: 添加偏移量边界验证

```cpp
// 当前代码
const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(binAddr);
const Elf64_Shdr* shHdr = reinterpret_cast<const Elf64_Shdr*>(binAddr + ehdr->e_shoff);

// 修复方案: 添加边界检查
bool BuildFuncSymbolTable(const char* binAddr, uint64_t binSize, ...) {
    // 验证 ELF header 在边界内
    if (binSize < sizeof(Elf64_Ehdr)) {
        return false;
    }
    
    const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(binAddr);
    
    // 验证 section header offset 在边界内
    if (ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr) > binSize) {
        return false;
    }
    
    const Elf64_Shdr* shHdr = reinterpret_cast<const Elf64_Shdr*>(binAddr + ehdr->e_shoff);
    
    // 验证 string table offset 在边界内
    if (ehdr->e_shstrndx >= ehdr->e_shnum ||
        shHdr[ehdr->e_shstrndx].sh_offset + shHdr[ehdr->e_shstrndx].sh_size > binSize) {
        return false;
    }
    
    // ... 继续处理
}
```

---

### 8.3 系统性改进建议

#### 代码模式审查

1. **Shell 脚本 eval 审查**: 使用 `shellcheck` 扫描所有 `.sh` 和 `.inc` 文件
   ```bash
   shellcheck -s bash scripts/package/common/sh/*.sh scripts/package/common/sh/*.inc
   ```

2. **Python subprocess 审查**: 确保所有 `subprocess.run` 使用参数列表而非字符串
   ```python
   # 安全方式
   subprocess.run(['ar', '-x', archive_path], check=True)
   
   # 不安全方式（避免）
   subprocess.run(f'ar -x {archive_path}', shell=True)
   ```

3. **C++ 输入验证**: 对所有外部数据源添加长度和边界检查

#### 安全开发规范

1. **禁止 eval**: Shell 脚本中应避免使用 `eval`，使用 `printf -v` 或重构代码
2. **白名单验证**: 所有动态执行的函数名/命令必须验证白名单
3. **路径安全**: 所有文件路径操作需验证最终路径在预期目录内
4. **边界检查**: 所有二进制解析（ELF、自定义格式）需添加边界验证

---

## 9. 整体安全评估结论

### 扫描统计

| 类别 | 数量 | 说明 |
|------|------|------|
| 已确认漏洞 | 0 | 无 |
| 高置信度漏洞 | 3 | 需立即关注 |
| 潜在漏洞 | 5 | 建议评估风险 |
| 误报排除 | 7 | 已过滤 |

### 安全风险评级: **中等**

**主要风险来源**:
- Shell 安装脚本中的 `eval` 使用（命令注入风险）
- 缺乏输入验证的动态函数执行
- ELF 二进制解析缺乏边界检查

**风险评估**:
- 若安装脚本以 root 权限执行，命令注入可导致系统完全沦陷
- ELF 解析漏洞可能导致信息泄露或内存损坏
- 环境变量读取仅影响功能开关，风险较低

**改进方向**:
1. 系统性替换 Shell 脚本中的 `eval` 使用
2. 为所有动态执行添加白名单验证
3. 为二进制解析添加边界检查
4. 建立 CI/CD 安全扫描流程

---

**报告生成时间**: 2026-04-22
**扫描工具**: 多 Agent 漏洞扫描系统 (DataFlow Scanner + Security Auditor)
**验证方式**: 人工审核 + 自动评分
