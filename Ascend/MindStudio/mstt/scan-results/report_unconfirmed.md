# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio Training Tools (mstt)  
**扫描时间**: 2026-04-21T12:00:00Z  
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞  

---

## 执行摘要

本报告汇总了扫描发现但未完全确认的漏洞（LIKELY 和 POSSIBLE 状态）。这些漏洞存在一定风险，但由于存在缓解措施或触发条件较为复杂，未能达到 CONFIRMED 的置信度阈值。

### 状态说明

| 状态 | 置信度范围 | 说明 |
|------|------------|------|
| LIKELY | 60-79 | 存在缓解措施，但缓解可能被绕过 |
| POSSIBLE | 40-59 | 需进一步调查，风险较低或触发条件复杂 |

### 关键风险类型分布

| 风险类型 | 数量 | 主要模块 |
|----------|------|----------|
| eval() 代码注入 | 3 | msprobe |
| 命令注入 | 3 | msprobe, affinity_cpu_bind |
| 不安全反序列化 | 2 | msprobe, msprobe_ccsrc |
| 文件写入无认证 | 1 | tb_graph_ascend |
| 动态库劫持 | 2 | msprobe_ccsrc |

### 建议处理方式

**LIKELY 类别**: 建议在安全评审中评估缓解措施的有效性，考虑是否需要加固

**POSSIBLE 类别**: 建议在后续迭代中审查，或作为代码质量改进项

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 14 | 51.9% |
| POSSIBLE | 6 | 22.2% |
| LIKELY | 6 | 22.2% |
| CONFIRMED | 1 | 3.7% |
| **总计** | **27** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Medium | 6 | 50.0% |
| Low | 6 | 50.0% |
| **有效漏洞总计** | **12** | - |
| 误报 (FALSE_POSITIVE) | 14 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-FILE-004]** file_write_without_auth (Medium) - `plugins/tensorboard-plugins/tb_graph_ascend/server/app/views/graph_views.py:255` @ `save_data` | 置信度: 65
2. **[VULN-DF-PYTHON-msprobe-001]** code_injection (Medium) - `debug/accuracy_tools/msprobe/pytorch/hook_module/wrap_aten.py:72` @ `forward` | 置信度: 65
3. **[VULN-DF-PYTHON-msprobe-001-EVAL]** eval_code_injection (Medium) - `debug/accuracy_tools/msprobe/pytorch/hook_module/wrap_aten.py:69` @ `AtenOPTemplate.forward` | 置信度: 65
4. **[VULN-DF-PYTHON-msprobe-002-DTYPE]** eval_code_injection (Medium) - `debug/accuracy_tools/msprobe/pytorch/api_accuracy_checker/generate_op_script/operator_replication.template:265` @ `generate_numerical_tensor` | 置信度: 65
5. **[VULN-DF-CPP-msprobe_ccsrc-002]** dlopen_library_hijacking (Medium) - `debug/accuracy_tools/msprobe/ccsrc/third_party/ACL/AclApi.cpp:71` @ `LoadAclApi` | 置信度: 60
6. **[VULN-DF-PYTHON-msprobe-003-PICKLE]** unsafe_deserialization (Medium) - `debug/accuracy_tools/msprobe/core/config_check/ckpt_compare/ckpt_comparator.py:49` @ `compare_checkpoints` | 置信度: 55
7. **[VULN-SEC-DLL-005]** unsafe_library_loading (Low) - `debug/accuracy_tools/msprobe/ccsrc/third_party/ACL/AclApi.cpp:71` @ `LoadAclApi` | 置信度: 60
8. **[VULN-DF-PYTHON-msprobe-004-SUBPROC]** command_injection (Low) - `debug/accuracy_tools/msprobe/pytorch/api_accuracy_checker/run_ut/multi_run_ut.py:110` @ `run_parallel_ut` | 置信度: 55
9. **[VULN-DF-PYTHON-affinity-002]** command_injection (Low) - `profiler/affinity_cpu_bind/bind_core.py:88` @ `get_running_pid_on_npu` | 置信度: 50
10. **[VULN-DF-PYTHON-affinity-003]** command_injection (Low) - `profiler/affinity_cpu_bind/bind_core.py:228` @ `_get_npu_affinity` | 置信度: 50

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@debug/accuracy_tools/msprobe/msprobe.py` | cmdline | untrusted_local | 命令行入口，接收用户提供的框架参数、路径参数等，通过sys.argv直接索引解析 | msprobe CLI主入口，支持compare/run_ut/api_precision_compare等子命令 |
| `msprof_analyze_cli@profiler/msprof_analyze/cli/entrance.py` | cmdline | untrusted_local | Click框架CLI入口，接收profiling路径、输出路径等参数，可被本地用户控制 | msprof-analyze CLI主入口，支持advisor/compare/cluster子命令 |
| `__parse_command@msfmktransplt/src/ms_fmk_transplt/ms_fmk_transplt.py` | cmdline | untrusted_local | argparse CLI入口，接收input/output路径和version参数 | PyTorch GPU到NPU迁移工具CLI入口 |
| `args_parse@profiler/affinity_cpu_bind/bind_core.py` | cmdline | untrusted_local | argparse CLI，接收--application参数直接执行用户命令，存在命令注入风险 | CPU绑核工具CLI，可通过--application参数启动任意进程 |
| `main@profiler/tinker/tinker_auto_parallel.py` | cmdline | untrusted_local | argparse CLI入口，接收模型配置和profiling路径 | Tinker自动并行策略寻优工具入口 |
| `get_plugin_apps@plugins/tensorboard-plugins/tb_graph_ascend/server/plugin.py` | web_route | untrusted_network | TensorBoard HTTP插件，创建19个REST API端点，默认绑定localhost但可通过--bind_all暴露到网络 | 模型可视化TensorBoard插件HTTP端点 |
| `load_meta_dir@plugins/tensorboard-plugins/tb_graph_ascend/server/app/views/graph_views.py` | web_route | untrusted_network | GET端点，扫描logdir目录返回.vis文件列表 | HTTP GET端点 - 加载元数据目录 |
| `load_graph_data@plugins/tensorboard-plugins/tb_graph_ascend/server/app/views/graph_views.py` | web_route | untrusted_network | GET端点，接收run/tag/type查询参数加载图数据 | HTTP GET端点 - 加载图可视化数据 |
| `load_graph_config_info@plugins/tensorboard-plugins/tb_graph_ascend/server/app/views/graph_views.py` | web_route | untrusted_network | POST端点，接收JSON payload解析metaData | HTTP POST端点 - 加载图配置信息 |
| `save_data@plugins/tensorboard-plugins/tb_graph_ascend/server/app/views/graph_views.py` | web_route | untrusted_network | POST端点，可写入数据到服务器文件系统 | HTTP POST端点 - 保存图数据（文件写入操作） |
| `forward@debug/accuracy_tools/msprobe/pytorch/hook_module/wrap_aten.py` | decorator | semi_trusted | eval()执行动态PyTorch算子，self.op来自YAML配置文件 | 动态算子执行 - eval代码注入风险点 |
| `generate_code@debug/accuracy_tools/msprobe/mindspore/api_accuracy_checker/generate_op_script/operator_replication.template` | file | semi_trusted | eval(data_dtype)从配置数据中解析dtype字符串 | 模板代码生成中的eval()调用 |
| `get_rank_id@debug/accuracy_tools/msprobe/ccsrc/base/Environment.cpp` | env | untrusted_local | 读取RANK_ID环境变量 | C++环境变量读取 - RANK_ID |
| `get_log_level@debug/accuracy_tools/msprobe/ccsrc/base/ErrorInfosManager.cpp` | env | untrusted_local | 读取MSPROBE_LOG_LEVEL环境变量 | C++环境变量读取 - MSPROBE_LOG_LEVEL |
| `load_acl_library@debug/accuracy_tools/msprobe/ccsrc/third_party/ACL/AclApi.cpp` | file | semi_trusted | dlopen加载libascendcl.so等动态库 | 动态库加载 - ACL API |
| `parse_config@debug/accuracy_tools/msprobe/ccsrc/base/DebuggerConfig.cpp` | file | semi_trusted | 解析外部JSON配置文件，使用re2正则表达式 | JSON配置文件解析 |
| `requeue_job@msfmktransplt/test/msFmkTransplt/resources/net/barlowtwins_amp/main.py` | env | untrusted_local | os.system()执行包含环境变量SLURM_JOB_ID的shell命令 | os.system命令注入 - SLURM环境变量 |

**其他攻击面**:
- CLI接口: msprobe/mprof-analyze/msfmktransplt/tinker/bind_core (命令行参数注入风险)
- HTTP接口: TensorBoard插件graph_ascend (19个REST端点，无认证)
- 文件输入: JSON/YAML配置文件解析、NPY数据加载
- 环境变量: RANK_ID/MSPROBE_LOG_LEVEL/SLURM_JOB_ID
- 动态库加载: dlopen加载libascendcl.so/libmindspore_ascend.so
- Python C扩展: ccsrc模块与Python交互边界
- 代码注入: eval()在wrap_aten.py和operator_replication.template
- 进程执行: subprocess.Popen/run在bind_core.py/profile_space.py

---

## 3. Medium 漏洞 (6)

### [VULN-SEC-FILE-004] file_write_without_auth - save_data

**严重性**: Medium | **CWE**: CWE-73 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `plugins/tensorboard-plugins/tb_graph_ascend/server/app/views/graph_views.py:255-260` @ `save_data`
**模块**: tb_graph_ascend

**描述**: TensorBoard 插件的 /saveData 端点允许通过 HTTP POST 写入数据到服务器文件系统。虽然有完整的安全校验（路径验证、符号链接检查、属主检查、权限验证），但端点无认证机制。当 TensorBoard 使用 --bind_all 参数暴露到网络时，远程用户可以触发文件写入操作。

**漏洞代码** (`plugins/tensorboard-plugins/tb_graph_ascend/server/app/views/graph_views.py:255-260`)

```c
data = GraphUtils.safe_json_loads(request.get_data().decode('utf-8'), {})
meta_data = data.get('metaData')
strategy = GraphView._get_strategy(meta_data)
save_result = strategy.save_data(meta_data)
```

**达成路径**

HTTP POST request → request.get_data() → GraphUtils.safe_json_loads() → strategy.save_data() → 文件写入

**验证说明**: TensorBoard /saveData endpoint allows file write without authentication. Path validation mitigations present (is_relative_to, safe_check_load_file_path). Risk when --bind_all enabled.

**评分明细**: base: 30 | reachability: 30 | controllability: 5 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-PYTHON-msprobe-001] code_injection - forward

**严重性**: Medium（原评估: Critical → 验证后: Medium） | **CWE**: CWE-95 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner, security-auditor

**位置**: `debug/accuracy_tools/msprobe/pytorch/hook_module/wrap_aten.py:72-73` @ `forward`
**模块**: msprobe

**描述**: eval() is used to dynamically execute PyTorch operators. The self.op value comes from YAML configuration file loaded via load_yaml(). If an attacker can control the YAML file, they can inject arbitrary code via the operator name. Although the code checks if self.op is in white_aten_ops or npu_custom_grad_functions, this is a whitelist bypass risk if the whitelist is incorrectly configured.

**漏洞代码** (`debug/accuracy_tools/msprobe/pytorch/hook_module/wrap_aten.py:72-73`)

```c
if self.op in white_aten_ops:
    return eval(f"torch.ops.aten.{self.op}")(*args, **kwargs)
```

**达成路径**

YAML config -> self.op -> eval(f"torch.ops.aten.{self.op}") -> code execution

**验证说明**: eval() with self.op from YAML config. Whitelist check (self.op in white_aten_ops) mitigates but YAML file modification could bypass. Trust level: semi_trusted. Mitigation: whitelist validation present.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-PYTHON-msprobe-001-EVAL] eval_code_injection - AtenOPTemplate.forward

**严重性**: Medium（原评估: Critical → 验证后: Medium） | **CWE**: CWE-95 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `debug/accuracy_tools/msprobe/pytorch/hook_module/wrap_aten.py:69-73` @ `AtenOPTemplate.forward`
**模块**: msprobe

**描述**: Dynamic code execution via eval() with user-controllable operation name. The self.op string parameter can originate from YAML configuration or runtime API calls, directly interpolated into eval() expression without sanitization. If attacker controls op name (through modified YAML config or malicious API registration), arbitrary Python code can be executed.

**漏洞代码** (`debug/accuracy_tools/msprobe/pytorch/hook_module/wrap_aten.py:69-73`)

```c
if isinstance(self.op, str):
    if self.op in npu_custom_grad_functions:
        return npu_custom_grad_functions[self.op](*args, **kwargs)
    if self.op in white_aten_ops:
        return eval(f"torch.ops.aten.{self.op}")(*args, **kwargs)
```

**达成路径**

support_wrap_ops.yaml -> load_yaml() -> ops.get('white_aten_ops', []) -> AtenOPTemplate.__init__(op, ...) -> self.op -> forward() -> eval(f"torch.ops.aten.{self.op}")

**验证说明**: Same vulnerability as VULN-DF-PYTHON-msprobe-001. eval() with whitelist mitigation. Duplicate concern.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-PYTHON-msprobe-002-DTYPE] eval_code_injection - generate_numerical_tensor

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-95 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `debug/accuracy_tools/msprobe/pytorch/api_accuracy_checker/generate_op_script/operator_replication.template:265-272` @ `generate_numerical_tensor`
**模块**: msprobe

**描述**: The data_dtype string variable derived from JSON configuration files passed directly to eval() to convert dtype strings to PyTorch dtype objects. Attacker controlling JSON config could inject arbitrary code through dtype field (e.g., dtype = "__import__('os').system('id')").

**漏洞代码** (`debug/accuracy_tools/msprobe/pytorch/api_accuracy_checker/generate_op_script/operator_replication.template:265-272`)

```c
def generate_numerical_tensor(low, high, shape, data_dtype):
    if data_dtype in TORCH_FLOAT_TYPE:
        scale = high - low
        rand01 = torch.rand(shape, dtype=eval(data_dtype))
        tensor = rand01 * scale + low
    elif data_dtype in TORCH_INT_TYPE:
        low, high = int(low), int(high)
        tensor = torch.randint(low, high + 1, shape, dtype=eval(data_dtype))
```

**达成路径**

User JSON config -> load_json() -> info.get('dtype') -> data_dtype -> generate_random_tensor() -> generate_numerical_tensor() -> eval(data_dtype)

**验证说明**: eval(data_dtype) with whitelist checks: if data_dtype in TORCH_FLOAT_TYPE/TORCH_INT_TYPE. Whitelist mitigates but JSON config modification could bypass.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-CPP-msprobe_ccsrc-002] dlopen_library_hijacking - LoadAclApi

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-426 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `debug/accuracy_tools/msprobe/ccsrc/third_party/ACL/AclApi.cpp:71-102` @ `LoadAclApi`
**模块**: msprobe_ccsrc

**描述**: dlopen loads libraries using RTLD_LAZY | RTLD_NOLOAD. While library names are hardcoded constants, the search path depends on LD_LIBRARY_PATH. An attacker who controls LD_LIBRARY_PATH can redirect library loading to malicious shared objects.

**漏洞代码** (`debug/accuracy_tools/msprobe/ccsrc/third_party/ACL/AclApi.cpp:71-102`)

```c
hLibAscendcl = dlopen(LIB_ASCEND_CL_NAME, RTLD_LAZY | RTLD_NOLOAD);
void* dumpHandler = dlopen(LIB_ASCEND_DUMP_NAME, RTLD_LAZY | RTLD_NOLOAD);
```

**达成路径**

LD_LIBRARY_PATH (environment) → dlopen search path → libascendcl.so/libascend_dump.so → dlsym loads function pointers → Used throughout AclDumper

**验证说明**: dlopen with RTLD_NOLOAD only checks if library already loaded, not loading from search path. Indirect risk: if library was hijacked elsewhere via LD_LIBRARY_PATH, functions would use hijacked code. Trust level: semi_trusted.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-DF-PYTHON-msprobe-003-PICKLE] unsafe_deserialization - compare_checkpoints

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-502 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `debug/accuracy_tools/msprobe/core/config_check/ckpt_compare/ckpt_comparator.py:49-54` @ `compare_checkpoints`
**模块**: msprobe

**描述**: torch.load with weights_only=False can cause arbitrary code execution via pickle deserialization. PyTorch pickle-based checkpoint files can contain arbitrary code that executes during deserialization.

**漏洞代码** (`debug/accuracy_tools/msprobe/core/config_check/ckpt_compare/ckpt_comparator.py:49-54`)

```c
if not confirm("You are using torch.load with weights_only is False, it may cause arbitrary code "
               "execution. Do it only if you get the file from a trusted source. Input yes to continue, "
               "otherwise exit", False):
    logger.error("Insecure risks found and exit!")
    raise Exception("Insecure risks found and exit!")
```

**达成路径**

User checkpoint files -> load_megatron_weights() -> torch.load(weights_only=False) -> pickle deserialization -> arbitrary code execution

**验证说明**: torch.load with weights_only=False. User confirmation prompt at line 50-54 mitigates risk. Requires user to explicitly accept risk.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

## 4. Low 漏洞 (6)

### [VULN-SEC-DLL-005] unsafe_library_loading - LoadAclApi

**严重性**: Low | **CWE**: CWE-114 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `debug/accuracy_tools/msprobe/ccsrc/third_party/ACL/AclApi.cpp:71-76` @ `LoadAclApi`
**模块**: msprobe_ccsrc

**描述**: AclApi.cpp 使用 dlopen 加载动态库 libascendcl.so。库路径硬编码为常量，使用 RTLD_NOLOAD 标志（仅检查库是否已加载）。但动态库路径依赖于系统库搜索路径（LD_LIBRARY_PATH），可被劫持。建议使用绝对路径加载库。

**漏洞代码** (`debug/accuracy_tools/msprobe/ccsrc/third_party/ACL/AclApi.cpp:71-76`)

```c
hLibAscendcl = dlopen(LIB_ASCEND_CL_NAME, RTLD_LAZY | RTLD_NOLOAD);
if (hLibAscendcl == nullptr) {
    LOG_ERROR(...);
}
```

**达成路径**

常量 LIB_ASCEND_CL_NAME → dlopen() → 动态库加载

**验证说明**: Same as VULN-DF-CPP-msprobe_ccsrc-002. dlopen with RTLD_NOLOAD only checks if library already loaded. Indirect risk via LD_LIBRARY_PATH hijacking elsewhere.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 10

---

### [VULN-DF-PYTHON-msprobe-004-SUBPROC] command_injection - run_parallel_ut

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `debug/accuracy_tools/msprobe/pytorch/api_accuracy_checker/run_ut/multi_run_ut.py:110-154` @ `run_parallel_ut`
**模块**: msprobe

**描述**: subprocess.Popen executes Python scripts with arguments from configuration files. While shell=False mitigates shell injection, command arguments including api_info file paths and output paths come from potentially untrusted JSON configuration.

**漏洞代码** (`debug/accuracy_tools/msprobe/pytorch/api_accuracy_checker/run_ut/multi_run_ut.py:110-154`)

```c
cmd = [
    sys.executable, run_ut_path,
    '-api_info', api_info,
    *(['-o', config.out_path] if config.out_path else []),
    '-d', str(dev_id),
    ...
]
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, bufsize=1, shell=False)
```

**达成路径**

User JSON config -> prepare_config() -> ParallelUTConfig -> create_cmd() -> subprocess.Popen(cmd)

**验证说明**: subprocess.Popen with shell=False mitigates shell injection. Arguments from config files. sys.executable and run_ut_path are safe sources. Config file paths could be manipulated.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-PYTHON-affinity-002] command_injection - get_running_pid_on_npu

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-78 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `profiler/affinity_cpu_bind/bind_core.py:88-91` @ `get_running_pid_on_npu`
**模块**: affinity_cpu_bind

**描述**: PID values extracted from npu-smi command output are NOT validated to be numeric before being used in taskset command. While shell=False prevents direct shell injection, an attacker who can manipulate npu-smi output (via binary replacement, PATH hijacking, or compromised driver) could inject malicious content into the PID field.

**漏洞代码** (`profiler/affinity_cpu_bind/bind_core.py:88-91`)

```c
for value in res:
    if value.startswith('id:'):
        pid = value.split(':')[1]  # NO VALIDATION
        pid_list.append(pid)
```

**达成路径**

npu-smi stdout -> value.split(':')[1] -> pid_list -> taskset command (L147) -> subprocess.run

**验证说明**: PID from npu-smi output not validated as numeric. shell=False prevents shell injection. Attack requires npu-smi binary hijacking (PATH or driver compromise).

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-PYTHON-affinity-003] command_injection - _get_npu_affinity

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-78 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `profiler/affinity_cpu_bind/bind_core.py:228-241` @ `_get_npu_affinity`
**模块**: affinity_cpu_bind

**描述**: CPU affinity values parsed from npu-smi topo output are minimally validated (only checks for '-' presence and split length) but NOT validated to be valid CPU numbers. An attacker controlling npu-smi output could inject malicious strings into the taskset command.

**漏洞代码** (`profiler/affinity_cpu_bind/bind_core.py:228-241`)

```c
for v in res:
    if '-' in v:
        cpus = v.split('-')
        # No validation that cpus are valid numbers
        affinity_cpus.append(cpus[0] + '-' + cpus[1])
```

**达成路径**

npu-smi topo stdout -> cpus values -> affinity_cpus -> npu_affinity_cpu_dict -> taskset command

**验证说明**: CPU affinity from npu-smi topo minimally validated. shell=False prevents shell injection. Attack requires npu-smi binary hijacking.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CPP-msprobe_ccsrc-007] untrusted_deserialization - DumpToDisk

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-502 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `debug/accuracy_tools/msprobe/ccsrc/core/AclDumpDataProcessor.cpp:900-904` @ `DumpToDisk`
**模块**: msprobe_ccsrc

**描述**: ParseFromArray is called with headerSegLen which was read from the external buffer. The protobuf parsing could potentially be exploited if the header segment contains crafted malicious data.

**漏洞代码** (`debug/accuracy_tools/msprobe/ccsrc/core/AclDumpDataProcessor.cpp:900-904`)

```c
if (!dumpData.ParseFromArray(msg + headerSegOffset, headerSegLen)) {
    LOG_ERROR(...);
}
```

**达成路径**

AclDumpChunk::dataBuf → buffer → headerSegLen read at line 405 → ParseFromArray(msg + headerSegOffset, headerSegLen)

**验证说明**: ParseFromArray with headerSegLen. headerSegLen was validated at line 406. Protobuf parsing has inherent security considerations but bounds were validated.

**评分明细**: base: 30 | reachability: 15 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CROSS-001] cross_module_attack_chain - save_data + forward

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-288 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `plugins/tensorboard-plugins/tb_graph_ascend/server/app/views/graph_views.py:255-260` @ `save_data + forward`
**模块**: tb_graph_ascend+msprobe
**跨模块**: tb_graph_ascend → msprobe

**描述**: 跨模块攻击链：TensorBoard 插件无认证 → HTTP 端点暴露 → 文件写入能力。攻击者可通过网络访问 /saveData 端点写入文件，虽然没有认证绕过链，但结合 eval() 潜在风险，如果攻击者能控制 YAML 配置文件并通过网络触发 msprobe 的 forward() 函数，可能实现远程代码执行。

**漏洞代码** (`plugins/tensorboard-plugins/tb_graph_ascend/server/app/views/graph_views.py:255-260`)

```c
HTTP POST /saveData → strategy.save_data() → 文件写入
YAML 配置 → eval() → 代码执行
```

**达成路径**

TensorBoard --bind_all → 网络暴露 → HTTP POST /saveData → 文件写入 → 配置文件篡改 → msprobe eval() → 代码执行

**验证说明**: Speculative attack chain: TensorBoard --bind_all -> file write -> config modification -> msprobe eval(). Each component has mitigations. Requires multiple conditions to be met.

**评分明细**: base: 30 | reachability: 15 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| affinity_cpu_bind | 0 | 0 | 0 | 2 | 2 |
| msprobe | 0 | 0 | 4 | 1 | 5 |
| msprobe_ccsrc | 0 | 0 | 1 | 2 | 3 |
| tb_graph_ascend | 0 | 0 | 1 | 0 | 1 |
| tb_graph_ascend+msprobe | 0 | 0 | 0 | 1 | 1 |
| **合计** | **0** | **0** | **6** | **6** | **12** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-95 | 3 | 25.0% |
| CWE-78 | 3 | 25.0% |
| CWE-502 | 2 | 16.7% |
| CWE-73 | 1 | 8.3% |
| CWE-426 | 1 | 8.3% |
| CWE-288 | 1 | 8.3% |
| CWE-114 | 1 | 8.3% |

---

## 7. 风险评估与建议

### LIKELY 漏洞处理建议

#### eval() 代码注入 (CWE-95)

**涉及漏洞**: VULN-DF-PYTHON-msprobe-001, VULN-DF-PYTHON-msprobe-001-EVAL, VULN-DF-PYTHON-msprobe-002-DTYPE

**现有缓解**: 白名单检查 (`if self.op in white_aten_ops`)

**加固建议**:
1. 使用 `getattr(torch.ops.aten, self.op)` 替代 `eval()` 动态调用
2. 为 YAML/JSON 配置文件添加 checksum 验证
3. 白名单应使用签名验证而非简单字符串匹配

#### TensorBoard 文件写入 (CWE-73)

**涉及漏洞**: VULN-SEC-FILE-004

**现有缓解**: 路径验证（`is_relative_to`, 符号链接检查, 属主检查）

**加固建议**:
1. 为 `/saveData` 端点添加 API Token 认证
2. 使用 `--bind_all` 时显示安全警告
3. 增加写入目录白名单限制

#### 动态库劫持 (CWE-426/CWE-114)

**涉及漏洞**: VULN-DF-CPP-msprobe_ccsrc-002, VULN-SEC-DLL-005

**现有缓解**: `RTLD_NOLOAD` 仅检查已加载库

**加固建议**:
1. 使用绝对路径加载库（如 `/usr/lib/ascend/libascendcl.so`）
2. 在加载前验证库文件完整性（checksum）
3. 记录库加载路径用于审计

### POSSIBLE 漏洞处理建议

#### 不安全反序列化 (CWE-502)

**涉及漏洞**: VULN-DF-PYTHON-msprobe-003-PICKLE, VULN-DF-CPP-msprobe_ccsrc-007

**现有缓解**: 用户确认提示、边界验证

**建议**: 在生产环境中强制使用 `weights_only=True`

#### 命令注入 (CWE-78)

**涉及漏洞**: VULN-DF-PYTHON-msprobe-004-SUBPROC, VULN-DF-PYTHON-affinity-002, VULN-DF-PYTHON-affinity-003

**现有缓解**: `shell=False` 阻止 shell 注入

**建议**: 对外部命令输出进行格式验证（如 PID 必须为数字）

### 跨模块攻击链

**涉及漏洞**: VULN-SEC-CROSS-001

**风险评估**: 该漏洞为推测性攻击链，需要多个条件同时满足：
1. TensorBoard 使用 `--bind_all` 暴露网络
2. 攻击者能通过网络写入配置文件
3. msprobe 加载被篡改的配置执行 `eval()`

**建议**: 分开处理各组件的安全问题，降低组合攻击的可能性

---

## 8. 附录：漏洞处置流程建议

| 阶段 | LIKELY 漏洞 | POSSIBLE 漏洞 |
|------|-------------|---------------|
| 评估 | 安全评审会议讨论 | 代码审查中提及 |
| 决策 | 根据使用场景决定是否加固 | 标记为改进项 |
| 实施 | 下一迭代周期内完成 | 长期改进计划 |
| 验证 | 安全测试验证加固效果 | 功能测试覆盖 |

---

*报告生成时间: 2026-04-21*  
*扫描工具: OpenCode Vulnerability Scanner*
