# 漏洞扫描报告 — 待确认漏洞

**项目**: vLLM-MindSpore
**扫描时间**: 2026-04-23T18:58:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 11 | 50.0% |
| POSSIBLE | 7 | 31.8% |
| LIKELY | 3 | 13.6% |
| CONFIRMED | 1 | 4.5% |
| **总计** | **22** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Medium | 5 | 50.0% |
| Low | 2 | 20.0% |
| **有效漏洞总计** | **10** | - |
| 误报 (FALSE_POSITIVE) | 11 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-003-MODELEXEC]** Path Traversal (Medium) - `vllm_mindspore/lora/models.py:150` @ `from_local_checkpoint` | 置信度: 55
2. **[VULN-SEC-CMD-001]** command_injection (Medium) - `dashboard/acc.py:23` @ `exec_shell_cmd` | 置信度: 45
3. **[VULN-SEC-CMD-004]** command_injection (Medium) - `dashboard/acc.py:147` @ `aisbench_test` | 置信度: 45
4. **[VULN-SEC-CMD-002]** command_injection (Medium) - `dashboard/acc.py:65` @ `shell_sed_cmd` | 置信度: 40
5. **[VULN-SEC-CMD-003]** command_injection (Medium) - `dashboard/acc.py:105` @ `exec_cmd` | 置信度: 40
6. **[VULN-EXEC-002]** Environment Variable Injection to Remote Actors (Low) - `vllm_mindspore/executor/ray_utils.py:211` @ `core_engine_actor_manager_init` | 置信度: 70
7. **[VULN-EXEC-005]** Sensitive Environment Variable Exposure (Low) - `vllm_mindspore/executor/ray_utils.py:212` @ `core_engine_actor_manager_init` | 置信度: 65
8. **[VULN-ENTRY-001]** Arbitrary Module Execution (HIGH) - `vllm_mindspore/entrypoints/__main__.py:49` @ `__main__` | 置信度: 85
9. **[VULN-ENTRY-002]** Information Disclosure via Error Messages (MEDIUM) - `vllm_mindspore/entrypoints/openai/serving_chat.py:100` @ `chat_completion_stream_generator` | 置信度: 75
10. **[VULN-ENTRY-003]** Improper Input Validation - Tool Call Parameters (MEDIUM) - `vllm_mindspore/entrypoints/openai/tool_parsers/deepseekv3_tool_parser.py:106` @ `extract_tool_calls` | 置信度: 70

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@vllm_mindspore/scripts.py` | cmdline | trusted_admin | CLI入口点，由管理员/用户通过命令行启动服务 | vllm-mindspore命令行主入口 |
| `subprocess.run@vllm_mindspore/entrypoints/__main__.py` | decorator | semi_trusted | 动态执行传入的模块名，模块名来自CLI参数，代码内容来自inspect.getsource | 动态加载执行vLLM入口模块 |
| `safetensors_weights_iterator@vllm_mindspore/model_executor/model_loader/weight_utils.py` | file | semi_trusted | 加载外部模型权重文件，路径由用户指定（--model参数） | 加载safetensors模型权重文件 |
| `exec_shell_cmd@dashboard/acc.py` | cmdline | untrusted_local | 执行shell命令，cmd参数来自函数调用者，用于基准测试 | 执行shell命令（shell=True） |
| `exec_cmd@dashboard/acc.py` | cmdline | untrusted_local | 执行shell命令，shell=True模式 | 执行shell命令 |
| `get_ascend_soc_version@vllm_mindspore/utils.py` | cmdline | internal | 内部函数，执行Python脚本获取设备版本，脚本内容是硬编码的 | 获取Ascend SOC版本 |
| `execute_command@vllm_mindspore/v1/worker/gpu_worker.py` | cmdline | internal | 内部函数，执行系统命令获取NUMA拓扑信息，命令内容硬编码 | 执行系统命令获取NUMA信息 |
| `shell_analyse@vllm_mindspore/v1/worker/profile.py` | cmdline | trusted_admin | 性能分析工具，路径来自环境变量VLLM_TORCH_PROFILER_DIR | 执行MindSpore性能分析 |
| `build_c_ops@setup.py` | cmdline | trusted_admin | 构建脚本，执行cmake命令编译C扩展，仅在安装时运行 | 构建C扩展模块 |

**其他攻击面**:
- CLI接口: vllm-mindspore serve <model> -- 启动推理服务
- 模型权重加载: 用户指定的模型路径或HuggingFace模型ID
- 环境变量: VLLM_MS_MODEL_BACKEND, ASCEND_HOME_PATH等配置
- Dashboard工具: shell命令执行用于基准测试
- OpenAI API兼容接口: 继承自vLLM框架的HTTP入口

---

## 3. Medium 漏洞 (5)

### [VULN-003-MODELEXEC] Path Traversal - from_local_checkpoint

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `vllm_mindspore/lora/models.py:150-154` @ `from_local_checkpoint`
**模块**: model_executor
**跨模块**: model_executor; lora; entrypoints

**描述**: from_local_checkpoint constructs file paths from user-controlled lora_dir parameter without path validation. Uses os.path.join to build paths like adapter_model.safetensors. LoRA path comes from LoRARequest which can be provided by API users.

**漏洞代码** (`vllm_mindspore/lora/models.py:150-154`)

```c
lora_tensor_path = os.path.join(lora_dir, "adapter_model.safetensors") with safetensors.safe_open(lora_tensor_path, framework="np") as f:
```

**达成路径**

API LoRARequest.lora_path -> lora_dir -> os.path.join(lora_dir, filename) -> safetensors.safe_open(path)

**验证说明**: LoRARequest.lora_path IS exposed via API. Attack vector verified: API user -> LoRARequest.lora_path -> from_local_checkpoint -> os.path.join(lora_dir, filename) -> safetensors.safe_open. However, exploitability is LIMITED because code expects specific filenames (adapter_model.safetensors, adapter_model.bin, new_embeddings.safetensors, new_embeddings.bin). Cannot directly read arbitrary files like /etc/passwd - only files matching expected naming patterns.

---

### [VULN-SEC-CMD-001] command_injection - exec_shell_cmd

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `dashboard/acc.py:23-53` @ `exec_shell_cmd`
**模块**: dashboard

**描述**: exec_shell_cmd() 函数使用 shell=True 执行命令，cmd 参数来自调用者且无输入验证。如果 cmd 包含恶意内容（如 shell 元字符），攻击者可执行任意系统命令。该函数被多处调用，包括 process_check() 和 aisbench_test()，影响基准测试工具的安全性。

**漏洞代码** (`dashboard/acc.py:23-53`)

```c
def exec_shell_cmd(cmd, execute_times=1, return_type=True, user_input=None):
    if not isinstance(cmd, str):
        print(f"TypeError: cmd type: {type(cmd)} must be str")
        return False
    for times in range(execute_times):
        sub = subprocess.Popen(args=cmd,
                               shell=True,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               universal_newlines=True)
```

**达成路径**

调用者 → exec_shell_cmd(cmd) → subprocess.Popen(shell=True) → shell 命令执行
trust_level: untrusted_local

**验证说明**: Trust boundary analysis: dashboard module is internal testing tool with trust_level=untrusted_local. No external network entry points. All parameters come from CLI args or hardcoded scripts (run_dashboard.sh). Attack requires local access. Partial mitigations exist in benchmark_to_dashboard.py (validate_args, shlex.split).

**评分明细**: 0: { | 1: r | 2: e | 3: a | 4: c | 5: h | 6: a | 7: b | 8: i | 9: l | 10: i | 11: t | 12: y | 13: : | 14:   | 15: 3 | 16: 0 | 17: , | 18:   | 19: c | 20: o | 21: n | 22: t | 23: r | 24: o | 25: l | 26: l | 27: a | 28: b | 29: i | 30: l | 31: i | 32: t | 33: y | 34: : | 35:   | 36: 4 | 37: 0 | 38: , | 39:   | 40: m | 41: i | 42: t | 43: i | 44: g | 45: a | 46: t | 47: i | 48: o | 49: n | 50: s | 51: : | 52:   | 53: 2 | 54: 0 | 55: , | 56:   | 57: t | 58: r | 59: u | 60: s | 61: t | 62: _ | 63: b | 64: o | 65: u | 66: n | 67: d | 68: a | 69: r | 70: y | 71: : | 72:   | 73: u | 74: n | 75: t | 76: r | 77: u | 78: s | 79: t | 80: e | 81: d | 82: _ | 83: l | 84: o | 85: c | 86: a | 87: l | 88: , | 89:   | 90: e | 91: n | 92: t | 93: r | 94: y | 95: _ | 96: p | 97: o | 98: i | 99: n | 100: t | 101: _ | 102: t | 103: y | 104: p | 105: e | 106: : | 107:   | 108: c | 109: m | 110: d | 111: l | 112: i | 113: n | 114: e | 115: , | 116:   | 117: v | 118: e | 119: t | 120: o | 121: _ | 122: c | 123: h | 124: e | 125: c | 126: k | 127: s | 128: : | 129:   | 130: { | 131: e | 132: x | 133: t | 134: e | 135: r | 136: n | 137: a | 138: l | 139: _ | 140: n | 141: e | 142: t | 143: w | 144: o | 145: r | 146: k | 147: _ | 148: e | 149: n | 150: t | 151: r | 152: y | 153: : | 154:   | 155: f | 156: a | 157: l | 158: s | 159: e | 160: , | 161:   | 162: c | 163: r | 164: o | 165: s | 166: s | 167: _ | 168: m | 169: o | 170: d | 171: u | 172: l | 173: e | 174: _ | 175: c | 176: a | 177: l | 178: l | 179: : | 180:   | 181: f | 182: a | 183: l | 184: s | 185: e | 186: , | 187:   | 188: p | 189: r | 190: o | 191: d | 192: u | 193: c | 194: t | 195: i | 196: o | 197: n | 198: _ | 199: e | 200: x | 201: p | 202: o | 203: s | 204: u | 205: r | 206: e | 207: : | 208:   | 209: f | 210: a | 211: l | 212: s | 213: e | 214: } | 215: }

---

### [VULN-SEC-CMD-004] command_injection - aisbench_test

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `dashboard/acc.py:147-202` @ `aisbench_test`
**模块**: dashboard

**描述**: aisbench_test() 函数拼接多个参数（path、model、host_ip、host_port 等）到 shell 命令字符串。这些参数来自 kwargs，未经安全验证。如果参数包含 shell 元字符，可能导致命令注入。

**漏洞代码** (`dashboard/acc.py:147-202`)

```c
def aisbench_test(aisbench_source, models, datasets, **kwargs):
    path = kwargs.get('path')
    model = kwargs.get('model')
    host_ip = kwargs.get('host_ip', '0.0.0.0')
    ...
    benchmark_cmd = ("unset http_proxy https_proxy;unset USE_TORCH;"
                     f"cd {aisbench_source}/benchmark;"
                     f"ais_bench --models {models} --datasets {datasets} "
                     f"--work-dir={path} --merge-ds --debug "
                     f"> {path}/{datasets}_bench.log 2>&1 &")
    exec_cmd(benchmark_cmd, script_exec_mode="python")
```

**达成路径**

kwargs 参数 → aisbench_test → benchmark_cmd 字符串拼接 → exec_cmd → subprocess.Popen(shell=True)

**验证说明**: kwargs concatenation to benchmark_cmd but risk limited. kwargs come from benchmark_to_dashboard.py run_eval(). model/path from args.model (CLI). validate_args() validates ais_bench_path. No external network entry. Attack requires local CLI manipulation.

**评分明细**: 0: { | 1: r | 2: e | 3: a | 4: c | 5: h | 6: a | 7: b | 8: i | 9: l | 10: i | 11: t | 12: y | 13: : | 14:   | 15: 3 | 16: 0 | 17: , | 18:   | 19: c | 20: o | 21: n | 22: t | 23: r | 24: o | 25: l | 26: l | 27: a | 28: b | 29: i | 30: l | 31: i | 32: t | 33: y | 34: : | 35:   | 36: 4 | 37: 0 | 38: , | 39:   | 40: m | 41: i | 42: t | 43: i | 44: g | 45: a | 46: t | 47: i | 48: o | 49: n | 50: s | 51: : | 52:   | 53: 2 | 54: 0 | 55: , | 56:   | 57: t | 58: r | 59: u | 60: s | 61: t | 62: _ | 63: b | 64: o | 65: u | 66: n | 67: d | 68: a | 69: r | 70: y | 71: : | 72:   | 73: u | 74: n | 75: t | 76: r | 77: u | 78: s | 79: t | 80: e | 81: d | 82: _ | 83: l | 84: o | 85: c | 86: a | 87: l | 88: , | 89:   | 90: e | 91: n | 92: t | 93: r | 94: y | 95: _ | 96: p | 97: o | 98: i | 99: n | 100: t | 101: _ | 102: t | 103: y | 104: p | 105: e | 106: : | 107:   | 108: c | 109: m | 110: d | 111: l | 112: i | 113: n | 114: e | 115: , | 116:   | 117: v | 118: e | 119: t | 120: o | 121: _ | 122: c | 123: h | 124: e | 125: c | 126: k | 127: s | 128: : | 129:   | 130: { | 131: e | 132: x | 133: t | 134: e | 135: r | 136: n | 137: a | 138: l | 139: _ | 140: n | 141: e | 142: t | 143: w | 144: o | 145: r | 146: k | 147: _ | 148: e | 149: n | 150: t | 151: r | 152: y | 153: : | 154:   | 155: f | 156: a | 157: l | 158: s | 159: e | 160: , | 161:   | 162: c | 163: r | 164: o | 165: s | 166: s | 167: _ | 168: m | 169: o | 170: d | 171: u | 172: l | 173: e | 174: _ | 175: c | 176: a | 177: l | 178: l | 179: : | 180:   | 181: f | 182: a | 183: l | 184: s | 185: e | 186: , | 187:   | 188: p | 189: r | 190: o | 191: d | 192: u | 193: c | 194: t | 195: i | 196: o | 197: n | 198: _ | 199: e | 200: x | 201: p | 202: o | 203: s | 204: u | 205: r | 206: e | 207: : | 208:   | 209: f | 210: a | 211: l | 212: s | 213: e | 214: } | 215: }

---

### [VULN-SEC-CMD-002] command_injection - shell_sed_cmd

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `dashboard/acc.py:65-81` @ `shell_sed_cmd`
**模块**: dashboard

**描述**: shell_sed_cmd() 函数拼接 path、old_list、new_list、file 参数到 sed 命令字符串，然后通过 get_status_cmd() 执行。参数未经安全验证，如果包含 shell 元字符（如 ;、|、$ 等），可能导致命令注入。

**漏洞代码** (`dashboard/acc.py:65-81`)

```c
def shell_sed_cmd(path, old_list, new_list, file, mark_flag=False):
    for i in range(len(old_list)):
        if mark_flag:
            cmd = (f"cd {path};sed -i "s#{old_list[i]}#"
                   f"{new_list[i]}#g" {file}")
        else:
            cmd = (f"cd {path};sed -i 's#{old_list[i]}#"
                   f"{new_list[i]}#g' {file}")
        get_status_cmd(cmd)
```

**达成路径**

path/old_list/new_list/file → shell_sed_cmd → cmd 字符串拼接 → get_status_cmd → subprocess.getstatusoutput

**验证说明**: Parameter concatenation exists but risk limited. Called only within aisbench_test(). old_list/new_list are hardcoded patterns. path comes from aisbench_source (CLI parameter). No external input path. Attack requires local access to modify scripts.

**评分明细**: 0: { | 1: r | 2: e | 3: a | 4: c | 5: h | 6: a | 7: b | 8: i | 9: l | 10: i | 11: t | 12: y | 13: : | 14:   | 15: 2 | 16: 5 | 17: , | 18:   | 19: c | 20: o | 21: n | 22: t | 23: r | 24: o | 25: l | 26: l | 27: a | 28: b | 29: i | 30: l | 31: i | 32: t | 33: y | 34: : | 35:   | 36: 3 | 37: 5 | 38: , | 39:   | 40: m | 41: i | 42: t | 43: i | 44: g | 45: a | 46: t | 47: i | 48: o | 49: n | 50: s | 51: : | 52:   | 53: 1 | 54: 5 | 55: , | 56:   | 57: t | 58: r | 59: u | 60: s | 61: t | 62: _ | 63: b | 64: o | 65: u | 66: n | 67: d | 68: a | 69: r | 70: y | 71: : | 72:   | 73: u | 74: n | 75: t | 76: r | 77: u | 78: s | 79: t | 80: e | 81: d | 82: _ | 83: l | 84: o | 85: c | 86: a | 87: l | 88: , | 89:   | 90: e | 91: n | 92: t | 93: r | 94: y | 95: _ | 96: p | 97: o | 98: i | 99: n | 100: t | 101: _ | 102: t | 103: y | 104: p | 105: e | 106: : | 107:   | 108: i | 109: n | 110: t | 111: e | 112: r | 113: n | 114: a | 115: l | 116: , | 117:   | 118: v | 119: e | 120: t | 121: o | 122: _ | 123: c | 124: h | 125: e | 126: c | 127: k | 128: s | 129: : | 130:   | 131: { | 132: e | 133: x | 134: t | 135: e | 136: r | 137: n | 138: a | 139: l | 140: _ | 141: n | 142: e | 143: t | 144: w | 145: o | 146: r | 147: k | 148: _ | 149: e | 150: n | 151: t | 152: r | 153: y | 154: : | 155:   | 156: f | 157: a | 158: l | 159: s | 160: e | 161: , | 162:   | 163: c | 164: r | 165: o | 166: s | 167: s | 168: _ | 169: m | 170: o | 171: d | 172: u | 173: l | 174: e | 175: _ | 176: c | 177: a | 178: l | 179: l | 180: : | 181:   | 182: f | 183: a | 184: l | 185: s | 186: e | 187: , | 188:   | 189: p | 190: r | 191: o | 192: d | 193: u | 194: c | 195: t | 196: i | 197: o | 198: n | 199: _ | 200: e | 201: x | 202: p | 203: o | 204: s | 205: u | 206: r | 207: e | 208: : | 209:   | 210: f | 211: a | 212: l | 213: s | 214: e | 215: } | 216: }

---

### [VULN-SEC-CMD-003] command_injection - exec_cmd

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `dashboard/acc.py:105-123` @ `exec_cmd`
**模块**: dashboard

**描述**: exec_cmd() 函数使用 shell=True 执行命令，cmd 参数来自调用者。虽然仅检查类型，但没有验证内容安全性。如果 cmd 包含恶意 shell 命令，可导致任意命令执行。

**漏洞代码** (`dashboard/acc.py:105-123`)

```c
def exec_cmd(*args, **kwargs):
    cmd = args[0]
    ...
    else:
        sub = subprocess.Popen(args=cmd, shell=True)
```

**达成路径**

调用者 → exec_cmd(cmd) → subprocess.Popen(shell=True)

**验证说明**: shell=True used but risk limited. Only called within aisbench_test(). benchmark_cmd is hardcoded template + kwargs parameters. kwargs come from CLI args. No external network exposure. Attack requires local CLI manipulation.

**评分明细**: 0: { | 1: r | 2: e | 3: a | 4: c | 5: h | 6: a | 7: b | 8: i | 9: l | 10: i | 11: t | 12: y | 13: : | 14:   | 15: 2 | 16: 5 | 17: , | 18:   | 19: c | 20: o | 21: n | 22: t | 23: r | 24: o | 25: l | 26: l | 27: a | 28: b | 29: i | 30: l | 31: i | 32: t | 33: y | 34: : | 35:   | 36: 3 | 37: 5 | 38: , | 39:   | 40: m | 41: i | 42: t | 43: i | 44: g | 45: a | 46: t | 47: i | 48: o | 49: n | 50: s | 51: : | 52:   | 53: 1 | 54: 5 | 55: , | 56:   | 57: t | 58: r | 59: u | 60: s | 61: t | 62: _ | 63: b | 64: o | 65: u | 66: n | 67: d | 68: a | 69: r | 70: y | 71: : | 72:   | 73: u | 74: n | 75: t | 76: r | 77: u | 78: s | 79: t | 80: e | 81: d | 82: _ | 83: l | 84: o | 85: c | 86: a | 87: l | 88: , | 89:   | 90: e | 91: n | 92: t | 93: r | 94: y | 95: _ | 96: p | 97: o | 98: i | 99: n | 100: t | 101: _ | 102: t | 103: y | 104: p | 105: e | 106: : | 107:   | 108: i | 109: n | 110: t | 111: e | 112: r | 113: n | 114: a | 115: l | 116: , | 117:   | 118: v | 119: e | 120: t | 121: o | 122: _ | 123: c | 124: h | 125: e | 126: c | 127: k | 128: s | 129: : | 130:   | 131: { | 132: e | 133: x | 134: t | 135: e | 136: r | 137: n | 138: a | 139: l | 140: _ | 141: n | 142: e | 143: t | 144: w | 145: o | 146: r | 147: k | 148: _ | 149: e | 150: n | 151: t | 152: r | 153: y | 154: : | 155:   | 156: f | 157: a | 158: l | 159: s | 160: e | 161: , | 162:   | 163: c | 164: r | 165: o | 166: s | 167: s | 168: _ | 169: m | 170: o | 171: d | 172: u | 173: l | 174: e | 175: _ | 176: c | 177: a | 178: l | 179: l | 180: : | 181:   | 182: f | 183: a | 184: l | 185: s | 186: e | 187: , | 188:   | 189: p | 190: r | 191: o | 192: d | 193: u | 194: c | 195: t | 196: i | 197: o | 198: n | 199: _ | 200: e | 201: x | 202: p | 203: o | 204: s | 205: u | 206: r | 207: e | 208: : | 209:   | 210: f | 211: a | 212: l | 213: s | 214: e | 215: } | 216: }

---

## 4. Low 漏洞 (2)

### [VULN-EXEC-002] Environment Variable Injection to Remote Actors - core_engine_actor_manager_init

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-918 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `vllm_mindspore/executor/ray_utils.py:211-219` @ `core_engine_actor_manager_init`
**模块**: executor
**跨模块**: executor,v1.worker,ray_distributed_executor

**描述**: Environment variables from os.environ are copied to remote Ray actors via RuntimeEnv without sanitization. This could expose sensitive secrets (API keys, passwords, tokens) to potentially untrusted remote workers. The get_env_vars_to_copy() function determines which vars to copy, and they are passed directly to Ray runtime environment.

**漏洞代码** (`vllm_mindspore/executor/ray_utils.py:211-219`)

```c
env_vars_list = get_env_vars_to_copy(destination="DPEngineCoreActor")\nself.env_vars_dict = {\n    name: os.environ[name]\n    for name in env_vars_list if name in os.environ\n}\nruntime_env = RuntimeEnv(env_vars=self.env_vars_dict | _RAY_NOSET_ASCEND_ENV)
```

**达成路径**

get_env_vars_to_copy() → os.environ[name] → RuntimeEnv() → ray.remote().options(runtime_env=...) → remote actor execution

**验证说明**: get_env_vars_to_copy uses whitelist approach (VLLM_, LMCACHE_, NCCL_, UCX_, HF_, HUGGING_FACE_ prefixes). Not blind copy of os.environ. However, VLLM_ prefixed vars could contain secrets if users set them. Risk reduced but not eliminated.

**评分明细**: factors: [object Object]

---

### [VULN-EXEC-005] Sensitive Environment Variable Exposure - core_engine_actor_manager_init

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-200 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `vllm_mindspore/executor/ray_utils.py:212-215` @ `core_engine_actor_manager_init`
**模块**: executor
**跨模块**: executor,v1.worker,ray_distributed_executor

**描述**: Environment variables from os.environ are passed to remote Ray actors without filtering for sensitive values. Variables like API keys, database credentials, or authentication tokens could be leaked to remote workers that may be on different hosts or operated by different entities.

**漏洞代码** (`vllm_mindspore/executor/ray_utils.py:212-215`)

```c
self.env_vars_dict = {\n    name: os.environ[name]\n    for name in env_vars_list if name in os.environ\n}
```

**达成路径**

os.environ → env_vars_dict → RuntimeEnv() → remote actor environment

**验证说明**: Same analysis as VULN-EXEC-002. Environment variables filtered through whitelist but VLLM_ prefixed vars could still expose sensitive data to remote workers. Lower confidence due to overlap with VULN-EXEC-002.

**评分明细**: factors: [object Object]

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| dashboard | 0 | 0 | 4 | 0 | 4 |
| entrypoints | 0 | 0 | 0 | 0 | 0 |
| executor | 0 | 0 | 0 | 2 | 2 |
| model_executor | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **0** | **5** | **2** | **7** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 4 | 40.0% |
| CWE-94 | 1 | 10.0% |
| CWE-918 | 1 | 10.0% |
| CWE-22 | 1 | 10.0% |
| CWE-209 | 1 | 10.0% |
| CWE-200 | 1 | 10.0% |
| CWE-20 | 1 | 10.0% |
