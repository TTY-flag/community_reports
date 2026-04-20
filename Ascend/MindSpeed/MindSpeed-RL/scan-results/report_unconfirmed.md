# 漏洞扫描报告 — 待确认漏洞

**项目**: MindSpeed-RL
**扫描时间**: 2026-04-20T10:09:36.569Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 7 | 43.8% |
| CONFIRMED | 5 | 31.3% |
| POSSIBLE | 3 | 18.8% |
| FALSE_POSITIVE | 1 | 6.3% |
| **总计** | **16** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 4 | 40.0% |
| Medium | 6 | 60.0% |
| **有效漏洞总计** | **10** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-001]** trust_remote_code_injection (High) - `mindspeed_rl/workers/rule_reward.py:45` @ `initialize` | 置信度: 75
2. **[VULN-DF-006]** code_injection (High) - `cli/train_ppo.py:420` @ `gpt_model_provider` | 置信度: 70
3. **[VULN-DF-007]** code_injection (High) - `cli/train_grpo.py:389` @ `gpt_model_provider` | 置信度: 70
4. **[VULN-DF-008]** code_injection (High) - `cli/train_dpo.py:175` @ `gpt_model_provider` | 置信度: 70
5. **[VULN-DF-002]** code_execution_api (Medium) - `mindspeed_rl/tools/sandbox_fusion_tool.py:55` @ `execute_code` | 置信度: 60
6. **[VULN-DF-010]** code_execution_api (Medium) - `mindspeed_rl/tools/retool.py:18` @ `execute` | 置信度: 60
7. **[VULN-SEC-SB-001]** external_code_execution (Medium) - `mindspeed_rl/tools/sandbox_fusion_tool.py:45` @ `execute` | 置信度: 60
8. **[VULN-DF-003]** ssrf (Medium) - `mindspeed_rl/tools/utils/tool_utils.py:512` @ `call_search_api` | 置信度: 55
9. **[VULN-DF-004]** ssrf (Medium) - `mindspeed_rl/tools/utils/tool_utils.py:322` @ `call_sandbox_api` | 置信度: 55
10. **[VULN-DF-005]** path_traversal (Medium) - `mindspeed_rl/datasets/templates.py:398` @ `register_custom_template` | 置信度: 50

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `undefined@undefined` | cli | - | - | PPO training entry point using Hydra configuration |
| `undefined@undefined` | cli | - | - | DAPO training entry point using Hydra configuration |
| `undefined@undefined` | cli | - | - | GRPO training entry point using Hydra configuration |
| `undefined@undefined` | cli | - | - | DPO training entry point using Hydra configuration |
| `undefined@undefined` | cli | - | - | Data preprocessing entry point for dataset preparation |
| `undefined@undefined` | cli | - | - | EPLB map generation for expert parallel load balancing |
| `undefined@undefined` | config | - | - | YAML configuration files loaded by Hydra for training parameters |
| `undefined@undefined` | api | - | - | Remote sandbox API for code execution |
| `undefined@undefined` | api | - | - | Remote search/retrieval API for knowledge retrieval |
| `undefined@undefined` | file | - | - | External dataset loading from local files or HuggingFace |
| `undefined@undefined` | file | - | - | Path resolution for input/output/tokenizer files |
| `undefined@undefined` | file | - | - | Custom template registration from JSON files |
| `undefined@undefined` | network | - | - | ZMQ-based distributed communication for training |


---

## 3. High 漏洞 (4)

### [VULN-DF-001] trust_remote_code_injection - initialize

**严重性**: High | **CWE**: CWE-949 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mindspeed_rl/workers/rule_reward.py:45-46` @ `initialize`
**模块**: mindspeed_rl.workers

**描述**: AutoTokenizer.from_pretrained with trust_remote_code=True allows loading tokenizer code from remote sources, which can execute arbitrary code. The tokenizer_name_or_path comes from configuration files and trust_remote_code parameter is configurable.

**漏洞代码** (`mindspeed_rl/workers/rule_reward.py:45-46`)

```c
self.hf_tokenizer = AutoTokenizer.from_pretrained(megatron_config.tokenizer_name_or_path,
                                                  trust_remote_code=trust_remote_code)
```

**达成路径**

configs/*.yaml -> megatron_config.tokenizer_name_or_path -> AutoTokenizer.from_pretrained [SINK]

**验证说明**: Verified: trust_remote_code parameter passed to AutoTokenizer.from_pretrained. If set to True, remote tokenizer code could be executed. Requires config file access to exploit.

---

### [VULN-DF-006] code_injection - gpt_model_provider

**严重性**: High | **CWE**: CWE-94 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cli/train_ppo.py:420-421` @ `gpt_model_provider`
**模块**: cli

**描述**: Megatron spec parameter from configuration is passed to import_module() which can import arbitrary Python modules. This allows an attacker with config file access to execute arbitrary code by specifying malicious module paths.

**漏洞代码** (`cli/train_ppo.py:420-421`)

```c
if args.spec is not None:
    transformer_layer_spec = import_module(args.spec)
```

**达成路径**

configs/*.yaml -> args.spec -> import_module(args.spec) [SINK]

**验证说明**: Verified: args.spec from YAML config passed to import_module() without validation. Allows arbitrary module import. Requires config file modification.

---

### [VULN-DF-007] code_injection - gpt_model_provider

**严重性**: High | **CWE**: CWE-94 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cli/train_grpo.py:389-390` @ `gpt_model_provider`
**模块**: cli

**描述**: Megatron spec parameter from configuration is passed to import_module() which can import arbitrary Python modules. Similar vulnerability in train_grpo.py.

**漏洞代码** (`cli/train_grpo.py:389-390`)

```c
if args.spec is not None:
    transformer_layer_spec = import_module(args.spec)
```

**达成路径**

configs/*.yaml -> args.spec -> import_module(args.spec) [SINK]

**验证说明**: Verified: Same pattern as DF-006. import_module(args.spec) in train_grpo.py.

---

### [VULN-DF-008] code_injection - gpt_model_provider

**严重性**: High | **CWE**: CWE-94 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cli/train_dpo.py:175-176` @ `gpt_model_provider`
**模块**: cli

**描述**: Megatron spec parameter from configuration is passed to import_module() which can import arbitrary Python modules. Similar vulnerability in train_dpo.py.

**漏洞代码** (`cli/train_dpo.py:175-176`)

```c
if args.spec is not None:
    transformer_layer_spec = import_module(args.spec)
```

**达成路径**

configs/*.yaml -> args.spec -> import_module(args.spec) [SINK]

**验证说明**: Verified: Same pattern as DF-006. import_module(args.spec) in train_dpo.py.

---

## 4. Medium 漏洞 (6)

### [VULN-DF-002] code_execution_api - execute_code

**严重性**: Medium | **CWE**: CWE-77 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mindspeed_rl/tools/sandbox_fusion_tool.py:55-64` @ `execute_code`
**模块**: mindspeed_rl.tools
**跨模块**: mindspeed_rl.tools → mindspeed_rl.tools.utils

**描述**: User-generated code (from model output) is sent to remote sandbox API for execution. While sandboxed, improper sandbox configuration could lead to code execution vulnerabilities. The code parameter comes from model-generated output via execute_code method.

**漏洞代码** (`mindspeed_rl/tools/sandbox_fusion_tool.py:55-64`)

```c
def execute_code(self, instance_id, code, timeout=30, language="python"):
    result_status, metadata = process_single_case(
        0, None, None, self.sandbox_fusion_url, code, timeout, self.memory_limit_mb, language
    )
```

**达成路径**

model_output -> parameters.code -> execute_code -> process_single_case -> call_sandbox_api -> remote_sandbox_execution [SINK]

**验证说明**: Verified: Code execution API sends model-generated code to external sandbox. Sandbox server isolation mitigates direct RCE but URL must be trusted.

---

### [VULN-DF-010] code_execution_api - execute

**严重性**: Medium | **CWE**: CWE-77 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mindspeed_rl/tools/retool.py:18-39` @ `execute`
**模块**: mindspeed_rl.tools
**跨模块**: mindspeed_rl.tools → mindspeed_rl.tools.utils

**描述**: ReTool class inherits from SandboxFusionTool and processes code from user/model output, modifying it before sending to sandbox for execution. The code modification pattern could potentially bypass sandbox restrictions.

**漏洞代码** (`mindspeed_rl/tools/retool.py:18-39`)

```c
def execute(self, instance_id: str, parameters: dict[str, Any], **kwargs) -> tuple[str, float, dict]:
    code = parameters["code"]
    matches = self.code_pattern.findall(code)
    if matches:
        code = matches[0].strip()
    lines = code.split("\n")
    for i, line in reversed(list(enumerate(lines))):
        if line == "":
            continue
        if not lines[i].startswith("print"):
            lines[i] = f"print({line})"
        break
    code = "\n".join(lines)
    result = ray.get(self.execution_pool.execute.remote(self.execute_code, instance_id, code, timeout, language))
```

**达成路径**

model_output -> parameters.code -> execute -> execute_code -> sandbox_execution [SINK]

**验证说明**: Verified: ReTool modifies and executes code via sandbox API. Similar to DF-002, sandbox isolation mitigates direct RCE.

---

### [VULN-SEC-SB-001] external_code_execution - execute

**严重性**: Medium | **CWE**: CWE-94 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `mindspeed_rl/tools/sandbox_fusion_tool.py:45-53` @ `execute`
**模块**: mindspeed_rl.tools

**描述**: SandboxFusionTool executes arbitrary code via remote sandbox API. The code parameter is taken from user input (parameters['code']) and sent to an external sandbox server for execution. While this is by design for training purposes, the sandbox_fusion_url must be properly configured and trusted. If the URL is misconfigured or points to a malicious server, arbitrary code could be executed.

**漏洞代码** (`mindspeed_rl/tools/sandbox_fusion_tool.py:45-53`)

```c
code = parameters.get("code", "")
...
result = ray.get(self.execution_pool.execute.remote(self.execute_code, instance_id, code, timeout, language))
```

**达成路径**

parameters['code'] (from model/tool call) → execute() → execute_code() → process_single_case() → call_sandbox_api() → HTTP POST to sandbox_fusion_url → remote code execution

**验证说明**: Verified: SandboxFusionTool executes code from parameters via external sandbox. Sandbox isolation mitigates but requires trusted URL.

---

### [VULN-DF-003] ssrf - call_search_api

**严重性**: Medium | **CWE**: CWE-918 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mindspeed_rl/tools/utils/tool_utils.py:512-598` @ `call_search_api`
**模块**: mindspeed_rl.tools

**描述**: Search API URL (retrieval_service_url) comes from configuration files and is used in HTTP requests without validation. An attacker who can modify configuration could make requests to arbitrary internal or external services.

**漏洞代码** (`mindspeed_rl/tools/utils/tool_utils.py:512-598`)

```c
response = requests.post(
    retrieval_service_url,
    headers=headers,
    json=payload,
    timeout=timeout,
)
```

**达成路径**

configs/tools/*.yaml -> retrieval_service_url -> requests.post [SINK]

**验证说明**: Verified: retrieval_service_url from config used in HTTP POST. SSRF possible if config is modified. Limited attack surface.

---

### [VULN-DF-004] ssrf - call_sandbox_api

**严重性**: Medium | **CWE**: CWE-918 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mindspeed_rl/tools/utils/tool_utils.py:322-416` @ `call_sandbox_api`
**模块**: mindspeed_rl.tools

**描述**: Sandbox API URL (sandbox_fusion_url) comes from configuration files and is used in HTTP requests without validation. An attacker who can modify configuration could make requests to arbitrary internal or external services.

**漏洞代码** (`mindspeed_rl/tools/utils/tool_utils.py:322-416`)

```c
response = requests.post(
    sandbox_fusion_url,
    headers=headers,
    data=payload,
    timeout=request_timeout,
)
```

**达成路径**

configs/tools/*.yaml -> sandbox_fusion_url -> requests.post [SINK]

**验证说明**: Verified: sandbox_fusion_url from config used in HTTP POST. SSRF possible if config is modified. Limited attack surface.

---

### [VULN-DF-005] path_traversal - register_custom_template

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `mindspeed_rl/datasets/templates.py:398-406` @ `register_custom_template`
**模块**: mindspeed_rl.datasets

**描述**: Custom template JSON file path (json_file_path/prompt_type_path) comes from configuration and is used to open arbitrary files. The regex validation only checks path format, not path traversal. Absolute paths like /etc/passwd would pass validation.

**漏洞代码** (`mindspeed_rl/datasets/templates.py:398-406`)

```c
if not bool(re.match(r'(?:(?:/|\.{1,2}/|[^/\0]+/)(?:[^/\0]+/)*[^/\0]*|\.{1,2})', json_file_path)):
    raise ValueError(f"Invalid Path: {json_file_path}...)
with open(json_file_path, 'r') as file:
    config = json.load(file)
```

**达成路径**

configs/*.yaml -> prompt_type_path -> register_custom_template -> open(json_file_path) [SINK]

**验证说明**: Verified: json_file_path from config used in open(). Regex validation exists but allows absolute paths. Limited path traversal.

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cli | 0 | 3 | 0 | 0 | 3 |
| mindspeed_rl.datasets | 0 | 0 | 1 | 0 | 1 |
| mindspeed_rl.tools | 0 | 0 | 5 | 0 | 5 |
| mindspeed_rl.workers | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **4** | **6** | **0** | **10** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-94 | 4 | 40.0% |
| CWE-918 | 2 | 20.0% |
| CWE-77 | 2 | 20.0% |
| CWE-949 | 1 | 10.0% |
| CWE-22 | 1 | 10.0% |
