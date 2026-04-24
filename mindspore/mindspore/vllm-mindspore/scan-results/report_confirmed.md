# 漏洞扫描报告 — 已确认漏洞

**项目**: vLLM-MindSpore
**扫描时间**: 2026-04-23T18:58:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次漏洞扫描覆盖了 vLLM-MindSpore 项目（共 154 个源文件，约 33,000 行代码），该项目是 vLLM 框架在华为 Atlas NPU 上的适配实现。经过严格的多阶段验证流程，从 22 个候选漏洞中确认了 **1 个真实漏洞**（Low 严重性），另有 11 个候选漏洞被判定为误报。

**主要发现**：唯一的已确认漏洞涉及硬编码系统命令执行，但该漏洞已具备完善的安全缓解措施（`shell=False`、命令硬编码、超时限制、异常处理），实际利用风险极低。漏洞执行的是只读系统信息查询命令（`lscpu`、`npu-smi`），不涉及数据修改或敏感信息泄露。

**业务影响**：由于该漏洞位于内部初始化流程，信任边界为 `internal`（由部署脚本控制环境），且命令参数完全硬编码无用户输入参与，因此对生产环境的安全风险可忽略不计。

**修复建议**：建议将该问题归类为代码风格改进而非安全修复。如追求极致安全风格，可考虑使用绝对路径执行系统命令，但这属于防御性编程而非必要安全修复。

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
| Low | 1 | 100.0% |
| **有效漏洞总计** | **1** | - |
| 误报 (FALSE_POSITIVE) | 11 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-v1-gpu-worker-execute-command-hardcoded]** Hardcoded Command Execution (Low) - `vllm_mindspore/v1/worker/gpu_worker.py:71` @ `execute_command` | 置信度: 95

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

## 3. Low 漏洞 (1)

### [VULN-v1-gpu-worker-execute-command-hardcoded] Hardcoded Command Execution - execute_command

**严重性**: Low | **CWE**: CWE-78 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `vllm_mindspore/v1/worker/gpu_worker.py:71-86` @ `execute_command`
**模块**: v1

**描述**: 硬编码系统命令执行：execute_command函数执行硬编码的系统命令（lscpu, npu-smi）获取NUMA拓扑信息。虽然使用shell=False防止了shell注入，但这些命令在worker进程启动时自动执行。ASCEND_RT_VISIBLE_DEVICES环境变量仅用于数组索引查找，不参与命令构造。

**漏洞代码** (`vllm_mindspore/v1/worker/gpu_worker.py:71-86`)

```c
subprocess.run(cmd_list, shell=False)
```

**达成路径**

ASCEND_RT_VISIBLE_DEVICES env var -> bind_cpu -> execute_command -> subprocess.run with hardcoded commands

**验证说明**: Confirmed: Hardcoded read-only commands (lscpu, npu-smi) for NUMA topology. shell=False prevents injection. trust_level=internal applies. Low severity because commands are system utilities with no security impact.

**深度分析**

**根因分析**

该漏洞位于 `vllm_mindspore/v1/worker/gpu_worker.py` 文件中的 `execute_command` 函数（行 71-86）。该函数被 `get_numa_map()` 调用，用于获取 NPU 与 CPU 的 NUMA 拓扑关系，以优化推理服务器的 CPU 亲和性绑定。

实际执行的命令为：
- `lscpu` — 显示 CPU 架构信息（只读）
- `npu-smi info -l` — 显示 NPU 设备列表（华为系统工具，只读）
- `npu-smi info -t topo` — 显示 NUMA 拓扑关系（只读）

从源代码分析（行 71-86），该函数已具备多层安全缓解措施：

```python
# vllm_mindspore/v1/worker/gpu_worker.py:71-86
def execute_command(cmd_list):
    try:
        result = subprocess.run(cmd_list,
                                shell=False,        # ← 阻止 shell 元字符解释
                                capture_output=True,
                                timeout=60,         # ← 防止资源耗尽
                                check=False)
        return result.stdout.decode()
    except FileNotFoundError:
        cmd = ' '.join(cmd_list)
        logger.warning("Bind CPU command not found: %s", cmd)
    except subprocess.TimeoutExpired as e:
        logger.warning("Bind CPU command execution timed out: %s", e)
    except Exception as e:
        logger.warning("Bind CPU command execution failed: %s", e)
```

**环境变量安全性验证**

环境变量 `ASCEND_RT_VISIBLE_DEVICES` 在 `bind_cpu()` 函数（行 180-187）中使用，但**完全不参与命令构造**：

```python
# vllm_mindspore/v1/worker/gpu_worker.py:180-189
if "ASCEND_RT_VISIBLE_DEVICES" in os.environ:
    device_control_env_var = os.environ["ASCEND_RT_VISIBLE_DEVICES"]
    try:
        device_id = int(device_control_env_var.split(",")[local_rank])  # 仅用于数组索引
    except IndexError as e:
        raise IndexError(...)
        
cpu_range = rank_cpu_maps[device_id]  # 从拓扑映射中获取 CPU 范围
```

环境变量的值仅用于从 `rank_cpu_maps` 数组中索引获取对应的 CPU 范围，不会拼接成命令字符串。

**潜在利用场景评估**

由于命令参数完全硬编码且使用 `shell=False`，攻击者无法：
1. 注入 shell 元字符（如 `; | & $` 等）
2. 修改命令参数或添加新命令
3. 通过环境变量控制命令内容

唯一的理论攻击路径是替换系统命令（如替换 `/usr/bin/lscpu`），但这需要 root 权限，已超出应用安全范畴。

**建议修复方式**

该漏洞的安全措施已完备，建议保持现状。如追求防御性编程，可考虑：

1. **使用绝对路径**（防止 PATH 劫持）：
```python
execute_command(["/usr/bin/lscpu"])
# npu-smi 路径可通过 ASCEND_HOME_PATH 环境变量动态确定
```

2. **添加命令白名单校验**：
```python
ALLOWED_COMMANDS = {"lscpu", "npu-smi"}
if cmd_list[0] not in ALLOWED_COMMANDS:
    raise ValueError(f"Command not allowed: {cmd_list[0]}")
```

但上述改进属于代码风格优化，而非必要安全修复。

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| v1 | 0 | 0 | 0 | 1 | 1 |
| **合计** | **0** | **0** | **0** | **1** | **1** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 1 | 100.0% |

---

## 6. 修复建议

### 优先级 1: 立即修复

**无 Critical/High 严重性漏洞需要立即修复。**

### 优先级 2: 短期修复

**无 Medium 严重性漏洞需要短期修复。**

### 优先级 3: 计划修复（可选）

**[VULN-v1-gpu-worker-execute-command-hardcoded] - Low 严重性**

该漏洞的安全缓解措施已完备（`shell=False`、硬编码命令、超时限制），实际利用风险极低。建议将其归类为代码风格改进而非安全修复。

可选改进方案：
1. 使用绝对路径执行系统命令，防止 PATH 劫持（需 root 权限才能实施）
2. 添加命令白名单校验，增强防御性编程

**修复优先级建议**：低优先级（可选），可在代码风格优化迭代中考虑。

---

## 7. 总结

本次扫描确认的 1 个漏洞（Low 严重性）已具备完善的安全缓解措施，实际利用风险可忽略不计。建议将该问题归档为代码风格改进，无需紧急修复。

扫描同时发现 10 个待确认漏洞（LIKELY/POSSIBLE），主要分布在 `dashboard` 模块（4 个命令执行相关）和 `executor` 模块（2 个环境变量暴露）。这些待确认漏洞的信任边界均为 `untrusted_local` 或 `semi_trusted`，攻击需要本地访问权限，远程利用难度较高。

**整体安全评估**：vLLM-MindSpore 项目在核心推理模块（`v1`、`model_executor`）中采用了良好的安全实践，如硬编码命令、`shell=False`、环境变量白名单过滤等。风险主要集中在测试工具模块（`dashboard`），但这些模块不参与生产环境运行。
