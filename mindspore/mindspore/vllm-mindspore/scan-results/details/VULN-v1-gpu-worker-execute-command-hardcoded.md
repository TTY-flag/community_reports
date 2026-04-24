# VULN-v1-gpu-worker-execute-command-hardcoded

## 漏洞概述

| 属性 | 值 |
|------|-----|
| ID | VULN-v1-gpu-worker-execute-command-hardcoded |
| 类型 | Hardcoded Command Execution |
| CWE | CWE-78 (OS Command Injection) |
| 严重性 | Low |
| 文件 | vllm_mindspore/v1/worker/gpu_worker.py |
| 行号 | 71-86, 88-172, 175-194 |
| 函数 | execute_command → get_numa_map → bind_cpu |
| 置信度 | 95% |

## 漏洞详情

### 源代码分析

`execute_command` 函数定义：

```python
def execute_command(cmd_list):
    try:
        result = subprocess.run(cmd_list,
                                shell=False,
                                capture_output=True,
                                timeout=60,
                                check=False)
        return result.stdout.decode()
    except FileNotFoundError:
        cmd = ' '.join(cmd_list)
        logger.warning("Bind CPU command not found: %s", cmd)
    ...
```

命令调用点（在 `get_numa_map` 函数中）：

```python
# 行 94: 获取 CPU 和 NUMA 信息
numa_info = execute_command(["lscpu"]).strip().split("\n")

# 行 103: 获取 NPU 芯片信息
chip_info = execute_command(["npu-smi", "info", "-l"]).strip().split("\n")

# 行 114: 获取 NUMA 和 NPU 亲和性拓扑
numa_topo_info = execute_command(["npu-smi", "info", "-t", "topo"]).strip().split("\n")
```

### 调用链分析

```
wrapper_worker_bind_cpu (装饰器)
  ↓
bind_cpu (行 175-194)
  ↓ get_numa_map()
  ↓ execute_command(["lscpu"])
  ↓ execute_command(["npu-smi", "info", "-l"])
  ↓ execute_command(["npu-smi", "info", "-t", "topo"])
  ↓ subprocess.run(cmd_list, shell=False)
```

## 安全评估

### 缓解措施分析

该漏洞已具备以下安全措施：

| 缓解措施 | 状态 | 说明 |
|----------|------|------|
| `shell=False` | ✓ 已实现 | 阻止 shell 元字符解释，防止 shell 注入 |
| 命令硬编码 | ✓ 已实现 | 命令参数完全固定，无用户输入参与 |
| 超时限制 | ✓ 已实现 | `timeout=60` 秒，防止无限等待 |
| 异常处理 | ✓ 已实现 | 捕获 FileNotFoundError、TimeoutExpired 等异常 |

### 环境变量分析

`ASCEND_RT_VISIBLE_DEVICES` 环境变量的使用方式（行 180-187）：

```python
if "ASCEND_RT_VISIBLE_DEVICES" in os.environ:
    device_control_env_var = os.environ["ASCEND_RT_VISIBLE_DEVICES"]
    try:
        device_id = int(device_control_env_var.split(",")[local_rank])
    except IndexError as e:
        raise IndexError(...)
```

**关键发现**：环境变量仅用于**数组索引查找**，从 `rank_cpu_maps` 中获取 CPU 范围：

```python
cpu_range = rank_cpu_maps[device_id]  # 行 189
```

环境变量**完全不参与命令构造**，不存在注入风险。

### 命令性质分析

| 命令 | 功能 | 安全性 |
|------|------|--------|
| `lscpu` | 显示 CPU 架构信息 | 只读，无安全影响 |
| `npu-smi info -l` | 显示 NPU 设备列表 | 只读，华为 NPU 系统工具 |
| `npu-smi info -t topo` | 显示 NUMA 拓扑关系 | 只读，无安全影响 |

所有命令都是**只读查询**，不修改系统状态，不涉及敏感数据。

### 信任边界分析

根据 `project_model.json`：

```
trust_level: internal
justification: 内部函数，执行系统命令获取NUMA拓扑信息，命令内容硬编码
```

该函数位于**可信边界内**：
- Worker 进程初始化阶段执行
- 部署在 Atlas NPU 服务器上，由管理员控制环境
- 环境变量由部署脚本设置，属于可信配置

## 利用分析

### 攻击路径评估

**无可达攻击路径**：

1. **无外部输入源**：命令参数完全硬编码
2. **无注入点**：`shell=False` 阻止任何 shell 元字符解释
3. **无数据流**：环境变量不拼接命令字符串
4. **只读操作**：命令仅查询系统信息，不修改状态

### PoC 构造尝试

**无法构造有效 PoC**：

尝试 1：假设能控制环境变量
```bash
ASCEND_RT_VISIBLE_DEVICES="malicious;rm -rf /"
```
结果：环境变量仅用于数组索引，不会拼接命令，无效。

尝试 2：假设能替换系统命令
```bash
# 替换 lscpu 为恶意脚本
ln -sf /path/to/malicious_script /usr/bin/lscpu
```
结果：这属于系统级攻击，已超出应用安全范畴。如果攻击者有权限替换系统命令，则已获得 root 权限，无需利用此漏洞。

### 漏洞影响范围

**无实际安全影响**：

- 无法被远程攻击者利用
- 无法被本地普通用户利用（需 root 权限才能替换系统命令）
- 执行结果仅用于 CPU 亲和性绑定，属于性能优化功能
- 不泄露敏感信息（仅硬件拓扑信息）

## 结论

### 最终判定

**无实际利用价值 - 误报（技术正确但无安全风险）**

### 判定依据

1. ✓ 代码确实使用了 `subprocess.run` 执行系统命令（技术正确）
2. ✓ `shell=False` 已阻止 shell 注入（缓解有效）
3. ✓ 命令参数完全硬编码，无用户输入参与（无注入点）
4. ✓ 执行的是只读系统信息查询命令（无安全影响）
5. ✓ 属于内部初始化流程，信任等级为 internal（可信边界内）

### 建议分类

此漏洞应归类为**代码风格问题**而非安全漏洞：

- 使用 `subprocess` 执行外部命令本身不是安全问题
- 安全措施已完备（shell=False, timeout, exception handling）
- 建议保持现状，无需修复

## 缓解措施建议

### 当前状态

无需额外缓解措施。现有安全措施已足够：

1. `shell=False` - 阻止 shell 注入
2. 硬编码命令 - 无参数化风险
3. 超时限制 - 防止资源耗尽
4. 异常处理 - 防止崩溃

### 可选改进（非必要）

如果团队追求极致安全风格，可考虑：

1. **使用绝对路径**（防止 PATH 劫持，但需 root 权限）：
   ```python
   execute_command(["/usr/bin/lscpu"])
   # npu-smi 路径需根据 ASCEND_HOME_PATH 确定
   ```

2. **添加命令白名单校验**：
   ```python
   ALLOWED_COMMANDS = {"lscpu", "npu-smi"}
   if cmd_list[0] not in ALLOWED_COMMANDS:
       raise ValueError(f"Command not allowed: {cmd_list[0]}")
   ```

但这些改进属于**防御性编程**，而非必要安全修复。

## 参考信息

- CWE-78: OS Command Injection - https://cwe.mitre.org/data/definitions/78.html
- Python subprocess security best practices - https://docs.python.org/3/library/subprocess.html#security-considerations