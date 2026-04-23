# 漏洞扫描报告 — 待确认漏洞

**项目**: ops-transformer
**扫描时间**: 2026-04-21T21:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 8 | 72.7% |
| LIKELY | 2 | 18.2% |
| FALSE_POSITIVE | 1 | 9.1% |
| **总计** | **11** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 2 | 100.0% |
| **有效漏洞总计** | **2** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-CMD-001]** command_injection (High) - `scripts/package/common/py/packer.py:218` @ `exec_pack_cmd` | 置信度: 65
2. **[VULN-DF-CMD-001]** command_injection (High) - `scripts/package/common/py/packer.py:227` @ `exec_pack_cmd` | 置信度: 65

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `aclnnFlashAttentionScoreGetWorkspaceSize@attention/flash_attention_score/op_api/aclnn_flash_attention_score.cpp` | 算子API | untrusted_network | ACLNN API 入口，接收外部框架传入的张量数据和参数 | Flash Attention 算子入口，处理 query/key/value 等输入张量 |
| `FlashAttentionScore@attention/flash_attention_score/op_api/flash_attention_score.cpp` | 算子API | untrusted_network | L0OP 层入口，直接处理用户传入的张量参数 | Flash Attention L0 算子函数 |
| `aclnnPromptFlashAttentionGetWorkspaceSize@attention/prompt_flash_attention/op_api/aclnn_prompt_flash_attention.cpp` | 算子API | untrusted_network | Prompt Flash Attention API 入口，处理 KV cache 数据 | Prompt Flash Attention 算子入口 |
| `aclnnMatmulAllReduceGetWorkspaceSize@mc2/matmul_all_reduce/op_api/aclnn_matmul_all_reduce.cpp` | 算子API | untrusted_network | Matmul All Reduce API 入口，分布式通信算子 | Matmul All Reduce 算子入口 |
| `aclnnMoeDistributeDispatchGetWorkspaceSize@mc2/moe_distribute_dispatch/op_api/aclnn_moe_distribute_dispatch.cpp` | 算子API | untrusted_network | MoE 分布式分发算子入口 | MoE Distribute Dispatch 算子入口 |
| `npu_moe_distribute_dispatch_v2@torch_extension/npu_ops_transformer/ops/__init__.py` | web_route | untrusted_network | Python API 入口，接收 PyTorch 模型的输入数据 | PyTorch 扩展 MoE 分发算子 |
| `main@build.sh` | cmdline | semi_trusted | 构建脚本入口，接收命令行参数 | 项目构建脚本，处理编译参数 |
| `main@cmake/scripts/parse_changed_files.py` | cmdline | semi_trusted | CI 脚本入口，解析文件路径 | CI 文件解析脚本，使用 yaml.load |
| `main@scripts/check_build_dependencies.py` | cmdline | semi_trusted | 构建依赖检查脚本，读取配置文件 | 构建依赖检查脚本 |

**其他攻击面**:
- ACLNN API 接口 (op_api/*.cpp) - 接收外部框架传入的张量数据
- Infershape 函数 (op_host/*_infershape.cpp) - 处理形状参数，可能存在整数溢出
- Kernel 实现 (op_kernel/*.cpp) - 内存分配和拷贝操作
- PyTorch 扩展 (torch_extension/) - Python API 入口
- 构建脚本 (build.sh, cmake/scripts/*.py) - 命令行参数处理

---

## 3. High 漏洞 (2)

### [VULN-SEC-CMD-001] command_injection - exec_pack_cmd

**严重性**: High | **CWE**: CWE-78 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `scripts/package/common/py/packer.py:218-232` @ `exec_pack_cmd`
**模块**: scripts

**描述**: 命令注入漏洞：scripts/package/common/py/packer.py 中 exec_pack_cmd 函数使用 subprocess.run(cmd, shell=True) 执行命令，其中 cmd 包含 delivery_dir 参数。如果 delivery_dir 包含 shell 元字符（如 ; 或 $()），攻击者可注入恶意命令。delivery_dir 来自用户传入的命令行参数 --delivery_dir。

**漏洞代码** (`scripts/package/common/py/packer.py:218-232`)

```c
def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str: 
    """执行打包命令"""
    if delivery_dir:
        cmd = f'cd {delivery_dir} && {pack_cmd}'
    else:
        cmd = pack_cmd
    CommLog.cilog_info("package cmd:%s", cmd)
    result = subprocess.run(cmd, shell=True, check=False, stdout=PIPE, stderr=STDOUT)
```

**达成路径**

用户命令行参数 --delivery_dir → package.py:658-660 delivery_dir → packer.py:223 cmd = f'cd {delivery_dir} && {pack_cmd}' → subprocess.run(cmd, shell=True)

**验证说明**: 命令注入漏洞很可能存在：delivery_dir 参数来自命令行参数 --delivery_dir，直接拼接到 subprocess.run(cmd, shell=True) 执行。若 delivery_dir 含 shell 元字符（如 ; $()），可执行任意命令。但由于这是构建脚本，需开发者权限执行，攻击面有限（Build System trust_boundary risk=Low）。建议使用 shlex.quote() 转义或 shell=False + 列表参数。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: -10 | cross_file: 0

---

### [VULN-DF-CMD-001] command_injection - exec_pack_cmd

**严重性**: High | **CWE**: CWE-78 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `scripts/package/common/py/packer.py:227-228` @ `exec_pack_cmd`
**模块**: scripts

**描述**: 命令注入风险：构建打包脚本使用 subprocess.run() 并设置 shell=True，cmd 参数由 delivery_dir 和 pack_cmd 拼接。如果这些参数来自外部输入或未经过验证的配置，可能导致命令注入。

**漏洞代码** (`scripts/package/common/py/packer.py:227-228`)

```c
cmd = f'cd {delivery_dir} && {pack_cmd}'
result = subprocess.run(cmd, shell=True, check=False, stdout=PIPE, stderr=STDOUT)
```

**达成路径**

外部配置/命令行参数 → delivery_dir [SOURCE] + pack_cmd [SOURCE] → cmd 字符串拼接 [PROPAGATION] → subprocess.run(shell=True) [SINK]

**验证说明**: 与 VULN-SEC-CMD-001 相同漏洞位置。命令注入风险在 packer.py exec_pack_cmd 函数。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: -10 | cross_file: 0

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| scripts | 0 | 2 | 0 | 0 | 2 |
| **合计** | **0** | **2** | **0** | **0** | **2** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 2 | 100.0% |
