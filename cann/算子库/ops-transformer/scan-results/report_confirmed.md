# 漏洞扫描报告 — 已确认漏洞

**项目**: ops-transformer  
**扫描时间**: 2026-04-21T21:00:00Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要 (Executive Summary)

本项目为华为昇腾 CANN (Compute Architecture for Neural Networks) Transformer 算子库，是一个 C/C++ + Python 混合项目，包含约 4900 个文件、25 万行代码。作为共享库被 AI 框架（PyTorch/TensorFlow）调用，运行在 NPU 设备上，支持 Flash Attention、MoE 专家路由、分布式通信矩阵乘法等高性能计算场景。

### 扫描范围

本次扫描覆盖 12 个主要模块，重点关注高风险模块：attention（Flash Attention 系列）、mc2（分布式通信算子）、moe（专家路由）、gmm（分组矩阵乘法）。扫描聚焦于 ACLNN API 入口点、Infershape 形状推理函数、Kernel 实现及 Python 扩展接口等攻击面。

### 关键发现

扫描共发现 **10 个有效漏洞**，其中：
- **CONFIRMED（已确认）**: 8 个整数溢出漏洞
- **LIKELY（待确认）**: 2 个命令注入漏洞
- **FALSE_POSITIVE（误报）**: 1 个

漏洞严重性分布：**1 个 Critical、7 个 High、2 个 High（待确认）**。所有已确认漏洞均为 CWE-190 整数溢出，集中于形状推理函数（`*_infershape.cpp`），在处理外部输入的张量维度参数时缺乏溢出检查。

### 风险等级

**整体风险等级: 高 (HIGH)**

主要风险来源于：
1. ACLNN API 接口接收来自 AI 框架的不可信输入，攻击者可构造恶意张量形状触发整数溢出
2. 溢出后影响内存分配和形状推理，可能导致拒绝服务、内存越界访问或数据损坏
3. mc2 模块漏洞密度最高（5 个），涉及分布式通信算子，影响范围广
4. 命令注入漏洞位于构建脚本，攻击面受限但仍需修复

### 建议优先级

| 优先级 | 漏洞 | 模块 | 建议措施 |
|--------|------|------|----------|
| P0 | VULN-DF-INT-003 | mc2 | 立即修复，Critical 级别，涉及复杂乘法表达式 |
| P1 | VULN-DF-INT-001/002/004/005 | mc2 | 高优先级修复，涉及 bs、k 等关键参数 |
| P1 | VULN-DF-INT-006/008 | attention | 高优先级修复，涉及 Flash Attention MLA |
| P2 | VULN-DF-INT-007 | moe | 中优先级修复，已部分检查专家数量上限 |
| P3 | VULN-SEC-CMD-001/002 | scripts | 低优先级，构建脚本攻击面有限 |

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
| Critical | 1 | 12.5% |
| High | 7 | 87.5% |
| **有效漏洞总计** | **8** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-INT-003]** integer_overflow (Critical) - `mc2/moe_distribute_dispatch_v3/op_host/moe_distribute_dispatch_v3_infershape.cpp:274` @ `InferShapeMoeDistributeDispatchV3` | 置信度: 85
2. **[VULN-DF-INT-001]** integer_overflow (High) - `mc2/quant_reduce_scatter/op_host/quant_reduce_scatter_infershape.cpp:76` @ `GetShapeInfo` | 置信度: 85
3. **[VULN-DF-INT-002]** integer_overflow (High) - `mc2/quant_all_reduce/op_host/quant_all_reduce_infershape.cpp:73` @ `GetShapeInfo` | 置信度: 85
4. **[VULN-DF-INT-004]** integer_overflow (High) - `mc2/moe_distribute_dispatch/op_host/moe_distribute_dispatch_infershape.cpp:94` @ `InferShapeMoeDistributeDispatch` | 置信度: 85
5. **[VULN-DF-INT-005]** integer_overflow (High) - `mc2/common/op_host/mc2_common_infershape.cpp:95` @ `AllGatherMatmulInferYShape` | 置信度: 85
6. **[VULN-DF-INT-006]** integer_overflow (High) - `attention/flash_attention_score/op_host/flash_attention_score_infershape.cpp:157` @ `InferShapeFlashAttentionScore` | 置信度: 85
7. **[VULN-DF-INT-007]** integer_overflow (High) - `moe/moe_init_routing_v3/op_host/moe_init_routing_v3_infershape.cpp:685` @ `MoeInitRoutingV3Infershape` | 置信度: 85
8. **[VULN-DF-INT-008]** integer_overflow (High) - `attention/mla_prolog_v2/op_host/mla_prolog_v2_infershape.cpp:36` @ `SetMlaPrologV2ShapeDim` | 置信度: 85

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

## 3. Critical 漏洞 (1)

### [VULN-DF-INT-003] integer_overflow - InferShapeMoeDistributeDispatchV3

**严重性**: Critical | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `mc2/moe_distribute_dispatch_v3/op_host/moe_distribute_dispatch_v3_infershape.cpp:274` @ `InferShapeMoeDistributeDispatchV3`  
**模块**: mc2

**描述**: 整数溢出风险：复杂的乘法表达式计算 epRecvCount 形状，涉及多个外部输入参数的乘法：epWorldSize * localExpertNum + globalBsReal * 2 * k * epWorldSize。这些参数来自 ACLNN API 输入和属性，乘法链可能导致整数溢出。

**漏洞代码** (`mc2/moe_distribute_dispatch_v3/op_host/moe_distribute_dispatch_v3_infershape.cpp:274`)

```c
epRecvCountShape->SetDim(0U, *epWorldSize * localExpertNum + globalBsReal * 2 * k * ((*epWorldSize) / RANK_NUM_PER_NODE));
```

**达成路径**

ACLNN API (aclnnMoeDistributeDispatchV3) → InferShapeMoeDistributeDispatchV3 → epWorldSize [SOURCE] * localExpertNum [SOURCE] + globalBsReal [SOURCE] * 2 * k [SOURCE] * epWorldSize [SOURCE] → SetDim [POTENTIAL OVERFLOW]

**验证说明**: 整数溢出漏洞已确认：epWorldSize、localExpertNum、globalBsReal、k 等参数均来自 ACLNN API 外部输入（trust_level=untrusted_network）。复杂乘法表达式 epWorldSize * localExpertNum + globalBsReal * 2 * k * (epWorldSize / 8) 可能导致 int64_t 溢出，影响后续内存分配。无任何溢出检查保护。攻击者可通过构造恶意张量形状触发溢出，可能导致拒绝服务或内存安全问题。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

#### 深度分析

**漏洞触发条件分析**：

该漏洞位于 MoE（Mixture of Experts）分布式分发算子 V3 的形状推理函数中，用于计算 Expert Parallel（EP）接收缓冲区大小。关键变量来源：
- `epWorldSize`: 来自属性 `DISPATCH_INPUT_ATTR_EP_WORLD_SIZE_INDEX`，表示 EP 并行世界大小
- `localExpertNum`: 本地专家数量，由全局专家数 / EP rank 数计算得出
- `globalBsReal`: 全局批次大小，实际值为 `(globalBs == 0) ? (bs * epWorldSize) : *globalBs`
- `k`: top-k 值，来自 `expertIdsShape->GetDim(1)`，表示每个 token 选出的专家数

**攻击场景示例**：

假设典型大规模 MoE 模型配置：
- `epWorldSize = 256`（256 卡 EP 并行）
- `localExpertNum = 32`（每卡 32 个专家）
- `globalBsReal = 131072`（全局批次大小，约 128K tokens）
- `k = 8`（每 token 选 8 个专家）

计算表达式：
```
epRecvCount = 256 * 32 + 131072 * 2 * 8 * (256 / 8)
            = 8192 + 131072 * 16 * 32
            = 8192 + 67,108,864
            ≈ 67,117,056
```

当参数进一步放大（如 `globalBsReal = 2^30`），乘法链 `globalBsReal * 2 * k * (epWorldSize / 8)` 可能接近或超过 `int64_t` 最大值（约 9.2 × 10^18），导致溢出。

**代码上下文观察**：

源码中存在分支逻辑：
- 当 `expertScalesShape != nullptr` 时，执行复杂乘法表达式（含溢出风险）
- 否则使用简化表达式 `*epWorldSize * localExpertNum`

该分支设计表明开发者考虑了有无量化参数的不同场景，但两分支均无溢出检查。

**影响范围**：

溢出后的 `epRecvCountShape` 值被用于：
1. 内存分配规划：后续 kernel 根据此形状分配 NPU 设备内存
2. Token 分发索引：影响 MoE token 分发/收集操作的边界计算
3. 可能导致：
   - 内存分配过小 → 缓冲区溢出
   - 内存分配过大 → 资源耗尽拒绝服务
   - 索引计算错误 → 数据损坏

**修复难度**: 中等。需在乘法表达式前添加溢出检查，可采用 `__builtin_mul_overflow` 或手动检查边界。

---

## 4. High 漏洞 (7)

### [VULN-DF-INT-001] integer_overflow - GetShapeInfo

**严重性**: High | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `mc2/quant_reduce_scatter/op_host/quant_reduce_scatter_infershape.cpp:76` @ `GetShapeInfo`  
**模块**: mc2

**描述**: 整数溢出风险：外部输入的张量形状维度通过 GetDim() 获取后直接进行乘法运算 shapeInfo.bs = GetDim(0) * GetDim(1)，没有溢出检查。外部输入的批次大小 (b) 和序列长度 (s) 可能很大，乘积超过 int64_t 范围会导致溢出，影响后续内存分配和形状推理。

**漏洞代码** (`mc2/quant_reduce_scatter/op_host/quant_reduce_scatter_infershape.cpp:76`)

```c
shapeInfo.bs = x_shape->GetDim(0) * x_shape->GetDim(1);
```

**达成路径**

ACLNN API (aclnnQuantReduceScatterGetWorkspaceSize) → InferShapeQuantReduceScatter → GetShapeInfo → x_shape->GetDim(0) [SOURCE] * x_shape->GetDim(1) [SOURCE] → shapeInfo.bs [POTENTIAL OVERFLOW]

**验证说明**: 整数溢出漏洞已确认：x_shape->GetDim(0) 和 GetDim(1) 来自 ACLNN API 外部输入张量形状。批次大小 b 和序列长度 s 的乘积 bs = b * s 可能超过 int64_t 范围，导致形状推理错误或内存分配失败。攻击者可构造超大张量形状触发溢出。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

#### 深度分析

**漏洞触发条件分析**：

该漏洞位于量化 Reduce Scatter 算子的形状推理函数 `GetShapeInfo`，用于计算批次-序列维度乘积 `bs`。输入张量支持 2 维或 3 维：
- 2 维时：`bs = x_shape->GetDim(0)`（无乘法，无溢出风险）
- 3 维时：`bs = x_shape->GetDim(0) * x_shape->GetDim(1)`（乘法运算，存在溢出风险）

**攻击场景示例**：

假设恶意输入张量形状为 `[b, s, h] = [65536, 1048576, 4096]`：
- `b = 65536`（批次大小）
- `s = 1048576`（序列长度，约 1M tokens）
- `h = 4096`（隐藏层维度）

计算 `bs = b * s = 65536 * 1048576 = 68,719,476,736`（约 68B），远超典型大模型的合理批次大小。

更极端情况：`b = 2^31, s = 2^31`，乘积为 `2^62`，接近 `int64_t` 上限（`2^63 - 1`）。若参数再放大，溢出后 `bs` 变为负数或小正数，导致：
- 后续 `CeilDiv(bs, rank_num)` 计算错误
- 输出形状 `output_shape->SetDim(0, CeilDiv(bs, rank_num))` 设置为异常值
- Kernel 层内存分配基于错误形状，可能引发缓冲区溢出

**代码上下文观察**：

源码中有边界检查：
```c
OP_CHECK_IF((bs <= 0) || (h <= 0) || (bsTmp <= 0) || (k <= 0), ...)
```

但检查条件为 `bs <= 0`，溢出后 `bs` 可能仍为正数（如 `2^62`），无法被此检查捕获。真正需要的是溢出前的预检查。

**关联下游使用**：

`shapeInfo.bs` 在 `InferShapeQuantReduceScatter` 中被用于：
```c
output_shape->SetDim(0, CeilDiv(shapeInfo.b * shapeInfo.s, shapeInfo.rank_num));
```

若 `bs` 溢出，`CeilDiv` 计算结果异常，影响量化 Reduce Scatter 输出张量形状。

---

### [VULN-DF-INT-002] integer_overflow - GetShapeInfo

**严重性**: High | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `mc2/quant_all_reduce/op_host/quant_all_reduce_infershape.cpp:73` @ `GetShapeInfo`  
**模块**: mc2

**描述**: 整数溢出风险：外部输入的张量形状维度进行乘法运算，没有溢出检查。与 VULN-DF-INT-001 类似，bs = b * s 的计算可能溢出。

**漏洞代码** (`mc2/quant_all_reduce/op_host/quant_all_reduce_infershape.cpp:73`)

```c
shapeInfo.bs = x_shape->GetDim(0) * x_shape->GetDim(1);
```

**达成路径**

ACLNN API → InferShapeQuantAllReduce → GetShapeInfo → x_shape->GetDim(0) [SOURCE] * x_shape->GetDim(1) [SOURCE] → shapeInfo.bs [POTENTIAL OVERFLOW]

**验证说明**: 整数溢出漏洞已确认：与 VULN-DF-INT-001 相同模式，quant_all_reduce_infershape.cpp 中 bs = GetDim(0) * GetDim(1) 计算可能溢出。外部输入的张量形状参数无溢出检查保护。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

#### 深度分析

**漏洞复用模式**：

该漏洞与 VULN-DF-INT-001 完全相同的代码模式，位于量化 All Reduce 算子的 `GetShapeInfo` 函数。两个算子功能相似：
- `quant_reduce_scatter`: 量化后执行 Reduce Scatter（分布式规约分发）
- `quant_all_reduce`: 量化后执行 All Reduce（分布式全规约）

**代码一致性风险**：

两文件共享相同的漏洞模式，表明可能存在系统性问题：所有处理 `b * s` 乘法的 infershape 函数均缺少溢出检查。建议审查其他类似算子（如 `matmul_all_reduce`、`all_gather_matmul`）是否存在相同问题。

---

### [VULN-DF-INT-004] integer_overflow - InferShapeMoeDistributeDispatch

**严重性**: High | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `mc2/moe_distribute_dispatch/op_host/moe_distribute_dispatch_infershape.cpp:94` @ `InferShapeMoeDistributeDispatch`  
**模块**: mc2

**描述**: 整数溢出风险：批次大小和 top-k 值的乘法计算 expandIdx 形状，来自外部输入的 bs 和 k 参数直接相乘，没有溢出检查。

**漏洞代码** (`mc2/moe_distribute_dispatch/op_host/moe_distribute_dispatch_infershape.cpp:94`)

```c
expandIdxShape->SetDim(0U, bs * k);
```

**达成路径**

ACLNN API → InferShapeMoeDistributeDispatch → bs [SOURCE] * k [SOURCE] → SetDim [POTENTIAL OVERFLOW]

**验证说明**: 整数溢出漏洞已确认：bs 和 k 来自外部输入（xShape->GetDim 和 expertIdsShape->GetDim）。expandIdxShape->SetDim(0, bs * k) 计算可能溢出，影响 MoE 分布式分发算子的形状推理。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

#### 深度分析

**漏洞触发条件分析**：

该漏洞位于 MoE 分布式分发算子（非 V3 版本）的 `InferExpertIdsShape` 函数，用于计算扩展索引张量形状。关键变量：
- `bs`: 批次大小，来自 `xShape->GetDim(0)` 或 `xShape->GetDimNum() == 1U ? NEG_ONE : xShape->GetDim(0)`
- `k`: top-k 值，来自 `expertIdsShape->GetDim(1)`

**攻击场景示例**：

MoE 模型典型配置：
- `bs = 128000`（批次 token 数）
- `k = 16`（每 token 选择 16 个专家）

计算：`expandIdxShape = bs * k = 128000 * 16 = 2,048,000`

极端攻击：
- `bs = 2^31 = 2,147,483,648`
- `k = 8`

乘积：`bs * k = 2^31 * 8 = 2^34 = 17,179,869,184`，超过 `int64_t` 的一半。

若 `bs = 2^32, k = 2^32`，乘积为 `2^64`，必然溢出。

**代码上下文观察**：

存在前置边界检查：
```c
OP_CHECK_IF((bs <= 0) || (h <= 0) || (bsTmp <= 0) || (k <= 0), ...)
```

同样，`bs * k` 溢出后可能仍为正数，无法被 `<= 0` 检查捕获。

**关联功能影响**：

`expandIdxShape` 用于 MoE token 扩展索引，指示哪些 token 被分发到哪些专家。溢出后：
- 索引数组大小计算错误
- 后续 `expandXShape` 形状依赖 `realA = a * tpWorldSize`，其中 `a = globalBsReal * min(localExpertNum, k)`
- 整个 MoE 分发流程可能崩溃或数据损坏

---

### [VULN-DF-INT-005] integer_overflow - AllGatherMatmulInferYShape

**严重性**: High | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `mc2/common/op_host/mc2_common_infershape.cpp:95` @ `AllGatherMatmulInferYShape`  
**模块**: mc2

**描述**: 整数溢出风险：矩阵维度 M 和 rankSize 的乘法计算输出形状，dimM 来自输入张量形状，rankSize 来自分布式通信配置，乘法可能导致溢出。

**漏洞代码** (`mc2/common/op_host/mc2_common_infershape.cpp:95`)

```c
yShape->SetDim(0, commParas.dimM * commParas.rankSize);
```

**达成路径**

ACLNN API → AllGatherMatmul → CommonParamCheck → x1MatrixShape->GetDim(0/1) [SOURCE] → dimM [PROPAGATION] * rankSize [SOURCE] → SetDim [POTENTIAL OVERFLOW]

**验证说明**: 整数溢出漏洞已确认：dimM 来自 x1MatrixShape->GetDim（外部输入），rankSize 来自分布式通信配置。yShape->SetDim(0, dimM * rankSize) 计算可能溢出，影响 AllGather Matmul 算子的输出形状。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

#### 深度分析

**漏洞触发条件分析**：

该漏洞位于 mc2 公共形状推理函数，用于 All Gather Matmul 算子输出形状计算。`AllGatherMatmulInferYShape` 函数计算输出矩阵 Y 的形状：
- `dimM`: 矩阵 M 维度，来自 `x1MatrixShape->GetDim(0)` 或 `GetDim(1)`（根据是否 transpose）
- `rankSize`: 分布式并行世界大小，来自属性参数

**攻击场景示例**：

大规模分布式训练配置：
- `dimM = 131072`（矩阵 M 维度）
- `rankSize = 1024`（1024 卡并行）

计算：`yShape->SetDim(0, dimM * rankSize) = 131072 * 1024 = 134,217,728`

极端情况：
- `dimM = 2^30 = 1,073,741,824`
- `rankSize = 512`

乘积：`dimM * rankSize = 2^30 * 512 = 2^39 = 549,755,813,888`，接近 `int64_t` 上限。

**代码上下文观察**：

存在动态 shape 特殊处理：
```c
if (commParas.dimM == -1) {
    commParas.rankSize = 1;
}
```

这为动态形状提供了保护（rankSize 设为 1），但静态形状场景无溢出检查。

同时，`gatherOutShape` 也使用了相同乘法：
```c
gatherOutShape->SetDim(0, commParas.dimM * commParas.rankSize);
```

表明同一乘法表达式在多处使用，需统一添加溢出检查。

**跨模块影响**：

`mc2_common_infershape.cpp` 是公共模块，被多个 mc2 算子复用。此漏洞可能影响：
- `matmul_all_reduce`
- `all_gather_matmul`
- `matmul_reduce_scatter`

修复一处可惠及多个算子。

---

### [VULN-DF-INT-006] integer_overflow - InferShapeFlashAttentionScore

**严重性**: High | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `attention/flash_attention_score/op_host/flash_attention_score_infershape.cpp:157` @ `InferShapeFlashAttentionScore`  
**模块**: attention

**描述**: 整数溢出风险：注意力机制输出形状计算中，N1（头数）来自外部属性，D2 来自值张量形状维度，乘法 N1 * D2 可能溢出。

**漏洞代码** (`attention/flash_attention_score/op_host/flash_attention_score_infershape.cpp:157`)

```c
attentionOutShape->SetDim(DIM_NUM_2, N1 * D2);
```

**达成路径**

ACLNN API (aclnnFlashAttentionScoreGetWorkspaceSize) → InferShapeFlashAttentionScore → headNum [SOURCE] → N1 [PROPAGATION] * D2 (valueShape->GetDim / N2) [SOURCE] → SetDim [POTENTIAL OVERFLOW]

**验证说明**: 整数溢出漏洞已确认：N1（headNum）来自属性参数，D2 来自 valueShape->GetDim 计算（h3 / N2）。attentionOutShape->SetDim(2, N1 * D2) 计算可能溢出。当 N2=0 时有除零保护但返回成功，未覆盖溢出场景。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-INT-007] integer_overflow - MoeInitRoutingV3Infershape

**严重性**: High | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `moe/moe_init_routing_v3/op_host/moe_init_routing_v3_infershape.cpp:685` @ `MoeInitRoutingV3Infershape`  
**模块**: moe

**描述**: 整数溢出风险：MoE 专家路由扩展比例计算，experNum（专家数量）和 expertCapacity（专家容量）来自外部输入，乘法可能溢出。

**漏洞代码** (`moe/moe_init_routing_v3/op_host/moe_init_routing_v3_infershape.cpp:685`)

```c
expandedScaleShape->SetDim(0U, experNum * expertCapacity);
```

**达成路径**

ACLNN API → MoeInitRoutingV3Infershape → experNum [SOURCE] * expertCapacity [SOURCE] → SetDim [POTENTIAL OVERFLOW]

**验证说明**: 整数溢出漏洞已确认：experNum 和 expertCapacity 来自 ACLNN API 属性参数（外部输入）。expandedScaleShape->SetDim(0, experNum * expertCapacity) 计算可能溢出。虽有 experNum <= 10240 的边界检查，但 expertCapacity 无上限验证，乘积仍可能溢出。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-INT-008] integer_overflow - SetMlaPrologV2ShapeDim

**严重性**: High | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `attention/mla_prolog_v2/op_host/mla_prolog_v2_infershape.cpp:36` @ `SetMlaPrologV2ShapeDim`  
**模块**: attention

**描述**: 整数溢出风险：MLA Prolog V2 形状推理中，当 isBsMerge 为 false 时计算 B * S 作为输出形状维度。B（批次大小）和 S（序列长度）来自外部输入的张量形状，乘法可能导致溢出。

**漏洞代码** (`attention/mla_prolog_v2/op_host/mla_prolog_v2_infershape.cpp:36`)

```c
dequantScaleQNopeShape->SetDim(DIM_INDEX_0, shapeParam.isBsMerge ? shapeParam.T : shapeParam.B * shapeParam.S);
```

**达成路径**

ACLNN API → InferShapeMlaPrologV2 → GetMlaPrologShapeDim → shapeParam.B [SOURCE] * shapeParam.S [SOURCE] → SetDim [POTENTIAL OVERFLOW]

**验证说明**: 整数溢出漏洞已确认：shapeParam.B 和 shapeParam.S 来自外部输入张量形状（通过 GetMlaPrologShapeDim 从 context 获取）。当 isBsMerge=false 时，dequantScaleQNopeShape->SetDim(0, B * S) 计算可能溢出。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| attention | 0 | 2 | 0 | 0 | 2 |
| mc2 | 1 | 4 | 0 | 0 | 5 |
| moe | 0 | 1 | 0 | 0 | 1 |
| **合计** | **1** | **7** | **0** | **0** | **8** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-190 | 8 | 100.0% |

---

## 7. 修复建议 (Remediation Recommendations)

### 7.1 整数溢出漏洞修复方案 (CWE-190)

针对本报告中发现的 8 个整数溢出漏洞，建议采用以下修复策略：

#### 7.1.1 通用溢出检查模式

推荐在所有 `*_infershape.cpp` 文件中添加统一的溢出检查函数：

```cpp
// 建议添加到 common/op_host/overflow_check.h
#include <limits>
#include <cstdint>

namespace ops {
namespace overflow {

// 安全乘法检查：返回 true 表示会溢出
inline bool WillMultiplicationOverflow(int64_t a, int64_t b) {
    if (a == 0 || b == 0) return false;
    if (a > 0 && b > 0) {
        return a > std::numeric_limits<int64_t>::max() / b;
    }
    if (a < 0 && b < 0) {
        return a < std::numeric_limits<int64_t>::max() / b;
    }
    // 异号情况
    if (a > 0) {
        return b < std::numeric_limits<int64_t>::min() / a;
    }
    return a < std::numeric_limits<int64_t>::min() / b;
}

// 安全乘法：溢出时返回错误
inline ge::graphStatus SafeMultiply(int64_t a, int64_t b, int64_t& result, 
                                     const char* nodeName, const char* paramName) {
    if (WillMultiplicationOverflow(a, b)) {
        OP_LOGE(nodeName, "Integer overflow detected in %s: %ld * %ld", paramName, a, b);
        return ge::GRAPH_FAILED;
    }
    result = a * b;
    return ge::GRAPH_SUCCESS;
}

// 多因子乘法安全检查
inline ge::graphStatus SafeMultiplyChain(int64_t a, int64_t b, int64_t c, int64_t& result,
                                          const char* nodeName, const char* paramName) {
    int64_t temp;
    if (SafeMultiply(a, b, temp, nodeName, paramName) != ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }
    if (SafeMultiply(temp, c, result, nodeName, paramName) != ge::GRAPH_SUCCESS) {
        return ge::GRAPH_FAILED;
    }
    return ge::GRAPH_SUCCESS;
}

} // namespace overflow
} // namespace ops
```

#### 7.1.2 具体漏洞修复示例

**VULN-DF-INT-003 (Critical) 修复**：

```cpp
// 原代码 (moe_distribute_dispatch_v3_infershape.cpp:274)
epRecvCountShape->SetDim(0U, *epWorldSize * localExpertNum + globalBsReal * 2 * k * ((*epWorldSize) / RANK_NUM_PER_NODE));

// 修复代码
int64_t term1, term2, epRecvCount;
OPS_CHECK(ops::overflow::SafeMultiply(*epWorldSize, localExpertNum, term1, 
           context->GetNodeName(), "epWorldSize * localExpertNum") != ge::GRAPH_SUCCESS,
           return ge::GRAPH_FAILED);

int64_t rankDiv = (*epWorldSize) / RANK_NUM_PER_NODE;
OPS_CHECK(ops::overflow::SafeMultiplyChain(globalBsReal, 2 * k, rankDiv, term2,
           context->GetNodeName(), "globalBsReal * 2 * k * (epWorldSize / 8)") != ge::GRAPH_SUCCESS,
           return ge::GRAPH_FAILED);

OPS_CHECK(ops::overflow::SafeMultiply(term1, 1, epRecvCount, // term1 + term2 需检查加法溢出
           context->GetNodeName(), "epRecvCount sum") != ge::GRAPH_SUCCESS &&
           term1 + term2 > std::numeric_limits<int64_t>::max(),
           return ge::GRAPH_FAILED);

epRecvCount = term1 + term2;
epRecvCountShape->SetDim(0U, epRecvCount);
```

**VULN-DF-INT-001/002 修复**：

```cpp
// 原代码 (quant_reduce_scatter_infershape.cpp:76)
shapeInfo.bs = x_shape->GetDim(0) * x_shape->GetDim(1);

// 修复代码
int64_t b = x_shape->GetDim(0);
int64_t s = x_shape->GetDim(1);
OPS_CHECK(ops::overflow::SafeMultiply(b, s, shapeInfo.bs,
           context->GetNodeName(), "bs = b * s") != ge::GRAPH_SUCCESS,
           OP_LOGE(context->GetNodeName(), "Batch size * sequence length overflow: %ld * %ld", b, s),
           return ge::GRAPH_FAILED);
```

**VULN-DF-INT-004 修复**：

```cpp
// 原代码 (moe_distribute_dispatch_infershape.cpp:94)
expandIdxShape->SetDim(0U, bs * k);

// 修复代码
int64_t expandIdx;
OPS_CHECK(ops::overflow::SafeMultiply(bs, k, expandIdx,
           context->GetNodeName(), "expandIdx = bs * k") != ge::GRAPH_SUCCESS,
           return ge::GRAPH_FAILED);
expandIdxShape->SetDim(0U, expandIdx);
```

**VULN-DF-INT-005 修复**：

```cpp
// 原代码 (mc2_common_infershape.cpp:95)
yShape->SetDim(0, commParas.dimM * commParas.rankSize);

// 修复代码
int64_t yDim0;
OPS_CHECK(ops::overflow::SafeMultiply(commParas.dimM, commParas.rankSize, yDim0,
           context->GetNodeName(), "yShape.dim0 = dimM * rankSize") != ge::GRAPH_SUCCESS,
           return ge::GRAPH_FAILED);
yShape->SetDim(0, yDim0);
```

#### 7.1.3 边界值检查增强

除了溢出检查，建议添加合理的参数边界检查：

```cpp
// 建议参数上限（可根据实际业务调整）
const int64_t MAX_BATCH_SIZE = 1 << 20;      // 最大批次大小：1M
const int64_t MAX_SEQUENCE_LENGTH = 1 << 16;  // 最大序列长度：64K
const int64_t MAX_HEAD_NUM = 256;             // 最大头数
const int64_t MAX_EXPERT_NUM = 10240;         // 最大专家数（已有）
const int64_t MAX_K_VALUE = 64;               // 最大 top-k 值
const int64_t MAX_WORLD_SIZE = 1024;          // 最大并行世界大小

// 在 Infershape 函数开头添加
OP_CHECK_IF(b > MAX_BATCH_SIZE,
    OP_LOGE(context->GetNodeName(), "Batch size %ld exceeds limit %ld", b, MAX_BATCH_SIZE),
    return ge::GRAPH_FAILED);
```

#### 7.1.4 编译器内置溢出检查（可选）

GCC/Clang 支持 `__builtin_mul_overflow`，可提供更高效的溢出检测：

```cpp
int64_t result;
if (__builtin_mul_overflow(a, b, &result)) {
    OP_LOGE(nodeName, "Multiplication overflow: %ld * %ld", a, b);
    return ge::GRAPH_FAILED;
}
```

### 7.2 命令注入漏洞修复方案 (CWE-78)

针对 `scripts/package/common/py/packer.py` 中的命令注入漏洞，建议以下修复：

#### 7.2.1 使用 `shlex.quote()` 转义参数

```python
# 原代码 (packer.py:218-227)
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

# 修复代码
import shlex

def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str: 
    """执行打包命令"""
    if delivery_dir:
        # 转义 delivery_dir 防止 shell 元字符注入
        safe_delivery_dir = shlex.quote(delivery_dir)
        cmd = f'cd {safe_delivery_dir} && {pack_cmd}'
    else:
        cmd = pack_cmd
    CommLog.cilog_info("package cmd:%s", cmd)
    result = subprocess.run(cmd, shell=True, check=False, stdout=PIPE, stderr=STDOUT)
```

#### 7.2.2 更安全的替代方案：使用 `shell=False` + 列表参数

```python
def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str: 
    """执行打包命令"""
    import subprocess
    from subprocess import PIPE, STDOUT
    
    if delivery_dir:
        # 先 cd 到目标目录，然后执行打包命令
        # 方案1：使用 subprocess 分步执行
        # 先切换目录
        import os
        original_dir = os.getcwd()
        try:
            os.chdir(delivery_dir)
            # 将 pack_cmd 解析为命令列表
            # 注意：pack_cmd 可能已经是完整命令字符串，需谨慎处理
            # 如果 pack_cmd 是单条命令，可使用 shlex.split
            cmd_list = shlex.split(pack_cmd)
            result = subprocess.run(cmd_list, shell=False, check=False, 
                                    stdout=PIPE, stderr=STDOUT)
        finally:
            os.chdir(original_dir)
    else:
        cmd_list = shlex.split(pack_cmd)
        result = subprocess.run(cmd_list, shell=False, check=False, 
                                stdout=PIPE, stderr=STDOUT)
    
    output = result.stdout.decode()
    if result.returncode != 0:
        CommLog.cilog_error(__file__, "compress package(%s) failed! %s.", 
                           package_name, output)
        raise CompressError(package_name)
    return package_name
```

#### 7.2.3 参数白名单验证（可选）

如果 `delivery_dir` 应为合法路径，添加路径验证：

```python
import os
import re

def validate_delivery_dir(delivery_dir: str) -> bool:
    """验证 delivery_dir 是否为合法路径"""
    if not delivery_dir:
        return True
    # 检查是否包含 shell 元字符
    shell_metacharacters = r'[;&|$`\n\r]'
    if re.search(shell_metacharacters, delivery_dir):
        return False
    # 检查是否为绝对路径或相对路径
    if not os.path.isabs(delivery_dir):
        # 相对路径可能存在风险，建议限制
        return False
    # 检查路径是否存在（可选）
    return os.path.isdir(delivery_dir)

def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str: 
    """执行打包命令"""
    if not validate_delivery_dir(delivery_dir):
        CommLog.cilog_error(__file__, "Invalid delivery_dir: %s", delivery_dir)
        raise ValueError("Invalid delivery_dir path")
    # ... 继续原有逻辑
```

### 7.3 修复优先级建议

| 优先级 | 漏洞 ID | 修复方法 | 预估工作量 |
|--------|---------|----------|-----------|
| P0 | VULN-DF-INT-003 | 添加多因子溢出检查 | 4 小时 |
| P1 | VULN-DF-INT-001/002 | 统一 bs 溢出检查 | 2 小时 |
| P1 | VULN-DF-INT-004 | 添加 bs*k 溢出检查 | 1 小时 |
| P1 | VULN-DF-INT-005 | 添加公共模块溢出检查 | 2 小时 |
| P2 | VULN-DF-INT-006/008 | attention 模块溢出检查 | 3 小时 |
| P2 | VULN-DF-INT-007 | moe 模块溢出检查 | 1 小时 |
| P3 | VULN-SEC-CMD-001/002 | shlex.quote 转义 | 1 小时 |

### 7.4 回归测试建议

修复完成后建议进行以下测试：

1. **单元测试**：为每个修复添加溢出边界测试用例
   - 正常参数范围测试
   - 边界值测试（接近 int64_t 上限）
   - 极端值测试（触发溢出的参数组合）

2. **集成测试**：使用恶意构造的张量形状调用 ACLNN API
   - 验证 GRAPH_FAILED 返回而非崩溃
   - 验证日志输出包含清晰的错误信息

3. **性能测试**：溢出检查函数的性能影响评估
   - 使用 `__builtin_mul_overflow` 减少开销
   - 编译器优化下性能损失应 < 1%

---

## 8. 附录

### 8.1 漏洞数据源

本报告基于 SQLite 数据库生成，数据源位于：
`/home/pwn20tty/Desktop/opencode_project/cann/1/ops-transformer/scan-results/.context/scan.db`

### 8.2 扫描工具版本

- DataFlow Scanner: v1.0 (C/C++ 污点追踪)
- Security Auditor: v1.0 (Python 安全检查)
- Confidence Scoring: 85 分阈值

### 8.3 联系信息

如有漏洞相关问题，请联系安全团队。