# 漏洞扫描报告 — 已确认漏洞

**项目**: triton-inference-server-ge-backend
**扫描时间**: 2026-04-22T10:30:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描针对 Triton Inference Server GE Backend 项目进行全面漏洞分析。该项目是华为昇腾 NPU 推理后端插件，作为 Triton Server 的自定义 backend 运行，接收来自远程客户端（HTTP/GRPC）的推理请求并通过华为 Ascend NPU 硬件执行模型推理。

**扫描范围**: 项目包含 11 个源文件，总计约 4,746 行 C++17 代码，涵盖 Backend API 入口、模型管理、推理引擎和调度器四个核心模块。

**关键发现**: 本次扫描共发现 29 个候选漏洞，经验证后确认 1 个真实漏洞。值得注意的是，已确认的漏洞为功能性逻辑缺陷（负载均衡算法失效），而非传统意义上的安全漏洞。该缺陷不会直接导致数据泄露或系统入侵，但可能影响系统性能和资源利用率。

**风险评估**: 该项目的攻击面主要位于 Backend API 入口点（`TRITONBACKEND_ModelInstanceExecute`），接收来自 Triton Server 的推理请求。由于配置文件和环境变量由部署管理员控制，远程攻击者无法直接修改这些输入。主要安全风险来自推理请求中的张量尺寸参数，可能导致整数溢出或内存越界，但这些漏洞在本次扫描中被归类为 LIKELY 或 POSSIBLE 状态，需要在生产环境中进一步验证。

**建议**: 优先修复已确认的负载均衡逻辑错误，同时关注待确认报告中的 High 级别整数溢出漏洞，在生产部署前进行全面的安全测试。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 13 | 44.8% |
| LIKELY | 10 | 34.5% |
| POSSIBLE | 5 | 17.2% |
| CONFIRMED | 1 | 3.4% |
| **总计** | **29** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Medium | 1 | 100.0% |
| **有效漏洞总计** | **1** | - |
| 误报 (FALSE_POSITIVE) | 13 | - |

### 1.3 Top 10 关键漏洞

1. **[SCHED-LOGIC-001]** Logic Error (Medium) - `src/scheduler.cpp:159` @ `Scheduler::SelectSingleInstance` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `TRITONBACKEND_ModelInstanceExecute@src/npu_ge.cpp` | rpc | semi_trusted | 作为 Triton Backend API 入口点，接收来自 Triton Server 的推理请求。这些请求最初来自远程客户端（HTTP/GRPC），经过 Triton Server 处理后传递给 backend。虽然 Triton Server 可能对请求进行了部分验证，但 backend 需要处理原始推理请求数据。 | 接收推理请求并调用 ProcessRequests 处理 |
| `ParseGeConfig@src/model_state.cpp` | env | trusted_admin | 解析 backend 配置，这些配置来自 Triton Server 的命令行参数（--backend-config），由部署管理员控制。攻击者无法直接修改这些配置。 | 解析 backend 命令行配置 JSON |
| `ParseModelConfig@src/model_state.cpp` | file | trusted_admin | 解析模型配置文件 config.pbtxt，该文件位于模型仓库目录中，由部署管理员准备。攻击者无法直接修改模型配置文件（需要管理员权限）。 | 解析 Triton 模型配置文件 |
| `FindModelFile@src/model_state.cpp` | file | trusted_admin | 查找模型文件（ONNX/TensorFlow pb），路径来自模型配置，由部署管理员控制。攻击者无法直接修改模型文件。 | 查找并加载模型文件 |
| `GetEnvVar@src/model_instance_state.cpp` | env | trusted_admin | 读取环境变量 GE_NPU_CONFIG，该环境变量由 Triton Server 启动脚本设置，由部署管理员控制。 | 读取 GE_NPU_CONFIG 环境变量 |
| `ProcessRequestInputsV2@src/inference.cpp` | rpc | semi_trusted | 处理来自 Triton Server 请求的输入数据。这些数据最初来自远程客户端推理请求，需要验证数据尺寸和类型。 | 处理推理请求的输入张量数据 |
| `SetDumpGraph@src/model_state.cpp` | file | trusted_admin | 设置图 dump 路径并执行清理命令。路径来自配置参数，由部署管理员控制。代码中有基本的命令注入过滤（检查 ; & \| 字符）。 | 设置 GE 图 dump 配置并执行清理命令 |

**其他攻击面**:
- Backend API: TRITONBACKEND_ModelInstanceExecute 接收推理请求
- 配置解析: ParseGeConfig 解析 backend 命令行配置
- 模型配置解析: ParseModelConfig 解析 config.pbtxt
- 模型加载: FindModelFile 查找并加载 ONNX/TensorFlow 模型
- 请求输入处理: ProcessRequestInputsV2 处理推理输入张量
- 命令执行: system() 在 SetDumpGraph 中执行路径清理命令（有基本过滤）
- 内存操作: aclrtMemcpy 在多处执行设备-主机内存复制
- JSON 解析: json::parse 解析 GE 配置
- 环境变量: getenv/setenv 读取和设置环境变量
- 文件系统遍历: std::filesystem 递归查找模型文件

---

## 3. Medium 漏洞 (1)

### [SCHED-LOGIC-001] Logic Error - Scheduler::SelectSingleInstance

**严重性**: Medium | **CWE**: CWE-682 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `src/scheduler.cpp:159-167` @ `Scheduler::SelectSingleInstance`
**模块**: scheduler

**描述**: SelectSingleInstance 中更新 selected_per_group 时，错误地遍历所有 group_infos 并给每个组都增加计数，而不是只更新选中实例所在的组。这导致负载均衡算法完全失效，所有组的负载计数都会同步增加，无法正确反映实际负载分布。

**漏洞代码** (`src/scheduler.cpp:159-167`)

```c
if (selected_instance) {
    // 找到selected_instance所在的组
    for (auto &group_info : group_infos) {  // 错误：遍历所有组
        selected_per_group[group_info.group_id]++;  // 所有组都增加计数
    }
}
```

**达成路径**

SelectInstancesWithLoadBalance -> SelectSingleInstance -> selected_per_group (错误的计数逻辑)

**验证说明**: 逻辑错误已确认：SelectSingleInstance 在159-167行错误地遍历所有 group_infos 并递增每个组的计数，而非仅递增选中实例所属组的计数。正确的实现应为 `selected_per_group[selected_instance->group_id]++`。此错误导致负载均衡完全失效。由于这是功能性逻辑缺陷而非安全漏洞，严重性降级为 Medium。上下文扣分：内部调度器函数(-15)，但影响核心功能完整性(+40 adjustment)。

**评分明细**: base: 30 | reachability: 5 | controllability: 25 | mitigations: 0 | context: -15 | cross_file: 0 | adjustment: 40

**深度分析**

**根因分析**: 通过对 `src/scheduler.cpp` 第 159-167 行代码的深入分析，确认该逻辑错误的根本原因是开发者误解了负载均衡算法的计数更新逻辑。正确的算法应该在选中某个实例后，仅更新该实例所属组的计数，以准确追踪各组被分配的任务数量。然而，当前代码错误地遍历所有 `group_infos` 并递增每个组的计数：

```cpp
// 错误代码 (src/scheduler.cpp:159-166)
if (selected_instance) {
    // 找到selected_instance所在的组
    for (auto &group_info : group_infos) {  // 错误：遍历所有组
        selected_per_group[group_info.group_id]++;  // 所有组都增加计数
    }
}
```

正确的实现应该直接访问选中实例的组 ID：

```cpp
// 正确代码
if (selected_instance) {
    selected_per_group[selected_instance->group_id]++;
}
```

**影响分析**: 
- **负载均衡失效**: 所有组的负载计数同步增加，导致 `CreateGroupLoadInfo` 中的 `current_load + selected_count` 计算无法反映真实的负载分布
- **调度决策错误**: `FindCandidateGroups` 基于错误的负载数据选择候选组，可能导致某些 NPU 设备过载而其他设备空闲
- **性能影响**: 在多实例并行推理场景下，负载分配不均衡可能导致整体吞吐量下降，部分请求延迟增加

**潜在利用场景**: 此漏洞为功能性缺陷，不涉及内存安全或数据泄露，攻击者无法利用此漏洞获取敏感信息或提升权限。但在高负载生产环境中，可能被攻击者利用进行资源耗尽攻击（通过发送大量请求导致部分 NPU 设备过载）。

**修复方式**: 建议直接修改第 165 行，使用选中实例的 `group_id` 属性：

```cpp
// src/scheduler.cpp:159-167 修复后
if (selected_instance) {
    // 仅更新选中实例所属组的计数
    selected_per_group[selected_instance->group_id]++;
}
```

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| scheduler | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **0** | **1** | **0** | **1** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-682 | 1 | 100.0% |

---

## 6. 修复建议

### 优先级 1: 立即修复 (Critical/High)

本次扫描未发现 Critical 或 High 级别的已确认漏洞。建议关注待确认报告中的以下高危漏洞：

- **VULN-INF-005**: shape 值无上限验证 - 建议在 `ProcessRequestInputsV2` 中添加张量尺寸上限检查
- **VULN-INF-002/VULN-INF-003/VULN-SEC-INT-005**: 整数溢出漏洞 - 建议在内存分配前进行溢出检查

### 优先级 2: 短期修复 (Medium)

**SCHED-LOGIC-001: 负载均衡逻辑错误**

修复位置: `src/scheduler.cpp:165`

修复代码示例:

```cpp
// 修复前 (第 159-167 行)
if (selected_instance) {
    for (auto &group_info : group_infos) {
        selected_per_group[group_info.group_id]++;
    }
}

// 修复后
if (selected_instance) {
    // 仅更新选中实例所属组的计数
    selected_per_group[selected_instance->group_id]++;
}
```

**验证修复**: 修复后建议进行以下测试：
1. 单元测试：验证 `SelectInstancesWithLoadBalance` 在多组场景下的负载分配比例
2. 性能测试：在多 NPU 设备环境下验证推理请求的吞吐量和延迟分布
3. 压力测试：高并发场景下的调度器稳定性

### 优先级 3: 代码质量改进

本次扫描发现的已确认漏洞为逻辑缺陷，建议在开发流程中引入以下改进：

1. **单元测试覆盖**: 为调度器模块添加完整的单元测试，特别是负载均衡算法的边界条件测试
2. **代码审查**: 对于涉及计数器、索引计算的代码段，进行专门的逻辑正确性审查
3. **静态分析**: 集成静态分析工具（如 Clang-Tidy）检测潜在的逻辑错误

---

## 7. 生产环境风险评估

### 漏洞影响评估

| 漏洞 | 安全影响 | 业务影响 | 修复难度 |
|------|----------|----------|----------|
| SCHED-LOGIC-001 | 无（功能性缺陷） | 中等（性能下降） | 低（单行修改） |

### 部署建议

在将此 backend 部署到生产 Triton Server 环境之前，建议：

1. **完成漏洞修复**: 确认并修复已确认的负载均衡逻辑错误
2. **压力测试**: 在模拟生产负载下验证修复后的调度器行为
3. **监控告警**: 配置 NPU 设备负载监控，及时发现异常的负载分配
4. **关注待确认漏洞**: 定期审查待确认报告中的 High 级别漏洞，在生产环境中观察是否触发

### 安全边界分析

根据项目信任边界分析：

- **Network Interface (Triton Server)**: 远程客户端通过 HTTP/GRPC 发送推理请求，这是主要的外部攻击面。Backend 接收的输入数据（张量形状、尺寸）来自此边界。
- **Backend Plugin**: 本项目作为 Triton Server 的插件，与 Triton Core 之间存在信任边界，但 API 调用遵循 Triton 规范，风险可控。
- **Model Repository**: 配置文件和模型文件由部署管理员控制，攻击者无法直接修改。

**结论**: 当前已确认漏洞不构成安全威胁，但需关注输入验证相关的待确认漏洞，建议在生产部署前进行全面的安全测试。

---

**报告生成时间**: 2026-04-22
**报告生成工具**: OpenCode Multi-Agent Vulnerability Scanner v1.0
