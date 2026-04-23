# 漏洞扫描报告 — 待确认漏洞

**项目**: ascend-transformer-boost  
**扫描时间**: 2026-04-22T07:30:54.131Z  
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本报告包含 **12 个待确认漏洞**，其中包括 4 个 High 级别、6 个 Medium 级别和 2 个 Low 级别。这些漏洞已通过数据流分析或安全审计识别，置信度介于 45-75 分，需要进一步人工验证。

### 风险概览

待确认漏洞主要集中在三类风险领域：

| 风险类别 | 漏洞数量 | 最高严重性 | 典型问题 |
|---------|---------|-----------|---------|
| **分布式通信安全** | 4 | High | Socket bootstrap 和 HCCL 通信缺乏身份验证，节点可被伪造或操控 |
| **环境变量注入** | 2 | Medium | ATB_HOME_PATH 等环境变量缺乏路径验证，可加载恶意配置 |
| **工作区计算溢出** | 2 | High | 张量维度计算中存在整数溢出风险，可导致缓冲区分配异常 |

### 关键发现摘要

**SEC-002（身份验证绕过）**：Socket bootstrap 服务器接收客户端 Rank ID 时仅进行边界检查，无身份验证。攻击者可连接到 bootstrap Socket 并声明任意有效 Rank ID，实现节点伪造。当前 Socket 默认绑定 127.0.0.1，限制攻击范围为本地用户，但计划支持多机通信时此问题将变得严重。

**VULN-DF-OPS-001（工作区整数溢出）**：`workspaceSize` 从用户控制的张量维度计算。多个 `AlignInt` 操作可导致整数溢出。攻击向量：大张量维度使工作区大小回绕到小值，导致内存分配不足，后续操作溢出缓冲区。

**VULN-DF-HCCL-001（路径遍历）**：`rankTableFile` 参数从 Python API 直接传递给 `HcclCommInitClusterInfo`。虽然 `PathCheckAndRegular` 使用 `realpath` 进行规范化，但缺乏边界验证。攻击者可指定任意可访问的文件路径进行 HCCL 配置注入。

### 建议处理顺序

根据风险严重性和修复依赖关系：

1. **P1（本周）**：SEC-002、SEC-005、VULN-DF-HCCL-001、VULN-DF-OPS-001
2. **P2（本月）**：其他 LIKELY 和 POSSIBLE 级别漏洞

完整修复方案请参考 `report_confirmed.md` 第 7 节"修复建议"。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 11 | 50.0% |
| FALSE_POSITIVE | 7 | 31.8% |
| CONFIRMED | 3 | 13.6% |
| POSSIBLE | 1 | 4.5% |
| **总计** | **22** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 4 | 33.3% |
| Medium | 6 | 50.0% |
| Low | 2 | 16.7% |
| **有效漏洞总计** | **12** | - |
| 误报 (FALSE_POSITIVE) | 7 | - |

### 1.3 Top 10 关键漏洞

1. **[SEC-002]** authentication_bypass (High) - `src/kernels/lcal/src/tools/socket/lcal_sock_exchange.cpp:219` @ `LcalSockExchange::Accept` | 置信度: 75
2. **[VULN-DF-OPS-001]** integer_overflow (High) - `src/atb/operation/operation_base.cpp:543` @ `OperationBase::SetupThrow` | 置信度: 75
3. **[VULN-DF-HCCL-001]** path_traversal (High) - `src/atb/runner/hccl_runner.cpp:104` @ `HcclRunner::CreateHcclCommInMulitProcessByRankFile` | 置信度: 70
4. **[VULN-DF-HCCL-003]** buffer_overflow (High) - `src/ops/ops_infer/all_gatherv/all_gatherv_hccl_runner.cpp:48` @ `AllGatherVHcclRunner::ExecuteImpl` | 置信度: 60
5. **[SEC-004]** configuration_manipulation (Medium) - `src/atb/utils/config.cpp:82` @ `Config::InitAtbHomePath` | 置信度: 75
6. **[SEC-005]** impersonation (Medium) - `src/kernels/lcal/src/tools/socket/lcal_sock_exchange.cpp:78` @ `LcalSockExchange::GetNodeNum` | 置信度: 75
7. **[VULN-DF-HCCL-002]** resource_injection (Medium) - `src/atb/runner/hccl_runner.cpp:164` @ `HcclRunner::CreateHcclRootInfo` | 置信度: 75
8. **[VULN-DF-ENV-002]** buffer_overflow (Medium) - `src/atb/utils/config.cpp:84` @ `Config::InitAtbHomePath` | 置信度: 75
9. **[SEC-006]** resource_exhaustion (Medium) - `src/torch_atb/bindings.cpp:42` @ `set_buffer_size` | 置信度: 65
10. **[VULN-DF-NET-001]** authentication_bypass (Medium) - `src/kernels/lcal/src/tools/socket/lcal_sock_exchange.cpp:232` @ `LcalSockExchange::Accept` | 置信度: 60

---

## 2. 攻击面分析

本次扫描识别了以下关键攻击入口：

| 入口类型 | 位置 | 信任等级 | 可达性 |
|---------|------|---------|--------|
| Socket Bootstrap | `lcal_sock_exchange.cpp` | untrusted_local | 本地用户可连接到 bootstrap Socket |
| HCCL 配置参数 | `hccl_runner.cpp` | semi_trusted | 用户可提供 rankTableFile/commDomain |
| 玥量维度 | `operation_base.cpp` | untrusted_user | 张量形状影响工作区计算 |
| 环境变量 | `config.cpp` | semi_trusted | 部署脚本可控制 ATB_HOME_PATH |

---

## 3. High 漏洞详情 (4)

### [SEC-002] authentication_bypass - LcalSockExchange::Accept

**严重性**: High | **CWE**: CWE-287 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/kernels/lcal/src/tools/socket/lcal_sock_exchange.cpp:219-247` @ `LcalSockExchange::Accept`  
**模块**: LCAL Communication Layer

**描述**: Socket bootstrap 通信缺乏身份验证。`LcalSockExchange::Accept()` 函数从已连接客户端接收 Rank ID 而不进行任何加密验证。攻击者可连接到 bootstrap 服务器并声明任意有效 Rank ID，可能中断分布式训练或伪造合法节点。

**漏洞代码** (`src/kernels/lcal/src/tools/socket/lcal_sock_exchange.cpp:219-247`)

```c
int LcalSockExchange::Accept()
{
    // ...
    int rank = 0;
    if (Recv(fd, &rank, sizeof(rank), 0) <= 0) { ... }
    if (rank >= rankSize_ || rank <= 0 || clientFds_[rank] >= 0) {
        // 仅边界检查，无身份验证
    }
    clientFds_[rank] = fd; // Rank 伪造可能
}
```

**数据流路径**

网络 Socket 连接 → Recv Rank ID → 仅边界检查 → clientFds_[rank] 分配 → 攻击者控制 Rank 身份

**验证说明**: 已确认漏洞：LcalSockExchange::Accept() 从已连接客户端接收 Rank ID 而不进行加密验证。服务器在第 237 行仅执行边界检查（rank >= rankSize_ || rank <= 0 || clientFds_[rank] >= 0），非身份验证。连接到 bootstrap Socket 的攻击者可声明任意有效 Rank ID，实现节点伪造。Socket 默认绑定 127.0.0.1（本地），但 BootstrapGetUniqueId() 通过 LCAL_COMM_ID 环境变量允许外部 IP 且无服务器端限制。多机支持已规划（第 147 行错误："暂不支持多机"），启用时将变成严重问题。当前仅限本地配置将攻击限制为本地入侵场景。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-OPS-001] integer_overflow - OperationBase::SetupThrow

**严重性**: High | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/atb/operation/operation_base.cpp:543-550` @ `OperationBase::SetupThrow`  
**模块**: atb_operation  
**跨模块**: torch_atb_bindings → atb_operation → atb_runner

**描述**: workspaceSize 从用户控制的张量维度计算。对用户派生的大值执行多个 AlignInt 操作可能导致工作区分配中的整数溢出。

**漏洞代码** (`src/atb/operation/operation_base.cpp:543-550`)

```c
runnerVariantPack_.workspaceBufferSize =
    static_cast<uint64_t>(TensorUtil::AlignInt(GetTotalWorkspaceBufferSize(), WORKSPACE_ALIGN));
runnerVariantPack_.intermediateBufferSize =
    static_cast<uint64_t>(TensorUtil::AlignInt(runner_->GetIntermediateBufferSize(), WORKSPACE_ALIGN));
workspaceSize = runnerVariantPack_.workspaceBufferSize + runnerVariantPack_.intermediateBufferSize;
```

**数据流路径**

Python 张量维度 [SOURCE]
→ InferShape → TensorDesc.shape [TAINTED]
→ GetTotalWorkspaceBufferSize() → workspaceBufferSize [TAINTED]
→ AlignInt 对齐 [TAINTED]
→ workspaceSize = sum [SINK]
→ 内存分配

**验证说明**: 已在工作区大小计算链中验证整数溢出：1) AlignInt(value+align-1) 对大值可能溢出，2) GetTotalWorkspaceBufferSize 累加多个流工作区大小无溢出检查，3) workspaceSize = workspaceBufferSize + intermediateBufferSize 缺乏溢出检查。用户控制的张量维度从 Python API 通过 InferShape 流向工作区计算。CalcTensorDataSize 对张量大小有溢出检查但非工作区分配。未发现工作区大小上限。攻击向量：大张量维度导致工作区大小回绕到小值，导致内存分配不足和后续缓冲区溢出。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-HCCL-001] path_traversal - HcclRunner::CreateHcclCommInMulitProcessByRankFile

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/atb/runner/hccl_runner.cpp:104-110` @ `HcclRunner::CreateHcclCommInMulitProcessByRankFile`  
**模块**: atb_runner  
**跨模块**: torch_atb_bindings → atb_runner

**描述**: rankTableFile 路径从 Python 参数传递给 HcclCommInitClusterInfo。虽然 PathCheckAndRegular 使用 realpath 进行规范化，但来自不可信 Python 输入的恶意 rank table 文件路径可能导致攻击者控制的 HCCL 配置初始化。

**漏洞代码** (`src/atb/runner/hccl_runner.cpp:104-110`)

```c
std::string resolvePath = Mki::FileSystem::PathCheckAndRegular(rankTableFile_);
if (resolvePath == "") { return HcclCommSharedPtr(); }
auto ret = HcclCommInitClusterInfo(resolvePath.c_str(), rank_, &newHcclComm);
```

**数据流路径**

Python rankTableFile 参数 [SOURCE]
→ AllGatherParam.rankTableFile (bindings.cpp:717)
→ HcclRunner 构造函数 (hccl_runner.cpp:35)
→ rankTableFile_ [TAINTED]
→ PathCheckAndRegular [SANITIZATION]
→ HcclCommInitClusterInfo [SINK]

**验证说明**: 已确认路径遍历漏洞。PathCheckAndRegular 通过 realpath 规范化提供部分净化，但缺乏边界验证。攻击者可指定任意可访问的文件路径用于 HCCL 配置，可能控制分布式通信设置。攻击需要文件存在且包含有效 HCCL rank table 格式。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-HCCL-003] buffer_overflow - AllGatherVHcclRunner::ExecuteImpl

**严重性**: High | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/ops/ops_infer/all_gatherv/all_gatherv_hccl_runner.cpp:48-55` @ `AllGatherVHcclRunner::ExecuteImpl`  
**模块**: ops_infer  
**跨模块**: torch_atb_bindings → ops_infer → atb_runner

**描述**: HcclAllGatherV 的 recvCounts 和 rdispls 参数直接来自用户提供的 hostData 张量而无验证。恶意值可能导致 HCCL 分布式通信中的缓冲区溢出，损坏 outTensors deviceData 缓冲区。

**漏洞代码** (`src/ops/ops_infer/all_gatherv/all_gatherv_hccl_runner.cpp:48-55`)

```c
HcclResult ret = HcclAllGatherV(runnerVariantPack.inTensors[0].deviceData,
    *(static_cast<int64_t *>(runnerVariantPack.inTensors[1].hostData)),  // 1 sendCount
    runnerVariantPack.outTensors[0].deviceData,
    runnerVariantPack.inTensors[2].hostData,  // 2 recvCounts
    runnerVariantPack.inTensors[3].hostData,  // 3 rdispls
    GetHcclDtype(runnerVariantPack.inTensors[0].desc.dtype),
    hcclComm_.get(), GetExecuteStream(runnerVariantPack.context));
```

**数据流路径**

Python 张量 hostData [SOURCE]
→ ConvertToAtbTensor (utils.cpp:69)
→ runnerVariantPack.inTensors[2].hostData (recvCounts) [TAINTED]
→ runnerVariantPack.inTensors[3].hostData (rdispls) [TAINTED]
→ HcclAllGatherV [SINK]
→ HCCL 网络通信使用未验证的偏移/大小

**验证说明**: SetupCheckImpl 对 recvCounts/rdispls 提供全面的边界检查（第 159-181 行），但验证仅在 Setup 阶段执行。ExecuteImpl 直接将 hostData 传递给 HcclAllGatherV 而无验证。C++ API 用户可绕过 Setup 并直接调用 Execute（见 runner_test.cpp:35,46），使验证在某些使用模式中无效。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: -15

---

## 4. Medium 漏洞详情 (6)

### [SEC-004] configuration_manipulation - Config::InitAtbHomePath

**严重性**: Medium | **CWE**: CWE-15 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/atb/utils/config.cpp:82-93` @ `Config::InitAtbHomePath`  
**模块**: Utilities

**描述**: ATB_HOME_PATH 环境变量读取时缺乏路径验证。InitAtbHomePath() 函数读取环境变量并仅进行长度检查（12800 字符）后直接存储为 atbHomePath_。无路径规范化或净化，可能允许路径操控攻击。

**漏洞代码** (`src/atb/utils/config.cpp:82-93`)

```c
void Config::InitAtbHomePath()
{
    const char *envStr = std::getenv("ATB_HOME_PATH");
    if (!envStr) { return; }
    if (strlen(envStr) > MAX_ENV_STRING_LEN) { return; } // 仅长度检查
    atbHomePath_ = std::string(envStr); // 无路径验证
}
```

**数据流路径**

ATB_HOME_PATH 环境变量 → getenv() → strlen 检查 → atbHomePath_ 字符串存储 → 用于库/配置路径

**验证说明**: LIKELY：有效的配置信任边界问题。ATB_HOME_PATH 环境变量缺乏路径规范化（PathCheckAndRegular 用于其他文件路径但此处未用）。路径用于加载 .ini 配置文件，攻击者控制环境变量时可加载任意配置文件。攻击需要进程级环境变量控制（通常为管理员/部署脚本）。因攻击面有限但仍对多租户或容器化部署存在真实安全风险，严重性保持 Medium。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-005] impersonation - LcalSockExchange::GetNodeNum

**严重性**: Medium | **CWE**: CWE-287 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/kernels/lcal/src/tools/socket/lcal_sock_exchange.cpp:78-123` @ `LcalSockExchange::GetNodeNum`  
**模块**: LCAL Communication Layer

**描述**: UUID 交换用于节点计数时缺乏加密验证。在 GetNodeNum() 中，服务器从已连接客户端接收 UUID 字符串并用于计算唯一节点。但 UUID 仅是 /proc/sys/kernel/random/boot_id 内容而无身份验证。攻击者可发送任意 UUID 操控节点计数。

**漏洞代码** (`src/kernels/lcal/src/tools/socket/lcal_sock_exchange.cpp:78-123`)

```c
int LcalSockExchange::GetNodeNum()
{
    // ...
    ifstream fileStream("/proc/sys/kernel/random/boot_id");
    // ...
    if (IsServer()) {
        for (int i = 1; i < rankSize_; ++i) {
            Recv(clientFds_[i], uuid.data(), uuid.size(), 0); // 无验证
            uuidSet.insert(uuid);
        }
    }
}
```

**数据流路径**

/proc UUID → 通过 Socket Send/Recv → uuidSet.insert() → nodeNum 计算 → 攻击者可操控

**验证说明**: 已确认漏洞：GetNodeNum() 从客户端接收 UUID 字符串而无加密验证。服务器从 /proc/sys/kernel/random/boot_id 读取本地 boot_id，客户端通过 Socket 发送。服务器在第 103 行将接收的 UUID 插入 uuidSet 而无验证。攻击者可发送任意 UUID 操控节点计数计算。这影响分布式训练初始化。错误的 nodeNum 可能导致训练使用错误的资源分配。与 SEC-002 相同的可达性约束（本地默认，LCAL_COMM_ID 可配置）。影响低于 SEC-002，因为影响节点计数而非直接伪造。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-HCCL-002] resource_injection - HcclRunner::CreateHcclRootInfo

**严重性**: Medium | **CWE**: CWE-99 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/atb/runner/hccl_runner.cpp:164-165` @ `HcclRunner::CreateHcclRootInfo`  
**模块**: atb_runner  
**跨模块**: torch_atb_bindings → atb_runner

**描述**: 共享内存名称从用户提供的 commDomain 构建而无验证。可预测的共享内存名称可能允许多进程环境中的命名空间碰撞攻击。

**漏洞代码** (`src/atb/runner/hccl_runner.cpp:164-165`)

```c
std::string shmName = "hcclShareMem" + commDomain_;
Mki::ShareMemory shm(shmName, sizeof(atb::CommInitInfo) + rankSize_ * sizeof(bool));
```

**数据流路径**

Python commDomain 参数 [SOURCE]
→ AllGatherParam.commDomain (bindings.cpp:718)
→ HcclRunner commDomain_ [TAINTED]
→ shmName = "hcclShareMem" + commDomain_ [SINK]
→ ShareMemory(shmName)

**验证说明**: 已确认资源注入漏洞。用户提供的 commDomain 直接拼接创建共享内存名称而无验证。攻击者可操控共享内存命名空间，在多进程分布式训练环境中造成碰撞攻击。影响受平台共享内存命名约束限制。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-ENV-002] buffer_overflow - Config::InitAtbHomePath

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/atb/utils/config.cpp:84-92` @ `Config::InitAtbHomePath`  
**模块**: atb_utils

**描述**: ATB_HOME_PATH 环境变量仅进行长度检查（MAX_ENV_STRING_LEN=12800）。未应用截断，仅记录错误。路径内容未验证安全字符。

**漏洞代码** (`src/atb/utils/config.cpp:84-92`)

```c
const char *envStr = std::getenv("ATB_HOME_PATH");
if (!envStr) { return; }
if (strlen(envStr) > MAX_ENV_STRING_LEN) {
    ATB_LOG(ERROR) << "ATB_HOME_PATH length is more than " << MAX_ENV_STRING_LEN;
    return;
}
atbHomePath_ = std::string(envStr);
```

**数据流路径**

ATB_HOME_PATH getenv [SOURCE]
→ 仅 strlen 检查 [PARTIAL VALIDATION]
→ atbHomePath_ [SINK]
→ 用于内核缓存和库路径

**验证说明**: 通过 ATB_HOME_PATH 可能进行路径注入。无路径遍历（../）、绝对路径或特殊字符验证。长度检查（12800）仅防止缓冲区溢出（std::string 已安全），非内容注入。路径用于加载 .ini 配置文件。攻击者控制环境变量时可加载恶意配置。需要本地访问设置环境变量。CWE 应为 CWE-73（外部控制文件名）而非 CWE-120。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-006] resource_exhaustion - set_buffer_size

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/torch_atb/bindings.cpp:42-43` @ `set_buffer_size`  
**模块**: PyTorch Bindings  
**跨模块**: PyTorch Bindings → Memory Manager

**描述**: set_buffer_size Python API 接受任意 uint64_t 而无上限验证。MemoryManager::SetBufferSize() 函数从 Python 绑定接受任意 uint64_t 值而不检查不合理值。可能导致过度内存分配，引起内存耗尽或拒绝服务。

**漏洞代码** (`src/torch_atb/bindings.cpp:42-43`)

```c
m.def("set_buffer_size", static_cast<void(*)(uint64_t)>(&TorchAtb::MemoryManager::SetBufferSize),
      py::arg("bytes"), "Set default workspace buffer size (bytes)");
// SetBufferSize 实现中无边界验证
```

**数据流路径**

Python 用户输入 → set_buffer_size 绑定 → MemoryManager::SetBufferSize(uint64_t size) → bufferSize_ = size → workspaceBuffers_ 分配

**验证说明**: set_buffer_size 接受任意 uint64_t 而无上限验证。用户可请求不合理内存分配导致 DoS。PyTorch/NPU 通过拒绝荒谬分配提供隐式缓解，但 API 层无显式验证。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: -10 | cross_file: 0

---

### [VULN-DF-NET-001] authentication_bypass - LcalSockExchange::Accept

**严重性**: Medium（原评估: Critical → 验证后: Medium）| **CWE**: CWE-287 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/kernels/lcal/src/tools/socket/lcal_sock_exchange.cpp:232-243` @ `LcalSockExchange::Accept`  
**模块**: kernels_lcal

**描述**: Socket bootstrap 从网络接受 Rank ID 而无身份验证确认。连接到 bootstrap 服务器的攻击者可声明任意有效 Rank ID（1 到 rankSize-1），可能在分布式通信中伪造其他节点。

**漏洞代码** (`src/kernels/lcal/src/tools/socket/lcal_sock_exchange.cpp:232-243`)

```c
if (Recv(fd, &rank, sizeof(rank), 0) <= 0) { ... }
if (rank >= rankSize_ || rank <= 0 || clientFds_[rank] >= 0) {
    MKI_LOG(ERROR) << "Server side recv invalid rank id " << rank;
    return LCAL_ERROR_INTERNAL;
}
clientFds_[rank] = fd;
```

**数据流路径**

Socket recv() [SOURCE] → Rank ID [TAINTED]
→ 仅范围检查 (rank >= rankSize_ || rank <= 0) [INSUFFICIENT]
→ clientFds_[rank] = fd [SINK]
→ 用于后续通信操作

**验证说明**: Socket bootstrap 从网络接受 Rank ID 而无身份验证。服务器绑定到 127.0.0.1（第 135 行），将攻击面限制为本地用户。本地攻击者可伪造任意 Rank（1 到 rankSize_-1），可能中断分布式计算完整性。无 Rank 声明的加密验证。

**评分明细**: base: 30 | reachability: 5 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. Low 漏洞详情 (2)

### [VULN-DF-ENV-001] improper_input_validation - Config::Config

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/atb/utils/config.cpp:37-39` @ `Config::Config`  
**模块**: atb_utils

**描述**: ATB_WORKSPACE_MEM_ALLOC_ALG_TYPE 环境变量使用 strtol 解析而无错误检查或边界验证。无效输入可能导致意外内存分配算法选择。

**漏洞代码** (`src/atb/utils/config.cpp:37-39`)

```c
const char *envStr = std::getenv("ATB_WORKSPACE_MEM_ALLOC_ALG_TYPE");
workspaceMemAllocAlgType_ = envStr != nullptr ? static_cast<uint32_t>(strtol(envStr, nullptr, DECIMAL)) :
                                                DEFAULT_WORKSPACE_MEM_ALLOC_ALG_TYPE;
```

**数据流路径**

ATB_WORKSPACE_MEM_ALLOC_ALG_TYPE getenv [SOURCE]
→ strtol(envStr, nullptr, DECIMAL) [TAINTED]
→ workspaceMemAllocAlgType_ [SINK]
→ 内存分配算法选择

**验证说明**: strtol 缺乏错误检查但影响仅限于内存分配器选择并有回退处理。类 switch 逻辑覆盖所有情况（0,1,2,else）。极大数值溢出导致 NoblockMemAllocationSolver。代码质量问题而非安全漏洞。

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-NET-002] improper_input_validation - LcalSockExchange::GetIpAndPort

**严重性**: Low（原评估: High → 验证后: Low）| **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/kernels/lcal/src/tools/socket/lcal_sock_exchange.cpp:127-137` @ `LcalSockExchange::GetIpAndPort`  
**模块**: kernels_lcal

**描述**: LCAL_COMM_ID 环境变量解析 IP:port 而无完整验证。恶意环境变量可能将 bootstrap 连接重定向到攻击者控制的服务器。

**漏洞代码** (`src/kernels/lcal/src/tools/socket/lcal_sock_exchange.cpp:127-137`)

```c
const char* env = Mki::GetEnv("LCAL_COMM_ID");
if (env == nullptr or ParseIpAndPort(env, ip_, port_) != LCAL_SUCCESS) {
    ip_ = LCAL_LOCAL_SOCK_IP;
    port_ = LCAL_DEFAULT_SOCK_PORT;
}
port_ += commDomain_;
```

**数据流路径**

LCAL_COMM_ID getenv [SOURCE]
→ ParseIpAndPort [TAINTED]
→ ip_, port_ [TAINTED]
→ inet_addr(ip_.c_str()) [SINK]
→ socket connect/bind

**验证说明**: 环境变量 LCAL_COMM_ID 已解析但 IP 硬编码为 127.0.0.1（第 135 行使用 LCAL_LOCAL_SOCK_IP，而非 ip_）。Prepare() 对客户端验证本地。仅端口可控。数据流引用 BootstrapGetUniqueId（第 348 行）中的 inet_addr(ip_.c_str())，而非 GetIpAndPort。位置不匹配。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| LCAL Communication Layer | 0 | 1 | 1 | 0 | 2 |
| PyTorch Bindings | 0 | 0 | 1 | 0 | 1 |
| Utilities | 0 | 0 | 1 | 0 | 1 |
| atb_operation | 0 | 1 | 0 | 0 | 1 |
| atb_runner | 0 | 1 | 1 | 0 | 2 |
| atb_utils | 0 | 0 | 1 | 1 | 2 |
| kernels_lcal | 0 | 0 | 1 | 1 | 2 |
| ops_infer | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **4** | **6** | **2** | **12** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-287 | 3 | 25.0% |
| CWE-20 | 2 | 16.7% |
| CWE-120 | 2 | 16.7% |
| CWE-99 | 1 | 8.3% |
| CWE-400 | 1 | 8.3% |
| CWE-22 | 1 | 8.3% |
| CWE-190 | 1 | 8.3% |
| CWE-15 | 1 | 8.3% |

---

## 8. 后续行动建议

### 8.1 人工验证优先级

以下漏洞建议进行人工代码审查验证：

| 优先级 | 漏洞 ID | 原因 |
|--------|---------|------|
| 高 | SEC-002, VULN-DF-OPS-001 | High 严重性，置信度 ≥ 70 |
| 高 | VULN-DF-HCCL-001, VULN-DF-HCCL-003 | 分布式通信安全风险 |
| 中 | SEC-004, VULN-DF-ENV-002 | 环境变量注入路径 |
| 中 | SEC-005, VULN-DF-HCCL-002 | 通信层身份验证 |
| 低 | VULN-DF-ENV-001, VULN-DF-NET-002 | Low 严重性或位置不匹配 |

### 8.2 完整修复方案参考

详细修复方案请参阅 `report_confirmed.md` 第 7 节"修复建议"，包含：

- **P0 立即修复漏洞**（SEC-001, VULN-DF-TENSOR-001, VULN-DF-MEM-001）
- **P1 本周修复漏洞**（SEC-002, SEC-005, VULN-DF-HCCL-001, VULN-DF-OPS-001）
- **P2 本月修复漏洞**（其他 LIKELY/POSSIBLE 级别）
- 各漏洞详细修复代码示例
- 次要缓解措施建议

### 8.3 相关深度分析报告

以下 CONFIRMED 漏洞有详细的深度分析报告：

- `{SCAN_OUTPUT}/details/SEC-001.md` — 自定义分配器任意代码执行
- `{SCAN_OUTPUT}/details/VULN-DF-TENSOR-001.md` — 张量指针缓冲区溢出
- `{SCAN_OUTPUT}/details/VULN-DF-MEM-001.md` — 缓冲区大小整数溢出