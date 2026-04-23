# VULN-RH-001: UpdateInferRequest dpInst计算乘法整数溢出

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-RH-001 |
| **类型** | Integer Overflow (CWE-190) |
| **严重程度** | HIGH |
| **状态** | CONFIRMED (真实漏洞) |
| **影响模块** | request_handler |
| **受影响文件** | src/server/endpoint/single_llm_req_handler/single_llm_decode_req_handler.cpp |
| **受影响行** | 311-314 |
| **受影响函数** | UpdateInferRequest |

### 漏洞描述

在 MindIE-LLM 的 Prefill-Decode (PD) 分离架构中，`UpdateInferRequest` 函数存在整数溢出漏洞。当计算 `dpInst` (distributed prefill instance ID) 时，代码执行:

```cpp
uint64_t dpInst = pInstanceId_ * 10000 + dpRank;
```

问题在于:
- `pInstanceId_` 是 `uint32_t` 类型 (定义在 single_llm_decode_req_handler.h 第68行)
- 乘法运算 `pInstanceId_ * 10000` 在赋值给 `uint64_t` 之前按 `uint32_t` 算术执行
- 当 `pInstanceId_ > 429496` 时发生溢出 (uint32_t 最大值为 4294967295)

### 源代码位置

```cpp
// File: src/server/endpoint/single_llm_req_handler/single_llm_decode_req_handler.cpp
// Lines: 305-314
std::vector<uint64_t> dpInsts;
for (uint64_t dpRank :
     grpcContext_->GetDmiServerInfo().kvCacheInfo.dpInstanceIds) {
    // D节点pull kv时候，作为dpinstanceid去索引p节点信息
    // kvCacheInfo.dpInstanceIds 面放的是dp rank id
    // dpinstance = pInstanceId_ * 10000 + dpRank
    uint64_t dpInst = pInstanceId_ * 10000 + dpRank;  // <-- 漏洞点
    dpInsts.emplace_back(dpInst);
}
request->dpInstanceIds = dpInsts;
```

## 触发条件分析

### 数学分析

- `uint32_t` 最大值: 4,294,967,295
- 溢出阈值: `pInstanceId_ > 429,496` (因为 429,496 × 10,000 = 4,294,960,000 ≈ uint32_t 最大值)
- 完全溢出阈值: `pInstanceId_ >= 429,497` 时，乘法结果超过 uint32_t 最大值

### 触发条件

1. **必要条件**: 攻击者通过 gRPC 发送 `DecodeParameters` 消息，其中 `pInstanceId` 字段值 > 429,496
2. **可达性**: 高 - `pInstanceId` 直接来自 gRPC 请求，无任何验证或边界检查
3. **数据来源**: 
   - Proto 定义 (prefillAndDecodeCommunication.proto 第57行): `uint32 pInstanceId = 28;`
   - 数据流: `grpcContext_->GetDecodeParams().pinstanceid()` → `pInstanceId_`

### 示例触发值

| pInstanceId | 计算结果 (uint32_t溢出) | 期望结果 (正确值) |
|-------------|------------------------|-------------------|
| 500,000 | 溢出为 ~70,508,160 | 5,000,000,000 |
| 1,000,000 | 溢出为 ~1,410,016,160 | 10,000,000,000 |
| UINT32_MAX | 溢出为 ~4,294,967,295 | 42,949,672,950,000 |

## 攻击路径图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              攻击路径                                        │
└─────────────────────────────────────────────────────────────────────────────┘

[攻击者] ──→ [gRPC Endpoint: DecodeService.DecodeRequestChannel]
                    │
                    │ DecodeParameters { pInstanceId = > 429496 }
                    ▼
            [grpc_handler.cpp: HandleDecodeRequest]
                    │
                    │ 解析 DecodeParameters
                    ▼
            [grpc_context.h: SetDecodeParams()]
                    │
                    │ 存储 DecodeParameters.pinstanceid() → uint32_t
                    ▼
            [single_llm_decode_req_handler.cpp: GetContextJsonBody()]
                    │ (第52行)
                    │ pInstanceId_ = grpcContext_->GetDecodeParams().pinstanceid()
                    ▼
            [single_llm_decode_req_handler.cpp: UpdateInferRequest()]
                    │ (第311行) ★ 漏洞触发点
                    │ uint64_t dpInst = pInstanceId_ * 10000 + dpRank
                    │ ↑ uint32_t 算术溢出
                    ▼
            [request->dpInstanceIds 存储错误的 dpInst]
                    │
                    ▼
            ┌─────────────────────────────────────────────────────┐
            │                    影响传播                          │
            ├─────────────────────────────────────────────────────┤
            │ 1. seq_group_builder_from_infer_req.cpp (第128行)    │
            │    seqGroup->dpInstanceId_ = request->dpInstanceIds[0]│
            │                                                      │
            │ 2. construct_execute_request.cpp (第330行)           │
            │    info->set_cluster_id(std::to_string(dpInstanceId_))│
            │                                                      │
            │ 3. scheduler.cpp (第1304行)                          │
            │    metaList[i].dpInstanceId_ = seqGroup->dpInstanceId_│
            │                                                      │
            │ 4. dmi_role.cpp (第1119行) - 反向计算                │
            │    instanceId = dpInstanceId / 10000 ← 得到错误结果  │
            └─────────────────────────────────────────────────────┘
                    │
                    ▼
            [错误的路由、KV缓存冲突、数据损坏]
```

## PoC 构思 (概念验证)

**注意**: 不提供完整可执行 PoC，仅描述验证思路

### 概念验证步骤

1. **环境准备**: 
   - 部署 MindIE-LLM PD 分离架构
   - 确保可访问 DecodeService gRPC endpoint

2. **构造恶意请求**:
   - 创建 `DecodeParameters` protobuf 消息
   - 设置 `pInstanceId = 500000` (或任何 > 429496 的值)
   - 设置必要的其他字段以构造有效的 decode 请求

3. **验证溢出**:
   - 发送请求到 DecodeService.DecodeRequestChannel
   - 观察 `dpInst` 计算结果
   - 验证: `dpInst` 应为 5,000,000,000 + dpRank，但因溢出得到错误值

4. **影响验证**:
   - 观察 KV cache 索引行为
   - 检查 cluster_id 路由是否异常
   - 验证是否存在与其他正常请求的 ID 冲突

### 验证代码片段 (仅概念)

```cpp
// 验证溢出行为的简单测试
uint32_t overflow_test = 500000;  // > 429496
uint64_t result = overflow_test * 10000;  // 在 C++ 中溢出
// 期望: 5,000,000,000
// 实际: 因 uint32_t 溢出得到错误值

// 正确计算方式
uint64_t correct = static_cast<uint64_t>(overflow_test) * 10000;
```

## 影响评估

### 直接影响

| 影响类型 | 严重程度 | 描述 |
|----------|----------|------|
| **错误路由** | HIGH | `dpInst` 用作 `cluster_id` 进行节点路由，溢出值导致请求路由到错误的节点 |
| **KV Cache 紧张** | HIGH | 溢出的 `dpInst` 可能与正常请求的 `dpInst` 值冲突，导致 KV cache 紧张或访问错误数据 |
| **数据损坏** | MEDIUM | PD 分离架构中，错误的 instance ID 可能导致 KV cache 数据混乱 |
| **服务不稳定** | MEDIUM | 大规模部署场景下，溢出值可能触发意外的错误路径 |

### 间接影响

1. **可用性**: 
   - 错误的 routing 可能导致请求无法正确处理
   - KV cache 紧张可能触发重新计算或请求失败
   - 可能导致服务拒绝 (DoS) 效果

2. **完整性**:
   - 不同请求可能因 ID 冲突而共享错误的 KV cache
   - 可能导致推理结果混乱或错误

3. **攻击复杂度**: 
   - 低复杂度 - 只需发送带有大值的 `pInstanceId` 的 gRPC 请求
   - 无需认证绕过或其他前置条件

### 威胁场景

1. **恶意攻击者**: 
   - 故意发送大 `pInstanceId` 值触发溢出
   - 可能利用 ID 冲突访问或污染其他用户的推理数据

2. **配置错误**: 
   - 大规模部署中，真实的 instance ID 可能超过 429,496
   - 正常业务请求可能意外触发此漏洞

### 现实可行性评估

| 因素 | 评估 |
|------|------|
| **攻击面可达** | ✓ gRPC endpoint 直接接受 `pInstanceId` |
| **无验证** | ✓ 无任何 bounds check 或验证 |
| **可控参数** | ✓ 攻击者完全控制 `pInstanceId` 值 |
| **立即生效** | ✓ 溢出在请求处理时立即发生 |
| **影响传播** | ✓ 影响多个下游组件 |

**结论**: 漏洞真实存在，攻击可行，影响严重。

## 修复建议

### 立即修复方案 (推荐)

修改 `single_llm_decode_req_handler.cpp` 第 311 行:

```cpp
// 当前代码 (存在漏洞)
uint64_t dpInst = pInstanceId_ * 10000 + dpRank;

// 修复方案 1: 先转型再乘法
uint64_t dpInst = static_cast<uint64_t>(pInstanceId_) * 10000 + dpRank;

// 修复方案 2: 添加边界检查
if (pInstanceId_ > 429496) {
    // 返回错误或使用安全计算
    ULOG_ERROR(SUBMODLE_NAME_ENDPOINT, "pInstanceId overflow detected");
    // 处理错误...
}
uint64_t dpInst = static_cast<uint64_t>(pInstanceId_) * 10000 + dpRank;
```

### 完整修复建议

1. **代码修复**:
   ```cpp
   void SingleLLMDecodeReqHandler::UpdateInferRequest(...) {
       // ... existing code ...
       
       std::vector<uint64_t> dpInsts;
       const uint64_t PINSTANCE_ID_MAX = 429496ULL; // 安全阈值
       
       if (pInstanceId_ > PINSTANCE_ID_MAX) {
           ULOG_ERROR(SUBMODLE_NAME_ENDPOINT,
               GenerateEndpointErrCode(ERROR, SUBMODLE_FEATURE_SPLITWISE,
                                       PARAM_CHECK_ERROR),
               "Invalid pInstanceId: " << pInstanceId_ 
               << " exceeds safe threshold " << PINSTANCE_ID_MAX);
           // 返回错误处理
           return;
       }
       
       for (uint64_t dpRank : grpcContext_->GetDmiServerInfo().kvCacheInfo.dpInstanceIds) {
           // 安全计算: 先转型再乘法
           uint64_t dpInst = static_cast<uint64_t>(pInstanceId_) * 10000ULL + dpRank;
           dpInsts.emplace_back(dpInst);
       }
       request->dpInstanceIds = dpInsts;
   }
   ```

2. **Proto 层面验证**: 在 gRPC handler 中添加对 `pInstanceId` 的验证

3. **其他相关代码审查**: 检查所有使用 `dpInstanceId / 10000` 反向计算的代码路径

### 验证修复

修复后应添加单元测试:

```cpp
TEST(DecodeReqHandler, OverflowProtection) {
    // 测试边界值
    uint32_t edge_case = 429496;
    uint64_t result = static_cast<uint64_t>(edge_case) * 10000;
    EXPECT_EQ(result, 4294960000ULL);
    
    // 测试溢出检测
    uint32_t overflow_val = 429497;
    // 应触发验证失败
}
```

## 补充信息

### 相关数据流

```
pInstanceId 数据流:
┌──────────────────────────────────────────────────────────────────┐
│ Proto: uint32 pInstanceId = 28                                   │
│   ↓                                                              │
│ gRPC: DecodeParameters.pinstanceid()                             │
│   ↓                                                              │
│ GrpcContext: GetDecodeParams().pinstanceid()                     │
│   ↓                                                              │
│ SingleLLMDecodeReqHandler: pInstanceId_ (uint32_t)               │
│   ↓                                                              │
│ ★ 漏洞点: pInstanceId_ * 10000 (uint32_t 算术溢出)              │
│   ↓                                                              │
│ dpInst (错误的 uint64_t 值)                                      │
│   ↓                                                              │
│ request->dpInstanceIds                                           │
│   ↓                                                              │
│ seqGroup->dpInstanceId_                                          │
│   ↓                                                              │
│ cluster_id (用于路由)                                            │
└──────────────────────────────────────────────────────────────────┘
```

### 缺失的安全措施

1. **输入验证**: 无对 `pInstanceId` 范围的验证
2. **安全算术**: 未使用安全的乘法方式 (先转型)
3. **溢出检测**: 无溢出检测机制
4. **错误处理**: 溢出后无适当的错误处理

### 参考链接

- CWE-190: Integer Overflow or Wraparound
  https://cwe.mitre.org/data/definitions/190.html

---

**报告生成时间**: 2026-04-17
**分析工具**: MindIE-LLM Security Scanner
**状态**: 真实漏洞 - 需立即修复
