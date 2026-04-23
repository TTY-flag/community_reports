# SEC-INFER-003: GenerateInferRequest输出长度计算整数溢出风险

## 漏洞概述

**漏洞ID**: SEC-INFER-003  
**类型**: Integer Overflow (CWE-190)  
**严重性**: Medium (验证后调整)  
**验证状态**: CONFIRMED  
**文件**: `src/server/endpoint/single_req_infer_interface/single_req_infer_interface_base.cpp`  
**位置**: 第 465-476 行，函数 `GenerateInferRequest`  
**关联漏洞**: VULN-RH-004 (整数下溢在 outputLenOffset 计算)

**代码片段**:
```cpp
if (inputParam->maxNewTokens > 0) {
    int maxOutputLen = inputParam->maxNewTokens - static_cast<int>(inputParam->outputLenOffset);
    if (maxOutputLen < 0) {
        if (inputParam->thinkingBudget.has_value() && inputParam->thinkingBudget.value() > 0) {
            maxOutputLen = 0;
        } else {
            msg = "MaxNewTokens is less than already generated tokens. The requestId is " + std::string(requestId_);
            MINDIE_LLM_LOG_ERROR(msg);
            return false;
        }
    }
    request_->maxOutputLen = static_cast<uint64_t>(maxOutputLen);
}
```

**问题描述**:  
当 `outputLenOffset` 因整数下溢变成极大值时（参见 VULN-RH-004），`static_cast<int>(outputLenOffset)` 的行为是实现定义的。虽然存在负值检查，但类型转换的不确定性可能导致：
1. 请求被拒绝 (DoS)
2. 在某些平台实现中，转换结果可能绕过负值检查

## 触发条件分析

### 1. 前置条件

漏洞触发依赖于 `outputLenOffset` 的异常值，其来源有两个路径：

**路径 A: D节点场景 (PD分离架构)**
```cpp
// single_llm_decode_req_handler.cpp:116-117
inputParam->outputLenOffset = respTokens.size() - grpcContext_->GetDecodeParams().prefilltokennum();
```
- 当 `prefilltokennum > respTokens.size()` 时发生整数下溢
- 需要恶意 gRPC 请求或内部状态不一致
- `prefilltokennum` 类型: uint32 (来自 proto)
- `respTokens.size()` 类型: size_t

**路径 B: 重计算场景**
```cpp
// single_req_infer_interface_base.cpp:1064-1065
inputParam->preOutputTokenNum = responseTokens.size();
inputParam->outputLenOffset = inputParam->preOutputTokenNum;
```
- 正常场景，`outputLenOffset` 来自已输出的 token 数量
- 需要用户输入构造极长的输出 token 列表才能触发

### 2. 漏洞触发链条

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          漏洞触发链条分析                                     │
└─────────────────────────────────────────────────────────────────────────────┘

阶段 1: outputLenOffset 整数下溢 (VULN-RH-004)
┌───────────────────────────────────────────────────────────────────────────────┐
│ 条件: prefilltokennum > respTokens.size()                                    │
│ 例如: prefilltokennum = 100, respTokens.size() = 10                          │
│ 结果: outputLenOffset = 10 - 100 = -90 (作为 size_t 存储)                    │
│ 实际值: outputLenOffset ≈ SIZE_MAX - 90 (约 18446744073709551525)            │
└───────────────────────────────────────────────────────────────────────────────┘
                                    ↓
阶段 2: 类型转换 (SEC-INFER-003 漏洞点)
┌───────────────────────────────────────────────────────────────────────────────┐
│ int maxOutputLen = maxNewTokens - static_cast<int>(outputLenOffset);         │
│                                                                               │
│ static_cast<int>(SIZE_MAX - 90) 行为分析:                                     │
│ - 在大多数实现中: 结果为负值 (-1 或其他实现定义值)                            │
│ - 在某些平台上: 可能截断为正值                                                │
│ - C++ 标准规定: 超出目标类型范围时行为是实现定义的                             │
└───────────────────────────────────────────────────────────────────────────────┘
                                    ↓
阶段 3: 负值检查 (缓解措施)
┌───────────────────────────────────────────────────────────────────────────────┐
│ if (maxOutputLen < 0) {                                                       │
│     // 如果 thinkingBudget 有效，设置为 0                                     │
│     // 否则返回 false，拒绝请求                                               │
│ }                                                                             │
│                                                                               │
│ 缓解效果:                                                                      │
│ - 如果转换结果为负值 → 请求被拒绝 (DoS)                                       │
│ - 如果转换结果为正值 → 可能绕过检查                                          │
└───────────────────────────────────────────────────────────────────────────────┘
                                    ↓
阶段 4: 最终赋值
┌───────────────────────────────────────────────────────────────────────────────┐
│ request_->maxOutputLen = static_cast<uint64_t>(maxOutputLen);                │
│                                                                               │
│ 影响:                                                                         │
│ - 如果 maxOutputLen 为负值并绕过检查 → uint64_t 产生极大正值                  │
│ - 可能导致后续推理过程中的异常行为                                            │
└───────────────────────────────────────────────────────────────────────────────┘
```

### 3. 可达性分析

| 入口点 | 可达性 | 所需条件 |
|-------|--------|---------|
| HTTP API (vLLM/TGI/OpenAI) | 低 | 需构造重计算场景，难以直接控制 outputLenOffset |
| gRPC API (D节点) | 中 | 需访问内部 gRPC 通信，可构造恶意 prefilltokennum |
| 内部错误 | 低 | 需 P-D 节点状态不一致 |

**主要攻击路径**: 通过 gRPC 发送恶意 DecodeParameters 消息

## 攻击路径图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           攻击路径 (Attack Path)                             │
└─────────────────────────────────────────────────────────────────────────────┘

1. 攻击入口
   ┌───────────────────────────────────────────────────────────────────────────┐
   │ 攻击者需要具备:                                                            │
   │ - 发送 gRPC DecodeParameters 请求的能力                                   │
   │ - 控制恶意 P 节点                                                         │
   │ - 或中间人攻击 gRPC 通信 (如果未加密)                                     │
   └───────────────────────────────────────────────────────────────────────────┘

2. 恶意请求构造
   ┌───────────────────────────────────────────────────────────────────────────┐
   │ DecodeParameters {                                                         │
   │   reqId: "malicious-request",                                             │
   │   firstToken: [],           // 空数组                                      │
   │   prefillTokenNum: 100,     // 恶意值，大于 firstToken.size()             │
   │   maxNewToken: 1000,        // 正常值                                      │
   │   // ... 其他必需字段                                                      │
   │ }                                                                          │
   └───────────────────────────────────────────────────────────────────────────┘
                                    ↓
3. D节点处理流程
   ┌───────────────────────────────────────────────────────────────────────────┐
   │ SingleLLMDecodeReqHandler::GetContextJsonBody()                           │
   │   ↓                                                                        │
   │ FillRespTokensAndReplayIds() → respTokens.size() = 0                      │
   │   ↓                                                                        │
   │ 第116-117行: outputLenOffset = 0 - 100 (整数下溢!)                        │
   │   ↓                                                                        │
   │ outputLenOffset ≈ SIZE_MAX - 100                                          │
   └───────────────────────────────────────────────────────────────────────────┘
                                    ↓
4. GenerateInferRequest 处理
   ┌───────────────────────────────────────────────────────────────────────────┐
   │ 第466行: int maxOutputLen = 1000 - static_cast<int>(SIZE_MAX-100)        │
   │   ↓                                                                        │
   │ 类型转换结果 (实现定义):                                                    │
   │   - 通常情况: static_cast<int>(SIZE_MAX-100) ≈ -1 或其他负值              │
   │   - 结果: maxOutputLen ≈ 1000 - (-1) = 1001 或其他值                       │
   │   ↓                                                                        │
   │ 第467行: if (maxOutputLen < 0) → 检查结果取决于实现                        │
   │   - 如果转换后 maxOutputLen 为负 → 请求被拒绝 (DoS)                       │
   │   - 如果转换后 maxOutputLen 为正 → 绕过检查                               │
   └───────────────────────────────────────────────────────────────────────────┘
                                    ↓
5. 最终影响
   ┌───────────────────────────────────────────────────────────────────────────┐
   │ 情况 A (常见): 请求被拒绝 → DoS                                            │
   │ 情况 B (罕见): maxOutputLen 异常 → 可能影响推理行为                        │
   └───────────────────────────────────────────────────────────────────────────┘

6. 后续处理 (额外缓解)
   ┌───────────────────────────────────────────────────────────────────────────┐
   │ seq_group_builder_from_infer_req.cpp:156                                  │
   │ seqGroup->maxOutputLen_ = std::min(seqGroup->maxIterTimes_,               │
   │                                     seqGroup->sampling->maxOutputLen);    │
   │                                                                             │
   │ 即使 maxOutputLen 异常大，也会被 maxIterTimes_ 限制                        │
   └───────────────────────────────────────────────────────────────────────────┘
```

## PoC 构思

**注意**: 以下仅为概念性说明，不提供完整可执行 PoC

### 恶意 gRPC 请求构造思路:

```protobuf
// 概念性恶意请求
DecodeParameters {
  reqId: "attack-001",
  firstToken: [],              // 空数组或极少量元素
  prefillTokenNum: 4294967295, // uint32 最大值，确保大于 firstToken.size()
  maxNewToken: 1000,           // 正常范围内的值
  isStream: false,
  // ... 设置其他必需字段使其通过验证
}
```

### 预期行为:

1. D节点接收请求
2. `respTokens.size()` = 0 (因为 firstToken 为空)
3. `outputLenOffset` = 0 - 4294967295 发生整数下溢
4. 类型转换行为取决于平台
5. 大多数情况下请求被拒绝，返回错误消息

### 测试验证方法:

```cpp
// 单元测试概念
TEST(VulnerabilityTest, IntegerOverflowInMaxOutputLen) {
    InferParamSPtr param = std::make_shared<InferParam>();
    param->maxNewTokens = 1000;
    param->outputLenOffset = SIZE_MAX - 100; // 模拟下溢结果
    
    int maxOutputLen = param->maxNewTokens - static_cast<int>(param->outputLenOffset);
    
    // 验证类型转换行为
    // 期望: 在大多数平台上 maxOutputLen < 0 或产生异常值
}
```

## 影响评估

### 1. 直接影响

| 影响类型 | 严重程度 | 描述 |
|---------|---------|------|
| 拒绝服务 (DoS) | **中** | 攻击者可导致特定 decode 请求失败，但不影响整体服务稳定性 |
| 信息泄露 | 低 | 错误消息可能泄露 requestId 等内部信息 |
| 内存耗尽 | 低 | 存在额外的 std::min 缓解，难以导致大量内存分配 |
| 代码执行 | 无 | 未发现可导致代码执行的路径 |
| 数据篡改 | 无 | 不涉及数据修改操作 |

### 2. 攻击复杂度

| 因素 | 评估 | 说明 |
|-----|------|------|
| 攻击向量 | Network (Internal) | 需要访问内部 gRPC 通信 |
| 所需权限 | Medium | 需发送 gRPC 请求的能力 |
| 用户交互 | None | 无需用户交互 |
| 攻击复杂度 | Medium | 需理解 P-D 架构和 gRPC 协议 |
| 可利用性 | Low | 多层缓解措施降低实际可利用性 |

### 3. 缓解措施分析

| 缓解措施 | 位置 | 有效性 | 说明 |
|---------|------|--------|------|
| 负值检查 | 第467行 `if (maxOutputLen < 0)` | 部分 | 仅捕获负值情况，不捕获正值溢出 |
| thinkingBudget 兜底 | 第468-469行 | 低 | 仅在特定条件下设置 maxOutputLen=0 |
| std::min 限制 | seq_group_builder 第156行 | 高 | 限制最终 maxOutputLen 不超过 maxIterTimes_ |
| maxNewTokens 范围验证 | infer_param.cpp 第708-710行 | 高 | 限制 maxNewTokens 在 (0, INT32_MAX] |

### 4. 影响范围

- **受影响组件**: 
  - D节点 (Decode Node) 的请求处理
  - 重计算场景的推理请求
  
- **不受影响场景**:
  - 标准 HTTP API 请求 (难以控制 outputLenOffset)
  - P节点 (Prefill Node) 单独运行

## 修复建议

### 优先级: 中

### 方案 1: 在上游修复整数下溢 (推荐)

修复 VULN-RH-004 即可阻止此漏洞触发：

```cpp
// single_llm_decode_req_handler.cpp 第116-117行修复
size_t prefillTokenNum = grpcContext_->GetDecodeParams().prefilltokennum();
if (prefillTokenNum > respTokens.size()) {
    ULOG_ERROR(SUBMODLE_NAME_ENDPOINT,
               "prefillTokenNum exceeds respTokens size: "
               << prefillTokenNum << " > " << respTokens.size());
    return false;
}
inputParam->outputLenOffset = respTokens.size() - prefillTokenNum;
```

### 方案 2: 加强类型转换边界检查

```cpp
// single_req_infer_interface_base.cpp 第465-476行修复
if (inputParam->maxNewTokens > 0) {
    // 验证 outputLenOffset 在安全范围内
    if (inputParam->outputLenOffset > static_cast<size_t>(INT_MAX)) {
        msg = "outputLenOffset exceeds safe range. requestId: " + std::string(requestId_);
        MINDIE_LLM_LOG_ERROR(msg);
        return false;
    }
    
    int maxOutputLen = inputParam->maxNewTokens - static_cast<int>(inputParam->outputLenOffset);
    
    // 增强检查：同时验证正值溢出
    if (maxOutputLen < 0 || maxOutputLen > MAX_SAFE_OUTPUT_LEN) {
        // ... 处理异常情况
    }
    
    request_->maxOutputLen = static_cast<uint64_t>(maxOutputLen);
}
```

### 方案 3: 使用更安全的类型

```cpp
// 使用 int64_t 进行中间计算，避免溢出
int64_t maxOutputLen = static_cast<int64_t>(inputParam->maxNewTokens) 
                     - static_cast<int64_t>(inputParam->outputLenOffset);

if (maxOutputLen < 0 || maxOutputLen > MAX_SAFE_OUTPUT_LEN) {
    // 处理异常
}

request_->maxOutputLen = static_cast<uint64_t>(std::max(0L, maxOutputLen));
```

### 建议的完整修复策略:

1. **优先修复 VULN-RH-004**: 阻止 outputLenOffset 整数下溢
2. **添加边界验证**: 验证 outputLenOffset 不超过 INT_MAX
3. **单元测试覆盖**: 
   - 测试 outputLenOffset 极大值场景
   - 测试 maxNewTokens 边界值场景
   - 测试类型转换行为

## 相关文件

| 文件 | 行号 | 描述 |
|-----|------|------|
| `src/server/endpoint/single_req_infer_interface/single_req_infer_interface_base.cpp` | 465-476 | 漏洞位置 |
| `src/server/endpoint/single_req_infer_interface/single_req_infer_interface_base.cpp` | 1064-1065 | outputLenOffset 来源 (重计算) |
| `src/server/endpoint/single_llm_req_handler/single_llm_decode_req_handler.cpp` | 116-117 | outputLenOffset 来源 (D节点) |
| `src/server/endpoint/utils/infer_param.h` | 40-41 | maxNewTokens/outputLenOffset 定义 |
| `src/server/endpoint/utils/infer_param.cpp` | 706-715 | AssignMaxNewTokens 验证 |
| `src/engine/seq_group_builder_from_infer_req.cpp` | 156 | std::min 缓解措施 |
| `src/server/endpoint/grpc_wrapper/prefillAndDecodeCommunication.proto` | 62-63 | prefillTokenNum 定义 |

## 时间线

- **发现时间**: 2026-04-17
- **验证时间**: 2026-04-17
- **状态**: 已确认，建议与 VULN-RH-004 同步修复

## 参考资料

- CWE-190: Integer Overflow or Wraparound
- CWE-191: Integer Underflow (Wrap or Wraparound)
- C++ Standard: Implementation-defined behavior for out-of-range conversions
- 相关漏洞: VULN-RH-004 (outputLenOffset 整数下溢)
