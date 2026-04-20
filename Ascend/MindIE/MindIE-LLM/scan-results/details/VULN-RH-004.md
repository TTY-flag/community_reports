# VULN-RH-004: Integer Underflow in Token Offset Calculation

## 漏洞概述

**漏洞ID**: VULN-RH-004  
**类型**: Integer Underflow/Negative Conversion (CWE-190)  
**严重性**: HIGH  
**验证状态**: CONFIRMED  
**文件**: `src/server/endpoint/single_llm_req_handler/single_llm_decode_req_handler.cpp`  
**位置**: 第 116-117 行，函数 `GetContextJsonBody`  
**代码片段**:
```cpp
inputParam->outputLenOffset =
    respTokens.size() - grpcContext_->GetDecodeParams().prefilltokennum();
```

**问题描述**:  
当 `prefilltokennum()` 的值大于 `respTokens.size()` 时，减法操作会产生负数结果。由于结果被赋值给 `size_t` 类型（无符号整数）的 `outputLenOffset`，负数会被转换为一个极大的正数（接近 2^64），导致整数下溢。

## 触发条件分析

### 1. 前置条件

漏洞存在于 P-D (Prefill-Decode) 分离架构中，D 节点处理 decode 请求时：

- **数据来源**: 
  - `respTokens.size()`: 来自 gRPC 参数 `firsttoken` 数组的大小
  - `prefilltokennum()`: 来自 gRPC 参数 `prefillTokenNum` 字段（uint32 类型）

- **正常流程**:
  - P 节点完成 prefill 后，将 `prefillTokenNum` 设置为 `firstToken_.size()` (见 `single_llm_prefill_req_handler.cpp:385`)
  - P 节点将数据通过 gRPC 发送到 D 节点
  - D 节点接收并处理

### 2. 触发场景

攻击者需要满足以下条件之一：

**场景 A: 恶意内部节点**
- 攻击者控制了一个 P 节点或能够发送恶意 gRPC 请求的组件
- 构造请求时设置 `prefillTokenNum` > `firsttoken` 数组长度

**场景 B: 中间人攻击**
- 如果 gRPC 通信未加密或加密被破解
- 篡改传输中的 `prefillTokenNum` 字段值

**场景 C: 软件缺陷**
- P 节点和 D 节点之间状态不同步
- 并发条件下的竞态条件导致参数不一致

### 3. 可达性分析

```
用户请求 → P节点(Prefill) → gRPC通信 → D节点(Decode) → GetContextJsonBody()
                                                              ↓
                                                        第116-117行触发漏洞
```

**可达性**: 高 - 该函数在每次 decode 请求时都会被调用

## 攻击路径图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           攻击路径 (Attack Path)                            │
└─────────────────────────────────────────────────────────────────────────────┘

1. 攻击入口 (Attack Entry)
   ├── 恶意P节点发送恶意gRPC请求
   ├── 中间人篡改gRPC消息
   └── 内部错误导致参数不一致

2. 数据流 (Data Flow)
   ┌──────────────────────────────────────────────────────────────────────┐
   │ gRPC请求参数:                                                        │
   │   firsttoken: [] (空数组或少量元素)                                  │
   │   prefillTokenNum: 100 (恶意设置的值)                               │
   └──────────────────────────────────────────────────────────────────────┘
                              ↓
   ┌──────────────────────────────────────────────────────────────────────┐
   │ D节点接收: FillRespTokensAndReplayIds()                             │
   │   respTokens.size() = firsttoken.size() = 0 (或很小)                │
   └──────────────────────────────────────────────────────────────────────┘
                              ↓
   ┌──────────────────────────────────────────────────────────────────────┐
   │ GetContextJsonBody() 第116-117行:                                   │
   │   outputLenOffset = 0 - 100  (整数下溢!)                            │
   │   outputLenOffset ≈ 2^64 - 100 (变成极大值)                         │
   └──────────────────────────────────────────────────────────────────────┘
                              ↓
   ┌──────────────────────────────────────────────────────────────────────┐
   │ GenerateInferRequest() 第466行:                                     │
   │   maxOutputLen = maxNewTokens - (int)outputLenOffset               │
   │   maxOutputLen < 0                                                  │
   └──────────────────────────────────────────────────────────────────────┘
                              ↓
   ┌──────────────────────────────────────────────────────────────────────┐
   │ 第467-474行的检查:                                                  │
   │   if (maxOutputLen < 0) → 请求被拒绝                                │
   └──────────────────────────────────────────────────────────────────────┘

3. 影响 (Impact)
   └── DoS: 请求处理失败，服务可用性受影响
```

## PoC 构思

**注意**: 以下仅为概念性说明，不提供完整 PoC

### 恶意 gRPC 请求构造思路:

```protobuf
// 恶意 DecodeParameters 消息
DecodeParameters {
  reqId: "attack-request-id",
  firstToken: [],              // 空数组或少量元素
  prefillTokenNum: 999999,     // 设置一个大于 firstToken.size() 的值
  // ... 其他必需字段
}
```

### 预期结果:
1. D 节点接收请求
2. `respTokens.size()` = 0 (或很小的值)
3. `outputLenOffset` = 0 - 999999 ≈ 18446744073709550617 (2^64 - 999999)
4. `maxOutputLen` 计算溢出，变为负数
5. 请求被拒绝，返回错误消息 "MaxNewTokens is less than already generated tokens"

## 影响评估

### 1. 直接影响

| 影响类型 | 严重程度 | 描述 |
|---------|---------|------|
| 拒绝服务 (DoS) | **高** | 攻击者可以通过构造恶意请求导致 decode 请求失败，影响服务可用性 |
| 信息泄露 | 低 | 错误消息可能泄露系统内部状态信息 |
| 代码执行 | 无 | 未发现可导致代码执行的路径 |
| 权限提升 | 无 | 不涉及权限相关操作 |

### 2. 攻击复杂度

| 因素 | 评估 |
|-----|------|
| 攻击向量 | 内部网络/gRPC 通信 |
| 所需权限 | 发送 gRPC 请求的能力 |
| 用户交互 | 无 |
| 攻击复杂度 | 低 |

### 3. 影响范围

- **受影响组件**: D 节点 (Decode Node) 
- **受影响功能**: 所有 decode 请求处理
- **影响用户**: 所有使用该服务的用户

### 4. 发现的其他问题

在同一文件中，`FillRespTokensAndReplayIds` 函数（第 269-286 行）使用了相同的逻辑，但**正确地使用了保护措施**：

```cpp
// 第 274-275 行 - 正确的做法
const int64_t replayStartIdx =
    std::max<int64_t>(0, tokenNum - prefillReplayTokenNum);
```

这表明开发者意识到这个问题的存在，但在第 116-117 行**遗漏了相同的保护措施**。

## 修复建议

### 优先级: **高**

### 方案 1: 添加边界检查 (推荐)

```cpp
// 修复代码 (第 116-117 行)
size_t prefillTokenNum = grpcContext_->GetDecodeParams().prefilltokennum();
if (prefillTokenNum > respTokens.size()) {
    // 记录错误日志
    ULOG_ERROR(SUBMODLE_NAME_ENDPOINT,
               "Invalid prefillTokenNum: " << prefillTokenNum 
               << " > respTokens.size(): " << respTokens.size());
    // 设置为安全值或返回错误
    inputParam->outputLenOffset = 0;
    return false; // 或抛出异常
} else {
    inputParam->outputLenOffset = respTokens.size() - prefillTokenNum;
}
```

### 方案 2: 使用 std::max 保护 (与现有代码风格一致)

```cpp
// 参考 FillRespTokensAndReplayIds 的实现
size_t prefillTokenNum = static_cast<size_t>(grpcContext_->GetDecodeParams().prefilltokennum());
inputParam->outputLenOffset = 
    respTokens.size() > prefillTokenNum ? 
    respTokens.size() - prefillTokenNum : 0;
```

### 方案 3: 在协议层面验证

在 gRPC 参数接收时进行验证：

```cpp
// 在 GetContextJsonBody 函数开始处添加
const int64_t prefillTokenNum = grpcContext_->GetDecodeParams().prefilltokennum();
const int64_t firstTokenSize = grpcContext_->GetDecodeParams().firsttoken_size();
if (prefillTokenNum > firstTokenSize) {
    ULOG_ERROR(SUBMODLE_NAME_ENDPOINT,
               "prefillTokenNum exceeds firsttoken size");
    return false;
}
```

### 建议的完整修复:

1. **立即修复**: 在第 116-117 行添加边界检查
2. **增强验证**: 在接收 gRPC 参数时验证 `prefillTokenNum <= firsttoken_size`
3. **单元测试**: 添加边界测试用例，覆盖以下场景：
   - `prefillTokenNum == firsttoken_size` (正常)
   - `prefillTokenNum > firsttoken_size` (应拒绝)
   - `prefillTokenNum == 0` (边界)
   - `firsttoken_size == 0` (边界)

## 相关文件

| 文件 | 行号 | 描述 |
|-----|------|------|
| `src/server/endpoint/single_llm_req_handler/single_llm_decode_req_handler.cpp` | 116-117 | 漏洞位置 |
| `src/server/endpoint/single_llm_req_handler/single_llm_decode_req_handler.cpp` | 274-275 | 正确的实现参考 |
| `src/server/endpoint/single_req_infer_interface/single_req_infer_interface_base.cpp` | 466 | outputLenOffset 使用位置 |
| `src/server/endpoint/utils/infer_param.h` | 41 | outputLenOffset 定义 |
| `src/server/endpoint/grpc_wrapper/prefillAndDecodeCommunication.proto` | 62 | prefillTokenNum 字段定义 |

## 时间线

- **发现时间**: 2026-04-17
- **验证时间**: 2026-04-17
- **状态**: 已确认，待修复

## 参考资料

- CWE-190: Integer Overflow or Wraparound
- CWE-191: Integer Underflow (Wrap or Wraparound)
- OWASP: Integer Overflow
