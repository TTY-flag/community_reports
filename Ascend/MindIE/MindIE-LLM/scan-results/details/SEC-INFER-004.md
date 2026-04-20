# SEC-INFER-004: Out-of-Bounds Read in BuildReComputeInput

## 漏洞概述

| 属性 | 值 |
|------|------|
| **漏洞ID** | SEC-INFER-004 |
| **类型** | Improper Validation of Array Index with User-Controlled Size (CWE-129) |
| **严重程度** | High |
| **状态** | CONFIRMED (真实漏洞) |
| **受影响文件** | `src/server/endpoint/single_req_infer_interface/single_req_triton_token_infer_interface.cpp` |
| **受影响函数** | `BuildReComputeInput` (行 417-419) |
| **CWE** | CWE-129 |

## 漏洞描述

在 MindIE-LLM 的 Triton Token 推理接口中,`BuildReComputeInput` 函数使用用户控制的 `oriReqTokenLen_` 值作为数组循环边界,未验证其是否小于 `reqTokens_` 数组实际大小。当攻击者通过 HTTP 请求设置 `is-recompute: true` 头并提供恶意构造的 `inputs[0].data` 数组时,可以触发越界读取,导致敏感内存信息泄露或服务崩溃。

## 触发条件分析

### 必要条件

1. **isReCompute_ 标志为 true**: 
   - 通过 HTTP 头 `is-recompute: true` 控制
   - 代码位置: `http_handler.cpp:191`

2. **用户控制 oriReqTokenLen_**:
   ```cpp
   // single_req_triton_token_infer_interface.cpp:93-98
   if (inputsData.size() > 0) {
       if (this->isReCompute_) {
           oriReqTokenLen_ = inputsData[0];  // 用户输入直接赋值
       } else {
           reqTokens_.push_back(inputsData[0]);
       }
       for (size_t i = 1; i < inputsData.size(); i++) {
           reqTokens_.push_back(inputsData[i]);
       }
   }
   ```

3. **缺乏边界验证**:
   ```cpp
   // single_req_triton_token_infer_interface.cpp:415-420
   void SingleReqTritonTokenInferInterface::BuildReComputeInput(std::vector<int64_t> &inputTokens)
   {
       inputTokens.push_back(oriReqTokenLen_);
       for (size_t i = 0; i < oriReqTokenLen_; i++) {  // 无边界检查!
           inputTokens.push_back(reqTokens_[i]);       // 越界读取
       }
       ...
   }
   ```

### 触发可达性

- **攻击面**: HTTP API 端点 `/v2/models/{model_name}/infer`
- **可达性**: 直接可达,无需认证(取决于部署配置)
- **触发难度**: 低 - 仅需构造特定 JSON 请求

## 攻击路径图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           攻击路径完整流程                                    │
└─────────────────────────────────────────────────────────────────────────────┘

[攻击者] ──┬── HTTP POST Request
           │   URL: /v2/models/{model}/infer
           │   Header: is-recompute: true
           │   Body: JSON with malicious inputs[0].data
           │
           ▼
┌──────────────────────────────────────┐
│  http_handler.cpp:191                │
│  MakeHttpHeadersOpt()                │
│  → option->isReCompute = true        │
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│  http_handler.cpp:1526-1530          │
│  DispatchInfer()                     │
│  → SingleReqTritonTokenInferInterface│
│    (isReCompute=true)                │
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│  ValidateAndPrepareReqToken()        │
│  (single_req_triton_token...cpp:93)  │
│  → oriReqTokenLen_ = inputsData[0]   │ ← 用户控制值(如 1000000)
│  → reqTokens_ = [inputsData[1..N]]   │ ← 实际只有 N-1 个元素
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│  SetDMIReComputeBuilder()            │
│  → BuildTritonTokenReComputeBody()   │
│    → BuildReComputeInput()           │
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│  BuildReComputeInput()               │  ★ 漏洞触发点 ★
│  for (i < oriReqTokenLen_) {         │
│      reqTokens_[i]  ← OOB READ       │  越界读取堆内存
│  }                                   │
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│  潜在影响:                            │
│  • 信息泄露 (堆内存内容)              │
│  • 服务崩溃 (DoS)                     │
│  • 内存破坏 (潜在)                    │
└──────────────────────────────────────┘
```

## PoC 构思 (概念性)

### 攻击请求示例

```http
POST /v2/models/test_model/infer HTTP/1.1
Host: target-server:port
is-recompute: true
Content-Type: application/json

{
    "inputs": [{
        "name": "input0",
        "shape": [1, 5],
        "datatype": "UINT32",
        "data": [1000000, 1, 2, 3, 4]
    }],
    "outputs": [{"name": "output0"}]
}
```

### 关键点说明

- `data[0] = 1000000` → `oriReqTokenLen_ = 1000000`
- `data[1..4]` → `reqTokens_.size() = 4`
- 循环将尝试读取 `reqTokens_[0..999999]`,远超 vector 实际大小
- `MAX_TOKENS_NUM = 1048576` (1M),大值仍可通过 `CheckReqInputData` 验证

## 影响评估

### 实际危害

| 影响类型 | 严重程度 | 说明 |
|----------|----------|------|
| **信息泄露** | High | 越界读取可暴露堆上敏感数据(如其他请求的 token、配置信息) |
| **拒绝服务** | Medium-High | 读取未映射内存可导致 SIGSEGV 崩溃 |
| **代码执行** | Low | 纯读取漏洞,不太可能直接导致代码执行 |

### CVSS 评估要素

- **Attack Vector (AV)**: Network (通过网络可达)
- **Attack Complexity (AC)**: Low (无需特殊条件)
- **Privileges Required (PR)**: None (无认证要求)
- **User Interaction (UI)**: None
- **Scope (S)**: Unchanged
- **Confidentiality (C)**: High (可泄露敏感内存)
- **Integrity (I)**: None (纯读取)
- **Availability (A)**: High (可导致崩溃)

### 已存在缓解措施分析

| 检查点 | 位置 | 是否有效 | 说明 |
|--------|------|----------|------|
| `CheckReqInputData` | 行 300-336 | **无效** | 仅检查 `data.size() <= MAX_TOKENS_NUM`,不检查 `data[0] vs reqTokens_.size()` |
| `CheckReqInputShape` | 行 231-270 | **无效** | 仅验证 shape 格式,不验证实际使用值 |
| Shape-Data 大小匹配 | 行 318-325 | **部分** | 要求 `data.size() == shape[1]`,但不约束 `data[0]` 的语义 |

**结论**: 现有缓解措施**无法阻止此漏洞**,因为验证逻辑未考虑 recompute 场景下 `data[0]` 的特殊用途。

## 修复建议

### 推荐修复方案

在 `ValidateAndPrepareReqToken` 或 `BuildReComputeInput` 中添加边界检查:

```cpp
// 方案1: 在 ValidateAndPrepareReqToken 中验证 (行 93-101)
if (inputsData.size() > 0) {
    if (this->isReCompute_) {
        oriReqTokenLen_ = inputsData[0];
        // 新增: 验证 oriReqTokenLen_ 不超过后续 token 数量
        if (oriReqTokenLen_ > inputsData.size() - 1) {
            msg = "oriReqTokenLen_ exceeds available token count";
            return false;
        }
    }
    ...
}

// 方案2: 在 BuildReComputeInput 中添加防御性检查 (行 415-420)
void SingleReqTritonTokenInferInterface::BuildReComputeInput(std::vector<int64_t> &inputTokens)
{
    inputTokens.push_back(oriReqTokenLen_);
    // 新增: 安全边界限制
    size_t safeLen = std::min(oriReqTokenLen_, reqTokens_.size());
    for (size_t i = 0; i < safeLen; i++) {
        inputTokens.push_back(reqTokens_[i]);
    }
    ...
}
```

### 其他建议

1. **输入范围验证**: 在 recompute 场景下,限制 `oriReqTokenLen_` 的可接受范围
2. **日志记录**: 添加异常情况的审计日志
3. **单元测试**: 添加针对此边界情况的测试用例

## 相关漏洞

此漏洞与 SEC-INFER-001 存在关联:
- SEC-INFER-001: `GetTokensFromInput` 中的整数溢出 (`oriReqTokenLen_ = std::stoll(token)`)
- SEC-INFER-004: `BuildReComputeInput` 中缺乏边界检查

两者都涉及 `oriReqTokenLen_` 的安全问题,建议一并修复。

---

**报告生成时间**: 2026-04-17
**分析工具**: 漏洞扫描系统 + 人工深度分析
