# SEC-INFER-001: GetTokensFromInput整数溢出致越界访问或拒绝服务

## 1. 漏洞概述

| 属性 | 值 |
|-----------|-------|
| **漏洞 ID** | SEC-INFER-001 |
| **类型** | 整数溢出/回绕 |
| **CWE** | CWE-190 |
| **严重程度** | 高 |
| **状态** | 已确认 - 真实漏洞 |
| **受影响文件** | `src/server/endpoint/single_req_infer_interface/single_req_infer_interface_base.cpp` |
| **漏洞函数** | `GetTokensFromInput()` |
| **行号** | 1045-1052 |
| **根本原因** | 从 `int64_t` 到 `uint64_t` 的不安全转换，缺少边界验证 |

### 描述
`GetTokensFromInput` 函数中的整数溢出。该函数使用 `std::stoll()` 将用户控制的输入字符串转换为 `int64_t`，然后转换为 `uint64_t` 而未进行适当的边界验证。如果恶意用户通过 recompute 输入参数提供负值，转换为 `uint64_t` 会产生一个极大的回绕值。该值随后在迭代循环中使用，可能导致越界内存访问、内存耗尽或拒绝服务。

---

## 2. 触发条件分析

### 2.1 前置条件
1. **HTTP 头**: 请求必须包含 `is-recompute: true` 头
2. **请求体**: 必须包含 `textInput`（或等效）字段，采用逗号分隔格式
3. **输入格式**: 第一个逗号分隔值代表 `oriReqTokenLen`

### 2.2 可达性评估
| 因素 | 评估 |
|--------|------------|
| **攻击面** | 外部 HTTP API - 可直接从网络访问 |
| **认证要求** | 无（公开推理 API） |
| **特殊条件** | 必须设置 `is-recompute: true` 头 |
| **用户控制** | 完全控制 `textInput` 内容 |

### 2.3 触发机制
```cpp
// 漏洞代码 (single_req_infer_interface_base.cpp, 第 1044-1047 行)
if (idx == 0) {
    oriReqTokenLen_ = static_cast<uint64_t>(std::stoll(token));  // 此处溢出
    idx++;
    continue;
}
```

**攻击输入示例**: `"textInput": "-1,100,200,300"`
- `std::stoll("-1")` 返回 `-1` (int64_t)
- `static_cast<uint64_t>(-1)` 回绕为 `18446744073709551615` (≈2^64-1)

---

## 3. 攻击路径图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            攻击路径流程                                       │
└─────────────────────────────────────────────────────────────────────────────┘

[攻击者]                                                                   
    │                                                                         
    │ HTTP POST 请求                                                          
    │ 头: is-recompute: true                                                  
    │ 体: {"textInput": "-1,token1,token2,..."}                               
    ▼                                                                         
┌───────────────────┐                                                         
│ HTTP Handler      │                                                         
│ (http_handler.cpp)│                                                         
│ 第 191 行:        │                                                         
│ isReCompute=true  │                                                         
└───────────────────┘                                                         
    │                                                                         
    ▼                                                                         
┌───────────────────┐                                                         
│ 推理接口          │                                                         
│ 构造函数          │                                                         
│ isReCompute_=true │                                                         
└───────────────────┘                                                         
    │                                                                         
    ▼                                                                         
┌───────────────────┐                                                         
│ ValidateAndPrepare│                                                         
│ ReqToken()        │                                                         
│ 多个入口点:       │                                                         
│ - self_develop    │                                                         
│ - triton_text     │                                                         
│ - vllm_openai     │                                                         
│ - tgi_text        │                                                         
└───────────────────┘                                                         
    │                                                                         
    │ if (isReCompute_)                                                       
    ▼                                                                         
┌───────────────────┐     ┌──────────────────────────────────────────────┐   
│ GetTokensFromInput│     │  漏洞转换                                      │   
│ (基类)            │     │  oriReqTokenLen_ =                            │   
│ 第 1036-1070 行   │────▶│  static_cast<uint64_t>(std::stoll(token))     │   
│                   │     │                                               │   
│                   │     │  输入: "-1" → 输出: ~2^64-1                   │   
└───────────────────┘     └──────────────────────────────────────────────┘   
    │                                                                         
    ▼                                                                         
┌───────────────────────────────────────────────────────────────────────────┐
│                         两条执行路径                                        │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  路径 A: 基类 BuildReComputeInput() (已缓解)                               │
│  文件: single_req_infer_interface_base.cpp, 第 1198-1212 行               │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  StreamAppend(ssInputs, reqTokens_, oriReqTokenLen_);                │  │
│  │                                                                      │  │
│  │  StreamAppend 实现:                                                   │  │
│  │  limit = std::min(source.size(), limit);  ← 缓解措施                 │  │
│  │  for (size_t i = 0; i < limit; ++i) { ... }                          │  │
│  │                                                                      │  │
│  │  结果: 安全 - 边界限制为实际数组大小                                   │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                           │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  路径 B: Triton Token BuildReComputeInput() (有漏洞)                      │
│  文件: single_req_triton_token_infer_interface.cpp, 第 415-428 行        │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  void BuildReComputeInput(std::vector<int64_t> &inputTokens)         │  │
│  │  {                                                                    │  │
│  │      inputTokens.push_back(oriReqTokenLen_);                         │  │
│  │      for (size_t i = 0; i < oriReqTokenLen_; i++) {     ← 无检查     │  │
│  │          inputTokens.push_back(reqTokens_[i]);  ← 越界               │  │
│  │      }                                                                │  │
│  │      ...                                                              │  │
│  │  }                                                                    │  │
│  │                                                                      │  │
│  │  结果: 有漏洞 - 直接数组访问无边界检查                                  │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
    │                                                                         
    ▼                                                                         
┌───────────────────┐                                                         
│ 影响:             │                                                         
│ - 越界            │                                                         
│   内存读取        │                                                         
│ - 内存            │                                                         
│   耗尽            │                                                         
│ - DoS             │                                                         
└───────────────────┘                                                         
```

---

## 4. PoC 概念（概念大纲）

### 4.1 攻击场景
攻击者可通过以下方式利用此漏洞：

1. **构造 HTTP 请求**:
   - 设置头: `is-recompute: true`
   - 提供带负首值的 `textInput`

2. **输入格式**:
   ```
   textInput 格式: "oriReqTokenLen,token1,token2,...,responseToken1,..."
   ```
   - 第一个值: `oriReqTokenLen`（易受溢出）
   - 后续值: token ID

3. **攻击值**:
   - `-1` → 回绕为 18446744073709551615（最大 uint64）
   - `-100` → 回绕为 18446744073709551616-100
   - 任何负值都会导致问题性回绕

### 4.2 入口点
多个 HTTP 端点可触发此漏洞：

| 端点类型 | 文件 | 行号 |
|---------------|------|------|
| Self-Develop API | `single_req_self_develop_infer_interface.cpp` | 108 |
| Triton Text API | `single_req_triton_text_infer_interface.cpp` | 255 |
| Triton Token API | `single_req_triton_token_infer_interface.cpp` | 94-95 |
| vLLM OpenAI Chat | `single_req_vllm_openai_infer_interface.cpp` | 710 |
| vLLM OpenAI Completions | `single_req_vllm_openai_completions_infer_interface.cpp` | 277 |
| vLLM API | `single_req_vllm_infer_interface.cpp` | 171 |
| TGI Text API | `single_req_tgi_text_infer_interface.cpp` | 154 |

### 4.3 Triton Token 接口（最易受攻击）
```cpp
// single_req_triton_token_infer_interface.cpp, 第 94-95 行
if (this->isReCompute_) {
    oriReqTokenLen_ = inputsData[0];  // 从 JSON 数组直接赋值
}
```
**注意**: JSON 解析可能有不同行为，但通过 `GetTokensFromInput` 的字符串解析路径仍有漏洞。

---

## 5. 影响评估

### 5.1 严重程度因素

| 因素 | 评分 | 说明 |
|--------|-------|-------------|
| **攻击向量** | 网络 (AV:N) | 可通过 HTTP API 利用 |
| **攻击复杂度** | 低 (AC:L) | 简单的头 + 体操作 |
| **权限要求** | 无 (PR:N) | 无需认证 |
| **用户交互** | 无 (UI:N) | 无需用户交互 |
| **范围** | 不变 (S:U) | 影响限于受漏洞组件 |
| **机密性** | 低 (C:L) | 潜在内存读取暴露 |
| **完整性** | 无 (I:N) | 无直接数据修改 |
| **可用性** | 高 (A:H) | 通过内存耗尽/崩溃导致 DoS |

### 5.2 具体影响

1. **越界内存读取**
   - `reqTokens_[i]` 在有效数组边界外访问
   - 可能暴露敏感内存内容
   - 可能导致进程崩溃

2. **拒绝服务 (DoS)**
   - 循环迭代次数: `~2^64`（不实际但会导致资源耗尽）
   - 为数十亿元素尝试内存分配
   - 服务不可用

3. **内存耗尽**
   - `inputTokens.push_back()` 被调用数十亿次
   - 系统内存耗尽
   - 可能被 OOM kill

### 5.3 实际影响
- **服务中断**: 推理服务不可用
- **系统不稳定**: 主机系统可能经历内存压力
- **数据暴露**: 越界读取可能暴露相邻内存

---

## 6. 现有缓解措施分析

### 6.1 当前缓解措施

| 缓解措施 | 位置 | 有效性 |
|------------|----------|---------------|
| `std::stoll` 异常处理 | 第 1055-1060 行 | 部分 - 捕获 int64_t 的 invalid_format 和 out_of_range，但不捕获有符号到无符号转换 |
| `StreamAppend` 边界检查 | `common_util.h` 第 129 行 | 仅对基类路径有效 |
| `MAX_TOKENS_NUM` 验证 | 多个文件，第 155+ 行 | 漏洞后检查，对 `oriReqTokenLen_` 无效 |
| JSON 数组验证 | `triton_token_infer_interface.cpp` | 部分 - 不同输入路径 |

### 6.2 缓解缺口

1. **有符号到无符号转换无边界检查**
   - 转换 `static_cast<uint64_t>(std::stoll(token))` 无验证
   - 异常处理不捕获此情况

2. **Triton Token 接口缺少边界检查**
   - `triton_token_infer_interface.cpp` 中 `BuildReComputeInput` 缺少 `StreamAppend`
   - 直接循环迭代无边界验证

3. **代码路径间缓解措施不一致**
   - 基类: 被 `StreamAppend` 保护
   - Triton Token 接口: 无保护

---

## 7. 修复建议

### 7.1 主要修复（推荐）

**在转换前添加边界验证**:

```cpp
// 在 GetTokensFromInput() (single_req_infer_interface_base.cpp)
if (idx == 0) {
    int64_t parsedValue = std::stoll(token);
    
    // 修复: 转换前验证边界
    if (parsedValue < 0) {
        errorMsg = "oriReqTokenLen must be non-negative";
        return false;
    }
    if (parsedValue > MAX_TOKENS_NUM) {
        errorMsg = "oriReqTokenLen exceeds maximum token limit";
        return false;
    }
    
    oriReqTokenLen_ = static_cast<uint64_t>(parsedValue);
    idx++;
    continue;
}
```

### 7.2 次要修复（Triton Token 接口）

**在 BuildReComputeInput 中添加边界检查**:

```cpp
// 在 BuildReComputeInput() (single_req_triton_token_infer_interface.cpp)
void SingleReqTritonTokenInferInterface::BuildReComputeInput(std::vector<int64_t> &inputTokens)
{
    inputTokens.push_back(oriReqTokenLen_);
    
    // 修复: 添加边界检查
    size_t safeLimit = std::min(static_cast<size_t>(oriReqTokenLen_), reqTokens_.size());
    for (size_t i = 0; i < safeLimit; i++) {
        inputTokens.push_back(reqTokens_[i]);
    }
    // ... 函数其余部分
}
```

### 7.3 深度防御建议

1. **输入验证层**
   - 在 JSON 解析层验证 `oriReqTokenLen`
   - 在 API 入口点拒绝负值

2. **头验证**
   - 考虑将 `is-recompute` 头限制为内部使用
   - 为 recompute 操作添加认证要求

3. **类型安全**
   - 使用 `std::stoull` 进行无符号解析而非 `std::stoll` + 转换
   - 或实现自定义安全解析函数

---

## 8. 验证总结

| 检查 | 结果 |
|-------|--------|
| 漏洞已确认 | ✅ 是 |
| 可从攻击面触发 | ✅ 是（HTTP API） |
| 触发条件可实现 | ✅ 是（头 + 体） |
| 实际利用可能 | ✅ 是（DoS/OOB） |
| 缓解措施不足 | ✅ 是（仅部分） |

**最终判定**: 这是一个**真实漏洞**，需要立即修复。

---

## 9. 参考资料

- CWE-190: 整数溢出或回绕
- 受影响文件:
  - `/src/server/endpoint/single_req_infer_interface/single_req_infer_interface_base.cpp`
  - `/src/server/endpoint/single_req_infer_interface/single_req_triton_token_infer_interface.cpp`
  - `/src/server/endpoint/http_wrapper/http_handler.cpp`
- 相关常量: `MAX_TOKENS_NUM = 1024 * 1024` (endpoint_def.h:66)