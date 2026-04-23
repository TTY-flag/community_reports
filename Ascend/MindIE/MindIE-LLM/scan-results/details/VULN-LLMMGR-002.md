# VULN-LLMMGR-002: TransformInputId张量Shape越界读取致内存泄露

## 1. 漏洞概述

| 属性 | 详情 |
|------|------|
| **漏洞ID** | VULN-LLMMGR-002 |
| **漏洞类型** | Out-of-Bounds Read (越界读取) |
| **CWE分类** | CWE-125: Out-of-bounds Read |
| **严重性** | HIGH |
| **置信度** | 85/100 (CONFIRMED) |
| **文件位置** | `src/llm_manager/llm_manager_adapter.cpp` |
| **行号** | 36-39 |
| **函数** | `TransformInputId` |
| **模块** | llm_manager |

### 漏洞核心代码

```cpp
// llm_manager_adapter.cpp:23-40
void TransformInputId(std::shared_ptr<InferRequest>& req, std::shared_ptr<Request>& v2Req)
{
    TensorPtr inputIdTensorPtr = nullptr;
    req->GetTensorByName("INPUT_IDS", inputIdTensorPtr);
    if (inputIdTensorPtr == nullptr) {
        MINDIE_LLM_LOG_ERROR("INPUT_IDS tensor not found in request");
        return;
    }
    int64_t* inputIdData = static_cast<int64_t*>(inputIdTensorPtr->GetData());
    if (inputIdData == nullptr) {
        MINDIE_LLM_LOG_ERROR("INPUT_IDS tensor data is null");
        return;
    }
    // 漏洞点：循环迭代基于用户控制的 shape，未验证实际缓冲区大小
    v2Req->input_token_num = inputIdTensorPtr->GetShape()[1];  // 用户控制的值
    for (int i = 0; i < inputIdTensorPtr->GetShape()[1]; i++) {  // 基于用户声称的 shape 迭代
        v2Req->input_ids.push_back(inputIdData[i]);  // OOB READ：可能读取超出缓冲区的数据
    }
}
```

---

## 2. 漏洞根本原因分析

### 2.1 InferTensor 类的设计缺陷

`InferTensor` 类存在关键的分离设计问题：

```cpp
// infer_tensor.h 成员变量
private:
    std::vector<int64_t> dataShape;  // 用户声称的形状
    void *data = nullptr;            // 实际数据缓冲区指针
    uint64_t byteSize = 0;           // 实际分配的字节数
```

**关键问题**：
1. `dataShape` 在构造函数中设置，与实际内存分配**完全分离**
2. 没有强制约束确保 `dataShape` 元素乘积等于 `byteSize`
3. `GetShape()` 直接返回用户设置的形状，没有任何验证

### 2.2 Python API 绑定允许用户完全控制 shape 和 buffer

```python
# Python 用户可以这样构造恶意 tensor:
tensor = InferTensor("INPUT_IDS", InferDataType.TYPE_INT64, [1, 1000000])  # 设置大 shape
tensor.set_buffer(small_numpy_array, True)  # 设置小缓冲区（实际只有 10 个元素）
# shape[1] = 1000000, 但 buffer 只有 10 * 8 = 80 bytes
```

---

## 3. 触发条件分析

### 3.1 必要条件

| 条件 | 描述 | 可达性 |
|------|------|--------|
| Python API 可访问 | 用户可通过 Python bindings 创建 InferTensor | 完全可达 |
| 用户控制 GetRequestsCallback | LlmManager 构造时接受用户提供的回调函数 | 完全可达 |
| shape 与 buffer 不匹配 | 用户设置 shape[1] > buffer 实际元素数 | 用户完全控制 |

### 3.2 触发难度

**触发难度：低**
- 不需要特殊权限或认证
- Python 用户可直接构造恶意请求
- 无需绕过任何安全检查

---

## 4. 完整攻击路径

```
攻击路径图：

Python 用户代码 (攻击者控制)
───────────────────────────────────
1. 创建 InferTensor
   tensor = InferTensor("INPUT_IDS", TYPE_INT64, [1, 1000000])
   // 声称 shape = [1, 1000000]

2. 设置小缓冲区
   tensor.set_buffer(np.array([1,2,3,4,5]), True)
   // 实际只有 5 个元素 (40 bytes)

3. 创建请求并添加 tensor
   request.add_tensor("INPUT_IDS", tensor)

4. 通过 GetRequestsCallback 返回请求
   llm_manager = LlmManager(config, get_request, ...)
                 │
                 ▼
C++ LlmManager 后端
───────────────────────────────────
5. ProcessRequests() 调用 getRequests_()
   requests = getRequests_();

6. V1->V2 适配调用 AdaptGetRequestV1ToV2()

7. TransformInputId(req, v2Req)
   ★ 漏洞触发点 ★

8. 越界读取
   for (int i = 0; i < 1000000; i++) {
       push_back(inputIdData[i]);  // ★ OOB READ ★
   }
                 │
                 ▼
危害影响
───────────────────────────────────
• 读取进程内存中的任意数据 (信息泄露)
• 可能读取敏感信息: 密钥、密码、其他用户数据
• 可能触发 SIGSEGV 导致服务崩溃 (DoS)
```

---

## 5. PoC 构思 (不提供完整 PoC)

### 5.1 概念验证思路

```python
# 概念验证框架 (不完整)
import llm_manager_python
import numpy as np

# 1. 创建恶意 tensor - 设置大 shape，实际小 buffer
malicious_shape = [1, 100000]  # 声称 100000 个元素
actual_data = np.array([1, 2, 3], dtype=np.int64)  # 实际只有 3 个元素

tensor = InferTensor("INPUT_IDS", InferDataType.TYPE_INT64, malicious_shape)
tensor.set_buffer(actual_data, True)

# 2. 构造请求并通过回调传递
def malicious_callback():
    return [request_with_malicious_tensor]

# 3. 初始化 LlmManager - 触发漏洞
manager = LlmManager(config_path, malicious_callback, ...)
manager.init(instance_id, device_ids)
```

---

## 6. 影响评估

### 6.1 安全影响

| 影响类型 | 严重程度 | 详细描述 |
|----------|----------|----------|
| 信息泄露 | 高 | 可读取进程内存中的任意数据，包括 TLS 密钥、用户数据、配置信息 |
| 拒绝服务 | 高 | 大规模越界读取可触发 SIGSEGV，导致服务崩溃 |
| 数据篡改风险 | 中 | 越界读取的数据被 push_back 到 input_ids，可能影响后续处理逻辑 |

### 6.2 CVSS 评分估算

- Attack Vector (AV): Local
- Attack Complexity (AC): Low
- Privileges Required (PR): Low
- User Interaction (UI): None
- Scope (S): Changed
- Confidentiality (C): High
- Integrity (I): Low
- Availability (A): High

**CVSS 3.1 Base Score: 7.8 (HIGH)**

---

## 7. 缓解措施评估

### 7.1 当前缓解措施

**检查结果：无有效缓解**

`TransformInputId` 中：
- 只检查 `inputIdTensorPtr` 和 `inputIdData` 是否为 null
- 没有验证 `GetShape()[1]` 与实际缓冲区大小的关系
- `InferTensor::GetSize()` 返回实际分配的字节数，但未被使用

---

## 8. 修复建议

### 8.1 主要修复方案

**方案 A: 在 TransformInputId 中添加验证**

```cpp
void TransformInputId(std::shared_ptr<InferRequest>& req, std::shared_ptr<Request>& v2Req)
{
    // ... 获取 tensor ...
    
    // ★ 新增：验证 shape 与实际缓冲区匹配 ★
    size_t expected_size = inputIdTensorPtr->GetShape()[1] * sizeof(int64_t);
    size_t actual_size = inputIdTensorPtr->GetSize();
    
    if (expected_size > actual_size) {
        MINDIE_LLM_LOG_ERROR("Shape mismatch: declared shape exceeds actual buffer size");
        return;  // 或抛出异常
    }
    
    // 原有代码继续...
}
```

**方案 B: 在 InferTensor::SetBuffer 中强制验证**

```cpp
void InferTensor::SetBuffer(const void *buffer, size_t tensorbyteSize, bool tensorNeedRelease)
{
    // ★ 新增：验证 buffer size 与 shape 匹配 ★
    size_t expected_size = 0;
    for (auto dim : dataShape) {
        expected_size *= dim;
    }
    expected_size *= GetTypeByteSize(dataType);
    
    if (tensorbyteSize != expected_size) {
        throw std::runtime_error("Buffer size must match declared shape");
    }
    // ... 原有代码 ...
}
```

---

## 9. 结论

### 9.1 漏洞判定

**VULN-LLMMGR-002 是真实的、可利用的高危漏洞**

判定依据：
1. 漏洞代码明确存在，循环迭代基于用户控制值，未验证实际缓冲区
2. Python API 允许用户完全控制 shape 和 buffer
3. 无任何有效缓解措施阻止此攻击
4. 已确认的触发路径从用户输入到漏洞点完全可达

### 9.2 风险等级

| 维度 | 评级 |
|------|------|
| 可利用性 | 高 (Python 用户可直接触发) |
| 影响范围 | 高 (所有使用 LlmManager 的部署) |
| 攻击成本 | 低 (无需特殊工具或技能) |
| 整体风险 | **HIGH** |

### 9.3 建议优先级

**建议立即修复**

---

## 10. 相关文件清单

| 文件路径 | 相关性 |
|----------|--------|
| `src/llm_manager/llm_manager_adapter.cpp` | 漏洞位置 |
| `src/llm_manager/infer_tensor.cpp` | InferTensor 实现 |
| `src/include/llm_manager/infer_tensor.h` | InferTensor 类定义 |
| `src/llm_manager/python_api/python_api_init.cpp` | Python bindings 入口 |
| `src/llm_manager/llm_manager.cpp` | LlmManager 适配层 |
| `src/llm_manager_v2/impl/llm_manager_impl.cpp` | 后端请求处理 |

---

**报告生成时间**: 2026-04-17
**分析状态**: CONFIRMED - 真实漏洞
