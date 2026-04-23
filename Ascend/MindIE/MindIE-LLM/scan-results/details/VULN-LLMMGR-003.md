# VULN-LLMMGR-003: TransformStopTokenIds基于用户可控Shape循环致越界读取

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-LLMMGR-003 |
| **漏洞类型** | Out-of-Bounds Read (CWE-125) |
| **严重程度** | HIGH |
| **状态** | CONFIRMED |
| **影响模块** | llm_manager |
| **相关漏洞** | VULN-LLMMGR-002 (相同漏洞模式) |

### 漏洞描述

在 `TransformStopTokenIds` 函数中存在越界读取漏洞。该函数基于用户可控的 tensor shape 进行循环迭代，但未验证实际 buffer 大小是否与 shape 匹配。攻击者可构造一个 tensor，其声称的 shape 远大于实际分配的 buffer，导致循环读取超出 buffer 范围的内存数据。

**漏洞代码位置:**
- 文件: `/src/llm_manager/llm_manager_adapter.cpp`
- 函数: `TransformStopTokenIds`
- 行号: 55-57

```cpp
void TransformStopTokenIds(std::shared_ptr<InferRequest>& req, std::shared_ptr<Request>& v2Req)
{
    TensorPtr stopTokenIdsTensorPtr = nullptr;
    req->GetTensorByName("STOP_TOKEN_IDS", stopTokenIdsTensorPtr);
    if (stopTokenIdsTensorPtr == nullptr) {
        MINDIE_LLM_LOG_ERROR("STOP_TOKEN_IDS tensor not found in request");
        return;
    }
    TokenId* stopTokenIdsTensorData = static_cast<TokenId*>(stopTokenIdsTensorPtr->GetData());
    if (stopTokenIdsTensorData == nullptr) {
        MINDIE_LLM_LOG_ERROR("INCLUDE_STOP_STR_IN_OUTPUT tensor data is null");
        return;
    }
    // 漏洞点: 使用 GetShape()[1] 决定循环次数，但未验证实际 buffer 大小
    for (int i = 0; i < stopTokenIdsTensorPtr->GetShape()[1]; i++) {
        v2Req->stopTokenIds.value().push_back(stopTokenIdsTensorData[i]);  // <-- OOB READ
    }
}
```

---

## 触发条件分析

### 1. Shape-Buffer 不一致的根本原因

`InferTensor` 类的设计缺陷允许 shape 和 buffer 大小独立设置:

**infer_tensor.cpp 构造函数 (第23-36行):**
```cpp
InferTensor::InferTensor(std::string name, InferDataType dataType, std::vector<int64_t> dataShape)
{
    this->name = name;
    this->dataType = dataType;
    this->dataShape = dataShape;  // shape 可任意设置
}
```

**infer_tensor.cpp SetBuffer 函数 (第127-140行):**
```cpp
void InferTensor::SetBuffer(const void *buffer, size_t tensorbyteSize, bool tensorNeedRelease)
{
    if (buffer == nullptr) {
        MINDIE_LLM_LOG_ERROR("SetBuffer fail: buffer is nullptr");
        return;
    }
    if (tensorbyteSize > MAX_BYTE_ALLOWED) {
        MINDIE_LLM_LOG_ERROR("SetBuffer fail: tensorbyteSize is too large");
        return;
    }
    data = const_cast<void *>(buffer);
    byteSize = tensorbyteSize;  // buffer 大小独立设置
    // 注意: 没有任何检查确保 byteSize 与 dataShape 一致!
}
```

### 2. Python API 暴露攻击入口

**python_api_init.cpp (第149-180行):**
```cpp
.def("set_buffer", [](InferTensor &self, py::buffer &buf, bool needRelease) {
    auto bufferInfo = buf.request();
    // 只检查 buffer 大小上限，未验证与 shape 的匹配关系
    if (bufferInfo.size < 0 || bufferInfo.size > MAX_INPUTS_NUM || ...) {
        throw std::runtime_error(...);
    }
    auto bufferSize = bufferInfo.size * bufferInfo.itemsize;
    if (bufferSize > MAX_BYTE_ALLOWED || bufferSize <= 0) {
        throw std::runtime_error(...);
    }
    // ... 分配并设置 buffer
    self.SetBuffer(data, bufferSize, needRelease);  // 未与 shape 交叉验证!
})
```

### 3. 触发所需条件

| 条件 | 是否必需 | 说明 |
|------|---------|------|
| 攻击者可控 tensor 创建 | **必需** | Python API 直接暴露 InferTensor 创建 |
| shape 大于 buffer 容量 | **必需** | 构造 shape[1] > 实际 buffer 元素数 |
| tensor 名称 "STOP_TOKEN_IDS" | **必需** | 硬编码的 tensor 名称匹配 |
| 无上游验证 | **存在** | 全链路无 shape-buffer 一致性检查 |

---

## 攻击路径图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            攻击路径                                          │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌───────────────┐
│ Python Client│───>│ InferTensor  │───>│ InferRequest │───>│ GetRequests   │
│ (攻击者)     │    │ 构造         │    │ 添加 tensor  │    │ Callback      │
└──────────────┘    └──────────────┘    └──────────────┘    └───────────────┘
      │                   │                    │                    │
      │                   │                    │                    │
      ▼                   ▼                    ▼                    ▼
 创建恶意请求        shape = [1, 1000]    tensor名称         getRequest()
                     buffer = 1元素      "STOP_TOKEN_IDS"     返回请求队列
                     (不一致!)                                 │
                                                               │
┌──────────────────────────────────────────────────────────────┘
│
│
┌──────────────┐    ┌──────────────────────┐    ┌────────────────────┐
│ LlmManager   │───>│ AdaptGetRequestV1ToV2│───>│ TransformStopTokenIds│
│ 处理请求     │    │ 调用转换函数         │    │ [漏洞触发点]        │
└──────────────┘    └──────────────────────┘    └────────────────────┘
                                                          │
                                                          │
                                                          ▼
                                               ┌────────────────────┐
                                               │ OOB READ 发生      │
                                               │ 读取 shape[1]=1000 │
                                               │ 但 buffer 只有 1   │
                                               │ → 越界读取999个元素│
                                               └────────────────────┘
                                                          │
                                                          ▼
                                               ┌────────────────────┐
                                               │ 信息泄露/崩溃      │
                                               │ 读取敏感内存数据   │
                                               │ 可能触发 SEGFAULT  │
                                               └────────────────────┘
```

---

## PoC 构思 (不提供完整 PoC)

### 攻击思路

1. **创建恶意 InferTensor**:
   - 设置 `dataShape = [1, N]` 其中 N 很大 (如 10000)
   - 通过 `set_buffer()` 设置实际 buffer，仅包含 1-2 个元素

2. **构建恶意 InferRequest**:
   - 将恶意 tensor 以名称 "STOP_TOKEN_IDS" 添加到请求
   - 通过 `LlmManager` 的 `GetRequestsCallback` 提交请求

3. **触发漏洞**:
   - `AdaptGetRequestV1ToV2` 调用 `TransformStopTokenIds`
   - 循环基于 `GetShape()[1]` (10000) 迭代
   - 实际 buffer 只有 1-2 个元素 → OOB READ

### 验证方法

- 使用 AddressSanitizer (ASan) 编译可检测越界访问
- 监控进程内存访问异常日志
- 通过 fuzz testing 验证触发路径

---

## 影响评估

### 1. 安全影响

| 影响类型 | 严重程度 | 说明 |
|---------|---------|------|
| **信息泄露** | HIGH | 可读取进程内存中的敏感数据 (密钥、凭证、其他用户数据) |
| **拒绝服务** | MEDIUM | 可能触发 SIGSEGV 导致服务崩溃 |
| **代码执行** | LOW | 纯读取漏洞，不直接导致代码执行 |
| **完整性破坏** | NONE | 不影响数据完整性 |

### 2. CVSS 评估要素

- **Attack Vector (AV)**: Network - 通过 Python API 远程触发
- **Attack Complexity (AC)**: Low - 无需特殊条件，直接构造请求即可
- **Privileges Required (PR)**: Low - 需要能调用 LLM Manager API
- **User Interaction (UI)**: None - 无需用户交互
- **Scope (S)**: Changed - 可影响同一进程中的其他数据
- **Confidentiality Impact (C)**: High - 可泄露任意内存数据
- **Integrity Impact (I)**: None - 不修改数据
- **Availability Impact (A)**: High - 可导致服务崩溃

### 3. 与 VULN-LLMMGR-002 的关系

两个漏洞完全相同的漏洞模式:
- **VULN-LLMMGR-002**: 在 `TransformInputId` 函数中的相同漏洞
- **VULN-LLMMGR-003**: 在 `TransformStopTokenIds` 函数中的相同漏洞

两者共享相同的根本原因 (InferTensor shape-buffer 不一致) 和攻击路径。

---

## 修复建议

### 1. 紧急缓解措施 (短期)

**在 TransformStopTokenIds 中添加边界检查:**

```cpp
void TransformStopTokenIds(std::shared_ptr<InferRequest>& req, std::shared_ptr<Request>& v2Req)
{
    TensorPtr stopTokenIdsTensorPtr = nullptr;
    req->GetTensorByName("STOP_TOKEN_IDS", stopTokenIdsTensorPtr);
    if (stopTokenIdsTensorPtr == nullptr) {
        MINDIE_LLM_LOG_ERROR("STOP_TOKEN_IDS tensor not found in request");
        return;
    }
    TokenId* stopTokenIdsTensorData = static_cast<TokenId*>(stopTokenIdsTensorPtr->GetData());
    if (stopTokenIdsTensorData == nullptr) {
        MINDIE_LLM_LOG_ERROR("INCLUDE_STOP_STR_IN_OUTPUT tensor data is null");
        return;
    }
    
    // 修复: 使用 GetSize() 获取实际 buffer 大小，而非 shape
    size_t actualElements = stopTokenIdsTensorPtr->GetSize() / sizeof(TokenId);
    size_t claimedElements = stopTokenIdsTensorPtr->GetShape()[1];
    
    // 验证一致性
    if (actualElements != claimedElements) {
        MINDIE_LLM_LOG_ERROR("STOP_TOKEN_IDS tensor size mismatch: buffer has " 
            + std::to_string(actualElements) + " elements but shape claims " 
            + std::to_string(claimedElements));
        return;  // 或抛出异常
    }
    
    for (size_t i = 0; i < actualElements; i++) {
        v2Req->stopTokenIds.value().push_back(stopTokenIdsTensorData[i]);
    }
}
```

### 2. 根本修复措施 (长期)

**在 InferTensor::SetBuffer 中强制一致性验证:**

```cpp
void InferTensor::SetBuffer(const void *buffer, size_t tensorbyteSize, bool tensorNeedRelease)
{
    if (buffer == nullptr) {
        MINDIE_LLM_LOG_ERROR("SetBuffer fail: buffer is nullptr");
        return;
    }
    if (tensorbyteSize > MAX_BYTE_ALLOWED) {
        MINDIE_LLM_LOG_ERROR("SetBuffer fail: tensorbyteSize is too large");
        return;
    }
    
    // 新增: 验证 buffer 大小与 shape 一致
    size_t expectedSize = CalculateExpectedSizeFromShape(dataShape, dataType);
    if (tensorbyteSize != expectedSize) {
        MINDIE_LLM_LOG_ERROR("SetBuffer fail: buffer size " + std::to_string(tensorbyteSize)
            + " does not match expected size from shape " + std::to_string(expectedSize));
        return;  // 拒绝不一致的设置
    }
    
    data = const_cast<void *>(buffer);
    byteSize = tensorbyteSize;
    this->needRelease = tensorNeedRelease;
}
```

### 3. Python API 加固

**在 set_buffer lambda 中添加交叉验证:**

```cpp
.def("set_buffer", [](InferTensor &self, py::buffer &buf, bool needRelease) {
    auto bufferInfo = buf.request();
    
    // 新增: 获取 tensor 的声称 shape
    auto shape = self.GetShape();
    size_t expectedElements = (shape.size() > 1) ? shape[1] : shape[0];
    size_t expectedBytes = expectedElements * self.GetTypeByteSize(self.GetDataType());
    
    // 验证 buffer 大小与 shape 匹配
    auto bufferSize = bufferInfo.size * bufferInfo.itemsize;
    if (bufferSize != expectedBytes) {
        throw std::runtime_error("Buffer size mismatch: expected " 
            + std::to_string(expectedBytes) + " bytes from shape, got " 
            + std::to_string(bufferSize) + " bytes");
    }
    
    // ... 后续代码
})
```

### 4. 同步修复 VULN-LLMMGR-002

相同的修复策略应应用于 `TransformInputId` 函数 (第36-39行)。

---

## 相关文件清单

| 文件路径 | 作用 |
|---------|------|
| `/src/llm_manager/llm_manager_adapter.cpp` | 漏洞触发点 |
| `/src/llm_manager/infer_tensor.cpp` | InferTensor 实现，根本原因 |
| `/src/include/llm_manager/infer_tensor.h` | InferTensor 类定义 |
| `/src/llm_manager/python_api/python_api_init.cpp` | Python 绑定，攻击入口 |
| `/src/llm_manager/llm_manager.cpp` | LlmManager 实现 |
| `/tests/fuzztest_llmmanager/llm_manager/llm_infer_engine.cpp` | Fuzz 测试入口 |

---

## 结论

**判定: 真实漏洞 (CONFIRMED)**

该漏洞是一个可被主动利用的高危漏洞:
- 根本原因明确: InferTensor 允许 shape 和 buffer 独立设置
- 攻击路径完整: 从 Python API 到漏洞触发点全链路可达
- 无缓解措施: 代码中不存在任何 shape-buffer 一致性验证
- 影响严重: 可导致敏感内存信息泄露和服务拒绝

建议立即实施紧急缓解措施，并在后续版本中进行根本性修复。同时修复相同模式的 VULN-LLMMGR-002 漏洞。
