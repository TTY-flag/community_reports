# VULN-LLMMGR-005: GetShape直接访问第二维度缺验证致越界访问

## 漏洞概述

**漏洞类型**: CWE-788 - Missing Shape Dimension Validation  
**严重程度**: MEDIUM  
**影响组件**: llm_manager  
**漏洞文件**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/src/llm_manager/llm_manager_adapter.cpp`  
**漏洞位置**: 行 36-37, 55  
**函数名**: `TransformInputId`, `TransformStopTokenIds`

### 漏洞描述

在 `TransformInputId` 函数中，代码直接访问 `GetShape()[1]` 获取张量的第二维度大小，但未预先验证张量形状向量是否至少包含2个维度。如果传入一个0D（标量）或1D张量，将导致 `std::vector` 的越界访问。

**漏洞代码片段**:
```cpp
// llm_manager_adapter.cpp:36-39
v2Req->input_token_num = inputIdTensorPtr->GetShape()[1];
for (int i = 0; i < inputIdTensorPtr->GetShape()[1]; i++) {
    v2Req->input_ids.push_back(inputIdData[i]);
}

// llm_manager_adapter.cpp:55 (相同问题)
for (int i = 0; i < stopTokenIdsTensorPtr->GetShape()[1]; i++) {
    v2Req->stopTokenIds.value().push_back(stopTokenIdsTensorData[i]);
}
```

---

## 触发条件分析

### 1. 前置条件

| 条件 | 是否必须 | 说明 |
|------|----------|------|
| INPUT_IDS 张量存在 | 必须 | 代码已检查 null |
| 张量数据指针非空 | 必须 | 代码已检查 null |
| 张量形状维度 >= 2 | **未检查** | **漏洞核心** |

### 2. 触发场景

| 场景 | 形状示例 | GetShape() 返回值 | 访问 [1] 结果 |
|------|----------|-------------------|---------------|
| 0D 张量（标量） | `{}` | 空向量 `[]` | **越界访问** |
| 1D 张量 | `{10}` | `[10]` | **越界访问** |
| 2D 张量（正常） | `{1, 100}` | `[1, 100]` | 正常访问 |

### 3. 可达性评估

**高度可达** - 存在多条攻击路径：

1. **Python API 直接绑定路径** (主要攻击面):
   - pybind11 绑定允许用户直接创建任意形状的张量
   - 无形状维度数量验证

2. **HTTP API 路径**:
   - Triton Token Infer Interface 有部分验证（检查 shape 为 1D 或 2D）
   - 但其他接口可能缺失验证

---

## 攻击路径图

```
┌─────────────────────────────────────────────────────────────────┐
│                        攻击入口点                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  入口1: Python API (主要)          入口2: HTTP Endpoint        │
│  ┌──────────────────────┐         ┌──────────────────────┐    │
│  │ llm_manager_python   │         │ Triton Token API     │    │
│  │ InferTensor(shape=[])│         │ (有部分验证)          │    │
│  └──────────────────────┘         └──────────────────────┘    │
│            │                              │                    │
│            ▼                              ▼                    │
│  ┌──────────────────────┐         ┌──────────────────────┐    │
│  │ InferRequest         │         │ Parse Protocol       │    │
│  │ add_tensor()         │         │ 创建 InferTensor     │    │
│  └──────────────────────┘         └──────────────────────┘    │
│            │                              │                    │
│            ▼                              ▼                    │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              LlmManager 处理请求                         │  │
│  │              AdaptGetRequestV1ToV2()                     │  │
│  └─────────────────────────────────────────────────────────┘  │
│                           │                                    │
│                           ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              漏洞触发点                                   │  │
│  │              TransformInputId()                          │  │
│  │              GetShape()[1] ← OOB ACCESS                  │  │
│  └─────────────────────────────────────────────────────────┘  │
│                           │                                    │
│                           ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              影响                                        │  │
│  │              - 程序崩溃 (DoS)                            │  │
│  │              - 未定义行为                                 │  │
│  │              - 潜在内存信息泄露                           │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## PoC 构思

### 概念验证思路 (不提供完整 PoC)

攻击者可以通过 Python API 创建一个形状维度不足的张量：

```python
# 概念演示 - 构造触发条件
import llm_manager_python

# 创建 0D 或 1D 张量作为 INPUT_IDS
malicious_shape = []  # 0D (空形状)
# 或: malicious_shape = [10]  # 1D

tensor = llm_manager_python.InferTensor(
    "INPUT_IDS",
    llm_manager_python.InferDataType.TYPE_INT64,
    malicious_shape  # 形状维度不足
)
# ... 通过 InferRequest 提交给 LlmManager
```

当 LlmManager 处理此请求时，`TransformInputId()` 函数将尝试访问 `GetShape()[1]`，触发越界访问。

---

## 影响评估

### 直接影响

| 影响类型 | 严重程度 | 说明 |
|----------|----------|------|
| **拒绝服务 (DoS)** | 高 | 程序崩溃，服务中断 |
| **信息泄露** | 低 | 异常消息可能包含内存布局信息 |
| **代码执行** | 无 | 纯数据访问漏洞，无代码注入路径 |

### 影响范围

- 影响所有使用 LlmManager Python API 的应用
- 可能影响部分 HTTP API 端点（取决于验证完整性）
- 服务崩溃后需重启恢复，影响业务连续性

### CVSS 评估因素

- **Attack Vector**: Network (通过 API 调用)
- **Attack Complexity**: Low (无需特殊条件)
- **Privileges Required**: Low (需要 API 访问权限)
- **User Interaction**: None
- **Scope**: Unchanged
- **Impact**: High (DoS), Low (信息泄露)

---

## 修复建议

### 1. 直接修复方案

在 `TransformInputId()` 函数中添加形状维度验证：

```cpp
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
    
    // [新增] 形状维度验证
    const auto& shape = inputIdTensorPtr->GetShape();
    if (shape.size() < 2) {
        MINDIE_LLM_LOG_ERROR("INPUT_IDS tensor shape must have at least 2 dimensions");
        return;
    }
    
    v2Req->input_token_num = shape[1];
    for (int i = 0; i < shape[1]; i++) {
        v2Req->input_ids.push_back(inputIdData[i]);
    }
}
```

### 2. 同样需要修复的位置

**TransformStopTokenIds 函数 (行 55)** 也存在相同问题：

```cpp
void TransformStopTokenIds(std::shared_ptr<InferRequest>& req, std::shared_ptr<Request>& v2Req)
{
    // ... 获取 tensor ...
    
    // [新增] 形状维度验证
    const auto& shape = stopTokenIdsTensorPtr->GetShape();
    if (shape.size() < 2) {
        MINDIE_LLM_LOG_ERROR("STOP_TOKEN_IDS tensor shape must have at least 2 dimensions");
        return;
    }
    
    for (int i = 0; i < shape[1]; i++) {
        v2Req->stopTokenIds.value().push_back(stopTokenIdsTensorData[i]);
    }
}
```

### 3. 深层防御建议

- **Python API 层面**: 在 `InferTensor` 构造时添加形状验证
- **InferRequest 层面**: 添加张量形状完整性检查
- **文档**: 明确说明 INPUT_IDS 张量必须是 2D 形状 `[batch_size, seq_len]`

---

## 现有缓解措施评估

| 缓解措施 | 位置 | 有效性 | 说明 |
|----------|------|--------|------|
| Triton Token API 验证 | `single_req_triton_token_infer_interface.cpp:250-256` | 部分 | 仅验证 HTTP API，不覆盖 Python 直接绑定 |
| Tensor null 检查 | `llm_manager_adapter.cpp:27-35` | 无效 | 不检查形状维度数量 |
| Python set_buffer 验证 | `python_api_init.cpp:172-174` | 无效 | 仅检查 numpy ndim，不检查 tensor shape |

**结论**: 当前缓解措施不完整，Python API 路径缺乏有效防护。

---

## 验证状态

| 项目 | 状态 |
|------|------|
| 漏洞确认 | CONFIRMED |
| 可达性分析 | 完成 |
| 影响评估 | 完成 |
| 修复建议 | 提供 |

---

## 相关文件

- `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/src/llm_manager/llm_manager_adapter.cpp` - 漏洞文件
- `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/src/llm_manager/python_api/python_api_init.cpp` - Python API 绑定
- `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/src/include/llm_manager/infer_tensor.h` - Tensor 接口定义
- `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/src/llm_manager/infer_tensor.cpp` - Tensor 实现

---

*报告生成时间: 2026-04-17*
