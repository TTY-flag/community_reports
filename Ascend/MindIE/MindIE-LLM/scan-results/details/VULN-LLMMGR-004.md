# VULN-LLMMGR-004: TransformRequest张量数据构造字符串缺空终止符致越界读取

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-LLMMGR-004 |
| **类型** | Buffer Over-read (CWE-125) |
| **严重性** | MEDIUM |
| **状态** | CONFIRMED - 真实漏洞 |
| **位置** | `/src/llm_manager/llm_manager_adapter.cpp:83-86` |
| **函数** | `TransformRequest` |
| **影响组件** | LLM Manager V1->V2 适配层 |

### 漏洞描述

在 `TransformRequest` 函数中，使用 `std::string` 构造函数从张量数据指针创建字符串时，未检查空终止符是否存在于分配边界内。如果张量数据不包含空终止符，字符串构造函数将读取超出缓冲区边界，导致缓冲区过度读取。

---

## 漏洞代码分析

### 漏洞代码片段

```cpp
// llm_manager_adapter.cpp:83-86
auto str = [](auto& field) {
    return [&field](void* data, TensorPtr) {
        field = std::string(static_cast<char*>(data));  // 漏洞点
    };
};
```

### 使用位置

```cpp
// llm_manager_adapter.cpp:89-91
transform("LORA_ID", str(v2Req->loraId));      // 受影响
transform("STOP_STRINGS", str(v2Req->stopStrings));  // 受影响
```

### 问题分析

`std::string(const char*)` 构造函数的行为：
1. 从给定的 `char*` 指针开始读取
2. 持续读取直到遇到空终止符 `\0`
3. **不检查读取边界**

如果张量数据：
- 不包含空终止符
- 或空终止符位于分配区域之外

则字符串构造将读取相邻内存，可能暴露敏感数据或导致崩溃。

---

## 触发条件分析

### 必要条件

| 条件 | 是否可达 | 说明 |
|------|----------|------|
| 张量数据存在 | ✓ 可达 | 通过 `GetTensorByName` 获取 |
| 张量数据无空终止符 | ✓ 可达 | 用户可控，通过 Python API |
| 调用 `TransformRequest` | ✓ 可达 | 正常请求处理流程 |

### 触发路径

```
请求入口 → LlmManager → AdaptGetRequestV1ToV2 → TransformRequest → str lambda → std::string构造
```

### 特殊条件评估

- **无需特殊权限**：只要能调用 LLM Manager API 即可触发
- **无需认证绕过**：漏洞位于内部处理逻辑，不依赖认证状态
- **无需竞争条件**：单次请求即可触发

---

## 攻击路径图

### 攻击面分析

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           攻击入口点                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐               │
│  │   HTTP API   │    │  Python API  │    │  gRPC API    │               │
│  │  (部分缓解)   │    │  (完全暴露)   │    │  (待分析)    │               │
│  └───┬────┬─────┘    └───┬────┬─────┘    └───┬────┬─────┘               │
│      │    │              │    │              │    │                      │
│      ▼    │              ▼    │              ▼    │                      │
│  JSON解析  │          Tensor创建 │          Proto解析│                      │
│ (确保\0)   │         (无验证)   │         (待确认) │                      │
│            │              │    │              │    │                      │
│            │              ▼    │              │    │                      │
│            │      ┌───────────┐│              │    │                      │
│            │      │set_buffer ││              │    │                      │
│            │      │任意数据注入││              │    │                      │
│            │      └───┬───────┘│              │    │                      │
│            │          │        │              │    │                      │
└────────────┼──────────┼────────┼──────────────┼────┼──────────────────────┘
             │          │        │              │    │
             ▼          ▼        ▼              ▼    ▼
      ┌────────────────────────────────────────────────────┐
      │              InferRequest (V1)                      │
      │  ┌─────────────────────────────────────────────┐   │
      │  │  Tensor: LORA_ID / STOP_STRINGS             │   │
      │  │  Data: [非空终止的二进制数据]                │   │
      │  └─────────────────────────────────────────────┘   │
      └───────────────────────┬────────────────────────────┘
                              │
                              ▼
      ┌────────────────────────────────────────────────────┐
      │         LlmManager::AdaptGetRequestV1ToV2()         │
      │                                                     │
      │  getRequest() → 返回 InferRequest 列表              │
      └───────────────────────┬────────────────────────────┘
                              │
                              ▼
      ┌────────────────────────────────────────────────────┐
      │           TransformRequest(req, v2Req)              │
      │                                                     │
      │  transform("LORA_ID", str(v2Req->loraId))           │
      │  transform("STOP_STRINGS", str(v2Req->stopStrings)) │
      └───────────────────────┬────────────────────────────┘
                              │
                              ▼
      ┌────────────────────────────────────────────────────┐
      │                str lambda 执行                       │
      │                                                     │
      │  field = std::string(static_cast<char*>(data))      │
      │                                                     │
      │  ████████ BUFFER OVER-READ ████████                 │
      │  读取直到遇到 \0，可能超出分配边界                   │
      └────────────────────────────────────────────────────┘
```

### 主要攻击路径：Python API

```
Python用户
    │
    ▼
┌─────────────────────────────────────┐
│  import llm_manager_python          │
│                                     │
│  tensor = InferTensor(              │
│    "LORA_ID",                       │
│    TYPE_STRING,                     │
│    [1, N]                           │
│  )                                  │
│                                     │
│  # 恶意数据：无空终止符              │
│  tensor.set_buffer(                 │
│    malicious_buffer,  # 无 \0       │
│    N,                               │
│    True                             │
│  )                                  │
│                                     │
│  request.add_tensor("LORA_ID", ...) │
└───────────────┬─────────────────────┘
                │
                ▼
        触发 TransformRequest
                │
                ▼
        Buffer Over-read 发生
```

---

## PoC 构思

### 概念验证思路（不提供完整代码）

1. **攻击向量选择**：通过 Python API 创建恶意张量

2. **恶意数据构造**：
   - 创建 LORA_ID 或 STOP_STRINGS 张量
   - 填充数据为非空终止的字符序列
   - 例如：填充 256 字节的非零数据

3. **触发漏洞**：
   - 将恶意张量添加到 InferRequest
   - 通过 GetRequestsCallback 提交请求
   - LlmManager 处理请求时触发过度读取

4. **预期结果**：
   - 内存读取超出边界
   - 可能导致崩溃或信息泄露
   - 日志中可能出现异常字符串

### 危险数据示例（示意）

```
正常数据:  "test_lora_id\0"      (有空终止符)
恶意数据:  "test_lora_id\xFF..." (无空终止符，后续为任意数据)
```

---

## 影响评估

### 直接影响

| 影响类型 | 严重程度 | 说明 |
|----------|----------|------|
| **信息泄露** | 中-高 | 读取相邻内存可能暴露敏感数据（密钥、内部状态） |
| **拒绝服务** | 中 | 可能导致进程崩溃 |
| **数据损坏** | 低 | 字符内容可能包含垃圾数据 |

### 间接影响

- **服务稳定性**：频繁触发可能导致服务不稳定
- **日志污染**：异常字符串可能污染日志系统
- **后续处理异常**：错误的字符串值可能导致下游逻辑异常

### 影响范围

- **本地攻击**：使用 Python API 的本地用户可直接触发
- **远程攻击**：通过 HTTP API 需要绕过 JSON 解析层的隐式空终止
- **多租户环境**：可能影响同一服务上的其他用户请求

---

## 缓解措施评估

### 现有缓解措施

| 措施 | 位置 | 有效性 |
|------|------|--------|
| LORA_ID 长度限制 | `endpoint_def.h:MAX_LORA_ID_LENGTH=256` | ❌ 无效 - 不检查空终止符 |
| JSON 解析隐式 \0 | `single_req_vllm_infer_interface.cpp` | ⚠️ 部分 - 仅保护 HTTP 入口 |
| 张量大小限制 | `infer_tensor.cpp:MAX_BYTE_ALLOWED` | ❌ 无效 - 不防止过度读取 |

### 缺失的缓解

- ❌ 无空终止符检查
- ❌ 无张量大小传递给字符串构造
- ❌ 无数据内容验证

---

## 修复建议

### 方案 1：使用 size-aware 字符串构造（推荐）

```cpp
auto str = [](auto& field) {
    return [&field](void* data, TensorPtr tensor) {
        if (tensor == nullptr || tensor->GetData() == nullptr) {
            return;
        }
        size_t size = tensor->GetSize();
        // 查找空终止符位置
        const char* charData = static_cast<const char*>(data);
        size_t strLen = 0;
        while (strLen < size && charData[strLen] != '\0') {
            strLen++;
        }
        field = std::string(charData, strLen);  // 使用指定长度构造
    };
};
```

### 方案 2：添加空终止符验证

```cpp
auto str = [](auto& field) {
    return [&field](void* data, TensorPtr tensor) {
        if (tensor == nullptr) {
            return;
        }
        const char* charData = static_cast<const char*>(data);
        size_t size = tensor->GetSize();
        // 验证空终止符存在
        bool hasNullTerminator = false;
        for (size_t i = 0; i < size; i++) {
            if (charData[i] == '\0') {
                hasNullTerminator = true;
                break;
            }
        }
        if (!hasNullTerminator) {
            MINDIE_LLM_LOG_ERROR("String tensor missing null terminator");
            return;  // 或抛出异常
        }
        field = std::string(charData);
    };
};
```

### 方案 3：张量创建时强制空终止

在 Python API 的 `set_buffer` 中添加空终止符：

```cpp
// python_api_init.cpp set_buffer lambda 修改
.def("set_buffer", [](InferTensor &self, py::buffer &buf, bool needRelease) {
    // ... 现有检查 ...
    
    // 对于 TYPE_STRING 张量，确保空终止
    if (self.GetDataType() == InferDataType::TYPE_STRING) {
        // 分配额外字节并添加 \0
        void *data = malloc(bufferSize + 1);
        memcpy_s(data, bufferSize, bufferInfo.ptr, bufferSize);
        static_cast<char*>(data)[bufferSize] = '\0';
        self.SetBuffer(data, bufferSize + 1, needRelease);
    } else {
        // 原有逻辑
    }
})
```

---

## 结论

### 漏洞判定：真实漏洞

**理由**：
1. 漏洞代码路径完全可达
2. 存在有效的攻击入口（Python API）
3. 无现有缓解措施阻止此攻击
4. 影响范围明确且可造成实际危害

### 建议

1. **立即修复**：采用方案 1 或方案 2 修复 `llm_manager_adapter.cpp`
2. **防御加固**：在张量创建层添加空终止符强制要求
3. **测试覆盖**：添加无空终止符张量的边界测试
4. **文档更新**：明确说明字符串张量必须包含空终止符

---

## 相关文件

- `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/src/llm_manager/llm_manager_adapter.cpp` - 漏洞文件
- `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/src/llm_manager/python_api/python_api_init.cpp` - 攻击入口
- `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/src/include/llm_manager/infer_tensor.h` - 张量定义
- `/home/pwn20tty/Desktop/opencode_project/shenteng/MindIE/MindIE-LLM/tests/dlt/ut/llm_manager/test_llm_manager_response_stub.cpp` - 正确用法示例

