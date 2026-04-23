# VULN-INF-002: InitPDNode中stoi转换缺异常处理致服务崩溃

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-INF-002 |
| **类型** | Improper Exception Handling (CWE-252) |
| **原始严重性** | Medium |
| **评估后严重性** | Low (防御性漏洞) |
| **文件位置** | `src/server/infer_instances/infer_instances.cpp` |
| **代码行** | 634-636 |
| **函数** | `InferInstance::InitPDNode` |
| **状态** | CONFIRMED (真实漏洞，但存在输入验证缓解) |

### 漏洞描述

在 `InitPDNode` 函数中，第635行的 `stoi(id)` 转换调用缺少异常处理。如果输入字符串包含非数字字符或超出 `int` 范围的数值，将抛出 `std::invalid_argument` 或 `std::out_of_range` 异常，导致服务崩溃。

```cpp
// 漏洞代码 (infer_instances.cpp:634-636)
for (auto &id : Split(ipInfo["local_logic_device_id"], ',')) {
    deviceIds.insert(static_cast<size_t>(stoi(id)));  // ← 无异常处理
}
```

---

## 触发条件分析

### 1. 原始触发条件

`std::stoi()` 在以下情况会抛出异常：

| 异常类型 | 触发条件 | 示例输入 |
|----------|----------|----------|
| `std::invalid_argument` | 字符串包含非数字字符 | `"abc"`, `"12a3"`, `""` |
| `std::out_of_range` | 数值超出 `int` 范围 | `"999999999999999999"` |

### 2. 实际可达性评估

**关键发现：HTTP端点存在输入验证**

漏洞触发需要绕过以下验证链：

```
HTTP Request → HandlePDRole/HandlePDRoleV2 → CheckPDRoleReqJson/CheckPDRoleV2ReqJson
                                          ↓
                            CheckPDIPInfo/CheckPDV2IPInfo
                                          ↓
                            ValidateDeviceField → CheckPDDeviceIPInfo
                                          ↓
                            IsNumber() 验证 device_logical_id
                                          ↓
                            (验证通过后) ProcessInitInfo/ProcessInitInfoV2
                                          ↓
                            localDeviceLogicalIds 被填充
                                          ↓
                            InitPDNode → stoi(id) [漏洞点]
```

### 3. 输入验证详情

**验证函数**: `IsNumber()` (`src/utils/common_util.cpp:252-267`)

```cpp
bool IsNumber(const std::string &str)
{
    if (str.empty() || str[0] == ' ') {
        return false;
    }
    try {
        size_t pos;
        std::stol(str, &pos);  // 使用 stol 进行验证
        return pos == str.size();
    } catch (const std::invalid_argument&) {
        return false;
    } catch (const std::out_of_range&) {
        return false;  // ← 捕获范围溢出异常
    }
}
```

**验证覆盖**:
- ✅ 检查字符串非空
- ✅ 检查无前导空格
- ✅ 捕获 `invalid_argument` 异常
- ✅ 捕获 `out_of_range` 异常
- ✅ 确保整个字符串被解析

### 4. 触发难度评估

| 维度 | 评估 |
|------|------|
| **直接攻击可达性** | LOW - 需绕过HTTP验证 |
| **内部调用可达性** | LOW - 仅通过HTTP API填充数据 |
| **配置文件路径** | N/A - 数据来自HTTP请求 |
| **总体触发难度** | LOW |

---

## 攻击路径图

### 主攻击路径 (被验证阻断)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        攻击尝试路径                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  [外部攻击者]                                                        │
│       │                                                              │
│       │  POST /v1/role/prefill 或 /v2/role/prefill                  │
│       │  Body: {"local": {"device": [{"device_logical_id": "abc"}]}}│
│       ▼                                                              │
│  ┌──────────────────────┐                                           │
│  │ HandlePDRole         │                                           │
│  │ HandlePDRoleV2       │                                           │
│  └──────────────────────┘                                           │
│       │                                                              │
│       ▼                                                              │
│  ┌──────────────────────┐                                           │
│  │ CheckPDRoleReqJson   │                                           │
│  │ CheckPDRoleV2ReqJson │                                           │
│  └──────────────────────┘                                           │
│       │                                                              │
│       ▼                                                              │
│  ┌──────────────────────┐    ┌─────────────────────┐               │
│  │ CheckPDIPInfo        │───▶│ ValidateDeviceField │               │
│  │ CheckPDV2IPInfo      │    └─────────────────────┘               │
│  └──────────────────────┘              │                            │
│                                        ▼                            │
│                          ┌─────────────────────┐                   │
│                          │ CheckPDDeviceIPInfo │                   │
│                          └─────────────────────┘                   │
│                                      │                              │
│                                      ▼                              │
│                          ┌─────────────────────┐                   │
│                          │ IsNumber() 验证     │                   │
│                          │ "abc" → 返回 false  │  ← 验证阻断点     │
│                          └─────────────────────┘                   │
│                                      │                              │
│                                      ▼                              │
│                          ┌─────────────────────┐                   │
│                          │ 返回 HTTP 422 错误  │                   │
│                          │ 请求被拒绝          │                   │
│                          └─────────────────────┘                   │
│                                                                      │
│  ❌ 攻击路径被阻断于输入验证层                                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 潜在绕过场景 (理论风险)

```
┌─────────────────────────────────────────────────────────────────────┐
│                      潜在绕过风险场景                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  场景1: 未来代码变更移除验证                                          │
│  ─────────────────────────────                                      │
│  如果未来版本移除 CheckPDDeviceIPInfo 验证，漏洞将直接可利用         │
│                                                                      │
│  场景2: 内部模块直接调用 InitPDNode                                   │
│  ─────────────────────────────                                      │
│  当前无此类调用，但如果新增代码路径直接填充 GlobalIpInfo              │
│  并调用 InitPDNode，将绕过验证                                       │
│                                                                      │
│  场景3: 配置文件或其他数据源                                          │
│  ─────────────────────────────                                      │
│  当前 localDeviceLogicalIds 仅从 HTTP API 填充                      │
│  如果未来支持从配置文件读取，可能绕过验证                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## PoC 构思

### 验证测试方案

**目的**: 验证输入验证的有效性

**测试用例**:

| 测试输入 | 预期结果 | 验证点 |
|----------|----------|--------|
| `"abc"` | HTTP 422 | 非数字字符被拒绝 |
| `"12a3"` | HTTP 422 | 部分数字被拒绝 |
| `""` | HTTP 422 | 空字符串被拒绝 |
| `" 123"` | HTTP 422 | 前导空格被拒绝 |
| `"999999999999999999"` | HTTP 422 | 范围溢出被拒绝 |
| `"123"` | HTTP 200 | 有效输入被接受 |

**测试请求示例** (用于验证输入验证):

```json
POST /v1/role/prefill
Content-Type: application/json

{
  "local": {
    "id": 1,
    "host_ip": "192.168.1.1",
    "server_ip": "192.168.1.1",
    "device": [
      {
        "device_ip": "192.168.1.10",
        "device_logical_id": "abc",  // ← 测试无效输入
        "device_id": "0"
      }
    ]
  },
  "peers": []
}
```

**预期响应**: HTTP 422 Unprocessable Content

---

## 影响评估

### 1. 直接影响 (假设绕过验证)

| 影响类型 | 评估 | 说明 |
|----------|------|------|
| **服务崩溃 (DoS)** | MEDIUM | 未捕获异常导致进程终止 |
| **信息泄露** | LOW | 异常信息可能泄露内部状态 |
| **代码执行** | NONE | 仅导致崩溃，无执行能力 |
| **数据完整性** | NONE | 不涉及数据修改 |

### 2. 实际风险 (考虑验证缓解)

| 风险维度 | 评估 | 说明 |
|----------|------|------|
| **攻击复杂度** | HIGH | 需找到绕过验证的方法 |
| **攻击者要求** | HIGH | 深入了解系统架构 |
| **现实可利用性** | LOW | 当前验证机制有效 |
| **整体风险等级** | LOW | 防御性漏洞 |

### 3. 代码质量问题

| 问题 | 严重性 | 说明 |
|------|--------|------|
| **防御缺失** | HIGH | 违反防御纵深原则 |
| **代码不一致** | HIGH | 同类代码 DeserializeSet 有异常处理 |
| **健壮性不足** | MEDIUM | 应有内部异常处理 |

---

## 代码对比分析

### 安全实现参考: DeserializeSet

`DeserializeSet` 函数 (`src/utils/common_util.cpp:792-824`) 展示了正确的异常处理模式：

```cpp
std::set<size_t> DeserializeSet(const std::string& data)
{
    std::set<size_t> resultSet{};
    std::size_t start = 0;
    std::size_t end;
    while ((end = data.find(',', start)) != std::string::npos) {
        std::string elemStr = data.substr(start, end - start);
        try {
            size_t elemUl = static_cast<size_t>(std::stoul(elemStr));
            resultSet.insert(elemUl);
            start = end + 1;
        } catch (const std::invalid_argument& e) {
            std::cout << "Invalid argument: " << e.what() << std::endl;
            continue;  // ← 异常处理：跳过无效元素
        } catch (const std::out_of_range& e) {
            std::cout << "Convert " << elemStr << "to unsigned long failed." 
                      << e.what() << std::endl;
            continue;  // ← 异常处理：跳过溢出元素
        } catch (...) {
            std::cout << "An unknown exception occurred..." << std::endl;
            continue;  // ← 异常处理：通用捕获
        }
    }
    // ... 处理最后一个元素 ...
    return resultSet;
}
```

### 漏洞代码 vs 安全代码

| 特性 | 漏洞代码 (InitPDNode) | 安全代码 (DeserializeSet) |
|------|----------------------|---------------------------|
| **异常捕获** | ❌ 无 | ✅ 捕获所有异常类型 |
| **错误处理** | ❌ 直接崩溃 | ✅ 跳过无效元素继续处理 |
| **日志记录** | ❌ 无 | ✅ 记录错误信息 |
| **返回处理** | ❌ 异常传播 | ✅ 返回有效结果集 |

---

## 修复建议

### 优先级: P2 (中等优先级 - 防御性改进)

### 修复方案

**方案1: 添加异常处理 (推荐)**

```cpp
// 修复后代码
for (auto &id : Split(ipInfo["local_logic_device_id"], ',')) {
    try {
        deviceIds.insert(static_cast<size_t>(stoi(id)));
    } catch (const std::invalid_argument& e) {
        ULOG_ERROR(SUBMODLE_NAME_INFERINSTANCE, "[MIE05E040001]",
                   "Invalid device_logical_id: " << id << ", " << e.what());
        return Status(Error::Code::ERROR, "Invalid device_logical_id format");
    } catch (const std::out_of_range& e) {
        ULOG_ERROR(SUBMODLE_NAME_INFERINSTANCE, "[MIE05E040001]",
                   "device_logical_id out of range: " << id << ", " << e.what());
        return Status(Error::Code::ERROR, "device_logical_id out of range");
    }
}
```

**方案2: 使用现有 DeserializeSet 工具函数**

```cpp
// 使用现有工具函数
std::set<size_t> deviceIds = DeserializeSet(ipInfo["local_logic_device_id"]);
```

**方案3: 使用更安全的转换函数**

```cpp
// 使用 stoul 并检查范围
for (auto &id : Split(ipInfo["local_logic_device_id"], ',')) {
    try {
        unsigned long val = std::stoul(id);
        if (val > std::numeric_limits<size_t>::max()) {
            ULOG_ERROR(...);
            return Status(Error::Code::ERROR, "Value out of range");
        }
        deviceIds.insert(static_cast<size_t>(val));
    } catch (...) {
        // 异常处理
    }
}
```

### 修复影响评估

| 维度 | 影响 |
|------|------|
| **代码改动量** | 小 - 仅需添加 try-catch |
| **测试需求** | 中 - 需测试异常场景 |
| **兼容性** | 无影响 - 行为保持一致 |
| **性能** | 微小影响 - 异常处理开销 |

---

## 相关漏洞

### 同类问题分布

| 位置 | 文件 | 行号 | 状态 |
|------|------|------|------|
| `std::stoi(device_id)` | `dmi_role.cpp` | 527, 663 | 有 try-catch |
| `std::stoi(super_device_id)` | `dmi_role.cpp` | 609, 739 | 有 try-catch |
| `std::stoi(device_logical_id)` | `http_handler.cpp` | 1196, 1228 | 有 catch(...) |
| `stoi(id)` | `infer_instances.cpp` | 635 | ❌ 无异常处理 |

---

## 结论

### 漏洞有效性判定

**判定**: **真实漏洞 (防御性漏洞)**

### 判定理由

1. **代码缺陷存在**: `stoi()` 调用确实缺少异常处理
2. **验证机制有效**: HTTP 端点存在有效的输入验证，阻止直接攻击
3. **防御纵深缺失**: 即使有外部验证，内部代码应有独立防御
4. **代码一致性问题**: 同类代码有异常处理，此处缺失不一致

### 建议处置

| 处置建议 | 原因 |
|----------|------|
| **保留漏洞记录** | 真实代码缺陷，需修复 |
| **调整严重性** | 从 Medium 调整为 Low |
| **标记为防御性** | 验证机制提供主要防护 |
| **计划修复** | P2 优先级，改进代码质量 |

---

## 附录: 数据流追踪

```
GlobalIpInfo.localDeviceLogicalIds 数据来源追踪:

┌──────────────────────────────────────────────────────────────────┐
│ HTTP Request Body                                                │
│ {                                                                │
│   "local": {                                                     │
│     "device": [{                                                 │
│       "device_logical_id": "123"  ← 原始输入                     │
│     }]                                                           │
│   }                                                              │
│ }                                                                │
└──────────────────────────────────────────────────────────────────┘
         │
         │ JSON 解析
         ▼
┌──────────────────────────────────────────────────────────────────┐
│ ProcessInitInfo / ProcessInitInfoV2 (dmi_role.cpp:397,448)       │
│                                                                  │
│ globalIpInfo.localDeviceLogicalIds.emplace_back(                 │
│     deviceInfo["device_logical_id"]);                            │
│                                                                  │
│ 存储类型: std::vector<std::string>                               │
└──────────────────────────────────────────────────────────────────┘
         │
         │ CreateIpInfo 转换
         ▼
┌──────────────────────────────────────────────────────────────────┐
│ CreateIpInfo (infer_instances.cpp:525)                           │
│                                                                  │
│ ipInfo["local_logic_device_id"] =                                │
│     JoinStrings(globalIpInfo.localDeviceLogicalIds, ",");        │
│                                                                  │
│ 存储类型: std::map<std::string, std::string>                     │
│ 值格式: "123,456,789" (逗号分隔)                                 │
└──────────────────────────────────────────────────────────────────┘
         │
         │ Split 解析
         ▼
┌──────────────────────────────────────────────────────────────────┐
│ InitPDNode (infer_instances.cpp:634-636)                         │
│                                                                  │
│ for (auto &id : Split(ipInfo["local_logic_device_id"], ',')) {   │
│     deviceIds.insert(static_cast<size_t>(stoi(id))); ← 漏洞点    │
│ }                                                                │
│                                                                  │
│ stoi() 输入类型: std::string                                     │
│ stoi() 输出类型: int → size_t                                    │
└──────────────────────────────────────────────────────────────────┘
```

