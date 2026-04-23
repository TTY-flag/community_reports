# SEC-INFER-002: GetFaultRecoveryCmdType枚举类型转换缺边界验证

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | SEC-INFER-002 |
| **类型** | Unsafe Enum Type Conversion (不安全枚举类型转换) |
| **CWE** | CWE-190 (Integer Overflow/Wrap-around) |
| **原始严重程度** | Medium |
| **分析结论** | **误报 / 低风险代码质量问题** |

### 漏洞位置

- **文件**: `src/server/endpoint/single_req_infer_interface/parse_protocol.cpp`
- **行号**: 206-207
- **函数**: `GetFaultRecoveryCmdType`

### 漏洞代码

```cpp
// 第199-214行
LOCAL_API uint32_t GetFaultRecoveryCmdType(const OrderedJson &jsonData, FaultRecoveryCmd &cmdType, std::string &cmdStr)
{
    if (!jsonData.contains("cmd") || jsonData["cmd"].is_null()) {
        return EP_PARSE_NO_PARAM_ERR;
    }
    // 漏洞点: 直接将int转换为枚举，无范围验证
    try {
        cmdType = static_cast<FaultRecoveryCmd>(jsonData["cmd"].get<int>());  // 危险
        cmdStr = FaultRecoveryCmdToString(cmdType);
    } catch (std::exception &exception) {
        ULOG_ERROR(SUBMODLE_NAME_ENDPOINT, GenerateEndpointErrCode(ERROR, SUBMODLE_FEATURE_FAULT_CONTROL,
            CHECK_ERROR), "Get FaultRecoveryCmdType type failed.");
        return EP_PARSE_JSON_ERR;
    }
    return EP_OK;
}
```

---

## 触发条件分析

### 枚举定义

```cpp
// src/include/llm_manager/data_type.h:93-99
enum FaultRecoveryCmd: int32_t {
    CMD_UNKNOWN = -1,
    CMD_PAUSE_ENGINE = 0,
    CMD_REINIT_NPU = 1,
    CMD_START_ENGINE = 2,
    CMD_PAUSE_ENGINE_ROCE = 3
};
```

**有效值范围**: -1 到 3

### 攻击入口

**HTTP端点**: `POST /v1/engine-server/fault-handling-command`

```cpp
// http_handler.cpp:712-718
server.Post("/v1/engine-server/fault-handling-command",
    [](const httplib::Request &request, httplib::Response &response) {
        ULOG_DEBUG(SUBMODLE_NAME_ENDPOINT, "POST /v1/engine-server/running-status request received");
        std::shared_ptr<RequestContext> context = std::make_shared<RequestContext>(request, response);
        HandlePostCmdToEngine(context);
        return;
    });
```

### 触发条件

| 条件 | 状态 |
|------|------|
| **外部可达** | ✅ 是 - 通过HTTP API |
| **需要认证** | ❓ 未知 - 需检查服务配置 |
| **可控输入** | ✅ 是 - `cmd` 字段完全由攻击者控制 |
| **特殊条件** | ❌ 否 - 无特殊前提条件 |

---

## 攻击路径图

```
┌─────────────────────────────────────────────────────────────────────┐
│                         攻击路径分析                                  │
└─────────────────────────────────────────────────────────────────────┘

[攻击者]
    │
    ▼
┌───────────────────────────────────────────────────────────────────┐
│ HTTP POST /v1/engine-server/fault-handling-command                │
│ Body: {"cmd": <恶意整数值>}                                        │
└───────────────────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────────────────┐
│ HttpHandler::HandlePostCmdToEngine()                               │
│ http_handler.cpp:721-779                                           │
└───────────────────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────────────────┐
│ JsonParse::DecodeFaultRecoveryCmd()                                │
│ parse_protocol.cpp:242-266                                         │
│ - JSON解析                                                         │
│ - UTF-8转换                                                        │
└───────────────────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────────────────┐
│ GetFaultRecoveryCmdType() ◄ 漏洞点                                 │
│ parse_protocol.cpp:199-214                                        │
│ - 提取 jsonData["cmd"].get<int>()                                 │
│ - static_cast<FaultRecoveryCmd> 无范围检查                         │
└───────────────────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────────────────┐
│ FaultRecoveryCmdToString() ◄ 缓解措施                              │
│ parse_protocol.cpp:183-197                                        │
│ - switch 语句有 default case                                      │
│ - 返回 "CMD_UNKNOWN" 对于无效值                                    │
└───────────────────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────────────────┐
│ HandlePostCmdToEngine() 命令处理逻辑                               │
│ http_handler.cpp:745-774                                          │
│ - callHandler lambda 只匹配有效枚举值                              │
│ - 无效值: handled = false → 返回 400 Bad Request                  │
└───────────────────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────────────────┐
│ 结果: 无效命令不被执行，返回错误响应                                │
└───────────────────────────────────────────────────────────────────┘
```

---

## 缓解措施分析

### 1. FaultRecoveryCmdToString 默认处理

```cpp
// parse_protocol.cpp:183-197
LOCAL_API std::string FaultRecoveryCmdToString(FaultRecoveryCmd cmdType)
{
    switch (cmdType) {
        case FaultRecoveryCmd::CMD_PAUSE_ENGINE:
            return "CMD_PAUSE_ENGINE";
        case FaultRecoveryCmd::CMD_REINIT_NPU:
            return "CMD_REINIT_NPU";
        case FaultRecoveryCmd::CMD_START_ENGINE:
            return "CMD_START_ENGINE";
        case FaultRecoveryCmd::CMD_PAUSE_ENGINE_ROCE:
            return "CMD_PAUSE_ENGINE_ROCE";
        default:
            return "CMD_UNKNOWN";  // ◄ 缓解措施
    }
}
```

### 2. 命令处理逻辑只匹配有效值

```cpp
// http_handler.cpp:745-774
auto callHandler = [cmdType, serviceStatus, &info, &status](
    FaultRecoveryCmd cmd, ServiceStatus statusToCheck,
    void (*handler)(RecoverCommandInfo&, Status&)
) -> bool {
    if (cmdType == cmd && serviceStatus == statusToCheck) {  // ◄ 枚举值比较
        handler(info, status);
        return true;
    }
    return false;
};

bool handled = callHandler(FaultRecoveryCmd::CMD_PAUSE_ENGINE, ...)
    || callHandler(FaultRecoveryCmd::CMD_REINIT_NPU, ...)
    || callHandler(FaultRecoveryCmd::CMD_START_ENGINE, ...)
    || callHandler(FaultRecoveryCmd::CMD_PAUSE_ENGINE_ROCE, ...);

if (!handled) {
    // 返回 400 Bad Request: "Command is not consistent with current status."
}
```

### 3. 后续命令处理基于字符串比较

```cpp
// executor.cpp:926-936
if (commandInfo.command == "CMD_PAUSE_ENGINE") {
    request.set_execute_type(PAUSE_COMMAND_EXEC);
} else if (commandInfo.command == "CMD_PAUSE_ENGINE_ROCE") {
    request.set_execute_type(PAUSE_COMMAND_EXEC_ROCE);
} else if (commandInfo.command == "CMD_REINIT_NPU") {
    request.set_execute_type(RECOVER_COMMAND_EXEC);
} else if (commandInfo.command == "CMD_START_ENGINE") {
    request.set_execute_type(START_COMMAND_EXEC);
}
// 无效字符串不匹配任何条件
```

---

## PoC 构思

### 测试用例 1: 超出范围的正整数

```json
POST /v1/engine-server/fault-handling-command
Content-Type: application/json

{"cmd": 999}
```

**预期结果**: 
- `cmdType = static_cast<FaultRecoveryCmd>(999)` → 未定义枚举值
- `FaultRecoveryCmdToString(999)` → 返回 "CMD_UNKNOWN"
- 命令不匹配任何处理器
- 返回 400 Bad Request

### 测试用例 2: 负整数

```json
POST /v1/engine-server/fault-handling-command
Content-Type: application/json

{"cmd": -100}
```

**预期结果**: 同上

### 测试用例 3: 有效值边界测试

```json
{"cmd": 0}   // CMD_PAUSE_ENGINE - 有效
{"cmd": 3}   // CMD_PAUSE_ENGINE_ROCE - 有效
{"cmd": 4}   // 超出范围 - 无效
{"cmd": -1}  // CMD_UNKNOWN - 边界情况
```

---

## 影响评估

### 漏洞分类

| 评估项 | 结论 |
|--------|------|
| **真实漏洞** | ❌ 否 - 实际为代码质量问题 |
| **内存安全** | ✅ 安全 - 无缓冲区溢出、UAF等 |
| **逻辑绕过** | ✅ 安全 - 无效命令不会被执行 |
| **DoS 可能** | ❌ 低风险 - 仅返回错误响应 |

### 影响程度

| 类型 | 影响 |
|------|------|
| **信息泄露** | 无 |
| **权限提升** | 无 |
| **代码执行** | 无 |
| **DoS** | 极低 - 仅错误处理开销 |
| **逻辑绕过** | 无 - 无效值被拒绝 |

### 结论

**此漏洞为误报或低风险代码质量问题**，原因：

1. ✅ **防御性编程**: `FaultRecoveryCmdToString` 有 default case
2. ✅ **命令验证**: 处理逻辑只匹配有效枚举值
3. ✅ **无安全绕过**: 无效命令被正确拒绝
4. ❌ **缺乏输入验证**: 应在转换前检查范围（代码质量问题）

---

## 修复建议

### 推荐修复方案

在 `GetFaultRecoveryCmdType` 函数中添加范围验证：

```cpp
LOCAL_API uint32_t GetFaultRecoveryCmdType(const OrderedJson &jsonData, 
                                            FaultRecoveryCmd &cmdType, 
                                            std::string &cmdStr)
{
    if (!jsonData.contains("cmd") || jsonData["cmd"].is_null()) {
        return EP_PARSE_NO_PARAM_ERR;
    }
    
    try {
        int cmdValue = jsonData["cmd"].get<int>();
        
        // 添加范围验证
        if (cmdValue < static_cast<int>(FaultRecoveryCmd::CMD_PAUSE_ENGINE) ||
            cmdValue > static_cast<int>(FaultRecoveryCmd::CMD_PAUSE_ENGINE_ROCE)) {
            ULOG_ERROR(SUBMODLE_NAME_ENDPOINT, 
                       GenerateEndpointErrCode(ERROR, SUBMODLE_FEATURE_FAULT_CONTROL, CHECK_ERROR), 
                       "Invalid FaultRecoveryCmd value: " << cmdValue);
            return EP_INVALID_PARAM;
        }
        
        cmdType = static_cast<FaultRecoveryCmd>(cmdValue);
        cmdStr = FaultRecoveryCmdToString(cmdType);
        
    } catch (std::exception &exception) {
        ULOG_ERROR(SUBMODLE_NAME_ENDPOINT, 
                   GenerateEndpointErrCode(ERROR, SUBMODLE_FEATURE_FAULT_CONTROL, CHECK_ERROR), 
                   "Get FaultRecoveryCmdType type failed.");
        return EP_PARSE_JSON_ERR;
    }
    return EP_OK;
}
```

### 替代方案：使用辅助函数

```cpp
LOCAL_API bool IsValidFaultRecoveryCmd(int value) {
    return value >= static_cast<int>(FaultRecoveryCmd::CMD_PAUSE_ENGINE) &&
           value <= static_cast<int>(FaultRecoveryCmd::CMD_PAUSE_ENGINE_ROCE);
}
```

---

## 最终判定

| 项目 | 结论 |
|------|------|
| **漏洞类型** | CWE-190 (不恰当的输入验证) |
| **实际风险** | **低 / 信息性** |
| **修复优先级** | P4 (建议修复，非紧急) |
| **建议处置** | 作为代码质量问题处理，不作为安全漏洞 |

**理由**: 虽然缺少显式输入验证是不良实践，但现有代码已有足够的防御措施防止安全影响。建议作为代码质量改进项处理，而非安全漏洞。

---

*报告生成时间: 2026-04-17*
*分析工具: 深度代码审计*
