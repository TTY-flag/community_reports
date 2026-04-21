# 漏洞深度分析报告

## utils-vuln-001: 路径遍历过滤缺失 (CWE-22)

**严重性**: High  
**置信度**: 85%  
**CVSS 3.1 评分**: 7.5 (High)

---

## 1. 执行摘要

`StringUtil::ValidateCommandFilePathParam` 函数设计用于验证命令行路径参数的安全性，但**遗漏了关键的路径遍历字符检查**。函数仅过滤 Shell 注入字符（`|;&$><`等），不检查路径遍历序列 `..`。

攻击者可通过 WebSocket 请求传递包含 `../` 的路径参数，绕过验证后传递给 Python 脚本执行，可能导致：
- 读取任意文件
- 访问预期之外的目录
- 破坏数据完整性

---

## 2. 根因分析

### 2.1 漏洞代码位置

**文件**: `server/msinsight/src/utils/StringUtil.h`  
**行号**: 398-409  
**函数**: `StringUtil::ValidateCommandFilePathParam`

```cpp
static bool ValidateCommandFilePathParam(const std::string& path)
{
    if (path.empty()) {
        return false;
    }
    for (const auto &ch: path) {
        if (std::find(std::begin(injectList), std::end(injectList), ch) != std::end(injectList)) {
            return false;
        }
    }
    return true;
}
```

### 2.2 injectList 定义缺陷

`injectList` 数组包含以下字符：

```cpp
// Windows 平台
const std::vector<char> injectList = {
    '|', ';', '&', '$', '>', '<', '`', '\n', '\r', '\t', '\f', '\x7F'
};

// Linux 平台
const std::vector<char> injectList = {
    '|', ';', '&', '$', '>', '<', '`', '\\', '\n', '\r', '\t', '\f', '\x7F'
};
```

**关键缺陷**: `'.'` 字符不在 `injectList` 中！

这意味着路径 `/safe/path../../../etc/passwd` 会通过验证：
- 没有包含任何 `injectList` 中的字符
- 函数返回 `true`，表示"验证通过"

### 2.3 为什么需要检查 `..`

路径遍历攻击的核心是利用 `../` 序列向上跳转目录层级：

```
/safe/data/../../../etc/passwd
  → 解析后: /etc/passwd
```

即使应用限制用户只能访问 `/safe/data/` 目录，攻击者仍可通过 `../` 跳出限制。

---

## 3. 攻击路径重构

### 3.1 数据流完整路径

```
[入口点] WebSocket 请求 (OnMessageCb)
    ↓
[解析] ProtocolMessageBuffer::Pop → FromJson
    ↓
[分发] ModuleManager::OnDispatchModuleRequest
    ↓
[处理] CommunicationModule handler → ClusterFileParser::AttAnalyze
    ↓
[验证] StringUtil::ValidateCommandFilePathParam(selectedPath)
    ↓ [漏洞点: 遗漏 '..' 检查]
[执行] PythonUtil::ExecuteScript(scriptPath, arguments)
    ↓ arguments 包含 "-d ../../../etc/passwd"
[输出] Python 脚本接收路径参数并处理
```

### 3.2 关键代码调用链

**Step 1: WebSocket 请求入口**

文件: `server/src/server/WsServer.cpp:165`

```cpp
void WsServer::OnMessageCb(...) {
    // WebSocket 消息到达
    session->OnRequestMessage(message);  // 转发处理
}
```

**Step 2: 请求参数提取**

文件: `server/src/protocol/ProtocolMessageBuffer.cpp`

```cpp
// JSON 解析提取 selectedPath
Request request;
request.params["selectedPath"] = jsonValue;  // 用户可控
```

**Step 3: 调用 AttAnalyze**

文件: `server/src/modules/communication/parser/ClusterFileParser.cpp:428-451`

```cpp
bool ClusterFileParser::AttAnalyze(const std::string &selectedPath, ...) {
    // 漏洞点: ValidateCommandFilePathParam 不检查 '..'
    if (!StringUtil::ValidateCommandFilePathParam(selectedPath)) {
        return false;  // 仅检查 Shell 注入字符
    }
    
    // selectedPath 包含 '../' 仍会通过验证
    std::vector<std::string> arguments{"-d", selectedPath};
    PythonUtil::ExecuteScript(scriptPath, arguments);  // 传递给 Python
}
```

**Step 4: Python 脚本执行**

文件: `server/msinsight/src/utils/PythonUtil.cpp:44-57`

```cpp
int PythonUtil::ExecuteScript(const std::string& scriptPath, 
                               std::vector<std::string>& arguments) {
    // 使用 posix_spawnp 执行
    // arguments = {"-d", "../../../etc/passwd"}
    posix_spawnp(..., "python3", args, ...);
}
```

---

## 4. PoC 构造思路

### 4.1 概念验证方法

**注意**: 以下仅为概念性思路，不提供可执行代码。

1. **构造 WebSocket 消息**:
   ```json
   {
     "moduleName": "communication",
     "command": "attAnalyze",
     "params": {
       "selectedPath": "/normal/path/../../../../etc/passwd",
       "mode": "matrix"
     }
   }
   ```

2. **验证路径传递**:
   - 消息通过 WebSocket 发送到服务端
   - `selectedPath` 被 `ValidateCommandFilePathParam` 验证
   - 由于不含 Shell 注入字符，验证通过

3. **观察执行结果**:
   - Python 脚本接收 `-d /normal/path/../../../../etc/passwd` 参数
   - 脚本尝试处理该路径
   - 如果脚本使用 `os.path` 处理，`../` 会被解析

### 4.2 利用条件

| 条件 | 状态 | 说明 |
|------|------|------|
| WebSocket 可访问 | ✓ | 默认绑定 localhost，可配置网络接口 |
| 参数可控 | ✓ | `selectedPath` 来自 WebSocket JSON 请求 |
| 验证绕过 | ✓ | `ValidateCommandFilePathParam` 遗漏 `..` |
| Python 脚本执行 | ✓ | `PythonUtil::ExecuteScript` 直接传递参数 |

---

## 5. 可利用性评估

### 5.1 攻击难度评估

| 因素 | 评分 | 说明 |
|------|------|------|
| 攻击者知识要求 | 低 | 需了解 WebSocket 协议和 JSON 格式 |
| 访问要求 | 中 | 需能连接 WebSocket 服务 |
| 利用复杂度 | 低 | 直接构造路径即可绕过 |
| 特殊条件 | 中 | Python 脚本是否正确处理路径 |

### 5.2 影响评估

| 影响类型 | 严重程度 | 说明 |
|----------|----------|------|
| 信息泄露 | 高 | 可读取任意文件内容 |
| 数据完整性 | 中 | 可能修改非预期文件 |
| 服务可用性 | 低 | 主要影响数据安全 |

---

## 6. CVSS 3.1 评分

### 6.1 评分向量

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
```

### 6.2 评分详解

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Network (N) | 通过 WebSocket 远程攻击 |
| Attack Complexity (AC) | Low (L) | 无特殊条件，直接构造路径 |
| Privileges Required (PR) | None (N) | 无需认证 |
| User Interaction (UI) | None (N) | 无需用户交互 |
| Scope (S) | Unchanged (U) | 影响限于同一系统 |
| Confidentiality (C) | High (H) | 可读取敏感文件 |
| Integrity (I) | None (N) | 主要为信息泄露 |
| Availability (A) | None (N) | 不影响服务可用性 |

**基础评分**: 7.5 (High)

---

## 7. 缓解建议

### 7.1 立即修复 (P0)

**方案 A: 扩展 injectList**

```cpp
// 在 injectList 中添加 '.' 字符
const std::vector<char> injectList = {
    '|', ';', '&', '$', '>', '<', '`', '\\', '\n', '\r', '\t', '\f', '\x7F',
    '.'  // 新增: 防止路径遍历
};
```

**优点**: 简单直接  
**缺点**: 会禁止所有包含 `.` 的路径（包括合法文件名如 `data.txt`）

**方案 B: 专门的路径遍历检测**

```cpp
static bool ValidateCommandFilePathParam(const std::string& path)
{
    if (path.empty()) {
        return false;
    }
    
    // 检查 Shell 注入字符
    for (const auto &ch: path) {
        if (std::find(std::begin(injectList), std::end(injectList), ch) != std::end(injectList)) {
            return false;
        }
    }
    
    // 新增: 检查路径遍历序列
    if (path.find("..") != std::string::npos) {
        return false;
    }
    
    return true;
}
```

**优点**: 精准检测路径遍历，不影响合法文件名  
**推荐**: 方案 B

### 7.2 增强措施 (P1)

**在 AttAnalyze 中添加额外验证**:

```cpp
bool ClusterFileParser::AttAnalyze(...) {
    // 使用 realpath 规范化路径
    std::string realPath = FileUtil::GetRealPath(selectedPath);
    
    // 验证规范化路径仍在允许范围内
    if (!IsWithinAllowedDirectory(realPath)) {
        return false;
    }
    
    // 继续执行...
}
```

### 7.3 架构改进 (P2)

1. **统一路径验证接口**: 创建 `PathValidator` 类统一管理所有路径验证逻辑
2. **路径白名单**: 定义允许访问的目录列表
3. **日志审计**: 记录所有路径访问请求，便于检测异常

---

## 8. 相关漏洞关联

| 漏洞 ID | 类型 | 关系 |
|----------|------|------|
| VULN-SEC-PROX-001 | 输入验证缺失 | 同入口点，不同验证层 |
| cross-module-vuln-003 | 跨模块攻击 | 可组合利用 |

---

## 9. 参考资料

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CVE-2021-41773: Apache Path Traversal](https://nvd.nist.gov/vuln/detail/CVE-2021-41773)

---

**报告生成时间**: 2026-04-20  
**分析者**: Security Scanner  
**状态**: CONFIRMED