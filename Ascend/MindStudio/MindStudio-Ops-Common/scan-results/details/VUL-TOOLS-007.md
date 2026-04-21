# VUL-TOOLS-007: 任意文件读取漏洞

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VUL-TOOLS-007 |
| **漏洞类型** | Arbitrary File Read（任意文件读取） |
| **CWE 编号** | CWE-22 |
| **严重等级** | High（高危） |
| **置信度** | 85% |
| **发现位置** | `csrc/tools/kernel_launcher/KernelRunner.cpp:44-50` |
| **函数名称** | `Run` |
| **代码片段** | `ReadBinary(kernelConfig.kernelBinaryPath, bin)` |

## 漏洞描述

`KernelRunner::Run()` 函数将 `kernelConfig.kernelBinaryPath` 直接传递给 `ReadBinary()` 函数读取文件内容。`kernelBinaryPath` 来源于配置文件的 `bin_path` 字段（通过 `SetBinPath` 设置），没有路径验证。攻击者可以指定任意文件路径，导致读取敏感文件内容。此漏洞与 VUL-TOOLS-001 同源，是路径验证缺失导致的下游影响。

## 漏洞触发条件分析

### 触发条件
1. **攻击者需控制 `config.json` 的 `bin_path` 字段**
2. **KernelRunner::Run() 被调用**
3. **目标文件需存在且可读**

### 数据流追踪

```
[数据流路径]
┌─────────────────────────────────────────────────────────────────────┐
│ Source: config.json 配置文件                                        │
│                                                                     │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ KernelConfigParser::SetBinPath(arg)                          │   │
│ │   → 【无验证】                                               │   │
│ │   → kernelConfig_.kernelBinaryPath = arg                     │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ KernelRunner::Run(kernelConfig)                              │   │
│ │   → fileSize = GetFileSize(kernelConfig.kernelBinaryPath)    │   │
│ │   → 【无验证】                                               │   │
│ │   → ReadBinary(kernelConfig.kernelBinaryPath, bin)           │   │
│ │   → [SINK] 读取任意文件                                      │   │
│ └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 关键代码片段

**KernelRunner.cpp:30-67 (Run 函数)**
```cpp
bool KernelRunner::Run(const KernelConfig& kernelConfig)
{
    // set device
    if (!rtAPI_.CheckRtResult(rtAPI_.RtSetDevice(kernelConfig.deviceID), "rtSetDevice")) {
        return false;
    }
    needResetDevice_ = true;
    deviceID_ = kernelConfig.deviceID;

    // create stream
    CHECK_RT_RESULT(rtAPI_.CheckRtResult(rtAPI_.RtStreamCreate(&rtStream_, 0), "rtStreamCreate"))
    needDestroyStream_ = true;

    // register kernel
    // 【漏洞点】直接使用未验证的路径
    size_t fileSize = GetFileSize(kernelConfig.kernelBinaryPath);
    std::vector<char> bin;
    if (ReadBinary(kernelConfig.kernelBinaryPath, bin) == 0) {
        ERROR_LOG("read op kernel file failed.");
        return false;
    }
    if (!RegisterKernel(kernelConfig, bin, fileSize)) {
        return false;
    }

    // ...
}
```

**FileSystem.cpp:114 (ReadBinary 函数)**
```cpp
size_t ReadBinary(const std::string &filename, std::vector<char> &buffer) {
    // 使用 open/read 读取文件内容
    // 无路径验证，直接读取任意路径
}
```

## 潜在攻击场景

### 场景 1: 读取敏感系统文件

**攻击配置**：
```json
{
  "bin_path": "/etc/shadow",
  // ...
}
```

**攻击效果**：
- 读取系统密码文件
- 可能通过错误日志或输出泄露内容
- kernel 格式验证可能失败，但文件内容已被读取到内存

### 场景 2: 读取用户敏感文件

**攻击配置**：
```json
{
  "bin_path": "/home/admin/.ssh/id_rsa",
  // ...
}
```

**攻击效果**：
- 读取 SSH 私钥
- 密钥泄露导致服务器被入侵

### 场景 3: 路径遍历攻击

**攻击配置**：
```json
{
  "bin_path": "../../../root/.bash_history",
  // ...
}
```

**攻击效果**：
- 读取用户历史命令
- 可能包含敏感密码或路径

### 场景 4: /proc 文件系统攻击

**攻击配置**：
```json
{
  "bin_path": "/proc/self/environ",
  // ...
}
```

**攻击效果**：
- 读取进程环境变量
- 获取敏感配置、密码等

### 场景 5: 与 VUL-TOOLS-001 的联动

由于 VUL-TOOLS-001（SetBinPath）和 VUL-TOOLS-007（ReadBinary）是同一漏洞链的上下游：
- VUL-TOOLS-001: 路径未验证存储
- VUL-TOOLS-007: 使用未验证路径读取

修复任一漏洞不能完全解决问题，需要同时修复两处。

## 影响范围评估

### 直接影响
| 影面 | 影响描述 |
|------|----------|
| **任意文件读取** | 可读取系统任意位置的文件 |
| **敏感信息泄露** | 密码、密钥、配置等 |
| **内存访问** | 文件内容被加载到进程内存 |

### 与 VUL-TOOLS-001 的关系

| 漏洞 | 类型 | 位置 | 关系 |
|------|------|------|------|
| VUL-TOOLS-001 | Path Traversal（存储） | KernelConfigParser.cpp:109 | 上游漏洞 |
| VUL-TOOLS-007 | Arbitrary File Read（读取） | KernelRunner.cpp:44 | 下游影响 |

两者形成完整的漏洞链：
```
[配置输入] → SetBinPath（无验证存储） → kernelBinaryPath → Run → ReadBinary（无验证读取）
```

### 受影响组件
| 文件 | 角色 |
|------|------|
| `csrc/tools/kernel_launcher/KernelRunner.cpp` | 漏洞点 - ReadBinary 调用 |
| `csrc/tools/kernel_launcher/KernelConfigParser.cpp` | 来源 - SetBinPath |
| `csrc/utils/FileSystem.cpp` | ReadBinary 函数实现 |

## 修复建议

### 建议 1: 在使用前验证路径（推荐）

```cpp
bool KernelRunner::Run(const KernelConfig& kernelConfig)
{
    // set device
    if (!rtAPI_.CheckRtResult(rtAPI_.RtSetDevice(kernelConfig.deviceID), "rtSetDevice")) {
        return false;
    }
    needResetDevice_ = true;
    deviceID_ = kernelConfig.deviceID;

    // 【新增】在使用前验证路径
    std::string safePath = kernelConfig.kernelBinaryPath;
    
    // 验证路径有效性
    if (!CheckInputFileValid(safePath)) {
        ERROR_LOG("Kernel binary path validation failed: %s", safePath.c_str());
        return false;
    }
    
    // 解析真实路径
    std::string realPath;
    if (!Realpath(safePath, realPath)) {
        ERROR_LOG("Cannot resolve kernel binary path: %s", safePath.c_str());
        return false;
    }
    
    // 【新增】白名单目录检查
    std::string ascendHomePath;
    if (GetAscendHomePath(ascendHomePath)) {
        std::string allowedDir = JoinPath({ascendHomePath, "kernel"});
        if (realPath.find(allowedDir) != 0) {
            ERROR_LOG("Kernel binary outside allowed directory: %s", realPath.c_str());
            return false;
        }
    }

    // create stream
    CHECK_RT_RESULT(rtAPI_.CheckRtResult(rtAPI_.RtStreamCreate(&rtStream_, 0), "rtStreamCreate"))
    needDestroyStream_ = true;

    // register kernel - 使用验证后的路径
    size_t fileSize = GetFileSize(realPath);
    std::vector<char> bin;
    if (ReadBinary(realPath, bin) == 0) {
        ERROR_LOG("read op kernel file failed.");
        return false;
    }
    if (!RegisterKernel(kernelConfig, bin, fileSize)) {
        return false;
    }

    // ...
}
```

### 建议 2: 同时修复上游漏洞

必须同时修复 VUL-TOOLS-001（SetBinPath），在配置解析阶段进行验证：

```cpp
// KernelConfigParser.cpp
bool KernelConfigParser::SetBinPath(const std::string &arg)
{
    // 【新增】路径验证
    if (!CheckInputFileValid(arg)) {
        ERROR_LOG("Binary path is invalid: %s", arg.c_str());
        return false;
    }
    
    std::string realPath;
    if (!Realpath(arg, realPath)) {
        ERROR_LOG("Cannot resolve path: %s", arg.c_str());
        return false;
    }
    
    kernelConfig_.kernelBinaryPath = realPath;
    return true;
}
```

### 建议 3: KernelConfig 增加验证字段

在 KernelConfig 结构中增加验证标志：

```cpp
struct KernelConfig {
    std::string kernelBinaryPath;
    bool kernelBinaryPathValidated = false;  // 【新增】验证标志
    // ...
};

// 在 KernelConfigParser 中设置标志
bool KernelConfigParser::SetBinPath(const std::string &arg) {
    if (!ValidateAndResolvePath(arg, kernelConfig_.kernelBinaryPath)) {
        return false;
    }
    kernelConfig_.kernelBinaryPathValidated = true;
    return true;
}

// 在 KernelRunner::Run 中检查标志
bool KernelRunner::Run(const KernelConfig& kernelConfig) {
    if (!kernelConfig.kernelBinaryPathValidated) {
        ERROR_LOG("Kernel binary path was not validated");
        return false;
    }
    // ...
}
```

### 建议 4: 文件类型/内容验证

```cpp
bool KernelRunner::Run(const KernelConfig& kernelConfig) {
    // ...
    
    // 【新增】验证文件是否为有效的 kernel 二进制
    size_t fileSize = GetFileSize(realPath);
    
    // 检查文件大小范围
    if (fileSize < MIN_KERNEL_SIZE || fileSize > MAX_KERNEL_SIZE) {
        ERROR_LOG("Invalid kernel file size: %zu", fileSize);
        return false;
    }
    
    std::vector<char> bin;
    ReadBinary(realPath, bin);
    
    // 【新增】验证 kernel 魔数或格式
    if (!ValidateKernelBinary(bin)) {
        ERROR_LOG("Invalid kernel binary format");
        return false;
    }
    
    // ...
}
```

## 验证测试建议

### 安全测试用例
| 测试项 | 测试方法 | 预期结果 |
|--------|----------|----------|
| 敏感文件读取 | `bin_path="/etc/shadow"` | 拒绝 |
| 路径遍历 | `bin_path="../../../etc/passwd"` | 拒绝 |
| 绝对路径 | `bin_path="/root/.ssh/id_rsa"` | 拒绝 |
| /proc 文件 | `bin_path="/proc/self/environ"` | 拒绝 |
| 正常 kernel | `bin_path="/valid/kernel.bin"` | 接受 |
| 空路径 | `bin_path=""` | 拒绝 |

### 与 VUL-TOOLS-001 联动测试

修复后需验证：
1. 只修复 VUL-TOOLS-001 时，VUL-TOOLS-007 是否仍可被绕过
2. 只修复 VUL-TOOLS-007 时，VUL-TOOLS-001 的验证是否有效
3. 同时修复后，完整路径是否安全

---

**报告生成时间**: 2026-04-21  
**分析工具**: MindStudio-Ops-Common 漏洞扫描器