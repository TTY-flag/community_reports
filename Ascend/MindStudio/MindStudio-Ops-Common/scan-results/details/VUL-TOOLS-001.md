# VUL-TOOLS-001：KernelConfigParser.SetBinPath路径遍历致任意二进制加载

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VUL-TOOLS-001 |
| **漏洞类型** | Path Traversal（路径遍历） |
| **CWE 编号** | CWE-22 |
| **严重等级** | High（高危） |
| **置信度** | 85% |
| **发现位置** | `csrc/tools/kernel_launcher/KernelConfigParser.cpp:109-113` |
| **函数名称** | `SetBinPath` |
| **代码片段** | `kernelConfig_.kernelBinaryPath = arg;` |

## 漏洞描述

`SetBinPath()` 函数直接将用户配置的 `bin_path` 字段赋值给 `kernelConfig_.kernelBinaryPath`，没有任何路径验证。该路径后续被用于加载 kernel 二进制文件，攻击者可以通过路径遍历字符（如 `../`）或绝对路径读取任意位置的文件，可能加载恶意 kernel 或读取敏感文件内容。

## 漏洞触发条件分析

### 触发条件
1. **攻击者需控制 `config.json` 的 `bin_path` 字段**：配置文件可能来自用户输入或外部来源
2. **Launcher/KernelRunner 需调用 `RegisterKernel()`**：触发读取二进制文件
3. **目标文件需存在且可读**：攻击者指定的路径需要可访问

### 数据流追踪

```
[数据流路径]
┌─────────────────────────────────────────────────────────────────────┐
│ Source: config.json 配置文件                                        │
│                                                                     │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ 配置文件解析                                                  │   │
│ │   → bin_path 字段                                            │   │
│ │   → 来自外部配置文件                                         │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ KernelConfigParser::Parse()                                  │   │
│ │   → 解析 JSON 配置                                           │   │
│ │   → 调用 SetBinPath(bin_path_value)                          │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ KernelConfigParser::SetBinPath(arg)                          │   │
│ │   → 【无验证】                                               │   │
│ │   → kernelConfig_.kernelBinaryPath = arg                     │   │
│ │   → [SINK] 路径遍历存储                                      │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ KernelRunner::Run()                                          │   │
│ │   → ReadBinary(kernelConfig.kernelBinaryPath, bin)           │   │
│ │   → 【SINK】读取任意文件                                     │   │
│ └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 关键代码片段

**KernelConfigParser.cpp:109-113 (SetBinPath 函数)**
```cpp
bool KernelConfigParser::SetBinPath(const std::string &arg)
{
    // 【漏洞点】直接赋值，无任何验证
    kernelConfig_.kernelBinaryPath = arg;
    return true;
}
```

对比其他字段的验证：

**KernelConfigParser.cpp:98-107 (SetKernelName 函数 - 有验证)**
```cpp
bool KernelConfigParser::SetKernelName(const std::string &arg)
{
    // 【有验证】检查字符串有效性
    if (!CheckInputStringValid(arg, FILE_NAME_LENGTH_LIMIT)) {
        ERROR_LOG("kernel_name: %s is invalid.", arg.c_str());
        return false;
    }
    kernelConfig_.kernelName = arg;
    return true;
}
```

**KernelRunner.cpp:44-50 (使用路径读取文件)**
```cpp
bool KernelRunner::Run(const KernelConfig& kernelConfig)
{
    // ...
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

## 潜在攻击场景

### 场景 1: 路径遍历读取敏感文件

**攻击配置**：
```json
{
  "bin_path": "../../../etc/passwd",
  "kernel_name": "test",
  // ...
}
```

**攻击效果**：
- 读取 `/etc/passwd` 文件内容作为 "kernel"
- 可能导致敏感信息泄露
- kernel 文件格式验证可能阻止执行，但文件内容已被读取

### 场景 2: 加载恶意 Kernel

**攻击配置**：
```json
{
  "bin_path": "/tmp/malicious_kernel.bin",
  "kernel_name": "test",
  // ...
}
```

**攻击效果**：
- 加载攻击者准备的恶意 kernel 二进制
- 可能导致 NPU 执行恶意代码
- 影响设备安全

### 场景 3: 符号链接攻击

**攻击步骤**：
1. 创建符号链接：`ln -s /etc/shadow kernel.bin`
2. 配置 `bin_path` 为该符号链接
3. KernelRunner 读取目标文件内容

### 场景 4: 绝对路径注入

**攻击配置**：
```json
{
  "bin_path": "/home/admin/.ssh/id_rsa",
  // ...
}
```

**攻击效果**：
- 读取用户 SSH 私钥
- 导致密钥泄露

## 影响范围评估

### 直接影响
| 影面 | 影响描述 |
|------|----------|
| **任意文件读取** | 可读取系统任意位置的文件内容 |
| **敏感信息泄露** | SSH 密钥、密码文件、配置文件等 |
| **恶意 Kernel 加载** | 可能加载恶意二进制影响 NPU |
| **数据完整性** | 可能影响 kernel 执行结果 |

### 对比分析

与 `SetKernelName()` 的对比：
| 函数 | 是否验证 | 验证方式 |
|------|----------|----------|
| `SetKernelName` | ✓ 是 | `CheckInputStringValid()` |
| `SetBinPath` | ✗ 否 | 直接赋值 |
| `SetMagic` | ✓ 是 | 白名单检查 |
| `SetInputPath` | ✗ 否 | 直接赋值 |

`SetBinPath` 和 `SetInputPath` 缺少必要的验证，是明显的安全缺陷。

### 受影响组件
| 文件 | 角色 |
|------|------|
| `csrc/tools/kernel_launcher/KernelConfigParser.cpp` | 漏洞点 - 无验证赋值 |
| `csrc/tools/kernel_launcher/KernelRunner.cpp` | SINK - ReadBinary 调用 |
| `csrc/tools/kernel_launcher/Launcher.cpp` | SINK - RegisterKernel 调用 |
| `csrc/utils/FileSystem.cpp` | ReadBinary 函数 |

## 修复建议

### 建议 1: 使用 CheckInputFileValid 验证（推荐）

项目中已有 `CheckInputFileValid` 函数，可直接使用：

```cpp
bool KernelConfigParser::SetBinPath(const std::string &arg)
{
    // 【新增】使用已有的路径验证函数
    if (!CheckInputFileValid(arg)) {
        ERROR_LOG("Binary path is invalid or contains traversal: %s", arg.c_str());
        return false;
    }
    
    // 【新增】转换为真实路径
    std::string realPath;
    if (!Realpath(arg, realPath)) {
        ERROR_LOG("Cannot resolve binary path: %s", arg.c_str());
        return false;
    }
    
    kernelConfig_.kernelBinaryPath = realPath;
    return true;
}
```

### 建议 2: 白名单目录检查

```cpp
bool KernelConfigParser::SetBinPath(const std::string &arg)
{
    // 基本验证
    if (!CheckInputStringValid(arg, PATH_LENGTH_LIMIT)) {
        ERROR_LOG("Binary path string invalid");
        return false;
    }
    
    // 解析真实路径
    std::string realPath;
    if (!Realpath(arg, realPath)) {
        ERROR_LOG("Cannot resolve path: %s", arg.c_str());
        return false;
    }
    
    // 【新增】白名单目录检查
    std::vector<std::string> allowedDirs = {
        "/usr/local/ascend kernels",
        "/home/user/kernels",
        // 可配置其他可信目录
    };
    
    bool inAllowedDir = false;
    for (const auto& dir : allowedDirs) {
        std::string allowedReal;
        if (Realpath(dir, allowedReal) && realPath.find(allowedReal) == 0) {
            inAllowedDir = true;
            break;
        }
    }
    
    if (!inAllowedDir) {
        ERROR_LOG("Binary path outside allowed directories: %s", realPath.c_str());
        return false;
    }
    
    kernelConfig_.kernelBinaryPath = realPath;
    return true;
}
```

### 建议 3: 文件类型验证

```cpp
bool KernelConfigParser::SetBinPath(const std::string &arg)
{
    // ... 路径验证 ...
    
    // 【新增】验证文件是否为有效的 kernel 二进制
    // 检查文件大小、魔数等
    size_t fileSize = GetFileSize(realPath);
    if (fileSize == 0 || fileSize > MAX_KERNEL_SIZE) {
        ERROR_LOG("Invalid kernel binary size: %zu", fileSize);
        return false;
    }
    
    // 检查文件魔数（根据 kernel 二进制格式）
    // ...
    
    kernelConfig_.kernelBinaryPath = realPath;
    return true;
}
```

### 建议 4: 配置文件来源验证

如果 config.json 来自外部，验证其来源：

```cpp
// 在解析配置前
bool ValidateConfigSource(const std::string& configPath) {
    std::string realPath;
    if (!Realpath(configPath, realPath)) {
        return false;
    }
    
    // 检查配置文件是否在可信目录
    // ...
}
```

## 验证测试建议

### 安全测试用例
| 测试项 | 测试方法 | 预期结果 |
|--------|----------|----------|
| 路径遍历 | `bin_path="../../../etc/passwd"` | 拒绝路径 |
| 绝对路径 | `bin_path="/etc/shadow"` | 拒绝路径 |
| 符号链接 | 创建指向敏感文件的链接 | 解析真实路径并拒绝 |
| 空路径 | `bin_path=""` | 拒绝 |
| 超长路径 | `bin_path="aaaa..."` (超长) | 拒绝 |
| 正常路径 | `bin_path="/valid/path/kernel.bin"` | 接受 |

---

**报告生成时间**: 2026-04-21  
**分析工具**: MindStudio-Ops-Common 漏洞扫描器