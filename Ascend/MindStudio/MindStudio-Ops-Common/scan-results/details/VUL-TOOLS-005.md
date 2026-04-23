# VUL-TOOLS-005：SaveOutputs文件路径拼接致任意文件写入

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VUL-TOOLS-005 |
| **漏洞类型** | File Path Injection（文件路径注入） |
| **CWE 编号** | CWE-73 |
| **严重等级** | High（高危） |
| **置信度** | 80% |
| **发现位置** | `csrc/tools/kernel_launcher/Launcher.cpp:213-214` |
| **函数名称** | `SaveOutputs` |
| **代码片段** | `filePath = outputDir + "/" + out.name + ".bin"` |

## 漏洞描述

`SaveOutputs()` 函数通过字符串拼接构造输出文件路径：`outputDir + "/" + out.name + ".bin"`。`out.name` 来自配置文件的 `output_name` 字段，没有任何路径验证或清洗。攻击者可以在 `out.name` 中注入路径遍历字符（如 `../`）或绝对路径前缀，导致写入任意位置的文件，实现任意文件写入或覆盖。

## 漏洞触发条件分析

### 触发条件
1. **攻击者需控制 `config.json` 的 `output_name` 字段**
2. **KernelRunner::Run() 执行完成**：触发 SaveOutputs
3. **目标写入目录需可写**：攻击者需要写入权限

### 数据流追踪

```
[数据流路径]
┌─────────────────────────────────────────────────────────────────────┐
│ Source: config.json 配置文件                                        │
│                                                                     │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ 配置文件解析                                                  │   │
│ │   → output_name 字段                                         │   │
│ │   → 存储到 params[].name                                     │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ Launcher::InitOutput(param)                                  │   │
│ │   → outputs_.emplace_back(param)                             │   │
│ │   → out.name = param.name                                    │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ Launcher::SaveOutputs(outputDir)                             │   │
│ │   → for (out : outputs_)                                     │   │
│ │   → 【无验证】                                               │   │
│ │   → filePath = outputDir + "/" + out.name + ".bin"           │   │
│ │   → WriteBinary(filePath, data)                              │   │
│ │   → [SINK] 写入任意文件                                      │   │
│ └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 关键代码片段

**Launcher.cpp:201-218 (SaveOutputs 函数)**
```cpp
bool Launcher::SaveOutputs(const std::string &outputDir)
{
    size_t outputSize = std::min({hostOutputPtrs_.size(), outputs_.size(), devOutputPtrs_.size()});
    for (size_t i = 0; i < outputSize; i++) {
        auto out = outputs_[i];
        size_t dataSize = out.dataSize;
        ACL_CHECK_MESSAGE_AND_RETURN(aclrtMemcpy(hostOutputPtrs_[i], dataSize, devOutputPtrs_[i], dataSize,
                                                 aclrtMemcpyKind::ACL_MEMCPY_DEVICE_TO_HOST), "aclrtMemcpy");
        if (!MkdirRecusively(outputDir)) {
            WARN_LOG("Failed to create directory %s", outputDir.c_str());
            return false;
        }
        // 【漏洞点】字符串拼接无验证
        std::string filePath = outputDir + "/" + out.name + ".bin";
        if (WriteBinary(filePath, static_cast<const char *>(hostOutputPtrs_[i]), dataSize) != dataSize) {
            return false;
        }
    }
    return true;
}
```

## 潜在攻击场景

### 场景 1: 路径遍历写入任意文件

**攻击配置**：
```json
{
  "output_name": "../../../tmp/malicious",
  // ...
}
```

**攻击效果**：
- 构造路径：`outputDir + "/" + "../../../tmp/malicious" + ".bin"`
- 结果：写入到 `/tmp/malicious.bin`（或其他遍历目标）
- 覆盖任意位置的文件

### 场景 2: 绝对路径写入

**攻击配置**：
```json
{
  "output_name": "/etc/cron.d/malicious",
  // ...
}
```

**攻击效果**：
- 构造路径：`outputDir + "/" + "/etc/cron.d/malicious" + ".bin"`
- 结果：可能写入 `/etc/cron.d/malicious.bin`（取决于路径处理）
- 植入 cron 任务实现持久化

### 场景 3: 文件覆盖攻击

**攻击配置**：
```json
{
  "output_name": "../critical_config",
  // ...
}
```

**攻击效果**：
- 覆盖上层目录的重要配置文件
- 破坏系统或应用程序配置

### 场景 4: 符号链接攻击

**攻击步骤**：
1. 在输出目录创建符号链接指向目标文件
2. 配置 `output_name` 为该链接名称
3. WriteBinary 通过链接写入目标文件

### 场景 5: 权限提升攻击

如果程序以较高权限运行：
```json
{
  "output_name": "../../../etc/sudoers.d/malicious",
  // ...
}
```

**攻击效果**：
- 写入 sudoers 配置
- 实现权限提升

## 影响范围评估

### 直接影响
| 影面 | 影响描述 |
|------|----------|
| **任意文件写入** | 写入任意位置的文件 |
| **文件覆盖** | 覆盖重要配置或数据文件 |
| **权限提升** | 写入特权文件（如 sudoers） |
| **持久化** | 写入 cron、startup 文件 |
| **数据破坏** | 破坏系统关键文件 |

### 特殊危险

与其他路径漏洞不同，这是一个**写入型**漏洞：
- 可以创建新文件（植入后门）
- 可以覆盖现有文件（破坏数据）
- 可能影响系统稳定性

### 受影响组件
| 文件 | 角色 |
|------|------|
| `csrc/tools/kernel_launcher/Launcher.cpp` | 漏洞点 - 字符串拼接 |
| `csrc/tools/kernel_launcher/KernelConfigParser.cpp` | 来源 - output_name 解析 |
| `csrc/utils/FileSystem.cpp` | WriteBinary 函数 |

## 修复建议

### 建议 1: 输出名称清洗（推荐）

```cpp
// 新增辅助函数：清洗文件名
std::string SanitizeOutputName(const std::string& name) {
    // 移除路径遍历字符
    std::string sanitized = name;
    
    // 移除所有 '/' 和 '\\'
    sanitized.erase(std::remove(sanitized.begin(), sanitized.end(), '/'), sanitized.end());
    sanitized.erase(std::remove(sanitized.begin(), sanitized.end(), '\\'), sanitized.end());
    
    // 移除 '..'
    size_t pos;
    while ((pos = sanitized.find("..")) != std::string::npos) {
        sanitized.erase(pos, 2);
    }
    
    // 只允许安全字符
    for (char& c : sanitized) {
        if (!std::isalnum(c) && c != '_' && c != '-' && c != '.') {
            c = '_';  // 替换为安全字符
        }
    }
    
    // 限制长度
    if (sanitized.length() > 255) {
        sanitized = sanitized.substr(0, 255);
    }
    
    return sanitized;
}

bool Launcher::SaveOutputs(const std::string &outputDir) {
    // ...
    for (size_t i = 0; i < outputSize; i++) {
        auto out = outputs_[i];
        
        // 【新增】清洗输出名称
        std::string safeName = SanitizeOutputName(out.name);
        if (safeName.empty()) {
            WARN_LOG("Empty output name after sanitization");
            safeName = "output_" + std::to_string(i);
        }
        
        // 使用清洗后的名称
        std::string filePath = JoinPath({outputDir, safeName + ".bin"});
        
        // 【新增】验证最终路径在输出目录内
        std::string realPath;
        if (!Realpath(filePath, realPath)) {
            // 文件不存在，检查路径结构
            realPath = filePath;
        }
        
        std::string realOutputDir;
        if (!Realpath(outputDir, realOutputDir)) {
            realOutputDir = outputDir;
        }
        
        if (realPath.find(realOutputDir) != 0) {
            ERROR_LOG("Output path escape detected: %s", realPath.c_str());
            return false;
        }
        
        WriteBinary(filePath, static_cast<const char *>(hostOutputPtrs_[i]), dataSize);
        // ...
    }
    return true;
}
```

### 建议 2: 配置解析时验证

在 KernelConfigParser 中添加验证：

```cpp
bool KernelConfigParser::SetOutputName(const std::string &arg) {
    // 【新增】输出名称验证
    if (!CheckInputStringValid(arg, FILE_NAME_LENGTH_LIMIT)) {
        ERROR_LOG("Output name invalid: %s", arg.c_str());
        return false;
    }
    
    // 【新增】检查路径遍历字符
    if (arg.find('/') != std::string::npos || 
        arg.find('\\') != std::string::npos ||
        arg.find("..") != std::string::npos) {
        ERROR_LOG("Output name contains path traversal: %s", arg.c_str());
        return false;
    }
    
    Param param;
    param.type = "output";
    param.name = arg;
    // ...
    kernelConfig_.params.emplace_back(param);
    return true;
}
```

### 建议 3: 使用安全的路径拼接函数

```cpp
bool Launcher::SaveOutputs(const std::string &outputDir) {
    // ...
    for (size_t i = 0; i < outputSize; i++) {
        auto out = outputs_[i];
        
        // 【修改】使用 JoinPath 替代字符串拼接
        // JoinPath 会规范化路径
        std::string baseName = out.name + ".bin";
        std::string filePath = JoinPath({outputDir, SanitizeOutputName(baseName)});
        
        // 【新增】路径边界检查
        std::string resolvedOutputDir;
        if (!Realpath(outputDir, resolvedOutputDir)) {
            resolvedOutputDir = outputDir;
        }
        
        std::string resolvedFilePath;
        Realpath(filePath, resolvedFilePath);  // 可能不存在
        
        // 检查是否仍在输出目录内
        if (!resolvedFilePath.empty() && 
            resolvedFilePath.find(resolvedOutputDir) != 0) {
            ERROR_LOG("Path traversal detected");
            return false;
        }
        
        WriteBinary(filePath, ...);
        // ...
    }
    return true;
}
```

### 建议 4: 白名单字符验证

```cpp
bool IsValidOutputName(const std::string& name) {
    // 只允许字母、数字、下划线、连字符
    for (char c : name) {
        if (!std::isalnum(c) && c != '_' && c != '-') {
            return false;
        }
    }
    return !name.empty() && name.length() <= 255;
}

bool Launcher::SaveOutputs(const std::string &outputDir) {
    // ...
    for (size_t i = 0; i < outputSize; i++) {
        auto out = outputs_[i];
        
        // 【新增】严格白名单验证
        if (!IsValidOutputName(out.name)) {
            WARN_LOG("Invalid output name, using default: %s", out.name.c_str());
            std::string safeName = "output_" + std::to_string(i);
            std::string filePath = JoinPath({outputDir, safeName + ".bin"});
        } else {
            std::string filePath = JoinPath({outputDir, out.name + ".bin"});
        }
        
        WriteBinary(filePath, ...);
        // ...
    }
    return true;
}
```

## 验证测试建议

### 安全测试用例
| 测试项 | 测试方法 | 预期结果 |
|--------|----------|----------|
| 路径遍历 | `output_name="../../../tmp/x"` | 清洗或拒绝 |
| 绝对路径 | `output_name="/etc/x"` | 清洗或拒绝 |
| 混合攻击 | `output_name="..\\..\\x"` | 清洗或拒绝 |
| 特殊字符 | `output_name="x\ny"` | 清洗或拒绝 |
| 空名称 | `output_name=""` | 使用默认名称 |
| 正常名称 | `output_name="valid_output"` | 接受 |

---

**报告生成时间**: 2026-04-21  
**分析工具**: MindStudio-Ops-Common 漏洞扫描器