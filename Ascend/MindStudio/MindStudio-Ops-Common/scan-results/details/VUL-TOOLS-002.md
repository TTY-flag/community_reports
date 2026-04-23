# VUL-TOOLS-002：KernelConfigParser.SetInputPath路径遍历致任意文件读取

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VUL-TOOLS-002 |
| **漏洞类型** | Path Traversal（路径遍历） |
| **CWE 编号** | CWE-22 |
| **严重等级** | High（高危） |
| **置信度** | 85% |
| **发现位置** | `csrc/tools/kernel_launcher/KernelConfigParser.cpp:157-181` |
| **函数名称** | `SetInputPath` |
| **代码片段** | `param.dataPath = binPath;` |

## 漏洞描述

`SetInputPath()` 函数将配置文件中的 `input_path` 字段直接赋值给 `param.dataPath`，没有调用 `CheckInputFileValid()` 进行路径验证。该路径后续用于 `ReadFile()` 读取输入数据文件，攻击者可以通过路径遍历或绝对路径读取任意文件内容，可能导致敏感信息泄露。

## 漏洞触发条件分析

### 触发条件
1. **攻击者需控制 `config.json` 的 `input_path` 字段**
2. **Launcher/KernelRunner 需调用 `InitInput()`**：触发文件读取
3. **目标文件需存在且可读**

### 数据流追踪

```
[数据流路径]
┌─────────────────────────────────────────────────────────────────────┐
│ Source: config.json 配置文件                                        │
│                                                                     │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ 配置文件解析                                                  │   │
│ │   → input_path 字段                                          │   │
│ │   → 多个路径以 ';' 分隔                                      │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ KernelConfigParser::SetInputPath(arg)                        │   │
│ │   → SplitString(path, ';', sizeVec)                          │   │
│ │   → for (binPath : sizeVec)                                  │   │
│ │   → 【无验证】                                               │   │
│ │   → param.dataPath = binPath                                 │   │
│ │   → [SINK] 路径遍历存储                                      │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ Launcher::InitInput(param)                                   │   │
│ │   → ReadFile(param.dataPath, buffer)                         │   │
│ │   → 【SINK】读取任意文件                                     │   │
│ └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 关键代码片段

**KernelConfigParser.cpp:157-181 (SetInputPath 函数)**
```cpp
bool KernelConfigParser::SetInputPath(const std::string &arg)
{
    const std::string& path = arg;
    std::vector<std::string> sizeVec;
    SplitString(path, ';', sizeVec);  // 分割多个路径
    if (sizeVec.empty()) {
        ERROR_LOG("Input path does not contain any elements");
        return false;
    }
    inputCount_ = sizeVec.size();
    for (const auto& binPath : sizeVec) {
        Param param;
        param.type = "input";
        param.dType = "int8";
        // 【漏洞点】直接赋值，无路径验证
        param.dataPath = binPath;
        if (param.dataPath == "n") {
            param.isRequired = false;
            DEBUG_LOG("Get null data");
        } else {
            param.isRequired = true;
            DEBUG_LOG("Get bin data, data path is %s", binPath.c_str());
        }
        kernelConfig_.params.emplace_back(param);
    }
    return true;
}
```

**Launcher.cpp 或 KernelRunner.cpp (InitInput 函数 - 使用路径)**
```cpp
// ReadFile 使用 param.dataPath 读取文件内容
// 无额外验证，直接读取任意路径
```

## 潜在攻击场景

### 场景 1: 读取敏感文件

**攻击配置**：
```json
{
  "input_path": "/etc/passwd;/home/admin/.ssh/id_rsa;/var/log/auth.log",
  // ...
}
```

**攻击效果**：
- 读取多个敏感文件作为 "输入数据"
- SSH 私钥、密码文件、日志文件等被泄露
- 文件内容可能被输出到结果中

### 场景 2: 路径遍历攻击

**攻击配置**：
```json
{
  "input_path": "../../../etc/shadow;../../../root/.bash_history",
  // ...
}
```

**攻击效果**：
- 遍历目录读取上层目录的敏感文件
- 用户历史命令可能包含敏感信息

### 场景 3: 符号链接攻击

**攻击步骤**：
1. 创建符号链接：`ln -s /etc/shadow input.bin`
2. 配置 `input_path` 包含该链接
3. ReadFile 读取目标敏感文件

### 场景 4: 多文件批量窃取

**攻击配置**：
```json
{
  "input_path": "/proc/self/environ;/proc/self/cmdline;/proc/self/maps",
  // ...
}
```

**攻击效果**：
- 读取进程环境变量、命令行、内存映射
- 获取进程敏感信息

## 影响范围评估

### 直接影响
| 影面 | 影响描述 |
|------|----------|
| **任意文件读取** | 可读取系统任意位置的文件 |
| **批量信息窃取** | 支持多路径读取，可批量窃取 |
| **进程信息泄露** | `/proc` 目录下的敏感信息 |
| **密钥泄露** | SSH 密钥、证书等 |

### 与 SetBinPath 的相似性

两个漏洞具有相同的根本原因：
| 漏洞 | 函数 | 缺失验证 |
|------|------|----------|
| VUL-TOOLS-001 | `SetBinPath` | 无路径验证 |
| VUL-TOOLS-002 | `SetInputPath` | 无路径验证 |

都需要添加相同的验证逻辑。

### 受影响组件
| 文件 | 角色 |
|------|------|
| `csrc/tools/kernel_launcher/KernelConfigParser.cpp` | 漏洞点 - 无验证赋值 |
| `csrc/tools/kernel_launcher/Launcher.cpp` | SINK - InitInput → ReadFile |
| `csrc/tools/kernel_launcher/KernelRunner.cpp` | SINK - InitInput → ReadFile |
| `csrc/utils/FileSystem.cpp` | ReadFile 函数 |

## 修复建议

### 建议 1: 添加 CheckInputFileValid 验证（推荐）

```cpp
bool KernelConfigParser::SetInputPath(const std::string &arg)
{
    const std::string& path = arg;
    std::vector<std::string> sizeVec;
    SplitString(path, ';', sizeVec);
    if (sizeVec.empty()) {
        ERROR_LOG("Input path does not contain any elements");
        return false;
    }
    inputCount_ = sizeVec.size();
    for (const auto& binPath : sizeVec) {
        Param param;
        param.type = "input";
        param.dType = "int8";
        
        // 【新增】路径验证
        if (binPath != "n") {  // "n" 表示空输入，跳过验证
            if (!CheckInputFileValid(binPath)) {
                ERROR_LOG("Input path is invalid or contains traversal: %s", binPath.c_str());
                return false;
            }
            
            // 【新增】转换为真实路径
            std::string realPath;
            if (!Realpath(binPath, realPath)) {
                ERROR_LOG("Cannot resolve input path: %s", binPath.c_str());
                return false;
            }
            param.dataPath = realPath;
        } else {
            param.dataPath = binPath;  // 保持 "n" 标记
            param.isRequired = false;
        }
        
        param.isRequired = (param.dataPath != "n");
        kernelConfig_.params.emplace_back(param);
    }
    return true;
}
```

### 建议 2: 白名单目录检查

```cpp
bool KernelConfigParser::SetInputPath(const std::string &arg)
{
    // ... 分割路径 ...
    
    // 【新增】白名单目录
    std::vector<std::string> allowedDirs = {
        "/home/user/test_data",
        "/data/kernel_inputs",
        // 可配置可信目录
    };
    
    for (const auto& binPath : sizeVec) {
        if (binPath == "n") {
            // 处理空输入
            // ...
            continue;
        }
        
        std::string realPath;
        if (!Realpath(binPath, realPath)) {
            ERROR_LOG("Cannot resolve: %s", binPath.c_str());
            return false;
        }
        
        // 【新增】检查是否在白名单目录
        bool allowed = false;
        for (const auto& dir : allowedDirs) {
            std::string realDir;
            if (Realpath(dir, realDir) && realPath.find(realDir) == 0) {
                allowed = true;
                break;
            }
        }
        
        if (!allowed) {
            ERROR_LOG("Input path outside allowed directory: %s", realPath.c_str());
            return false;
        }
        
        param.dataPath = realPath;
        // ...
    }
    return true;
}
```

### 建议 3: 文件大小限制

防止读取过大的文件导致资源耗尽：

```cpp
for (const auto& binPath : sizeVec) {
    // ... 验证路径 ...
    
    // 【新增】检查文件大小
    size_t fileSize = GetFileSize(realPath);
    if (fileSize > MAX_INPUT_FILE_SIZE) {
        ERROR_LOG("Input file too large: %zu bytes (max %zu)", 
                  fileSize, MAX_INPUT_FILE_SIZE);
        return false;
    }
    
    // ...
}
```

### 建议 4: 统一验证函数

创建统一的路径验证函数，减少代码重复：

```cpp
// 新增辅助函数
bool KernelConfigParser::ValidateAndResolvePath(const std::string& path, 
                                                  std::string& resolvedPath) {
    if (path.empty()) {
        return false;
    }
    
    // 使用 CheckInputFileValid 验证
    if (!CheckInputFileValid(path)) {
        return false;
    }
    
    // 解析真实路径
    if (!Realpath(path, resolvedPath)) {
        return false;
    }
    
    return true;
}

bool KernelConfigParser::SetInputPath(const std::string &arg) {
    // ...
    for (const auto& binPath : sizeVec) {
        std::string resolvedPath;
        if (binPath != "n" && !ValidateAndResolvePath(binPath, resolvedPath)) {
            ERROR_LOG("Invalid input path: %s", binPath.c_str());
            return false;
        }
        param.dataPath = (binPath == "n") ? binPath : resolvedPath;
        // ...
    }
    return true;
}

bool KernelConfigParser::SetBinPath(const std::string &arg) {
    std::string resolvedPath;
    if (!ValidateAndResolvePath(arg, resolvedPath)) {
        ERROR_LOG("Invalid binary path: %s", arg.c_str());
        return false;
    }
    kernelConfig_.kernelBinaryPath = resolvedPath;
    return true;
}
```

## 验证测试建议

### 安全测试用例
| 测试项 | 测试方法 | 预期结果 |
|--------|----------|----------|
| 单路径遍历 | `input_path="../../../etc/passwd"` | 拒绝 |
| 多路径遍历 | `input_path="../../../etc/passwd;/etc/shadow"` | 拒绝 |
| 绝对路径注入 | `input_path="/root/.ssh/id_rsa"` | 拒绝 |
| 混合攻击 | `input_path="valid.bin;../../../etc/passwd"` | 拒绝全部 |
| 空输入标记 | `input_path="n"` | 接受 |
| 正常多路径 | `input_path="a.bin;b.bin;c.bin"` | 接受 |

---

**报告生成时间**: 2026-04-21  
**分析工具**: MindStudio-Ops-Common 漏洞扫描器