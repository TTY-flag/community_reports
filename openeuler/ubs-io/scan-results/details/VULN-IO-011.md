# VULN-IO-011: HookOpen等文件打开函数路径验证缺失致路径遍历攻击

## 漏洞概述

| 属性 | 值 |
|------|-----|
| 漏洞ID | VULN-IO-011 |
| 类型 | Path Traversal (路径遍历) |
| CWE | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| 严重性 | HIGH |
| 置信度 | 85% |
| 状态 | 已确认 (真实漏洞，需理解设计上下文) |

## 受影响代码

### 文件位置
- **主文件**: `ubsio-boostio/src/io_interceptor/src/posix_interceptor.cpp`
- **行号**: 81-139
- **函数**: `HookOpen`, `HookOpen64`, `HookOpenAt`, `HookOpenAt64`
- **相关文件**: `posix_interface.cpp` (入口点), `proxy_operations.cpp` (PROXY模式处理)

### 漏洞代码片段

```cpp
// 不安全的路径验证函数 (lines 68-79)
static inline bool CheckPath(const char *path)
{
    if (path == nullptr) {
        errno = EFAULT;
        return false;
    }
    if (path[0] == '\0') {
        errno = ENOENT;
        return false;
    }
    return true;  // 仅检查非空和非空字符串，无路径遍历验证！
}

// HookOpen - 文件打开钩子 (lines 81-94)
int HookOpen(const char *path, int flags, va_list args)
{
    if (!CheckPath(path) || !InitNativeHook() || CHECKNATIVEFUNC(open)) {
        return -1;
    }
    int ret;
    if (CHECKPROXYLOADED || CHECKPROXYFUNC(open)) {
        mode_t mode = va_arg(args, mode_t);
        ret = NATIVE(open)(path, flags, mode);  // 路径直接传递给原生 open！
        return ret;
    }
    ret = PROXY(open)(path, flags, args);  // 或传递给代理 open！
    return ret;
}

// HookOpen64 - 64位文件打开钩子 (lines 96-109)
int HookOpen64(const char *path, int flags, va_list args)
{
    if (!CheckPath(path) || !InitNativeHook() || CHECKNATIVEFUNC(open64)) {
        return -1;
    }
    int ret;
    if (CHECKPROXYLOADED || CHECKPROXYFUNC(open64)) {
        mode_t mode = va_arg(args, mode_t);
        ret = NATIVE(open64)(path, flags, mode);  // 路径直接传递！
        return ret;
    }
    ret = PROXY(open64)(path, flags, args);
    return ret;
}

// HookOpenAt - 相对路径文件打开钩子 (lines 111-124)
int HookOpenAt(int dirfd, const char *path, int flags, va_list args)
{
    if (!CheckPath(path) || !InitNativeHook() || CHECKNATIVEFUNC(openat)) {
        return -1;
    }
    int ret;
    if (CHECKPROXYLOADED || CHECKPROXYFUNC(openat)) {
        mode_t mode = va_arg(args, mode_t);
        ret = NATIVE(openat)(dirfd, path, flags, mode);  // 路径直接传递！
        return ret;
    }
    ret = PROXY(openat)(dirfd, path, flags, args);
    return ret;
}

// HookOpenAt64 - 64位相对路径文件打开钩子 (lines 126-139)
int HookOpenAt64(int dirfd, const char *path, int flags, va_list args)
{
    if (!CheckPath(path) || !InitNativeHook() || CHECKNATIVEFUNC(openat64)) {
        return -1;
    }
    int ret;
    if (CHECKPROXYLOADED || CHECKPROXYFUNC(openat64)) {
        mode_t mode = va_arg(args, mode_t);
        ret = NATIVE(openat64)(dirfd, path, flags, mode);  // 路径直接传递！
        return ret;
    }
    ret = PROXY(openat64)(dirfd, path, flags, args);
    return ret;
}
```

### 入口点

```cpp
// posix_interface.cpp:26-34
extern "C" {
INTERCEPTOR_API int open(const char* path, int flags, ...)
{
    INTERCEPTORLOG_DEBUG("Hooking open %s  %d succeeded.", path, flags);
    va_list args;
    va_start(args, flags);
    auto ret = HookOpen(path, flags, args);
    va_end(args);
    return ret;
}

// posix_interface.cpp:46-54
INTERCEPTOR_API int openat(int dirfd, const char *path, int flags, ...)
{
    INTERCEPTORLOG_DEBUG("Hooking openat %d %s succeeded.", dirfd, path);
    va_list args;
    va_start(args, flags);
    auto ret = HookOpenAt(dirfd, path, flags, args);
    va_end(args);
    return ret;
}
}
```

### NATIVE 和 PROXY 宏定义

```cpp
// native_operations_loader.h:21
#define NATIVE(func) ock::interceptor::NativeOperationsLoader::GetProxy().func

// proxy_operations_loader.h:23
#define PROXY(func) ock::interceptor::ProxyOperationsLoader::GetProxy()->func
```

## 漏洞分析

### 1. 触发条件

**必要条件:**
1. 目标应用程序通过 `LD_PRELOAD` 加载了 `libock_interceptor.so`
2. 应用程序调用 `open()`, `open64()`, `openat()`, 或 `openat64()` 系统调用
3. 应用程序允许用户输入或外部数据控制文件路径参数

**充分条件:**
- 应用程序未对用户提供的路径进行充分验证
- 或应用程序错误地依赖 UBS-IO 进行路径验证（安全假设错误）

### 2. 数据流分析

```
[用户输入/应用程序]
        │
        ▼
    用户可控路径 (如: "../../../etc/passwd")
        │
        ▼
[LD_PRELOAD 拦截层]
    posix_interface.cpp
        │ open(path, flags) / openat(dirfd, path, flags)
        ▼
[Hook 函数层]
    posix_interceptor.cpp
        │ HookOpen() / HookOpenAt()
        ▼
[验证层 - 有缺陷]
    CheckPath(path)
        │ 仅检查: path != NULL && path[0] != '\0'
        │ 缺失检查: "../" 路径遍历
        │          绝对路径限制
        │          符号链接解析
        │          路径长度限制
        ▼
[执行层]
    NATIVE(open)(path, flags, mode) → 直接系统调用
    或
    PROXY(open)(path, flags, args) → 代理操作
        │
        ▼
[PROXY 模式内部]
    proxy_operations.cpp: OpenProxy -> Open
        │ CONTEXT.GetOperations()->open(path, flags)
        │ FullPath() 仅处理相对路径转绝对路径，无验证
        ▼
[文件系统]
    打开指定文件 (可能为任意文件！)
```

### 3. PROXY 模式分析

```cpp
// proxy_operations.cpp:125-149
int ProxyOperations::OpenProxy(const char *path, int flags, va_list args)
{
    mode_t mode = 0;
    if ((static_cast<uint32_t>(flags) & O_CREAT) || (static_cast<uint32_t>(flags) & O_TMPFILE)) {
        mode = va_arg(args, mode_t);
        return OpenMode(path, flags, mode);
    }
    return Open(path, flags);
}

int ProxyOperations::Open(const char *path, int flags)
{
    int realFd = CONTEXT.GetOperations()->open(path, flags);  // 直接调用原生 open！
    if (UNLIKELY(realFd < 0)) {
        return -1;
    }
    auto ret = OpenInner(path, realFd);  // OpenInner 在打开后才检查 mountPoint
    // ...
}

// FullPath 函数 - 仅处理相对路径，无安全验证
int32_t ProxyOperations::FullPath(const char *nativePath, std::string &realPath)
{
    std::string filePath;
    if (nativePath[0] != '/') {
        filePath = AddPrefix(GetCWD(), nativePath);  // 相对路径转绝对路径
    } else {
        filePath = nativePath;  // 绝对路径直接使用！
    }
    realPath = filePath;
    return BIO_OK;
}

// CheckSelfPath 在 OpenInner 中调用，用于追踪管理，不是安全边界
// interceptor_context.h: mountPoint = "/bfs"
int ProxyOperations::CheckSelfPath(const std::string &mountPoint, const std::string &restoredPath)
{
    size_t pointLen = mountPoint.size();
    return restoredPath.compare(0, pointLen, mountPoint, 0, pointLen);
}
```

**关键发现:**
- `FullPath()` 不验证路径遍历，只是拼接路径
- `CheckSelfPath()` 在文件打开**之后**调用，用于判断是否需要追踪该文件
- mountPoint `/bfs` 不是安全边界，只是缓存管理的标识

### 4. 攻击场景

#### 场景 A: 本地敏感文件读取
```
攻击者输入: "../../../../etc/passwd"
预期行为: 打开应用程序工作目录下的数据文件
实际行为: 打开 /etc/passwd (如果权限允许)
```

#### 场景 B: 绝对路径攻击
```
攻击者输入: "/etc/shadow"
预期行为: 打开应用程序数据目录下的文件
实际行为: 尝试打开系统敏感文件
```

#### 场景 C: 符号链接攻击
```
1. 攻击者创建符号链接: ln -s /etc/passwd /tmp/app_data/malicious_link
2. 攻击者触发读取: open("/tmp/app_data/malicious_link", O_RDONLY)
3. 实际读取: /etc/passwd 内容
```

#### 场景 D: AI/ML 场景特有攻击
```
[AI 推理服务]
        │ 加载模型权重文件
        │ 用户可控路径参数
        ▼
[UBS-IO 拦截层]
        │ HookOpen(path, flags)
        ▼
[读取系统敏感文件]
        - 读取 /etc/shadow 获取凭证
        - 读取 ~/.ssh/id_rsa 获取 SSH 私钥
        - 读取应用程序配置文件获取 API 密钥
```

#### 场景 E: PROXY 模式远程风险
```
[客户端应用程序]
        │ open("../../../../remote_secret", O_RDONLY)
        ▼
[UBS-IO 客户端拦截层]
        │ PROXY(open)(path, flags, args)
        ▼
[远程 UBS-IO 服务器]
        │ 接收文件打开请求
        │ (假设服务器端有路径验证?)
        ▼
[远程文件系统]
        打开远程服务器上的敏感文件
```

### 5. PoC 构造思路

**步骤 1: 环境准备**
```bash
# 编译 UBS-IO
cd ubsio-boostio
bash build.sh -t release

# 准备测试环境
mkdir -p /tmp/test_ubs/{safe_dir,outside_dir}
echo "SECRET_DATA: admin_password=secret123" > /tmp/test_ubs/outside_dir/secret.txt
echo "normal_data" > /tmp/test_ubs/safe_dir/normal.txt

# 模拟敏感系统文件
sudo mkdir -p /tmp/test_sensitive
sudo echo "root_password_hash" > /tmp/test_sensitive/shadow
sudo chmod 644 /tmp/test_sensitive/shadow
```

**步骤 2: 构造测试程序**
```c
// poc_read.c - 演示路径遍历读取漏洞
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define BUFFER_SIZE 1024

void read_and_print(const char *path) {
    printf("Attempting to read: %s\n", path);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open failed");
        return;
    }
    
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = read(fd, buffer, BUFFER_SIZE - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("SUCCESS! Content:\n%s\n", buffer);
    }
    close(fd);
}

int main(int argc, char *argv[]) {
    // 场景1: 相对路径遍历 - 从 safe_dir 遍历到 outside_dir
    // 假设应用程序预期在 /tmp/test_ubs/safe_dir 下工作
    chdir("/tmp/test_ubs/safe_dir");
    read_and_print("../outside_dir/secret.txt");
    
    // 场景2: 多级路径遍历
    read_and_print("../../outside_dir/secret.txt");
    
    // 场景3: 绝对路径攻击 - 尝试读取系统敏感文件
    read_and_print("/tmp/test_sensitive/shadow");
    
    // 场景4: 符号链接攻击 (需要预先创建符号链接)
    // ln -s /tmp/test_sensitive/shadow /tmp/test_ubs/safe_dir/link
    read_and_print("link");
    
    // 场景5: 尝试读取真实系统文件 (需要权限)
    read_and_print("/etc/passwd");
    
    return 0;
}
```

**步骤 3: 执行 PoC**
```bash
# 编译测试程序
gcc -o poc_read poc_read.c

# 创建符号链接
cd /tmp/test_ubs/safe_dir
ln -s /tmp/test_sensitive/shadow link

# 使用 UBS-IO 拦截器运行
LD_PRELOAD=./dist/libock_interceptor.so ./poc_read

# 预期输出: 成功读取 outside_dir/secret.txt 和其他敏感文件
```

**步骤 4: 验证漏洞**
```bash
# 如果输出包含 SECRET_DATA，说明路径遍历成功
# 如果输出包含 root_password_hash，说明符号链接攻击成功
```

### 6. 实际可利用性评估

| 维度 | 评估 | 说明 |
|------|------|------|
| **前置条件** | 中等偏高 | 需要应用程序加载 UBS-IO 拦截器且用户可控路径 |
| **攻击复杂度** | 低 | 路径遍历攻击简单直接 |
| **权限要求** | 取决于应用程序 | 不能突破应用程序原有权限边界 |
| **用户交互** | 低 | 可通过 API 接口或配置文件触发 |
| **影响范围** | 信息泄露 | 可读取应用程序可访问的任意文件 |
| **远程利用** | 中 | PROXY 模式可能影响远程服务器 |

**综合评估: 设计缺陷型漏洞**

### 7. 与 libc 标准函数对比

| 特性 | libc open() | UBS-IO HookOpen() |
|------|-------------|-------------------|
| 路径验证 | 无 | 无 (仅检查空) |
| 权限边界 | 应用程序权限 | 应用程序权限 |
| 安全假设 | 无安全承诺 | **可能被误解为安全边界** |
| 额外风险 | 无 | PROXY 模式远程转发 |

**关键区别:** UBS-IO 作为中间层可能被开发者错误假设为提供安全验证，这是安全边界误解风险。

## 影响范围

### 直接影响
1. **敏感信息泄露**: 攻击者可读取应用程序可访问的任意文件
2. **凭证窃取**: 读取 SSH 密钥、API 密钥、数据库密码等
3. **配置暴露**: 读取应用程序配置文件获取敏感信息

### 间接影响
1. **权限提升准备**: 读取的信息可用于后续攻击
2. **横向移动**: 获取凭证后攻击其他系统
3. **AI 模型窃取**: 在 AI 场景中读取模型权重文件

### 受影响的部署场景
- **AI/ML 推理服务**: UBS-IO 主要应用场景，模型加载路径可能可控
- **大数据处理平台**: 数据集路径可能由用户指定
- **存算分离架构**: PROXY 模式可能转发到远程存储
- **NPU 加速应用**: 通过 UBS-IO 访问 NPU 数据

### 特殊风险场景

**AI 推理服务攻击链:**
```
1. 攻击者控制模型路径参数
2. 通过 UBS-IO 拦截层传递恶意路径
3. 读取系统敏感文件
4. 获取凭证后攻击其他服务
5. 可能进一步攻击 NPU 或分布式存储
```

## 设计本质分析

### UBS-IO 的设计目的

UBS-IO 是一个 **IO 加速中间件**，不是安全隔离系统：
- 目的: 提供高性能 IO 缓存和 NPU 直通存储
- 机制: 通过 LD_PRELOAD hook 标准 POSIX 文件操作
- 转发: 到本地缓存系统或远程存储服务器

### 安全边界假设问题

**问题根源:**
- `CheckPath()` 函数的存在可能让开发者误解 UBS-IO 提供路径验证
- 文档未明确说明安全边界责任
- 应用程序可能依赖 UBS-IO 进行安全验证（错误假设）

**正确理解:**
- `CheckPath()` 的目的是防止空指针导致的崩溃，不是安全验证
- 安全验证应由应用程序或底层存储系统负责
- UBS-IO 只是 IO 转发层，不应承担安全边界职责

### 是否应在此层验证路径？

**不验证的理由 (设计角度):**
1. 应用程序本身有同等权限
2. libc 的 open() 也不验证路径
3. 安全验证应由应用程序或存储系统负责

**应验证的理由 (防御角度):**
1. 防止安全边界误解导致的漏洞
2. PROXY 模式远程转发需要额外防护
3. 作为中间层应提供深度防御
4. 文档应明确说明安全边界责任

**推荐做法:** 至少在文档中明确说明安全边界，并考虑可选的路径验证功能。

## 修复建议

### 1. 立即缓解措施 (短期)

**方案 A: 增强 CheckPath 函数**

```cpp
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_PATH_LENGTH 4096

// 可配置的安全验证模式
enum PathValidationMode {
    VALIDATION_NONE = 0,      // 无验证 (默认，保持兼容性)
    VALIDATION_BASIC = 1,     // 基本验证 (检查 .. 和长度)
    VALIDATION_STRICT = 2,    // 严格验证 (白名单)
};

static PathValidationMode validationMode = VALIDATION_NONE;

static inline bool CheckPath(const char *path)
{
    // 基础检查
    if (path == nullptr) {
        errno = EFAULT;
        return false;
    }
    if (path[0] == '\0') {
        errno = ENOENT;
        return false;
    }
    
    // 如果验证模式为 NONE，直接返回 (保持原有行为)
    if (validationMode == VALIDATION_NONE) {
        return true;
    }
    
    // 路径长度检查
    if (strlen(path) > MAX_PATH_LENGTH) {
        INTERCEPTORLOG_WARN("Path too long: %s", path);
        errno = ENAMETOOLONG;
        return false;
    }
    
    // 基本路径遍历检查
    if (validationMode >= VALIDATION_BASIC) {
        if (strstr(path, "..") != nullptr) {
            INTERCEPTORLOG_WARN("Path traversal detected: %s", path);
            errno = EINVAL;
            return false;
        }
    }
    
    return true;
}

// 配置接口
INTERCEPTOR_API void SetPathValidationMode(PathValidationMode mode)
{
    validationMode = mode;
    INTERCEPTORLOG_INFO("Path validation mode set to: %d", mode);
}
```

**方案 B: 文档明确安全边界**

在 README.md 和 interceptor.h 中添加明确说明：
```cpp
/**
 * @warning 安全边界说明
 * 
 * UBS-IO 是 IO 加速中间件，不是安全隔离系统。
 * CheckPath() 函数仅检查路径参数的有效性（非空），不进行安全验证。
 * 
 * 安全验证责任:
 * - 应用程序应自行验证用户提供的文件路径
 * - 远程存储系统应有独立的路径验证机制
 * 
 * 路径遍历防护:
 * - 如需路径验证，请调用 SetPathValidationMode() 启用
 * - 默认不启用验证以保持兼容性
 */
```

### 2. 深度防御 (中期)

**可选的白名单验证机制:**

```cpp
class PathWhitelist {
private:
    std::vector<std::string> allowed_dirs_;
    bool enabled_ = false;
    
public:
    void AddAllowedDir(const std::string& dir) {
        allowed_dirs_.push_back(dir);
    }
    
    bool Validate(const char *path) {
        if (!enabled_ || allowed_dirs_.empty()) {
            return true;  // 未启用白名单，跳过验证
        }
        
        char resolved[PATH_MAX];
        if (realpath(path, resolved) == nullptr) {
            // 文件不存在时，检查路径是否可能指向允许目录
            // 可以使用更复杂的逻辑
            return false;
        }
        
        for (const auto& dir : allowed_dirs_) {
            if (strncmp(resolved, dir.c_str(), dir.length()) == 0) {
                return true;
            }
        }
        
        INTERCEPTORLOG_WARN("Path outside whitelist: %s", path);
        return false;
    }
    
    void SetEnabled(bool enabled) { enabled_ = enabled; }
};
```

### 3. 架构改进 (长期)

**建议实现:**
1. **文档完善**: 明确说明安全边界和责任归属
2. **可选验证**: 提供可配置的路径验证功能
3. **审计日志**: 记录所有文件访问操作，便于追溯
4. **PROXY 模式安全**: 确保远程服务器有独立的路径验证

### 4. 其他受影响函数

同样存在问题的函数（使用 CheckPath）：
- `HookCreat` / `HookCreat64` (文件创建)
- `HookTruncate` / `HookTruncate64` (文件截断)
- `HookRename` (文件重命名)
- `HookAccess` (文件访问检查)
- `HookUtimes` (文件时间修改)
- `HookStat` / `HookLstat` / `HookFstatAt` (文件状态)
- `HookUnlink` / `HookUnlinkat` / `HookRemove` (文件删除 - VULN-IO-012)

## 参考资料

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- CWE-73: External Control of File Name or Path
- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- SEI CERT C Coding Standard: FIO02-C. Canonicalize path names originating from untrusted sources

## 结论

**漏洞状态: 已确认 (TRUE POSITIVE - 设计缺陷型)**

### 漏洞本质

这是一个 **设计缺陷型漏洞**，而非传统的安全漏洞。UBS-IO 作为 IO 加速中间件，其 `CheckPath()` 函数设计目的是防止空指针崩溃，而非安全验证。但是：

1. **安全边界误解风险**: 开发者可能错误假设 UBS-IO 提供路径验证
2. **PROXY 模式风险**: 恶意路径可能转发到远程服务器
3. **防御不足**: 缺少基本的路径遍历检查

### 实际风险评估

| 风险维度 | 评估 |
|----------|------|
| **直接权限突破** | 低 (不能突破应用程序原有权限) |
| **信息泄露** | 中高 (可读取应用程序可访问的任意文件) |
| **安全假设风险** | 高 (可能被误解为安全边界) |
| **PROXY 远程风险** | 中 (取决于远程服务器验证) |

### 修复优先级

1. **高优先级**: 文档明确说明安全边界和责任归属
2. **中优先级**: 提供可选的路径验证功能
3. **低优先级**: 实现严格的白名单机制 (可选)

### 与 VULN-IO-012 的关系

本漏洞与 VULN-IO-012 (文件删除) 是同一设计缺陷在不同操作类型上的体现：
- VULN-IO-011: 文件读取/打开 - 信息泄露风险
- VULN-IO-012: 文件删除 - 数据破坏风险

建议统一修复所有使用 `CheckPath()` 的 Hook 函数。

---

**分析日期**: 2026-04-20  
**分析者**: OpenCode Security Scanner  
**相关漏洞**: VULN-IO-012 (文件删除路径遍历)
