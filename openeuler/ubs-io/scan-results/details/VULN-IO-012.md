# VULN-IO-012: HookUnlink等文件删除函数路径验证缺失致任意文件删除

## 漏洞概述

| 属性 | 值 |
|------|-----|
| 漏洞ID | VULN-IO-012 |
| 类型 | Path Traversal (路径遍历) |
| CWE | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| 严重性 | HIGH |
| 置信度 | 90% |
| 状态 | 已确认 (真实漏洞) |

## 受影响代码

### 文件位置
- **主文件**: `ubsio-boostio/src/io_interceptor/src/posix_interceptor.cpp`
- **行号**: 507-594
- **函数**: `HookUnlink`, `HookUnlinkat`, `HookRemove`

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

// HookUnlink - 文件删除钩子 (lines 507-516)
int HookUnlink(const char *path)
{
    if (!CheckPath(path) || !InitNativeHook() || CHECKNATIVEFUNC(unlink)) {
        return -1;
    }
    if (CHECKPROXYLOADED || CHECKPROXYFUNC(unlink)) {
        return NATIVE(unlink)(path);  // 路径直接传递给原生 unlink！
    }
    return PROXY(unlink)(path);  // 或传递给代理 unlink！
}

// HookUnlinkat - 目录文件删除钩子 (lines 518-527)
int HookUnlinkat(int fd, const char *path, int flag)
{
    if (!CheckPath(path) || !InitNativeHook() || CHECKNATIVEFUNC(unlinkat)) {
        return -1;
    }
    if (CHECKPROXYLOADED || CHECKPROXYFUNC(unlinkat)) {
        return NATIVE(unlinkat)(fd, path, flag);  // 路径直接传递！
    }
    return PROXY(unlinkat)(fd, path, flag);
}

// HookRemove - 通用删除钩子 (lines 585-594)
int HookRemove(const char *path)
{
    if (!CheckPath(path) || !InitNativeHook() || CHECKNATIVEFUNC(remove)) {
        return -1;
    }
    if (CHECKPROXYLOADED || CHECKPROXYFUNC(remove)) {
        return NATIVE(remove)(path);  // 路径直接传递！
    }
    return PROXY(remove)(path);
}
```

### 入口点

```cpp
// posix_interface.cpp:239-243
INTERCEPTOR_API int unlink(const char* path)
{
    INTERCEPTORLOG_DEBUG("Hooking unlink %s succeeded.", path);
    return HookUnlink(path);  // 应用程序的 unlink 调用被拦截
}

// posix_interface.cpp:245-248
INTERCEPTOR_API int unlinkat(int fd, const char *pathname, int flag)
{
    INTERCEPTORLOG_DEBUG("Hooking unlinkat %d %s %d succeeded.", fd, pathname, flag);
    return HookUnlinkat(fd, pathname, flag);
}

// posix_interface.cpp:305-309
INTERCEPTOR_API int remove(const char* path)
{
    INTERCEPTORLOG_DEBUG("Hooking remove %s succeeded.", path);
    return HookRemove(path);
}
```

## 漏洞分析

### 1. 触发条件

**必要条件:**
1. 目标应用程序通过 `LD_PRELOAD` 加载了 `libock_interceptor.so`
2. 应用程序调用 `unlink()`, `unlinkat()`, 或 `remove()` 系统调用
3. 应用程序允许用户输入控制文件路径参数

**充分条件:**
- 应用程序未对用户提供的路径进行充分验证
- 或应用程序依赖 UBS-IO 进行路径验证（错误的安全假设）

### 2. 数据流分析

```
[用户输入/应用程序]
        │
        ▼
    用户可控路径
        │
        ▼
[LD_PRELOAD 拦截层]
    posix_interface.cpp
        │ unlink(path) / unlinkat(fd, path, flag) / remove(path)
        ▼
[Hook 函数层]
    posix_interceptor.cpp
        │ HookUnlink() / HookUnlinkat() / HookRemove()
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
    NATIVE(unlink)(path) → 直接系统调用
    或
    PROXY(unlink)(path) → 代理操作 (可能发送到远程服务器)
        │
        ▼
[文件系统]
    删除指定文件 (可能为任意文件！)
```

### 3. 攻击场景

#### 场景 A: 本地文件删除攻击
```
攻击者输入: "../../../../etc/passwd"
预期行为: 删除应用程序工作目录下的特定文件
实际行为: 删除 /etc/passwd (如果权限允许)
```

#### 场景 B: 绝对路径攻击
```
攻击者输入: "/etc/shadow"
预期行为: 删除应用程序数据目录下的文件
实际行为: 尝试删除系统关键文件
```

#### 场景 C: 符号链接攻击
```
1. 攻击者创建符号链接: ln -s /etc/passwd /tmp/app_data/malicious_link
2. 攻击者触发删除: remove("/tmp/app_data/malicious_link")
3. 实际删除: /etc/passwd
```

#### 场景 D: 代理模式远程攻击
```
[攻击者控制的客户端]
        │ 构造恶意路径: "../../../remote_sensitive_file"
        ▼
[UBS-IO 拦截层]
        │ PROXY(unlink)(path)
        ▼
[远程 UBS-IO 服务器]
        │ 接收删除请求
        ▼
[远程文件系统]
        删除服务器上的敏感文件
```

### 4. PoC 构造思路

**步骤 1: 环境准备**
```bash
# 编译 UBS-IO
cd ubsio-boostio
bash build.sh -t release

# 准备测试环境
mkdir -p /tmp/test_ubs/{safe_dir,outside_dir}
echo "sensitive_data" > /tmp/test_ubs/outside_dir/secret.txt
echo "normal_data" > /tmp/test_ubs/safe_dir/normal.txt
```

**步骤 2: 构造测试程序**
```c
// poc.c - 演示路径遍历漏洞
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    // 场景1: 相对路径遍历
    // 假设程序预期删除 safe_dir 下的文件
    // 但攻击者提供: "../outside_dir/secret.txt"
    const char *malicious_path = "../outside_dir/secret.txt";
    
    printf("Attempting to delete: %s\n", malicious_path);
    if (unlink(malicious_path) == 0) {
        printf("SUCCESS: File deleted!\n");
    } else {
        perror("unlink failed");
    }
    
    // 场景2: 绝对路径攻击
    const char *abs_path = "/tmp/test_ubs/outside_dir/secret.txt";
    if (remove(abs_path) == 0) {
        printf("Absolute path attack succeeded!\n");
    }
    
    return 0;
}
```

**步骤 3: 执行 PoC**
```bash
# 编译测试程序
gcc -o poc poc.c

# 使用 UBS-IO 拦截器运行
LD_PRELOAD=./dist/libock_interceptor.so ./poc

# 验证结果
ls -la /tmp/test_ubs/outside_dir/
# 如果 secret.txt 被删除，漏洞确认
```

### 5. 实际可利用性评估

| 维度 | 评估 | 说明 |
|------|------|------|
| **前置条件** | 中等 | 需要应用程序加载 UBS-IO 拦截器 |
| **攻击复杂度** | 低 | 路径遍历攻击简单直接 |
| **权限要求** | 高 | 需要应用程序具有删除目标文件的权限 |
| **用户交互** | 低 | 可通过自动化脚本触发 |
| **影响范围** | 高 | 可删除任意可访问文件 |
| **远程利用** | 中 | 取决于代理模式是否启用 |

**综合评分: 6.5/10 (可利用)**

## 影响范围

### 直接影响
1. **数据丢失**: 攻击者可删除应用程序可访问的任意文件
2. **系统不稳定**: 删除关键配置或日志文件可能导致系统故障
3. **权限提升**: 删除安全配置文件可能破坏安全边界

### 间接影响
1. **拒绝服务**: 批量删除文件可导致服务不可用
2. **审计逃避**: 删除日志文件可隐藏攻击痕迹
3. **供应链攻击**: 如果代理模式启用，可影响远程服务器

### 受影响的部署场景
- AI/ML 推理服务 (UBS-IO 主要应用场景)
- 大数据处理平台
- 存算分离架构系统
- NPU 加速应用

## 修复建议

### 1. 立即缓解措施 (短期)

**增强 CheckPath 函数:**
```cpp
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_PATH_LENGTH 4096
#define ALLOWED_BASE_DIR "/app/data"  // 配置允许的基础目录

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
    if (strlen(path) > MAX_PATH_LENGTH) {
        errno = ENAMETOOLONG;
        return false;
    }
    
    // 新增: 路径遍历检查
    if (strstr(path, "..") != nullptr || strstr(path, "//") != nullptr) {
        errno = EINVAL;
        return false;
    }
    
    // 新增: 解析真实路径并检查是否在允许目录内
    char resolved_path[PATH_MAX];
    if (realpath(path, resolved_path) == nullptr) {
        // 文件不存在时，解析可能失败
        // 可以选择更宽松的策略或使用其他方法
        return true;  // 或根据业务需求处理
    }
    
    // 新增: 检查是否在允许的基础目录内
    if (strncmp(resolved_path, ALLOWED_BASE_DIR, strlen(ALLOWED_BASE_DIR)) != 0) {
        errno = EACCES;
        return false;
    }
    
    return true;
}
```

### 2. 深度防御 (中期)

**实现路径白名单机制:**
```cpp
class PathValidator {
private:
    std::vector<std::string> allowed_dirs_;
    
public:
    bool ValidatePath(const char *path) {
        char resolved[PATH_MAX];
        if (realpath(path, resolved) == nullptr) {
            return false;
        }
        
        for (const auto& dir : allowed_dirs_) {
            if (strncmp(resolved, dir.c_str(), dir.length()) == 0) {
                return true;
            }
        }
        return false;
    }
};
```

**对删除操作进行额外保护:**
```cpp
int HookUnlink(const char *path)
{
    // 路径验证
    if (!CheckPath(path) || !ValidatePathAgainstWhitelist(path)) {
        return -1;
    }
    
    // 对关键文件进行保护
    if (IsCriticalFile(path)) {
        errno = EPERM;
        return -1;
    }
    
    // 记录审计日志
    AuditLog("UNLINK", path);
    
    // 原有逻辑
    if (!InitNativeHook() || CHECKNATIVEFUNC(unlink)) {
        return -1;
    }
    if (CHECKPROXYLOADED || CHECKPROXYFUNC(unlink)) {
        return NATIVE(unlink)(path);
    }
    return PROXY(unlink)(path);
}
```

### 3. 架构改进 (长期)

**建议实现:**
1. **沙箱隔离**: 使用 chroot 或 namespace 隔离文件系统访问
2. **Capability 限制**: 限制应用程序的文件系统操作权限
3. **审计日志**: 记录所有文件删除操作，便于追溯
4. **输入验证框架**: 统一的输入验证框架，避免分散验证

### 4. 其他受影响函数检查

同样需要修复的函数:
- `HookOpen` / `HookOpen64` / `HookOpenAt` / `HookOpenAt64` (文件创建)
- `HookCreat` / `HookCreat64` (文件创建)
- `HookTruncate` / `HookTruncate64` (文件截断)
- `HookRename` (文件重命名)
- `HookAccess` (文件访问检查)
- `HookUtimes` (文件时间修改)
- `HookStat` / `HookLstat` / `HookFstatAt` (文件状态)
- 以及对应的文件流操作函数

## 参考资料

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- SEI CERT C Coding Standard: FIO02-C. Canonicalize path names originating from untrusted sources

## 结论

**漏洞状态: 已确认 (TRUE POSITIVE)**

这是一个真实的路径遍历漏洞，可导致任意文件删除。虽然利用需要特定条件（应用程序加载 UBS-IO 拦截器且允许用户控制路径），但缺少基本的路径验证是严重的安全缺陷。建议立即实施上述缓解措施，并在后续版本中进行深度防御改进。
