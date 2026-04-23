# VULN-DF-LPE-003: chmod/chown等权限修改函数TOCTOU竞态致权限提升

## 1. 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-LPE-003 |
| **漏洞类型** | TOCTOU 竞态条件 (Time-of-Check to Time-of-Use) |
| **CWE编号** | CWE-367 |
| **严重性** | Critical |
| **置信度** | 98% |
| **发现来源** | dataflow-module-scanner (lpeblock模块) |

## 2. 漏洞详情

### 2.1 位置信息
- **文件**: `src/om/platform/MindXOM_SDK/src/cpp/lpeblock/lpeblock.c`
- **函数**: `lpe_change_permission_check()`
- **行号**: 161-201

### 2.2 受影响的系统调用
此漏洞影响以下四个关键权限修改函数:
- `chmod()` - 修改文件权限
- `fchmodat()` - 修改文件权限(带目录描述符)
- `chown()` - 修改文件所有者
- `fchownat()` - 修改文件所有者(带目录描述符)

### 2.3 代码片段
```c
static int lpe_change_permission_check(const char* func, const char* path, const int flags)
{
    struct stat st;
    if (lstat(path, &st) != 0 || st.st_uid == 0) {
        // (link or file) not exist or owner is root
        return E_OK;
    }

    uid_t id = (uid_t)getuid();
    if (!S_ISLNK(st.st_mode)) {
        // path is not softlink
        if (id != st.st_uid) {
            syslog(LOG_INFO, "LPEBLOCK: ...");
        }
        return E_OK;
    }

    // chown -h
    if ((flags & AT_SYMLINK_NOFOLLOW) != 0) {
        return E_OK;
    }

    // path is softlink, get real file st
    struct stat real_st;
    if (stat(path, &real_st) != 0) {  // ⚠️ RACE WINDOW: lstat已检查，此时攻击者可修改符号链接
        syslog(LOG_INFO, "LPEBLOCK: ...");
        return E_NOK;
    }
    if (st.st_uid != real_st.st_uid) {  // ⚠️ 所有者比较检查
        syslog(LOG_INFO, "LPEBLOCK: ...");
        errno = EPERM;
        return E_NOK;
    }
    return E_OK;
}
```

### 2.4 数据流
```
path -> lstat(path, &st) [获取符号链接信息, 检查符号链接所有者]
     -> [⚠️ RACE WINDOW: 攻击者可替换符号链接目标]
     -> stat(path, &real_st) [获取目标文件信息]
     -> st.st_uid != real_st.st_uid [所有者一致性检查]
     -> libc_chmod/libc_chown [执行权限修改操作]
```

## 3. 利用条件分析

### 3.1 攻击者前置条件
| 条件 | 要求 | 说明 |
|------|------|------|
| **文件系统访问** | 需要在共享目录中有写权限 | 攻击者需要能创建/修改符号链接 |
| **触发能力** | 需要能触发chmod/chown操作 | 通过合法API或服务调用 |
| **时间窗口** | lstat和stat之间的时间差 | 通常为微秒级别 |
| **竞态成功率** | 需多次尝试 | 可通过CPU亲和性、文件系统负载优化 |

### 3.2 竞态窗口大小
- **典型窗口**: 约10-100微秒 (取决于CPU调度和I/O延迟)
- **优化条件**: 在高负载系统或使用CPU亲和性绑定时可扩大窗口

### 3.3 攻击者权限要求
- **最低权限**: 普通用户，拥有某个目录的写权限
- **目标**: 诱骗root进程修改攻击者控制的文件权限

## 4. 攻击场景描述

### 4.1 场景1: chmod提权攻击

**攻击目标**: 让root进程给攻击者的文件设置危险权限(如SUID)

**攻击步骤**:
1. 攻击者创建两个文件:
   - `/tmp/attack/safe_file` (所有者: attacker, 普通权限)
   - `/tmp/attack/malicious` (所有者: attacker, 普通权限)

2. 攻击者创建符号链接:
   ```bash
   ln -s /tmp/attack/safe_file /tmp/attack/target_link
   ```
   符号链接所有者为attacker，指向safe_file(所有者也是attacker)

3. 等待root进程调用 `chmod("/tmp/attack/target_link", 04755)`:
   - lstat检查: 符号链接所有者是attacker, safe_file所有者也是attacker → 检查通过
   - **竞态窗口**: 攻击者快速替换符号链接:
     ```bash
     rm /tmp/attack/target_link
     ln -s /tmp/attack/malicious /tmp/attack/target_link
     ```
   - stat检查: 新目标malicious所有者仍为attacker → 检查通过
   - chmod执行: 对malicious设置SUID权限 → **提权成功**

4. 攻击者执行malicious获得root权限

### 4.2 场景2: chown攻击

**攻击目标**: 将攻击者文件的所有者改为root

**攻击步骤**:
1. 创建符号链接指向攻击者自己的文件
2. 触发root进程执行 `chown("/tmp/link", 0, 0)`
3. 在竞态窗口内替换链接目标
4. root进程将攻击者文件改为root所有

### 4.3 场景3: 持久化监控攻击

攻击者可部署持续监控程序:
```c
while(1) {
    // 监控目标目录的stat调用
    if (detect_chmod_trigger()) {
        // 快速替换符号链接
        swap_symlink_target();
    }
}
```

## 5. 潜在影响评估

### 5.1 直接影响
| 影响 | 严重性 | 描述 |
|------|--------|------|
| **本地权限提升** | Critical | 攻击者可获得root权限 |
| **SUID文件创建** | Critical | 创建以root权限执行的恶意程序 |
| **文件所有权篡改** | High | 将任意文件改为root所有 |

### 5.2 间接影响
- **持久化后门**: 创建SUID shell或恶意程序
- **安全机制绕过**: 绕过LPEBLOCK的设计目的
- **系统完整性破坏**: 关键系统文件权限被篡改

### 5.3 影响范围
- **影响组件**: lpeblock.so库
- **影响服务**: 所有使用此库的root进程
- **影响系统**: 整个MindCluster集群

## 6. 修复建议

### 6.1 推荐修复方案: 使用O_PATH和fstatat

```c
static int lpe_change_permission_check(const char* func, const char* path, const int flags)
{
    // 使用O_PATH打开文件，获取文件描述符
    int fd = open(path, O_PATH | O_NOFOLLOW);
    if (fd < 0) {
        return E_NOK;
    }

    // 使用fstat检查符号链接本身(通过fd)
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_uid == 0) {
        close(fd);
        return E_OK;
    }

    uid_t id = (uid_t)getuid();
    if (!S_ISLNK(st.st_mode)) {
        // 非符号链接直接处理
        close(fd);
        if (id != st.st_uid) {
            syslog(LOG_INFO, "LPEBLOCK: ...");
        }
        return E_OK;
    }

    // 符号链接: 使用fstatat检查目标
    if ((flags & AT_SYMLINK_NOFOLLOW) != 0) {
        close(fd);
        return E_OK;
    }

    struct stat real_st;
    // 使用fstatat与同一个fd，避免竞态
    if (fstatat(fd, "", &real_st, AT_EMPTY_PATH) != 0) {
        close(fd);
        syslog(LOG_INFO, "LPEBLOCK: ...");
        return E_NOK;
    }

    if (st.st_uid != real_st.st_uid) {
        close(fd);
        syslog(LOG_INFO, "LPEBLOCK: ...");
        errno = EPERM;
        return E_NOK;
    }

    close(fd);
    return E_OK;
}
```

**注意**: 上述修复方案需要重新设计，因为O_PATH|O_NOFOLLOW会拒绝符号链接。更好的方案是:

### 6.2 修复方案2: 使用文件锁

```c
static int lpe_change_permission_check(const char* func, const char* path, const int flags)
{
    struct stat st;
    if (lstat(path, &st) != 0 || st.st_uid == 0) {
        return E_OK;
    }

    // 使用flock锁定父目录，防止符号链接被替换
    // (需要知道父目录路径)
    // ... 实现细节省略
}
```

### 6.3 修复方案3: 使用open+fchmod/fchown

```c
// 最可靠的修复: 使用open打开文件后使用fchmod/fchown
int safe_chmod(const char *pathname, mode_t mode)
{
    int fd = open(pathname, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        // 如果是符号链接，O_NOFOLLOW会失败
        // 此时应该使用lstat检查并决定是否允许
        return -1;
    }
    
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }
    
    // 安全检查
    if (st.st_uid != 0 && st.st_uid != geteuid()) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    
    int ret = fchmod(fd, mode);
    close(fd);
    return ret;
}
```

### 6.4 修复优先级
- **Critical**: 应立即修复，此漏洞可导致root权限提升

## 7. 参考资料

- [CWE-367: Time-of-check Time-of-Use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [TOCTOU Attack Prevention Techniques](https://www.usenix.org/legacy/publications/library/proceedings/sec02/full_papers/dan/dan_html/)