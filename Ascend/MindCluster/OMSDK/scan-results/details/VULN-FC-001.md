# VULN-FC-001: 证书检查使用stat而非lstat致符号链接绕过攻击

## 1. 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-FC-001 |
| **漏洞类型** | 符号链接绕过 (Symlink Bypass) |
| **CWE编号** | CWE-59 |
| **严重性** | High |
| **置信度** | 95% |
| **发现来源** | dataflow-module-scanner (fault_check模块) |

## 2. 漏洞详情

### 2.1 位置信息
- **文件**: `src/om/platform/MindXOM_SDK/src/cpp/fault_check/fault_check.c`
- **函数**: `check_cert_security()`
- **行号**: 131-153

### 2.2 代码片段
```c
int check_cert_security(const char *filename)
{
    struct stat st;
    if (stat(filename, &st) < 0) {  // ⚠️ BUG: 使用stat()而非lstat()
        FAULT_LOG_ERR("certfile error");
        return VOS_ERR;
    }

    // 大小校验
    signed long fsize = st.st_size;
    if (fsize < 0 || fsize > MAX_CERTFILE_SIZE) {
        FAULT_LOG_ERR("certfile size:%ld invalid", fsize);
        return VOS_ERR;
    }

    // 软链接校验 - ⚠️ 此检查永远无法生效!
    if (S_ISLNK(st.st_mode)) {
        FAULT_LOG_ERR("certfile is a link");
        return VOS_ERR;
    }

    return VOS_OK;
}
```

### 2.3 漏洞根因分析

**关键错误**: 使用 `stat()` 而非 `lstat()` 来检测符号链接

- `stat()`: 获取**目标文件**的元信息，如果路径是符号链接，会跟随链接获取目标文件的stat
- `lstat()`: 获取**符号链接本身**的元信息，如果是符号链接，`S_ISLNK()` 会返回true

**结果**: 当路径是符号链接时:
- `stat()` 返回目标文件的 `st_mode`
- `S_ISLNK(st.st_mode)` 检查的是目标文件是否为符号链接
- 如果目标是普通文件，检查结果为 `false`，符号链接检测被绕过

### 2.4 数据流
```
check_cert.c:get_cert_status()
    -> check_cert_security(CERT_FILE) [fault_check.c:131]
    -> stat(filename, &st) [⚠️ 错误: 应使用lstat]
    -> S_ISLNK(st.st_mode) [⚠️ 检查目标文件而非链接本身]
    -> 检查"通过" -> certPeriodicalCheck() [处理证书]
```

### 2.5 调用链分析

```c
// check_cert.c:63-79
static unsigned int get_cert_status(const char *CERT_FILE)
{
    if (access(CERT_FILE, F_OK) == 0) {
        if (check_cert_security(CERT_FILE) != 0) {  // 调用点
            return state_root;
        }
        ret_root = certPeriodicalCheck(CERT_FILE, &day_root);
        // ...
    }
}

// check_cert.c:81-92
static unsigned int fault_cert_status(void)
{
    state_nginx = get_cert_status(DIR_NGINX_CERT);   // 检查nginx证书
    state_redfish = get_cert_status(DIR_REDFISH_CERT); // 检查redfish证书
    // ...
}

// fault_check.c:94-112
int fault_check_cert_warn(unsigned int fault_id, unsigned int sub_id, unsigned short *value)
{
    state = fault_cert_status();  // 定期调用
    // ...
}
```

**入口点**: 定期运行的故障检测任务线程 `fault_manage_check_thread()` 会调用 `fault_check_cert_warn()`

## 3. 利用条件分析

### 3.1 攻击者前置条件
| 条件 | 要求 | 说明 |
|------|------|------|
| **证书目录写权限** | `/home/data/config/default/` 或 `/home/data/config/redfish/` | 需要能替换证书文件为符号链接 |
| **恶意证书准备** | 需要准备伪造的证书文件 | 攻击者控制的恶意证书 |
| **触发时机** | 等待证书检测周期执行 | 定期检测，周期可配置 |

### 3.2 证书路径
```c
#define DIR_NGINX_CERT    "/home/data/config/default/server_kmc.cert"
#define DIR_REDFISH_CERT  "/home/data/config/redfish/server_kmc.cert"
```

### 3.3 利用难度
- **难度**: Medium
- **原因**: 需要对证书目录的写权限，但一旦获得，攻击非常可靠

## 4. 攻击场景描述

### 4.1 场景1: 恶意证书注入攻击

**攻击目标**: 将系统使用的证书替换为攻击者控制的恶意证书

**攻击步骤**:
1. 攻击者获得证书目录的写权限
2. 创建恶意证书文件 `/tmp/malicious.cert`
3. 替换真实证书为符号链接:
   ```bash
   mv /home/data/config/default/server_kmc.cert /home/data/config/default/server_kmc.cert.bak
   ln -s /tmp/malicious.cert /home/data/config/default/server_kmc.cert
   ```
4. 系统进行证书检测:
   - `access()` 检查文件存在 → 通过
   - `check_cert_security()` 检查:
     - `stat()` 获取 `/tmp/malicious.cert` 的信息 → 普通文件
     - `S_ISLNK()` 检查 → false → **符号链接检测被绕过**
     - 文件大小检查 → 通过(攻击者可控制)
   - 检查结果: VOS_OK → **安全检查通过**
5. 系统使用恶意证书进行TLS通信
6. 攻击者可进行中间人攻击、证书伪造等

### 4.2 场景2: 证书文件劫持

**攻击目标**: 劫持证书文件，影响系统安全通信

**攻击步骤**:
1. 创建符号链接指向攻击者控制的文件
2. 当系统加载证书时，实际加载的是攻击者的文件
3. 可能的影响:
   - TLS连接被中间人攻击
   - 证书验证被绕过
   - 客户端信任恶意服务器

### 4.3 场景3: 证书过期告警抑制

**攻击目标**: 阻止证书过期告警

**攻击步骤**:
1. 将证书文件替换为指向不存在文件的符号链接
2. `stat()` 失败，返回错误
3. 证书检测静默失败，不产生告警
4. 系统管理员不知道证书即将过期

## 5. 潜在影响评估

### 5.1 直接影响
| 影响 | 严重性 | 描述 |
|------|--------|------|
| **证书验证绕过** | High | 系统使用恶意证书进行TLS通信 |
| **中间人攻击** | High | 攻击者可拦截/修改TLS通信内容 |
| **信任链破坏** | High | 客户端信任攻击者控制的证书 |

### 5.2 间接影响
- **Redfish API安全**: TLS通信被劫持
- **Nginx服务安全**: HTTPS通信被攻击
- **集群管理安全**: 管理员凭证可能泄露

### 5.3 影响范围
- **影响组件**: fault_check模块
- **影响服务**: nginx, redfish服务
- **影响系统**: 整个MindCluster集群

## 6. 修复建议

### 6.1 推荐修复方案: 使用lstat()

```c
int check_cert_security(const char *filename)
{
    struct stat st;
    // 使用lstat而非stat，正确检测符号链接
    if (lstat(filename, &st) < 0) {  // ✅ 修复: lstat
        FAULT_LOG_ERR("certfile error");
        return VOS_ERR;
    }

    // 大小校验
    signed long fsize = st.st_size;
    if (fsize < 0 || fsize > MAX_CERTFILE_SIZE) {
        FAULT_LOG_ERR("certfile size:%ld invalid", fsize);
        return VOS_ERR;
    }

    // 软链接校验 - 现在可以正确检测符号链接
    if (S_ISLNK(st.st_mode)) {
        FAULT_LOG_ERR("certfile is a link");
        return VOS_ERR;
    }

    // 额外建议: 检查文件所有者是否为root或预期用户
    if (st.st_uid != 0) {
        FAULT_LOG_ERR("certfile owner is not root");
        return VOS_ERR;
    }

    // 额外建议: 检查文件权限
    if ((st.st_mode & 0777) != 0600) {
        FAULT_LOG_ERR("certfile has unsafe permissions");
        return VOS_ERR;
    }

    return VOS_OK;
}
```

### 6.2 增强修复方案: 使用open+fstat

```c
int check_cert_security(const char *filename)
{
    // 使用O_NOFOLLOW阻止符号链接
    int fd = open(filename, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ELOOP) {
            FAULT_LOG_ERR("certfile is a symlink");
        } else {
            FAULT_LOG_ERR("certfile open error");
        }
        return VOS_ERR;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        FAULT_LOG_ERR("certfile fstat error");
        return VOS_ERR;
    }

    close(fd);

    // 其他检查...
    return VOS_OK;
}
```

### 6.3 修复优先级
- **High**: 应尽快修复，此漏洞可导致TLS通信安全失效

## 7. 参考资料

- [CWE-59: Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)
- [stat vs lstat - Linux man pages](https://man7.org/linux/man-pages/man2/lstat.2.html)
- [Symlink Attack Prevention](https://wiki.sei.cmu.edu/confluence/display/c/SEC05-C.+Use+stat()+securely)