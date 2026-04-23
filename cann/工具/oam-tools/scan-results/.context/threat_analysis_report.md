# 威胁分析报告

> 项目: oam-tools (华为 Ascend NPU 运维工具套件)
> 分析时间: 2026-04-22
> 分析模式: 自主分析模式（无 threat.md 约束文件）

## 项目概况

oam-tools 是华为 Ascend NPU 的运维工具套件，包含以下主要模块：

| 模块 | 语言 | 功能 | 源文件数 |
|------|------|------|----------|
| asys | Python | Ascend 系统诊断和信息收集工具 | 97 |
| msprof | C/C++ | 性能分析和数据收集工具 | 446 |
| msaicerr | Python | AI Core 错误分析工具 | 10 |
| hccl_test | C/C++ | HCCL 集合通信测试工具 | 13 |
| third_party | C/C++ | 第三方依赖 | 3 |

**项目类型**: CLI 工具套件，用户在 Ascend NPU 服务器上本地执行

**部署模型**: 
- 在 Linux 服务器上作为命令行工具执行
- 通过 sys.argv 接收用户输入
- 通过 Unix Domain Socket 进行进程间通信（msprof）
- 执行外部命令和脚本（asys launch）

## 信任边界分析

### 识别的信任边界

| 边界 | 可信一侧 | 不可信一侧 | 风险等级 |
|------|----------|------------|----------|
| Command Line Interface | 本地用户 Shell 权限 | 用户提供的参数和路径 | High |
| File System | 工具内部逻辑 | 用户指定的路径和文件 | High |
| IPC/Unix Socket | msprof 收集器进程 | 连接到 Unix Socket 的外部进程 | Medium |
| Environment Variables | 工具配置 | 外部环境变量值 | Medium |

### 边界风险分析

**CLI 边界 (High)**:
- 用户通过命令行参数完全控制工具行为
- 参数包括：命令类型、文件路径、设备 ID、超时时间等
- asys launch 命令直接执行用户提供的脚本命令

**文件系统边界 (High)**:
- 工具大量处理用户指定的文件路径
- 功能包括：信息收集、日志分析、coredump 分析、tar 文件解压
- 路径验证存在但可能不完整

**IPC/Unix Socket 边界 (Medium)**:
- msprof 使用 Unix Domain Socket 进行进程间通信
- 接收来自外部进程的数据包
- Socket 文件权限设置为 S_IRUSR | S_IWUSR（仅用户读写）

## STRIDE 威胁建模

### Spoofing (身份伪造)

| 威胁 | 风险 | 影响组件 |
|------|------|----------|
| Unix Socket 连接伪造 | Medium | msprof collector |
| 进程 PID 伪造（stacktrace 模式） | Low | asys stacktrace |

### Tampering (数据篡改)

| 威胁 | 风险 | 影响组件 |
|------|------|----------|
| 命令行参数篡改 | Low（本地执行） | asys, msaicerr, msprof |
| 配置文件篡改 | Medium | asys config |
| 日志文件篡改 | Medium | asys analyze, msaicerr |
| 输入文件篡改 | High | 所有工具 |

### Repudiation (抵赖)

| 威害 | 风险 | 影响组件 |
|------|------|----------|
| 无操作日志审计 | Low | 所有工具 |
| 输出结果篡改 | Medium | 所有工具 |

### Information Disclosure (信息泄露)

| 威害 | 风险 | 影响组件 |
|------|------|----------|
| 敏感信息写入输出文件 | Medium | 所有工具 |
| 日志文件包含敏感信息 | Medium | asys, msaicerr |
| 调试日志暴露内部信息 | Low | 所有工具 |

### Denial of Service (拒绝服务)

| 威害 | 风险 | 影响组件 |
|------|------|----------|
| 无限循环或超时配置 | Low | asys diagnose timeout |
| 大文件处理耗尽资源 | Low | 所有工具 |
| Socket 连接阻塞 | Low | msprof |

### Elevation of Privilege (权限提升)

| 威害 | 风险 | 影响组件 |
|------|------|----------|
| **命令注入** | **Critical** | **asys launch, asys cmd_run** |
| 路径遍历 | High | 所有工具文件操作 |
| 动态库加载（dlopen） | Medium | msprof prof_runtime_plugin |

## 关键攻击面分析

### 1. 命令执行 (Critical 风险)

**受影响组件**: asys launch 命令

**攻击路径**:
```
sys.argv → main() → CommandLineParser.parse() → ParamDict.get_arg("task") 
→ AsysLaunch.run() → execute_task() → subprocess.Popen(shell=True)
```

**风险点**:
- `src/asys/launch/asys_launch.py:80` - 使用 `subprocess.Popen(shell=True)` 执行用户命令
- `src/asys/common/cmd_run.py:42,57,84` - 多处使用 `subprocess.run(shell=True)` 和 `os.popen()`

**漏洞类型**: CWE-78 (OS Command Injection)

**现有防护**:
- `arg_checker.py` 中的 `check_arg_executable()` 对脚本类型进行验证
- 仅允许特定格式的脚本命令（sh/bash/python + .sh/.bash/.py 后缀）

**绕过可能性**:
- 正则表达式验证可能不完整
- 环境变量 `PATH` 可能影响命令解析
- 嵌套命令执行可能绕过验证

### 2. 文件路径处理 (High 风险)

**受影响组件**: 所有工具的文件操作功能

**攻击路径**:
```
sys.argv → 参数解析 → 路径校验 → os.path.realpath() → 文件操作
```

**风险点**:
- `src/msaicerr/msaicerr.py:53` - `tar.extractall(path)` 解压用户指定 tar 文件
- `src/msaicerr/ms_interface/utils.py:178` - `check_path_valid()` 路径校验
- `src/asys/cmdline/arg_checker.py:65` - `check_arg_exist_dir()` 目录校验

**漏洞类型**: CWE-22 (Path Traversal), CWE-73 (External Control of File Name or Path)

**现有防护**:
- `check_path_special_character()` 检查特殊字符（但不包括 `..`）
- `os.path.realpath()` 规范化路径
- 检查路径是否存在和是否有读写权限

**绕过可能性**:
- 特殊字符黑名单不完整（缺少 `..` 路径遍历检查）
- 符号链接可能导致路径逃逸
- tar 文件可能包含恶意路径（tar slip 漏洞）

### 3. Unix Socket 通信 (Medium 风险)

**受影响组件**: msprof 进程间通信

**攻击路径**:
```
外部进程 → Unix Socket connect → LocalSocket.Accept() → LocalSocket.Recv() 
→ Receiver.Run() → dispatcher_->OnNewMessage()
```

**风险点**:
- `src/msprof/collector/dvvp/common/socket/local_socket.cpp:40` - Socket 创建
- `src/msprof/collector/dvvp/common/socket/local_socket.cpp:149` - 数据接收
- `src/msprof/collector/dvvp/transport/receiver.cpp:110` - 数据包处理

**漏洞类型**: CWE-287 (Improper Authentication), CWE-20 (Improper Input Validation)

**现有防护**:
- Socket 文件权限设置为仅用户读写 (`S_IRUSR | S_IWUSR`)
- 接收超时设置 (`SO_RCVTIMEO`)

**绕过可能性**:
- 同用户的恶意进程可以连接
- 接收的数据包格式验证依赖 protobuf 解析
- 无连接认证机制

### 4. 动态库加载 (Medium 风险)

**受影响组件**: msprof 插件加载

**风险点**:
- `src/msprof/collector/dvvp/profapi/src/prof_runtime_plugin.cpp` - `dlopen()` 加载动态库

**漏洞类型**: CWE-426 (Untrusted Search Path)

**现有防护**:
- 依赖环境变量 `ASCEND_OPP_PATH` 确定库路径

**绕过可能性**:
- 环境变量篡改可能导致加载恶意库

## 高风险文件列表

| 文件 | 风险等级 | 原因 |
|------|----------|------|
| `src/asys/launch/asys_launch.py` | Critical | 命令执行入口，shell=True 命令注入风险 |
| `src/asys/common/cmd_run.py` | Critical | 命令执行封装，多处 shell=True |
| `src/msaicerr/msaicerr.py` | High | tar 解压、路径处理 |
| `src/asys/cmdline/cmd_parser.py` | High | 参数解析入口 |
| `src/asys/cmdline/arg_checker.py` | High | 参数校验逻辑 |
| `src/msprof/.../input_parser.cpp` | High | C++ 命令行参数解析 |
| `src/msprof/.../local_socket.cpp` | High | Unix Socket 通信 |
| `src/msprof/.../receiver.cpp` | High | 数据包接收处理 |
| `src/msaicerr/ms_interface/utils.py` | High | 命令执行和文件操作 |
| `src/msaicerr/ms_interface/collection.py` | High | 文件收集功能 |

## 建议的扫描重点

### 优先级 1 - Critical

1. **命令注入分析**:
   - `src/asys/launch/asys_launch.py` - `subprocess.Popen(shell=True)`
   - `src/asys/common/cmd_run.py` - 所有 `subprocess.run(shell=True)` 和 `os.popen()` 调用
   - 验证参数校验 `check_arg_executable()` 是否完整

2. **数据流追踪**:
   - `sys.argv` → 命令执行点
   - 环境变量 → 命令执行点

### 优先级 2 - High

1. **路径遍历分析**:
   - 所有文件路径参数的校验逻辑
   - `tar.extractall()` 调用（tar slip 漏洞）
   - 符号链接处理

2. **参数校验完整性**:
   - `src/asys/cmdline/arg_checker.py` 的正则表达式验证
   - `src/msaicerr/ms_interface/utils.py` 的路径校验

### 优先级 3 - Medium

1. **Unix Socket 安全**:
   - 数据包格式验证
   - 连接认证机制

2. **动态库加载安全**:
   - `dlopen()` 调用路径来源
   - 环境变量依赖

## 扫漏建议

基于威胁分析，建议漏洞扫描重点关注以下漏洞类型：

| CWE | 漏洞类型 | 优先级 | 关键文件 |
|-----|----------|--------|----------|
| CWE-78 | OS Command Injection | 1 | asys launch, cmd_run.py |
| CWE-22 | Path Traversal | 2 | arg_checker.py, utils.py |
| CWE-73 | External Control of File | 2 | msaicerr.py tar 解压 |
| CWE-426 | Untrusted Search Path | 3 | prof_runtime_plugin.cpp |
| CWE-20 | Improper Input Validation | 3 | input_parser.cpp, local_socket.cpp |
| CWE-787 | Out-of-bounds Write | 3 | strcpy_s 调用点 |

## 总结

oam-tools 项目的主要安全风险集中在：

1. **命令执行**：asys launch 命令允许用户执行任意脚本，存在命令注入风险
2. **文件路径处理**：所有工具大量处理用户指定的文件路径，路径验证可能不完整
3. **进程间通信**：msprof 使用 Unix Socket 通信，数据包验证依赖 protobuf 解析

建议优先扫描命令注入和路径遍历漏洞，重点关注 Python 模块的命令执行点和文件操作点。