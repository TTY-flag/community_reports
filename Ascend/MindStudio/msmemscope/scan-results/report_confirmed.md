# 漏洞扫描报告 — 已确认漏洞

**项目**: msMemScope
**扫描时间**: 2026-04-20T06:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 8 | 47.1% |
| POSSIBLE | 4 | 23.5% |
| CONFIRMED | 3 | 17.6% |
| FALSE_POSITIVE | 2 | 11.8% |
| **总计** | **17** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 2 | 66.7% |
| Medium | 1 | 33.3% |
| **有效漏洞总计** | **3** | - |
| 误报 (FALSE_POSITIVE) | 2 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-PROC-001]** process_execution (High) - `csrc/framework/process.cpp:224` @ `Process::DoLaunch` | 置信度: 85
2. **[VULN-DF-CROSS-002]** cross_module_data_flow (High) - `跨模块:0` @ `CommandLine to Process Execution Chain` | 置信度: 85
3. **[SEC-006]** Improper_Link_Resolution (Medium) - `csrc/framework/process.cpp:42` @ `ExecCmd::ExecCmd` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@csrc/main.cpp` | cmdline | untrusted_local | CLI工具的主入口，接收用户命令行参数(argc, argv)，用户可以控制所有参数内容 | 程序主入口，解析命令行参数并执行命令 |
| `ClientParser::Interpretor@csrc/framework/client_parser.cpp` | cmdline | untrusted_local | 命令行参数解析入口，接收argc/argv并解析大量用户可控参数（路径、步骤、分析类型等） | 解析命令行参数并配置工具行为 |
| `ParseInputPaths@csrc/framework/client_parser.cpp` | file | untrusted_local | 解析用户指定的输入文件路径（--input参数），路径内容完全由用户控制 | 解析内存对比分析所需的输入文件路径 |
| `ParseOutputPath@csrc/framework/client_parser.cpp` | file | untrusted_local | 解析用户指定的输出目录路径（--output参数），路径内容完全由用户控制 | 解析分析结果输出目录路径 |
| `PyInit__msmemscope@csrc/python_itf/msleaksmodule.cpp` | decorator | untrusted_local | Python C扩展模块入口，被Python解释器调用，配置参数由Python调用者传入 | Python模块初始化，注册start/stop/config/step等接口 |
| `MsmemscopeConfig@csrc/python_itf/msleaksmodule.cpp` | decorator | untrusted_local | Python config()接口，接收用户传入的kwargs配置参数，包括路径、分析类型等 | Python接口配置工具参数 |
| `PyMemScopeWatcherWatch@csrc/python_itf/watcherobject.cpp` | decorator | untrusted_local | Python watcher.watch()接口，接收用户传入的tensor或addr+length参数进行内存监测 | Python接口添加内存监测对象 |
| `ExecuteCommand@csrc/event_trace/vallina_symbol.cpp` | cmdline | semi_trusted | 通过popen执行外部命令(which sqlite3)，命令参数来自硬编码字符串，但popen本身存在风险 | 执行外部shell命令查找sqlite3库路径 |
| `Process::SetPreloadEnv@csrc/framework/process.cpp` | env | trusted_admin | 设置LD_PRELOAD环境变量，Hook库路径来自工具安装目录和ATB_HOME_PATH环境变量，由管理员/部署者控制 | 设置进程预加载的Hook库环境变量 |
| `Process::Launch@csrc/framework/process.cpp` | cmdline | untrusted_local | 启动目标进程执行内存采集，目标程序路径和参数由用户命令行指定 | 启动被检测的目标进程 |
| `ctypes.CDLL@python/msmemscope/__init__.py` | file | semi_trusted | 动态加载libascend_leaks.so，路径来自ASCEND_HOME_PATH环境变量拼接，环境变量由部署者控制 | Python模块初始化时加载C扩展库 |
| `LeaksAnalyzer.read_file@python/msmemscope/analyzer/leaks.py` | file | untrusted_local | 读取用户指定的CSV文件进行分析，文件路径由Python调用者传入 | 读取CSV内存事件数据文件 |

**其他攻击面**:
- 命令行参数接口: msmemscope <options> <prog-and-args>
- Python API接口: msmemscope.config(), msmemscope.start(), msmemscope.stop(), msmemscope.watcher.watch()
- 文件输入接口: --input=path1,path2 (CSV/DB文件)
- 文件输出接口: --output=path (输出目录)
- 动态库加载: dlopen(libsqlite3.so), dlopen(libascend_leaks.so)
- Hook注入机制: LD_PRELOAD设置，Hook库注入目标进程
- Shell命令执行: popen("which sqlite3")
- 进程执行: execvpe()执行用户指定的目标程序

---

## 3. High 漏洞 (2)

### [VULN-DF-PROC-001] process_execution - Process::DoLaunch

**严重性**: High | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `csrc/framework/process.cpp:224-228` @ `Process::DoLaunch`
**模块**: framework

**描述**: execvpe 执行用户通过命令行参数指定的目标程序。用户可以通过 msmemscope CLI 工具的命令行参数控制要执行的程序路径和参数。如果该工具以更高权限运行（如 root 或特殊 capabilities），可能导致权限提升。数据流: argv → ClientParser::Interpretor → ClientParser::Parse → userCommand.cmd → Process::Launch → ExecCmd → execvpe

**漏洞代码** (`csrc/framework/process.cpp:224-228`)

```c
void Process::DoLaunch(const ExecCmd &cmd)
{
    execvpe(cmd.ExecPath().c_str(), cmd.ExecArgv(), environ);
    _exit(EXIT_FAILURE);
}
```

**达成路径**

argv@csrc/main.cpp:22 [SOURCE]
→ ClientParser::Interpretor@csrc/framework/client_parser.cpp:211
→ ClientParser::Parse@csrc/framework/client_parser.cpp:859
→ userCommand.cmd@csrc/framework/client_parser.cpp:892
→ Process::Launch@csrc/framework/process.cpp:163
→ ExecCmd@csrc/framework/process.cpp:49
→ execvpe@csrc/framework/process.cpp:227 [SINK]

**验证说明**: CLI工具设计意图：用户通过命令行参数控制目标程序。数据流完整(argv→ClientParser→Process::Launch→execvpe)。关键风险点：工具以更高权限运行时的权限提升。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-CROSS-002] cross_module_data_flow - CommandLine to Process Execution Chain

**严重性**: High | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `跨模块:0` @ `CommandLine to Process Execution Chain`
**模块**: cross_module
**跨模块**: main → framework

**描述**: 跨模块命令行到进程执行链：用户命令行参数从 main.cpp 传入，经过 framework 模块的 ClientParser 解析，最终在 process.cpp 中通过 execvpe 执行用户指定的目标程序。整个链路跨越 main、framework 两个模块，用户可控的程序路径直接到达进程执行 sink。

**漏洞代码** (`跨模块:0`)

```c
跨模块传播，涉及 csrc/main.cpp → csrc/framework/client_parser.cpp → csrc/framework/process.cpp
```

**达成路径**

argv@csrc/main.cpp:22 [SOURCE-main模块]
→ ClientParser::Interpretor@csrc/framework/client_parser.cpp:211 [framework模块]
→ ClientParser::Parse@csrc/framework/client_parser.cpp:859
→ userCommand.cmd@csrc/framework/client_parser.cpp:892
→ Process::Launch@csrc/framework/process.cpp:163
→ execvpe@csrc/framework/process.cpp:227 [SINK-framework模块]

**验证说明**: 跨模块命令行到进程执行链。数据流完整(main→ClientParser→Process→execvpe)。用户可控程序路径直接到达进程执行sink。与VULN-DF-PROC-001相同问题。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (1)

### [SEC-006] Improper_Link_Resolution - ExecCmd::ExecCmd

**严重性**: Medium | **CWE**: CWE-59 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `csrc/framework/process.cpp:42-63` @ `ExecCmd::ExecCmd`
**模块**: framework

**描述**: ExecCmd 构造函数接受用户传入的程序路径参数，使用 realpath() 解析为绝对路径，但没有验证目标程序文件的属主和权限安全性。虽然这是工具的功能设计(用户指定要分析的目标程序)，但仍应加强安全检查，防止执行恶意程序或通过软链接攻击。

**漏洞代码** (`csrc/framework/process.cpp:42-63`)

```c
ExecCmd::ExecCmd(std::vector<std::string> const &args) : path_{}, argc_{0}, args_{args} {
    if (args_.empty()) { return; }
    char *absPath = realpath(args[0].c_str(), nullptr);
    if (absPath) {
        path_ = std::string(absPath);
        // 缺少对目标程序文件的属主/权限验证
    }
}
```

**达成路径**

argv命令行参数 -> args[0] -> realpath() -> path_ -> execvpe()

**验证说明**: CLI工具设计意图：用户通过命令行参数指定目标程序。使用realpath()解析路径。风险在于工具以更高权限运行时的权限提升场景。需加强程序文件安全验证。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cross_module | 0 | 1 | 0 | 0 | 1 |
| framework | 0 | 1 | 1 | 0 | 2 |
| **合计** | **0** | **2** | **1** | **0** | **3** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 2 | 66.7% |
| CWE-59 | 1 | 33.3% |
