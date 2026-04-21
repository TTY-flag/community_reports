# 威胁分析报告 - MindStudio Service Profiler

> **分析模式：自主分析模式**
> threat.md 不存在，本次攻击面分析由 AI 自主识别。

## 1. 项目架构概览

### 1.1 项目定位

**MindStudio Service Profiler** 是一款专为大模型推理服务设计的全栈性能分析与调优工具。项目采用 **C++ + Python 混合架构**：

- **C++ 层**：提供高性能数据采集能力，编译为动态库 `libms_service_profiler.so`
- **Python 层**：提供 CLI 工具、数据分析、配置管理、Hook/Patch 机制

**项目类型判定**：Python CLI 工具 + C++ 库（作为插件被 Python ctypes 加载）

**典型部署模型**：
- 用户在昇腾服务器上通过命令行调用工具
- 工具加载 C++ 库进行性能数据采集
- Python 脚本解析采集数据并生成报告

### 1.2 模块结构

| 模块 | 语言 | 风险等级 | 说明 |
|------|------|----------|------|
| cpp/src | C++ | High | 核心数据采集库，包含配置解析、安全检查 |
| ms_service_profiler | Python | Medium | 性能分析主模块，CLI 入口 |
| ms_service_profiler/patcher | Python | High | 动态 Hook/Patch 机制，配置加载与代码注入 |
| ms_service_profiler/tracer | Python | High | Unix Socket 服务器，接收 traced 数据 |
| ms_service_metric | Python | High | Metric 收集框架，共享内存 IPC |
| ms_service_profiler/utils | Python | High | 安全文件操作检查 |
| ms_serviceparam_optimizer | Python | Medium | 参数自动寻优 |
| msservice_advisor | Python | Low | 专家建议生成 |

### 1.3 信任边界

```
┌─────────────────────────────────────────────────────────────────┐
│  用户进程                                                        │
│  ┌─────────────────┐                                            │
│  │ CLI 入口        │ ←── 命令行参数 (untrusted_local)           │
│  │ (__main__.py)   │                                            │
│  └────────┬────────┘                                            │
│           │                                                      │
│  ┌────────▼────────┐   ┌─────────────────┐                     │
│  │ Python 分析层   │──→│ C++ 采集库      │ (ctypes binding)   │
│  │ (ms_service_    │   │ (libms_service_ │                     │
│  │  profiler)      │   │  profiler.so)   │                     │
│  └────────┬────────┘   └─────────────────┘                     │
│           │                                                      │
│  ┌────────▼────────┐                                            │
│  │ Unix Socket     │ ←── Traced 进程数据 (semi_trusted)        │
│  │ Server          │    (peer cred 验证: uid/gid/pid)          │
│  └────────┬────────┘                                            │
│           │                                                      │
│  ┌────────▼────────┐                                            │
│  │ YAML/JSON       │ ←── 配置文件 (semi_trusted)               │
│  │ Config Parser   │    (管理员控制，但路径可被环境变量影响)     │
│  └────────┬────────┘                                            │
│           │                                                      │
│  ┌────────▼────────┐                                            │
│  │ Shared Memory   │ ←── IPC 控制命令 (semi_trusted)           │
│  │ IPC             │    (posix_ipc + SIGUSR1, 同用户进程)       │
│  └─────────────────┘                                            │
└─────────────────────────────────────────────────────────────────┘
```

## 2. 攻击面分析

### 2.1 高风险攻击面

#### (1) 配置文件解析攻击面

**入口点**：
- `Config.cpp:ReadConfigFile()` - 读取 JSON 配置
- `config_loader.py:load_yaml_config()` - 读取 YAML 配置
- `symbol_config.py:load()` - 加载 YAML 配置

**风险分析**：
- 配置路径来自环境变量 `SERVICE_PROF_CONFIG_PATH` / `MS_SERVICE_METRIC_CONFIG_PATH`
- 环境变量可被攻击者修改，指向恶意配置文件
- YAML 配置中可指定 `handler` 函数路径，通过 `importlib.import_module` 动态导入并执行
- 存在潜在的 **代码注入** 风险（通过配置指定恶意 handler）

**防护措施**：
- `SecurityUtils::CheckFileBeforeRead()` 有软链接、权限、大小检查
- `file_open_check.py:ms_open()` 有路径白名单检查

#### (2) 动态 Handler 导入攻击面

**入口点**：
- `config_loader.py:_resolve_handler_func()`
- `config_loader.py:_resolve_metrics_handler_func()`

**风险分析**：
- 配置文件中可指定 `handler: "module.path:function_name"`
- 使用 `importlib.import_module(mod_str)` + `getattr(mod_obj, func_name)` 导入
- 如果攻击者能控制配置文件，可指定任意 Python 模块路径
- **存在代码执行风险**

#### (3) Unix Domain Socket 攻击面

**入口点**：
- `socket_server.py:AbstractSocketServer`

**风险分析**：
- 监听 abstract namespace Unix socket
- 接收 traced 进程发送的 OTLP 数据
- **防护措施**：
  - `_validate_peer_cred()` 检查 uid/gid/pid 匹配
  - 检查 PID namespace 和 User namespace 匹配
  - 防止不同用户进程连接
- **剩余风险**：同用户的恶意进程可发送恶意数据

#### (4) 共享内存 IPC 攻击面

**入口点**：
- `shm_manager.py:SharedMemoryManager`
- `cli.py:send_control_command()`

**风险分析**：
- 使用 `posix_ipc` 共享内存 + `SIGUSR1` 信号
- 控制命令可开启/关闭 metric 收集
- **防护措施**：仅同用户进程可通过共享内存通信
- **剩余风险**：同用户的恶意进程可发送控制命令

### 2.2 中风险攻击面

#### (5) CLI 参数解析攻击面

**入口点**：
- `__main__.py:main()`
- `parse.py:parse()`

**风险分析**：
- argparse 解析用户传入的 `--input-path`, `--output-path`
- 路径可能包含恶意路径（目录遍历）、超大文件
- **防护措施**：`check_input_dir_valid()` 有路径检查

#### (6) 环境变量攻击面

**入口点**：
- `Config.cpp:ReadConfigPath()` - `SERVICE_PROF_CONFIG_PATH`
- `file_open_check.py:get_valid_lib_path()` - `ASCEND_HOME_PATH`
- `symbol_config.py:load()` - `MS_SERVICE_METRIC_CONFIG_PATH`

**风险分析**：
- 环境变量由进程 owner 设置
- 攻击者如果能控制进程环境，可指向恶意路径
- `ASCEND_HOME_PATH` 可影响动态库加载路径

#### (7) 动态库加载攻击面

**入口点**：
- `mstx.py:LibServiceProfiler.__init__()`

**风险分析**：
- ctypes 加载 `libms_service_profiler.so`
- 库路径来自 `ASCEND_HOME_PATH` 或系统默认路径
- **防护措施**：`get_valid_lib_path()` 有白名单检查（只允许 `libms_service_profiler.so`）

#### (8) 字节码注入攻击面

**入口点**：
- `inject.py:inject_function()`

**风险分析**：
- 在 Python 函数入口和返回点注入 hook 代码
- 通过 `types.CodeType` 和 `types.FunctionType` 构造新函数
- 操纵字节码，可能影响函数行为

### 2.3 低风险攻击面

#### (9) 文件路径检查模块

**入口点**：
- `SecurityUtils.cpp` 各检查函数
- `file_open_check.py` 各检查函数

**风险分析**：
- 这些模块本身是防护措施
- 但需要检查验证逻辑的完整性（是否有遗漏）

## 3. STRIDE 威胁建模

### 3.1 Spoofing (欺骗)

| 威胁 | 描述 | 风险等级 | 缓解措施 |
|------|------|----------|----------|
| Unix Socket 客户端欺骗 | 恶意进程尝试连接 socket | Medium | peer cred 验证 (uid/gid/pid + namespace) |
| 共享内存进程欺骗 | 恶意进程尝试写入共享内存 | Medium | posix_ipc 需要同用户权限 |

### 3.2 Tampering (篡改)

| 威胁 | 描述 | 风险等级 | 缓解措施 |
|------|------|----------|----------|
| 配置文件篡改 | 攻击者修改配置文件内容 | High | 文件权限检查 (CheckFileBeforeRead) |
| YAML Handler 篡改 | 通过配置注入恶意 handler | Critical | 需要 handler 白名单或沙箱 |
| 路径篡改 | 通过环境变量篡改路径 | High | 环境变量验证 |
| 动态库篡改 | 替换 libms_service_profiler.so | Medium | 库名白名单检查 |

### 3.3 Repudiation (抵赖)

| 威胁 | 描述 | 风险等级 | 缓解措施 |
|------|------|----------|----------|
| 操作日志缺失 | 缺少完整的操作审计日志 | Low | 需要增加审计日志 |

### 3.4 Information Disclosure (信息泄露)

| 威胁 | 描述 | 风险等级 | 缓解措施 |
|------|------|----------|----------|
| 性能数据泄露 | traced 数据可能包含敏感信息 | Medium | Socket 仅允许同用户进程 |
| 配置信息泄露 | 配置文件可能包含敏感参数 | Medium | 文件权限检查 (0640) |
| 共享内存泄露 | 共享内存数据可能被读取 | Medium | posix_ipc 权限控制 |

### 3.5 Denial of Service (拒绝服务)

| 威胁 | 描述 | 风险等级 | 缓解措施 |
|------|------|----------|----------|
| 大文件解析 DoS | 解析超大输入文件导致资源耗尽 | Medium | 文件大小检查 (IsFileSizeLegal) |
| Socket 数据堆积 | Queue 满导致数据丢弃 | Low | Queue 大小限制 + 警告日志 |
| 无效进程堆积 | 共享内存中堆积无效 PID | Low | cleanup_invalid_processes() |

### 3.6 Elevation of Privilege (权限提升)

| 娰胁 | 描述 | 风险等级 | 缓解措施 |
|------|------|----------|----------|
| Handler 代码注入 | 通过配置执行任意代码 | Critical | 需要 handler 白名单 |
| 动态库加载提权 | 加载恶意动态库 | Medium | 库名白名单 |
| 模块导入提权 | importlib 导入恶意模块 | High | 需要模块路径白名单 |

## 4. 模块风险评估

### 4.1 C++ 模块

| 模块 | 文件 | STRIDE 威胁 | 风险等级 | 说明 |
|------|------|-------------|----------|------|
| 配置解析 | Config.cpp | T, E | **Critical** | JSON 解析，环境变量路径，realpath 使用 |
| 安全检查 | SecurityUtils.cpp | T | High | 文件操作检查，软链接检测 |
| 核心管理 | ServiceProfilerManager.cpp | I, D | High | 数据采集入口，多线程处理 |
| 数据库写入 | ServiceProfilerDbWriter.cpp | I | Medium | SQLite 写入，需检查 SQL 注入 |

### 4.2 Python 模块

| 模块 | 文件 | STRIDE 威胁 | 风险等级 | 说明 |
|------|------|-------------|----------|------|
| 配置加载 | config_loader.py | T, E | **Critical** | YAML 解析，动态 handler 导入 |
| 动态 Hook | dynamic_hook.py | T, E | High | 函数替换，字节码操作 |
| Socket 服务 | socket_server.py | S, I, T | High | Unix socket 监听，数据接收 |
| 共享内存 | shm_manager.py | S, T, I | High | 进程间通信 |
| 文件检查 | file_open_check.py | T | High | 安全文件操作，路径验证 |
| YAML 配置 | symbol_config.py | T, E | High | YAML 解析，handler 导入 |
| 字节码注入 | inject.py | T, E | High | Python 字节码操纵 |

## 5. 跨语言边界分析

### 5.1 Python → C++ 接口

**接口文件**：`mstx.py`

**数据流**：
```
Python ctypes call → libms_service_profiler.so → C++ function execution
```

**关键调用**：
- `service_profiler.start_span()` → `StartSpanWithName()`
- `service_profiler.span_end_ex()` → `SpanEndEx()`
- `service_profiler.mark_event_ex()` → `MarkEventEx()`

**风险**：
- 参数通过 ctypes 传递，需检查类型转换
- 字符串参数（char*）可能包含恶意数据
- 库路径受 `ASCEND_HOME_PATH` 影响

### 5.2 数据流向

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ 配置文件     │────→│ Python 解析  │────→│ C++ 配置读取 │
│ (JSON/YAML)  │     │              │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
                           │
                           ▼
                     ┌──────────────┐
                     │ Handler 导入 │
                     │ (importlib)  │
                     └──────────────┘
                           │
                           ▼
                     ┌──────────────┐
                     │ Hook 执行    │
                     │ (函数替换)   │
                     └──────────────┘
```

## 6. 安全加固建议

### 6.1 高优先级建议

#### (1) Handler 导入白名单

**问题**：`_resolve_handler_func()` 通过 `importlib.import_module` 导入任意模块。

**建议**：
- 实现 handler 函数白名单机制
- 只允许导入预定义的模块路径
- 或使用沙箱环境隔离 handler 执行

#### (2) 配置文件路径验证

**问题**：配置路径来自环境变量，可被攻击者控制。

**建议**：
- 增加配置文件路径的白名单验证
- 检查配置文件的数字签名或哈希
- 限制环境变量值的合法范围

#### (3) YAML 安全解析

**问题**：使用 `yaml.safe_load()`，但配置内容仍可指定 handler 路径。

**建议**：
- 对配置中的 `handler` 字段进行路径验证
- 限制 handler 只能是内置函数或白名单模块

### 6.2 中优先级建议

#### (4) 输入路径深度检查

**问题**：CLI 输入路径有基本检查，但需增强。

**建议**：
- 增强路径遍历检查
- 检查符号链接指向的目标
- 限制路径深度

#### (5) 共享内存访问控制

**问题**：posix_ipc 需要同用户权限，但进程列表可能堆积。

**建议**：
- 定期清理无效进程
- 增加进程注册验证

### 6.3 低优先级建议

#### (6) 审计日志增强

**建议**：
- 记录所有配置文件读取操作
- 记录 handler 导入和执行
- 记录 socket 连接和数据接收

#### (7) 错误处理增强

**建议**：
- 统一错误处理策略
- 避免敏感信息泄露到日志
- 增加异常情况的安全回退

## 7. 总结

MindStudio Service Profiler 是一个功能完善的性能分析工具，已实现了多种安全防护机制：

**已有防护**：
- Unix Socket peer cred 验证
- 文件操作安全检查（软链接、权限、大小）
- 动态库白名单
- 文件路径白名单正则检查

**待增强防护**：
- **Handler 导入白名单**（Critical）
- **配置文件完整性验证**（High）
- **环境变量范围限制**（High）
- **审计日志增强**（Low）

建议优先处理 Handler 导入安全问题，这是当前架构中最危险的攻击路径。