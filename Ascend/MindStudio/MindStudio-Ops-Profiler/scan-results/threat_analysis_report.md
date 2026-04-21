# MindStudio-Ops-Profiler 威胁分析报告

> **分析模式：自主分析模式**  
> 本次攻击面分析未检测到 `threat.md` 约束文件，AI 自主识别所有潜在攻击面和高风险模块。

## 项目架构概览

### 项目定位

**MindStudio-Ops-Profiler (msOpProf)** 是华为昇腾AI算子调优工具，属于 **CLI 工具** 类别。

**典型部署场景**：
- 作为命令行工具在本地执行
- 用于采集和分析昇腾AI处理器上的算子性能数据
- 支持真机部署模式和仿真模式
- 接受 JSON 配置文件或命令行参数指定待分析的目标

**主要功能**：
- 性能数据采集：通过执行用户提供的二进制文件或可执行程序
- 数据解析：解析性能日志、二进制数据文件
- 性能分析：计算性能指标、生成可视化报告

### 技术栈

| 语言 | 文件数 | 代码行数 | 占比 |
|------|--------|----------|------|
| C/C++ | 247 | ~46K | 98% |
| Python | 11 | ~1.2K | 2% |

**主要模块**：
- `csrc/op_profiling/` - 核心业务逻辑（性能分析）
- `csrc/utils/` - 工具库（命令执行、文件操作、JSON解析）
- `csrc/op_runner/` - 算子运行器（二进制执行）
- `package/script/` - Python打包脚本
- `build.py`, `download_dependencies.py` - 构建脚本

### 信任边界模型

| 信任边界 | 可信一侧 | 不可信一侧 | 风险等级 |
|---------|---------|-----------|----------|
| **CLI Interface** | Application logic | Local user (命令行参数、配置文件) | Medium |
| **Binary Execution** | Profiler tool | User-provided executable/binary files | **High** |
| **File Input** | Parser logic | User-provided JSON config and performance data files | **High** |
| **Dynamic Library Loading** | Tool runtime | System libraries (runtime, HAL, DCMI) | Medium |

## 模块风险评估

### Critical 级别模块（必须重点扫描）

| 模块 | 路径 | 风险类型 | 原因 |
|------|------|----------|------|
| **utils** | csrc/utils/cpputils/ | 命令执行 | 包含 `CmdExecute` 函数，通过 fork/execvp/posix_spawnp 执行外部命令 |
| **op_runner** | csrc/op_runner/runner_impl/ | 命令执行 | `ExecBinaryRunner::Run` 执行用户提供的二进制文件 |
| **profiling_core** | csrc/op_profiling/profiling/ | 任务执行 | 调用命令执行和动态库加载，整合性能分析流程 |

### High 级别模块（需要关注）

| 模块 | 路径 | 风险类型 | 原因 |
|------|------|----------|------|
| **interface** | csrc/op_profiling/interface/ | 参数解析 | 接收命令行参数，解析用户输入 |
| **argparser** | csrc/op_profiling/argparser/ | 参数校验 | 处理用户输入参数，路径验证逻辑 |
| **common** | csrc/op_profiling/common/ | 动态库加载 | 通过 dlopen 加载 runtime/HAL/DCMI 库 |
| **parse** | csrc/op_profiling/parse/ | 数据解析 | 解析性能数据文件，包含路径处理 |

### Medium 级别模块（常规扫描）

| 模块 | 路径 | 风险类型 | 原因 |
|------|------|----------|------|
| **profiling_device** | csrc/op_profiling/profiling/device/ | 数据处理 | 解析设备端性能数据 |
| **profiling_simulator** | csrc/op_profiling/profiling/simulator/ | 数据处理 | 解析仿真数据 |
| **plugin** | csrc/op_profiling/plugin/ | 数据处理 | 插件模块，处理指令数据 |
| **python_scripts** | package/script/ | 文件操作 | 打包脚本，解析 XML 配置 |

### Low 级别模块（可选扫描）

| 模块 | 路径 | 风险类型 | 原因 |
|------|------|----------|------|
| **build_scripts** | ./ | 配置/构建 | 构建和依赖下载脚本 |

## 攻击面分析

### 主要攻击入口

#### 1. 命令行参数（untrusted_local）

**入口点**：
- `main()` @ csrc/op_profiling/main.cpp:24
- `BuildDeviceArgParser()` @ csrc/op_profiling/interface/ms_op_prof.cpp:60
- `BuildSimulatorArgParser()` @ csrc/op_profiling/interface/ms_op_prof.cpp:81

**攻击向量**：
- `--application` 参数：指定待执行的可执行文件路径
- `--config` 参数：指定 JSON 配置文件路径
- `--output` 参数：指定输出路径，可能用于路径遍历
- `--kernel-name` 参数：指定内核名称，可能用于注入

**风险分析**：
本地用户可通过命令行参数控制：
1. **待执行的二进制文件**（恶意代码执行）
2. **配置文件路径**（指向恶意配置）
3. **输出路径**（路径遍历、权限提升）

#### 2. JSON 配置文件（untrusted_local）

**入口点**：
- `ParseRunConfigJson()` @ csrc/utils/cpputils/json_parser.cpp:395

**攻击向量**：
- `kernel_path` 字段：指定内核二进制文件路径
- `data_path` 字段：指定输入数据文件路径
- `tiling_data_path` 字段：指定 Tiling 数据路径
- `output_data_path` 字段：指定输出数据路径

**风险分析**：
用户可通过 JSON 配置控制多个文件路径，这些路径流向：
1. **二进制执行**（kernel_path → ExecBinaryRunner）
2. **文件读取**（data_path → ifstream::open）
3. **文件写入**（output_data_path → ofstream）

#### 3. 命令执行接口（semi_trusted）

**入口点**：
- `CmdExecute()` @ csrc/utils/cpputils/cmd_execute.cpp:111
- `CmdExecuteWithOutput()` @ csrc/utils/cpputils/cmd_execute.cpp:80
- `ExecBinaryRunner::Run()` @ csrc/op_runner/runner_impl/exec_binary_runner.cpp:36

**攻击向量**：
- 命令参数来自上层解析（JSON 或命令行）
- 使用 `fork/execvp/execvpe` 或 `posix_spawnp` 执行

**风险分析**：
这是最危险的操作，攻击者可通过控制命令参数实现：
1. **命令注入**（如果参数未正确过滤）
2. **恶意代码执行**（执行任意二进制）
3. **权限提升**（如果工具以更高权限运行）

#### 4. 动态库加载（trusted_admin）

**入口点**：
- `RuntimeHelper::Init()` @ csrc/op_profiling/common/runtime_helper.cpp:57
- `HalHelper::Init()` @ csrc/op_profiling/common/hal_helper.cpp:39
- `OpProfTask::RunSimulator()` @ csrc/op_profiling/profiling/op_prof_task.cpp:44

**攻击向量**：
- `ASCEND_HOME_PATH` 环境变量：影响库路径
- `LD_LIBRARY_PATH` 环境变量：影响库搜索路径

**风险分析**：
虽然标记为 `trusted_admin`，但如果本地用户可修改这些环境变量：
1. **动态库劫持**（替换恶意库）
2. **代码注入**（通过预加载库）

#### 5. 环境变量（mixed）

| 环境变量 | 信任等级 | 风险 | 影响 |
|---------|---------|------|------|
| `MSOPT_LOG_LEVEL` | untrusted_local | Low | 仅影响日志级别 |
| `ASCEND_HOME_PATH` | trusted_admin | Medium | 影响库加载路径 |
| `LD_LIBRARY_PATH` | trusted_admin | Medium | 影响库搜索路径 |
| `PATH` | trusted_admin | Low | 影响命令搜索路径 |
| `HOME` | trusted_admin | Low | 影响默认路径 |

## STRIDE 威胁建模

### Spoofing（欺骗）

| 威胁 | 描述 | 风险等级 | 受影响模块 |
|------|------|----------|-----------|
| **身份伪装** | 工具无用户认证机制，任何本地用户都可执行 | Low | interface |
| **库伪装** | 通过 ASCEND_HOME_PATH/LD_LIBRARY_PATH 可替换系统库 | Medium | common (runtime_helper, hal_helper) |

**缓解措施**：
- 系统管理员应限制关键环境变量的修改权限
- 使用绝对路径加载系统库

### Tampering（篡改）

| 威胁 | 描述 | 风险等级 | 受影响模块 |
|------|------|----------|-----------|
| **配置篡改** | JSON 配置文件可被用户修改，注入恶意路径 | High | utils (json_parser) |
| **数据篡改** | 性能数据文件可被用户修改，触发解析漏洞 | Medium | profiling_device, profiling_simulator |
| **命令篡改** | 命令参数可被用户控制，执行恶意命令 | **Critical** | utils (cmd_execute), op_runner |

**缓解措施**：
- 对用户输入路径进行严格校验（已实现部分检查）
- 使用白名单限制可执行的命令
- 对配置文件进行权限检查（已在 json_parser.cpp 中实现）

### Repudiation（抵赖）

| 威胁 | 描述 | 风险等级 | 受影响模块 |
|------|------|----------|-----------|
| **操作抵赖** | 工具无审计日志，无法追溯用户操作 | Low | 全项目 |

**缓解措施**：
- 增强日志记录，记录关键操作（命令执行、文件访问）
- 添加操作审计功能

### Information Disclosure（信息泄露）

| 威胁 | 描述 | 风险等级 | 受影响模块 |
|------|------|----------|-----------|
| **日志泄露** | 日志可能包含敏感路径和参数 | Low | utils (log) |
| **数据泄露** | 性能数据可能包含敏感信息 | Medium | profiling_device, profiling_simulator |

**缓解措施**：
- 日志脱敏处理
- 限制日志级别（通过 MSOPT_LOG_LEVEL 控制）

### Denial of Service（拒绝服务）

| 威胁 | 描述 | 风险等级 | 受影响模块 |
|------|------|----------|-----------|
| **资源耗尽** | 解析大文件可能耗尽内存 | Medium | profiling_device (data_parse) |
| **进程阻塞** | 命令执行可能阻塞主进程 | Low | utils (cmd_execute) |

**缓解措施**：
- 对文件大小进行限制（已在 json_parser.cpp 中实现 MAX_JSON_FILE_SIZE）
- 使用超时机制（已在 ExecBinaryRunner 中实现）

### Elevation of Privilege（权限提升）

| 威胁 | 描述 | 风险等级 | 受影响模块 |
|------|------|----------|-----------|
| **恶意代码执行** | 通过 --application 执行恶意二进制 | **Critical** | op_runner (exec_binary_runner) |
| **命令注入** | 通过命令参数执行恶意命令 | **Critical** | utils (cmd_execute) |
| **库劫持** | 通过环境变量劫持系统库 | Medium | common (runtime_helper, hal_helper) |

**缓解措施**：
- **已实现**：
  - 工具检测 root 用户并发出警告（main.cpp:40）
  - 文件权限检查（json_parser.cpp:413）
  - 路径验证（filesystem.cpp）
  
- **建议增加**：
  - 白名单限制可执行的应用路径
  - 禁止执行 root 权限的应用
  - 沙箱执行用户提供的二进制

## 关键数据流路径

### 高风险数据流（优先验证）

```
[CLI 参数] --application → ProfArgsInit → ExecBinaryRunner::Run → posix_spawnp
  风险: 用户控制待执行的二进制文件，可能导致恶意代码执行
  
[JSON 配置] kernel_path → ParseRunConfigJson → ExecBinaryRunner::Run → posix_spawnp  
  风险: JSON 文件中的路径字段流向命令执行
  
[命令参数] executeCmd → CmdExecute → fork → execvpe
  风险: 命令参数直接流向 exec 系函数，未经过充分过滤
```

### 中风险数据流

```
[环境变量] ASCEND_HOME_PATH → GetAscendHomePath → RuntimeHelper::Init → dlopen
  风险: 环境变量影响动态库加载路径
  
[JSON 配置] data_path → ParseRunConfigJson → ifstream::open
  风险: JSON 文件中的路径字段流向文件打开操作
  
[二进制数据] binaryData → TlvParse::ReadData → memcpy_s
  风险: 二进制数据流向内存复制（已使用安全函数）
```

## 安全加固建议（架构层面）

### 1. 命令执行安全

**当前问题**：
- `ExecBinaryRunner::Run()` 直接执行用户提供二进制
- `CmdExecute()` 使用 fork/execvpe 执行命令，参数来自用户输入

**建议措施**：
- 实现应用白名单：仅允许执行预定义的安全应用路径
- 沙箱执行：使用 namespace/seccomp 限制用户二进行的权限
- 参数过滤：对命令参数进行严格的字符过滤，防止注入

### 2. 配置文件安全

**当前问题**：
- JSON 配置文件包含多个路径字段，流向敏感操作
- 已有权限检查，但可能不完整

**建议措施**：
- 增强路径验证：使用 canonicalize_file_name 获取真实路径
- 路径白名单：限制配置文件只能指向特定目录
- 配置签名：对关键配置文件进行签名验证

### 3. 动态库加载安全

**当前问题**：
- 通过 dlopen 加载系统库，路径受环境变量影响
- 使用 RTLD_LAZY 可能延迟绑定错误

**建议措施**：
- 使用绝对路径：直接指定库的绝对路径，不依赖环境变量
- 校验库文件：加载前验证库文件的签名或哈希
- 使用 RTLD_NOW：立即绑定所有符号，捕获加载错误

### 4. 输入验证增强

**当前实现**：
- 文件大小限制（MAX_JSON_FILE_SIZE）
- 文件权限检查（CheckOwnerPermission, CheckPermission）
- 路径长度限制（FILE_NAME_LENGTH_LIMIT）

**建议增强**：
- 实现完整的输入验证框架
- 对所有用户输入进行类型和范围检查
- 使用正则表达式验证路径格式

### 5. 日志和审计

**当前实现**：
- 基础日志记录（log.cpp）
- 日志级别控制（MSOPT_LOG_LEVEL）

**建议增强**：
- 增加操作审计日志：记录命令执行、文件访问等关键操作
- 实现日志脱敏：过滤敏感信息（路径、参数）
- 集中日志管理：支持日志远程上报

## 高风险文件列表（扫描优先级）

| 优先级 | 文件路径 | 风险等级 | 主要威胁 |
|--------|----------|----------|----------|
| 1 | csrc/utils/cpputils/cmd_execute.cpp | Critical | 命令执行（execvp/posix_spawnp） |
| 2 | csrc/op_runner/runner_impl/exec_binary_runner.cpp | Critical | 二进制执行（posix_spawnp） |
| 3 | csrc/op_profiling/common/runtime_helper.cpp | High | 动态库加载（dlopen） |
| 4 | csrc/op_profiling/common/hal_helper.cpp | High | 动态库加载（dlopen） |
| 5 | csrc/utils/cpputils/json_parser.cpp | High | JSON解析（用户配置） |
| 6 | csrc/utils/cpputils/filesystem.cpp | High | 文件操作（路径处理） |
| 7 | csrc/op_profiling/profiling/op_prof_task.cpp | High | 任务执行（整合命令执行和库加载） |
| 8 | csrc/op_profiling/interface/ms_op_prof.cpp | High | 参数解析（命令行） |
| 9 | csrc/op_profiling/argparser/arg_checker.cpp | High | 参数校验（输入验证） |
| 10 | csrc/op_profiling/main.cpp | High | 主入口（CLI） |

## 总结

MindStudio-Ops-Profiler 作为 CLI 工具，其核心攻击面集中在：

1. **命令执行**（Critical）：工具执行用户提供的二进制文件，这是最危险的攻击入口，可能导致恶意代码执行和权限提升。

2. **配置解析**（High）：JSON 配置文件中的路径字段流向命令执行和文件操作，需要严格的输入验证。

3. **动态库加载**（Medium）：系统库路径受环境变量影响，存在库劫持风险。

**关键发现**：
- 项目已实现部分安全措施（文件权限检查、大小限制、root 用户警告）
- 使用了安全函数（strcpy_s, memcpy_s）进行内存操作
- 但命令执行路径仍需加强安全控制

**下一步行动**：
- 重点扫描 cmd_execute.cpp 和 exec_binary_runner.cpp 的命令注入漏洞
- 验证 json_parser.cpp 的路径验证逻辑完整性
- 检查 runtime_helper.cpp 和 hal_helper.cpp 的动态库加载安全性