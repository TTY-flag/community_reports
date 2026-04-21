# msMemScope 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析由 AI 自主识别，未使用 `threat.md` 约束文件。

## 项目架构概览

### 项目定位
- **项目名称**: msMemScope
- **项目类型**: CLI工具 + Python库（开发调测工具）
- **主要功能**: 内存泄漏检测、内存对比、监测、拆解、低效识别
- **语言组成**: C/C++ 128文件(19099行) + Python 9文件(1435行)
- **部署方式**: Linux服务器上的开发调测工具，通过命令行或Python接口运行

### 核心架构
msMemScope 是一个基于昇腾硬件的内存检测工具，采用以下架构：

1. **命令行入口层** (`csrc/framework`)
   - `main.cpp` → `ClientParser` → `Command` → `Process`
   - 解析命令行参数，配置工具行为，启动目标进程

2. **Hook注入层** (`csrc/event_trace`)
   - 通过 `LD_PRELOAD` 环境变量注入Hook库
   - Hook库包括：`hal_hooks`, `kernel_hooks`, `mstx_hooks`, `acl_hooks`
   - 采集内存事件并上报到分析模块

3. **数据分析层** (`csrc/analysis`)
   - `Dump`: 事件数据落盘
   - `MemoryCompare`: 内存对比分析
   - `HalAnalyzer`: HAL内存分析
   - `InefficientAnalyzer`: 低效内存识别
   - `DecomposeAnalyzer`: 内存拆解

4. **Python接口层** (`csrc/python_itf` + `python/msmemscope`)
   - Python C扩展模块 `_msmemscope`
   - 提供 `start()`, `stop()`, `config()`, `watcher.watch()` 等接口
   - Python分析器 `LeaksAnalyzer`, `InefficientAnalyzer`

5. **工具支撑层** (`csrc/utility`)
   - 文件/路径操作（带安全检查）
   - SQLite数据库操作（动态加载）
   - JSON配置管理
   - 日志系统

### 模块依赖关系
```
main.cpp → framework/client_parser → framework/command → framework/process
                ↓
         event_trace/trace_manager → event_trace/event_report
                ↓
         analysis/dump → analysis/data_handler → utility/file
                ↓
         utility/sqlite_loader → event_trace/vallina_symbol → dlopen
```

## 模块风险评估

| 模块 | 语言 | 主要风险 | STRIDE威胁 | 风险等级 |
|------|------|----------|-----------|----------|
| framework | c_cpp | 命令行参数解析、进程启动 | T,E | Critical |
| python_itf | c_cpp | Python接口输入验证 | T,I | High |
| event_trace/vallina_symbol | c_cpp | dlopen、popen执行命令 | T,E | Critical |
| event_trace/mstx_hooks | c_cpp | Hook注入、函数指针替换 | T,E | High |
| event_trace/hal_hooks | c_cpp | 内存操作Hook | T,I | High |
| event_trace/kernel_hooks | c_cpp | Kernel/Runtime Hook | T,E | High |
| utility | c_cpp | 文件路径验证、SQLite操作 | T,I | High |
| analysis | c_cpp | 数据落盘、内存分析 | I,D | Medium |
| python_analyzer | python | CSV文件读取分析 | I | Medium |

## 攻击面分析

### 信任边界模型

本项目存在以下信任边界：

1. **命令行接口边界** (风险: Medium)
   - 可信侧：工具内部逻辑
   -不可信侧：本地用户（命令行参数）
   - 用户可控制所有命令行参数内容

2. **Python API接口边界** (风险: Medium)
   - 可信侧：工具内部逻辑
   - 不可信侧：Python调用者
   - Python接口参数由调用者传入

3. **文件系统边界** (风险: Medium)
   - 可信侧：工具内部逻辑
   - 不可信侧：用户指定的文件路径
   - 输入/输出路径由用户控制

4. **动态库加载边界** (风险: High)
   - 可信侧：工具内部逻辑
   - 不可信侧：外部动态库
   - SQLite、Hook库路径来自环境变量

### 入口点详细分析

#### 1. 命令行参数解析 (Critical)

**位置**: `csrc/framework/client_parser.cpp`
**函数**: `ClientParser::Interpretor`, `ClientParser::Parse`, `ParseUserCommand`

**用户可控参数**:
- `--input=path1,path2`: 输入文件路径（内存对比分析）
- `--output=path`: 输出目录路径
- `--steps=1,2,3`: 采集步骤选择
- `--call-stack=c:10,python:5`: 调用栈深度配置
- `--events=alloc,free,launch`: 事件类型配置
- `--analysis=leaks,decompose`: 分析类型配置
- `--watch=start:end`: 内存监测配置
- `<prog-and-args>`: 目标程序路径和参数

**潜在风险**:
- 参数解析函数使用 `strncpy_s` 拷贝路径到固定大小缓冲区
- 输入路径验证包含软链接检查、权限检查、长度限制
- 目标程序路径直接传递给 `execvpe()`

#### 2. Python API接口 (High)

**位置**: `csrc/python_itf/msleaksmodule.cpp`, `csrc/python_itf/watcherobject.cpp`

**用户可控接口**:
- `msmemscope.config(**kwargs)`: 配置参数（路径、分析类型等）
- `msmemscope.watcher.watch(tensor, name="xxx")`: 监测tensor对象
- `msmemscope.watcher.watch(addr, length=xxx, name="xxx")`: 监测指定内存地址

**潜在风险**:
- `PyUnicode_AsUTF8` 直接将Python字符串转为C字符串
- `PyLong_AsUnsignedLongLong` 将Python整数转为地址/长度
- 监测名称长度限制为64字符

#### 3. 文件路径操作 (High)

**位置**: `csrc/utility/file.cpp`, `csrc/utility/path.cpp`

**安全检查措施**:
- `CheckIsValidInputPath`: 验证路径存在性、可读性、长度、深度、软链接、权限
- `CheckIsValidOutputPath`: 验证路径长度、深度、软链接、非法字符
- `IsPermissionValid`: 检查属主为root或当前用户，禁止group/others写权限
- `IsSoftLink`: 检查路径是否为软链接并拒绝
- `IsValidOutputPath`: 仅允许ASCII字符和中文（UTF-8验证）

**潜在风险**:
- 软链接检查使用 `lstat()`，但路径解析使用 `Resolved()` 可能受符号链接攻击
- 权限检查在root用户时跳过

#### 4. 动态库加载 (Critical)

**位置**: `csrc/event_trace/vallina_symbol.cpp`

**关键函数**:
- `LibLoad`: 使用 `dlopen()` 加载动态库
- `ExecuteCommand`: 使用 `popen("which sqlite3")` 执行shell命令
- `FindAndLoadSqliteInDir`: 递归搜索目录加载SQLite库

**潜在风险**:
- `popen()` 执行外部命令，命令字符串为硬编码，但存在shell注入风险点
- `dlopen()` 加载库文件，路径来自 `ASCEND_HOME_PATH` 环境变量拼接
- `ValidateLibrary` 检查库文件权限和属主

#### 5. 进程启动与Hook注入 (High)

**位置**: `csrc/framework/process.cpp`

**关键函数**:
- `SetPreloadEnv`: 设置 `LD_PRELOAD` 环境变量
- `DoLaunch`: 使用 `execvpe()` 执行目标程序

**Hook库列表**:
- `libleaks_ascend_hal_hook.so`
- `libascend_mstx_hook.so`
- `libascend_kernel_hook.so`
- `libatb_abi_0_hook.so` / `libatb_abi_1_hook.so`

**潜在风险**:
- 目标程序路径和参数由用户命令行指定
- Hook库路径来自工具安装目录或 `LD_PRELOAD_PATH` 环境变量
- `execvpe()` 继承当前进程的所有环境变量

#### 6. Hook函数注入 (High)

**位置**: `csrc/event_trace/mstx_hooks/mstx_inject.cpp`, `csrc/event_trace/hal_hooks/hal_hooks.cpp`

**注入机制**:
- `InitInjectionMstx`: 替换MSTX函数表中的函数指针
- `MstxMarkAFunc`, `MstxRangeStartAFunc`, `MstxRangeEndFunc`: Hook实现
- `halMemAlloc`, `halMemFree`: HAL内存操作Hook

**潜在风险**:
- 函数指针替换可能导致代码执行流被劫持
- Hook函数内部调用原始函数（`halMemAllocInner`, `halMemFreeInner`）

#### 7. SQLite数据库操作 (High)

**位置**: `csrc/utility/sqlite_loader.cpp`, `csrc/utility/file.cpp`

**关键函数**:
- `Sqlite3Open`: 打开数据库文件
- `Sqlite3Exec`: 执行SQL语句
- `CreateDbFile`: 创建数据库文件和表

**潜在风险**:
- 数据库文件路径由用户 `--output` 参数控制
- SQL语句由工具内部生成，不存在用户可控SQL注入
- SQLite库动态加载，路径通过 `which sqlite3` 命令查找

## STRIDE威胁建模

### Spoofing (欺骗) - 身份伪造风险

| 风险点 | 说明 | 可能性 | 影响 |
|--------|------|--------|------|
| Python模块加载 | 攻击者可能伪造 `_msmemscope` 模块 | 低 | 中 |
| Hook库加载 | 攻击者可能替换Hook库实现恶意行为 | 中 | 高 |

**缓解措施**:
- `ValidateLibrary` 检查库文件属主和权限
- 仅加载root或当前用户拥有的库文件

### Tampering (篡改) - 数据篡改风险

| 风险点 | 说明 | 可能性 | 影响 |
|--------|------|--------|------|
| 命令行参数 | 用户可控制所有参数内容 | 高 | 中 |
| 配置文件 | JSON配置文件可能被篡改 | 中| 中 |
| 输出文件 | 输出CSV/DB文件可能被篡改 | 中 | 低 |
| Hook函数表 | 函数指针可能被替换 | 中 | 高 |

**缓解措施**:
- 输入路径验证包含权限检查
- 输出文件使用 `UmaskGuard` 设置安全权限
- 配置文件路径由工具内部控制

### Repudiation (抵赖) - 操作抵赖风险

| 风险点 | 说明 | 可能性 | 影响 |
|--------|------|--------|------|
| 日志记录 | 工具操作日志记录到文件 | 低 | 低 |

**缓解措施**:
- 日志系统记录工具行为

### Information Disclosure (信息泄露) - 敏感信息暴露风险

| 风险点 | 说明 | 可能性 | 影响 |
|--------|------|--------|------|
| 内存数据泄露 | 内存事件数据包含敏感地址信息 | 中| 中 |
| 输出文件权限 | 输出文件权限设置不当可能泄露数据 | 低 | 中 |
| 日志信息泄露 | 日志可能包含路径、内存地址等敏感信息 | 低 | 低 |

**缓解措施**:
- 输出文件使用安全umask创建
- 日志级别可配置，默认warn级别
- 文件权限检查禁止group/others写权限

### Denial of Service (拒绝服务) - 服务中断风险

| 风险点 | 说明 | 可能性 | 影响 |
|--------|------|--------|------|
| 无效路径 | 用户指定不存在的路径可能导致工具退出 | 高| 低 |
| 超长路径 | 超长路径字符串可能导致缓冲区问题 | 中 | 中 |
| 无效参数 | 无效参数导致工具退出并显示帮助信息 | 高 | 低 |

**缓解措施**:
- 路径长度限制为 `PATH_MAX`
- 参数验证失败时打印帮助信息并退出
- 使用 `strncpy_s` 进行安全字符串拷贝

### Elevation of Privilege (权限提升) - 权限升级风险

| 风险点 | 说明 | 可能性 | 影响 |
|--------|------|--------|------|
| 目标进程执行 | 工具以当前用户权限执行目标程序 | 高 | 中 |
| Hook库注入 | Hook库以目标进程权限运行 | 中 | 高 |
| 动态库加载 | 加载恶意库可能导致权限提升 | 中 | 高 |

**缓解措施**:
- 文档明确说明不建议使用root用户运行工具
- Hook库路径验证属主和权限
- SQLite库验证属主和权限

## 安全加固建议

### 架构层面建议

1. **动态库加载安全强化**
   - 增加 `dlopen()` 调用前的库文件完整性校验（如SHA256校验）
   - 限制库文件搜索范围，避免遍历用户可写目录
   - 移除 `popen()` 调用，使用安全的库路径查找方式

2. **命令行参数处理强化**
   - 对目标程序路径增加白名单校验
   - 增加参数值的最小/最大范围校验
   - 对特殊字符进行更严格的过滤

3. **Python接口安全强化**
   - 增加Python字符串参数的长度限制
   - 对内存地址参数增加合法性验证
   - 增加接口调用的权限检查

4. **Hook注入安全强化**
   - 增加Hook函数表的完整性校验
   - 记录Hook注入行为到日志
   - 提供Hook状态查询接口

### 代码层面建议

1. **移除危险的 `popen()` 调用**
   ```cpp
   // 当前代码 (vallina_symbol.cpp:52)
   FILE* pipe = popen(cmd, "r");
   
   // 建议: 使用安全的库路径查找方式
   // 例如: 预定义库路径列表，从配置文件读取
   ```

2. **增强路径验证**
   ```cpp
   // 建议: 在Resolved()后再次检查软链接
   Path realPath = path.Resolved();
   if (realPath.IsSoftLink()) {
       return false;
   }
   ```

3. **增加Python接口参数验证**
   ```cpp
   // 建议: 在PyUnicode_AsUTF8后增加长度检查
   const char* value_str = PyUnicode_AsUTF8(value);
   if (strlen(value_str) > MAX_CONFIG_VALUE_LENGTH) {
       PyErr_SetString(PyExc_ValueError, "Parameter value too long");
       return nullptr;
   }
   ```

## 总结

msMemScope 作为开发调测工具，其主要攻击面集中在：

1. **命令行参数解析** - 用户可控制大量参数
2. **Python接口** - Python调用者可传入配置和监测数据
3. **动态库加载** - 使用 `dlopen()` 和 `popen()` 加载外部库
4. **进程启动** - 使用 `execvpe()` 执行用户指定的目标程序
5. **Hook注入** - 通过 `LD_PRELOAD` 注入Hook库

工具已实施了多项安全措施：
- 路径验证（软链接检查、权限检查、长度限制）
- 库文件验证（属主检查、权限检查）
- 安全字符串拷贝（strncpy_s）
- 输出文件安全权限（UmaskGuard）

但仍存在需要关注的风险点：
- `popen()` 执行shell命令
- 动态库路径依赖环境变量
- 目标程序路径由用户完全控制
- Hook函数指针替换机制

建议后续扫描重点关注：
- `csrc/framework/client_parser.cpp` 的参数解析
- `csrc/event_trace/vallina_symbol.cpp` 的动态库加载
- `csrc/python_itf/watcherobject.cpp` 的Python接口
- `csrc/framework/process.cpp` 的进程启动
- 各Hook文件的函数指针操作