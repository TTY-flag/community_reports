# 威胁分析报告 - MindStudio Ops Tuner

> **分析模式：自主分析模式**
> 本次攻击面分析未受 threat.md 约束，AI 自主识别了所有潜在攻击面和高风险模块。

## 项目架构概览

### 项目定位

**MindStudio Ops Tuner (msOpTuner)** 是华为 Ascend NPU 算子 Tiling 参数寻优工具，属于 **CLI 工具** 类型。

**部署模型**：本地执行的命令行工具，用户在 Ascend NPU 设备上运行，用于批量测试算子性能并输出调优数据到 CSV 文件。

**语言组成**：
- C/C++ 源文件：13 个 (.cpp)，16 个 (.h)
- Python 文件：10 个 (.py)
- 总代码行数：6402 行

### 模块结构

| 模块 | 语言 | 文件数 | 主要功能 |
|------|------|--------|----------|
| tuner_core | c_cpp | 11 | 主调优逻辑、命令行解析、设备管理、性能采集 |
| tuner_headers | c_cpp | 12 | 头文件定义 |
| dfx_kernel | c_cpp | 1 | L2 缓存清除内核 |
| library_core | c_cpp | 3 | 算子库接口 |
| library_headers | c_cpp | 2 | 库头文件 |
| code_generator | python | 7 | 算子代码生成脚本 |
| build_scripts | python | 2 | 构建和依赖下载脚本 |

### 核心数据流

```
用户命令行参数 → 命令行解析 → 设备初始化 → 算子配置 → 算子运行 → 性能采集 → CSV 输出
```

## 模块风险评估

| 模块 | 风险等级 | 主要风险点 |
|------|----------|-----------|
| tuner_core (metrics.cpp) | **Critical** | 文件路径处理、软链接检测、权限验证 |
| tuner_core (command_line_parser.cpp) | **High** | 参数解析、类型转换、溢出检查 |
| tuner_core (profiler.cpp) | **High** | 外部驱动调用、环境变量读取、设备控制 |
| tuner_core (device_memory_manager.cpp) | **High** | 设备内存分配、内存边界检查 |
| tuner_core (catlass_tuner.cpp) | **High** | 主协调逻辑、参数传递 |
| build_scripts (download_dependencies.py) | **High** | 外部命令执行（git, curl, tar） |
| build_scripts (build.py) | **Medium** | 构建命令执行（cmake, make） |
| tuner_core (gemm_op_config.cpp) | **Medium** | 内存参数计算、安全乘法 |
| tuner_core (op_launcher.cpp) | **Medium** | 算子启动接口 |
| code_generator | **Low** | 代码生成脚本，构建时运行 |

## 攻击面分析

### 1. 命令行参数接口（High Risk）

**入口点**：`main(argc, argv)` @ `tuner/src/main.cpp:21`

**信任等级**：`untrusted_local`

**攻击者可达性**：本地用户直接控制

**可控参数**：
- `--m/--n/--k`：矩阵维度（可能触发整数溢出）
- `--output`：输出文件路径（可能触发路径遍历）
- `--device`：设备 ID（可能触发设备访问异常）
- `--kernels`：算子过滤字符串（已做字符白名单检查）
- `--A/--B/--C`：张量类型配置（格式解析）

**潜在风险**：
- 整数溢出：参数转换使用 `std::stoll/stoull`，有溢出检查
- 参数注入：`--output` 参数直接传入文件路径处理

### 2. 文件输出接口（Critical Risk）

**入口点**：`Metrics::SetOutputPath()` @ `tuner/src/metrics.cpp:196`

**信任等级**：`untrusted_local`

**攻击者可达性**：用户通过 `--output` 参数指定

**安全措施**（已实现）：
- 路径规范化：`StandardizePath()` 将相对路径转为绝对路径
- 软链接检测：`IsSoftLink()` 检查并警告
- 权限验证：`CheckPermission()` 检查目录权限
- 非法字符检查：`CheckInvalidChar()` 过滤危险字符
- 递归目录创建：`MkdirRecursively()` 设置安全权限（0750）

**潜在攻击路径**：
- 路径遍历：使用 `/../` 尝试访问敏感文件
- 软链接攻击：指向 `/etc/passwd` 或其他敏感文件
- 权限提升：写入其他用户可读写的目录

**代码位置**：
- 路径检查逻辑：`tuner/src/metrics.cpp:137-144`（`IsSafePath`）
- 权限验证：`tuner/src/metrics.cpp:100-123`（`CheckPermission`）
- 文件写入：`tuner/src/metrics.cpp:257-261`

### 3. 环境变量接口（Medium Risk）

**入口点**：`ProfileDataHandler::SetDeviceId()` @ `tuner/src/profiler.cpp:395`

**信任等级**：`semi_trusted`

**攻击者可达性**：环境变量由系统管理员或部署脚本设置，非普通用户直接控制

**读取的环境变量**：
- `ASCEND_RT_VISIBLE_DEVICES`：设备可见性配置

**潜在风险**：
- 环境变量注入：恶意设置可能导致设备访问异常
- ID 映射错误：`rtGetVisibleDeviceIdByLogicDeviceId` 转换失败

### 4. 设备驱动接口（High Risk）

**入口点**：`Profiler::Start()` @ `tuner/src/profiler.cpp:180`

**信任等级**：`internal`（但依赖外部驱动）

**外部函数调用**：
- `prof_drv_start(deviceId, channelId, startPara)`：启动性能采集
- `prof_channel_read(deviceId, channelId, outBuf, bufSize)`：读取采集数据
- `prof_channel_poll(outBuf, num, timeout)`：轮询数据通道
- `prof_stop(deviceId, channelId)`：停止采集
- `halGetDeviceInfo(devId, moduleType, infoType, value)`：获取设备信息

**潜在风险**：
- 驱动返回数据解析：`prof_channel_read` 返回的二进制数据直接解析
- 设备资源耗尽：大量算子运行可能导致设备资源紧张
- 多线程竞态：数据读取线程与主线程的数据传递

### 5. 设备内存接口（High Risk）

**入口点**：`DeviceMemoryManager::Initialize()` @ `tuner/src/device_memory_manager.cpp:96`

**外部函数调用**：
- `aclInit()`：初始化 ACL 运行时
- `aclrtSetDevice(deviceId)`：设置设备
- `aclrtCreateStream()`：创建流
- `aclrtMalloc(addr, size, policy)`：分配设备内存
- `aclrtMemcpyAsync(dst, size, src, size, type, stream)`：异步拷贝
- `aclrtSynchronizeStream(stream)`：同步流

**潜在风险**：
- 内存大小计算：`gemm_op_config.cpp` 中的 `SafeMul` 检查防止溢出
- 内存边界验证：`FillDeviceData()` 检查目标地址是否在合法范围
- 设备内存耗尽：大量算子可能导致内存分配失败

### 6. 构建脚本命令执行（High Risk）

**入口点**：`DependencyManager::_exec_shell_cmd()` @ `download_dependencies.py:51`

**信任等级**：`trusted_admin`（构建时执行）

**外部命令**：
- `git submodule update --init`
- `curl -Lfk --retry 5 -o <archive> <url>`
- `tar -xf <archive> -C <extract_path>`
- `cmake .. -DBUILD_TESTS=ON`
- `make -j <jobs>`

**潜在风险**：
- 命令注入：参数来自配置文件 `dependencies.json`，非用户直接输入
- 网络下载：`curl` 下载二进制包，有 SHA256 校验
- 文件解压：`tar` 解压可能触发路径遍历（使用 shutil.move 作为回退）

## STRIDE 威胁建模

### Spoofing (欺骗)

| 威胁场景 | 风险等级 | 描述 |
|----------|----------|------|
| 设备 ID 伪造 | Low | 用户通过 `--device` 参数指定设备，映射逻辑验证 |
| 输出文件伪装 | Medium | 软链接可能指向其他用户文件，已做检测 |

### Tampering (篡改)

| 娇胁场景 | 风险等级 | 描述 |
|----------|----------|------|
| CSV 文件篡改 | Medium | 输出文件权限设置为 0640，仅 owner 可写 |
| 配置文件篡改 | Low | `search_space_config.py` 配置由开发者控制 |
| 设备内存篡改 | Medium | 设备内存数据来自用户参数，有边界检查 |

### Repudiation (抵赖)

| 威胁场景 | 风险等级 | 描述 |
|----------|----------|------|
| 操作日志缺失 | Low | 使用 LOGI/LOGW/LOGE 记录操作，但无审计日志 |

### Information Disclosure (信息泄露)

| 威胁场景 | 风险等级 | 描述 |
|----------|----------|------|
| 性能数据泄露 | Medium | CSV 输出包含设备 ID、算子名称，权限 0640 |
| 设备信息泄露 | Low | 驱动返回数据仅包含时间戳，无敏感信息 |
| 路径信息泄露 | Low | 日志中输出文件路径和错误信息 |

### Denial of Service (拒绝服务)

| 威胁场景 | 风险等级 | 描述 |
|----------|----------|------|
| 设备资源耗尽 | High | 大量算子运行可能导致设备内存耗尽或超时 |
| 文件系统耗尽 | Low | 输出文件大小受算子数量限制（最多 10000） |
| 无限循环 | Low | 算子运行次数固定（RUN_TIMES=5） |

### Elevation of Privilege (权限提升)

| 威胁场景 | 风险等级 | 描述 |
|----------|----------|------|
| 文件权限提升 | Medium | 输出目录权限 0750，文件权限 0640 |
| 设备权限提升 | Low | 设备访问受 ASCEND_RT_VISIBLE_DEVICES 控制 |

## 安全加固建议（架构层面）

### 1. 文件输出路径安全（已实现，建议增强）

**现状**：已有路径安全检查、软链接检测、权限验证

**建议增强**：
- 添加路径黑名单：禁止写入 `/etc`、`/root`、`/home` 等敏感目录
- 强制输出目录：建议将输出限制在用户工作目录或指定目录
- 文件内容验证：输出前验证 CSV 内容格式

### 2. 命令行参数安全（已实现，建议增强）

**现状**：已有类型转换、溢出检查、非法字符过滤

**建议增强**：
- 参数范围限制：`m/n/k` 建议设置合理范围（如 1-100000）
- `--output` 路径前缀检查：强制 `.csv` 扩展名，禁止其他文件类型
- 参数数量限制：防止参数过多导致内存耗尽

### 3. 设备资源管理（建议实现）

**现状**：无设备资源限制

**建议实现**：
- 算子数量限制：已有 10000 上限，建议降低或动态调整
- 内存预检查：运行前检查设备可用内存
- 超时保护：`aclrtSynchronizeStreamWithTimeout` 已有 1000s 超时，建议可配置

### 4. 构建脚本安全（建议增强）

**现状**：下载依赖有 SHA256 校验

**建议增强**：
- 网络下载证书验证：`curl` 已使用 `-k` 跳过证书验证，建议在生产环境验证证书
- 解压路径检查：`tar` 解压前检查目标路径权限
- 命令参数白名单：限制可执行的命令类型

### 5. 日志和审计（建议实现）

**现状**：使用 LOGI/LOGW/LOGE 输出到标准输出

**建议实现**：
- 结构化日志：输出到文件，包含时间戳、用户 ID、操作类型
- 审计日志：记录关键操作（设备访问、文件写入）
- 日志权限：日志文件权限设置为 0640

## 高风险文件列表（按优先级排序）

| 优先级 | 文件路径 | 风险等级 | 模块类型 | 关键函数 |
|--------|----------|----------|----------|----------|
| 1 | tuner/src/metrics.cpp | Critical | 文件系统操作 | SetOutputPath, IsSafePath, CheckPermission |
| 2 | tuner/src/command_line_parser.cpp | High | 参数解析 | Parse, Get |
| 3 | tuner/src/profiler.cpp | High | 设备驱动接口 | Start, CreateReadThread, SetDeviceId |
| 4 | tuner/src/device_memory_manager.cpp | High | 设备内存管理 | Initialize, FillDeviceData, Expand |
| 5 | tuner/src/catlass_tuner.cpp | High | 主协调逻辑 | CatlassTuner, Run, RunOp |
| 6 | download_dependencies.py | High | 构建脚本 | _exec_shell_cmd, proc_artifact |
| 7 | tuner/src/gemm_op_config.cpp | Medium | 内存参数计算 | InitArgument, SafeMul |
| 8 | tuner/src/op_launcher.cpp | Medium | 算子启动 | Init, operator() |

## 跨文件数据流路径

### 路径 1：命令行参数 → 文件输出

```
argv (main.cpp:21)
  → CommandLineParser::Parse (command_line_parser.cpp:165)
  → CommandLineParser::Get (command_line_parser.cpp:25)
  → CatlassTuner::CatlassTuner (catlass_tuner.cpp:26)
  → Metrics::SetOutputPath (metrics.cpp:196)
  → IsSafePath (metrics.cpp:137)
  → CheckPermission (metrics.cpp:100)
  → stat (系统调用)
```

**风险**：用户可控路径传递到文件权限检查，检查逻辑可能遗漏部分攻击场景

### 路径 2：矩阵维度 → 设备内存

```
argv --m/--n/--k (main.cpp:21)
  → CommandLineParser::Parse (command_line_parser.cpp:165)
  → GemmOpConfig::InitConfig (gemm_op_config.cpp:47)
  → BasicGemmOpConfig::InitArgument (gemm_op_config.cpp:92)
  → SafeMul (gemm_op_config.cpp:100)
  → DeviceMemoryManager::MallocDeviceMemory (device_memory_manager.cpp:64)
  → aclrtMalloc (设备 API)
```

**风险**：大数值参数可能导致整数溢出或设备内存耗尽，已有 `SafeMul` 检查

### 路径 3：环境变量 → 设备 ID

```
ASCEND_RT_VISIBLE_DEVICES (环境变量)
  → getenv (profiler.cpp:399)
  → ProfileDataHandler::SetDeviceId (profiler.cpp:395)
  → rtGetVisibleDeviceIdByLogicDeviceId (profiler.cpp:401)
  → deviceId_ (profiler.cpp:408)
  → Profiler::Start (profiler.cpp:180)
  → prof_drv_start (驱动函数)
```

**风险**：环境变量控制设备访问范围，恶意设置可能导致设备访问异常

---

**报告生成时间**：2026-04-21  
**分析工具**：Architecture Agent (自主分析模式)  
**项目版本**：MindStudio Ops Tuner (首次上线 2025.12.30)