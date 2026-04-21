# 漏洞扫描报告 — 已确认漏洞

**项目**: MindStudio-Ops-Common
**扫描时间**: 2026-04-21T04:55:18Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次漏洞扫描针对 MindStudio-Ops-Common 项目进行了深度安全分析，该项目作为动态库(.so)通过 LD_PRELOAD 注入方式运行在开发维测环境中，处理用户算子代码、kernel 二进制文件及各类输入输出数据。扫描共发现 **7 个已确认漏洞**，其中 **2 个 Critical 级别**、**5 个 High 级别**，整体安全风险较高。

**关键发现**：
- **动态库加载漏洞（Critical）**: 两处漏洞均涉及 `dlopen()` 加载用户控制的插件路径，缺乏路径验证和签名校验，攻击者可通过 IPC 配置注入或环境变量控制加载任意共享库，实现进程内任意代码执行。
- **路径遍历漏洞（High）**: kernel_launcher 工具链存在多处路径验证缺失，攻击者可通过配置文件指定任意文件路径，读取系统敏感文件（如 SSH 密钥、密码文件）或加载恶意 kernel 二进制。
- **命令注入漏洞（High）**: SimulatorLauncher 通过环境变量控制执行路径，攻击者控制环境变量可执行任意程序。

**业务影响**：
- 开发维测环境的完整性被破坏，可能影响算子工具链的可信度
- 宿主应用程序进程安全受威胁，敏感数据可能被窃取或篡改
- NPU 设备可能因恶意 kernel 加载而受到安全影响

**建议修复优先级**：
1. **立即修复**: VULN-CORE-001 和 VULN-CORE-003（动态库加载漏洞）—— 添加路径白名单验证和签名校验
2. **短期修复**: VUL-TOOLS-001/002/007（路径遍历漏洞）—— 使用 CheckInputFileValid 进行路径验证
3. **计划修复**: VULN-runtime-001（命令注入）—— 环境变量路径验证

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 17 | 40.5% |
| LIKELY | 16 | 38.1% |
| CONFIRMED | 7 | 16.7% |
| FALSE_POSITIVE | 2 | 4.8% |
| **总计** | **42** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 2 | 28.6% |
| High | 5 | 71.4% |
| **有效漏洞总计** | **7** | - |
| 误报 (FALSE_POSITIVE) | 2 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-CORE-003]** Untrusted Function Pointer Execution (Critical) - `csrc/core/BinaryInstrumentation.cpp:227` @ `CustomDBI::Convert` | 置信度: 90
2. **[VULN-CORE-001]** Unsafe Dynamic Library Loading (Critical) - `csrc/core/BinaryInstrumentation.cpp:260` @ `CustomDBI::SetConfig` | 置信度: 85
3. **[VUL-TOOLS-001]** Path Traversal (High) - `/csrc/tools/kernel_launcher/KernelConfigParser.cpp:109` @ `SetBinPath` | 置信度: 85
4. **[VUL-TOOLS-002]** Path Traversal (High) - `/csrc/tools/kernel_launcher/KernelConfigParser.cpp:157` @ `SetInputPath` | 置信度: 85
5. **[VUL-TOOLS-007]** Arbitrary File Read (High) - `/csrc/tools/kernel_launcher/KernelRunner.cpp:44` @ `Run` | 置信度: 85
6. **[VUL-TOOLS-005]** File Path Injection (High) - `/csrc/tools/kernel_launcher/Launcher.cpp:213` @ `SaveOutputs` | 置信度: 80
7. **[VULN-runtime-001]** Command Injection (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/runtime/inject_helpers/ProfDataCollect.cpp:439` @ `SimulatorLauncher::Launch` | 置信度: 75

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `CustomDBI::SetConfig@csrc/core/BinaryInstrumentation.cpp` | file | semi_trusted | dlopen() 加载用户指定的 pluginPath SO 文件，pluginPath 来自调用方配置，调用方(msOpProf/msSanitizer)需要确保路径安全，但用户可通过环境变量或配置文件间接影响 | 动态加载用户插件 SO 文件 |
| `PipeCall@csrc/utils/PipeCall.cpp` | rpc | semi_trusted | fork() + execvp() 执行外部命令(bisheng-tune、llvm-objdump等)，命令参数来自调用方，调用方需要确保参数安全，但用户提供的 kernel 文件路径可能被传递到命令中 | 执行外部工具命令进行二进制处理 |
| `DomainSocketServer::ListenAndBind@csrc/core/DomainSocket.cpp` | network | semi_trusted | Unix Domain Socket 服务端绑定路径并监听连接，socket 路径由调用方配置，需要在本地有权限才能连接，仅限开发维测环境使用 | IPC 服务端监听客户端连接 |
| `DomainSocketServer::Read@csrc/core/DomainSocket.cpp` | network | semi_trusted | 从 IPC 客户端读取数据，数据来自 msOpProf/msSanitizer 控制进程，需要在本地有 socket 连接权限 | 从 IPC 客户端读取控制数据 |
| `ReadBinary@csrc/utils/FileSystem.cpp` | file | semi_trusted | 读取用户提供的 kernel 二进制文件，文件路径来自调用方配置或用户输入，调用方需要确保路径安全并转换为真实绝对路径 | 读取 kernel 二进制文件 |
| `GetEnv@csrc/utils/FileSystem.cpp` | env | semi_trusted | 读取环境变量(ASCEND_HOME_PATH、SOC_VERSION等)，环境变量由用户或系统设置，调用方文档要求用户确保内容安全可信 | 读取环境变量获取系统配置 |
| `GetAscendHomePath@csrc/utils/Environment.cpp` | env | semi_trusted | 从环境变量获取 ASCEND_HOME_PATH 路径，路径由用户环境设置，用于定位依赖库和工具 | 获取 Ascend 安装路径 |
| `HijackedFuncOfKernelLaunch::Pre@csrc/runtime/HijackedFuncOfKernelLaunch.cpp` | decorator | semi_trusted | 劫持 rtKernelLaunch API，处理用户提供的 kernel 参数(args、argsSize等)，参数来自应用程序调用，应用程序需要确保参数有效 | 劫持 kernel launch API 处理用户参数 |
| `HijackedFuncOfMalloc::Pre@csrc/runtime/HijackedFuncOfMalloc.cpp` | decorator | semi_trusted | 劫持 rtMalloc API，处理用户提供的内存分配请求(size、type等)，参数来自应用程序调用 | 劫持内存分配 API |
| `HijackedFuncOfMemcpy::Pre@csrc/runtime/HijackedFuncOfMemcpy.cpp` | decorator | semi_trusted | 劫持 rtMemcpy API，处理用户提供的内存拷贝请求(src、dst、cnt等)，指针来自应用程序，需确保指针有效 | 劫持内存拷贝 API |
| `HijackedFuncOfAclrtLaunchKernelImpl::Pre@csrc/acl_rt_impl/HijackedFuncOfAclrtLaunchKernelImpl.cpp` | decorator | semi_trusted | 劫持 aclrtLaunchKernel API，处理用户提供的 kernel 启动参数，参数来自应用程序 | 劫持 ACL kernel launch API |

**其他攻击面**:
- 动态库加载: dlopen() 加载用户指定的 plugin SO 文件
- 进程执行: PipeCall() 执行外部命令(bisheng-tune, llvm-objdump, llvm-objcopy, ld.lld)
- IPC 通信: DomainSocket 服务端接受客户端连接并读写数据
- 文件读取: ReadBinary()、ReadFile() 读取用户提供的 kernel 二进制文件
- 环境变量: GetEnv()、GetAscendHomePath()、GetSocVersionFromEnvVar() 读取环境变量
- 劫持 API: 所有 HijackedFunc 类处理来自应用程序的参数和指针
- 内存操作: HijackedFuncOfMalloc、HijackedFuncOfMemcpy、HijackedFuncOfMemset 处理用户内存请求
- IPC 内存: rtIpcSetMemoryName、rtIpcOpenMemory 处理跨进程内存共享

---

## 3. Critical 漏洞 (2)

### [VULN-CORE-003] Untrusted Function Pointer Execution - CustomDBI::Convert

**严重性**: Critical | **CWE**: CWE-822 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `csrc/core/BinaryInstrumentation.cpp:227` @ `CustomDBI::Convert`
**模块**: core
**跨模块**: core,runtime

**描述**: CustomDBI::Convert() invokes initFunc_ function pointer obtained via dlsym(handle_, "MSBitStart") from the loaded plugin. The plugin is loaded from user-provided pluginPath without validation, so arbitrary code can be executed when MSBitStart is called with tempCtrlPath argument.

**漏洞代码** (`csrc/core/BinaryInstrumentation.cpp:227`)

```c
initFunc_(tempCtrlPath.c_str(), tempCtrlPath.length());
```

**达成路径**

[IN] IPC pluginPath -> dlopen() -> dlsym("MSBitStart") -> initFunc_ call(tempCtrlPath) [OUT]

**验证说明**: pluginPath来自IPC客户端，直接控制dlopen加载的插件，通过dlsym获取的函数指针可执行任意代码，调用链完整可达

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 5

**深度分析**

**根因分析**: 漏洞源于两个层面的信任边界违反：(1) IPC 客户端与 Injection Library 之间的信任边界被突破，IPC 配置中的 `pluginPath` 字段未经任何验证直接传递给 `dlopen()`；(2) 动态库加载接口本身缺乏白名单机制或签名校验。项目中虽然存在 `CheckInputFileValid()` 和 `Realpath()` 等路径验证函数，但在 `CustomDBI::SetConfig()` 中完全未使用这些安全措施。

**潜在利用场景**:
1. **环境变量劫持**: 攻击者设置 `MSOPPROF_EXE_PATH_ENV` 环境变量指向攻击者控制的目录，放置恶意共享库并导出 `MSBitStart` 符号，当应用程序使用 msOpProf 工具时，恶意插件被加载执行
2. **IPC 配置注入**: 通过 Domain Socket 发送包含恶意 `pluginPath` 的配置消息，直接加载攻击者准备的任意 `.so` 文件
3. **库构造函数攻击**: 恶意共享库通过 `__attribute__((constructor))` 在 `dlopen()` 时自动执行代码，无需等待 `MSBitStart` 被调用

**建议修复方式**:
- 在 `CustomDBI::SetConfig()` 中调用 `CheckInputFileValid()` 验证路径
- 使用 `Realpath()` 解析真实路径并检查是否在白名单目录（如 `{ASCEND_HOME_PATH}/lib64`）下
- 实现插件签名验证机制，拒绝未签名或签名无效的插件
- 在 IPC 配置接收端增加路径验证逻辑

---

### [VULN-CORE-001] Unsafe Dynamic Library Loading - CustomDBI::SetConfig

**严重性**: Critical | **CWE**: CWE-114 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-module-scanner, security-auditor

**位置**: `csrc/core/BinaryInstrumentation.cpp:260` @ `CustomDBI::SetConfig`
**模块**: core
**跨模块**: core,runtime,bind

**描述**: CustomDBI::SetConfig() calls dlopen() with pluginPath directly without path validation. pluginPath originates from external IPC client via ConfigManager.cpp which receives SanitizerConfig including pluginPath field. No CheckInputFileValid() or Realpath() is applied before dlopen, allowing potential loading of arbitrary shared libraries.

**漏洞代码** (`csrc/core/BinaryInstrumentation.cpp:260`)

```c
handle_ = dlopen(pluginPath.c_str(), RTLD_LAZY);
```

**达成路径**

[IN] IPC Client (ConfigManager.cpp:pluginPath) -> DBITaskConfig::pluginPath_ -> CustomDBI::SetConfig::config.pluginPath -> dlopen() [OUT]

**验证说明**: pluginPath来自IPC客户端ConfigManager，无路径验证直接传给dlopen，可加载任意共享库，双来源确认(dataflow+security)

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: `pluginPath` 数据流完整追踪显示其来源有两个：(1) IPC 客户端配置通过 `ConfigManager.cpp` 接收的 `SanitizerConfig.pluginPath` 字段；(2) 环境变量 `MSOPPROF_EXE_PATH_ENV` 通过 `ProfConfig::GetMsopprofPath()` 获取后拼接形成。这两个来源均为"semi_trusted"级别，但在传递到 `dlopen()` 的整个路径中没有任何验证节点。对比项目中其他字段的处理（如 `SetKernelName()` 使用 `CheckInputStringValid()`），`SetConfig()` 对路径的处理存在明显安全缺失。

**潜在利用场景**:
1. **路径遍历加载**: 通过 IPC 发送 `pluginPath="../../../tmp/malicious.so"` 或绝对路径 `/tmp/malicious.so`，绕过预期目录限制
2. **符号链接攻击**: 创建符号链接 `ln -s /tmp/malicious.so /usr/local/ascend/lib64/libprofplugin_xxx.so`，程序加载"合法路径"但实际执行恶意代码
3. **库注入攻击**: 恶意库通过构造函数在 `dlopen()` 加载时立即执行，无需等待任何业务函数调用
4. **运行时替换**: 在插件加载后替换原始文件，后续调用可能加载恶意版本

**建议修复方式**:
- 实现 `ValidatePluginPath()` 函数，检查路径是否在 `{ASCEND_HOME_PATH}/lib64` 等白名单目录下
- 使用 `CheckInputFileValid()` 检查路径遍历字符，使用 `Realpath()` 解析真实路径
- 在 `ProfConfig::GetMsopprofPath()` 中增加环境变量路径验证
- 添加审计日志记录所有插件加载操作

---

## 4. High 漏洞 (5)

### [VUL-TOOLS-001] Path Traversal - SetBinPath

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/csrc/tools/kernel_launcher/KernelConfigParser.cpp:109-113` @ `SetBinPath`
**模块**: tools

**描述**: SetBinPath accepts arbitrary file path from configuration without validation. The binary path is directly assigned without checking for path traversal characters, symlinks, or permission validation. This could allow loading malicious kernel binaries from arbitrary locations.

**漏洞代码** (`/csrc/tools/kernel_launcher/KernelConfigParser.cpp:109-113`)

```c
kernelConfig_.kernelBinaryPath = arg;
```

**达成路径**

[IN] config.json::bin_path -> SetBinPath() -> kernelConfig_.kernelBinaryPath -> [OUT] Launcher::RegisterKernel()/KernelRunner::RegisterKernel()

**验证说明**: config.json的bin_path直接赋值给kernelBinaryPath，无路径验证可加载任意位置的恶意kernel

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: 对比 `KernelConfigParser.cpp` 中不同字段的处理方式，`SetKernelName()` 函数调用 `CheckInputStringValid()` 进行验证，而 `SetBinPath()` 直接赋值无任何验证。这种不一致的安全处理模式暴露了代码审查中的遗漏。`bin_path` 字段来自外部配置文件 `config.json`，属于不可信来源，但被直接用于 `ReadBinary()` 读取文件内容，形成完整的路径遍历攻击链。

**潜在利用场景**:
1. **敏感文件读取**: 配置 `bin_path="../../../etc/passwd"` 或 `bin_path="/etc/shadow"`，读取系统密码文件或敏感配置
2. **SSH 密钥窃取**: 配置 `bin_path="/home/admin/.ssh/id_rsa"`，读取用户私钥导致服务器被入侵
3. **恶意 kernel 加载**: 配置 `bin_path="/tmp/malicious_kernel.bin"`，加载攻击者准备的恶意二进制影响 NPU 安全
4. **符号链接攻击**: 创建 `ln -s /etc/shadow kernel.bin`，通过符号链接读取敏感文件
5. **进程信息泄露**: 配置 `bin_path="/proc/self/environ"`，读取进程环境变量中的敏感信息

**建议修复方式**:
- 在 `SetBinPath()` 中调用 `CheckInputFileValid()` 验证路径有效性
- 使用 `Realpath()` 解析真实路径并存储
- 增加白名单目录检查，只允许从预定义可信目录加载 kernel
- 验证文件类型（检查魔数或格式）确保为有效 kernel 二进制

---

### [VUL-TOOLS-002] Path Traversal - SetInputPath

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/csrc/tools/kernel_launcher/KernelConfigParser.cpp:157-181` @ `SetInputPath`
**模块**: tools

**描述**: SetInputPath directly uses paths from configuration without calling CheckInputFileValid. Input paths are split and stored without symlink check, path canonicalization, or permission validation. Attacker can read arbitrary files by manipulating input_path field in config.

**漏洞代码** (`/csrc/tools/kernel_launcher/KernelConfigParser.cpp:157-181`)

```c
param.dataPath = binPath;
```

**达成路径**

[IN] config.json::input_path -> SetInputPath() -> kernelConfig_.params[].dataPath -> [OUT] Launcher::InitInput()/KernelRunner::InitInput() -> ReadFile()

**验证说明**: config.json的input_path直接使用无验证，可读取任意文件内容

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: `SetInputPath()` 与 `SetBinPath()` 存在相同的根本原因：缺少路径验证。但 `SetInputPath()` 的危害更大，因为它支持多路径输入（通过 `;` 分隔），攻击者可批量窃取多个敏感文件。数据流追踪显示：`input_path` → `SplitString()` → `param.dataPath` → `Launcher::InitInput()` → `ReadFile()`，整个链条无任何验证节点。项目中有现成的 `CheckInputFileValid()` 函数可用于验证，但未被调用。

**潜在利用场景**:
1. **批量敏感文件窃取**: 配置 `input_path="/etc/passwd;/home/admin/.ssh/id_rsa;/var/log/auth.log"`，一次性读取多个敏感文件
2. **路径遍历组合攻击**: 配置 `input_path="../../../etc/shadow;../../../root/.bash_history"`，遍历上层目录批量窃取
3. **进程信息批量泄露**: 配置 `input_path="/proc/self/environ;/proc/self/cmdline;/proc/self/maps"`，获取进程完整环境信息
4. **符号链接批量攻击**: 创建多个符号链接指向不同敏感文件，通过 `input_path` 批量读取
5. **配置文件窃取**: 配置 `input_path="/etc/mysql/debian.cnf;/etc/apache2/apache2.conf"`，窃取服务配置中的密码

**建议修复方式**:
- 对分割后的每个路径调用 `CheckInputFileValid()` 验证
- 使用 `Realpath()` 解析真实路径，检查是否在白名单目录
- 限制单个文件大小（添加 `MAX_INPUT_FILE_SIZE` 检查），防止资源耗尽
- 创建统一的 `ValidateAndResolvePath()` 辅助函数，减少代码重复
- 与 `SetBinPath()` 共用相同的验证逻辑，保持安全处理一致性

---

### [VUL-TOOLS-007] Arbitrary File Read - Run

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/csrc/tools/kernel_launcher/KernelRunner.cpp:44-50` @ `Run`
**模块**: tools

**描述**: KernelRunner RegisterKernel loads kernel binary from user-controlled path without path validation.

**漏洞代码** (`/csrc/tools/kernel_launcher/KernelRunner.cpp:44-50`)

```c
ReadBinary(kernelConfig.kernelBinaryPath, bin)
```

**达成路径**

[IN] config.json::bin_path -> kernelBinaryPath -> [OUT] RegisterKernel()

**验证说明**: kernelBinaryPath无验证直接用于ReadBinary，可加载任意文件内容

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**: 此漏洞与 VUL-TOOLS-001 同源但处于不同层次：VUL-TOOLS-001 在配置解析阶段（存储层面）缺失验证，VUL-TOOLS-007 在运行阶段（使用层面）直接消费未验证的路径。两者形成完整漏洞链：`config.json` → `SetBinPath()`（无验证存储）→ `kernelBinaryPath` → `KernelRunner::Run()` → `ReadBinary()`（无验证读取）。修复任一处都不能完全解决问题，需要同时修复上下游。

**潜在利用场景**:
1. **系统敏感文件读取**: `bin_path="/etc/shadow"` 读取密码文件，内容被加载到进程内存
2. **用户密钥窃取**: `bin_path="/home/admin/.ssh/id_rsa"` 获取 SSH 私钥
3. **历史命令泄露**: `bin_path="../../../root/.bash_history"` 可能包含敏感密码或路径
4. **/proc 文件系统攻击**: `bin_path="/proc/self/environ"` 读取进程环境变量中的密码或配置
5. **联动攻击**: 与 VUL-TOOLS-001 配合，攻击者先绕过配置验证，再在 KernelRunner 中读取任意文件

**建议修复方式**:
- 在 `KernelRunner::Run()` 使用路径前调用 `CheckInputFileValid()` 进行二次验证（防御性编程）
- 使用 `Realpath()` 解析真实路径，检查是否在 `{ASCEND_HOME_PATH}/kernel` 等白名单目录
- 在 `KernelConfig` 结构中增加 `kernelBinaryPathValidated` 标志，确保路径已被上游验证
- 验证文件大小范围（`MIN_KERNEL_SIZE` ~ `MAX_KERNEL_SIZE`）和文件格式（魔数检查）
- 同时修复 VUL-TOOLS-001，在配置解析阶段进行首次验证

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| core | 2 | 0 | 0 | 0 | 2 |
| runtime | 0 | 1 | 0 | 0 | 1 |
| tools | 0 | 4 | 0 | 0 | 4 |
| **合计** | **2** | **5** | **0** | **0** | **7** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 3 | 42.9% |
| CWE-822 | 1 | 14.3% |
| CWE-78 | 1 | 14.3% |
| CWE-73 | 1 | 14.3% |
| CWE-114 | 1 | 14.3% |

---

## 7. 修复建议

### 优先级 1: 立即修复（Critical 漏洞）

#### VULN-CORE-001 & VULN-CORE-003: 动态库加载漏洞

**影响**: 允许加载任意共享库，实现进程内任意代码执行，风险等级最高。

**修复方案**:

```cpp
// csrc/core/BinaryInstrumentation.cpp
bool CustomDBI::SetConfig(const Config& config) {
    const std::string& pluginPath = config.pluginPath;
    
    // 1. 基本验证
    if (pluginPath.empty() || config.archName.empty()) {
        return false;
    }
    
    // 2. 调用已有的路径验证函数
    if (!CheckInputFileValid(pluginPath)) {
        ERROR_LOG("Plugin path contains traversal characters: %s", pluginPath.c_str());
        return false;
    }
    
    // 3. 解析真实路径（处理符号链接）
    std::string realPath;
    if (!Realpath(pluginPath, realPath)) {
        ERROR_LOG("Cannot resolve plugin path: %s", pluginPath.c_str());
        return false;
    }
    
    // 4. 白名单目录检查
    std::string ascendHomePath;
    if (!GetAscendHomePath(ascendHomePath)) {
        ERROR_LOG("Cannot get ASCEND_HOME_PATH");
        return false;
    }
    std::string allowedDir = JoinPath({ascendHomePath, "lib64"});
    if (realPath.find(allowedDir) != 0) {
        ERROR_LOG("Plugin outside allowed directory: %s", realPath.c_str());
        return false;
    }
    
    // 5. 文件权限检查（可选）
    struct stat st;
    if (stat(realPath.c_str(), &st) == 0) {
        if (st.st_mode & (S_IWOTH | S_IWGRP)) {
            WARN_LOG("Plugin has insecure permissions: %s", realPath.c_str());
        }
    }
    
    handle_ = dlopen(realPath.c_str(), RTLD_LAZY);
    // ...
}
```

**同时修复环境变量验证**:

```cpp
// csrc/runtime/inject_helpers/ProfConfig.cpp
std::string ProfConfig::GetMsopprofPath() const {
    std::string path = GetEnv(MSOPPROF_EXE_PATH_ENV);
    if (!path.empty()) {
        std::string realPath;
        if (!Realpath(path, realPath)) {
            WARN_LOG("Invalid MSOPPROF path from env");
            return "";
        }
        std::string ascendHome;
        if (GetAscendHomePath(ascendHome) && realPath.find(ascendHome) != 0) {
            WARN_LOG("MSOPPROF path outside ASCEND_HOME");
            return "";
        }
        return realPath;
    }
    // ...
}
```

### 优先级 2: 短期修复（High 漏洞）

#### VUL-TOOLS-001/002/007: 路径遍历漏洞链

**影响**: 可读取任意文件，窃取敏感信息，加载恶意 kernel。

**修复方案**（统一验证函数）:

```cpp
// csrc/tools/kernel_launcher/KernelConfigParser.cpp
bool KernelConfigParser::ValidatePath(const std::string& path, std::string& resolvedPath) {
    if (path.empty()) return false;
    
    // 使用已有验证函数
    if (!CheckInputFileValid(path)) {
        return false;
    }
    
    // 解析真实路径
    if (!Realpath(path, resolvedPath)) {
        return false;
    }
    
    return true;
}

bool KernelConfigParser::SetBinPath(const std::string& arg) {
    std::string resolvedPath;
    if (!ValidatePath(arg, resolvedPath)) {
        ERROR_LOG("Invalid binary path: %s", arg.c_str());
        return false;
    }
    kernelConfig_.kernelBinaryPath = resolvedPath;
    return true;
}

bool KernelConfigParser::SetInputPath(const std::string& arg) {
    std::vector<std::string> paths;
    SplitString(arg, ';', paths);
    
    for (const auto& p : paths) {
        if (p == "n") {
            // 空输入标记，跳过验证
            kernelConfig_.params.push_back(Param{"input", "int8", "n", false});
            continue;
        }
        
        std::string resolvedPath;
        if (!ValidatePath(p, resolvedPath)) {
            ERROR_LOG("Invalid input path: %s", p.c_str());
            return false;
        }
        kernelConfig_.params.push_back(Param{"input", "int8", resolvedPath, true});
    }
    return true;
}
```

**KernelRunner 增加防御性验证**:

```cpp
// csrc/tools/kernel_launcher/KernelRunner.cpp
bool KernelRunner::Run(const KernelConfig& kernelConfig) {
    // 二次验证路径（防御性编程）
    std::string safePath;
    if (!Realpath(kernelConfig.kernelBinaryPath, safePath)) {
        ERROR_LOG("Cannot resolve kernel path");
        return false;
    }
    
    // 文件大小检查
    size_t fileSize = GetFileSize(safePath);
    if (fileSize == 0 || fileSize > MAX_KERNEL_SIZE) {
        ERROR_LOG("Invalid kernel size: %zu", fileSize);
        return false;
    }
    
    std::vector<char> bin;
    if (ReadBinary(safePath, bin) == 0) {
        ERROR_LOG("Read kernel failed");
        return false;
    }
    // ...
}
```

#### VULN-runtime-001: 命令注入漏洞

**修复方案**:

```cpp
// csrc/runtime/inject_helpers/ProfDataCollect.cpp
std::string ProfConfig::GetMsopprofPath() const {
    std::string path = GetEnv(MSOPPROF_EXE_PATH_ENV);
    if (!path.empty()) {
        // 验证路径
        std::string realPath;
        if (!Realpath(path, realPath)) {
            WARN_LOG("Invalid MSOPPROF path");
            return "";
        }
        
        // 白名单检查
        std::string ascendHome;
        if (GetAscendHomePath(ascendHome)) {
            if (realPath.find(ascendHome) != 0) {
                WARN_LOG("Executable outside ASCEND_HOME");
                return "";
            }
        }
        return realPath;
    }
    // 默认路径（可信）
    return GetDefaultMsopprofPath();
}
```

### 优先级 3: 计划修复（长期改进）

1. **插件签名机制**: 所有官方插件必须签名，加载前验证签名有效性
2. **审计日志**: 记录所有插件加载、文件读取操作，便于安全审计
3. **配置来源验证**: 验证 `config.json` 来源是否可信
4. **SELinux/AppArmor**: 使用安全机制限制插件加载和文件访问范围
5. **文档安全要求**: 在用户文档中明确说明安全配置要求（环境变量、配置文件）

### 测试验证清单

| 漏洞 | 测试项 | 预期结果 |
|------|--------|----------|
| VULN-CORE-001 | `pluginPath="../../../tmp/evil.so"` | 拒绝 |
| VULN-CORE-001 | `pluginPath="/tmp/evil.so"` | 拒绝（非白名单目录） |
| VULN-CORE-001 | 符号链接攻击 | 解析真实路径并拒绝 |
| VUL-TOOLS-001 | `bin_path="../../../etc/passwd"` | 拒绝 |
| VUL-TOOLS-002 | `input_path="/etc/shadow;../.."` | 拒绝 |
| VUL-TOOLS-007 | `bin_path="/proc/self/environ"` | 拒绝 |
| VULN-runtime-001 | 环境变量注入恶意路径 | 拒绝（非白名单目录） |

---

**报告生成时间**: 2026-04-21  
**分析工具**: MindStudio-Ops-Common 多 Agent 漏洞扫描系统
