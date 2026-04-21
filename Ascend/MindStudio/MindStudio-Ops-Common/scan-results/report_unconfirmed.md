# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-Ops-Common
**扫描时间**: 2026-04-21T04:55:18Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| High | 7 | 23.3% |
| Medium | 17 | 56.7% |
| Low | 6 | 20.0% |
| **有效漏洞总计** | **30** | - |
| 误报 (FALSE_POSITIVE) | 2 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-CORE-002]** Process Execution with File Path Arguments (High) - `csrc/core/BinaryInstrumentation.cpp:98` @ `BBCountDBI::Convert, PGODBI::Convert, CustomDBI::Convert` | 置信度: 65
2. **[acl_rt_impl-004]** Out-of-bounds Access (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtBinaryLoadFromDataImpl.cpp:44` @ `Post` | 置信度: 60
3. **[VULN-CORE-006]** Library Loading Path Resolution Mismatch (High) - `csrc/core/FunctionLoader.cpp:52` @ `FunctionLoader::Get` | 置信度: 55
4. **[bind-init-race-001]** Race Condition (High) - `csrc/bind/BindSanitizer.cpp:37` @ `HijackedCtor` | 置信度: 50
5. **[bind-init-race-002]** Race Condition (High) - `csrc/bind/BindOpprof.cpp:44` @ `HijackedCtor` | 置信度: 50
6. **[acl_rt_impl-001]** Memory Corruption (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtLaunchKernelImpl.cpp:69` @ `InitParam` | 置信度: 50
7. **[acl_rt_impl-003]** Out-of-bounds Access (High) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtLaunchKernelWithHostArgsImpl.cpp:67` @ `InitParam` | 置信度: 50
8. **[VUL-TOOLS-003]** Path Traversal (Medium) - `/csrc/tools/kernel_launcher/KernelConfigParser.cpp:261` @ `SetOutputDir` | 置信度: 75
9. **[VUL-TOOLS-004]** Path Traversal (Medium) - `/csrc/tools/kernel_launcher/KernelConfigParser.cpp:287` @ `SetTilingDataPath` | 置信度: 75
10. **[VUL-TOOLS-009]** Path Traversal (Medium) - `/csrc/tools/kernel_launcher/Launcher.cpp:46` @ `GenJson` | 置信度: 70

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

## 3. High 漏洞 (7)

### [VULN-CORE-002] Process Execution with File Path Arguments - BBCountDBI::Convert, PGODBI::Convert, CustomDBI::Convert

**严重性**: High | **CWE**: CWE-78 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `csrc/core/BinaryInstrumentation.cpp:98-247` @ `BBCountDBI::Convert, PGODBI::Convert, CustomDBI::Convert`
**模块**: core
**跨模块**: core,utils,runtime

**描述**: Multiple Convert() methods (BBCountDBI::Convert, PGODBI::Convert, CustomDBI::Convert) call PipeCall() with kernel file paths as arguments to external tools (bisheng-tune, llvm-objdump, llvm-objcopy, ld.lld). While execvp() is used instead of shell execution, file paths containing special characters or traversal sequences may cause unexpected behavior. The paths originate from user kernel files stored in tmpDir.

**漏洞代码** (`csrc/core/BinaryInstrumentation.cpp:98-247`)

```c
if (!PipeCall(args, output)) { ... }
```

**达成路径**

[IN] LaunchContext::oldKernelFile -> BinaryInstrumentation::Convert::oldKernelFile -> PipeCall::args -> execvp() [OUT]

**验证说明**: 用户kernel文件路径通过PipeCall传给外部工具，使用execvp而非shell执行缓解了注入风险，但路径仍可被工具特殊解析

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [acl_rt_impl-004] Out-of-bounds Access - Post

**严重性**: High | **CWE**: CWE-125 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtBinaryLoadFromDataImpl.cpp:44-54` @ `Post`
**模块**: acl_rt_impl

**描述**: Binary load options array accessed without bounds validation. Loop iterates options_->numOpt without verifying that numOpt does not exceed the actual size of options array, potentially causing out-of-bounds read when accessing options_->options[i].

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtBinaryLoadFromDataImpl.cpp:44-54`)

```c
for (size_t i = 0; i < options_->numOpt; i++) { if (options_->options[i].type == ACL_RT_BINARY_LOAD_OPT_MAGIC ... }
```

**达成路径**

[IN] options (user binary load options) -> magic value extraction

**验证说明**: options_->numOpt未验证是否超出options数组实际大小，循环访问可能越界

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CORE-006] Library Loading Path Resolution Mismatch - FunctionLoader::Get

**严重性**: High | **CWE**: CWE-114 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `csrc/core/FunctionLoader.cpp:52` @ `FunctionLoader::Get`
**模块**: core

**描述**: FunctionLoader::Get() constructs fileName as "lib" + name + ".so", checks validity via GetSoFromEnvVar() + CheckInputFileValid(), but then calls dlopen(fileName.c_str()) using the ORIGINAL fileName (not the resolved Realpath). This allows dlopen to potentially load a different file than what was validated if LD_LIBRARY_PATH contains symlinks.

**漏洞代码** (`csrc/core/FunctionLoader.cpp:52`)

```c
auto hdl = dlopen(this->fileName.c_str(), RTLD_LAZY);
```

**达成路径**

[IN] FunctionLoader::name -> fileName -> GetSoFromEnvVar -> CheckInputFileValid -> dlopen(fileName) [OUT]

**验证说明**: 有CheckInputFileValid验证但验证后使用原始fileName而非Realpath，存在验证与实际使用路径不一致的风险

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [bind-init-race-001] Race Condition - HijackedCtor

**严重性**: High | **CWE**: CWE-367 | **置信度**: 50/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `csrc/bind/BindSanitizer.cpp:37-117` @ `HijackedCtor`
**模块**: bind
**跨模块**: core,runtime,ascendcl

**描述**: HijackedCtor() 使用非原子全局变量 g_isCtorDone 作为初始化完成标志，多个劫持函数在检测到未完成时调用 HijackedCtor()，可能导致多线程场景下的重复初始化或竞态条件。作为 LD_PRELOAD 库的 constructor，在程序启动阶段可能被多个线程同时访问

**漏洞代码** (`csrc/bind/BindSanitizer.cpp:37-117`)

```c
static bool g_isCtorDone = false;\nvoid __attribute__ ((constructor)) HijackedCtor() { ... g_isCtorDone = true; }\n// rtDevBinaryRegister, rtRegisterAllKernel, AdumpGetDFXInfoAddrForDynamic 检查 g_isCtorDone 并可能重复调用 HijackedCtor
```

**达成路径**

[IN] LD_PRELOAD injection -> HijackedCtor() [OUT] -> runtime/RuntimeOriginCtor() [OUT] -> ascendcl/AscendclOriginCtor() [OUT] -> core/FuncSelector

**验证说明**: 非原子g_isCtorDone存在竞态风险，但实际场景取决于程序启动阶段的多线程访问

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [bind-init-race-002] Race Condition - HijackedCtor

**严重性**: High | **CWE**: CWE-367 | **置信度**: 50/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `csrc/bind/BindOpprof.cpp:44-181` @ `HijackedCtor`
**模块**: bind
**跨模块**: core,runtime,hccl,camodel,profapi

**描述**: BindOpprof.cpp中HijackedCtor使用非原子g_isCtorDone,多函数检查并可能重复调用HijackedCtor存在竞态

**漏洞代码** (`csrc/bind/BindOpprof.cpp:44-181`)

```c
static bool g_isCtorDone = false; g_isCtorDone = true; 多函数检查并调用
```

**达成路径**

[IN]LD_PRELOAD->HijackedCtor[OUT]->runtime/RuntimeOriginCtor[OUT]->hccl/HcclOriginCtor[OUT]->camodel/CamodelCtor

**验证说明**: 与bind-init-race-001相同问题，BindOpprof.cpp中的非原子g_isCtorDone存在竞态

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [acl_rt_impl-001] Memory Corruption - InitParam

**严重性**: High | **CWE**: CWE-787 | **置信度**: 50/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtLaunchKernelImpl.cpp:69-70` @ `InitParam`
**模块**: acl_rt_impl

**描述**: Kernel args data pointer used without null validation before CreateContext. The argsData parameter is cast with const_cast<void*> and passed directly to ArgsManager::CreateContext without null check, potentially leading to null pointer dereference or memory corruption when creating args context.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtLaunchKernelImpl.cpp:69-70`)

```c
argsCtx_ = ArgsManager::Instance().CreateContext(const_cast<void *>(argsData), argsSize, true);
```

**达成路径**

[IN] argsData (user-provided kernel args) -> argsCtx_ (ArgsContext creation)

**验证说明**: argsData未验证null直接传给CreateContext，实际取决于ACL API调用方是否保证参数有效

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [acl_rt_impl-003] Out-of-bounds Access - InitParam

**严重性**: High | **CWE**: CWE-125 | **置信度**: 50/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtLaunchKernelWithHostArgsImpl.cpp:67-72` @ `InitParam`
**模块**: acl_rt_impl

**描述**: PlaceHolder array accessed without bounds validation. The loop iterates over placeHolderNum without checking if placeHolderArray is nullptr or if placeHolderNum exceeds actual array size, potentially causing buffer overflow or null pointer dereference.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtLaunchKernelWithHostArgsImpl.cpp:67-72`)

```c
if (placeHolderArray) { placeHolderArray_.resize(placeHolderNum); for (size_t i = 0; i < placeHolderNum; i++) { placeHolderArray_[i].addrOffset = placeHolderArray[i].addrOffset; ... } }
```

**达成路径**

[IN] placeHolderArray, placeHolderNum (user params) -> placeHolderArray_ (internal vector)

**验证说明**: 有placeHolderArray null检查但placeHolderNum未与实际数组大小比较，存在越界风险

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (17)

### [VUL-TOOLS-003] Path Traversal - SetOutputDir

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/csrc/tools/kernel_launcher/KernelConfigParser.cpp:261-264` @ `SetOutputDir`
**模块**: tools

**描述**: SetOutputDir accepts arbitrary directory path from configuration without validation. The output directory path is directly stored and later used for writing kernel execution results. No check for path traversal or write permission validation.

**漏洞代码** (`/csrc/tools/kernel_launcher/KernelConfigParser.cpp:261-264`)

```c
kernelConfig_.outputDir = arg;
```

**达成路径**

[IN] config.json::output_dir -> SetOutputDir() -> kernelConfig_.outputDir -> [OUT] Launcher::SaveOutputs()/KernelRunner::SaveOutputs() -> WriteBinary()

**验证说明**: output_dir无验证直接存储，用于WriteBinary写入文件，路径遍历风险

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VUL-TOOLS-004] Path Traversal - SetTilingDataPath

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/csrc/tools/kernel_launcher/KernelConfigParser.cpp:287-307` @ `SetTilingDataPath`
**模块**: tools

**描述**: SetTilingDataPath directly uses path from configuration without validation. The tiling data path from split result is stored in param.dataPath without safety checks. Attacker can specify arbitrary file path for tiling data.

**漏洞代码** (`/csrc/tools/kernel_launcher/KernelConfigParser.cpp:287-307`)

```c
param.dataPath = sizeVec[0];
```

**达成路径**

[IN] config.json::tiling_data_path -> SetTilingDataPath() -> kernelConfig_.params[].dataPath -> [OUT] Launcher::InitTiling()/KernelRunner::InitTiling() -> ReadFile()

**验证说明**: tiling_data_path无验证直接存储，用于ReadFile读取文件

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VUL-TOOLS-009] Path Traversal - GenJson

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/csrc/tools/kernel_launcher/Launcher.cpp:46-52` @ `GenJson`
**模块**: tools
**跨模块**: utils

**描述**: GenJson constructs JSON file path from kernelBinaryPath. Derived path may be manipulated if kernelBinaryPath contains path traversal sequences.

**漏洞代码** (`/csrc/tools/kernel_launcher/Launcher.cpp:46-52`)

```c
jsonFilePath = kernelBinaryPath.substr(0, dotPos) + .json
```

**达成路径**

[IN] config.json::bin_path -> kernelBinaryPath -> [OUT] GenJson() -> jsonFilePath

**验证说明**: 从kernelBinaryPath派生JSON路径，继承路径遍历风险但为派生路径

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VUL-TOOLS-011] Incomplete Input Validation - SetOutputName

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/csrc/tools/kernel_launcher/KernelConfigParser.cpp:273-284` @ `SetOutputName`
**模块**: tools

**描述**: SetOutputName accepts arbitrary names without CheckInputStringValid. Output names directly stored and used in path construction. No validation for /, .., or control characters.

**漏洞代码** (`/csrc/tools/kernel_launcher/KernelConfigParser.cpp:273-284`)

```c
param.name = nameVec[i]
```

**达成路径**

[IN] config.json::output_name -> SetOutputName() -> params[].name -> [OUT] SaveOutputs()

**验证说明**: output_name无验证可包含特殊字符，在路径构造中可能造成问题

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [bind-env-injection-001] Configuration Injection - HijackedCtor

**严重性**: Medium | **CWE**: CWE-15 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `csrc/bind/BindOpprof.cpp:116-122` @ `HijackedCtor`
**模块**: bind

**描述**: HijackedCtor读取环境变量IS_SIMULATOR_ENV和DEVICE_PROF_DUMP_PATH_ENV决定运行模式和路径

**漏洞代码** (`csrc/bind/BindOpprof.cpp:116-122`)

```c
GetEnv(IS_SIMULATOR_ENV); BBCountDumper::Init(GetEnv(DEVICE_PROF_DUMP_PATH_ENV))
```

**达成路径**

[IN]UserEnv->HijackedCtor[OUT]->RuntimeConfig[OUT]->BBCountDumper

**验证说明**: 环境变量IS_SIMULATOR_ENV和DEVICE_PROF_DUMP_PATH_ENV控制运行模式和路径，攻击者控制环境可影响行为

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-runtime-004] Path Injection - DataCollect::DataCollect

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/runtime/inject_helpers/ProfDataCollect.cpp:418-424` @ `DataCollect::DataCollect`
**模块**: runtime
**跨模块**: runtime,utils

**描述**: Environment variable controlled paths used for file operations without proper path validation/sanitization. Multiple GetEnv() calls retrieve paths used for file operations. An attacker controlling these environment variables could perform path traversal attacks or write to arbitrary locations.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/runtime/inject_helpers/ProfDataCollect.cpp:418-424`)

```c
outputPath_ = GetEnv(MSOPPROF_OUTPUT_DUMP_PATH_ENV);\n...\nif (!outputPath_.empty() && !MkdirRecusively(outputPath_))
```

**达成路径**

[IN] Environment Variable: MSOPPROF_OUTPUT_DUMP_PATH_ENV -> outputPath_ -> MkdirRecusively/WriteStringToFile

**验证说明**: 环境变量控制outputPath用于MkdirRecusively和WriteStringToFile，可进行路径遍历攻击，但需控制环境变量

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [bind-domain-input-001] Missing Input Validation - MstxDomainCreateA

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `csrc/bind/BindSanitizer.cpp:311-314` @ `MstxDomainCreateA`
**模块**: bind

**描述**: MstxDomainCreateA未验证domainName参数

**漏洞代码** (`csrc/bind/BindSanitizer.cpp:311-314`)

```c
return MsTx::Instance().MstxDomainCreateA(std::string(domainName))
```

**达成路径**

[IN]User->MstxDomainCreateA[OUT]->MsTx

**验证说明**: domainName参数未验证直接传给MsTx，可能造成功能异常但非直接安全漏洞

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-003] Command Argument Injection - CustomDBI::GenerateOrderingFile/GenerateTempProbe/Convert

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/core/BinaryInstrumentation.cpp:135-247` @ `CustomDBI::GenerateOrderingFile/GenerateTempProbe/Convert`
**模块**: core

**描述**: BinaryInstrumentation.cpp 多处将用户文件路径作为命令参数传递给外部工具（bisheng-tune、llvm-objdump、llvm-objcopy、ld.lld）。虽然使用 execvp 不通过 shell，但文件路径可能被工具特殊解析。例如 oldKernelFile、pluginPath 等未经过充分验证即传递给工具。

**漏洞代码** (`csrc/core/BinaryInstrumentation.cpp:135-247`)

```c
args = { "llvm-objdump", "--syms", kernelFile }; PipeCall(args, output);
```

**达成路径**

oldKernelFile/pluginPath(调用方) -> PipeCall args -> execvp(外部工具)

**验证说明**: 与VULN-CORE-002相同路径，execvp缓解shell注入但工具可能特殊解析路径

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [bind-sanitizer-report-001] Missing Input Validation - __sanitizer_report_malloc

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `csrc/bind/BindSanitizer.cpp:521-538` @ `__sanitizer_report_malloc`
**模块**: bind

**描述**: __sanitizer_report_malloc/report_free未验证ptr有效性

**漏洞代码** (`csrc/bind/BindSanitizer.cpp:521-538`)

```c
extern C visibility(default) __sanitizer_report_malloc(void *ptr)
```

**达成路径**

[IN]External->report_malloc[OUT]->ReportMalloc

**验证说明**: ptr参数未验证，实际风险取决于调用方传入的指针有效性

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-001] Buffer Over-read - ElfLoader::FromBuffer

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 50/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/utils/ElfLoader.cpp:210-211` @ `ElfLoader::FromBuffer`
**模块**: utils

**描述**: ElfLoader.cpp 第 210 行构造 sectionName 时未检查 sh_name 是否在 nameBuffer 范围内。恶意构造的 ELF 文件可能使 sh_name 超出 nameBuffer 边界，导致越界读取。虽然 ELF 文件头已校验，但 sh_name 字段未与 nameBuffer.sh_size 进行边界检查。

**漏洞代码** (`csrc/utils/ElfLoader.cpp:210-211`)

```c
std::string sectionName = std::string{nameBuffer.data() + sectionHeader.sh_name};
```

**达成路径**

buffer_(用户ELF文件) -> ReadArrayFromBuffer(nameBuffer) -> sectionHeader.sh_name(未校验索引) -> nameBuffer.data() + sh_name(可能越界)

**验证说明**: 恶意构造的ELF文件可使sh_name超出nameBuffer边界，虽有ELF头校验但sh_name字段未与nameBuffer.sh_size比较

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [acl_rt_impl-002] Integer Overflow - Pre

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtMemcpy2dImpl.cpp:44-57` @ `Pre`
**模块**: acl_rt_impl

**描述**: Potential integer overflow in 2D memory copy loop calculation. The expression r * dpitch and r * spitch could overflow when height is large (even after truncation to MAX_MEMORY_RECORD_HEIGHT), leading to incorrect address calculation and potential memory access violation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtMemcpy2dImpl.cpp:44-57`)

```c
for (size_t r = 0; r < height; ++r) { ... dstAddr + static_cast<uint64_t>(r * dpitch) ... }
```

**达成路径**

[IN] height, dpitch, spitch (user params) -> address calculation

**验证说明**: 有MAX_MEMORY_RECORD_HEIGHT截断但r*dpitch表达式可能整数溢出导致地址计算错误

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [acl_rt_impl-005] Buffer Overflow - Post

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtIpcMemGetExportKeyImpl.cpp:52-64` @ `Post`
**模块**: acl_rt_impl

**描述**: IPC memory key copied without proper length validation. The std::copy_n copies key_ to record.setInfo.name using length derived from GetValidLength, but the destination buffer size may not match the copied length if len_ parameter exceeds sizeof(IPCMemorySetInfo::name).

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtIpcMemGetExportKeyImpl.cpp:52-64`)

```c
uint64_t length = GetValidLength(key_, std::min<uint64_t>(len_, sizeof(IPCMemorySetInfo::name))); std::copy_n(key_, length, record.setInfo.name);
```

**达成路径**

[IN] key_, len_ (IPC key params) -> IPCMemRecord (IPC interaction)

**验证说明**: 有std::min<>(len_, sizeof(name))长度限制，但GetValidLength逻辑需确认完全安全

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [bind-hccl-reinit-001] Race Condition - HcclCommInitClusterInfo/HcclCommInitRootInfo

**严重性**: Medium | **CWE**: CWE-367 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `csrc/bind/BindOpprof.cpp:696-736` @ `HcclCommInitClusterInfo/HcclCommInitRootInfo`
**模块**: bind
**跨模块**: hccl

**描述**: HcclCommInitClusterInfo,HcclCommInitRootInfo等HCCL函数在g_isCtorDone=false时调用HijackedCtor(),可能造成HCCL通信初始化与主初始化流程的竞态

**漏洞代码** (`csrc/bind/BindOpprof.cpp:696-736`)

```c
if(!g_isCtorDone){HijackedCtor();}
```

**达成路径**

[IN]External->HcclCommInit[OUT]->HijackedCtor[OUT]->RegisterHccl

**验证说明**: HCCL初始化检查g_isCtorDone可能触发竞态，实际风险取决于HCCL调用时机

**评分明细**: base: 30 | reachability: 10 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [SEC-004] IPC Credential Bypass - DomainSocketServer::Accept

**严重性**: Medium | **CWE**: CWE-287 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/core/DomainSocket.cpp:126-129` @ `DomainSocketServer::Accept`
**模块**: core
**跨模块**: core,Communication

**描述**: 跨模块安全分析发现：DomainSocket.cpp 的 Accept 函数检查客户端凭证（uid/gid 必须相同），但该检查仅在服务端执行。如果攻击者能够控制 IPC 客户端进程（通过 msOpProf/msSanitizer），可能绕过此检查。信任边界文档表明 IPC 客户端属于 'untrusted' 边界，凭证检查依赖于 uid/gid 比较，在容器环境或权限提升场景下可能失效。

**漏洞代码** (`csrc/core/DomainSocket.cpp:126-129`)

```c
if (getuid() != cred.uid || getgid() != cred.gid) { WARN_LOG(...); return false; }
```

**达成路径**

IPC Client (msOpProf/msSanitizer) -> DomainSocket::Accept -> cred.uid/cred.gid check -> 允许/拒绝连接

**验证说明**: 凭证验证在容器环境或权限提升场景可能失效，但实际攻击场景有限

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -20 | context: -10 | cross_file: 0

---

### [VULN-CORE-005] IPC Data Reception Without Content Validation - DomainSocketServer::Read

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `csrc/core/DomainSocket.cpp:184-196` @ `DomainSocketServer::Read`
**模块**: core
**跨模块**: core,runtime

**描述**: DomainSocketServer::Read() receives data from IPC clients without validating message content structure. Mitigation present: SO_PEERCRED credential checking (uid/gid verification) at line 126 ensures only same-user processes can connect. However, message content is passed directly to handlers without schema validation.

**漏洞代码** (`csrc/core/DomainSocket.cpp:184-196`)

```c
ssize_t ret = read(cfd, buffer.data(), maxBytes);
```

**达成路径**

[IN] IPC Client message -> DomainSocketServer::Read -> message.assign() -> clientMsgHandlerHook_ [OUT]

**验证说明**: 有SO_PEERCRED凭证验证(uid/gid)确保仅同用户进程可连接，但消息内容未做schema验证

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-runtime-002] Improper Input Validation - HijackedFuncOfKernelLaunch::Pre/Call

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/runtime/HijackedFuncOfKernelLaunch.cpp:232-294` @ `HijackedFuncOfKernelLaunch::Pre/Call`
**模块**: runtime

**描述**: Insufficient validation of args pointer before memory operations. While argsSize is validated against MAX_ALL_PARAM_SIZE, the args pointer itself is not validated for null or invalid addresses before being used in memory copy operations. A null or corrupted args pointer could lead to crashes or memory corruption.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/runtime/HijackedFuncOfKernelLaunch.cpp:232-294`)

```c
void Pre(const void *stubFunc, uint32_t blockDim, void *args, uint32_t argsSize, rtSmDesc_t *smDesc, rtStream_t stm)\n{\n    InitParam(stubFunc, blockDim, args, argsSize, smDesc, stm);
```

**达成路径**

[IN] User args/argsSize -> InitParam -> ExpandArgs -> std::copy_n(args, argsSize, ...)

**验证说明**: argsSize有MAX_ALL_PARAM_SIZE验证但args指针未验证null，实际风险取决于调用方参数有效性

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-runtime-003] Integer Overflow - GetAlignSize

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/runtime/inject_helpers/LaunchArgs.cpp:31-34` @ `GetAlignSize`
**模块**: runtime

**描述**: Potential integer overflow in alignment calculations. The GetAlignSize function performs arithmetic operations (s + ALIGN_SIZE - 1) which could overflow if s is close to UINT32_MAX. This could lead to undersized buffer allocations when argsSize is very large.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/runtime/inject_helpers/LaunchArgs.cpp:31-34`)

```c
uint32_t GetAlignSize(uint32_t s)\n{\n    return (s + ALIGN_SIZE - 1) / ALIGN_SIZE * ALIGN_SIZE;\n}
```

**达成路径**

[IN] argsSize(uint32_t) -> GetAlignSize(argsSize) -> buffer resize

**验证说明**: GetAlignSize存在整数溢出风险但argsSize有上限验证，极端情况下可能分配过小buffer

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (6)

### [VULN-runtime-005] Binary Injection/Command Injection - GetObjdumpOutput

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-77 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/runtime/inject_helpers/RegisterContext.cpp:65-80` @ `GetObjdumpOutput`
**模块**: runtime
**跨模块**: runtime,utils

**描述**: PipeCall executes external commands (llvm-objdump, grep) on user-provided binary data. The GetObjdumpOutput function runs llvm-objdump on binary data that comes from user-provided kernel binaries. Malicious binary data could potentially exploit vulnerabilities in llvm-objdump.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/runtime/inject_helpers/RegisterContext.cpp:65-80`)

```c
bool ret = PipeCall({"llvm-objdump", "-t", "-"}, objdumpOutput, binaryData);\n...\nret = PipeCall({"grep", "g     F .text"}, output, objdumpOutput);
```

**达成路径**

[IN] User Binary Data -> GetSymInfoFromBinary -> PipeCall(llvm-objdump)

**验证说明**: 用户二进制数据通过PipeCall传给llvm-objdump，依赖工具安全性而非直接漏洞，实际风险取决于llvm-objdump的漏洞

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -5 | context: 0 | cross_file: 0

---

### [SEC-005] Environment Variable Injection - SimulatorLauncher::SimulatorLauncher/SetEnvToSimu

**严重性**: Low | **CWE**: CWE-78 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/runtime/inject_helpers/ProfDataCollect.cpp:494-522` @ `SimulatorLauncher::SimulatorLauncher/SetEnvToSimu`
**模块**: runtime
**跨模块**: runtime,profapi

**描述**: 跨模块安全分析发现：ProfDataCollect.cpp SimulatorLauncher::Launch 函数设置 LD_PRELOAD 环境变量，opprofInjectionLib_ 路径来自 ProfConfig 配置。如果配置被篡改或 ProfConfig::GetMsopprofPath() 返回恶意路径，可能导致加载恶意动态库。虽然路径有 IsExist/IsExecutable 检查，但这些检查不足以防止符号链接攻击。

**漏洞代码** (`csrc/runtime/inject_helpers/ProfDataCollect.cpp:494-522`)

```c
env["LD_PRELOAD"] = opprofInjectionLib_ + ":libruntime_camodel.so";
```

**达成路径**

ProfConfig::GetMsopprofPath() -> opprofInjectionLib_ -> LD_PRELOAD env -> fork/execvpe

**验证说明**: LD_PRELOAD路径有IsExist/IsExecutable检查但不足以防止符号链接攻击，与runtime-001相关但severity较低

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -15 | context: -5 | cross_file: 0

---

### [acl_rt_impl-007] Missing Validation - InitParam

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtLaunchKernelImpl.cpp:56-70` @ `InitParam`
**模块**: acl_rt_impl

**描述**: Kernel args size passed without upper bound validation. argsSize parameter is used directly for creating ArgsContext without checking for reasonable upper limits, potentially allowing excessive memory allocation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtLaunchKernelImpl.cpp:56-70`)

```c
bool InitParam(... size_t argsSize ...) {... argsCtx_ = ArgsManager::Instance().CreateContext(const_cast<void *>(argsData), argsSize, true); }
```

**达成路径**

[IN] argsSize (user param) -> ArgsContext creation

**验证说明**: argsSize无上限验证，实际风险是内存过量分配而非安全漏洞

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: -10 | cross_file: 0

---

### [acl_rt_impl-010] Missing Validation - Pre/Post

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtCreateBinaryImpl.cpp:24-36` @ `Pre/Post`
**模块**: acl_rt_impl

**描述**: Binary data length passed without validation. dataLen parameter in aclrtCreateBinaryImpl is stored directly and passed to RegisterManager without size validation, potentially allowing excessive data caching.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Ops-Common/csrc/acl_rt_impl/HijackedFuncOfAclrtCreateBinaryImpl.cpp:24-36`)

```c
void Pre(const void *data, size_t dataLen) { data_ = static_cast<const char*>(data); dataLen_ = dataLen; } ... RegisterManager::Instance().CacheElfData(bin, data_, dataLen_);
```

**达成路径**

[IN] data, dataLen (binary data) -> RegisterManager cache

**验证说明**: dataLen无上限验证，实际风险是缓存过量而非安全漏洞

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: -10 | cross_file: 0

---

### [VUL-TOOLS-008] Improper Input Validation - GetJsonFromBin

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/csrc/tools/kernel_launcher/KernelConfigParser.cpp:351-365` @ `GetJsonFromBin`
**模块**: tools

**描述**: GetJsonFromBin reads JSON without size limit validation

**漏洞代码** (`/csrc/tools/kernel_launcher/KernelConfigParser.cpp:351-365`)

```c
std::vector<char> rawFile(fileSize)
```

**达成路径**

[IN] argv -c filePath -> GetJsonFromBin()

**验证说明**: 无大小限制读取JSON，实际风险是内存消耗而非安全漏洞

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: -10 | cross_file: 0

---

### [VUL-TOOLS-010] Unchecked Pointer Dereference - ClearL2Cache

**严重性**: Low | **CWE**: CWE-822 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/csrc/tools/dfx_kernel/ClearL2Cache.cpp:26-27` @ `ClearL2Cache`
**模块**: tools

**描述**: ClearL2Cache dereferences tilingSize without null check

**漏洞代码** (`/csrc/tools/dfx_kernel/ClearL2Cache.cpp:26-27`)

```c
*(__gm__ uint64_t *)tilingSize
```

**达成路径**

[IN] kernel launch args

**验证说明**: tilingSize无null检查解引用，实际风险取决于kernel launch参数

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: -10 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| acl_rt_impl | 0 | 3 | 2 | 2 | 7 |
| bind | 0 | 2 | 4 | 0 | 6 |
| core | 0 | 2 | 3 | 0 | 5 |
| runtime | 0 | 0 | 3 | 2 | 5 |
| tools | 0 | 0 | 4 | 2 | 6 |
| utils | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **7** | **17** | **6** | **30** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 8 | 26.7% |
| CWE-22 | 4 | 13.3% |
| CWE-78 | 3 | 10.0% |
| CWE-367 | 3 | 10.0% |
| CWE-125 | 3 | 10.0% |
| CWE-190 | 2 | 6.7% |
| CWE-822 | 1 | 3.3% |
| CWE-787 | 1 | 3.3% |
| CWE-77 | 1 | 3.3% |
| CWE-287 | 1 | 3.3% |
| CWE-15 | 1 | 3.3% |
| CWE-120 | 1 | 3.3% |
| CWE-114 | 1 | 3.3% |
