# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-Ops-Profiler
**扫描时间**: 2026-04-20T21:50:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本次漏洞扫描对 MindStudio-Ops-Profiler 项目（华为昇腾算子性能分析工具）进行了深入的安全审计。该项目作为本地 CLI 工具运行，存在多个与环境变量信任和动态库加载相关的安全风险。

### 扫描概况

- **扫描范围**：C/C++ 源代码全量扫描，涵盖 6 个主要模块
- **漏洞发现**：29 个待确认漏洞（9 High + 14 Medium + 6 Low）
- **主要风险类型**：动态库注入（48.3%）、路径遍历（17.2%）、权限检查缺陷（13.8%）

### 核心风险分析

**1. 环境变量信任链断裂**

项目核心安全缺陷在于对环境变量的过度信任：
- `LD_LIBRARY_PATH` 被 `GetSoFromEnvVar()` 直接用于动态库搜索
- `ASCEND_HOME_PATH` 用于构建运行时库路径但缺少完整性验证
- 这些环境变量在攻击场景中可能被本地用户篡改

**2. 动态库加载缺乏安全控制**

多个 `dlopen()` 调用点存在库注入风险：
- `RuntimeHelper` 在非仿真模式下直接拼接路径加载 `libruntime.so`
- `HalHelper` 从 `LD_LIBRARY_PATH` 加载 `libascend_hal.so` 和 `libdcmi.so`
- `CheckInputFileValid()` 对 `.so` 文件跳过所有者权限检查（设计缺陷）

**3. 路径验证不完整**

- 符号链接检查仅发出警告，不阻止操作
- `object_dump.txt` 中的路径直接用于文件复制和目录创建
- 部分路径处理函数缺少 `realpath()` 规范化

### 业务影响评估

作为本地性能分析工具，这些漏洞的攻击前提是：
- 本地用户可以控制进程启动时的环境变量
- 本地用户有写入权限到输出目录或中间文件

在高安全场景（如 sudo 执行、容器环境、多租户共享系统）中，这些漏洞可能被利用实现：
- 任意代码执行（通过恶意动态库注入）
- 数据篡改或泄露（通过路径遍历）
- 权限提升（在特定部署配置下）

### 建议修复优先级

| 优先级 | 漏洞类型 | 数量 | 关键修复点 |
|--------|----------|------|------------|
| P1 | 动态库注入 | 9 | 强制使用绝对路径、添加签名校验 |
| P2 | 路径遍历 | 5 | 完整路径规范化、禁止符号链接 |
| P3 | 权限检查 | 4 | 启用所有者检查、修复 CheckInputFileValid |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 30 | 50.0% |
| FALSE_POSITIVE | 17 | 28.3% |
| LIKELY | 13 | 21.7% |
| **总计** | **60** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 9 | 31.0% |
| Medium | 14 | 48.3% |
| Low | 6 | 20.7% |
| **有效漏洞总计** | **29** | - |
| 误报 (FALSE_POSITIVE) | 17 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-001]** library_injection (High) - `csrc/op_profiling/profiling/op_prof_task.cpp:36` @ `Task::CheckSimulatorSoExist` | 置信度: 75
2. **[VULN-DF-DYN-001]** dynamic_library_injection (High) - `csrc/op_profiling/common/runtime_helper.cpp:55` @ `RuntimeHelper::RuntimeHelper` | 置信度: 75
3. **[VULN-DF-005]** untrusted_search_path (High) - `csrc/utils/cpputils/ascend_helper.cpp:28` @ `GetAscendHomePath` | 置信度: 70
4. **[VULN-SA-COMMON-002]** library_injection (High) - `csrc/op_profiling/common/runtime_helper.cpp:54` @ `RuntimeHelper::RuntimeHelper` | 置信度: 70
5. **[VULN-SA-PT-001]** path_traversal (High) - `csrc/op_profiling/profiling/simulator/data_parse/sim_data_parse.cpp:183` @ `GetObjectOutPathAndCopyAicoreFile` | 置信度: 70
6. **[VULN-DF-002]** library_injection (High) - `csrc/op_profiling/common/hal_helper.cpp:34` @ `HalHelper::HalHelper` | 置信度: 65
7. **[VULN-DF-003]** library_injection (High) - `csrc/op_profiling/common/hal_helper.cpp:203` @ `HalHelper::CheckGmType` | 置信度: 65
8. **[VULN-DF-004]** library_injection (High) - `csrc/op_profiling/common/runtime_helper.cpp:50` @ `RuntimeHelper::RuntimeHelper` | 置信度: 65
9. **[VULN-SA-COMMON-001]** library_injection (High) - `csrc/utils/cpputils/ascend_helper.cpp:135` @ `GetSoFromEnvVar` | 置信度: 65
10. **[VULN-DF-DYN-002]** dynamic_library_injection (Medium) - `csrc/op_profiling/common/hal_helper.cpp:34` @ `HalHelper::HalHelper` | 置信度: 65

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@csrc/op_profiling/main.cpp` | cmdline | untrusted_local | main() 接收 argc/argv，本地用户通过命令行启动工具，可控制所有参数 | CLI 主入口，接收命令行参数 |
| `BuildDeviceArgParser@csrc/op_profiling/interface/ms_op_prof.cpp` | cmdline | untrusted_local | 解析 --application、--config、--output 等命令行参数，用户可控制待执行的应用路径和配置 | 设备模式参数解析器 |
| `BuildSimulatorArgParser@csrc/op_profiling/interface/ms_op_prof.cpp` | cmdline | untrusted_local | 解析仿真模式命令行参数，包括 --application、--config、--export 等 | 仿真模式参数解析器 |
| `ParseRunConfigJson@csrc/utils/cpputils/json_parser.cpp` | file | untrusted_local | 解析用户提供的 JSON 配置文件，包含 kernel_path、data_path、application 等敏感路径字段 | 解析用户JSON配置文件 |
| `CmdExecute@csrc/utils/cpputils/cmd_execute.cpp` | rpc | semi_trusted | 执行外部命令，命令参数来自上层解析（JSON配置或命令行），存在命令注入风险 | 执行外部命令（fork/execvpe） |
| `ExecBinaryRunner::Run@csrc/op_runner/runner_impl/exec_binary_runner.cpp` | rpc | semi_trusted | 通过 posix_spawnp 执行用户指定的二进制文件（来自 --application 或 JSON 配置），存在恶意代码执行风险 | 执行用户提供的二进制文件 |
| `RuntimeHelper::Init@csrc/op_profiling/common/runtime_helper.cpp` | decorator | trusted_admin | 通过 dlopen 加载系统运行时库（libruntime.so），路径由 ASCEND_HOME_PATH 环境变量控制，管理员可控 | 动态加载 runtime 库 |
| `HalHelper::Init@csrc/op_profiling/common/hal_helper.cpp` | decorator | trusted_admin | 通过 dlopen 加载系统 HAL 库，路径由环境变量控制，管理员可控 | 动态加载 HAL 和 DCMI 库 |
| `GetAscendHomePath@csrc/utils/cpputils/ascend_helper.cpp` | env | trusted_admin | 读取 ASCEND_HOME_PATH 环境变量确定工具安装路径，由部署人员控制 | 读取 ASCEND_HOME_PATH 环境变量 |
| `SetLogLevelByEnvVar@csrc/utils/cpputils/log.cpp` | env | untrusted_local | 读取 MSOPT_LOG_LEVEL 环境变量设置日志级别，本地用户可控制 | 读取日志级别环境变量 |
| `OpProfTask::RunSimulator@csrc/op_profiling/profiling/op_prof_task.cpp` | decorator | semi_trusted | 通过 dlopen 加载仿真器库（simulator.so），路径来自系统安装目录或用户配置 | 动态加载仿真器库 |

**其他攻击面**:
- CLI 参数注入：通过 --application 参数指定恶意可执行文件
- JSON 配置注入：通过 JSON 文件中的 kernel_path、data_path 字段控制文件路径
- 命令注入：CmdExecute 函数执行用户控制的命令参数
- 动态库加载：dlopen 加载系统库，路径受环境变量影响
- 文件路径遍历：JSON 配置文件中的路径可能指向任意位置
- 环境变量操纵：MSOPT_LOG_LEVEL、ASCEND_HOME_PATH 等可被本地用户修改
- 二进制数据解析：解析性能数据文件时可能触发缓冲区溢出

---

## 3. High 漏洞 (9)

### [VULN-DF-001] library_injection - Task::CheckSimulatorSoExist

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-426 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/op_profiling/profiling/op_prof_task.cpp:36-44` @ `Task::CheckSimulatorSoExist`
**模块**: profiling_core

**描述**: Library injection via LD_LIBRARY_PATH. GetSoFromEnvVar reads library path from LD_LIBRARY_PATH environment variable and passes it directly to dlopen. An attacker controlling LD_LIBRARY_PATH can inject malicious libruntime_camodel.so, libascend_hal.so, or libdcmi.so to execute arbitrary code.

**漏洞代码** (`csrc/op_profiling/profiling/op_prof_task.cpp:36-44`)

```c
std::string simulatorSo = GetSoFromEnvVar("libruntime_camodel.so");
...
simulatorSo = Realpath(simulatorSo);
...
void *rtHandle = dlopen(simulatorSo.c_str(), RTLD_LAZY);
```

**达成路径**

ascend_helper.cpp:137 getenv("LD_LIBRARY_PATH") [SOURCE] → ascend_helper.cpp:145-150 GetSoFromEnvVar() → op_prof_task.cpp:36 simulatorSo → op_prof_task.cpp:44 dlopen() [SINK]

**验证说明**: Library injection via LD_LIBRARY_PATH is real threat when attacker can control environment variables. Realpath provides path traversal protection but no owner permission check. VULN-DF-001 does NOT call CheckInputFileValid unlike others, making it more severe. Attack requires local access to set LD_LIBRARY_PATH.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：
该漏洞的根本原因在于 `GetSoFromEnvVar()` 函数（ascend_helper.cpp:135-153）直接信任 `LD_LIBRARY_PATH` 环境变量，并从该变量指定的路径搜索动态库。函数流程：
1. 从 `getenv("LD_LIBRARY_PATH")` 获取环境变量值
2. 按 `:` 分割得到多个路径
3. 在每个路径中搜索目标库（如 `libruntime_camodel.so`）
4. 使用 `Realpath()` 规范化路径但**不检查文件所有者权限**
5. 返回第一个找到的库路径

关键设计缺陷：`CheckSimulatorSoExist()` 在找到库后直接调用 `dlopen()`，**没有调用 `CheckInputFileValid()` 进行安全校验**，这与 RuntimeHelper 和 HalHelper 的处理方式不同。

**潜在利用场景**：
1. 攻击者在共享系统上设置恶意环境变量：`export LD_LIBRARY_PATH=/tmp/malicious:$LD_LIBRARY_PATH`
2. 在 `/tmp/malicious/` 目录放置恶意 `libruntime_camodel.so`
3. 当用户运行 msopprof 工具时，恶意库被加载并执行任意代码
4. 在 sudo 场景（`sudo -E msopprof`）或容器环境中风险更高

**建议修复方式**：
```cpp
// 修复方案：添加完整性验证
std::string simulatorSo = GetSoFromEnvVar("libruntime_camodel.so");
if (simulatorSo.empty() || !CheckInputFileValid(simulatorSo, "so")) {
    LogError("Invalid simulator library path");
    return false;
}
// 进一步建议：验证库签名或使用固定安装路径
if (!ValidateLibrarySignature(simulatorSo)) {
    LogError("Library signature verification failed");
    return false;
}
```

---

### [VULN-DF-DYN-001] dynamic_library_injection - RuntimeHelper::RuntimeHelper

**严重性**: High | **CWE**: CWE-426 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/op_profiling/common/runtime_helper.cpp:55-57` @ `RuntimeHelper::RuntimeHelper`
**模块**: common
**跨模块**: common → ascend_helper

**描述**: dlopen loads runtime library (libruntime.so) from path derived from ASCEND_HOME_PATH environment variable without adequate validation. In non-simulation mode, the library path is constructed as ascendHomePath + '/lib64/libruntime.so' and passed directly to dlopen. While GetAscendHomePath() uses realpath() to canonicalize the path, it does not verify the library is authentic or owned by a trusted user. A malicious actor who can manipulate ASCEND_HOME_PATH could cause arbitrary code execution.

**漏洞代码** (`csrc/op_profiling/common/runtime_helper.cpp:55-57`)

```c
std::string soName;
if (isSim_) {
    soName = GetSoFromEnvVar("libruntime_camodel.so");
    if (soName.empty() || !CheckInputFileValid(soName, "so")) { ... }
} else {
    soName = ascendHomePath + "/lib64/libruntime.so";
}
handle_ = dlopen(soName.c_str(), RTLD_LAZY);
```

**达成路径**

ASCEND_HOME_PATH [SOURCE] @csrc/utils/cpputils/ascend_helper.cpp:30 getenv()
→ GetAscendHomePath() @csrc/utils/cpputils/ascend_helper.cpp:28-46 realpath() partial sanitization
→ ascendHomePath @csrc/op_profiling/common/runtime_helper.cpp:44
→ soName = ascendHomePath + '/lib64/libruntime.so' @csrc/op_profiling/common/runtime_helper.cpp:55 [NO VALIDATION]
→ dlopen(soName.c_str()) @csrc/op_profiling/common/runtime_helper.cpp:57 [SINK]

**验证说明**: In non-simulation mode, RuntimeHelper loads libruntime.so from ASCEND_HOME_PATH without CheckInputFileValid validation. Path is constructed as ascendHomePath + '/lib64/libruntime.so'. realpath used but no file ownership/permission validation. High severity as this affects production mode, not just simulation.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：
该漏洞揭示了仿真模式和生产模式下安全验证的不一致性。对比代码逻辑：

| 模式 | 路径来源 | 安全验证 |
|------|----------|----------|
| 仿真模式 (isSim_=true) | LD_LIBRARY_PATH | ✅ CheckInputFileValid |
| 生产模式 (isSim_=false) | ASCEND_HOME_PATH | ❌ 无验证 |

生产模式下的漏洞流程：
1. `GetAscendHomePath()` 从环境变量获取路径并使用 `realpath()` 规范化
2. 直接拼接：`ascendHomePath + "/lib64/libruntime.so"`
3. **跳过 `CheckInputFileValid()` 校验**，直接调用 `dlopen()`

这是比仿真模式更严重的漏洞，因为生产模式是默认运行模式，且 `ASCEND_HOME_PATH` 被设计为"trusted_admin"但实际可能被篡改。

**潜在利用场景**：
```bash
# 场景：攻击者控制 ASCEND_HOME_PATH
export ASCEND_HOME_PATH=/tmp/malicious_ascend
mkdir -p /tmp/malicious_ascend/lib64
# 创建恶意 libruntime.so
gcc -shared -fPIC -o /tmp/malicious_ascend/lib64/libruntime.so malicious.c
# 运行工具时恶意库被加载
msopprof --application <valid_app>
```

在容器部署或 CI/CD 环境中，环境变量通常通过配置文件传递，攻击者可能通过配置文件注入控制部署路径。

**建议修复方式**：
```cpp
// 修复方案：统一验证逻辑
} else {
    soName = ascendHomePath + "/lib64/libruntime.so";
    // 添加验证（当前缺失）
    if (!CheckInputFileValid(soName, "so")) {
        LogError("Invalid runtime library path");
        return;
    }
}
```

---

### [VULN-DF-005] untrusted_search_path - GetAscendHomePath

**严重性**: High | **CWE**: CWE-426 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner, security-auditor

**位置**: `csrc/utils/cpputils/ascend_helper.cpp:28-46` @ `GetAscendHomePath`
**模块**: profiling_core
**跨模块**: profiling_core → utils

**描述**: ASCEND_HOME_PATH environment variable controls multiple file and library paths. GetAscendHomePath reads ASCEND_HOME_PATH from environment and uses it to construct paths for simulator libraries, config files, and runtime libraries. Attacker controlling this variable can redirect to malicious files.

**漏洞代码** (`csrc/utils/cpputils/ascend_helper.cpp:28-46`)

```c
char const *env = getenv("ASCEND_HOME_PATH");
std::string pathFromEnv = env == nullptr ? "" : env;
...
if (realpath(pathFromEnv.c_str(), buf) == nullptr)
```

**达成路径**

ascend_helper.cpp:30 getenv("ASCEND_HOME_PATH") [SOURCE] → realpath canonicalization → used in multiple path constructions: op_prof_task.cpp:272 camodelLibDir_, runtime_helper.cpp:55 libruntime.so path

**验证说明**: ASCEND_HOME_PATH environment variable controls multiple paths. GetAscendHomePath uses realpath for canonicalization. Attack requires local access to set environment variable before process starts. Real threat in scenarios where attacker can control process environment (sudo with env vars, container setups, shared systems).

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: -10 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：
`ASCEND_HOME_PATH` 环境变量是项目的核心信任锚点，被用于构建多个关键路径：

| 用途 | 路径构建 | 影响组件 |
|------|----------|----------|
| 运行时库 | $ASCEND_HOME_PATH/lib64/libruntime.so | RuntimeHelper |
| HAL库 | $ASCEND_HOME_PATH/lib64/libascend_hal.so | HalHelper |
| 仿真器目录 | $ASCEND_HOME_PATH/tools/simulator | GetSimulators() |
| 配置文件 | $ASCEND_HOME_PATH/... | 多个解析模块 |

虽然 `GetAscendHomePath()` 使用了 `realpath()` 进行路径规范化，但这只能防止路径遍历（`..` 序列），不能防止：
1. **恶意目录替换**：攻击者可以设置 `ASCEND_HOME_PATH` 指向自己创建的恶意目录
2. **符号链接攻击**：`realpath()` 解析后的路径可能仍然包含攻击者控制的符号链接

**潜在利用场景**：
```bash
# 场景1：直接控制环境变量
export ASCEND_HOME_PATH=/attacker/path
msopprof ...  # 加载攻击者目录中的恶意库

# 场景2：通过 set_env.sh 篡改（部署脚本注入）
# 攻击者修改 set_env.sh 文件
echo 'export ASCEND_HOME_PATH=/attacker/path' >> set_env.sh
source set_env.sh  # 用户执行时加载恶意配置
```

在云原生部署场景中，环境变量可能通过 Kubernetes ConfigMap 或 Docker ENV 设置，攻击者可能通过配置注入实现供应链攻击。

**建议修复方式**：
1. **白名单验证**：验证路径是否在允许的安装目录列表中
2. **签名校验**：验证关键库文件的签名或哈希
3. **所有者检查**：确保库文件由可信用户（如 root）拥有
```cpp
// 建议添加白名单检查
const std::vector<std::string> allowedPaths = {
    "/usr/local/Ascend", "/opt/Ascend", "/home/*/Ascend"
};
if (!IsPathInWhitelist(ascendHomePath, allowedPaths)) {
    LogError("ASCEND_HOME_PATH not in allowed installation paths");
    return false;
}
```

---

### [VULN-SA-COMMON-002] library_injection - RuntimeHelper::RuntimeHelper

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-426 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/op_profiling/common/runtime_helper.cpp:54-57` @ `RuntimeHelper::RuntimeHelper`
**模块**: common

**描述**: RuntimeHelper 构造函数在非模拟器模式下直接拼接 ascendHomePath + "/lib64/libruntime.so" 并调用 dlopen，未经过 CheckInputFileValid 校验。虽然 GetAscendHomePath 使用 realpath 解析路径，但缺少对软链接安全性、文件存在性和权限的完整检查。

**漏洞代码** (`csrc/op_profiling/common/runtime_helper.cpp:54-57`)

```c
} else {
    soName = ascendHomePath + "/lib64/libruntime.so";
}
handle_ = dlopen(soName.c_str(), RTLD_LAZY);
```

**达成路径**

ASCEND_HOME_PATH [SOURCE: getenv] → GetAscendHomePath → ascendHomePath + "/lib64/libruntime.so" [dlopen]

**验证说明**: Variant of Critical library injection. Non-simulation mode loads libruntime.so from ASCEND_HOME_PATH without CheckInputFileValid. Direct dlopen after path concatenation. Higher severity as this affects production mode.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: -10 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：
该漏洞与 VULN-DF-DYN-001 指向同一代码位置，但从静态分析角度强调路径拼接的安全性。核心问题在于 `GetAscendHomePath()` 的 `realpath()` 调用时机：

```cpp
// ascend_helper.cpp:28-46
char const *env = getenv("ASCEND_HOME_PATH");  // 获取原始路径
std::string pathFromEnv = env == nullptr ? "" : env;
char buf[PATH_MAX];
if (realpath(pathFromEnv.c_str(), buf) == nullptr) {  // 规范化
    return false;
}
ascendHomePath = buf;  // 返回规范化后的路径
```

`realpath()` 只在路径验证阶段调用一次，后续路径拼接（如 `+ "/lib64/libruntime.so"`）不再经过规范化，这可能导致：
- 路径组件被注入（虽然基本路径已规范化）
- 符号链接绕过（如果规范化后的路径下存在符号链接）

**潜在利用场景**：
在非仿真模式下，攻击者可以：
1. 创建恶意目录结构：`/tmp/mal/lib64/libruntime.so`
2. 设置 `ASCEND_HOME_PATH=/tmp/mal`
3. `realpath()` 解析 `/tmp/mal` → `/tmp/mal`（正常）
4. 拼接得到 `/tmp/mal/lib64/libruntime.so`
5. `dlopen()` 加载恶意库

**与 VULN-DF-DYN-001 的关系**：两者指向同一漏洞的不同表现，VULN-DF-DYN-001 从数据流角度分析，VULN-SA-COMMON-002 从静态安全模式角度分析。建议作为同一漏洞组处理。

---

### [VULN-SA-PT-001] path_traversal - GetObjectOutPathAndCopyAicoreFile

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/op_profiling/profiling/simulator/data_parse/sim_data_parse.cpp:183-223` @ `GetObjectOutPathAndCopyAicoreFile`
**模块**: profiling_simulator

**描述**: Path traversal via unvalidated file read. GetObjectOutPathAndCopyAicoreFile reads path from 'object_dump.txt' file (line 183-184) and uses it directly for directory creation (MkdirRecusively), file copying (CopyFile), and permission setting (chmod) without validation. If the dump file is tampered, attacker can write to arbitrary locations.

**漏洞代码** (`csrc/op_profiling/profiling/simulator/data_parse/sim_data_parse.cpp:183-223`)

```c
if (GetFileLines(kernelNamePath, fileLines) && fileLines.size() == 2) {
    outPath = fileLines[0];
    ...
    if (!IsExist(outPath) && !MkdirRecusively(outPath)) { ... }
    CopyFile(aicoreBinFileSrc, aicoreBinFileDest);
    CopyFile(dir_entry.path().string(), outputPath);
    chmod(dstFilePath.c_str(), SAVE_DATA_FILE_AUTHORITY);
```

**达成路径**

object_dump.txt [SOURCE] -> fileLines[0] (unvalidated path) -> MkdirRecusively(outPath) [SINK] -> CopyFile [SINK] -> chmod [SINK]

**验证说明**: Path traversal vulnerability via object_dump.txt file content. The file is generated by profiling process in user's output directory. If attacker can tamper with this intermediate file (requires write access to output dir), they can control output paths for MkdirRecusively, CopyFile, and chmod. No path validation or realpath call on fileLines[0]. Attack requires local access to output directory.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：
该漏洞是最严重的路径遍历风险点，位于仿真数据解析流程中。漏洞链路：

```cpp
// sim_data_parse.cpp:183-223
// 读取 object_dump.txt 文件
std::string kernelNamePath = JoinPath({path, "object_dump.txt"});
if (GetFileLines(kernelNamePath, fileLines) && fileLines.size() == 2) {
    outPath = fileLines[0];  // 直接使用文件内容作为路径！
    // 无任何路径验证
    if (!IsExist(outPath) && !MkdirRecusively(outPath)) { return false; }
    // 文件复制到用户可控路径
    CopyFile(aicoreBinFileSrc, aicoreBinFileDest);
    // 设置文件权限
    chmod(dstFilePath.c_str(), SAVE_DATA_FILE_AUTHORITY);
}
```

**关键缺陷**：
1. `fileLines[0]` 从 `object_dump.txt` 文件读取，**无任何验证**
2. 该路径直接传递给 `MkdirRecusively()`、`CopyFile()` 和 `chmod()`
3. 没有 `realpath()` 调用，没有路径白名单检查

**潜在利用场景**：
```bash
# 场景1：篡改中间文件
# object_dump.txt 由 profiling 流程生成在输出目录
# 如果攻击者有输出目录写权限，可以篡改该文件
echo '/root/.ssh' > /output_dir/object_dump.txt  # 等待工具读取
# 工具执行时会在 /root/.ssh 目录创建文件并设置权限

# 场景2：跨模块攻击链
# interface 入口接收 --config 参数
# JSON 配置中的 data_path 控制中间目录位置
# 攻击者预置恶意 object_dump.txt
msopprof --config malicious_config.json
```

**建议修复方式**：
```cpp
// 修复方案：添加完整路径验证
if (GetFileLines(kernelNamePath, fileLines) && fileLines.size() == 2) {
    outPath = fileLines[0];
    // 添加路径验证
    outPath = Realpath(outPath);  // 规范化
    if (!IsPathInAllowedDirectory(outPath, allowedOutputDirs)) {
        LogError("Output path not in allowed directories");
        return false;
    }
    if (!CheckInputFileValid(outPath, "dir")) {
        LogError("Invalid output path");
        return false;
    }
    // 继续处理...
}
```

---

### [VULN-DF-002] library_injection - HalHelper::HalHelper

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/op_profiling/common/hal_helper.cpp:34-39` @ `HalHelper::HalHelper`
**模块**: profiling_core
**跨模块**: profiling_core → profiling_common

**描述**: Library injection via LD_LIBRARY_PATH in HalHelper constructor. GetSoFromEnvVar reads libascend_hal.so path from LD_LIBRARY_PATH and passes it to dlopen. Attacker controlling LD_LIBRARY_PATH can inject malicious library.

**漏洞代码** (`csrc/op_profiling/common/hal_helper.cpp:34-39`)

```c
std::string halSo = GetSoFromEnvVar("libascend_hal.so");
...
handleHal_ = dlopen(halSo.c_str(), RTLD_LAZY);
```

**达成路径**

ascend_helper.cpp:137 getenv("LD_LIBRARY_PATH") [SOURCE] → ascend_helper.cpp:145-150 GetSoFromEnvVar() → hal_helper.cpp:34 halSo → hal_helper.cpp:39 dlopen() [SINK]

**验证说明**: Library injection via LD_LIBRARY_PATH. HalHelper calls CheckInputFileValid which checks existence and read permission. However, CheckInputFileValid for .so files does NOT check owner permission (FileTypePermission['so'].second=false). Symlink check is warning-only. Attack requires local access to control LD_LIBRARY_PATH.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-DF-003] library_injection - HalHelper::CheckGmType

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/op_profiling/common/hal_helper.cpp:203-208` @ `HalHelper::CheckGmType`
**模块**: profiling_core
**跨模块**: profiling_core → profiling_common

**描述**: Library injection via LD_LIBRARY_PATH for libdcmi.so. GetSoFromEnvVar reads libdcmi.so path from LD_LIBRARY_PATH and passes it to dlopen in CheckGmType(). Attacker controlling LD_LIBRARY_PATH can inject malicious library.

**漏洞代码** (`csrc/op_profiling/common/hal_helper.cpp:203-208`)

```c
std::string dcmiSo = GetSoFromEnvVar("libdcmi.so");
...
handleDcmi_ = dlopen(dcmiSo.c_str(), RTLD_LAZY | RTLD_LOCAL);
```

**达成路径**

ascend_helper.cpp:137 getenv("LD_LIBRARY_PATH") [SOURCE] → ascend_helper.cpp:145-150 GetSoFromEnvVar() → hal_helper.cpp:203 dcmiSo → hal_helper.cpp:208 dlopen() [SINK]

**验证说明**: Library injection via LD_LIBRARY_PATH for libdcmi.so. Similar to VULN-DF-002, CheckInputFileValid is called but owner permission is NOT checked for .so files. Attack requires local access to control environment.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-DF-004] library_injection - RuntimeHelper::RuntimeHelper

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/op_profiling/common/runtime_helper.cpp:50-57` @ `RuntimeHelper::RuntimeHelper`
**模块**: profiling_core
**跨模块**: profiling_core → profiling_common

**描述**: Library injection via LD_LIBRARY_PATH in RuntimeHelper constructor when isSim_=true. GetSoFromEnvVar reads libruntime_camodel.so path from LD_LIBRARY_PATH and passes it to dlopen.

**漏洞代码** (`csrc/op_profiling/common/runtime_helper.cpp:50-57`)

```c
soName = GetSoFromEnvVar("libruntime_camodel.so");
...
handle_ = dlopen(soName.c_str(), RTLD_LAZY);
```

**达成路径**

ascend_helper.cpp:137 getenv("LD_LIBRARY_PATH") [SOURCE] → ascend_helper.cpp:145-150 GetSoFromEnvVar() → runtime_helper.cpp:50 soName → runtime_helper.cpp:57 dlopen() [SINK]

**验证说明**: Library injection via LD_LIBRARY_PATH in simulator mode. RuntimeHelper calls CheckInputFileValid in isSim_ mode but owner permission check is skipped for .so files. Attack requires local access to control LD_LIBRARY_PATH environment.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-SA-COMMON-001] library_injection - GetSoFromEnvVar

**严重性**: High | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/utils/cpputils/ascend_helper.cpp:135-153` @ `GetSoFromEnvVar`
**模块**: common
**跨模块**: common → utils

**描述**: GetSoFromEnvVar 从 LD_LIBRARY_PATH 环境变量获取动态库路径，虽然调用了 CheckInputFileValid 进行文件校验，但校验不阻止从用户可控路径加载库。对于 .so 文件类型不检查 owner 权限（FileTypePermission['so'].second=false），攻击者可在 LD_LIBRARY_PATH 中的可写目录放置恶意 .so 文件实现库注入。该函数被 RuntimeHelper 和 HalHelper 的 dlopen 调用。

**漏洞代码** (`csrc/utils/cpputils/ascend_helper.cpp:135-153`)

```c
std::string GetSoFromEnvVar(const std::string &soName)
{
    char const *ldEnv = getenv("LD_LIBRARY_PATH");
    if (ldEnv == nullptr) { return ""; }
    std::string pathFromEnv = ldEnv;
    std::vector<std::string> envs;
    SplitString(pathFromEnv, ':', envs);
    for (const std::string &path : envs) {
        std::string soPath = JoinPath({path.c_str(), soName});
        std::string realSoPath = Realpath(soPath);
        if (realSoPath.empty()) { continue; }
        return realSoPath;
    }
    return "";
}
```

**达成路径**

LD_LIBRARY_PATH [SOURCE: getenv] → GetSoFromEnvVar → RuntimeHelper::RuntimeHelper() [dlopen] / HalHelper::HalHelper() [dlopen]

**验证说明**: Duplicate of Critical library injection vulnerabilities. GetSoFromEnvVar from LD_LIBRARY_PATH. CheckInputFileValid called but .so files skip owner check. Real threat when attacker can control LD_LIBRARY_PATH environment.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: -15 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (14)

### [VULN-DF-DYN-002] dynamic_library_injection - HalHelper::HalHelper

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/op_profiling/common/hal_helper.cpp:34-39` @ `HalHelper::HalHelper`
**模块**: common
**跨模块**: common → ascend_helper → filesystem

**描述**: dlopen loads HAL library (libascend_hal.so) from path derived from LD_LIBRARY_PATH environment variable. GetSoFromEnvVar() searches LD_LIBRARY_PATH paths and uses Realpath() for canonicalization, followed by CheckInputFileValid(). However, CheckInputFileValid for 'so' files only checks read permission (S_IRUSR) and explicitly skips owner permission verification (second param is false in FileTypePermission map). This allows loading libraries not owned by root/trusted user.

**漏洞代码** (`csrc/op_profiling/common/hal_helper.cpp:34-39`)

```c
std::string halSo = GetSoFromEnvVar("libascend_hal.so");
if (halSo.empty() || !CheckInputFileValid(halSo, "so")) {
    LogWarn("Can't find valid libascend_hal.so, please check your LD_LIBRARY_PATH");
    return;
}
handleHal_ = dlopen(halSo.c_str(), RTLD_LAZY);
```

**达成路径**

LD_LIBRARY_PATH [SOURCE] @csrc/utils/cpputils/ascend_helper.cpp:137 getenv()
→ GetSoFromEnvVar() @csrc/utils/cpputils/ascend_helper.cpp:135-153 Realpath() + path search
→ halSo @csrc/op_profiling/common/hal_helper.cpp:34
→ CheckInputFileValid(halSo, "so") @csrc/op_profiling/common/hal_helper.cpp:35 [WEAK VALIDATION - skips owner check for .so]
→ dlopen(halSo.c_str()) @csrc/op_profiling/common/hal_helper.cpp:39 [SINK]

**验证说明**: Variant of library injection. HalHelper loads libascend_hal.so from LD_LIBRARY_PATH. CheckInputFileValid called but owner check skipped for .so. Attack requires environment control.

**评分明细**: base: 30 | reachability: 25 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-DYN-003] dynamic_library_injection - HalHelper::CheckGmType

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `csrc/op_profiling/common/hal_helper.cpp:203-208` @ `HalHelper::CheckGmType`
**模块**: common
**跨模块**: common → ascend_helper → filesystem

**描述**: dlopen loads DCMI library (libdcmi.so) from path derived from LD_LIBRARY_PATH environment variable. Similar to VULN-DF-DYN-002, validation via CheckInputFileValid() for 'so' files only checks read permission and skips owner verification. This could allow loading malicious libraries if an attacker can control LD_LIBRARY_PATH or place files in searchable paths.

**漏洞代码** (`csrc/op_profiling/common/hal_helper.cpp:203-208`)

```c
std::string dcmiSo = GetSoFromEnvVar("libdcmi.so");
if (dcmiSo.empty() || !CheckInputFileValid(dcmiSo, "so")) {
    LogWarn("Can't find valid libdcmi.so, will use default gm type value");
    return;
}
handleDcmi_ = dlopen(dcmiSo.c_str(), RTLD_LAZY | RTLD_LOCAL);
```

**达成路径**

LD_LIBRARY_PATH [SOURCE] @csrc/utils/cpputils/ascend_helper.cpp:137 getenv()
→ GetSoFromEnvVar() @csrc/utils/cpputils/ascend_helper.cpp:135-153
→ dcmiSo @csrc/op_profiling/common/hal_helper.cpp:203
→ CheckInputFileValid(dcmiSo, "so") @csrc/op_profiling/common/hal_helper.cpp:204 [WEAK VALIDATION]
→ dlopen(dcmiSo.c_str()) @csrc/op_profiling/common/hal_helper.cpp:208 [SINK]

**验证说明**: Similar to VULN-DF-DYN-002. libdcmi.so loaded via LD_LIBRARY_PATH. CheckInputFileValid validation weak for .so files.

**评分明细**: base: 30 | reachability: 25 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SA-COMMON-004] library_injection - CheckInputFileValid

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `csrc/utils/cpputils/filesystem.cpp:368-418` @ `CheckInputFileValid`
**模块**: common
**跨模块**: common → utils

**描述**: CheckInputFileValid 对 .so 文件类型不检查 owner 权限（FileTypePermission['so'].second=false），仅检查文件存在性、读取权限和大小。攻击者可在可写目录放置恶意 .so 文件并诱导程序通过 LD_LIBRARY_PATH 加载。

**漏洞代码** (`csrc/utils/cpputils/filesystem.cpp:368-418`)

```c
const std::map<std::string, std::pair<uint32_t, bool>> FileTypePermission = {
    {"json", {S_IRUSR, true}}, {"cpp", {S_IRUSR, false}},
    {"bin", {S_IRUSR, true}}, {"kernel", {S_IRUSR, true}},
    {"dump", {S_IRUSR, true}}, {"dir", {S_IRUSR, true}},
    {"so", {S_IRUSR, false}},  // 不检查 owner 权限
};
```

**达成路径**

CheckInputFileValid(path, "so") → FileTypePermission["so"] → skip CheckOwnerPermission → dlopen

**验证说明**: CheckInputFileValid for .so files skips owner check (FileTypePermission['so'].second=false). Design flaw - allows loading untrusted .so files. Contributes to library injection vulnerabilities.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SA-XMOD-001] credential_flow_attack - 跨模块数据流

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-426 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `多文件:1` @ `跨模块数据流`
**模块**: cross_module
**跨模块**: interface → argparser → profiling_core → common → utils

**描述**: 跨模块环境变量信任链攻击。LD_LIBRARY_PATH环境变量被多个模块信任：argparser模块的FindExecutableCommand依赖PATH，profiling_core模块的CheckSimulatorSoExist通过GetSoFromEnvVar加载库，common模块的RuntimeHelper/HalHelper通过LD_LIBRARY_PATH加载.so。攻击者篡改环境变量可实现：1) 恶意可执行文件替换 2) 恶意动态库注入 3) 任意代码执行。信任边界不一致：interface入口标记为untrusted_local但环境变量在各模块被视为trusted_admin。

**漏洞代码** (`多文件:1`)

```c
数据流：main.cpp(untrusted_local) → argparser(FindExecutableCommand:getenv("PATH")) → profiling_core(GetSoFromEnvVar:getenv("LD_LIBRARY_PATH")) → common(dlopen)
```

**达成路径**

[SOURCE] getenv("LD_LIBRARY_PATH/PATH") → [MODULE1] argparser:FindExecutableCommand → [MODULE2] profiling_core:CheckSimulatorSoExist → [MODULE3] common:RuntimeHelper::Init → [SINK] dlopen/posix_spawnp

**验证说明**: Cross-module environment variable trust chain. Multiple modules trust LD_LIBRARY_PATH/PATH without consistent validation. Attack requires environment control at process start. Combines findings from individual library injection vulnerabilities. Complexity is higher as attack must work across module boundaries.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-001] untrusted_search_path - Task::CheckSimulatorSoExist

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/op_profiling/profiling/op_prof_task.cpp:36-51` @ `Task::CheckSimulatorSoExist`
**模块**: profiling_core
**跨模块**: profiling_core → utils

**描述**: dlopen动态加载仿真器库时，库路径来源于LD_LIBRARY_PATH环境变量。虽然使用了Realpath进行路径规范化防止路径遍历，但环境变量仍可能被攻击者控制，存在加载恶意动态库的风险。

**漏洞代码** (`csrc/op_profiling/profiling/op_prof_task.cpp:36-51`)

```c
std::string simulatorSo = GetSoFromEnvVar("libruntime_camodel.so");
...
simulatorSo = Realpath(simulatorSo);
...
void *rtHandle = dlopen(simulatorSo.c_str(), RTLD_LAZY);
```

**达成路径**

getenv("LD_LIBRARY_PATH") [SOURCE] → GetSoFromEnvVar() @ ascend_helper.cpp:135 → Realpath() @ filesystem.h:258 [SANITIZATION] → dlopen() @ op_prof_task.cpp:44 [SINK]

**验证说明**: Duplicate/variant of library injection via LD_LIBRARY_PATH. CheckSimulatorSoExist uses GetSoFromEnvVar with Realpath. Same threat model as Critical vulnerabilities.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-006] command_injection - SymbolizerParser::SymbolizerPartAddr

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/op_profiling/profiling/op_prof_data_parse.cpp:193-232` @ `SymbolizerParser::SymbolizerPartAddr`
**模块**: profiling_core
**跨模块**: profiling_core → utils

**描述**: User-controlled relocFilePath passed to CmdExecute via llvm-symbolizer command. relocFilePath comes from user-provided kernel binary path and is added to command arguments. Although execvp is used (no shell), the executable path argument is user-controlled.

**漏洞代码** (`csrc/op_profiling/profiling/op_prof_data_parse.cpp:193-232`)

```c
std::vector<std::string> cmd = {symbolizerPath, "-f", "-e", relocFilePath_, ...};
...
CmdExecute(partCmd, env, partOutput)
```

**达成路径**

json_parser.cpp:246 kernelConfig.kernelBinaryPath [SOURCE] → op_prof_data_parse.cpp:157 relocFilePath_ → op_prof_data_parse.cpp:193 cmd vector → op_prof_data_parse.cpp:232 CmdExecute → cmd_execute.cpp:133 execvp() [SINK]

**验证说明**: User-controlled relocFilePath passed to llvm-symbolizer command. execvp prevents shell injection. Path comes from user kernel binary config. The executable argument (symbolizerPath) is fixed, only the -e argument (relocFilePath) is user-controlled. Attack requires attacker to provide malicious kernel binary path that gets passed to symbolizer tool.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-DF-VAL-001] insufficient_permission_check - CheckInputFileValid

**严重性**: Medium | **CWE**: CWE-732 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/utils/cpputils/filesystem.cpp:368-372` @ `CheckInputFileValid`
**模块**: common

**描述**: CheckInputFileValid() in filesystem.cpp explicitly skips owner permission verification for .so files (FileTypePermission map has {"so", {S_IRUSR, false}}). The false flag prevents CheckOwnerPermission() from being called (line 408). This means any user-readable .so file can pass validation regardless of ownership, weakening protection against library injection attacks.

**漏洞代码** (`csrc/utils/cpputils/filesystem.cpp:368-372`)

```c
const std::map<std::string, std::pair<uint32_t, bool>> FileTypePermission = {
    {"json", {S_IRUSR, true}}, {"cpp", {S_IRUSR, false}},
    {"bin", {S_IRUSR, true}}, {"kernel", {S_IRUSR, true}},
    {"dump", {S_IRUSR, true}}, {"dir", {S_IRUSR, true}},
    {"so", {S_IRUSR, false}},  // false = skip owner check
};
```

**达成路径**

Internal validation configuration flaw - .so file type configured to skip owner permission check, affecting all dlopen operations that use CheckInputFileValid for validation.

**验证说明**: FileTypePermission map has 'so' with second=false, skipping owner check. This is root cause of library injection weakness. Design flaw affecting all .so loading paths.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SA-XMOD-004] data_integrity_breach - 跨模块路径遍历

**严重性**: Medium（原评估: Critical → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `多文件:1` @ `跨模块路径遍历`
**模块**: cross_module
**跨模块**: interface → argparser → profiling_simulator → parse

**描述**: 跨模块路径遍历攻击链。interface入口接收用户控制的数据路径，经过argparser的NormalizeConfig获取绝对路径但缺少完整验证，最终在profiling_simulator的GetObjectOutPathAndCopyAicoreFile读取object_dump.txt中的路径并直接使用。完整的攻击链：用户通过CLI控制输入 → argparser部分验证 → profiling_device生成数据文件 → profiling_simulator读取篡改后的数据文件路径 → 写入任意位置。这是最严重的跨模块漏洞。

**漏洞代码** (`多文件:1`)

```c
interface:main → argparser:NormalizeConfig(缺少CheckInputFileValid) → profiling_simulator:GetObjectOutPathAndCopyAicoreFile(fileLines[0]直接使用)
```

**达成路径**

[SOURCE] argv:--config/JSON:kernel_path → [MODULE1] interface:ProfArgsInit → [MODULE2] argparser:NormalizeConfig(no CheckInputFileValid) → [MODULE3] profiling_simulator:object_dump.txt → [SINK] MkdirRecusively/CopyFile/chmod到任意路径

**验证说明**: Cross-module path traversal chain requires multiple conditions: 1) Attacker controls --config/JSON kernel_path input, 2) argparser NormalizeConfig lacks CheckInputFileValid (only GetAbsolutePath), 3) profiling_simulator reads object_dump.txt from intermediate location. Attack complexity is high - requires tampering intermediate files in output directory. The chain is partially validated at output path level.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-ARG-001] path_traversal - ArgChecker::CheckOutputPathValid

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/op_profiling/argparser/arg_checker.cpp:246-257` @ `ArgChecker::CheckOutputPathValid`
**模块**: argparser

**描述**: Symlink check in CheckOutputPathValid only logs warning but allows operation to continue (LogWarn at line 247). An attacker can create symlink in output path to redirect profiling data to attacker-controlled location, potentially causing data leakage or overwrite of critical files.

**漏洞代码** (`csrc/op_profiling/argparser/arg_checker.cpp:246-257`)

```c
if (IsSoftLinkRecursively(checkPath)) {
    LogWarn("Output path contains soft link, may cause security problems");
}
// Operation continues - symlink not blocked
```

**达成路径**

argv (CLI input) -> ArgParser::Parse -> ArgChecker::Check -> CheckOutputPathValid -> IsSoftLinkRecursively [WARN ONLY] -> Output path used without blocking

**验证说明**: Symlink check in CheckOutputPathValid only logs warning, operation continues. Attack requires: 1) Attacker creates symlink in existing output path directory, 2) Profiling writes data through symlink. Lower impact - primarily data redirection rather than arbitrary write. Requires local access to output directory.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SA-XMOD-002] trust_boundary_inconsistency - 跨模块符号链接处理

**严重性**: Medium | **CWE**: CWE-732 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `多文件:1` @ `跨模块符号链接处理`
**模块**: cross_module
**跨模块**: interface → argparser → profiling_simulator → utils

**描述**: 跨模块符号链接检查不一致。argparser模块的CheckOutputPathValid和utils模块的CheckInputFileValid发现符号链接仅警告不阻止（LogWarn），但interface模块的入口点标记为untrusted_local。攻击者可通过符号链接链：1) interface入口接收用户路径 → 2) argparser警告但不阻止 → 3) profiling_simulator模块写入数据到符号链接指向的任意位置。导致数据泄露或敏感文件覆盖。

**漏洞代码** (`多文件:1`)

```c
arg_checker.cpp:247 LogWarn("soft link") → sim_data_parse.cpp:189 MkdirRecusively(outPath)
```

**达成路径**

[SOURCE] argv:--output → [MODULE1] interface:ProfArgsInit → [MODULE2] argparser:CheckOutputPathValid(IsSoftLinkRecursively:WARN_ONLY) → [MODULE3] profiling_simulator:ParseExportDumpFile → [SINK] MkdirRecusively/CopyFile

**验证说明**: Cross-module symlink inconsistency. Medium threat.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-007] command_injection - HotSpotFunctionGenerator::GenFdata

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/op_profiling/profiling/device/data_parse/hotspot_function_generator.cpp:534-539` @ `HotSpotFunctionGenerator::GenFdata`
**模块**: profiling_core
**跨模块**: profiling_core → device_data_parse

**描述**: User-controlled paths (bbmapPath, extraPath) passed to bisheng-tune command via CmdExecute. Paths are concatenated into command arguments. execvp is used so shell metacharacters are not interpreted, but paths are still user-controlled.

**漏洞代码** (`csrc/op_profiling/profiling/device/data_parse/hotspot_function_generator.cpp:534-539`)

```c
std::vector<std::string> cmd = {"bisheng-tune", "--action=analyze-profile", "--bbbmap=" + bbmapPath, extraPath, "-o=" + fdataPath};
CmdExecute(cmd, {}, output)
```

**达成路径**

User-provided bbmapPath, extraPath, fdataPath [SOURCE] → hotspot_function_generator.cpp:534-536 cmd construction → hotspot_function_generator.cpp:539 CmdExecute → cmd_execute.cpp:133 execvp() [SINK]

**验证说明**: User paths passed to bisheng-tune command. execvp prevents shell injection. Paths come from profiling config. Limited impact - bisheng-tune is Ascend tool. Attack requires controlling intermediate profiling data paths.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-008] command_injection - HotSpotFunctionGenerator::GenTlvdata

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/op_profiling/profiling/device/data_parse/hotspot_function_generator.cpp:565-570` @ `HotSpotFunctionGenerator::GenTlvdata`
**模块**: profiling_core
**跨模块**: profiling_core → device_data_parse

**描述**: User-controlled kernelPath passed to bisheng-tune command via CmdExecute for TLV data generation. Path is concatenated into command arguments. execvp prevents shell interpretation but path is user-controlled.

**漏洞代码** (`csrc/op_profiling/profiling/device/data_parse/hotspot_function_generator.cpp:565-570`)

```c
std::vector<std::string> cmd = {"bisheng-tune", kernelPath, "--lrm=count", "--lrm-output=" + lrmPath};
CmdExecute(cmd, {}, output)
```

**达成路径**

User-provided kernelPath [SOURCE] → hotspot_function_generator.cpp:565-567 cmd construction → hotspot_function_generator.cpp:570 CmdExecute → cmd_execute.cpp:133 execvp() [SINK]

**验证说明**: Similar to VULN-DF-007. kernelPath passed to bisheng-tune. execvp prevents shell injection. Attack complexity similar.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-ARG-002] permission_check_bypass - CheckOwnerPermission

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-732 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/utils/cpputils/filesystem.cpp:621-639` @ `CheckOwnerPermission`
**模块**: argparser
**跨模块**: argparser → utils/cpputils

**描述**: CheckOwnerPermission returns true even when file is NOT owned by current user (line 637-638). Function logs warning but allows operation. Attacker-controlled directories can be used as output/export paths, enabling data manipulation or race condition attacks.

**漏洞代码** (`csrc/utils/cpputils/filesystem.cpp:621-639`)

```c
if (fileStat.st_uid == 0 || fileStat.st_uid == static_cast<uint32_t>(getuid())) {
    return true;
}
LogWarn("%s is not owned by the current user, which may cause security problems", path.c_str());
return true;  // SECURITY: Returns true even for non-owner
```

**达成路径**

argv -> ArgParser::Parse -> ArgChecker::CheckOutputPathValid -> CheckOwnerPermission -> returns true for non-owner paths

**验证说明**: CheckOwnerPermission returns true even for non-owner paths (warning only). This is design choice for usability - allows using system directories. Lower security impact as attacker needs write permission in non-owner directory anyway. More of a design weakness than exploitable vulnerability.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SA-XMOD-003] permission_bypass_chain - 跨模块权限检查

**严重性**: Medium | **CWE**: CWE-732 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `多文件:1` @ `跨模块权限检查`
**模块**: cross_module
**跨模块**: argparser → utils → profiling_simulator

**描述**: 跨模块权限检查绕过链。utils模块的CheckOwnerPermission函数（filesystem.cpp:621-639）对非owner文件返回true（仅警告），导致argparser模块的CheckOutputPathValid允许使用攻击者可控目录作为输出路径。信任边界被穿透：argparser信任utils的权限检查结果，但utils实际上不阻止非owner路径。攻击者可在可控目录放置恶意文件或符号链接。

**漏洞代码** (`多文件:1`)

```c
filesystem.cpp:637-638 return true (非owner) → arg_checker.cpp:251 CheckOwnerPermission → sim_data_parse.cpp
```

**达成路径**

[SOURCE] argv:--output → [MODULE1] argparser:CheckOutputPathValid → [MODULE2] utils:CheckOwnerPermission(return true for non-owner) → [MODULE3] profiling_simulator → [SINK] write to attacker-controlled path

**验证说明**: Cross-module permission bypass. Medium threat.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (6)

### [VULN-SEC-INT-004] external_control_file_path - NormalizeConfig

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-73 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/op_profiling/argparser/arg_normalize.cpp:101-107` @ `NormalizeConfig`
**模块**: interface
**跨模块**: interface → argparser → utils

**描述**: 配置文件参数缺少完整验证。--config参数通过NormalizeConfig获取绝对路径，但后续没有调用CheckInputFileValid进行完整验证，缺少符号链接检查、路径遍历检查和权限验证。

**漏洞代码** (`csrc/op_profiling/argparser/arg_normalize.cpp:101-107`)

```c
bool ArgNormalize::NormalizeConfig(Common::ProfArgs &config, std::string &msg) const {
    if (config.argConfig.empty()) { return true; }
    return NormalizeOptionPath(config.argConfig, msg, "config");
}
```

**达成路径**

main.cpp:28 ProfArgsInit() → arg_normalize.cpp:101-107 NormalizeConfig() → [缺少CheckInputFileValid调用] → json_parser.cpp:401 ParseRunConfigJson()

**验证说明**: --config path lacks CheckInputFileValid after NormalizeConfig. NormalizeConfig only calls NormalizeOptionPath (GetAbsolutePath). JSON content paths may bypass validation. Attack requires malicious config file with crafted paths.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-004] arbitrary_file_link - SimulatorTask::RuntimeToTargetLib

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-61 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/op_profiling/profiling/simulator/run/simulator_task.cpp:59-83` @ `SimulatorTask::RuntimeToTargetLib`
**模块**: profiling_core

**描述**: RuntimeToTargetLib函数在用户可控路径创建符号链接(soName = JoinPath({runtimePath, "libruntime.so"}))，runtimePath来自CAMODEL_LOG_PATH环境变量（由用户输出路径控制）。攻击者可能通过控制输出路径在任意位置创建指向恶意库的符号链接。

**漏洞代码** (`csrc/op_profiling/profiling/simulator/run/simulator_task.cpp:59-83`)

```c
std::string soName = JoinPath({runtimePath, "libruntime.so"});
...
if (symlink(targetPath.c_str(), soName.c_str()) != 0) {...}
```

**达成路径**

env["CAMODEL_LOG_PATH"] = tmpPath_ [USER_INPUT] → RuntimeToTargetLib(runtimePath) → symlink(targetPath, soName) [SINK]

**验证说明**: Symlink creation in user-controlled output directory. runtimePath comes from CAMODEL_LOG_PATH which is derived from tmpPath_ (user output). Attack requires controlling output directory. symlink to arbitrary path - limited by directory permissions.

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-INT-001] symlink_attack - CheckInputFileValid

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-59 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/utils/cpputils/filesystem.cpp:382-384` @ `CheckInputFileValid`
**模块**: interface
**跨模块**: interface → argparser → utils

**描述**: 符号链接检查仅输出警告不阻止操作。IsSoftLinkRecursively 函数检测到路径包含符号链接时只输出 LogWarn 警告，不阻止后续操作，可能允许攻击者通过符号链接绕过路径检查访问敏感文件。

**漏洞代码** (`csrc/utils/cpputils/filesystem.cpp:382-384`)

```c
if (IsSoftLinkRecursively(absPath)) {
    LogWarn("Input parameter%s path contains softlink, may cause security problems", paramName.c_str());
}
```

**达成路径**

main.cpp:28 ProfArgsInit() → arg_normalize.cpp:101-107 NormalizeConfig() → arg_checker.cpp CheckApplicationValid() → filesystem.cpp:364-418 CheckInputFileValid() [在此只警告不阻断]

**验证说明**: Symlink check warning-only in CheckInputFileValid. Same issue as other symlink warnings. Low impact - primarily informational file access.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-ARG-001] path_traversal - GetAbsolutePath

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `csrc/utils/cpputils/filesystem.cpp:291-322` @ `GetAbsolutePath`
**模块**: argparser

**描述**: GetAbsolutePath() in filesystem.cpp uses manual path resolution without realpath(), potentially allowing symlink-based path traversal. User-provided paths (--output, --config, --export) flow through NormalizeOptionPath which calls GetAbsolutePath, but unresolved symlinks or '..' sequences may bypass intended directory restrictions.

**漏洞代码** (`csrc/utils/cpputils/filesystem.cpp:291-322`)

```c
std::string GetAbsolutePath(std::string const &path) {
    std::string absPath = path;
    // ... manually resolves '..' and '.' without realpath()
    std::vector<std::string> dirs;
    // ...
    return "/" + JoinPath(dirs);
}
```

**达成路径**

argv (interface) → ProfArgsParse → ProfArgsNormalize → NormalizeOptionPath → GetAbsolutePath [SINK]
User input: --output/--config/--export options

**验证说明**: GetAbsolutePath manually resolves .. without realpath. Symlink traversal possible. Partial mitigation by manual .. handling. Lower threat.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-ARG-003] untrusted_search_path - FindExecutableCommand

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-426 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner, security-auditor

**位置**: `csrc/utils/cpputils/filesystem.cpp:581-604` @ `FindExecutableCommand`
**模块**: argparser

**描述**: FindExecutableCommand() searches PATH environment variable to resolve relative command names. An attacker can manipulate PATH to point to malicious executables, causing unintended program execution. Called from NormalizeApp when processing --application argument.

**漏洞代码** (`csrc/utils/cpputils/filesystem.cpp:581-604`)

```c
const char *env = getenv("PATH");
if (env && !std::string(env).empty()) {
    SplitString(std::string(env), ':', paths);
}
for (auto &dir : paths) {
    dir.append("/" + command);
    if (!IsDir(dir) && IsExecutable(dir)) {
        return dir;  // Returns first executable found in PATH
    }
}
```

**达成路径**

argv → ProfArgsParse → args.argApplication → NormalizeApp → FindExecutableCommand [SINK]
PATH env var (attacker-controlled) → executable resolution

**验证说明**: FindExecutableCommand searches PATH for command resolution. This is standard behavior similar to shell command lookup. Attack requires controlling PATH AND having malicious executable with matching name in PATH directory. CheckApplicationValid validates existence and executability. Combined with VULN-DF-OPRUNNER-001 assessment - this is expected tool behavior, not vulnerability.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN-SA-PARSE-001] path_traversal - ParsePcCode::GetPcSetByKernelName

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `csrc/op_profiling/parse/data_parser/parser_utils/parse_pc_code.cpp:203-207` @ `ParsePcCode::GetPcSetByKernelName`
**模块**: parse
**跨模块**: parse → utils → interface

**描述**: User-controlled file path passed to llvm-objdump command execution. The dumpPath_ parameter originates from CLI arguments (outputPath) and is used to construct aicoreFilePath without proper path validation or sanitization. While the command execution uses execvpe (mitigating shell injection), a malicious user could potentially manipulate the path to read arbitrary files via symbolic links or relative path traversal.

**漏洞代码** (`csrc/op_profiling/parse/data_parser/parser_utils/parse_pc_code.cpp:203-207`)

```c
std::string aicoreFilePath = Utility::JoinPath({dumpPath_, Common::AICORE_KERNEL_NAME});
std::string output;
std::map<std::string, std::string> envs;
bool result = Utility::CmdExecute({"llvm-objdump", "-t", aicoreFilePath}, envs, output);
```

**达成路径**

CLI args(main.cpp) → outputPath → RealTimeDataParser::Start(line 292) → outputPath_ → ParsePcCode(dumpPath_) → JoinPath → CmdExecute → execvpe

**验证说明**: User dumpPath_ passed to llvm-objdump. execvpe safe.

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| argparser | 0 | 0 | 2 | 2 | 4 |
| common | 0 | 3 | 4 | 0 | 7 |
| cross_module | 0 | 0 | 4 | 0 | 4 |
| interface | 0 | 0 | 0 | 2 | 2 |
| parse | 0 | 0 | 0 | 1 | 1 |
| profiling_core | 0 | 5 | 4 | 1 | 10 |
| profiling_simulator | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **9** | **14** | **6** | **29** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-426 | 14 | 48.3% |
| CWE-22 | 5 | 17.2% |
| CWE-732 | 4 | 13.8% |
| CWE-78 | 3 | 10.3% |
| CWE-73 | 1 | 3.4% |
| CWE-61 | 1 | 3.4% |
| CWE-59 | 1 | 3.4% |

---

## 8. 修复建议

### 优先级 1: 立即修复（High 严重性）

#### 8.1 动态库加载安全加固

**影响范围**：9 个 High 严重性漏洞，涉及 RuntimeHelper、HalHelper、Task 等组件

**修复方案**：

```cpp
// 1. 统一添加完整性验证（runtime_helper.cpp, hal_helper.cpp）
std::string soName = GetSoFromEnvVar("libruntime_camodel.so");
if (soName.empty() || !CheckInputFileValid(soName, "so")) {
    LogError("Library path validation failed");
    return;
}
// 修复 CheckInputFileValid 对 .so 文件的所有者检查
// filesystem.cpp:372 将 {"so", {S_IRUSR, false}} 改为 {"so", {S_IRUSR, true}}

// 2. 生产模式路径验证（runtime_helper.cpp:55）
} else {
    soName = ascendHomePath + "/lib64/libruntime.so";
    if (!CheckInputFileValid(soName, "so")) {  // 添加缺失的验证
        LogError("Invalid runtime library");
        return;
    }
}

// 3. 添加库签名验证（可选但推荐）
bool ValidateLibrarySignature(const std::string& path) {
    // 计算文件哈希并与预置哈希比对
    // 或验证数字签名
}
```

#### 8.2 环境变量信任边界修正

**影响范围**：ASCEND_HOME_PATH、LD_LIBRARY_PATH 环境变量

**修复方案**：

```cpp
// ascend_helper.cpp:28-46
bool GetAscendHomePath(std::string &ascendHomePath) {
    // 添加白名单验证
    const std::vector<std::string> allowedInstallPaths = {
        "/usr/local/Ascend",
        "/opt/Ascend/ascend-toolkit",
        getenv("HOME") + "/Ascend"
    };
    
    char const *env = getenv("ASCEND_HOME_PATH");
    if (env == nullptr) { return false; }
    
    std::string pathFromEnv = env;
    // 规范化
    char buf[PATH_MAX];
    if (realpath(pathFromEnv.c_str(), buf) == nullptr) { return false; }
    
    // 白名单检查（新增）
    bool inWhitelist = false;
    for (const auto& allowed : allowedInstallPaths) {
        if (strncmp(buf, allowed.c_str(), allowed.length()) == 0) {
            inWhitelist = true;
            break;
        }
    }
    if (!inWhitelist) {
        LogError("ASCEND_HOME_PATH not in trusted installation paths");
        return false;
    }
    
    ascendHomePath = buf;
    return true;
}
```

### 优先级 2: 短期修复（Medium 严重性）

#### 8.3 路径遍历防护

**影响范围**：5 个路径遍历相关漏洞

**修复方案**：

```cpp
// sim_data_parse.cpp:183-223
bool SimDataParse::GetObjectOutPathAndCopyAicoreFile(...) {
    // 添加路径验证
    outPath = fileLines[0];
    outPath = Realpath(outPath);  // 规范化
    
    // 白名单检查
    std::string expectedOutputBase = GetExpectedOutputPath();  // 从配置获取
    if (!IsSubPath(outPath, expectedOutputBase)) {
        LogError("Output path escapes expected directory");
        return false;
    }
    
    // 检查符号链接
    if (IsSoftLink(outPath)) {
        LogError("Output path contains symlink");
        return false;
    }
    // 继续处理...
}

// filesystem.cpp 路径辅助函数
bool IsSubPath(const std::string& path, const std::string& base) {
    std::string normPath = Realpath(path);
    std::string normBase = Realpath(base);
    return normPath.find(normBase) == 0;
}
```

#### 8.4 权限检查强化

**影响范围**：CheckInputFileValid、CheckOwnerPermission 函数

**修复方案**：

```cpp
// filesystem.cpp:368-373 修复配置
const std::map<std::string, std::pair<uint32_t, bool>> FileTypePermission = {
    {"json", {S_IRUSR, true}},
    {"cpp", {S_IRUSR, true}},  // 改为 true（原来是 false）
    {"bin", {S_IRUSR, true}},
    {"kernel", {S_IRUSR, true}},
    {"dump", {S_IRUSR, true}},
    {"dir", {S_IRUSR, true}},
    {"so", {S_IRUSR, true}},   // 关键修复：启用所有者检查
};

// filesystem.cpp:382-384 符号链接处理
if (IsSoftLinkRecursively(absPath)) {
    LogError("Path contains symlink, operation blocked");  // 改为阻止
    return false;  // 不允许继续操作
}

// filesystem.cpp:621-639 所有者检查
if (fileStat.st_uid != 0 && fileStat.st_uid != static_cast<uint32_t>(getuid())) {
    LogError("%s is not owned by trusted user", path.c_str());
    return false;  // 改为返回 false（原来是返回 true）
}
```

#### 8.5 命令执行安全

**影响范围**：3 个命令注入相关漏洞（CWE-78）

**修复方案**：

```cpp
// op_prof_data_parse.cpp, hotspot_function_generator.cpp
// 已使用 execvp 避免 shell 注入，建议添加路径白名单

std::vector<std::string> cmd = {symbolizerPath, "-f", "-e", relocFilePath_};
// 验证所有路径参数
if (!ValidateToolPath(symbolizerPath) || !ValidateInputPath(relocFilePath_)) {
    LogError("Invalid command parameters");
    return false;
}
CmdExecute(cmd, env, output);
```

### 优先级 3: 计划修复（Low 严重性）

#### 8.6 路径处理规范化

**影响范围**：GetAbsolutePath、FindExecutableCommand

**修复方案**：

```cpp
// filesystem.cpp:291-322 使用 realpath 替代手动解析
std::string GetAbsolutePath(std::string const &path) {
    char buf[PATH_MAX];
    if (realpath(path.c_str(), buf) != nullptr) {
        return std::string(buf);
    }
    // fallback 处理...
}

// filesystem.cpp:581-604 添加可执行文件路径验证
std::string FindExecutableCommand(const std::string& command) {
    // 添加白名单：只允许从系统目录搜索
    const std::vector<std::string> trustedPaths = {
        "/usr/bin", "/usr/local/bin", "/opt/Ascend/bin"
    };
    // 在 trustedPaths 中搜索而非完整 PATH
}
```

#### 8.7 符号链接处理策略

**影响范围**：多处符号链接检查仅警告不阻止

**修复方案**：

统一符号链接处理策略：所有安全敏感路径（库文件、配置文件、输出路径）遇到符号链接应阻止操作，而非仅警告。

---

## 9. 附录：安全加固部署建议

### 9.1 运行环境配置

| 配置项 | 建议 |
|--------|------|
| ASCEND_HOME_PATH | 通过部署脚本固定为可信安装路径，禁止用户覆盖 |
| LD_LIBRARY_PATH | 不依赖此变量，使用 RPATH 编译时嵌入库路径 |
| 输出目录权限 | 设置 750 权限，仅允许工具用户写入 |
| 配置文件权限 | 设置 640 权限，禁止非所有者修改 |

### 9.2 部署场景风险评估

| 场景 | 风险等级 | 加固建议 |
|------|----------|----------|
| 单用户本地使用 | 低 | 标准部署即可 |
| 多用户共享系统 | 中 | 使用专用用户运行，限制环境变量继承 |
| sudo 执行 | 高 | 使用 sudo 环境变量过滤（`sudo --reset-env`） |
| 容器环境 | 高 | 使用只读挂载关键库目录，固定环境变量 |
| CI/CD 自动化 | 高 | 完全固定环境变量和路径配置 |

### 9.3 持续安全监控

1. **定期安全扫描**：每次版本发布前执行漏洞扫描
2. **环境变量审计**：监控 ASCEND_HOME_PATH、LD_LIBRARY_PATH 的异常设置
3. **库文件完整性校验**：定期校验关键库文件哈希值
4. **日志审计**：记录所有 dlopen、命令执行操作用于审计
