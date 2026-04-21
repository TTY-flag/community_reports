# 漏洞扫描报告 — 已确认漏洞

**项目**: MindStudio-Ops-Profiler
**扫描时间**: 2026-04-20T21:50:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次漏洞扫描对 MindStudio-Ops-Profiler 项目进行了全面的安全审计，扫描覆盖了 C/C++ 源代码中的关键安全风险点，重点关注动态库加载、命令执行、路径处理等攻击面。

**扫描结论**：本次扫描未发现已确认（CONFIRMED）的安全漏洞。然而，发现了 **29 个待确认漏洞**（LIKELY 和 POSSIBLE 状态），其中包括 9 个高严重性漏洞和 14 个中严重性漏洞。这些待确认漏洞主要涉及：

- **动态库注入风险**（CWE-426）：通过 LD_LIBRARY_PATH 或 ASCEND_HOME_PATH 环境变量控制库加载路径
- **路径遍历风险**（CWE-22）：用户可控的文件路径可能被用于任意文件操作
- **权限检查不足**（CWE-732）：部分验证函数对符号链接和文件所有权的检查不完整

建议在发布前对待确认漏洞进行人工复核，特别是涉及环境变量信任和动态库加载的漏洞类型。

---

## 重要说明

本次扫描共验证了 60 个候选漏洞，其中：

| 状态 | 数量 | 说明 |
|------|------|------|
| CONFIRMED | 0 | 无已确认漏洞 |
| LIKELY | 13 | 置信度 60-79，需人工复核 |
| POSSIBLE | 30 | 罋信度 40-59，建议评估 |
| FALSE_POSITIVE | 17 | 已排除的误报 |

**已确认漏洞数为 0，本报告为空报告。** 请参考 `report_unconfirmed.md` 查看 LIKELY 和 POSSIBLE 状态的漏洞详情。

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
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 17 | - |

### 1.3 Top 10 关键漏洞


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

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
