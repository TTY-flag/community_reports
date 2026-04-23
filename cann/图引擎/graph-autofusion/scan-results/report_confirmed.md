# 漏洞扫描报告 — 已确认漏洞

**项目**: graph-autofusion
**扫描时间**: 2026-04-22T00:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次漏洞扫描未发现任何 **已确认 (CONFIRMED)** 状态的安全漏洞。

扫描共识别出 **15 个候选漏洞**，经人工验证后：
- **CONFIRMED**: 0 个（本报告范围）
- **LIKELY**: 3 个（需要重点关注，详见 unconfirmed 报告）
- **POSSIBLE**: 5 个（潜在风险，详见 unconfirmed 报告）
- **FALSE_POSITIVE**: 7 个（已排除）

### 安全评估结论

**整体安全评级**: 中等风险

虽然未发现已确认漏洞，但存在 **3 个高置信度的潜在漏洞 (LIKELY)**，主要集中在：
1. **Shell 脚本命令注入** - 2 个 High 级别漏洞（eval 使用不当）
2. **动态函数执行** - 1 个 Medium 级别漏洞（函数名参数未验证）

这些潜在漏洞存在于软件包安装脚本 (`scripts/package/common/sh/`) 中，攻击者若能控制安装命令参数，可能实现命令注入。

**建议**: 优先修复 LIKELY 状态的 3 个漏洞，详见 `report_unconfirmed.md`。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 7 | 46.7% |
| POSSIBLE | 5 | 33.3% |
| LIKELY | 3 | 20.0% |
| **总计** | **15** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 7 | - |

### 1.3 Top 10 关键漏洞


---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `aclskOptimize@super_kernel/src/aot/super_kernel.cpp` | rpc | semi_trusted | C API 入口，接收 aclmdlRI 模型句柄和 aclskOptions 配置选项，来自上层 AI 框架调用 | 执行 Super Kernel 图优化，处理模型图并生成融合内核 |
| `aclskScopeBegin@super_kernel/src/aot/super_kernel.cpp` | rpc | semi_trusted | C API 入口，接收 scopeName 字符串参数和 stream 句柄 | 开始一个 Super Kernel scope 区域 |
| `aclskScopeEnd@super_kernel/src/aot/super_kernel.cpp` | rpc | semi_trusted | C API 入口，接收 scopeName 字符串参数和 stream 句柄 | 结束一个 Super Kernel scope 区域 |
| `GenEntryInfo@super_kernel/src/aot/sk_task_builder.cpp` | env | semi_trusted | 读取环境变量 ASCEND_PROF_SK_ON 和 ASCEND_SK_OP_TRACE_ON 配置 profiling 功能 | 生成 Super Kernel 入口信息，读取环境变量决定功能模式 |
| `InitSkLogger@super_kernel/src/aot/sk_log.h` | env | semi_trusted | 读取环境变量 ASCEND_OP_COMPILE_SAVE_KERNEL_META 控制日志输出 | 初始化日志系统，由环境变量控制 |
| `TryGenerateConstantFuncHandle@super_kernel/src/aot/sk_constant_codegen.cpp` | env | semi_trusted | 读取环境变量 SK_CONSTANT 控制常量代码生成 | 尝试生成常量化代码，由环境变量控制 |
| `SkEventRecorder::Init@super_kernel/src/aot/sk_event_recorder.cpp` | env | semi_trusted | 读取环境变量 ENV_SK_EVENT_RECORD 控制 profiling | 初始化事件记录器，由环境变量控制 |
| `gen_super_kernel_file@super_kernel/src/jit/superkernel/super_kernel.py` | decorator | semi_trusted | Python JIT 编译入口，接收 super_operator 配置对象，生成内核源文件 | 生成 Super Kernel 源代码文件 |
| `parse_super_kernel_options@super_kernel/src/jit/superkernel/super_kernel_option_parse.py` | cmdline | semi_trusted | 解析用户提供的编译选项字符串 | 解析 Super Kernel 编译选项 |
| `compile_sub_kernel@super_kernel/src/jit/superkernel/super_kernel_op_infos.py` | rpc | semi_trusted | 调用 subprocess.run 执行编译命令 | 编译子内核，调用外部编译工具 |
| `execute_packaging@scripts/package/package.py` | cmdline | semi_trusted | 打包脚本入口，接收命令行参数 | 执行软件包打包流程 |

**其他攻击面**:
- ACL C API: aclskOptimize/aclskScopeBegin/aclskScopeEnd - 接收模型句柄和配置选项
- 环境变量: ASCEND_PROF_SK_ON, ASCEND_SK_OP_TRACE_ON, ASCEND_OP_COMPILE_SAVE_KERNEL_META, SK_CONSTANT
- 配置选项结构体: aclskOptions (包含字符串列表和扩展选项)
- Python 编译选项: 通过 parse_super_kernel_options 解析的选项字符串
- 编译工具链调用: subprocess.run 执行的 ar/编译命令
- Shell 脚本 eval: 多处使用 eval 执行命令和赋值
- ELF 二进制解析: sk_common.cpp 直接解析内核二进制文件
- 文件写入: 内核源文件、日志文件、JSON dump 文件

---

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
