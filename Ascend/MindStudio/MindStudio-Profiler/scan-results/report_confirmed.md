# 漏洞扫描报告 — 已确认漏洞

**项目**: MindStudio-Profiler
**扫描时间**: 2026-04-20T21:50:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次漏洞扫描对 MindStudio-Profiler 项目进行了全面的安全审计，共检测到 98 个候选漏洞，经人工验证后：
- **已确认漏洞 (CONFIRMED): 0 个** — 本次扫描未发现可明确确认的安全漏洞
- **疑似漏洞 (LIKELY): 1 个** — 需优先关注 PATH 劫持风险
- **可能漏洞 (POSSIBLE): 29 个** — 建议在后续迭代中逐步修复
- **误报 (FALSE_POSITIVE): 68 个** — 已过滤排除

虽然本次未发现确认漏洞，但检测到的 1 个疑似 PATH 劫持漏洞（置信度 65）在 root 权限运行场景下具有显著风险，建议优先评估和修复。其余 29 个可能漏洞主要集中在资源消耗、路径验证、SQL 注入等类别，虽置信度较低但仍建议在安全加固计划中纳入。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 68 | 69.4% |
| POSSIBLE | 29 | 29.6% |
| LIKELY | 1 | 1.0% |
| **总计** | **98** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 68 | - |

### 1.3 Top 10 关键漏洞


---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@analysis/msinterface/msprof_entrance.py` | cmdline | untrusted_local | CLI 工具的主入口，用户可通过命令行调用，提供的路径参数和数据目录由本地用户控制 | 主 CLI 入口，解析命令行参数并执行 export/query/import/analyze 子命令 |
| `_add_collect_path_argument@analysis/msinterface/msprof_entrance.py` | cmdline | untrusted_local | 接收用户提供的 collection_path 参数，该路径指向用户的性能数据目录，由用户完全控制 | 解析 -dir/--collection-dir 参数，接收用户数据目录路径 |
| `_add_reports_argument@analysis/msinterface/msprof_entrance.py` | cmdline | semi_trusted | 接收用户提供的 reports_path 参数（JSON 配置文件路径），配置文件需要用户有一定权限才能创建和修改 | 解析 --reports 参数，接收 JSON 配置文件路径 |
| `main@analysis/interface/get_msprof_info.py` | cmdline | untrusted_local | 基本信息查询工具的入口，用户通过命令行调用，提供的路径参数由本地用户控制 | 基本信息查询入口，接收 collection_path 参数 |
| `main@misc/host_analyzer/entrance.py` | cmdline | semi_trusted | 主机分析工具入口，接收配置文件路径参数，配置文件需要用户有一定权限才能创建 | 主机分析工具入口，接收 -c/--config 配置文件路径参数 |
| `ENABLE_LIBKPERF@misc/function_monitor/function_monitor.py` | env | semi_trusted | 通过环境变量 ENABLE_LIBKPERF 控制功能开关，环境变量由启动进程的用户设置 | 环境变量控制，启用/禁用 libkperf 功能 |
| `ENABLE_FUNCTION_MONITOR@misc/function_monitor/function_monitor.py` | env | semi_trusted | 通过环境变量 ENABLE_FUNCTION_MONITOR 控制功能开关，环境变量由启动进程的用户设置 | 环境变量控制，启用/禁用函数监控功能 |
| `get_log_path@misc/function_monitor/function_monitor.py` | env | semi_trusted | 通过环境变量 FUNCTION_MONITOR_LOG_PATH 设置日志路径，环境变量由启动进程的用户设置 | 环境变量控制，设置日志输出路径 |

**其他攻击面**:
- CLI 参数接口：用户提供的路径参数（collection_path、reports_path）
- 文件系统接口：用户提供的性能数据文件（二进制、CSV、JSON 格式）
- 配置文件接口：用户提供的 JSON 配置文件
- 环境变量接口：misc 工具通过环境变量控制功能开关和路径
- SQLite 数据库接口：工具生成的数据库文件（内部数据，风险较低）

---

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
