# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio Profiler Analyze (msprof-analyze)
**扫描时间**: 2026-04-20T21:51:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本次漏洞扫描对 MindStudio Profiler Analyze (msprof-analyze) 项目进行了全面的安全审计。扫描发现的 5 个候选漏洞均已通过人工验证，全部被判定为误报 (FALSE_POSITIVE)。

**扫描结论**: 本次扫描 **未发现待确认的安全漏洞**。

所有候选漏洞均与 SQL 注入相关，但验证过程确认：
- SQL 查询中的表名参数来源于硬编码常量 (`Constant.TABLE_*`)
- 不存在用户可控输入到达 SQL 语句的路径
- 数据库查询使用安全的参数化方式

因此，本报告中 **无 LIKELY 或 POSSIBLE 状态的漏洞需进一步确认**。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 5 | 100.0% |
| **总计** | **5** | 100% |

**说明**: 无 LIKELY 或 POSSIBLE 状态的漏洞。

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 5 | - |

### 1.3 Top 10 关键漏洞

**无待确认漏洞**

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `msprof_analyze_cli@msprof_analyze/cli/entrance.py` | cmdline | untrusted_local | CLI 入口函数，用户通过命令行调用 msprof-analyze 命令，参数由本地用户控制 | 主 CLI 入口点，处理 msprof-analyze 命令及其子命令 (advisor, compare, cluster) |
| `analyze_all@msprof_analyze/cli/analyze_cli.py` | cmdline | untrusted_local | advisor 子命令入口，用户通过 -d 参数指定 profiling 数据路径，路径由用户控制 | advisor all 子命令，分析 timeline fusion operators、operators、dispatching 和 cluster |
| `cluster_cli@msprof_analyze/cli/cluster_cli.py` | cmdline | untrusted_local | cluster 子命令入口，用户通过 -d 参数指定 profiling 数据路径，路径由用户控制 | cluster 子命令，分析集群数据定位性能瓶颈 |
| `compare_cli@msprof_analyze/cli/compare_cli.py` | cmdline | untrusted_local | compare 子命令入口，用户指定 GPU/NPU profiling 数据路径进行比对 | compare 子命令，对比 GPU/NPU 性能差异 |
| `read_json_file@msprof_analyze/prof_common/file_manager.py` | file | untrusted_local | 读取用户指定的 JSON 文件，文件内容由用户控制 | 读取 JSON profiling 数据文件 |
| `read_csv_file@msprof_analyze/prof_common/file_manager.py` | file | untrusted_local | 读取用户指定的 CSV 文件，文件内容由用户控制 | 读取 CSV profiling 数据文件 |
| `read_yaml_file@msprof_analyze/prof_common/file_manager.py` | file | untrusted_local | 读取用户指定的 YAML 文件，使用 yaml.safe_load 解析 | 读取 YAML 配置文件 |
| `create_connect_db@msprof_analyze/prof_common/db_manager.py` | file | untrusted_local | 连接用户指定的 SQLite 数据库文件，数据库内容由用户控制 | 创建并连接 SQLite 数据库 |
| `_parse_csv@msprof_analyze/advisor/dataset/profiling/profiling_parser.py` | file | untrusted_local | 解析用户提供的 CSV profiling 数据文件 | 解析 CSV 格式的 profiling 数据 |
| `_parse_json@msprof_analyze/advisor/dataset/profiling/profiling_parser.py` | file | untrusted_local | 解析用户提供的 JSON profiling 数据文件 | 解析 JSON 格式的 profiling 数据 |
| `get_analyze_processes@msprof_analyze/advisor/utils/utils.py` | env | untrusted_local | 读取环境变量 ADVISOR_ANALYZE_PROCESSES，本地用户可设置 | 从环境变量获取分析进程数 |
| `get_logger@msprof_analyze/prof_common/logger.py` | env | untrusted_local | 读取环境变量 MSPROF_ANALYZE_LOG_LEVEL 设置日志级别，本地用户可设置 | 从环境变量获取日志级别配置 |
| `_load_timeline_data@msprof_analyze/advisor/dataset/timeline_event_dataset.py` | file | untrusted_local | 读取用户提供的 timeline 数据文件 | 加载 timeline event 数据 |
| `_parse_json_file@msprof_analyze/compare_tools/compare_backend/profiling_parser/base_profiling_parser.py` | file | untrusted_local | 解析用户提供的 JSON profiling 数据文件 | 解析 profiling JSON 文件 |

**其他攻击面**:
- 命令行参数输入: profiling_path (-d), output_path (-o), benchmark_profiling_path (-bp)
- 文件输入: JSON, CSV, YAML, SQLite DB profiling 数据文件
- 环境变量: MSPROF_ANALYZE_LOG_LEVEL, ADVISOR_ANALYZE_PROCESSES, ADVISOR_LOG_LEVEL
- SQLite 数据库查询: 用户提供的 DB 文件中的 SQL 查询
- YAML 配置解析: environment_variable_info.yaml 等配置文件

---

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|

---

## 误报详细说明

本次扫描中发现的 5 个 SQL 注入候选漏洞均被验证为误报。以下是验证过程的关键发现：

### VULN-SEC-SQL-001 至 VULN-SEC-SQL-005 验证结论

**误报原因**: SQL 查询中的动态表名参数来源于硬编码常量类 `Constant.TABLE_*`，而非用户可控输入。

验证过程中确认：
1. **数据流追踪**: 从入口点到 SQL 查询的数据流路径中，表名参数始终来源于常量定义
2. **常量约束**: 项目使用 `Constant` 类集中管理数据库表名，确保表名不可被外部修改
3. **参数化查询**: SQL 查询中的动态值（如 `value_form`）使用参数化绑定方式

### 安全设计评价

项目在 SQL 查询设计上采用了以下安全措施，有效防止了 SQL 注入风险：

| 安全措施 | 实现方式 | 效果 |
|----------|----------|------|
| 表名常量化 | `Constant.TABLE_*` 常量定义 | 防止表名动态拼接 |
| 参数化查询 | 使用参数绑定而非字符串拼接 | 防止值注入 |
| 输入隔离 | 硬编码常量与用户输入分离 | 阻断攻击路径 |

---

## 附录：验证统计

| 统计项 | 数值 |
|--------|------|
| 候选漏洞总数 | 5 |
| 已确认漏洞 (CONFIRMED) | 0 |
| 待确认漏洞 (LIKELY) | 0 |
| 可能漏洞 (POSSIBLE) | 0 |
| 误报 (FALSE_POSITIVE) | 5 |
| 误报率 | 100% |
| 主要误报类型 | SQL Injection |