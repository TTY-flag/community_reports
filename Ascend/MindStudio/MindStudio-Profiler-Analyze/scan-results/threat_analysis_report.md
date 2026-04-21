# 娭胁分析报告 - MindStudio Profiler Analyze (msprof-analyze)

> **分析模式：自主分析模式**
> threat.md 约束文件不存在，本次攻击面分析由 AI 自主识别所有潜在入口点。

## 项目架构概览

### 项目定位

- **项目名称**: MindStudio Profiler Analyze (msprof-analyze)
- **项目类型**: Python CLI 工具 (cli_tool_python)
- **语言组成**: Python 439 文件（主要），C++ 1 文件（辅助）
- **总代码量**: 约 43,019 行 Python 代码
- **部署模型**: 用户本地执行的命令行工具，通过 pip 安装后使用 `msprof-analyze` 命令进行昇腾 AI 训练/推理性能数据分析

### 主要功能模块

| 模块 | 路径 | 语言 | 功能 | 风险等级 |
|------|------|------|------|----------|
| cli | msprof_analyze/cli | python | 命令行入口，处理用户输入 | Medium |
| prof_common | msprof_analyze/prof_common | python | 公共能力（文件管理、路径验证、数据库操作） | High |
| advisor | msprof_analyze/advisor | python | 专家建议模块，分析性能数据并给出优化建议 | High |
| cluster_analyse | msprof_analyze/cluster_analyse | python | 集群分析模块，汇总集群通信数据 | Medium |
| compare_tools | msprof_analyze/compare_tools | python | 性能比对模块，对比 GPU/NPU 性能差异 | High |
| prof_exports | msprof_analyze/prof_exports | python | 导出模块 | Low |
| misc_autofuse | misc/autofuse_performance_comparison | mixed | 自动融合性能对比（含 C++ 辅助代码） | Medium |

### 信任边界模型

| 边界名称 | 可信一侧 | 不可信一侧 | 风险等级 |
|----------|----------|------------|----------|
| Command Line Interface | Application logic | Local user (command arguments) | Medium |
| File Input | Application logic | User-provided profiling data files (JSON/CSV/YAML/DB) | High |
| Environment Variables | Application logic | Local user (environment configuration) | Low |
| Database Connection | Application logic | SQLite DB files (user-provided) | High |

---

## 模块风险评估

### 高风险模块

#### 1. prof_common (公共能力模块)

| 文件 | 风险等级 | STRIDE 威胁 | 说明 |
|------|----------|-------------|------|
| file_manager.py | High | T, I | 处理所有文件读写操作（JSON、CSV、YAML），是数据输入的核心入口 |
| path_manager.py | High | T | 路径验证逻辑，包含安全检查（软链接检测、权限验证、路径长度限制） |
| db_manager.py | High | T, I | SQLite 数据库操作，执行 SQL 查询和写入 |

**关键数据流**:
- 命令行参数 → PathManager.expanduser_for_cli → 文件路径验证 → FileManager.read_* → 数据解析
- SQLite DB 文件 → DBManager.create_connect_db → curs.execute → 数据查询

#### 2. advisor/dataset/profiling (数据解析模块)

| 文件 | 风险等级 | STRIDE 威胁 | 说明 |
|------|----------|-------------|------|
| profiling_parser.py | High | T, I | 解析 CSV/JSON profiling 数据，使用 pandas.read_sql 查询数据库 |
| profiling_dataset.py | High | T, I | Profiling 数据集处理 |
| db_manager.py | High | T, I | Advisor 模块的数据库管理 |

#### 3. compare_tools/compare_backend (比对后端模块)

| 文件 | 风险等级 | STRIDE 威胁 | 说明 |
|------|----------|-------------|------|
| base_profiling_parser.py | High | T, I | 解析 JSON profiling 数据文件 |

### 中风险模块

#### 4. cli (命令行入口模块)

| 文件 | 风险等级 | STRIDE 威胁 | 说明 |
|------|----------|-------------|------|
| entrance.py | Medium | T | 主 CLI 入口，路由到各子命令 |
| analyze_cli.py | Medium | T | advisor 子命令入口，处理 profiling_path 参数 |
| cluster_cli.py | Medium | T | cluster 子命令入口，处理 profiling_path 参数 |
| compare_cli.py | Medium | T | compare 子命令入口，处理 GPU/NPU 路径参数 |

#### 5. cluster_analyse (集群分析模块)

| 文件 | 风险等级 | STRIDE 威胁 | 说明 |
|------|----------|-------------|------|
| cluster_analysis.py | Medium | T | 集群分析主入口 |
| base_recipe_analysis.py | Medium | T | Recipe 分析基类 |

---

## 攻击面分析

### 入口点清单

#### 命令行入口 (untrusted_local)

| 文件 | 行号 | 函数 | 说明 |
|------|------|------|------|
| msprof_analyze/cli/entrance.py | 77 | msprof_analyze_cli | 主 CLI 入口 |
| msprof_analyze/cli/analyze_cli.py | 72 | analyze_all | advisor all 子命令 |
| msprof_analyze/cli/analyze_cli.py | 111 | analyze_schedule | advisor schedule 子命令 |
| msprof_analyze/cli/analyze_cli.py | 150 | analyze_computation | advisor computation 子命令 |
| msprof_analyze/cli/cluster_cli.py | 44 | cluster_cli | cluster 子命令 |
| msprof_analyze/cli/compare_cli.py | 20 | compare_cli | compare 子命令 |

#### 文件输入入口 (untrusted_local)

| 文件 | 行号 | 函数 | 输入类型 | 说明 |
|------|------|------|----------|------|
| msprof_analyze/prof_common/file_manager.py | 31 | read_json_file | JSON | 读取 profiling JSON 数据 |
| msprof_analyze/prof_common/file_manager.py | 50 | read_csv_file | CSV | 读取 profiling CSV 数据 |
| msprof_analyze/prof_common/file_manager.py | 79 | read_yaml_file | YAML | 读取配置 YAML 文件 |
| msprof_analyze/prof_common/db_manager.py | 39 | create_connect_db | SQLite DB | 连接用户数据库 |
| msprof_analyze/advisor/dataset/profiling/profiling_parser.py | 166 | _parse_csv | CSV | 解析 CSV profiling 数据 |
| msprof_analyze/advisor/dataset/profiling/profiling_parser.py | 193 | _parse_json | JSON | 解析 JSON profiling 数据 |
| msprof_analyze/advisor/dataset/timeline_event_dataset.py | 176 | _load_timeline_data | JSON | 加载 timeline 数据 |
| msprof_analyze/compare_tools/compare_backend/profiling_parser/base_profiling_parser.py | 407 | _parse_json_file | JSON | 解析 profiling JSON |

#### 环境变量入口 (untrusted_local)

| 文件 | 行号 | 函数 | 环境变量 | 说明 |
|------|------|------|----------|------|
| msprof_analyze/prof_common/logger.py | 20 | get_logger | MSPROF_ANALYZE_LOG_LEVEL | 日志级别配置 |
| msprof_analyze/advisor/utils/utils.py | 129 | get_analyze_processes | ADVISOR_ANALYZE_PROCESSES | 分析进程数 |
| msprof_analyze/advisor/utils/utils.py | 23 | log | ADVISOR_LOG_LEVEL | Advisor 日志级别 |

### 攻击面总结

1. **命令行参数输入**: profiling_path (-d), output_path (-o), benchmark_profiling_path (-bp) 等路径参数由用户控制
2. **文件输入**: JSON、CSV、YAML、SQLite DB profiling 数据文件内容由用户控制
3. **环境变量**: MSPROF_ANALYZE_LOG_LEVEL、ADVISOR_ANALYZE_PROCESSES 等环境变量由本地用户设置
4. **SQLite 数据库查询**: 用户提供的 DB 文件中的 SQL 查询执行
5. **YAML 配置解析**: environment_variable_info.yaml 等配置文件解析

---

## STRIDE 威胁建模

### Spoofing (欺骗)

**风险等级**: Low

- 项目为本地 CLI 工具，无网络服务入口，无身份认证机制
- 主要欺骗风险来自文件路径伪造（用户可提供恶意构造的文件路径）
- 已有防护: PathManager.check_input_file_path 验证路径有效性

### Tampering (篡改)

**风险等级**: High

| 威胁场景 | 影响模块 | 说明 |
|----------|----------|------|
| 恶意 JSON 文件注入 | prof_common/file_manager.py | json.loads 解析用户提供的 JSON 文件，可能导致异常解析 |
| 恶意 CSV 文件注入 | prof_common/file_manager.py, advisor/dataset/profiling/profiling_parser.py | csv.DictReader/csv.reader 解析用户数据 |
| SQLite 数据库篡改 | prof_common/db_manager.py | 用户提供的 SQLite DB 文件可能包含恶意数据 |
| YAML 配置篡改 | prof_common/file_manager.py | yaml.safe_load 解析配置文件（使用 safe_load 降低风险） |

### Repudiation (抵赖)

**风险等级**: Low

- CLI 工具无审计日志机制，用户操作不可追踪
- 建议添加操作日志记录

### Information Disclosure (信息泄露)

**风险等级**: Medium

| 威胁场景 | 影响模块 | 说明 |
|----------|----------|------|
| 敏感 profiling 数据泄露 | advisor/display/html | HTML 报告生成可能包含敏感性能数据 |
| 日志信息泄露 | prof_common/logger.py | 日志可能包含敏感路径信息 |
| 文件内容泄露 | prof_common/file_manager.py | 读取文件内容可能在日志中暴露 |

### Denial of Service (拒绝服务)

**风险等级**: Medium

| 威胁场景 | 影响模块 | 说明 |
|----------|----------|------|
| 大文件处理耗尽资源 | prof_common/file_manager.py | 文件大小限制已实现（MAX_JSON_SIZE, MAX_CSV_SIZE） |
| 数据库查询超时 | prof_common/db_manager.py | 大规模数据查询可能导致性能问题 |
| 无限深度目录遍历 | prof_common/path_manager.py | 已有 limited_depth_walk 限制 |

### Elevation of Privilege (权限提升)

**风险等级**: Medium

| 威胁场景 | 影响模块 | 说明 |
|----------|----------|------|
| root 用户运行警告 | msprof_analyze/cli/entrance.py | 已检测并警告 root 用户运行风险 |
| 软链接攻击 | prof_common/path_manager.py | 已检测软链接并拒绝处理 |
| 文件权限绕过 | prof_common/path_manager.py | 已验证文件权限（check_path_owner_consistent） |

---

## 安全加固建议（架构层面）

### 1. 输入验证增强

- **文件类型白名单**: 限制可接受的文件类型扩展名
- **JSON 解析安全**: 考虑使用 JSON 解析器的严格模式，防止畸形 JSON 导致的异常
- **CSV 解析边界检查**: 验证 CSV 行数和列数，防止过大文件导致的内存问题

### 2. 数据库操作安全

- **SQL 查询参数化**: 确保 SQL 查询使用参数化方式，防止 SQL 注入（当前实现已使用参数化）
- **数据库文件验证**: 增强 SQLite DB 文件的完整性检查
- **查询结果限制**: 对数据库查询结果数量进行限制

### 3. 错误处理改进

- **异常信息最小化**: 避免在错误消息中暴露敏感路径信息
- **安全异常处理**: 确保文件操作异常不泄露系统内部状态

### 4. 配置安全

- **环境变量白名单**: 仅读取预定义的安全环境变量
- **配置文件权限**: 验证配置文件的权限设置

### 5. 输出安全

- **报告内容过滤**: HTML/文本报告中过滤敏感路径信息
- **临时文件清理**: 确保临时输出文件的安全清理

---

## 分析元信息

- **分析时间**: 2026-04-20T21:51:00Z
- **LSP 可用性**: False (pyright-langserver 无法启动，使用 grep 回退分析)
- **分析模式**: 自主分析模式（threat.md 不存在）
- **扫描文件数**: 440
- **扫描代码行数**: 43,019

---

## 附录：关键文件清单

### 高风险文件 (优先级 1-3)

| 优先级 | 文件路径 | 风险等级 | 模块类型 |
|--------|----------|----------|----------|
| 1 | msprof_analyze/cli/entrance.py | Medium | CLI 入口 |
| 1 | msprof_analyze/prof_common/file_manager.py | High | 文件操作 |
| 2 | msprof_analyze/prof_common/path_manager.py | High | 路径验证 |
| 3 | msprof_analyze/prof_common/db_manager.py | High | 数据库操作 |
| 1 | msprof_analyze/advisor/dataset/profiling/profiling_parser.py | High | 数据解析 |
| 1 | msprof_analyze/compare_tools/compare_backend/profiling_parser/base_profiling_parser.py | High | 数据解析 |

---

**报告生成完成**