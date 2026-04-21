# 威胁分析报告 - msprof-analyze

## 项目概述

| 属性 | 值 |
|------|------|
| 项目名称 | msprof-analyze (MindStudio Profiler Analyze) |
| 项目类型 | CLI 工具 (Python) |
| 文件数量 | 409 个 Python 文件 |
| 代码行数 | 39,429 行 |
| 扫描时间 | 2026-04-20 |

## 项目定位

msprof-analyze 是 MindStudio 性能分析工具，用于分析 AI 训练场景的性能数据，识别性能瓶颈。该工具：

- 作为 pip 包安装在用户本地环境
- 通过命令行 `msprof-analyze` 执行
- 处理用户提供的 profiling 数据文件夹
- 输出分析结果到指定目录

**主要功能模块**：
- advisor: 性能分析建议器
- cluster_analyse: 集群分析核心
- compare_tools: 性能对比工具
- prof_common: 公共工具（数据库、文件管理）
- prof_exports: 数据导出

## 信任边界分析

### 边界 1: CLI 输入 → 应用逻辑

| 属性 | 值 |
|------|------|
| 边界 | CLI Input |
| 可信侧 | Application logic |
| 不可信侧 | User-provided profiling data directory and parameters |
| 风险等级 | Medium |

**说明**：用户通过命令行参数指定 profiling 数据路径、输出路径、分析模式等。这些参数直接影响程序行为。

### 边界 2: 文件系统 → 应用逻辑

| 属性 | 值 |
|------|------|
| 边界 | File System |
| 可信侧 | Application logic |
| 不可信侧 | User-provided profiling data files (JSON, CSV, SQLite DB) |
| 风险等级 | Medium |

**说明**：程序读取用户提供的 JSON、CSV、SQLite 数据库文件。这些文件内容完全由用户控制。

### 边界 3: 数据库 → 应用逻辑

| 属性 | 值 |
|------|------|
| 边界 | Database |
| 可信侧 | Application logic |
| 不可信侧 | User-provided SQLite database files |
| 风险等级 | Medium |

**说明**：程序连接用户提供的 SQLite 数据库文件，执行 SQL 查询获取 profiling 数据。

## 攻击面分析

### 主要攻击入口

| 文件 | 行号 | 函数 | 入口类型 | 信任等级 | 说明 |
|------|------|------|----------|----------|------|
| msprof_analyze/cli/entrance.py | 77 | msprof_analyze_cli | cmdline | untrusted_local | CLI 主入口点，接收命令行参数 |
| msprof_analyze/cli/cluster_cli.py | 43 | cluster_cli | cmdline | untrusted_local | cluster 子命令入口，接收 profiling_path 参数 |
| msprof_analyze/cli/compare_cli.py | 53 | compare_cli | cmdline | untrusted_local | compare 子命令入口，接收两个 profiling 路径 |
| msprof_analyze/cli/analyze_cli.py | 68 | analyze_all | cmdline | untrusted_local | advisor analyze 子命令入口 |
| msprof_analyze/prof_common/file_manager.py | 31 | read_json_file | file | untrusted_local | 读取用户 JSON 文件 |
| msprof_analyze/prof_common/file_manager.py | 50 | read_csv_file | file | untrusted_local | 读取用户 CSV 文件 |
| msprof_analyze/prof_common/file_manager.py | 79 | read_yaml_file | file | untrusted_local | 读取用户 YAML 文件（使用 safe_load） |
| msprof_analyze/prof_common/db_manager.py | 39 | create_connect_db | file | untrusted_local | 连接用户 SQLite 数据库 |
| msprof_analyze/prof_common/path_manager.py | 36 | check_input_directory_path | file | untrusted_local | 验证用户输入目录路径 |
| msprof_analyze/prof_common/path_manager.py | 59 | check_input_file_path | file | untrusted_local | 验证用户输入文件路径 |

### 攻击面总结

1. **CLI 参数输入**：用户通过命令行参数指定 profiling 数据路径、输出路径、分析模式等
2. **文件系统输入**：用户提供的 profiling 数据目录包含 JSON、CSV、SQLite DB 文件
3. **SQLite 数据库输入**：用户提供的 .db 文件包含 profiling 数据，应用程序读取并执行 SQL 查询
4. **路径操作**：用户提供的路径参数通过 os.path.join 和 os.path.abspath 处理
5. **YAML 配置文件**：项目读取配置文件，使用 yaml.safe_load 安全加载
6. **安全控制绕过**：--force 参数允许绕过权限检查、文件大小限制等安全验证

## STRIDE 威胁建模

### Spoofing (身份伪造)

| 威胁 | 风险 | 现有缓解措施 | 建议 |
|------|------|--------------|------|
| 文件属主伪造 | Low | PathManager.check_path_owner_consistent 检查文件属主与当前用户一致 | 已有足够保护 |

### Tampering (数据篡改)

| 威胁 | 风险 | 现有缓解措施 | 建议 |
|------|------|--------------|------|
| Profiling 数据篡改 | Medium | 文件权限检查、大小限制 | --force 参数可绕过，建议审查使用场景 |
| 数据库内容篡改 | Medium | 无完整性校验 | 数据库为用户提供，篡改风险可接受 |
| 输出文件篡改 | Low | 文件权限设置 (0o640) | 已有足够保护 |

### Repudiation (否认)

| 威胁 | 风险 | 现有缓解措施 | 建议 |
|------|------|--------------|------|
| 操作否认 | Low | 日志记录 | 建议增加详细操作日志 |

### Information Disclosure (信息泄露)

| 威胁 | 风险 | 现有缓解措施 | 建议 |
|------|------|--------------|------|
| 日志信息泄露 | Low | 日志级别控制 | 已有足够保护 |
| 临时文件泄露 | Low | 使用安全文件权限 | 已有足够保护 |

### Denial of Service (拒绝服务)

| 威胁 | 风险 | 现有缓解措施 | 建议 |
|------|------|--------------|------|
| 大文件处理 DoS | Medium | 文件大小限制（JSON 10GB、CSV 5GB、DB 8GB） | --force 可绕过，建议警告用户风险 |
| 软链接攻击 | Low | PathManager 检查并拒绝软链接 | 已有足够保护 |
| 路径深度攻击 | Low | PathManager.limited_depth_walk 限制遍历深度（max_depth=10） | 已有足够保护 |

### Elevation of Privilege (权限提升)

| 威胁 | 风险 | 现有缓解措施 | 建议 |
|------|------|--------------|------|
| Root 用户执行 | Medium | is_root() 检查并警告 | 建议：禁止 root 用户执行（仅警告不够） |
| 权限绕过 | Medium | --force 参数检查 | 建议：明确记录 force 使用，审计日志 |

## 安全代码分析

### 已实现的安全措施

#### 1. 路径安全 (path_manager.py)

- **软链接检测**：所有路径操作前检查 `os.path.islink(path)`，拒绝软链接
- **路径长度限制**：`MAX_PATH_LENGTH = 4096`，`MAX_FILE_NAME_LENGTH = 255`
- **字符验证**：使用正则表达式 `r'(\.|:|\\|/|_|-|\s|[~0-9a-zA-Z\u4e00-\u9fa5])+'` 验证路径字符
- **属主一致性检查**：`check_path_owner_consistent()` 确保文件属主与当前用户一致
- **权限检查**：检查可读、可写、可执行权限
- **其他用户写权限检查**：`check_others_writable()` 确保文件不被其他用户写入

#### 2. 文件安全 (file_manager.py)

- **文件大小限制**：
  - JSON: 10GB (`MAX_JSON_SIZE`)
  - CSV: 5GB (`MAX_CSV_SIZE`)
  - DB: 8GB (`MAX_READ_DB_FILE_BYTES`)
  - 普通文件: 1GB (`MAX_COMMON_SIZE`)
- **安全文件创建**：使用 `os.open()` 与 `os.fdopen()` 创建文件，设置权限 `FILE_AUTHORITY = 0o640`
- **YAML 安全加载**：使用 `yaml.safe_load()` 而非 `yaml.load()`

#### 3. 数据库安全 (db_manager.py)

- **参数化查询**：SQL 查询使用参数化方式 `curs.execute(sql, params)`
- **连接验证**：检查数据库连接有效性

#### 4. Root 用户警告 (entrance.py)

```python
if is_root():
    logger.warning(
        "Security Warning: Do not run this tool as root. "
        "Running with elevated privileges may compromise system security. "
        "Use a regular user account."
    )
```

### 潜在安全风险

#### 1. SQL 拼接风险 (CWE-89)

**位置**：
- `msprof_analyze/cluster_analyse/recipes/p2p_pairing/p2p_pairing.py:75-88`
- `msprof_analyze/compare_tools/compare_backend/profiling_parser/npu_profiling_db_parser.py:184, 280`

**分析**：
- `p2p_pairing.py` 使用 f-string 构造 ALTER TABLE 和 UPDATE SQL
- 表名 `TARGET_TABLE_NAME` 和列名来自类常量，非用户输入
- `npu_profiling_db_parser.py` 使用 `.format()` 构造 WHERE 条件
- 但 WHERE 条件值通过参数化传递 `curs.execute(sql, param=param)`

**风险评估**：**低风险** - 表名和列名来自常量，非用户可控

#### 2. 安全控制绕过风险 (--force 参数)

**位置**：多处使用 `AdditionalArgsManager().force` 检查

**分析**：
- `--force` 参数允许绕过：
  - 文件属主检查
  - 文件大小限制
  - 权限检查
  - 其他用户写权限检查

**风险评估**：**中等风险** - 需要用户明确了解绕过后果

#### 3. Root 用户执行风险

**位置**：`msprof_analyze/cli/entrance.py:79`

**分析**：
- 仅警告用户不要以 root 执行
- 未强制阻止 root 用户

**风险评估**：**中等风险** - 建议：考虑阻止 root 用户执行（或记录到审计日志）

## 高风险文件清单

| 文件 | 风险等级 | 风险原因 |
|------|----------|----------|
| msprof_analyze/prof_common/path_manager.py | High | 处理用户输入路径，需严格验证 |
| msprof_analyze/prof_common/file_manager.py | High | 读取用户文件，文件大小控制 |
| msprof_analyze/prof_common/db_manager.py | High | 连接用户数据库，SQL 执行 |
| msprof_analyze/advisor/utils/file.py | High | 文件打开操作 |
| msprof_analyze/cli/entrance.py | Medium | CLI 入口，root 用户警告 |
| msprof_analyze/cluster_analyse/recipes/p2p_pairing/p2p_pairing.py | Medium | SQL 语句构造 |

## 安全建议

### 优先级 1 (高)

1. **Root 用户阻止**：将 root 用户警告升级为强制阻止，或要求用户确认后记录审计日志
2. **Force 参数审计**：记录 `--force` 参数使用到审计日志，便于事后追溯

### 优先级 2 (中)

1. **SQL 语句审查**：定期审查 SQL 拼接代码，确保表名/列名来源可控
2. **数据库完整性校验**：考虑对关键数据库文件添加完整性校验（如 SHA256）

### 优先级 3 (低)

1. **日志审计增强**：增加详细操作日志，包括输入路径、输出路径、分析模式等
2. **输入数据验证**：对 JSON/CSV 数据添加 schema 验证

## 总结

msprof-analyze 项目整体安全性较好：

**优点**：
- 路径处理有严格的安全验证（软链接检测、长度限制、字符验证、属主检查）
- 文件大小限制有效防止资源耗尽
- YAML 使用 safe_load，避免反序列化攻击
- 数据库查询使用参数化方式
- 文件权限设置合理 (0o640)

**待改进**：
- --force 参数绕过安全检查需审计日志
- Root 用户警告应升级为阻止或审计
- SQL 拼接代码需持续审查

该项目作为本地 CLI 工具，主要风险来自用户提供的 profiling 数据文件。现有安全措施已覆盖大部分威胁场景，建议重点关注 --force 参数使用和 root 用户执行场景。