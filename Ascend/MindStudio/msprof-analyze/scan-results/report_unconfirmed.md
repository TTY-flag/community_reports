# 漏洞扫描报告 — 待确认漏洞

**项目**: msprof-analyze
**扫描时间**: 2026-04-20T12:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 24 | 55.8% |
| POSSIBLE | 8 | 18.6% |
| LIKELY | 7 | 16.3% |
| CONFIRMED | 4 | 9.3% |
| **总计** | **43** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Medium | 2 | 14.3% |
| Low | 4 | 28.6% |
| **有效漏洞总计** | **14** | - |
| 误报 (FALSE_POSITIVE) | 24 | - |

### 1.3 Top 10 关键漏洞

1. **[CLI-ROOT-BYPASS-001]** Privilege Escalation Context (Medium) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof-analyze/msprof_analyze/cli/entrance.py:79` @ `msprof_analyze_cli` | 置信度: 70
2. **[CLI-ROOT-WARNING-002]** insufficient_access_control (Medium) - `msprof_analyze/cli/entrance.py:79` @ `msprof_analyze_cli` | 置信度: 65
3. **[CLI-SINGLETON-FORCE-003]** singleton_state_issue (Low) - `msprof_analyze/prof_common/additional_args_manager.py:36` @ `AdditionalArgsManager` | 置信度: 55
4. **[CLI-PATH-VALIDATION-GAP-004]** validation_timing_gap (Low) - `msprof_analyze/prof_common/path_manager.py:106` @ `input_path_common_check` | 置信度: 50
5. **[CLI-PATH-EXPAND-001]** Path Traversal (Low) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof-analyze/msprof_analyze/prof_common/path_manager.py:262` @ `expanduser_for_cli` | 置信度: 45
6. **[CLI-NO-PARAM-VALIDATION-001]** Missing Input Validation (Low) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof-analyze/msprof_analyze/cli/cluster_cli.py:28` @ `cluster_cli` | 置信度: 40
7. **[VULN-ADVISOR-005]** TOCTOU (MEDIUM) - `msprof_analyze/advisor/utils/utils.py:327` @ `SafeOpen.__init__` | 置信度: 75
8. **[VULN-ADVISOR-007]** Missing Symlink Check (MEDIUM) - `msprof_analyze/advisor/utils/utils.py:226` @ `safe_write` | 置信度: 75
9. **[VULN-ADVISOR-001]** TOCTOU (HIGH) - `msprof_analyze/advisor/utils/file.py:37` @ `FileOpen.__enter__` | 置信度: 70
10. **[VULN-ADVISOR-002]** TOCTOU (HIGH) - `msprof_analyze/advisor/utils/file.py:62` @ `FdOpen.__enter__` | 置信度: 70

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `msprof_analyze_cli@msprof_analyze/cli/entrance.py` | cmdline | untrusted_local | CLI 入口点，通过 click 框架接收命令行参数。用户通过 msprof-analyze 命令调用，参数包括 profiling 数据路径、输出路径、分析模式等。 | 接收 CLI 参数并分发到子命令处理器 |
| `cluster_cli@msprof_analyze/cli/cluster_cli.py` | cmdline | untrusted_local | cluster 子命令入口点，接收用户提供的 profiling_path 参数指向用户数据目录。 | 处理集群分析子命令 |
| `compare_cli@msprof_analyze/cli/compare_cli.py` | cmdline | untrusted_local | compare 子命令入口点，接收 comparison_profiling_path 和 base_profiling_path 两个用户数据路径。 | 处理性能比对子命令 |
| `analyze_all@msprof_analyze/cli/analyze_cli.py` | cmdline | untrusted_local | advisor analyze 子命令入口点，接收 profiling_path 参数指向用户数据目录。 | 处理性能分析建议子命令 |
| `read_json_file@msprof_analyze/prof_common/file_manager.py` | file | untrusted_local | 读取用户提供的 JSON 文件内容，文件路径来自 CLI 参数。数据内容完全由用户提供。 | 读取并解析用户 JSON 文件 |
| `read_csv_file@msprof_analyze/prof_common/file_manager.py` | file | untrusted_local | 读取用户提供的 CSV 文件内容，文件路径来自 CLI 参数。 | 读取并解析用户 CSV 文件 |
| `read_yaml_file@msprof_analyze/prof_common/file_manager.py` | file | untrusted_local | 读取用户提供的 YAML 文件，使用 yaml.safe_load 安全加载。 | 读取并解析用户 YAML 文件 |
| `create_connect_db@msprof_analyze/prof_common/db_manager.py` | file | untrusted_local | 连接用户提供的 SQLite 数据库文件，数据库路径来自 CLI 参数。 | 连接用户 SQLite 数据库 |
| `check_input_directory_path@msprof_analyze/prof_common/path_manager.py` | file | untrusted_local | 验证用户提供的目录路径，检查路径有效性、权限等。 | 验证用户输入目录路径 |
| `check_input_file_path@msprof_analyze/prof_common/path_manager.py` | file | untrusted_local | 验证用户提供的文件路径，检查路径有效性、权限等。 | 验证用户输入文件路径 |
| `judge_table_exists@msprof_analyze/prof_common/db_manager.py` | file | untrusted_local | 检查用户数据库中是否存在指定表，SQL 查询使用参数化。 | 检查数据库表是否存在 |
| `update_connection_info_to_table@msprof_analyze/cluster_analyse/recipes/p2p_pairing/p2p_pairing.py` | file | untrusted_local | 更新用户数据库表，使用 f-string 构造 ALTER TABLE 和 UPDATE SQL 语句，表名来自常量。 | 更新数据库表连接信息 |
| `mapper_func@msprof_analyze/cluster_analyse/recipes/communication_matrix_sum/communication_matrix_sum.py` | file | untrusted_local | 使用 ast.literal_eval 解析用户数据，这是安全的替代方案。 | 解析用户数据中的结构化信息 |

**其他攻击面**:
- CLI 参数输入：用户通过命令行参数指定 profiling 数据路径、输出路径、分析模式等
- 文件系统输入：用户提供的 profiling 数据目录包含 JSON、CSV、SQLite DB 文件
- SQLite 数据库输入：用户提供的 .db 文件包含 profiling 数据，应用程序读取并执行 SQL 查询
- 路径操作：用户提供的路径参数通过 os.path.join 和 os.path.abspath 处理
- YAML 配置文件：项目读取配置文件，使用 yaml.safe_load 安全加载
- 安全控制绕过：--force 参数允许绕过权限检查、文件大小限制等安全验证

---

## 3. Medium 漏洞 (2)

### [CLI-ROOT-BYPASS-001] Privilege Escalation Context - msprof_analyze_cli

**严重性**: Medium（原评估: Low → 验证后: Medium） | **CWE**: CWE-250 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof-analyze/msprof_analyze/cli/entrance.py:79-84` @ `msprof_analyze_cli`
**模块**: cli
**跨模块**: cli,prof_common

**描述**: The CLI warns users about running as root but does not prevent it. Running as root bypasses all security checks via is_root() condition in PathManager, making the tool vulnerable to processing malicious files with elevated privileges.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof-analyze/msprof_analyze/cli/entrance.py:79-84`)

```c
if is_root(): logger.warning(...)
```

**达成路径**

User runs CLI as root -> is_root() returns True -> all security checks bypassed

**验证说明**: LIKELY: Running CLI as root bypasses all security checks via is_root() condition in PathManager, equivalent to --force effect. entrance.py only warns (lines 79-84) without preventing execution. Verified at path_manager.py line 25: is_root() = os.getuid() == 0, and security checks at lines 137-199 return early if is_root(). While user has partial control (must have root access), the security impact is significant.

**评分明细**: base_score: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0 | total: 75

---

### [CLI-ROOT-WARNING-002] insufficient_access_control - msprof_analyze_cli

**严重性**: Medium | **CWE**: CWE-274 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `msprof_analyze/cli/entrance.py:79-84` @ `msprof_analyze_cli`
**模块**: cli
**跨模块**: cli, prof_common

**描述**: Root 用户检测仅警告不阻止执行。Root 用户可以绕过所有安全检查（与 --force 相同效果），可能导致权限提升风险。

**漏洞代码** (`msprof_analyze/cli/entrance.py:79-84`)

```c
if is_root(): logger.warning(...)
```

**验证说明**: LIKELY: Root user warning at entrance.py lines 79-84 is only informational, does not prevent execution. When running as root, all security checks in PathManager are bypassed via is_root() condition. Creates privilege escalation context where tool processes potentially malicious files with elevated privileges.

**评分明细**: base_score: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0 | total: 65

---

## 4. Low 漏洞 (4)

### [CLI-SINGLETON-FORCE-003] singleton_state_issue - AdditionalArgsManager

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-668 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `msprof_analyze/prof_common/additional_args_manager.py:36-55` @ `AdditionalArgsManager`
**模块**: cli
**跨模块**: cli, prof_common

**描述**: AdditionalArgsManager 使用单例模式存储 force 参数状态，可能导致多次调用时状态意外保留，影响安全检查的一致性。

**漏洞代码** (`msprof_analyze/prof_common/additional_args_manager.py:36-55`)

```c
@singleton class AdditionalArgsManager
```

**验证说明**: POSSIBLE: AdditionalArgsManager uses singleton pattern which could cause _force state to persist across multiple calls within the same process. However, singleton implementation uses pid-based isolation, mitigating cross-process state retention. Within a single process, if init() is called with force=True once, subsequent calls may still have force=True active.

**评分明细**: base_score: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: -15 | cross_file: 0 | total: 35

---

### [CLI-PATH-VALIDATION-GAP-004] validation_timing_gap - input_path_common_check

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `msprof_analyze/prof_common/path_manager.py:106-126` @ `input_path_common_check`
**模块**: cli

**描述**: 路径验证时机存在漏洞：expanduser_for_cli 在 input_path_common_check 验证之前执行，可能导致未完全验证的路径被处理。软链接检测在 input_path_common_check 中有效，但路径字符验证的正则表达式可能不够严格。

**漏洞代码** (`msprof_analyze/prof_common/path_manager.py:106-126`)

```c
pattern validation regex
```

**验证说明**: POSSIBLE: Path validation timing gap - expanduser_for_cli callback invoked before input_path_common_check validation. Soft link detection is effective in input_path_common_check. Character validation regex may allow path traversal characters. Security impact is limited due to downstream validation.

**评分明细**: base_score: 30 | reachability: 20 | controllability: 10 | mitigations: -20 | context: 0 | cross_file: -15 | total: 25

---

### [CLI-PATH-EXPAND-001] Path Traversal - expanduser_for_cli

**严重性**: Low | **CWE**: CWE-22 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof-analyze/msprof_analyze/prof_common/path_manager.py:262-268` @ `expanduser_for_cli`
**模块**: cli
**跨模块**: prof_common,cluster_analyse,advisor,compare_tools

**描述**: PathManager.expanduser_for_cli only performs os.path.expanduser() without validating path traversal sequences (../). The expanded path is passed downstream before full validation. While downstream validation in get_realpath and input_path_common_check exists, the callback is invoked before validation creating a potential gap.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof-analyze/msprof_analyze/prof_common/path_manager.py:262-268`)

```c
0
```

**达成路径**

CLI path parameter -> expanduser_for_cli callback -> downstream modules (Interface, AnalyzerController)

**验证说明**: POSSIBLE: expanduser_for_cli (path_manager.py lines 262-268) only performs os.path.expanduser() without validating path traversal sequences (../). However, downstream validation exists: get_realpath (line 245) checks for soft links, input_path_common_check (line 109) also checks soft links and validates path characters via regex. The vulnerability gap exists in callback timing but security impact is mitigated.

**评分明细**: base_score: 30 | reachability: 30 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: -15 | total: 40

---

### [CLI-NO-PARAM-VALIDATION-001] Missing Input Validation - cluster_cli

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof-analyze/msprof_analyze/cli/cluster_cli.py:28-42` @ `cluster_cli`
**模块**: cli
**跨模块**: cli,cluster_analyse,advisor,compare_tools

**描述**: CLI entry points accept user-provided paths directly without pre-validation before passing to downstream modules. The click.Path() type only validates existence, not security properties. Parameters like rank_list, step_id, op_name_map are passed without strict validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof-analyze/msprof_analyze/cli/cluster_cli.py:28-42`)

```c
@click.option(--profiling_path, type=click.Path())
```

**达成路径**

CLI untrusted input -> kwargs dict -> Interface.run/AnalyzerController.do_analysis

**验证说明**: POSSIBLE: CLI entry points accept user-provided paths via click.Path() which only validates existence, not security properties. However, downstream validation is comprehensive: Interface.__init__ calls PathManager.get_realpath, and Interface.run calls PathManager.check_input_directory_path which includes owner, permission, soft link checks.

**评分明细**: base_score: 30 | reachability: 30 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: -15 | total: 40

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| advisor | 0 | 0 | 0 | 0 | 0 |
| cli | 0 | 0 | 2 | 4 | 6 |
| **合计** | **0** | **0** | **2** | **4** | **6** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-367 | 6 | 42.9% |
| CWE-22 | 3 | 21.4% |
| CWE-20 | 2 | 14.3% |
| CWE-668 | 1 | 7.1% |
| CWE-274 | 1 | 7.1% |
| CWE-250 | 1 | 7.1% |
