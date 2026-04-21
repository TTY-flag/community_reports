# 漏洞扫描报告 — 待确认漏洞

**项目**: msprof
**扫描时间**: 2026-04-20T06:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 21 | 42.9% |
| FALSE_POSITIVE | 18 | 36.7% |
| LIKELY | 9 | 18.4% |
| CONFIRMED | 1 | 2.0% |
| **总计** | **49** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| **有效漏洞总计** | **24** | - |
| 误报 (FALSE_POSITIVE) | 18 | - |

### 1.3 Top 10 关键漏洞

1. **[msparser-npu_mem_bean-001]** Buffer Overread (HIGH) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof/analysis/msparser/npu_mem/npu_mem_bean.py:74` @ `npu_mem_decode` | 置信度: 75
2. **[msparser-parse_dp_data-001]** Buffer Overread (HIGH) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof/analysis/msparser/aicpu/parse_dp_data.py:200` @ `read_bin_data` | 置信度: 75
3. **[VULN-common_func-TOCTOU-001]** TOCTOU (HIGH) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof/analysis/common_func/msvp_common.py:277` @ `bak_and_make_dir` | 置信度: 70
4. **[msparser-compact_info_bean-001]** Improper Validation of Array Index (HIGH) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof/analysis/msparser/compact_info/compact_info_bean.py:27` @ `__init__` | 置信度: 70
5. **[msparser-hccl_op_info_bean-001]** Improper Validation of Array Index (HIGH) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof/analysis/msparser/compact_info/hccl_op_info_bean.py:33` @ `__init__` | 置信度: 70
6. **[msparser-runtime_op_info_bean-001]** Improper Validation of Array Index (HIGH) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof/analysis/msparser/add_info/runtime_op_info_bean.py:34` @ `__init__` | 置信度: 70
7. **[msparser-data_parser-001]** Buffer Overread (MEDIUM) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof/analysis/msparser/interface/data_parser.py:70` @ `check_magic_num` | 置信度: 65
8. **[msparser-tscpu_parser-001]** Improper Validation of Array Index (MEDIUM) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof/analysis/msparser/hardware/tscpu_parser.py:194` @ `_insert_ts_data_in_mdc` | 置信度: 65
9. **[msparser-data_preparation_parser-001]** Type Confusion (MEDIUM) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof/analysis/msparser/aicpu/data_preparation_parser.py:163` @ `_parse_data_queue_file` | 置信度: 65
10. **[VULN-common_func-PATH-003]** PATH_TRAVERSAL (MEDIUM) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/mstt/msprof/analysis/common_func/file_manager.py:45` @ `FileManager.remove_file` | 置信度: 60

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@analysis/msinterface/msprof_entrance.py` | cmdline | untrusted_local | CLI 入口，用户通过命令行参数控制工具行为，路径参数可被外部控制 | 接收用户命令行参数，启动 msprof 工具 |
| `construct_arg_parser@analysis/msinterface/msprof_entrance.py` | cmdline | untrusted_local | 解析用户提供的命令行参数，包括路径、配置文件等 | 构建 argparse 参数解析器 |
| `_handle_export_command@analysis/msinterface/msprof_entrance.py` | file | untrusted_local | 处理用户指定的数据导出目录 | 处理 export 命令 |
| `_handle_analyze_command@analysis/msinterface/msprof_entrance.py` | file | untrusted_local | 处理用户指定的分析目录 | 处理 analyze 命令 |
| `__get_json_data@analysis/common_func/info_conf_reader.py` | file | untrusted_local | 从用户提供的目录读取 info.json 配置文件 | 读取并解析 JSON 配置文件 |
| `check_path_valid@analysis/common_func/file_manager.py` | file | semi_trusted | 校验用户提供的文件路径，防止路径遍历攻击 | 校验文件路径有效性 |
| `FileReader::Open@analysis/csrc/infrastructure/utils/file.cpp` | file | untrusted_local | C++ 层打开用户提供的文件进行读取 | 打开文件进行读取操作 |
| `parse_api_event@analysis/csrc/domain/services/parser/host/cann/api_event_parser.cpp` | file | untrusted_local | 解析用户提供的二进制性能数据文件 | 解析 API 事件数据 |

**其他攻击面**:
- CLI 命令行参数 (-dir/--collection-dir, --reports-path)
- 文件系统读取 (profiling data directory)
- JSON 配置文件解析 (info.json, sample.json)
- 二进制数据文件解析 (profiling binary files)
- SQLite 数据库操作 (读写数据库文件)
- Shell 脚本执行 (安装/构建脚本)
- CSV/JSON 文件导出

---

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| common_func | 0 | 0 | 0 | 0 | 0 |
| msinterface | 0 | 0 | 0 | 0 | 0 |
| msparser | 0 | 0 | 0 | 0 | 0 |
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 6 | 25.0% |
| CWE-73 | 4 | 16.7% |
| CWE-130 | 4 | 16.7% |
| CWE-129 | 4 | 16.7% |
| CWE-502 | 2 | 8.3% |
| CWE-89 | 1 | 4.2% |
| CWE-843 | 1 | 4.2% |
| CWE-59 | 1 | 4.2% |
| CWE-36 | 1 | 4.2% |
