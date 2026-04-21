# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio-Profiler
**扫描时间**: 2026-04-20T21:50:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本次漏洞扫描对 MindStudio-Profiler 性能分析工具进行了安全审计，共检测到 30 个待确认漏洞（1 个 LIKELY + 29 个 POSSIBLE），按严重性分布为：High 1 个、Medium 17 个、Low 12 个。

**关键发现**：

1. **PATH 劫持漏洞（High，置信度 65）**: `misc/gil_tracer/gil_trace_record.py` 使用 `os.getenv('PATH')` 作为 subprocess 执行环境，在 root/sudo 场景下攻击者可劫持 sysTrace_cli 命令执行恶意代码。这是本次扫描最严重的发现，需优先修复。

2. **资源消耗漏洞（Medium，9 处）**: msparser 模块多处使用无界的 `struct.unpack` 格式字符串乘法，用户提供的超大性能数据文件可能导致内存耗尽或 DoS。

3. **路径验证缺陷（Medium，多处）**: 环境变量控制的日志路径、衍生路径计算（如 `../host`）未执行与原始路径相同的验证，可能导致路径遍历。

4. **SQL 注入模式（Medium/Low，6 处）**: msmodel 模块多处使用 f-string/.format() 构建 SQL，虽数据来源多为内部处理结果，但不符合安全编码规范。

**业务影响评估**：
MindStudio-Profiler 为本地 CLI 工具，攻击面主要来自用户提供的性能数据文件和命令行参数。在普通用户场景下风险可控，但在 root/sudo 运行场景下，PATH 劫持漏洞可能导致权限提升。

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
| High | 1 | 3.3% |
| Medium | 17 | 56.7% |
| Low | 12 | 40.0% |
| **有效漏洞总计** | **30** | - |
| 误报 (FALSE_POSITIVE) | 68 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SA-MISC-001]** untrusted_search_path (High) - `misc/gil_tracer/gil_trace_record.py:77` @ `GilTraceRecord.start` | 置信度: 65
2. **[VULN_MISC_001]** path_traversal (Medium) - `misc/function_monitor/function_monitor.py:62` @ `MonitorLogger.get_log_path` | 置信度: 55
3. **[VULN-SEC-001]** resource_consumption (Medium) - `analysis/msparser/hardware/qos_parser.py:63` @ `read_binary_data` | 置信度: 55
4. **[VULN-SEC-002]** resource_consumption (Medium) - `analysis/msparser/aicpu/parse_dp_data.py:200` @ `read_bin_data` | 置信度: 55
5. **[VULN-SEC-003]** resource_consumption (Medium) - `analysis/msparser/hardware/ddr_parser.py:69` @ `read_binary_data` | 置信度: 55
6. **[VULN-SEC-005]** resource_consumption (Medium) - `analysis/msparser/l2_cache/l2_cache_parser.py:79` @ `parse` | 置信度: 50
7. **[VULN-SEC-006]** resource_consumption (Medium) - `analysis/msparser/l2_cache/soc_pmu_parser.py:84` @ `parse` | 置信度: 50
8. **[VULN-SEC-008]** resource_consumption (Medium) - `analysis/msparser/hardware/tscpu_parser.py:240` @ `_do_read_binary_data, _do_read_mdc_binary_data` | 置信度: 50
9. **[VULN-SEC-009]** resource_consumption (Medium) - `analysis/msparser/hardware/llc_parser.py:105` @ `_read_binary_helper` | 置信度: 50
10. **[PY-DF-profiling_bean-002]** Improper Input Validation (Medium) - `analysis/profiling_bean/struct_info/freq.py:71` @ `construct_bean` | 置信度: 50

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

## 3. High 漏洞 (1)

### [VULN-SA-MISC-001] untrusted_search_path - GilTraceRecord.start

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `misc/gil_tracer/gil_trace_record.py:77-78` @ `GilTraceRecord.start`
**模块**: misc_tools

**描述**: subprocess.run() 使用 os.getenv('PATH') 作为环境变量，未对 PATH 进行验证或限制。攻击者可通过设置恶意 PATH 环境变量劫持 sysTrace_cli 命令的执行位置，导致执行恶意代码。工具需要 root 权限运行，在 sudo 场景下风险显著提升。

**漏洞代码** (`misc/gil_tracer/gil_trace_record.py:77-78`)

```c
result = subprocess.run(start_command, capture_output=True, text=True, check=False, env={'LD_PRELOAD': '', 'PATH': os.getenv('PATH', '')})
```

**达成路径**

os.getenv('PATH') [SOURCE] → subprocess.run(..., env={'PATH': ...}) [SINK] → sysTrace_cli 命令执行

**验证说明**: PATH环境变量劫持漏洞：subprocess.run使用os.getenv('PATH')作为环境变量，攻击者可通过设置恶意PATH劫持sysTrace_cli命令执行位置。工具需root权限，在sudo场景下风险显著。建议使用绝对路径或限制PATH范围。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：从源代码可见（`misc/gil_tracer/gil_trace_record.py:72-78`），`subprocess.run()` 直接将 `os.getenv('PATH', '')` 作为环境变量传递给子进程，而 `start_command` 使用裸命令 `'sysTrace_cli'` 而非绝对路径。这意味着系统将按照 PATH 环境变量中的目录顺序查找 sysTrace_cli 可执行文件。

**潜在利用场景**：
1. 攻击者在其可控目录（如 `/tmp/evil/`）中放置名为 `sysTrace_cli` 的恶意脚本
2. 设置 `PATH=/tmp/evil:/usr/bin:/bin` 环境变量
3. 当工具以 root/sudo 权限运行 gil_tracer 功能时，系统会优先在 `/tmp/evil/` 中找到恶意 sysTrace_cli 并执行
4. 恶意脚本可执行任意命令，实现权限维持或数据窃取

**风险加剧因素**：代码注释显示此工具需要 root 权限运行，在 sudo 场景下 PATH 劫持影响尤为严重。同时，`stop()` 方法（第 88-94 行）也存在相同的 PATH 劫持模式。

**建议修复方式**：
1. 使用 sysTrace_cli 的绝对路径，如 `/usr/local/bin/sysTrace_cli` 或通过配置文件指定
2. 限制 PATH 为已知安全目录，如 `env={'PATH': '/usr/bin:/bin', ...}`
3. 在执行前验证 sysTrace_cli 的路径是否为预期位置
4. 添加日志记录实际执行的命令路径，便于审计追踪

---

## 4. Medium 漏洞 (17)

### [VULN_MISC_001] path_traversal - MonitorLogger.get_log_path

**严重性**: Medium（原评估: HIGH → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner-python

**位置**: `misc/function_monitor/function_monitor.py:62-86` @ `MonitorLogger.get_log_path`
**模块**: misc_tools
**跨模块**: function_monitor → file_manager

**描述**: Environment variable FUNCTION_MONITOR_LOG_PATH flows to file operations without proper path validation. Attacker controlling this env var can write log files to arbitrary locations (e.g., sensitive system files, other users' directories).

**漏洞代码** (`misc/function_monitor/function_monitor.py:62-86`)

```c
log_path = os.getenv('FUNCTION_MONITOR_LOG_PATH', None)
...
FileManager.make_dir_safety(log_path)
...
log_file = os.path.join(log_path, f"{__name__}_{cls.PID}.log")
FileManager.create_file_by_path(log_file)
...
file_handler = logging.FileHandler(log_file)
```

**达成路径**

os.getenv('FUNCTION_MONITOR_LOG_PATH') → log_path → FileManager.make_dir_safety() → FileManager.create_file_by_path() → logging.FileHandler()

**验证说明**: FUNCTION_MONITOR_LOG_PATH环境变量控制日志路径，攻击者可写入任意位置。但 FileManager.make_dir_safety 有部分验证。建议添加路径前缀限制。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：从源代码（`misc/function_monitor/function_monitor.py:62-86`）可见，日志路径由环境变量 `FUNCTION_MONITOR_LOG_PATH` 控制。虽然第 68-69 行调用了 `FileManager.make_dir_safety()` 和 `check_path_writeable()` 进行验证，但这些验证仅检查目录的可写性和权限，未限制路径前缀范围。

**潜在利用场景**：
1. 攻击者设置 `FUNCTION_MONITOR_LOG_PATH=/etc` 或 `/root`
2. 如果工具以高权限运行，可能创建日志文件覆盖敏感系统配置
3. 若路径为符号链接指向其他位置，日志文件可能写入非预期目录
4. 第 80-82 行创建日志文件 `{module_name}_{PID}.log`，文件名可控性较低但仍需注意

**缓解因素**：代码第 67-73 行有异常处理，若验证失败会回退到默认路径 `$HOME/function_monitor_log`，降低了部分风险。但攻击者仍可尝试绕过验证。

**建议修复方式**：
1. 添加路径前缀白名单验证，限制日志路径必须在 `$HOME`、`/var/log` 等安全目录下
2. 在调用 `FileManager` 方法前，先用 `os.path.realpath()` 解析符号链接并验证解析后的路径前缀
3. 添加路径前缀检查：`if not resolved_path.startswith(allowed_prefix): reject`
4. 对日志文件名添加安全字符过滤，防止路径注入

---

### [VULN-SEC-001] resource_consumption - read_binary_data

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-400 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `analysis/msparser/hardware/qos_parser.py:63-65` @ `read_binary_data`
**模块**: msparser

**描述**: Uncontrolled Resource Consumption (DoS) via unbounded struct.unpack format string multiplication. The code calculates struct_nums from file_size and multiplies it with a format string to create a format specifier for struct.unpack. For large files, this can create extremely long format strings, causing memory exhaustion.

**漏洞代码** (`analysis/msparser/hardware/qos_parser.py:63-65`)

```c
struct_nums = _file_size // StructFmt.QOS_FMT_SIZE
struct_data = struct.unpack(StructFmt.BYTE_ORDER_CHAR + StructFmt.QOS_FMT * struct_nums, qos_data)
```

**达成路径**

File size from os.path.getsize() → struct_nums calculation → format string multiplication (QOS_FMT * struct_nums) → struct.unpack() with unbounded format string

**验证说明**: struct.unpack格式字符串乘法可能导致内存消耗。文件来自用户CLI参数指定目录，用户可控制文件大小触发DoS。但本地CLI工具场景，攻击者需要物理访问。建议添加文件大小限制。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：从源代码（`analysis/msparser/hardware/qos_parser.py:63-65`）可见，关键漏洞在于第 64-65 行的格式字符串乘法：

```python
struct_nums = _file_size // StructFmt.QOS_FMT_SIZE  # 结构体数量
struct_data = struct.unpack(StructFmt.BYTE_ORDER_CHAR + StructFmt.QOS_FMT * struct_nums, qos_data)
```

假设 `QOS_FMT` 为典型的结构体格式字符串（如 `'14Q'` 表示14个unsigned long），当 `struct_nums` 极大时，格式字符串 `'14Q' * struct_nums` 可能生成数百万字符的字符串。`struct.unpack()` 在解析时会为整个数据集分配内存，同时格式字符串本身也占用内存。

**潜在利用场景**：
1. 用户通过 CLI 参数指定性能数据目录
2. 攻击者在该目录放置伪造的超大 `qos.data` 文件（如 10GB）
3. `struct_nums = 10GB / 112字节 ≈ 89M` 个结构体
4. 格式字符串长度可达数百万字符，加上解析数据内存占用，导致 OOM
5. 工具进程崩溃，影响分析任务或导致系统资源耗尽

**风险等级**：作为本地 CLI 工具，攻击者需有本地文件写入权限。但在服务器共享环境中，恶意用户可影响其他用户的分析任务。

**建议修复方式**：
1. 添加文件大小上限检查：`MAX_FILE_SIZE = 500 * 1024 * 1024` (500MB)
2. 在解析前验证：`if _file_size > MAX_FILE_SIZE: raise SizeLimitExceededError()`
3. 分块解析大数据文件，而非一次性加载全部内容
4. 使用生成器模式逐步处理，避免一次性内存分配

---

### [VULN-SEC-002] resource_consumption - read_bin_data

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-400 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `analysis/msparser/aicpu/parse_dp_data.py:200-202` @ `read_bin_data`
**模块**: msparser

**描述**: Uncontrolled Resource Consumption (DoS) via unbounded struct.unpack format string multiplication in binary DP data parsing. Similar pattern as VULN-SEC-001 but in DP data parsing.

**漏洞代码** (`analysis/msparser/aicpu/parse_dp_data.py:200-202`)

```c
struct_nums = file_size // cls.DP_DATA_FMT_SIZE
dp_data = struct.unpack(cls.DP_BIN_START_TAG + cls.DP_DATA_FMT * struct_nums, dp_bin_data)
```

**达成路径**

File size from os.path.getsize() → struct_nums calculation → format string multiplication (DP_DATA_FMT * struct_nums) → struct.unpack() with unbounded format string

**验证说明**: DP数据解析的struct.unpack内存消耗问题。文件来自用户目录，用户可控制大小。建议添加文件大小限制。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：从源代码（`analysis/msparser/aicpu/parse_dp_data.py:196-202`）可见，DP 数据解析存在与 qos_parser 相同的模式。第 199 行直接读取整个文件内容，第 201-202 行使用无界格式字符串乘法：

```python
dp_bin_data = file_reader.file_reader.read()  # 读取全部文件内容
struct_nums = file_size // cls.DP_DATA_FMT_SIZE
dp_data = struct.unpack(cls.DP_BIN_START_TAG + cls.DP_DATA_FMT * struct_nums, dp_bin_data)
```

**与 VULN-SEC-001 的区别**：此处使用 `file_reader.read()` 而非通过 `pre_process()` 方法，直接将整个文件读入内存，进一步增加了内存压力。`struct.unpack()` 需要完整的二进制数据作为输入，无法流式处理。

**潜在利用场景**：
1. 攻击者提供超大 DP 二进制数据文件
2. 文件内容全部加载到内存（第 199 行）
3. `struct.unpack()` 为解析结果分配内存（与输入大小成正比）
4. 双重内存消耗导致系统资源耗尽

**建议修复方式**：
1. 添加文件大小限制，参考 VULN-SEC-001 的修复方案
2. 使用 `file_reader.read(MAX_CHUNK_SIZE)` 分块读取
3. 对于超大文件，考虑使用 mmap 进行内存映射解析而非完全加载
4. 统一 msparser 模块的文件大小检查逻辑，避免各解析器独立实现

---

### [VULN-SEC-003] resource_consumption - read_binary_data

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-400 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `analysis/msparser/hardware/ddr_parser.py:69-71` @ `read_binary_data`
**模块**: msparser

**描述**: Uncontrolled Resource Consumption (DoS) via unbounded struct.unpack format string multiplication in DDR parser.

**漏洞代码** (`analysis/msparser/hardware/ddr_parser.py:69-71`)

```c
struct_nums = len(ddr_data) // StructFmt.DDR_FMT_SIZE
struct_data = struct.unpack(StructFmt.BYTE_ORDER_CHAR + StructFmt.DDR_FMT * struct_nums, ddr_data)
```

**达成路径**

File data length → struct_nums calculation → format string multiplication (DDR_FMT * struct_nums) → struct.unpack() with unbounded format string

**验证说明**: DDR解析的内存消耗问题。文件来自用户目录，建议添加大小限制。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：从源代码（`analysis/msparser/hardware/ddr_parser.py:67-71`）可见，DDR 数据解析同样存在无界内存分配问题。第 68-71 行：

```python
ddr_data = self.calculate.pre_process(ddr_f.file_reader, os.path.getsize(ddr_file))
struct_nums = len(ddr_data) // StructFmt.DDR_FMT_SIZE
struct_data = struct.unpack(StructFmt.BYTE_ORDER_CHAR + StructFmt.DDR_FMT * struct_nums, ddr_data)
```

**代码路径分析**：
- `ddr_file` 路径来自 `self.sample_config.get("result_dir", "")` + `data` + `file_name`
- `result_dir` 由 CLI 参数指定，攻击者可控制
- 文件内容由 `pre_process()` 处理后全量传入 `struct.unpack()`

**潜在利用场景**：
1. 用户指定包含恶意 DDR 数据文件的 result_dir
2. 攻击者放置超大的 ddr_*.data 文件
3. 循环解析（第 73-76 行）进一步消耗内存处理每个结构体
4. 多文件并发处理可能导致内存累积消耗

**设计改进建议**：
1. 统一实现 `BaseParser` 类，包含文件大小验证逻辑
2. 所有解析器继承并复用安全验证
3. 添加全局配置 `MAX_PARSE_FILE_SIZE_MB = 500`
4. 在 FileOpen 或 pre_process 层统一注入大小检查

---

### [VULN-SEC-005] resource_consumption - parse

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `analysis/msparser/l2_cache/l2_cache_parser.py:79-85` @ `parse`
**模块**: msparser

**描述**: Unbounded file read in L2 cache parser. Reads entire file content into memory without size limit check before processing. Large files could cause memory exhaustion.

**漏洞代码** (`analysis/msparser/l2_cache/l2_cache_parser.py:79-85`)

```c
_all_l2_cache_data = _l2_cache_file.file_reader.read(_file_size)
for _index in range(_file_size // StructFmt.L2_CACHE_DATA_SIZE):
    l2_cache_data_bean.decode(_all_l2_cache_data[...])
```

**达成路径**

os.path.getsize() → read(file_size) without MAX_READ_FILE_BYTES limit → memory consumption proportional to file size

**验证说明**: L2缓存解析的无限制文件读取。文件来自用户CLI参数目录。建议添加MAX_READ_FILE_BYTES检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-006] resource_consumption - parse

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `analysis/msparser/l2_cache/soc_pmu_parser.py:84-88` @ `parse`
**模块**: msparser

**描述**: Unbounded file read in SOC PMU parser. Similar pattern - reads entire file content without size validation.

**漏洞代码** (`analysis/msparser/l2_cache/soc_pmu_parser.py:84-88`)

```c
_all_soc_pmu_data = _soc_pmu_file.file_reader.read(_file_size)
for index in range(_file_size // StructFmt.SOC_PMU_FMT_SIZE):
    soc_pmu_data_bean.decode(_all_soc_pmu_data[...])
```

**达成路径**

os.path.getsize() → read(file_size) without MAX_READ_FILE_BYTES limit → memory consumption proportional to file size

**验证说明**: SOC PMU解析的无限制文件读取。与SEC-005类似。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-008] resource_consumption - _do_read_binary_data, _do_read_mdc_binary_data

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `analysis/msparser/hardware/tscpu_parser.py:240-258` @ `_do_read_binary_data, _do_read_mdc_binary_data`
**模块**: msparser

**描述**: Unbounded file read in TSCPU parser. Reads entire file into memory using calculate.pre_process without size validation. Multiple files processed in loop could cause memory exhaustion.

**漏洞代码** (`analysis/msparser/hardware/tscpu_parser.py:240-258`)

```c
tscpu_data = self.calculate.pre_process(file, file_size)
for _index in range(file_size // StructFmt.TSCPU_FMT_SIZE):
    decoder = TscpuDecoder.decode(tscpu_data[...])
```

**达成路径**

os.path.getsize() → pre_process() reads entire file → memory consumption proportional to file size

**验证说明**: TSCPU解析的无限制文件读取。建议添加文件大小检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-009] resource_consumption - _read_binary_helper

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `analysis/msparser/hardware/llc_parser.py:105-115` @ `_read_binary_helper`
**模块**: msparser

**描述**: Unbounded file read in LLC parser. Similar pattern - reads entire file into memory without size limit.

**漏洞代码** (`analysis/msparser/hardware/llc_parser.py:105-115`)

```c
llc_data = self.calculate.pre_process(llc_file, _file_size)
for _index in range(_file_size // StructFmt.LLC_FMT_SIZE):
    struct.unpack(StructFmt.LLC_FMT, one_slice)
```

**达成路径**

os.path.getsize() → pre_process() reads entire file → memory consumption proportional to file size

**验证说明**: LLC解析的无限制文件读取。建议添加文件大小检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [PY-DF-profiling_bean-002] Improper Input Validation - construct_bean

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow_scanner

**位置**: `analysis/profiling_bean/struct_info/freq.py:71-76` @ `construct_bean`
**模块**: profiling_bean

**描述**: Binary data count value used in loop iteration without upper bounds validation. The _count field from binary data (struct.unpack result) controls loop iteration count. Maliciously crafted binary data with extremely large count values could cause denial of service through excessive iterations or index out of bounds errors.

**漏洞代码** (`analysis/profiling_bean/struct_info/freq.py:71-76`)

```c
self._count = freq_data[self.COUNT_INDEX]
self._lpm_data = []
for idx in range(self.count):
    syscnt = freq_data[self.SYSCNT_BEGIN_INDEX + self.INTERVAL * idx]
    freq = freq_data[self.FREQ_BEGIN_INDEX + self.INTERVAL * idx]
    self._lpm_data.append(LpmData(syscnt, freq))
```

**达成路径**

bin_data (user file) -> struct.unpack() -> freq_data -> freq_data[COUNT_INDEX] -> self._count -> range(self.count) -> potential DoS/index overflow

**验证说明**: 二进制数据count值控制循环迭代，用户可控制文件大小触发DoS或索引越界。建议添加count上限检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [PY-DF-profiling_bean-003] Improper Input Validation - construct_bean

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow_scanner

**位置**: `analysis/profiling_bean/struct_info/lpm_info_bean.py:76-80` @ `construct_bean`
**模块**: profiling_bean

**描述**: Binary data count value used in loop iteration without upper bounds validation. Similar to freq.py, the _count field controls loop iterations for data extraction. Large count values could cause index out of bounds when accessing lpm_info_data array.

**漏洞代码** (`analysis/profiling_bean/struct_info/lpm_info_bean.py:76-80`)

```c
self._count = lpm_info_data[0]
self._type = lpm_info_data[1]
for i in range(self._count):
    self._lpm_data.append(LpmData(lpm_info_data[2 + i * 3], lpm_info_data[3 + i * 3]))
```

**达成路径**

bin_data (user file) -> struct.unpack() -> lpm_info_data -> lpm_info_data[0] -> self._count -> range(self._count) -> potential index overflow

**验证说明**: 与bean-002相同，二进制数据count控制循环。建议添加上限检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SA-MISC-002] improper_authentication - CustomBind.find_threads

**严重性**: Medium | **CWE**: CWE-287 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `misc/host_analyzer/cpu_binder/cpu_binder.py:422-428` @ `CustomBind.find_threads`
**模块**: misc_tools

**描述**: 进程名称匹配使用字符串包含检查（`if self.process_name in line`），可能导致匹配到错误进程。攻击者可创建包含目标进程名称的恶意进程，导致绑核操作影响错误进程或实现权限提升。

**漏洞代码** (`misc/host_analyzer/cpu_binder/cpu_binder.py:422-428`)

```c
for line in out.splitlines():
    if self.process_name in line:
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            pid = int(parts[select_idx])
            ppid = int(parts[1 - select_idx])
            pid_list.append((pid, ppid))
```

**达成路径**

配置文件 process_name [SOURCE] → ps 命令输出 → 字符串包含匹配 → taskset 绑核命令 [SINK]

**验证说明**: 进程名称字符串包含匹配可能匹配错误进程。攻击者可创建包含目标名称的恶意进程。建议使用精确匹配或PID验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-IF-001] Improper Link Resolution Before File Access - get_host_result_dir

**严重性**: Medium | **CWE**: CWE-59 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: SecurityAuditor

**位置**: `analysis/common_func/path_manager.py:97-101` @ `get_host_result_dir`
**模块**: interface
**跨模块**: interface → common_func → msmodel → profiling_bean

**描述**: PathManager.get_host_result_dir() accesses derived path 'collection_path/../host' without symlink validation. While check_path_valid validates the user-provided path itself, the derived path calculated by get_host_result_dir (line 97-101 in path_manager.py) uses os.path.realpath to resolve symlinks but is not validated. If '/home/host' or similar derived path is a symlink pointing to sensitive data directories, the tool will access unintended locations via MsProfClusterInfo and ClusterInfoViewModel.

**漏洞代码** (`analysis/common_func/path_manager.py:97-101`)

```c
def get_host_result_dir(cls, result_dir: str):
    return os.path.realpath(cls.get_path_under_result_dir(result_dir, "..", cls.HOST))
```

**达成路径**

[CREDENTIAL_FLOW] User input (collection_path) -> check_path_valid (validates original path only) -> PathManager.get_db_path -> get_host_result_dir -> os.path.realpath(collection_path/../host) -> If symlink, resolves to unintended location -> ClusterInfoViewModel.init -> DBManager.create_connect_db -> Reads database from resolved path

**验证说明**: 衍生路径../host通过realpath解析但未执行与原始路径相同的验证。与CROSS-003相同问题。建议对衍生路径验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -10 | context: 0 | cross_file: 0

---

### [PY-MSMODEL-SQL-001] SQL Injection - get_ge_info_by_device_id

**严重性**: Medium（原评估: HIGH → 验证后: Medium） | **CWE**: CWE-89 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow_scanner_python

**位置**: `analysis/msmodel/ge/ge_info_model.py:78-83` @ `get_ge_info_by_device_id`
**模块**: msmodel

**描述**: SQL injection via f-string in ge_info_model.py:78-81. The device_id and task_type values are directly embedded into SQL queries without parameterization. The table_name parameter is also embedded directly via .format().

**漏洞代码** (`analysis/msmodel/ge/ge_info_model.py:78-83`)

```c
ge_sql = "select * from {0} where device_id={1} ".format(table_name, device_id)
condition += " AND task_type != '{0}' ".format(t)
```

**达成路径**

table_name (param) -> .format() -> SQL execute; device_id (param) -> .format() -> SQL execute; task_type_filter (param) -> loop t -> .format() -> SQL execute

**验证说明**: device_id和task_type来自内部数据处理，非用户直接输入。table_name来自TablesConfig常量。风险受限于数据来源。

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [PY-MSMODEL-SQL-004] SQL Injection - get_hccl_ops

**严重性**: Medium（原评估: HIGH → 验证后: Medium） | **CWE**: CWE-89 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow_scanner_python

**位置**: `analysis/msmodel/hccl/hccl_model.py:122-130` @ `get_hccl_ops`
**模块**: msmodel

**描述**: SQL injection via f-string in hccl_model.py:122. The model_id and index_id parameters are directly embedded into SQL WHERE condition without parameterization.

**漏洞代码** (`analysis/msmodel/hccl/hccl_model.py:122-130`)

```c
where_condition = f'and model_id={model_id} and (index_id={index_id} or index_id=0)'
```

**达成路径**

model_id (param) -> f-string -> SQL; index_id (param) -> f-string -> SQL

**验证说明**: model_id和index_id来自内部数据处理结果，非用户直接输入。但应使用参数化查询。

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SA-CROSS-003] symlink_following_cross_module - get_host_result_dir_cross_module

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-59 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `analysis/common_func/path_manager.py:97-101` @ `get_host_result_dir_cross_module`
**模块**: cross_module
**跨模块**: interface → common_func → msmodel

**描述**: 跨模块符号链接跟随漏洞：衍生路径未验证链 interface → common_func/path_manager.get_host_result_dir() → os.path.realpath。用户提供的路径验证后，衍生路径 ../host 通过 os.path.realpath 解析符号链接，未进行相同验证。攻击者可在特定位置创建符号链接指向敏感目录。

**漏洞代码** (`analysis/common_func/path_manager.py:97-101`)

```c
调用链: interface.get_msprof_info → check_path_valid(原始路径) → PathManager.get_host_result_dir → os.path.realpath(衍生路径)
```

**达成路径**

collection_path → check_path_valid [仅验证原始路径] → get_host_result_dir → os.path.realpath(../host) [未验证的衍生路径]

**验证说明**: 衍生路径../host通过realpath解析符号链接，但未进行与原始路径相同的验证。攻击者可在特定位置创建符号链接指向敏感目录。建议对衍生路径也执行check_path_valid。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -10 | context: 0 | cross_file: 0

---

### [DF-PY-012] PATH_TRAVERSAL - FileManager.remove_file

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner-python

**位置**: `analysis/common_func/file_manager.py:46-47` @ `FileManager.remove_file`
**模块**: common_func
**跨模块**: common_func → export_command → import_command

**描述**: Arbitrary file deletion in remove_file(): file_path passed to os.remove() without os.path.realpath() prefix check to prevent traversal

**漏洞代码** (`analysis/common_func/file_manager.py:46-47`)

```c
if os.path.isfile(file_path):
    os.remove(file_path)
```

**达成路径**

[IN] file_path (from ExportCommand/ImportCommand) -> os.remove() [SINK]

**验证说明**: remove_file接收file_path参数，路径来自CLI入口并经过check_path_valid验证。但验证不检查路径前缀限制，用户理论上可删除任意位置的已验证路径文件。本地CLI工具，风险受限于用户权限。

**评分明细**: base: 30 | reachability: 30 | controllability: 0 | mitigations: -20 | context: 0 | cross_file: 0

---

### [DF-PY-013] PATH_TRAVERSAL - PathManager.del_dir

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner-python

**位置**: `analysis/common_func/path_manager.py:223-224` @ `PathManager.del_dir`
**模块**: common_func

**描述**: Arbitrary directory deletion in del_dir(): del_path passed to shutil.rmtree() and os.remove() without proper path validation

**漏洞代码** (`analysis/common_func/path_manager.py:223-224`)

```c
os.chmod(file_path, stat.S_IWUSR)
os.remove(file_path)
shutil.rmtree(del_path, ignore_errors=True)
```

**达成路径**

[IN] del_path -> os.remove()/shutil.rmtree() [SINK]

**验证说明**: del_dir的shutil.rmtree路径来自CLI参数，经check_path_valid验证但不限制前缀。用户可删除任意已验证目录。本地CLI工具风险。

**评分明细**: base: 30 | reachability: 30 | controllability: 0 | mitigations: -20 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (12)

### [VULN-SEC-004] resource_consumption - _is_mdc_binary_data

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-400 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `analysis/msparser/hardware/tscpu_parser.py:168-176` @ `_is_mdc_binary_data`
**模块**: msparser

**描述**: Potential infinite loop in MDC binary data validation. The while loop reads 4 bytes header and 180 bytes data repeatedly without checking remaining file size. If file appears valid but is corrupted, loop could consume significant resources.

**漏洞代码** (`analysis/msparser/hardware/tscpu_parser.py:168-176`)

```c
while True:
    header = binary_file.read(self.HEADER_SIZE)
    if not header:
        break
    if struct.unpack(self.BYTE_ORDER_CHAR + 'L', header)[0] != self.HEADER_NUMBER:
        return False
    binary_file.read(self.MDC_DATA_LENGTH)
```

**达成路径**

binary_file.read() in infinite loop → no file size boundary check

**验证说明**: MDC二进制验证的潜在无限循环。文件来自用户目录，但有header检查中断循环。风险较低。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -5 | context: 0 | cross_file: 0

---

### [PY-MSMODEL-SQL-007] SQL Injection - get_ascend_task_data_with_op_name_pattern_and_stream_id

**严重性**: Low（原评估: MEDIUM → 验证后: Low） | **CWE**: CWE-89 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow_scanner_python

**位置**: `analysis/msmodel/task_time/ascend_task_model.py:70-84` @ `get_ascend_task_data_with_op_name_pattern_and_stream_id`
**模块**: msmodel

**描述**: SQL injection via .format() in ascend_task_model.py:70,80-84. The stream_ids and op_name_pattern are directly embedded into SQL query. The op_name_pattern is placed in LIKE clause without escaping.

**漏洞代码** (`analysis/msmodel/task_time/ascend_task_model.py:70-84`)

```c
stream_id_condition = "b.stream_id in ({})".format(",".join(map(str, stream_ids)))
and (a.op_name like '%{pattern}' or {stream_id_condition})
```

**达成路径**

stream_ids (param) -> map -> join -> .format() -> SQL; op_name_pattern (param) -> .format() -> SQL LIKE

**验证说明**: stream_ids和op_name_pattern来自内部数据处理，非用户直接输入。

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [DF-msinterface-004] Path Traversal - _start_view

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: DataFlow Scanner

**位置**: `analysis/msinterface/msprof_export.py:811` @ `_start_view`
**模块**: msinterface
**跨模块**: msinterface → csrc

**描述**: User-controlled reports_path passed to C interface without comprehensive path traversal validation. While check_file_readable blocks symlinks and validates existence, it does not prevent '../' sequences. The path is passed to msprof_analysis C library for file reading, potentially allowing arbitrary file access if the resolved path escapes intended boundaries.

**漏洞代码** (`analysis/msinterface/msprof_export.py:811`)

```c
export_timeline(path_table.get("collection_path"), self.reports_path)
```

**达成路径**

sys.argv → args.reports_path → check_file_readable() → self.reports_path → export_timeline() → msprof_analysis.parser.export_timeline(project_path, report_json_path)

**验证说明**: reports_path传给C接口，路径经过check_file_readable验证。但C接口可能有额外风险需独立评估。

**评分明细**: base: 30 | reachability: 30 | controllability: 0 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN_MISC_002] arbitrary_file_read - run

**严重性**: Low（原评估: MEDIUM → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner-python

**位置**: `misc/host_analyzer/cpu_binder/cpu_binder.py:569-573` @ `run`
**模块**: misc_tools
**跨模块**: host_analyzer → gil_tracer

**描述**: Command line argument args.config can point to arbitrary file path. While FileManager implements owner consistency and symlink checks, an attacker with file write capability could still read arbitrary JSON files for information disclosure.

**漏洞代码** (`misc/host_analyzer/cpu_binder/cpu_binder.py:569-573`)

```c
if not os.path.exists(args.config):
    logging.error(f"The {args.config} file does not exist...")
input_data = FileManager.read_json_file(args.config)
```

**达成路径**

args.config (cmdline) → FileManager.read_json_file() → json.load()

**验证说明**: args.config读取JSON文件，但有FileManager验证和owner检查。本地CLI工具风险受控。

**评分明细**: base: 30 | reachability: 30 | controllability: 0 | mitigations: -20 | context: 0 | cross_file: 0

---

### [VULN_MISC_003] insecure_config_loading - load_custom_bind / run

**严重性**: Low（原评估: MEDIUM → 验证后: Low） | **CWE**: CWE-626 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner-python

**位置**: `misc/host_analyzer/cpu_binder/cpu_binder.py:542-584` @ `load_custom_bind / run`
**模块**: misc_tools

**描述**: Loaded configuration controls critical system operations: process binding (taskset), IRQ affinity manipulation. Malicious config file could bind processes to unauthorized CPUs, manipulate interrupt handlers, or target specific PIDs for manipulation.

**漏洞代码** (`misc/host_analyzer/cpu_binder/cpu_binder.py:542-584`)

```c
input_data = FileManager.read_json_file(args.config)
binders.append(CustomBind(
    process_name=item.get('process_name'),
    pid=item.get('pid'),
    irq_id=item.get('irq_id')
))
bind.irq_bind()  # writes to /proc/irq/{irq_id}/smp_affinity
```

**达成路径**

json.load() → load_custom_bind() → CustomBind.bind() → irq_bind() → open(f'/proc/irq/{irq_id}/smp_affinity', 'w')

**验证说明**: 配置文件控制进程绑定和IRQ操作，但工具需特定权限。配置来源受控。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-010] resource_consumption - parse

**严重性**: Low | **CWE**: CWE-400 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `analysis/msparser/parallel/parallel_strategy_parser.py:63-70` @ `parse`
**模块**: msparser

**描述**: Potential DoS in parallel_strategy_parser via unbounded JSON file concatenation. Multiple files are read and concatenated before json.loads(), which could consume large memory.

**漏洞代码** (`analysis/msparser/parallel/parallel_strategy_parser.py:63-70`)

```c
for _parallel_file in parallel_files:
    parallel_file = PathManager.get_data_file_path(self._project_path, _parallel_file)
    with FileOpen(parallel_file, 'rt') as _file:
        parallel_data = parallel_data + _file.file_reader.read()
parallel_data = json.loads(parallel_data)
```

**达成路径**

Multiple files → concatenated string parallel_data → json.loads() → memory proportional to total file sizes

**验证说明**: 并行策略解析的多文件拼接。文件来自用户目录，建议添加总大小限制。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -15 | context: 0 | cross_file: 0

---

### [PY-MSMODEL-SQL-005] SQL Injection - get_all_events_from_db

**严重性**: Low（原评估: MEDIUM → 验证后: Low） | **CWE**: CWE-89 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow_scanner_python

**位置**: `analysis/msmodel/cluster_info/communication_model.py:42-46` @ `get_all_events_from_db`
**模块**: msmodel

**描述**: SQL injection via .format() in communication_model.py:42-46. The top_hccl_ops tuple values (op_name) are directly embedded into SQL IN clause without parameterization.

**漏洞代码** (`analysis/msmodel/cluster_info/communication_model.py:42-46`)

```c
condition = "op_name='{}'".format(top_hccl_ops[0])
condition = "op_name IN {}".format(top_hccl_ops)
```

**达成路径**

top_hccl_ops (param) -> .format() -> SQL IN clause

**验证说明**: top_hccl_ops来自内部数据处理，非用户输入。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [PY-MSMODEL-SQL-006] SQL Injection - get_ascend_task_time_extremes

**严重性**: Low（原评估: MEDIUM → 验证后: Low） | **CWE**: CWE-89 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow_scanner_python

**位置**: `analysis/msmodel/task_time/ascend_task_model.py:102-108` @ `get_ascend_task_time_extremes`
**模块**: msmodel

**描述**: SQL injection via f-string in ascend_task_model.py:102-103. The filter_type list values are mapped to quoted strings and embedded into SQL NOT IN clause without proper sanitization.

**漏洞代码** (`analysis/msmodel/task_time/ascend_task_model.py:102-108`)

```c
type_condition = "host_task_type not in ({})".format(
    ",".join(map(lambda x: f"'{x}'", filter_type)))
```

**达成路径**

filter_type (param) -> map -> join -> f-string -> SQL

**验证说明**: filter_type来自内部常量列表，非用户输入。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [PY-MSMODEL-SQL-008] SQL Injection - _init_ai_core_events_table

**严重性**: Low（原评估: LOW → 验证后: Low） | **CWE**: CWE-89 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow_scanner_python

**位置**: `analysis/msmodel/aic/ai_core_sample_model.py:232-238` @ `_init_ai_core_events_table`
**模块**: msmodel

**描述**: SQL injection via f-string in ai_core_sample_model.py:232-238. PMU event values from events list are used as table names after replace('0x', 'r') transformation. If events contain malicious values, SQL injection is possible.

**漏洞代码** (`analysis/msmodel/aic/ai_core_sample_model.py:232-238`)

```c
DBManager.execute_sql(self.conn, "create table {tablename}(timestamp INTEGER, pmucount INTEGER, coreid INTEGER).format(tablename=value.replace('0x', 'r')))
```

**达成路径**

events (param) -> enumerate -> value -> replace -> .format() -> SQL CREATE TABLE

**验证说明**: events来自内部配置，经过replace处理。非用户直接输入。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [host_prof_pt_001] Path Traversal - __init__

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow_scanner_python

**位置**: `analysis/host_prof/host_prof_base/host_prof_presenter_base.py:35-36` @ `__init__`
**模块**: host_prof
**跨模块**: host_prof → common_func

**描述**: Path traversal vulnerability in PathManager.get_data_file_path() and check_path_valid(). The file_name parameter from os.listdir() is combined with base path using os.path.join() without verifying that os.path.realpath() of the combined path stays within the expected data directory boundary. An attacker who controls the data directory could create files with path traversal names like '../../../etc/passwd' which would resolve to paths outside the data directory.

**漏洞代码** (`analysis/host_prof/host_prof_base/host_prof_presenter_base.py:35-36`)

```c
self.file_name = PathManager.get_data_file_path(result_dir, file_name)
```

**达成路径**

Source: file_name (os.listdir in analysis/*.py) → Propagation: PathManager.get_data_file_path(os.path.join) → Sink: FileOpen(open)

**验证说明**: file_name来自os.listdir，在用户目录中。虽然有风险但需用户控制数据目录内容。建议添加路径验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -15 | context: 0 | cross_file: 0

---

### [host_prof_iv_001] Improper Input Validation - __init__

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow_scanner_python

**位置**: `analysis/host_prof/host_cpu_usage/model/cpu_time_info.py:23-29` @ `__init__`
**模块**: host_prof

**描述**: Missing bounds checking in CpuTimeInfo.__init__(). The class parses performance data lines and directly accesses array indices (fields[0], fields[3], fields[13], fields[14], fields[38]) without verifying the line has sufficient fields. Malformed performance data files could cause IndexError exceptions.

**漏洞代码** (`analysis/host_prof/host_cpu_usage/model/cpu_time_info.py:23-29`)

```c
fields = line_info.split()
self._pid = int(fields[0])
self._tid = int(fields[3])
self._utime = int(fields[13])
self._stime = int(fields[14])
self._cpu_no = int(fields[38])
```

**达成路径**

Source: file content (user-provided performance data) → Propagation: line iteration, split() → Sink: array index access without bounds check

**验证说明**: 数组索引访问缺少边界检查，但数据来自用户提供的性能数据文件。建议添加len(fields)检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -15 | context: 0 | cross_file: 0

---

### [host_prof_iv_002] Improper Input Validation - _get_disk_usage_items

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow_scanner_python

**位置**: `analysis/host_prof/host_disk_usage/presenter/host_disk_usage_presenter.py:147-183` @ `_get_disk_usage_items`
**模块**: host_prof

**描述**: Missing bounds checking in host_disk_usage_presenter._get_disk_usage_items(). The code accesses fields[1], fields[4], fields[5], fields[6], fields[7], fields[8], fields[10] after only checking len(fields) < 2. The condition at line 161 checks len(fields) < 8 but fields[10] requires at least 11 fields.

**漏洞代码** (`analysis/host_prof/host_disk_usage/presenter/host_disk_usage_presenter.py:147-183`)

```c
for line in file:
    fields = line.split()
    if len(fields) < 2: continue
    ...
    if len(fields) < 8: continue  # Only checks 8, but accesses fields[10]
```

**达成路径**

Source: file content (user-provided disk usage data) → Propagation: line iteration, split() → Sink: array index access (potential IndexError)

**验证说明**: 边界检查不完整(len<8但访问fields[10])，建议修复。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -15 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| common_func | 0 | 0 | 2 | 0 | 2 |
| cross_module | 0 | 0 | 1 | 0 | 1 |
| host_prof | 0 | 0 | 0 | 3 | 3 |
| interface | 0 | 0 | 1 | 0 | 1 |
| misc_tools | 0 | 1 | 2 | 2 | 5 |
| msinterface | 0 | 0 | 0 | 1 | 1 |
| msmodel | 0 | 0 | 2 | 4 | 6 |
| msparser | 0 | 0 | 7 | 2 | 9 |
| profiling_bean | 0 | 0 | 2 | 0 | 2 |
| **合计** | **0** | **1** | **17** | **12** | **30** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-400 | 9 | 30.0% |
| CWE-89 | 6 | 20.0% |
| CWE-22 | 6 | 20.0% |
| CWE-20 | 4 | 13.3% |
| CWE-59 | 2 | 6.7% |
| CWE-626 | 1 | 3.3% |
| CWE-426 | 1 | 3.3% |
| CWE-287 | 1 | 3.3% |

---

## 8. 修复建议

### 优先级 1: 立即修复（High 严重性）

**[VULN-SA-MISC-001] PATH 劫持漏洞**

这是本次扫描唯一的高严重性漏洞，需立即处理：

1. **使用绝对路径**：将 `sysTrace_cli` 替换为绝对路径（如 `/usr/local/bin/sysTrace_cli`），或通过配置文件指定工具路径
2. **限制 PATH 范围**：使用受限 PATH 执行子进程
   ```python
   env={'PATH': '/usr/bin:/bin:/usr/local/bin', 'LD_PRELOAD': ''}
   ```
3. **路径验证**：执行前验证 sysTrace_cli 是否位于预期路径，检查文件权限和签名
4. **审计日志**：记录实际执行的命令路径和返回码，便于事后审计

**修复示例**：
```python
SYSTRACE_CLI_PATH = '/usr/local/bin/sysTrace_cli'  # 或从配置加载
if not os.path.isfile(SYSTRACE_CLI_PATH):
    raise RuntimeError("sysTrace_cli not found at expected path")
subprocess.run([SYSTRACE_CLI_PATH, 'record', ...], env={'PATH': '/usr/bin:/bin'})
```

### 优先级 2: 短期修复（Medium 严重性）

**CWE-400 资源消耗漏洞（9 处）**

建议统一修复 msparser 模块的资源消耗问题：

1. **定义全局文件大小限制**
   ```python
   MAX_FILE_SIZE_MB = 500
   MAX_FILE_SIZE = MAX_FILE_SIZE_MB * 1024 * 1024
   ```

2. **在 BaseParser 或 FileOpen 中注入验证**
   ```python
   def validate_file_size(file_path):
       size = os.path.getsize(file_path)
       if size > MAX_FILE_SIZE:
           raise ValueError(f"File size {size} exceeds limit {MAX_FILE_SIZE}")
   ```

3. **分块处理超大文件**：对于大文件使用生成器模式逐步解析

**CWE-22 路径遍历漏洞（6 处）**

建议统一路径验证机制：

1. **路径前缀白名单**：定义允许的目录前缀列表
2. **符号链接验证**：使用 `os.path.realpath()` 解析并验证
3. **衍生路径验证**：确保衍生路径（如 `../host`）与原始路径执行相同验证

**CWE-89 SQL 注入模式（6 处）**

建议使用参数化查询：

```python
# 替换
ge_sql = "select * from {0} where device_id={1}".format(table_name, device_id)
# 使用
ge_sql = "select * from ? where device_id=?"
cursor.execute(ge_sql, (table_name, device_id))
```

### 优先级 3: 计划修复（Low 严重性）

**CWE-20 输入验证缺失（4 处）**

添加边界检查：

```python
# freq.py 示例
self._count = freq_data[self.COUNT_INDEX]
if self._count > MAX_COUNT_LIMIT:
    raise ValueError("count exceeds safety limit")
for idx in range(min(self._count, MAX_ITERATIONS)):
    ...
```

**CWE-59 符号链接问题（2 处）**

确保衍生路径也执行符号链接验证：

```python
def get_host_result_dir(cls, result_dir):
    derived_path = cls.get_path_under_result_dir(result_dir, "..", cls.HOST)
    resolved_path = os.path.realpath(derived_path)
    cls.check_path_valid(resolved_path)  # 对衍生路径也验证
    return resolved_path
```

---

## 9. 修复优先级总结

| 优先级 | 漏洞数量 | 主要类别 | 建议处理周期 |
|--------|----------|----------|--------------|
| P1 - 立即 | 1 | PATH 劫持 | 1 周内 |
| P2 - 短期 | 17 | 资源消耗、路径遍历、SQL注入 | 1-2 月迭代 |
| P3 - 计划 | 12 | 输入验证、符号链接 | 3-6 月计划 |

**建议**：
- P1 漏洞影响 root/sudo 运行场景，需在下次发布前修复
- P2 漏洞可分批修复，建议优先处理高频调用的 msparser 模块
- P3 漏洞风险可控，可在日常维护中逐步改进
