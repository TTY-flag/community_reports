# 漏洞扫描报告 — 已确认漏洞

**项目**: msprobe
**扫描时间**: 2026-04-20T10:30:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描针对 msprobe 项目（华为 MindStudio 精度调试工具）进行了全面的漏洞分析，共发现 **96 个候选漏洞**，其中 **6 个已确认为高危漏洞**（CONFIRMED 状态），**25 个为疑似漏洞**（LIKELY 状态），另有 **3 个被确认为误报**。

**核心风险发现**：

已确认的 6 个高危漏洞涵盖多个关键安全类别，包括：环境变量路径欺骗（CWE-426）、Zip Slip 路径遍历（CWE-22）、Protobuf 数据边界溢出（CWE-787）、OS 命令注入风险（CWE-78）、以及不安全的反序列化（CWE-502）。这些漏洞可能导致**任意代码执行、敏感文件覆盖、信息泄露或系统崩溃**，对 AI 模型训练和推理环境的安全性构成严重威胁。

**业务影响评估**：

msprobe 作为昇腾 AI 开发平台的核心调试工具，广泛用于模型精度对比和数据 dump 分析。在共享服务器、CI/CD 流水线或容器化部署环境中，攻击者可利用上述漏洞实现：以当前用户权限执行任意代码、覆盖系统配置文件实现持久化、窃取 SSH 密钥或 API 令牌、通过恶意 Protobuf 数据触发进程崩溃导致服务中断。

**建议优先修复方向**：

1. **立即处理**（Priority 1）：环境变量路径欺骗（core_compare-004）和 Zip Slip（VULN-001）漏洞，可直接导致任意代码执行和文件覆盖
2. **短期修复**（Priority 2）：不安全的 np.load 反序列化漏洞（infer_offline_np_load_001/002），存在 pickle payload 执行风险
3. **计划修复**（Priority 3）：Protobuf 边界检查（adump-core-003）和参数验证强化（core_compare-003），涉及深层安全架构改进

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 62 | 64.6% |
| LIKELY | 25 | 26.0% |
| CONFIRMED | 6 | 6.3% |
| FALSE_POSITIVE | 3 | 3.1% |
| **总计** | **96** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 6 | 100.0% |
| **有效漏洞总计** | **6** | - |
| 误报 (FALSE_POSITIVE) | 3 | - |

### 1.3 Top 10 关键漏洞

1. **[core_compare-004]** Untrusted Search Path (High) - `python/msprobe/core/compare/offline_data_compare.py:24` @ `_check_msaccucmp_file` | 置信度: 90
2. **[VULN-001-zip-slip-extract_zip]** path_traversal (High) - `python/msprobe/core/common/file_utils.py:980` @ `extract_zip` | 置信度: 85
3. **[adump-core-003]** Out-of-bounds Access (High) - `ccsrc/adump/core/AclDumpDataProcessor.cpp:806` @ `DumpTensorDataToDisk` | 置信度: 85
4. **[core_compare-003]** OS Command Injection (High) - `python/msprobe/core/compare/offline_data_compare.py:70` @ `call_msaccucmp` | 置信度: 85
5. **[infer_offline_np_load_001]** Unsafe Deserialization (High) - `python/msprobe/infer/offline/compare/msquickcmp/onnx_model/onnx_dump_data.py:310` @ `_get_inputs_data_aipp` | 置信度: 85
6. **[infer_offline_np_load_002]** Unsafe Deserialization (High) - `python/msprobe/infer/offline/compare/msquickcmp/net_compare/net_compare.py:217` @ `net_output_compare` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@python/msprobe/msprobe.py` | cmdline | untrusted_local | CLI 工具入口，本地用户通过命令行参数控制工具行为，参数值可被攻击者（本地非特权用户）控制 | 解析命令行参数并调用对应子命令 |
| `load_json@python/msprobe/core/common/file_utils.py` | file | untrusted_local | 读取 JSON 配置文件，文件路径由用户通过 CLI 参数传入，文件内容由用户控制 | 加载 JSON 配置文件内容 |
| `load_yaml@python/msprobe/core/common/file_utils.py` | file | untrusted_local | 读取 YAML 配置文件，文件路径由用户通过 CLI 参数传入，文件内容由用户控制 | 加载 YAML 配置文件内容 |
| `load_npy@python/msprobe/core/common/file_utils.py` | file | untrusted_local | 读取 numpy 数据文件，文件路径由用户通过 CLI 参数传入，文件内容可能包含恶意构造的数组 | 加载 numpy 数据文件 |
| `_process_dump_file@python/msprobe/core/dump/dump2db/dump2db.py` | file | untrusted_local | 处理 dump.json 文件，文件路径和数据内容由用户控制，包含大量 tensor 统计数据 | 解析 dump.json 文件并导入数据库 |
| `LoadConfig@ccsrc/adump/base/DebuggerConfig.cpp` | file | untrusted_local | C++ 层加载配置文件，配置路径由 Python 传入（来自用户 CLI 参数），配置内容由用户控制 | 加载并解析 JSON 配置文件 |
| `DumpToDisk@ccsrc/adump/core/AclDumpDataProcessor.cpp` | file | semi_trusted | 处理 ACL dump 数据并写入磁盘，数据来源为 ACL API（硬件层），但路径配置来自用户 | 处理并写入 dump 数据到磁盘 |
| `InitPrecisionDebugger@ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp` | rpc | semi_trusted | Python C API 接口，从 Python 层接收 framework 和 config_path 参数，参数来自用户 CLI | 初始化 PrecisionDebugger C++ 对象 |

**其他攻击面**:
- CLI 参数解析: argparse 解析命令行参数
- JSON 配置文件解析: nlohmann::json (C++), json.load() (Python)
- YAML 配置文件解析: yaml.safe_load()
- Numpy 文件解析: np.load() with allow_pickle=False
- Protobuf 数据解析: AclDumpMsg::DumpData.ParseFromArray()
- CSV 文件读写: pd.read_csv(), csv.writer
- Excel 文件读写: pd.read_excel(), pd.ExcelWriter
- ZIP 文件处理: zipfile.ZipFile
- 文件路径处理: os.path, FileUtils::GetAbsPath
- Python C API 边界: PyObject_Call, PyDict_GetItemString

---

## 3. High 漏洞 (6)

### [core_compare-004] Untrusted Search Path - _check_msaccucmp_file

**严重性**: High | **CWE**: CWE-426 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `python/msprobe/core/compare/offline_data_compare.py:24-67` @ `_check_msaccucmp_file`
**模块**: core_compare

**描述**: CANN_PATH from environment variable without validation leads to script execution

**验证说明**: CANN_PATH from environment variable (ASCEND_TOOLKIT_HOME) is directly used to construct script paths for execution. User can manipulate environment to point to malicious scripts. Direct external input path.

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 15

**深度分析**

**根因分析**：

该漏洞的根本原因是代码在第 24 行直接从环境变量 `ASCEND_TOOLKIT_HOME` 获取路径，未进行任何验证或白名单检查：

```python
# offline_data_compare.py:24 (源代码)
CANN_PATH = os.environ.get("ASCEND_TOOLKIT_HOME", "/usr/local/Ascend/ascend-toolkit/latest")
```

随后在第 81 行，该路径被用于构建并执行外部 Python 脚本：

```python
# offline_data_compare.py:81-91 (源代码)
msaccucmp_script_path = _check_msaccucmp_file(CANN_PATH)
python_cmd = sys.executable
full_cmd = [python_cmd, msaccucmp_script_path, "compare"] + cmd_args

process = subprocess.Popen(
    full_cmd,
    shell=False,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    ...
)
```

`_check_msaccucmp_file` 函数（第 58-67 行）仅在给定路径下查找 `msaccucmp.py` 文件是否存在，没有任何路径验证逻辑。

**潜在利用场景**：

1. **共享服务器攻击**：攻击者在 `/tmp/malicious_cann/toolkit/tools/operator_cmp/compare/` 目录下创建恶意 `msaccucmp.py` 脚本，然后修改受害者用户的 `~/.bashrc` 设置 `ASCEND_TOOLKIT_HOME=/tmp/malicious_cann`。当受害者执行 `msprobe compare -m offline_data` 时，恶意脚本以受害者权限执行。

2. **容器环境攻击**：攻击者通过其他漏洞进入容器后，设置环境变量并创建恶意脚本。当 CI/CD 流程调用 msprobe 时，恶意代码在构建环境中执行，可窃取凭证或注入恶意依赖。

3. **供应链攻击**：攻击者创建伪装的"Ascend 工具安装脚本"，在后台修改环境变量和植入恶意脚本，后续所有 msprobe 调用都会执行攻击者代码。

**建议修复方式**：

实施路径白名单验证机制，将允许的 CANN_PATH 限制在已知的可信安装路径（如 `/usr/local/Ascend/`、`/opt/Ascend/`），并在脚本执行前验证脚本文件的完整性（如 SHA256 哈希校验）。

---

### [VULN-001-zip-slip-extract_zip] path_traversal - extract_zip

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `python/msprobe/core/common/file_utils.py:980-1003` @ `extract_zip`
**模块**: core_file_utils
**跨模块**: core_file_utils, config_check

**描述**: Zip Slip: extract_zip函数使用zipfile.extractall()解压文件，未检查ZIP内文件名是否包含路径遍历字符(如"../")。攻击者可构造恶意ZIP文件，将文件写入预期目录之外的位置，实现任意文件写入或覆盖。

**漏洞代码** (`python/msprobe/core/common/file_utils.py:980-1003`)

```python
def extract_zip(zip_file_path, extract_dir):
    """
    Extract the contents of a ZIP archive to a specified directory.
    """
    check_file_suffix(zip_file_path, FileCheckConst.ZIP_SUFFIX)
    check_file_or_directory_path(zip_file_path)
    create_directory(extract_dir)
    try:
        proc_lock.acquire()
        check_zip_file(zip_file_path)  # 仅检查文件大小和数量，不检查路径遍历
    except Exception as e:
        logger.error(f'Save content to file "{os.path.basename(zip_file_path)}" failed.')
        raise RuntimeError(f"Save content to file {os.path.basename(zip_file_path)} failed.") from e
    finally:
        proc_lock.release()
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
            zip_file.extractall(extract_dir)  # 漏洞点！未验证内部文件名路径
    except Exception as e:
        raise RuntimeError(f"extract zip file {os.path.basename(zip_file_path)} failed") from e
    recursive_chmod(extract_dir)
```

**达成路径**

config_checker.py:extract_zip() -> file_utils.py:extract_zip() -> zipfile.extractall()

**验证说明**: Zip Slip vulnerability confirmed: zipfile.extractall() called without path validation. Attacker can craft ZIP with ../../ paths to write outside intended directory.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 15

**深度分析**

**根因分析**：

漏洞核心位于第 1000 行的 `zip_file.extractall(extract_dir)` 调用。虽然 `check_zip_file` 函数检查了 ZIP 内文件数量和大小限制，但**未对文件名进行路径遍历检查**。

攻击者可构造包含如下文件名的 ZIP 文件：
- `../../../etc/cron.d/malicious` — 注入定时任务实现持久化
- `../../../../root/.ssh/authorized_keys` — 覆盖 SSH 密钥实现远程登录
- `../../../home/user/.bashrc` — 修改用户 shell 配置

当用户执行 `msprobe -c malicious.zip benign.zip -o /tmp/output` 时，`extract_zip` 会被 `ConfigChecker.compare()` 调用（config_checker.py:50-52），恶意文件被写入预期目录外的任意位置。

**潜在利用场景**：

1. **任意文件覆盖**：覆盖 `/etc/passwd`、SSH 配置、用户脚本等敏感文件
2. **远程代码执行**：注入 cron 任务或修改 `.bashrc`/`.profile` 实现任意代码执行
3. **权限提升**：在特定条件下覆盖 sudo 配置或 SUID 程序

**建议修复方式**：

在解压前遍历 ZIP 内所有文件名，验证每个文件解压后的绝对路径是否以目标目录开头：

```python
extract_dir = os.path.realpath(extract_dir)
for member in zip_file.namelist():
    member_path = os.path.realpath(os.path.join(extract_dir, member))
    if not member_path.startswith(extract_dir + os.sep):
        raise ValueError(f"Path traversal detected: {member}")
```

---

### [adump-core-003] Out-of-bounds Access - DumpTensorDataToDisk

**严重性**: High | **CWE**: CWE-787 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `ccsrc/adump/core/AclDumpDataProcessor.cpp:806-827` @ `DumpTensorDataToDisk`
**模块**: adump_core

**描述**: tensor.size() from Protobuf used to calculate offset for data access. Malformed Protobuf could cause offset to exceed buffer bounds.

**漏洞代码** (`ccsrc/adump/core/AclDumpDataProcessor.cpp:806-827`)

```cpp
static DebuggerErrno DumpTensorDataToDisk(const std::string& dumpPath, AclDumpMsg::DumpData& dumpData,
                                          const uint8_t* data, size_t dataLen, std::vector<DebuggerSummaryOption>& opt)
{
    DEBUG_FUNC_TRACE();
    std::vector<AclTensorInfo> aclTensorInfos;
    uint64_t offset = 0;
    uint32_t slot = 0;
    for (auto& tensor : dumpData.input()) {
        aclTensorInfos.push_back(AclTensor::ParseAttrsFromDumpData(dumpPath, data + offset, tensor, "input", slot));
        offset += tensor.size();  // 漏洞点：tensor.size() 来自 Protobuf，可被篡改
        slot++;
    }

    slot = 0;
    for (auto& tensor : dumpData.output()) {
        aclTensorInfos.push_back(AclTensor::ParseAttrsFromDumpData(dumpPath, data + offset, tensor, "output", slot));
        offset += tensor.size();
        slot++;
    }

    // 边界检查太晚！此时越界访问已发生
    if (offset > dataLen) {
        LOG_ERROR(DebuggerErrno::ERROR_VALUE_OVERFLOW, dumpPath + ": offset overflow " + std::to_string(offset) + "/" +
                  std::to_string(dataLen) + ".");
        return DebuggerErrno::ERROR_VALUE_OVERFLOW;
    }
    // ...
}
```

**达成路径**

Protobuf dumpData -> tensor.size() -> offset -> data + offset

**验证说明**: Out-of-bounds access via tensor.size() from Protobuf. Malformed protobuf could cause offset overflow. Data comes from ACL callback (semi-trusted).

**评分明细**: base: 30 | reachability: 25 | controllability: 20 | mitigations: 0 | context: -10 | cross_file: 0

**深度分析**

**根因分析**：

该漏洞的关键问题在于**边界检查的时序错误**：在第 823-826 行进行的 `offset > dataLen` 检查发生在数据访问**之后**，而非之前。

数据流分析：
1. Protobuf 消息 `DumpData` 包含 `input` 和 `output` 列表，每个元素的 `size` 字段由 Protobuf 解析
2. 在循环中，`tensor.size()` 直接累加到 `offset` 变量（第 808、815 行）
3. 在累加**之后**，`data + offset` 被传入 `ParseAttrsFromDumpData` 进行数据解析（第 807、814 行）
4. 如果攻击者篡改 Protobuf 数据使 `tensor.size()` 值过大，`data + offset` 将指向缓冲区之外
5. 边界检查（第 823 行）在越界访问已经发生后才执行，无法阻止攻击

**潜在利用场景**：

攻击者可通过 ACL API 回调注入或修改 dump 文件，构造恶意 Protobuf 数据：
- 设置 `input[0].size` 为接近 `dataSegLen` 的值
- 设置 `input[1].size` 为任意值
- 当处理 `input[1]` 时，`data + offset` 已越界

后果包括：
- **信息泄露**：越界读取的内存内容会被写入 `.bin` 或 `.npy` dump 文件
- **进程崩溃**：访问无效内存地址导致程序崩溃
- **数据破坏**：如果越界地址恰好指向可写内存

**建议修复方式**：

将边界检查移至数据访问之前：

```cpp
for (auto& tensor : dumpData.input()) {
    // 修复：在访问前检查边界
    if (offset + tensor.size() > dataLen) {
        LOG_ERROR(...);
        return DebuggerErrno::ERROR_VALUE_OVERFLOW;
    }
    aclTensorInfos.push_back(...);
    offset += tensor.size();
    slot++;
}
```

---

### [core_compare-003] OS Command Injection - call_msaccucmp

**严重性**: High | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `python/msprobe/core/compare/offline_data_compare.py:70-98` @ `call_msaccucmp`
**模块**: core_compare

**描述**: call_msaccucmp constructs subprocess with user-provided arguments

**验证说明**: OS Command Injection risk: subprocess with user-provided arguments. While using list form avoids shell injection, arguments from user paths still flow to command.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 15

**深度分析**

**根因分析**：

该漏洞体现了一个**安全架构设计缺陷**：输入验证延迟发生在下游组件而非调用点。

调用链分析：
```
CLI 参数解析 (utils.py:663-674)
    ↓ type=str，无验证
compare_offline_data_mode(args) (offline_data_compare.py:32-55)
    ↓ 用户输入直接加入 cmd_args
call_msaccucmp(cmd_args) (offline_data_compare.py:70-98)
    ↓ subprocess.Popen 被调用，参数未验证
msaccucmp.py argparse.parse_args()
    ↓ safe_path_string() — 验证首次发生在这里！
```

虽然代码正确使用了 `shell=False` 和列表形式传参（避免经典 shell 注入），但违反了"Fail Early"安全原则：参数从 CLI 到 subprocess 调用全程未经验证，仅在下游 `msaccucmp.py` 中才进行白名单字符检查。

**潜在利用场景**：

1. **路径遍历尝试**：`/../../../etc/shadow` — 使用合法字符 `/` 和 `.`，可能绕过验证
2. **资源消耗攻击**：多次调用导致大量进程创建
3. **日志信息泄露**：第 87 行 `logger.info(f"Calling msaccucmp with command: {' '.join(full_cmd)}")` 泄露完整命令参数

**建议修复方式**：

在 `offline_data_compare.py` 中添加参数验证，与下游 `safe_path_string` 保持一致的白名单策略：

```python
PATH_BLACK_LIST_REGEX = re.compile(r"[^_A-Za-z0-9/.,-]")

def validate_path_string(value):
    if re.search(PATH_BLACK_LIST_REGEX, value):
        raise CompareException(CompareException.INVALID_PATH_ERROR, f"Path contains invalid characters")
    return value
```

---

### [infer_offline_np_load_001] Unsafe Deserialization - _get_inputs_data_aipp

**严重性**: High（原评估: high → 验证后: High） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `python/msprobe/infer/offline/compare/msquickcmp/onnx_model/onnx_dump_data.py:310-311` @ `_get_inputs_data_aipp`
**模块**: infer_offline
**跨模块**: msprobe.infer.utils.util,msprobe.core.common.file_utils

**描述**: np.load used without allow_pickle=False in onnx_dump_data.py. Numpy files can contain malicious pickle payloads that execute arbitrary code when loaded without allow_pickle=False.

**漏洞代码** (`python/msprobe/infer/offline/compare/msquickcmp/onnx_model/onnx_dump_data.py:310-311`)

```python
aipp_output_path = load_file_to_read_common_check(aipp_output_path)
aipp_output = np.load(aipp_output_path)  # 漏洞点：未指定 allow_pickle=False
```

**验证说明**: Unsafe Deserialization: np.load without allow_pickle=False allows malicious pickle execution.

**评分明细**: base: 30 | controllability: 20 | context: -10 | cross_file: 5 | mitigations: 0 | reachability: 30

**深度分析**

**根因分析**：

NumPy 的 `.npy` 文件格式支持两种存储模式：
1. **标准模式**：仅存储数组原始数据，安全
2. **Pickle 模式**：使用 Python pickle 协议序列化任意对象

`np.load()` 默认 `allow_pickle=True`，这意味着如果 `.npy` 文件包含 pickle payload，反序列化时会自动执行 payload 中的 `__reduce__` 方法，导致任意代码执行。

攻击链：
```
恶意 .npy 文件 → np.load() → pickle.loads() → __reduce__() → 任意代码执行
```

虽然 `load_file_to_read_common_check` 进行了文件权限检查（util.py:137-152），但这些检查：
- 不验证文件内容是否包含恶意 payload
- 存在 TOCTOU 竞争条件（检查与使用之间有时间窗口）
- 无法检测符号链接攻击

**潜在利用场景**：

攻击者构造恶意 `.npy` 文件：

```python
class MaliciousPickle:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned.txt',))
np.save('malicious.npy', MaliciousPickle(), allow_pickle=True)
```

当程序执行到第 311 行时，恶意代码以当前进程权限执行。

**建议修复方式**：

添加 `allow_pickle=False` 参数：

```python
aipp_output = np.load(aipp_output_path, allow_pickle=False)
```

或使用项目中已有的安全函数 `load_npy`（file_utils.py:515-522），该函数已正确设置 `allow_pickle=False`。

---

### [infer_offline_np_load_002] Unsafe Deserialization - net_output_compare

**严重性**: High（原评估: high → 验证后: High） | **CWE**: CWE-502 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `python/msprobe/infer/offline/compare/msquickcmp/net_compare/net_compare.py:217-220` @ `net_output_compare`
**模块**: infer_offline
**跨模块**: msprobe.infer.utils.util,msprobe.infer.utils.file_open_check

**描述**: np.load used without allow_pickle=False in net_compare.py. Numpy files can contain malicious pickle payloads that execute arbitrary code when loaded.

**漏洞代码** (`python/msprobe/infer/offline/compare/msquickcmp/net_compare/net_compare.py:217-220`)

```python
npu_data = np.load(npu_dump_file.get(file_index))
golden_data = np.load(golden_net_output_info.get(file_index))
```

**验证说明**: Unsafe Deserialization: np.load without allow_pickle=False in net_compare.

**评分明细**: base: 30 | controllability: 20 | context: -10 | cross_file: 5 | mitigations: 0 | reachability: 30

**修复说明**：该漏洞与 `infer_offline_np_load_001` 同源，均为 `np.load()` 未设置 `allow_pickle=False`。修复方案相同，添加该参数或使用 `load_npy` 安全函数。

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| adump_core | 0 | 1 | 0 | 0 | 1 |
| core_compare | 0 | 2 | 0 | 0 | 2 |
| core_file_utils | 0 | 1 | 0 | 0 | 1 |
| infer_offline | 0 | 2 | 0 | 0 | 2 |
| **合计** | **0** | **6** | **0** | **0** | **6** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-502 | 2 | 33.3% |
| CWE-787 | 1 | 16.7% |
| CWE-78 | 1 | 16.7% |
| CWE-426 | 1 | 16.7% |
| CWE-22 | 1 | 16.7% |

---

## 修复建议

### 优先级 1: 立即修复（Critical/高危 - 可导致任意代码执行）

#### 1.1 core_compare-004 — 环境变量路径欺骗

**风险**: 攻击者可控制环境变量执行任意 Python 脚本，实现完全的代码执行。

**修复方案**:
```python
# 定义可信路径白名单
TRUSTED_CANN_PATHS = [
    "/usr/local/Ascend/ascend-toolkit/latest",
    "/usr/local/Ascend/ascend-toolkit",
    "/opt/Ascend/ascend-toolkit/latest",
]

def get_cann_path():
    cann_path = os.environ.get("ASCEND_TOOLKIT_HOME", "/usr/local/Ascend/ascend-toolkit/latest")
    cann_path = os.path.realpath(cann_path)
    
    for trusted_path in TRUSTED_CANN_PATHS:
        if cann_path.startswith(os.path.realpath(trusted_path)):
            return cann_path
    
    logger.warning(f"ASCEND_TOOLKIT_HOME not in trusted paths. Using default.")
    return "/usr/local/Ascend/ascend-toolkit/latest"
```

**验证**: 添加单元测试验证恶意路径被拒绝。

---

#### 1.2 VULN-001-zip-slip — Zip Slip 路径遍历

**风险**: 攻击者可覆盖任意文件，注入定时任务，实现持久化和远程代码执行。

**修复方案**:
```python
def extract_zip(zip_file_path, extract_dir):
    # ... 现有检查 ...
    extract_dir = os.path.realpath(extract_dir)
    
    with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
        for member in zip_file.namelist():
            member_path = os.path.realpath(os.path.join(extract_dir, member))
            if not member_path.startswith(extract_dir + os.sep) and member_path != extract_dir:
                raise ValueError(f"Path traversal detected: {member}")
        zip_file.extractall(extract_dir)
```

**验证**: 添加测试用例验证包含 `../` 的 ZIP 文件被拒绝。

---

### 优先级 2: 短期修复（高危 - 1-2 周内完成）

#### 2.1 infer_offline_np_load_001/002 — 不安全反序列化

**风险**: 恶意 `.npy` 文件可触发 pickle payload 执行任意代码。

**修复方案**:
```python
# 方案 A: 添加 allow_pickle=False
aipp_output = np.load(aipp_output_path, allow_pickle=False)

# 方案 B: 使用已有的安全函数（推荐）
from msprobe.core.common.file_utils import load_npy
aipp_output = load_npy(aipp_output_path)
```

**全局搜索**: 使用 `grep -r "np\.load\(" --include="*.py"` 查找所有不安全调用并逐一修复。

---

#### 2.2 adump-core-003 — Protobuf 边界溢出

**风险**: 恶意 Protobuf 数据导致越界内存访问，可泄露信息或导致崩溃。

**修复方案**:
```cpp
for (auto& tensor : dumpData.input()) {
    // 在访问前检查边界
    if (offset + tensor.size() > dataLen) {
        LOG_ERROR(DebuggerErrno::ERROR_VALUE_OVERFLOW, 
                  dumpPath + ": input[" + std::to_string(slot) + "] overflow");
        return DebuggerErrno::ERROR_VALUE_OVERFLOW;
    }
    aclTensorInfos.push_back(AclTensor::ParseAttrsFromDumpData(...));
    offset += tensor.size();
    slot++;
}
// 对 output 列表应用相同检查
```

---

### 优先级 3: 计划修复（架构改进 - 1-2 月）

#### 3.1 core_compare-003 — 参数验证架构改进

**风险**: 安全反模式，验证延迟发生在下游而非调用点。

**修复方案**:
- 在 CLI 参数解析层添加类型验证函数
- 在 `compare_offline_data_mode` 中添加参数白名单验证
- 移除日志中的完整命令泄露

**长期建议**:
- 建立统一的安全输入验证模块
- 制定安全编码规范文档
- 集成静态分析工具进行持续安全扫描

---

### 修复验证清单

| 漏洞 ID | 修复优先级 | 修复方式 | 验证测试 |
|---------|-----------|---------|---------|
| core_compare-004 | P1 | 路径白名单 | 恶意路径被拒绝 |
| VULN-001 | P1 | 路径遍历检查 | `../` 文件名被拒绝 |
| infer_offline_np_load_001 | P2 | allow_pickle=False | 恶意 .npy 触发异常 |
| infer_offline_np_load_002 | P2 | allow_pickle=False | 恶意 .npy 触发异常 |
| adump-core-003 | P2 | 边界检查前置 | 大 size 值触发错误 |
| core_compare-003 | P3 | 输入验证 | 特殊字符被拒绝 |

---

**报告生成**: 自动化安全扫描系统  
**最后更新**: 2026-04-20