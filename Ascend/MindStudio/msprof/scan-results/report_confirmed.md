# 漏洞扫描报告 — 已确认漏洞

**项目**: msprof (MindStudio Profiling Tool)
**扫描时间**: 2026-04-20T06:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次漏洞扫描对 **msprof** 项目进行了全面的安全审计。msprof 是一个用于分析 AI 任务性能数据的命令行工具，包含 C/C++ 和 Python 混合代码库。扫描覆盖了 1155 个源文件，共约 125,906 行代码。

### 关键发现

扫描发现 **1 个已确认漏洞 (CONFIRMED)**，属于高危 Buffer Overread 类型。该漏洞存在于二进制数据解析模块中，攻击者可通过构造恶意的性能数据文件触发缓冲区越界读取。

### 漏洞影响评估

| 维度 | 评估结果 |
|------|----------|
| **攻击可达性** | 高 — 漏洞位于 CLI 工具的数据解析路径，用户通过命令行参数指定输入文件，路径可达 |
| **攻击可控性** | 高 — `tensor_num` 值直接从解析的二进制数据中获取，攻击者完全可控 |
| **安全影响** | 高 — 缓冲区越界读取可能导致敏感信息泄露或程序崩溃 |
| **修复优先级** | **P1 (立即修复)** |

### 建议优先级

1. **立即修复**: 已确认的 Buffer Overread 漏洞 (msparser-runtime_op_info_bean-002)
2. **计划修复**: 9 个 LIKELY 状态漏洞，主要涉及二进制解析和 TOCTOU 问题
3. **评估后修复**: 21 个 POSSIBLE 状态漏洞，多为路径遍历风险和输入验证不足

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
| **有效漏洞总计** | **1** | - |
| HIGH | 1 | 100% |
| 误报 (FALSE_POSITIVE) | 18 | - |

---

## 2. 已确认漏洞详情

### 漏洞 #1: Buffer Overread in Binary Data Parser

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | msparser-runtime_op_info_bean-002 |
| **类型** | Buffer Overread (CWE-130) |
| **严重性** | HIGH |
| **置信度** | 85/100 |
| **文件路径** | `analysis/msparser/add_info/runtime_op_info_bean.py` |
| **行号** | 154-156 |
| **函数名** | `decode` |

#### 漏洞描述

`RuntimeTensorBean.decode()` 方法中存在缓冲区越界读取漏洞。`tensor_num` 值来自解析的二进制数据 (`data[15]`)，被直接用于 `struct.unpack_from()` 的格式字符串构造：

```python
# analysis/msparser/add_info/runtime_op_info_bean.py:154-156
def decode(self: any, binary_data: bytes, additional_fmt: str, tensor_num: int) -> any:
    parse_data = struct.unpack_from(StructFmt.BYTE_ORDER_CHAR + tensor_num * additional_fmt, binary_data)
    self._deal_with_tensor_data(parse_data[self.TENSOR_PER_LEN:], tensor_num, self.TENSOR_LEN)
    return self
```

攻击者可构造恶意的二进制性能数据文件，使 `tensor_num` 值过大，导致 `tensor_num * additional_fmt` 超出 `binary_data` 的实际长度，触发缓冲区越界读取。

#### 数据流路径

```
用户提供的二进制文件
    ↓
FileOpen() 读取文件内容
    ↓
struct.unpack() 解析头部数据
    ↓
data[15] = tensor_num (攻击者可控)
    ↓
RuntimeTensorBean.decode(binary_data, fmt, tensor_num)
    ↓
struct.unpack_from(tensor_num * fmt, binary_data) [SINK]
    ↓
Buffer Overread (读取超出 binary_data 边界)
```

#### 源代码上下文

漏洞位于 `RuntimeOpInfo256Bean` 的父类 `RuntimeTensorBean` 中。完整调用链如下：

1. `RuntimeOpInfo256Bean.__init__()` 调用父类初始化
2. 从 `args[0]` (struct.unpack 结果) 获取 `tensor_num = data[15]`
3. 调用 `_deal_with_tensor_data()` 处理 tensor 数据
4. 在 `decode()` 方法中，`tensor_num` 被用于构造 `struct.unpack_from` 的格式

**关键问题**: `tensor_num` 来自外部二进制数据，未经过任何范围校验。攻击者只需修改二进制文件中对应偏移的字节，即可控制 `tensor_num` 值。

#### 攻击场景

**场景 1: 信息泄露**
攻击者构造一个性能数据文件，设置 `tensor_num` 为极大值。当 msprof 解析该文件时，`struct.unpack_from` 会读取超出 `binary_data` 边界的内存区域，可能泄露敏感信息。

**场景 2: 拒绝服务**
设置 `tensor_num` 为不合理的大值，导致程序抛出异常崩溃，影响工具可用性。

#### 修复建议

**优先级**: P1 (立即修复)

**修复方案 1: 输入验证**
```python
def decode(self: any, binary_data: bytes, additional_fmt: str, tensor_num: int) -> any:
    # 计算期望的数据长度
    expected_size = struct.calcsize(additional_fmt) * tensor_num
    actual_size = len(binary_data)
    
    # 验证 tensor_num 不超出数据边界
    if expected_size > actual_size:
        raise ValueError(f"tensor_num {tensor_num} exceeds binary_data length")
    
    # 验证 tensor_num 在合理范围内
    MAX_TENSOR_NUM = 1000  # 根据实际业务需求设定上限
    if tensor_num < 0 or tensor_num > MAX_TENSOR_NUM:
        raise ValueError(f"Invalid tensor_num: {tensor_num}")
    
    parse_data = struct.unpack_from(StructFmt.BYTE_ORDER_CHAR + tensor_num * additional_fmt, binary_data)
    ...
```

**修复方案 2: 异常处理**
```python
def decode(self: any, binary_data: bytes, additional_fmt: str, tensor_num: int) -> any:
    try:
        fmt = StructFmt.BYTE_ORDER_CHAR + tensor_num * additional_fmt
        parse_data = struct.unpack_from(fmt, binary_data)
    except struct.error as e:
        logging.error(f"Buffer overread prevented: {e}")
        return None  # 或抛出更明确的异常
    ...
```

**测试建议**
1. 创建单元测试验证边界条件
2. 使用模糊测试生成各种畸形的二进制文件
3. 验证修复后的代码能正确处理异常数据

---

## 3. 攻击面分析

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
- **二进制数据文件解析 (profiling binary files) — 主要攻击路径**
- SQLite 数据库操作 (读写数据库文件)
- Shell 脚本执行 (安装/构建脚本)
- CSV/JSON 文件导出

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| msparser | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **1** | **0** | **0** | **1** |

**模块分析**:
- **msparser 模块**: 负责解析各种二进制性能数据格式，是本次扫描中发现漏洞最多的模块。该模块直接处理用户提供的二进制文件，缺乏输入验证是其主要安全问题。

---

## 5. CWE 分布

| CWE | 数量 | 占比 | 说明 |
|-----|------|------|------|
| CWE-130 | 1 | 100.0% | 缓冲区越界读取 — 验证数组/缓冲区索引不超出边界 |

---

## 6. 修复建议汇总

### 立即修复 (P1)

| 漏洞 ID | 问题 | 修复建议 |
|---------|------|----------|
| msparser-runtime_op_info_bean-002 | Buffer Overread | 在 `struct.unpack_from` 前验证 `tensor_num` 范围 |

### 系统性修复建议

#### 1. 二进制数据解析模块 (msparser)

**问题**: 多个解析器直接使用从二进制数据中提取的值进行后续操作，缺乏边界检查。

**建议修复策略**:
- 建立统一的二进制解析安全框架
- 所有从二进制数据中提取的数值在使用前必须进行范围验证
- 为 `struct.unpack`/`struct.unpack_from` 添加数据长度校验

```python
# 建议的安全解析基类
class SafeBinaryParser:
    @staticmethod
    def safe_unpack(fmt: str, data: bytes) -> tuple:
        expected = struct.calcsize(fmt)
        if len(data) < expected:
            raise ValueError(f"Data too short: {len(data)} < {expected}")
        return struct.unpack(fmt, data)
    
    @staticmethod  
    def safe_unpack_from(fmt: str, data: bytes, offset: int = 0) -> tuple:
        expected = struct.calcsize(fmt)
        if offset + expected > len(data):
            raise ValueError(f"Buffer overflow: offset {offset} + size {expected} > len {len(data)}")
        return struct.unpack_from(fmt, data, offset)
```

#### 2. 文件操作安全

**问题**: 存在多个 TOCTOU 和路径遍历风险点。

**建议**:
- 使用 `os.open()` 配合 `O_NOFOLLOW` 标志防止符号链接攻击
- 在验证和操作之间使用原子操作
- 使用绝对路径规范化并验证路径前缀

#### 3. 测试覆盖

**建议**:
- 为所有二进制解析器添加边界测试
- 使用模糊测试验证异常输入处理
- 添加安全回归测试用例

---

## 7. 附录

### A. 扫描配置

- 项目类型: CLI Tool (C/C++ + Python 混合)
- LSP 可用性: 否
- 扫描文件总数: 1155
- 代码行总数: 125,906

### B. 相关 CWE 参考

- **CWE-130**: Improper Handling of Length Parameter or Inconsistency
- **CWE-129**: Improper Validation of Array Index
- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory
- **CWE-36**: Time-of-check Time-of-use (TOCTOU) Race Condition

---

*报告生成时间: 2026-04-20*
*扫描工具: OpenCode Multi-Agent Vulnerability Scanner*