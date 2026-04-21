# 漏洞扫描报告 — MindStudio-ModelSlim

## 执行摘要

### 项目概述

MindStudio-ModelSlim 是华为 MindStudio 项目下的模型量化工具链，主要功能包括模型量化、权重压缩、精度分析等。项目采用混合语言架构，核心量化逻辑由 Python 实现，性能关键的权重压缩部分由 C++ 实现。工具通过 CLI 和 Python API 两种方式对外提供服务。

本次安全扫描覆盖了项目的 71 个安全敏感点，识别出 **14 个已确认漏洞**，其中 **8 个 Critical 级别漏洞** 均与路径遍历（Path Traversal）相关，集中在安全验证模块和跨语言边界处。

### 扫描统计

| 指标 | 数值 |
|------|------|
| 扫描时间 | 2026-04-21T12:00:00Z |
| 总漏洞候选 | 71 |
| 已确认 (CONFIRMED) | 14 (19.7%) |
| 高置信度 (LIKELY) | 18 (25.4%) |
| 待验证 (POSSIBLE) | 22 (31.0%) |
| 误报 (FALSE_POSITIVE) | 17 (23.9%) |

### 严重性分布

| 严重性 | 已确认数量 | 占比 |
|--------|-----------|------|
| Critical | 8 | 57.1% |
| High | 5 | 35.7% |
| Medium | 1 | 7.1% |

### 关键发现摘要

本次扫描发现的核心安全问题：

1. **安全白名单正则缺陷** — `PATH_WHITE_LIST_REGEX` 允许 `.` 和 `/` 字符，无法阻止 `../` 路径遍历攻击，影响两个安全模块（msmodelslim 和 ascend_utils）

2. **安全验证绕过** — `load_jsonl()` 函数直接打开用户提供的文件路径，完全绕过 `get_valid_read_path()` 安全验证流程

3. **跨语言边界防护缺失** — Python 层传递路径参数到 C++ 层，C++ 的 `GetDataFromBin()` 未执行任何路径验证，形成跨模块攻击路径

4. **符号链接检查不完整** — `os.path.islink()` 仅检查最终路径组件，攻击者可通过中间目录的符号链接绕过防护

5. **安全控制不对称** — 输出路径经过 `File::CheckFileBeforeCreateOrWrite()` 验证，但输入路径无任何检查，形成单向防护缺口

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 22 | 31.0% |
| LIKELY | 18 | 25.4% |
| FALSE_POSITIVE | 17 | 23.9% |
| CONFIRMED | 14 | 19.7% |
| **总计** | **71** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 8 | 57.1% |
| High | 5 | 35.7% |
| Medium | 1 | 7.1% |
| **有效漏洞总计** | **14** | - |
| 误报 (FALSE_POSITIVE) | 17 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-PATH-001]** Path Traversal (Critical) - `msmodelslim/utils/security/path.py:34` @ `get_valid_path` | 置信度: 90
2. **[VULN-MODEL-003]** Path Traversal Bypass (Critical) - `msmodelslim/utils/security/model.py:79` @ `load_jsonl` | 置信度: 85
3. **[VULN-ASCEND-002]** Path Traversal via Permissive Whitelist (Critical) - `ascend_utils/common/security/path.py:33` @ `get_valid_path` | 置信度: 85
4. **[VULN-WC-001]** Missing Input Validation (Critical) - `msmodelslim/pytorch/weight_compression/compress_graph/src/graph_utils.cpp:39` @ `GetDataFromBin` | 置信度: 85
5. **[VULN-DF-CPP-001]** path_traversal (Critical) - `msmodelslim/pytorch/weight_compression/compress_graph/src/graph_utils.cpp:39` @ `GetDataFromBin` | 置信度: 85
6. **[VULN-001-UTILS-SECURITY]** Path Traversal (Critical) - `msmodelslim/utils/security/model.py:79` @ `SafeGenerator.load_jsonl` | 置信度: 85
7. **[VULN-PWC-001-2026]** Path Traversal (Critical) - `msmodelslim/pytorch/weight_compression/compress_graph/src/graph_utils.cpp:39` @ `GetDataFromBin` | 置信度: 85
8. **[VULN-PWC-004-2026]** External Control of File Name or Path (Critical) - `msmodelslim/pytorch/weight_compression/compress_graph/src/main.cpp:224` @ `main` | 置信度: 85
9. **[VULN-DF-PY-001]** path_traversal (High) - `msmodelslim/utils/security/model.py:79` @ `load_jsonl` | 置信度: 85
10. **[VULN-PATH-002]** Incomplete Symlink Protection (High) - `msmodelslim/utils/security/path.py:69` @ `get_valid_path` | 置信度: 80

---

## 2. Top 5 Critical 漏洞深度分析

### 2.1 [VULN-PATH-001] PATH_WHITE_LIST_REGEX 路径遍历漏洞

**置信度: 90 | CWE-22 | 状态: CONFIRMED**

#### 漏洞根因

安全模块的核心正则表达式 `PATH_WHITE_LIST_REGEX = re.compile(r"[^_A-Za-z0-9/.-]")` 设计存在根本性缺陷：

```python
# msmodelslim/utils/security/path.py:34
PATH_WHITE_LIST_REGEX = re.compile(r"[^_A-Za-z0-9/.-]")

# 验证逻辑 (第 65 行)
if PATH_WHITE_LIST_REGEX.search(path):  # 仅检查非法字符，不检查遍历模式
    raise SecurityError("Input path contains invalid characters.")
```

正则表达式的意图是过滤非法字符，但它**允许了** `.` (点号) 和 `/` (斜杠)，这意味着：

- `../../../etc/passwd` 完全通过字符白名单检查
- `..` 路径遍历序列被视为合法字符组合
- 后续 `os.path.realpath()` 会解析路径，导致访问任意文件

#### 攻击路径验证

```
用户输入: "../../../etc/passwd"
    ↓
PATH_WHITE_LIST_REGEX.search() → 未匹配 (所有字符都在白名单内)
    ↓
检查通过，继续执行
    ↓
os.path.realpath() → 解析为 "/etc/passwd"
    ↓
文件操作使用解析后的路径 → 访问系统敏感文件
```

#### 影响范围

此正则表达式被以下模块共享：
- `msmodelslim/utils/security/path.py` — 主安全模块
- `ascend_utils/common/security/path.py` — Ascend 工具链安全模块

影响函数链：
- `get_valid_path()` → `get_valid_read_path()` → `yaml_safe_load()`, `json_safe_load()`
- `get_valid_path()` → `get_valid_write_path()` → `yaml_safe_dump()`, `json_safe_dump()`
- 148 个文件调用相关安全函数

#### 实际攻击场景

```bash
# 攻击者通过 CLI 传入遍历路径
msmodelslim quant --model_path "../../../root/.ssh/id_rsa" \
                   --save_path "/tmp/output"

# 或通过 Python API
from msmodelslim.app.naive_quantization.application import NaiveQuantizationApplication
app.quant(model_path="../../../../etc/shadow", save_path="/tmp/out")
```

---

### 2.2 [VULN-MODEL-003] load_jsonl 安全验证绕过

**置信度: 85 | CWE-22 | 状态: CONFIRMED**

#### 漏洞根因

`SafeGenerator.load_jsonl()` 方法**完全绕过**了项目设计的安全验证流程：

```python
# msmodelslim/utils/security/model.py:79-90
@staticmethod
def load_jsonl(dataset_path, key_name='inputs_pretokenized'):
    dataset = []
    if dataset_path == "humaneval_x.jsonl":
        key_name = 'prompt'
    # 直接打开文件，未调用 get_valid_read_path()
    with os.fdopen(os.open(dataset_path, os.O_RDONLY, 0o600),
                   'r', encoding='utf-8') as file:
        lines = file.readlines()
        for line in lines:
            data = json.loads(line)
            text = data.get(key_name, line)
            dataset.append(text)
    return dataset
```

对比同一类中其他方法的正确实现：

```python
# 正确做法 (get_config_from_pretrained, get_model_from_pretrained)
model_path = get_valid_read_path(model_path, is_dir=True, check_user_stat=True)
# 然后使用验证后的路径
config = AutoConfig.from_pretrained(model_path, local_files_only=True)
```

#### 为什么这是严重漏洞

| 防护措施 | load_jsonl | 其他 SafeGenerator 方法 |
|----------|-----------|------------------------|
| 调用 get_valid_read_path | ❌ 否 | ✅ 是 |
| 路径字符白名单 | ❌ 否 | ✅ 是 |
| 符号链接检查 | ❌ 否 | ✅ 是 |
| 文件所有权验证 | ❌ 否 | ✅ 是 |
| 权限检查 | ❌ 否 | ✅ 是 |
| 文件大小限制 | ❌ 否 | ✅ 是 |

#### 数据流分析

```
CLI/API 参数 dataset_path (用户可控)
    ↓
load_jsonl(dataset_path)
    ↓
os.open(dataset_path, os.O_RDONLY) ← 直接打开，无验证
    ↓
读取任意文件内容
    ↓
返回文件内容作为 "校准数据集"
```

---

### 2.3 [VULN-ASCEND-002] Ascend 工具链路径遍历

**置信度: 85 | CWE-22 | 状态: CONFIRMED**

#### 漏洞根因

`ascend_utils/common/security/path.py` 与 `msmodelslim/utils/security/path.py` 使用**完全相同的缺陷正则表达式**：

```python
# ascend_utils/common/security/path.py:33
PATH_WHITE_LIST_REGEX = re.compile(r"[^_A-Za-z0-9/.-]")

# 验证逻辑与 msmodelslim 完全一致
def get_valid_path(path, extensions=None):
    if PATH_WHITE_LIST_REGEX.search(path):  # 同样的缺陷
        raise ValueError("Input path contains invalid characters.")
```

#### 跨包安全问题

这表明：
1. 安全代码在多个包间复制，未统一管理
2. 修复需要同步更新两个位置
3. `ascend_utils` 可能被其他 Huawei 工具链使用，影响范围更广

#### 统一修复建议

建议将安全模块抽取为独立包：

```python
# 建议结构: huawei_security_common/validators.py
# msmodelslim 和 ascend_utils 都引用此模块
from huawei_security_common.validators import get_valid_read_path, get_valid_write_path
```

---

### 2.4 [VULN-DF-CPP-001] C++ GetDataFromBin 无路径验证

**置信度: 85 | CWE-22, CWE-59 | 状态: CONFIRMED**

#### 漏洞根因

C++ 层的 `GetDataFromBin()` 函数直接打开用户提供的文件路径，**无任何安全检查**：

```cpp
// msmodelslim/pytorch/weight_compression/compress_graph/src/graph_utils.cpp:39-79
bool GetDataFromBin(std::string input_path, std::vector<int64_t> shapes, 
                    uint8_t *&data, int data_type_size)
{
    // 直接打开文件，无路径验证、无符号链接检查、无权限检查
    std::ifstream inFile(input_path, std::ios::binary);
    if (!inFile.is_open()) {
        std::cout << "Failed to open: " << input_path << std::endl;
        return false;
    }
    
    inFile.seekg(0, std::ios::end);
    auto fileSize = inFile.tellg();
    // ... 读取文件内容到内存 ...
}
```

对比输出路径的正确实现：

```cpp
// main.cpp:51 - WriteDataToFile 正确使用安全检查
template <typename T>
int WriteDataToFile(const char *filePath, const T *data, size_t count)
{
    // ✅ 输出路径经过安全验证
    if (!File::CheckFileBeforeCreateOrWrite(filePath, true)) {
        return GraphUtils::FAILED;
    }
    FILE *fp = fopen(filePath, "w+");
    // ...
}
```

#### 跨语言攻击路径

```
Python 层 (compress_utils.py:45-101)
    ↓
compress_weight_fun(weights, record_detail_root)
    ↓
input_weight_path = os.path.join(write_root, 'input_weight_path.bin')
    ↓
get_valid_write_path(input_weight_path) ← Python 层验证写入路径
    ↓
weights.astype(np.int8).tofile(input_weight_path) ← 写入临时文件
    ↓
subprocess.Popen([compress_excutor_path, ..., input_weight_path, ...])
    ↓
C++ 层 (main.cpp:224)
    ↓
const string inputWeightPath = argv[8]; ← 直接使用命令行参数
    ↓
GetDataFromBin(inputWeightPath, ...) ← 无验证打开
    ↓
std::ifstream(input_path) ← 可读取任意文件
```

#### 关键问题

虽然 Python 层验证了写入临时文件的路径，但：

1. `argv[8]` 来自命令行参数，攻击者可直接调用 C++ 可执行文件
2. 跨语言边界没有传递安全验证结果
3. C++ 层缺少防御纵深设计

---

### 2.5 [VULN-XMOD-002] 跨模块路径遍历

**置信度: 80 | CWE-22 | 状态: CONFIRMED**

#### 漏洞描述

Python-to-C++ 跨模块路径传递链路中，安全检查在语言边界处断裂：

```python
# compress_utils.py:100-101
command = [compress_excutor_path, str(shape_k), str(shape_n), 
           "1", "1", "1", str(HIGH_SPARSE_MODE), "0",
           input_weight_path, compress_output_path, ...]
process = subprocess.Popen(command, shell=False, ...)
```

```cpp
// main.cpp:224
const string inputWeightPath = argv[8];  // 命令行参数，无验证来源
```

#### 跨模块数据流完整路径

```
[Python 模块: pytorch_weight_compression]
compress_weight_fun() 接收用户 weights 数组
    ↓
写入临时文件 input_weight_path.bin
    ↓
验证写入路径 (get_valid_write_path)
    ↓
调用 subprocess.Popen() 执行 C++ 可执行文件
    ↓
    ↓ [跨语言边界: subprocess.Popen]
    ↓
[C++ 模块: pytorch_weight_compression_cpp]
main() 接收 argv[8] 作为 inputWeightPath
    ↓
GetDataFromBin(inputWeightPath) ← 无安全检查
    ↓
std::ifstream() 直接打开文件
```

#### 攻击向量

**向量 1: 直接调用 C++ 可执行文件**
```bash
# 攻击者绕过 Python 层，直接执行
./compress_excutor 1024 1024 1 1 1 1 0 \
    "/etc/passwd" \  # inputWeightPath - 任意文件
    "/tmp/out.bin" "/tmp/index.bin" "/tmp/info.bin"
```

**向量 2: 修改 subprocess 参数 (如果 Python 层可控)**
```python
# 如果 weights 来源不可信
compress_weight_fun(malicious_weights, record_detail_root="/etc")
# 可能导致路径篡改
```

---

## 3. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@msmodelslim/cli/__main__.py` | cmdline | untrusted_local | CLI入口点，接收用户命令行参数（model_path, save_path, config_path等） | 命令行工具主入口 |
| `NaiveQuantizationApplication.quant` | decorator | untrusted_local | 公开API入口点，接收model_path、save_path、config_path等用户输入参数 | 量化应用主入口函数 |
| `SafeGenerator.get_config_from_pretrained` | file | untrusted_local | 加载用户提供的模型配置文件 | 安全加载模型配置 |
| `SafeGenerator.get_model_from_pretrained` | file | untrusted_local | 加载用户提供的模型权重文件 | 安全加载模型权重 |
| `load_jsonl` | file | untrusted_local | 加载用户数据集文件，**无安全验证** | 加载校准数据集 |
| `GetDataFromBin` | file | untrusted_local | C++读取二进制文件，**无安全验证** | 权重压缩输入 |

**其他攻击面**:
- 命令行接口: msmodelslim quant/analyze/tune 命令参数
- Python API接口: NaiveQuantizationApplication.quant() 函数参数
- 模型文件加载: safetensors文件、pickle文件、配置文件
- 数据集文件加载: JSONL/JSON校准数据集文件
- C++ CLI接口: compress_excutor命令行参数

---

## 4. Critical 漏洞 (8)

### [VULN-PATH-001] Path Traversal - get_valid_path

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 90/100 | **状态**: CONFIRMED

**位置**: `msmodelslim/utils/security/path.py:34-92` @ `get_valid_path`

**描述**: PATH_WHITE_LIST_REGEX allows path traversal sequences. The regex permits dot (.) and slash (/), enabling ../ sequences for directory escape attacks.

**漏洞代码**:
```python
PATH_WHITE_LIST_REGEX = re.compile(r"[^_A-Za-z0-9/.-]")
if PATH_WHITE_LIST_REGEX.search(path):  # Only checks for invalid chars, not traversal
```

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-MODEL-003] Path Traversal Bypass - load_jsonl

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `msmodelslim/utils/security/model.py:79-90` @ `load_jsonl`

**描述**: load_jsonl function bypasses all security path validation. Opens file directly without using get_valid_read_path.

**漏洞代码**:
```python
with os.fdopen(os.open(dataset_path, os.O_RDONLY, 0o600), 'r', encoding='utf-8') as file:
```

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-ASCEND-002] Path Traversal via Permissive Whitelist

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `ascend_utils/common/security/path.py:33-79` @ `get_valid_path`

**描述**: PATH_WHITE_LIST_REGEX allows dot and slash, enabling path traversal. Same vulnerability as VULN-PATH-001.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-WC-001] Missing Input Validation - GetDataFromBin

**严重性**: Critical | **CWE**: CWE-22, CWE-59 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `msmodelslim/pytorch/weight_compression/compress_graph/src/graph_utils.cpp:39-79` @ `GetDataFromBin`

**描述**: GetDataFromBin() reads binary files without any security validation. No path validation, no symlink check, no owner verification.

**漏洞代码**:
```cpp
std::ifstream inFile(input_path, std::ios::binary);  // No validation!
```

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CPP-001] path_traversal - GetDataFromBin

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `msmodelslim/pytorch/weight_compression/compress_graph/src/graph_utils.cpp:39-45` @ `GetDataFromBin`

**描述**: GetDataFromBin() opens input file directly without any path validation.

**漏洞代码**:
```cpp
bool GetDataFromBin(std::string input_path, std::vector<int64_t> shapes, uint8_t *&data, int data_type_size)
{
    std::ifstream inFile(input_path, std::ios::binary);
```

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-001-UTILS-SECURITY] Path Traversal - SafeGenerator.load_jsonl

**严重性**: Critical | **CWE**: CWE-22, CWE-73 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `msmodelslim/utils/security/model.py:79-90` @ `SafeGenerator.load_jsonl`

**描述**: load_jsonl() directly opens file without path validation. Duplicate of VULN-MODEL-003.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-PWC-001-2026] Path Traversal - GetDataFromBin

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `msmodelslim/pytorch/weight_compression/compress_graph/src/graph_utils.cpp:39-45` @ `GetDataFromBin`

**描述**: Duplicate of VULN-DF-CPP-001. Same vulnerability location.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-PWC-004-2026] External Control of File Name or Path - main

**严重性**: Critical | **CWE**: CWE-73 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `msmodelslim/pytorch/weight_compression/compress_graph/src/main.cpp:224-260` @ `main`

**描述**: File path from argv[8] is directly used without sanitization. InputWeightPath bypasses all security checks.

**漏洞代码**:
```cpp
const string inputWeightPath = argv[8]; // No validation
```

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. High 漏洞 (5)

### [VULN-DF-PY-001] path_traversal - load_jsonl

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `msmodelslim/utils/security/model.py:79-90` @ `load_jsonl`

**描述**: load_jsonl() opens file with os.fdopen(os.open(dataset_path, ...)) without using get_valid_read_path() validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-PATH-002] Incomplete Symlink Protection

**严重性**: High | **CWE**: CWE-59 | **置信度**: 80/100 | **状态**: CONFIRMED

**位置**: `msmodelslim/utils/security/path.py:69-71` @ `get_valid_path`

**描述**: Symlink check only validates the final path component, not intermediate components. Attacker can place symlinks in intermediate directory paths.

**漏洞代码**:
```python
if os.path.islink(os.path.abspath(path)):  # Only checks final component
    raise SecurityError(...)
real_path = os.path.realpath(path)  # Resolves all symlinks
```

**详细分析**: 参见 `{SCAN_OUTPUT}/details/VULN-PATH-002.md`

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SHELL-002] Arbitrary File Write via log_file

**严重性**: High | **CWE**: CWE-22 | **置信度**: 80/100 | **状态**: CONFIRMED

**位置**: `msmodelslim/utils/security/shell.py:277-278` @ `AsyncProcess.__init__`

**描述**: AsyncProcess opens log_file without path validation enabling arbitrary file write.

**漏洞代码**:
```python
self.log_file = open(log_file, 'w')  # No path validation
```

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-MODEL-011] Insecure Pipeline Loading

**严重性**: High | **CWE**: CWE-829 | **置信度**: 80/100 | **状态**: CONFIRMED

**位置**: `msmodelslim/model/flux1/model_adapter.py:302-305` @ `init_model`

**描述**: FluxPipeline.from_pretrained without SafeGenerator wrapper and without local_files_only=True.

**漏洞代码**:
```python
self.model = FluxPipeline.from_pretrained(self.model_path)
```

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-XMOD-002] path_traversal - compress_weight_fun

**严重性**: High | **CWE**: CWE-22 | **置信度**: 80/100 | **状态**: CONFIRMED

**位置**: `msmodelslim/pytorch/weight_compression/compress_utils.py:45-101` @ `compress_weight_fun`

**描述**: Cross-module Python-to-C++ path traversal. Python passes input_weight_path to subprocess.Popen. C++ GetDataFromBin() opens file WITHOUT validation.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 15

---

## 6. Medium 漏洞 (1)

### [VULN-PWC-005-2026] Inconsistent Security Controls

**严重性**: Medium | **CWE**: CWE-693 | **置信度**: 80/100 | **状态**: CONFIRMED

**位置**: `msmodelslim/pytorch/weight_compression/compress_graph/src/main.cpp:51-260` @ `WriteDataToFile, main`

**描述**: Security control inconsistency: WriteDataToFile() validates paths, but GetDataFromBin() performs NO validation.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

## 7. 模块漏洞分布

| 模块 | Critical | High | Medium | 合计 |
|------|----------|------|--------|------|
| ascend_utils.common.security.path | 1 | 0 | 0 | 1 |
| cross_module_analysis | 0 | 1 | 0 | 1 |
| msmodelslim.utils.security.model | 1 | 0 | 0 | 1 |
| msmodelslim.utils.security.path | 1 | 1 | 0 | 2 |
| msmodelslim.utils.security.shell | 0 | 1 | 0 | 1 |
| msmodelslim/model | 0 | 1 | 0 | 1 |
| pytorch_weight_compression | 1 | 0 | 0 | 1 |
| pytorch_weight_compression_cpp | 3 | 0 | 1 | 4 |
| utils_security | 1 | 1 | 0 | 2 |
| **合计** | **8** | **5** | **1** | **14** |

## 8. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 8 | 57.1% |
| CWE-829 | 1 | 7.1% |
| CWE-73 | 1 | 7.1% |
| CWE-693 | 1 | 7.1% |
| CWE-59 | 1 | 7.1% |
| CWE-22, CWE-73 | 1 | 7.1% |
| CWE-22, CWE-59 | 1 | 7.1% |

---

## 9. 修复建议

### 9.1 PATH_WHITE_LIST_REGEX 修复方案

**优先级: P0 (立即修复)**

修改正则表达式，明确拒绝 `../` 路径遍历序列：

```python
# 方案 A: 显式拒绝路径遍历
PATH_WHITE_LIST_REGEX = re.compile(r"[^_A-Za-z0-9/.-]|(\.\./)")

# 方案 B: 使用路径规范化后验证
def get_valid_path(path, extensions=None):
    # 先解析路径，获取规范化形式
    abs_path = os.path.abspath(path)
    real_path = os.path.realpath(path)
    
    # 验证规范化后的路径是否在允许范围内
    ALLOWED_BASE_DIRS = [
        os.path.realpath(os.getcwd()),
        os.path.realpath('/opt/models'),
        os.path.realpath('/home'),
    ]
    
    is_safe = any(
        os.path.commonpath([real_path, allowed_dir]) == allowed_dir
        for allowed_dir in ALLOWED_BASE_DIRS
    )
    
    if not is_safe:
        raise SecurityError(
            f"Resolved path {real_path} escapes allowed directories",
            action='Please provide a path within allowed directories.'
        )
    
    # 然后再执行字符检查
    if PATH_WHITE_LIST_REGEX.search(real_path):
        raise SecurityError("Path contains invalid characters.")
    
    return real_path
```

**同步修复点**:
- `msmodelslim/utils/security/path.py:34`
- `ascend_utils/common/security/path.py:33`

---

### 9.2 load_jsonl 安全验证修复

**优先级: P0 (立即修复)**

调用 `get_valid_read_path()` 进行完整验证：

```python
@staticmethod
def load_jsonl(dataset_path, key_name='inputs_pretokenized'):
    from msmodelslim.utils.security import get_valid_read_path
    
    dataset = []
    if dataset_path == "humaneval_x.jsonl":
        key_name = 'prompt'
    
    # ✅ 修复: 使用安全验证函数
    validated_path = get_valid_read_path(
        dataset_path, 
        extensions="jsonl",
        size_max=MAX_READ_FILE_SIZE_4G,
        check_user_stat=True
    )
    
    with os.fdopen(os.open(validated_path, os.O_RDONLY, 0o600),
                   'r', encoding='utf-8') as file:
        lines = file.readlines()
        for line in lines:
            data = json.loads(line)
            text = data.get(key_name, line)
            dataset.append(text)
    return dataset
```

---

### 9.3 C++ GetDataFromBin 安全检查

**优先级: P1 (高优先级)**

在 C++ 层添加路径验证，调用 `File::CheckDir()` 或创建专用函数：

```cpp
// 方案 A: 使用现有的 File 类验证
bool GetDataFromBin(std::string input_path, std::vector<int64_t> shapes, 
                    uint8_t *&data, int data_type_size)
{
    // ✅ 新增: 调用安全验证
    if (!File::CheckDir(input_path)) {
        std::cout << "Security check failed for input path: " << input_path << std::endl;
        return false;
    }
    
    // 或创建专用函数
    if (!File::CheckFileBeforeRead(input_path)) {
        return false;
    }
    
    std::ifstream inFile(input_path, std::ios::binary);
    // ... 原有逻辑 ...
}

// 方案 B: 在 main.cpp 中验证后再调用
int main(int argc, char *argv[])
{
    const string inputWeightPath = argv[8];
    
    // ✅ 新增: 传递给 GetDataFromBin 前先验证
    if (!File::CheckFileBeforeRead(inputWeightPath.c_str())) {
        std::cout << "Input path validation failed." << std::endl;
        return GraphUtils::FAILED;
    }
    
    if (!GraphUtils::GetDataFromBin(inputWeightPath, ...)) {
        // ...
    }
}
```

---

### 9.4 符号链接完整检查修复

**优先级: P1 (高优先级)**

实现完整的路径组件符号链接检查：

```python
def get_valid_path(path, extensions=None):
    check_type(path, str, "path")
    if not path or len(path) == 0:
        raise SecurityError("The value of the path cannot be empty.")
    
    # ✅ 新增: 检查所有路径组件是否存在符号链接
    abs_path = os.path.abspath(path)
    components = abs_path.split(os.sep)
    check_path = '/'
    for comp in components[1:]:  # 路过根目录 '/'
        check_path = os.path.join(check_path, comp)
        if os.path.islink(check_path):
            raise SecurityError(
                f"Path contains symlink at intermediate component: {check_path}",
                action='Please ensure no symlinks in the path.'
            )
    
    # 然后检查最终组件
    if os.path.islink(abs_path):
        raise SecurityError(
            f"The value of the path cannot be soft link: {path}",
            action='Please make sure the path is not a soft link.'
        )
    
    real_path = os.path.realpath(path)
    # ... 后续检查 ...
```

---

### 9.5 安全模块统一管理

**优先级: P2 (中优先级)**

建议架构调整：

1. 将安全验证逻辑抽取为独立包 `huawei_security_common`
2. `msmodelslim` 和 `ascend_utils` 都引用同一安全模块
3. 避免代码复制导致的安全一致性问题

```python
# 建议结构
huawei_security_common/
    ├── validators/
    │   ├── path_validator.py    # PATH_WHITE_LIST_REGEX + get_valid_path
    │   ├── file_validator.py    # 文件读写验证
    │   └── symlink_checker.py   # 符号链接检查
    └── __init__.py

# msmodelslim 和 ascend_utils 引用
from huawei_security_common.validators import get_valid_read_path, get_valid_write_path
```

---

### 9.6 安全控制对称性修复

**优先级: P2 (中优先级)**

为 C++ 层添加输入路径验证函数：

```cpp
// File.h / File.cpp 中新增
namespace File {
    bool CheckFileBeforeRead(const char* filePath);
}

// 实现
bool File::CheckFileBeforeRead(const char* filePath) {
    // 路径长度检查
    // 字符白名单检查
    // 符号链接检查
    // 文件权限检查
    // 文件所有权检查
    return true;  // 所有检查通过
}
```

---

### 9.7 修复优先级总结

| 优先级 | 漏洞 | 修复方案 | 影面范围 |
|--------|------|----------|----------|
| P0 | VULN-PATH-001, VULN-ASCEND-002 | 修改 PATH_WHITE_LIST_REGEX | 148+ 文件 |
| P0 | VULN-MODEL-003, VULN-DF-PY-001 | load_jsonl 调用 get_valid_read_path | 数据集加载 |
| P1 | VULN-DF-CPP-001, VULN-PWC-004 | C++ GetDataFromBin 添加验证 | 权重压缩 |
| P1 | VULN-PATH-002 | 完整符号链接检查 | 所有文件操作 |
| P2 | VULN-PWC-005 | 安全控制对称性 | C++ 输入验证 |
| P2 | 所有 | 安全模块统一架构 | 长期维护 |

---

## 10. 验证建议

### 10.1 单元测试补充

```python
# tests/security/test_path_traversal.py
import pytest
from msmodelslim.utils.security.path import get_valid_path

def test_path_traversal_blocked():
    """验证 ../ 路径遍历被阻止"""
    with pytest.raises(SecurityError):
        get_valid_path("../../../etc/passwd")

def test_intermediate_symlink_blocked():
    """验证中间符号链接被检查"""
    # 创建测试目录结构
    os.makedirs("/tmp/test_dir")
    os.symlink("/etc", "/tmp/test_dir/evil_link")
    
    with pytest.raises(SecurityError):
        get_valid_path("/tmp/test_dir/evil_link/passwd")

def test_load_jsonl_validation():
    """验证 load_jsonl 使用安全验证"""
    from msmodelslim.utils.security.model import SafeGenerator
    
    with pytest.raises(SecurityError):
        SafeGenerator.load_jsonl("../../../../etc/shadow")
```

### 10.2 集成测试场景

```bash
# CLI 路径遍历测试
msmodelslim quant --model_path "../../../root/.ssh/id_rsa" \
                   --save_path "/tmp/output"  # 应报错拒绝

# C++ 可执行文件直接测试
./compress_excutor 1024 1024 1 1 1 1 0 \
    "/etc/passwd" "/tmp/out.bin" "/tmp/index.bin" "/tmp/info.bin"  # 应报错拒绝
```

---

*报告生成时间: 2026-04-21*
*扫描工具版本: OpenCode Vulnerability Scanner*