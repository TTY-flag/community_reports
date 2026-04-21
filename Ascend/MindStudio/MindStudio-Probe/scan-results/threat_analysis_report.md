# MindStudio-Probe 威胁分析报告

> 扫描时间: 2026-04-20
> 项目路径: /home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Probe
> 项目类型: CLI工具 + 库 (AI模型精度调试工具)

## 1. 项目概述

MindStudio-Probe (msprobe) 是华为昇腾AI全场景精度调试工具，专为模型开发的精度调试环节设计。该工具支持PyTorch和MindSpore框架，提供数据采集、精度比对、溢出检测等功能。

### 项目统计

| 指标 | 数量 |
|------|------|
| Python文件 | 443 |
| C/C++文件 | 59 |
| 总代码行数 | 91,528 |
| 模块数量 | 10 |

### 语言分布

- Python: 79,510 行 (主要业务逻辑)
- C/C++: 12,018 行 (底层性能优化和Python扩展)

## 2. 信任边界分析

### 2.1 信任边界定义

| 边界 | 可信侧 | 不可信侧 | 风险等级 | 说明 |
|------|--------|----------|----------|------|
| **文件系统接口** | 应用逻辑 | 用户提供的文件 | High | 工具处理用户提供的模型文件、dump数据、配置文件 |
| **命令行接口** | 应用逻辑 | 用户命令参数 | Medium | CLI参数包含路径和配置选项 |
| **Python/C++桥接** | Python应用 | C++扩展模块 | Low | CPython API调用 |

### 2.2 信任边界风险评估

本工具作为开发阶段调试工具，主要信任模型为：
- **开发者可信**: 工具用户为模型开发者，具有一定技术背景
- **文件可信假设**: 工具假设用户提供的文件来自可信来源
- **无网络暴露**: 工具不涉及网络通信，仅处理本地文件

**关键安全声明** (来自项目README):

> MindStudio Probe is a development-phase tool. It does not restrict the ownership or permissions of files it processes. Users are responsible for assigning appropriate ownership and permissions based on their usage scenarios.

## 3. 入口点分析

### 3.1 CLI入口点

| 入口点 | 文件 | 函数 | 信任等级 | 处理的数据类型 |
|--------|------|------|----------|----------------|
| CLI主入口 | msprobe.py:36 | main | untrusted_local | 命令行参数、子命令选择 |
| compare命令 | compare_cli.py:68 | compare_cli | untrusted_local | 文件路径、比对配置 |
| parse命令 | parse_cli.py:35 | parse_cli | untrusted_local | dump文件路径 |
| acc_check命令 | acc_check_cli.py:54 | acc_check_cli | untrusted_local | API info JSON路径 |
| offline_dump命令 | main.py:106 | offline_dump_cli | untrusted_local | ONNX/OM模型路径、输入数据路径 |
| config_check命令 | config_check_cli.py | config_check_cli | untrusted_local | 配置文件路径 |

### 3.2 文件解析入口点

| 入口点 | 文件 | 函数 | 处理格式 | 风险等级 |
|--------|------|------|----------|----------|
| Tensor二进制解析 | tensor_bin_parser.py:39 | parse | .bin | High |
| ONNX模型加载 | onnx_dump_data.py:166 | _load_onnx | .onnx | High |
| OM模型解析 | om_parser.py:95 | _load_json_file | .json | High |
| PyTorch文件加载 | utils.py:80 | safe_torch_load | .pt | Critical |
| NumPy文件加载 | file_utils.py:476 | load_npy | .npy | Medium |
| YAML配置加载 | file_utils.py:464 | load_yaml | .yaml | Medium |
| JSON配置加载 | file_utils.py:486 | load_json | .json | Medium |
| C++配置加载 | DebuggerConfig.cpp:464 | LoadConfig | .json | High |

## 4. STRIDE威胁建模

### 4.1 Spoofing (身份伪造)

| 威胁 | 风险 | 现有缓解措施 | 建议 |
|------|------|--------------|------|
| 文件所有权伪装 | Medium | 检查文件owner是否为当前用户 | 已有较好的检查机制 |

**现有防护措施**:
- Python: `FileStat.check_owner_or_root()` 检查文件所有权
- C++: `FileUtils::IsFileOwner()` 检查文件所有者
- Python: `os.stat().st_uid` 与 `os.geteuid()` 比较

### 4.2 Tampering (数据篡改)

| 威胁 | 风险 | 现有缓解措施 | 建议 |
|------|------|--------------|------|
| 配置文件篡改 | High | 文件权限检查、软链接禁止 | 已有防护 |
| 模型文件篡改 | High | 文件完整性检查较弱 | 建议增加哈希校验 |
| 输入数据篡改 | High | 文件权限检查 | 已有基本防护 |

**现有防护措施**:
- 禁止软链接处理 (除特定白名单)
- 文件权限限制: 读取文件权限不超过0o755
- 组写权限检查: `READ_FILE_NOT_PERMITTED_STAT = S_IWGRP | S_IWOTH`

### 4.3 Repudiation (否认)

| 威害 | 风险 | 现有缓解措施 | 建议 |
|------|------|--------------|------|
| 操作日志缺失 | Low | 有基本日志功能 | 日志记录操作详情 |

### 4.4 Information Disclosure (信息泄露)

| 威胁 | 风险 | 现有缓解措施 | 建议 |
|------|------|--------------|------|
| 敏感数据文件泄露 | Medium | 输出文件权限控制 | 已有较好的权限设置 |
| 日志信息泄露 | Low | 日志不包含敏感信息 | 保持现状 |

**现有防护措施**:
- 输出文件权限: `DATA_FILE_AUTHORITY = 0o640`
- 输出目录权限: `DATA_DIR_AUTHORITY = 0o750`
- CSV注入防护: `CSV_BLACK_LIST` 正则检查

### 4.5 Denial of Service (拒绝服务)

| 威胁 | 风险 | 现有缓解措施 | 建议 |
|------|------|--------------|------|
| 大文件处理OOM | High | 文件大小限制 | 有多个大小限制检查 |
| 无限递归 | Medium | 递归深度限制 | 有depth_decorator限制 |
| ZIP炸弹 | High | ZIP文件检查 | 有zip检查机制 |

**现有防护措施**:
- 文件大小限制:
  - JSON: MAX_JSON_SIZE (10MB)
  - YAML: MAX_YAML_SIZE (10MB)
  - NPY: MAX_NUMPY_SIZE
  - PT: MAX_PT_SIZE
  - ZIP: MAX_ZIP_SIZE
- 递归深度限制: `max_depth=16`
- ZIP炸弹检测: `check_zip_file()` 检查文件数量和大小

### 4.6 Elevation of Privilege (权限提升)

| 威害 | 风险 | 现有缓解措施 | 建议 |
|------|------|--------------|------|
| Pickle反序列化RCE | Critical | weights_only参数，但有绕过风险 | **需重点关注** |
| Root用户运行风险 | Medium | root权限警告 | 已有警告机制 |
| 动态库注入 | Low | dlopen调用检查 | 无明显风险点 |

**关键风险点 - Pickle反序列化**:

工具使用 `torch.load()` 加载PyTorch模型文件，该函数底层使用pickle反序列化。

现有缓解措施分析:
1. `safe_torch_load()` 函数尝试使用 `weights_only=True`
2. 当weights_only加载失败时，会提示用户确认风险后使用 `weights_only=False`
3. 存在用户交互绕过风险

代码路径:
```
python/msprobe/infer/utils/util.py:80-99
python/msprobe/pytorch/common/utils.py:340-342
```

## 5. 关键攻击面分析

### 5.1 高风险攻击面

#### 5.1.1 Pickle反序列化漏洞 (CWE-502)

**风险等级**: Critical

**影响范围**:
- `python/msprobe/infer/utils/util.py:safe_torch_load()`
- `python/msprobe/pytorch/common/utils.py` 中的 `torch.load()` 调用

**漏洞机制**:
PyTorch的 `.pt` 文件使用pickle序列化，加载恶意构造的 `.pt` 文件可能导致任意代码执行。

**现有缓解**:
```python
# infer/utils/util.py:80-99
def safe_torch_load(path, **kwargs):
    kwargs['weights_only'] = True
    try:
        tensor = torch.load(path, **kwargs)
    except pickle.UnpicklingError:
        # 用户确认后绕过
        kwargs['weights_only'] = False
        tensor = torch.load(path, **kwargs)
```

**绕过路径**:
1. 构造恶意 `.pt` 文件
2. 文件故意触发 `pickle.UnpicklingError`
3. 用户在交互中输入 'y'
4. `weights_only=False` 导致RCE

**建议**:
- 强制使用 `weights_only=True`，不允许绕过
- 或在绕过前进行更严格的文件来源验证

#### 5.1.2 文件路径操作 (CWE-22)

**风险等级**: High

**影响范围**:
- 所有文件路径参数处理
- C++和Python的路径处理函数

**现有缓解措施 (较为完善)**:
1. 软链接禁止: `check_link()`, `IsFileSymbolLink()`
2. 路径长度限制: 最大4096字符
3. 路径字符白名单: `FILE_VALID_PATTERN = r"[^_:\\A-Za-z0-9/.-]"`
4. 路径深度限制: `PATH_DEPTH_MAX`
5. 路径规范化: `os.path.realpath()`

#### 5.1.3 ONNX模型解析 (CWE-502)

**风险等级**: High

**影响范围**:
- `python/msprobe/infer/offline/compare/msquickcmp/onnx_model/onnx_dump_data.py`

**漏洞机制**:
ONNX模型使用protobuf序列化，恶意构造的模型可能:
- 触发protobuf解析漏洞
- 模型结构异常导致内存问题
- 通过自定义算子执行危险操作

**现有缓解**:
- 文件大小限制
- 文件所有权检查

### 5.2 中风险攻击面

#### 5.2.1 JSON配置解析 (CWE-20)

**风险等级**: Medium

**影响范围**:
- Python JSON加载 (`load_json()`)
- C++ JSON加载 (`DebuggerConfig::Parse()`)

**现有缓解**:
- 文件大小限制
- JSON解析异常捕获

#### 5.2.2 NumPy文件解析 (CWE-20)

**风险等级**: Medium

**影响范围**:
- `python/msprobe/core/common/file_utils.py:load_npy()`

**现有缓解**:
- `allow_pickle=False` 设置

### 5.3 低风险攻击面

#### 5.3.1 YAML配置解析

**风险等级**: Low

**现有缓解**:
- 使用 `yaml.safe_load()` (而非 `yaml.load()`)

#### 5.3.2 CSV注入

**风险等级**: Low

**现有缓解**:
- `CSV_BLACK_LIST` 正则检查
- `sanitize_csv_value()` 函数

## 6. 数据流分析

### 6.1 关键数据流路径

| 数据流 | Source | Sink | 风险等级 |
|--------|--------|------|----------|
| CLI参数→文件操作 | sys.argv | 文件系统API | Medium |
| PT文件→pickle反序列化 | .pt文件 | pickle.loads | Critical |
| ONNX文件→模型执行 | .onnx文件 | onnxruntime | High |
| JSON配置→程序逻辑 | .json文件 | 配置对象 | Medium |

### 6.2 污点传播路径

```
用户输入 (CLI参数/文件内容)
    → 参数解析 (argparse)
    → 路径验证 (FileChecker/FileStat)
    → 文件打开 (FileOpen/ms_open)
    → 数据解析 (torch.load/onnx.load/numpy.load/json.load)
    → 业务逻辑处理
    → 结果输出 (save_*函数)
```

## 7. 安全机制评估

### 7.1 已实现的安全机制

| 机制 | 实现位置 | 有效性 |
|------|----------|--------|
| 软链接禁止 | Python/C++ | 有效 |
| 文件大小限制 | Python/C++ | 有效 |
| 文件权限检查 | Python/C++ | 有效 |
| 文件所有权检查 | Python/C++ | 有效 |
| 路径规范化 | Python/C++ | 有效 |
| 路径字符白名单 | Python/C++ | 有效 |
| yaml.safe_load | Python | 有效 |
| np.load(allow_pickle=False) | Python | 有效 |
| weights_only=torch.load | Python | 部分(可绕过) |
| CSV注入防护 | Python | 有效 |

### 7.2 需要加强的安全机制

| 机制 | 当前状态 | 建议改进 |
|------|----------|----------|
| Pickle反序列化防护 | 可被用户交互绕过 | 强制weights_only或禁止绕过 |
| 模型文件完整性校验 | 无 | 增加哈希校验选项 |
| 配置文件签名 | 无 | 可考虑签名机制 |

## 8. 总结与建议

### 8.1 关键发现

1. **Pickle反序列化风险**: 这是本工具最大的安全隐患，虽然采取了 `weights_only=True` 的保护措施，但存在用户交互绕过路径。

2. **文件安全机制完善**: 工具在文件路径处理、权限检查、软链接禁止等方面有较为完善的实现。

3. **无网络暴露**: 工具不涉及网络通信，降低了攻击面。

4. **安全声明明确**: 工具明确声明为开发阶段工具，用户需自行负责文件安全。

### 8.2 优先级建议

| 优先级 | 建议项 |
|--------|--------|
| P1 | 评估pickle反序列化风险，考虑完全禁止weights_only绕过 |
| P2 | 对关键配置文件增加完整性校验 |
| P3 | 增强日志记录，记录操作来源 |
| P4 | 文档中明确说明各文件格式的安全风险 |

### 8.3 风险等级分布

| 风险等级 | 入口点数量 | 主要威胁类型 |
|----------|------------|--------------|
| Critical | 2 | Pickle反序列化RCE |
| High | 8 | 文件篡改、模型解析 |
| Medium | 5 | 配置篡改、信息泄露 |
| Low | 3 | 否认、日志泄露 |

---

**报告生成工具**: OpenCode Vulnerability Scanner
**分析版本**: 1.0.0