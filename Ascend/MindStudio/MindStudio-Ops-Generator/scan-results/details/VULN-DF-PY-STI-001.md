# VULN-DF-PY-STI-001：case_generator动态导入用户指定Python文件致任意代码执行

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-PY-STI-001 |
| **漏洞类型** | Arbitrary Code Execution (动态导入代码注入) |
| **CWE** | CWE-94: Improper Control of Generation of Code ('Code Injection') |
| **严重性** | High |
| **置信度** | 85% CONFIRMED |
| **影响文件** | `tools/msopst/st/interface/case_generator.py` |
| **漏洞位置** | 第 96 行, `_get_ms_ops_info` 函数; 第 356-365 行, `_parse_py_to_json` 函数 |
| **所属模块** | msopst/st/interface |

### 漏洞描述

在 MindStudio Ops Generator 工具的 `case_generator.py` 中，当用户通过 CLI `-i` 参数指定 `.py` 类型的算子信息文件时，工具会通过 `importlib.import_module` 动态导入该 Python 文件。由于导入路径完全由用户控制，且现有的路径验证机制不检查文件内容安全性，攻击者可以通过指定包含恶意代码的 Python 文件路径，实现任意代码执行。

## 攻击向量分析

### 数据流路径

```
SOURCE: CLI 参数 -i (用户可控)
  └── args.input_file → self.input_file_path
      ├── os.path.realpath(self.input_file_path) [路径规范化]
      ├── check_path_valid(self.input_file_path) [仅验证路径存在性和权限]
      ├── sys.path.append(os.path.dirname(expect_func_file)) [添加用户目录到 sys.path]
      │   └── 添加恶意文件目录到 Python 导入路径
      └── importlib.import_module(module_name) [SINK - 任意模块导入]
          └── 导入并执行恶意 Python 模块的全部代码
```

### 关键代码片段

```python
# case_generator.py:356-365 (_parse_py_to_json 函数)
def _parse_py_to_json(self):
    expect_func_file = self.input_file_path  # 来自 CLI -i 参数
    sys.path.append(os.path.dirname(expect_func_file))  # 添加用户目录到 sys.path
    py_file = os.path.basename(expect_func_file)
    module_name, _ = os.path.splitext(py_file)
    utils.print_info_log("Start to import {} in {}.".format(
        module_name, py_file))
    class_name = "{}op_info".format(module_name.rstrip("impl"))
    mindspore_ops_info = self._get_ms_ops_info(module_name, class_name)  # 导入模块

# case_generator.py:95-97 (_get_ms_ops_info 函数)
@staticmethod
def _get_ms_ops_info(module_name, class_name):
    params = importlib.import_module(module_name)  # 动态导入任意模块
    return getattr(params, class_name)
```

### 现有缓解措施及其局限性

| 缓解措施 | 实现位置 | 验证内容 | 局限性 |
|----------|----------|----------|--------|
| `os.path.realpath` | case_generator.py:46 | 路径规范化，解析软链接 | **不防止路径遍历后的恶意文件** |
| `check_path_valid` | utils.py:310-359 | 路径存在性、可读权限、文件类型 | **不验证文件内容安全性** |
| `check_file_valid` | utils.py:398-410 | 文件大小、路径长度、字符格式 | **不验证文件内容安全性** |
| `check_path_pattern_valid` | utils.py:372-374 | 路径字符合法性 | **允许任意合法路径格式** |
| 文件扩展名检查 | case_generator.py:239-244 | 只允许 `.ini`、`.py`、`.cpp` | **恶意文件可以是合法的 .py 文件** |

**关键结论**: 所有验证措施仅确保：
1. 路径格式符合规范
2. 文件存在且可读
3. 文件扩展名为 `.py`、`.ini` 或 `.cpp`

**完全不验证文件内容的安全性**。任何格式合法、可读的 Python 文件都会被导入执行。

### 攻击入口分析

**入口点类型**: CLI 参数输入 (`-i` 参数)

**信任边界**: 
- **可信侧**: MindStudio Ops Generator 工具执行环境
- **不可信侧**: 用户通过 CLI 参数指定的 Python 文件

**CLI 调用链**:
```
msopst.py (CLI 入口)
  └── MsopstArgParser.parse_args() → args.input_file
      └── CaseGenerator(args)
          └── __init__: self.input_file_path = os.path.realpath(args.input_file)
          └── check_argument_valid(): utils.check_path_valid(self.input_file_path)
          └── parse(): 
              └── if .py file: _parse_py_to_json()
                  └── importlib.import_module(module_name)
```

### 与 VULN-DF-CODE-001 的区别

| 维度 | VULN-DF-CODE-001 | VULN-DF-PY-STI-001 |
|------|------------------|---------------------|
| **数据源** | JSON 测试用例文件中的字段 | CLI `-i` 参数直接指定 |
| **触发方式** | DataGenerator 处理测试用例 | CaseGenerator 解析算子信息 |
| **攻击复杂度** | Medium (需构造 JSON) | Low (直接指定文件) |
| **用户交互** | 处理他人提供的测试用例时风险更高 | 直接执行自己指定的文件 |

**重要差异**: VULN-DF-PY-STI-001 的攻击向量更直接——用户直接通过 CLI 参数指定要导入的文件。这在以下场景中风险更高：

1. **共享环境**: 多用户共享服务器，A 用户执行 B 用户提供的文件
2. **自动化流程**: CI/CD 系统自动处理提交的算子文件
3. **文件共享**: 从不信任来源下载的算子信息文件

## PoC 概念性描述

### 攻击场景

**前提条件**:
1. 攻击者有能力在目标系统上创建或放置 Python 文件
2. 攻击者能触发 `msopst` 工具执行（或诱导他人执行）

**攻击步骤**:

1. **创建恶意 Python 算子信息文件** (`malicious_op_impl.py`):
   - 文件名符合算子信息文件的命名约定（如 `xxximpl.py`）
   - 在模块顶层放置恶意代码（importlib 导入时自动执行）
   - 定义符合预期的 `xxxop_info` 类以避免立即报错

2. **执行恶意文件**:
   ```bash
   msopst create -i /path/to/malicious_op_impl.py -out /some/output
   ```
   
   或者在自动化流程中：
   ```bash
   msopst gen_ascendc -i /path/to/malicious_op_impl.py -kernel /valid/kernel.cpp
   ```

3. **攻击触发**:
   - 工具将 `/path/to` 目录添加到 `sys.path`
   - `importlib.import_module("malicious_op_impl")` 导入模块
   - **模块顶层代码立即执行**（包括恶意代码）
   - 工具尝试读取 `malicious_opop_info` 类继续正常流程

### 攻击效果

由于 Python 模块在导入时执行所有顶层代码，攻击者可实现：

- **立即代码执行**: 无需等待函数被调用，导入时即执行恶意代码
- **环境篡改**: 修改 sys.path、环境变量、全局配置
- **数据窃取**: 在工具执行前窃取敏感信息
- **权限提升**: 利用工具启动时的权限上下文
- **进程劫持**: 替换关键函数、植入钩子

### 特殊攻击向量

**场景 1: 利用现有可信文件**
- 攻击者在可信算子目录中放置恶意 `.py` 文件
- 开发者正常使用时，工具可能扫描目录并导入恶意文件

**场景 2: 符号链接攻击**
- 攻击者创建软链接：`ln -s /malicious/file.py /trusted/op_impl.py`
- 虽然有软链接警告，但路径仍被解析和导入

**场景 3: CI/CD 供应链攻击**
- 在代码仓库中提交恶意算子信息文件
- CI/CD 流程自动执行 `msopst` 处理算子文件
- 构建环境被入侵，影响后续所有构建产物

## 影响评估

### 影响范围

| 维度 | 评估 |
|------|------|
| **攻击复杂度** | Low - 直接指定恶意文件路径 |
| **攻击者要求** | Low - 只需文件创建权限 |
| **影响严重性** | High - 完全控制执行环境 |
| **可利用性** | High - 开发者常用的工作流程 |

### 业务影响

- **开发环境安全**: 开发者执行他人提供的算子文件时面临风险
- **CI/CD 安全**: 自动化流程处理提交的算子文件时可能被入侵
- **供应链安全**: 恶意算子文件通过代码仓库传播
- **团队协作**: 共享开发环境中的恶意文件可能影响其他开发者
- **信任边界破坏**: 算子文件本应可信，漏洞破坏此信任假设

### CVSS 评估建议

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector | Local | 需要本地文件访问 |
| Attack Complexity | Low | 无特殊条件 |
| Privileges Required | Low | 需要文件创建权限 |
| User Interaction | Required | 需要用户/系统执行工具 |
| Scope | Changed | 可影响工具执行环境外的系统 |
| Confidentiality | High | 可窃取任意数据 |
| Integrity | High | 可修改任意数据 |
| Availability | High | 可破坏系统 |

**建议 CVSS 评分**: 7.8 (High)

## 修复建议

### 短期修复 (紧急)

#### 方案 1: 严格白名单目录

限制 `-i` 参数指定的 `.py` 文件只能在预定义的安全目录内：

```python
ALLOWED_OP_INFO_DIRS = [
    os.path.join(PROJECT_ROOT, 'operators'),
    os.path.join(PROJECT_ROOT, 'custom_ops'),
]

def check_argument_valid(self):
    # 原有验证
    if os.path.splitext(self.input_file_path)[-1] not in ConstManager.INPUT_SUFFIX_LIST:
        raise OpTestGenException(...)
    utils.check_path_valid(self.input_file_path)
    
    # 新增: .py 文件路径白名单验证
    if self.input_file_path.endswith('.py'):
        allowed = False
        for allowed_dir in ALLOWED_OP_INFO_DIRS:
            allowed_dir = os.path.realpath(allowed_dir)
            if self.input_file_path.startswith(allowed_dir + os.sep):
                allowed = True
                break
        if not allowed:
            utils.print_error_log(
                "Python operator info file must be in allowed directories: %s" 
                % ALLOWED_OP_INFO_DIRS)
            raise OpTestGenException(ConstManager.OP_TEST_GEN_INVALID_PATH_ERROR)
```

#### 方案 2: 文件内容静态分析

在导入前检查 Python 文件的内容安全性：

```python
def check_py_file_safe(file_path):
    """静态分析 Python 文件内容"""
    dangerous_patterns = [
        r'import\s+os',           # 系统操作
        r'import\s+subprocess',   # 进程执行
        r'import\s+socket',       # 网络通信
        r'eval\s*\(',             # 动态执行
        r'exec\s*\(',             # 动态执行
        r'__import__\s*\(',       # 动态导入
        r'open\s*\(.+,\s*[\'\"]w', # 文件写入
        r'system\s*\(',           # 系统命令
    ]
    
    content = utils.read_file(file_path)
    for pattern in dangerous_patterns:
        if re.search(pattern, content):
            utils.print_error_log(
                "Python file contains potentially dangerous code: %s" % pattern)
            return False
    return True

def _parse_py_to_json(self):
    expect_func_file = self.input_file_path
    
    # 新增: 内容安全检查
    if not check_py_file_safe(expect_func_file):
        raise OpTestGenException("Operator info file contains unsafe code")
    
    # 后续导入逻辑...
```

### 中期修复 (推荐)

#### 方案: 算子信息文件注册机制

建立算子信息文件的注册和审核流程：

1. **预注册**: 开发者提交算子信息文件到注册表
2. **安全审核**: 安全团队审核文件内容
3. **签名发布**: 审核通过的文件获得签名
4. **强制验证**: 工具只接受带有效签名的文件

```python
# 注册表配置
REGISTERED_OP_INFO = {
    "relu_impl": {
        "path": "/safe/path/relu_impl.py",
        "signature": "SHA256:abc123...",
        "owner": "developer_a",
        "approved": True,
    }
}

def verify_registered_file(file_path):
    """验证文件是否在注册表中且签名有效"""
    module_name = os.path.splitext(os.path.basename(file_path))[0]
    
    if module_name not in REGISTERED_OP_INFO:
        raise OpTestGenException(f"Operator info file not registered: {module_name}")
    
    registered = REGISTERED_OP_INFO[module_name]
    if not registered["approved"]:
        raise OpTestGenException(f"Operator info file not approved: {module_name}")
    
    # 验证签名
    actual_sig = compute_file_signature(file_path)
    if actual_sig != registered["signature"]:
        raise OpTestGenException(f"Operator info file signature mismatch: {module_name}")
    
    return registered["path"]
```

### 长期修复 (架构改进)

#### 方案: 算子信息文件标准化

将算子信息文件从可执行的 Python 文件改为纯数据配置文件：

1. **使用 JSON/YAML**: 算子信息使用纯数据格式描述
2. **去除动态导入**: 不再需要导入 Python 模块获取算子信息
3. **严格解析**: 只解析预定义的字段结构
4. **类型验证**: 所有字段有严格的类型约束

```python
# 新的算子信息 JSON 格式
{
    "op_type": "Relu",
    "inputs": [
        {"name": "x", "dtype": ["float16", "float32"], "format": "ND"}
    ],
    "outputs": [
        {"name": "y", "dtype": ["float16", "float32"], "format": "ND"}
    ],
    "attrs": []
}

# 解析逻辑（无需导入）
def _parse_json_op_info(self):
    op_info = utils.load_json_file(self.input_file_path)
    self._validate_op_info_schema(op_info)
    self.op_info = op_info
```

### 修复优先级建议

| 方案 | 优先级 | 实施难度 | 安全效果 | 兼容性影响 |
|------|--------|----------|----------|------------|
| 白名单目录 | P0 | Low | Medium | Medium |
| 内容静态分析 | P1 | Medium | Medium | Low |
| 注册机制 | P2 | High | High | High |
| 文件格式标准化 | P3 | High | Very High | High |

**建议**: 先实施 P0/P1 方案作为紧急修复，后续逐步推进 P2/P3 架构改进。

### 修复验证建议

1. **白名单测试**: 验证非法路径被有效拒绝
2. **内容检查测试**: 验证包含危险模式的文件被拒绝
3. **正常用例回归**: 验证合法算子文件仍能正常处理
4. **边界测试**: 验证软链接、路径规范化等边界情况

## 相关漏洞

本漏洞与 **VULN-DF-CODE-001** 属于同一类漏洞模式（通过 `importlib.import_module` 导入用户可控模块），但攻击入口不同。建议：

1. **同时修复两处漏洞**: 采用统一的安全机制
2. **共享修复方案**: 白名单、内容检查等机制可复用
3. **统一安全策略**: 建立统一的动态导入安全规范

## 参考资料

- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [Python Dynamic Import Security](https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html)
- [Secure File Handling in Python](https://python.readthedocs.io/en/stable/library/security.html)
- [Supply Chain Security Best Practices](https://slsa.dev/)