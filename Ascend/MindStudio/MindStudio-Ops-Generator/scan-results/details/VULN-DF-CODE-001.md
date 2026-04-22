# VULN-DF-CODE-001 - Arbitrary Code Execution via Dynamic Import

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-CODE-001 |
| **漏洞类型** | Arbitrary Code Execution (代码注入) |
| **CWE** | CWE-94: Improper Control of Generation of Code ('Code Injection') |
| **严重性** | Critical |
| **置信度** | 85% CONFIRMED |
| **影响文件** | `tools/msopst/st/interface/data_generator.py` |
| **漏洞位置** | 第 389-409 行, `_get_tensors_and_func` 函数 |
| **所属模块** | msopst |

### 漏洞描述

在 MindStudio Ops Generator 工具的 `data_generator.py` 中，`_get_tensors_and_func` 函数通过 `importlib.import_module` 动态导入用户指定的 Python 模块。该模块路径来源于 JSON 测试用例文件的 `calc_expect_func_file` 字段，属于用户可控输入。由于缺乏对导入文件内容的安全性验证，攻击者可以通过提供恶意构造的 JSON 测试用例文件，指向包含恶意代码的 Python 文件，从而实现任意代码执行。

## 攻击向量分析

### 数据流路径

```
SOURCE: JSON 测试用例文件 (用户可控)
  └── load_json_file@utils.py:596 → case dict
      └── case.get("calc_expect_func_file") → expect_func_file
          ├── sys.path.append(os.path.dirname(expect_func_file)) [无安全验证]
          │   └── 添加恶意文件目录到 Python 导入路径
          ├── importlib.import_module(module_name) [SINK - 任意模块导入]
          │   └── 导入并执行恶意 Python 模块
          └── getattr(module, expect_func) → func() [任意函数执行]
              └── 执行恶意模块中的任意函数
```

### 关键代码片段

```python
# data_generator.py:389-409
def _get_tensors_and_func(self, case, calc_func_params_tmp):
    expect_func_file = case.get("calc_expect_func_file")  # 用户可控
    expect_func = case.get("calc_expect_func_file_func")   # 用户可控
    sys.path.append(os.path.dirname(expect_func_file))     # 添加任意目录到 sys.path
    py_file = os.path.basename(expect_func_file)
    module_name, _ = os.path.splitext(py_file)
    module = importlib.import_module(module_name)           # 导入任意模块
    expect_result_tensors = self._get_expect_result_tensors(
        module, expect_func, calc_func_params_tmp)          # 执行任意函数
```

### 现有缓解措施及其局限性

| 缓解措施 | 实现位置 | 验证内容 | 局限性 |
|----------|----------|----------|--------|
| `check_path_valid` | utils.py:310-359 | 路径存在性、可读权限 | **不验证文件内容安全性** |
| `check_file_valid` | utils.py:398-410 | 文件大小、路径长度、字符格式 | **不验证文件内容安全性** |
| `check_path_pattern_valid` | utils.py:372-374 | 路径字符合法性（允许 `.` `/` `:` `_` `-` ` ` `+` `~` 及字母数字） | **允许任意合法路径，包括攻击者可控路径** |

**关键结论**: 现有的路径验证机制只确保路径格式合法和文件可访问，**完全不验证导入文件的内容安全性**。任何可读的 Python 文件都能被导入执行，包括攻击者预先放置的恶意文件。

### 攻击入口分析

**入口点类型**: 文件输入 (JSON 测试用例文件)

**信任边界**: 
- **可信侧**: MindStudio Ops Generator 工具执行环境
- **不可信侧**: 用户提供的 JSON 测试用例文件及其指定的 Python 文件

**CLI 调用链**:
```
msopst.py (CLI 入口)
  └── CaseDesign(args.input_file, args.case_name, report)
      └── load_json_file(json_path) → case_list
          └── DataGenerator(case_list, output_path, ...)
              └── _get_tensors_and_func(case, ...) → importlib.import_module()
```

## PoC 概念性描述

### 攻击场景

**前提条件**:
1. 攻击者有能力创建或修改 JSON 测试用例文件
2. 攻击者能在目标系统上放置恶意 Python 文件（或利用已存在的恶意文件）

**攻击步骤**:

1. **创建恶意 Python 模块** (`malicious_impl.py`):
   - 放置在攻击者可控的目录中
   - 模块内容包含恶意代码（如反向 shell、数据窃取、权限提升等）
   - 定义一个符合工具预期的函数名（如 `calc_expect_func`）

2. **构造恶意 JSON 测试用例文件**:
   ```json
   {
     "op": "some_operator",
     "calc_expect_func_file": "/path/to/malicious_impl.py",
     "calc_expect_func_file_func": "calc_expect_func",
     ...其他必需字段...
   }
   ```

3. **触发漏洞**:
   - 执行 `msopst` 工具处理该 JSON 文件
   - 工具将 `/path/to` 目录添加到 `sys.path`
   - 导入 `malicious_impl` 模块，执行模块级代码
   - 调用 `calc_expect_func` 函数，执行函数级代码

### 攻击效果

攻击者可实现：
- **任意代码执行**: 在 MindStudio 执行环境中运行任意 Python 代码
- **数据窃取**: 读取敏感文件、环境变量、配置信息
- **权限提升**: 利用工具执行权限进行特权操作
- **横向移动**: 在共享环境中植入后门
- **持久化**: 创建持久化的恶意脚本或配置

## 影响评估

### 影响范围

| 维度 | 评估 |
|------|------|
| **攻击复杂度** | Low - 只需构造 JSON 文件和 Python 文件 |
| **攻击者要求** | Medium - 需要能在目标系统上放置文件或利用现有文件 |
| **影响严重性** | Critical - 完全控制执行环境 |
| **可利用性** | High - 工具广泛用于 AI 算子开发测试场景 |

### 业务影响

- **开发环境安全**: 开发人员使用的 MindStudio 工具可能被利用执行恶意代码
- **CI/CD 安全**: 在自动化测试流程中，恶意测试用例可能导致构建环境被入侵
- **供应链安全**: 如果恶意测试用例被共享或分发，可能影响其他开发者
- **数据安全**: 执行环境中的敏感数据（模型、配置、密钥）可能被窃取

### CVSS 评估建议

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector | Local | 需要本地文件访问能力 |
| Attack Complexity | Low | 无特殊条件要求 |
| Privileges Required | Low | 需要文件写入权限 |
| User Interaction | Required | 需要用户执行工具处理测试用例 |
| Scope | Changed | 可影响工具执行环境外的系统 |
| Confidentiality | High | 可窃取任意数据 |
| Integrity | High | 可修改任意数据 |
| Availability | High | 可破坏系统可用性 |

**建议 CVSS 评分**: 7.8-8.0 (High-Critical)

## 修复建议

### 短期修复 (紧急)

#### 方案 1: 白名单路径限制

限制 `calc_expect_func_file` 只能指向预定义的安全目录：

```python
ALLOWED_FUNC_DIRS = [
    os.path.join(PROJECT_ROOT, 'custom_impl'),
    os.path.join(PROJECT_ROOT, 'test_utils'),
]

def _get_tensors_and_func(self, case, calc_func_params_tmp):
    expect_func_file = case.get("calc_expect_func_file")
    expect_func_file = os.path.realpath(expect_func_file)
    
    # 验证路径在白名单目录内
    allowed = False
    for allowed_dir in ALLOWED_FUNC_DIRS:
        allowed_dir = os.path.realpath(allowed_dir)
        if expect_func_file.startswith(allowed_dir + os.sep):
            allowed = True
            break
    
    if not allowed:
        raise OpTestGenException("calc_expect_func_file must be in allowed directories")
    
    # 后续导入逻辑...
```

#### 方案 2: 模块签名验证

要求用户提供的 Python 模块必须包含有效的数字签名：

```python
def verify_module_signature(file_path):
    """验证模块文件签名"""
    # 使用项目或组织的签名公钥验证
    # 代码签名机制需要配套的签名流程
    pass

def _get_tensors_and_func(self, case, calc_func_params_tmp):
    expect_func_file = case.get("calc_expect_func_file")
    
    if not verify_module_signature(expect_func_file):
        raise OpTestGenException("Module signature verification failed")
    
    # 后续导入逻辑...
```

### 中期修复 (推荐)

#### 方案: 预注册模块机制

建立模块注册表，只允许预先注册的模块被导入：

```python
# 模块注册表配置文件
REGISTERED_MODULES = {
    "calc_relu": "/safe/path/relu_impl.py",
    "calc_conv2d": "/safe/path/conv2d_impl.py",
    # ...
}

def _get_tensors_and_func(self, case, calc_func_params_tmp):
    expect_func_name = case.get("calc_expect_func_file_func")
    
    # 从注册表获取安全路径
    if expect_func_name not in REGISTERED_MODULES:
        raise OpTestGenException(f"Unknown expect function: {expect_func_name}")
    
    expect_func_file = REGISTERED_MODULES[expect_func_name]
    
    # 后续导入逻辑使用安全路径...
```

### 长期修复 (架构改进)

#### 方案: 安全沙箱执行

将用户提供的计算函数放入受限沙箱环境执行：

1. **使用 RestrictedPython**: 约束可执行的 Python 代码
2. **进程隔离**: 在单独的低权限进程中执行用户代码
3. **资源限制**: 限制 CPU、内存、文件访问等资源
4. **审计日志**: 记录所有用户代码执行行为

```python
from RestrictedPython import compile_restricted, safe_builtins

def _execute_in_sandbox(module_path, func_name, params):
    """在沙箱中执行用户函数"""
    # 编译受限代码
    code = compile_restricted(source_code, mode='exec')
    
    # 使用受限内置函数
    safe_globals = {'__builtins__': safe_builtins}
    
    # 执行代码
    exec(code, safe_globals)
    func = safe_globals[func_name]
    return func(params)
```

### 修复验证建议

修复后应进行以下验证：

1. **路径限制测试**: 验证白名单机制有效阻止非法路径
2. **签名验证测试**: 验证无签名或签名无效的模块被拒绝
3. **沙箱测试**: 验证沙箱能有效限制恶意代码行为
4. **回归测试**: 验证正常使用场景不受影响

## 相关漏洞

本漏洞与 **VULN-DF-PY-STI-001** 存在相似的攻击机制，两者都通过 `importlib.import_module` 导入用户可控的 Python 文件。建议同时修复两处漏洞。

## 参考资料

- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [Python importlib Security Considerations](https://docs.python.org/3/library/importlib.html)
- [RestrictedPython Documentation](https://restrictedpython.readthedocs.io/)