# 漏洞扫描报告 — 已确认漏洞

**项目**: MindStudio-Ops-Generator  
**扫描时间**: 2026-04-21T04:30:00Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描在 MindStudio-Ops-Generator 项目中发现 **2 个已确认的高危漏洞**，均为代码注入类漏洞（CWE-94）。这两个漏洞的共同特征是通过 `importlib.import_module` 动态导入用户可控的 Python 文件，导致任意代码执行风险。

### 关键发现

| 漏洞编号 | 严重性 | 漏洞类型 | 影响模块 | 攻击向量 |
|----------|--------|----------|----------|----------|
| VULN-DF-CODE-001 | **Critical** | 代码注入 | msopst | JSON 测试用例文件的 `calc_expect_func_file` 字段 |
| VULN-DF-PY-STI-001 | **High** | 代码注入 | msopst/st/interface | CLI `-i` 参数指定的 Python 文件 |

### 影响评估

**攻击者能力**：通过这两个漏洞，攻击者可以在 MindStudio 执行环境中运行任意 Python 代码，实现：
- 数据窃取（读取敏感文件、环境变量、配置信息）
- 权限提升（利用工具执行权限进行特权操作）
- 横向移动（在共享环境中植入后门）
- 持久化（创建恶意脚本或配置）

**影响场景**：
1. **开发环境安全**：开发者使用 MindStudio 处理他人提供的测试用例或算子文件时面临风险
2. **CI/CD 安全**：自动化构建流程处理外部提交的测试用例时可能被入侵
3. **供应链安全**：恶意测试用例通过代码仓库或共享平台传播

### 修复优先级

| 优先级 | 漏洞 | 建议修复时间 | 修复方案 |
|--------|------|--------------|----------|
| **P0** | VULN-DF-CODE-001 | 立即 | 实施白名单目录限制 |
| **P0** | VULN-DF-PY-STI-001 | 立即 | 实施白名单目录限制 |
| **P1** | 两漏洞统一修复 | 1-2 周 | 建立模块注册机制 |
| **P2** | 架构改进 | 长期 | 采用安全沙箱或纯数据格式 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 12 | 36.4% |
| POSSIBLE | 11 | 33.3% |
| LIKELY | 8 | 24.2% |
| CONFIRMED | 2 | 6.1% |
| **总计** | **33** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 1 | 50.0% |
| High | 1 | 50.0% |
| **有效漏洞总计** | **2** | - |
| 误报 (FALSE_POSITIVE) | 12 | - |

### 1.3 Top 2 已确认漏洞

1. **[VULN-DF-CODE-001]** code_injection (Critical) - `tools/msopst/st/interface/data_generator.py:389` @ `_get_tensors_and_func` | 置信度: 85
2. **[VULN-DF-PY-STI-001]** Arbitrary Code Execution (High) - `tools/msopst/st/interface/case_generator.py:96` @ `_get_ms_ops_info` | 置信度: 85

---

## 2. 攻击面分析

项目作为 Python CLI 开发工具，主要攻击面集中在用户输入处理：

| 信任边界 | 可信侧 | 不可信侧 | 风险等级 |
|----------|--------|----------|----------|
| **CLI Interface** | Application logic | User command line arguments and input files | High |
| **File System** | Application generated output | User-provided input files (JSON, Excel, INI, Model files) | High |
| **Dynamic Module Loading** | Application importlib calls | User-provided Python modules | **Critical** |

**关键攻击路径**：
- CLI 参数 → JSON 文件解析 → 动态模块导入 → 代码执行
- 测试用例文件 → `calc_expect_func_file` → `importlib.import_module` → RCE

---

## 3. Critical 漏洞深度分析

### [VULN-DF-CODE-001] Arbitrary Code Execution via Dynamic Import

> **详细分析报告**: [scan-results/details/VULN-DF-CODE-001.md](./details/VULN-DF-CODE-001.md)

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `tools/msopst/st/interface/data_generator.py:389-409` @ `_get_tensors_and_func`  
**模块**: msopst | **跨模块**: msopst → msopst-st-interface

#### 漏洞机制

漏洞存在于测试数据生成器的 `_get_tensors_and_func` 函数中：

```python
def _get_tensors_and_func(self, case, calc_func_params_tmp):
    expect_func_file = case.get("calc_expect_func_file")  # 用户可控
    expect_func = case.get("calc_expect_func_file_func")
    sys.path.append(os.path.dirname(expect_func_file))    # 添加任意目录
    module = importlib.import_module(module_name)          # 导入任意模块
    expect_result_tensors = self._get_expect_result_tensors(
        module, expect_func, calc_func_params_tmp)         # 执行任意函数
```

#### 数据流分析

```
SOURCE: JSON 测试用例文件 (用户可控)
  └── load_json_file@utils.py:596 → case dict
      └── case.get("calc_expect_func_file")
          ├── sys.path.append(dirname) [无安全验证]
          └── importlib.import_module() [SINK - 任意代码执行]
              └── getattr(module, func) → func()
```

#### 攻击场景

**前提条件**：
1. 攻击者能创建或修改 JSON 测试用例文件
2. 攻击者能在目标系统放置恶意 Python 文件

**攻击步骤**：
1. 创建恶意 Python 模块（包含反向 shell、数据窃取代码）
2. 构造 JSON 测试用例文件，`calc_expect_func_file` 指向恶意模块
3. 触发 `msopst` 工具处理该测试用例
4. 恶意模块被导入执行，攻击者获得代码执行能力

#### 现有缓解措施局限性

| 缓解措施 | 验证内容 | 局限性 |
|----------|----------|--------|
| `check_path_valid` | 路径存在性、权限 | **不验证文件内容** |
| `check_file_valid` | 文件大小、格式 | **不验证文件内容** |
| `check_path_pattern_valid` | 路径字符合法性 | **允许任意合法路径** |

**关键结论**: 所有验证仅确保文件存在且可读，**完全无法阻止恶意代码执行**。

---

## 4. High 漏洞深度分析

### [VULN-DF-PY-STI-001] Arbitrary Code Execution via CLI Input

> **详细分析报告**: [scan-results/details/VULN-DF-PY-STI-001.md](./details/VULN-DF-PY-STI-001.md)

**严重性**: High | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED

**位置**: `tools/msopst/st/interface/case_generator.py:96` @ `_get_ms_ops_info`  
**模块**: msopst/st/interface | **跨模块**: msopst/st/interface → msopst

#### 漏洞机制

漏洞存在于测试用例生成器的 `_parse_py_to_json` 函数中：

```python
def _parse_py_to_json(self):
    expect_func_file = self.input_file_path  # 来自 CLI -i 参数
    sys.path.append(os.path.dirname(expect_func_file))
    module_name, _ = os.path.splitext(os.path.basename(expect_func_file))
    mindspore_ops_info = self._get_ms_ops_info(module_name, class_name)

@staticmethod
def _get_ms_ops_info(module_name, class_name):
    params = importlib.import_module(module_name)  # 动态导入
    return getattr(params, class_name)
```

#### 数据流分析

```
SOURCE: CLI 参数 -i (用户可控)
  └── args.input_file → self.input_file_path
      ├── os.path.realpath() [仅路径规范化]
      ├── check_path_valid() [仅验证存在性]
      └── importlib.import_module() [SINK - 任意代码执行]
```

#### 与 VULN-DF-CODE-001 的区别

| 维度 | VULN-DF-CODE-001 | VULN-DF-PY-STI-001 |
|------|------------------|---------------------|
| **数据源** | JSON 文件字段 | CLI 参数直接指定 |
| **触发方式** | DataGenerator 处理测试用例 | CaseGenerator 解析算子信息 |
| **攻击复杂度** | Medium (需构造 JSON) | **Low (直接指定文件)** |
| **共享环境风险** | 处理他人提供的测试用例 | 执行他人提供的算子文件 |

**关键差异**: CLI 直接指定攻击向量更直接，在共享开发环境或 CI/CD 场景风险更高。

---

## 5. 综合修复建议

### 5.1 紧急修复方案（立即实施）

#### 方案 A: 白名单目录限制

限制动态导入的文件路径只能在预定义的安全目录内：

```python
# 安全目录白名单
ALLOWED_IMPORT_DIRS = [
    os.path.join(PROJECT_ROOT, 'operators'),
    os.path.join(PROJECT_ROOT, 'test_utils'),
    os.path.join(PROJECT_ROOT, 'custom_impl'),
]

def validate_import_path(file_path):
    """验证导入路径在白名单目录内"""
    real_path = os.path.realpath(file_path)
    for allowed_dir in ALLOWED_IMPORT_DIRS:
        allowed_real = os.path.realpath(allowed_dir)
        if real_path.startswith(allowed_real + os.sep):
            return True
    raise SecurityException(
        f"Import path not in allowed directories: {file_path}"
    )

# 在 _get_tensors_and_func 和 _parse_py_to_json 中调用
validate_import_path(expect_func_file)
```

**优点**：
- 实施快速，代码改动小
- 明确限制导入范围
- 易于审计和维护

**缺点**：
- 需要预先定义安全目录
- 可能影响现有工作流程

#### 方案 B: 文件内容安全检查

在导入前对 Python 文件进行静态安全扫描：

```python
def check_py_file_safe(file_path):
    """检查 Python 文件是否包含危险代码模式"""
    DANGEROUS_PATTERNS = [
        r'import\s+os\b',
        r'import\s+subprocess\b',
        r'import\s+socket\b',
        r'eval\s*\(',
        r'exec\s*\(',
        r'__import__\s*\(',
        r'open\s*\(.+,\s*[\'\"]w',
        r'subprocess\.',
    ]
    
    content = read_file(file_path)
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, content):
            return False
    return True
```

**优点**：
- 不限制目录，灵活性高
- 可检测常见恶意模式

**缺点**：
- 静态分析可能被绕过
- 正常代码可能误报

### 5.2 中期修复方案（1-2 周实施）

#### 建立模块注册机制

创建模块注册表，只允许预先注册和审核的模块被导入：

```python
# 模块注册配置文件 (registered_modules.yaml)
modules:
  calc_relu:
    path: /safe/path/relu_impl.py
    signature: SHA256:abc123...
    owner: developer_a
    approved: true
  
  calc_conv2d:
    path: /safe/path/conv2d_impl.py
    signature: SHA256:def456...
    owner: developer_b
    approved: true

def get_registered_module(module_name):
    """从注册表获取安全模块路径"""
    registry = load_yaml('registered_modules.yaml')
    if module_name not in registry['modules']:
        raise SecurityException(f"Module not registered: {module_name}")
    
    module_info = registry['modules'][module_name]
    if not module_info['approved']:
        raise SecurityException(f"Module not approved: {module_name}")
    
    # 验证签名
    actual_sig = compute_sha256(module_info['path'])
    if actual_sig != module_info['signature']:
        raise SecurityException(f"Module signature mismatch: {module_name}")
    
    return module_info['path']
```

**优点**：
- 高安全性，需审核才能导入
- 签名验证防止篡改
- 明确的责任归属

**缺点**：
- 需建立审核流程
- 影响开发效率
- 需维护注册表

### 5.3 长期架构改进

#### 方案 A: 安全沙箱执行

将用户提供的计算函数放入受限环境执行：

```python
from RestrictedPython import compile_restricted, safe_builtins

def execute_in_sandbox(source_code, func_name, params):
    """在受限环境中执行用户代码"""
    # 编译受限代码
    code = compile_restricted(source_code, mode='exec')
    
    # 使用受限内置函数
    safe_globals = {
        '__builtins__': safe_builtins,
        'numpy': numpy,  # 允许使用的库
    }
    
    exec(code, safe_globals)
    func = safe_globals[func_name]
    return func(params)
```

#### 方案 B: 纯数据格式替代

将算子信息从可执行 Python 文件改为纯数据配置：

```json
{
    "op_type": "Relu",
    "inputs": [{"name": "x", "dtype": ["float16", "float32"]}],
    "outputs": [{"name": "y", "dtype": ["float16", "float32"]}],
    "calc_expect": {
        "type": "predefined",
        "function": "relu"
    }
}
```

**优点**：
- 完全消除代码注入风险
- 配置文件易于验证和审计
- 支持预定义的安全计算函数

**缺点**：
- 需重构现有架构
- 灵活性降低
- 需迁移现有用例

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| msopst | 1 | 0 | 0 | 0 | 1 |
| msopst/st/interface | 0 | 1 | 0 | 0 | 1 |
| **合计** | **1** | **1** | **0** | **0** | **2** |

---

## 7. CWE 分布

| CWE | 数量 | 占比 | 说明 |
|-----|------|------|------|
| CWE-94 | 2 | 100.0% | Improper Control of Generation of Code ('Code Injection') |

---

## 8. 附录：验证测试建议

修复后应进行以下安全测试：

### 8.1 白名单测试

```
测试用例：
- 正常路径（白名单目录内）→ 应成功导入
- 非白名单路径 → 应拒绝并报错
- 路径遍历尝试（../../../etc/passwd）→ 应拒绝
- 软链接绕过 → 应拒绝
```

### 8.2 内容检查测试

```
测试用例：
- 包含 os/subprocess 导入的文件 → 应拒绝
- 包含 eval/exec 调用的文件 → 应拒绝
- 正常计算函数 → 应通过
```

### 8.3 回归测试

```
测试用例：
- 使用现有合法测试用例 → 应正常工作
- 使用现有合法算子信息文件 → 应正常工作
- CI/CD 流程 → 应不受影响
```

---

## 9. 参考资料

- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [OWASP Code Injection Guide](https://owasp.org/www-community/attacks/Code_Injection)
- [Python importlib Security Considerations](https://docs.python.org/3/library/importlib.html)
- [RestrictedPython Documentation](https://restrictedpython.readthedocs.io/)
- [Supply Chain Security Best Practices (SLSA)](https://slsa.dev/)