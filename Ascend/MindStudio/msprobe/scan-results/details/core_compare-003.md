# 漏洞分析报告: core_compare-003

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | core_compare-003 |
| **CWE分类** | CWE-78 (OS Command Injection) / CWE-88 (Argument Injection) |
| **文件路径** | python/msprobe/core/compare/offline_data_compare.py:70-98 |
| **函数** | `call_msaccucmp` |
| **置信度** | 85 → **确认有效** |
| **严重性** | 中低 (Medium-Low) |
| **信任级别** | untrusted_local |

### 漏洞描述

`call_msaccucmp` 函数使用 `subprocess.Popen` 执行外部命令，参数来源于用户提供的 CLI 路径参数。虽然代码正确使用了 `shell=False` 和列表形式传参（避免经典 shell 注入），但 **msprobe 在调用 subprocess 前未对路径参数进行输入验证**，依赖下游 `msaccucmp.py` 的验证机制，这是一个安全反模式。

---

## 漏洞代码分析

### 1. 入口点参数解析 (无验证)

**文件**: `python/msprobe/core/compare/utils.py:663-674`

```python
def _compare_parser(parser):
    parser.add_argument("-tp", "--target_path", dest="target_path", type=str,  # ← 仅 type=str，无验证!
                        help="<Required> The compare target device path", required=True)
    parser.add_argument("-gp", "--golden_path", dest="golden_path", type=str,  # ← 仅 type=str，无验证!
                        help="<Required> The compare golden device path", required=True)
    # ... 其他参数同样无验证
```

**问题**: 参数直接使用 `type=str`，没有应用任何安全验证函数。

### 2. 参数传递到命令 (无验证)

**文件**: `python/msprobe/core/compare/offline_data_compare.py:32-55`

```python
def compare_offline_data_mode(args):
    cmd_args = []
    
    if args.target_path:
        cmd_args.extend(['-m', args.target_path])  # ← 用户输入直接加入命令
    
    if args.golden_path:
        cmd_args.extend(['-g', args.golden_path])  # ← 用户输入直接加入命令
    
    if args.fusion_rule_file:
        cmd_args.extend(['-f', args.fusion_rule_file])
    
    if args.quant_fusion_rule_file:
        cmd_args.extend(['-q', args.quant_fusion_rule_file])
    
    if args.close_fusion_rule_file:
        cmd_args.extend(['-cf', args.close_fusion_rule_file])
    
    if args.output_path:
        cmd_args.extend(['-out', args.output_path])
    
    call_msaccucmp(cmd_args)  # ← 直接调用，无验证
```

### 3. Subprocess 调用 (shell=False)

**文件**: `python/msprobe/core/compare/offline_data_compare.py:70-98`

```python
def call_msaccucmp(cmd_args):
    msaccucmp_script_path = _check_msaccucmp_file(CANN_PATH)
    python_cmd = sys.executable
    full_cmd = [python_cmd, msaccucmp_script_path, "compare"] + cmd_args
    
    logger.info(f"Calling msaccucmp with command: {' '.join(full_cmd)}")  # ← 日志泄露命令
    
    process = subprocess.Popen(
        full_cmd,
        shell=False,  # ← 正确：避免 shell 注入
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    # ...
```

### 4. 下游验证 (延迟验证)

**文件**: `python/msaccucmp/src/compare/cmp_utils/utils.py:36-43`

```python
PATH_BLACK_LIST_REGEX = re.compile(r"[^_A-Za-z0-9/.,-]")  # 允许: _字母数字/.,-

def safe_path_string(value):
    if re.search(PATH_BLACK_LIST_REGEX, value):
        raise ValueError("String parameter contains invalid characters.")
    return value
```

**msaccucmp.py 的参数解析**:
```python
compare_parser.add_argument(
    '-m', '--my_dump_path', dest='my_dump_path', default='', type=safe_path_string, required=True,
    ...
)
```

---

## 调用链完整追踪

```
用户输入 (CLI)
    ↓
msprobe.py:main() → argparse.parse_args()
    ↓
compare_cli(args, sys_argv) → check_valid_args() [仅检查参数名，不检查值]
    ↓
compare_offline_data_mode(args) → 构建 cmd_args [无验证]
    ↓
call_msaccucmp(cmd_args) → subprocess.Popen [无验证，shell=False]
    ↓
msaccucmp.py → argparse.parse_args() → safe_path_string() [首次验证发生在这里!]
```

**关键问题**: 验证发生在 subprocess 调用**之后**，而非之前。

---

## 攻击场景分析

### 场景 1: 特殊字符注入 (被下游验证阻止)

**攻击尝试**:
```bash
msprobe compare -m offline_data -tp "/path/to/target; rm -rf /" -gp "/path/to/golden"
```

**结果**: 
- `shell=False` 阻止 `; rm -rf /` 作为 shell 命令执行
- msaccucmp.py 的 `safe_path_string` 会拒绝 `;` 和 ` ` (空格)
- 攻击被下游验证阻止，但 subprocess 仍被调用

### 场景 2: 合法字符路径注入 (可能绕过验证)

**攻击尝试**:
```bash
msprobe compare -m offline_data -tp "/../../../etc/passwd" -gp "/path/to/golden"
```

**分析**:
- `/../../../etc/passwd` 只包含 `/`, `.`, `字母`，符合 `safe_path_string` 允许字符
- 可能导致路径遍历问题
- 如果 msaccucmp.py 有其他路径检查，可能被阻止

### 场景 3: 环境变量/特殊路径

**攻击尝试**:
```bash
msprobe compare -m offline_data -tp "~root/.ssh" -gp "/path/to/golden"
```

**分析**:
- `~` 不在允许字符列表中，会被拒绝
- 但 subprocess 在验证前被调用

### 场景 4: 空格/Unicode 攻击

**攻击尝试**:
```bash
msprobe compare -m offline_data -tp "/path with spaces" -gp "/path/to/golden"
```

**分析**:
- 空格不在允许字符列表，会被拒绝
- 但 CLI 参数解析和 subprocess 调用仍然发生

---

## PoC 构造思路

### 基础 PoC (验证漏洞存在)

```python
import argparse
from msprobe.core.compare.offline_data_compare import compare_offline_data_mode

# 构造包含特殊字符的参数
args = argparse.Namespace(
    target_path="/path/to/target; echo 'INJECTED'",  # Shell 元字符
    golden_path="/path/to/golden",
    fusion_rule_file=None,
    quant_fusion_rule_file=None,
    close_fusion_rule_file=None,
    output_path=None
)

# 触发漏洞路径
compare_offline_data_mode(args)
```

**预期结果**:
- subprocess.Popen 被调用，命令参数包含 `; echo 'INJECTED'`
- msaccucmp.py 会因 `safe_path_string` 验证失败
- 攻击被阻止，但证明了验证延迟的问题

### 高级 PoC (路径遍历)

```python
args = argparse.Namespace(
    target_path="/../../../etc/shadow",  # 路径遍历尝试
    golden_path="/../../../etc/passwd",
    fusion_rule_file=None,
    quant_fusion_rule_file=None,
    close_fusion_rule_file=None,
    output_path="/tmp/malicious_output"
)

compare_offline_data_mode(args)
```

---

## 影响范围

### 直接影响
- **subprocess 调用未验证参数**: 安全反模式
- **日志泄露命令**: `logger.info(f"Calling msaccucmp with command: {' '.join(full_cmd)}")` 可能泄露敏感路径

### 间接影响
- 如果 msaccucmp.py 的验证存在 bug，攻击可能成功
- 路径遍历风险（使用合法字符如 `/`, `.`）
- 资源消耗攻击（多次调用导致进程创建）

### 受影响组件
- `msprobe compare -m offline_data` 命令
- 所有通过 CLI 传入的路径参数

---

## 安全评估

### 为什么 shell=False 不是完全解决方案

| 防护措施 | 有效性 | 限制 |
|----------|--------|------|
| `shell=False` | 有效阻止 shell 注入 | 不阻止参数注入 |
| 列表形式传参 | 减少解析风险 | 不验证参数内容 |
| 下游 safe_path_string | 验证字符白名单 | 延迟验证，subprocess 已被调用 |

### 安全原则违反

1. **"Fail Early" 原则**: 验证应在输入点立即发生，而非下游
2. **"Defense in Depth" 原则**: 应有多层验证，而非单点依赖
3. **"Least Privilege" 原则**: subprocess 执行前应最小化权限

---

## 修复建议

### 修复方案 1: 在 msprobe 添加输入验证 (推荐)

**文件**: `python/msprobe/core/compare/offline_data_compare.py`

```python
import re

PATH_BLACK_LIST_REGEX = re.compile(r"[^_A-Za-z0-9/.,-]")

def validate_path_string(value):
    """在 subprocess 调用前验证路径参数"""
    if not value:
        return value
    if re.search(PATH_BLACK_LIST_REGEX, value):
        raise CompareException(CompareException.INVALID_PATH_ERROR,
                                f"Path contains invalid characters: {value}")
    # 可选: 检查路径是否存在
    if not os.path.exists(value):
        raise CompareException(CompareException.INVALID_PATH_ERROR,
                                f"Path does not exist: {value}")
    return value

def compare_offline_data_mode(args):
    cmd_args = []
    
    # 添加验证
    if args.target_path:
        validated_path = validate_path_string(args.target_path)
        cmd_args.extend(['-m', validated_path])
    
    if args.golden_path:
        validated_path = validate_path_string(args.golden_path)
        cmd_args.extend(['-g', validated_path])
    
    # ... 对所有路径参数应用相同验证
    
    call_msaccucmp(cmd_args)
```

### 修复方案 2: 在 argparse 添加类型验证

**文件**: `python/msprobe/core/compare/utils.py`

```python
def safe_path_string(value):
    """安全路径字符串验证"""
    if re.search(r"[^_A-Za-z0-9/.,-]", value):
        raise argparse.ArgumentTypeError(f"Invalid characters in path: {value}")
    return value

def _compare_parser(parser):
    parser.add_argument("-tp", "--target_path", dest="target_path", 
                        type=safe_path_string,  # ← 添加验证
                        help="<Required> The compare target device path", 
                        required=True)
    parser.add_argument("-gp", "--golden_path", dest="golden_path", 
                        type=safe_path_string,  # ← 添加验证
                        help="<Required> The compare golden device path", 
                        required=True)
```

### 修复方案 3: 使用 shlex.quote 作为额外防护

```python
import shlex

def call_msaccucmp(cmd_args):
    # 即使 shell=False，使用 shlex.quote 作为防御层
    safe_cmd_args = [shlex.quote(arg) for arg in cmd_args]
    
    # 或者: 使用 subprocess.run 的安全参数
    process = subprocess.Popen(
        full_cmd,
        shell=False,
        # ...
    )
```

### 修复方案 4: 移除命令日志泄露

```python
# 修改日志，不泄露完整命令
logger.info(f"Calling msaccucmp with target_path")
# 而非:
# logger.info(f"Calling msaccucmp with command: {' '.join(full_cmd)}")
```

---

## 验证修复

修复后应通过以下测试:

```python
# 测试 1: 特殊字符被拒绝
args = argparse.Namespace(target_path="/path; rm -rf /", ...)
# 期望: CompareException 或 argparse.ArgumentTypeError

# 测试 2: 路径遍历被检测
args = argparse.Namespace(target_path="/../../../etc/shadow", ...)
# 期望: 验证失败或路径规范化

# 测试 3: 合法路径正常工作
args = argparse.Namespace(target_path="/valid/path/to/data", ...)
# 期望: 正常执行
```

---

## 结论

### 漏洞状态: **确认有效 (VALIDATED)**

这是一个**真实的输入验证缺陷**，虽然攻击路径受限，但违反了安全最佳实践:

1. **CWE-78 部分适用**: 虽然 shell=False 阻止了经典 shell 注入，但参数流未经验证到达 subprocess 调用
2. **CWE-88 更准确**: 这是 Argument Injection 的变体
3. **严重性评估**: 中低风险，因为下游验证存在，但安全架构存在缺陷

### 推荐优先级: **中等**

- 不是立即可利用的高危漏洞
- 但违反安全设计原则
- 应作为安全加固的一部分修复

---

## 附录: 相关 CWE 参考

- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **CWE-88**: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')
- **CWE-20**: Improper Input Validation
- **CWE-77**: Improper Neutralization of Special Elements used in a Command ('Command Injection')
