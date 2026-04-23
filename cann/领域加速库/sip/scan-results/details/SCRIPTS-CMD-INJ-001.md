# SCRIPTS-CMD-INJ-001：compile脚本命令注入漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | SCRIPTS-CMD-INJ-001 |
| **类型** | Command Injection (命令注入) |
| **CWE** | CWE-78 (OS Command Injection) |
| **严重级别** | Critical |
| **文件** | scripts/compile_ascendc.py |
| **位置** | 第 227 行 (exe_cmd 函数) |
| **影响范围** | 第 227-323 行 (所有调用 exe_cmd 的位置) |

## 根因分析

### 漏洞代码

```python
# 第 226-231 行
def exe_cmd(cmd):
    if os.system(cmd) != 0:
        logging.error("execute command failed")
        logging.debug("command: %s", cmd)
        return -1
    return 0
```

### 问题根源

1. **使用 `os.system()` 执行 shell 命令**
   - `os.system()` 通过 `/bin/sh` 执行命令，会解析 shell 元字符
   - 无任何输入验证或转义机制

2. **命令字符串通过 `' '.join()` 拼接**
   ```python
   # 第 252 行 - 典型漏洞模式
   compile_cmd = ' '.join(gen_compile_cmd(args, dst, arch, opt))
   if(exe_cmd(compile_cmd)) != 0:
       return -1
   ```

3. **多个用户可控参数直接嵌入命令**
   - `--srcs` (源文件路径)
   - `--dst` (目标文件路径)
   - `--code_root` (代码根目录)
   - `--kernel` (内核名称)
   - `--include_directories` (包含目录列表)
   - `--soc` (芯片类型)
   - `--channel` (通道类型)

### 数据流追踪

```
CLI 参数 / CMake 变量
    ↓
argparse.parse_args() / kernel_config.cmake 构建 PYTHON_ARGS
    ↓
gen_compile_cmd*() 函数构建参数列表
    ↓
' '.join(cmd_list) 拼接为字符串
    ↓
exe_cmd(cmd)
    ↓
os.system(cmd) → /bin/sh -c "cmd"
```

## 攻击向量分析

### 向量 1: 通过 CMake 构建系统

**触发位置**: `cmake/kernel_config.cmake` 第 39 行

```cmake
add_custom_command(
    OUTPUT ${${kernel}_${soc}_output}
    DEPENDS ${srcs}
    WORKING_DIRECTORY ${OPS_PROJECT_ROOT_DIR}
    COMMAND python3 ${PROJECT_SOURCE_DIR}/scripts/compile_ascendc.py ${PYTHON_ARGS}
)
```

**攻击场景**:
- 攻击者控制项目中的 `CMakeLists.txt` 文件
- 通过注入恶意 `kernel` 或 `soc` 参数值触发命令执行
- 在 CI/CD 管道中自动触发

**示例**:
```cmake
# 恶意 CMakeLists.txt 片段
add_kernel("kernel;touch /tmp/pwned" ascend910b mix src.cce Kernel)
# 或
add_kernel(kernel "ascend910b;id" mix src.cce Kernel)
```

### 向量 2: 直接命令行调用

**攻击前提**: 攻击者能够直接执行 Python 脚本

**注入点分析**:
| 参数 | 污染源 | 拼接位置 |
|------|--------|----------|
| `--srcs` | 第 44, 70, 98, 119 行 | 直接作为命令参数 |
| `--dst` | 第 45, 71, 99, 120 行 | `-o` 参数后 |
| `--code_root` | 第 36-37, 62-63, 90-91, 115-116 行 | 编译器路径前缀 |
| `--kernel` | 第 251, 262, 273, 282, 292, 300, 307, 313 行 | `-D` 宏定义 |
| `--include_directories` | 第 191-192 行 | `-I` 参数后 |

### 向量 3: 环境变量注入

**相关代码**: 第 241-242 行
```python
ascend_home_path = os.getenv("ASCEND_HOME_PATH", "ASCEND_HOME_PATH does not exist.")
mssanitizer_path = os.path.join(ascend_home_path, "tools", "mssanitizer", "lib64")
```

虽然路径用于 `dsts.append()` 而非直接执行，但环境变量污染可能影响其他方面。

## 触发条件

### 条件 1: Shell 元字符注入

以下 shell 元字符可用于注入命令：
- **命令分隔符**: `;`, `&&`, `||`, `\n`
- **命令替换**: `$(cmd)`, `` `cmd` ``
- **重定向**: `>`, `>>`, `<`
- **管道**: `|`
- **后台执行**: `&`

### 条件 2: 具体触发位置

| 行号 | 函数 | 漏洞调用 |
|------|------|----------|
| 253 | compile_ascendc_operation | `exe_cmd(compile_cmd)` - ascend310p/ascend910 编译 |
| 264 | compile_ascendc_operation | `exe_cmd(compile_cmd)` - ascend910b 编译 |
| 275 | compile_ascendc_operation | `exe_cmd(compile_cmd)` - ascend910b mix AIC |
| 284 | compile_ascendc_operation | `exe_cmd(compile_cmd)` - ascend910b mix AIV |
| 294 | compile_ascendc_operation | `exe_cmd(compile_cmd)` - ascend310b 编译 |
| 302 | compile_ascendc_operation | `exe_cmd(compile_cmd)` - ascend950 编译 |
| 309 | compile_ascendc_operation | `exe_cmd(compile_cmd)` - ascend950 mix AIC |
| 315 | compile_ascendc_operation | `exe_cmd(compile_cmd)` - ascend950 mix AIV |
| 324 | compile_ascendc_operation | `exe_cmd(link_cmd)` - 链接命令 |

### 条件 3: 运行环境

1. **CI/CD 管道**: 构建系统自动执行编译脚本
2. **开发者环境**: 本地构建时触发
3. **供应链场景**: 下游用户编译受污染的项目

## 影响范围

### 直接影响

1. **任意命令执行**
   - 攻击者可执行任意系统命令
   - 继承当前进程权限（可能为构建服务账户或 root）

2. **数据泄露**
   - 读取敏感文件（密钥、配置、源代码）
   - 窃取构建产物和中间文件

3. **系统破坏**
   - 删除文件和目录
   - 修改系统配置
   - 安装后门

### 供应链攻击场景

```
[恶意项目维护者]
        ↓ 修改 CMakeLists.txt 注入恶意参数
    [代码仓库]
        ↓ 用户克隆代码
    [CI/CD 管道] ──→ [构建服务器被控制]
        ↓                   ↓
    [发布产物]         [横向移动攻击]
        ↓
    [下游用户受影响]
```

### 具体威胁场景

1. **开源项目投毒**
   - 攻击者向开源项目提交恶意 CMakeLists.txt
   - 不知情的开发者在本地构建时触发漏洞
   - CI/CD 系统自动构建时被攻击

2. **企业内部攻击**
   - 内部人员修改构建配置
   - 在构建服务器上执行恶意代码
   - 横向移动攻击内网其他系统

3. **第三方依赖污染**
   - 供应链上游被攻击
   - 所有下游用户在编译时受影响

## PoC 构造思路

### 思路 1: 通过 --kernel 参数注入

**原理**: `--kernel` 参数在第 251 行等位置被拼接到 `-D` 宏定义中

**恶意输入格式**:
```bash
--kernel "kernel_name;id;#"
# 或
--kernel "$(id)"
```

**构造方法**:
1. 识别命令拼接点（如 `-Dkernel_name=kernel_name_key`）
2. 在参数值中注入 shell 元字符
3. 元字符后跟恶意命令
4. 使用注释符号 `#` 清理后续内容

### 思路 2: 通过 --srcs 参数注入

**原理**: `--srcs` 直接作为编译器输入参数（第 44 行等）

**恶意输入格式**:
```bash
--srcs "source.cce;touch /tmp/pwned;"
# 或
--srcs "source.cce$(cat /etc/passwd > /tmp/leak)"
```

### 思路 3: 通过 --include_directories 参数注入

**原理**: 第 191-192 行将 include_directories 拼接到 `-I` 参数后

**恶意输入格式**:
```bash
--include_directories "/usr/include" "/tmp;id"
```

### 思路 4: 通过 --code_root 参数注入

**原理**: 用于构建编译器路径（第 36-37 行等）

**恶意输入格式**:
```bash
--code_root "/path/to/code;id;#"
```

### 最小化 PoC 演示思路

**安全验证方式**（不提供完整可执行代码）:
1. 使用无害命令验证漏洞存在（如 `id`, `echo`, `touch`）
2. 观察命令执行结果（输出、文件创建等）
3. 确认注入点有效性

**验证步骤**:
1. 准备最小合法输入参数（soc, channel, srcs, dst 等）
2. 在一个参数中注入测试命令（如 `;echo VULNERABLE;`）
3. 执行脚本并观察是否输出 "VULNERABLE"
4. 检查日志或输出确认命令被执行

## 修复建议

### 修复方案 1: 使用 subprocess + shell=False（推荐）

**修改位置**: `exe_cmd` 函数（第 226-231 行）

**修复代码**:
```python
import subprocess
import shlex

def exe_cmd(cmd_list):
    """
    安全执行命令 - 使用列表形式避免 shell 注入
    
    Args:
        cmd_list: 命令列表，如 ['gcc', '-c', 'source.c', '-o', 'output.o']
                  或已拼接的字符串（将被安全解析）
    Returns:
        0 成功, -1 失败
    """
    if isinstance(cmd_list, str):
        # 如果传入字符串，使用 shlex.split 安全解析
        # 注意：shlex.split 会正确处理引号和转义
        cmd_list = shlex.split(cmd_list)
    
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            shell=False,  # 关键：禁用 shell 解析
            timeout=3600  # 添加超时保护
        )
        if result.returncode != 0:
            logging.error("execute command failed")
            logging.error("stdout: %s", result.stdout)
            logging.error("stderr: %s", result.stderr)
            return -1
        return 0
    except subprocess.TimeoutExpired:
        logging.error("command execution timeout")
        return -1
    except Exception as e:
        logging.error("command execution error: %s", e)
        return -1
```

**调用方修改**（移除 `' '.join()` 拼接）:

```python
# 修改前（第 252-254 行）
compile_cmd = ' '.join(gen_compile_cmd(args, dst, arch, opt))
if(exe_cmd(compile_cmd)) != 0:
    return -1

# 修改后
compile_cmd = gen_compile_cmd(args, dst, arch, opt)  # 直接传递列表
if exe_cmd(compile_cmd) != 0:
    return -1
```

**需要修改的所有位置**:
| 行号 | 原代码 | 修改后 |
|------|--------|--------|
| 252-253 | `compile_cmd = ' '.join(...)`, `exe_cmd(compile_cmd)` | `compile_cmd = gen_compile_cmd(...)`, `exe_cmd(compile_cmd)` |
| 263-264 | 同上 | 同上 |
| 274-275 | 同上 | 同上 |
| 283-284 | 同上 | 同上 |
| 293-294 | 同上 | 同上 |
| 301-302 | 同上 | 同上 |
| 308-309 | 同上 | 同上 |
| 314-315 | 同上 | 同上 |
| 323-324 | `link_cmd = ' '.join(...)`, `exe_cmd(link_cmd)` | `link_cmd = gen_fatbin_cmd(...)`, `exe_cmd(link_cmd)` |

### 修复方案 2: 参数验证 + shlex.quote

如果必须保持 `os.system()`（不推荐），至少要对参数进行转义：

```python
import shlex

def gen_compile_cmd_safe(args, dst: str, sub_arch: str, compile_options):
    """生成安全的编译命令列表，所有用户输入都经过转义"""
    # 转义用户可控参数
    safe_srcs = shlex.quote(args.srcs)
    safe_dst = shlex.quote(dst)
    safe_kernel = shlex.quote(args.kernel)
    safe_code_root = shlex.quote(args.code_root)
    
    compile_cmd = [
        shlex.quote(os.path.join(args.code_root, '3rdparty', 'compiler', 'ccec_compiler', 'bin', 'ccec')),
        '-c'
    ]
    
    # ... 其余代码使用 safe_* 变量
    
    return compile_cmd
```

**注意**: 方案 2 仍然存在风险，建议采用方案 1。

### 修复方案 3: 输入验证白名单

对特定参数进行白名单验证：

```python
import re

def validate_soc(soc: str) -> bool:
    """验证 soc 参数"""
    allowed_socs = ['ascend310p', 'ascend910', 'ascend910b', 'ascend310b', 'ascend950']
    return soc in allowed_socs

def validate_channel(channel: str) -> bool:
    """验证 channel 参数"""
    allowed_channels = ['vector', 'cube', 'mix']
    return channel in allowed_channels

def validate_path(path: str) -> bool:
    """验证路径参数 - 不包含 shell 元字符"""
    # 禁止危险字符
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r']
    return not any(char in path for char in dangerous_chars)

def validate_kernel_name(kernel: str) -> bool:
    """验证内核名称 - 只允许字母数字和下划线"""
    return bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', kernel))

def parse_args():
    parser = argparse.ArgumentParser()
    # ... 参数定义
    
    args = parser.parse_args()
    
    # 验证参数
    if not validate_soc(args.soc):
        parser.error(f"Invalid soc value: {args.soc}")
    if not validate_channel(args.channel):
        parser.error(f"Invalid channel value: {args.channel}")
    if not validate_path(args.srcs):
        parser.error(f"Invalid srcs path: security violation")
    if not validate_path(args.dst):
        parser.error(f"Invalid dst path: security violation")
    if not validate_path(args.code_root):
        parser.error(f"Invalid code_root path: security violation")
    if not validate_kernel_name(args.kernel):
        parser.error(f"Invalid kernel name: {args.kernel}")
    if args.include_directories:
        for dir in args.include_directories:
            if not validate_path(dir):
                parser.error(f"Invalid include_directory path: security violation")
    
    return args
```

### 完整修复代码示例

```python
#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# ... (版权声明)

import argparse
import json
import os
import re
import stat
import logging
import subprocess
import shlex
from typing import List


def validate_soc(soc: str) -> bool:
    """验证 soc 参数"""
    allowed_socs = ['ascend310p', 'ascend910', 'ascend910b', 'ascend310b', 'ascend950']
    return soc in allowed_socs


def validate_channel(channel: str) -> bool:
    """验证 channel 参数"""
    allowed_channels = ['vector', 'cube', 'mix']
    return channel in allowed_channels


def validate_path(path: str) -> bool:
    """验证路径 - 检查 shell 元字符"""
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r', '\x00']
    return not any(char in path for char in dangerous_chars)


def validate_kernel_name(kernel: str) -> bool:
    """验证内核名称 - 只允许安全的标识符"""
    return bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', kernel))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--soc', type=str, required=True)
    parser.add_argument('--channel', type=str, required=True)
    parser.add_argument('--srcs', type=str, required=True)
    parser.add_argument('--dst', type=str, required=True)
    parser.add_argument('--code_root', type=str, required=True)
    parser.add_argument('--kernel', type=str, required=True)
    parser.add_argument('--use_msdebug', type=str)
    parser.add_argument('--use_mssanitizer', type=str, required=True)
    parser.add_argument('--no_warning', action='store_true')
    parser.add_argument('--include_directories', type=str, required=False, nargs="+")
    parser.add_argument('--use_ascendc_dump', action='store_true')
    
    args = parser.parse_args()
    
    # 参数安全验证
    if not validate_soc(args.soc):
        parser.error(f"Invalid --soc value: {args.soc}. Allowed: ascend310p, ascend910, ascend910b, ascend310b, ascend950")
    if not validate_channel(args.channel):
        parser.error(f"Invalid --channel value: {args.channel}. Allowed: vector, cube, mix")
    if not validate_path(args.srcs):
        parser.error("Invalid --srcs path: contains dangerous characters")
    if not validate_path(args.dst):
        parser.error("Invalid --dst path: contains dangerous characters")
    if not validate_path(args.code_root):
        parser.error("Invalid --code_root path: contains dangerous characters")
    if not validate_kernel_name(args.kernel):
        parser.error(f"Invalid --kernel name: {args.kernel}. Must be a valid identifier")
    if args.include_directories:
        for dir in args.include_directories:
            if not validate_path(dir):
                parser.error(f"Invalid --include_directories path: contains dangerous characters")
    
    return args


def exe_cmd(cmd_list: List[str]) -> int:
    """
    安全执行命令 - 使用 subprocess 避免 shell 注入
    
    Args:
        cmd_list: 命令列表形式，如 ['gcc', '-c', 'source.c']
    
    Returns:
        0 成功, -1 失败
    """
    if not isinstance(cmd_list, list):
        logging.error("cmd_list must be a list, not a string")
        return -1
    
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            shell=False,  # 关键：禁用 shell
            timeout=3600,
            check=False
        )
        
        if result.returncode != 0:
            logging.error("execute command failed")
            logging.error("command: %s", ' '.join(cmd_list))
            if result.stderr:
                logging.error("stderr: %s", result.stderr)
            return -1
        
        logging.debug("command executed successfully: %s", ' '.join(cmd_list))
        return 0
        
    except subprocess.TimeoutExpired:
        logging.error("command execution timeout (>3600s)")
        return -1
    except FileNotFoundError as e:
        logging.error("command not found: %s", e)
        return -1
    except Exception as e:
        logging.error("command execution error: %s", e)
        return -1


# ... gen_compile_cmd 等函数保持不变，返回列表而非字符串 ...


def compile_ascendc_operation(args):
    dsts = []
    kernels = []
    options = get_common_options(args)
    arch = get_arch(args.soc, args.channel)
    compile_cmd = []  # 初始化为列表
    link_cmd = []
    ascend_home_path = os.getenv("ASCEND_HOME_PATH", "ASCEND_HOME_PATH does not exist.")
    mssanitizer_path = os.path.join(ascend_home_path, "tools", "mssanitizer", "lib64")

    if arch == "None":
        return -1
    
    tiling_key_ids = get_tiling_key_ids(args.srcs)
    logging.debug("tiling_key_ids: %s", tiling_key_ids)
    
    for key in tiling_key_ids:
        if args.soc == "ascend310p" or args.soc == "ascend910":
            dst = os.path.splitext(args.dst)[0] + f"_{key}.o"
            opt = options + [f'-D{args.kernel}={args.kernel}_{key}', f'-DTILING_KEY_VAR={key}']
            compile_cmd = gen_compile_cmd(args, dst, arch, opt)  # 直接使用列表
            if exe_cmd(compile_cmd) != 0:
                return -1
            dsts.append(dst)
            # ... 其余代码同理修改 ...
    
    # 链接命令
    link_cmd = gen_fatbin_cmd(args, dsts, args.dst)  # 直接使用列表
    if exe_cmd(link_cmd) != 0:
        return -1
    
    gen_json(args, kernels)
    return 0


if __name__ == '__main__':
    input_args = parse_args()
    output_dir = os.path.dirname(input_args.dst)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    res = compile_ascendc_operation(input_args)
    if res != 0:
        logging.error("compile ascend C failed!")
        exit(1)
```

## 修复优先级

| 优先级 | 修复项 | 工作量 | 风险降低 |
|--------|--------|--------|----------|
| **P0** | 替换 `os.system()` 为 `subprocess.run(shell=False)` | 中 | 95% |
| **P0** | 移除所有 `' '.join()` 拼接 | 中 | 配合 P0 |
| **P1** | 添加参数验证白名单 | 低 | 90% (独立使用) |
| **P2** | 添加路径规范化和安全检查 | 低 | 额外防护 |

## 总结

本漏洞是典型的 **OS Command Injection** 漏洞，根因是使用不安全的 `os.system()` 执行由用户输入拼接的命令字符串。攻击者可通过多种路径（CMake 配置、命令行参数）注入 shell 元字符，实现任意命令执行。

**关键修复措施**:
1. 使用 `subprocess.run()` 替代 `os.system()`
2. 设置 `shell=False` 禁用 shell 解析
3. 移除命令字符串拼接，直接传递列表
4. 添加输入验证白名单作为深度防御

**测试建议**:
修复后应使用包含各种 shell 元字符的测试用例验证安全性，确保无法注入命令。
