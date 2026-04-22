# 威胁分析报告 - ascend-deployer

## 项目概述

| 属性 | 值 |
|------|-----|
| 项目名称 | ascend-deployer |
| 项目类型 | CLI工具 (Python) |
| 项目定位 | 华为Ascend NPU硬件部署工具 |
| 语言 | Python 3.6+ |
| 文件数量 | 131个Python文件 |
| 代码行数 | ~19,927行 |
| 扫描时间 | 2025-04-21 |

## 项目简介

ascend-deployer是华为Ascend NPU（神经网络处理器）的离线部署工具，用于在Linux服务器上安装和管理Ascend软件栈，包括：
- CANN (Compute Architecture for Neural Networks)
- NPU驱动和固件
- MindSpore/TensorFlow/PyTorch AI框架
- Kubernetes设备插件和容器运行时
- 大规模分布式部署

该项目主要通过Ansible进行自动化部署，支持单机和大规模并行部署模式。

---

## 攻击面分析

### 1. CLI命令行接口 (Critical)

**入口文件**: `ascend_deployer/start_deploy.py`

**描述**: 主CLI入口接收用户命令行参数，控制整个部署流程。

**可达路径**:
```
sys.argv → CLI._process_args() → CLI._run_handler() → AnsibleJob.run_playbook()
```

**风险点**:
- 用户输入的`--install`、`--upgrade`、`--scene`等参数直接传递给Ansible
- 参数值用于选择安装包和执行特定任务
- 无充分的输入验证，用户可控制安装行为

**STRIDE分析**:
- **Tampering**: 用户可通过命令行参数篡改安装流程，选择安装恶意包
- **Elevation of Privilege**: 通过`--install`执行系统级安装操作

---

### 2. Inventory配置文件解析 (Critical)

**入口文件**: `ascend_deployer/module_utils/inventory_file.py`

**描述**: 解析用户提供的inventory配置文件，包含主机IP、SSH用户名密码等信息。

**高风险函数**: `StrTool.safe_eval()` (第50行)

**可达路径**:
```
inventory_file → InventoryFile.parse() → HostParams.generate_new_params_str_list() 
→ StrTool.safe_eval() → eval()
```

**风险点**:
```python
def safe_eval(cls, expr):
    if not re.fullmatch(cls._FURMULA_PATTERN, expr):
        raise ValueError("unsafe expression: {}".format(expr))
    return str(eval(expr, cls._SAFE_EVAL_SCOPE))
```
- 使用`eval()`执行表达式，虽有正则过滤`r'^[\w\s\.\+\-\*\/\(\)\'"]+$'`
- `__builtins__`被设置为`None`，但仍可能存在绕过方式
- 表达式来自inventory配置文件中的参数字段

**STRIDE分析**:
- **Tampering**: 通过构造特殊表达式可能执行任意代码
- **Elevation of Privilege**: eval执行可导致代码注入

**建议**: 使用`ast.literal_eval()`替代`eval()`，或实现完全安全的表达式解析器。

---

### 3. CSV/Excel文件解析 (High)

**入口文件**: `ascend_deployer/trans_excel_to_inventory.py`

**描述**: 从用户提供的CSV模板文件读取主机配置信息，生成inventory文件。

**可达路径**:
```
CSV file → InventoryInfo.get_table_info() → csv.reader() → HostInfo → inventory_file
```

**风险点**:
- CSV文件包含IP地址、SSH用户名、密码等敏感信息
- IP验证使用`ipaddress.ip_address()`，但有边界情况未覆盖
- SSH密码直接写入inventory文件，无加密处理

**STRIDE分析**:
- **Spoofing**: 伪造CSV文件中的主机信息，连接到恶意服务器
- **Information Disclosure**: 密码以明文写入inventory文件

---

### 4. 远程文件下载 (High)

**入口文件**: `ascend_deployer/downloader/download_util.py`

**描述**: 从远程HTTP/HTTPS服务器下载软件包。

**高风险函数**:
- `DownloadUtil.download()` (第305行)
- `DownloadUtil.urlopen()` (第361行)

**可达路径**:
```
URL(config file) → DownloadUtil.download() → request.urlretrieve() → local_file
```

**风险点**:
- URL来自配置文件`downloader/config.ini`或环境变量
- SSL验证可配置关闭 (`verify = False`)
- 无完整性验证强制要求（SHA256可选）
- 下载文件直接用于安装

**STRIDE分析**:
- **Tampering**: 通过中间人攻击篡改下载的软件包
- **Spoofing**: 伪造下载服务器提供恶意软件包

---

### 5. SSH/SCP命令执行 (Critical)

**入口文件**: 
- `ascend_deployer/library/scp.py` (Ansible模块)
- `ascend_deployer/large_scale_deploy/tools/spread_tool.py`

**描述**: 通过SSH/SCP在远程主机执行命令和传输文件。

**高风险函数**:
- `Scp._run_cmd()` (scp.py:69)
- `run_ssh_cmd()` (spread_tool.py:162)
- `scp()` (spread_tool.py:174)

**可达路径**:
```
AnsibleModule.params → Scp.run_scp() → shlex.split() → subprocess.Popen(scp command)
```

**风险点**:
```python
ssh_cmd = f"{sshpass_cmd}ssh -o StrictHostKeyChecking=no {account_}{host_info.ip} '{cmd}'"
```
- 使用`StrictHostKeyChecking=no`禁用SSH主机密钥验证
- 命令通过字符串拼接构建，虽有`shlex.split()`处理
- 主机IP和密码来自Ansible模块参数

**STRIDE分析**:
- **Spoofing**: 通过伪造inventory中的主机IP，连接到恶意服务器
- **Tampering**: 通过SSH执行任意命令篡改远程系统

---

### 6. Ansible模块命令执行 (Critical)

**入口文件**: `ascend_deployer/library/` 目录下的安装模块

**涉及文件**:
- `install_cann.py` - CANN安装
- `install_sys_pkg.py` - 系统包安装
- `process_npu.py` - NPU驱动/固件安装
- `uncompress_resources.py` - 资源包解压

**高风险函数**:
- `CANNInstaller._run_cmd()` (install_cann.py:432)
- `SysInstaller._run_cmd()` (install_sys_pkg.py:291)
- `NpuInstallation._run_command()` (process_npu.py:92)

**可达路径**:
```
AnsibleModule.params(resources_dir, pkg_name) → glob.glob() → script_path 
→ _run_cmd("bash {script}") → subprocess.Popen()
```

**风险点**:
- 安装脚本路径通过`glob.glob()`查找，文件名来自用户放置的资源目录
- 直接执行`.run`或`.sh`脚本文件
- 使用`AnsibleModule.run_command(..., use_unsafe_shell=True)`
- 脚本参数来自Ansible模块参数

**STRIDE分析**:
- **Tampering**: 放置恶意脚本文件，通过glob匹配被执行
- **Elevation of Privilege**: 以root权限执行安装脚本

---

### 7. ZIP/TAR文件解压 (High)

**入口文件**:
- `ascend_deployer/jobs.py` (ResourcePkg类)
- `ascend_deployer/library/uncompress_resources.py`
- `ascend_deployer/module_utils/path_manager.py` (CompressedFileCheckUtils)

**描述**: 解压下载或用户提供的软件包。

**安全检查**:
```python
# CompressedFileCheckUtils.check_package_inner_file_name()
check_str_list = ["../", "..\\", ".\\", "./", "~/"]
```

**风险点**:
- 有路径遍历检查（检查`../`等）
- 有符号链接检查（检查`.issym()`）
- 但白名单目录允许特定路径绕过检查 (`WHITELIST_DIRS`)
- 解压后的文件权限被设置为`member.mode &= ~0o022`

**STRIDE分析**:
- **Tampering**: 通过Zip Slip攻击覆盖系统文件（已有检查但需验证完整性）
- **Elevation of Privilege**: 解压后的脚本可能被提权执行

---

### 8. 系统命令执行核心函数 (Critical)

**入口文件**: `ascend_deployer/utils.py`

**高风险函数**: `run_cmd()` (第297行)

**描述**: 项目核心命令执行函数，被多处调用。

**代码分析**:
```python
def run_cmd(args, oneline=False, **kwargs):
    if not kwargs.get('shell') and isinstance(args, str):
        args = shlex.split(args, posix=platform.system() == 'Linux')
    process = Popen(args, stdout=stdout, stderr=stderr, ...)
```

**风险点**:
- 使用`subprocess.Popen()`执行命令
- 支持`shell=True`模式（通过kwargs传递）
- 参数来自多种来源：CLI参数、配置文件、Ansible模块参数
- 使用`shlex.split()`进行分词处理，但原始字符串可能已包含危险字符

**调用关系**:
- `PrepareJob.pip_install()`
- `PrepareJob.install_ansible()`
- `AnsibleJob.run_playbook()`
- `install_pkg()`
- `ResourcePkg.verify_cms()`
- `start_nexus()`

---

## 信任边界分析

| 边界 | 可信侧 | 不可信侧 | 风险等级 |
|------|--------|----------|----------|
| CLI Interface | 应用逻辑 | 用户输入(命令参数、配置文件) | High |
| Network Interface (Download) | 应用逻辑 | 远程HTTP服务器 | High |
| SSH/Ansible Interface | 本地控制器 | 远程NPU节点 | Medium |
| File System Interface | 应用逻辑 | 外部文件(ZIP/TAR、CSV) | High |
| Inventory Configuration | Ansible引擎 | 用户提供的inventory_file | Medium |

---

## 高风险模块列表

### Critical级模块

| 模块 | 文件 | 主要风险 |
|------|------|----------|
| entry_points | start_deploy.py | CLI参数处理，无充分验证 |
| entry_points | jobs.py | Ansible playbook执行，命令拼接 |
| entry_points | utils.py | 核心命令执行函数Popen |
| library | scp.py | SSH/SCP命令执行，密码传递 |
| library | install_cann.py | 安装脚本执行，glob路径查找 |
| library | install_sys_pkg.py | yum/apt命令执行 |
| library | process_npu.py | NPU驱动安装，root执行 |
| large_scale_deploy | spread_tool.py | SSH命令执行，密码在命令行 |
| module_utils | inventory_file.py | eval()代码执行 |

### High级模块

| 模块 | 文件 | 主要风险 |
|------|------|----------|
| downloader | download_util.py | 远程文件下载，SSL验证可关闭 |
| downloader | downloader.py | 软件包下载入口 |
| library | uncompress_resources.py | TAR文件解压 |
| module_utils | path_manager.py | 压缩文件安全检查（有白名单） |
| entry_points | trans_excel_to_inventory.py | CSV解析，密码明文存储 |

---

## 数据流风险路径

### 1. 命令注入路径
```
CLI参数 → AnsibleJob.run_playbook() → run_cmd() → subprocess.Popen()
```
**风险**: 用户可控参数直接传递给Ansible playbook执行。

### 2. 代码执行路径
```
inventory_file → StrTool.safe_eval() → eval()
```
**风险**: 配置文件中的表达式通过eval执行，存在代码注入风险。

### 3. 远程命令执行路径
```
inventory_file(IP/password) → SSH connection → run_ssh_cmd() → subprocess.Popen()
```
**风险**: SSH密码通过命令行传递给sshpass，主机密钥验证被禁用。

### 4. 供应链攻击路径
```
Config URL → DownloadUtil.download() → 本地文件 → 解压 → 安装脚本执行
```
**风险**: 下载的软件包可能被篡改，直接用于安装。

---

## STRIDE威胁模型

### Spoofing (身份伪造)
- 伪造inventory中的主机IP，通过SSH连接到恶意服务器
- 伪造下载服务器URL，提供恶意软件包
- SSH主机密钥验证被禁用，无法验证服务器身份

### Tampering (数据篡改)
- 命令行参数篡改安装流程
- 配置文件篡改安装包路径
- 中间人攻击篡改下载的软件包
- 恶意脚本替换正常安装脚本

### Repudiation (抵赖)
- 无完整的操作审计日志
- 部署结果日志可能被删除

### Information Disclosure (信息泄露)
- SSH密码以明文写入inventory文件
- CSV文件包含敏感凭证信息
- 日志文件可能包含敏感操作记录

### Denial of Service (拒绝服务)
- 无资源限制检查，可能导致系统资源耗尽
- 大规模部署可能导致网络拥塞

### Elevation of Privilege (权限提升)
- 以root权限执行安装脚本
- eval()代码执行可能导致权限提升
- 安装软件包可能修改系统配置

---

## 安全建议

### 1. 命令执行安全
- 使用`subprocess.run()`替代`Popen()`，避免shell=True
- 对所有命令参数进行严格验证和白名单过滤
- 使用参数化方式传递命令参数，避免字符串拼接

### 2. 配置文件解析安全
- 使用`ast.literal_eval()`替代`eval()`
- 实现完全安全的表达式解析器
- 对inventory配置文件进行严格的格式验证

### 3. 网络通信安全
- 强制启用SSL证书验证
- 实现软件包完整性验证（强制SHA256校验）
- 启用SSH主机密钥验证

### 4. 文件处理安全
- 强制执行路径遍历检查（移除白名单）
- 对解压后的文件进行权限限制
- 实现文件来源验证

### 5. 凭证管理
- 使用加密存储SSH密码
- 支持SSH密钥认证替代密码认证
- 实现凭证轮换机制

### 6. 日志与审计
- 实现完整的操作审计日志
- 日志文件应设置适当的权限
- 记录所有安全相关事件

---

## 扫描范围建议

### 必须扫描的文件 (Critical)

1. `ascend_deployer/start_deploy.py` - CLI入口
2. `ascend_deployer/jobs.py` - Ansible执行核心
3. `ascend_deployer/utils.py` - 命令执行核心
4. `ascend_deployer/library/scp.py` - SSH/SCP执行
5. `ascend_deployer/library/install_cann.py` - CANN安装
6. `ascend_deployer/library/install_sys_pkg.py` - 系统包安装
7. `ascend_deployer/library/process_npu.py` - NPU安装
8. `ascend_deployer/large_scale_deploy/tools/spread_tool.py` - SSH命令执行
9. `ascend_deployer/module_utils/inventory_file.py` - eval()执行

### 建议扫描的文件 (High)

10. `ascend_deployer/downloader/download_util.py` - 文件下载
11. `ascend_deployer/downloader/downloader.py` - 下载入口
12. `ascend_deployer/library/uncompress_resources.py` - 文件解压
13. `ascend_deployer/module_utils/path_manager.py` - 压缩文件检查
14. `ascend_deployer/trans_excel_to_inventory.py` - CSV解析

---

## 结论

ascend-deployer是一个复杂的部署工具，存在多个高风险攻击面：

1. **最严重风险**: `inventory_file.py`中的`eval()`代码执行漏洞，可导致任意代码执行
2. **高风险**: 多处命令执行函数使用`subprocess.Popen()`，参数来自用户可控输入
3. **高风险**: SSH连接禁用主机密钥验证，存在服务器伪造风险
4. **高风险**: 远程文件下载缺乏强制完整性验证
5. **中风险**: ZIP/TAR解压有安全检查但存在白名单绕过

建议按照上述优先级进行漏洞扫描和修复。重点关注代码执行、命令注入和数据篡改类漏洞。

---

*报告生成时间: 2025-04-21*
*扫描工具: OpenCode Architecture Agent*