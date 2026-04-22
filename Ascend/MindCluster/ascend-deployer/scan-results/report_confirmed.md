# 漏洞扫描报告 — 已确认漏洞

**项目**: ascend-deployer
**扫描时间**: 2025-04-21T06:15:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 9 | 50.0% |
| POSSIBLE | 5 | 27.8% |
| FALSE_POSITIVE | 4 | 22.2% |
| **总计** | **18** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞


---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@ascend_deployer/start_deploy.py` | cmdline | untrusted_local | CLI入口，接收用户命令行参数，包括--install、--upgrade、--check等参数，用户可控制安装包选择和部署行为 | CLI主入口，解析命令行参数并执行部署任务 |
| `_process_args@ascend_deployer/start_deploy.py` | cmdline | untrusted_local | 处理用户输入的命令行参数，直接用于控制Ansible执行 | 解析并处理CLI参数 |
| `run_playbook@ascend_deployer/jobs.py` | cmdline | semi_trusted | 通过Ansible playbook执行部署任务，tags参数来自用户CLI输入 | Ansible playbook执行入口 |
| `run@ascend_deployer/trans_excel_to_inventory.py` | file | untrusted_local | 解析用户提供的CSV/Excel文件，生成inventory配置，文件内容可包含IP地址、SSH凭证等敏感数据 | CSV/Excel转inventory配置入口 |
| `get_table_info@ascend_deployer/trans_excel_to_inventory.py` | file | untrusted_local | 读取用户CSV文件，解析为inventory配置数据 | CSV文件读取解析 |
| `parse@ascend_deployer/module_utils/inventory_file.py` | file | untrusted_local | 解析inventory_file配置文件，包含主机IP、SSH用户名密码等敏感信息 | Inventory配置文件解析入口 |
| `safe_eval@ascend_deployer/module_utils/inventory_file.py` | file | untrusted_local | 使用eval()执行表达式解析配置参数，虽有正则过滤但仍有潜在风险 | 配置参数表达式解析（含eval） |
| `download@ascend_deployer/downloader/download_util.py` | network | untrusted_network | 从远程HTTP/HTTPS服务器下载软件包，URL来自配置文件或用户输入 | 远程文件下载入口 |
| `urlopen@ascend_deployer/downloader/download_util.py` | network | untrusted_network | 打开远程URL获取内容，用于下载元数据和软件包信息 | HTTP请求入口 |
| `run_scp@ascend_deployer/library/scp.py` | network | semi_trusted | 执行SCP命令复制文件到远程主机，主机IP、用户名、密码来自Ansible模块参数 | SCP文件传输入口 |
| `run_ssh_cmd@ascend_deployer/large_scale_deploy/tools/spread_tool.py` | network | semi_trusted | 通过SSH在远程主机执行命令，包含主机IP和密码信息 | SSH命令执行入口 |
| `scp@ascend_deployer/large_scale_deploy/tools/spread_tool.py` | network | semi_trusted | 执行SCP命令传输文件，包含主机认证信息 | SCP传输入口 |
| `run_cmd@ascend_deployer/utils.py` | cmdline | semi_trusted | 执行shell命令的核心函数，参数可来自用户输入或配置，支持shell=True模式 | 通用命令执行函数（Popen） |
| `extract_zip@ascend_deployer/jobs.py` | file | untrusted_local | 解压ZIP文件，文件来自下载的软件包或用户提供的资源包 | ZIP文件解压入口 |
| `extract_tar@ascend_deployer/jobs.py` | file | untrusted_local | 解压TAR文件，文件来自下载的软件包 | TAR文件解压入口 |
| `run@ascend_deployer/library/uncompress_resources.py` | file | untrusted_local | 解压资源包tar文件到目标目录，文件路径来自Ansible模块参数 | 资源包解压入口 |
| `_run_cmd@ascend_deployer/library/install_cann.py` | cmdline | semi_trusted | 执行安装脚本的命令函数，脚本路径来自glob查找结果 | CANN安装命令执行入口 |
| `_run_cmd@ascend_deployer/library/install_sys_pkg.py` | cmdline | semi_trusted | 执行系统包安装命令（yum/apt），命令参数来自配置文件解析 | 系统包安装命令执行入口 |
| `_run_command@ascend_deployer/library/process_npu.py` | cmdline | semi_trusted | 执行NPU驱动/固件安装命令，脚本路径来自glob查找 | NPU安装命令执行入口 |
| `safe_read@ascend_deployer/module_utils/safe_file_handler.py` | file | untrusted_local | 安全文件读取函数，读取用户配置文件或下载的文件 | 文件读取入口 |
| `safe_write@ascend_deployer/module_utils/safe_file_handler.py` | file | trusted_admin | 安全文件写入函数，用于写入配置和日志文件 | 文件写入入口 |
| `main@ascend_deployer/large_scale_deployer.py` | cmdline | untrusted_local | 大规模部署CLI入口，处理大量主机的并行部署 | 大规模部署主入口 |

**其他攻击面**:
- CLI Arguments: 用户通过命令行参数控制安装包选择、场景配置、升级操作等
- Configuration Files: inventory_file, CSV/Excel模板文件包含主机IP、SSH凭证等敏感信息
- Download URLs: 从远程服务器下载软件包，URL来自配置文件
- Package Archives: ZIP/TAR软件包文件，包含安装脚本和二进制文件
- SSH Connections: 通过Ansible SSH连接远程主机执行部署任务
- Environment Variables: ASCEND_DEPLOYER_HOME, SSH_CLIENT等环境变量影响程序行为
- Ansible Playbooks: 通过YAML playbook定义部署流程，可能包含用户定制内容
- Excel/CSV Input Files: 用户提供的CSV模板文件，解析后生成inventory配置

---

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
