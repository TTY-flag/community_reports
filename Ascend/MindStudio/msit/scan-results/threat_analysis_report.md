# MindStudio Inference Tools (msIT) 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析由 AI 自主完成，未使用 threat.md 约束文件。

## 项目架构概览

MindStudio Inference Tools (msIT) 是华为昇腾 AI 推理开发工具链，提供模型压缩、调试与调优等能力。项目采用 Python CLI 工具架构，包含以下主要模块：

### 模块组成

| 模块 | 语言 | 功能 | 文件数 |
|------|------|------|--------|
| msit | Python | 核心推理工具（benchmark, debug, analyze, convert, profile, llm） | 100+ |
| msmodelslim | Mixed (Python + C++) | 模型压缩/量化工具 | 100+ |
| msprechecker | Python | 环境预检工具 | 85 |
| msserviceprofiler | Mixed (Python + C++) | 服务调优工具 | 100+ |
| msmodelslim_cpp | C/C++ | 权重压缩 C++ 扩展 | 6 (.cpp) + 8 (.h) |

### C/C++ 文件分布

- `msmodelslim/msmodelslim/pytorch/weight_compression/`: 4 个 .cpp + 4 个 .h
- `msserviceprofiler/include/msServiceProfiler/`: 4 个 .h
- `msit/components/llm/msit_llm/opcheck/`: 1 个 .cpp + 1 个 .h

### 项目定位

- **项目类型**: Python CLI 工具套件
- **部署模型**: 用户本地环境或服务器，通过 pip 安装后以命令行方式运行
- **典型用户**: AI 开发者、模型工程师

## 信任边界分析

### 边界 1: CLI Interface (Medium Risk)

| 属性 | 说明 |
|------|------|
| 可信侧 | 工具逻辑和内置验证函数 |
| 不可信侧 | 命令行参数（--model_path, --save_path, --config_path 等） |
| 风险 | 用户可控制文件路径，需验证防止路径遍历 |

### 边界 2: File System (High Risk)

| 属性 | 说明 |
|------|------|
| 可信侧 | 工具生成的输出文件 |
| 不可信侧 | 用户提供的模型文件、配置文件、校准数据集 |
| 风险 | 输入文件可能包含恶意数据或代码 |

### 边界 3: Subprocess Execution (High Risk)

| 属性 | 说明 |
|------|------|
| 可信侧 | 工具内部的命令构建逻辑 |
| 不可信侧 | 外部工具（atc, msprof, benchmark binaries）的参数 |
| 风险 | 参数验证不足可能导致命令注入 |

### 边界 4: Network Interface (Medium Risk)

| 属性 | 说明 |
|------|------|
| 可信侧 | 工具内部的 HTTP 请求逻辑 |
| 不可信侧 | vllm/MindIE 服务端响应 |
| 风险 | 请求目标被限制为 localhost 或内网，但验证逻辑可能存在绕过 |

## 模块风险评估

### Critical Risk 模块

| 模块 | 文件 | STRIDE 威胁 | 风险等级 |
|------|------|-------------|----------|
| 命令执行 | msmodelslim/msmodelslim/utils/security/shell.py | T, E | Critical |

**威胁分析**:
- **Tampering**: 命令参数篡改可能导致命令注入
- **Elevation of Privilege**: 通过命令注入可能执行任意代码

### High Risk 模块

| 模块 | 文件 | STRIDE 威胁 | 风险等级 |
|------|------|-------------|----------|
| 文件操作(C++) | msmodelslim/.../security/src/File.cpp | T, I | High |
| 反序列化 | msserviceprofiler/.../msguard/security/injection.py | T, E | High |
| 路径验证 | msit/components/utils/security_check.py | T | High |

**File.cpp 威胁分析**:
- **Tampering**: 路径参数可能导致目录遍历或权限绕过
- **Information Disclosure**: 文件权限验证不足可能导致敏感信息泄露

**injection.py 威胁分析**:
- **Tampering**: pickle 反序列化可能导致恶意代码执行
- **Elevation of Privilege**: 通过 SafeUnpickler 限制，但白名单可能不完整

### Medium Risk 模块

| 模块 | 文件 | STRIDE 威腾 | 风险等级 |
|------|------|-------------|----------|
| HTTP请求 | msmodelslim/.../utils/security/request.py | T, I | Medium |
| 网络检查 | msprechecker/msprechecker/utils/network.py | D | Medium |
| CLI入口 | msit/components/__main__.py | T | Medium |

## 攻击面分析

### 1. 命令注入攻击面

**入口点**: `msmodelslim/msmodelslim/utils/security/shell.py`

**数据流路径**:
```
用户参数 → build_safe_command_with_options() → validate_safe_identifier() → _run_cmd() → subprocess.run()
```

**现有防护**:
- `validate_safe_identifier()` 使用正则验证参数字符
- 使用 `shell=False` 防止 shell 元字符解析
- `shlex.split()` 正确处理引号

**潜在风险**:
- 正则表达式 `^[a-zA-Z0-9_\-./{}:",]+$` 可能允许某些危险字符
- 花括号 `{}` 可能被用于参数展开
- 双引号 `"` 可能被用于特殊构造

### 2. 文件路径攻击面

**入口点**: 多个 CLI 工具的 `--model_path`, `--save_path` 参数

**数据流路径**:
```
argparse → get_valid_read_path() → os.stat/os.access → 文件操作
argparse → get_valid_write_path() → check_write_directory() → 文件写入
```

**现有防护**:
- `PATH_WHITE_LIST_REGEX` 限制特殊字符
- `os.path.islink()` 检查软链接
- `is_belong_to_user_or_group()` 验证文件所有权
- 文件长度限制 (4096 字符)

**潜在风险**:
- 路径验证逻辑可能遗漏某些边缘情况
- 符号链接检查可能在某些场景下不够严格

### 3. Pickle 反序列化攻击面

**入口点**: `msserviceprofiler/msserviceprofiler/msguard/security/injection.py`

**数据流路径**:
```
pickle文件 → pickle_load_s() → SafeUnpickler.load() → find_class() → 白名单验证
```

**现有防护**:
- `SafeUnpickler` 类限制反序列化的类
- `default_safe_callback()` 白名单只允许基础类型
- 自定义 callback 函数支持

**潜在风险**:
- 白名单包含 numpy 和 pandas，这些库可能有自己的危险操作
- 如果用户提供自定义 callback，可能绕过限制

### 4. SSRF 攻击面

**入口点**: `msmodelslim/msmodelslim/utils/security/request.py`

**数据流路径**:
```
URL参数 → validate_safe_host() → socket.gethostbyname() → requests.get()
```

**现有防护**:
- 只允许 localhost, 127.0.0.1, ::1
- 内网 IP 检查 (RFC 1918: 10.x, 172.16-31.x, 192.168.x)
- 禁用重定向 (`allow_redirects=False`)

**潜在风险**:
- DNS 重绑定攻击可能绕过 IP 检查
- socket.gethostbyname() 可能被 DNS 欺骗影响

### 5. 模型加载攻击面

**入口点**: `--model_path` 参数 → `trust_remote_code=True`

**数据流路径**:
```
model_path → transformers.load_model → trust_remote_code → 执行模型代码
```

**现有防护**:
- 默认 `trust_remote_code=False`
- 用户需显式启用

**潜在风险**:
- 用户可能被诱导使用 `--trust_remote_code=True`
- 模型代码可能包含恶意操作

## STRIDE 威胁建模

### Spoofing (欺骗)

| 威胁 | 影响 | 防护措施 |
|------|------|----------|
| 模型文件身份伪造 | 加载恶意模型代码 | trust_remote_code 默认禁用 |
| DNS 欺骗影响 SSRF 检查 | 访问非预期地址 | IP 地址双重验证 |

### Tampering (篡改)

| 娇胁 | 影响 | 防护措施 |
|------|------|----------|
| 命令参数篡改 | 命令注入攻击 | 正则验证, shell=False |
| 文件路径篡改 | 目录遍历攻击 | 软链接检查, 路径白名单 |
| Pickle 数据篡改 | 反序列化攻击 | SafeUnpickler 白名单 |
| CSV 数据篡改 | CSV 注入攻击 | sanitize_csv_value() |

### Repudiation (抵赖)

| 威胁 | 影响 | 防护措施 |
|------|------|----------|
| 工具执行无日志 | 无法追溯操作 | 建议添加审计日志 |

### Information Disclosure (信息泄露)

| 威胁 | 影响 | 防护措施 |
|------|------|----------|
| 敏感文件读取 | 配置/权重泄露 | 文件权限验证 |
| 错误消息泄露路径 | 路径信息泄露 | 错误消息不包含完整路径 |

### Denial of Service (拒绝服务)

| 威胁 | 影响 | 防护措施 |
|------|------|----------|
| 大文件读取 | 内存耗尽 | 文件大小限制 (4G/32G) |
| 网络请求超时 | 工具卡死 | 默认 timeout=3.0 |
| 无限递归路径检查 | 栈溢出 | max_depth=200 限制 |

### Elevation of Privilege (权限提升)

| 威胁 | 影响 | 防护措施 |
|------|------|----------|
| 命令注入 | 执行任意命令 | validate_safe_identifier() |
| Pickle 反序列化 | 任意代码执行 | SafeUnpickler 白名单 |
| trust_remote_code | 模型代码执行 | 默认禁用, 需显式启用 |
| root 权限运行 | 权限过大 | cli.py 检查 os.geteuid() == 0 并警告 |

## 安全加固建议（架构层面）

### 1. 命令执行安全

- **建议**: 在 `validate_safe_identifier()` 正则中移除花括号 `{}` 和双引号 `"`
- **建议**: 添加命令白名单，只允许预定义的命令执行
- **建议**: 记录所有 subprocess 调用的审计日志

### 2. 文件路径安全

- **建议**: 在 `get_valid_path()` 中添加 `..` 检查
- **建议**: 使用 `os.path.normpath()` 规范化路径后再验证
- **建议**: 对敏感文件操作添加二次验证

### 3. Pickle 反序列化安全

- **建议**: 在 `SafeUnpickler` 白名单中移除 numpy.ndarray（可能触发危险操作）
- **建议**: 强制要求用户提供自定义 callback，禁用默认 callback
- **建议**: 添加 pickle 数据签名验证机制

### 4. SSRF 防护

- **建议**: 添加 DNS 缓存，防止 DNS 重绑定攻击
- **建议**: 在请求前和请求后双重验证 IP 地址
- **建议**: 添加请求内容大小限制

### 5. 模型加载安全

- **建议**: 当 `trust_remote_code=True` 时，扫描模型代码中的危险模式
- **建议**: 添加沙箱机制隔离模型代码执行
- **建议**: 在加载前验证模型文件的签名

### 6. 日志与审计

- **建议**: 添加操作审计日志，记录所有文件读写和命令执行
- **建议**: 添加敏感操作告警机制

---

**报告生成时间**: 2026-04-21  
**分析工具**: Architecture Agent  
**下一步**: 启动 DataFlow Scanner 和 Security Auditor 进行深度漏洞扫描