# MindStudio-Modeling 威胁分析报告

## 执行摘要

MindStudio-Modeling 是一个 AI 模型推理框架项目，用于模拟和分析 LLM/扩散模型的推理性能。本项目识别了 **5 个关键攻击面**，发现 **2 个 Critical 级别漏洞路径** 和 **3 个 High 级别漏洞路径**。

### 关键发现

| 风险级别 | 漏洞类型 | CWE | 关键路径 |
|---------|---------|-----|---------|
| **Critical** | 远程代码执行 | CWE-94 | CLI model_id → trust_remote_code |
| **Critical** | 远程代码执行 | CWE-94 | AutoConfig/AutoModel from_pretrained |
| **High** | 命令注入 | CWE-78 | check_dependencies → subprocess |
| **High** | 路径遍历 | CWE-22 | Config file → YAML loading |
| **High** | 路径遍历 | CWE-22 | Video model path → config.json |
| **Medium** | 路径遍历 | CWE-22 | Chrome trace output |

---

## 项目架构概述

### 模块结构

```
MindStudio-Modeling/
├── cli/                    # CLI 入口点 (Critical Risk)
│   └── inference/
│       ├── text_generate.py   # 文本推理 CLI
│       ├── video_generate.py  # 视频推理 CLI
│       └── throughput_optimizer.py
├── tensor_cast/            # 核心推理逻辑 (Critical Risk)
│   ├── core/
│   │   ├── model_runner.py    # 模型运行器
│   │   ├── model_builder.py   # 模型构建器
│   │   ├── config_resolver.py # 配置解析器
│   │   ├── user_config.py     # 用户配置
│   │   └── input_generator.py # 输入生成器
│   ├── transformers/
│   │   ├── model.py           # Transformer 模型封装
│   │   ├── utils.py           # AutoModelConfigLoader (⚠️ RCE)
│   │   └── custom_model_registry.py
│   ├── diffusers/
│   │   └── diffusers_model.py # Diffusers 模型加载
│   ├── runtime.py             # 运行时模拟
│   └── utils.py               # 依赖检查 (⚠️ Command Injection)
├── serving_cast/           # 服务层 (High Risk)
│   ├── config.py              # YAML 配置加载 (⚠️ Path Traversal)
│   ├── model_runner.py
│   ├── instance.py
│   └── parallel_runner.py
├── tools/linter/           # Linter 工具 (High Risk)
│   └── adapters/
│       ├── pip_init.py        # pip 安装 (⚠️ Command Injection)
│       ├── ruff_linter.py
│       └── flake8_linter.py
└── tests/                  # 测试文件 (Low Risk)
```

### 攻击面分析

#### 1. CLI 入口点 (Critical Risk)

**入口文件：**
- `cli/inference/text_generate.py:23` - `main()`
- `cli/inference/video_generate.py:313` - `main()`

**用户可控输入：**
- `model_id`: 用户指定的模型标识符，可以是：
  - HuggingFace 模型 ID (如 `meta-llama/Llama-2-7b-hf`)
  - 本地目录路径
  - ModelScope 远程 ID
- `device`: 设备类型选择
- `graph_log_url`: 编译图日志输出路径
- `chrome_trace`: Chrome trace 输出路径
- `profiling_database`: 性能数据库路径

**攻击向量：**
用户可以通过 `model_id` 参数：
1. 指定恶意模型仓库（包含恶意 `config.json` 和 `modeling_*.py`）
2. 指定包含恶意代码的本地路径
3. 利用 `trust_remote_code=True` 执行任意代码

---

## 关键漏洞路径详解

### PATH-001: CLI model_id → Remote Code Execution (Critical)

**CWE-94: Improper Control of Generation of Code ('Code Injection')**

**数据流路径：**

```
[SOURCE] cli/inference/text_generate.py:255
    args.model_id (argparse 命令行参数)
    ↓
[PROPAGATION] tensor_cast/core/user_config.py:29
    UserInputConfig.model_id = args.model_id
    ↓
[PROPAGATION] tensor_cast/core/config_resolver.py:60
    ConfigResolver.model_id = user_input.model_id
    ↓
[CALL] tensor_cast/transformers/utils.py:256
    AutoConfig.from_pretrained(model_id)  // 尝试原生加载
    ↓
[SINK] tensor_cast/transformers/utils.py:259  ⚠️ CRITICAL
    AutoConfig.from_pretrained(model_id, trust_remote_code=True)
    // 当原生加载失败时，启用 trust_remote_code=True
    // HuggingFace 会下载并执行 model_id 仓库中的 Python 代码
```

**漏洞分析：**

代码位于 `tensor_cast/transformers/utils.py:255-272`：

```python
try:
    hf_config = AutoConfig.from_pretrained(model_id)
    self.is_transformers_natively_supported = True
except Exception:
    hf_config = AutoConfig.from_pretrained(model_id, trust_remote_code=True)
    // ⚠️ 当模型类型不被 transformers 原生支持时，
    // 自动启用 trust_remote_code=True，允许执行远程代码
```

**攻击场景：**

1. 攻击者创建恶意 HuggingFace 模型仓库，包含：
   - `config.json` - 模型配置
   - `modeling_malicious.py` - 包含恶意代码的模型实现
   
2. 用户运行：
   ```bash
   python -m cli.inference.text_generate attacker/malicious-model \
       --num-queries 1 --query-length 128
   ```

3. 由于 `malicious-model` 不是 transformers 原生支持的模型类型，
   `trust_remote_code=True` 会自动启用

4. `modeling_malicious.py` 中的代码在加载时被执行

**影响：** 完全的远程代码执行，攻击者可以：
- 读取敏感文件
- 执行任意系统命令
- 安装恶意软件
- 窃取用户数据

---

### PATH-002: Dependency Check Command Injection (High)

**CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')**

**数据流路径：**

```
[CALL] cli/inference/text_generate.py:24
    check_dependencies()
    ↓
[SOURCE] tensor_cast/utils.py:182
    importlib.metadata.version("transformers")
    // 检查 transformers 版本
    ↓
[SINK] tensor_cast/utils.py:196  ⚠️ HIGH
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", f"{pkg}=={target_ver}"]
    )
    // 自动执行 pip install transformers==5.3.0
```

**漏洞分析：**

代码位于 `tensor_cast/utils.py:175-198`：

```python
def check_dependencies():
    pkg = "transformers"
    target_ver = "5.3.0"
    
    try:
        curr_ver = importlib.metadata.version(pkg)
        curr_tup = tuple(map(int, curr_ver.split(".")[:3]))
        req_tup = tuple(map(int, target_ver.split(".")[:3]))
        if curr_tup >= req_tup:
            return
    except importlib.metadata.PackageNotFoundError:
        curr_ver = None
    
    print("WARNING: Incompatible transformers version detected")
    print("Automatically upgrading now...")
    
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", f"{pkg}=={target_ver}"]
    )
```

**风险分析：**

- 虽然 `pkg` 和 `target_ver` 是硬编码的，但：
  - 在用户环境中自动执行 pip 安装
  - 可能被恶意环境劫持（如 `sys.executable` 被替换）
  - 在 CI/CD 环境中可能导致供应链攻击

- 相关工具代码 `tools/linter/adapters/pip_init.py` 允许用户指定任意包名：
  ```python
  parser.add_argument("packages", nargs="+", help="pip packages to install")
  run_command(pip_args, env=env)  // subprocess.run
  ```

---

### PATH-003: Config File Path Traversal (High)

**CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')**

**数据流路径：**

```
[SOURCE] serving_cast/config.py:96
    parsed_args.instance_config_path (命令行参数)
    ↓
[SINK] serving_cast/config.py:109  ⚠️ HIGH
    open(path, encoding="utf-8")
    // 直接打开用户指定的配置文件路径
    ↓
[SINK] serving_cast/config.py:110
    yaml.safe_load(f)
    // 加载 YAML 内容（safe_load 防止反序列化 RCE）
```

**漏洞分析：**

代码位于 `serving_cast/config.py:108-116`：

```python
@staticmethod
def _parse_common_config(path: str) -> CommonConfig:
    with open(path, encoding="utf-8") as f:
        d = yaml.safe_load(f)
    model = ModelConfig(**d.pop("model_config", {}))
    // ...
```

**风险分析：**

- `yaml.safe_load()` 使用安全的加载器，不会执行任意 Python 代码
- 但 `path` 参数完全由用户控制，没有路径验证：
  - 可以读取任意位置的文件（信息泄露）
  - 可以读取 `/etc/passwd` 等系统文件
  - 在某些配置下可能写入敏感信息

**攻击场景：**

```bash
python -m serving_cast.main \
    --instance-config-path /etc/passwd \
    --common-config-path /root/.ssh/id_rsa
```

---

### PATH-004: Video Model Path Traversal (High)

**CWE-22: Path Traversal to Arbitrary File Read**

**数据流路径：**

```
[SOURCE] cli/inference/video_generate.py:331
    args.model_id (命令行参数，声称是 Diffusers 模型目录)
    ↓
[PROPAGATION] tensor_cast/diffusers/diffusers_model.py:36
    model_path = model_id
    ↓
[PATH_OP] tensor_cast/diffusers/diffusers_model.py:61  ⚠️
    os.walk(model_path)
    // 遍历用户指定的目录及其所有子目录
    ↓
[SINK] tensor_cast/diffusers/diffusers_model.py:70  ⚠️ HIGH
    open(config_path)
    // 打开目录中找到的 config.json
    ↓
[SINK] tensor_cast/diffusers/diffusers_model.py:71
    json.load(f)
```

**漏洞分析：**

代码位于 `tensor_cast/diffusers/diffusers_model.py:47-72`：

```python
def load_config_from_file(model_path: str, ...):
    if not os.path.isdir(model_path):
        raise ValueError(...)
    
    config_path_dict: Dict[str, str] = {}
    model_path = os.path.abspath(model_path)  // 仅转换为绝对路径，无边界检查
    
    for root, _, files in os.walk(model_path):
        if "config.json" in files:
            folder_name = os.path.basename(root)
            config_path = os.path.join(root, "config.json")
            config_path_dict[folder_name] = config_path
    
    for key, config_path in config_path_dict.items():
        with open(config_path) as f:
            config = json.load(f)
```

**风险分析：**

- 仅检查路径是否为目录，不检查是否在允许范围内
- `os.walk()` 会遍历整个目录树，可能访问敏感目录
- 如果用户指定 `/` 作为 model_path，会扫描整个文件系统
- 可以读取任意目录中名为 `config.json` 的文件

---

### PATH-005: Chrome Trace Output Path Traversal (Medium)

**CWE-22: Path Traversal to Arbitrary File Write**

**数据流路径：**

```
[SOURCE] cli/inference/text_generate.py:131
    args.chrome_trace
    ↓
[PROPAGATION] tensor_cast/core/user_config.py:37
    UserInputConfig.chrome_trace
    ↓
[CALL] tensor_cast/core/model_runner.py:215
    runtime.export_chrome_trace(self.user_input.chrome_trace)
    ↓
[SINK] tensor_cast/runtime.py:426  ⚠️ MEDIUM
    open(trace_file, "w")
```

**风险分析：**

- 用户可以指定任意输出路径
- 可能覆盖系统文件（如 `/etc/cron.d/malicious`）
- 需要结合其他漏洞才能造成严重影响

---

## 高风险模块详解

### tensor_cast/transformers/utils.py

**风险级别：Critical**

**关键函数：**

| 函数 | 行号 | 风险 | 描述 |
|------|------|------|------|
| `load_config` | 235-278 | Critical | 使用 `trust_remote_code=True` 回退机制 |
| `load_model` | 280-296 | Critical | 调用 `try_to_load_model` |
| `try_to_load_model` | 327-338 | Critical | `AutoModel.from_config` 执行远程代码 |
| `auto_load_model_and_config` | 312-324 | Critical | 组合上述两个危险操作 |

**代码片段：**

```python
# tensor_cast/transformers/utils.py:255-272
def load_config(self, model_id: str, remote_source: str = RemoteSource.huggingface):
    try:
        hf_config = AutoConfig.from_pretrained(model_id)
        self.is_transformers_natively_supported = True
    except Exception:
        # ⚠️ CRITICAL: 当模型类型不被原生支持时，自动启用远程代码执行
        hf_config = AutoConfig.from_pretrained(model_id, trust_remote_code=True)
```

### tensor_cast/utils.py

**风险级别：High**

**关键函数：**

| 函数 | 行号 | 风险 | CWE |
|------|------|------|-----|
| `check_dependencies` | 175-198 | High | CWE-78 |
| `pattern_match` | 50-70 | Medium | Regex-based validation |

**代码片段：**

```python
# tensor_cast/utils.py:196
subprocess.check_call(
    [sys.executable, "-m", "pip", "install", f"{pkg}=={target_ver}"]
)
```

### serving_cast/config.py

**风险级别：High**

**关键函数：**

| 函数 | 行号 | 风险 | CWE |
|------|------|------|-----|
| `Config.__init__` | 96-105 | High | CWE-22 |
| `_parse_common_config` | 108-116 | High | CWE-22 |
| `_parse_instance_config` | 119-132 | High | CWE-22 |

---

## 修复建议

### 1. 远程代码执行防护 (CWE-94)

**优先级：Critical**

**修复建议：**

```python
# tensor_cast/transformers/utils.py 修复方案

def load_config(self, model_id: str, ...):
    # 1. 添加模型来源白名单
    ALLOWED_MODEL_SOURCES = {
        "huggingface": ["meta-llama/", "mistralai/", "Qwen/", ...],
        "modelscope": [...]
    }
    
    # 2. 验证 model_id 是否在白名单中
    if not self._is_allowed_model(model_id, remote_source):
        raise ValueError(f"Model {model_id} is not in allowed list")
    
    # 3. 对于本地路径，验证路径边界
    if os.path.exists(model_id):
        real_path = os.path.realpath(model_id)
        allowed_base = os.path.realpath(ALLOWED_MODEL_DIR)
        if not real_path.startswith(allowed_base):
            raise ValueError("Local model path must be within allowed directory")
    
    # 4. 禁止自动启用 trust_remote_code
    # 用户必须显式通过 --trust-remote-code 参数启用
    trust_remote_code = getattr(user_input, "explicit_trust_remote_code", False)
    if trust_remote_code:
        logger.warning("trust_remote_code is enabled, this may execute remote code")
    
    try:
        hf_config = AutoConfig.from_pretrained(model_id)
    except Exception:
        # 不自动启用 trust_remote_code
        raise ValueError(
            f"Model {model_id} is not natively supported. "
            "If you trust this model, explicitly set --trust-remote-code"
        )
```

### 2. 命令注入防护 (CWE-78)

**优先级：High**

**修复建议：**

```python
# tensor_cast/utils.py 修复方案

def check_dependencies():
    # 1. 不要自动执行 pip install
    # 仅检测并警告用户
    pkg = "transformers"
    target_ver = "5.3.0"
    
    try:
        curr_ver = importlib.metadata.version(pkg)
        if tuple(map(int, curr_ver.split(".")[:3])) >= tuple(map(int, target_ver.split(".")[:3])):
            return
    except PackageNotFoundError:
        pass
    
    # 2. 仅输出警告，不自动安装
    logger.error(
        f"Incompatible {pkg} version: current={curr_ver}, required>={target_ver}. "
        "Please manually run: pip install {pkg}=={target_ver}"
    )
    sys.exit(1)  # 阻止继续执行
    
    # 3. 如果必须安装，添加确认提示
    # response = input("Do you want to install? [y/N]: ")
    # if response.lower() != 'y':
    #     sys.exit(1)
```

### 3. 路径遍历防护 (CWE-22)

**优先级：High**

**修复建议：**

```python
# serving_cast/config.py 修复方案

def _parse_common_config(path: str) -> CommonConfig:
    # 1. 定义允许的配置目录
    ALLOWED_CONFIG_DIRS = [
        os.path.realpath("./config"),
        os.path.realpath("/etc/mindstudio/config"),
    ]
    
    # 2. 验证路径边界
    real_path = os.path.realpath(path)
    is_allowed = any(
        real_path.startswith(allowed_dir) 
        for allowed_dir in ALLOWED_CONFIG_DIRS
    )
    if not is_allowed:
        raise ValueError(f"Config path {path} is outside allowed directories")
    
    # 3. 检查文件扩展名
    if not path.endswith(".yaml") and not path.endswith(".yml"):
        raise ValueError("Config file must be .yaml or .yml")
    
    with open(real_path, encoding="utf-8") as f:
        d = yaml.safe_load(f)
    ...

# tensor_cast/diffusers/diffusers_model.py 修复方案

def load_config_from_file(model_path: str, ...):
    # 1. 定义允许的模型目录
    ALLOWED_MODEL_DIRS = [
        os.path.realpath("./models"),
        os.path.realpath("/data/models"),
    ]
    
    # 2. 验证路径边界
    real_path = os.path.realpath(model_path)
    is_allowed = any(
        real_path.startswith(allowed_dir)
        for allowed_dir in ALLOWED_MODEL_DIRS
    )
    if not is_allowed:
        raise ValueError(f"Model path {model_path} is outside allowed directories")
    
    # 3. 限制 os.walk 深度
    max_depth = 3
    for root, dirs, files in os.walk(real_path):
        depth = root[len(real_path):].count(os.sep)
        if depth >= max_depth:
            dirs[:] = []  # 不进入更深目录
        ...
```

### 4. 输入验证增强

**优先级：Medium**

**修复建议：**

```python
# cli/utils.py 增强验证

def check_model_id_valid(model_id: str, max_len=512) -> str:
    # 1. 长度限制
    if len(model_id) > max_len:
        raise argparse.ArgumentTypeError(f"Model ID too long: {len(model_id)} > {max_len}")
    
    # 2. 对于远程 ID，验证格式
    if "/" in model_id and not os.path.exists(model_id):
        # HuggingFace 格式: organization/model-name
        if not re.match(r^[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+$", model_id):
            raise argparse.ArgumentTypeError(f"Invalid HF model ID format: {model_id}")
    else:
        # 本地路径验证
        real_path = os.path.realpath(model_id)
        if not os.path.exists(real_path):
            raise argparse.ArgumentTypeError(f"Local path does not exist: {model_id}")
    
    return model_id

def check_output_path_valid(path: str) -> str:
    # 1. 验证不允许覆盖系统文件
    dangerous_paths = ["~/.ssh/", "/etc/", "/var/", "/root/"]
    real_path = os.path.realpath(path)
    for dangerous in dangerous_paths:
        if real_path.startswith(os.path.realpath(dangerous)):
            raise argparse.ArgumentTypeError(f"Output path cannot be in {dangerous}")
    
    # 2. 确保父目录存在
    parent_dir = os.path.dirname(real_path)
    if not os.path.exists(parent_dir):
        raise argparse.ArgumentTypeError(f"Parent directory does not exist: {parent_dir}")
    
    return path
```

---

## 扫描范围和限制

### 已覆盖范围

- ✅ CLI 入口点参数验证
- ✅ 模型加载路径（HuggingFace/ModelScope/本地）
- ✅ 配置文件加载路径
- ✅ 命令执行操作
- ✅ 文件读写操作

### 未覆盖范围（需后续分析）

- ⚠️ `tensor_cast/compilation/` 编译模块的安全性
- ⚠️ 多进程模型（`serving_cast/model_runner.py` 的 `AsyncTaskManager`）
- ⚠️ 自定义模型注册表的安全性
- ⚠️ 性能模型数据库的安全性
- ⚠️ 并行组的网络通信安全

---

## 结论

MindStudio-Modeling 项目存在 **2 个 Critical 级别** 和 **3 个 High 级别** 的安全漏洞，主要涉及：

1. **远程代码执行风险**：通过 `trust_remote_code=True` 自动回退机制，攻击者可以通过恶意模型仓库执行任意代码。

2. **命令注入风险**：自动 pip 安装操作可能在特定环境下被利用。

3. **路径遍历风险**：多处文件操作未验证路径边界，可能读取/写入敏感文件。

**建议立即修复 Critical 级别漏洞，特别是：**
- 禁止自动启用 `trust_remote_code=True`
- 添加模型来源白名单
- 添加路径边界验证

---

*报告生成时间：2026-04-20*
*扫描工具：Architecture Agent*
*项目类型：纯 Python 项目*