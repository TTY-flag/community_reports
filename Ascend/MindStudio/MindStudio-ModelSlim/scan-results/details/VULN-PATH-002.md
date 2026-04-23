# VULN-PATH-002：get_valid_path符号链接检查缺失致任意文件访问

## 漏洞概要

| 属性 | 值 |
|------|-----|
| 漏洞 ID | VULN-PATH-002 |
| 类型 | Incomplete Symlink Protection (CWE-59) |
| 严重性 | High |
| 状态 | CONFIRMED |
| 置信度 | 80 |
| 文件 | msmodelslim/utils/security/path.py |
| 位置 | 第 69-71 行 |
| 函数 | `get_valid_path` |

## 漏洞本质

**防御措施不完整：符号链接检查只验证最终路径组件，忽略中间目录中的符号链接。**

```python
# 问题代码 (path.py:69-71)
if os.path.islink(os.path.abspath(path)):  # ❌ 只检查最终组件
    raise SecurityError("The value of the path cannot be soft link: {}.".format(path),
                        action='Please make sure the path is not a soft link.')
real_path = os.path.realpath(path)  # 解析所有符号链接，包括中间的
```

**关键问题：**
- `os.path.islink(path)` 只检查 `path` 字符串指向的**最后一个组件**是否为符号链接
- 它**不会检查**路径中间的目录是否包含符号链接
- `os.path.realpath(path)` 会解析整个路径中的所有符号链接
- 检查通过后，实际文件操作使用 `real_path`，可能指向攻击者控制的敏感位置

## 攻击链完整性验证

### 1. 入口点可达性 ✅ 已验证

**CLI 入口点 (cli/__main__.py:50-61)**
```python
quant_parser.add_argument('--model_path', required=True, type=str,
                          help="Path to the original model")
quant_parser.add_argument('--save_path', required=True, type=str,
                          help="Path to save quantized model")
quant_parser.add_argument('--config_path', type=str,
                          help="Explicit path to quantization config file")
```

**Python API 入口点 (app/naive_quantization/application.py)**
- `NaiveQuantizationApplication.quant()` 接收 `model_path`, `save_path`, `config_path` 参数
- 用户可通过 Python API 直接调用，完全控制路径参数

### 2. 数据流验证 ✅ 已验证

```
用户输入路径 (CLI/API)
    ↓
model_path / save_path / config_path
    ↓
yaml_safe_load / json_safe_load / get_valid_read_path / get_valid_write_path
    ↓
get_valid_path(path)  ← 漏洞点：islink检查只看最终组件
    ↓
检查通过，返回 real_path
    ↓
文件操作使用 real_path (可能指向攻击者目标)
```

### 3. 信任边界确认 ✅ 已验证

根据 `project_model.json`：
- **User Input - Model Path**: High Risk (用户提供的模型文件路径)
- **User Input - Config Path**: High Risk (用户提供的配置文件路径)
- **User Input - Save Path**: Medium Risk (用户指定的输出目录)

用户控制的路径参数跨越信任边界进入安全验证函数。

## PoC 可行性评估

### 攻击场景构造

```bash
# 步骤 1: 攻击者创建包含符号链接的目录结构
mkdir -p /tmp/trusted_model_dir
ln -s /etc /tmp/trusted_model_dir/config_links
ln -s /root /tmp/trusted_model_dir/weight_links

# 步骤 2: 在符号链接目录下放置诱饵文件（或利用已存在文件）
# /tmp/trusted_model_dir/config_links/passwd → /etc/passwd
# /tmp/trusted_model_dir/weight_links/.ssh/id_rsa → /root/.ssh/id_rsa

# 步骤 3: 通过 CLI 或 API 调用，传入包含中间符号链接的路径
msmodelslim quant --model_path /tmp/trusted_model_dir/weight_links/config.json \
                   --save_path /tmp/output \
                   --model_type Qwen2.5-7B-Instruct

# 步骤 4: 漏洞触发流程
# 1. get_valid_path("/tmp/trusted_model_dir/weight_links/config.json")
# 2. os.path.abspath() → "/tmp/trusted_model_dir/weight_links/config.json"
# 3. os.path.islink() → False (config.json 不是符号链接)
# 4. 检查通过！
# 5. os.path.realpath() → "/root/config.json" (解析了 weight_links 符号链接)
# 6. 实际访问 /root/config.json，可能泄露或修改敏感文件
```

### Python API PoC

```python
from msmodelslim.app.naive_quantization.application import NaiveQuantizationApplication

# 前置条件: 已创建 /tmp/evil_dir/sensitive → /etc 的符号链接
app = NaiveQuantizationApplication()
# 尝试读取敏感文件
result = app.quant(
    model_type="Qwen2.5-7B-Instruct",
    model_path="/tmp/evil_dir/sensitive/passwd",  # passwd 本身不是符号链接
    save_path="/tmp/output"
)
# get_valid_path 检查通过，但 realpath 解析到 /etc/passwd
```

### 攻击成功条件

| 条件 | 状态 |
|------|------|
| 入口点可控 | ✅ CLI/API 参数完全用户可控 |
| 中间符号链接可创建 | ⚠️ 需攻击者有目录创建权限 |
| 检查绕过可行 | ✅ `islink` 只检查最终组件 |
| realpath 解析执行 | ✅ 代码明确使用 `os.path.realpath` |

## 影响范围分析

### 直接影响函数

| 函数 | 用途 | 风险 |
|------|------|------|
| `get_valid_path` (核心) | 路径验证 | Critical |
| `get_valid_read_path` | 文件读取验证 | High |
| `get_valid_write_path` | 文件写入验证 | High |
| `yaml_safe_load` | YAML 配置加载 | High |
| `json_safe_load` | JSON 配置加载 | High |
| `safe_copy_file` | 文件复制 | Medium |
| `safe_delete_path_if_exists` | 文件删除 | High |

### 影响文件统计

- **148 个文件** 使用了相关安全函数
- 覆盖模块：
  - CLI 命令处理 (`cli/`)
  - 量化应用 (`app/naive_quantization/`)
  - 模型适配器 (`model/`)
  - 权重压缩 (`pytorch/weight_compression/`)
  - LLM PTQ (`pytorch/llm_ptq/`)
  - 数据集加载 (`infra/dataset_loader/`)
  - 配置管理 (`infra/yaml_*`)

### 具体攻击效果

| 操作类型 | 潜在影响 |
|----------|----------|
| 文件读取 | 泄露敏感文件内容 (/etc/passwd, /root/.ssh/, 配置文件) |
| 文件写入 | 覆盖敏感文件，植入恶意内容 |
| 文件删除 | 删除关键系统文件或用户数据 |
| 配置加载 | 加载恶意配置，改变程序行为 |

## 缓解措施评估

### 当前代码的防御尝试

1. **符号链接检查** (第 69 行) - ❌ 不完整
2. **路径字符白名单** (第 65 行) - ⚠️ 无法阻止中间符号链接
3. **文件长度检查** (第 76-80 行) - ❌ 无防御作用
4. **realpath 字符检查** (第 83 行) - ⚠️ 仅检查字符，不验证路径范围

### 缺失的关键防御

1. **没有路径范围验证** - 未限制解析后的路径必须在安全目录内
2. **没有中间组件检查** - 未逐层检查路径组件是否为符号链接
3. **没有 O_NOFOLLOW 标志** - 文件打开时未阻止跟随符号链接

## 正确的修复方案

### 方案 A: 完整路径组件检查 (推荐)

```python
def get_valid_path(path, extensions=None):
    # ... 现有检查 ...
    
    # ✅ 新增：检查所有路径组件是否存在符号链接
    abs_path = os.path.abspath(path)
    components = abs_path.split(os.sep)
    check_path = '/'
    for comp in components[1:]:  # 跳过根目录 '/'
        check_path = os.path.join(check_path, comp)
        if os.path.islink(check_path):
            raise SecurityError(
                f"Path contains symlink at intermediate component: {check_path}",
                action='Please ensure no symlinks in the path.'
            )
    
    # 然后检查最终组件
    if os.path.islink(abs_path):
        raise SecurityError(...)
    
    real_path = os.path.realpath(path)
    # ... 后续检查 ...
```

### 方案 B: 路径范围白名单

```python
def get_valid_path(path, extensions=None):
    # ... 现有检查 ...
    
    real_path = os.path.realpath(path)
    
    # ✅ 新增：验证解析后的路径必须在允许范围内
    ALLOWED_BASE_DIRS = [
        os.path.realpath('/home/user/models'),
        os.path.realpath('/opt/models'),
    ]
    
    is_safe = False
    for allowed_dir in ALLOWED_BASE_DIRS:
        if os.path.commonpath([real_path, allowed_dir]) == allowed_dir:
            is_safe = True
            break
    
    if not is_safe:
        raise SecurityError(
            f"Resolved path {real_path} is outside allowed directories",
            action='Please provide a path within allowed model directories.'
        )
    
    # ... 后续检查 ...
```

### 方案 C: 使用 O_NOFOLLOW (Linux)

```python
import os
import stat

def safe_open_file(path):
    real_path = get_valid_path(path)  # 先做基本验证
    
    # ✅ 使用 O_NOFOLLOW 标志，阻止打开符号链接
    fd = os.open(real_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        return os.fdopen(fd, 'r')
    except:
        os.close(fd)
        raise
```

## 风险评分

| 维度 | 分数 | 说明 |
|------|------|------|
| 基础分 | 30 | CWE-59 路径遍历类漏洞 |
| 可达性 | 20 | CLI/API 入口点完全用户可控 |
| 可控性 | 20 | 攻击者可构造包含符号链接的路径 |
| 缓解措施 | -5 | 存在不完整的符号链接检查 |
| 上下文 | 0 | 需攻击者有目录创建权限 |
| 跨模块 | 0 | 单一函数漏洞 |
| **总分** | **65** | High (CONFIRMED) |

## 结论

**这是一个真实的安全漏洞 (CONFIRMED)**

### 漏洞确认依据

1. ✅ `os.path.islink()` 确实只检查最终路径组件
2. ✅ 攻击者可以通过中间符号链接绕过检查
3. ✅ `os.path.realpath()` 会解析被绕过的符号链接
4. ✅ 148 个调用点使用受影响的验证函数
5. ✅ CLI/API 入口点允许用户完全控制路径参数

### 建议优先级

- **立即修复**: 实施方案 A (完整路径组件检查) 或方案 B (路径范围白名单)
- **影响面**: 需同步更新所有 148 个调用点的行为预期
- **测试验证**: 添加符号链接攻击场景的单元测试

---

*分析完成时间: 2026-04-21*
*分析者: Details Worker*
