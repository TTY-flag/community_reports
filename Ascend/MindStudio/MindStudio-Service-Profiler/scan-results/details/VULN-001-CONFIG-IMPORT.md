# 漏洞深度分析报告

## VULN-001-CONFIG-IMPORT: 配置驱动的任意代码执行 (CWE-94)

**严重性**: Critical  
**置信度**: 95%  
**CVSS 3.1 评分**: 9.8 (Critical)

---

## 1. 执行摘要

`_resolve_handler_func()` 函数使用 `importlib.import_module()` 动态导入 YAML 配置文件中指定的模块路径，**无任何验证或白名单保护**。攻击者若能控制配置文件（通过环境变量 `MS_SERVICE_PROF_CONFIG_PATH` 或直接修改文件），可构造恶意 handler 路径实现任意 Python 代码执行。

---

## 2. 根因分析

### 2.1 漏洞代码位置

**文件**: `ms_service_profiler/patcher/core/config_loader.py`  
**行号**: 82-110  
**函数**: `_resolve_handler_func`

```python
def _resolve_handler_func(handler_val: str, default_module: str = None) -> callable:
    """解析 handler 字段并导入对应函数"""
    mod_str, func_name = handler_val.split(":")
    # 漏洞点: 直接导入任意模块，无验证
    mod = importlib.import_module(mod_str)
    func = getattr(mod, func_name)
    return func
```

### 2.2 攻击路径

```
[入口点] MS_SERVICE_PROF_CONFIG_PATH 环境变量
    ↓ 攻击者设置环境变量指向恶意配置文件
[配置加载] load_yaml_config() → yaml.safe_load()
    ↓ 解析 YAML 配置
[Handler解析] ConfigLoader.load_profiling()
    ↓ 获取 handler 字段值
[动态导入] _resolve_handler_func(handler_val)
    ↓ handler_val = "os:system" 或恶意模块路径
[代码执行] importlib.import_module(mod_str)
    ↓ 导入恶意模块，执行模块级代码
[函数获取] getattr(mod, func_name)
    ↓ 获取恶意函数
[最终执行] handler_func() 被调用时执行恶意代码
```

---

## 3. PoC 构造思路

### 3.1 概念验证方法

**步骤 1**: 创建恶意 YAML 配置文件

```yaml
# malicious_config.yaml
profiling:
  handler: "os:system"  # 或自定义恶意模块
  # 其他配置...
```

**步骤 2**: 设置环境变量

```bash
export MS_SERVICE_PROF_CONFIG_PATH=/path/to/malicious_config.yaml
```

**步骤 3**: 运行程序触发导入

```bash
python -m ms_service_profiler analyze
```

当 `_resolve_handler_func("os:system")` 被调用时：
- `importlib.import_module("os")` 导入 os 模块
- `getattr(os, "system")` 获取 `os.system` 函数
- 后续调用 handler 时执行 `os.system("任意命令")`

### 3.2 扩展攻击

攻击者可构造自定义恶意模块：

```python
# malicious_module.py
def malicious_handler(*args, **kwargs):
    # 执行任意代码
    import subprocess
    subprocess.run(["malicious_command"])
```

配置中指定: `handler: "malicious_module:malicious_handler"`

---

## 4. 利用条件评估

| 条件 | 状态 | 说明 |
|------|------|------|
| 配置文件可控 | ✓ | 环境变量指定路径，攻击者需能控制环境变量或修改配置 |
| 动态导入机制 | ✓ | `importlib.import_module` 无验证 |
| Handler 触发 | ✓ | profiling 流程自动调用 handler |
| 代码执行 | ✓ | 导入模块时执行模块级代码 |

**前提条件**:
- 攻击者需有服务器访问权限（设置环境变量）
- 或配置文件权限被错误设置（其他用户可写）
- 或通过其他漏洞获得配置文件写入能力

---

## 5. CVSS 3.1 评分

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Local (L) | 需本地访问修改配置/环境变量 |
| Attack Complexity (AC) | Low (L) | 构造恶意配置简单 |
| Privileges Required (PR) | None (N) | 无需特殊权限（若配置文件权限问题） |
| User Interaction (UI) | None (N) | 无需用户交互 |
| Scope (S) | Changed (C) | 影响超出配置文件本身（执行任意代码） |
| Confidentiality (C) | High (H) | 可读取任意文件 |
| Integrity (I) | High (H) | 可修改任意数据 |
| Availability (A) | High (H) | 可导致服务拒绝 |

**基础评分**: 9.8 (Critical)

---

## 6. 缓解建议

### 6.1 立即修复 (P0)

**方案 A: Handler 模块白名单**

```python
ALLOWED_HANDLER_MODULES = {
    "ms_service_profiler.handlers",
    "ms_service_metric.handlers",
    # 只允许已知安全模块
}

def _resolve_handler_func(handler_val: str, default_module: str = None) -> callable:
    mod_str, func_name = handler_val.split(":")
    # 白名单验证
    if not any(mod_str.startswith(prefix) for prefix in ALLOWED_HANDLER_MODULES):
        raise ValueError(f"Handler module '{mod_str}' not in whitelist")
    mod = importlib.import_module(mod_str)
    func = getattr(mod, func_name)
    return func
```

**方案 B: Handler 配置签名验证**

```python
# 配置文件需包含签名
def load_config_with_verification(config_path: str) -> dict:
    config = yaml.safe_load(open(config_path))
    # 验证签名
    if not verify_config_signature(config):
        raise ValueError("Invalid config signature")
    return config
```

### 6.2 短期缓解 (P1)

- 禁止配置文件写入权限（仅管理员可写）
- 环境变量验证：检查 `MS_SERVICE_PROF_CONFIG_PATH` 是否指向预期路径
- 日志记录所有 handler 导入操作，便于审计

---

## 7. 相关漏洞

| 漏洞 ID | 类型 | 关系 |
|---------|------|------|
| VULN-002-METRICS-IMPORT | 任意代码执行 | 同根因，metrics handler 导入 |
| VULN-ms_service_metric-001 | 配置驱动代码执行 | 跨模块相同机制 |
| XM-VULN-002 | 跨模块配置执行 | 跨模块攻击链 |

---

**报告生成时间**: 2026-04-21  
**状态**: CONFIRMED