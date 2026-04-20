# 漏洞扫描报告 — 已确认漏洞

**项目**: MindSeriesSDK-AgentSDK
**扫描时间**: 2026-04-20T08:15:50.733Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次漏洞扫描对 MindSeriesSDK-AgentSDK 项目进行了全面的安全分析，共发现 **25** 个候选漏洞，经验证后确认 **1** 个真实漏洞。

### 关键发现

**已确认漏洞 (CONFIRMED)**: 1 个高危漏洞 — **TOCTOU (Time-of-Check to Time-of-Use) 竞态条件漏洞**。该漏洞位于路径验证函数 `check_path_is_exist_and_valid()` 与动态模块加载函数 `load_subclasses_from_file()` 之间，攻击者可利用验证与使用之间的时间窗口执行文件替换攻击，导致任意代码执行。

### 威胁评估

| 指标 | 评估 |
|------|------|
| 攻击复杂度 | 中等 — 需精确控制时间窗口 |
| 攻击者权限要求 | 当前用户权限文件操作能力 |
| 影响范围 | 任意代码执行，完全控制系统 |
| 业务影响 | 高 — 可导致训练数据篡改、模型污染、系统接管 |

### 风险等级

| 风险等级 | 漏洞数 | 占比 |
|----------|--------|------|
| 高危 (HIGH) | 1 | 100% |
| 中危 (MEDIUM) | 0 | 0% |
| 低危 (LOW) | 0 | 0% |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 17 | 68.0% |
| LIKELY | 4 | 16.0% |
| FALSE_POSITIVE | 3 | 12.0% |
| CONFIRMED | 1 | 4.0% |
| **总计** | **25** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| **有效漏洞总计** | **1** | - |
| 误报 (FALSE_POSITIVE) | 3 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-BASEUTILS-005]** TOCTOU Race Condition (HIGH) - `agentic_rl/base/utils/file_utils.py:30` @ `check_path_is_exist_and_valid` | 置信度: 85

---

## 2. Top 漏洞深度分析

### VULN-DF-BASEUTILS-005: TOCTOU 竞态条件漏洞

#### 基本信息

| 属性 | 值 |
|------|-----|
| 漏洞ID | VULN-DF-BASEUTILS-005 |
| 类型 | TOCTOU Race Condition |
| CWE | CWE-367 |
| 严重性 | HIGH |
| 置信度 | 85 |
| 文件 | `agentic_rl/base/utils/file_utils.py` |
| 行号 | 30-58 |
| 函数 | `check_path_is_exist_and_valid` |

#### 漏洞描述

存在典型的 **Time-of-Check to Time-of-Use (TOCTOU)** 竞态条件漏洞。路径验证函数 `check_path_is_exist_and_valid()` 执行检查后，存在时间窗口，攻击者可在该窗口内替换文件，绕过安全检查。

#### 数据流分析

```
[CHECK 阶段]
用户路径 → check_path_is_exist_and_valid() (file_utils.py:30)
  ├── os.path.exists(path) 验证存在性
  ├── 正则表达式过滤非法字符
  ├── ".." 检查防止路径遍历
  ├── os.path.realpath() 检测符号链接
  └── 权限验证 (owner/group/mode)

[时间窗口 - 竞态条件]
        ↓ ↓ ↓ 危险窗口 ↓ ↓ ↓
        攻击者可在此期间：
        1. 删除原文件
        2. 创建符号链接指向恶意文件
        3. 替换文件内容为恶意Python代码

[USE 阶段]
验证后的路径 → load_subclasses_from_file() (class_loader.py:46)
  ├── FileCheck.check_data_path_is_valid() [再次验证但仍有窗口]
  ├── pathlib.Path(file_path).resolve()
  ├── importlib.util.spec_from_file_location()
  └── spec.loader.exec_module(module) [危险！任意代码执行]
```

#### 代码分析

**验证阶段 (file_utils.py:30-58)**:
```python
def check_path_is_exist_and_valid(path: str):
    if not isinstance(path, str) or not os.path.exists(path):  # CHECK 1
        raise ValueError("Path is not a string or path is not existed.")
    
    # ... 其他检查 ...
    
    real_path = os.path.realpath(path)  # CHECK 2 - 符号链接检测
    if real_path != os.path.normpath(path):
        raise ValueError("Path is link, it's not supported.")
```

**使用阶段 (class_loader.py:46-63)**:
```python
def load_subclasses_from_file(file_path: str, base_class: Type) -> Type:
    FileCheck.check_data_path_is_valid(file_path)  # CHECK (仍有窗口)
    file_path = pathlib.Path(file_path).resolve()
    # ...
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # USE - 执行任意代码
```

#### 攻击场景

**攻击步骤**:

1. **准备阶段**: 攻击者创建合法的 Python 文件 `legitimate_wrapper.py`，内容为正常的 BaseEngineWrapper 子类，确保文件权限符合要求 (mode=640, owner=current_user)

2. **触发验证**: 通过配置文件指定 `agent_engine_wrapper_path=legitimate_wrapper.py`，系统调用 `check_data_path_is_valid()` 进行验证

3. **竞态窗口**: 在验证完成但尚未执行 `exec_module()` 期间，攻击者快速：
   - 删除 `legitimate_wrapper.py`
   - 创建符号链接指向恶意文件 `malicious_code.py`
   - 或直接替换文件内容为恶意代码

4. **代码执行**: `exec_module()` 加载并执行恶意 Python 代码，攻击者获得完全控制

**攻击影响**:
- 执行任意系统命令
- 读取/修改敏感数据
- 窃取训练数据或模型权重
- 植入后门代码污染模型

#### 控制流路径

```
CLI 参数 --config-path → yaml.safe_load → cfg 字典
    → AgenticRLConfig.agent_engine_wrapper_path
    → RunnerWorker.__init__ (runner_worker.py:115)
    → load_subclasses_from_file (class_loader.py:35)
    → FileCheck.check_data_path_is_valid [CHECK]
    → [竞态窗口]
    → spec.loader.exec_module [USE - 代码执行]
```

#### 修复建议

**优先级**: 高 — 立即修复

**方案一: 使用文件描述符锁定 (推荐)**
```python
import os
import fcntl

def load_subclasses_from_file_secure(file_path: str, base_class: Type) -> Type:
    # 打开文件并获取文件描述符
    fd = os.open(file_path, os.O_RDONLY)
    try:
        # 获取文件锁，防止并发修改
        fcntl.flock(fd, fcntl.LOCK_SH)
        
        # 使用文件描述符进行验证
        stat_info = os.fstat(fd)
        # 验证权限、owner等...
        
        # 从文件描述符读取内容执行
        # 或使用 fd 路径进行加载
        spec = importlib.util.spec_from_file_location(
            module_name, 
            file_path,
            loader=importlib.machinery.SourceFileLoader(module_name, file_path)
        )
        # ...
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
```

**方案二: 验证后立即使用原子操作**
```python
def load_subclasses_from_file_atomic(file_path: str, base_class: Type) -> Type:
    # 一次性完成验证和加载
    resolved_path = pathlib.Path(file_path).resolve()
    
    # 原子检查: 使用 stat 获取文件信息
    stat_before = resolved_path.stat()
    
    # 立即加载
    spec = importlib.util.spec_from_file_location(module_name, resolved_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    
    # 验证加载后文件未被修改
    stat_after = resolved_path.stat()
    if stat_before.st_mtime != stat_after.st_mtime:
        raise ImportError("File was modified during loading")
```

**方案三: 使用白名单目录**
```python
ALLOWED_DIRS = [
    "/opt/agentsdk/wrappers/",
    "/home/user/safe_wrappers/"
]

def load_subclasses_from_file_whitelist(file_path: str, base_class: Type) -> Type:
    resolved = pathlib.Path(file_path).resolve()
    
    # 检查路径是否在白名单目录内
    for allowed_dir in ALLOWED_DIRS:
        try:
            resolved.relative_to(pathlib.Path(allowed_dir))
            break
        except ValueError:
            continue
    else:
        raise ImportError(f"File path not in allowed directories: {file_path}")
    
    # 继续加载...
```

---

## 3. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@agentic_rl/trainer/main.py` | cli_entry | 低信任 | 命令行参数可控 | 用户可通过 --config-path 指定配置文件 |
| `_load_config@agentic_rl/trainer/main.py` | file_input | 中信任 | YAML配置解析 | 配置文件内容影响运行时行为 |
| `load_subclasses_from_file@agentic_rl/base/utils/class_loader.py` | dynamic_load | 高风险 | 动态加载执行代码 | TOCTOU漏洞可达 |
| `__init__@agentic_rl/runner/infer_adapter/async_server.py` | env_var | 中信任 | 环境变量读取 | VLLM_DP_SIZE 环境变量 |
| `_process_dataset@agentic_rl/trainer/train_adapter/mindspeed_rl/train_agent_grpo.py` | file_input | 中信任 | 加载训练数据集 | JSON数据文件处理 |

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| base_utils | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **1** | **0** | **0** | **1** |

---

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-367 | 1 | 100.0% |

---

## 6. 修复建议总结

### 紧急修复 (24小时内)

| 漏洞ID | 问题描述 | 修复方案 | 验证方法 |
|--------|----------|----------|----------|
| VULN-DF-BASEUTILS-005 | TOCTOU竞态条件 | 实现文件锁定或原子验证-使用 | 渗透测试验证竞态窗口消除 |

### 代码改进建议

1. **路径验证重构**: 将 `check_path_is_exist_and_valid()` 和后续使用操作合并为原子操作
2. **添加白名单机制**: 只允许从预定义的安全目录加载动态模块
3. **审计日志增强**: 记录所有动态模块加载事件，包括加载前后的文件状态
4. **沙箱隔离**: 使用 Ray actor 或进程隔离执行动态加载的代码

### 长期安全策略

1. **供应链安全**: 对所有外部模块进行签名验证
2. **运行时监控**: 实现文件完整性监控，检测异常修改
3. **定期安全扫描**: 建立持续安全测试流程

---

## 7. 附录

### CWE-367 参考信息

**CWE-367: Time-of-Check Time-of-Use (TOCTOU) Race Condition**

该漏洞类别描述了在资源状态检查与资源使用之间存在时间窗口，攻击者可在此期间修改资源状态，导致安全检查被绕过。

**常见场景**:
- 文件访问竞态 (检查存在性 → 使用)
- 权限检查竞态 (检查权限 → 操作)
- 符号链接竞态 (检查路径 → 解析)

**防御策略**:
- 使用原子操作
- 文件锁定机制
- 白名单/沙箱隔离