# 漏洞扫描报告 — 已确认漏洞

**项目**: MindStudio-Ops-Tuner
**扫描时间**: 2026-04-21T10:30:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描对 MindStudio-Ops-Tuner 项目进行了全面的漏洞分析，该项目是华为 Ascend NPU 算子 Tiling 参数寻优的 CLI 工具。扫描发现 **2 个已确认漏洞**，均位于 Python 代码生成模块中，涉及路径遍历和符号链接攻击两种高风险安全缺陷。

**关键风险概述**：

- **Path Traversal (Critical)**：用户通过 `--workspace-dir` 命令行参数可指定任意目录作为工作空间，代码在未进行路径验证的情况下直接执行 `shutil.rmtree()` 和 `os.mkdir()`，攻击者可利用此漏洞删除系统关键目录（如 `/etc`、`/root`）或创建恶意目录结构。
- **Symlink Attack (High)**：代码虽然检测到目标目录为符号链接并记录警告，但并未终止操作，仍继续执行 `shutil.rmtree()`，攻击者可通过预先创建符号链接使工具删除任意目录。

**业务影响**：

这两个漏洞共同构成一个完整的攻击链：攻击者首先通过符号链接准备攻击环境，然后触发代码生成流程，最终导致任意目录删除。由于该工具通常由开发者或运维人员在本地执行，攻击者需具备本地执行权限，但在多用户共享开发环境或 CI/CD 管道中，该漏洞可能导致严重的系统损坏或数据丢失。

**建议修复优先级**：

建议立即修复这两个漏洞，在路径操作前添加完整的路径验证（包括路径规范化、白名单检查、符号链接拒绝），并使用 `O_NOFOLLOW` 标志或 `realpath()` 解析真实路径后再执行文件操作。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 24 | 54.5% |
| LIKELY | 18 | 40.9% |
| CONFIRMED | 2 | 4.5% |
| **总计** | **44** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 1 | 50.0% |
| High | 1 | 50.0% |
| **有效漏洞总计** | **2** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-CODEGEN-TAINT-001]** Path Traversal (Critical) - `library/scripts/manifest.py:134` @ `generate_code` | 置信度: 65
2. **[VULN-CODEGEN-TAINT-002]** Symlink Attack (High) - `library/scripts/manifest.py:140` @ `generate_code` | 置信度: 65

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@tuner/src/main.cpp` | cmdline | untrusted_local | CLI 工具入口点，本地用户通过命令行参数（argv）控制程序行为，参数包括矩阵维度（m/n/k）、设备 ID、输出文件路径、算子过滤条件等 | 程序主入口，接收并解析命令行参数 |
| `ProfileDataHandler::SetDeviceId@tuner/src/profiler.cpp` | env | semi_trusted | 读取环境变量 ASCEND_RT_VISIBLE_DEVICES 进行设备 ID 映射，环境变量由系统管理员或部署脚本设置，非普通用户直接控制 | 设备可见性配置，通过环境变量控制设备访问 |
| `Metrics::SetOutputPath@tuner/src/metrics.cpp` | file | untrusted_local | 用户通过 --output 参数指定 CSV 文件输出路径，路径可能包含敏感目录（如 /etc、/root）或软链接，代码包含路径安全检查逻辑 | 性能数据输出路径处理，包含路径规范化、软链接检测、权限验证 |
| `CommandLineParser::Parse@tuner/src/command_line_parser.cpp` | cmdline | untrusted_local | 命令行参数解析入口，处理 --key=value 格式的参数，参数值直接传入程序逻辑 | 解析 argc/argv 为键值对映射 |

**其他攻击面**:
- 命令行参数注入：用户可控的参数包括 m/n/k（矩阵维度）、output（文件路径）、device（设备 ID）、kernels（算子过滤）、A/B/C（张量类型）
- 文件路径操作：用户指定的输出路径可能触发路径遍历、软链接攻击、权限提升
- 设备驱动接口：调用外部 C 函数 prof_drv_start、prof_channel_read、prof_stop、halGetDeviceInfo
- 环境变量读取：ASCEND_RT_VISIBLE_DEVICES 设备可见性配置
- 构建脚本命令执行：download_dependencies.py 执行 git submodule、curl、tar 命令，build.py 执行 cmake、make 命令

---

## 3. Critical 漏洞 (1)

### [VULN-CODEGEN-TAINT-001] Path Traversal - generate_code

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: CONFIRMED | **来源**: taint_analyzer, python-security-module-scanner

**位置**: `library/scripts/manifest.py:134-147` @ `generate_code`
**模块**: code_generator
**跨模块**: code_generator.py → manifest.py

**描述**: User-controlled workspace_dir from CLI argument flows directly to shutil.rmtree() and os.mkdir() without any path validation or canonicalization. An attacker could supply --workspace-dir=/ or --workspace-dir=/etc to delete arbitrary directories.

**漏洞代码** (`library/scripts/manifest.py:134-147`)

```c
workspace_dir = self.args.workspace_dir; generated_dir = os.path.join(workspace_dir, generated); shutil.rmtree(generated_dir); os.mkdir(generated_dir)
```

**达成路径**

CLI --workspace-dir -> args.workspace_dir -> Manifest.__init__ -> generate_code() -> shutil.rmtree/os.mkdir

**验证说明**: Direct CLI argument --workspace-dir flows to shutil.rmtree() and os.mkdir() without any path validation. Attacker can delete arbitrary directories (e.g., --workspace-dir=/). Data flow: CLI -> args.workspace_dir -> Manifest.generate_code() -> shutil.rmtree.

**评分明细**: 0: R | 1: e | 2: a | 3: c | 4: h | 5: a | 6: b | 7: i | 8: l | 9: i | 10: t | 11: y | 12:   | 13: + | 14: 3 | 15: 0 | 16:   | 17: ( | 18: d | 19: i | 20: r | 21: e | 22: c | 23: t | 24:   | 25: f | 25: r | 26: o | 27: m | 28:   | 29: m | 30: a | 31: i | 32: n | 33:   | 34: e | 35: n | 36: t | 37: r | 38: y | 39:   | 40: p | 41: o | 42: i | 43: n | 44: t | 45: ) | 46:   | 47: + | 48:   | 49: C | 50: o | 51: n | 52: t | 53: r | 54: o | 55: l | 56: l | 57: a | 58: b | 59: i | 60: l | 61: i | 62: t | 63: y | 64:   | 65: + | 66: 2 | 67: 0 | 68:   | 69: ( | 70: f | 71: u | 72: l | 73: l | 74:   | 75: C | 76: L | 77: I | 78:   | 79: c | 80: o | 81: n | 82: t | 83: r | 84: o | 85: l | 86: ) | 87:   | 88: + | 89:   | 90: C | 91: r | 92: o | 93: s | 94: s | 95: - | 96: m | 97: o | 98: d | 99: u | 100: l | 101: e | 102:   | 103: + | 104: 1 | 105: 5 | 106:   | 107: ( | 108: c | 109: o | 110: d | 111: e | 112: _ | 113: g | 114: e | 115: n | 116: e | 117: r | 118: a | 119: t | 120: o | 121: r | 122: . | 123: p | 124: y | 125:   | 126: - | 127: > | 128:   | 129: m | 130: a | 131: n | 132: i | 133: f | 134: e | 135: s | 136: t | 137: . | 138: p | 139: y | 140: )

**深度分析**

**根因分析**：

从源代码 `library/scripts/manifest.py:134-147` 和 `library/scripts/code_generator.py:38-41` 可以看到完整的数据流：

```python
# code_generator.py:38-41 - CLI 参数定义
parser.add_argument(
    '--workspace-dir',
    type=str,
    help="Workspace directory",
)

# manifest.py:134-147 - 漏洞代码
def generate_code(self):
    workspace_dir = self.args.workspace_dir  # 直接获取用户输入
    generated_dir = os.path.join(workspace_dir, 'generated')
    
    if os.path.exists(generated_dir):
        if os.path.islink(generated_dir):
            LOGGER.warning(...)  # 仅警告，不阻止
        shutil.rmtree(generated_dir)  # 无验证直接删除
    
    os.mkdir(generated_dir)  # 无验证直接创建
```

漏洞的根本原因是：
1. **缺少路径规范化**：`workspace_dir` 直接从 CLI 参数获取，未使用 `os.path.realpath()` 或 `os.path.abspath()` 进行规范化
2. **缺少路径白名单检查**：未验证 `workspace_dir` 是否在允许的目录范围内（如项目目录、临时目录）
3. **缺少危险路径检测**：未检测路径是否包含 `..`、是否指向系统敏感目录

**潜在利用场景**：

攻击者可通过以下命令触发漏洞：

```bash
# 删除系统目录（需要 root 权限）
python code_generator.py --workspace-dir=/etc

# 删除用户数据
python code_generator.py --workspace-dir=/home/victim/important_data

# 创建恶意目录结构
python code_generator.py --workspace-dir=/tmp/malicious
```

在 CI/CD 环境中，如果构建脚本调用了代码生成器，攻击者可能通过修改构建配置注入恶意参数，导致整个构建环境的破坏。

**建议修复方式**：

```python
import os
import pathlib

def generate_code(self):
    workspace_dir = self.args.workspace_dir
    
    # 1. 路径规范化
    workspace_dir = os.path.realpath(workspace_dir)
    
    # 2. 白名单检查 - 只允许在项目目录或安全的临时目录内操作
    project_root = pathlib.Path(__file__).parent.parent.parent.resolve()
    allowed_prefixes = [str(project_root), '/tmp/catlass_', '/var/tmp/catlass_']
    
    if not any(workspace_dir.startswith(prefix) for prefix in allowed_prefixes):
        raise ValueError(f"workspace_dir must be within allowed directories: {workspace_dir}")
    
    # 3. 禁止符号链接
    if os.path.islink(workspace_dir):
        raise ValueError(f"workspace_dir cannot be a symlink: {workspace_dir}")
    
    # 4. 使用安全的目录操作
    generated_dir = os.path.join(workspace_dir, 'generated')
    # 使用 tempfile 或在创建前验证父目录权限
    ...
```

---

## 4. High 漏洞 (1)

### [VULN-CODEGEN-TAINT-002] Symlink Attack - generate_code

**严重性**: High | **CWE**: CWE-59 | **置信度**: 65/100 | **状态**: CONFIRMED | **来源**: taint_analyzer

**位置**: `library/scripts/manifest.py:140-143` @ `generate_code`
**模块**: code_generator

**描述**: The code detects that generated_dir is a symlink but STILL proceeds to delete it with shutil.rmtree(). This allows symlink-to-outside attacks.

**漏洞代码** (`library/scripts/manifest.py:140-143`)

```c
if os.path.islink(generated_dir): LOGGER.warning(...); shutil.rmtree(generated_dir)
```

**达成路径**

generated_dir -> os.path.islink check -> warning logged but NO abort -> shutil.rmtree

**验证说明**: Code detects symlink via os.path.islink() and logs warning but STILL proceeds with shutil.rmtree(). No abort/return after detection. Classic symlink-to-outside attack vector. Warning proves awareness but no actual mitigation.

**评分明细**: 0: R | 1: e | 2: a | 3: c | 4: h | 5: a | 6: b | 7: i | 8: l | 9: i | 10: t | 11: y | 12:   | 13: + | 14: 3 | 15: 0 | 16:   | 17: ( | 18: s | 19: a | 20: m | 21: e | 22:   | 23: p | 24: a | 25: t | 26: h | 27:   | 28: a | 29: s | 30:   | 31: T | 32: A | 33: I | 34: N | 35: T | 36: - | 37: 0 | 38: 0 | 39: 1 | 40: ) | 41:   | 42: + | 43:   | 44: C | 45: o | 46: n | 47: t | 48: r | 49: o | 50: l | 51: l | 52: a | 53: b | 54: i | 55: l | 56: i | 57: t | 58: y | 59:   | 60: + | 61: 2 | 62: 0 | 63:   | 64: ( | 65: v | 66: i | 67: a | 68:   | 69: w | 70: o | 71: r | 72: k | 73: s | 74: p | 75: a | 76: c | 77: e | 78: _ | 79: d | 80: i | 81: r | 82: ) | 83:   | 84: + | 85:   | 86: C | 87: r | 88: o | 89: s | 90: s | 91: - | 92: m | 93: o | 94: d | 95: u | 96: l | 97: e | 98:   | 99: + | 100: 1 | 101: 5

**深度分析**

**根因分析**：

从源代码 `library/scripts/manifest.py:140-143` 可以看到问题代码：

```python
if os.path.exists(generated_dir):
    if os.path.islink(generated_dir):
        LOGGER.warning(f'generated directory is a soft link, which is not recommended to be removed. Please check if the generated directory is correct.')
    shutil.rmtree(generated_dir)  # 问题：警告后仍然删除
```

漏洞的根本原因是：
1. **检测到风险但未阻止**：代码正确地检测到 `generated_dir` 是符号链接，但只记录警告日志，没有终止操作或抛出异常
2. **缺少 `return` 或 `raise`**：警告后代码继续执行 `shutil.rmtree()`，导致符号链接指向的目录被删除
3. **开发者意识到了风险但未实现防护**：警告消息表明开发者知道符号链接有风险，但未实现实际的安全措施

**潜在利用场景**：

攻击者可通过预置符号链接，使代码生成器删除任意目录：

```bash
# 步骤 1：创建指向目标目录的符号链接
mkdir -p /tmp/target  # 攻击者控制的工作空间
ln -s /home/victim/important_data /tmp/target/generated

# 步骤 2：触发代码生成
python code_generator.py --workspace-dir=/tmp/target

# 结果：/home/victim/important_data 被删除！
# 即使代码检测到符号链接并记录警告，仍然执行了删除操作
```

这是一个经典的 **"检测到但不阻止"（detect-but-don't-block）** 安全缺陷，代码表明了开发者对风险的认知，但实际防护措施缺失。

**建议修复方式**：

```python
import os
import pathlib

def generate_code(self):
    workspace_dir = os.path.realpath(self.args.workspace_dir)  # 解析真实路径
    generated_dir = os.path.join(workspace_dir, 'generated')
    
    if os.path.exists(generated_dir):
        # 严格拒绝符号链接
        if os.path.islink(generated_dir):
            raise ValueError(
                f"Security violation: generated_dir is a symlink. "
                f"Refusing to delete. Symlink points to: {os.readlink(generated_dir)}"
            )
        
        # 验证目标路径确实在工作空间内
        real_path = os.path.realpath(generated_dir)
        if not real_path.startswith(workspace_dir):
            raise ValueError(
                f"Security violation: generated_dir resolves outside workspace. "
                f"Real path: {real_path}, Workspace: {workspace_dir}"
            )
        
        shutil.rmtree(generated_dir)
    
    os.mkdir(generated_dir)
```

关键改进点：
1. 检测到符号链接后立即抛出异常终止操作，而不是仅记录警告
2. 使用 `os.path.realpath()` 解析真实路径，防止符号链接逃逸
3. 验证真实路径确实在工作空间范围内

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| code_generator | 1 | 1 | 0 | 0 | 2 |
| **合计** | **1** | **1** | **0** | **0** | **2** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-59 | 1 | 50.0% |
| CWE-22 | 1 | 50.0% |

---

## 修复建议

### 优先级 1: 立即修复（Critical 漏洞）

#### [VULN-CODEGEN-TAINT-001] Path Traversal

**修复方案**：

1. **路径规范化**：使用 `os.path.realpath()` 或 `pathlib.Path.resolve()` 解析用户输入的真实路径，消除 `..` 和符号链接影响

2. **白名单检查**：限制 `workspace_dir` 只能在以下允许的目录范围内：
   - 项目根目录及其子目录
   - 指定的安全临时目录（如 `/tmp/catlass_`）

3. **危险路径检测**：拒绝包含以下特征的路径：
   - 路径包含 `..` 序列
   - 路径指向系统敏感目录（`/etc`、`/root`、`/var`、`/usr`）
   - 路径是符号链接

4. **权限验证**：验证用户对目标目录具有适当的读写权限

**示例代码**：

```python
import os
import pathlib

ALLOWED_BASE_DIRS = [
    pathlib.Path(__file__).parent.parent.parent.resolve(),  # 项目根目录
    pathlib.Path('/tmp/catlass'),
]

def validate_workspace_dir(workspace_dir: str) -> str:
    """验证并规范化工作空间目录路径"""
    # 1. 解析真实路径
    real_path = pathlib.Path(workspace_dir).resolve()
    
    # 2. 检查是否在允许的目录范围内
    is_allowed = any(
        str(real_path).startswith(str(allowed))
        for allowed in ALLOWED_BASE_DIRS
    )
    if not is_allowed:
        raise ValueError(
            f"workspace_dir must be within allowed directories. "
            f"Provided: {real_path}"
        )
    
    # 3. 检查是否为符号链接
    if pathlib.Path(workspace_dir).is_symlink():
        raise ValueError(
            f"workspace_dir cannot be a symlink. Provided: {workspace_dir}"
        )
    
    return str(real_path)
```

### 优先级 2: 短期修复（High 漏洞）

#### [VULN-CODEGEN-TAINT-002] Symlink Attack

**修复方案**：

1. **强制终止策略**：检测到符号链接后立即抛出异常终止操作，而不是仅记录警告

2. **双重验证**：在删除目录前再次验证路径是否在工作空间范围内（防止 TOCTOU 攻击）

3. **使用 `O_NOFOLLOW`**：在打开文件/目录时使用 `O_NOFOLLOW` 标志拒绝符号链接（Linux）

**示例代码**：

```python
def safe_rmtree(path: str, workspace_root: str) -> None:
    """安全的目录删除函数"""
    # 1. 解析真实路径
    real_path = os.path.realpath(path)
    
    # 2. 严格拒绝符号链接
    if os.path.islink(path):
        raise ValueError(
            f"Security violation: path is a symlink. Refusing to delete. "
            f"Symlink: {path}, Target: {os.readlink(path)}"
        )
    
    # 3. 验证路径在工作空间范围内
    real_workspace = os.path.realpath(workspace_root)
    if not real_path.startswith(real_workspace):
        raise ValueError(
            f"Security violation: path resolves outside workspace. "
            f"Path: {real_path}, Workspace: {real_workspace}"
        )
    
    # 4. 执行删除
    shutil.rmtree(real_path)
```

### 优先级 3: 安全加固建议

#### 代码生成模块整体安全加固

1. **输入验证框架**：建立统一的 CLI 参数验证框架，对所有用户输入进行类型检查、范围检查和格式验证

2. **安全审计日志**：记录所有路径操作（创建、删除）的详细信息，包括操作者、目标路径、时间戳

3. **权限降级**：在执行文件操作前临时降级权限，避免以 root 权限执行危险操作

4. **单元测试覆盖**：为路径验证逻辑添加安全测试用例，覆盖各种攻击场景：
   - 路径遍历（`../`）
   - 符号链接攻击
   - 绝对路径注入
   - 空路径/特殊字符处理

5. **安全配置文件**：将允许的目录白名单配置在独立的安全配置文件中，便于管理员根据环境调整

#### 构建环境安全建议

1. **CI/CD 环境隔离**：在 CI/CD 管道中使用独立的临时容器执行代码生成，避免对宿主机造成影响

2. **权限最小化**：构建脚本应以最低必要权限运行，避免 root 权限

3. **输入参数审核**：CI/CD 配置文件中的参数应经过安全审核，避免恶意参数注入

---

**报告完成时间**: 2026-04-21
**审核建议**: 建议安全团队和开发团队共同评审本报告，制定详细的修复计划和测试策略。
