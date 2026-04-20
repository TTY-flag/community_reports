# 漏洞扫描报告 — 待确认漏洞

**项目**: MindIE-Turbo
**扫描时间**: 2026-04-19T20:53:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 29 | 87.9% |
| POSSIBLE | 2 | 6.1% |
| LIKELY | 1 | 3.0% |
| CONFIRMED | 1 | 3.0% |
| **总计** | **33** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Medium | 2 | 66.7% |
| Low | 1 | 33.3% |
| **有效漏洞总计** | **3** | - |
| 误报 (FALSE_POSITIVE) | 29 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-009-directoryutils-walk-symlink]** Directory Walk Symlink Bypass (Medium) - `mindie_turbo/utils/directory_utils.py:189` @ `safe_walk` | 置信度: 75
2. **[VULN-007-fileutils-symlink-timing]** Symlink Check Timing Vulnerability (Medium) - `mindie_turbo/utils/file_utils.py:86` @ `standardize_path` | 置信度: 50
3. **[VULN-010-cli-setattr-injection]** Arbitrary Attribute Injection via setattr (Low) - `mindie_turbo/utils/cli.py:127` @ `_safe_set_attribute` | 置信度: 55

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `parse_custom_args@mindie_turbo/utils/cli.py` | cmdline | untrusted_local | 接受外部命令行参数，通过 argparse.parse_known_args() 传入，用户可通过 CLI 直接控制参数值 | CLI 命令行参数解析入口，处理未知参数并动态设置 Namespace 属性 |
| `apply_patch@mindie_turbo/utils/patcher.py` | rpc | semi_trusted | 通过 register_patch 注册目标函数路径后，apply_patch 修改 sys.modules 和模块属性，实现动态代码替换 | 动态函数替换入口，修改已加载模块的函数实现 |
| `parse_path@mindie_turbo/utils/patcher.py` | rpc | semi_trusted | 解析模块路径字符串，可创建虚假模块并注入到 sys.modules，存在模块名注入风险 | 模块路径解析入口，支持动态创建虚假模块 |
| `register_patch@mindie_turbo/utils/patcher.py` | rpc | semi_trusted | 注册补丁目标路径，通过字符串指定要替换的函数/模块，路径验证存在绕过风险 | 补丁注册入口，指定目标函数路径和替换方式 |
| `safe_open@mindie_turbo/utils/file_utils.py` | file | untrusted_local | 接受用户提供的文件路径参数，进行路径标准化和安全检查后打开文件 | 安全文件打开入口，处理外部路径输入 |
| `check_file_path@mindie_turbo/utils/file_utils.py` | file | untrusted_local | 验证用户提供的文件路径，检查符号链接、特殊字符、路径长度等 | 文件路径验证入口，处理外部路径输入 |
| `check_directory_path@mindie_turbo/utils/directory_utils.py` | file | untrusted_local | 验证用户提供的目录路径，检查符号链接、权限等 | 目录路径验证入口，处理外部路径输入 |
| `safe_listdir@mindie_turbo/utils/directory_utils.py` | file | untrusted_local | 读取用户指定的目录内容，限制文件数量防止资源耗尽 | 安全目录遍历入口 |
| `get_validated_optimization_level@mindie_turbo/adaptor/vllm_turbo.py` | env | untrusted_local | 读取环境变量 VLLM_OPTIMIZATION_LEVEL，决定补丁激活级别 | 环境变量读取入口，控制优化级别 |
| `activate@mindie_turbo/adaptor/base_turbo.py` | decorator | semi_trusted | 激活优化级别后调用 register_patches 和 patcher.apply_patches()，触发动态代码修改 | 优化激活入口，触发补丁应用 |
| `__getattr__@mindie_turbo/env.py` | env | untrusted_local | 动态属性访问器，根据 env_variables 字典调用验证函数读取环境变量 | 动态环境变量访问入口 |
| `load_module_from_path@setup.py` | file | semi_trusted | 安装过程中动态加载 Python 模块，路径受 allowed_dirs 白名单约束 | 安装过程中的动态模块加载 |

**其他攻击面**:
- CLI 参数解析: parse_custom_args() 接受未知命令行参数
- 环境变量读取: VLLM_OPTIMIZATION_LEVEL 控制 patcher 行为
- 动态模块修改: patcher.py 可修改 sys.modules 和模块属性
- 文件系统访问: file_utils.py 和 directory_utils.py 处理外部路径
- 模块导入触发: 导入 mindie_turbo 时自动激活 vllm_turbo

---

## 3. Medium 漏洞 (2)

### [VULN-009-directoryutils-walk-symlink] Directory Walk Symlink Bypass - safe_walk

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `mindie_turbo/utils/directory_utils.py:189-214` @ `safe_walk`
**模块**: utils

**描述**: safe_walk checks directories but does not verify files are not symlinks pointing outside traversal scope. Symlinks in listed files could point to arbitrary locations bypassing intended path restrictions.

**漏洞代码** (`mindie_turbo/utils/directory_utils.py:189-214`)

```c
for root, dirs, files in os.walk(dir_path):\n    # Files not checked for symlinks
```

**达成路径**

safe_walk -> check_directory_path -> os.walk

**验证说明**: safe_walk validates subdirectories but not files returned in os.walk. Symlinks in the files list bypass path restrictions. Attackers can place symlink files pointing to arbitrary locations. Impact is limited as function only returns paths (no automatic file operations), but callers may trust the returned paths.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-007-fileutils-symlink-timing] Symlink Check Timing Vulnerability - standardize_path

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindie_turbo/utils/file_utils.py:86-90` @ `standardize_path`
**模块**: utils

**描述**: Symlink check (check_path_is_link) is performed BEFORE os.path.realpath() in standardize_path. The realpath result is NOT re-checked for symlinks. An attacker could create symlink between checks or the realpath could resolve to symlink target without re-validation.

**漏洞代码** (`mindie_turbo/utils/file_utils.py:86-90`)

```c
if check_link:\n    check_path_is_link(path)\npath = os.path.realpath(path)
```

**达成路径**

safe_open -> standardize_path -> check_path_is_link -> os.path.realpath

**验证说明**: Intermediate symlink bypass confirmed: os.path.islink() only checks final component. Paths with symlinked intermediate directories bypass the check. However, exploitation requires local filesystem access to create symlinks AND control of path input via environment variables or config. Attack vector is local, not remote. The realpath() after check mitigates some aspects but the symlink check timing is fundamentally flawed.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Low 漏洞 (1)

### [VULN-010-cli-setattr-injection] Arbitrary Attribute Injection via setattr - _safe_set_attribute

**严重性**: Low | **CWE**: CWE-917 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindie_turbo/utils/cli.py:127-133` @ `_safe_set_attribute`
**模块**: utils
**跨模块**: utils, adaptor

**描述**: _safe_set_attribute uses setattr to set arbitrary attributes on argparse.Namespace. While key validation uses isidentifier(), it does not block Python dunder attributes like __class__, __dict__, __bases__ which could allow object manipulation.

**漏洞代码** (`mindie_turbo/utils/cli.py:127-133`)

```c
setattr(args, key, value)
```

**达成路径**

parse_custom_args -> _safe_set_attribute -> setattr

**验证说明**: isidentifier() allows dunder attributes (__class__, __dict__, __bases__). However, argparse.Namespace is a simple data container with no privileged operations. Modifying dunder attributes has minimal impact - __class__ only changes class reference, __dict__ equals direct attribute modification. This is a code quality issue rather than security vulnerability. No sensitive methods can be overridden.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: -10 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| utils | 0 | 0 | 2 | 1 | 3 |
| **合计** | **0** | **0** | **2** | **1** | **3** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 2 | 66.7% |
| CWE-917 | 1 | 33.3% |
