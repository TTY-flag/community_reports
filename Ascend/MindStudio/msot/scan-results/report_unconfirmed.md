# 漏洞扫描报告 — 待确认漏洞

**项目**: MindStudio Operator Tools (msOT)
**扫描时间**: 2026-04-21T01:17:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 14 | 60.9% |
| CONFIRMED | 6 | 26.1% |
| LIKELY | 2 | 8.7% |
| POSSIBLE | 1 | 4.3% |
| **总计** | **23** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Medium | 3 | 100.0% |
| **有效漏洞总计** | **3** | - |
| 误报 (FALSE_POSITIVE) | 14 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-BUILD-009]** Git Remote Command Execution via Hooks (Medium) - `download_dependencies.py:66` @ `_download_submodule_recursively` | 置信度: 70
2. **[VULN-CROSS-001]** Cross-Module Credential Flow: Build Chain (Medium) - `build.py:72` @ `BuildManager.run` | 置信度: 70
3. **[VULN-BUILD-004]** Trusted Configuration File Without Integrity Protection (Medium) - `download_dependencies.py:47` @ `__init__` | 置信度: 50

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `BuildManager.__init__@build.py` | cmdline | untrusted_local | Python CLI工具，通过argparse解析命令行参数，本地用户可通过传入恶意参数影响构建过程 | 构建管理器初始化，解析命令行参数 |
| `main@download_dependencies.py` | cmdline | untrusted_local | Python CLI工具，解析命令行参数决定下载行为，本地用户可控制下载源 | 依赖下载入口，解析命令行参数 |
| `args_prase@package/script/parser.py` | cmdline | untrusted_local | Python CLI工具，通过argparse解析xml文件路径和delivery路径，本地用户可指定任意路径 | 打包解析器入口，解析XML配置文件 |
| `main@example/quick_start/public/ctr_in.py` | cmdline | untrusted_local | Docker容器管理CLI工具，解析容器名称、用户名和镜像名，本地用户可控制Docker操作 | Docker容器管理入口 |
| `get_npu_id@example/quick_start/public/get_ai_soc_version.py` | env | semi_trusted | 读取NPU设备信息需要系统已安装CANN软件包，本地有权限用户才能执行npu-smi命令 | NPU芯片型号检测入口 |
| `OpRunner.__init__@example/quick_start/msopgen/caller/exec.py` | env | semi_trusted | 依赖环境变量REAL_ASCEND_INSTALL_PATH，该变量由运行脚本run.sh设置，需要正确的昇腾环境 | 算子执行器初始化，读取环境变量 |
| `__main__@example/quick_start/mskpp/mskpp_demo.py` | env | semi_trusted | 依赖环境变量MY_STUDY_VAR_CHIP_SOC_TYPE指定芯片型号，需要正确的昇腾环境配置 | msKPP示例入口，读取芯片型号环境变量 |
| `main@example/quick_start/msopgen/caller/main.cpp` | cmdline | untrusted_local | C++ CLI程序，通过argv[1]接收deviceId参数，本地用户可控制NPU设备选择 | 算子调用主程序入口 |
| `OpRunner.run@example/quick_start/msopgen/caller/exec.py` | cmdline | untrusted_local | 可通过sys.argv[1]传入自定义NPU ID，本地用户可控制设备选择 | 算子执行入口，可接收命令行参数 |

**其他攻击面**:
- 命令行参数解析: argparse.ArgumentParser() (build.py, download_dependencies.py, parser.py, ctr_in.py)
- 环境变量读取: os.environ.get() (exec.py, mskpp_demo.py)
- 外部命令执行: subprocess.run() (build.py, download_dependencies.py, parser.py, exec.py, get_ai_soc_version.py, ctr_in.py)
- 文件系统操作: shutil.copy(), os.makedirs(), Path.read_text() (download_dependencies.py, parser.py, keep_soc_info.py)
- Git操作: subprocess.run(['git', ...]) (download_dependencies.py)
- Docker操作: subprocess.run(['docker', ...]) (ctr_in.py)
- NPU设备访问: npu-smi命令调用 (get_ai_soc_version.py, exec.py)

---

## 3. Medium 漏洞 (3)

### [VULN-BUILD-009] Git Remote Command Execution via Hooks - _download_submodule_recursively

**严重性**: Medium | **CWE**: CWE-88 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `download_dependencies.py:66-73` @ `_download_submodule_recursively`
**模块**: build_tools

**描述**: The --revision argument flows through git checkout command. When checking out a branch that contains malicious .git/hooks, git may execute pre-commit/post-checkout hooks automatically. Combined with force_latest_submodules feature (--remote flag), this could trigger execution of untrusted code from remote repositories.

**漏洞代码** (`download_dependencies.py:66-73`)

```c
if self.args.revision:\n    self._exec_shell_cmd(["git", "checkout", self.args.revision], cwd=mod_dir)\ncmd = [sys.executable, script.name] + ([-r, self.args.revision] if self.args.revision else [])
```

**达成路径**

CLI --revision -> BuildManager -> DependencyManager -> git checkout -> submodule download_dependencies.py recursion

**验证说明**: --revision argument flows directly from CLI to git checkout command. Can trigger Git hooks execution if submodule repo contains malicious hooks. Combined with --remote flag (force_latest_submodules feature) could pull malicious code from compromised remote repos. Attack requires: (1) submodule repo containing malicious hooks, OR (2) attacker controls revision to point to malicious branch.

**评分明细**: base: 30 | reachability: 30 | reachability_reason: direct_external - CLI argument --revision | controllability: 10 | controllability_reason: length_only - revision format constrained by git checkout, requires malicious hooks pre-existing in submodule repo | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CROSS-001] Cross-Module Credential Flow: Build Chain - BuildManager.run

**严重性**: Medium | **CWE**: CWE-288 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `build.py:72-89` @ `BuildManager.run`
**模块**: build_tools
**跨模块**: build_tools,build_tools

**描述**: [CREDENTIAL_FLOW] 跨模块凭证传递链：build.py → download_dependencies.py。--revision 参数从BuildManager传递到DependencyManager，最终流向git checkout命令。结合递归子模块下载机制，攻击者可通过恶意revision参数触发Git Hook执行，影响整个构建链条。

**达成路径**

CLI --revision → BuildManager → DependencyManager → git checkout → submodule recursion

**验证说明**: Cross-module credential flow verified: build.py:72-73 imports and calls DependencyManager with parsed_arguments, passing --revision to download_dependencies.py. Revision flows through git checkout chain at line 69. Same vulnerability as VULN-BUILD-009 from cross-module perspective.

**评分明细**: base: 30 | reachability: 30 | reachability_reason: direct_external - CLI --revision flows through BuildManager to DependencyManager | controllability: 10 | controllability_reason: length_only - requires malicious hooks in submodule repo | mitigations: 0 | context: 0 | cross_file: 0 | cross_file_reason: chain_complete - BuildManager.run() -> DependencyManager(parsed_arguments).run() -> _download_submodule_recursively() -> git checkout

---

### [VULN-BUILD-004] Trusted Configuration File Without Integrity Protection - __init__

**严重性**: Medium | **CWE**: CWE-494 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `download_dependencies.py:47-48` @ `__init__`
**模块**: build_tools

**描述**: dependencies.json is read and trusted without integrity verification. URLs and submodule paths from this file are used directly for downloads. If this file is modified (e.g., by supply chain attack, compromised repo, or local tampering), attackers can redirect downloads to malicious artifacts or inject malicious submodule paths.

**漏洞代码** (`download_dependencies.py:47-48`)

```c
self.config = json.loads((self.root / "dependencies.json").read_text())
```

**达成路径**

dependencies.json -> DependencyManager.config -> proc_submodule/proc_artifact -> remote downloads

**验证说明**: Configuration file lacks integrity protection. However, actual threat is limited: (1) artifacts array empty - no binary downloads, (2) submodule URLs defined in separate .gitmodules file, not dependencies.json. Attacker needs local file write access to inject malicious submodule/artifact URLs.

**评分明细**: base: 30 | reachability: 5 | reachability_reason: internal_only - requires attacker with local file write permission | controllability: 15 | controllability_reason: partial - submodule list constrained by .gitmodules definitions | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| build_tools | 0 | 0 | 3 | 0 | 3 |
| **合计** | **0** | **0** | **3** | **0** | **3** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-88 | 1 | 33.3% |
| CWE-494 | 1 | 33.3% |
| CWE-288 | 1 | 33.3% |
