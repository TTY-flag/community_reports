# 漏洞扫描报告 — 已确认漏洞

**项目**: MindStudio-Probe
**扫描时间**: 2025-04-20T20:39:00+08:00
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 16 | 47.1% |
| CONFIRMED | 7 | 20.6% |
| FALSE_POSITIVE | 6 | 17.6% |
| POSSIBLE | 5 | 14.7% |
| **总计** | **34** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 4 | 57.1% |
| High | 1 | 14.3% |
| Medium | 1 | 14.3% |
| **有效漏洞总计** | **7** | - |
| 误报 (FALSE_POSITIVE) | 6 | - |

### 1.3 Top 10 关键漏洞

1. **[atb_probe_cwe426_dlopen_001]** untrusted_search_path (Critical) - `ccsrc/atb_probe/atb_probe.cpp:171` @ `GetCurrentDeviceId` | 置信度: 95
2. **[SEC-DLOPEN-ROOT-BYPASS-001]** privilege_bypass (Critical) - `ccsrc/atb_probe/atb_probe.cpp:179` @ `GetCurrentDeviceId` | 置信度: 95
3. **[SEC-ACL-SAVE-BYPASS-001]** api_bypass (Critical) - `ccsrc/aclgraph_dump/aclgraph_dump.cpp:341` @ `acl_save_impl` | 置信度: 92
4. **[CROSS-MODULE-002]** cross_module_data_flow (Critical) - `ccsrc/aclgraph_dump/aclgraph_dump.cpp:341` @ `acl_save_impl` | 置信度: 85
5. **[VULN-ACLGRAPH-001]** path_traversal (High) - `ccsrc/aclgraph_dump/aclgraph_dump.cpp:341` @ `acl_save_impl` | 置信度: 85
6. **[VULN-ACLGRAPH-002]** missing_path_validation (Medium) - `ccsrc/aclgraph_dump/aclgraph_dump.cpp:92` @ `build_final_path` | 置信度: 60
7. **[VUL-CORE-001]** zip_slip (HIGH) - `python/msprobe/core/common/file_utils.py:943` @ `extract_zip` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main()@python/msprobe/msprobe.py` | cmdline | - | - | - |
| `InitPrecisionDebugger@ccsrc/adump/if/python/PrecisionDebuggerIfPython.cpp` | decorator | - | - | - |

**其他攻击面**:
- [object Object]
- [object Object]
- [object Object]

---

## 3. Critical 漏洞 (4)

### [atb_probe_cwe426_dlopen_001] untrusted_search_path - GetCurrentDeviceId

**严重性**: Critical | **CWE**: CWE-426 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `ccsrc/atb_probe/atb_probe.cpp:171-195` @ `GetCurrentDeviceId`
**模块**: atb_probe

**描述**: dlopen loads library from ASCEND_TOOLKIT_HOME environment variable with flawed owner validation - when running as root, owner check is bypassed

**漏洞代码** (`ccsrc/atb_probe/atb_probe.cpp:171-195`)

```c
dlopen(ascendclPath.c_str(), RTLD_LAZY) - owner check if (getuid() != 0 && ...) bypassed for root
```

**达成路径**

ASCEND_TOOLKIT_HOME (env) -> ascendclPath -> dlopen -> arbitrary code execution

**验证说明**: Duplicate of SEC-DLOPEN-ROOT-BYPASS-001. Root bypass confirmed at line 179.

---

### [SEC-DLOPEN-ROOT-BYPASS-001] privilege_bypass - GetCurrentDeviceId

**严重性**: Critical | **CWE**: CWE-250 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `ccsrc/atb_probe/atb_probe.cpp:179` @ `GetCurrentDeviceId`
**模块**: atb_probe

**描述**: dlopen owner validation bypassed when running as root user. The condition `if (getuid() != 0 && fileStat.st_uid != getuid())` skips owner check entirely when process runs as root (uid=0), allowing arbitrary library loading via ASCEND_TOOLKIT_HOME environment variable.

**漏洞代码** (`ccsrc/atb_probe/atb_probe.cpp:179`)

```c
if (getuid() != 0 && fileStat.st_uid != getuid()) { return deviceId; } // root bypasses check
```

**达成路径**

ASCEND_TOOLKIT_HOME (env) -> ascendclPath -> stat() -> owner check bypassed for root -> dlopen() -> arbitrary code execution

**验证说明**: Source code confirms: line 179 `if (getuid() != 0 && fileStat.st_uid != getuid())` skips owner check when uid=0 (root). This allows arbitrary library loading via ASCEND_TOOLKIT_HOME env var when running as root.

---

### [SEC-ACL-SAVE-BYPASS-001] api_bypass - acl_save_impl

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 92/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `ccsrc/aclgraph_dump/aclgraph_dump.cpp:341-346` @ `acl_save_impl`
**模块**: cross_module
**跨模块**: pytorch → aclgraph_dump

**描述**: acl_save Python API can bypass validation by direct C extension call. The C++ acl_save_impl receives arbitrary path and writes without validation. Python callers may bypass path validation if they call the C extension directly or if Python validation is incomplete.

**漏洞代码** (`ccsrc/aclgraph_dump/aclgraph_dump.cpp:341-346`)

```c
acl_save_impl(tensor, path) -> build_final_path preserves directory -> write_pt_or_throw
```

**达成路径**

[PYTHON] acl_save(tensor, path) -> [CPP:aclgraph_dump] acl_save_impl -> build_final_path (no validation) -> arbitrary file write

**验证说明**: build_final_path() (line 92-104) preserves entire directory path from user input without validation. Only modifies filename portion. User can write to arbitrary locations via path traversal or absolute paths.

---

### [CROSS-MODULE-002] cross_module_data_flow - acl_save_impl

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `ccsrc/aclgraph_dump/aclgraph_dump.cpp:341-346` @ `acl_save_impl`
**模块**: cross_module
**跨模块**: pytorch → aclgraph_dump

**描述**: Cross-language vulnerability: Python acl_save function bypasses Python validation when called directly, C++ writes to arbitrary path

**漏洞代码** (`ccsrc/aclgraph_dump/aclgraph_dump.cpp:341-346`)

```c
Python acl_save(tensor, path) -> C++ aclgraph_dump::acl_save_impl -> arbitrary file write
```

**达成路径**

[PYTHON:pytorch] acl_save(path) -> [CPP:aclgraph_dump] acl_save_impl -> build_final_path -> write_pt_or_throw

**验证说明**: Python acl_save accepts arbitrary path with NO validation. C++ acl_save_impl passes to build_final_path which only modifies filename, preserving directory traversal. Direct file write via ofstream. Complete exploitation path.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. High 漏洞 (1)

### [VULN-ACLGRAPH-001] path_traversal - acl_save_impl

**严重性**: High | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `ccsrc/aclgraph_dump/aclgraph_dump.cpp:341-346` @ `acl_save_impl`
**模块**: aclgraph_dump
**跨模块**: aclgraph_dump → pytorch

**描述**: acl_save_impl receives path directly from Python and writes to arbitrary locations - build_final_path preserves directory path without validation

**漏洞代码** (`ccsrc/aclgraph_dump/aclgraph_dump.cpp:341-346`)

```c
User-provided path -> build_final_path (no validation) -> write_pt_or_throw
```

**达成路径**

Python acl_save(x, path) → acl_save_impl(path) → build_final_path(path) [preserves directory] → write_pt_or_throw(final_path) [arbitrary file write]

**验证说明**: Path traversal confirmed: build_final_path preserves directory path unchanged (line 103), no validation for ../ absolute paths or symlinks. write_pt_or_throw writes directly to user-controlled path. Compare with atb_probe which uses SafetyGuard validation.

**评分明细**: base_score: 30 | reachability: direct_external | reachability_points: 30 | controllability: full | controllability_points: 25 | mitigations:  | mitigation_points: 0 | context:  | context_points: 0 | cross_file: chain_complete | cross_file_points: 0 | total: 85

---

## 5. Medium 漏洞 (1)

### [VULN-ACLGRAPH-002] missing_path_validation - build_final_path

**严重性**: Medium | **CWE**: CWE-73 | **置信度**: 60/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `ccsrc/aclgraph_dump/aclgraph_dump.cpp:92-104` @ `build_final_path`
**模块**: aclgraph_dump

**描述**: build_final_path extracts filename but preserves directory path unchanged - no validation for ../ absolute paths symlinks

**漏洞代码** (`ccsrc/aclgraph_dump/aclgraph_dump.cpp:92-104`)

```c
path.substr(0, last_slash + 1) + oss_name.str() - directory preserved
```

**达成路径**

path input → build_final_path → filename extracted, directory preserved unchanged

**验证说明**: Root cause of VULN-ACLGRAPH-001: build_final_path function extracts filename but preserves directory path unchanged without any validation. Missing checks for: parent directory traversal (../), absolute paths, symlinks, allowed directories.

**评分明细**: base_score: 30 | reachability: internal_only | reachability_points: 5 | controllability: full | controllability_points: 25 | mitigations:  | mitigation_points: 0 | context:  | context_points: 0 | total: 60

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| aclgraph_dump | 0 | 1 | 1 | 0 | 2 |
| atb_probe | 2 | 0 | 0 | 0 | 2 |
| core | 0 | 0 | 0 | 0 | 0 |
| cross_module | 2 | 0 | 0 | 0 | 2 |
| **合计** | **4** | **1** | **1** | **0** | **6** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 4 | 57.1% |
| CWE-73 | 1 | 14.3% |
| CWE-426 | 1 | 14.3% |
| CWE-250 | 1 | 14.3% |
