# OMSDK 漏洞扫描报告 — 已确认漏洞

**项目**: OMSDK (华为边缘管理系统 SDK)
**扫描时间**: 2026-04-21
**报告范围**: 仅包含 CONFIRMED 状态的漏洞 (置信度 ≥80)

---

## 执行摘要

本次扫描对 OMSDK 项目进行了全面的漏洞分析，发现了 **4 个已确认的真实漏洞**（排除正面发现），其中 **1 个 Critical 级别**、**3 个 High 级别**。主要风险集中在 **TOCTOU 竞态条件** 和 **SSRF 验证缺失**。

### 关键发现

| 风险等级 | 发现 |
|---------|------|
| **Critical** | TOCTOU 竞态条件导致权限提升风险 (lpeblock 模块) |
| **High** | 符号链接检查逻辑缺陷，安全验证可绕过 (fault_check 模块) |
| **High** | TOCTOU 竞态条件导致 root 进程可执行非 root 控制代码 (lpeblock 模块) |
| **High** | SSRF 验证缺失，可访问内网/云元数据服务 (om_event_subscription 模块) |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 说明 |
|------|------|------|
| CONFIRMED | 5 | 确认漏洞 (含 1 个正面发现) |
| LIKELY | 25 | 高可能性漏洞 |
| POSSIBLE | 41 | 可能漏洞 |
| FALSE_POSITIVE | 2 | 误报/排除 |
| **总计** | **73** | - |

### 1.2 严重性分布 (CONFIRMED)

| 严重性 | 数量 |
|--------|------|
| Critical | 1 |
| High | 3 |
| Info | 1 (安全控制验证 - 正面发现) |
| **总计** | **5** |

---

## 2. Top 4 关键漏洞详情

### VULN-DF-LPE-003: TOCTOU 竞态条件 (Critical)

| 属性 | 值 |
|------|-----|
| **CWE** | CWE-367 |
| **文件** | src/om/platform/MindXOM_SDK/src/cpp/lpeblock/lpeblock.c |
| **行号** | 161-201 |
| **函数** | lpe_change_permission_check |
| **置信度** | 98% |

**漏洞描述**: 在 lpe_change_permission_check() 中，先调用 lstat() 获取符号链接信息，再调用 stat() 获取目标文件信息，两次调用之间存在竞态窗口。攻击者可在两次检查之间修改符号链接目标，绕过所有者一致性检查。

**数据流**:
```
path → lstat(path, &st) [check symlink owner]
      → [RACE WINDOW: attacker can change symlink target]
      → stat(path, &real_st) [check target owner]
      → owner comparison → libc_chmod/libc_chown
```

**修复建议**: 使用 fstatat() 配合 AT_SYMLINK_NOFOLLOW 标志，或使用 openat() + fstat() 组合实现原子性检查。

---

### VULN-FC-001: 符号链接检查逻辑缺陷 (High)

| 属性 | 值 |
|------|-----|
| **CWE** | CWE-59 |
| **文件** | src/om/platform/MindXOM_SDK/src/cpp/fault_check/fault_check.c |
| **行号** | 131-153 |
| **函数** | check_cert_security |
| **置信度** | 95% |

**漏洞描述**: check_cert_security() 使用 stat() 代替 lstat()，导致 S_ISLNK() 永远无法检测符号链接。恶意符号链接可绕过安全验证。

**修复建议**: 将 stat() 替换为 lstat() 来正确检测符号链接。

---

### VULN-DF-LPE-002: TOCTOU 竞态条件 (High)

| 属性 | 值 |
|------|-----|
| **CWE** | CWE-367 |
| **文件** | src/om/platform/MindXOM_SDK/src/cpp/lpeblock/lpeblock.c |
| **行号** | 138-155 |
| **函数** | lpe_exe_check |
| **置信度** | 95% |

**漏洞描述**: 在 lpe_exe_check() 中，stat() 检查与 execve() 调用之间存在竞态条件。攻击者可在检查后替换可执行文件，导致 root 进程执行非 root 用户控制的代码。

**修复建议**: 使用 openat() 打开文件获取 fd，然后通过 fd 使用 fstat() 检查，最后通过 fdexecve() (或 fexecve()) 执行，确保原子性。

---

### VULN-SSRF-003: SSRF 验证缺失 (High)

| 属性 | 值 |
|------|-----|
| **CWE** | CWE-918 |
| **文件** | src/om/src/app/sys_om/RedfishServer/om_event_subscription/param_checker.py |
| **行号** | 77-96 |
| **函数** | DestinationChecker |
| **置信度** | 85% |

**漏洞描述**: DestinationChecker 只做正则验证 HTTPS URL 格式，不阻止私有 IP (127.0.0.1, 192.168.x.x, 10.x.x.x)、云元数据端点 (169.254.169.254) 或 DNS 重绑定攻击。

**修复建议**: 添加 URL 目标 IP 地址验证，阻止私有 IP 范围和云元数据地址。

---

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| lpeblock | 1 | 1 | - | - | 2 |
| fault_check | - | 1 | - | - | 1 |
| om_event_subscription | - | 1 | - | - | 1 |
| om_fd_msg_process | - | - | - | Info | 1 (正面发现) |

---

## 4. CWE 分布

| CWE | 类型 | 数量 |
|-----|------|------|
| CWE-367 | TOCTOU 竞态条件 | 2 |
| CWE-59 | 符号链接跟随 | 1 |
| CWE-918 | SSRF | 1 |

---

## 5. 修复优先级建议

1. **立即修复 (Critical)**:
   - VULN-DF-LPE-003: TOCTOU 竞态条件影响 chmod/chown 系统调用

2. **高优先级修复 (High)**:
   - VULN-FC-001: 符号链接检查缺陷影响证书安全验证
   - VULN-DF-LPE-002: TOCTOU 竞态条件影响 execve 系统调用
   - VULN-SSRF-003: SSRF 验证缺失影响事件订阅功能

---

## 6. 深度分析报告

详细利用分析报告存放于:
- `/scan-results/details/VULN-DF-LPE-003.md`
- `/scan-results/details/VULN-FC-001.md`

---

**报告生成**: 2026-04-21
**扫描引擎**: OpenCode Multi-Agent Vulnerability Scanner