# 漏洞扫描报告 — 待确认漏洞

**项目**: mind-cluster
**扫描时间**: 2026-04-22T01:24:26.206Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 4 | 44.4% |
| LIKELY | 3 | 33.3% |
| POSSIBLE | 2 | 22.2% |
| **总计** | **9** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 1 | 20.0% |
| Medium | 3 | 60.0% |
| Low | 1 | 20.0% |
| **有效漏洞总计** | **5** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞

1. **[MINDIO-002]** Insecure File Operation (High) - `/component/mindio/acp/python_whl/mindio_acp/mindio_acp/acc_io/acc_io.py:89` @ `save` | 置信度: 70
2. **[TASKD-001]** Command Injection (Medium) - `/component/taskd/taskd/python/framework/agent/base_agent/base_agent.py:87` @ `handle_message` | 置信度: 55
3. **[ADR-002]** Container Escape (Medium) - `/component/ascend-docker-runtime/cli/src/main.c:419` @ `SetupContainer` | 置信度: 50
4. **[ADR-005]** DLL Hijacking (Medium) - `/component/ascend-docker-runtime/destroy/src/main.c:150` @ `DeclareDcmiApiAndCheck` | 置信度: 50
5. **[ADR-004]** Symlink Bypass (Low) - `/component/ascend-docker-runtime/cli/src/utils.c:33` @ `SetAllowLink/CheckLegality` | 置信度: 40

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@/component/ascend-docker-runtime/cli/src/main.c` | CLI | - | - | - |
| `save/load@/component/mindio/acp/python_whl/mindio_acp/mindio_acp/acc_io/acc_io.py` | API | - | - | - |
| `init_taskd_manager@/component/taskd/taskd/api/taskd_manager_api.py` | API | - | - | - |


---

## 3. High 漏洞 (1)

### [MINDIO-002] Insecure File Operation - save

**严重性**: High | **CWE**: CWE-73 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: orchestrator

**位置**: `/component/mindio/acp/python_whl/mindio_acp/mindio_acp/acc_io/acc_io.py:89-90` @ `save`
**模块**: mindio

**描述**: acc_io.py save() function uses os.path.realpath() but depends on torch_save_helper for actual file operations. Need to verify downstream security.

**漏洞代码** (`/component/mindio/acp/python_whl/mindio_acp/mindio_acp/acc_io/acc_io.py:89-90`)

```c
path = os.path.realpath(path); return torch_save_helper(obj, path, open_way)
```

**达成路径**

path (user input) -> os.path.realpath -> torch_save_helper

**验证说明**: User-provided path passed to save() with only os.path.realpath() processing. realpath() only resolves symlinks, does not provide path traversal protection or access control. Could potentially write to arbitrary locations if downstream torch_save_helper lacks proper validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (3)

### [TASKD-001] Command Injection - handle_message

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: orchestrator

**位置**: `/component/taskd/taskd/python/framework/agent/base_agent/base_agent.py:87` @ `handle_message`
**模块**: taskd

**描述**: base_agent.py executes command based on message code without validation. If attacker can send malicious messages, could trigger unintended actions.

**漏洞代码** (`/component/taskd/taskd/python/framework/agent/base_agent/base_agent.py:87`)

```c
self.command_map.get(item.code)(item)
```

**达成路径**

msg_queue -> item.code -> command_map.get -> command execution

**验证说明**: Network messages control which command from command_map is executed. msg_queue receives messages from AgentMessageManager (network source). While command_map limits available commands, attacker could trigger predefined commands (stop_workers, exit_agent, restart_workers) via crafted network messages.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -15 | context: -5 | cross_file: 0

---

### [ADR-002] Container Escape - SetupContainer

**严重性**: Medium | **CWE**: CWE-288 | **置信度**: 50/100 | **状态**: LIKELY | **来源**: orchestrator

**位置**: `/component/ascend-docker-runtime/cli/src/main.c:419-427` @ `SetupContainer`
**模块**: ascend-docker-runtime

**描述**: setns() syscall enters container's mount namespace. If compromised or called with wrong PID, could allow namespace escape or unauthorized mount operations.

**漏洞代码** (`/component/ascend-docker-runtime/cli/src/main.c:419-427`)

```c
ret = EnterNsByPath((const char *)config.containerNsPath, CLONE_NEWNS);
```

**达成路径**

args->pid -> GetNsPath -> containerNsPath -> EnterNsByPath -> setns

**验证说明**: Potential namespace escape via setns. PID is validated (must be < pid_max) but attacker could potentially specify a malicious process PID. Attack path is limited as this is a docker runtime hook called by runc, not directly by user.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [ADR-005] DLL Hijacking - DeclareDcmiApiAndCheck

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: orchestrator

**位置**: `/component/ascend-docker-runtime/destroy/src/main.c:150-154` @ `DeclareDcmiApiAndCheck`
**模块**: ascend-docker-runtime

**描述**: dlopen loads libdcmi.so without full path. If attacker places malicious libdcmi.so in library search path, could lead to arbitrary code execution.

**漏洞代码** (`/component/ascend-docker-runtime/destroy/src/main.c:150-154`)

```c
*handle = dlopen("libdcmi.so", RTLD_LAZY);
```

**达成路径**

dlopen("libdcmi.so") -> libdcmi.so loading

**验证说明**: dlopen uses relative path 'libdcmi.so' which relies on library search path. Post-load verification via dlinfo+CheckAExternalFile exists but happens AFTER loading - malicious code could execute during dlopen. Requires attacker to place library in search path.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (1)

### [ADR-004] Symlink Bypass - SetAllowLink/CheckLegality

**严重性**: Low | **CWE**: CWE-61 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: orchestrator

**位置**: `/component/ascend-docker-runtime/cli/src/utils.c:33-407` @ `SetAllowLink/CheckLegality`
**模块**: ascend-docker-runtime

**描述**: g_allowLink flag can be set via --allow-link True command argument, disabling symlink security check. Attackers could use symlinks to bypass path validation.

**漏洞代码** (`/component/ascend-docker-runtime/cli/src/utils.c:33-407`)

```c
static bool g_allowLink = false; ... (!g_allowLink && (S_ISLNK(fileStat.st_mode) != 0))
```

**达成路径**

--allow-link True -> LinkCheckCmdArgParser -> SetAllowLink(true) -> g_allowLink -> symlink check bypassed

**验证说明**: Security feature (symlink check) can be disabled via --allow-link True command argument. Default is secure (false), but misconfiguration by admin could enable symlink bypass. Limited attack surface as parameter is controlled by container configuration.

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -10 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| ascend-docker-runtime | 0 | 0 | 2 | 1 | 3 |
| mindio | 0 | 1 | 0 | 0 | 1 |
| taskd | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **1** | **3** | **1** | **5** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 1 | 20.0% |
| CWE-73 | 1 | 20.0% |
| CWE-61 | 1 | 20.0% |
| CWE-426 | 1 | 20.0% |
| CWE-288 | 1 | 20.0% |
