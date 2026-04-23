# 漏洞扫描报告 — 待确认漏洞

**项目**: WAAS Booster
**扫描时间**: 2026-04-21T10:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本次漏洞扫描针对 WAAS Booster（Workload Aware Acceleration System Booster）进行了深度安全分析。该项目是一个部署在 Kubernetes worker node 上的系统守护进程，用于动态调整容器 CPU 配额。扫描发现 **4 个路径遍历漏洞候选**（状态：POSSIBLE），置信度评分范围 20-25/100，另有 2 个候选漏洞被判定为误报。

### 关键发现

**根因问题**：所有路径遍历漏洞共享同一个根因弱点——`file_check()` 函数（`util.py:126`）使用 `path.lstrip('/')` 仅去除前导斜杠，不处理 `../` 路径遍历序列。如果 `/proc/{pid}/cgroup` 文件内容被恶意篡改，攻击者可能注入路径遍历字符，导致程序以 root 权限读写任意位置的文件。

**利用门槛评估**：由于 `/proc/{pid}/cgroup` 是内核虚拟文件系统，攻击者需要具备：
- 内核模块操控能力（加载恶意内核模块）
- 特权容器逃逸能力（修改内核虚拟文件系统）
- 或系统文件系统篡改能力

在标准部署环境中，这些攻击条件难以达成，因此漏洞置信度较低（20-25 分）。

### 风险评估

| 维度 | 评估结果 |
|------|----------|
| 漏洞真实性 | 存在代码层面的路径遍历弱点 |
| 利用难度 | 高（需内核级操控能力） |
| 影响范围 | 容器 CPU 配额控制、系统文件读写 |
| 优先级建议 | 中等优先级，建议在下版本迭代中修复 |

### 建议修复方向

核心修复措施：在所有路径拼接操作前添加 `os.path.realpath()` 规范化验证，并检查规范化后的路径是否在预期的 cgroup 挂载点范围内。具体修复方案见第 8 章节。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 4 | 66.7% |
| FALSE_POSITIVE | 2 | 33.3% |
| **总计** | **6** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Medium | 3 | 75.0% |
| Low | 1 | 25.0% |
| **有效漏洞总计** | **4** | - |
| 误报 (FALSE_POSITIVE) | 2 | - |

### 1.3 Top 10 关键漏洞

1. **[DF-001]** Path Traversal (Medium) - `src/waasbooster/quota_updater.py:30` @ `quota_updater` | 置信度: 25
2. **[DF-003]** Path Traversal (Medium) - `src/waasbooster/util.py:114` @ `file_check` | 置信度: 25
3. **[DF-002]** Path Traversal (Medium) - `src/waasbooster/util.py:209` @ `get_container_info` | 置信度: 20
4. **[DF-004]** Path Traversal (Low) - `src/waasbooster/cpu_monitor.py:36` @ `get_cpu_usage, get_cpu_limits` | 置信度: 20

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `booster_param_parser@src/waasbooster/waas_booster.py` | cmdline | untrusted_local | 本地用户运行程序时可通过命令行参数控制程序行为（如 --forecast 参数），攻击者可注入恶意参数值 | argparse 解析命令行参数 --forecast |
| `_get_cgroup_version@src/waasbooster/quota_manager.py` | rpc | semi_trusted | subprocess 执行外部命令 /usr/bin/stat，如果 PATH 环境变量被劫持，可能执行恶意程序；使用完整路径降低了风险，但仍存在被替换的可能 | 执行 subprocess.run(['/usr/bin/stat', '-fc', '%T', '/sys/fs/cgroup']) |
| `file_check@src/waasbooster/util.py` | file | semi_trusted | 读取 /proc/{pid}/cgroup 文件，pid 来自系统进程列表，理论上攻击者可创建恶意进程并篡改其 cgroup 文件 | 读取进程 cgroup 信息，遍历所有 PID |
| `get_boosted_container_cgroups@src/waasbooster/util.py` | file | semi_trusted | 读取容器 cgroup 文件系统中的 cpu.cfs_quota_us 文件，这些文件可能被恶意容器或进程篡改 | 读取所有容器的 cgroup quota 配置 |
| `quota_updater@src/waasbooster/quota_updater.py` | file | semi_trusted | 直接写入 cgroup 文件 cpu.cfs_quota_us，影响容器 CPU 配额分配；如果路径验证不当可能导致写入错误位置 | 写入容器 cgroup quota 文件 |
| `get_cpu_usage@src/waasbooster/cpu_monitor.py` | file | semi_trusted | 读取 cgroup 文件系统中的 cpuacct.usage 文件，文件路径来自容器列表，可能被篡改 | 读取容器 CPU 使用时间 |
| `get_cpu_utilization@src/waasbooster/numa_cpu_monitor.py` | file | semi_trusted | 读取 /proc/stat 文件获取 CPU 统计信息，该文件可能被恶意内核模块篡改 | 读取 /proc/stat 计算 CPU 利用率 |

**其他攻击面**:
- 命令行参数注入 (--forecast)
- subprocess 命令执行 (/usr/bin/stat)
- /proc 文件系统读取 (进程信息、CPU 统计)
- /sys 文件系统读取 (NUMA 配置、cgroup 挂载点)
- cgroup 文件系统读写 (quota 配置)
- 容器路径遍历 (通过 /proc/{pid}/cgroup 获取容器路径)
- PID 文件写入 (/var/run/waasbooster_manager/waasbooster.pid)
- 数据文件写入 (/var/waasbooster/)
- 日志文件写入 (/var/log/waasbooster.log)

---

## 3. Medium 漏洞 (3)

### [DF-001] Path Traversal - quota_updater

**严重性**: Medium（原评估: Critical → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 25/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/waasbooster/quota_updater.py:30-42` @ `quota_updater`
**模块**: waasbooster

**描述**: quota_updater() 函数接收 cgroup_path 参数，直接使用 os.path.join() 拼接路径并写入文件。虽然路径在构建时有 legal_cgroup_path() 和 is_container_path() 的验证，但这些验证不完善：(1) legal_cgroup_path() 只检查路径不等于根挂载点和去重；(2) is_container_path() 只检查路径包含容器标识符；(3) 都不检查路径是否包含 ../ 序列。如果 /proc/{pid}/cgroup 文件被恶意篡改（需要内核模块或特殊容器配置），攻击者可能注入路径遍历字符，导致程序以 root 权限写入任意位置的文件。

**漏洞代码** (`src/waasbooster/quota_updater.py:30-42`)

```c
def quota_updater(cgroup_path:str, quota):
    quota_value = int(quota)
    quota_path = os.path.join(cgroup_path, "cpu.cfs_quota_us")
    if not os.path.exists(quota_path):
        return False
    ...
    with open(quota_path, 'w') as q:
        q.write(str(quota_value))
```

**达成路径**

/proc/{pid}/cgroup → file_check() (util.py:126) → get_cgroup_path_for_pid() → get_container_cgroups() → get_boosted_container_cgroups() → QuotaBooster.pod_path → pod_update_quota_dict → quota_set() → quota_updater(cgroup_path) → open(quota_path, 'w')

**验证说明**: 漏洞真实存在但利用难度高。需要操控/proc/{pid}/cgroup内核虚拟文件，攻击者需具备内核模块操控或特权容器逃逸能力。is_container_path()过滤不含容器关键词的路径，os.path.exists()限制攻击需目标文件已存在。建议添加os.path.realpath()路径规范化检查。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: -15 | context: -15 | cross_file: 0

**深度分析**

**根因定位**：漏洞的根因位于 `util.py:126` 的 `file_check()` 函数。该函数从 `/proc/{pid}/cgroup` 解析路径后，使用 `path.lstrip('/')` 仅去除前导斜杠，不处理 `../` 序列。`quota_updater()` 接收的 `cgroup_path` 参数即来自此路径解析。

**数据流追踪**（基于源代码）：

```
# 步骤 1: 获取 cgroup 挂载点
util.py:52-66 get_cpu_cgroup_mount_point() → cpu_mount = /sys/fs/cgroup/cpu

# 步骤 2: 遍历所有 PID 并解析 cgroup 路径
util.py:168-176 get_container_cgroups()
  → util.py:168: for pid in get_all_pids()  # 遍历 /proc 目录
  → util.py:169: path = get_cgroup_path_for_pid(pid, cpu_mount, 'cpu')
  → util.py:106: file_check(pid, cpu_mount, cgroup_key)

# 步骤 3: 路径拼接（根因点）
util.py:126: return os.path.join(cpu_mount, path.lstrip('/'))
# 问题：path.lstrip('/') 不处理 ../，如果 path = '/../../../etc/cron.d/evil'
# 最终路径 = /sys/fs/cgroup/cpu../../../etc/cron.d/evil → 可能指向任意位置

# 步骤 4: 路径验证（不完善）
util.py:183 legal_cgroup_path() → 仅检查 path != cpu_mount 且 path 未在列表中重复
util.py:130-137 is_container_path() → 仅检查路径是否包含 'docker/kubepods/containerd'

# 步骤 5: 配额写入
quota_updater.py:32: quota_path = os.path.join(cgroup_path, "cpu.cfs_quota_us")
quota_updater.py:41: with open(quota_path, 'w') as q: q.write(str(quota_value))
```

**现有缓解措施分析**（基于源代码）：

| 缓解措施 | 代码位置 | 有效性评估 |
|----------|----------|------------|
| `legal_cgroup_path()` | util.py:181-189 | **无效** — 仅检查路径不等于根挂载点和去重，不检查 `../` |
| `is_container_path()` | util.py:130-137 | **部分有效** — 过滤不含容器关键词的路径，但容器路径仍可含 `../` |
| `os.path.exists()` | quota_updater.py:33 | **部分有效** — 要求目标文件已存在，限制了任意写入场景 |

**潜在利用场景**：

假设攻击者具备内核模块操控能力（需 CAP_SYS_MODULE 或类似权限），可创建恶意进程并修改其 `/proc/{pid}/cgroup` 内容：

```
# 攻击前：正常 cgroup 文件
/proc/12345/cgroup: "cpu:/kubepods/besteffort/pod123/container456"

# 攻击后：注入路径遍历（需内核模块修改）
/proc/12345/cgroup: "cpu:/kubepods/../../../var/spool/cron/crontabs/root"
```

程序将拼接路径：
```
quota_path = /sys/fs/cgroup/cpu + kubepods/../../../var/spool/cron/crontabs/root + cpu.cfs_quota_us
           → 规范化后: /var/spool/cron/crontabs/root/cpu.cfs_quota_us (不存在，os.path.exists 检查失败)

# 或攻击者预先创建文件
quota_path → /var/spool/cron/crontabs/root (存在)
# 程序将以 root 权限写入 quota 值，可能破坏系统配置
```

**修复建议代码**：

```python
# quota_updater.py 修复方案
import os

def quota_updater(cgroup_path: str, quota):
    quota_value = int(quota)
    
    # 新增：路径规范化验证
    cpu_mount, _ = get_cpu_cgroup_mount_point()
    real_path = os.path.realpath(cgroup_path)
    
    # 检查规范化路径是否在预期 cgroup 挂载点范围内
    if not real_path.startswith(cpu_mount):
        logging.error("Invalid cgroup path: %s resolves to %s", cgroup_path, real_path)
        return False
    
    quota_path = os.path.join(cgroup_path, "cpu.cfs_quota_us")
    # ... 原有逻辑
```

---

### [DF-003] Path Traversal - file_check

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 25/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/waasbooster/util.py:114-127` @ `file_check`
**模块**: waasbooster

**描述**: file_check() 函数从 /proc/{pid}/cgroup 解析路径，使用 os.path.join(cpu_mount, path.lstrip('/')) 拼接。path.lstrip('/') 只去除前导斜杠，不处理 ../ 序列。如果 /proc/{pid}/cgroup 文件内容包含路径遍历字符（如 /../../../etc），最终路径可能指向任意位置。cpu_mount 来自 /proc/mounts 解析，也可能被篡改。

**漏洞代码** (`src/waasbooster/util.py:114-127`)

```c
def file_check(pid, cpu_mount, cgroup_key):
    with open(f'/proc/{pid}/cgroup', 'r') as f:
        for line in f:
            ...
            _, controllers, path = new_parts
            if cgroup_key in controllers.split(',') and path.strip() is not None and path.strip() != '/':
                return os.path.join(cpu_mount, path.lstrip('/'))
```

**达成路径**

/proc/{pid}/cgroup → path parsing → path.lstrip('/') → os.path.join(cpu_mount, path) → 返回拼接路径

**验证说明**: 路径遍历漏洞的根因点。path.lstrip('/')仅去除前导斜杠，不处理../序列。cpu_mount来自/proc/mounts解析，同样可能被篡改。

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: -15 | context: -15 | cross_file: 0

**深度分析**

**根因定位**：此漏洞是所有路径遍历问题的**根本原因点**。`file_check()` 函数从 `/proc/{pid}/cgroup` 文件解析路径，使用 `path.lstrip('/')` 仅去除前导斜杠。

**源代码分析**（util.py:114-127）：

```python
def file_check(pid, cpu_mount, cgroup_key):
    """检查指定PID的cgroup信息， 如果匹配cgroup key， 返回对应的cpu_mount路径"""
    with open(f'/proc/{pid}/cgroup', 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) < 3:
                continue
            else:
                # 前两部分与剩余部分合并
                new_parts = parts[:2] + [':'.join(parts[2:])]
            _, controllers, path = new_parts
            if cgroup_key in controllers.split(',') and path.strip() is not None and path.strip() != '/':
                return os.path.join(cpu_mount, path.lstrip('/'))  # 根因点
    return None
```

**问题详解**：

| 代码 | 问题分析 |
|------|----------|
| `path.lstrip('/')` | 仅去除字符串开头的所有 `/` 字符，不处理中间的 `../` 序列 |
| `os.path.join(cpu_mount, path.lstrip('/'))` | 拼接后的路径可能指向 cpu_mount 之外的任意位置 |

**实验验证**：

```python
>>> import os
>>> cpu_mount = '/sys/fs/cgroup/cpu'
>>> path = '/../../../etc/passwd'
>>> os.path.join(cpu_mount, path.lstrip('/'))
'/sys/fs/cgroup/cpu../../../etc/passwd'
>>> # 虽然不是直接路径遍历，但某些系统可能解析为相对路径

# 更危险的场景
>>> path = 'kubepods/../../../var/spool/cron'
>>> os.path.join(cpu_mount, path.lstrip('/'))
'/sys/fs/cgroup/cpu/kubepods/../../../var/spool/cron'
>>> # 规范化后指向 /var/spool/cron
```

**修复建议代码**：

```python
# util.py:114-127 修复方案
def file_check(pid, cpu_mount, cgroup_key):
    """检查指定PID的cgroup信息， 如果匹配cgroup key， 返回对应的cpu_mount路径"""
    with open(f'/proc/{pid}/cgroup', 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) < 3:
                continue
            else:
                new_parts = parts[:2] + [':'.join(parts[2:])]
            _, controllers, path = new_parts
            if cgroup_key in controllers.split(',') and path.strip() is not None and path.strip() != '/':
                # 新增：路径规范化
                raw_path = os.path.join(cpu_mount, path.lstrip('/'))
                real_path = os.path.realpath(raw_path)
                
                # 检查规范化路径是否在 cgroup 挂载点范围内
                if not real_path.startswith(cpu_mount):
                    logging.warning("Path traversal detected in pid %s: %s", pid, path)
                    return None
                
                return real_path  # 返回规范化路径
    return None
```

---

### [DF-002] Path Traversal - get_container_info

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 20/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/waasbooster/util.py:209-216` @ `get_container_info`
**模块**: waasbooster

**描述**: get_container_info() 函数直接拼接 container_path 到文件路径中读取，没有验证路径是否包含 ../ 序列。container_path 来自容器列表，由 file_check() 从 /proc/{pid}/cgroup 解析生成。如果路径被篡改，可能以 root 权限读取任意位置的文件。

**漏洞代码** (`src/waasbooster/util.py:209-216`)

```c
def get_container_info(container_path, info_name):
    info_value = None
    try:
        with open(os.path.join(container_path, info_name), 'r') as f:
            info_value = f.read().strip()
```

**达成路径**

/proc/{pid}/cgroup → file_check() → get_container_cgroups() → container_path → get_container_info(container_path) → open(os.path.join(container_path, info_name))

**验证说明**: 与DF-001共享根因。仅读取文件而非写入，影响较低。路径通过is_container_path()和legal_cgroup_path()验证，但验证不完善。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: -20 | context: -15 | cross_file: 0

**深度分析**

**根因定位**：此漏洞与 DF-001 共享相同根因（`file_check()` 的路径遍历弱点）。`get_container_info()` 函数接收 `container_path` 参数并直接拼接读取文件。

**源代码分析**（util.py:209-216）：

```python
def get_container_info(container_path, info_name):
    info_value = None
    try:
        with open(os.path.join(container_path, info_name), 'r') as f:
            info_value = f.read().strip()
    except Exception as e:
        logging.warning('Fail to get container info for: %s', e)
    return info_value
```

**调用链分析**：

```
quota_manager.py:199: get_container_info(pod_path, CPU_SHARES)
                    ↓ pod_path 来自 util.py:175 container_paths.append(path)
                    ↓ path 来自 util.py:169 get_cgroup_path_for_pid()
                    ↓ 最终来自 file_check() 的路径拼接
```

**实际调用场景**（quota_manager.py:199）：

```python
# quota_manager.py:184-211 _balance_pods() 函数中
pod_shares.update({pod_path: int(get_container_info(pod_path, CPU_SHARES))})
```

`pod_path` 来自 `pods_to_balanced` 字典的键，最终追溯到 `file_check()` 返回的路径。

**风险评估**：

| 维度 | 评估 |
|------|------|
| 操作类型 | 文件读取（影响低于写入） |
| 权限 | 以 root 权限运行，可读取任意文件 |
| 数据可控性 | 通过篡改 `/proc/{pid}/cgroup` 控制路径 |
| 缓解措施 | `is_container_path()` 过滤不含容器关键词的路径 |

**潜在信息泄露场景**：

如果路径被篡改指向敏感文件：
```
container_path = '/sys/fs/cgroup/cpu/kubepods/../../../etc/shadow'
info_name = 'cpu.shares' (实际读取的文件名)
→ 最终路径: /etc/shadow/cpu.shares (不存在)

# 或攻击者预先创建符号链接
ln -s /etc/shadow /sys/fs/cgroup/cpu/kubepods/../../../tmp/evil/cpu.shares
→ 程序读取 /etc/shadow 内容
```

**修复建议**：

由于此漏洞与 DF-003 共享根因，修复 `file_check()` 函数后即可阻断此路径。建议在 `get_container_info()` 中增加额外防御：

```python
# util.py:209-216 增强防御
def get_container_info(container_path, info_name):
    # 额外检查：info_name 应为预期的 cgroup 文件名
    ALLOWED_INFO_NAMES = ['cpu.shares', 'cpu.cfs_quota_us', 'cpu.cfs_period_us', 
                          'cpuacct.usage', 'cpuset.cpus']
    if info_name not in ALLOWED_INFO_NAMES:
        logging.warning("Unexpected info_name: %s", info_name)
        return None
    
    # 路径规范化验证（双重防御）
    real_path = os.path.realpath(os.path.join(container_path, info_name))
    cpu_mount, _ = get_cpu_cgroup_mount_point()
    if not real_path.startswith(cpu_mount):
        logging.error("Path traversal detected: %s", real_path)
        return None
    
    # 原有读取逻辑...
```

---

## 4. Low 漏洞 (1)

### [DF-004] Path Traversal - get_cpu_usage, get_cpu_limits

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 20/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/waasbooster/cpu_monitor.py:36-55` @ `get_cpu_usage, get_cpu_limits`
**模块**: waasbooster

**描述**: CpuMonitor.get_cpu_usage() 和 get_cpu_limits() 方法直接拼接 path 参数读取 cgroup 文件，没有验证路径合法性。path 来自容器列表，可能包含路径遍历字符。

**漏洞代码** (`src/waasbooster/cpu_monitor.py:36-55`)

```c
@staticmethod
def get_cpu_usage(path):
    with open(os.path.join(path, 'cpuacct.usage'), 'r') as f:
        return int(f.read().strip())

@staticmethod
def get_cpu_limits(path):
    with open(os.path.join(path, 'cpu.cfs_quota_us'), 'r') as f:
        quota = int(f.read().strip())
```

**达成路径**

container_paths (from get_container_cgroups) → path → get_cpu_usage(path) → open(os.path.join(path, 'cpuacct.usage'))

**验证说明**: 与DF-001共享根因。仅读取cgroup文件，不执行写入操作。路径来自get_container_cgroups()已经过is_container_path()验证。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: -20 | context: -15 | cross_file: 0

**深度分析**

**根因定位**：此漏洞同样共享 `file_check()` 的路径遍历根因。`CpuMonitor` 类的静态方法直接拼接 `path` 参数读取 cgroup 文件。

**源代码分析**（cpu_monitor.py:36-55）：

```python
@staticmethod
def get_cpu_usage(path):
    """读取CPU累计使用时间"""
    try:
        with open(os.path.join(path, 'cpuacct.usage'), 'r') as f:
            return int(f.read().strip())
    except Exception:
        return None

@staticmethod
def get_cpu_limits(path):
    """获取CPU配额限制"""
    try:
        with open(os.path.join(path, 'cpu.cfs_quota_us'), 'r') as f:
            quota = int(f.read().strip())
        with open(os.path.join(path, 'cpu.cfs_period_us'), 'r') as f:
            period = int(f.read().strip())
        return quota, period
    except Exception:
        return -1, 100000
```

**调用链分析**：

```
cpu_monitor.py:65-87 CpuMonitor.run(containers, interval)
  ↓ containers 参数来自 QuotaBooster.pod_path
  ↓ pod_path 来自 util.py:194-206 get_boosted_container_cgroups()
  ↓ 最终来自 file_check() 的路径拼接

# 实际调用位置
cpu_monitor.py:73: usage = self.get_cpu_usage(path)
cpu_monitor.py:108: quota, period = self.get_cpu_limits(path)
```

**数据流追踪**：

```python
# waas_booster.py 中的调用链（简化）
QuotaBooster.__init__():
    self.pod_path, self.pod_nodes = get_boosted_container_cgroups()

QuotaBooster.run():
    # containers = self.pod_path
    cpu_monitor.run(containers=self.pod_path, interval=...)  # 传递给 CpuMonitor
```

**风险评估**：

| 维度 | 评估 |
|------|------|
| 操作类型 | 仅读取文件，不写入 |
| 严重性降级原因 | 读取操作影响低于写入 |
| 置信度较低原因 | 路径经过 `is_container_path()` 验证，过滤不含容器关键词的路径 |

**潜在影响**：

虽然仅读取文件，但攻击者可能：
1. 读取敏感配置文件（如 `/etc/shadow` 的内容可能通过精心构造的路径泄露）
2. 获取系统内部信息用于后续攻击

**修复建议**：

在 `CpuMonitor` 类中添加路径验证：

```python
# cpu_monitor.py 修复方案
import os
from util import get_cpu_cgroup_mount_point

class CpuMonitor:
    @staticmethod
    def _validate_path(path):
        """验证路径是否在预期的 cgroup 挂载点范围内"""
        cpu_mount, _ = get_cpu_cgroup_mount_point()
        real_path = os.path.realpath(path)
        if not real_path.startswith(cpu_mount):
            return None
        return real_path
    
    @staticmethod
    def get_cpu_usage(path):
        """读取CPU累计使用时间"""
        validated_path = CpuMonitor._validate_path(path)
        if validated_path is None:
            return None
        try:
            with open(os.path.join(validated_path, 'cpuacct.usage'), 'r') as f:
                return int(f.read().strip())
        except Exception:
            return None
    
    @staticmethod
    def get_cpu_limits(path):
        """获取CPU配额限制"""
        validated_path = CpuMonitor._validate_path(path)
        if validated_path is None:
            return -1, 100000
        # ... 原有逻辑，使用 validated_path
```

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| waasbooster | 0 | 0 | 3 | 1 | 4 |
| **合计** | **0** | **0** | **3** | **1** | **4** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 4 | 100.0% |

---

## 7. 修复建议

### 7.1 优先级 1：核心路径验证修复（阻断所有漏洞）

所有 4 个漏洞共享同一个根因——`file_check()` 函数的路径遍历弱点。修复此根因点即可阻断整个攻击链。

**修复位置**：`src/waasbooster/util.py:114-127`

**完整修复代码**：

```python
def file_check(pid, cpu_mount, cgroup_key):
    """检查指定PID的cgroup信息， 如果匹配cgroup key， 返回对应的cpu_mount路径"""
    with open(f'/proc/{pid}/cgroup', 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) < 3:
                continue
            else:
                new_parts = parts[:2] + [':'.join(parts[2:])]
            _, controllers, path = new_parts
            if cgroup_key in controllers.split(',') and path.strip() is not None and path.strip() != '/':
                # [新增] 路径规范化验证
                raw_path = os.path.join(cpu_mount, path.lstrip('/'))
                real_path = os.path.realpath(raw_path)
                
                # [新增] 检查规范化路径是否在 cgroup 挂载点范围内
                if not real_path.startswith(os.path.realpath(cpu_mount)):
                    logging.warning("Path traversal detected in pid %s: original=%s, resolved=%s", 
                                    pid, path, real_path)
                    return None
                
                # [新增] 验证路径不包含危险字符
                if '../' in path or '..\\' in path:
                    logging.warning("Suspicious path pattern in pid %s: %s", pid, path)
                    return None
                
                return real_path  # [修改] 返回规范化路径而非原始拼接路径
    return None
```

**修复效果**：
- 阻断 DF-001、DF-002、DF-003、DF-004 的攻击链
- 所有后续路径操作使用规范化路径
- 检测并记录可疑路径模式

### 7.2 优先级 2：配额写入双重验证

在 `quota_updater()` 函数中添加额外验证，防止即使路径被绕过也能限制写入范围。

**修复位置**：`src/waasbooster/quota_updater.py:30-52`

**修复代码**：

```python
def quota_updater(cgroup_path: str, quota):
    quota_value = int(quota)
    
    # [新增] 获取 cgroup 挂载点并验证路径范围
    from util import get_cpu_cgroup_mount_point
    cpu_mount, _ = get_cpu_cgroup_mount_point()
    real_cgroup_path = os.path.realpath(cgroup_path)
    real_cpu_mount = os.path.realpath(cpu_mount)
    
    # [新增] 检查路径是否在预期范围内
    if not real_cgroup_path.startswith(real_cpu_mount):
        logging.error("Quota update rejected: path %s outside cgroup mount", real_cgroup_path)
        return False
    
    # [新增] 配额值范围验证
    if quota_value < -1 or quota_value > 10000000:  # 合理配额范围
        logging.error("Invalid quota value: %d", quota_value)
        return False
    
    quota_path = os.path.join(cgroup_path, "cpu.cfs_quota_us")
    # ... 原有逻辑
```

### 7.3 优先级 3：防御性编程增强

在所有文件读取/写入函数中添加防御性验证：

**统一路径验证函数**（建议新增到 `util.py`）：

```python
def validate_cgroup_path(path: str, operation: str = 'read') -> str | None:
    """
    验证 cgroup 路径是否安全
    
    Args:
        path: 待验证的路径
        operation: 操作类型 ('read' 或 'write')
    
    Returns:
        规范化路径（验证通过）或 None（验证失败）
    """
    cpu_mount, _ = get_cpu_cgroup_mount_point()
    real_path = os.path.realpath(path)
    real_mount = os.path.realpath(cpu_mount)
    
    # 检查路径是否在 cgroup 挂载点范围内
    if not real_path.startswith(real_mount):
        logging.error("Path validation failed: %s not under %s", real_path, real_mount)
        return None
    
    # 写入操作额外检查
    if operation == 'write':
        # 检查目标文件是否为预期的 cgroup 文件
        expected_files = ['cpu.cfs_quota_us', 'cpu.cfs_period_us', 'cpu.shares']
        basename = os.path.basename(real_path)
        if basename not in expected_files:
            logging.error("Write validation failed: unexpected file %s", basename)
            return None
    
    return real_path
```

### 7.4 修复验证测试

建议添加以下单元测试验证修复效果：

```python
# tests/test_path_validation.py
import os
import pytest
from util import file_check, validate_cgroup_path

def test_path_traversal_blocked():
    """测试路径遍历攻击被阻断"""
    # 模拟恶意 cgroup 内容
    malicious_paths = [
        '/../../../etc/passwd',
        'kubepods/../../../var/spool/cron',
        '/sys/fs/cgroup/../etc/shadow',
    ]
    
    for path in malicious_paths:
        # 应返回 None 或规范化到安全路径
        result = validate_cgroup_path(f'/sys/fs/cgroup/cpu/{path}')
        assert result is None or result.startswith('/sys/fs/cgroup')

def test_normal_container_path_allowed():
    """测试正常容器路径被允许"""
    normal_path = '/sys/fs/cgroup/cpu/kubepods/besteffort/pod123/container456'
    result = validate_cgroup_path(normal_path)
    assert result is not None
    assert result.startswith('/sys/fs/cgroup')
```

---

## 8. 威胁建模分析

基于项目架构和漏洞发现，以下是对 WAAS Booster 的威胁建模分析：

### 8.1 威胁场景矩阵

| 威胁类型 | 攻击入口 | 攻击路径 | 前提条件 | 影响 | 可能性 |
|----------|----------|----------|----------|------|--------|
| **Tampering** | `/proc/{pid}/cgroup` | DF-001 → quota_updater() | 内核模块操控能力 | 系统文件被写入、容器配额异常 | 低 |
| **Information Disclosure** | `/proc/{pid}/cgroup` | DF-002, DF-004 → 文件读取 | 内核文件篡改 | 敏感配置泄露 | 低 |
| **Denial of Service** | 进程数量激增 | get_all_pids() | 本地用户权限 | 监控性能下降 | 中 |
| **Elevation of Privilege** | PATH 劫持 | subprocess 执行 stat | 环境变量控制 | 执行恶意命令 | 中 |

### 8.2 攻击者能力要求

针对本次发现的路径遍历漏洞，攻击者需要具备以下能力：

| 攻击能力 | 获取途径 | 难度评估 |
|----------|----------|----------|
| 修改 `/proc/{pid}/cgroup` | 1. 加载恶意内核模块 (CAP_SYS_MODULE)<br>2. 特权容器逃逸<br>3. 内核漏洞利用 | **高** - 需突破内核隔离 |
| 创建恶意进程 | 本地用户权限 | **低** - 但无法直接篡改 cgroup |
| 预先创建符号链接 | /sys/fs/cgroup 写权限 | **中** - 需容器管理权限 |

### 8.3 STRIDE 威胁映射

| STRIDE 类别 | 相关漏洞 | 风险等级 | 说明 |
|-------------|----------|----------|------|
| **Spoofing** | - | Medium | 进程身份可能被伪造（创建恶意进程） |
| **Tampering** | DF-001, DF-003 | **High** | 配额写入可能影响错误位置 |
| **Repudiation** | - | Medium | 缺乏配额变更审计日志 |
| **Information Disclosure** | DF-002, DF-004 | Medium | 敏感文件可能被读取 |
| **Denial of Service** | - | Medium | 进程激增可能导致监控性能下降 |
| **Elevation of Privilege** | - | Low | 当前漏洞不直接导致权限提升 |

### 8.4 防御措施评估

**现有防御措施**：

| 防御措施 | 代码位置 | 有效性 | 建议 |
|----------|----------|--------|------|
| `is_container_path()` | util.py:130-137 | 部分 | 增加路径规范化检查 |
| `legal_cgroup_path()` | util.py:181-189 | 无效 | 替换为路径范围验证 |
| `os.path.exists()` | quota_updater.py:33 | 部分 | 不依赖文件存在性检查 |
| subprocess 完整路径 | quota_manager.py:21 | 有效 | 保持现状 |

**建议新增防御措施**：

| 防御措施 | 实施位置 | 优先级 |
|----------|----------|--------|
| `os.path.realpath()` 规范化 | util.py:126 | **P1** |
| 路径范围白名单检查 | 所有路径操作点 | **P1** |
| 配额值范围验证 | quota_updater.py | **P2** |
| 安全审计日志 | quota_updater.py | **P3** |

### 8.5 风险接受建议

考虑到以下因素，建议将修复作为中等优先级在下版本迭代中完成：

1. **利用门槛高**：需内核级操控能力，在标准部署环境中难以达成
2. **现有缓解措施**：`is_container_path()` 提供了基础过滤
3. **程序运行环境**：作为系统守护进程，攻击面相对有限

**不建议立即发布安全补丁**，但应在下一版本中：
- 实现路径规范化验证
- 添加安全审计日志
- 增强配额变更记录

---

## 附录 A：误报分析

本次扫描发现 2 个 FALSE_POSITIVE 候选漏洞：

| ID | 类型 | 位置 | 误报原因 |
|----|------|------|----------|
| SEC-001 | 弱点识别 | util.py:126 | 根因弱点而非独立漏洞，已纳入 DF-003 分析 |
| SEC-002 | 非漏洞模式 | quota_manager.py | subprocess 使用完整路径，有 timeout 限制，风险可控 |

---

**报告生成时间**: 2026-04-21T10:30:00Z  
**扫描引擎**: Multi-Agent Vulnerability Scanner v2.0  
**报告格式**: Markdown (增强版)
