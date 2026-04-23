# WAAS Booster 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析基于源码扫描和架构分析自主识别所有攻击面，无 threat.md 约束文件。

**分析时间**: 2026-04-21
**项目名称**: WAAS Booster (Workload Aware Acceleration System Booster)
**语言**: Python (10 文件, 2081 行)
**LSP 可用**: 否 (pyright-langserver 无法启动)

---

## 1. 项目架构概览

### 1.1 项目定位

WAAS Booster 是一个 **系统守护进程/CLI 工具**，部署在 Kubernetes worker node 上，用于：

- 实时监控容器 CPU 使用情况
- 基于负载感知和预测动态调整容器 CPU 配额
- 通过修改 cgroup 文件系统 (`cpu.cfs_quota_us`) 控制容器资源分配
- 支持 NUMA 架构的 CPU 资源平衡

**典型部署方式**:
- 作为 systemd 服务运行 (`waasbooster.service`)
- 需要 root/特权权限访问 cgroup 文件系统
- 针对鲲鹏920处理器上的容器环境

### 1.2 模块结构

| 模块 | 文件 | 代码行数 | 主要功能 | 风险等级 |
|------|------|----------|----------|----------|
| 配额更新 | quota_updater.py | 52 | 写入 cgroup quota 文件 | **Critical** |
| 配额管理 | quota_manager.py | 212 | 配额审批决策、subprocess 执行 | **High** |
| 主控制 | waas_booster.py | 546 | 主入口、命令行参数、协调各模块 | **High** |
| 工具函数 | util.py | 358 | 进程遍历、文件系统读取 | **High** |
| CPU 监控 | cpu_monitor.py | 138 | cgroup 文件读取 | Medium |
| NUMA 监控 | numa_cpu_monitor.py | 136 | /proc/stat 读取 | Medium |
| 数据收集 | data_collector.py | 174 | CSV/ZIP 文件写入 | Medium |
| 日志模块 | boost_log.py | 252 | 日志文件写入、tarfile | Medium |
| 负载预测 | load_predictor.py | 163 | Prophet 模型预测 | Low |
| 配额计算 | quota_calculator.py | 57 | PID 控制器计算 | Low |

### 1.3 核心调用链

```
cpu_booster_main() [主入口]
  → booster_param_parser() [命令行参数]
  → QuotaBooster.__init__() [初始化]
    → get_all_pod() → get_boosted_container_cgroups() [获取容器列表]
    → NUMAMonitor.__init__() [NUMA 监控]
  → QuotaBooster.run() [主运行循环]
    → QuotaManager.__init__() → _get_cgroup_version() [subprocess 执行]
    → monitor_container() [监控循环]
      → CpuMonitor.run() [读取 cgroup 文件]
      → check_pod_status() → calculate_container_quota() [配额计算]
      → QuotaManager.quota_approval() [配额审批]
      → quota_set() → quota_updater() [写入 cgroup quota]
```

---

## 2. 攻击面分析

### 2.1 信任边界

| 信任边界 | 可信侧 | 不可信侧 | 风险等级 | 说明 |
|----------|--------|----------|----------|------|
| 命令行接口 | 程序内部逻辑 | 本地用户命令行参数 | Medium | 用户可控制 --forecast 参数 |
| 系统文件系统 | 程序读取的系统数据 | /proc, /sys, cgroup 文件 | High | 可能被恶意进程篡改 |
| Cgroup 配额控制 | 容器资源管理逻辑 | 写入 cgroup quota 文件 | **Critical** | 影响容器资源分配 |
| 外部命令执行 | 程序内部调用 | subprocess 执行 stat | High | PATH 可能被劫持 |

### 2.2 入口点列表

| 文件 | 行号 | 函数 | 入口类型 | 信任等级 | 可达性分析 |
|------|------|------|----------|----------|------------|
| waas_booster.py | 509 | booster_param_parser | cmdline | untrusted_local | 本地用户运行程序时可通过 --forecast 参数控制预测功能开关 |
| quota_manager.py | 20 | _get_cgroup_version | subprocess | semi_trusted | 执行 /usr/bin/stat 命令获取 cgroup 版本，使用完整路径降低风险，但仍存在命令被替换的可能 |
| util.py | 116 | file_check | file | semi_trusted | 读取 /proc/{pid}/cgroup，pid 来自系统进程列表，攻击者可创建恶意进程 |
| util.py | 199 | get_boosted_container_cgroups | file | semi_trusted | 读取容器 cgroup 文件，可能被恶意容器篡改 |
| quota_updater.py | 41 | quota_updater | file | semi_trusted | 直接写入 cgroup quota 文件，影响容器 CPU 配额 |
| cpu_monitor.py | 40 | get_cpu_usage | file | semi_trusted | 读取 cgroup cpuacct.usage 文件 |
| numa_cpu_monitor.py | 63 | get_cpu_utilization | file | semi_trusted | 读取 /proc/stat 文件 |

### 2.3 关键数据流路径

**数据流 1: 命令行参数 → 预测功能**
```
argparse.parse_args() → booster_param_parser() → cpu_booster_main() → QuotaBooster.__init__()
```

**数据流 2: 进程信息 → 容器路径**
```
/proc/{pid}/cgroup → file_check() → get_container_cgroups() → QuotaBooster.pod_path
```

**数据流 3: CPU 使用 → 配额调整（核心）**
```
cgroup cpuacct.usage → CpuMonitor.run() → cpu_queue_dict → check_pod_status() → pod_update_quota_dict → quota_updater() → 写入 cgroup quota
```

---

## 3. STRIDE 威胁建模

### 3.1 Spoofing (欺骗)

| 威胁场景 | 影响组件 | 风险等级 | 描述 |
|----------|----------|----------|------|
| 进程身份伪造 | util.py | High | 攻击者可创建恶意进程并篡改其 /proc/{pid}/cgroup 文件内容，导致程序监控错误的容器 |
| 命令替换 | quota_manager.py | High | /usr/bin/stat 命令可能被替换为恶意程序，返回错误的 cgroup 版本信息 |

### 3.2 Tampering (篡改)

| 威胁场景 | 影响组件 | 风险等级 | 描述 |
|----------|----------|----------|------|
| cgroup 文件篡改 | quota_updater.py | **Critical** | 恶意进程或容器篡改 cpu.cfs_quota_us 文件，导致错误的配额设置 |
| 配额数据篡改 | waas_booster.py | High | pod_update_quota_dict 在传递过程中可能被中间函数篡改 |
| 日志文件篡改 | boost_log.py | Medium | 日志文件可能被篡改，掩盖攻击痕迹 |
| 数据文件篡改 | data_collector.py | Medium | CSV/ZIP 数据文件可能被篡改，影响历史数据分析 |

### 3.3 Repudiation (抵赖)

| 威胁场景 | 影响组件 | 风险等级 | 描述 |
|----------|----------|----------|------|
| 操作日志缺失 | boost_log.py | Medium | 日志轮转可能导致关键操作记录丢失 |
| 配额变更无审计 | quota_updater.py | Medium | 配额写入操作缺乏审计日志 |

### 3.4 Information Disclosure (信息泄露)

| 威胁场景 | 影响组件 | 风险等级 | 描述 |
|----------|----------|----------|------|
| 容器信息泄露 | util.py | Medium | 通过 /proc/{pid}/cgroup 遍历可获取所有容器路径信息 |
| CPU 使用数据泄露 | data_collector.py | Medium | CSV 数据文件可能泄露容器性能信息 |
| 日志信息泄露 | boost_log.py | Medium | 日志文件包含敏感的容器路径和配额信息 |

### 3.5 Denial of Service (拒绝服务)

| 威胁场景 | 影响组件 | 风险等级 | 描述 |
|----------|----------|----------|------|
| 进程数量激增 | util.py | Medium | 攻击者可创建大量恶意进程，导致 get_all_pids() 性能下降 |
| cgroup 文件阻塞 | cpu_monitor.py | Medium | 频繁读取 cgroup 文件可能导致 I/O 阻塞 |
| 配额耗尽 | quota_manager.py | High | 恶意容器申请大量配额，导致正常容器无法获得资源 |

### 3.6 Elevation of Privilege (权限提升)

| 威胁场景 | 影动组件 | 飧险等级 | 描述 |
|----------|----------|----------|------|
| cgroup 配额提升 | quota_updater.py | **Critical** | 程序通过写入 cgroup 文件提升容器 CPU 配额，如果控制不当可能导致资源滥用 |
| subprocess 命令注入 | quota_manager.py | High | PATH 环境变量劫持可能导致执行恶意命令 |

---

## 4. 模块风险评估

### 4.1 Critical 风险模块

**quota_updater.py**
- **主要风险**: 直接写入系统 cgroup quota 文件 (`cpu.cfs_quota_us`)
- **影响**: 影响容器 CPU 资源分配，可能导致资源滥用或服务拒绝
- **关键函数**: `quota_updater()`, `_update_parent_quota()`
- **数据流**: 配额值直接写入文件，缺乏充分验证

### 4.2 High 风险模块

**quota_manager.py**
- **主要风险**: 使用 subprocess 执行外部命令，管理配额审批决策
- **关键函数**: `_get_cgroup_version()` (subprocess), `quota_approval()`, `_balance_pods()`
- **缓解措施**: 使用完整路径 `/usr/bin/stat`，有 timeout 限制

**waas_booster.py**
- **主要风险**: 主入口，处理命令行参数，协调所有模块
- **关键函数**: `cpu_booster_main()`, `booster_param_parser()`, `QuotaBooster.run()`
- **数据流**: 命令行参数直接影响程序行为

**util.py**
- **主要风险**: 遍历所有系统进程，读取多个系统文件
- **关键函数**: `get_all_pids()`, `file_check()`, `get_container_cgroups()`
- **数据流**: 进程信息 → 容器路径列表

### 4.3 Medium 风险模块

**cpu_monitor.py, numa_cpu_monitor.py**
- **主要风险**: 读取系统文件，可能被篡改
- **缓解措施**: 仅读取，不写入

**data_collector.py, boost_log.py**
- **主要风险**: 文件写入操作，数据持久化
- **缓解措施**: 文件权限设置

### 4.4 Low 险险模块

**load_predictor.py, quota_calculator.py**
- **主要风险**: 纯计算逻辑，无外部输入处理
- **说明**: 风险可控，无直接安全威胁

---

## 5. 安全加固建议（架构层面）

### 5.1 命令执行安全

**现状**: `quota_manager.py:20` 使用 `subprocess.run(['/usr/bin/stat', ...])`

**建议**:
1. 验证命令路径存在且为预期文件
2. 使用绝对路径，不依赖 PATH 环境变量
3. 检查命令文件权限和所有权
4. 考虑使用 Python 内置函数替代外部命令（如 `os.statvfs`）

### 5.2 文件路径验证

**现状**: 多处使用 `os.path.join()` 拼接路径

**建议**:
1. 在写入 cgroup 文件前验证路径合法性
2. 检查路径是否在预期的 cgroup 挂载点范围内
3. 防止路径遍历攻击（检查 `../` 等危险模式）
4. 验证写入的配额值范围合理

### 5.3 输入验证

**现状**: 命令行参数通过 argparse 解析

**建议**:
1. 限制参数值范围（如 `--forecast` 只接受 True/False）
2. 添加参数类型检查
3. 拒绝异常参数组合

### 5.4 配额写入保护

**现状**: 直接写入 cgroup quota 文件

**建议**:
1. 在写入前检查配额值是否在合理范围内
2. 添加配额变更审计日志
3. 实现配额变更速率限制
4. 验证目标容器确实在监控列表中

### 5.5 进程信息验证

**现状**: 遍历 /proc 目录获取进程信息

**建议**:
1. 验证读取的 PID 确实是有效数字
2. 检查 /proc/{pid}/cgroup 文件格式合法性
3. 过滤掉异常或可疑的进程路径

### 5.6 日志和数据安全

**现状**: 日志和数据文件写入

**建议**:
1. 设置适当的文件权限（当前已有 0o640, 0o600 设置）
2. 验证日志路径不在用户可写目录
3. 数据文件加密存储敏感信息

---

## 6. 总结

WAAS Booster 作为系统级资源管理工具，其核心安全风险集中在：

1. **cgroup 文件操作** (Critical): 配额写入直接影响容器资源分配
2. **外部命令执行** (High): subprocess 执行可能被劫持
3. **系统文件读取** (High): /proc, /sys, cgroup 文件可能被篡改

由于程序需要特权运行，攻击者如果能：
- 劫持 PATH 环境变量
- 篡改系统文件（/proc, /sys, cgroup）
- 注入恶意进程

可能导致程序行为异常，影响容器资源分配。

建议后续 Scanner Agent 重点扫描：
- `quota_updater.py` 的文件写入操作
- `quota_manager.py` 的 subprocess 执行
- `util.py` 的文件路径处理
- 所有涉及外部数据输入的函数