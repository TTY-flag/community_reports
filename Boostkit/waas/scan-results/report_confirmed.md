# 漏洞扫描报告 — 已确认漏洞

**项目**: WAAS Booster
**扫描时间**: 2026-04-21T10:30:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次漏洞扫描未发现任何已确认（CONFIRMED）状态的漏洞。所有候选漏洞经验证后均被判定为 POSSIBLE（置信度 20-25）或 FALSE_POSITIVE 状态。

### 验证结论

| 验证状态 | 数量 | 说明 |
|----------|------|------|
| CONFIRMED | **0** | 无已确认漏洞 |
| POSSIBLE | 4 | 路径遍历候选漏洞，利用门槛高 |
| FALSE_POSITIVE | 2 | 根因弱点/非漏洞模式 |

### 无确认漏洞的原因分析

1. **路径遍历漏洞（4 个 POSSIBLE）**：
   - 根因存在于 `file_check()` 函数的路径拼接逻辑
   - 但利用前提是篡改 `/proc/{pid}/cgroup` 内核虚拟文件
   - 需要内核模块操控能力或特权容器逃逸，在标准部署环境中难以达成
   - 现有缓解措施（`is_container_path()` 过滤）提供基础防护

2. **置信度评分结果**：
   - 最高置信度仅 25/100（DF-001, DF-003）
   - 评分明细显示：可达性评分低（仅 5 分），攻击路径受限
   - 缓解措施评分扣分（-15），存在基础过滤

### 建议

虽然没有已确认漏洞，但建议在下版本迭代中：
- 在 `util.py` 的 `file_check()` 函数中添加 `os.path.realpath()` 路径规范化
- 在 `quota_updater.py` 中添加路径范围验证
- 增加配额变更审计日志

完整漏洞分析详见 `report_unconfirmed.md`。

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
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 2 | - |

### 1.3 Top 10 关键漏洞


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

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
