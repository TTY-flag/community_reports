# 漏洞扫描报告 — 已确认漏洞

**项目**: mind-cluster
**扫描时间**: 2026-04-22T01:24:26.206Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

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
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 4 | - |

### 1.3 Top 10 关键漏洞


---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@/component/ascend-docker-runtime/cli/src/main.c` | CLI | - | - | - |
| `save/load@/component/mindio/acp/python_whl/mindio_acp/mindio_acp/acc_io/acc_io.py` | API | - | - | - |
| `init_taskd_manager@/component/taskd/taskd/api/taskd_manager_api.py` | API | - | - | - |


---

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
