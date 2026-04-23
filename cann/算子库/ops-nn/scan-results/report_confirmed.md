# 漏洞扫描报告 — 已确认漏洞

**项目**: ops-nn
**扫描时间**: 2026-04-22T05:07:13.750Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 6 | 66.7% |
| POSSIBLE | 2 | 22.2% |
| FALSE_POSITIVE | 1 | 11.1% |
| **总计** | **9** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞


---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `undefined@undefined` | api_function | - | - | ACL NN API workspace size calculation - user input validation |
| `undefined@undefined` | api_function | - | - | ACL NN API execution function - kernel dispatch |
| `undefined@undefined` | kernel_function | - | - | APT kernel implementation - device-side execution |
| `undefined@undefined` | tiling_function | - | - | Tiling strategy calculation - memory block planning |


---

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
