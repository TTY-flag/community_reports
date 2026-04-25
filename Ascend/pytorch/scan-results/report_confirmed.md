# 漏洞扫描报告 — 已确认漏洞

**项目**: torch_npu
**扫描时间**: 2026-04-24T07:12:08.786Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 6 | 37.5% |
| FALSE_POSITIVE | 6 | 37.5% |
| LIKELY | 4 | 25.0% |
| **总计** | **16** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 6 | - |

### 1.3 Top 10 关键漏洞


---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `undefined@undefined` | network | - | - | TCP Socket 通信 - 分布式训练网络接口 |
| `undefined@undefined` | ipc | - | - | 共享内存 IPC - 跨进程 NPU Tensor 共享 |
| `undefined@undefined` | file | - | - | 文件操作 - 性能数据导出、调试信息写入 |
| `undefined@undefined` | library_loading | - | - | 动态库加载 - NPU 功能扩展加载 |
| `undefined@undefined` | environment_variable | - | - | 环境变量 - 配置参数读取 |
| `undefined@undefined` | serialization | - | - | Tensor 序列化/反序列化 |
| `undefined@undefined` | python_api | - | - | Python API - 用户调用入口 |


---

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
