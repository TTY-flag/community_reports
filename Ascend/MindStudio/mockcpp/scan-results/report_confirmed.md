# 漏洞扫描报告 — 已确认漏洞

**项目**: mockcpp
**扫描时间**: 2026-04-21T06:10:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

**本次扫描未发现已确认的安全漏洞。**

经多阶段深度验证，mockcpp 项目作为 C/C++ 单元测试 Mock 框架，其核心功能（API Hook、虚函数表操作、函数指针注入）均为测试框架的预期设计。验证过程中识别的 17 个候选漏洞，经人工复核与置信度评估：

- **14 个被判定为误报 (FALSE_POSITIVE)**：这些是测试框架的正常功能，不构成安全风险
- **3 个待进一步确认 (LIKELY/POSSIBLE)**：存在设计缺陷，但在测试框架场景下影响有限

**风险评估结论**：项目整体安全风险较低。建议关注待确认报告中提及的设计改进建议，以提升代码健壮性。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 14 | 82.4% |
| POSSIBLE | 2 | 11.8% |
| LIKELY | 1 | 5.9% |
| **总计** | **17** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 14 | - |

### 1.3 Top 10 关键漏洞


---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `MOCK_METHOD@include/mockcpp/mockcpp.h` | decorator | semi_trusted | 用户测试代码调用 MOCK_METHOD 宏创建 Mock 方法，输入来自测试开发者，具有开发权限 | Mock 方法创建宏入口 |
| `invoke@include/mockcpp/HookMockObject.h` | decorator | semi_trusted | 用户调用 invoke() 设置 API Hook，传入的函数指针由开发者提供，具有开发权限 | API Hook 创建入口 |
| `CodeModifier::modify@src/UnixCodeModifier.cpp` | internal | internal | 内部函数，由 ApiHook 系统调用，不直接对外暴露 | 代码段修改内部函数 |
| `CodeModifier::modify@src/WinCodeModifier.cpp` | internal | internal | 内部函数，由 ApiHook 系统调用，不直接对外暴露 | Windows 平台代码段修改内部函数 |
| `startHook@src/JmpOnlyApiHook.cpp` | internal | internal | 内部函数，由 ApiHook 构造函数调用 | 启动 Hook，修改目标函数入口代码 |
| `appyApiHook@include/mockcpp/ApiHookGenerator.h` | decorator | semi_trusted | 模板函数，由用户代码调用设置 Hook，函数地址参数由开发者提供 | 应用 API Hook 的模板函数入口 |
| `PROC_STUB@include/mockcpp/ProcStub.h` | decorator | semi_trusted | 宏定义，创建函数指针 Stub，参数由开发者提供 | 函数 Stub 创建宏入口 |

**其他攻击面**:
- API Hook 代码修改: UnixCodeModifier::modify() 使用 mprotect+mmemcpy 修改代码段权限和内容
- API Hook 代码修改: WinCodeModifier::modify() 使用 VirtualProtect+WriteProcessMemory 修改代码段
- Virtual Table 操作: VirtualTable 创建和操作虚函数表，修改函数指针
- Mock Object 生命周期: MockObjectBase 管理对象创建和删除
- Type Casting: AnyCast 模板实现涉及整数范围检查
- Python 脚本输入: generate_vtbl_related_files.py 接收命令行参数并生成代码

---

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
