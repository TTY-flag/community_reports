# optune-kernel_modifier-replace_param-003：_replace_param代码注入（合并至cross-module）

## 合并状态

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | optune-kernel_modifier-replace_param-003 |
| **漏洞类型** | Code Injection (CWE-94) |
| **严重程度** | High |
| **置信度** | 90% |
| **合并到** | cross-module-configs-to-command-exec |
| **合并原因** | 与 VULN-SEC-OPT-001 完全相同，主报告已完整覆盖 |

---

## 漏洞位置

| 属性 | 值 |
|------|-----|
| **文件** | mskl/optune/kernel_modifier.py |
| **行号** | 63-91 |
| **函数** | `_replace_param` |
| **类** | `Replacer` |

---

## 重复关系确认

### 与 VULN-SEC-OPT-001 的对比

| 维度 | optune-kernel_modifier-replace_param-003 | VULN-SEC-OPT-001 |
|------|------------------------------------------|------------------|
| **文件** | mskl/optune/kernel_modifier.py | mskl/optune/kernel_modifier.py |
| **函数** | `_replace_param` | `_replace_param` |
| **行号** | 63-91 | 76-88 (核心注入点) |
| **漏洞类型** | Code Injection (CWE-94) | Code Injection (CWE-94) |
| **描述** | 直接插入用户控制的 value 字符串 | 用户配置值直接写入内核源文件 |

**结论**: 两个漏洞报告指向**同一代码位置的同一安全问题**。

---

## 漏洞详情

### 问题描述

`_replace_param()` 方法将用户提供的 `val` 参数直接插入内核源代码行，未经任何内容清理：

```python
# kernel_modifier.py:63-91
@staticmethod
def _replace_param(key, val, lines):
    ...
    # mode 1, match alias name
    if line_without_space.endswith('//' + alias_key):
        lines[index] = Replacer._replace_content_for_alias_name(index, line, val)
        # ↑ val 直接拼接，无过滤
        replace_param_success = True
        break
    # mode 2, match tunable name
    if line_without_space.endswith('//' + 'tunable') and key in line:
        ...
        if key == variale_name:
            lines[index] = Replacer._replace_content_for_tunable_name(index, line, val)
            # ↑ val 直接拼接，无过滤
            replace_param_success = True
            break
    return replace_param_success
```

### 注入辅助方法

```python
@staticmethod
def _replace_content_for_alias_name(line_index, line, replacement):
    index = len(line) - len(line.lstrip())
    new_line = line[:index] + replacement  # 【注入点】
    if line.endswith('\n'):
        new_line += '\n'
    return new_line

@staticmethod
def _replace_content_for_tunable_name(line_index, line, replacement):
    return line[:line.index('=') + 1] + ' ' + replacement + ';\n'  # 【注入点】
```

---

## 主报告覆盖情况

### cross-module-configs-to-command-exec.md 已完整覆盖

| 覆盖维度 | 是否覆盖 | 报告位置 |
|----------|----------|----------|
| **注入机制分析** | ✓ | 第 85-101 行 |
| **数据流图** | ✓ | 第 38-40 行标注注入点 |
| **上游输入入口** | ✓ | tuner.py:251 (第 53-64 行) |
| **输入验证缺陷** | ✓ | autotune_utils.py:39-49 (第 67-82 行) |
| **下游编译执行** | ✓ | compiler.py + driver.py (第 121-132 行) |
| **PoC 攻击示例** | ✓ | 4 个完整 PoC (第 137-263 行) |
| **修复建议** | ✓ | 完整修复方案 (第 296-430 行) |

---

## 合并判定

| 维度 | 评估 |
|------|------|
| **技术一致性** | 与 VULN-SEC-OPT-001 完全相同 |
| **覆盖完整性** | 主报告覆盖更完整（全链路攻击分析） |
| **独立性** | 无独立技术细节，无需单独报告 |
| **追溯性** | 已有完整攻击链分析 |

### 结论

**optune-kernel_modifier-replace_param-003 是 VULN-SEC-OPT-001 的重复报告**，两者指向同一代码位置的同一漏洞。VULN-SEC-OPT-001 已合并到主报告 `cross-module-configs-to-command-exec.md`。

**无需创建独立报告**。

---

## 参考报告

完整技术分析和攻击链请参考：

1. **[cross-module-configs-to-command-exec.md](./cross-module-configs-to-command-exec.md)** - 主报告（完整攻击链分析）
2. **[VULN-SEC-OPT-001.md](./VULN-SEC-OPT-001.md)** - 第一次合并说明

---

**报告生成时间**: 2026-04-21  
**合并判定**: optune-kernel_modifier-replace_param-003 = VULN-SEC-OPT-001，均为 cross-module-configs-to-command-exec 攻击链的核心注入点
