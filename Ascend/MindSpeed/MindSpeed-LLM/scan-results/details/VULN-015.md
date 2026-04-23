# VULN-015：Checkpoint转换插件动态加载存在importlib模块注入风险

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-015 |
| **CWE** | CWE-94 (Improper Control of Generation of Code) |
| **严重性** | High |
| **置信度** | 85/100 |
| **位置** | `convert_ckpt.py:22-26` |
| **函数** | `load_plugin` |
| **模块** | root |

---

## 漏洞代码

```python
# convert_ckpt.py:22-26

def load_plugin(plugin_type, name):
    if name == '':
        module_name = f"{MODULE_ROOT}.{plugin_type}"
    else:
        module_name = f"{MODULE_ROOT}.{plugin_type}_{name}"
    try:
        plugin = importlib.import_module(module_name)  # 用户控制 name
    except ModuleNotFoundError:
        # 备用路径...
```

---

## 与 VULN-SEC-DYN-001 关系

**合并报告**: 此漏洞与 VULN-SEC-DYN-001 位置相同，详细分析请参考 `VULN-SEC-DYN-001.md`。

---

## 数据流来源

```
argparse --loader/--saver → name
  ↓
load_plugin(plugin_type, name)
  ↓
importlib.import_module(module_name)
  ↓ [SINK]
动态模块加载
```

---

## 修复建议

参考 `VULN-SEC-DYN-001.md` 中的白名单验证修复方案。

---

**报告生成时间**: 2026-04-20  
**合并说明**: 此漏洞与 VULN-SEC-DYN-001 同位置，完整分析见 VULN-SEC-DYN-001.md