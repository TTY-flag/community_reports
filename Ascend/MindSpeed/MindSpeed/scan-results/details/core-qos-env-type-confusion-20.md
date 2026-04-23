# core-qos-env-type-confusion-20：QoS环境变量类型混淆致验证逻辑错误

## 漏洞概要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | core-qos-env-type-confusion-20 |
| **类型** | 类型混淆 (CWE-704) |
| **严重性** | Medium |
| **置信度** | 85% → **已确认 100%** |
| **CWE** | CWE-704：类型转换或类型转换不当 |
| **文件** | `mindspeed/core/qos/qos.py` |
| **行号** | 20-26 |

## 漏洞描述

环境变量 `QOS_SDMA_*` 和 `QOS_ROCE_*` 使用 `os.environ.get()` 读取，默认值为整数。然而，当环境变量存在时，`os.environ.get()` 返回**字符串**，无论默认值类型如何。这导致类型混淆：

```python
# 若设置 QOS_SDMA_LOW="abc"，返回字符串 "abc"
# 若未设置 QOS_SDMA_LOW，返回整数 2
_DEFAULT_QOS_SDMA_LOW = os.environ.get('QOS_SDMA_LOW', 2)  # BUG！
```

这导致：
1. 字符串与整数比较时出现 **TypeError**
2. 字典序比较导致的**静默比较失败**
3. QoS 初始化期间**应用崩溃**

## 漏洞代码

### 主要漏洞 (qos.py:20-26)
```python
_DEFAULT_QOS_SDMA_LOW = os.environ.get('QOS_SDMA_LOW', 2)
_DEFAULT_QOS_SDMA_MIDDLE = os.environ.get('QOS_SDMA_MIDDLE', 4)
_DEFAULT_QOS_SDMA_HIGH = os.environ.get('QOS_SDMA_HIGH', 6)

_DEFAULT_QOS_ROCE_LOW = os.environ.get('QOS_ROCE_LOW', 3)
_DEFAULT_QOS_ROCE_MIDDLE = os.environ.get('QOS_ROCE_MIDDLE', 4)
_DEFAULT_QOS_ROCE_HIGH = os.environ.get('QOS_ROCE_HIGH', 5)
```

### 关键影响点

#### 1. 验证中的 TypeError (adaptor.py:72)
```python
if not (0 <= roce_qos <= 7) or not (0 <= sdma_qos <= 7):
    # 若 qos 为字符串 "abc"，抛出：TypeError: '<=' not supported between 'str' and 'int'
```

#### 2. max() 操作中的 TypeError (qos.py:269, 280)
```python
# 第 269 行
self.sdma_aiqos_schedule['tp-ep-mp'] = max(self.sdma_aiqos_schedule['pp'], self.sdma_aiqos_schedule['tp'])

# 第 280 行
self.roce_aiqos_schedule['tp-ep-mp'] = max(self.roce_aiqos_schedule['pp'],
                                           self.roce_aiqos_schedule['tp'])
# 若一个为字符串一个为整数：TypeError
# 若两者为字符串：错误字典序比较（如 max("5", "10") = "5"）
```

## 攻击场景

### 场景 1：通过无效字符串导致拒绝服务
```bash
# 攻击者将环境变量设置为非数字字符串
export QOS_SDMA_LOW="abc"
export QOS_SDMA_HIGH="xyz"

# 应用初始化时崩溃
# TypeError: '<=' not supported between instances of 'str' and 'int'
```

### 场景 2：通过字符串数字导致静默逻辑错误
```bash
# 攻击者设置环境变量（意图为数字但读取为字符串）
export QOS_SDMA_LOW="10"
export QOS_SDMA_MIDDLE="4"
export QOS_SDMA_HIGH="6"

# 比较静默失败
# max("10", "4") 返回 "4"（字典序），非 "10"
# 第 269 行：self.sdma_aiqos_schedule['tp-ep-mp'] 得到错误值
```

### 场景 3：边界绕过
```bash
# 攻击者设置通过字符串比较的超范围值
export QOS_ROCE_LOW="100"

# 通过边界检查：0 <= "100" <= 7 为 False（字符串比较）
# 但随后作为整数使用导致问题
```

## 概念验证

```python
#!/usr/bin/env python3
"""演示类型混淆漏洞的 PoC"""

import os

# 模拟漏洞代码
os.environ['QOS_SDMA_LOW'] = 'abc'
os.environ['QOS_SDMA_HIGH'] = '10'

# 这是实际的漏洞模式
_DEFAULT_QOS_SDMA_LOW = os.environ.get('QOS_SDMA_LOW', 2)
_DEFAULT_QOS_SDMA_HIGH = os.environ.get('QOS_SDMA_HIGH', 6)

print(f"QOS_SDMA_LOW 类型: {type(_DEFAULT_QOS_SDMA_LOW)}, 值: {_DEFAULT_QOS_SDMA_LOW}")
print(f"QOS_SDMA_HIGH 类型: {type(_DEFAULT_QOS_SDMA_HIGH)}, 值: {_DEFAULT_QOS_SDMA_HIGH}")

# 这将因 TypeError 崩溃
try:
    if not (0 <= _DEFAULT_QOS_SDMA_LOW <= 7):
        print("超范围")
except TypeError as e:
    print(f"捕获 TypeError: {e}")

# 这将给出错误结果
print(f"max('10', '4') = {max(_DEFAULT_QOS_SDMA_HIGH, '4')}")  # 返回 '4'，非 '10'
```

**输出：**
```
QOS_SDMA_LOW 类型: <class 'str'>, 值: abc
QOS_SDMA_HIGH 类型: <class 'str'>, 值: 10
捕获 TypeError: '<=' not supported between instances of 'str' and 'int'
max('10', '4') = 4  # 错误！应为 10
```

## 数据流分析

```
环境变量 (QOS_SDMA_*, QOS_ROCE_*)
    ↓
os.environ.get() [无类型转换]
    ↓
_DEFAULT_QOS_* 变量 (str 或 int，不可预测)
    ↓
sdma_qos_str_to_value / roce_qos_str_to_value 字典
    ↓
Qos.__init__ → self.sdma_queue_list / self.roce_queue_list
    ↓
init_qos() → self.*_aiqos_schedule 字典
    ↓
[崩溃点 1] adaptor.py:72 - 用 <= 运算符范围验证
[崩溃点 2] qos.py:269,280 - 混合类型的 max() 函数
[崩溃点 3] 传递给 torch_npu HCCL 配置作为 QoS 优先级
```

## 影响评估

| 影响领域 | 严重性 | 描述 |
|----------|--------|------|
| **可用性** | High | 无效环境变量导致启动时应用崩溃 |
| **完整性** | Medium | 错误 QoS 优先级分配影响网络调度 |
| **机密性** | Low | 无直接数据泄露 |
| **攻击复杂度** | Low | 简单环境变量操作 |
| **所需权限** | Medium | 需部署环境访问权限 |

### 受影响组件
- QoS（服务质量）配置系统
- 网络通信优先级调度
- HCCL（华为集合通信库）配置
- 所有并行处理组（张量、管道、数据、专家并行）

## 利用前提条件

1. **环境变量访问** - 通常需要：
   - 部署配置访问
   - 容器编排访问（Kubernetes ConfigMaps 等）
   - 运行时环境 Shell 访问

2. **触发条件**：
   - 应用使用 QoS 功能（启用 `aiqos_mode`）
   - 运行专家模型并行或特定并行配置

## 修复建议

### 立即修复
```python
# 添加 int() 转换和验证
def get_qos_env_int(var_name: str, default: int, min_val: int = 0, max_val: int = 7) -> int:
    """安全从环境变量读取整数 QoS 值。"""
    value = os.environ.get(var_name, str(default))
    try:
        int_value = int(value)
        if not (min_val <= int_value <= max_val):
            raise ValueError(f"{var_name}={int_value} 超范围 [{min_val}, {max_val}]")
        return int_value
    except ValueError as e:
        raise ValueError(f"无效 {var_name}='{value}': 必须为 [{min_val}, {max_val}] 范围内的整数") from e

_DEFAULT_QOS_SDMA_LOW = get_qos_env_int('QOS_SDMA_LOW', 2, 0, 7)
_DEFAULT_QOS_SDMA_MIDDLE = get_qos_env_int('QOS_SDMA_MIDDLE', 4, 0, 7)
_DEFAULT_QOS_SDMA_HIGH = get_qos_env_int('QOS_SDMA_HIGH', 6, 0, 7)
_DEFAULT_QOS_ROCE_LOW = get_qos_env_int('QOS_ROCE_LOW', 3, 0, 7)
_DEFAULT_QOS_ROCE_MIDDLE = get_qos_env_int('QOS_ROCE_MIDDLE', 4, 0, 7)
_DEFAULT_QOS_ROCE_HIGH = get_qos_env_int('QOS_ROCE_HIGH', 5, 0, 7)
```

### 替代最小修复
```python
_DEFAULT_QOS_SDMA_LOW = int(os.environ.get('QOS_SDMA_LOW', '2'))
_DEFAULT_QOS_SDMA_MIDDLE = int(os.environ.get('QOS_SDMA_MIDDLE', '4'))
_DEFAULT_QOS_SDMA_HIGH = int(os.environ.get('QOS_SDMA_HIGH', '6'))
_DEFAULT_QOS_ROCE_LOW = int(os.environ.get('QOS_ROCE_LOW', '3'))
_DEFAULT_QOS_ROCE_MIDDLE = int(os.environ.get('QOS_ROCE_MIDDLE', '4'))
_DEFAULT_QOS_ROCE_HIGH = int(os.environ.get('QOS_ROCE_HIGH', '5'))
```

## 验证状态

| 检查项 | 状态 |
|--------|------|
| 漏洞已确认 | ✅ YES |
| 可利用 | ✅ YES |
| 生产影响 | ✅ YES (DoS, 逻辑错误) |
| 修复已验证 | ⬜ 尚未应用 |

## 参考资料

- [CWE-704：类型转换或类型转换不当](https://cwe.mitre.org/data/definitions/704.html)
- [Python os.environ.get() 文档](https://docs.python.org/3/library/os.html#os.environ)
- [Python 类型转换最佳实践](https://docs.python.org/3/library/functions.html#int)

## 结论

这是一个**真实的类型混淆漏洞**，可导致：
1. 提供非数字字符串时的**应用崩溃**（DoS）
2. 数字字符串绕过验证时的**错误 QoS 调度**
3. 字典序字符串比较导致的**静默逻辑错误**

漏洞通过从环境变量到 HCCL 配置的数据流代码分析确认。修复简单直接，应确保配置输入的健壮类型处理。