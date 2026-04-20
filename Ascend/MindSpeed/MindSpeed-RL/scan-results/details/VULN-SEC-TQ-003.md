# VULN-SEC-TQ-003: Pickle 反序列化远程代码执行 (客户端响应)

## 漏洞概述

| 属性 | 值 |
|------|-----|
| ID | VULN-SEC-TQ-003 |
| CWE | CWE-502 (Deserialization of Untrusted Data) |
| 严重性 | **Critical** |
| 置信度 | 90/100 |
| 文件 | `mindspeed_rl/utils/transfer_queue/tq_client.py` |
| 行号 | 368 |
| 函数 | `get_experience` |

---

## 漏洞详情

### 漏洞描述

客户端接收的 ZMQ 响应数据被直接传递给 `pickle.loads()`。攻击者可通过 MitM 或恶意 shard 服务器注入恶意 payload。

### 漏洞代码

```python
# tq_client.py:360-368
sock.send_multipart([b"GET", pickle.dumps(payload)])
reply = sock.recv_multipart()
if not (reply and reply[0]):
    raise RuntimeError(f"No response received")

response = pickle.loads(reply[0])  # ⚠️ VULNERABLE
shard_experience = deserialize_tensor_lists(response["experience_bytes"])
```

---

## 攻击场景

### 场景 1: MitM 攻击

```
合法客户端 → ZMQ DEALER → [攻击者拦截] → ZMQ ROUTER → shard
                              ↓
                    替换响应为恶意 payload
                              ↓
客户端 → pickle.loads(malicious_response) → RCE
```

### 场景 2: 恶意 Shard

如果攻击者已控制某个 shard 服务器，可在响应中注入恶意 payload。

---

## 影响

- **客户端 RCE**: 在客户端进程中执行任意代码
- **训练中断**: 可破坏训练流程
- **数据篡改**: 可修改接收的训练数据

---

## 修复方案

### 端到端签名

```python
# 服务端签名响应
def send_signed_response(socket, identity, response):
    payload = pickle.dumps(response)
    signature = hmac.new(SECRET_KEY, payload, hashlib.sha256).hexdigest()
    signed = f"{signature}|".encode() + payload
    socket.send_multipart([identity, signed])

# 客户端验证签名
def recv_and_verify(socket):
    reply = socket.recv_multipart()
    sig, payload = reply[0].split(b"|", 1)
    expected = hmac.new(SECRET_KEY, payload, hashlib.sha256).hexdigest()
    if sig.decode() != expected:
        raise ValueError("Invalid signature")
    return pickle.loads(payload)
```

---

## 参考

- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- CVE-2024-27132: MLflow Redis cache RCE (类似模式)