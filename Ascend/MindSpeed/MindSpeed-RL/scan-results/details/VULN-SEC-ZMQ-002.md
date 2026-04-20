# VULN-SEC-ZMQ-002: 无认证 ZMQ 网络服务 (Pub/Sub 模式)

## 漏洞概述

| 属性 | 值 |
|------|-----|
| ID | VULN-SEC-ZMQ-002 |
| CWE | CWE-306 (Missing Authentication for Critical Function) |
| 严重性 | **High** |
| 置信度 | 80/100 |
| 文件 | `mindspeed_rl/utils/zmq_communication.py` |
| 行号 | 169-174 |
| 函数 | `init_socket` |

---

## 漏洞详情

### 漏洞描述

ZMQ PUB/REP/PULL socket 绑定到可配置的 IP 地址，但无认证机制。客户端可订阅发布数据、发送注册请求、发送确认消息，全部无认证。

### 漏洞代码

```python
# zmq_communication.py:169-174
self.publisher = self.context.socket(zmq.PUB)
self.publisher.bind(f"tcp://{self.server_info.ip_addr}:{self.server_info.publisher_port}")

self.register = self.context.socket(zmq.REP)
self.register.bind(f"tcp://{self.server_info.ip_addr}:{self.server_info.register_port}")

self.reliability = self.context.socket(zmq.PULL)
self.reliability.bind(f"tcp://{self.server_info.ip_addr}:{self.server_info.reliability_port}")
```

---

## 攻击场景

### 1. 数据订阅攻击

攻击者可订阅 PUB socket，获取训练过程中的数据广播。

### 2. 注册攻击

攻击者可发送恶意注册请求：

```python
socket = context.socket(zmq.REQ)
socket.connect("tcp://server:register_port")
socket.send_json({"type": "register", "rank": 999})  # 伪造 rank
```

### 3. ACK 注入

攻击者可发送伪造的可靠性确认消息：

```python
socket = context.socket(zmq.PUSH)
socket.connect("tcp://server:reliability_port")
socket.send(b"fake_ack")
```

---

## 修复方案

### 添加注册认证

```python
# zmq_communication.py 修改
def handle_register(self):
    message = self.register.recv_json()
    
    # ✅ 添加 token 验证
    if message.get("token") != self.auth_token:
        self.register.send_json({"type": "error", "message": "Unauthorized"})
        return
    
    if message.get("type") == "register":
        rank = message.get("rank")
        self.ready_pubsub_rank.add(rank)
        self.register.send_json({"type": "register_ack", "status": "ok"})
```

### 启用 ZMQ CURVE

```python
# 所有 socket 配置 CURVE
socket.curve_server = True
socket.curve_secretkey = server_secret
socket.curve_publickey = server_public
```

---

## 参考

- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- ZMQ Security Patterns: http://hintjens.com/blog:49