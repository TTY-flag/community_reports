# VULN-SEC-ZMQ-001: 无认证 ZMQ 网络服务

## 漏洞概述

| 属性 | 值 |
|------|-----|
| ID | VULN-SEC-ZMQ-001 |
| CWE | CWE-306 (Missing Authentication for Critical Function) |
| 严重性 | **High** |
| 置信度 | 85/100 |
| 文件 | `mindspeed_rl/utils/transfer_queue/tq_data.py` |
| 行号 | 53-58 |
| 函数 | `__init__` |

---

## 漏洞详情

### 漏洞描述

ZMQ ROUTER socket 绑定到所有网络接口 (`tcp://0.0.0.0`)，没有任何认证机制。任意网络位置的攻击者都可以连接并发送消息，配合 pickle 反序列化漏洞实现完整攻击链。

### 漏洞代码

```python
# tq_data.py:48-58
self.router = self.zmq_context.socket(zmq.ROUTER)

if port is None:
    chosen_port = self.router.bind_to_random_port("tcp://0.0.0.0")  # ⚠️ 所有接口
    bind_addr = f"tcp://0.0.0.0:{chosen_port}"
else:
    bind_addr = f"tcp://0.0.0.0:{port}"  # ⚠️ 所有接口
    self.router.bind(bind_addr)
```

---

## 风险分析

### 绑定 0.0.0.0 的影响

```
tcp://0.0.0.0 绑定到所有网络接口:
├── 127.0.0.1 (本地回环)
├── 10.x.x.x (内网 IP)
├── 192.168.x.x (内网 IP)
└── 公网 IP (如果主机有公网地址)
```

### 无认证机制

- 无 ZMQ CURVE 加密
- 无 PLAIN 用户名密码认证
- 无 IP 白名单
- 无 ZAP 认证协议

---

## 完整攻击链

```
1. ZMQ bind("tcp://0.0.0.0") → 外部可达
2. 无认证 → 任意客户端可连接
3. recv_multipart() → 接收任意消息
4. pickle.loads() → 反序列化恶意数据
5. RCE → 远程代码执行
```

---

## 修复方案

### 紧急修复: 绑定具体内网 IP

```python
# tq_data.py 修改
node_ip = get_node_ip_address()  # Ray 工具获取节点 IP

if port is None:
    chosen_port = self.router.bind_to_random_port(f"tcp://{node_ip}")
else:
    self.router.bind(f"tcp://{node_ip}:{port}")
```

### 中期修复: 添加 ZMQ CURVE 认证

```python
import zmq.auth

# 生成证书
zmq.auth.create_certificates("certs", "server")

# 配置认证
auth = ThreadAuthenticator(context)
auth.start()
auth.allow('10.0.0.0/8')  # IP 白名单
auth.configure_curve(domain='*', location='certs/public_keys')

# 服务器配置
socket.curve_server = True
socket.curve_secretkey = server_secret
socket.curve_publickey = server_public
```

---

## 参考

- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- ZMQ CURVE: https://libzmq.readthedocs.io/en/latest/zmq_curve.html
- ZAP RFC 27: http://rfc.zeromq.org/spec:27