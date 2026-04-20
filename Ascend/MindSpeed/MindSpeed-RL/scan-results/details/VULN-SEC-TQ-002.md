# VULN-SEC-TQ-002: Pickle 反序列化远程代码执行 (PUT 命令)

## 漏洞概述

| 属性 | 值 |
|------|-----|
| ID | VULN-SEC-TQ-002 |
| CWE | CWE-502 (Deserialization of Untrusted Data) |
| 严重性 | **Critical** |
| 置信度 | 95/100 |
| 文件 | `mindspeed_rl/utils/transfer_queue/tq_data.py` |
| 行号 | 147 |
| 函数 | `_serve_loop` |

---

## 漏洞详情

### 漏洞描述

与 TQ-001 相同的漏洞模式，但位于 PUT 命令处理分支。攻击者通过发送 PUT 命令触发 pickle 反序列化。

### 漏洞代码

```python
# tq_data.py:142-158
elif command == "PUT":
    if len(msg) < 3:
        self.router.send_multipart([identity, b"ERROR: Missing data for PUT"])
    else:
        payload = pickle.loads(msg[2])  # ⚠️ VULNERABLE
        self._handle_put(
            payload["topic"],
            payload["experience_columns"],
            deserialize_tensor_lists(payload["experience_bytes"]),
            payload["indexes"],
            payload["data_status"],
        )
```

---

## 利用步骤

与 TQ-001 相同，仅命令类型不同：

```python
socket.send_multipart([b"attacker", b"PUT", payload])
```

---

## 修复方案

与 TQ-001 相同的修复方案：
1. 替换 pickle 为 json/msgpack
2. 添加 HMAC 签名验证
3. 使用 RestrictedUnpickler 白名单

---

## 参考

- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- VULN-SEC-TQ-001: 同文件第 127 行的相同漏洞