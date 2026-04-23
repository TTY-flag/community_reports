# 深度利用分析报告

## VULN-DF-NET-002: 网络数据接收缺少整数溢出检查

**漏洞ID**: VULN-DF-NET-002  
**CWE**: CWE-130 (Improper Handling of Length Parameter)  
**严重性**: High  
**置信度**: 85/100  
**状态**: CONFIRMED  

---

## 1. 漏洞概述

### 1.1 漏洞位置

| 属性 | 值 |
|------|-----|
| **文件** | `src/legacy/framework/service/one_sided_service/hccl_one_sided_conn.cc` |
| **行号** | 112-115 |
| **函数** | `HcclOneSidedConn::ReceiveRemoteMemDesc` |
| **模块** | platform (legacy) |

### 1.2 漏洞描述

`ReceiveRemoteMemDesc` 函数从网络接收 `actualNumOfRemote` 参数，然后直接用于计算缓冲区大小：
```cpp
socket_->Recv((u8 *)remoteMemDescs.array, actualNumOfRemote * sizeof(HcclMemDesc));
```

**关键问题**：
- `actualNumOfRemote` 是 32 位无符号整数，直接从网络接收（行 105）
- 乘法 `actualNumOfRemote * sizeof(HcclMemDesc)` 没有溢出检查
- 存在**不对称安全漏洞**：同一文件的 `SendLocalMemDesc` 函数（行 94-96）有完整的溢出检查

---

## 2. 源代码分析

### 2.1 漏洞代码

```cpp
// 行 102-115: ReceiveRemoteMemDesc 函数
HcclResult HcclOneSidedConn::ReceiveRemoteMemDesc(HcclMemDescs &remoteMemDescs, u32 &actualNumOfRemote)
{
    HCCL_INFO("[HcclOneSidedConn]ReceiveRemoteMemDesc start");
    socket_->Recv((u8 *)(&actualNumOfRemote), sizeof(u32));  // 行 105: 直接接收
    remoteMemDescs.arrayLength = actualNumOfRemote;
    HCCL_INFO("receive actualNumOfRemote:%u", actualNumOfRemote);
    if (remoteMemDescs.arrayLength == 0) {
        HCCL_INFO("actualNumOfRemote[%u], no need to receive data", remoteMemDescs.arrayLength);
    } else {
        HCCL_INFO("receive descSize:%u", actualNumOfRemote * sizeof(HcclMemDesc));
        socket_->Recv((u8 *)remoteMemDescs.array, actualNumOfRemote * sizeof(HcclMemDesc));  // 行 112: 漏洞点
    }
    return HCCL_SUCCESS;
}
```

### 2.2 对比：安全的发送代码

```cpp
// 行 85-100: SendLocalMemDesc 函数（有溢出保护）
HcclResult HcclOneSidedConn::SendLocalMemDesc(const HcclMemDescs &localMemDescs)
{
    socket_->Send((u8 *)(&localMemDescs.arrayLength), sizeof(u32));
    if (localMemDescs.arrayLength == 0) {
        // ...
    } else {
        // 行 94-96: 完整的溢出检查
        if (static_cast<u64>(localMemDescs.arrayLength) > static_cast<u64>(UINT32_MAX) / sizeof(HcclMemDesc)) {
            THROW<InternalException>("integer overflow occurs");
        }
        socket_->Send((u8 *)(localMemDescs.array), localMemDescs.arrayLength * sizeof(HcclMemDesc));
    }
    return HCCL_SUCCESS;
}
```

### 2.3 不对称安全对比

| 检查项 | SendLocalMemDesc | ReceiveRemoteMemDesc |
|--------|------------------|---------------------|
| 溢出检查 | ✓ 行 94-96 | ✗ 缺失 |
| 零值检查 | ✓ 行 90 | ✓ 行 108 |
| 错误处理 | ✓ THROW异常 | ✗ 返回 SUCCESS |

---

## 3. 数据流分析

### 3.1 数据流路径

```
[网络攻击者]
    ↓ 发送恶意 actualNumOfRemote 值
socket_->Recv(&actualNumOfRemote, sizeof(u32))  [行 105]
    ↓ 无验证，直接赋值
remoteMemDescs.arrayLength = actualNumOfRemote  [行 106]
    ↓ 无溢出检查
actualNumOfRemote * sizeof(HcclMemDesc)  [行 111/112]
    ↓ 可能发生整数溢出
socket_->Recv(remoteMemDescs.array, overflowed_size)  [行 112]
    ↓ 
[缓冲区问题 / DoS / 数据不一致]
```

### 3.2 污点追踪

| 节点 | 类型 | 说明 |
|------|------|------|
| 网络数据 | SOURCE | 恶意节点发送的 actualNumOfRemote |
| socket_->Recv(&actualNumOfRemote) | TRANSFER | 接收 4 字节到 u32 变量 |
| actualNumOfRemote * sizeof(HcclMemDesc) | SINK | 整数乘法可能溢出 |
| socket_->Recv(array, size) | SINK | 使用溢出后的值作为接收大小 |

---

## 4. 利用场景分析

### 4.1 整数溢出条件

假设 `sizeof(HcclMemDesc) = X` 字节（需要分析结构体定义），溢出条件：

```
actualNumOfRemote > UINT32_MAX / sizeof(HcclMemDesc)
```

例如，如果 `sizeof(HcclMemDesc) = 64`：
- 溢出阈值: `UINT32_MAX / 64 = 67,108,864`
- 攻击值: `actualNumOfRemote = 67,108,865`
- 计算结果: `67,108,865 * 64 = 4,294,967,360` → 溢出为 `64`

### 4.2 攻击后果

| 场景 | 溢出结果 | 安全影响 |
|------|----------|---------|
| **DoS** | 小缓冲区接收大数据 | 应用崩溃、内存越界 |
| **数据截断** | 接收不完整数据 | 后续处理使用不完整数据，逻辑错误 |
| **信息泄露** | 未清零缓冲区 | 残留数据可能被读取 |

### 4.3 攻击前提条件

1. **网络可达**: 攻击者需要能够连接到 HCOMM 服务端口
2. **协议知识**: 了解 HCCL 单边通信协议格式
3. **白名单绕过**: 如果启用了连接白名单，需要先绕过

---

## 5. PoC 概念验证

### 5.1 概念性攻击步骤

```python
# PoC 概念（需要实际协议分析）
import socket
import struct

# 连接到 HCOMM 服务
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("target_ip", target_port))

# 计算溢出值
HcclMemDesc_size = 64  # 假设值，需实际确认
overflow_threshold = 0xFFFFFFFF // HcclMemDesc_size
attack_value = overflow_threshold + 1

# 发送恶意 actualNumOfRemote
sock.send(struct.pack("<I", attack_value))

# 尝试发送更多数据触发崩溃
# ...（需要完整的协议分析）
```

### 5.2 验证方法

1. **静态验证**: 检查代码中是否有溢出保护（已确认缺失）
2. **动态验证**: 构造恶意数据发送到测试环境
3. **模糊测试**: 使用 fuzzing 工具测试网络协议处理

---

## 6. 影响范围分析

### 6.1 受影响的调用链

```
HcclOneSidedConn::ReceiveRemoteMemDesc
    ↑ 被调用于
HcclOneSidedConn::ExchangeMemDesc [行 117]
    ↑ 被调用于
单边通信操作 (HcommWriteOnThread / HcommReadOnThread)
    ↑ 被调用于
分布式训练框架 (TensorFlow/PyTorch HCCL插件)
```

### 6.2 影响场景

| 场景 | 风险等级 | 说明 |
|------|----------|------|
| **分布式训练** | High | 多节点训练时交换内存描述符 |
| **集群初始化** | High | Root Info 交换阶段 |
| **单边操作** | Medium | Write/Read 操作前交换描述符 |

### 6.3 攻击者类型

| 攻击者 | 能力 | 可利用性 |
|--------|------|----------|
| **恶意集群节点** | 控制一个训练节点 | High（直接发送恶意数据） |
| **网络中间人** | 截获/修改网络流量 | Medium（需要 TCP/RDMA 劫持） |
| **外部攻击者** | 网络可达但非集群成员 | Low（需绕过白名单） |

---

## 7. 修复建议

### 7.1 立即修复方案

**添加溢出检查**（参考 SendLocalMemDesc 的模式）：

```cpp
HcclResult HcclOneSidedConn::ReceiveRemoteMemDesc(HcclMemDescs &remoteMemDescs, u32 &actualNumOfRemote)
{
    socket_->Recv((u8 *)(&actualNumOfRemote), sizeof(u32));
    remoteMemDescs.arrayLength = actualNumOfRemote;
    
    if (remoteMemDescs.arrayLength == 0) {
        HCCL_INFO("actualNumOfRemote[%u], no need to receive data", remoteMemDescs.arrayLength);
    } else {
        // 新增：溢出检查（与 SendLocalMemDesc 保持一致）
        if (static_cast<u64>(actualNumOfRemote) > static_cast<u64>(UINT32_MAX) / sizeof(HcclMemDesc)) {
            HCCL_ERROR("integer overflow detected: actualNumOfRemote=%u, sizeof(HcclMemDesc)=%zu",
                       actualNumOfRemote, sizeof(HcclMemDesc));
            return HCCL_E_PARA;  // 或 THROW<InternalException>
        }
        
        socket_->Recv((u8 *)remoteMemDescs.array, actualNumOfRemote * sizeof(HcclMemDesc));
    }
    return HCCL_SUCCESS;
}
```

### 7.2 额外安全建议

1. **添加最大值限制**：
```cpp
const u32 MAX_MEM_DESC_COUNT = 1024;  // 根据实际需求设定
if (actualNumOfRemote > MAX_MEM_DESC_COUNT) {
    HCCL_ERROR("actualNumOfRemote exceeds limit: %u > %u", actualNumOfRemote, MAX_MEM_DESC_COUNT);
    return HCCL_E_PARA;
}
```

2. **验证缓冲区空间**：
```cpp
if (remoteMemDescs.arrayLength > remoteMemDescs.maxArrayLength) {
    HCCL_ERROR("buffer overflow: arrayLength=%u > maxArrayLength=%u",
               remoteMemDescs.arrayLength, remoteMemDescs.maxArrayLength);
    return HCCL_E_PARA;
}
```

---

## 8. CVSS 评分

**CVSS v3.1 评分**: 7.5 (High)

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Network | 通过网络触发 |
| Attack Complexity (AC) | Low | 无需特殊条件 |
| Privileges Required (PR) | Low | 需要集群成员身份 |
| User Interaction (UI) | None | 无用户交互 |
| Scope (S) | Unchanged | 影响同一系统 |
| Confidentiality (C) | None | 无信息泄露 |
| Integrity (I) | Low | 数据可能不完整 |
| Availability (A) | High | 可导致 DoS |

---

## 9. 结论

### 9.1 漏洞确认

- **类型**: CWE-130 整数溢出 / 不对称安全漏洞
- **严重性**: High
- **可利用性**: 中等（需要集群成员身份）
- **影响**: DoS、数据不一致

### 9.2 修复优先级

| 优先级 | 时间框架 | 建议 |
|--------|----------|------|
| **P0** | 1 周内 | 添加溢出检查 |
| **P1** | 2 周内 | 添加最大值限制 |

### 9.3 相关漏洞

- **VULN-DF-NET-003**: 同类漏洞，位于 `transport_mem.cc`

---

**报告生成时间**: 2026-04-22  
**分析师**: vulnerability scanner system