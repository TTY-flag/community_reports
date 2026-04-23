# VULN-DF-NET-003：网络数据接收整数溢出漏洞

**漏洞ID**: VULN-DF-NET-003  
**CWE**: CWE-130 (Improper Handling of Length Parameter)  
**严重性**: High  
**置信度**: 85/100  
**状态**: CONFIRMED  

---

## 1. 漏洞概述

### 1.1 漏洞位置

| 属性 | 值 |
|------|-----|
| **文件** | `src/platform/resource/transport/onesided/transport_mem.cc` |
| **行号** | 165 |
| **函数** | `TransportMem::ReceiveRemoteMemDesc` |
| **模块** | platform |

### 1.2 漏洞描述

`ReceiveRemoteMemDesc` 函数从网络接收 `actualNumOfRemote` 参数后，直接用于计算接收缓冲区大小：

```cpp
ret = dataSocket_->Recv(remoteMemDescs.array, actualNumOfRemote * sizeof(RmaMemDesc));
```

**问题本质**：与 VULN-DF-NET-002 相同，缺少整数溢出检查。

---

## 2. 源代码分析

### 2.1 漏洞代码（完整函数）

```cpp
// 行 153-171: ReceiveRemoteMemDesc 函数
HcclResult TransportMem::ReceiveRemoteMemDesc(RmaMemDescs &remoteMemDescs, u32 &actualNumOfRemote)
{
    // 行 155: 从网络接收 actualNumOfRemote
    HcclResult ret = dataSocket_->Recv(&actualNumOfRemote, sizeof(u32));
    remoteMemDescs.arrayLength = actualNumOfRemote;
    
    CHK_PRT_RET(ret != HCCL_SUCCESS,
        HCCL_ERROR("errNo[0x%016llx] localRank[%u] receive actualNumOfRemote to remote "\
            "failed, ret[%u]", HCCL_ERROR_CODE(ret), localRankId_, ret), ret);
    
    HCCL_DEBUG("receive actualNumOfRemote:%u", actualNumOfRemote);
    
    if (actualNumOfRemote == 0) {
        HCCL_INFO("actualNumOfRemote[%u], no need to receive data", actualNumOfRemote);
    } else {
        HCCL_DEBUG("receive descSize:%u", actualNumOfRemote * sizeof(RmaMemDesc));
        // 行 165: 漏洞点 - 无溢出检查
        ret = dataSocket_->Recv(remoteMemDescs.array, actualNumOfRemote * sizeof(RmaMemDesc));
        
        CHK_PRT_RET(ret != HCCL_SUCCESS,
            HCCL_ERROR("errNo[0x%016llx] localRank[%u] receive remoteMemDesc from remote "\
                "failed, ret[%u]", HCCL_ERROR_CODE(ret), localRankId_, ret), ret);
    }
    return HCCL_SUCCESS;
}
```

### 2.2 缺失的安全检查

对比 `HcclOneSidedConn::SendLocalMemDesc` 的溢出保护：

```cpp
// 应该存在但实际缺失的检查：
if (static_cast<u64>(actualNumOfRemote) > static_cast<u64>(UINT32_MAX) / sizeof(RmaMemDesc)) {
    // 错误处理
    return HCCL_E_PARA;
}
```

---

## 3. 数据流分析

### 3.1 污点追踪图

```
[远程恶意节点]
    ↓ 发送恶意 actualNumOfRemote
dataSocket_->Recv(&actualNumOfRemote)  [行 155 - SOURCE]
    ↓ 直接赋值，无验证
remoteMemDescs.arrayLength = actualNumOfRemote  [行 156]
    ↓ 进入 else 分支
actualNumOfRemote * sizeof(RmaMemDesc)  [行 164/165 - SINK]
    ↓ 整数溢出可能发生
dataSocket_->Recv(array, overflowed_size)  [行 165 - SINK]
```

### 3.2 关键数据流节点

| 节点位置 | 数据 | 说明 |
|----------|------|------|
| 行 155 | `actualNumOfRemote` | 从网络接收，受攻击者控制 |
| 行 156 | `arrayLength` | 直接赋值，未检查范围 |
| 行 164 | `descSize` | 日志输出溢出后的值（调试可见） |
| 行 165 | `Recv buffer size` | 使用溢出值，核心漏洞点 |

---

## 4. 利用场景分析

### 4.1 整数溢出计算

假设 `sizeof(RmaMemDesc)` 结构体大小：

| 假设值 | 溢出阈值 | 攻击值 |
|--------|----------|--------|
| 32 bytes | 134,217,728 | 134,217,729 |
| 64 bytes | 67,108,864 | 67,108,865 |
| 128 bytes | 33,554,432 | 33,554,433 |

**溢出示例**（假设 sizeof(RmaMemDesc) = 64）：
```
攻击值: 67,108,865
计算: 67,108,865 * 64 = 4,294,967,360
溢出: 4,294,967,360 mod 2^32 = 64
结果: 实际只接收 64 字节，但声称接收更多
```

### 4.2 攻击后果矩阵

| 攻击场景 | 技术效果 | 业务影响 |
|----------|----------|----------|
| **缓冲区越界** | Recv 尝试写入超过分配的内存 | 进程崩溃、DoS |
| **数据截断** | 接收不完整的描述符数组 | 后续单边操作使用错误地址 |
| **逻辑错误** | arrayLength 与实际数据不匹配 | 训练任务失败 |
| **内存损坏** | 堆/栈破坏 | 潜在代码执行（较难） |

### 4.3 与 VULN-DF-NET-002 的关联

两个漏洞属于同一类问题，位于不同的传输层：

| 层次 | 文件 | 用途 |
|------|------|------|
| Legacy 层 | hccl_one_sided_conn.cc | 单边服务连接 |
| Transport 层 | transport_mem.cc | 内存传输实现 |

---

## 5. PoC 概念验证

### 5.1 攻击流程概念

```
步骤 1: 建立连接（需满足白名单或其他认证）
步骤 2: 进入 ReceiveRemoteMemDesc 调用路径
步骤 3: 发送恶意 actualNumOfRemote 值
    - 计算: (UINT32_MAX / sizeof(RmaMemDesc)) + 1
步骤 4: 观察系统行为
    - 检查日志中 "receive descSize" 的值（行 164）
    - 观察是否有崩溃或错误
```

### 5.2 触发条件

```
必要条件:
1. 攻击者是集群成员（或在白名单内）
2. 使用单边通信功能（RMA/One-sided）
3. actualNumOfRemote > UINT32_MAX / sizeof(RmaMemDesc)

充分条件:
1. remoteMemDescs.array 缓冲区大小有限
2. 实际发送数据量与声称值不符
```

---

## 6. 影响范围分析

### 6.1 调用路径

```
TransportMem::ReceiveRemoteMemDesc
    ↑
单边传输操作
    ↑
分布式训练集合通信
    ↑
TensorFlow / PyTorch HCCL 插件
```

### 6.2 受影响组件

| 组件 | 风险 | 说明 |
|------|------|------|
| RMA 单边操作 | High | Write/Read 前需要交换描述符 |
| 集合通信 | Medium | AllToAll 等操作可能触发 |
| 内存注册 | Medium | 描述符包含内存地址信息 |

---

## 7. 修复建议

### 7.1 立即修复

```cpp
HcclResult TransportMem::ReceiveRemoteMemDesc(RmaMemDescs &remoteMemDescs, u32 &actualNumOfRemote)
{
    HcclResult ret = dataSocket_->Recv(&actualNumOfRemote, sizeof(u32));
    CHK_PRT_RET(ret != HCCL_SUCCESS, ..., ret);
    
    remoteMemDescs.arrayLength = actualNumOfRemote;
    
    // 新增：溢出检查
    if (actualNumOfRemote > 0) {
        u64 expectedSize = static_cast<u64>(actualNumOfRemote) * sizeof(RmaMemDesc);
        if (expectedSize > UINT32_MAX || expectedSize / sizeof(RmaMemDesc) != actualNumOfRemote) {
            HCCL_ERROR("Integer overflow detected: actualNumOfRemote=%u, sizeof(RmaMemDesc)=%zu",
                       actualNumOfRemote, sizeof(RmaMemDesc));
            return HCCL_E_PARA;
        }
        
        // 新增：缓冲区容量检查
        if (actualNumOfRemote > remoteMemDescs.maxArrayLength) {
            HCCL_ERROR("Buffer overflow: requested %u > capacity %u",
                       actualNumOfRemote, remoteMemDescs.maxArrayLength);
            return HCCL_E_PARA;
        }
    }
    
    if (actualNumOfRemote == 0) {
        HCCL_INFO("actualNumOfRemote[%u], no need to receive data", actualNumOfRemote);
    } else {
        ret = dataSocket_->Recv(remoteMemDescs.array, actualNumOfRemote * sizeof(RmaMemDesc));
        CHK_PRT_RET(ret != HCCL_SUCCESS, ..., ret);
    }
    return HCCL_SUCCESS;
}
```

### 7.2 系统性修复

建议在所有网络数据接收点统一添加溢出检查：

1. 搜索所有 `Recv(&count, sizeof(u32))` 模式
2. 检查后续的 `count * sizeof(...)` 计算
3. 添加统一的溢出检查宏

---

## 8. CVSS 评分

**CVSS v3.1**: 7.5 (High)

与 VULN-DF-NET-002 相同评分，攻击向量相同。

---

## 9. 结论

### 9.1 漏洞确认

| 属性 | 值 |
|------|-----|
| 类型 | CWE-130 整数溢出 |
| 严重性 | High |
| 根因 | 缺少乘法溢出检查 |
| 关联 | VULN-DF-NET-002（同类漏洞） |

### 9.2 修复优先级

**P0 - 1 周内修复**，与 VULN-DF-NET-002 同批次处理。

---

**报告生成时间**: 2026-04-22