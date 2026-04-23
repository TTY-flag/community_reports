# VULN-ADXL-002：内存耗尽漏洞

## 漏洞概要

| 字段 | 值 |
|------|-----|
| 漏洞ID | VULN-ADXL-002 |
| 漏洞类型 | Memory Exhaustion (内存耗尽) |
| CWE分类 | CWE-789: Uncontrolled Memory Allocation |
| 严重性 | Critical (严重) |
| 置信度 | 85 |
| 影响文件 | `src/llm_datadist/adxl/channel_manager.cc` |
| 漏洞位置 | 第 196-199 行 |
| 受影响函数 | `HandleControlMessage` |

## 漏洞详情

### 漏洞描述

在 `channel_manager.cc` 的 `HandleControlMessage` 函数中，第 199 行使用网络接收的 `expected_body_size_` 参数直接构造 `std::string` 对象：

```cpp
// 第 193-199 行
Status ChannelManager::HandleControlMessage(const ChannelPtr &channel) const {
  ADXL_CHK_BOOL_RET_STATUS(channel->expected_body_size_ > sizeof(ControlMsgType), FAILED,
                           "Received msg invalid, channel:%s.", channel->GetChannelId().c_str());
  auto data = channel->recv_buffer_.data();
  ControlMsgType msg_type = 
    *llm::PtrToPtr<char, ControlMsgType>(data);
  std::string msg_str(data + sizeof(ControlMsgType), channel->expected_body_size_ - sizeof(ControlMsgType));
  // ...
}
```

### 数据流分析

`expected_body_size_` 的来源追溯到网络数据：

```cpp
// 第 140-153 行 ProcessReceivedData
Status ChannelManager::ProcessReceivedData(const ChannelPtr &channel) const {
  while (true) {
    if (channel->recv_state_ == RecvState::WAITING_FOR_HEADER) {
      if (channel->bytes_received_ < sizeof(ProtocolHeader)) {
        break;
      }
      ProtocolHeader *header = nullptr;
      header = llm::PtrToPtr<char, ProtocolHeader>(channel->recv_buffer_.data());
      // header->body_size 来自网络数据，未验证上限
      channel->expected_body_size_ = header->body_size;  // <-- 污点源
      channel->recv_state_ = RecvState::WAITING_FOR_BODY;
      // ...
    }
  }
}
```

**数据流路径**：
1. `recv()` 接收网络数据 → `recv_buffer_`
2. 解析 `ProtocolHeader` → 提取 `body_size` 字段
3. `expected_body_size_` = `header->body_size` (无上限验证)
4. `std::string` 构造使用 `expected_body_size_` 作为长度参数

### 根本原因

漏洞的根本原因是 **缺乏对网络数据中 `body_size` 字段的上限验证**：

1. **第 194 行检查**：仅验证 `expected_body_size_ > sizeof(ControlMsgType)`，即确保消息体至少有一个字节的类型标识
2. **缺失的上限检查**：没有验证 `expected_body_size_` 是否在合理范围内（如 `< MAX_MSG_SIZE`）
3. **直接内存分配**：`std::string` 构造函数会根据指定长度分配内存，若长度为 `UINT64_MAX` 将导致系统内存耗尽

## 攻击路径分析

### 攻击场景

**攻击前提条件**：
- 攻击者能够建立到目标节点的 TCP 连接（ADXL 通道）
- 目标系统运行 `llm_datadist` 模块并监听网络端口

**攻击步骤**：
1. 攻击者连接到目标节点的 ADXL 服务端口
2. 发送精心构造的 `ProtocolHeader`，设置 `body_size` 为极大值（如 `UINT64_MAX - sizeof(ControlMsgType)`）
3. 目标系统接收数据并解析 header
4. `HandleControlMessage` 尝试构造 `std::string`，触发大规模内存分配
5. 系统内存耗尽，导致 OOM（Out of Memory）崩溃或服务拒绝

### 攻击链路

```
[攻击者]
    ↓ TCP 连接
[ChannelManager::HandleChannelEvent] (行 118-138)
    ↓ recv() 接收数据
[ProcessReceivedData] (行 140-191)
    ↓ 解析 ProtocolHeader
[expected_body_size_ = header->body_size] (行 152)  <-- 污点注入点
    ↓ 状态转换
[HandleControlMessage] (行 193-220)
    ↓ std::string msg_str(data, expected_body_size_)  <-- 内存耗尽触发点
[系统 OOM / 服务崩溃]
```

### 攻击可行性评估

| 因素 | 评估 |
|------|------|
| 攻击复杂度 | 低 - 仅需发送恶意网络数据包 |
| 前置条件 | 中 - 需要能够建立 TCP 连接到目标端口 |
| 攻击成功率 | 高 - 无防护措施，攻击几乎必定成功 |
| 影响范围 | 高 - 可导致整个节点服务不可用 |

## 潜在影响分析

### 直接影响

1. **服务拒绝 (DoS)**：目标节点内存耗尽，无法处理其他请求
2. **节点崩溃**：系统触发 OOM Killer，可能终止关键进程
3. **集群级联影响**：在 LLM 推理集群中，单个节点崩溃可能导致整个推理服务中断

### 间接影响

1. **推理延迟增加**：节点重启恢复需要时间
2. **数据丢失风险**：崩溃可能导致未完成的传输任务数据丢失
3. **集群稳定性下降**：频繁攻击可能导致集群频繁重平衡

### 攻击影响矩阵

| 影响维度 | 严重程度 | 说明 |
|----------|----------|------|
| 可用性 | Critical | 完全服务拒绝 |
| 数据完整性 | Medium | 崩溃可能导致传输中断 |
| 系统稳定性 | High | 可能触发系统级 OOM |

## 利用难度评估

### 利用难度：低

**理由**：
- 攻击不需要特殊权限
- 攻击代码简单，仅需构造恶意网络包
- 无需绕过任何防护机制
- 攻击效果立竿见影

### 攻击者能力要求

- 网络访问能力：能够连接到目标 ADXL 端口
- 基础编程能力：能够构造符合协议格式的数据包

## 修复建议

### 优先级：Critical (紧急修复)

### 修复方案

#### 方案 1：添加消息大小上限验证（推荐）

在 `ProcessReceivedData` 函数中，解析 `ProtocolHeader` 后立即验证 `body_size`：

```cpp
// 建议在 channel_manager.cc 第 152 行后添加
constexpr size_t kMaxMessageBodySize = 10 * 1024 * 1024;  // 10 MB 上限

Status ChannelManager::ProcessReceivedData(const ChannelPtr &channel) const {
  // ...
  channel->expected_body_size_ = header->body_size;
  
  // 新增：验证消息体大小上限
  if (channel->expected_body_size_ > kMaxMessageBodySize) {
    LLMLOGE(FAILED, "Message body size too large: %zu, max allowed: %zu, channel:%s",
            channel->expected_body_size_, kMaxMessageBodySize, channel->GetChannelId().c_str());
    return FAILED;
  }
  // ...
}
```

#### 方案 2：使用预分配缓冲区

避免动态内存分配，使用固定大小的缓冲区处理控制消息：

```cpp
// 定义固定大小缓冲区
constexpr size_t kControlMsgBufferSize = 4096;
char msg_buffer[kControlMsgBufferSize];

// 验证大小后使用固定缓冲区
if (channel->expected_body_size_ - sizeof(ControlMsgType) > kControlMsgBufferSize) {
  return FAILED;  // 消息过大
}
memcpy(msg_buffer, data + sizeof(ControlMsgType), 
       channel->expected_body_size_ - sizeof(ControlMsgType));
```

#### 方案 3：渐进式内存分配

对于大消息，分块接收处理，避免一次性大内存分配：

```cpp
// 分块处理大消息
if (channel->expected_body_size_ > kMaxMessageBodySize) {
  return ProcessLargeMessage(channel);  // 特殊处理大消息
}
```

### 修复验证

修复后应确保：
1. 所有网络接收的 size 参数都有上限验证
2. 动态内存分配操作有失败处理
3. 添加单元测试验证恶意大小参数被拒绝

## 缓解措施（临时）

在修复实施前，可采取以下临时缓解措施：

1. **网络层防护**：在防火墙层面限制连接到 ADXL 端口的来源 IP
2. **资源限制**：使用 `ulimit` 或 cgroups 限制进程最大内存使用
3. **监控告警**：监控进程内存使用，异常增长时自动重启服务
4. **连接超时**：设置合理的连接和数据接收超时时间

## 参考信息

- **CWE-789**: https://cwe.mitre.org/data/definitions/789.html
- **CVE 参考**: 多个知名软件因类似问题遭受内存耗尽攻击

---

**报告生成时间**: 2026-04-21
**分析工具**: details-analyzer Agent