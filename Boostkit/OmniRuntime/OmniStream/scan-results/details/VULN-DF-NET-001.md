# VULN-DF-NET-001：网络缓冲区readInt无上限验证漏洞

## 漏洞标识

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-DF-NET-001 |
| **严重程度** | **High（高危）** |
| **置信度** | 80% |
| **CWE 编号** | CWE-190（整数溢出或环绕）+ CWE-120（缓冲区溢出） |
| **涉及模块** | runtime_io_network |

---

## 一、漏洞概述

本漏洞位于网络反序列化组件 `NonSpanningWrapper::readInt()` 中，从网络缓冲区读取的 32 位整数（record length）缺乏上限验证。恶意远程 TaskManager 可以发送极大或负数的 recordLength 值，导致后续的缓冲区分配出现异常行为。

这是一个典型的网络协议解析安全问题：来自不可信网络源的数据被直接用于内存分配决策，缺乏合理范围检查。

---

## 二、漏洞代码分析

### 原始代码（存在漏洞）

```cpp
// cpp/runtime/io/network/api/serialization/NonSpanningWrapper.h
// Lines 131-147
inline int NonSpanningWrapper::readInt()
{
    // big endian
    // 仅检查是否有足够的字节可读
    if (unlikely(position_ + sizeof(uint32_t) > length_)) {
        THROW_LOGIC_EXCEPTION("EOFException");
    }
    
    // 从网络缓冲区读取 32 位整数
    uint32_t value = (static_cast<uint32_t>(data_[position_]) << 24) |
                     (static_cast<uint32_t>(data_[position_ + 1]) << 16) |
                     (static_cast<uint32_t>(data_[position_ + 2]) << 8) |
                     static_cast<uint32_t>(data_[position_ + 3]);
    
    position_ += sizeof(uint32_t);
    
    // **问题**：返回完整的 32 位整数，无上限验证！
    return static_cast<int>(value);
}
```

### 问题分析

| 问题 | 说明 |
|------|------|
| **无上限验证** | readInt() 只检查边界，不检查值范围 |
| **负数风险** | static_cast<int> 可能产生负值 |
| **极大值风险** | 最大可达 INT_MAX (2,147,483,647) |
| **网络来源** | data_ 来自远程 TaskManager（不可信） |

---

## 三、数据流分析

### recordLength 的使用路径

```
┌─────────────────────────────────────────────────────────────────────────┐
│  远程 TaskManager（不可信网络源）                                          │
│  • 发送网络缓冲区数据                                                      │
│  • 可以控制 buffer 内容                                                   │
│  • 可以设置任意 recordLength 值                                           │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 网络传输
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  SingleInputGate::getNextBuffer()                                       │
│  • 接收来自远程 TaskManager 的缓冲区                                      │
│  • 缓冲区内容包含 recordLength 字段                                        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ setNextBuffer(buffer, size)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  SpillingAdaptiveSpanningRecordDeserializer.cpp                         │
│  Line 56-63: readNonSpanningRecord()                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │  int recordLen = nonSpanningWrapper->readInt();  // 获取长度          ││
│  │  if (nonSpanningWrapper->canReadRecord(recordLen)) {                ││
│  │      // recordLen <= remaining()                                    ││
│  │      return nonSpanningWrapper->readInto(target);                   ││
│  │  } else {                                                           ││
│  │      spanningWrapper->transferFrom(*nonSpanningWrapper, recordLen); ││
│  │      // **触发缓冲区扩展**                                            ││
│  │  }                                                                  ││
│  └─────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ transferFrom(recordLen)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  SpanningWrapper.h                                                       │
│  Line 186-192: ensureBufferCapacity(recordLen)                          │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │  if (minLength > buffer_.capacity()) {                              ││
│  │      int newCapacity_ = std::max(minLength,                         ││
│  │                              static_cast<int>(buffer_.capacity()*2));││
│  │      buffer_.reserve(newCapacity_);  // **内存分配**                  ││
│  │  }                                                                  ││
│  └─────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 攻击效果
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  **攻击效果**                                                             │
│  • recordLen = INT_MAX → 申请 2GB 内存                                   │
│  • recordLen = -1 → 转换为极大正值                                        │
│  • 内存分配失败 → 进程崩溃                                                │
│  • 内存分配成功 → 内存耗尽                                                │
└─────────────────────────────────────────────────────────────────────────┘
```

### canReadRecord 的局限性

```cpp
// NonSpanningWrapper.h Line 154-157
inline bool NonSpanningWrapper::canReadRecord(int recordLength) const
{
    return recordLength <= remaining();  // 只检查当前缓冲区剩余
}
```

**问题**：`canReadRecord` 只检查当前缓冲区是否有足够数据，不检查 recordLength 是否合理。

---

## 四、攻击场景分析

### 攻击方式

#### 1. 极大值攻击

远程 TaskManager 发送：
```
网络缓冲区内容：
[4字节 recordLength = INT_MAX (0x7FFFFFFF)]
[数据...]
```

结果：
- `readInt()` 返回 2,147,483,647
- `canReadRecord()` 返回 false（缓冲区不够大）
- `SpanningWrapper::ensureBufferCapacity()` 尝试分配 2GB 内存
- 内存分配失败 → OOM → 进程崩溃

#### 2. 负数攻击

由于 `readInt()` 使用 `static_cast<int>(value)`，当 value > INT_MAX 时会产生负数：

```
网络缓冲区内容：
[4字节 recordLength = 0x80000001 (超出 INT_MAX)]
```

结果：
- `static_cast<int>(0x80000001)` = -2,147,483,647
- 负数处理可能触发未定义行为
- 后续逻辑可能出错

#### 3. 资源耗尽攻击

远程 TaskManager 反复发送大量 "大 recordLength" 的缓冲区：
- 每次请求大量内存
- 即使分配失败，已分配的内存可能不被释放
- 最终导致 TaskExecutor 内存耗尽

---

## 五、利用条件与前置要求

| 条件类型 | 具体要求 | 难度评估 |
|----------|----------|----------|
| **网络访问** | 能连接到 TaskManager 网络端口 | 需要内网访问 |
| **协议控制** | 能构造恶意网络缓冲区 | 中等 |
| **远程 TM 控制** | 或控制一个远程 TaskManager | 高 |

### 利用难度评估

- **攻击复杂度**：中等（需要了解 Flink 网络协议）
- **前置条件**：高（需要控制远程 TaskManager 或中间人攻击）
- **影响范围**：极高（可导致 TaskExecutor 崩溃）

---

## 六、潜在影响范围

### 直接影响

1. **进程崩溃**
   - 极大 recordLength 导致内存分配失败
   - TaskExecutor 进程可能崩溃
   - 所有运行的任务受影响

2. **拒绝服务**
   - 阻止任务接收网络数据
   - 流处理链中断
   - 集群功能受损

3. **资源耗尽**
   - 反复攻击消耗系统内存
   - 其他进程受影响
   - 需要重启 TaskExecutor

### 间接影响

1. **集群不稳定**：多个 TaskExecutor 受影响
2. **任务链断裂**：下游算子无法接收数据
3. **运维负担**：需要重启和排查

---

## 七、代码证据

### 现有保护措施（不充分）

```cpp
// NonSpanningWrapper.h - 位置边界检查（存在）
if (unlikely(position_ + sizeof(uint32_t) > length_)) {
    THROW_LOGIC_EXCEPTION("EOFException");
}

// SpanningWrapper.h - 边界检查（存在但不针对上限）
if (recordLength_ >= 0 && accumulatedRecordBytes_ >= recordLength_) {
    // 只检查是否已累积足够数据
}
```

### 缺失的上限验证

```cpp
// 应该添加但没有的检查：
const int MAX_RECORD_SIZE = 100 * 1024 * 1024;  // 100MB 上限
if (recordLen > MAX_RECORD_SIZE || recordLen < 0) {
    THROW_LOGIC_EXCEPTION("Invalid record length: " + std::to_string(recordLen));
}
```

---

## 八、修复建议

### 紧急修复（优先级 P0）

#### 方案 1：在 readInt 后添加验证

```cpp
// SpillingAdaptiveSpanningRecordDeserializer.cpp - 修复版本
DeserializationResult &SpillingAdaptiveSpanningRecordDeserializer::readNonSpanningRecord(IOReadableWritable &target)
{
    int recordLen = nonSpanningWrapper->readInt();
    
    // **新增**：上限验证
    const int MAX_RECORD_SIZE = 100 * 1024 * 1024;  // 100MB
    if (recordLen > MAX_RECORD_SIZE) {
        LOG_ERROR("Record length exceeds maximum allowed: " + std::to_string(recordLen));
        THROW_LOGIC_EXCEPTION("Record size limit exceeded");
    }
    if (recordLen < 0) {
        LOG_ERROR("Negative record length: " + std::to_string(recordLen));
        THROW_LOGIC_EXCEPTION("Invalid negative record length");
    }
    
    if (nonSpanningWrapper->canReadRecord(recordLen)) {
        return nonSpanningWrapper->readInto(target);
    } else {
        spanningWrapper->transferFrom(*nonSpanningWrapper, recordLen);
        return DeserializationResult_PARTIAL_RECORD;
    }
}
```

#### 方案 2：在 SpanningWrapper 添加验证

```cpp
// SpanningWrapper.h - 修复版本
inline void SpanningWrapper::ensureBufferCapacity(int minLength)
{
    // **新增**：上限验证
    const int MAX_BUFFER_SIZE = 200 * 1024 * 1024;  // 200MB
    if (minLength > MAX_BUFFER_SIZE) {
        THROW_LOGIC_EXCEPTION("Buffer size request exceeds maximum: " + std::to_string(minLength));
    }
    
    if (static_cast<size_t>(minLength) > buffer_.capacity()) {
        int newCapacity_ = std::max(minLength, static_cast<int>(buffer_.capacity() * 2));
        // 限制 newCapacity_ 不超过 MAX_BUFFER_SIZE
        newCapacity_ = std::min(newCapacity_, MAX_BUFFER_SIZE);
        buffer_.reserve(newCapacity_);
    }
}
```

### 长期修复（优先级 P1）

#### 1. 全局配置上限

```yaml
# omnistream-config.yaml
network:
  max_record_size: 100MB
  max_buffer_size: 200MB
  max_batch_size: 10000
```

#### 2. 统一的长度验证函数

```cpp
// core/utils/NetworkValidator.h
class NetworkValidator {
public:
    static const int MAX_RECORD_SIZE = 100 * 1024 * 1024;
    static const int MAX_BUFFER_SIZE = 200 * 1024 * 1024;
    
    static bool isValidRecordLength(int length) {
        return length >= 0 && length <= MAX_RECORD_SIZE;
    }
    
    static bool isValidBufferSize(int size) {
        return size >= 0 && size <= MAX_BUFFER_SIZE;
    }
};
```

---

## 九、验证方法

### 测试用例

```cpp
TEST(NetworkBufferSafety, MaxRecordSize) {
    // 构造恶意缓冲区（极大 recordLength）
    std::vector<uint8_t> maliciousBuffer;
    writeInt32(maliciousBuffer, INT_MAX);  // 2GB
    
    NonSpanningWrapper wrapper;
    wrapper.initializeFromMemoryBuffer(maliciousBuffer.data(), maliciousBuffer.size());
    
    EXPECT_THROW(wrapper.readInt(), std::logic_exception);  // 应拒绝
}

TEST(NetworkBufferSafety, NegativeRecordLength) {
    std::vector<uint8_t> maliciousBuffer;
    writeInt32(maliciousBuffer, 0x80000001);  // 会转为负数
    
    // 验证负数被检测
    EXPECT_THROW(readNonSpanningRecord(target), std::logic_exception);
}

TEST(NetworkBufferSafety, ValidRecordLength) {
    std::vector<uint8_t> validBuffer;
    writeInt32(validBuffer, 1024);  // 正常大小
    
    EXPECT_NO_THROW(readNonSpanningRecord(target));
}
```

---

## 十、总结

| 维度 | 评估 |
|------|------|
| **漏洞真实性** | ✅ 确认存在上限验证缺失 |
| **攻击可达性** | ⚠️ 中等（需要网络访问） |
| **攻击复杂度** | ⚠️ 中等（需要协议知识） |
| **影响严重性** | ✅ 极高（可导致进程崩溃） |
| **修复紧迫性** | ✅ **High**（应立即修复） |

**建议处理顺序**：
1. 立即添加 recordLength 上限验证（100MB）
2. 添加负数检测（防止整数溢出）
3. 完善网络协议安全配置（长期）