# VULN-CROSS-004：跨模块缓冲区溢出链漏洞

## 漏洞概述

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-CROSS-004 |
| **类型** | Cross-Module Buffer Overflow (CWE-125) |
| **严重性** | High (verified, 原始 Critical) |
| **置信度** | 80 |
| **源模块** | cross_module (runtime_io_network + streaming_runtime_io) |
| **发现者** | dataflow-scanner |

## 漏洞详细描述

这是一个**跨模块缓冲区越界读取链**，攻击者通过网络发送恶意构造的数据包，经过 runtime_io_network 模块反序列化后，传递到 streaming_runtime_io 模块，最终触发越界访问。虽然 SpillingAdaptiveSpanningRecordDeserializer 有部分边界检查，但 ObjectBuffer.GetSize() 返回值仍可被攻击者控制，导致越界读取。

### 跨模块链路

```
[模块1: runtime_io_network]
  Network buffer 接收
  ↓
  SpillingAdaptiveSpanningRecordDeserializer::SetNextBuffer()
  ↓
  NonSpanningWrapper::readInt() ← 部分边界检查
  ↓
  数据长度解析

       ↓ 网络数据传递

[模块2: streaming_runtime_io]
  OmniAbstractStreamTaskNetworkInput::emitNext()
  ↓
  OmniAbstractStreamTaskNetworkInput::processBufferOrEventOptForSQL()
  ↓
  buff->GetSize() ← 未验证的网络数据
  ↓
  objSegment->getObject(index) ← 越界访问
```

## 攻击向量分析

### 阶段 1: runtime_io_network 层反序列化

```cpp
// SpillingAdaptiveSpanningRecordDeserializer.cpp:109-123
void SpillingAdaptiveSpanningRecordDeserializer::SetNextBuffer(ReadOnlySlicedNetworkBuffer* buffer)
{
    currentBuffer = buffer;
    auto memorySegment = buffer->getMemorySegment();
    int offset = buffer->GetMemorySegmentOffset();
    int numBytes = buffer->GetSize();
    const uint8_t *data = memorySegment->getData();

    if (spanningWrapper->getNumGatheredBytes() > 0) {
        data = data + offset;
        spanningWrapper->addNextChunkFromMemoryBuffer(data, numBytes);
    } else {
        nonSpanningWrapper->InitializeFromMemoryBuffer(data, offset, numBytes + offset);
    }
}
```

### 阶段 2: NonSpanningWrapper 边界检查（部分保护）

```cpp
// NonSpanningWrapper.h:131-147
inline int NonSpanningWrapper::readInt()
{
    // 有边界检查：防止读取超出当前缓冲区
    if (unlikely(position_ + sizeof(uint32_t) > length_)) {
        THROW_LOGIC_EXCEPTION("EOFException");
    }
    
    uint32_t value = (static_cast<uint32_t>(data_[position_]) << 24) |
                     (static_cast<uint32_t>(data_[position_ + 1]) << 16) |
                     (static_cast<uint32_t>(data_[position_ + 2]) << 8) |
                     static_cast<uint32_t>(data_[position_ + 3]);
    
    position_ += sizeof(uint32_t);
    return static_cast<int>(value);
}

// NonSpanningWrapper.h:154-157
inline bool NonSpanningWrapper::canReadRecord(int recordLength) const
{
    return recordLength <= remaining();
}
```

**保护机制分析**：
- `readInt()` 有边界检查，防止读取超出当前缓冲区
- `canReadRecord()` 检查记录长度是否超出剩余数据
- **但这仅保护了缓冲区解析过程，不保护后续使用！**

### 阶段 3: streaming_runtime_io 层越界访问

```cpp
// OmniAbstractStreamTaskNetworkInput.h:167-188
DataInputStatus processBufferOrEventOptForSQL(...)
{
    if (bufferOrEvent->isBuffer()) {
        auto buff = reinterpret_cast<ObjectBuffer*>(bufferOrEvent->getBuffer());

        // 漏洞点：GetSize() 来自网络数据，无验证
        auto size = buff->GetSize();
        auto objSegment = buff->GetObjectSegment();
        auto offset = buff->GetOffset();

        // 循环使用未验证的 size/offset
        for (int64_t index = offset; index < offset + size; index++) {
            // 越界访问：getObject 无边界检查
            StreamElement *object = objSegment->getObject(index);
            ...
        }
    }
}
```

### 漏洞成因分析

```
验证缺口分析：

[runtime_io_network]
  readInt() 有边界检查 ✓
  canReadRecord() 有边界检查 ✓
  
  但解析后的值如何使用？没有限制！
  
  网络数据包：
    recordLen = readInt()  → 读取成功（值在缓冲区内）
    recordLen = 0xFFFFFFFF → 合法读取，但值超大！

[streaming_runtime_io]
  GetSize() 返回值来自网络数据
  未验证该值是否超出 ObjectSegment 容量 ✗
  
  直接使用：
    for (index = offset; index < offset + size; index++)
      getObject(index)  → 越界！
```

## 利用步骤 (PoC 思路)

### 步骤 1：构造恶意网络数据包

```
网络数据包结构：
+------------------+
| Header           |
|  bufferType: ... |
+------------------+
| Record Metadata  |
|  recordLen: 4 bytes  ← readInt() 解析
+------------------+
| ObjectBuffer     |
|  claimedSize: 0x10000  ← GetSize() 来源，超大值
|  claimedOffset: 0      ← GetOffset() 来源
+------------------+
| ObjectSegment    |
|  actualSize: 5         ← 实际只有5个元素
|  objects_[0-4]         ← 实际数据
+------------------+
```

### 步骤 2：攻击流程

```
1. runtime_io_network 接收数据包
   ↓
2. readInt() 解析 recordLen
   - 检查：position + 4 <= length_ ✓ 通过
   - 返回值：recordLen = 4 (合法)
   
3. 解析 ObjectBuffer metadata
   - claimedSize = 0x10000 (从网络数据读取)
   - 此时仅有缓冲区边界检查，无语义验证
   
4. 构建 ObjectSegment
   - actualSize = 5 (实际容量)
   
5. 传递到 streaming_runtime_io
   ↓
6. processBufferOrEventOptForSQL()
   - size = buff->GetSize() = 0x10000 (来自网络)
   - objSegment->getSize() = 5 (实际容量)
   
7. 循环执行
   for (index = 0; index < 0x10000; index++)
     getObject(index)
     
   index = 5 时 → 越界访问！
```

### 步骤 3：PoC 代码思路

```cpp
// 构造恶意网络数据包（概念性）
void constructMaliciousPacket(uint8_t* buffer) {
    // 写入 recordLen (合法，readInt 能读取)
    uint32_t recordLen = 4;
    memcpy(buffer + 0, &recordLen, 4);
    
    // 写入 claimedSize (超大值)
    uint32_t claimedSize = 0x10000;  // 远超实际容量
    memcpy(buffer + 4, &claimedSize, 4);
    
    // 写入 actualSize (小值)
    uint32_t actualSize = 5;
    memcpy(buffer + 8, &actualSize, 4);
    
    // 写入少量 object data
    // ...
}

// 发送到目标 TaskManager
sendNetworkPacket(target_taskmanager, malicious_packet);
```

## 影响范围评估

### 跨模块影响对比

| 阶段 | 模块 | 保护状态 | 风险 |
|------|------|----------|------|
| 网络接收 | runtime_io_network | 部分边界检查 | Low |
| 数据解析 | runtime_io_network | 缓冲区边界 ✓，语义验证 ✗ | Medium |
| 数据使用 | streaming_runtime_io | 无边界检查 | Critical |

### canReadRecord 检查的局限性

```cpp
// NonSpanningWrapper.h:61-66
if (nonSpanningWrapper->canReadRecord(recordLen)) {
    return nonSpanningWrapper->readInto(target);
} else {
    spanningWrapper->transferFrom(*nonSpanningWrapper, recordLen);
    return DeserializationResult_PARTIAL_RECORD;
}
```

**局限性分析**：
- `canReadRecord` 仅检查 `recordLen <= remaining()`
- 检查的是"能否读取"，不是"值是否合理"
- 大值（如 0xFFFFFFFF）只要 remaining 足够就能通过
- **语义验证缺失**：未检查 recordLen 是否超出目标对象容量

### CVSS 评分估算

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H
Base Score: 7.5 (High)

降级理由：
- 有部分边界检查（canReadRecord）
- 但检查不足以防止所有攻击场景
- 最终仍可触发越界访问
```

## 相关代码片段

### 关键验证缺口

```cpp
// === runtime_io_network 层 ===
// SpillingAdaptiveSpanningRecordDeserializer.cpp:57-66
int recordLen = nonSpanningWrapper->readInt();  // 有边界检查 ✓

if (nonSpanningWrapper->canReadRecord(recordLen)) {
    // 检查通过，但 recordLen 值未限制
    return nonSpanningWrapper->readInto(target);  
}

// === streaming_runtime_io 层 ===
// OmniAbstractStreamTaskNetworkInput.h:167-174
auto size = buff->GetSize();  // 来自网络，无验证 ✗
auto objSegment = buff->GetObjectSegment();

for (int64_t index = offset; index < offset + size; index++) {
    StreamElement *object = objSegment->getObject(index);  // 越界 ✗
}
```

## 修复建议

### runtime_io_network 层增强

```cpp
// NonSpanningWrapper.h 添加语义验证
inline bool canReadRecord(int recordLength) const
{
    // 原有检查
    if (recordLength > remaining()) {
        return false;
    }
    
    // 新增：语义验证
    if (recordLength < 0) {
        THROW_LOGIC_EXCEPTION("Negative record length");
    }
    if (recordLength > MAX_RECORD_SIZE) {
        THROW_LOGIC_EXCEPTION("Record size exceeds limit: " + std::to_string(recordLength));
    }
    
    return true;
}

// 添加常量定义
const int MAX_RECORD_SIZE = 1024 * 1024;  // 1MB
```

### streaming_runtime_io 层修复

参考 [VULN-STREAM-001.md](./VULN-STREAM-001.md) 的完整修复方案。

### 跨模块协调

```cpp
// 定义跨模块验证接口
class NetworkBufferValidator {
public:
    static bool validateObjectBufferMetadata(
        int claimedSize, int claimedOffset, int actualCapacity) 
    {
        if (claimedSize < 0 || claimedSize > actualCapacity) {
            return false;
        }
        if (claimedOffset < 0 || claimedOffset >= actualCapacity) {
            return false;
        }
        if (claimedOffset + claimedSize > actualCapacity) {
            return false;
        }
        return true;
    }
};

// 在网络数据反序列化后调用
void afterDeserializeObjectBuffer(ObjectBuffer* buffer) {
    int claimedSize = buffer->GetSize();
    int claimedOffset = buffer->GetOffset();
    int actualCapacity = buffer->GetObjectSegment()->getSize();
    
    if (!NetworkBufferValidator::validateObjectBufferMetadata(
            claimedSize, claimedOffset, actualCapacity)) {
        throw SecurityException("Invalid ObjectBuffer metadata from network");
    }
}
```

## 相关漏洞

- **VULN-STREAM-001** - 最终 sink 漏洞（越界访问）
- **SEC-008** - 最终 sink 的重复发现

## 参考资料

- [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- [CWE-119: Improper Restriction of Operations within Bounds of Buffer](https://cwe.mitre.org/data/definitions/119.html)
- [完整分析: VULN-STREAM-001.md](./VULN-STREAM-001.md)