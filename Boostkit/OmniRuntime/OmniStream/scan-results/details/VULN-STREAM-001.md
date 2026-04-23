# VULN-STREAM-001：网络数据未验证导致越界访问

## 漏洞概述

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-STREAM-001 |
| **类型** | Out-of-bounds Read (CWE-125) |
| **严重性** | Critical |
| **置信度** | 85 |
| **源模块** | streaming_runtime_io |
| **发现者** | dataflow-scanner |

## 漏洞详细描述

`OmniAbstractStreamTaskNetworkInput::processBufferOrEventOptForSQL()` 方法在处理网络数据时，直接使用 `ObjectBuffer::GetSize()` 和 `ObjectBuffer::GetOffset()` 返回的值进行循环迭代，访问 `ObjectSegment::getObject(index)`。这些值来自网络缓冲区数据，攻击者可以通过发送恶意构造的网络数据包控制 size 和 offset 值，导致：

1. **越界读取** - size 或 offset 超出 ObjectSegment 实际容量，访问未分配内存
2. **信息泄露** - 读取相邻内存区域，可能泄露敏感数据
3. **进程崩溃** - 访问无效内存地址导致 SIGSEGV
4. **潜在代码执行** - 配合其他漏洞可能实现任意代码执行

## 攻击向量分析

### 数据流路径

```
Remote TaskManager (外部网络)
  ↓ Network I/O Layer
  ↓ CheckpointedInputGate::pollNext()
  ↓ BufferOrEvent (包含 ObjectBuffer)
  ↓ OmniAbstractStreamTaskNetworkInput::emitNext()
  ↓ OmniAbstractStreamTaskNetworkInput::processBufferOrEventOptForSQL() ← 漏洞点
  ↓ buff->GetSize() / buff->GetOffset() ← 未验证的网络数据
  ↓ for (int64_t index = offset; index < offset + size; index++)
  ↓ objSegment->getObject(index) ← 越界访问
```

### 信任边界

- **Network Interface** → Remote TaskManagers / JobManager → TaskExecutor（Critical 风险）
- 数据来源为 **untrusted_network**，攻击者可控制网络数据包内容

### ObjectSegment 结构分析

```cpp
// ObjectSegment.h:23-58
class ObjectSegment : public Segment {
public:
    explicit ObjectSegment(size_t size): Segment(SegmentType::OBJECT_SEGMENT), size(size)
    {
        objects_ = new StreamElement* [size];  // 固定大小分配
    }

    StreamElement* getObject(int offset)
    {
        return objects_[offset];  // ❌ 无边界检查！直接访问数组
    }

    size_t getSize()
    {
        return size;  // ObjectSegment 实际容量
    }
private:
    size_t size;
    StreamElement** objects_;  // 固定大小数组
};
```

**关键发现**：`ObjectSegment::getObject()` 直接访问 `objects_[offset]`，无任何边界检查！

## 利用步骤 (PoC 思路)

### 步骤 1：理解数据包结构

网络数据包包含：
- ObjectBuffer metadata（包含 size, offset）
- ObjectSegment 数据（包含 StreamElement 指针数组）

### 步骤 2：构造恶意数据包

攻击者需控制发送到目标 TaskManager 的网络数据：

```
网络数据包结构：
+----------------+
| ObjectBuffer   |
|  - size: 0x7FFFFFFF  ← 超大值，超出实际容量
|  - offset: 0         ← 或构造 offset + size 越界
+----------------+
| ObjectSegment  |
|  - 实际 size: 10     ← 远小于 ObjectBuffer.size
|  - objects_[0-9]     ← 仅10个有效指针
+----------------+
```

### 步骤 3：触发越界访问

```cpp
// OmniAbstractStreamTaskNetworkInput.h:167-188
auto size = buff->GetSize();      // 返回恶意值 0x7FFFFFFF
auto objSegment = buff->GetObjectSegment();
auto offset = buff->GetOffset();  // 返回 0

// 循环从 offset(0) 到 offset+size(0x7FFFFFFF)
for (int64_t index = offset; index < offset + size; index++) {
    // 越界访问：index > objSegment->getSize() (10)
    StreamElement *object = objSegment->getObject(index);  // SIGSEGV
    ...
}
```

### PoC 代码思路

```cpp
// 攻击者构造的网络数据包（概念性）
struct MaliciousNetworkPacket {
    uint32_t buffer_type;      // ObjectBuffer type
    uint32_t claimed_size;     // 0x10000 (远大于实际)
    uint32_t offset;           // 0
    uint8_t object_segment_data[100]; // 实际只有少量数据
};

// 发送到目标 TaskManager
send_to_taskmanager(malicious_packet);
// 目标解析后：
// - buff->GetSize() = 0x10000 (攻击者控制)
// - objSegment->getSize() = 5 (实际容量)
// - 循环尝试访问 index 0-0x10000
// - index >= 5 时发生越界读取
```

## 影响范围评估

### 直接影响

| 影响对象 | 影响程度 |
|----------|----------|
| TaskManager 进程 | SIGSEGV 崩溃 |
| 内存安全 | 越界读取，信息泄露风险 |
| 正在处理的数据流 | 数据丢失，状态损坏 |
| 整个 Flink 集群 | 任务失败，需要重启恢复 |

### 越界访问后果

```
index 范围:
  0 - objSegment->getSize()-1  → 正常访问
  objSegment->getSize() - ...  → 越界访问

越界访问可能读取到：
  - 相邻内存区域的其他数据
  - 堆管理 metadata
  - 其他对象的数据
  - 无效指针 → 崩溃
```

### CVSS 评分估算

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H
Base Score: 7.5 (High)

解释：
- AV:N - 网络可达
- AC:L - 无需特殊条件，直接构造数据包
- PR:N - 无需认证（TaskManager 网络接口）
- C:L - 可能泄露内存数据（信息泄露）
- A:H - 进程崩溃，服务完全不可用
```

## 相关代码片段

### 漏洞代码 (OmniAbstractStreamTaskNetworkInput.h:167-188)

```cpp
DataInputStatus processBufferOrEventOptForSQL(OmniPushingAsyncDataInput::OmniDataOutput* output,
                                              BufferOrEvent* bufferOrEvent)
{
    ...
    if (bufferOrEvent->isBuffer()) {
        auto buff = reinterpret_cast<ObjectBuffer*>(bufferOrEvent->getBuffer());

        // 漏洞点 1：GetSize() 来自网络数据，未验证
        auto size = buff->GetSize();
        auto objSegment = buff->GetObjectSegment();
        
        // 漏洞点 2：GetOffset() 来自网络数据，未验证
        auto offset = buff->GetOffset();
        
        // 漏洞点 3：未验证 size + offset 是否超出 objSegment 容量
        for (int64_t index = offset; index < offset + size; index++) {
            // 漏洞点 4：getObject() 无边界检查，直接访问数组
            StreamElement *object = objSegment->getObject(index);
            
            if (object->getTag() == StreamElementTag::TAG_REC_WITH_TIMESTAMP ||
                object->getTag() == StreamElementTag::TAG_REC_WITHOUT_TIMESTAMP) {
                auto record = static_cast<StreamRecord *>(object);
                auto vectorBatch = static_cast<VectorBatch *>(record->getValue());
                output->emitRecord(record);
            }
        }
        buff->RecycleBuffer();
        return DataInputStatus::MORE_AVAILABLE;
    }
    ...
}
```

### ObjectBuffer 接口

```cpp
// ObjectBuffer.h:33-57
class ObjectBuffer : public Buffer {
public:
    // 这些方法的返回值来自网络数据，需验证
    virtual ObjectSegment *GetObjectSegment() = 0;
    
    int GetOffset() const override
    {
        return 0;  // 默认返回，但具体实现可能来自网络
    };
    
    // GetSize() 继承自 Buffer，具体实现来自网络数据
};
```

### Buffer 基类 (GetSize 来源)

```cpp
// Buffer.h (推测)
class Buffer {
public:
    virtual int GetSize() const = 0;  // 由网络数据反序列化填充
};
```

## 修复建议

### 立即修复

```cpp
DataInputStatus processBufferOrEventOptForSQL(OmniPushingAsyncDataInput::OmniDataOutput* output,
                                              BufferOrEvent* bufferOrEvent)
{
    ...
    if (bufferOrEvent->isBuffer()) {
        auto buff = reinterpret_cast<ObjectBuffer*>(bufferOrEvent->getBuffer());

        auto claimed_size = buff->GetSize();
        auto objSegment = buff->GetObjectSegment();
        auto claimed_offset = buff->GetOffset();
        
        // 修复 1：获取 ObjectSegment 实际容量
        size_t actual_capacity = objSegment->getSize();
        
        // 修复 2：验证 offset 有效性
        if (claimed_offset < 0 || claimed_offset >= actual_capacity) {
            LOG_ERROR("Invalid offset: " << claimed_offset << " >= capacity: " << actual_capacity);
            buff->RecycleBuffer();
            return DataInputStatus::MORE_AVAILABLE;
        }
        
        // 修复 3：验证 size 有效性
        if (claimed_size < 0 || claimed_size > actual_capacity) {
            LOG_ERROR("Invalid size: " << claimed_size << " > capacity: " << actual_capacity);
            buff->RecycleBuffer();
            return DataInputStatus::MORE_AVAILABLE;
        }
        
        // 修复 4：验证 offset + size 不超出容量
        if (claimed_offset + claimed_size > actual_capacity) {
            LOG_ERROR("offset + size overflow: " << claimed_offset + claimed_size 
                      << " > capacity: " << actual_capacity);
            buff->RecycleBuffer();
            return DataInputStatus::MORE_AVAILABLE;
        }
        
        // 使用验证后的值
        size_t size = static_cast<size_t>(claimed_size);
        size_t offset = static_cast<size_t>(claimed_offset);
        
        for (size_t index = offset; index < offset + size; index++) {
            // 添加额外检查
            if (index < actual_capacity) {
                StreamElement *object = objSegment->getObject(static_cast<int>(index));
                // ... 处理 object
            }
        }
        
        buff->RecycleBuffer();
        return DataInputStatus::MORE_AVAILABLE;
    }
    ...
}
```

### ObjectSegment 修复

```cpp
// ObjectSegment.h 修复
StreamElement* getObject(int offset)
{
    // 添加边界检查
    if (offset < 0 || offset >= static_cast<int>(size)) {
        LOG_ERROR("ObjectSegment OOB access: offset=" << offset << " size=" << size);
        return nullptr;  // 或抛出异常
    }
    return objects_[offset];
}
```

### 长期改进

1. **网络协议层验证** - 在网络数据反序列化时添加元数据验证
2. **类型安全** - 使用 size_t 代替 int64_t，避免负数问题
3. **断言检查** - 添加 debug 模式的边界断言
4. **防御性编程** - 在所有数组访问前添加边界检查

## 相关漏洞

- **SEC-008** - 同一漏洞的重复发现
- **VULN-CROSS-004** - 跨模块缓冲区溢出链，包含本漏洞作为最终 sink

## 参考资料

- [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- [CWE-119: Improper Restriction of Operations within Bounds of Buffer](https://cwe.mitre.org/data/definitions/119.html)
- [Secure Coding in C++: Bounds Checking](https://isocpp.org/wiki/faq/operators#array-size-checking)