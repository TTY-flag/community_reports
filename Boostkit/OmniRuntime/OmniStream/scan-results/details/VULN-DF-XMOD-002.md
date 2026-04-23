# VULN-DF-XMOD-002：Kafka到JSON反序列化跨模块数据流漏洞

## 1. 漏洞概述

| 属性 | 详情 |
|------|------|
| **漏洞ID** | VULN-DF-XMOD-002 |
| **漏洞类型** | 跨模块数据流 - Kafka消息反序列化漏洞 |
| **CWE分类** | CWE-502: Deserialization of Untrusted Data |
| **严重程度** | **Critical** |
| **影响版本** | 当前版本及所有使用该数据流的版本 |
| **发现日期** | 2025-04-19 |

### 漏洞描述

该漏洞存在于OmniStream的Kafka连接器中，未经信任的网络数据从Kafka Broker流入系统后，经过多模块传递最终被反序列化，整个过程缺乏有效的输入验证和安全检查。

攻击者可以通过控制Kafka消息内容，触发以下安全问题：
- JSON解析器拒绝服务（DoS）
- 内存耗尽攻击
- 异常抛出导致服务崩溃

---

## 2. 攻击场景分析

### 2.1 攻击向量

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           攻击向量示意图                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   攻击者 ──► 恶意Kafka消息 ──► Kafka Broker ──► OmniStream Consumer    │
│                                                                         │
│   恶意Payload示例:                                                       │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ {"field": "AAAA...[超长字符串]...AAAA"}                          │   │
│   │ 或                                                              │   │
│   │ {"a": {"b": {"c": {...深度嵌套...}}}}                            │   │
│   │ 或                                                              │   │
│   │ [畸形JSON数据触发解析异常]                                        │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 攻击触发条件

1. **前置条件**:
   - 攻击者能够向Kafka Topic发送消息
   - OmniStream应用配置了Kafka数据源
   - 使用JSON反序列化模式处理消息

2. **触发路径**:
   - 攻击者发送恶意构造的JSON消息到Kafka
   - OmniStream Kafka消费者获取消息
   - 消息经过多层传递到达JSON解析器
   - 解析器处理恶意数据触发漏洞

### 2.3 具体攻击场景

#### 场景一：拒绝服务攻击（DoS）
攻击者发送深度嵌套的JSON数据或超长字符串，导致：
- 栈溢出（深度嵌套JSON解析）
- 内存耗尽（超大JSON对象）
- CPU资源耗尽（复杂JSON结构解析）

#### 场景二：异常终止攻击
发送畸形JSON数据触发异常：
- 非UTF-8编码数据
- 不完整的JSON结构
- 非法Unicode字符

---

## 3. 利用条件与前置要求

### 3.1 利用前提条件

| 条件 | 描述 | 难度 |
|------|------|------|
| Kafka访问权限 | 攻击者需要能够向目标Topic发送消息 | 中等 |
| 网络可达性 | 攻击者网络可达Kafka Broker | 低 |
| 消息格式知识 | 了解目标应用期望的JSON消息格式 | 中等 |

### 3.2 攻击复杂度分析

- **攻击复杂度**: 低
- **所需权限**: Kafka消息发送权限
- **用户交互**: 无需
- **攻击向量**: 网络（Adjacent）

### 3.3 利用难度评估

| 因素 | 评分 | 说明 |
|------|------|------|
| 可访问性 | 3/5 | 需要Kafka集群的写入权限 |
| 复杂度 | 1/5 | 构造恶意JSON非常简单 |
| 影响 | 5/5 | 可导致服务完全不可用 |
| 检测难度 | 4/5 | 正常Kafka消息难以区分恶意消息 |

---

## 4. 潜在影响范围

### 4.1 技术影响

| 影响类型 | 严重程度 | 描述 |
|----------|----------|------|
| 拒绝服务 | 高 | 服务崩溃或资源耗尽 |
| 数据完整性 | 中 | 解析错误可能导致数据丢失 |
| 系统稳定性 | 高 | 频繁崩溃影响系统可用性 |
| 资源消耗 | 高 | 内存和CPU资源被恶意消耗 |

### 4.2 业务影响

- **服务中断**: 流处理任务中断，影响实时数据处理
- **数据丢失**: 未处理的消息可能丢失
- **级联故障**: 下游系统可能因输入中断而故障
- **运维成本**: 频繁重启增加运维负担

### 4.3 影响范围

受影响的组件：
- 所有使用KafkaSourceReader的应用
- 配置了JSON反序列化Schema的数据流
- 依赖该数据处理管道的下游系统

---

## 5. 代码证据

### 5.1 完整数据流路径验证

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          数据流路径图                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  SOURCE: Kafka Broker (网络数据源)                                           │
│     │                                                                        │
│     ▼                                                                        │
│  [1] RdKafkaConsumer.cpp:55-62                                               │
│      └── poll() 方法从Kafka消费消息                                          │
│          consumer_->consumeBatch(timeoutMs, batch_size_)                     │
│     │                                                                        │
│     ▼                                                                        │
│  [2] KafkaPartitionSplitReader.cpp:37-72                                     │
│      └── fetch() 方法调用 poll()                                             │
│          consumerRecords = consumer->poll(POLL_TIMEOUT);                     │
│     │                                                                        │
│     ▼                                                                        │
│  [3] KafkaSourceReader.h:27-44                                               │
│      └── 继承 SingleThreadMultiplexSourceReaderBase                          │
│          管理消息流的读取和分发                                                │
│     │                                                                        │
│     ▼                                                                        │
│  [4] KafkaRecordEmitter.cpp:27-52                                            │
│      └── emitRecord()/emitBatchRecord() 触发反序列化                          │
│          deserializationSchema->deserialize(consumerRecord, ...)            │
│     │                                                                        │
│     ▼                                                                        │
│  [5] KafkaValueOnlyDeserializationSchemaWrapper.h:34-49                      │
│      └── 从Kafka消息提取payload                                              │
│          deserializationSchema->deserialize(                                 │
│              static_cast<const uint8_t*>(record->payload()),                 │
│              record->len(), out)                                             │
│     │                                                                        │
│     ▼                                                                        │
│  [6] JsonRowDataDeserializationSchema.h:33-47  [SINK]                        │
│      └── 解析JSON数据（无验证）                                               │
│          node = nlohmann::json::parse(...)                                   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 关键代码片段

#### 5.2.1 SOURCE: 网络数据入口

**文件**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniStream/cpp/connector/kafka/source/reader/RdKafkaConsumer.cpp`

```cpp
// 第55-62行: poll方法 - 从Kafka Broker获取网络消息
ConsumerRecords* RdKafkaConsumer::poll(int timeoutMs)
{
    // 直接从网络获取消息，无任何验证
    std::unordered_map<RdKafka::TopicPartition *, std::vector<RdKafka::Message *>> records =
        consumer_->consumeBatch(timeoutMs, batch_size_);  // 网络数据源

    ConsumerRecords* consumerRecords = new ConsumerRecords(std::move(records));

    return consumerRecords;
}
```

**安全缺陷**: 
- 消息直接从网络获取
- 无任何验证或过滤
- 消息内容完全由外部控制

#### 5.2.2 数据传递链

**文件**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniStream/cpp/connector/kafka/source/reader/KafkaPartitionSplitReader.cpp`

```cpp
// 第37-47行: fetch方法
RecordsWithSplitIds<RdKafka::Message>* KafkaPartitionSplitReader::fetch()
{
    ConsumerRecords* consumerRecords;
    try {
        consumerRecords = consumer->poll(POLL_TIMEOUT);  // 获取未验证的消息
    } catch (const std::exception& e) {
        consumerRecords = ConsumerRecords::EMPTY;
        // ...
    }
    auto recordsBySplits = new KafkaPartitionSplitRecords(consumerRecords);
    // ...消息被直接传递，无验证...
    return recordsBySplits;
}
```

**文件**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniStream/cpp/connector/kafka/source/reader/KafkaRecordEmitter.cpp`

```cpp
// 第27-38行: emitRecord方法
void KafkaRecordEmitter::emitRecord(RdKafka::Message* consumerRecord, SourceOutput* output,
    KafkaPartitionSplitState* splitState)
{
    try {
        sourceOutputWrapper->setSourceOutput(output);
        sourceOutputWrapper->setTimestamp(consumerRecord->timestamp().timestamp);
        // 直接调用反序列化，无验证
        deserializationSchema->deserialize(consumerRecord, sourceOutputWrapper);
        splitState->setCurrentOffset(consumerRecord->offset() + 1);
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to deserialize consumer record due to: " + std::string(e.what()));
    }
}

// 第40-52行: emitBatchRecord方法
void KafkaRecordEmitter::emitBatchRecord(
    const std::vector<RdKafka::Message*>& messageVec, SourceOutput* output,
    KafkaPartitionSplitState* splitState)
{
    try {
        sourceOutputWrapper->setSourceOutput(output);
        sourceOutputWrapper->setTimestamp(messageVec.back()->timestamp().timestamp);
        // 批量反序列化，无验证
        deserializationSchema->deserialize(messageVec, sourceOutputWrapper);
        splitState->setCurrentOffset(messageVec.back()->offset() + 1);
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to deserialize consumer record due to: " + std::string(e.what()));
    }
}
```

#### 5.2.3 中间层：消息payload提取

**文件**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniStream/cpp/connector/kafka/source/reader/deserializer/KafkaValueOnlyDeserializationSchemaWrapper.h`

```cpp
// 第34-49行: 从Kafka消息中提取原始数据
void deserialize(RdKafka::Message* record, Collector* out) override
{
    // 直接提取payload，无验证
    deserializationSchema->deserialize(
        static_cast<const uint8_t*>(record->payload()),  // 原始网络数据
        record->len(), 
        out
    );
}

void deserialize(std::vector<RdKafka::Message*> recordVec, Collector* out) override
{
    int size = static_cast<int>(recordVec.size());
    prepareForVecData(size);
    for (auto record : recordVec) {
        // 批量提取payload
        valueVec.push_back(static_cast<const uint8_t*>(record->payload()));
        lengthVec.push_back(record->len());
        timeVec.push_back(record->timestamp().timestamp);
    }
    deserializationSchema->deserialize(valueVec, lengthVec, timeVec, out);
}
```

#### 5.2.4 SINK: 不安全的JSON解析

**文件**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniStream/cpp/core/api/common/serialization/JsonRowDataDeserializationSchema.h`

```cpp
// 第33-47行: 核心反序列化方法 - 直接解析未经验证的数据
void* deserialize(std::vector<const uint8_t*>& messageVec, std::vector<size_t>& lengthVec) override
{
    int rowSize = static_cast<int>(messageVec.size());
    int colSize = static_cast<int>(fieldNames.size());
    auto *vectorBatch = createBatch(rowSize, fieldTypes);
    nlohmann::json node;
    
    for (int rowIndex = 0; rowIndex < rowSize; rowIndex++) {
        // 【漏洞点】直接解析来自Kafka的未验证数据
        node = nlohmann::json::parse(std::string_view(
            reinterpret_cast<const char *>(messageVec[rowIndex]), 
            lengthVec[rowIndex]  // 攻击者控制的数据长度
        ));
        
        for (int colIndex = 0; colIndex < colSize; colIndex++) {
            setColValue(rowIndex, colIndex, vectorBatch, node);
        }
    }
    return vectorBatch;
}
```

**安全缺陷**:
1. **无输入验证**: 直接使用`nlohmann::json::parse()`解析外部数据
2. **无大小限制**: 未限制消息大小
3. **无深度限制**: 未限制JSON嵌套深度
4. **无异常安全**: 异常处理不完整，可能导致资源泄漏

### 5.3 数据流完整调用链

```
RdKafkaConsumer::poll()                           [网络数据入口]
    │
    ├── consumer_->consumeBatch()                 [librdkafka获取Kafka消息]
    │
    └── ConsumerRecords 消息集合
            │
            ▼
KafkaPartitionSplitReader::fetch()                [消息分发]
    │
    ├── consumer->poll()                          [调用poll获取消息]
    │
    └── KafkaPartitionSplitRecords
            │
            ▼
KafkaSourceReader                                 [源读取器]
    │
    │  (继承 SingleThreadMultiplexSourceReaderBase)
    │
    └── 消息传递
            │
            ▼
KafkaRecordEmitter::emitRecord/emitBatchRecord    [消息发射器]
    │
    ├── deserializationSchema->deserialize()      [触发反序列化]
    │
    └── 消息转发
            │
            ▼
KafkaValueOnlyDeserializationSchemaWrapper        [消息包装器]
    │
    ├── record->payload()                         [提取原始payload]
    │
    └── deserializationSchema->deserialize()
            │
            ▼
JsonRowDataDeserializationSchema::deserialize()  [【SINK】JSON解析]
    │
    └── nlohmann::json::parse()                   [危险操作]
```

### 5.4 攻击验证PoC概念

```cpp
// 概念性攻击Payload构造
// 注意：这是概念性代码，仅用于安全研究和修复验证

// 场景1: 深度嵌套JSON导致栈溢出
std::string constructDeeplyNestedJson(int depth) {
    std::string result;
    for (int i = 0; i < depth; i++) {
        result += "{\"a\":";
    }
    result += "1";
    for (int i = 0; i < depth; i++) {
        result += "}";
    }
    return result;
}

// 场景2: 超大JSON对象导致内存耗尽
std::string constructLargeJson(size_t sizeMB) {
    std::string result = "{\"field\":\"";
    result += std::string(sizeMB * 1024 * 1024, 'A');  // 填充大量数据
    result += "\"}";
    return result;
}

// 场景3: 畸形UTF-8字符触发解析异常
std::string constructMalformedJson() {
    return "{\"field\":\"\xFF\xFE\xFD\"}";  // 非法UTF-8字节序列
}

// 攻击流程:
// 1. 攻击者将构造的恶意消息发送到Kafka Topic
// 2. OmniStream Kafka消费者获取该消息
// 3. 消息经过数据流路径传递
// 4. 最终到达JsonRowDataDeserializationSchema::deserialize()
// 5. nlohmann::json::parse() 解析恶意数据
// 6. 触发拒绝服务或异常
```

---

## 6. 修复建议

### 6.1 紧急修复方案

#### 修复方案1: 输入验证层

**文件**: `JsonRowDataDeserializationSchema.h`

```cpp
void* deserialize(std::vector<const uint8_t*>& messageVec, std::vector<size_t>& lengthVec) override
{
    // 【新增】配置参数
    const size_t MAX_MESSAGE_SIZE = 10 * 1024 * 1024;  // 10MB限制
    const int MAX_JSON_DEPTH = 100;                      // 最大嵌套深度
    
    int rowSize = static_cast<int>(messageVec.size());
    int colSize = static_cast<int>(fieldNames.size());
    auto *vectorBatch = createBatch(rowSize, fieldTypes);
    nlohmann::json node;
    
    for (int rowIndex = 0; rowIndex < rowSize; rowIndex++) {
        // 【新增】大小验证
        if (lengthVec[rowIndex] > MAX_MESSAGE_SIZE) {
            std::cerr << "Message size exceeds limit: " << lengthVec[rowIndex] 
                      << " > " << MAX_MESSAGE_SIZE << std::endl;
            continue;  // 跳过过大的消息
        }
        
        // 【新增】空数据检查
        if (messageVec[rowIndex] == nullptr || lengthVec[rowIndex] == 0) {
            std::cerr << "Empty message at row " << rowIndex << std::endl;
            continue;
        }
        
        try {
            // 【修改】使用带异常处理的解析
            node = nlohmann::json::parse(
                std::string_view(
                    reinterpret_cast<const char *>(messageVec[rowIndex]), 
                    lengthVec[rowIndex]
                )
            );
            
            // 【新增】深度验证
            if (getJsonDepth(node) > MAX_JSON_DEPTH) {
                std::cerr << "JSON depth exceeds limit at row " << rowIndex << std::endl;
                continue;
            }
            
            for (int colIndex = 0; colIndex < colSize; colIndex++) {
                setColValue(rowIndex, colIndex, vectorBatch, node);
            }
        } catch (const nlohmann::json::parse_error& e) {
            // 【新增】完善的异常处理
            std::cerr << "JSON parse error at row " << rowIndex << ": " << e.what() << std::endl;
            continue;
        } catch (const std::exception& e) {
            std::cerr << "Unexpected error at row " << rowIndex << ": " << e.what() << std::endl;
            continue;
        }
    }
    return vectorBatch;
}

private:
// 【新增】辅助函数：计算JSON深度
int getJsonDepth(const nlohmann::json& j, int currentDepth = 0) {
    if (currentDepth > 1000) return currentDepth;  // 防止无限递归
    
    if (!j.is_object() && !j.is_array()) {
        return currentDepth;
    }
    
    int maxDepth = currentDepth + 1;
    for (auto it = j.begin(); it != j.end(); ++it) {
        int depth = getJsonDepth(it.value(), currentDepth + 1);
        maxDepth = std::max(maxDepth, depth);
    }
    return maxDepth;
}
```

#### 修复方案2: 在消息入口处验证

**文件**: `KafkaValueOnlyDeserializationSchemaWrapper.h`

```cpp
// 添加配置参数
class KafkaValueOnlyDeserializationSchemaWrapper : public KafkaRecordDeserializationSchema {
public:
    // 【新增】构造函数接受配置参数
    explicit KafkaValueOnlyDeserializationSchemaWrapper(
        DeserializationSchema* deserializationSchema,
        size_t maxMessageSize = 10 * 1024 * 1024  // 默认10MB
    ) : deserializationSchema(deserializationSchema), maxMessageSize_(maxMessageSize)
    {
    }

    void deserialize(RdKafka::Message* record, Collector* out) override
    {
        // 【新增】大小验证
        if (record->len() > maxMessageSize_) {
            std::cerr << "Kafka message exceeds size limit: " << record->len() 
                      << " > " << maxMessageSize_ << std::endl;
            return;  // 拒绝处理过大的消息
        }
        
        // 【新增】空消息检查
        if (record->payload() == nullptr || record->len() == 0) {
            std::cerr << "Empty Kafka message received" << std::endl;
            return;
        }
        
        deserializationSchema->deserialize(
            static_cast<const uint8_t*>(record->payload()), 
            record->len(), 
            out
        );
    }

private:
    DeserializationSchema* deserializationSchema;
    size_t maxMessageSize_;
    std::vector<const uint8_t*> valueVec;
    std::vector<size_t> lengthVec;
    std::vector<int64_t> timeVec;
};
```

### 6.2 长期改进建议

#### 1. 实现Schema验证

```cpp
// 建议添加JSON Schema验证层
class JsonSchemaValidator {
public:
    bool validate(const nlohmann::json& data, const nlohmann::json& schema) {
        // 实现基于JSON Schema的验证
        // 验证字段类型、必需字段、范围限制等
        return true;
    }
};
```

#### 2. 添加速率限制和熔断机制

```cpp
// 建议在Kafka消费者层添加熔断机制
class CircuitBreaker {
    int failureCount = 0;
    int threshold = 10;
    bool isOpen = false;
    
public:
    bool allowRequest() {
        if (isOpen) return false;
        return true;
    }
    
    void recordFailure() {
        if (++failureCount >= threshold) {
            isOpen = true;
        }
    }
    
    void reset() {
        failureCount = 0;
        isOpen = false;
    }
};
```

#### 3. 监控和告警

- 添加消息大小监控
- 记录解析失败率
- 设置异常阈值告警

### 6.3 配置建议

在配置文件中添加安全参数：

```yaml
kafka:
  consumer:
    max-message-size: 10485760  # 10MB
    max-json-depth: 100
    validation:
      enabled: true
      strict-mode: true
    circuit-breaker:
      enabled: true
      failure-threshold: 10
      reset-timeout-seconds: 60
```

---

## 7. 总结

### 风险评级: Critical

该漏洞允许攻击者通过Kafka消息投毒，利用未经验证的JSON解析实现拒绝服务攻击。完整的攻击链已验证存在：

1. **SOURCE确认**: RdKafkaConsumer.cpp:55-62 从Kafka Broker获取未验证的网络数据
2. **数据流验证**: 完整的6层调用链从网络入口到JSON解析点
3. **SINK确认**: JsonRowDataDeserializationSchema.h:40-41 使用nlohmann::json::parse()无验证解析

### 修复优先级: 高

建议立即实施以下措施：
1. 添加消息大小限制
2. 实现JSON深度验证
3. 完善异常处理
4. 部署监控告警

---

*报告生成时间: 2025-04-19*
*分析工具: OpenCode Vulnerability Scanner*
