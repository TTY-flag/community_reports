# VULN-SERIAL-001：JSON反序列化缺少异常处理

## 漏洞概述

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-SERIAL-001 |
| **类型** | Deserialization of Untrusted Data (CWE-502) |
| **严重性** | Critical |
| **置信度** | 85 |
| **源模块** | core_serialization |
| **发现者** | dataflow-scanner |

## 漏洞详细描述

`JsonRowDataDeserializationSchema::deserialize()` 方法在解析 Kafka 消息 JSON 数据时，直接调用 `nlohmann::json::parse()` 而未进行任何异常处理。当外部攻击者通过 Kafka 发送恶意构造的 JSON 数据（如畸形 JSON、超长字符串、深度嵌套结构）时，会导致：

1. **解析异常崩溃** - 畸形 JSON 触发 `parse_error` 异常，未捕获导致程序崩溃
2. **拒绝服务 (DoS)** - 超长字符串或深度嵌套导致内存耗尽或无限循环解析
3. **潜在内存损坏** - nlohmann::json 库在解析失败时可能产生未定义行为

## 攻击向量分析

### 数据流路径

```
Kafka Broker (外部网络)
  ↓ RdKafkaConsumer::poll()
  ↓ ConsumerRecords::addRecord()
  ↓ KafkaRecordEmitter::emitRecord()
  ↓ KafkaRecordDeserializationSchema::deserialize()
  ↓ JsonRowDataDeserializationSchema::deserialize() ← 漏洞点
  ↓ nlohmann::json::parse()
```

### 信任边界

- **Network Interface** → Kafka Broker → KafkaSource Reader（Critical 风险）
- 数据来源为 **untrusted_network**，攻击者完全可控 Kafka 消息内容

### 攻击条件

1. 攻击者需能访问 Kafka 集群或控制消息生产者
2. 构造恶意 JSON payload 发送到被消费的 topic
3. OmniStream 任务正在消费该 topic

## 利用步骤 (PoC 思路)

### 步骤 1：准备恶意 JSON payload

```json
// 畸形 JSON - 导致 parse_error 异常
{"data": "value", "nested": {}}}}}

// 超长字符串 - 导致内存耗尽
{"field": "AAAAAAAAAAAAAAAA..." * 100000000}

// 深度嵌套 - 导致栈溢出或解析缓慢
{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":...}}}}}}}}}}
```

### 步骤 2：发送到 Kafka Topic

```bash
# 使用 kafka-console-producer 或自定义生产者
kafka-console-producer --broker-list <target:9092> --topic <victim-topic>
# 输入恶意 JSON payload
```

### 步骤 3：触发漏洞

当 OmniStream 任务消费该消息时：
- 畸形 JSON → `nlohmann::json::parse()` 抛出 `parse_error` 异常
- 异常未被捕获 → TaskManager 进程崩溃
- 整个 Flink 任务失败

## 影响范围评估

### 直接影响

| 影响对象 | 影响程度 |
|----------|----------|
| TaskManager 进程 | 进程崩溃，任务中断 |
| Flink Job | 任务失败，需要重启 |
| 正在处理的数据 | 数据丢失，状态不一致 |
| 其他并发任务 | 共享 TaskManager 的其他任务受影响 |

### 间接影响

- **服务可用性** - DoS 攻击可导致服务完全不可用
- **数据完整性** - 任务中断可能导致部分数据未处理
- **系统稳定性** - 频繁崩溃导致资源泄漏和性能下降

### CVSS 评分估算

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H
Base Score: 7.5 (High)
```

## 相关代码片段

### 漏洞代码 (JsonRowDataDeserializationSchema.h:40-44)

```cpp
void* deserialize(std::vector<const uint8_t*>& messageVec, std::vector<size_t>& lengthVec) override
{
    int rowSize = static_cast<int>(messageVec.size());
    int colSize = static_cast<int>(fieldNames.size());
    auto *vectorBatch = createBatch(rowSize, fieldTypes);
    nlohmann::json node;
    for (int rowIndex = 0; rowIndex < rowSize; rowIndex++) {
        // 漏洞点：无异常处理的 JSON 解析
        node = nlohmann::json::parse(std::string_view(
            reinterpret_cast<const char *>(messageVec[rowIndex]), lengthVec[rowIndex]));
        for (int colIndex = 0; colIndex < colSize; colIndex++) {
            setColValue(rowIndex, colIndex, vectorBatch, node);
        }
    }
    return vectorBatch;
}
```

### 缺失的安全检查

1. **无异常捕获** - 没有 try-catch 包裹 parse() 调用
2. **无输入验证** - 未检查 JSON 格式合法性
3. **无大小限制** - 未限制 JSON 字符串长度
4. **无深度限制** - 未限制 JSON 嵌套深度

## 修复建议

### 立即修复

```cpp
void* deserialize(std::vector<const uint8_t*>& messageVec, std::vector<size_t>& lengthVec) override
{
    int rowSize = static_cast<int>(messageVec.size());
    int colSize = static_cast<int>(fieldNames.size());
    auto *vectorBatch = createBatch(rowSize, fieldTypes);
    nlohmann::json node;
    
    for (int rowIndex = 0; rowIndex < rowSize; rowIndex++) {
        // 修复 1：添加异常处理
        try {
            // 修复 2：添加大小限制
            const size_t MAX_JSON_SIZE = 1024 * 1024; // 1MB
            if (lengthVec[rowIndex] > MAX_JSON_SIZE) {
                LOG_ERROR("JSON message too large: " << lengthVec[rowIndex]);
                continue; // 或抛出特定异常
            }
            
            // 修复 3：安全解析选项
            node = nlohmann::json::parse(
                std::string_view(
                    reinterpret_cast<const char *>(messageVec[rowIndex]), 
                    lengthVec[rowIndex]),
                nullptr, // callback
                false,   // allow exceptions = false
                true     // ignore comments
            );
            
            if (node.is_discarded()) {
                LOG_ERROR("Invalid JSON at row " << rowIndex);
                continue;
            }
            
            for (int colIndex = 0; colIndex < colSize; colIndex++) {
                setColValue(rowIndex, colIndex, vectorBatch, node);
            }
        } catch (const nlohmann::json::parse_error& e) {
            LOG_ERROR("JSON parse error at row " << rowIndex << ": " << e.what());
            // 根据策略：跳过错误行 或 记录到错误队列
        } catch (const std::exception& e) {
            LOG_ERROR("Unexpected error at row " << rowIndex << ": " << e.what());
        }
    }
    return vectorBatch;
}
```

### 长期改进

1. **输入验证层** - 在 Kafka 层添加 JSON schema 验证
2. **错误隔离** - 将解析错误隔离到单独的异常处理路径
3. **资源限制** - 配置全局 JSON 解析限制（大小、深度）
4. **监控告警** - 添加解析错误计数和告警机制

## 相关漏洞

- **SEC-010** - 同一漏洞的重复发现，同一文件不同行号范围
- **VULN-CROSS-001** - 跨模块反序列化链，包含本漏洞作为最终 sink

## 参考资料

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [nlohmann::json Exception Handling](https://json.nlohmann.me/api/basic_json/parse/)
- [OWASP: Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)