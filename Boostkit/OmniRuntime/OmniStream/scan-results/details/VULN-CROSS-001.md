# VULN-CROSS-001：跨模块反序列化漏洞链

## 漏洞概述

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN-CROSS-001 |
| **类型** | Cross-Module Deserialization Chain (CWE-502) |
| **严重性** | Critical |
| **置信度** | 85 |
| **源模块** | cross_module (jni + connector_kafka + core_serialization) |
| **发现者** | dataflow-scanner |

## 漏洞详细描述

这是一个**跨模块数据流漏洞链**，攻击者可通过 JNI 配置入口注入恶意配置，经过多个模块传递，最终在 JSON 反序列化层触发漏洞。整个数据流路径跨越三个模块，每个环节都缺少必要的验证和安全检查。

### 跨模块链路

```
[模块1: jni]
  JNI 配置入口 → Java 侧传递的 opDescriptionJSON
  ↓
[模块2: connector_kafka]
  KafkaSource 构造函数 → 解析 JSON 配置
  ↓
  DeserializationFactory::getDeserializationSchema(opDescriptionJSON)
  ↓
[模块3: core_serialization]
  JsonRowDataDeserializationSchema 构造函数 → 解析 outputNames/outputTypes
  ↓
  deserialize() 方法 → 解析 Kafka 消息 JSON ← 最终漏洞点
```

## 攻击向量分析

### 阶段 1: JNI 配置注入

```cpp
// jni_OmniStreamTask.cpp:18-40
JNIEXPORT jlong JNICALL Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask(
    JNIEnv *env, jclass clazz, jstring TDDString, jlong statusAddress, jlong nativeTask)
{
    const char *cStrTDD = (env)->GetStringUTFChars(TDDString, 0);
    
    // 漏洞点 1：直接解析 Java 传递的 JSON，无验证
    nlohmann::json tdd = nlohmann::json::parse(cStrTDD);
    
    // 漏洞点 2：将未验证的 JSON 传递给 StreamTask
    auto *streamTask = new omnistream::datastream::StreamTask(tdd, bufferStatus, task->getRuntimeEnv());
    
    env->ReleaseStringUTFChars(TDDString, cStrTDD);
    return reinterpret_cast<long>(streamTask);
}
```

**攻击入口**：Java Flink Runtime 通过 JNI 传递 TDD（TaskDeploymentDescriptor）JSON 字符串，虽然 Java 侧属于 semi_trusted，但攻击者可能：
- 控制配置文件内容
- 利用 Java 侧漏洞注入恶意配置
- 通过环境变量或命令行参数影响配置

### 阶段 2: KafkaSource 配置解析

```cpp
// KafkaSource.cpp:15-34
KafkaSource::KafkaSource(nlohmann::json& opDescriptionJSON, bool isBatch) : isBatch(isBatch)
{
    // 漏洞点 3：解析 Kafka properties 配置
    nlohmann::json properties = opDescriptionJSON["properties"];
    for (auto &[key, value] : properties.items()) {
        // 未验证 key/value 有效性
        auto iter = ConsumerConfigUtil::GetConfig().find(key);
        if (iter != ConsumerConfigUtil::GetConfig().end() && iter->second != "") {
            props.emplace(iter->second, value);
        }
    }
    
    // 漏洞点 4：创建反序列化 schema，传递未验证的 opDescriptionJSON
    auto innerDeserializationSchema = DeserializationFactory::getDeserializationSchema(opDescriptionJSON);
    deserializationSchema = KafkaRecordDeserializationSchema::valueOnly(innerDeserializationSchema);
}
```

**传递风险**：
- `opDescriptionJSON` 未经验证直接传递给 `DeserializationFactory`
- `outputNames` 和 `outputTypes` 可被攻击者控制

### 阶段 3: DeserializationFactory 和 JsonRowDataDeserializationSchema

```cpp
// DeserializationFactory (推测实现)
DeserializationSchema* DeserializationFactory::getDeserializationSchema(nlohmann::json& opDescriptionJSON)
{
    // 根据 opDescriptionJSON["format"] 选择 schema 类型
    // 若 format == "json"，创建 JsonRowDataDeserializationSchema
    return new JsonRowDataDeserializationSchema(opDescriptionJSON);
}

// JsonRowDataDeserializationSchema.h:20-27
explicit JsonRowDataDeserializationSchema(nlohmann::json& opDescriptionJSON)
    : fieldNames(opDescriptionJSON["outputNames"].get<std::vector<std::string>>())
{
    // 漏洞点 5：解析 outputTypes，未验证类型有效性
    auto outputTypes = opDescriptionJSON["outputTypes"].get<std::vector<std::string>>();
    for (std::string type : outputTypes) {
        fieldTypes.push_back(LogicalType::flinkTypeToOmniTypeId(type));
    }
}
```

**构造阶段风险**：
- `outputNames` 数组大小和内容未验证
- `outputTypes` 类型字符串未验证（可能导致类型转换错误）

### 阶段 4: 最终漏洞触发 (JsonRowDataDeserializationSchema::deserialize)

```cpp
// JsonRowDataDeserializationSchema.h:33-47
void* deserialize(std::vector<const uint8_t*>& messageVec, std::vector<size_t>& lengthVec) override
{
    // 漏洞点 6：使用未验证的 fieldNames/fieldTypes 进行解析
    int colSize = static_cast<int>(fieldNames.size());
    
    for (int rowIndex = 0; rowIndex < rowSize; rowIndex++) {
        // 漏洞点 7：无异常处理的 JSON 解析 ← 最终崩溃点
        node = nlohmann::json::parse(std::string_view(
            reinterpret_cast<const char *>(messageVec[rowIndex]), lengthVec[rowIndex]));
        
        for (int colIndex = 0; colIndex < colSize; colIndex++) {
            // 漏洞点 8：使用未验证的 fieldNames[colIndex] 访问 node
            setColValue(rowIndex, colIndex, vectorBatch, node);
        }
    }
    return vectorBatch;
}
```

## 利用步骤 (PoC 思路)

### 攻击路径 A：通过 Java 配置注入

```
步骤 1：准备恶意配置
  - Java 侧任务配置 JSON (TDD)
  - 包含恶意的 opDescriptionJSON

步骤 2：配置内容
{
  "operators": [{
    "type": "KafkaSource",
    "opDescriptionJSON": {
      "outputNames": ["field1", "field2", ...],  ← 控制字段名
      "outputTypes": ["INT", "STRING", ...],     ← 控制类型
      "properties": {...}
    }
  }]
}

步骤 3：触发路径
  JNI → StreamTask → KafkaSource → JsonRowDataDeserializationSchema
  
步骤 4：配合 Kafka 消息攻击
  发送匹配恶意配置的 JSON 消息到 Kafka topic
  触发 deserialize() 解析
```

### 攻击路径 B：直接 Kafka 消息攻击

```
步骤 1：假设已存在 JsonRowDataDeserializationSchema 任务
步骤 2：向 Kafka topic 发送恶意 JSON
步骤 3：OmniStream 消费消息 → deserialize() → parse() 异常
步骤 4：TaskManager 崩溃
```

### PoC JSON Payload 示例

```json
// Kafka 消息 payload - 触发 parse 异常
{"field1": 123, "field2": "}}}"}  // 畸形 JSON

// Kafka 消息 payload - 触发字段访问异常
{"wrong_field": 123}  // 缺少期望字段

// Kafka 消息 payload - 触发类型转换异常
{"field1": "not_an_int"}  // 类型不匹配
```

## 影响范围评估

### 跨模块影响分析

| 模块 | 影响点 | 风险等级 |
|------|--------|----------|
| jni | JSON 解析无验证 | High |
| connector_kafka | 配置传递无验证 | High |
| core_serialization | JSON 反序列化无异常处理 | Critical |

### 攻击复杂度分析

```
攻击复杂度：Medium → High

低复杂度路径：
  直接向 Kafka 发送恶意消息（需能访问 Kafka）

高复杂度路径：
  通过 Java 配置注入（需控制 Java Flink Runtime）

组合攻击：
  配置注入 + Kafka 消息攻击 = 更精确的漏洞触发
```

### CVSS 评分估算

```
CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:H
Base Score: 7.5 (High)

解释：
- AV:N - 网络可达（JNI/Kafka）
- AC:H - 需多步骤攻击
- PR:N - 无需认证（若能访问 Kafka）
- S:C - 跨模块影响，可能影响其他任务
- A:H - 进程崩溃
```

## 相关代码片段

### 完整数据流路径

```cpp
// === 模块1: jni ===
// jni_OmniStreamTask.cpp:27
nlohmann::json tdd = nlohmann::json::parse(cStrTDD);  // ← 起点

// === 模块2: connector_kafka ===
// KafkaSource.cpp:31-32
auto innerDeserializationSchema = DeserializationFactory::getDeserializationSchema(opDescriptionJSON);

// === 模块3: core_serialization ===
// JsonRowDataDeserializationSchema.h:40-41
node = nlohmann::json::parse(std::string_view(...));  // ← 最终漏洞点
```

### 跨模块验证缺失清单

| 检查点 | 当前状态 | 应有验证 |
|--------|----------|----------|
| JNI JSON 解析 | 无验证 | schema 验证、大小限制 |
| opDescriptionJSON 传递 | 无验证 | 字段完整性检查 |
| outputNames 数组 | 无验证 | 大小限制、内容验证 |
| outputTypes 类型 | 无验证 | 类型有效性检查 |
| Kafka 消息解析 | 无异常处理 | try-catch、格式验证 |
| fieldNames 字段访问 | 无验证 | 字段存在性检查 |

## 修复建议

### 模块级修复

#### 1. JNI 层修复

```cpp
// jni_OmniStreamTask.cpp
JNIEXPORT jlong JNICALL ...createNativeStreamTask(...)
{
    const char *cStrTDD = (env)->GetStringUTFChars(TDDString, 0);
    
    // 修复：添加大小限制
    size_t tdd_len = strlen(cStrTDD);
    if (tdd_len > MAX_TDD_SIZE) {
        LOG_ERROR("TDD JSON too large: " << tdd_len);
        env->ReleaseStringUTFChars(TDDString, cStrTDD);
        return 0;
    }
    
    // 修复：安全解析
    nlohmann::json tdd;
    try {
        tdd = nlohmann::json::parse(cStrTDD, nullptr, false, true);
        if (tdd.is_discarded()) {
            LOG_ERROR("Invalid TDD JSON");
            return 0;
        }
    } catch (...) {
        LOG_ERROR("TDD parse exception");
        return 0;
    }
    
    // 修复：验证必要字段
    if (!tdd.contains("operators") || !tdd["operators"].is_array()) {
        LOG_ERROR("TDD missing 'operators' field");
        return 0;
    }
    
    // ... 传递验证后的 JSON
}
```

#### 2. connector_kafka 层修复

```cpp
// KafkaSource.cpp
KafkaSource::KafkaSource(nlohmann::json& opDescriptionJSON, bool isBatch)
{
    // 修复：验证必要字段
    if (!opDescriptionJSON.contains("outputNames") || 
        !opDescriptionJSON.contains("outputTypes")) {
        throw std::invalid_argument("Missing required fields in opDescriptionJSON");
    }
    
    // 修复：验证数组大小
    auto& outputNames = opDescriptionJSON["outputNames"];
    auto& outputTypes = opDescriptionJSON["outputTypes"];
    if (!outputNames.is_array() || !outputTypes.is_array()) {
        throw std::invalid_argument("outputNames/outputTypes must be arrays");
    }
    if (outputNames.size() != outputTypes.size()) {
        throw std::invalid_argument("outputNames and outputTypes size mismatch");
    }
    if (outputNames.size() > MAX_COLUMNS) {
        throw std::invalid_argument("Too many columns");
    }
    
    // ... 安全创建 schema
}
```

#### 3. core_serialization 层修复

参考 [VULN-SERIAL-001.md](./VULN-SERIAL-001.md) 的修复建议。

### 跨模块协调修复

1. **统一验证接口**：定义 `validateOpDescriptionJSON()` 函数，所有模块调用
2. **错误传播机制**：验证失败时，通过异常或错误码向上传播
3. **边界隔离**：在每个模块边界添加数据验证

## 相关漏洞

- **VULN-SERIAL-001** - 最终 sink 漏洞（JSON 反序列化）
- **SEC-010** - 最终 sink 的重复发现

## 参考资料

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP: Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [JSON Schema Validation](https://json-schema.org/)