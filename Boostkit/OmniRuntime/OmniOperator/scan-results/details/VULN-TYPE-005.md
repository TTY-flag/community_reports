# VULN-TYPE-005: 空指针返回漏洞

## 漏洞概述

**漏洞类型**: 空指针解引用 (CWE-476)  
**严重级别**: High  
**置信度**: 90%  
**影响模块**: type, operator

OmniOperator 的 `DataTypeJsonParser` 函数在遇到未支持的数据类型 ID 时，返回 `nullptr` 而非抛出异常。这个空指针被添加到类型向量中，后续代码使用时可能导致空指针解引用崩溃。

## 漏洞触发条件

1. 攻击者能够控制传入的数据类型 JSON
2. JSON 中包含未支持或恶意构造的 dataTypeId
3. 后续代码使用返回的 DataType 指针时触发空指针解引用

## 完整攻击路径

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Null Pointer Return Flow                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. 数据类型 JSON 输入                                                        │
│     [{"id": 999}]  // 未支持的 dataTypeId                                    │
│                                                                              │
│  2. Deserialize 调用 data_type_serializer.cpp:23-31                          │
│     DataTypes Deserialize(const std::string &dataTypes)                      │
│     {                                                                         │
│         auto dataTypeJsons = nlohmann::json::parse(dataTypes);               │
│         std::vector<DataTypePtr> types;                                      │
│         for (const auto &dataTypeJson : dataTypeJsons) {                     │
│             types.push_back(DataTypeJsonParser(dataTypeJson));               │
│         }                                                                     │
│         return DataTypes(types);                                             │
│     }                                                                         │
│                                                                              │
│  3. DataTypeJsonParser data_type_serializer.cpp:84-87                        │
│     switch (dataTypeId) {                                                     │
│         case OMNI_INT: return IntType();                                     │
│         case OMNI_LONG: return LongType();                                   │
│         ...                                                                   │
│         default:                                                              │
│             LogError("Not Supported Data Type : %d", dataTypeId);            │
│             return nullptr;  // ⚠️ 返回空指针而非抛异常                        │
│     }                                                                         │
│                                                                              │
│  4. nullptr 被添加到向量                                                      │
│     types.push_back(nullptr);  // ⚠️ 空指针被存储                             │
│                                                                              │
│  5. 后续使用触发空指针解引用                                                   │
│     // operator/aggregation 等模块使用 DataType                               │
│     DataTypePtr type = types[0];                                             │
│     type->GetWidth();  // ⚠️ 如果 type == nullptr → Crash                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 关键代码分析

### data_type_serializer.cpp:84-87

```cpp
DataTypePtr DataTypeJsonParser(const nlohmann::json &dataTypeJson)
{
    int dataTypeId = dataTypeJson[ID].get<int>();
    switch (dataTypeId) {
        case OMNI_NONE:
            return NoneType();
        case OMNI_INT:
            return IntType();
        ...
        default:
            LogError("Not Supported Data Type : %d", dataTypeId);
            return nullptr;  // ⚠️ 返回 nullptr 而非抛异常
    }
}
```

**安全缺陷分析**:
- `default` 分支返回 `nullptr` 而非抛出异常
- 调用方 `Deserialize` 不检查返回值有效性
- `nullptr` 被直接 push 到 `types` 向量中
- 后续代码假设向量中的元素都是有效指针

### 下游代码风险

```cpp
// 可能的下游使用
for (const auto& type : types) {
    // ⚠️ 如果 type 为 nullptr，这里会崩溃
    auto width = type->GetWidth();  // 空指针解引用
}
```

## 利用步骤 (PoC)

### 构造恶意 JSON

```json
// malicious_types.json
[
    {"id": 0},  // 正常类型
    {"id": 999},  // ⚠️ 未支持的类型 ID → 返回 nullptr
    {"id": 1}   // 正常类型
]
```

### SQL 查询攻击

```sql
-- 攻击者构造包含未支持类型的查询计划
-- 通过 Spark/Hive 传入恶意 JSON
SELECT * FROM table WHERE col_type_cast(column, 'malicious_type_spec');
```

### 直接调用攻击

```cpp
// 直接调用 Deserialize
auto types = Deserialize("[{\"id\": 999}]");
// types[0] == nullptr

// 后续使用触发空指针解引用
auto type = types[0];
if (type) {  // ⚠️ 没有这个检查
    type->GetWidth();  // Crash
}
```

## 危害评估

### 攻击影响
- **Denial of Service**: 导致 Worker 进程崩溃
- **数据处理中断**: 算子初始化失败
- **潜在内存破坏**: 如果空指针被用于 memcpy 等操作

### CVSS 评分预估
- **攻击向量**: Network (通过 SQL/JSON 输入)
- **攻击复杂度**: Low
- **权限要求**: Low
- **影响**: High (进程崩溃)

**预估 CVSS 评分**: 7.0 (High)

## 修复建议

### 1. 抛出异常替代返回 nullptr（优先级：高）

```cpp
DataTypePtr DataTypeJsonParser(const nlohmann::json &dataTypeJson)
{
    int dataTypeId = dataTypeJson[ID].get<int>();
    switch (dataTypeId) {
        case OMNI_NONE:
            return NoneType();
        ...
        default:
            // 抛出异常而非返回 nullptr
            throw std::runtime_error("Unsupported Data Type ID: " + std::to_string(dataTypeId));
    }
}
```

### 2. 在 Deserialize 中添加验证（优先级：高）

```cpp
DataTypes Deserialize(const std::string &dataTypes)
{
    auto dataTypeJsons = nlohmann::json::parse(dataTypes);
    std::vector<DataTypePtr> types;
    for (const auto &dataTypeJson : dataTypeJsons) {
        auto type = DataTypeJsonParser(dataTypeJson);
        // 添加空指针检查
        if (type == nullptr) {
            throw std::runtime_error("Invalid data type in JSON");
        }
        types.push_back(type);
    }
    return DataTypes(types);
}
```

### 3. 使用 JNI_METHOD_START/END 包装调用（优先级：中）

```cpp
// 在 JNI 层调用 Deserialize 时添加异常处理
JNI_METHOD_START
auto sourceDataTypes = Deserialize(sourceTypesCharPtr);
// 检查结果有效性
if (sourceDataTypes.empty() || hasNullType(sourceDataTypes)) {
    SetError(contextPtr, "Invalid data types");
    return 0;
}
JNI_METHOD_END(0L)
```

## 参考信息

- CWE-476: NULL Pointer Dereference
- C++ Exception Handling Best Practices