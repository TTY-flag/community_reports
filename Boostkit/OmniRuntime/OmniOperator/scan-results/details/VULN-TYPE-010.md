# VULN-TYPE-010: 异常处理缺失漏洞

## 漏洞概述

**漏洞类型**: 异常处理缺失 (CWE-248)  
**严重级别**: High  
**置信度**: 95%  
**影响模块**: jni_bindings, type

OmniOperator 的 JNI 绑定层在调用 `Deserialize` 函数时缺少 try-catch 异常处理。当 `nlohmann::json::parse` 解析恶意 JSON 时抛出异常，会导致 JNI 调用崩溃或未定义行为。

## 漏洞触发条件

1. 攻击者能够控制传入的数据类型 JSON 字符串
2. JSON 字符串格式错误或包含特殊构造的内容
3. 异常在 JNI 调用栈中传播导致崩溃

## 关键代码分析

### jni_operator_factory.cpp:137

```cpp
// GetDataTypesVector 函数
auto dataTypes = Deserialize(sourceTypesCharPtr);  // ⚠️ 无 try-catch 保护
```

### data_type_serializer.cpp:25

```cpp
DataTypes Deserialize(const std::string &dataTypes)
{
    // ⚠️ nlohmann::json::parse 可能抛出异常
    auto dataTypeJsons = nlohmann::json::parse(dataTypes);
    ...
}
```

**安全缺陷分析**:
- `nlohmann::json::parse` 在解析无效 JSON 时抛出 `json::exception`
- JNI 层调用 `Deserialize` 时没有 `try-catch` 或 `JNI_METHOD_START/END` 保护
- 异常会传播到 JNI 边界，导致崩溃

## 利用步骤 (PoC)

### 构造恶意 JSON

```java
// 通过 Java 适配层传入恶意 JSON
String maliciousJson = "[{\"id\": invalid}";  // 缺少闭合括号，无效 JSON
// 或
String maliciousJson = "{\"id\": \"not_a_number\"}";  // 类型错误
// 或
String maliciousJson = "[\x00\x01\x02]";  // 包含非法字符
```

### SQL 查询攻击

```sql
-- 攻击者通过构造恶意的类型描述触发异常
SELECT * FROM table WHERE filter_with_malicious_types(column);
```

### JNI 直接调用

```cpp
// 直接调用 Deserialize
auto types = Deserialize("invalid json");  // 抛出 json::exception
// 如果没有异常处理 → Crash
```

## 危害评估

### 攻击影响
- **JNI 崩溃**: C++ 异常穿过 JNI 边界导致进程崩溃
- **Denial of Service**: Worker 进程异常退出
- **未定义行为**: 异常处理不当可能导致内存状态不一致

### CVSS 评分预估
- **攻击向量**: Network (通过 JSON 输入)
- **攻击复杂度**: Low (简单构造无效 JSON)
- **权限要求**: Low
- **影响**: High (进程崩溃)

**预估 CVSS 评分**: 6.5 (Medium-High)

## 修复建议

### 1. 添加 try-catch 异常处理（优先级：高）

```cpp
// 在所有 Deserialize 调用处添加异常处理
auto sourceTypesCharPtr = env->GetStringUTFChars(jSourceTypes, JNI_FALSE);
try {
    auto sourceDataTypes = Deserialize(sourceTypesCharPtr);
    // 正常处理
} catch (const nlohmann::json::exception& e) {
    env->ThrowNew(omniRuntimeExceptionClass, 
        "JSON parse error: " + std::string(e.what()));
    env->ReleaseStringUTFChars(jSourceTypes, sourceTypesCharPtr);
    return 0;
} catch (const std::exception& e) {
    env->ThrowNew(omniRuntimeExceptionClass, e.what());
    env->ReleaseStringUTFChars(jSourceTypes, sourceTypesCharPtr);
    return 0;
}
env->ReleaseStringUTFChars(jSourceTypes, sourceTypesCharPtr);
```

### 2. 使用 JNI_METHOD_START/END 包装（优先级：高）

```cpp
// 确保所有 JNI 函数使用 JNI_METHOD_START/END
JNIEXPORT jlong JNICALL Java_..._createSortOperatorFactory(...)
{
    auto sourceTypesCharPtr = env->GetStringUTFChars(jSourceTypes, JNI_FALSE);
    
    JNI_METHOD_START  // 提供异常处理
    auto sourceDataTypes = Deserialize(sourceTypesCharPtr);
    ...
    JNI_METHOD_END(0L)  // 确保异常被正确处理
    
    env->ReleaseStringUTFChars(jSourceTypes, sourceTypesCharPtr);
    return ...;
}
```

### 3. Deserialize 函数内部处理异常（优先级：中）

```cpp
DataTypes Deserialize(const std::string &dataTypes)
{
    try {
        auto dataTypeJsons = nlohmann::json::parse(dataTypes);
        std::vector<DataTypePtr> types;
        for (const auto &dataTypeJson : dataTypeJsons) {
            auto type = DataTypeJsonParser(dataTypeJson);
            if (type != nullptr) {
                types.push_back(type);
            }
        }
        return DataTypes(types);
    } catch (const nlohmann::json::exception& e) {
        LogError("JSON parse failed: %s", e.what());
        return DataTypes();  // 返回空结果而非抛异常
    }
}
```

## 参考信息

- CWE-248: Uncaught Exception
- JNI Exception Handling Best Practices
- nlohmann::json Exception Handling