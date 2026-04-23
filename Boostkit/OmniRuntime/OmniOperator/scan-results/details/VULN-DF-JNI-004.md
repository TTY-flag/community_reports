# VULN-DF-JNI-004：JNI指针转换导致越界访问

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-JNI-004 |
| **类型** | 类型混淆 / 指针转换 |
| **CWE** | CWE-843 (Access of Resource Using Incompatible Type) |
| **严重程度** | High |
| **置信度** | 85/100 |
| **影响模块** | bindings/java, vector |
| **文件位置** | `bindings/java/src/main/cpp/src/jni_operator.cpp:348-356` |
| **函数名** | `Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_parseOneRow` |

## 技术分析

### 漏洞代码

```cpp
JNIEXPORT void JNICALL Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_parseOneRow(JNIEnv *env,
    jclass jcls, jlong parserAddr, jbyteArray bytes, jint rowIndex)
{
    jboolean isCopy = false;
    auto *row = env->GetByteArrayElements(bytes, &isCopy);
    auto *parser = reinterpret_cast<RowParser *>(parserAddr);  // 无验证转换
    parser->ParseOnRow(reinterpret_cast<uint8_t *>(row), rowIndex);  // 使用转换后的指针
    env->ReleaseByteArrayElements(bytes, row, 0);
}
```

### 漏洞机制

1. **parserAddr 指针无验证**: `jlong parserAddr` 直接转换为 `RowParser*`，没有检查有效性
2. **bytes 数据直接使用**: Java byte array 的元素直接被解释为行数据，没有长度验证
3. **rowIndex 没有边界检查**: `rowIndex` 参数没有验证是否在合法范围内
4. **双重指针风险**: `parser` 指针和 `row` 指针都可能被攻击者控制

### 与其他 JNI 漏洞的差异

| 特性 | addInputNative | parseOneRow |
|------|---------------|-------------|
| 指针参数数量 | 2 | 1 (parserAddr) |
| 数据参数 | jlong | jbyteArray |
| 数据来源 | Java 指针值 | Java byte array |
| 主要风险 | 指针注入 | 指针注入 + 数据解析 |
| 危险等级 | Critical | High |

### 数据流分析

```
Java byte array (bytes)
    ↓
GetByteArrayElements → jbyte* → reinterpret_cast<uint8_t*>
    ↓
RowParser::ParseOnRow(row, rowIndex)
    ↓
解析行数据，写入 Vector 结构
```

## 攻击场景演示

### 场景 1: 无效 parser 指针导致崩溃

```java
public class ParserCrash {
    public void exploit() {
        OmniRowDeserializer deserializer = new OmniRowDeserializer();
        byte[] data = new byte[100];
        
        // 传入无效的 parser 地址
        long fakeParserAddr = 0xDEADBEEF;
        deserializer.parseOneRow(fakeParserAddr, data, 0);
        
        // RowParser 对象不存在，ParseOnRow 调用导致崩溃
    }
}
```

### 场景 2: 恶意数据注入

```java
public class DataInjection {
    public void exploit() {
        // 获取合法的 parser
        OmniRowDeserializer deserializer = getDeserializer();
        long parserAddr = deserializer.getParserAddress();
        
        // 构造恶意 byte array，包含假的 Vector 结构
        byte[] maliciousData = constructFakeVectorStructure();
        
        // 解析恶意数据
        deserializer.parseOneRow(parserAddr, maliciousData, 0);
        
        // 如果 RowParser::ParseOnRow 没有验证数据结构
        // 可能写入非法内存或触发代码执行
    }
}
```

### 场景 3: rowIndex 越界

```java
public class RowIndexOverflow {
    public void exploit() {
        OmniRowDeserializer deserializer = getDeserializer();
        byte[] data = new byte[10];  // 小数据
        
        // 传入巨大的 rowIndex
        int maliciousRowIndex = Integer.MAX_VALUE;
        
        deserializer.parseOneRow(parserAddr, data, maliciousRowIndex);
        
        // 如果 RowParser 使用 rowIndex 计算偏移量
        // 可能访问超出数组边界的内存
    }
}
```

### 场景 4: 结合其他漏洞的利用链

```
[步骤 1] 通过 VULN-DF-JNI-001 获取合法 Operator 地址
[步骤 2] 通过 parseOneRow 的 parserAddr 参数注入假 RowParser
[步骤 3] 构造假 RowParser 的虚函数表指向 shellcode
[步骤 4] 触发 ParseOnRow 虚函数调用执行代码
```

## 影响评估

### 直接影响

| 影响 | 严重程度 | 说明 |
|------|---------|------|
| **进程崩溃** | High | 无效 parserAddr 导致崩溃 |
| **内存越界访问** | Medium | rowIndex 或 bytes 长度问题 |
| **数据结构破坏** | Medium | 恶意 bytes 数据破坏 Vector |
| **代码执行** | Medium | 结合其他漏洞可能实现 |

### CVSS 评估

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector | Local | 需要访问 Java API |
| Attack Complexity | Medium | 需要构造特定数据 |
| Privileges Required | Low | 需要有代码执行权限 |
| User Interaction | None | 无需用户交互 |
| Scope | Unchanged | 影响同进程 |
| Confidentiality | Low | 可能泄露少量数据 |
| Integrity | Medium | 可修改数据结构 |
| Availability | High | 可导致进程崩溃 |

**CVSS 评分: 7.1 (High)**

### 降级原因

相比 Critical 级别的 JNI 指针注入漏洞，此漏洞被评估为 High 级别，原因：

1. **parserAddr 需要更复杂的攻击路径**：不能像 addInputNative 直接传入任意地址就生效
2. **bytes 数据来自 Java 端**：Java 端已经过 JNI 的 GetByteArrayElements 处理，有一定缓冲
3. **攻击链较长**：需要结合其他漏洞才能实现代码执行
4. **DoS 风险明确**：但代码执行风险相对较低

## 修复建议

### 短期修复

```cpp
JNIEXPORT void JNICALL Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_parseOneRow(JNIEnv *env,
    jclass jcls, jlong parserAddr, jbyteArray bytes, jint rowIndex)
{
    // 修复 1: NULL 检查
    if (parserAddr == 0) {
        env->ThrowNew(omniRuntimeExceptionClass, "Invalid null parser address");
        return;
    }
    
    // 修复 2: 魔术字验证
    auto *parser = reinterpret_cast<RowParser *>(parserAddr);
    if (!RowParser::IsValidObject(parser)) {
        env->ThrowNew(omniRuntimeExceptionClass, "Invalid RowParser pointer");
        return;
    }
    
    // 修复 3: bytes 长度检查
    jsize bytesLen = env->GetArrayLength(bytes);
    if (bytesLen <= 0) {
        env->ThrowNew(omniRuntimeExceptionClass, "Empty byte array");
        return;
    }
    
    // 修复 4: rowIndex 边界检查（如果知道最大行数）
    // 需要从 parser 获取最大行数信息
    if (rowIndex < 0 || rowIndex >= parser->GetMaxRows()) {
        env->ThrowNew(omniRuntimeExceptionClass, "Invalid row index");
        return;
    }
    
    // 原有逻辑
    jboolean isCopy = false;
    auto *row = env->GetByteArrayElements(bytes, &isCopy);
    parser->ParseOnRow(reinterpret_cast<uint8_t *>(row), rowIndex);
    env->ReleaseByteArrayElements(bytes, row, 0);
}
```

### RowParser 类增加验证方法

```cpp
class RowParser {
private:
    static constexpr uint32_t MAGIC = 0xROWPARSER;
    uint32_t magic_ = MAGIC;
    int32_t maxRows_;
    
public:
    static bool IsValidObject(RowParser* ptr) {
        return ptr != nullptr && ptr->magic_ == MAGIC;
    }
    
    int32_t GetMaxRows() const { return maxRows_; }
    
    void ParseOnRow(uint8_t* row, int32_t rowIndex) {
        // 内部也需要验证 rowIndex
        if (rowIndex < 0 || rowIndex >= maxRows_) {
            throw OmniException("Invalid row index");
        }
        
        // 验证 row 指针有效性
        if (row == nullptr) {
            throw OmniException("Null row pointer");
        }
        
        // 原有解析逻辑
        // ...
    }
};
```

### Java 层面防御

```java
public class OmniRowDeserializer {
    private long parserHandle;  // 注册表 ID 而非裸指针
    
    public void parseOneRow(byte[] bytes, int rowIndex) {
        // 输入验证
        if (bytes == null || bytes.length == 0) {
            throw new IllegalArgumentException("Invalid bytes");
        }
        if (rowIndex < 0) {
            throw new IllegalArgumentException("Invalid rowIndex");
        }
        
        // 使用安全接口
        parseOneRowNative(parserHandle, bytes, rowIndex);
    }
    
    private native void parseOneRowNative(long parserHandle, byte[] bytes, int rowIndex);
}
```

## 相关漏洞

- **VULN-DF-JNI-001**: `addInputNative` 存在更严重的指针注入问题
- **parseOneRowByAddr** (line 358-366): 同文件中存在类似函数，已添加 NULL 检查但缺少完整验证

建议统一所有 RowParser 相关 JNI 入口点的验证逻辑。