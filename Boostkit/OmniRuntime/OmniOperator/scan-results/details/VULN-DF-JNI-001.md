# VULN-DF-JNI-001：JNI addInput指针注入漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-JNI-001 (同时涉及 VULN-SEC-JNI-001) |
| **类型** | 类型混淆 / 指针注入 |
| **CWE** | CWE-843 (Access of Resource Using Incompatible Type) |
| **严重程度** | Critical |
| **置信度** | 85/100 |
| **影响模块** | bindings/java, operator |
| **文件位置** | `bindings/java/src/main/cpp/src/jni_operator.cpp:159-171` |
| **函数名** | `Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative` |

## 技术分析

### 漏洞代码

```cpp
JNIEXPORT jint JNICALL Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative(JNIEnv *env, jobject jObj,
    jlong jOperatorAddress, jlong jVecBatchAddress)
{
    int32_t errNo = 0;
    // 危险操作：直接将 jlong 转换为指针，无任何验证
    auto *vecBatch = reinterpret_cast<VectorBatch *>(jVecBatchAddress);
    auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddress);
    JNI_METHOD_START
    RecordInputVectorsStack(vecBatch, env);
    nativeOperator->SetInputVecBatch(vecBatch);
    errNo = nativeOperator->AddInput(vecBatch);
    JNI_METHOD_END_WITH_VECBATCH(errNo, nativeOperator->GetInputVecBatch())
    return errNo;
}
```

### 漏洞机制

1. **入口点暴露**: 该函数是 JNI 公开的入口点，任何持有 `OmniOperator` Java 对象的代码都可以调用
2. **类型转换缺失验证**: `jlong` (64位整数) 直接通过 `reinterpret_cast` 转换为 `VectorBatch*` 和 `Operator*` 指针
3. **无边界检查**: 没有检查指针是否为 NULL、是否指向有效内存区域、是否为预期的对象类型
4. **无魔术字验证**: 缺少对象魔术字（magic number）验证来确认指针确实指向预期的 C++ 对象

### 数据流

```
Java 代码 (攻击者控制)
    ↓
jlong jOperatorAddress / jVecBatchAddress (任意64位值)
    ↓
reinterpret_cast<VectorBatch*>(jVecBatchAddress)  [无验证]
reinterpret_cast<op::Operator*>(jOperatorAddress)  [无验证]
    ↓
nativeOperator->AddInput(vecBatch)
    ↓
内存访问 / 虚函数调用 / 内存写入
```

## 攻击场景演示

### 场景 1: 内存任意读取

攻击者通过 Java 代码传入一个精心构造的地址值：

```java
// 恶意 Java 代码
public class AttackDemo {
    public void exploit() {
        OmniOperator operator = getOperator();  // 获取合法 Operator
        
        // 尝试读取内核内存地址 0xffffffff80000000
        long fakeVecBatchAddr = 0xffffffff80000000L;
        
        // 触发 JNI 调用
        operator.addInputNative(operator.getNativeAddress(), fakeVecBatchAddr);
        // 当 nativeOperator->AddInput(vecBatch) 被调用时
        // VectorBatch 的虚函数表指针会被读取
        // 如果 vecBatch->GetVectorCount() 被调用，攻击者可能读取目标地址的内容
    }
}
```

### 场景 2: 任意内存写入

```java
// 攻击者传入指向攻击者控制内存区域的指针
long attackerBuffer = allocateAttackerMemory();
long fakeOperator = constructFakeOperatorObject(attackerBuffer);

operator.addInputNative(fakeOperator, attackerBuffer);
// Operator::AddInput 会向 vecBatch 写入数据
// 如果攻击者能控制写入的内容和位置，可以覆盖关键数据结构
```

### 场景 3: 类型混淆导致代码执行

```cpp
// 如果攻击者能控制内存布局，构造假的 VectorBatch 对象
// VectorBatch 的虚函数表可以被篡改
struct FakeVectorBatch {
    void* vtable;  // 攻击者构造的虚表指针
    // ... 其他字段
};

// 当调用 vecBatch->GetVectorCount() 等虚函数时
// 控制流会被劫持到攻击者指定的地址
```

### 场景 4: DoS 攻击

```java
// 简单的崩溃攻击
operator.addInputNative(0xDEADBEEF, 0x0);  // 无效地址
// 导致 JVM 进程崩溃
```

## 影响评估

### 直接影响

| 影响 | 严重程度 | 说明 |
|------|---------|------|
| **任意内存读取** | High | 可读取进程内存任意位置，泄露敏感数据 |
| **任意内存写入** | Critical | 可修改进程内存，破坏数据完整性 |
| **代码执行** | Critical | 通过虚表劫持可实现任意代码执行 |
| **进程崩溃** | High | 传入无效地址导致 DoS |

### 业务影响

1. **数据泄露**: 攻击者可读取加密密钥、用户凭证、内部数据结构
2. **权限提升**: 通过修改内存中的权限检查逻辑，提升攻击者权限
3. **远程代码执行**: 在适当的内存布局下，可实现 shellcode 执行
4. **服务拒绝**: 导致 Spark/Presto 计算引擎崩溃，影响业务连续性

### CVSS 评估

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector | Network | 通过网络提交的 SQL 查询可触发 |
| Attack Complexity | Low | 无需特殊条件，直接传入恶意参数即可 |
| Privileges Required | Low | 需要有提交查询的权限 |
| User Interaction | None | 无需用户交互 |
| Scope | Changed | 可影响底层操作系统 |
| Confidentiality | High | 可读取所有内存内容 |
| Integrity | High | 可修改任意内存 |
| Availability | High | 可导致进程崩溃 |

**CVSS 评分: 9.8 (Critical)**

## 修复建议

### 短期修复 (紧急)

```cpp
JNIEXPORT jint JNICALL Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative(JNIEnv *env, jobject jObj,
    jlong jOperatorAddress, jlong jVecBatchAddress)
{
    int32_t errNo = 0;
    
    // 修复 1: NULL 检查
    if (jOperatorAddress == 0 || jVecBatchAddress == 0) {
        env->ThrowNew(omniRuntimeExceptionClass, "Invalid null pointer address");
        return -1;
    }
    
    // 修复 2: 魔术字验证
    auto *vecBatch = reinterpret_cast<VectorBatch *>(jVecBatchAddress);
    if (!VectorBatch::IsValidObject(vecBatch)) {
        env->ThrowNew(omniRuntimeExceptionClass, "Invalid VectorBatch pointer");
        return -1;
    }
    
    auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddress);
    if (!op::Operator::IsValidObject(nativeOperator)) {
        env->ThrowNew(omniRuntimeExceptionClass, "Invalid Operator pointer");
        return -1;
    }
    
    // 原有逻辑
    JNI_METHOD_START
    RecordInputVectorsStack(vecBatch, env);
    nativeOperator->SetInputVecBatch(vecBatch);
    errNo = nativeOperator->AddInput(vecBatch);
    JNI_METHOD_END_WITH_VECBATCH(errNo, nativeOperator->GetInputVecBatch())
    return errNo;
}
```

### 长期修复 (推荐)

1. **使用安全的指针注册机制**:
```cpp
// 在 OperatorFactory::CreateOperator 时，将指针注册到全局表
static std::unordered_map<uint64_t, Operator*> validOperators;
static std::mutex operatorsMutex;

uint64_t RegisterOperator(Operator* op) {
    uint64_t id = GenerateSecureId();
    std::lock_guard<std::mutex> lock(operatorsMutex);
    validOperators[id] = op;
    return id;
}

Operator* ValidateAndGetOperator(uint64_t id) {
    std::lock_guard<std::mutex> lock(operatorsMutex);
    auto it = validOperators.find(id);
    if (it == validOperators.end()) return nullptr;
    return it->second;
}
```

2. **Java 层面使用 opaque handle 而非裸指针**:
```java
// 不暴露原始指针值
public class OmniOperator {
    private long handleId;  // 注册表 ID，而非内存地址
    
    // native 方法使用 handleId 而非地址
    private native int addInputNative(long handleId, long vecBatchHandleId);
}
```

3. **添加地址范围验证**:
```cpp
// 检查指针是否在合法内存范围内
bool IsValidPointer(void* ptr) {
    // 获取进程内存映射
    // 检查 ptr 是否在已分配的堆/栈范围内
    return true; // 实现具体逻辑
}
```

### 架构层面建议

1. **所有 JNI 入口点统一使用验证宏**:
```cpp
#define VALIDATE_JNI_POINTER(env, ptr, type, errmsg) \
    if (ptr == 0) { \
        env->ThrowNew(omniRuntimeExceptionClass, errmsg); \
        return ERROR_INVALID_POINTER; \
    } \
    if (!type::IsValidObject(reinterpret_cast<type*>(ptr))) { \
        env->ThrowNew(omniRuntimeExceptionClass, errmsg); \
        return ERROR_INVALID_OBJECT; \
    }
```

2. **实现对象魔术字**:
```cpp
class Operator {
private:
    static constexpr uint32_t MAGIC = 0xDEADBEEF;
    uint32_t magic_ = MAGIC;
    
public:
    static bool IsValidObject(Operator* ptr) {
        return ptr != nullptr && ptr->magic_ == MAGIC;
    }
};
```

## 相关漏洞

此漏洞在 `jni_operator.cpp` 中存在多个相似位置：
- **VULN-DF-JNI-002 / VULN-SEC-JNI-002**: `getOutputNative` 函数存在相同问题
- **VULN-DF-JNI-003 / VULN-SEC-JNI-003**: `closeNative` 函数存在相同问题

建议一并修复所有相似漏洞。

## 参考

- [CWE-843: Access of Resource Using Incompatible Type](https://cwe.mitre.org/data/definitions/843.html)
- [JNI Best Practices - Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/)
- [Secure Coding in C++ - pointer validation](https://isocpp.org/wiki/faq/security)