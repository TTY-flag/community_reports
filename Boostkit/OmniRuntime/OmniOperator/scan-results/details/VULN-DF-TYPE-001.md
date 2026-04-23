# VULN-DF-TYPE-001：JNI指针转换导致类型混淆

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-TYPE-001 |
| **类型** | 类型混淆 / C-style cast 无验证 |
| **CWE** | CWE-843 (Access of Resource Using Incompatible Type) |
| **严重程度** | High |
| **置信度** | 85/100 |
| **影响模块** | bindings/java |
| **文件位置** | `bindings/java/src/main/cpp/src/jni_operator_factory.cpp:156-171` |
| **函数名** | `Java_nova_hetu_omniruntime_operator_OmniOperatorFactory_createOperatorNative` |

## 技术分析

### 漏洞代码

```cpp
JNIEXPORT jlong JNICALL Java_nova_hetu_omniruntime_operator_OmniOperatorFactory_createOperatorNative(JNIEnv *env,
    jobject jObj, jlong jNativeFactoryObj)
{
    // 危险操作：使用 C-style cast 直接转换，无任何验证
    auto operatorFactory = (OperatorFactory *)jNativeFactoryObj;
    omniruntime::op::Operator *nativeOperator = nullptr;

    JNI_METHOD_START
    nativeOperator = operatorFactory->CreateOperator();  // 虚函数调用
    if (nativeOperator == nullptr) {
        throw omniruntime::exception::OmniException("CREATE_OPERATOR_FAILED",
            "return a null pointer when creating operator");
    }
    JNI_METHOD_END(0L)

    return reinterpret_cast<intptr_t>(static_cast<void *>(nativeOperator));
}
```

### 漏洞机制

1. **C-style cast 而非 reinterpret_cast**: 使用 `(OperatorFactory *)` 这种更危险的 C 风格转换
2. **无任何验证**: 直接将 `jlong` 转换为 `OperatorFactory*`，没有 NULL 检查或魔术字验证
3. **虚函数调用**: `operatorFactory->CreateOperator()` 是虚函数调用，依赖虚函数表指针
4. **返回值泄露**: 创建的 Operator 指针被返回给 Java 端，可能被用于后续攻击

### C-style cast 的额外风险

C-style cast `(OperatorFactory *)` 比 `reinterpret_cast` 更危险，因为：

| 转换类型 | 行为 | 风险 |
|---------|------|------|
| `reinterpret_cast` | 仅重新解释位模式 | 类型混淆 |
| C-style cast | 可能尝试 const_cast + static_cast + reinterpret_cast 组合 | 更复杂的行为，可能绕过 const 保护 |

在 C++ 最佳实践中，应该避免使用 C-style cast，优先使用更明确的 cast 操作。

### 数据流

```
Java jlong jNativeFactoryObj (攻击者控制)
    ↓
(OperatorFactory *)jNativeFactoryObj  [C-style cast，无验证]
    ↓
operatorFactory->CreateOperator()  [虚函数调用]
    ↓
nativeOperator 指针
    ↓
返回给 Java 端 (可用于后续攻击)
```

## 攻击场景演示

### 场景 1: 无效 factory 地址

```java
public class InvalidFactory {
    public void exploit() {
        OmniOperatorFactory factory = new OmniOperatorFactory();
        
        // 传入无效的 factory 地址
        long fakeFactoryAddr = 0xDEADBEEF;
        OmniOperator operator = factory.createOperatorNative(fakeFactoryAddr);
        
        // OperatorFactory::CreateOperator 虚函数调用
        // 读取 fakeFactoryAddr 处的虚函数表指针
        // 导致崩溃或执行攻击者代码
    }
}
```

### 场景 2: 返回值滥用

```java
public class ReturnValueAbuse {
    public void exploit() {
        OmniOperatorFactory factory = getFactory();
        long factoryAddr = factory.getNativeAddress();
        
        // 正常创建 Operator
        OmniOperator operator = factory.createOperatorNative(factoryAddr);
        long operatorAddr = operator.getNativeAddress();
        
        // 将 operatorAddr 用于其他 JNI 漏洞
        // 例如传入 addInputNative 的 jOperatorAddress 参数
        operator.addInputNative(operatorAddr, maliciousVecBatchAddr);
    }
}
```

### 场景 3: 虚表劫持

```cpp
// 如果攻击者能控制 jNativeFactoryObj 指向的内存区域
// 并布置假的 OperatorFactory 结构

struct FakeOperatorFactory {
    void* vtable;  // 攻击者构造的虚表
    // ... 其他字段
};

// 当 CreateOperator 虚函数被调用时
// 控制流被劫持到攻击者指定的代码
```

### 场景 4: 利用链组合

```
[步骤 1] 通过 createOperatorNative 获取一个 Operator 指针
[步骤 2] 通过 VULN-DF-JNI-001 将此指针用于恶意操作
[步骤 3] 通过 VULN-DF-JNI-003 删除此指针
[步骤 4] 利用 Use-After-Free 漏洞执行代码
```

## 影响评估

### 直接影响

| 影响 | 严重程度 | 说明 |
|------|---------|------|
| **进程崩溃** | High | 无效 factory 地址导致崩溃 |
| **虚表劫持** | Medium | 需要精确内存布局控制 |
| **返回值滥用** | Medium | 创建的对象可用于其他漏洞 |
| **代码执行** | Medium | 与其他漏洞组合 |

### CVSS 评分: 7.5 (High)

### 与其他 JNI 漏洞的关系

此漏洞是整个攻击链的一部分：

```
createOperatorNative (创建对象)
    ↓
addInputNative (操作对象) [VULN-DF-JNI-001]
    ↓
getOutputNative (获取输出) [VULN-DF-JNI-002]
    ↓
closeNative (删除对象) [VULN-DF-JNI-003]
```

每个环节都存在指针验证问题，需要统一修复。

## 修复建议

### 短期修复

```cpp
JNIEXPORT jlong JNICALL Java_nova_hetu_omniruntime_operator_OmniOperatorFactory_createOperatorNative(JNIEnv *env,
    jobject jObj, jlong jNativeFactoryObj)
{
    // 修复 1: NULL 检查
    if (jNativeFactoryObj == 0) {
        env->ThrowNew(omniRuntimeExceptionClass, "Invalid null factory address");
        return 0;
    }
    
    // 修复 2: 使用 reinterpret_cast 替代 C-style cast
    auto operatorFactory = reinterpret_cast<OperatorFactory *>(jNativeFactoryObj);
    
    // 修复 3: 魔术字验证
    if (!OperatorFactory::IsValidObject(operatorFactory)) {
        env->ThrowNew(omniRuntimeExceptionClass, "Invalid OperatorFactory pointer");
        return 0;
    }
    
    omniruntime::op::Operator *nativeOperator = nullptr;

    JNI_METHOD_START
    nativeOperator = operatorFactory->CreateOperator();
    if (nativeOperator == nullptr) {
        throw omniruntime::exception::OmniException("CREATE_OPERATOR_FAILED",
            "return a null pointer when creating operator");
    }
    JNI_METHOD_END(0L)

    // 修复 4: 注册新创建的 Operator（防止后续滥用）
    uint64_t operatorId = OperatorRegistry::Register(nativeOperator);

    return operatorId;  // 返回注册表 ID 而非裸指针
}
```

### OperatorFactory 类增加验证

```cpp
class OperatorFactory {
private:
    static constexpr uint32_t MAGIC = 0xFACTORY42;
    uint32_t magic_ = MAGIC;
    
public:
    static bool IsValidObject(OperatorFactory* ptr) {
        return ptr != nullptr && ptr->magic_ == MAGIC;
    }
    
    virtual Operator* CreateOperator() {
        // 内部也应该验证
        // ...
    }
};
```

### 统一修复所有 Factory 相关 JNI 入口点

在 `jni_operator_factory.cpp` 中存在大量类似的 JNI 入口点，都使用类似的模式：

```cpp
// 例如 HashAggregationOperatorFactory 创建（line 176-234）
JNIEXPORT jlong JNICALL Java_..._createHashAggregationOperatorFactory(...)
{
    // 这里创建的 OperatorFactory 指针也需要注册
    // ...
    return reinterpret_cast<intptr_t>(static_cast<void *>(nativeOperatorFactory));
}
```

建议创建统一的工厂注册机制：

```cpp
class FactoryRegistry {
private:
    static std::unordered_map<uint64_t, OperatorFactory*> factories_;
    static std::mutex mutex_;
    
public:
    static uint64_t RegisterFactory(OperatorFactory* factory) {
        uint64_t id = GenerateSecureId();
        std::lock_guard<std::mutex> lock(mutex_);
        factories_[id] = factory;
        return id;
    }
    
    static OperatorFactory* ValidateAndGetFactory(uint64_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = factories_.find(id);
        return (it != factories_.end()) ? it->second : nullptr;
    }
    
    static bool DeleteFactory(uint64_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = factories_.find(id);
        if (it == factories_.end()) return false;
        delete it->second;
        factories_.erase(it);
        return true;
    }
};
```

### Java 层面改进

```java
public class OmniOperatorFactory {
    private long factoryHandleId;  // 注册表 ID
    
    public OmniOperator createOperator() {
        long operatorHandleId = createOperatorNative(factoryHandleId);
        return new OmniOperator(operatorHandleId);  // 使用 ID 而非裸指针
    }
    
    private native long createOperatorNative(long factoryHandleId);
}
```

## 代码风格修复

除了安全修复，还需要改进代码风格：

### 避免 C-style cast

```cpp
// 错误（当前代码）
auto operatorFactory = (OperatorFactory *)jNativeFactoryObj;

// 正确
auto operatorFactory = reinterpret_cast<OperatorFactory *>(jNativeFactoryObj);
```

### 统一使用 C++ cast

在所有 JNI 文件中搜索并替换：
- `(OperatorFactory *)` → `reinterpret_cast<OperatorFactory *>(...)`
- `(Operator *)` → `reinterpret_cast<Operator *>(...)`
- `(VectorBatch *)` → `reinterpret_cast<VectorBatch *>(...)`

## 相关漏洞

- **VULN-DF-JNI-001/002/003**: 同文件中的 Operator 操作漏洞
- **VULN-DF-JNI-005**: 数组指针转换漏洞

建议对所有 JNI 文件统一实施：
1. 替换 C-style cast 为 `reinterpret_cast`
2. 添加 NULL 检查和魔术字验证
3. 使用注册表机制管理所有裸指针