# VULN-DF-JNI-003：JNI close指针注入漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-JNI-003 (同时涉及 VULN-SEC-JNI-003) |
| **类型** | 类型混淆 / Use-After-Free / Arbitrary Memory Free |
| **CWE** | CWE-843 (Access of Resource Using Incompatible Type) + CWE-416 (Use After Free) |
| **严重程度** | Critical |
| **置信度** | 85/100 |
| **影响模块** | bindings/java |
| **文件位置** | `bindings/java/src/main/cpp/src/jni_operator.cpp:205-214` |
| **函数名** | `Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative` |

## 技术分析

### 漏洞代码

```cpp
JNIEXPORT void JNICALL Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative(JNIEnv *env, jobject jObj,
    jlong jOperatorAddr)
{
    try {
        // 危险操作：直接转换并删除对象
        auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddr);
        op::Operator::DeleteOperator(nativeOperator);  // 可能释放任意内存
    } catch (const std::exception &e) {
        env->ThrowNew(omniRuntimeExceptionClass, e.what());
    }
}
```

### 漏洞机制

1. **内存释放操作**: `DeleteOperator` 会调用对象的析构函数并释放内存
2. **任意内存释放风险**: 攻击者可以传入任意地址，触发对非法内存的释放操作
3. **Use-After-Free**: 如果攻击者知道合法 Operator 的地址，可以多次调用 `closeNative` 导致 double-free
4. **堆破坏**: 对非堆内存调用 `delete` 会破坏堆管理器状态

### 危险等级分析

| 操作 | 风险等级 | 说明 |
|------|---------|------|
| 释放无效地址 | Critical | 可能导致堆破坏或进程崩溃 |
| Double-free | Critical | 已释放的对象再次释放，经典漏洞 |
| 释放栈内存 | High | 调用栈上的内存被释放，导致未定义行为 |
| 释放全局内存 | Medium | 全局/静态变量区域被释放 |

## 攻击场景演示

### 场景 1: Double-Free 攻击

```java
public class DoubleFreeAttack {
    public void exploit() {
        OmniOperator operator = getOperator();
        long operatorAddr = operator.getNativeAddress();
        
        // 第一次关闭 - 正常释放
        operator.closeNative();
        
        // 第二次关闭 - double-free
        operator.closeNative();  // operatorAddr 指向已释放内存
        
        // 此时堆管理器状态被破坏
        // 后续内存分配可能返回攻击者控制区域的内存
        // 结合其他漏洞可实现代码执行
    }
}
```

### 场景 2: Arbitrary Free

```java
public class ArbitraryFreeAttack {
    public void exploit() {
        // 尝试释放栈上的内存
        long stackAddr = getStackAddress();
        OmniOperator fakeOperator = new OmniOperator(stackAddr);
        fakeOperator.closeNative();  // 释放栈内存
        
        // 或释放其他合法对象
        SomeObject other = getSomeObject();
        long otherAddr = getOtherObjectAddress(other);
        OmniOperator fakeOp = new OmniOperator(otherAddr);
        fakeOp.closeNative();  // 错误释放其他对象
        
        // other 对象现在处于无效状态
        // 使用 other 可能触发 use-after-free
    }
}
```

### 场景 3: 堆喷射结合攻击

```cpp
// 攻击者首先喷射堆内存，布置特定数据结构
// 然后通过 closeNative 释放精心选择的地址
// 使堆管理器重新分配攻击者控制区域的对象

// 步骤 1: 堆喷射
for (int i = 0; i < 10000; i++) {
    allocateMemoryWithSpecificPattern();
}

// 步骤 2: 找到喷射区域中的目标地址
long targetAddr = findTargetInSprayedMemory();

// 步骤 3: 释放目标地址（攻击者控制的内存被标记为"已释放"）
OmniOperator fakeOp = new OmniOperator(targetAddr);
fakeOp.closeNative();

// 步骤 4: 请求新分配，堆管理器可能返回攻击者控制的内存
Operator* newOp = OperatorFactory::CreateOperator();
// newOp 可能指向攻击者布置的数据结构
// 虚函数调用会执行攻击者代码
```

## 影响评估

### 直接影响

| 影响 | 严重程度 | 说明 |
|------|---------|------|
| **Double-Free** | Critical | 经典漏洞模式，可导致代码执行 |
| **任意内存释放** | Critical | 破坏堆状态，影响后续所有内存操作 |
| **堆破坏** | High | 堆管理器元数据被破坏 |
| **Use-After-Free** | Critical | 与其他漏洞组合可实现利用链 |
| **进程崩溃** | High | 释放非法地址导致崩溃 |

### CVSS 评分: 9.8 (Critical)

## 修复建议

### 短期修复

```cpp
JNIEXPORT void JNICALL Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative(JNIEnv *env, jobject jObj,
    jlong jOperatorAddr)
{
    // 修复 1: NULL 检查
    if (jOperatorAddr == 0) {
        return;  // NULL 指针，安全忽略
    }
    
    // 修复 2: 魔术字验证
    auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddr);
    if (!op::Operator::IsValidObject(nativeOperator)) {
        env->ThrowNew(omniRuntimeExceptionClass, "Invalid Operator pointer");
        return;
    }
    
    // 修复 3: 从注册表移除（防止 double-free）
    if (!OperatorRegistry::UnregisterAndDelete(jOperatorAddr)) {
        env->ThrowNew(omniRuntimeExceptionClass, "Operator already closed or invalid");
        return;
    }
}
```

### 推荐修复 - 注册表机制

```cpp
// 全局 Operator 注册表
class OperatorRegistry {
private:
    static std::unordered_map<uint64_t, Operator*> operators_;
    static std::mutex mutex_;
    
public:
    // 创建时注册
    static uint64_t Register(Operator* op) {
        uint64_t id = GenerateSecureId();
        std::lock_guard<std::mutex> lock(mutex_);
        operators_[id] = op;
        return id;
    }
    
    // 删除时移除并释放
    static bool UnregisterAndDelete(uint64_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = operators_.find(id);
        if (it == operators_.end()) {
            return false;  // 已被删除或无效
        }
        Operator::DeleteOperator(it->second);
        operators_.erase(it);
        return true;
    }
    
    // 验证并获取
    static Operator* Get(uint64_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = operators_.find(id);
        return (it != operators_.end()) ? it->second : nullptr;
    }
};
```

### Java 层面改进

```java
public class OmniOperator {
    private long handleId;  // 注册表 ID，而非内存地址
    private boolean closed = false;
    
    public void close() {
        if (closed) {
            throw new IllegalStateException("Operator already closed");
        }
        closeNative(handleId);
        closed = true;
    }
    
    private native void closeNative(long handleId);
}
```

## 相关漏洞

- **VULN-DF-JNI-001 / VULN-SEC-JNI-001**: `addInputNative` 存在相同问题
- **VULN-DF-JNI-002 / VULN-SEC-JNI-002**: `getOutputNative` 存在相同问题

建议对所有涉及指针删除的 JNI 入口点实现统一的注册表管理机制。

## 参考

- [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html)
- [Double-Free Vulnerabilities - OWASP](https://owasp.org/www-community/vulnerabilities/Double_Free)
- [Heap Exploitation Techniques](https://github.com/shellphish/how2heap)