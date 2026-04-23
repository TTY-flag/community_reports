# VULN-DF-JNI-002：JNI getOutput指针注入漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-JNI-002 (同时涉及 VULN-SEC-JNI-002) |
| **类型** | 类型混淆 / 指针注入 |
| **CWE** | CWE-843 (Access of Resource Using Incompatible Type) |
| **严重程度** | Critical |
| **置信度** | 85/100 |
| **影响模块** | bindings/java |
| **文件位置** | `bindings/java/src/main/cpp/src/jni_operator.cpp:178-198` |
| **函数名** | `Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative` |

## 技术分析

### 漏洞代码

```cpp
JNIEXPORT jobject JNICALL Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative(JNIEnv *env, jobject jObj,
    jlong jOperatorAddr)
{
    std::call_once(loadVecBatchClsFlag, LoadVecBatchAndOmniResults, env);
    if (vecBatchCls == nullptr || omniResultsCls == nullptr) {
        env->ThrowNew(omniRuntimeExceptionClass, "The class VecBatch or OmniResult has not load yet.");
        return nullptr;
    }

    // 危险操作：直接转换，无验证
    auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddr);
    VectorBatch *outputVecBatch = nullptr;
    JNI_METHOD_START
    nativeOperator->GetOutput(&outputVecBatch);  // 调用虚函数
    JNI_METHOD_END_WITH_VECBATCH(nullptr, outputVecBatch)
    jobject result = nullptr;
    if (outputVecBatch) {
        RecordOutputVectorsStack(*outputVecBatch, env);
        result = Transform(env, *outputVecBatch);
    }
    return env->NewObject(omniResultsCls, omniResultsInitMethodId, result, nativeOperator->GetStatus());
}
```

### 漏洞机制

1. **单一参数暴露**: 只有一个 `jOperatorAddr` 参数，攻击面更简单
2. **虚函数调用风险**: `nativeOperator->GetOutput()` 是虚函数调用，依赖虚函数表指针
3. **无对象验证**: 没有检查指针是否指向有效的 Operator 对象
4. **返回值泄露**: `nativeOperator->GetStatus()` 会读取对象状态，可能泄露内存内容

### 与 addInputNative 的差异

| 特性 | addInputNative | getOutputNative |
|------|---------------|-----------------|
| 参数数量 | 2个指针 | 1个指针 |
| 调用类型 | 数据输入 | 数据输出 |
| 内存操作 | 写入 VectorBatch | 读取 VectorBatch |
| 虚函数调用 | AddInput | GetOutput |
| 主要风险 | 内存写入 + 虚表劫持 | 内存读取 + 虚表劫持 |

## 攻击场景演示

### 场景 1: 虚函数表劫持

```java
// 攻击者在内存中构造假的 Operator 对象
public class VirtualTableAttack {
    public void exploit() {
        // 分配内存并构造假对象
        long fakeOperatorAddr = allocateFakeOperator();
        
        // 设置假的虚函数表指针指向 shellcode
        writeVirtualTablePointer(fakeOperatorAddr, shellcodeAddr);
        
        // 调用 getOutputNative 触发虚函数调用
        OmniOperator fakeOperator = new OmniOperator(fakeOperatorAddr);
        OmniResults results = fakeOperator.getOutputNative();
        
        // GetOutput() 虚函数被调用时，控制流被劫持
    }
}
```

### 场景 2: 内存泄露

```java
// 通过多次调用读取进程内存布局
public class MemoryLeak {
    public void scanMemory() {
        for (long addr = 0x1000; addr < 0xFFFFFFFF; addr += 0x1000) {
            try {
                OmniOperator fakeOp = new OmniOperator(addr);
                OmniResults results = fakeOp.getOutputNative();
                // 如果没有崩溃，说明 addr 是一个可读地址
                // 分析返回结果获取内存内容
            } catch (Exception e) {
                // 地址无效，继续扫描
            }
        }
    }
}
```

### 场景 3: 状态值泄露

```cpp
// nativeOperator->GetStatus() 会读取内存
// 如果攻击者传入指向敏感数据的地址
// GetStatus() 可能返回该地址的内容作为状态值

// 例如：如果 Operator 对象的 status_ 字段位于偏移 0x20
// 攻击者可以读取 target_addr + 0x20 的内容
```

## 影响评估

### 直接影响

| 影响 | 严重程度 | 说明 |
|------|---------|------|
| **虚表劫持** | Critical | 可实现任意代码执行 |
| **内存泄露** | High | 可读取进程内存任意位置 |
| **信息泄露** | Medium | GetStatus() 返回值可能泄露敏感数据 |
| **进程崩溃** | High | 传入无效地址导致崩溃 |

### CVSS 评分: 9.1 (Critical)

## 修复建议

参见 [VULN-DF-JNI-001](./VULN-DF-JNI-001.md) 的修复建议，核心修复方案相同：

```cpp
JNIEXPORT jobject JNICALL Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative(JNIEnv *env, jobject jObj,
    jlong jOperatorAddr)
{
    // 修复: NULL 检查
    if (jOperatorAddr == 0) {
        env->ThrowNew(omniRuntimeExceptionClass, "Invalid null operator address");
        return nullptr;
    }
    
    // 修复: 魔术字验证
    auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddr);
    if (!op::Operator::IsValidObject(nativeOperator)) {
        env->ThrowNew(omniRuntimeExceptionClass, "Invalid Operator pointer");
        return nullptr;
    }
    
    // 原有逻辑
    std::call_once(loadVecBatchClsFlag, LoadVecBatchAndOmniResults, env);
    // ...
}
```

## 相关漏洞

- **VULN-DF-JNI-001 / VULN-SEC-JNI-001**: `addInputNative` 存在相同问题
- **VULN-DF-JNI-003 / VULN-SEC-JNI-003**: `closeNative` 存在相同问题

建议使用统一的验证机制修复所有 JNI 指针转换漏洞。