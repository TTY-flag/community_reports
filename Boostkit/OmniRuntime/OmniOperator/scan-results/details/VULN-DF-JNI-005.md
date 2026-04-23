# VULN-DF-JNI-005：JNI数组指针注入漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-JNI-005 (同时涉及 VULN-SEC-HELPER-001) |
| **类型** | 类型混淆 / 数组指针注入 |
| **CWE** | CWE-843 (Access of Resource Using Incompatible Type) |
| **严重程度** | High |
| **置信度** | 85/100 |
| **影响模块** | bindings/java |
| **文件位置** | `bindings/java/src/main/cpp/src/jni_helper.cpp:8-25` |
| **函数名** | `Java_nova_hetu_omniruntime_utils_ShuffleHashHelper_computePartitionIds` |

## 技术分析

### 漏洞代码

```cpp
JNIEXPORT jlong JNICALL Java_nova_hetu_omniruntime_utils_ShuffleHashHelper_computePartitionIds(JNIEnv *env,
    jclass jClass, jlongArray vecAddrArray, jint partitionNum, jint rowCount)
{
    // 基础检查
    if (partitionNum == 0) {
        env->ThrowNew(omniRuntimeExceptionClass, "PartitionNum should not be 0");
        return 0;
    }
    
    jsize length = env->GetArrayLength(vecAddrArray);
    jlong *addrs = (*env).GetLongArrayElements(vecAddrArray, nullptr);
    std::vector<omniruntime::vec::BaseVector *> vecs;
    
    // 危险操作：循环转换每个 jlong 为 BaseVector*，无验证
    for (int i = 0; i < length; ++i) {
        auto vec = reinterpret_cast<omniruntime::vec::BaseVector *>(addrs[i]);  // 无验证！
        vecs.push_back(vec);
    }
    
    env->ReleaseLongArrayElements(vecAddrArray, addrs, JNI_ABORT);
    
    // 使用转换后的指针数组
    auto ret = omniruntime::op::HashUtil::ComputePartitionIds(vecs, partitionNum, rowCount);
    return (jlong)ret.release();
}
```

### 漏洞机制

1. **数组批量转换**: 传入的是 `jlongArray`，包含多个指针值，批量转换为 `BaseVector*` 数组
2. **循环无验证**: 循环中每个元素都直接转换，没有魔术字或 NULL 检查
3. **指针数组传递**: 整个转换后的数组传递给 `HashUtil::ComputePartitionIds`
4. **partitionNum 有检查但 vecAddrArray 没有**: 只检查了 partitionNum，忽略了指针有效性

### 数组注入的特殊风险

| 特性 | 单指针注入 | 数组指针注入 |
|------|-----------|-------------|
| 单次攻击点 | 1个 | 多个 |
| 控制粒度 | 粗粒度 | 细粒度（每个元素） |
| 利用难度 | 较低 | 较低 |
| 检测难度 | 较易 | 较难（需验证所有元素） |
| 堆喷射效率 | 单点 | 多点布局 |

### 数据流

```
Java jlongArray vecAddrArray (包含 N 个地址)
    ↓
GetLongArrayElements → jlong* addrs
    ↓
循环：reinterpret_cast<BaseVector*>(addrs[i])  [无验证，N次]
    ↓
std::vector<BaseVector*> vecs
    ↓
HashUtil::ComputePartitionIds(vecs, partitionNum, rowCount)
    ↓
计算每个 vector 的哈希分区 ID
```

## 攻击场景演示

### 场景 1: 数组注入导致批量崩溃

```java
public class ArrayCrash {
    public void exploit() {
        // 构造包含多个无效地址的数组
        long[] fakeVecAddrs = new long[100];
        for (int i = 0; i < 100; i++) {
            fakeVecAddrs[i] = 0xDEAD0000L + i;  // 全是无效地址
        }
        
        ShuffleHashHelper helper = new ShuffleHashHelper();
        long result = helper.computePartitionIds(fakeVecAddrs, 10, 100);
        
        // 循环中的每个转换都会触发内存访问
        // 导致 JVM 进程崩溃
    }
}
```

### 场景 2: 混合合法/非法地址攻击

```java
public class MixedAttack {
    public void exploit() {
        // 获取合法 Vector 地址
        long[] vecAddrs = getLegalVectorAddresses();
        
        // 混入一个恶意地址
        vecAddrs[50] = 0xCAFEBABE;  // 无效地址
        
        ShuffleHashHelper helper = new ShuffleHashHelper();
        long result = helper.computePartitionIds(vecAddrs, 10, 100);
        
        // 前 50 个正常处理，第 51 个触发问题
        // 可能导致部分数据损坏或崩溃
    }
}
```

### 场景 3: 堆布局探测

```java
public class HeapProbe {
    public void probeHeap() {
        // 构造大量不同地址进行探测
        long[] probeAddrs = new long[1000];
        for (long addr = 0x1000; addr < 0xFFFFFFFF; addr += 0x10000) {
            // 填充探测数组
            probeAddrs[(int)(addr / 0x10000) % 1000] = addr;
        }
        
        // 批量尝试，找出可访问的内存区域
        try {
            ShuffleHashHelper helper = new ShuffleHashHelper();
            long result = helper.computePartitionIds(probeAddrs, 10, 1000);
            // 如果不崩溃，某些地址是有效的
        } catch (Exception e) {
            // 分析崩溃模式推断内存布局
        }
    }
}
```

### 场景 4: 虚表劫持批量攻击

```cpp
// 如果攻击者能在多个地址布置假的 BaseVector 结构
// 且这些结构的虚函数表指向 shellcode

struct FakeBaseVector {
    void* vtable;  // 指向攻击者构造的虚表
    // ... 其他字段匹配真实 BaseVector
};

// 当 HashUtil::ComputePartitionIds 调用虚函数时
// 例如 vec->GetTypeId() 或 vec->GetValue()
// 控制流被批量劫持
```

## 影响评估

### 直接影响

| 影响 | 严重程度 | 说明 |
|------|---------|------|
| **批量崩溃** | High | 数组中任一无效地址导致崩溃 |
| **内存探测** | Medium | 可探测进程内存布局 |
| **虚表批量劫持** | Medium | 需要精确的内存布局控制 |
| **数据损坏** | Medium | 可能损坏部分 vector 数据 |

### CVSS 评分: 7.5 (High)

### 与 Critical 漏洞的差异

1. **partitionNum 有基础检查**: 至少验证了 partitionNum != 0
2. **数组参数更复杂**: 需要验证多个元素，增加了攻击难度
3. **rowCount 参数作用**: rowCount 限制了处理的行数，有一定约束
4. **HashUtil 内部可能有检查**: 如果 HashUtil::ComputePartitionIds 内部有检查，风险降低

## 修复建议

### 短期修复 - 数组元素验证

```cpp
JNIEXPORT jlong JNICALL Java_nova_hetu_omniruntime_utils_ShuffleHashHelper_computePartitionIds(JNIEnv *env,
    jclass jClass, jlongArray vecAddrArray, jint partitionNum, jint rowCount)
{
    // 原有检查
    if (partitionNum == 0) {
        env->ThrowNew(omniRuntimeExceptionClass, "PartitionNum should not be 0");
        return 0;
    }
    
    // 新增：rowCount 检查
    if (rowCount <= 0) {
        env->ThrowNew(omniRuntimeExceptionClass, "RowCount should be positive");
        return 0;
    }
    
    jsize length = env->GetArrayLength(vecAddrArray);
    if (length <= 0) {
        env->ThrowNew(omniRuntimeExceptionClass, "Empty vecAddrArray");
        return 0;
    }
    
    jlong *addrs = (*env).GetLongArrayElements(vecAddrArray, nullptr);
    std::vector<omniruntime::vec::BaseVector *> vecs;
    
    // 修复：循环中验证每个元素
    for (int i = 0; i < length; ++i) {
        // NULL 检查
        if (addrs[i] == 0) {
            env->ThrowNew(omniRuntimeExceptionClass, "Null vector address at index " + std::to_string(i));
            env->ReleaseLongArrayElements(vecAddrArray, addrs, JNI_ABORT);
            return 0;
        }
        
        auto vec = reinterpret_cast<omniruntime::vec::BaseVector *>(addrs[i]);
        
        // 魔术字验证
        if (!omniruntime::vec::BaseVector::IsValidObject(vec)) {
            env->ThrowNew(omniRuntimeExceptionClass, 
                "Invalid BaseVector pointer at index " + std::to_string(i));
            env->ReleaseLongArrayElements(vecAddrArray, addrs, JNI_ABORT);
            return 0;
        }
        
        vecs.push_back(vec);
    }
    
    env->ReleaseLongArrayElements(vecAddrArray, addrs, JNI_ABORT);
    auto ret = omniruntime::op::HashUtil::ComputePartitionIds(vecs, partitionNum, rowCount);
    return (jlong)ret.release();
}
```

### BaseVector 类增加验证

```cpp
namespace omniruntime::vec {
class BaseVector {
private:
    static constexpr uint32_t MAGIC = 0xBASEVEC42;
    uint32_t magic_ = MAGIC;
    
public:
    static bool IsValidObject(BaseVector* ptr) {
        if (ptr == nullptr) return false;
        // 注意：需要确保读取 magic_ 不会触发访问违规
        // 可以添加地址范围检查
        try {
            return ptr->magic_ == MAGIC;
        } catch (...) {
            return false;
        }
    }
};
}
```

### 安全的指针转换工具

```cpp
// 创建安全的指针转换工具
namespace SafeCast {
    template<typename T>
    static T* SafeJlongToPtr(jlong addr, JNIEnv* env, const char* errmsg) {
        if (addr == 0) {
            env->ThrowNew(omniRuntimeExceptionClass, errmsg);
            return nullptr;
        }
        
        T* ptr = reinterpret_cast<T*>(addr);
        if (!T::IsValidObject(ptr)) {
            env->ThrowNew(omniRuntimeExceptionClass, errmsg);
            return nullptr;
        }
        
        return ptr;
    }
    
    template<typename T>
    static bool ValidateArray(jlongArray arr, JNIEnv* env, std::vector<T*>& out) {
        jsize length = env->GetArrayLength(arr);
        jlong* addrs = env->GetLongArrayElements(arr, nullptr);
        
        for (int i = 0; i < length; ++i) {
            T* ptr = SafeJlongToPtr<T>(addrs[i], env, 
                "Invalid pointer at index " + std::to_string(i));
            if (ptr == nullptr) {
                env->ReleaseLongArrayElements(arr, addrs, JNI_ABORT);
                return false;
            }
            out.push_back(ptr);
        }
        
        env->ReleaseLongArrayElements(arr, addrs, JNI_ABORT);
        return true;
    }
}
```

### 使用安全工具重构

```cpp
JNIEXPORT jlong JNICALL Java_nova_hetu_omniruntime_utils_ShuffleHashHelper_computePartitionIds(JNIEnv *env,
    jclass jClass, jlongArray vecAddrArray, jint partitionNum, jint rowCount)
{
    if (partitionNum == 0) {
        env->ThrowNew(omniRuntimeExceptionClass, "PartitionNum should not be 0");
        return 0;
    }
    
    std::vector<omniruntime::vec::BaseVector*> vecs;
    if (!SafeCast::ValidateArray<omniruntime::vec::BaseVector>(vecAddrArray, env, vecs)) {
        return 0;  // 验证失败已抛出异常
    }
    
    auto ret = omniruntime::op::HashUtil::ComputePartitionIds(vecs, partitionNum, rowCount);
    return (jlong)ret.release();
}
```

## 相关漏洞

- **VULN-SEC-HELPER-001**: 同一漏洞，由 security-auditor 发现
- **VULN-DF-JNI-001/002/003**: 单指针注入漏洞，更严重

建议为所有 JNI 数组指针转换创建统一的 `ValidateArray` 工具函数。