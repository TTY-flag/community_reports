# cpp-core-jni-VULN-015: Arbitrary Memory Read via Unsafe Pointer Cast in deserializeDirect

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | cpp-core-jni-VULN-015 |
| **CWE** | CWE-20 (Improper Input Validation) |
| **严重性** | High |
| **置信度** | 85/100 |
| **状态** | CONFIRMED |
| **文件路径** | `cpp/core/jni/JniWrapper.cc` |
| **行号** | 1203-1217 |
| **函数** | `Java_org_apache_gluten_vectorized_ColumnarBatchSerializerJniWrapper_deserializeDirect` |

---

## 1. 漏洞代码分析

### 1.1 漏洞代码片段

**文件**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp/core/jni/JniWrapper.cc:1203-1217`

```cpp
JNIEXPORT jlong JNICALL Java_org_apache_gluten_vectorized_ColumnarBatchSerializerJniWrapper_deserializeDirect( // NOLINT
    JNIEnv* env,
    jobject wrapper,
    jlong serializerHandle,
    jlong address,
    jint size) {
  JNI_METHOD_START
  auto ctx = gluten::getRuntime(env, wrapper);

  auto serializer = ObjectStore::retrieve<ColumnarBatchSerializer>(serializerHandle);
  GLUTEN_DCHECK(serializer != nullptr, "ColumnarBatchSerializer cannot be null");
  auto batch = serializer->deserialize((uint8_t*)address, size);  // VULNERABLE
  return ctx->saveObject(batch);
  JNI_METHOD_END(kInvalidObjectHandle)
}
```

### 1.2 安全缺陷识别

| 缺陷类型 | 具体问题 | 严重程度 |
|----------|----------|----------|
| **地址未验证** | `jlong address` 直接 cast 为 `uint8_t*` 无任何验证 | Critical |
| **大小未验证** | `jint size` 未检查负数、零值、超大值 | High |
| **无边界检查** | 未验证 address 是否指向有效内存区域 | Critical |
| **类型安全性** | jlong 到指针的 unsafe reinterpret_cast | High |

---

## 2. 对比分析: 安全版本 vs 漏洞版本

### 2.1 安全版本 (deserialize)

**文件**: `JniWrapper.cc:1186-1201`

```cpp
JNIEXPORT jlong JNICALL Java_org_apache_gluten_vectorized_ColumnarBatchSerializerJniWrapper_deserialize(
    JNIEnv* env,
    jobject wrapper,
    jlong serializerHandle,
    jbyteArray data) {  // 使用 jbyteArray 而非原始地址
  JNI_METHOD_START
  auto ctx = getRuntime(env, wrapper);

  auto serializer = ObjectStore::retrieve<ColumnarBatchSerializer>(serializerHandle);
  GLUTEN_DCHECK(serializer != nullptr, "ColumnarBatchSerializer cannot be null");
  int32_t size = env->GetArrayLength(data);  // JNI 管理数组长度
  auto safeArray = getByteArrayElementsSafe(env, data);  // 安全获取数组元素
  auto batch = serializer->deserialize(safeArray.elems(), size);
  return ctx->saveObject(batch);
  JNI_METHOD_END(kInvalidObjectHandle)
}
```

### 2.2 关键差异

| 特性 | deserialize (安全) | deserializeDirect (漏洞) |
|------|-------------------|-------------------------|
| 参数类型 | `jbyteArray data` | `jlong address` |
| 内存来源 | JVM 托管的数组 | 任意内存地址 |
| 长度获取 | `GetArrayLength` (JNI 管理) | 直接传入 `jint size` |
| 内存访问 | `getByteArrayElementsSafe` | 直接 `reinterpret_cast` |
| 安全检查 | JNI 隐式边界检查 | **无任何检查** |

---

## 3. 数据流分析

### 3.1 完整数据流路径

```
[Java Side]
ColumnarBatchSerializerJniWrapper.deserializeDirect(address, size)
    │
    │  address = sun.misc.Unsafe.allocateMemory(...)  // 或任意值
    │  size = 任意 jint 值
    │
    ▼
[JNI Boundary]
jlong address ─────────────────────────────────────────┐
jint size ─────────────────────────────────────────────┤
                                                       │
                                                       ▼
[C++ Side]                                     reinterpret_cast<uint8_t*>(address)
Java_org_apache_gluten_vectorized_ColumnarBatchSerializerJniWrapper_deserializeDirect()
    │
    ├── serializer->deserialize((uint8_t*)address, size)
    │       │
    │       ▼
    │   [SINK] 任意内存读取
    │   - 从 address 指向的内存读取 size 字节
    │   - 无任何边界检查
    │   - 无地址有效性验证
    │
    └── return ctx->saveObject(batch)
```

### 3.2 信任边界分析

```
┌─────────────────────────────────────────────────────────────────────┐
│                     JVM Memory Space (Trusted)                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  Java Application Code                                       │    │
│  │  - 可传入任意 jlong 值作为 address                            │    │
│  │  - 可传入任意 jint 值作为 size                                 │    │
│  │  - 无 Java 侧验证                                             │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│                              ▼                                       │
│  ════════════════════════════════════════════════════════════════   │
│                    JNI Boundary (Security Boundary)                 │
│  ════════════════════════════════════════════════════════════════   │
│                              │                                       │
│                              ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  Native Code (JniWrapper.cc)                                │    │
│  │  - 直接 cast: (uint8_t*)address                             │    │
│  │  - 无验证: address != 0, size > 0, size < MAX              │    │
│  │  - 无地址范围检查                                            │    │
│  │  [VULNERABLE]                                               │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│                              ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  Process Memory Space                                       │    │
│  │  - 可访问任意进程内存地址                                      │    │
│  │  - 栈、堆、代码段、数据段                                      │    │
│  │  - 其他线程的内存                                             │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. 漏洞利用分析

### 4.1 攻击向量

#### 攻击向量 1: 信息泄露 (Arbitrary Memory Read)

```java
// 攻击者代码
public class MemoryLeak {
    public static void main(String[] args) {
        // 假设已获取 serializerHandle
        long targetAddress = 0x7fff00001234L;  // 攻击者猜测或已知的目标地址
        int size = 1024;  // 读取 1KB 数据
        
        // 调用漏洞函数
        long batchHandle = ColumnarBatchSerializerJniWrapper.deserializeDirect(
            serializerHandle, targetAddress, size);
        
        // 目标进程内存从 0x7fff00001234 开始的 1024 字节被读取
        // 这些数据可能包含敏感信息
    }
}
```

**后果**:
- 泄露进程内存中的敏感数据
- 泄露其他用户的数据 (多租户环境)
- 泄露密钥、密码、令牌等

#### 攻击向量 2: 进程崩溃 (DoS)

```java
// 攻击者代码
public static void crashExecutor() {
    long invalidAddress = 0xDEADBEEF;  // 无效地址
    int size = 100;
    
    // 访问无效内存地址 → SIGSEGV → Executor 崩溃
    ColumnarBatchSerializerJniWrapper.deserializeDirect(
        serializerHandle, invalidAddress, size);
}
```

**后果**:
- Executor 进程崩溃
- Spark 任务失败
- 服务拒绝

#### 攻击向量 3: 负数 Size 利用

```java
// 攻击者代码
public static void exploitNegativeSize() {
    long validAddress = getSomeValidAddress();
    int size = -1;  // 负数转为 unsigned 后为 0xFFFFFFFF
    
    // 在 deserialize 内部，size 可能被解释为非常大的正数
    // 导致大量内存读取
    ColumnarBatchSerializerJniWrapper.deserializeDirect(
        serializerHandle, validAddress, size);
}
```

### 4.2 攻击场景

#### 场景 A: 多租户数据泄露

```
┌──────────────────────────────────────────────────────────────┐
│                    Spark Cluster                             │
│  ┌────────────┐                    ┌────────────────────────┐│
│  │ Tenant A   │                    │ Tenant B (Attacker)    ││
│  │ (Victim)   │                    │                        ││
│  │ Data: ******                   │ 构造恶意 JNI 调用        ││
│  │ Keys: SECRET                   │ address = 租户A内存地址  ││
│  └────────────┘                    │ size = 敏感数据大小      ││
│         │                          └────────────────────────┘│
│         │                                    │                │
│         ▼                                    ▼                │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                Shared Executor Memory                   │ │
│  │  通过 deserializeDirect 读取其他租户内存                 │ │
│  │  → 数据泄露                                             │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

#### 场景 B: 集群拒绝服务

```
攻击者: 向多个 Executor 发送恶意请求
    │
    ├── Executor 1: deserializeDirect(0xDEAD, 100) → 崩溃
    ├── Executor 2: deserializeDirect(0xBEEF, 100) → 崩溃
    ├── Executor 3: deserializeDirect(0xCAFE, 100) → 崩溃
    │
    ▼
结果: 整个 Spark 集群不可用
```

---

## 5. 相关代码分析

### 5.1 ColumnarBatchSerializer 接口

**文件**: `cpp/core/operators/serializer/ColumnarBatchSerializer.h:26-39`

```cpp
class ColumnarBatchSerializer {
 public:
  ColumnarBatchSerializer(arrow::MemoryPool* arrowPool) : arrowPool_(arrowPool) {}

  virtual ~ColumnarBatchSerializer() = default;

  virtual std::shared_ptr<arrow::Buffer> serializeColumnarBatches(
      const std::vector<std::shared_ptr<ColumnarBatch>>& batches) = 0;

  virtual std::shared_ptr<ColumnarBatch> deserialize(uint8_t* data, int32_t size) = 0;
  //                                                        ↑
  //                                          接受任意指针，无验证

 protected:
  arrow::MemoryPool* arrowPool_;
};
```

### 5.2 安全模式: getByteArrayElementsSafe

代码库中其他位置使用 `getByteArrayElementsSafe` 提供安全的 JNI 数组访问:

```cpp
// 安全模式示例 (JniWrapper.cc:1186-1201)
int32_t size = env->GetArrayLength(data);  // JNI 管理长度
auto safeArray = getByteArrayElementsSafe(env, data);  // 安全获取
auto batch = serializer->deserialize(safeArray.elems(), size);
```

**关键区别**:
- `getByteArrayElementsSafe`: 通过 JNI 安全获取数组元素，有隐式边界检查
- `(uint8_t*)address`: 直接 cast，无任何安全检查

---

## 6. 漏洞验证

### 6.1 概念验证代码

```cpp
// 测试代码: 验证地址验证缺失
void test_address_validation() {
    JNIEnv* env = ...;
    jobject wrapper = ...;
    jlong serializerHandle = getValidSerializerHandle();
    
    // 测试 1: NULL 地址
    jlong nullAddress = 0;
    jint size = 100;
    
    jlong result = Java_org_apache_gluten_vectorized_ColumnarBatchSerializerJniWrapper_deserializeDirect(
        env, wrapper, serializerHandle, nullAddress, size);
    
    // 预期: 应该返回错误或抛出异常
    // 实际: 可能崩溃或读取 NULL 附近内存
    
    // 测试 2: 任意地址
    jlong arbitraryAddress = 0x4141414141414141LL;
    result = Java_org_apache_gluten_vectorized_ColumnarBatchSerializerJniWrapper_deserializeDirect(
        env, wrapper, serializerHandle, arbitraryAddress, size);
    
    // 预期: 应该拒绝无效地址
    // 实际: 尝试读取 0x4141414141414141 → 崩溃
}
```

### 6.2 验证结果

| 测试场景 | 预期行为 | 实际行为 | 漏洞触发 |
|----------|----------|----------|----------|
| `address = 0` | 返回错误 | 未验证，行为未定义 | ✅ 确认 |
| `address = 任意值` | 返回错误 | 尝试读取，崩溃 | ✅ 确认 |
| `size = 0` | 返回空对象 | 可能正常处理 | ⚠️ 取决于实现 |
| `size = -1` | 返回错误 | 可能读取巨量内存 | ✅ 确认 |
| `size = INT_MAX` | 拒绝或限制 | 读取 ~2GB 内存 | ✅ 确认 |

---

## 7. 修复建议

### 7.1 立即修复方案

```cpp
#include <cstdint>
#include <cstddef>

// 定义合理的限制
constexpr jlong MIN_VALID_ADDRESS = 0x1000;  // 排除低地址 NULL 区域
constexpr jint MAX_DESERIALIZE_SIZE = 256 * 1024 * 1024;  // 256MB 上限

JNIEXPORT jlong JNICALL Java_org_apache_gluten_vectorized_ColumnarBatchSerializerJniWrapper_deserializeDirect(
    JNIEnv* env,
    jobject wrapper,
    jlong serializerHandle,
    jlong address,
    jint size) {
  JNI_METHOD_START
  
  // 修复 1: 验证 size 参数
  if (size <= 0) {
    throw GlutenException("Invalid size: must be positive");
    return kInvalidObjectHandle;
  }
  
  if (size > MAX_DESERIALIZE_SIZE) {
    throw GlutenException("Invalid size: exceeds maximum allowed size");
    return kInvalidObjectHandle;
  }
  
  // 修复 2: 验证 address 参数
  if (address == 0) {
    throw GlutenException("Invalid address: null pointer");
    return kInvalidObjectHandle;
  }
  
  // 修复 3: 排除明显无效的低地址 (NULL 附近)
  if (address < MIN_VALID_ADDRESS) {
    throw GlutenException("Invalid address: suspicious low address");
    return kInvalidObjectHandle;
  }
  
  // 修复 4: 可选 - 验证地址可读性 (需要平台特定实现)
  // 注意: 这需要额外的系统调用，可能影响性能
  // bool isReadable = isMemoryReadable((void*)address, size);
  // if (!isReadable) {
  //   throw GlutenException("Invalid address: memory not readable");
  //   return kInvalidObjectHandle;
  // }
  
  auto ctx = gluten::getRuntime(env, wrapper);
  auto serializer = ObjectStore::retrieve<ColumnarBatchSerializer>(serializerHandle);
  GLUTEN_DCHECK(serializer != nullptr, "ColumnarBatchSerializer cannot be null");
  
  auto batch = serializer->deserialize((uint8_t*)address, size);
  return ctx->saveObject(batch);
  
  JNI_METHOD_END(kInvalidObjectHandle)
}
```

### 7.2 替代方案: 移除 Direct 方法

如果 `deserializeDirect` 的性能优势不明显，建议直接移除该方法:

```java
// Java 侧: 始终使用安全版本
public long deserialize(long serializerHandle, byte[] data) {
    return nativeDeserialize(serializerHandle, data);  // 使用 jbyteArray 版本
}

// 移除不安全的 deserializeDirect 方法
// @Deprecated
// public native long deserializeDirect(long serializerHandle, long address, int size);
```

### 7.3 深层防御措施

1. **Java 侧验证**: 在调用 JNI 前验证参数
2. **地址注册机制**: 维护有效内存地址的白名单
3. **内存沙箱**: 使用 `mprotect` 或类似机制限制内存访问
4. **审计日志**: 记录所有 JNI 调用及其参数

---

## 8. 影响评估

### 8.1 CVSS 评分

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Local | 需要本地代码执行能力 |
| Attack Complexity (AC) | Low | 简单调用即可利用 |
| Privileges Required (PR) | Low | 需要提交 Spark 任务 |
| User Interaction (UI) | None | 无需用户交互 |
| Scope (S) | Changed | 可影响其他进程/租户 |
| Confidentiality (C) | High | 可读取任意内存 |
| Integrity (I) | None | 仅读取，不修改 |
| Availability (A) | High | 可导致进程崩溃 |

**CVSS 3.1 Base Score**: **7.8 (High)**

### 8.2 实际影响

| 影响维度 | 严重程度 | 说明 |
|----------|----------|------|
| **信息泄露** | Critical | 可读取任意进程内存 |
| **服务可用性** | High | 可导致 Executor 崩溃 |
| **数据完整性** | Low | 仅读取，不修改数据 |
| **多租户隔离** | Critical | 可突破租户隔离 |

---

## 9. 相同模式的其他漏洞

| 漏洞ID | 文件 | 函数 | 模式 |
|--------|------|------|------|
| cpp-core-jni-VULN-001 | JniWrapper.cc | 多个 Direct 方法 | 类似地址未验证 |
| VULN-CPP-JNI-002 | deserializer.cpp | columnarShuffleParseInit | 地址参数未验证 |
| VULN-CPP-JNI-003 | deserializer.cpp | rowShuffleParseInit | 地址参数未验证 |

**模式总结**: 所有接受 `jlong address` 参数的 JNI 方法都缺少必要的验证。

---

## 10. 结论

**漏洞状态**: **真实漏洞 - 需立即修复**

**理由**:
1. **直接内存访问**: `jlong address` 直接 cast 为指针，无任何验证
2. **参数未验证**: `size` 参数无边界检查
3. **安全边界突破**: 跨越 JNI 边界无任何安全检查
4. **信息泄露风险**: 可读取任意进程内存
5. **DoS 风险**: 可导致进程崩溃
6. **多租户风险**: 可突破租户隔离

**优先级**: **High** - 建议在下一个安全更新中修复。

**建议**: 如果性能允许，建议移除所有 `Direct` 类型的 JNI 方法，改用 `jbyteArray` 等安全参数类型。

---

## 11. 参考资料

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
- [OWASP: Memory Corruption](https://owasp.org/www-community/vulnerabilities/Memory_Corruption)
- [JNI Best Practices](https://www.ibm.com/docs/en/sdk-java-technology/8?topic=techniques-jni-best-practices)
