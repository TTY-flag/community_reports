# 漏洞扫描报告 — 已确认漏洞

**项目**: OmniOperator
**扫描时间**: 2026-04-19T12:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次漏洞扫描针对 OmniOperator 大数据引擎加速库进行了全面的安全分析。扫描范围涵盖 596 个 C/C++ 文件和 4 个 Python 文件，共发现 **15 个已确认漏洞**（CONFIRMED 状态），其中 **4 个 Critical 级别**、**11 个 High 级别**漏洞。

**核心风险**: 本次扫描发现的最严重问题是 **UDF（用户定义函数）执行路径存在完整的任意代码执行攻击链**。攻击者可以通过 SQL 查询中的 UDF 函数调用，绕过所有安全检查，执行任意 Java 代码。具体表现为：

1. **信任边界违规**: C++ 层接收来自 SQL 查询的 UDF 类名参数，直接通过 JNI 传递给 Java 层，无任何白名单验证或格式校验
2. **安全控制绕过**: DLLEXPORT 导出函数 `EvaluateHiveUdfSingle` 可被外部直接调用，完全绕过配置文件中的白名单机制
3. **静态初始化器攻击**: Java 层使用 `Class.forName(udfClassName, true, loader)` 加载类时，类的静态初始化器在 UDF 接口检查之前执行，攻击者可借此执行任意代码

**业务影响**: 该漏洞可能导致：
- 数据泄露：攻击者可读取任意文件或数据库内容
- 系统被控：攻击者可在服务器上执行任意命令
- 横向渗透：通过 JVM 进程权限访问其他系统组件

**建议优先修复方向**: 
1. 在 UDF 类名传递前添加白名单验证机制
2. 移除或限制 DLLEXPORT 函数的外部访问
3. 在 Java 层使用 `Class.forName(className, false, loader)` 延迟初始化，先检查 UDF 接口后再初始化

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 41 | 40.6% |
| LIKELY | 29 | 28.7% |
| CONFIRMED | 16 | 15.8% |
| FALSE_POSITIVE | 15 | 14.9% |
| **总计** | **101** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 4 | 26.7% |
| High | 11 | 73.3% |
| **有效漏洞总计** | **15** | - |
| 误报 (FALSE_POSITIVE) | 15 | - |

### 1.3 Top 10 关键漏洞

1. **[udf-001]** trust_boundary_violation (Critical) - `core/src/udf/cplusplus/java_udf_functions.cpp:42` @ `ExecuteHiveUdfSingle` | 置信度: 95
2. **[VULN-SEC-UDF-001]** arbitrary_code_execution (Critical) - `core/src/udf/cplusplus/java_udf_functions.cpp:42` @ `ExecuteHiveUdfSingle` | 置信度: 95
3. **[VULN-SEC-UDF-004]** bypass_security_control (Critical) - `core/src/codegen/functions/udffunctions.cpp:29` @ `EvaluateHiveUdfSingle/EvaluateHiveUdfBatch` | 置信度: 95
4. **[VULN-XMOD-001]** arbitrary_code_execution_udf_chain (Critical) - `core/src/udf/cplusplus/java_udf_functions.cpp:42` @ `ExecuteHiveUdfSingle` | 置信度: 85
5. **[VULN-TYPE-010]** Improper Exception Handling (High) - `bindings/java/src/main/cpp/src/jni_operator_factory.cpp:137` @ `GetDataTypesVector` | 置信度: 95
6. **[VULN-TYPE-005]** NULL Pointer Dereference (High) - `core/src/type/data_type_serializer.cpp:84` @ `DataTypeJsonParser` | 置信度: 90
7. **[udf-002]** env_var_injection (High) - `core/src/udf/cplusplus/jni_util.cpp:144` @ `CreateJavaVM` | 置信度: 90
8. **[JNI-001]** Null Pointer Dereference (High) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator.cpp:159` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative` | 置信度: 85
9. **[JNI-005]** Null Pointer Dereference (High) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator.cpp:178` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative` | 置信度: 85
10. **[JNI-006]** Stack Buffer Overflow (High) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator_factory.cpp:288` @ `Java_nova_hetu_omniruntime_operator_sort_OmniSortOperatorFactory_createSortOperatorFactory` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative@bindings/java/src/main/cpp/src/jni_operator.cpp` | jni | semi_trusted | JNI 接口，由 Spark/Hive Java 适配层调用，传入 VectorBatch 数据地址。调用方是与 C++ 在同一进程的 JVM，非远程网络调用。 | 接收来自 Java 端的输入数据向量批次 |
| `Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative@bindings/java/src/main/cpp/src/jni_operator.cpp` | jni | semi_trusted | JNI 接口，返回处理结果到 Java 端。调用方是与 C++ 在同一进程的 JVM。 | 返回处理结果到 Java 端 |
| `Java_nova_hetu_omniruntime_operator_OmniOperatorFactory_createOperatorNative@bindings/java/src/main/cpp/src/jni_operator_factory.cpp` | jni | semi_trusted | JNI 接口，创建算子实例。调用方是与 C++ 在同一进程的 JVM。 | 创建算子实例 |
| `Java_nova_hetu_omniruntime_operator_filter_OmniFilterAndProjectOperatorFactory_createFilterAndProjectOperatorFactory@bindings/java/src/main/cpp/src/jni_operator_factory.cpp` | jni | semi_trusted | JNI 接口，接收 JSON 格式的表达式字符串进行解析。表达式来自 SQL 查询解析结果，可能包含用户输入的表达式。 | 创建过滤和投影算子，解析 JSON 表达式 |
| `JSONParser::ParseJSON@core/src/expression/jsonparser/jsonparser.h` | decorator | semi_trusted | 解析从 Java 端传入的 JSON 格式表达式。表达式来自 Spark/Hive SQL 解析器，包含用户 SQL 查询中的表达式。 | 解析 JSON 格式的表达式 |
| `Deserialize@core/src/type/data_type_serializer.cpp` | decorator | semi_trusted | 反序列化从 Java 端传入的数据类型 JSON 字符串。数据类型描述来自 Spark/Hive 的查询计划。 | 反序列化数据类型 JSON |
| `ExecuteHiveUdfSingle@core/src/udf/cplusplus/java_udf_functions.cpp` | jni | untrusted_local | 执行用户定义的 Hive UDF 函数，UDF 类名来自配置或用户输入。用户可以通过 SQL 查询指定自定义 UDF。 | 执行用户定义的 Hive UDF 函数 |
| `GetOmniHome@core/src/util/config_util.cpp` | env | trusted_admin | 读取 OMNI_HOME 环境变量，由部署人员/管理员在启动脚本中设置。非用户可控。 | 读取 OMNI_HOME 环境变量 |
| `GetConfigFilePath@core/src/util/config_util.cpp` | env | trusted_admin | 读取 OMNI_CONF 环境变量，由部署人员/管理员在启动脚本中设置。配置文件由管理员控制。 | 读取 OMNI_CONF 环境变量 |
| `SpillWriter::WriteVecBatch@core/src/operator/spill/spiller.cpp` | file | trusted_admin | Spill 文件路径由配置目录决定，目录由管理员控制。文件名由进程 ID 和线程 ID 生成。 | 写入 Spill 临时文件 |
| `CreateJavaVM@core/src/udf/cplusplus/jni_util.cpp` | env | trusted_admin | 读取 OMNI_OPERATOR_CLASSPATH 环境变量设置 JVM classpath。由部署人员/管理员在启动脚本中设置。 | 创建 JVM 时读取 classpath 环境变量 |
| `Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_parseOneRow@bindings/java/src/main/cpp/src/jni_operator.cpp` | jni | semi_trusted | JNI 接口，解析单行数据。数据来自 Shuffle 传输的序列化行数据，可能来自其他节点。 | 解析序列化的单行数据 |
| `LLVMEngine::LLVMEngine@core/src/codegen/llvm_engine.cpp` | decorator | internal | LLVM JIT 引擎初始化，用于代码生成。表达式来自内部解析结果，非直接用户输入。 | 初始化 LLVM JIT 代码生成引擎 |

**其他攻击面**:
- JNI 接口层: 数据从 Java JVM 传入 C++ Native 层
- JSON 表达式解析: 解析 SQL 表达式字符串
- 数据类型反序列化: 解析 JSON 格式数据类型描述
- UDF 执行: 调用用户定义的 Java/Hive UDF 函数
- Spill 文件操作: 内存溢出数据的临时文件读写
- 环境变量读取: OMNI_HOME, OMNI_CONF, OMNI_OPERATOR_CLASSPATH

---

## 3. Critical 漏洞 (4)

### [udf-001] trust_boundary_violation - ExecuteHiveUdfSingle

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `core/src/udf/cplusplus/java_udf_functions.cpp:42-73` @ `ExecuteHiveUdfSingle`
**模块**: udf

**描述**: ExecuteHiveUdfSingle/ExecuteHiveUdfBatch receives udfClass parameter from user SQL query via codegen module, passes it directly to JNI without any validation. The Java side uses Class.forName(udfClassName) to load arbitrary classes. No whitelist/blacklist, no format validation. Attack vector: User can execute arbitrary Java code through SQL UDF function calls.

**达成路径**

SQL Query -> codegen/udffunctions.cpp:EvaluateHiveUdfSingle -> java_udf_functions.cpp:ExecuteHiveUdfSingle -> JNI CallStaticVoidMethod -> Java HiveUdfExecutor.java:Class.forName(udfClassName)

**验证说明**: VERIFIED: Complete data flow confirmed. SQL Query → jsonparser.cpp → FuncExpr.funcName → expression_codegen.cpp → EvaluateHiveUdfSingle(DLLEXPORT) → ExecuteHiveUdfSingle → JNI → Class.forName(). No validation. Static initializer executes before UDF check.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: _ | 5: s | 6: c | 7: o | 8: r | 9: e | 10: = | 11: 3 | 12: 0 | 13:   | 14: + | 15:   | 16: r | 17: e | 18: a | 19: c | 20: h | 21: a | 22: b | 23: i | 24: l | 25: i | 26: t | 27: y | 28: _ | 29: d | 30: i | 31: r | 32: e | 33: c | 34: t | 35: _ | 36: e | 37: x | 38: t | 39: e | 40: r | 41: n | 42: a | 43: l | 44: = | 45: 3 | 46: 0 | 47:   | 48: + | 49:   | 50: c | 51: o | 52: n | 53: t | 54: r | 55: o | 56: l | 57: l | 58: a | 59: b | 60: i | 61: l | 62: i | 63: t | 64: y | 65: _ | 66: f | 67: u | 68: l | 69: l | 70: = | 71: 2 | 72: 5 | 73:   | 74: + | 75:   | 76: c | 77: r | 78: o | 79: s | 80: s | 81: _ | 82: m | 83: o | 84: d | 85: u | 86: l | 87: e | 88: = | 89: 1 | 90: 0 | 91:   | 92: = | 93:   | 94: 9 | 95: 5

**深度分析**

**根因分析**: 漏洞根源于 `ExecuteHiveUdfSingle` 函数（`java_udf_functions.cpp:42-73`）对 `udfClass` 参数的完全信任。该函数接收来自上游调用者的 UDF 类名，在第 55 行直接调用 `env->NewStringUTF(udfClass)` 创建 JNI 字符串对象，然后在第 66 行通过 `CallStaticVoidMethod` 传递给 Java 端。整个传递链中没有对 `udfClass` 进行任何验证。

**源代码位置** (`core/src/udf/cplusplus/java_udf_functions.cpp:55-66`):
```c
jstring jUdfClassName = env->NewStringUTF(udfClass);  // 无验证，直接使用
if (jUdfClassName == nullptr) {
    SetError(contextPtr, JVM_OOM);
    return;
}
...
env->CallStaticVoidMethod(executorCls, executeSingleMethod, jUdfClassName, jParamTypes, jRetType, ...);
```

**潜在利用场景**: 
1. **SQL 注入式攻击**: 用户在 SQL 查询中指定恶意 UDF 类名，如 `SELECT malicious_udf_func(column) FROM table`
2. **静态初始化器执行**: Java 端 `HiveUdfExecutor.java:169` 调用 `Class.forName(udfClassName, true, loader)` 时，类的静态初始化器会先执行，攻击者可在初始化器中执行任意代码
3. **绕过白名单机制**: 攻击者可通过构造特殊类名或直接调用 DLLEXPORT 函数绕过配置文件白名单

**建议修复方式**:
1. 在 `ExecuteHiveUdfSingle` 入口处添加类名格式验证（只允许合法的 Java 类名格式 `[a-zA-Z_][a-zA-Z0-9_.]*`）
2. 实现白名单机制：在传递给 JNI 之前，验证类名是否在配置文件的白名单中
3. 在 Java 端使用 `Class.forName(className, false, loader)` 延迟初始化，先检查 UDF 接口后再初始化

---

### [VULN-SEC-UDF-001] arbitrary_code_execution - ExecuteHiveUdfSingle

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-470 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `core/src/udf/cplusplus/java_udf_functions.cpp:42-73` @ `ExecuteHiveUdfSingle`
**模块**: udf
**跨模块**: util → codegen → udf

**描述**: UDF类名参数未验证，允许任意Java类执行。ExecuteHiveUdfSingle/ExecuteHiveUdfBatch函数直接接收udfClass参数并通过JNI传递给Java端，无任何白名单验证或格式校验。若配置文件被篡改或DLLEXPORT函数被直接调用，攻击者可执行任意Java代码。

**漏洞代码** (`core/src/udf/cplusplus/java_udf_functions.cpp:42-73`)

```c
void ExecuteHiveUdfSingle(int64_t contextPtr, const char *udfClass, ...) {
    ...
    jstring jUdfClassName = env->NewStringUTF(udfClass);  // 无验证
    ...
    env->CallStaticVoidMethod(executorCls, executeSingleMethod, jUdfClassName, ...);
}
```

**达成路径**

1. config_util.cpp: getenv(OMNI_HOME/OMNI_CONF) → 配置文件路径
2. config_util.cpp: hiveUdfPropertyFilePath → UDF属性文件路径
3. func_registry_hive_udf.cpp: GenerateHiveUdfMap() → 解析UDF类名
4. udffunctions.cpp:29 EvaluateHiveUdfSingle() [DLLEXPORT入口] → 接收udfClass
5. java_udf_functions.cpp:42 ExecuteHiveUdfSingle() → 无验证传递udfClass
6. JNI → HiveUdfExecutor.executeSingle() → 执行任意类

**验证说明**: VERIFIED CRITICAL: Complete attack chain confirmed. SQL Query user input → jsonparser.cpp ParseJSON → FuncExpr.funcName (udfClass name) → expression_codegen.cpp:979 CreateConstantString(fExpr.funcName) → udffunctions.cpp:29 EvaluateHiveUdfSingle [DLLEXPORT] → java_udf_functions.cpp:55 NewStringUTF(udfClass) → JNI CallStaticVoidMethod → HiveUdfExecutor.java:169 Class.forName(udfClassName, true, loader). NO validation of class name format. NO whitelist of allowed classes. Static initializer executes BEFORE UDF interface check. Direct external attacker control.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: _ | 23: d | 24: i | 25: r | 26: e | 27: c | 28: t | 29: _ | 30: e | 31: x | 32: t | 33: e | 34: r | 35: n | 36: a | 37: l | 38: = | 39: 3 | 40: 0 | 41:   | 42: + | 43:   | 44: c | 45: o | 46: n | 47: t | 48: r | 49: o | 50: l | 51: l | 52: a | 53: b | 54: i | 55: l | 56: i | 57: t | 58: y | 59: _ | 60: f | 61: u | 62: l | 63: l | 64: = | 65: 2 | 66: 5 | 67:   | 68: + | 69:   | 70: c | 71: r | 72: o | 73: s | 74: s | 75: _ | 76: m | 77: o | 78: d | 79: u | 80: l | 81: e | 82: = | 83: 1 | 84: 0 | 85:   | 86: = | 87:   | 88: 9 | 89: 5

**深度分析**

**根因分析**: 此漏洞是 udf-001 的完整跨模块追踪。攻击链从 util 模块的配置文件路径开始，经过 codegen 模块的表达式解析，最终到达 udf 模块的 JNI 调用。关键节点是 `udffunctions.cpp:29` 的 `EvaluateHiveUdfSingle` 函数，它作为 DLLEXPORT 导出函数，可被外部代码直接调用，完全绕过 `func_registry_hive_udf.cpp` 中实现的属性文件白名单机制。

**源代码位置** (`core/src/codegen/functions/udffunctions.cpp:29-39`):
```c
extern DLLEXPORT void EvaluateHiveUdfSingle(int64_t contextPtr, const char *udfClass, int32_t *inputTypes,
    int32_t retType, int32_t vecCount, ...) {
    std::call_once(init_udf_flag, InitHiveUdf);
    if (!g_isUdfInited) {
        SetError(contextPtr, INIT_UDF_FAILED);
        return;
    }
    ExecuteHiveUdfSingle(contextPtr, udfClass, inputTypes, retType, vecCount, ...);  // 直接传递，无验证
}
```

**潜在利用场景**:
1. **直接调用 DLLEXPORT 函数**: 外部恶意代码可通过动态链接库接口直接调用 `EvaluateHiveUdfSingle`，传入任意类名
2. **绕过所有安全检查**: 即使配置文件中设置了 UDF 白名单，此路径完全绕过该检查
3. **恶意类加载**: Java 端 `HiveUdfExecutor.java:169` 使用 `Class.forName(udfClassName, true, loader)` 加载类时，静态初始化器立即执行

**建议修复方式**:
1. 移除 DLLEXPORT 声明或将其改为内部调用接口
2. 在 `EvaluateHiveUdfSingle` 函数中添加白名单验证，检查 `udfClass` 是否在允许的类名列表中
3. 实现调用者身份验证，确保只有可信的内部模块可以调用此函数

---

### [VULN-SEC-UDF-004] bypass_security_control - EvaluateHiveUdfSingle/EvaluateHiveUdfBatch

**严重性**: Critical（原评估: High → 验证后: Critical） | **CWE**: CWE-693 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `core/src/codegen/functions/udffunctions.cpp:29-53` @ `EvaluateHiveUdfSingle/EvaluateHiveUdfBatch`
**模块**: udf
**跨模块**: codegen → udf

**描述**: DLLEXPORT导出函数EvaluateHiveUdfSingle/EvaluateHiveUdfBatch直接接收udfClass参数，无验证。攻击者可绕过属性文件白名单机制，直接调用导出函数执行任意Java类。

**漏洞代码** (`core/src/codegen/functions/udffunctions.cpp:29-53`)

```c
extern DLLEXPORT void EvaluateHiveUdfSingle(int64_t contextPtr, const char *udfClass, ...) {
    std::call_once(init_udf_flag, InitHiveUdf);
    ...
    ExecuteHiveUdfSingle(contextPtr, udfClass, ...);  // 无验证直接传递
}
```

**达成路径**

1. 外部调用者 → 直接传入udfClass参数
2. udffunctions.cpp:29 EvaluateHiveUdfSingle() [DLLEXPORT入口]
3. udffunctions.cpp:38 ExecuteHiveUdfSingle() → 绕过属性文件
4. java_udf_functions.cpp → JNI执行任意类
注: func_registry_hive_udf.cpp的属性文件白名单机制被完全绕过

**验证说明**: VERIFIED CRITICAL: udffunctions.cpp:29 EvaluateHiveUdfSingle() and :42 EvaluateHiveUdfBatch() are DLLEXPORT functions accepting udfClass parameter WITHOUT validation. COMPLETELY BYPASSES property file whitelist in func_registry_hive_udf.cpp. Any external caller can invoke with arbitrary class names.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: _ | 23: d | 24: i | 25: r | 26: e | 27: c | 28: t | 29: _ | 30: e | 31: x | 32: t | 33: e | 34: r | 35: n | 36: a | 37: l | 38: = | 39: 3 | 40: 0 | 41:   | 42: + | 43:   | 44: c | 45: o | 46: n | 47: t | 48: r | 49: o | 50: l | 51: l | 52: a | 53: b | 54: i | 55: l | 56: i | 57: t | 58: y | 59: _ | 60: f | 61: u | 62: l | 63: l | 64: = | 65: 2 | 66: 5 | 67:   | 68: + | 69:   | 70: s | 71: e | 72: c | 73: u | 74: r | 75: i | 76: t | 77: y | 78: _ | 79: b | 80: y | 81: p | 82: a | 83: s | 84: s | 85: = | 86: 1 | 87: 0 | 88:   | 89: = | 90:   | 91: 9 | 92: 5

**深度分析**

**根因分析**: 此漏洞的核心问题是 DLLEXPORT 函数直接暴露了 UDF 执行入口点，完全绕过了 `func_registry_hive_udf.cpp` 中实现的属性文件白名单机制。`EvaluateHiveUdfSingle` 和 `EvaluateHiveUdfBatch` 函数使用 `extern DLLEXPORT` 声明，意味着它们被导出为动态链接库的公共符号，任何外部代码都可以直接调用这些函数。

**源代码位置** (`core/src/codegen/functions/udffunctions.cpp:29-42`):
```c
extern DLLEXPORT void EvaluateHiveUdfSingle(int64_t contextPtr, const char *udfClass, ...) {
    std::call_once(init_udf_flag, InitHiveUdf);
    if (!g_isUdfInited) {
        SetError(contextPtr, INIT_UDF_FAILED);
        return;
    }
    ExecuteHiveUdfSingle(contextPtr, udfClass, ...);  // 直接传递，完全绕过白名单
}

extern DLLEXPORT void EvaluateHiveUdfBatch(int64_t contextPtr, const char *udfClass, ...) {
    // 同样的问题
}
```

**潜在利用场景**:
1. **直接 DLL 调用**: 恶意代码加载 OmniOperator 动态库后，直接调用导出的函数
2. **绕过所有安全检查**: 即使 `func_registry_hive_udf.cpp` 中的属性文件白名单配置正确，此路径完全绕过该检查
3. **Java 层攻击**: 通过 JNI 调用后，Java 端 `Class.forName(udfClassName, true, loader)` 加载任意类

**建议修复方式**:
1. 移除 `DLLEXPORT` 声明，将函数改为内部调用
2. 或在函数内部添加白名单验证逻辑，检查 `udfClass` 是否在配置文件的白名单中
3. 实现调用者上下文验证，只允许来自可信 SQL 解析路径的调用

---

### [VULN-XMOD-001] arbitrary_code_execution_udf_chain - ExecuteHiveUdfSingle

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `core/src/udf/cplusplus/java_udf_functions.cpp:42-73` @ `ExecuteHiveUdfSingle`
**模块**: cross_module
**跨模块**: util → codegen → udf → jni_bindings

**描述**: 完整的跨模块攻击路径：(1) util模块的hiveUdfPropertyFilePath配置可被环境变量控制；(2) codegen模块的CallHiveUdfFunction将funcName传递到udf模块；(3) udf模块的ExecuteHiveUdfSingle直接通过JNI调用Java Class.forName加载任意类；(4) 无白名单/黑名单验证，无类格式检查；(5) EvaluateHiveUdfSingle为DLLEXPORT导出函数，可被外部直接调用绕过配置白名单。攻击者可通过SQL UDF函数执行任意Java代码。

**达成路径**

SQL查询 → codegen/udffunctions.cpp:EvaluateHiveUdfSingle → udf/java_udf_functions.cpp:ExecuteHiveUdfSingle → JNI → Java Class.forName(udfClassName) → 任意Java代码执行

**验证说明**: VERIFIED: Complete cross-module attack chain confirmed. (1) EvaluateHiveUdfSingle is DLLEXPORT externally accessible (codegen/functions/udffunctions.cpp:29). (2) Directly calls ExecuteHiveUdfSingle without validation (udf/java_udf_functions.cpp:42). (3) udfClass parameter passed to JNI without any whitelist/blacklist check (line 55: env->NewStringUTF(udfClass)). (4) Java Class.forName loads arbitrary class. Chain: util->codegen->udf->jni_bindings. Reachability: untrusted_local(+30). Cross-file: chain_complete(0). Score: 30+30+25(critical_bonus)=85.

**深度分析**

**根因分析**: 此漏洞展示了完整的跨模块攻击链，从 SQL 查询输入到任意代码执行。关键路径：
- **util 模块**: `hiveUdfPropertyFilePath` 配置路径可被环境变量 OMNI_HOME/OMNI_CONF 控制
- **codegen 模块**: `expression_codegen.cpp` 将 SQL 表达式中的函数名 `fExpr.funcName` 作为 UDF 类名传递
- **udf 模块**: `ExecuteHiveUdfSingle` 无验证地通过 JNI 调用 Java 端
- **Java 层**: `HiveUdfExecutor.java:169` 使用 `Class.forName(udfClassName, true, loader)` 加载并初始化类

**Java 端关键代码** (`HiveUdfExecutor.java:169-170`):
```java
Class<?> udfClass = Class.forName(udfClassName, true, loader);  // 第二个参数 true 导致立即初始化
if (UDF.class.isAssignableFrom(udfClass)) {  // 检查在初始化之后，太晚了！
    // ...
}
```

**潜在利用场景**:
1. **静态初始化器攻击**: 恶意类的静态初始化器在 `UDF.class.isAssignableFrom` 检查之前执行，可执行任意代码
2. **恶意 UDF 类示例**:
```java
public class MaliciousUdf extends UDF {
    static {  // 静态初始化器在类加载时立即执行
        Runtime.getRuntime().exec("rm -rf /tmp/data");
    }
    public String evaluate(String input) { return input; }
}
```

**建议修复方式**:
1. 在 Java 端使用 `Class.forName(udfClassName, false, loader)` 延迟初始化
2. 先检查类是否继承 `UDF` 接口，再调用 `newInstance()` 进行初始化
3. 在 C++ 层实现完整的白名单机制，验证所有传递的类名

---

## 4. High 漏洞 (11)

### [VULN-TYPE-010] Improper Exception Handling - GetDataTypesVector

**严重性**: High | **CWE**: CWE-248 | **置信度**: 95/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `bindings/java/src/main/cpp/src/jni_operator_factory.cpp:137` @ `GetDataTypesVector`
**模块**: type
**跨模块**: jni_bindings,type

**描述**: JNI绑定层jni_operator_factory.cpp中调用Deserialize函数缺少try-catch异常处理。当Deserialize抛出异常时，会导致JNI调用崩溃或未定义行为。

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator_factory.cpp:137`)

```c
auto dataTypes = Deserialize(sourceTypesCharPtr);
```

**达成路径**

[IN] Java传入JSON -> JNI层 -> Deserialize (无异常处理)

**验证说明**: JNI binding layer jni_operator_factory.cpp lacks try-catch for Deserialize calls. GetDataTypesVector (line 131-141) calls Deserialize without JNI_METHOD_START/END protection. Multiple other Deserialize calls (lines 195-197, 245-252) are also outside exception handling blocks. When nlohmann::json::parse throws exception, it propagates to JNI causing crash. Mitigation: PARTIAL - Some JNI functions use JNI_METHOD_START/END, but helper functions and some direct calls are unprotected.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: _ | 23: d | 24: i | 25: r | 26: e | 27: c | 28: t | 29: = | 30: 2 | 31: 5 | 32:   | 33: - | 34:   | 35: p | 36: a | 37: r | 38: t | 39: i | 40: a | 41: l | 42: _ | 43: m | 44: i | 45: t | 46: i | 47: g | 48: a | 49: t | 50: i | 51: o | 52: n | 53: = | 54: 1 | 55: 0 | 56:   | 57: + | 58:   | 59: c | 60: r | 61: o | 62: s | 63: s | 64: _ | 65: m | 66: o | 67: d | 68: u | 69: l | 70: e | 71: = | 72: 2 | 73: 0 | 74:   | 75: + | 76:   | 77: p | 78: r | 79: e | 80: _ | 81: v | 82: a | 83: l | 84: i | 85: d | 86: a | 87: t | 88: e | 89: d | 90: = | 91: 3 | 92: 0 | 93:   | 94: = | 95:   | 96: 9 | 97: 5

**深度分析**

**根因分析**: `GetDataTypesVector` 辅助函数（第 131-141 行）调用 `Deserialize` 解析 JSON 格式的数据类型描述，但该调用未被 `JNI_METHOD_START/END` 异常处理宏包裹。当 `nlohmann::json::parse` 遇到格式错误的 JSON 时会抛出异常，该异常会直接传播到 JNI 层，导致 JVM 崩溃或未定义行为。

**源代码位置** (`bindings/java/src/main/cpp/src/jni_operator_factory.cpp:131-141`):
```c
void GetDataTypesVector(JNIEnv *env, jobjectArray jSourceType, std::vector<DataTypes> &output) {
    auto len = static_cast<int32_t>(env->GetArrayLength(jSourceType));
    for (int i = 0; i < len; ++i) {
        auto str = static_cast<jstring>(env->GetObjectArrayElement(jSourceType, i));
        auto sourceTypesCharPtr = env->GetStringUTFChars(str, JNI_FALSE);
        auto dataTypes = Deserialize(sourceTypesCharPtr);  // 无 try-catch，异常会传播到 JNI
        env->ReleaseStringUTFChars(str, sourceTypesCharPtr);
        output.push_back(dataTypes);
    }
}
```

**潜在利用场景**:
1. **恶意 JSON 输入**: Java 端传入格式错误的 JSON 字符串，如 `"invalid json[[["`，触发 `nlohmann::json::parse` 异常
2. **拒绝服务攻击**: 异常导致 JNI 调用崩溃，整个 Spark/Hive 任务失败
3. **多次调用风险**: 同一文件中多处 `Deserialize` 调用（第 195-197、245-252、301、346-347 行等）同样缺少异常处理

**建议修复方式**:
1. 在所有 `Deserialize` 调用处添加 `try-catch` 块，捕获异常并设置 JNI 错误状态
2. 或使用 `JNI_METHOD_START/JNI_METHOD_END` 宏包裹整个辅助函数
3. 在调用 `Deserialize` 前验证 JSON 字符串格式的有效性

---

### [VULN-TYPE-005] NULL Pointer Dereference - DataTypeJsonParser

**严重性**: High | **CWE**: CWE-476 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `core/src/type/data_type_serializer.cpp:84-86` @ `DataTypeJsonParser`
**模块**: type
**跨模块**: type,operator

**描述**: DataTypeJsonParser的default分支返回nullptr而非抛出异常。当遇到未支持的dataTypeId时，返回的nullptr被push到vector中，后续使用可能导致空指针解引用崩溃。

**漏洞代码** (`core/src/type/data_type_serializer.cpp:84-86`)

```c
default: LogError("Not Supported Data Type : %d", dataTypeId); return nullptr;
```

**达成路径**

[IN] 恶意dataTypeId -> return nullptr -> types.push_back -> 后续空指针访问

**验证说明**: DataTypeJsonParser default branch (lines 84-87) returns nullptr for unsupported data type IDs. The nullptr is pushed into types vector at line 28 of Deserialize function. Downstream code in operator/aggregation modules may dereference this nullptr, causing crashes. Code verified: data_type_serializer.cpp:84-86. Cross-module impact confirmed.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: _ | 23: d | 24: i | 25: r | 26: e | 27: c | 28: t | 29: = | 30: 2 | 31: 5 | 32:   | 33: + | 34:   | 35: n | 36: o | 37: _ | 38: m | 39: i | 40: t | 41: i | 42: g | 43: a | 44: t | 45: i | 46: o | 47: n | 48: = | 49: 0 | 50:   | 51: + | 52:   | 53: c | 54: r | 55: o | 56: s | 57: s | 58: _ | 59: m | 60: o | 61: d | 62: u | 63: l | 64: e | 65: = | 66: 1 | 67: 0 | 68:   | 69: + | 70:   | 71: p | 72: r | 73: e | 74: _ | 75: v | 76: a | 77: l | 78: i | 79: d | 80: a | 81: t | 82: e | 83: d | 84: = | 85: 2 | 86: 5 | 87:   | 88: = | 89:   | 90: 9 | 91: 0

---

### [udf-002] env_var_injection - CreateJavaVM

**严重性**: High | **CWE**: CWE-78 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `core/src/udf/cplusplus/jni_util.cpp:144-149` @ `CreateJavaVM`
**模块**: udf

**描述**: CreateJavaVM reads OMNI_OPERATOR_CLASSPATH environment variable via getenv() and uses it directly as JVM option without validation. No sanitization of path format, no bounds check. Attacker controlling this environment variable can inject arbitrary JVM options, potentially leading to arbitrary code execution or path traversal.

**达成路径**

Environment Variable OMNI_OPERATOR_CLASSPATH -> getenv() -> JavaVMOption.optionString -> JNI_CreateJavaVM

**验证说明**: VERIFIED: jni_util.cpp:144 getenv(OMNI_OPERATOR_CLASSPATH) directly used as JVM option. No validation.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: _ | 5: s | 6: c | 7: o | 8: r | 9: e | 10: = | 11: 3 | 12: 0 | 13:   | 14: + | 15:   | 16: r | 17: e | 18: a | 19: c | 20: h | 21: a | 22: b | 23: i | 24: l | 25: i | 26: t | 27: y | 28: _ | 29: i | 30: n | 31: d | 32: i | 33: r | 34: e | 35: c | 36: t | 37: = | 38: 2 | 39: 0 | 40:   | 41: + | 42:   | 43: c | 44: o | 45: n | 46: t | 47: r | 48: o | 49: l | 50: l | 51: a | 52: b | 53: i | 54: l | 55: i | 56: t | 57: y | 58: _ | 59: f | 60: u | 61: l | 62: l | 63: = | 64: 2 | 65: 5 | 66:   | 67: + | 68:   | 69: e | 70: n | 71: v | 72: _ | 73: d | 74: e | 75: p | 76: e | 77: n | 78: d | 79: e | 80: n | 81: c | 82: y | 83: = | 84: 1 | 85: 5 | 86:   | 87: = | 88:   | 89: 9 | 90: 0

---

### [JNI-001] Null Pointer Dereference - Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-476 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator.cpp:159-170` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative`
**模块**: jni_bindings
**跨模块**: jni_bindings,operator

**描述**: JNI入口函数addInputNative直接将jlong转换为指针使用，未进行有效性验证。恶意Java代码可传入无效地址导致native侧空指针解引用或任意地址访问。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator.cpp:159-170`)

```c
auto *vecBatch = reinterpret_cast<VectorBatch *>(jVecBatchAddress);\nauto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddress);\nnativeOperator->SetInputVecBatch(vecBatch);
```

**达成路径**

[IN] jVecBatchAddress(jlong) -> reinterpret_cast -> vecBatch(VectorBatch*) -> Operator::AddInput

**验证说明**: Code analysis confirmed: lines 163-164 cast jlong directly to pointer without null check. Pointer immediately dereferenced in SetInputVecBatch/AddInput calls. Exception handling catches crashes but doesn't prevent invalid memory access.

**评分明细**: base_score: 30 | reachability: direct_external | reachability_score: 30 | controllability: full | controllability_score: 25 | mitigations_found: exception_handling | mitigation_score: 0 | final_score: 85 | rationale: JNI entry point directly casts jlong to pointer without null validation. JNI_METHOD_START provides exception handling but NO null check before dereference. Attacker in same JVM process can pass invalid address causing crash or memory corruption.

---

### [JNI-005] Null Pointer Dereference - Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-476 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator.cpp:178-198` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative`
**模块**: jni_bindings
**跨模块**: jni_bindings,operator

**描述**: getOutputNative函数获取nativeOperator指针后立即调用GetOutput，无空指针检查。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator.cpp:178-198`)

```c
auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddr);\nJNI_METHOD_START\nnativeOperator->GetOutput(&outputVecBatch);
```

**达成路径**

[IN] jOperatorAddr(jlong) -> reinterpret_cast -> nativeOperator->GetOutput

**验证说明**: Code analysis: line 187 casts jOperatorAddr to pointer, immediately calls GetOutput at line 190. No null validation before use.

**评分明细**: base_score: 30 | reachability: direct_external | reachability_score: 30 | controllability: full | controllability_score: 25 | mitigations_found: exception_handling | mitigation_score: 0 | final_score: 85 | rationale: Same pattern as JNI-001: direct jlong cast to Operator pointer without null check. GetOutput called immediately on potentially invalid pointer.

---

### [JNI-006] Stack Buffer Overflow - Java_nova_hetu_omniruntime_operator_sort_OmniSortOperatorFactory_createSortOperatorFactory

**严重性**: High | **CWE**: CWE-121 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator_factory.cpp:288-318` @ `Java_nova_hetu_omniruntime_operator_sort_OmniSortOperatorFactory_createSortOperatorFactory`
**模块**: jni_bindings

**描述**: createSortOperatorFactory使用多个变长数组(VLA)，数组大小来自JNI输入未验证上限。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator_factory.cpp:288-318`)

```c
auto sortColsCount = env->GetArrayLength(jSortCols);\nint32_t sortColsArr[sortColsCount];
```

**达成路径**

[IN] jSortCols(jobjectArray) -> GetArrayLength -> VLA sortColsArr

**验证说明**: CRITICAL: VLA array int32_t sortColsArr[sortColsCount] on stack. sortColsCount comes DIRECTLY from env->GetArrayLength(jSortCols) with NO upper bound validation. A malicious JNI caller (compromised Java adapter) can pass extremely large array causing stack overflow. Direct exploit path confirmed.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: ( | 23: d | 24: i | 25: r | 26: e | 27: c | 28: t | 29: _ | 30: e | 31: x | 32: t | 33: e | 34: r | 35: n | 36: a | 37: l | 38: , | 39: + | 40: 3 | 41: 0 | 42: ) | 43:   | 44: + | 45:   | 46: c | 47: o | 48: n | 49: t | 50: r | 51: o | 52: l | 53: l | 54: a | 55: b | 56: i | 57: l | 58: i | 59: t | 60: y | 61: ( | 62: f | 63: u | 64: l | 65: l | 66: , | 67: + | 68: 2 | 69: 5 | 70: ) | 71:   | 72: = | 73:   | 74: 8 | 75: 5 | 76: . | 77:   | 78: s | 79: o | 80: r | 81: t | 82: C | 83: o | 84: l | 85: s | 86: C | 87: o | 88: u | 89: n | 90: t | 91:   | 92: d | 93: i | 94: r | 95: e | 96: c | 97: t | 98: l | 99: y | 100:   | 101: f | 102: r | 103: o | 104: m | 105:   | 106: J | 107: N | 108: I | 109:   | 110: G | 111: e | 112: t | 113: A | 114: r | 115: r | 116: a | 117: y | 118: L | 119: e | 120: n | 121: g | 122: t | 123: h | 124:   | 125: w | 126: i | 127: t | 128: h | 129:   | 130: n | 131: o | 132:   | 133: v | 134: a | 135: l | 136: i | 137: d | 138: a | 139: t | 140: i | 141: o | 142: n | 143: .

---

### [udf-005] insecure_class_loading - executeSingle

**严重性**: High | **CWE**: CWE-94 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `core/src/udf/java/src/main/java/omniruntime/udf/HiveUdfExecutor.java:169-176` @ `executeSingle`
**模块**: udf
**跨模块**: codegen,udf

**描述**: HiveUdfExecutor.java loads UDF classes using Class.forName(udfClassName, true, loader) without validating that the class extends UDF interface BEFORE instantiation. Only checks isAssignableFrom AFTER loading. A malicious class could be loaded and its static initializer executed before the UDF check. The classLoader is created from files in hiveUdfDir without signature verification.

**达成路径**

udfClassName -> Class.forName(udfClassName, true, loader) -> static initializer execution -> UDF.class.isAssignableFrom check (too late)

**验证说明**: VERIFIED: HiveUdfExecutor.java:169 and 370 - Class.forName(udfClassName, true, loader) loads class with initialization=true. This causes static initializer to RUN BEFORE line 170/371 checks UDF.class.isAssignableFrom(udfClass). A malicious class with static initializer can execute arbitrary code (e.g., Runtime.exec()) before being rejected as non-UDF. The UDF check is TOO LATE.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: _ | 5: s | 6: c | 7: o | 8: r | 9: e | 10: = | 11: 3 | 12: 0 | 13:   | 14: + | 15:   | 16: r | 17: e | 18: a | 19: c | 20: h | 21: a | 22: b | 23: i | 24: l | 25: i | 26: t | 27: y | 28: _ | 29: d | 30: i | 31: r | 32: e | 33: c | 34: t | 35: = | 36: 2 | 37: 0 | 38:   | 39: + | 40:   | 41: c | 42: o | 43: n | 44: t | 45: r | 46: o | 47: l | 48: l | 49: a | 50: b | 51: i | 52: l | 53: i | 54: t | 55: y | 56: _ | 57: f | 58: u | 59: l | 60: l | 61: = | 62: 2 | 63: 5 | 64:   | 65: + | 66:   | 67: b | 68: y | 69: p | 70: a | 71: s | 72: s | 73: _ | 74: c | 75: h | 76: e | 77: c | 78: k | 79: = | 80: 1 | 81: 0 | 82:   | 83: = | 84:   | 85: 8 | 86: 5

---

### [VULN-EXPR-002] Uncontrolled Recursion - ParseJSON

**严重性**: High | **CWE**: CWE-674 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/core/src/expression/jsonparser/jsonparser.cpp:530-565` @ `ParseJSON`
**模块**: expression

**描述**: ParseJSON函数递归解析嵌套表达式缺少深度限制

**漏洞代码** (`/core/src/expression/jsonparser/jsonparser.cpp:530-565`)

```c
ParseJSON递归调用
```

**达成路径**

[JNI] JSON字符串 -> ParseJSON递归解析 -> 栈溢出风险

**验证说明**: ParseJSON递归解析无深度限制。代码确认: jsonparser.cpp:530-564，所有嵌套表达式类型(BINARY/UNARY/IN/BETWEEN/IF/SWITCH/FUNC)都递归调用ParseJSON。无任何深度计数器或限制。

**评分明细**: base: 30 | reachability: [object Object] | cross_file: [object Object] | mitigations: [object Object] | veto: null | exploitability: [object Object]

---

### [VULN-SEC-EXPR-001] uncontrolled_recursion - ParseJSON

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-674 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `core/src/expression/jsonparser/jsonparser.cpp:530-564` @ `ParseJSON`
**模块**: expression
**跨模块**: bindings/java → expression

**描述**: JSON解析函数ParseJSON在处理嵌套表达式时进行递归调用，未设置递归深度限制。攻击者可构造深度嵌套的JSON表达式，导致栈溢出崩溃。影响ParseJSONBinary、ParseJSONUnary、ParseJSONIn、ParseJSONBetween、ParseJSONIf、ParseJSONSwitch、ParseJSONFunc等所有递归解析入口。

**漏洞代码** (`core/src/expression/jsonparser/jsonparser.cpp:530-564`)

```c
Expr *JSONParser::ParseJSON(const Json &jsonExpr)
{
    string exprTypeStr = jsonExpr["exprType"].get<string>();
    if (exprTypeStr == "FIELD_REFERENCE") {
        return ParseJSONFieldRef(jsonExpr);
    } else if (exprTypeStr == "BINARY") {
        return ParseJSONBinary(jsonExpr);  // 递归调用
    } ...
}
```

**达成路径**

jni_operator_factory.cpp:70 nlohmann::json::parse(keysArr[i]) [SOURCE]
jsonparser.cpp:530 ParseJSON() -> 递归调用 ParseJSONBinary/ParseJSONUnary/... [SINK]

**验证说明**: 与VULN-EXPR-002重复。ParseJSON递归解析嵌套表达式无深度限制。攻击者可构造深度嵌套JSON表达式导致栈溢出。

**评分明细**: base: 30 | reachability: [object Object] | exploitability: [object Object] | veto: null

---

### [VULN-EXPR-001] Improper Input Validation - ParseJSONFieldRef

**严重性**: High | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `/core/src/expression/jsonparser/jsonparser.cpp:18-39` @ `ParseJSONFieldRef`
**模块**: expression
**跨模块**: jni_bindings,expression,codegen

**描述**: JSON字段访问缺少类型和范围验证。jsonExpr["dataType"]强制转换为DataTypeId时未检查值范围，恶意输入可能导致未定义行为或越界访问。

**漏洞代码** (`/core/src/expression/jsonparser/jsonparser.cpp:18-39`)

```c
auto typeId = static_cast<DataTypeId>(jsonExpr["dataType"].get<int32_t>());
```

**达成路径**

[JNI] Java传入JSON字符串 -> jsonparser.cpp ParseJSONFieldRef -> DataTypeId强制转换

**验证说明**: DataTypeId强制转换无范围验证。代码确认: jsonparser.cpp:18 static_cast<DataTypeId>无检查。DataTypeId有效范围0-73，超出可能导致未定义行为。ExprVerifier有部分缓解但不覆盖此场景。

**评分明细**: base: 30 | reachability: [object Object] | cross_file: [object Object] | mitigations: [object Object] | veto: null

---

### [VULN-SEC-OOB-001] out_of_bounds_read - RegexpExtractRetNull

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-125 | **置信度**: 50/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `core/src/codegen/functions/stringfunctions.cpp:155-162` @ `RegexpExtractRetNull`
**模块**: codegen

**描述**: RegexpExtractRetNull 函数在处理多字节 UTF-8 字符时存在越界读取风险。函数将输入字符串转换为宽字符串进行正则匹配，但将宽字符串的匹配位置（startIdx）直接用于字节字符串的偏移计算。当输入包含多字节 UTF-8 字符时，宽字符串索引与字节字符串索引不一致，可能导致读取错误位置或越界访问。

**漏洞代码** (`core/src/codegen/functions/stringfunctions.cpp:155-162`)

```c
int startIdx = match.position(group); // Get start position of group 2
...
memcpy_s(ret, *outLen + 1, str + startIdx, *outLen + 1);
```

**达成路径**

str (byte string) → std::string s(str, strLen) → StringUtil::ToWideString(s) → ws (wide string) → regex_search(ws, match, re) → match.position(group) → startIdx (wide string index) → str + startIdx (wrong byte offset)

**验证说明**: CONFIRMED VULNERABILITY: Clear bug in UTF-8 handling. StringUtil::ToWideString converts to wide string (ws), match.position(group) returns position in wide string (startIdx), but str+startIdx uses byte string offset. For multi-byte UTF-8 characters, this causes incorrect offset or OOB read.

**评分明细**: base: 30 | reachability: 20 | mitigations: 0 | reason: CONFIRMED BUG: Wide string index used with byte string at lines 156-162. match.position(group) returns wide char position, str+startIdx uses byte offset.

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| codegen | 0 | 1 | 0 | 0 | 1 |
| cross_module | 1 | 0 | 0 | 0 | 1 |
| expression | 0 | 3 | 0 | 0 | 3 |
| jni_bindings | 0 | 3 | 0 | 0 | 3 |
| type | 0 | 2 | 0 | 0 | 2 |
| udf | 3 | 2 | 0 | 0 | 5 |
| **合计** | **4** | **11** | **0** | **0** | **15** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-94 | 3 | 20.0% |
| CWE-476 | 3 | 20.0% |
| CWE-674 | 2 | 13.3% |
| CWE-78 | 1 | 6.7% |
| CWE-693 | 1 | 6.7% |
| CWE-470 | 1 | 6.7% |
| CWE-248 | 1 | 6.7% |
| CWE-20 | 1 | 6.7% |
| CWE-125 | 1 | 6.7% |
| CWE-121 | 1 | 6.7% |

---

## 7. 修复建议

### 优先级 1: 立即修复 (Critical 漏洞)

**UDF 任意代码执行漏洞 (udf-001, VULN-SEC-UDF-001, VULN-SEC-UDF-004, VULN-XMOD-001)**

这些漏洞构成完整的攻击链，允许攻击者通过 SQL UDF 执行任意 Java 代码。建议采取以下措施：

1. **实现 UDF 类名白名单机制**
   - 在 `ExecuteHiveUdfSingle` 入口处验证 `udfClass` 是否在配置文件的白名单中
   - 添加类名格式验证：只允许合法的 Java 类名格式 `[a-zA-Z_][a-zA-Z0-9_.]*`
   
   ```c
   // 建议的验证逻辑
   if (!IsValidClassName(udfClass) || !IsWhitelisted(udfClass)) {
       SetError(contextPtr, "Invalid UDF class name");
       return;
   }
   ```

2. **移除或限制 DLLEXPORT 函数**
   - 移除 `udffunctions.cpp` 中 `EvaluateHiveUdfSingle/EvaluateHiveUdfBatch` 的 `DLLEXPORT` 声明
   - 或添加调用者上下文验证，只允许来自可信 SQL 解析路径的调用

3. **修复 Java 层静态初始化器漏洞**
   - 在 `HiveUdfExecutor.java:169` 使用延迟初始化：
   
   ```java
   Class<?> udfClass = Class.forName(udfClassName, false, loader);  // false = 不初始化
   if (UDF.class.isAssignableFrom(udfClass)) {
       udfClass.getConstructor().newInstance();  // 现在才初始化
   }
   ```

### 优先级 2: 短期修复 (High 漏洞)

**空指针解引用漏洞 (JNI-001, JNI-005, VULN-TYPE-005)**

1. **JNI 入口点添加空指针检查**
   ```c
   auto *vecBatch = reinterpret_cast<VectorBatch *>(jVecBatchAddress);
   if (vecBatch == nullptr) {
       env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), "Invalid vector batch address");
       return;
   }
   ```

2. **DataTypeJsonParser 返回值处理**
   - 将 `nullptr` 返回改为抛出异常，避免空指针被 push 到 vector

**异常处理漏洞 (VULN-TYPE-010)**

在所有 `Deserialize` 调用处添加 try-catch：
```c
try {
    auto dataTypes = Deserialize(sourceTypesCharPtr);
    output.push_back(dataTypes);
} catch (const std::exception& e) {
    LogError("Deserialize failed: %s", e.what());
    output.push_back(DataTypes());  // 返回空类型
}
```

**栈溢出漏洞 (JNI-006)**

添加 VLA 数组大小上限验证：
```c
auto sortColsCount = env->GetArrayLength(jSortCols);
if (sortColsCount > MAX_SORT_COLS) {  // 定义合理上限，如 1024
    env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), "Too many sort columns");
    return;
}
int32_t sortColsArr[sortColsCount];  // 或改用 std::vector
```

**递归深度漏洞 (VULN-EXPR-002, VULN-SEC-EXPR-001)**

在 `ParseJSON` 中添加递归深度计数器：
```c
Expr *JSONParser::ParseJSON(const Json &jsonExpr, int depth = 0) {
    if (depth > MAX_PARSE_DEPTH) {  // 定义合理上限，如 100
        throw OmniException("Expression nesting too deep");
    }
    // ... 递归调用时传入 depth + 1
}
```

### 优先级 3: 计划修复 (Medium/Low 漏洞)

**环境变量注入漏洞 (udf-002)**

- 对 `OMNI_OPERATOR_CLASSPATH` 环境变量添加格式验证和路径安全检查
- 使用安全的 JVM 配置方式，如从配置文件读取而非环境变量

**输入验证漏洞 (VULN-EXPR-001)**

- 在 `static_cast<DataTypeId>` 前添加范围验证（有效范围 0-73）

---

**报告生成时间**: 2026-04-19
**报告版本**: v1.0
