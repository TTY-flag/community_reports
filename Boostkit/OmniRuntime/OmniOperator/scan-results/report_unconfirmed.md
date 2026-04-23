# 漏洞扫描报告 — 待确认漏洞

**项目**: OmniOperator
**扫描时间**: 2026-04-23T07:52:37.639Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| High | 8 | 61.5% |
| Medium | 4 | 30.8% |
| Low | 1 | 7.7% |
| **有效漏洞总计** | **13** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-CONFIG-001]** path_traversal (High) - `core/src/operator/config/operator_config.cpp:67` @ `OperatorConfig::DeserializeOperatorConfig` | 置信度: 75
2. **[VULN-DF-CONFIG-002]** path_traversal (High) - `core/src/operator/config/operator_config.cpp:152` @ `CreateSpillDirectories` | 置信度: 75
3. **[VULN-SEC-CFG-001]** path_traversal (High) - `core/src/operator/config/operator_config.cpp:67` @ `DeserializeOperatorConfig` | 置信度: 75
4. **[VULN-SEC-CFG-002]** path_traversal (High) - `core/src/operator/config/operator_config.cpp:152` @ `CreateSpillDirectory` | 置信度: 75
5. **[VULN-DF-EXPR-001]** injection (High) - `core/src/expression/jsonparser/jsonparser.cpp:405` @ `JSONParser::ParseJSONFunc` | 置信度: 70
6. **[VULN-DF-EXPR-002]** expression_injection (High) - `bindings/java/src/main/cpp/src/jni_operator_factory.cpp:457` @ `Java_nova_hetu_omniruntime_operator_filter_OmniFilterAndProjectOperatorFactory_createFilterAndProjectOperatorFactory` | 置信度: 70
7. **[VULN-SEC-EXPR-001]** function_name_injection (High) - `core/src/expression/jsonparser/jsonparser.cpp:405` @ `ParseJSONFunc` | 置信度: 70
8. **[VULN-SEC-JNI-005]** input_validation_missing (High) - `bindings/java/src/main/cpp/src/jni_operator_factory.cpp:457` @ `Java_nova_hetu_omniruntime_operator_filter_OmniFilterAndProjectOperatorFactory_createFilterAndProjectOperatorFactory` | 置信度: 70
9. **[VULN-DF-ENV-001]** library_injection (Medium) - `core/src/udf/cplusplus/jni_util.cpp:133` @ `CreateJavaVM` | 置信度: 65
10. **[VULN-DF-LOOKUP-001]** injection (Medium) - `core/src/codegen/func_registry.cpp:249` @ `FunctionRegistry::LookupHiveUdf` | 置信度: 65

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

## 3. High 漏洞 (8)

### [VULN-DF-CONFIG-001] path_traversal - OperatorConfig::DeserializeOperatorConfig

**严重性**: High | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `core/src/operator/config/operator_config.cpp:67-112` @ `OperatorConfig::DeserializeOperatorConfig`
**模块**: operator_config

**描述**: Spill path from external JSON configuration used in mkdir without path validation. The spillPath is extracted from user-provided JSON and passed to CreateSpillDirectory which calls mkdir. No validation for path traversal patterns like '..' or absolute paths to sensitive directories (/etc, /root, etc.).

**漏洞代码** (`core/src/operator/config/operator_config.cpp:67-112`)

```c
auto spillPath = result.at("spillConfig").at("spillPath").get<std::string>();
// ... later CreateSpillDirectory(spillPath.c_str()) calls mkdir
```

**达成路径**

JSON configString spillPath [SOURCE] -> nlohmann::json::parse -> SpillConfig -> CreateSpillDirectory -> mkdir [SINK]

**验证说明**: spillPath from JSON config directly used for mkdir without path normalization or traversal check. Attacker can inject paths like '../../../etc/'. Verified: operator_config.cpp lines 85, 152-179.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-CONFIG-002] path_traversal - CreateSpillDirectories

**严重性**: High | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `core/src/operator/config/operator_config.cpp:152-180` @ `CreateSpillDirectories`
**模块**: operator_config

**描述**: Path traversal vulnerability in CreateSpillDirectories function. The function iteratively creates directories along the spill path without validating the path components. Paths like '/etc/../root/.ssh' or '../../../etc/passwd' could create directories outside intended spill locations.

**漏洞代码** (`core/src/operator/config/operator_config.cpp:152-180`)

```c
mkdir(spillPathChars, 0750);
// Creates all parent directories without validation
```

**达成路径**

spillPath from JSON [SOURCE] -> CreateSpillDirectories -> mkdir [SINK]

**验证说明**: CreateSpillDirectory directly calls mkdir with user-provided path. No realpath/normalize. Verified: operator_config.cpp line 154.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-SEC-CFG-001] path_traversal - DeserializeOperatorConfig

**严重性**: High | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `core/src/operator/config/operator_config.cpp:67-128` @ `DeserializeOperatorConfig`
**模块**: operator_config

**描述**: DeserializeOperatorConfig从JSON解析spillPath，CreateSpillDirectory直接使用未验证的路径创建目录。攻击者可通过路径注入访问或创建敏感目录。

**漏洞代码** (`core/src/operator/config/operator_config.cpp:67-128`)

```c
OperatorConfig OperatorConfig::DeserializeOperatorConfig(const std::string &configString) {
    ...
    auto spillPath = result.at("spillConfig").at("spillPath").get<std::string>(); // 直接获取路径
    ...
    resultSpillConfig = new SpillConfig(spillConfigId, spillEnabled, spillPath, ...);
```

**达成路径**

External (JSON spillPath) -> SpillConfig -> CreateSpillDirectory -> mkdir()

**验证说明**: Same as VULN-DF-CONFIG-001: spillPath path traversal in DeserializeOperatorConfig.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-SEC-CFG-002] path_traversal - CreateSpillDirectory

**严重性**: High | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `core/src/operator/config/operator_config.cpp:152-180` @ `CreateSpillDirectory`
**模块**: operator_config

**描述**: CreateSpillDirectory函数直接调用mkdir()使用用户提供的路径，没有路径规范化或验证。可能导致路径遍历攻击。

**漏洞代码** (`core/src/operator/config/operator_config.cpp:152-180`)

```c
static void CreateSpillDirectory(const char *spillPathChars)
{
    mkdir(spillPathChars, 0750); // 直接创建目录，无验证
    if (access(spillPathChars, 0) != 0) {
        ...
```

**达成路径**

External (spillPathChars) -> mkdir() -> Directory creation

**验证说明**: Same as VULN-DF-CONFIG-002: mkdir without path validation.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-EXPR-001] injection - JSONParser::ParseJSONFunc

**严重性**: High | **CWE**: CWE-94 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `core/src/expression/jsonparser/jsonparser.cpp:405-502` @ `JSONParser::ParseJSONFunc`
**模块**: expression
**跨模块**: expression → codegen

**描述**: Function name from JSON expression used to lookup and execute functions without whitelist validation. The funcName is extracted from user-provided JSON and used to call FunctionRegistry::LookupFunction and FunctionRegistry::LookupHiveUdf. This could allow unintended function execution or Hive UDF invocation if malicious function names are crafted.

**漏洞代码** (`core/src/expression/jsonparser/jsonparser.cpp:405-502`)

```c
string funcName = jsonExpr["function_name"];
auto function = omniruntime::codegen::FunctionRegistry::LookupFunction(&signature);
auto &hiveUdfClass = omniruntime::codegen::FunctionRegistry::LookupHiveUdf(funcName);
```

**达成路径**

JSON function_name [SOURCE] -> FunctionRegistry::LookupFunction/LookupHiveUdf -> FuncExpr execution [SINK]

**验证说明**: function_name extracted from JSON and used to lookup functions. If LookupFunction returns null, function is not executed (mitigation -5). However, attacker can still call any registered function. Verified: jsonparser.cpp lines 407-491.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [VULN-DF-EXPR-002] expression_injection - Java_nova_hetu_omniruntime_operator_filter_OmniFilterAndProjectOperatorFactory_createFilterAndProjectOperatorFactory

**严重性**: High | **CWE**: CWE-94 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_operator_factory.cpp:457-530` @ `Java_nova_hetu_omniruntime_operator_filter_OmniFilterAndProjectOperatorFactory_createFilterAndProjectOperatorFactory`
**模块**: bindings/java
**跨模块**: bindings/java → expression → codegen

**描述**: JSON expression from JNI input parsed and executed without proper validation. The filterExpression string comes from Java via JNI and is parsed by JSONParser::ParseJSON, which builds expression trees that are later executed. No input sanitization allows potential expression injection attacks.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator_factory.cpp:457-530`)

```c
auto filterJsonExpr = nlohmann::json::parse(filterExpression);
filterExpr = JSONParser::ParseJSON(filterJsonExpr);
```

**达成路径**

JNI jstring jExpression [SOURCE] -> GetStringUTFChars -> nlohmann::json::parse -> JSONParser::ParseJSON -> ExpressionEvaluator [SINK]

**验证说明**: filterExpression JSON parsed and executed. Has CheckExpressionSupported validation at line 509-513, but still allows crafted expressions. Verified: jni_operator_factory.cpp lines 484-485.

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-SEC-EXPR-001] function_name_injection - ParseJSONFunc

**严重性**: High | **CWE**: CWE-94 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `core/src/expression/jsonparser/jsonparser.cpp:405-502` @ `ParseJSONFunc`
**模块**: expression

**描述**: ParseJSONFunc函数直接从JSON解析function_name字段，并通过FunctionRegistry::LookupFunction查找函数。没有对函数名进行白名单验证，可能执行未预期函数。

**漏洞代码** (`core/src/expression/jsonparser/jsonparser.cpp:405-502`)

```c
Expr *JSONParser::ParseJSONFunc(const Json &jsonExpr)
{
    string funcName = jsonExpr["function_name"]; // 直接获取函数名
    ...
    auto function = omniruntime::codegen::FunctionRegistry::LookupFunction(&signature);
    if (function != nullptr) {
        return new FuncExpr(funcName, args, std::move(retType), function);
    }
```

**达成路径**

External (JSON function_name) -> FunctionRegistry::LookupFunction -> FuncExpr execution

**验证说明**: Same as VULN-DF-EXPR-001: ParseJSONFunc function name injection.

**评分明细**: base: 30 | controllability: 25 | context: 0 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [VULN-SEC-JNI-005] input_validation_missing - Java_nova_hetu_omniruntime_operator_filter_OmniFilterAndProjectOperatorFactory_createFilterAndProjectOperatorFactory

**严重性**: High | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `bindings/java/src/main/cpp/src/jni_operator_factory.cpp:457-530` @ `Java_nova_hetu_omniruntime_operator_filter_OmniFilterAndProjectOperatorFactory_createFilterAndProjectOperatorFactory`
**模块**: bindings/java

**描述**: createFilterAndProjectOperatorFactory入口点解析用户提供的表达式JSON，没有验证表达式内容的合法性。可能导致表达式注入攻击。

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator_factory.cpp:457-530`)

```c
JNIEXPORT jlong JNICALL ...createFilterAndProjectOperatorFactory(...) {
    ...
    auto filterJsonExpr = nlohmann::json::parse(filterExpression); // 直接解析用户表达式
    filterExpr = JSONParser::ParseJSON(filterJsonExpr);
```

**达成路径**

External (Java jExpression JSON) -> nlohmann::json::parse -> JSONParser::ParseJSON -> Expression tree

**验证说明**: Same as VULN-DF-EXPR-002: createFilterAndProjectOperatorFactory expression injection.

**评分明细**: base: 30 | controllability: 20 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

## 4. Medium 漏洞 (4)

### [VULN-DF-ENV-001] library_injection - CreateJavaVM

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `core/src/udf/cplusplus/jni_util.cpp:133-161` @ `CreateJavaVM`
**模块**: udf

**描述**: Environment variable OMNI_OPERATOR_CLASSPATH used to configure JVM classpath without validation. The classpath from environment could contain paths to malicious JAR files, leading to arbitrary code execution when JVM loads classes from those paths.

**漏洞代码** (`core/src/udf/cplusplus/jni_util.cpp:133-161`)

```c
auto classPath = getenv("OMNI_OPERATOR_CLASSPATH");
options[0].optionString = classPath;
JNI_CreateJavaVM(&javaVm, (void **)&env, &vmArgs);
```

**达成路径**

getenv OMNI_OPERATOR_CLASSPATH [SOURCE] -> JavaVMOption -> JNI_CreateJavaVM [SINK - Library Injection]

**验证说明**: OMNI_OPERATOR_CLASSPATH environment variable directly used for JVM classpath. Attacker with local access can inject malicious JARs. Verified: jni_util.cpp lines 144-149. Requires local access (context -20).

**评分明细**: base: 30 | controllability: 15 | context: -20 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-LOOKUP-001] injection - FunctionRegistry::LookupHiveUdf

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `core/src/codegen/func_registry.cpp:249-257` @ `FunctionRegistry::LookupHiveUdf`
**模块**: codegen
**跨模块**: codegen → expression → udf

**描述**: LookupHiveUdf function allows arbitrary UDF class lookup by name. The udfName parameter could come from malicious JSON expressions and is used to map to Hive UDF class names. No whitelist validation of allowed UDF names.

**漏洞代码** (`core/src/codegen/func_registry.cpp:249-257`)

```c
auto result = hiveUdfMap->find(udfName);
return result->second;
```

**达成路径**

udfName from expression parser [SOURCE] -> hiveUdfMap lookup -> Hive UDF class name [SINK -> External Execution]

**验证说明**: LookupHiveUdf only returns classes from pre-registered hiveUdfMap (InitHiveUdfMap). Attacker cannot inject arbitrary classes, only select from registered list. Verified: func_registry.cpp lines 249-256.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-MEM-001] memory_corruption - ExecHiveUdfOutputString

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-119 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `core/src/udf/cplusplus/java_udf_functions.cpp:99-127` @ `ExecHiveUdfOutputString`
**模块**: udf

**描述**: Memory address manipulation in UDF output handling without bounds checking. The outputValueAddr and outputLengthAddr are treated as array pointers and manipulated without validating the underlying buffer sizes.

**漏洞代码** (`core/src/udf/cplusplus/java_udf_functions.cpp:99-127`)

```c
auto outputValueAddrArr = reinterpret_cast<int64_t *>(outputValueAddr);
auto outputLengthArr = reinterpret_cast<int32_t *>(outputLengthAddr);
outputValueAddrArr[i] = reinterpret_cast<int64_t>(outputValuePtr + offset);
offset += outputLengthArr[i];
```

**达成路径**

int64_t outputValueAddr/outputLengthAddr [SOURCE] -> reinterpret_cast -> Array access without bounds check [SINK]

**验证说明**: Memory addresses cast to arrays and indexed without bounds validation. Buffer overflow possible. Verified: java_udf_functions.cpp lines 99-126.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-SEC-EXPR-002] arbitrary_code_execution - ParseJSONFunc

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `core/src/expression/jsonparser/jsonparser.cpp:493-496` @ `ParseJSONFunc`
**模块**: expression

**描述**: ParseJSONFunc中LookupHiveUdf允许通过函数名查找并执行任意Hive UDF。没有验证机制，可能导致任意代码执行。

**漏洞代码** (`core/src/expression/jsonparser/jsonparser.cpp:493-496`)

```c
auto &hiveUdfClass = omniruntime::codegen::FunctionRegistry::LookupHiveUdf(funcName);
    if (!hiveUdfClass.empty()) {
        return new FuncExpr(hiveUdfClass, args, std::move(retType), HIVE_UDF);
```

**达成路径**

External (JSON function_name) -> LookupHiveUdf -> HiveUdfExecutor -> Arbitrary Java class

**验证说明**: Same as VULN-DF-LOOKUP-001: HiveUdfMap lookup limited to pre-registered classes.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

## 5. Low 漏洞 (1)

### [VULN-DF-DESC-001] input_validation - Deserialize

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `core/src/type/data_type_serializer.cpp:23-31` @ `Deserialize`
**模块**: bindings/java
**跨模块**: bindings/java → type

**描述**: Data type deserialization from external JSON without bounds validation. The Deserialize function parses JSON data type strings that could contain invalid or malicious type IDs, potentially causing unexpected behavior.

**漏洞代码** (`core/src/type/data_type_serializer.cpp:23-31`)

```c
auto dataTypeJsons = nlohmann::json::parse(dataTypes);
for (const auto &dataTypeJson : dataTypeJsons) {
    types.push_back(DataTypeJsonParser(dataTypeJson));
}
```

**达成路径**

JNI jstring dataTypes [SOURCE] -> GetStringUTFChars -> nlohmann::json::parse -> DataTypeJsonParser [SINK]

**验证说明**: JSON data type deserialization without bounds check. However, switch case at lines 42-87 handles invalid types by returning nullptr. Limited impact.

**评分明细**: base: 30 | controllability: 15 | context: 0 | cross_file: 0 | mitigations: 0 | reachability: 20

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| bindings/java | 0 | 2 | 0 | 1 | 3 |
| codegen | 0 | 0 | 1 | 0 | 1 |
| expression | 0 | 2 | 1 | 0 | 3 |
| operator_config | 0 | 4 | 0 | 0 | 4 |
| udf | 0 | 0 | 2 | 0 | 2 |
| **合计** | **0** | **8** | **4** | **1** | **13** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-94 | 5 | 38.5% |
| CWE-22 | 4 | 30.8% |
| CWE-20 | 2 | 15.4% |
| CWE-426 | 1 | 7.7% |
| CWE-119 | 1 | 7.7% |
