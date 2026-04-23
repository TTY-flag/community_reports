# OmniOperator Threat Analysis Report

## Executive Summary

OmniOperator is a C++ native runtime library providing high-performance operators for big data query execution. The project serves as a backend processing engine for OmniRuntime, accessed primarily through Java JNI bindings.

**Key Security Findings:**
- **Primary Attack Surface**: JNI interface serves as the main entry point for external data and control flow
- **High-Risk Areas**: Expression parsing, UDF execution, and configuration deserialization
- **Data Flow**: External JSON strings control expression trees, function execution, and file system operations
- **Code Execution Risk**: Hive UDF framework allows arbitrary Java class invocation through class name strings

**Overall Risk Assessment**: **HIGH** - Multiple paths for external input to influence native code execution

---

## Project Overview

| Attribute | Value |
|-----------|-------|
| Project Name | OmniOperator |
| Project Type | C++ Native Runtime Library |
| Primary Language | C++17 |
| Secondary Languages | Java (JNI bindings), Python (test scripts) |
| Source Files | 291 C++ + 304 Headers |
| Primary Use Case | Big data query execution operators |

### Module Architecture

```
OmniOperator/
├── bindings/java/          [HIGH RISK] - JNI interface layer
│   └── src/main/cpp/       - Native JNI implementations
│   └── src/main/java/      - Java vector/operator classes
├── core/src/
│   ├── udf/                [HIGH RISK] - User-defined function execution
│   ├── expression/         [HIGH RISK] - Expression parsing
│   ├── operator/           [MEDIUM]    - Data processing operators
│   ├── codegen/            [MEDIUM]    - Function registry & codegen
│   ├── type/               [MEDIUM]    - Type serialization
│   ├── vector/             [LOW]       - Columnar data structures
│   ├── memory/             [LOW]       - Memory management
│   └── util/               [LOW]       - Utilities
├── examples/
│   └── externalfunctions/  [HIGH RISK] - External function registration
└── core/test/              - Test suite
```

---

## Attack Surface Analysis

### 1. JNI Interface Layer (Critical Risk)

**Location**: `bindings/java/src/main/cpp/src/`

**Entry Points Identified**:

| Function | File | Line | Risk Level |
|----------|------|------|------------|
| `addInputNative` | jni_operator.cpp | 159 | HIGH |
| `getOutputNative` | jni_operator.cpp | 178 | HIGH |
| `createOperatorNative` | jni_operator_factory.cpp | 156 | HIGH |
| `createFilterAndProjectOperatorFactory` | jni_operator_factory.cpp | 457 | CRITICAL |
| `createLookupJoinOperatorFactory` | jni_operator_factory.cpp | 620 | HIGH |
| `parseOneRow` | jni_operator.cpp | 348 | HIGH |

**Threat Analysis**:

1. **Pointer Injection via jlong**
   - JNI methods receive `jlong` values that are directly cast to native pointers
   - Example: `reinterpret_cast<VectorBatch*>(jVecBatchAddress)`
   - **Risk**: Malicious pointer values could cause arbitrary memory access, type confusion, or memory corruption

2. **Expression Injection via JSON**
   - `createFilterAndProjectOperatorFactory` receives expression strings parsed as JSON
   - Flow: `jstring -> GetStringUTFChars -> nlohmann::json::parse -> JSONParser::ParseJSON`
   - **Risk**: Malicious JSON expressions could trigger unexpected function calls or type coercion

3. **Configuration Injection**
   - Operator configuration received as JSON string
   - Flow: `jstring -> OperatorConfig::DeserializeOperatorConfig`
   - **Risk**: Configuration manipulation affecting spill paths, memory limits, or operator behavior

### 2. Expression Parsing (High Risk)

**Location**: `core/src/expression/jsonparser/`

**Data Flow**:
```
JSON String → nlohmann::json::parse → JSONParser::ParseJSON → Expr Tree → FunctionRegistry::LookupFunction
```

**Key Vulnerabilities**:

1. **Function Name Injection**
   - `ParseJSONFunc` extracts `function_name` from JSON: `string funcName = jsonExpr["function_name"]`
   - Function name used to lookup execution targets: `FunctionRegistry::LookupFunction(&signature)`
   - **CWE-94**: Code Injection via function name manipulation

2. **Hive UDF Class Name Injection**
   - `FunctionRegistry::LookupHiveUdf(funcName)` returns Java UDF class name
   - Class name passed to JVM for execution: `ExecuteHiveUdfSingle(udfClass, ...)`
   - **CWE-94**: Arbitrary Java class execution via manipulated function name

3. **Type Coercion Issues**
   - JSON literal parsing performs implicit type conversions
   - Decimal types constructed from JSON values without validation
   - **CWE-704**: Type casting issues leading to precision loss or overflow

**Affected Code**:
```cpp
// jsonparser.cpp:405-502
Expr *JSONParser::ParseJSONFunc(const Json &jsonExpr) {
    string funcName = jsonExpr["function_name"];  // Direct extraction from JSON
    // ... function lookup and execution ...
    auto &hiveUdfClass = omniruntime::codegen::FunctionRegistry::LookupHiveUdf(funcName);
    if (!hiveUdfClass.empty()) {
        return new FuncExpr(hiveUdfClass, args, std::move(retType), HIVE_UDF);  // Executes external Java class
    }
}
```

### 3. UDF Execution Framework (Critical Risk)

**Location**: `core/src/udf/cplusplus/`

**Execution Chain**:
```
ExecuteHiveUdfSingle/ExecuteHiveUdfBatch → JniUtil::GetJNIEnv → NewStringUTF(udfClass) → CallStaticVoidMethod → HiveUdfExecutor.executeSingle/executeBatch
```

**Threats Identified**:

1. **Arbitrary Java Class Execution**
   - UDF class name comes from expression parsing chain
   - No class name validation or whitelist enforcement
   - **CWE-470**: Use of Externally-Controlled Input to Select Classes/Code

2. **Direct Memory Pointer Exposure**
   - Native memory addresses passed to Java UDFs
   - `inputValueAddr`, `outputValueAddr` parameters
   - **CWE-787**: Out-of-bounds write via manipulated pointer values

3. **JVM Exception Handling**
   - Exceptions caught but error messages passed back through `SetError`
   - Potential information disclosure via exception messages

**Affected Code**:
```cpp
// java_udf_functions.cpp:42-73
void ExecuteHiveUdfSingle(int64_t contextPtr, const char *udfClass, ...) {
    jstring jUdfClassName = env->NewStringUTF(udfClass);  // Class name from external source
    env->CallStaticVoidMethod(executorCls, executeSingleMethod, jUdfClassName, ...);  // Execute arbitrary class
}
```

### 4. Configuration Deserialization (Medium-High Risk)

**Location**: `core/src/operator/config/operator_config.cpp`

**Attack Vector**: JSON configuration string controls:
- Spill configuration (file paths)
- Overflow handling behavior
- Memory thresholds

**Key Vulnerabilities**:

1. **Path Injection in Spill Configuration**
   - `spillPath` extracted from JSON: `result.at("spillConfig").at("spillPath").get<std::string>()`
   - Path used for directory creation: `CreateSpillDirectory(spillPath.c_str())`
   - **CWE-22**: Path Traversal via manipulated spill path

2. **File System Operations**
   - `mkdir(spillPathChars, 0750)` - Directory creation
   - `statfs(spillPathChars, &diskInfo)` - File system stat
   - `access(spillPathChars, 0)` - File access check
   - **CWE-73**: External Control of File Name/Path

**Affected Code**:
```cpp
// operator_config.cpp:67-112
OperatorConfig OperatorConfig::DeserializeOperatorConfig(const std::string &configString) {
    auto result = nlohmann::json::parse(configString);
    auto spillPath = result.at("spillConfig").at("spillPath").get<std::string>();  // Path from JSON
    // ... later used in CreateSpillDirectories ...
}

// operator_config.cpp:152-159
static void CreateSpillDirectory(const char *spillPathChars) {
    mkdir(spillPathChars, 0750);  // Uses path from configuration
}
```

### 5. Data Type Serialization (Medium Risk)

**Location**: `core/src/type/data_type_serializer.cpp`

**Function**: `Deserialize(const std::string &dataTypes)`

**Vulnerabilities**:
- Type IDs extracted from JSON without validation
- Recursive parsing of nested type structures
- **CWE-20**: Improper Input Validation

### 6. External Function Registration (High Risk)

**Location**: `examples/externalfunctions/`

**Threat**: Dynamic loading of native functions from configuration file
- `externalregistration.conf` defines function signatures
- Functions loaded at runtime via `extern "C" DLLEXPORT`
- **CWE-502**: Deserialization of Untrusted Data leading to code execution

---

## Data Flow Analysis

### Critical Data Flow Path 1: Expression Execution

```
[Java/JNI] createFilterAndProjectOperatorFactory
    ↓ GetStringUTFChars (jExpression)
    ↓ nlohmann::json::parse (expression string)
    ↓ JSONParser::ParseJSON
    ↓ ParseJSONFunc → funcName extraction
    ↓ FunctionRegistry::LookupHiveUdf (funcName)
    ↓ ExecuteHiveUdfSingle (hiveUdfClass, memory pointers)
    ↓ JVM: HiveUdfExecutor.executeSingle
    ↓ [Native Memory] Output buffer manipulation
```

**Risk Assessment**: Full chain from external JSON to arbitrary Java code execution with native memory access.

### Critical Data Flow Path 2: Configuration to File System

```
[Java/JNI] createOperatorFactory (jOperatorConfig)
    ↓ GetStringUTFChars (configString)
    ↓ OperatorConfig::DeserializeOperatorConfig
    ↓ JSON parse → spillPath extraction
    ↓ OperatorConfig::CheckSpillConfig
    ↓ CreateSpillDirectories
    ↓ mkdir (spillPath from JSON)
```

**Risk Assessment**: External JSON controls file system operations.

### Critical Data Flow Path 3: Row Data Processing

```
[Java/JNI] parseOneRow (jbyteArray bytes)
    ↓ GetByteArrayElements
    ↓ RowParser::ParseOnRow (uint8_t* row)
    ↓ Vector manipulation
    ↓ Memory write operations
```

**Risk Assessment**: Raw byte array from Java processed in native code without bounds checking.

---

## Trust Boundaries

| Boundary | Description | Crossing Mechanism | Risk |
|----------|-------------|-------------------|------|
| Java ↔ Native | JNI interface | Pointer casts, array elements | Memory corruption |
| External Config ↔ Internal State | JSON configuration | nlohmann::json::parse | Behavior manipulation |
| Expression String ↔ Expression Tree | Query predicates | JSONParser::ParseJSON | Function injection |
| UDF Class Name ↔ Java Execution | Hive UDF framework | JniUtil + JVM calls | Arbitrary code execution |
| JSON ↔ File System | Spill configuration | mkdir, statfs | Path traversal |

---

## Vulnerability Summary by CWE

| CWE ID | CWE Name | Affected Components | Severity |
|--------|----------|---------------------|----------|
| CWE-94 | Code Injection | expression/jsonparser.cpp, codegen/func_registry.cpp | CRITICAL |
| CWE-470 | Externally-Controlled Class Selection | udf/java_udf_functions.cpp | CRITICAL |
| CWE-22 | Path Traversal | operator/config/operator_config.cpp | HIGH |
| CWE-787 | Out-of-bounds Write | bindings/jni_operator.cpp (pointer handling) | HIGH |
| CWE-20 | Improper Input Validation | Multiple JSON parsing locations | MEDIUM |
| CWE-704 | Type Casting Issues | jsonparser.cpp (literal parsing) | MEDIUM |
| CWE-73 | External Control of File Path | operator_config.cpp | HIGH |
| CWE-502 | Deserialization of Untrusted Data | externalfunctions example | HIGH |

---

## High-Risk Function List

| Priority | Function | File | Line | Threat |
|----------|----------|------|------|--------|
| 1 | `ExecuteHiveUdfSingle` | java_udf_functions.cpp | 42 | Arbitrary Java class execution |
| 2 | `ExecuteHiveUdfBatch` | java_udf_functions.cpp | 166 | Batch UDF execution with memory pointers |
| 3 | `ParseJSONFunc` | jsonparser.cpp | 405 | Function name extraction and lookup |
| 4 | `DeserializeOperatorConfig` | operator_config.cpp | 67 | Configuration parsing with spill path |
| 5 | `createFilterAndProjectOperatorFactory` | jni_operator_factory.cpp | 457 | Expression parsing entry point |
| 6 | `CheckSpillConfig` | operator_config.cpp | 182 | File system operations |
| 7 | `FunctionRegistry::LookupHiveUdf` | func_registry.cpp | - | UDF class name lookup |
| 8 | `addInputNative` | jni_operator.cpp | 159 | Pointer cast from jlong |
| 9 | `parseOneRow` | jni_operator.cpp | 348 | Raw byte array processing |

---

## Recommendations

### Immediate Actions (Critical)

1. **UDF Class Whitelist**: Implement a whitelist of allowed UDF class names in `FunctionRegistry::LookupHiveUdf`
2. **Expression Validation**: Add schema validation for JSON expression input before parsing
3. **Pointer Validation**: Add bounds checking and null pointer validation for jlong casts

### Short-Term Actions (High Priority)

4. **Path Sanitization**: Validate and sanitize spill path in `OperatorConfig::CheckSpillConfig`
5. **Memory Address Validation**: Validate memory addresses passed to UDF execution
6. **Function Name Validation**: Restrict allowed function names in expression parsing

### Medium-Term Actions (Medium Priority)

7. **JSON Schema Enforcement**: Define strict schemas for all JSON input types
8. **Error Message Sanitization**: Sanitize exception messages before returning to JNI
9. **Input Rate Limiting**: Add limits on expression complexity and nesting depth

### Long-Term Actions

10. **Security Architecture Review**: Consider separation between expression parsing and execution
11. **Code Signing**: Implement code signing for external functions
12. **Audit Logging**: Add comprehensive logging for security-sensitive operations

---

## Appendix A: JNI Entry Point Details

### Full JNI Method List

```cpp
// Operator Operations (jni_operator.cpp)
Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative
Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative
Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative
Java_nova_hetu_omniruntime_operator_OmniOperator_getSpilledBytesNative
Java_nova_hetu_omniruntime_operator_OmniOperator_getMetricsInfoNative
Java_nova_hetu_omniruntime_operator_OmniOperator_alignSchemaNative
Java_nova_hetu_omniruntime_operator_OmniOperator_getHashMapUniqueKeysNative

// Vector Operations (jni_vector.cpp)
Java_nova_hetu_omniruntime_vector_Vec_newVectorNative
Java_nova_hetu_omniruntime_vector_Vec_newDictionaryVectorNative
Java_nova_hetu_omniruntime_vector_Vec_sliceVectorNative
Java_nova_hetu_omniruntime_vector_Vec_copyPositionsNative
Java_nova_hetu_omniruntime_vector_Vec_freeVectorNative
Java_nova_hetu_omniruntime_vector_VecBatch_newVectorBatchNative
Java_nova_hetu_omniruntime_vector_VecBatch_freeVectorBatchNative

// Row Operations (jni_operator.cpp)
Java_nova_hetu_omniruntime_vector_RowBatch_freeRowBatchNative
Java_nova_hetu_omniruntime_vector_RowBatch_newRowBatchNative
Java_nova_hetu_omniruntime_vector_RowBatch_transFromVectorBatch
Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_newOmniRowDeserializer
Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_freeOmniRowDeserializer
Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_parseOneRow
Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_parseOneRowByAddr
Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_parseAllRow

// Operator Factory Operations (jni_operator_factory.cpp)
Java_nova_hetu_omniruntime_operator_OmniOperatorFactory_createOperatorNative
Java_nova_hetu_omniruntime_operator_aggregator_OmniHashAggregationOperatorFactory_createHashAggregationOperatorFactory
Java_nova_hetu_omniruntime_operator_aggregator_OmniAggregationOperatorFactory_createAggregationOperatorFactory
Java_nova_hetu_omniruntime_operator_sort_OmniSortOperatorFactory_createSortOperatorFactory
Java_nova_hetu_omniruntime_operator_window_OmniWindowOperatorFactory_createWindowOperatorFactory
Java_nova_hetu_omniruntime_operator_topn_OmniTopNOperatorFactory_createTopNOperatorFactory
Java_nova_hetu_omniruntime_operator_filter_OmniFilterAndProjectOperatorFactory_createFilterAndProjectOperatorFactory
Java_nova_hetu_omniruntime_operator_project_OmniProjectOperatorFactory_createProjectOperatorFactory
Java_nova_hetu_omniruntime_operator_join_OmniHashBuilderOperatorFactory_createHashBuilderOperatorFactory
Java_nova_hetu_omniruntime_operator_join_OmniLookupJoinOperatorFactory_createLookupJoinOperatorFactory
Java_nova_hetu_omniruntime_operator_union_OmniUnionOperatorFactory_createUnionOperatorFactory
```

---

## Appendix B: JSON Expression Schema Risk Analysis

### Expression Types Processed

| Type | JSON Key | Risk |
|------|----------|------|
| FIELD_REFERENCE | `colVal`, `dataType` | Type confusion |
| LITERAL | `value`, `dataType`, `isNull` | Value injection |
| BINARY | `operator`, `left`, `right` | Operator manipulation |
| UNARY | `operator`, `expr` | Operator injection |
| FUNC/FUNCTION | `function_name`, `arguments`, `returnType` | **CRITICAL** - Function injection |
| IN | `arguments` | List injection |
| BETWEEN | `value`, `lower_bound`, `upper_bound` | Range manipulation |
| IF | `condition`, `if_true`, `if_false` | Logic injection |
| SWITCH | `numOfCases`, `CaseN` | Complex expression nesting |
| COALESCE | `value1`, `value2` | Null handling manipulation |
| IS_NULL/IS_NOT_NULL | `arguments` | Null check manipulation |
| MULTIPLE_AND_OR | `operator`, `conditions` | Logic chain injection |

---

## Report Metadata

- **Generated**: 2026-04-22
- **Analyzer**: Sisyphus-Junior (OpenCode)
- **Scan Output**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/OmniRuntime/OmniOperator/scan-results/`
- **Context Files**: 
  - `project_model.json`
  - `call_graph.json`
- **Next Phase**: DataFlow Scanner module-by-module analysis