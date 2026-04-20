# 漏洞扫描报告 — 待确认漏洞

**项目**: OmniOperator
**扫描时间**: 2026-04-19T12:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

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
| Critical | 1 | 1.8% |
| High | 7 | 12.7% |
| Medium | 27 | 49.1% |
| Low | 20 | 36.4% |
| **有效漏洞总计** | **55** | - |
| 误报 (FALSE_POSITIVE) | 15 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-XMOD-004]** jni_pointer_chain_null_deref (Critical) - `bindings/java/src/main/cpp/src/jni_operator.cpp:159` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative` | 置信度: 75
2. **[VULN-SA-JNI-001]** null_pointer_dereference (High) - `bindings/java/src/main/cpp/src/jni_operator.cpp:159` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative` | 置信度: 75
3. **[VULN-SA-JNI-002]** null_pointer_dereference (High) - `bindings/java/src/main/cpp/src/jni_operator.cpp:178` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative` | 置信度: 75
4. **[VULN-SA-JNI-003]** null_pointer_dereference (High) - `bindings/java/src/main/cpp/src/jni_operator.cpp:348` @ `Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_parseOneRow` | 置信度: 70
5. **[VULN-SA-JNI-007]** null_pointer_dereference (High) - `bindings/java/src/main/cpp/src/jni_operator.cpp:205` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative` | 置信度: 70
6. **[VULN-XMOD-002]** uncontrolled_recursion_expression_chain (High) - `core/src/expression/jsonparser/jsonparser.cpp:530` @ `ParseJSON` | 置信度: 70
7. **[VULN-XMOD-005]** expr_pointer_lifetime_cross_module (High) - `core/src/plannode/planNode.h:436` @ `~AbstractJoinNode` | 置信度: 60
8. **[VULN-CODEGEN-002]** Code Injection (High) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/core/src/codegen/expression_codegen.cpp:975` @ `CallHiveUdfFunction` | 置信度: 50
9. **[udf-003]** integer_overflow (Medium) - `core/src/udf/cplusplus/java_udf_functions.cpp:108` @ `ExecHiveUdfOutputString` | 置信度: 75
10. **[VULN-EXPR-004]** Use of Potentially Dangerous Function (Medium) - `/core/src/expression/jsonparser/jsonparser.cpp:584` @ `ParseJSON(string)` | 置信度: 70

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

## 3. Critical 漏洞 (1)

### [VULN-XMOD-004] jni_pointer_chain_null_deref - Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative

**严重性**: Critical | **CWE**: CWE-476 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `bindings/java/src/main/cpp/src/jni_operator.cpp:159-170` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative`
**模块**: cross_module
**跨模块**: jni_bindings → operator → vector → memory

**描述**: JNI指针传递链缺乏验证：从JNI接口传入的jlong地址被直接reinterpret_cast为VectorBatch指针，然后传递到operator模块的算子，最终到达vector和memory模块进行数据操作。恶意Java代码可传入无效地址，导致整条调用链的空指针解引用或任意内存访问。

**达成路径**

JNI(jni_operator.cpp:159) → reinterpret_cast<VectorBatch*>(jVecBatchAddress) → operator模块算子 → vector模块 Vector::SetValue/GetValue → memory模块 AlignedBuffer

**验证说明**: VERIFIED: JNI pointer chain null dereference confirmed. (1) Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative (jni_operator.cpp:159-170) takes jlong jVecBatchAddress. (2) Line 163: auto *vecBatch = reinterpret_cast<VectorBatch *>(jVecBatchAddress) - no null check. (3) Line 167: nativeOperator->SetInputVecBatch(vecBatch) - direct use. (4) Line 168: nativeOperator->AddInput(vecBatch) - propagates to operator/vector/memory modules. Malicious Java code can pass invalid address causing crash or memory corruption. Chain: jni_bindings->operator->vector->memory. Reachability: untrusted_local(+30). Cross-file: chain_complete(0). Score: 30+30+15(criticality)=75.

---

## 4. High 漏洞 (7)

### [VULN-SA-JNI-001] null_pointer_dereference - Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-476 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_operator.cpp:159-171` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_addInputNative`
**模块**: jni_bindings
**跨模块**: jni_bindings → operator

**描述**: JNI entry point addInputNative directly casts jlong addresses to C++ pointers without null validation. If Java passes null or invalid addresses, the native code dereferences them causing crashes or potential memory corruption.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator.cpp:159-171`)

```c
auto *vecBatch = reinterpret_cast<VectorBatch *>(jVecBatchAddress);
auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddress);
JNI_METHOD_START
RecordInputVectorsStack(vecBatch, env);
nativeOperator->SetInputVecBatch(vecBatch);
errNo = nativeOperator->AddInput(vecBatch);
```

**达成路径**

Java caller → jVecBatchAddress (semi_trusted) → reinterpret_cast → vecBatch pointer → dereference in SetInputVecBatch/AddInput

**验证说明**: JNI入口确实直接将jlong转换为指针，无空指针验证。semi_trusted输入源，攻击者可通过恶意Java代码传入无效地址导致native侧崩溃。

**评分明细**: base_score: 30 | reachability: direct_external | reachability_score: 30 | controllability: full | controllability_score: 25 | mitigations_found: exception_handling | mitigation_score: 0 | final_score: 85 | rationale: Duplicate of JNI-001. Same vulnerability in addInputNative.

---

### [VULN-SA-JNI-002] null_pointer_dereference - Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-476 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_operator.cpp:178-198` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_getOutputNative`
**模块**: jni_bindings
**跨模块**: jni_bindings → operator

**描述**: JNI entry point getOutputNative casts jlong address to Operator pointer without null validation. The pointer is immediately used in GetOutput() call, risking crash if invalid address is passed from Java.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator.cpp:178-198`)

```c
auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddr);
VectorBatch *outputVecBatch = nullptr;
JNI_METHOD_START
nativeOperator->GetOutput(&outputVecBatch);
```

**达成路径**

Java caller → jOperatorAddr (semi_trusted) → reinterpret_cast → nativeOperator → GetOutput() dereference

**验证说明**: getOutputNative函数直接使用jlong转换后的指针调用GetOutput，无空指针检查。可导致native侧崩溃。

**评分明细**: base_score: 30 | reachability: direct_external | reachability_score: 30 | controllability: full | controllability_score: 25 | mitigations_found: exception_handling | mitigation_score: 0 | final_score: 85

---

### [VULN-SA-JNI-003] null_pointer_dereference - Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_parseOneRow

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-476 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_operator.cpp:348-356` @ `Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_parseOneRow`
**模块**: jni_bindings
**跨模块**: jni_bindings → vector

**描述**: parseOneRow function receives jbyteArray from Java, converts to uint8_t pointer and passes to parser without validating the array content or size. Malformed data could cause parsing errors or buffer issues downstream.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator.cpp:348-356`)

```c
jboolean isCopy = false;
auto *row = env->GetByteArrayElements(bytes, &isCopy);
auto *parser = reinterpret_cast<RowParser *>(parserAddr);
parser->ParseOnRow(reinterpret_cast<uint8_t *>(row), rowIndex);
```

**达成路径**

Java caller → jbyteArray bytes (semi_trusted) → GetByteArrayElements → row pointer → ParseOnRow (cross-module)

**验证说明**: parseOneRow函数接收jbyteArray并直接解析，数据来源可控，可能导致解析错误或内存问题。

**评分明细**: base_score: 30 | reachability: direct_external | reachability_score: 30 | controllability: full | controllability_score: 25 | mitigations_found: exception_handling | mitigation_score: -5 | final_score: 80 | rationale: parseOneRow receives jbyteArray from Java, converts to uint8_t pointer via GetByteArrayElements. No size validation before passing to RowParser::ParseOnRow. Malformed data could cause parsing issues downstream in RowParser.

---

### [VULN-SA-JNI-007] null_pointer_dereference - Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-476 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_operator.cpp:205-214` @ `Java_nova_hetu_omniruntime_operator_OmniOperator_closeNative`
**模块**: jni_bindings
**跨模块**: jni_bindings → operator

**描述**: closeNative directly casts jlong to Operator pointer and calls DeleteOperator without null check. Passing invalid address could cause memory corruption or double-free issues.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator.cpp:205-214`)

```c
try {
    auto *nativeOperator = reinterpret_cast<op::Operator *>(jOperatorAddr);
    op::Operator::DeleteOperator(nativeOperator);
} catch (...)
```

**达成路径**

Java → jOperatorAddr (semi_trusted) → reinterpret_cast → nativeOperator → DeleteOperator (memory deallocation)

**验证说明**: closeNative直接转换jlong为Operator指针并调用DeleteOperator，无空检查，可能导致内存问题。

**评分明细**: base_score: 30 | reachability: direct_external | reachability_score: 30 | controllability: full | controllability_score: 25 | mitigations_found: exception_handling | mitigation_score: 0 | final_score: 85 | rationale: closeNative directly casts jlong to Operator pointer and calls DeleteOperator without null check. Passing invalid address could cause memory corruption or double-free. Exception handling catches crashes but doesn't prevent invalid memory operations.

---

### [VULN-XMOD-002] uncontrolled_recursion_expression_chain - ParseJSON

**严重性**: High | **CWE**: CWE-674 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `core/src/expression/jsonparser/jsonparser.cpp:530-594` @ `ParseJSON`
**模块**: cross_module
**跨模块**: jni_bindings → expression → codegen

**描述**: 跨模块递归攻击链：JSON表达式从JNI边界传入，经过expression模块的ParseJSON递归解析（无深度限制），然后到codegen模块进行LLVM JIT编译执行。恶意构造的深度嵌套JSON表达式可能导致：(1) expression模块栈溢出；(2) codegen模块资源耗尽；(3) 最终算子崩溃影响整个查询执行。

**达成路径**

JNI接口(jni_operator_factory.cpp:458) → JSON表达式字符串 → expression/jsonparser.cpp:ParseJSON → codegen/expression_codegen.cpp → LLVM JIT编译 → 算子执行

**验证说明**: VERIFIED: Recursive parsing chain confirmed but requires specific trigger. (1) JNI interface (jni_operator_factory.cpp:71,86,105) calls ParseJSON with user-supplied JSON. (2) ParseJSON (jsonparser.cpp:530-594) recursively parses nested expressions without depth limit. (3) Each branch (ParseJSONBinary:134,138, ParseJSONUnary:204, ParseJSONBetween:228,232,237) calls ParseJSON recursively. Stack overflow achievable with deeply nested JSON. Chain: jni_bindings->expression->codegen. Reachability: untrusted_local(+30). Cross-file: chain_complete(0). Score: 30+30+10(complexity_penalty)=70.

---

### [VULN-XMOD-005] expr_pointer_lifetime_cross_module - ~AbstractJoinNode

**严重性**: High | **CWE**: CWE-416 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `core/src/plannode/planNode.h:436-443` @ `~AbstractJoinNode`
**模块**: cross_module
**跨模块**: plannode → expression → compute

**描述**: Expr对象内存管理跨模块不一致：plannode模块的AbstractJoinNode析构函数delete了partitionKeys中的Expr指针，但这些指针可能被compute模块或其他模块仍持有。不同类对Expr*的管理不一致(有的delete，有的不delete)，导致潜在的UAF或内存泄漏。

**达成路径**

plannode/planNode.h:AbstractJoinNode析构函数 → delete partitionKeys中的Expr* → expression模块的Expr对象被释放 → compute模块持有的指针副本可能UAF

**验证说明**: VERIFIED: Expr pointer lifecycle inconsistency confirmed. (1) AbstractJoinNode destructor (planNode.h:436-443) deletes partitionKeys Expr pointers: for (auto expr: partitionKeys) { delete expr; }. (2) Other modules (operator/join/lookup_join_expr.cpp:35, operator/topnsort/topn_sort_expr.cpp:32) obtain partitionKeys via getter. (3) No ownership tracking - potential UAF if pointer used after AbstractJoinNode destruction. Unclear if actual exploitable race exists. Chain: plannode->expression->compute. Reachability: semi_trusted(+20). Cross-file: chain_complete(0). Score: 30+20+10(uncertainty)=60.

---

### [VULN-CODEGEN-002] Code Injection - CallHiveUdfFunction

**严重性**: High | **CWE**: CWE-94 | **置信度**: 50/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/core/src/codegen/expression_codegen.cpp:975-1033` @ `CallHiveUdfFunction`
**模块**: codegen
**跨模块**: expression,udf

**描述**: UDF class name passed directly to JNI without validation in CallHiveUdfFunction. The fExpr.funcName is used directly to construct jUdfClassName and passed to Java JVM via CallStaticVoidMethod. An attacker could potentially register malicious UDF classes leading to arbitrary code execution.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/core/src/codegen/expression_codegen.cpp:975-1033`)

```c
argVals.emplace_back(CreateConstantString(fExpr.funcName));\njstring jUdfClassName = env->NewStringUTF(udfClass);\nenv->CallStaticVoidMethod(executorCls, executeSingleMethod, jUdfClassName, ...)
```

**达成路径**

[IN] funcName <- expression parsing (user controlled)\n[PROCESS] ExpressionCodeGen::Visit(FuncExpr) -> CallHiveUdfFunction\n[OUT] JNI call -> udf module (ExecuteHiveUdfSingle)

**验证说明**: CONFIRMED: udfClass parameter passed directly to JNI NewStringUTF at line 55 without validation. funcName from SQL expression parsing. Depends on upstream SQL validation for security.

**评分明细**: base: 30 | reachability: 20 | mitigations: 0 | reason: UDF class name passes directly to JNI at java_udf_functions.cpp:55. No validation before NewStringUTF and CallStaticVoidMethod.

---

## 5. Medium 漏洞 (27)

### [udf-003] integer_overflow - ExecHiveUdfOutputString

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `core/src/udf/cplusplus/java_udf_functions.cpp:108-128` @ `ExecHiveUdfOutputString`
**模块**: udf

**描述**: ExecHiveUdfOutputString allocates memory with doubling capacity strategy starting at 1024 bytes. No upper bound check on outputValueCapacity before doubling. Potential integer overflow leading to memory allocation failure or exploitation. No null check on returned pointer from ArenaAllocatorMalloc.

**达成路径**

outputValueCapacity=1024 -> ArenaAllocatorMalloc(contextPtr, outputValueCapacity) -> outputValueCapacity*=2 (unbounded loop)

**验证说明**: VERIFIED: java_udf_functions.cpp:128 outputValueCapacity *= 2 in unbounded loop. Starting at 1024, doubling can reach overflow after ~21 iterations (2^21 * 1024 > INT_MAX). However, requires rowCount to be extremely large AND string output to exceed capacity repeatedly. Attack scenario requires controlled UDF output.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: _ | 5: s | 6: c | 7: o | 8: r | 9: e | 10: = | 11: 3 | 12: 0 | 13:   | 14: + | 15:   | 16: r | 17: e | 18: a | 19: c | 20: h | 21: a | 22: b | 23: i | 24: l | 25: i | 26: t | 27: y | 28: _ | 29: i | 30: n | 31: d | 32: i | 33: r | 34: e | 35: c | 36: t | 37: = | 38: 1 | 39: 5 | 40:   | 41: + | 42:   | 43: c | 44: o | 45: n | 46: t | 47: r | 48: o | 49: l | 50: l | 51: a | 52: b | 53: i | 54: l | 55: i | 56: t | 57: y | 58: _ | 59: p | 60: a | 61: r | 62: t | 63: i | 64: a | 65: l | 66: = | 67: 1 | 68: 5 | 69:   | 70: + | 71:   | 72: t | 73: r | 74: i | 75: g | 76: g | 77: e | 78: r | 79: _ | 80: c | 81: o | 82: m | 83: p | 84: l | 85: e | 86: x | 87: i | 88: t | 89: y | 90: = | 91: - | 92: 5 | 93:   | 94: = | 95:   | 96: 7 | 97: 5

---

### [VULN-EXPR-004] Use of Potentially Dangerous Function - ParseJSON(string)

**严重性**: Medium | **CWE**: CWE-676 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/core/src/expression/jsonparser/jsonparser.cpp:584-594` @ `ParseJSON(string)`
**模块**: expression
**跨模块**: jni_bindings,expression

**描述**: nlohmann::json::parse未捕获异常，JSON解析失败时抛出异常但JNI层处理不完整，可能导致资源泄漏或程序崩溃。

**漏洞代码** (`/core/src/expression/jsonparser/jsonparser.cpp:584-594`)

```c
expr = JSONParser::ParseJSON(nlohmann::json::parse(exprStr));
```

**达成路径**

[JNI] exprStr -> nlohmann::json::parse -> 可能抛出parse_error异常

**验证说明**: nlohmann::json::parse异常处理。JNI_METHOD_START/JNI_METHOD_END宏提供try-catch包装。异常可被捕获但可能导致JNI状态问题。

**评分明细**: base: 30 | reachability: [object Object] | mitigations: [object Object] | veto: null

---

### [VULN-SA-JNI-004] improper_input_validation - GetExprsFromJson

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_operator_factory.cpp:67-79` @ `GetExprsFromJson`
**模块**: jni_bindings
**跨模块**: jni_bindings → expression

**描述**: JSON expression strings received from Java are parsed directly using nlohmann::json::parse() without schema validation. These expressions are later used to construct executable expression trees. Malformed JSON could cause parsing exceptions, and crafted expressions could potentially create unsafe expression objects.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator_factory.cpp:67-79`)

```c
for (int32_t i = 0; i < keyCount; i++) {
    auto jsonExpression = nlohmann::json::parse(keysArr[i]);
    auto expression = JSONParser::ParseJSON(jsonExpression);
    if (expression == nullptr) {
        Expr::DeleteExprs(expressions);
        throw omniruntime::exception::OmniException("EXPRESSION_NOT_SUPPORT", "...");
    }
    expressions.push_back(expression);
}
```

**达成路径**

Java → jExpression (semi_trusted) → GetStringUTFChars → nlohmann::json::parse → JSONParser::ParseJSON → Expr objects (used in operator execution)

**验证说明**: JSON表达式解析无schema验证，恶意JSON可导致解析异常，但JNI层有异常处理机制部分缓解。

**评分明细**: base_score: 30 | reachability: indirect_external | reachability_score: 20 | controllability: partial | controllability_score: 15 | mitigations_found: nullptr_check,exception_handling | mitigation_score: -10 | final_score: 55

---

### [VULN-SA-JNI-006] improper_input_validation - Java_nova_hetu_omniruntime_operator_filter_OmniFilterAndProjectOperatorFactory_createFilterAndProjectOperatorFactory

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_operator_factory.cpp:458-530` @ `Java_nova_hetu_omniruntime_operator_filter_OmniFilterAndProjectOperatorFactory_createFilterAndProjectOperatorFactory`
**模块**: jni_bindings
**跨模块**: jni_bindings → expression → operator

**描述**: createFilterAndProjectOperatorFactory receives filter expression as jstring from Java, parses it directly without validation. The parsed expression is used to create an ExpressionEvaluator that executes on data vectors. Invalid expressions could cause runtime errors or unexpected behavior.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator_factory.cpp:458-530`)

```c
auto expressionCharPtr = env->GetStringUTFChars(jExpression, JNI_FALSE);
std::string filterExpression = std::string(expressionCharPtr);
...
auto filterJsonExpr = nlohmann::json::parse(filterExpression);
filterExpr = JSONParser::ParseJSON(filterJsonExpr);
```

**达成路径**

Java → jExpression (semi_trusted) → filterExpression string → json::parse → JSONParser::ParseJSON → filterExpr → ExpressionEvaluator

**验证说明**: filter表达式直接解析无验证，恶意表达式可导致解析器崩溃，但Spark/Hive层有部分过滤。

**评分明细**: base_score: 30 | reachability: direct_external | reachability_score: 30 | controllability: partial | controllability_score: 15 | mitigations_found: ExprVerifier,nullptr_check,IsSupportedExpr | mitigation_score: -25 | final_score: 50

---

### [JNI-009] Improper Input Validation - Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_parseOneRow

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator.cpp:348-356` @ `Java_nova_hetu_omniruntime_vector_serialize_OmniRowDeserializer_parseOneRow`
**模块**: jni_bindings

**描述**: parseOneRow函数获取byte数组元素后直接解析，rowIndex未验证是否在有效范围内。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator.cpp:348-356`)

```c
auto *row = env->GetByteArrayElements(bytes, &isCopy);\nparser->ParseOnRow(reinterpret_cast<uint8_t *>(row), rowIndex);
```

**达成路径**

[IN] bytes(jbyteArray) -> GetByteArrayElements -> ParseOnRow

**验证说明**: rowIndex (jint) passed from JNI to ParseOnRow without validation. ParseOnRow calls SetValue on vectors without bounds check. Negative or excessive rowIndex could cause out-of-bounds write. Trust boundary: Shuffle/Java adapter.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: ( | 23: i | 24: n | 25: d | 26: i | 27: r | 28: e | 29: c | 30: t | 31: _ | 32: e | 33: x | 34: t | 35: e | 36: r | 37: n | 38: a | 39: l | 40: , | 41: + | 42: 2 | 43: 0 | 44: ) | 45:   | 46: + | 47:   | 48: c | 49: o | 50: n | 51: t | 52: r | 53: o | 54: l | 55: l | 56: a | 57: b | 58: i | 59: l | 60: i | 61: t | 62: y | 63: ( | 64: p | 65: a | 66: r | 67: t | 68: i | 69: a | 70: l | 71: , | 72: + | 73: 1 | 74: 5 | 75: ) | 76:   | 77: = | 78:   | 79: 6 | 80: 5 | 81: . | 82:   | 83: r | 84: o | 85: w | 86: I | 87: n | 88: d | 89: e | 90: x | 91:   | 92: f | 93: r | 94: o | 95: m | 96:   | 97: S | 98: h | 99: u | 100: f | 101: f | 102: l | 103: e | 104:   | 105: d | 106: a | 107: t | 108: a | 109: , | 110:   | 111: n | 112: o | 113:   | 114: b | 115: o | 116: u | 117: n | 118: d | 119: s | 120:   | 121: c | 122: h | 123: e | 124: c | 125: k | 126: .

---

### [JNI-010] Integer Overflow or Wraparound - Java_nova_hetu_omniruntime_operator_topn_OmniTopNOperatorFactory_createTopNOperatorFactory

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator_factory.cpp:394-416` @ `Java_nova_hetu_omniruntime_operator_topn_OmniTopNOperatorFactory_createTopNOperatorFactory`
**模块**: jni_bindings

**描述**: 多处将jint/jlong直接转换为int32_t用于数组索引或大小，未检查负值或溢出。如jN、jOffset参数。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator_factory.cpp:394-416`)

```c
auto limit = (int32_t)jN;\nauto offset = static_cast<int32_t>(jOffset);
```

**达成路径**

[IN] jN(jint), jOffset(jint) -> int32_t转换 -> TopNOperatorFactory

**验证说明**: jN (limit) and jOffset from JNI passed to TopNOperatorFactory without validation. Negative limit causes pq.size() < limit always true (unlimited entries). Negative offset causes arithmetic underflow in totalRowCount - offset. Trust boundary: Spark/Hive query plan.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: ( | 23: i | 24: n | 25: d | 26: i | 27: r | 28: e | 29: c | 30: t | 31: _ | 32: e | 33: x | 34: t | 35: e | 36: r | 37: n | 38: a | 39: l | 40: , | 41: + | 42: 2 | 43: 0 | 44: ) | 45:   | 46: + | 47:   | 48: c | 49: o | 50: n | 51: t | 52: r | 53: o | 54: l | 55: l | 56: a | 57: b | 58: i | 59: l | 60: i | 61: t | 62: y | 63: ( | 64: p | 65: a | 66: r | 67: t | 68: i | 69: a | 70: l | 71: , | 72: + | 73: 1 | 74: 5 | 75: ) | 76:   | 77: = | 78:   | 79: 6 | 80: 5 | 81: . | 82:   | 83: L | 84: i | 85: m | 86: i | 87: t | 88: / | 89: o | 90: f | 91: f | 92: s | 93: e | 94: t | 95:   | 96: f | 97: r | 98: o | 99: m | 100:   | 101: q | 102: u | 103: e | 104: r | 105: y | 106:   | 107: p | 108: l | 109: a | 110: n | 111: , | 112:   | 113: n | 114: o | 115:   | 116: n | 117: e | 118: g | 119: a | 120: t | 121: i | 122: v | 123: e | 124:   | 125: v | 126: a | 127: l | 128: u | 129: e | 130:   | 131: c | 132: h | 133: e | 134: c | 135: k | 136: .

---

### [VULN-EXPR-003] Improper Neutralization - ParseJSONFunc

**严重性**: Medium | **CWE**: CWE-74 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/core/src/expression/jsonparser/jsonparser.cpp:405-502` @ `ParseJSONFunc`
**模块**: expression
**跨模块**: jni_bindings,expression,codegen

**描述**: funcName直接从JSON获取用于函数查找

**漏洞代码** (`/core/src/expression/jsonparser/jsonparser.cpp:405-502`)

```c
string funcName = jsonExpr["function_name"]
```

**达成路径**

[JNI] JSON字符串 -> ParseJSONFunc -> FunctionRegistry::LookupHiveUdf

**验证说明**: funcName从JSON直接读取用于函数查找。代码确认: jsonparser.cpp:407。FunctionRegistry::LookupFunction和LookupHiveUdf查询funcName。但未找到函数时返回nullptr，有部分缓解。

**评分明细**: base: 30 | reachability: [object Object] | mitigations: [object Object] | veto: null

---

### [VULN-SA-JNI-005] buffer_overflow - Java_nova_hetu_omniruntime_operator_sort_OmniSortOperatorFactory_createSortOperatorFactory

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-121 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_operator_factory.cpp:296-297` @ `Java_nova_hetu_omniruntime_operator_sort_OmniSortOperatorFactory_createSortOperatorFactory`
**模块**: jni_bindings

**描述**: Multiple JNI functions use Variable Length Arrays (VLA) with sizes from Java arrays without bounds validation. Large array lengths could cause stack overflow. Examples: int32_t sortColsArr[sortColsCount] in createSortOperatorFactory, std::string keysArr[groupByNum] in createHashAggregationWithExprOperatorFactory.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_operator_factory.cpp:296-297`)

```c
auto sortColsCount = env->GetArrayLength(jSortCols);
int32_t sortColsArr[sortColsCount];
```

**达成路径**

Java → jSortCols array length → sortColsCount → VLA allocation on stack

**验证说明**: VLA使用数组大小来自Java输入，超大数组可能导致栈溢出，但实际数据量通常有限制。

**评分明细**: base_score: 30 | reachability: direct_external | reachability_score: 30 | controllability: length_only | controllability_score: 10 | mitigations_found:  | mitigation_score: 0 | final_score: 70 | rationale: VLA (Variable Length Array) used with size from Java array length (line 296: int32_t sortColsArr[sortColsCount]). No bounds check on array length. Large arrays could cause stack overflow. Multiple similar patterns in jni_operator_factory.cpp (groupByCols, aggCols, etc.).

---

### [VULN-SEC-EXPR-002] integer_overflow - ParseJSONSwitch

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `core/src/expression/jsonparser/jsonparser.cpp:258-282` @ `ParseJSONSwitch`
**模块**: expression
**跨模块**: bindings/java → expression

**描述**: numOfCases从JSON输入直接读取为int32_t，用于循环控制但未进行边界验证。恶意输入可设置极大numOfCases值，导致内存耗尽或循环溢出。影响ParseJSONSwitch和ParseJSONSwitchGeneral函数。

**漏洞代码** (`core/src/expression/jsonparser/jsonparser.cpp:258-282`)

```c
auto numOfCases = jsonExpr["numOfCases"].get<int32_t>();
std::vector<std::pair<Expr *, Expr *>> whenClause;
for (int32_t i = 0; i < numOfCases; i++) {
    Expr *left = ParseJSON(jsonExpr["input"]); // 无边界检查
    ...
```

**达成路径**

jni_operator_factory.cpp:70 nlohmann::json::parse(keysArr[i]) [SOURCE]
jsonparser.cpp:258 numOfCases = jsonExpr["numOfCases"].get<int32_t>() [SINK - 无验证]

**验证说明**: numOfCases从JSON读取无边界验证。jsonparser.cpp:258/304。可能导致内存耗尽。但JSON来自Spark/Hive解析结果，非直接用户输入。

**评分明细**: base: 30 | reachability: [object Object] | mitigations: [object Object] | veto: null

---

### [VULN-TYPE-001] improper_input_validation - Deserialize

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/type/data_type_serializer.cpp:23-87` @ `Deserialize`
**模块**: type
**跨模块**: type → jni → operator

**描述**: JSON deserialization from semi-trusted source (Spark/Hive) lacks schema validation. Missing JSON fields trigger exceptions, potentially causing DoS. Uncontrolled type ID values and parameters flow directly to DataType constructors without bounds checking.

**漏洞代码** (`core/src/type/data_type_serializer.cpp:23-87`)

```c
DataTypes Deserialize(const std::string &dataTypes)
{
    auto dataTypeJsons = nlohmann::json::parse(dataTypes);
    ...
    int dataTypeId = dataTypeJson[ID].get<int>();
    switch (dataTypeId) { ... }
}
```

**达成路径**

Java_adapter:DataType_JSON@jni_operator_factory.cpp → Deserialize@data_type_serializer.cpp:23 → nlohmann::json::parse:25 → DataTypeJsonParser:39 → DataType constructors

**验证说明**: JSON反序列化缺少schema验证，但来自Spark/Hive而非直接用户输入。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: _ | 23: d | 24: i | 25: r | 26: e | 27: c | 28: t | 29: = | 30: 2 | 31: 5 | 32:   | 33: - | 34:   | 35: p | 36: a | 37: r | 38: t | 39: i | 40: a | 41: l | 42: _ | 43: m | 44: i | 45: t | 46: i | 47: g | 48: a | 49: t | 50: i | 51: o | 52: n | 53: = | 54: 1 | 55: 5 | 56:   | 57: + | 58:   | 59: c | 60: r | 61: o | 62: s | 63: s | 64: _ | 65: m | 66: o | 67: d | 68: u | 69: l | 70: e | 71: = | 72: 1 | 73: 0 | 74:   | 75: = | 76:   | 77: 5 | 78: 0

---

### [JNI-003] Improper Input Validation - GetExprsFromJson

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator_factory.cpp:67-79` @ `GetExprsFromJson`
**模块**: jni_bindings
**跨模块**: jni_bindings,expression

**描述**: JSON表达式解析函数GetExprsFromJson直接解析来自Java的字符串为JSON，无格式验证。恶意JSON可能导致解析异常或表达式注入。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator_factory.cpp:67-79`)

```c
auto jsonExpression = nlohmann::json::parse(keysArr[i]);\nauto expression = JSONParser::ParseJSON(jsonExpression);
```

**达成路径**

[IN] keysArr(string[]) -> json::parse -> JSONParser::ParseJSON -> expression(Expr*)

**验证说明**: GetExprsFromJson parses JSON without schema validation. But has nullptr check (line 72-76) and exception handling. Expression source is Spark/Hive SQL parser (semi-trusted). Risk is parsing errors/DoS, not code injection.

**评分明细**: base_score: 30 | reachability: indirect_external | reachability_score: 20 | controllability: partial | controllability_score: 15 | mitigations_found: nullptr_check_for_result,exception_handling | mitigation_score: -10 | final_score: 55 | rationale: JSON parsing without schema validation. However: 1) nullptr check on parsed result (line 72), 2) Exception thrown for unsupported expressions, 3) Expressions come from Spark/Hive SQL parser, not directly from user. Not a direct exploitable vulnerability but could cause DoS via parse errors.

---

### [VULN-SEC-EXPR-003] improper_input_validation - ParseJSONFieldRef

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `core/src/expression/jsonparser/jsonparser.cpp:22-38` @ `ParseJSONFieldRef`
**模块**: expression
**跨模块**: bindings/java → expression

**描述**: width/precision/scale值从JSON直接读取用于创建DataType对象，未进行边界验证。负数或极大值可能导致DataType构造异常、内存分配问题或运行时错误。

**漏洞代码** (`core/src/expression/jsonparser/jsonparser.cpp:22-38`)

```c
int width = jsonExpr["width"].get<int32_t>();
if (typeId == OMNI_CHAR) {
    retType = std::make_shared<CharDataType>(width); // width未验证
} else {
    retType = std::make_shared<VarcharDataType>(width); // width未验证
}
```

**达成路径**

jni_operator_factory.cpp:70 nlohmann::json::parse(keysArr[i]) [SOURCE]
jsonparser.cpp:22 width = jsonExpr["width"].get<int32_t>() [SINK]

**验证说明**: width/precision/scale值从JSON读取未验证。jsonparser.cpp:22-38。DataType构造函数可能有内部检查(INT_MAX限制)。风险降低但仍存在。

**评分明细**: base: 30 | reachability: [object Object] | mitigations: [object Object] | veto: null

---

### [VULN-TYPE-003] uncontrolled_recursion - DataTypeJsonParser

**严重性**: Medium | **CWE**: CWE-674 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/type/data_type_serializer.cpp:77-82` @ `DataTypeJsonParser`
**模块**: type
**跨模块**: type → jni

**描述**: ContainerType parsing recursively invokes DataTypeJsonParser for each fieldType. Deeply nested or cyclic type structures in malicious JSON could cause stack overflow, leading to DoS.

**漏洞代码** (`core/src/type/data_type_serializer.cpp:77-82`)

```c
case OMNI_CONTAINER: {
    std::vector<DataTypePtr> fieldTypes;
    for (const auto &fieldJson : dataTypeJson[FIELD_TYPES]) {
        fieldTypes.push_back(DataTypeJsonParser(fieldJson));
    }
    return ContainerType(fieldTypes);
}
```

**达成路径**

Java_adapter:DataType_JSON → Deserialize:23 → DataTypeJsonParser:39 → recursive call for fieldTypes → potential stack overflow

**验证说明**: ContainerType递归解析无深度限制，可能导致栈溢出。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: _ | 23: d | 24: i | 25: r | 26: e | 27: c | 28: t | 29: = | 30: 2 | 31: 5 | 32:   | 33: + | 34:   | 35: n | 36: o | 37: _ | 38: m | 39: i | 40: t | 41: i | 42: g | 43: a | 44: t | 45: i | 46: o | 47: n | 48: = | 49: 0 | 50:   | 51: + | 52:   | 53: c | 54: r | 55: o | 56: s | 57: s | 58: _ | 59: m | 60: o | 61: d | 62: u | 63: l | 64: e | 65: = | 66: 5 | 67:   | 68: = | 69:   | 70: 6 | 71: 0

---

### [VULN-SEC-UDF-002] insecure_external_input - CreateJavaVM

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/udf/cplusplus/jni_util.cpp:133-161` @ `CreateJavaVM`
**模块**: udf

**描述**: JVM创建时环境变量OMNI_OPERATOR_CLASSPATH未验证，直接用作JVM选项。若攻击者可控制此环境变量，可注入恶意classpath或潜在JVM选项。

**漏洞代码** (`core/src/udf/cplusplus/jni_util.cpp:133-161`)

```c
static void CreateJavaVM() {
    ...
    auto classPath = getenv("OMNI_OPERATOR_CLASSPATH");
    if (classPath == nullptr) {
        LogError("Create JVM failed...");
        return;
    }
    options[0].optionString = classPath;  // 直接使用，无验证
    ...
}
```

**达成路径**

1. jni_util.cpp:144 getenv("OMNI_OPERATOR_CLASSPATH") [SOURCE - 环境变量]
2. jni_util.cpp:149 options[0].optionString = classPath [无验证传播]
3. jni_util.cpp:157 JNI_CreateJavaVM(&javaVm, ..., &vmArgs) [SINK - JVM配置]

**验证说明**: OMNI_OPERATOR_CLASSPATH环境变量未验证，但由管理员控制。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: _ | 5: s | 6: c | 7: o | 8: r | 9: e | 10: = | 11: 3 | 12: 0 | 13:   | 14: + | 15:   | 16: r | 17: e | 18: a | 19: c | 20: h | 21: a | 22: b | 23: i | 24: l | 25: i | 26: t | 27: y | 28: _ | 29: i | 30: n | 31: d | 32: i | 33: r | 34: e | 35: c | 36: t | 37: = | 38: 2 | 39: 0 | 40:   | 41: + | 42:   | 43: c | 44: o | 45: n | 46: t | 47: r | 48: o | 49: l | 50: l | 51: a | 52: b | 53: i | 54: l | 55: i | 56: t | 57: y | 58: _ | 59: f | 60: u | 61: l | 62: l | 63: = | 64: 2 | 65: 5 | 66:   | 67: + | 68:   | 69: e | 70: n | 71: v | 72: = | 73: 1 | 74: 5 | 75:   | 76: = | 77:   | 78: 9 | 79: 0

---

### [VULN-SEC-UDF-003] configuration_tampering - GetOmniHome/GetConfigFilePath

**严重性**: Medium | **CWE**: CWE-15 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/util/config_util.cpp:19-41` @ `GetOmniHome/GetConfigFilePath`
**模块**: udf
**跨模块**: util → codegen → udf

**描述**: 配置文件路径受环境变量OMNI_HOME/OMNI_CONF控制，可指向恶意配置文件。恶意配置可设置hiveUdfPropertyFilePath指向伪造的UDF属性文件，从而控制可执行的Java类。

**漏洞代码** (`core/src/util/config_util.cpp:19-41`)

```c
static std::string GetOmniHome() {
    auto omniHome = std::getenv("OMNI_HOME");
    if (omniHome != nullptr && omniHome[0] != '\0') {
        return confDir;  // 环境变量控制
    }
}
static std::string GetConfigFilePath() {
    auto omniConf = std::getenv("OMNI_CONF");
    ...
    return confDir + confFile;  // 可指向任意路径
}
```

**达成路径**

1. config_util.cpp:21 getenv("OMNI_HOME") [SOURCE]
2. config_util.cpp:34 getenv("OMNI_CONF") [SOURCE]
3. config_util.cpp:47 LoadConf() → 加载配置
4. config_util.cpp:105 hiveUdfPropertyFilePath → UDF文件路径
5. func_registry_hive_udf.cpp:33 → 加载UDF映射
6. java_udf_functions.cpp → 执行指定UDF类

**验证说明**: 配置文件路径受环境变量控制，但为管理员信任边界。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: _ | 5: s | 6: c | 7: o | 8: r | 9: e | 10: = | 11: 3 | 12: 0 | 13:   | 14: + | 15:   | 16: r | 17: e | 18: a | 19: c | 20: h | 21: a | 22: b | 23: i | 24: l | 25: i | 26: t | 27: y | 28: _ | 29: i | 30: n | 31: d | 32: i | 33: r | 34: e | 35: c | 36: t | 37: = | 38: 2 | 39: 0 | 40:   | 41: + | 42:   | 43: c | 44: o | 45: n | 46: t | 47: r | 48: o | 49: l | 50: l | 51: a | 52: b | 53: i | 54: l | 55: i | 56: t | 57: y | 58: _ | 59: p | 60: a | 61: r | 62: t | 63: i | 64: a | 65: l | 66: = | 67: 2 | 68: 0 | 69:   | 70: + | 71:   | 72: m | 73: i | 74: t | 75: i | 76: g | 77: a | 78: t | 79: i | 80: o | 81: n | 82: = | 83: - | 84: 5 | 85:   | 86: = | 87:   | 88: 8 | 89: 5

---

### [VULN-SEC-VEC-001] array_index_validation_missing - Vector::CopyPositions

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-129 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/vector/vector.h:336-358` @ `Vector::CopyPositions`
**模块**: vector

**描述**: Vector::CopyPositions方法中，从positions数组读取的位置值未进行边界验证。当position不为-1(null标记)且超出当前向量边界时，调用IsNull(position)、GetValue(position)会导致越界访问，可能引发内存破坏。

**漏洞代码** (`core/src/vector/vector.h:336-358`)

```c
for (int32_t i = 0; i < length; i++) {
    int position = startPositions[i];
    if (UNLIKELY(position == -1)) { ... }
    if (UNLIKELY(IsNull(position))) { ... }
    vector->SetValue(i, GetValue(position));
}
```

**达成路径**

positions数组 → startPositions[i] → position → IsNull(position) → GetValue(position) [SINK: 越界访问]

**验证说明**: Vector::CopyPositions中positions数组未验证边界，但positions来源为内部计算而非直接外部输入。

---

### [VULN-SEC-VEC-002] array_index_validation_missing - ArrayVector::CopyPositions

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-129 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/vector/array_vector.cpp:47-87` @ `ArrayVector::CopyPositions`
**模块**: vector
**跨模块**: vector → memory

**描述**: ArrayVector::CopyPositions方法中，positions数组中的位置值未验证是否在源向量边界内。直接调用GetOffset(position)和GetSize(position)访问offsets数组可能导致越界。

**漏洞代码** (`core/src/vector/array_vector.cpp:47-87`)

```c
int position = startPositions[i];
if (UNLIKELY(position == -1)) { ... }
int elementIndex = this->GetOffset(position);
int elementSize = this->GetSize(position);
```

**达成路径**

positions → startPositions[i] → position → GetOffset(position) → offsets[position] [SINK: 越界读]

**验证说明**: ArrayVector::CopyPositions未验证positions边界，但来源为内部计算。

---

### [VULN-SEC-VEC-003] array_index_validation_missing - MapVector::CopyPositions

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-129 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/vector/map_vector.cpp:16-62` @ `MapVector::CopyPositions`
**模块**: vector
**跨模块**: vector → memory

**描述**: MapVector::CopyPositions方法中，positions数组的位置值未验证边界。调用GetOffset(position)和GetSize(position)访问offsets数组可能导致越界读。

**漏洞代码** (`core/src/vector/map_vector.cpp:16-62`)

```c
int position = startPositions[i];
if (UNLIKELY(IsNull(position))) { ... }
int keyIndex = this->GetOffset(position);
int keySize = this->GetSize(position);
```

**达成路径**

positions → startPositions[i] → position → GetOffset(position) → offsets[position] [SINK: 越界读]

**验证说明**: MapVector::CopyPositions类似VEC-002，内部计算来源。

---

### [simd-001] Buffer Overflow - QuickSortAscSIMD/QuickSortDescSIMD

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-121 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `core/src/simd/func/quick_sort_simd.cpp:369-384` @ `QuickSortAscSIMD/QuickSortDescSIMD`
**模块**: simd

**描述**: Fixed-size stack buffer allocated without validating input array size in QuickSortAscSIMD/QuickSortDescSIMD functions. BUFFER_SIZE=50 is used as stack buffer size, but no validation ensures input array length fits within this limit, potentially causing stack overflow for large arrays.

**漏洞代码** (`core/src/simd/func/quick_sort_simd.cpp:369-384`)

```c
ValType valueBuf[BUFFER_SIZE]; // BUFFER_SIZE=50, no size check
```

**达成路径**

from/to parameters -> valueBuf[50]/addrBuf[50] -> potential stack overflow

**验证说明**: BUFFER_SIZE=50 is adequate for typical SIMD partitioning operations (DrawSamples uses 3*OMNI_LANES=6-12 elements, PartitionWithSIMD uses buffer for CompressStore). However, no explicit bounds validation exists. Algorithm recursion limits buffer usage per call. Mitigation: caller constraints and algorithm design.

---

### [simd-002] Stack Buffer Overflow - SmallCaseSortAsec/SmallCaseSortDesc

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-121 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `core/src/simd/func/small_case_sort.h:1370-1398` @ `SmallCaseSortAsec/SmallCaseSortDesc`
**模块**: simd

**描述**: MAX_LEVELS=50 stack buffer allocated in SmallCaseSortAsec/SmallCaseSortDesc without validating dataLen. If dataLen exceeds MAX_LEVELS, stack buffer overflow occurs.

**漏洞代码** (`core/src/simd/func/small_case_sort.h:1370-1398`)

```c
OMNI_ALIGN RawDataType valueBuf[MAX_LEVELS]; // MAX_LEVELS=50, no check if dataLen > MAX_LEVELS
```

**达成路径**

dataLen=to-from -> valueBuf[50]/addrBuf[50] -> stack overflow if dataLen > 50

**验证说明**: MAX_LEVELS=50 stack buffer without size validation. Usage pattern mitigates: QuickSortInternalSIMD only calls with dataLen<=SMALL_CASE_LENGTH(16). However, functions can be called directly with larger sizes causing overflow. No explicit bounds check.

---

### [JNI-007] Improper Input Validation - Java_nova_hetu_omniruntime_operator_filter_OmniFilterAndProjectOperatorFactory_createFilterAndProjectOperatorFactory

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator_factory.cpp:458-530` @ `Java_nova_hetu_omniruntime_operator_filter_OmniFilterAndProjectOperatorFactory_createFilterAndProjectOperatorFactory`
**模块**: jni_bindings
**跨模块**: jni_bindings,expression

**描述**: createFilterAndProjectOperatorFactory解析JSON表达式串，filterExpression和projectExpressions来自Java端无验证。恶意表达式可能导致解析器崩溃或代码注入。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator_factory.cpp:458-530`)

```c
auto filterJsonExpr = nlohmann::json::parse(filterExpression);\nfilterExpr = JSONParser::ParseJSON(filterJsonExpr);
```

**达成路径**

[IN] jExpression(jstring) -> json::parse -> JSONParser::ParseJSON -> ExpressionEvaluator

**验证说明**: Multiple mitigations: ExprVerifier (expr_verifier.cpp) validates expression types and operations. nullptr check at line 503. IsSupportedExpr at line 523. Not a direct exploitable vulnerability.

**评分明细**: base_score: 30 | reachability: direct_external | reachability_score: 30 | controllability: partial | controllability_score: 15 | mitigations_found: ExprVerifier_check,nullptr_check,IsSupportedExpr_check | mitigation_score: -25 | final_score: 50 | rationale: Expression parsing in createFilterAndProjectOperatorFactory. Mitigations present: 1) ExprVerifier validates expression structure (lines 509-518), 2) nullptr check on parsed result (lines 503-507), 3) IsSupportedExpr check (line 523). Expressions from Spark/Hive SQL parser (semi-trusted).

---

### [VULN-CODEGEN-003] Unsafe Symbol Registration - LLVMEngine::Compile/RegisterFunctions

**严重性**: Medium | **CWE**: CWE-749 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/core/src/codegen/llvm_engine.cpp:71-129` @ `LLVMEngine::Compile/RegisterFunctions`
**模块**: codegen
**跨模块**: operator

**描述**: LLVMEngine::RegisterFunctions registers external function addresses directly without validation. The func.GetAddress() is used to create JITEvaluatedSymbol with Exported flags. Combined with DynamicLibrarySearchGenerator::GetForCurrentProcess, this exposes all process symbols potentially allowing JIT code to call arbitrary functions.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/core/src/codegen/llvm_engine.cpp:71-129`)

```c
jit->getMainJITDylib().addGenerator(\n    eoe(DynamicLibrarySearchGenerator::GetForCurrentProcess(...)));\nauto s = llvm::orc::absoluteSymbols({ { mangle(func.GetId()),\n    JITEvaluatedSymbol(pointerToJITTargetAddress(func.GetAddress()), JITSymbolFlags::Exported) } });
```

**达成路径**

[IN] Function addresses <- FunctionRegistry\n[PROCESS] RegisterFunctions -> jit->addIRModule\n[OUT] JIT compiled code -> operator module (expression evaluation)

**验证说明**: CONFIRMED CODE PRESENT: DynamicLibrarySearchGenerator::GetForCurrentProcess exposes process symbols. This is a design choice for JIT functionality. Security risk if combined with untrusted expression input.

**评分明细**: base: 30 | reachability: 20 | mitigations: 0 | reason: DynamicLibrarySearchGenerator::GetForCurrentProcess at line 74 exposes all process symbols. JITEvaluatedSymbol with Exported flags at line 118.

---

### [VULN-CODEGEN-005] Format String - FromUnixTime/FromUnixTimeWithoutTz

**严重性**: Medium | **CWE**: CWE-134 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/core/src/codegen/functions/datetime_functions.cpp:57-96` @ `FromUnixTime/FromUnixTimeWithoutTz`
**模块**: codegen
**跨模块**: expression,vector

**描述**: FromUnixTime functions use user-provided format string directly in strftime without proper validation. The fmtStr is converted via toOmniTimeFormat but the resulting format string is passed directly to strftime which could contain format specifiers beyond the expected set, potentially causing buffer issues or information exposure.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/core/src/codegen/functions/datetime_functions.cpp:57-96`)

```c
std::string fmt(fmtStr, fmtLen);\nstd::string fmtOmniTimeStr = toOmniTimeFormat(fmtStr1);\nint ret = strftime(result, resultLen, fmtOmniTimeStr.c_str(), &ltm);
```

**达成路径**

[IN] fmtStr <- expression module\n[PROCESS] toOmniTimeFormat -> strftime\n[OUT] formatted string -> vector module

**验证说明**: PARTIAL CONFIRMATION: Format string passed through toOmniTimeFormat which only does limited conversions (yyyy/MM/dd etc). strftime itself handles format specifiers safely - no buffer overflow risk.

**评分明细**: base: 30 | reachability: 20 | mitigations: 0 | reason: toOmniTimeFormat at lines 98-111 does limited conversion. strftime at line 71/92 handles format specifiers safely.

---

### [VULN-XMOD-003] static_initialization_config_inconsistency - GetProperties

**严重性**: Medium | **CWE**: CWE-457 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `core/src/util/config_util.h:102-106` @ `GetProperties`
**模块**: cross_module
**跨模块**: util → operator → compute → udf

**描述**: 静态初始化顺序问题导致跨模块配置不一致。config_util.h在头文件中定义static g_properties并直接初始化，违反C++静态初始化最佳实践：(1) 每个编译单元有独立副本；(2) 静态初始化顺序未定义；(3) 导致不同模块(operator/aggregation、operator/sort、compute/task等)可能使用不同的安全策略配置。

**达成路径**

util/config_util.h:102 → static Properties g_properties → 每个包含头文件的编译单元独立副本 → operator/aggregation.cpp, operator/sort.cpp, compute/task.cpp 等使用不一致的配置值

**验证说明**: VERIFIED: Static initialization design flaw confirmed. (1) config_util.h:102 declares static Properties g_properties = ConfigUtil::CreateProperties() in header. (2) Each translation unit gets independent copy. (3) Static initialization order undefined (C++ SIOF). (4) Modules (operator, aggregation, sort, compute, udf) may use different config values. Limited security impact - more of a reliability issue. Not a direct attack vector. Reachability: N/A. Cross-file: chain_complete(0). Score: 30+0+15(design_issue)=45.

---

### [VULN-TYPE-007] Integer Overflow or Wrap-around - Decimal128::Decimal128

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `core/src/type/decimal128.h:27-42` @ `Decimal128::Decimal128`
**模块**: type

**描述**: Decimal128字符串构造函数中value累加缺少溢出检查。循环中value *= 10和value += digit可能导致int128_t溢出，特别是处理超长数字字符串时。

**漏洞代码** (`core/src/type/decimal128.h:27-42`)

```c
for (char i : s) { if (isdigit(i)) { value *= 10; value += i - '0'; } }
```

**达成路径**

[IN] 数字字符串 -> value累乘加 -> int128_t溢出

**验证说明**: Decimal128 string constructor (decimal128.h:27-42) accumulates value without overflow check: value *= 10; value += i - 0;. int128_t has huge range (~10^38), so overflow requires extremely long numeric strings (39+ digits). Reachability: INDIRECT via Decimal128Type constructor at data_type_serializer.cpp:64. Mitigation: PARTIAL - int128_t range makes overflow unlikely for normal inputs.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: _ | 23: i | 24: n | 25: d | 26: i | 27: r | 28: e | 29: c | 30: t | 31: = | 32: 2 | 33: 0 | 34:   | 35: - | 36:   | 37: p | 38: a | 39: r | 40: t | 41: i | 42: a | 43: l | 44: _ | 45: m | 46: i | 47: t | 48: i | 49: g | 50: a | 51: t | 52: i | 53: o | 54: n | 55: = | 56: 1 | 57: 0 | 58:   | 59: = | 60:   | 61: 4 | 62: 0

---

### [OP-VULN-003] Buffer Overflow - VariableTypeDeserializer

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-120 | **置信度**: 40/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/core/src/operator/hashmap/vector_marshaller.cpp:20-50` @ `VariableTypeDeserializer`
**模块**: operator
**跨模块**: operator,hashmap,vector

**描述**: VariableTypeDeserializer reads rowLenSize and stringLen from serialized data without bounds validation. stringLen is read directly from buffer and used to create string_view. If stringLen is maliciously crafted, this could lead to out-of-bounds memory read.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/core/src/operator/hashmap/vector_marshaller.cpp:20-50`)

```c
auto rowLenSize = *reinterpret_cast<const uint8_t *>(pos);\nswitch (rowLenSize) {\n    case BYTE_1: stringLen = *reinterpret_cast<const int8_t *>(pos + 1); break;\n    ...\n}\nstd::string_view strView(pos, stringLen);
```

**达成路径**

[IN] Serialized data pos -> rowLenSize -> stringLen -> string_view(pos, stringLen)

**验证说明**: LIKELY: VariableTypeDeserializer lacks bounds validation for stringLen. Used internally for hash table serialization. Mitigated by internal-only access but missing explicit bounds check.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7: , | 8: r | 9: e | 10: a | 11: c | 12: h | 13: a | 14: b | 15: i | 16: l | 17: i | 18: t | 19: y | 20: : | 21: i | 22: n | 23: t | 24: e | 25: r | 26: n | 27: a | 28: l | 29: _ | 30: o | 31: n | 32: l | 33: y | 34: ( | 35: + | 36: 5 | 37: ) | 38: , | 39: m | 40: i | 41: t | 42: i | 43: g | 44: a | 45: t | 46: i | 47: o | 48: n | 49: : | 50: n | 51: o | 52: n | 53: e | 54: ( | 55: 0 | 56: ) | 57: , | 58: t | 59: o | 60: t | 61: a | 62: l | 63: : | 64: 3 | 65: 5

---

### [VULN-SEC-COMP-005] null_pointer_dereference - createOperator

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-476 | **置信度**: 40/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `core/src/compute/local_planner.cpp:33-39` @ `createOperator`
**模块**: compute
**跨模块**: compute → operator

**描述**: In local_planner.cpp, createOperator() result is passed directly to emplace_back without null check. If factory->CreateOperator() returns nullptr or throws, the code continues assuming valid operator, leading to null pointer dereference when accessing operator methods.

**漏洞代码** (`core/src/compute/local_planner.cpp:33-39`)

```c
std::shared_ptr<omniruntime::op::Operator> operatorPtr(factory->CreateOperator());
operatorPtr->setNoMoreInput(false);
operatorPtr->SetPlanNodeId(planNode->Id());
```

**达成路径**

factory->CreateOperator() may return nullptr
→ operatorPtr (shared_ptr) wraps nullptr
→ operatorPtr->setNoMoreInput(false) dereferences nullptr
→ Crash or undefined behavior

**验证说明**: Verified pattern at local_planner.cpp:33-39. factory->CreateOperator() result wrapped in shared_ptr without null check. operator_factory.h:18-21 shows base OperatorFactory::CreateOperator() returns nullptr by default. While derived classes typically return valid pointers or throw, defensive null check is strongly recommended before operatorPtr->setNoMoreInput() dereference.

**评分明细**: 0: { | 1: " | 2: b | 3: a | 4: s | 5: e | 6: " | 7: : | 8: 3 | 9: 0 | 10: , | 11: " | 12: r | 13: e | 14: a | 15: c | 16: h | 17: a | 18: b | 19: i | 20: l | 21: i | 22: t | 23: y | 24: " | 25: : | 26: " | 27: i | 28: n | 29: t | 30: e | 31: r | 32: n | 33: a | 34: l | 35: _ | 36: o | 37: n | 38: l | 39: y | 40: " | 41: : | 42: 5 | 43: , | 44: " | 45: c | 46: r | 47: o | 48: s | 49: s | 50: _ | 51: m | 52: o | 53: d | 54: u | 55: l | 56: e | 57: " | 58: : | 59: 5 | 60: , | 61: " | 62: c | 63: o | 64: d | 65: e | 66: _ | 67: v | 68: e | 69: r | 70: i | 71: f | 72: i | 73: e | 74: d | 75: " | 76: : | 77: 5 | 78: , | 79: " | 80: m | 81: i | 82: t | 83: i | 84: g | 85: a | 86: t | 87: i | 88: n | 89: g | 90: " | 91: : | 92: - | 93: 5 | 94: , | 95: " | 96: f | 97: i | 98: n | 99: a | 100: l | 101: " | 102: : | 103: 4 | 104: 0 | 105: }

---

## 6. Low 漏洞 (20)

### [udf-004] memory_leak - ExecHiveUdfOutputString

**严重性**: Low | **CWE**: CWE-401 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `core/src/udf/cplusplus/java_udf_functions.cpp:102-132` @ `ExecHiveUdfOutputString`
**模块**: udf

**描述**: ExecHiveUdfOutputString allocates OutputState with new but has incomplete cleanup paths. The outputState object is only deleted in exception handler and normal completion, but intermediate exceptions could lead to memory leak. Also jUdfClassName local reference may not be released in all error paths.

**达成路径**

new OutputState -> loop execution -> potential exception -> incomplete cleanup

**验证说明**: VERIFIED: java_udf_functions.cpp:102 new OutputState is deleted at line 118 (exception) and 132 (normal completion). jUdfClassName deleted at lines 72, 117, 131, 163. Cleanup paths appear complete. However, if exception occurs after line 108 ArenaAllocatorMalloc but before line 117, potential for Arena corruption. Memory leak unlikely to be exploitable.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: _ | 5: s | 6: c | 7: o | 8: r | 9: e | 10: = | 11: 3 | 12: 0 | 13:   | 14: + | 15:   | 16: r | 17: e | 18: a | 19: c | 20: h | 21: a | 22: b | 23: i | 24: l | 25: i | 26: t | 27: y | 28: _ | 29: i | 30: n | 31: d | 32: i | 33: r | 34: e | 35: c | 36: t | 37: = | 38: 1 | 39: 0 | 40:   | 41: + | 42:   | 43: c | 44: o | 45: n | 46: t | 47: r | 48: o | 49: l | 50: l | 51: a | 52: b | 53: i | 54: l | 55: i | 56: t | 57: y | 58: _ | 59: l | 60: o | 61: w | 62: = | 63: 1 | 64: 0 | 65:   | 66: + | 67:   | 68: l | 69: o | 70: w | 71: _ | 72: e | 73: x | 74: p | 75: l | 76: o | 77: i | 78: t | 79: a | 80: b | 81: i | 82: l | 83: i | 84: t | 85: y | 86: = | 87: 2 | 88: 0 | 89:   | 90: = | 91:   | 92: 7 | 93: 0

---

### [JNI-004] Type Confusion - GetColumnsFromExpressions

**严重性**: Low | **CWE**: CWE-843 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator_factory.cpp:47-55` @ `GetColumnsFromExpressions`
**模块**: jni_bindings

**描述**: GetColumnsFromExpressions函数使用std::stoi解析列号字符串，但字符串格式未验证。columnString+1操作假设特定格式，格式不符时可能抛出异常或解析错误值。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator_factory.cpp:47-55`)

```c
const char *columnString = env->GetStringUTFChars(jSortCol, JNI_FALSE);\ncolumns[i] = std::stoi(columnString + 1);
```

**达成路径**

[IN] jSortCol(jstring) -> GetStringUTFChars -> stoi(columnString+1)

**验证说明**: std::stoi(columnString+1) assumes format with prefix character. Malformed input can cause std::invalid_argument exception. This is robustness/error handling issue rather than exploitable type confusion. No memory corruption path identified.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: ( | 23: i | 24: n | 25: d | 26: i | 27: r | 28: e | 29: c | 30: t | 31: _ | 32: e | 33: x | 34: t | 35: e | 36: r | 37: n | 38: a | 39: l | 40: , | 41: + | 42: 2 | 43: 0 | 44: ) | 45:   | 46: + | 47:   | 48: c | 49: o | 50: n | 51: t | 52: r | 53: o | 54: l | 55: l | 56: a | 57: b | 58: i | 59: l | 60: i | 61: t | 62: y | 63: ( | 64: p | 65: a | 66: r | 67: t | 68: i | 69: a | 70: l | 71: , | 72: + | 73: 1 | 74: 5 | 75: ) | 76:   | 77: - | 78:   | 79: m | 80: i | 81: s | 82: c | 83: ( | 84: - | 85: 1 | 86: 0 | 87: ) | 88:   | 89: = | 90:   | 91: 5 | 92: 5 | 93: . | 94:   | 95: F | 96: o | 97: r | 98: m | 99: a | 100: t | 101:   | 102: a | 103: s | 104: s | 105: u | 106: m | 107: p | 108: t | 109: i | 110: o | 111: n | 112:   | 113: i | 114: s | 115: s | 116: u | 117: e | 118: , | 119:   | 120: p | 121: r | 122: i | 123: m | 124: a | 125: r | 126: i | 127: l | 128: y | 129:   | 130: r | 131: o | 132: b | 133: u | 134: s | 135: t | 136: n | 137: e | 138: s | 139: s | 140:   | 141: c | 142: o | 143: n | 144: c | 145: e | 146: r | 147: n | 148:   | 149: n | 150: o | 151: t | 152:   | 153: m | 154: e | 155: m | 156: o | 157: r | 158: y | 159:   | 160: s | 161: a | 162: f | 163: e | 164: t | 165: y | 166: .

---

### [JNI-002] Stack Buffer Overflow - Transform

**严重性**: Low | **CWE**: CWE-121 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator.cpp:91-110` @ `Transform`
**模块**: jni_bindings

**描述**: Transform函数使用变长数组(VLA)存储向量地址，vecCount来自GetVectorCount()未验证。超大vecCount可能导致栈溢出。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_operator.cpp:91-110`)

```c
int32_t vecCount = result.GetVectorCount();\nint64_t vecAddresses[vecCount];\nint32_t encodings[vecCount];\n// ... 多个VLA数组
```

**达成路径**

[IN] vecCount(int32_t) -> VLA分配 -> 栈空间使用

**验证说明**: VLA arrays on stack without bounds check. However, vecCount is derived from internal VectorBatch (operator output), not directly controllable from JNI. Exploitability requires corrupting internal operator state. Trust boundary: internal processing.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: ( | 23: i | 24: n | 25: t | 26: e | 27: r | 28: n | 29: a | 30: l | 31: _ | 32: o | 33: n | 34: l | 35: y | 36: , | 37: + | 38: 5 | 39: ) | 40:   | 41: + | 42:   | 43: c | 44: o | 45: n | 46: t | 47: r | 48: o | 49: l | 50: l | 51: a | 52: b | 53: i | 54: l | 55: i | 56: t | 57: y | 58: ( | 59: p | 60: a | 61: r | 62: t | 63: i | 64: a | 65: l | 66: , | 67: + | 68: 1 | 69: 5 | 70: ) | 71:   | 72: = | 73:   | 74: 5 | 75: 0 | 76: . | 77:   | 78: v | 79: e | 80: c | 81: C | 82: o | 83: u | 84: n | 85: t | 86:   | 87: f | 88: r | 89: o | 90: m | 91:   | 92: i | 93: n | 94: t | 95: e | 96: r | 97: n | 98: a | 99: l | 100:   | 101: o | 102: p | 103: e | 104: r | 105: a | 106: t | 107: o | 108: r | 109:   | 110: o | 111: u | 112: t | 113: p | 114: u | 115: t | 116: , | 117:   | 118: n | 119: o | 120: t | 121:   | 122: d | 123: i | 124: r | 125: e | 126: c | 127: t | 128:   | 129: J | 130: N | 131: I | 132:   | 133: c | 134: o | 135: n | 136: t | 137: r | 138: o | 139: l | 140: . | 141:   | 142: L | 143: i | 144: m | 145: i | 146: t | 147: e | 148: d | 149:   | 150: e | 151: x | 152: p | 153: l | 154: o | 155: i | 156: t | 157: a | 158: b | 159: i | 160: l | 161: i | 162: t | 163: y | 164:   | 165: t | 166: h | 167: r | 168: o | 169: u | 170: g | 171: h | 172:   | 173: S | 174: Q | 175: L | 176:   | 177: s | 178: c | 179: h | 180: e | 181: m | 182: a | 183: .

---

### [VULN-SA-JNI-008] integer_overflow - Java_nova_hetu_omniruntime_vector_Vec_newVectorNative

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `bindings/java/src/main/cpp/src/jni_vector.cpp:40-55` @ `Java_nova_hetu_omniruntime_vector_Vec_newVectorNative`
**模块**: jni_bindings
**跨模块**: jni_bindings → vector

**描述**: newVectorNative receives jint values from Java for vector creation. Negative or extremely large values for jValueCount or jCapacityInBytes could cause integer overflow in allocation calculations.

**漏洞代码** (`bindings/java/src/main/cpp/src/jni_vector.cpp:40-55`)

```c
JNIEXPORT jlong JNICALL Java_nova_hetu_omniruntime_vector_Vec_newVectorNative(JNIEnv *env, jclass jcls,
    jint jValueCount, jint jVectorEncodingId, jint jVectorTypeId, jint jCapacityInBytes)
{
    BaseVector *vector = nullptr;
    JNI_METHOD_START
    vector = VectorHelper::CreateVector(jVectorEncodingId, jVectorTypeId, jValueCount, jCapacityInBytes);
```

**达成路径**

Java → jint jValueCount, jCapacityInBytes → VectorHelper::CreateVector → memory allocation

**验证说明**: jint值可能整数溢出，但VectorHelper有内部检查。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: ( | 23: d | 24: i | 25: r | 26: e | 27: c | 28: t | 29: _ | 30: e | 31: x | 32: t | 33: e | 34: r | 35: n | 36: a | 37: l | 38: , | 39: + | 40: 3 | 41: 0 | 42: ) | 43:   | 44: + | 45:   | 46: c | 47: o | 48: n | 49: t | 50: r | 51: o | 52: l | 53: l | 54: a | 55: b | 56: i | 57: l | 58: i | 59: t | 60: y | 61: ( | 62: f | 63: u | 64: l | 65: l | 66: , | 67: + | 68: 2 | 69: 5 | 70: ) | 71:   | 72: - | 73:   | 74: m | 75: i | 76: t | 77: i | 78: g | 79: a | 80: t | 81: i | 82: o | 83: n | 84: s | 85: ( | 86: b | 87: o | 88: u | 89: n | 90: d | 91: s | 92: _ | 93: c | 94: h | 95: e | 96: c | 97: k | 98: , | 99: - | 100: 1 | 101: 5 | 102: ) | 103:   | 104: = | 105:   | 106: 7 | 107: 0 | 108: . | 109:   | 110: M | 111: e | 112: m | 113: o | 114: r | 115: y | 116:   | 117: a | 118: l | 119: l | 120: o | 121: c | 122: a | 123: t | 124: o | 125: r | 126:   | 127: p | 128: r | 129: o | 130: v | 131: i | 132: d | 133: e | 134: s | 135:   | 136: i | 137: m | 138: p | 139: l | 140: i | 141: c | 142: i | 143: t | 144:   | 145: b | 146: o | 147: u | 148: n | 149: d | 150: s | 151: .

---

### [VULN-SEC-EXPR-006] improper_input_validation - ParseJSONFieldRef

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/expression/jsonparser/jsonparser.cpp:20-39` @ `ParseJSONFieldRef`
**模块**: expression
**跨模块**: bindings/java → expression

**描述**: colVal字段索引从JSON直接读取用于FieldExpr构造，未验证是否在合法列索引范围内。可能导致后续数据访问越界。

**漏洞代码** (`core/src/expression/jsonparser/jsonparser.cpp:20-39`)

```c
auto colVal = jsonExpr["colVal"].get<int32_t>();
...
return new FieldExpr(colVal, std::move(retType)); // colVal未验证范围
```

**达成路径**

jni_operator_factory.cpp:70 nlohmann::json::parse(keysArr[i]) [SOURCE]
jsonparser.cpp:20 colVal = jsonExpr["colVal"].get<int32_t>() -> FieldExpr [SINK]

**验证说明**: colVal字段索引从JSON读取无范围验证。jsonparser.cpp:20。后续使用中可能导致越界。但来自内部解析。

**评分明细**: base: 30 | reachability: [object Object] | mitigations: [object Object] | veto: null

---

### [VULN-TYPE-002] uncontrolled_resource_consumption - DataTypeJsonParser

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-789 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/type/data_type_serializer.cpp:74-76` @ `DataTypeJsonParser`
**模块**: type
**跨模块**: type → jni

**描述**: Width parameter for VarcharType and CharType is extracted directly from JSON without upper bound validation. Malicious JSON with excessive width values (e.g., UINT32_MAX) could lead to memory allocation failures or resource exhaustion downstream.

**漏洞代码** (`core/src/type/data_type_serializer.cpp:74-76`)

```c
case OMNI_VARCHAR:
    return VarcharType(dataTypeJson[WIDTH].get<uint32_t>());
case OMNI_CHAR:
    return CharType(dataTypeJson[WIDTH].get<uint32_t>());
```

**达成路径**

Java_adapter:DataType_JSON → Deserialize:23 → DataTypeJsonParser:39 → dataTypeJson[WIDTH].get<uint32_t>() → VarcharType/CharType constructor

**验证说明**: Width参数无上限验证，但实际使用场景有限。

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: _ | 23: d | 24: i | 25: r | 26: e | 27: c | 28: t | 29: = | 30: 2 | 31: 5 | 32:   | 33: + | 34:   | 35: n | 36: o | 37: _ | 38: m | 39: i | 40: t | 41: i | 42: g | 43: a | 44: t | 45: i | 46: o | 47: n | 48: = | 49: 0 | 50:   | 51: + | 52:   | 53: c | 54: r | 55: o | 56: s | 57: s | 58: _ | 59: m | 60: o | 61: d | 62: u | 63: l | 64: e | 65: = | 66: 5 | 67:   | 68: = | 69:   | 70: 6 | 71: 0

---

### [JNI-008] Null Pointer Dereference - TransformVector

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-476 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_vector.cpp:22-25` @ `TransformVector`
**模块**: jni_bindings

**描述**: TransformVector函数直接将jlong转换为BaseVector指针，无有效性检查。被多个JNI函数调用。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/bindings/java/src/main/cpp/src/jni_vector.cpp:22-25`)

```c
static ALWAYS_INLINE BaseVector *TransformVector(long vectorAddr)\n{\n    return reinterpret_cast<BaseVector *>(vectorAddr);\n}
```

**达成路径**

[IN] vectorAddr(jlong) -> reinterpret_cast -> BaseVector*

**验证说明**: TransformVector is a static helper, not a JNI entry point. Caller functions have varying null check coverage. freeVectorNative has check at line 113, others don't. Low confidence due to indirect exposure.

**评分明细**: base_score: 30 | reachability: internal_only | reachability_score: 5 | controllability: partial | controllability_score: 15 | mitigations_found: caller_null_check_partial | mitigation_score: -5 | final_score: 45 | rationale: Static inline helper function, not directly exposed. Some callers have null checks (e.g., freeVectorNative line 113, getCapacityInBytesNative line 123). Depends on caller context for exploitability.

---

### [VULN-SEC-EXPR-004] resource_exhaustion - ParseJSONLiteral

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-400 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/expression/jsonparser/jsonparser.cpp:102-114` @ `ParseJSONLiteral`
**模块**: expression
**跨模块**: bindings/java → expression

**描述**: 字符串值从JSON直接读取并动态分配string对象，未限制字符串长度。攻击者可传入极大字符串值导致内存耗尽。

**漏洞代码** (`core/src/expression/jsonparser/jsonparser.cpp:102-114`)

```c
case OMNI_DECIMAL128: {
    auto *dec128String = new string(jsonExpr["value"].get<string>()); // 无长度限制
    ...
}
case OMNI_CHAR: {
    auto *stringVal = new string(jsonExpr["value"].get<string>()); // 无长度限制
    ...
}
```

**达成路径**

jni_operator_factory.cpp:70 nlohmann::json::parse(keysArr[i]) [SOURCE]
jsonparser.cpp:102 new string(jsonExpr["value"].get<string>()) [SINK]

**验证说明**: 字符串值动态分配无长度限制。jsonparser.cpp:102-114。但JSON来自Spark/Hive解析，有间接缓解。实际攻击面较低。

**评分明细**: base: 30 | reachability: [object Object] | mitigations: [object Object] | veto: null

---

### [OP-VULN-002] Integer Overflow or Wrap-around - SpillReader::ReadVecBatch

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/core/src/operator/spill/spill_merger.cpp:21-109` @ `SpillReader::ReadVecBatch`
**模块**: operator
**跨模块**: operator,vector

**描述**: SpillReader::ReadVecBatch reads rowCount from spill file without adequate bounds validation. The rowCount is read from file and used to allocate memory. If rowCount is corrupted or maliciously crafted, the offset calculation offsets[rowCount] - offsets[0] could result in negative value or buffer overflow.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/OmniOperator/core/src/operator/spill/spill_merger.cpp:21-109`)

```c
int32_t rowCount = 0;\nif (Read(&rowCount, sizeof(int32_t)) != ErrorCode::SUCCESS) {...}\nvectorBatch = std::make_unique<VectorBatch>(rowCount);\nauto length = offsets[rowCount] - offsets[0];
```

**达成路径**

[IN] Spill file -> Read(&rowCount) -> VectorBatch allocation -> ReadVector -> offsets[rowCount] -> length calculation

**验证说明**: LIKELY: rowCount read from internal spill files created by same process. Mitigated by internal-only access and rowCount comparison with maxRowCount. However, no upper bound validation on rowCount itself.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7: , | 8: r | 9: e | 10: a | 11: c | 12: h | 13: a | 14: b | 15: i | 16: l | 17: i | 18: t | 19: y | 20: : | 21: i | 22: n | 23: t | 24: e | 25: r | 26: n | 27: a | 28: l | 29: _ | 30: o | 31: n | 32: l | 33: y | 34: ( | 35: + | 36: 5 | 37: ) | 38: , | 39: m | 40: i | 41: t | 42: i | 43: g | 44: a | 45: t | 46: i | 47: o | 48: n | 49: : | 50: b | 51: o | 52: u | 53: n | 54: d | 55: s | 56: _ | 57: c | 58: h | 59: e | 60: c | 61: k | 62: ( | 63: - | 64: 1 | 65: 5 | 66: ) | 67: , | 68: t | 69: o | 70: t | 71: a | 72: l | 73: : | 74: 2 | 75: 0

---

### [VULN-SEC-VEC-004] integer_overflow - LargeStringContainer::GetBufferWithSpace

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/vector/large_string_container.cpp:83-99` @ `LargeStringContainer::GetBufferWithSpace`
**模块**: vector

**描述**: LargeStringContainer::GetBufferWithSpace中，容量翻倍循环存在整数溢出风险。当needCapacityInBytes接近UINT64_MAX/2时，toCapacityInBytes *= 2可能溢出，导致分配过小缓冲区。

**漏洞代码** (`core/src/vector/large_string_container.cpp:83-99`)

```c
uint64_t toCapacityInBytes = initCapacityInBytes;
while (toCapacityInBytes < needCapacityInBytes) {
    toCapacityInBytes = toCapacityInBytes * 2;
}
```

**达成路径**

needCapacityInBytes → toCapacityInBytes *= 2 [SINK: 整数溢出]

**验证说明**: LargeStringContainer容量翻倍可能整数溢出，但实际数据量有限。

---

### [VULN-SEC-VEC-005] array_index_validation_missing - LargeStringContainer::GetValue

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-129 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/vector/large_string_container.cpp:20-25` @ `LargeStringContainer::GetValue`
**模块**: vector

**描述**: LargeStringContainer::GetValue访问offsets[index]和offsets[index+1]未进行边界验证。当index超出size范围时，会导致越界读。

**漏洞代码** (`core/src/vector/large_string_container.cpp:20-25`)

```c
char *valuePtr = bufferSupplier->Data() + offsets[index];
size_t valueLen = offsets[index + 1] - offsets[index];
```

**达成路径**

index → offsets[index], offsets[index+1] [SINK: 越界读]

**验证说明**: GetValue访问offsets[index]无边界验证，但index来自内部。

---

### [VULN-SEC-VEC-006] array_index_validation_missing - LargeStringContainer::SetValue

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-129 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/vector/large_string_container.cpp:28-46` @ `LargeStringContainer::SetValue`
**模块**: vector

**描述**: LargeStringContainer::SetValue访问offsets[index]和offsets[index+1]未进行边界验证。当index超出size范围时，会导致越界读写。

**漏洞代码** (`core/src/vector/large_string_container.cpp:28-46`)

```c
FillSlots(index);
int32_t needCapacityInBytes = offsets[index] + valueSize;
offsets[index + 1] = needCapacityInBytes;
```

**达成路径**

index → offsets[index], offsets[index+1] [SINK: 越界读写]

**验证说明**: SetValue访问offsets[index+1]无边界验证，内部使用。

---

### [VULN-SEC-VEC-012] array_index_validation_missing - AlignedBuffer::GetValue

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-129 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/memory/aligned_buffer.h:65-68` @ `AlignedBuffer::GetValue`
**模块**: vector
**跨模块**: vector → memory

**描述**: AlignedBuffer::GetValue方法访问buffer[index]时未验证index边界。

**漏洞代码** (`core/src/memory/aligned_buffer.h:65-68`)

```c
RAW_DATA_TYPE GetValue(int32_t index) { return buffer[index]; }
```

**达成路径**

index → buffer[index] [SINK: 越界读]

**验证说明**: AlignedBuffer::GetValue无边界检查，内部调用。

---

### [VULN-SEC-VEC-013] array_index_validation_missing - ArrayVector::SetValue

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-129 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/vector/array_vector.cpp:11-25` @ `ArrayVector::SetValue`
**模块**: vector
**跨模块**: vector → memory

**描述**: ArrayVector::SetValue方法未验证index边界，调用GetOffset(index)和SetSize(index, valueSize)可能越界。

**漏洞代码** (`core/src/vector/array_vector.cpp:11-25`)

```c
int elementVectorSize = GetOffset(index);
SetSize(index, valueSize);
```

**达成路径**

index → GetOffset(index) → offsets[index] [SINK: 越界访问]

**验证说明**: ArrayVector::SetValue无边界检查，内部调用。

---

### [VULN-SEC-EXPR-005] information_exposure - ParseJSON

**严重性**: Low | **CWE**: CWE-200 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/expression/jsonparser/jsonparser.cpp:574-575` @ `ParseJSON`
**模块**: expression

**描述**: 错误日志消息中包含完整的JSON表达式内容dump，可能泄露敏感数据到日志文件。

**漏洞代码** (`core/src/expression/jsonparser/jsonparser.cpp:574-575`)

```c
LogWarn("The %d-th expression is not supported: %s", i, expressions[i].dump(1).c_str());
```

**达成路径**

jni_operator_factory.cpp:70 nlohmann::json::parse(keysArr[i]) [SOURCE]
jsonparser.cpp:574 expressions[i].dump(1).c_str() -> LogWarn() [SINK]

**验证说明**: 日志消息泄露JSON内容。jsonparser.cpp:574。LogWarn输出完整JSON dump。低严重性信息泄露。

**评分明细**: base: 30 | reachability: [object Object] | mitigations: [object Object] | severity_adjustment: -20

---

### [VULN-SEC-VEC-007] array_index_validation_missing - Vector::SetValue, Vector::GetValue

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-129 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/vector/vector.h:262-299` @ `Vector::SetValue, Vector::GetValue`
**模块**: vector

**描述**: Vector模板类的SetValue/GetValue内联方法未进行index边界验证。values[index]和values[index+offset]的访问可能导致越界。

**漏洞代码** (`core/src/vector/vector.h:262-299`)

```c
void SetValue(int index, ...) { values[index] = value; }
auto GetValue(int index) { return values[index + offset]; }
```

**达成路径**

index → values[index] [SINK: 越界访问]

**验证说明**: Vector模板SetValue/GetValue无边界检查，但为内部API而非外部接口。

---

### [VULN-SEC-VEC-008] array_index_validation_missing - ArrayVector::GetOffset, GetSize, SetOffset, SetSize

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-129 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/vector/array_vector.h:43-71` @ `ArrayVector::GetOffset, GetSize, SetOffset, SetSize`
**模块**: vector

**描述**: ArrayVector::GetOffset/GetSize/SetOffset/SetSize方法访问offsets数组时未验证index边界。当index超出size范围时会导致越界。

**漏洞代码** (`core/src/vector/array_vector.h:43-71`)

```c
int64_t GetOffset(int64_t index) { return offsets[index]; }
int64_t GetSize(int64_t index) { return offsets[index + 1] - offsets[index]; }
```

**达成路径**

index → offsets[index], offsets[index+1] [SINK: 越界访问]

**验证说明**: ArrayVector GetOffset/GetSize无边界检查，内部API。

---

### [VULN-SEC-VEC-009] array_index_validation_missing - MapVector::GetOffset, GetSize, SetOffset, SetSize

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-129 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/vector/map_vector.h:44-87` @ `MapVector::GetOffset, GetSize, SetOffset, SetSize`
**模块**: vector

**描述**: MapVector::GetOffset/GetSize/SetOffset/SetSize方法访问offsets数组时未验证index边界。

**漏洞代码** (`core/src/vector/map_vector.h:44-87`)

```c
int64_t GetOffset(int64_t index) { return offsets[index]; }
int64_t GetSize(int64_t index) { return offsets[index + 1] - offsets[index]; }
```

**达成路径**

index → offsets[index], offsets[index+1] [SINK: 越界访问]

**验证说明**: MapVector GetOffset/GetSize类似VEC-008。

---

### [VULN-SEC-VEC-010] array_index_validation_missing - NullsBuffer::SetNull, SetNotNull, IsNull

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-129 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/vector/nulls_buffer.h:50-84` @ `NullsBuffer::SetNull, SetNotNull, IsNull`
**模块**: vector
**跨模块**: vector → util

**描述**: NullsBuffer::SetNull/SetNotNull/IsNull方法调用BitUtil操作前未验证index边界。当index超出size范围时，可能导致位操作越界。

**漏洞代码** (`core/src/vector/nulls_buffer.h:50-84`)

```c
void SetNull(int32_t index) { BitUtil::SetBit(nulls, index); }
bool IsNull(int32_t index) { return BitUtil::IsBitSet(nulls, index); }
```

**达成路径**

index → BitUtil::SetBit(nulls, index) [SINK: 越界位操作]

**验证说明**: NullsBuffer SetNull/IsNull无边界检查，内部API。

---

### [VULN-SEC-VEC-011] array_index_validation_missing - VectorBatch::SetVector

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-129 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `core/src/vector/vector_batch.cpp:23-26` @ `VectorBatch::SetVector`
**模块**: vector

**描述**: VectorBatch::SetVector方法未验证index边界。vectors[index] = vector的操作当index超出vectors大小时会导致越界写。

**漏洞代码** (`core/src/vector/vector_batch.cpp:23-26`)

```c
void SetVector(int32_t index, BaseVector *vector) { vectors[index] = vector; }
```

**达成路径**

index → vectors[index] [SINK: 越界写]

**验证说明**: VectorBatch::SetVector无边界检查，内部API。

---

## 7. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| codegen | 0 | 1 | 2 | 0 | 3 |
| compute | 0 | 0 | 1 | 0 | 1 |
| cross_module | 1 | 2 | 1 | 0 | 4 |
| expression | 0 | 0 | 4 | 3 | 7 |
| jni_bindings | 0 | 4 | 7 | 4 | 15 |
| operator | 0 | 0 | 1 | 1 | 2 |
| simd | 0 | 0 | 2 | 0 | 2 |
| type | 0 | 0 | 3 | 1 | 4 |
| udf | 0 | 0 | 3 | 1 | 4 |
| vector | 0 | 0 | 3 | 10 | 13 |
| **合计** | **1** | **7** | **27** | **20** | **55** |

## 8. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-129 | 12 | 21.8% |
| CWE-20 | 8 | 14.5% |
| CWE-476 | 7 | 12.7% |
| CWE-190 | 7 | 12.7% |
| CWE-121 | 4 | 7.3% |
| CWE-674 | 2 | 3.6% |
| CWE-94 | 1 | 1.8% |
| CWE-843 | 1 | 1.8% |
| CWE-789 | 1 | 1.8% |
| CWE-78 | 1 | 1.8% |
| CWE-749 | 1 | 1.8% |
| CWE-74 | 1 | 1.8% |
| CWE-676 | 1 | 1.8% |
| CWE-457 | 1 | 1.8% |
| CWE-416 | 1 | 1.8% |
| CWE-401 | 1 | 1.8% |
| CWE-400 | 1 | 1.8% |
| CWE-200 | 1 | 1.8% |
| CWE-15 | 1 | 1.8% |
| CWE-134 | 1 | 1.8% |
| CWE-120 | 1 | 1.8% |
