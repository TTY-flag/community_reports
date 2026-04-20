# OmniOperator 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析为 AI 自主识别，未受 threat.md 约束。

## 项目架构概览

### 项目定位

**OmniOperator** 是华为鲲鹏 BoostKit 大数据 OmniRuntime 的核心特性之一，是一个大数据引擎加速库：

- **项目类型**：库/SDK
- **主要语言**：C/C++ (Native 实现) + Python (辅助脚本)
- **部署方式**：作为 Spark/Hive 的动态库被 JVM 通过 JNI 调用
- **核心功能**：用高性能 Native 算子替代 Spark/Hive 的 Java/Scala 算子

### 核心架构组件

```
┌─────────────────────────────────────────────────────────────────┐
│                    Spark/Hive Java 适配层                         │
│  (SparkExtension / Gluten / HiveExtension)                      │
└─────────────────────────────┬───────────────────────────────────┘
                              │ JNI 调用
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    JNI 绑定层 (bindings/java)                    │
│  - jni_operator.cpp      算子操作接口                            │
│  - jni_operator_factory.cpp  算子工厂接口                        │
│  - jni_vector.cpp        向量数据接口                            │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    C++ Native 算子层 (core/src)                   │
│                                                                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │  operator/   │ │  codegen/    │ │  expression/ │            │
│  │  aggregation │ │  llvm_engine │ │  jsonparser  │            │
│  │  join        │ │  functions   │ │  parser      │            │
│  │  sort        │ │              │ │              │            │
│  │  filter      │ │              │ │              │            │
│  │  window      │ │              │ │              │            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
│                                                                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │  vector/     │ │  memory/     │ │  type/       │            │
│  │  vector_batch│ │  memory_pool │ │  data_type   │            │
│  │  string_cont │ │  allocator   │ │  serializer  │            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
│                                                                  │
│  ┌──────────────┐ ┌──────────────┐                              │
│  │  udf/        │ │  util/       │                              │
│  │  java_udf    │ │  config_util │                              │
│  │  jni_util    │ │  native_log  │                              │
│  └──────────────┘ └──────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
```

### 模块分布

| 模块 | 文件数 | 主要功能 | 风险等级 |
|------|--------|----------|----------|
| jni_bindings | 6 | JNI 接口层 | Critical |
| operator | 50+ | 算子实现 | Medium |
| codegen | 40+ | LLVM 代码生成 | High |
| expression | 10+ | 表达式解析 | High |
| vector | 20+ | 向量数据结构 | Medium |
| memory | 10+ | 内存管理 | Medium |
| type | 10+ | 数据类型 | Medium |
| udf | 2 | UDF 执行 | High |
| util | 8 | 工具类 | Low |

## 模块风险评估

### Critical 级别模块

#### 1. JNI 绑定层 (jni_bindings)

**风险描述**：这是 Java JVM 与 C++ Native 层的唯一交互通道，所有数据和控制流都通过此层传递。

**主要风险点**：
- `jni_operator.cpp`：直接接收 Java 传入的内存地址指针，进行指针转换和内存访问
- `jni_operator_factory.cpp`：接收 JSON 格式的表达式字符串，进行解析和算子创建
- 数据类型反序列化：解析从 Java 传入的数据类型 JSON

**潜在漏洞类型**：
- 内存访问越界（指针转换后访问超出边界）
- 类型混淆（错误的数据类型转换）
- JSON 解析异常（恶意构造的 JSON 表达式）

### High 级别模块

#### 2. 表达式解析 (expression/jsonparser)

**风险描述**：解析从 Java 端传入的 JSON 格式 SQL 表达式。

**主要风险点**：
- `JSONParser::ParseJSON`：解析嵌套的 JSON 结构
- 表达式字符串来自 Spark/Hive SQL 解析器，包含用户查询中的表达式

**潜在漏洞类型**：
- JSON 解析异常导致的崩溃
- 表达式注入（构造特殊表达式触发异常行为）

#### 3. LLVM 代码生成 (codegen/llvm_engine)

**风险描述**：使用 LLVM JIT 动态编译和执行表达式代码。

**主要风险点**：
- `LLVMEngine::Compile`：编译生成的 LLVM IR
- 动态函数注册和调用

**潜在漏洞类型**：
- JIT 编译时资源消耗（CPU/内存）
- 生成的代码执行异常

#### 4. UDF 执行 (udf/java_udf_functions)

**风险描述**：执行用户定义的 Hive/Java UDF 函数。

**主要风险点**：
- `ExecuteHiveUdfSingle/Batch`：调用 Java UDF
- UDF 类名来自配置或 SQL 查询

**潜在漏洞类型**：
- UDF 类名注入（指定恶意 UDF 类）
- JVM 调用异常

### Medium 级别模块

#### 5. 数据处理 (vector/, operator/)

**风险描述**：大量使用 memcpy_s 进行数据复制。

**主要风险点**：
- `Vector::SetValues`：批量数据复制
- `LargeStringContainer::SetValue`：字符串存储
- Spill 文件读写

**潜在漏洞类型**：
- 内存复制越界
- 文件路径构造问题

#### 6. 配置处理 (util/config_util)

**风险描述**：从环境变量和配置文件读取运行参数。

**主要风险点**：
- `getenv("OMNI_HOME/OMNI_CONF")`：环境变量读取
- 配置文件解析

**潜在漏洞类型**：
- 配置文件路径遍历（符号链接问题）
- 环境变量影响运行行为

## 攻击面分析

### 信任边界模型

```
┌─────────────────────────────────────────────────────────────────┐
│  信任边界 1: JNI 接口边界 (Critical)                             │
│  ─────────────────────────────────────────────────────────────  │
│  可信侧: C++ Native 算子实现                                     │
│  不可信侧: Spark/Hive Java 适配层                                │
│  说明: Java JVM 与 C++ 在同一进程，但数据来自外部查询            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  信任边界 2: UDF 执行边界 (High)                                  │
│  ─────────────────────────────────────────────────────────────  │
│  可信侧: C++ Native 算子                                         │
│  不可信侧: 用户定义的 Java UDF 函数                               │
│  说明: UDF 由用户通过 SQL 查询指定，代码由用户编写               │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  信任边界 3: 数据输入边界 (Medium)                                │
│  ─────────────────────────────────────────────────────────────  │
│  可信侧: 内部数据处理逻辑                                         │
│  不可信侧: 从数据文件读取的数据                                   │
│  说明: ORC/Parquet 数据文件内容                                   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  信任边界 4: 配置边界 (Low)                                       │
│  ─────────────────────────────────────────────────────────────  │
│  可信侧: 管理员控制的配置                                         │
│  不可信侧: 环境变量                                               │
│  说明: 部署人员设置 OMNI_HOME/OMNI_CONF                          │
└─────────────────────────────────────────────────────────────────┘
```

### 入口点分析

| 入口类型 | 位置 | 信任等级 | 数据来源 | 可控性 |
|----------|------|----------|----------|--------|
| JNI addInput | jni_operator.cpp | semi_trusted | Spark/Hive 查询数据 | 由查询引擎控制 |
| JNI createOperator | jni_operator_factory.cpp | semi_trusted | Spark/Hive 查询计划 | 由查询引擎控制 |
| JSON 表达式解析 | jsonparser.h | semi_trusted | SQL 表达式 | 用户通过 SQL 控制 |
| 数据类型反序列化 | data_type_serializer.cpp | semi_trusted | 查询计划中的类型 | 由查询引擎控制 |
| UDF 执行 | java_udf_functions.cpp | untrusted_local | 用户指定的 UDF 类 | 用户直接控制 |
| Spill 文件 | spiller.cpp | trusted_admin | 配置的目录 | 管理员控制 |
| 环境变量 | config_util.cpp | trusted_admin | 启动脚本设置 | 管理员控制 |

## STRIDE 威胁建模

### Spoofing (欺骗)

| 威胁 | 描述 | 风险等级 | 影响模块 |
|------|------|----------|----------|
| UDF 类名伪造 | 用户指定非预期的 UDF 类名执行恶意代码 | High | udf/java_udf_functions |
| 数据类型伪装 | JSON 数据类型描述与实际数据不符 | Medium | type/data_type_serializer |

### Tampering (篡改)

| 威胁 | 描述 | 风险等级 | 影响模块 |
|------|------|----------|----------|
| 内存数据篡改 | JNI 传递的内存地址被错误使用 | High | jni_bindings, vector |
| 配置篡改 | 配置文件被非授权修改 | Low | util/config_util |
| Spill 文件篡改 | 临时文件被其他进程修改 | Low | operator/spill |

### Repudiation (抵赖)

| 威胁 | 描述 | 风险等级 | 影响模块 |
|------|------|----------|----------|
| 操作日志缺失 | 缺少关键操作的审计日志 | Low | util/native_log |
| UDF 执行无记录 | UDF 执行缺乏追踪机制 | Medium | udf/java_udf_functions |

### Information Disclosure (信息泄露)

| 威胁 | 描述 | 风险等级 | 影响模块 |
|------|------|----------|----------|
| 内存数据泄露 | 错误返回内存地址导致数据泄露 | Medium | jni_operator.cpp (Transform) |
| Spill 文件数据泄露 | 临时文件包含敏感查询数据 | Medium | operator/spill |
| 日志信息泄露 | 日志包含敏感查询内容 | Low | util/native_log |

### Denial of Service (拒绝服务)

| 威胁 | 描述 | 风险等级 | 影响模块 |
|------|------|----------|----------|
| JSON 解析耗尽资源 | 深度嵌套或超大 JSON 消耗 CPU | High | expression/jsonparser |
| LLVM 编译耗时 | 复杂表达式编译消耗大量 CPU | Medium | codegen/llvm_engine |
| 内存耗尽 | 处理超大数据批次耗尽堆外内存 | Medium | memory/, vector/ |
| UDF 执行阻塞 | 恶意 UDF 阻塞 JVM 调用 | Medium | udf/java_udf_functions |

### Elevation of Privilege (权限提升)

| 威胁 | 描述 | 风险等级 | 影响模块 |
|------|------|----------|----------|
| UDF 代码执行 | 恶意 UDF 在 JVM 中执行任意代码 | High | udf/java_udf_functions |
| JIT 代码注入 | 通过 LLVM JIT 执行非预期代码 | Medium | codegen/llvm_engine |

## 数据流分析

### 关键数据流路径

#### 1. JNI 输入数据流

```
Java VectorBatch → JNI addInputNative → Operator::AddInput → memcpy_s (Vector::SetValues)
```

**风险点**：
- Java 传入的内存地址直接转换
- 批量数据复制可能越界

#### 2. JSON 表达式解析流

```
Java JSON expression → nlohmann::json::parse → JSONParser::ParseJSON → Expr 创建
```

**风险点**：
- JSON 解析异常处理
- 表达式对象内存管理

#### 3. UDF 执行流

```
SQL UDF ClassName → ExecuteHiveUdf → JNI CallStaticVoidMethod → Java UDF 执行
```

**风险点**：
- UDF 类名验证不足
- JNI 调用异常传播

#### 4. Spill 文件流

```
内存数据 → memcpy_s → SpillWriter::WriteVecBatch → fwrite → 临时文件
```

**风险点**：
- 文件路径构造
- 数据写入完整性

## 安全加固建议

### 架构层面建议

1. **JNI 接口安全加固**
   - 增加传入指针的边界检查
   - 对 JSON 输入增加深度和大小限制
   - 增加调用者身份验证机制

2. **UDF 执行安全加固**
   - 增加允许执行的 UDF 类白名单
   - 对 UDF 执行设置超时限制
   - 增加沙箱机制隔离 UDF 执行环境

3. **表达式解析安全加固**
   - 对 JSON 解析设置深度限制
   - 增加表达式复杂度限制
   - 对解析异常进行安全处理

4. **内存操作安全加固**
   - 使用安全的内存复制函数（已使用 memcpy_s）
   - 增加内存分配上限检查
   - 对向量大小进行合理性检查

5. **配置安全加固**
   - 验证配置文件路径的合法性
   - 对环境变量设置默认安全值
   - 增加配置完整性检查

6. **日志审计加固**
   - 增加关键操作审计日志
   - 对 UDF 执行进行记录
   - 避免日志中包含敏感数据

### 代码层面建议

1. 对所有 JNI 传入的指针增加 null 检查和范围检查
2. 对 JSON 解析增加异常捕获和资源限制
3. 对 UDF 类名增加白名单验证
4. 对 Spill 文件路径增加规范化处理
5. 增加内存使用的监控和限制机制

---

*报告生成时间：2026-04-19*
*分析范围：OmniOperator C/C++ Native 实现 + JNI 绑定层*
*分析工具：Architecture Agent*