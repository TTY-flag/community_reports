# OmniAdaptor 威胁分析报告

**项目名称**: OmniAdaptor  
**扫描时间**: 2026-04-22 15:30:00  
**项目类型**: 华为鲲鹏 OmniRuntime 加速适配器（Spark/Flink Native 算子扩展）  
**语言组成**: C/C++ + Python 混合（约 8631 行代码）

---

## 1. 执行摘要

OmniAdaptor 是华为鲲鹏 OmniRuntime 的 Spark/Flink Native 算子扩展组件，通过 JNI 接口将大数据计算任务从 Java 运行时下沉到 C++ Native 代码执行。经过深度架构分析，本项目存在以下关键安全风险：

| 风险等级 | 数量 | 主要来源 |
|----------|------|----------|
| **Critical** | 1 | JNI 接口层 - 跨语言数据边界 |
| **High** | 7 | 文件 IO、Shuffle 处理、内存操作 |
| **Medium** | 4 | Python CLI、环境变量、压缩处理 |
| **Low** | 2 | Python 解析器辅助模块 |

**核心风险点**：
1. JNI 接口接收来自 Java 的用户可控参数（文件路径、压缩类型、环境变量），缺乏充分的输入验证
2. 文件操作路径直接来自 JNI 参数，存在路径遍历风险
3. 内存分配和拷贝操作基于数据大小，可能存在整数溢出或缓冲区溢出风险
4. Python CLI 工具执行外部 Java 进程，存在命令注入风险

---

## 2. 项目架构概述

### 2.1 模块结构

```
OmniAdaptor/
├── omnioperator/omniop-spark-extension/cpp/    [C++ - Critical Risk]
│   ├── src/jni/                                 [JNI Interface - Critical]
│   │   ├── SparkJniWrapper.cpp                  (231 lines)
│   │   ├── jni_common.cpp                       (114 lines)
│   │   └── jni_common.h                         (78 lines)
│   ├── src/io/                                  [IO Module - High]
│   │   ├── SparkFile.cc                         (184 lines) - File Operations
│   │   ├── Compression.cc                       (646 lines) - LZ4/ZSTD/ZLIB/Snappy
│   │   ├── MemoryPool.cc                        (159 lines) - Memory Management
│   │   ├── OutputStream.cc                      (108 lines) - Buffered Output
│   │   ├── ColumnWriter.cc                      (61 lines)
│   │   └── wrap/                                [Stream Wrappers - Medium]
│   ├── src/shuffle/                             [Shuffle Module - High]
│   │   ├── splitter.cpp                         (1033 lines) - Core Shuffle Logic
│   │   ├── splitter.h                           (283 lines)
│   │   ├── type.h                               (75 lines)
│   │   └── utils.h                              (134 lines)
│   └── src/common/                              [Common Utilities - Medium]
│       ├── common.cpp                           (50 lines)
│       ├── common.h                             (84 lines)
│       ├── Buffer.h                             (57 lines)
│       └── debug.h
│
├── omnistream/omniop-flink-extension/java/src/main/resources/ai4c/ai4c-cpp/
│   ├── MapFunction.cpp                          [Auto-generated JNI - Medium]
│   ├── ReduceFunction.cpp
│   └── KeySelector.cpp
│
└── omnihelper/                                  [Python - Medium/Low]
    ├── main.py                                  (161 lines) - CLI Entry
    ├── spark_log_parser.py                      (326 lines) - Log Analysis
    ├── flink_log_parser.py                      (225 lines) - Flink API Client
    ├── parser/                                  [SQL Parsing - Low]
    ├── util/                                    [Utilities - Low]
    └── constants/                               [Enums - Low]
```

### 2.2 数据流架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Spark/Flink Executor (Java)                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐              │
│  │   User      │───▶│  Spark      │───▶│  JNI        │───┐          │
│  │   Query     │    │  Executor   │    │  Wrapper    │   │          │
│  └─────────────┘    └─────────────┘    └─────────────┘   │          │
└──────────────────────────────────────────────────────────────────│──┘
                                                                     │
                                          JNI Interface (Critical)   │
                                                                     │
┌────────────────────────────────────────────────────────────────────▼─┐
│                      OmniAdaptor Native Layer (C++)                   │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐   │
│  │  SparkJniWrapper │───▶│     Splitter     │───▶│   File IO       │   │
│  │  (JNI Entry)    │    │  (Shuffle)       │    │ (Spill/Output)  │   │
│  │                 │    │                  │    │                 │   │
│  │  - nativeMake   │    │  - Split()       │    │  - open()       │   │
│  │  - split()      │    │  - DoSplit()     │    │  - write()      │   │
│  │  - rowSplit()   │    │  - Allocate()    │    │  - Compression  │   │
│  │  - stop()       │    │  - memcpy_s()    │    │                 │   │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘   │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 3. 信任边界分析

### 3.1 边界 1: JNI Interface (Critical)

| 属性 | 值 |
|------|-----|
| **边界名称** | Java-to-C++ JNI Interface |
| **可信侧** | C++ Native Code (OmniAdaptor) |
| **不可信侧** | Java Spark/Flink Executor |
| **风险等级** | Critical |

**风险描述**：
JNI 接口是本项目最关键的信任边界。Java 侧的 Spark Executor 接收用户查询请求，并将配置参数通过 JNI 传递给 C++ Native 层。这些参数包括：
- `partitioning_name`: 分区策略名称（字符串）
- `compression_type`: 压缩类型（字符串）
- `data_file`: 数据文件路径（字符串）
- `local_dirs`: 本地目录路径（字符串）
- `jInputType`: 类型描述字符串（用于反序列化）
- `jVecBatchAddress`: VectorBatch 内存地址（jlong）

**潜在攻击路径**：
1. 恶意用户构造特殊的 Spark 任务，控制传递给 JNI 的参数
2. 路径参数包含路径遍历字符，指向敏感文件
3. jlong 地址参数指向无效内存或恶意构造的数据结构

### 3.2 边界 2: File System (High)

| 属性 | 值 |
|------|-----|
| **边界名称** | Native Code ↔ Disk Files |
| **可信侧** | C++ Native Code |
| **不可信侧** | Disk Files (Shuffle Data, Spill Files) |
| **风险等级** | High |

**风险描述**：
文件路径来自 JNI 参数，通过 `setenv()` 设置环境变量后，被 `GetConfiguredLocalDirs()` 读取并用于创建临时文件和目录。文件操作使用 `open()` 系统调用，无路径规范化或验证。

### 3.3 边界 3: Python CLI Interface (Medium)

| 属性 | 值 |
|------|-----|
| **边界名称** | CLI Arguments ↔ Python Code |
| **可信侧** | Python Parser Logic |
| **不可信侧** | User Command Line Arguments |
| **风险等级** | Medium |

**风险描述**：
Python CLI 工具接收管理员/用户提供的参数，包括文件路径、Java 可执行路径、类路径等。这些参数被用于执行外部 Java 子进程。

---

## 4. STRIDE 威胁建模

### 4.1 Spoofing (身份伪造)

| 威胁 ID | 威胁描述 | 影范围 | 风险等级 |
|---------|----------|--------|----------|
| S-001 | JNI 指针伪装：恶意 Java 代码传递无效的 jlong 地址，伪装为合法 Splitter 或 VectorBatch 对象 | JNI 接口 | Critical |

**缓解建议**：
- 在 JNI 接口层添加指针有效性验证
- 使用安全的指针管理机制（如智能指针）
- 对传入的 jlong 地址进行范围检查

### 4.2 Tampering (数据篡改)

| 威胁 ID | 威胁描述 | 影响范围 | 风险等级 |
|---------|----------|----------|----------|
| T-001 | 路径篡改：用户控制的 `data_file` 和 `local_dirs` 参数可能导致路径遍历，写入/读取非预期位置 | File IO | High |
| T-002 | 环境变量篡改：`setenv()` 使用用户控制的 `local_dirs` 值，可能影响后续进程行为 | JNI | Medium |
| T-003 | 配置篡改：`compression_type` 参数映射到枚举值，无效值可能导致异常或未定义行为 | Compression | Medium |

**缓解建议**：
- 对所有文件路径进行规范化处理（去除路径遍历字符）
- 验证环境变量值的合法性
- 对压缩类型进行白名单验证

### 4.3 Repudiation (抵赖)

| 威胁 ID | 威胁描述 | 影响范围 | 风险等级 |
|---------|----------|----------|----------|
| R-001 | 无安全日志：JNI 接口和 Shuffle 处理缺乏详细的安全审计日志 | 全项目 | Low |

**缓解建议**：
- 在关键操作点添加安全审计日志
- 记录所有 JNI 调用参数和文件操作

### 4.4 Information Disclosure (信息泄露)

| 威胁 ID | 威胁描述 | 影响范围 | 风险等级 |
|---------|----------|----------|----------|
| I-001 | 路径泄露：文件操作异常可能泄露内部路径信息 | File IO | Medium |
| I-002 | 内存泄露：Buffer 对象析构时可能未正确释放内存 | Memory Management | Medium |

**缓解建议**：
- 异常处理时隐藏敏感路径信息
- 添加内存泄露检测机制

### 4.5 Denial of Service (拒绝服务)

| 威胁 ID | 威胁描述 | 影响范围 | 风险等级 |
|---------|----------|----------|----------|
| D-001 | 内存耗尽：恶意构造的 VectorBatch 可能触发大量内存分配 | Shuffle | High |
| D-002 | 文件系统耗尽：大量临时文件创建可能耗尽磁盘空间 | File IO | Medium |

**缓解建议**：
- 实施内存配额限制
- 添加临时文件清理机制

### 4.6 Elevation of Privilege (权限提升)

| 威胁 ID | 威胁描述 | 影响范围 | 风险等级 |
|---------|----------|----------|----------|
| E-001 | 命令注入：Python CLI 工具执行 Java 子进程，路径参数可能包含 shell 元字符 | Python CLI | Medium |

**缓解建议**：
- 使用参数列表形式而非字符串拼接执行子进程
- 验证所有路径参数不含 shell 元字符

---

## 5. 高风险函数分析

### 5.1 Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_nativeMake (Critical)

**文件**: `omnioperator/omniop-spark-extension/cpp/src/jni/SparkJniWrapper.cpp`  
**行号**: 32-132

**风险点**:
```cpp
// 行 83-85: 字符串转换无长度验证
auto partitioning_name_c = env->GetStringUTFChars(partitioning_name_jstr, JNI_FALSE);
auto partitioning_name = std::string(partitioning_name_c);
env->ReleaseStringUTFChars(partitioning_name_jstr, partitioning_name_c);

// 行 99-101: 文件路径直接使用
auto data_file_c = env->GetStringUTFChars(data_file_jstr, JNI_FALSE);
splitOptions.data_file = std::string(data_file_c);
env->ReleaseStringUTFChars(data_file_jstr, data_file_c);

// 行 103-105: 环境变量设置
auto local_dirs = env->GetStringUTFChars(local_dirs_jstr, JNI_FALSE);
setenv("NATIVESQL_SPARK_LOCAL_DIRS", local_dirs, 1);
env->ReleaseStringUTFChars(local_dirs_jstr, local_dirs);
```

**潜在漏洞**:
1. **路径遍历 (CWE-22)**: `data_file` 和 `local_dirs` 未经规范化处理
2. **环境变量注入 (CWE-78)**: `setenv()` 使用用户控制值
3. **空指针解引用 (CWE-476)**: `GetStringUTFChars` 返回值未检查 NULL

### 5.2 FileInputStream::FileInputStream (High)

**文件**: `omnioperator/omniop-spark-extension/cpp/src/io/SparkFile.cc`  
**行号**: 49-60

**风险点**:
```cpp
FileInputStream(std::string _filename) {
  filename = _filename;
  file = open(filename.c_str(), O_BINARY | O_RDONLY);  // 行 51 - 直接 open
  if (file == -1) {
    throw std::runtime_error("Can't open " + filename);  // 行 53 - 异常泄露路径
  }
}
```

**潜在漏洞**:
1. **路径遍历 (CWE-22)**: 未规范化路径
2. **信息泄露 (CWE-209)**: 异常信息包含完整路径

### 5.3 Splitter::AllocatePartitionBuffers (High)

**文件**: `omnioperator/omniop-spark-extension/cpp/src/shuffle/splitter.cpp`  
**行号**: 55-119

**风险点**:
```cpp
// 行 77-78: 内存分配基于数据大小
void *ptr_tmp = static_cast<void *>(options_.allocator->Alloc(new_size * (1 << column_type_id_[i])));
fixed_valueBuffer_size_[partition_id] += new_size * (1 << column_type_id_[i]);

// 行 79-82: 空指针检查但无大小验证
if (nullptr == ptr_tmp) {
    throw std::runtime_error("Allocator for AllocatePartitionBuffers Failed! ");
}
```

**潜在漏洞**:
1. **整数溢出 (CWE-190)**: `new_size * (1 << column_type_id_[i])` 可能溢出
2. **内存耗尽 (CWE-789)**: 无配额限制的内存分配

### 5.4 Splitter::SplitFixedWidthValueBuffer (High)

**文件**: `omnioperator/omniop-spark-extension/cpp/src/shuffle/splitter.cpp`  
**行号**: 121-224

**风险点**:
```cpp
// 行 142-143: reinterpret_cast 和数组访问
reinterpret_cast<CTYPE*>(dst_addrs[pid])[dst_offset] =
    reinterpret_cast<CTYPE*>(src_addr)[reinterpret_cast<int32_t *>(ids_addr)[row]];

// 行 144: 缓冲区大小更新基于计算值
partition_fixed_width_buffers_[col][pid][1]->size_ += shuffle_size;
```

**潜在漏洞**:
1. **缓冲区溢出 (CWE-119)**: 数组索引基于用户数据计算
2. **类型混淆 (CWE-843)**: reinterpret_cast 未验证类型一致性

### 5.5 LogParser::parse_single_file (Medium)

**文件**: `omnihelper/spark_log_parser.py`  
**行号**: 94-109

**风险点**:
```python
cmd = [
    self.args.java_path,    # 来自 CLI 参数
    "-cp",
    self.args.class_path,   # 来自 CLI 参数
    "org.apache.spark.deploy.history.ParseLog",
    input_file_path,        # 来自文件扫描
    output_file_path,
    filename
]
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='gbk')
```

**潜在漏洞**:
1. **命令注入 (CWE-78)**: 虽然使用列表形式，但 `java_path` 和 `class_path` 含 shell 元字符仍有风险

---

## 6. 数据流风险分析

### 6.1 JNI String → File Path 数据流

```
[Source] Java jstring (data_file_jstr)
    ↓
[Processing] GetStringUTFChars() → std::string
    ↓
[Transfer] splitOptions.data_file
    ↓
[Sink] open() in FileOutputStream
```

**风险**: 路径未经过任何验证或规范化处理，可能包含 `../` 等路径遍历字符。

### 6.2 JNI jlong → Pointer 数据流

```
[Source] Java jlong (splitter_addr, jVecBatchAddress)
    ↓
[Processing] reinterpret_cast<Splitter*>(splitter_addr)
    ↓
[Use] Splitter::Split(*vecBatch)
    ↓
[Sink] memcpy_s() operations
```

**风险**: jlong 地址可能指向无效内存，导致解引用失败或内存损坏。

### 6.3 VectorBatch → Memory Allocation 数据流

```
[Source] VectorBatch (row count, column types)
    ↓
[Processing] ComputeAndCountPartitionId()
    ↓
[Calculation] new_size = partition_id_cnt_cur_[pid] > options_.buffer_size ? ...
    ↓
[Sink] Allocator::Alloc(new_size * (1 << column_type_id_[i]))
```

**风险**: 内存分配大小基于用户数据计算，可能触发整数溢出或大量内存分配。

---

## 7. 攻击面汇总

| 攻击面 | 类型 | 风险等级 | 描述 |
|--------|------|----------|------|
| JNI 字符串参数 | RPC | Critical | partitioning_name, compression_type, data_file, local_dirs 来自 Java |
| JNI 指针参数 | RPC | High | splitter_addr, jVecBatchAddress 需验证有效性 |
| 文件路径 | File | High | open() 调用路径来自 JNI 参数 |
| 环境变量 | Env | Medium | setenv() 使用用户控制值 |
| 压缩类型 | Config | Medium | 字符串到枚举映射需白名单验证 |
| 内存分配 | Memory | High | 大小基于数据计算，无上限 |
| Python CLI 参数 | Cmdline | Medium | java_path, class_path, input_data |
| Python HTTP 客户端 | Network | Medium | Flink Dashboard URL |

---

## 8. 安全建议

### 8.1 Critical 级别建议

1. **JNI 输入验证**
   - 对所有 jstring 参数进行长度限制（建议最大 4096 字节）
   - 对文件路径参数进行规范化处理（使用 `realpath()` 或等效函数）
   - 验证 jlong 指针参数的有效性（范围检查、地址对齐检查）

2. **路径安全**
   - 在 `FileInputStream/FileOutputStream` 构造函数中添加路径规范化
   - 使用白名单验证文件路径前缀（如只允许特定目录）
   - 异常信息中隐藏完整路径（使用相对路径或哈希值）

### 8.2 High 级别建议

1. **内存安全**
   - 在 `AllocatePartitionBuffers` 中添加整数溢出检查
   - 实施内存配额限制（基于 `executor_spill_mem_threshold`）
   - 使用安全的数组索引计算（添加边界检查）

2. **数据验证**
   - 在 `ComputeAndCountPartitionId` 中验证 partition ID 范围
   - 对 VectorBatch 数据进行完整性检查

### 8.3 Medium 级别建议

1. **环境变量安全**
   - 验证 `local_dirs` 值不含危险字符
   - 考虑使用安全的配置传递方式而非环境变量

2. **Python CLI 安全**
   - 对所有路径参数进行验证（不含 shell 元字符）
   - 添加 URL 白名单验证（限制 Flink Dashboard 的可达范围）

---

## 9. 扫描建议

基于本威胁分析，建议后续漏洞扫描重点关注以下模块和漏洞类型：

### 9.1 C/C++ 模块扫描重点

| 模块 | 重点漏洞类型 | 关键文件 |
|------|-------------|----------|
| jni-interface | CWE-22 (路径遍历), CWE-476 (空指针), CWE-787 (越界写入) | SparkJniWrapper.cpp |
| io-module | CWE-22 (路径遍历), CWE-209 (信息泄露) | SparkFile.cc |
| shuffle-module | CWE-119 (缓冲区溢出), CWE-190 (整数溢出), CWE-789 (内存耗尽) | splitter.cpp |
| compression | CWE-787 (越界写入) | Compression.cc |

### 9.2 Python 模块扫描重点

| 模块 | 重点漏洞类型 | 关键文件 |
|------|-------------|----------|
| python-main | CWE-78 (命令注入), CWE-918 (SSRF) | spark_log_parser.py, flink_log_parser.py |

---

## 10. 附录

### 10.1 文件统计

| 类别 | 文件数 | 代码行数 |
|------|--------|----------|
| C++ 源文件 (.cpp/.cc) | 14 | 2547 |
| C++ 头文件 (.h) | 14 | 884 |
| Python 源文件 (.py) | 30 | ~5200 |
| **总计** | 58 | ~8631 |

### 10.2 入口点列表

| 文件 | 行号 | 函数 | 类型 |
|------|------|------|------|
| SparkJniWrapper.cpp | 32 | Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_nativeMake | JNI |
| SparkJniWrapper.cpp | 134 | Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_split | JNI |
| SparkJniWrapper.cpp | 152 | Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_rowSplit | JNI |
| SparkFile.cc | 49 | FileInputStream::FileInputStream | File |
| SparkFile.cc | 117 | FileOutputStream::FileOutputStream | File |
| utils.h | 57 | GetConfiguredLocalDirs | Env |
| main.py | 117 | main | CLI |

---

**报告生成完毕**  
**生成工具**: OpenCode Architecture Analyzer  
**分析深度**: Full Project Scan