# 漏洞扫描报告 — 已确认漏洞

**项目**: OmniAdaptor  
**扫描时间**: 2026-04-22T15:30:00+08:00  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞  
**代码规模**: 28 文件, 8631 行  
**语言组成**: C/C++ + Python 混合

---

## 执行摘要

本次漏洞扫描针对华为鲲鹏 OmniRuntime 加速适配器项目 OmniAdaptor 进行了全面的安全审计。该项目作为 Spark/Flink Native 算子扩展库，通过 JNI 接口与 Java 运行时交互，主要包含 Shuffle 数据处理、文件 I/O 和压缩处理等核心模块。

### 关键发现

扫描共发现 **31 个候选漏洞**，经过验证确认 **3 个 Critical 级别路径遍历漏洞**：

| 漏洞类型 | 数量 | 严重性 | 影响模块 |
|----------|------|----------|----------|
| **路径遍历 (CWE-22)** | 3 | Critical | JNI 接口层 |

### 风险评估

**路径遍历漏洞 (VULN-DF-PTH-001, VULN-DF-PTH-002, SEC-007)** 是本次扫描的核心发现：

- **攻击向量**: JNI 接口接收来自 Java Spark Executor 的文件路径参数（`local_dirs`, `data_file`），这些参数未经任何路径验证直接传递给文件操作函数
- **攻击场景**: 恶意 Spark 作业可通过配置注入包含 `../` 序列的路径，将 Shuffle 数据文件写入任意系统位置
- **潜在影响**:
  - 覆盖系统关键文件 (`/etc/passwd`, `/etc/shadow`)
  - 写入恶意配置实现权限提升
  - 导致拒绝服务（覆盖系统文件）
  - 数据泄露（将 Shuffle 数据写入攻击者可访问位置）

### 攻击面特征

OmniAdaptor 的安全边界集中在 **JNI 接口层**：
- Java 到 C++ 的字符串转换（`GetStringUTFChars`）无长度/格式验证
- 指针地址直接 `reinterpret_cast` 转换无有效性检查
- 环境变量 `NATIVESQL_SPARK_LOCAL_DIRS` 可被用户输入控制
- 文件路径直接用于 `open()` 调用无路径规范化

### 紧急修复建议

1. **立即行动**: 在 JNI 入口点实现路径规范化验证
2. **短期缓解**: 配置 Spark Executor 的文件访问权限限制（SELinux/AppArmor）
3. **长期方案**: 实现白名单目录机制和路径验证框架

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 12 | 38.7% |
| FALSE_POSITIVE | 12 | 38.7% |
| POSSIBLE | 4 | 12.9% |
| CONFIRMED | 3 | 9.7% |
| **总计** | **31** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 3 | 100.0% |
| **有效漏洞总计** | **3** | - |
| 误报 (FALSE_POSITIVE) | 12 | - |

### 1.3 Top 关键漏洞

| 序号 | ID | 类型 | 严重性 | 位置 | 置信度 |
|------|-----|------|--------|------|--------|
| 1 | VULN-DF-PTH-001 | path_traversal | Critical | `SparkJniWrapper.cpp:103` | 85 |
| 2 | VULN-DF-PTH-002 | path_traversal | Critical | `SparkJniWrapper.cpp:99` | 85 |
| 3 | SEC-007 | PATH_TRAVERSAL | Critical | `SparkJniWrapper.cpp:99` | 85 |

---

## 2. 攻击面分析

### 2.1 信任边界

| 边界 | 可信侧 | 不可信侧 | 风险等级 |
|------|--------|----------|----------|
| **JNI Interface** | C++ Native Code (OmniAdaptor) | Java Spark/Flink Executor | **Critical** |
| File System | C++ Native Code | Disk Files (Shuffle Data, Spill Files) | High |
| Python CLI Interface | Python Parser Logic | User Command Line Arguments | Medium |
| Flink REST API | Python Parser Logic | Flink Dashboard HTTP API | Medium |

### 2.2 入口点分析

| 入口点 | 类型 | 信任等级 | 可达性理由 |
|--------|------|----------|-----------|
| `Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_nativeMake` | rpc | semi_trusted | JNI 入口点，接收配置字符串（partitioning_name, compression_type, data_file, local_dirs），这些值来自 Spark 配置，可能受用户查询影响 |
| `FileInputStream::FileInputStream` | file | semi_trusted | 基于 JNI 提供的路径打开文件读取 Shuffle 数据 |
| `FileOutputStream::FileOutputStream` | file | semi_trusted | 基于 JNI 提供的路径创建文件写入 Shuffle spill 数据 |
| `GetConfiguredLocalDirs` | env | semi_trusted | 读取环境变量 `NATIVESQL_SPARK_LOCAL_DIRS`，该变量由 JNI 设置 |

### 2.3 数据流风险模式

| 模式 | 源 | 目标 | 风险 |
|------|-----|------|------|
| **JNI String to File Path** | Java jstring (data_file, local_dirs) | open() syscall | **Critical - 无路径验证** |
| JNI String to C++ String | Java jstring | std::string via GetStringUTFChars | High - 可能返回 NULL |
| JNI Pointer Conversion | Java jlong addresses | reinterpret_cast | High - 无地址验证 |
| Environment Variable Setting | JNI local_dirs | setenv() | Medium - 影响后续行为 |

---

## 3. 漏洞深度分析

### 3.1 [VULN-DF-PTH-001] JNI local_dirs 路径遍历

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED

#### 漏洞概述

JNI 入口函数 `Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_nativeMake` 接收来自 Java 的 `local_dirs_jstr` 参数，该参数未经任何路径验证直接通过 `setenv()` 设置为环境变量 `NATIVESQL_SPARK_LOCAL_DIRS`，随后被 `GetConfiguredLocalDirs()` 读取并用于创建 Shuffle 文件目录和文件。

#### 漏洞代码

```cpp
// SparkJniWrapper.cpp:103-105
auto local_dirs = env->GetStringUTFChars(local_dirs_jstr, JNI_FALSE);
setenv("NATIVESQL_SPARK_LOCAL_DIRS", local_dirs, 1);  // 直接设置环境变量
env->ReleaseStringUTFChars(local_dirs_jstr, local_dirs);
```

#### 数据流路径

```
JNI local_dirs_jstr [SOURCE]
    ↓ GetStringUTFChars() [SparkJniWrapper.cpp:103]
    ↓ setenv("NATIVESQL_SPARK_LOCAL_DIRS", local_dirs, 1) [SparkJniWrapper.cpp:104]
    ↓ getenv() [utils.h:58]
    ↓ GetConfiguredLocalDirs() [utils.h:57]
    ↓ mkdir() [utils.h:79]
    ↓ CreateTempShuffleFile() [utils.h:121]
    ↓ ConcatAbstractPath()
    ↓ open() [SparkFile.cc:121] [SINK]
```

#### 攻击场景

1. **攻击准备**: 恶意用户提交包含路径遍历序列的 Spark 作业配置
2. **路径注入**: 配置中设置 `local_dirs = "../../../etc/"`
3. **触发执行**: Spark Executor 调用 JNI 创建 Splitter 实例
4. **文件创建**: Native 代码尝试在 `/etc/` 目录下创建 Shuffle 子目录
5. **任意写入**: 后续 Shuffle 操作将数据文件写入系统敏感目录

#### 漏洞影响

| 影响类型 | 描述 |
|----------|------|
| **文件覆盖** | 使用 `O_CREAT|O_TRUNC` 模式可覆盖任意可写文件 |
| **权限提升** | 覆盖 `/etc/shadow` 或配置文件可实现权限提升 |
| **数据泄露** | 将 Shuffle 数据写入攻击者可访问的路径 |
| **拒绝服务** | 覆盖关键系统文件导致服务中断 |

#### 修复建议

```cpp
// 推荐修复方案
auto local_dirs = env->GetStringUTFChars(local_dirs_jstr, JNI_FALSE);

// 1. 路径规范化验证
std::string validated_path = validateBaseDirectory(local_dirs);
if (validated_path.empty()) {
    env->ThrowNew(runtimeExceptionClass, 
        "Invalid local_dirs: path traversal detected or outside allowed directories");
    env->ReleaseStringUTFChars(local_dirs_jstr, local_dirs);
    return 0;
}

// 2. 设置验证后的路径
setenv("NATIVESQL_SPARK_LOCAL_DIRS", validated_path.c_str(), 1);
env->ReleaseStringUTFChars(local_dirs_jstr, local_dirs);

// 验证函数示例
std::string validateBaseDirectory(const char* input_path) {
    // 使用 realpath 规范化路径
    char resolved[PATH_MAX];
    if (realpath(input_path, resolved) == nullptr) {
        return ""; // 路径无效或不存在
    }
    
    // 检查是否在允许的基础目录内
    const char* allowed_bases[] = {"/tmp", "/var/spark", "/data/shuffle"};
    for (auto base : allowed_bases) {
        if (strncmp(resolved, base, strlen(base)) == 0) {
            return std::string(resolved);
        }
    }
    return ""; // 路径不在允许范围内
}
```

---

### 3.2 [VULN-DF-PTH-002] JNI data_file 路径遍历

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED

#### 漏洞概述

JNI 入口函数接收 `data_file_jstr` 参数，该参数直接存储到 `splitOptions.data_file` 中，在 `Split_Init()` 阶段通过 `CreateTempShuffleFile()` 创建文件时使用。文件路径未经任何验证，攻击者可通过注入 `../` 序列实现任意路径写入。

#### 漏洞代码

```cpp
// SparkJniWrapper.cpp:99-101
auto data_file_c = env->GetStringUTFChars(data_file_jstr, JNI_FALSE);
splitOptions.data_file = std::string(data_file_c);  // 直接使用未验证路径
env->ReleaseStringUTFChars(data_file_jstr, data_file_c);
```

#### 数据流路径

```
JNI data_file_jstr [SOURCE]
    ↓ GetStringUTFChars() [SparkJniWrapper.cpp:99]
    ↓ splitOptions.data_file = std::string(data_file_c) [SparkJniWrapper.cpp:100]
    ↓ Splitter::Split_Init() [splitter.cpp:562]
    ↓ CreateTempShuffleFile() [utils.h:121]
    ↓ open() [SparkFile.cc:121] [SINK]
```

#### 攻击场景

1. 恶意 Spark 作业配置 `data_file = "/etc/cron.d/malicious"`
2. Native 代码使用 `O_CREAT|O_TRUNC` 模式打开该路径
3. Shuffle 数据被写入 cron 任务目录
4. 实现持久化恶意任务执行

#### 漏洞影响

与 VULN-DF-PTH-001 相同，可实现任意文件写入和覆盖。

#### 修复建议

```cpp
// 推荐修复方案
auto data_file_c = env->GetStringUTFChars(data_file_jstr, JNI_FALSE);

// 验证路径并确保在 local_dirs 目录内
std::string validated_path = validateShuffleFilePath(std::string(data_file_c));
if (validated_path.empty()) {
    env->ThrowNew(runtimeExceptionClass,
        "Invalid data_file path: must be within configured local_dirs");
    env->ReleaseStringUTFChars(data_file_jstr, data_file_c);
    return 0;
}

splitOptions.data_file = validated_path;
env->ReleaseStringUTFChars(data_file_jstr, data_file_c);

// 路径验证函数
std::string validateShuffleFilePath(const std::string& input_path) {
    // 获取已验证的 local_dirs
    char* local_dirs = getenv("NATIVESQL_SPARK_LOCAL_DIRS");
    if (!local_dirs) return "";
    
    // 构造完整路径并规范化
    std::string full_path = std::string(local_dirs) + "/" + input_path;
    char resolved[PATH_MAX];
    if (realpath(full_path.c_str(), resolved) == nullptr) {
        // 对于新文件，验证父目录
        size_t last_slash = full_path.find_last_of('/');
        if (last_slash != std::string::npos) {
            std::string parent = full_path.substr(0, last_slash);
            if (realpath(parent.c_str(), resolved)) {
                // 验证父目录在 local_dirs 内
                char local_resolved[PATH_MAX];
                realpath(local_dirs, local_resolved);
                if (strncmp(resolved, local_resolved, strlen(local_resolved)) == 0) {
                    return full_path; // 安全路径
                }
            }
        }
        return "";
    }
    
    // 验证完整路径在 local_dirs 内
    char local_resolved[PATH_MAX];
    realpath(local_dirs, local_resolved);
    if (strncmp(resolved, local_resolved, strlen(local_resolved)) == 0) {
        return std::string(resolved);
    }
    return "";
}
```

---

### 3.3 [SEC-007] PATH_TRAVERSAL (与 VULN-DF-PTH-002 相同)

**严重性**: Critical | **CWE**: CWE-22 | **置信度**: 85/100 | **状态**: CONFIRMED

此漏洞由 Security Auditor Agent 独立发现，与 VULN-DF-PTH-002 位于相同代码位置，具有相同的漏洞根因。应作为同一漏洞进行修复处理。

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **jni-interface** | 3 | 0 | 0 | 0 | 3 |
| **合计** | **3** | **0** | **0** | **0** | **3** |

所有已确认漏洞均位于 JNI 接口层，表明该模块是项目安全防护的关键薄弱点。

---

## 5. CWE 分布

| CWE | 数量 | 占比 | 描述 |
|-----|------|------|------|
| **CWE-22** | 3 | 100.0% | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') |

---

## 6. 综合修复建议

### 6.1 紧急修复（P0 - 立即执行）

#### 6.1.1 JNI 入口点路径验证

**位置**: `SparkJniWrapper.cpp` 的 `nativeMake` 函数

**修复策略**:
1. 对所有来自 JNI 的文件路径参数实施路径规范化
2. 使用 `realpath()` 解析路径并验证是否在允许的基础目录内
3. 拒绝包含 `../` 序列、绝对路径、或超出白名单范围的路径

**实施步骤**:
```cpp
// 创建路径验证辅助模块
namespace PathValidator {
    bool isPathSafe(const std::string& path, const std::vector<std::string>& allowed_bases);
    std::string canonicalizeAndValidate(const char* input, const std::string& base_dir);
}

// 在 nativeMake 中应用
auto data_file_c = env->GetStringUTFChars(data_file_jstr, JNI_FALSE);
std::string safe_path = PathValidator::canonicalizeAndValidate(data_file_c, local_dirs);
if (safe_path.empty()) {
    // 记录安全事件并抛出异常
    LogsSecurity("Path traversal attempt detected: %s", data_file_c);
    env->ThrowNew(runtimeExceptionClass, "Invalid file path");
}
```

#### 6.1.2 环境变量安全设置

**位置**: `SparkJniWrapper.cpp:104`

**修复策略**:
- 不允许通过 JNI 直接设置影响文件操作的环境变量
- 将 `local_dirs` 存储在进程内部变量而非环境变量中
- 或在设置前进行严格的路径验证

### 6.2 短期缓解（P1 - 一周内）

#### 6.2.1 系统级访问控制

使用 SELinux 或 AppArmor 配置 Spark Executor 的文件访问策略：

```bash
# SELinux 示例配置
# 仅允许访问特定 shuffle 目录
semanage fcontext -a -t spark_shuffle_file_t '/data/shuffle(/.*)?'
restorecon -Rv /data/shuffle

# 限制进程文件写入范围
setsebool -P spark_exec_file_write 1
```

#### 6.2.2 运行时监控

添加 JNI 入口点的安全日志记录：

```cpp
// 在 SparkJniWrapper.cpp 中添加
LogsSecurity("JNI call: nativeMake with data_file=%s, local_dirs=%s", 
    data_file_c, local_dirs);
```

### 6.3 长期方案（P2 - 版本迭代）

#### 6.3.1 架构级安全框架

1. **输入验证层**: 在 JNI 边界实现统一的输入验证模块
2. **路径白名单**: 配置化的允许目录列表，支持动态更新
3. **安全审计**: 集成日志系统，记录所有文件操作和安全事件

#### 6.3.2 Java 端防护

在 Java Spark Executor 层实施预验证：

```java
// SparkJniWrapper.java
public long nativeMake(...) {
    // 在调用 JNI 前验证路径
    String validatedLocalDirs = SparkPathValidator.validate(localDirs);
    String validatedDataFile = SparkPathValidator.validate(dataFile);
    // 仅传递验证后的参数
}
```

---

## 7. 验证与测试建议

### 7.1 安全测试用例

| 测试场景 | 输入 | 预期结果 |
|----------|------|----------|
| 基本路径遍历 | `local_dirs = "../../../etc"` | 拒绝并抛出异常 |
| 绝对路径注入 | `data_file = "/etc/passwd"` | 拒绝并抛出异常 |
| 混合序列 | `local_dirs = "/tmp/../etc"` | 解析为 `/etc` 后拒绝 |
| 有效路径 | `local_dirs = "/data/spark"` | 接受并正常执行 |
| Unicode 编码绕过 | `local_dirs = "..%2f..%2f"` | 拒绝（应解码后验证） |

### 7.2 渗透测试建议

建议对以下攻击路径进行专项测试：
- 通过 Spark SQL 注入路径配置
- 通过 Spark 任务提交参数注入
- 通过环境变量或配置文件注入

---

## 8. 参考资源

- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal Prevention](https://owasp.org/www-community/attacks/Path_Traversal)
- 深度分析报告: `scan-results/details/VULN-DF-PTH-001.md`, `scan-results/details/VULN-DF-PTH-002.md`