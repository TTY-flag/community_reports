# VULN-DF-PTH-001：路径遍历导致任意目录写入

## 1. 漏洞概述

**漏洞类型**: 路径遍历 (CWE-22)  
**严重程度**: Critical  
**置信度**: 85 → 90 (基于完整数据流验证)

**核心问题**: JNI 接口接收来自 Java 层的 `local_dirs` 参数，直接通过 `setenv()` 写入环境变量，后续通过 `getenv()` 读取并用于文件系统操作，全程缺乏路径验证和规范化处理。

**影响范围**: 攻击者可控制 Spark shuffle 数据文件的写入路径，实现任意目录下的文件写入/覆盖，可能导致：
- 敏感文件覆盖（如 `/etc/passwd`, `/root/.ssh/authorized_keys`）
- 权限提升
- 横向移动（写入恶意配置文件）
- 拒绝服务（覆盖关键系统文件）

---

## 2. 攻击场景描述

### 场景 A：恶意用户控制 Spark 配置

**攻击者角色**: 拥有 Spark 任务提交权限的普通用户  
**攻击路径**:
1. 攻击者提交 Spark 任务，通过配置参数控制 `spark.local.dirs`:
   ```bash
   spark-submit --conf spark.local.dirs="/../../etc/cron.d" ...
   ```
2. Shuffle 数据被写入 `/etc/cron.d/temp_shuffle_<uuid>.data`
3. 如果攻击者能控制 shuffle 数据内容，可注入 cron 任务实现权限提升

### 场景 B：容器化环境突破

**攻击者角色**: 容器内的恶意用户  
**攻击路径**:
1. 在 Kubernetes/Docker 环境中，攻击者设置 `spark.local.dirs=/../../host-filesystem/root`
2. 通过 JNI 写入 `authorized_keys` 或 `.bashrc` 文件
3. 实现容器逃逸到宿主机

### 场景 C：敏感配置覆盖

**攻击者角色**: 多租户集群中的恶意租户  
**攻击路径**:
1. 设置 `spark.local.dirs=/../../var/lib/spark/conf`
2. 覆盖 Spark 配置文件，注入恶意配置
3. 影响后续所有任务的执行环境

---

## 3. 完整数据流图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ SOURCE: Java/Scala 层                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ [1] ColumnarShuffleWriter.scala:49                                          │
│     localDirs = blockManager.diskBlockManager.localDirs.mkString(",")       │
│     ↑ 来源: spark.local.dirs 配置                                            │
│ [2] SparkJniWrapper.java:30-54                                              │
│     make() → nativeMake(localDirs)                                          │
│     ↑ 无验证，直接传递                                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ JNI ENTRY: SparkJniWrapper.cpp                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│ [3] SparkJniWrapper.cpp:103                                                 │
│     auto local_dirs = env->GetStringUTFChars(local_dirs_jstr, JNI_FALSE);   │
│     ↑ 获取 JNI 字符串                                                        │
│ [4] SparkJniWrapper.cpp:104                                                 │
│     setenv("NATIVESQL_SPARK_LOCAL_DIRS", local_dirs, 1);                    │
│     ⚠ CRITICAL: 直接写入环境变量，无任何验证                                   │
│ [5] SparkJniWrapper.cpp:105                                                 │
│     env->ReleaseStringUTFChars(local_dirs_jstr, local_dirs);                │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ ENVIRONMENT PROPAGATION                                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ [6] utils.h:58                                                              │
│     auto joined_dirs_c = std::getenv("NATIVESQL_SPARK_LOCAL_DIRS");         │
│     ↑ 从环境变量读取                                                          │
│ [7] utils.h:65-74                                                           │
│     按逗号分割目录列表                                                        │
│     ⚠ 无路径验证                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ DIRECTORY CREATION                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ [8] utils.h:79                                                              │
│     mkdir(omni_tmp_dir.c_str(), S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);           │
│     ⚠ 可在任意位置创建目录                                                    │
│ [9] utils.h:127                                                             │
│     mkdir(dir.c_str(), S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);                    │
│     ⚠ CreateTempShuffleFile() 中同样无验证                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ PATH CONSTRUCTION                                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ [10] utils.h:102-111                                                        │
│     ConcatAbstractPath(base, stem)                                          │
│     return EnsureTrailingSlash(base) + RemoveLeadingSlash(stem);            │
│     ⚠ 仅移除 stem 的前导斜杠，不处理 ".." 序列                                 │
│                                                                              │
│ [11] utils.h:117                                                            │
│     GetSpilledShuffleFileDir(configured_dir, sub_dir_id)                    │
│     dir = ConcatAbstractPath(configured_dir, "shuffle_" + ss.str())         │
│                                                                              │
│ [12] utils.h:130                                                            │
│     file_path = ConcatAbstractPath(dir, "temp_shuffle_" + GenerateUUID())   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ USAGE IN SPLITTER                                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ [13] splitter.cpp:556                                                       │
│     configured_dirs_ = GetConfiguredLocalDirs();                            │
│                                                                              │
│ [14] splitter.cpp:563                                                       │
│     options_.data_file = CreateTempShuffleFile(configured_dirs_[0]);        │
│                                                                              │
│ [15] splitter.cpp:1357                                                      │
│     options_.next_spilled_file_dir = CreateTempShuffleFile(NextSpilledFileDir());│
│                                                                              │
│ [16] splitter.cpp:1413                                                      │
│     GetSpilledShuffleFileDir(configured_dirs_[dir_selection_], ...)         │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ SINK: FILE WRITE                                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│ [17] SparkFile.cc:121-127                                                   │
│     FileOutputStream(std::string _filename) {                               │
│         file = open(filename.c_str(),                                       │
│                     O_BINARY | O_CREAT | O_WRONLY | O_TRUNC,                │
│                     S_IRUSR | S_IWUSR);                                     │
│     }                                                                        │
│     ⚠ CRITICAL: 使用 O_CREAT | O_TRUNC 可创建/覆盖任意文件                    │
│                                                                              │
│ [18] splitter.cpp:1159,1176,1196,1247,1298,1320                             │
│     writeLocalFile(options_.next_spilled_file_dir + ".data")                │
│     writeLocalFile(options_.data_file)                                      │
│     ⚠ 最终写入点                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. 利用条件分析

### 前置条件

| 条件 | 说明 | 难度 |
|------|------|------|
| **C1: Spark 任务提交权限** | 攻击者需要能够提交 Spark 任务 | 低（普通用户权限） |
| **C2: 配置控制能力** | 需能控制 `spark.local.dirs` 配置 | 低（可通过 spark-submit --conf 设置） |
| **C3: 文件系统访问** | 目标路径需要可写权限 | 中（取决于目标目录权限） |
| **C4: JNI 库加载** | OmniAdaptor JNI 库需要被加载使用 | 低（默认 shuffle 场景） |

### 利用可行性评估

**高可行性场景**:
- 多租户 Spark 集群（用户可自由设置配置）
- 容器化环境（容器内路径可能映射到宿主机）
- 未启用配置白名单的集群

**低可行性场景**:
- 配置严格锁定的企业集群
- 使用 YARN/K8s 动态分配且配置不可用户控制
- 所有敏感目录权限严格隔离

---

## 5. 潜在影响评估

### 5.1 直接影响

| 影响类型 | 具体表现 | 严重程度 |
|----------|----------|----------|
| **文件覆盖** | 覆盖 `/etc/passwd`, `/etc/shadow` 等敏感文件 | Critical |
| **权限提升** | 写入 SSH authorized_keys、cron 任务 | High |
| **配置注入** | 覆盖应用配置文件，注入恶意配置 | High |
| **拒绝服务** | 覆盖关键系统文件导致服务崩溃 | High |
| **数据泄露** | 将敏感数据写入攻击者可控路径 | Medium |

### 5.2 攻击链扩展

```
路径遍历 → 任意文件写入 → 权限提升 → 横向移动 → 集群沦陷
```

**典型攻击链示例**:
1. 设置 `spark.local.dirs=/../../root/.ssh`
2. Shuffle 数据写入 `/root/.ssh/temp_shuffle_<uuid>.data`
3. 如果数据内容可控，重命名为 `authorized_keys`
4. 获得 root SSH 访问权限

---

## 6. 修复建议

### 6.1 立即修复（高优先级）

**修复点 1: JNI 入口验证**
```cpp
// SparkJniWrapper.cpp:103-105
auto local_dirs = env->GetStringUTFChars(local_dirs_jstr, JNI_FALSE);

// 新增: 路径验证函数
bool ValidateLocalDir(const std::string& path) {
    // 1. 检查是否为绝对路径
    if (path.empty() || path[0] != '/') return false;
    
    // 2. 规范化路径，检测 ".." 序列
    std::string normalized = NormalizePath(path);
    if (normalized.find("..") != std::string::npos) return false;
    
    // 3. 检查是否在允许的根目录范围内
    const std::vector<std::string> allowed_roots = {"/tmp", "/var/tmp", "/var/lib/spark"};
    for (const auto& root : allowed_roots) {
        if (normalized.substr(0, root.length()) == root) return true;
    }
    return false;
}

// 在 setenv 之前验证
std::vector<std::string> dirs = SplitByComma(local_dirs);
for (const auto& dir : dirs) {
    if (!ValidateLocalDir(dir)) {
        env->ThrowNew(runtimeExceptionClass,
            std::string("Invalid local_dir path: " + dir).c_str());
        return 0;
    }
}
setenv("NATIVESQL_SPARK_LOCAL_DIRS", local_dirs, 1);
```

**修复点 2: 路径规范化**
```cpp
// utils.h 新增函数
std::string NormalizePath(const std::string& path) {
    std::vector<std::string> components;
    std::stringstream ss(path);
    std::string component;
    
    while (std::getline(ss, component, '/')) {
        if (component.empty() || component == ".") continue;
        if (component == "..") {
            if (!components.empty()) components.pop_back();
        } else {
            components.push_back(component);
        }
    }
    
    std::string result = "/";
    for (size_t i = 0; i < components.size(); ++i) {
        result += components[i];
        if (i < components.size() - 1) result += "/";
    }
    return result;
}
```

**修复点 3: ConcatAbstractPath 增强**
```cpp
// utils.h:102-111 修改
std::string ConcatAbstractPath(const std::string& base, const std::string& stem) {
    if(stem.empty()) {
        throw std::runtime_error("stem empty!");
    }
    
    // 新增: 检查 stem 不包含路径遍历序列
    if (stem.find("..") != std::string::npos) {
        throw std::runtime_error("Path traversal detected in stem!");
    }
    
    std::string result = EnsureTrailingSlash(NormalizePath(base)) + RemoveLeadingSlash(stem);
    
    // 新增: 最终路径验证
    if (result.find("..") != std::string::npos) {
        throw std::runtime_error("Path traversal in final path!");
    }
    
    return result;
}
```

### 6.2 配置层防御

**Java 层验证**:
```scala
// ColumnarShuffleWriter.scala 新增验证
private def validateLocalDirs(dirs: Array[String]): Array[String] = {
    dirs.map { dir =>
        val normalized = new File(dir).getCanonicalPath
        // 检查规范化后的路径是否仍在允许范围内
        if (!normalized.startsWith("/tmp") && 
            !normalized.startsWith("/var/tmp") &&
            !normalized.startsWith("/var/lib/spark")) {
            throw new IllegalArgumentException(s"Invalid local dir: $dir")
        }
        normalized
    }
}

private val localDirs = validateLocalDirs(
    blockManager.diskBlockManager.localDirs
).mkString(",")
```

### 6.3 长期改进建议

1. **配置白名单**: 在 Spark 配置层面限制 `spark.local.dirs` 可接受的路径范围
2. **权限隔离**: 确保运行 Spark Executor 的用户权限最小化
3. **审计日志**: 记录所有文件创建/写入操作的完整路径
4. **沙箱机制**: 使用 namespace/chroot 隔离文件系统访问

---

## 7. 结论

**漏洞判定**: **真实漏洞**

**置信度**: 85 → 90 (基于完整数据流验证)

**理由**:
1. 完整的数据流从 JNI Source 到 File Write Sink 已验证
2. 全程缺乏路径验证/规范化
3. `ConcatAbstractPath()` 仅处理前导斜杠，不检测 `..` 序列
4. `open()` 使用 `O_CREAT | O_TRUNC` 标志可覆盖现有文件
5. 环境变量作为中间传递媒介，进一步放大风险

**修复优先级**: Critical，建议立即修复 JNI 入口验证层。