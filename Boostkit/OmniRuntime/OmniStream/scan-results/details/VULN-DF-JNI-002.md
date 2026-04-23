# VULN-DF-JNI-002：JNI StreamTask TDD JSON解析异常安全漏洞

## 漏洞标识

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-DF-JNI-002 / SEC-002 |
| **严重程度** | **High（高危）** |
| **置信度** | 85% |
| **CWE 编号** | CWE-502（不可信数据反序列化）+ CWE-755（异常处理不当） |
| **涉及模块** | jni, streaming_runtime_tasks（跨模块） |
| **关联漏洞** | SEC-002 为同一漏洞的重复报告 |

---

## 一、漏洞概述

本漏洞位于 JNI 任务创建函数 `createNativeStreamTask` 中，任务部署描述符（TDD）JSON 字符串被解析时缺乏异常安全保护。虽然存在 `ReleaseStringUTFChars` 调用，但其位置在 `json::parse()` 之后，如果解析抛出异常，释放操作将被跳过，导致 JNI 内存泄漏。

---

## 二、漏洞代码分析

### 原始代码（存在漏洞）

```cpp
// cpp/jni/tasks/jni_OmniStreamTask.cpp
// Lines 18-40
JNIEXPORT jlong JNICALL Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask(
    JNIEnv *env, jclass clazz, jstring TDDString, jlong statusAddress, jlong nativeTask)
{
    LOG("this is create native task object")
    
    // Line 21: 获取 JNI 字符串指针
    const char *cStrTDD = (env)->GetStringUTFChars(TDDString, 0);
    
    LOG("debug tdd is: " + std::string(cStrTDD))
    
    void *bufferStatus = reinterpret_cast<void *>(statusAddress);
    
    // Line 27: 解析 JSON - 可能抛出异常！
    nlohmann::json tdd = nlohmann::json::parse(cStrTDD);
    
    LOG("Calling  StreamTask with json " + tdd.dump(2))
    
    // 更新环境设置
    auto task = reinterpret_cast<omnistream::OmniTask *>(nativeTask);
    
    // Line 34: 创建 StreamTask
    auto *streamTask = new omnistream::datastream::StreamTask(tdd, bufferStatus, task->getRuntimeEnv());
    LOG("After Calling StreamTask with json  " << reinterpret_cast<long>(streamTask))
    
    // Line 37: 释放 JNI 字符串 - 但如果 parse 抛异常，这行不会执行！
    env->ReleaseStringUTFChars(TDDString, cStrTDD);
    
    return reinterpret_cast<long>(streamTask);
}
```

### 问题分析

| 问题 | 代码位置 | 说明 |
|------|----------|------|
| **获取 JNI 字符串** | Line 21 | `GetStringUTFChars` 获取指针 |
| **异常风险点** | Line 27 | `json::parse()` 可能抛出 `parse_error` |
| **释放位置错误** | Line 37 | 释放操作在 parse 之后，异常时跳过 |
| **无异常处理** | 无 | 无 try-catch 块 |

### 执行流程分析

```
正常流程：
GetStringUTFChars → parse 成功 → 创建 StreamTask → ReleaseStringUTFChars ✓

异常流程：
GetStringUTFChars → parse 抛异常 → 跳过 ReleaseStringUTFChars → 内存泄漏！
                                                    ↓
                                          异常传播到 JVM → 可能崩溃
```

---

## 三、攻击场景分析

### 攻击路径图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          攻击者                                          │
│  构造恶意 TDD JSON：{"operators": [...畸形 JSON...]}                      │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 通过 JobManager 提交任务
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Java JobManager                                                         │
│  • 构建任务部署描述符（TDD）                                               │
│  • TDD 包含算子配置、状态信息等                                            │
│  • 攻击者传入畸形 JSON                                                    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ JNI 调用 createNativeStreamTask
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  cpp/jni/tasks/jni_OmniStreamTask.cpp                                   │
│  Line 21: GetStringUTFChars(TDDString)                                  │
│  Line 27: json::parse(cStrTDD) → 抛出异常！                               │
│  Line 37: ReleaseStringUTFChars 被跳过                                   │
│  **内存泄漏 + 异常传播**                                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 异常传播到 JVM
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  **攻击效果**                                                             │
│  • JNI 内存泄漏                                                          │
│  • JVM 可能捕获异常或崩溃                                                 │
│  • 任务创建失败                                                          │
│  • TaskExecutor 不稳定                                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 攻击效果

| 攻击方式 | 效果 | 影响程度 |
|----------|------|----------|
| 畸形 TDD JSON | 触发 parse_error 异常 | 任务创建失败 |
| 深度嵌套 JSON | 消耗大量栈内存 | 可能栈溢出 |
| 反复提交恶意任务 | 每次泄漏 JNI 内存 | 最终内存耗尽 |
| 特定畸形格式 | 触发 nlohmann/json 问题 | 未知后果 |

---

## 四、利用条件与前置要求

| 条件类型 | 具体要求 | 难度评估 |
|----------|----------|----------|
| **任务提交** | 能通过 JobManager 提交任务 | 需要作业提交权限 |
| **TDD 内容** | 能控制 TDD JSON 内容 | 中等 |
| **JSON 格式** | 提供畸形 JSON 触发解析异常 | 低 |

### 利用难度评估

- **攻击复杂度**：低（只需提交畸形 JSON 任务）
- **前置条件**：中等（需要作业提交权限）
- **影响范围**：高（影响任务创建和 TaskExecutor 稳定性）

---

## 五、潜在影响范围

### 直接影响

1. **任务创建失败**
   - 畸形 TDD 导致任务无法创建
   - 流处理作业无法启动
   - 依赖该任务的其他任务链断裂

2. **内存泄漏**
   - 每次异常泄漏一个 JNI 字符串内存块
   - TDD 通常较大，泄漏量可观
   - 反复攻击可耗尽内存

3. **JVM 稳定性**
   - 异常传播到 JVM 可能影响稳定性
   - 可能触发 JVM 内部错误处理
   - TaskExecutor 可能需要重启

### 间接影响

1. **集群资源浪费**：失败的任务占用调度资源
2. **作业链中断**：依赖任务的下游算子无法工作
3. **运维负担**：需要重启 TaskExecutor 清理泄漏

---

## 六、代码证据

### 对比正确模式

在 `jni_OmniTaskExecutor.cpp` 中存在更安全的模式：

```cpp
// cpp/jni/taskexecutor/jni_OmniTaskExecutor.cpp
// Lines 50-56（较安全模式）
const char* jobString = jniEnv->GetStringUTFChars(jobjson, nullptr);
std::string jobInfoString(jobString);       // 立即复制
jniEnv->ReleaseStringUTFChars(jobjson, jobString);  // 立即释放（在 parse 之前！）
nlohmann::json job = nlohmann::json::parse(jobInfoString);  // 解析安全副本
```

### 当前代码的隐患

```cpp
// 当前 jni_OmniStreamTask.cpp 的错误顺序
const char *cStrTDD = (env)->GetStringUTFChars(TDDString, 0);  // 获取
nlohmann::json tdd = nlohmann::json::parse(cStrTDD);           // 解析（可能抛异常）
env->ReleaseStringUTFChars(TDDString, cStrTDD);                // 释放（异常时跳过！）
```

---

## 七、修复建议

### 紧急修复（优先级 P0）

#### 方案 1：复制后立即释放 + try-catch

```cpp
// cpp/jni/tasks/jni_OmniStreamTask.cpp - 修复版本
JNIEXPORT jlong JNICALL Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask(
    JNIEnv *env, jclass clazz, jstring TDDString, jlong statusAddress, jlong nativeTask)
{
    LOG("this is create native task object")
    
    // 1. 获取 JNI 字符串
    const char *cStrTDD = env->GetStringUTFChars(TDDString, nullptr);
    if (cStrTDD == nullptr) {
        env->ExceptionClear();
        LOG_ERROR("Failed to get TDD string from JNI");
        return 0;
    }
    
    // 2. 立即复制到安全内存
    std::string tddStringCopy(cStrTDD);
    LOG("debug tdd is: " + tddStringCopy);
    
    // 3. 立即释放 JNI 内存（在 parse 之前！）
    env->ReleaseStringUTFChars(TDDString, cStrTDD);
    
    // 4. 添加异常处理
    try {
        nlohmann::json tdd = nlohmann::json::parse(tddStringCopy);
        LOG("Calling StreamTask with json " + tdd.dump(2));
        
        void *bufferStatus = reinterpret_cast<void *>(statusAddress);
        auto task = reinterpret_cast<omnistream::OmniTask *>(nativeTask);
        
        auto *streamTask = new omnistream::datastream::StreamTask(tdd, bufferStatus, task->getRuntimeEnv());
        LOG("After Calling StreamTask with json " << reinterpret_cast<long>(streamTask));
        
        return reinterpret_cast<long>(streamTask);
        
    } catch (const nlohmann::json::parse_error& e) {
        LOG_ERROR("Failed to parse TDD JSON: " + std::string(e.what()));
        throw std::runtime_error("Invalid TDD JSON format");
    } catch (const std::exception& e) {
        LOG_ERROR("Unexpected error creating StreamTask: " + std::string(e.what()));
        throw;
    }
}
```

#### 方案 2：使用 RAII 包装器

```cpp
// 使用 JniStringHolder（建议创建此辅助类）
JNIEXPORT jlong JNICALL Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeStreamTask(
    JNIEnv *env, jclass clazz, jstring TDDString, jlong statusAddress, jlong nativeTask)
{
    JniStringHolder holder(env, TDDString);  // RAII：析构时自动释放
    if (!holder.valid()) {
        env->ExceptionClear();
        return 0;
    }
    
    std::string tddString = holder.toString();  // 获取安全副本
    LOG("debug tdd is: " + tddString);
    
    try {
        nlohmann::json tdd = nlohmann::json::parse(tddString);
        // ... 创建 StreamTask
        return reinterpret_cast<long>(streamTask);
    } catch (const nlohmann::json::parse_error& e) {
        LOG_ERROR("TDD parse error: " + std::string(e.what()));
        return 0;  // 或抛出异常
    }
}
```

---

## 八、验证方法

### 测试用例

```cpp
TEST(JniStreamTaskCreation, MalformedTDD) {
    JNIEnv* env = getMockJNIEnv();
    jstring malformedTDD = env->NewStringUTF("{\"operators\": [}");
    
    // 验证畸形 TDD 不导致崩溃
    jlong result = createNativeStreamTask(env, nullptr, malformedTDD, 0, 0);
    EXPECT_EQ(result, 0);  // 应返回错误码而非崩溃
    EXPECT_FALSE(env->ExceptionCheck());  // 异常应被处理
}

TEST(JniStreamTaskCreation, MemoryLeak) {
    JNIEnv* env = getMockJNIEnv();
    jstring malformedTDD = env->NewStringUTF("{\"invalid\": }");
    
    size_t before = getJniMemoryUsage(env);
    for (int i = 0; i < 100; i++) {
        createNativeStreamTask(env, nullptr, malformedTDD, 0, 0);
    }
    size_t after = getJniMemoryUsage(env);
    
    EXPECT_NEAR(before, after, 1024);  // 无显著内存泄漏
}

TEST(JniStreamTaskCreation, ValidTDD) {
    JNIEnv* env = getMockJNIEnv();
    jstring validTDD = env->NewStringUTF("{\"operators\": []}");
    
    jlong result = createNativeStreamTask(env, nullptr, validTDD, 0, mockNativeTask);
    EXPECT_NE(result, 0);  // 应成功创建
}
```

---

## 九、总结

| 维度 | 评估 |
|------|------|
| **漏洞真实性** | ✅ 确认存在异常安全问题 |
| **攻击可达性** | ✅ 高（任务创建是关键入口） |
| **攻击复杂度** | ✅ 低（只需提交畸形 TDD） |
| **影响严重性** | ✅ 高（可导致内存泄漏和任务失败） |
| **修复紧迫性** | ✅ **High**（应立即修复） |

**建议处理顺序**：
1. 立即将 `ReleaseStringUTFChars` 移到 `parse` 之前
2. 添加 try-catch 异常处理
3. 创建 RAII 包装器统一处理所有 JNI 字符串操作