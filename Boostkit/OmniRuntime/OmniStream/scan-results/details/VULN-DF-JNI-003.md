# VULN-DF-JNI-003：JNI Channel Info JSON解析异常安全漏洞

## 漏洞标识

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-DF-JNI-003 |
| **严重程度** | **High（高危）** |
| **置信度** | 85% |
| **CWE 编号** | CWE-502（不可信数据反序列化）+ CWE-755（异常处理不当） |
| **涉及模块** | jni, streaming_runtime_io（跨模块） |

---

## 一、漏洞概述

本漏洞位于 JNI 输入处理器创建函数 `createNativeOmniInputProcessor` 中，输入通道信息（Channel Info）JSON 字符串被解析时存在异常安全问题。虽然 `ReleaseStringUTFChars` 在 Line 50 被调用，但它紧接在 `json::parse()` 之后，如果解析在 Line 49 抛出异常，释放操作将被跳过。

此漏洞与 VULN-DF-JNI-002 同属 `jni_OmniStreamTask.cpp` 文件，模式相同但触发场景不同。

---

## 二、漏洞代码分析

### 原始代码（存在漏洞）

```cpp
// cpp/jni/tasks/jni_OmniStreamTask.cpp
// Lines 42-57
JNIEXPORT jlong JNICALL Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeOmniInputProcessor(
    JNIEnv *env, jclass clazz, jlong omniStreamTaskRef, jstring inputChannelInfo, jint operatorMethodIndicator)
{
    // Line 45: 获取 JNI 字符串指针
    const char *channelInfos = (env)->GetStringUTFChars(inputChannelInfo, 0);
    
    LOG("channel info is: " + std::string(channelInfos))
    
    // Line 49: 解析 JSON - 可能抛出异常！
    nlohmann::json channelJson = nlohmann::json::parse(channelInfos);
    
    // Line 50: 释放 JNI 字符串 - 如果 parse 抛异常，这行不会执行！
    env->ReleaseStringUTFChars(inputChannelInfo, channelInfos);
    
    // 后续处理
    auto *streamTask = reinterpret_cast<omnistream::datastream::StreamTask *>(omniStreamTaskRef);
    auto *processor = streamTask->createOmniInputProcessor(channelJson, operatorMethodIndicator);
    std::cout << "createNativeOmniInputProcessor operatorMethodIndicator :" << operatorMethodIndicator << std::endl;
    streamTask->addStreamOneInputProcessor(processor);
    
    return reinterpret_cast<long>(processor);
}
```

### 问题分析

| 问题 | 代码位置 | 说明 |
|------|----------|------|
| **获取 JNI 字符串** | Line 45 | `GetStringUTFChars` 获取指针 |
| **异常风险点** | Line 49 | `json::parse()` 可能抛出 `parse_error` |
| **释放位置错误** | Line 50 | 释放紧接在 parse 后，异常时跳过 |
| **无异常处理** | 无 | 无 try-catch 块 |

### 执行流程分析

```
正常流程：
GetStringUTFChars → parse 成功 → ReleaseStringUTFChars ✓ → 创建处理器

异常流程：
GetStringUTFChars → parse 抛异常 → 跳过 ReleaseStringUTFChars → 内存泄漏！
                                          ↓
                                  异常传播 → JVM 不稳定
```

---

## 三、攻击场景分析

### Channel Info 的作用

Channel Info JSON 包含输入通道的配置信息，如：
- 通道类型（本地/远程）
- 通道索引
- 网络连接信息
- 数据分区配置

攻击者如果能篡改这些信息，可以：
1. 触发 JSON 解析异常导致内存泄漏
2. 影响输入处理器的创建
3. 破坏流处理任务的输入链

### 攻击路径图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          攻击者                                          │
│  构造恶意 Channel Info JSON                                               │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 通过 JobManager 配置输入通道
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Java JobManager → TaskDeploymentDescriptor                              │
│  • 配置输入通道信息                                                       │
│  • 攻击者注入畸形 JSON                                                    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ JNI 调用 createNativeOmniInputProcessor
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  cpp/jni/tasks/jni_OmniStreamTask.cpp                                   │
│  Line 45: GetStringUTFChars(inputChannelInfo)                           │
│  Line 49: json::parse(channelInfos) → 抛出异常！                          │
│  Line 50: ReleaseStringUTFChars 被跳过                                   │
│  **内存泄漏 + 输入处理器创建失败**                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ 影响
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  **攻击效果**                                                             │
│  • JNI 内存泄漏                                                          │
│  • 输入处理器无法创建                                                      │
│  • 流处理任务无法接收输入数据                                               │
│  • 任务链中断                                                             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 四、利用条件与前置要求

| 条件类型 | 具体要求 | 难度评估 |
|----------|----------|----------|
| **任务配置** | 能控制 Channel Info 配置 | 需要作业配置权限 |
| **JSON 格式** | 提供畸形 JSON 触发解析异常 | 低 |
| **触发时机** | 任务初始化时创建输入处理器 | 自动触发 |

### 利用难度评估

- **攻击复杂度**：低（只需配置畸形 Channel Info）
- **前置条件**：中等（需要作业配置权限）
- **影响范围**：高（直接影响任务输入处理）

---

## 五、潜在影响范围

### 直接影响

1. **输入处理器创建失败**
   - 无法创建 OmniInputProcessor
   - 任务无法接收输入数据
   - 流处理链从源头中断

2. **内存泄漏**
   - 每次异常泄漏 Channel Info 字符串内存
   - Channel Info 可能较大（包含多个通道配置）
   - 反复攻击可耗尽内存

3. **任务无法启动**
   - 输入处理器是任务启动的前提条件
   - 创建失败意味着任务无法运行

### 间接影响

1. **作业链断裂**：整个流处理作业无法运行
2. **资源浪费**：TaskExecutor 资源被占用但任务无法工作
3. **集群不稳定**：大量任务启动失败影响调度

---

## 六、代码证据

### 与其他漏洞对比

| 漏洞 | 文件 | 函数 | 问题点 |
|------|------|------|--------|
| VULN-DF-JNI-001 | init.cpp | initTMConfiguration | 无 ReleaseStringUTFChars |
| VULN-DF-JNI-002 | jni_OmniStreamTask.cpp | createNativeStreamTask | Release 在 parse 后 |
| **VULN-DF-JNI-003** | jni_OmniStreamTask.cpp | createNativeOmniInputProcessor | Release 在 parse 后 |

### 当前代码的危险模式

```cpp
// Line 45-50 的危险顺序
const char *channelInfos = (env)->GetStringUTFChars(inputChannelInfo, 0);  // 获取
nlohmann::json channelJson = nlohmann::json::parse(channelInfos);          // 解析（可能抛异常）
env->ReleaseStringUTFChars(inputChannelInfo, channelInfos);                // 释放（异常时跳过！）
```

### 正确模式参考

```cpp
// 正确的顺序：获取 → 复制 → 释放 → 解析
const char *channelInfos = env->GetStringUTFChars(inputChannelInfo, nullptr);
std::string channelInfoCopy(channelInfos);  // 立即复制
env->ReleaseStringUTFChars(inputChannelInfo, channelInfos);  // 立即释放（在 parse 之前）
nlohmann::json channelJson = nlohmann::json::parse(channelInfoCopy);  // 解析安全副本
```

---

## 七、修复建议

### 紧急修复（优先级 P0）

```cpp
// cpp/jni/tasks/jni_OmniStreamTask.cpp - 修复版本
JNIEXPORT jlong JNICALL Java_com_huawei_omniruntime_flink_runtime_tasks_OmniStreamTask_createNativeOmniInputProcessor(
    JNIEnv *env, jclass clazz, jlong omniStreamTaskRef, jstring inputChannelInfo, jint operatorMethodIndicator)
{
    // 1. 获取 JNI 字符串
    const char *channelInfos = env->GetStringUTFChars(inputChannelInfo, nullptr);
    if (channelInfos == nullptr) {
        env->ExceptionClear();
        LOG_ERROR("Failed to get channel info string from JNI");
        return 0;
    }
    
    // 2. 立即复制到安全内存
    std::string channelInfoCopy(channelInfos);
    LOG("channel info is: " + channelInfoCopy);
    
    // 3. 立即释放 JNI 内存（在 parse 之前！）
    env->ReleaseStringUTFChars(inputChannelInfo, channelInfos);
    
    // 4. 添加异常处理
    try {
        nlohmann::json channelJson = nlohmann::json::parse(channelInfoCopy);
        
        auto *streamTask = reinterpret_cast<omnistream::datastream::StreamTask *>(omniStreamTaskRef);
        auto *processor = streamTask->createOmniInputProcessor(channelJson, operatorMethodIndicator);
        
        std::cout << "createNativeOmniInputProcessor operatorMethodIndicator :" 
                  << operatorMethodIndicator << std::endl;
        streamTask->addStreamOneInputProcessor(processor);
        
        return reinterpret_cast<long>(processor);
        
    } catch (const nlohmann::json::parse_error& e) {
        LOG_ERROR("Failed to parse channel info JSON: " + std::string(e.what()));
        return 0;
    } catch (const std::exception& e) {
        LOG_ERROR("Unexpected error creating input processor: " + std::string(e.what()));
        return 0;
    }
}
```

---

## 八、验证方法

### 测试用例

```cpp
TEST(JniInputProcessor, MalformedChannelInfo) {
    JNIEnv* env = getMockJNIEnv();
    jstring malformedChannel = env->NewStringUTF("{\"channels\": [}");
    
    jlong result = createNativeOmniInputProcessor(env, nullptr, mockTaskRef, malformedChannel, 0);
    EXPECT_EQ(result, 0);  // 应返回错误码
    EXPECT_FALSE(env->ExceptionCheck());  // 异常应被处理
}

TEST(JniInputProcessor, MemoryLeakOnException) {
    JNIEnv* env = getMockJNIEnv();
    jstring malformedChannel = env->NewStringUTF("{\"invalid\": }");
    
    size_t before = getJniMemoryUsage(env);
    for (int i = 0; i < 100; i++) {
        createNativeOmniInputProcessor(env, nullptr, mockTaskRef, malformedChannel, 0);
    }
    size_t after = getJniMemoryUsage(env);
    
    EXPECT_NEAR(before, after, 1024);  // 无显著泄漏
}

TEST(JniInputProcessor, ValidChannelInfo) {
    JNIEnv* env = getMockJNIEnv();
    jstring validChannel = env->NewStringUTF("{\"channels\": []}");
    
    jlong result = createNativeOmniInputProcessor(env, nullptr, mockTaskRef, validChannel, 0);
    EXPECT_NE(result, 0);  // 应成功创建
}
```

---

## 九、总结

| 维度 | 评估 |
|------|------|
| **漏洞真实性** | ✅ 确认存在异常安全问题 |
| **攻击可达性** | ✅ 高（输入处理器创建是关键入口） |
| **攻击复杂度** | ✅ 低（只需配置畸形 Channel Info） |
| **影响严重性** | ✅ 高（可导致任务无法启动） |
| **修复紧迫性** | ✅ **High**（应立即修复） |

**建议处理顺序**：
1. 与 VULN-DF-JNI-001/002 同步修复
2. 创建统一的 JNI 字符串处理辅助类
3. 统一所有 JNI 入口的异常处理模式