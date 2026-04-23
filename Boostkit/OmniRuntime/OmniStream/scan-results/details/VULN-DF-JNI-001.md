# VULN-DF-JNI-001：JNI init.cpp JSON解析异常安全漏洞

## 漏洞标识

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-DF-JNI-001 / SEC-001 |
| **严重程度** | **High（高危）** |
| **置信度** | 85% |
| **CWE 编号** | CWE-502（不可信数据反序列化）+ CWE-401（内存泄漏） |
| **涉及模块** | jni |
| **关联漏洞** | SEC-001 为同一漏洞的重复报告 |

---

## 一、漏洞概述

本漏洞位于 JNI 配置初始化函数 `initTMConfiguration` 中，存在两个严重安全问题：

1. **内存泄漏**：`GetStringUTFChars` 获取的 JNI 字符串指针从未通过 `ReleaseStringUTFChars` 释放
2. **异常安全缺失**：`json::parse()` 调用无 try-catch 保护，异常将直接传播到 JVM

这两个问题组合在一起，形成严重的安全风险：当传入畸形 JSON 配置时，解析异常会触发，但 JNI 内存永远不会释放，最终导致 JVM 内存耗尽。

---

## 二、漏洞代码分析

### 原始代码（存在漏洞）

```cpp
// cpp/jni/init.cpp
// Line 50-55
JNIEXPORT void JNICALL Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration(
    JNIEnv *env, jclass, jstring configStr)
{
    const char *cStrCon = (env)->GetStringUTFChars(configStr, 0);  // Line 52: 获取 JNI 字符串
    nlohmann::json config = nlohmann::json::parse(cStrCon);        // Line 53: 解析 JSON（可能抛异常）
    Configuration::TM_CONFIG->setConfiguration(config);            // Line 54: 设置配置
    // 函数结束，但从未调用 ReleaseStringUTFChars！
}
```

### 问题分析

| 问题 | 代码位置 | 说明 |
|------|----------|------|
| **内存泄漏** | Line 52 | `GetStringUTFChars` 获取 JNI 字符串指针 |
| **无释放** | 无 | 整个函数中没有 `ReleaseStringUTFChars` 调用 |
| **异常风险** | Line 53 | `json::parse()` 可能抛出 `parse_error` 异常 |
| **异常传播** | 无 | 无 try-catch，异常直接传播到 JVM |

---

## 三、攻击场景分析

### 正常执行流程

```
Java 调用 initTMConfiguration(configStr)
    ↓
GetStringUTFChars(configStr) → 获取 cStrCon 指针
    ↓
json::parse(cStrCon) → 成功解析
    ↓
setConfiguration(config) → 设置配置
    ↓
函数返回（但 cStrCon 未释放！）
    ↓
JNI 内存泄漏
```

### 异常触发流程

```
Java 调用 initTMConfiguration(malformedJson)
    ↓
GetStringUTFChars(configStr) → 获取 cStrCon 指针
    ↓
json::parse(cStrCon) → 抛出 parse_error 异常！
    ↓
异常传播到 JVM（cStrCon 仍未释放）
    ↓
JVM 捕获异常，但 JNI 内存已永久泄漏
```

### 攻击效果

| 攻击方式 | 效果 | 影响程度 |
|----------|------|----------|
| 传入畸形 JSON | 触发 parse_error 异常 | 进程可能崩溃 |
| 反复调用畸形配置 | 每次泄漏 JNI 内存 | 最终 JVM 内存耗尽 |
| 特定畸形 JSON | 触发 nlohmann/json 内部问题 | 可能导致更严重后果 |

---

## 四、利用条件与前置要求

| 条件类型 | 具体要求 | 难度评估 |
|----------|----------|----------|
| **调用入口** | 能调用 initTMConfiguration | 配置初始化阶段 |
| **参数控制** | 能控制 configStr 内容 | 需要控制配置源 |
| **JSON 格式** | 提供畸形 JSON 触发解析异常 | 低 |

### 利用难度评估

- **攻击复杂度**：低（只需发送畸形 JSON）
- **前置条件**：中等（需要能影响配置初始化）
- **影响范围**：高（TaskManager 初始化失败）

---

## 五、潜在影响范围

### 直接影响

1. **内存泄漏**
   - 每次调用泄漏一个 JNI 字符串内存块
   - 大小取决于输入字符串长度
   - 反复调用可耗尽 JVM 内存

2. **进程崩溃**
   - 异常传播到 JVM 可能导致进程终止
   - TaskManager 初始化失败
   - 集群可能无法启动新的 TaskManager

3. **拒绝服务**
   - 恶意配置阻止正常初始化
   - 集群管理功能受影响

### 间接影响

1. **集群稳定性**：多个 TaskManager 无法正常初始化
2. **任务启动失败**：依赖配置的任务无法启动
3. **资源浪费**：泄漏的内存无法回收

---

## 六、代码证据

### 正确模式对比

在其他 JNI 文件中存在正确的处理模式：

#### 正确模式 1：复制后立即释放

```cpp
// cpp/jni/taskexecutor/jni_OmniTaskExecutor.cpp
// Lines 50-56（正确示例）
const char* jobString = jniEnv->GetStringUTFChars(jobjson, nullptr);
std::string jobInfoString(jobString);       // 复制到安全内存
jniEnv->ReleaseStringUTFChars(jobjson, jobString);  // 立即释放！
nlohmann::json job = nlohmann::json::parse(jobInfoString);  // 解析安全副本
```

#### 正确模式 2：RAII 包装器

```cpp
// 建议的 JniStringHolder 类
class JniStringHolder {
    JNIEnv* env_;
    jstring jstr_;
    const char* cstr_;
public:
    JniStringHolder(JNIEnv* env, jstring jstr) 
        : env_(env), jstr_(jstr), cstr_(env->GetStringUTFChars(jstr, nullptr)) {}
    ~JniStringHolder() { if (cstr_) env_->ReleaseStringUTFChars(jstr_, cstr_); }
    const char* get() const { return cstr_; }
    std::string toString() const { return std::string(cstr_ ? cstr_ : ""); }
};
```

### 错误模式证据

通过 grep 搜索验证问题：

```bash
# init.cpp 中 GetStringUTFChars 被调用
grep "GetStringUTFChars" cpp/jni/init.cpp
# 输出：Line 52: const char *cStrCon = (env)->GetStringUTFChars(configStr, 0);

# 但 init.cpp 中没有 ReleaseStringUTFChars
grep "ReleaseStringUTFChars" cpp/jni/init.cpp
# 输出：（无结果）

# 对比其他文件
grep "ReleaseStringUTFChars" cpp/jni/taskexecutor/jni_OmniTaskExecutor.cpp
# 输出：多处正确调用
```

---

## 七、修复建议

### 紧急修复（优先级 P0）

#### 方案 1：复制后立即释放

```cpp
// cpp/jni/init.cpp - 修复版本
JNIEXPORT void JNICALL Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration(
    JNIEnv *env, jclass, jstring configStr)
{
    // 1. 获取 JNI 字符串
    const char *cStrCon = env->GetStringUTFChars(configStr, nullptr);
    if (cStrCon == nullptr) {
        // JNI 内存不足或异常
        env->ExceptionClear();
        return;
    }
    
    // 2. 立即复制到安全内存
    std::string configStrCopy(cStrCon);
    
    // 3. 立即释放 JNI 内存（在 parse 之前！）
    env->ReleaseStringUTFChars(configStr, cStrCon);
    
    // 4. 添加异常处理
    try {
        nlohmann::json config = nlohmann::json::parse(configStrCopy);
        Configuration::TM_CONFIG->setConfiguration(config);
    } catch (const nlohmann::json::parse_error& e) {
        LOG_ERROR("Failed to parse TM configuration: " + std::string(e.what()));
        // 根据业务需求处理错误
        throw std::runtime_error("Invalid TM configuration JSON");
    } catch (const std::exception& e) {
        LOG_ERROR("Unexpected error parsing configuration: " + std::string(e.what()));
        throw;
    }
}
```

#### 方案 2：使用 RAII 包装器

```cpp
// cpp/jni/utils/JniStringHolder.h - 新建辅助类
class JniStringHolder {
private:
    JNIEnv* env_;
    jstring jstr_;
    const char* cstr_;
    bool released_;
    
public:
    JniStringHolder(JNIEnv* env, jstring jstr) 
        : env_(env), jstr_(jstr), released_(false) {
        cstr_ = env->GetStringUTFChars(jstr, nullptr);
    }
    
    ~JniStringHolder() {
        if (!released_ && cstr_) {
            env_->ReleaseStringUTFChars(jstr_, cstr_);
        }
    }
    
    const char* get() const { return cstr_; }
    bool valid() const { return cstr_ != nullptr; }
    std::string toString() const { return cstr_ ? std::string(cstr_) : ""; }
    
    void release() {
        if (!released_ && cstr_) {
            env_->ReleaseStringUTFChars(jstr_, cstr_);
            released_ = true;
        }
    }
};

// cpp/jni/init.cpp - 使用 RAII
JNIEXPORT void JNICALL Java_org_apache_flink_runtime_taskexecutor_TaskManagerRunner_initTMConfiguration(
    JNIEnv *env, jclass, jstring configStr)
{
    JniStringHolder holder(env, configStr);  // RAII：析构时自动释放
    if (!holder.valid()) {
        env->ExceptionClear();
        return;
    }
    
    try {
        nlohmann::json config = nlohmann::json::parse(holder.toString());
        Configuration::TM_CONFIG->setConfiguration(config);
    } catch (const nlohmann::json::parse_error& e) {
        LOG_ERROR("JSON parse error: " + std::string(e.what()));
    }
}
```

---

## 八、验证方法

### 测试用例

```cpp
TEST(JniInitSafety, MemoryLeak) {
    JNIEnv* env = getMockJNIEnv();
    jstring testStr = env->NewStringUTF("{\"test\": \"value\"}");
    
    // 验证修复后无内存泄漏
    size_t before = getJniMemoryUsage(env);
    for (int i = 0; i < 1000; i++) {
        initTMConfiguration(env, nullptr, testStr);
    }
    size_t after = getJniMemoryUsage(env);
    
    EXPECT_NEAR(before, after, 1024);  // 允许少量波动
}

TEST(JniInitSafety, ExceptionHandling) {
    JNIEnv* env = getMockJNIEnv();
    jstring malformedStr = env->NewStringUTF("{\"test\": \"value\"");
    
    // 验证畸形 JSON 不导致崩溃
    EXPECT_NO_THROW(initTMConfiguration(env, nullptr, malformedStr));
    
    // 验证异常被正确处理
    EXPECT_FALSE(env->ExceptionCheck());
}

TEST(JniInitSafety, CorrectPattern) {
    JNIEnv* env = getMockJNIEnv();
    jstring validStr = env->NewStringUTF("{\"key\": \"value\"}");
    
    // 验证正常功能
    initTMConfiguration(env, nullptr, validStr);
    EXPECT_TRUE(Configuration::TM_CONFIG->hasConfiguration());
}
```

---

## 九、总结

| 维度 | 评估 |
|------|------|
| **漏洞真实性** | ✅ 确认存在内存泄漏和异常安全问题 |
| **攻击可达性** | ✅ 高（配置初始化是关键入口） |
| **攻击复杂度** | ✅ 低（只需发送畸形 JSON） |
| **影响严重性** | ✅ 高（可导致内存耗尽和进程崩溃） |
| **修复紧迫性** | ✅ **High**（应立即修复） |

**建议处理顺序**：
1. 立即添加 `ReleaseStringUTFChars` 调用（修复内存泄漏）
2. 添加 try-catch 异常处理（修复异常安全）
3. 创建 RAII 包装器统一处理所有 JNI 字符串