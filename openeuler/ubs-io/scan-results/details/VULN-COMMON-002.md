# VULN-COMMON-002: TLS库句柄指针赋值错误致静态变量Use-After-Free漏洞

## 漏洞概要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-COMMON-002 |
| **漏洞类型** | 指针赋值错误 → Use-After-Free |
| **CWE分类** | CWE-667: Improper Locking |
| **严重性** | MEDIUM (确认后评估) |
| **置信度** | 95% (已确认为真实漏洞) |
| **影响文件** | `ubsio-boostio/src/common/bio_tls_util.h` |
| **影响行号** | 62-69 (CloseTlsLib 函数) |
| **关键错误行** | 第 67 行 |

---

## 1. 漏洞详情分析

### 1.1 漏洞代码

**文件**: `ubsio-boostio/src/common/bio_tls_util.h`

```cpp
// 第 35-39 行: 静态句柄存储
static inline void **GetTlsLibHandler()
{
    static void *decryptLibHandle = nullptr;  // 静态变量存储库句柄
    return &decryptLibHandle;
}

// 第 41-60 行: 加载解密函数
static inline DecryptFunc LoadDecryptFunction(const char *decrypterLibPath)
{
    void **decryptLibHandlePtr = GetTlsLibHandler();  // 获取静态变量的地址

    if (*decryptLibHandlePtr == nullptr) {
        *decryptLibHandlePtr = dlopen(decrypterLibPath, RTLD_LAZY);
    }

    if (*decryptLibHandlePtr != nullptr) {
        const auto decryptFunc = (DecryptFunc)dlsym(*decryptLibHandlePtr, "DecryptPassword");
        if (decryptFunc != nullptr) {
            return decryptFunc;
        } else {
            CloseTlsLib();  // dlsym 失败时关闭库
            return nullptr;
        }
    }

    return nullptr;
}

// 第 62-69 行: 关闭库 - 存在 BUG
static inline void CloseTlsLib()
{
    void **decryptLibHandlePtr = GetTlsLibHandler();
    if (*decryptLibHandlePtr != nullptr) {
        dlclose(*decryptLibHandlePtr);      // ✓ 正确: 关闭库
        decryptLibHandlePtr = nullptr;      // ✗ 错误: 只修改了局部变量！
        // 应该是: *decryptLibHandlePtr = nullptr;
    }
}
```

### 1.2 漏洞根因

| 层级 | 分析 |
|------|------|
| **代码层面** | `decryptLibHandlePtr` 是局部变量，存储的是 `&decryptLibHandle`（静态变量地址）。`decryptLibHandlePtr = nullptr` 只修改了局部变量本身，没有修改静态变量 `decryptLibHandle`。 |
| **内存模型** | 调用 `dlclose()` 后，动态库被卸载，但静态变量 `decryptLibHandle` 仍然保持着旧的句柄值（现已无效的悬空指针）。 |
| **设计意图** | 原本应该将静态变量清零，以便后续重新加载。但错误赋值导致静态变量永远不会被重置。 |

---

## 2. 漏洞触发条件

### 2.1 必要条件

1. **库路径可配置**: `decrypterLibPath` 来自配置文件（`bio_config_instance.cpp` 第 141 行）
2. **首次加载失败**: 提供的动态库不包含 `DecryptPassword` 符号
3. **二次加载尝试**: 程序再次调用 `LoadDecryptFunction()`

### 2.2 完整触发链

```
用户配置 decrypterLibPath
         ↓
bio_server.cpp / bio_client.cpp 读取配置
         ↓
net_engine.cpp::PrepareTlsDecrypter()
         ↓
TlsUtil::LoadDecryptFunction(path)
         ↓
    dlopen() 成功 → 句柄保存到 decryptLibHandle
         ↓
    dlsym(handle, "DecryptPassword") 失败（符号不存在）
         ↓
    CloseTlsLib() 被调用
         ↓
    dlclose() 关闭库 ✓
         ↓
    decryptLibHandlePtr = nullptr ✗ (只修改局部变量)
         ↓
    decryptLibHandle 仍然保持旧值（悬空指针）
         ↓
再次调用 LoadDecryptFunction(newPath)
         ↓
    *decryptLibHandlePtr != nullptr (条件为真，跳过 dlopen)
         ↓
    dlsym(悬空句柄, ...) → USE-AFTER-FREE
```

### 2.3 代码路径追踪

**调用入口**:
```cpp
// net_engine.cpp:794-810
BResult NetEngine::PrepareTlsDecrypter(const NetOptions &config)
{
    if (config.decrypterLibPath.empty()) {
        RegisterDecryptHandler(static_cast<DecryptFunc>(TlsUtil::DefaultDecrypter));
        return BIO_OK;
    }

    const auto decrypter = TlsUtil::LoadDecryptFunction(config.decrypterLibPath.c_str());
    if (decrypter == nullptr) {
        LOG_ERROR("Failed to load customized decrypt function.");
        return BIO_INVALID_PARAM;
    }
    // ...
}
```

**调用时机**:
- `net_engine.cpp:485`: `NetEngine::Init()` 中调用
- `net_engine.cpp:588`: `NetEngine::ReConfig()` 中调用

---

## 3. PoC 构造思路

### 3.1 环境准备

**恶意库构造 (malicious_lib.cpp)**:
```cpp
// 编译: g++ -shared -fPIC -o malicious_lib.so malicious_lib.cpp
// 故意不导出 DecryptPassword 符号

// 不包含 DecryptPassword 函数，仅包含其他符号
extern "C" {
    void DummyFunction() {
        // 故意为空
    }
}
```

### 3.2 触发场景模拟

**场景 1: 基础触发 (DoS)**
```cpp
// 步骤 1: 首次加载 - 使用恶意库（无 DecryptPassword 符号）
// 配置文件设置: decrypterLibPath = "/path/to/malicious_lib.so"
auto func1 = TlsUtil::LoadDecryptFunction("/path/to/malicious_lib.so");
// 结果: func1 == nullptr, 库被关闭，但 decryptLibHandle 未清零

// 步骤 2: 二次加载 - 使用有效库
auto func2 = TlsUtil::LoadDecryptFunction("/path/to/valid_decrypter.so");
// BUG: *decryptLibHandlePtr != nullptr (因为之前未清零)
// 跳过 dlopen，直接使用悬空句柄调用 dlsym
// 结果: 使用已关闭的句柄 → USE-AFTER-FREE → 可能崩溃
```

**场景 2: 服务重配触发**
```
1. 服务启动，配置无效库路径
2. NetEngine::Init() 调用 PrepareTlsDecrypter()，加载失败
3. 管理员修改配置，使用有效库路径
4. 调用 NetEngine::ReConfig()
5. 再次调用 PrepareTlsDecrypter()，使用新路径
6. 但由于 bug，实际使用悬空句柄
7. 服务崩溃或行为异常
```

### 3.3 利用场景分析

**攻击向量**:
```
攻击者控制配置文件
         ↓
设置 decrypterLibPath 为恶意库（无 DecryptPassword）
         ↓
服务启动/重载时触发 CloseTlsLib()
         ↓
句柄成为悬空指针
         ↓
后续重配或重试时使用悬空句柄
         ↓
dlsym() 访问已释放内存
         ↓
DoS (服务崩溃) 或潜在代码执行
```

---

## 4. 实际可利用性评估

### 4.1 利用难度分析

| 因素 | 评估 |
|------|------|
| **攻击者需要控制的资源** | 配置文件中的 `decrypterLibPath` |
| **前置条件** | 能够修改服务配置并触发服务重启/重载 |
| **利用复杂度** | 低 - 只需构造不包含 DecryptPassword 的库 |
| **可靠触发** | 中 - 需要两次加载操作 |

### 4.2 影响范围

| 影响维度 | 分析 |
|----------|------|
| **可用性** | 高 - 可导致服务崩溃 (DoS) |
| **完整性** | 低 - 不太可能直接导致数据篡改 |
| **机密性** | 低 - 不太可能直接导致信息泄露 |
| **代码执行** | 低-中 - 取决于 dlclose 后内存状态 |

### 4.3 风险评级

**严重性**: MEDIUM
- 可靠的 DoS 攻击路径
- 代码执行难度较高（需要堆布局控制）
- 需要特定配置触发

**攻击复杂度**: MEDIUM
- 需要能够修改配置
- 需要触发二次加载

### 4.4 实际利用限制

1. **配置访问**: 攻击者需要能够修改服务配置文件
2. **服务重启**: 需要触发服务重新加载配置
3. **内存状态**: use-after-free 的实际影响取决于内存分配器状态
4. **dlsym 行为**: dlsym 本身操作相对安全，主要风险在内存访问

---

## 5. 修复建议

### 5.1 正确修复方案

**当前错误代码** (第 67 行):
```cpp
decryptLibHandlePtr = nullptr;  // 错误: 只修改了局部变量
```

**正确代码**:
```cpp
*decryptLibHandlePtr = nullptr;  // 正确: 解引用后赋值，修改静态变量
```

### 5.2 完整修复后的函数

```cpp
static inline void CloseTlsLib()
{
    void **decryptLibHandlePtr = GetTlsLibHandler();
    if (*decryptLibHandlePtr != nullptr) {
        dlclose(*decryptLibHandlePtr);
        *decryptLibHandlePtr = nullptr;  // 修复: 使用解引用赋值
    }
}
```

### 5.3 增强建议

**建议 1: 添加返回值**
```cpp
static inline bool CloseTlsLib()
{
    void **decryptLibHandlePtr = GetTlsLibHandler();
    if (*decryptLibHandlePtr != nullptr) {
        int ret = dlclose(*decryptLibHandlePtr);
        *decryptLibHandlePtr = nullptr;
        return ret == 0;
    }
    return true;
}
```

**建议 2: 考虑线程安全**
```cpp
// 如果可能被多线程调用，考虑添加锁
static std::mutex gTlsLibMutex;

static inline void CloseTlsLib()
{
    std::lock_guard<std::mutex> lock(gTlsLibMutex);
    void **decryptLibHandlePtr = GetTlsLibHandler();
    if (*decryptLibHandlePtr != nullptr) {
        dlclose(*decryptLibHandlePtr);
        *decryptLibHandlePtr = nullptr;
    }
}
```

### 5.4 验证测试用例

```cpp
// 测试修复后的行为
void TestCloseTlsLibReset() {
    // 1. 加载库（可以是有效的或无效的）
    TlsUtil::LoadDecryptFunction("/path/to/lib.so");
    
    // 2. 关闭库
    TlsUtil::CloseTlsLib();
    
    // 3. 验证句柄已重置
    void **handle = TlsUtil::GetTlsLibHandler();
    assert(*handle == nullptr);  // 修复后应该通过
}
```

---

## 6. 总结

### 6.1 漏洞确认

**这是一个真实的、有效的漏洞**，属于典型的指针操作错误导致的 use-after-free 问题。

### 6.2 关键发现

1. **代码错误确认**: 第 67 行 `decryptLibHandlePtr = nullptr` 应为 `*decryptLibHandlePtr = nullptr`
2. **影响确认**: 可导致服务不稳定或崩溃
3. **触发路径清晰**: 通过配置无效库路径 → 触发 CloseTlsLib → 二次加载

### 6.3 修复优先级

| 维度 | 评级 | 说明 |
|------|------|------|
| **技术正确性** | 高 | 这是明显的编码错误 |
| **服务稳定性** | 高 | 可导致服务崩溃 |
| **安全风险** | 中 | 需要特定条件触发 |

### 6.4 修复成本

**极低** - 单行代码修改，仅需将 `decryptLibHandlePtr = nullptr` 改为 `*decryptLibHandlePtr = nullptr`。

---

## 附录: 相关代码位置

| 文件 | 行号 | 说明 |
|------|------|------|
| `bio_tls_util.h` | 35-39 | GetTlsLibHandler 定义 |
| `bio_tls_util.h` | 41-60 | LoadDecryptFunction 定义 |
| `bio_tls_util.h` | 62-69 | CloseTlsLib 定义（含 BUG） |
| `bio_tls_util.h` | 67 | BUG 位置 |
| `net_engine.cpp` | 794-810 | PrepareTlsDecrypter 调用入口 |
| `net_engine.cpp` | 485 | Init 中调用 |
| `net_engine.cpp` | 588 | ReConfig 中调用 |
| `bio_config_instance.cpp` | 141 | 配置读取 |
