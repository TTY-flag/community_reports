# VULN-SEC-UDF-004: 安全控制绕过漏洞

## 漏洞概述

**漏洞类型**: 安全控制绕过 (CWE-693)  
**严重级别**: Critical  
**置信度**: 95%  
**影响模块**: codegen, udf

OmniOperator 的 `EvaluateHiveUdfSingle` 和 `EvaluateHiveUdfBatch` 函数使用 `extern DLLEXPORT` 公开导出，允许外部代码直接调用并传入任意 `udfClass` 参数。这完全绕过了 `func_registry_hive_udf.cpp` 中实现的属性文件白名单机制。

## 漏洞触发条件

1. 攻击者能够直接调用共享库中的导出函数
2. 攻击者能够传入任意 UDF 类名参数
3. 攻击者能够在指定目录放置恶意 Java 类文件

## 完整攻击路径

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Security Control Bypass Flow                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  正常路径（有白名单保护）:                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ SQL → JSONParser → func_registry_hive_udf.cpp                       │    │
│  │        ↓                                                            │    │
│  │      属性文件白名单检查 ← 安全控制                                    │    │
│  │        ↓                                                            │    │
│  │      仅允许预定义类名                                                │    │
│  │        ↓                                                            │    │
│  │      ExecuteHiveUdfSingle                                           │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  攻击路径（完全绕过白名单）:                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 外部攻击者                                                           │    │
│  │        ↓                                                            │    │
│  │ 直接调用 DLLEXPORT 函数                                             │    │
│  │ udffunctions.cpp:29 EvaluateHiveUdfSingle()                         │    │
│  │        ↓                                                            │    │
│  │ 【无任何验证，直接接收 udfClass 参数】                                │    │
│  │        ↓                                                            │    │
│  │ ExecuteHiveUdfSingle(contextPtr, "attacker.MaliciousClass", ...)   │    │
│  │        ↓                                                            │    │
│  │ JNI → Class.forName → 任意代码执行                                  │    │
│  │                                                                     │    │
│  │ ⚠️ 属性文件白名单机制从未被检查                                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 关键代码分析

### udffunctions.cpp:29-40

```cpp
extern DLLEXPORT void EvaluateHiveUdfSingle(int64_t contextPtr, const char *udfClass,
    int32_t *inputTypes, int32_t retType, int32_t vecCount, ...)
{
    std::call_once(init_udf_flag, InitHiveUdf);
    if (!g_isUdfInited) {
        SetError(contextPtr, INIT_UDF_FAILED);
        return;
    }
    // ⚠️ 关键缺陷: 无验证直接传递 udfClass 参数
    ExecuteHiveUdfSingle(contextPtr, udfClass, inputTypes, retType, vecCount, ...);
}
```

**安全缺陷分析**:
- `extern DLLEXPORT` 使函数对外公开可见
- `udfClass` 参数直接接收外部输入
- 没有任何白名单检查或格式验证
- 属性文件白名单机制完全被绕过

### func_registry_hive_udf.cpp 白名单机制

```cpp
// 这个白名单检查只在通过属性文件注册的 UDF 调用时生效
// DLLEXPORT 直接调用时，此检查从未执行
```

## 利用步骤 (PoC)

### 直接调用攻击

```cpp
// attacker_code.cpp - 直接调用导出函数
#include <dlfcn.h>

int main() {
    // 加载 OmniOperator 共享库
    void* handle = dlopen("libomni_operator.so", RTLD_NOW);
    
    // 获取导出函数地址
    typedef void (*EvaluateFunc)(int64_t, const char*, ...);
    EvaluateFunc eval = (EvaluateFunc)dlsym(handle, "EvaluateHiveUdfSingle");
    
    // 直接传入恶意类名，完全绕过白名单
    int64_t context = create_context();
    eval(context, "attacker.MaliciousClass", inputTypes, retType, ...);
    
    // 恶意类的静态初始化器执行，完成攻击
    dlclose(handle);
    return 0;
}
```

### JNI 绑定攻击

```java
// 如果攻击者能在 JVM 中运行代码，可以通过 JNI 绑定直接调用
public class Attacker {
    // 假设 JNI 绑定暴露了这些函数
    native void evaluateHiveUdfSingle(long context, String udfClass, ...);
    
    public void attack() {
        // 绕过所有安全检查
        evaluateHiveUdfSingle(ctx, "attacker.MaliciousClass", ...);
    }
}
```

## 危害评估

### 攻击场景
- **本地攻击者**: 能够加载共享库的攻击者可直接调用导出函数
- **提权攻击**: 从 SQL 注入点扩展到代码执行
- **横向移动**: 在同一节点上运行的其他进程

### CVSS 评分预估
- **攻击向量**: Local (需要本地代码执行能力)
- **攻击复杂度**: Low
- **权限要求**: Low
- **影响**: High (完全绕过安全控制)

**预估 CVSS 评分**: 8.5 (High)

## 修复建议

### 1. 移除 DLLEXPORT 导出（优先级：高）

```cpp
// udffunctions.cpp
// 移除 extern DLLEXPORT，改为内部 static 函数
static void EvaluateHiveUdfSingle(int64_t contextPtr, const char *udfClass, ...)
{
    // 保持原有逻辑，但不再对外公开
    ...
}
```

### 2. 在导出函数入口添加验证（优先级：高）

```cpp
// 如果必须保留导出，添加白名单验证
extern DLLEXPORT void EvaluateHiveUdfSingle(...)
{
    // 获取白名单
    const auto& allowedClasses = FunctionRegistry::GetAllowedUdfClasses();
    
    // 验证 udfClass 是否在白名单中
    if (allowedClasses.find(udfClass) == allowedClasses.end()) {
        SetError(contextPtr, "UDF class not in whitelist: " + std::string(udfClass));
        LogSecurity("Unauthorized UDF attempt: class=%s", udfClass);
        return;
    }
    
    // 原有逻辑
    ...
}
```

### 3. 添加调用来源验证（优先级：中）

```cpp
// 验证调用是否来自合法的代码生成路径
static bool IsValidCaller() {
    // 检查调用栈，验证来自 ExpressionEvaluator
    ...
}
```

## 相关漏洞

- VULN-XMOD-001: 完整 UDF 攻击链
- VULN-SEC-UDF-001: 任意代码执行
- udf-001: 信任边界违规

## 参考信息

- CWE-693: Mechanism Failure to Enforce Access Control
- OWASP: Broken Access Control