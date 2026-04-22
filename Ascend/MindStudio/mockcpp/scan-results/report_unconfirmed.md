# 漏洞扫描报告 — 待确认漏洞

**项目**: mockcpp
**扫描时间**: 2026-04-21T06:10:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本次扫描针对 mockcpp C/C++ 单元测试 Mock 框架进行了深度安全分析。经过多阶段验证流程，共识别出 **3 个待确认的安全设计缺陷**，均属于中低风险级别。

### 扫描范围与发现

- **扫描范围**: 全项目源代码（C/C++），重点关注 API Hook、虚函数表操作、内存权限管理等敏感操作
- **候选漏洞总数**: 17 个
- **误报数量**: 14 个（82.4%）— 测试框架的正常功能被误识别为漏洞
- **待确认漏洞**: 3 个（17.6%）— LIKELY 1 个，POSSIBLE 2 个

### 风险评估

**整体风险等级：低**

mockcpp 作为单元测试框架，其用户群体为开发者（信任等级: semi_trusted），核心功能涉及代码段修改和函数指针操作，这些特性本身就是测试 Mock 框架的必要能力：

1. **VULN-APIHOOK-002 (LIKELY, Medium)** - Unix 平台内存权限未恢复问题，与 Windows 版本实现不一致，存在设计缺陷但影响有限
2. **VULN-VTABLE-001 (POSSIBLE, Low)** - 函数指针注入是框架预期功能，索引验证已防止越界
3. **VULN-APIHOOK-011 (POSSIBLE, Low)** - 参数缺失验证，但下游有 mprotect 保护

### 业务影响

由于项目定位为开发测试工具，上述问题不会影响生产环境安全性。建议在后续版本中进行代码改进，提升跨平台一致性和健壮性。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 14 | 82.4% |
| POSSIBLE | 2 | 11.8% |
| LIKELY | 1 | 5.9% |
| **总计** | **17** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Medium | 1 | 33.3% |
| Low | 2 | 66.7% |
| **有效漏洞总计** | **3** | - |
| 误报 (FALSE_POSITIVE) | 14 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-APIHOOK-002]** Security-Sensitive Operation without Restore (Medium) - `src/UnixCodeModifier.cpp:31` @ `CodeModifier::modify` | 置信度: 60
2. **[VULN-APIHOOK-011]** Missing Parameter Validation (Low) - `src/ApiHook.cpp:42` @ `ApiHook::ApiHook` | 置信度: 45
3. **[VULN-VTABLE-001]** Function Pointer Injection (Low) - `src/VirtualTable.cpp:259` @ `VirtualTable::addMethod` | 置信度: 40

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `MOCK_METHOD@include/mockcpp/mockcpp.h` | decorator | semi_trusted | 用户测试代码调用 MOCK_METHOD 宏创建 Mock 方法，输入来自测试开发者，具有开发权限 | Mock 方法创建宏入口 |
| `invoke@include/mockcpp/HookMockObject.h` | decorator | semi_trusted | 用户调用 invoke() 设置 API Hook，传入的函数指针由开发者提供，具有开发权限 | API Hook 创建入口 |
| `CodeModifier::modify@src/UnixCodeModifier.cpp` | internal | internal | 内部函数，由 ApiHook 系统调用，不直接对外暴露 | 代码段修改内部函数 |
| `CodeModifier::modify@src/WinCodeModifier.cpp` | internal | internal | 内部函数，由 ApiHook 系统调用，不直接对外暴露 | Windows 平台代码段修改内部函数 |
| `startHook@src/JmpOnlyApiHook.cpp` | internal | internal | 内部函数，由 ApiHook 构造函数调用 | 启动 Hook，修改目标函数入口代码 |
| `appyApiHook@include/mockcpp/ApiHookGenerator.h` | decorator | semi_trusted | 模板函数，由用户代码调用设置 Hook，函数地址参数由开发者提供 | 应用 API Hook 的模板函数入口 |
| `PROC_STUB@include/mockcpp/ProcStub.h` | decorator | semi_trusted | 宏定义，创建函数指针 Stub，参数由开发者提供 | 函数 Stub 创建宏入口 |

**其他攻击面**:
- API Hook 代码修改: UnixCodeModifier::modify() 使用 mprotect+mmemcpy 修改代码段权限和内容
- API Hook 代码修改: WinCodeModifier::modify() 使用 VirtualProtect+WriteProcessMemory 修改代码段
- Virtual Table 操作: VirtualTable 创建和操作虚函数表，修改函数指针
- Mock Object 生命周期: MockObjectBase 管理对象创建和删除
- Type Casting: AnyCast 模板实现涉及整数范围检查
- Python 脚本输入: generate_vtbl_related_files.py 接收命令行参数并生成代码

---

## 3. Medium 漏洞 (1)

### [VULN-APIHOOK-002] Security-Sensitive Operation without Restore - CodeModifier::modify

**严重性**: Medium（原评估: Critical → 验证后: Medium） | **CWE**: CWE-1233 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/UnixCodeModifier.cpp:31-59` @ `CodeModifier::modify`
**模块**: api_hook

**描述**: UnixCodeModifier::modify uses mprotect to change memory permissions to PROT_READ|PROT_WRITE|PROT_EXEC but never restores original permissions after memcpy. This leaves code pages with elevated write permissions, creating a persistent attack surface for code injection.

**漏洞代码** (`src/UnixCodeModifier.cpp:31-59`)

```c
if(::mprotect(...) != 0) { return false; } memcpy(dest, src, size); return true; // NO restore!
```

**达成路径**

CodeModifier::modify() -> mprotect(PROT_RWX) -> memcpy() -> returns WITHOUT restoring permissions

**验证说明**: 确认 Unix 版本未恢复内存权限，对比 Windows 版本有正确恢复。虽然用户是开发者(semi_trusted)，但这确实是设计缺陷，可能导致代码页持续暴露写权限。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: 10 | cross_file: 0

**深度分析**

**根因分析**：

通过对比 Unix 和 Windows 两个平台的实现，发现代码修改后的内存权限恢复逻辑存在显著差异：

| 平台 | 文件 | 内存权限恢复 |
|------|------|-------------|
| Unix | `src/UnixCodeModifier.cpp:31-59` | ❌ 未恢复 |
| Windows | `src/WinCodeModifier.cpp:24-36` | ✅ 正确恢复 |

**Unix 版本问题代码** (`src/UnixCodeModifier.cpp:31-59`)：

```cpp
bool CodeModifier::modify(void *dest, const void *src, size_t size)
{
    int page_size = getpagesize();
    // 步骤1: 提升权限为可读写执行
    if(::mprotect(ALIGN_TO_PAGE_BOUNDARY(dest, page_size), page_size * 2, 
                  PROT_EXEC | PROT_WRITE | PROT_READ ) != 0)
    {  
       return false; 
    }

    // 步骤2: 执行内存拷贝
    ::memcpy(dest, src, size);

    // ❌ 缺失: 未恢复原始权限!
    return true;
}
```

**Windows 版本正确实现** (`src/WinCodeModifier.cpp:24-36`)：

```cpp
bool CodeModifier::modify(void *dest, const void *src, size_t size)
{
    DWORD dwOldProtect(0);
    DWORD dwReadWrite(PAGE_EXECUTE_READWRITE);

    // 步骤1: 保存原始权限并提升权限
    BOOL bRet = ::VirtualProtect(dest, size, dwReadWrite, &dwOldProtect);  // ← 保存原始权限
    
    // 步骤2: 执行内存写入
    bRet = bRet && ::WriteProcessMemory(::GetCurrentProcess(), dest, src, size, NULL);
    
    // 步骤3: 恢复原始权限 ← Unix版本缺失此步骤!
    bRet = bRet && ::VirtualProtect(dest, size, dwOldProtect, &dwReadWrite);
    
    return (bRet == TRUE);
}
```

**潜在利用场景**：

1. **持久化攻击面**: 代码页持续暴露 `PROT_WRITE` 权限，攻击者可能利用后续的内存写入漏洞修改代码
2. **W^X 策略绕过**: 现代安全机制要求内存页不同时可写可执行，此设计违反了该原则
3. **跨进程利用**: 在共享内存场景下，其他进程可能利用残留的写权限

**实际风险评估**：

在 mockcpp 的使用场景中，这些风险被显著降低：
- 用户是开发者（semi_trusted），非外部攻击者
- Hook 操作发生在测试环境，非生产环境
- 现代操作系统在进程退出时会清理内存权限

**修复建议**：

参考 Windows 版本实现，在 Unix 版本中添加权限恢复逻辑：

```cpp
bool CodeModifier::modify(void *dest, const void *src, size_t size)
{
    int page_size = getpagesize();
    void* page_addr = ALIGN_TO_PAGE_BOUNDARY(dest, page_size);
    
    // 保存原始权限
    int old_prot;
    if(::mprotect(page_addr, page_size * 2, PROT_EXEC | PROT_WRITE | PROT_READ) != 0)
        return false;
    
    // 记录原始权限（需要先查询）
    // 注：Linux 没有直接查询权限的 API，建议保存 PROT_EXEC 或通过 /proc/self/maps 查询
    
    ::memcpy(dest, src, size);
    
    // 恢复原始权限（建议恢复为 PROT_READ | PROT_EXEC）
    ::mprotect(page_addr, page_size * 2, PROT_READ | PROT_EXEC);
    
    return true;
}
```

---

## 4. Low 漏洞 (2)

### [VULN-APIHOOK-011] Missing Parameter Validation - ApiHook::ApiHook

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-476 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/ApiHook.cpp:42-47` @ `ApiHook::ApiHook`
**模块**: api_hook
**跨模块**: api_hook

**描述**: ApiHook constructor accepts api and stub pointers without validation. NULL or invalid pointers would propagate through the call chain causing crashes or undefined behavior.

**漏洞代码** (`src/ApiHook.cpp:42-47`)

```c
ApiHook::ApiHook ( const void* api, const void* stub )\n\t: This(new ApiHookImpl(api, stub))\n{\n}
```

**达成路径**

ApiHook(NULL, NULL) -> ApiHookImpl(NULL, NULL) -> JmpOnlyApiHookImpl(NULL, NULL) -> JmpCode(NULL, NULL) -> mprotect(NULL, ...)

**验证说明**: 参数没有验证，但下游有mprotect保护。这是设计缺陷（缺少输入验证），但在测试框架场景下影响有限。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -5 | context: -15 | cross_file: 0

**深度分析**

**根因分析**：

ApiHook 构造函数直接接受 `api` 和 `stub` 指针参数，未进行任何有效性验证：

**问题代码** (`src/ApiHook.cpp:42-47`)：

```cpp
ApiHook::ApiHook ( const void* api, const void* stub )
	: This(new ApiHookImpl(api, stub))
{
}
```

参数直接传递给 `ApiHookImpl`，再传递给 `JmpOnlyApiHook`，最终到达 `JmpCode` 和 `CodeModifier::modify`。如果传入 NULL 或无效指针：

```
调用链: ApiHook(NULL, NULL) 
      → ApiHookImpl(NULL, NULL) 
      → JmpOnlyApiHook(NULL, NULL) 
      → JmpCode(NULL, NULL) 
      → mprotect(NULL, ...)  ← mprotect 会返回错误
```

**保护机制分析**：

虽然构造函数没有验证，但下游 `mprotect` 提供了隐式保护：
- `mprotect` 对 NULL 指针会返回 `-1`（错误）
- `CodeModifier::modify` 在 `mprotect` 失败时返回 `false`
- 整个 Hook 创建流程会失败，不会执行危险的内存操作

**实际影响评估**：

| 场景 | 输入 | 结果 |
|------|------|------|
| 正常使用 | 有效函数地址 | Hook 创建成功 |
| NULL 指针 | NULL | mprotect 失败，返回 false |
| 无效地址 | 0xDEADBEEF | mprotect 失败，返回 false |

在测试框架场景下，无效参数只会导致测试失败，不会造成安全漏洞。

**设计改进建议**：

虽然当前实现有隐式保护，但良好的 API 设计应显式验证参数：

```cpp
ApiHook::ApiHook ( const void* api, const void* stub )
	: This(new ApiHookImpl(
        api != nullptr ? api : throw std::invalid_argument("api pointer is null"),
        stub != nullptr ? stub : throw std::invalid_argument("stub pointer is null")
    ))
{
}
```

---

### [VULN-VTABLE-001] Function Pointer Injection - VirtualTable::addMethod

**严重性**: Low（原评估: Critical → 验证后: Low） | **CWE**: CWE-822 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/VirtualTable.cpp:259-265` @ `VirtualTable::addMethod`
**模块**: virtual_table
**跨模块**: virtual_table,mock_object_core

**描述**: VirtualTable::addMethod writes arbitrary function pointer to vtbl without validation. The methodAddr parameter is directly assigned to vtbl[index] without any validation of the function address. External user-supplied method addresses flow through MockObject::method -> createInvocationMockerBuilderGetter -> MockObjectBaseImpl::createMethod -> VirtualTable::addMethod, enabling arbitrary code execution if attacker controls the function pointer.

**漏洞代码** (`src/VirtualTable.cpp:259-265`)

```c
void VirtualTable::addMethod(void* methodAddr, unsigned int indexOfVtbl, unsigned int indexOfVptr) { This->validateIndexOfVtbl(indexOfVtbl); This->validateIndexOfVptr(indexOfVptr); This->vtbl[getRealVtblIndex(indexOfVptr, indexOfVtbl)] = methodAddr; }
```

**达成路径**

User Code -> MockObject<Interface>::method(m) -> getDelegatedFunction() -> addr (function pointer) -> createInvocationMockerBuilderGetter(name, addr, ...) -> MockObjectBaseImpl::createMethod(name, addr, ...) -> vtbl->addMethod(addr, ...) -> vtbl[index] = addr [OUT: vtbl used for virtual dispatch]

**验证说明**: 这是测试框架的预期功能：用户指定Mock方法地址。虽然有设计缺陷(没有验证函数地址有效性)，但有索引验证防止越界，且用户是开发者。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -10 | context: -15 | cross_file: 0

**深度分析**

**根因分析**：

`VirtualTable::addMethod` 是 mockcpp 框架的核心功能，用于动态构建 Mock 对象的虚函数表。该函数将用户提供的函数指针直接写入虚函数表：

**代码分析** (`src/VirtualTable.cpp:259-265`)：

```cpp
void VirtualTable::addMethod(void* methodAddr, unsigned int indexOfVtbl, unsigned int indexOfVptr)
{
    // ✅ 有索引验证防止越界写入
    This->validateIndexOfVtbl(indexOfVtbl);
    This->validateIndexOfVptr(indexOfVptr);

    // ❌ 无函数地址有效性验证
    This->vtbl[getRealVtblIndex(indexOfVptr, indexOfVtbl)] = methodAddr;
}
```

**安全边界分析**：

该函数有明确的输入验证：

| 验证项 | 实现位置 | 保护效果 |
|--------|----------|----------|
| vtable 索引 | `validateIndexOfVtbl()` | 防止数组越界写入 |
| vptr 索引 | `validateIndexOfVptr()` | 防止超出继承层级 |

**缺失验证**：

- **函数地址有效性**: `methodAddr` 可以是任意值（包括 NULL、无效地址、攻击者提供的地址）
- **代码段归属**: 未验证函数指针是否指向合法代码段

**实际风险评估**：

这是 Mock 框架的**预期设计功能**，而非漏洞：

1. **用户信任等级**: 开发者使用测试框架，传入的是测试用的 Mock 函数地址
2. **使用场景**: 仅在单元测试中使用，不暴露给外部攻击者
3. **数据流路径**: 
   ```
   开发者 → MockObject::method(m) → MockObjectBaseImpl::createMethod → VirtualTable::addMethod
   ```
   函数地址完全由开发者控制，不存在外部攻击者注入的可能性

**验证函数设计意图**：

索引验证的设计目的是防止开发者配置错误导致的崩溃，而非安全防护：

```cpp
void VirtualTableImpl::validateIndexOfVtbl(unsigned int index)
{
    oss_t oss;
    oss << "Did you define too many methods in an interface? ...";
    MOCKCPP_ASSERT_TRUE(oss.str(), index < MOCKCPP_MAX_VTBL_SIZE);
}
```

错误消息面向开发者，而非安全警告。

**结论**：

该问题在 mockcpp 场景下**不构成安全漏洞**，而是测试框架的预期能力。建议在文档中明确说明此设计特性，避免被安全扫描工具误报。

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| api_hook | 0 | 0 | 1 | 1 | 2 |
| virtual_table | 0 | 0 | 0 | 1 | 1 |
| **合计** | **0** | **0** | **1** | **2** | **3** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-822 | 1 | 33.3% |
| CWE-476 | 1 | 33.3% |
| CWE-1233 | 1 | 33.3% |

---

## 7. 修复建议

### 优先级 1: 立即修复（Medium 级别）

#### VULN-APIHOOK-002 - UnixCodeModifier 内存权限未恢复

**修复方案**: 参考 Windows 版本实现，在内存操作后恢复原始权限

**具体步骤**:
1. 在 `mprotect` 调用前，通过 `/proc/self/maps` 或其他方式查询并保存原始权限
2. 在 `memcpy` 完成后，调用 `mprotect` 恢复原始权限
3. 建议恢复为 `PROT_READ | PROT_EXEC`，确保代码页不可写

**影响范围**: 仅影响 Unix 平台（Linux/macOS），Windows 版本无需修改

---

### 优先级 2: 短期改进（Low 级别）

#### VULN-APIHOOK-011 - ApiHook 参数缺失验证

**修复方案**: 在构造函数中添加参数有效性检查

**建议代码**:
```cpp
ApiHook::ApiHook(const void* api, const void* stub)
    : This(new ApiHookImpl(
        api ? api : (throw std::invalid_argument("api pointer cannot be null"), nullptr),
        stub ? stub : (throw std::invalid_argument("stub pointer cannot be null"), nullptr)
    ))
{
}
```

**注意**: 当前设计通过下游 `mprotect` 提供隐式保护，此改进主要提升代码健壮性和错误诊断能力。

#### VULN-VTABLE-001 - VirtualTable 函数指针注入

**修复方案**: 无需修复，这是测试框架的预期功能

**建议措施**:
- 在项目文档中明确说明此设计特性
- 在代码注释中标注"测试框架核心功能，允许开发者注入 Mock 函数"
- 建议在 CI 流程中配置静态分析工具白名单，排除此类预期功能的误报

---

### 优先级 3: 架构改进建议

#### 跨平台一致性改进

**现状**: Unix 和 Windows 版本的 `CodeModifier::modify` 实现存在不一致

**建议**:
1. 统一两个平台的内存权限管理策略
2. 创建抽象基类 `CodeModifierBase`，定义标准流程（提升权限 → 修改 → 恢复权限）
3. 各平台实现类继承基类，确保行为一致性

#### 错误处理改进

**现状**: 部分函数使用返回值表示错误，缺乏统一错误处理机制

**建议**:
1. 引入异常处理机制（如 `MockCppException`）
2. 在关键操作失败时提供详细错误信息（如内存权限修改失败的具体原因）
3. 确保所有错误路径都有明确的处理逻辑

---

## 8. 总结

本次扫描针对 mockcpp 测试框架进行了全面的安全分析。项目整体安全风险较低，主要发现为设计层面的改进建议而非严重安全漏洞。

**关键结论**:
- 无已确认的安全漏洞
- 3 个待确认问题均为设计缺陷，影响有限
- 测试框架的核心功能（函数指针注入、代码修改）是预期设计，不构成安全风险

**建议优先级**:
1. **立即**: 修复 Unix 平台内存权限未恢复问题（跨平台一致性）
2. **短期**: 添加参数验证，提升代码健壮性
3. **长期**: 架构改进，统一跨平台行为和错误处理机制
