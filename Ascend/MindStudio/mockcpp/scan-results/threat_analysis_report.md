# mockcpp 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析基于 AI 对项目源码的自主分析，未受 `threat.md` 约束文件限制。

**项目**: mockcpp - A C/C++ Mock Framework  
**分析时间**: 2026-04-21  
**分析范围**: src/ 和 include/mockcpp/ 核心代码

---

## 1. 项目架构概览

### 1.1 项目定位

mockcpp 是一个通用的 C/C++ Mock 框架，用于单元测试中 Mock 对象和方法。项目定位为 **库 (library)** 类型，主要功能包括：

- **Virtual Method Mock**: 虚函数 Mock，通过操作虚函数表实现
- **Global Function Mock**: 全局函数 Mock，通过 API Hook 实现
- **Overloaded Function Mock**: 重载函数 Mock
- **Stub/Matcher 系统**: 定义 Mock 方法的返回行为和匹配条件

### 1.2 技术栈

- **语言**: C++ (核心实现) + Python (构建时代码生成)
- **平台**: Linux (GCC), Windows (MinGW/VS2019)
- **依赖**: 无外部依赖，纯标准库实现

### 1.3 目录结构

| 目录 | 内容 | 语言 | 风险等级 |
|------|------|------|----------|
| src/ | 核心实现源文件 | C++ | High-Critical |
| include/mockcpp/ | 公共 API 头文件 | C++ | High |
| src/*.py | 构建时代码生成脚本 | Python | Low |

---

## 2. 信任边界模型

### 2.1 信任边界定义

| 边界 | 可信一侧 | 不可信一侧 | 风险等级 | 说明 |
|------|----------|------------|----------|------|
| **Library API Boundary** | User Test Code | Library Internal | Medium | 用户测试代码调用库 API，输入来自开发者 |
| **Code Modification Boundary** | Mock Framework | Target Process Memory | Critical | Mock 框架修改目标进程的代码段 |
| **Function Pointer Boundary** | Virtual Table Ops | External Function Addr | High | 虚函数表操作涉及函数指针注入 |
| **Type Cast Boundary** | AnyCast System | User Input Types | Medium | 类型转换涉及范围检查 |

### 2.2 信任等级分类

| 等级 | 描述 | 适用场景 |
|------|------|----------|
| **semi_trusted** | 具有开发权限的用户输入 | 测试开发者调用 Mock API |
| **internal** | 库内部生成的数据 | JmpCode 机器码生成 |
| **trusted_admin** | 构建环境参数 | Python 脚本的命令行参数 |

---

## 3. 模块风险评估

### 3.1 高风险模块

#### API Hook 系统 (Critical)

| 文件 | 功能 | 风险点 |
|------|------|--------|
| UnixCodeModifier.cpp | Linux 平台代码修改 | `mprotect()` 修改内存权限，`memcpy()` 写入代码段 |
| WinCodeModifier.cpp | Windows 平台代码修改 | `VirtualProtect()` + `WriteProcessMemory()` |
| JmpCode.cpp | 生成跳转机器码 | 直接生成 x86/x64 JMP 指令机器码 |
| JmpOnlyApiHook.cpp | Hook 实现 | `startHook()` 修改目标函数入口代码 |
| ApiHook.cpp | Hook 管理 | 构造函数接收用户提供的函数指针 |

**风险说明**: 
- API Hook 系统直接修改运行时进程的代码段，属于高风险操作
- 如果 Hook 目标地址无效，可能导致进程崩溃
- 如果 Hook 代码生成错误，可能导致不可预测的行为
- 潜在的代码注入风险：如果用户提供了恶意的 stub 函数地址

#### Virtual Table 系统 (High)

| 文件 | 功能 | 风险点 |
|------|------|--------|
| VirtualTable.cpp | 虚函数表管理 | 操作 `void** vtbl`，写入函数指针 |
| VirtualTableUtils.cpp | vtable 创建 | `createVtbls()` 分配内存，`initializeVtbls()` 设置 RTTI |
| MockObjectBase.cpp | Mock 对象基类 | `addMethod()` 向 vtable 写入用户提供的地址 |

**风险说明**:
- 虚函数表操作涉及函数指针直接写入
- 如果用户提供的 Mock 方法地址无效，调用时会导致崩溃
- RTTI 操纵可能涉及类型混淆

#### Type System (Medium)

| 文件 | 功能 | 风险点 |
|------|------|--------|
| AnyCast.cpp | 类型转换 | 整数范围检查，可能有溢出风险 |
| Result.cpp | 返回值处理 | 类型匹配检查 |

**风险说明**:
- `any_cast` 实现涉及整数类型的范围检查
- C-style cast `(T*)ul` 可能导致类型混淆

### 3.2 中风险模块

| 模块 | 功能 | 风险点 |
|------|------|--------|
| Mock Object Core | 对象生命周期管理 | `new/delete` 内存管理 |
| Invocation Mocker | 调用匹配 | 参数传递和匹配 |
| Stub System | 返回行为定义 | Stub 对象创建和管理 |

### 3.3 低风险模块

| 模块 | 功能 | 风险点 |
|------|------|--------|
| Matcher System | 调用条件匹配 | 纯逻辑匹配 |
| Constraint System | 参数约束 | 参数匹配 |
| Assertion | 断言和异常 | 测试失败报告 |
| Python Generator | 构建时代码生成 | 仅在构建时运行 |

---

## 4. 攻击面分析

### 4.1 主要攻击面

| 攻击面 | 位置 | 风险等级 | 描述 |
|--------|------|----------|------|
| **API Hook 代码修改** | UnixCodeModifier::modify() | Critical | 使用 mprotect+memcpy 修改目标进程代码段 |
| **API Hook 代码修改** | WinCodeModifier::modify() | Critical | 使用 VirtualProtect+WriteProcessMemory 修改代码段 |
| **Virtual Table 操作** | VirtualTable::addMethod() | High | 向虚函数表写入用户提供的函数指针 |
| **Mock Object 生命周期** | MockObjectBase 析构函数 | High | 管理对象删除，可能有内存泄漏或 double-free |
| **Type Casting** | any_cast<T>() | Medium | 整数范围检查，可能溢出 |

### 4.2 攻击路径分析

#### 路径 1: API Hook 代码注入

```
用户调用 HookMockObject::method(api_addr)
  → ApiHook::ApiHook(api_addr, stub_addr)
    → JmpOnlyApiHookImpl::startHook()
      → JmpOnlyApiHookImpl::changeCode(jmp_code)
        → CodeModifier::modify(api_addr, jmp_code)
          → mprotect(PROT_WRITE) + memcpy(api_addr, jmp_code)
```

**威胁**: 如果用户提供的 `api_addr` 或 `stub_addr` 无效或恶意，可能导致：
- 代码注入 (写入恶意 stub 地址)
- 内存破坏 (写入到无效地址)
- 进程崩溃 (Hook 目标地址不可写)

#### 路径 2: Virtual Table 函数指针注入

```
用户调用 MOCK_METHOD(obj, method)
  → MockObjectBase::createInvocationMockerBuilderGetter(method_addr)
    → MockObjectBaseImpl::createMethod(method_addr)
      → VirtualTable::addMethod(method_addr)
        → vtbl[index] = method_addr
```

**威胁**: 如果用户提供的 `method_addr` 无效：
- 调用时跳转到无效地址，导致崩溃
- 类型混淆（接口类型与实际类型不匹配）

#### 路径 3: 类型转换溢出

```
any_cast<int>(AnyBase*)
  → scope_check_any_cast<int>()
    → if (*ul <= numeric_limits<int>::max()) return (int*)ul
```

**威胁**: 
- 范围检查正确，但 C-style cast `(int*)ul` 可能导致指针 reinterpret
- 如果源类型与目标类型不匹配，可能导致数据损坏

---

## 5. STRIDE 威胁建模

### 5.1 Spoofing (欺骗)

| 威胁 | 风险 | 描述 | 缓解措施 |
|------|------|------|----------|
| Mock Object 类型伪造 | Medium | 用户可能使用错误的接口类型创建 Mock | `validateNumberOfVptr()` 检查继承数量 |

### 5.2 Tampering (篡改)

| 威胁 | 风险 | 描述 | 缓解措施 |
|------|------|------|----------|
| 代码段篡改 | Critical | API Hook 修改目标函数入口代码 | 仅限开发者调用，无外部攻击者可达路径 |
| Virtual Table 篡改 | High | 向 vtable 写入用户函数指针 | 仅限开发者调用 |
| 内存篡改 | Medium | JmpCode::m_code 缓冲区 | 固定大小，无溢出风险 |

### 5.3 Repudiation (抵赖)

| 威胁 | 风险 | 描述 | 缓解措施 |
|------|------|------|----------|
| 调用记录缺失 | Low | Mock 调用可能未被记录 | `SimpleInvocationRecorder` 提供记录功能 |

### 5.4 Information Disclosure (信息泄露)

| 威伤 | 风险 | 描述 | 缓解措施 |
|------|------|------|----------|
| RTTI 信息泄露 | Low | VirtualTable 操作涉及 type_info | 仅用于测试环境，无敏感信息 |
| 原始代码泄露 | Low | JmpOnlyApiHook 保存原始代码 | `saveOriginalData()` 仅保存用于恢复 |

### 5.5 Denial of Service (拒绝服务)

| 威胁 | 风险 | 描述 | 缓解措施 |
|------|------|------|----------|
| 进程崩溃 | High | Hook 无效地址导致崩溃 | `MOCKCPP_ASSERT_TRUE` 检查 method != 0 |
| 内存耗尽 | Low | Mock Object 未正确释放 | `reset()` 和析构函数提供清理 |

### 5.6 Elevation of Privilege (权限提升)

| 威胁 | 风险 | 描述 | 缓解措施 |
|------|------|------|----------|
| 代码执行提升 | Critical | 如果恶意 stub 被执行，可能绕过安全检查 | 仅限测试环境使用，运行在开发者权限下 |

---

## 6. 安全加固建议

### 6.1 架构层面

1. **API Hook 权限验证**
   - 在 `CodeModifier::modify()` 添加目标地址范围验证
   - 检查目标地址是否在可执行段内
   - 建议添加调试模式下禁止 Hook 系统函数

2. **Virtual Table 安全检查**
   - 在 `VirtualTable::addMethod()` 添加函数地址有效性检查
   - 建议添加类型匹配验证（RTTI 检查）

3. **Mock Object 生命周期**
   - 确保 `reset()` 在析构前被调用
   - 建议使用 RAII 模式管理 Mock Object

### 6.2 代码层面

1. **UnixCodeModifier.cpp**
   ```cpp
   // 建议：验证目标地址范围
   if (dest == nullptr || !isValidCodeAddress(dest)) {
       return false;
   }
   ```

2. **JmpCode.cpp**
   ```cpp
   // 建议：验证地址距离是否在跳转范围内
   if (distanceTooFar(from, to)) {
       MOCKCPP_REPORT_FAILURE("Jump distance too far");
   }
   ```

3. **AnyCast.cpp**
   ```cpp
   // 建议：使用 static_cast 替代 C-style cast
   return static_cast<ValueType*>(ul);  // 更安全的转换
   ```

### 6.3 测试环境建议

- Mock 框架仅用于单元测试环境，不应在生产代码中使用
- 测试进程应运行在受限权限下，避免 Hook 系统函数
- 建议在 CI/CD 中禁止对系统库的 Hook

---

## 7. 结论

mockcpp 作为单元测试 Mock 框架，其核心功能涉及代码段修改和函数指针操作，属于高风险操作类型。但由于以下原因，实际攻击风险较低：

1. **使用场景受限**: 仅用于单元测试环境，运行在开发者权限下
2. **无外部输入**: 所有输入来自测试开发者，无网络或文件外部输入
3. **调用者可信**: 测试代码由开发者编写，具有开发权限

**主要风险**: 开发者误用导致的进程崩溃或测试失败，而非恶意攻击。

**建议**: 重点审核 API Hook 和 Virtual Table 相关代码的健壮性，确保边界检查和错误处理完善。

---

## 附录：高风险文件清单

| 优先级 | 文件 | 风险等级 | 模块 | 关键函数 |
|--------|------|----------|------|----------|
| 1 | UnixCodeModifier.cpp | Critical | api_hook | CodeModifier::modify() |
| 2 | WinCodeModifier.cpp | Critical | api_hook | CodeModifier::modify() |
| 3 | JmpCode.cpp | Critical | api_hook | JmpCode::JmpCode() |
| 4 | JmpOnlyApiHook.cpp | Critical | api_hook | startHook(), changeCode() |
| 5 | VirtualTable.cpp | High | virtual_table | addMethod(), setDestructor() |
| 6 | VirtualTableUtils.cpp | High | virtual_table | createVtbls(), initializeVtbls() |
| 7 | MockObjectBase.cpp | High | mock_object_core | createMethod(), ~MockObjectBase() |
| 8 | HookMockObject.cpp | High | mock_object_core | getMethod(), getInvokable() |
| 9 | AnyCast.cpp | Medium | type_system | any_cast<T>(), scope_check_any_cast<T>() |
| 10 | ChainingMockHelper.cpp | Medium | helper | returnValue(), once() |

---

**报告生成**: Architecture Agent  
**下一步**: 交付给 DataFlow Scanner 进行漏洞扫描