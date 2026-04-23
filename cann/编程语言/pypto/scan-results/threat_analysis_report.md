# CANN/pypto 威胁分析报告

> **生成时间**: 2026-04-22  
> **项目路径**: /home/pwn20tty/Desktop/opencode_project/cann/5/pypto  
> **项目类型**: AI Operator Compiler Framework (NPU算子编译框架)  
> **分析者**: @architecture Agent

---

## 1. 项目概述

### 1.1 项目定位

**CANN/pypto** 是华为 NPU (昇腾处理器) 的算子编译和优化框架，属于 CANN (Compute Architecture for Neural Networks) 生态的核心组件。

- **主要功能**: 将用户定义的 Python 算子编译为可在 NPU 上执行的低级内核
- **技术栈**: C++ (框架层) + Python (API层) + pybind11 (绑定层)
- **语言构成**: C++ 1456 文件 (88,573 行) + Python 523 文件 (149,869 行)
- **部署模式**: 部署于 Linux 服务器，作为 AI 推理/训练的后端编译器

### 1.2 项目类型分类

根据攻击面特征，本项目归类为 **`network_service`** 类型的延伸：

- **实际类型**: `AI Compiler Service` (AI 编译服务)
- **部署场景**: 作为 Python 库被 AI 应用调用，或作为独立服务进程
- **信任边界**: Python 用户空间 → C++ 编译后端 → NPU 设备空间

---

## 2. 攻击面分析

### 2.1 关键入口点风险评估

| 入口类型 | 文件位置 | 函数/类 | 信任等级 | 风险等级 | 描述 |
|---------|---------|---------|---------|---------|------|
| `python_api` | python/src/pybind11.cpp:23 | PYBIND11_MODULE | untrusted_local | **Critical** | 主 Python 模块入口，暴露所有 C++ 功能 |
| `python_api` | python/pypto/frontend/parser/entry.py:301 | JitCallableWrapper.__call__ | untrusted_local | **Critical** | JIT 编译入口，执行用户 Python 代码 |
| `python_api` | python/src/bindings/runtime.cpp:186 | DeviceRunOnceDataFromHost | untrusted_local | **Critical** | 执行内核，接受用户 tensor 数据 |
| `python_api` | python/src/bindings/tensor.cpp:21 | BindTensor | untrusted_local | **High** | 创建 tensor，接受用户 shape/dtype/pointer |
| `dynamic_library` | framework/src/cann_host_runtime/cann_host_runtime.cpp:37 | CannHostRuntime constructor | untrusted_environment | **High** | 加载 libruntime.so，路径来自环境变量 |
| `dynamic_library` | framework/src/adapter/manager/plugin_handler.cpp:28 | PluginHandler::OpenHandler | untrusted_local | **High** | dlopen 加载动态库，无路径验证 |
| `file_io` | framework/src/adapter/api/runtime_api.cpp:194 | RuntimeBinaryLoadFromFile | untrusted_local | **High** | 加载内核二进制文件 |
| `environment` | framework/src/cann_host_runtime/cann_host_runtime.cpp:40 | ASCEND_CANN_PACKAGE_PATH | untrusted_environment | **Medium** | 环境变量控制库加载路径 |

### 2.2 信任边界分析

本项目存在 **4 个主要信任边界**：

#### 边界 1: Python 用户 → C++ 后端

```
[Python 用户空间] ---------> [C++ 编译后端]
    (不可信)                    (可信)
    
边界位置: python/src/bindings/*
数据流: Tensor shape, dtype, raw memory pointer, Python AST
风险: 数据注入、类型混淆、内存破坏
```

**关键函数**:
- `BindTensor@tensor.cpp`: 直接接受用户 shape/dtype
- `DeviceRunOnceDataFromHost@runtime.cpp`: 接受原始内存指针
- `LaunchKernelTorch@runtime.cpp`: 直接执行用户 tensor

#### 边界 2: 外部动态库 → 运行时系统

```
[外部共享库] ---------> [框架运行时]
  (不可信)                 (可信)
  
边界位置: framework/src/cann_host_runtime/, framework/src/adapter/manager/
数据流: 库路径字符串, 函数指针
风险: 库路径注入、恶意库加载、函数指针篡改
```

**关键函数**:
- `CannHostRuntime::CannHostRuntime`: 从环境变量构建库路径，调用 dlopen
- `PluginHandler::OpenHandler`: 接受任意库路径字符串
- `GetCalcOps@calc.cpp`: 加载 libtile_fwk_calculator.so

#### 边界 3: 文件系统 → 内核加载

```
[文件系统] ---------> [设备内核]
 (不可信)               (可信)
 
边界位置: framework/src/adapter/api/runtime_api.cpp
数据流: 内核二进制文件路径
风险: 路径遍历、恶意二进制注入
```

**关键函数**:
- `RuntimeBinaryLoadFromFile`: 加载内核二进制
- `RuntimeRegisterAllKernel`: 注册内核到设备

#### 边界 4: 用户代码 → JIT 编译

```
[用户 Python 代码] ---------> [PTO IR 编译]
     (不可信)                   (可信)
     
边界位置: python/pypto/frontend/parser/
数据流: Python AST, 函数定义
风险: 代码注入、任意代码执行
```

**关键函数**:
- `Parser.parse@parser.py`: 解析用户 Python AST (无沙箱)
- `Parser._visit_function_def`: 编译用户函数为 IR
- `JitCallableWrapper.compile`: 绑定用户控制的动态维度

---

## 3. STRIDE 威胁建模

### 3.1 Spoofing (身份伪造)

| 威胁ID | 描述 | 风险等级 | 攻击路径 |
|--------|------|---------|---------|
| S-01 | 伪造 ASCEND_CANN_PACKAGE_PATH 环境变量 | High | 攻击者设置恶意环境变量，框架加载恶意 libruntime.so |
| S-02 | 伪造 tensor dtype 导致类型混淆 | Critical | 用户传入错误 dtype，导致内存布局不匹配，引发数据破坏 |
| S-03 | 伪造库路径注入恶意动态库 | High | 通过 PluginHandler::OpenHandler 加载恶意库，劫持运行时 |

**缓解建议**:
- [S-01] 环境变量验证：检查 ASCEND_CANN_PACKAGE_PATH 是否指向可信路径
- [S-02] 类型验证：在 BindTensor 中强制验证 dtype 与实际数据的匹配
- [S-03] 库路径白名单：限制 PluginHandler 只能加载预定义路径的库

### 3.2 Tampering (数据篡改)

| 威胁ID | 描述 | 风险等级 | 攻击路径 |
|--------|------|---------|---------|
| T-01 | 篡改 tensor shape 导致缓冲区溢出 | Critical | 用户传入超大 shape，内核分配不足内存，溢出到相邻区域 |
| T-02 | 篡改 kernel binary 内容 | High | 通过 RuntimeBinaryLoadFromFile 加载被篡改的二进制，执行恶意指令 |
| T-03 | 篡改控制流缓存 | Medium | 修改 ControlFlowCache 数据，影响内核执行路径 |
| T-04 | 篡改 JIT 编译中的动态维度 | High | 通过 SymbolicScalar 注入恶意维度值，影响 tensor 分配 |

**缓解建议**:
- [T-01] Shape 边界检查：在 BindTensor 和 LaunchKernelTorch 中验证 shape 范围
- [T-02] 二进制签名验证：对加载的 kernel binary 进行签名检查
- [T-03] 控制流缓存校验：增加缓存数据完整性检查
- [T-04] 动态维度约束：限制 SymbolicScalar 的有效范围

### 3.3 Repudiation (抵赖)

| 威胁ID | 描述 | 风险等级 | 说明 |
|--------|------|---------|------|
| R-01 | 缺乏编译操作审计日志 | Medium | JIT 编译过程无完整日志，无法追踪恶意编译行为 |
| R-02 | 缺乏设备执行审计 | Low | NPU 执行结果缺乏可验证的日志记录 |

**缓解建议**:
- [R-01] 编译审计日志：记录每次 JIT 编译的源代码哈希、编译选项、时间戳
- [R-02] 执行追踪：在 DeviceLauncher 中增加关键操作的日志记录

### 3.4 Information Disclosure (信息泄露)

| 威胁ID | 描述 | 风险等级 | 攻击路径 |
|--------|------|---------|---------|
| I-01 | Tensor 数据泄露到日志 | Medium | VerifyData 将用户 tensor 数据复制到 host，可能泄露敏感数据 |
| I-02 | 内存指针泄露 | Low | DeviceTensorData 暴露原始内存地址 |
| I-03 | 编译 IR 泄露 | Low | PTO Function IR 可能包含模型结构敏感信息 |

**缓解建议**:
- [I-01] 数据脱敏：日志中避免打印 tensor 原始数据内容
- [I-02] 指针保护：对暴露给 Python 的指针增加访问控制
- [I-03] IR 加密：对存储的 IR 进行加密保护

### 3.5 Denial of Service (拒绝服务)

| 威胁ID | 描述 | 风险等级 | 攻击路径 |
|--------|------|---------|---------|
| D-01 | Shape 注入导致内存耗尽 | High | 用户传入极大 shape 值 (如 [1e15, 1e15])，导致 OOM |
| D-02 | JIT 编译循环阻塞 | Medium | 用户代码包含无限循环，Parser 解析超时 |
| D-03 | 动态库加载失败导致崩溃 | Medium | dlopen 失败后部分功能不可用 |

**缓解建议**:
- [D-01] Shape 上限限制：强制 shape 各维度不得超过物理内存容量
- [D-02] 编译超时机制：已有的 compile_timeout 选项，需确保默认启用
- [D-03] 库加载容错：dlopen 失败时优雅降级而非崩溃

### 3.6 Elevation of Privilege (权限提升)

| 威胁ID | 描述 | 风险等级 | 攻击路径 |
|--------|------|---------|---------|
| E-01 | 恶意库加载获得运行时控制权 | **Critical** | 通过环境变量或 PluginHandler 加载恶意库，执行任意代码 |
| E-02 | 原始指针注入导致任意内存访问 | **Critical** | DeviceTensorData 接受 Python 传入的任意指针，读写任意内存 |
| E-03 | JIT 代码执行获得编译器控制权 | High | 用户 Python 代码通过 JIT 编译获得在编译器进程执行的能力 |

**缓解建议**:
- [E-01] 库签名验证：对所有 dlopen 的库进行签名校验
- [E-02] 指针验证：验证传入指针是否属于合法分配的内存区域
- [E-03] JIT 沙箱：限制 Parser 支持的 Python 语法，禁止危险操作

---

## 4. 高风险攻击场景

### 4.1 场景 1: 环境变量库注入 (Critical)

**攻击链**:
```
1. 攻击者设置 ASCEND_CANN_PACKAGE_PATH=/tmp/malicious_cann
2. 框架启动时 CannHostRuntime 构造函数执行
3. 构造 libruntime.so 路径: /tmp/malicious_cann/lib64/libruntime.so
4. dlopen 加载恶意库
5. 恶意库的 rtGetSocVersion 等函数被调用
6. 恶意代码获得执行权限
```

**影响**: 完全的进程控制权，可窃取 tensor 数据、篡改编译结果、植入后门。

**验证状态**: 需要人工验证环境变量是否被其他机制约束。

### 4.2 场景 2: Tensor Shape 缓冲区溢出 (Critical)

**攻击链**:
```
1. 用户通过 Python API 创建 Tensor(dtype=DT_FP32, shape=[1000000000000])
2. BindTensor 不验证 shape 合理性
3. 内核分配内存时按 shape 计算大小
4. 内存分配失败或溢出
5. 相邻内存被破坏，可能影响其他 tensor 或控制结构
```

**影响**: 内存破坏、崩溃、潜在的代码执行。

### 4.3 场景 3: 原始指针注入 (Critical)

**攻击链**:
```
1. 用户传入 DeviceTensorData(dtype=DT_FP32, addr=0xdeadbeef, shape=[1024])
2. DeviceRunOnceDataFromHost 直接使用该指针
3. RawTensorData::CreateTensor 将指针封装为 tensor 数据
4. 内核执行时读写该地址
5. 任意内存地址被读写
```

**影响**: 任意内存读写，可窃取敏感数据、破坏关键数据结构。

### 4.4 场景 4: JIT 代码注入 (High)

**攻击链**:
```
1. 用户传入包含恶意 Python 代码的函数
2. @jit 装饰器触发 Parser.parse
3. Parser 解析 AST，无沙箱限制
4. 用户代码中的任意函数调用被执行
5. 潜在的任意代码执行
```

**影响**: 编译器进程内的任意代码执行。

---

## 5. 模块风险评估

### 5.1 模块风险矩阵

| 模块 | 路径 | 语言 | 风险等级 | 主要威胁类型 |
|------|------|------|---------|-------------|
| bindings | python/src/bindings | C++ | **Critical** | E-02, T-01, S-02 |
| pypto_api | python/pypto | Python | **Critical** | E-03, T-04, D-01 |
| frontend_parser | python/pypto/frontend/parser | Python | **Critical** | E-03, D-02 |
| cann_host_runtime | framework/src/cann_host_runtime | C++ | **High** | S-01, E-01 |
| adapter | framework/src/adapter | C++ | **High** | S-03, E-01, T-02 |
| interface | framework/src/interface | C++ | **High** | T-02, E-02 |
| machine | framework/src/machine | C++ | **High** | T-02, T-03 |
| tools | tools | Python | **Medium** | T-02 (文件解析) |
| codegen | framework/src/codegen | C++ | **Medium** | T-02 |
| models | models | Python | **Low** | 无外部输入 |

### 5.2 重点扫描模块推荐

根据风险评估，建议以下扫描优先级：

**第一优先级 (Critical)**:
1. `bindings` - Python-C++ 绑定层，接受用户输入的入口
2. `frontend_parser` - JIT 编译解析，用户代码入口
3. `pypto_api` - Python API 层，用户交互入口

**第二优先级 (High)**:
4. `cann_host_runtime` - 动态库加载，环境变量入口
5. `adapter` - 外部库适配，库路径入口
6. `interface` - 内核注册，二进制入口
7. `machine` - 设备执行，内核执行入口

**第三优先级 (Medium)**:
8. `tools` - 文件处理工具
9. `codegen` - 代码生成模块

---

## 6. 安全扫描建议

### 6.1 数据流扫描重点

| 数据流路径 | 源 | 汇 | 风险类型 | 建议 Scanner |
|------------|----|----|---------|--------------|
| Python tensor → Device execution | Python user | LaunchAicoreKernel | Buffer overflow | C/C++ DataFlow Scanner |
| Environment → dlopen | ASCEND_CANN_PACKAGE_PATH | libruntime.so | Library injection | C/C++ DataFlow Scanner |
| Library path → dlopen | libName parameter | Loaded library handle | Library injection | C/C++ DataFlow Scanner |
| File path → Binary load | binPath parameter | RtBinHandle | Path traversal | C/C++ DataFlow Scanner |
| Python AST → PTO IR | User code | pypto.Function | Code injection | Python Taint Scanner |

### 6.2 污点追踪配置

**C/C++ 污点源 (Taint Sources)**:
- `py::cast<T>()` - Python 类型转换函数
- `py::getattr()` - Python 属性获取
- `ASCEND_CANN_PACKAGE_PATH` - 环境变量
- `PluginHandler::OpenHandler` 参数 - 库路径

**C/C++ 污点汇 (Taint Sinks)**:
- `dlopen()` - 动态库加载
- `dlsym()` - 函数指针获取
- `RawTensorData::CreateTensor` - 原始指针使用
- `DeviceLauncher::LaunchAicoreKernel` - 设备执行
- `RuntimeBinaryLoadFromFile` - 二进制加载

**Python 污点源**:
- `torch.Tensor` - 用户传入的 tensor
- `inspect.getsource()` - 用户源代码
- `ast.parse()` - 用户 AST
- `os.environ.get()` - 环境变量

**Python 污点汇**:
- `pypto_impl.DeviceTensorData()` - 原始指针传递
- `pypto_impl.LaunchKernelTorch()` - 内核执行
- `pypto.function()` - IR 编译

### 6.3 验证优先级

建议对以下候选漏洞优先验证：

1. **Buffer Overflow**: `BindTensor@tensor.cpp` shape 验证缺失
2. **Arbitrary Memory Access**: `DeviceRunOnceDataFromHost@runtime.cpp` 指针验证缺失
3. **Library Injection**: `CannHostRuntime@cann_host_runtime.cpp` 环境变量验证缺失
4. **Library Injection**: `PluginHandler::OpenHandler@plugin_handler.cpp` 路径验证缺失
5. **Path Traversal**: `RuntimeBinaryLoadFromFile@runtime_api.cpp` 路径验证缺失
6. **Code Injection**: `Parser.parse@parser.py` AST 解析无沙箱

---

## 7. 总结

### 7.1 关键发现

1. **Python-C++ 边界安全薄弱**: pybind11 绑定层直接接受用户控制的数据（shape、dtype、原始指针），缺乏验证机制。

2. **动态库加载路径可控**: 环境变量 `ASCEND_CANN_PACKAGE_PATH` 和函数参数可控制库加载路径，存在库注入风险。

3. **JIT 编译缺乏沙箱**: Parser 直接解析用户 Python AST，无语法限制或沙箱隔离。

4. **原始指针直接使用**: DeviceTensorData 接受并使用 Python 传入的原始内存指针，无地址验证。

### 7.2 风险量化

- **Critical 风险入口**: 4 个
- **High 风险入口**: 4 个
- **Critical 模块**: 3 个
- **High 模块**: 4 个
- **主要攻击向量**: 库注入、缓冲区溢出、任意内存访问、代码注入

### 7.3 后续行动建议

1. **立即行动**: 
   - 在 BindTensor 和 DeviceRunOnceDataFromHost 中增加输入验证
   - 限制 ASCEND_CANN_PACKAGE_PATH 的有效路径范围

2. **中期改进**:
   - 实现库签名验证机制
   - 为 Parser 增加语法白名单

3. **长期架构**:
   - 重新设计 Python-C++ 边界的安全验证层
   - 实现完整的编译审计日志系统

---

**报告结束**  
*Generated by @architecture Agent | CANN/pypto Vulnerability Scanning Project*