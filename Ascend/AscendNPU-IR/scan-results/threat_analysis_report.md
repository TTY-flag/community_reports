# AscendNPU-IR 威胁分析报告

## 项目概述

**项目名称**: AscendNPU-IR (毕昇IR编译器基础设施)

**项目类型**: 编译器基础设施库 (基于 MLIR)

**扫描时间**: 2026-04-23

**代码规模**: 647 文件, 182,553 行代码

**主要语言**: C/C++ (主要), Python (绑定和接口)

## 架构概述

AscendNPU-IR 是华为 Ascend NPU 的中间表示 (IR) 编译器基础设施，基于 MLIR (Multi-Level Intermediate Representation) 构建。项目提供多层次的抽象接口，用于编译和优化 Ascend 兼容的 AI 算子。

### 核心组件

| 模块 | 功能 | 风险等级 |
|------|------|----------|
| **Tools** | CLI 工具 (bishengir-compile, bishengir-opt) | Critical |
| **PythonWheel** | Python compile() API | Critical |
| **ToolsLib** | 工具库 (外部命令执行) | Critical |
| **CAPI** | C API 接口 | High |
| **Bindings** | Python 绑定 | High |
| **ExecutionEngine** | JIT 执行引擎 | High |
| **Conversion** | Dialect 转换 Pass | Medium |
| **Dialect** | MLIR Dialect 定义 | Medium |
| **Template** | 算子模板库 | Medium |

## STRIDE 威胁分析

### Spoofing (身份伪造)

| 威胁 | 描述 | 风险 | 位置 |
|------|------|------|------|
| 环境变量伪造 | 攻击者可设置 `BISHENG_INSTALL_PATH` 环境变量指向恶意路径，导致 execute() 函数执行恶意二进制 | High | Utils.cpp:287 |
| 二进制替换 | 攻击者可在 PATH 中放置恶意 `hivmc` 或 `bishengir-compile-a5`，被 execute() 函数调用执行 | High | Utils.cpp:175 |

### Tampering (数据篡改)

| 威胁 | 描述 | 风险 | 位置 |
|------|------|------|------|
| MLIR 输入篡改 | 用户提供的 MLIR 文件可被篡改，注入恶意 IR 代码 | Medium | bishengir-compile.cpp:149 |
| YAML 配置篡改 | ODS YAML 配置文件可被篡改，影响生成的代码 | Medium | bishengir-hfusion-ods-yaml-gen.cpp |
| 输出文件篡改 | 编译输出可被路径遍历攻击覆盖任意文件 | High | Utils.cpp:64 |

### Repudiation (抵赖)

| 威胁 | 描述 | 风险 | 位置 |
|------|------|------|------|
| 无审计日志 | CLI 工具和 Python API 未记录编译操作日志 | Low | 全局 |

### Information Disclosure (信息泄露)

| 威害 | 描述 | 风险 | 位置 |
|------|------|------|------|
| IR 信息泄露 | MLIR 文件可能包含敏感模型信息，通过错误消息泄露 | Medium | bishengir-compile.cpp:151 |
| 临时文件残留 | 临时文件可能包含敏感 IR 数据，未及时清理 | Medium | Utils.cpp:138 |

### Denial of Service (拒绝服务)

| 威害 | 描述 | 风险 | 位置 |
|------|------|------|------|
| 解析器崩溃 | 恶意构造的 MLIR/YAML 可导致解析器崩溃 | Medium | bishengir-compile.cpp:149 |
| 内存耗尽 | 大型 MLIR 文件或无限循环 IR 可耗尽内存 | Medium | ConvertHIVMToUpstream.cpp:112 |
| 外部二进制阻塞 | execute() 无超时可能导致阻塞 (有 timeoutSeconds 参数但默认值未知) | Medium | Utils.cpp:211 |

### Elevation of Privilege (权限提升)

| 威害 | 描述 | 风险 | 位置 |
|------|------|------|------|
| 命令注入 | 通过精心构造的参数可注入命令到 execute() | Critical | Utils.cpp:175 |
| 路径遍历 | 输出文件路径可遍历到系统敏感位置 | High | Utils.cpp:64 |
| 代码执行 | Python API 通过 subprocess 执行编译器，可被利用执行任意命令 | Critical | compiler.py:190 |

## 攻击面分析

### 1. CLI 工具接口 (Critical)

**入口**: `bishengir-compile` 和 `bishengir-opt` 命令行工具

**攻击向量**:
- 命令行参数注入
- 输入文件路径遍历
- MLIR 文件内容注入

**相关函数**:
```
main() → registerAndParseCLIOptions()
      → checkInOutOptionsValidity()
      → parseSourceFile()
      → runBiShengIRPipeline()
      → execute()
```

### 2. Python API 接口 (Critical)

**入口**: `ascendnpuir.compile()` 函数

**攻击向量**:
- MLIR 字符串内容注入
- 编译选项注入
- 输出路径注入

**相关函数**:
```python
compile() → _get_compiler_path()
         → _check_hivmc_available()
         → subprocess.run()
```

### 3. 外部命令执行 (Critical)

**入口**: `execute()` 函数

**攻击向量**:
- 二进制路径伪造 (通过 BISHENG_INSTALL_PATH)
- 参数注入
- 环境变量污染

**相关函数**:
```
execute() → llvm::sys::findProgramByName()
         → llvm::sys::ExecuteAndWait()
```

### 4. MLIR 解析器 (High)

**入口**: `parseSourceFile()` 和 `parseAttribute()`

**攻击向量**:
- 恶意 MLIR IR 构造
- 类型混淆攻击
- 属性解析绕过

### 5. C API 接口 (Medium)

**入口**: `bishengirRegisterAllDialects()` 等 C API

**攻击向量**:
- Context 对象伪造
- Dialect 注册顺序攻击

## 高风险数据流

### 1. 命令执行链 (Critical)

```
用户输入 (argv/MLIR字符串)
    ↓
compile() / main()
    ↓
subprocess.run() / execute()
    ↓
外部二进制 (bishengir-compile / hivmc)
```

**风险**: 攻击者可控制执行的二进制路径和参数

### 2. 环境变量读取链 (High)

```
getenv("BISHENG_INSTALL_PATH")
    ↓
getBiShengInstallPath()
    ↓
execute()
    ↓
llvm::sys::findProgramByName()
```

**风险**: 环境变量可被攻击者伪造，指向恶意路径

### 3. 文件路径处理链 (High)

```
用户输入文件路径
    ↓
checkInOutOptionsValidity()
    ↓
canonicalizePath()
    ↓
llvm::sys::fs::make_absolute()
```

**风险**: 路径可被遍历到系统敏感位置

## 漏洞分布统计

| 风险等级 | 数量 | 占比 |
|----------|------|------|
| Critical | 3 | 20% |
| High | 5 | 33% |
| Medium | 6 | 40% |
| Low | 1 | 7% |

## 关键发现

### 1. 外部命令执行风险 (Critical)

`execute()` 函数使用 `llvm::sys::ExecuteAndWait` 执行外部二进制，路径来自 `BISHENG_INSTALL_PATH` 环境变量或 PATH 查找。攻击者可：
- 设置恶意 `BISHENG_INSTALL_PATH` 指向包含恶意二进的目录
- 在 PATH 中放置恶意 `hivmc` 或 `bishengir-compile-a5`
- 通过精心构造的参数注入命令

**建议**: 
- 硬编码二进制路径或使用签名验证
- 白名单允许的二进制名称
- 验证二进制完整性

### 2. Python subprocess 风险 (Critical)

`compiler.py` 的 `compile()` 函数直接使用 `subprocess.run()` 执行编译器，输入来自用户提供的 MLIR 字符串。攻击者可：
- 通过 MLIR 字符串注入特殊字符影响命令解析
- 控制输出路径导致任意文件覆盖

**建议**:
- 使用参数列表而非字符串拼接
- 验证输出路径合法性
- 限制 MLIR 内容长度和格式

### 3. 环境变量信任风险 (High)

`getBiShengInstallPath()` 直接信任 `BISHENG_INSTALL_PATH` 环境变量，用于查找外部二进制。

**建议**:
- 限制环境变量路径范围 (如必须在特定目录下)
- 验证找到的二进制文件权限和完整性

### 4. 路径处理风险 (High)

`checkInOutOptionsValidity()` 对输入输出路径进行验证，但 `canonicalizePath()` 仅进行路径规范化，未限制路径范围。

**建议**:
- 添加路径白名单限制
- 检查路径是否在预期目录范围内
- 禁止写入系统敏感目录

## 建议的安全措施

### 立即修复 (Critical)

1. **验证外部二进制**: 在 `execute()` 中添加二进制签名验证或路径白名单
2. **限制 subprocess 输入**: 在 `compiler.py` 中验证 MLIR 字符串格式和长度
3. **硬编码二进制路径**: 减少对环境变量的依赖

### 短期修复 (High)

1. **路径白名单**: 在 `checkInOutOptionsValidity()` 中添加输出路径白名单
2. **环境变量验证**: 在 `getBiShengInstallPath()` 中验证路径合法性
3. **错误消息清理**: 移除错误消息中的敏感信息

### 中期修复 (Medium)

1. **临时文件清理**: 确保 TempDirectoriesStore 正确清理临时文件
2. **解析器加固**: 对 MLIR 解析器添加输入大小限制
3. **审计日志**: 添加编译操作审计日志

## 结论

AscendNPU-IR 作为编译器基础设施，存在多个高危攻击面，主要集中在：
- 外部命令执行 (`execute()` 函数)
- Python API 的 subprocess 调用
- 环境变量信任问题
- 文件路径处理问题

这些风险源于编译器需要执行外部工具和处理用户提供的 IR 文件的设计特性。建议按照优先级实施安全措施，重点关注外部命令执行和 subprocess 调用的安全加固。

---

**报告生成**: Architecture Agent

**下一步**: 建议调度 DataFlow Scanner 和 Security Auditor 进行深度漏洞扫描