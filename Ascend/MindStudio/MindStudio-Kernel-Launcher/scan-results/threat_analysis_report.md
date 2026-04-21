# MindStudio-Kernel-Launcher 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析为 AI 自主识别，未使用 `threat.md` 约束文件。

## 项目架构概览

### 项目简介

MindStudio-Kernel-Launcher (msKL) 是一个 Python 库/CLI 工具，用于在华为昇腾 NPU 上进行 AI 算子的轻量化调用和自动调优。项目提供以下核心功能：

1. **Kernel 启动接口**：生成、编译、运行 Kernel 代码
2. **Tiling 函数接口**：调用 msOpGen 算子工程的 tiling 函数
3. **自动调优功能**：基于模板库进行 Kernel 参数自动调优

### 项目类型与部署模型

| 属性 | 值 |
|------|-----|
| 项目类型 | Python CLI/Library 工具 |
| 语言组成 | 纯 Python（22 个源文件，约 4500 行） |
| 部署方式 | pip/setuptools 安装，从用户脚本调用 API |
| 运行环境 | 昇腾 NPU 服务器，依赖 CANN 环境 |

### 模块结构

```
mskl/
├── launcher/          # Kernel 启动模块 (Critical)
│   ├── compiler.py    # 编译与动态库加载
│   ├── code_generator.py  # C++ 代码生成
│   ├── driver.py      # NPU 驱动接口与动态加载
│   ├── config.py      # 配置类定义
│   └── opgen_workflow.py  # 工作流协调
├── optune/            # 自动调优模块 (High)
│   ├── tuner.py       # 调优装饰器与执行
│   └── kernel_modifier.py  # Kernel 源码修改
└── utils/             # 工具模块 (Medium)
    ├── safe_check.py  # 安全检查函数
    ├── launcher_utils.py  # 启动工具
    └── autotune_utils.py  # 调优工具
```

## 模块风险评估

### 高风险文件列表

| 优先级 | 文件路径 | 风险等级 | 模块类型 | 主要风险 |
|--------|----------|----------|----------|----------|
| 1 | mskl/launcher/compiler.py | Critical | 编译执行 | Bash 脚本执行、动态库加载 |
| 2 | mskl/launcher/code_generator.py | Critical | 代码生成 | C++ 代码生成、路径嵌入 |
| 3 | mskl/launcher/driver.py | Critical | 动态加载 | importlib 动态模块加载 |
| 4 | mskl/optune/tuner.py | High | 自动调优 | msprof 命令执行、文件读写 |
| 5 | mskl/launcher/opgen_workflow.py | High | 工作流 | 协调编译执行流程 |
| 6 | mskl/launcher/config.py | High | 配置解析 | 用户输入验证 |
| 7 | mskl/optune/kernel_modifier.py | Medium | 代码修改 | 源码替换注入 |
| 8 | build.py | High | 构建脚本 | 子进程命令执行 |

### 模块 STRIDE 建模

| 模块 | S | T | R | I | D | E | 主要威胁 |
|------|---|---|---|---|---|---|---------|
| launcher/compiler | ● | ● | ○ | ● | ● | ● | 命令注入、代码执行 |
| launcher/code_generator | ○ | ● | ○ | ● | ○ | ○ | 代码注入、信息泄露 |
| launcher/driver | ○ | ○ | ○ | ● | ○ | ● | 恶意库加载、权限提升 |
| optune/tuner | ○ | ○ | ○ | ● | ● | ○ | 信息泄露、DoS |
| optune/kernel_modifier | ○ | ● | ○ | ○ | ○ | ○ | 源码篡改 |
| utils/safe_check | ○ | ○ | ○ | ● | ○ | ○ | 权限绕过 |

## 攻击面分析

### 入口点列表

| 文件 | 行号 | 函数 | 入口类型 | 信任等级 | 理由 | 说明 |
|------|------|------|----------|----------|------|------|
| mskl/launcher/compiler.py | 171 | compile() | cmdline | untrusted_local | 用户脚本调用 API，build_script 参数完全可控 | 执行用户提供的 Bash 脚本 |
| mskl/launcher/compiler.py | 319 | compile_executable() | cmdline | untrusted_local | 用户脚本调用 API，build_script 参数完全可控 | 编译用户提供的源文件 |
| mskl/launcher/opgen_workflow.py | 53 | tiling_func() | cmdline | untrusted_local | API 入口，op_type/inputs/outputs/lib_path 可控 | 生成并执行 tiling 代码 |
| mskl/launcher/opgen_workflow.py | 74 | get_kernel_from_binary() | cmdline | untrusted_local | API 入口，kernel_binary_file 路径可控 | 加载用户提供的 Kernel 二进制 |
| mskl/launcher/code_generator.py | 340 | Launcher() | cmdline | untrusted_local | 配置包含 kernel_src_file/kernel_name | 代码生成入口 |
| mskl/optune/tuner.py | 251 | autotune() | decorator | untrusted_local | 装饰器接收 configs 列表 | 自动调优装饰器 |
| mskl/optune/tuner.py | 557 | autotune_v2() | decorator | untrusted_local | 装饰器接收 configs 列表 | 自动调优 v2 装饰器 |
| build.py | 117 | main() | cmdline | untrusted_local | CLI 工具，命令行参数可控 | 构建脚本入口 |
| mskl/launcher/driver.py | 143 | is_lib_preloaded() | env | semi_trusted | 读取 LD_PRELOAD 环境变量 | 预加载库检查 |
| mskl/launcher/driver.py | 31 | load_mspti_so() | env | semi_trusted | 读取 ASCEND_HOME_PATH | 加载 MSPTI 库 |
| mskl/utils/launcher_utils.py | 23 | get_cann_path() | env | semi_trusted | 读取 ASCEND_HOME_PATH | CANN 路径获取 |
| mskl/utils/logger.py | 34 | module_init | env | semi_trusted | 读取 MSKL_LOG_LEVEL | 日志配置 |

### 信任边界模型

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Deployment Environment                        │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                  Trusted: Admin/Deployment                      │  │
│  │  - ASCEND_HOME_PATH (CANN 安装路径)                             │  │
│  │  - LD_PRELOAD (预加载库检查)                                     │  │
│  │  - MSKL_LOG_LEVEL (日志级别)                                     │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                              ↓                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                     mskl Library Code                           │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │  │
│  │  │  launcher   │  │   optune    │  │   utils     │              │  │
│  │  │  (Critical) │  │   (High)    │  │  (Medium)   │              │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘              │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                              ↑                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                Untrusted: User/Local Attacker                   │  │
│  │  - User scripts calling mskl API                                │  │
│  │  - File paths: build_script, kernel_src_file, kernel_binary    │  │
│  │  - Configuration parameters: op_type, inputs, outputs, attrs   │  │
│  │  - Auto-tune configs: parameter values                          │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## 关键数据流分析

### 命令执行数据流（最高风险）

```
用户脚本调用 mskl.compile(build_script="malicious.sh", ...)
    │
    ▼
compile() @ compiler.py:171
    │ 接收 build_script 参数
    ▼
_check_compile_input() @ compiler.py:109
    │ FileChecker 检查文件存在性和权限
    │ ⚠️ 检查不验证脚本内容安全性
    ▼
subprocess.run(["bash", build_script, ...]) @ compiler.py:206
    │
    ▼
[SINK] 执行任意 Bash 脚本命令
```

**风险**：用户可控制 build_script 路径，尽管有文件权限检查，但脚本内容完全可控。恶意脚本可实现：
- 命令注入
- 权限提升
- 数据窃取
- 系统破坏

### 动态库加载数据流

```
NPULauncher.__init__(module=".so path") @ driver.py:70
    │
    ▼
NPULauncher.__call__() @ driver.py:78
    │
    ▼
importlib.util.spec_from_file_location(module_name, self._module)
    │ self._module 来自 output_bin_path
    ▼
spec.loader.exec_module(module) @ driver.py:105
    │
    ▼
getattr(module, func_name) @ driver.py:116
    │
    ▼
func(blockdim, l2ctrl, stream, *kernel_meta) @ driver.py:120
    │
    ▼
[SINK] 执行动态加载模块中的任意函数
```

**风险**：如果 output_bin_path 被替换为恶意 .so 文件，可实现：
- 任意代码执行
- 内存篡改
- 数据泄露

### 代码生成数据流

```
KernelInvokeConfig(kernel_src_file="...", kernel_name="...") @ config.py:31
    │ kernel_src_file 嵌入到代码模板
    ▼
KernelLauncher.code_gen() @ code_generator.py:176
    │
    ▼
KERNEL_TEMPLATE.format(kernel_src_file=...) @ code_generator.py:247
    │ 生成 C++ 代码
    │ ⚠️ kernel_src_file 直接嵌入 #include 指令
    ▼
f.write(src) @ code_generator.py:257
    │
    ▼
compile() 编译生成的代码
    │
    ▼
[SINK] 编译包含用户控制头文件的代码
```

**风险**：kernel_src_file 路径可能包含特殊字符或恶意路径，影响：
- 头文件注入
- 代码模板污染

## STRIDE 详细威胁建模

### Spoofing (欺骗)

| 威胁 | 描述 | 可能性 | 影响 |
|------|------|--------|------|
| 恶意库伪装 | 替换 libruntime.so 或 libmspti.so 为恶意库 | 低（需环境变量控制） | 高 |

### Tampering (篡改)

| 威胁 | 描述 | 可能性 | 影响 |
|------|------|--------|------|
| 源码修改注入 | autotune configs 注入恶意代码到 Kernel 源文件 | 高 | 高 |
| 编译脚本篡改 | build_script 包含恶意内容 | 高 | 高 |
| 配置参数篡改 | op_type、attrs 参数包含特殊字符 | 中 | 中 |

### Repudiation (抵赖)

| 威胁 | 描述 | 可能性 | 影响 |
|------|------|--------|------|
| 操作日志缺失 | MSKL_LOG_LEVEL 控制日志级别，可能关闭日志 | 低 | 中 |

### Information Disclosure (信息泄露)

| 威胁 | 描述 | 可能性 | 影响 |
|------|------|--------|------|
| Kernel 信息泄露 | kernel_name、kernel_src_file 路径泄露到日志 | 中 | 中 |
| 性能数据泄露 | autotune 结果 CSV 文件包含敏感参数 | 低 | 低 |
| 环境路径泄露 | ASCEND_HOME_PATH 路径可见 | 低 | 低 |

### Denial of Service (拒绝服务)

| 威胁 | 描述 | 可能性 | 影响 |
|------|------|--------|------|
| 资源耗尽 | 并行编译进程数未严格限制 | 中 | 中 |
| 超时阻塞 | subprocess.run timeout 设置为 600 秒 | 低 | 中 |
| 文件系统填充 | 临时文件未清理（log_level=0 时跳过清理） | 中 | 低 |

### Elevation of Privilege (权限提升)

| 威胁 | 描述 | 可能性 | 影响 |
|------|------|--------|------|
| 恶意脚本执行 | build_script 以当前用户权限执行任意命令 | 高 | 高 |
| 动态库提权 | 加载恶意 .so 获取进程权限 | 高 | 高 |

## 安全加固建议（架构层面）

### 1. 命令执行防护（Critical）

**问题**：`compile()` 和 `compile_executable()` 直接执行用户提供的 Bash 脚本。

**建议**：
- 移除 Bash 脚本执行，改用固定编译命令模板
- 如果必须支持自定义脚本，添加白名单机制限制可用命令
- 对 build_script 内容进行安全审计（检测危险命令如 `rm`, `sudo`, `chmod`）
- 使用 `subprocess.run([...], shell=False)` 替代 `shell=True`

### 2. 动态库加载防护（Critical）

**问题**：使用 `importlib` 加载用户控制的 .so 文件。

**建议**：
- 对加载的 .so 文件进行签名验证
- 限制 .so 文件只能从特定安全目录加载
- 使用沙箱机制隔离动态加载的模块

### 3. 代码生成防护（High）

**问题**：用户提供的路径和名称直接嵌入生成的 C++ 代码。

**建议**：
- 对 kernel_src_file、kernel_name 进行严格的字符白名单验证
- 使用相对路径而非绝对路径嵌入
- 添加路径规范化（os.path.realpath）防止路径遍历

### 4. 源码修改防护（Medium）

**问题**：`autotune` 配置直接修改 Kernel 源文件。

**建议**：
- 对配置值进行严格的语法验证
- 限制可替换的变量范围
- 生成修改后的文件时进行安全检查

### 5. 文件操作防护（Medium）

**问题**：多处文件读写操作，临时文件可能未清理。

**建议**：
- 始终清理临时文件（不依赖 log_level）
- 对输出文件权限严格控制（当前使用 0o640，良好）
- 使用 os.fdopen + os.O_EXCL 防止符号链接攻击

### 6. 环境变量防护（Low）

**问题**：ASCEND_HOME_PATH 等环境变量用于库加载路径。

**建议**：
- 对环境变量路径进行签名或哈希验证
- 提供配置文件替代环境变量（配置文件权限更可控）

---

## 附录：LSP 可用性检测结果

| 检测项 | 结果 |
|--------|------|
| LSP 类型 | pyright-langserver |
| 启动状态 | 失败 (ENOEXEC) |
| 回退方案 | 使用 grep 进行跨文件分析 |

---

**报告生成时间**：2026-04-21
**分析范围**：22 个 Python 源文件（排除测试目录）