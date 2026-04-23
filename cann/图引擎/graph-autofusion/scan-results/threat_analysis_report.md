# 威胁分析报告 - Graph-Autofusion (Super Kernel 自动融合模块)

> 分析时间: 2026-04-22
> 项目路径: /home/pwn20tty/Desktop/opencode_project/cann/4/graph-autofusion
> 分析模式: 自主分析（threat.md 不存在）

## 1. 项目概述

### 1.1 项目定位

**Graph-autofusion** 是华为 CANN (Compute Architecture for Neural Networks) 框架的编译优化组件，专门用于在昇腾（Ascend）NPU 上执行 **Super Kernel 自动融合** 功能。该组件通过 AOT（Ahead-of-Time）和 JIT（Just-in-Time）编译机制，将多个算子内核融合为单个超级内核，以减少调度开销和提升推理性能。

### 1.2 技术架构

| 语言 | 文件数 | 主要职责 |
|------|--------|----------|
| C/C++ | 38 个核心文件 | AOT 编译引擎，图优化，任务调度，设备参数生成 |
| Python | 25 个核心文件 | JIT 编译器，内核源代码生成，编译选项解析 |
| Shell | 多个脚本 | 软件包打包和安装流程 |

### 1.3 部署模型

```
┌─────────────────────────────────────────────────────────────┐
│                    AI 推理框架                                │
│           (TensorFlow/PyTorch Ascend Backend)               │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ ACL API 调用
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                graph-autofusion 库                           │
│  ┌──────────────────┐    ┌───────────────────────┐          │
│  │  AOT Engine (C++)│◄───│ JIT Compiler (Python) │          │
│  │  - 图优化         │    │ - 源代码生成           │          │
│  │  - 任务调度       │    │ - 编译选项解析         │          │
│  │  - 设备参数生成   │    │ - 工具链调用           │          │
│  └──────────────────┘    └───────────────────────┘          │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ Ascend Runtime
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    Ascend NPU                                │
└─────────────────────────────────────────────────────────────┘
```

## 2. 信任边界分析

### 2.1 输入信任边界

| 边界名称 | 可信侧 | 不可信侧 | 风险等级 | 描述 |
|----------|--------|----------|----------|------|
| **ACL API 边界** | AI 推理框架 | graph-autofusion | Low | 通过 aclskOptimize 等 C API 接收模型句柄和配置，数据来自可信框架 |
| **环境变量边界** | 系统管理员 | 库代码 | Medium | 读取 ASCEND_PROF_SK_ON 等环境变量控制功能 |
| **配置选项边界** | 应用开发者 | 库代码 | Medium | 通过 aclskOptions 结构体传递配置参数 |
| **Python JIT 边界** | JIT 编译器 | AOT引擎 | Medium | Python 生成的内核源代码被 C++ 加载执行 |
| **编译工具链边界** | subprocess调用 | 外部工具 | High | Python 调用 ar/编译器等外部工具 |
| **Shell脚本边界** | 安装脚本 | eval执行 | High | Shell脚本使用eval执行命令 |

### 2.2 数据流信任分析

```
外部输入源 → 解析/验证 → 内部处理 → 输出/执行

[Source]                          [Sink]
├─ ACL API 参数                    ├─ memcpy_s (内存复制)
├─ 环境变量                        ├─ 文件写入
├─ 配置选项字符串                  ├─ subprocess.run (命令执行)
├─ 编译选项字符串                  ├─ eval (Shell执行)
├─ ELF 二进制文件                  ├─ ACL runtime API
```

## 3. 攻击面分析

### 3.1 C/C++ 攻击面

#### 3.1.1 API 入口点

| 入口点 | 文件位置 | 参数类型 | 风险 | 说明 |
|--------|----------|----------|------|------|
| `aclskOptimize` | super_kernel.cpp:77 | `aclmdlRI model, aclskOptions *options` | High | 主优化入口，接收外部模型和配置 |
| `aclskScopeBegin` | super_kernel.cpp:148 | `const char* scopeName, aclrtStream stream` | Medium | Scope 开始，接收字符串参数 |
| `aclskScopeEnd` | super_kernel.cpp:156 | `const char* scopeName, aclrtStream stream` | Medium | Scope 结束，接收字符串参数 |

**潜在风险**: 
- scopeName 字符串参数仅检查空字符串，未限制长度或特殊字符
- aclskOptions 结构体包含多个字符串指针和扩展选项字段

#### 3.1.2 环境变量输入

| 环境变量 | 使用位置 | 功能 | 风险 |
|----------|----------|------|------|
| `ASCEND_OP_COMPILE_SAVE_KERNEL_META` | sk_log.h:423 | 控制日志输出 | Medium |
| `ASCEND_PROF_SK_ON` | sk_task_builder.cpp:1551 | 启用 profiling | Medium |
| `ASCEND_SK_OP_TRACE_ON` | sk_task_builder.cpp:1555 | 启用 op_trace | Medium |
| `SK_CONSTANT` | sk_constant_codegen.cpp:792 | 控制常量代码生成 | Medium |
| `ENV_SK_EVENT_RECORD` | sk_event_recorder.cpp:115 | 控制事件记录 | Medium |

**潜在风险**: 环境变量可被外部设置，影响库的执行行为

#### 3.1.3 危险操作（Sink）

| 操作类型 | 使用位置 | 函数 | CWE | 风险 |
|----------|----------|------|-----|------|
| 内存复制 | sk_task_builder.cpp:1015-1047 | `memcpy_s` | CWE-120 | High |
| 内存复制 | sk_scope_launch.cpp:43 | `memcpy_s` | CWE-120 | Medium |
| 内存复制 | sk_event_recorder.cpp:638-687 | `memcpy_s` | CWE-120 | Medium |
| 文件打开 | sk_file_guard.h:23/44 | `fopen` | CWE-22 | Medium |
| ELF解析 | sk_common.cpp:35-86 | 直接解析二进制 | CWE-119 | Medium |
| 正则匹配 | sk_options_manager.cpp:247-285 | 自实现正则引擎 | CWE-1333 | Low |

#### 3.1.4 选项解析风险

```cpp
// sk_options_manager.cpp:74-136
bool ParseAndValidateExtendOptionValue(const char* rawValue, ...) {
    // 解析格式: key1=value1,value2:key2=value3,value4
    // 验证:
    // 1. 长度限制 (kMaxExtendOptionLength = 1024)
    // 2. token字符验证 (字母数字 + _-. + /)
    // 3. 格式验证 (key=value 结构)
}
```

**缓解措施**: 
- 长度限制有效
- 字符集验证有效
- 但未检查 path traversal 或特殊字符组合

### 3.2 Python 攻击面

#### 3.2.1 命令执行（高风险）

| 文件 | 行号 | 操作 | 风险 |
|------|------|------|------|
| super_kernel_op_infos.py | 69, 75, 836, 843 | `subprocess.run(cmds)` | High |
| super_kernel_sub_op_infos.py | 623, 651, 664 | `subprocess.run(['ar', 'x', ...])` | High |
| package.py | 147, 177 | `subprocess.run(cmd_list)` | Medium |

**潜在风险**:
- cmds 列表由内部构造，但可能包含来自解析的选项
- 命令参数未进行完整的安全检查

#### 3.2.2 文件操作

| 文件 | 行号 | 操作 | 风险 |
|------|------|------|------|
| super_kernel.py | 691, 1037 | `os.fdopen(os.open(kernel_file, ...))` | Medium |
| super_kernel_sub_op_infos.py | 311 | `open(json_path, 'r')` | Low |
| package.py | 73, 239, 670 | `open(filepath, 'w')` | Low |

**缓解措施**:
- super_kernel.py 使用 `stat.S_IWUSR | stat.S_IRUSR` 权限创建文件

#### 3.2.3 选项解析

```python
# super_kernel_option_parse.py:171-194
def parse_super_kernel_options(option_string: str):
    # 解析格式: key1=value1:key2=value2
    pairs = option_string.split(':')
    for pair in pairs:
        key, value = pair.split('=', 1)
        parser = factory.get_parse_func(key)
        result_options[key] = parser.parse_option(value)
```

**潜在风险**: 
- 解析用户提供的选项字符串
- 各 Parser 有验证（如 NumberParser 检查范围）
- NonEmptyParser 仅检查非空

### 3.3 Shell 脚本攻击面（高风险）

#### 3.3.1 eval 使用

**高危位置**:

| 文件 | eval 数量 | 风险说明 |
|------|-----------|----------|
| common_func.inc | 22+ | 大量 `eval "${_outvar}=\"${_result}\""` |
| install_common_parser.sh | 15+ | `eval "${func_before_remove}"`, `exec_with_param` |
| version_cfg.inc | 30+ | `eval "${_outvar}=\"${_value}\""` |
| manager_func.sh | 15+ | `eval sh "${installer_path}"` |

**示例危险代码**:
```bash
# common_func.inc:61
eval "${_outvar}=\"${_result}\""

# manager_func.sh:507
eval sh "${installer_path}" "${install_options}"
```

**潜在风险**:
- 如果 `_result` 或 `installer_path` 包含恶意内容，可能导致命令注入
- 安装脚本可能在安装过程中被触发

## 4. STRIDE 威胁建模

### 4.1 Spoofing（身份伪造）

| 威胁 | 影范围 | 风险等级 | 说明 |
|------|--------|----------|------|
| 环境变量欺骗 | Low | Medium | 攻击者可设置环境变量影响 profiling/trace 功能 |
| 配置选项伪造 | Low | Medium | aclskOptions 可由上层传递，可能包含异常配置 |

**缓解**: 环境变量和配置由可信框架控制，但建议添加验证

### 4.2 Tampering（数据篡改）

| 威胁 | 影响范围 | 风险等级 | 说明 |
|------|----------|----------|------|
| ELF二进制篡改 | Medium | Medium | sk_common.cpp 解析内核二进制，如果文件被篡改可能导致解析错误 |
| 配置文件篡改 | Low | Low | JSON 配置文件读取后使用，文件完整性依赖文件系统保护 |

**缓解**: 
- ELF 解析有边界检查
- 建议：验证二进制签名或 hash

### 4.3 Repudiation（抵赖）

| 威胁 | 影响范围 | 风险等级 | 说明 |
|------|----------|----------|------|
| 日志系统 | Medium | Low | profiling 和 op_trace 功能可由环境变量控制，可能被禁用 |

**缓解**: 关键操作应有不可禁用的日志记录

### 4.4 Information Disclosure（信息泄露）

| 威胁 | 影响范围 | 风险等级 | 说明 |
|------|----------|----------|------|
| 日志文件 | Medium | Medium | super_kernel.log 写入模型信息到磁盘 |
| JSON dump | Low | Medium | sk_graph_rts_before/after_*.json 包含完整图结构 |
| 内核源码 | Low | Low | JIT 生成的内核源码包含算子信息 |

**缓解**: 
- 日志目录权限受控
- 建议：敏感信息脱敏处理

### 4.5 Denial of Service（拒绝服务）

| 威胁 | 影响范围 | 风险等级 | 说明 |
|------|----------|----------|------|
| 内存分配失败 | Medium | Low | 大任务队列可能导致内存耗尽 |
| 无限循环检测 | Low | Low | FindKernelNodeInDirection 有 maxHops=100 限制 |
| 正则匹配复杂度 | Low | Low | MatchRegex 是简单的正则实现，无 ReDoS 风险 |

**缓解**: 
- maxHops 循环限制有效
- 建议：添加内存使用监控

### 4.6 Elevation of Privilege（权限提升）

| 威胁 | 影响范围 | 风险等级 | 说明 |
|------|----------|----------|------|
| Shell eval 注入 | High | High | 安装脚本使用 eval，如果可控则可执行任意命令 |
| subprocess 命令注入 | Medium | High | Python 调用 subprocess.run，如果参数可控则可注入 |
| 文件权限 | Low | Low | 生成的内核文件权限为 owner read/write only |

**缓解**: 
- subprocess 调用参数由内部构造（非直接用户输入）
- 建议：审计 Shell 脚本的 eval 使用，添加参数验证

## 5. 高风险模块汇总

### 5.1 Critical 风险模块

| 模块 | 文件 | 主要风险 | 建议优先级 |
|------|------|----------|------------|
| Shell 安装脚本 | common_func.inc, manager_func.sh | eval 命令执行 | P0 |
| Python 编译工具 | super_kernel_op_infos.py | subprocess.run | P0 |
| C++ 任务构建器 | sk_task_builder.cpp | memcpy_s + 环境变量 | P1 |

### 5.2 High 风险模块

| 模块 | 文件 | 主要风险 |
|------|------|----------|
| 选项管理器 | sk_options_manager.cpp | 选项解析 + 正则匹配 |
| Scope 启动器 | sk_scope_launch.cpp | memcpy_s + 字符串参数 |
| 子操作处理 | super_kernel_sub_op_infos.py | subprocess.run(ar) |
| 打包脚本 | package.py | subprocess.run |

### 5.3 Medium 风险模块

| 模块 | 文件 | 主要风险 |
|------|------|----------|
| 日志系统 | sk_log.cpp | 文件写入 + 环境变量 |
| 常量代码生成 | sk_constant_codegen.cpp | 代码生成 + 环境变量 |
| 事件记录器 | sk_event_recorder.cpp | memcpy_s + 环境变量 |
| ELF 解析 | sk_common.cpp | 二进制解析 |
| JIT 编译器 | super_kernel.py | 文件生成 |

## 6. 安全建议

### 6.1 立即处理（P0）

1. **Shell 脚本 eval 安全审计**
   - 检查所有 eval 调用点的输入来源
   - 对动态执行的命令添加白名单验证
   - 考虑替换为更安全的变量赋值方式

2. **Python subprocess 参数验证**
   - 验证 cmds 列表中的每个参数
   - 禁止 shell=True 模式
   - 使用绝对路径调用工具

### 6.2 短期处理（P1）

1. **C++ API 参数验证**
   - 为 scopeName 添加长度限制和字符验证
   - 验证 aclskOptions 结构体中的字符串指针

2. **环境变量安全检查**
   - 添加环境变量值范围验证
   - 记录关键环境变量的使用日志

### 6.3 长期改进（P2）

1. **ELF 解析安全增强**
   - 添加二进制签名验证
   - 增强解析错误处理

2. **日志信息脱敏**
   - 避免记录敏感的模型信息
   - 提供日志级别控制

## 7. 扫描范围建议

基于以上分析，建议后续漏洞扫描重点关注：

| 扫描范围 | 语言 | 重点类型 | 文件数 |
|----------|------|----------|--------|
| AOT 核心引擎 | C/C++ | 内存操作, 配置解析, ELF解析 | 12 |
| JIT 编译器 | Python | subprocess调用, 文件操作 | 6 |
| 打包脚本 | Shell+Python | eval, subprocess | 15+ |

**预计漏洞类型分布**:
- Buffer Overflow: memcpy_s 相关 (Medium)
- Command Injection: eval, subprocess (High)
- Path Traversal: 文件操作 (Low)
- Integer Overflow: 任务计数 (Low)
- Configuration Tampering: 选项解析 (Medium)

---

*报告生成: Architecture Agent*
*数据库初始化: scan.db 已创建*