# MindStudio-MemScope 威胁分析报告

> 生成时间: 2026-04-20T20:30:00Z
> 项目路径: /home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-MemScope
> 项目类型: C++ + Python 混合项目（NPU内存分析/性能分析工具）

## 1. 项目概述

MindStudio-MemScope 是华为 MindStudio 套件中的内存分析工具，主要用于：
- NPU（Ascend）设备显存泄漏检测
- 显存使用效率分析
- Tensor数据监控和Dump
- 性能追踪和调用栈分析

该项目通过 LD_PRELOAD 机制注入钩子库，拦截 Ascend ACL/ATB/Runtime API，收集内存分配/释放事件，并通过 Python API 提供用户交互接口。

## 2. 攻击面分析

### 2.1 命令行接口攻击面

| 入口点 | 文件位置 | 风险等级 | 说明 |
|--------|----------|----------|------|
| `--output` 参数 | client_parser.cpp:415 | **Critical** | 路径注入，可控制输出目录，存在路径遍历风险 |
| `--input` 参数 | client_parser.cpp:386 | **Critical** | 输入文件路径，可控制比较分析的输入文件 |
| `--watch` 参数 | client_parser.cpp:607 | **High** | 监控配置参数，包含 op 名称和 outputId |
| `--steps` 参数 | client_parser.cpp:254 | **Medium** | 步骤选择参数，整数验证存在边界检查 |
| 用户命令执行 | process.cpp:226 | **Critical** | `execvpe()` 执行用户指定程序，路径来自命令行 |

**数据流路径**:
```
argv → ClientParser::Parse → ParseOutputPath → strncpy_s(config.outputDir)
argv → Process::Launch → ExecCmd → execvpe(cmd.ExecPath())
```

### 2.2 Python API 攻击面

| API | 文件位置 | 风险等级 | 说明 |
|-----|----------|----------|------|
| `msmemscope.config(**kwargs)` | msleaksmodule.cpp:77 | **Critical** | kwargs 参数包含路径、设备、配置等 |
| `msmemscope.take_snapshot(memory_info)` | msleaksmodule.cpp:135 | **Critical** | memory_info 字典包含设备ID、名称等 |
| `watcher.watch(tensor, name=...)` | watcherobject.cpp:148 | **Critical** | tensor 数据指针 + 监控名称 |
| `init_framework_hooks(framework, version, ...)` | __init__.py:49 | **High** | 模块劫持注册，控制劫持目标 |

**数据流路径**:
```
kwargs → MsmemscopeConfig → ConfigManager::SetConfig → ParseOutputPath → strncpy_s
tensor → PyMemScopeWatcherWatch → TensorMonitor::AddWatchTensor → TensorDumper::Dump
```

### 2.3 环境变量攻击面

| 环境变量 | 使用位置 | 风险等级 | 说明 |
|----------|----------|----------|------|
| `LD_PRELOAD_PATH` | process.cpp:177 | **Critical** | 控制钩子库加载路径，可注入恶意库 |
| `ATB_HOME_PATH` | process.cpp:187 | **Critical** | 决定 ATB 钩子库版本，可控制 ABI 选择 |
| `ASCEND_HOME_PATH` | vallina_symbol.cpp:33 | **Critical** | Ascend 库路径，可注入恶意库 |
| `MSMEMSCOPE_CONFIG_ENV` | json_manager.cpp:269 | **Medium** | JSON 配置文件路径，可控制配置 |

**数据流路径**:
```
getenv(ASCEND_HOME_PATH) → LibLoad → dlopen(libPath)
getenv(LD_PRELOAD_PATH) → Process::SetPreloadEnv → setenv(LD_PRELOAD)
```

### 2.4 动态加载/注入攻击面

| 机制 | 文件位置 | 风险等级 | 说明 |
|------|----------|----------|------|
| `dlopen()` 库加载 | vallina_symbol.cpp:37 | **Critical** | 动态加载 Ascend 库，路径来自环境变量 |
| `dlsym()` 符号获取 | vallina_symbol.cpp:48 | **High** | 获取原始函数指针，可能被劫持 |
| `InitInjectionMstx()` | mstx_inject.cpp:179 | **Critical** | MSTX API 函数指针表注入 |
| Python `sys.meta_path` | hijack_utility.py:346 | **Critical** | 模块导入劫持，可控制模块加载 |

### 2.5 文件操作攻击面

| 操作 | 文件位置 | 风险等级 | 说明 |
|------|----------|----------|------|
| JSON 配置读取 | json_manager.cpp:54 | **Medium** | 从用户指定路径读取配置 |
| Tensor Dump | tensor_dumper.cpp:58 | **High** | Dump tensor 到用户可控路径 |
| CSV/DB 文件创建 | file.cpp:138-209 | **Medium** | 输出文件创建，路径来自 config |

## 3. 高风险模块分析

### 3.1 kernel_hooks 模块 [Critical]

**核心风险**:
- 通过 LD_PRELOAD 机制拦截系统/驱动 API
- 使用 `dlopen`/`dlsym` 获取原始函数指针
- 环境变量控制库加载路径

**关键文件**:
- `runtime_hooks.cpp`: 拦截 `rtKernelLaunch` 等内核启动 API
- `acl_hooks.cpp`: 拦截 `aclInit`/`aclFinalize` 等 ACL API
- `vallina_symbol.cpp`: 动态库加载和符号获取

**潜在漏洞**:
- CWE-426: Untrusted Search Path - 环境变量控制库路径
- CWE-94: Code Injection - 动态库加载可注入恶意代码

### 3.2 python_hijacker 模块 [Critical]

**核心风险**:
- 通过 `sys.meta_path` 注入自定义模块加载器
- 可替换任意 Python 模块的函数实现
- stub 回调函数由用户传入

**关键文件**:
- `hijack_utility.py`: 劫持注册核心逻辑
- `hijack_manager.py`: 劫持生命周期管理
- `hijack_map.py`: 预定义劫持目标映射

**潜在漏洞**:
- CWE-94: Code Injection - stub 回调函数注入
- CWE-822: Untrusted Pointer Dereference - setattr 控制函数指针

### 3.3 process 模块 [Critical]

**核心风险**:
- 使用 `execvpe()` 执行用户指定程序
- 设置 `LD_PRELOAD` 环境变量
- 程序路径来自命令行参数

**关键文件**:
- `process.cpp`: 进程启动和钩子注入

**潜在漏洞**:
- CWE-78: Command Injection - 用户程序路径执行
- CWE-426: Untrusted Search Path - LD_PRELOAD 路径控制

### 3.4 memory_watch 模块 [High]

**核心风险**:
- Tensor 数据 Dump 到文件
- 文件名来自用户传入的 op 名称
- 使用 `aclrtMemcpy` 从设备复制数据

**关键文件**:
- `tensor_dumper.cpp`: Tensor 数据 Dump
- `memory_watch.cpp`: 监控逻辑

**潜在漏洞**:
- CWE-22: Path Traversal - Dump 文件名包含用户传入字符串
- CWE-787: Out-of-bounds Write - memcpy 目标缓冲区大小来自 tensor.dataSize

### 3.5 python_itf 模块 [Critical]

**核心风险**:
- Python C 扩展 API，参数来自 Python 层
- 字符串/路径参数通过 `PyUnicode_AsUTF8` 获取
- 使用 `strncpy_s` 复制到固定大小缓冲区

**关键文件**:
- `msleaksmodule.cpp`: Python 模块入口
- `watcherobject.cpp`: Watcher API 实现

**潜在漏洞**:
- CWE-120: Buffer Overflow - strncpy_s 到固定大小缓冲区
- CWE-20: Improper Input Validation - Python 参数验证不充分

### 3.6 client_parser 模块 [Critical]

**核心风险**:
- 命令行参数解析
- 路径参数存在字符验证但可能绕过
- 整数参数存在边界验证

**关键文件**:
- `client_parser.cpp`: 参数解析核心逻辑

**潜在漏洞**:
- CWE-22: Path Traversal - 输出路径验证可能不充分
- CWE-78: Command Injection - 用户命令直接执行

## 4. 数据流分析

### 4.1 命令行到文件写入路径

```
Source: argv (命令行参数)
  ↓
Process: ClientParser::Parse
  ↓
Process: ParseOutputPath (路径验证)
  ↓
Sink: strncpy_s(config.outputDir) [CWE-120 潜在溢出]
  ↓
Process: FileCreateManager::CreateFile
  ↓
Sink: fopen/fprintf (文件写入)
```

### 4.2 环境变量到库加载路径

```
Source: getenv(ASCEND_HOME_PATH)
  ↓
Process: LibLoad
  ↓
Process: libPath = pathEnv + "/lib64/" + libName
  ↓
Sink: dlopen(libPath) [CWE-426 恶意库注入]
```

### 4.3 Python API 到 Tensor Dump 路径

```
Source: watcher.watch(tensor, name=user_name)
  ↓
Process: PyMemScopeWatcherWatch
  ↓
Process: TensorDumper::SetDumpName(ptr, name)
  ↓
Process: TensorDumper::DumpTensorBinary
  ↓
Process: CleanFileName (文件名清理)
  ↓
Sink: std::ofstream::write (文件写入) [CWE-22 路径遍历风险]
```

### 4.4 MSTX 注入路径

```
Source: getFuncTable (外部库提供的函数指针表)
  ↓
Process: InitInjectionMstx
  ↓
Process: MstxTableCoreInject
  ↓
Sink: *outTable[index] = (MstxFuncPointer)MstxMarkAFunc [CWE-822 函数指针劫持]
```

### 4.5 Python 模块劫持路径

```
Source: module, class_name, method_name, stub (用户参数)
  ↓
Process: hijacker()
  ↓
Process: HiJackerManager.add_unit
  ↓
Process: HiJackerWrapperFunction.activate
  ↓
Sink: setattr(parent_obj, func_name, wrapper) [CWE-94 代码注入]
  ↓
Sink: unit.stub(*args, **kws) [CWE-822 回调执行]
```

## 5. STRIDE 建模

### 5.1 Spoofing (身份伪造)

| 威胁场景 | 影响 | 严重程度 |
|----------|------|----------|
| 通过 LD_PRELOAD_PATH 注入恶意钩子库伪装成合法库 | 钩子函数被劫持，收集的数据被篡改 | **Critical** |
| 通过 ASCEND_HOME_PATH 加载恶意 Ascend 库 | ACL API 被劫持，可能导致设备控制权丢失 | **Critical** |
| Python 模块劫持替换合法函数 | 用户代码逻辑被篡改 | **High** |

### 5.2 Tampering (数据篡改)

| 威胁场景 | 影响 | 严重程度 |
|----------|------|----------|
| 通过 MSTX 函数指针表注入篡改回调行为 | MSTX 标记数据被篡改 | **High** |
| 通过 JSON 配置文件篡改配置参数 | 分析参数被修改，输出路径被控制 | **Medium** |
| Tensor Dump 文件名注入特殊字符 | 文件写入到非预期路径 | **Medium** |

### 5.3 Repudiation (抵赖)

| 威胁场景 | 影响 | 严重程度 |
|----------|------|----------|
| 日志写入用户可控路径 | 日志文件可能被篡改或删除 | **Medium** |
| 缺少操作审计记录 | 无法追踪恶意操作来源 | **Low** |

### 5.4 Information Disclosure (信息泄露)

| 威胁场景 | 影响 | 严重程度 |
|----------|------|----------|
| Tensor Dump 写入不安全路径 | Tensor 数据可能泄露到非预期位置 | **High** |
| 配置文件包含敏感路径信息 | 路径信息可能泄露 | **Medium** |
| 调用栈信息写入日志 | 可能泄露代码结构信息 | **Low** |

### 5.5 Denial of Service (拒绝服务)

| 娃胁场景 | 影响 | 严重程度 |
|----------|------|----------|
| 通过 --input 参数传入超大文件 | 文件解析可能导致资源耗尽 | **Medium** |
| Tensor 监控数量无限制 | 可能导致内存耗尽 | **Medium** |
| Python trace 深度可达 1000 | 深调用栈可能导致性能问题 | **Low** |

### 5.6 Elevation of Privilege (权限提升)

| 威胁场景 | 影响 | 严重程度 |
|----------|------|----------|
| 通过 LD_PRELOAD 加载恶意库 | 以目标程序权限执行恶意代码 | **Critical** |
| Python stub 回调执行用户代码 | 以 Python 进程权限执行 | **High** |
| execvpe 执行用户程序 | 以当前进程权限执行任意程序 | **Critical** |

## 6. 安全控制措施分析

### 6.1 已存在的安全控制

| 控制措施 | 位置 | 有效性 |
|----------|------|--------|
| 路径字符验证 | string_validator.cpp:71 | 部分有效，仅限制特殊字符 |
| 路径深度验证 | path.cpp:190 | 有效，限制 32 层 |
| 路径长度验证 | path.cpp:196 | 有效，限制 NAME_MAX/PATH_MAX |
| 软链接检测 | path.cpp:212 | 有效，拒绝软链接 |
| 权限检测 | path.cpp:219 | 有效，检查 group/other 写权限 |
| 整数范围验证 | string_validator.cpp:114 | 有效，min/max 边界 |
| strncpy_s 使用 | client_parser.cpp:443 | 有效，安全字符串复制 |
| memset_s 使用 | process.cpp:838 | 有效，安全内存清零 |

### 6.2 缺失的安全控制

| 缺失控制 | 风险 | 建议 |
|----------|------|------|
| 环境变量白名单验证 | **Critical** | 验证 LD_PRELOAD_PATH/ASCEND_HOME_PATH 路径合法性 |
| dlopen 库签名验证 | **Critical** | 添加库签名校验机制 |
| 文件名完整路径遍历防护 | **High** | 使用 realpath 并验证前缀 |
| Python 参数深度验证 | **High** | 验证字典键值类型和范围 |
| Tensor 监控数量限制 | **Medium** | 添加最大监控数量限制 |
| MSTX 函数指针表校验 | **High** | 验证函数指针范围和合法性 |
| stub 回调函数验证 | **Critical** | 限制可劫持的模块/函数范围 |

## 7. 漏洞优先级排序

### Critical 级别 (立即处理)

1. **CWE-426: Untrusted Search Path** - 环境变量控制库加载路径
   - 文件: vallina_symbol.cpp, process.cpp
   - 影响: 恶意库注入，代码执行

2. **CWE-78: Command Injection** - 用户程序路径直接执行
   - 文件: process.cpp:226
   - 影响: 以当前权限执行任意程序

3. **CWE-94: Code Injection** - Python stub 回调函数执行
   - 文件: hijack_utility.py
   - 影响: 任意代码执行

### High 级别 (短期处理)

4. **CWE-822: Untrusted Pointer Dereference** - MSTX 函数指针表注入
   - 文件: mstx_inject.cpp
   - 影响: 函数指针劫持

5. **CWE-22: Path Traversal** - Tensor Dump 文件名路径遍历
   - 文件: tensor_dumper.cpp
   - 影响: 文件写入到非预期路径

6. **CWE-120: Buffer Overflow** - strncpy_s 到固定缓冲区
   - 文件: msleaksmodule.cpp, watcherobject.cpp
   - 影响: 缓冲区溢出（已使用 strncpy_s 但需验证长度）

### Medium 级别 (中期处理)

7. **CWE-20: Improper Input Validation** - Python API 参数验证
   - 文件: msleaksmodule.cpp, watcherobject.cpp
   - 影响: 参数类型/范围验证不充分

8. **CWE-787: Out-of-bounds Write** - memcpy 目标缓冲区
   - 文件: tensor_dumper.cpp:130
   - 影响: tensor.dataSize 控制复制大小

## 8. 建议修复方案

### 8.1 环境变量控制加固

```cpp
// 建议: 在 LibLoad 中添加路径白名单验证
bool ValidateLibPath(const std::string& libPath) {
    // 验证路径不包含 ../ 和特殊字符
    // 验证路径以预期目录前缀开头
    // 验证文件权限
}
```

### 8.2 命令执行加固

```cpp
// 建议: 在 Process::DoLaunch 中添加路径验证
bool ValidateExecPath(const std::string& path) {
    // 使用 realpath 获取实际路径
    // 验证路径在允许范围内
    // 验证文件权限和所有权
}
```

### 8.3 Python 模块劫持加固

```python
# 建议: 在 hijack_utility.py 中添加白名单验证
ALLOWED_MODULES = set([
    "torch",
    "torch_npu",
    "vllm_ascend",
    ...
])

def hijacker(...):
    if module not in ALLOWED_MODULES:
        raise ValueError(f"Module {module} is not in allowed list")
```

### 8.4 文件操作加固

```cpp
// 建议: 在 TensorDumper::DumpTensorBinary 中添加完整路径验证
std::string ValidateAndSanitizePath(const std::string& fileName, const std::string& baseDir) {
    // 1. 清理文件名中的危险字符
    // 2. 拼接完整路径
    // 3. 使用 realpath 获取实际路径
    // 4. 验证实际路径以 baseDir 开头
}
```

## 9. 总结

MindStudio-MemScope 是一个涉及底层系统交互的内存分析工具，存在多个高风险攻击面：

1. **LD_PRELOAD 机制** 是核心风险点，环境变量控制可导致恶意库注入
2. **Python API 层** 参数验证不充分，存在多种注入风险
3. **文件操作** 存在路径遍历和信息泄露风险
4. **动态加载/注入** 机制存在函数指针劫持风险

建议优先处理 Critical 级别的漏洞，特别是环境变量控制和动态库加载的安全加固。