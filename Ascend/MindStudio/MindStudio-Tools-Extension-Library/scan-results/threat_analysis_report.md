# 威胁分析报告

> 项目: MindStudio-Tools-Extension-Library (mstx)
> 分析时间: 2026-04-20
> 分析模式: 自主分析（无 threat.md 约束文件）

## 1. 项目概述

MindStudio Tools Extension Library (mstx) 是华为昇腾 AI 算子工具扩展接口库，提供性能打点和追踪功能。该项目包含：

- **C/C++ 核心库**: 提供底层 API 实现，包括 `mstxMarkA`、`mstxRangeStartA` 等标记函数
- **Python 绑定**: 通过 C++ 实现的 Python 扩展模块，将 C API 封装为 Python 函数
- **构建脚本**: Python 实现的依赖下载和构建管理

项目作为动态库被其他应用程序加载，或作为 Python 扩展模块导入。

## 2. STRIDE 威胁建模

### 2.1 Spoofing (身份伪造)

| 威胁 | 风险等级 | 描述 | 相关入口 |
|------|----------|------|----------|
| 动态库伪造 | **Critical** | 通过 `MSTX_INJECTION_PATH` 环境变量加载外部库，攻击者可伪造合法注入库 | `mstxInitWithInjectionLib` |

**分析**: 
- `mstx_impl.h:178-180` 使用 `getenv()` 获取 `MSTX_INJECTION_PATH`，然后调用 `dlopen()` 加载指定路径的动态库
- 无签名验证、无路径限制、无白名单检查
- 攻击者可设置环境变量为恶意库路径，实现代码注入

### 2.2 Tampering (数据篡改)

| 威胁 | 风险等级 | 描述 | 相关入口 |
|------|----------|------|----------|
| 依赖包篡改 | **High** | 从远程 URL 下载依赖包，存在中间人攻击或恶意包注入风险 | `download_dependencies.py` |
| 内存区域篡改 | **Medium** | 内存管理 API 接收外部结构体指针，可能篡改内存权限配置 | `mstxMemPermissionsAssign` |

**分析**:
- `download_dependencies.py:104` 使用 `curl -Lfk` 下载文件，`-L` 允许重定向，`-k` 禁用 SSL 验证
- SHA256 校验可选（`spec[name].get("sha256")`），部分依赖可能未配置校验
- URL 从 `dependencies.json` 读取，文件可能被篡改

### 2.3 Repudiation (抵赖)

| 威胁 | 风险等级 | 描述 |
|------|----------|------|
| 无日志记录 | **Low** | 库初始化过程无详细日志，无法追溯注入库加载来源 |

**分析**: 初始化失败仅返回 `MSTX_FAIL`，无详细错误信息或日志记录。

### 2.4 Information Disclosure (信息泄露)

| 威告 | 风险等级 | 描述 | 相关入口 |
|------|----------|------|----------|
| 调用路径泄露 | **Low** | `dlopen()` 失败时可能泄露库搜索路径信息 | `mstxInitWithInjectionLib` |

**分析**: 当前代码在 `dlopen()` 失败时无错误信息输出，风险较低。

### 2.5 Denial of Service (拒绝服务)

| 威胁 | 风险等级 | 描述 | 相关入口 |
|------|----------|------|----------|
| NULL 指针崩溃 | **High** | `message` 参数文档声明不可为 NULL，但代码无检查 | `mstxMarkA`, `mstxRangeStartA` |
| 初始化死锁 | **Medium** | 多线程初始化时的忙等待循环可能导致 CPU 资源耗尽 | `mstxInitOnce` |

**分析**:
- `mstx_impl_core.h:22-28` 中 `mstxMarkA` 直接调用 `(*local)(message, stream)`，无 NULL 检查
- 文档注释声明 "cannot be null"，但依赖调用方遵守，存在潜在风险
- Python 绑定中 `PyArg_ParseTupleAndKeywords` 使用 `"|sO"` 格式，`message` 可能为 NULL

### 2.6 Elevation of Privilege (权限提升)

| 威胁 | 风险等级 | 描述 | 相关入口 |
|------|----------|------|----------|
| 动态库注入 | **Critical** | 通过 `MSTX_INJECTION_PATH` 加载任意库，可执行任意代码 | `mstxInitWithInjectionLib` |
| 内存权限篡改 | **Medium** | `mstxMemPermissionsAssign` 可修改内存区域的读写权限 | `mstxMemPermissionsAssign` |

**分析**: 
- 动态库注入是最严重的威胁，攻击者可完全控制库的行为
- `mstxMemPermissionsAssign` 可修改进程内存权限，潜在风险需关注

## 3. 高风险攻击面

### 3.1 环境变量注入攻击面 (Critical)

**代码位置**: `c/include/mstx/mstx_detail/mstx_impl.h:174-188`

```c
const char *const MSTX_INJECTION_PATH = "MSTX_INJECTION_PATH";
char *injectionPath = getenv(MSTX_INJECTION_PATH);
if (injectionPath) {
    handle = dlopen(injectionPath, RTLD_LAZY | RTLD_LOCAL);
}
```

**攻击向量**:
1. 攻击者设置 `MSTX_INJECTION_PATH=/path/to/malicious.so`
2. 应用程序加载 mstx 库并调用任何 API
3. `mstxInitOnce()` 触发初始化
4. 恶意库的 `InitInjectionMstx` 函数被调用
5. 恶意代码获得执行机会

**影响**: 完全控制应用程序行为，可窃取数据、篡改计算结果、植入后门

### 3.2 Python API NULL 参数攻击面 (High)

**代码位置**: `python/mstx_api.cpp:31-38`

```c
void ParseArgs(PyObject *args, PyObject *kwds, char *&message, aclrtStream &stream)
{
    message = nullptr;
    stream = nullptr;
    static char arg1[] = "message";
    static char arg2[] = "stream";
    static char *kwlist[] = {arg1, arg2, nullptr};
    PyArg_ParseTupleAndKeywords(args, kwds, "|sO", kwlist, &message, &stream);
}
```

**问题**:
- `"|sO"` 格式中 `|` 表示可选参数，`message` 可能为 NULL
- `mstxMarkA(message, stream)` 在 `message == NULL` 时会传递 NULL 给底层函数指针

**攻击向量**:
```python
import mstx
mstx.mark()  # message 未提供，导致 NULL
```

### 3.3 依赖下载攻击面 (High)

**代码位置**: `download_dependencies.py:93-126`

```python
self._exec_shell_cmd(["curl", "-Lfk", "--retry", "5", "--retry-delay", "2",
                      "-o", str(archive_path), url], msg=f"Download {name} ...")
```

**问题**:
- `-k` 禁用 SSL 证书验证
- `-L` 允许跟随重定向
- SHA256 校验可选

**攻击向量**:
1. 中间人攻击劫持下载 URL
2. 重定向到恶意服务器
3. 提供篡改后的依赖包

## 4. 模块风险评估

| 模块 | 风险等级 | 关键问题 | 优先级 |
|------|----------|----------|--------|
| c_core | **Critical** | 环境变量注入、NULL 检查缺失 | 1 |
| python_binding | **High** | 参数解析可能导致 NULL 传递 | 2 |
| build_scripts | **High** | 远程下载安全性不足 | 2 |

## 5. 建议缓解措施

### 5.1 环境变量注入缓解 (Critical)

1. **路径白名单**: 限制 `MSTX_INJECTION_PATH` 只能加载特定目录下的库
2. **签名验证**: 要求注入库必须具有有效签名
3. **路径清理**: 禁止加载包含 `..` 或绝对路径指向敏感目录的库
4. **日志记录**: 记录所有库加载操作，便于审计

### 5.2 NULL 参数缓解 (High)

1. **添加检查**: 在 `mstxMarkA`/`mstxRangeStartA` 中添加 NULL 检查
2. **修改 Python 绑定**: 使用 `"sO"` 格式（无 `|`）强制 message 参数
3. **默认值处理**: 为 NULL message 提供默认值或返回错误

### 5.3 依赖下载缓解 (High)

1. **强制 SHA256**: 所有依赖必须配置 SHA256 校验
2. **移除 `-k`**: 启用 SSL 证书验证
3. **限制重定向**: 使用 `--max-redirs` 限制重定向次数
4. **HTTPS 强制**: 只允许 HTTPS URL

## 6. 扫描建议

### 6.1 优先扫描文件

| 文件 | 原因 |
|------|------|
| `c/include/mstx/mstx_detail/mstx_impl.h` | 环境变量注入入口，Critical 风险 |
| `c/include/mstx/mstx_detail/mstx_impl_core.h` | API 实现，NULL 检查缺失 |
| `python/mstx_api.cpp` | Python 绑定，参数解析问题 |
| `download_dependencies.py` | 远程下载，安全风险 |

### 6.2 扫描重点

1. **数据流追踪**: 从 `getenv(MSTX_INJECTION_PATH)` 到 `dlopen()` 的完整路径
2. **NULL 安全**: 所有接受字符串指针的 API 函数
3. **边界检查**: 内存管理 API 的结构体数组边界
4. **输入验证**: Python 绑定的参数格式字符串

## 7. 总结

MindStudio-Tools-Extension-Library 存在以下主要安全风险：

1. **环境变量注入 (Critical)**: 最严重的问题，可导致完全控制应用程序
2. **NULL 参数传递 (High)**: Python 绑定设计缺陷，可能导致拒绝服务
3. **依赖下载安全 (High)**: 缺乏足够的下载安全保护

建议优先修复环境变量注入问题，这是攻击者最容易利用的高风险漏洞。同时应加强 NULL 检查和依赖下载的安全性。