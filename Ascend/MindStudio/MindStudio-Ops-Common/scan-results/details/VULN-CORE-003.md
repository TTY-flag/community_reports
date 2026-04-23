# VULN-CORE-003：CustomDBI.Convert不可信函数指针执行致任意代码执行

## 1. 漏洞基本信息

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-CORE-003 |
| **漏洞类型** | Untrusted Function Pointer Execution (不可信函数指针执行) |
| **CWE 编号** | CWE-822 |
| **严重等级** | Critical |
| **置信度** | 90/100 |
| **文件路径** | csrc/core/BinaryInstrumentation.cpp |
| **触发位置** | 行 227 |
| **函数名称** | CustomDBI::Convert |
| **代码片段** | `initFunc_(tempCtrlPath.c_str(), tempCtrlPath.length());` |
| **影响模块** | core, runtime |
| **数据流** | IPC pluginPath → dlopen() → dlsym("MSBitStart") → initFunc_ call |

---

## 2. 触发条件分析

### 2.1 核心漏洞代码

**位置**: `csrc/core/BinaryInstrumentation.cpp:227`

```cpp
bool CustomDBI::Convert(const std::string& newKernelFile, const std::string& oldKernelFile,
    const std::string& tilingKey)
{
    // ... 前置处理 ...
    
    // 行 227: 直接调用从插件加载的函数指针
    initFunc_(tempCtrlPath.c_str(), tempCtrlPath.length());
    
    // ... 后续处理 ...
}
```

**位置**: `csrc/core/BinaryInstrumentation.cpp:250-271`

```cpp
bool CustomDBI::SetConfig(const Config& config)
{
    config_ = config;
    const string &pluginPath = config.pluginPath;
    
    // 行 260: 直接加载用户指定的插件，无路径验证
    handle_ = dlopen(pluginPath.c_str(), RTLD_LAZY);
    if (handle_ == nullptr) {
        DEBUG_LOG("Invalid dbi config, dlopen %s failed", pluginPath.c_str());
        return false;
    }
    
    // 行 265: 从加载的插件中获取函数指针
    initFunc_ = reinterpret_cast<PluginInitFunc>(dlsym(handle_, "MSBitStart"));
    if (!initFunc_) {
        DEBUG_LOG("Invalid dbi config, no msbitStart function");
        return false;
    }
    
    return true;
}
```

### 2.2 触发条件

漏洞触发需要满足以下条件：

1. **插件路径来源**: pluginPath 通过 IPC 通信从外部进程传入
2. **插件加载**: 使用 dlopen() 加载指定的动态库文件
3. **函数查找**: 使用 dlsym() 查找 "MSBitStart" 函数符号
4. **函数调用**: 在 Convert() 中直接调用 initFunc_ 函数指针
5. **攻击者控制**: 攻击者能够控制 IPC 消息中的 pluginPath 内容

---

## 3. 数据流追踪

### 3.1 完整数据流路径

```
[起点] IPC 客户端进程
  ↓ 发送 SanitizerConfig 消息
  
[接收点] ConfigManager::GetConfig() @csrc/runtime/inject_helpers/ConfigManager.cpp:48
  ↓ LocalDevice::GetInstance(deviceId).Wait(msg, timeOut)
  ↓ Deserialize(msg, *configPtr)
  ↓ 提取 configPtr->pluginPath (无验证)
  
[传递点] DBITaskConfig::Init() @csrc/runtime/inject_helpers/DBITask.cpp:277
  ↓ pluginPath_ = pluginPath
  
[配置点] DBITask::Run() @csrc/runtime/inject_helpers/DBITask.cpp:139/193
  ↓ BinaryInstrumentation::Config config{taskConfig.pluginPath_, ...}
  
[加载点] DBITask::Convert() @csrc/runtime/inject_helpers/DBITask.cpp:255
  ↓ dbi_->SetConfig(config)
  
[动态库加载] CustomDBI::SetConfig() @csrc/core/BinaryInstrumentation.cpp:260
  ↓ dlopen(pluginPath.c_str(), RTLD_LAZY)  ← 加载任意 SO 文件
  
[函数指针获取] CustomDBI::SetConfig() @csrc/core/BinaryInstrumentation.cpp:265
  ↓ dlsym(handle_, "MSBitStart")  ← 获取函数指针
  
[函数指针执行] CustomDBI::Convert() @csrc/core/BinaryInstrumentation.cpp:227
  ↓ initFunc_(tempCtrlPath.c_str(), tempCtrlPath.length())  ← [终点] 任意代码执行
```

### 3.2 关键数据结构

**IPC 配置结构** (csrc/utils/Protocol.h:518-537):

```cpp
struct SanitizerConfig {
    bool defaultCheck;
    bool memCheck;
    // ... 其他配置项 ...
    char pluginPath[PLUGIN_PATH_MAX];  // 256 字节的路径字符串
    char kernelName[KERNEL_NAME_MAX];
    char dumpPath[DUMP_PATH_MAX];
};
```

**函数指针类型** (csrc/core/BinaryInstrumentation.h:107):

```cpp
using PluginInitFunc = void(*)(const char *outputPath, uint16_t length);
```

---

## 4. 攻击场景

### 4.1 攻击流程

**步骤 1: 准备恶意插件**
```cpp
// 编写恶意 SO 文件
extern "C" {
    void MSBitStart(const char *outputPath, uint16_t length) {
        // 执行任意代码
        system("malicious_command");
        // 破坏系统文件
        // 提升权限
        // 窃取数据
    }
}
```

**步骤 2: 编译恶意插件**
```bash
gcc -shared -fPIC -o malicious_plugin.so malicious_plugin.c
```

**步骤 3: 通过 IPC 发送恶意路径**
- 攻击者控制 msSanitizer 或 msOpProf 进程
- 通过 IPC 发送 SanitizerConfig 消息
- 将 pluginPath 设置为恶意 SO 文件路径，例如：
  - `/tmp/malicious_plugin.so`
  - `/home/attacker/exploit.so`
  - 相对路径如 `./malicious_plugin.so`

**步骤 4: 漏洞触发**
- 注入库接收 IPC 配置
- 直接加载恶意 SO 文件
- 执行 MSBitStart 函数中的任意代码

### 4.2 攻击后果

1. **任意代码执行**: 以当前进程权限执行任意命令
2. **权限提升**: 如果进程有特权，攻击者可提升权限
3. **数据窃取**: 读取敏感数据，如 kernel 源码、配置文件
4. **系统破坏**: 破坏关键系统文件，植入后门
5. **横向渗透**: 利用注入库的访问权限攻击其他系统组件

---

## 5. 影响范围

### 5.1 直接影响

- **受影响组件**: 
  - `CustomDBI` 类（动态插桩功能）
  - 所有调用 `DBIFactory::Create(BIType::CUSTOMIZE)` 的代码路径
  
- **受影响入口点**:
  1. `ConfigManager::GetConfig()` - IPC 配置接收
  2. `HijackedFuncOfKernelLaunch.cpp:273` - kernel launch hook
  3. `HijackedFuncOfAclrtLaunchKernelImpl.cpp:100` - ACL API hook
  4. 其他 9+ 个 kernel launch hijacked 函数

- **信任边界**: 
  - IPC 客户端 → 注入库（msOpCom）
  - 用户插件 → 注入库（Dynamic Library Loading Interface）
  - 项目模型标注：**risk: Critical**

### 5.2 部署环境风险

根据项目模型（project_model.json）：

```json
{
  "boundary": "Dynamic Library Loading Interface",
  "trusted_side": "Injection Library (msOpCom)",
  "untrusted_side": "User Plugins (.so files specified by pluginPath)",
  "risk": "Critical"
}
```

**部署场景**:
- msOpCom 作为动态库通过 LD_PRELOAD 注入到目标应用程序
- 运行在开发维测环境下
- 与 msOpProf、msSanitizer 等控制进程进行 IPC 通信

**攻击者机会**:
- 通过控制 IPC 客户端进程（msSanitizer/msOpProf）
- 或通过环境变量影响配置路径
- 或通过配置文件注入恶意路径

---

## 6. 安全缺陷分析

### 6.1 已有的安全措施（不足）

**仅有的安全检查**:

1. **空字符终止** (ConfigManager.cpp:52-54):
   ```cpp
   configPtr->pluginPath[PLUGIN_PATH_MAX - 1] = '\0'; // 确保以空字符结尾
   configPtr->kernelName[KERNEL_NAME_MAX - 1] = '\0';
   configPtr->dumpPath[DUMP_PATH_MAX - 1] = '\0';
   ```
   **评价**: 仅防止缓冲区溢出，不提供路径安全验证

2. **dlopen/dlsym 错误处理** (BinaryInstrumentation.cpp:261-269):
   ```cpp
   if (handle_ == nullptr) {
       DEBUG_LOG("Invalid dbi config, dlopen %s failed", pluginPath.c_str());
       return false;
   }
   if (!initFunc_) {
       DEBUG_LOG("Invalid dbi config, no msbitStart function");
       return false;
   }
   ```
   **评价**: 仅检查加载是否成功，不验证路径合法性

### 6.2 缺失的安全措施

**完全缺失**:

1. ❌ **路径白名单验证**: 未检查 pluginPath 是否在允许的目录范围内
2. ❌ **路径规范化**: 未消除 `..`、符号链接等路径遍历风险
3. ❌ **权限检查**: 未验证 SO 文件的权限和所有权
4. ❌ **符号验证**: 未验证 dlsym 获取的函数指针是否可信
5. ❌ **插件签名验证**: 未检查 SO 文件的数字签名
6. ❌ **沙箱隔离**: 未限制插件代码的执行权限
7. ❌ **IPC 消息验证**: 未验证 IPC 消息来源的可信性

---

## 7. 修复建议

### 7.1 核心修复方案（推荐）

**优先级**: **P0（立即修复）**

#### 方案 1: 路径白名单 + 严格验证

**实施步骤**:

1. **定义白名单目录**:
   ```cpp
   // 在 PlatformConfig.h 中定义
   constexpr const char* ALLOWED_PLUGIN_DIRS[] = {
       "/usr/local/ascend/tools/msopt/lib64",
       "/opt/ascend/tools/msopt/lib64",
       nullptr  // 结束标记
   };
   ```

2. **实现路径验证函数**:
   ```cpp
   // 在 BinaryInstrumentation.cpp 中添加
   bool ValidatePluginPath(const std::string& pluginPath) {
       // 检查空路径
       if (pluginPath.empty()) {
           ERROR_LOG("Empty plugin path");
           return false;
       }
       
       // 规范化路径（消除 .. 和符号链接）
       char resolvedPath[PATH_MAX];
       if (realpath(pluginPath.c_str(), resolvedPath) == nullptr) {
           ERROR_LOG("Cannot resolve plugin path: %s", pluginPath.c_str());
           return false;
       }
       
       // 检查是否在白名单目录内
       bool inWhitelist = false;
       for (const char* allowedDir : ALLOWED_PLUGIN_DIRS) {
           if (allowedDir == nullptr) break;
           if (strncmp(resolvedPath, allowedDir, strlen(allowedDir)) == 0) {
               inWhitelist = true;
               break;
           }
       }
       
       if (!inWhitelist) {
           ERROR_LOG("Plugin path not in whitelist: %s", resolvedPath);
           return false;
       }
       
       // 检查文件权限（必须是 root:root 或可信用户）
       struct stat fileStat;
       if (stat(resolvedPath, &fileStat) != 0) {
           ERROR_LOG("Cannot stat plugin file: %s", resolvedPath);
           return false;
       }
       
       // 只允许 root 或可信用户拥有的文件
       if (fileStat.st_uid != 0 && fileStat.st_uid != getuid()) {
           ERROR_LOG("Plugin file owner not trusted: %s", resolvedPath);
           return false;
       }
       
       // 文件权限必须是 0644 或更严格
       if ((fileStat.st_mode & 0777) > 0644) {
           ERROR_LOG("Plugin file permissions too loose: %s", resolvedPath);
           return false;
       }
       
       return true;
   }
   ```

3. **在 SetConfig 中添加验证**:
   ```cpp
   bool CustomDBI::SetConfig(const Config& config)
   {
       config_ = config;
       const string &pluginPath = config.pluginPath;
       
       // 新增：路径白名单验证
       if (!ValidatePluginPath(pluginPath)) {
           ERROR_LOG("Plugin path validation failed: %s", pluginPath.c_str());
           return false;
       }
       
       // 检查架构名称
       if (config.archName.empty()) {
           ERROR_LOG("Empty arch name");
           return false;
       }
       
       // 加载插件
       handle_ = dlopen(pluginPath.c_str(), RTLD_NOW);  // 改用 RTLD_NOW 立即绑定
       if (handle_ == nullptr) {
           ERROR_LOG("dlopen failed: %s", dlerror());
           return false;
       }
       
       // 验证函数指针
       initFunc_ = reinterpret_cast<PluginInitFunc>(dlsym(handle_, "MSBitStart"));
       if (!initFunc_) {
           ERROR_LOG("MSBitStart function not found");
           dlclose(handle_);
           handle_ = nullptr;
           return false;
       }
       
       return true;
   }
   ```

**预期效果**:
- 阻止加载任意路径的插件
- 防止路径遍历攻击（`..`、符号链接）
- 确保插件文件来自可信来源
- 限制文件权限，防止恶意修改

---

#### 方案 2: 插件签名验证（更高安全性）

**实施步骤**:

1. **引入签名验证库**:
   - 使用 OpenSSL 或 GnuPG 验证数字签名
   - 为官方插件生成签名证书

2. **在加载前验证签名**:
   ```cpp
   bool VerifyPluginSignature(const std::string& pluginPath) {
       // 读取插件文件
       // 计算哈希值
       // 验证数字签名
       // 返回验证结果
   }
   ```

3. **集成到 SetConfig**:
   ```cpp
   if (!VerifyPluginSignature(pluginPath)) {
       ERROR_LOG("Plugin signature verification failed");
       return false;
   }
   ```

**预期效果**:
- 确保插件未被篡改
- 防止恶意插件注入
- 提供端到端的安全保证

---

#### 方案 3: IPC 消息验证

**实施步骤**:

1. **验证 IPC 客户端身份**:
   ```cpp
   bool ValidateIPCClient(int32_t deviceId) {
       // 检查进程 UID/GID
       // 验证进程路径是否可信
       // 检查进程权限
   }
   ```

2. **在接收 IPC 配置时验证**:
   ```cpp
   SanitizerConfig const &ConfigManager<SanitizerConfig>::GetConfig() const
   {
       // 新增：验证 IPC 客户端
       if (!ValidateIPCClient(deviceId)) {
           ERROR_LOG("IPC client not trusted");
           return defaultConfig;
       }
       
       // 接收配置
       auto readSize = LocalDevice::GetInstance(deviceId).Wait(msg, timeOut);
       // ...
   }
   ```

**预期效果**:
- 防止恶意进程发送伪造的 IPC 消息
- 增强信任边界的安全性

---

### 7.2 短期缓解措施（临时方案）

**优先级**: **P1（快速部署）**

1. **限制插件路径为内部生成**:
   ```cpp
   // 在 ConfigManager.cpp 中修改
   if (!IsValidPluginPath(configPtr->pluginPath)) {
       // 使用内部生成的安全路径
       std::string safePath = ProfConfig::Instance().GetPluginPath(ProfDBIType::MEMORY_CHART);
       strcpy(configPtr->pluginPath, safePath.c_str());
   }
   ```

2. **禁用自定义插件功能**:
   ```cpp
   // 在 BinaryInstrumentation.cpp 中添加配置开关
   if (!AllowCustomPlugin()) {
       ERROR_LOG("Custom plugin disabled for security");
       return false;
   }
   ```

3. **增加日志审计**:
   ```cpp
   // 记录所有插件加载操作
   INFO_LOG("Loading plugin from: %s by user: %d", pluginPath.c_str(), getuid());
   INFO_LOG("Plugin handle: %p, initFunc: %p", handle_, initFunc_);
   ```

---

### 7.3 长期安全架构建议

**优先级**: **P2（架构改进）**

1. **插件沙箱隔离**:
   - 使用 seccomp 或 SELinux 限制插件代码权限
   - 在独立进程中加载和运行插件
   - 使用 IPC 通信而非直接函数调用

2. **插件管理框架**:
   - 建立插件注册和审核机制
   - 实现插件生命周期管理
   - 提供插件安全策略配置接口

3. **信任链验证**:
   - 从 IPC 客户端到插件加载建立完整的信任链
   - 使用证书和签名验证每个环节
   - 实现端到端的安全审计

---

## 8. 验证测试建议

### 8.1 安全测试用例

**测试用例 1: 路径遍历攻击**
```cpp
// 输入: pluginPath = "/usr/local/ascend/../tmp/malicious.so"
// 预期: 拒绝加载（路径不在白名单）
// 实际: 当前会加载并执行恶意代码
```

**测试用例 2: 符号链接攻击**
```cpp
// 输入: pluginPath = "/usr/local/ascend/lib64/plugin.so"（符号链接指向恶意文件）
// 预期: 拒绝加载（resolve 后路径不在白名单）
// 实际: 当前会加载恶意文件
```

**测试用例 3: 伪造 IPC 消息**
```cpp
// 输入: 通过 IPC 发送 SanitizerConfig，pluginPath = "/tmp/exploit.so"
// 预期: 拒绝加载（路径不在白名单）
// 实际: 当前会加载并执行 exploit.so
```

### 8.2 漏洞复现步骤

**环境准备**:
1. 编译 msOpCom 库
2. 编写恶意插件：
   ```cpp
   // malicious_plugin.cpp
   extern "C" {
       void MSBitStart(const char *outputPath, uint16_t length) {
           system("echo 'VULNERABILITY CONFIRMED' > /tmp/pwned.txt");
       }
   }
   ```
   ```bash
   gcc -shared -fPIC -o /tmp/malicious_plugin.so malicious_plugin.cpp
   ```

3. 编写 IPC 客户端：
   ```cpp
   // attacker_ipc.cpp
   SanitizerConfig config;
   strcpy(config.pluginPath, "/tmp/malicious_plugin.so");
   // 发送 IPC 消息...
   ```

4. 运行目标应用程序：
   ```bash
   LD_PRELOAD=./msOpCom.so target_application
   ```

**预期结果**:
- `/tmp/pwned.txt` 文件被创建，内容为 "VULNERABILITY CONFIRMED"
- 证明任意代码执行漏洞存在

---

## 9. 相关漏洞和参考

### 9.1 相关 CWE

- **CWE-822**: Untrusted Function Pointer Execution
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')
- **CWE-426**: Untrusted Search Path
- **CWE-20**: Improper Input Validation

### 9.2 相关安全事件

- **CVE-2019-18634**: sudo 插件路径验证不足导致权限提升
- **CVE-2020-15778**: OpenSSH scp 命令注入漏洞（类似路径验证缺失）

### 9.3 安全最佳实践参考

- OWASP: Path Traversal Prevention
- NIST: Secure Software Development Framework
- Linux: Secure Coding Guidelines for Dynamic Library Loading

---

## 10. 结论

### 10.1 漏洞确认

**确认结论**: **这是一个真实的 Critical 级别漏洞**

**关键证据**:
1. ✅ pluginPath 从 IPC 客户端直接传入，无信任边界验证
2. ✅ 路径直接用于 dlopen，无任何安全检查
3. ✅ 函数指针从动态库中获取并无条件执行
4. ✅ 完整的攻击链清晰可追踪
5. ✅ 无任何缓解措施（仅有空字符终止检查）
6. ✅ 项目模型明确标注风险为 Critical

### 10.2 风险评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **可利用性** | High | 攻击者可通过 IPC 直接控制 pluginPath |
| **影响范围** | Critical | 任意代码执行，权限提升，系统破坏 |
| **攻击难度** | Low | 无需特殊权限，仅需控制 IPC 客户端 |
| **检测难度** | Medium | 需监控 IPC 消息和 dlopen 调用 |
| **修复难度** | Medium | 需添加多层验证，但不影响核心功能 |

### 10.3 建议优先级

| 修复方案 | 优先级 | 时间估计 | 风险降低 |
|----------|--------|----------|----------|
| 路径白名单验证 | P0 | 1-2 天 | 80% |
| 插件签名验证 | P0 | 3-5 天 | 95% |
| IPC 客户端验证 | P1 | 2-3 天 | 70% |
| 禁用自定义插件 | P1 | 0.5 天 | 100%（临时） |
| 插件沙箱隔离 | P2 | 1-2 周 | 99% |

---

## 11. 附录

### 11.1 代码位置索引

| 文件 | 行号 | 功能 | 安全问题 |
|------|------|------|----------|
| BinaryInstrumentation.cpp | 227 | initFunc_ call | 直接执行函数指针 |
| BinaryInstrumentation.cpp | 260 | dlopen() | 加载任意路径 |
| BinaryInstrumentation.cpp | 265 | dlsym() | 获取函数指针 |
| ConfigManager.cpp | 48 | IPC 接收 | 接收外部配置 |
| ConfigManager.cpp | 56 | 路径传递 | 无验证传递 |
| Protocol.h | 534 | SanitizerConfig | 定义 IPC 结构 |
| DBITask.cpp | 139/193 | Config 构造 | 路径流入配置 |

### 11.2 调用图摘要

```
IPC Client Process
  └─> LocalDevice::Wait()
       └─> ConfigManager::GetConfig()
            └─> DBITaskConfig::Init(pluginPath)
                 └─> DBITask::Run()
                      └─> DBITask::Convert()
                           └─> CustomDBI::SetConfig()
                                ├─> dlopen(pluginPath)
                                └─> dlsym("MSBitStart")
                                     └─> CustomDBI::Convert()
                                          └─> initFunc_() [ARBITRARY CODE EXECUTION]
```

---

**报告生成时间**: 2026-04-21  
**扫描工具**: OpenCode Multi-Agent Vulnerability Scanner  
**分析 Agent**: details-worker  
**状态**: CONFIRMED - Critical Severity
