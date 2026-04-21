# 漏洞扫描报告 - 已确认漏洞

**项目**: msPTI (MindStudio Profiling Tools Interface)
**扫描时间**: 2026-04-20T00:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描针对华为昇腾 NPU 性能分析工具库 msPTI (MindStudio Profiling Tools Interface) 进行了全面的安全审计。msPTI 是华为昇腾 AI 处理器生态系统中的核心性能分析组件，被广泛应用于 AI 模型训练和推理场景的性能优化。

扫描发现 **1 个已确认的高危漏洞 (SEC-001)**，涉及动态库加载路径的安全问题。该漏洞允许攻击者通过控制环境变量劫持库加载路径，可能导致恶意代码以受害者进程权限执行，影响范围覆盖使用 msPTI 进行性能分析的各类场景，包括 AI 训练任务、分布式训练集群、DevOps 环境和容器化部署。

**关键发现**：

| 维度 | 数据 |
|------|------|
| 扫描文件数 | 97 个源文件，共 4608 行代码 |
| 漏洞总数 | 8 个候选漏洞 |
| 已确认漏洞 | 1 个 (High 级别) |
| 待确认漏洞 | 6 个 (1 LIKELY + 5 POSSIBLE) |
| 误报 | 1 个 |

**风险等级**: **高** - 已确认漏洞可能导致任意代码执行，建议立即修复。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 5 | 62.5% |
| LIKELY | 1 | 12.5% |
| FALSE_POSITIVE | 1 | 12.5% |
| CONFIRMED | 1 | 12.5% |
| **总计** | **8** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 1 | 100.0% |
| **有效漏洞总计** | **1** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[SEC-001]** Untrusted Search Path (High) - `csrc/common/function_loader.cpp:58` @ `CanonicalSoPath` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `msptiSubscribe@csrc/callback/callback_manager.cpp` | decorator | semi_trusted | 公共API入口点，用户通过此函数订阅回调，传入自定义回调函数和用户数据，用户数据直接传递到回调中 | 注册性能分析回调订阅者 |
| `msptiActivityRegisterCallbacks@csrc/activity/activity_manager.cpp` | decorator | semi_trusted | 公共API入口点，用户注册缓冲区回调函数，回调函数由用户实现并可能处理来自驱动的数据 | 注册活动记录缓冲区回调 |
| `dlopen@csrc/common/function_loader.cpp` | env | untrusted_local | 使用dlopen动态加载外部库，库路径由ASCEND_HOME_PATH环境变量决定，可能被恶意用户篡改导致加载恶意库 | 动态加载libascendcl.so/libhccl.so/libprofapi.so等外部库 |
| `ProfChannelRead@csrc/common/inject/driver_inject.cpp` | file | semi_trusted | 从驱动通道读取原始性能数据，数据来自设备驱动层，可能被篡改或包含异常数据结构 | 从驱动读取通道数据 |
| `ChannelReader::Execute@csrc/activity/ascend/channel/channel_reader.cpp` | file | semi_trusted | 从驱动读取数据后直接进行类型转换和解析，数据未经过验证直接reinterpret_cast | 读取并解析通道数据 |
| `MstxMarkAFunc@csrc/common/inject/mstx_inject.cpp` | stdin | semi_trusted | 用户提供的msg字符串直接传递到内部处理，仅做长度检查，未对内容进行完整验证 | 处理用户标记消息 |
| `CanonicalSoPath@csrc/common/utils.cpp` | env | untrusted_local | 从ASCEND_HOME_PATH环境变量获取库路径，路径拼接后使用realpath规范化但未做充分验证 | 从环境变量解析动态库路径 |
| `KernelParser::ReportRtTaskTrack@csrc/activity/ascend/parser/kernel_parser.cpp` | rpc | semi_trusted | 从MsprofCompactInfo结构解析数据，数据来自profapi回调，结构体内容可能包含异常值 | 解析内核任务追踪数据 |

**其他攻击面**:
- 动态库加载机制: dlopen/dlsym 加载 libascendcl.so, libhccl.so, libprofapi.so, libascend_hal.so
- 环境变量依赖: ASCEND_HOME_PATH 控制动态库搜索路径
- 驱动数据通道: ProfChannelRead 从设备驱动读取原始二进制数据
- 用户回调机制: msptiSubscribe/msptiActivityRegisterCallbacks 注册用户回调函数
- 字符串输入: mstx标记函数的消息字符串(msg)、域名(domain)
- 结构体转换: reinterpret_cast 直接转换驱动数据为内部结构体
- 缓冲区操作: memcpy_s 复制活动记录数据到用户提供的缓冲区

---

## 3. High 漏洞 (1)

### [SEC-001] Untrusted Search Path - CWE-426 动态库注入漏洞

**严重性**: High | **CWE**: CWE-426 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `csrc/common/function_loader.cpp:58-74` @ `CanonicalSoPath`
**模块**: common_utils

---

#### 3.1 漏洞概述

Dynamic library loading uses untrusted environment variable ASCEND_HOME_PATH. When ASCEND_HOME_PATH is not set or empty, the library name is passed directly to dlopen() which searches system default paths (LD_LIBRARY_PATH, /etc/ld.so.cache, default paths). An attacker who can control LD_LIBRARY_PATH or place malicious libraries in system paths could inject arbitrary code into the profiling tool.

**漏洞代码** (`csrc/common/function_loader.cpp:58-74`)

```cpp
char *ascendHomePath = std::getenv("ASCEND_HOME_PATH");
if (ascendHomePath == nullptr || ascendHomePath[0] == '\0') {
    return soName_;  // Falls back to system library search path
}
auto soPath = std::string(ascendHomePath) + "/lib64/" + soName_;
```

---

#### 3.2 深度技术分析

**漏洞原理**

msPTI 通过动态加载机制 (dlopen) 加载外部依赖库，包括 libascendcl.so (昇腾计算库)、libhccl.so (集合通信库)、libprofapi.so (性能分析 API) 等核心组件。

漏洞存在于 `CanonicalSoPath()` 函数的路径解析逻辑中。当 `ASCEND_HOME_PATH` 环境变量未设置或为空时，函数直接返回原始库名 (如 `"libascendcl.so"`)，后续 `dlopen()` 将依赖系统默认的动态库搜索机制。

**dlopen 搜索顺序** (当路径不含 `/` 时):

1. RPATH/RUNPATH (编译时嵌入，如果存在)
2. **LD_LIBRARY_PATH** 环境变量指定的路径
3. /etc/ld.so.cache 缓存文件
4. 默认路径: /lib、/usr/lib 等

攻击者可通过控制 `LD_LIBRARY_PATH` 来劫持库加载路径。

**调用链分析**

```
用户调用 msptiSubscribe() 或其他 API
    ↓
acl_inject.cpp: LoadAclFunction() [pthread_once 初始化]
    ↓
RegisterFunction("libascendcl", "aclrtSetDevice")
    ↓
FunctionRegister::GetInstance()->Get(soName, funcName)
    ↓
FunctionLoader::Get(funcName)  [首次调用时加载库]
    ↓
CanonicalSoPath()  [路径解析]
    ↓
dlopen(soPath.c_str(), RTLD_LAZY)  [第74行：动态加载]
```

触发时机：任何使用 msPTI 性能分析功能的应用程序首次调用昇腾 API 时。

**安全缓解措施评估**

| 缓解措施 | 有效性 | 限制 |
|----------|--------|------|
| 库名白名单 | 有效 | 仅防止加载非预期库名，不防路径劫持 |
| realpath() 规范化 | 部分有效 | 仅在 ASCEND_HOME_PATH 设置时生效 |
| FileExist/FileReadable 检查 | 部分有效 | 仅在 ASCEND_HOME_PATH 设置时生效 |
| 未设置时的回退逻辑 | **无效** | 直接返回库名，依赖不可信的搜索路径 |

---

#### 3.3 利用路径分析

**攻击场景 A: ASCEND_HOME_PATH 路径注入**

前提条件:
- 攻击者可控制进程环境变量 (如通过 shell 配置、容器环境、SSH 配置等)
- 攻击者可在控制的目录下创建恶意库文件

攻击步骤:
1. 准备恶意动态库: 编译包含恶意代码的 `libascendcl.so`
2. 设置环境变量: `ASCEND_HOME_PATH=/tmp/malicious`
3. 放置恶意库: `/tmp/malicious/lib64/libascendcl.so`
4. 诱导受害者使用 msPTI 性能分析功能
5. 恶意库被加载，恶意代码执行

**攻击场景 B: LD_LIBRARY_PATH 劫持** (更危险)

前提条件:
- `ASCEND_HOME_PATH` 未设置 (默认安装场景)
- 攻击者可控制 `LD_LIBRARY_PATH` 或可在系统默认搜索路径下放置文件

攻击步骤:
1. 准备恶意动态库: 编译包含恶意代码的 `libascendcl.so`
2. 设置环境变量: `LD_LIBRARY_PATH=/tmp/malicious`
3. 放置恶意库: `/tmp/malicious/libascendcl.so`
4. 确保 ASCEND_HOME_PATH 未设置 (或设为空)
5. 诱导受害者运行使用 msPTI 的应用程序
6. `dlopen("libascendcl.so")` 在 LD_LIBRARY_PATH 路径中找到恶意库
7. 恶意库被加载，恶意代码以受害者权限执行

**优势**: 此场景绕过了 `realpath()` 和 `FileExist()` 检查，因为这些检查仅在 `ASCEND_HOME_PATH` 设置时执行。

---

#### 3.4 影响评估

**直接影响**

| 影响维度 | 评估 |
|----------|------|
| 代码执行 | **完全控制** - 恶意库代码以受害者进程权限执行 |
| 权限提升 | **可能** - 若受害者有特权 (如 root 或设备管理权限) |
| 数据窃取 | **高风险** - 可访问 NPU 设备数据、用户模型、性能数据 |
| 持久化 | **中风险** - 通过植入系统路径可实现持久化 |

**受影响组件**

- `libascendcl.so`: 昇腾计算库 (ACL)，核心运行时库
- `libhccl.so`: 集合通信库 (HCCL)，分布式训练关键组件
- `libprofapi.so`: 性能分析 API 库
- `libascend_hal.so`: 硬件抽象层库
- `libascendalog.so`: 日志库

**受影响场景**

1. **AI 模型训练/推理**: 使用 msPTI 进行性能分析的训练或推理任务
2. **分布式训练**: HCCL 库劫持可影响整个分布式训练集群
3. **DevOps 环境**: CI/CD 流水线中使用性能分析的场景
4. **容器化部署**: 容器环境变量可控性更高，攻击更易实施
5. **共享服务器**: 多用户服务器上用户间相互影响

---

#### 3.5 评分明细

**置信度**: 85/100

| 评分维度 | 分数 | 说明 |
|----------|------|------|
| base | 30 | CWE-426 标准基础分 |
| reachability | 30 | 从 API 入口点可直接到达漏洞点 |
| controllability | 25 | 环境变量完全可控，攻击成本低 |
| mitigations | 0 | 白名单仅限制库名，不防路径劫持 |
| context | 0 | 无额外上下文加分 |
| cross_file | 0 | 漏洞位于单文件内 |

---

#### 3.6 详细分析报告

完整的深度利用分析报告请参阅: `details/SEC-001.md`

---

## 4. 修复建议

### 4.1 紧急修复措施 (高优先级)

#### 修复方案 1: 强制路径安全验证

**修改位置**: `csrc/common/function_loader.cpp:58-74`

```cpp
std::string FunctionLoader::CanonicalSoPath()
{
    // ... 白名单检查保持不变 ...
    
    char *ascendHomePath = std::getenv("ASCEND_HOME_PATH");
    if (ascendHomePath == nullptr || ascendHomePath[0] == '\0') {
        // 修复：不回退到系统搜索路径，使用安全默认值或报错
        // 方案 A：使用编译时确定的固定路径
        static const std::string DEFAULT_ASCEND_PATH = "/usr/local/Ascend";
        auto soPath = DEFAULT_ASCEND_PATH + "/lib64/" + soName_;
        auto canonicalPath = Utils::RealPath(Utils::RelativeToAbsPath(soPath));
        
        if (!Utils::FileExist(canonicalPath)) {
            MSPTI_LOGE("ASCEND_HOME_PATH not set and default path invalid: %s", 
                       canonicalPath.c_str());
            return "";  // 拒绝加载
        }
        return canonicalPath;
        
        // 方案 B：直接报错拒绝加载 (更严格)
        // MSPTI_LOGE("ASCEND_HOME_PATH must be set for secure library loading.");
        // return "";
    }
    
    // ... 原有逻辑保持不变 ...
}
```

#### 修复方案 2: 环境变量白名单验证

```cpp
// 添加对 ASCEND_HOME_PATH 路径的安全检查
static const std::set<std::string> ALLOWED_PATH_PREFIXES = {
    "/usr/local/Ascend",
    "/opt/Ascend",
    "/usr/lib/Ascend",
    // 可根据实际部署环境扩展
};

bool IsPathAllowed(const std::string& path) {
    // 检查路径是否在允许的前缀列表中
    for (const auto& prefix : ALLOWED_PATH_PREFIXES) {
        if (path.find(prefix) == 0) {
            return true;
        }
    }
    return false;
}

// 在 CanonicalSoPath 中使用
if (!IsPathAllowed(std::string(ascendHomePath))) {
    MSPTI_LOGE("ASCEND_HOME_PATH '%s' not in allowed paths.", ascendHomePath);
    return "";
}
```

---

### 4.2 中期加固措施

#### 加固措施 1: 编译时 RUNPATH/RPATH 设置

在 CMakeLists.txt 或编译脚本中设置安全的库搜索路径:

```cmake
# CMakeLists.txt
set_target_properties(mspti PROPERTIES
    INSTALL_RPATH "/usr/local/Ascend/lib64:/opt/Ascend/lib64"
    BUILD_WITH_INSTALL_RPATH TRUE
)
```

这使库加载优先使用编译时确定的安全路径，而非环境变量控制的路径。

#### 加固措施 2: 库完整性验证

加载前验证库文件签名或哈希值:

```cpp
bool VerifyLibraryIntegrity(const std::string& path, const std::string& expectedHash) {
    // 1. 计算文件 SHA256 哈希
    std::string actualHash = ComputeFileHash(path);
    
    // 2. 比对预存的哈希值 (可存储在配置文件或编译时嵌入)
    if (actualHash != expectedHash) {
        MSPTI_LOGE("Library integrity check failed: %s", path.c_str());
        return false;
    }
    return true;
}
```

---

### 4.3 长期安全改进

#### 改进 1: 使用安全加载 API

- 考虑使用 `secure_getenv()` 替代 `getenv()` (在特权进程中，它会忽略 LD_LIBRARY_PATH 等危险环境变量)
- 实现自定义的安全加载函数，增加路径验证和完整性检查

#### 改进 2: 审计日志

记录所有库加载事件，便于安全审计和异常检测:

```cpp
void LogLibraryLoad(const std::string& soPath, const std::string& envValue) {
    MSPTI_LOGI("Loading library: %s from path: %s (ASCEND_HOME_PATH=%s)",
               soName_.c_str(), soPath.c_str(), 
               envValue.empty() ? "unset" : envValue.c_str());
}
```

#### 改进 3: 安全配置指南

- 文档中明确要求必须设置 ASCEND_HOME_PATH
- 提供安全配置检查脚本，验证环境变量设置是否符合安全要求
- 在安装脚本中强制设置正确的 ASCEND_HOME_PATH

---

### 4.4 修复优先级建议

| 优先级 | 措施 | 预计工作量 | 安全收益 |
|--------|------|------------|----------|
| **P0 紧急** | 强制路径安全验证 | 1-2 小时 | 完全阻止 LD_LIBRARY_PATH 劫持 |
| **P0 紧急** | 环境变量白名单验证 | 1-2 小时 | 阻止非预期路径注入 |
| **P1 高** | 编译时 RUNPATH 设置 | 30 分钟 | 增加一层防护 |
| **P2 中** | 库完整性验证 | 4-8 小时 | 防止库文件篡改 |
| **P3 低** | 审计日志 | 2-4 小时 | 便于安全审计 |

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| common_utils | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **1** | **0** | **0** | **1** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-426 | 1 | 100.0% |

---

## 附录

### A. CWE 参考链接

- [CWE-426: Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)
- [CWE-427: Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html)
- [CWE-114: Process Control](https://cwe.mitre.org/data/definitions/114.html)

### B. 相关技术参考

- [dlopen(3) - Linux man page](https://man7.org/linux/man-pages/man3/dlopen.3.html)
- [LD_LIBRARY_PATH security considerations](https://access.redhat.com/blogs/766563/posts/1976223)
- [RPATH/RUNPATH best practices](https://cmake.org/cmake/help/latest/prop_tgt/INSTALL_RPATH.html)

---

**报告生成时间**: 2026-04-20
**扫描工具**: Multi-Agent C/C++ Vulnerability Scanner
**分析者**: Security Auditor + Details Analyzer