# 漏洞扫描报告 — 已确认漏洞

**项目**: HCCL
**扫描时间**: 2026-04-22T05:31:49.717Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

### 项目概述

HCCL (Huawei Collective Communication Library) 是华为昇腾AI处理器集群的高性能集合通信库。该库为分布式AI训练和推理场景提供集合通信（如 AllReduce、AllGather、Broadcast 等）和点对点通信（Send/Recv）能力。HCCL 作为 CANN (Compute Architecture for Neural Networks) 软件栈的核心组件，支撑大规模模型训练的多卡协同计算。

项目采用分层架构设计：上层为公共 API 接口层，提供标准化的通信算子接口；中间为算子实现层，包含各类集合通信算子的具体实现；底层为通信执行层，通过动态库加载机制调用底层通信引擎（libhcomm.so）。项目支持多种执行模式（AICPU、AIV、CCU 等），通过环境变量灵活配置运行参数。

### 关键发现

本次扫描共识别出 **5 个已确认（CONFIRMED）漏洞**，全部为 **High 严重性**，均属于同一漏洞类型：

**CWE-426: Untrusted Search Path（不受信任的搜索路径）**

核心问题集中在两个关键安全风险点：

1. **动态库注入风险（2 个漏洞）**：`dlopen` 使用相对路径加载 `libhcomm.so`，完全依赖系统库搜索路径（LD_LIBRARY_PATH 等）。攻击者可通过环境变量劫持或同名恶意库放置实现任意代码执行。

2. **Kernel Binary 加载路径劫持风险（3 个漏洞）**：`ASCEND_HOME_PATH` 环境变量直接控制 AIV/AICPU kernel 二进制文件的加载路径，无任何路径校验或规范化。恶意路径设置可导致篡改的 kernel 代码被加载执行。

### 风险评估

| 维度 | 评估 | 说明 |
|------|------|------|
| **攻击复杂度** | 低 | 攻击者仅需设置环境变量或放置同名文件，无需复杂技术手段 |
| **攻击面广度** | 中 | 环境变量控制点是标准 Linux 攻击向量，但需具备系统访问权限 |
| **影响范围** | 高 | 漏洞涉及核心通信库初始化和 kernel 执行，影响所有使用 HCCL 的 AI 应用 |
| **代码执行能力** | 高 | 攻击成功后可实现完全的代码执行控制 |
| **可信边界突破** | 高 | 恶意代码可在 kernel 执行层面运行，绕过应用层安全检查 |

**综合风险等级：HIGH**

这些漏洞在以下攻击场景中具有实际威胁：

- **容器环境**：容器部署时环境变量通常通过外部配置注入，攻击者可篡改配置
- **共享服务器**：多用户共享环境下，恶意用户可放置同名库文件于公共目录
- **CI/CD 管道**：构建脚本中恶意配置可注入环境变量
- **供应链攻击**：第三方部署工具或脚本可包含恶意环境变量设置

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 11 | 45.8% |
| FALSE_POSITIVE | 7 | 29.2% |
| CONFIRMED | 5 | 20.8% |
| LIKELY | 1 | 4.2% |
| **总计** | **24** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 5 | 100.0% |
| **有效漏洞总计** | **5** | - |
| 误报 (FALSE_POSITIVE) | 7 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-DL-002]** untrusted_search_path (High) - `src/ops/op_common/dlhcomm_function.cc:49` @ `unknown` | 置信度: 85
2. **[VULN-SEC-BIN-001]** untrusted_search_path (High) - `src/ops/op_common/template/aiv/hccl_aiv_utils.cc:140` @ `GetAivOpBinaryPath` | 置信度: 85
3. **[VULN-SEC-BIN-002]** untrusted_search_path (High) - `src/ops/op_common/template/aicpu/load_kernel.cc:19` @ `GetKernelFilePath` | 置信度: 85
4. **[VULN-DF-007]** untrusted_search_path (High) - `src/common/hcomm_dlsym/hcomm_dlsym.cc:60` @ `HcommDlInit` | 置信度: 85
5. **[VULN-DF-008]** untrusted_search_path (High) - `src/ops/op_common/template/aiv/hccl_aiv_utils.cc:145` @ `GetAivOpBinaryPath` | 置信度: 85

---

## 2. Top 5 漏洞深度分析

### 漏洞 1: VULN-SEC-DL-002 & VULN-DF-007 — 动态库注入攻击

**影响模块**: `dlhcomm_function`, `hcomm_dlsym`

#### 漏洞根源分析

HCCL 采用动态库加载机制实现通信引擎的解耦设计。核心通信能力由 `libhcomm.so` 库提供，HCCL 通过 `dlopen/dlsym` 动态加载该库并获取函数符号。

问题代码位于两个入口点：

```cpp
// hcomm_dlsym.cc:60 — 主初始化入口
gLibHandle = dlopen("libhcomm.so", RTLD_NOW);

// dlhcomm_function.cc:49 — 单例初始化入口  
void* h = dlopen("libhcomm.so", RTLD_NOW);
```

#### 攻击路径分析

`dlopen` 使用相对路径时，系统按以下顺序搜索库文件：

1. `LD_LIBRARY_PATH` 环境变量指定的路径
2. `/etc/ld.so.cache` 中缓存的路径
3. 默认系统路径 `/lib`, `/usr/lib`

攻击者可通过以下方式注入恶意库：

**攻击方式 A: 环境变量劫持**
```
export LD_LIBRARY_PATH=/malicious/path:$LD_LIBRARY_PATH
# 在 /malicious/path 中放置恶意 libhcomm.so
```

**攻击方式 B: 文件放置攻击**
```
# 在系统默认搜索路径之一放置同名库
cp malicious.so /usr/lib/libhcomm.so
```

#### 影响链分析

初始化流程受影响：
```
HcommDlInit()
  -> dlopen("libhcomm.so")  // 加载恶意库
    -> HcclResDlInit(gLibHandle)
    -> HcclRankGraphDlInit(gLibHandle)
    -> HcommPrimitivesDlInit(gLibHandle)
    -> ...  // 所有符号从恶意库获取
```

恶意库可在 `HcclResDlInit` 等函数中注入任意代码，完全控制 HCCL 的通信行为。

#### 上下文补充

查看完整初始化代码，`HcommDlInit` 被调用时机为 HCCL 库首次使用时：

```cpp
// hcomm_dlsym.cc 完整流程
void HcommDlInit(void) {
    if (gLibHandle != nullptr) return;  // 单次初始化
    
    gLibHandle = dlopen("libhcomm.so", RTLD_NOW);  // 问题点
    if (!gLibHandle) {
        fprintf(stderr, "[HcclWrapper] Failed to open libhcomm: %s\n", dlerror());
        return;
    }
    
    // 从加载的库中获取所有通信函数符号
    HcclResDlInit(gLibHandle);
    HcclRankGraphDlInit(gLibHandle);
    HcommPrimitivesDlInit(gLibHandle);
    HcclInnerDlInit(gLibHandle);
    HcommProfilingDlInit(gLibHandle);
    HcclCommDlInit(gLibHandle);
}
```

`dlhcomm_function.cc` 提供了另一处加载入口，采用单例模式：

```cpp
DlHcommFunction &DlHcommFunction::GetInstance() {
    static DlHcommFunction hcclDlHcommFunction;
    (void)hcclDlHcommFunction.DlHcommFunctionInit();
    return hcclDlHcommFunction;
}

HcclResult DlHcommFunction::DlHcommFunctionInit() {
    std::lock_guard<std::mutex> lock(handleMutex_);
    if (handle_ != nullptr) return HCCL_SUCCESS;
    
    void* h = dlopen("libhcomm.so", RTLD_NOW);  // 问题点
    CHK_PRT_RET(h == nullptr, HCCL_WARNING("dlopen libhcomm.so failed, error: %s", dlerror()), HCCL_E_PTR);
    handle_ = h;
    CHK_RET(DlHcommFunctionInterInit());
    return HCCL_SUCCESS;
}
```

---

### 漏洞 2: VULN-SEC-BIN-001 & VULN-DF-008 — AIV Kernel Binary 加载路径劫持

**影响模块**: `aiv_utils`, `op_common_template`

#### 漏洞根源分析

AIV (AI Vector) 模式是 HCCL 的高性能执行模式之一，需要加载预编译的 kernel binary 文件在向量引擎上执行。`GetAivOpBinaryPath` 函数负责获取这些 binary 文件的路径。

问题代码：

```cpp
// hccl_aiv_utils.cc:140-158
HcclResult GetAivOpBinaryPath(const std::string &aivBinaryName, std::string &binaryPath) {
    std::string libPath;
    char *getPath = nullptr;
    MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, getPath);  // 从环境变量获取路径
    
    if (getPath != nullptr) {
        libPath = getPath;  // 直接使用，无校验
    } else {
        libPath = "/usr/local/Ascend/cann";  // 默认路径
        HCCL_WARNING("[GetAivOpBinaryPath]ENV:ASCEND_HOME_PATH is not set");
    }
    
    binaryPath = libPath + "/lib64";  // 拼接子目录
    binaryPath += "/" + aivBinaryName;  // 拼接文件名
    HCCL_INFO("[GetAivOpBinaryPath]op binary file path[%s]", binaryPath.c_str());
    return HCCL_SUCCESS;
}
```

#### 攻击路径分析

攻击者设置恶意 `ASCEND_HOME_PATH`：

```
export ASCEND_HOME_PATH=/malicious/cann
# 在 /malicious/cann/lib64/ 中放置篡改的 kernel binary
```

加载流程：

```
RegisterKernel()
  -> GetAivOpBinaryPath("hccl_aiv_all_reduce.bin", binFilePath)
    -> 返回 "/malicious/cann/lib64/hccl_aiv_all_reduce.bin"
  -> LoadBinaryFromFile(binFilePath.c_str(), ...)
    -> 加载恶意 kernel binary 到设备
  -> aclrtBinaryGetFunction(g_binHandle, kernelName, &funcHandle)
    -> 从恶意 binary 获取 kernel 函数
  -> aclrtLaunchKernelWithHostArgs(funcHandle, ...)
    -> 在设备上执行恶意 kernel 代码
```

#### 安全影响

AIV kernel 在昇腾处理器的向量引擎上执行，具备：
- 直接访问设备内存
- 执行高吞吐计算操作
- 与其他 kernel 协同工作

恶意 kernel 可实现：
- 破坏其他进程的计算结果
- 泄露敏感数据（模型参数、训练数据）
- 修改通信数据流
- 导致设备状态异常

#### 上下文补充

查看完整的 kernel 注册流程：

```cpp
// hccl_aiv_utils.cc:194-227
HcclResult RegisterKernel() {
    lock_guard<mutex> guard(g_mut);
    if (g_init) return HCCL_SUCCESS;  // 全局单次初始化
    
    for (const auto& item : g_aivKernelInfoMap) {
        const HcclCMDType cmdType = item.first;
        const std::string& aivBinaryName = item.second.first;  // 如 "hccl_aiv_all_reduce.bin"
        const std::vector<AivKernelInfo>& aivKernelInfoList = item.second.second;
        
        HcclResult ret;
        string binFilePath;
        ret = GetAivOpBinaryPath(aivBinaryName, binFilePath);  // 问题入口
        
        ret = LoadBinaryFromFile(binFilePath.c_str(), ACL_RT_BINARY_LOAD_OPT_LAZY_LOAD, 1, g_binHandle);
        // 加载恶意 binary
        
        for (auto &aivKernelInfo: aivKernelInfoList) {
            ret = RegisterBinaryKernel(aivKernelInfo.kernelName, g_binHandle, ...);
            // 注册恶意 kernel 函数
        }
    }
    
    g_init = true;
    return HCCL_SUCCESS;
}
```

Kernel 执行入口：

```cpp
// hccl_aiv_utils.cc:243-290
HcclResult ExecuteKernelLaunchInner(const AivOpArgs &opArgs, void* args, u32 argsSize) {
    // ... 配置 kernel 属性 ...
    
    aclrtLaunchKernelWithHostArgs(funcHandle, opArgs.numBlocks, opArgs.stream,
        &cfg, args, argsSize, nullptr, 0);  // 执行恶意 kernel
    
    return HCCL_SUCCESS;
}
```

---

### 漏洞 3: VULN-SEC-BIN-002 — AICPU Kernel 文件路径劫持

**影响模块**: `load_kernel`

#### 漏洞根源分析

AICPU 模式是另一种执行模式，使用 AI CPU 处理通信任务。`GetKernelFilePath` 函数获取 AICPU kernel 配置文件路径。

问题代码：

```cpp
// load_kernel.cc:19-36
HcclResult GetKernelFilePath(std::string &binaryPath) {
    std::string libPath;
    char *getPath = getenv("ASCEND_HOME_PATH");  // 直接使用 getenv
    MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, getPath);  // 再次获取
    
    if (getPath != nullptr) {
        libPath = getPath;  // 直接使用
    } else {
        libPath = "/usr/local/Ascend/cann/";
        HCCL_WARNING("[GetKernelFilePath]ENV:ASCEND_HOME_PATH is not set");
    }
    
    libPath += "/opp/built-in/op_impl/aicpu/config/";
    binaryPath = libPath;
    HCCL_DEBUG("[GetKernelFilePath]kernel folder path[%s]", binaryPath.c_str());
    
    return HCCL_SUCCESS;
}
```

#### 攻击路径分析

与 AIV 模式类似，攻击者设置恶意路径后：

```
LoadAICPUKernel()
  -> GetKernelFilePath(jsonPath)
    -> 返回 "/malicious/cann/opp/built-in/op_impl/aicpu/config/"
  -> jsonPath += "libscatter_aicpu_kernel.json"
  -> LoadBinaryFromFile(jsonPath.c_str(), ACL_RT_BINARY_LOAD_OPT_CPU_KERNEL_MODE, ...)
    -> 加载恶意配置和 kernel
```

#### 上下文补充

查看完整加载流程：

```cpp
// load_kernel.cc:40-55
HcclResult LoadAICPUKernel(void) {
    if (g_binKernelHandle != nullptr) return HCCL_SUCCESS;
    
    std::string jsonPath;
    CHK_RET(GetKernelFilePath(jsonPath));  // 问题入口
    jsonPath += "libscatter_aicpu_kernel.json";  // JSON 配置文件
    
    HcclResult ret = LoadBinaryFromFile(jsonPath.c_str(), 
        ACL_RT_BINARY_LOAD_OPT_CPU_KERNEL_MODE, 0, g_binKernelHandle);
    // 加载恶意 kernel
    
    return HCCL_SUCCESS;
}
```

---

### 漏洞共性分析

三个漏洞组具有相同的根源：**对环境变量的信任未加验证**

| 漏洞组 | 受信任源 | 加载目标 | 攻击入口 |
|--------|----------|----------|----------|
| DL-002/DF-007 | LD_LIBRARY_PATH | libhcomm.so | dlopen 相对路径 |
| BIN-001/DF-008 | ASCEND_HOME_PATH | AIV kernel binary | 路径拼接无校验 |
| BIN-002 | ASCEND_HOME_PATH | AICPU kernel config | 路径拼接无校验 |

根本缺陷：
- 环境变量被视为可信配置源，但实际上可被多种攻击手段篡改
- 路径拼接前无规范化处理，未检测路径穿越或绝对路径覆盖
- 加载前无文件完整性校验（如签名验证、哈希校验）

---

## 3. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `HcclAllReduce@include/hccl.h` | public_api | high | API 入口触发库初始化 | 首次调用触发 HcommDlInit |
| `HcclAllGatherV@include/hccl.h` | public_api | high | 变长参数处理入口 | 复杂参数处理逻辑 |
| `HcclAlltoAllV@include/hccl.h` | public_api | high | 多数组参数入口 | 多个数组参数处理 |
| `HcclSend@include/hccl.h` | public_api | high | 点对点通信入口 | 跨 Rank 数据传输 |
| `HcclRecv@include/hccl.h` | public_api | high | 点对点接收入口 | 数据接收处理 |
| `HcclBatchSendRecv@include/hccl.h` | public_api | high | 批量通信入口 | 数组结构参数 |
| `HcclLaunchAicpuKernel@kernel_launch.cc` | internal_api | high | Kernel 执行入口 | AICPU kernel 执行 |
| `InitEnvConfig@alg_env_config.cc` | internal_api | medium | 环境变量解析 | 配置初始化 |
| `HcommDlInit@hcomm_dlsym.cc` | internal_api | high | 动态库初始化 | libhcomm.so 加载 |


---

## 4. High 漏洞 (5)

### [VULN-SEC-DL-002] untrusted_search_path - unknown

**严重性**: High | **CWE**: CWE-426 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/ops/op_common/dlhcomm_function.cc:49-50` @ `unknown`
**模块**: dlhcomm_function

**描述**: 动态库加载使用相对路径，同样存在库注入风险。与VULN-SEC-DL-001相同的安全问题，位于另一处调用点。

**漏洞代码** (`src/ops/op_common/dlhcomm_function.cc:49-50`)

```c
void* h = dlopen("libhcomm.so", RTLD_NOW);
CHK_PRT_RET(h == nullptr, HCCL_WARNING("dlopen libhcomm.so failed, error: %s", dlerror()), HCCL_E_PTR);
```

**达成路径**

用户设置 LD_LIBRARY_PATH -> dlopen 搜索路径 -> 加载恶意 libhcomm.so

**验证说明**: 确认使用dlopen相对路径加载libhcomm.so，依赖LD_LIBRARY_PATH环境变量，攻击者可设置恶意路径实现库注入。直接外部输入+完全可控。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-BIN-001] untrusted_search_path - GetAivOpBinaryPath

**严重性**: High | **CWE**: CWE-426 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/ops/op_common/template/aiv/hccl_aiv_utils.cc:140-158` @ `GetAivOpBinaryPath`
**模块**: aiv_utils

**描述**: ASCEND_HOME_PATH环境变量控制AIV kernel二进制文件加载路径，环境变量值直接拼接成路径，无路径规范化或校验。攻击者可设置恶意路径加载篡改的二进制文件，导致代码执行。

**漏洞代码** (`src/ops/op_common/template/aiv/hccl_aiv_utils.cc:140-158`)

```c
MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, getPath);
if (getPath != nullptr) {
    libPath = getPath;
} else {
    libPath = "/usr/local/Ascend/cann";
}
binaryPath = libPath + "/lib64";
binaryPath += "/" + aivBinaryName;
```

**达成路径**

ASCEND_HOME_PATH 环境变量 -> getPath -> libPath -> binaryPath -> LoadBinaryFromFile -> aclrtLaunchKernelWithHostArgs

**验证说明**: 确认ASCEND_HOME_PATH环境变量直接拼接路径加载AIV kernel binary，无路径规范化校验，攻击者可设置恶意路径加载篡改的二进制文件。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-BIN-002] untrusted_search_path - GetKernelFilePath

**严重性**: High | **CWE**: CWE-426 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `src/ops/op_common/template/aicpu/load_kernel.cc:19-36` @ `GetKernelFilePath`
**模块**: load_kernel

**描述**: ASCEND_HOME_PATH环境变量控制AICPU kernel文件加载路径，同样缺少路径校验。虽然static_restore.cc有完善的安全校验，但此处的load_kernel.cc直接使用getenv结果拼接路径。

**漏洞代码** (`src/ops/op_common/template/aicpu/load_kernel.cc:19-36`)

```c
char *getPath = getenv("ASCEND_HOME_PATH");
MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, getPath);
if (getPath != nullptr) {
    libPath = getPath;
} else {
    libPath = "/usr/local/Ascend/cann/";
}
libPath += "/opp/built-in/op_impl/aicpu/config/";
```

**达成路径**

ASCEND_HOME_PATH -> getPath -> libPath -> binaryPath -> LoadBinaryFromFile

**验证说明**: 确认getenv(ASCEND_HOME_PATH)直接用于拼接AICPU kernel文件路径，无路径校验，存在二进制文件注入风险。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-007] untrusted_search_path - HcommDlInit

**严重性**: High | **CWE**: CWE-426 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner, security-auditor

**位置**: `src/common/hcomm_dlsym/hcomm_dlsym.cc:60-64` @ `HcommDlInit`
**模块**: hcomm_dlsym

**描述**: HcommDlInit使用相对路径dlopen加载libhcomm.so，依赖系统库搜索路径(LD_LIBRARY_PATH等)。恶意用户可通过设置环境变量或放置同名恶意库实现库注入。

**漏洞代码** (`src/common/hcomm_dlsym/hcomm_dlsym.cc:60-64`)

```c
gLibHandle = dlopen("libhcomm.so", RTLD_NOW);
if (!gLibHandle) {
    fprintf(stderr, "[HcclWrapper] Failed to open libhcomm: %s\n", dlerror());
    return;
}
```

**达成路径**

HcommDlInit -> dlopen("libhcomm.so") -> 系统库搜索路径

**验证说明**: 确认HcommDlInit使用dlopen("libhcomm.so", RTLD_NOW)相对路径加载库，依赖系统搜索路径(LD_LIBRARY_PATH等)，攻击者可通过设置环境变量实现库注入。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-008] untrusted_search_path - GetAivOpBinaryPath

**严重性**: High | **CWE**: CWE-426 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `src/ops/op_common/template/aiv/hccl_aiv_utils.cc:145-156` @ `GetAivOpBinaryPath`
**模块**: op_common_template

**描述**: GetAivOpBinaryPath从ASCEND_HOME_PATH环境变量获取路径加载kernel binary。环境变量可被外部设置，恶意路径可能导致加载篡改的kernel代码。

**漏洞代码** (`src/ops/op_common/template/aiv/hccl_aiv_utils.cc:145-156`)

```c
MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, getPath);
if (getPath != nullptr) {
    libPath = getPath;
} else {
    libPath = "/usr/local/Ascend/cann";
}
binaryPath = libPath + "/lib64" + "/" + aivBinaryName;
```

**达成路径**

ASCEND_HOME_PATH环境变量 -> GetAivOpBinaryPath -> LoadBinaryFromFile -> aclrtLaunchKernelWithHostArgs

**验证说明**: 确认ASCEND_HOME_PATH环境变量控制AIV kernel binary加载路径，直接拼接无校验，攻击者可设置恶意路径加载篡改的kernel代码实现代码执行。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| aiv_utils | 0 | 1 | 0 | 0 | 1 |
| dlhcomm_function | 0 | 1 | 0 | 0 | 1 |
| hcomm_dlsym | 0 | 1 | 0 | 0 | 1 |
| load_kernel | 0 | 1 | 0 | 0 | 1 |
| op_common_template | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **5** | **0** | **0** | **5** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-426 | 5 | 100.0% |

---

## 7. 修复建议

### 7.1 动态库加载安全修复 (VULN-SEC-DL-002, VULN-DF-007)

**问题**: `dlopen` 使用相对路径加载 `libhcomm.so`

**推荐修复方案**:

#### 方案 A: 使用绝对路径

```cpp
// 修复代码示例
HcclResult GetHcommLibraryPath(std::string &libPath) {
    // 优先从编译时确定的安装路径获取
    libPath = HCCL_INSTALL_PREFIX "/lib/libhcomm.so";
    
    // 验证文件存在且为预期文件
    struct stat st;
    if (stat(libPath.c_str(), &st) != 0) {
        HCCL_ERROR("libhcomm.so not found at expected path: %s", libPath.c_str());
        return HCCL_E_NOT_FOUND;
    }
    
    // 可选: 校验文件签名或哈希
    // if (!VerifyFileSignature(libPath)) { ... }
    
    return HCCL_SUCCESS;
}

// 修复后的加载代码
void HcommDlInit(void) {
    if (gLibHandle != nullptr) return;
    
    std::string libPath;
    if (GetHcommLibraryPath(libPath) != HCCL_SUCCESS) {
        return;
    }
    
    gLibHandle = dlopen(libPath.c_str(), RTLD_NOW);
    if (!gLibHandle) {
        fprintf(stderr, "[HcclWrapper] Failed to open libhcomm: %s\n", dlerror());
        return;
    }
    // ... 后续初始化
}
```

#### 方案 B: 禁用 LD_LIBRARY_PATH 搜索

```cpp
// 使用 dlmopen 或指定 RTLD_DEEPBIND 防止环境变量影响
gLibHandle = dlopen(libPath.c_str(), RTLD_NOW | RTLD_DEEPBIND);

// 或使用 secure_getenv 替代 getenv (glibc 扩展)
// secure_getenv 在 AT_SECURE=1 (setuid/setgid) 时返回 NULL
```

#### 方案 C: 环境变量白名单校验

```cpp
// 仅允许特定格式和位置的 ASCEND_HOME_PATH
bool ValidateInstallPath(const char* path) {
    // 校验路径格式: 必须以 /usr/local/Ascend 或 /opt/Ascend 开头
    if (!path) return false;
    
    std::string p(path);
    // 防止路径穿越
    if (p.find("..") != std::string::npos) return false;
    
    // 校验在允许的安装目录范围内
    std::vector<std::string> allowedPrefixes = {
        "/usr/local/Ascend",
        "/opt/Ascend",
        "/home/ascend/install"  // 用户自定义安装路径
    };
    
    for (const auto& prefix : allowedPrefixes) {
        if (p.substr(0, prefix.length()) == prefix) {
            return true;
        }
    }
    return false;
}
```

### 7.2 Kernel Binary 加载路径安全修复 (VULN-SEC-BIN-001, VULN-SEC-BIN-002, VULN-DF-008)

**问题**: `ASCEND_HOME_PATH` 直接控制 kernel binary 加载路径

**推荐修复方案**:

#### 方案 A: 路径白名单 + 规范化

```cpp
#include <limits.h>
#include <stdlib.h>

HcclResult GetSecureBinaryPath(const std::string &binaryName, std::string &binaryPath) {
    char rawPath[PATH_MAX];
    const char* ascendHome = getenv("ASCEND_HOME_PATH");
    
    if (ascendHome == nullptr) {
        // 使用编译时确定的默认路径
        binaryPath = HCCL_DEFAULT_INSTALL_PATH "/lib64/" + binaryName;
    } else {
        // 1. 校验路径格式 (白名单)
        if (!ValidateInstallPath(ascendHome)) {
            HCCL_ERROR("Invalid ASCEND_HOME_PATH: %s", ascendHome);
            return HCCL_E_PARA;
        }
        
        // 2. 规范化路径 (消除 .. 和符号链接)
        if (realpath(ascendHome, rawPath) == nullptr) {
            HCCL_ERROR("Cannot resolve ASCEND_HOME_PATH: %s", ascendHome);
            return HCCL_E_PARA;
        }
        
        // 3. 再次校验规范化后的路径
        if (!ValidateInstallPath(rawPath)) {
            HCCL_ERROR("Resolved path outside allowed range: %s", rawPath);
            return HCCL_E_PARA;
        }
        
        binaryPath = std::string(rawPath) + "/lib64/" + binaryName;
    }
    
    // 4. 校验目标文件存在
    struct stat st;
    if (stat(binaryPath.c_str(), &st) != 0) {
        HCCL_ERROR("Binary not found: %s", binaryPath.c_str());
        return HCCL_E_NOT_FOUND;
    }
    
    return HCCL_SUCCESS;
}
```

#### 方案 B: 文件完整性校验

```cpp
// 加载前校验文件签名或哈希
#include <openssl/sha.h>

bool VerifyBinaryIntegrity(const std::string& filePath) {
    // 从可信来源获取预期哈希
    std::string expectedHash = GetExpectedHashForBinary(filePath);
    
    // 计算实际文件哈希
    std::string actualHash = ComputeFileHash(filePath);
    
    if (expectedHash != actualHash) {
        HCCL_ERROR("Binary integrity check failed for: %s", filePath.c_str());
        return false;
    }
    return true;
}

std::string ComputeFileHash(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&ctx, buffer, file.gcount());
    }
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);
    
    // 转换为 hex string
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}
```

#### 方案 C: 移除环境变量依赖，使用编译时路径

```cpp
// 最安全的方案: 完全不依赖环境变量
HcclResult GetAivOpBinaryPath(const std::string &aivBinaryName, std::string &binaryPath) {
    // 使用编译时宏定义的安装路径
    // 编译时通过 -DHCCL_INSTALL_PREFIX=/usr/local/Ascend/cann 指定
    binaryPath = std::string(HCCL_INSTALL_PREFIX) + "/lib64/" + aivBinaryName;
    
    HCCL_INFO("[GetAivOpBinaryPath] Using fixed path: %s", binaryPath.c_str());
    return HCCL_SUCCESS;
}
```

### 7.3 综合安全加固建议

| 修复项 | 优先级 | 实施难度 | 效果 |
|--------|--------|----------|------|
| 使用绝对路径加载动态库 | **P0** | 低 | 根本解决动态库注入 |
| 路径白名单校验 | **P0** | 中 | 防止恶意路径设置 |
| 路径规范化 (realpath) | **P1** | 低 | 防止路径穿越攻击 |
| 文件完整性校验 | **P2** | 中 | 检测篡改的文件 |
| 移除环境变量依赖 | **P1** | 高 | 最彻底的解决方案 |
| 添加加载失败详细日志 | **P3** | 低 | 便于检测攻击尝试 |

### 7.4 部署环境安全建议

**容器环境**:
- 不要在容器镜像中设置 `LD_LIBRARY_PATH` 或 `ASCEND_HOME_PATH`
- 使用只读挂载确保库文件和 kernel binary 不可被篡改
- 限制容器内进程的环境变量修改能力

**共享服务器**:
- 对关键库文件和 kernel binary 设置严格权限 (root:root, 0644)
- 监控库文件的修改事件
- 使用文件完整性监控工具 (如 AIDE, Tripwire)

**CI/CD 管道**:
- 在构建脚本中硬编码安装路径
- 验证所有外部注入的环境变量
- 使用可信的库文件来源

---

## 8. 附录

### 8.1 CWE-426 参考资料

- [CWE-426: Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)
- [MITRE ATT&CK: T1574.006 - Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006/)
- [Secure Coding in C and C++ - Chapter 2: String Vulnerabilities](https://www.cert.org/books/secure-coding/)

### 8.2 Linux 动态库搜索机制

`dlopen` 相对路径搜索顺序：
1. `LD_LIBRARY_PATH` 环境变量
2. `/etc/ld.so.cache` 缓存
3. `/lib`, `/usr/lib` 默认路径
4. `/lib64`, `/usr/lib64` (64位系统)

攻击防护机制：
- `secure_getenv`: 在 setuid/setgid 进程中返回 NULL
- `RTLD_DEEPBIND`: 优先使用库自身的符号，减少全局影响
- 文件权限: 库文件应设置为 root:root 0644

### 8.3 扫描配置

```json
{
  "scanner_version": "v1.0",
  "scan_date": "2026-04-22T05:31:49.717Z",
  "agents": ["dataflow-scanner", "security-auditor"],
  "confidence_threshold": 40,
  "language": "C++"
}
```