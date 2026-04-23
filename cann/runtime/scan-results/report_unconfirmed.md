# 漏洞扫描报告 — 待确认漏洞

**项目**: CANN Runtime
**扫描时间**: 2026-04-23T02:23:49.669Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要 (Executive Summary)

本次安全扫描对 CANN Runtime 代码库进行了全面的静态分析，发现了 **41 个有效漏洞候选**，其中 **11 个为 LIKELY 状态**（置信度较高，建议优先处理），**30 个为 POSSIBLE 状态**（需进一步人工验证）。另有 21 个候选漏洞被判定为 FALSE_POSITIVE（误报）。

### 关键发现

扫描结果显示该代码库存在以下主要安全风险类别：

1. **动态库加载安全风险 (CWE-427/426)** — 共 10 个漏洞，占总数的 24.4%。多个模块使用相对路径或环境变量控制库加载路径，可通过 LD_LIBRARY_PATH 劫持或环境变量篡改实现恶意代码注入。

2. **路径遍历风险 (CWE-22)** — 共 5 个漏洞，占总数的 12.2%。共享内存操作和文件操作未充分验证路径字符，可能导致越权访问或 symlink 攻击。

3. **认证/授权缺失 (CWE-287/862)** — 共 5 个漏洞，属于设计层面问题。Socket 通信和数据传输通道缺少身份验证机制。

### 建议优先级

- **高优先级**: 处理 Top 5 LIKELY 漏洞，涉及共享内存路径遍历和库劫持风险
- **中优先级**: 审查剩余 LIKELY 漏洞的缓解措施
- **低优先级**: 评估 POSSIBLE 漏洞的实际可达性和攻击场景

### 影响评估

若攻击者成功利用上述漏洞，可能导致：
- 执行任意代码（通过库劫持）
- 访问或篡改其他用户的共享内存数据
- 绕过安全边界获取敏感信息

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 30 | 48.4% |
| FALSE_POSITIVE | 21 | 33.9% |
| LIKELY | 11 | 17.7% |
| **总计** | **62** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 11 | 26.8% |
| Medium | 20 | 48.8% |
| Low | 10 | 24.4% |
| **有效漏洞总计** | **41** | - |
| 误报 (FALSE_POSITIVE) | 21 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-MEM-002]** buffer_overflow (High) - `src/runtime/driver/npu_driver_mem.cc:52` @ `NpuDriver::MallocHostSharedMemory` | 置信度: 75
2. **[VULN-SEC-RUN-001]** path_traversal (High) - `src/runtime/driver/npu_driver_mem.cc:42` @ `MallocHostSharedMemory` | 置信度: 75
3. **[VULN-SEC-AIC-005]** untrusted_search_path (High) - `src/aicpu_sched/aicpu_schedule/execute/main.cpp:155` @ `RegQueueScheduleModuleCallBack` | 置信度: 70
4. **[VULN-SEC-AIC-006]** untrusted_search_path (High) - `src/aicpu_sched/aicpu_schedule/common/aicpusd_hccl_api.cpp:67` @ `LoadHccdLib/LoadHcclLib` | 置信度: 70
5. **[VULN-SEC-QS-003]** untrusted_search_path (High) - `src/queue_schedule/server/main.cpp:93` @ `RegAicpuSchedulerModuleCallBack` | 置信度: 70
6. **[VULN-SEC-QS-004]** untrusted_search_path (High) - `src/queue_schedule/server/hccl/hccl_so_manager.cpp:31` @ `LoadSo` | 置信度: 70
7. **[VULN-DF-LIB-001]** library_injection (High) - `src/aicpu_sched/aicpu_processer/ae_so_manager.cc:311` @ `MultiSoManager::Init` | 置信度: 65
8. **[VULN-DF-LIB-002]** library_injection (High) - `src/aicpu_sched/aicpu_processer/ae_so_manager.cc:189` @ `SingleSoManager::OpenSo` | 置信度: 65
9. **[VULN-SEC-AIC-004]** untrusted_search_path (High) - `src/aicpu_sched/aicpu_processer/ae_so_manager.cc:311` @ `GetInnerKernelPath/GetCustKernelPath` | 置信度: 65
10. **[VULN-SEC-QS-005]** untrusted_search_path (High) - `src/queue_schedule/common/bqs_log.cpp:63` @ `OpenLogSo` | 置信度: 65

---

### 1.4 Top 5 LIKELY 漏洞深度分析

以下是对置信度最高的 5 个 LIKELY 漏洞的深度技术分析，包括漏洞原理、攻击路径和实际风险评估。

#### 1.4.1 VULN-SEC-RUN-001 & VULN-DF-MEM-002: 共享内存路径遍历 (置信度 75)

**漏洞位置**: `src/runtime/driver/npu_driver_mem.cc:42-80`

**漏洞原理分析**:

通过源代码分析，`MallocHostSharedMemory` 函数存在两处安全问题：

```cpp
// 第 47 行: 直接拼接用户输入到路径
retSafe = strcat_s(name, sizeof(name), in->name);

// 第 52 行: shm_open 使用用户传入的名称
out->fd = shm_open(in->name, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
```

**攻击向量**:

1. **路径遍历**: 用户可通过 `in->name` 参数传入包含 `../` 的路径，如 `../../../etc/passwd_ro`，尝试在 `/dev/shm` 目录外创建或访问共享内存对象。虽然 `shm_open` 的语义限制了路径解析（仅操作 `/dev/shm` 目录），但 `../` 可能被部分系统解释为特殊字符。

2. **Symlink 攻击**: 如果攻击者预先在 `/dev/shm` 中创建指向敏感文件的符号链接，当受害进程使用相同名称调用 `shm_open` 时，可能意外访问或覆盖目标文件。

3. **名称冲突**: 用户指定的共享内存名称可能与其他进程冲突，导致数据污染或资源抢占。

**实际风险评估**:

- `rtMallocHostSharedMemory` 是公开 API，用户可控制 `in->name` 参数
- 虽然有 `stat` 检查（第 50 行），但检查与操作之间存在 TOCTOU 时间窗口
- `shm_open` 的 POSIX 规范规定名称必须以 `/` 开头且不含其他 `/`，但实现可能有差异

**缓解措施评估**:

- ✓ 有长度检查（`strnlen` 隐式检查）
- ✓ 使用 `strcat_s` 安全函数
- ✗ 缺少路径遍历字符过滤（`../` 检查）
- ✗ 缺少名称格式白名单验证

---

#### 1.4.2 VULN-SEC-AIC-005: 库劫持风险 via LD_LIBRARY_PATH (置信度 70)

**漏洞位置**: `src/aicpu_sched/aicpu_schedule/execute/main.cpp:155`

**漏洞原理分析**:

```cpp
void RegQueueScheduleModuleCallBack()
{
    g_qslibHandle = dlopen(QUEUE_SCHEDULE_SO_NAME.c_str(), RTLD_LAZY);
    // QUEUE_SCHEDULE_SO_NAME = "libqueue_schedule.so" (相对路径)
```

当使用相对路径调用 `dlopen` 时，动态链接器按以下顺序搜索库：

1. RPATH (编译时指定)
2. LD_LIBRARY_PATH 环境变量
3. RUNPATH
4. /etc/ld.so.cache
5. 默认路径 /lib, /usr/lib

**攻击向量**:

攻击者可通过以下方式劫持库加载：

1. **环境变量注入**: 若进程启动时攻击者能控制 `LD_LIBRARY_PATH`，可指定包含恶意 `libqueue_schedule.so` 的目录优先被搜索。

2. **进程继承**: 若父进程设置了 `LD_LIBRARY_PATH`，子进程继承该环境。在某些部署场景下，管理进程可能被攻击者控制。

3. **容器/沙箱逃逸**: 在容器化部署中，若容器内进程共享宿主机的库搜索路径配置，攻击可能跨越隔离边界。

**实际风险评估**:

- 该进程为 AICPU 调度服务守护进程，通常由系统服务管理器启动
- 需评估进程启动环境的安全性（是否允许用户控制环境变量）
- 多个模块存在相同模式：`libaicpu_scheduler.so`, `libhccd.so`, `libhccl_heterog.so`

---

#### 1.4.3 VULN-SEC-AIC-006: HCCL 库劫持风险 (置信度 70)

**漏洞位置**: `src/aicpu_sched/aicpu_schedule/common/aicpusd_hccl_api.cpp:67-95`

**漏洞原理分析**:

```cpp
void HcclSoManager::LoadHccdSo()
{
    hccdSoHandle_ = dlopen("libhccd.so", RTLD_LAZY);  // 相对路径
}

void HcclSoManager::LoadHcclSo()
{
    hcclSoHandle_ = dlopen("libhccl_heterog.so", RTLD_LAZY);  // 相对路径
}
```

与 VULN-SEC-AIC-005 相同的 `dlopen` 相对路径问题，但涉及不同的库文件。

**特殊风险点**:

- HCCL (Huawei Collective Communication Library) 处理分布式训练通信
- 劫持这些库可能导致：
  - 梯度数据泄露
  - 分布式训练结果篡改
  - 跨节点通信劫持

---

#### 1.4.4 VULN-SEC-QS-003: Queue Schedule 库劫持风险 (置信度 70)

**漏洞位置**: `src/queue_schedule/server/main.cpp:93`

**漏洞原理分析**:

```cpp
void RegAicpuSchedulerModuleCallBack()
{
    g_aicpuSdlibHandle = dlopen(AICPU_SCHEDULER_SO_NAME.c_str(), RTLD_LAZY);
    // AICPU_SCHEDULER_SO_NAME = "libaicpu_scheduler.so"
}
```

Queue Schedule 服务同样使用相对路径加载子模块库，攻击向量与前述漏洞一致。

---

#### 1.4.5 VULN-DF-LIB-001/002: 环境变量控制库路径 (置信度 65)

**漏洞位置**: `src/aicpu_sched/aicpu_processer/ae_so_manager.cc:311-337`

**漏洞原理分析**:

```cpp
aeStatus_t MultiSoManager::Init()
{
    // 第 311 行: 读取环境变量控制内核库路径
    const char_t * const innerDirName = getenv(AICPU_INNER_SO_PATH_ENV_VAR_NAME);
    // AICPU_INNER_SO_PATH_ENV_VAR_NAME = "ASCEND_AICPU_KERNEL_PATH"
    
    if (innerDirName != nullptr) {
        const std::string str = innerDirName;
        const size_t len = str.length();
        if ((len == 0U) || (len >= static_cast<size_t>(PATH_MAX))) {
            return AE_STATUS_INNER_ERROR;
        }
        innerKernelPath_ = str;  // 直接赋值，无路径验证
    }
    
    // 第 325 行: 自定义内核路径
    const char_t * const custDirName = getenv(AICPU_CUSTOM_SO_PATH_ENV_VAR);
    custKernelPath_ = str;  // 同样无验证
}
```

**攻击向量**:

1. **直接路径控制**: 攻击者设置 `ASCEND_AICPU_KERNEL_PATH=/tmp/malicious/`，该目录包含恶意的 `libxxx_kernels.so`。

2. **OpenSo 调用链**:
```
Init() → getenv() → innerKernelPath_ → GetSoPath() → OpenSo() → dlopen(realpath(path))
```

虽然有 `realpath` 调用（第 183 行），但这仅用于路径规范化，不验证路径是否在预期范围内。

**实际风险评估**:

- 环境变量通常由部署脚本或父进程设置，攻击者需具备进程启动环境控制能力
- 存在长度检查 (`PATH_MAX`)，防止缓冲区溢出
- `realpath` 可检测 symlink，但不足以防止路径篡改
- 缺少白名单验证（如仅允许 `/usr/lib64/aicpu_kernel/` 等安全路径）

---

## 2. 攻击面分析

未找到入口点数据。


---

## 3. High 漏洞 (11)

### [VULN-DF-MEM-002] buffer_overflow - NpuDriver::MallocHostSharedMemory

**严重性**: High | **CWE**: CWE-119 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/runtime/driver/npu_driver_mem.cc:52-80` @ `NpuDriver::MallocHostSharedMemory`
**模块**: runtime

**描述**: Shared memory operations with input-controlled name. shm_open() is called with in->name which comes from input. The name is used without sufficient validation, potentially allowing path traversal or symlink attacks in /dev/shm namespace.

**漏洞代码** (`src/runtime/driver/npu_driver_mem.cc:52-80`)

```c
out->fd = shm_open(in->name, static_cast<int32_t>(O_CREAT) | static_cast<int32_t>(O_RDWR), static_cast<mode_t>(S_IRUSR) | static_cast<mode_t>(S_IWUSR));
out->ptr = mmap(nullptr, in->size, ...);
```

**达成路径**

rtMallocHostSharedMemory() → MallocHostSharedMemory(in) → shm_open(in->name) → mmap(in->size) [SINK]

**验证说明**: shm_open使用用户通过公共API传入的in->name参数，可能路径遍历攻击。mmap使用in->size参数无上限验证。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-RUN-001] path_traversal - MallocHostSharedMemory

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/runtime/driver/npu_driver_mem.cc:42-57` @ `MallocHostSharedMemory`
**模块**: runtime

**描述**: 共享内存名称未验证，in->name可能包含路径遍历字符如../，直接用于shm_open和路径拼接

**漏洞代码** (`src/runtime/driver/npu_driver_mem.cc:42-57`)

```c
strcat_s(name, sizeof(name), in->name); out->fd = shm_open(in->name, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
```

**达成路径**

用户输入in->name → strcat_s构建路径 → shm_open创建共享内存

**验证说明**: shm_open使用用户通过公共API传入的in->name参数，没有验证路径遍历字符。rtMallocHostSharedMemory是公共API，用户可控制共享内存名称。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-AIC-005] untrusted_search_path - RegQueueScheduleModuleCallBack

**严重性**: High | **CWE**: CWE-427 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/aicpu_sched/aicpu_schedule/execute/main.cpp:155` @ `RegQueueScheduleModuleCallBack`
**模块**: aicpu_sched

**描述**: main.cpp使用相对路径libaicpu_scheduler.so进行dlopen，攻击者可通过设置LD_LIBRARY_PATH劫持库加载

**漏洞代码** (`src/aicpu_sched/aicpu_schedule/execute/main.cpp:155`)

```c
g_qslibHandle = dlopen(QUEUE_SCHEDULE_SO_NAME.c_str(), RTLD_LAZY); // QUEUE_SCHEDULE_SO_NAME = "libqueue_schedule.so"
```

**达成路径**

相对路径 → dlopen搜索LD_LIBRARY_PATH

**验证说明**: 使用相对路径libqueue_schedule.so进行dlopen，可被LD_LIBRARY_PATH劫持加载恶意库。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-AIC-006] untrusted_search_path - LoadHccdLib/LoadHcclLib

**严重性**: High | **CWE**: CWE-427 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/aicpu_sched/aicpu_schedule/common/aicpusd_hccl_api.cpp:67-95` @ `LoadHccdLib/LoadHcclLib`
**模块**: aicpu_sched

**描述**: aicpusd_hccl_api.cpp使用相对路径libhccd.so和libhccl_heterog.so进行dlopen，存在库劫持风险

**漏洞代码** (`src/aicpu_sched/aicpu_schedule/common/aicpusd_hccl_api.cpp:67-95`)

```c
dlopen("libhccd.so", RTLD_LAZY); dlopen("libhccl_heterog.so", RTLD_LAZY);
```

**达成路径**

相对路径 → dlopen → LD_LIBRARY_PATH劫持

**验证说明**: 使用相对路径libhccd.so/libhccl_heterog.so进行dlopen，可被LD_LIBRARY_PATH劫持。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-QS-003] untrusted_search_path - RegAicpuSchedulerModuleCallBack

**严重性**: High | **CWE**: CWE-427 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/queue_schedule/server/main.cpp:93` @ `RegAicpuSchedulerModuleCallBack`
**模块**: queue_schedule

**描述**: main.cpp使用相对路径libaicpu_scheduler.so进行dlopen，攻击者可通过LD_LIBRARY_PATH劫持

**漏洞代码** (`src/queue_schedule/server/main.cpp:93`)

```c
g_aicpuSdlibHandle = dlopen(AICPU_SCHEDULER_SO_NAME.c_str(), RTLD_LAZY);
```

**达成路径**

相对路径 → dlopen → LD_LIBRARY_PATH劫持

**验证说明**: 使用相对路径libaicpu_scheduler.so进行dlopen，可被LD_LIBRARY_PATH劫持加载恶意库。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-QS-004] untrusted_search_path - LoadSo

**严重性**: High | **CWE**: CWE-427 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/queue_schedule/server/hccl/hccl_so_manager.cpp:31` @ `LoadSo`
**模块**: queue_schedule

**描述**: hccl_so_manager.cpp使用相对路径libhccd.so进行dlopen，存在库劫持风险

**漏洞代码** (`src/queue_schedule/server/hccl/hccl_so_manager.cpp:31`)

```c
soHandle_ = dlopen("libhccd.so", RTLD_LAZY);
```

**达成路径**

相对路径 → dlopen → 库劫持

**验证说明**: 使用相对路径libhccd.so进行dlopen，可被LD_LIBRARY_PATH劫持。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-LIB-001] library_injection - MultiSoManager::Init

**严重性**: High | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/aicpu_sched/aicpu_processer/ae_so_manager.cc:311-337` @ `MultiSoManager::Init`
**模块**: aicpu_sched

**描述**: Library injection via environment variable. The function reads kernel paths from environment variables ASCEND_AICPU_KERNEL_PATH and ASCEND_CUST_AICPU_KERNEL_CACHE_PATH. These paths are then used in dlopen() to load shared libraries. An attacker controlling these environment variables can load arbitrary code.

**漏洞代码** (`src/aicpu_sched/aicpu_processer/ae_so_manager.cc:311-337`)

```c
const char_t * const innerDirName = getenv(AICPU_INNER_SO_PATH_ENV_VAR_NAME);
if (innerDirName != nullptr) {
    innerKernelPath_ = str;
}
const char_t * const custDirName = getenv(AICPU_CUSTOM_SO_PATH_ENV_VAR);
```

**达成路径**

MultiSoManager::Init() → getenv("ASCEND_AICPU_KERNEL_PATH") [SOURCE] → innerKernelPath_ → OpenSo() → dlopen(path.get()) [SINK]

**验证说明**: 环境变量ASCEND_AICPU_KERNEL_PATH控制库加载路径，攻击者可设置恶意路径。有长度检查(PATH_MAX)但无路径验证。dlopen使用realpath处理有一定缓解但不足以完全防护。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-LIB-002] library_injection - SingleSoManager::OpenSo

**严重性**: High | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/aicpu_sched/aicpu_processer/ae_so_manager.cc:189-199` @ `SingleSoManager::OpenSo`
**模块**: aicpu_sched

**描述**: dlopen() with path potentially controlled by environment variables. The path passed to dlopen() may originate from getenv() calls in Init(), allowing an attacker to load malicious shared libraries.

**漏洞代码** (`src/aicpu_sched/aicpu_processer/ae_so_manager.cc:189-199`)

```c
void * const handle = dlopen(path.get(), static_cast<int32_t>((static_cast<uint32_t>(RTLD_LAZY))|(static_cast<uint32_t>(RTLD_GLOBAL))));
```

**达成路径**

MultiSoManager::Init() → getenv() → innerKernelPath_/custKernelPath_ → GetSoPath() → OpenSo() → dlopen() [SINK]

**验证说明**: dlopen路径来自getenv获取的环境变量，攻击者可控制库加载路径。realpath有一定验证但不完整。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-AIC-004] untrusted_search_path - GetInnerKernelPath/GetCustKernelPath

**严重性**: High | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/aicpu_sched/aicpu_processer/ae_so_manager.cc:311-337` @ `GetInnerKernelPath/GetCustKernelPath`
**模块**: aicpu_sched

**描述**: ae_so_manager.cc使用getenv获取ASCEND_AICPU_KERNEL_PATH和ASCEND_CUST_AICPU_KERNEL_CACHE_PATH环境变量，直接用于dlopen加载库，攻击者可设置恶意路径加载任意代码

**漏洞代码** (`src/aicpu_sched/aicpu_processer/ae_so_manager.cc:311-337`)

```c
const char_t * const innerDirName = getenv(AICPU_INNER_SO_PATH_ENV_VAR_NAME); innerKernelPath_ = innerDirName; dlopen(path.get(), RTLD_LAZY|RTLD_GLOBAL);
```

**达成路径**

环境变量 → 路径构建 → dlopen加载

**验证说明**: 环境变量控制dlopen路径，攻击者可加载恶意库。有长度检查但无白名单验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-QS-005] untrusted_search_path - OpenLogSo

**严重性**: High | **CWE**: CWE-807 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/queue_schedule/common/bqs_log.cpp:63-54` @ `OpenLogSo`
**模块**: queue_schedule

**描述**: bqs_log.cpp使用环境变量ASCEND_AICPU_PATH控制库加载路径，攻击者可设置恶意路径加载任意共享库

**漏洞代码** (`src/queue_schedule/common/bqs_log.cpp:63-54`)

```c
bqs::GetEnvVal("ASCEND_AICPU_PATH", ascendAicpuPath); void *logSoHandle = dlopen(path.get(), ...);
```

**达成路径**

环境变量ASCEND_AICPU_PATH → realpath → dlopen加载

**验证说明**: 环境变量ASCEND_AICPU_PATH控制库加载路径，攻击者可设置恶意路径加载任意共享库。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-TSD-003] untrusted_search_path - OpenTfSo

**严重性**: High | **CWE**: CWE-426 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/tsd/tsdclient/src/thread_mode_manager.cpp:48-60` @ `OpenTfSo`
**模块**: tsd

**描述**: thread_mode_manager.cpp使用HOME环境变量构建库路径进行mmDlopen，攻击者可设置恶意HOME路径加载恶意库

**漏洞代码** (`src/tsd/tsdclient/src/thread_mode_manager.cpp:48-60`)

```c
GetEnvFromMmSys(MM_ENV_HOME, "HOME", homeEnv); tfLibraryPath = homeEnv + "/aicpu_kernels/"; mmDlopen(tfLibraryPath.c_str());
```

**达成路径**

HOME环境变量 → 路径构建 → mmDlopen加载

**验证说明**: HOME环境变量控制库加载路径，攻击者可设置恶意HOME路径加载恶意库。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (20)

### [VULN-SEC-MMP-005] path_traversal - mmUnlink

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/mmpa/src/mmpa_linux_file.c:512-519` @ `mmUnlink`
**模块**: mmpa

**描述**: mmUnlink直接使用用户路径无验证，不验证路径是否包含../、符号链接等路径遍历攻击

**漏洞代码** (`src/mmpa/src/mmpa_linux_file.c:512-519`)

```c
return unlink(filename);
```

**达成路径**

用户传入filename → unlink删除文件

**验证说明**: mmUnlink使用用户路径无验证，可能路径遍历。需要检查调用路径确定是否用户可控。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-MMP-006] path_traversal - mmChmod/mmStatGet/mmRmdir/mmMkdir

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-73 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/mmpa/src/mmpa_linux_file.c:527-65` @ `mmChmod/mmStatGet/mmRmdir/mmMkdir`
**模块**: mmpa

**描述**: mmChmod/mmStatGet/mmRmdir/mmMkdir等函数直接使用用户提供的路径，无路径遍历验证

**漏洞代码** (`src/mmpa/src/mmpa_linux_file.c:527-65`)

```c
chmod(filename); stat(pathName); rmdir(pathName); mkdir(pathName)
```

**达成路径**

用户传入路径 → 文件操作

**验证说明**: mmChmod/mmStatGet等函数使用用户路径无验证，需要检查调用路径。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-AIC-007] untrusted_search_path - BuildCustSoPath

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/aicpu_sched/aicpu_processer/ae_so_manager.cc:364-453` @ `BuildCustSoPath`
**模块**: aicpu_sched

**描述**: ae_so_manager.cc使用getenv(HOME)构建库路径，攻击者可篡改HOME指向恶意目录

**漏洞代码** (`src/aicpu_sched/aicpu_processer/ae_so_manager.cc:364-453`)

```c
const char_t * const innerDirName = getenv("HOME");
```

**达成路径**

getenv(HOME) → 路径构建

**验证说明**: 使用getenv(HOME)构建库路径。HOME环境变量可被攻击者控制，但通常由系统设置。有长度检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-TSD-004] untrusted_search_path - OpenAicpuSchedulerSo

**严重性**: Medium | **CWE**: CWE-427 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/tsd/tsdclient/src/thread_mode_manager.cpp:115-117` @ `OpenAicpuSchedulerSo`
**模块**: tsd

**描述**: thread_mode_manager.cpp当绝对路径加载失败后，回退到相对路径(仅soname)加载，依赖LD_LIBRARY_PATH

**漏洞代码** (`src/tsd/tsdclient/src/thread_mode_manager.cpp:115-117`)

```c
const std::string helperPath = "libaicpu_scheduler.so"; handle_ = mmDlopen(helperPath.c_str(), MMPA_RTLD_NOW);
```

**达成路径**

相对路径 → mmDlopen → LD_LIBRARY_PATH劫持

**验证说明**: 相对路径mmDlopen可被LD_LIBRARY_PATH劫持。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-DFX-006] untrusted_search_path - dumper_core

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/dfx/trace/atrace/utrace/stacktrace/dumper_process/dumper_core.c:77` @ `dumper_core`
**模块**: dfx

**描述**: dumper_core.c使用execlp执行asc_dumper，exePath来自动态计算路径，PATH环境变量被篡改可能执行恶意程序

**漏洞代码** (`src/dfx/trace/atrace/utrace/stacktrace/dumper_process/dumper_core.c:77`)

```c
execlp(args->exePath, STACKTRACE_DUMP_EXE, binFile, NULL)
```

**达成路径**

exePath → execlp搜索PATH

**验证说明**: execlp执行asc_dumper，exePath来自动态计算，PATH可能被篡改。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MEM-001] integer_overflow - XpuArgManage::CreateArgRes

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/runtime/feature/xpu/arg_manage_xpu.cc:32-65` @ `XpuArgManage::CreateArgRes`
**模块**: runtime

**描述**: Potential integer overflow in memory allocation. argPoolSize_ is calculated as XPU_ARG_POOL_COPY_SIZE multiplied by stream depth. If the multiplication exceeds integer limits, malloc() may allocate insufficient memory leading to heap overflow.

**漏洞代码** (`src/runtime/feature/xpu/arg_manage_xpu.cc:32-65`)

```c
argPoolSize_ = XPU_ARG_POOL_COPY_SIZE * (dev->GetXpuStreamDepth());
devAddr = malloc(argPoolSize_);
```

**达成路径**

XpuArgManage::CreateArgRes() → GetXpuStreamDepth() → multiplication → malloc(argPoolSize_) [SINK]

**验证说明**: argPoolSize_=XPU_ARG_POOL_COPY_SIZE*GetXpuStreamDepth()可能整数溢出。XPU_ARG_POOL_COPY_SIZE是常量，溢出可能性取决于实际值范围。

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-PATH-001] path_traversal - PackageVerify::ChangePackageMode

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/tsd/common/src/package_verify.cpp:77-84` @ `PackageVerify::ChangePackageMode`
**模块**: tsd

**描述**: chmod() with externally-controlled path. The pkgPath_ member variable comes from external input and is used directly in chmod(). While there is access() check earlier, no path canonicalization or validation against allowed directories.

**漏洞代码** (`src/tsd/common/src/package_verify.cpp:77-84`)

```c
const int32_t ret = chmod(pkgPath_.c_str(), (S_IRWXU|S_IRGRP|S_IXGRP));
```

**达成路径**

PackageVerify::VerifyPackage() → IsPackageValid() → ChangePackageMode() → chmod(pkgPath_) [SINK]

**验证说明**: chmod(pkgPath_)路径来自PackageVerify成员变量，需要检查pkgPath_来源是否可控。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-PATH-002] arbitrary_file_access - PackageVerify::GetPkgCodeLen

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/tsd/common/src/package_verify.cpp:183-223` @ `PackageVerify::GetPkgCodeLen`
**模块**: tsd

**描述**: fopen() with externally-controlled path. The srcPath parameter comes from pkgPath_ which is externally controlled. While there is realpath check in IsPackageValid(), multiple fopen() calls are made to the same path.

**漏洞代码** (`src/tsd/common/src/package_verify.cpp:183-223`)

```c
FILE *fp = fopen(srcPath.c_str(), "r");
```

**达成路径**

VerifyPackageByCms() → GetPkgCodeLen(pkgPath_) → fopen(srcPath) [SINK]

**验证说明**: fopen(srcPath)路径来自pkgPath_，需要检查调用路径确定是否用户可控。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-MMP-002] missing_authentication - mmSocket/mmConnect/mmAccept

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-287 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/mmpa/src/mmpa_linux.c:271-457` @ `mmSocket/mmConnect/mmAccept`
**模块**: mmpa

**描述**: Socket通信没有身份认证机制，mmAccept接受连接时不验证客户端身份

**漏洞代码** (`src/mmpa/src/mmpa_linux.c:271-457`)

```c
mmSocket(), mmConnect(), mmAccept()
```

**达成路径**

Socket创建 → 连接/接受 → 无认证

**验证说明**: Socket通信缺少身份认证，但这是设计层面问题而非代码漏洞。POSIX socket机制本身无认证，应用层需自行实现。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-ACL-008] path_traversal - GetCANNVersionInternal

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/acl/aclrt_impl/acl.cpp:806-813` @ `GetCANNVersionInternal`
**模块**: acl

**描述**: acl.cpp使用环境变量ASCEND_HOME_PATH直接构建文件路径，没有充分的路径遍历检查

**漏洞代码** (`src/acl/aclrt_impl/acl.cpp:806-813`)

```c
MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, pathEnv); GetCANNVersionInternal(name, *version, std::string(pathEnv) + "/share/info");
```

**达成路径**

环境变量 → 路径构建 → 文件访问

**验证说明**: ASCEND_HOME_PATH环境变量构建文件路径，攻击者可控制路径。需要进一步验证路径遍历检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-DFX-002] unnecessary_privilege - ScdPtraceAttach

**严重性**: Medium | **CWE**: CWE-250 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/dfx/trace/atrace/utrace/stacktrace/stacktrace_dumper/scd_ptrace.c:21` @ `ScdPtraceAttach`
**模块**: dfx

**描述**: scd_ptrace.c中ptrace(PTRACE_ATTACH)操作缺乏对目标进程的权限验证，可能被恶意进程利用获取敏感数据

**漏洞代码** (`src/dfx/trace/atrace/utrace/stacktrace/stacktrace_dumper/scd_ptrace.c:21`)

```c
if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) != 0)
```

**达成路径**

tid参数 → ptrace ATTACH → 无权限验证

**验证说明**: ptrace(PTRACE_ATTACH)操作缺乏目标进程权限验证，可能被恶意进程利用。ptrace本身有Linux安全机制限制。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-DFX-005] command_injection - script

**严重性**: Medium | **CWE**: CWE-78 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/dfx/msprof/collector/dvvp/adda/devprof/prof_collect.sh:122-133` @ `script`
**模块**: dfx

**描述**: prof_collect.sh脚本参数直接传递给shell命令，参数可能包含恶意字符绕过检查，使用su命令执行cp操作

**漏洞代码** (`src/dfx/msprof/collector/dvvp/adda/devprof/prof_collect.sh:122-133`)

```c
/usr/bin/perf record -o ${current_dir} -F ${2} -e '${3}' -a; su - ${perf_user} -c "cp ${file} ${1}.${perf_count}"
```

**达成路径**

脚本参数 → shell命令执行

**验证说明**: prof_collect.sh脚本参数可能包含恶意字符。但脚本运行环境受限，需要进一步验证参数来源。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-RUN-002] missing_authentication - MallocHostSharedMemory

**严重性**: Medium（原评估: Critical → 验证后: Medium） | **CWE**: CWE-287 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/runtime/driver/npu_driver_mem.cc:42-57` @ `MallocHostSharedMemory`
**模块**: runtime

**描述**: 共享内存访问缺少认证验证，任意进程可创建/访问共享内存对象

**漏洞代码** (`src/runtime/driver/npu_driver_mem.cc:42-57`)

```c
shm_open(in->name, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
```

**达成路径**

shm_open创建共享内存 → 无访问控制验证

**验证说明**: shm_open共享内存访问缺少认证验证，但POSIX共享内存机制本身有文件系统权限控制。这是设计层面的问题而非代码漏洞。

**评分明细**: base: 30 | reachability: 30 | controllability: 0 | mitigations: 0 | context: -15 | cross_file: 0

---

### [VULN-SEC-MMP-003] missing_encryption - mmSocketRecv

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-311 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/mmpa/src/mmpa_linux.c:418-430` @ `mmSocketRecv`
**模块**: mmpa

**描述**: 数据传输没有加密保护，接收的网络数据直接存入用户buffer无内容验证

**漏洞代码** (`src/mmpa/src/mmpa_linux.c:418-430`)

```c
mmSsize_t ret = recv(sockFd, recvBuf, rcvLen, recvFlag);
```

**达成路径**

Socket接收 → recv存入buffer → 无加密无验证

**验证说明**: 数据传输无加密保护，但这是设计层面问题。recv直接存入buffer是正常socket使用模式。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN-SEC-ACL-001] untrusted_search_path - GetHandler

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-427 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/acl/acl_tdt_channel/tensor_data_transfer.cpp:64-81` @ `GetHandler`
**模块**: acl

**描述**: tensor_data_transfer.cpp使用mmDlopen加载libdatatransfer.so，路径由GetSoRealPath获取，使用RTLD_GLOBAL可能导致符号冲突

**漏洞代码** (`src/acl/acl_tdt_channel/tensor_data_transfer.cpp:64-81`)

```c
void *handler = mmDlopen(soName.c_str(), RTLD_NOW | RTLD_GLOBAL);
```

**达成路径**

GetSoRealPath → mmDlopen加载

**验证说明**: mmDlopen加载libdatatransfer.so，路径由GetSoRealPath获取。RTLD_GLOBAL可能导致符号冲突。需要检查路径构建过程。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-ACL-002] missing_authentication - acltdtSendTensor/acltdtReceiveTensor

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-287 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/acl/acl_tdt_channel/tensor_data_transfer.cpp:1082-1125` @ `acltdtSendTensor/acltdtReceiveTensor`
**模块**: acl

**描述**: acltdtSendTensor/acltdtReceiveTensor函数在数据传输前没有进行任何身份认证，通道名称直接作为标识符

**漏洞代码** (`src/acl/acl_tdt_channel/tensor_data_transfer.cpp:1082-1125`)

```c
tdtHostPushData(handle->name, itemVec, 0);
```

**达成路径**

通道名称 → 数据传输 → 无认证

**验证说明**: acltdtSendTensor/acltdtReceiveTensor数据传输缺少认证，这是设计层面问题而非代码漏洞。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-ACL-003] missing_authorization - aclrtSetDeviceImpl

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-862 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/acl/aclrt_impl/device.cpp:47-65` @ `aclrtSetDeviceImpl`
**模块**: acl

**描述**: 所有Runtime API直接调用底层runtime函数，没有ACL级别的权限验证，deviceId参数没有访问控制检查

**漏洞代码** (`src/acl/aclrt_impl/device.cpp:47-65`)

```c
const rtError_t rtErr = rtSetDevice(deviceId);
```

**达成路径**

deviceId → rtSetDevice → 无权限检查

**验证说明**: ACL API直接调用底层runtime，deviceId参数无权限检查。这是设计层面问题而非代码漏洞。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-ACL-006] buffer_overflow - UnpackageRecvDataInfo

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/acl/acl_tdt_channel/tensor_data_transfer.cpp:534-578` @ `UnpackageRecvDataInfo`
**模块**: acl

**描述**: UnpackageRecvDataInfo函数cnt值直接从解包数据中读取可能被攻击者控制，虽有offset检查但整体数据结构验证不足

**漏洞代码** (`src/acl/acl_tdt_channel/tensor_data_transfer.cpp:534-578`)

```c
uint32_t cnt = head->cnt; ItemInfo *tmp = reinterpret_cast<ItemInfo *>(outputHostAddr + offset);
```

**达成路径**

网络数据 → cnt读取 → 内存操作

**验证说明**: cnt值从网络数据读取但有offset检查。需要进一步验证边界检查是否充分。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-RUN-003] race_condition - MallocHostSharedMemory

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-362 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/runtime/driver/npu_driver_mem.cc:42-57` @ `MallocHostSharedMemory`
**模块**: runtime

**描述**: stat检查后到shm_open之间存在TOCTOU竞态条件，可能被篡改

**漏洞代码** (`src/runtime/driver/npu_driver_mem.cc:42-57`)

```c
stat检查 → shm_open创建
```

**达成路径**

stat检查文件 → 时间窗口 → shm_open操作

**验证说明**: stat检查后到shm_open之间存在TOCTOU竞态条件，但时间窗口很短。代码有stat检查提供一定缓解。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-MMP-004] missing_input_validation - mmIoctl

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-782 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/mmpa/src/mmpa_linux_file.c:236-247` @ `mmIoctl`
**模块**: mmpa

**描述**: ioctlCode由用户提供未验证是否为合法ioctl命令，inbuf内容未验证，恶意ioctlCode可能导致内核驱动安全问题

**漏洞代码** (`src/mmpa/src/mmpa_linux_file.c:236-247`)

```c
UINT32 request = (UINT32)ioctlCode; INT32 ret = ioctl(fd, request, bufPtr->inbuf);
```

**达成路径**

ioctlCode用户输入 → ioctl调用

**验证说明**: ioctlCode由用户传入但mmIoctl是内部API。上层调用需验证ioctlCode合法性。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -10 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (10)

### [VULN-SEC-RUN-006] integer_overflow - AllocCpyTmpMem

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/runtime/core/src/task/task_info/memory/memory_task.cc:98-144` @ `AllocCpyTmpMem`
**模块**: runtime

**描述**: malloc分配后未立即检查返回值是否为NULL，addrSize参数可能触发整数溢出导致分配过小内存

**漏洞代码** (`src/runtime/core/src/task/task_info/memory/memory_task.cc:98-144`)

```c
memcpyAsyncTaskInfo->srcPtr = malloc(addrSize + ASYNC_MEMORY_SIZE);
```

**达成路径**

addrSize参数 → malloc分配 → 未检查返回值

**验证说明**: malloc分配后未立即检查返回值，但后续有使用检查。addrSize参数可能溢出但需进一步分析实际范围。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-RUN-007] missing_authorization - rtMalloc

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-862 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/runtime/api/api_c_memory.cc:52-66` @ `rtMalloc`
**模块**: runtime

**描述**: API层缺少调用者权限验证和moduleId白名单，未限制size参数上限可能导致资源耗尽攻击

**漏洞代码** (`src/runtime/api/api_c_memory.cc:52-66`)

```c
NULL_RETURN_ERROR_WITH_EXT_ERRCODE(apiInstance); const rtError_t error = apiInstance->DevMalloc(devPtr, size, type, moduleId);
```

**达成路径**

API调用 → 仅检查指针非空 → DevMalloc分配内存

**验证说明**: API层缺少调用者权限验证，但这是设计层面问题而非代码漏洞。底层有设备权限控制。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-QS-006] untrusted_input - BindAicpu

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-807 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/queue_schedule/server/bind_cpu_utils.cpp:241-256` @ `BindAicpu`
**模块**: queue_schedule

**描述**: 环境变量PROCMGR_AICPU_CPUSET控制程序执行分支，攻击者可设置此变量改变CPU绑定行为

**漏洞代码** (`src/queue_schedule/server/bind_cpu_utils.cpp:241-256`)

```c
const char * const envValue = std::getenv("PROCMGR_AICPU_CPUSET"); if (cpuSetFlag == "1") BindAicpuByPm();
```

**达成路径**

getenv → 控制流分支

**验证说明**: 环境变量控制执行路径，属于配置控制而非安全漏洞。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN-SEC-DFX-003] improper_privilege - stacktrace_exec

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-269 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/dfx/trace/atrace/utrace/stacktrace/stacktrace_exec.c:124-136` @ `stacktrace_exec`
**模块**: dfx

**描述**: stacktrace_exec.c使用prctl(PR_SET_DUMPABLE, 1)允许进程被dump，使用PR_SET_PTRACER允许特定进程绕过ptrace限制

**漏洞代码** (`src/dfx/trace/atrace/utrace/stacktrace/stacktrace_exec.c:124-136`)

```c
prctl(PR_SET_DUMPABLE, 1, 0, 0, 0); prctl(PR_SET_PTRACER, child, 0, 0, 0);
```

**达成路径**

prctl设置 → 降低安全边界

**验证说明**: prctl(PR_SET_DUMPABLE, 1)是调试诊断的正常用法，降低安全边界但属于设计选择。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-MMP-008] buffer_error - mmMmap

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-119 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/mmpa/src/mmpa_linux_file.c:709-719` @ `mmMmap`
**模块**: mmpa

**描述**: mmap的size和offset未验证是否在文件范围内，prot和flags由用户控制可能导致安全问题

**漏洞代码** (`src/mmpa/src/mmpa_linux_file.c:709-719`)

```c
VOID *data = mmap(NULL, size, prot, flags, fd, offset);
```

**达成路径**

size/offset/prot/flags用户输入 → mmap映射

**验证说明**: mmap参数(size/offset/prot/flags)由用户控制，需要检查调用路径。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-TSD-002] command_injection - ProcessSoPackage

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-78 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/tsd/common/src/aicpu_package_process.cpp:210-217` @ `ProcessSoPackage`
**模块**: tsd

**描述**: aicpu_package_process.cpp构建shell命令(mkdir/mv/tar/rm)，路径变量直接拼接到命令中，可能包含shell元字符

**漏洞代码** (`src/tsd/common/src/aicpu_package_process.cpp:210-217`)

```c
cmd = "mkdir -p " + aicpuSoPath + " ; mv " + extendSoPath + "*.so* " + aicpuSoPath; PackSystem(cmd.c_str());
```

**达成路径**

路径变量 → 命令拼接 → PackSystem → TsdExecuteCmd

**验证说明**: 命令由内部路径变量拼接，路径来自TsdPathMgr构建，不是用户直接输入。但路径构建过程需进一步验证。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN-SEC-TSD-005] race_condition - IsPackageValid/VerifyPackage

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-367 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/tsd/common/src/package_verify.cpp:64-183` @ `IsPackageValid/VerifyPackage`
**模块**: tsd

**描述**: package_verify.cpp使用access()检查和后续fopen()之间存在TOCTOU时间窗口，攻击者可在检查后替换文件

**漏洞代码** (`src/tsd/common/src/package_verify.cpp:64-183`)

```c
access(pkgPath_.c_str(), F_OK); fopen(srcPath.c_str(), "r");
```

**达成路径**

access检查 → 时间窗口 → fopen使用

**验证说明**: access检查后fopen存在TOCTOU竞态，但时间窗口很短。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-ACL-005] missing_authorization - acltdtGrantQueue

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-732 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/acl/acl_tdt_queue/queue_process.cpp:77-89` @ `acltdtGrantQueue`
**模块**: acl

**描述**: acltdtGrantQueue和acltdtAttachQueue功能未实现但暴露了API接口，队列创建后没有权限控制

**漏洞代码** (`src/acl/acl_tdt_queue/queue_process.cpp:77-89`)

```c
ACL_LOG_ERROR("acltdtGrantQueue is not supported in this version.");
```

**达成路径**

队列API → 未实现 → 缺少权限控制

**验证说明**: acltdtGrantQueue功能未实现，不是安全漏洞而是功能限制。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-DFX-004] info_exposure - 全局定义

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-552 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/dfx/trace/atrace/utrace/stacktrace/stacktrace_unwind_dfx.c:16-17` @ `全局定义`
**模块**: dfx

**描述**: stacktrace_unwind_dfx.c将栈信息和ELF文件dump到/tmp公开可写目录，可能被其他用户读取或篡改

**漏洞代码** (`src/dfx/trace/atrace/utrace/stacktrace/stacktrace_unwind_dfx.c:16-17`)

```c
#define TMP_DUMP_STACK_PATH "/tmp/stack.bin" #define TMP_DUMP_ELF_PATH "/tmp/elf_%zu.bin"
```

**达成路径**

栈/ELF信息 → dump到/tmp → 信息泄露

**验证说明**: 栈/ELF信息dump到/tmp是诊断功能设计，/tmp权限由系统控制。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN-SEC-DFX-007] info_exposure - record_proc_info

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-200 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/dfx/trace/atrace/utrace/stacktrace/stacktrace_safe_recorder.c:285` @ `record_proc_info`
**模块**: dfx

**描述**: stacktrace_safe_recorder.c转储进程的内存映射、状态、limits等敏感信息到文件，文件权限0640可能不足

**漏洞代码** (`src/dfx/trace/atrace/utrace/stacktrace/stacktrace_safe_recorder.c:285`)

```c
snprintf_s(path, CORE_BUFFER_LEN, "/proc/%d/maps", pid);
```

**达成路径**

/proc信息 → dump到文件 → 信息泄露

**验证说明**: /proc信息dump是诊断功能设计，文件权限0640有一定保护。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: -5 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| acl | 0 | 0 | 5 | 1 | 6 |
| aicpu_sched | 0 | 5 | 1 | 0 | 6 |
| dfx | 0 | 0 | 3 | 3 | 6 |
| mmpa | 0 | 0 | 5 | 1 | 6 |
| queue_schedule | 0 | 3 | 0 | 1 | 4 |
| runtime | 0 | 2 | 3 | 2 | 7 |
| tsd | 0 | 1 | 3 | 2 | 6 |
| **合计** | **0** | **11** | **20** | **10** | **41** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-427 | 6 | 14.6% |
| CWE-22 | 5 | 12.2% |
| CWE-426 | 4 | 9.8% |
| CWE-287 | 3 | 7.3% |
| CWE-94 | 2 | 4.9% |
| CWE-862 | 2 | 4.9% |
| CWE-807 | 2 | 4.9% |
| CWE-78 | 2 | 4.9% |
| CWE-190 | 2 | 4.9% |
| CWE-119 | 2 | 4.9% |
| CWE-782 | 1 | 2.4% |
| CWE-732 | 1 | 2.4% |
| CWE-73 | 1 | 2.4% |
| CWE-552 | 1 | 2.4% |
| CWE-367 | 1 | 2.4% |
| CWE-362 | 1 | 2.4% |
| CWE-311 | 1 | 2.4% |
| CWE-269 | 1 | 2.4% |
| CWE-250 | 1 | 2.4% |
| CWE-200 | 1 | 2.4% |
| CWE-129 | 1 | 2.4% |

---

## 8. 修复建议 (Remediation Recommendations)

基于本次扫描发现的漏洞类型分布，提出以下分类修复建议。

### 8.1 高优先级修复建议 (针对 LIKELY 漏洞)

#### 8.1.1 共享内存路径遍历修复 (VULN-SEC-RUN-001, VULN-DF-MEM-002)

**修复位置**: `src/runtime/driver/npu_driver_mem.cc`

**建议方案**:

1. **添加名称验证函数**:
```cpp
bool IsValidShmName(const char_t *name) {
    if (name == nullptr) return false;
    
    // POSIX shm_open 要求: 以 "/" 开头，不含其他 "/"
    size_t len = strlen(name);
    if (len == 0 || len > NAME_MAX) return false;
    if (name[0] != '/') return false;
    
    // 检查路径遍历字符
    if (strstr(name, "..") != nullptr) return false;
    if (strstr(name, "//") != nullptr) return false;
    
    // 仅允许字母、数字、下划线、连字符
    for (size_t i = 1; i < len; ++i) {
        char_t c = name[i];
        if (!(isalnum(c) || c == '_' || c == '-')) return false;
    }
    return true;
}
```

2. **在 shm_open 前调用验证**:
```cpp
if (!IsValidShmName(in->name)) {
    RT_LOG_ERROR("Invalid shared memory name: %s", in->name);
    return RT_ERROR_INVALID_VALUE;
}
```

3. **使用 O_EXCL 标志防止 symlink 攻击**:
```cpp
out->fd = shm_open(in->name, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
```

---

#### 8.1.2 动态库加载安全修复 (CWE-427 类漏洞)

**影响文件**:
- `src/aicpu_sched/aicpu_schedule/execute/main.cpp`
- `src/aicpu_sched/aicpu_schedule/common/aicpusd_hccl_api.cpp`
- `src/queue_schedule/server/main.cpp`
- `src/queue_schedule/server/hccl/hccl_so_manager.cpp`

**建议方案**:

1. **使用绝对路径加载库**:
```cpp
// 原代码
dlopen("libqueue_schedule.so", RTLD_LAZY);

// 修复方案: 构建绝对路径
std::string libPath = GetInstallPath() + "/lib64/libqueue_schedule.so";
dlopen(libPath.c_str(), RTLD_LAZY);
```

2. **在编译时指定 RPATH/RUNPATH**:
```cmake
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib64")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
```

3. **添加环境变量安全检查**:
```cpp
void SafeDlopen(const std::string &soName) {
    // 检查 LD_LIBRARY_PATH 是否被非预期设置
    const char *ldPath = getenv("LD_LIBRARY_PATH");
    if (ldPath != nullptr && !IsWhitelistedPath(ldPath)) {
        syslog(LOG_WARNING, "LD_LIBRARY_PATH is set to non-standard path");
    }
    
    // 使用绝对路径
    std::string fullPath = GetSecureLibPath(soName);
    return dlopen(fullPath.c_str(), RTLD_LAZY);
}
```

---

#### 8.1.3 环境变量路径验证修复 (VULN-DF-LIB-001, VULN-DF-LIB-002)

**修复位置**: `src/aicpu_sched/aicpu_processer/ae_so_manager.cc`

**建议方案**:

1. **添加路径白名单验证**:
```cpp
const std::vector<std::string> ALLOWED_KERNEL_PATHS = {
    "/usr/lib64/aicpu_kernel/",
    "/usr/local/Ascend/",
    // 其他官方安装路径
};

bool IsPathWhitelisted(const std::string &path) {
    std::string resolved = realpath(path.c_str(), nullptr);
    if (resolved.empty()) return false;
    
    for (const auto &allowed : ALLOWED_KERNEL_PATHS) {
        if (resolved.find(allowed) == 0) return true;
    }
    return false;
}

// 在 Init() 中添加验证
const char_t * const innerDirName = getenv(AICPU_INNER_SO_PATH_ENV_VAR_NAME);
if (innerDirName != nullptr) {
    std::string path = innerDirName;
    if (!IsPathWhitelisted(path)) {
        AE_ERR_LOG("Environment variable path is not in whitelist: %s", path.c_str());
        return AE_STATUS_INNER_ERROR;
    }
    innerKernelPath_ = path;
}
```

2. **限制环境变量使用范围**:
仅在特定运行模式（如 THREAD_MODE）下允许使用环境变量覆盖，其他模式强制使用默认路径。

---

### 8.2 中优先级修复建议

#### 8.2.1 文件操作路径验证 (CWE-22 类漏洞)

为 `mmpa` 模块的文件操作函数添加路径验证:

```cpp
// mmUnlink, mmChmod, mmStatGet 等函数调用前添加验证
int32_t SafeFileOperation(const char_t *filename) {
    if (filename == nullptr) return MM_ERROR;
    
    // 检查路径遍历
    if (strstr(filename, "..") != nullptr) {
        syslog(LOG_WARNING, "Path traversal detected: %s", filename);
        return MM_ERROR_INVALID_PATH;
    }
    
    // 使用 realpath 规范化路径
    char_t resolved[PATH_MAX];
    if (realpath(filename, resolved) == nullptr) return MM_ERROR;
    
    // 执行原始操作
    return unlink(resolved);
}
```

---

### 8.3 部署层面建议

#### 8.3.1 进程环境安全

1. **服务启动脚本清理环境变量**:
```bash
# systemd 服务文件
[Service]
Environment="LD_LIBRARY_PATH="
Environment="ASCEND_AICPU_KERNEL_PATH=/usr/lib64/aicpu_kernel"
UnsetEnvironment=LD_PRELOAD
```

2. **使用 capabilities 替代 root 权限**:
避免以 root 运行服务进程，使用 Linux capabilities 精细控制权限。

3. **SELinux/AppArmor 策略**:
为关键服务进程配置强制访问控制策略，限制文件访问范围。

---

### 8.4 代码审查建议

建议针对以下模式进行专项代码审查:

| 模式 | 检查项 | 建议工具 |
|------|--------|----------|
| `dlopen(...)` | 检查是否使用绝对路径 | grep + AST-grep |
| `getenv(...)` | 检查路径类环境变量的验证 | 数据流分析 |
| `shm_open(...)` | 检查名称格式验证 | 静态分析 |
| `mmap(...)` | 检查 size 参数上限 | 边界分析 |

---

### 8.5 修复进度建议

| 阶段 | 漏洞范围 | 建议时间 |
|------|----------|----------|
| 阶段 1 | LIKELY 漏洞 (11 个) | 2-4 周 |
| 阶段 2 | POSSIBLE High/Medium (22 个) | 4-6 周 |
| 阶段 3 | POSSIBLE Low (10 个) | 评估后决定 |

---

**报告生成时间**: 2026-04-23
**扫描工具版本**: CANN Security Scanner v1.0
**报告状态**: 待人工审核验证
