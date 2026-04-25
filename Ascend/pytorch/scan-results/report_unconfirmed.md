# 漏洞扫描报告 — 待确认漏洞

**项目**: torch_npu  
**扫描时间**: 2026-04-24T07:12:08.786Z  
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本次扫描在 torch_npu 项目中发现 **10 个待确认漏洞**（排除6个误报），其中 **4 个 LIKELY 漏洞**均为 **IPC 路径遍历（CWE-22）**，位于跨进程 Tensor 共享机制中。

### 关键发现

**IPC 共享内存路径遍历漏洞（High 严重性）**  
torch_npu 的跨进程 NPU Tensor 共享机制（`StorageSharing.cpp`）存在路径验证缺失问题。在 `THNPStorage_releaseIPCCounter` 和 `THNPStorage_newSharedNpu` 函数中，引用计数器文件路径（`ref_counter_handle`）直接来自 Python IPC 参数，未经任何安全验证便传递给 `RefcountedMapAllocator::makeDataPtr()`。

### 安全风险评估

- **攻击前提**: 需要参与多进程训练环境的恶意进程
- **潜在影响**: 文件系统越权访问、敏感数据泄露、共享内存污染
- **置信度**: 70/100 — 漏洞模式清晰，数据流可追溯，缺乏缓解措施
- **实际风险**: Medium — 虽需本地进程妥协，但在云训练/多租户场景下风险上升

### 建议优先级

| 优先级 | 漏洞类型 | 数量 | 建议措施 |
|--------|----------|------|----------|
| **P0** | IPC path traversal | 4 | 立即添加路径白名单验证 |
| **P1** | Distributed path traversal | 3 | 环境变量路径规范化 |
| **P2** | Network input validation | 2 | 消息大小限制与解析校验 |
| **P3** | Framework path check | 1 | realpath 结果验证 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 6 | 37.5% |
| FALSE_POSITIVE | 6 | 37.5% |
| LIKELY | 4 | 25.0% |
| **总计** | **16** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 4 | 40.0% |
| Medium | 3 | 30.0% |
| Low | 3 | 30.0% |
| **有效漏洞总计** | **10** | - |
| 误报 (FALSE_POSITIVE) | 6 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-IPC-001]** path_traversal (High) - `torch_npu/csrc/ipc/StorageSharing.cpp:116` @ `THNPStorage_releaseIPCCounter` | 置信度: 70
2. **[VULN-DF-IPC-002]** path_traversal (High) - `torch_npu/csrc/ipc/StorageSharing.cpp:165` @ `THNPStorage_newSharedNpu` | 置信度: 70
3. **[VULN-SEC-PATH-004]** path_traversal (High) - `torch_npu/csrc/ipc/StorageSharing.cpp:132` @ `THNPStorage_releaseIPCCounter` | 置信度: 70
4. **[VULN-SEC-PATH-005]** path_traversal (High) - `torch_npu/csrc/ipc/StorageSharing.cpp:227` @ `THNPStorage_newSharedNpu` | 置信度: 70
5. **[VULN-DF-FILE-001]** path_traversal (Medium) - `torch_npu/csrc/distributed/ProcessGroupHCCL.cpp:404` @ `checkAndMakePath, createFile` | 置信度: 55
6. **[VULN-SEC-PATH-001]** path_traversal (Medium) - `torch_npu/csrc/distributed/ProcessGroupHCCL.cpp:415` @ `createFile` | 置信度: 55
7. **[VULN-SEC-PATH-002]** path_traversal (Medium) - `torch_npu/csrc/distributed/ProcessGroupHCCL.cpp:404` @ `checkAndMakePath` | 置信度: 55
8. **[VULN-DF-NET-001]** improper_input_validation (Low) - `torch_npu/csrc/distributed/ParallelTcpServer.cpp:34` @ `ClientIoContext::ReceiveData` | 置信度: 45
9. **[VULN-DF-NET-002]** improper_input_validation (Low) - `torch_npu/csrc/distributed/StoreClient.cpp:202` @ `Client::SyncCall` | 置信度: 45
10. **[VULN-SEC-PATH-008]** path_traversal (Low) - `torch_npu/csrc/framework/interface/EnvVariables.cpp:18` @ `ValidPathCheck` | 置信度: 40

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `undefined@undefined` | network | - | - | TCP Socket 通信 - 分布式训练网络接口 |
| `undefined@undefined` | ipc | - | - | 共享内存 IPC - 跨进程 NPU Tensor 共享 |
| `undefined@undefined` | file | - | - | 文件操作 - 性能数据导出、调试信息写入 |
| `undefined@undefined` | library_loading | - | - | 动态库加载 - NPU 功能扩展加载 |
| `undefined@undefined` | environment_variable | - | - | 环境变量 - 配置参数读取 |
| `undefined@undefined` | serialization | - | - | Tensor 序列化/反序列化 |
| `undefined@undefined` | python_api | - | - | Python API - 用户调用入口 |


---

## 3. High 漏洞 (4)

### [VULN-DF-IPC-001] path_traversal - THNPStorage_releaseIPCCounter

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `torch_npu/csrc/ipc/StorageSharing.cpp:116-151` @ `THNPStorage_releaseIPCCounter`
**模块**: ipc
**跨模块**: ipc → core

**描述**: IPC handle string (ref_counter_handle) passed directly to RefcountedMapAllocator::makeDataPtr without validation. The handle comes from Python bytes passed across processes via IPC. A malicious process could provide a handle containing arbitrary path, potentially accessing unauthorized shared memory files.

**漏洞代码** (`torch_npu/csrc/ipc/StorageSharing.cpp:116-151`)

```c
PyObject* _ref_counter = PyTuple_GET_ITEM(args, 0);
std::string ref_counter_handle = PyBytes_AS_STRING(_ref_counter);
...
auto sptr = at::RefcountedMapAllocator::makeDataPtr(
    ref_counter_handle.c_str(),
    flags, ...)
```

**达成路径**

Python IPC call args[0] -> _ref_counter [SOURCE - IPC from other process]
PyBytes_AS_STRING(_ref_counter) -> ref_counter_handle [TAINTED]
RefcountedMapAllocator::makeDataPtr(ref_counter_handle.c_str()) [SINK - file/memory access]

**验证说明**: IPC handle (ref_counter_handle) comes directly from Python argument without validation. Genuine path traversal vulnerability - malicious process in IPC environment could pass arbitrary handle string to access unauthorized shared memory files. Requires local process compromise but attack path is valid.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

#### 深度分析

**攻击场景**

在 PyTorch 多进程训练场景中（如 `multiprocessing` 模块的 `torch.multiprocessing.spawn`），生产者进程通过 IPC 机制将 NPU Tensor 传递给消费者进程：

```
Process A (Producer):
  - 创建 NPU Tensor
  - 调用 THNPStorage_shareNpu() 生成 IPC handle
  - 将 ref_counter_handle 作为 Python bytes 传递给 Process B

Process B (Consumer):
  - 接收 IPC 参数
  - 调用 THNPStorage_newSharedNpu() 或 THNPStorage_releaseIPCCounter()
  - 直接使用 ref_counter_handle 打开共享内存文件
```

**攻击步骤**：
1. 恶意进程（已妥协的训练进程）修改 IPC 参数中的 `ref_counter_handle`
2. 将路径从预期的共享内存目录（如 `/dev/shm/`）改为任意路径：
   - `../../../etc/passwd` — 读取敏感系统文件
   - `/home/user/.ssh/id_rsa` — 窃取私钥
   - `/dev/shm/other_process_memory` — 干扰其他进程的共享内存
3. `RefcountedMapAllocator::makeDataPtr()` 尝试以读写权限打开该路径
4. 成功打开后，攻击者可读取/修改文件内容

**影响评估**

| 维度 | 评估 | 说明 |
|------|------|------|
| **数据泄露** | High | 可读取任意可访问文件（权限受限但仍有风险） |
| **数据篡改** | Medium | 可修改共享内存计数器，破坏 IPC 机制完整性 |
| **DoS** | Medium | 提供无效路径导致异常，中断训练流程 |
| **提权** | Low | 需已有进程执行权限，无直接提权路径 |

**实际风险等级**: **Medium-High**
- 在单租户本地训练场景：风险较低（需已有恶意代码执行）
- 在云训练/多租户共享集群：风险显著上升（进程隔离可能不足）

#### 修复建议

**方案一：路径白名单验证（推荐）**

```cpp
static bool isValidIPCHandle(const std::string& handle) {
    // 1. 检查路径是否在允许的共享内存目录内
    const std::string allowed_prefix = "/dev/shm/torch_npu_ipc_";
    
    // 2. 规范化路径，消除 .. 和符号链接
    char resolved[PATH_MAX];
    if (realpath(handle.c_str(), resolved) == nullptr) {
        return false; // 路径不存在或无效
    }
    
    // 3. 检查是否在白名单目录内
    if (strncmp(resolved, allowed_prefix.c_str(), allowed_prefix.size()) != 0) {
        return false;
    }
    
    // 4. 检查是否包含路径遍历字符
    if (handle.find("..") != std::string::npos) {
        return false;
    }
    
    return true;
}

static PyObject* THNPStorage_releaseIPCCounter(PyObject* _unused, PyObject* args) {
    ...
    std::string ref_counter_handle = PyBytes_AS_STRING(_ref_counter);
    
    // 添加验证
    if (!isValidIPCHandle(ref_counter_handle)) {
        TORCH_CHECK(false, "Invalid IPC handle: potential path traversal attack",
                    PTA_ERROR(ErrCode::PARAM));
    }
    
    auto sptr = at::RefcountedMapAllocator::makeDataPtr(...);
    ...
}
```

**方案二：Handle 格式验证**

IPC handle 应具有固定格式（如 UUID 或随机字符串），而非自由路径：

```cpp
// 在 THNPStorage_shareNpu() 中生成 handle 时使用固定格式
std::string generateIPCHandle() {
    // 使用 UUID 或随机字节，而非路径字符串
    std::string handle = "torch_npu_ipc_" + generateUUID();
    return handle;
}

// 验证 handle 格式而非路径
static bool isValidIPCHandleFormat(const std::string& handle) {
    // 检查格式：torch_npu_ipc_<36-char-uuid>
    if (handle.size() != 50) return false;
    if (handle.substr(0, 15) != "torch_npu_ipc_") return false;
    // 进一步验证 UUID 格式...
    return true;
}
```

**方案三：使用抽象命名空间（Linux 特有）**

Linux 支持抽象 socket 命名空间（以 `\0` 开头的路径），不在文件系统中：

```cpp
// 使用抽象命名空间，路径不存在于文件系统
std::string abstract_handle = "\0torch_npu_ipc_" + uuid;
```

**优先级**: **P0 — 立即修复**

---

### [VULN-DF-IPC-002] path_traversal - THNPStorage_newSharedNpu

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `torch_npu/csrc/ipc/StorageSharing.cpp:165-275` @ `THNPStorage_newSharedNpu`
**模块**: ipc
**跨模块**: ipc → core

**描述**: Similar IPC handle vulnerability in THNPStorage_newSharedNpu. ref_counter_handle from Python bytes (IPC argument) passed to RefcountedMapAllocator::makeDataPtr without validation.

**漏洞代码** (`torch_npu/csrc/ipc/StorageSharing.cpp:165-275`)

```c
std::string ref_counter_handle = PyBytes_AS_STRING(_ref_counter);
...
auto sptr = at::RefcountedMapAllocator::makeDataPtr(
    ctx->ref_counter_handle.c_str(),
    flags, ...)
```

**达成路径**

Python IPC args[4] -> _ref_counter [SOURCE]
PyBytes_AS_STRING(_ref_counter) -> ref_counter_handle [TAINTED]
IpcDeleterContext lambda: makeDataPtr(ctx->ref_counter_handle.c_str()) [SINK]

**验证说明**: Same pattern as VULN-DF-IPC-001. ref_counter_handle from Python IPC argument passed to makeDataPtr without validation. Malicious IPC process could specify arbitrary path.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

#### 深度分析

**与 VULN-DF-IPC-001 的关系**

此漏洞与 VULN-DF-IPC-001 共享同一根本原因，但触发时机不同：
- **VULN-DF-IPC-001**: 在 `THNPStorage_releaseIPCCounter()` 中，消费者进程释放 IPC 资源时触发
- **VULN-DF-IPC-002**: 在 `THNPStorage_newSharedNpu()` 中，消费者进程创建共享 Tensor 时触发
- **额外风险**: 漏洞代码位于 lambda deleter 中（第248-274行），延迟执行，增加攻击隐蔽性

**代码特征**

```cpp
// 第231-243行：将 handle 存储在 deleter context 中
struct IpcDeleterContext {
    std::string ref_counter_handle;  // 未验证的 handle
    ...
};

auto ctx = std::make_unique<IpcDeleterContext>();
ctx->ref_counter_handle = std::move(ref_counter_handle);  // 直接赋值

// 第264-268行：在 deleter lambda 中使用
auto sptr = at::RefcountedMapAllocator::makeDataPtr(
    ctx->ref_counter_handle.c_str(),  // 仍然未验证
    flags, ...);
```

**攻击时序**

```
[Process A] 生成 Tensor -> 传递 IPC handle
[Process B] 接收参数 -> 创建 NPU Tensor -> handle 存入 IpcDeleterContext
              ↓
[Tensor 被使用/释放] -> deleter lambda 执行 -> makeDataPtr(handle) 
              ↓
[攻击发生] 在资源释放阶段，可能比 VULN-DF-IPC-001 更隐蔽
```

**修复方案**

与 VULN-DF-IPC-001 采用相同的修复方案（路径白名单验证）。需要同时验证：
1. **第227行**: `std::string ref_counter_handle = PyBytes_AS_STRING(_ref_counter)` — 接收时验证
2. **第264行**: deleter lambda 中的 `makeDataPtr()` 调用 — 执行时二次验证

**优先级**: **P0 — 与 VULN-DF-IPC-001 同批修复**

---

### [VULN-SEC-PATH-004] path_traversal - THNPStorage_releaseIPCCounter

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `torch_npu/csrc/ipc/StorageSharing.cpp:132-144` @ `THNPStorage_releaseIPCCounter`
**模块**: ipc

**描述**: THNPStorage_releaseIPCCounter and THNPStorage_newSharedNpu accept ref_counter_handle from Python arguments and use it directly to open shared memory files via at::RefcountedMapAllocator::makeDataPtr(). A malicious Python process in a multi-process environment could specify arbitrary file paths to access or modify files outside the intended IPC mechanism.

**漏洞代码** (`torch_npu/csrc/ipc/StorageSharing.cpp:132-144`)

```c
std::string ref_counter_handle = PyBytes_AS_STRING(_ref_counter);
...
auto sptr = at::RefcountedMapAllocator::makeDataPtr(
    ref_counter_handle.c_str(),
    flags,
    sizeof(int64_t) * torch_npu::ipc::NPU_IPC_REF_COUNTER_FILE_SIZE,
    nullptr);
```

**达成路径**

Python args (external input) -> PyBytes_AS_STRING(_ref_counter) -> ref_counter_handle -> at::RefcountedMapAllocator::makeDataPtr(ref_counter_handle.c_str())

**验证说明**: Duplicate of VULN-DF-IPC-001. Same vulnerability confirmed - IPC handle passed to makeDataPtr without validation.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

#### 深度分析

**漏洞关系**

此漏洞与 VULN-DF-IPC-001 完全相同，只是由 Security Auditor 独立发现并记录。两者指向同一代码位置：
- **VULN-DF-IPC-001**: DataFlow Scanner 通过污点追踪发现
- **VULN-SEC-PATH-004**: Security Auditor 通过模式匹配发现

**Security Auditor 的补充发现**

Security Auditor 额外识别到该函数接受多个 Python 参数（args[0] 和 args[1]），但只有 args[0]（ref_counter_handle）被用于文件操作。args[1]（ref_counter_offset）用于内存偏移计算，风险较低。

**统一修复**

此漏洞应与 VULN-DF-IPC-001 统一修复，无需单独处理。修复后两个漏洞 ID 将同时失效。

**优先级**: **P0 — 与其他 IPC 漏洞同批修复**

---

### [VULN-SEC-PATH-005] path_traversal - THNPStorage_newSharedNpu

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `torch_npu/csrc/ipc/StorageSharing.cpp:227-268` @ `THNPStorage_newSharedNpu`
**模块**: ipc

**描述**: THNPStorage_newSharedNpu accepts ref_counter_handle from Python arguments and uses it to open shared memory files. Same vulnerability as VULN-SEC-PATH-004 but in different function.

**漏洞代码** (`torch_npu/csrc/ipc/StorageSharing.cpp:227-268`)

```c
std::string ref_counter_handle = PyBytes_AS_STRING(_ref_counter);
...
auto sptr = at::RefcountedMapAllocator::makeDataPtr(
    ctx->ref_counter_handle.c_str(),
    flags,
    sizeof(int64_t) * torch_npu::ipc::NPU_IPC_REF_COUNTER_FILE_SIZE,
    nullptr);
```

**达成路径**

Python args (external input) -> PyBytes_AS_STRING(_ref_counter) -> ref_counter_handle -> at::RefcountedMapAllocator::makeDataPtr()

**验证说明**: Duplicate of VULN-DF-IPC-002. Same vulnerability confirmed - IPC handle passed to makeDataPtr without validation.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 5

#### 深度分析

**漏洞关系**

此漏洞与 VULN-DF-IPC-002 完全相同，由 Security Auditor 独立发现。两者指向同一代码位置的 deleter lambda 中的 `makeDataPtr()` 调用。

**Security Auditor 补充发现**

Security Auditor 强调了该函数接受 8 个 Python 参数（args[0] 到 args[7]），其中 args[4]（ref_counter_handle）是最危险的参数，用于文件操作。其他参数（如 args[0] 的 device index、args[1] 的 handle）虽也来自 IPC，但使用方式相对安全。

**统一修复**

此漏洞应与 VULN-DF-IPC-002 统一修复。修复后两个漏洞 ID 将同时失效。

**优先级**: **P0 — 与其他 IPC 漏洞同批修复**

---

## IPC 漏洞统一修复方案

上述 4 个 LIKELY 漏洞本质上是同一安全问题在不同函数和不同 Scanner 中的表现。建议采用统一修复方案：

### 修复要点

1. **在 `StorageSharing.cpp` 中添加验证函数**：
   ```cpp
   namespace torch_npu {
   namespace ipc {
   
   bool validateIPCHandle(const std::string& handle) {
       // 实现路径白名单验证（见 VULN-DF-IPC-001 的修复建议）
   }
   
   } // namespace ipc
   } // namespace torch_npu
   ```

2. **在所有 IPC handle 使用点添加验证**：
   - `THNPStorage_releaseIPCCounter()` 第132行
   - `THNPStorage_newSharedNpu()` 第227行和第264行（deleter lambda）

3. **测试验证**：
   - 创建恶意 IPC handle 测试用例
   - 验证白名单机制有效阻止路径遍历
   - 确保正常 IPC 机制不受影响

### 修复后效果

修复一个文件（`StorageSharing.cpp`）将同时解决 4 个 LIKELY 漏洞，显著降低代码维护负担。

---

## 4. Medium 漏洞 (3)

### [VULN-DF-FILE-001] path_traversal - checkAndMakePath, createFile

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `torch_npu/csrc/distributed/ProcessGroupHCCL.cpp:404-422` @ `checkAndMakePath, createFile`
**模块**: distributed

**描述**: File path operations in ProcessGroupHCCL with potential tainted input. checkAndMakePath() and createFile() take const char* path parameters that could come from environment variables or configuration without validation.

**漏洞代码** (`torch_npu/csrc/distributed/ProcessGroupHCCL.cpp:404-422`)

```c
if (access(path, W_OK) != 0 && mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP) != 0) {
...
int fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);
```

**达成路径**

Function parameter: path [POTENTIAL_TAINTED]
access(path, W_OK), mkdir(path, ...) [CHECK/CREATE]
open(path, O_WRONLY | O_CREAT) [SINK]

**验证说明**: Path comes from TORCH_HCCL_STATUS_SAVE_PATH environment variable. Requires attacker to have shell/environment access. Functions checkAndMakePath/createFile lack path traversal validation. Lower severity due to local access requirement.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: -10 | cross_file: 15

---

### [VULN-SEC-PATH-001] path_traversal - createFile

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `torch_npu/csrc/distributed/ProcessGroupHCCL.cpp:415-422` @ `createFile`
**模块**: distributed
**跨模块**: distributed → core

**描述**: createFile() creates files at arbitrary paths without validation. The function uses open() with O_CREAT flag directly on the path parameter. If the path comes from environment variables or other tainted sources, an attacker could create arbitrary files or overwrite sensitive files.

**漏洞代码** (`torch_npu/csrc/distributed/ProcessGroupHCCL.cpp:415-422`)

```c
void createFile(const char* path)
{
    int fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd == -1) {
        throw std::runtime_error("Create file failed. Please check whether input file is valid." + DIST_ERROR(ErrCode::NOT_FOUND));
    }
    close(fd);
}
```

**达成路径**

Environment variables (HCCL_STATUS_SAVE_PATH, etc) -> OptionsManager.GetStatusSavePath() -> checkAndMakePath() -> createFile() -> open(path, O_CREAT)

**验证说明**: createFile() uses open(O_CREAT) on environment-controlled path without validation. Requires local environment access. Same underlying issue as VULN-DF-FILE-001.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: -10 | cross_file: 15

---

### [VULN-SEC-PATH-002] path_traversal - checkAndMakePath

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `torch_npu/csrc/distributed/ProcessGroupHCCL.cpp:404-413` @ `checkAndMakePath`
**模块**: distributed
**跨模块**: distributed → core

**描述**: checkAndMakePath() creates directories at arbitrary paths without validation. The function calls mkdir() directly on the path parameter without checking for path traversal sequences (../) or validating the path against a whitelist.

**漏洞代码** (`torch_npu/csrc/distributed/ProcessGroupHCCL.cpp:404-413`)

```c
void checkAndMakePath(const char* path, std::string errormessage)
{
    try {
        if (access(path, W_OK) != 0 && mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP) != 0) {
            throw std::exception();
        }
    } catch (std::exception& e) {
        throw std::runtime_error(errormessage + DIST_ERROR(ErrCode::NOT_FOUND));
    }
}
```

**达成路径**

Environment variables -> OptionsManager.GetStatusSavePath() -> checkAndMakePath(status_save_path.c_str()) -> mkdir(path)

**验证说明**: checkAndMakePath() uses mkdir() on environment-controlled path without validation. Requires local environment access. Same underlying issue as VULN-DF-FILE-001.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: -10 | cross_file: 15

---

## 5. Low 漏洞 (3)

### [VULN-DF-NET-001] improper_input_validation - ClientIoContext::ReceiveData

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `torch_npu/csrc/distributed/ParallelTcpServer.cpp:34-60` @ `ClientIoContext::ReceiveData`
**模块**: distributed

**描述**: Network message unpacking in ClientIoContext::ReceiveData() without visible size validation. Data read from socket is unpacked into StoreMessage structure. Malformed or oversized messages could cause parsing errors or unexpected behavior.

**漏洞代码** (`torch_npu/csrc/distributed/ParallelTcpServer.cpp:34-60`)

```c
auto count = read(fd_, recBuf_.data() + recSize_, recBuf_.size() - recSize_);
...
while ((used = StoreMessagePacker::Unpack(recBuf_, request)) > 0) {
    requests_.emplace_back(std::move(request));
```

**达成路径**

read(fd_, ...) -> recBuf_ [SOURCE - network socket]
StoreMessagePacker::Unpack(recBuf_, request) [PARSE]
requests_.emplace_back(request) [USE]

**验证说明**: Network message unpacking without explicit size validation. Potential DoS via oversized messages but buffer appears bounded. Not memory corruption - lower severity. Requires network access to distributed training.

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-NET-002] improper_input_validation - Client::SyncCall

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `torch_npu/csrc/distributed/StoreClient.cpp:202-251` @ `Client::SyncCall`
**模块**: distributed

**描述**: Client-side network message unpacking without visible validation. Response data from server is unpacked without size checks.

**漏洞代码** (`torch_npu/csrc/distributed/StoreClient.cpp:202-251`)

```c
ret = read(socketFd_, buffer, READ_BUF_SZ);
responseBuf.insert(responseBuf.end(), buffer, buffer + ret);
...
auto unpackRet = StoreMessagePacker::Unpack(responseBuf, response);
```

**达成路径**

read(socketFd_, buffer) [SOURCE - network]
responseBuf.insert() [BUFFER]
StoreMessagePacker::Unpack(responseBuf, response) [PARSE]

**验证说明**: Client-side network unpacking similar to VULN-DF-NET-001. DoS potential, not memory corruption. Requires network access.

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-PATH-008] path_traversal - ValidPathCheck

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `torch_npu/csrc/framework/interface/EnvVariables.cpp:18-24` @ `ValidPathCheck`
**模块**: framework
**跨模块**: framework → core

**描述**: ValidPathCheck() only verifies that a path exists using realpath(), but does not validate against malicious paths or path traversal sequences. The validated path is then passed to aclmdlSetDump() which could create files at arbitrary locations.

**漏洞代码** (`torch_npu/csrc/framework/interface/EnvVariables.cpp:18-24`)

```c
void ValidPathCheck(const std::string& file_path)
{
    char abs_path[PATH_MAX] = {'\0'};
    if (realpath(file_path.c_str(), abs_path) == nullptr) {
        TORCH_CHECK(0, "configPath path Fails, path ", (char*)file_path.c_str(), PTA_ERROR(ErrCode::PTR));
    }
}
```

**达成路径**

Environment variable -> REGISTER_OPTION_HOOK(mdldumpconfigpath) -> ValidPathCheck(val) -> aclmdlSetDump(val.c_str())

**验证说明**: ValidPathCheck uses realpath() to verify path exists - this prevents creating new files but doesn't prevent path traversal if attacker controls env. Path comes from mdldumpconfigpath environment option. Requires local config access. Low practical risk.

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: -5 | context: -10 | cross_file: 15

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| distributed | 0 | 0 | 3 | 2 | 5 |
| framework | 0 | 0 | 0 | 1 | 1 |
| ipc | 0 | 4 | 0 | 0 | 4 |
| **合计** | **0** | **4** | **3** | **3** | **10** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 8 | 80.0% |
| CWE-20 | 2 | 20.0% |

---

## 8. 整体安全建议

### 8.1 核心问题总结

本次扫描发现 torch_npu 项目存在两个核心安全问题：

1. **路径验证缺失（CWE-22）** — 占漏洞总数的 80%
   - IPC 模块（High 严重性）：跨进程通信中路径未经白名单验证
   - Distributed 模块（Medium 严重性）：环境变量控制的文件路径缺乏规范化
   - Framework 模块（Low 严重性）：`realpath()` 验证不足以阻止路径遍历

2. **输入验证不足（CWE-20）** — 分布式训练网络接口
   - 网络消息解析缺乏大小限制
   - DoS 风险（非内存破坏）

### 8.2 修复优先级矩阵

| 优先级 | 模块 | 漏洞数量 | 建议时间 | 关键措施 |
|--------|------|----------|----------|----------|
| **P0** | ipc | 4 | 1-2 周 | 实现 IPC handle 白名单验证 |
| **P1** | distributed (path) | 3 | 2-3 周 | 环境变量路径规范化 + 白名单 |
| **P2** | distributed (net) | 2 | 3-4 周 | 消息大小限制 + 解析异常处理 |
| **P3** | framework | 1 | 4-5 周 | `ValidPathCheck` 增强（二次验证） |

### 8.3 架构层面建议

#### 1. 建立统一路径验证模块

```cpp
// 建议创建：torch_npu/csrc/core/utils/PathValidator.h
namespace torch_npu {
namespace core {
namespace utils {

class PathValidator {
public:
    // 验证路径是否在白名单目录内
    static bool isInAllowedDirectory(const std::string& path, 
                                      const std::vector<std::string>& allowed_dirs);
    
    // 规范化路径并消除遍历字符
    static std::string normalize(const std::string& path);
    
    // 验证 IPC handle 格式（UUID 或固定前缀）
    static bool isValidIPCHandleFormat(const std::string& handle);
    
    // 验证环境变量路径（相对/绝对路径转换）
    static std::string validateEnvPath(const std::string& env_var_name,
                                        const std::string& default_value);
};

} // namespace utils
} // namespace core
} // namespace torch_npu
```

**适用范围**：
- IPC 模块（StorageSharing.cpp）
- Distributed 模块（ProcessGroupHCCL.cpp）
- Framework 模块（EnvVariables.cpp）

#### 2. 安全编码规范

| 规范 | 要求 | 检查点 |
|------|------|--------|
| **外部输入验证** | 所有来自 IPC/网络/环境变量的数据必须验证 | Code review checklist |
| **路径操作** | 使用 `realpath()` + 白名单双重验证 | Static analysis hook |
| **文件创建** | 禁止在用户可控路径创建文件 | Filesystem audit |
| **错误处理** | 安全相关错误应记录日志并优雅拒绝 | Logging policy |

#### 3. 测试覆盖

建议添加以下安全测试用例：

```python
# tests/security/ipc_path_traversal_test.py
def test_ipc_malicious_handle():
    """测试 IPC handle 路径遍历攻击被阻止"""
    malicious_handle = "../../../etc/passwd"
    with pytest.raises(SecurityError):
        storage._release_ipc_counter(malicious_handle, 0)

def test_ipc_absolute_path_outside_whitelist():
    """测试绝对路径被白名单拒绝"""
    malicious_handle = "/tmp/malicious_file"
    with pytest.raises(SecurityError):
        storage._new_shared_npu(..., malicious_handle, ...)
```

### 8.4 云环境特殊建议

针对云训练/多租户场景的额外安全措施：

| 掻施 | 实现方式 | 防护目标 |
|------|----------|----------|
| **进程隔离增强** | 使用容器沙箱或 seccomp | 防止 IPC 漏洞横向传播 |
| **环境变量审计** | 启动时验证所有 HCCL_* 变量 | 防止路径注入 |
| **文件系统隔离** | 挂载独立的 `/dev/shm` namespace | 防止共享内存越权访问 |
| **日志监控** | 记录所有 IPC handle 创建/释放 | 检测异常路径模式 |

### 8.5 风险接受评估

对于暂时不修复的漏洞，建议进行风险接受评估：

| 漏洞 ID | 风险接受条件 | 监控措施 | 接受期限 |
|---------|--------------|----------|----------|
| VULN-DF-NET-001/002 | 仅本地训练环境使用 | 监控异常网络流量 | 下个版本周期 |
| VULN-SEC-PATH-008 | 无云训练部署计划 | 定期审查环境变量配置 | 暂不修复 |

**不接受条件**：任何云或多租户部署前，必须修复所有 P0/P1 漏洞。

---

## 9. 结论

torch_npu 的 IPC 共享内存机制存在明确的安全漏洞，需要立即采取行动。建议按照优先级矩阵逐步修复，并在修复过程中同步建立安全编码规范和测试覆盖，防止同类漏洞再次引入。

**关键行动项**：
1. ✅ 立即实施 IPC handle 白名单验证（P0）
2. ✅ 建立统一路径验证模块（架构层面）
3. ✅ 添加安全测试用例（持续保障）
4. ⏳ 云部署前完成 P0-P2 漏洞修复（准入门槛）

---

**报告生成**: OpenCode Vulnerability Scanner  
**Reporter Agent**: Completed with enhanced analysis  
**最后更新**: 2026-04-24
