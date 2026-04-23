# 漏洞扫描报告 — 待确认漏洞

**项目**: triton-inference-server-ge-backend
**扫描时间**: 2026-04-22T10:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 13 | 44.8% |
| LIKELY | 10 | 34.5% |
| POSSIBLE | 5 | 17.2% |
| CONFIRMED | 1 | 3.4% |
| **总计** | **29** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 7 | 46.7% |
| Medium | 7 | 46.7% |
| Low | 1 | 6.7% |
| **有效漏洞总计** | **15** | - |
| 误报 (FALSE_POSITIVE) | 13 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-INF-005]** Missing Input Validation (High) - `src/inference.cpp:283` @ `ProcessRequestInputsV2` | 置信度: 75
2. **[VULN-SEC-INT-005]** integer_overflow (High) - `src/inference.cpp:330` @ `AllocateCombinedMemoryV2` | 置信度: 65
3. **[VULN-INF-002]** Integer Overflow (High) - `src/inference.cpp:268` @ `AllocateSingleMemoryV2` | 置信度: 65
4. **[VULN-INF-003]** Integer Overflow (High) - `src/inference.cpp:336` @ `AllocateCombinedMemoryV2` | 置信度: 65
5. **[VULN-BACKEND-API-001]** Missing Input Validation (High) - `/home/pwn20tty/Desktop/opencode_project/cann/4/triton-inference-server-ge-backend/src/npu_ge.cpp:165` @ `TRITONBACKEND_ModelInstanceExecute` | 置信度: 65
6. **[VULN-BACKEND-API-002]** Unchecked API Return (High) - `/home/pwn20tty/Desktop/opencode_project/cann/4/triton-inference-server-ge-backend/src/inference.cpp:282` @ `ProcessRequestInputsV2` | 置信度: 65
7. **[VULN-BACKEND-API-003]** Buffer Overflow Potential (High) - `/home/pwn20tty/Desktop/opencode_project/cann/4/triton-inference-server-ge-backend/src/inference.cpp:253` @ `AllocateSingleMemoryV2` | 置信度: 65
8. **[VULN-BACKEND-API-004]** Out-of-Bounds Access (Medium) - `/home/pwn20tty/Desktop/opencode_project/cann/4/triton-inference-server-ge-backend/src/inference.cpp:1337` @ `SetBatchTaskAndResult` | 置信度: 65
9. **[VULN-BACKEND-API-005]** Integer Overflow (Medium) - `/home/pwn20tty/Desktop/opencode_project/cann/4/triton-inference-server-ge-backend/src/inference.cpp:237` @ `AllocateSingleMemoryV2` | 置信度: 65
10. **[VULN-SEC-MEM-007]** memory_safety (Medium) - `src/inference.cpp:525` @ `ExecuteInferenceCycleV2` | 置信度: 60

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `TRITONBACKEND_ModelInstanceExecute@src/npu_ge.cpp` | rpc | semi_trusted | 作为 Triton Backend API 入口点，接收来自 Triton Server 的推理请求。这些请求最初来自远程客户端（HTTP/GRPC），经过 Triton Server 处理后传递给 backend。虽然 Triton Server 可能对请求进行了部分验证，但 backend 需要处理原始推理请求数据。 | 接收推理请求并调用 ProcessRequests 处理 |
| `ParseGeConfig@src/model_state.cpp` | env | trusted_admin | 解析 backend 配置，这些配置来自 Triton Server 的命令行参数（--backend-config），由部署管理员控制。攻击者无法直接修改这些配置。 | 解析 backend 命令行配置 JSON |
| `ParseModelConfig@src/model_state.cpp` | file | trusted_admin | 解析模型配置文件 config.pbtxt，该文件位于模型仓库目录中，由部署管理员准备。攻击者无法直接修改模型配置文件（需要管理员权限）。 | 解析 Triton 模型配置文件 |
| `FindModelFile@src/model_state.cpp` | file | trusted_admin | 查找模型文件（ONNX/TensorFlow pb），路径来自模型配置，由部署管理员控制。攻击者无法直接修改模型文件。 | 查找并加载模型文件 |
| `GetEnvVar@src/model_instance_state.cpp` | env | trusted_admin | 读取环境变量 GE_NPU_CONFIG，该环境变量由 Triton Server 启动脚本设置，由部署管理员控制。 | 读取 GE_NPU_CONFIG 环境变量 |
| `ProcessRequestInputsV2@src/inference.cpp` | rpc | semi_trusted | 处理来自 Triton Server 请求的输入数据。这些数据最初来自远程客户端推理请求，需要验证数据尺寸和类型。 | 处理推理请求的输入张量数据 |
| `SetDumpGraph@src/model_state.cpp` | file | trusted_admin | 设置图 dump 路径并执行清理命令。路径来自配置参数，由部署管理员控制。代码中有基本的命令注入过滤（检查 ; & \| 字符）。 | 设置 GE 图 dump 配置并执行清理命令 |

**其他攻击面**:
- Backend API: TRITONBACKEND_ModelInstanceExecute 接收推理请求
- 配置解析: ParseGeConfig 解析 backend 命令行配置
- 模型配置解析: ParseModelConfig 解析 config.pbtxt
- 模型加载: FindModelFile 查找并加载 ONNX/TensorFlow 模型
- 请求输入处理: ProcessRequestInputsV2 处理推理输入张量
- 命令执行: system() 在 SetDumpGraph 中执行路径清理命令（有基本过滤）
- 内存操作: aclrtMemcpy 在多处执行设备-主机内存复制
- JSON 解析: json::parse 解析 GE 配置
- 环境变量: getenv/setenv 读取和设置环境变量
- 文件系统遍历: std::filesystem 递归查找模型文件

---

## 3. High 漏洞 (7)

### [VULN-INF-005] Missing Input Validation - ProcessRequestInputsV2

**严重性**: High | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/inference.cpp:283-292` @ `ProcessRequestInputsV2`
**模块**: inference_engine

**描述**: Missing upper bound validation for TRITONBACKEND_InputProperties shape values. The shape array returned from TRITONBACKEND_InputProperties contains dimension sizes controlled by remote clients. These values are used directly in memory size calculations without validation for reasonable upper bounds. Malicious input with extremely large dimension values can cause excessive memory allocation or integer overflow in downstream calculations.

**漏洞代码** (`src/inference.cpp:283-292`)

```c
const int64_t *shape;\nuint32_t dims_count;\n...\nTRITONBACKEND_InputProperties(input, &input_name, &datatype, &shape, &dims_count, nullptr, nullptr);\n// No validation of shape values\nTRITONBACKEND_InputBuffer(input, 0, &buffer, &buffer_size, &memory_type, &memory_type_id);
```

**达成路径**

TRITONBACKEND_Request -> TRITONBACKEND_RequestInput -> TRITONBACKEND_InputProperties(shape, dims_count) -> AllocateSingleMemoryV2 -> memory operations

**验证说明**: No upper bound validation for shape values from TRITONBACKEND_InputProperties. Shape[0] used directly for batch_result (line 1338), shape values used in per_buffer_size/total_out_size calculations enabling downstream integer overflow attacks.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-INT-005] integer_overflow - AllocateCombinedMemoryV2

**严重性**: High | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/inference.cpp:330-358` @ `AllocateCombinedMemoryV2`
**模块**: inference_engine

**描述**: AllocateCombinedMemoryV2 函数中，total_out_size 通过连续乘法计算：sample_element_size * batch_total * dims[k]。对于大批次和复杂张量维度，可能发生整数溢出，导致分配过小的内存，后续 aclrtMemcpy 会写入超出分配范围的数据。

**漏洞代码** (`src/inference.cpp:330-358`)

```c
int64_t total_out_size = static_cast<int64_t>(sample_element_size);
total_out_size *= batch_total;
for (size_t k = 0; k < dims_in.size(); k++) {
    total_out_size *= dims_in[k];
}
acl_ret = aclrtMalloc(&indev_buffer, total_out_size, ACL_MEM_MALLOC_NORMAL_ONLY);
```

**达成路径**

[SOURCE] batch_total 来自请求批次
[PROCESS] total_out_size *= batch_total * dims
[SINK] aclrtMalloc → 可能分配过小内存

**验证说明**: Same vulnerability as VULN-INF-003 - AllocateCombinedMemoryV2 total_out_size overflow. Duplicate from security-auditor.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-INF-002] Integer Overflow - AllocateSingleMemoryV2

**严重性**: High | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/inference.cpp:268-271` @ `AllocateSingleMemoryV2`
**模块**: inference_engine

**描述**: Integer overflow in per_buffer_size calculation at AllocateSingleMemoryV2. The per_buffer_size variable (int type) is multiplied by shape[k] values from untrusted input in a loop. Integer overflow can cause per_buffer_size to become negative or unexpectedly small, leading to incorrect buffer offset calculations when used in ProcessRequestInputsV2 for memcpy destination offset computation.

**漏洞代码** (`src/inference.cpp:268-271`)

```c
int per_buffer_size = sample_element_size;\nfor (size_t k = index; k < dims_count; k++) {\n    per_buffer_size *= shape[k];\n}\nindev_line_size_.push_back(per_buffer_size);
```

**达成路径**

TRITONBACKEND_InputProperties(shape) -> AllocateSingleMemoryV2 -> per_buffer_size *= shape[k] -> indev_line_size_ -> ProcessRequestInputsV2 offset

**验证说明**: per_buffer_size (int type) overflow at line 269 from shape[k] multiplication. Overflowed value stored in indev_line_size_ used for offset calculations in aclrtMemcpy causing potential OOB write.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-INF-003] Integer Overflow - AllocateCombinedMemoryV2

**严重性**: High | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/inference.cpp:336-357` @ `AllocateCombinedMemoryV2`
**模块**: inference_engine

**描述**: Integer overflow in AllocateCombinedMemoryV2. total_out_size computed by multiplying batch_total and dims_in without overflow check, leading to heap overflow.

**漏洞代码** (`src/inference.cpp:336-357`)

```c
total_out_size *= batch_total;\nfor (size_t k = 0; k < dims_in.size(); k++) {\n    total_out_size *= dims_in[k];\n}
```

**达成路径**

batch_total -> AllocateCombinedMemoryV2 -> total_out_size overflow

**验证说明**: total_out_size (int64_t) overflow from batch_total * dims_in[k] at lines 344-346. Uses total_out_size for aclrtMalloc allocation (line 350) - real vulnerability. Overflow requires extremely large values due to int64_t type but exploitable.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-BACKEND-API-001] Missing Input Validation - TRITONBACKEND_ModelInstanceExecute

**严重性**: High | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/4/triton-inference-server-ge-backend/src/npu_ge.cpp:165-183` @ `TRITONBACKEND_ModelInstanceExecute`
**模块**: backend_api

**描述**: TRITONBACKEND_ModelInstanceExecute entry point lacks validation of request_count and requests pointer array. No null check on request pointers before processing.

**达成路径**

TRITONBACKEND_Request -> ProcessRequests -> HandleRequest

**验证说明**: Confirmed: TRITONBACKEND_ModelInstanceExecute entry point lacks validation. No null check on 'requests' pointer array before dereferencing at ProcessRequests call (line 175). No validation of 'request_count' boundary. Trust boundary: semi_trusted from Triton Server. Exploitable if Triton passes malformed request array.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-BACKEND-API-002] Unchecked API Return - ProcessRequestInputsV2

**严重性**: High | **CWE**: CWE-252 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/4/triton-inference-server-ge-backend/src/inference.cpp:282-292` @ `ProcessRequestInputsV2`
**模块**: backend_api

**描述**: TRITONBACKEND_RequestInput/TRITONBACKEND_InputProperties/TRITONBACKEND_InputBuffer return values not checked. Uninitialized pointers used in aclrtMemcpy.

**达成路径**

TRITONBACKEND_Request -> unchecked APIs -> aclrtMemcpy

**验证说明**: Confirmed: TRITONBACKEND_RequestInput (line 282), TRITONBACKEND_InputProperties (line 287), TRITONBACKEND_InputBuffer (line 292) return values not checked. If any API fails, 'input', 'shape', 'buffer' pointers remain uninitialized, leading to potential crashes or memory corruption in subsequent aclrtMemcpy calls (lines 303-305, 312).

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-BACKEND-API-003] Buffer Overflow Potential - AllocateSingleMemoryV2

**严重性**: High | **CWE**: CWE-787 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/4/triton-inference-server-ge-backend/src/inference.cpp:253-258` @ `AllocateSingleMemoryV2`
**模块**: backend_api

**描述**: aclrtMemcpy uses buffer_size directly without upper bound validation. Cross-module: flows to acl runtime.

**达成路径**

buffer_size -> aclrtMemcpy

**验证说明**: Confirmed: aclrtMemcpy uses buffer_size directly without upper bound validation. buffer_size comes from TRITONBACKEND_InputBuffer (line 292, unchecked return). While aclrtMalloc allocates buffer_size (line 246), no check ensures buffer_size fits within device memory limits. Cross-module note: 'acl runtime' refers to external Ascend ACL API, not internal inference_engine module.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (7)

### [VULN-BACKEND-API-004] Out-of-Bounds Access - SetBatchTaskAndResult

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/4/triton-inference-server-ge-backend/src/inference.cpp:1337-1338` @ `SetBatchTaskAndResult`
**模块**: backend_api

**描述**: shape[0] accessed without verifying dims_count>0.

**达成路径**

shape -> shape[0]

**验证说明**: Confirmed: shape[0] accessed at line 1338 without verifying dims_count > 0. TRITONBACKEND_InputProperties return value also unchecked (line 1337). If API fails or returns dims_count=0, shape pointer may be invalid, causing out-of-bounds read. Triton API typically guarantees dims_count>=1 for valid tensors, but unchecked return means failure case is unprotected.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-BACKEND-API-005] Integer Overflow - AllocateSingleMemoryV2

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/4/triton-inference-server-ge-backend/src/inference.cpp:237-241` @ `AllocateSingleMemoryV2`
**模块**: backend_api

**描述**: total_out_size multiplication chain without overflow check.

**达成路径**

shape[] -> total_out_size overflow

**验证说明**: Confirmed: Integer overflow in multiplication chain. Lines 237-241: total_out_size starts as int64_t(sample_element_size), then multiplied by shape[i] values in loop. No overflow check before using total_out_size for aclrtMalloc (line 246). Large input tensor dimensions could cause overflow, leading to undersized allocation and subsequent buffer overflow in aclrtMemcpy.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-MEM-007] memory_safety - ExecuteInferenceCycleV2

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/inference.cpp:525-580` @ `ExecuteInferenceCycleV2`
**模块**: inference_engine

**描述**: ExecuteInferenceCycleV2 函数中，内存偏移计算使用 (input_offset[instance_index] + k) * line_size，如果 input_offset 数组索引越界或偏移值异常，可能导致读取或写入超出分配内存范围。

**漏洞代码** (`src/inference.cpp:525-580`)

```c
void *src_ptr = (void *)((BYTE_PTR)indev_buffer_[j] + (input_offset[instance_index] + k) * indev_line_size_[j]);
aclrtMemcpy(inputs[j].GetAddr(), buffer_size, src_ptr, buffer_size, ACL_MEMCPY_DEVICE_TO_DEVICE);
```

**达成路径**

[SOURCE] input_offset → 批次偏移
[PROCESS] 偏移 * line_size 计算
[SINK] aclrtMemcpy → 可能越界访问

**验证说明**: Offset calculation (input_offset[instance_index] + k) * indev_line_size_[j] at line 540 lacks bounds validation. input_offset from cumulative batch_result sum, k from cycle_count loop. No validation that calculated offset stays within allocated buffer.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-INF-004] Buffer Overflow - ProcessRequestInputsV2

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/inference.cpp:292-310` @ `ProcessRequestInputsV2`
**模块**: inference_engine

**描述**: Missing size validation before aclrtMemcpy in ProcessRequestInputsV2. The buffer_size from TRITONBACKEND_InputBuffer (remote client controlled) is used directly in aclrtMemcpy without upper bound validation. A malicious client can send a large buffer_size that exceeds allocated buffer, or the destination offset calculation (input_offset[request_index] * indev_line_size_[j]) can overflow causing out-of-bounds write. The size check at line 294 only validates consistency with expected size but does not prevent overflow in offset calculation.

**漏洞代码** (`src/inference.cpp:292-310`)

```c
TRITONBACKEND_InputBuffer(input, 0, &buffer, &buffer_size, &memory_type, &memory_type_id);\n...\naclrtMemcpy(static_cast<char *>(indev_buffer_[j]) + input_offset[request_index] * indev_line_size_[j],\n            buffer_size, buffer, buffer_size, ACL_MEMCPY_HOST_TO_DEVICE);
```

**达成路径**

TRITONBACKEND_Request -> TRITONBACKEND_RequestInput -> TRITONBACKEND_InputBuffer(buffer_size) -> ProcessRequestInputsV2 -> offset overflow -> aclrtMemcpy

**验证说明**: Offset overflow possible in input_offset[request_index] * indev_line_size_[j]. Buffer_size validated at line 294 but offset calculation lacks bounds check. indev_line_size_ derived from shape values can overflow (int type). Input_offset is cumulative sum of batch_result (shape[0] from remote).

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [SCHED-DTOR-001] Missing Cleanup - Scheduler::~Scheduler

**严重性**: Medium | **CWE**: CWE-404 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/scheduler.cpp:305-307` @ `Scheduler::~Scheduler`
**模块**: scheduler

**描述**: Scheduler 析构函数为空，没有通知可能在 cv.wait() 上等待的线程。如果有线程正在 WaitForIdleInstances 中等待条件变量，析构时可能导致未定义行为或程序崩溃。

**漏洞代码** (`src/scheduler.cpp:305-307`)

```c
Scheduler::~Scheduler()
{
    // 空析构函数，没有通知等待中的线程
}
```

**达成路径**

析构时可能有线程在 cv.wait() 等待 -> 未定义行为

**验证说明**: 设计缺陷：Scheduler 析构函数为空，未通知可能在 cv.wait() 上等待的线程。若有线程在 WaitForIdleInstances 中阻塞，析构时会导致未定义行为。当前代码路径显示 GetIdleInstances 在推理请求中使用，若 Scheduler 在请求处理中被销毁，将触发此问题。严重性 Medium。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0 | adjustment: 20

---

### [VULN-INF-006] Integer Overflow - ProcessRequestInputsV2

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/inference.cpp:304-305` @ `ProcessRequestInputsV2`
**模块**: inference_engine

**描述**: Integer overflow in offset calculation during batch combine. input_offset[request_index] * indev_line_size_[j] can overflow causing out-of-bounds write in aclrtMemcpy destination.

**达成路径**

ProcessRequestInputsV2 -> input_offset * indev_line_size_ -> offset overflow -> aclrtMemcpy OOB

**验证说明**: Same as VULN-INF-004 - offset overflow input_offset[request_index] * indev_line_size_[j]. Duplicate focus on offset overflow aspect.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [SCHED-PTR-001] Use After Free - Scheduler::GetIdleInstances

**严重性**: Medium | **CWE**: CWE-416 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/scheduler.cpp:247-255` @ `Scheduler::GetIdleInstances`
**模块**: scheduler

**描述**: GetIdleInstances、SelectInstancesSimple、SelectInstancesWithLoadBalance 等方法返回指向 instances 向量内部元素的指针。如果 instances 向量被修改（如 AddInstance 添加新元素），这些指针可能失效导致悬空指针访问。

**漏洞代码** (`src/scheduler.cpp:247-255`)

```c
std::vector<Scheduler::Instance *> Scheduler::GetIdleInstances(...)
{
    std::unique_lock<std::mutex> lock(mutex);
    WaitForIdleInstances(num, lock);
    return SelectInstancesWithLoadBalance(now_context, num);  // 返回指向内部元素的指针
}
```

**达成路径**

GetIdleInstances -> 返回 Instance* -> 外部使用时 instances 可能被修改

**验证说明**: 设计风险：GetIdleInstances 返回指向 instances 向量内部元素的指针。若 AddInstance 在外部持有指针期间被调用，emplace_back 可能重新分配内存导致悬空指针。当前 AddInstance 仅在初始化阶段调用（model_instance_state.cpp:202），但设计未强制此约束。严重性 Medium，因触发需要特定的并发时序。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0 | adjustment: 15

---

## 5. Low 漏洞 (1)

### [SCHED-RC-001] Race Condition - Scheduler::HasIdleInstance

**严重性**: Low | **CWE**: CWE-362 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/scheduler.cpp:276-288` @ `Scheduler::HasIdleInstance`
**模块**: scheduler

**描述**: HasIdleInstance() 方法直接访问共享数据 instances 而没有获取锁保护。作为 public 方法，它可以在任何上下文中被调用，可能导致竞态条件。当多个线程同时访问或修改实例状态时，可能导致数据不一致或程序崩溃。

**漏洞代码** (`src/scheduler.cpp:276-288`)

```c
bool Scheduler::HasIdleInstance(int num)
{
    int res = 0;
    for (const auto &instance : instances) {  // 无锁访问共享数据
        if (instance.status == Status::IDLE) {
            res++;
        }
    }
    return res >= num;
}
```

**达成路径**

WaitForIdleInstances -> HasIdleInstance (共享数据 instances 无锁访问)

**验证说明**: 设计缺陷：HasIdleInstance 是公共方法且不获取锁，直接访问共享数据 instances。当前代码路径中仅从 WaitForIdleInstances 调用（此时锁已持有），故实际风险较低。但公共接口设计使未来可能被不安全调用。严重性降级为 Low，因当前调用路径安全。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: -15 | cross_file: 0 | adjustment: 25

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| backend_api | 0 | 3 | 2 | 0 | 5 |
| inference_engine | 0 | 4 | 3 | 0 | 7 |
| scheduler | 0 | 0 | 2 | 1 | 3 |
| **合计** | **0** | **7** | **7** | **1** | **15** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-190 | 5 | 33.3% |
| CWE-20 | 2 | 13.3% |
| CWE-125 | 2 | 13.3% |
| CWE-787 | 1 | 6.7% |
| CWE-416 | 1 | 6.7% |
| CWE-404 | 1 | 6.7% |
| CWE-362 | 1 | 6.7% |
| CWE-252 | 1 | 6.7% |
| CWE-120 | 1 | 6.7% |
