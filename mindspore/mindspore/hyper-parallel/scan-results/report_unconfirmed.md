# 漏洞扫描报告 — 待确认漏洞

**项目**: hyper-parallel
**扫描时间**: 2026-04-24T03:23:21.000Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本报告包含 **19 个待确认漏洞**（8 个 LIKELY + 15 个 POSSIBLE），需要进一步人工验证以确定其真实性和严重程度。这些漏洞主要涉及环境变量注入、配置注入、路径遍历等安全问题。

### 关键发现

1. **环境变量攻击面**: `shard` 和 `symmetric_memory` 模块存在多处环境变量注入风险（CWE-15），攻击者可通过控制 `HYPER_PARALLEL_OPS_YAML_DIR`、`HYPER_PARALLEL_OPS_PYTHON_PATH`、`MS_SCHED_HOST` 等环境变量实现代码注入或通信重定向。

2. **分布式通信风险**: `pipeline_parallel` 和 `platform` 模块的 P2P/集体通信操作使用 pickle 序列化（CWE-502），恶意节点可发送恶意 payload 攻击其他训练节点。

3. **路径遍历隐患**: `distributed_checkpoint` 和 `auto_parallel` 模块存在路径验证不足的问题（CWE-22），可能导致加载任意文件。

4. **C++ 层安全风险**: `symmetric_memory` 和 `multicore` 模块的 C++ 代码存在潜在的缓冲区溢出（CWE-120）、整数溢出和内存安全问题。

### 验证建议

| 漏洞类别 | 建议验证方法 |
|---------|------------|
| 环境变量注入 (CWE-15) | 检查环境变量是否在部署时由可信方控制 |
| 分布式通信 (CWE-502) | 验证分布式训练的安全模型和认证机制 |
| 路径遍历 (CWE-22) | 检查路径验证代码和输入来源 |
| C++ 内存安全 | 需动态测试和边界验证 |

### 优先关注

| 漏洞 ID | 类型 | 置信度 | 建议行动 |
|--------|------|--------|---------|
| VULN-DF-004 | path_traversal | 70 | 优先验证路径验证逻辑 |
| VULN-DF-005, VULN-SEC-CFG-001 | config_injection | 65 | 验证环境变量控制权限 |
| VULN-SEC-CFG-002 | code_injection | 65 | 高风险，需立即检查 importlib 使用 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 15 | 50.0% |
| LIKELY | 8 | 26.7% |
| CONFIRMED | 5 | 16.7% |
| FALSE_POSITIVE | 2 | 6.7% |
| **总计** | **30** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 13 | 68.4% |
| Medium | 6 | 31.6% |
| **有效漏洞总计** | **19** | - |
| 误报 (FALSE_POSITIVE) | 2 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-004]** path_traversal (High) - `hyper_parallel/core/distributed_checkpoint/offline_transform.py:444` @ `convert_full_checkpoint_to_dcp` | 置信度: 70
2. **[VULN-DF-005]** config_injection (High) - `hyper_parallel/core/shard/_op_dispatch.py:234` @ `OpDispatcher.__init__` | 置信度: 65
3. **[VULN-SEC-CFG-001]** configuration_injection (High) - `hyper_parallel/core/shard/_op_dispatch.py:234` @ `OpDispatcher.__init__` | 置信度: 65
4. **[VULN-SEC-CFG-002]** code_injection (High) - `hyper_parallel/core/shard/_op_dispatch.py:348` @ `_register_single_distributed_op` | 置信度: 65
5. **[VULN-DF-006]** insecure_deserialization (High) - `hyper_parallel/core/pipeline_parallel/stage.py:304` @ `PipelineStage._communicate_meta` | 置信度: 60
6. **[VULN-DF-011]** insecure_deserialization (High) - `hyper_parallel/platform/platform.py:880` @ `Platform.all_gather_object` | 置信度: 60
7. **[VULN-SEC-CFG-003]** path_injection (High) - `hyper_parallel/core/shard/_op_dispatch.py:310` @ `_extend_sys_path` | 置信度: 60
8. **[VULN-SEC-OBJ-001]** insecure_deserialization (High) - `hyper_parallel/platform/platform.py:879` @ `Platform.all_gather_object` | 置信度: 60
9. **[VULN-DF-010]** config_injection (High) - `hyper_parallel/core/symmetric_memory/platform/mindspore/c_api/allocator/symmetric_memory_allocator.cc:86` @ `initialize_npushmem` | 置信度: 55
10. **[VULN-DF-CROSS-004]** config_injection (High) - `hyper_parallel/core/symmetric_memory/platform/mindspore/c_api/allocator/symmetric_memory_allocator.cc:55` @ `GetShmemIpPort` | 置信度: 55

---

## 2. 攻击面分析

未找到入口点数据。


---

## 3. High 漏洞 (13)

### [VULN-DF-004] path_traversal - convert_full_checkpoint_to_dcp

**严重性**: High | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `hyper_parallel/core/distributed_checkpoint/offline_transform.py:444-493` @ `convert_full_checkpoint_to_dcp`
**模块**: distributed_checkpoint

**描述**: User-provided checkpoint path (src_ckpt) is directly used to load checkpoint files without path validation. Allows loading arbitrary files from filesystem.

**漏洞代码** (`hyper_parallel/core/distributed_checkpoint/offline_transform.py:444-493`)

```c
if src_platform == 'torch':\n    state_dict = platform.load_checkpoint(str(src_ckpt), ckpt_format=fmt)
```

**达成路径**

convert_full_checkpoint_to_dcp(src_ckpt, dst_dir, src_platform) [SOURCE: user input]\n-> platform.load_checkpoint(str(src_ckpt))\n-> torch.load(src_ckpt) [SINK: CWE-22]

**验证说明**: Verified: src_ckpt path is validated for file existence but not sanitized against path traversal. User provides path directly to convert_full_checkpoint_to_dcp(). Combined with VULN-DF-003, enables loading arbitrary files.

**评分明细**: base: 30 | context: 0 | controllability: 20 | cross_file: 0 | mitigations: -10 | reachability: 30

---

### [VULN-DF-005] config_injection - OpDispatcher.__init__

**严重性**: High | **CWE**: CWE-15 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `hyper_parallel/core/shard/_op_dispatch.py:234-355` @ `OpDispatcher.__init__`
**模块**: shard

**描述**: Environment variables HYPER_PARALLEL_OPS_YAML_DIR and HYPER_PARALLEL_OPS_PYTHON_PATH control YAML loading paths and Python module imports, enabling arbitrary code execution via malicious YAML configs or imported modules.

**漏洞代码** (`hyper_parallel/core/shard/_op_dispatch.py:234-355`)

```c
self._env_yaml_dir: Optional[str] = os.environ.get('HYPER_PARALLEL_OPS_YAML_DIR')\nself._env_python_path: Optional[str] = os.environ.get('HYPER_PARALLEL_OPS_PYTHON_PATH')\n...\nmodule = importlib.import_module(module_file)
```

**达成路径**

os.environ.get('HYPER_PARALLEL_OPS_YAML_DIR/PYTHON_PATH') [SOURCE]\n-> safe_load_yaml_from_dir()\n-> _register_single_distributed_op()\n-> importlib.import_module(env_python_path) [SINK: CWE-15]

**验证说明**: Verified: Environment variables HYPER_PARALLEL_OPS_YAML_DIR and HYPER_PARALLEL_OPS_PYTHON_PATH allow arbitrary YAML/Python module loading. However, environment variables are typically controlled by trusted administrators in production. Requires root/admin level compromise to exploit. Code injection via sys.path.insert(0, path) and importlib.import_module().

**评分明细**: base: 30 | context: -5 | controllability: 20 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-SEC-CFG-001] configuration_injection - OpDispatcher.__init__

**严重性**: High | **CWE**: CWE-15 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `hyper_parallel/core/shard/_op_dispatch.py:234-240` @ `OpDispatcher.__init__`
**模块**: shard

**描述**: HYPER_PARALLEL_OPS_YAML_DIR and HYPER_PARALLEL_OPS_PYTHON_PATH environment variables allow loading arbitrary YAML configuration files and importing arbitrary Python modules. Attackers can inject malicious modules by controlling these environment variables, leading to arbitrary code execution.

**漏洞代码** (`hyper_parallel/core/shard/_op_dispatch.py:234-240`)

```c
self._env_yaml_dir: Optional[str] = os.environ.get("HYPER_PARALLEL_OPS_YAML_DIR")
self._env_python_path: Optional[str] = os.environ.get("HYPER_PARALLEL_OPS_PYTHON_PATH")
self._setup_paths_from_env()
```

**达成路径**

OpDispatcher.__init__() [ENTRY]
→ os.environ.get("HYPER_PARALLEL_OPS_YAML_DIR") [SOURCE, line 234]
→ safe_load_yaml_from_dir() [_op_dispatch.py:795]
→ yaml.safe_load() [safe, but path is injectable]
→ importlib.import_module(module_file) [SINK, line 351, arbitrary code execution]

**验证说明**: Verified: Environment variable injection leading to arbitrary YAML config and Python module loading. Same root cause as VULN-DF-005. HYPER_PARALLEL_OPS_YAML_DIR controls YAML loading paths, enabling configuration manipulation.

**评分明细**: base: 30 | context: -5 | controllability: 20 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-SEC-CFG-002] code_injection - _register_single_distributed_op

**严重性**: High | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `hyper_parallel/core/shard/_op_dispatch.py:348-355` @ `_register_single_distributed_op`
**模块**: shard

**描述**: importlib.import_module() called with module name derived from HYPER_PARALLEL_OPS_PYTHON_PATH environment variable. When _env_python_path is set, arbitrary modules can be imported directly by name, bypassing the 'hyper_parallel.core.shard.ops.' prefix, leading to arbitrary code execution.

**漏洞代码** (`hyper_parallel/core/shard/_op_dispatch.py:348-355`)

```c
try:
    module_name = "hyper_parallel.core.shard.ops." + module_file
    module = importlib.import_module(module_name)
except (ModuleNotFoundError, ImportError):
    if self._env_python_path:
        module = importlib.import_module(module_file)  # Arbitrary import
```

**达成路径**

OpDispatcher.__init__() [ENTRY]
→ os.environ.get("HYPER_PARALLEL_OPS_PYTHON_PATH") [SOURCE]
→ _extend_sys_path(env_python_path) [line 310-316]
→ sys.path.insert(0, path) [line 316]
→ _register_single_distributed_op(op_name, config) [line 322]
→ importlib.import_module(module_file) [SINK, line 351, arbitrary import]

**验证说明**: Verified: importlib.import_module() with arbitrary module name when _env_python_path is set. Bypasses 'hyper_parallel.core.shard.ops.' prefix. Code injection via malicious Python module. Requires environment variable control.

**评分明细**: base: 30 | context: -5 | controllability: 20 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-006] insecure_deserialization - PipelineStage._communicate_meta

**严重性**: High | **CWE**: CWE-502 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner, security-auditor

**位置**: `hyper_parallel/core/pipeline_parallel/stage.py:304-320` @ `PipelineStage._communicate_meta`
**模块**: pipeline_parallel

**描述**: P2P communication uses send_object_list/recv_object_list which internally uses pickle serialization for Python objects. Remote ranks can send malicious pickle payloads leading to arbitrary code execution.

**漏洞代码** (`hyper_parallel/core/pipeline_parallel/stage.py:304-320`)

```c
platform.send_object_list([meta_send], global_rank)\n...\nplatform.recv_object_list(obj_list, global_rank)
```

**达成路径**

PipelineStage._communicate_meta()\n-> platform.send_object_list()/recv_object_list()\n-> torch.distributed.send_object_list/recv_object_list()\n-> pickle serialization/deserialization [SINK: CWE-502]

**验证说明**: Verified: send_object_list/recv_object_list uses pickle serialization for P2P communication. In distributed training, ranks are typically trusted. Exploit requires a malicious rank to join the process group (authentication bypass). Combined with VULN-DF-CROSS-003 increases risk.

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [VULN-DF-011] insecure_deserialization - Platform.all_gather_object

**严重性**: High | **CWE**: CWE-502 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `hyper_parallel/platform/platform.py:880-891` @ `Platform.all_gather_object`
**模块**: platform
**跨模块**: platform → collectives

**描述**: all_gather_object() gathers Python objects from all ranks using pickle serialization. Remote ranks in distributed training can send malicious pickle payloads leading to arbitrary code execution.

**漏洞代码** (`hyper_parallel/platform/platform.py:880-891`)

```c
def all_gather_object(object_list, obj, group=None) -> None:\n    raise NotImplementedError('Platform subclasses must implement all_gather_object')
```

**达成路径**

Platform.all_gather_object(object_list, obj, group)\n-> torch.distributed.all_gather_object() [via TorchPlatform]\n-> pickle serialization/deserialization [SINK: CWE-502]

**验证说明**: Verified: Cross-module all_gather_object() collects Python objects via pickle. Same attack vector as VULN-DF-006. Requires malicious rank to join process group.

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [VULN-SEC-CFG-003] path_injection - _extend_sys_path

**严重性**: High | **CWE**: CWE-73 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `hyper_parallel/core/shard/_op_dispatch.py:310-316` @ `_extend_sys_path`
**模块**: shard

**描述**: sys.path.insert(0, path) adds user-controlled paths from HYPER_PARALLEL_OPS_PYTHON_PATH to Python's module search path. This allows Python to load modules from attacker-controlled directories before trusted locations.

**漏洞代码** (`hyper_parallel/core/shard/_op_dispatch.py:310-316`)

```c
python_paths = env_python_path.split(":")
for path in python_paths:
    if path and os.path.isdir(path) and path not in sys.path:
        sys.path.insert(0, path)
```

**达成路径**

OpDispatcher.__init__() [ENTRY]
→ os.environ.get("HYPER_PARALLEL_OPS_PYTHON_PATH") [SOURCE]
→ _extend_sys_path(env_python_path) [line 283]
→ sys.path.insert(0, path) [SINK, line 316, modifies module search path]

**验证说明**: Verified: sys.path.insert(0, path) adds user-controlled paths to Python module search. Path validation: os.path.isdir(path) check exists but no sanitization. Enables module hijacking before trusted locations. Requires HYPER_PARALLEL_OPS_PYTHON_PATH control.

**评分明细**: base: 30 | context: -5 | controllability: 15 | cross_file: 0 | mitigations: -5 | reachability: 25

---

### [VULN-SEC-OBJ-001] insecure_deserialization - Platform.all_gather_object

**严重性**: High | **CWE**: CWE-502 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `hyper_parallel/platform/platform.py:879-891` @ `Platform.all_gather_object`
**模块**: platform
**跨模块**: distributed_checkpoint → platform

**描述**: all_gather_object() collects Python objects from all distributed ranks using pickle serialization. Objects received from potentially untrusted remote ranks are deserialized, allowing arbitrary code execution if a malicious rank sends crafted objects.

**漏洞代码** (`hyper_parallel/platform/platform.py:879-891`)

```c
@staticmethod
def all_gather_object(object_list, obj, group=None) -> None:
    raise NotImplementedError("Platform subclasses must implement all_gather_object")
```

**达成路径**

distributed_checkpoint._gather_from_all_ranks() [ENTRY, api.py:57]
→ platform.all_gather_object(all_objects, local_object) [api.py:75]
→ dist.all_gather_object(object_list, obj, group) [torch/platform.py:792]
→ pickle serialization/deserialization [SINK]

**验证说明**: Verified: Cross-module all_gather_object() via platform.all_gather_object() -> dist.all_gather_object() uses pickle. Same attack vector as VULN-DF-006/VULN-DF-011.

**评分明细**: base: 30 | context: 0 | controllability: 15 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [VULN-DF-010] config_injection - initialize_npushmem

**严重性**: High | **CWE**: CWE-15 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `hyper_parallel/core/symmetric_memory/platform/mindspore/c_api/allocator/symmetric_memory_allocator.cc:86-112` @ `initialize_npushmem`
**模块**: symmetric_memory

**描述**: Environment variables RANK_ID, RANK_SIZE, SYMMETRIC_MEMORY_HEAP_SIZE are read without upper bound validation. SYMMETRIC_MEMORY_HEAP_SIZE uses std::stoull() which could cause integer overflow on very large values, leading to memory allocation issues.

**漏洞代码** (`hyper_parallel/core/symmetric_memory/platform/mindspore/c_api/allocator/symmetric_memory_allocator.cc:86-112`)

```c
auto rank_id_env = std::getenv('RANK_ID');\nauto rank_size_env = std::getenv('RANK_SIZE');\n...\nuint64_t temp_shmem_size = std::stoull(shmem_size);\nlocal_mem_size = temp_shmem_size;
```

**达成路径**

std::getenv('RANK_ID/RANK_SIZE/SYMMETRIC_MEMORY_HEAP_SIZE') [SOURCE]\n-> std::stoi()/std::stoull()\n-> aclshmemx_init_attr() [SINK: CWE-15]

**验证说明**: Verified POSSIBLE: std::stoull() can overflow on very large SYMMETRIC_MEMORY_HEAP_SIZE values. Environment variables require privileged access to modify. Would cause memory allocation issues but not direct code execution. Combined with other environment injection vulnerabilities increases risk.

**评分明细**: base: 30 | context: -5 | controllability: 15 | cross_file: 0 | mitigations: -10 | reachability: 25

---

### [VULN-DF-CROSS-004] config_injection - GetShmemIpPort

**严重性**: High | **CWE**: CWE-15 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `hyper_parallel/core/symmetric_memory/platform/mindspore/c_api/allocator/symmetric_memory_allocator.cc:55-78` @ `GetShmemIpPort`
**模块**: symmetric_memory
**跨模块**: symmetric_memory → collectives

**描述**: Cross-module vulnerability: symmetric_memory reads MS_SCHED_HOST and MS_SCHED_PORT environment variables (controlled by distributed scheduler) to construct IP address for shmem communication. Malicious environment variables could redirect communication to attacker-controlled endpoints.

**漏洞代码** (`hyper_parallel/core/symmetric_memory/platform/mindspore/c_api/allocator/symmetric_memory_allocator.cc:55-78`)

```c
auto sched_host_env = std::getenv('MS_SCHED_HOST');\nauto sched_port_env = std::getenv('MS_SCHED_PORT');\nip_port = 'tcp://' + sched_host + ':' + std::to_string(new_port);
```

**达成路径**

MS_SCHED_HOST/MS_SCHED_PORT environment variables [SOURCE: controlled by distributed scheduler]
-> GetShmemIpPort() [cross-module dependency]
-> aclshmemx_init_attr(ip_port) [SINK: CWE-15]

**验证说明**: Verified POSSIBLE: MS_SCHED_HOST and MS_SCHED_PORT environment variables control TCP rendezvous address for symmetric memory. These are typically set by distributed scheduler. Malicious values could redirect to attacker-controlled endpoints. Requires environment compromise.

**评分明细**: base: 30 | context: -5 | controllability: 15 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [VULN-DF-012] buffer_overflow - GetmemKernel::Process

**严重性**: High | **CWE**: CWE-120 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `hyper_parallel/core/symmetric_memory/ops/get_mem/kernel/get_mem_kernel.cpp:55-60` @ `GetmemKernel::Process`
**模块**: symmetric_memory

**描述**: Pointer arithmetic without bounds validation. The target_ptr and src_ptr are calculated using target_offset_, src_offset_, and size_per_core which are read from global memory. If these values exceed buffer bounds, memory corruption occurs.

**漏洞代码** (`hyper_parallel/core/symmetric_memory/ops/get_mem/kernel/get_mem_kernel.cpp:55-60`)

```c
auto size_per_core = size_ / aiv_num_;
auto target_ptr = target_ + target_offset_ + aiv_idx_ * size_per_core;
auto src_ptr = src_ + src_offset_ + aiv_idx_ * size_per_core;
```

**达成路径**

CopyGmSingleValueToUb<int64_t>(target_offset, &target_offset_) [SOURCE: from global memory]
-> GetmemKernel::Process()
-> target_ptr = target_ + target_offset_ + aiv_idx_ * size_per_core [SINK: CWE-120]

**验证说明**: Verified POSSIBLE: Pointer arithmetic in GetmemKernel::Process() without bounds validation. target_offset_ and src_offset_ read from global memory. Need to verify if these values are validated upstream in aclshmem_get_mem() caller.

**评分明细**: base: 30 | context: -10 | controllability: 10 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-CROSS-003] authentication_bypass - init_process_group

**严重性**: High | **CWE**: CWE-287 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `hyper_parallel/collectives/cc.py:24-48` @ `init_process_group`
**模块**: collectives
**跨模块**: collectives → platform

**描述**: Cross-module vulnerability: collectives.init_process_group() calls platform.init_process_group() with TCP/file-based rendezvous. The init_method URL is user-controlled and could connect to malicious endpoints, allowing unauthorized processes to join distributed training.

**漏洞代码** (`hyper_parallel/collectives/cc.py:24-48`)

```c
platform.init_process_group(backend=backend, init_method=init_method, timeout=timeout, world_size=world_size, rank=rank)
```

**达成路径**

collectives.init_process_group(init_method) [SOURCE: user input]
-> platform.init_process_group() [cross-module call]
-> TCP/file rendezvous with potential malicious endpoint [SINK: CWE-287]

**验证说明**: Verified POSSIBLE: init_method URL for TCP/file rendezvous is user-controlled. Could connect to malicious endpoints if URL is not validated. Standard distributed training pattern but needs URL validation. Combined with P2P pickle vulnerabilities increases risk.

**评分明细**: base: 30 | context: -5 | controllability: 15 | cross_file: 0 | mitigations: -10 | reachability: 20

---

### [VULN-DF-009] use_after_free - Manager::free_tensor

**严重性**: High | **CWE**: CWE-416 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `hyper_parallel/core/symmetric_memory/platform/torch/torch_bindings.cpp:68-75` @ `Manager::free_tensor`
**模块**: symmetric_memory

**描述**: aclshmem_free() is called on tensor data pointer obtained via tensor.data_ptr(). However, there is no ownership tracking - if the tensor is still referenced elsewhere, use-after-free occurs when other code accesses the freed memory.

**漏洞代码** (`hyper_parallel/core/symmetric_memory/platform/torch/torch_bindings.cpp:68-75`)

```c
void* aclshmem_ptr = const_cast<void*>(aclshmem_tensor.data_ptr());\naclshmem_free(aclshmem_ptr);
```

**达成路径**

Manager::free_tensor(const at::Tensor &aclshmem_tensor) [SOURCE]\n-> aclshmem_tensor.data_ptr()\n-> aclshmem_free(aclshmem_ptr) [SINK: CWE-416]

**验证说明**: Verified POSSIBLE: Null pointer check exists (line 69), but aclshmem_free() is called on tensor.data_ptr() without ownership tracking. If tensor is still referenced elsewhere, use-after-free could occur. Requires analysis of tensor lifecycle management to fully verify.

**评分明细**: base: 30 | context: -10 | controllability: 10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

## 4. Medium 漏洞 (6)

### [VULN-DF-CROSS-005] insecure_deserialization - _load_from_checkpoint

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `hyper_parallel/integration/llamafactory/trainer.py:536-539` @ `_load_from_checkpoint`
**模块**: integration
**跨模块**: integration → distributed_checkpoint

**描述**: Cross-module vulnerability: integration module calls distributed_checkpoint.load() which internally uses pickle.load() on metadata files. The checkpoint path from LlamaFactory could be manipulated to load malicious checkpoints.

**漏洞代码** (`hyper_parallel/integration/llamafactory/trainer.py:536-539`)

```c
hp_load(state_dict, checkpoint_id=model_dir, use_collectives=False)\ntarget.load_state_dict(state_dict)
```

**达成路径**

LlamaFactory checkpoint path [SOURCE: user provided]
-> integration._load_from_checkpoint() -> distributed_checkpoint.hp_load() [cross-module call]
-> pickle.load(metadata) [SINK: CWE-502]

**验证说明**: Verified POSSIBLE: Cross-module vulnerability. LlamaFactory checkpoint path passed to distributed_checkpoint.hp_load() which uses pickle.load(). Same root cause as VULN-DF-001. User controls model_dir path.

**评分明细**: base: 30 | context: -5 | controllability: 15 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-013] improper_input_validation - moe_ffn_fwd_npu

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `hyper_parallel/core/multicore/platform/torch/csrc/moe_ffn_fwd.cpp:23-64` @ `moe_ffn_fwd_npu`
**模块**: multicore

**描述**: 22 tensor parameters passed to EXEC_NPU_CMD_EXT without explicit validation. The function relies on framework-level validation which may be incomplete. Malicious tensor shapes or corrupted data could cause kernel execution failures or memory corruption.

**漏洞代码** (`hyper_parallel/core/multicore/platform/torch/csrc/moe_ffn_fwd.cpp:23-64`)

```c
EXEC_NPU_CMD_EXT(aclnnMegaKernelGmm,
    dispatch_target, dispatch_target_off,
    dispatch_src, dispatch_src_off, dispatch_size,
    up_proj_weight, up_proj_glist,
    ...  // 22 tensors total
```

**达成路径**

moe_ffn_fwd(dispatch_target, ...) [SOURCE: Python API]
-> moe_ffn_fwd_npu() [C++ dispatcher]
-> EXEC_NPU_CMD_EXT(aclnnMegaKernelGmm, ...) [SINK: CWE-20]

**验证说明**: Verified POSSIBLE: 22 tensor parameters passed to EXEC_NPU_CMD_EXT without explicit validation. Relies on framework-level validation which may be incomplete. Malicious tensor shapes could cause kernel execution failures. Low risk - framework typically validates tensor shapes.

**评分明细**: base: 30 | context: -10 | controllability: 10 | cross_file: 0 | mitigations: -5 | reachability: 20

---

### [VULN-SEC-CFG-004] environment_injection - initialize_npushmem

**严重性**: Medium | **CWE**: CWE-15 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `hyper_parallel/core/symmetric_memory/platform/mindspore/c_api/allocator/symmetric_memory_allocator.cc:86-112` @ `initialize_npushmem`
**模块**: symmetric_memory

**描述**: RANK_ID, RANK_SIZE, and SYMMETRIC_MEMORY_HEAP_SIZE environment variables are read without upper bound validation. std::stoi/std::stoull conversions could cause integer overflow if malicious values are provided, affecting memory allocation size calculations.

**漏洞代码** (`hyper_parallel/core/symmetric_memory/platform/mindspore/c_api/allocator/symmetric_memory_allocator.cc:86-112`)

```c
auto rank_id_env = std::getenv("RANK_ID");
auto rank_size_env = std::getenv("RANK_SIZE");
...
int32_t my_pe = std::stoi(rank_id_env);
int32_t n_ranks = std::stoi(rank_size_env);
...
auto shmem_size = std::getenv("SYMMETRIC_MEMORY_HEAP_SIZE");
uint64_t temp_shmem_size = std::stoull(shmem_size);
```

**达成路径**

initialize_npushmem() [ENTRY]
→ std::getenv("RANK_ID") [SOURCE, line 86]
→ std::getenv("RANK_SIZE") [SOURCE, line 87]
→ std::stoi(rank_id_env) [line 92]
→ std::getenv("SYMMETRIC_MEMORY_HEAP_SIZE") [SOURCE, line 96]
→ std::stoull(shmem_size) [SINK, line 100, potential integer overflow]

**验证说明**: Verified POSSIBLE: RANK_ID, RANK_SIZE, SYMMETRIC_MEMORY_HEAP_SIZE without upper bound validation. std::stoull could overflow. Same as VULN-DF-010. Requires environment variable control.

**评分明细**: base: 30 | context: -5 | controllability: 10 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-SEC-CFG-005] external_control - GetShmemIpPort

**严重性**: Medium | **CWE**: CWE-15 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `hyper_parallel/core/symmetric_memory/platform/mindspore/c_api/allocator/symmetric_memory_allocator.cc:57-77` @ `GetShmemIpPort`
**模块**: symmetric_memory

**描述**: MS_SCHED_HOST and MS_SCHED_PORT environment variables control TCP connection address for symmetric memory rendezvous. An attacker controlling these variables could redirect connections to malicious endpoints.

**漏洞代码** (`hyper_parallel/core/symmetric_memory/platform/mindspore/c_api/allocator/symmetric_memory_allocator.cc:57-77`)

```c
auto sched_host_env = std::getenv("MS_SCHED_HOST");
auto sched_port_env = std::getenv("MS_SCHED_PORT");
...
std::string sched_host(sched_host_env);
int sched_port = std::stoi(sched_port_env);
ip_port = "tcp://" + sched_host + ":" + std::to_string(new_port);
```

**达成路径**

GetShmemIpPort() [ENTRY]
→ std::getenv("MS_SCHED_HOST") [SOURCE, line 57]
→ std::getenv("MS_SCHED_PORT") [SOURCE, line 58]
→ std::stoi(sched_port_env) [line 63]
→ "tcp://" + sched_host + ":" + port [SINK, line 65, external endpoint control]

**验证说明**: Verified POSSIBLE: MS_SCHED_HOST/MS_SCHED_PORT control TCP rendezvous for symmetric memory. Same as VULN-DF-CROSS-004. Requires environment compromise.

**评分明细**: base: 30 | context: -5 | controllability: 10 | cross_file: 0 | mitigations: 0 | reachability: 20

---

### [VULN-DF-014] race_condition - SwapTensor.async_load/wait_load/async_offload/wait_offload

**严重性**: Medium | **CWE**: CWE-362 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `hyper_parallel/core/activation_checkpoint/swap.py:77-151` @ `SwapTensor.async_load/wait_load/async_offload/wait_offload`
**模块**: activation_checkpoint

**描述**: Tensor lifecycle state machine (device/host/d2h/h2d) requires strict ordering of async_load, wait_load, async_offload, wait_offload calls. If called in wrong order or from multiple threads simultaneously, memory corruption or data loss could occur. Code has warnings but no enforcement.

**漏洞代码** (`hyper_parallel/core/activation_checkpoint/swap.py:77-151`)

```c
def async_load(self):
    if self._state != self.STATE_HOST:
        warnings.warn(...)
        return
    self._state = self.STATE_H2D
```

**达成路径**

SwapTensor state machine operations [SOURCE]
-> async_load/wait_load/async_offload/wait_offload state transitions
-> Potential race condition if called in wrong order [SINK: CWE-362]

**验证说明**: Verified POSSIBLE: Tensor lifecycle state machine with warnings.warn() for wrong order calls. No enforcement mechanism. Race condition possible if called from multiple threads. Memory corruption risk if async_load/wait_load called in wrong order. Low security risk - primarily reliability issue.

**评分明细**: base: 30 | context: -10 | controllability: 10 | cross_file: 0 | mitigations: -10 | reachability: 20

---

### [VULN-DF-017] path_traversal - CLI pipeline_tool

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `hyper_parallel/auto_parallel/fast-tuner/fast_tuner/pipeline_tool.py:1-50` @ `CLI pipeline_tool`
**模块**: auto_parallel

**描述**: CLI accepts file paths (--yaml_path, --shell_path) which are used to load configuration files. If user provides malicious paths, could lead to loading arbitrary files.

**漏洞代码** (`hyper_parallel/auto_parallel/fast-tuner/fast_tuner/pipeline_tool.py:1-50`)

```c
CLI arguments: --yaml_path, --shell_path (file paths from user)
```

**达成路径**

CLI arguments --yaml_path, --shell_path [SOURCE: user input]
-> File loading operations
-> Potential CWE-22 path traversal

**验证说明**: Verified POSSIBLE: CLI accepts file paths (--yaml_path, --shell_path). Paths are explicit user input to auto_parallel tool. Path traversal possible but tool is typically used by trusted operators. Not a remote attack vector.

**评分明细**: base: 30 | context: -10 | controllability: 10 | cross_file: 0 | mitigations: -10 | reachability: 20

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| activation_checkpoint | 0 | 0 | 1 | 0 | 1 |
| auto_parallel | 0 | 0 | 1 | 0 | 1 |
| collectives | 0 | 1 | 0 | 0 | 1 |
| distributed_checkpoint | 0 | 1 | 0 | 0 | 1 |
| integration | 0 | 0 | 1 | 0 | 1 |
| multicore | 0 | 0 | 1 | 0 | 1 |
| pipeline_parallel | 0 | 1 | 0 | 0 | 1 |
| platform | 0 | 2 | 0 | 0 | 2 |
| shard | 0 | 4 | 0 | 0 | 4 |
| symmetric_memory | 0 | 4 | 2 | 0 | 6 |
| **合计** | **0** | **13** | **6** | **0** | **19** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-15 | 6 | 31.6% |
| CWE-502 | 4 | 21.1% |
| CWE-22 | 2 | 10.5% |
| CWE-94 | 1 | 5.3% |
| CWE-73 | 1 | 5.3% |
| CWE-416 | 1 | 5.3% |
| CWE-362 | 1 | 5.3% |
| CWE-287 | 1 | 5.3% |
| CWE-20 | 1 | 5.3% |
| CWE-120 | 1 | 5.3% |
