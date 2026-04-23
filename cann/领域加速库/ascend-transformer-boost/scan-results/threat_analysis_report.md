# ATB Library Threat Analysis Report

**Project**: Ascend Transformer Boost (ATB)  
**Vendor**: Huawei Technologies Co., Ltd.  
**Analysis Date**: 2026-04-21  
**Analysis Mode**: Autonomous (no threat.md provided)  
**Codebase Size**: 716 source files, 686 header files, ~128,505 lines of code  

---

## Executive Summary

The Ascend Transformer Boost (ATB) library is a Huawei-developed acceleration framework for Transformer model inference and training on NPU (Neural Processing Unit) hardware. This security analysis identifies **multiple critical attack surfaces** and potential vulnerabilities that could be exploited in production deployments.

**Key Findings**:
- **Critical risk**: Python bindings expose raw tensor memory pointers without validation
- **Critical risk**: HCCL network communication receives untrusted data from distributed nodes
- **Critical risk**: Socket bootstrap protocol lacks authentication for initial rank setup
- **High risk**: Environment variables control critical configuration paths
- **High risk**: User-provided allocators enable arbitrary code execution
- **Medium risk**: memcpy operations with complex size calculations

---

## 1. Attack Surface Analysis

### 1.1 Primary Entry Points

| Entry Point | Location | Risk Level | Description |
|-------------|----------|------------|-------------|
| **Python API** | `src/torch_atb/bindings.cpp` | CRITICAL | pybind11 bindings expose all operations, tensor pointers passed without validation |
| **C++ Public API** | `include/atb/*.h` | HIGH | Context, Operation, Graph APIs with user-provided structures |
| **HCCL Network** | `src/atb/runner/hccl_runner.cpp` | CRITICAL | Receives tensor data from distributed nodes during collective operations |
| **Socket Bootstrap** | `src/kernels/lcal/src/tools/socket/lcal_sock_exchange.cpp` | CRITICAL | Initial rank coordination via TCP sockets before HCCL init |
| **Environment Variables** | `src/atb/utils/config.cpp` | HIGH | ~10+ environment variables control paths, sizes, and behaviors |
| **Shared Memory IPC** | `src/atb/utils/comm.cpp` | HIGH | HCCL root info exchanged via shared memory segments |

### 1.2 Tainted Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TAINT PROPAGATION DIAGRAM                            │
└─────────────────────────────────────────────────────────────────────────────┘

Python torch.Tensor                    Distributed HCCL Node
    │                                       │
    │ (user memory pointer)                 │ (network tensor data)
    ▼                                       ▼
┌─────────────────┐                   ┌─────────────────────┐
│ OperationWrapper│                   │ HcclRunner::Execute │
│   ::Forward()   │                   │    Impl()           │
└─────────────────┘                   └─────────────────────┘
    │                                       │
    │ torch_tensor.data_ptr()               │ HcclAllReduce/HcclAllGather
    ▼                                       ▼
┌─────────────────┐                   ┌─────────────────────┐
│  VariantPack    │◄──────────────────│  recvBuf from       │
│  inTensors[].   │    data merge     │  remote ranks       │
│  deviceData     │                   └─────────────────────┘
│  hostData       │
└─────────────────┘
    │
    │ memcpy/aclrtMemcpy
    ▼
┌─────────────────┐
│ NPU Kernel      │
│ Execution       │
│ (AscendC)       │
└─────────────────┘
```

---

## 2. Detailed Threat Analysis

### THREAT-001: Unvalidated Tensor Memory Pointer Usage

**Severity**: CRITICAL  
**CWE**: CWE-20 (Improper Input Validation), CWE-119 (Buffer Overflow)  
**Location**: `include/atb/types.h:118-127`, all runner implementations  
**Affected Modules**: All operations  

**Description**:  
The `Tensor` structure contains two raw memory pointers (`deviceData`, `hostData`) that are directly provided by users via Python bindings or C++ API. These pointers are used without any bounds validation in:
- `aclrtMemcpy` calls
- Kernel input binding
- HCCL collective operations

**Attack Vector**:
```python
# Attacker-controlled Python code
import torch_atb
import torch

# Create malicious tensor with arbitrary pointer
malicious_tensor = torch.tensor([1.0])  # Valid torch tensor
op = torch_atb.Operation(torch_atb.LinearParam())  # Create operation

# The library blindly uses:
# - malicious_tensor.data_ptr() as deviceData pointer
# - malicious_tensor.size() * dtype size as dataSize
# No validation of:
# - Pointer validity/alignment
# - Size consistency with operation requirements
# - Memory ownership
```

**Impact**: Memory corruption, arbitrary read/write, potential code execution on NPU  

**Recommendation**:
1. Validate tensor data pointers are within valid memory ranges
2. Verify dataSize matches expected operation input size
3. Add optional bounds checking mode for production deployments
4. Use safe copy operations instead of direct pointer usage

---

### THREAT-002: HCCL Network Data Trust

**Severity**: CRITICAL  
**CWE**: CWE-346 (Origin Validation Error), CWE-20  
**Location**: `src/ops/ops_infer/all_*/*_hccl_runner.cpp`, `src/ops/ops_infer/broadcast/`, `src/ops/ops_infer/reduce_scatter/`  
**Affected Operations**: AllGather, AllGatherV, AllReduce, Broadcast, ReduceScatter, Send, Recv  

**Description**:  
HCCL collective operations receive tensor data from distributed nodes without cryptographic authentication. Any compromised node in the cluster can:
- Inject malicious tensor data
- Manipulate tensor sizes/count parameters
- Spoof rank identities

**Critical Code Patterns**:
```cpp
// all_gatherv_hccl_runner.cpp:49-53 - Unvalidated host memory
HcclAllGatherV(
    runnerVariantPack.inTensors[0].deviceData,
    *(static_cast<int64_t *>(runnerVariantPack.inTensors[1].hostData)),  // User-controlled
    runnerVariantPack.outTensors[0].deviceData,
    runnerVariantPack.inTensors[2].hostData,  // recvCounts - user-controlled
    runnerVariantPack.inTensors[3].hostData,  // rdispls - user-controlled
    ...
);
```

**Attack Vector**:
1. Compromise one node in distributed cluster
2. Send malicious recvCounts/rdispls to cause buffer overflow on receiving nodes
3. All nodes trust network data without authentication

**Impact**: Memory corruption across distributed cluster, data exfiltration, model poisoning  

**Recommendation**:
1. Implement HMAC-based message authentication for HCCL transfers
2. Validate recvCounts/rdispls against expected bounds
3. Add secure communication channel option with TLS
4. Implement rank authentication during bootstrap

---

### THREAT-003: Socket Bootstrap Authentication Bypass

**Severity**: CRITICAL  
**CWE**: CWE-287 (Improper Authentication), CWE-346  
**Location**: `src/kernels/lcal/src/tools/socket/lcal_sock_exchange.cpp`  
**Affected Functions**: Listen(), Accept(), Connect(), AllGather()  

**Description**:  
The LCAL bootstrap protocol uses raw TCP sockets for initial rank coordination before HCCL initialization. There is **no authentication** of connecting clients:

```cpp
// lcal_sock_exchange.cpp:232-243
int rank = 0;
if (Recv(fd, &rank, sizeof(rank), 0) <= 0) { ... }
if (rank >= rankSize_ || rank <= 0 || clientFds_[rank] >= 0) {
    MKI_LOG(ERROR) << "Server side recv invalid rank id " << rank;
    return LCAL_ERROR_INTERNAL;
}
clientFds_[rank] = fd;  // Rank ID determines data routing
```

**Attack Vector**:
1. Attacker connects to bootstrap server on port 10067+domain
2. Sends spoofed rank ID (e.g., rank=1)
3. Server accepts connection and routes data through clientFds_[1]
4. Attacker intercepts/modifies bootstrap information (devIds, PIDs, memory names)
5. All subsequent HCCL operations use compromised configuration

**Impact**: Complete cluster compromise, MITM on all distributed operations  

**Recommendation**:
1. Implement TLS with certificate-based authentication
2. Add challenge-response authentication during Accept()
3. Verify connecting IP addresses match expected ranks
4. Use cryptographic signatures for bootstrap data

---

### THREAT-004: Environment Variable Injection

**Severity**: HIGH  
**CWE**: CWE-15 (External Control of System-Sensitive Configuration)  
**Location**: `src/atb/utils/config.cpp`  
**Affected Variables**: ATB_HOME_PATH, ATB_WORKSPACE_MEM_ALLOC_ALG_TYPE, LCAL_COMM_ID, etc.  

**Description**:  
Multiple environment variables control critical library behavior without adequate validation:

| Variable | Usage | Risk |
|----------|-------|------|
| `ATB_HOME_PATH` | Library home directory | Path traversal, arbitrary code loading |
| `ATB_WORKSPACE_MEM_ALLOC_ALG_TYPE` | Memory allocation algorithm | Algorithm manipulation |
| `LCAL_COMM_ID` | Bootstrap network address (IP:port) | Network redirection, MITM |
| `ATB_SHARE_MEMORY_NAME_SUFFIX` | Shared memory names | IPC name collision |
| `ATB_STREAM_SYNC_*` | Stream synchronization | DoS via excessive sync |

**Critical Code**:
```cpp
// config.cpp:82-93
void Config::InitAtbHomePath() {
    const char *envStr = std::getenv("ATB_HOME_PATH");
    if (!envStr) return;
    if (strlen(envStr) > MAX_ENV_STRING_LEN) {  // Only length check
        ATB_LOG(ERROR) << "ATB_HOME_PATH length is more than " << MAX_ENV_STRING_LEN;
        return;
    }
    atbHomePath_ = std::string(envStr);  // Used for library/config loading
}

// lcal_sock_exchange.cpp:127-138
const char* env = Mki::GetEnv("LCAL_COMM_ID");
if (env) {
    if (GetAddrFromString(&handle.addr, env) != LCAL_SUCCESS) { ... }
    // Network connection to attacker-controlled address
}
```

**Impact**: Arbitrary library loading, network MITM, DoS  

**Recommendation**:
1. Whitelist allowed values for critical environment variables
2. Validate ATB_HOME_PATH against expected locations
3. Add cryptographic verification for loaded library files
4. Use configuration files instead of environment variables where possible

---

### THREAT-005: Custom Allocator Arbitrary Code Execution

**Severity**: HIGH  
**CWE**: CWE-94 (Code Injection)  
**Location**: `include/atb/context.h:168`, `src/atb/context/context_base.cpp:51-74`  

**Description**:  
The `CreateContext` API allows users to provide custom memory allocator/deallocator functions:

```cpp
// context.h:168
Status CreateContext(Context **context, 
    const std::function<void*(size_t)>& alloc, 
    const std::function<void(void*)>& dealloc);
```

These functions are called during context initialization for tiling buffer allocation. A malicious allocator could:
- Return attacker-controlled memory addresses
- Execute arbitrary code during allocation
- Leak memory contents to external channels

**Attack Vector**:
```python
import torch_atb

def malicious_allocator(size):
    # Execute arbitrary code
    # Return memory at attacker-controlled address
    return malicious_address

# Create context with malicious allocator
ctx = torch_atb.create_context_with_allocator(malicious_allocator, lambda x: None)
```

**Impact**: Arbitrary code execution, memory corruption  

**Recommendation**:
1. Disable custom allocators in production builds
2. Add allocator signature verification
3. Validate returned pointers are within valid ranges
4. Use only verified internal allocators for critical paths

---

### THREAT-006: memcpy_s Size Calculation Errors

**Severity**: HIGH  
**CWE**: CWE-130 (Improper Handling of Length Parameter)  
**Location**: `src/kernels/tbe_adapter/tiling_runner/tbe_tiling_runner.cpp`  

**Description**:  
Multiple `memcpy_s` calls use complex size calculations that could lead to buffer overflow:

```cpp
// tbe_tiling_runner.cpp:120
memcpy_s(tensor->GetData<uint8_t>(), totalSize - sizeof(Tensor), data, size);

// tbe_tiling_runner.cpp:409
memcpy_s(attrPos + currentOffset, attrSize - currentOffset, 
    attrs_[i].first.get(), attrs_[i].second);

// tbe_tiling_runner.cpp:442
memcpy_s(attr, (totalSize - offset), attrPtr.get(), attrSize);
```

**Risk Factors**:
- `totalSize - sizeof(Tensor)` could underflow
- Complex offset arithmetic in attribute packing
- Source size (`attrs_[i].second`) not validated against destination

**Impact**: Buffer overflow, memory corruption  

**Recommendation**:
1. Add explicit bounds checks before each memcpy_s
2. Validate totalSize > sizeof(Tensor) before subtraction
3. Use safe wrapper functions with validated parameters

---

### THREAT-007: Shared Memory Race Conditions

**Severity**: MEDIUM  
**CWE**: CWE-362 (Race Condition), CWE-367  
**Location**: `src/atb/utils/comm.cpp`, `src/atb/runner/hccl_runner.cpp`  

**Description**:  
Shared memory segments (`hcclShareMem`) are used for HCCL root info exchange with semaphore-based synchronization:

```cpp
// comm.cpp:27-40
void ShmGetHcclRootInfo(Mki::ShareMemory &shm, const CommInitInfo &shmInfo, HcclRootInfo &hcclRootInfo) {
    while (true) {
        shm.SemLock();
        if (shmInfo.signal != 0) {
            hcclRootInfo = shmInfo.hcclRootInfo;  // Copy while locked
            commIdReady = true;
        }
        shm.SemUnLock();  // Unlock before checking condition
        if (commIdReady) break;
    }
}
```

**Risk**: SemLock/SemUnLock cycle leaves window for concurrent modification  

**Impact**: Data inconsistency, potential deadlock  

**Recommendation**:
1. Hold lock until data copy is complete
2. Add checksum verification for shared memory data
3. Use atomic operations for signal variable

---

### THREAT-008: Integer Overflow in Memory Allocation

**Severity**: MEDIUM  
**CWE**: CWE-190 (Integer Overflow)  
**Location**: `src/atb/utils/mem_allocation_solver/*.cpp`  

**Description**:  
Block-based memory allocation solvers use int64_t for block sizes with inadequate validation:

```cpp
// block_mem_allocation_solver.cpp:26-30
void *BlockMemAllocationSolver::GetOffset(int64_t blockSize) {
    if (blockSize <= 0) {
        blockSize = 0;  // Sets to 0 but continues
    }
    // ... proceeds with allocation even with blockSize=0
}
```

**Risk**: Negative block sizes converted to 0 but allocation still proceeds  

**Impact**: Memory corruption, unexpected behavior  

**Recommendation**:
1. Return error for blockSize <= 0
2. Add maximum blockSize limits
3. Use size_t instead of int64_t for unsigned sizes

---

## 3. High-Risk Modules Summary

| Module | Files | Risk Level | Primary Threats |
|--------|-------|------------|-----------------|
| torch_atb bindings | 10 | CRITICAL | THREAT-001, THREAT-005 |
| HCCL runners | 15+ | CRITICAL | THREAT-002 |
| Socket bootstrap | 2 | CRITICAL | THREAT-003 |
| Config utilities | 3 | HIGH | THREAT-004 |
| Context management | 5 | HIGH | THREAT-005 |
| Memory allocators | 4 | HIGH | THREAT-006, THREAT-008 |
| TBE adapter | 10+ | HIGH | THREAT-006 |
| Communication utils | 3 | MEDIUM | THREAT-007 |

---

## 4. Security Recommendations

### 4.1 Immediate Actions (Critical)

1. **Disable raw tensor pointer usage in production builds**
   - Replace with validated copy operations
   - Add optional "safe mode" for untrusted environments

2. **Implement HCCL authentication**
   - Add HMAC verification for collective operation data
   - Implement rank certificate validation during bootstrap

3. **Add socket bootstrap TLS**
   - Replace raw TCP with TLS sockets
   - Require certificate-based rank authentication

### 4.2 High-Priority Actions

4. **Environment variable validation**
   - Whitelist allowed ATB_HOME_PATH locations
   - Validate LCAL_COMM_ID format and allowed IPs

5. **Remove or restrict custom allocators**
   - Disable in production builds
   - Add allocator function signature verification

6. **Fix memcpy_s bounds checks**
   - Add explicit validation before all complex size calculations
   - Implement safe wrapper for attribute packing

### 4.3 Medium-Priority Actions

7. **Shared memory synchronization fixes**
   - Hold semaphore during complete data copy
   - Add checksum verification

8. **Integer overflow prevention**
   - Change to size_t for block sizes
   - Add maximum size limits

---

## 5. Attack Scenarios

### Scenario A: Distributed Model Poisoning

```
Step 1: Attacker gains access to one worker node in distributed cluster
Step 2: During AllReduce operation, attacker sends manipulated gradient data
Step 3: No authentication of network data -> all nodes accept poisoned gradients
Step 4: Model training converges to attacker-controlled weights
Step 5: Production inference uses poisoned model
```

**Threats Involved**: THREAT-002, THREAT-003  
**Impact**: Model integrity compromise, potential downstream attacks

### Scenario B: Memory Corruption via Python API

```
Step 1: Attacker crafts malicious Python script using torch_atb
Step 2: Creates tensor with data_ptr pointing to attacker-controlled address
Step 3: Calls Operation::Forward with malicious tensor
Step 4: Library uses attacker's pointer in aclrtMemcpy without validation
Step 5: NPU kernel reads/writes attacker-controlled memory
```

**Threats Involved**: THREAT-001  
**Impact**: Memory corruption, potential NPU code execution

### Scenario C: Bootstrap MITM

```
Step 1: Attacker intercepts bootstrap socket connections (LCAL_COMM_ID manipulation)
Step 2: Attacker sets LCAL_COMM_ID to attacker-controlled server
Step 3: All ranks connect to attacker's bootstrap server
Step 4: Attacker provides malicious devIds/memory names
Step 5: HCCL initialization uses attacker-controlled configuration
Step 6: All subsequent distributed operations compromised
```

**Threats Involved**: THREAT-003, THREAT-004  
**Impact**: Complete cluster compromise

---

## 6. References

- CWE-20: Improper Input Validation
- CWE-119: Improper Restriction of Operations within Bounds
- CWE-130: Improper Handling of Length Parameter
- CWE-190: Integer Overflow or Wraparound
- CWE-287: Improper Authentication
- CWE-346: Origin Validation Error
- CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
- CWE-94: Improper Control of Generation of Code ('Code Injection')

---

## Appendix A: Environment Variables

| Variable | Default | Usage | Security Impact |
|----------|---------|-------|-----------------|
| ATB_HOME_PATH | None | Library installation path | Path traversal if attacker-controlled |
| ATB_WORKSPACE_MEM_ALLOC_ALG_TYPE | 1 | Memory algorithm selection | Algorithm manipulation |
| ATB_STREAM_SYNC_EVERY_KERNEL_ENABLE | 0 | Kernel sync mode | DoS if excessive |
| ATB_STREAM_SYNC_EVERY_RUNNER_ENABLE | 0 | Runner sync mode | DoS if excessive |
| ATB_COMPARE_TILING_EVERY_KERNEL | 0 | Tiling verification | Performance DoS |
| ATB_MATMUL_SHUFFLE_K_ENABLE | 1 | Matmul optimization | Algorithm behavior change |
| ATB_SHARE_MEMORY_NAME_SUFFIX | None | IPC memory naming | Name collision |
| LCAL_COMM_ID | None | Bootstrap address (IP:port) | Network MITM |
| HCCL_CONNECT_TIMEOUT | 1800s | Connection retry limit | DoS via timeout |

---

## Appendix B: HCCL Operations Security Matrix

| Operation | Network Input | User Input | Validation Status |
|-----------|---------------|------------|-------------------|
| AllGather | recvBuf from all ranks | sendBuf, sendCount | No network validation |
| AllGatherV | recvBuf from all ranks | recvCounts, rdispls | CRITICAL: unvalidated host memory |
| AllReduce | result from all ranks | sendBuf, count, op | No network validation |
| Broadcast | buf from root rank | count, root | No source authentication |
| ReduceScatter | recvBuf from all ranks | recvCount, op | No network validation |
| Send | N/A | sendBuf, destRank | No destination validation |
| Recv | recvBuf from srcRank | srcRank | No source validation |

---

*End of Threat Analysis Report*