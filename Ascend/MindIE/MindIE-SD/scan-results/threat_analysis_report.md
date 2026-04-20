# MindIE-SD Threat Analysis Report

## Executive Summary

MindIE-SD is a Stable Diffusion inference engine optimized for Huawei Ascend hardware, providing accelerated inference capabilities through custom C++ operators and Python APIs. This threat analysis identifies multiple critical security concerns, particularly in the service deployment example which lacks authentication and proper input validation.

**Key Findings:**
- **Critical**: Unauthenticated HTTP API service with file path control by users
- **High**: ZMQ-based IPC with configurable network binding and handle broadcasting
- **High**: C++ custom operators with potential bounds checking issues
- **Medium**: File handling utilities with path validation gaps in service layer
- **Medium**: Callable execution in CacheAgent without proper sanitization

---

## 1. Project Overview

| Attribute | Value |
|-----------|-------|
| Project Name | MindIE-SD |
| Version | 2.3.0 |
| License | Mulan PSL v2 |
| Vendor | Huawei Technologies Co., Ltd. |
| Languages | C/C++ (120 files), Python (148 files) |
| Architecture | Hybrid PyTorch Extension with NPU Integration |

### Module Structure

```
MindIE-SD/
├── csrc/                    # C++ source code
│   ├── ops/                 # Ascend kernel implementations
│   │   ├── ascendc/         # AscendC operators
│   │   ├── block_sparse_attention/
│   │   ├── laser_attention/
│   │   └── sparse_block_estimate/
│   └── plugin/              # PyTorch NPU plugin layer
│       ├── register_ops.cpp # Operator registration
│       ├── pytorch_npu_helper.h
│       └── *.cpp            # Individual operator implementations
├── mindiesd/                # Python package
│   ├── layers/              # High-level API wrapping C++ ops
│   ├── cache_agent/         # Attention/block cache
│   ├── quantization/        # Model quantization
│   ├── compilation/         # FX graph compilation
│   ├── eplb/                # Load balancing
│   ├── utils/               # Utilities (file, env, logging)
│   ├── offload.py           # Memory offload
│   └── share_memory.py      # ZMQ-based IPC
├── examples/
│   └── service/             # HTTP API service example
│       ├── server.py        # FastAPI server
│       ├── worker.py        # Ray distributed worker
│       └── request.py       # Request model
├── build/                   # Build scripts
└── tests/                   # Test cases
```

---

## 2. Attack Surface Analysis

### 2.1 Network Service (Critical)

**Location**: `examples/service/server.py`

| Aspect | Details |
|--------|---------|
| Endpoint | `/generate` POST |
| Binding | `0.0.0.0:6000` |
| Authentication | None |
| Framework | FastAPI + Ray |

**Attack Vector**: Direct network access to inference service without authentication. Any attacker on the network can:
1. Send arbitrary prompts for model inference
2. Control output file paths (`save_disk_path`)
3. Control checkpoint directories (`ckpt_dir`)
4. Provide arbitrary image files (`image`)

**Request Model** (`examples/service/request.py`):
```python
class GeneratorRequest(BaseModel):
    prompt: str                      # User text input
    save_disk_path: Optional[str]    # Arbitrary file path
    ckpt_dir: Optional[str]          # Model checkpoint path
    image: Optional[str]             # Input image file path
    # ... other parameters
```

**CWE Classifications**:
- CWE-306: Missing Authentication for Critical Function
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-20: Improper Input Validation

**Risk Assessment**: 
- **Impact**: High - Unauthorized model inference, file system manipulation, potential denial of service
- **Likelihood**: High - Service binds to all interfaces, no access controls
- **Severity**: **CRITICAL**

---

### 2.2 IPC Network Communication (High)

**Location**: `mindiesd/share_memory.py`

| Aspect | Details |
|--------|---------|
| Protocol | ZMQ TCP |
| Default Address | 127.0.0.1 (configurable) |
| Default Port | 5555+ (base_port configurable) |
| Purpose | NPU memory handle broadcasting |

**Attack Vector**: ZMQ sockets for inter-process memory sharing:
1. `master_addr` is configurable - can bind to external interfaces
2. Memory handles are broadcasted over network without encryption
3. No authentication mechanism for ZMQ connections

```python
def init_share_memory(instance_world_size: int, 
                      instance_id: int,
                      master_addr: str = "127.0.0.1",  # CONFIGURABLE
                      base_port: int = 5555):
    ...
    self.pub_socket.bind(f"tcp://{self.master_addr}:{self.pub_port}")
```

**CWE Classifications**:
- CWE-287: Improper Authentication
- CWE-319: Cleartext Transmission of Sensitive Information
- CWE-311: Missing Encryption of Sensitive Data

**Risk Assessment**:
- **Impact**: High - Memory handle exposure could enable unauthorized memory access
- **Likelihood**: Medium - Requires specific deployment configuration
- **Severity**: **HIGH**

---

### 2.3 File Operations (High)

**Location**: `examples/service/worker.py`, `mindiesd/utils/file_utils.py`

**Attack Vector**: User-controlled file paths in service layer:

| Operation | File | Line | Path Source |
|-----------|------|------|-------------|
| Image.open() | worker.py | 140 | request.image (user input) |
| save_video() | worker.py | 195 | request.save_disk_path (user input) |
| Model loading | worker.py | 278 | args.ckpt_dir (user input) |

**Existing Controls** (in `mindiesd/utils/file_utils.py`):
- Symlink detection: `check_path_is_link()`
- Path length limits: `MAX_PATH_LENGTH = 4096`
- File size limits: `MAX_FILE_SIZE`
- Permission checks: `check_max_permission()`
- Owner validation: `check_owner()`

**Gap Analysis**: 
- File utilities provide good validation but are **NOT USED** in the service layer
- `worker.py` directly uses `Image.open()` and `save_video()` without validation
- No sanitization of user-provided paths before file operations

**CWE Classifications**:
- CWE-22: Path Traversal
- CWE-73: External Control of File Name or Path

**Risk Assessment**:
- **Impact**: High - Arbitrary file read/write
- **Likelihood**: High - Direct user control of file paths
- **Severity**: **HIGH**

---

### 2.4 Custom Operators (Medium-High)

**Location**: `csrc/plugin/*.cpp`, `csrc/ops/*.cpp`

**Attack Vector**: C++ custom operators for attention and normalization:

| Operator | File | Key Concern |
|----------|------|-------------|
| block_sparse_attention | block_sparse_attention.cpp | Tensor bounds, sparse_mask handling |
| rainfusionattention | rainfusionattention.cpp | Block shape parameters |
| sparse_block_estimate | sparse_block_estimate.cpp | Threshold, sparse_size parameters |
| la | la.cpp | Attention mask handling |
| layernorm | layernorm.cpp | normalized_shape array |

**Tiling Overflow Risk**:
- `block_sparse_attention_tiling.cpp` (~266KB) contains complex tiling calculations
- Integer overflow potential in size calculations
- No explicit bounds checking on tensor dimensions

```cpp
// From register_ops.cpp
m.def("block_sparse_attention(Tensor query, Tensor key,  
    Tensor value, Tensor sparse_mask, Tensor sparse_count_table,  
    str input_layout='BNSD', int sparse_size=128, int num_heads=1, ...)");
```

**CWE Classifications**:
- CWE-787: Out-of-bounds Write
- CWE-125: Out-of-bounds Read
- CWE-190: Integer Overflow or Wraparound
- CWE-131: Incorrect Calculation of Buffer Size

**Risk Assessment**:
- **Impact**: High - Memory corruption, NPU crash
- **Likelihood**: Medium - Requires malformed tensor inputs
- **Severity**: **MEDIUM-HIGH**

---

### 2.5 Dynamic Library Loading (Medium)

**Location**: `csrc/plugin/pytorch_npu_helper.h`, `csrc/plugin/find_op_path.cpp`

**Attack Vector**: dlopen/dlsym-based library loading for ACLNN APIs:

```cpp
inline void* FindFuncInCustomLibPath(const char* apiName, const std::string& libPath) {
    void* handle = dlopen(libPath.c_str(), RTLD_LAZY);
    // ...
    void* funcAddr = dlsym(handle, apiName);
    return funcAddr;
}
```

**Paths loaded from**:
- `g_customLibPath` - configurable custom library paths
- `g_defaultCustomLibPath` - default library paths

**CWE Classifications**:
- CWE-427: Uncontrolled Search Path Element
- CWE-114: Process Control

**Risk Assessment**:
- **Impact**: High - Arbitrary code execution via library injection
- **Likelihood**: Low - Requires environment manipulation
- **Severity**: **MEDIUM**

---

### 2.6 Callable Execution (Medium)

**Location**: `mindiesd/cache_agent/cache_agent.py`

**Attack Vector**: Config-based callable function execution:

```python
def apply(self, function: callable, *args, **kwargs):
    if not callable(function):
        raise ParametersInvalid("Input function must be callable.")
    return self._cache_method.apply(function, *args, **kwargs)
```

**Concern**: While callable check exists, the function is executed with arbitrary arguments. If attacker can control the function passed to CacheAgent.apply(), arbitrary code execution is possible.

**CWE Classifications**:
- CWE-20: Improper Input Validation

**Risk Assessment**:
- **Impact**: High - Arbitrary code execution
- **Likelihood**: Low - Requires internal compromise
- **Severity**: **MEDIUM**

---

### 2.7 Environment Variable Parsing (Low)

**Location**: `mindiesd/utils/env.py`

**Attack Vector**: Environment variable parsing for logging configuration:

**Existing Controls**:
- String length limits: `MAX_STRING_LENGTH = 256`
- Character validation: `check_string_valid()` rejects control characters
- Regex parsing for rotate parameters

**Gap**: Log path (`MINDIE_LOG_PATH`) is parsed but may not be validated before file operations.

**Risk Assessment**:
- **Impact**: Low - Log injection, path traversal in logging
- **Likelihood**: Low - Requires environment manipulation
- **Severity**: **LOW**

---

### 2.8 Prompt Injection (Medium)

**Location**: `examples/service/request.py`, `worker.py`

**Attack Vector**: Text prompt processing for model inference:

- Prompt is passed directly to T5 encoder and model inference
- No content filtering or sanitization
- Potential for prompt injection attacks (model manipulation)

**CWE Classifications**:
- CWE-20: Improper Input Validation

**Risk Assessment**:
- **Impact**: Medium - Model behavior manipulation, output corruption
- **Likelihood**: Medium - Direct user control
- **Severity**: **MEDIUM**

---

## 3. High-Risk Module Analysis

### 3.1 examples/service (CRITICAL)

**Why High-Risk**:
1. HTTP API without authentication on public interface
2. Direct user control of file system paths
3. Ray distributed execution without access controls
4. Minimal Pydantic validation on request model

**Required Actions**:
- Add authentication mechanism (JWT, API keys)
- Implement rate limiting
- Use `file_utils.safe_open()` for all file operations
- Add path sanitization and directory restrictions
- Add prompt content filtering

---

### 3.2 mindiesd/share_memory (HIGH)

**Why High-Risk**:
1. Network-based IPC with configurable binding
2. Sensitive memory handles broadcasted without encryption
3. No authentication for ZMQ connections

**Required Actions**:
- Default binding to localhost only
- Add authentication for ZMQ connections
- Encrypt memory handles before transmission
- Validate master_addr against whitelist

---

### 3.3 csrc/plugin (HIGH)

**Why High-Risk**:
1. Custom operator implementations with tensor manipulation
2. ACLNN API calls with parameter checking gaps
3. Dynamic library loading for operator implementations

**Required Actions**:
- Add comprehensive bounds checking on tensor dimensions
- Validate all integer parameters against valid ranges
- Add overflow checks in tiling calculations
- Secure library path loading

---

### 3.4 csrc/ops/block_sparse_attention (HIGH)

**Why High-Risk**:
1. Complex tiling logic (~266KB source)
2. Multiple integer calculations with overflow potential
3. Hardware-specific memory layout handling

**Required Actions**:
- Add bounds assertions on all size calculations
- Validate sparse_size, num_heads against hardware limits
- Add unit tests for edge cases (large tensors)

---

### 3.5 mindiesd/cache_agent (MEDIUM)

**Why High-Risk**:
1. Callable function execution
2. Config validation gaps
3. Memory-intensive operations

**Required Actions**:
- Validate callable function against whitelist
- Add strict config validation
- Add memory usage limits

---

## 4. Data Flow Analysis

### Primary Data Flows

| Flow ID | Source | Path | Destination | Security Boundary |
|---------|--------|------|-------------|-------------------|
| DF001 | HTTP Request | request.py -> worker.py -> wan pipeline | Model Output | Yes (network) |
| DF002 | User Path | request.save_disk_path -> save_video() | File System | Yes (file) |
| DF003 | User Image | request.image -> Image.open() | PIL Image | Yes (file) |
| DF004 | Tensors | Python -> torch.ops.mindiesd -> ACLNN | NPU Hardware | Yes (Python/C++) |
| DF005 | Handles | ShareMemoryManager -> ZMQ -> Network | Remote Process | Yes (IPC) |
| DF006 | Prompt | request.prompt -> T5 encoder -> Model | Generated Content | No |

### Taint Propagation Points

1. **Entry Point**: HTTP API (`/generate`)
   - Taint Source: `prompt`, `save_disk_path`, `image`, `ckpt_dir`
   
2. **Propagation**: Through worker to model inference
   - Prompt -> T5 encoder (processed)
   - Paths -> File operations (used directly)
   
3. **Sink Points**:
   - File write: `save_video()` - needs validation
   - File read: `Image.open()` - needs validation
   - Model inference: T5 encoder - prompt injection risk
   - NPU memory: Shared handles - needs encryption

---

## 5. Security Control Assessment

### Existing Controls

| Control | Location | Effectiveness |
|---------|----------|---------------|
| Path validation | mindiesd/utils/file_utils.py | Good but unused in service |
| Symlink checks | file_utils.py | Good |
| Permission checks | file_utils.py | Good |
| Env validation | mindiesd/utils/env.py | Adequate |
| TORCH_CHECK | C++ operators | Partial |
| Pydantic model | request.py | Minimal |

### Missing Controls

| Control | Priority | Impact |
|---------|----------|--------|
| Authentication mechanism | Critical | Prevents unauthorized access |
| Rate limiting | High | Prevents DoS |
| Path sanitization in service | Critical | Prevents path traversal |
| Network authentication for IPC | High | Prevents handle exposure |
| Tensor bounds checking | Medium | Prevents memory corruption |
| Prompt content filtering | Medium | Prevents prompt injection |
| Library path validation | Medium | Prevents code injection |

---

## 6. Recommendations

### Critical Priority

1. **Add Authentication to HTTP Service**
   - Implement JWT or API key authentication
   - Add request signing for sensitive operations
   
2. **Implement Path Validation in Service Layer**
   - Use `file_utils.safe_open()` for all file operations
   - Restrict output directory to configured safe paths
   - Validate image input paths against whitelist
   
3. **Add Rate Limiting**
   - Limit requests per IP/user
   - Implement request queuing
   - Add timeout for long-running inference

### High Priority

4. **Secure ZMQ IPC**
   - Bind to localhost by default
   - Add authentication for ZMQ connections
   - Encrypt memory handles before transmission
   
5. **Add Tensor Bounds Checking**
   - Validate tensor dimensions in Python layer
   - Add overflow checks in C++ tiling calculations
   - Implement hardware limit validation

### Medium Priority

6. **Add Library Path Validation**
   - Whitelist allowed library directories
   - Verify library signatures
   - Add audit logging for library loading
   
7. **Add Prompt Filtering**
   - Implement content validation
   - Add length limits
   - Filter potentially malicious prompts
   
8. **Secure CacheAgent Callable**
   - Validate callable against registered functions
   - Add execution context restrictions

---

## 7. Conclusion

MindIE-SD presents significant security risks in its default service deployment configuration. The most critical vulnerability is the unauthenticated HTTP API with direct user control of file system operations. Immediate action is required to add authentication and path validation before deploying the service in production environments.

The C++ custom operators, while less directly exposed, contain potential memory safety issues that should be addressed through comprehensive bounds checking and overflow validation.

The security controls implemented in `file_utils.py` are well-designed but are not utilized in the service layer, creating a significant gap between defensive capabilities and actual deployment security.

---

**Report Generated**: 2026-04-17
**Analysis Tool**: OpenCode Vulnerability Scanner
**Project**: MindIE-SD v2.3.0