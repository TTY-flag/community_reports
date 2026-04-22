# Threat Analysis Report: MemFabric Hybrid

## Executive Summary

**Project**: MemFabric Hybrid (华为 MindCluster 内存池化组件)
**Vendor**: Huawei Technologies Co., Ltd.
**License**: Mulan PSL v2
**Analysis Date**: 2026-04-21
**Analysis Mode**: Autonomous (无 threat.md 约束文件)

MemFabric Hybrid 是华为 MindCluster 的核心内存池化软件，实现 DRAM/HBM 混合池化，支持 RDMA、SDMA、共享内存等多种传输方式。本项目是一个 C/C++ + Python 混合项目，包含约 284 个源文件，涉及网络通信、RDMA 远程内存访问、TLS/SSL 安全通信、内核驱动交互等多个高风险领域。

### Key Findings

| Category | Count | Risk Level |
|----------|-------|------------|
| Network Entry Points | 5 | HIGH |
| IPC Entry Points | 3 | HIGH |
| API Interfaces | 3 | HIGH |
| Configuration Interfaces | 2 | MEDIUM |
| Dynamic Library Interfaces | 4 | HIGH |
| Taint Flows Identified | 8 | HIGH |
| High-Risk Functions | 9 | HIGH |

### Overall Risk Assessment: **HIGH**

---

## 1. Project Architecture Overview

### 1.1 Module Structure

The project consists of four main modules:

#### hybm (Hybrid Big Memory)
- **Description**: Global Memory Management, Data Operation, Transport Management
- **Sub-modules**:
  - `driver`: Device driver and userspace communication (ioctl interface)
  - `transport`: RDMA and network transport (device/host RDMA, QP management)
  - `data_operation`: Data copy operations (RDMA, SDMA, SHM, MTE)
  - `mm`: Memory management (segments, VA manager)
  - `under_api`: Dynamic library APIs (ACL, HAL, HCCL, HCCP, HCOM)
- **Risk Level**: **HIGH**

#### smem (Shared Memory)
- **Description**: Semantic interfaces, config store, network engine
- **Sub-modules**:
  - `config_store`: TCP store, etcd backend, HA config
  - `net`: Network group engine for distributed coordination
  - `smem_shm/smem_bm/smem_trans`: Memory operations
  - `python_wrapper`: Python bindings (pybind11)
- **Risk Level**: **HIGH**

#### acc_links (Accelerator Links)
- **Description**: TCP server, SSL/TLS helper, internal communication
- **Sub-modules**:
  - `tcp_server`: TCP connection handling
  - `security`: SSL/TLS certificate handling
  - `under_api`: OpenSSL dynamic loading
- **Risk Level**: **HIGH**

#### util
- **Description**: Utility functions
- **Sub-modules**: Logging, file ops, fault injection, etcd client (Go)
- **Risk Level**: **MEDIUM**

---

## 2. Attack Surface Analysis

### 2.1 Network Interfaces

#### 2.1.1 TCP Config Store Server

**File**: `src/smem/csrc/config_store/tcp_store/smem_tcp_config_store_server.cpp`
**Function**: `AccStoreServer::Startup`
**Protocol**: TCP with optional TLS 1.3
**Risk Level**: HIGH

**Attack Vectors**:
- **Message Injection**: Malformed `SmemMessage` structure injection via TCP connection
- **Key/Value Injection**: Arbitrary key-value pairs stored in configuration backend
- **DoS Attack**: Excessive requests causing resource exhaustion
- **TLS Certificate Spoofing**: If TLS disabled, certificate validation bypassed

**Data Flow**:
```
TCP Connection → ReceiveMessageHandler → SmemMessagePacker::Unpack → Request Handlers → backend_->Put/Get
```

**Mitigations Present**:
- TLS 1.3 with certificate validation
- Message type validation (MessageType enum check)
- Key size limit (MAX_KEY_LEN_SERVER = 1024)
- Value size limit (MAX_VALUE_SIZE = 10MB)

**Remaining Vulnerabilities**:
- No integrity check on message structure beyond size validation
- Potential for integer overflow in AddHandler (mitigated at line 614-619)

#### 2.1.2 TCP Accelerator Link Server

**File**: `src/acc_links/csrc/acc_tcp_server_default.cpp`
**Function**: `AccTcpServerDefault::Start`
**Protocol**: TCP with TLS 1.3
**Risk Level**: HIGH

**Attack Vectors**:
- **Connection Hijacking**: Unauthorized connection establishment
- **Magic/Version Spoofing**: Handshake bypass via magic/version manipulation
- **SSL Certificate Manipulation**: Certificate validation bypass
- **Man-in-the-middle**: If TLS disabled, traffic interception

**Handshake Validation** (Line 361-370):
```cpp
if (req.magic != options_.magic) {
    LOG_ERROR("New link connected but magic mismatched, refuse the link...");
    return ACC_ERROR;
}
if (req.version != options_.version) {
    LOG_ERROR("New link connected but version mismatched...");
    return ACC_ERROR;
}
```

**Mitigations**:
- Magic number validation
- Version matching
- TLS 1.3 with peer certificate verification

#### 2.1.3 RDMA Device Transport

**File**: `src/hybm/csrc/transport/device/device_rdma_transport_manager.cpp`
**Function**: `RdmaTransportManager::OpenDevice`
**Protocol**: RDMA over RoCE/UB
**Risk Level**: HIGH

**Attack Vectors**:
- **Unauthorized Memory Region Registration**: Registration of arbitrary memory regions
- **QP Hijacking**: Queue Pair manipulation
- **Remote Memory Read/Write**: Unauthorized remote memory access
- **RDMA Packet Injection**: Injection of RDMA operations

**Critical Functions**:
- `RegisterMemoryRegion`: Registers memory for RDMA access
- `QueryMemoryKey`: Returns memory keys for remote access
- `ReadRemote/WriteRemote`: Remote memory operations

**Remaining Vulnerabilities**:
- Memory address validation relies on caller
- No bounds checking on remote memory access addresses
- Memory key exposure enables unauthorized access

### 2.2 IPC Interfaces

#### 2.2.1 Shared Memory Operations

**File**: `src/smem/csrc/smem_shm/smem_shm.cpp`
**Function**: `smem_shm_create`
**Risk Level**: HIGH

**Attack Vectors**:
- **Shared Memory Race Conditions**: Concurrent access without proper synchronization
- **Memory Disclosure**: GVA address exposure
- **Use-after-free**: Improper memory lifecycle management
- **Double-free**: Memory deallocation issues

**GVA (Global Virtual Address) Handling**:
- GVA is a simple uint64 address
- All processes share the same GVA space
- GVA can be used to access remote memory directly

#### 2.2.2 Device IOCTL Interface

**File**: `src/hybm/csrc/driver/userspace/devmm_ioctl.cpp`
**Function**: `HybmMapShareMemory`
**Risk Level**: HIGH

**Attack Vectors**:
- **ioctl Parameter Manipulation**: Kernel driver parameter injection
- **Kernel Memory Corruption**: Driver vulnerability exploitation
- **Privilege Escalation**: Kernel driver exploitation

**ioctl Operations**:
- `DEVMM_SVM_IPC_MEM_OPEN`: Open shared memory
- `DEVMM_SVM_IPC_MEM_QUERY`: Query memory size
- `DEVMM_SVM_PREFETCH`: Prefetch memory
- `DEVMM_SVM_ALLOC`: Allocate SVM memory
- `DEVMM_SVM_ADVISE`: Memory advise

### 2.3 API Interfaces

#### 2.3.1 C API - smem_bm

**File**: `src/smem/include/host/smem_bm.h`
**Risk Level**: HIGH

**Attack Vectors**:
- **Parameter Injection**: Invalid parameters to API functions
- **Memory Address Manipulation**: GVA address spoofing
- **Copy Size Overflow**: Large copy size causing memory corruption

**Key Functions**:
- `smem_bm_init`: Initialize big memory
- `smem_bm_create`: Create memory object
- `smem_bm_copy`: Copy data between memory regions
- `smem_bm_copy_batch`: Batch copy operations
- `smem_bm_register_user_mem`: Register user memory

#### 2.3.2 Python API

**File**: `src/smem/csrc/python_wrapper/memfabric_hybrid/pymf_hybrid.cpp`
**Risk Level**: HIGH

**Attack Vectors**:
- **Python Callback Injection**: Injected callback for TLS decryption
- **Memory Address Passing**: Python passing addresses to C++
- **Decrypt Handler Manipulation**: Custom decrypt handler injection

**Critical: Python Decrypt Handler** (Line 374-415):
```cpp
static int py_decrypt_handler_wrapper(const char *cipherText, size_t cipherTextLen, 
                                       char *plainText, size_t &plainTextLen) {
    // Decrypts private key password via Python callback
    std::string plain = py::cast<std::string>(g_py_decrypt_func(py_cipher).cast<py::str>());
    // Password used for SSL private key decryption
}
```

This is a HIGH-RISK injection point - Python code can inject arbitrary decryption logic.

---

## 3. Taint Flow Analysis

### TF001: TCP Message to KV Store

**Severity**: HIGH
**CWE**: CWE-20 (Improper Input Validation)

**Source**: `context.DataPtr()` at `AccStoreServer::ReceiveMessageHandler` (line 167)
**Propagation**: `SmemMessagePacker::Unpack` → `message.keys, message.values`
**Sink**: `backend_->Put(key, value)` (line 356)

**Description**: Raw binary data from TCP connection is unpacked and stored in configuration backend without comprehensive validation.

### TF002: RDMA Remote Memory Read to Local Memory

**Severity**: HIGH
**CWE**: CWE-125 (Out-of-bounds Read)

**Source**: `rAddr` at `transportManager_->ReadRemote` (line 200)
**Propagation**: `HostDataOpRdma::SafeGet` → `tmpHost` → `DlHybridApi::Memcpy`
**Sink**: `destVA` (application memory)

**Description**: Remote memory address specified by caller is used to read data without bounds validation.

### TF003: Python Decrypt Callback to SSL Context

**Severity**: HIGH
**CWE**: CWE-94 (Code Injection)

**Source**: `cipherText` at `g_py_decrypt_func` (line 374)
**Propagation**: `py_decrypt_handler_wrapper` → `buffer`
**Sink**: `mKeyPass.first` in `OpenSslApiWrapper::SslCtxSetDefaultPasswdCbUserdata`

**Description**: Python callback injects decrypted private key password into SSL context. This is a critical code injection point.

### TF004: Dynamic Library Path Loading

**Severity**: HIGH
**CWE**: CWE-426 (Untrusted Search Path)

**Source**: `dynLibPath` at `OpenSslApiWrapper::Load` (line 20)
**Propagation**: `FileUtil::Realpath` → `libPath`
**Sink**: `dlopen(libPath)`

**Description**: Dynamic library path from configuration is loaded into process. Symlink validation exists but path manipulation possible.

### TF005: Certificate File Path to SSL Context

**Severity**: HIGH
**CWE**: CWE-295 (Improper Certificate Validation)

**Source**: `tlsTopPath + tlsCert` (configuration)
**Propagation**: `AccTcpSslHelper::LoadServerCert` → `tmpPath`
**Sink**: `OpenSslApiWrapper::SslCtxUseCertificateFile`

**Description**: Certificate path from configuration loaded into SSL context. Certificate validation performed but path spoofing possible.

### TF006: WriteHandler Offset to Memory Write

**Severity**: HIGH
**CWE**: CWE-787 (Out-of-bounds Write)

**Source**: `value.data()` at `AccStoreServer::WriteHandler` (line 711)
**Propagation**: `offset` extracted from value
**Sink**: `std::copy_n(curValue.data() + offset)` (line 768)

**Description**: Offset from network message used for memory write. Bounds checking present but potential for overflow.

**Mitigations** (Lines 733-746):
```cpp
if (realValSize > SIZE_MAX / static_cast<size_t>(MAX_U16_INDEX)) {
    STORE_LOG_ERROR("WRITE realValSize too large...");
}
STORE_VALIDATE_RETURN(offset <= MAX_U16_INDEX * realValSize, "offset too large...");
if (totalSize < realValSize) { // overflow check
    STORE_LOG_ERROR("WRITE offset+realValSize overflow...");
}
```

### TF007: AddHandler Integer Overflow

**Severity**: MEDIUM
**CWE**: CWE-190 (Integer Overflow)

**Source**: `request.values[0]` at `AccStoreServer::AddHandler` (line 566)
**Propagation**: `valueNum` → `storedValueNum`
**Sink**: `storedValueNum += valueNum` (line 621)

**Mitigations Present** (Lines 614-620):
```cpp
if ((valueNum > 0 && storedValueNum > LONG_MAX - valueNum) ||
    (valueNum < 0 && storedValueNum < LONG_MIN - valueNum)) {
    LOG_ERROR("ADD overflow...");
}
```

### TF008: GVA Address to Memory Operations

**Severity**: HIGH
**CWE**: CWE-119 (Buffer Overflow)

**Source**: `params.src, params.dest` at `smem_bm_copy` (line 150)
**Propagation**: `HostDataOpRdma::TransformVa`
**Sink**: `HostDataOpRdma::SafePut` / `SafeGet`

**Description**: Global Virtual Address from API used directly for memory operations without bounds validation.

---

## 4. High-Risk Functions

| Function | File | Line | Risk | CWE |
|----------|------|------|------|-----|
| `SmemMessagePacker::Unpack` | smem_message_packer.cpp | 89 | Network unpacking without validation | CWE-20, CWE-787 |
| `AccTcpSslHelper::LoadPrivateKey` | acc_tcp_ssl_helper.cpp | 191 | Private key decryption callback injection | CWE-94, CWE-327 |
| `RdmaTransportManager::RemoteIO` | device_rdma_transport_manager.cpp | 718 | Remote memory access | CWE-119, CWE-125, CWE-787 |
| `HostDataOpRdma::SafePut` | hybm_data_op_host_rdma.cpp | 267 | Unvalidated RDMA write | CWE-787, CWE-20 |
| `HostDataOpRdma::SafeGet` | hybm_data_op_host_rdma.cpp | 321 | Unvalidated RDMA read | CWE-125, CWE-20 |
| `AccStoreServer::WriteHandler` | smem_tcp_config_store_server.cpp | 711 | Offset-based memory write | CWE-787 |
| `HybmMapShareMemory` | devmm_ioctl.cpp | 48 | ioctl to kernel driver | CWE-782, CWE-20 |
| `OpenSslApiWrapper::Load` | openssl_api_dl.cpp | 20 | Dynamic library loading | CWE-426, CWE-114 |
| `py_decrypt_handler_wrapper` | pymf_hybrid.cpp | 374 | Python callback for crypto | CWE-94, CWE-20 |

---

## 5. Trust Boundaries

### 5.1 Network - External
**Boundary**: TCP/RDMA connections from external nodes
**Crosses**:
- TCP Config Store Server
- TCP Accelerator Link Server
- RDMA Transport Managers

**Security Measures**:
- TLS 1.3 with mutual authentication
- Magic/version handshake validation
- Certificate verification with CRL

### 5.2 IPC - Shared Memory
**Boundary**: Shared memory segments
**Crosses**:
- smem_shm operations
- Memory segment management

**Security Measures**:
- Memory region registration
- VA transformation

### 5.3 Kernel - Userspace
**Boundary**: ioctl interface
**Crosses**:
- devmm_ioctl.cpp
- npu_direct_rdma.c

**Security Measures**:
- Name length validation
- ioctl structure validation

### 5.4 Python - C++
**Boundary**: Python bindings crossing to native code
**Crosses**:
- pymf_hybrid.cpp
- pytransfer.cpp

**Security Measures**:
- GIL management
- Parameter validation

### 5.5 Dynamic Library - Native
**Boundary**: dlopen/dlsym calls
**Crosses**:
- dl_acl_api.cpp, dl_hccp_api.cpp, openssl_api_dl.cpp, dl_etcd_api.cpp

**Security Measures**:
- realpath validation
- Symlink detection

---

## 6. Vulnerability Categories

### 6.1 Memory Safety Vulnerabilities

**RDMA Operations**:
- Remote memory read/write without bounds checking
- Memory address validation relies on caller
- Memory key exposure enables unauthorized access

**Shared Memory**:
- Race conditions possible
- GVA address handling without bounds validation

**ioctl Interface**:
- Kernel driver interaction
- Parameter validation limited

### 6.2 Input Validation Vulnerabilities

**TCP Message Handling**:
- SmemMessage unpacking with size limits only
- No semantic validation of message content
- Key/value injection possible

**Python API**:
- Address passing from Python to C++
- Decrypt callback injection

### 6.3 Cryptographic Vulnerabilities

**TLS Configuration**:
- Certificate path manipulation possible
- Private key decryption callback injection
- CRL expiration handling

**Dynamic Library Loading**:
- OpenSSL library path injection
- Symbol hijacking possible

### 6.4 Privilege Escalation

**Kernel Driver**:
- ioctl interface enables kernel interaction
- Potential for driver exploitation

**Dynamic Library Loading**:
- Library injection enables code execution

---

## 7. Recommendations

### 7.1 Critical Recommendations

1. **Add semantic validation to SmemMessagePacker::Unpack**
   - Validate message structure beyond size
   - Add checksum/integrity verification
   - Implement message authentication

2. **Implement bounds checking for RDMA operations**
   - Validate remote addresses against registered regions
   - Add size limits for remote operations
   - Implement authorization checks for memory keys

3. **Secure Python decrypt callback**
   - Implement callback whitelist
   - Add callback authentication
   - Limit callback execution context

4. **Enhance TLS certificate validation**
   - Add certificate fingerprint verification
   - Implement certificate path whitelist
   - Add CRL automatic refresh

### 7.2 High Priority Recommendations

1. **Add message authentication to TCP protocol**
   - Implement HMAC for message integrity
   - Add sequence numbers for replay protection

2. **Implement memory region authorization**
   - Add per-rank memory access control
   - Implement memory access logging

3. **Enhance ioctl parameter validation**
   - Add comprehensive parameter validation
   - Implement ioctl logging

### 7.3 Medium Priority Recommendations

1. **Add input sanitization for all API parameters**
   - Implement parameter range checking
   - Add type validation

2. **Implement comprehensive logging**
   - Add security event logging
   - Implement anomaly detection

3. **Add fuzz testing**
   - TCP message handling
   - RDMA operations
   - Python API

---

## 8. Summary Statistics

| Metric | Value |
|--------|-------|
| Total Source Files | 284 |
| High-Risk Entry Points | 12 |
| Medium-Risk Entry Points | 3 |
| Taint Flows Identified | 8 |
| High-Risk Functions | 9 |
| Trust Boundaries | 5 |
| Cross-Module Calls | 7 |

### CWE Distribution

| CWE ID | Count | Description |
|--------|-------|-------------|
| CWE-20 | 6 | Improper Input Validation |
| CWE-787 | 5 | Out-of-bounds Write |
| CWE-125 | 3 | Out-of-bounds Read |
| CWE-119 | 2 | Buffer Overflow |
| CWE-94 | 2 | Code Injection |
| CWE-426 | 2 | Untrusted Search Path |
| CWE-295 | 1 | Improper Certificate Validation |
| CWE-327 | 1 | Broken Cryptographic Algorithm |
| CWE-190 | 1 | Integer Overflow |
| CWE-782 | 1 | Exposed IOCTL |
| CWE-114 | 1 | Process Control |

---

## 9. Appendix

### 9.1 Files Analyzed

Key files analyzed in this assessment:
- `src/smem/csrc/config_store/tcp_store/smem_tcp_config_store_server.cpp` (1270 lines)
- `src/acc_links/csrc/acc_tcp_server_default.cpp` (686 lines)
- `src/acc_links/csrc/security/acc_tcp_ssl_helper.cpp` (612 lines)
- `src/hybm/csrc/transport/device/device_rdma_transport_manager.cpp` (1024 lines)
- `src/hybm/csrc/data_operation/host/hybm_data_op_host_rdma.cpp` (1099 lines)
- `src/hybm/csrc/driver/userspace/devmm_ioctl.cpp` (148 lines)
- `src/smem/csrc/config_store/tcp_store/smem_message_packer.cpp` (148 lines)
- `src/smem/csrc/python_wrapper/memfabric_hybrid/pymf_hybrid.cpp` (845 lines)
- `src/smem/csrc/config_store/backend/smem_etcd_store_backend.cpp` (316 lines)
- `src/smem/csrc/net/smem_net_group_engine.cpp` (1278+ lines)

### 9.2 Analysis Limitations

- Static analysis only (no runtime testing)
- No dynamic library content validation
- Python callback analysis limited
- Kernel driver behavior not fully analyzed

---

**Report Generated**: 2026-04-21
**Analyzer**: Autonomous Security Analysis Agent
**Confidence Level**: High (based on comprehensive code review)