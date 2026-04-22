# MemCache_Hybrid Threat Analysis Report

## Executive Summary

MemCache_Hybrid is a distributed memory caching system similar to memcached, designed for deployment in Kubernetes clusters. The system provides high-performance caching through RDMA/TCP/Shared Memory protocols and includes HTTP management endpoints for monitoring and administration.

**Key Security Findings:**

1. **No Authentication on HTTP Endpoints**: All HTTP management endpoints (`/health`, `/get_all_keys`, `/query_key`, `/get_all_segments`, `/metrics`) are accessible without authentication, exposing cache metadata to any network-connected attacker.

2. **Unauthenticated RPC Protocol**: Network RPC handlers for critical operations (Alloc, Get, Remove, RemoveAll, BmRegister) accept requests from remote clients without apparent authentication or authorization checks.

3. **Python Bindings Memory Safety**: Python bindings accept raw memory pointers (`uintptr_t`) from user code, potentially enabling memory corruption if malicious pointers are passed.

4. **Configuration File Security**: Configuration parsing lacks input validation and sanitization, potentially allowing injection through configuration files.

5. **Dynamic Library Loading**: UBS IO proxy uses `dlopen()` to load external libraries, which could be exploited if library paths are manipulated.

---

## Project Profile

| Attribute | Value |
|-----------|-------|
| Project Type | Network Service (Distributed Memory Cache) |
| Deployment Model | Linux server daemon in Kubernetes clusters |
| Primary Languages | C/C++ (21,587 lines) + Python (454 lines) |
| Network Exposure | High - TCP/RDMA listeners + HTTP server |
| Authentication | Not detected in analyzed code paths |

---

## Attack Surface Analysis

### 1. HTTP Management Endpoints (Critical Risk)

| Endpoint | Function | Exposure | Data Exposed |
|----------|----------|----------|--------------|
| `/health` | RegisterHealthCheckEndpoint | Network | Service status |
| `/get_all_keys` | RegisterDataManagementEndpoints | Network | All cache keys |
| `/query_key?key=X` | RegisterDataManagementEndpoints | Network | Object metadata, locations |
| `/get_all_segments` | RegisterSegmentManagementEndpoints | Network | Memory segment info |
| `/metrics` | RegisterMetricsEndpoint | Network | Prometheus metrics |
| `/metrics/summary` | RegisterMetricsEndpoint | Network | Operational statistics |
| `/metrics/ptracer` | RegisterMetricsEndpoint | Network | Tracer diagnostics |

**Location**: `src/memcache/csrc/meta_service/mmc_http_server.cpp:37-159`

**Risk**: Any network-connected attacker can:
- Enumerate all cache keys (`/get_all_keys`)
- Query object metadata including storage locations (`/query_key`)
- Access internal diagnostics and metrics
- Potentially identify sensitive data patterns

### 2. Network RPC Protocol (Critical Risk)

| RPC Handler | Operation | Input Source | Risk |
|-------------|-----------|--------------|------|
| HandleAlloc | Memory allocation | Network serialized data | Unauthenticated memory operations |
| HandleGet | Object retrieval | Network serialized data | Information disclosure |
| HandleRemove | Object deletion | Network serialized data | Unauthorized data destruction |
| HandleRemoveAll | Bulk deletion | Network serialized data | Mass data destruction |
| HandleBmRegister | Buffer manager registration | Network serialized data | Resource manipulation |
| HandlePing | Heartbeat | Network serialized data | Network reconnaissance |

**Location**: `src/memcache/csrc/meta_service/mmc_meta_net_server.cpp:50-80`

**Data Flow**: Network → NetMsgUnpacker::Deserialize → Request handlers → Internal operations

### 3. Protocol Deserialization (High Risk)

The `NetMsgUnpacker` class deserializes arbitrary network data:

```cpp
void Deserialize(std::string &val) {
    uint32_t size = 0;
    inStream_.read(reinterpret_cast<char *>(&size), sizeof(size));
    val.resize(size);  // No upper bound validation (only MAX_CONTAINER_SIZE for vectors)
    inStream_.read(&val[0], size);
}
```

**Location**: `src/memcache/csrc/proto/mmc_msg_packer.h:135-141`

**Concerns**:
- String size read from network without individual validation (vector has `MAX_CONTAINER_SIZE = 1MB` check)
- Could lead to memory exhaustion if malicious large sizes are sent

### 4. Python Bindings Memory Operations (High Risk)

Python bindings accept raw memory pointers via `uintptr_t`:

| Function | Risk | Description |
|----------|------|-------------|
| `register_buffer(buffer_ptr, size)` | Memory corruption | Accepts arbitrary pointer for RDMA registration |
| `get_into(key, buffer_ptr, size)` | Memory write to arbitrary address | Writes data to user-provided buffer |
| `put_from(key, buffer_ptr, size)` | Memory read from arbitrary address | Reads data from user-provided buffer |
| `get_into_layers(key, buffer_ptrs, sizes)` | Multiple memory operations | Batch memory operations |

**Location**: `src/memcache/csrc/python_wrapper/pymmc.cpp:641-716`

**Attack Vector**: Malicious Python code could pass invalid pointers causing:
- Memory corruption
- Information disclosure
- Crash/DoS

### 5. Configuration File Security (Medium Risk)

Configuration loading via KVParser:

```cpp
bool Configuration::LoadFromFile(const std::string &filePath) {
    auto *kvParser = new KVParser();
    kvParser->FromFile(filePath);  // Reads file without validation
    // ... sets configuration values directly
}
```

**Location**: `src/memcache/csrc/config/mmc_configuration.cpp:119-155`

**Concerns**:
- No apparent sanitization of configuration values
- Path values may not be validated before use
- Memory size parsing could overflow (has overflow check via `WillMemSizeOverflow`)

### 6. TLS Certificate Path Validation (Medium Risk)

TLS validation checks for symlinks:

```cpp
int Configuration::ValidateTLSConfig(const mmc_tls_config &tlsConfig) {
    MMC_RETURN_ERROR(ValidatePathNotSymlink(item.first), "does not exist or is symlink");
}
```

**Location**: `src/memcache/csrc/config/mmc_configuration.cpp:523-557`

**Concerns**:
- Symlink validation could be bypassed if file is replaced after validation
- No apparent certificate content validation

### 7. Dynamic Library Loading (Medium Risk)

UBS IO proxy uses dynamic library loading:

```cpp
Result DlDfcApi::LoadLibrary() {
    // dlopen() call for external library
}
```

**Location**: `src/memcache/csrc/under_api/ubs_io/dl_dfc_api.cpp:35`

**Attack Vector**: If library path is manipulated, arbitrary code could be loaded.

---

## STRIDE Threat Model

### Spoofing

| Threat | Location | Likelihood | Impact |
|--------|----------|------------|--------|
| RPC Client Identity Spoofing | mmc_meta_net_server.cpp:50-80 | High | Critical - Unauthenticated clients can perform operations |
| Kubernetes Pod Identity Spoofing | meta_service_leader_election.py:113 | Medium | High - Could hijack leader election |

**Mitigation Gaps**:
- No client authentication in RPC protocol
- No certificate validation beyond existence checks
- Leader election relies on Kubernetes identity (assumed secure)

### Tampering

| Threat | Location | Likelihood | Impact |
|--------|----------|------------|--------|
| Cache Data Tampering via RPC | mmc_meta_net_server.cpp:167,274 | High | Critical - RemoveAll can destroy all data |
| Configuration File Tampering | mmc_configuration.cpp:119 | Medium | High - Config affects all operations |
| Memory Tampering via Python | pymmc.cpp:641-716 | Medium | Critical - Pointer manipulation |

**Mitigation Gaps**:
- No integrity checks on cached data
- No configuration file checksum validation
- Python bindings accept arbitrary pointers

### Repudiation

| Threat | Location | Likelihood | Impact |
|--------|----------|------------|--------|
| Unaudited Cache Operations | All RPC handlers | High | High - No operation attribution |
| Unaudited HTTP Access | mmc_http_server.cpp | High | Medium - HTTP endpoints lack logging |

**Mitigation Gaps**:
- Audit logging exists (`MMC_AUDIT_LOG`) but not visible for all operations
- HTTP access not logged at endpoint level

### Information Disclosure

| Threat | Location | Likelihood | Impact |
|--------|----------|------------|--------|
| Key Enumeration via HTTP | mmc_http_server.cpp:55 | High | Critical - Exposes all cache keys |
| Object Metadata Disclosure | mmc_http_server.cpp:80 | High | High - Exposes storage locations |
| Metrics Exposure | mmc_http_server.cpp:133 | High | Medium - Internal statistics exposed |
| Memory Disclosure via Python | pymmc.cpp:658-716 | Medium | High - Arbitrary memory read |

**Mitigation Gaps**:
- HTTP endpoints completely unauthenticated
- No rate limiting on key queries
- Python bindings allow arbitrary memory read

### Denial of Service

| Threat | Location | Likelihood | Impact |
|--------|----------|------------|--------|
| Memory Exhaustion via Large Strings | mmc_msg_packer.h:135 | Medium | High - Unbounded string resize |
| RemoveAll RPC Attack | mmc_meta_net_server.cpp:305 | High | Critical - Bulk deletion |
| Resource Exhaustion via BmRegister | mmc_meta_net_server.cpp:97 | Medium | High - Resource registration |
| Python Pointer DoS | pymmc.cpp:641 | Medium | High - Invalid pointers cause crash |

**Mitigation Gaps**:
- Vector size limit (`MAX_CONTAINER_SIZE = 1MB`) exists but string resize lacks individual upper bound
- No rate limiting on bulk operations
- No resource quotas on registration

### Elevation of Privilege

| Threat | Location | Likelihood | Impact |
|--------|----------|------------|--------|
| Leader Election Hijacking | meta_service_leader_election.py:113 | Medium | Critical - Leader has full control |
| Dynamic Library Injection | dl_dfc_api.cpp:35 | Low | Critical - Code execution |
| Memory Corruption Exploitation | pymmc.cpp:641-716 | Medium | Critical - Potential code execution |

**Mitigation Gaps**:
- Leader election relies on Kubernetes security (out of scope)
- Library path comes from configuration (assumed trusted)
- Python bindings exposed to application code

---

## High-Risk Files Summary

| File | Risk Level | Primary Concerns |
|------|------------|------------------|
| mmc_http_server.cpp | Critical | Unauthenticated HTTP endpoints exposing metadata |
| mmc_meta_net_server.cpp | Critical | Unauthenticated RPC handlers for critical operations |
| pymmc.cpp | Critical | Python bindings accepting raw memory pointers |
| mmc_msg_packer.h | High | Deserialization without full bounds validation |
| mmc_configuration.cpp | High | Configuration parsing without sanitization |
| mmc_client.cpp | High | Client API accepting user keys without validation |
| mmc_meta_manager.cpp | High | Core operations on user-provided keys |
| mmcache_store.cpp | High | High-level API processing user data |
| meta_service_leader_election.py | Medium | Kubernetes API interaction |

---

## Key Entry Points

### Primary Attack Entry Points

1. **HTTP Endpoints** (`mmc_http_server.cpp:47-159`)
   - Network accessible without authentication
   - Expose cache metadata and internal state

2. **RPC Network Handlers** (`mmc_meta_net_server.cpp:50-80`)
   - Accept serialized requests from remote clients
   - Process operations on cache data

3. **Python Bindings** (`pymmc.cpp:611-859`)
   - Exposed to Python application code
   - Accept memory pointers and user keys

### Secondary Entry Points

4. **Configuration File** (`mmc_configuration.cpp:119`)
   - Loaded at startup
   - Affects runtime behavior

5. **Kubernetes Leader Election** (`meta_service_leader_election.py`)
   - External API interaction
   - Controls service leadership

6. **Dynamic Library Loading** (`dl_dfc_api.cpp`)
   - External library path
   - Code execution capability

---

## Recommendations

### Critical (Immediate)

1. **Add Authentication to HTTP Endpoints**: Implement token-based or certificate authentication for all HTTP management endpoints.

2. **Add Authentication to RPC Protocol**: Implement client authentication and authorization checks before processing RPC requests.

3. **Validate Memory Pointers in Python Bindings**: Add validation for `uintptr_t` inputs to ensure they point to valid, registered memory regions.

4. **Add Input Validation for Keys**: Implement key content validation (no control characters, length enforcement, character whitelist).

### High (Short-term)

5. **Add Rate Limiting**: Implement rate limiting on bulk operations (RemoveAll, BatchGet, BatchPut).

6. **Add Bounds Validation**: Add upper bounds to all deserialized string sizes.

7. **Add Configuration Validation**: Implement schema validation and sanitization for configuration values.

8. **Enhance Audit Logging**: Ensure all cache operations are logged with client attribution.

### Medium (Long-term)

9. **Add Integrity Checks**: Implement checksums for cached data to detect tampering.

10. **Secure Library Loading**: Add signature verification for dynamically loaded libraries.

11. **Add Certificate Content Validation**: Validate TLS certificate contents beyond file existence.

---

## Appendix: Module Risk Assessment

| Module | Files | Risk | Primary Concerns |
|--------|-------|------|------------------|
| meta_service | 14 | Critical | HTTP/RPC endpoints without authentication |
| python_wrapper | 3 | Critical | Memory pointer handling from Python |
| proto | 4 | High | Protocol deserialization bounds |
| client | 3 | High | User input handling |
| config | 6 | High | Configuration parsing |
| net | 4 | High | Network engine exposed to remote data |
| local_service | 4 | Medium | Local operations |
| ha | 3 | Medium | Leader election |
| under_api | 4 | Medium | External library calls |
| common | 12 | Low | Utility functions |
| daemon | 1 | Low | Entry point |
| entities | 4 | Low | Data structures |
| log | 1 | Low | Logging |
| python | 2 | Medium | Leader election script |

---

*Report generated: 2026-04-21*
*Analyzer: Architecture Agent*
*Project: MemCache_Hybrid*