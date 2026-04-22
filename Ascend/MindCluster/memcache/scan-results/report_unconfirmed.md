# 漏洞扫描报告 — 待确认漏洞

**项目**: memcache
**扫描时间**: 2026-04-21T06:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 3 | 75.0% |
| CONFIRMED | 1 | 25.0% |
| **总计** | **4** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 1 | 33.3% |
| Medium | 2 | 66.7% |
| **有效漏洞总计** | **3** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-PYW-002]** Sensitive Configuration Information Exposure (High) - `src/memcache/csrc/python_wrapper/pymmc.cpp:345` @ `LocalConfig.__str__,MetaConfig.__str__` | 置信度: 65
2. **[VULN-SEC-PYW-003]** TLS Configuration Path Injection (Medium) - `src/memcache/csrc/python_wrapper/pymmc.cpp:168` @ `LocalConfig.tls_key_path,LocalConfig.tls_key_pass_path,LocalConfig.tls_decrypter_path` | 置信度: 75
3. **[VULN-SEC-PYW-004]** Arbitrary Dynamic Library Path Configuration (Medium) - `src/memcache/csrc/python_wrapper/pymmc.cpp:216` @ `tls_decrypter_path setters` | 置信度: 75

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@src/memcache/csrc/daemon/mmc_daemon.cpp` | cmdline | trusted_admin | Daemon process entry point, started by system administrator or Kubernetes | Main entry point for meta service daemon process |
| `RegisterHealthCheckEndpoint@src/memcache/csrc/meta_service/mmc_http_server.cpp` | web_route | untrusted_network | HTTP endpoint /health accessible without authentication | Health check HTTP endpoint - no authentication required |
| `RegisterDataManagementEndpoints@src/memcache/csrc/meta_service/mmc_http_server.cpp` | web_route | untrusted_network | HTTP endpoints /get_all_keys, /query_key accessible without authentication | Data management HTTP endpoints - expose cache metadata |
| `RegisterSegmentManagementEndpoints@src/memcache/csrc/meta_service/mmc_http_server.cpp` | web_route | untrusted_network | HTTP endpoint /get_all_segments accessible without authentication | Segment management HTTP endpoint - expose memory segment info |
| `RegisterMetricsEndpoint@src/memcache/csrc/meta_service/mmc_http_server.cpp` | web_route | untrusted_network | HTTP endpoints /metrics, /metrics/summary, /metrics/ptracer accessible without authentication | Metrics HTTP endpoints - expose Prometheus metrics |
| `HandleAlloc@src/memcache/csrc/meta_service/mmc_meta_net_server.cpp` | rpc | untrusted_network | RPC handler for allocation requests from remote clients | RPC handler for AllocRequest - allocates memory objects |
| `HandleBmRegister@src/memcache/csrc/meta_service/mmc_meta_net_server.cpp` | rpc | untrusted_network | RPC handler for buffer manager registration from remote clients | RPC handler for BmRegisterRequest - registers buffer managers |
| `HandleBmUnregister@src/memcache/csrc/meta_service/mmc_meta_net_server.cpp` | rpc | untrusted_network | RPC handler for buffer manager unregistration from remote clients | RPC handler for BmUnregisterRequest - unregisters buffer managers |
| `HandlePing@src/memcache/csrc/meta_service/mmc_meta_net_server.cpp` | rpc | untrusted_network | RPC handler for ping requests from remote clients | RPC handler for PingMsg - network heartbeat |
| `HandleGet@src/memcache/csrc/meta_service/mmc_meta_net_server.cpp` | rpc | untrusted_network | RPC handler for get requests from remote clients | RPC handler for GetRequest - retrieves cached objects |
| `HandleAlloc@src/memcache/csrc/meta_service/mmc_meta_net_server.cpp` | rpc | untrusted_network | RPC handler for allocation requests - processes client key_ input | RPC handler receiving key_ string from network |
| `HandleBatchGet@src/memcache/csrc/meta_service/mmc_meta_net_server.cpp` | rpc | untrusted_network | RPC handler for batch get requests from remote clients | RPC handler for BatchGetRequest - batch retrieve cached objects |
| `HandleRemove@src/memcache/csrc/meta_service/mmc_meta_net_server.cpp` | rpc | untrusted_network | RPC handler for remove requests from remote clients | RPC handler for RemoveRequest - removes cached objects |
| `HandleRemoveAll@src/memcache/csrc/meta_service/mmc_meta_net_server.cpp` | rpc | untrusted_network | RPC handler for remove all requests - dangerous operation | RPC handler for RemoveAllRequest - removes ALL cached objects |
| `MetaService::setup@src/memcache/csrc/python_wrapper/pymmc.cpp` | decorator | semi_trusted | Python binding for setting up meta service configuration | Python API entry point for meta service configuration |
| `DistributedObjectStore::setup@src/memcache/csrc/python_wrapper/pymmc.cpp` | decorator | semi_trusted | Python binding for client setup - accepts user configuration | Python API entry point for client configuration |
| `put@src/memcache/csrc/python_wrapper/pymmc.cpp` | decorator | semi_trusted | Python binding for put operation - accepts user key and buffer | Python API for storing objects with user-provided keys |
| `get@src/memcache/csrc/python_wrapper/pymmc.cpp` | decorator | semi_trusted | Python binding for get operation - accepts user key | Python API for retrieving objects with user-provided keys |
| `register_buffer@src/memcache/csrc/python_wrapper/pymmc.cpp` | decorator | semi_trusted | Python binding accepts raw memory pointer from user | Python API accepting uintptr_t for memory buffer registration |
| `LoadFromFile@src/memcache/csrc/config/mmc_configuration.cpp` | file | semi_trusted | Loads configuration from file path - file content affects runtime behavior | Configuration file parsing entry point |
| `update_lease@src/memcache/python/memcache_hybrid/meta_service_leader_election.py` | rpc | semi_trusted | Kubernetes API call for leader election lease update | Kubernetes lease update for HA leader election |

**其他攻击面**:
- HTTP Management Endpoints: /health, /get_all_keys, /query_key, /get_all_segments, /metrics, /metrics/summary, /metrics/ptracer - No authentication visible
- Network RPC Protocol: Multiple RPC handlers (Alloc, Get, Remove, RemoveAll, BmRegister) accept serialized data from remote clients
- Protocol Deserialization: NetMsgUnpacker deserializes network data including strings, vectors, maps - potential for deserialization vulnerabilities
- Python Bindings Memory Operations: register_buffer, get_into, put_from accept uintptr_t (raw memory pointers) from Python code
- Configuration File Parsing: KVParser reads key-value pairs from configuration files without apparent sanitization
- TLS Path Handling: ValidatePathNotSymlink checks TLS certificate paths - potential symlink attacks if validation fails
- Key Handling: User-provided keys flow through entire system (up to 256 chars limit, but no content validation)
- Leader Election Kubernetes API: Python code interacts with Kubernetes API without apparent credential validation
- Dynamic Library Loading: DlDfcApi::LoadLibrary() loads external library for UBS IO operations
- Memory Pool Operations: Global allocator handles memory allocation/deallocation based on remote requests

---

## 3. High 漏洞 (1)

### [VULN-SEC-PYW-002] Sensitive Configuration Information Exposure - LocalConfig.__str__,MetaConfig.__str__

**严重性**: High | **CWE**: CWE-312,CWE-256 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/memcache/csrc/python_wrapper/pymmc.cpp:345-353` @ `LocalConfig.__str__,MetaConfig.__str__`
**模块**: python_wrapper

**描述**: The local_config_to_string and meta_config_to_string functions expose TLS key paths (tls_key_path, tls_key_pass_path, tls_key_pass_path) through __str__ and __repr__ methods. These sensitive credential paths are exposed to Python users through print(config) or str(config) operations, revealing the location of private key files and passphrase files to potentially unauthorized users.

**漏洞代码** (`src/memcache/csrc/python_wrapper/pymmc.cpp:345-353`)

```c
.def("str", &local_config_to_string).def("__str__", &local_config_to_string).def("__repr__", &local_config_to_string)
```

**达成路径**

Python caller -> str(config) / print(config) -> local_config_to_string() -> outputs tls_key_path, tls_key_pass_path etc.

**验证说明**: Python caller 可通过 str()/print() 触发敏感路径暴露。tls_key_path、tls_key_pass_path 等敏感凭证路径被输出。虽需用户主动调用，但暴露风险明确。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (2)

### [VULN-SEC-PYW-003] TLS Configuration Path Injection - LocalConfig.tls_key_path,LocalConfig.tls_key_pass_path,LocalConfig.tls_decrypter_path

**严重性**: Medium | **CWE**: CWE-22,CWE-73 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/memcache/csrc/python_wrapper/pymmc.cpp:168-342` @ `LocalConfig.tls_key_path,LocalConfig.tls_key_pass_path,LocalConfig.tls_decrypter_path`
**模块**: python_wrapper

**描述**: TLS configuration paths (tls_key_path, tls_key_pass_path, tls_decrypter_path) can be set directly through Python without validation. The SafeCopy function only copies strings but does not validate: (1) path existence, (2) symlink checks, (3) file permissions. Although ValidatePathNotSymlink exists in mmc_functions.h, it is not invoked in Python bindings. Attackers can configure paths to malicious files.

**漏洞代码** (`src/memcache/csrc/python_wrapper/pymmc.cpp:168-342`)

```c
.def_property("tls_key_path", [](const local_config &cfg) { return std::string(cfg.tls_key_path); }, [](local_config &cfg, const std::string &value) { SafeCopy(value, cfg.tls_key_path, sizeof(cfg.tls_key_path)); })
```

**达成路径**

Python caller -> config.tls_key_path = "path" -> SafeCopy() -> no validation -> stored in config -> used in TLS setup

**验证说明**: Python caller 可设置任意 TLS 配置路径，SafeCopy 只复制字符串不做验证。路径未检查存在性、symlink、权限。攻击者可配置恶意文件路径。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PYW-004] Arbitrary Dynamic Library Path Configuration - tls_decrypter_path setters

**严重性**: Medium | **CWE**: CWE-426,CWE-114 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/memcache/csrc/python_wrapper/pymmc.cpp:216-342` @ `tls_decrypter_path setters`
**模块**: python_wrapper

**描述**: The tls_decrypter_path parameters allow configuring arbitrary dynamic library paths through Python bindings. These paths are used to load external decryption libraries via dlopen/dlsym. An attacker who can control these paths could specify a malicious library path leading to arbitrary code execution.

**漏洞代码** (`src/memcache/csrc/python_wrapper/pymmc.cpp:216-342`)

```c
def_property for decrypter_path
```

**达成路径**

Python -> decrypter_path setter -> SafeCopy -> dlopen -> code execution

**验证说明**: Python caller 可配置任意 decrypter_path，该路径用于 dlopen 加载动态库。攻击者可指定恶意库路径导致任意代码执行。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| python_wrapper | 0 | 1 | 2 | 0 | 3 |
| **合计** | **0** | **1** | **2** | **0** | **3** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-426,CWE-114 | 1 | 33.3% |
| CWE-312,CWE-256 | 1 | 33.3% |
| CWE-22,CWE-73 | 1 | 33.3% |
