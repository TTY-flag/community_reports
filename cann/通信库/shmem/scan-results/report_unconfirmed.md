# 漏洞扫描报告 — 待确认漏洞

**项目**: shmem
**扫描时间**: 2026-04-25T08:05:29.946Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 20 | 40.8% |
| POSSIBLE | 12 | 24.5% |
| LIKELY | 10 | 20.4% |
| CONFIRMED | 7 | 14.3% |
| **总计** | **49** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 1 | 5.6% |
| High | 6 | 33.3% |
| Medium | 9 | 50.0% |
| Low | 2 | 11.1% |
| **有效漏洞总计** | **18** | - |
| 误报 (FALSE_POSITIVE) | 20 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-CROSS-001]** callback_injection (Critical) - `src/host/python_wrapper/pyshmem.cpp:310` @ `set_conf_store_tls_key` | 置信度: 75
2. **[VULN-SEC-INIT-001]** plaintext_credential_storage (High) - `src/host/init/shmem_init.cpp:620` @ `aclshmemx_set_config_store_tls_key` | 置信度: 75
3. **[VULN-DF-PY-001]** buffer_overflow (High) - `src/host/python_wrapper/pyshmem.cpp:72` @ `py_decrypt_handler_wrapper` | 置信度: 65
4. **[VULN-SEC-PYBIND-004]** arbitrary_pointer (High) - `src/host/python_wrapper/pyshmem.cpp:341` @ `multiple (aclshmem_malloc, aclshmem_free, aclshmem_putmem, etc.)` | 置信度: 65
5. **[VULN-SEC-INIT-005]** global_state_sensitive_data (High) - `src/host/utils/shmemi_host_types.h:32` @ `aclshmemi_bootstrap_handle_t (struct definition)` | 置信度: 60
6. **[VULN-DF-RMA-001]** memory_bounds (High) - `include/host/data_plane/shmem_host_rma.h:483` @ `aclshmem_putmem/aclshmem_getmem` | 置信度: 55
7. **[VULN-DF-CROSS-002]** memory_bounds (High) - `src/host/python_wrapper/pyshmem.cpp:494` @ `aclshmem_putmem` | 置信度: 55
8. **[VULN-DF-PY-002]** race_condition (Medium) - `src/host/python_wrapper/pyshmem.cpp:26` @ `aclshmem_set_conf_store_tls_key_with_decrypt` | 置信度: 60
9. **[VULN-SEC-INIT-003]** plaintext_credential_storage (Medium) - `src/host/init/shmem_init.cpp:605` @ `aclshmemx_set_conf_store_tls` | 置信度: 55
10. **[VULN-SEC-PYBIND-002]** use_after_free (Medium) - `src/host/python_wrapper/pyshmem.cpp:26` @ `global_variables` | 置信度: 55

---

## 2. 攻击面分析

未找到入口点数据。


---

## 3. Critical 漏洞 (1)

### [VULN-DF-CROSS-001] callback_injection - set_conf_store_tls_key

**严重性**: Critical | **CWE**: CWE-94 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/host/python_wrapper/pyshmem.cpp:310-322` @ `set_conf_store_tls_key`
**模块**: Cross-Module Analysis
**跨模块**: host_python_wrapper → host_init → host_bootstrap/config_store

**描述**: Cross-module data flow: Python layer registers decrypt callback -> pyshmem.cpp stores global function pointer -> shmem_init.cpp passes handler to boot_handle -> acc_tcp_ssl_helper.cpp invokes callback. This chain allows Python code to inject arbitrary decryption logic affecting TLS security in C++ code.

**漏洞代码** (`src/host/python_wrapper/pyshmem.cpp:310-322`)

```c
m.def("set_conf_store_tls_key", &shm::aclshmem_set_conf_store_tls_key_with_decrypt, py::call_guard<py::gil_scoped_release>(), py::arg("tls_pk"), py::arg("tls_pk_pw"), py::arg("py_decrypt_func"));
```

**达成路径**

Python: py_decrypt_func [SOURCE] -> pyshmem.cpp: g_py_decrypt_func -> shmem_init.cpp: g_boot_handle.decrypt_handler -> acc_tcp_ssl_helper.cpp: mDecryptHandler_ [SINK]

**验证说明**: 代码验证确认跨模块攻击链：Python层g_py_decrypt_func(line 107)->C++回调wrapper(line 72-97)->TLS层GetPkPass调用。攻击者可通过Python API注入恶意回调影响TLS安全。

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: -5 | cross_file: 0

---

## 4. High 漏洞 (6)

### [VULN-SEC-INIT-001] plaintext_credential_storage - aclshmemx_set_config_store_tls_key

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-798 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/host/init/shmem_init.cpp:620-630` @ `aclshmemx_set_config_store_tls_key`
**模块**: 初始化模块

**描述**: TLS private key password stored as plaintext pointer in global bootstrap handle structure without encryption or memory protection. The password is stored directly in g_boot_handle.tls_pk_pw without any protection.

**漏洞代码** (`src/host/init/shmem_init.cpp:620-630`)

```c
g_boot_handle.tls_pk_pw = tls_pk_pw;
```

**达成路径**

API parameter -> global structure (plaintext) -> accessible to all process code

**验证说明**: 代码验证确认：aclshmemx_set_config_store_tls_key()直接将TLS私钥密码存储到全局g_boot_handle.tls_pk_pw(line 625)，无加密或内存保护。任何进程代码可访问此内存。但由于调用者需管理员权限配置TLS，降低可控性。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-PY-001] buffer_overflow - py_decrypt_handler_wrapper

**严重性**: High | **CWE**: CWE-120 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/host/python_wrapper/pyshmem.cpp:72-97` @ `py_decrypt_handler_wrapper`
**模块**: Python Binding Module
**跨模块**: host_python_wrapper → host_bootstrap/config_store

**描述**: Python decryption callback wrapper copies decrypted password to output buffer. The check at line 83 verifies plain.size() < plainTextLen, but the buffer size plainTextLen is provided by caller and could be mismatched. Python callback can return arbitrary size data.

**漏洞代码** (`src/host/python_wrapper/pyshmem.cpp:72-97`)

```c
py::str py_cipher = py::str(cipherText, cipherTextLen);
std::string plain = py::cast<std::string>(g_py_decrypt_func(py_cipher).cast<py::str>());
if (plain.size() >= plainTextLen) {
    std::cerr << "output cipher len is too long" << std::endl;
    return -1;
}
std::copy(plain.begin(), plain.end(), plainText);
```

**达成路径**

cipherText (Python) -> g_py_decrypt_func (Python callback) [SOURCE] -> plain -> std::copy -> plainText buffer [SINK]

**验证说明**: 代码验证：存在边界检查(line 83: plain.size() >= plainTextLen)，但plainTextLen由调用者提供，可能与实际缓冲区大小不匹配。Python回调可返回任意大小数据。MAX_CIPHER_LEN限制(10MB)存在。

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-PYBIND-004] arbitrary_pointer - multiple (aclshmem_malloc, aclshmem_free, aclshmem_putmem, etc.)

**严重性**: High | **CWE**: CWE-668 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/host/python_wrapper/pyshmem.cpp:341-1650` @ `multiple (aclshmem_malloc, aclshmem_free, aclshmem_putmem, etc.)`
**模块**: Python绑定模块

**描述**: 60+ Python-exposed functions accept intptr_t allowing arbitrary memory manipulation from Python. Python code can manipulate arbitrary memory addresses, leading to arbitrary memory read/write, memory corruption, or security bypass.

**漏洞代码** (`src/host/python_wrapper/pyshmem.cpp:341-1650`)

```c
[](intptr_t dst, intptr_t src, ...) { auto dst_addr = (void *)dst; aclshmem_putmem(dst_addr, src_addr, ...); }
```

**达成路径**

Python integer -> intptr_t -> void* cast -> arbitrary memory read/write

**验证说明**: 代码验证：60+函数确实接受intptr_t转换为void*。这是设计意图以支持Python内存操作。但用户可传入任意整数导致任意内存访问。建议添加地址范围验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN-SEC-INIT-005] global_state_sensitive_data - aclshmemi_bootstrap_handle_t (struct definition)

**严重性**: High | **CWE**: CWE-798 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/host/utils/shmemi_host_types.h:32-60` @ `aclshmemi_bootstrap_handle_t (struct definition)`
**模块**: 初始化模块

**描述**: Global bootstrap handle structure stores TLS credentials (key, password, info) as plaintext pointers accessible to any code in the process.

**漏洞代码** (`src/host/utils/shmemi_host_types.h:32-60`)

```c
const char *tls_pk_pw; // Plaintext password field
```

**达成路径**

Credentials stored in global structure without protection

**验证说明**: 代码验证：全局结构体存储TLS凭证指针。与VULN-SEC-INIT-001关联。任何进程代码可访问。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN-DF-RMA-001] memory_bounds - aclshmem_putmem/aclshmem_getmem

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-787 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `include/host/data_plane/shmem_host_rma.h:483-552` @ `aclshmem_putmem/aclshmem_getmem`
**模块**: Remote Memory Access Module
**跨模块**: host_data_plane → host_transport

**描述**: Remote memory access functions accept user-provided dst/src pointers and elem_size without validation. If elem_size exceeds allocated buffer size on remote PE, causes out-of-bounds write/read. If pointers are invalid, causes memory corruption. Critical for distributed memory safety.

**漏洞代码** (`include/host/data_plane/shmem_host_rma.h:483-552`)

```c
ACLSHMEM_HOST_API void aclshmem_putmem(void* dst, void* src, size_t elem_size, int32_t pe);
ACLSHMEM_HOST_API void aclshmem_getmem(void* dst, void* src, size_t elem_size, int32_t pe);
ACLSHMEM_HOST_API void aclshmemx_putmem_on_stream(void* dst, void* src, size_t elem_size, int32_t pe, aclrtStream stream);
```

**达成路径**

user elem_size -> aclshmem_putmem -> RDMA/MTE transfer -> remote PE memory [SINK]
user dst/src pointers -> aclshmem_putmem/getmem -> memory address [SINK]

**验证说明**: 代码验证：aclshmem_putmem/getmem确实接受用户提供的指针和elem_size，但这是设计意图的RMA操作。elem_size可能越界，但dst/src指针有效性由对称内存模型保证。降低为High级别，因为这是库的核心功能而非漏洞。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -10 | cross_file: 0

---

### [VULN-DF-CROSS-002] memory_bounds - aclshmem_putmem

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-787 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/host/python_wrapper/pyshmem.cpp:494-501` @ `aclshmem_putmem`
**模块**: Cross-Module Analysis
**跨模块**: host_python_wrapper → host_data_plane → host_transport

**描述**: Cross-module data flow: Python passes memory addresses and size -> pyshmem.cpp converts intptr_t to void* -> shmem_host_rma.h performs remote memory write. Python integers are converted to C++ pointers without validation. Size elem_size flows to RDMA/MTE transport. User can specify arbitrary addresses and sizes affecting remote PE memory.

**漏洞代码** (`src/host/python_wrapper/pyshmem.cpp:494-501`)

```c
m.def("aclshmem_putmem", [](intptr_t dst, intptr_t src, size_t elem_size, int pe) { auto dst_addr = (void *)dst; auto src_addr = (void *)src; aclshmem_putmem(dst_addr, src_addr, elem_size, pe); }, py::call_guard<py::gil_scoped_release>())
```

**达成路径**

Python: dst, src, elem_size, pe [SOURCE] -> pyshmem.cpp: intptr_t conversion -> shmem_host_rma.h: aclshmem_putmem -> RDMA/MTE transport [SINK]

**验证说明**: 代码验证确认：pyshmem.cpp中aclshmem_putmem接受intptr_t转换为void*(line 494-501)。与VULN-SEC-PYBIND-004和VULN-SEC-CROSS-003关联。用户可传入任意地址执行远程内存写。这是设计意图的RMA功能，但缺少地址范围验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: -10 | cross_file: 0

---

## 5. Medium 漏洞 (9)

### [VULN-DF-PY-002] race_condition - aclshmem_set_conf_store_tls_key_with_decrypt

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-362 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/host/python_wrapper/pyshmem.cpp:26-109` @ `aclshmem_set_conf_store_tls_key_with_decrypt`
**模块**: Python Binding Module

**描述**: Global static Python function pointer g_py_decrypt_func is set without mutex protection. In multi-threaded Python scenarios, race conditions could cause one thread to use another thread's decrypt function, or crash if function is modified during execution.

**漏洞代码** (`src/host/python_wrapper/pyshmem.cpp:26-109`)

```c
static py::function g_py_decrypt_func;
...
g_py_decrypt_func = *py_decrypt_func;
return aclshmemx_set_config_store_tls_key(..., py_decrypt_handler_wrapper);
```

**达成路径**

Thread A: set g_py_decrypt_func -> Thread B: call g_py_decrypt_func -> Race condition

**验证说明**: 代码验证：g_py_decrypt_func确实是全局静态变量，无mutex保护。但该函数只在初始化时设置一次，正常运行时不会修改。竞态条件仅发生在并发初始化场景。

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-INIT-003] plaintext_credential_storage - aclshmemx_set_conf_store_tls

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-798 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/host/init/shmem_init.cpp:605-612` @ `aclshmemx_set_conf_store_tls`
**模块**: 初始化模块

**描述**: TLS info stored without encryption in global structure. The TLS configuration information is stored directly in g_boot_handle.tls_info.

**漏洞代码** (`src/host/init/shmem_init.cpp:605-612`)

```c
g_boot_handle.tls_info = tls_info;
```

**达成路径**

API parameter -> global structure

**验证说明**: 代码验证：g_boot_handle.tls_info直接赋值。这只是TLS配置信息(非密码)。风险较低。

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-PYBIND-002] use_after_free - global_variables

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-416 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/host/python_wrapper/pyshmem.cpp:26-27` @ `global_variables`
**模块**: Python绑定模块

**描述**: Global py::function objects without lifetime management risk use-after-free if Python GC reclaims the callback while C code still holds reference.

**漏洞代码** (`src/host/python_wrapper/pyshmem.cpp:26-27`)

```c
static py::function g_py_decrypt_func; static py::function g_py_logger_func;
```

**达成路径**

Python passes callback -> stored globally -> Python GC -> C code calls dangling reference

**验证说明**: 代码验证：全局py::function对象确实存在生命周期问题。pybind11内部使用引用计数，Python GC回收时C++仍持有引用可能导致use-after-free。但实际场景中回调通常在整个会话期间保持有效。

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN-DF-RMA-002] input_validation - aclshmem_putmem/aclshmem_getmem

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-119 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `include/host/data_plane/shmem_host_rma.h:483-497` @ `aclshmem_putmem/aclshmem_getmem`
**模块**: Remote Memory Access Module
**跨模块**: host_data_plane → host_team

**描述**: PE number (pe parameter) is used to access remote memory without visible validation. If PE number is invalid (negative, >= n_pes, or wrong team), could access wrong PE's memory or cause memory corruption. PE validation should occur before remote operations.

**漏洞代码** (`include/host/data_plane/shmem_host_rma.h:483-497`)

```c
ACLSHMEM_HOST_API void aclshmem_putmem(void* dst, void* src, size_t elem_size, int32_t pe);
```

**达成路径**

user pe parameter -> aclshmem_putmem -> remote PE selection -> memory access [SINK]

**验证说明**: 代码验证：pe参数用于选择远程PE。底层实现应通过team验证pe范围，但API层未显式检查。负数或超范围pe可能导致错误行为。建议添加pe范围验证。

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN-DF-MEM-001] integer_overflow - aclshmem_malloc/aclshmem_calloc/aclshmem_align

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `include/host/mem/shmem_host_heap.h:28-94` @ `aclshmem_malloc/aclshmem_calloc/aclshmem_align`
**模块**: Memory Management Module
**跨模块**: host_mem → host_python_wrapper

**描述**: Memory allocation functions accept size/count parameters from user without visible overflow protection. aclshmem_calloc calculates nmemb * size which could overflow. Extreme size values could cause heap exhaustion or allocation failures.

**漏洞代码** (`include/host/mem/shmem_host_heap.h:28-94`)

```c
ACLSHMEM_HOST_API void *aclshmem_malloc(size_t size);
ACLSHMEM_HOST_API void *aclshmem_calloc(size_t nmemb, size_t size);
ACLSHMEM_HOST_API void *aclshmem_align(size_t alignment, size_t size);
```

**达成路径**

user size/nmemb [SOURCE] -> aclshmem_malloc/calloc -> memory allocation [SINK]

**验证说明**: 代码验证：aclshmem_calloc计算nmemb*size可能溢出。但现代系统使用安全分配函数，size_t类型防止常见溢出。极端值可能导致分配失败而非安全漏洞。

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-CROSS-003] integer_overflow - aclshmem_malloc

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/host/python_wrapper/pyshmem.cpp:335-347` @ `aclshmem_malloc`
**模块**: Cross-Module Analysis
**跨模块**: host_python_wrapper → host_mem

**描述**: Cross-module data flow: Python size parameter -> pyshmem.cpp -> shmem_host_heap.h -> memory_manager allocation. Python integers can be very large (unbounded). Size flows to C++ allocation without explicit overflow protection in Python layer. C++ implementation should handle but Python wrapper lacks pre-validation.

**漏洞代码** (`src/host/python_wrapper/pyshmem.cpp:335-347`)

```c
m.def("aclshmem_malloc", [](size_t size) { auto ptr = aclshmem_malloc(size); if (ptr == nullptr) { throw std::runtime_error("aclshmem_malloc failed"); } return (intptr_t)ptr; }, py::call_guard<py::gil_scoped_release>())
```

**达成路径**

Python: size [SOURCE] -> pyshmem.cpp: size_t -> shmem_host_heap.h: aclshmem_malloc -> memory_manager->malloc [SINK]

**验证说明**: 与VULN-DF-MEM-001相同，Python层传递size到C++分配。底层实现应处理溢出。Python层无预验证但不直接导致漏洞。

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: 0 | context: -5 | cross_file: 0

---

### [VULN-DF-CROSS-004] input_validation - aclshmem_initialize_unique_id

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/host/python_wrapper/pyshmem.cpp:52-70` @ `aclshmem_initialize_unique_id`
**模块**: Cross-Module Analysis
**跨模块**: host_python_wrapper → host_init → host_bootstrap

**描述**: Cross-module data flow: Python bytes uid -> pyshmem.cpp copies to aclshmemx_uniqueid_t -> shmem_init.cpp uses uid for bootstrap. The uid bytes from Python are copied to C++ struct. If uid is malformed or contains wrong magic/version, bootstrap initialization could fail or behave unexpectedly.

**漏洞代码** (`src/host/python_wrapper/pyshmem.cpp:52-70`)

```c
int aclshmem_initialize_unique_id(int rank, int world_size, int64_t mem_size, const std::string &bytes) { if (bytes.size() < sizeof(aclshmemx_uniqueid_t)) { return -1; } aclshmemx_uniqueid_t uid; std::copy_n(bytes.data(), sizeof(uid), reinterpret_cast<char*>(&uid)); ... }
```

**达成路径**

Python: bytes (uid) [SOURCE] -> pyshmem.cpp: std::copy_n -> aclshmemx_uniqueid_t uid -> shmem_init.cpp: aclshmemx_set_attr_uniqueid_args [SINK]

**验证说明**: 代码验证：Python bytes uid复制到C++结构。存在sizeof检查。格式验证不足但有限制。

**评分明细**: base: 30 | reachability: 10 | controllability: 10 | mitigations: 0 | context: -10 | cross_file: 0

---

### [VULN-SEC-TLS-003] missing_permission_check - LoadCaCert

**严重性**: Medium | **CWE**: CWE-732 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp:154-166` @ `LoadCaCert`
**模块**: TLS安全模块

**描述**: Certificate and key files are opened with fopen() without validating file permissions. The code uses realpath() and checks for symlinks, but does not verify that certificate/key files have restricted permissions (e.g., 600 for private keys). Attackers with file system access could modify these files.

**漏洞代码** (`src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp:154-166`)

```c
FILE *fp = fopen(caFile.c_str(), "r");
if (!fp) {
    LOG_ERROR("Failed to open ca file");
    return ACC_ERROR;
}
```

**达成路径**

tlsCaFile -> fopen() -> PEM_read_X509

**验证说明**: 代码验证：证书文件权限未检查。使用realpath检查符号链接。建议添加权限检查(600)。

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-RDMA-002] thread_safety_issue - ostream operator

**严重性**: Medium | **CWE**: CWE-362 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/host/transport/device_rdma/device_rdma_common.h:116` @ `ostream operator`
**模块**: RDMA地址解析模块

**描述**: inet_ntoa() uses a static internal buffer, causing race conditions in multi-threaded environments. Used in 8+ locations including logging operators.

**漏洞代码** (`src/host/transport/device_rdma/device_rdma_common.h:116`)

```c
inet_ntoa(rdev.localIp.addr)
```

**达成路径**

Multi-threaded logging -> inet_ntoa static buffer -> race condition -> data corruption

**验证说明**: 代码验证：inet_ntoa()使用静态缓冲区。多线程环境可能导致竞态条件。建议使用inet_ntoa_r替代。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: -5 | cross_file: 0

---

## 6. Low 漏洞 (2)

### [VULN-DF-TLS-002] buffer_overflow - GetPkPass

**严重性**: Low（原评估: High → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp:196-201` @ `GetPkPass`
**模块**: TLS Security Module

**描述**: Buffer allocation based on encryptedText.length() without upper bound check. If input password length is extremely large, could cause heap exhaustion or allocation failure. The MAX_CIPHER_LEN check (10MB) exists in pyshmem.cpp but not in this C++ module.

**漏洞代码** (`src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp:196-201`)

```c
auto buffer = new (std::nothrow) char[encryptedText.length() * UNO_2];
if (buffer == nullptr) {
    LOG_ERROR("allocate memory for buffer failed");
    return ACC_ERROR;
}
size_t bufferLen = encryptedText.length() * UNO_2;
```

**达成路径**

tlsPkPwd (user input) -> GetPkPass -> encryptedText.length() * UNO_2 -> buffer allocation [SINK]

**验证说明**: 代码验证：encryptedText.length()*UNO_2分配。Python层有MAX_CIPHER_LEN(10MB)限制，但C++模块缺少。std::nothrow防止崩溃。大输入导致分配失败而非安全漏洞。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-INIT-001] integer_overflow - aclshmemi_state_init_attr

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/host/init/shmem_init.cpp:118-131` @ `aclshmemi_state_init_attr`
**模块**: Initialization Module

**描述**: Heap size calculation adds ACLSHMEM_EXTRA_SIZE to user-provided local_mem_size. While bounds check exists at line 150 (ACLSHMEM_MAX_LOCAL_SIZE), the addition operation could overflow on edge cases. size_t type prevents most overflow but extreme values could cause issues.

**漏洞代码** (`src/host/init/shmem_init.cpp:118-131`)

```c
g_state.heap_size = attributes->local_mem_size + ACLSHMEM_EXTRA_SIZE;
```

**达成路径**

attributes->local_mem_size [SOURCE] -> check_attr (validation) -> aclshmemi_state_init_attr -> g_state.heap_size + ACLSHMEM_EXTRA_SIZE [SINK]

**验证说明**: 代码验证：heap_size = local_mem_size + ACLSHMEM_EXTRA_SIZE。存在ACLSHMEM_MAX_LOCAL_SIZE检查。边界检查存在。

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: -5 | context: 0 | cross_file: 0

---

## 7. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| Cross-Module Analysis | 1 | 1 | 2 | 0 | 4 |
| Initialization Module | 0 | 0 | 0 | 1 | 1 |
| Memory Management Module | 0 | 0 | 1 | 0 | 1 |
| Python Binding Module | 0 | 1 | 1 | 0 | 2 |
| Python绑定模块 | 0 | 1 | 1 | 0 | 2 |
| RDMA地址解析模块 | 0 | 0 | 1 | 0 | 1 |
| Remote Memory Access Module | 0 | 1 | 1 | 0 | 2 |
| TLS Security Module | 0 | 0 | 0 | 1 | 1 |
| TLS安全模块 | 0 | 0 | 1 | 0 | 1 |
| 初始化模块 | 0 | 2 | 1 | 0 | 3 |
| **合计** | **1** | **6** | **9** | **2** | **18** |

## 8. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-190 | 4 | 22.2% |
| CWE-798 | 3 | 16.7% |
| CWE-787 | 2 | 11.1% |
| CWE-362 | 2 | 11.1% |
| CWE-94 | 1 | 5.6% |
| CWE-732 | 1 | 5.6% |
| CWE-668 | 1 | 5.6% |
| CWE-416 | 1 | 5.6% |
| CWE-20 | 1 | 5.6% |
| CWE-120 | 1 | 5.6% |
| CWE-119 | 1 | 5.6% |
