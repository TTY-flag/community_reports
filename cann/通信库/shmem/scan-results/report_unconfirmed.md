# 漏洞扫描报告 — 待确认漏洞

**项目**: shmem
**扫描时间**: 2026-04-21T22:15:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 执行摘要

本次对 shmem 项目（华为 CANN 分布式共享内存通信库）的安全扫描发现了 40 个待确认漏洞，其中 7 个为 LIKELY 状态（置信度 ≥70），69 个为 POSSIBLE 状态。

**关键风险领域**：

1. **Python/C++ 跨边界安全**：Python API 层暴露的回调函数机制可能被恶意利用，攻击者可通过注入恶意 Python 回调函数窃取 TLS 私钥密码或执行任意代码。跨模块数据流（python_wrapper → init → config_store → security_ssl）缺乏统一的安全验证机制。

2. **远程节点数据信任边界**：UDMA 和 RDMA 传输层直接使用来自远程 PE 节点的内存注册信息、EID 数据和内存密钥，未进行有效性验证。在分布式训练场景中，恶意节点可能发送伪造数据导致内存损坏或越权访问。

3. **整数溢出风险**：多处内存分配计算涉及 rankCount 乘法运算，缺乏溢出检查。超大 rank 值可能导致内存分配不足，进而引发缓冲区溢出。

**业务影响评估**：

- **High 级别漏洞**：可能导致内存损坏、远程代码执行或凭证泄露，直接影响分布式训练任务的稳定性和数据安全
- **Medium 级别漏洞**：可能导致资源耗尽、信息泄露或竞态条件，影响服务可用性

**建议优先修复方向**：
1. 对 Python 回调函数机制添加安全验证层
2. 在传输层实现远程数据验证机制
3. 添加内存分配溢出保护

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 69 | 90.8% |
| LIKELY | 7 | 9.2% |
| **总计** | **76** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 5 | 12.5% |
| Medium | 29 | 72.5% |
| Low | 6 | 15.0% |
| **有效漏洞总计** | **40** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-CROSS-001]** configuration_injection (High) - `cross_module: python_wrapper → init → config_store → security_ssl:1` @ `Python TLS callback chain` | 置信度: 75
2. **[VULN-SEC-UDMA-003]** improper_input_validation (High) - `src/host/transport/device_udma/device_udma_transport_manager.cpp:176` @ `AsyncConnect` | 置信度: 72
3. **[VULN-DF-PYW-001]** callback_injection (High) - `src/host/python_wrapper/pyshmem.cpp:72` @ `py_decrypt_handler_wrapper` | 置信度: 70
4. **[VULN-SEC-RDMA-002]** improper_memory_access_authorization (High) - `src/host/transport/device_rdma/device_rdma_transport_manager.cpp:213` @ `Prepare` | 置信度: 70
5. **[VULN-SEC-UDMA-001]** integer_overflow (High) - `src/host/transport/device_udma/device_jetty_manager.cpp:168` @ `ReserveUdmaInfoSpace` | 置信度: 65
6. **[VULN-DF-MEM-001]** buffer_overflow (Medium) - `src/host/mem/shmem_mm.cpp:74` @ `aclshmem_calloc` | 置信度: 60
7. **[VULN-SEC-UDMA-002]** buffer_overflow (Medium) - `src/host/transport/device_udma/device_jetty_manager.cpp:447` @ `FillUdmaInfo` | 置信度: 60
8. **[VULN-SEC-CFG-002]** resource_exhaustion (Medium) - `src/host/bootstrap/config_store/store_tcp_config_server.cpp:376` @ `AccStoreServer::AppendHandler` | 置信度: 55
9. **[VULN-SEC-RDMA-001]** protocol_handling_error (Medium) - `src/host/transport/device_rdma/device_rdma_helper.cpp:138` @ `ParseDeviceNic` | 置信度: 55
10. **[VULN-SEC-UDMA-006]** improper_input_validation (Medium) - `src/host/transport/device_udma/device_jetty_manager.cpp:437` @ `FillUdmaInfo` | 置信度: 55

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `TcpConfigStore::Startup@src/host/bootstrap/config_store/store_tcp_config.cpp` | network | semi_trusted | TCP 服务器启动入口，绑定指定端口等待连接。端口范围可由管理员通过环境变量 SHMEM_INSTANCE_PORT_RANGE 配置。TLS 默认开启，需证书认证。攻击者需在同一内网且有证书才能连接。 | TCP 配置存储服务器启动 |
| `AccTcpSslHelper::InitSSL@src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp` | file | trusted_admin | 读取 TLS 证书文件（CA、服务器证书、私钥）。证书路径由管理员在初始化时通过 tls_info 参数指定，文件位于 /etc/ssl/ 等系统目录，由管理员控制。 | TLS/SSL 初始化，加载证书 |
| `aclshmemi_instance_port_selection@src/host/init/shmem_init.cpp` | env | semi_trusted | 读取环境变量 SHMEM_INSTANCE_PORT_RANGE 确定端口范围。环境变量通常由启动脚本或部署系统设置，本地用户可能可控但需有启动权限。 | 从环境变量读取端口范围配置 |
| `aclshmemx_set_log_level@src/host/init/shmem_init.cpp` | env | untrusted_local | 读取环境变量 SHMEM_LOG_LEVEL 设置日志级别。任何本地用户都可以设置此环境变量。 | 从环境变量读取日志级别 |
| `socket_get_uid_info_from_server@src/host/bootstrap/shmemi_bootstrap_uid.cpp` | env | semi_trusted | 读取 SHMEM_UID_SESSION_ID 和 SHMEM_UID_SOCK_IFNAME 环境变量用于 UID bootstrap。这些变量由分布式启动脚本设置。 | 从环境变量读取 UID session 配置 |
| `uid_bootstrap_exchange@src/host/bootstrap/shmemi_bootstrap_uid.cpp` | network | semi_trusted | 通过 Unix socket 或 TCP 进行 UID 信息交换。socket 文件路径由启动脚本控制，TCP 连接需在同一内网。 | UID bootstrap 网络交换 |
| `RdmaTransportManager::OpenDevice@src/host/transport/device_rdma/device_rdma_transport_manager.cpp` | network | semi_trusted | RDMA 设备初始化，获取设备 IP 地址。设备 IP 由系统管理员配置，连接需在同一 RDMA 网络内。 | RDMA 传输设备初始化 |
| `aclshmem_initialize@src/host/python_wrapper/pyshmem.cpp` | decorator | semi_trusted | Python API 入口，通过 pybind11 暴露。调用者需是可信的 Python 应用程序，通常为分布式训练脚本。 | Python 初始化接口 |
| `AccTcpSslHelper::LoadCaCert@src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp` | file | trusted_admin | 读取 CA 证书文件验证连接。证书路径由管理员指定，使用 realpath 进行路径验证防止路径遍历。 | 加载 CA 证书文件 |
| `prof_util_init@src/host/utils/prof/prof_util.cpp` | env | semi_trusted | 读取环境变量 SHMEM_CYCLE_PROF_PE 设置 profiling PE。由开发者或管理员设置。 | Profiling 配置环境变量 |
| `GetAscendHomePath@src/host/entity/mem_entity_entry.cpp` | env | trusted_admin | 读取 ASCEND_HOME_PATH 环境变量定位 CANN 安装路径。由系统安装脚本设置，非用户可控。 | 获取 CANN 安装路径 |

**其他攻击面**:
- TCP Network Interface: 管理面通信端口（默认 1025-65535 范围），支持 TLS 1.3 加密
- RDMA Network Interface: 设备间 RDMA 通信，依赖硬件和网络配置
- Unix Domain Socket: UID bootstrap 本地通信（路径由启动脚本控制）
- Environment Variables: SHMEM_LOG_LEVEL, SHMEM_INSTANCE_PORT_RANGE, SHMEM_UID_SESSION_ID 等
- File System: TLS 证书文件（CA/Server Cert/Private Key）、配置文件
- Python API: 通过 pybind11 暴露的 C++ 接口，用于分布式训练场景
- Dynamic Library Loading: dlopen 加载 OpenSSL、CANN API 等依赖库

---

## 3. High 漏洞 (5)

### [VULN-DF-CROSS-001] configuration_injection - Python TLS callback chain

**严重性**: High | **CWE**: CWE-15 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `cross_module: python_wrapper → init → config_store → security_ssl:1` @ `Python TLS callback chain`
**模块**: cross_module
**跨模块**: python_wrapper → init → config_store → security_ssl

**描述**: 跨模块数据流: Python TLS私钥密码通过回调函数传递到SSL模块。Python层(pyshmem.cpp)接收私钥密码和自定义解密回调函数，通过aclshmemx_set_config_store_tls_key传递到C++层(shmem_init.cpp)，最终到达SSL模块(acc_tcp_ssl_helper.cpp)。恶意Python回调函数可能窃取密码或执行任意代码。数据流跨越python_wrapper→init→config_store→security_ssl四个模块。

**漏洞代码** (`cross_module: python_wrapper → init → config_store → security_ssl:1`)

```c
Python: set_conf_store_tls_key_with_decrypt(tls_pk, tls_pk_pw, py_decrypt_func)
→ C++: aclshmemx_set_config_store_tls_key → g_boot_handle.tls_pk/tls_pk_pwd
→ SSL: AccTcpSslHelper::LoadPrivateKey → g_py_decrypt_func(py_cipher)
```

**达成路径**

[Python] pyshmem.cpp:99 tls_pk, tls_pk_pw, py_decrypt_func [SOURCE]
→ [init] shmem_init.cpp:620-630 g_boot_handle存储
→ [config_store] store_factory.cpp:256-295 tlsOption存储
→ [security_ssl] acc_tcp_ssl_helper.cpp:72-97 py_decrypt_handler_wrapper回调执行 [SINK]

**验证说明**: Python回调函数可执行任意代码。Python应用层为semi_trusted，攻击者若能控制Python代码可窃取私钥密码。跨模块调用链完整(python_wrapper→init→config_store→security_ssl)。建议限制回调函数执行范围。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：
从源代码分析，该漏洞的核心问题在于 Python 回调函数的信任传递机制缺乏安全边界检查：

1. **pyshmem.cpp:99-110** - Python 层接收 `py_decrypt_func` 回调函数，存储到全局变量 `g_py_decrypt_func`
2. **shmem_init.cpp:620-630** - 将回调函数指针通过 `g_boot_handle.decrypt_handler` 存储到全局 boot handle
3. **acc_tcp_ssl_helper.cpp:72-97** - `py_decrypt_handler_wrapper` 执行 Python 回调，直接调用 `g_py_decrypt_func(py_cipher)` 处理加密的私钥密码

```cpp
// pyshmem.cpp:81-82 - 关键漏洞点
py::str py_cipher = py::str(cipherText, cipherTextLen);
std::string plain = py::cast<std::string>(g_py_decrypt_func(py_cipher).cast<py::str>());
```

**潜在利用场景**：
- 恶意 Python 代码替换 `py_decrypt_func` 为自定义函数，在解密过程中窃取私钥密码
- 回调函数可访问 Python GIL，能够执行任意 Python 代码（如网络传输、文件写入）
- 攻击者可能通过修改训练脚本的 import 钩子或环境变量注入恶意代码

**建议修复方式**：
1. **限制回调函数执行范围**：使用沙箱机制隔离 Python 回调执行
2. **添加回调函数签名验证**：在注册回调时验证函数来源（如检查模块路径）
3. **使用安全替代方案**：考虑使用 C++ 内置解密机制替代 Python 回调

---

### [VULN-SEC-UDMA-003] improper_input_validation - AsyncConnect

**严重性**: High | **CWE**: CWE-20 | **置信度**: 72/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `src/host/transport/device_udma/device_udma_transport_manager.cpp:176-201` @ `AsyncConnect`
**模块**: transport_udma
**跨模块**: transport_udma → bootstrap

**描述**: Unvalidated external data from remote ranks via g_boot_handle.allgather(). In AsyncConnect(), memory registration info from all ranks (mrList) is collected and used directly in RaCtxRmemImport without validation. This violates the Network Interface trust boundary - remote PE nodes are marked as untrusted. Malicious remote rank could send crafted memory registration data leading to memory corruption or information disclosure.

**漏洞代码** (`src/host/transport/device_udma/device_udma_transport_manager.cpp:176-201`)

```c
g_boot_handle.allgather(&localMR_, mrList.data(), sizeof(RegMemResultInfo), &g_boot_handle);
for (auto &mr : mrList) {
  mrImportInfo.in.key = mr.key;
  mrImportInfo.in.ub.tokenValue = mr.tokenValue;
  auto ret = shm::DlHccpV2Api::RaCtxRmemImport(ctxHandle_, &mrImportInfo, &rmemHandle);
```

**达成路径**

Remote rank data → allgather → mrList → mr.key/mr.tokenValue → RaCtxRmemImport (no validation)

**验证说明**: 远程节点数据通过allgather直接使用未验证。Network Interface为Critical信任边界，恶意远程节点可发送伪造内存注册信息。建议验证远程数据。

**评分明细**: base: 30 | reachability: 20 | controllability: 22 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：
从源代码 `device_udma_transport_manager.cpp:174-201` 分析，该漏洞的核心问题在于分布式通信中的信任边界缺失：

```cpp
// 行 176-177: 收集远程节点的内存注册信息
std::vector<RegMemResultInfo> mrList(rankCount_);
g_boot_handle.allgather(&localMR_, mrList.data(), sizeof(RegMemResultInfo), &g_boot_handle);

// 行 186-195: 直接使用远程数据，无验证
for (auto &mr : mrList) {
    mrImportInfo.in.key = mr.key;           // 直接使用远程 key
    mrImportInfo.in.ub.tokenValue = mr.tokenValue;  // 直接使用远程 token
    auto ret = shm::DlHccpV2Api::RaCtxRmemImport(ctxHandle_, &mrImportInfo, &rmemHandle);
}
```

**潜在利用场景**：
- 恶意 PE 节点发送伪造的 `RegMemResultInfo`，包含恶意 `key` 或 `tokenValue`
- `RaCtxRmemImport` 使用未验证的数据导入远程内存，可能：
  - 映射到未授权的设备内存区域
  - 导致内存损坏或信息泄露
  - 绕过内存访问权限检查

**业务影响**：
在分布式训练场景中，攻击者若能控制一个训练节点，可影响整个训练集群的内存安全。

**建议修复方式**：
1. **添加数据验证**：验证 `mr.key` 和 `mr.tokenValue` 的格式和范围
2. **实施节点认证**：在 allgather 前验证远程节点的身份
3. **内存区域白名单**：只允许导入预先注册的合法内存区域

---

### [VULN-DF-PYW-001] callback_injection - py_decrypt_handler_wrapper

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-82 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/host/python_wrapper/pyshmem.cpp:72-97` @ `py_decrypt_handler_wrapper`
**模块**: python_wrapper

**描述**: Python回调函数执行私钥密码解密。py_decrypt_handler_wrapper函数执行Python回调函数g_py_decrypt_func处理私钥密码。恶意回调函数可能窃取密码数据或执行任意代码。回调函数来自set_conf_store_tls_key_with_decrypt的py_decrypt_func参数。

**漏洞代码** (`src/host/python_wrapper/pyshmem.cpp:72-97`)

```c
py::str py_cipher = py::str(cipherText, cipherTextLen);
std::string plain = py::cast<std::string>(g_py_decrypt_func(py_cipher).cast<py::str>());
```

**达成路径**

cipherText [SOURCE: 加密的密码]
→ py::str(cipherText, cipherTextLen)
→ g_py_decrypt_func(py_cipher) [回调执行]
→ plain password → SslCtxSetDefaultPasswdCbUserdata

**验证说明**: Python回调函数执行私钥解密。Python应用层可注入恶意回调函数窃取密码。跨Python/C++边界。建议验证回调函数来源。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：
该漏洞与 VULN-DF-CROSS-001 存在关联，但聚焦于回调函数执行层本身的安全问题。从 `pyshmem.cpp:72-97` 分析：

```cpp
// 行 81-82: 直接执行 Python 回调函数
py::str py_cipher = py::str(cipherText, cipherTextLen);
std::string plain = py::cast<std::string>(g_py_decrypt_func(py_cipher).cast<py::str>());

// 行 83: 边界检查存在 Off-by-one 问题
if (plain.size() >= plainTextLen) {  // 应为 > 以留出 null terminator 空间
    ...
}

// 行 89-90: 可能触发单字节溢出
std::copy(plain.begin(), plain.end(), plainText);
plainText[plain.size()] = '\0';  // 当 plain.size() == plainTextLen 时溢出
```

**潜在利用场景**：
1. **回调注入攻击**：攻击者注入恶意回调函数，执行任意 Python 代码窃取密码
2. **Off-by-one 溢出**：精心构造输入使 `plain.size()` 等于 `plainTextLen`，导致单字节缓冲区溢出
3. **GIL 劫持**：回调函数执行期间持有 GIL，可阻塞其他 Python 线程

**建议修复方式**：
1. **修正边界检查**：将 `>=` 改为 `>` 以正确处理 null terminator
2. **回调函数白名单**：只允许预定义的安全解密函数
3. **密码清零增强**：确保密码数据在所有执行路径都被安全清零

---

### [VULN-SEC-RDMA-002] improper_memory_access_authorization - Prepare

**严重性**: High | **CWE**: CWE-287 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `src/host/transport/device_rdma/device_rdma_transport_manager.cpp:213-214` @ `Prepare`
**模块**: transport_rdma
**跨模块**: transport_rdma → memory_management

**描述**: Memory keys (memKeys) received from remote ranks in Prepare() and UpdateRankOptions() are accepted without validation against locally registered memory regions. This allows remote ranks to potentially reference memory regions that should not be accessible, leading to unauthorized RDMA memory access.

**漏洞代码** (`src/host/transport/device_rdma/device_rdma_transport_manager.cpp:213-214`)

```c
rankInfo.emplace(it->first, ConnectRankInfo{it->second.role, deviceNetwork, it->second.memKeys});  // memKeys from external ranks used directly without validation
```

**达成路径**

HybmTransPrepareOptions.options[].memKeys (external input from remote ranks) -> ConnectRankInfo.memKeys -> QpManager::SetRemoteRankInfo() -> RDMA remote memory access operations

**验证说明**: RDMA内存密钥从远程节点接收未验证。远程PE节点为untrusted边界，攻击者可发送恶意memKeys访问未授权内存区域。实际攻击需在RDMA网络内。建议验证内存密钥范围。

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：
从源代码 `device_rdma_transport_manager.cpp:200-230` 分析，该漏洞涉及 RDMA 远程内存访问授权：

```cpp
// 行 206-213: 接收远程节点的内存密钥，直接使用
for (auto it = options.options.begin(); it != options.options.end(); ++it) {
    ret = ParseDeviceNic(it->second.nic, deviceNetwork);
    ...
    // 关键漏洞点：memKeys 来自远程节点，未验证
    rankInfo.emplace(it->first, ConnectRankInfo{it->second.role, deviceNetwork, it->second.memKeys});
}

// 行 217: 将未验证的 memKeys 设置到 QP Manager
ret = qpManager_->SetRemoteRankInfo(rankInfo);
```

**潜在利用场景**：
- RDMA 允许直接远程内存访问，`memKeys` 控制可访问的内存区域
- 恶意节点发送伪造 `memKeys`，可能：
  - 访问其他节点的非共享内存区域
  - 读取敏感数据（如模型参数、训练数据）
  - 写入恶意数据导致训练任务异常

**业务影响**：
RDMA 是高性能分布式训练的核心通信机制，内存密钥泄露可能导致：
- 训练数据泄露
- 模型参数篡改
- 集群内存损坏

**建议修复方式**：
1. **内存密钥验证**：验证 memKeys 对应的内存区域是否在合法共享范围内
2. **节点信任等级**：建立节点认证机制，区分可信和不可信节点
3. **内存访问审计**：记录 RDMA 内存访问操作，便于事后分析

---

### [VULN-SEC-UDMA-001] integer_overflow - ReserveUdmaInfoSpace

**严重性**: High | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `src/host/transport/device_udma/device_jetty_manager.cpp:168-173` @ `ReserveUdmaInfoSpace`
**模块**: transport_udma

**描述**: Integer overflow in memory size calculations using rankCount_ without validation. In ReserveUdmaInfoSpace() (line 168-173), size calculations like 'rankCount_ * sizeof(HccpEid)' and 'sizeof(ACLSHMEMAIVUDMAInfo) + oneQpSize * rankCount_' can overflow if rankCount_ is large, leading to undersized memory allocation and subsequent buffer overflow.

**漏洞代码** (`src/host/transport/device_udma/device_jetty_manager.cpp:168-173`)

```c
auto oneQpSize = 2U * (wqSize + cqSize) + sizeof(ACLSHMEMUBmemInfo) * qpNum;
udmaInfoSize_ = sizeof(ACLSHMEMAIVUDMAInfo) + oneQpSize * rankCount_;
```

**达成路径**

rankCount_ from TransportOptions (line 53) → ReserveUdmaInfoSpace() → multiplication without overflow check → undersized aclrtMalloc

**验证说明**: rankCount_乘法可能导致整数溢出。rankCount来自TransportOptions(semi_trusted)，超大值可导致内存分配不足。建议添加溢出检查。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

**根因分析**：
从源代码 `device_jetty_manager.cpp:160-175` 分析，该漏洞涉及内存分配计算中的整数溢出风险：

```cpp
// 行 164-168: 多个乘法运算，缺乏溢出检查
constexpr int32_t qpNum = 1;
auto wqSize = sizeof(ACLSHMEMUDMAWQCtx) * qpNum;
auto cqSize = sizeof(ACLSHMEMUDMACqCtx) * qpNum;
auto oneQpSize = 2U * (wqSize + cqSize) + sizeof(ACLSHMEMUBmemInfo) * qpNum;
udmaInfoSize_ = sizeof(ACLSHMEMAIVUDMAInfo) + oneQpSize * rankCount_;  // 关键溢出点

// 行 172-173: 另一处乘法溢出风险
aclrtMalloc(&hccpEidDevice_, rankCount_ * sizeof(HccpEid), ACL_MEM_MALLOC_HUGE_FIRST);
```

**潜在利用场景**：
1. **超大 rankCount 触发溢出**：若 `rankCount_` 超过 ~2^16（约 65000），乘法运算可能溢出
2. **内存分配不足**：溢出导致 `udmaInfoSize_` 实际值远小于预期
3. **后续缓冲区溢出**：代码按预期大小访问内存，实际分配不足导致越界写入

**整数溢出示例**：
- 假设 `oneQpSize ≈ 500 bytes`
- 正常情况：`rankCount_=1000 → udmaInfoSize_≈500KB` ✓
- 恶意情况：`rankCount_=50000000 → 溢出后可能变为几十 KB` ✗

**建议修复方式**：
1. **添加溢出检查**：在乘法运算前检查是否会溢出
```cpp
if (rankCount_ > SIZE_MAX / oneQpSize) {
    SHM_LOG_ERROR("rankCount_ too large, potential overflow");
    return false;
}
```
2. **使用安全乘法函数**：引入 `SafeMultiply` 或 `std::numeric_limits` 检查
3. **限制 rankCount 上限**：在 TransportOptions 中添加最大值限制

---

## 4. Medium 漏洞 (29)

### [VULN-DF-MEM-001] buffer_overflow - aclshmem_calloc

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/host/mem/shmem_mm.cpp:74-81` @ `aclshmem_calloc`
**模块**: mem

**描述**: calloc memset使用错误参数。aclshmem_calloc和aclshmemx_calloc函数中，aclrtMemset使用size参数而非total_size参数进行内存清零。当nmemb>1时，只清零第一个元素的内存，可能导致后续元素包含未初始化数据。这可能引发信息泄露或内存安全问题。

**漏洞代码** (`src/host/mem/shmem_mm.cpp:74-81`)

```c
auto total_size = nmemb * size;
auto ptr = aclshmemi_memory_manager->allocate(total_size);
if (ptr != nullptr) {
    auto ret = aclrtMemset(ptr, size, 0, size); // 应为 aclrtMemset(ptr, total_size, 0, total_size)
```

**达成路径**

nmemb, size parameters [SOURCE]
→ total_size = nmemb * size
→ aclrtMemset(ptr, size, ...) [错误: 使用 size 而非 total_size]

**验证说明**: calloc memset使用错误参数size而非total_size。nmemb>1时后续元素未初始化，可能导致信息泄露。代码bug需修复。

**评分明细**: base: 30 | reachability: 5 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-UDMA-002] buffer_overflow - FillUdmaInfo

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-122 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `src/host/transport/device_udma/device_jetty_manager.cpp:447-471` @ `FillUdmaInfo`
**模块**: transport_udma

**描述**: Out-of-bounds write risk via unchecked pointer arithmetic in FillUdmaInfo(). Pointer calculations like '(ACLSHMEMUDMAWQCtx *)copyInfo->sqPtr + rankCount_ * qpNum' rely on rankCount_ value without bounds validation. If rankCount_ is corrupted or extremely large, pointer arithmetic can overflow leading to writes outside allocated buffer bounds.

**漏洞代码** (`src/host/transport/device_udma/device_jetty_manager.cpp:447-471`)

```c
copyInfo->sqPtr = (uint64_t)((ACLSHMEMAIVUDMAInfo *)udmaInfo_ + 1);
copyInfo->rqPtr = (uint64_t)((ACLSHMEMUDMAWQCtx *)copyInfo->sqPtr + rankCount_ * qpNum);
copyInfo->scqPtr = (uint64_t)((ACLSHMEMUDMAWQCtx *)copyInfo->rqPtr + rankCount_ * qpNum);
```

**达成路径**

rankCount_ → pointer arithmetic → potential overflow → aclrtMemcpy to device memory

**验证说明**: 指针算术依赖rankCount_可能导致越界。rankCount_验证不足，极端值可导致指针溢出。实际触发概率较低。

**评分明细**: base: 30 | reachability: 15 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CFG-002] resource_exhaustion - AccStoreServer::AppendHandler

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/bootstrap/config_store/store_tcp_config_server.cpp:376-417` @ `AccStoreServer::AppendHandler`
**模块**: config_store

**描述**: Unbounded memory growth via repeated APPEND operations. AppendHandler() allows appending network-controlled values to existing keys without size limits. An attacker can send multiple APPEND requests with large values to exhaust server memory.

**漏洞代码** (`src/host/bootstrap/config_store/store_tcp_config_server.cpp:376-417`)

```c
auto &value = request.values[0];
...
if (pos != kvStore_.end()) {
    pos->second.insert(pos->second.end(), value.begin(), value.end());
    newSize = pos->second.size();
}
```

**达成路径**

Network request -> SmemMessagePacker::Unpack() -> AppendHandler() -> request.values[0] [SOURCE] -> kvStore_[key] unlimited growth [SINK]

**验证说明**: APPEND操作无大小限制导致内存增长。入口点semi_trusted(网络请求)，可通过多次APPEND请求耗尽内存。建议添加单key大小限制。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-RDMA-001] protocol_handling_error - ParseDeviceNic

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/transport/device_rdma/device_rdma_helper.cpp:138` @ `ParseDeviceNic`
**模块**: transport_rdma

**描述**: IPv4 sin_port is set in host byte order without htons() conversion, while IPv6 correctly uses htons() at line 101. This inconsistency causes port number misinterpretation in network communication - IPv4 ports may bind to incorrect port numbers.

**漏洞代码** (`src/host/transport/device_rdma/device_rdma_helper.cpp:138`)

```c
address.ip.ipv4.sin_port = port_val;  // Missing htons() unlike IPv6 at line 101: address.ip.ipv6.sin6_port = htons(port_val);
```

**达成路径**

options.nic (semi_trusted) -> ParseDeviceNic() [line 72] -> address.ip.ipv4.sin_port (host byte order) -> InitializeDeviceAddress() -> deviceAddr -> qpManager_ -> CreateServerSocket() -> listenInfo.port -> RaSocketListenStart() (expects network byte order)

**验证说明**: IPv4端口设置缺少htons()转换。与IPv6不一致。可能导致端口绑定错误。建议统一字节序转换。

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-UDMA-006] improper_input_validation - FillUdmaInfo

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/transport/device_udma/device_jetty_manager.cpp:437-440` @ `FillUdmaInfo`
**模块**: transport_udma
**跨模块**: transport_udma → bootstrap

**描述**: Unvalidated external EID data from remote ranks. In FillUdmaInfo(), hccpEidList_ populated via allgather (line 437) is copied directly to device memory without validation. The EID (endpoint identifier) from remote ranks could be maliciously crafted, potentially enabling unauthorized connections or memory access bypass.

**漏洞代码** (`src/host/transport/device_udma/device_jetty_manager.cpp:437-440`)

```c
g_boot_handle.allgather((void *)&localHccpEid_, hccpEidList_.data(), sizeof(HccpEid), &g_boot_handle);
auto ret = aclrtMemcpy(hccpEidDevice_, rankCount_ * sizeof(HccpEid), hccpEidList_.data(), ...);
```

**达成路径**

Remote EID → allgather → hccpEidList_ → aclrtMemcpy to device (no validation)

**验证说明**: 远程EID数据未验证直接拷贝到设备内存。EID篡改可能导致连接问题但影响有限。建议添加数据验证。

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PYWRAPPER-001] Integer Overflow - aclshmem_calloc

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/python_wrapper/pyshmem.cpp:350-368` @ `aclshmem_calloc`
**模块**: python_wrapper
**跨模块**: python_wrapper → init

**描述**: Integer overflow vulnerability in aclshmem_calloc Python binding. The nmemb and size parameters from Python are multiplied without bounds checking. If nmemb * size overflows (e.g., nmemb=0x10000, size=0x10000 on 32-bit), the actual allocation becomes much smaller than expected, leading to heap overflow when the buffer is used.

**漏洞代码** (`src/host/python_wrapper/pyshmem.cpp:350-368`)

```c
m.def(
    "aclshmem_calloc",
    [](size_t nmemb, size_t size) {
        auto ptr = aclshmem_calloc(nmemb, size);
        if (ptr == nullptr) {
            throw std::runtime_error("aclshmem_calloc failed");
        }
        return (intptr_t)ptr;
    },
    ...)
```

**达成路径**

Python nmemb,size -> pybind11 lambda -> aclshmem_calloc() -> multiplication overflow -> undersized allocation

**验证说明**: Python层nmemb*size乘法无溢出检查。Python应用为semi_trusted，但pybind11和底层C++已做size_t处理，32位溢出在现代64位系统概率低。建议添加显式检查。

**评分明细**: base: 30 | reachability: 15 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PYWRAPPER-003] Arbitrary Pointer Dereference - aclshmem_free, aclshmem_putmem, aclshmem_getmem, aclshmem_ptr

**严重性**: Medium | **CWE**: CWE-476 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/python_wrapper/pyshmem.cpp:392-510` @ `aclshmem_free, aclshmem_putmem, aclshmem_getmem, aclshmem_ptr`
**模块**: python_wrapper
**跨模块**: python_wrapper

**描述**: Arbitrary pointer dereference risk in multiple Python binding functions. intptr_t values from Python are directly cast to void* without validation (e.g., aclshmem_free, aclshmem_putmem, aclshmem_getmem). A malicious Python caller could provide arbitrary pointer values causing memory corruption.

**漏洞代码** (`src/host/python_wrapper/pyshmem.cpp:392-510`)

```c
m.def(
    "aclshmem_free",
    [](intptr_t ptr) {
        auto mem = (void *)ptr;  // Direct cast without validation
        aclshmem_free(mem);
    }, ...
);
m.def(
    "aclshmem_putmem",
    [](intptr_t dst, intptr_t src, size_t elem_size, int pe) {
        auto dst_addr = (void *)dst;  // Direct cast
        auto src_addr = (void *)src;
        aclshmem_putmem(dst_addr, src_addr, elem_size, pe);
    }, ...);
```

**达成路径**

Python intptr_t -> direct cast to void* -> underlying C function -> arbitrary pointer use

**验证说明**: Python intptr_t直接cast为void*。Python应用可传入任意指针值导致内存损坏。跨Python/C++边界。建议添加指针范围验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CONFIG-001] buffer_overflow - ClientWatchContext::SetFinished

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/host/bootstrap/config_store/store_tcp_config.cpp:85-103` @ `ClientWatchContext::SetFinished`
**模块**: config_store

**描述**: 网络响应数据解包可能存在解析漏洞。ClientWatchContext::SetFinished和TcpConfigStore::GetReal函数中，网络接收的response数据通过SmemMessagePacker::Unpack解包。若Unpack实现存在整数溢出或长度检查不足，可能触发缓冲区溢出。

**漏洞代码** (`src/host/bootstrap/config_store/store_tcp_config.cpp:85-103`)

```c
auto data = reinterpret_cast<const uint8_t *>(response.DataPtr());
SmemMessage responseBody;
auto ret = SmemMessagePacker::Unpack(data, response.DataLen(), responseBody);
```

**达成路径**

AccTcpRequestContext response [SOURCE from network]
→ response.DataPtr() [外部数据]
→ SmemMessagePacker::Unpack [SINK: 解包操作]

**验证说明**: 网络响应解包可能存在漏洞。TcpConfigStore入口点semi_trusted，SmemMessagePacker::Unpack需检查是否有完整边界验证。实际风险取决于Unpack实现。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CFG-001] resource_exhaustion - SmemMessagePacker::Unpack

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/bootstrap/config_store/store_message_packer.cpp:69-120` @ `SmemMessagePacker::Unpack`
**模块**: config_store

**描述**: Memory exhaustion vulnerability: SmemMessagePacker::Unpack allows up to MAX_VALUE_SIZE (64MB) per value with MAX_VALUE_COUNT (10) values, potentially allocating 640MB per malicious message. Combined with MAX_RECV_BODY_LEN (10MB) receive limit, values up to 10MB can still cause significant memory pressure if processed concurrently.

**漏洞代码** (`src/host/bootstrap/config_store/store_message_packer.cpp:69-120`)

```c
uint64_t valueSize = 0;
std::copy_n(reinterpret_cast<const uint64_t *>(buffer + length), 1, &valueSize);
length += sizeof(uint64_t);
SHM_CHECK_CONDITION_RET(valueSize > MAX_VALUE_SIZE || length + valueSize > bufferLen, -1);
message.values.emplace_back(buffer + length, buffer + length + valueSize);
```

**达成路径**

Network recv() -> AccTcpRequestContext.DataPtr/DataLen -> SmemMessagePacker::Unpack() [SOURCE] -> message.values allocation [SINK]

**验证说明**: SmemMessagePacker::Unpack允许大内存分配。MAX_RECV_BODY_LEN=10MB限制单次分配，但并发处理可能导致内存压力。建议添加并发限制。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-MEM-001] integer_overflow - ReserveMemorySpace

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/mem/heap/hybm_acl_device_mem_segment.cpp:82-83` @ `ReserveMemorySpace`
**模块**: mem_heap

**描述**: Integer overflow in memory size calculation. The multiplication 'options_.rankCnt * reserveAlignedSize' at line 83 could overflow if rankCnt (uint32_t) is large. This could result in insufficient memory allocation, potentially leading to buffer overflow or memory corruption when subsequent operations assume a larger allocated size.

**漏洞代码** (`src/host/mem/heap/hybm_acl_device_mem_segment.cpp:82-83`)

```c
size_t reserveAlignedSize = ALIGN_UP(options_.size, DEVMM_HEAP_SIZE);
size_t totalReservedSize = options_.rankCnt * reserveAlignedSize;
```

**达成路径**

options_.rankCnt (external input) -> reserveAlignedSize (derived) -> totalReservedSize (overflow risk) -> aclrtReserveMemAddress (insufficient allocation)

**验证说明**: rankCnt乘法可能溢出。rankCnt来自内部配置，实际攻击需控制rankCnt值。建议添加溢出检查。

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-INIT-001] configuration_injection - aclshmemi_instance_port_selection

**严重性**: Medium | **CWE**: CWE-15 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/host/init/shmem_init.cpp:247-324` @ `aclshmemi_instance_port_selection`
**模块**: init

**描述**: 环境变量端口范围解析影响网络配置。aclshmemi_instance_port_selection函数从SHMEM_INSTANCE_PORT_RANGE环境变量解析端口范围，直接影响attributes->ip_port的端口值。恶意端口范围配置可能导致绑定非预期端口或绕过端口限制。

**漏洞代码** (`src/host/init/shmem_init.cpp:247-324`)

```c
const char* env_port_range = std::getenv("SHMEM_INSTANCE_PORT_RANGE");
...
uint16_t port = start_port + static_cast<uint16_t>(instance_id);
```

**达成路径**

getenv("SHMEM_INSTANCE_PORT_RANGE") [SOURCE]
→ stoi parsing → start_port/end_port
→ instance_id + start_port = port
→ attributes->ip_port [配置目标]

**验证说明**: 环境变量SHMEM_INSTANCE_PORT_RANGE影响端口配置。入口点semi_trusted(启动脚本控制)，有end_port<start_port验证。恶意配置可能导致非预期端口绑定。建议添加端口范围白名单。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-SSL-001] credential_exposure - LoadPrivateKey

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-311 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp:227-235` @ `LoadPrivateKey`
**模块**: security_ssl

**描述**: Private key material (tlsPk string) loaded into BIO memory buffer without explicit zeroing after SSL_CTX loading. The private key content persists in the tlsPk string member variable throughout the object lifetime, potentially exposing sensitive cryptographic material to memory dumps or debugging.

**漏洞代码** (`src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp:227-235`)

```c
bio = OpenSslApiWrapper::BioNewMemBuf(tlsPk.c_str(), static_cast<int>(tlsPk.size()));
pkey = OpenSslApiWrapper::PemReadBioPk(bio, nullptr, nullptr, (void*)mKeyPass.first);
```

**达成路径**

InitTlsPath() -> tlsPk = param.tlsPk [STORED]
LoadPrivateKey() -> tlsPk.c_str() -> BioNewMemBuf [EXPOSED IN BIO]
Private key material persists in tlsPk member variable after SSL initialization

**验证说明**: 私钥材料在内存中存储但未清零。入口点为trusted_admin(管理员控制)，可达性仅内部调用(+5)。无直接外部攻击路径，实际风险较低。建议在SSL初始化后清零内存。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: -15 | cross_file: 0

---

### [VULN-SEC-SSL-003] certificate_revocation - ProcessCrlAndVerifyCert

**严重性**: Medium | **CWE**: CWE-297 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp:417-418` @ `ProcessCrlAndVerifyCert`
**模块**: security_ssl

**描述**: Certificate validation continues with expired CRL (Certificate Revocation List). When CRL has expired (current time after nextUpdate), only a warning is logged but the CRL is still loaded into X509_STORE, allowing potentially revoked certificates to be accepted as valid.

**漏洞代码** (`src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp:417-418`)

```c
if (OpenSslApiWrapper::X509CmpCurrentTime(OpenSslApiWrapper::X509CrlGet0NextUpdate(crl)) <= 0) {
    LOG_WARN("Crl has expired! current time after next update time.");
}
```

**达成路径**

LoadCaCert() -> crlFullPath loaded from config
ProcessCrlAndVerifyCert() -> LoadCertRevokeListFile() -> CRL parsed
Expired CRL warning logged -> X509StoreAddCrl() called anyway [CRL ACCEPTED]

**验证说明**: 过期CRL仍被加载。这可能导致接受被撤销证书。入口点trusted_admin(证书文件由管理员控制)。建议拒绝过期CRL或强制更新。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-RMA-001] buffer_overflow - aclshmem_putmem/aclshmem_getmem

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/host/data_plane/shmem_host_rma.cpp:286-304` @ `aclshmem_putmem/aclshmem_getmem`
**模块**: data_plane

**描述**: RMA操作elem_size参数无边界验证。aclshmem_putmem/aclshmem_getmem等函数直接将elem_size参数传递给底层传输函数，没有验证大小是否合理或是否会超出缓冲区边界。超大elem_size可能导致缓冲区溢出或内存越界访问。

**漏洞代码** (`src/host/data_plane/shmem_host_rma.cpp:286-304`)

```c
void aclshmem_putmem(void *dst, void *src, size_t elem_size, int32_t pe) {
    int ret = aclshmemi_prepare_and_post_rma(..., elem_size, 1, pe, ...);
```

**达成路径**

elem_size parameter [SOURCE]
→ aclshmemi_prepare_and_post_rma [无边界验证]
→ RDMA/内存传输

**验证说明**: RMA elem_size参数无边界验证。调用者来自Python API(semi_trusted)。超大elem_size可能导致缓冲区溢出。建议添加大小上限检查。

**评分明细**: base: 30 | reachability: 15 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CROSS-002] configuration_injection - Port configuration chain

**严重性**: Medium | **CWE**: CWE-15 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `cross_module: init → bootstrap → config_store:1` @ `Port configuration chain`
**模块**: cross_module
**跨模块**: init → bootstrap → config_store

**描述**: 跨模块数据流: 端口配置从环境变量通过初始化链传递到Config Store网络层。SHMEM_INSTANCE_PORT_RANGE环境变量在init模块(shmem_init.cpp)解析，通过aclshmemx_init_attr传递到bootstrap模块，最终影响TcpConfigStore的网络端口配置。恶意端口配置可能导致绑定非预期端口。数据流跨越init→bootstrap→config_store三个模块。

**漏洞代码** (`cross_module: init → bootstrap → config_store:1`)

```c
Init: getenv("SHMEM_INSTANCE_PORT_RANGE") → aclshmemi_instance_port_selection
→ Bootstrap: aclshmemi_bootstrap_init → attributes传递
→ Config Store: TcpConfigStore::Startup → serverPort_网络绑定
```

**达成路径**

[init] shmem_init.cpp:250 getenv("SHMEM_INSTANCE_PORT_RANGE") [SOURCE]
→ aclshmemi_instance_port_selection → attributes->ip_port
→ [bootstrap] bootstrap initialization → comm_args传递
→ [config_store] store_tcp_config.cpp:120-127 serverPort_ = port [SINK: 网络端口配置]

**验证说明**: 端口配置跨模块传递(init→bootstrap→config_store)。入口点semi_trusted(启动脚本)。跨模块调用链完整。建议统一端口范围验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-INIT-001] improper_input_validation - aclshmemi_instance_port_selection

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/init/shmem_init.cpp:247-284` @ `aclshmemi_instance_port_selection`
**模块**: init

**描述**: The aclshmemi_instance_port_selection function reads SHMEM_INSTANCE_PORT_RANGE environment variable and uses it to determine port range for instance creation. The function does NOT validate that ports should be >= 1024 (privileged port threshold). The bootstrap module has this check in is_valid_ip_port_url(), but this function lacks it. Any local user can set this environment variable to specify port range including privileged ports (0-1023), potentially influencing which ports a privileged process binds to.

**漏洞代码** (`src/host/init/shmem_init.cpp:247-284`)

```c
const char* env_port_range = std::getenv("SHMEM_INSTANCE_PORT_RANGE");
...
start_port = static_cast<uint16_t>(std::stoi(env_port_range_str.substr(0, env_pos))); // No check for < 1024
end_port = static_cast<uint16_t>(std::stoi(env_port_range_str.substr(env_pos + 1, env_port_range_str.size())));
...
if (end_port < start_port) { return ACLSHMEM_INVALID_VALUE; } // Only checks order, not privileged range
...
uint16_t port = start_port + static_cast<uint16_t>(instance_id);
```

**达成路径**

getenv("SHMEM_INSTANCE_PORT_RANGE") [SOURCE - semi_trusted] -> std::stoi() -> static_cast<uint16_t> -> start_port/end_port -> validation (only checks end < start) -> port calculation [SINK - port binding]

**验证说明**: 端口范围未验证特权端口(<1024)。入口点semi_trusted(启动脚本)。bootstrap模块有is_valid_ip_port_url检查，但此函数缺失。建议统一添加端口范围验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-RDMA-003] race_condition - OpenTsd, RaInit

**严重性**: Medium | **CWE**: CWE-362 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/transport/device_rdma/device_rdma_transport_manager.cpp:23-26` @ `OpenTsd, RaInit`
**模块**: transport_rdma

**描述**: Static boolean flags (tsdOpened_, raInitialized_, deviceIpRetired_, storedRdmaHandle_) track initialization state without thread synchronization. In multi-threaded concurrent initialization scenarios, race conditions can cause double initialization (TsdOpen, RaInit called multiple times) or incomplete initialization with flags indicating success.

**漏洞代码** (`src/host/transport/device_rdma/device_rdma_transport_manager.cpp:23-26`)

```c
bool RdmaTransportManager::tsdOpened_ = false;  // Static state without mutex
bool RdmaTransportManager::raInitialized_ = false;  // Race condition: check-and-set pattern without synchronization
```

**达成路径**

Thread A: OpenDevice() -> OpenTsd() check tsdOpened_=false -> Thread B: OpenDevice() -> OpenTsd() check tsdOpened_=false -> Both threads call TsdOpen -> Race on initialization

**验证说明**: 静态标志位无线程同步。多线程并发初始化可能导致竞态条件。实际触发取决于并发初始化场景。建议添加mutex保护。

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-UDMA-007] race_condition - UdmaTransportManager

**严重性**: Medium | **CWE**: CWE-362 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/transport/device_udma/device_udma_transport_manager.cpp:21-24` @ `UdmaTransportManager`
**模块**: transport_udma

**描述**: Potential race condition on shared static state variables. tsdOpened_, raInitialized_, storedCtxHandle_, subPid_ are static class members shared across instances. If multiple UdmaTransportManager instances are created concurrently, the static state could be corrupted leading to double-initialization or skipped initialization. This is a distributed training context where concurrent PE initialization is possible.

**漏洞代码** (`src/host/transport/device_udma/device_udma_transport_manager.cpp:21-24`)

```c
bool UdmaTransportManager::tsdOpened_ = false;
bool UdmaTransportManager::raInitialized_ = false;
void *UdmaTransportManager::storedCtxHandle_ = nullptr;
```

**达成路径**

Static state → concurrent OpenDevice() calls → potential race → corrupted state

**验证说明**: 静态状态变量竞态条件。多实例并发初始化可能状态混乱。建议添加线程同步机制。

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PYWRAPPER-005] Buffer Overflow - py_decrypt_handler_wrapper

**严重性**: Medium | **CWE**: CWE-121 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/python_wrapper/pyshmem.cpp:72-97` @ `py_decrypt_handler_wrapper`
**模块**: python_wrapper

**描述**: Off-by-one error in decryption callback buffer handling. The comparison at line 83 uses >= instead of >, meaning if plain.size() equals plainTextLen, there's insufficient space for the null terminator added at line 90. This could cause a single byte overflow.

**漏洞代码** (`src/host/python_wrapper/pyshmem.cpp:72-97`)

```c
static int py_decrypt_handler_wrapper(const char *cipherText, size_t cipherTextLen, char *plainText,
                                      size_t &plainTextLen) {
    ...
    if (plain.size() >= plainTextLen) {  // Should be > to allow for null terminator
        std::cerr << "output cipher len is too long" << std::endl;
        ...
    }
    std::copy(plain.begin(), plain.end(), plainText);
    plainText[plain.size()] = '\0';  // Requires plain.size() < plainTextLen
    ...}
```

**达成路径**

Python decryption function -> std::string plain -> size check with >= -> copy + null terminator -> potential overflow

**验证说明**: 解密回调缓冲区大小检查>=而非>可能导致单字节溢出。Off-by-one错误。建议修正边界检查。

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-MEM-005] unchecked_deserialization - Import

**严重性**: Medium | **CWE**: CWE-502 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/mem/heap/hybm_acl_device_mem_segment.cpp:272-292` @ `Import`
**模块**: mem_heap
**跨模块**: mem_heap → transport

**描述**: Deserialized external data used without validation. In Import(), deserialized HbmExportInfo values (rankId, size, deviceId) from external exchange info are used directly without bounds/validity checking. If malicious data is injected via compromised communication channel, could lead to invalid memory mappings or data corruption.

**漏洞代码** (`src/host/mem/heap/hybm_acl_device_mem_segment.cpp:272-292`)

```c
auto ret = translator.Deserialize(allExInfo[i], desInfos[i]);
if (ret != 0) { ... }
importMap.emplace(desInfos[i].rankId, desInfos[i]); // rankId not validated against options_.rankCnt
```

**达成路径**

allExInfo (external input from other ranks) -> Deserialize -> desInfos[i].rankId -> importMap -> Mmap -> aclrtMapMem (potential invalid access)

**验证说明**: 反序列化外部数据未验证。rankId/size等来自远程节点交换。建议添加数据范围验证。

**评分明细**: base: 30 | reachability: 15 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-SSL-002] credential_exposure - GetPkPass

**严重性**: Medium | **CWE**: CWE-311 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp:185-212` @ `GetPkPass`
**模块**: security_ssl

**描述**: Plaintext password path copies tlsPkPwd to new buffer (mKeyPass) without clearing the original tlsPkPwd string. The password remains in the parameter's tlsPkPwd member alongside the copied buffer, doubling memory exposure risk for this sensitive credential.

**漏洞代码** (`src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp:185-212`)

```c
size_t len = encryptedText.length();
mKeyPass = std::make_pair(new char[len + 1], len);
std::copy(encryptedText.begin(), encryptedText.end(), mKeyPass.first);
```

**达成路径**

InitTlsPath() -> tlsPkPwd = param.tlsPkPwd [STORED]
GetPkPass() -> encryptedText = tlsPkPwd -> mKeyPass [COPIED]
tlsPkPwd remains populated after copy, both locations contain password

**验证说明**: 密码存储在两处内存位置。入口点trusted_admin，内存泄露需内存转储攻击。实际攻击复杂度高。建议统一清理策略。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: -5 | cross_file: 0

---

### [socket-004] Missing Thread Safety for Socket State - socket_progress

**严重性**: Medium | **CWE**: CWE-668 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/bootstrap/socket/uid_socket.cpp:47-51` @ `socket_progress`
**模块**: socket
**跨模块**: socket → bootstrap

**描述**: Socket state transitions (SOCKET_STATE_CREATED -> READY) lack thread synchronization mechanisms. The socket_t structure is modified without mutex protection. In multi-threaded bootstrap scenarios, race conditions could corrupt socket state, potentially leading to use-after-close or invalid state access.

**漏洞代码** (`src/host/bootstrap/socket/uid_socket.cpp:47-51`)

```c
if (state_check && sock->state != SOCKET_STATE_READY) { sock->state = SOCKET_STATE_ERROR; ... }
```

**达成路径**

Multiple functions modify sock->state without synchronization: socket_progress(), socket_listen(), socket_accept(), socket_connect()

**验证说明**: Socket状态无线程同步。多线程bootstrap场景可能导致竞态条件。实际触发取决于并发初始化频率。建议添加mutex保护。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-OPENSSL-001] library_injection - OPENSSLAPIDL::LoadOpensslAPI

**严重性**: Medium | **CWE**: CWE-426 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/host/bootstrap/config_store/acc_links/csrc/under_api/openssl/openssl_api_dl.cpp:247-303` @ `OPENSSLAPIDL::LoadOpensslAPI`
**模块**: openssl_wrapper

**描述**: OpenSSL库动态加载路径依赖环境变量。OPENSSLAPIDL::LoadOpensslAPI函数从libPath参数加载libssl.so和libcrypto.so，libPath通常来自EP_OPENSSL_PATH环境变量。虽然有Realpath和IsSymlink验证，但如果环境变量指向恶意库路径，仍可能加载恶意OpenSSL库。

**漏洞代码** (`src/host/bootstrap/config_store/acc_links/csrc/under_api/openssl/openssl_api_dl.cpp:247-303`)

```c
std::string libDir = libPath;
...
if (GetLibPath(libDir, libSslPath, libCryptoPath) != 0) {...}
...
auto cryptoHandle = dlopen(libCryptoPath.c_str(), RTLD_NOW | RTLD_GLOBAL);
```

**达成路径**

libPath parameter [SOURCE from EP_OPENSSL_PATH env]
→ GetLibPath → libSslPath, libCryptoPath
→ FileValidator checks
→ dlopen(libCryptoPath/libSslPath) [SINK: 动态加载]

**验证说明**: OpenSSL库加载依赖EP_OPENSSL_PATH环境变量。入口点trusted_admin(系统安装)。有Realpath和IsSymlink验证。库劫持需管理员权限被滥用。

**评分明细**: base: 30 | reachability: 10 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CROSS-004] buffer_overflow - Memory allocation chain

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `cross_module: python_wrapper → mem:1` @ `Memory allocation chain`
**模块**: cross_module
**跨模块**: python_wrapper → mem

**描述**: 跨模块数据流: 内存分配大小从Python层传递到内存管理模块。Python层调用aclshmem_malloc(size)，参数传递到mem模块(shmem_mm.cpp)进行实际内存分配。超大size参数可能导致内存耗尽或分配失败后的安全问题。数据流跨越python_wrapper→mem模块。

**漏洞代码** (`cross_module: python_wrapper → mem:1`)

```c
Python: aclshmem_malloc(size) → intptr_t ptr = aclshmem_malloc(size)
→ C++ wrapper: pyshmem.cpp:336 size parameter → aclshmem_malloc(size)
→ Mem: shmem_mm.cpp:44 aclshmemi_memory_manager->allocate(size)
```

**达成路径**

[python_wrapper] pyshmem.cpp:336 size parameter from Python [SOURCE]
→ aclshmem_malloc(size) [跨Python/C++边界]
→ [mem] shmem_mm.cpp:44 allocate(size) [SINK: 无上限验证的内存分配]

**验证说明**: Python层size参数传递到mem模块。Python API为semi_trusted。超大size可能导致内存耗尽。建议添加size上限。

**评分明细**: base: 30 | reachability: 10 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-INIT-004] dangling_pointer - aclshmemx_set_conf_store_tls

**严重性**: Medium | **CWE**: CWE-416 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/init/shmem_init.cpp:605-612` @ `aclshmemx_set_conf_store_tls`
**模块**: init
**跨模块**: init → bootstrap

**描述**: The aclshmemx_set_conf_store_tls function stores tls_info pointer directly in g_boot_handle without taking ownership or copying the data. If the caller frees this memory before the bootstrap uses it, this could lead to use-after-free. The library assumes the caller maintains the memory lifetime, which is not enforced.

**漏洞代码** (`src/host/init/shmem_init.cpp:605-612`)

```c
g_boot_handle.tls_enable = enable;
g_boot_handle.tls_info = tls_info;  // Stores raw pointer without ownership
g_boot_handle.tls_info_len = tls_info_len;
```

**达成路径**

API parameter tls_info pointer [SOURCE] -> stored in g_boot_handle.tls_info [SINK - potential use-after-free if caller frees]

**验证说明**: tls_info指针直接存储未复制。跨模块(init→bootstrap)。若调用者提前释放内存可能触发UAF。建议复制数据或明确生命周期约定。

**评分明细**: base: 30 | reachability: 10 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-UDMA-005] improper_resource_shutdown - CleanupResources

**严重性**: Medium | **CWE**: CWE-401 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/transport/device_udma/device_udma_transport_manager.cpp:397-433` @ `CleanupResources`
**模块**: transport_udma

**描述**: Incomplete cleanup on error in CleanupResources(). The function has multiple early return statements (lines 407, 419, 429) on API failure. If an error occurs during unimport or unregister, subsequent cleanup steps are skipped, leaving tokenIdHandle_ or other resources unfreeed. This could lead to resource leaks or inconsistent state on repeated cleanup attempts.

**漏洞代码** (`src/host/transport/device_udma/device_udma_transport_manager.cpp:397-433`)

```c
auto ret = shm::DlHccpV2Api::RaCtxRmemUnimport(ctxHandle_, memoryHandleList_[i]);
if (ret != 0) { SHM_LOG_ERROR(...); return; }
```

**达成路径**

CleanupResources() → error in RaCtxRmemUnimport → early return → tokenIdHandle_ not freed

**验证说明**: CleanupResources错误路径可能跳过部分清理。资源泄漏而非安全漏洞。建议使用统一清理流程。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PYWRAPPER-004] Improper Resource Locking - g_py_decrypt_func, g_py_logger_func, aclshmem_set_conf_store_tls_key_with_decrypt, aclshmem_set_extern_logger_py

**严重性**: Medium | **CWE**: CWE-668 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/python_wrapper/pyshmem.cpp:26-124` @ `g_py_decrypt_func, g_py_logger_func, aclshmem_set_conf_store_tls_key_with_decrypt, aclshmem_set_extern_logger_py`
**模块**: python_wrapper

**描述**: Global Python callback function storage without thread synchronization. g_py_decrypt_func and g_py_logger_func are stored in static global variables and can be overwritten by concurrent calls. In multi-threaded Python environments, race conditions could cause callback confusion or stale function references.

**漏洞代码** (`src/host/python_wrapper/pyshmem.cpp:26-124`)

```c
static py::function g_py_decrypt_func;
static py::function g_py_logger_func;
...
int32_t aclshmem_set_conf_store_tls_key_with_decrypt(...) {
    ...
    g_py_decrypt_func = *py_decrypt_func;  // No thread synchronization
    ...
}
int32_t aclshmem_set_extern_logger_py(py::function pyfunc) {
    g_py_logger_func = pyfunc;  // No thread synchronization
    ...
}
```

**达成路径**

Python function -> stored in static global -> callback invoked from C thread -> potential race condition

**验证说明**: 全局Python回调函数无线程同步。多线程环境可能导致回调混乱。建议添加线程同步机制。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-MEM-002] integer_overflow - MemoryInRange

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/mem/heap/hybm_acl_device_mem_segment.cpp:403-411` @ `MemoryInRange`
**模块**: mem_heap

**描述**: Integer overflow in pointer arithmetic bounds check. The calculation 'begin + size' at line 407 could overflow if size is a very large value (close to UINT64_MAX). This overflow would cause the bounds check to incorrectly pass, allowing memory access outside the valid segment range.

**漏洞代码** (`src/host/mem/heap/hybm_acl_device_mem_segment.cpp:403-411`)

```c
if (static_cast<const uint8_t *>(begin) + size >= globalVirtualAddress_ + totalVirtualSize_) {
    return false;
}
```

**达成路径**

begin (external input) + size (external input) -> potential pointer overflow -> incorrect bounds validation -> out-of-bounds memory access

**验证说明**: 指针边界检查begin+size可能溢出。size接近UINT64_MAX时边界检查失效。实际触发需超大size参数，概率低但存在风险。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-MEM-003] integer_overflow - RemoveImported

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `src/host/mem/heap/hybm_acl_device_mem_segment.cpp:365-368` @ `RemoveImported`
**模块**: mem_heap

**描述**: Integer overflow in address calculation for imported memory removal. The calculation 'reserveAlignedSize * rank' at line 367 could overflow, potentially causing incorrect address calculation when removing imported memory mappings.

**漏洞代码** (`src/host/mem/heap/hybm_acl_device_mem_segment.cpp:365-368`)

```c
size_t reserveAlignedSize = ALIGN_UP(options_.size, DEVMM_HEAP_SIZE);
uint64_t addr = reinterpret_cast<uint64_t>(globalVirtualAddress_) + reserveAlignedSize * rank;
```

**达成路径**

options_.size -> reserveAlignedSize -> reserveAlignedSize * rank (overflow risk) -> addr (incorrect address) -> aclrtUnmapMem (wrong memory unmapped)

**验证说明**: reserveAlignedSize*rank可能溢出。rank来自内部配置。建议添加溢出检查。

**评分明细**: base: 30 | reachability: 5 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (6)

### [VULN-DF-BOOT-001] input_validation - aclshmemi_get_ip_from_env

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/host/bootstrap/shmemi_bootstrap_uid.cpp:247-327` @ `aclshmemi_get_ip_from_env`
**模块**: bootstrap

**描述**: 环境变量IP/端口格式解析可能存在边界问题。aclshmemi_get_ip_from_env函数解析SHMEM_UID_SESSION_ID环境变量为IP:端口格式，使用std::stoi转换端口值。IPv6格式解析中scope_id通过if_nametoindex获取，未验证接口名长度。

**漏洞代码** (`src/host/bootstrap/shmemi_bootstrap_uid.cpp:247-327`)

```c
std::string portStr = ipPortStr.substr(bracket_end + 2);
uint16_t port = static_cast<uint16_t>(std::stoi(portStr));
uid_args->addr.addr.addr6.sin6_scope_id = if_nametoindex(if_name.c_str());
```

**达成路径**

getenv("SHMEM_UID_SESSION_ID") [SOURCE]
→ string parsing → IP/port extraction
→ inet_pton conversion → sin6_addr
→ if_nametoindex(if_name) → sin6_scope_id

**验证说明**: SHMEM_UID_SESSION_ID环境变量解析。入口点semi_trusted，使用inet_pton转换。if_nametoindex接口名长度未验证，但接口名通常受限。风险较低。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-SEC-PY-003] improper_input_validation - get_peer_buffer

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/python/shmem/core/memory.py:58-72` @ `get_peer_buffer`
**模块**: python_core
**跨模块**: python_core → cpp_shmem

**描述**: The pe (PE number) parameter is not validated before calling aclshmem_ptr. Invalid PE numbers (negative, out of range) could cause undefined behavior, out-of-bounds memory access, or access to unintended remote processing elements in the distributed system.

**漏洞代码** (`src/python/shmem/core/memory.py:58-72`)

```c
def get_peer_buffer(buf: Buffer, pe: int) -> Buffer:
    peer_addr = _pyshmem.aclshmem_ptr(buf.addr, pe)
```

**达成路径**

Python API: memory.py:get_peer_buffer(pe) [SOURCE] -> _pyshmem.aclshmem_ptr(buf.addr, pe) -> C++ layer [SINK]

**验证说明**: pe参数无验证。Python调用者semi_trusted。无效PE可能导致undefined behavior。建议添加PE范围验证。

**评分明细**: base: 30 | reachability: 10 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PY-004] improper_input_validation - put_signal

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/python/shmem/core/rma.py:24-39` @ `put_signal`
**模块**: python_core
**跨模块**: python_core → cpp_shmem

**描述**: The remote_pe parameter defaults to -1 and is not validated before calling aclshmemx_putmem_signal. A default of -1 suggests 'use current PE' but could also be interpreted as invalid by the C++ layer, causing undefined behavior. Additionally, signal_val is not validated for range.

**漏洞代码** (`src/python/shmem/core/rma.py:24-39`)

```c
def put_signal(dst: Buffer, src: Buffer, signal_var: Buffer, signal_val: int, signal_operation: SignalOp,
                remote_pe: int=-1, stream=None) -> None:
    _pyshmem.aclshmemx_putmem_signal(
        dst.addr, src.addr, signal_var.length, signal_var.addr, signal_val, signal_operation, remote_pe
    )
```

**达成路径**

Python API: rma.py:put_signal(remote_pe, signal_val) [SOURCE] -> _pyshmem.aclshmemx_putmem_signal(...) -> C++ layer [SINK]

**验证说明**: remote_pe参数默认-1无验证。Python调用者semi_trusted。底层C++对无效PE有处理。建议明确语义和范围验证。

**评分明细**: base: 30 | reachability: 10 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PY-005] improper_input_validation - signal_op

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/python/shmem/core/rma.py:42-60` @ `signal_op`
**模块**: python_core
**跨模块**: python_core → cpp_shmem

**描述**: The remote_pe parameter is not validated before being passed to aclshmemx_signal_op_on_stream. Invalid PE numbers could cause atomic signal operations to target unintended remote processing elements, potentially causing data corruption in the distributed system.

**漏洞代码** (`src/python/shmem/core/rma.py:42-60`)

```c
_pyshmem.aclshmemx_signal_op_on_stream(signal_var.addr, signal_val, signal_operation, remote_pe, stream)
```

**达成路径**

Python API: rma.py:signal_op(remote_pe, signal_val) [SOURCE] -> _pyshmem.aclshmemx_signal_op_on_stream(...) -> C++ layer [SINK]

**验证说明**: remote_pe参数无验证。Python调用者semi_trusted。建议添加PE范围验证。

**评分明细**: base: 30 | reachability: 10 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PY-006] improper_input_validation - put

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/python/shmem/core/rma.py:83-94` @ `put`
**模块**: python_core
**跨模块**: python_core → cpp_shmem

**描述**: The remote_pe parameter defaults to -1 and is not validated before calling aclshmemx_putmem_on_stream. Invalid PE numbers could cause remote memory writes to unintended targets in the distributed training system, potentially corrupting peer memory.

**漏洞代码** (`src/python/shmem/core/rma.py:83-94`)

```c
def put(dst: Buffer, src: Buffer, remote_pe: int=-1, stream: int=None) -> None:
    _pyshmem.aclshmemx_putmem_on_stream(dst.addr, src.addr, src.length, remote_pe, stream)
```

**达成路径**

Python API: rma.py:put(remote_pe) [SOURCE] -> _pyshmem.aclshmemx_putmem_on_stream(...) -> C++ layer [SINK]

**验证说明**: remote_pe参数默认-1无验证。建议明确语义和范围验证。

**评分明细**: base: 30 | reachability: 10 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PY-007] improper_input_validation - get

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/python/shmem/core/rma.py:96-107` @ `get`
**模块**: python_core
**跨模块**: python_core → cpp_shmem

**描述**: The remote_pe parameter defaults to -1 and is not validated before calling aclshmemx_getmem_on_stream. Invalid PE numbers could cause remote memory reads from unintended sources, potentially leaking data or causing out-of-bounds access.

**漏洞代码** (`src/python/shmem/core/rma.py:96-107`)

```c
def get(dst: Buffer, src: Buffer, remote_pe: int=-1, stream: int=None) -> None:
    _pyshmem.aclshmemx_getmem_on_stream(dst.addr, src.addr, src.length, remote_pe, stream)
```

**达成路径**

Python API: rma.py:get(remote_pe) [SOURCE] -> _pyshmem.aclshmemx_getmem_on_stream(...) -> C++ layer [SINK]

**验证说明**: remote_pe参数默认-1无验证。建议明确语义和范围验证。

**评分明细**: base: 30 | reachability: 10 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| bootstrap | 0 | 0 | 0 | 1 | 1 |
| config_store | 0 | 0 | 3 | 0 | 3 |
| cross_module | 0 | 1 | 2 | 0 | 3 |
| data_plane | 0 | 0 | 1 | 0 | 1 |
| init | 0 | 0 | 3 | 0 | 3 |
| mem | 0 | 0 | 1 | 0 | 1 |
| mem_heap | 0 | 0 | 4 | 0 | 4 |
| openssl_wrapper | 0 | 0 | 1 | 0 | 1 |
| python_core | 0 | 0 | 0 | 5 | 5 |
| python_wrapper | 0 | 1 | 4 | 0 | 5 |
| security_ssl | 0 | 0 | 3 | 0 | 3 |
| socket | 0 | 0 | 1 | 0 | 1 |
| transport_rdma | 0 | 1 | 2 | 0 | 3 |
| transport_udma | 0 | 2 | 4 | 0 | 6 |
| **合计** | **0** | **5** | **29** | **6** | **40** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 9 | 22.5% |
| CWE-190 | 6 | 15.0% |
| CWE-120 | 4 | 10.0% |
| CWE-15 | 3 | 7.5% |
| CWE-668 | 2 | 5.0% |
| CWE-400 | 2 | 5.0% |
| CWE-362 | 2 | 5.0% |
| CWE-311 | 2 | 5.0% |
| CWE-82 | 1 | 2.5% |
| CWE-502 | 1 | 2.5% |
| CWE-476 | 1 | 2.5% |
| CWE-426 | 1 | 2.5% |
| CWE-416 | 1 | 2.5% |
| CWE-401 | 1 | 2.5% |
| CWE-297 | 1 | 2.5% |
| CWE-287 | 1 | 2.5% |
| CWE-122 | 1 | 2.5% |
| CWE-121 | 1 | 2.5% |

---

## 8. 修复建议

### 优先级 1: 立即修复（High 级别 LIKELY 漏洞）

以下 5 个 High 级别漏洞需要优先处理，建议在下一个版本发布前完成修复：

#### 1.1 Python/C++ 跨边界安全增强

**涉及漏洞**: VULN-DF-CROSS-001, VULN-DF-PYW-001

**修复方案**:
```cpp
// 建议：在 pyshmem.cpp 中添加回调函数验证层
int32_t aclshmem_set_conf_store_tls_key_with_decrypt(...) {
    // 1. 添加回调函数签名验证
    if (!ValidateCallbackSource(py_decrypt_func)) {
        return ACLSHMEM_INVALID_PARAM;
    }
    
    // 2. 使用沙箱机制执行回调
    g_py_decrypt_func = CreateSandboxedCallback(*py_decrypt_func);
    
    // 3. 修正边界检查（Off-by-one）
    // 原: if (plain.size() >= plainTextLen)
    // 改: if (plain.size() > plainTextLen - 1)  // 留出 null terminator
}
```

**实施建议**:
- 创建回调函数白名单机制，只允许预定义的安全函数
- 使用 Python 子进程或受限执行环境隔离回调执行
- 添加回调函数调用审计日志

#### 1.2 远程节点数据验证机制

**涉及漏洞**: VULN-SEC-UDMA-003, VULN-SEC-RDMA-002

**修复方案**:
```cpp
// 建议：在 device_udma_transport_manager.cpp AsyncConnect 中添加验证
for (auto &mr : mrList) {
    // 1. 验证远程数据的格式和范围
    if (!ValidateMemoryRegistration(mr.key, mr.tokenValue, mr.cacheable, mr.access)) {
        SHM_LOG_ERROR("Invalid memory registration from rank " << idx);
        continue;  // 拒绝无效数据
    }
    
    // 2. 验证内存区域是否在合法范围内
    if (!IsMemoryRegionAuthorized(mr.key, localMR_)) {
        SHM_LOG_WARN("Unauthorized memory region attempt from rank " << idx);
        continue;
    }
    
    mrImportInfo.in.key = mr.key;
    ...
}
```

**实施建议**:
- 建立节点信任等级体系，区分可信/半可信/不可信节点
- 在分布式启动阶段建立节点认证机制
- 维护内存区域白名单，只允许导入预先注册的区域

#### 1.3 内存分配溢出保护

**涉及漏洞**: VULN-SEC-UDMA-001

**修复方案**:
```cpp
// 建议：在 device_jetty_manager.cpp ReserveUdmaInfoSpace 中添加溢出检查
bool DeviceJettyManager::ReserveUdmaInfoSpace() {
    constexpr int32_t qpNum = 1;
    auto wqSize = sizeof(ACLSHMEMUDMAWQCtx) * qpNum;
    auto cqSize = sizeof(ACLSHMEMUDMACqCtx) * qpNum;
    auto oneQpSize = 2U * (wqSize + cqSize) + sizeof(ACLSHMEMUBmemInfo) * qpNum;
    
    // 添加溢出检查
    if (rankCount_ > SIZE_MAX / oneQpSize) {
        SHM_LOG_ERROR("rankCount_ overflow: " << rankCount_ << " exceeds limit");
        return false;
    }
    
    udmaInfoSize_ = sizeof(ACLSHMEMAIVUDMAInfo) + oneQpSize * rankCount_;
    
    // 同样检查 EID 分配
    if (rankCount_ > SIZE_MAX / sizeof(HccpEid)) {
        SHM_LOG_ERROR("rankCount_ overflow for EID allocation");
        return false;
    }
    
    aclrtMalloc(&hccpEidDevice_, rankCount_ * sizeof(HccpEid), ...);
}
```

**实施建议**:
- 定义 `MAX_RANK_COUNT` 常量（建议值：65535）
- 使用安全的乘法函数包装器（如 `SafeMultiply<T>`）
- 在 TransportOptions 初始化时验证 rankCount 范围

---

### 优先级 2: 短期修复（Medium 级别漏洞）

以下 Medium 级别漏洞建议在近期版本迭代中修复：

#### 2.1 输入验证增强

**涉及漏洞**: VULN-DF-MEM-001, VULN-SEC-CFG-002, VULN-SEC-INIT-001

**修复重点**:
- 修复 `aclshmem_calloc` 中的 memset 参数错误（使用 total_size 而非 size）
- 为 Config Store APPEND 操作添加单 key 大小限制
- 统一端口范围验证，添加特权端口（<1024）检查

#### 2.2 资源管理改进

**涉及漏洞**: VULN-SEC-UDMA-005, VULN-SEC-INIT-004

**修复重点**:
- 实现统一的清理流程，避免错误路径跳过资源释放
- 复制 tls_info 数据而非存储原始指针，防止 use-after-free

#### 2.3 线程安全增强

**涉及漏洞**: VULN-SEC-RDMA-003, VULN-SEC-UDMA-007, socket-004

**修复重点**:
- 为静态状态变量添加 mutex 保护
- 统一 socket 状态管理，使用原子操作或锁机制

---

### 优先级 3: 计划修复（Low 级别漏洞）

Low 级别漏洞属于代码质量改进，建议在后续版本中逐步完善：

#### 3.1 Python API 参数验证

**涉及漏洞**: VULN-SEC-PY-003 ~ VULN-SEC-PY-007

**修复建议**:
- 在 Python 层添加 PE 编号范围验证
- 明确 remote_pe=-1 的语义（是否表示当前 PE）
- 添加参数验证装饰器统一处理

#### 3.2 凭证处理改进

**涉及漏洞**: VULN-SEC-SSL-001, VULN-SEC-SSL-002

**修复建议**:
- 在 SSL 初始化后主动清零密码内存
- 实现统一的敏感数据处理策略

---

### 修复优先级总结

| 优先级 | 漏洞级别 | 数量 | 建议时间框架 |
|--------|----------|------|--------------|
| P1 | High (LIKELY) | 5 | 下一个版本发布前 |
| P2 | Medium (LIKELY/POSSIBLE) | 29 | 近期版本迭代（2-3 个版本） |
| P3 | Low | 6 | 后续版本逐步完善 |

**注意**: 本次扫描未发现已确认漏洞，所有漏洞均为待确认状态。建议在修复前进行人工审查，确认漏洞的实际可利用性后再投入修复资源。
