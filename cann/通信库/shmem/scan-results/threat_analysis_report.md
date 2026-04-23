# 娿胁分析报告 - SHMEM 共享内存库

> **分析模式：自主分析模式**
> threat.md 文件不存在，本次攻击面分析由 AI 自主完成，识别所有可能的攻击面和高风险模块。

---

## 一、项目架构概览

### 1.1 项目简介

**SHMEM** 是面向昇腾平台的多机多卡内存通信库，为分布式训练和算子开发提供高效、易用的跨设备内存通信能力。项目通过封装 Host 侧与 Device 侧接口，实现跨设备的高效内存访问与数据同步。

### 1.2 技术栈

| 类别 | 技术/组件 |
|------|----------|
| 主要语言 | C/C++ (约 90,636 行) + Python (约 6,329 行) |
| 构建系统 | CMake |
| 外部依赖 | CANN (Ascend Computing Architecture), OpenSSL, PyTorch/torch_npu |
| 网络协议 | TCP (TLS 加密), RDMA (RoCE), SDMA, UDMA |
| Python 封装 | pybind11 |

### 1.3 模块结构

项目采用分层架构设计：

```
┌─────────────────────────────────────────────────────────┐
│                    Python API Layer                      │
│  (src/python/shmem/__init__.py, core/init_final.py)     │
├─────────────────────────────────────────────────────────┤
│                  Python C++ Wrapper                      │
│           (src/host/python_wrapper/pyshmem.cpp)          │
├─────────────────────────────────────────────────────────┤
│                    Host API Layer                        │
│    (init, mem, team, sync, data_plane, utils)            │
├─────────────────────────────────────────────────────────┤
│                 Bootstrap / Config Store                 │
│   (bootstrap, config_store, TCP/RDMA transport)          │
├─────────────────────────────────────────────────────────┤
│                 Security / TLS Module                    │
│     (acc_links/csrc/security/acc_tcp_ssl_helper.cpp)     │
├─────────────────────────────────────────────────────────┤
│                 Transport Layer                          │
│      (RDMA, SDMA, UDMA, MTE transport managers)          │
├─────────────────────────────────────────────────────────┤
│                 Device API Layer                         │
│              (device/gm2gm, device/team)                 │
└─────────────────────────────────────────────────────────┘
```

---

## 二、模块风险评估

### 2.1 风险等级分布

| 风险等级 | 模块数 | 关键模块 |
|----------|--------|----------|
| Critical | 2 | security_ssl, config_store (TCP) |
| High | 7 | transport_rdma, init, bootstrap, python_wrapper, socket |
| Medium | 8 | mem, team, sync, python_core, utils, entity |
| Low | 3 | log, prof (部分), construct_tensor |

### 2.2 高风险模块详细分析

#### 2.2.1 安全/TLS 模块 (Critical)

**路径**: `src/host/bootstrap/config_store/acc_links/csrc/security/`

**核心功能**: TLS 证书加载、验证、SSL 连接建立

**关键文件**:
- `acc_tcp_ssl_helper.cpp` - SSL/TLS 初始化和证书处理

**潜在风险点**:
| 风险类型 | 位置 | 说明 |
|----------|------|------|
| 证书路径验证 | LoadCaCert:122 | 使用 realpath 验证路径，需确保无路径遍历漏洞 |
| 私钥处理 | LoadPrivateKey:214 | 私钥内容从内存加载，需确保安全存储和清理 |
| 密码解密 | GetPkPass:185 | 支持外部解密函数，需防止恶意回调注入 |
| 证书有效期检查 | CertVerify:441 | 检查证书过期和密钥长度 |
| CRL 加载 | ProcessCrlAndVerifyCert:398 | 加载证书吊销列表验证 |

**安全措施**:
- 强制 TLS 1.3 协议
- 密码套件限制为强加密算法 (TLS_AES_128_GCM_SHA256 等)
- 私钥密码使用后主动清零 (EraseDecryptData)
- 密钥长度检查 (MIN_PRIVATE_KEY_CONTENT_BIT_LEN)
- 证书有效期周期性检查线程

#### 2.2.2 TCP 配置存储模块 (Critical)

**路径**: `src/host/bootstrap/config_store/`

**核心功能**: TCP 服务器/客户端通信、配置数据交换

**关键文件**:
- `store_tcp_config.cpp` - TCP 配置存储客户端
- `acc_tcp_server_default.cpp` - TCP 服务器实现
- `acc_tcp_listener.cpp` - TCP 连接监听

**潜在风险点**:
| 风险类型 | 位置 | 说明 |
|----------|------|------|
| 网络监听 | TcpConfigStore::Startup:152 | TCP 服务器绑定端口等待连接 |
| 数据包解析 | SmemMessagePacker::Unpack | 消息反序列化，需防止解析漏洞 |
| Key 验证 | Set/GetReal:233,259 | 检查 key 长度 (MAX_KEY_LEN_CLIENT) |
| 连接超时 | Connect retry | 60 次重试，可配置 |

#### 2.2.3 RDMA 传输模块 (High)

**路径**: `src/host/transport/device_rdma/`

**核心功能**: RDMA 设备初始化、QP 管理、内存区域注册

**关键文件**:
- `device_rdma_transport_manager.cpp` - RDMA 传输管理
- `device_qp_manager.cpp` - Queue Pair 管理
- `device_rdma_helper.cpp` - RDMA 辅助函数

**潜在风险点**:
| 风险类型 | 位置 | 说明 |
|----------|------|------|
| 设备 IP 获取 | RetireDeviceIp:412 | 从网卡获取设备 IP，依赖系统配置 |
| 内存注册 | RegisterMemoryRegion:118 | 注册内存区域用于 RDMA |
| QP 连接 | Connect:232 | RDMA 连接建立 |
| TSD 初始化 | OpenTsd:351 | TSD 打开操作 |

#### 2.2.4 初始化模块 (High)

**路径**: `src/host/init/`

**核心功能**: 库初始化、实例管理、配置加载

**关键文件**:
- `shmem_init.cpp` - 主初始化逻辑

**潜在风险点**:
| 风险类型 | 位置 | 说明 |
|----------|------|------|
| 端口范围解析 | aclshmemi_instance_port_selection:247 | 从环境变量解析端口范围 |
| 日志级别设置 | aclshmemx_set_log_level:583 | 从环境变量读取日志级别 |
| TLS 配置 | aclshmemx_set_conf_store_tls:605 | 设置 TLS 开关和证书路径 |
| 属性检查 | check_attr:140 | 验证初始化属性有效性 |

#### 2.2.5 Bootstrap 模块 (High)

**路径**: `src/host/bootstrap/`

**核心功能**: 分布式初始化协调、UID 交换

**关键文件**:
- `shmemi_bootstrap_uid.cpp` - UID bootstrap 实现
- `shmemi_bootstrap_config_store.cpp` - Config store bootstrap

**潜在风险点**:
| 风险类型 | 位置 | 说明 |
|----------|------|------|
| 环境变量读取 | socket_get_uid_info_from_server:1165 | SHMEM_UID_SESSION_ID, SHMEM_UID_SOCK_IFNAME |
| Socket 通信 | uid_socket.cpp | Unix socket / TCP 通信 |
| UID 信息交换 | uid_bootstrap_exchange | PE 信息同步 |

#### 2.2.6 Python Wrapper (High)

**路径**: `src/host/python_wrapper/`

**核心功能**: C++ API 的 Python 绑定

**关键文件**:
- `pyshmem.cpp` - pybind11 绑定实现

**潜在风险点**:
| 风险类型 | 位置 | 说明 |
|----------|------|------|
| 类型转换 | 多处 | Python 类型到 C++ 类型转换 |
| GIL 管理 | py::call_guard<py::gil_scoped_release> | GIL 释放和获取 |
| 解密回调 | py_decrypt_handler_wrapper:72 | Python 解密函数回调 |
| 内存地址转换 | intptr_t 转换 | Python 整数到 C++ 指针 |

---

## 三、攻击面分析

### 3.1 网络攻击面

#### 3.1.1 TCP 通信接口

**入口点**: TCP Server/Client (管理面通信)

**特征**:
- 端口范围: 1025-65535 (可通过 SHMEM_INSTANCE_PORT_RANGE 配置)
- 协议: TCP，默认启用 TLS 1.3 加密
- 认证: 数字证书双向认证
- 数据: 配置信息交换、UID bootstrap 信息

**信任边界分析**:
- 攻击者可达性: 需在同一内网环境，且有有效证书
- 数据可控性: TLS 加密后可控性有限
- 防护措施: 强 TLS 配置、证书验证、CRL 检查

**潜在攻击场景**:
| 场景 | 风险 | 条件 |
|------|------|------|
| TLS 禁用时的网络监听 | High | 管理员禁用 TLS 且暴露公网 |
| 证书伪造 | Medium | 需获得 CA 证书签发能力 |
| DDOS 攻击 | Medium | 网络可达即可尝试 |

#### 3.1.2 RDMA 通信接口

**入口点**: RDMA 设备通信

**特征**:
- 协议: RDMA/RoCE
- 依赖: HCCP API、设备网络配置
- 数据: 内存区域注册、QP 连接

**信任边界分析**:
- 攻击者可达性: 需在同一 RDMA 网络环境
- 数据可控性: RDMA 网络隔离
- 防护措施: 设备级访问控制

### 3.2 环境变量攻击面

**可读环境变量**:

| 变量名 | 位置 | 用途 | 风险 |
|--------|------|------|------|
| SHMEM_INSTANCE_PORT_RANGE | shmem_init.cpp:250 | 端口范围配置 | Medium - 本地用户可控 |
| SHMEM_LOG_LEVEL | shmem_init.cpp:586 | 日志级别 | Low - 仅影响日志 |
| SHMEM_UID_SESSION_ID | shmemi_bootstrap_uid.cpp:1165 | UID Session | Medium - 分布式启动配置 |
| SHMEM_UID_SOCK_IFNAME | shmemi_bootstrap_uid.cpp:1175 | Socket 接口名 | Medium - 网络配置 |
| SHMEM_CYCLE_PROF_PE | prof_util.cpp:33 | Profiling PE | Low - 仅影响 profiling |
| ASCEND_HOME_PATH | mem_entity_entry.cpp:52 | CANN 路径 | Low - 安装时配置 |
| LD_LIBRARY_PATH | dl_comm_def.cpp:134 | 动态库路径 | Medium - 库加载 |
| ACCLINK_CHECK_PERIOD_HOURS | acc_tcp_ssl_helper.cpp:555 | 证书检查周期 | Low - 安全配置 |
| ACCLINK_CERT_CHECK_AHEAD_DAYS | acc_tcp_ssl_helper.cpp:562 | 证书预警天数 | Low - 安全配置 |

**信任边界分析**:
- 攻击者可达性: 本地用户可设置环境变量
- 数据可控性: 部分变量有范围检查和验证
- 防护措施: 输入验证、安全范围限制

### 3.3 文件系统攻击面

**证书文件读取**:

| 文件类型 | 路径来源 | 验证措施 |
|----------|----------|----------|
| CA 证书 | tls_info 参数指定 | realpath 验证、X509 解析验证 |
| Server 证书 | tls_info 参数指定 | realpath 验证、有效期检查 |
| Private Key | tls_info 参数指定 | 内存加载、使用后清零 |
| CRL 文件 | tls_info 参数指定 | realpath 验证、有效期检查 |

**信任边界分析**:
- 攻击者可达性: 证书路径由管理员指定，非用户可控
- 数据可控性: 文件需位于可信目录 (/etc/ssl 等)
- 防护措施: realpath 路径验证、X509 格式验证、证书有效期检查

**潜在攻击场景**:
| 场景 | 风险 | 条件 |
|------|------|------|
| 路径遍历 | Low | realpath 验证防护 |
| 证书篡改 | Medium | 需管理员权限修改证书文件 |
| 私钥泄露 | High | 需文件系统访问权限 |

### 3.4 Python API 攻击面

**入口点**: pybind11 绑定的 Python 函数

**关键 API**:
- `aclshmem_init(attributes)` - 初始化
- `aclshmem_malloc(size)` - 内存分配
- `aclshmem_putmem/getmem(...)` - 数据传输
- `set_conf_store_tls_key(...)` - TLS 配置
- `team_split_strided/split_2d(...)` - Team 管理

**信任边界分析**:
- 攻击者可达性: Python 应用程序调用
- 数据可控性: 参数来自 Python 应用
- 防护措施: 参数验证、GIL 管理、类型检查

---

## 四、STRIDE 廿胁建模

### 4.1 Spoofing (欺骗)

| 威胁场景 | 位置 | 风险 | 防护措施 |
|----------|------|------|----------|
| 证书伪造攻击 | TLS 模块 | Medium | 双向证书认证、CA 验证 |
| PE 身份伪造 | Bootstrap | Medium | UID 验证、Session ID 检查 |
| IP 地址欺骗 | RDMA 传输 | Low | RDMA 网络隔离 |

### 4.2 Tampering (篡改)

| 威胁场景 | 位置 | 风险 | 防护措施 |
|----------|------|------|----------|
| 证书文件篡改 | 文件系统 | Medium | 文件权限控制、CRL 检查 |
| 配置数据篡改 | TCP 通信 | Low | TLS 加密 |
| 内存数据篡改 | RDMA | Low | 内存注册验证 |

### 4.3 Repudiation (抵赖)

| 威胁场景 | 位置 | 风险 | 防护措施 |
|----------|------|------|----------|
| 操作日志缺失 | Logging | Low | 可配置日志级别 |
| TLS 连接无日志 | TLS 模块 | Low | 连接日志记录 |

### 4.4 Information Disclosure (信息泄露)

| 威胁场景 | 位置 | 风险 | 防护措施 |
|----------|------|------|----------|
| 私钥内存泄露 | TLS 模块 | High | 使用后主动清零 |
| 日志敏感信息 | Logging | Medium | 建议移除敏感信息日志 |
| 网络数据泄露 | TCP 通信 | Medium | TLS 加密 (默认开启) |

### 4.5 Denial of Service (拒绝服务)

| 威胁场景 | 位置 | 风险 | 防护措施 |
|----------|------|------|----------|
| TCP 连接耗尽 | TCP Server | Medium | 连接超时、重试限制 |
| RDMA QP 资源耗尽 | RDMA | Medium | QP 管理器 |
| 内存资源耗尽 | Memory | Medium | 内存大小配置限制 |

### 4.6 Elevation of Privilege (权限提升)

| 威胁场景 | 位置 | 风险 | 防护措施 |
|----------|------|------|----------|
| 解密回调注入 | TLS 模块 | Medium | 回调函数验证 |
| 动态库加载劫持 | DL API | Medium | LD_LIBRARY_PATH 验证 |
| 环境变量注入 | 初始化 | Low | 参数范围检查 |

---

## 五、安全加固建议

### 5.1 架构层面

1. **TLS 加密保持默认开启**
   - 生产环境不建议关闭 TLS
   - 如需关闭，确保在网络隔离的完全可信内网

2. **证书管理加强**
   - 定期检查证书有效期（已实现周期检查线程）
   - 使用硬件安全模块 (HSM) 存储私钥
   - 证书文件权限严格控制 (600)

3. **环境变量安全**
   - 关键配置变量增加范围验证
   - 部署脚本中固化关键变量值
   - 不建议用户直接设置 SHMEM_INSTANCE_PORT_RANGE

4. **网络隔离**
   - TCP 通信端口应在防火墙规则中限制来源
   - RDMA 网络应与普通网络隔离

### 5.2 代码层面

1. **敏感数据处理**
   - 私钥密码使用后立即清零 (已实现)
   - 避免在日志中打印证书路径、密码等敏感信息

2. **输入验证强化**
   - 环境变量解析增加更多边界检查
   - Python API 参数验证强化

3. **错误处理改进**
   - 安全相关错误应记录详细信息但不暴露敏感数据
   - 连接失败时清理所有临时资源

---

## 六、总结

### 6.1 风险评估总结

SHMEM 是一个设计较为安全的共享内存通信库，主要安全措施包括：

| 安全措施 | 实现情况 |
|----------|----------|
| TLS 加密 | 默认开启，TLS 1.3，强密码套件 |
| 证书验证 | 双向认证，CA 验证，CRL 支持 |
| 私钥保护 | 内存使用后清零 |
| 路径验证 | realpath 防止路径遍历 |
| 输入验证 | 参数范围检查，长度限制 |

### 6.2 主要关注点

1. **TLS 模块** 是最关键的安全组件，需确保证书管理流程安全
2. **网络通信** 默认有 TLS 保护，但需注意关闭 TLS 时的风险
3. **环境变量** 部分可由本地用户控制，需部署时固化关键配置
4. **Python API** 需确保调用方为可信应用程序

### 6.3 扫描建议

建议后续漏洞扫描重点关注：
- TLS/SSL 模块的证书处理逻辑
- 环境变量解析的边界检查
- 网络数据包解析的缓冲区处理
- Python wrapper 的类型转换和内存操作
- 动态库加载的路径验证

---

**报告生成时间**: 2026-04-21
**分析工具**: Architecture Agent
**LSP 状态**: 不可用（缺少外部依赖头文件）