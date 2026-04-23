# 漏洞扫描报告 — 已确认漏洞

**项目**: shmem
**扫描时间**: 2026-04-21T22:15:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次扫描未发现已确认的漏洞。经过数据流分析和安全审计，所有候选漏洞均被标记为 LIKELY 或 POSSIBLE 状态，置信度评分未达到 CONFIRMED 级别（需 ≥85 分）。

**扫描结论**：
- 无已确认漏洞，但存在 7 个 LIKELY 级别和 69 个 POSSIBLE 级别的候选漏洞需要进一步验证
- 重点关注 5 个 High 级别的 LIKELY 漏洞，涉及跨模块数据流和远程节点数据处理
- 建议对 LIKELY 漏洞进行人工审查，确认实际风险后再决定修复优先级

详细的待确认漏洞分析请参见 [report_unconfirmed.md](./report_unconfirmed.md)。

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
| **有效漏洞总计** | **0** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞


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

## 3. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| **合计** | **0** | **0** | **0** | **0** | **0** |

## 4. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
