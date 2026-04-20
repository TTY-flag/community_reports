# MindIE-Motor 威胁分析报告

## 执行摘要

MindIE-Motor 是华为开发的分布式 AI 推理引擎管理系统，采用 C++ 和 Python 混合架构，包含 Controller、Coordinator、Node Manager 三个核心服务组件。系统通过 HTTP/gRPC 进行集群间通信，通过共享内存进行本地进程间通信（IPC），并通过 subprocess 管理 AI 推理引擎进程。

本报告识别了系统的关键攻击面，包括：
- **网络攻击面**：HTTP/gRPC 服务接口接受外部请求
- **IPC 攻击面**：共享内存通信可能被本地恶意进程利用
- **进程管理攻击面**：subprocess 执行存在命令注入风险
- **配置解析攻击面**：JSON 配置文件解析存在潜在风险

系统已实施多项安全措施（路径验证、命令白名单、TLS 认证），但仍需关注跨语言数据流安全、网络输入验证、以及进程执行安全。

---

## 项目概况

### 系统架构

MindIE-Motor 采用三层架构：

| 组件 | 语言 | 部署位置 | 主要职责 |
|------|------|----------|----------|
| Controller | C++ | 控制节点 | 集群状态管理、故障处理、进程监控 |
| Coordinator | C++ | 协调节点 | 任务调度、负载均衡、请求分发 |
| Node Manager | Python | 计算节点 | Daemon 进程管理、心跳监控、故障上报 |

### 通信模式

```
外部客户端/CCAE ──HTTP──> Controller ──gRPC──> Coordinator
                              │
                              ├──HTTP──> Node Manager
                              │
                              └─ Shared Memory ──> 本地进程

Node Manager ──subprocess──> mindie_llm_server
Node Manager ──Kafka──> 监控系统
```

---

## 信任边界分析

### 边界 1: Network Interface (HTTP/gRPC) - Critical

**可信侧**: MindIE-Motor Services
**不可信侧**: External Clients, CCAE System, Kafka Cluster

**风险场景**:
- 攻击者发送恶意 HTTP 请求（畸形 JSON、超大 body、路径遍历）
- gRPC 消息包含恶意数据（伪造的节点状态、注入的故障信号）
- 中间人攻击（如未启用 TLS）

**现有防护**:
- TLS 1.3 加密（Ssl::context::tlsv13_server/client）
- 证书双向验证（verify_peer | verify_fail_if_no_peer_cert）
- Body size 限制（10MB）
- Header size 限制（8KB）
- Target 路径验证（禁止 ".."）

---

### 边界 2: Shared Memory IPC - High

**可信侧**: Local MindIE Processes
**不可信侧**: Potentially compromised local process

**风险场景**:
- 共享内存数据被恶意进程篡改（心跳伪造、状态欺骗）
- 环形缓冲区溢出（恶意写入超量数据）
- TOCTOU 攻击（读取和写入之间的时间窗口）

**现有防护**:
- 信号量同步（sem_t*）
- 环形缓冲区设计（防溢出）
- 共享内存名称固定（减少竞争）

---

### 边界 3: Process Execution - High

**可信侧**: MindIE-Motor Daemon Manager
**不可信侧**: mindie_llm_server subprocess

**风险场景**:
- 命令注入（配置文件路径被篡改）
- CPU binding 参数注入（taskset 参数）
- 工作目录路径遍历

**现有防护**:
- 命令白名单验证（is_valid_daemon_command）
- 路径安全检查（PathCheck.check_path_full）
- 禁止软链接
- Owner/Group 验证
- 权限模式验证（0o750, 0o640）

---

### 边界 4: Configuration Files - Medium

**可信侧**: MindIE-Motor Services
**不可信侧**: Administrator controlled files

**风险场景**:
- 配置文件被篡改（恶意 JSON、注入命令）
- 环境变量注入（MIES_INSTALL_PATH、POD_IP）
- Rank table 文件伪造

**现有防护**:
- 路径安全检查（禁止 ".."、禁止软链接）
- Owner/Group 验证
- 权限验证（mode 检查）
- JSON 解析错误处理

---

### 边界 5: Environment Variables - Medium

**可信侧**: MindIE-Motor Services
**不可信侧**: Deployment environment

**风险场景**:
- POD_IP 伪造（IP 地址验证不足）
- MIES_INSTALL_PATH 指向恶意路径
- RANK_TABLE_FILE 指向恶意文件

**现有防护**:
- IP 地址格式验证（ipaddress.ip_address）
- 路径存在性验证
- 路径安全检查

---

## 高风险入口点

### Critical 风险入口

| 文件 | 行号 | 函数 | 类型 | 说明 |
|------|------|------|------|------|
| HttpServer.cpp | 115 | HandleRequest | network | HTTP 请求处理，接收外部 body 和 target |
| HttpServer.cpp | 383 | Listener::Run | network | HTTP 监听端口，接受外部连接 |
| server_api.py | 31 | running_status | web_route | FastAPI GET 路由，接收外部 HTTP 请求 |
| server_api.py | 49 | fault_handling_command | web_route | FastAPI POST 路由，接收故障命令 |

### High 风险入口

| 文件 | 行号 | 函数 | 类型 | 说明 |
|------|------|------|------|------|
| SharedMemoryUtils.cpp | 43 | Read | ipc | 从共享内存读取外部数据 |
| HttpClient.cpp | 45 | SendRequest | network | 发送 HTTP 请求并接收响应 |
| base_daemon_manager.py | 144 | start_daemon_process | cmdline | 使用 subprocess.Popen 启动进程 |
| heartbeat_mng.py | 122 | _query_engine_server_status | network | 向 engine server 查询状态 |
| circular_memory.py | 17 | read_data | ipc | Python 共享内存读取 |
| kafka_produce.py | 52 | send | network | 向 Kafka 发送消息 |

### Medium 风险入口

| 文件 | 行号 | 函数 | 类型 | 说明 |
|------|------|------|------|------|
| JsonFileLoader.cpp | 17 | FileToJsonObj | file | 从文件加载 JSON |
| config.py | 87 | _update_info | env | 从环境变量加载配置 |
| utils.py | 103 | _is_child_process_detected | cmdline | 执行 ps 命令检测进程 |

---

## STRIDE 威胁建模

### Spoofing (身份伪造)

| 威胁 | 影响组件 | 风险等级 | 缓解措施 |
|------|----------|----------|----------|
| HTTP 客户端身份伪造 | HttpServer | High | TLS 双向认证、证书验证 |
| gRPC 节点身份伪造 | GrpcClusterClient | High | TLS 双向认证 |
| 共享内存进程伪造 | HeartbeatProducer | Medium | 进程 PID 验证 |

### Tampering (数据篡改)

| 威胁 | 影响组件 | 风险等级 | 缓解措施 |
|------|----------|----------|----------|
| HTTP Body 篡改 | HandleRequest | High | TLS 加密 |
| 共享内存数据篡改 | SharedMemoryUtils | High | 信号量同步、环形缓冲区 |
| 配置文件篡改 | FileToJsonObj | Medium | 权限验证、Owner 检查 |
| 进程命令篡改 | start_daemon_process | High | 命令白名单、路径验证 |

### Repudiation (抵赖)

| 威胁 | 影响组件 | 风险等级 | 缓解措施 |
|------|----------|----------|----------|
| HTTP 请求抵赖 | HttpServer | Medium | 日志记录（LOG_I/LOG_E） |
| 故障处理抵赖 | fault_handling_command | Medium | 日志记录 |

### Information Disclosure (信息泄露)

| 威胁 | 影响组件 | 风险等级 | 缓解措施 |
|------|----------|----------|----------|
| HTTP Body 泄露 | HandleRequest | High | TLS 加密 |
| 配置文件泄露 | FileToJsonObj | Medium | 权限验证（0400/0640） |
| 证书密钥泄露 | cert_util.py | Medium | 权限验证（700） |

### Denial of Service (拒绝服务)

| 娗胁 | 影响组件 | 风险等级 | 缓解措施 |
|------|----------|----------|----------|
| HTTP Body 超限 | HandleRequest | High | Body 限制 10MB |
| 连接数超限 | Listener::OnAccept | High | mMaxConnections 限制 |
| 心跳超时 | heartbeat_mng | Medium | Timeout 设置 |

### Elevation of Privilege (权限提升)

| 威胁 | 影响组件 | 风险等级 | 缓解措施 |
|------|----------|----------|----------|
| 命令注入 | start_daemon_process | High | 命令白名单、路径验证 |
| 路径遍历 | PathCheck | Medium | 禁止 ".."、禁止软链接 |
| 配置注入 | FileToJsonObj | Medium | JSON 解析验证 |

---

## C++/Python 交互边界风险

### 共享内存 IPC

**C++ 侧**: `SharedMemoryUtils::Read/Write`
**Python 侧**: `CircularShareMemory::read_data/write_data`

**风险**:
- 数据格式不一致（C++ 使用 `std::string`，Python 使用 `bytes`）
- 编码问题（Python 使用 UTF-8 decode，可能因非法字节序列失败）
- 大小限制不一致（C++ 10MB，Python 无显式限制）

**建议**:
- 统一数据格式验证
- 添加 magic number 验证数据完整性
- 实现版本协商机制

### 配置文件共享

**C++ 侧**: `FileToJsonObj` (nlohmann::json)
**Python 侧**: `JsonUtil.read_json_file`

**风险**:
- JSON 解析库差异可能导致行为不一致
- 配置字段验证不一致

**建议**:
- 统一 JSON Schema 定义
- 实现配置版本检查

### 进程状态同步

**C++ 侧**: `ProcessManager::LoadProcessFile`
**Python 侧**: `LLMDaemonManager::run`

**风险**:
- 进程状态文件可能被篡改
- PID 信息可能伪造

**建议**:
- 使用加密签名验证状态文件
- 实现进程心跳双向验证

---

## 安全措施评估

### 已实施的安全措施

| 类别 | 控制措施 | 实施位置 | 有效性 |
|------|----------|----------|--------|
| 加密 | TLS 1.3 | HttpServer, HttpClient | 高 |
| 认证 | 双向证书验证 | HttpServer | 高 |
| 输入验证 | 路径安全检查 | PathCheck | 高 |
| 输入验证 | 命令白名单 | is_valid_daemon_command | 高 |
| 资源限制 | Body size 限制 | HttpServer (10MB) | 中 |
| 资源限制 | 连接数限制 | HttpServer (mMaxConnections) | 中 |
| 日志 | 操作日志记录 | LOG_I/LOG_E/LOG_M | 中 |
| 权限 | 文件权限验证 | PathCheck.check_path_mode | 高 |

### 缺失的安全措施

| 类别 | 缺失控制 | 风险 |
|------|----------|------|
| 输入验证 | JSON Schema 严格验证 | JSON 解析异常、注入风险 |
| 输入验证 | HTTP Header 白名单 | Header 注入 |
| 输入验证 | gRPC 字段验证 | gRPC 消息伪造 |
| 审计 | 完整审计日志 | 安全事件追溯困难 |
| 监控 | 异常流量检测 | DoS 攻击检测延迟 |
| 加密 | 共享内存数据签名 | IPC 数据篡改 |

---

## 扫描优先级建议

### 优先级 1 (Critical - 立即扫描)

| 文件 | 模块 | 理由 |
|------|------|------|
| HttpServer.cpp | common | HTTP 入口，处理外部请求 |
| server_api.py | node_manager | FastAPI 路由，接收外部命令 |
| SharedMemoryUtils.cpp | common/ipc | 共享内存 IPC，跨语言边界 |

### 优先级 2 (High - 尽快扫描)

| 文件 | 模块 | 理由 |
|------|------|------|
| HttpClient.cpp | http_client_ctl | HTTP 客户端，接收外部响应 |
| base_daemon_manager.py | node_manager/daemon | subprocess 执行，命令注入风险 |
| heartbeat_mng.py | node_manager/core | 心跳监控，接收网络数据 |
| circular_memory.py | om_adapter | Python 共享内存 IPC |
| kafka_produce.py | om_adapter | Kafka 客户端，外部系统 |

### 优先级 3 (Medium - 优先扫描)

| 文件 | 模块 | 理由 |
|------|------|------|
| JsonFileLoader.cpp | controller | JSON 配置解析 |
| config.py | node_manager/core | 配置加载、环境变量 |
| SecurityUtils.cpp | common/securityutils | 安全工具函数 |
| cert_util.py | om_adapter/common | 证书处理 |

---

## 结论与建议

### 主要风险总结

1. **网络攻击面广泛**: HTTP/gRPC 接口接受外部输入，需强化输入验证
2. **IPC 跨语言安全**: 共享内存通信跨越 C++/Python 边界，数据验证不足
3. **进程执行风险**: subprocess 执行存在命令注入风险，已有白名单但需强化
4. **配置安全依赖管理员**: 配置文件由管理员控制，需强化权限和完整性验证

### 关键建议

1. **实施 JSON Schema 验证**: 对所有 HTTP body 和配置文件实施严格的 JSON Schema 验证
2. **添加 IPC 数据签名**: 为共享内存数据添加加密签名，防止篡改
3. **强化 gRPC 消息验证**: 实现严格的字段类型和范围验证
4. **实施完整审计日志**: 记录所有安全相关事件（请求、命令执行、故障处理）
5. **添加异常流量检测**: 实现连接频率限制和异常请求检测

---

**报告生成时间**: 2026-04-17T00:30:00Z
**扫描项目**: MindIE-Motor
**分析范围**: C++ + Python 混合项目（334 文件，56790 行代码）