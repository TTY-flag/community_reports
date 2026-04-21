# MindStudio-Monitor 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析由 Architecture Agent 自主完成，识别范围为项目全部代码。

## 项目架构概览

### 项目定位

MindStudio-Monitor（msMonitor）是面向昇腾集群场景的在线性能监测与动态采集工具，基于 dynolog 和 MSPTI 构建。项目类型为 **网络服务/守护进程**，主要包含以下核心组件：

| 组件 | 作用 | 技术栈 |
|------|------|--------|
| `Dynolog daemon` | 服务端守护进程，接收 dyno 请求并触发监测与采集 | C++ |
| `Dyno CLI` | 客户端命令行入口，下发 npu-monitor 和 nputrace 命令 | 外部工具 |
| `MSPTI Monitor` | 基于 MSPTI 的采集模块，获取并上报性能数据 | C++ + Python |

### 语言组成

- **C/C++**: 79 文件，约 11,477 行（主体）
- **Python**: 8 文件，约 523 行（Python C 扩展绑定）

### 模块划分

| 模块 | 语言 | 风险等级 | 关键文件 |
|------|------|----------|----------|
| dynolog_daemon | c_cpp | **Critical** | SimpleJsonServer.cpp, IPCMonitor.cpp |
| ipc_monitor | c_cpp | **High** | NpuIpcClient.cpp, MsptiMonitor.cpp |
| IPCMonitor_python | python | Low | monitor.py, dynamic_monitor_proxy.py |
| bindings | c_cpp | Medium | bindings.cpp |

---

## 攻击面分析

### 信任边界模型

项目存在以下信任边界：

| 信任边界 | 可信侧 | 不可信侧 | 风险等级 | 说明 |
|----------|--------|----------|----------|------|
| **Network Interface (TCP RPC)** | dynolog daemon | Remote clients | **Critical** | TCP 端口监听，支持 SSL/TLS，远程客户端可触达 |
| **IPC Unix Domain Socket** | dynolog daemon | Local monitored processes | **High** | 本地进程间通信，需权限连接 |
| **Local User Interface** | dynolog daemon startup | Local user (CLI args, env) | **Medium** | 启动参数由用户控制 |

### 主要入口点

#### 1. TCP RPC 服务入口（Critical）

**文件**: `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp`

| 入口点 | 行号 | 函数 | 说明 |
|--------|------|------|------|
| TCP Socket 绑定 | 77 | `initSocket()` | 绑定 IPv6 任意地址，监听端口（默认 1778） |
| TCP 连接接受 | 157 | `accept()` | 接受远程 TCP 连接 |
| 消息读取 | 199 | `get_message()` | 通过 recv() 或 SSL_read() 读取 RPC 请求 |
| JSON 解析 | 179 | `processOneImpl()` | 解析 JSON 格式的 RPC 请求 |

**数据流路径**：
```
TCP recv/SSL_read → get_message → processOneImpl → toJson → json::parse
```

**安全措施**：
- ✅ 支持 SSL/TLS 加密（需配置证书目录）
- ✅ 支持 SSL_VERIFY_PEER 双向证书验证
- ✅ RSA 密钥长度要求 ≥3072 位
- ✅ 证书版本和签名算法验证（仅允许 RSA_SHA_256/512）
- ⚠️ 支持 NO_CERTS 模式（无加密）
- ⚠️ JSON 解析无深度限制防护（但有 CheckJsonDepth 函数）

#### 2. IPC Unix Domain Socket 入口（High）

**文件**: `dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp`

| 入口点 | 行号 | 函数 | 说明 |
|--------|------|------|------|
| IPC 消息接收 | 58 | `ipc_manager_->recv()` | 接收 IPC 消息 |
| IPC 数据接收 | 70 | `data_ipc_manager_->recv()` | 接收 IPC 数据消息 |
| 消息处理 | 79 | `processMsg()` | 处理 IPC 消息（注册、请求、状态更新） |
| JSON 数据解析 | 141 | `processDataMsg()` | 解析 IPC 数据消息中的 JSON |

**数据流路径**：
```
recvmsg → FabricManager::recv → IPCMonitor::loop → processMsg → LibkinetoConfigManager
recvmsg → FabricManager::recv → IPCMonitor::dataLoop → processDataMsg → json::parse
```

**安全措施**：
- ✅ Unix Domain Socket 权限 0600（仅 owner 可访问）
- ✅ Socket 文件路径需在用户 home 目录下
- ✅ 消息大小限制 MAX_MSG_SIZE = 4096
- ⚠️ memcmp 比较消息类型（有长度检查）

#### 3. 命令行参数入口（Medium）

**文件**: `dynolog_npu/dynolog/src/Main.cpp`, `ThreadManager.cpp`

| 入口点 | 行号 | 函数 | 说明 |
|--------|------|------|------|
| 程序入口 | 11 | `main()` | 解析 argc, argv |
| 参数解析 | 201 | `gflags::ParseCommandLineFlags` | 解析命令行参数 |

**可配置参数**：
- `--port`: RPC 监听端口
- `--certs-dir`: SSL 证书目录
- `--enable-ipc-monitor`: 启用 IPC 监控
- `--enable-gpu-monitor`: 启用 GPU 监控
- `--metric-log-dir`: 日志目录

---

## 模块风险评估

### STRIDE 威胁建模

#### dynolog_daemon 模块（Critical）

| 威胁类型 | 风险 | 描述 |
|----------|------|------|
| **Spoofing (欺骗)** | Medium | SSL 双向证书验证可防止身份伪造；NO_CERTS 模式存在风险 |
| **Tampering (篡改)** | High | 网络数据可被中间人篡改（无 SSL 时）；JSON 配置可能被篡改 |
| **Repudiation (抵赖)** | Low | 有日志记录 |
| **Information Disclosure (信息泄露)** | High | 性能数据、进程信息可能通过网络暴露 |
| **Denial of Service (拒绝服务)** | High | 大量 RPC 请求可能导致服务过载；JSON 解析可能触发 DoS |
| **Elevation of Privilege (权限提升)** | Medium | setKinetOnDemandRequest 可能影响被监控进程 |

#### ipc_monitor 模块（High）

| 威胁类型 | 风险 | 描述 |
|----------|------|------|
| **Spoofing** | Low | IPC 需本地权限，伪造难度高 |
| **Tampering** | Medium | IPC 消息可能被篡改 |
| **Information Disclosure** | Medium | 性能数据通过 IPC 传递 |
| **Denial of Service** | Medium | IPC 消息洪水攻击 |
| **Elevation of Privilege** | Low | IPC 客户端权限受限 |

---

## 高风险文件列表

按优先级排序：

| 优先级 | 文件路径 | 风险等级 | 模块类型 | 关键风险点 |
|--------|----------|----------|----------|------------|
| 1 | `dynolog_npu/dynolog/src/rpc/SimpleJsonServer.cpp` | **Critical** | 网络/通信 | TCP RPC 服务入口、JSON 解析 |
| 2 | `dynolog_npu/dynolog/src/rpc/SimpleJsonServerInl.h` | **Critical** | 协议解析 | RPC 请求处理、配置解析 |
| 3 | `dynolog_npu/dynolog/src/tracing/IPCMonitor.cpp` | **High** | IPC/通信 | IPC 消息处理、JSON 解析 |
| 4 | `dynolog_npu/dynolog/src/ipcfabric/Endpoint.h` | **High** | IPC/通信 | Unix Socket 通信 |
| 5 | `dynolog_npu/dynolog/src/ipcfabric/FabricManager.h` | **High** | IPC/通信 | IPC 消息管理 |
| 6 | `dynolog_npu/dynolog/src/ThreadManager.cpp` | **High** | 线程管理 | 参数解析、线程启动 |
| 7 | `plugin/ipc_monitor/NpuIpcClient.cpp` | **High** | IPC 客户端 | IPC 客户端通信 |
| 8 | `plugin/bindings.cpp` | **Medium** | Python 绑定 | Python C 扩展接口 |

---

## 跨文件调用关系

### 关键调用链

#### RPC 请求处理链

```
main() [Main.cpp:11]
  → ThreadManager::run() [ThreadManager.cpp:199]
    → ThreadManager::start_threads() [ThreadManager.cpp:166]
      → SimpleJsonServer::run() [SimpleJsonServer.cpp:332]
        → SimpleJsonServer::loop() [SimpleJsonServer.cpp:303]
          → SimpleJsonServer::processOne() [SimpleJsonServer.cpp:314]
            → ClientSocketWrapper::accept() [SimpleJsonServer.cpp:151]
            → ClientSocketWrapper::get_message() [SimpleJsonServer.cpp:199]
              → read_helper() → recv()/SSL_read() [SimpleJsonServer.cpp:281]
            → processOneImpl() [SimpleJsonServerInl.h:179]
              → toJson() → json::parse() [SimpleJsonServerInl.h:58]
              → handleSetKinetOnDemandRequest() [SimpleJsonServerInl.h:141]
```

#### IPC 消息处理链

```
ThreadManager::start_threads() [ThreadManager.cpp:166]
  → IPCMonitor::loop() [IPCMonitor.cpp:55]
    → FabricManager::recv() [FabricManager.h:135]
      → EndPoint::tryPeekMsg() → recvmsg() [Endpoint.h:149]
      → EndPoint::tryRcvMsg() → recvmsg() [Endpoint.h:132]
    → IPCMonitor::processMsg() [IPCMonitor.cpp:79]
      → IPCMonitor::getLibkinetoOnDemandRequest() [IPCMonitor.cpp:173]
        → LibkinetoConfigManager::obtainOnDemandConfig()
```

---

## 安全加固建议（架构层面）

### 1. 网络通信安全

- **强制 SSL/TLS**: 建议禁止 NO_CERTS 模式，强制使用证书验证
- **证书管理**: 确保 `--certs-dir` 路径权限正确，防止证书文件被篡改
- **端口绑定**: 考虑绑定到特定 IP 而非任意地址（in6addr_any）

### 2. JSON 解析安全

- **深度限制**: 确保 CheckJsonDepth 函数有效防止 JSON 深度攻击
- **大小限制**: 考虑更严格的消息大小限制（当前 MAX_MESSAGE_LEN = 8192）
- **异常处理**: 增强 JSON 解析异常处理，防止异常信息泄露

### 3. IPC 安全

- **权限检查**: 确保 Unix Socket 文件权限 0600
- **路径验证**: 加强 Socket 路径验证，防止路径遍历
- **消息类型验证**: 加强消息类型 memcmp 的长度检查

### 4. 配置安全

- **参数验证**: 验证 --port、--certs-dir 等参数的有效性
- **敏感配置**: 避免通过命令行传递敏感信息
- **权限降级**: daemon 启动后考虑降低权限（当前已有 root 检查警告）

### 5. 日志安全

- **日志内容**: 避免在日志中记录敏感数据（如消息内容）
- **日志权限**: 确保日志文件权限正确

---

## 分析总结

MindStudio-Monitor 是一个典型的网络服务/守护进程项目，主要风险集中在 **TCP RPC 服务入口**。项目已实现多项安全措施（SSL/TLS、证书验证、IPC 权限控制），但仍存在以下潜在风险：

1. **NO_CERTS 模式**：无加密的 RPC 通信可能被中间人攻击
2. **JSON 解析**：大量 JSON 解析请求可能导致 DoS 或内存问题
3. **配置参数**：命令行参数可能被滥用
4. **IPC 消息**：本地 IPC 消息可能被篡改或伪造

建议后续 Scanner Agent 重点扫描：
- SimpleJsonServer.cpp 中的网络输入处理
- JSON 解析相关的输入验证
- IPC 消息处理的安全性
- 配置文件和参数的安全性

---

> **报告生成时间**: 2026-04-20
> **分析 Agent**: Architecture Agent
> **项目路径**: /home/pwn20tty/Desktop/opencode_project/shenteng/MindStudio/MindStudio-Monitor