# MindStudio Monitor (msmonitor) 威胁分析报告

## 执行摘要

本报告对 msmonitor (MindStudio Monitor) 项目进行安全威胁分析。msmonitor 是一个基于 dynolog 开发的 AI 模型性能监控守护进程，提供 npu-monitor 和 nputrace 功能。

**关键发现：**
- 项目类型：网络服务守护进程，监听 TCP 端口 1778
- 主要风险：远程 RPC 接口暴露、IPC 消息解析、JSON 数据处理
- 高风险入口点：13 个
- 高风险函数：8 个

---

## 项目概况

### 项目定位

| 属性 | 描述 |
|------|------|
| 项目类型 | `network_service` |
| 部署模式 | Linux 服务器上的守护进程，通过 RPC 端口 1778 接受客户端命令，通过 Unix Domain Socket 与 MSPTI 插件通信 |
| 语言组成 | C/C++ (80 文件) + Python (5 文件) + Rust CLI |
| 总代码量 | ~15,000 行 |

### 信任边界

| 边界 | 可信侧 | 不可信侧 | 风险等级 |
|------|--------|----------|----------|
| RPC Network Interface (Port 1778) | Dynolog Daemon | Remote dyno CLI clients | **Critical** |
| IPC Unix Domain Socket | Dynolog Daemon | Local MSPTI plugin processes | Medium |
| MSPTI Callback | Application | MSPTI activity data | Low |
| Configuration File | Dynolog Daemon | /etc/libkineto.conf | Low |

---

## 模块分析

### 模块结构

| 模块名称 | 路径 | 语言 | 风险等级 | 主要组件 |
|----------|------|------|----------|----------|
| dynolog_daemon | dynolog_npu/dynolog/src | C++ | **Critical** | RPC 服务器、IPC 监控、配置管理 |
| dyno_cli | dynolog_npu/cli/src | Rust | High | TLS 客户端、命令解析 |
| ipc_monitor_plugin | plugin/ipc_monitor | C++ | High | IPC 客户端、MSPTI 数据处理、数据库写入 |
| python_bindings | plugin/IPCMonitor | Python | Medium | Python 代理类、工具函数 |

### 高风险文件

| 文件 | 语言 | 风险 | 行数 | 优先级 | 原因 |
|------|------|------|------|--------|------|
| SimpleJsonServer.cpp | C++ | **Critical** | 818 | 1 | RPC 网络接口，接受远程连接 |
| IPCMonitor.cpp | C++ | **Critical** | 274 | 2 | IPC 消息处理，JSON 解析 |
| NpuIpcClient.cpp | C++ | **Critical** | 193 | 5 | IPC 客户端，消息发送/接收 |
| NpuIpcEndPoint.h | C++ | **Critical** | 272 | 6 | Unix Socket 端点，路径验证 |
| LibkinetoConfigManager.cpp | C++ | High | 375 | 3 | 配置文件解析 |
| InputParser.cpp | C++ | High | 157 | 7 | 配置字符串解析 |
| MsptiMonitor.cpp | C++ | High | 287 | 8 | MSPTI 缓冲区处理 |
| DBProcessManager.cpp | C++ | High | 493 | 10 | 数据库写入操作 |
| JsonlProcessManager.cpp | C++ | High | 389 | 11 | JSON 数据处理和文件写入 |

---

## 入口点分析

### 网络入口点

| 入口点 | 文件:行号 | 信任等级 | 描述 |
|--------|-----------|----------|------|
| RPC 端口初始化 | SimpleJsonServer.cpp:72 | untrusted_network | 监听 TCP 端口 1778，IPv6 |
| 客户端连接 | SimpleJsonServer.cpp:151 | untrusted_network | accept() 接受远程连接 |
| RPC 消息读取 | SimpleJsonServer.cpp:199 | untrusted_network | 从客户端读取 JSON 消息 |

### IPC 入口点

| 入口点 | 文件:行号 | 信任等级 | 描述 |
|--------|-----------|----------|------|
| IPC 消息循环 | IPCMonitor.cpp:55 | untrusted_local | Unix Domain Socket 监听 |
| IPC 消息处理 | IPCMonitor.cpp:79 | untrusted_local | 解析 IPC 消息类型和内容 |
| IPC 数据消息 | IPCMonitor.cpp:141 | untrusted_local | JSON 数据解析 |

### 其他入口点

| 入口点 | 文件:行号 | 信任等级 | 描述 |
|--------|-----------|----------|------|
| 配置文件读取 | LibkinetoConfigManager.cpp:103 | trusted_admin | 读取 /etc/libkineto.conf |
| IPC 客户端端点 | NpuIpcEndPoint.h:58 | untrusted_local | Unix Socket 客户端 |
| IPC 配置解析 | InputParser.cpp:142 | untrusted_local | 解析守护进程配置字符串 |
| MSPTI 回调 | MsptiMonitor.cpp:249 | semi_trusted | 处理原始活动数据 |
| Python 绑定 | bindings.cpp:1 | trusted_admin | Python 模块入口 |

---

## STRIDE 威胁分析

### Spoofing (身份伪造)

| 威胁 | 入口点 | 风险 | 缓解措施 |
|------|--------|------|----------|
| RPC 客户端身份伪造 | SimpleJsonServer.cpp | High | TLS 双向认证 (可选 NO_CERTS 模式存在风险) |
| IPC 进程身份伪造 | IPCMonitor.cpp | Medium | Unix Socket 文件权限检查 (0600) |
| MSPTI 数据源伪造 | MsptiMonitor.cpp | Low | 来自可信设备驱动 |

### Tampering (数据篡改)

| 威胁 | 入口点 | 风险 | 缓解措施 |
|------|--------|------|----------|
| RPC 消息篡改 | SimpleJsonServer.cpp | High | TLS 加密传输 |
| IPC 消息篡改 | IPCMonitor.cpp | Medium | Unix Socket 本地传输 |
| 配置文件篡改 | LibkinetoConfigManager.cpp | Low | 需要 root 权限 |
| 数据库文件篡改 | DBProcessManager.cpp | Medium | 文件权限控制 |

### Repudiation (否认)

| 威慑 | 入口点 | 风险 | 缓解措施 |
|------|--------|------|----------|
| RPC 命令否认 | SimpleJsonServer.cpp | Medium | glog 日志记录 |
| IPC 消息否认 | IPCMonitor.cpp | Medium | glog 日志记录 |

### Information Disclosure (信息泄露)

| 威胁 | 入口点 | 风险 | 缓解措施 |
|------|--------|------|----------|
| RPC 数据泄露 | SimpleJsonServer.cpp | High | TLS 加密 (可选) |
| IPC 数据泄露 | IPCMonitor.cpp | Low | Unix Socket 本地 |
| 日志文件泄露 | MsptiMonitor.cpp | Medium | 文件权限 0600 |
| 数据库内容泄露 | DBProcessManager.cpp | Medium | SQLite 文件权限 |

### Denial of Service (拒绝服务)

| 威胁 | 入口点 | 风险 | 缓解措施 |
|------|--------|------|----------|
| RPC 连接耗尽 | SimpleJsonServer.cpp | High | CLIENT_QUEUE_LEN=50 限制 |
| RPC 消息超时 | SimpleJsonServer.cpp:172 | Medium | SOCKET_TIMEOUT_SEC=3s |
| IPC 消息堆积 | IPCMonitor.cpp | Medium | 缓冲区大小限制 |
| 内存耗尽 | MsptiMonitor.cpp:232 | Medium | MAX_ALLOC_CNT 限制 |

### Elevation of Privilege (权限提升)

| 威胁 | 入口点 | 风险 | 缓解措施 |
|------|--------|------|----------|
| RPC 命令执行 | ServiceHandler.cpp | **Critical** | 未发现明显的命令执行漏洞 |
| IPC 消息处理漏洞 | IPCMonitor.cpp:79 | High | 需进一步验证 |
| 配置注入 | InputParser.cpp | High | validateArgs 输入验证 |
| 文件路径注入 | NpuIpcEndPoint.h:225 | High | 软链接检查 |

---

## 数据流分析

### 关键数据流路径

```
[远程 RPC 客户端]
    ↓ TCP/TLS
[SimpleJsonServer::processOne]
    ↓ JSON 解析
[ServiceHandler::handleRequest]
    → 配置分发
```

```
[本地 MSPTI 插件进程]
    ↓ Unix Socket
[FabricManager::recv]
    ↓ 消息队列
[IPCMonitor::processMsg]
    ↓ 类型判断 (memcmp)
[IPCMonitor::processDataMsg]
    ↓ JSON 解析
[LibkinetoConfigManager]
```

```
[MSPTI 设备回调]
    ↓ BufferRequest/BufferComplete
[MsptiMonitor::BufferConsume]
    ↓ 数据解析
[DBProcessManager/JsonlProcessManager]
    ↓ 文件写入
[SQLite 数据库 / JSONL 文件]
```

---

## 高风险函数

| 函数 | 文件:行号 | 风险 | 原因 |
|------|-----------|------|------|
| initSocket | SimpleJsonServer.cpp:72 | **Critical** | 监听公网 TCP 端口，绑定 IPv6 任意地址 |
| accept | SimpleJsonServer.cpp:151 | **Critical** | 接受远程客户端连接，处理 IPv6 地址 |
| get_message | SimpleJsonServer.cpp:199 | **Critical** | 从网络读取数据，消息大小由客户端控制 |
| processDataMsg | IPCMonitor.cpp:141 | **Critical** | 解析 IPC JSON 消息，可能触发 JSON 解析漏洞 |
| processMsg | IPCMonitor.cpp:79 | **Critical** | IPC 消息类型判断，使用 memcmp 可能绕过 |
| DynoLogGetOpts | InputParser.cpp:142 | High | 解析守护进程配置字符串，验证逻辑可能不完整 |
| BufferComplete | MsptiMonitor.cpp:249 | High | 处理 MSPTI 原始缓冲区数据，可能存在缓冲区溢出 |
| NpuIpcEndPoint | NpuIpcEndPoint.h:57 | High | 创建 Unix Domain Socket，路径验证可能不足 |

---

## 攻击面总结

### 外部攻击面

1. **RPC TCP 端口 1778 (IPv6)** - 最关键攻击面
   - 可选 TLS 认证 (NO_CERTS 模式完全无认证)
   - JSON 消息解析
   - 客户端地址可伪造

2. **Unix Domain Socket IPC** - 本地攻击面
   - 文件权限控制 (0600)
   - JSON 数据消息解析
   - memcmp 类型判断

### 内部攻击面

1. **MSPTI 活动数据缓冲区** - 半可信
   - 来自设备驱动
   - 大小由 MSPTI 控制

2. **SQLite 数据库文件** - 本地
   - 文件写入操作
   - 数据解析

3. **JSONL 日志文件** - 本地
   - JSON 数据构建
   - 文件写入

4. **配置文件 /etc/libkineto.conf** - 管理员控制
   - 需 root 权限修改

---

## 安全建议

### Critical 级别

1. **强制 TLS 认证**
   - 移除 NO_CERTS 模式或明确标记为不安全
   - 验证 RSA 密钥长度 >= 3072 位 (已实现)
   - 验证证书吊销状态 (已实现 CRL 检查)

2. **RPC 消息验证**
   - 限制最大消息长度 (已实现 MAX_MESSAGE_LEN = 8KB)
   - 添加请求速率限制
   - 记录所有 RPC 命令

### High 级别

3. **IPC 消息处理**
   - 添加消息完整性校验
   - 使用安全的字符串比较 (替代 memcmp)
   - 限制消息处理频率

4. **JSON 解析安全**
   - 添加 JSON 深度检查 (已实现 CheckJsonDepth)
   - 验证 JSON 字段类型
   - 防止异常抛出导致的崩溃

5. **输入验证**
   - 完善 InputParser 验证逻辑
   - 添加路径规范化
   - 防止软链接攻击 (已实现 IsSoftLink 检查)

### Medium 级别

6. **资源限制**
   - 添加 IPC 连接数量限制
   - 添加内存使用监控
   - 实现优雅降级机制

7. **日志安全**
   - 避免在日志中记录敏感数据
   - 添加日志文件权限检查
   - 实现日志轮转

---

## 附录

### A. 入口点完整列表

| ID | 文件 | 行号 | 函数 | 类型 | 信任等级 |
|----|------|------|------|------|----------|
| EP-001 | SimpleJsonServer.cpp | 72 | initSocket | network | untrusted_network |
| EP-002 | SimpleJsonServer.cpp | 151 | accept | network | untrusted_network |
| EP-003 | SimpleJsonServer.cpp | 199 | get_message | network | untrusted_network |
| EP-004 | IPCMonitor.cpp | 55 | loop | rpc | untrusted_local |
| EP-005 | IPCMonitor.cpp | 79 | processMsg | rpc | untrusted_local |
| EP-006 | IPCMonitor.cpp | 141 | processDataMsg | rpc | untrusted_local |
| EP-007 | LibkinetoConfigManager.cpp | 103 | readConfigFromConfigFile | file | trusted_admin |
| EP-008 | NpuIpcEndPoint.h | 58 | NpuIpcEndPoint | rpc | untrusted_local |
| EP-009 | InputParser.cpp | 142 | DynoLogGetOpts | rpc | untrusted_local |
| EP-010 | MsptiMonitor.cpp | 179 | Run | rpc | semi_trusted |
| EP-011 | MsptiMonitor.cpp | 249 | BufferComplete | rpc | semi_trusted |
| EP-012 | bindings.cpp | 1 | PYBIND11_MODULE | decorator | trusted_admin |
| EP-013 | dynamic_monitor_proxy.py | 31 | init_dyno | decorator | trusted_admin |

### B. 已实现的安全措施

| 措施 | 实现位置 | 描述 |
|------|----------|------|
| Root 用户警告 | ThreadManager.cpp:205, main.rs:642 | 启动时警告不要以 root 运行 |
| TLS 双向认证 | SimpleJsonServer.cpp:815 | SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
| RSA 密钥长度检查 | SimpleJsonServer.cpp:543, main.rs:54 | 要求 >= 3072 位 |
| 证书版本检查 | SimpleJsonServer.cpp:502, main.rs:262 | 要求 X.509v3 |
| 证书有效期检查 | SimpleJsonServer.cpp:550, main.rs:377 | 检查 not_before/not_after |
| CRL 吊销检查 | SimpleJsonServer.cpp:712, main.rs:405 | 检查证书吊销状态 |
| Socket 超时 | SimpleJsonServer.cpp:172 | 3 秒超时 |
| 消息长度限制 | SimpleJsonServer.cpp:28 | MAX_MESSAGE_LEN = 8KB |
| 软链接检查 | utils.cpp:455 | IsSoftLink 检查 |
| 路径权限检查 | utils.cpp:463 | DirPathCheck 验证 |
| JSON 深度检查 | IPCMonitor.cpp:157 | CheckJsonDepth |
| 注册数量限制 | LibkinetoConfigManager.cpp:26 | kMaxRegisterCount = 50 |
| 缓冲区分配限制 | MsptiMonitor.cpp:32 | MAX_ALLOC_CNT 限制 |
| 内存安全分配 | MsptiMonitor.cpp:309 | posix_memalign |
| securec 函数 | NpuIpcEndPoint.h:27 | memcpy_s, memset_s |

---

*报告生成时间: 2026-04-20*
*扫描工具: OpenCode Multi-Agent Vulnerability Scanner*