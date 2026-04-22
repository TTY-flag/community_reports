# MindCluster 威胁分析报告

**生成时间**: 2026-04-21
**项目路径**: /home/pwn20tty/Desktop/opencode_project/shenteng/MindCluster/mind-cluster
**分析模式**: 自主分析（无 threat.md 约束文件）

---

## 1. 项目概述

### 1.1 项目定位

MindCluster（AI集群系统软件）是华为开发的NPU（昇腾AI处理器）集群管理软件，用于深度学习训练和推理场景。主要功能包括：
- NPU集群作业调度
- 运维监测
- 故障恢复
- 设备管理
- 高性能数据传输

### 1.2 部署架构

MindCluster 以 Kubernetes 容器化部署方式运行，包含以下核心组件：

| 组件 | 类型 | 语言 | 运行方式 |
|------|------|------|----------|
| ascend-operator | Kubernetes Operator | Go | Deployment |
| clusterd | gRPC 服务 | Go | DaemonSet |
| noded | Node Agent | Go | DaemonSet |
| ascend-device-plugin | Device Plugin | Go | DaemonSet |
| ascend-docker-runtime | Runtime Hook | Go/C | Host 安装 |
| container-manager | Container Manager | Go | DaemonSet |
| taskd | Task Daemon | Go/Python | DaemonSet |
| npu-exporter | Prometheus Exporter | Go | DaemonSet |
| ascend-faultdiag | Fault Diagnosis Tool | Python | CLI/Service |
| mindio/tft | High-Speed I/O | C++/Python | Library |
| ascend-for-volcano | Scheduler Plugin | Go | Deployment |

### 1.3 语言组成

| 语言 | 文件数 | 占比 |
|------|--------|------|
| Go | 807 | 57% |
| Python | 430 | 30% |
| C/C++ | 199 | 13% |

---

## 2. 信任边界分析

### 2.1 信任边界定义

| 边界 | 可信侧 | 不可信侧 | 风险等级 | 说明 |
|------|--------|----------|----------|------|
| Kubernetes API | MindCluster Operators | Kubernetes API Server | Medium | Operators 通过 ServiceAccount 认证访问 K8s API |
| Kubelet Device Plugin Socket | ascend-device-plugin | Kubelet | Medium | Unix Socket 位于 /var/lib/kubelet/device-plugins/ |
| Container Runtime Hook | ascend-docker-runtime hook | Docker/containerd | **Critical** | stdin 接收容器状态 JSON，执行 CLI 工具 |
| gRPC Network Interface | clusterd gRPC server | Pod Network | High | POD_IP:port 对集群内 Pod 可达 |
| TCP/SSL Network Interface | mindio/tft | Remote Nodes | High | 高速传输框架，节点间通信 |
| Prometheus Metrics Endpoint | npu-exporter | Prometheus Scraper | Medium | HTTP metrics 端口 |
| CGO Interface | taskd Go backend | Python Worker Scripts | High | Python 调用 Go 函数 |
| Configuration Files | All Components | Host Filesystem | Low | 配置文件由管理员控制 |

### 2.2 关键信任边界详解

#### 2.2.1 Container Runtime Hook 边界（Critical）

**组件**: `ascend-docker-runtime/hook/process/process.go`

**威胁场景**:
- stdin 接收来自 Docker/containerd 的容器状态 JSON
- 解析 OCI spec 文件（config.json）
- 读取环境变量：`ASCEND_RUNTIME_OPTIONS`, `ASCEND_RUNTIME_MOUNTS`, `ASCEND_VISIBLE_DEVICES`, `ASCEND_ALLOW_LINK`
- 最终执行 `syscall.Exec(cliPath, args, os.Environ())`

**数据流**:
```
stdin (container state JSON)
  → getContainerConfig()
  → parseOciSpecFile()
  → getValueByKey() [读取环境变量]
  → readMountConfig() [读取挂载配置]
  → syscall.Exec() [执行 CLI]
```

**潜在攻击向量**:
- 恏意容器配置注入
- 环境变量篡改（容器镜像中的恶意 ENV）
- 配置文件路径遍历
- CLI 参数注入

#### 2.2.2 gRPC Network Interface 边界（High）

**组件**: `clusterd/pkg/interface/grpc/grpc_init.go`

**威胁场景**:
- gRPC 服务监听 `POD_IP:port`（端口常量）
- 暴露的服务：
  - FaultRecoverService
  - PubFaultService
  - TrainingDataTraceService
  - ConfigServer
  - FaultServer
  - JobServer

**潜在攻击向量**:
- Pod 内横向移动（恶意 Pod 调用 gRPC API）
- gRPC 消息注入/篡改
- 未授权的故障恢复操作
- 配置篡改

#### 2.2.3 TCP/SSL Network Interface 边界（High）

**组件**: `mindio/tft/src/csrc/acc_links/`

**威胁场景**:
- TCP 服务器监听集群网络
- OpenSSL/TLS 加密通信
- 证书管理（CA, CRL, 证书过期检查）

**潜在攻击向量**:
- 网络流量劫持
- SSL/TLS 配置漏洞（弱加密套件、证书问题）
- 中间人攻击
- 网络协议漏洞

---

## 3. STRIDE 威胁建模

### 3.1 Spoofing（身份伪造）

| 威胁 | 影响组件 | 严重程度 | 说明 |
|------|----------|----------|------|
| Pod 身份伪造 | clusterd, ascend-operator | High | 恶意 Pod 可伪造身份调用 gRPC API |
| ServiceAccount Token 泄露 | 所有 Operator | Medium | README 提示 token 明文存储风险 |
| 证书伪造 | mindio/tft | High | SSL/TLS 证书管理存在伪造风险 |

### 3.2 Tampering（数据篡改）

| 威胁 | 影响组件 | 严重程度 | 说明 |
|------|----------|----------|------|
| Container State 篡改 | ascend-docker-runtime | **Critical** | stdin JSON 可被篡改 |
| 配置文件篡改 | ascend-docker-runtime | High | mount.list 配置可被篡改 |
| gRPC 消息篡改 | clusterd | Medium | Pod 网络消息可被篡改 |
| Prometheus Metrics 篡改 | npu-exporter | Low | Metrics 数据可被篡改 |

### 3.3 Repudiation（否认）

| 威胁 | 影响组件 | 严重程度 | 说明 |
|------|----------|----------|------|
| 操作日志缺失 | 所有组件 | Medium | 需审计日志完整性 |
| gRPC 调用无审计 | clusterd | Medium | 无明确的 API 调用审计机制 |

### 3.4 Information Disclosure（信息泄露）

| 威胁 | 影害组件 | 严重程度 | 说明 |
|------|----------|----------|------|
| Metrics 信息泄露 | npu-exporter | Medium | NPU 状态信息对外暴露 |
| Container Config 泄露 | ascend-docker-runtime | Medium | 挂载配置、环境变量可见 |
| 日志信息泄露 | 所有组件 | Low | 日志可能包含敏感信息 |
| 加密密钥泄露 | ascend-faultdiag/crypto.py | Medium | AES 密钥存储和派生机制 |

### 3.5 Denial of Service（拒绝服务）

| 威胁 | 影响组件 | 严重程度 | 说明 |
|------|----------|----------|------|
| gRPC 连接耗尽 | clusterd | Medium | 有 limiter.LimitListener 保护 |
| TCP 连接耗尽 | mindio/tft | Medium | 无明确的连接限制机制 |
| 资源耗尽攻击 | 所有组件 | Low | Kubernetes 资源限制 |

### 3.6 Elevation of Privilege（权限提升）

| 威害 | 影响组件 | 严重程度 | 说明 |
|------|----------|----------|------|
| CLI 参数注入 → 权限提升 | ascend-docker-runtime | **Critical** | syscall.Exec 参数可被控制 |
| 特权容器部署 | ascend-device-plugin | High | README 提示特权容器风险 |
| CGO 跨语言调用 → 权限边界穿越 | taskd | High | Python → Go 权限边界 |
| exec.Command 权限提升 | ascend-common/hccn_tool | High | 执行外部命令 |

---

## 4. 高风险模块分析

### 4.1 进程执行模块（Critical）

**关键文件**:
- `component/ascend-docker-runtime/hook/process/process.go` (L388: `syscall.Exec`)
- `component/ascend-docker-runtime/runtime/process/process.go`
- `component/ascend-common/devmanager/hccn/hccn_tool.go` (`exec.Command`)
- `component/ascend-faultdiag/toolkit_src/ascend_fd_tk/utils/executors.py` (`subprocess`)

**风险分析**:

#### 4.1.1 ascend-docker-runtime Hook

```go
// hook/process/process.go:388
if err := doExec(cliPath, args, os.Environ()); err != nil {
    return fmt.Errorf("failed to exec docker-cli %v: %v", args, err)
}
```

**问题**:
- `args` 包含从环境变量解析的参数：`ASCEND_RUNTIME_OPTIONS`, `ASCEND_RUNTIME_MOUNTS`
- `cliPath` 路径基于当前可执行文件路径拼接
- 无输入验证或参数净化

**攻击场景**:
1. 恶意容器镜像包含恶意环境变量
2. 环境变量注入 CLI 参数
3. `ascend-docker-cli` 执行恶意操作

### 4.2 网络接口模块（High）

**关键文件**:
- `component/clusterd/pkg/interface/grpc/grpc_init.go` (gRPC server)
- `component/mindio/tft/src/csrc/acc_links/acc_tcp_server.cpp` (TCP server)
- `component/npu-exporter/cmd/npu-exporter/main.go` (HTTP metrics)

**风险分析**:

#### 4.2.1 clusterd gRPC Server

```go
// grpc_init.go:79-90
ipStr := os.Getenv("POD_IP")
listenAddress := ipStr + constant.GrpcPort
listen, err := net.Listen("tcp", listenAddress)
```

**问题**:
- `POD_IP` 来自环境变量（Kubernetes Pod IP）
- 无 TLS 加密（grpc.WithInsecure）
- 多个敏感服务暴露

**攻击场景**:
1. Pod 网络内的恶意 Pod 调用 gRPC API
2. 未授权触发故障恢复
3. 篡改集群配置

### 4.3 加密模块（Medium）

**关键文件**:
- `component/mindio/tft/src/csrc/acc_links/security/acc_tcp_ssl_helper.cpp` (OpenSSL)
- `component/ascend-faultdiag/toolkit_src/ascend_fd_tk/core/crypto/crypto.py` (AES-GCM)

**风险分析**:

#### 4.3.1 SSL/TLS 配置

```cpp
// acc_tcp_ssl_helper.cpp:94-97
ret = OpenSslApiWrapper::SslCtxSetCipherSuites(sslCtx, "TLS_AES_128_GCM_SHA256:"
                                                       "TLS_AES_256_GCM_SHA384:"
                                                       "TLS_CHACHA20_POLY1305_SHA256:"
                                                       "TLS_AES_128_CCM_SHA256");
```

**问题**:
- 强制 TLS 1.3（L90-92）- 较好
- 使用强加密套件 - 较好
- 但证书管理复杂（过期检查、CA/CRL 加载）

#### 4.3.2 Python Crypto

```python
# crypto.py:31-38
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=self.salt,
    iterations=self.iterations,
)
self.derived_key = kdf.derive(self.master_key)
```

**问题**:
- master_key 包含静态字符串 `"ImKeyPart"`（L13）
- iterations 默认 100000 - 较好
- AES-GCM 加密 - 较好

### 4.4 文件操作模块（Medium）

**关键文件**:
- `component/ascend-docker-runtime/hook/process/process.go` (readMountConfig)
- `component/mindio/acp/src/sdk/memfs/sdk/fs_operation.cpp`
- `component/ascend-common/common-utils/utils/file.go`

**风险分析**:

#### 4.4.1 Mount Configuration Parsing

```go
// process.go:275-279
absMountPath, err := filepath.Abs(mountPath)
if err != nil {
    continue
}
mountPath = absMountPath
```

**问题**:
- 转换为绝对路径 - 有一定防护
- 但未验证路径是否在允许范围内
- 路径遍历风险

---

## 5. 入口点清单

### 5.1 网络入口点

| 文件 | 行号 | 函数 | 类型 | 信任等级 | 说明 |
|------|------|------|------|----------|------|
| component/clusterd/pkg/interface/grpc/grpc_init.go | 90 | Start | rpc | semi_trusted | gRPC on POD_IP |
| component/ascend-device-plugin/pkg/server/server.go | 178 | createNetListener | rpc | semi_trusted | Unix Socket |
| component/mindio/tft/src/csrc/acc_links/acc_tcp_server.cpp | - | AccTcpServer | network | semi_trusted | TCP/SSL Server |
| component/npu-exporter/cmd/npu-exporter/main.go | - | main | network | semi_trusted | HTTP metrics |

### 5.2 标准输入入口点

| 文件 | 行号 | 函数 | 类型 | 信任等级 | 说明 |
|------|------|------|------|----------|------|
| component/ascend-docker-runtime/hook/process/process.go | 60 | DoPrestartHook | stdin | untrusted_local | Container state JSON |

### 5.3 环境变量入口点

| 文件 | 行号 | 函数 | 变量 | 信任等级 | 说明 |
|------|------|------|------|----------|------|
| component/ascend-docker-runtime/hook/process/process.go | 343 | DoPrestartHook | ASCEND_VISIBLE_DEVICES | untrusted_local | Container ENV |
| component/ascend-docker-runtime/hook/process/process.go | 347 | DoPrestartHook | ASCEND_RUNTIME_MOUNTS | untrusted_local | Container ENV |
| component/ascend-docker-runtime/hook/process/process.go | 358 | DoPrestartHook | ASCEND_RUNTIME_OPTIONS | untrusted_local | Container ENV |
| component/clusterd/pkg/interface/grpc/grpc_init.go | 79 | Start | POD_IP | semi_trusted | Pod IP from K8s |

### 5.4 命令行入口点

| 文件 | 行号 | 函数 | 类型 | 信任等级 | 说明 |
|------|------|------|------|----------|------|
| component/ascend-device-plugin/main.go | 269 | main | cmdline | trusted_admin | Device Plugin daemon |
| component/ascend-faultdiag/src/ascend_fd/controller/controller.py | - | main | cmdline | trusted_admin | Fault diagnosis CLI |

---

## 6. 安全建议

### 6.1 Critical 级别问题

#### 6.1.1 ascend-docker-runtime Hook 输入验证

**问题**: `syscall.Exec` 参数来自环境变量，缺乏净化

**建议**:
1. 实现严格的参数白名单验证
2. 使用正则表达式验证 `ASCEND_RUNTIME_OPTIONS` 格式
3. 验证挂载路径必须在 `/usr/local/Ascend/` 等安全目录内
4. 添加审计日志记录所有 CLI 执行

#### 6.1.2 ServiceAccount Token 安全

**问题**: README 提示 token 明文存储

**建议**:
1. 使用 Kubernetes TokenRequest API 获取短期 token
2. 实现 token 自动轮换
3. 使用 RBAC 严格限制权限

### 6.2 High 级别问题

#### 6.2.1 gRPC 安全加固

**问题**: clusterd gRPC 无 TLS

**建议**:
1. 实现 gRPC TLS/mTLS
2. 添加认证机制（ServiceAccount 或证书）
3. 实现请求审计日志
4. 细化 RBAC 权限

#### 6.2.2 特权容器风险

**问题**: README 提示特权容器部署风险

**建议**:
1. 评估是否可使用非特权容器
2. 实现最小权限原则
3. 使用 SecurityContext 限制能力

#### 6.2.3 CGO 边界安全

**问题**: taskd Go → Python 跨语言调用

**建议**:
1. 实现输入验证和类型检查
2. 添加边界审计
3. 限制可调用的函数范围

### 6.3 Medium 级别问题

#### 6.3.1 Metrics 端点保护

**问题**: npu-exporter HTTP 端点无认证

**建议**:
1. 添加 basic auth 或 token auth
2. 使用 NetworkPolicy 限制访问
3. 过滤敏感指标

#### 6.3.2 配置文件安全

**问题**: 配置文件路径遍历风险

**建议**:
1. 实现路径白名单验证
2. 使用 safejoin 或类似库
3. 验证文件权限

---

## 7. 总结

### 7.1 威胁等级分布

| 等级 | 数量 | 说明 |
|------|------|------|
| **Critical** | 1 | ascend-docker-runtime Hook - 进程执行注入 |
| High | 6 | gRPC接口、TCP/SSL、CGO边界、特权容器等 |
| Medium | 4 | Metrics泄露、配置篡改、日志安全等 |
| Low | 3 | 文件I/O、一般信息泄露等 |

### 7.2 优先修复顺序

1. **Critical**: ascend-docker-runtime hook 输入验证
2. **High**: clusterd gRPC TLS 加密
3. **High**: ServiceAccount token 安全加固
4. **High**: CGO 边界输入验证
5. **Medium**: Metrics 端点认证

### 7.3 后续扫描建议

建议对以下模块进行深度漏洞扫描：

- `component/ascend-docker-runtime/hook/process/process.go` - **最优先**
- `component/clusterd/pkg/interface/grpc/grpc_init.go`
- `component/mindio/tft/src/csrc/acc_links/` (网络模块)
- `component/ascend-common/devmanager/hccn/hccn_tool.go`
- `component/ascend-faultdiag/toolkit_src/ascend_fd_tk/utils/executors.py`

---

**报告生成工具**: Architecture Agent (自主分析模式)
**LSP 可用性**: 不可用 (gopls 未安装)
**分析方法**: grep-based 静态分析 + 代码审查