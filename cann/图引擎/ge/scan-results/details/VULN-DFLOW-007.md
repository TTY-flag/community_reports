# VULN-DFLOW-007：gRPC通信缺乏传输层加密保护漏洞

## 概要

| 字段 | 值 |
|-------|-------|
| **ID** | VULN-DFLOW-007 |
| **CWE** | CWE-319: 明文传输敏感信息 |
| **类型** | 缺失传输层保护 |
| **严重性** | High |
| **置信度** | 95% (已确认) |
| **文件** | `dflow/deployer/deploy/rpc/deployer_client.cc:46` |
| **函数** | `DeployerClient::GrpcClient::Init` |

---

## 漏洞描述

`DeployerClient::GrpcClient::Init` 中的 gRPC 客户端使用 `grpc::InsecureChannelCredentials()` 建立到远程部署服务器的网络连接。这意味着**客户端与服务器之间的所有通信都以明文传输，无任何加密或完整性保护**。

### 漏洞代码

**文件: `dflow/deployer/deploy/rpc/deployer_client.cc`**

```cpp
Status DeployerClient::GrpcClient::Init(const std::string &address) {
  GELOGI("Start to create channel, address=%s", address.c_str());
  grpc::ChannelArguments channel_arguments;
  channel_arguments.SetMaxReceiveMessageSize(INT32_MAX);
  channel_arguments.SetMaxSendMessageSize(INT32_MAX);
  // 漏洞: 使用不安全凭证 - 无加密
  auto channel = grpc::CreateCustomChannel(address, grpc::InsecureChannelCredentials(), channel_arguments);
  if (channel == nullptr) {
    GELOGE(FAILED, "[Create][Channel]Failed to create channel, address = %s", address.c_str());
    return FAILED;
  }
  stub_ = deployer::DeployerService::NewStub(channel);
  // ...
}
```

**对应服务端漏洞** (`dflow/deployer/deploy/rpc/deployer_server.cc:63`):

```cpp
server_builder.AddListeningPort(server_addr, grpc::InsecureServerCredentials());
```

---

## 攻击面分析

### 网络暴露

`RemoteDeployer` 类通过网络建立到**远程节点**的连接：

```cpp
// 文件: dflow/deployer/deploy/deployer/deployer.cc:270
const std::string rpc_address = node_config_.ipaddr + ":" + std::to_string(node_config_.port);
client_->Initialize(rpc_address);
```

`ipaddr` 可以是任意远程 IP 地址，不限于 localhost。配置示例：

```json
{
  "ipaddr": "192.168.0.1",
  "port": 50051,
  "is_local": false
}
```

### 传输的敏感数据

分析 `proto/deployer.proto` 发现以下敏感数据通过不安全通道传输：

#### 1. 认证凭证
```protobuf
message InitRequest {
  int32 logic_device_id = 2;
  string type = 3;
  string sign_data = 4;           // 认证令牌 - 明文传输!
  map<string, string> envs = 5;   // 环境变量
}
```

#### 2. 模型和文件数据
```protobuf
message TransferFileRequest {
  string path = 1;
  bytes content = 2;              // 文件内容明文传输
  bool eof = 3;
}

message ExecutorRequest {
  message DownloadModelRequest {
    uint32 model_id = 1;
    uint32 root_model_id = 2;
    uint64 offset = 3;
    bytes model_data = 4;         // 模型二进制数据明文传输
  }
  // ...
}
```

#### 3. 部署配置
```protobuf
message UpdateDeployPlanRequest {
  int32 device_id = 1;
  uint64 session_id = 2;
  uint32 root_model_id = 3;
  repeated SubmodelDesc submodel_descs = 6;  // 包含模型路径
  Options options = 14;                       // 配置选项
}
```

---

## 攻击场景

### 场景 1: 中间人攻击 (MITM)

**前提条件:**
- 攻击者在客户端和服务器之间有网络访问权限（同子网、被攻破的路由器等）

**攻击流程:**
1. 攻击者拦截 DeployerClient 和 DeployerServer 之间的 gRPC 流量
2. 攻击者从 `InitRequest` 消息中捕获 `sign_data` 认证令牌
3. 攻击者现在可以使用捕获的令牌作为合法客户端认证
4. 攻击者获得部署服务的完整访问权限

**影响:** 完全绕过认证，未授权访问 AI 模型部署基础设施。

### 场景 2: 模型数据窃取

**攻击流程:**
1. 攻击者拦截 `DownloadModelRequest` 或 `TransferFileRequest` 消息
2. 攻击者提取：
   - 模型二进制数据 (`bytes model_data`)
   - 文件内容 (`bytes content`)
   - 模型路径 (`string model_path`, `string saved_model_file_path`)
3. 专有 AI 模型和知识产权被盗

**影响:** 知识产权损失，模型被盗。

### 场景 3: 模型注入/篡改

**攻击流程:**
1. 攻击者拦截并修改传输中的消息：
   - 修改 `model_path` 指向恶意模型
   - 向 `model_data` 注入恶意代码
   - 修改 `Options` 中的配置
2. 修改后的数据被服务器接受（无完整性保护）
3. 恶意模型部署到生产环境

**影响:** 任意代码执行，数据污染，系统被攻破。

### 场景 4: 响应操纵

**攻击流程:**
1. 攻击者修改服务器响应：
   - 修改 `InitResponse.client_id` 冒充其他客户端
   - 修改 `HeartbeatResponse.device_status` 隐藏设备故障
   - 在响应载荷中注入恶意数据
2. 客户端基于伪造响应执行操作

**影响:** 数据完整性违规，系统不稳定，隐蔽持久访问。

---

## PoC 构建指南

### 步骤 1: 环境设置
```
DeployerServer (目标) <----[网络]----> DeployerClient (受害者)
                               |
                               v
                          攻击者 (MITM)
```

### 步骤 2: 流量捕获
使用标准网络工具（tcpdump、Wireshark）在服务器端口捕获 gRPC 流量。由于 gRPC 使用 HTTP/2，protobuf 消息在 HTTP/2 帧解码后可见明文。

### 步骤 3: 认证令牌提取
1. 监控 `InitRequest` 消息
2. 提取 `sign_data` 字段值
3. 重放认证到服务器

### 步骤 4: 数据提取/篡改
1. 从捕获流量解析 protobuf 消息
2. 提取或修改模型数据、文件内容
3. 将修改后的消息转发到目标

---

## 影响评估

| 影响类别 | 评级 | 说明 |
|-----------------|--------|--------------|
| **机密性** | High | 所有数据明文传输；敏感认证令牌、模型数据和配置暴露 |
| **完整性** | High | 无消息认证；流量可被修改且无法检测 |
| **可用性** | Medium | MITM 可丢弃或延迟消息导致部署失败 |
| **认证** | Critical | 认证令牌不安全传输且可被重放 |

### 业务影响
- **IP 盗窃:** 专有 AI 模型可被盗取
- **合规性:** 可能违反数据保护法规（GDPR、HIPAA 如适用）
- **安全:** 部署基础设施可能被完全攻破

---

## 受影响组件

| 组件 | 文件路径 | 行号 |
|-----------|-----------|------|
| gRPC Client | `dflow/deployer/deploy/rpc/deployer_client.cc` | 46 |
| gRPC Server | `dflow/deployer/deploy/rpc/deployer_server.cc` | 63 |
| Remote Deployer | `dflow/deployer/deploy/deployer/deployer.cc` | 275 |
| Protocol Definition | `dflow/deployer/proto/deployer.proto` | - |

---

## 修复建议

### 1. 启用 TLS 加密（推荐）

**客户端修复:**
```cpp
// 使用 TLS 凭证替代不安全凭证
grpc::SslCredentialsOptions ssl_options;
ssl_options.pem_root_certs = root_ca_cert;  // 用于服务器验证的 CA 证书

auto channel = grpc::CreateCustomChannel(
    address, 
    grpc::SslCredentials(ssl_options), 
    channel_arguments
);
```

**服务端修复:**
```cpp
grpc::SslServerCredentialsOptions ssl_options;
ssl_options.pem_key_cert_pairs.push_back(
    {server_key, server_cert}
);
ssl_options.pem_root_certs = ca_cert;  // 用于客户端证书验证

server_builder.AddListeningPort(
    server_addr, 
    grpc::SslServerCredentials(ssl_options)
);
```

### 2. 实现双向 TLS (mTLS) 强化认证

为最大安全性，实现双向 TLS 同时认证客户端和服务器：

```cpp
// 客户端 mTLS 配置
grpc::SslCredentialsOptions ssl_options;
ssl_options.pem_root_certs = ca_cert;
ssl_options.pem_private_key = client_key;
ssl_options.pem_cert_chain = client_cert;

// 服务端 mTLS 配置
grpc::SslServerCredentialsOptions ssl_options(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
ssl_options.pem_key_cert_pairs.push_back({server_key, server_cert});
ssl_options.pem_root_certs = ca_cert;
```

### 3. 配置化 TLS 开关

向 `NodeConfig` 添加 TLS 配置选项：

```cpp
struct NodeConfig {
  // ... 现有字段 ...
  bool use_tls = true;
  std::string ca_cert_path;
  std::string client_cert_path;  // 用于 mTLS
  std::string client_key_path;   // 用于 mTLS
};
```

### 4. 弃用明文通道上的认证令牌

当前 `sign_data` 认证机制在明文传输时根本不安全。应：
- 要求 TLS 后才接受认证令牌
- 实现应用级消息签名，使用 nonce/时间戳防止重放攻击

---

## 参考资料

- [CWE-319: 明文传输敏感信息](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-311: 缺失敏感数据加密](https://cwe.mitre.org/data/definitions/311.html)
- [CWE-326: 加密强度不足](https://cwe.mitre.org/data/definitions/326.html)
- [gRPC 安全最佳实践](https://grpc.io/docs/guides/auth/)

---

## 附录: 数据流图

```
┌─────────────────┐                    ┌─────────────────┐
│  DeployerClient │                    │  DeployerServer │
│   (gRPC 客户端)  │                    │   (gRPC 服务端)  │
└────────┬────────┘                    └────────┬────────┘
         │                                      │
         │  ┌────────────────────────────────────┐
         │  │ 不安全通道 (无 TLS)                │
         │  │                                    │
         │  │  ▼ 明文消息 ▼                      │
         │  │                                    │
         │  │  • InitRequest (sign_data)         │
         │  │  • LoadModelRequest                │
         │  │  • TransferFileRequest (content)   │
         │  │  • UpdateDeployPlanRequest         │
         │  │  • Model data (bytes)              │
         │  │                                    │
         ├──┼────────────────────────────────────┤
         │  │  ▲ MITM 攻击向量 ▲                 │
         │  │                                    │
         │  │  - 窃听                            │
         │  │  - 令牌捕获                        │
         │  │  - 数据篡改                        │
         │  │  - 响应注入                        │
         │  └────────────────────────────────────┘
         │                                      │
         └──────────────────────────────────────┘
```

---

**报告生成时间:** 2026-04-22  
**漏洞状态:** 已确认 - 真实漏洞需修复