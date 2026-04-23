# VULN-DFLOW-003: gRPC通信缺乏TLS加密保护

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **CWE编号** | CWE-319: Cleartext Transmission of Sensitive Information |
| **漏洞类型** | Missing Transport Layer Protection |
| **严重程度** | 高危 |
| **CVSS评分** | 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| **影响组件** | dflow/deployer |

## 漏洞详情

### 受影响代码

**服务端 (deployer_server.cc:63)**
```cpp
Status DeployerServer::Impl::Run() {
    const auto &device_info = Configurations::GetInstance().GetLocalNode();
    std::string port = std::to_string(device_info.port);
    std::string ip = device_info.ipaddr;
    std::string server_addr = ip + ":" + port;
    grpc::ServerBuilder server_builder;
    server_builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);
    // 漏洞点：使用不安全凭据，数据明文传输
    server_builder.AddListeningPort(server_addr, grpc::InsecureServerCredentials());
    // ...
}
```

**客户端 (deployer_client.cc:46)**
```cpp
Status DeployerClient::GrpcClient::Init(const std::string &address) {
    // 漏洞点：客户端同样使用不安全凭据
    auto channel = grpc::CreateCustomChannel(address, grpc::InsecureChannelCredentials(), channel_arguments);
    // ...
}
```

### 网络配置分析

服务监听地址由配置文件动态决定：
- **IP地址**: 来自 `NodeConfig.ipaddr`，由 `resource.json` 配置
- **端口**: 来自 `NodeConfig.port`

这意味着服务可能绑定到任意网络接口，包括：
- 公网IP地址
- 局域网地址
- `0.0.0.0` (所有接口)

## 传输数据敏感性分析

通过分析 `deployer.proto`，确认该gRPC服务传输以下敏感数据：

### 1. 模型数据 (LoadModelRequest / UpdateDeployPlanRequest)
```protobuf
message SubmodelDesc {
  uint32 submodel_id = 1;
  string model_name = 2;
  string model_path = 3;
  uint64 model_size = 4;
  // ... 模型配置信息
}

message ExecutorRequest {
  message DownloadModelRequest {
    uint32 model_id = 1;
    uint32 root_model_id = 2;
    uint64 offset = 3;
    bytes model_data = 4;  // 明文传输模型二进制数据
  }
}
```

### 2. 文件传输 (TransferFileRequest)
```protobuf
message TransferFileRequest {
  string path = 1;
  bytes content = 2;  // 明文传输文件内容
  bool eof = 3;
}
```

### 3. 认证签名数据 (InitRequest)
```protobuf
message InitRequest {
  int32 logic_device_id = 2;
  string type = 3;
  string sign_data = 4;  // 认证签名明文传输
  map<string, string> envs = 5;
}
```

### 4. 配置数据 (DownloadConfigRequest)
```protobuf
message DownloadConfigRequest {
  DeviceConfigType sub_type = 1;
  int32 device_id = 2;
  bytes config_data = 3;  // 设备配置明文传输
}
```

## 现有安全机制评估

代码中存在应用层认证机制 (`deployer_authentication.cc`)，但这**不能替代传输层加密**：

```cpp
// daemon_service.cc:63-71
Status DaemonService::VerifySignData(const deployer::DeployerRequest &request) {
  const auto &local_node = Configurations::GetInstance().GetLocalNode();
  if (local_node.auth_lib_path.empty()) {
    GELOGI("No need to verify data for deployer");
    return SUCCESS;  // 如果未配置auth_lib_path，认证被完全跳过
  }
  // ...
}
```

**问题**：
1. 应用层签名**不提供传输加密**，数据仍以明文形式在网络中传输
2. 认证签名字段本身在无TLS情况下可被窃取并用于**重放攻击**
3. 当 `auth_lib_path` 未配置时，认证完全被跳过

## 攻击路径

```
┌─────────────────┐                ┌─────────────────┐
│  Deployer Node A │                │  Deployer Node B │
│   (Client)      │                │   (Server)      │
└────────┬────────┘                └────────┬────────┘
         │                                  │
         │  gRPC (明文 HTTP/2)              │
         │  ─────────────────────────────> │
         │  - 模型数据                      │
         │  - 文件内容                      │
         │  - 认证签名                      │
         │  - 配置信息                      │
         │                                  │
    ┌────▼──────────────────────────────────▼────┐
    │           攻击者位置                        │
    │  ┌──────────────────────────────────────┐  │
    │  │  1. 网络嗅探 - 捕获所有gRPC流量        │  │
    │  │  2. 数据提取 - 获取模型、配置、签名    │  │
    │  │  3. 重放攻击 - 使用窃取的签名认证      │  │
    │  │  4. 中间人攻击 - 篡改传输数据          │  │
    │  └──────────────────────────────────────┘  │
    └────────────────────────────────────────────┘
```

### 攻击场景

**场景1：模型数据窃取**
1. 攻击者在网络中嗅探gRPC流量
2. 捕获 `DownloadModelRequest.model_data` 字段
3. 获取完整AI模型二进制文件
4. 模型知识产权泄露

**场景2：重放攻击**
1. 捕获 `InitRequest` 请求中的 `sign_data`
2. 在有效期内重放该签名
3. 绕过认证获取系统访问权限

**场景3：配置篡改**
1. 进行中间人攻击
2. 修改 `DownloadConfigRequest.config_data`
3. 注入恶意配置导致系统行为异常

## 影响范围

### 受影响组件
- `dflow/deployer/deploy/rpc/deployer_server.cc`
- `dflow/deployer/deploy/rpc/deployer_client.cc`

### 受影响操作
| 操作类型 | 敏感数据 | 风险等级 |
|----------|----------|----------|
| LoadModel | 模型路径、大小、配置 | 高 |
| DownloadModel | 模型二进制数据 | 高 |
| TransferFile | 文件内容 | 高 |
| InitRequest | 认证签名、环境变量 | 高 |
| UpdateDeployPlan | 部署计划、模型描述 | 中 |
| DownloadConfig | 设备配置数据 | 中 |
| Heartbeat | 客户端状态 | 低 |

## 修复建议

### 推荐方案：启用TLS加密

**服务端修改 (deployer_server.cc)**
```cpp
#include <grpc++/security/server_credentials.h>

Status DeployerServer::Impl::Run() {
    const auto &device_info = Configurations::GetInstance().GetLocalNode();
    std::string port = std::to_string(device_info.port);
    std::string ip = device_info.ipaddr;
    std::string server_addr = ip + ":" + port;
    
    grpc::ServerBuilder server_builder;
    server_builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);
    
    // 修复：使用TLS加密
    grpc::SslServerCredentialsOptions ssl_options;
    ssl_options.pem_root_certs = LoadRootCert();  // 加载CA证书
    ssl_options.pem_key_cert_pairs.push_back({
        LoadServerPrivateKey(),  // 加载服务器私钥
        LoadServerCert()         // 加载服务器证书
    });
    
    auto server_credentials = grpc::SslServerCredentials(ssl_options);
    server_builder.AddListeningPort(server_addr, server_credentials);
    // ...
}
```

**客户端修改 (deployer_client.cc)**
```cpp
Status DeployerClient::GrpcClient::Init(const std::string &address) {
    grpc::ChannelArguments channel_arguments;
    channel_arguments.SetMaxReceiveMessageSize(INT32_MAX);
    channel_arguments.SetMaxSendMessageSize(INT32_MAX);
    
    // 修复：使用TLS加密
    grpc::SslCredentialsOptions ssl_options;
    ssl_options.pem_root_certs = LoadRootCert();  // 加载CA证书
    
    auto channel = grpc::CreateCustomChannel(
        address, 
        grpc::SslCredentials(ssl_options),
        channel_arguments
    );
    // ...
}
```

### 配置文件扩展

在 `NodeConfig` 结构中添加TLS配置字段：

```cpp
// configurations.h
struct TlsConfig {
    std::string cert_path;      // 服务器证书路径
    std::string key_path;       // 私钥路径
    std::string ca_path;        // CA证书路径
    bool verify_client = true;  // 是否验证客户端证书
};

struct NodeConfig {
    // ... 现有字段
    TlsConfig tls_config;       // 新增TLS配置
};
```

### 备选方案

**短期缓解措施（无法立即部署TLS时）**：

1. **网络隔离**：确保部署节点处于隔离网络环境
2. **防火墙规则**：限制gRPC端口仅对授权节点开放
3. **强制认证**：确保 `auth_lib_path` 已正确配置
4. **审计日志**：记录所有gRPC请求用于安全审计

## 检测方法

### 静态检测
```bash
# 搜索不安全gRPC凭据使用
grep -rn "InsecureServerCredentials\|InsecureChannelCredentials" \
    --include="*.cc" --include="*.cpp" --include="*.h"
```

### 动态检测
```bash
# 使用tcpdump捕获gRPC流量验证是否明文
tcpdump -i any -A port <deployer_port> -w grpc_traffic.pcap

# 检查是否可读取到明文HTTP/2帧
strings grpc_traffic.pcap | grep -i "deployer\|model\|transfer"
```

## 参考资料

- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [gRPC Security: Authentication](https://grpc.io/docs/guides/auth/)
- [OWASP: Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

## 时间线

| 时间 | 事件 |
|------|------|
| 发现时间 | 源代码审计 |
| 报告时间 | 安全分析报告生成 |
| 修复状态 | 待修复 |

---

**报告生成时间**: 2026-04-22  
**分析工具**: 人工代码审计 + 静态分析
