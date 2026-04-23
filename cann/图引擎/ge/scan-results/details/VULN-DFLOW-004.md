# VULN-DFLOW-004: IDOR (Insecure Direct Object Reference) - Missing Authorization

## 漏洞概述

| 属性 | 值 |
|------|-----|
| CWE | CWE-862: Missing Authorization |
| 类型 | IDOR (Insecure Direct Object Reference) |
| 文件 | `dflow/deployer/daemon/daemon_service.cc:178-188` |
| 函数 | `GetClient` |
| 严重性 | **高危 (High)** |
| CVSS | 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |

## 漏洞描述

`GetClient` 函数仅根据 `client_id` 查找客户端对象，**不验证请求来源是否为该客户端的合法所有者**。攻击者可以通过猜测或枚举 `client_id` 来访问、操作其他用户的部署会话，执行部署、模型加载、缓存操作等敏感功能。

### 漏洞代码位置

```cpp
// daemon_service.cc:178-188
bool DaemonService::GetClient(int64_t client_id, DeployerDaemonClient **client, deployer::DeployerResponse &response) {
  *client = client_manager_->GetClient(client_id);  // 仅根据ID查找，不验证所有权
  if (*client != nullptr) {
    return true;  // 直接返回成功，无授权检查
  }
  REPORT_INNER_ERR_MSG("E19999", "Get client[%ld] failed.", client_id);
  GELOGE(FAILED, "[Get][Client] Get client[%ld] failed.", client_id);
  response.set_error_code(FAILED);
  response.set_error_message("Not exist client id");
  return false;
}
```

### 问题根源分析

#### 1. client_id 生成机制可预测

```cpp
// daemon_client_manager.h:108
int64_t client_id_gen_ = 0;  // 从 0 开始顺序递增

// daemon_client_manager.cc:86-92
int64_t new_client_id = client_id_gen_;
auto new_client = CreateClient(new_client_id);
clients_.emplace(new_client_id, std::move(new_client));
++client_id_gen_;  // 简单递增
client_id = new_client_id;
```

**枚举难度极低**:
- client_id 从 0 开始顺序分配
- 最大客户端数限制为 32 (`kMaxClientSize`)
- 攻击者只需枚举 0-31 即可找到有效 client_id

#### 2. 授权验证缺失 - 仅 InitRequest 有验证

```cpp
// daemon_service.cc:31-44 - Process 函数分支
Status DaemonService::Process(const std::string &peer_uri,
                              const deployer::DeployerRequest &request,
                              deployer::DeployerResponse &response) {
  auto request_type = request.type();
  if (request_type == deployer::kInitRequest) {
    ProcessInitRequest(peer_uri, request, response);  // ← 有 VerifyInitRequest
  } else if (request_type == deployer::kDisconnect) {
    ProcessDisconnectRequest(peer_uri, request, response);  // ← 无授权验证
  } else if (request_type == deployer::kHeartbeat) {
    ProcessHeartbeatRequest(request, response);  // ← 无授权验证，甚至不传 peer_uri
  } else {
    ProcessDeployRequest(request, response);  // ← 无授权验证
  }
  return SUCCESS;
}
```

**关键发现**: 
- `ProcessInitRequest` 调用 `VerifyInitRequest` (验证 IP + 签名)
- `ProcessDisconnectRequest` 传入 `peer_uri` 但仅用于日志记录
- `ProcessHeartbeatRequest` 和 `ProcessDeployRequest` 完全不验证请求来源

#### 3. 已有基础设施未用于安全验证

```cpp
// daemon_client_manager.h:92-95 - ClientAddr 结构体
struct ClientAddr {
  std::string ip;
  std::string port;
};

// daemon_client_manager.h:109 - 存储了 client_id -> peer_uri 映射
std::map<int64_t, ClientAddr> client_addrs_;

// daemon_client_manager.cc:148-155 - 创建时记录
Status DaemonClientManager::RecordClientInfo(const int64_t client_id, const std::string &peer_uri) {
  ClientAddr client;
  GE_CHK_STATUS_RET_NOLOG(GetClientIpAndPort(peer_uri, client));
  client_addrs_.emplace(client_id, client);  // ← 存储了所有权映射
  // 但 GetClient 从未使用此映射进行验证!
}
```

**讽刺的安全设计**: 系统已经记录了 client_id 与 IP 的对应关系，但从未用于授权验证。

## 完整攻击路径与数据流

### 数据流图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           正常流程 (有授权)                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  用户A (192.168.1.100)                                                      │
│       │                                                                     │
│       │ InitRequest                                                         │
│       │ sign_data + envs                                                    │
│       ▼                                                                     │
│  ProcessInitRequest()                                                       │
│       │                                                                     │
│       │ VerifyInitRequest(peer_uri, request)                                │
│       │   ├─ VerifyIpaddr(peer_uri) ← IP白名单验证                          │
│       │   └─ VerifySignData(request) ← 签名验证                              │
│       ▼                                                                     │
│  CreateAndInitClient(peer_uri, ...)                                         │
│       │                                                                     │
│       │ client_id_gen_++ → client_id=0                                      │
│       │ RecordClientInfo(client_id=0, peer_uri="192.168.1.100")             │
│       ▼                                                                     │
│  返回 client_id=0 给用户A                                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           漏洞流程 (无授权)                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  攻击者 (192.168.1.200)                                                     │
│       │                                                                     │
│       │ DeployerRequest                                                     │
│       │ client_id=0 (受害者ID)                                              │
│       │ type=kUnloadModel                                                   │
│       ▼                                                                     │
│  Process(peer_uri="192.168.1.200", request)                                 │
│       │                                                                     │
│       │ request.type() != kInitRequest                                      │
│       │ → ProcessDeployRequest(request)                                     │
│       │     peer_uri 未传入! ← 关键漏洞                                      │
│       ▼                                                                     │
│  GetClient(client_id=0, ...)                                                │
│       │                                                                     │
│       │ client_manager_->GetClient(0)                                       │
│       │ → 返回用户A的 DeployerDaemonClient                                   │
│       │                                                                     │
│       │ ❌ 无 peer_uri 验证                                                  │
│       │ ❌ client_addrs_ 未使用                                              │
│       ▼                                                                     │
│  client->ProcessDeployRequest(request, response)                            │
│       │                                                                     │
│       │ → 操作用户A的 sub_deployer 进程                                      │
│       │ → 卸载用户A的模型                                                    │
│       ▼                                                                     │
│  攻击成功! 用户A的模型被卸载                                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 攻击步骤详解

1. **获取有效 client_id**:
   - 方法A: 枚举 0-31 (简单暴力枚举)
   - 方法B: 通过 client.json 文件泄露获取
   - 方法C: 网络嗅探 (gRPC 无加密)

2. **构造恶意请求**:
   ```cpp
   // proto/deployer.proto 定义
   message DeployerRequest {
     int64 client_id = 1;        // ← 攻击者填入受害者ID
     uint64 message_id = 2;
     DeployerRequestType type = 3;
     oneof body {
       // 各种操作类型...
     }
   }
   ```

3. **发送请求执行攻击**

## 可利用的操作类型分析

基于 `proto/deployer.proto` 的 `DeployerRequestType` 定义:

| 类型值 | 操作名 | 攻击危害 | 数据流 |
|--------|--------|----------|--------|
| 1 | `kDisconnect` | **DoS**: 强制断开受害者会话 | `ProcessDisconnectRequest` → `CloseClient` → 终止 sub_deployer 进程 |
| 4 | `kLoadModel` | **代码注入**: 在受害者环境加载恶意模型 | `ProcessDeployRequest` → `LoadModelProcess` → `HeterogeneousModelDeployer::DeployModel` |
| 5 | `kUnloadModel` | **业务破坏**: 卸载受害者正在使用的模型 | `ProcessDeployRequest` → `UnloadModelProcess` → `UnloadSubmodels` |
| 7 | `kDownloadVarManager` | **数据篡改**: 修改变量管理器状态 | `ProcessDeployRequest` → `MultiVarManagerInfoProcess` |
| 8 | `kDownloadSharedContent` | **内存操作**: 修改共享内容描述 | `ProcessDeployRequest` → `SharedContentProcess` |
| 10 | `kDownloadConf` | **配置篡改**: 修改设备配置 | `ProcessDeployRequest` → `DownloadDevMaintenanceCfgProcess` |
| 11 | `kUpdateDeployPlan` | **计划篡改**: 修改部署计划 | `ProcessDeployRequest` → `UpdateDeployPlanProcess` → `UpdateDeployPlan` |
| 12 | `kTransferFile` | **文件写入**: 向受害者环境写入文件 | `ProcessDeployRequest` → `TransferFileProcess` → `AppendToFile` |
| 13 | `kAddFlowRoutePlan` | **路由篡改**: 修改流路由计划 | `ProcessDeployRequest` → `FlowRoutePlanProcess` |
| 15 | `kClearModelData` | **数据清除**: 清除模型运行数据 | `ProcessDeployRequest` → `ClearModelRunningData` |
| 16 | `kDataFlowExceptionNotify` | **虚假异常**: 注入异常通知 | `ProcessDeployRequest` → `DataFlowExceptionNotifyProcess` |
| 127 | `kHeartbeat` | **会话劫持**: 控制心跳状态 | `ProcessHeartbeatRequest` → `OnHeartbeat` (更新过期时间) |

### 高危操作详细分析

#### 1. kTransferFile - 文件写入攻击

```cpp
// deployer_service_impl.cc:220-242
void DeployerServiceImpl::TransferFileProcess(DeployContext &context,
                                              const deployer::DeployerRequest &request,
                                              deployer::DeployerResponse &response) {
  const auto &req_body = request.transfer_file_request();
  auto ret = context.flow_model_receiver_.AppendToFile(
      context.GetBaseDir() + req_body.path(),   // ← 写入路径可控
      req_body.content().data(),                 // ← 内容可控
      req_body.content().size(),
      req_body.eof());
  // ...
}
```

**攻击场景**: 向受害者工作目录写入恶意模型文件或配置文件。

#### 2. kUnloadModel - 模型卸载攻击

```cpp
// deployer_service_impl.cc:101-110
void DeployerServiceImpl::UnloadModelProcess(DeployContext &context,
                                              const deployer::DeployerRequest &request,
                                              deployer::DeployerResponse &response) {
  const auto &req_body = request.unload_model_request();
  auto ret = context.UnloadSubmodels(req_body.model_id());  // ← 卸载指定模型
  // ...
}
```

**攻击场景**: 卸载受害者正在推理的模型，造成服务中断。

#### 3. kHeartbeat - 会话状态操纵

```cpp
// daemon_service.cc:159-168
void DaemonService::ProcessHeartbeatRequest(const deployer::DeployerRequest &request,
                                            deployer::DeployerResponse &response) {
  int64_t client_id = request.client_id();
  DeployerDaemonClient *client = nullptr;
  if (GetClient(client_id, &client, response)) {
    client->SetIsExecuting(true);
    client->OnHeartbeat();  // ← 更新心跳时间，防止过期
    client->SetIsExecuting(false);
    (void)client->ProcessHeartbeatRequest(request, response);
  }
}
```

**攻击场景**: 
- 为受害者的会话发送心跳，延长其生命周期
- 或伪造执行状态，干扰系统调度

## PoC 构造思路

**注意**: 不提供完整可执行 PoC，仅说明构造方法。

### 思路 1: client_id 枚举

```
步骤:
1. 连接目标 daemon gRPC 服务 (默认端口通常在配置文件中)
2. 循环发送 kHeartbeat 或 kDisconnect 请求，client_id 从 0 到 31
3. 观察响应:
   - "Not exist client id" → 无效ID，继续枚举
   - 成功响应 → 找到有效 client_id，开始攻击
```

### 思路 2: 利用 client.json 信息泄露

```cpp
// daemon_client_manager.cc:157-184 - client.json 写入
Status DaemonClientManager::UpdateJsonFile() {
  const auto &dir = Configurations::GetInstance().GetDeployResDir();
  const std::string kClientFile = dir + "client.json";
  // 写入所有 client_addrs_ 到 JSON 文件
  nlohmann::json json;
  for (const auto &client : client_addrs_) {
    nlohmann::json client_addr = nlohmann::json{{"ip", client.second.ip}, {"port", client.second.port}};
    json["connections"].push_back(client_addr);
  }
  // ...
}
```

**信息泄露路径**:
- `client.json` 文件可能通过其他漏洞被读取
- 文件包含所有活跃客户端的 IP 和端口信息
- 配合枚举可精确定位受害者 client_id

### 思路 3: gRPC 无加密嗅探

```cpp
// deployer_server.cc (推测位置)
server_builder.AddListeningPort(server_addr, grpc::InsecureServerCredentials());
```

- gRPC 使用不安全凭据，无 TLS 加密
- 网络嗅探可直接获取 InitResponse 中的 client_id

## 影响范围评估

### 直接影响

| 影响类型 | 严重程度 | 描述 |
|----------|----------|------|
| 会话劫持 | **严重** | 完全控制其他用户的部署会话 |
| 服务拒绝 | **严重** | 强制断开连接，终止推理服务 |
| 数据篡改 | **高危** | 修改部署计划、模型配置 |
| 代码执行 | **高危** | 通过模型加载植入恶意代码 |

### 间接影响

1. **横向移动**: 控制部署会话后，可访问该会话管理的 NPU 设备资源
2. **供应链攻击**: 通过 TransferFile 和 LoadModel 植入恶意模型
3. **持久化**: 通过 Heartbeat 保持被劫持会话长期存活

### 受影响组件清单

| 文件 | 行号 | 问题 |
|------|------|------|
| `daemon_service.cc` | 178-188 | GetClient 无授权验证 |
| `daemon_service.cc` | 159-168 | ProcessHeartbeatRequest 不传 peer_uri |
| `daemon_service.cc` | 191-206 | ProcessDeployRequest 不传 peer_uri |
| `daemon_service.cc` | 147-156 | ProcessDisconnectRequest 不验证 peer_uri |
| `daemon_client_manager.h` | 108 | client_id_gen_ 从 0 开始 |
| `daemon_client_manager.cc` | 86-92 | 顺序 ID 分配 |
| `deployer.proto` | 53 | client_id 字段暴露在请求中 |

## 修复建议

### 优先级 P0: 立即修复 - 添加所有权验证

```cpp
// daemon_service.cc - 修复方案
bool DaemonService::GetClient(const std::string &peer_uri, int64_t client_id, 
                              DeployerDaemonClient **client, 
                              deployer::DeployerResponse &response) {
  // 1. 从 client_addrs_ 获取预期的客户端地址
  auto expected_addr = client_manager_->GetClientAddr(client_id);
  if (!expected_addr.has_value()) {
    response.set_error_code(FAILED);
    response.set_error_message("Client not found");
    return false;
  }
  
  // 2. 解析请求来源地址
  ClientAddr request_addr;
  if (DaemonClientManager::GetClientIpAndPort(peer_uri, request_addr) != SUCCESS) {
    response.set_error_code(FAILED);
    response.set_error_message("Invalid request source");
    return false;
  }
  
  // 3. 验证所有权 - IP 必须匹配
  if (request_addr.ip != expected_addr.value().ip) {
    GEEVENT("Authorization denied: client_id=%ld belongs to %s, request from %s",
            client_id, expected_addr.value().ip.c_str(), request_addr.ip.c_str());
    response.set_error_code(FAILED);
    response.set_error_message("Authorization denied");
    return false;
  }
  
  // 4. 获取客户端对象
  *client = client_manager_->GetClient(client_id);
  return (*client != nullptr);
}

// 需要修改所有调用处，传入 peer_uri:
// ProcessHeartbeatRequest(peer_uri, request, response)
// ProcessDeployRequest(peer_uri, request, response)
```

### 优先级 P1: 强化 client_id 生成

```cpp
// daemon_client_manager.h
#include <random>

class DaemonClientManager {
 private:
  std::random_device rd_;
  std::mt19937_64 gen_{rd_()};
  
  int64_t GenerateSecureClientId() {
    int64_t id;
    do {
      id = gen_();  // 使用加密安全的随机数
    } while (clients_.find(id) != clients_.end() || id == 0);
    return id;
  }
};
```

### 优先级 P2: 启用 gRPC TLS/mTLS

```cpp
// deployer_server.cc
grpc::SslServerCredentialsOptions ssl_options;
ssl_options.pem_root_certs = load_file("ca.pem");
ssl_options.pem_key_cert_pairs.push_back({
  load_file("server_key.pem"),
  load_file("server_cert.pem")
});
ssl_options.force_client_auth = true;  // mTLS
server_builder.AddListeningPort(server_addr, 
                                grpc::SslServerCredentials(ssl_options));
```

### 优先级 P3: 添加审计和速率限制

```cpp
// 添加安全审计日志
GEEVENT_SECURITY("Request processed: client_id=%ld, peer_uri=%s, type=%s, result=%s",
                 client_id, peer_uri.c_str(), 
                 DeployerRequestType_Name(request.type()).c_str(),
                 response.error_code() == 0 ? "SUCCESS" : "FAILED");

// 添加速率限制防止枚举
class RateLimiter {
  std::map<std::string, int> request_count_;
  std::map<std::string, std::chrono::steady_clock::time_point> last_reset_;
  // 每分钟最多 60 次请求
};
```

## 缓解措施 (临时)

在无法立即修复的情况下:

1. **网络隔离**: 将 daemon 服务部署在隔离网络，仅允许可信客户端访问
2. **IP 白名单强化**: 增强 `VerifyIpaddr` 的白名单范围
3. **日志监控**: 监控异常的跨 IP client_id 使用模式
4. **会话超时**: 减少 `kHeartbeatExpireSec` 从 30 秒到更短时间

## 结论

此漏洞为**真实且严重的安全漏洞**，属于典型的 IDOR (CWE-862) 漏洞模式:

- ✅ 漏洞代码明确存在
- ✅ 攻击路径可行且低成本
- ✅ 影响范围覆盖所有后续请求操作
- ✅ 已有基础设施可用于修复但未被使用
- ❌ 无现有缓解措施

**建议立即修复**，优先实施所有权验证机制，并考虑启用传输层安全认证。

---

*报告生成时间: 2026-04-22*
*分析深度: 深度利用分析*
*CWE 参考: https://cwe.mitre.org/data/definitions/862.html*
