# Vulnerability Report: VULN-DFLOW-007

## Summary

| Field | Value |
|-------|-------|
| **ID** | VULN-DFLOW-007 |
| **CWE** | CWE-319: Cleartext Transmission of Sensitive Information |
| **Type** | Missing Transport Layer Protection |
| **Severity** | High |
| **Confidence** | 95% (Confirmed) |
| **File** | `dflow/deployer/deploy/rpc/deployer_client.cc:46` |
| **Function** | `DeployerClient::GrpcClient::Init` |

---

## Vulnerability Description

The gRPC client in `DeployerClient::GrpcClient::Init` uses `grpc::InsecureChannelCredentials()` to establish network connections to remote deployer servers. This means **all communications between the client and server are transmitted in plaintext without any encryption or integrity protection**.

### Vulnerable Code

**File: `dflow/deployer/deploy/rpc/deployer_client.cc`**

```cpp
Status DeployerClient::GrpcClient::Init(const std::string &address) {
  GELOGI("Start to create channel, address=%s", address.c_str());
  grpc::ChannelArguments channel_arguments;
  channel_arguments.SetMaxReceiveMessageSize(INT32_MAX);
  channel_arguments.SetMaxSendMessageSize(INT32_MAX);
  // VULNERABLE: Uses insecure credentials - no encryption
  auto channel = grpc::CreateCustomChannel(address, grpc::InsecureChannelCredentials(), channel_arguments);
  if (channel == nullptr) {
    GELOGE(FAILED, "[Create][Channel]Failed to create channel, address = %s", address.c_str());
    return FAILED;
  }
  stub_ = deployer::DeployerService::NewStub(channel);
  // ...
}
```

**Corresponding Server-Side Vulnerability** (`dflow/deployer/deploy/rpc/deployer_server.cc:63`):

```cpp
server_builder.AddListeningPort(server_addr, grpc::InsecureServerCredentials());
```

---

## Attack Surface Analysis

### Network Exposure

The `RemoteDeployer` class establishes connections to **remote nodes** over the network:

```cpp
// File: dflow/deployer/deploy/deployer/deployer.cc:270
const std::string rpc_address = node_config_.ipaddr + ":" + std::to_string(node_config_.port);
client_->Initialize(rpc_address);
```

The `ipaddr` can be any remote IP address, not limited to localhost. Configuration example:

```json
{
  "ipaddr": "192.168.0.1",
  "port": 50051,
  "is_local": false
}
```

### Sensitive Data Transmitted

Analysis of `proto/deployer.proto` reveals the following sensitive data transmitted over insecure channels:

#### 1. Authentication Credentials
```protobuf
message InitRequest {
  int32 logic_device_id = 2;
  string type = 3;
  string sign_data = 4;           // AUTHENTICATION TOKEN - transmitted in plaintext!
  map<string, string> envs = 5;   // Environment variables
}
```

#### 2. Model and File Data
```protobuf
message TransferFileRequest {
  string path = 1;
  bytes content = 2;              // File content in plaintext
  bool eof = 3;
}

message ExecutorRequest {
  message DownloadModelRequest {
    uint32 model_id = 1;
    uint32 root_model_id = 2;
    uint64 offset = 3;
    bytes model_data = 4;         // Model binary data in plaintext
  }
  // ...
}
```

#### 3. Deployment Configuration
```protobuf
message UpdateDeployPlanRequest {
  int32 device_id = 1;
  uint64 session_id = 2;
  uint32 root_model_id = 3;
  repeated SubmodelDesc submodel_descs = 6;  // Contains model paths
  Options options = 14;                       // Configuration options
}
```

---

## Attack Scenarios

### Scenario 1: Man-in-the-Middle (MITM) Attack

**Prerequisites:**
- Attacker has network access between client and server (same subnet, compromised router, etc.)

**Attack Flow:**
1. Attacker intercepts gRPC traffic between DeployerClient and DeployerServer
2. Attacker captures `sign_data` authentication tokens from `InitRequest` messages
3. Attacker can now authenticate as a legitimate client using captured tokens
4. Attacker gains full access to deployer service functionality

**Impact:** Complete authentication bypass, unauthorized access to AI model deployment infrastructure.

### Scenario 2: Model Data Exfiltration

**Attack Flow:**
1. Attacker intercepts `DownloadModelRequest` or `TransferFileRequest` messages
2. Attacker extracts:
   - Model binary data (`bytes model_data`)
   - File contents (`bytes content`)
   - Model paths (`string model_path`, `string saved_model_file_path`)
3. Proprietary AI models and intellectual property are stolen

**Impact:** Loss of intellectual property, model theft.

### Scenario 3: Model Injection / Tampering

**Attack Flow:**
1. Attacker intercepts and modifies messages in transit:
   - Modify `model_path` to point to malicious model
   - Inject malicious code into `model_data`
   - Alter configuration in `Options`
2. Modified data accepted by server (no integrity protection)
3. Malicious model deployed to production

**Impact:** Arbitrary code execution, data poisoning, system compromise.

### Scenario 4: Response Manipulation

**Attack Flow:**
1. Attacker modifies server responses:
   - Alter `InitResponse.client_id` to impersonate other clients
   - Modify `HeartbeatResponse.device_status` to hide device failures
   - Inject malicious data in response payloads
2. Client acts on falsified responses

**Impact:** Data integrity violations, system instability, covert persistent access.

---

## PoC Construction Guidance

### Step 1: Environment Setup
```
DeployerServer (Target) <----[Network]----> DeployerClient (Victim)
                              |
                              v
                         Attacker (MITM)
```

### Step 2: Traffic Capture
Use standard network tools (tcpdump, Wireshark) to capture gRPC traffic on the server port. Since gRPC uses HTTP/2, the protobuf messages are visible in plaintext after HTTP/2 frame decoding.

### Step 3: Authentication Token Extraction
1. Monitor for `InitRequest` messages
2. Extract `sign_data` field value
3. Replay authentication to server

### Step 4: Data Extraction/Tampering
1. Parse protobuf messages from captured traffic
2. Extract or modify model data, file contents
3. Forward modified messages to destination

---

## Impact Assessment

| Impact Category | Rating | Justification |
|-----------------|--------|--------------|
| **Confidentiality** | High | All data transmitted in plaintext; sensitive authentication tokens, model data, and configurations exposed |
| **Integrity** | High | No message authentication; traffic can be modified without detection |
| **Availability** | Medium | MITM can drop or delay messages causing deployment failures |
| **Authentication** | Critical | Authentication tokens transmitted insecurely and can be replayed |

### Business Impact
- **IP Theft:** Proprietary AI models can be stolen
- **Regulatory:** May violate data protection regulations (GDPR, HIPAA if applicable)
- **Security:** Complete compromise of deployment infrastructure possible

---

## Affected Components

| Component | File Path | Line |
|-----------|-----------|------|
| gRPC Client | `dflow/deployer/deploy/rpc/deployer_client.cc` | 46 |
| gRPC Server | `dflow/deployer/deploy/rpc/deployer_server.cc` | 63 |
| Remote Deployer | `dflow/deployer/deploy/deployer/deployer.cc` | 275 |
| Protocol Definition | `dflow/deployer/proto/deployer.proto` | - |

---

## Remediation Recommendations

### 1. Enable TLS Encryption (Recommended)

**Client-Side Fix:**
```cpp
// Use TLS credentials instead of insecure
grpc::SslCredentialsOptions ssl_options;
ssl_options.pem_root_certs = root_ca_cert;  // CA certificate for server verification

auto channel = grpc::CreateCustomChannel(
    address, 
    grpc::SslCredentials(ssl_options), 
    channel_arguments
);
```

**Server-Side Fix:**
```cpp
grpc::SslServerCredentialsOptions ssl_options;
ssl_options.pem_key_cert_pairs.push_back(
    {server_key, server_cert}
);
ssl_options.pem_root_certs = ca_cert;  // For client certificate verification

server_builder.AddListeningPort(
    server_addr, 
    grpc::SslServerCredentials(ssl_options)
);
```

### 2. Implement Mutual TLS (mTLS) for Strong Authentication

For maximum security, implement mutual TLS to authenticate both client and server:

```cpp
// Client mTLS configuration
grpc::SslCredentialsOptions ssl_options;
ssl_options.pem_root_certs = ca_cert;
ssl_options.pem_private_key = client_key;
ssl_options.pem_cert_chain = client_cert;

// Server mTLS configuration
grpc::SslServerCredentialsOptions ssl_options(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
ssl_options.pem_key_cert_pairs.push_back({server_key, server_cert});
ssl_options.pem_root_certs = ca_cert;
```

### 3. Configuration-Based TLS Toggle

Add TLS configuration options to `NodeConfig`:

```cpp
struct NodeConfig {
  // ... existing fields ...
  bool use_tls = true;
  std::string ca_cert_path;
  std::string client_cert_path;  // For mTLS
  std::string client_key_path;   // For mTLS
};
```

### 4. Deprecate Authentication Token Over Insecure Channel

The current `sign_data` authentication mechanism is fundamentally insecure when transmitted over plaintext. Either:
- Require TLS before accepting authentication tokens
- Implement application-level message signing with nonce/timestamp to prevent replay attacks

---

## References

- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [gRPC Security Best Practices](https://grpc.io/docs/guides/auth/)

---

## Appendix: Data Flow Diagram

```
┌─────────────────┐                    ┌─────────────────┐
│  DeployerClient │                    │  DeployerServer │
│   (gRPC Client) │                    │   (gRPC Server) │
└────────┬────────┘                    └────────┬────────┘
         │                                      │
         │  ┌────────────────────────────────────┐
         │  │ INSECURE CHANNEL (No TLS)          │
         │  │                                    │
         │  │  ▼ Plaintext Messages ▼            │
         │  │                                    │
         │  │  • InitRequest (sign_data)         │
         │  │  • LoadModelRequest                │
         │  │  • TransferFileRequest (content)   │
         │  │  • UpdateDeployPlanRequest         │
         │  │  • Model data (bytes)              │
         │  │                                    │
         ├──┼────────────────────────────────────┤
         │  │  ▲ MITM Attack Vector ▲            │
         │  │                                    │
         │  │  - Eavesdropping                   │
         │  │  - Token Capture                   │
         │  │  - Data Tampering                  │
         │  │  - Response Injection              │
         │  └────────────────────────────────────┘
         │                                      │
         └──────────────────────────────────────┘
```

---

**Report Generated:** 2026-04-22  
**Vulnerability Status:** CONFIRMED - Real vulnerability requiring remediation
