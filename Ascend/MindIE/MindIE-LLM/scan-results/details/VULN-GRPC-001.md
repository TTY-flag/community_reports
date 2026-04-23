# VULN-GRPC-001: HandleDecodeRequest gRPC消息大小未上限验证致内存耗尽

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-GRPC-001 |
| **漏洞类型** | Memory Exhaustion (CWE-789) |
| **严重等级** | High |
| **影响组件** | `src/server/endpoint/grpc_wrapper/grpc_handler.cpp` |
| **漏洞函数** | `HandleDecodeRequest()` |
| **漏洞行号** | 85-92 |
| **验证状态** | 真实漏洞 (CONFIRMED) |

### 漏洞描述

在 MindIE-LLM 的 PD disaggregation（Prefill-Decode 分离部署）架构中，Decode 节点通过 gRPC 接收来自 Prefill 节点的 `DecodeParameters` 消息。在 `HandleDecodeRequest()` 函数中，`blocktable_size()` 和 `blockid_size()` 的值直接用于内存分配，未进行上限验证，攻击者可构造恶意 protobuf 消息导致内存耗尽。

### 漏洞代码

```cpp
// 文件: src/server/endpoint/grpc_wrapper/grpc_handler.cpp
// 行号: 85-92

KvCacheInfo kvCacheInfo;

// 问题1: blocktable_size() 未验证上限
kvCacheInfo.blockTable.resize(para.blocktable_size());

for (int i = 0; i < para.blocktable_size(); ++i) {
    const auto &blocktable = para.blocktable(i);
    
    // 问题2: blockid_size() 未验证上限
    kvCacheInfo.blockTable[i].reserve(blocktable.blockid_size());
    
    for (int j = 0; j < blocktable.blockid_size(); ++j) {
        kvCacheInfo.blockTable[i].push_back(blocktable.blockid(j));
    }
}
```

---

## 触发条件分析

### 必要条件

| 条件 | 说明 |
|------|------|
| **gRPC 可达** | 攻击者能连接到 interCommPort (默认 1121) |
| **TLS 未启用** 或 **证书泄露** | `interCommTLSEnabled = false` 或持有有效客户端证书 |
| **恶意消息构造** | 构造 `DecodeParameters` 消息，设置极大 `blocktable_size()` 值 |

### Protobuf 结构

```protobuf
// 文件: src/server/endpoint/grpc_wrapper/prefillAndDecodeCommunication.proto

message DecodeParameters {
    // ... 其他字段 ...
    repeated BlockIds blockTable = 26;  // 无大小限制!
}

message BlockIds {
    repeated int64 blockId = 1;  // 无大小限制!
}
```

### Protobuf Varint 编码特性

关键点：Protobuf 使用 varint 编码，大数值可用极小字节表示：

| 数值 | Varint 编码字节 |
|------|----------------|
| 127 | 1 字节 |
| 16,383 | 2 字节 |
| 2,097,151 | 3 字节 |
| 268,435,455 | 4 字节 |
| 4,294,967,295 (UINT32_MAX) | 5 字节 |
| 1,000,000,000 | 5 字节 |

这意味着一个声称包含 **10 亿个元素** 的数组，其 `_size()` 字段仅需 **5 字节** 编码！

### KvCacheInfo 结构

```cpp
// 文件: src/server/endpoint/grpc_wrapper/grpc_context.h

struct KvCacheInfo {
    std::vector<std::vector<int64_t>> blockTable;  // 嵌套 vector!
    std::vector<uint64_t> dpInstanceIds;
};
```

内存计算：
- 每个 `int64_t` = 8 字节
- 每个 `std::vector` 有约 24-32 字节开销
- 总内存 ≈ `blocktable_size() * (32 + blockid_size() * 8)` 字节

**示例计算**：
| blocktable_size | blockid_size | 预估内存分配 |
|-----------------|--------------|-------------|
| 100,000 | 1,000 | ~800 MB |
| 1,000,000 | 100 | ~80 MB (但 resize 会先分配 1M 个空 vector) |
| 1,000,000 | 1,000 | ~8 GB |
| 100,000,000 | 1 | ~3.2 GB (仅 resize) |

---

## 攻击路径图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            攻击路径 - VULN-GRPC-001                          │
└─────────────────────────────────────────────────────────────────────────────┘

┌───────────────┐
│   攻击者      │
│ (外部/内部)   │
└───────┬───────┘
        │
        │ 1. 网络访问
        │    (确认 interCommPort 可达)
        ▼
┌───────────────┐     ┌─────────────────────────────────────┐
│  gRPC 端点    │◄────│ 条件: interCommTLSEnabled = false   │
│ (interCommPort│     │ 或: 持有有效客户端证书              │
│  默认 1121)   │     └─────────────────────────────────────┘
└───────┬───────┘
        │
        │ 2. 发送恶意 DecodeParameters
        │    protobuf 消息
        ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                  DecodeService.DecodeRequestChannel()                      │
│                  (dmi_msg_receiver.cpp)                                    │
│                                                                           │
│  输入: DecodeParameters para                                              │
│                                                                           │
│  isValidRequest() 检查:                                                   │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │ ✓ request != nullptr                                             │     │
│  │ ✓ response != nullptr                                            │     │
│  │ ✓ para.maxnewtoken() >= 0                                        │     │
│  │ ✗ para.blocktable_size() - 无验证!                               │     │
│  │ ✗ para.blocktable(i).blockid_size() - 无验证!                    │     │
│  └─────────────────────────────────────────────────────────────────┘     │
└───────────────────────────────────────┬───────────────────────────────────┘
                                        │
                                        │ 3. 调用注册的 handler
                                        ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                  HandleDecodeRequest()                                     │
│                  (grpc_handler.cpp: 35-151)                                │
│                                                                           │
│  KvCacheInfo kvCacheInfo;                                                 │
│                                                                           │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │ 第 85 行:                                                         │    │
│  │ kvCacheInfo.blockTable.resize(para.blocktable_size());           │    │
│  │                                                                   │    │
│  │ 风险: 如果 para.blocktable_size() = 100,000,000                  │    │
│  │       resize() 将尝试分配 100M 个 std::vector<int64_t>           │    │
│  │       预估内存: ~3.2 GB                                           │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                           │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │ 第 86-92 行:                                                      │    │
│  │ for (int i = 0; i < para.blocktable_size(); ++i) {               │    │
│  │     kvCacheInfo.blockTable[i].reserve(blocktable.blockid_size());│    │
│  │     for (int j = 0; j < blocktable.blockid_size(); ++j) {        │    │
│  │         kvCacheInfo.blockTable[i].push_back(blocktable.blockid(j));│    │
│  │     }                                                             │    │
│  │ }                                                                 │    │
│  │                                                                   │    │
│  │ 风险: 如果每个 blockid_size() = 1,000                             │    │
│  │       reserve() 为每个 vector 预分配 8KB                         │    │
│  │       总计: 100M * 8KB = 800 GB (理论值)                          │    │
│  │       实际: 系统会在 OOM 时崩溃                                    │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└───────────────────────────────────────┬───────────────────────────────────┘
                                        │
                                        │ 4. 内存耗尽触发
                                        ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                           系统响应                                         │
│                                                                           │
│  ┌─────────────────────────────┐    ┌─────────────────────────────────┐  │
│  │ std::bad_alloc 异常         │ OR │ OOM Killer 终止进程             │  │
│  │ (resize/reserve 失败)       │    │ (Linux 内核介入)                │  │
│  └─────────────────────────────┘    └─────────────────────────────────┘  │
│                                                                           │
│  结果: Decode 节点服务崩溃，无法处理后续推理请求                           │
│  影响: 分布式推理系统中的 Decode 节点不可用                                │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## PoC 构思 (概念验证)

**注意：以下仅为构思框架，不提供完整可执行代码**

### 步骤 1: 确认目标可达

```python
# 概念: 端口探测
import socket
target_port = 1121  # 默认 interCommPort
# 检查端口是否开放
```

### 步骤 2: 构造恶意 Protobuf 消息

```protobuf
# 概念消息结构
DecodeParameters {
    reqId: "malicious-request"
    blockTable: [
        BlockIds { blockId: [1, 2, 3, ...] }  # 声称有大量元素
        # 重复 BlockIds...
    ]
}
```

关键点：利用 protobuf varint 编码特性，用极少字节声明极大数组大小。

### 步骤 3: 发送 gRPC 请求

```python
# 概念: 使用 gRPC 客户端
import grpc
# channel = grpc.insecure_channel('target:1121')  # TLS 禁用时
# stub = DecodeServiceStub(channel)
# response = stub.DecodeRequestChannel(malicious_params)
```

### 步骤 4: 观察效果

- 目标进程内存快速增长
- 系统触发 OOM Killer 或进程崩溃
- 服务日志显示内存分配错误

---

## 影响评估

### 直接影响

| 影响类型 | 程度 | 说明 |
|----------|------|------|
| **拒绝服务 (DoS)** | 高 | Decode 节点崩溃，无法处理推理请求 |
| **服务可用性** | 高 | PD 分离架构中 Decode 不可用导致整个推理中断 |
| **数据泄露** | 无 | 纯内存分配漏洞，不涉及数据读取 |
| **代码执行** | 极低 | 内存耗尽不直接导致代码执行，除非结合其他漏洞 |

### 攻击场景分析

#### 场景 A: TLS 禁用环境 (高风险)

```
触发概率: 高
前提条件:
  - interCommTLSEnabled = false (配置文件)
  - 攻击者能访问 interCommPort 端口

发现依据:
  - 多个 README 文档示例显示 "interCommTLSEnabled" : false
  - 测试环境通常禁用 TLS 简化配置
  - 某些部署场景为性能考虑禁用 TLS
```

#### 场景 B: TLS 启用环境 (中等风险)

```
触发概率: 中等
前提条件:
  - interCommTLSEnabled = true
  - 攻击者持有有效客户端证书
  - 内部威胁或证书泄露场景

风险来源:
  - 内部恶意节点
  - 证书管理不当导致泄露
  - 供应链攻击植入恶意证书
```

### 业务影响

在 MindIE-LLM 的 PD disaggregation 架构中：
- **Prefill 节点**: 处理输入 token 的预填充
- **Decode 节点**: 处理后续 token 生成

攻击 Decode 节点会导致：
1. 推理请求无法完成
2. Prefill 节点缓存无法释放（KV Release 消息无法处理）
3. 整个分布式推理系统瘫痪
4. 潜在的请求积压和资源浪费

---

## 缓解措施分析

### 已存在缓解

| 缓解措施 | 文件位置 | 有效性 |
|----------|----------|--------|
| **消息大小限制** | `grpc_communication_mng.cpp:44` | 部分有效 |
| **TLS/mTLS** | `grpc_communication_mng.cpp:141` | 环境依赖 |
| **线程数限制** | `grpc_communication_mng.cpp:51` | 无关 |
| **并发流限制** | `grpc_communication_mng.cpp:53` | 无关 |

#### 消息大小限制分析

```cpp
// grpc_communication_mng.cpp:44
static const int MAX_MESSAGE_LENGTH = 16 * 1024 * 1024;  // 16MB

// grpc_communication_mng.cpp:126
builder.SetMaxReceiveMessageSize(MAX_MESSAGE_LENGTH);
```

**问题**：此限制针对的是 protobuf 消息的**序列化大小**，而非**解析后的内存占用**：

- Protobuf varint 编码：`blocktable_size() = 100,000,000` 只需 ~5 字节
- 消息可合法通过 16MB 限制
- 但解析后 `resize()` 会尝试分配巨大内存

### 缺失缓解

| 缺失措施 | 影响 |
|----------|------|
| `blocktable_size()` 上限检查 | 直接导致漏洞可利用 |
| `blockid_size()` 上限检查 | 加倍内存耗尽效果 |
| 内存分配异常处理 | 无 try-catch 保护 |
| 请求速率限制 | 无防 flood 保护 |

---

## 修复建议

### 建议 1: 添加大小上限验证 (优先级: 高)

```cpp
// 文件: grpc_handler.cpp
// 在 HandleDecodeRequest() 开头添加:

void HandleDecodeRequest(const prefillAndDecodeCommunication::DecodeParameters &para,
    prefillAndDecodeCommunication::DecodeRequestResponse &response)
{
    // 新增: 验证 blockTable 大小上限
    constexpr size_t MAX_BLOCK_TABLE_SIZE = 10000;  // 根据实际业务需求调整
    constexpr size_t MAX_BLOCK_ID_SIZE = 10000;     // 根据实际业务需求调整
    
    if (para.blocktable_size() > MAX_BLOCK_TABLE_SIZE) {
        response.set_errormessage("blocktable_size exceeds maximum limit");
        response.set_isvaliddecodeparameters(false);
        ULOG_ERROR(SUBMODLE_NAME_ENDPOINT, ...);
        return;
    }
    
    for (int i = 0; i < para.blocktable_size(); ++i) {
        if (para.blocktable(i).blockid_size() > MAX_BLOCK_ID_SIZE) {
            response.set_errormessage("blockid_size exceeds maximum limit");
            response.set_isvaliddecodeparameters(false);
            ULOG_ERROR(SUBMODLE_NAME_ENDPOINT, ...);
            return;
        }
    }
    
    // ... 继续原有处理 ...
}
```

### 建议 2: 在 isValidRequest() 中添加验证 (优先级: 高)

```cpp
// 文件: dmi_msg_receiver.cpp
// 扩展 isValidRequest() 函数:

bool DecodeRequestReceiver::isValidRequest(
    const prefillAndDecodeCommunication::DecodeParameters* request,
    prefillAndDecodeCommunication::DecodeRequestResponse* response,
    std::string& errMsg)
{
    // ... 现有检查 ...
    
    // 新增: blocktable_size 验证
    constexpr int MAX_BLOCK_TABLE_SIZE = 10000;
    if (request->blocktable_size() > MAX_BLOCK_TABLE_SIZE) {
        errMsg = "blocktable_size exceeds maximum allowed value";
        return false;
    }
    
    // 新增: blockid_size 验证
    constexpr int MAX_BLOCK_ID_SIZE = 10000;
    for (int i = 0; i < request->blocktable_size(); ++i) {
        if (request->blocktable(i).blockid_size() > MAX_BLOCK_ID_SIZE) {
            errMsg = "blockid_size exceeds maximum allowed value";
            return false;
        }
    }
    
    return true;
}
```

### 建议 3: 添加内存分配异常保护 (优先级: 中)

```cpp
// 文件: grpc_handler.cpp
// 使用 try-catch 保护内存分配:

KvCacheInfo kvCacheInfo;

try {
    kvCacheInfo.blockTable.resize(para.blocktable_size());
    for (int i = 0; i < para.blocktable_size(); ++i) {
        const auto &blocktable = para.blocktable(i);
        kvCacheInfo.blockTable[i].reserve(blocktable.blockid_size());
        for (int j = 0; j < blocktable.blockid_size(); ++j) {
            kvCacheInfo.blockTable[i].push_back(blocktable.blockid(j));
        }
    }
} catch (const std::bad_alloc& e) {
    response.set_errormessage("Memory allocation failed: blocktable too large");
    response.set_isvaliddecodeparameters(false);
    ULOG_ERROR(SUBMODLE_NAME_ENDPOINT, ...);
    return;
}
```

### 建议 4: Protobuf 定义添加限制注释 (优先级: 低)

```protobuf
// 文件: prefillAndDecodeCommunication.proto
// 添加文档说明字段预期范围:

message DecodeParameters {
    // ...
    // 注意: blockTable 元素数量不应超过业务合理范围 (建议 < 10000)
    repeated BlockIds blockTable = 26;
}

message BlockIds {
    // 注意: blockId 数量不应超过业务合理范围 (建议 < 10000)
    repeated int64 blockId = 1;
}
```

### 建议 5: 强制启用 TLS (优先级: 中)

```cpp
// 文件: config_manager/server_config.cpp
// 建议在生产环境强制要求 TLS:

if (serverConfig_.inferMode != "standard" && !serverConfig_.interCommTLSEnabled) {
    ULOG_WARN(SUBMODLE_NAME_ENDPOINT, 
              "interCommTLSEnabled is false - this is insecure for production!");
    // 可选: 强制启用或拒绝启动
}
```

---

## 相关文件清单

| 文件路径 | 作用 |
|----------|------|
| `/src/server/endpoint/grpc_wrapper/grpc_handler.cpp` | 漏洞所在文件 |
| `/src/server/endpoint/grpc_wrapper/grpc_handler.h` | handler 头文件 |
| `/src/server/endpoint/grpc_wrapper/grpc_communication_mng.cpp` | gRPC 服务初始化 |
| `/src/server/endpoint/grpc_wrapper/grpc_communication_mng.h` | 通信管理头文件 |
| `/src/server/endpoint/grpc_wrapper/dmi_msg_receiver.cpp` | 消息接收与验证 |
| `/src/server/endpoint/grpc_wrapper/dmi_msg_receiver.h` | 接收器头文件 |
| `/src/server/endpoint/grpc_wrapper/grpc_context.h` | KvCacheInfo 结构定义 |
| `/src/server/endpoint/grpc_wrapper/prefillAndDecodeCommunication.proto` | Protobuf 定义 |
| `/src/config_manager/server_config.cpp` | 配置解析 |
| `/src/include/config/config_info.h` | 配置结构定义 |

---

## 结论

**判定结果: 真实漏洞**

### 理由

1. **缺乏输入验证**: `blocktable_size()` 和 `blockid_size()` 直接用于内存分配，无上限检查
2. **可达性**: 在 TLS 禁用配置下，任何网络可达攻击者都可触发
3. **实际影响**: 可导致 Decode 节点 OOM 崩溃，影响分布式推理系统可用性
4. **配置风险**: 多处文档示例显示 TLS 禁用配置，表明此场景在部署中存在
5. **消息大小限制无效**: 16MB 限制针对序列化大小，而非解析后内存占用

### 建议优先级

| 建议 | 优先级 | 复杂度 |
|------|--------|--------|
| 添加大小上限验证 | 高 | 低 |
| isValidRequest 扩展 | 高 | 低 |
| 异常处理保护 | 中 | 低 |
| TLS 配置建议 | 中 | 配置变更 |
| Protobuf 文档 | 低 | 文档变更 |

---

## 附录: 相似漏洞参考

### CWE-789: Memory Allocation with Excessive Size Value

> "The product performs memory allocation on the basis of an untrusted size value, allowing an attacker to influence the size of the memory allocation."

### 类似案例

- CVE-2019-17571: Apache Log4j 1.2 deserialization memory exhaustion
- CVE-2021-44228: Log4Shell (类似攻击向量，不同影响)

### 安全最佳实践

1. **永远不信任外部输入的大小值**
2. **在内存分配前验证上限**
3. **使用 try-catch 处理内存分配失败**
4. **敏感通信必须启用 TLS/mTLS**
