# VULN-007：RDMA写操作缓冲区溢出漏洞

## 漏洞概述

| 属性 | 值 |
|------|------|
| **漏洞ID** | VULN-007 |
| **CWE** | CWE-120 (Buffer Copy without Checking Size of Input) |
| **类型** | buffer_overflow |
| **严重性** | Critical |
| **置信度** | 90% |
| **位置** | src/storage/service/StorageOperator.cc:539-562 |
| **函数** | StorageOperator::doUpdate |
| **模块** | storage |
| **跨模块** | 是 (storage + common/net) |

## 漏洞详情

### 问题代码

```cpp
// StorageOperator.cc:516-592 (doUpdate 函数)
CoTask<IOResult> StorageOperator::doUpdate(ServiceRequestContext &requestCtx,
                                           const UpdateIO &updateIO,
                                           const UpdateOptions &updateOptions,
                                           uint32_t featureFlags,
                                           const std::shared_ptr<StorageTarget> &target,
                                           net::IBSocket *ibSocket,
                                           BufferPool::Buffer &buffer,
                                           net::RDMARemoteBuf &remoteBuf,
                                           ChunkEngineUpdateJob &chunkEngineJob,
                                           bool allowToAllocate) {
  // ...
  
  if (updateIO.isWrite()) {
    // Line 546-548: 按 rdmabuf.size() 分配缓冲区
    auto allocateResult = buffer.tryAllocate(updateIO.rdmabuf.size());
    if (UNLIKELY(!allocateResult)) {
      allocateResult = co_await buffer.allocate(updateIO.rdmabuf.size());
    }
    // ...
    
    // Line 558: 数据指针指向分配的缓冲区
    job.state().data = allocateResult->ptr();
    
    // Line 561-562: RDMA 读取数据到本地缓冲区
    auto readBatch = ibSocket->rdmaReadBatch();
    readBatch.add(updateIO.rdmabuf, std::move(*allocateResult));
    // ...
  }
  
  // Line 597-598: 后续写入使用 updateIO.length
  co_await updateWorker_.enqueue(&job);
  co_await job.complete();
}
```

### 数据结构

```cpp
// fbs/storage/Common.h:326-344
struct UpdateIO {
  SERDE_STRUCT_FIELD(offset, uint32_t{});
  SERDE_STRUCT_FIELD(length, uint32_t{});      // 写入长度（客户端控制）
  SERDE_STRUCT_FIELD(chunkSize, uint32_t{});
  SERDE_STRUCT_FIELD(key, GlobalKey{});
  SERDE_STRUCT_FIELD(rdmabuf, net::RDMARemoteBuf{});  // RDMA缓冲区信息
  SERDE_STRUCT_FIELD(updateVer, ChunkVer{});
  SERDE_STRUCT_FIELD(updateType, UpdateType{});
  SERDE_STRUCT_FIELD(checksum, ChecksumInfo{});
  SERDE_STRUCT_FIELD(inlinebuf, UInt8Vector{});
  
  bool isWrite() const { return updateType == UpdateType::WRITE; }
};
```

```cpp
// common/net/ib/RDMABuf.h:40-62
class RDMARemoteBuf {
  uint64_t addr() const { return addr_; }
  size_t size() const { return length_; }  // RDMA缓冲区大小
};
```

### 漏洞原理

| 操作 | 缓冲区分配依据 | 写入长度依据 |
|------|----------------|--------------|
| **缓冲区分配** | `updateIO.rdmabuf.size()` | - |
| **数据写入** | - | `updateIO.length` |

**不对称安全**：
- 缓冲区大小 = `rdmabuf.size()` (客户端声明)
- 写入长度 = `updateIO.length` (客户端声明)
- **缺少验证**：`length <= rdmabuf.size()` 未检查

如果恶意客户端设置 `length > rdmabuf.size()`，则发生缓冲区溢出。

### 对比分析：读操作有验证

```cpp
// StorageOperator.cc:122-128 (batchRead 函数)
for (AioReadJobIterator it(&batch); it; it++) {
  // 读操作有长度验证！
  if (FAULT_INJECTION_POINT(requestCtx.debugFlags.injectServerError(),
                            true,
                            UNLIKELY(it->readIO().length > it->readIO().rdmabuf.size()))) {
    auto msg = fmt::format("invalid read buffer size {}", it->readIO());
    XLOG(ERR, msg);
    co_return makeError(StatusCode::kInvalidArg, std::move(msg));
  }
}
```

**读操作有验证，写操作无验证 —— 不对称安全设计**

### 后续写入点

```cpp
// ChunkReplica.cc:287 (正常写入)
writeResult = doRealWrite(chunkId, chunkInfo, state.data, writeIO.length, writeIO.offset);

// ChunkReplica.cc:102-129 (doRealWrite)
static Result<uint32_t> doRealWrite(const ChunkId &chunkId,
                                    ChunkInfo &chunkInfo,
                                    const uint8_t *writeData,    // 源：job.state().data
                                    uint32_t writeSize,          // 大小：writeIO.length
                                    uint32_t writeOffset) {
  auto writeResult = chunkInfo.view.write(writeData, writeSize, writeOffset, meta);
  // ...
}
```

## 攻击路径

### 数据流

```
客户端请求 (UpdateIO)
  │
  ├── rdmabuf.size() = X  (用于分配本地缓冲区)
  ├── length = Y          (用于写入操作)
  │
  ▼
StorageOperator::write()  [src/storage/service/StorageOperator.cc:233]
  │
  ▼
StorageOperator::handleUpdate()  [StorageOperator.cc:333]
  │
  ▼
StorageOperator::doUpdate()  [StorageOperator.cc:516]
  │
  ├── buffer.tryAllocate(rdmabuf.size())  分配 X 字节
  ├── job.state().data = allocateResult->ptr()
  │
  ▼
updateWorker_.enqueue(&job)  [StorageOperator.cc:597]
  │
  ▼
StorageTarget::updateChunk()  [StorageTarget.cc:306]
  │
  ▼
ChunkReplica::update()  [ChunkReplica.cc:132]
  │
  ▼
doRealWrite(..., state.data, writeIO.length, ...)  [ChunkReplica.cc:287]
  │
  ▼
chunkInfo.view.write(writeData, writeSize, ...)  [ChunkReplica.cc:122]
  │
  ▼
缓冲区溢出！(如果 length > rdmabuf.size())
```

### 入口点可达性

| 层级 | 入口 | 信任等级 |
|------|------|----------|
| 1 | RDMA Network Interface | untrusted_network |
| 2 | Storage RPC Service | untrusted_network |
| 3 | StorageOperator::write/update | untrusted_network |

**攻击者路径**：
1. 恶意客户端通过 RDMA 连接发送 UpdateReq
2. UpdateReq 包含构造的 UpdateIO，其中 `length > rdmabuf.size()`
3. StorageOperator 按 rdmabuf.size() 分配本地缓冲区
4. RDMA 读取数据到本地缓冲区（最多 rdmabuf.size() 字节）
5. ChunkEngine/ChunkReplica 按 length 字节写入，导致溢出

### 触发条件

恶意客户端构造请求：

```cpp
// 恶意请求构造
UpdateIO maliciousUpdateIO;
maliciousUpdateIO.rdmabuf = RDMARemoteBuf(addr, 1024, rkeys);  // 声明缓冲区 1024 字节
maliciousUpdateIO.length = 4096;  // 声明写入 4096 字节
maliciousUpdateIO.updateType = UpdateType::WRITE;

UpdateReq maliciousReq;
maliciousReq.payload = maliciousUpdateIO;
// 发送到 StorageService
```

服务器端：
1. 分配 1024 字节缓冲区
2. RDMA 读取最多 1024 字节
3. 尝试写入 4096 字节 → 缓冲区溢出

## 利用场景

### 场景1：堆破坏攻击

```
BufferPool::Buffer 分配内存池
  │
  ▼
allocateResult->ptr() 返回堆地址
  │
  ▼
ChunkReplica::doRealWrite 写入超长数据
  │
  ▼
覆盖堆中相邻对象的内存
  │
  ▼
可能破坏 ChunkInfo、ChunkMetadata 等关键数据结构
```

### 场景2：代码执行

在特定条件下：
1. 溢出覆盖 ChunkInfo 结构体中的函数指针
2. 后续调用该函数指针时执行攻击者代码
3. 需要精确控制溢出内容和堆布局

### 场景3：服务拒绝

最简单的攻击：
1. 大量发送恶意请求
2. 导致存储服务崩溃
3. 整个分布式文件系统不可用

### 场景4：数据篡改

1. 溢出覆盖相邻 Chunk 的元数据
2. 破坏 ChunkMetadata 中的 checksum、version 等字段
3. 导致数据校验失败或数据损坏

## 影响评估

### 直接影响

| 影响 | 描述 |
|------|------|
| 内存破坏 | BufferPool 内存池被溢出破坏 |
| 程序崩溃 | 服务进程崩溃导致存储不可用 |
| 数据损坏 | 相邻 Chunk 数据或元数据被覆盖 |

### 间接影响

| 影响 | 描述 |
|------|------|
| 远程代码执行 | 在堆布局可控条件下可实现 |
| 权限提升 | 存储服务通常以高权限运行 |
| 服务拒绝 | 整个分布式文件系统瘫痪 |

### 影响范围

- **攻击面**：RDMA Network Interface (远程客户端)
- **攻击者**：任何能连接 RDMA 网络的远程客户端
- **影响对象**：
  - Storage 服务进程
  - 所有使用该存储的文件系统客户端
  - 整个分布式文件系统的数据完整性

### 系统级影响

```
单点溢出
  │
  ▼
Storage Server 崩溃
  │
  ▼
Target 状态变为 OFFLINE
  │
  ▼
Chain 复制链断裂
  │
  ▼
客户端读写请求失败
  │
  ▼
整个文件系统不可用
```

## 修复建议

### 方案1：添加长度验证（推荐）

```cpp
CoTask<IOResult> StorageOperator::doUpdate(...) {
  if (updateIO.isWrite()) {
    // 添加长度验证，与读操作保持一致
    if (UNLIKELY(updateIO.length > updateIO.rdmabuf.size())) {
      auto msg = fmt::format("invalid write buffer size {}, length {} > rdmabuf.size {}",
                             updateIO, updateIO.length, updateIO.rdmabuf.size());
      XLOG(ERR, msg);
      co_return makeError(StatusCode::kInvalidArg, std::move(msg));
    }
    
    // 原有代码...
    auto allocateResult = buffer.tryAllocate(updateIO.rdmabuf.size());
    // ...
  }
}
```

### 方案2：统一验证框架

```cpp
// 创建统一的验证函数
Result<Void> validateUpdateIO(const UpdateIO &updateIO) {
  if (updateIO.isWrite() && updateIO.length > updateIO.rdmabuf.size()) {
    return makeError(StatusCode::kInvalidArg, 
                     fmt::format("length {} exceeds rdmabuf.size {}", 
                                 updateIO.length, updateIO.rdmabuf.size()));
  }
  return Void{};
}

// 在 write() 和 update() 入口处调用
CoTryTask<WriteRsp> StorageOperator::write(...) {
  auto validateResult = validateUpdateIO(req.payload);
  if (!validateResult) {
    rsp.result.lengthInfo = makeError(std::move(validateResult.error()));
    co_return rsp;
  }
  // ...
}
```

### 方案3：按 length 分配缓冲区（备选）

```cpp
// 如果业务需要支持 length > rdmabuf.size()，可改为：
auto allocateResult = buffer.tryAllocate(updateIO.length);  // 按 length 分配
// 但这需要验证 rdmabuf 实际可用大小
```

### 修复优先级

| 优先级 | 原因 |
|--------|------|
| **紧急** | Critical 级别，影响整个分布式文件系统安全 |

### 测试建议

修复后应添加安全测试：

```cpp
TEST(StorageOperator, ValidateUpdateIOBufferSize) {
  UpdateIO updateIO;
  updateIO.rdmabuf = RDMARemoteBuf(0, 1024, {});
  updateIO.length = 4096;  // length > rdmabuf.size
  updateIO.updateType = UpdateType::WRITE;
  
  auto result = validateUpdateIO(updateIO);
  EXPECT_FALSE(result.hasValue());
  EXPECT_EQ(result.error().code(), StatusCode::kInvalidArg);
}
```

## 总结

这是一个严重的远程缓冲区溢出漏洞，由于 RDMA 写操作缺少长度验证而导致。攻击者作为远程客户端，可通过恶意构造的 UpdateReq 请求触发溢出，可能实现远程代码执行、服务拒绝或数据篡改。该漏洞的核心问题是读操作有长度验证而写操作没有——不对称的安全设计。修复方案简单明确：在 doUpdate 或 write 入口添加与读操作一致的长度验证。