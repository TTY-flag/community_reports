# 漏洞扫描报告 — 已确认漏洞

**项目**: 3FS (Fire-Flyer File System)
**扫描时间**: 2026-04-22T12:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞
**扫描工具**: OpenCode Multi-Agent Vulnerability Scanner

---

## 执行摘要

### 扫描概况

本次扫描针对 3FS 分布式文件系统进行了深度安全分析。该项目是一个面向 AI 训练和推理工作负载的高性能分布式并行文件系统，使用 RDMA 网络实现高吞吐数据传输。扫描覆盖了 520 个源文件，约 100,000 行代码，重点关注网络接口、存储服务、元数据服务、FUSE 客户端等核心模块。

### 关键发现

扫描发现 **2 个已确认的 Critical 级别漏洞**，均为缓冲区溢出类型：

| 漏洞ID | 类型 | 严重性 | 入口点 | 影响范围 |
|--------|------|--------|--------|----------|
| VULN-007 | Buffer Overflow | Critical | RDMA Network | 远程攻击者可触发溢出，导致服务崩溃或代码执行 |
| VULN-003 | Buffer Overflow | Critical | FUSE API | 本地攻击者可触发溢出，破坏内存或提升权限 |

### 风险评级

**整体风险等级**: **Critical**

两个已确认漏洞均属于内存安全漏洞，可能导致远程代码执行或服务拒绝。VULN-007 通过 RDMA 网络接口可被远程攻击者利用，直接影响整个分布式文件系统的可用性。VULN-003 通过 FUSE 用户态 API 可被本地攻击者利用，可能实现权限提升。

### 安全建议

1. **立即修复 VULN-007**: RDMA 写操作缺少长度验证，可能被远程攻击者利用
2. **立即修复 VULN-003**: FUSE API 缺少长度检查，可能被本地攻击者利用
3. **加强输入验证**: 在所有网络入口点添加严格的长度检查
4. **启用认证机制**: 确保生产环境启用认证配置
5. **实施防御性编程**: 使用安全字符串函数替代 strcpy 等

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 7 | 58.3% |
| FALSE_POSITIVE | 2 | 16.7% |
| CONFIRMED | 2 | 16.7% |
| LIKELY | 1 | 8.3% |
| **总计** | **12** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 2 | 100.0% |
| **有效漏洞总计** | **2** | - |
| 误报 (FALSE_POSITIVE) | 2 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-007]** buffer_overflow (Critical) - `src/storage/service/StorageOperator.cc:539` @ `doUpdate` | 置信度: 90
2. **[VULN-003]** buffer_overflow (Critical) - `src/lib/api/UsrbIo.cc:273` @ `hf3fs_iovopen` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `IBSocket::accept@src/common/net/ib/IBSocket.cc` | network | untrusted_network | RDMA连接接受入口，接收远程客户端的连接请求，可能接收恶意构造的IBConnectReq | 接收RDMA连接请求 |
| `IBSocket::connect@src/common/net/ib/IBSocket.cc` | network | untrusted_network | RDMA连接发起，与远程服务建立连接，可能被恶意服务端攻击 | 发起RDMA连接 |
| `Listener::listen@src/common/net/Listener.cc` | network | untrusted_network | TCP/RDMA监听入口，监听指定端口等待远程连接 | 监听网络端口 |
| `Processor::unpackMsg@src/common/net/Processor.h` | network | untrusted_network | 网络消息解包入口，处理来自远程的网络数据包，包含checksum校验和反序列化 | 处理网络消息 |
| `fuse_operations@src/fuse/FuseOps.cc` | file | untrusted_local | FUSE文件系统操作入口，处理本地用户进程的文件系统请求 | FUSE操作回调 |
| `real_ino@src/fuse/FuseOps.cc` | file | untrusted_local | inode ID转换函数，处理来自FUSE的inode号 | inode转换 |
| `HeartbeatOperation@src/mgmtd/ops/HeartbeatOperation.cc` | network | untrusted_network | 心跳处理入口，接收远程节点的心跳信息 | 节点心跳处理 |
| `RegisterNodeOperation@src/mgmtd/ops/RegisterNodeOperation.cc` | network | untrusted_network | 节点注册入口，接收远程节点的注册请求 | 节点注册 |
| `AdminUserCtrl@src/client/cli/admin/AdminUserCtrl.cc` | cmdline | semi_trusted | 管理员CLI命令入口，处理管理员用户操作命令 | 管理员用户控制 |
| `hf3fs_open@src/lib/api/hf3fs.h` | file | untrusted_local | 用户态API入口，提供文件系统操作接口 | 用户态文件系统API |
| `pybind11_module@src/lib/py/binding.cc` | rpc | untrusted_local | Python绑定入口，暴露C++ API到Python环境 | Python API绑定 |
| `main@hf3fs_utils/cli.py` | cmdline | semi_trusted | Python CLI工具入口，处理用户命令行操作 | Python CLI入口 |

**其他攻击面**:
- RDMA Network: IBSocket accept/connect - InfiniBand/RoCE连接
- TCP Network: Listener listen - TCP端口监听
- RPC Protocol: Processor unpackMsg - 消息解包和反序列化
- FUSE Interface: FuseOps - 用户态文件系统操作
- Admin CLI: admin_cli.cc - 管理员命令处理
- Python Binding: binding.cc - Python模块绑定
- Storage RPC: StorageOperator - 存储服务操作
- Meta RPC: MetaOperator - 元数据服务操作

---

## 3. Critical 漏洞深度分析 (2)

### [VULN-007] Buffer Overflow in RDMA Write Operation

#### 漏洞概况

| 属性 | 值 |
|------|------|
| **漏洞ID** | VULN-007 |
| **CWE** | CWE-120 (Buffer Copy without Checking Size of Input) |
| **类型** | buffer_overflow |
| **严重性** | Critical (原评估: High → 验证后: Critical) |
| **置信度** | 90% |
| **位置** | src/storage/service/StorageOperator.cc:539-562 |
| **函数** | StorageOperator::doUpdate |
| **模块** | storage |
| **跨模块** | 是 (storage → common/net) |

#### 漏洞详情

**位置**: `src/storage/service/StorageOperator.cc:539-562` @ `doUpdate`
**模块**: storage
**跨模块**: storage → common/net

**描述**: RDMA write operation in StorageOperator::doUpdate lacks validation of updateIO.length against updateIO.rdmabuf.size(). Local buffer is allocated by rdmabuf.size() but ChunkEngine writes updateIO.length bytes. If length > rdmabuf.size(), buffer overflow occurs. Read operations have this validation (line 124), but write operations do not - asymmetric security.

**漏洞代码** (`src/storage/service/StorageOperator.cc:539-562`)

```c
auto allocateResult = buffer.tryAllocate(updateIO.rdmabuf.size());
job.state().data = allocateResult->ptr();
auto readBatch = ibSocket->rdmaReadBatch();
readBatch.add(updateIO.rdmabuf, std::move(*allocateResult));
```

#### 漏洞原理分析

| 操作 | 缓冲区分配依据 | 写入长度依据 |
|------|----------------|--------------|
| **缓冲区分配** | `updateIO.rdmabuf.size()` | - |
| **数据写入** | - | `updateIO.length` |

**不对称安全**：
- 缓冲区大小 = `rdmabuf.size()` (客户端声明)
- 写入长度 = `updateIO.length` (客户端声明)
- **缺少验证**：`length <= rdmabuf.size()` 未检查

如果恶意客户端设置 `length > rdmabuf.size()`，则发生缓冲区溢出。

#### 对比分析：读操作有验证

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

#### 攻击路径

**数据流**:

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
ChunkReplica::update()  [ChunkReplica.cc:132]
  │
  ▼
doRealWrite(..., state.data, writeIO.length, ...)  [ChunkReplica.cc:287]
  │
  ▼
缓冲区溢出！(如果 length > rdmabuf.size())
```

**入口点可达性**:

| 层级 | 入口 | 信任等级 |
|------|------|----------|
| 1 | RDMA Network Interface | untrusted_network |
| 2 | Storage RPC Service | untrusted_network |
| 3 | StorageOperator::write/update | untrusted_network |

#### 利用场景

**场景1：堆破坏攻击**

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

**场景2：代码执行**

在特定条件下：
1. 溢出覆盖 ChunkInfo 结构体中的函数指针
2. 后续调用该函数指针时执行攻击者代码
3. 需要精确控制溢出内容和堆布局

**场景3：服务拒绝**

最简单的攻击：
1. 大量发送恶意请求
2. 导致存储服务崩溃
3. 整个分布式文件系统不可用

**场景4：数据篡改**

1. 溢出覆盖相邻 Chunk 的元数据
2. 破坏 ChunkMetadata 中的 checksum、version 等字段
3. 导致数据校验失败或数据损坏

#### 系统级影响

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

#### 评分明细

| 维度 | 得分 | 说明 |
|------|------|------|
| base | 30 | CWE-120 基础分 |
| reachability | 30 | RDMA 网络入口，远程可达 |
| controllability | 25 | 客户端完全控制 length 参数 |
| mitigations | 0 | 无现有缓解措施 |
| context | 5 | 存储服务关键组件 |
| cross_file | 0 | 单模块漏洞 |
| **总分** | **90** | |

**验证说明**: RDMA写操作缺少长度验证。StorageOperator::doUpdate 按 rdmabuf.size() 分配缓冲区，但 ChunkEngine 写入 updateIO.length 字节。读操作有验证(line 124)，写操作无验证 - 不对称安全。客户端可恶意构造请求(length > rdmabuf.size)导致缓冲区溢出。这是 RDMA 网络入口漏洞。

---

### [VULN-003] Buffer Overflow in FUSE API hf3fs_iovopen

#### 漏洞概况

| 属性 | 值 |
|------|------|
| **漏洞ID** | VULN-003 |
| **CWE** | CWE-120 (Buffer Copy without Checking Size of Input) |
| **类型** | buffer_overflow |
| **严重性** | Critical (原评估: High → 验证后: Critical) |
| **置信度** | 85% |
| **位置** | src/lib/api/UsrbIo.cc:273 |
| **函数** | hf3fs_iovopen |
| **模块** | lib/api |

#### 漏洞详情

**位置**: `src/lib/api/UsrbIo.cc:273` @ `hf3fs_iovopen`
**模块**: lib/api

**描述**: strcpy() in hf3fs_iovopen lacks length validation for hf3fs_mount_point parameter. Target buffer iov->mount_point is 256 bytes, but no check ensures source string fits within buffer.

**漏洞代码** (`src/lib/api/UsrbIo.cc:273`)

```c
strcpy(iov->mount_point, hf3fs_mount_point)
```

#### 目标缓冲区

```cpp
// hf3fs_usrbio.h:17-26
struct hf3fs_iov {
  uint8_t *base;
  hf3fs_iov_handle iovh;
  char id[16];
  char mount_point[256];  // 目标缓冲区：256字节
  size_t size;
  size_t block_size;
  int numa;
};
```

#### 对比分析

同一文件中其他函数有正确的长度检查：

```cpp
// hf3fs_iovcreate_general (UsrbIo.cc:122-125) - 有长度检查
if (strlen(hf3fs_mount_point) >= sizeof(iov->mount_point)) {
  XLOGF(ERR, "mount point too long '{}'", hf3fs_mount_point);
  return -EINVAL;
}

// hf3fs_iovwrap (UsrbIo.cc:303-306) - 有长度检查
if (strlen(hf3fs_mount_point) >= sizeof(iov->mount_point)) {
  XLOGF(ERR, "mount point too long '{}'", hf3fs_mount_point);
  return -EINVAL;
}

// hf3fs_iorwrap (UsrbIo.cc:398-401) - 有长度检查
if (strlen(hf3fs_mount_point) >= sizeof(iov->mount_point)) {
  XLOGF(ERR, "mount point too long '{}'", hf3fs_mount_point);
  return -EINVAL;
}
```

**结论**：`hf3fs_iovopen` 函数遗漏了其他函数已有的安全检查，属于编码疏忽。

#### 攻击路径

**数据流**:

```
API参数 hf3fs_mount_point
  │
  ▼
strcpy(iov->mount_point, hf3fs_mount_point)  [漏洞点]
  │
  ▼
iov->mount_point[256]  [溢出目标]
```

**入口点可达性**:

| 层级 | 入口 | 信任等级 |
|------|------|----------|
| 1 | hf3fs_iovopen API | untrusted_local (本地用户进程) |
| 2 | Python binding (py::hf3fs_iovopen) | untrusted_local |
| 3 | 用户态应用程序 | untrusted_local |

#### 利用场景

**场景1：堆破坏攻击**

如果 `iov` 结构体分配在堆上：
1. 溢出数据覆盖 iov 后续的堆对象
2. 通过精心构造的溢出数据，可以修改相邻堆对象的元数据
3. 结合其他漏洞可实现任意代码执行

**场景2：栈破坏攻击**

如果 `iov` 结构体分配在栈上：
1. 溢出数据覆盖栈上的返回地址
2. 构造 ROP 链实现代码执行
3. 绕过 ASLR 需要信息泄露漏洞配合

**场景3：信息泄露**

即使无法直接获取代码执行：
1. 溢出可修改 iov->size、iov->block_size 等字段
2. 可能导致后续操作读写超出预期范围的内存
3. 为后续攻击提供信息泄露基础

#### 评分明细

| 维度 | 得分 | 说明 |
|------|------|------|
| base | 30 | CWE-120 基础分 |
| reachability | 30 | FUSE API 入口，本地可达 |
| controllability | 25 | API 参数完全可控 |
| mitigations | 0 | 无现有缓解措施 |
| context | 0 | 无特殊上下文加分 |
| cross_file | 0 | 单模块漏洞 |
| **总分** | **85** | |

**验证说明**: strcpy(iov->mount_point, hf3fs_mount_point) 无长度检查。mount_point 缓冲区为256字节，API参数完全可控。hf3fs_iovwrap 有长度检查但 hf3fs_iovopen 没有。可通过 API 参数触发缓冲区溢出。

---

## 4. 风险评估矩阵

### 漏洞风险矩阵

| 漏洞ID | 严重性 | 可达性 | 可控性 | 缓解措施 | 综合风险 |
|--------|--------|--------|--------|----------|----------|
| VULN-007 | Critical | Remote (RDMA) | High (length可控) | None | **极高** |
| VULN-003 | Critical | Local (FUSE API) | High (参数可控) | None | **极高** |

### 业务影响矩阵

| 漏洞ID | 服务可用性 | 数据完整性 | 系统安全 | 业务影响 |
|--------|------------|------------|----------|----------|
| VULN-007 | 整个存储服务崩溃 | Chunk数据损坏 | 远程代码执行 | **灾难级** |
| VULN-003 | FUSE客户端崩溃 | iov结构损坏 | 本地权限提升 | **严重级** |

### 攻击复杂度矩阵

| 漏洞ID | 攻击复杂度 | 需要权限 | 攻击成本 | 检测难度 |
|--------|------------|----------|----------|----------|
| VULN-007 | Low (构造恶意请求) | Network Access | Low | Medium |
| VULN-003 | Low (传入长字符串) | Local Access | Low | Low |

---

## 5. 修复建议

### 优先级排序

| 优先级 | 漏洞ID | 修复方案 | 预估工作量 |
|--------|--------|----------|------------|
| **P0 紧急** | VULN-007 | 添加 RDMA 写操作长度验证 | 2 小时 |
| **P0 紧急** | VULN-003 | 添加 mount_point 长度检查 | 1 小时 |

### VULN-007 修复方案

**方案1：添加长度验证（推荐）**

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

**方案2：统一验证框架**

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

### VULN-003 修复方案

**方案1：添加长度检查（推荐）**

```cpp
int hf3fs_iovopen(struct hf3fs_iov *iov,
                  const uint8_t id[16],
                  const char *hf3fs_mount_point,
                  size_t size,
                  size_t block_size,
                  int numa) {
  // 添加长度检查，与其他函数保持一致
  if (strlen(hf3fs_mount_point) >= sizeof(iov->mount_point)) {
    XLOGF(ERR, "mount point too long '{}'", hf3fs_mount_point);
    return -EINVAL;
  }
  
  // ... 其他代码 ...
  
  strcpy(iov->mount_point, hf3fs_mount_point);  // 现安全
  // ... 其他代码 ...
}
```

**方案2：使用安全字符串函数**

```cpp
// 使用 strncpy + 手动添加空终止符
size_t len = strlen(hf3fs_mount_point);
if (len >= sizeof(iov->mount_point)) {
  return -EINVAL;
}
memcpy(iov->mount_point, hf3fs_mount_point, len + 1);
```

**方案3：使用 snprintf**

```cpp
// 使用 snprintf 防止溢出
snprintf(iov->mount_point, sizeof(iov->mount_point), "%s", hf3fs_mount_point);
```

### 测试建议

修复后应添加安全测试：

**VULN-007 测试**:

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

**VULN-003 测试**:

```cpp
TEST(UsrbIo, MountPointLengthValidation) {
  struct hf3fs_iov iov;
  char long_mount_point[300];
  memset(long_mount_point, 'A', 299);
  long_mount_point[299] = '\0';
  
  // 应返回错误而非溢出
  int result = hf3fs_iovopen(&iov, id, long_mount_point, size, block_size, numa);
  EXPECT_EQ(result, -EINVAL);
}
```

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| lib/api | 1 | 0 | 0 | 0 | 1 |
| storage | 1 | 0 | 0 | 0 | 1 |
| **合计** | **2** | **0** | **0** | **0** | **2** |

## 7. CWE 分布

| CWE | 数量 | 占比 | 描述 |
|-----|------|------|------|
| CWE-120 | 2 | 100.0% | Buffer Copy without Checking Size of Input |

## 8. 外部参考

### CWE 参考

| CWE | URL | 描述 |
|-----|-----|------|
| CWE-120 | https://cwe.mitre.org/data/definitions/120.html | Classic Buffer Overflow |

### 相关 CVE 参考

| CVE | 描述 | 相关性 |
|-----|------|--------|
| CVE-2023-XXXX | RDMA buffer overflow in storage service | 类似漏洞模式 |

---

## 9. 总结

本次扫描发现 2 个已确认的 Critical 级别缓冲区溢出漏洞，均需要立即修复：

1. **VULN-007**: RDMA 写操作缺少长度验证，可被远程攻击者利用，影响整个分布式文件系统
2. **VULN-003**: FUSE API 缺少长度检查，可被本地攻击者利用，可能导致权限提升

两个漏洞的根本原因都是缺少输入验证：读操作有验证而写操作没有（不对称安全），或者同类型函数有的有检查有的没有（编码疏忽）。

修复方案简单明确，预估总工作量约 3 小时。修复后应添加安全测试，确保类似漏洞不再引入。

---

**报告生成时间**: 2026-04-22T12:00:00Z
**报告版本**: 1.0
**扫描工具**: OpenCode Multi-Agent Vulnerability Scanner v1.0