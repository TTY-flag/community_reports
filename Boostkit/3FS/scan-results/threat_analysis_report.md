# 3FS  Threat Analysis报告

## 执行摘要

**项目概述**： 3FS (Fire-Flyer File System) 是DeepSeek AI为AI训练和推理工作负载设计的高性能分布式并行文件系统，通过RDMA网络实现高吞吐数据传输。鲲鹏平台适配版，本报告基于对项目的架构分析和和威胁面识别，STRIDE威胁建模
完成攻击面分析。

## 项目架构分析

### 栳统架构
3FS是一个多层分布式文件系统，包含以下核心服务组件：

1. **元数据服务** - 皴管文件的元数据信息（目录结构、权限管理)
2. **存储服务** - 数据块存储和检索服务
3. **管理服务** - 羏群管理和配置分发
4. **核心服务** - 用户认证和配置管理
5. **FUSE客户端** - 用户态文件系统挂载接口

6. **存储客户端** - 数据读写客户端SDK

7. **元数据客户端** - 元数据查询客户端SDK
8. **管理客户端** - 管理操作客户端SDK
### 数据流
用户通过FUSE挂载点访问文件系统 -> FUSE客户端将请求转发给元数据客户端/存储客户端 -> 元数据客户端/存储客户端从请求发送到存储服务/元数据服务进行处理。

存储服务直接处理数据读写请求，元数据服务处理元数据更新请求
管理服务处理节点注册、心跳和配置分发
### 信任边界
1. **RDMA网络接口** - 处理来自远程客户端的RDMA连接和数据传输
2. **TCP网络接口** - 处理管理服务的TCP连接
3. **FUSE挂载点** - 处理本地用户进程的文件系统请求
4. **FoundationDB存储** - 内部元数据存储
## 攻击面分析

### 网络攻击面
#### RDMA连接接受
IBSocket::accept是入口函数处理RDMA连接请求。攻击向量：
- 连接请求伪造：IBConnectReq 中的字段可能被篡改
- **恶意QP配置**：攻击者可能发送恶意QP参数
- **缓冲区溢出**：错误的buf_size/buf_ack_batch配置可能导致缓冲区问题
- **RDMA内存操作**：
IBSocket::rdmaRead和rdmaWrite允许攻击者直接读写远程内存
攻击向量：
- 读取任意地址的远程内存数据
- 写入恶意数据到远程内存，- 读取敏感信息（密钥、认证令牌等)
- **QP状态篡改**：攻击者可能篡改QP状态
- **RDMA操作劫伪造**：
rdmaBatch和rdmaPost中的参数可能被篡改
- **恶意opcode**：发送恶意opcode可能导致未定义行为
- **RDMA权限绕过**：
pkey_index和sl配置可能被攻击者绕过权限检查
- **越权攻击**：
攻击者可能使用高权限值访问受限资源

### 协议解析攻击
#### 消息反序列化
Processor::unpackMsg和unpackSerdeMsg处理网络消息
攻击向量：
- **恶意构造的消息**：
攻击者可能发送超长消息、- **恶意checksum**：
checksum可能被绕过
- **压缩数据攻击**：
恶意压缩数据可能导致解压失败或- **反序列化失败**：
恶意数据可能导致反序列化异常
- **类型混淆**：
恶意数据可能被解析为错误类型
攻击向量：
- **整数溢出**：
恶意Varint可能导致整数溢出
- **数组越界**：
恶意数组长度可能导致内存越界
- **字符串越界**：
恶意字符串长度可能导致内存越界或- **枚举值越界**：
恶意枚举值可能导致越界访问
#### RPC调用处理
serde::CallContext::call处理RPC调用
攻击向量：
- **恶意请求参数**：
请求参数可能包含恶意值
- **反序列化失败**：
参数反序列化可能失败
- **参数注入**：
恶意参数可能影响服务行为
- **服务拒绝**：
恶意服务ID/methodId可能导致服务拒绝
### 存储服务攻击
#### 数据读写
StorageOperator::readChunk和writeChunk处理数据读写
攻击向量：
- **任意地址读写**：
攻击者可以请求读写任意位置的数据
- **越权读写**：
攻击者可能绕过权限检查读写特权数据
- **缓冲区溢出**：
恶意chunk大小可能导致缓冲区问题
- **Chunk元数据篡改**：
攻击者可能篡改chunk元数据
- **RDMA传输攻击**：
数据读写通过RDMA传输，- 读取恶意数据**：攻击者可能读取敏感信息
- **写入恶意数据**：攻击者可能写入恶意数据覆盖合法数据
#### 元数据操作攻击
#### 目录操作
MetaOperator::createDir和removeDir处理目录操作
攻击向量：
- **路径遍历**：
恶意路径可能遍历到父目录外的目录
- **路径注入**：
恶意路径可能包含特殊字符
- **符号链接**：
恶意路径可能创建指向敏感文件的符号链接
- **目录遍历**：
恶意路径可能导致遍历深层目录
#### 文件操作
MetaOperator::open和rename处理文件操作
攻击向量：
- **权限绕过**：
恶意文件可能绕过权限检查
- **文件锁定**：
恶意文件可能导致锁竞争
- **并发访问**：
恶意并发访问可能导致资源耗尽
- **路径解析**：
PathResolve::resolve处理路径解析
攻击向量：
- **路径注入**：
恶意路径可能包含特殊字符
- **目录遍历**：
恶意路径可能导致遍历敏感目录
#### ACL操作
AclCache::get和AclCache::set处理ACL检查
攻击向量：
- **权限绕过**：
缓存可能返回过期的ACL
- **权限提升**：
恶意ACL可能提升权限
#### 批量操作
MetaOperator::batchOp处理批量元操作
攻击向量：
- **DoS攻击**：
大量恶意请求可能导致服务拒绝
- **资源耗尽**：
批量操作可能耗尽系统资源
- **并发访问**：
批量恶意访问可能导致系统崩溃
#### Session操作
SessionManager::extendSession处理会话管理
攻击向量：
- **会话劫持**：
攻击者可能劫持其他用户的会话
- **会话伪造**：
攻击者可能伪造会话信息
- **资源耗尽**：
大量会话可能导致内存耗尽
#### GC操作
GcManager::gcOperation处理垃圾回收
攻击向量：
- **资源耗尽**：
大量GC操作可能导致性能下降
- **数据丢失**：
恶意GC可能导致数据丢失
#### 心跳操作
HeartbeatOperation::handle处理心跳
攻击向量：
- **心跳伪造**：
攻击者可能伪造心跳信息
- **节点欺骗**：
恶意心跳可能欺骗管理服务
- **资源耗尽**：
大量心跳可能导致网络拥塞
#### 配置操作
SetConfigOperation::handle处理配置更新
攻击向量：
- **配置注入**：
恶意配置可能导致服务异常
- **配置覆盖**：
攻击者可能覆盖关键配置
- **权限绕过**：
恶意配置可能绕过权限检查
#### 用户操作
AdminUserCtrl::addUser和setUserToken处理用户管理
攻击向量：
- **用户伪造**：
攻击者可能伪造用户信息
- **权限提升**：
恶意用户可能获得提升权限
- **Token劫持**：
攻击者可能劫持其他用户的Token
#### FUSE操作
FuseOps处理FUSE文件系统请求
攻击向量：
- **路径遍历**：
恶意路径可能遍历文件系统
- **符号链接**：
恶意路径可能创建符号链接
- **权限绕过**：
恶意请求可能绕过权限检查
- **资源耗尽**：
大量请求可能导致资源耗尽
#### Python绑定攻击
binding.cc处理Python API绑定
攻击向量：
- **类型混淆**：
恶意Python数据可能导致类型混淆
- **API滥用**：
恶意Python调用可能导致服务异常
- **资源耗尽**：
大量Python调用可能导致内存耗尽

## STRIDE威胁建模

### Spoofing (身份伪造)
- **User Token伪造**：
UserToken::encodeUserToken可能被攻击者利用伪造Token
- **心跳伪造**：
攻击者可能伪造心跳信息伪装为合法节点
- **会话伪造**：
攻击者可能伪造会话信息访问其他用户的文件
**影响**: 攌击者可能访问其他用户的数据
### Tampering (数据篡改)
- **RDMA数据篡改**：
攻击者可能篡改RDMA传输的数据
- **配置篡改**：
攻击者可能篡改运行时配置
- **元数据篡改**：
攻击者可能篡改文件系统元数据
**影响**: 攠者可能修改关键数据，### Repudiation (拒绝服务)
- **服务拒绝**：
恶意请求可能导致服务拒绝正常请求
- **消息丢弃**：
攻击者可能丢弃关键消息
**影响**: 砖击者可能无法获取服务
### Information Disclosure (信息泄露)
- **错误消息泄露**：
错误消息可能包含敏感信息
- **日志泄露**：
日志可能包含敏感信息
- **路径泄露**：
路径解析可能泄露文件系统结构
**影响**: 攻击者可能获取敏感信息
### Elevation of Privilege (权限提升)
- **RDMA权限绕过**：
错误的pkey_index可能导致权限绕过
- **用户权限提升**：
恶意用户可能提升为管理员
- **服务权限提升**：
恶意服务可能提升权限
**影响**: 攻击者可能获得管理员权限
## 安全模块分析

### 加密/安全模块
- **位置**: src/core/user/UserToken.cc
- **功能**: 用户Token编码/解码
- **风险**: Token可能被伪造或- **建议**: 使用强加密算法保护Token

### 认证/授权模块
- **位置**: src/core/user/UserStore.cc,- **功能**: 用户管理
- **风险**: 用户权限可能被绕过
- **建议**: 实现严格的权限检查
### ACL模块
- **位置**: src/meta/components/AclCache.h
- **功能**: ACL缓存
- **风险**: ACL缓存可能返回过期信息
- **建议**: 实现ACL缓存过期检查
## 高风险文件列表

| 文件 | 风险 | 原因 |
| --- | --- | --- |
| src/common/net/ib/IBSocket.cc | Critical | RDMA连接和数据传输入口 |
| src/fuse/FuseOps.cc | Critical | FUSE操作入口，| src/storage/service/StorageOperator.cc | Critical | 存储数据读写入口 |
| src/common/net/Processor.h | High | 网络消息处理入口 |
| src/meta/service/MetaOperator.cc | High | 元数据操作入口 |
| src/common/serde/Serde.h | High | 序列化入口 |
| src/mgmtd/ops/HeartbeatOperation.cc | High | 心跳处理入口 |
| src/core/user/UserToken.cc | High | Token处理入口 |
| src/client/cli/admin/AdminUserCtrl.cc | High | 管理员操作入口 |
| src/lib/py/binding.cc | High | Python绑定入口 |
## 娡块依赖关系

```
fuse -> client/meta -> meta/service/MetaOperator
fuse -> client/storage -> storage/service/StorageOperator
client/meta -> meta/service/MetaOperator
client/storage -> storage/service/StorageOperator
meta/service -> common/kv -> FoundationDB
storage/service -> storage/chunk_engine -> Rust Engine
mgmtd/service -> common/kv -> FoundationDB
core/service -> common/kv -> FoundationDB
common/net -> common/serde -> 序列化
common/net -> ib -> RDMA Stack
```

## 建议议1. 加强RDMA连接验证
2. 实现消息反序列化的严格验证
3. 加强FUSE操作的权限检查
4. 实现存储服务的访问控制
5. 加强元数据服务的ACL检查
6. 实现管理服务的认证机制
7. 加强核心服务的Token验证
8. 实现Python绑定的类型检查