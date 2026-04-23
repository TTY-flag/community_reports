# UBS-Memory 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析为 AI 自主识别，未受 threat.md 约束。分析范围覆盖所有 IPC/RPC 入口点和高风险模块。

## 项目架构概览

### 项目定位

**项目类型**：网络服务（守护进程）

**部署模型**：
- 以 systemd 服务形式运行（ubsmd）
- 提供 Unix Domain Socket IPC 接口供本地进程使用
- 提供 TCP RPC 接口供远程节点通信（可选 TLS）
- 依赖 UBSE 硬件引擎库提供底层内存服务

**信任边界**：
| 边界 | 可信侧 | 不可信侧 | 风险等级 |
|------|--------|----------|----------|
| IPC Interface | ubsmd daemon (root) | Local processes | High |
| RPC Interface | Cluster nodes (TLS) | Remote nodes | Medium |
| UBSE Library | ubs-mem service | UBSE engine | Low |
| Config Files | Admin controlled | Service reads | Low |

### 模块结构

项目包含 13 个核心模块，194 个源文件，约 22,153 行代码：

| 模块 | 功能 | 语言 | 风险等级 |
|------|------|------|----------|
| mxm_shm | 共享内存管理、IPC/RPC 处理 | C++ | Critical |
| mxm_lease | 内存借用（租约）管理 | C++ | High |
| communication | IPC/RPC 通信引擎 | C++ | Critical |
| security | 加密解密、证书验证 | C++ | High |
| under_api | UBSE 底层 API 适配 | C++ | Critical |
| process | 守护进程管理 | C++ | High |
| zen_discovery | 节点发现与选主 | C++ | High |
| dlock_utils | 分布式锁 | C++ | High |
| store | 数据记录存储 | C++ | Medium |
| mxm_message | 消息定义与打包 | C++ | Medium |
| app_lib | 应用侧 SDK 库 | C++ | High |
| ulog | 日志模块 | C++ | Low |
| ptracer | 性能追踪 | C++ | Low |

### 核心数据流

```
Local Process → Unix Domain Socket → IPC Server → IPC Handler → UBSE Adapter
                                                    ↓
                                              SHM Manager / MLS Manager

Remote Node → TCP (TLS) → RPC Server → RPC Handler → DLock / ZenDiscovery
```

## 模块风险评估

### Critical 级别模块

#### 1. mxm_shm (IPC Handler)

**文件**: `src/mxm_shm/ipc_handler.cpp` (1407 行)

**关键入口点**：
- `ShmCreate`: 创建共享内存，接收 name/size/regionDesc 参数
- `ShmMap`: 映射共享内存，接收 name/size/prot 参数
- `ShmDelete`: 删除共享内存
- `ShmWriteLock/ShmReadLock`: 分布式锁请求

**风险分析**：
- 直接处理 IPC 请求中的用户数据
- 参数传递到底层 UBSE API
- 包含权限检查逻辑但依赖外部验证

#### 2. communication (通信引擎)

**文件**: `src/communication/adapter/mxm_com_engine.cpp` (1179 行)

**关键功能**：
- 创建 IPC/RPC 通道
- 网络连接管理
- 消息分发处理

**风险分析**：
- 网络输入入口点
- 消息解析可能存在缓冲区问题
- 使用 memcpy_s 安全函数但仍需验证

#### 3. under_api (UBSE Adapter)

**文件**: `src/under_api/ubse/ubse_mem_adapter.cpp` (1808 行)

**关键功能**：
- dlopen 加载外部库 `/usr/lib64/libubse-client.so.1`
- 封装 UBSE API 调用
- 内存分配/释放操作

**风险分析**：
- 动态库加载风险（路径硬编码）
- 底层内存操作（malloc/free/memcpy）
- 使用 strcpy_s/memcpy_s 安全函数

### High 级别模块

#### 4. dlock_utils (分布式锁)

**文件**: `src/dlock_utils/ubsm_lock.cpp` (1131 行)

**关键功能**：
- 分布式锁初始化
- Lock/Unlock 操作
- TLS 配置加载

**风险分析**：
- 网络通信（RPC）
- 动态库加载（libdlock）
- IPv6 EID 解析（inet_pton）

#### 5. zen_discovery (节点发现)

**文件**: `src/zen_discovery/zen_discovery.cpp` (900 行)

**关键功能**：
- 节点 Ping/Join 请求处理
- 选举逻辑
- 多线程并发处理

**风险分析**：
- RPC 入口点
- 并发状态管理
- 网络消息处理

#### 6. security (加密处理)

**文件**: `src/security/cryptor/ubs_cryptor_handler.cpp` (254 行)

**关键功能**：
- dlopen 加载解密库 `/usr/local/ubs_mem/lib/libdecrypt.so`
- 文件读取解密
- 密钥处理

**风险分析**：
- 动态库加载（检查软链接）
- 文件路径验证
- 内存敏感数据处理

#### 7. process (守护进程)

**文件**: `src/process/daemon/ock_daemon.cpp` (775 行)

**关键功能**：
- 服务初始化
- 配置加载
- TLS 证书路径配置

**风险分析**：
- 配置文件解析
- 文件路径验证
- 服务生命周期管理

## 攻击面分析

### IPC 入口点 (Unix Domain Socket)

| 入口函数 | 文件 | 行号 | 数据来源 | 处理逻辑 |
|----------|------|------|----------|----------|
| ShmCreate | ipc_handler.cpp | 118 | IPC Request | 创建共享内存 |
| ShmMap | ipc_handler.cpp | 584 | IPC Request | 映射共享内存 |
| ShmDelete | ipc_handler.cpp | 308 | IPC Request | 删除共享内存 |
| AppMallocMemory | ipc_handler.cpp | 169 | IPC Request | 借用内存 |

**攻击者可达性**：本地进程通过 Unix Domain Socket 发送请求，socket 权限由管理员配置。

**数据可控性**：请求中的 name、size、prot、regionDesc 等参数由调用进程控制。

### RPC 入口点 (TCP Network)

| 入口函数 | 文件 | 行号 | 数据来源 | 保护措施 |
|----------|------|------|----------|----------|
| HandleMemLock | rpc_handler.cpp | 73 | RPC Request | TLS 认证 |
| PingRequestInfo | rpc_handler.cpp | 120 | RPC Request | TLS 认证 |
| JoinRequestInfo | rpc_handler.cpp | 151 | RPC Request | TLS 认证 |

**攻击者可达性**：远程节点通过 TCP 连接，需 TLS 证书认证。

**数据可控性**：请求中的 memName、isExclusive、nodeId 由远程节点控制。

### 文件/配置入口点

| 入口函数 | 文件 | 路径 | 来源 | 验证措施 |
|----------|------|------|------|----------|
| LoadDecryptFunction | ubs_cryptor_handler.cpp | /usr/local/ubs_mem/lib/libdecrypt.so | 管理员安装 | 软链接检查 |
| Initialize | ubse_mem_adapter.cpp | /usr/lib64/libubse-client.so.1 | 系统安装 | 系统路径 |
| LoadDaemonConf | ock_daemon.cpp | /opt/ubs_mem/config/ubsmd.conf | 管理员配置 | 路径验证 |

### 动态库加载风险

项目多处使用 dlopen 加载外部动态库：

| 加载位置 | 库路径 | 安全措施 |
|----------|--------|----------|
| ubse_mem_adapter.cpp | /usr/lib64/libubse-client.so.1 | 系统路径，无软链接检查 |
| ubs_cryptor_handler.cpp | /usr/local/ubs_mem/lib/libdecrypt.so | 软链接检查、普通文件验证 |
| ubsm_lock.cpp | libdlock (动态路径) | 配置文件指定 |
| openssl_dl.cpp | libcrypto/libssl | 系统库 |

## STRIDE 威胁建模

### Spoofing (身份伪造)

| 威胁场景 | 风险 | 缓解措施 |
|----------|------|----------|
| 本地进程伪造其他用户身份 | Medium | IPC 请求携带 pid/uid/gid，由 kernel 保证 |
| 远程节点伪造身份 | Low | TLS 证书双向认证 |
| 动态库替换攻击 | Medium | 软链接检查、路径验证 |

### Tampering (数据篡改)

| 威胁场景 | 风险 | 缓解措施 |
|----------|------|----------|
| IPC 请求参数篡改 | High | 请求通过 UDS，kernel 保证完整性 |
| RPC 消息篡改 | Low | TLS 加密传输 |
| 配置文件篡改 | Low | 管理员权限保护 |
| 共享内存数据篡改 | Medium | 权限检查、分布式锁 |

### Repudiation (操作抵赖)

| 威胁场景 | 风险 | 缓解措施 |
|----------|------|----------|
| 用户否认内存操作 | Medium | 审计日志记录（DBG_AUDITINFO） |
| 远程节点否认操作 | Medium | TLS 认证日志 |

### Information Disclosure (信息泄露)

| 威胁场景 | 风险 | 缓解措施 |
|----------|------|----------|
| 共享内存内容泄露 | High | 权限检查、用户隔离 |
| TLS 密钥泄露 | High | 密钥文件权限、密钥解密后清零 |
| 日志信息泄露 | Medium | 日志级别控制 |

### Denial of Service (拒绝服务)

| 威胁场景 | 风险 | 缓解措施 |
|----------|------|----------|
| IPC 连接耗尽 | Medium | 最大连接数配置 |
| 内存资源耗尽 | Medium | 内存借用缓存管理 |
| 分布式锁死锁 | Medium | 锁超时配置 |

### Elevation of Privilege (权限提升)

| 威胁场景 | 风险 | 缓解措施 |
|----------|------|----------|
| 通过 IPC 获取其他用户内存访问权 | High | uid/gid 权限检查 |
| 通过 RPC 控制其他节点的锁 | Medium | TLS 认证、锁所有权验证 |
| 动态库注入提升权限 | High | 库路径验证、软链接检查 |

## 安全加固建议

### 架构层面建议

1. **IPC 权限验证强化**
   - 确保 IPC 请求中的 pid/uid/gid 验证完整性
   - 考虑添加额外的 capability 检查
   - 对敏感操作（删除/权限变更）加强审计

2. **动态库安全加固**
   - 对所有 dlopen 调用添加软链接检查
   - 使用绝对路径并验证文件签名
   - 考虑使用 SELinux/AppArmor 约束库加载路径

3. **内存操作安全**
   - 确认所有内存操作使用安全函数（memcpy_s/strcpy_s）
   - 添加边界检查冗余验证
   - 对 size 参数添加合理范围检查

4. **RPC 认证强化**
   - 确保 TLS 配置正确启用
   - 证书过期检测机制已存在（ubs_certify_handler）
   - 考虑添加 IP 白名单限制

5. **并发安全**
   - 审查多线程并发访问的锁机制
   - 检查 zen_discovery 选举逻辑的状态一致性
   - 确保共享内存操作的原子性

### 代码层面建议

1. **输入验证**
   - 对 IPC/RPC 请求中的 name/size 等参数添加格式验证
   - 添加数值范围检查（如 size 不能为负、regionDesc.num 不能超限）

2. **错误处理**
   - 确保所有错误路径都有正确的资源释放
   - 避免在错误路径中泄露敏感信息

3. **日志安全**
   - 确保日志不包含敏感数据（密钥、内存内容）
   - 控制审计日志的访问权限

## 分析完成确认

=== 架构分析结果 ===

## 项目概览
- 项目名称: ubs-mem
- 语言组成: C/C++ 194 文件
- 源文件数: 194
- 主要功能: 提供超节点内存借用、共享、缓存服务能力

## 高风险文件列表（按优先级排序）

| 优先级 | 文件路径 | 风险等级 | 模块类型 |
|--------|----------|----------|----------|
| 1 | src/mxm_shm/ipc_handler.cpp | Critical | IPC请求处理 |
| 2 | src/under_api/ubse/ubse_mem_adapter.cpp | Critical | 底层API |
| 3 | src/communication/adapter/mxm_com_engine.cpp | Critical | 通信引擎 |
| 4 | src/dlock_utils/ubsm_lock.cpp | High | 分布式锁 |
| 5 | src/app_lib/mxm_shm_lib/mxmem_shmem.cpp | High | 共享内存SDK |
| 6 | src/store/record_store.cpp | High | 数据存储 |
| 7 | src/zen_discovery/zen_discovery.cpp | High | 节点发现 |
| 8 | src/process/daemon/ock_daemon.cpp | High | 守护进程 |

## 入口点列表（外部输入位置）

| 文件 | 行号 | 函数 | 入口类型 | 信任等级 | 理由 | 说明 |
|------|------|------|----------|----------|------|------|
| src/mxm_shm/ipc_handler.cpp | 118 | ShmCreate | ipc | semi_trusted | UDS接口，本地进程请求创建共享内存 | IPC入口 |
| src/mxm_shm/ipc_handler.cpp | 584 | ShmMap | ipc | semi_trusted | UDS接口，本地进程请求映射共享内存 | IPC入口 |
| src/mxm_shm/rpc_handler.cpp | 73 | HandleMemLock | rpc | semi_trusted | RPC接口，远程节点请求分布式锁 | RPC入口 |
| src/under_api/ubse/ubse_mem_adapter.cpp | 62 | Initialize | file | trusted_admin | dlopen加载UBSE库，路径硬编码 | 动态库加载 |
| src/security/cryptor/ubs_cryptor_handler.cpp | 226 | LoadDecryptFunction | file | trusted_admin | dlopen加载解密库 | 动态库加载 |

## 跨文件调用关系（关键）

| 调用方文件 | 调用方函数 | 被调用文件 | 被调用函数 | 数据传递 |
|------------|------------|------------|------------|----------|
| ipc_handler.cpp | ShmCreate | ubse_mem_adapter.cpp | ShmCreate | name/size/regionDesc |
| ipc_handler.cpp | ShmMap | ubse_mem_adapter.cpp | ShmAttach | name/prot |
| rpc_handler.cpp | HandleMemLock | ubsm_lock.cpp | Lock | memName/isExclusive |

## 模块风险评估

| 模块 | 文件 | STRIDE 威胁 | 风险等级 |
|------|------|-------------|----------|
| IPC处理 | ipc_handler.cpp | S,T,I,E | Critical |
| 底层API | ubse_mem_adapter.cpp | T,E | Critical |
| 通信引擎 | mxm_com_engine.cpp | T,D | Critical |
| 分布式锁 | ubsm_lock.cpp | S,T,D | High |

=== 分析结束 ===