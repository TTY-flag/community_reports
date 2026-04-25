# torch_npu 威胁分析报告

## 项目概览

| 属性 | 值 |
|------|-----|
| 项目名称 | torch_npu (华为 PyTorch NPU 扩展) |
| 语言组成 | C++ (353文件) + Python (331文件) |
| 主要功能 | NPU 设备支持、分布式训练、性能分析、IPC 通信 |
| 分析日期 | 2026-04-23 |

## 模块划分

torch_npu 项目采用分层架构，主要模块如下：

### 1. 分布式通信模块 (distributed/) - **最高风险**
- **C++ 实现**: `torch_npu/csrc/distributed/`
- **Python 绑定**: `torch_npu/distributed/`
- **功能**: HCCL/LCCL 进程组、TCP Store、RPC Agent
- **风险等级**: Priority 9 (Critical)

### 2. IPC 通信模块 (ipc/) - **高风险**
- **路径**: `torch_npu/csrc/ipc/`
- **功能**: NPU 跨进程内存共享
- **风险等级**: Priority 9 (Critical)

### 3. 核心模块 (core/) - **中高风险**
- **路径**: `torch_npu/csrc/core/`
- **功能**: 内存管理、设备管理、动态库加载、序列化
- **风险等级**: Priority 7-8

### 4. 框架层 (framework/) - **中风险**
- **路径**: `torch_npu/csrc/framework/`
- **功能**: 操作命令处理、格式转换、环境变量配置
- **风险等级**: Priority 6

### 5. 性能分析器 (profiler/, toolkit/profiler/) - **中高风险**
- **路径**: `torch_npu/csrc/profiler/`, `torch_npu/csrc/toolkit/profiler/`
- **功能**: 性能追踪、数据导出
- **风险等级**: Priority 6-7

### 6. ATen 操作 (aten/) - **中风险**
- **路径**: `torch_npu/csrc/aten/`
- **功能**: NPU 原生函数、自定义操作
- **风险等级**: Priority 5

---

## 攻击面分析

### 攻击面 1: 网络通信 (Critical)

#### 概述
分布式训练使用 TCP Socket 和 Unix Domain Socket 进行进程间通信。网络接口是主要的攻击入口，特别是在多节点训练场景中。

#### 涉及文件
| 文件 | 优先级 | 关键函数 |
|------|--------|----------|
| `ParallelTcpServer.cpp` | 9 | `CreateSocket`, `CreateLocalSocket`, `ProcessListenEvent`, `accept` |
| `ParallelTcpStore.cpp` | 8 | `ParallelTcpStore` 构造函数 |
| `StoreClient.cpp` | 8 | `TryConnect`, `LocalConnect`, `SyncCall` |
| `ProcessGroupHCCL.cpp` | 9 | `broadcastMasterID`, HCCL 初始化 |
| `tensorpipe_agent.cpp` | 8 | `send`, `pipeRead`, `pipeWrite` |

#### 协议栈
- **TCP (IPv4/IPv6)**: 用于跨节点分布式训练通信
- **Unix Domain Socket**: 用于本地节点内进程通信
- **HCCL**: 华昇集群通信库协议
- **TensorPipe**: RPC 传输层

#### 潜在攻击向量
1. **中间人攻击 (MITM)**: 分布式训练中的网络通信可能被截获和篡改
2. **连接劫持**: 恶意进程可能伪造 HCCL Master ID 或 Store 连接
3. **消息篡改**: `StoreMessagePacker::Unpack` 解析网络消息时可能存在解析漏洞
4. **拒绝服务 (DoS)**: 大量连接请求可能耗尽服务器资源

#### 安全观察
```cpp
// ParallelTcpServer.cpp:305 - strncpy 使用存在潜在风险
strncpy(servAddr.sun_path + 1, localSocketPath.c_str(), sizeof(servAddr.sun_path) - 2);
// 未验证路径长度，可能导致截断

// StoreClient.cpp:93 - getaddrinfo 使用
int r = ::getaddrinfo(host_.c_str(), std::to_string(port_).c_str(), &hints, &result);
// 主机名由用户提供，可能被恶意控制
```

### 攻击面 2: IPC 共享内存 (Critical)

#### 概述
IPC 机制通过共享内存传递 NPU Tensor，涉及引用计数文件和 IPC 事件句柄。恶意进程可能访问或篡改共享数据。

#### 涉及文件
| 文件 | 优先级 | 关键函数 |
|------|--------|----------|
| `StorageSharing.cpp` | 9 | `THNPStorage_shareNpu`, `THNPStorage_newSharedNpu`, `THNPStorage_releaseIPCCounter` |
| `NPUIPCTypes.cpp` | 8 | IPC 类型定义 |

#### IPC 数据流
1. **发送端**: `THNPStorage_shareNpu` 序列化 NPU Tensor 为 IPC Handle
2. **接收端**: `THNPStorage_newSharedNpu` 从 IPC Handle 恢复 Tensor
3. **引用管理**: `THNPStorage_releaseIPCCounter` 通过共享内存文件管理引用计数

#### 潏在攻击向量
1. **内存泄露**: IPC Handle 序列化可能泄露 NPU 设备内存信息
2. **内存篡改**: 共享内存区域可能被恶意进程访问和修改
3. **引用计数篡改**: 引用计数文件 (`/dev/shm` 或类似位置) 可能被恶意修改
4. **IPC Handle 伪造**: 恶意进程可能伪造 IPC Handle 导致内存访问异常

#### 安全观察
```cpp
// StorageSharing.cpp:132 - 直接从 Python bytes 获取字符串作为文件路径
std::string ref_counter_handle = PyBytes_AS_STRING(_ref_counter);
// 路径未经过验证，可能指向任意位置

// StorageSharing.cpp:220 - 从 IPC Handle 获取设备指针
std::shared_ptr<void> basePtr = c10_npu::NPUCachingAllocator::getIpcDevPtr(s_handle);
// IPC Handle 来自网络传输，可能被篡改
```

### 攻击面 3: 文件操作 (High)

#### 概述
性能分析器将数据写入文件系统，路径可能受用户控制或环境变量影响。

#### 涉及文件
| 文件 | 优先级 | 关键函数 |
|------|--------|----------|
| `data_dumper.cpp` | 7 | `Dump`, `GatherAndDumpData`, `CreateDir` |
| `ProcessGroupHCCL.cpp` | 9 | `DumpPipe` 构造函数 (`mkfifo`, `unlink`) |

#### 文件操作类型
- **文件创建**: `Utils::CreateFile`, `fopen`
- **目录创建**: `Utils::CreateDir`
- **数据写入**: `fwrite`
- **命名管道**: `mkfifo`

#### 潜在攻击向量
1. **路径遍历**: 文件路径拼接可能允许写入任意位置
2. **符号链接攻击**: 文件操作前未检查符号链接
3. **权限问题**: 创建的文件可能具有不安全的权限

#### 安全观察
```cpp
// data_dumper.cpp:124 - 路径拼接
const std::string dump_file = path_ + "/" + data.first;
// path_ 来自初始化参数，data.first 来自数据标签，可能被控制

// ProcessGroupHCCL.hpp:154 - mkfifo 创建命名管道
TORCH_CHECK(mkfifo(filename.c_str(), 0666) != -1, "Error creating named pipe ", filename);
// 权限 0666 允许任意用户读写
```

### 攻击面 4: 动态库加载 (High)

#### 概述
动态库加载机制使用 `dlopen` 加载共享库，库名称可能受配置影响。

#### 涉及文件
| 文件 | 优先级 | 关键函数 |
|------|--------|----------|
| `FunctionLoader.cpp` | 8 | `Get` (`dlopen`, `dlsym`) |

#### 加载机制
```cpp
// FunctionLoader.cpp:28
auto handle = dlopen(this->fileName.c_str(), this->flags);
// fileName 由注册时指定: name + ".so"
```

#### 潜在攻击向量
1. **库注入**: 如果库名称可被控制，可能加载恶意库
2. **符号查找**: `dlsym` 查找的函数名可能被篡改
3. **搜索路径**: `dlopen` 使用默认搜索路径，可能加载非预期库

### 攻击面 5: 环境变量 (Medium)

#### 概述
大量环境变量用于配置分布式训练和性能参数。

#### 关键环境变量
| 变量名 | 使用模块 | 风险 |
|--------|----------|------|
| `HCCL_BLOCKING_WAIT` | distributed | 控制等待行为 |
| `MASTER_ADDR` | distributed | 分布式主节点地址 |
| `RANK`, `LOCAL_RANK` | distributed | 进程排名 |
| `HCCL_ALGO` | distributed | HCCL 算法选择 |
| `TORCH_NPU_LOGS_FILTER` | logging | 日志过滤 |
| `ASCEND_HOME_PATH` | framework | CANN 安装路径 |

#### 潜在攻击向量
1. **配置篡改**: 环境变量可被恶意进程修改
2. **地址注入**: `MASTER_ADDR` 可能被设置为恶意地址
3. **路径注入**: `ASCEND_HOME_PATH` 可能指向恶意库

---

## 高风险文件清单

按优先级排序:

| 优先级 | 文件 | 模块 | 主要风险因素 |
|--------|------|------|--------------|
| 9 | `ProcessGroupHCCL.cpp` | distributed | 网络通信、环境变量、文件操作、IPC管理、HCCL通信器管理 |
| 9 | `ParallelTcpServer.cpp` | distributed | TCP服务器、epoll事件处理、socket操作、消息解析 |
| 9 | `StorageSharing.cpp` | ipc | IPC序列化、共享内存管理、引用计数文件操作 |
| 8 | `ParallelTcpStore.cpp` | distributed | TCP Store、存储操作、连接处理 |
| 8 | `StoreClient.cpp` | distributed | TCP客户端、socket连接、消息传输 |
| 8 | `FunctionLoader.cpp` | core | dlopen/dlsym、动态库加载 |
| 8 | `NPUIPCTypes.cpp` | ipc | IPC类型定义、发送数据跟踪 |
| 8 | `tensorpipe_agent.cpp` | distributed | RPC Agent、TensorPipe通信、网络传输 |
| 7 | `reducer.cpp` | distributed | 梯度同步、Tensor分桶、DDP实现 |
| 7 | `HCCLUtils.cpp` | distributed | HCCL工具函数、调试信息写入 |
| 7 | `data_dumper.cpp` | toolkit/profiler | 文件操作、路径拼接、数据导出 |
| 6 | `distributed_c10d.py` | distributed (Python) | ProcessGroup创建、HCCL后端配置 |

---

## CWE 分类映射

| CWE ID | 名称 | 涉及模块 | 示例 |
|--------|------|----------|------|
| CWE-20 | 输入验证不当 | distributed, ipc | 消息解析未验证长度 |
| CWE-78 | OS 命令注入 | - | 无直接OS命令执行 |
| CWE-79 | XSS | - | 无Web界面 |
| CWE-89 | SQL注入 | - | 无数据库操作 |
| CWE-119 | 内存缓冲区边界操作不当 | distributed | strncpy 使用 |
| CWE-125 | 内存越界读取 | ipc | IPC Handle 解析 |
| CWE-134 | 格式字符串问题 | - | 无printf格式化 |
| CWE-200 | 信息泄露 | distributed | IPC Handle 序列化泄露设备信息 |
| CWE-22 | 路径遍历 | toolkit/profiler | 文件路径拼接 |
| CWE-787 | 越界写入 | - | 未发现明显越界写入 |
| CWE-426 | 不可信搜索路径 | core | dlopen 库搜索路径 |
| CWE-74 | 输入注入 | distributed | 网络消息注入 |

---

## 推荐安全扫描重点

### 第一阶段扫描 (最高优先级 - Priority 9)

**模块**: distributed, ipc

**重点文件**:
1. `ProcessGroupHCCL.cpp` - HCCL 通信器管理、网络消息处理
2. `ParallelTcpServer.cpp` - TCP 服务器实现、socket 操作
3. `StorageSharing.cpp` - IPC 共享内存、引用计数文件

**扫描规则**:
- 网络消息解析漏洞 (CWE-20, CWE-119)
- IPC Handle 处理漏洞 (CWE-125, CWE-200)
- 文件路径处理漏洞 (CWE-22)

### 第二阶段扫描 (高优先级 - Priority 8)

**模块**: distributed, core

**重点文件**:
1. `StoreClient.cpp` - TCP 客户端实现
2. `FunctionLoader.cpp` - 动态库加载
3. `tensorpipe_agent.cpp` - RPC Agent 实现

**扫描规则**:
- 库加载安全 (CWE-426)
- 网络连接处理 (CWE-20)

### 第三阶段扫描 (中高优先级 - Priority 7)

**模块**: toolkit/profiler, distributed

**重点文件**:
1. `data_dumper.cpp` - 文件操作
2. `reducer.cpp` - DDP 实现
3. `HCCLUtils.cpp` - HCCL 工具函数

**扫描规则**:
- 文件路径安全 (CWE-22)
- 调试信息处理安全

---

## 安全建议

1. **网络通信安全**:
   - 实现 TCP 连接认证机制
   - 对 StoreMessage 进行完整性验证
   - 考虑加密分布式通信

2. **IPC 安全**:
   - 验证 IPC Handle 来源
   - 使用安全权限创建引用计数文件
   - 实现 IPC 访问控制

3. **文件操作安全**:
   - 验证文件路径合法性
   - 使用安全权限创建文件
   - 检查符号链接

4. **库加载安全**:
   - 使用绝对路径加载库
   - 验证库签名
   - 实现库白名单机制

5. **环境变量安全**:
   - 验证关键环境变量格式
   - 实现配置安全检查
   - 考虑使用配置文件替代环境变量

---

## 附录: 分析元数据

| 属性 | 值 |
|------|-----|
| 分析器 | architecture_analysis_agent |
| 分析日期 | 2026-04-23 |
| 版本 | 1.0 |
| C++ 文件数 | 353 |
| Python 文件数 | 331 |
| 高风险文件数 | 12 |
| 模块数 | 11 |
| 攻击面数 | 5 |