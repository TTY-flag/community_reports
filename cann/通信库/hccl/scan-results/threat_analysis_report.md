# HCCL 威胁分析报告

## 项目概述

HCCL (Huawei Collective Communication Library) 是华为基于昇腾AI处理器的高性能集合通信库，为计算集群提供集合通信和点对点通信能力。

- **项目类型**: 通信库 (Library)
- **主要语言**: C++ (689个文件), Python (27个文件)
- **核心功能**: 集合通信原语 (AllReduce, Broadcast, AllGather, ReduceScatter等)

---

## 一、攻击面识别

### 1.1 公开API入口点

HCCL提供14个公开API作为主要入口点，这些接口直接接收用户输入：

| API | 文件位置 | 风险级别 | 主要参数 |
|-----|---------|---------|---------|
| HcclAllReduce | include/hccl.h:35 | 高 | sendBuf, recvBuf, count |
| HcclAllGatherV | include/hccl.h:134 | 高 | sendBuf, recvBuf, recvCounts, recvDispls |
| HcclAlltoAllV | include/hccl.h:202 | 高 | sendBuf, recvBuf, sendCounts, recvCounts, sdispls, rdispls |
| HcclAlltoAllVC | include/hccl.h:180 | 高 | sendBuf, sendCountMatrix |
| HcclReduceScatterV | include/hccl.h:85 | 高 | sendBuf, sendCounts, sendDispls |
| HcclSend | include/hccl.h:149 | 高 | sendBuf, count, destRank |
| HcclRecv | include/hccl.h:163 | 高 | recvBuf, count, srcRank |
| HcclBatchSendRecv | include/hccl.h:249 | 高 | sendRecvInfo, itemNum |

### 1.2 环境变量配置入口

系统通过以下环境变量控制通信行为：

| 环境变量 | 用途 | 风险级别 |
|---------|-----|---------|
| HCCL_OP_EXPANSION_MODE | 算子展开模式 | 中 |
| HCCL_INTRA_PCIE_ENABLE/HCCL_INTRA_ROCE_ENABLE | 通信协议选择 | 中 |
| HCCL_INTER_HCCS_DISABLE | HCCS禁用开关 | 中 |
| HCCL_ALGO | 算法配置 | 中 |
| ASCEND_HOME_PATH | CANN安装路径 | 高 |

### 1.3 动态库加载入口

- `HcommDlInit` 使用 `dlopen("libhcomm.so")` 加载通信基础库
- `GetAivOpBinaryPath` 根据 `ASCEND_HOME_PATH` 加载kernel二进制文件

### 1.4 序列化数据入口

- `AlgResourceCtxSerializable::DeSerialize` 从序列化数据恢复上下文
- `BinaryStream::operator>>` 从二进制流读取数据

---

## 二、高风险模块分析

### 2.1 变长参数处理模块 (风险级别: 高)

**涉及模块**: all_gather_v, all_to_all_v, reduce_scatter_v

**关键代码位置**:
- `src/ops/all_gather_v/all_gather_v_op.cc:140-217` (AllGatherVOutPlace)
- `src/ops/op_common/template/aicpu/kernel_launch.cc:516-584` (RestoreVarData*)

**风险因素**:
1. `recvCounts`/`recvDispls` 数组由用户传入，直接影响缓冲区偏移计算
2. 缓冲区大小计算: `outputSize = sum(recvCounts[i] * perDataSize)`
3. 缺少数组元素值的有效性校验
4. 可能导致整数溢出或缓冲区越界

**示例代码分析** (all_gather_v_op.cc:149-152):
```cpp
const u64 *u64RecvCount = reinterpret_cast<const u64 *>(recvCounts);
for (u64 i = 0; i < userRankSize; i++) {
    outputSize += u64RecvCount[i] * perDataSize;  // 未校验每个元素的有效性
}
```

**潜在漏洞类型**:
- CWE-129: 数组索引不当验证
- CWE-190: 整数溢出或环绕
- CWE-787: 越界写入

### 2.2 跨节点数据传输模块 (风险级别: 高)

**涉及模块**: send, recv, batch_send_recv

**关键代码位置**:
- `src/ops/send/send_op.cc:23-58` (HcclSend)
- `src/ops/batch_send_recv/batch_send_recv_op.cc:23-69` (HcclBatchSendRecv)

**风险因素**:
1. `destRank`/`srcRank` 由用户传入，控制数据传输目标
2. 跨节点通信可能被中间人攻击篡改数据
3. 缓冲区大小由 `count` 参数决定，可能导致内存操作问题
4. `BatchSendRecv` 接收 `HcclSendRecvItem` 数组，每个元素包含完整的通信参数

**潜在漏洞类型**:
- CWE-20: 输入验证不当
- CWE-311: 缺少加密敏感数据
- CWE-787: 越界写入

### 2.3 动态库加载模块 (风险级别: 高)

**关键代码位置**:
- `src/common/hcomm_dlsym/hcomm_dlsym.cc:57-74` (HcommDlInit)

**风险因素**:
```cpp
gLibHandle = dlopen("libhcomm.so", RTLD_NOW);  // 硬编码库名
```

1. 使用硬编码库名，依赖系统库搜索路径
2. 环境变量 `LD_LIBRARY_PATH` 可被篡改
3. 同名恶意库可能被加载
4. 符号劫持风险

**潜在漏洞类型**:
- CWE-426: 不受信任的搜索路径
- CWE-427: 不受信任的搜索路径控制

### 2.4 Kernel二进制加载模块 (风险级别: 高)

**关键代码位置**:
- `src/ops/op_common/template/aiv/hccl_aiv_utils.cc:140-158` (GetAivOpBinaryPath)

**风险因素**:
```cpp
char *getPath = nullptr;
MM_SYS_GET_ENV(MM_ENV_ASCEND_HOME_PATH, getPath);
if (getPath != nullptr) {
    libPath = getPath;
} else {
    libPath = "/usr/local/Ascend/cann";  // 默认路径
}
binaryPath = libPath + "/lib64" + "/" + aivBinaryName;
```

1. 二进制路径由 `ASCEND_HOME_PATH` 环境变量控制
2. 用户可配置任意路径
3. 恶意二进制文件可被加载并执行
4. 二进制文件可能包含注入代码

**潜在漏洞类型**:
- CWE-426: 不受信任的搜索路径
- CWE-494: 从不受信任位置下载代码

### 2.5 序列化/反序列化模块 (风险级别: 中)

**关键代码位置**:
- `src/common/binary_stream.h:64-91` (BinaryStream operators)
- `src/ops/op_common/inc/alg_param.h:413-439` (AlgResourceCtxSerializable::DeSerialize)

**风险因素**:
1. 序列化数据在Host-Device边界传递
2. 反序列化缺少边界检查
3. 数组大小从流中读取后直接使用 `resize()`
4. 数据可能被篡改

**潜在漏洞类型**:
- CWE-502: 不受信任数据的反序列化
- CWE-129: 数组索引不当验证

---

## 三、数据流分析

### 3.1 关键数据流路径

#### 路径1: AllGatherV 变长参数流
```
HcclAllGatherV(recvCounts, recvDispls) 
    -> CheckAllGatherVInputPara(指针校验)
    -> AllGatherVOutPlace(缓冲区大小计算) 
    -> memcpy_s(数组复制) 
    -> HcclExecOp 
    -> RestoreVarDataAllGatherV(指针恢复)
```

**污点源**: recvCounts, recvDispls (外部数组)
**污点汇**: 缓冲区偏移计算, 内存访问

#### 路径2: Send/Recv 跨节点通信流
```
HcclSend(sendBuf, count, destRank) 
    -> GetAndCheckSendPara(rank校验) 
    -> GenerateSendOpParam(OpParam构建) 
    -> HcclExecOp 
    -> 网络传输 -> destRank节点
```

**污点源**: sendBuf, destRank (外部输入)
**污点汇**: 网络传输, 远程节点数据写入

#### 路径3: BatchSendRecv 批量通信流
```
HcclBatchSendRecv(sendRecvInfo[], itemNum) 
    -> CheckBatchSendRecvInputPara(指针校验)
    -> BatchSendRecvOutPlace(数组复制) 
    -> memcpy_s 
    -> HcclExecOp 
    -> RestoreVarDataBatchSendRecv
```

**污点源**: sendRecvInfo数组结构
**污点汇**: 批量网络通信

#### 路径4: 环境变量配置流
```
MM_SYS_GET_ENV(env_id) 
    -> GetEnv(env_value) 
    -> ParseOpExpansion/ParseHcclAlgo/ParseIntraLinkType(解析) 
    -> 配置标志设置
```

**污点源**: 系统环境变量
**污点汇**: 通信模式, 协议选择

#### 路径5: 二进制文件加载流
```
MM_SYS_GET_ENV(ASCEND_HOME_PATH) 
    -> GetAivOpBinaryPath(binary_path) 
    -> LoadBinaryFromFile(file_read) 
    -> aclrtLaunchKernelWithHostArgs(kernel执行)
```

**污点源**: ASCEND_HOME_PATH环境变量
**污点汇**: Kernel代码加载执行

---

## 四、潜在漏洞类型汇总

| CWE ID | 漏洞类型 | 涉及模块 | 发现位置 |
|--------|---------|---------|---------|
| CWE-129 | 数组索引不当验证 | all_gather_v, all_to_all_v, reduce_scatter_v | recvCounts/recvDispls处理 |
| CWE-190 | 整数溢出或环绕 | all_gather_v | outputSize累加计算 |
| CWE-20 | 输入验证不当 | send, recv, batch_send_recv | destRank/srcRank参数 |
| CWE-787 | 越界写入 | 变长参数模块 | 基于外部偏移的内存访问 |
| CWE-426 | 不受信任的搜索路径 | hcomm_dlsym, aiv_utils | dlopen, 二进制加载 |
| CWE-502 | 不受信任数据的反序列化 | binary_stream, kernel_launch | AlgResourceCtx反序列化 |
| CWE-311 | 缺少加密敏感数据 | send, recv | 跨节点数据传输 |

---

## 五、高风险文件清单

### 5.1 需重点关注文件 (风险级别: 高)

| 文件 | 风险描述 | 潜在漏洞 |
|-----|---------|---------|
| src/ops/all_gather_v/all_gather_v_op.cc | 变长参数处理，缓冲区计算 | CWE-129, CWE-190, CWE-787 |
| src/ops/all_to_all_v/* | 复杂变长参数处理 | CWE-129, CWE-190, CWE-787 |
| src/ops/reduce_scatter_v/* | 变长参数处理 | CWE-129, CWE-190, CWE-787 |
| src/ops/send/send_op.cc | 跨节点数据发送 | CWE-20, CWE-311 |
| src/ops/recv/* | 跨节点数据接收 | CWE-20, CWE-787 |
| src/ops/batch_send_recv/batch_send_recv_op.cc | 批量通信参数处理 | CWE-20, CWE-129 |
| src/common/hcomm_dlsym/hcomm_dlsym.cc | 动态库加载 | CWE-426 |
| src/ops/op_common/template/aiv/hccl_aiv_utils.cc | Kernel二进制加载 | CWE-426, CWE-494 |
| src/ops/op_common/template/aicpu/kernel_launch.cc | 参数恢复, 反序列化 | CWE-502, CWE-129 |
| src/common/binary_stream.h | 序列化操作 | CWE-502 |

### 5.2 需一般关注文件 (风险级别: 中)

| 文件 | 风险描述 |
|-----|---------|
| src/common/alg_env_config.cc | 环境变量解析 |
| src/common/param_check.cc | 参数校验逻辑 |
| src/ops/op_common/executor/channel/channel.cc | 通信链路建立 |
| src/ops/op_common/op_common.cc | 执行流程编排 |

---

## 六、攻击场景分析

### 6.1 场景1: 变长参数缓冲区攻击

**攻击方式**:
1. 用户调用 `HcclAllGatherV`，传入恶意构造的 `recvCounts` 数组
2. 数组包含超大值，导致 `outputSize` 累加溢出
3. 或数组包含负值（转换为正整数），导致偏移计算错误
4. 最终导致缓冲区越界访问或内存破坏

**影响**: 内存破坏, 信息泄露, 服务崩溃

### 6.2 场景2: 恶意二进制注入

**攻击方式**:
1. 攻击者设置 `ASCEND_HOME_PATH=/tmp/malicious_path`
2. 在该路径下放置篡改的kernel二进制文件
3. HCCL加载并执行恶意kernel代码
4. 恶意代码可执行任意操作

**影响**: 代码执行, 数据窃取, 系统入侵

### 6.3 场景3: 动态库劫持

**攻击方式**:
1. 攻击者设置 `LD_LIBRARY_PATH=/tmp/malicious_libs`
2. 在该路径放置恶意 `libhcomm.so`
3. HCCL通过 `dlopen` 加载恶意库
4. 恶意库可劫持所有通信函数

**影响**: 代码执行, 数据篡改, 通信劫持

### 6.4 场景4: 跨节点通信篡改

**攻击方式**:
1. 攻击者在网络中间节点位置
2. 窃听或篡改跨节点通信数据
3. 修改传输中的通信参数或数据内容
4. 导致计算结果错误或信息泄露

**影响**: 数据篡改, 信息泄露

### 6.5 场景5: 批量通信参数注入

**攻击方式**:
1. 用户调用 `HcclBatchSendRecv`，传入恶意 `sendRecvInfo` 数组
2. 数组项包含恶意 `destRank`, `srcRank`, `count` 参数
3. 导致数据发送到错误节点或错误大小的数据传输
4. 可能导致内存操作错误

**影响**: 内存破坏, 数据泄露, 服务崩溃

---

## 七、安全建议

### 7.1 变长参数处理改进

1. **添加数组元素有效性校验**: 
   - 校验每个 `recvCounts[i]` 是否在合理范围内
   - 校验 `recvDispls[i]` 不会导致缓冲区越界

2. **添加整数溢出检测**:
   - 在累加计算前检查是否会溢出
   - 使用安全的整数运算函数

3. **添加边界检查**:
   - 校验数组长度与 `rankSize` 匹配
   - 校验偏移值不超过缓冲区大小

### 7.2 动态加载安全改进

1. **使用绝对路径加载库**:
   - 不依赖系统搜索路径
   - 使用可信路径配置

2. **添加签名校验**:
   - 对加载的二进制文件进行签名验证
   - 检查文件完整性

3. **限制环境变量影响**:
   - 不使用 `LD_LIBRARY_PATH`
   - 使用内部配置而非环境变量控制路径

### 7.3 通信安全改进

1. **添加数据校验**:
   - 对传输数据进行完整性校验
   - 添加序列号或校验码

2. **添加加密传输**:
   - 对敏感数据加密传输
   - 使用安全通信协议

### 7.4 序列化安全改进

1. **添加数据校验**:
   - 校验序列化数据的长度有效性
   - 校验结构体字段的有效性

2. **添加边界检查**:
   - 检查数组resize前的数据大小
   - 防止恶意数据导致过大内存分配

---

## 八、总结

HCCL作为高性能集合通信库，其核心功能涉及跨节点数据传输和复杂参数处理。通过分析，识别出以下关键风险领域：

1. **变长参数处理**: AllGatherV/AlltoAllV/ReduceScatterV等算子接收外部数组参数，直接影响内存访问
2. **动态库加载**: 使用dlopen加载外部库，存在搜索路径劫持风险
3. **二进制文件加载**: Kernel二进制路径由环境变量控制，存在代码注入风险
4. **跨节点通信**: 数据通过网络传输，存在篡改和窃听风险

建议在进行安全扫描时，重点关注上述高风险文件和数据流路径，特别是涉及外部输入处理和内存操作的代码段。