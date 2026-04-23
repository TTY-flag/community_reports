# VULN-DF-CPP-msprobe_ccsrc-004：DumpOpDebugDataToDisk固定偏移量致越界读取

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-DF-CPP-msprobe_ccsrc-004 |
| **漏洞类型** | Out-of-Bounds Read (CWE-125) |
| **位置** | `debug/accuracy_tools/msprobe/ccsrc/core/AclDumpDataProcessor.cpp:452-471` |
| **严重性** | High |
| **置信度** | 80 → **确认真实漏洞** |
| **影响函数** | `DumpOpDebugDataToDisk()` 和 `ParseOverflowInfo()` |

**漏洞描述**: 函数 `DumpOpDebugDataToDisk()` 使用固定偏移量常量读取数据缓冲区，但从未验证 `dataLen` 参数是否足够包含所需的数据结构。恶意或损坏的数据可能导致越界内存读取。

---

## 技术分析

### 代码上下文

**漏洞函数签名**:
```cpp
static DebuggerErrno DumpOpDebugDataToDisk(const std::string& dumpPath, AclDumpMsg::DumpData& dumpData,
                                           const uint8_t* data, size_t dataLen)
```

**问题代码片段 (L452-471)**:
```cpp
// 函数接收 dataLen 参数但从未使用
uint32_t num = static_cast<uint32_t>(dumpData.output().size());
for (uint32_t slot = 0; slot < num; slot++) {
    uint32_t offset = 0;
    // ❌ 无边界检查：直接从 offset=0 读取 128 字节结构
    nlohmann::json dhaAtomicAddInfo = ParseOverflowInfo(data + offset);  // L452
    offset += DHA_ATOMIC_ADD_INFO_SIZE;                                   // L453: += 128
    
    // ❌ 继续累积偏移量，无任何验证
    nlohmann::json l2AtomicAddInfo = ParseOverflowInfo(data + offset);   // L455
    offset += L2_ATOMIC_ADD_INFO_SIZE;                                    // L456: += 128
    
    nlohmann::json aiCoreInfo = ParseOverflowInfo(data + offset);         // L458
    offset += AICORE_INFO_SIZE;                                           // L459: += 256
    
    // ❌ 继续无验证读取
    dhaAtomicAddInfo["status"] = DataUtils::UnpackUint64ValueLe(data + offset);  // L461
    offset += DHA_ATOMIC_ADD_STATUS_SIZE;                                        // L462: += 256
    
    l2AtomicAddInfo["status"] = DataUtils::UnpackUint64ValueLe(data + offset);   // L464
    offset += L2_ATOMIC_ADD_STATUS_SIZE;                                         // L465: += 256
    
    // ❌ 最后几次读取，总偏移量已达 1048+
    uint64_t kernelCode = DataUtils::UnpackUint64ValueLe(data + offset);  // L467
    offset += UINT64_SIZE;                                                // L468: += 8
    uint64_t blockIdx = DataUtils::UnpackUint64ValueLe(data + offset);    // L469
    offset += UINT64_SIZE;                                                // L470: += 8
    uint64_t status = DataUtils::UnpackUint64ValueLe(data + offset);      // L471 ❌ 最高偏移点
```

**ParseOverflowInfo() 函数 (L417-441)**:
```cpp
static nlohmann::json ParseOverflowInfo(const uint8_t* data)
{
    uint32_t index = 0;
    // ❌ 无任何长度参数，直接读取6个uint64 (48字节)
    uint64_t modelId = DataUtils::UnpackUint64ValueLe(data);           // index = 0
    index += UINT64_SIZE;                                              // index = 8
    uint64_t streamId = DataUtils::UnpackUint64ValueLe(data + index);  // index = 8
    index += UINT64_SIZE;                                              // index = 16
    uint64_t taskId = DataUtils::UnpackUint64ValueLe(data + index);    // index = 16
    index += UINT64_SIZE;                                              // index = 24
    uint64_t taskType = DataUtils::UnpackUint64ValueLe(data + index);  // index = 24
    index += UINT64_SIZE;                                              // index = 32
    uint64_t pc_start = DataUtils::UnpackUint64ValueLe(data + index);  // index = 32
    index += UINT64_SIZE;                                              // index = 40
    uint64_t para_base = DataUtils::UnpackUint64ValueLe(data + index); // index = 40
    // 总共读取 48 字节，无边界验证
}
```

### 固定偏移量常量定义 (L43-48)

```cpp
constexpr size_t DHA_ATOMIC_ADD_INFO_SIZE = 128;      // 第一次累积偏移
constexpr size_t L2_ATOMIC_ADD_INFO_SIZE = 128;       // 第二次累积偏移  
constexpr size_t AICORE_INFO_SIZE = 256;              // 第三次累积偏移
constexpr size_t DHA_ATOMIC_ADD_STATUS_SIZE = 256;    // 第四次累积偏移
constexpr size_t L2_ATOMIC_ADD_STATUS_SIZE = 256;     // 第五次累积偏移
constexpr size_t UINT64_SIZE = sizeof(uint64_t);      // = 8
```

**每个输出槽位最小数据需求**:
| 偏移位置 | 操作 | 累积偏移 | 读取量 |
|----------|------|----------|--------|
| 0 | ParseOverflowInfo | 0 → 128 | 48 bytes |
| 128 | ParseOverflowInfo | 128 → 256 | 48 bytes |
| 256 | ParseOverflowInfo | 256 → 512 | 48 bytes |
| 512 | UnpackUint64ValueLe | 512 → 768 | 8 bytes |
| 768 | UnpackUint64ValueLe | 768 → 1024 | 8 bytes |
| 1024 | UnpackUint64ValueLe | 1024 → 1032 | 8 bytes |
| 1032 | UnpackUint64ValueLe | 1032 → 1040 | 8 bytes |
| 1040 | UnpackUint64ValueLe | 1040 | **最后一次读取** | 8 bytes |

**总最小需求**: `1048 bytes` 每个输出槽位

### 缺失边界检查分析

**关键问题**: `dataLen` 参数被传入函数，但在整个函数体中**从未被引用**。

对比同文件中的安全函数 `DumpTensorDataToDisk()` (L803-861):

```cpp
static DebuggerErrno DumpTensorDataToDisk(..., const uint8_t* data, size_t dataLen, ...)
{
    uint64_t offset = 0;
    for (auto& tensor : dumpData.input()) {
        aclTensorInfos.push_back(AclTensor::ParseAttrsFromDumpData(dumpPath, data + offset, tensor, ...));
        offset += tensor.size();  // ✅ 使用 protobuf 提供的 size
    }
    
    // ✅ 存在边界检查！
    if (offset > dataLen) {
        LOG_ERROR(DebuggerErrno::ERROR_VALUE_OVERFLOW, 
                  dumpPath + ": offset overflow " + std::to_string(offset) + "/" +
                  std::to_string(dataLen) + ".");
        return DebuggerErrno::ERROR_VALUE_OVERFLOW;  // ✅ 返回错误码
    }
    // ... 继续处理
}
```

**对比结论**:
- `DumpTensorDataToDisk()`: 有边界检查，返回错误码，安全
- `DumpOpDebugDataToDisk()`: 无任何边界检查，危险

---

## 数据来源追踪

### AclDumpChunk 数据结构

**定义位置**: `third_party/ACL/AclApi.h:32-39`

```cpp
typedef struct AclDumpChunk {
    char       fileName[4096];    // 待落盘的文件名
    uint32_t   bufLen;            // ⚠️ 数据长度（由硬件/驱动提供）
    uint32_t   isLastChunk;       // 是否最后一包
    int64_t    offset;            // 文件偏移
    int32_t    flag;              // 预留标识
    uint8_t    dataBuf[0];        // ⚠️ 柔性数组，数据来自 NPU 硬件
} AclDumpChunk;
```

### 数据流追踪

```
┌─────────────────────────────────────────────────────────────────────┐
│                    TRUST BOUNDARY                                    │
│  ┌──────────────┐                                                   │
│  │  Ascend NPU  │ → 硬件/固件层                                      │
│  │   Hardware   │                                                   │
│  └──────────────┘                                                   │
│         ↓ ACL Runtime Callback                                      │
├─────────────────────────────────────────────────────────────────────┤
│  AclDumpCallBack(chunk, len)                                        │
│  ↓                                                                  │
│  AclDumper::OnAclDumpCallBack(chunk, len)                           │
│  ↓                                                                  │
│  AclDumpDataProcessor::PushData(chunk)                              │
│    - chunk->bufLen → totalLen                                       │
│    - chunk->dataBuf → buffer                                        │
│  ↓                                                                  │
│  AclDumpDataProcessor::ConcatenateData()                            │
│    - 计算 headerSegLen, dataSegOffset, dataSegLen                   │
│  ↓                                                                  │
│  AclDumpDataProcessor::DumpToDisk()                                 │
│    - 检测文件名前缀 "Opdebug.Node_OpDebug."                          │
│    - 调用 DumpOpDebugDataToDisk(dataPath, dumpData,                 │
│                               msg + dataSegOffset, dataSegLen)      │
│  ↓                                                                  │
│  ❌ DumpOpDebugDataToDisk()                                         │
│    - dataLen 参数被忽略                                              │
│    - 无边界检查直接读取                                              │
│    - ⚠️ 越界读取风险                                                 │
└─────────────────────────────────────────────────────────────────────┘
```

### 信任边界分析

**数据来源**: 
- Ascend NPU (华为AI处理器) 硬件层
- ACL (Ascend Computing Language) Runtime 驱动

**信任假设问题**:
- 代码隐式假设 NPU 硬件和驱动总是提供正确格式的数据
- 未考虑硬件故障、固件漏洞或恶意驱动的可能性
- 未处理数据损坏或格式不一致的情况

---

## 攻击路径分析

### 入口点分析

**触发条件**:
1. 用户启用溢出检查配置 (`OverflowCheckCfg`)
2. 调试级别设置为 L2 (`DebuggerLevel::L2`)
3. 模型执行时触发溢出检测

**调用链**:
```
用户配置溢出检查
    ↓
DebuggerConfig::GetOverflowCheckCfg() != nullptr
    ↓
AclDumper::Initialize() 
    ↓ 注册回调
AcldumpRegCallback(AclDumpCallBack, 0)
    ↓ NPU执行溢出检测
AclDumpCallBack(chunk, len) [硬件回调]
    ↓
AclDumper::OnAclDumpCallBack()
    ↓
processor->PushData(chunk) → processor->DumpToDisk()
    ↓ 检测文件名包含 "Opdebug.Node_OpDebug."
DumpOpDebugDataToDisk() ← **漏洞触发点**
```

### 恶意数据注入可能性

**场景1: NPU固件/驱动异常**
- 损坏的 NPU 固件可能发送格式错误的数据
- `bufLen` 声称的数据长度与实际内容不符
- `dumpData.output()` 包含的槽位数量与实际数据量不匹配

**场景2: 硬件故障**
- NPU 硬件故障导致数据传输错误
- 内存损坏导致 `dataBuf` 内容被截断

**场景3: 数据竞争**
- 多线程环境下数据被部分覆盖

---

## 影响评估

### 内存信息泄露风险

**越界读取可能泄露的数据类型**:
- 程序内存中相邻的敏感数据
- 其他 tensor 数据片段
- 配置信息或密钥材料
- 用户模型参数

**泄露范围评估**:
- 如果 `dataLen` 仅 100 字节，函数将尝试读取 `data + 1040` 处的 8 字节
- 这导致读取距离缓冲区末尾约 948+ 字节外的内存区域
- 可能触发段错误或读取任意内存内容

### 拒绝服务风险

**崩溃触发条件**:
- 读取未映射内存页 → `SIGSEGV`
- 读取只读保护区域 → 访问违规
- 读取无效地址 → 未定义行为

**影响**:
- 调试进程崩溃，中断数据采集
- 模型训练/推理中断
- 可能导致部分数据丢失

### 其他影响

**可靠性影响**:
- 未定义行为可能导致不可预测的程序状态
- 内存损坏可能传播到其他组件

**安全审计影响**:
- CWE-125 被认为是可能导致信息泄露的基础漏洞
- 在高安全性环境中可能被攻击者利用进行内存探测

---

## PoC 概念验证（安全描述）

### 触发条件分析（不含实际代码）

**最小触发条件**:
1. 配置溢出检查功能启用
2. 模型执行并触发 NPU 溢出检测回调
3. NPU 返回调试数据包

**触发数据特征**:
- 文件名前缀为 `"Opdebug.Node_OpDebug."`（触发 `DumpOpDebugDataToDisk` 分支）
- `dumpData.output()` 包含至少 1 个输出槽位
- `dataSegLen` < 1048 字节（每个槽位的最小需求）

**恶意数据构造（理论）**:
```
假设攻击者能控制 NPU 驱动响应:

AclDumpChunk 构造:
- fileName: "path/Opdebug.Node_OpDebug.xxx"  // 触发漏洞分支
- bufLen: 100                                // 声称有100字节（远小于1048）
- dataBuf: [100字节真实数据]                  // 实际数据很短

结果:
- slot = 0 时第一次 ParseOverflowInfo(data + 0) 可能成功（需48字节）
- offset += 128 后，offset = 128
- ParseOverflowInfo(data + 128) 尝试读取 data[128-175] → 越界48字节
- 如果内存未映射 → 程序崩溃
- 如果内存可读 → 泄露相邻内存内容
```

**触发阈值**:
- 最小恶意数据大小: 48 字节（第一次 `ParseOverflowInfo` 就能触发）
- 推荐测试数据: 100-200 字节（模拟部分数据传输失败）

---

## 修复建议

### 边界检查实现

**方案1: 在函数入口添加总长度检查**

```cpp
static DebuggerErrno DumpOpDebugDataToDisk(const std::string& dumpPath, AclDumpMsg::DumpData& dumpData,
                                           const uint8_t* data, size_t dataLen)
{
    DEBUG_FUNC_TRACE();
    
    // ✅ 新增：计算最小需求长度
    constexpr size_t MIN_SLOT_SIZE = 
        DHA_ATOMIC_ADD_INFO_SIZE +      // 128
        L2_ATOMIC_ADD_INFO_SIZE +       // 128
        AICORE_INFO_SIZE +              // 256
        DHA_ATOMIC_ADD_STATUS_SIZE +    // 256
        L2_ATOMIC_ADD_STATUS_SIZE +     // 256
        3 * UINT64_SIZE;                // 24
    
    uint32_t num = static_cast<uint32_t>(dumpData.output().size());
    
    // ✅ 新增：总长度验证
    size_t requiredSize = num * MIN_SLOT_SIZE;
    if (dataLen < requiredSize) {
        LOG_ERROR(DebuggerErrno::ERROR_INVALID_FORMAT, 
                  dumpPath + ": debug data too short. Required " + 
                  std::to_string(requiredSize) + " bytes, got " + 
                  std::to_string(dataLen) + " bytes.");
        return DebuggerErrno::ERROR_INVALID_FORMAT;
    }
    
    // ... 继续原有处理
}
```

**方案2: 每次读取前验证偏移**

```cpp
static DebuggerErrno DumpOpDebugDataToDisk(const std::string& dumpPath, AclDumpMsg::DumpData& dumpData,
                                           const uint8_t* data, size_t dataLen)
{
    uint32_t num = static_cast<uint32_t>(dumpData.output().size());
    for (uint32_t slot = 0; slot < num; slot++) {
        uint32_t offset = 0;
        
        // ✅ 每次读取前检查边界
        #define CHECK_OFFSET(required) \
            if (offset + required > dataLen) { \
                LOG_ERROR(DebuggerErrno::ERROR_INVALID_FORMAT, \
                          dumpPath + ": buffer overflow at slot " + std::to_string(slot)); \
                return DebuggerErrno::ERROR_INVALID_FORMAT; \
            }
        
        CHECK_OFFSET(48);  // ParseOverflowInfo 需要 48 字节
        nlohmann::json dhaAtomicAddInfo = ParseOverflowInfo(data + offset);
        offset += DHA_ATOMIC_ADD_INFO_SIZE;
        
        CHECK_OFFSET(48);
        nlohmann::json l2AtomicAddInfo = ParseOverflowInfo(data + offset);
        offset += L2_ATOMIC_ADD_INFO_SIZE;
        
        // ... 对所有读取点应用相同检查
    }
}
```

**方案3: 修改 ParseOverflowInfo 接口**

```cpp
// ✅ 改进接口，增加长度参数
static nlohmann::json ParseOverflowInfo(const uint8_t* data, size_t availableLen)
{
    constexpr size_t REQUIRED_SIZE = 6 * UINT64_SIZE;  // 48 bytes
    
    if (availableLen < REQUIRED_SIZE) {
        LOG_WARNING(DebuggerErrno::ERROR_INVALID_FORMAT, 
                    "Insufficient data for overflow info parsing.");
        return nlohmann::json();  // 返回空 JSON
    }
    
    // ... 原有解析逻辑
}

// 调用时传递剩余长度
nlohmann::json dhaAtomicAddInfo = ParseOverflowInfo(data + offset, dataLen - offset);
```

### 错误处理建议

**推荐错误码**: `DebuggerErrno::ERROR_INVALID_FORMAT`

**推荐日志级别**: `LOG_ERROR`

**处理策略**:
- 发现无效数据时立即返回错误
- 不要尝试部分解析或恢复
- 记录详细的长度和偏移信息便于诊断

### 最佳实践

1. **防御性编程**: 始终验证外部数据长度
2. **一致性设计**: 同文件中类似函数已有边界检查，应保持一致
3. **文档更新**: 注释说明固定数据结构的预期大小
4. **单元测试**: 添加边界条件测试用例

---

## 参考链接

- **CWE-125**: https://cwe.mitre.org/data/definitions/125.html
- **OWASP Memory Corruption**: https://owasp.org/www-community/vulnerabilities/Memory_corruption
- **华为 Ascend ACL 文档**: (内部参考)

---

## 分析结论

### 最终判定: **确认真实漏洞**

**判定依据**:

| 检查项 | 结果 |
|--------|------|
| 参数 `dataLen` 是否被使用 | ❌ 未使用 |
| 是否存在边界检查 | ❌ 无 |
| 对比同文件安全函数 | ✅ 确认缺失 |
| 固定偏移量累积风险 | ⚠️ 最高达 1048+ bytes |
| 数据来源信任边界 | ⚠️ NPU硬件/驱动 |
| 信息泄露可能性 | ✅ 存在 |
| 拒绝服务可能性 | ✅ 存在 |

### 漏洞严重性评估

| 维度 | 评分 |
|------|------|
| **实际严重性** | Medium-High |
| **攻击复杂度** | Medium (需特定触发条件) |
| **影响范围** | 调试模块溢出检查功能 |
| **修复难度** | Low (简单边界检查) |

### 建议

**立即修复**: 添加边界检查，参考 `DumpTensorDataToDisk()` 的实现模式。

**建议优先级**: 高优先级 - 虽然触发条件较为特定，但该漏洞违反了基本的安全编码原则，可能导致程序崩溃和信息泄露。

---

*报告生成时间: 2026-04-21*
*分析工具: OpenCode Vulnerability Scanner*
