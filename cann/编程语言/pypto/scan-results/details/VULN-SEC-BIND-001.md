# VULN-SEC-BIND-001: Unvalidated data_ptr in DeviceRunOnceDataFromHost

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-BIND-001 |
| **类型** | 内存损坏 (Memory Corruption) |
| **CWE** | CWE-119: Improper Restriction of Operations within Bounds of Memory Buffer |
| **严重性** | Critical |
| **置信度** | 85 |
| **状态** | CONFIRMED |
| **发现者** | security-auditor |

## 漏洞位置

| 文件 | 行号 | 函数 |
|------|------|------|
| python/src/bindings/runtime.cpp | 186-230 | DeviceRunOnceDataFromHost |

## 漏洞性质

此漏洞与 **VULN-DF-MEM-001 是同一漏洞点**，由 Security Auditor 独立发现。它描述了同一安全问题的不同视角：从绑定层安全审计角度而非数据流角度。

## 关联漏洞

- **VULN-DF-MEM-001**: 同一漏洞的 DataFlow Scanner 发现
- **VULN-DF-MEM-002**: 入口点漏洞
- **VULN-SEC-PYAPI-001**: Python API 层
- **VULN-DF-MEM-005**: Sink 点

## 漏洞代码

```cpp
// runtime.cpp:186-230
std::string DeviceRunOnceDataFromHost(
    const std::vector<DeviceTensorData>& inputs, 
    const std::vector<DeviceTensorData>& outputs)
{
    // ... 省略前置代码 ...
    
    // InitializeInputOutputData 使用 inputs[i].GetAddr()
    InitializeInputOutputData(inputs, outputs);
    
    // ... 省略中间代码 ...
    
    // 输出数据写回到用户提供的地址
    for (size_t i = 0; i < outputs.size(); i++) {
        auto output = ProgramData::GetInstance().GetOutputData(i);
        StringUtils::DataCopy(
            outputs[i].GetAddr(),     // ← 用户控制的地址
            output->GetDataSize(), 
            output->data(), 
            output->GetDataSize()
        );
    }
    
    // inplace 操作时，输入地址也被写入
    if (HasInplaceArgs(...) || outputs.size() == 0) {
        for (size_t i = 0; i < inputs.size(); i++) {
            auto input = ProgramData::GetInstance().GetInputData(i);
            StringUtils::DataCopy(
                inputs[i].GetAddr(),   // ← 用户控制的地址
                input->GetDataSize(), 
                input->data(), 
                input->GetDataSize()
            );
        }
    }
    return "";
}
```

## 问题分析

### Security Auditor 视角

从安全审计角度，此漏洞具有以下特征：

| 特征 | 分析 |
|------|------|
| **信任边界** | Python → C++，跨语言边界 |
| **输入来源** | Python 用户提供 DeviceTensorData |
| **数据类型** | 指针 (data_ptr)，高危类型 |
| **验证缺失** | 无指针有效性、边界、所有权验证 |
| **操作类型** | memcpy (DataCopy)，高风险操作 |
| **影响范围** | 输入地址读取 + 输出地址写入 |

### InitializeInputOutputData 内部

```cpp
// runtime.cpp:172-184
static void InitializeInputOutputData(
    const std::vector<DeviceTensorData>& inputs, 
    const std::vector<DeviceTensorData>& outputs)
{
    for (size_t i = 0; i < inputs.size(); i++) {
        auto rawData = RawTensorData::CreateTensor(
            inputs[i].GetDataType(), 
            inputs[i].GetShape(), 
            (uint8_t*)inputs[i].GetAddr()  // ← 无验证的指针使用
        );
        ProgramData::GetInstance().AppendInput(rawData);
    }
    // ...
}
```

### 双向危险

此漏洞具有**双向危险**：

1. **读取方向**: `inputs[i].GetAddr()` 作为数据源，任意内存读取
2. **写入方向**: `outputs[i].GetAddr()` 作为数据目的地，任意内存写入

## 利用场景

### 读取敏感数据

```python
# 读取内核或进程内存中的敏感数据
secret_addr = FindSecretDataAddress()  # 攻击者预先探测
inputs = [DeviceTensorData(DT_UINT8, secret_addr, [4096])]
outputs = [ValidTensorForOutput()]
DeviceRunOnceDataFromHost(inputs, outputs)
# outputs[0] 现在包含 secret_addr 处的 4KB 数据
```

### 覆盖关键结构

```python
# 覆盖进程中的关键数据结构
target_addr = FindGOTEntry()  # 找到 GOT 表项
payload = CraftMaliciousPayload()  # 构造恶意数据

# 输入是我们的 payload
inputs = [TensorWithData(payload)]
# 输出地址指向 GOT 表项
outputs = [DeviceTensorData(DT_UINT64, target_addr, [1])]
DeviceRunOnceDataFromHost(inputs, outputs)
# GOT 表项被覆盖，触发函数调用时执行攻击者代码
```

## 与 MEM-001 的对比

| 维度 | MEM-001 (DataFlow) | BIND-001 (Security) |
|------|-------------------|---------------------|
| 发现方式 | 数据流追踪 | 安全审计 |
| 视角 | 从入口到 Sink 的完整路径 | 单点安全风险评估 |
| 描述重点 | 数据流过程 | 边界检查缺失 |
| 补充价值 | 展示完整攻击链 | 强调双向危险 |

## 修复建议

参考 VULN-DF-MEM-001 的修复建议，重点：

1. **输入验证**: 验证 inputs 地址有效性
2. **输出验证**: 验证 outputs 地址有效性
3. **边界检查**: 验证数据大小不超过内存边界
4. **所有权验证**: 确认地址属于调用者拥有的内存

### 快速修复代码

```cpp
std::string DeviceRunOnceDataFromHost(
    const std::vector<DeviceTensorData>& inputs, 
    const std::vector<DeviceTensorData>& outputs)
{
    // 新增: 验证所有地址
    for (const auto& input : inputs) {
        if (!ValidateTensorAddress(input.GetAddr(), input.GetDataSize())) {
            return "Invalid input address";
        }
    }
    for (const auto& output : outputs) {
        if (!ValidateTensorAddress(output.GetAddr(), output.GetDataSize())) {
            return "Invalid output address";
        }
    }
    
    // 原有逻辑...
}
```

## 参考链接

- CWE-119: Improper Restriction of Operations within Bounds
- VULN-DF-MEM-001 详细分析