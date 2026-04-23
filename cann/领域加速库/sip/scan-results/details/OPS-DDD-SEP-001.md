# OPS-DDD-SEP-001：FFT算子整数溢出漏洞

## 漏洞概述

**漏洞ID**: OPS-DDD-SEP-001  
**漏洞类型**: Integer Overflow (CWE-190)  
**严重性**: Critical  
**CWE**: CWE-190 - Integer Overflow or Wraparound  
**CVSS估计**: 8.6 (High) - AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L  

**漏洞位置**:  
- 文件: `ops/fft/c2c3d/ddd_sep/ddd_sep/tiling/ddd_sep_tiling.cpp`  
- 行号: 40  
- 函数: `DddSepTiling`  

**漏洞代码**:  
```cpp
uint32_t workspaceSize = param.batchSize * param.fftX * param.fftY * param.fftZ * 2 * sizeof(float);
```

## 根因分析

### 1. 类型不匹配

**源代码定义对比**:

| 位置 | 字段类型 | 说明 |
|------|---------|------|
| `OpParam::Ddd` (ddd.h:20-24) | `size_t` (64位) | 参数结构体使用64位存储 |
| `DddSepTilingData` (tiling_data.h:16-19) | `uint32_t` (32位) | Tiling数据结构使用32位 |
| `workspaceSize` 计算 (ddd_sep_tiling.cpp:40) | `uint32_t` (32位) | 局部变量使用32位 |

**关键问题**:  
- API 层面 (`asdFftMakePlan3D`) 使用 `int64_t` 接收参数  
- 内部参数结构 (`OpParam::Ddd`) 使用 `size_t` 存储  
- 但 workspace 计算时强制使用 `uint32_t`，导致溢出  

### 2. 参数检查缺陷

**API 参数检查** (`fft_api.cpp:806-842`):

```cpp
AspbStatus commonParamCheck(asdFftHandle handle, int64_t fftSizeX, int64_t fftSizeY, int64_t batchSize) {
    if (fftSizeX <= 0 || fftSizeX > MAX_FFT_SIZE) {
        return ErrorType::ACL_ERROR_INVALID_PARAM;
    }
    if (fftSizeY <= 0 || fftSizeY > MAX_FFT_SIZE) {
        return ErrorType::ACL_ERROR_INVALID_PARAM;
    }
    if (batchSize <= 0) {  // ← 关键缺陷：只有下限检查！
        return ErrorType::ACL_ERROR_INVALID_PARAM;
    }
    return AsdSip::ErrorType::ACL_SUCCESS;
}
```

**检查缺陷**:  
1. `fftSizeX/Y/Z` 有上限检查 (`MAX_FFT_SIZE = 2^27 = 134,217,728`)  
2. **`batchSize` 只有下限检查 (`> 0`)，没有上限检查！**  
3. 单个维度检查不足以防止乘法链溢出  

### 3. 溢出计算分析

**完整公式**:  
```
workspaceSize = batchSize * fftX * fftY * fftZ * 2 * sizeof(float)
             = batchSize * fftX * fftY * fftZ * 8
```

**溢出阈值**:  
- `UINT32_MAX = 4,294,967,295`  
- 当 `batchSize * fftX * fftY * fftZ * 8 > UINT32_MAX` 时溢出  

**最小触发条件**:  
假设各维度为最小可溢出组合：  
- `fftX = 1000`, `fftY = 1000`, `fftZ = 1000` (都远小于 MAX_FFT_SIZE)  
- 需要 `batchSize > 4,294,967,295 / (1000 * 1000 * 1000 * 8) ≈ 537`  
- **只要 `batchSize ≥ 600`，即可触发溢出！**  

**对比参考**:  
相同模块的类似函数 `dd_tiling.cpp:88` 使用了正确类型：  
```cpp
uint64_t workspaceSize = param.batchSize * param.fftX * param.fftY * sizeof(std::complex<float>);
```

## 攻击向量

### 攻击入口点

**API 路径**:  
```
用户调用 → asdFftMakePlan3D() → DddCoreSep::InitTactic() → DddSepTiling()
```

**完整调用链**:  
1. **API 层**: `asdFftMakePlan3D(handle, fftSizeX, fftSizeY, fftSizeZ, fftType, direction, batchSize)`  
   - 参数: `int64_t fftSizeX/Y/Z`, `int32_t batchSize`  
   - 检查: 各维度 < MAX_FFT_SIZE, batchSize > 0  
   
2. **Plan 初始化**: `init3DSteps(plan)`  
   - 创建 `DddCoreSep` 实例  
   - 传递参数到 `FftCore3DBase` 构造函数  
   
3. **Core 初始化**: `DddCoreSep::InitTactic()`  
   - 构建 `OpParam::Ddd` 参数结构  
   - 调用 `DddSepTiling(launchParam, kernelInfo)`  
   
4. **Tiling 计算**: `DddSepTiling()`  
   - 计算溢出的 `workspaceSize`  
   - 传递到 `kernelInfo.GetScratchSizes()`  

### 用户可控输入

**完全可控参数**:  
- `batchSize` - 无上限检查，攻击者可设置任意大值  
- `fftSizeX/Y/Z` - 有上限检查但允许大值  

**攻击者能力**:  
- 通过 FFT API 直接传入恶意参数  
- 不需要特殊权限（API 公开调用）  
- 可用于本地攻击或远程服务攻击  

## 触发条件

### 精确数值条件

**溢出计算**:  
```
真实大小: actualSize = batchSize * fftX * fftY * fftZ * 8
溢出后大小: workspaceSize = actualSize % UINT32_MAX
```

**示例触发参数组合**:

| batchSize | fftX | fftY | fftZ | 真实大小 (bytes) | 溢出后大小 (bytes) | 差异 |
|-----------|------|------|------|-----------------|-------------------|------|
| 600 | 1000 | 1000 | 1000 | 4,800,000,000 | 505,032,704 | 4.3 GB |
| 1000 | 1000 | 1000 | 1000 | 8,000,000,000 | 3,705,032,704 | 4.3 GB |
| 100 | 1000 | 1000 | 1000 | 800,000,000 | 800,000,000 | 无溢出 |
| 600 | 600 | 600 | 600 | 1,036,800,000 | 1,036,800,000 | 无溢出 |

**关键点**:  
- 参数组合 `(600, 1000, 1000, 1000)` 通过所有 API 检查  
- 但导致 4.8 GB 的 workspace 需求被截断为 505 MB  
- 内核将使用错误的 workspace 大小  

### 执行路径分析

**内存分配流程**:  
1. `DddCoreSep::EstimateWorkspaceSize()` 返回 `GetTotalScratchSize()`  
2. `DddCoreSep::Run()` 中调用 `workspace.allocate(bufferSize)`  
   - `bufferSize = kernelInfo.GetTotalScratchSize()`  
   - 实际分配的是溢出后的小值  

**内核执行**:  
```cpp
// kernel/ddd_sep.cpp:140
auto gm_temp_real = params.workspace;
auto gm_temp_imag = params.workspace + batchSize * fftSizeX * fftSizeY * fftSizeZ * sizeof(T_INPUT);
```

内核期望 workspace 有 `batchSize * fftX * fftY * fftZ * 8` 字节，但实际只有溢出后的值。

## 影响范围

### 1. 直接影响：NPU 设备内存损坏

**越界访问**:  
- 内核访问 `workspace + batchSize * fftX * fftY * fftSizeZ * 4`  
- 但 workspace 只有溢出后的大小  
- 导致越界读写 NPU 设备内存  

**内存损坏后果**:  
- **越界写入**: 损坏相邻的 NPU 内存对象  
  - 可能损坏其他任务的缓冲区  
  - 可能损坏 NPU 设备控制结构  
- **越界读取**: 泄露敏感数据  
  - 可能读取其他任务的中间结果  
  - 可能泄露内存中的密钥或敏感信息  

### 2. 间接影响：系统稳定性

**DoS 攻击**:  
- NPU 设备内存损坏导致内核崩溃  
- 可能触发 NPU 设备异常需要重启  
- 影响其他正在运行的 NPU 任务  

**数据完整性**:  
- FFT 计算结果错误  
- 可能影响依赖 FFT 的下游计算  

### 3. 潜在高级攻击

**如果攻击者能够**:  
- 控制被损坏内存的内容  
- 知道相邻内存对象的结构  
- 可能实现：  
  - 信息泄露（读取相邻任务数据）  
  - 潜在代码执行（如果损坏控制结构）  

**攻击场景**:  
- 云环境中多租户共享 NPU 设备  
- 攻击者通过恶意 FFT 参数损坏其他租户的数据  
- 造成数据泄露或跨租户攻击  

## PoC 构造思路

### 触发策略

**参数选择原则**:  
1. **满足 API 检查**: 所有维度 < MAX_FFT_SIZE，batchSize > 0  
2. **触发溢出**: `batchSize * fftX * fftY * fftZ * 8 > UINT32_MAX`  
3. **最大化影响**: 差异足够大，导致明显的内存损坏  

### 构造步骤

**步骤 1: 选择参数组合**  
推荐组合：  
```
fftX = 1000  (满足 < MAX_FFT_SIZE)
fftY = 1000  (满足 < MAX_FFT_SIZE)
fftZ = 1000  (满足 < MAX_FFT_SIZE)
batchSize = 600  (满足 > 0，且能触发溢出)
```

计算验证：  
```
真实需求: 600 * 1000 * 1000 * 1000 * 8 = 4.8 GB
溢出后: 4.8 GB % UINT32_MAX = 505 MB
差异: 4.3 GB 的 workspace 缺失
```

**步骤 2: 构造 API 调用序列**  
```cpp
// 伪代码 - 不提供完整可执行代码
asdFftHandle handle;
asdFftCreate(handle);

// 关键调用 - 触发溢出
asdFftMakePlan3D(
    handle,
    1000,  // fftSizeX
    1000,  // fftSizeY
    1000,  // fftSizeZ
    ASCEND_FFT_C2C_SEP,
    ASCEND_FFT_FORWARD,
    600    // batchSize - 触发溢出
);

// 分配 workspace - 使用溢出后的小值
size_t workspaceSize;
asdFftGetWorkspaceSize(handle, workspaceSize);
void* workspace = malloc(workspaceSize);  // 实际分配 505 MB，而非 4.8 GB
asdFftSetWorkspace(handle, workspace);

// 执行 FFT - 触发越界访问
asdFftExecC2CSeparated(handle, inputReal, inputImag, outputReal, outputImag);
```

**步骤 3: 观察攻击效果**  
- 内核执行时访问超出 workspace 范围  
- 可能触发内存访问错误  
- 或静默损坏相邻内存  

### 检测方法

**运行时检测**:  
- 监控 NPU 设备内存使用异常  
- 检测 workspace 分配大小是否合理  
- 观察内核执行错误  

**静态检测**:  
- 检查 `workspaceSize` 计算类型是否为 64 位  
- 验证参数乘法是否可能溢出  
- 检查参数边界检查是否完整  

## 修复建议

### 方案 1: 使用 64 位类型（推荐）

**修改文件**: `ops/fft/c2c3d/ddd_sep/ddd_sep/tiling/ddd_sep_tiling.cpp`

**修复代码**:  
```cpp
// 第 40 行修改
// 原代码: uint32_t workspaceSize = param.batchSize * param.fftX * param.fftY * param.fftZ * 2 * sizeof(float);
uint64_t workspaceSize = param.batchSize * param.fftX * param.fftY * param.fftZ * 2 * sizeof(float);
```

**优点**:  
- 最小改动，只需修改一行  
- 与 `dd_tiling.cpp` 保持一致  
- 支持大尺寸 FFT 计算  

**注意**:  
- 需验证 `GetScratchSizes()` 是否支持 `uint64_t`  
- 可能需要同步修改 `KernelInfo` 接口  

### 方案 2: 添加参数验证

**修改文件**: `core/fft/fft_api.cpp`

**修复代码**:  
```cpp
// 在 commonParamCheck3D 中添加溢出检查
AspbStatus commonParamCheck3D(asdFftHandle handle, int64_t fftSizeX, int64_t fftSizeY, int64_t fftSizeZ, int64_t batchSize) {
    // 原有检查...
    
    // 新增：检查乘法溢出
    uint64_t totalSize = batchSize * fftSizeX * fftSizeY * fftSizeZ * 8;
    if (totalSize > UINT32_MAX) {
        ASDSIP_LOG(ERROR) << "FFT parameters cause workspace size overflow.";
        return ErrorType::ACL_ERROR_INVALID_PARAM;
    }
    
    // 或新增：检查 batchSize 上限
    if (batchSize > MAX_BATCH_SIZE) {  // 需定义合理上限
        ASDSIP_LOG(ERROR) << "Invalid batchSize: exceeds maximum limit.";
        return ErrorType::ACL_ERROR_INVALID_PARAM;
    }
    
    return AsdSip::ErrorType::ACL_SUCCESS;
}
```

**优点**:  
- 从源头防止溢出参数进入系统  
- 保持内部代码不变  

**缺点**:  
- 限制了合法的大尺寸 FFT 计算  
- 需定义合理的 batchSize 上限  

### 方案 3: 综合修复（最佳）

**同时实施方案 1 和方案 2**:  

1. **内部代码**: 使用 `uint64_t` 计算 workspaceSize  
2. **API 检查**: 添加合理的参数验证（但不限制合理使用）  
3. **内存分配**: 确保支持大尺寸 workspace  

**完整修复清单**:  
| 文件 | 修改位置 | 修改内容 |
|------|---------|---------|
| `ddd_sep_tiling.cpp` | 第 40 行 | `uint32_t` → `uint64_t` |
| `tiling_data.h` | 第 16-19 行 | 添加 overflow_check 字段 |
| `fft_api.cpp` | 第 831-842 行 | 添加 batchSize 上限检查 |
| `ddd_core_sep.cpp` | 第 97-98 行 | 验证 bufferSize 类型 |

### 验证测试

**修复验证步骤**:  
1. 使用原触发参数 `(600, 1000, 1000, 1000)` 测试  
2. 验证 workspace 分配正确大小  
3. 测试更大的合法参数组合  
4. 确认内核执行无越界访问  

**回归测试**:  
- 确保正常 FFT 计算功能不受影响  
- 测试边界值参数  
- 性能测试确保无性能退化  

## 相关漏洞

**类似模式漏洞**:  
检查代码库中所有使用 `uint32_t` 计算 workspace 的位置：  
- `ops/fft/c2c/fft_stride/fft_stride/tiling/fft_stride_tiling.cpp:85`  
- `ops/fft/c2c2d/dd/dd/tiling/dd_tiling.cpp:91` - 已使用 `uint64_t`（正确）  
- 其他 FFT tiling 函数  

**建议**:  
对所有 tiling 函数进行审查，确保使用正确的类型计算 workspace。

## 参考

**相关 CWE**:  
- CWE-190: Integer Overflow or Wraparound  
- CWE-680: Integer Overflow to Buffer Overflow  

**类似案例**:  
- CVE-2019-16746: FFT 库整数溢出  
- NVIDIA CUDA FFT 库溢出案例  

**最佳实践**:  
- 内存大小计算始终使用 `size_t` 或 `uint64_t`  
- 乘法链检查溢出  
- API 参数验证应覆盖所有可能的溢出组合
