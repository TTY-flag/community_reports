# SIP (Signal Processing) 威胁分析报告

> 由 Architecture Agent 生成
> 生成时间: 2026-04-21T15:30:00Z
> 项目路径: /home/pwn20tty/Desktop/opencode_project/cann/3/sip
> 项目类型: Library (华为 CANN 框架 SIP 模块)

## 1. 项目概述

### 1.1 项目定位
SIP (Signal Processing) 是华为 CANN (Compute Architecture for Neural Networks) 框架中的信号处理模块，提供 BLAS/FFT/Filter/Interpolation 等算子的 NPU 实现。

### 1.2 项目统计
- **总文件数**: 617 个 (612 C/C++, 5 Python)
- **总代码行数**: 59,178 行
- **主要模块**: ops (342文件), core (176文件), example (46文件), sip_pta (42文件)

### 1.3 部署模式
作为库模块部署在 Ascend NPU 服务器上，通过 Ascend CL API 被机器学习应用程序调用，或通过 PyTorch adapter (sip_pta) 被训练脚本调用。

## 2. 攻击面分析

### 2.1 信任边界

| 边界 | 可信侧 | 不可信侧 | 风险等级 |
|------|--------|----------|----------|
| API Interface | SIP Library | External callers via aclTensor | High |
| Device Memory | SIP Kernel execution | User-provided tensor data | High |
| PyTorch Adapter | sip_pta adapter layer | PyTorch tensor data | Medium |

### 2.2 主要入口点

#### 高风险入口点 (Critical/High)

| 入口点 | 文件 | 行号 | 信任等级 | 外部数据 |
|--------|------|------|----------|----------|
| asdBlasCgemmBatched | include/blas_api.h | 198 | untrusted_local | 批处理矩阵数据 |
| asdBlasCmatinvBatched | include/blas_api.h | 206 | untrusted_local | 批处理矩阵数据 |
| asdBlasCgemm | include/blas_api.h | 112 | untrusted_local | 矩阵 A, B, C |
| asdBlasCgemv | include/blas_api.h | 119 | untrusted_local | 矩阵 A, 向量 x, y |
| asdFftExecC2C | include/fft_api.h | 65 | untrusted_local | FFT 输入张量 |
| asdFftExecC2R | include/fft_api.h | 73 | untrusted_local | 复数输入张量 |
| asdFftExecR2C | include/fft_api.h | 76 | untrusted_local | 实数输入张量 |
| asdConvolve | include/filter_api.h | 29 | untrusted_local | 信号/核张量 |
| torch_sip_cgemm | sip_pta/csrc/blas/asd_blas_cgemm.cpp | 25 | untrusted_local | PyTorch tensors |

### 2.3 攻击面向量

1. **aclTensor API 接口**: 所有 BLAS/FFT/Filter 操作接收外部张量数据
2. **维度参数**: 用户提供的 m, n, k, lda, ldb, ldc, fftSize, batchSize 值
3. **PyTorch Adapter**: sip_pta 将 PyTorch tensors 转换为 Ascend 格式
4. **工作空间内存**: 基于计算大小的内部缓冲区分配
5. **设备内存拷贝**: aclrtMemcpy 和 MkiRtMemCopy 操作
6. **Tiling Data**: 内核 tiling 中的 memcpy_s 操作

## 3. 安全漏洞分析

### 3.1 高危漏洞

#### 3.1.1 memcpy_s 返回值未检查 (CRITICAL)

**位置**: `ops/blas/iamax/iamax/tiling/iamax_tiling.cpp` (lines 181-191)

**问题描述**:
- 11 个连续 memcpy_s 调用，未检查返回值
- 使用 `ASDSIP_CHECK_WITH_NO_RETURN` 只记录日志不阻止执行
- 如果源/目标地址无效，会导致内存损坏

**影响**: 内存损坏、缓冲区溢出、设备崩溃

**修复建议**:
```cpp
auto ret = memcpy_s(dest, destSize, src, srcSize);
if (ret != EOK) {
    ASDSIP_LOG(ERROR) << "memcpy_s failed with error: " << ret;
    return ErrorType::ACL_ERROR_INTERNAL_ERROR;
}
```

#### 3.1.2 Workspace 分配边界检查缺失 (CRITICAL)

**位置**: `core/fft/utils/workspace.cpp` (lines 39-47)

**问题描述**:
- `allocate()` 函数未验证请求的 dataSize 不超过可用工作空间
- 缺少检查: `offset + dataSize > dataSize_`

**影响**: 工作空间耗尽时的缓冲区溢出

**修复建议**:
```cpp
void* Workspace::allocate(size_t dataSize) {
    if (offset_ + dataSize > dataSize_) {
        ASDSIP_LOG(ERROR) << "Workspace exhausted: requested " << dataSize 
                          << " but only " << (dataSize_ - offset_) << " available";
        throw std::runtime_error("Workspace overflow");
    }
    ...
}
```

#### 3.1.3 张量尺寸计算整数溢出 (HIGH)

**位置**: `core/blas/blasplan/BlasCgemvPlan.cpp` (lines 107-110)

**问题描述**:
- `ySize *= storageDims[i]` 乘法循环无溢出检查
- storageDims 来自用户提供的张量维度

**影响**: 整数溢出导致分配不足或 memcpy 过大

**修复建议**:
使用安全的乘法函数检查 SIZE_MAX:
```cpp
for (size_t i = 0; i < storageDimsNum; i++) {
    if (ySize > SIZE_MAX / storageDims[i]) {
        ASDSIP_LOG(ERROR) << "Integer overflow in size calculation";
        return ErrorType::ACL_ERROR_INVALID_PARAM;
    }
    ySize *= storageDims[i];
}
```

### 3.2 中危漏洞

#### 3.2.1 malloc/free 混合使用 (HIGH)

**位置**: `core/utils/ops_base.cpp` (line 196), `core/blas/blasplan/BlasCgemvPlan.cpp` (line 155)

**问题描述**:
- 部分代码使用 malloc/free，部分使用 new[]/delete[]
- 不一致的分配/释放可能导致内存损坏

**影响**: 内存损坏、double-free、use-after-free

#### 3.2.2 new[] 分配基于用户维度 (HIGH)

**位置**: 
- `core/fft/fftcore/dft_core.cpp` (line 75)
- `core/blas/blasplan/BlasCgemmPlan.cpp` (line 39)

**问题描述**:
- `new float[tensorSize]` 的大小来自用户参数计算
- 无上限验证防止极端大值

**影响**: 内存耗尽、整数溢出

#### 3.2.3 aclTensor 数据地址验证不一致 (MEDIUM)

**位置**: `core/fft/fft_api.cpp` (lines 1025-1034)

**问题描述**:
- `Mki::GetStorageAddr()` 返回值检查不一致
- 某些位置检查空指针，某些可能遗漏

**影响**: 空指针解引用

### 3.3 低危漏洞

#### 3.3.1 PyTorch Adapter 缺乏深度验证 (MEDIUM)

**位置**: `sip_pta/csrc/*.cpp`

**问题描述**:
- PyTorch tensors 直接转换为 aclTensor
- 缺乏深度验证，依赖上游框架

**影响**: 类型混淆、维度不匹配

## 4. STRIDE 威胁建模

### Spoofing (身份伪造)
- **风险**: Low - Library 模块不涉及身份验证
- **缓解**: 由 Ascend CL 框架处理

### Tampering (数据篡改)
- **风险**: High - 外部张量数据可被篡改
- **缓解**: 输入验证框架 (common_check.cpp)
- **缺口**: 部分验证路径不完整

### Repudiation (抵赖)
- **风险**: Low - Library 模块无日志审计需求
- **缓解**: ASDSIP_LOG 日志系统

### Information Disclosure (信息泄露)
- **风险**: Low - 无敏感数据处理
- **缓解**: 无特殊需求

### Denial of Service (拒绝服务)
- **风险**: High - 整数溢出可导致崩溃
- **缓解**: 需要 size bounds checking
- **缺口**: 工作空间分配无上限检查

### Elevation of Privilege (权限提升)
- **风险**: Low - Library 模块无权限管理
- **缓解**: 由框架层处理

## 5. 高风险文件清单

| 文件 | 风险等级 | 主要问题 |
|------|----------|----------|
| ops/blas/iamax/iamax/tiling/iamax_tiling.cpp | Critical | memcpy_s 返回值未检查 |
| core/fft/utils/workspace.cpp | Critical | allocate() 边界检查缺失 |
| core/blas/blasplan/BlasCgemvPlan.cpp | Critical | 整数溢出、malloc/free 混合 |
| core/utils/ops_base.cpp | Critical | malloc 无边界验证 |
| core/fft/fft_api.cpp | High | 外部张量处理入口点 |
| core/blas/cgemm.cpp | High | 外部矩阵数据处理 |
| core/fft/fftcore/dft_core.cpp | High | 基于用户维度的分配 |
| ops/blas/caxpy/caxpy/tiling/caxpy_tiling.cpp | High | ASDSIP_CHECK_WITH_NO_RETURN |

## 6. 推荐修复优先级

### P0 (立即修复)
1. iamax_tiling.cpp memcpy_s 返回值检查
2. workspace.cpp allocate() 边界验证
3. BlasCgemvPlan.cpp ySize 溢出检查

### P1 (短期修复)
1. 统一内存分配风格 (malloc/free vs new[]/delete[])
2. 添加张量维度上限验证
3. 所有 tiling 文件使用 ASDSIP_ECHECK 替代 ASDSIP_CHECK_WITH_NO_RETURN

### P2 (中期改进)
1. 创建统一的 aclTensor 验证函数
2. PyTorch adapter 添加深度验证
3. 添加安全测试用例

## 7. 数据流分析

### 关键数据流路径

```
外部输入 (aclTensor)
    │
    ▼
API 入口 (blas_api.h, fft_api.h)
    │
    ├─► Handle/Plan 验证 (PlanCache)
    │
    ├─► aclGetStorageShape 获取维度
    │   └── ⚠️ 需检查返回值和 storageDims != nullptr
    │
    ├─► 维度验证 (common_check.cpp)
    │   ├── dtype 检查
    │   ├── shape > 0 检查
    │   └── ⚠️ 缺少上限检查
    │
    ▼
RunAsdOpsV2 (ops_base.cpp)
    │
    ├─► LaunchParam 添加张量
    │
    ├─► MallocTensorInDevice
    │   └── ⚠️ dataSize 可能溢出
    │
    ├─► MkiRtMemCopy
    │   └── ⚠️ 大小来自用户维度
    │
    ▼
Kernel 执行
    │
    ├─► Tiling 计算
    │   └── ⚠️ memcpy_s 未检查返回值
    │
    ▼
NPU 设备执行
```

## 8. 结论

SIP 模块作为华为 CANN 框架的信号处理库，存在以下主要安全风险:

1. **内存安全漏洞**: memcpy_s 返回值未检查、workspace 边界检查缺失
2. **整数溢出**: 多处张量尺寸计算缺乏溢出保护
3. **输入验证缺口**: 维度上限检查、空指针检查不一致

建议立即修复 P0 级别漏洞，并在后续版本中完善输入验证框架。

---

**报告生成者**: Architecture Agent
**扫描 ID**: scan_sip_20260421
**状态**: 已完成架构分析，待启动漏洞扫描