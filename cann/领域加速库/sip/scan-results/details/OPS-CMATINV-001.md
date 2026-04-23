# OPS-CMATINV-001 整数溢出漏洞深度分析报告

## 漏洞概述

**漏洞ID**: OPS-CMATINV-001  
**类型**: Integer Overflow (CWE-190)  
**严重级别**: Critical  
**影响组件**: cmatinv_batched tiling 计算  
**攻击面**: API Interface (untrusted_local)

### 位置信息
- **文件**: `ops/blas/cmatinv_batched/cmatinv_batched/tiling/cmatinv_batched_tiling.cpp`
- **函数**: `CmatinvBatchedTiling`
- **行号**: 52, 65
- **数据流**: `param.n → n → offset = n * n * COMPLEX_ELENUM → startOffset (NPU memory addressing)`

---

## 根因分析

### 1. 源代码问题

漏洞代码位于矩阵偏移量计算中：

```cpp
// Line 19: 常量定义
static constexpr uint32_t COMPLEX_ELENUM = 2;  // 复数元素数量
static constexpr uint32_t MAX_CORE_CNT = 40;

// Line 34: 参数转换（从 int64_t 强转为 uint32_t）
uint32_t n = static_cast<uint32_t>(param.n);

// Line 52: 第一个溢出点
tilingDataPtr->startOffset[i] = i * n * n * COMPLEX_ELENUM;

// Line 65: 第二个溢出点（累加更危险）
currOffset += currComputeNum * n * n * COMPLEX_ELENUM;
```

### 2. 类型选择不当

所有偏移量计算使用 `uint32_t`：
- `startOffset[]` 数组成员是 `uint32_t` (cmatinv_batched_tiling_data.h:20)
- 循环变量 `i`, `currOffset`, `currComputeNum` 都是 `uint32_t`
- `n` 从 `int64_t` 强转为 `uint32_t`，丢失高位验证能力

### 3. 无溢出保护

计算表达式 `i * n * n * COMPLEX_ELENUM` 或 `currComputeNum * n * n * COMPLEX_ELENUM` 直接执行，缺少：
- 乘法前的溢出检查
- 安全乘法函数（如 `SafeMul`）
- 上限阈值验证

### 4. 上层验证不足

虽然 `core/blas/cmatinv_batched.cpp` 中存在验证：
```cpp
ASDSIP_ECHECK(n <= MAX_MATRIX_SHAPE && batchSize <= MAX_MATRIX_BATCH, ...);
// MAX_MATRIX_SHAPE = 256, MAX_MATRIX_BATCH = 3000
```

但该验证存在以下问题：
- **目的错位**: 验证是为了功能性约束（NPU 算子支持范围），而非安全防护
- **位置不当**: 验证在 API 层，kernel 层无二次验证
- **阈值不足**: n ≤ 256 是基于性能/硬件限制，非整数溢出防护
- **强转风险**: `int64_t → uint32_t` 强转前未验证高位为零

---

## 溢出数学分析

### uint32_t 溢出阈值

uint32_t 最大值 = 2^32 - 1 = **4,294,967,295**

### 计算路径一: `i * n * n * COMPLEX_ELENUM`

表达式分解：`result = i × n × n × 2`

**单因子溢出阈值**:
- `n × n` 首次溢出：n = **46,341** (n² = 2,147,488,281 > 2^31)
- `n × n × 2` 首次溢出：n = **46,340** (n² × 2 ≈ 4,294,790,400，接近上限)

**组合因子溢出阈值** (考虑 i ≤ 40):
- 当 i = 1: n ≈ 46,340 时溢出
- 当 i = 40: n ≈ 32,768 时溢出 (40 × 32,768² × 2 ≈ 4.29×10^9)

### 计算路径二: `currOffset += currComputeNum * n * n * COMPLEX_ELENUM`

这是**累加溢出**，更危险：
- `currOffset` 在循环中累加
- 最大情况下累加整个 batch 的总偏移量
- `total = batchSize × n × n × 2`

**累加溢出阈值**:
- batchSize = 3000, n = 256: total = 3000 × 256² × 2 = **1,536,000,000** (未溢出)
- batchSize = 3000, n = 463: total ≈ 4,290,000,000 (接近溢出)
- batchSize = 3000, n = 464: total > uint32_max (溢出!)

### 漏洞报告阈值分析

报告中提及 "n > ~65536" 可能是以下情况：
1. **错误计算**: 工具使用 sqrt(2^32) ≈ 65,536 作为单因子阈值
2. **理论阈值**: 未考虑 COMPLEX_ELENUM 和 i/currComputeNum 的放大效应
3. **保守估计**: 作为理论最大值参考

**真实溢出阈值**:
- 单矩阵偏移溢出: n > 32,768 (当 i=40) 或 n > 46,340 (当 i=1)
- 累加偏移溢出: n > 463 (当 batchSize=3000)

---

## 攻击向量分析

### 向量 1: API 验证绕过

**前提**: 找到内部调用路径绕过 `asdBlasCmatinvBatched` 的验证层。

**潜在路径**:
- 直接调用 `CmatinvBatchedTiling` (unlikely - 内部符号)
- 通过 `asdBlasMakeCmatinvBatchedPlan` → `makeCmatinvBatchedPlan` → `CmatinvBatchedTiling`
- 通过其他算子的共享 tiling 机制

**风险**: 代码架构显示 `CmatinvBatchedTiling` 仅由 kernel 的 `InitImpl` 调用，直接绕过难度高。

### 向量 2: 验证逻辑缺陷

**前提**: 验证代码本身存在可利用缺陷。

**分析当前验证**:
```cpp
// core/blas/cmatinv_batched.cpp:191-196
ASDSIP_ECHECK(n > 0 && batchSize > 0, ...);
ASDSIP_ECHECK(n <= MAX_MATRIX_SHAPE && batchSize <= MAX_MATRIX_BATCH, ...);
```

**潜在缺陷**:
1. `ASDSIP_ECHECK` 是日志宏，不阻止返回值处理
2. 强转 `int64_t → uint32_t` 可导致正数变负数（若 n > 2^31）
3. 验证后数据仍可被篡改（TOCTOU）

### 向量 3: 算子分支条件

**关键分支**:
```cpp
// core/blas/cmatinv_batched.cpp:162-166
if (implParam.n < MATRIX_SHAPE_LIMIT) {
    runOpsStatus = runCmatinvBatchedOps(handle, implParam);  // 使用 CmatinvBatchedTiling
} else {
    runOpsStatus = runCgetriBatchedOps(handle, implParam);   // 使用 CgetriBatchedTiling
}
```

**MATRIX_SHAPE_LIMIT = 32**

这意味着：
- n < 32 时使用 **有漏洞的 tiling**
- n ≥ 32 时使用 **另一个 tiling** (可能也有类似问题)
- 当前验证 n ≤ 256 允许 n = 32~256 进入 **有漏洞分支**

### 向量 4: 并行计算放大

**NPU 多核执行**:
- `vecCoreNum` 可高达 `MAX_CORE_CNT = 40`
- 每个 core 独立读取 `startOffset[i]` 和 `calNum[i]`
- 溢出的偏移量导致不同 core 访问错误的内存区域

---

## 触发条件

### 条件组合

| 参数 | 范围 | 溢出触发值 | 备注 |
|------|------|-----------|------|
| `n` | 1 ~ 256 (验证后) | n > 32,768 (绕过验证时) | 验证阈值不足 |
| `batchSize` | 1 ~ 3000 (验证后) | batchSize > 1 | 累加放大 |
| `i` | 0 ~ 39 | i ≥ 1 | 累乘因子 |
| `currComputeNum` | batchSize / vecCoreNum | ≥ 1 | 累加步长 |

### 精确触发条件

**假设验证被完全绕过**:

1. **单偏移溢出** (Line 52):
   - 条件: `i × n² × 2 > 4,294,967,295`
   - 触发: n > 46,340 且 i ≥ 1，或 n > 32,768 且 i ≥ 40

2. **累加溢出** (Line 65):
   - 条件: `batchSize × n² × 2 > 4,294,967,295`
   - 触发: n > 463 且 batchSize = 3000，或 n > 1,400 且 batchSize = 1,000

3. **强转截断**:
   - 条件: `param.n` (int64_t) > 2^32
   - 触发: 用户传入 n = 4,294,967,296 (0x1_0000_0000)
   - 结果: 强转为 0，导致偏移量全部为 0 (逻辑错误)

### 当前代码实际触发可能性

由于 n ≤ 256 的验证：
- **Line 52 溢出**: 不可能触发 (256² × 40 × 2 = 5.24M < 4.29G)
- **Line 65 溢出**: 不可能触发 (3000 × 256² × 2 = 1.54G < 4.29G)
- **强转截断**: 可能触发 (若验证逻辑有缺陷)

**结论**: 当前验证暂时阻止溢出，但验证逻辑不健壮，存在未来绕过风险。

---

## 影响范围

### 1. NPU 内存损坏

**机制**:
- `startOffset[i]` 溢出后变成一个小的正数或零
- NPU core i 使用错误的偏移量访问输入矩阵数据
- 实际访问地址偏离预期，可能：
  - 读到其他矩阵的数据 (数据混淆)
  - 读到 workspace 区域 (隐私泄露)
  - 读到非分配区域 (设备异常)

### 2. 批处理矩阵混淆

**场景**: batchSize = 3000, n 越界触发溢出

- 理想偏移: Matrix 0 at offset 0, Matrix 1 at offset n²×2, ...
- 溢出后: 多个矩阵映射到重叠偏移量
- 结果: 矩阵求逆计算使用错误输入数据，输出结果不可预测

### 3. 计算结果错误

**后果**:
- 批处理矩阵求逆结果全部错误
- 上层机器学习训练/推理产生噪声结果
- 数值稳定性下降，可能触发 NaN 或 Inf

### 4. 设备级故障

**严重情况**:
- NPU 访问未映射的设备内存 → 硬件异常
- 设备驱动捕获异常 → 进程终止或设备重启
- 多用户共享 NPU 环境 → 其他用户受影响 (DoS)

### 5. 信息泄露

**隐私风险**:
- 溢出的偏移量可能指向 workspace 中的其他用户数据
- NPU 计算过程读取了本不应访问的数据
- 结果输出可能包含其他矩阵的片段

---

## PoC 构造思路

### 构造策略

**不提供完整可执行代码，仅描述逻辑思路**

### 思路 1: 构造越界参数

**目标**: 绕过或突破验证限制

**步骤**:
1. 研究 `ASDSIP_ECHECK` 宏的具体实现（是否返回错误码）
2. 尝试传入 n 值接近验证上限边缘 (n = 255, 256)
3. 观察 `int64_t → uint32_t` 强转在高值时是否截断
4. 若存在 TOCTOU 窗口，在验证后修改张量维度

### 思路 2: 利用算子分支

**目标**: 找到进入漏洞分支的合法路径

**分析**:
- n < 32 进入漏洞分支
- 但 n < 32 不足以触发溢出
- 需要 n 在 [32, 256] 区间并绕过验证进入错误分支

### 思路 3: 张量维度欺骗

**目标**: 张量实际维度与参数不匹配

**步骤**:
1. 创建张量 A with shape [batchSize, n_real, n_real]
2. 调用 API 时传入参数 n_param > n_real
3. 观察张量形状检查是否捕获不匹配
4. 若检查不严格，tiling 使用 n_param 计算，但张量实际为 n_real

### 思路 4: 内核级测试

**目标**: 直接构造 tiling 数据触发溢出

**前提**: 有内核调试权限或 tiling 数据注入能力

**步骤**:
1. 修改 `CmatinvBatchedTilingData` 结构体的 `n` 字段为越界值
2. 手工构造 `startOffset[]` 数组注入溢出值
3. 触发 NPU kernel 执行
4. 观察设备行为（内存访问日志、异常报告）

### 思路 5: 累加路径触发

**目标**: 利用循环累加产生溢出

**构造**:
- 选择 batchSize 使 `currComputeNum` 在循环中累加多次
- 设计 n 值使 `currComputeNum × n² × 2` 单步接近阈值
- 经过多次循环后 `currOffset` 溢出

---

## 修复建议

### P0 级修复: 立即实施

#### 修复 1: tiling 层添加溢出检查

**位置**: `cmatinv_batched_tiling.cpp:34-66`

```cpp
// 添加安全乘法函数
static inline bool SafeMulUint32(uint32_t a, uint32_t b, uint32_t& result) {
    if (a > UINT32_MAX / b) {
        return false;  // 溢出
    }
    result = a * b;
    return true;
}

// 修改 Line 34: 保留 int64_t，避免强转截断
int64_t n64 = param.n;  // 不强转
ASDSIP_ECHECK(n64 > 0 && n64 <= 256, "n out of valid range", 
              return ErrorType::ACL_ERROR_INVALID_PARAM);
uint32_t n = static_cast<uint32_t>(n64);  // 安全强转

// 修改 Line 52: 使用安全乘法
uint32_t matSize;
if (!SafeMulUint32(n, n, matSize) || !SafeMulUint32(matSize, COMPLEX_ELENUM, matSize)) {
    ASDSIP_LOG(ERROR) << "Integer overflow in matrix size calculation";
    return ErrorType::ACL_ERROR_INVALID_PARAM;
}
if (!SafeMulUint32(i, matSize, tilingDataPtr->startOffset[i])) {
    ASDSIP_LOG(ERROR) << "Integer overflow in startOffset[" << i << "]";
    return ErrorType::ACL_ERROR_INVALID_PARAM;
}

// 修改 Line 65: 使用安全累加
uint32_t step;
if (!SafeMulUint32(currComputeNum, matSize, step) ||
    currOffset > UINT32_MAX - step) {
    ASDSIP_LOG(ERROR) << "Integer overflow in currOffset accumulation";
    return ErrorType::ACL_ERROR_INVALID_PARAM;
}
currOffset += step;
```

#### 修复 2: tiling 数据结构升级

**位置**: `cmatinv_batched_tiling_data.h:17-22`

```cpp
struct CmatinvBatchedTilingData {
    uint32_t dtype;
    uint32_t n;
    uint64_t startOffset[40];  // 升级为 uint64_t，支持大偏移量
    uint32_t calNum[40];
};
```

**同步修改**: kernel 层 `cmatinv_batched.h:266` 需解析 uint64_t offset

### P1 级修复: 短期改进

#### 修复 3: API 验证升级

**位置**: `core/blas/cmatinv_batched.cpp:191-196`

```cpp
// 增强验证，明确安全目的
ASDSIP_ECHECK(n > 0, "n must be positive", return ErrorType::ACL_ERROR_INVALID_PARAM);
ASDSIP_ECHECK(n <= 256, "n exceeds hardware support limit", 
              return ErrorType::ACL_ERROR_INVALID_PARAM);
// 新增: 强转安全验证
ASDSIP_ECHECK(param.n <= UINT32_MAX, "n exceeds uint32_t range", 
              return ErrorType::ACL_ERROR_INVALID_PARAM);
// 新增: 溢出阈值验证 (数学安全上限)
const int64_t SAFE_N_LIMIT = 46340;  // sqrt(UINT32_MAX / 2)
ASDSIP_ECHECK(param.n <= SAFE_N_LIMIT, "n causes integer overflow risk",
              return ErrorType::ACL_ERROR_INVALID_PARAM);
```

#### 修复 4: Kernel 层二次验证

**位置**: `cmatinv_batched_kernel.cpp:45-50`

```cpp
Status InitImpl(const LaunchParam &launchParam) override {
    // 新增: 参数二次验证
    OpParam::CmatinvBatched param = AnyCast<OpParam::CmatinvBatched>(launchParam.GetParam());
    ASDSIP_ECHECK(param.n > 0 && param.n <= 256, "Invalid n in kernel layer",
                  return Status::FailStatus(ERROR_INVALID_VALUE));
    ASDSIP_ECHECK(param.batchSize > 0 && param.batchSize <= 3000, 
                  "Invalid batchSize in kernel layer",
                  return Status::FailStatus(ERROR_INVALID_VALUE));
    
    auto status = CmatinvBatchedTiling(launchParam, kernelInfo_);
    ...
}
```

### P2 级修复: 长期改进

#### 修复 5: 统一安全乘法库

创建 `utils/safe_math.h`:

```cpp
namespace AsdSip {
namespace SafeMath {

template<typename T>
inline bool SafeMul(T a, T b, T& result) {
    if (a == 0 || b == 0) {
        result = 0;
        return true;
    }
    if (a > std::numeric_limits<T>::max() / b) {
        return false;
    }
    result = a * b;
    return true;
}

template<typename T>
inline bool SafeAdd(T a, T b, T& result) {
    if (a > std::numeric_limits<T>::max() - b) {
        return false;
    }
    result = a + b;
    return true;
}

}  // namespace SafeMath
}  // namespace AsdSip
```

#### 修复 6: 全算子扫描

使用 AST-grep 扫描所有 tiling 文件的乘法模式：

```bash
ast-grep --pattern '$_VAR = $A * $B * $C' --lang cpp ops/
```

为所有类似模式添加 `SafeMul` 调用。

---

## 验证测试

### 测试用例设计

#### 正常边界测试

| n | batchSize | 预期结果 |
|---|-----------|----------|
| 1 | 1 | PASS |
| 32 | 100 | PASS |
| 256 | 3000 | PASS |
| 255 | 2999 | PASS |

#### 异常边界测试

| n | batchSize | 预期结果 |
|---|-----------|----------|
| 0 | 100 | FAIL - Invalid param |
| 257 | 100 | FAIL - Exceeds limit |
| 256 | 3001 | FAIL - Exceeds limit |
| -1 | 100 | FAIL - Negative param |
| UINT64_MAX | 100 | FAIL - Overflow in cast |

#### 安全边界测试

| n | batchSize | 预期结果 |
|---|-----------|----------|
| 46340 | 1 | PASS - Safe math limit |
| 46341 | 1 | WARN - Near overflow (if bypass) |
| 464 | 3000 | WARN - Cumulative overflow risk |

---

## 结论

### 漏洞评估

| 维度 | 评级 | 说明 |
|------|------|------|
| **严重性** | Critical | NPU 内存损坏，设备故障风险 |
| **可利用性** | Medium | 当前验证暂时阻止，但验证逻辑脆弱 |
| **影响范围** | High | 批处理矩阵全部受影响，DoS 风险 |
| **修复难度** | Low | 加溢出检查即可 |

### 关键发现

1. **代码层面**: 乘法计算无溢出保护，类型选择不当 (uint32_t)
2. **验证层面**: 上限验证基于功能而非安全，kernel 层无二次验证
3. **架构层面**: API → kernel → tiling 三层未形成纵深防御
4. **数据层面**: tiling 数据结构字段不足以承载理论最大偏移量

### 修复优先级

**立即修复**: P0 级修复 1-2（tiling 层溢出检查）  
**短期修复**: P1 级修复 3-4（API 和 kernel 验证）  
**长期改进**: P2 级修复 5-6（统一安全库和全算子扫描）

---

**报告生成**: Details Worker Agent  
**漏洞ID**: OPS-CMATINV-001  
**生成时间**: 2026-04-22T10:00:00Z  
**状态**: 分析完成，建议立即修复
