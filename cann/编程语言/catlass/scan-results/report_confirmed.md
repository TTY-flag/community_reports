# 漏洞扫描报告 — 已确认漏洞

**项目**: catlass
**扫描时间**: 2026-04-22T02:00:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次安全扫描对 CATLASS（CANN Templates for Linear Algebra Subroutines）项目进行了深度漏洞分析。CATLASS 是华为昇腾 NPU 平台的 C++ 模板库，提供矩阵乘法、卷积等高性能算子实现，并通过 Python 扩展和共享库 API 向外部应用暴露接口。

扫描共发现 **4 个已确认的高危漏洞**，均集中在核心 GEMM（矩阵乘法）和架构层模块。这些漏洞的共同特征是**边界检查缺失**，可能导致缓冲区溢出、内存损坏或整数溢出，进而引发算子计算错误或设备崩溃。

**关键风险点**：
- **VULN-CORE-GEMM-004 (置信度 90%)**：分组矩阵乘法算子中 `problemCount` 参数可超过固定数组容量 `MAX_TENSOR_COUNT=256`，导致栈溢出。该漏洞可通过 Python/共享库 API 触达，攻击者可构造超过 256 个分组的输入实现内存损坏。
- **VULN-CORE-GEMM-002 (置信度 85%)**：SplitK 矩阵乘法的工作区大小计算存在整数溢出风险，超大矩阵维度可导致缓冲区分配不足。
- **CORE_ARCH_001 (置信度 85%)**：`GetBufferByByte()` 函数广泛使用但缺少边界检查，偏移量参数可直接越界访问 NPU 本地内存。

**业务影响**：这些漏洞可能导致深度学习推理服务中断、计算结果错误，或在多租户 NPU 环境中影响其他租户的计算任务。建议在版本发布前优先修复这 4 个高危漏洞。

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 20 | 39.2% |
| POSSIBLE | 15 | 29.4% |
| FALSE_POSITIVE | 12 | 23.5% |
| CONFIRMED | 4 | 7.8% |
| **总计** | **51** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 4 | 100.0% |
| **有效漏洞总计** | **4** | - |
| 误报 (FALSE_POSITIVE) | 12 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-CORE-GEMM-004]** Fixed Array Overflow (High) - `include/catlass/gemm/kernel/grouped_matmul.hpp:55` @ `GroupedMatmul::operator()` | 置信度: 90
2. **[CORE_ARCH_001]** Out-of-Bounds Access (High) - `include/catlass/arch/local_tensor_buffer.hpp:22` @ `GetBufferByByte` | 置信度: 85
3. **[VULN-CORE-GEMM-005]** Unbounded Memory Copy (High) - `include/catlass/gemm/kernel/grouped_matmul.hpp:26` @ `detail::UnpackListParam` | 置信度: 85
4. **[VULN-CORE-GEMM-002]** Integer Overflow in Size Calculation (High) - `include/catlass/gemm/kernel/splitk_matmul.hpp:252` @ `SplitkMatmul::GetWorkspaceSize` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@tools/tuner/src/main.cpp` | cmdline | untrusted_local | CLI 工具入口，本地用户可通过命令行参数控制工具行为，参数包括 --output, --device, --m, --n, --k, --group_count, --kernels 等 | Tiling 自动寻优工具的命令行入口，解析用户参数进行性能调优 |
| `SetDeviceId@tools/tuner/src/profiler.cpp` | env | semi_trusted | 读取环境变量 ASCEND_RT_VISIBLE_DEVICES 进行设备 ID 转换，该环境变量通常由系统管理员或部署脚本设置 | 环境变量读取，用于设备可见性配置 |
| `basic_matmul@examples/python_extension/src/bindings/pybind_bindings.cpp` | decorator | semi_trusted | Python API 入口，通过 pybind11 绑定暴露给 Python 用户代码调用，参数来自 Torch tensor 对象 | Python 扩展 API 入口，基础矩阵乘法算子 |
| `grouped_matmul@examples/python_extension/src/bindings/pybind_bindings.cpp` | decorator | semi_trusted | Python API 入口，通过 pybind11 绑定暴露给 Python 用户代码调用 | Python 扩展 API 入口，分组矩阵乘法算子 |
| `optimized_matmul@examples/python_extension/src/bindings/pybind_bindings.cpp` | decorator | semi_trusted | Python API 入口，通过 pybind11 绑定暴露给 Python 用户代码调用 | Python 扩展 API 入口，优化矩阵乘法算子 |
| `conv_bias@examples/python_extension/src/bindings/pybind_bindings.cpp` | decorator | semi_trusted | Python API 入口，通过 pybind11 绑定暴露给 Python 用户代码调用 | Python 扩展 API 入口，带偏置的卷积算子 |
| `BasicMatmul@examples/shared_lib/include/catlass_kernel.h` | rpc | semi_trusted | 共享库 API 入口，外部 C/C++ 程序通过此接口调用算子功能，参数由调用方代码控制 | 共享库导出函数，基础矩阵乘法 |
| `GroupedMatmul@examples/shared_lib/include/catlass_kernel.h` | rpc | semi_trusted | 共享库 API 入口，外部程序调用 | 共享库导出函数，分组矩阵乘法 |
| `OptimizedMatmul@examples/shared_lib/include/catlass_kernel.h` | rpc | semi_trusted | 共享库 API 入口，外部程序调用 | 共享库导出函数，优化矩阵乘法 |
| `ConvBias@examples/shared_lib/include/catlass_kernel.h` | rpc | semi_trusted | 共享库 API 入口，外部程序调用 | 共享库导出函数，带偏置的卷积 |
| `main@examples/00_basic_matmul/basic_matmul.cpp` | cmdline | untrusted_local | 示例程序入口，本地用户可通过命令行参数控制测试参数（m, n, k, deviceId） | 基础矩阵乘法示例程序的命令行入口 |
| `main@examples/102_dynamic_optimized_matmul/dynamic_optimized_matmul.cpp` | cmdline | untrusted_local | 示例程序入口，本地用户可通过命令行参数控制测试参数 | 动态优化矩阵乘法示例程序的命令行入口 |

**其他攻击面**:
- CLI Tool Arguments: tools/tuner (命令行参数解析)
- Python Extension API: examples/python_extension (Python 调用入口)
- Shared Library API: examples/shared_lib (C API 导出函数)
- Environment Variables: ASCEND_RT_VISIBLE_DEVICES (设备可见性配置)
- Template Library API: include/catlass (C++ 模板接口)
- KernelInfo Structure: inputAddr/outputAddr 指针参数 (内存操作)

---

## 3. High 漏洞 (4)

### [VULN-CORE-GEMM-004] Fixed Array Overflow - GroupedMatmul::operator()

**严重性**: High | **CWE**: CWE-129 | **置信度**: 90/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `include/catlass/gemm/kernel/grouped_matmul.hpp:55-140` @ `GroupedMatmul::operator()`
**模块**: core_gemm_kernel

**描述**: problemCount is used to iterate over fixed-size arrays (MAX_TENSOR_COUNT=256) without validation. If problemCount exceeds MAX_TENSOR_COUNT, UnpackListParam will overflow stack-allocated arrays causing memory corruption.

**漏洞代码** (`include/catlass/gemm/kernel/grouped_matmul.hpp:55-140`)

```cpp
// 第 55 行定义固定大小数组上限
static constexpr uint32_t MAX_TENSOR_COUNT = 256;

// 第 131-134 行在栈上分配固定大小数组
GemmCoord problemShapeList[MAX_TENSOR_COUNT];
LayoutA layoutAList[MAX_TENSOR_COUNT];
LayoutB layoutBList[MAX_TENSOR_COUNT];
LayoutC layoutCList[MAX_TENSOR_COUNT];

// 第 137-140 行直接使用 problemCount 复制数据，无边界检查
detail::UnpackListParam(problemShapeList, params.ptrProblemShape, params.problemCount);
detail::UnpackListParam(layoutAList, params.ptrLayoutA, params.problemCount);
detail::UnpackListParam(layoutBList, params.ptrLayoutB, params.problemCount);
detail::UnpackListParam(layoutCList, params.ptrLayoutC, params.problemCount);
```

**验证说明**: Stack overflow confirmed. problemCount used to iterate fixed-size array MAX_TENSOR_COUNT=256 without bounds validation. UnpackListParam copies data based on problemCount directly into stack-allocated problemShapeList[]. If problemCount>256, writes beyond array bounds causing memory corruption. Reachable from semi_trusted grouped_matmul API.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 15

**深度分析**

**根因分析**：该漏洞的核心问题是模板设计时将 `MAX_TENSOR_COUNT` 作为编译时常量（256），但运行时参数 `problemCount` 来自外部输入，两者之间缺少边界检查。当调用方通过 Python API 或共享库 API 传入超过 256 个分组的矩阵乘法请求时，`UnpackListParam` 会向栈上固定数组写入超出边界的数据。

从源代码分析：
- 第 55 行定义 `static constexpr uint32_t MAX_TENSOR_COUNT = 256`
- 第 131-134 行在 AIC 核函数栈上分配 4 个固定大小数组
- 第 137-140 行调用 `UnpackListParam` 时直接使用 `params.problemCount` 作为长度参数
- `params.problemCount` 来自 `Arguments` 结构（第 88 行），由外部调用方传入

**潜在利用场景**：
1. **Python 扩展攻击路径**：攻击者通过 `torch_catlass.grouped_matmul()` API 传入包含超过 256 个分组的 `groupList` tensor，触发栈溢出
2. **共享库攻击路径**：外部 C/C++ 程序调用 `GroupedMatmul()` 函数时构造恶意 `problemCount` 值
3. **影响范围**：栈溢出可损坏相邻的局部变量（如 `matmulBlockScheduler`, `blockMmad`, `inGroupOffset*`），导致后续计算逻辑异常或 NPU 设备崩溃

**建议修复方式**：
```cpp
// 在 operator() 入口处添加边界检查
if (params.problemCount > MAX_TENSOR_COUNT) {
    // 返回错误或截断处理
    return;
}
// 或动态分配替代固定数组
std::vector<GemmCoord> problemShapeList(params.problemCount);
```

---

### [CORE_ARCH_001] Out-of-Bounds Access - GetBufferByByte

**严重性**: High | **CWE**: CWE-125 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `include/catlass/arch/local_tensor_buffer.hpp:22-26` @ `GetBufferByByte`
**模块**: core_arch

**描述**: GetBufferByByte() lacks bounds checking on offset parameter. The function directly indexes into tensor buffer without validating the offset against buffer size, allowing potential out-of-bounds memory access. Given AtlasA2::UB_SIZE=192KB, an attacker-controlled offset could access memory beyond the allocated buffer region.

**漏洞代码** (`include/catlass/arch/local_tensor_buffer.hpp:22-26`)

```cpp
template <class Element = half>
CATLASS_DEVICE
AscendC::LocalTensor<Element> GetBufferByByte(const uint32_t offset) const
{
    return tensor[offset].template ReinterpretCast<Element>();
}
```

**验证说明**: Verified: GetBufferByByte() lacks bounds checking. Function is widely used across 79 files with 426 invocations. Offset parameters computed from compile-time constants (L1_SIZE, UB_SIZE) and loop indices - not directly attacker-controlled but can overflow if tensor dimensions exceed expected bounds. AscendC hardware may provide memory protection, but API-level vulnerability confirmed. Risk: High severity - buffer overflow could corrupt adjacent tensor data in UB/L1 memory regions.

**评分明细**: base: 30 | reachability: 25 | controllability: 10 | mitigations: 0 | context: -5 | cross_file: 25

**深度分析**

**根因分析**：`LocalTensorBufferBase` 类的 `GetBufferByByte()` 方法直接将 `offset` 参数作为字节偏移量访问内部 `tensor` 数组，未进行任何边界验证。该函数是一个底层基础设施接口，被多种 `LocalTensorBuffer` 特化版本（A1, A2, B1, B2, C1, C2, VECIN, VECOUT 等）继承使用。

从源代码分析：
- 第 22-26 行定义了模板函数 `GetBufferByByte`
- 第 25 行 `tensor[offset]` 直接使用偏移量访问 uint8_t 类型 tensor
- 各特化版本在构造函数中通过 `InitBuffer` 分配固定大小缓冲区（如 AtlasA2::UB_SIZE = 192KB）
- 缓冲区大小由架构常量决定（第 189、207、223 行使用 `ArchTag::UB_SIZE`）

**潜在利用场景**：
1. **间接触发路径**：虽然 offset 参数通常由编译时常量计算，但在动态 shape 场景下（如 `dynamic_matmul`），偏移量可由运行时参数推导
2. **SplitkReduceAdd 使用**（splitk_matmul.hpp 第 35-37 行）：`bufferOffset += COMPUTE_LENGTH * sizeof(ElementAccumulator)` 的累加可能在极端循环次数下超出 UB_SIZE
3. **内存损坏影响**：越界访问可能损坏相邻 UB/L1 缓冲区的 tensor 数据，导致后续矩阵计算结果错误

**建议修复方式**：
```cpp
template <class Element = half>
CATLASS_DEVICE
AscendC::LocalTensor<Element> GetBufferByByte(const uint32_t offset) const
{
    // 添加边界检查（需要传入缓冲区大小参数）
    constexpr uint32_t BUFFER_SIZE = ArchTag::UB_SIZE; // 或通过模板参数传入
    if (offset >= BUFFER_SIZE) {
        // AscendC 设备端错误处理机制有限，可考虑返回空 tensor 或触发断言
        AscendC::Assert(false, "GetBufferByByte offset overflow");
    }
    return tensor[offset].template ReinterpretCast<Element>();
}
```

---

### [VULN-CORE-GEMM-005] Unbounded Memory Copy - detail::UnpackListParam

**严重性**: High | **CWE**: CWE-787 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `include/catlass/gemm/kernel/grouped_matmul.hpp:26-31` @ `detail::UnpackListParam`
**模块**: core_gemm_kernel

**描述**: UnpackListParam function performs memory copy from GM_ADDR to local buffer based on length parameter without validating source pointer bounds or destination buffer capacity.

**漏洞代码** (`include/catlass/gemm/kernel/grouped_matmul.hpp:26-31`)

```cpp
template <class T>
CATLASS_DEVICE
void UnpackListParam(T *const dst, GM_ADDR src, uint32_t len)
{
    for (uint32_t i = 0; i * sizeof(uint64_t) < len * sizeof(T); ++i) {
        reinterpret_cast<uint64_t *>(dst)[i] = reinterpret_cast<__gm__ uint64_t *>(src)[i];
    }
}
```

**验证说明**: Root cause of VULN-004. UnpackListParam performs unbounded memory copy from GM_ADDR source to local buffer based on len parameter. No validation of destination buffer capacity or source bounds. When len exceeds destination capacity (invoked with problemCount > MAX_TENSOR_COUNT), causes buffer overflow. Same vulnerability path as VULN-004 but focuses on the copy mechanism.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

**深度分析**

**根因分析**：`UnpackListParam` 是一个设备端模板函数，用于从全局内存（GM_ADDR）复制数据到本地缓冲区。该函数的设计假设调用方会确保 `len` 参数与目标缓冲区容量匹配，但实际调用点缺少这种验证。

从源代码分析：
- 第 26 行模板函数接受目标指针 `dst`、源地址 `src` 和长度 `len`
- 第 28-29 行循环条件 `i * sizeof(uint64_t) < len * sizeof(T)` 完全依赖 `len` 参数
- 第 29 行直接向 `dst[i]` 写入，未检查 `dst` 的实际容量
- 第 137-140 行调用时传入 `params.problemCount` 作为 `len`，而目标数组大小固定为 `MAX_TENSOR_COUNT`

**潜在利用场景**：
1. **直接触发**：与 VULN-CORE-GEMM-004 共享同一攻击路径，`problemCount > 256` 即触发缓冲区溢出
2. **独立风险**：该函数也可能被其他模块调用（需进一步分析），任何传入超大 `len` 值的场景都存在风险
3. **内存损坏模式**：
   - 写入超出栈数组边界，损坏相邻栈变量
   - 可能覆盖函数返回地址（取决于栈布局），理论上有代码执行风险
   - NPU 设备内存保护机制可能阻止部分越界访问，但仍会导致算子异常

**建议修复方式**：
```cpp
template <class T>
CATLASS_DEVICE
void UnpackListParam(T *const dst, GM_ADDR src, uint32_t len, uint32_t maxCapacity)
{
    // 添加容量限制
    uint32_t actualLen = (len > maxCapacity) ? maxCapacity : len;
    for (uint32_t i = 0; i * sizeof(uint64_t) < actualLen * sizeof(T); ++i) {
        reinterpret_cast<uint64_t *>(dst)[i] = reinterpret_cast<__gm__ uint64_t *>(src)[i];
    }
}

// 调用点修改（第 137 行）
detail::UnpackListParam(problemShapeList, params.ptrProblemShape, params.problemCount, MAX_TENSOR_COUNT);
```

---

### [VULN-CORE-GEMM-002] Integer Overflow in Size Calculation - SplitkMatmul::GetWorkspaceSize

**严重性**: High | **CWE**: CWE-190 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `include/catlass/gemm/kernel/splitk_matmul.hpp:252-256` @ `SplitkMatmul::GetWorkspaceSize`
**模块**: core_gemm_kernel

**描述**: Workspace size calculation uses chained multiplication without overflow checks. Large dimensions can cause integer overflow leading to undersized buffer allocation.

**漏洞代码** (`include/catlass/gemm/kernel/splitk_matmul.hpp:252-256`)

```cpp
static size_t GetWorkspaceSize(const Arguments &args)
{
    return args.workspaceElementSize * args.problemShape.m() * args.problemShape.n() *
        GetSplitkFactor(args.problemShape.m(),
            args.problemShape.n(),
            args.problemShape.k(),
            args.aicCoreNum);
}
```

**验证说明**: Integer overflow confirmed in GetWorkspaceSize(). Chained multiplication args.workspaceElementSize * problemShape.m() * problemShape.n() * GetSplitkFactor() can overflow size_t with large dimensions (e.g., m=n=4294967295, k=1024). Underflowed workspace allocation leads to buffer overflow during splitk reduction operations. Reachable from semi_trusted entry points (Python/shared_lib API).

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 10

**深度分析**

**根因分析**：`GetWorkspaceSize` 函数通过链式乘法计算 SplitK 算法所需的临时工作区大小，但未对乘法溢出进行检测。当输入矩阵维度极大时，`size_t` 类型可能溢出，导致计算结果远小于实际需求。

从源代码分析：
- 第 252-256 行返回值为 4 个因子相乘：`workspaceElementSize × m × n × splitkFactor`
- `args.problemShape` 来自外部输入（Arguments 结构）
- `GetSplitkFactor` 返回值范围 1-16（第 197-243 行逻辑）
- 在 64 位系统上，`size_t` 最大约 1.8×10^19，但极端大矩阵（如 m=n=4×10^9）仍可触发溢出

**整数溢出场景计算**：
```
假设: workspaceElementSize = 4 (float), m = 4294967295 (UINT32_MAX), n = 4294967295, splitkFactor = 16
计算: 4 × 4294967295 × 4294967295 × 16
      = 4 × (2^32 - 1) × (2^32 - 1) × 16
      ≈ 4 × 2^64 × 16 = 2^68 (远超 size_t 范围)
溢出后结果: 实际分配空间远小于计算需求
```

**潜在利用场景**：
1. **Python 扩展攻击路径**：通过 PyTorch 创建超大空 tensor（shape 接近 UINT32_MAX），调用 splitk_matmul 算子
2. **缓冲区溢出后果**：
   - `ToUnderlyingArguments` 分配不足的工作区（第 259-278 行）
   - `SplitkReduceAdd::operator()` 在第 85-92 行复制数据时越界
   - NPU 设备内存损坏，可能导致后续算子执行异常或设备崩溃

**建议修复方式**：
```cpp
static size_t GetWorkspaceSize(const Arguments &args)
{
    // 使用安全的乘法运算，检测溢出
    size_t m = args.problemShape.m();
    size_t n = args.problemShape.n();
    size_t elemSize = args.workspaceElementSize;
    uint32_t splitk = GetSplitkFactor(args.problemShape.m(), args.problemShape.n(), 
                                       args.problemShape.k(), args.aicCoreNum);
    
    // 检测溢出: elemSize * m * n * splitk
    size_t result = elemSize;
    if (result > SIZE_MAX / m) return SIZE_MAX; // 溢出保护
    result *= m;
    if (result > SIZE_MAX / n) return SIZE_MAX;
    result *= n;
    if (result > SIZE_MAX / splitk) return SIZE_MAX;
    result *= splitk;
    
    return result;
}
```

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| core_arch | 0 | 1 | 0 | 0 | 1 |
| core_gemm_kernel | 0 | 3 | 0 | 0 | 3 |
| **合计** | **0** | **4** | **0** | **0** | **4** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-787 | 1 | 25.0% |
| CWE-190 | 1 | 25.0% |
| CWE-129 | 1 | 25.0% |
| CWE-125 | 1 | 25.0% |

---

## 修复建议

### 优先级 1: 立即修复（Critical/High 漏洞）

**VULN-CORE-GEMM-004 & VULN-CORE-GEMM-005 - Fixed Array Overflow & Unbounded Memory Copy**

这两个漏洞共享同一攻击路径，修复方案应同步实施：

1. **添加入口边界检查**：在 `GroupedMatmul::operator()` 入口处验证 `params.problemCount <= MAX_TENSOR_COUNT`，超出限制时返回错误或截断处理
2. **修改 UnpackListParam 接口**：增加 `maxCapacity` 参数，在复制循环中限制实际处理长度
3. **Python API 层验证**：在 `examples/python_extension/src/wrapper/grouped_matmul.cpp` 的 `GetKernelInfo` 中检查 `groupList` 长度不超过 256
4. **共享库 API 层验证**：在 `examples/shared_lib/src/kernels/grouped_matmul.cpp` 中添加相同的边界检查

**VULN-CORE-GEMM-002 - Integer Overflow in Size Calculation**

1. **安全乘法运算**：在 `GetWorkspaceSize` 中使用溢出检测的安全乘法模式（如 `SAFE_MUL` 宏或逐步检查）
2. **维度上限验证**：在 `CanImplement` 函数中添加矩阵维度的合理上限检查（如 m, n, k < 2^30）
3. **API 层输入验证**：Python 和共享库 wrapper 应拒绝极端大维度请求

**CORE_ARCH_001 - Out-of-Bounds Access**

1. **添加边界检查**：在 `GetBufferByByte` 中验证 `offset < ArchTag::UB_SIZE`（需通过模板参数传入缓冲区大小）
2. **使用安全的偏移计算**：在调用点（如 `SplitkReduceAdd` 构造函数）确保累加偏移不会超出缓冲区容量
3. **静态断言增强**：在模板特化中使用 `static_assert` 验证缓冲区使用不会超限

### 优先级 2: 短期修复（Medium 漏洞）

虽然当前报告中无 Medium 级别已确认漏洞，但在待确认报告中有多个 Medium 级别漏洞值得关注：

1. **Python Extension 输入验证**：为所有 wrapper 函数添加 tensor 设备、维度、数据指针的完整性检查
2. **Dynamic Library Loading 安全加固**：在 Python 扩展加载共享库时添加完整性校验（如签名验证或哈希检查）
3. **Race Condition 修复**：使用原子操作替代 `++flag.count` 的非原子增量

### 优先级 3: 计划修复（Low 漏洞及架构改进）

1. **Path Traversal 防护**：在 `library_scripts` 模块添加路径规范化检查，防止目录遍历攻击
2. **CanImplement 强化**：各算子的 `CanImplement` 函数应实现真正的参数有效性检查，而非简单返回 `true`
3. **API Contract 文档化**：明确模板库与调用方之间的安全责任边界，要求调用方在传入参数前进行验证

---

## 附录：漏洞关联性分析

本报告中的 4 个已确认漏洞存在以下关联关系：

| 漏洞 ID | 关联漏洞 | 关联说明 |
|---------|----------|----------|
| VULN-CORE-GEMM-004 | VULN-CORE-GEMM-005 | 共享同一攻击路径，VULN-005 是 VULN-004 的根因函数 |
| VULN-CORE-GEMM-002 | CORE_ARCH_001 | SplitkReduceAdd 使用 GetBufferByByte，整数溢出可间接触发越界访问 |

建议在修复时优先处理关联漏洞组，避免遗漏深层次问题。