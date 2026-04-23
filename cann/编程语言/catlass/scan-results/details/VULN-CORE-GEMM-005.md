# VULN-CORE-GEMM-005 漏洞分析报告

## 漏洞基本信息

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-CORE-GEMM-005 |
| **漏洞类型** | Unbounded Memory Copy (CWE-787: Out-of-bounds Write) |
| **严重程度** | High (原始: Medium, 验证升级) |
| **文件位置** | include/catlass/gemm/kernel/grouped_matmul.hpp |
| **函数** | detail::UnpackListParam |
| **行范围** | 26-31 |
| **CWE** | CWE-787 (Out-of-bounds Write) |

---

## 1. 漏洞真实性验证

### 1.1 确认结果: **真实漏洞**

### 1.2 漏洞代码分析

**漏洞函数 UnpackListParam** (grouped_matmul.hpp:26-31):

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

**关键问题**:
1. `dst` 是栈上分配的固定大小缓冲区指针
2. `src` 是全局内存地址 (GM_ADDR)，由调用方传入
3. `len` 是复制长度参数，完全由用户控制
4. **无任何边界检查**: 函数不验证 `len` 是否超过 `dst` 的容量
5. 按 uint64_t (8字节) 块进行逐字复制，没有安全终止条件

**调用点** (grouped_matmul.hpp:131-140):

```cpp
// 固定大小的栈缓冲区
static constexpr uint32_t MAX_TENSOR_COUNT = 256;  // 第55行定义

GemmCoord problemShapeList[MAX_TENSOR_COUNT];  // 仅256个元素
LayoutA layoutAList[MAX_TENSOR_COUNT];
LayoutB layoutBList[MAX_TENSOR_COUNT];
LayoutC layoutCList[MAX_TENSOR_COUNT];

// 使用用户控制的 problemCount 进行复制
detail::UnpackListParam(problemShapeList, params.ptrProblemShape, params.problemCount);
detail::UnpackListParam(layoutAList, params.ptrLayoutA, params.problemCount);
detail::UnpackListParam(layoutBList, params.ptrLayoutB, params.problemCount);
detail::UnpackListParam(layoutCList, params.ptrLayoutC, params.problemCount);
```

**触发条件**: 当 `params.problemCount > 256` 时发生栈缓冲区溢出。

---

## 2. 攻击路径分析

### 2.1 完整攻击路径

```
Python API 入口
└── pybind_bindings.cpp:25
│   └── grouped_matmul(mat1, mat2, groupList, outDType, transA, transB, splitK)
│
├── catlass_kernel_wrapper.cpp:46-61
│   └── RunGroupedMatmul(...)
│       └── GroupedMatmulLike::GetKernelInfo(mat1, mat2, groupList, ...)
│           │
│           └── grouped_matmul.cpp:33 [关键: 无验证]
│               └── kernelInfo.g = groupListVec.size()  ← 用户控制!
│
├── grouped_matmul.cpp:81
│   └── GroupedMatmul(blockNum, stream, kernelInfo)
│       └── GroupedMatmulImpl<...>(blockNum, stream, kernelInfo)
│           └── MatmulKernel::Arguments arguments{..., problemCount, ...}
│
└── grouped_matmul.hpp:129-140 [漏洞触发点]
    └── operator()<AscendC::AIC>(params)
        └── 栈分配: GemmCoord problemShapeList[MAX_TENSOR_COUNT] (256)
        └── detail::UnpackListParam(problemShapeList, src, problemCount)
            └── [溢出] 当 problemCount > 256
```

### 2.2 关键数据流

```
groupList tensor (Python)
    → groupListVec.size() → kernelInfo.g → problemCount → params.problemCount
    → UnpackListParam(dst, src, problemCount)
    → 栈溢出
```

---

## 3. 漏洞触发条件分析

### 3.1 len 参数来源

**Python 层**:
```python
# 用户可以创建任意大小的 groupList tensor
groupList = torch.tensor([100, 200, 300, ...], dtype=torch.int64)  # size 可控
result = torch_catlass.grouped_matmul(mat1, mat2, groupList, ...)
```

**Wrapper 层** (grouped_matmul.cpp:30-33):
```cpp
at::Tensor groupListHost = groupList.to(torch::kCPU).to(torch::kInt64);
std::vector<int64_t> groupListVec(groupListHost.data_ptr<int64_t>(),
                                  groupListHost.data_ptr<int64_t>() + groupListHost.numel());
kernelInfo.g = groupListVec.size();  // ← 直接使用 size，无上限检查!
```

**无任何验证**: 没有检查 `groupListVec.size()` 是否超过 MAX_TENSOR_COUNT (256)。

### 3.2 触发条件

| 条件 | 描述 |
|------|------|
| **必要条件** | groupList tensor 元素数量 > 256 |
| **攻击向量** | Python API 调用时传入超大 groupList |
| **最小触发值** | problemCount >= 257 |

### 3.3 CanImplement 检查缺失

(grouped_matmul.hpp:97-100):
```cpp
static bool CanImplement(const Arguments &args)
{
    return true;  // ← 永远返回 true，无任何验证!
}
```

---

## 4. 漏洞影响分析

### 4.1 缓冲区大小计算

**数据结构大小**:

| 类型 | 继承/成员 | 大小 |
|------|----------|------|
| GemmCoord | Coord<3, uint32_t> | 3 × 4 = 12 字节 |
| RowMajor/ColumnMajor | Coord<2, uint32_t> + Coord<2, int64_t> | 8 + 16 = 24 字节 |

**栈缓冲区分配**:

| 数组 | 元素大小 | 元素数量 | 总大小 |
|------|----------|----------|--------|
| problemShapeList | 12 字节 | 256 | 3,072 字节 |
| layoutAList | 24 字节 | 256 | 6,144 字节 |
| layoutBList | 24 字节 | 256 | 6,144 字节 |
| layoutCList | 24 字节 | 256 | 6,144 字节 |
| **总计** | | | **21,504 字节 (~21KB)** |

### 4.2 溢出影响范围

当 `problemCount = N > 256` 时:

**problemShapeList 溢出**:
- 正常写入: 256 × 12 = 3,072 字节
- 额外写入: (N - 256) × 12 字节
- 溢出覆盖: layoutAList 及后续栈数据

**单次 UnpackListParam 调用溢出量**:
```
overflow_bytes = (problemCount - MAX_TENSOR_COUNT) * sizeof(T)
```

**总溢出量** (4 次调用):
```
total_overflow = (problemCount - 256) × (12 + 24 + 24 + 24) 
               = (problemCount - 256) × 84 字节
```

### 4.3 影响分析

| 影响类型 | 描述 | 严重程度 |
|----------|------|----------|
| **栈缓冲区溢出** | 覆盖局部变量、返回地址等 | Critical |
| **控制流劫持** | 可能覆盖返回地址，实现代码执行 | High |
| **数据篡改** | 覆盖 layout 数据导致计算错误 | Medium |
| **内存破坏** | 破坏栈帧，导致程序崩溃 | High |

---

## 5. 可利用性评估

### 5.1 利用难度: Medium

| 因素 | 分析 |
|------|------|
| **攻击入口** | Python API (semi_trusted) - 需要访问权限 |
| **参数控制** | 完全可控 - groupList tensor 大小由用户决定 |
| **溢出可控性** | 部分 - 溢出数据来自全局内存，内容可控 |
| **利用稳定性** | 取决于栈布局和 NPU 执行环境 |

### 5.2 利用条件

1. **攻击者需要**: Python 代码执行权限
2. **触发方式**: 调用 grouped_matmul API 传入超大 groupList
3. **利用目标**: 栈溢出 → 控制流劫持 / 数据破坏

### 5.3 利用场景

- **场景 1**: 深度学习模型推理过程中的恶意输入
- **场景 2**: 模型训练过程中的 adversarial attack
- **场景 3**: 恶意 PyTorch 扩展库调用

---

## 6. PoC 构造思路

### 6.1 基础触发 PoC

```python
import torch
import torch_catlass

# 创建超大 groupList 触发溢出
# MAX_TENSOR_COUNT = 256, 传入 300 个元素

mat1 = torch.randn(1000, 128, dtype=torch.float16, device='npu:0')
mat2 = torch.randn(300, 128, 64, dtype=torch.float16, device='npu:0')

# groupList 元素数量 > 256
groupList = torch.tensor([10] * 300, dtype=torch.int64, device='npu:0')

# 触发漏洞
result = torch_catlass.grouped_matmul(
    mat1, mat2, groupList, 
    outDType='float16',
    transA=False,
    transB=False,
    splitK=False
)
```

### 6.2 精确溢出控制 PoC

```python
# 构造精确溢出以控制栈数据
overflow_size = 300 - 256  # 44 个额外元素

# 在全局内存中准备溢出数据
# 这些数据将被复制到栈上覆盖原有数据
 crafted_data = torch.tensor([...], dtype=torch.int64, device='npu:0')
# 利用 UnpackListParam 的逐字复制特性，精确控制栈上的值
```

### 6.3 漏洞验证步骤

1. 创建 groupList tensor，size = 300 (> 256)
2. 准备配套的 mat1, mat2 tensor
3. 调用 grouped_matmul API
4. 预期结果: NPU kernel 执行时栈溢出
5. 实际表现: 可能导致 kernel crash 或计算结果异常

---

## 7. 与 VULN-CORE-GEMM-004 的关系

### 7.1 关系定义

| 漏洞 ID | 关注层面 | 描述 |
|---------|----------|------|
| VULN-004 | **缓冲区定义问题** | 栈缓冲区固定为 256，但用于存储可变数量的数据 |
| VULN-005 | **复制机制问题** | UnpackListParam 函数无容量检查，执行无界复制 |

**关系**: VULN-005 是 VULN-004 的 **根因 (Root Cause)**

### 7.2 分层分析

```
VULN-004 (缓冲区溢出后果)
    ↑
    │ 因果关系
    │
VULN-005 (无界复制根因)
    ↑
    │ 设计缺陷
    │
设计层面: 缺少容量验证机制
```

### 7.3 修复建议覆盖

修复 VULN-005 会同时修复 VULN-004，因为:
- 在 UnpackListParam 中添加容量检查 → 防止无界复制
- 或在调用前验证 problemCount <= MAX_TENSOR_COUNT → 防止溢出调用

---

## 8. Mitigations 分析

### 8.1 当前状态

| 验证点 | 存在性 | 代码位置 |
|--------|--------|----------|
| Python 层验证 | **不存在** | grouped_matmul.cpp |
| Wrapper 层验证 | **不存在** | GetKernelInfo 函数 |
| Kernel 入口验证 | **不存在** | CanImplement 返回 true |
| UnpackListParam 验证 | **不存在** | 函数无边界检查 |

### 8.2 缺失的安全机制

1. **无输入验证**: `groupListVec.size()` 直接赋值给 `kernelInfo.g`
2. **无容量检查**: CanImplement 永远返回 true
3. **无边界验证**: UnpackListParam 不检查 len vs dst capacity
4. **无错误处理**: 溢出后无任何检测或恢复机制

---

## 9. 修复建议

### 9.1 立即修复 (High Priority)

**方案 A: 在 UnpackListParam 中添加容量检查**

```cpp
template <class T>
CATLASS_DEVICE
void UnpackListParam(T *const dst, GM_ADDR src, uint32_t len, uint32_t capacity)
{
    // 添加容量验证
    if (len > capacity) {
        // 错误处理: 截断或报错
        len = capacity;  // 安全截断
    }
    for (uint32_t i = 0; i * sizeof(uint64_t) < len * sizeof(T); ++i) {
        reinterpret_cast<uint64_t *>(dst)[i] = reinterpret_cast<__gm__ uint64_t *>(src)[i];
    }
}

// 调用时传入容量
detail::UnpackListParam(problemShapeList, params.ptrProblemShape, params.problemCount, MAX_TENSOR_COUNT);
```

**方案 B: 在 Wrapper 层验证**

```cpp
// grouped_matmul.cpp:33
kernelInfo.g = groupListVec.size();
if (kernelInfo.g > 256) {  // 添加验证
    throw std::runtime_error("groupList size exceeds maximum supported count (256)");
}
```

**方案 C: 在 CanImplement 中验证**

```cpp
static bool CanImplement(const Arguments &args)
{
    return args.problemCount <= MAX_TENSOR_COUNT;  // 添加验证
}
```

### 9.2 长期改进

1. **动态内存分配**: 使用动态分配替代固定栈数组
2. **文档说明**: 在 API 文档中明确参数限制
3. **输入验证框架**: 建立统一的参数验证机制

---

## 10. 总结

### 10.1 漏洞确认

| 项目 | 结论 |
|------|------|
| **真实性** | 确认真实漏洞 |
| **可触发** | 通过 Python API 可触发 |
| **影响范围** | 栈缓冲区溢出，潜在控制流劫持 |
| **严重程度** | High (升级) |

### 10.2 关键发现

1. **UnpackListParam 函数设计缺陷**: 无界内存复制，缺少容量验证
2. **参数传递链无验证**: 从 Python 到 Kernel 全链路无检查
3. **MAX_TENSOR_COUNT 约束被绕过**: 固定栈大小 vs 可变参数
4. **VULN-005 是 VULN-004 的根因**: 修复此漏洞可同时修复 VULN-004

### 10.3 建议优先级

| 优先级 | 建议 |
|--------|------|
| **P0** | 在 Wrapper 层添加 groupList size 验证 |
| **P1** | 在 CanImplement 中添加 problemCount 检查 |
| **P2** | UnpackListParam 添加容量参数和验证 |

---

**报告生成时间**: 2026-04-22
**分析工具**: Codebase Search Agent
