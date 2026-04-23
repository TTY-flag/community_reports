# 漏洞扫描报告 — 待确认漏洞

**项目**: ops-nn (华为 CANN 神经网络算子库)
**扫描时间**: 2026-04-22T05:07:13.750Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## Executive Summary

本次安全扫描针对华为 CANN (Compute Architecture for Neural Networks) ops-nn 算子库中的 hash 模块进行了深度分析。hash 模块作为 CANN 框架的核心组件，负责嵌入向量哈希表的查找与插入操作，是推荐系统、大语言模型训练等场景的关键基础设施。

### 扫描结果概述

扫描发现 **8 个待确认漏洞**，其中 1 个 High 级别，6 个 Medium 级别，1 个 Low 级别。所有漏洞集中在 `embedding_hash_table_lookup_or_insert` 算子实现中，涉及哈希表内核计算的内存安全、整数溢出和输入验证问题。

| 指标 | 数值 |
|------|------|
| 有效漏洞总数 | 8 |
| High 严重性 | 1 (12.5%) |
| Medium 严重性 | 6 (75.0%) |
| Low 严重性 | 1 (12.5%) |
| 涉及模块 | hash (100%) |
| 涉及文件 | 3 个核心文件 |

### 关键风险点

**最严重漏洞**：OPSNN_HASH_ARRAY_OOB_001（数组越界写入，置信度 65）

该漏洞位于哈希表查找内核的主循环中，当处理大量 embedding key 时，数组索引计算 `i * embeddingDim + j` 可能发生整数溢出，导致写入超出分配的 values 缓冲区边界。攻击者可通过构造极端的 tensor shape 参数触发此漏洞，造成内核内存破坏，潜在影响包括：

* 设备侧内核崩溃导致训练任务中断
* 内存污染可能影响同一设备上的其他模型计算
* 在特定条件下可能构成代码执行风险

**系统性缺陷**：所有漏洞源于同一设计模式

6 个漏洞（除 NULL_PTR 外）均源于对用户可控参数缺乏边界校验。`embeddingDim` 和 `keyNum` 通过 ACL NN API 间接传入内核，但内核层未进行二次校验。这种"信任上游"的设计假设在内核级代码中存在风险，因为 ACL NN API 的校验逻辑可能存在遗漏或被绕过。

### 建议优先级

| 优先级 | 漏洞 ID | 风险描述 |
|--------|---------|----------|
| P0 | OPSNN_HASH_ARRAY_OOB_001 | 内存破坏，可导致内核崩溃 |
| P1 | OPSNN_HASH_DIV_ZERO_001 | 除零异常，导致算子执行失败 |
| P1 | OPSNN_HASH_INT_OVERFLOW_001/002/003 | 整数溢出，间接导致内存越界 |
| P2 | OPSNN_HASH_NULL_PTR_001 | NULL 检查不完整，依赖上游校验 |
| P3 | OPSNN_HASH_KEYNUM_LOOP_001 | 循环边界过大，DoS 风险 |

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 6 | 66.7% |
| POSSIBLE | 2 | 22.2% |
| FALSE_POSITIVE | 1 | 11.1% |
| **总计** | **9** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 1 | 12.5% |
| Medium | 6 | 75.0% |
| Low | 1 | 12.5% |
| **有效漏洞总计** | **8** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[OPSNN_HASH_ARRAY_OOB_001]** Out-of-bounds Write (High) - `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/kernel_lookup_or_insert_general.h:42` @ `ComputeLookupOrInsert` | 置信度: 65
2. **[OPSNN_HASH_DIV_ZERO_001]** Division by Zero (Medium) - `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/kernel_lookup_or_insert_general.h:60` @ `ComputeLookupOrInsert` | 置信度: 65
3. **[OPSNN_HASH_ARRAY_OOB_002]** Out-of-bounds Read (Medium) - `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/kernel_lookup_or_insert_general.h:121` @ `ComputeLookupOrInsert` | 置信度: 65
4. **[OPSNN_HASH_INT_OVERFLOW_001]** Integer Overflow (Medium) - `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/kernel_lookup_or_insert_general.h:61` @ `ComputeLookupOrInsert` | 置信度: 60
5. **[OPSNN_HASH_INT_OVERFLOW_002]** Integer Overflow (Medium) - `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/kernel_lookup_or_insert_general.h:104` @ `ComputeLookupOrInsert` | 置信度: 60
6. **[OPSNN_HASH_BUCKETSIZE_OVERFLOW_001]** Integer Overflow (Medium) - `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/lookup_or_insert_base.h:106` @ `KernelLookupOrInsertBase::Init` | 置信度: 60
7. **[OPSNN_HASH_NULL_PTR_001]** NULL Pointer Dereference (Medium) - `hash/embedding_hash_table_lookup_or_insert/op_kernel/embedding_hash_table_lookup_or_insert.cpp:84` @ `KernelLookupOrInsertBase::Init` | 置信度: 50
8. **[OPSNN_HASH_KEYNUM_LOOP_001]** Improper Input Validation (Low) - `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/kernel_lookup_or_insert_general.h:36` @ `ComputeLookupOrInsert` | 置信度: 55

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `aclnn_embedding_hash_table_lookup_or_insert` | api_function | untrusted_network | 用户通过 ACL NN API 调用算子 | ACL NN API workspace size calculation - user input validation |
| `aclnn_embedding_hash_table_lookup_or_insert` | api_function | untrusted_network | 用户通过 ACL NN API 调用算子 | ACL NN API execution function - kernel dispatch |
| `embedding_hash_table_lookup_or_insert` | kernel_function | semi_trusted | 内核入口，参数经 tiling 传递 | APT kernel implementation - device-side execution |
| TilingData | tiling_function | semi_trusted | 由 host 端计算并传递 | Tiling strategy calculation - memory block planning |

**攻击路径**：

```
用户 Tensor 参数 (keys, values, embeddingDim, keyNum)
    ↓
ACL NN API (aclnn_embedding_hash_table_lookup_or_insert)
    ↓
Tiling 计算 (host 端)
    ↓
TilingData 结构体
    ↓
内核初始化 (Init)
    ↓
内核执行 (ComputeLookupOrInsert)
    ↓
内存操作 (pValues, pTable)
```

---

## 3. High 漏洞详细分析 (Top 5)

### [OPSNN_HASH_ARRAY_OOB_001] Out-of-bounds Write - ComputeLookupOrInsert

**严重性**: High | **CWE**: CWE-787 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/kernel_lookup_or_insert_general.h:42` @ `ComputeLookupOrInsert`

#### 深度分析

**漏洞触发条件**：

```c
// 第 36-42 行的循环结构
for (uint32_t i = threadYIdx + blockIdx * threadYNum; i < keyNum; i += blockNum * threadYNum) {
    int64_t insertKey = pKeys[i];
    if constexpr (WITH_FILTERING_LOGIC) {
        if (insertKey == filterKey) {
            if (defaultKeyOrValue == 0) {
                for (size_t j = threadXIdx; j < embeddingDim; j += threadXNum) {
                    pValues[i * embeddingDim + j] = defaultValue; // ← 越界写入点
                }
            }
        }
    }
}
```

**漏洞根因**：

1. `keyNum` 来自 `tilingData.keyNum`，未经内核层校验
2. `embeddingDim` 来自 `tilingData.embeddingDim`，同样未经校验
3. 索引计算 `i * embeddingDim + j`：
   * `i` 为 `uint32_t`，理论上最大可达 `UINT32_MAX`
   * `embeddingDim` 为 `int64_t`，若接近 `SIZE_MAX/2`，乘法结果溢出
   * 即使不溢出，`i * embeddingDim` 可能远超 `pValues` 缓冲区分配大小

**实际风险场景**：

假设典型训练场景中：
* `embeddingDim = 1024`（推荐系统常用）
* `keyNum = 100000`（批量查找）
* `pValues` 分配大小 = `keyNum * embeddingDim * sizeof(float)`

若攻击者通过恶意构造 tensor shape：
* `embeddingDim` 设置为 `INT64_MAX/100000 ≈ 9.2e13`
* 实际分配的 values 缓冲区远小于索引计算结果
* 写入操作将破坏内核内存空间

**现有缓解措施**：无。内核代码完全依赖 ACL NN API 层的参数校验。

**影响范围**：
* 设备侧内核内存污染
* 可能触发设备异常或训练任务崩溃
* 多租户场景下可能影响同设备其他任务

---

## 4. Medium 漏洞详细分析

### [OPSNN_HASH_DIV_ZERO_001] Division by Zero - ComputeLookupOrInsert

**严重性**: Medium | **CWE**: CWE-369 | **置信度**: 65/100 | **状态**: LIKELY

**位置**: `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/kernel_lookup_or_insert_general.h:60`

#### 深度分析

**漏洞代码**：

```c
// 第 60 行：哈希索引计算
currIdx = static_cast<size_t>(MurmurHash3(pKeys + i, sizeof(int64_t), 0) % tableSize);
```

**触发条件**：

`tableSize` 来自 `tilingData.size`（第 94 行：`tableSize_ = data.size`），若 `size == 0`：
* `MurmurHash3(...) % 0` 触发除零异常
* 导致内核执行失败，设备侧算子无法完成

**上游参数来源追踪**：

```
tilingData.size ← Tiling 计算 ← host 端 ← ACL NN API ← 用户参数
```

`size` 通常对应哈希表容量，应由 `init_embedding_hash_table` 算子初始化。但在以下场景可能为 0：

1. 哈希表未正确初始化
2. Tiling 计算逻辑错误
3. 异常的 hash table handle

**影响**：算子执行失败，不影响内存安全，但会导致训练流程中断。

---

### [OPSNN_HASH_ARRAY_OOB_002] Out-of-bounds Read - ComputeLookupOrInsert

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 65/100 | **状态**: LIKELY

**位置**: `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/kernel_lookup_or_insert_general.h:121`

#### 深度分析

**漏洞代码**：

```c
// 第 118-122 行：查找成功后的值读取
for (size_t j = threadXIdx; j < embeddingDim; j += threadXNum) {
    __gm__ float* pCurrValue = reinterpret_cast<__gm__ float*>(pCurrBucket + VALUES_OFFSET) + j;
    pValues[i * embeddingDim + j] = *pCurrValue; // ← 从 pCurrValue 读取，写入 pValues
}
```

**与 OOB_001 的区别**：

* OOB_001：写入新 key 时填充默认值（初始化场景）
* OOB_002：查找成功后读取哈希桶中的值

**双重风险**：

1. `*pCurrValue` 读取：`pCurrBucket + VALUES_OFFSET + j` 的偏移计算可能超出哈希桶边界
2. `pValues[i * embeddingDim + j]` 写入：同 OOB_001 的索引溢出风险

**攻击向量**：

构造大量查找请求，使 `currIdx * bucketSize` 计算指向哈希表末尾区域，读取越界内存。

---

### [OPSNN_HASH_INT_OVERFLOW_001] Integer Overflow - ComputeLookupOrInsert

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY

**位置**: `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/kernel_lookup_or_insert_general.h:61`

#### 深度分析

**漏洞代码**：

```c
// 第 60-61 行：哈希桶定位
currIdx = static_cast<size_t>(MurmurHash3(pKeys + i, sizeof(int64_t), 0) % tableSize);
pCurrBucket = pTable + currIdx * bucketSize;
```

**溢出分析**：

* `currIdx`：由 `hash % tableSize` 得出，理论最大值为 `tableSize - 1`
* `bucketSize`：由 `VALUES_OFFSET + embeddingDim * sizeof(float)` 计算（见 lookup_or_insert_base.h:106）

若 `embeddingDim` 过大：
```c
bucketSize = VALUES_OFFSET + embeddingDim * sizeof(float)
           ≈ 24 + embeddingDim * 4
```

当 `embeddingDim > SIZE_MAX/4`（在 64 位系统上约为 `4.6e18`），乘法溢出。

**连锁效应**：

`currIdx * bucketSize` 若溢出为小值，`pCurrBucket` 指向错误位置，后续读写操作产生不可预期行为。

---

### [OPSNN_HASH_INT_OVERFLOW_002] Integer Overflow - ComputeLookupOrInsert (Collision Resolution)

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY

**位置**: `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/kernel_lookup_or_insert_general.h:104`

#### 深度分析

**漏洞代码**：

```c
// 第 103-104 行：线性探测碰撞处理
currIdx = (currIdx + 1) % tableSize;
pCurrBucket = pTable + currIdx * bucketSize;
```

**与 INT_OVERFLOW_001 的关系**：

同一计算模式在碰撞解决循环中重复出现。每次探测都可能触发溢出。

**探测循环结构**：

```c
while (detectCounts < tableSize) {
    // ... 尝试插入或查找 ...
    currIdx = (currIdx + 1) % tableSize;
    pCurrBucket = pTable + currIdx * bucketSize; // ← 每轮迭代重复计算
}
```

若哈希表负载高、碰撞频繁，此计算被执行多次，增加触发概率。

---

### [OPSNN_HASH_BUCKETSIZE_OVERFLOW_001] Integer Overflow - KernelLookupOrInsertBase::Init

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY

**位置**: `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/lookup_or_insert_base.h:106`

#### 深度分析

**漏洞代码**：

```c
// lookup_or_insert_base.h 第 106 行
bucketSize_ = RoundUpTo8<size_t>(static_cast<size_t>(VALUES_OFFSET + embeddingDim_ * sizeof(float)));
```

**初始化阶段的溢出风险**：

此计算发生在 `Init` 函数中，在内核执行前完成。若溢出：

1. `bucketSize_` 获得一个错误的小值
2. 哈希表中的 bucket 实际分配空间不足
3. 后续 `ComputeLookupOrInsert` 中的读写操作越界

**数据流**：

```
tilingData.embeddingDim → embeddingDim_ → embeddingDim_ * sizeof(float) → bucketSize_
```

**RoundUpTo8 的影响**：

溢出后的小值经过 `RoundUpTo8` 对齐，无法修复溢出问题，反而可能使错误值"看起来正常"。

---

### [OPSNN_HASH_NULL_PTR_001] NULL Pointer Dereference - KernelLookupOrInsertBase::Init

**严重性**: Medium | **CWE**: CWE-476 | **置信度**: 50/100 | **状态**: POSSIBLE

**位置**: `hash/embedding_hash_table_lookup_or_insert/op_kernel/embedding_hash_table_lookup_or_insert.cpp:84-92`

#### 深度分析

**现有检查**：

```c
// embedding_hash_table_lookup_or_insert.cpp 第 27-34 行
if (workspace == nullptr) {
    return;
}
SetSysWorkspace(workspace);
GM_ADDR userWS = GetUserWorkspace(workspace);
if (userWS == nullptr) {
    return;
}
```

**缺失检查**：

```c
// 第 84-92 行：Init 函数中
int64_t handleAddr = *reinterpret_cast<__gm__ int64_t*>(tableHandles); // ← 未检查 tableHandles
pTableHandle_ = reinterpret_cast<__gm__ int64_t*>(handleAddr);
int64_t tableAddr = *pTableHandle_; // ← 未检查 pTableHandle_
pTable_ = reinterpret_cast<__gm__ uint8_t*>(tableAddr);
pKeys_ = reinterpret_cast<__gm__ int64_t*>(keys);   // ← 未检查 keys
pValues_ = reinterpret_cast<__gm__ float*>(values); // ← 未检查 values
```

**风险评估**：

ACL NN API 层应校验 tensor 参数有效性。但若上游校验存在遗漏：

* `tableHandles` 为 NULL → 解引用失败
* `keys` 或 `values` 为 NULL → 后续内核操作崩溃

**置信度降低原因**：部分检查存在（workspace），降低完全无防护的评估。

---

## 5. Low 漏洞 (1)

### [OPSNN_HASH_KEYNUM_LOOP_001] Improper Input Validation - ComputeLookupOrInsert

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE

**位置**: `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/kernel_lookup_or_insert_general.h:36`

**漏洞代码**：

```c
for (uint32_t i = threadYIdx + blockIdx * threadYNum; i < keyNum; i += blockNum * threadYNum)
```

**影响**：

过大的 `keyNum` 导致循环执行时间过长，但不直接造成内存破坏。循环工作分散到多个线程块，单一线程的迭代次数有限。

---

## 6. 修复建议 (Remediation Recommendations)

### 优先级 P0：OPSNN_HASH_ARRAY_OOB_001

**修复方案**：在内核层添加参数边界校验

```c
// 在 ComputeLookupOrInsert 函数开头添加
// 1. 校验 keyNum 合理性
if (keyNum > MAX_REASONABLE_KEYNUM || keyNum <= 0) {
    return; // 或设置错误标志
}

// 2. 校验 embeddingDim 合理性
if (embeddingDim > MAX_EMBEDDING_DIM || embeddingDim <= 0) {
    return;
}

// 3. 检查索引计算是否会溢出
size_t maxIndex = static_cast<size_t>(keyNum) * static_cast<size_t>(embeddingDim);
if (maxIndex > SIZE_MAX / sizeof(float)) {
    return; // 索引溢出风险
}

// 4. 与缓冲区实际大小比对（需从 tilingData 传递 values 缓冲区大小）
if (maxIndex > valuesBufferSize) {
    return; // 越界风险
}
```

**建议常量定义**：

```c
constexpr int64_t MAX_REASONABLE_KEYNUM = 10000000; // 单次查找上限
constexpr int64_t MAX_EMBEDDING_DIM = 10000;        // embedding 维度上限
```

### 优先级 P1：OPSNN_HASH_DIV_ZERO_001

**修复方案**：除零保护

```c
// 在 hash 索引计算前添加
if (tableSize <= 0) {
    return; // 或返回查找失败
}
currIdx = static_cast<size_t>(MurmurHash3(pKeys + i, sizeof(int64_t), 0) % tableSize);
```

### 优先级 P1：OPSNN_HASH_INT_OVERFLOW_001/002/003

**修复方案**：乘法溢出检测

```c
// 在 bucketSize 计算时使用安全乘法
// lookup_or_insert_base.h
size_t embeddingBytes = SafeMul(embeddingDim_, sizeof(float));
if (embeddingBytes == SIZE_MAX) { // 溢出标志
    return;
}
bucketSize_ = RoundUpTo8<size_t>(VALUES_OFFSET + embeddingBytes);

// 或使用编译器内置函数
#if defined(__GNUC__)
size_t embeddingBytes;
if (__builtin_mul_overflow(embeddingDim_, sizeof(float), &embeddingBytes)) {
    return; // 溢出发生
}
#endif
```

**安全乘法辅助函数**：

```c
__aicore__ inline size_t SafeMul(size_t a, size_t b) {
    if (a == 0 || b == 0) return 0;
    if (a > SIZE_MAX / b) return SIZE_MAX; // 溢出标记
    return a * b;
}
```

### 优先级 P2：OPSNN_HASH_NULL_PTR_001

**修复方案**：完善 NULL 检查

```c
// 在 embedding_hash_table_lookup_or_insert.cpp 的 Init 调用前
if (tableHandle == nullptr || keys == nullptr || values == nullptr) {
    return;
}

// 或在 Init 函数内部添加
if (tableHandles == nullptr) {
    return;
}
int64_t handleAddr = *reinterpret_cast<__gm__ int64_t*>(tableHandles);
if (handleAddr == 0) {
    return;
}
```

### 优先级 P3：OPSNN_HASH_KEYNUM_LOOP_001

**修复方案**：循环边界限制

```c
// 在 Tiling 计算阶段限制 keyNum
// 或在内核中添加软限制
keyNum = min(keyNum, MAX_KEYNUM_PER_KERNEL_LAUNCH);
```

### 系统性改进建议

1. **TilingData 结构扩展**：添加 `valuesBufferSize`、`tableBufferSize` 字段，供内核校验使用

2. **参数校验层统一设计**：
   * Host 端 Tiling 计算：执行初步校验，限制极端参数
   * Kernel 端 Init：二次校验，确保内核层安全
   * 双层校验避免单点依赖

3. **安全算子模板**：为所有涉及用户可控参数的算子建立统一的安全校验框架

4. **测试覆盖**：
   * 极端参数边界测试（embeddingDim = SIZE_MAX/4, keyNum = INT64_MAX）
   * 零值参数测试（tableSize = 0, embeddingDim = 0）
   * NULL 指针测试

---

## 7. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| hash | 0 | 1 | 6 | 1 | 8 |
| **合计** | **0** | **1** | **6** | **1** | **8** |

## 8. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-190 | 3 | 37.5% |
| CWE-787 | 1 | 12.5% |
| CWE-476 | 1 | 12.5% |
| CWE-369 | 1 | 12.5% |
| CWE-20 | 1 | 12.5% |
| CWE-125 | 1 | 12.5% |

---

## 附录：漏洞 ID 索引

| ID | 类型 | 严重性 | 置信度 | 文件 | 行号 |
|----|------|--------|--------|------|------|
| OPSNN_HASH_ARRAY_OOB_001 | Out-of-bounds Write | High | 65 | kernel_lookup_or_insert_general.h | 42 |
| OPSNN_HASH_DIV_ZERO_001 | Division by Zero | Medium | 65 | kernel_lookup_or_insert_general.h | 60 |
| OPSNN_HASH_ARRAY_OOB_002 | Out-of-bounds Read | Medium | 65 | kernel_lookup_or_insert_general.h | 121 |
| OPSNN_HASH_INT_OVERFLOW_001 | Integer Overflow | Medium | 60 | kernel_lookup_or_insert_general.h | 61 |
| OPSNN_HASH_INT_OVERFLOW_002 | Integer Overflow | Medium | 60 | kernel_lookup_or_insert_general.h | 104 |
| OPSNN_HASH_BUCKETSIZE_OVERFLOW_001 | Integer Overflow | Medium | 60 | lookup_or_insert_base.h | 106 |
| OPSNN_HASH_NULL_PTR_001 | NULL Pointer Dereference | Medium | 50 | embedding_hash_table_lookup_or_insert.cpp | 84 |
| OPSNN_HASH_KEYNUM_LOOP_001 | Improper Input Validation | Low | 55 | kernel_lookup_or_insert_general.h | 36 |