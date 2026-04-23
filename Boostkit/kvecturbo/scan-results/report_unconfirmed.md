# 漏洞扫描报告 — 待确认漏洞

**项目**: KVecTurbo
**扫描时间**: 2026-04-22T10:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 18 | 38.3% |
| POSSIBLE | 15 | 31.9% |
| FALSE_POSITIVE | 11 | 23.4% |
| CONFIRMED | 3 | 6.4% |
| **总计** | **47** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 1 | 3.1% |
| High | 15 | 46.9% |
| Medium | 15 | 46.9% |
| Low | 1 | 3.1% |
| **有效漏洞总计** | **32** | - |
| 误报 (FALSE_POSITIVE) | 11 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-CORE-002]** buffer_overflow (Critical) - `src/kvecturbo.cpp:1027` @ `ComputePQTable` | 置信度: 75
2. **[VULN-DF-CORE-003]** array_out_of_bounds (High) - `src/kvecturbo.cpp:1196` @ `ComputeVectorPQCode` | 置信度: 80
3. **[VULN-DF-CORE-008]** integer_overflow (High) - `src/kvecturbo.cpp:1226` @ `ComputeOne` | 置信度: 80
4. **[VULN-DF-CORE-018]** buffer_overflow (High) - `src/kvecturbo.cpp:512` @ `handleClusterOrInitializeRandomly` | 置信度: 80
5. **[VULN-DF-CORE-021]** cross_module_data_flow (High) - `src/kvecturbo.cpp:938` @ `ComputePQTable` | 置信度: 80
6. **[VULN-DF-CORE-001]** integer_overflow (High) - `src/kvecturbo.cpp:1027` @ `ComputePQTable` | 置信度: 75
7. **[VULN-SEC-CORE-001]** integer_overflow (High) - `src/kvecturbo.cpp:1028` @ `ComputePQTable` | 置信度: 75
8. **[VULN-SEC-CORE-002]** integer_overflow (High) - `src/kvecturbo.cpp:1198` @ `ComputeVectorPQCode` | 置信度: 75
9. **[VULN-SEC-CORE-004]** integer_overflow (High) - `src/kvecturbo.cpp:1365` @ `GetPQDistanceTableAdc` | 置信度: 75
10. **[VULN-SEC-CORE-006]** integer_overflow (High) - `src/kvecturbo.cpp:1226` @ `ComputeOne` | 置信度: 75

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `ComputeVectorPQCode@include/kvecturbo.h` | rpc | semi_trusted | 公共 API，接收调用方（openGauss）传入的向量数据和 PQ 参数。向量数据可能来自数据库用户上传，需验证数据有效性 | 计算单个向量的 PQ 编码，接收 float* vector、PQParams* params、unsigned char* pqCode |
| `ComputePQTable@include/kvecturbo.h` | rpc | semi_trusted | 公共 API，接收 VectorArray 样本数据和 PQ 参数。样本数据来自数据库用户上传的训练向量，可能触发大量内存操作和 K-means 计算 | 计算 PQ 码本，接收 VectorArray samples 和 PQParams* params |
| `GetPQDistanceTableSdc@include/kvecturbo.h` | rpc | semi_trusted | 公共 API，接收 PQParams 参数计算距离表。参数结构体可能包含无效值导致内存越界访问 | 计算 SDC 模式距离表，接收 PQParams* params 和输出缓冲区 |
| `GetPQDistanceTableAdc@include/kvecturbo.h` | rpc | semi_trusted | 公共 API，接收用户查询向量计算 ADC 距离表。向量数据可能来自数据库用户查询请求 | 计算 ADC 模式距离表，接收 float* vector、PQParams* params 和输出缓冲区 |
| `GetPQDistance@include/kvecturbo.h` | rpc | semi_trusted | 公共 API，接收 basecode、querycode、距离表等参数计算 PQ 距离。所有输入参数可被调用方控制，需验证数组边界 | 计算 PQ 距离，接收 basecode、querycode、params、distanceTable 和输出指针 |

**其他攻击面**:
- 公共 API 接口: 5 个导出函数可被 openGauss 数据库调用
- 向量数据输入: 用户上传的向量数据通过 ComputePQTable 和 ComputeVectorPQCode 进入
- 参数结构体: PQParams 和 VectorArray 结构体字段可被调用方控制
- 缓冲区操作: 所有 API 都涉及 memcpy_s 内存拷贝操作
- 整数参数: dim、pqM、pqKsub 等参数可影响内存计算和数组索引

---

## 3. Critical 漏洞 (1)

### [VULN-DF-CORE-002] buffer_overflow - ComputePQTable

**严重性**: Critical | **CWE**: CWE-119 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/kvecturbo.cpp:1027-1038` @ `ComputePQTable`
**模块**: core
**跨模块**: core → api

**描述**: Heap buffer overflow in ComputePQTable: missing pqTable buffer size validation and incorrect memcpy_s remainingSize calculation. Caller may allocate insufficient buffer leading to overflow when writing pqM * pqKsub * itemSize bytes.

**漏洞代码** (`src/kvecturbo.cpp:1027-1038`)

```c
size_t remainingSize = (pqKsub - i) * centers->itemSize;
errno_t result = memcpy_s(pqTable + (m * pqKsub + i) * centers->itemSize, remainingSize, static_cast<void *>(vec), centers->itemSize);
```

**达成路径**

Caller (openGauss) → ComputePQTable (public API) → params->pqTable (caller allocated) → memcpy_s writes pqM * pqKsub * itemSize bytes → buffer overflow if pqTable insufficient

**验证说明**: pqTable buffer provided by caller without size validation. memcpy_s writes to offset (m * pqKsub + i) * itemSize without checking buffer capacity. Real cross-module vulnerability - caller may allocate insufficient buffer.

---

## 4. High 漏洞 (15)

### [VULN-DF-CORE-003] array_out_of_bounds - ComputeVectorPQCode

**严重性**: High | **CWE**: CWE-129 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/kvecturbo.cpp:1196-1206` @ `ComputeVectorPQCode`
**模块**: core

**描述**: Array index out of bounds in VectorL2SquaredDistancePQ. Vector pointer vector + i * dsub accessed without bounds validation. Caller provides vector data with unknown length, params->dim controls loop iteration count.

**漏洞代码** (`src/kvecturbo.cpp:1196-1206`)

```c
for (int i = 0; i < pqM; i++) { unsigned char minIndex = -1; Vector *tempVec2 = reinterpret_cast<Vector *>(pqTable + (i * pqKsub) * subItemSize); minIndex = VectorL2SquaredDistancePQ(step, vector + i * dsub, tempVec2->x, pqKsub, dsub); }
```

**达成路径**

[SOURCE] ComputeVectorPQCode@1166 vector (caller-provided, semi_trusted)\n[PROPAGATION] Line 1175-1176: dim = params->dim, dsub = dim / pqM\n[SINK] Line 1203: vector + i * dsub - no validation vector has >= pqM * dsub elements\n[ADDITIONAL] Line 1198: pqTable + (i * pqKsub) * subItemSize - similar overflow risk

**验证说明**: vector + i*dsub pointer arithmetic without bounds validation. Caller provides vector with unknown actual size.

---

### [VULN-DF-CORE-008] integer_overflow - ComputeOne

**严重性**: High | **CWE**: CWE-190 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/kvecturbo.cpp:1226-1236` @ `ComputeOne`
**模块**: core

**描述**: Integer overflow in GetPQDistanceTableSdc pqTable offset. Expression (k * pqKsub + i) * subItemSize and (k * pqKsub + j) * subItemSize can overflow. pqKsub max is 256, pqM max is 2000, subItemSize can be large - combined multiplication exceeds 32-bit.

**漏洞代码** (`src/kvecturbo.cpp:1226-1236`)

```c
Vector *vec1 = reinterpret_cast<Vector *>(pqTable + (k * pqKsub + i) * subItemSize); Vector *vec2 = reinterpret_cast<Vector *>(pqTable + (k * pqKsub + j) * subItemSize);
```

**达成路径**

[SOURCE] GetPQDistanceTableSdc@1271 params->pqKsub, params->pqM, params->subItemSize\n[PROPAGATION] ComputeOne@1218-1224: pqKsub, pqM, subItemSize from params\n[SINK] Line 1226: (k * pqKsub + i) * subItemSize - overflow risk\n[SINK] Line 1232: (k * pqKsub + j) * subItemSize - overflow risk\n[IMPACT] Invalid pointer dereference, memory corruption

**验证说明**: Integer overflow in (k * pqKsub + i) * subItemSize. pqM max 2000, pqKsub max 256, subItemSize can overflow on 32-bit.

---

### [VULN-DF-CORE-018] buffer_overflow - handleClusterOrInitializeRandomly

**严重性**: High | **CWE**: CWE-119 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/kvecturbo.cpp:512-575` @ `handleClusterOrInitializeRandomly`
**模块**: core

**描述**: memcpy_s in handleClusterOrInitializeRandomly with insufficient buffer validation. sumBuffer and maxCenterSumBuffer accessed without bounds validation. remainingBytes passed as pointer may not reflect actual buffer size.

**漏洞代码** (`src/kvecturbo.cpp:512-575`)

```c
errno_t result = memcpy_s(sumBuffer, *newCentersSize, maxCenterSumBuffer, dimensions * sizeof(float)); ... result = memcpy_s(&newCenters[j * dimensions], *newCentersSize, sumBuffer, dimensions * sizeof(float));
```

**达成路径**

[SOURCE] handleClusterOrInitializeRandomly@512 agg, newCenters, centerCounts\n[PROPAGATION] ComputeNewCenters@639: passes agg buffer and remainingBytes pointer\n[SINK] Line 533, 556, 563: memcpy_s with *newCentersSize as dest size\n[ISSUE] *newCentersSize is (numCentersD - offset) * sizeof(float), may not reflect actual buffer\n[DATA OUT] Written to newCenters flows back to centers in NormalKmeans

**验证说明**: memcpy_s in handleClusterOrInitializeRandomly with sumBuffer/newCentersSize validation issues.

---

### [VULN-DF-CORE-021] cross_module_data_flow - ComputePQTable

**严重性**: High | **CWE**: CWE-119 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/kvecturbo.cpp:938-1046` @ `ComputePQTable`
**模块**: core
**跨模块**: core → api

**描述**: Cross-module boundary violation: samples VectorArray from caller flows through ComputePQTable to NormalKmeans and VectorArraySplitSingle without capacity validation. samples->items buffer assumed to have sufficient size.

**漏洞代码** (`src/kvecturbo.cpp:938-1046`)

```c
VectorArray subVectorArrays = VectorArraySplitSingle(samples, pqM, m); if (NormalKmeans(subVectorArrays, centers, pqM) == -1) { ... }
```

**达成路径**

[SOURCE] samples VectorArray from caller (api module)\n[PROPAGATION] Line 994: VectorArraySplitSingle(samples, pqM, m)\n[PROPAGATION] VectorArraySplitSingle@295: VectorArrayGet(arr, index) -> samples->items + offset * itemSize\n[SINK] NormalKmeans@707: memcpy_s samplesData from vec->x\n[ISSUE] samples->maxLen and samples->length validated but samples->items buffer size unknown

**验证说明**: samples VectorArray flows from API caller to NormalKmeans. samples->items buffer size unknown - assumes caller allocated correctly. Cross-module boundary violation.

---

### [VULN-DF-CORE-001] integer_overflow - ComputePQTable

**严重性**: High | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/kvecturbo.cpp:1027-1032` @ `ComputePQTable`
**模块**: core

**描述**: Integer overflow in pqTable offset calculation. Expression (m * pqKsub + i) * centers->itemSize can overflow when pqM, pqKsub or itemSize are large values from params. No validation that m*pqKsub+i stays within integer bounds before multiplication by itemSize.

**漏洞代码** (`src/kvecturbo.cpp:1027-1032`)

```c
size_t remainingSize = (pqKsub - i) * centers->itemSize; errno_t result = memcpy_s(pqTable + (m * pqKsub + i) * centers->itemSize, remainingSize, static_cast<void *>(vec), centers->itemSize);
```

**达成路径**

[SOURCE] ComputePQTable@938 params->pqM, params->pqKsub (semi_trusted)\n[PROPAGATION] Line 951-952: pqKsub = params->pqKsub, Line 992: loop m in [0, pqM]\n[PROPAGATION] Line 1001: centers->itemSize = subItemSize = MAXALIGN(VECTOR_SIZE(dsub))\n[SINK] Line 1028: (m * pqKsub + i) * centers->itemSize - overflow when m=pqM-1, i=pqKsub-1, itemSize large

**验证说明**: Integer overflow in pqTable offset (m*pqKsub+i)*itemSize possible when pqM=2000,pqKsub=256,itemSize~8000. Overflow on 32-bit systems. Mitigations: pqM<=2000,pqKsub<=256,dim<=2000 validation exist (lines 965-972) but no overflow check on multiplication.

**评分明细**: reachability: true | input_validation: true | safe_functions: true | cross_module: true | simd: false

---

### [VULN-SEC-CORE-001] integer_overflow - ComputePQTable

**严重性**: High | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/kvecturbo.cpp:1028-1031` @ `ComputePQTable`
**模块**: core
**跨模块**: core → openGauss

**描述**: ComputePQTable函数中pqTable索引计算存在整数溢出风险。索引(m * pqKsub + i) * centers->itemSize在pqM=2000、pqKsub=256、itemSize≈8000时乘积约4GB，可能导致越界访问。pqTable缓冲区大小由params传入，未验证其是否足够容纳计算后的索引。

**漏洞代码** (`src/kvecturbo.cpp:1028-1031`)

```c
errno_t result = memcpy_s(pqTable + (m * pqKsub + i) * centers->itemSize, remainingSize, static_cast<void *>(vec), centers->itemSize);
```

**达成路径**

入口点: ComputePQTable(line 938, semi_trusted) -> pqM/pqKsub/dim参数(外部) -> 索引计算(m * pqKsub + i) * centers->itemSize -> pqTable数组访问[line 1028]

**验证说明**: Integer overflow in pqTable offset (m*pqKsub+i)*centers->itemSize at line 1028. Same issue as VULN-DF-CORE-001. Overflow possible on 32-bit when m=1999, pqKsub=256, i=255, itemSize~8000.

**评分明细**: reachability: true | input_validation: true | safe_functions: true | cross_module: true | simd: false

---

### [VULN-SEC-CORE-002] integer_overflow - ComputeVectorPQCode

**严重性**: High | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/kvecturbo.cpp:1198-1203` @ `ComputeVectorPQCode`
**模块**: core
**跨模块**: core → openGauss

**描述**: ComputeVectorPQCode函数中pqTable指针算术存在整数溢出风险。索引(i * pqKsub) * subItemSize在i=pqM-1、pqKsub=256、subItemSize≈2000时可能溢出，导致越界指针传递给VectorL2SquaredDistancePQ。

**漏洞代码** (`src/kvecturbo.cpp:1198-1203`)

```c
Vector *tempVec2 = reinterpret_cast<Vector *>(pqTable + (i * pqKsub) * subItemSize);
```

**达成路径**

入口点: ComputeVectorPQCode(line 1166, semi_trusted) -> pqM/pqKsub/dim参数(外部) -> 索引计算(i * pqKsub) * subItemSize[line 1198] -> pqTable指针[line 1198] -> VectorL2SquaredDistancePQ[line 1203]

**验证说明**: Integer overflow in pqTable pointer arithmetic (i*pqKsub)*subItemSize at line 1198. i ranges 0 to pqM-1 (max 2000), pqKsub max 256. Overflow on 32-bit systems.

**评分明细**: reachability: true | input_validation: true | safe_functions: false | cross_module: true | simd: false

---

### [VULN-SEC-CORE-004] integer_overflow - GetPQDistanceTableAdc

**严重性**: High | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/kvecturbo.cpp:1365-1374` @ `GetPQDistanceTableAdc`
**模块**: core
**跨模块**: core → openGauss

**描述**: GetPQDistanceTableAdc函数中pqTable指针计算存在整数溢出风险。索引(i * pqKsub) * subItemSize在i=pqM-1、pqKsub=256、subItemSize≈2000时乘积可能超出size_t范围或超出pqTable实际大小。

**漏洞代码** (`src/kvecturbo.cpp:1365-1374`)

```c
Vector *tmpvec = reinterpret_cast<Vector *>(pqTable + (i * pqKsub) * subItemSize);
```

**达成路径**

入口点: GetPQDistanceTableAdc(line 1327, semi_trusted) -> pqM/pqKsub/dim参数(外部) -> 索引计算(i * pqKsub) * subItemSize[line 1365] -> pqTable指针

**验证说明**: Integer overflow in pqTable pointer (i*pqKsub)*subItemSize at line 1365. Same pattern as CORE-002. GetPQDistanceTableAdc entry point semi_trusted.

**评分明细**: reachability: true | input_validation: true | safe_functions: false | cross_module: true | simd: false

---

### [VULN-SEC-CORE-006] integer_overflow - ComputeOne

**严重性**: High | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/kvecturbo.cpp:1226-1236` @ `ComputeOne`
**模块**: core
**跨模块**: core → openGauss

**描述**: ComputeOne函数中pqTable索引计算存在整数溢出风险。索引(k * pqKsub + i) * subItemSize在k=pqM-1、i=pqKsub-1、subItemSize≈2000时乘积可能超出缓冲区范围。

**漏洞代码** (`src/kvecturbo.cpp:1226-1236`)

```c
Vector *vec1 = reinterpret_cast<Vector *>(pqTable + (k * pqKsub + i) * subItemSize);
```

**达成路径**

入口点: GetPQDistanceTableSdc(line 1271, semi_trusted) -> ComputeOne(line 1216) -> pqTable索引计算[line 1226]

**验证说明**: Integer overflow in pqTable index (k*pqKsub+i)*subItemSize at line 1226. Same pattern as CORE-001. k ranges 0 to pqM-1, i ranges 0 to pqKsub-1.

**评分明细**: reachability: true | input_validation: true | safe_functions: false | cross_module: true | simd: false

---

### [VULN-DF-CORE-004] buffer_overflow - VectorArrayCopy

**严重性**: High | **CWE**: CWE-119 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/kvecturbo.cpp:199-214` @ `VectorArrayCopy`
**模块**: core

**描述**: memcpy_s in VectorArrayCopy with insufficient destination buffer validation. dstSize = arr->itemSize but bytesToCopy = newDim * sizeof(float). If newDim derived from external data exceeds expected dimension, buffer overflow occurs.

**漏洞代码** (`src/kvecturbo.cpp:199-214`)

```c
size_t bytesToCopy = newDim * sizeof(float); size_t dstSize = arr->itemSize; errno_t result = memcpy_s(dst, dstSize, src, bytesToCopy);
```

**达成路径**

[SOURCE] VectorArraySplitSingle@269 arr->dim, chunkNum (from samples)\n[PROPAGATION] Line 276: newDim = originalDim / subnum\n[PROPAGATION] VectorArrayCopy@206: bytesToCopy = newDim * sizeof(float)\n[SINK] Line 208: memcpy_s(dst, dstSize, src, bytesToCopy) - dstSize may be smaller if arr was initialized with wrong itemSize

**验证说明**: VectorArrayCopy bytesToCopy may exceed dstSize if newDim larger than expected.

---

### [VULN-DF-CORE-007] simd_memory_violation - L2Distance2Simd

**严重性**: High | **CWE**: CWE-119 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/kvecturbo.cpp:157-189` @ `L2Distance2Simd`
**模块**: core

**描述**: SIMD NEON vld1q_f32 memory load without bounds validation in L2Distance2Simd. Pointer arithmetic pa + i, pb + i assumes valid memory up to dim elements. If actual vector size is smaller than dim, SIMD load reads uninitialized/out-of-bounds memory.

**漏洞代码** (`src/kvecturbo.cpp:157-189`)

```c
float32x4_t sum_vec = vdupq_n_f32(0.0f); for (; i + 3 < dim; i += 4) { float32x4_t va = vld1q_f32(pa + i); float32x4_t vb = vld1q_f32(pb + i); ... }
```

**达成路径**

[SOURCE] L2Distance2Simd@157: float *a, float *b, int size (from NormalKmeans)\n[PROPAGATION] NormalKmeans@756: sample = samplesData.get() + j * dimensions\n[PROPAGATION] NormalKmeans@755: center = centersData.get() + k * dimensions\n[SINK] Line 169-170: vld1q_f32(pa + i), vld1q_f32(pb + i) - loads 4 floats at once\n[ISSUE] No validation that pa/pb have >= dim valid elements, SIMD reads past buffer end

**验证说明**: SIMD NEON vld1q_f32 loads without bounds validation. dim validated but pa/pb pointers may point to insufficient buffer.

---

### [VULN-DF-CORE-011] integer_overflow - GetPQDistanceTableAdc

**严重性**: High | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/kvecturbo.cpp:1364-1374` @ `GetPQDistanceTableAdc`
**模块**: core

**描述**: Integer overflow in GetPQDistanceTableAdc pqTable offset. Expression (i * pqKsub) * subItemSize used to compute Vector pointer. Combined multiplication can overflow size_t bounds with large pqM, pqKsub, subItemSize values.

**漏洞代码** (`src/kvecturbo.cpp:1364-1374`)

```c
for (int i = 0; i < pqM; i++) { Vector *tmpvec = reinterpret_cast<Vector *>(pqTable + (i * pqKsub) * subItemSize); ... for (; k < pqKsub; k++) { float *b = c + k * step; ... } }
```

**达成路径**

[SOURCE] GetPQDistanceTableAdc@1327 params->pqM, params->pqKsub, params->subItemSize\n[PROPAGATION] Line 1362: step = subItemSize / sizeof(float)\n[SINK] Line 1365: pqTable + (i * pqKsub) * subItemSize - overflow when i near pqM, pqKsub=256\n[SINK] Line 1374: c + k * step - k iterates to pqKsub, pointer arithmetic

**验证说明**: Integer overflow in (i * pqKsub) * subItemSize in GetPQDistanceTableAdc.

---

### [VULN-DF-CORE-014] simd_memory_violation - L2SquaredDistanceNeonV2

**严重性**: High | **CWE**: CWE-119 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/kvecturbo.cpp:891-928` @ `L2SquaredDistanceNeonV2`
**模块**: core

**描述**: NEON SIMD memory load in L2SquaredDistanceNeonV2 without bounds validation. Loads 16 floats per iteration (4x float32x4_t) assuming valid memory. If actual vector size smaller than dim, reads uninitialized memory causing information leak or crash.

**漏洞代码** (`src/kvecturbo.cpp:891-928`)

```c
for (; i + prefetchStride <= dim; i += prefetchStride, pta += prefetchStride, ptb += prefetchStride) { float32x4_t packdata_a0 = vld1q_f32(pta); float32x4_t packdata_a1 = vld1q_f32(pta + 4); ... float32x4_t packdata_a3 = vld1q_f32(pta + 12); }
```

**达成路径**

[SOURCE] L2SquaredDistanceNeonV2@879: float *ax, float *bx, int dim\n[PROPAGATION] ComputeOne@1239: vec1->x, vec2->x from pqTable\n[SINK] Line 892-900: vld1q_f32 loads 4 floats each, 16 total per iteration\n[ISSUE] No validation ax/bx have >= dim valid floats, SIMD may read past buffer\n[IMPACT] Information disclosure from uninitialized memory, potential crash

**验证说明**: NEON SIMD loads 16 floats per iteration without buffer size validation.

---

### [VULN-SEC-CORE-005] array_out_of_bounds - GetPQDistance

**严重性**: High | **CWE**: CWE-129 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/kvecturbo.cpp:1150-1151` @ `GetPQDistance`
**模块**: core
**跨模块**: core → openGauss

**描述**: GetPQDistance函数中pqDistanceTable索引计算存在越界风险。offset = k * pqKsub * pqKsub + i * pqKsub + j在pqM=2000、pqKsub=256时最大索引约128M个float，pqDistanceTable_size需验证是否足够。仅检查size<pqM*pqKsub*pqKsub但未检查缓冲区实际容量。

**漏洞代码** (`src/kvecturbo.cpp:1150-1151`)

```c
offset = k * pqKsub * pqKsub + i * pqKsub + j; distance += pqDistanceTable[offset];
```

**达成路径**

入口点: GetPQDistance(line 1061, semi_trusted) -> basecode/querycode(外部) -> pqDistanceTable索引offset[line 1150] -> 数组访问pqDistanceTable[offset][line 1151]

**验证说明**: pqDistanceTable index offset=k*pqKsub*pqKsub+i*pqKsub+j at line 1150. Max offset ~131M elements when pqM=2000,pqKsub=256. Size validation exists but insufficient for all cases.

**评分明细**: reachability: true | input_validation: true | safe_functions: false | cross_module: true | simd: false

---

### [VULN-SEC-CORE-010] integer_overflow - ComputeOne

**严重性**: High | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `src/kvecturbo.cpp:1240-1244` @ `ComputeOne`
**模块**: core
**跨模块**: core → openGauss

**描述**: GetPQDistanceTableSdc函数中pqDistanceTable索引访问存在整数溢出风险。offset = k * pqKsub * pqKsub + i * pqKsub + j在pqM=2000、pqKsub=256时最大索引约128M个float元素，超出pqDistanceTable_size验证范围。

**漏洞代码** (`src/kvecturbo.cpp:1240-1244`)

```c
size_t offset = k * pqKsub * pqKsub + i * pqKsub + j; pqDistanceTable[offset] = pqDis;
```

**达成路径**

入口点: GetPQDistanceTableSdc(line 1271, semi_trusted) -> ComputeOne(line 1216) -> pqDistanceTable索引offset[line 1240] -> 数组赋值pqDistanceTable[offset][line 1241]

**验证说明**: pqDistanceTable index offset=k*pqKsub*pqKsub+i*pqKsub+j at line 1240. Same as CORE-005. Max offset ~131M elements. pqDistanceTable_size validation may be insufficient.

**评分明细**: reachability: true | input_validation: true | safe_functions: false | cross_module: true | simd: false

---

## 5. Medium 漏洞 (15)

### [VULN-SEC-API-001] improper_input_validation - API Functions (ComputeVectorPQCode, ComputePQTable, GetPQDistanceTableSdc, GetPQDistanceTableAdc, GetPQDistance)

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `include/kvecturbo.h:65-110` @ `API Functions (ComputeVectorPQCode, ComputePQTable, GetPQDistanceTableSdc, GetPQDistanceTableAdc, GetPQDistance)`
**模块**: api
**跨模块**: api → core

**描述**: 公共 API 函数缺少参数有效性验证的文档说明。所有入口函数（ComputeVectorPQCode、ComputePQTable、GetPQDistanceTableSdc、GetPQDistanceTableAdc、GetPQDistance）接受外部传入的指针参数，但头文件未定义哪些参数可以为 NULL、哪些必须非 NULL，也未说明调用者的安全契约。作为库的公共接口，这种文档缺失会导致调用方误用，可能在下游 core 模块中引发空指针解引用或未定义行为。

**漏洞代码** (`include/kvecturbo.h:65-110`)

```c
KVEC_API_PUBLIC int ComputeVectorPQCode(float *vector, const PQParams *params, unsigned char *pqCode, size_t pqCode_size);
KVEC_API_PUBLIC int ComputePQTable(VectorArray samples, PQParams *params);
KVEC_API_PUBLIC int GetPQDistanceTableSdc(const PQParams *params, float *pqDistanceTable, size_t pqDistanceTable_size);
KVEC_API_PUBLIC int GetPQDistanceTableAdc(float *vector, const PQParams *params, float *pqDistanceTable, size_t pqDistanceTable_size);
KVEC_API_PUBLIC int GetPQDistance(const unsigned char *basecode, const unsigned char *querycode, const PQParams *params, const float *pqDistanceTable, float *pqDistance, size_t basecode_size, size_t querycode_size, size_t pqDistanceTable_size, size_t pqDistance_size);
```

**达成路径**

include/kvecturbo.h:65-110 API Functions [SOURCE: semi_trusted] -> (参数传递到 core 模块) -> [SINK: core 模块内部处理]

**验证说明**: Documentation deficiency confirmed. Runtime parameter validation exists but header lacks explicit parameter contract specification.

**评分明细**: evidence: Runtime null pointer checks exist in all API functions | mitigations: Null pointer validation in ComputePQTable,Null pointer validation in ComputeVectorPQCode,Null pointer validation in GetPQDistance | data_flow_verified: true

---

### [VULN-DF-CORE-005] integer_overflow - VectorArrayGet

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/kvecturbo.cpp:90-93` @ `VectorArrayGet`
**模块**: core

**描述**: Integer overflow in VectorArrayGet offset calculation. Expression offset * arr->itemSize can overflow when offset and itemSize are large integers. Called from multiple functions handling external data.

**漏洞代码** (`src/kvecturbo.cpp:90-93`)

```c
char *VectorArrayGet(VectorArray arr, int offset) { return (static_cast<char *>(arr->items)) + (offset * arr->itemSize); }
```

**达成路径**

[SOURCE] VectorArrayGet@90 offset (from external callers)\n[PROPAGATION] NormalKmeans@707, 733, ComputePQTable@1018 pass offsets derived from samples->length\n[SINK] Line 92: offset * arr->itemSize - overflow when offset near INT_MAX and itemSize large\n[IMPACT] Returns corrupted pointer leading to memory corruption

**验证说明**: Integer overflow in offset * arr->itemSize in VectorArrayGet.

---

### [VULN-DF-CORE-009] array_out_of_bounds - GetPQDistance

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/kvecturbo.cpp:1094-1135` @ `GetPQDistance`
**模块**: core

**描述**: basecode array index out of bounds in GetPQDistance. Loop processes pqM elements from basecode but only validates basecode_size >= pqM initially. Inner loop k increments without bounds check relative to basecode_size.

**漏洞代码** (`src/kvecturbo.cpp:1094-1135`)

```c
while (num / 8 > 0) { int i1 = basecode[k++]; int i2 = basecode[k++]; ... int i8 = basecode[k++]; ... num -= 8; } while (num > 0) { int i = basecode[k++]; ... num -= 1; }
```

**达成路径**

[SOURCE] GetPQDistance@1061 basecode (semi_trusted), basecode_size\n[VALIDATION] Line 1075: basecode_size >= pqM check\n[ISSUE] Line 1094-1135: k increments in inner loop without tracking k < basecode_size\n[SINK] Line 1095-1102: basecode[k++] accessed, k may exceed basecode_size if pqM calculation wrong\n[ADDITIONAL] pqDistanceTable[offset + i] at line 1108-1132 - offset may overflow

**验证说明**: basecode array access in GetPQDistance. basecode_size validated but inner loop k increments without tracking.

---

### [VULN-DF-CORE-016] integer_overflow - VectorArrayInit

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/kvecturbo.cpp:223-245` @ `VectorArrayInit`
**模块**: core

**描述**: Integer overflow in malloc/calloc size calculations in VectorArrayInit. calloc(maxLen, itemSize) can overflow when maxLen * itemSize exceeds SIZE_MAX. While maxLen and itemSize validated separately, combined size not checked.

**漏洞代码** (`src/kvecturbo.cpp:223-245`)

```c
VectorArray res = static_cast<VectorArray>(malloc(sizeof(VectorArrayData))); res->maxLen = maxLen; res->itemSize = itemSize; res->items = static_cast<char *>(calloc(maxLen, itemSize));
```

**达成路径**

[SOURCE] VectorArrayInit@223 maxLen, dimensions, itemSize (from callers)\n[PROPAGATION] ComputePQTable@1001: maxLen = pqKsub (max 256), itemSize = subItemSize\n[SINK] Line 238: calloc(maxLen, itemSize) - overflow if maxLen * itemSize > SIZE_MAX\n[ISSUE] No combined size validation before allocation\n[IMPACT] Allocation returns smaller buffer than expected, subsequent writes overflow

**验证说明**: calloc(maxLen, itemSize) overflow in VectorArrayInit.

---

### [VULN-SEC-API-002] buffer_size_calculation_error - Vector struct

**严重性**: Medium | **CWE**: CWE-131 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `include/kvecturbo.h:38-43` @ `Vector struct`
**模块**: api
**跨模块**: api → core

**描述**: Vector 结构体使用灵活数组成员 float x[FLEXIBLE_ARRAY_MEMBER]，其大小由 vlen 和 dim 字段控制。这些字段完全由调用方控制，如果分配内存时未正确验证 vlen 与 dim 的一致性，或 vlen 被设置为恶意值，可能导致内存分配不足或缓冲区溢出。头文件未定义这些字段的有效范围和验证规则。

**漏洞代码** (`include/kvecturbo.h:38-43`)

```c
typedef struct Vector {
    signed int vlen;                /* Length of the vector */
    signed short dim;               /* Vector dimension */
    signed short unused;            /* Reserved field for future use */
    float x[FLEXIBLE_ARRAY_MEMBER]; /* Vector data */
} Vector;
```

**达成路径**

include/kvecturbo.h:38-43 Vector 结构体定义 [SOURCE: semi_trusted caller controls vlen/dim] -> (传递给 core 模块处理) -> [SINK: core 模块内存操作]

**验证说明**: Flexible array member concern is valid. Size calculations are correct but header lacks explicit consistency contract.

**评分明细**: evidence: Vector struct uses flexible array member. VECTOR_SIZE properly computes size based on dim. InitVector allocates correctly. | mitigations: VECTOR_SIZE proper calculation,MAXALIGN memory alignment,InitVector validated allocation | data_flow_verified: true

---

### [VULN-DF-CORE-010] buffer_overflow - InitCenters

**严重性**: Medium | **CWE**: CWE-119 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/kvecturbo.cpp:381-391` @ `InitCenters`
**模块**: core

**描述**: memcpy_s in InitCenters uses remainingSize calculation (numCenters - i) * dimension * sizeof(float) but sample index idx from shuffled indices may be invalid if samples buffer smaller than expected.

**漏洞代码** (`src/kvecturbo.cpp:381-391`)

```c
for (int i = 0; i < numCenters; ++i) { size_t remainingSize = (numCenters - i) * dimension * sizeof(float); int idx = sampleIndices[i]; errno_t result = memcpy_s(&centers[i * dimension], remainingSize, &samples[idx * dimension], sizeof(float) * dimension); }
```

**达成路径**

[SOURCE] InitCenters@356 samples, numSamples, numCenters, dimension\n[PROPAGATION] Line 372-375: sampleIndices shuffled with numSamples range\n[SINK] Line 385: &samples[idx * dimension] - idx validated <= numSamples but samples buffer size unknown\n[SINK] memcpy_s destination size = remainingSize, source size = dimension * sizeof(float)

**验证说明**: InitCenters memcpy_s with samples buffer size unknown.

---

### [VULN-DF-CORE-013] buffer_overflow - VectorArraySet

**严重性**: Medium | **CWE**: CWE-119 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/kvecturbo.cpp:103-113` @ `VectorArraySet`
**模块**: core

**描述**: memcpy_s in VectorArraySet may overflow. Destination size arr->itemSize validated against vecSize parameter, but vecSize comes from VECTOR_SIZE(vec->dim) which may differ from actual vector content size.

**漏洞代码** (`src/kvecturbo.cpp:103-113`)

```c
int VectorArraySet(VectorArray arr, int offset, char *val, size_t vecSize) { void *dest = VectorArrayGet(arr, offset); size_t arrSize = arr->itemSize; errno_t result = memcpy_s(dest, arrSize, val, vecSize); }
```

**达成路径**

[SOURCE] VectorArraySet@103 arr, offset, val, vecSize (from NormalKmeans)\n[PROPAGATION] NormalKmeans@802: vecSize = VECTOR_SIZE(vec->dim)\n[SINK] Line 107: memcpy_s(dest, arrSize, val, vecSize)\n[ISSUE] vecSize is VECTOR_SIZE based on vec->dim, but val content size unknown\n[DATA OUT] Written data stored in arr->items, accessible to callers

**验证说明**: VectorArraySet vecSize may differ from actual val content size.

---

### [VULN-DF-CORE-012] buffer_overflow - GetPQDistanceTableAdc

**严重性**: Medium | **CWE**: CWE-119 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/kvecturbo.cpp:1377-1391` @ `GetPQDistanceTableAdc`
**模块**: core

**描述**: pqDistanceTable write in GetPQDistanceTableAdc without size validation. Loop writes to pqDistanceTable[i * pqKsub + k] but only validates pqDistanceTable_size >= pqM * pqKsub * pqKsub, actual write pattern is pqM * pqKsub entries.

**漏洞代码** (`src/kvecturbo.cpp:1377-1391`)

```c
for (int i = 0; i < pqM; i++) { for (; k < pqKsub; k++) { size_t l2Offset = i * pqKsub + k; pqDistanceTable[l2Offset] = l2Disatance; } }
```

**达成路径**

[SOURCE] GetPQDistanceTableAdc@1327 pqDistanceTable, pqDistanceTable_size\n[VALIDATION] Line 1341: pqDistanceTable_size < pqM * pqKsub * pqKsub check\n[ISSUE] Actual write pattern writes pqM * pqKsub entries, not pqM * pqKsub * pqKsub\n[SINK] Line 1382, 1389: pqDistanceTable[i * pqKsub + k] = value\n[NOTE] Validation is overly strict but actual writes may still exceed buffer if validation bypassed

**验证说明**: pqDistanceTable write pattern validation mismatch.

---

### [VULN-DF-CORE-015] division_by_zero - VectorArraySplitSingle

**严重性**: Medium | **CWE**: CWE-369 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/kvecturbo.cpp:269-317` @ `VectorArraySplitSingle`
**模块**: core

**描述**: Division by zero risk in VectorArraySplitSingle. newDim = originalDim / subnum calculation. While subnum <= 0 check exists, originalDim % subnum != 0 check ensures subnum != 0. However, if subnum = 1 and originalDim = 0, division succeeds but newDim = 0 causes downstream issues.

**漏洞代码** (`src/kvecturbo.cpp:269-317`)

```c
int originalDim = arr->dim; if ((subnum <= 0) || (originalDim % subnum != 0)) { return nullptr; } int newDim = originalDim / subnum;
```

**达成路径**

[SOURCE] VectorArraySplitSingle@269 arr->dim, subnum (from ComputePQTable)\n[PROPAGATION] ComputePQTable@994: subnum = pqM\n[VALIDATION] Line 272: subnum <= 0 check\n[ISSUE] No check originalDim > 0, if originalDim = 0 then newDim = 0\n[SINK] Line 279: VectorArrayInit with newDim = 0, creates empty array\n[DOWNSTREAM] VectorArrayCopy@206: bytesToCopy = newDim * sizeof(float) = 0

**验证说明**: Division by zero risk if originalDim=0 passed.

---

### [VULN-DF-CORE-019] information_leak - L2Distance2Simd

**严重性**: Medium | **CWE**: CWE-200 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/kvecturbo.cpp:169-186` @ `L2Distance2Simd`
**模块**: core

**描述**: Information disclosure through uninitialized SIMD memory reads. NEON SIMD loads may read uninitialized memory regions when vector buffers are smaller than expected dim. Sensitive data from adjacent memory may be exposed through distance calculations.

**漏洞代码** (`src/kvecturbo.cpp:169-186`)

```c
float32x4_t va = vld1q_f32(pa + i); float32x4_t vb = vld1q_f32(pb + i); float32x4_t diff = vsubq_f32(va, vb); sum_vec = vmlaq_f32(sum_vec, diff, diff);
```

**达成路径**

[SOURCE] L2Distance2Simd@157: pa, pb pointers from samples/centers\n[PROPAGATION] NormalKmeans@752-755: sample, center derived from VectorArray\n[SINK] Line 169-172: SIMD loads 4 floats, may read uninitialized memory\n[DATA OUT] sum returned to NormalKmeans, influences clustering decisions\n[INFO LEAK] Uninitialized memory values contribute to distance calculation

**验证说明**: Information leak from uninitialized SIMD memory reads.

---

### [VULN-SEC-API-004] use_of_signed_integer - VectorArrayData and Vector structs

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `include/kvecturbo.h:27-40` @ `VectorArrayData and Vector structs`
**模块**: api
**跨模块**: api → core

**描述**: VectorArrayData.length、Vector.vlen 和 Vector.dim 使用有符号整数类型（int、signed int、signed short）。如果调用方传入负值，后续的无符号比较或尺寸计算可能产生意外结果。建议在文档中明确禁止负值，或使用 size_t/unsigned 类型。

**漏洞代码** (`include/kvecturbo.h:27-40`)

```c
int length;      /* Number of vectors in the array */
int maxLen;      /* Maximum length of vectors */
int dim;         /* Vector dimension */
...
signed int vlen;                /* Length of the vector */
signed short dim;               /* Vector dimension */
```

**达成路径**

include/kvecturbo.h:27-40 有符号整数字段 [SOURCE: semi_trusted] -> (传递到 core 模块) -> [SINK: 可能的类型转换错误或比较逻辑缺陷]

**验证说明**: Valid concern about signed integer types. Partially mitigated by runtime checks.

**评分明细**: evidence: Signed integers used for length/dimension. Runtime positive checks exist but signed types could cause edge case issues. | mitigations: Positive value checks,size_t casting for calculations | data_flow_verified: true

---

### [VULN-DF-INT-001] integer_overflow - NormalKmeans

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner, security-auditor

**位置**: `src/kvecturbo.cpp:679-680` @ `NormalKmeans`
**模块**: core

**描述**: 整数溢出风险：numSamplesD = numSamples * dimensions 和 numCentersD = numCenters * dimensions 的乘法运算可能导致整数溢出。当 numSamples 或 dimensions 为大值时，乘积可能超过 size_t 范围，导致内存分配不足或缓冲区溢出。

**漏洞代码** (`src/kvecturbo.cpp:679-680`)

```c
const size_t numSamplesD = static_cast<size_t>(numSamples) * dimensions;
const size_t numCentersD = static_cast<size_t>(numCenters) * dimensions;
```

**达成路径**

ComputePQTable.samples.length → NormalKmeans.numSamples → numSamplesD calculation → std::make_unique<float[]>(numSamplesD)

**验证说明**: numSamplesD=numSamples*dimensions multiplication could overflow. Mitigations: dimensions validated<=2000 upstream, std::make_unique throws bad_alloc on failure. However overflow before allocation check.

**评分明细**: reachability: true | input_validation: true | safe_functions: false | cross_module: false | simd: false

---

### [VULN-DF-ARR-001] array_index_out_of_bounds - VectorArrayGet

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `src/kvecturbo.cpp:90-93` @ `VectorArrayGet`
**模块**: core

**描述**: 数组越界风险：VectorArrayGet 函数没有对 offset 参数进行边界检查。offset 可能超过 arr->maxLen，导致返回指针指向超出数组范围的内存。该函数被多处调用，包括 VectorArraySplitSingle、NormalKmeans、ComputePQTable 等。

**漏洞代码** (`src/kvecturbo.cpp:90-93`)

```c
char *VectorArrayGet(VectorArray arr, int offset)
{
    return (static_cast<char *>(arr->items)) + (offset * arr->itemSize);
}
```

**达成路径**

VectorArraySplitSingle(index) → VectorArrayGet(offset) → arr->items + offset * itemSize [潜在越界]

**验证说明**: VectorArrayGet lacks bounds validation on offset parameter. Callers use bounded indices (0 to arr->length/arr->maxLen). Function itself should validate offset against arr->maxLen.

**评分明细**: reachability: true | input_validation: false | safe_functions: false | cross_module: false | simd: false

---

### [VULN-SEC-CORE-003] array_out_of_bounds - VectorL2SquaredDistancePQ

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/kvecturbo.cpp:838-850` @ `VectorL2SquaredDistancePQ`
**模块**: core

**描述**: VectorL2SquaredDistancePQ函数中指针算术c + k * step存在越界风险。step = subItemSize / sizeof(float)约500，k从0到pqKsub-1=255，c指针偏移约255*500=127500个float元素。需验证pqTable缓冲区大小是否足够。

**漏洞代码** (`src/kvecturbo.cpp:838-850`)

```c
float *b = c + k * step;
```

**达成路径**

入口点: ComputeVectorPQCode(line 1166) -> pqTable指针[line 1198] -> VectorL2SquaredDistancePQ参数c[line 832] -> 指针算术c + k * step[line 838]

**验证说明**: Pointer arithmetic c + k*step in VectorL2SquaredDistancePQ. step=subItemSize/sizeof(float). k ranges 0 to pqKsub-1. Depends on upstream pqTable pointer validity.

**评分明细**: reachability: true | input_validation: true | safe_functions: false | cross_module: false | simd: false

---

### [VULN-SEC-CORE-008] array_out_of_bounds - VectorArraySplitSingle

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `src/kvecturbo.cpp:302-303` @ `VectorArraySplitSingle`
**模块**: core

**描述**: VectorArraySplitSingle函数中向量数据指针偏移可能越界。originalVec->x + (chunkNum * newDim)在chunkNum=pqM-1、newDim=dim/pqM时偏移可能超出Vector结构体的x数组边界。

**漏洞代码** (`src/kvecturbo.cpp:302-303`)

```c
float *src = originalVec->x + (chunkNum * newDim);
```

**达成路径**

入口点: ComputePQTable(line 938) -> VectorArraySplitSingle(line 269) -> 指针偏移originalVec->x + (chunkNum * newDim)[line 302] -> VectorArrayCopy[line 303]

**验证说明**: Pointer offset originalVec->x+(chunkNum*newDim) at line 302. chunkNum ranges 0 to subnum-1. Validation: originalDim%subnum!=0 ensures proper split. However offset could exceed Vector->x boundary.

**评分明细**: reachability: true | input_validation: true | safe_functions: false | cross_module: false | simd: false

---

## 6. Low 漏洞 (1)

### [VULN-DF-CORE-017] integer_overflow - InitVector

**严重性**: Low | **CWE**: CWE-190 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/kvecturbo.cpp:324-345` @ `InitVector`
**模块**: core

**描述**: Integer overflow in calloc size calculation in InitVector. VECTOR_SIZE(dim) = offsetof(Vector, x) + sizeof(float) * dim. When dim is large (max 2000 per validation), sizeof(float) * dim = 8000 bytes plus offsetof ~12 bytes. Under normal bounds safe, but if validation bypassed dim could overflow.

**漏洞代码** (`src/kvecturbo.cpp:324-345`)

```c
int size; size = VECTOR_SIZE(dim); result = static_cast<Vector *>(calloc(size, sizeof(Vector)));
```

**达成路径**

[SOURCE] InitVector@324 dim (from NormalKmeans@790)\n[PROPAGATION] NormalKmeans@669: dimensions = centers->dim\n[SINK] Line 330: calloc(size, sizeof(Vector))\n[ISSUE] sizeof(Vector) includes flexible array member placeholder, actual allocation may be insufficient\n[NOTE] calloc(size, sizeof(Vector)) allocates size * sizeof(Vector) which may overflow

**验证说明**: InitVector calloc overflow unlikely under normal bounds.

---

## 7. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| api | 0 | 0 | 3 | 0 | 3 |
| core | 1 | 15 | 12 | 1 | 29 |
| **合计** | **1** | **15** | **15** | **1** | **32** |

## 8. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-190 | 13 | 40.6% |
| CWE-119 | 9 | 28.1% |
| CWE-129 | 6 | 18.8% |
| CWE-369 | 1 | 3.1% |
| CWE-200 | 1 | 3.1% |
| CWE-20 | 1 | 3.1% |
| CWE-131 | 1 | 3.1% |
