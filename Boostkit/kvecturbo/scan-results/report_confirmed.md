# 漏洞扫描报告 — 已确认漏洞

**项目**: KVecTurbo
**扫描时间**: 2026-04-22T10:30:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次漏洞扫描针对 KVecTurbo 向量检索加速库进行了全面的安全审计，共发现 **3 个已确认漏洞**，其中 **2 个高风险漏洞**和 **1 个低风险漏洞**。该库作为 openGauss 数据库的向量检索核心组件，其安全性直接影响数据库系统的稳定性和数据完整性。

**关键发现**:

- **VULN-DF-CORE-006 (High)**: 在 `NormalKmeans` 函数中发现缓冲区溢出漏洞。由于安全检查逻辑错误，当向量维度较大时（`dimensions * sizeof(float) > SECUREC_MEM_MAX_LEN`），`memcpy_s` 会写入超过目标缓冲区限制的数据，可能导致内存破坏、代码执行或服务拒绝。此漏洞可通过传入特制的向量数据触发。

- **VULN-DF-CORE-020 (High)**: 跨模块数据流漏洞。`ComputePQTable` 函数写入 `pqTable` 缓冲区时未验证调用方分配的缓冲区大小，当调用方分配的空间不足时将导致缓冲区溢出。该漏洞影响多个下游函数，攻击面较广。

- **VULN-SEC-API-006 (Low)**: API 错误码定义不完整。所有公共 API 函数返回 `int` 类型错误码，但未定义具体的错误码枚举，调用方无法区分不同类型的失败情况。

**风险影响**: 高风险漏洞可被恶意用户通过构造特制的向量数据或参数触发，可能导致内存破坏、服务拒绝或潜在代码执行。鉴于该库被 openGauss 数据库直接调用，漏洞影响范围较大。

**修复建议**: 建议优先修复两个高风险缓冲区溢出漏洞，重点关注内存操作的安全检查逻辑。低风险的 API 文档问题可在后续版本中逐步完善。

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
| High | 2 | 66.7% |
| Low | 1 | 33.3% |
| **有效漏洞总计** | **3** | - |
| 误报 (FALSE_POSITIVE) | 11 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-CORE-006]** buffer_overflow (High) - `src/kvecturbo.cpp:716` @ `NormalKmeans` | 置信度: 85
2. **[VULN-DF-CORE-020]** cross_module_data_flow (High) - `src/kvecturbo.cpp:1027` @ `ComputePQTable` | 置信度: 85
3. **[VULN-SEC-API-006]** insufficient_documentation (Low) - `include/kvecturbo.h:65` @ `All API Functions` | 置信度: 80

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

## 3. High 漏洞 (2)

### [VULN-DF-CORE-006] buffer_overflow - NormalKmeans

**严重性**: High | **CWE**: CWE-119 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `src/kvecturbo.cpp:716-726` @ `NormalKmeans`
**模块**: core

**描述**: memcpy_s in NormalKmeans with remainingSize truncation to SECUREC_MEM_MAX_LEN. When remainingSize exceeds SECUREC_MEM_MAX_LEN, it is capped but actual copy size dimensions * sizeof(float) may exceed the capped value, causing buffer overflow.

**漏洞代码** (`src/kvecturbo.cpp:716-726`)

```c
size_t remainingSize = static_cast<size_t>((numSamples - i) * dimensions * sizeof(float)); if (remainingSize > SECUREC_MEM_MAX_LEN) { remainingSize = SECUREC_MEM_MAX_LEN; } errno_t result = memcpy_s(samplesData.get() + i * dimensions, remainingSize, vec->x, dimensions * sizeof(float));
```

**达成路径**

[SOURCE] NormalKmeans@662 samples->length, samples->dim (semi_trusted)\n[PROPAGATION] Line 716: remainingSize = (numSamples - i) * dimensions * sizeof(float)\n[TRUNCATION] Line 717-719: remainingSize capped to SECUREC_MEM_MAX_LEN\n[SINK] Line 720-721: memcpy_s with dstSize=remainingSize (capped), srcSize=dimensions*sizeof(float) (uncapped)\n[OVERFLOW] If dimensions*sizeof(float) > SECUREC_MEM_MAX_LEN, buffer overflow occurs

**验证说明**: SECUREC_MEM_MAX_LEN truncation causes buffer overflow. When dimensions*sizeof(float) > SECUREC_MEM_MAX_LEN, memcpy_s srcSize exceeds capped dstSize.

**深度分析**

**根因分析**:

该漏洞位于 `NormalKmeans` 函数的数据转换循环中（第 716-721 行）。问题源于安全检查逻辑的设计缺陷：

```c
// src/kvecturbo.cpp:716-721
size_t remainingSize = static_cast<size_t>((numSamples - i) * dimensions * sizeof(float));
if (remainingSize > SECUREC_MEM_MAX_LEN) {
    remainingSize = SECUREC_MEM_MAX_LEN;
}
errno_t result = memcpy_s(samplesData.get() + i * dimensions, remainingSize, vec->x, dimensions * sizeof(float));
```

漏洞的根因在于：
1. `remainingSize` 用于限制目标缓冲区大小（`dstSize` 参数），被截断到 `SECUREC_MEM_MAX_LEN`
2. 但实际拷贝的数据大小 `dimensions * sizeof(float)` 没有被限制
3. 当 `dimensions * sizeof(float) > SECUREC_MEM_MAX_LEN` 时，`memcpy_s` 的源数据大小超过了目标缓冲区的声明大小

**触发条件**:
- `dimensions > SECUREC_MEM_MAX_LEN / sizeof(float)` 时触发
- 假设 `SECUREC_MEM_MAX_LEN` 为典型值 0x7FFFFFFF（约 2GB），则 `dimensions > 536,870,911` 时触发
- 实际触发阈值取决于 `SECUREC_MEM_MAX_LEN` 的具体定义

**潜在利用场景**:

1. **服务拒绝 (DoS)**: 攻击者可以构造高维向量数据（如 `dimensions = 1,000,000,000`），触发缓冲区溢出导致程序崩溃。

2. **内存破坏**: 溢出写入可能覆盖相邻内存区域，破坏关键数据结构，导致不可预测的行为。

3. **潜在代码执行**: 如果攻击者能精确控制溢出内容和内存布局，可能实现任意代码执行（取决于系统的 ASLR/DEP 等保护机制）。

**修复建议**:

```c
// 修复方案：限制单次拷贝大小
size_t copySize = dimensions * sizeof(float);
if (copySize > SECUREC_MEM_MAX_LEN) {
    std::cerr << "Error: Vector dimensions too large for safe copy" << std::endl;
    errCondition.store(true);
    continue;
}
size_t remainingSize = static_cast<size_t>((numSamples - i) * dimensions * sizeof(float));
if (remainingSize > SECUREC_MEM_MAX_LEN) {
    remainingSize = SECUREC_MEM_MAX_LEN;
}
errno_t result = memcpy_s(samplesData.get() + i * dimensions, remainingSize, vec->x, copySize);
```

---

### [VULN-DF-CORE-020] cross_module_data_flow - ComputePQTable

**严重性**: High | **CWE**: CWE-119 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: unknown

**位置**: `src/kvecturbo.cpp:1027-1038` @ `ComputePQTable`
**模块**: core
**跨模块**: core → api

**描述**: Cross-module boundary violation: params->pqTable written by ComputePQTable writes pqM * pqKsub * itemSize bytes without validation of buffer capacity.

**漏洞代码** (`src/kvecturbo.cpp:1027-1038`)

```c
memcpy_s(pqTable + (m * pqKsub + i) * centers->itemSize, remainingSize, static_cast<void *>(vec), centers->itemSize);
```

**达成路径**

[SOURCE] params->pqTable from caller (api module boundary)\n[PROPAGATION] ComputePQTable writes pqM * pqKsub * itemSize bytes\n[DATA OUT] pqTable flows to: ComputeVectorPQCode@1198, GetPQDistanceTableSdc@1226, GetPQDistanceTableAdc@1365\n[CROSS MODULE] No size parameter tracking across module boundary\n[ISSUE] Each downstream function assumes pqTable has sufficient size

**验证说明**: Cross-module data flow confirmed. params->pqTable written by ComputePQTable flows to ComputeVectorPQCode, GetPQDistanceTableSdc, GetPQDistanceTableAdc without size tracking. Each downstream function assumes pqTable has sufficient size.

**深度分析**

**根因分析**:

该漏洞是典型的跨模块边界数据流安全问题。查看 `ComputePQTable` 函数的接口定义：

```c
// include/kvecturbo.h:74
KVEC_API_PUBLIC int ComputePQTable(VectorArray samples, PQParams *params);
```

函数接收 `PQParams *params`，其中包含 `char *pqTable` 字段（第 54 行），但接口中：
1. **没有传递 `pqTable` 的缓冲区大小**
2. **调用方无法告知函数其分配了多少空间**
3. **函数假设调用方已分配足够的空间**（`pqM * pqKsub * itemSize` 字节）

在函数实现中（第 1027-1031 行）：

```c
// src/kvecturbo.cpp:1027-1031
size_t remainingSize = (pqKsub - i) * centers->itemSize;
errno_t result = memcpy_s(pqTable + (m * pqKsub + i) * centers->itemSize,
    remainingSize,
    static_cast<void *>(vec),
    centers->itemSize);
```

**问题**:
- `remainingSize` 计算的是从当前位置到缓冲区末尾的理论剩余空间
- 但这假设 `pqTable` 指向的缓冲区已经分配了 `pqM * pqKsub * itemSize` 字节
- 如果调用方分配的空间不足，`remainingSize` 的计算仍然会返回一个合理的值，但实际写入会越界

**影响范围**:

根据数据流分析，`pqTable` 被以下函数读取：
- `ComputeVectorPQCode` (src/kvecturbo.cpp:1198)
- `GetPQDistanceTableSdc` (src/kvecturbo.cpp:1226)
- `GetPQDistanceTableAdc` (src/kvecturbo.cpp:1365)

这些下游函数同样假设 `pqTable` 有足够大小，形成了连锁的安全假设。

**潜在利用场景**:

1. **缓冲区溢出**: 恶意调用方传入分配不足的 `pqTable`，触发写入越界
2. **信息泄露**: 下游函数读取越界数据，可能泄露敏感内存内容
3. **服务拒绝**: 内存破坏导致程序崩溃

**修复建议**:

```c
// 修复方案：在 API 中添加缓冲区大小参数
KVEC_API_PUBLIC int ComputePQTable(
    VectorArray samples, 
    PQParams *params,
    size_t pqTable_size);  // 新增参数

// 在函数开头验证缓冲区大小
size_t required_size = params->pqM * params->pqKsub * params->subItemSize;
if (pqTable_size < required_size) {
    std::cerr << "Error: pqTable buffer too small. Required: " << required_size 
              << ", provided: " << pqTable_size << std::endl;
    return -1;
}
```

---

## 4. Low 漏洞 (1)

### [VULN-SEC-API-006] insufficient_documentation - All API Functions

**严重性**: Low | **CWE**: CWE-476 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-module-scanner

**位置**: `include/kvecturbo.h:65-110` @ `All API Functions`
**模块**: api

**描述**: 头文件定义了返回值为 int 类型的错误码（0 表示成功），但未定义其他可能的错误码值。调用方无法区分不同类型的失败（如参数无效、内存不足、内部错误），也无法实现针对性的错误处理。建议定义完整的错误码枚举或宏。

**漏洞代码** (`include/kvecturbo.h:65-110`)

```c
KVEC_API_PUBLIC int ComputeVectorPQCode(...); // return 0 for success
KVEC_API_PUBLIC int ComputePQTable(...); // return 0 for success
KVEC_API_PUBLIC int GetPQDistanceTableSdc(...); // return 0 for success
KVEC_API_PUBLIC int GetPQDistanceTableAdc(...); // return 0 for success
KVEC_API_PUBLIC int GetPQDistance(...); // return 0 for success
```

**达成路径**

include/kvecturbo.h:65-110 API 函数 [SOURCE] -> [SINK: 调用方无法正确处理错误]

**验证说明**: Confirmed documentation deficiency. Error codes not enumerated. Low security impact.

**评分明细**: evidence: All API functions return 0/-1. No explicit error code enumeration. Caller cannot distinguish error types. | mitigations: Consistent 0/-1 return pattern,stderr error messages | data_flow_verified: true

**深度分析**

**根因分析**:

查看所有公共 API 函数的定义，其返回值约定为：
- `0`: 成功
- `-1`: 失败

```c
// include/kvecturbo.h:63-110
// 所有函数的文档注释都标注 "@return int Error code, 0 for success"
```

**问题**:
1. **错误码缺乏语义**: 所有错误情况都返回 `-1`，调用方无法区分：
   - 参数无效（如 `nullptr` 参数）
   - 内存分配失败
   - 内部计算错误
   - 缓冲区大小不足

2. **错误处理困难**: 调用方代码通常如下：
   ```c
   int ret = ComputePQTable(samples, params);
   if (ret != 0) {
       // 无法知道具体错误原因
       // 只能打印通用错误信息或尝试所有可能的恢复策略
   }
   ```

3. **调试困难**: 错误发生时，开发者需要查看 stderr 日志或使用调试器才能确定具体错误原因。

**影响评估**:

虽然此问题不会直接导致安全漏洞，但会影响：
- 系统可靠性：错误处理逻辑不完善可能导致异常状态持续
- 运维效率：故障排查需要更多时间和资源
- 代码质量：调用方代码难以实现健壮的错误恢复

**修复建议**:

```c
// 定义错误码枚举
typedef enum {
    KVEC_SUCCESS = 0,
    KVEC_ERR_NULL_PARAM = -1,
    KVEC_ERR_INVALID_DIM = -2,
    KVEC_ERR_INVALID_SIZE = -3,
    KVEC_ERR_MEM_ALLOC = -4,
    KVEC_ERR_KMEANS_FAILED = -5,
    KVEC_ERR_BUFFER_OVERFLOW = -6,
} KVecErrorCode;

// 更新函数声明
KVEC_API_PUBLIC KVecErrorCode ComputeVectorPQCode(...);
KVEC_API_PUBLIC KVecErrorCode ComputePQTable(...);
```

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| api | 0 | 0 | 0 | 1 | 1 |
| core | 0 | 2 | 0 | 0 | 2 |
| **合计** | **0** | **2** | **0** | **1** | **3** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-119 | 2 | 66.7% |
| CWE-476 | 1 | 33.3% |

---

## 7. 修复建议

### 优先级 1: 立即修复

**VULN-DF-CORE-006 (buffer_overflow in NormalKmeans)**

该漏洞可能导致内存破坏和潜在代码执行，建议立即修复。

修复步骤：
1. 在 `memcpy_s` 调用前，验证 `dimensions * sizeof(float)` 不超过 `SECUREC_MEM_MAX_LEN`
2. 如果超过限制，返回错误码并记录错误日志
3. 添加对 `dimensions` 参数的上限验证，防止过大值传入

```c
// 在 NormalKmeans 函数开头添加参数验证
const size_t MAX_DIMENSIONS = SECUREC_MEM_MAX_LEN / sizeof(float);
if (dimensions > MAX_DIMENSIONS) {
    std::cerr << "Error: dimensions " << dimensions << " exceeds maximum " << MAX_DIMENSIONS << std::endl;
    return -1;
}
```

**VULN-DF-CORE-020 (cross_module_data_flow in ComputePQTable)**

该漏洞影响多个下游函数，建议立即修复。

修复步骤：
1. 修改 `ComputePQTable` API，添加 `pqTable_size` 参数
2. 在函数开头验证缓冲区大小是否满足要求
3. 同步更新所有调用方的代码

```c
// API 修改
KVEC_API_PUBLIC int ComputePQTable(
    VectorArray samples, 
    PQParams *params,
    size_t pqTable_size);

// 验证逻辑
size_t required = params->pqM * params->pqKsub * params->subItemSize;
if (pqTable_size < required) {
    std::cerr << "Error: pqTable buffer insufficient" << std::endl;
    return KVEC_ERR_BUFFER_OVERFLOW;
}
```

### 优先级 2: 短期修复

无 Medium 严重性漏洞。

### 优先级 3: 计划修复

**VULN-SEC-API-006 (insufficient_documentation)**

该问题不影响系统安全性，但影响代码可维护性，建议在下一个版本中修复。

修复步骤：
1. 定义 `KVecErrorCode` 枚举，包含所有可能的错误码
2. 更新所有 API 函数的返回类型和文档注释
3. 更新所有内部函数使用新的错误码
4. 在调用方代码中实现针对性的错误处理

**建议的错误码定义**:

| 错误码 | 值 | 含义 |
|--------|-----|------|
| `KVEC_SUCCESS` | 0 | 成功 |
| `KVEC_ERR_NULL_PARAM` | -1 | 参数为空指针 |
| `KVEC_ERR_INVALID_DIM` | -2 | 无效的维度参数 |
| `KVEC_ERR_INVALID_SIZE` | -3 | 无效的大小参数 |
| `KVEC_ERR_MEM_ALLOC` | -4 | 内存分配失败 |
| `KVEC_ERR_KMEANS_FAILED` | -5 | K-means 聚类失败 |
| `KVEC_ERR_BUFFER_OVERFLOW` | -6 | 缓冲区溢出风险 |
| `KVEC_ERR_INTERNAL` | -99 | 内部错误 |

---

## 8. 总结

本次扫描发现 KVecTurbo 库存在 **2 个高风险缓冲区溢出漏洞** 和 **1 个低风险 API 文档问题**。高风险漏洞主要集中在内存安全检查逻辑上：

1. `NormalKmeans` 中的安全检查逻辑错误导致 `memcpy_s` 的源数据大小超过目标缓冲区声明大小
2. `ComputePQTable` 跨模块边界缺少缓冲区大小验证，可能导致写入越界

鉴于该库作为 openGauss 数据库的向量检索核心组件，建议优先修复高风险漏洞，并完善 API 错误处理规范。同时建议增加单元测试覆盖边界条件，并考虑引入静态分析工具到 CI/CD 流程中。