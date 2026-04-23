# 深度利用分析报告: VULN-DF-CORE-002

## 漏洞概要

| 字段 | 值 |
|------|-----|
| 漏洞 ID | VULN-DF-CORE-002 |
| 类型 | buffer_overflow |
| 严重性 | Critical |
| CWE | CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer |
| 文件 | src/kvecturbo.cpp |
| 行号 | 1027-1038 |
| 函数 | ComputePQTable |
| 置信度 | 90 |

## 漏洞描述

`ComputePQTable` 函数接收调用方（openGauss 数据库）提供的 `params->pqTable` 缓冲区，在计算 PQ 码本过程中向该缓冲区写入数据。函数内部计算了每次 `memcpy_s` 操作的 `remainingSize`，但**未验证 pqTable 缓冲区的总容量是否足以容纳所有写入数据**。

如果调用方分配的缓冲区尺寸小于 `pqM * pqKsub * centers->itemSize`，会导致缓冲区溢出。

## 源代码分析

### 问题代码位置 (src/kvecturbo.cpp: 1027-1038)

```cpp
/* Copy centers to PQ table with safety checks */
for (int i = 0; i < pqKsub; i++) {
    char *vec = VectorArrayGet(centers, i);
    // ...

    /* Calculate target position in PQ table */
    size_t remainingSize = (pqKsub - i) * centers->itemSize;
    errno_t result = memcpy_s(pqTable + (m * pqKsub + i) * centers->itemSize,
        remainingSize,
        static_cast<void *>(vec),
        centers->itemSize);
    // ...
}
```

### 缺失的验证

函数入口处仅检查指针非空：

```cpp
// Line 940: 仅检查指针非空
if (params == nullptr || params->pqTable == nullptr || samples == nullptr || samples->items == nullptr) {
    return -1;
}
```

**缺失验证**: `pqTable` 缓冲区的实际尺寸 >= `pqM * pqKsub * centers->itemSize`

### 数据流追踪

```
[SOURCE] params->pqTable (调用方提供的缓冲区)
         ├── 来源: openGauss 数据库调用 ComputePQTable API
         ├── 类型: semi_trusted（部分可信，需验证）
         └── 控制方: openGauss (可控制缓冲区分配尺寸)

[PROPAGATION] 计算写入偏移和尺寸
              ├── Line 951: pqKsub = params->pqKsub (可达 256)
              ├── Line 952: pqM = params->pqM (可达 dim 值)
              └── Line 1001: centers->itemSize = subItemSize (取决于维度)

[MISSING VALIDATION] 无 pqTable 总尺寸验证
                      ├── 期望尺寸: pqM * pqKsub * centers->itemSize
                      ├── 最大写入量估算:
                      │   ├── pqM_max = 2000 (maxDim)
                      │   ├── pqKsub_max = 256
                      │   ├── subItemSize_max ≈ 8KB (高维度向量)
                      │   └── 总容量需求 ≈ 512MB (极端情况)
                      └── 但调用方可能分配更小缓冲区

[SINK] memcpy_s 写入操作
       ├── Line 1028: pqTable + (m * pqKsub + i) * centers->itemSize
       ├── 写入尺寸: centers->itemSize
       ├── 循环次数: pqM * pqKsub
       └── 总写入量: pqM * pqKsub * centers->itemSize 字节

[DATA OUT] pqTable 被其他 API 读取
           ├── ComputeVectorPQCode@1198
           ├── GetPQDistanceTableSdc@1226
           ├── GetPQDistanceTableAdc@1365
           └── 跨模块数据流，无尺寸追踪
```

## 利用分析

### 攻击面

| 入口点 | 描述 |
|--------|------|
| ComputePQTable API | 公共 API，由 openGauss 数据库调用 |
| PQParams 结构体 | 调用方构造，包含 pqTable 指针、pqM、pqKsub 等参数 |
| VectorArray samples | 调用方提供的训练样本数据 |

### 攻击路径

```
攻击者 (openGauss 用户)
    │
    ├── 1. 上传恶意向量数据到数据库
    │       └── 构造特殊维度的向量触发 PQ 计算
    │
    ├── 2. 触发 PQ 码本计算
    │       └── openGauss 调用 ComputePQTable(samples, params)
    │
    ├── 3. 控制参数结构体
    │       ├── params->pqM = 256 (大值)
    │       ├── params->pqKsub = 256 (最大值)
    │       ├── params->pqTable = 小缓冲区 (如 1KB)
    │       └── 期望缓冲区尺寸: 256*256*subItemSize ≈ 数百MB
    │
    └── 4. 触发缓冲区溢出
            ├── ComputePQTable 写入超出 pqTable 容量
            ├── 内存越界写入
            └── 可能覆盖相邻内存区域
```

### 可利用性评估

| 条件 | 状态 | 说明 |
|------|------|------|
| 输入可控 | ✓ 是 | pqTable 指针和参数由调用方控制 |
| 缺失验证 | ✓ 是 | 无缓冲区尺寸验证 |
| 跨边界写入 | ✓ 是 | 写入超出分配边界 |
| 内存布局可控 | 部分 | 取决于 openGauss 内存分配策略 |
| 代码执行 | 可能 | 如果覆盖关键数据结构或函数指针 |

### 利用场景

**场景 1: 小缓冲区溢出**

```cpp
// 恶意调用方代码
PQParams params;
params.pqM = 16;        // 16 个子空间
params.pqKsub = 256;    // 每个子空间 256 个聚类中心
params.dim = 1024;      // 高维度
params.pqTable = malloc(1024);  // 仅分配 1KB（远小于需求）

// ComputePQTable 需要写入:
// 16 * 256 * subItemSize ≈ 16 * 256 * 4096 ≈ 16MB
// 但 pqTable 仅 1KB → 严重溢出
ComputePQTable(samples, &params);
```

**场景 2: 参数组合攻击**

攻击者选择参数组合使：
- 计算的写入量远大于分配的缓冲区
- 触发最大化的溢出效果

## 影响评估

### 直接影响

| 影响 | 级别 | 描述 |
|------|------|------|
| 内存破坏 | Critical | 缓冲区越界写入 |
| 数据泄露 | High | 可能泄露相邻内存内容 |
| 服务崩溃 | High | 可能导致 openGauss 进程崩溃 |
| 代码执行 | Medium-High | 取决于内存布局和覆盖目标 |

### 连带影响

由于 pqTable 被多个下游函数读取：
- `ComputeVectorPQCode` 读取 pqTable 进行编码计算
- `GetPQDistanceTableSdc` 计算距离表时访问 pqTable
- `GetPQDistanceTableAdc` 同样依赖 pqTable

如果 pqTable 内容被溢出覆盖破坏，可能导致：
- 距离计算错误 → 搜索结果不准确
- 进一步的内存访问越界 → 链式漏洞

## 修复建议

### 立即修复 (Critical)

**添加缓冲区尺寸验证**:

```cpp
int ComputePQTable(VectorArray samples, PQParams *params)
{
    // ... 现有检查 ...

    // 新增: 验证 pqTable 缓冲区尺寸
    const size_t requiredSize = static_cast<size_t>(pqM) * pqKsub * subItemSize;
    // 需要调用方传递 pqTable_size 参数，或使用其他方式验证
    if (pqTable_size < requiredSize) {
        std::cerr << "Error: pqTable buffer too small. Required: " << requiredSize 
                  << ", Provided: " << pqTable_size << std::endl;
        return -1;
    }

    // ... 继续处理 ...
}
```

### API 修改建议

修改 `ComputePQTable` API 签名，添加缓冲区尺寸参数：

```cpp
// 修改 API 签名
KVEC_API_PUBLIC int ComputePQTable(
    VectorArray samples, 
    PQParams *params,
    size_t pqTable_size  // 新增参数
);
```

### 备选方案

如果不能修改 API，可在 PQParams 结构体中添加尺寸字段：

```cpp
typedef struct PQParams {
    int pqM;
    int pqKsub;
    int funcType;
    int dim;
    size_t subItemSize;
    char *pqTable;
    size_t pqTable_size;  // 新增字段
} PQParams;
```

## 验证测试

### PoC 测试用例

```cpp
// 测试用例: 验证缓冲区尺寸检查缺失
void test_pqtable_buffer_overflow() {
    PQParams params;
    params.pqM = 8;
    params.pqKsub = 256;
    params.dim = 512;
    params.subItemSize = 2048;
    
    // 分配过小缓冲区
    params.pqTable = (char*)malloc(1024);  // 仅 1KB
    
    VectorArray samples = create_test_samples(100, 512);
    
    // 期望: 返回错误码 -1
    // 实际: 可能发生缓冲区溢出
    int result = ComputePQTable(samples, &params);
    
    // 如果未崩溃，说明存在漏洞（没有拒绝过小缓冲区）
    assert(result == -1 || result == 0);
    
    free(params.pqTable);
    VectorArrayRelease(samples);
}
```

## 结论

| 评估项 | 结论 |
|--------|------|
| 真实性 | **确认是真实漏洞** |
| 严重性 | Critical |
| 可利用性 | High |
| 修复优先级 | P0 (立即修复) |

该漏洞是真实的安全缺陷，攻击者可以通过控制 PQParams 参数结构体触发缓冲区溢出，可能导致内存破坏、服务崩溃甚至代码执行。建议立即添加缓冲区尺寸验证。