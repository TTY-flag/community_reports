# KVecTurbo 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析基于 AI 自主识别，未使用 threat.md 约束文件。

## 1. 项目架构概览

### 1.1 项目基本信息

| 项目属性 | 说明 |
|---------|------|
| 项目名称 | KVecTurbo |
| 项目类型 | C++ 库/SDK |
| 主要功能 | 高维向量量化压缩（PQ）、K-means 聚类、SIMD 距离计算加速 |
| 目标平台 | 鲲鹏 920 7282C 处理器，NEON 指令集（128位） |
| 部署方式 | 作为动态库（.so）或静态库链接到 openGauss 向量数据库 |
| 源文件数 | 3 个核心文件（不含文档和测试） |
| 总代码行数 | 2055 行 |

### 1.2 目录结构

```
kvecturbo/
├── include/
│   └── kvecturbo.h      # 公共 API 头文件 (118行)
├── src/
│   └── kvecturbo.cpp    # 核心实现 (1395行)
├── test/
│   └── ut_test/
│       └── test.cpp     # 单元测试 (542行)
└── docs/                # 文档目录
```

### 1.3 核心模块划分

| 模块 | 文件 | 功能 | 语言 |
|------|------|------|------|
| API 接口 | include/kvecturbo.h | 公共 API 定义、结构体定义 | c_cpp |
| 核心计算 | src/kvecturbo.cpp | K-means、PQ 编码/搜索、SIMD 加速 | c_cpp |
| 测试 | test/ut_test/test.cpp | 单元测试 | c_cpp |

## 2. 攻击面分析

### 2.1 项目定位与信任边界

**项目类型判断**：`library`（库/SDK）

- 无 main() 函数，无独立进程
- 导出 5 个公共 API（`KVEC_API_PUBLIC` 标记）
- 作为 openGauss 向量数据库的加速组件被调用
- 数据来源：数据库用户上传的向量数据和查询请求

**信任边界模型**：

| 边界 | 可信侧 | 不可信侧 | 风险等级 |
|------|--------|----------|----------|
| Library API | KVecTurbo 内部计算 | openGauss 传入的用户向量数据 | High |
| Memory Operations | 库内部内存管理 | 调用方提供的缓冲区和参数 | High |
| Parallel Computing | OpenMP 线程内部 | 共享数据竞争 | Medium |

### 2.2 公共 API 入口点

| API 函数 | 位置 | 入口类型 | 信任等级 | 主要风险 |
|---------|------|----------|----------|----------|
| ComputeVectorPQCode | kvecturbo.h:65 | rpc | semi_trusted | 接收外部向量，触发内存操作 |
| ComputePQTable | kvecturbo.h:74 | rpc | semi_trusted | 接收样本数据，触发 K-means 和大量内存分配 |
| GetPQDistanceTableSdc | kvecturbo.h:83 | rpc | semi_trusted | 参数验证可能不完整 |
| GetPQDistanceTableAdc | kvecturbo.h:92 | rpc | semi_trusted | 接收查询向量 |
| GetPQDistance | kvecturbo.h:108 | rpc | semi_trusted | 数组索引依赖外部参数 |

### 2.3 数据输入路径

```
数据库用户 → openGauss → KVecTurbo API → 内部计算
                                    ↓
                    [VectorArray/PQParams 结构体]
                                    ↓
                    [memcpy_s / malloc / 数组索引]
```

**关键数据流**：

1. **向量数据流**：用户向量 → ComputePQTable/ComputeVectorPQCode → memcpy_s → SIMD 操作
2. **参数数据流**：PQParams 结构体 → 内存大小计算 → malloc/calloc
3. **距离表数据流**：basecode/querycode → GetPQDistance → 数组索引访问

## 3. 高风险文件评估

### 3.1 文件风险评估

| 优先级 | 文件 | 风险等级 | 关键风险点 |
|--------|------|----------|------------|
| 1 | src/kvecturbo.cpp | Critical | 大量 memcpy_s (30+处)、malloc/calloc/free、NEON SIMD、OpenMP 并行、整数计算 |
| 2 | include/kvecturbo.h | High | 公共 API 定义、外部可控参数结构体 |
| 3 | test/ut_test/test.cpp | Low | 单元测试，非生产代码 |

### 3.2 关键风险函数

| 函数 | 行号 | 风险等级 | 风险描述 |
|------|------|----------|----------|
| ComputePQTable | 938 | Critical | 公共 API，触发 K-means 和大量内存操作，接收外部 VectorArray |
| NormalKmeans | 662 | Critical | 处理外部样本数据，OpenMP 并行内存访问，memcpy_s 循环 |
| VectorArrayGet | 90 | High | 数组索引计算，可能越界访问 |
| L2Distance2Simd | 157 | High | NEON SIMD 内存加载，依赖外部向量指针 |
| GetPQDistance | 1061 | High | 数组索引依赖 basecode 值，参数验证可能不足 |

## 4. STRIDE 威胁建模

### 4.1 Spoofing (欺骗)

**风险等级**：Low

- 作为库组件，无身份认证需求
- 调用方身份由 openGauss 数据库管理

### 4.2 Tampering (篡改)

**风险等级**：High

**威胁场景**：
- 用户上传的向量数据可能被篡改，导致：
  - 参数结构体字段（dim, pqM, pqKsub）包含恶意值
  - 内存大小计算结果异常，导致溢出或分配失败
  - 数组索引越界访问

**具体威胁点**：
| 位置 | 威胁描述 |
|------|----------|
| kvecturbo.cpp:984 | dsub = dim / pqM，整数除法可能导致异常值 |
| kvecturbo.cpp:225 | malloc(maxLen * itemSize)，乘法可能溢出 |
| kvecturbo.cpp:1095 | basecode[k++] 数组索引，依赖外部 basecode 值 |
| kvecturbo.cpp:169 | NEON vld1q_f32(pa + i)，SIMD 内存加载 |

### 4.3 Repudiation (抵赖)

**风险等级**：Low

- 库组件无操作日志需求
- 审计由上层 openGauss 数据库处理

### 4.4 Information Disclosure (信息泄露)

**风险等级**：Medium

**威胁场景**：
- 内存越界读取可能泄露相邻内存内容
- 未初始化内存可能导致数据泄露

**潜在泄露点**：
| 位置 | 威胁描述 |
|------|----------|
| VectorArrayInit:238 | calloc 初始化，但 malloc 分配的 res 未初始化 |
| L2SquaredDistanceNeonV2:927 | 剩余元素处理可能读取未对齐数据 |

### 4.5 Denial of Service (拒绝服务)

**风险等级**：High

**威胁场景**：
- 异常参数导致内存分配失败（OOM）
- 无限循环或死锁（OpenMP 并行区域）
- SIMD 操作崩溃导致整个数据库进程终止

**具体威胁点**：
| 位置 | 威胁描述 |
|------|----------|
| NormalKmeans:745 | K-means 循环 maxIterations=30，可能长时间阻塞 |
| ComputePQTable:979 | samplenum 参数过大导致内存耗尽 |
| OpenMP parallel | 并行线程异常可能导致部分线程阻塞 |

### 4.6 Elevation of Privilege (权限提升)

**风险等级**：Medium

**威胁场景**：
- 库以数据库进程权限运行，崩溃可能影响数据库整体稳定性
- 内存损坏可能导致后续操作异常

## 5. 模块风险评估汇总

| 模块 | STRIDE 分类 | 总风险等级 | 关键威胁 |
|------|-------------|------------|----------|
| API 接口层 | T, I, D | High | 参数篡改、信息泄露 |
| K-means 计算模块 | T, D | Critical | 内存操作、拒绝服务 |
| PQ 编码模块 | T, D | High | 数组索引、内存操作 |
| SIMD 加速模块 | T, D, I | High | 内存加载、进程崩溃 |
| 并行计算模块 | D | Medium | 线程竞争、阻塞 |

## 6. 安全加固建议

### 6.1 输入验证加固

1. **参数边界检查**：
   - 增强 PQParams 结构体字段验证（dim, pqM, pqKsub）
   - 验证 VectorArray.length <= VectorArray.maxLen
   - 检查 itemSize 与 dim 的计算关系

2. **整数溢出防护**：
   - 内存大小计算前检查乘法溢出（maxLen * itemSize）
   - 使用安全的整数运算库

3. **数组索引验证**：
   - GetPQDistance 中的 basecode 值检查（已有部分检查，建议增强）
   - offset 计算前验证 pqKsub 边界

### 6.2 内存安全加固

1. **现有防护措施（已实现）**：
   - 使用 memcpy_s 替代 memcpy（华为安全库）
   - 使用 std::unique_ptr 管理 K-means 临时内存
   - 参数 NULL 检查

2. **建议增强**：
   - VectorArrayInit 中 res 结构体使用 calloc 初始化
   - 增加内存分配失败的优雅处理（返回错误而非崩溃）
   - SIMD 操作前验证指针和长度

### 6.3 并行计算安全

1. **OpenMP 安全**：
   - 已使用 std::atomic<bool> errCondition 处理错误传播
   - 已使用 #pragma omp critical 保护敏感操作
   - 建议：增加 OpenMP cancel 后的资源清理

### 6.4 API 设计加固

1. **错误处理**：
   - 已使用返回值 0/-1 表示成功/失败
   - 建议：增加详细的错误码枚举

2. **版本兼容**：
   - 建议增加 API 版本号和参数校验函数

## 7. 扫描优先级建议

基于架构分析，建议后续漏洞扫描按以下优先级进行：

| 优先级 | 扫描目标 | 扫描类型 | 理由 |
|--------|----------|----------|------|
| P1 | src/kvecturbo.cpp | 数据流污点追踪 | Critical 文件，大量内存操作 |
| P2 | ComputePQTable 调用链 | 参数验证、内存安全 | 触发最复杂计算路径 |
| P3 | GetPQDistance 调用链 | 数组索引、边界检查 | 直接依赖外部参数值 |
| P4 | SIMD 函数族 | 内存对齐、指针验证 | NEON 指令集安全 |

---

**分析完成时间**：2026-04-22  
**分析工具**：Architecture Agent  
**下一步**：建议启动 DataFlow Scanner 进行详细漏洞扫描