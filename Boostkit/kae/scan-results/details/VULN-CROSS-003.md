# VULN-CROSS-003: 跨模块硬件信任漏洞 - 无边界检查的硬件输出值

## 漏洞摘要

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-CROSS-003 |
| **类型** | Hardware Trust Issue / Buffer Overflow |
| **CWE** | CWE-1309 (Improper Protection Against Physical Side Channels) / CWE-787 (Out-of-bounds Write) |
| **严重性** | **High** (原始 Medium，验证后升级) |
| **置信度** | 85% → **CONFIRMED** |
| **影响模块** | KAEZlib, KAEZstd, KAELz4, KAESnappy (所有压缩模块) |
| **攻击向量** | Hardware DMA → 无验证的 memcpy |

---

## 漏洞描述

所有 KAE 压缩模块（KAEZlib、KAEZstd、KAELz4、KAESnappy）信任来自鲲鹏 ZIP 硬件加速器的 DMA 输出值，未进行任何边界验证。硬件返回的 `lit_num` 和 `seq_num` 值（32位无符号整数，最大可达 4GB）被直接用于 memcpy 操作或指针运算，而目标缓冲区容量有限（最大 8MB），导致缓冲区溢出风险。

**核心问题**：
- 硬件值来源：`sqe->comp_data_length` → `lit_num`，`sqe->produced` → `seq_num`
- 这些值通过 DMA 从硬件返回，可被恶意/故障硬件篡改
- 所有压缩模块直接使用这些值进行 memcpy，无边界检查
- 目标缓冲区 `litStart` 和 `sequencesStart` 容量有限

---

## 漏洞位置

### 硬件值获取（根源）

**文件**: `uadk/v1/drv/hisi_zip_udrv.c`
```c
// Line 820-821: fill_priv_lz77_zstd()
format->lit_num = sqe->comp_data_length;  // ← 直接信任硬件值，无检查
format->seq_num = sqe->produced;           // ← 直接信任硬件值，无检查
```

**文件**: `uadk/drv/hisi_comp.c`
```c
// Line 1311-1312: get_data_size_lz77_zstd()
data->lit_num = sqe->comp_data_length;    // ← 直接信任硬件值，无检查
data->seq_num = sqe->produced;             // ← 直接信任硬件值，无检查
```

### 受影响模块

#### 1. KAEZstd V1

**文件**: `KAEZstd/src/v1/kaezstd_comp.c`
```c
// Line 28-33: kaezstd_data_parsing()
memcpy(zc->seqStore.litStart, config->zstd_data.literals_start, 
       config->zstd_data.lit_num);        // ← lit_num 未验证，最大 4GB
zc->seqStore.lit += config->zstd_data.lit_num;

memcpy((unsigned char*)zc->seqStore.sequencesStart, 
       config->zstd_data.sequences_start,
       config->zstd_data.seq_num * sizeof(seqDef)); // ← seq_num 未验证
zc->seqStore.sequences += config->zstd_data.seq_num;
```

#### 2. KAEZstd V2

**文件**: `KAEZstd/src/v2/kaezstd_compress.c`
```c
// Line 37-42: kaezstd_data_parsing()
memcpy(zc->seqStore.litStart, config->tuple.litStart, config->tuple.litlen);
zc->seqStore.lit += config->tuple.litlen;

memcpy((unsigned char*)zc->seqStore.sequencesStart, 
       config->tuple.sequencesStart,
       config->tuple.seqnum*sizeof(seqDef));  // ← litlen/seqnum 未验证
zc->seqStore.sequences += config->tuple.seqnum;
```

#### 3. KAELz4 V1

**文件**: `KAELz4/src/v1/kaelz4_comp.c`
```c
// Line 42, 50: kaelz4_data_parsing()
zc->seqStore.lit = zc->seqStore.litStart;
zc->seqStore.lit += config->lz4_data.lit_num;    // ← 指针偏移无检查

zc->seqStore.sequences = zc->seqStore.sequencesStart;
zc->seqStore.sequences += config->lz4_data.seq_num; // ← 指针偏移无检查
```

#### 4. KAELz4 V2

**文件**: `KAELz4/src/v2/kaelz4_compress.c`
```c
// Line 36-41: kaelz4_data_parsing()
memcpy(zc->seqStore.litStart, config->tuple.litStart, config->tuple.litlen);
zc->seqStore.lit += config->tuple.litlen;

memcpy((unsigned char*)zc->seqStore.sequencesStart, 
       config->tuple.sequencesStart,
       config->tuple.seqnum*sizeof(seqDef));  // ← litlen/seqnum 未验证
zc->seqStore.sequences += config->tuple.seqnum;
```

#### 5. KAESnappy V2

**文件**: `KAESnappy/src/v2/kaesnappy_compress.c`
```c
// Line 39-44: kaesnappy_data_parsing()
memcpy(zc->seqStore.litStart, config->tuple.litStart, config->tuple.litlen);
zc->seqStore.lit += config->tuple.litlen;

memcpy((unsigned char*)zc->seqStore.sequencesStart, 
       config->tuple.sequencesStart,
       config->tuple.seqnum*sizeof(seqDef));  // ← litlen/seqnum 未验证
zc->seqStore.sequences += config->tuple.seqnum;
```

---

## 数据流分析

```
┌─────────────────────────────────────────────────────────────────────┐
│                     鲲鹏 ZIP 硬件加速器 (DMA)                        │
├─────────────────────────────────────────────────────────────────────┤
│  硬件返回值:                                                         │
│  - sqe->comp_data_length (__u32, max 4GB) → lit_num                 │
│  - sqe->produced (__u32, max 4GB) → seq_num                         │
│                                                                      │
│  攻击向量:                                                           │
│  1. 恶意硬件固件返回超大值                                            │
│  2. 硬件故障/DMA损坏                                                  │
│  3. 物理攻击篡改 DMA 数据                                             │
└─────────────────────────────────────────────────────────────────────┘
                                    ↓
                                    ↓ 无验证直接赋值
                                    ↓
┌─────────────────────────────────────────────────────────────────────┐
│               uadk/v1/drv/hisi_zip_udrv.c:820-821                   │
│               uadk/drv/hisi_comp.c:1311-1312                        │
├─────────────────────────────────────────────────────────────────────┤
│  format->lit_num = sqe->comp_data_length;                           │
│  format->seq_num = sqe->produced;                                   │
│                                                                      │
│  ❌ 缺失检查:                                                        │
│  - lit_num ≤ lits_size (缓冲区容量)                                  │
│  - seq_num ≤ seq_capacity (序列容量)                                 │
└─────────────────────────────────────────────────────────────────────┘
                                    ↓
                                    ↓ 传递到压缩模块
                                    ↓
┌─────────────────────────────────────────────────────────────────────┐
│              所有压缩模块的 data_parsing 函数                         │
├─────────────────────────────────────────────────────────────────────┤
│  KAEZstd V1: memcpy(litStart, ..., lit_num)                         │
│  KAEZstd V2: memcpy(litStart, ..., litlen)                          │
│  KAELz4 V1:  lit += lit_num (指针越界)                               │
│  KAELz4 V2:  memcpy(litStart, ..., litlen)                          │
│  KAESnappy V2: memcpy(litStart, ..., litlen)                        │
│                                                                      │
│  ❌ 目标缓冲区容量有限:                                               │
│  - HZ_MAX_SIZE = 8MB (最大用户缓冲区)                                │
│  - 硬件值可达 4GB                                                    │
│  → 缓冲区溢出！                                                      │
└─────────────────────────────────────────────────────────────────────┘
                                    ↓
                                    ↓ 内存损坏
                                    ↓
┌─────────────────────────────────────────────────────────────────────┐
│                          安全影响                                    │
├─────────────────────────────────────────────────────────────────────┤
│  ✗ 堆缓冲区溢出 (Heap Buffer Overflow)                              │
│  ✗ 内存损坏 (Memory Corruption)                                     │
│  ✗ 可能的代码执行 (Arbitrary Code Execution)                         │
│  ✗ 拒绝服务 (Denial of Service)                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 控制流分析

```
1. 用户调用压缩 API (如 ZSTD_compress, LZ4_compress)
   ↓
2. 请求发送到鲲鹏 ZIP 硬件加速器
   ↓
3. 硬件处理并返回结果 (通过 DMA)
   - sqe->comp_data_length → lit_num
   - sqe->produced → seq_num
   ↓
4. 驱动层解析硬件响应
   [hisi_zip_udrv.c:820-821]
   format->lit_num = sqe->comp_data_length;  ← 直接赋值，无检查
   format->seq_num = sqe->produced;
   ↓
5. 值传递到压缩模块
   ↓
6. 压缩模块 data_parsing 函数
   [kaezstd_comp.c:28-32]
   memcpy(zc->seqStore.litStart, ..., lit_num);  ← 无边界检查
   memcpy(zc->seqStore.sequencesStart, ..., seq_num*sizeof(seqDef));
   ↓
7. 如果硬件返回恶意超大值 → 缓冲区溢出
```

---

## 缓冲区容量分析

| 缓冲区 | 定义位置 | 容量限制 |
|--------|---------|---------|
| litStart | seqStore 结构 | 受输入大小限制，通常 ≤ 64KB + 预留 |
| sequencesStart | seqStore 结构 | `seq_avail_out = out_size - lits_size` |
| HZ_MAX_SIZE | hisi_comp.c:79 | 8MB (用户缓冲区上限) |
| HARDWARE_BLOCK_SIZE | kaelz4_comp.h:31 | 64KB (硬件块大小) |

**问题**：硬件返回值可达 4GB（32位最大值），远超缓冲区容量。

---

## 攻击向量

### 1. 恶意硬件固件
- 鲲鹏 ZIP 加速器固件被篡改
- 返回超大 `comp_data_length` 或 `produced` 值
- 导致所有使用该硬件的系统缓冲区溢出

### 2. 硬件故障/DMA 损坏
- 硬件故障导致 DMA 数据损坏
- 返回无效的大值
- 触发意外缓冲区溢出

### 3. 物理攻击
- 物理访问篡改 DMA 数据传输
- 修改硬件 SQE 字段
- 实现内存攻击

### 4. 恶意虚拟化环境
- 在虚拟化环境中，恶意 hypervisor 可篡改硬件响应
- 影响所有使用 KAE 压缩的虚拟机

---

## 安全影响

### 直接影响

1. **堆缓冲区溢出 (CWE-787)**
   - memcpy 使用超大值作为长度参数
   - 溢出目标缓冲区 `litStart` 或 `sequencesStart`
   - 覆盖相邻堆内存

2. **内存损坏**
   - 损坏其他数据结构
   - 损坏堆管理元数据
   - 导致程序状态异常

3. **可能的代码执行**
   - 如果攻击者能控制溢出内容
   - 可能覆盖函数指针或 vtable
   - 实现任意代码执行

### 间接影响

1. **拒绝服务 (DoS)**
   - 程序崩溃
   - 服务中断

2. **信息泄露**
   - 溢出可能导致敏感数据泄露
   - 内存损坏可能导致未初始化数据暴露

3. **跨模块影响**
   - 所有压缩模块都受影响
   - 攻击一个模块可能影响整个系统

---

## 严重性评估

### 评分依据

| 因素 | 评估 | 分数 |
|------|------|------|
| **攻击向量** | Hardware/DMA | 需要物理访问或恶意固件，降低可利用性 |
| **影响范围** | 所有压缩模块 | 影响面广 |
| **技术难度** | 缓冲区溢出是已知攻击模式 | 概念验证简单 |
| **实际后果** | 内存损坏 → 可能代码执行 | 严重 |
| **发现位置** | 驱动层 + 应用层 | 多层防护缺失 |

### 为什么从 Medium 升级到 High

1. **跨模块共同漏洞模式**：所有压缩模块都有相同问题
2. **缺乏任何缓解措施**：完全没有边界检查
3. **硬件信任假设危险**：硬件输出不应被无条件信任
4. **缓冲区溢出是高危漏洞**：可能导致代码执行

---

## 缺失的安全检查

### 当前代码缺失

```c
// ❌ 当前代码：无任何检查
memcpy(zc->seqStore.litStart, ..., config->zstd_data.lit_num);
```

### 应有的安全检查

```c
// ✓ 正确做法：添加边界检查
if (config->zstd_data.lit_num > max_lit_capacity) {
    US_ERR("Hardware returned invalid lit_num: %u exceeds capacity %u\n",
           config->zstd_data.lit_num, max_lit_capacity);
    return KAE_ZSTD_HW_ERROR;
}

if (config->zstd_data.seq_num > max_seq_capacity) {
    US_ERR("Hardware returned invalid seq_num: %u exceeds capacity %u\n",
           config->zstd_data.seq_num, max_seq_capacity);
    return KAE_ZSTD_HW_ERROR;
}

// 安全的 memcpy
memcpy(zc->seqStore.litStart, ..., config->zstd_data.lit_num);
```

---

## 缓解措施建议

### 1. 驱动层验证（根源防护）

在硬件值获取处添加验证：

```c
// hisi_zip_udrv.c 或 hisi_comp.c
// 在赋值前验证硬件值

// 计算预期最大值
__u32 expected_lit_max = recv_msg->in_size + ZSTD_LIT_RSV_SIZE;
__u32 expected_seq_max = recv_msg->avail_out / sizeof(seqDef);

// 验证 lit_num
if (sqe->comp_data_length > expected_lit_max) {
    WD_ERR("Hardware returned invalid lit_num: %u exceeds expected max %u\n",
           sqe->comp_data_length, expected_lit_max);
    // 拒绝该值或设置安全上限
    format->lit_num = expected_lit_max;  // 或返回错误
}

// 验证 seq_num
if (sqe->produced > expected_seq_max) {
    WD_ERR("Hardware returned invalid seq_num: %u exceeds expected max %u\n",
           sqe->produced, expected_seq_max);
    format->seq_num = expected_seq_max;  // 或返回错误
}
```

### 2. 应用层验证（深度防护）

在每个压缩模块的 data_parsing 函数中添加检查：

```c
// kaezstd_comp.c / kaelz4_comp.c 等
static int kaezstd_data_parsing(ZSTD_CCtx* zc, kaezstd_ctx_t* config)
{
    // 获取缓冲区容量
    size_t lit_capacity = zc->seqStore.litCapacity;  // 需要追踪此值
    size_t seq_capacity = zc->seqStore.seqCapacity;
    
    // 边界检查
    if (config->zstd_data.lit_num > lit_capacity) {
        US_ERR("Invalid lit_num from hardware: %u > capacity %zu\n",
               config->zstd_data.lit_num, lit_capacity);
        return KAE_ZSTD_INVAL_PARA;
    }
    
    if (config->zstd_data.seq_num * sizeof(seqDef) > seq_capacity) {
        US_ERR("Invalid seq_num from hardware: %u > capacity %zu\n",
               config->zstd_data.seq_num, seq_capacity / sizeof(seqDef));
        return KAE_ZSTD_INVAL_PARA;
    }
    
    // 安全的 memcpy
    memcpy(zc->seqStore.litStart, config->zstd_data.literals_start, 
           config->zstd_data.lit_num);
    ...
}
```

### 3. 硬件状态验证

```c
// 检查硬件返回的状态字段
if (sqe->dw3 & HZ_STATUS_MASK) {
    // 硬件返回错误状态，不应信任输出值
    return HW_ERROR;
}
```

---

## PoC 构思（概念验证）

### 模拟攻击场景

由于无法直接访问鲲鹏硬件，可以通过以下方式验证漏洞存在性：

1. **代码审计**：确认缺少边界检查
2. **静态分析**：使用工具检测 memcpy 参数问题
3. **模拟测试**：构造模拟硬件返回超大值

```c
// 测试代码：模拟硬件返回超大值
void test_hardware_trust_vulnerability() {
    kaezstd_ctx_t config;
    ZSTD_CCtx zc;
    
    // 模拟硬件返回恶意值
    config.zstd_data.lit_num = 0xFFFFFFFF;  // 4GB - 1
    config.zstd_data.seq_num = 0xFFFFFFFF;
    config.zstd_data.literals_start = mock_src;
    config.zstd_data.sequences_start = mock_src;
    
    // 调用 data_parsing
    // 预期：缓冲区溢出或程序崩溃
    kaezstd_data_parsing(&zc, &config);
}
```

---

## 相关漏洞

本漏洞是以下已确认漏洞的共同根源：

- **VULN-SEC-ZSTD-001**: KAEZstd V1 无边界检查 memcpy
- **VULN-SEC-ZSTD-002**: KAEZstd V2 无边界检查 memcpy  
- **VULN-SEC-LZ4-001**: KAELz4 无边界检查

---

## 修复优先级

| 等级 | 描述 |
|------|------|
| **P1 - Critical** | 所有压缩模块都受影响，应立即修复 |

### 修复步骤

1. 在驱动层添加硬件值验证（最关键）
2. 在每个压缩模块添加边界检查（深度防护）
3. 添加单元测试验证边界检查生效
4. 更新文档说明硬件输出验证策略

---

## 验证说明

### 验证过程

1. **代码审查**：确认所有压缩模块使用相同的硬件值处理模式
2. **数据流追踪**：从硬件 SQE → 驱动赋值 → 模块 memcpy
3. **缓冲区容量分析**：确认目标缓冲区容量有限
4. **攻击向量评估**：确认硬件/DMA 是可信攻击路径

### 验证结论

**确认漏洞真实存在**，理由：

1. 硬件值来源明确（DMA）
2. 无任何边界检查代码
3. 目标缓冲区容量有限
4. 所有模块都有相同问题
5. 符合 CWE-787 缓冲区溢出定义

---

## 参考资料

- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [CWE-1309: Improper Protection Against Physical Side Channels](https://cwe.mitre.org/data/definitions/1309.html)
- [鲲鹏加速器文档](https://www.hikunpeng.com/)
- [DMA 安全最佳实践](https://www.kernel.org/doc/html/latest/driver-api/dmaengine.html)

---

**报告生成时间**: 2026-04-21  
**分析者**: Security Auditor  
**状态**: CONFIRMED
