# DISK-003: 异步IO偏移计算整数溢出致磁盘操作位置错误

## 漏洞概览

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | DISK-003 |
| **CWE 分类** | CWE-190 (Integer Overflow or Wraparound) |
| **严重性** | HIGH |
| **置信度** | 85 |
| **文件** | `ubsio-boostio/src/disk/common/bdm_disk.c:427` |
| **函数** | `BdmDiskSubmitAIO` |
| **跨模块影响** | Yes (disk, allocator, async I/O) |

---

## 1. 漏洞代码分析

### 1.1 漏洞位置

```c
// File: bdm_disk.c, Line 427
int32_t BdmDiskSubmitAIO(void **argList, uint32_t argNum, void *ctx)
{
    ...
    BdmIoContext *bdmIo = (BdmIoContext *)argList[i];
    BdmDiskItem *item = (BdmDiskItem *)bdmIo->item;
    uint64_t rwOffset = item->offset + item->dataOffset + item->minChunkSize * bdmIo->chunkId + bdmIo->offset;
    if (bdmIo->isRead) {
        io_prep_pread(&bdmIo->iocb, item->asyncfd[fdIdx], bdmIo->buf, bdmIo->len, rwOffset);
    } else {
        io_prep_pwrite(&bdmIo->iocb, item->asyncfd[fdIdx], bdmIo->buf, bdmIo->len, rwOffset);
    }
    ...
}
```

### 1.2 问题表达式

```c
uint64_t rwOffset = item->offset + item->dataOffset + item->minChunkSize * bdmIo->chunkId + bdmIo->offset;
```

该表达式包含 **4 个累加操作**：
1. `item->offset` - 磁盘设备的起始偏移（来自用户配置）
2. `item->dataOffset` - 数据区起始偏移（计算得出）
3. `item->minChunkSize * bdmIo->chunkId` - chunk 基地址
4. `bdmIo->offset` - chunk 内偏移

**没有任何溢出检查**。

---

## 2. 数据流分析

### 2.1 完整调用链

```
用户调用 BdmReadAsync/BdmWriteAsync(chunkId, offset, buf, len, ioCtx)
    ↓
BdmReadAsync (bdm_core.c:156) / BdmWriteAsync (bdm_core.c:196)
    ↓
req.chunkId = DENCODE_CHUNK_ID(chunkId)  // 解码为 48 位值
    ↓
BdmDiskHandleAIO(req, isRead) (bdm_disk.c:445)
    ↓
BdmAllocatorCheckChunk(allocator, chunkId, offset, len)  // 边界验证
    ↓
bdmIo->chunkId = req->chunkId
bdmIo->offset = req->offset
    ↓
BdmDiskSubmitAIO(argList, 1, threadCtx) (bdm_disk.c:408)
    ↓
rwOffset = item->offset + item->dataOffset + minChunkSize * bdmIo->chunkId + bdmIo->offset  // 无溢出检查
    ↓
io_prep_pread/pwrite(..., rwOffset)  // 使用溢出后的偏移值
```

### 2.2 数据来源

| 变量 | 来源 | 验证状态 |
|------|------|----------|
| `item->offset` | `para->offset` (用户配置) | **无验证** |
| `item->dataOffset` | `ROUND_UP(headSize + metaSize, BDM_ALIGN_SIZE)` | 计算得出 |
| `item->minChunkSize` | `para->minChunkSize` (用户配置) | 只检查非零 |
| `bdmIo->chunkId` | `req->chunkId` → `DENCODE_CHUNK_ID` | `BdmAllocatorCheckChunk` 检查 |
| `bdmIo->offset` | 用户传入 | 检查 `< BDM_MAX_CHUNK_LENGTH` |

---

## 3. 漏洞触发条件

### 3.1 关键发现：`para->offset` 无验证

在 `BdmDiskCreateCheck` 函数（bdm_disk.c:503-528）中：

```c
int32_t BdmDiskCreateCheck(BdmCreatePara *para)
{
    if (para->name == NULL || para->sn == NULL) {
        BDM_LOGERROR(0, "Invalid name or sn.");
        return BDM_CODE_INVALID_PARAM;
    }
    if (strlen(para->name) == 0UL || strlen(para->sn) == 0UL) {
        BDM_LOGERROR(0, "Invalid name or sn.");
        return BDM_CODE_INVALID_PARAM;
    }

    if (para->length == 0UL) {
        BDM_LOGERROR(0, "Invalid length(%lu).", para->length);
        return BDM_CODE_INVALID_PARAM;
    }

    if (para->minChunkSize == 0UL) {
        BDM_LOGERROR(0, "Invalid min chunk size(%lu).", para->minChunkSize);
        return BDM_CODE_INVALID_PARAM;
    }
    if (para->maxChunkSize == 0UL) {
        BDM_LOGERROR(0, "Invalid max chunk size(%lu), min chunk size(%lu).", 
                     para->maxChunkSize, para->minChunkSize);
        return BDM_CODE_INVALID_PARAM;
    }
    return BDM_CODE_OK;
}
```

**关键问题**：`para->offset` 没有任何验证！

### 3.2 溢出触发数学分析

设：
- `O_disk = item->offset` (磁盘设备偏移)
- `O_data = item->dataOffset` (数据区偏移)
- `C_size = item->minChunkSize` (最小 chunk 大小)
- `C_id = bdmIo->chunkId` (chunk ID)
- `O_chunk = bdmIo->offset` (chunk 内偏移)

溢出条件：
```
O_disk + O_data + C_size * C_id + O_chunk >= 2^64
```

**攻击场景**：

假设攻击者配置：
- `para->offset = 0xFFFFFFFFFFFFFF00` (接近 uint64_t 最大值)
- `para->length = 1073741824` (1GB)
- `para->minChunkSize = 4194304` (4MB)
- `para->maxChunkSize = 4194304` (4MB)

然后执行正常的异步读操作：
- `chunkId = 0` (有效 chunk)
- `offset = 0` (chunk 内偏移)

计算：
```
rwOffset = 0xFFFFFFFFFFFFFF00 + ~2MB + 0 + 0
         ≈ 0xFFFFFFFFFFFFFF00 + 0x200000
         ≈ 会溢出回绕到一个小值
```

结果：读取操作将在错误的磁盘位置执行！

---

## 4. PoC 构造思路

### 4.1 攻击前提条件

1. **攻击者能够控制磁盘配置**：通过 `BdmCreate` API 配置恶意 `para->offset`
2. **系统允许创建磁盘设备**：需要有效的磁盘路径和设备名称
3. **攻击者能够发起异步 I/O 操作**：调用 `BdmReadAsync` 或 `BdmWriteAsync`

### 4.2 PoC 概念代码

```c
#include "bdm_core.h"

int main() {
    BdmCreatePara para = {0};
    uint32_t bdmId;
    
    // 配置恶意偏移值 - 接近 uint64_t 最大值
    strncpy(para.name, "/tmp/test_disk", BDM_NAME_LEN);
    strncpy(para.sn, "malicious_sn", BDM_SN_LEN);
    para.offset = 0xFFFFFFFFFFFFFF00;  // 恶意偏移值！
    para.length = 1073741824UL;        // 1GB
    para.minChunkSize = 4194304UL;     // 4MB
    para.maxChunkSize = 4194304UL;     // 4MB
    
    // 创建恶意配置的磁盘
    int32_t ret = BdmCreate(&para, &bdmId);
    if (ret != BDM_CODE_OK) {
        printf("BdmCreate failed: %d\n", ret);
        return -1;
    }
    
    // 分配一个 chunk
    uint64_t chunkId;
    ret = BdmAlloc(bdmId, 0, 0, 4194304, &chunkId);
    if (ret != BDM_CODE_OK) {
        printf("BdmAlloc failed: %d\n", ret);
        return -1;
    }
    
    // 发起异步读操作 - 会触发溢出
    char buf[4194304];
    BdmIoCtx ioCtx;
    ioCtx.cb = callback;
    ioCtx.ctx = NULL;
    
    ret = BdmReadAsync(chunkId, 0, buf, 4194304, &ioCtx);
    
    // 由于 offset 溢出，实际读取位置是错误的
    // 可能读到其他数据或触发其他安全问题
    
    BdmDestroy(bdmId);
    return 0;
}
```

### 4.3 实际利用限制

1. **磁盘配置权限**：通常需要管理员权限配置磁盘设备
2. **磁盘文件存在**：需要实际的磁盘设备文件存在
3. **系统设计约束**：正常情况下 `offset` 应为 0 或合理的分区偏移

---

## 5. 实际可利用性评估

### 5.1 利用难度评估

| 因素 | 评估 | 说明 |
|------|------|------|
| 输入控制难度 | 中等 | 需要控制 `para->offset` 配置 |
| 触发条件复杂度 | 低 | 配置后任何异步 I/O 都可触发 |
| 攻击者位置要求 | 本地/管理 | 需要磁盘配置权限 |
| 利用可靠性 | 中等 | 溢出值可控，但依赖磁盘布局 |

### 5.2 影响范围评估

| 影响类型 | 严重性 | 说明 |
|----------|--------|------|
| 数据完整性 | 高 | 可导致数据写入错误位置 |
| 数据泄露 | 高 | 可读取非预期位置的数据 |
| 系统稳定性 | 中 | 可能触发磁盘 I/O 错误 |

### 5.3 实际攻击场景

**场景 1：分区偏移滥用**
- 某磁盘有多个分区，每个分区有自己的偏移
- 攻击者配置一个分区的偏移为极大值
- 溢出后读写操作可能跨越分区边界，破坏其他分区数据

**场景 2：多租户环境**
- 共享存储系统中，不同租户有不同磁盘设备
- 恶意租户配置异常偏移，溢出后访问其他租户数据

**场景 3：容器/虚拟化环境**
- 虚拟机或容器配置磁盘时设置异常偏移
- 可能突破隔离边界访问宿主机数据

---

## 6. 相似漏洞关联

### 6.1 同类型漏洞

本漏洞与 DISK-001 和 DISK-002 属于同一系列：

| 漏洞 ID | 位置 | 函数 | 描述 |
|---------|------|------|------|
| DISK-001 | bdm_disk.c:308 | `BdmDiskRead` | 同样的溢出模式 |
| DISK-002 | bdm_disk.c:337 | `BdmDiskWrite` | 同样的溢出模式 |
| DISK-003 | bdm_disk.c:427 | `BdmDiskSubmitAIO` | 异步 I/O 版本 |

### 6.2 共同问题根源

所有三个漏洞的根本原因是：
1. **偏移计算没有溢出检查**
2. **`para->offset` 配置参数无验证**
3. **依赖上游验证不够全面**

---

## 7. 修复建议

### 7.1 立即修复方案

#### 修复点 1：添加 `para->offset` 验证

```c
// File: bdm_disk.c, Line ~503
int32_t BdmDiskCreateCheck(BdmCreatePara *para)
{
    // 添加 offset 验证
    if (para->offset > BDM_MAX_DISK_OFFSET) {
        BDM_LOGERROR(0, "Invalid offset(%llu), exceeds maximum allowed.", para->offset);
        return BDM_CODE_INVALID_PARAM;
    }
    
    // 添加 offset + length 溢出检查
    if (para->offset + para->length < para->offset) {  // 溢出检测
        BDM_LOGERROR(0, "Offset + length overflow detected.");
        return BDM_CODE_INVALID_PARAM;
    }
    
    // ... 原有验证代码
}
```

定义常量：
```c
#define BDM_MAX_DISK_OFFSET (0x7FFFFFFFFFFFFFFFUL)  // uint64_t 最大值的一半
```

#### 修复点 2：添加偏移计算溢出检查

```c
// File: bdm_disk.c, Line ~427
int32_t BdmDiskSubmitAIO(void **argList, uint32_t argNum, void *ctx)
{
    ...
    BdmDiskItem *item = (BdmDiskItem *)bdmIo->item;
    
    // 使用安全乘法函数
    uint64_t chunkBase;
    if (!SafeMultiply(item->minChunkSize, bdmIo->chunkId, &chunkBase)) {
        BDM_LOGERROR(0, "Chunk offset multiplication overflow detected.");
        return BDM_CODE_ERR;
    }
    
    // 使用安全加法进行累加
    uint64_t rwOffset;
    if (!SafeAdd(item->offset, item->dataOffset, &rwOffset)) {
        BDM_LOGERROR(0, "Offset addition overflow detected.");
        return BDM_CODE_ERR;
    }
    if (!SafeAdd(rwOffset, chunkBase, &rwOffset)) {
        BDM_LOGERROR(0, "Chunk base addition overflow detected.");
        return BDM_CODE_ERR;
    }
    if (!SafeAdd(rwOffset, bdmIo->offset, &rwOffset)) {
        BDM_LOGERROR(0, "Final offset addition overflow detected.");
        return BDM_CODE_ERR;
    }
    
    // 添加边界检查
    if (rwOffset + bdmIo->len > item->offset + item->totalSize) {
        BDM_LOGERROR(0, "Disk offset exceeds bounds.");
        return BDM_CODE_ERR;
    }
    
    if (bdmIo->isRead) {
        io_prep_pread(&bdmIo->iocb, item->asyncfd[fdIdx], bdmIo->buf, bdmIo->len, rwOffset);
    } else {
        io_prep_pwrite(&bdmIo->iocb, item->asyncfd[fdIdx], bdmIo->buf, bdmIo->len, rwOffset);
    }
    ...
}
```

#### 修复点 3：实现安全算术函数

```c
// File: bdm_core.h 或 bdm_disk.c
static inline bool SafeMultiply(uint64_t a, uint64_t b, uint64_t *result)
{
    if (a == 0 || b == 0) {
        *result = 0;
        return true;
    }
    if (a > UINT64_MAX / b) {
        return false;  // 会溢出
    }
    *result = a * b;
    return true;
}

static inline bool SafeAdd(uint64_t a, uint64_t b, uint64_t *result)
{
    if (a > UINT64_MAX - b) {
        return false;  // 会溢出
    }
    *result = a + b;
    return true;
}
```

### 7.2 同步修复位置

同时修复：
- `BdmDiskRead` (bdm_disk.c:308)
- `BdmDiskWrite` (bdm_disk.c:337)

---

## 8. 总结

### 8.1 漏洞确认

**这是一个真实的整数溢出漏洞**，主要表现为：
1. 偏移计算表达式没有溢出保护
2. 用户配置参数 `para->offset` 完全无验证
3. 可能导致磁盘读写位置错误

### 8.2 实际风险评估

| 维度 | 评级 | 说明 |
|------|------|------|
| 漏洞真实性 | **确认** | 代码缺陷明确存在 |
| 默认配置安全性 | **安全** | 正常使用不会触发 |
| 恶意配置可利用性 | **高危** | 攻击者可恶意配置触发 |
| 修复必要性 | **必要** | 防止极端配置导致安全问题 |

### 8.3 建议

1. **立即修复**：添加 `para->offset` 验证和溢出检查
2. **同步修复**：DISK-001, DISK-002 同样需要修复
3. **回归测试**：添加边界值测试用例
4. **文档更新**：说明 `offset` 参数的有效范围

---

## 附录：关键常量

| 常量 | 值 | 含义 |
|------|-----|------|
| `BDM_MAX_CHUNK_LENGTH` | 16777216 (16MB) | 最大 chunk 长度 |
| `BDM_ALIGN_SIZE` | 2097152 (2MB) | 对齐大小 |
| `uint64_t MAX` | 18446744073709551615 | 64 位无符号整数最大值 |
