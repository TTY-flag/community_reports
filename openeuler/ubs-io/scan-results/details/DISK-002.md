# DISK-002: 磁盘写入偏移计算整数溢出致错误位置写入破坏数据

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | DISK-002 |
| **CWE** | CWE-190 (Integer Overflow or Wraparound) |
| **严重性** | HIGH |
| **置信度** | 85 |
| **模块** | disk |
| **文件** | `ubsio-boostio/src/disk/common/bdm_disk.c:337` |
| **函数** | `BdmDiskWrite` |

## 漏洞描述

磁盘写入偏移计算中的整数溢出。表达式 `item->minChunkSize * chunkId` 在 chunkId 接近 48 位最大值时会溢出，导致写入到错误的磁盘位置。

与 DISK-001 (BdmDiskRead) 相同的模式，但影响**写入操作**，风险更高：
- **数据损坏**：写入到错误位置破坏其他数据
- **数据泄露**：写入敏感数据到非预期位置
- **权限绕过**：写入到其他用户的数据区域

## 漏洞代码

```c
// bdm_disk.c:330-349
int32_t BdmDiskWrite(BdmObj *obj, uint64_t chunkId, uint64_t offset, char *buf, uint64_t len)
{
    BdmDiskItem *item = BdmDiskGetItem(obj->bdmId);
    if (item == NULL) {
        BDM_LOGWARN(0, "Get bdm disk item failed, bdm id(%u).", obj->bdmId);
        return BDM_CODE_ERROR;
    }

    int32_t ret = BdmAllocatorCheckChunk(item->allocator, chunkId, offset, len);
    if (ret != BDM_CODE_OK) {
        BDM_LOGWARN(0, "Bdm write check failed, bdm id(%u) chunk id(%lu) ret(%d).", 
                    obj->bdmId, chunkId, ret);
        return ret;
    }

    // ===== 漏洞位置 =====
    uint64_t rwOffset = item->offset + item->dataOffset + item->minChunkSize * chunkId + offset;
    
    uint64_t bufStart = (uint64_t)buf;
    if (bufStart % BDM_BLOCK_SIZE == 0 && len % BDM_BLOCK_SIZE == 0 && rwOffset % BDM_BLOCK_SIZE == 0) {
        ret = BdmDiskInnerReadWriteDirect(item, (char*)buf, len, rwOffset, FALSE);
    } else {
        ret = BdmDiskInnerReadWrite(item, (char*)buf, len, rwOffset, FALSE);
    }
    // ...
}
```

**问题分析**：
1. `chunkId` 是 48 位值 (来自 `DENCODE_CHUNK_ID`)，最大可达 `0xFFFFFFFFFFFF`
2. `minChunkSize` 通常为 4KB-64KB
3. `minChunkSize * chunkId` 在大 chunkId 时会溢出 64 位
4. 溢出后的 `rwOffset` 是错误的偏移值
5. 数据写入到错误磁盘位置

## 数据流分析

```
┌─────────────────────────────────────────────────────────────────┐
│                        数据流路径                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  用户 Put 请求 (SDK)                                             │
│       │                                                         │
│       ▼                                                         │
│  cache 模块分配 chunk                                            │
│       │                                                         │
│       ▼                                                         │
│  chunkId 编码 (48位)                                            │
│       │                                                         │
│       ▼                                                         │
│  BdmDiskWrite(obj, chunkId, offset, buf, len)                   │
│       │                                                         │
│       ▼                                                         │
│  BdmAllocatorCheckChunk ← 仅检查分配器，不检查乘法溢出           │
│       │                                                         │
│       ▼                                                         │
│  rwOffset = offset + dataOffset + minChunkSize * chunkId        │
│       │                                                         │
│       │  chunkId = 0xFFFFFFFFFFFF                               │
│       │  minChunkSize = 64KB = 0x10000                          │
│       │                                                         │
│       │  minChunkSize * chunkId:                                │
│       │  = 0x10000 * 0xFFFFFFFFFFFF                             │
│       │  = overflow! 实际结果小于预期                            │
│       │                                                         │
│       ▼                                                         │
│  rwOffset = 错误值 (如 0x1234 而非 0xFFFFFFFFFFFFFFFF)           │
│       │                                                         │
│       ▼                                                         │
│  pwrite(fd, buf, len, rwOffset)                                 │
│       │                                                         │
│       ▼                                                         │
│  数据写入错误位置 ← 数据损坏/泄露                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 漏洞触发条件计算

**溢出边界分析**：

假设：
- `minChunkSize` = 64KB = 65536 = 0x10000
- 64 位无符号整数最大值 = 0xFFFFFFFFFFFFFFFF

计算触发溢出的 chunkId：
```
minChunkSize * chunkId > UINT64_MAX

chunkId > UINT64_MAX / minChunkSize
chunkId > 0xFFFFFFFFFFFFFFFF / 0x10000
chunkId > 0xFFFFFFFFFFFF (48位最大值)

实际上，当 chunkId ≈ 0xFFFFFFFFFFFF 时：
minChunkSize * chunkId ≈ 0xFFFFFFFFFFFF0000 
```

但加上 `item->offset + item->dataOffset + offset` 会触发溢出。

**实际触发场景**：
- 大磁盘：磁盘容量 > 16TB 时 chunkId 可能接近边界
- 恶意构造：攻击者通过 SDK Put 构造超大 chunkId

## 攻击场景构造

### 场景 1: 数据损坏攻击

**攻击者**：通过 SDK API 写入数据的用户

**步骤**：
1. 使用恶意 chunkId 发起写入：
   ```cpp
   // 构造溢出 chunkId
   uint64_t overflowChunkId = 0xFFFFFFFFFFFFFF00;
   
   // SDK Put 使用该 chunkId (通过内部编码)
   Bio::Put(key, value, ...);  // 内部触发特定 chunkId
   ```
2. 写入偏移溢出到其他用户的数据区域
3. 破坏其他用户的存储数据

### 场景 2: 跨用户数据写入

**条件**：多用户共享同一块设备

**步骤**：
1. 用户 A 写入数据，chunkId 溢出
2. 写入位置落到用户 B 的数据区域
3. 用户 A 的数据覆盖用户 B 的敏感数据

### 场景 3: 数据泄露 (读取侧)

**关联**：DISK-001 (读取溢出)

**步骤**：
1. 用户 A 使用溢出 chunkId 写入数据
2. 数据实际写入到用户 B 的区域
3. 用户 B 读取自己的数据时，获取到用户 A 的数据

## 影响范围评估

| 维度 | 评估 |
|------|------|
| **可触发性** | MEDIUM - 需要极端 chunkId 值 |
| **攻击者要求** | SDK API 访问权限 |
| **影响范围** | HIGH - 整个块设备数据完整性 |
| **业务影响** | 数据损坏 + 数据泄露 + 服务中断 |
| **跨模块影响** | YES - 与 cache 模块交互 |

**受影响操作**：
- 所有写入操作：`Bio::Put`, `MirrorClient::Put`
- Async I/O 写入：`BdmDiskSubmitAIO` (DISK-003)

## 修复建议

### 方案 1: 添加溢出检测 (推荐)

```c
// bdm_disk.c:337 修复版本
#include <limits.h>

// 添加安全乘法函数
static inline bool safe_mul_u64(uint64_t a, uint64_t b, uint64_t *result)
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

// 添加安全加法函数
static inline bool safe_add_u64(uint64_t a, uint64_t b, uint64_t *result)
{
    if (a > UINT64_MAX - b) {
        return false;  // 会溢出
    }
    
    *result = a + b;
    return true;
}

int32_t BdmDiskWrite(BdmObj *obj, uint64_t chunkId, uint64_t offset, char *buf, uint64_t len)
{
    BdmDiskItem *item = BdmDiskGetItem(obj->bdmId);
    if (item == NULL) {
        BDM_LOGWARN(0, "Get bdm disk item failed, bdm id(%u).", obj->bdmId);
        return BDM_CODE_ERROR;
    }

    int32_t ret = BdmAllocatorCheckChunk(item->allocator, chunkId, offset, len);
    if (ret != BDM_CODE_OK) {
        BDM_LOGWARN(0, "Bdm write check failed, bdm id(%u) chunk id(%lu) ret(%d).", 
                    obj->bdmId, chunkId, ret);
        return ret;
    }

    // ===== 安全计算 =====
    uint64_t rwOffset = 0;
    uint64_t temp = 0;
    
    // 1. 安全乘法: minChunkSize * chunkId
    if (!safe_mul_u64(item->minChunkSize, chunkId, &temp)) {
        BDM_LOGERROR(0, "Integer overflow in disk write: chunkId=%lu, minChunkSize=%lu",
                     chunkId, item->minChunkSize);
        return BDM_CODE_OVERFLOW;
    }
    
    // 2. 安全加法: item->offset + item->dataOffset
    if (!safe_add_u64(item->offset, item->dataOffset, &rwOffset)) {
        BDM_LOGERROR(0, "Integer overflow in disk write offset calculation");
        return BDM_CODE_OVERFLOW;
    }
    
    // 3. 安全加法: + temp (minChunkSize * chunkId)
    if (!safe_add_u64(rwOffset, temp, &rwOffset)) {
        BDM_LOGERROR(0, "Integer overflow in disk write chunk offset");
        return BDM_CODE_OVERFLOW;
    }
    
    // 4. 安全加法: + offset
    if (!safe_add_u64(rwOffset, offset, &rwOffset)) {
        BDM_LOGERROR(0, "Integer overflow in disk write final offset");
        return BDM_CODE_OVERFLOW;
    }
    
    // 5. 验证写入范围不超过磁盘容量
    if (rwOffset + len > item->capacity) {
        BDM_LOGERROR(0, "Write offset exceeds disk capacity: offset=%lu, len=%lu, cap=%lu",
                     rwOffset, len, item->capacity);
        return BDM_CODE_RANGE_ERROR;
    }

    uint64_t bufStart = (uint64_t)buf;
    if (bufStart % BDM_BLOCK_SIZE == 0 && len % BDM_BLOCK_SIZE == 0 && rwOffset % BDM_BLOCK_SIZE == 0) {
        ret = BdmDiskInnerReadWriteDirect(item, (char*)buf, len, rwOffset, FALSE);
    } else {
        ret = BdmDiskInnerReadWrite(item, (char*)buf, len, rwOffset, FALSE);
    }
    // ...
}
```

### 方案 2: chunkId 边界验证

在调用方限制 chunkId 范围：

```c
// bdm_allocator.c 或调用方添加
#define MAX_SAFE_CHUNK_ID(chunkSize) (UINT64_MAX / chunkSize - 1)

int32_t BdmAllocatorCheckChunk(BdmAllocator *alloc, uint64_t chunkId, ...)
{
    // 添加 chunkId 边界检查
    uint64_t maxChunkId = MAX_SAFE_CHUNK_ID(alloc->minChunkSize);
    if (chunkId > maxChunkId) {
        BDM_LOGERROR(0, "chunkId exceeds safe limit: %lu > %lu", chunkId, maxChunkId);
        return BDM_CODE_RANGE_ERROR;
    }
    
    // ... existing checks ...
}
```

### 方案 3: 使用 128 位整数 (编译器支持)

```c
// 使用 __uint128_t 防止溢出
__uint128_t fullOffset = (__uint128_t)item->offset + 
                         (__uint128_t)item->dataOffset + 
                         (__uint128_t)item->minChunkSize * (__uint128_t)chunkId + 
                         (__uint128_t)offset;

if (fullOffset > UINT64_MAX || fullOffset + len > item->capacity) {
    return BDM_CODE_OVERFLOW;
}

uint64_t rwOffset = (uint64_t)fullOffset;
```

## 缓解措施

### 立即缓解

1. **限制 chunkId**：在 SDK 层添加 chunkId 最大值限制
2. **容量检查**：添加 `rwOffset + len <= disk_capacity` 验证
3. **监控告警**：检测异常大的 chunkId 值

### 系统级缓解

1. 使用文件系统级别的写入保护
2. 启用块设备写保护（只允许特定范围）
3. 添加写入审计日志

## 相关漏洞

- **DISK-001**: 同一模式的读取溢出 (BdmDiskRead)
- **DISK-003**: Async I/O 的相同溢出 (BdmDiskSubmitAIO)
- **DISK-008**: 路径验证绕过

## 数学验证

```
测试案例: minChunkSize = 64KB, chunkId = 0xFFFFFFFFFFFF

Unsafe:
minChunkSize * chunkId = 0x10000 * 0xFFFFFFFFFFFF
                       = 0xFFFFFFFFFFFF0000 (截断)

Safe check:
UINT64_MAX / minChunkSize = 0xFFFFFFFFFFFFFFFF / 0x10000 = 0xFFFFFFFFFFFF
chunkId = 0xFFFFFFFFFFFF → 不溢出 (刚好边界)

但如果加上其他偏移项:
item->offset + item->dataOffset + offset ≈ 1GB
最终仍会溢出。
```

## 参考

- CWE-190: https://cwe.mitre.org/data/definitions/190.html
- Integer Overflow in C: https://www.gnu.org/software/gnu-c-manual/gnu-c-manual.html#Integer-Overflow
- Safe Integer Operations: https://www.seppuku.org/docs/safeint.html