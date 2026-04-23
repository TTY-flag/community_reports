# VULN_QUEUE_002 - ioctl 参数上限检查缺陷

## 基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN_QUEUE_002 |
| **CWE** | CWE-20 (Improper Input Validation) |
| **严重级别** | High |
| **状态** | CONFIRMED |
| **置信度** | 70 |
| **文件** | src/sdk_driver/queue/host/queue_fops.c |
| **函数** | queue_para_check / queue_get_vector |
| **行号** | 263-278 (check), 179-206 (allocation) |

## 漏洞描述

函数 `queue_para_check` 对 `iovec_count` 的上限检查存在严重缺陷：

1. **无效的阈值定义**：`QUEUE_MAX_IOVEC_NUM = ((~0U) - 1) = 0xFFFFFFFE`（接近 UINT_MAX）
2. **巨额内存分配请求**：用户可通过 ioctl 请求近 68GB 的内核内存分配
3. **无合理的操作限制**：单次 ioctl 操作应限制在合理范围内（如几百个 iovec）

该检查在形式上存在，但在实质上无效，因为阈值本身远超系统实际能力。

## 数据流分析

```
用户 ioctl (queue_ioctl_enqueue)
  │
  ├─ para->iovec_count (用户可控, unsigned int)
  │
  └─ queue_para_check(para)
      │  [line 263]
      │  if (para->iovec_count > QUEUE_MAX_IOVEC_NUM) → 检查通过！
      │    因为 QUEUE_MAX_IOVEC_NUM = 0xFFFFFFFE, 允许几乎所有值
      │
  └─ queue_get_vector(para)
      │  [line 185]
      │  vector_len = sizeof(struct buff_iovec) + para->iovec_count * sizeof(struct iovec_info)
      │  若 iovec_count = 0xFFFFFFFE:
      │    vector_len = 24 + 0xFFFFFFFE * 16 ≈ 68GB
      │
      └─ queue_kvalloc(vector_len, 0)
          │  [queue_dma.c:39-47]
          │  kmalloc(size, GFP_ATOMIC) → 失败
          │  ka_vmalloc(size) → 失败
          │  返回 NULL → 安全失败
```

## 代码片段

### queue_para_check (无效检查)

```c
// queue_fops.c:255-278
static int queue_para_check(struct queue_ioctl_enqueue *para)
{
    // ...
    
    // [line 263] 检查存在但阈值无效
    if ((para->vector == NULL) || (para->iovec_count > QUEUE_MAX_IOVEC_NUM)) {
        queue_err("Vector invalid. (iovec_count=%u)\n", para->iovec_count);
        return -EINVAL;
    }
    // QUEUE_MAX_IOVEC_NUM = 0xFFFFFFFE → 允许 iovec_count 达到 UINT_MAX - 1
    // ...
    return 0;
}
```

### QUEUE_MAX_IOVEC_NUM 定义

```c
// ascend_hal_define.h:254
#define QUEUE_MAX_IOVEC_NUM ((~0U) - 1)  // = 0xFFFFFFFE ≈ 4 billion
```

### queue_get_vector (巨额分配)

```c
// queue_fops.c:179-206
STATIC struct buff_iovec *queue_get_vector(struct queue_ioctl_enqueue *para)
{
    struct buff_iovec *vector = NULL;
    u64 vector_len;
    
    // [line 185] 计算分配大小
    vector_len = (u64)sizeof(struct buff_iovec) + (u64)para->iovec_count * sizeof(struct iovec_info);
    // sizeof(struct iovec_info) = 16 (void* + u64)
    // 若 iovec_count = 0xFFFFFFFE:
    //   vector_len = 24 + 4294967294 * 16 = 68,719,476,704 bytes ≈ 68GB
    
    vector = (struct buff_iovec *)queue_kvalloc(vector_len, 0);
    // ...
}
```

### struct buff_iovec (flexible array member)

```c
// ascend_hal_define.h:255-260
struct buff_iovec {
    void *context_base;
    unsigned long long context_len;
    unsigned int count;
    struct iovec_info ptr[];  // flexible array
};

struct iovec_info {
    void *iovec_base;        // 8 bytes
    unsigned long long len;  // 8 bytes → 总共 16 bytes
};
```

## 安全影响

### 直接影响

1. **资源耗尽攻击**：
   - 用户可通过 ioctl 请求巨额内核内存分配
   - 大量失败分配请求仍消耗 CPU 时间和内核资源
   - 可导致系统响应延迟或拒绝服务

2. **代码质量问题**：
   - 检查存在但不生效，违反"合理上限"原则
   - 阈值定义与实际系统能力完全脱节

### 实际攻击可行性

| 因素 | 分析 |
|------|------|
| 分配失败处理 | ✅ 正确：返回 NULL 并终止操作 |
| 用户可控 | ✅ 完全可控：`iovec_count` 来自 ioctl 参数 |
| 实际内存分配 | ❌ 系统无法分配 68GB，请求会失败 |
| DoS 影响 | ⚠️ 大量失败请求仍消耗资源 |

### 与类似系统对比

| 系统/标准 | 典型 iovec 限制 |
|-----------|----------------|
| Linux内核 (sys_iovec) | UIO_MAXIOV = 1024 |
| POSIX 标准 | IOV_MAX ≥ 16 |
| 本代码 | 0xFFFFFFFE ≈ 4 billion |

差距约 **4 million倍**。

## 置信度评分

| 维度 | 评分 | 说明 |
|------|------|------|
| Base | 30 | 默认基础分 |
| Reachability | +30 | 直接外部输入（ioctl 用户可控） |
| Controllability | +25 | 完全可控（用户控制 iovec_count） |
| Mitigations | -15 | 有边界检查但无效 |
| Context | 0 | 外部 API |
| Cross-file | 0 | 调用链完整 |
| **Total** | **70** | LIKELY → CONFIRMED |

**注**：虽然边界检查存在，但因阈值本身无效，评分不减为 FALSE_POSITIVE。这是 CWE-20 的典型模式：检查存在但实质无效。

## 修复建议

### 竭期修复（推荐）

修改 `ascend_hal_define.h` 中的阈值定义：

```c
// 修改前
#define QUEUE_MAX_IOVEC_NUM ((~0U) - 1)

// 修改后 - 参考 Linux 内核 UIO_MAXIOV
#define QUEUE_MAX_IOVEC_NUM 1024  // 或根据实际硬件能力定义
```

### 增强验证

在 `queue_para_check` 中添加额外合理性检查：

```c
static int queue_para_check(struct queue_ioctl_enqueue *para)
{
    // 新增：单次操作内存总量限制
    u64 total_size_estimate = (u64)para->iovec_count * sizeof(struct iovec_info);
    if (total_size_estimate > 64 * 1024) {  // 限制单次分配 ≤ 64KB
        queue_err("iovec_count too large. (count=%u, size=%llu)\n", 
                  para->iovec_count, total_size_estimate);
        return -EINVAL;
    }
    
    // 原有检查...
    if ((para->vector == NULL) || (para->iovec_count > QUEUE_MAX_IOVEC_NUM)) {
        return -EINVAL;
    }
    // ...
}
```

### 配合修改

同时更新 `queue_client_comm.c:129` 中的检查保持一致。

## 相关代码位置

| 文件 | 行号 | 用途 |
|------|------|------|
| `ascend_hal_define.h` | 254 | 阈值定义 |
| `queue_fops.c` | 263 | 参数检查 |
| `queue_fops.c` | 185 | 内存分配计算 |
| `queue_client_comm.c` | 129 | 同样的检查 |
| `queue_client.c` | 985 | 向用户返回该值 |
| `que_clt_ub.c` | 643 | 向用户返回该值 |

## 参考

- CWE-20: Improper Input Validation
- Linux kernel UIO_MAXIOV = 1024 (include/linux/uio.h)
- POSIX IOV_MAX (sysconf(_SC_IOV_MAX) typically ≥ 16)
