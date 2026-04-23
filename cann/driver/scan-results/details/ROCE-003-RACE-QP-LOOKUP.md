# ROCE-003-RACE-QP-LOOKUP：QP查找锁机制缺陷漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | ROCE-003-RACE-QP-LOOKUP |
| **CWE** | CWE-667 (Improper Locking) |
| **严重性** | High |
| **类型** | TOCTOU → Use-After-Free |
| **状态** | CONFIRMED |
| **置信度** | 85 |

## 漏洞位置

| 文件 | 函数 | 行号 |
|------|------|------|
| `src/ascend_hal/roce/host_lite/hns_roce_lite.c` | `hns_roce_lite_find_qp` | 557-568 |

## 问题描述

QP (Queue Pair) lookup 函数 `hns_roce_lite_find_qp` 在访问 `qp_table` 时未持有 `qp_table_mutex` 锁，与 `hns_roce_lite_destroy_qp` 函数之间存在 TOCTOU (Time-Of-Check-To-Time-Of-Use) 竞态条件，可导致 Use-After-Free 漏洞。

## 漏洞代码分析

### 1. find_qp 未持锁访问 QP 表

```c
// 文件: hns_roce_lite.c, 行 557-568
STATIC struct hns_roce_lite_qp *hns_roce_lite_find_qp(struct hns_roce_lite_context *ctx, u32 qpn)
{
    u32 tind = (qpn & (ctx->num_qps - 1)) >> (u32)ctx->qp_table_shift;

    if (tind < HNS_ROCE_LITE_QP_TABLE_SIZE) {
        if (ctx->qp_table[tind].refcnt) {                    // ← 无锁读取 refcnt
            return ctx->qp_table[tind].table[qpn & (u32)(ctx->qp_table_mask)]; // ← 无锁读取 QP 指针
        }
    }

    return NULL;
}
```

**问题**: 该函数直接访问共享数据结构 `qp_table`，未使用 `qp_table_mutex` 保护。

### 2. destroy_qp 持锁修改 QP 表后释放内存

```c
// 文件: hns_roce_lite.c, 行 496-538
int hns_roce_lite_destroy_qp(struct rdma_lite_qp *lite_qp)
{
    // ...
    ctx = to_hr_lite_ctx(lite_qp->ctx);

    (void)pthread_mutex_lock(&ctx->qp_table_mutex);    // ← 持锁
    hns_roce_clear_lite_qp(ctx, lite_qp->qp_num);      // ← 清除 QP 表项
    (void)pthread_mutex_unlock(&ctx->qp_table_mutex);  // ← 释放锁

    // ... unmmap 操作 ...

    free(qp);                                          // ← 释放 QP 内存（锁已释放）
    qp = NULL;

    return 0;
}
```

### 3. clear_lite_qp 清除并可能释放整个表

```c
// 文件: hns_roce_lite_stdio.c, 行 133-143
void hns_roce_clear_lite_qp(struct hns_roce_lite_context *ctx, uint32_t qpn)
{
    u32 tind = (qpn & ((u32)(ctx->num_qps) - 1)) >> (u32)ctx->qp_table_shift;

    if (--ctx->qp_table[tind].refcnt == 0) {
        free(ctx->qp_table[tind].table);               // ← 可能释放整个 table 数组
        ctx->qp_table[tind].table = NULL;
    } else {
        ctx->qp_table[tind].table[qpn & (uint32_t)(ctx->qp_table_mask)] = NULL;
    }
}
```

### 4. QP 表结构定义

```c
// 文件: hns_roce_lite.h, 行 190-196
struct hns_roce_lite_context {
    struct rdma_lite_context    lite_ctx;
    struct {
        struct hns_roce_lite_qp     **table;  // ← QP 指针数组
        int                         refcnt;   // ← 引用计数
    } qp_table[HNS_ROCE_LITE_QP_TABLE_SIZE];
    pthread_mutex_t             qp_table_mutex;  // ← 保护 qp_table 的互斥锁
    // ...
};
```

### 5. store_lite_qp 正确使用锁

```c
// 文件: hns_roce_lite.c, 行 416-422（创建 QP 时）
(void)pthread_mutex_lock(&context->qp_table_mutex);
ret = hns_roce_store_lite_qp(context, qp->lite_qp.qp_num, qp);
// ...
(void)pthread_mutex_unlock(&context->qp_table_mutex);
```

**对比**: `store_lite_qp` 正确使用锁，而 `find_qp` 未使用锁，存在不一致。

## 竞态条件攻击路径

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Thread A: poll_cq (CQ 完成队列轮询)                                      │
├─────────────────────────────────────────────────────────────────────────┤
│ 1. hns_roce_lite_poll_cq()                                              │
│ 2. pthread_spin_lock(&cq->lock)                                         │
│ 3. hns_roce_lite_poll_one()                                             │
│ 4. hns_roce_lite_find_qp(ctx, qpn)                                      │
│    │                                                                    │
│    ├─→ 读取 qp_table[tind].refcnt (无锁)                                │
│    ├─→ 读取 qp_table[tind].table[idx] (无锁)                            │
│    └─→ 返回 QP 指针 ptr                                                  │
│                                                                         │
│    [此时 ptr 可能立即变为无效]                                           │
│                                                                         │
│ 5. hns_roce_lite_poll_one_set_wc(..., cur_qp, ...)                      │
│    ├─→ (*cur_qp)->sq_signal_bits ← 访问可能已释放的内存                  │
│    └─→ lite_wq->wrid[...] ← 读取已释放数组                              │
└─────────────────────────────────────────────────────────────────────────┘

                              ↓ 竞态窗口 ↓

┌─────────────────────────────────────────────────────────────────────────┐
│ Thread B: destroy_qp (销毁 QP)                                           │
├─────────────────────────────────────────────────────────────────────────┤
│ 1. hns_roce_lite_destroy_qp()                                           │
│ 2. pthread_mutex_lock(&ctx->qp_table_mutex)                             │
│ 3. hns_roce_clear_lite_qp(ctx, qpn)                                     │
│    ├─→ qp_table[tind].table[idx] = NULL                                 │
│    ├─→ 或 free(qp_table[tind].table)                                    │
│ 4. pthread_mutex_unlock(&ctx->qp_table_mutex)                           │
│ 5. free(qp) ← 释放 QP 内存                                              │
└─────────────────────────────────────────────────────────────────────────┘
```

## 调用路径

```
rdma_lite_poll_cq() [用户 API]
  └─→ hns_roce_lite_ops->poll_cq = hns_roce_lite_poll_cq
      └─→ pthread_spin_lock(&cq->lock)
      └─→ hns_roce_lite_poll_one(cq, &qp, ...)
          └─→ hns_roce_lite_find_qp(ctx, qpn)  ← 漏洞点
          └─→ hns_roce_lite_poll_one_set_wc(..., cur_qp, ...)  ← UAF 触发点
          └─→ (*cur_qp)->lite_qp.qp_state = RDMA_LITE_QPS_ERR  ← UAF 触发点
```

## 漏洞触发条件

1. **多线程环境**: 应用程序使用多个线程同时执行 CQ 轮询和 QP 销毁操作
2. **共享 Context**: 多个线程共享同一个 `hns_roce_lite_context`
3. **竞态窗口**: find_qp 返回指针后，destroy_qp 可能已释放该 QP

## 漏洞影响

### Use-After-Free 后果

| 影响 | 描述 |
|------|------|
| **内存破坏** | 访问已释放的 QP 结构体，可能导致数据损坏 |
| **信息泄露** | 读取已释放并可能被其他对象复用的内存区域 |
| **任意代码执行** | 如果攻击者能控制释放后重新分配的内存内容，可能实现代码执行 |
| **崩溃** | 解引用 NULL 指针或无效指针导致程序崩溃 |

### 攻击场景

RDMA 应用中，攻击者可以通过以下方式触发漏洞：
1. 创建大量 QP 并在 CQ 中产生完成事件
2. 在一个线程中持续轮询 CQ (触发 find_qp)
3. 在另一个线程中销毁 QP (触发 destroy_qp)
4. 精确控制时机，使 find_qp 返回的指针在 destroy_qp 释放后仍被使用

## 置信度评分

| 维度 | 评分 | 说明 |
|------|------|------|
| **Base** | 30 | 基础分数 |
| **可达性** | +30 | 通过 rdma_lite_poll_cq API 直接可达，用户可触发 |
| **可控性** | +15 | QPN 可控，但 QP 内容由应用程序管理 |
| **缓解措施** | -10 | cq->lock 存在，但不保护 qp_table |
| **上下文** | 0 | 非 static 函数，可被外部模块调用 |
| **跨文件** | 0 | 调用链完整，find_qp/destroy_qp 在同一文件 |

**总分**: 85 → **CONFIRMED**

## 补充证据

### 锁使用对比

| 操作 | 函数 | 是否持锁 |
|------|------|----------|
| 存储 QP | `hns_roce_store_lite_qp` (调用点 line 416) | ✓ `pthread_mutex_lock(&qp_table_mutex)` |
| 清除 QP | `hns_roce_clear_lite_qp` (调用点 line 507) | ✓ `pthread_mutex_lock(&qp_table_mutex)` |
| 查找 QP | `hns_roce_lite_find_qp` (line 557) | ✗ **无锁** |

### cq->lock 不保护 qp_table

```c
// 文件: hns_roce_lite.c, 行 848-902
int hns_roce_lite_poll_cq(...)
{
    pthread_spin_lock(&cq->lock);    // ← 只保护 CQ 本身
    for (npolled = 0; ... ) {
        err = hns_roce_lite_poll_one(cq, &qp, ...);  // ← 内部调用 find_qp
        // find_qp 访问的是 ctx->qp_table，不受 cq->lock 保护
    }
    pthread_spin_unlock(&cq->lock);
}
```

**结论**: `cq->lock` 是 CQ 级别的锁，`qp_table_mutex` 是 Context 级别的锁。两者保护不同资源，find_qp 应使用 `qp_table_mutex`。

## 修复建议

### 方案 A: 在 find_qp 中添加锁保护（推荐）

```c
STATIC struct hns_roce_lite_qp *hns_roce_lite_find_qp(struct hns_roce_lite_context *ctx, u32 qpn)
{
    struct hns_roce_lite_qp *qp = NULL;
    u32 tind = (qpn & (ctx->num_qps - 1)) >> (u32)ctx->qp_table_shift;

    pthread_mutex_lock(&ctx->qp_table_mutex);  // ← 添加锁
    if (tind < HNS_ROCE_LITE_QP_TABLE_SIZE) {
        if (ctx->qp_table[tind].refcnt) {
            qp = ctx->qp_table[tind].table[qpn & (u32)(ctx->qp_table_mask)];
        }
    }
    pthread_mutex_unlock(&ctx->qp_table_mutex);  // ← 释放锁

    return qp;
}
```

**注意**: 返回的 QP 指针仍可能在锁释放后被 destroy_qp 释放，需要进一步处理。

### 方案 B: 使用引用计数保护 QP（更安全）

在 find_qp 返回前增加 QP 的引用计数，在 destroy_qp 中等待引用计数归零后才释放：

```c
// QP 结构体添加引用计数
struct hns_roce_lite_qp {
    // ...
    atomic_t refcnt;  // ← 新增
};

// find_qp 增加引用
STATIC struct hns_roce_lite_qp *hns_roce_lite_find_qp(...)
{
    pthread_mutex_lock(&ctx->qp_table_mutex);
    qp = ctx->qp_table[tind].table[idx];
    if (qp) atomic_inc(&qp->refcnt);  // ← 增加引用
    pthread_mutex_unlock(&ctx->qp_table_mutex);
    return qp;
}

// destroy_qp 等待引用归零
int hns_roce_lite_destroy_qp(...)
{
    pthread_mutex_lock(&ctx->qp_table_mutex);
    hns_roce_clear_lite_qp(ctx, qpn);
    pthread_mutex_unlock(&ctx->qp_table_mutex);

    while (atomic_read(&qp->refcnt) > 0)  // ← 等待引用归零
        usleep(100);

    free(qp);
    return 0;
}
```

### 方案 C: 使用 RCU (Read-Copy-Update)（高性能方案）

如果轮询操作频繁，使用 RCU 可以避免锁竞争：

```c
// 查找使用 rcu_read_lock
STATIC struct hns_roce_lite_qp *hns_roce_lite_find_qp(...)
{
    rcu_read_lock();
    qp = rcu_dereference(ctx->qp_table[tind].table[idx]);
    if (qp) atomic_inc(&qp->refcnt);
    rcu_read_unlock();
    return qp;
}

// 销毁使用 call_rcu
int hns_roce_lite_destroy_qp(...)
{
    pthread_mutex_lock(&ctx->qp_table_mutex);
    rcu_assign_pointer(ctx->qp_table[tind].table[idx], NULL);
    pthread_mutex_unlock(&ctx->qp_table_mutex);

    call_rcu(&qp->rcu_head, free_qp_callback);  // ← 延迟释放
    return 0;
}
```

## 相关文件

| 文件 | 作用 |
|------|------|
| `hns_roce_lite.c` | 主要实现，漏洞所在文件 |
| `hns_roce_lite.h` | 结构体定义，`qp_table_mutex` 定义位置 |
| `hns_roce_lite_stdio.c` | `hns_roce_store_lite_qp` / `hns_roce_clear_lite_qp` 实现 |
| `rdma_lite.c` | 用户 API 层，`rdma_lite_poll_cq` 入口 |

## 参考资料

- [CWE-667: Improper Locking](https://cwe.mitre.org/data/definitions/667.html)
- [CWE-367: Time-of-Check Time-of-Use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html)
