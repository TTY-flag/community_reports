# VULN_QUEUE_RESOURCE_LIMIT_002：进程级资源限制缺失漏洞

## 基本信息

| 字段 | 值 |
|------|-----|
| **漏洞ID** | VULN_QUEUE_RESOURCE_LIMIT_002 |
| **CWE** | CWE-400 (Uncontrolled Resource Consumption) |
| **严重级别** | High |
| **状态** | CONFIRMED |
| **置信度** | 85 |
| **文件** | src/sdk_driver/queue/host/queue_fops.c |
| **函数** | queue_drv_enqueue |
| **行号** | 404-486 |

## 漏洞描述

函数 `queue_drv_enqueue` 缺乏进程级资源限制，恶意进程可通过创建大量队列通道并分配大尺寸DMA缓冲区来耗尽内核内存：

1. **无队列数量限制**：进程可无限调用 `queue_drv_enqueue`，每次创建新的 `queue_chan` 结构
2. **无DMA内存限制**：用户可通过 `iovec.len` 控制每次分配的DMA缓冲区大小，无进程级累计上限
3. **资源追踪缺失**：`context_private_data` 仅用链表追踪队列通道，无计数器或内存统计

该漏洞允许恶意进程耗尽内核内存，导致系统拒绝服务。

## 数据流分析

```
用户进程 open("/dev/queue") → queue_drv_open
  │
  ├─ queue_context_init(tgid)
  │    └─ 创建 queue_context，关联到进程 tgid
  │    └─ context_private_data.node_list_head (空链表，无计数器)
  │
  └─ 循环调用 ioctl(QUEUE_ENQUEUE_CMD) → queue_fop_enqueue
      │
      ├─ uda_devid_to_phy_devid (参数转换)
      │
      └─ queue_drv_enqueue(filep, para, dev)
          │  [line 404-486]
          │
          ├─ queue_para_check(para)
          │    └─ 仅检查单次请求参数，无累计限制
          │
          ├─ queue_drv_que_chan_create(ctx_private, para, serial_num, dev)
          │    │  [line 380-402]
          │    │
          │    ├─ queue_chan_create(&attr)
          │    │    └─ queue_drv_kvmalloc(sizeof(struct queue_chan))
          │    │    └─ 返回 que_chan (新增一个队列通道)
          │    │
          │    └─ queue_chan_dma_create(que_chan, iovec_count + 1)
          │         │  [queue_channel.c:389-408]
          │         │
          │         └─ size = local_total_va_num * sizeof(struct queue_chan_dma)
          │         └─ queue_chan_alloc_node(que_chan, size)
          │              └─ queue_drv_kvmalloc_node(size, GFP_KERNEL | __GFP_ACCOUNT)
          │
          ├─ queue_get_vector(para)
          │    └─ queue_kvalloc(vector_len)
          │    └─ copy_from_user (用户数据)
          │
          ├─ queue_drv_vector_add(que_chan, para, vector)
          │    │  [line 349-378]
          │    │
          │    └─ queue_chan_iovec_add(que_chan, &iovec)
          │         │  [queue_channel.c:255-278]
          │         │
          │         ├─ _queue_chan_dma_iovec_add(chan_dma, va, len, dma_flag)
          │         │    └─ 用户控制的 len 可任意大
          │         │
          │         └─ queue_make_dma_list(dev, hccs_vm_flag, devid, &dma_list)
          │              │  [queue_dma.c:362-410]
          │              │
          │              ├─ queue_alloc_dma_blks(dma_list)
          │              │    └─ queue_kvalloc(page_num * sizeof(ka_page_t*))
          │              │    └─ queue_kvalloc(page_num * sizeof(queue_dma_block))
          │              │
          │              ├─ queue_get_user_pages(dma_list)
          │              │    └─ ka_mm_get_user_pages_fast(va, page_num, FOLL_WRITE, pages)
          │              │    └─ pin 用户内存页（内核内存占用！）
          │              │
          │              └─ queue_map_dma_blks(dev, dma_list)
          │                   └─ hal_kernel_devdrv_dma_map_page (DMA映射)
          │
          └─ queue_add_que_chan(ctx_private, que_chan)
               │  [line 233-238, queue_fops.c]
               │
               └─ ka_list_add_tail(&que_chan->list, &ctx_private->node_list_head)
               │    └─ 仅添加到链表，无计数器检查！
               │    └─ 无检查：node_list_head 中有多少个节点？
               │
          └─ queue_chan_send(que_chan, timeout)
          └─ queue_chan_wait(que_chan, timeout)
          └─ queue_del_que_chan(ctx_private, que_chan)
          └─ queue_chan_destroy(que_chan)
               └─ 临时队列，操作完成后销毁
               └─ 但并发调用可同时存在多个队列通道
```

## 代码片段

### context_private_data - 无资源限制字段

```c
// queue_ctx_private.h:19-23
struct context_private_data {
    ka_list_head_t node_list_head;      // 链表头，无计数器！
    ka_task_spinlock_t lock;            // 自旋锁
    int hdc_session[MAX_DEVICE];        // HDC会话
};
// 缺失：无 queue_count、无 total_dma_size、无 total_pages
```

### queue_drv_enqueue - 无累计限制检查

```c
// queue_fops.c:404-486
STATIC long queue_drv_enqueue(ka_file_t *filep, struct queue_ioctl_enqueue *para, ka_device_t *dev)
{
    struct queue_context *context = filep->private_data;
    struct context_private_data *ctx_private = NULL;
    struct queue_chan *que_chan = NULL;
    // ...
    
    ctx_private = (struct context_private_data *)context->private_data;
    
    // [line 423-426] 参数检查 - 仅单次请求
    ret = queue_para_check(para);
    if (ret != 0) {
        return ret;
    }
    
    // [line 430] 直接创建队列通道，无累计检查
    que_chan = queue_drv_que_chan_create(ctx_private, para, serial_num, dev);
    if (que_chan == NULL) {
        queue_err("Que chan inst create fail.\n");
        return -ENOMEM;  // 仅当单次分配失败才返回错误
    }
    
    // [line 436-448] 获取并添加用户向量
    vector = queue_get_vector(para);
    // ...
    ret = queue_drv_vector_add(que_chan, para, vector);
    // ...
    
    // [line 456] 添加到进程链表 - 无计数检查！
    queue_add_que_chan(ctx_private, que_chan);
    
    // [line 457-468] 发送并等待
    ret = queue_chan_send(que_chan, para->time_out);
    // ...
    ret = queue_chan_wait(que_chan, QUEUE_HOST_WAIT_MAX_TIME);
    
    // [line 477-480] 清理
    queue_del_que_chan(ctx_private, que_chan);
    queue_put_vector(vector);
    queue_chan_destroy(que_chan);
    
    return ret;
}
```

### queue_para_check - 仅检查单次请求

```c
// queue_fops.c:255-278
static int queue_para_check(struct queue_ioctl_enqueue *para)
{
    // 仅检查 msg_len、vector、iovec_count、type、qid
    // 无累计资源检查：
    //   - 该进程已创建多少队列？
    //   - 该进程已分配多少DMA内存？
    //   - 该进程已pin多少用户页？
    
    if (para->qid >= MAX_SURPORT_QUEUE_NUM) {  // 仅检查qid索引有效性
        queue_err("Invalid qid. (qid=%u)\n", para->qid);
        return -EINVAL;
    }
    return 0;
}
```

### queue_add_que_chan - 仅链表添加，无计数

```c
// queue_fops.c:233-238
static inline void queue_add_que_chan(struct context_private_data *ctx_private, 
                                       struct queue_chan *que_chan)
{
    ka_task_spin_lock_bh(&ctx_private->lock);
    ka_list_add_tail(&que_chan->list, &ctx_private->node_list_head);
    // 缺失：
    //   - ctx_private->queue_count++;
    //   - if (ctx_private->queue_count > MAX_QUEUES_PER_PROCESS) return -ENOMEM;
    ka_task_spin_unlock_bh(&ctx_private->lock);
}
```

### queue_chan_dma_create - 内存分配无上限

```c
// queue_channel.c:389-408
int queue_chan_dma_create(struct queue_chan *que_chan, u32 local_total_va_num)
{
    size_t size = (size_t)local_total_va_num * sizeof(struct queue_chan_dma);
    struct queue_chan_dma *chan_dma = NULL;
    
    // 仅检查溢出，无累计限制
    if (ka_unlikely((local_total_va_num == 0) || (size < (size_t)local_total_va_num))) {
        return -EINVAL;
    }
    
    chan_dma = queue_chan_alloc_node(que_chan, size);
    // 分配失败才返回错误，无进程级限制
    if (ka_unlikely(chan_dma == NULL)) {
        return -ENOMEM;
    }
    // ...
}
```

### queue_make_dma_list - 用户页pin无限制

```c
// queue_dma.c:362-410
int queue_make_dma_list(ka_device_t *dev, bool hccs_vm_flag, u32 dev_id, 
                        struct queue_dma_list *dma_list)
{
    // ...
    ret = queue_alloc_dma_blks(dma_list, dma_sva_enable);
    // page_num = queue_get_page_num(va, len)
    // 用户控制的 len → 可控制 pin 的页数
    
    ret = queue_fill_dma_blks(dma_list, dma_sva_enable);
    // queue_get_user_pages(dma_list)
    //   → queue_get_user_pages_fast(va, page_num, FOLL_WRITE, pages)
    //   → 每页消耗内核内存，无进程累计限制
    // ...
}
```

### queue_get_user_pages_fast - Pin大量用户页

```c
// queue_dma.c:202-228
STATIC int queue_get_user_pages_fast(u64 va, u64 page_num, ka_page_t **pages)
{
    u64 got_num, remained_num, tmp_va;
    int expected_num, tmp_num;
    
    for (got_num = 0; got_num < page_num;) {
        tmp_va = va + got_num * KA_MM_PAGE_SIZE;
        remained_num = page_num - got_num;
        expected_num = (int)((remained_num > QUEUE_GET_2M_PAGE_NUM) ? 
                             QUEUE_GET_2M_PAGE_NUM : remained_num);
        tmp_num = ka_mm_get_user_pages_fast(tmp_va, expected_num, KA_FOLL_WRITE, 
                                            &pages[got_num]);
        // 每次最多获取 512 页 (2MB)
        // 循环调用可pin任意数量的页
        // 无进程级累计检查！
        // ...
    }
    return 0;
}
```

## 攻击场景分析

### 攻击向量

```
攻击者进程:
  │
  ├─ 1. open("/dev/queue") → 获取 queue_context
  │
  ├─ 2. ioctl(QUEUE_HOST_COMMON_OP_CMD, QUEUE_INIT) → 建立 HDC 连接
  │
  └─ 3. 并发/循环调用 ioctl(QUEUE_ENQUEUE_CMD)
      │    参数设置：
      │    - para->iovec_count = QUEUE_MAX_IOVEC_NUM (≈ 4 billion，实际合理值)
      │    - para->vector->ptr[i].len = 大值 (如 1GB)
      │    - 不同 qid 值
      │
      └─ 每次调用分配：
          ├─ struct queue_chan (~1KB)
          ├─ struct queue_chan_dma 数组 (iovec_count * sizeof)
          ├─ struct buff_iovec + iovec_info 数组
          ├─ DMA block 结构数组 (page_num * sizeof)
          ├─ 用户页 pin (page_num 个 ka_page_t*)
          └─ DMA mapping 资源
      │
      └─ 累计效果：
          ├─ 若并发 100 个调用，每个 len = 1GB
          │    → 100GB 用户页被 pin
          │    → 大量内核内存用于元数据
          │    → DMA mapping 表耗尽
          │
          └─ 系统响应：
              ├─ 内存不足 → OOM killer
              ├─ 进程可能被杀死，但已造成系统干扰
              ├─ 其他进程无法正常分配内存
              └─ 服务拒绝状态
```

### 攻击代码示例

```c
// 概念性攻击代码（PoC）
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define QUEUE_DEVICE "/dev/queue"
#define QUEUE_ENQUEUE_CMD 0xXXX
#define MAX_ITERATIONS 4096
#define LARGE_IOVEC_LEN (1UL << 30)  // 1GB per iovec

void attack_resource_exhaustion() {
    int fd = open(QUEUE_DEVICE, O_RDWR);
    
    // 初始化 HDC 连接
    ioctl_init(fd);
    
    // 并发创建大量队列（使用多线程）
    pthread_t threads[100];
    for (int i = 0; i < 100; i++) {
        pthread_create(&threads[i], NULL, enqueue_thread, fd);
    }
    
    // 每个线程循环调用 enqueue
    // 每次传入大 len 的 iovec
    // 由于无进程级限制，可持续消耗内核内存
}

void* enqueue_thread(void* arg) {
    int fd = (int)arg;
    struct queue_ioctl_enqueue para;
    
    // 设置大量 iovec，每个 len 很大
    para.iovec_count = 100;  // 合理值，但每个 len = 1GB
    for (int i = 0; i < MAX_ITERATIONS; i++) {
        para.qid = i % 4096;
        // 每个 iovec.len = 1GB → 需要 pin 大量页
        ioctl(fd, QUEUE_ENQUEUE_CMD, &para);
        // 操作完成后队列销毁，但并发时可积累
    }
    return NULL;
}
```

### 实际攻击可行性评估

| 因素 | 分析 |
|------|------|
| 用户可控 | ✅ 完全可控：`iovec_count`、`iovec.len` 来自用户 |
| 并发能力 | ✅ 可多线程并发调用，同时存在多个队列通道 |
| 内存消耗 | ✅ 大量 pin 用户页，内核元数据结构 |
| 系统响应 | ⚠️ 最终会 OOM，但已造成 DoS |
| 防护缺失 | ✅ 无 RLIMIT 检查，无进程级计数器 |

## 安全影响

### 直接影响

1. **内核内存耗尽**：
   - 用户可通过大 `iovec.len` pin 大量用户页
   - 内核需维护 DMA block 结构、queue_chan 结构等元数据
   - 每次操作可能消耗 MB 级内核内存

2. **并发放大效应**：
   - 多线程并发调用可同时存在大量队列通道
   - `queue_chan_wait` 等待期间，队列通道持续占用资源
   - 资源积累直到操作完成才释放

3. **系统拒绝服务**：
   - 内核内存耗尽触发 OOM killer
   - 可能杀死关键进程（如 SSH daemon）
   - 系统响应延迟或崩溃

### 量化估算

| 资源类型 | 单次消耗 | 100并发 | 4096队列 |
|----------|----------|---------|----------|
| queue_chan结构 | ~1KB | ~100KB | ~4MB |
| queue_chan_dma数组 | 100*~200B | ~20KB | ~800KB |
| DMA block结构 | page_num*~32B | page_num*~3.2KB | page_num*~128KB |
| 用户页pin | len/4K页 | 100*len/4K | 理论上限巨大 |

若每个 iovec.len = 1GB：
- 单次 pin: 262,144 页 (1GB/4KB)
- 100并发: 26M 页 = 100GB
- 内核无法承受此负载

## 与 VULN_QUEUE_002 的区别

| 漏洞 | 类型 | 检查缺陷 | 攻击向量 |
|------|------|----------|----------|
| VULN_QUEUE_002 | CWE-20 | 阈值定义无效（~0U-1） | 单次请求巨额内存 |
| VULN_QUEUE_RESOURCE_LIMIT_002 | CWE-400 | 无累计资源限制 | 多次/并发请求积累 |

两个漏洞互补：VULN_QUEUE_002 使单次请求可申请巨额内存；本漏洞使多次请求可累计消耗资源。

## 置信度评分

| 维度 | 评分 | 说明 |
|------|------|------|
| Base | 30 | 默认基础分 |
| Reachability | +30 | 直接外部输入（ioctl） |
| Controllability | +25 | 完全可控（iovec参数） |
| Mitigations | 0 | 无进程级限制检查 |
| Context | 0 | 外部 API |
| Cross-file | +10 | 涉及 queue_fops.c, queue_channel.c, queue_dma.c |
| Exploitability | +10 | 易于利用（多线程并发） |
| **Total** | **85** | CONFIRMED |

**注**：置信度较高，因为代码明确缺失资源追踪字段和限制检查，且攻击向量直接可行。

## 修复建议

### 长期修复（推荐）

修改 `queue_ctx_private.h`，增加资源追踪字段：

```c
// 修改前
struct context_private_data {
    ka_list_head_t node_list_head;
    ka_task_spinlock_t lock;
    int hdc_session[MAX_DEVICE];
};

// 修改后
struct context_private_data {
    ka_list_head_t node_list_head;
    ka_task_spinlock_t lock;
    int hdc_session[MAX_DEVICE];
    
    // 新增：进程级资源追踪
    u32 active_queue_count;           // 当前活跃队列数
    u64 total_dma_pages;              // 累计 pin 的页数
    u64 total_dma_size;               // 累计 DMA 内存大小
};
```

### 增强限制检查

修改 `queue_drv_enqueue`，增加累计限制检查：

```c
// queue_fops.c:404-486 (建议修改)
STATIC long queue_drv_enqueue(ka_file_t *filep, struct queue_ioctl_enqueue *para, ka_device_t *dev)
{
    struct queue_context *context = filep->private_data;
    struct context_private_data *ctx_private = NULL;
    // ...
    
    ctx_private = (struct context_private_data *)context->private_data;
    
    // 新增：进程级限制检查
    ka_task_spin_lock_bh(&ctx_private->lock);
    
    // 队列数量限制
    if (ctx_private->active_queue_count >= MAX_QUEUES_PER_PROCESS) {
        ka_task_spin_unlock_bh(&ctx_private->lock);
        queue_err("Process queue limit exceeded. (count=%u, max=%u)\n",
                  ctx_private->active_queue_count, MAX_QUEUES_PER_PROCESS);
        return -ENOMEM;
    }
    
    // DMA 内存限制
    u64 request_size = queue_estimate_dma_size(para);
    if (ctx_private->total_dma_size + request_size > MAX_DMA_SIZE_PER_PROCESS) {
        ka_task_spin_unlock_bh(&ctx_private->lock);
        queue_err("Process DMA limit exceeded. (current=%llu, request=%llu, max=%llu)\n",
                  ctx_private->total_dma_size, request_size, MAX_DMA_SIZE_PER_PROCESS);
        return -ENOMEM;
    }
    
    // 预占用计数
    ctx_private->active_queue_count++;
    ctx_private->total_dma_size += request_size;
    ka_task_spin_unlock_bh(&ctx_private->lock);
    
    // ...原有逻辑...
    
    // 操作完成后减少计数
    queue_del_que_chan(ctx_private, que_chan);
    ka_task_spin_lock_bh(&ctx_private->lock);
    ctx_private->active_queue_count--;
    ctx_private->total_dma_size -= actual_size;  // 使用实际大小
    ka_task_spin_unlock_bh(&ctx_private->lock);
    
    queue_chan_destroy(que_chan);
    return ret;
}
```

### 定义合理限制值

```c
// queue_ctx_private.h 或 queue_module.h
#define MAX_QUEUES_PER_PROCESS    256    // 每进程最大并发队列数
#define MAX_DMA_SIZE_PER_PROCESS  (1ULL << 30)  // 每进程最大DMA内存：1GB
#define MAX_DMA_PAGES_PER_PROCESS 262144  // 每进程最大pin页数：256K页 = 1GB
```

### 参考 RLIMIT 实现

参考 Linux 内核 RLIMIT_MEMLOCK 实现，考虑使用内核 memfd 或 accounted memory：

```c
// 参考 kernel/mm/mlock.c
// 使用 mm->locked_vm 计数器追踪 locked pages

// 在 queue_get_user_pages_fast 中检查：
if (current->mm->locked_vm + page_num > current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur) {
    return -ENOMEM;
}
```

## 相关代码位置

| 文件 | 行号 | 用途 | 问题 |
|------|------|------|------|
| `queue_ctx_private.h` | 19-23 | 进程私有数据定义 | 缺失资源追踪字段 |
| `queue_fops.c` | 404-486 | 队列入队入口 | 无累计限制检查 |
| `queue_fops.c` | 255-278 | 参数检查 | 仅检查单次请求 |
| `queue_fops.c` | 233-238 | 添加队列到链表 | 无计数检查 |
| `queue_channel.c` | 352-380 | 队列通道创建 | 无进程级限制 |
| `queue_channel.c` | 389-408 | DMA创建 | 仅失败才返回错误 |
| `queue_dma.c` | 362-410 | DMA列表创建 | 无累计限制 |
| `queue_dma.c` | 202-228 | 用户页获取 | 无进程级限制 |

## 参考

- CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')
- Linux kernel RLIMIT_MEMLOCK (include/uapi/linux/resource.h)
- Linux kernel mm->locked_vm accounting (mm/mlock.c)
- POSIX rlimit API (setrlimit/getrlimit)
- VULN_QUEUE_002: ioctl参数上限检查缺陷（相关漏洞）

## 标签

- resource-exhaustion
- process-limit
- dma-memory
- uncontrolled-allocation
- kernel-memory
- dos-vulnerable
