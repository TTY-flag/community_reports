# VULN_QUEUE_RACE_STATIC_001：静态变量竞态条件漏洞

## 漏洞摘要

| 属性 | 值 |
|------|-----|
| **CWE** | CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization |
| **严重级别** | Medium |
| **文件** | `src/sdk_driver/queue/host/queue_fops.c` |
| **函数** | `queue_get_host_phy_mach_flag` |
| **行号** | 295-308 |
| **置信度** | HIGH (已确认) |

## 漏洞描述

函数 `queue_get_host_phy_mach_flag()` 内使用静态全局变量 `get_flag` 和 `get_host_flag` 作为缓存标志，但访问这些变量时未使用任何同步机制。当多个线程并发调用此函数时，可能导致：

1. **TOCTOU 竞态**: 检查 `get_flag == false` 与设置 `get_flag = true` 之间存在竞态窗口
2. **双重初始化**: 多个线程可能同时进入初始化分支，导致 `devdrv_get_host_phy_mach_flag()` 被多次调用
3. **数据不一致**: 一个线程正在写入 `get_host_flag` 时，另一个线程可能读取到部分更新的值

## 受影响代码

```c
// 文件: src/sdk_driver/queue/host/queue_fops.c, 行 293-309
STATIC int queue_get_host_phy_mach_flag(u32 devid, u32 *host_flag)
{
    static bool get_flag = false;      // 静态变量，无同步保护
    static u32 get_host_flag;          // 静态变量，无同步保护
    int ret;

    if (get_flag == false) {           // 检查点：非原子操作
        ret = devdrv_get_host_phy_mach_flag(devid, &get_host_flag);
        if (ret != 0) {
            queue_err("Get host physics flag failed.(devid=%u;ret=%d).\n", devid, ret);
            return ret;
        }
        get_flag = true;               // 设置点：非原子操作
    }
    *host_flag = get_host_flag;        // 读取点：可能读到不一致值
    return 0;
}
```

## 调用链分析

```
用户态 ioctl 调用
    ↓
queue_fop_enqueue() [行 526, ioctl handler]
    ↓
queue_drv_enqueue() [行 560]
    ↓
queue_drv_que_chan_create() [行 430]
    ↓
queue_chan_attr_pack() [行 389]
    ↓
queue_is_hccs_vm_through_scene() [行 346]
    ↓
queue_get_host_phy_mach_flag() [行 316] ← 漏洞点
```

### 并发上下文

- `queue_fop_enqueue` 是 ioctl 处理函数，可被多个用户进程/线程并发调用
- 无外部锁保护整个调用链
- 函数在内核模块中执行，可能被多个 CPU 核心同时进入

## 竞态场景

### 场景 1: 双重初始化
```
时间线:
T1: Thread A 检查 get_flag == false → 进入 if 块
T2: Thread B 检查 get_flag == false → 进入 if 块 (竞态!)
T3: Thread A 调用 devdrv_get_host_phy_mach_flag()
T4: Thread B 调用 devdrv_get_host_phy_mach_flag() ← 重复调用
T5: Thread A 设置 get_flag = true
T6: Thread B 设置 get_flag = true (无意义重复设置)
```

### 场景 2: 读取不一致值
```
时间线:
T1: Thread A 检查 get_flag == false → 进入 if 块
T2: Thread A 开始写入 get_host_flag
T3: Thread B 检查 get_flag → 可能为 false 或 true (取决于写入顺序)
T4: Thread B 读取 get_host_flag → 可能读到部分更新或不一致的值
```

## 影响分析

### 潜在后果

1. **功能异常**: 
   - 多次初始化可能导致资源泄漏或状态不一致
   - `devdrv_get_host_phy_mach_flag()` 的副作用可能被意外重复执行

2. **决策错误**:
   - `queue_is_hccs_vm_through_scene()` 依赖 `host_flag` 做判断
   - 错误的 `host_flag` 值可能导致错误的 HCCS 直通场景判断
   - 影响后续的通信协议选择和设备配置

3. **稳定性风险**:
   - 在高并发负载下，竞态条件更容易触发
   - 可能导致难以复现的间歇性故障

### 受影响组件

- Queue 子系统的设备初始化路径
- HCCS 虚拟机直通场景判断逻辑
- 设备通信协议选择

## 修复建议

### 方案 1: 使用原子变量 (推荐)

```c
#include <linux/atomic.h>

STATIC int queue_get_host_phy_mach_flag(u32 devid, u32 *host_flag)
{
    static atomic_t get_flag = ATOMIC_INIT(0);
    static u32 get_host_flag;
    int ret;

    // 使用原子比较交换，确保只有一个线程执行初始化
    if (atomic_cmpxchg(&get_flag, 0, 1) == 0) {
        ret = devdrv_get_host_phy_mach_flag(devid, &get_host_flag);
        if (ret != 0) {
            atomic_set(&get_flag, 0);  // 初始化失败，重置标志
            queue_err("Get host physics flag failed.(devid=%u;ret=%d).\n", devid, ret);
            return ret;
        }
    }
    *host_flag = READ_ONCE(get_host_flag);  // 使用 READ_ONCE 确保读取完整性
    return 0;
}
```

### 方案 2: 使用互斥锁

```c
#include <linux/mutex.h>

static DEFINE_MUTEX(host_flag_mutex);
static bool get_flag = false;
static u32 get_host_flag;

STATIC int queue_get_host_phy_mach_flag(u32 devid, u32 *host_flag)
{
    int ret;

    mutex_lock(&host_flag_mutex);
    if (get_flag == false) {
        ret = devdrv_get_host_phy_mach_flag(devid, &get_host_flag);
        if (ret != 0) {
            mutex_unlock(&host_flag_mutex);
            queue_err("Get host physics flag failed.(devid=%u;ret=%d).\n", devid, ret);
            return ret;
        }
        get_flag = true;
    }
    *host_flag = get_host_flag;
    mutex_unlock(&host_flag_mutex);
    return 0;
}
```

### 方案 3: 模块初始化时获取 (最彻底)

将 `get_host_flag` 的初始化移至模块或设备初始化阶段，避免运行时竞态：

```c
// 在模块初始化或设备探测时调用
static u32 g_host_phy_mach_flag;
static bool g_host_flag_initialized = false;

int queue_host_flag_init(u32 devid)
{
    int ret;
    ret = devdrv_get_host_phy_mach_flag(devid, &g_host_phy_mach_flag);
    if (ret == 0) {
        g_host_flag_initialized = true;
    }
    return ret;
}

STATIC int queue_get_host_phy_mach_flag(u32 devid, u32 *host_flag)
{
    if (!g_host_flag_initialized) {
        queue_err("Host flag not initialized.\n");
        return -EINVAL;
    }
    *host_flag = g_host_phy_mach_flag;
    return 0;
}
```

## 推荐修复方案

**推荐方案 1 (原子变量)**，理由：
- 性能开销最小
- 代码改动量小
- 无需引入新的锁机制
- 内核模块中常见的惰性初始化模式

## 验证方法

### 静态分析
- 使用 ThreadSanitizer 或类似的并发分析工具
- 检查所有对静态变量的访问是否有同步保护

### 动态测试
- 多线程并发调用 ioctl 接口
- 使用 KASAN 或 KCSAN (Kernel Concurrency Sanitizer) 检测竞态
- 添加调试日志验证 `devdrv_get_host_phy_mach_flag()` 是否被多次调用

## 相关文件

- `src/sdk_driver/queue/host/queue_fops.c` - 漏洞所在文件
- `src/sdk_driver/queue/host/common/queue_proc_fs.c` - 同目录下使用原子操作的示例

## 参考资料

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
- [Linux Kernel Atomic Operations](https://www.kernel.org/doc/html/latest/core-api/atomic_ops.html)
- [KCSAN - Kernel Concurrency Sanitizer](https://www.kernel.org/doc/html/latest/dev-tools/kcsan.html)
