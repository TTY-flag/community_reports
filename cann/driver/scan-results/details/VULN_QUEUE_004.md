# VULN_QUEUE_004：DMA地址验证不足致越界写入漏洞

**漏洞ID**: VULN_QUEUE_004  
**漏洞类型**: dma_validation_missing  
**CWE**: CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer)  
**严重级别**: Critical  
**置信度**: 85  

## 漏洞概述

`queue_dma_sync_link_copy` 函数直接使用用户提供的 DMA 节点地址进行硬件 DMA 操作，缺少对 DMA 地址范围和大小上限的完整验证。具体而言，`queue_get_user_pages` 函数只检查虚拟地址的 VMA（Virtual Memory Area）存在性，但未验证 `va + len` 是否在 VMA 的有效范围内（`va + len <= vma->vm_end`），导致用户可以指定超大的长度触发 DMA 越界写入。

**核心问题**：
- **不完整的 VMA 验证**：只检查起始地址 `va` 是否在 VMA 范围内，忽略长度验证
- **绕过标准验证层**：直接调用 `hal_kernel_devdrv_dma_sync_link_copy`，跳过 `devdrv_dma_node_check` 等安全检查
- **无整数溢出防护**：缺少 `va + len` 溢出检测，可绕过边界检查

## 攻击路径分析

### 1. 入口点（ioctl 接口）

**位置**: `src/sdk_driver/queue/host/queue_fops.c:404`  
**函数**: `queue_drv_enqueue`

```c
// 用户通过 ioctl 提交队列请求
STATIC long queue_drv_enqueue(ka_file_t *filep, struct queue_ioctl_enqueue *para, ka_device_t *dev)
{
    // para->vector 包含用户提供的地址和长度
    vector = queue_get_vector(para);  // 从用户空间复制数据 (line 436)
    ...
    ret = queue_drv_vector_add(que_chan, para, vector);  // line 444
}
```

### 2. 用户数据复制（污点源）

**位置**: `queue_fops.c:192`  
**函数**: `queue_get_vector`

```c
// 从用户空间复制 vector 结构体（包含 iovec_base 和 len）
if (ka_base_copy_from_user(vector, para->vector, vector_len) != 0) {
    queue_err("copy_from_user failed.\n");
    return NULL;
}
```

**污点数据**：
- `vector->context_base` - 用户提供的基地址
- `vector->context_len` - 用户提供的长度
- `vector->ptr[i].iovec_base` - 用户提供的缓冲区地址
- `vector->ptr[i].len` - 用户提供的缓冲区长度

### 3. 污点传播（地址赋值）

**位置**: `queue_fops.c:358-368`  
**函数**: `queue_drv_vector_add`

```c
// 将用户提供的地址和长度赋值给 iovec 结构
iovec.va = (u64)(uintptr_t)vector->context_base;  // 用户提供的 va
iovec.len = vector->context_len;                  // 用户提供的 len
iovec.dma_flag = true;
ret = queue_chan_iovec_add(que_chan, &iovec);

for (i = 0; i < vector->count; i++) {
    iovec.va = (u64)(uintptr_t)vector->ptr[i].iovec_base;  // 用户提供的 va
    iovec.len = vector->ptr[i].len;                        // 用户提供的 len
    ...
}
```

### 4. DMA 列表初始化（缺少验证）

**位置**: `queue_channel.c:165-170`  
**函数**: `_queue_chan_dma_iovec_add`

```c
// 直接将用户提供的 va 和 len 赋值给 dma_list，无任何验证
static inline void _queue_chan_dma_iovec_add(struct queue_chan_dma *chan_dma,
    u64 va, u64 len, bool dma_flag)
{
    chan_dma->dma_list.va = va;      // 用户提供的值，无验证
    chan_dma->dma_list.len = len;    // 用户提供的值，无验证
    chan_dma->dma_list.dma_flag = dma_flag;
}
```

### 5. 不完整的 VMA 验证（漏洞核心）

**位置**: `queue_dma.c:235-260`  
**函数**: `queue_get_user_pages`

```c
STATIC int queue_get_user_pages(struct queue_dma_list *dma_list)
{
    ka_vm_area_struct_t *vma = NULL;
    bool svm_flag;
    int ret;

    ka_task_down_read(get_mmap_sem(ka_task_get_current()->mm));
    vma = ka_mm_find_vma(ka_task_get_current()->mm, dma_list->va);  // 查找 VMA
    if ((vma == NULL) || (dma_list->va < vma->vm_start)) {          // ⚠️ 不完整验证
        ka_task_up_read(get_mmap_sem(ka_task_get_current()->mm));
        queue_err("Get vma failed. (va=0x%pK; len=0x%llx; page_num=%llu)\n",
            (void *)(uintptr_t)dma_list->va, dma_list->len, dma_list->page_num);
        return -EFBIG;
    }
    // ❌ 缺失关键检查: dma_list->va + dma_list->len <= vma->vm_end
    svm_flag = is_svm_addr(vma, dma_list->va);
    ka_task_up_read(get_mmap_sem(ka_task_get_current()->mm));
    ...
}
```

**缺失验证分析**：
- ✅ 检查 `vma != NULL` - VMA 存在性
- ✅ 检查 `va >= vma->vm_start` - 起始地址合法
- ❌ **缺失**: `va + len <= vma->vm_end` - 地址范围完整性
- ❌ **缺失**: `va + len` 整数溢出检测 - 避免 wrap-around

### 6. DMA 操作执行（污点汇）

**位置**: `queue_dma.c:424-462`  
**函数**: `queue_dma_sync_link_copy`

```c
int queue_dma_sync_link_copy(u32 dev_id, struct devdrv_dma_node *dma_node, u64 dma_node_num)
{
    struct devdrv_dma_node *copy_node = dma_node;  // 用户控制的 DMA 节点
    ...
    // ⚠️ 直接调用硬件 DMA，跳过标准验证层
    ret = hal_kernel_devdrv_dma_sync_link_copy(dev_id, DEVDRV_DMA_DATA_TRAFFIC, 
        DEVDRV_DMA_WAIT_INTR, copy_node, copy_num);
    ...
}
```

**对比标准验证流程**：
标准函数 `devdrv_dma_sync_link_copy_plus_inner` 包含：
- `devdrv_dma_para_check()` - 设备/类型验证
- `devdrv_dma_node_check()` - node_cnt 范围、size!=0、direction 合法性
- `devdrv_peh_dma_node_addr_check()` - HCCS 地址范围和整数溢出检测

`queue_dma_sync_link_copy` **跳过所有验证**。

## 利用条件

### 条件 1: 用户具有 ioctl 访问权限
攻击者需要能够访问 `/dev/ascend_queue` 设备文件并调用 ioctl 接口。

### 条件 2: VMA 地址合法但长度超大
攻击者需要找到一个合法的虚拟地址 `va`，该地址有对应的 VMA，但提供的长度 `len` 远大于实际 VMA 覆盖范围。

**攻击示例**：
```c
// 假设进程有一个合法的映射区域: vma->vm_start=0x10000, vma->vm_end=0x20000 (64KB)
struct iovec_info iov;
iov.iovec_base = 0x10000;  // 合法的起始地址（在 VMA 范围内）
iov.len = 0x100000;        // 超大长度 (1MB)，超出 VMA 范围

// 通过 ioctl 提交请求
ioctl(fd, QUEUE_IOCTL_ENQUEUE, &para);
```

### 条件 3: DMA 方向为写入
如果 DMA 操作方向为 `DEVDRV_DMA_DEVICE_TO_HOST`（设备写入主机），可导致越界写入。

### 条件 4: HCCS 连接场景（部分缓解失效）
在 HCCS（High-Speed Coherent Communication System）连接场景下，`devdrv_peh_dma_node_addr_check` 会检查物理地址范围，但该检查在 `queue_dma_sync_link_copy` 中被跳过。

## 影响评估

### 1. DMA 越界写入
攻击者可以控制 DMA 写入的目标地址和大小，写入超出合法范围的内存区域：
- 写入其他进程的内存（信息泄露、内存破坏）
- 写入内核内存（权限提升、系统崩溃）
- 写入设备内存（硬件故障）

### 2. 信息泄露
通过 DMA 读操作（`DEVDRV_DMA_HOST_TO_DEVICE`）读取超出范围的内存：
- 读取其他进程的敏感数据
- 读取内核内存（凭证、密钥）
- 读取其他设备的内存区域

### 3. 权限提升
如果攻击者能够通过越界写入修改关键内核结构：
- 修改进程权限结构（cred 结构）
- 修改内核函数指针
- 修改内存保护属性

### 4. 系统崩溃/拒绝服务
越界 DMA 操作可能导致：
- 访问非法物理地址导致硬件异常
- 内存破坏导致系统崩溃
- 设备 DMA 引擎故障

### 5. 硬件安全风险
在服务器场景下，可能影响：
- 其他虚拟机的内存（虚拟化环境）
- 其他容器/进程的数据（容器化环境）
- 设备固件/配置区域

## 修复建议

### 1. 完善 VMA 范围验证（关键修复）

**位置**: `queue_dma.c:235-260`  
**修复方案**:

```c
STATIC int queue_get_user_pages(struct queue_dma_list *dma_list)
{
    ka_vm_area_struct_t *vma = NULL;
    bool svm_flag;
    int ret;
    u64 end_addr;

    // 整数溢出检测
    end_addr = dma_list->va + dma_list->len;
    if (end_addr < dma_list->va) {  // wrap-around 检测
        queue_err("Integer overflow detected. (va=0x%pK; len=0x%llx)\n",
            (void *)(uintptr_t)dma_list->va, dma_list->len);
        return -EINVAL;
    }

    ka_task_down_read(get_mmap_sem(ka_task_get_current()->mm));
    vma = ka_mm_find_vma(ka_task_get_current()->mm, dma_list->va);
    if ((vma == NULL) || (dma_list->va < vma->vm_start)) {
        ka_task_up_read(get_mmap_sem(ka_task_get_current()->mm));
        queue_err("Get vma failed. (va=0x%pK; len=0x%llx)\n",
            (void *)(uintptr_t)dma_list->va, dma_list->len);
        return -EFBIG;
    }
    
    // ✅ 新增: 完整地址范围验证
    if (end_addr > vma->vm_end) {
        ka_task_up_read(get_mmap_sem(ka_task_get_current()->mm));
        queue_err("Address range exceeds VMA bounds. (va=0x%pK; len=0x%llx; "
            "vma_start=0x%pK; vma_end=0x%pK)\n",
            (void *)(uintptr_t)dma_list->va, dma_list->len,
            (void *)(uintptr_t)vma->vm_start, (void *)(uintptr_t)vma->vm_end);
        return -EINVAL;
    }
    
    svm_flag = is_svm_addr(vma, dma_list->va);
    ka_task_up_read(get_mmap_sem(ka_task_get_current()->mm));
    ...
}
```

### 2. 添加 DMA 节点验证

**位置**: `queue_dma.c:424`  
**修复方案**:

```c
int queue_dma_sync_link_copy(u32 dev_id, struct devdrv_dma_node *dma_node, u64 dma_node_num)
{
    struct devdrv_dma_dev *dma_dev;
    int ret;
    
    // ✅ 新增: DMA 参数验证
    dma_dev = devdrv_get_dma_dev(dev_id);
    if (dma_dev == NULL) {
        queue_err("Invalid device ID. (dev_id=%u)\n", dev_id);
        return -EINVAL;
    }
    
    // ✅ 新增: DMA 节点验证（复用标准验证函数）
    ret = devdrv_dma_node_check(dev_id, dma_node, (u32)dma_node_num, dma_dev);
    if (ret != 0) {
        queue_err("DMA node validation failed. (dev_id=%u; ret=%d)\n", dev_id, ret);
        return ret;
    }
    
    // ✅ 新增: HCCS 地址范围验证
    int connect_protocol = devdrv_get_connect_protocol(dev_id);
    if (connect_protocol == CONNECT_PROTOCOL_HCCS) {
        for (u64 i = 0; i < dma_node_num; i++) {
            ret = devdrv_peh_dma_node_addr_check(&dma_node[i]);
            if (ret != 0) {
                queue_err("PEH DMA node address check failed. (index=%llu; ret=%d)\n", i, ret);
                return ret;
            }
        }
    }
    
    // 执行 DMA 操作
    ...
}
```

### 3. 添加大小上限限制

**修复方案**:

```c
// 在 queue_dma.h 中添加最大 DMA 大小定义
#define QUEUE_DMA_MAX_TRANSFER_SIZE (1024 * 1024 * 1024)  // 1GB 上限

// 在 queue_get_user_pages 或 queue_make_dma_list 中添加检查
if (dma_list->len > QUEUE_DMA_MAX_TRANSFER_SIZE) {
    queue_err("DMA transfer size exceeds limit. (len=0x%llx; max=%llu)\n",
        dma_list->len, QUEUE_DMA_MAX_TRANSFER_SIZE);
    return -EINVAL;
}
```

### 4. 统一使用标准验证路径

**长期修复方案**:
重构代码，使用 `devdrv_dma_sync_link_copy_plus_inner` 等标准函数，而非直接调用 HAL 层接口。

## 参考

- **CWE-119**: Improper Restriction of Operations within the Bounds of a Memory Buffer
- **类似问题**: `udis_data.c:955` 同样直接调用 `hal_kernel_devdrv_dma_sync_link_copy`，跳过验证
- **标准验证示例**: `devdrv_dma.c:621-656` (devdrv_dma_node_check)
- **PEH 地址检查**: `devdrv_dma.c:849-866` (devdrv_peh_dma_node_addr_check)

## 缓解措施（现有）

### vma_lookup_only（部分缓解，无效）
- 仅检查 VMA 存在性
- **无效原因**: 缺少完整地址范围验证，无法防止越界访问

---

**报告生成时间**: 2026-04-22  
**分析工具**: DataFlow Scanner + Security Auditor  
**验证状态**: CONFIRMED (置信度: 85)
