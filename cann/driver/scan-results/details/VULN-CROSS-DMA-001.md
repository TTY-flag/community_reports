# VULN-CROSS-DMA-001：跨模块DMA地址验证缺失漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-CROSS-DMA-001 |
| **类型** | DMA地址验证缺失 (DMA Address Validation Missing) |
| **CWE** | CWE-119: Improper Restriction of Operations within Bounds |
| **严重性** | Critical |
| **置信度** | 85% |
| **模块** | cross_module (queue_operations, hdc_communication, ascend_hal) |
| **文件** | src/sdk_driver/queue/host/common/queue_dma.c |
| **行号** | 424-462 |
| **函数** | queue_dma_sync_link_copy |

### 描述

跨模块DMA地址验证缺失：queue_operations模块通过hal_kernel_devdrv_dma_sync_link_copy传递用户提供的DMA地址到HAL模块，hdc_communication模块的DMA映射同样缺少地址范围验证。攻击者可构造恶意DMA地址导致越界写入设备内存或物理内存。

## 攻击路径分析

### 数据流图

```
┌─────────────────┐                    ┌──────────────────────┐
│ 用户进程        │                    │ ioctl(queue_drv_     │
│ (untrusted)     │ ─── ioctl() ─────► │   enqueue)           │
└─────────────────┘                    └──────────┬───────────┘
       │                                          │
       │ 提供DMA参数                               │ copy_from_user
       │ - dma_node.addr                          │ queue_get_vector
       │ - dma_node.size                          │
       ▼                                          ▼
┌─────────────────┐                    ┌──────────────────────┐
│ 构造恶意DMA参数 │                    │ queue_make_dma_list  │
│ - 越界地址      │                    │ queue_chan_iovec_add │
│ - 超大size      │ ─────────────────►│ @ line 424           │
└─────────────────┘                    └──────────┬───────────┘
                                                   │
                                                   │ 缺失验证:
                                                   │ - addr范围
                                                   │ - size上限
                                                   │ - 整数溢出
                                                   ▼
                                        ┌──────────────────────┐
                                        │ queue_dma_sync_      │
                                        │   link_copy          │
                                        │ @ line 424-462       │
                                        └──────────┬───────────┘
                                                   │
                                                   │ hal_kernel_devdrv_
                                                   │ dma_sync_link_copy
                                                   ▼
┌─────────────────┐                    ┌──────────────────────┐
│ 设备DMA引擎     │ ◄───────────────── │ HAL层                │
│                 │                    │ 直接使用用户地址     │
└────────┬────────┘                    └──────────────────────┘
         │
         │ DMA写入
         │ - 越界写入设备内存
         │ - 写入物理内存任意位置
         ▼
┌─────────────────┐
│ 设备内存损坏    │
│ 物理内存破坏    │
│ 系统崩溃        │
└─────────────────┘
```

### 跨模块调用链

```
┌─────────────────────────────────────────────────────────────┐
│                    Cross Module DMA Flow                     │
├─────────────────────────────────────────────────────────────┤
│  queue_operations                                            │
│  ├── queue_drv_enqueue (ioctl入口)                          │
│  ├── queue_get_vector (copy_from_user)                      │
│  ├── queue_chan_iovec_add (无验证)                          │
│  └── queue_dma_sync_link_copy (DMA触发)                     │
│                                                              │
│  ascend_hal                                                  │
│  ├── hal_kernel_devdrv_dma_sync_link_copy                   │
│  └── devdrv_dma_node_check (仅检查size/direction)           │
│                                                              │
│  hdc_communication                                           │
│  ├── hdcdrv_dma_map                                          │
│  └── PCIe硬件 → 设备固件                                    │
                                                              │
│  关键缺陷: 用户DMA地址未经完整范围验证                       │
└─────────────────────────────────────────────────────────────┘
```

### 关键代码分析

```c
// queue_dma.c: line 424-462
int queue_dma_sync_link_copy(...)
{
    // 问题: 用户DMA节点直接使用
    // copy_node 来自用户提供的 dma_node
    ret = hal_kernel_devdrv_dma_sync_link_copy(
        dev_id, 
        DEVDRV_DMA_DATA_TRAFFIC,
        DEVDRV_DMA_WAIT_INTR,
        copy_node,  // 用户地址，未验证
        copy_num
    );
    
    // 缺失验证:
    // - copy_node[].addr 是否在合法DMA范围
    // - copy_node[].size 是否超过设备内存限制
    // - addr + size 是否发生整数溢出
}

// 对比: devdrv_dma.c 的标准验证 (line 621-656)
int devdrv_dma_node_check(struct devdrv_dma_node *node)
{
    // 只验证 size 和 direction
    if (node->size > DEVDRV_DMA_MAX_SIZE) {
        return -EINVAL;
    }
    
    // 但不验证 addr 字段!
    // 地址验证缺失导致越界风险
}
```

### VMA验证不完整

```c
// queue_dma.c: line 235-260 (queue_get_user_pages)
vma = ka_mm_find_vma(current->mm, dma_list->va);

// 问题: 验证不完整
if ((vma == NULL) || (dma_list->va < vma->vm_start)) {
    return -EINVAL;
}

// 缺失验证:
// - dma_list->va + dma_list->len <= vma->vm_end (范围检查)
// - dma_list->len 是否导致整数溢出
```

## 利用条件

### 触发条件

| 条件 | 描述 |
|------|------|
| **攻击者位置** | 本地用户进程 (User Space) |
| **信任边界** | 跨越 User Space Interface → HAL → Device 边界 |
| **前置条件** | 设备文件访问权限 (/dev/queue) |
| **触发方式** | ioctl(queue_drv_enqueue) |

### 攻击者能力要求

- **能力等级**: Unprivileged Local
- **所需权限**: 设备文件访问权限
- **技术要求**: 
  - 了解 DMA ioctl 参数格式
  - 构造越界 DMA 地址
  - 了解设备内存布局

### 利用步骤

```c
// 1. 构造恶意DMA参数
struct dma_node malicious_node = {
    .addr = DEVICE_MEMORY_BASE + overflow_offset,  // 越界地址
    .size = 0xFFFFFFFF,  // 超大size触发溢出
    .direction = DMA_TO_DEVICE
};

// 2. 通过ioctl触发DMA
ioctl(fd, QUEUE_DRV_ENQUEUE, &enqueue_param);

// 3. DMA越界写入效果
// - 写入设备内存非法区域
// - 破坏设备固件代码
// - 写入其他进程的物理内存
```

## 影响评估

### 直接影响

| 影响类型 | 严重性 | 描述 |
|----------|--------|------|
| **DMA越界写入** | Critical | 写入设备内存非法区域 |
| **设备固件损坏** | Critical | 破坏设备执行代码 |
| **物理内存破坏** | Critical | 写入任意物理地址 |
| **信息泄露** | High | DMA读取越界内存 |

### 潜在后果

1. **设备崩溃**: DMA写入破坏设备固件
2. **系统崩溃**: DMA写入破坏关键物理内存
3. **权限提升**: 通过DMA修改内存中的进程凭证
4. **设备侧执行**: 在设备固件中注入恶意代码

### CVSS 评估

- **攻击向量**: Local
- **攻击复杂度**: Medium
- **权限要求**: Low
- **用户交互**: None
- **影响范围**: Changed
- **CVSS 评分**: 7.8 (High)

## 修复建议

### 立即修复方案

```c
// 1. 添加完整DMA地址验证
int queue_dma_sync_link_copy_safe(...)
{
    struct devdrv_dma_node *node;
    int i;
    
    for (i = 0; i < copy_num; i++) {
        node = &copy_node[i];
        
        // 新增: 地址范围验证
        if (!validate_dma_address(node->addr, node->size, dev_id)) {
            devdrv_err("DMA address out of bounds (dev=%d; addr=0x%llx)\n",
                       dev_id, node->addr);
            return -EINVAL;
        }
        
        // 新增: 整数溢出检查
        if (node->addr + node->size < node->addr) {  // 溢出检测
            return -EINVAL;
        }
        
        // 新增: size上限检查
        if (node->size > DMA_MAX_TRANSFER_SIZE) {
            return -EINVAL;
        }
    }
    
    // 验证通过后执行DMA
    return hal_kernel_devdrv_dma_sync_link_copy(...);
}

// 2. VMA完整验证
int queue_get_user_pages_safe(struct dma_list *dma_list)
{
    unsigned long va_end = dma_list->va + dma_list->len;
    
    // 检查整数溢出
    if (va_end < dma_list->va) {
        return -EINVAL;
    }
    
    // 检查完整范围
    vma = find_vma(current->mm, dma_list->va);
    if (vma == NULL || va_end > vma->vm_end) {
        return -EINVAL;
    }
    
    // 检查权限
    if (!(vma->vm_flags & VM_WRITE) && dma_list->direction == DMA_TO_DEVICE) {
        return -EACCES;
    }
}
```

### 增强HAL层验证

```c
// 3. 在HAL层添加验证
int hal_kernel_devdrv_dma_sync_link_copy_safe(...)
{
    // 调用验证函数
    if (devdrv_dma_node_full_check(copy_node, copy_num, dev_id) != 0) {
        return -EINVAL;
    }
    
    // 原有DMA操作
    return hal_kernel_devdrv_dma_sync_link_copy(...);
}

int devdrv_dma_node_full_check(struct devdrv_dma_node *nodes, int num, int dev_id)
{
    struct device_mem_range *range = get_device_mem_range(dev_id);
    
    for (i = 0; i < num; i++) {
        // 验证地址在设备内存范围内
        if (nodes[i].addr < range->start || 
            nodes[i].addr + nodes[i].size > range->end) {
            return -EINVAL;
        }
    }
    return 0;
}
```

### 长期修复方案

1. **DMA沙箱**: 为每个进程建立独立的DMA地址空间
2. **IOMMU保护**: 启用IOMMU限制DMA地址范围
3. **审计日志**: 记录所有DMA操作用于事后审计
4. **资源配额**: 限制单进程DMA传输总量

### 配置加固

```bash
# 启用IOMMU保护
echo 1 > /sys/module/kernel/parameters/iommu

# 限制设备DMA权限
# 使用 VFIO 替代直接 DMA 访问
```

## 验证状态

- **源代码审查**: 已确认 queue_dma_sync_link_copy → hal_kernel_devdrv_dma_sync_link_copy 路径
- **数据流追踪**: 完成 ioctl → copy_node → DMA_engine
- **边界检查**: 仅检查size/direction，不验证addr范围
- **置信度评分**: 85/100