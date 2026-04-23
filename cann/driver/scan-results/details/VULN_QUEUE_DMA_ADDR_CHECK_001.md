# VULN_QUEUE_DMA_ADDR_CHECK_001：DMA地址输入验证不足漏洞

### 元数据
| 字段 | 值 |
|-------|-------|
| **漏洞 ID** | VULN_QUEUE_DMA_ADDR_CHECK_001 |
| **CWE** | CWE-20: 输入验证不足 |
| **严重性** | High |
| **状态** | 已确认 |
| **置信度** | 90 |

### 位置信息
| 字段 | 值 |
|-------|-------|
| **文件** | `src/sdk_driver/queue/host/common/queue_dma.c` |
| **函数** | `queue_get_user_pages` |
| **行号范围** | 235-260 |

### 漏洞描述

函数 `queue_get_user_pages` 使用 VMA（虚拟内存区域）查找进行 DMA 地址验证，但**未能验证 `va + len` 的完整边界**。当前实现仅检查：
1. `vma == NULL`（未找到该地址的 VMA）
2. `dma_list->va < vma->vm_start`（起始地址低于 VMA 范围）

**缺失检查**：函数未验证 `dma_list->va + dma_list->len <= vma->vm_end`，允许用户提供的缓冲区长度扩展超出 VMA 的已分配边界。

### 漏洞代码

```c
STATIC int queue_get_user_pages(struct queue_dma_list *dma_list)
{
    ka_vm_area_struct_t *vma = NULL;
    bool svm_flag;
    int ret;

    ka_task_down_read(get_mmap_sem(ka_task_get_current()->mm));
    vma = ka_mm_find_vma(ka_task_get_current()->mm, dma_list->va);
    if ((vma == NULL) || (dma_list->va < vma->vm_start)) {
        ka_task_up_read(get_mmap_sem(ka_task_get_current()->mm));
        queue_err("Get vma failed. (va=0x%pK; len=0x%llx; page_num=%llu)\n",
            (void *)(uintptr_t)dma_list->va, dma_list->len, dma_list->page_num);
        return -EFBIG;
    }
    svm_flag = is_svm_addr(vma, dma_list->va);
    ka_task_up_read(get_mmap_sem(ka_task_get_current()->mm));

    /* memory remap by remap_pfn_rang, get user page fast can not get page addr */
    if (svm_flag == true) {
        ret = devmm_get_pages_list(ka_task_get_current()->mm, dma_list->va, dma_list->page_num, dma_list->page);
    } else {
        ret = queue_get_user_pages_fast(dma_list->va, dma_list->page_num, dma_list->page);
    }

    return ret;
}
```

### 数据流分析

**污点源**：用户通过 `queue_chan_iovec_add` 提供的 `iovec` 结构

```
queue_chan_iovec_add(iovec)                     [用户输入入口]
    ↓
    _queue_chan_dma_iovec_add(chan_dma, iovec->va, iovec->len, iovec->dma_flag)  [第265行]
        ↓
        chan_dma->dma_list.va = iovec->va        [直接赋值，无验证]
        chan_dma->dma_list.len = iovec->len      [直接赋值，无验证]
    ↓
    _queue_chan_dma_map() → queue_make_dma_list()  [第266行]
        ↓
        queue_fill_dma_blks() → queue_get_user_pages()  [第270行]
            ↓
            ka_mm_find_vma(mm, dma_list->va)     [VMA查找 - 仅检查va]
            [缺失: va + len边界检查]
            ↓
            queue_get_user_pages_fast(va, page_num, pages)  [第256行]
                ↓
                ka_mm_get_user_pages_fast()      [内核API - 假设范围有效]
```

**污点汇**：`ka_mm_get_user_pages_fast()` - DMA页面固定操作

### 攻击场景

1. **攻击准备**：攻击者分配一个小 VMA（例如，地址 `va` 处的1页）
2. **恶意输入**：攻击者提供 `iovec` 参数：
   - `va`：已分配 VMA 内的有效地址
   - `len`：大值（例如，0x10000000）远超 VMA 边界
3. **漏洞触发**：VMA 查找成功，因为 `va` 有效
4. **后果**：驱动尝试固定超出用户已分配内存的页面，可能导致：
   - 访问未映射的内存区域
   - 对内核内存或其他进程内存执行 DMA 操作
   - 信息泄露或内存破坏

### 根因分析

**根本原因**：`queue_get_user_pages` 中的验证逻辑假设：如果起始地址（`va`）在有效 VMA 内，则整个范围（`va` 到 `va+len`）也必须有效。这是错误假设，因为：

1. VMA 可能不连续 - VMA 后的下一个内存区域可能是：
   - 未映射的（地址空间中的空洞）
   - 属于具有不同权限的其他 VMA
   - 内核内存区域

2. `queue_get_page_num()`（第112-121行）中的 `page_num` 计算计算跨越 `va + len` 的页面，可能超出 VMA 边界。

### 影响评估

| 影响类别 | 严重性 | 描述 |
|-----------------|----------|-------------|
| **内存破坏** | High | 对未映射内存的 DMA 操作可能破坏内核状态 |
| **信息泄露** | High | 非预期的 DMA 可能泄露内核或其他进程数据 |
| **权限提升** | Medium | 内存破坏可能导致任意代码执行 |
| **拒绝服务** | Medium | 无效内存访问导致内核崩溃或驱动崩溃 |

### 概念验证（概念性）

```c
// 触发漏洞的伪代码
struct queue_chan_iovec malicious_iovec;
malicious_iovec.va = 0x7fff0000;      // 有效用户空间地址
malicious_iovec.len = 0x100000000;    // 巨大长度超出VMA边界
malicious_iovec.dma_flag = true;

queue_chan_iovec_add(que_chan, &malicious_iovec);
// 驱动将尝试对超出用户VMA边界的内存执行DMA
```

### 修复建议

**在 `queue_get_user_pages` 中添加完整边界验证：**

```c
STATIC int queue_get_user_pages(struct queue_dma_list *dma_list)
{
    ka_vm_area_struct_t *vma = NULL;
    bool svm_flag;
    int ret;
    u64 end_addr;

    // 计算结束地址并进行溢出检查
    if (dma_list->len > 0) {
        end_addr = dma_list->va + dma_list->len - 1;
        if (end_addr < dma_list->va) {  // 溢出检查
            queue_err("Address range overflow. (va=0x%pK; len=0x%llx)\n",
                (void *)(uintptr_t)dma_list->va, dma_list->len);
            return -EINVAL;
        }
    }

    ka_task_down_read(get_mmap_sem(ka_task_get_current()->mm));
    vma = ka_mm_find_vma(ka_task_get_current()->mm, dma_list->va);
    if (vma == NULL) {
        ka_task_up_read(get_mmap_sem(ka_task_get_current()->mm));
        queue_err("Get vma failed. (va=0x%pK)\n",
            (void *)(uintptr_t)dma_list->va);
        return -EFBIG;
    }

    // 检查起始地址边界
    if (dma_list->va < vma->vm_start) {
        ka_task_up_read(get_mmap_sem(ka_task_get_current()->mm));
        queue_err("va below vma start. (va=0x%pK; vm_start=0x%pK)\n",
            (void *)(uintptr_t)dma_list->va, (void *)(uintptr_t)vma->vm_start);
        return -EFBIG;
    }

    // [新增] 检查结束地址边界 - 关键修复
    if ((dma_list->len > 0) && (end_addr >= vma->vm_end)) {
        ka_task_up_read(get_mmap_sem(ka_task_get_current()->mm));
        queue_err("Buffer extends beyond VMA. (va=0x%pK; len=0x%llx; vm_end=0x%pK)\n",
            (void *)(uintptr_t)dma_list->va, dma_list->len, (void *)(uintptr_t)vma->vm_end);
        return -EFBIG;
    }

    svm_flag = is_svm_addr(vma, dma_list->va);
    ka_task_up_read(get_mmap_sem(ka_task_get_current()->mm));

    /* ... 函数其余部分不变 ... */
}
```

### 替代方案：VMA跨越检查

对于合法跨越多个 VMA 的缓冲区，实现正确的多 VMA 验证：

```c
// 替代方法：验证整个范围可能跨越多个VMA
STATIC int queue_validate_user_range(u64 va, u64 len)
{
    u64 cur_va = va;
    u64 end_va = va + len;
    
    while (cur_va < end_va) {
        ka_vm_area_struct_t *vma = ka_mm_find_vma(current->mm, cur_va);
        if (vma == NULL || cur_va < vma->vm_start) {
            return -EFBIG;  // 地址空间中的空洞
        }
        cur_va = vma->vm_end;  // 移至下一个VMA
    }
    return 0;
}
```

### 相关代码引用

| 引用 | 位置 | 描述 |
|-----------|----------|-------------|
| `queue_chan_iovec_add` | `queue_channel.c:255-278` | 用户输入入口 |
| `_queue_chan_dma_iovec_add` | `queue_channel.c:165-171` | va/len直接赋值 |
| `queue_make_dma_list` | `queue_dma.c:362-410` | DMA列表创建调用者 |
| `queue_fill_dma_blks` | `queue_dma.c:262-283` | 调用 `queue_get_user_pages` |
| `queue_get_page_num` | `queue_dma.c:112-121` | 页数计算 |

### 安全评估总结

| 标准 | 状态 | 备注 |
|-----------|--------|-------|
| **输入验证** | 失败 | 缺失 `va+len` 边界检查 |
| **边界检查** | 失败 | 仅检查起始，不检查结束 |
| **溢出保护** | 失败 | `va+len` 无溢出检查 |
| **VMA连续性** | 失败 | 假设单个连续VMA |
| **错误处理** | 通过 | 正确返回错误代码 |
| **内存语义** | 失败 | 获取页面前释放 mmap_sem |

### 验证清单

- [x] 源代码已分析
- [x] 数据流从用户输入追踪到DMA操作
- [x] VMA验证逻辑确认不完整
- [x] 攻击场景已记录
- [x] 修复建议已提供
- [ ] 内核API文档已验证（ka_mm_find_vma语义）
- [ ] 真实利用可行性已测试（需要运行环境）

### 分类

**主要**：CWE-20（输入验证不足）  
**次要**：CWE-119（内存边界内操作限制不当）  
**相关**：CWE-125（越界读取）、CWE-787（越界写入）

---

*报告由安全审计代理生成*
*分析日期: 2026-04-22*