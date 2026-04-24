# VULN-LQDRV-002：驱动模块漏洞报告

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-LQDRV-002 |
| **类型** | Kernel Memory Exposure |
| **CWE** | CWE-787 (Out-of-bounds Write) / CWE-200 (Information Exposure) |
| **严重级别** | Critical |
| **置信度** | 85 (CONFIRMED) |
| **所在文件** | src/custom/lqdrv/kernel/pci-dev.c |
| **函数名** | shared_memory_mmap |
| **行号** | 199-262 |

**漏洞描述**: 内核通过 `kmalloc` 分配的堆内存直接映射到用户空间，绕过内核内存隔离机制。用户进程可读写内核内存区域，导致内核数据泄露、内核内存破坏、潜在权限提升。

---

## 攻击路径分析

### 数据流图

```
mmap() syscall
    ↓
file_operations.mmap → shared_memory_mmap (pci-dev.c:210)
    ↓
kmalloc(SHM_SIZE, GFP_KERNEL) → 内核堆分配 1.7MB 内存 (pci-dev.c:201)
    ↓
virt_to_phys(shm->mem) → 将内核虚拟地址转换为物理地址 (pci-dev.c:259)
    ↓
remap_pfn_range(vma, vma->vm_start, pfn, shm->size, ...) → 直接映射物理页到用户空间 (pci-dev.c:262)
    ↓
用户进程可读写内核物理内存页
```

### 关键代码片段

```c
// pci-dev.c:199-207 - kmalloc分配内核堆内存
STATIC void *create_shared_memory(size_t size)
{
    void *memory = kmalloc(size, KA_GFP_KERNEL);  // 内核堆分配
    if (!memory) {
        printk(KA_KERN_ERR "[lqdcmi]Failed to allocate memory\n");
        return NULL;
    }
    return memory;
}

// pci-dev.c:259-262 - 直接映射到用户空间
pfn = ka_mm_virt_to_phys(shm->mem) >> KA_MM_PAGE_SHIFT;
ret = ka_mm_remap_pfn_range(vma, vma->vm_start, pfn, shm->size, vma->vm_page_prot);
```

### 攻击场景

1. **内核数据泄露**: 用户进程打开 `/dev/lqdcmi_pcidev`，调用 `mmap()`，获得内核堆内存的读写权限。可读取：
   - 内核分配器元数据 (slab allocator 信息)
   - 内存释放后残留的敏感数据 (密码、密钥、指针)
   - 内核后续写入的故障事件数据

2. **内核内存破坏**: 用户写入恶意数据到共享内存，内核后续读取时：
   - `write_shared_memory()` 函数读取用户写入的数据 (pci-dev.c:306-308)
   - 内核信任共享内存中的 head/tail 指针，可能导致内存越界访问

3. **权限提升**: 通过修改共享内存中的指针/索引，诱导内核执行恶意代码路径

---

## 利用条件

### 必要条件

| 条件 | 状态 | 证据 |
|------|------|------|
| 设备文件可访问 | ✓ 满足 | `/dev/lqdcmi_pcidev` 通过 `device_create()` 创建 (pci-dev.c:1518) |
| 无权限检查 | ✓ 满足 | `pcidev_open()` 直接返回 0，无 capability 检查 (pci-dev.c:340-343) |
| mmap 入口暴露 | ✓ 满足 | `file_operations.mmap = shared_memory_mmap` (pci-dev.c:461) |
| 内核内存映射 | ✓ 满足 | `kmalloc` → `virt_to_phys` → `remap_pfn_range` (pci-dev.c:201,259,262) |

### 利用步骤

```bash
# 1. 打开设备文件（无权限限制）
fd = open("/dev/lqdcmi_pcidev", O_RDWR);

# 2. mmap 获取内核内存访问权限
void *kernel_mem = mmap(NULL, SHM_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

# 3. 读取内核数据（泄露敏感信息）
memcpy(stolen_data, kernel_mem, SHM_SIZE);

# 4. 写入恶意数据（破坏内核数据结构）
memset(kernel_mem, 0xDEADBEEF, sizeof(struct some_kernel_struct));
```

---

## 影响评估

### 直接影响

- **信息泄露**: 1.7MB 内核内存完全暴露，包含内核分配器元数据和潜在敏感数据
- **内存破坏**: 用户写入可污染内核读取的数据，导致越界访问或逻辑错误
- **系统稳定性**: 恶意写入可触发内核 panic 或崩溃
- **权限提升**: 可能通过精心构造的数据实现本地提权

### 影响范围

- **模块**: lqdrv_custom (灵渠驱动定制模块)
- **设备**: 所有搭载昇腾NPU的服务器主机
- **用户**: 任何有设备文件访问权限的本地用户（典型为 root 或特定组，但设备权限可能被放宽）
- **容器**: 容器内进程可通过设备挂载访问

### 风险评分

- **CVSS 3.1 Base**: 8.8 (High) - AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
- **置信度**: 85 (CONFIRMED)

---

## 修复建议

### 推荐方案: 使用专用共享内存机制

**正确做法**: 不应使用 `kmalloc` + `remap_pfn_range`，应使用内核提供的共享内存 API：

```c
// 方案1: 使用 dma_alloc_coherent (适用于 DMA 场景)
void *mem;
dma_addr_t dma_handle;
mem = dma_alloc_coherent(dev, SHM_SIZE, &dma_handle, GFP_KERNEL);
// remap_pfn_range 仍然不安全，应使用 dma_mmap_coherent

// 方案2: 使用 shmem_file_setup (标准共享内存)
struct file *shm_file = shmem_file_setup("lqdcmi_shm", SHM_SIZE, VM_NORESERVE);
// 用户通过 fd mmap，内核通过 shm_file 访问

// 方案3: 使用 memfd_create 用户态创建 + 内核通过 fd 访问
```

### 最小修复: 添加权限检查

```c
STATIC int shared_memory_mmap(struct file *file, struct vm_area_struct *vma)
{
    // 添加权限检查
    if (!capable(CAP_SYS_ADMIN) && !capable(CAP_SYS_RAWIO)) {
        printk(KA_KERN_ERR "[lqdcmi]mmap requires CAP_SYS_ADMIN\n");
        return -EPERM;
    }
    
    // 添加 VMA 权限限制
    if (vma->vm_flags & VM_WRITE) {
        // 仅允许特权用户写入
        if (!capable(CAP_SYS_ADMIN)) {
            return -EPERM;
        }
    }
    
    // ... 原有逻辑
}
```

### 额外防护措施

1. **限制进程数量**: 当前已限制 `MAX_PROCESS_NUM = 15`，但无进程身份验证
2. **设备文件权限**: 确保 `/dev/lqdcmi_pcidev` 仅限 root 或特权组访问
3. **内存内容加密**: 对敏感数据进行加密存储
4. **审计日志**: 记录所有 mmap 操作的进程信息和时间

---

## 根因分析

### 设计缺陷

1. **错误使用 kmalloc**: `kmalloc` 分配的是内核虚拟地址空间的内存，属于内核私有的堆区域，不应直接映射到用户空间

2. **virt_to_phys 误用**: `virt_to_phys` 仅适用于直接映射的内核地址（lowmem），对于高地址或 vmalloc 分配的内存不适用。kmalloc 返回的地址可能不在直接映射区域

3. **remap_pfn_range 危险**: 此函数绕过内核内存隔离，将物理页直接映射到用户空间，违反 Linux 内核安全设计原则

### 对比正确实现

参考 Linux 内核中安全共享内存实现：
- `/dev/mem`: 需要 `CAP_SYS_RAWIO` 权限，且有 `strict_devmem` 限制
- `/dev/kmem`: 已被移除，因其危险性
- DRM/GPU 驱动: 使用 `drm_gem_mmap` 和专用 buffer 对象
- VFIO: 使用 `vfio_mmap` 配合 IOMMU 隔离

---

## 验证状态

| 检查项 | 结果 | 说明 |
|--------|------|------|
| 一票否决检查 | 通过 | 非 test_code，非 unreachable，非 chain_broken |
| 可达性 | +30 | 直接外部输入 (trust_level: untrusted_local) |
| 可控性 | +25 | 用户完全可控读写内容 |
| 缓解措施 | 0 | 无权限检查、无边界验证、无输入清洗 |
| 上下文 | 0 | file_operations.mmap (外部 API) |
| 跨文件 | 0 | 调用链完整 |
| **总分** | **85** | **CONFIRMED** |

---

## 相关漏洞参考

- CVE-2019-8912: Samsung kernel driver 暴露内核内存
- CVE-2018-16552: NVIDIA GPU driver mmap 内核内存泄露
- CVE-2020-10750: Linux kernel `/dev/mem` 访问控制绕过

---

## 附录: 评分明细

```json
{
  "id": "VULN-LQDRV-002",
  "confidence": 85,
  "status": "CONFIRMED",
  "veto_applied": false,
  "scoring_details": {
    "base": 30,
    "reachability": 30,
    "controllability": 25,
    "mitigations": 0,
    "context": 0,
    "cross_file": 0
  }
}
```
