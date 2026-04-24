# VULN-CROSS-MMAP-001：跨模块内核内存暴露漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | VULN-CROSS-MMAP-001 |
| **类型** | 内核内存暴露 (Kernel Memory Exposure) |
| **CWE** | CWE-787: Out-of-bounds Write |
| **严重性** | Critical |
| **置信度** | 90% |
| **模块** | cross_module (lqdrv_custom, svm_memory) |
| **文件** | src/custom/lqdrv/kernel/pci-dev.c |
| **行号** | 210-267 |
| **函数** | shared_memory_mmap |

### 描述

跨模块内核内存暴露：lqdrv_custom模块的shared_memory_mmap将kmalloc分配的内核堆内存通过remap_pfn_range直接映射到用户空间，svm_memory模块的内存映射同样存在物理地址暴露风险。用户进程可直接读写内核内存，导致数据泄露或内核崩溃。

## 攻击路径分析

### 数据流图

```
┌─────────────────┐                    ┌──────────────────────┐
│ 用户进程        │                    │ shared_memory_mmap   │
│ (untrusted)     │ ─── mmap() ───────►│   @ line 210         │
└─────────────────┘                    └──────────┬───────────┘
                                                   │
                                                   │ kmalloc(SHM_SIZE)
                                                   │ @ line 201
                                                   ▼
                                        ┌──────────────────────┐
                                        │ 内核堆内存            │
                                        │ shm->mem (kmalloc)   │
                                        └──────────┬───────────┘
                                                   │
                                                   │ virt_to_phys()
                                                   │ ka_mm_virt_to_phys()
                                                   │ @ line 259
                                                   ▼
                                        ┌──────────────────────┐
                                        │ 物理地址 (PFN)        │
                                        │ pfn = phys >> shift  │
                                        └──────────┬───────────┘
                                                   │
                                                   │ remap_pfn_range()
                                                   │ @ line 262
                                                   ▼
┌─────────────────┐                    ┌──────────────────────┐
│ 用户虚拟地址    │ ◄───────────────── │ 用户VMA映射           │
│ 可读写内核内存  │                    │ vma->vm_start        │
└─────────────────┘                    └──────────────────────┘
        │
        │ 攻击利用:
        │ - 读取敏感内核数据
        │ - 修改内核结构体
        │ - 注入恶意代码
        ▼
┌─────────────────┐
│ 权限提升        │
│ 内核崩溃        │
│ 数据泄露        │
└─────────────────┘
```

### 跨模块影响

```
┌───────────────────────────────────────────────────────────┐
│                    Cross Module Attack                     │
├───────────────────────────────────────────────────────────┤
│  lqdrv_custom                                              │
│  ├── shared_memory_mmap → kmalloc → remap_pfn_range       │
│  └── 无能力检查 (CAP_SYS_ADMIN)                           │
│                                                            │
│  svm_memory                                                │
│  ├── devmm_svm_mmap → 共享内存映射                        │
│  └── 无容器隔离验证                                        │
│                                                            │
│  user_process                                              │
│  └── 可跨容器访问共享内存                                 │
│  └── 攻击面扩大                                            │
└───────────────────────────────────────────────────────────┘
```

### 关键代码分析

```c
// pci-dev.c: line 210-267
static int shared_memory_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct shm_info *shm = ...;
    
    // 问题1: kmalloc分配的内核堆内存
    shm->mem = kmalloc(SHM_SIZE, GFP_KERNEL);  // line 201
    
    // 问题2: 直接获取物理地址，无隔离
    pfn = ka_mm_virt_to_phys(shm->mem) >> KA_MM_PAGE_SHIFT;  // line 259
    
    // 问题3: 直接映射到用户空间，无能力检查
    ret = ka_mm_remap_pfn_range(vma, vma->vm_start, pfn, 
                                 shm->size, vma->vm_page_prot);  // line 262
    
    // 缺失验证:
    // - 无 CAP_SYS_ADMIN 检查
    // - 无设备所有权验证
    // - 无 VMA 权限标志验证
    // - 无 vm_pgoff 验证
}
```

## 利用条件

### 触发条件

| 条件 | 描述 |
|------|------|
| **攻击者位置** | 本地用户进程 (User Space) |
| **信任边界** | 跨越 User Space Interface 边界 |
| **前置条件** | 设备文件访问权限 (/dev/lqdrv) |
| **触发方式** | mmap 系统调用 |

### 攻击者能力要求

- **能力等级**: Unprivileged Local
- **所需权限**: 设备文件访问权限
- **技术要求**: 
  - 了解 mmap 系统调用
  - 了解 remap_pfn_range 机制
  - 知道设备文件路径

### 利用步骤

```bash
# 1. 打开设备文件
fd = open("/dev/lqdrv", O_RDWR);

# 2. 映射共享内存
void *map = mmap(NULL, SHM_SIZE, PROT_READ|PROT_WRITE, 
                 MAP_SHARED, fd, 0);

# 3. 读/写内核内存
// 直接读取内核堆内存内容
kernel_data = *(uint64_t*)(map + offset);

// 修改内核结构体
*(uint64_t*)(map + offset) = malicious_value;

# 4. 利用效果
// 信息泄露: 读取进程凭证、密钥等
// 权限提升: 修改进程权限结构
// 内核崩溃: 破坏关键内核数据
```

## 影响评估

### 直接影响

| 影响类型 | 严重性 | 描述 |
|----------|--------|------|
| **内核内存泄露** | Critical | 用户可读取任意内核堆内存 |
| **内核内存损坏** | Critical | 用户可修改内核数据结构 |
| **权限提升** | Critical | 修改进程凭证实现提权 |
| **容器隔离绕过** | High | 跨容器访问共享内存 |

### 潜在后果

1. **信息泄露**: 读取内核中存储的敏感数据（密钥、凭证）
2. **权限提升**: 修改 cred 结构体提升进程权限至 root
3. **内核崩溃**: 破坏关键内核数据导致系统崩溃
4. **容器逃逸**: 跨容器访问其他进程的内存

### CVSS 评估

- **攻击向量**: Local
- **攻击复杂度**: Low
- **权限要求**: Low
- **用户交互**: None
- **影响范围**: Changed
- **CVSS 评分**: 8.8 (High)

## 修复建议

### 立即修复方案

```c
// 1. 添加能力检查
static int shared_memory_mmap(struct file *filp, struct vm_area_struct *vma)
{
    // 新增: 权限检查
    if (!capable(CAP_SYS_ADMIN)) {
        printk(KERN_ERR "mmap requires CAP_SYS_ADMIN\n");
        return -EPERM;
    }
    
    // 新增: 设备所有权验证
    struct shm_info *shm = filp->private_data;
    if (!verify_device_ownership(current->pid, shm->device_id)) {
        return -EACCES;
    }
    
    // 新增: VMA权限验证
    if (vma->vm_flags & VM_EXEC) {
        return -EPERM;  // 禁止执行权限
    }
    
    // 新增: 大小验证
    if (vma->vm_end - vma->vm_start > shm->size) {
        return -EINVAL;
    }
    
    // 新增: vm_pgoff验证
    if (vma->vm_pgoff != 0) {
        return -EINVAL;
    }
    
    // ... 继续处理
}
```

### 使用专用内存

```c
// 2. 使用独立的共享内存区域，而非内核堆
static int shared_memory_mmap_safe(struct file *filp, struct vm_area_struct *vma)
{
    // 使用 vmalloc 或专用 DMA 内存
    void *shared_mem = vmalloc_user(SHM_SIZE);  // 用户安全的内存
    
    // 或使用 DMA 缓冲区
    dma_addr_t dma_handle;
    void *dma_mem = dma_alloc_coherent(dev, SHM_SIZE, &dma_handle, GFP_KERNEL);
    
    // 映射专用内存而非内核堆
    ret = remap_pfn_range(vma, vma->vm_start, 
                          vmalloc_to_pfn(shared_mem), 
                          shm->size, pgprot_noncached(vma->vm_page_prot));
}
```

### 长期修复方案

1. **分离内核内存**: 使用专用共享内存池，不暴露内核堆
2. **加密映射**: 映射前加密数据，防止直接读取
3. **审计日志**: 记录所有 mmap 操作用于审计
4. **资源限制**: 限制单进程可映射的总内存大小

### 配置加固

```bash
# 限制设备文件访问权限
chmod 0600 /dev/lqdrv
chown root:root /dev/lqdrv

# 使用 SELinux/AppArmor 限制访问
# SELinux policy:
type lqdrv_device_t;
allow privileged_process_t lqdrv_device_t:chr_file { read write mmap };
```

## 验证状态

- **源代码审查**: 已确认 kmalloc → virt_to_phys → remap_pfn_range 路径
- **数据流追踪**: 完成 user_mmap → kernel_heap → user_mapping
- **边界检查**: 无 CAP_SYS_ADMIN、无设备所有权验证
- **置信度评分**: 90/100