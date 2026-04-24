# VULN-LQDRV-001：驱动模块安全漏洞详情

## 漏洞概述

**漏洞ID**: VULN-LQDRV-001  
**类型**: 内存映射验证缺失 (Memory Mapping Validation Failure)  
**CWE**: CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer)  
**严重级别**: **Critical**  
**CVSS评分**: 9.8 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

### 基本信息
- **文件**: `src/custom/lqdrv/kernel/pci-dev.c`
- **函数**: `shared_memory_mmap`
- **行号**: 210-267
- **漏洞点**: 第 262 行

### 漏洞描述

`shared_memory_mmap` 函数在将内核共享内存映射到用户空间时，存在两个关键安全缺陷：

1. **边界验证缺失**：未验证用户请求的映射大小（`vma->vm_end - vma->vm_start`）是否超过实际分配的共享内存大小（`SHM_SIZE = 1835264 字节`）
2. **权限标志验证缺失**：未检查 `vma->vm_flags` 中的 `VM_WRITE` 或 `VM_EXEC` 标志，允许用户以任意权限映射内核内存

## 攻击路径分析

### 数据流路径
```
用户空间 mmap 调用
    ↓
sys_mmap (系统调用入口)
    ↓
file_operations.mmap (g_pcidev_fops)
    ↓
shared_memory_mmap (漏洞函数)
    ↓
ka_mm_remap_pfn_range (内核内存映射)
    ↓
用户可访问的内核内存区域
```

### 关键代码片段

**漏洞代码**（pci-dev.c:262）：
```c
// 第 210-267 行
STATIC int shared_memory_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct shared_memory *shm = file->private_data;
    unsigned long pfn;
    int ret = 0;

    ka_task_mutex_lock(&shared_mem_mutex);

    if (!shm) {
        // ... 分配共享内存
        shm->mem = create_shared_memory(SHM_SIZE);  // 分配固定大小
        shm->size = SHM_SIZE;  // 设置为 1835264 字节
        // ...
    }

    pfn = ka_mm_virt_to_phys(shm->mem) >> KA_MM_PAGE_SHIFT;

    // ⚠️ 漏洞：直接使用 vma->vm_start，未验证映射范围
    // ⚠️ 漏洞：直接使用 vma->vm_page_prot，未验证权限标志
    ret = ka_mm_remap_pfn_range(vma, vma->vm_start, pfn, shm->size, vma->vm_page_prot);

out:
    ka_task_mutex_unlock(&shared_mem_mutex);
    return ret;
}
```

### 攻击场景演示

**场景 1：越界内存读取**
```c
// 用户空间攻击代码
void *map1 = mmap(NULL, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
void *map2 = mmap(NULL, SHM_SIZE * 2, PROT_READ, MAP_SHARED, fd, 0);  // 请求 2x 大小

// map2 的后半部分会映射到内核内存中 SHM_SIZE 之后的内容
// 攻击者可读取未授权的内核数据
```

**场景 2：可写映射攻击**
```c
// 用户空间攻击代码
void *map = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

// 可以修改内核内存内容
*((unsigned long *)map) = 0x41414141;  // 直接写入内核空间
```

**场景 3：可执行映射攻击**
```c
// 用户空间攻击代码
void *map = mmap(NULL, SHM_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);

// 将共享内存作为代码执行
void (*func)() = (void (*)())map;
func();  // 执行位于内核内存的代码
```

## 利用条件

### 必要条件
1. **设备访问权限**：攻击者需要能够打开 `/dev/lqdcmi` 设备文件（需要适当的权限）
   - 通常需要 `root` 权限或在 `video/render` 组等特权组中
   - 设备权限配置不当可能导致低权限用户可访问

2. **本地访问**：攻击者需要在本地系统上执行代码

### 充分条件
- ✅ 无需特殊知识，公开 API 即可触发
- ✅ 无需绕过额外防护机制（如无 SMEP/SMAP 或防护可被绕过）
- ✅ 攻击代码简单，易于编写

### 环境因素
- **内核版本**：所有使用该驱动的内核版本
- **系统配置**：
  - SMEP (Supervisor Mode Execution Prevention)：可防止可执行映射攻击
  - SMAP (Supervisor Mode Access Prevention)：增加利用难度但非不可利用
  - KPTI (Kernel Page Table Isolation)：不影响此漏洞

## 影响评估

### 直接影响

1. **内核信息泄露** (CWE-200)
   - 可读取内核内存中敏感数据
   - 绕过 KASLR（内核地址空间布局随机化）
   - 泄露内核数据结构、指针、密钥等

2. **内核代码执行** (CWE-787)
   - 通过可写映射修改内核代码
   - 注入恶意代码实现提权
   - 修改内核数据结构破坏系统安全

3. **权限提升** (CWE-269)
   - 从普通用户提升至 root 权限
   - 突破容器/沙箱隔离
   - 获取完整系统控制权

### 间接影响

1. **系统完整性破坏**
   - 修改关键内核数据结构
   - 破坏系统调用表、中断描述符表等
   - 导致系统崩溃或不稳定

2. **数据泄露**
   - 读取其他进程的内存数据
   - 获取加密密钥、凭证等敏感信息
   - 窃取用户隐私数据

3. **持久化攻击**
   - 植入 rootkit
   - 修改系统启动流程
   - 建立后门访问

### 风险评级

| 维度 | 评级 | 说明 |
|------|------|------|
| 攻击复杂度 | 低 | 仅需简单 mmap 调用 |
| 权限要求 | 低-中 | 需要设备访问权限 |
| 用户交互 | 无 | 无需用户干预 |
| 影响范围 | 完整系统 | 可控制整个内核 |
| 机密性影响 | 高 | 可读取任意内核内存 |
| 完整性影响 | 高 | 可修改内核内存 |
| 可用性影响 | 高 | 可导致系统崩溃 |

## 修复建议

### 立即修复方案

**修改 `shared_memory_mmap` 函数**，添加边界和权限验证：

```c
STATIC int shared_memory_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct shared_memory *shm = file->private_data;
    unsigned long pfn;
    unsigned long map_size;
    int ret = 0;

    // ========== 新增：权限验证 ==========
    // 禁止可写映射
    if (vma->vm_flags & VM_WRITE) {
        printk(KA_KERN_ERR "[lqdcmi]Write mapping not allowed\n");
        return -EPERM;
    }

    // 禁止可执行映射
    if (vma->vm_flags & VM_EXEC) {
        printk(KA_KERN_ERR "[lqdcmi]Execute mapping not allowed\n");
        return -EPERM;
    }

    // ========== 新增：边界验证 ==========
    map_size = vma->vm_end - vma->vm_start;
    if (map_size > SHM_SIZE) {
        printk(KA_KERN_ERR "[lqdcmi]Invalid mapping size: %lu > %d\n",
               map_size, SHM_SIZE);
        return -EINVAL;
    }

    // 可选：确保映射不跨越页边界
    if (!PAGE_ALIGNED(vma->vm_start) || !PAGE_ALIGNED(vma->vm_end)) {
        printk(KA_KERN_ERR "[lqdcmi]Unaligned mapping address\n");
        return -EINVAL;
    }

    ka_task_mutex_lock(&shared_mem_mutex);

    // ... 原有分配逻辑 ...

    pfn = ka_mm_virt_to_phys(shm->mem) >> KA_MM_PAGE_SHIFT;

    // 使用验证后的 map_size（或 shm->size，取较小值）
    ret = ka_mm_remap_pfn_range(vma, vma->vm_start, pfn, 
                                 min(map_size, shm->size), 
                                 vma->vm_page_prot);

out:
    ka_task_mutex_unlock(&shared_mem_mutex);
    return ret;
}
```

### 加固措施

1. **设备文件权限控制**
   ```bash
   # 限制设备访问权限为 root 专用
   chmod 0600 /dev/lqdcmi
   chown root:root /dev/lqdcmi
   ```

2. **内核命令行加固**
   ```bash
   # 启用 SMEP/SMAP
   # 在 GRUB 配置中添加（通常默认启用）
   GRUB_CMDLINE_LINUX="nosmep=0 nosmap=0"
   ```

3. **SELinux/AppArmor 策略**
   ```bash
   # 限制只有特定进程可以访问设备
   # 示例 SELinux 策略
   allow lqdcmi_domain lqdcmi_device_t:chr_file { open read mmap };
   ```

### 验证方法

**测试代码**：
```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#define SHM_SIZE (256 + 7 * 1024 * 256)  // 1835264

int main() {
    int fd = open("/dev/lqdcmi", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // 测试 1: 越界映射（应该失败）
    void *map1 = mmap(NULL, SHM_SIZE * 2, PROT_READ, MAP_SHARED, fd, 0);
    if (map1 != MAP_FAILED) {
        printf("VULN: Oversized mapping allowed!\n");
        munmap(map1, SHM_SIZE * 2);
    } else {
        printf("OK: Oversized mapping rejected\n");
    }

    // 测试 2: 可写映射（应该失败）
    void *map2 = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map2 != MAP_FAILED) {
        printf("VULN: Writeable mapping allowed!\n");
        munmap(map2, SHM_SIZE);
    } else {
        printf("OK: Writeable mapping rejected\n");
    }

    // 测试 3: 可执行映射（应该失败）
    void *map3 = mmap(NULL, SHM_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    if (map3 != MAP_FAILED) {
        printf("VULN: Executable mapping allowed!\n");
        munmap(map3, SHM_SIZE);
    } else {
        printf("OK: Executable mapping rejected\n");
    }

    // 测试 4: 合法映射（应该成功）
    void *map4 = mmap(NULL, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    if (map4 != MAP_FAILED) {
        printf("OK: Legal mapping allowed\n");
        munmap(map4, SHM_SIZE);
    } else {
        printf("ERROR: Legal mapping rejected\n");
    }

    close(fd);
    return 0;
}
```

## 相关漏洞参考

- **CVE-2019-19523**: Linux kernel memory mapping vulnerability
- **CVE-2020-10758**: Incorrect bounds check in memory mapping
- **CWE-119**: Improper Restriction of Operations within the Bounds of a Memory Buffer
- **CWE-787**: Out-of-bounds Write
- **CWE-125**: Out-of-bounds Read

## 时间线

- **发现日期**: 2026-04-22
- **分析完成**: 2026-04-22
- **报告生成**: 2026-04-22

## 附录：关键代码位置

| 文件 | 行号 | 描述 |
|------|------|------|
| `pci-dev.c` | 210-267 | 漏洞函数 `shared_memory_mmap` |
| `pci-dev.c` | 262 | 漏洞代码行 `ka_mm_remap_pfn_range` |
| `pci-dev.c` | 461 | 函数注册点 `.mmap = shared_memory_mmap` |
| `ioctl_comm_def.h` | 12 | `SHM_SIZE` 定义 (1835264 字节) |

## 联系信息

如需更多信息或协助修复，请联系驱动开发团队。
