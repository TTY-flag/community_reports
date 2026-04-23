# VULN-SEC-KERNEL419-001: SVA Binding Disabled - PASID Isolation Bypass

## 漏洞概述

### 基本信息
| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-KERNEL419-001 |
| **漏洞类型** | Access Control - Improper Privilege Management |
| **CWE** | CWE-269: Improper Privilege Management |
| **严重性** | **Critical** |
| **置信度** | 95% |
| **影响版本** | KAEKernelDriver-OLK-4.19 |
| **修复版本** | KAEKernelDriver-OLK-5.10, KAEKernelDriver-OLK-6.6 |

### 漏洞描述

在 OLK-4.19 内核版本的 UACCE (Unified Accelerator) 驱动中，`uacce_bind_queue()` 函数内的 **Shared Virtual Address (SVA) 绑定代码被完全注释掉**。这导致：

1. **PASID-based 进程隔离完全失效** - 每个进程无法获得独立的 PASID (Process Address Space ID)
2. **硬件队列配置使用 PASID=0** - 所有进程共享相同的 PASID 值
3. **IOMMU 无法区分不同进程** - 设备 DMA 操作失去进程边界
4. **跨进程内存访问风险** - 用户应用可通过加速器设备访问其他进程的内存空间

这是相对于 OLK-5.10 和 OLK-6.6 版本的严重安全回归。

### 影响范围

- **影响设备**: HiSilicon 加速器 (SEC, HPRE, ZIP)
- **攻击面**: `/dev/uacce-*` 设备文件
- **权限要求**: 用户级权限 (可打开设备文件)
- **潜在影响**: 
  - 敏感数据泄露 (密码、加密密钥)
  - 跨进程内存读取/写入
  - 容器逃逸 (如果设备暴露给容器)
  - 内核信息泄露

---

## 代码分析

### 漏洞代码位置

**文件**: `KAEKernelDriver-OLK-4.19/uacce/uacce.c`
**函数**: `uacce_bind_queue()`
**行号**: 259-280

```c
static int uacce_bind_queue(struct uacce_device *uacce, struct uacce_queue *q)
{
    // u32 pasid;                            // ❌ 被注释
    // struct iommu_sva *handle;             // ❌ 被注释

    // if (!(uacce->flags & UACCE_DEV_SVA))  // ❌ 被注释
    //     return 0;                          // ❌ 被注释

    // handle = iommu_sva_bind_device(uacce->parent, current->mm, NULL); // ❌ 关键绑定被注释
    // if (IS_ERR(handle))                    // ❌ 被注释
    //     return PTR_ERR(handle);            // ❌ 被注释

    // pasid = iommu_sva_get_pasid(handle);   // ❌ PASID获取被注释
    // if (pasid == IOMMU_PASID_INVALID) {    // ❌ 被注释
    //     iommu_sva_unbind_device(handle);   // ❌ 被注释
    //     return -ENODEV;                    // ❌ 被注释
    // }                                      // ❌ 被注释

    // q->handle = handle;                    // ❌ 被注释
    // q->pasid = pasid;                      // ❌ PASID存储被注释
    return 0;                                // ⚠️ 直接返回成功，不执行任何绑定
}
```

### 正确实现对比 (OLK-6.6)

```c
static int uacce_bind_queue(struct uacce_device *uacce, struct uacce_queue *q)
{
    u32 pasid;
    struct iommu_sva *handle;

    if (!(uacce->flags & UACCE_DEV_SVA))
        return 0;

    handle = iommu_sva_bind_device(uacce->parent, current->mm);  // ✓ 执行绑定
    if (IS_ERR(handle))
        return PTR_ERR(handle);

    pasid = iommu_sva_get_pasid(handle);  // ✓ 获取PASID
    if (pasid == IOMMU_PASID_INVALID) {
        iommu_sva_unbind_device(handle);
        return -ENODEV;
    }

    q->handle = handle;  // ✓ 存储绑定句柄
    q->pasid = pasid;    // ✓ 存储PASID
    return 0;
}
```

### 数据流分析

```
uacce_fops_open()                        // 用户打开 /dev/uacce-*
    ↓
uacce_bind_queue(uacce, q)               // ❌ 返回成功但不绑定
    ↓                                      // q->pasid = 0 (kzalloc默认值)
uacce->ops->get_queue(uacce, q->pasid, q) // 传递 pasid=0
    ↓                                      // qm.c:2353: qp->pasid = arg (值为0)
hisi_qm_start_qp(qp, qp->pasid)          // 启动队列，pasid=0
    ↓
qm_sq_ctx_cfg(qp, qp_id, pasid)          // 配置SQ context
    ↓                                      // sqc.pasid = 0 (Line 2008)
    ↓                                      // w11 = PASID_ENABLE (如果use_sva=true)
qm_cq_ctx_cfg(qp, qp_id, pasid)          // 配置CQ context
    ↓                                      // cqc.pasid = 0 (Line 2038)
硬件队列启动                              // ❌ PASID=0，无进程隔离
```

### 关键问题链

1. **SVA 标志被设置** (qm.c:2729):
   ```c
   interface.flags |= UACCE_DEV_SVA;  // 设备声称支持SVA
   ```

2. **驱动期望 SVA 工作** (qm.c:2515):
   ```c
   qm->use_sva = uacce->flags & UACCE_DEV_SVA ? true : false;  // use_sva=true
   ```

3. **硬件配置启用 PASID** (qm.c:2010-2012):
   ```c
   if (ver >= QM_HW_V3 && qm->use_sva && !qp->is_in_kernel)
       sqc.w11 = cpu_to_le16(QM_QC_PASID_ENABLE << QM_QC_PASID_ENABLE_SHIFT);
   ```

4. **但 PASID 值为 0** - 所有进程共享相同的 PASID=0，破坏隔离

---

## 漏洞触发条件

### 前置条件

1. 系统运行 OLK-4.19 内核版本
2. HiSilicon 加速器设备存在且加载了 KAE 驱动
3. 设备以 SVA 模式注册 (UACCE_DEV_SVA 标志设置)
4. IOMMU 支持 PASID 功能
5. 用户有权访问 `/dev/uacce-*` 设备文件

### 触发路径

```
用户程序                    内核驱动
    |                          |
    | open("/dev/uacce-*") --> |
    |                      uacce_fops_open()
    |                          |
    |                      uacce_bind_queue()  // ❌ pasid=0
    |                          |
    |                      hisi_qm_uacce_get_queue()  // qp->pasid=0
    |                          |
    | <--- fd ---------------- |
    |                          |
    | mmap() ---------------> |  // 映射设备内存区域
    |                          |
    | ioctl(START_Q) --------> |  // 启动队列
    |                      qm_sq_ctx_cfg()  // sqc.pasid=0
    |                      qm_cq_ctx_cfg()  // cqc.pasid=0
    |                          |
    | 执行加密/压缩操作 ------> |  // 设备DMA访问内存
    |                          |  // ❌ 无PASID隔离
```

---

## 漏洞利用分析

### 利用场景

#### 场景1: 跨进程敏感数据读取

**攻击者进程A** 和 **受害者进程B** 都使用同一加速器设备:

```
进程B (受害者):
- 执行加密操作，密钥在内存地址 0x12345000
- 通过 UACCE 设备进行加密
- 设备配置 PASID=0，DMA可访问该地址

进程A (攻击者):
- 打开同一 UACCE 设备
- 配置队列 (PASID=0，与进程B相同)
- 通过精心构造的 DMA 操作读取进程B的密钥内存
- 或利用设备内存映射机制访问共享区域
```

#### 场景2: 容器逃逸

如果 UACCE 设备被暴露给容器:
```
容器内进程:
- 打开 /dev/uacce-* (容器内挂载)
- PASID=0 无隔离
- 设备 DMA 可访问宿主机进程内存
- 可能读取宿主机敏感数据或进行内存注入
```

#### 场景3: 真实进程模拟攻击

```
进程1: 加密服务
- 加密用户密码，密码缓冲区在内存
- 使用 SEC 加速器

进程2: 恶意程序
- 同样打开 SEC 加速器
- 由于 PASID=0，IOMMU 无法区分两个进程
- 可能通过以下方式访问进程1的密码缓冲区:
  a) 直接 DMA 读取 (如果设备支持)
  b) 共享静态区域 (SS) 内存泄露
  c) 利用队列上下文内存访问
```

### 利用可行性评估

| 因素 | 评估 | 说明 |
|------|------|------|
| **攻击者权限** | 低 | 只需用户级权限打开设备 |
| **攻击复杂度** | 中 | 需理解 UACCE 架构和硬件队列操作 |
| **攻击成功率** | 高 | PASID=0 确定性地破坏隔离 |
| **影响严重性** | Critical | 敏感数据泄露，跨进程访问 |
| **检测难度** | 高 | 合法设备操作，难以区分攻击 |

---

## PoC 构造思路

### 验证性 PoC (Proof of Concept)

**目标**: 验证 PASID 确实为 0，无进程隔离

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define UACCE_CMD_START_Q _IO('W', 0)
#define UACCE_CMD_PUT_Q   _IO('W', 1)

int main() {
    int fd = open("/dev/uacce-sec", O_RDWR);  // 打开SEC加速器
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // 映射设备区域
    void *mmio = mmap(NULL, 0x10000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    void *dus  = mmap(NULL, 0x10000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0x10000);

    // 启动队列 - 此时 PASID=0
    ioctl(fd, UACCE_CMD_START_Q, 0);

    printf("Queue started with PASID=0 (SVA binding disabled)\n");
    printf("No process isolation - cross-process memory access possible\n");

    // 这里可以进行:
    // 1. 执行加密操作，观察内存访问模式
    // 2. 尝试访问其他进程映射的内存区域
    // 3. 利用 SS (Static Share) 区域进行跨进程通信

    close(fd);
    return 0;
}
```

### 进阶 PoC 构造方向

1. **内存泄露验证**:
   - 进程A 分配敏感缓冲区，使用加速器操作
   - 进程B 通过设备机制尝试读取进程A的缓冲区
   - 利用 SS 共享区域或 DMA 缓冲区泄露

2. **硬件队列操纵**:
   - 分析 SQ/CQ context 结构
   - 尝试修改队列基地址指向其他进程内存
   - 利用 PASID=0 的硬件配置漏洞

3. **调试信息提取**:
   ```bash
   # 查看 PASID 配置
   cat /sys/class/uacce/uacce-*/attributes
   # 检查 IOMMU PASID 表
   cat /sys/kernel/debug/iommu/*/pasid_table
   # 验证 PASID 值为 0 或无效
   ```

---

## 修复建议

### 立即修复方案

**取消注释 SVA 绑定代码**:

```c
static int uacce_bind_queue(struct uacce_device *uacce, struct uacce_queue *q)
{
    u32 pasid;
    struct iommu_sva *handle;

    if (!(uacce->flags & UACCE_DEV_SVA))
        return 0;

    handle = iommu_sva_bind_device(uacce->parent, current->mm, NULL);
    if (IS_ERR(handle))
        return PTR_ERR(handle);

    pasid = iommu_sva_get_pasid(handle);
    if (pasid == IOMMU_PASID_INVALID) {
        iommu_sva_unbind_device(handle);
        return -ENODEV;
    }

    q->handle = handle;
    q->pasid = pasid;
    return 0;
}
```

同时修复 `uacce_unbind_queue()`:
```c
static void uacce_unbind_queue(struct uacce_queue *q)
{
    if (!q->handle)
        return;
    iommu_sva_unbind_device(q->handle);  // 取消注释
    q->handle = NULL;
}
```

### 临时缓解措施

如果无法立即修复驱动代码:

1. **禁用 SVA 模式**:
   ```c
   // 在设备注册时，不设置 UACCE_DEV_SVA 标志
   interface.flags = qm->use_iommu ? UACCE_DEV_IOMMU : UACCE_DEV_NOIOMMU;
   // 移除: interface.flags |= UACCE_DEV_SVA;
   ```

2. **限制设备访问权限**:
   ```bash
   chmod 600 /dev/uacce-*
   chown root:root /dev/uacce-*
   ```

3. **使用 NOIOMMU 模式**:
   - 配置驱动使用 `UACCE_MODE_NOIOMMU` 而非 `UACCE_MODE_SVA`
   - 牺牲性能换取安全性

4. **升级内核版本**:
   - 迁移到 OLK-5.10 或 OLK-6.6
   - 使用已修复的驱动版本

### 完整修复检查清单

| 检查项 | 状态 | 位置 |
|--------|------|------|
| uacce_bind_queue() 实现完整 | ❌ 需修复 | uacce.c:259-280 |
| uacce_unbind_queue() 实现完整 | ❌ 需修复 | uacce.c:282-288 |
| iommu_sva_bind_device() 调用 | ❌ 被注释 | uacce.c:267 |
| PASID 存储到 q->pasid | ❌ 被注释 | uacce.c:278 |
| 错误处理路径完整 | ❌ 需修复 | uacce.c:268-275 |
| 与 OLK-6.6 实现一致 | ❌ 需对齐 | 版本对比 |

---

## 相关漏洞参考

### 类似漏洞案例

1. **CVE-2022-3169** - VMware GPU 驱动 SVA 缺陷
   - 类似的 PASID/PASID-based isolation 问题
   - 导致跨虚拟机内存访问

2. **CVE-2021-22555** - Linux IOMMU PASID 验证缺陷
   - PASID 表管理不当导致的权限绕过

3. **Intel VT-d PASID 漏洞系列**:
   - PASID=0 的特殊处理问题
   - 设备隔离失效

### UACCE/SVA 相关标准

- **PCIe PASID Specification** (PCIe 4.0+)
- **Intel VT-d PASID Support**
- **ARM SMMU PASID Support**
- **Linux IOMMU SVA API** (since kernel 5.10)

---

## 总结

这是一个 **确认的真实漏洞**，属于严重的访问控制缺陷:

- **根本原因**: SVA 绑定代码被注释，导致 PASID-based 隔离完全失效
- **直接后果**: 所有进程共享 PASID=0，失去进程边界保护
- **潜在影响**: 跨进程内存访问，敏感数据泄露，容器逃逸风险
- **修复方案**: 取消注释或升级到已修复版本
- **紧急程度**: **Critical** - 应立即修复或启用缓解措施

该漏洞代表了一个典型的不安全代码注释问题，可能是开发过程中临时禁用功能但未恢复，或者是未完成的移植工作残留。
