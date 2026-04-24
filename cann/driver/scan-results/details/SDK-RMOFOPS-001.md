# SDK-RMOFOPS-001：RMO模块缺失访问控制漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | SDK-RMOFOPS-001 |
| **类型** | 缺失访问控制 (Missing Access Control) |
| **CWE** | CWE-287: Improper Authentication |
| **严重性** | High |
| **置信度** | 75% |
| **模块** | sdk_driver (dpa/rmo) |
| **文件** | src/sdk_driver/dpa/rmo/rmo_fops.c |
| **行号** | 64-80 |
| **函数** | rmo_ioctl |

### 描述

rmo_ioctl函数缺乏访问控制——仅验证命令号范围和arg!=NULL，缺失能力检查(CAP_SYS_ADMIN/CAP_SYS_RAWIO)用于进程管理操作。任何非特权用户可直接通过ioctl触发进程管理操作。

## 攻击路径分析

### 数据流图

```
┌─────────────────┐                    ┌──────────────────────┐
│ 用户进程        │                    │ rmo_ioctl            │
│ (unprivileged)  │ ─── ioctl() ─────► │   @ line 64          │
└─────────────────┘                    └──────────┬───────────┘
                                                   │
       验证缺失:                                    │
       - 无 CAP_SYS_ADMIN                          │ 仅验证:
       - 无 CAP_SYS_RAWIO                          │ - arg != 0
       - 无进程所有权验证                            │ - cmd范围
                                                   ▼
                                        ┌──────────────────────┐
                                        │ rmo_ioctl_handler[]  │
                                        │   @ line 79          │
                                        └──────────┬───────────┘
                                                   │
                                                   │ 进程管理操作:
                                                   │ - 进程创建
                                                   │ - 进程销毁
                                                   │ - 内存重映射
                                                   │ - 资源分配
                                                   ▼
┌─────────────────┐                    ┌──────────────────────┐
│ 受影响进程      │ ◄───────────────── │ 未授权操作执行        │
│ - 被终止        │                    └──────────────────────┘
│ - 内存被映射    │
│ - 资源被分配    │
└────────┬────────┘
         │
         │ 攻击效果:
         │ - 干扰其他进程
         │ - 内存映射冲突
         │ - 资源耗尽
         ▼
┌─────────────────┐
│ 进程崩溃        │
│ 服务中断        │
│ 资源耗尽        │
└─────────────────┘
```

### 关键代码分析

```c
// rmo_fops.c: line 64-80
static long rmo_ioctl(ka_file_t *file, u32 cmd, unsigned long arg)
{
    // 问题: 仅检查arg非空，不检查调用者权限
    if (arg == 0) {
        return -EINVAL;
    }
    
    // 问题: 仅检查命令号范围，不验证特权
    if (_KA_IOC_NR(cmd) >= RMO_MAX_CMD) {
        rmo_err("The command is invalid. (cmd=%u)\n", _KA_IOC_NR(cmd));
        return -EINVAL;
    }

    // 缺失验证:
    // - capable(CAP_SYS_ADMIN)
    // - capable(CAP_SYS_RAWIO)
    // - 进程与设备绑定关系
    
    // 直接调用处理函数
    return rmo_ioctl_handler[_KA_IOC_NR(cmd)](cmd, arg);  // line 79
}
```

### RMO功能分析

RMO (Remote Memory Operations) 提供的功能:
- 远程进程内存操作
- 跨进程内存映射
- 进程间内存共享管理

这些操作应当需要特权才能执行。

## 利用条件

### 触发条件

| 条件 | 描述 |
|------|------|
| **攻击者位置** | 本地用户进程 (User Space) |
| **信任边界** | 跨越 User Space Interface 边界 |
| **前置条件** | 设备文件访问权限 (/dev/rmo) |
| **触发方式** | ioctl 系统调用 |

### 攻击者能力要求

- **能力等级**: Unprivileged Local
- **所需权限**: 设备文件访问权限
- **技术要求**: 
  - 了解 RMO ioctl 命令格式

### 利用步骤

```c
// 1. 打开RMO设备（无特权要求）
fd = open("/dev/rmo", O_RDWR);

// 2. 执行进程管理操作
struct rmo_ioctl_param arg;
arg.target_pid = victim_pid;
arg.operation = RMO_OP_REMAP;

ioctl(fd, RMO_CMD_REMAP, &arg);

// 3. 攻击效果:
// - 干扰目标进程的内存映射
// - 执行未授权的进程管理操作
```

## 影响评估

### 直接影响

| 影响类型 | 严重性 | 描述 |
|----------|--------|------|
| **未授权进程操作** | High | 任何用户可执行进程管理 |
| **进程干扰** | High | 干扰其他进程正常运行 |
| **资源耗尽** | Medium | 恶意进程可耗尽资源 |

### CVSS 评估

- **攻击向量**: Local
- **攻击复杂度**: Low
- **权限要求**: Low
- **用户交互**: None
- **影响范围**: Changed
- **CVSS 评分**: 6.5 (Medium-High)

## 修复建议

### 立即修复方案

```c
// 1. 添加能力检查
static long rmo_ioctl(ka_file_t *file, u32 cmd, unsigned long arg)
{
    // 新增: 权限检查
    if (!capable(CAP_SYS_ADMIN) && !capable(CAP_SYS_RAWIO)) {
        rmo_err("rmo_ioctl requires elevated privileges\n");
        return -EPERM;
    }
    
    if (arg == 0) {
        return -EINVAL;
    }
    
    if (_KA_IOC_NR(cmd) >= RMO_MAX_CMD) {
        return -EINVAL;
    }
    
    return rmo_ioctl_handler[_KA_IOC_NR(cmd)](cmd, arg);
}
```

### 配置加固

```bash
# 限制设备文件权限
chmod 0600 /dev/rmo
chown root:root /dev/rmo
```

## 验证状态

- **源代码审查**: 已确认 rmo_ioctl 无 capable() 检查
- **置信度评分**: 75/100