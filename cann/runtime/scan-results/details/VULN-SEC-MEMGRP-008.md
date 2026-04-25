# VULN-SEC-MEMGRP-008 - 内存组进程添加授权缺失漏洞深度利用分析

> **漏洞ID**: VULN-SEC-MEMGRP-008  
> **类型**: Missing Authorization  
> **CWE**: CWE-862 (缺失授权)  
> **严重性**: High  
> **置信度**: 85%  
> **文件**: src/runtime/driver/npu_driver_queue.cc  
> **行号**: 429-450  
> **函数**: MemGrpAddProc

---

## 1. 漏洞原理和根因分析

### 1.1 漏洞根因

该漏洞的核心问题是**内存组添加进程操作缺乏授权检查**，任意进程可以将其他进程添加到内存组，导致权限边界突破。

**关键代码片段**：
```cpp
// npu_driver_queue.cc: 429-450
rtError_t NpuDriver::MemGrpAddProc(const char_t * const name, const int32_t pid,
                                   const rtMemGrpShareAttr_t * const attr)
{
    RT_LOG(RT_LOG_INFO, "add process for mem group, deviceId=0.");

    // 仅检查 API 存在性，无权限验证！
    COND_RETURN_WARN(&halGrpAddProc == nullptr, RT_ERROR_FEATURE_NOT_SUPPORT,
        "[drv api] halGrpAddProc does not exist.");
    
    // 直接构造属性并调用驱动，无任何授权检查
    GroupShareAttr drvAttr = {};
    drvAttr.admin = attr->admin;   // 攻击者可设置 admin=true!
    drvAttr.read = attr->read;
    drvAttr.write = attr->write;
    drvAttr.alloc = attr->alloc;
    
    // 直接调用驱动层，添加任意 PID
    const drvError_t drvRet = static_cast<drvError_t>(halGrpAddProc(name, pid, drvAttr));
    COND_RETURN_WARN(drvRet == DRV_ERROR_REPEATED_INIT, RT_GET_DRV_ERRCODE(drvRet), "repeated init");
    
    if (drvRet != DRV_ERROR_NONE) {
        DRV_ERROR_PROCESS(drvRet, "Call driver api halGrpAddProc failed, drvRetCode=%d, drvDevId=0.",
            static_cast<int32_t>(drvRet));
        return RT_GET_DRV_ERRCODE(drvRet);
    }

    return RT_ERROR_NONE;
}
```

### 1.2 内存组概念

**内存组 (Memory Group) 是什么？**

内存组是 CANN Runtime 中的共享内存池机制，允许多个进程共享 NPU 内存资源：

```
┌─────────────────────────────────────────────────────────┐
│                    Memory Group                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │         共享 NPU 内存池                            │  │
│  │  - 高性能内存分配                                  │  │
│  │  - 跨进程共享                                      │  │
│  │  - HBM/DDR 内存资源                               │  │
│  └───────────────────────────────────────────────────┘  │
│                                                          │
│  进程成员:                                               │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐            │
│  │ PID 1000  │ │ PID 2000  │ │ PID 3000  │            │
│  │ admin=y   │ │ read=y    │ │ write=y   │            │
│  │ write=y   │ │ write=n   │ │ alloc=n   │            │
│  └───────────┘ ┌───────────┐ ┌───────────┐            │
│                │ PID 9999  │ │ PID XXXX  │ ← 漏洞允许  │
│                │ 攻击进程  │ │ 任意进程  │   添加任意  │
│                └───────────┘ └───────────┘            │
└─────────────────────────────────────────────────────────┘
```

### 1.3 缺失的安全检查

**漏洞代码未检查**：

1. **调用者权限**: 未验证调用者是否有权限操作该内存组
2. **PID 合法性**: 未验证目标 PID 是否属于合法进程
3. **属性合理性**: 未验证 `attr` 参数是否超出调用者权限范围
4. **组所有权**: 未验证调用者是否为内存组的管理员

---

## 2. 利用条件和前提条件

### 2.1 前提条件

| 条件 | 状态 | 说明 |
|------|------|------|
| API 可访问性 | ✓ | `MemGrpAddProc` 为公开 API |
| 输入可控性 | ✓ | `name`, `pid`, `attr` 全部由调用者控制 |
| 内存组存在 | 需探测 | 知道有效的内存组名称 |
| PID 存在 | 需探测 | 目标 PID 应存在（否则驱动可能失败） |

### 2.2 攻击者能力假设

- 攻击者进程拥有 CANN Runtime API 调用权限
- 攻击者可探测系统中存在的内存组名称
- 攻击者可枚举或猜测关键进程 PID

### 2.3 利用难度

**Low** - API 参数完全可控，无认证机制

---

## 3. 具体利用步骤和攻击路径

### 3.1 攻击场景 A: 高权限进程注入

**目标**: 将攻击者进程注入到高价值内存组，获取 admin 权限

```
步骤 1: 探测系统中的内存组名称
        - 通过 ps/proc 扫描
        - 通过驱动日志分析
        - 通过侧信道信息推断

步骤 2: 确定目标内存组 (如 "ai_training_group")

步骤 3: 调用 MemGrpAddProc
        - name = "ai_training_group"
        - pid = 攻击者自身 PID (getpid())
        - attr.admin = true (设置管理员权限!)
        - attr.write = true
        - attr.alloc = true

步骤 4: 驱动层无授权检查，添加成功

步骤 5: 攻击者获得内存组的完全控制权
        - 可分配/释放内存
        - 可读取/修改共享数据
        - 可踢出其他成员
```

**PoC 概念**：
```cpp
// 攻击者进程
rtMemGrpShareAttr_t maliciousAttr;
maliciousAttr.admin = 1;   // 请求管理员权限！
maliciousAttr.read = 1;
maliciousAttr.write = 1;
maliciousAttr.alloc = 1;   // 请求分配权限！

// 探测到的目标内存组名称
const char* targetGroup = "npu_hbm_pool_0";

// 攻击者 PID
int32_t attackerPid = getpid();

// 添加攻击者到内存组
rtError_t ret = MemGrpAddProc(targetGroup, attackerPid, &maliciousAttr);

if (ret == RT_ERROR_NONE) {
    // 成功！攻击者现在拥有内存组的 admin 权限
    // 可以：
    // 1. 读取其他进程的 NPU 内存数据
    // 2. 篡改共享内存内容
    // 3. 踢出合法进程
    // 4. 破坏内存分配逻辑
}
```

### 3.2 攻击场景 B: 合法进程权限篡改

**目标**: 修改合法进程的权限等级，造成权限混乱

```
步骤 1: 探测合法进程 PID (如推理服务 PID=1000)
步骤 2: 调用 MemGrpAddProc
        - name = "inference_group"
        - pid = 1000 (受害进程)
        - attr.admin = 0  // 剥夺管理员权限
        - attr.write = 0  // 剥夺写入权限

步骤 3: 合法进程权限被篡改
步骤 4: 推理服务无法正常工作
```

### 3.3 攻击场景 C: 内存池破坏攻击

**目标**: 添加大量恶意进程，耗尽内存组资源

```
步骤 1: 攻击者创建大量子进程
步骤 2: 逐个调用 MemGrpAddProc 将子进程加入内存组
步骤 3: 设置每个进程请求大量内存分配权限
步骤 4: 内存组资源耗尽
步骤 5: 合法进程无法分配内存
```

### 3.4 攻击场景 D: 内存数据窃取

**目标**: 注入进程读取其他进程的敏感数据

```
步骤 1: 将攻击者进程注入到数据加载内存组
步骤 2: 设置 read=true 权限
步骤 3: 读取内存组中的共享内存区域
步骤 4: 窃取训练数据、推理结果、模型参数
```

---

## 4. 影响范围和危害评估

### 4.1 直接影响

| 影响类型 | 危害等级 | 说明 |
|----------|----------|------|
| 权限提升 | **Critical** | 可获得内存组 admin 权限 |
| 数据泄露 | **Critical** | 可读取共享内存中的敏感数据 |
| 数据篡改 | **Critical** | 可修改其他进程的内存数据 |
| 服务中断 | **High** | 可踢出合法进程或耗尽资源 |
| 权限篡改 | **High** | 可修改其他进程的权限等级 |

### 4.2 业务影响

1. **AI 模型窃取**: 共享内存中的模型参数可被读取
2. **训练数据泄露**: 数据加载内存组中的训练数据可被窃取
3. **推理结果窃取**: 推理队列的输出数据可被截获
4. **计算服务破坏**: 内存组被破坏导致 AI 服务中断
5. **资源争夺**: 恶意进程占用大量 NPU 内存资源

### 4.3 攻击链扩展

成功利用此漏洞后，攻击者可进一步：

```
MemGrpAddProc 漏洞利用
    ↓
获得内存组 admin 权限
    ↓
读取/修改共享 NPU 内存
    ↓
┌─────────────────────────────────────────────┐
│ 后续攻击:                                    │
│ - 窃取 AI 模型权重                           │
│ - 篡改推理中间结果                           │
│ - 注入恶意计算数据                           │
│ - 破坏训练过程                               │
│ - DoS 内存分配                               │
└─────────────────────────────────────────────┘
```

---

## 5. 修复建议和缓解措施

### 5.1 完整修复方案

**方案 A: API 层授权检查**

```cpp
rtError_t NpuDriver::MemGrpAddProc(const char_t * const name, const int32_t pid,
                                   const rtMemGrpShareAttr_t * const attr)
{
    RT_LOG(RT_LOG_INFO, "add process for mem group, deviceId=0.");

    // === 新增安全检查 ===
    
    // 1. 获取调用者 PID
    int32_t callerPid = getpid();
    
    // 2. 检查调用者是否有权限操作该内存组
    rtMemGrpQueryInput_t queryInput;
    rtMemGrpQueryOutput_t queryOutput;
    
    queryInput.cmd = GRP_QUERY_GROUPS_OF_PROCESS;
    queryInput.grpQueryByProc.pid = callerPid;
    
    rtError_t ret = MemGrpQuery(&queryInput, &queryOutput);
    if (ret != RT_ERROR_NONE) {
        RT_LOG(RT_LOG_ERROR, "Caller %d has no access to group '%s'", callerPid, name);
        return RT_ERROR_PERMISSION_DENIED;
    }
    
    // 3. 检查调用者是否有 admin 权限（只有 admin 才能添加成员）
    bool hasAdminPerm = false;
    for (size_t i = 0; i < queryOutput.resultNum; i++) {
        if (strcmp(queryOutput.groupsOfProc[i].groupName, name) == 0) {
            if (queryOutput.groupsOfProc[i].attr.admin == 1) {
                hasAdminPerm = true;
                break;
            }
        }
    }
    
    if (!hasAdminPerm) {
        RT_LOG(RT_LOG_ERROR, "Caller %d lacks admin permission for group '%s'", callerPid, name);
        return RT_ERROR_PERMISSION_DENIED;
    }
    
    // 4. 限制授予的权限不能超过调用者的权限等级
    // (调用者不能授予比自己更高等级的权限)
    // ...
    
    // === 原有逻辑 ===
    COND_RETURN_WARN(&halGrpAddProc == nullptr, RT_ERROR_FEATURE_NOT_SUPPORT,
        "[drv api] halGrpAddProc does not exist.");
    
    GroupShareAttr drvAttr = {};
    drvAttr.admin = attr->admin;
    drvAttr.read = attr->read;
    drvAttr.write = attr->write;
    drvAttr.alloc = attr->alloc;
    
    const drvError_t drvRet = static_cast<drvError_t>(halGrpAddProc(name, pid, drvAttr));
    // ...
}
```

**方案 B: 驱动层授权检查**

在驱动层 (`halGrpAddProc`) 实现内核级授权：

```c
// 驱动层建议实现
drvError_t halGrpAddProc(const char* name, int32_t pid, GroupShareAttr attr)
{
    // 1. 验证调用者进程权限
    int32_t callerPid = current->pid;  // 内核获取
    
    // 2. 检查内存组元数据
    MemGroup* group = FindMemGroup(name);
    if (group == NULL) {
        return DRV_ERROR_NOT_FOUND;
    }
    
    // 3. 验证调用者是 group 的管理员
    ProcessMember* caller = FindMember(group, callerPid);
    if (caller == NULL || caller->attr.admin == 0) {
        LogSecurityEvent("Unauthorized MemGrpAddProc", callerPid, name);
        return DRV_ERROR_PERMISSION_DENIED;
    }
    
    // 4. 权限降级：不允许授予超过调用者等级的权限
    if (attr.admin > caller->attr.admin) {
        attr.admin = caller->attr.admin;
    }
    // 类似处理其他权限...
    
    // 5. 执行添加
    return DoAddProc(group, pid, attr);
}
```

### 5.2 权限模型设计

**建议的权限模型**：

```
Memory Group 权限层次:

Level 0: Creator/Admin
    - 可添加/移除成员
    - 可设置成员权限
    - 可分配/释放内存
    - 可销毁内存组

Level 1: Manager
    - 可添加成员（但不能设置 admin）
    - 可分配内存
    - 可读写共享内存

Level 2: Contributor
    - 可分配内存
    - 可读写共享内存

Level 3: Reader
    - 只可读取共享内存

权限授予规则:
- 调用者只能授予 ≤ 自己权限等级的权限
- 只有 Admin 可以授予 Admin 权限
- Creator (第一个成员) 自动获得 Admin 权限
```

### 5.3 缓解措施

**短期缓解**：

1. **API 文档约束**: 明确声明该 API 仅限管理员调用
2. **日志审计**: 记录所有 `MemGrpAddProc` 调用
3. **进程白名单**: 在驱动层限制可添加的 PID 范围
4. **权限上限**: 禁止授予 `admin=1`（除非调用者是 creator）

### 5.4 系统加固

1. **内存组命名隔离**: 使用 namespace 或用户组隔离
2. **PID 验证**: 验证目标 PID 属于同一用户/组
3. **SELinux/AppArmor**: 使用 LSM 模块控制内存组访问
4. **Capability 检查**: 要求 CAP_SYS_ADMIN 才能 admin 操作

---

## 6. 总结

该漏洞是一个**极其严重的授权缺失问题**，其危害程度甚至超过 VULN-SEC-QUEUE-002：

| 对比项 | VULN-SEC-QUEUE-002 | VULN-SEC-MEMGRP-008 |
|--------|--------------------|---------------------|
| 攻击目标 | 队列绑定 | 内存组成员添加 |
| 数据访问 | 队列数据流 | 共享内存直接访问 |
| 权限提升 | 队列访问权限 | 内存组 admin 权限 |
| 影响范围 | 队列调度系统 | NPU 内存系统 |
| 数据篡改 | 队列消息 | 内存原始数据 |
| 危害等级 | High | **Critical** |

**实际利用难度**: Low - API 参数完全可控，无认证机制

**建议优先级**: **Critical** - 必须立即修复

---

## 7. 参考资料

- CWE-862: Missing Authorization
- CWE-269: Improper Privilege Management
- NIST SP 800-53: AC-6 Least Privilege
- OWASP: Broken Access Control - Privilege Escalation

---

*报告生成时间: 2026-04-25*  
*分析工具: CANN Vulnerability Scanner*