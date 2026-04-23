# SVM-MEM-SHARE-001: 共享内存访问控制缺失漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | SVM-MEM-SHARE-001 |
| **类型** | 共享内存访问控制缺失 (Memory Sharing Access Control) |
| **CWE** | CWE-662: Improper Synchronization of Shared Data |
| **严重性** | High |
| **置信度** | 92% |
| **模块** | svm_memory |
| **文件** | src/sdk_driver/svm/v2/master/comm/svm_master_mem_share.c |
| **行号** | 623-651 |
| **函数** | devmm_share_agent_blk_get |

### 描述

SVM共享内存块的访问控制缺失。devmm_share_agent_blk_get函数仅通过share_id查找共享内存块，未验证请求进程是否有权限访问该内存块。攻击者可通过猜测或泄露的share_id访问其他进程的共享内存，造成敏感数据泄露或内存破坏。

## 攻击路径分析

### 数据流图

```
┌─────────────────┐                    ┌──────────────────────┐
│ 攻击者进程      │                    │ devmm_ioctl_mem_     │
│ (unprivileged)  │ ─── ioctl() ─────► │   import             │
│ share_id=泄露值 │                    └──────────┬───────────┘
└─────────────────┘                               │
                                                   │ para->share_id
                                                   │ (用户提供)
                                                   ▼
                                        ┌──────────────────────┐
                                        │ devmm_share_agent_   │
                                        │   blk_get            │
                                        │   @ line 623         │
                                        └──────────┬───────────┘
                                                   │
                                                   │ devmm_rb_search
                                                   │ 按 share_id 查找
                                                   │ 无进程权限验证
                                                   ▼
┌─────────────────┐                    ┌──────────────────────┐
│ 共享内存块      │ ◄───────────────── │ ka_base_rb_entry     │
│ (受害者进程)    │                    │ ka_base_kref_get     │
│ - 敏感数据      │                    │ @ line 644-645       │
│ - 密钥/凭证     │                    └──────────────────────┘
└────────┬────────┘
         │
         │ 攻击效果:
         │ - 读取受害者进程数据
         │ - 修改共享内存内容
         │ - 破坏数据一致性
         ▼
┌─────────────────┐
│ 数据泄露        │
│ 内存破坏        │
│ 权限提升        │
└─────────────────┘
```

### share_id泄露途径

```
┌─────────────────────────────────────────────────────────────┐
│                    share_id 泄露途径                         │
├─────────────────────────────────────────────────────────────┤
│  1. 信息泄露漏洞                                             │
│     - 其他漏洞泄露内核数据                                    │
│     - 日志文件记录share_id                                   │
│                                                              │
│  2. 暴力枚举                                                  │
│     - share_id可能为连续整数                                  │
│     - 尝试枚举可能的share_id值                               │
│                                                              │
│  3. 共享攻击                                                  │
│     - 合法用户与攻击者合作                                    │
│     - 通过其他通道传递share_id                               │
│                                                              │
│  4. 内存取证                                                  │
│     - 通过其他内存泄露漏洞                                    │
│     - 从进程内存读取share_id                                 │
└─────────────────────────────────────────────────────────────┘
```

### 关键代码分析

```c
// svm_master_mem_share.c: line 623-651
static struct devmm_share_phy_addr_agent_blk *devmm_share_agent_blk_get(
    u32 devid, int share_id)
{
    struct devmm_share_phy_addr_agent_blk *blk = NULL;
    struct devmm_dev_res_mng *dev_res_mng = NULL;
    ka_rb_node_t *node = NULL;

    // 问题: 仅按 share_id 查找，不验证调用者权限
    node = devmm_rb_search(&dev_res_mng->share_agent_blk_mng.rbtree,
                           (u64)share_id,  // 用户提供的 share_id
                           rb_handle_of_share_agent_blk_node);
    
    if (node == NULL) {
        goto get_from_dev_fail;
    }

    // 问题: 直接获取引用，无权限验证
    blk = ka_base_rb_entry(node, struct devmm_share_phy_addr_agent_blk,
                           dev_res_mng_node);
    ka_base_kref_get(&blk->ref);  // 增加引用计数，返回内存块

    // 缺失验证:
    // - blk->owner_pid != current->tgid (所有权验证)
    // - blk->allowed_pids 包含 current->tgid (访问列表验证)
    // - blk->namespace 与 current->namespace 匹配

    return blk;
}
```

## 利用条件

### 触发条件

| 条件 | 描述 |
|------|------|
| **攻击者位置** | 本地用户进程 (User Space) |
| **信任边界** | 跨越 Shared Memory Region 边界 |
| **前置条件** | 获取有效的 share_id |
| **触发方式** | ioctl(DEVMM_SVM_CMD_MEM_IMPORT) |

### 攻击者能力要求

- **能力等级**: Unprivileged Local
- **所需权限**: 设备文件访问权限 + 泄露的 share_id
- **技术要求**: 
  - 获取目标进程的 share_id
  - 了解 SVM 内存导入接口

### 利用步骤

```c
// 1. 获取目标进程的share_id (通过泄露或枚举)
int target_share_id = leaked_share_id;  // 从其他途径获取

// 2. 导入目标进程的共享内存
struct devmm_ioctl_mem_import arg;
arg.share_id = target_share_id;  // 使用泄露的share_id

ioctl(fd, DEVMM_SVM_CMD_MEM_IMPORT, &arg);

// 3. 访问受害者进程的内存
void *victim_memory = mmap(fd, ...);

// 4. 攻击效果:
// - 读取受害者进程的敏感数据
// - 修改共享内存内容破坏数据一致性
// - 注入恶意数据实现进一步攻击
```

## 彼响评估

### 直接影响

| 影响类型 | 严重性 | 描述 |
|----------|--------|------|
| **数据泄露** | Critical | 读取其他进程的共享内存数据 |
| **内存破坏** | High | 修改共享内存导致受害者进程异常 |
| **权限绑定绕过** | High | 绕过进程隔离访问限制 |
| **容器逃逸** | High | 跨容器访问共享内存 |

### 潜在后果

1. **敏感数据泄露**: 读取密钥、凭证、AI模型数据
2. **数据完整性破坏**: 修改共享数据导致计算错误
3. **进程崩溃**: 修改共享内存导致受害者进程崩溃
4. **横向移动**: 通过共享内存访问更多进程数据

### CVSS 评估

- **攻击向量**: Local
- **攻击复杂度**: Medium (需要获取share_id)
- **权限要求**: Low
- **用户交互**: None
- **影响范围**: Changed
- **CVSS 评分**: 7.5 (High)

## 修复建议

### 立即修复方案

```c
// 1. 添加所有权验证
static struct devmm_share_phy_addr_agent_blk *devmm_share_agent_blk_get_safe(
    u32 devid, int share_id, pid_t requester_pid)
{
    struct devmm_share_phy_addr_agent_blk *blk = NULL;
    
    // 查找共享内存块
    blk = devmm_share_agent_blk_get_internal(devid, share_id);
    
    if (blk == NULL) {
        return NULL;
    }
    
    // 新增: 验证请求者权限
    if (blk->owner_pid != requester_pid) {
        // 检查访问列表
        if (!pid_in_access_list(blk, requester_pid)) {
            devmm_drv_err("Unauthorized access to share_id=%d (requester=%d, owner=%d)\n",
                          share_id, requester_pid, blk->owner_pid);
            ka_base_kref_put(&blk->ref, ...);
            return NULL;
        }
    }
    
    // 新增: 验证namespace匹配
    if (!namespace_match(blk->owner_nsproxy, current->nsproxy)) {
        devmm_drv_err("Namespace mismatch for share_id=%d\n", share_id);
        ka_base_kref_put(&blk->ref, ...);
        return NULL;
    }
    
    return blk;
}

// 2. 增加访问列表机制
struct devmm_share_phy_addr_agent_blk {
    pid_t owner_pid;
    struct list_head allowed_pids;  // 允许访问的进程列表
    struct nsproxy *owner_nsproxy;  // 所有者的namespace
    // ...
};

static bool pid_in_access_list(struct devmm_share_phy_addr_agent_blk *blk, pid_t pid)
{
    struct allowed_pid_entry *entry;
    list_for_each_entry(entry, &blk->allowed_pids, list) {
        if (entry->pid == pid) {
            return true;
        }
    }
    return false;
}
```

### 加密share_id

```c
// 3. 使用加密的share_id防止泄露利用
int generate_secure_share_id(struct devmm_share_phy_addr_agent_blk *blk, pid_t owner_pid)
{
    // 使用加密哈希生成share_id
    u8 hash[32];
    sha256(blk->unique_token, owner_pid, blk->creation_time, hash);
    
    // 取部分哈希作为share_id
    blk->share_id = *((int*)hash) & 0x7FFFFFFF;  // 正整数
    
    return blk->share_id;
}

// 验证share_id时同时验证请求者
bool verify_share_id_request(int share_id, pid_t requester_pid, u32 devid)
{
    // 重新计算哈希验证share_id有效性
    // 同时验证请求者是否在授权列表中
}
```

### 长期修复方案

1. **访问控制列表**: 为每个共享内存块维护允许访问的进程列表
2. **加密标识**: 使用加密哈希作为share_id防止猜测
3. **Namespace隔离**: 强制验证共享内存的namespace边界
4. **审计日志**: 记录所有共享内存访问用于审计

### 配置加固

```bash
# 启用共享内存审计
echo 1 > /sys/module/svm/parameters/share_audit

# 限制共享内存访问
echo "require_explicit_grant" > /sys/module/svm/parameters/share_policy
```

## 验证状态

- **源代码审查**: 已确认 devmm_share_agent_blk_get 仅按 share_id 查找
- **数据流追踪**: 完成 ioctl_import → devmm_share_agent_blk_get → 内存块访问
- **边界检查**: 无 owner_pid 验证，无 access_list 检查
- **置信度评分**: 92/100