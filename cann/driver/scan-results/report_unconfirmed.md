# 漏洞扫描报告 — 待确认漏洞

**项目**: cann-driver
**扫描时间**: 2026-04-22T03:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| CONFIRMED | 37 | 31.4% |
| LIKELY | 33 | 28.0% |
| FALSE_POSITIVE | 26 | 22.0% |
| POSSIBLE | 22 | 18.6% |
| **总计** | **118** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 11 | 21.2% |
| Medium | 37 | 71.2% |
| Low | 2 | 3.8% |
| **有效漏洞总计** | **52** | - |
| 误报 (FALSE_POSITIVE) | 26 | - |

### 1.3 Top 10 关键漏洞

1. **[SVM-REF-COUNT-003]** Reference Count Use-After-Free (High) - `src/sdk_driver/svm/v2/common/svm_proc_mng.c:900` @ `devmm_svm_proc_put/devmm_svm_release_work` | 置信度: 78
2. **[ROCE-VULN-001]** untrusted_data_use (High) - `src/ascend_hal/roce/host_lite/hns_roce_lite.c:645` @ `hns_roce_lite_mark_recv_opcode` | 置信度: 75
3. **[ROCE-001-OOB-WRITE-WRID]** Memory Corruption (High) - `src/ascend_hal/roce/host_lite/hns_roce_lite.c:593` @ `hns_roce_lite_poll_one_set_wc` | 置信度: 75
4. **[VULN-CROSS-CONTAINER-001]** container_isolation_bypass (High) - `src/sdk_driver/dms/devmng/drv_devmng/drv_devmng_host/ascend910/devdrv_manager_container.c:1` @ `devdrv_manager_container_logical_id_to_physical_id` | 置信度: 75
5. **[VULN-CROSS-RDMA-001]** untrusted_network_data_flow (High) - `src/ascend_hal/roce/host_lite/hns_roce_lite.c:645` @ `hns_roce_lite_poll_cq` | 置信度: 75
6. **[VULN-CROSS-HDC-001]** device_firmware_data_validation (High) - `src/sdk_driver/hdc/pcie/common/hdcdrv_core.c:4151` @ `hdcdrv_ctrl_msg_recv` | 置信度: 70
7. **[ROCE-006-NULL-PTR-WRITE]** Memory Corruption (High) - `src/ascend_hal/roce/host_lite/hns_roce_lite.c:858` @ `hns_roce_lite_poll_cq` | 置信度: 65
8. **[VULN_IOCTL_CONTAINER_BYPASS_001]** container_isolation_bypass (High) - `src/sdk_driver/dms/devmng/drv_devmng/drv_devmng_host/ascend910/devdrv_manager_ioctl.c:114` @ `devdrv_manager_get_container_devids` | 置信度: 60
9. **[VULN-LQDRV-003]** user_pointer_validation (High) - `src/custom/lqdrv/kernel/ioctl_comm.c:77` @ `lq_get_fault_event_head_info` | 置信度: 60
10. **[VULN_IOCTL_PARENT_CHILD_001]** privilege_escalation (High) - `src/sdk_driver/dms/devmng/drv_devmng/drv_devmng_host/ascend910/devdrv_manager_pid_map.c:685` @ `check_parent_child_relationship` | 置信度: 55

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `devdrv_manager_ioctl@src/sdk_driver/dms/devmng/drv_devmng/drv_devmng_host/ascend910/devdrv_manager_ioctl.c` | ioctl | untrusted_local | 用户空间通过/dev设备文件调用ioctl，传递命令和数据到内核驱动，任何有设备访问权限的用户进程都可触发 | 设备管理器ioctl主入口，处理100+命令类型 |
| `pcidev_ioctl@src/custom/lqdrv/kernel/ioctl_comm.c` | ioctl | untrusted_local | 灵渠PCIe设备的ioctl入口，用户空间可直接调用 | PCIe设备ioctl处理 |
| `queue_drv_open@src/sdk_driver/queue/host/queue_fops.c` | file | untrusted_local | 用户进程通过open系统调用打开设备文件，创建队列上下文 | 队列驱动open入口 |
| `queue_drv_host_init@src/sdk_driver/queue/host/queue_fops.c` | ioctl | untrusted_local | ioctl命令初始化主机侧队列 | 队列ioctl初始化 |
| `shared_memory_mmap@src/custom/lqdrv/kernel/pci-dev.c` | file | untrusted_local | 用户进程通过mmap映射共享内存，直接访问内核内存区域 | 共享内存mmap入口 |
| `g_bmc_pci_mem.pmap_addr@src/custom/lqdrv/kernel/pci-dev.c` | file | internal | 内核内ioremap BAR空间，非用户直接入口但潜在风险点 | PCIe BAR空间ioremap |
| `hns_roce_lite_init@src/ascend_hal/roce/host_lite/hns_roce_lite.c` | network | untrusted_network | RoCE RDMA网络接口，可接收远程网络数据包 | RoCE网络入口 |
| `hdc_server_init@src/ascend_hal/hdc/common/hdc_server.c` | network | semi_trusted | HDC服务器处理主机-设备通信，数据来源为设备侧固件 | HDC服务器入口 |
| `svm_init@src/sdk_driver/svm/v2/common/svm_module_ops.c` | rpc | untrusted_local | SVM共享虚拟内存模块入口，用户通过ioctl调用内存操作 | SVM模块入口 |
| `module_init@src/sdk_driver/kernel_adapt/ka_module_init.c` | file | trusted_admin | 内核模块初始化入口，由系统加载触发 | 内核模块init入口 |

**其他攻击面**:
- ioctl接口: 471个文件包含ioctl处理，100+命令类型
- copy_from_user/copy_to_user: 102个文件进行内核-用户数据交换
- 网络接口(RoCE/HDC): 579个文件包含socket/network操作
- 内存映射(mmap/ioremap): 5个文件直接映射物理内存
- PCIe DMA操作: 多文件处理DMA传输
- 文件操作: 957个文件包含文件读写
- 缓冲区操作(sprintf/strcpy/memcpy): 50+文件存在潜在溢出风险
- 容器接口: 支持容器环境，存在namespace隔离风险
- 设备虚拟化: vnic/vmng/vascend虚拟化特性
- 共享内存: 进程间共享内存通信

---

## 3. High 漏洞 (11)

### [SVM-REF-COUNT-003] Reference Count Use-After-Free - devmm_svm_proc_put/devmm_svm_release_work

**严重性**: High | **CWE**: CWE-401 | **置信度**: 78/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/sdk_driver/svm/v2/common/svm_proc_mng.c:900-970` @ `devmm_svm_proc_put/devmm_svm_release_work`
**模块**: svm_memory

**描述**: SVM进程引用计数管理存在潜在竞态条件。devmm_svm_proc_put函数仅减少引用计数，不检查是否触发清理。release work超时长达一周(DEVMM_RELEASE_WAIT_TIMES_OUT=604800)，期间结构可能被错误访问。存在UAF风险：引用计数降为0但清理未完成时，其他线程可能访问已释放结构。

**漏洞代码** (`src/sdk_driver/svm/v2/common/svm_proc_mng.c:900-970`)

```c
ka_base_atomic_dec(&svm_proc->ref); // No cleanup triggered if ref==0 but work pending
```

**达成路径**

Process A decrements ref -> ref==0 -> release_work scheduled with 1 week timeout -> Process B accesses freed structure

**验证说明**: devmm_svm_proc_put just decrements ref. devmm_svm_release_work has 1-week timeout(604800). UAF window exists between ref=0 and cleanup completion.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: i | 23: o | 24: c | 25: t | 26: l | 27: _ | 28: c | 29: l | 30: o | 31: s | 32: e | 33: + | 34: 2 | 35: 5 | 36: , | 37:   | 38: c | 39: o | 40: n | 41: t | 42: r | 43: o | 44: l | 45: l | 46: a | 47: b | 48: i | 49: l | 50: i | 51: t | 52: y | 53: = | 54: p | 55: a | 56: r | 57: t | 58: i | 59: a | 60: l | 61: + | 62: 1 | 63: 5 | 64: , | 65:   | 66: m | 67: i | 68: t | 69: i | 70: g | 71: a | 72: t | 73: i | 74: o | 75: n | 76: s | 77: = | 78: r | 79: e | 80: f | 81: _ | 82: t | 83: r | 84: a | 85: c | 86: k | 87: i | 88: n | 89: g | 90: - | 91: 1 | 92: 0 | 93: ( | 94: l | 95: o | 96: n | 97: g | 98: _ | 99: t | 100: i | 101: m | 102: e | 103: o | 104: u | 105: t | 106: )

---

### [ROCE-VULN-001] untrusted_data_use - hns_roce_lite_mark_recv_opcode

**严重性**: High（原评估: HIGH → 验证后: High） | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite.c:645-696` @ `hns_roce_lite_mark_recv_opcode`
**模块**: roce_network
**跨模块**: roce_network,nda_ibv_extend

**描述**: Untrusted byte_len from CQE (Completion Queue Entry) used without validation. The byte_cnt field from hardware/network CQE is directly converted and stored in lite_wc->byte_len without bounds checking. This could lead to buffer over-read if the reported length exceeds actual receive buffer size.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite.c:645-696`)

```c
lite_wc->byte_len = le32toh(cqe->byte_cnt);
```

**达成路径**

CQE[network] -> le32toh() -> lite_wc->byte_len -> user application

**验证说明**: LIKELY: byte_len from CQE (network) stored in lite_wc->byte_len without validation. Could exceed receive buffer size. Direct data flow from network hardware to user application.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: d | 29: i | 30: r | 31: e | 32: c | 33: t | 34: _ | 35: e | 36: x | 37: t | 38: e | 39: r | 40: n | 41: a | 42: l | 43: , | 44: r | 45: e | 46: a | 47: c | 48: h | 49: a | 50: b | 51: i | 52: l | 53: i | 54: t | 55: y | 56: _ | 57: s | 58: c | 59: o | 60: r | 61: e | 62: : | 63: 3 | 64: 0 | 65: , | 66: c | 67: o | 68: n | 69: t | 70: r | 71: o | 72: l | 73: l | 74: a | 75: b | 76: i | 77: l | 78: i | 79: t | 80: y | 81: : | 82: p | 83: a | 84: r | 85: t | 86: i | 87: a | 88: l | 89: , | 90: c | 91: o | 92: n | 93: t | 94: r | 95: o | 96: l | 97: l | 98: a | 99: b | 100: i | 101: l | 102: i | 103: t | 104: y | 105: _ | 106: s | 107: c | 108: o | 109: r | 110: e | 111: : | 112: 1 | 113: 5 | 114: , | 115: m | 116: i | 117: t | 118: i | 119: g | 120: a | 121: t | 122: i | 123: o | 124: n | 125: s | 126: : | 127: [ | 128: ] | 129: , | 130: m | 131: i | 132: t | 133: i | 134: g | 135: a | 136: t | 137: i | 138: o | 139: n | 140: _ | 141: s | 142: c | 143: o | 144: r | 145: e | 146: : | 147: 0 | 148: , | 149: f | 150: i | 151: n | 152: a | 153: l | 154: _ | 155: s | 156: c | 157: o | 158: r | 159: e | 160: : | 161: 7 | 162: 5 | 163: }

---

### [ROCE-001-OOB-WRITE-WRID] Memory Corruption - hns_roce_lite_poll_one_set_wc

**严重性**: High | **CWE**: CWE-787 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite.c:593-597` @ `hns_roce_lite_poll_one_set_wc`
**模块**: roce_network

**描述**: Out-of-bounds write in wrid array access. The code uses wrid[tail & (wqe_cnt - 1)] without validating wqe_cnt. If wqe_cnt is 0, wqe_cnt - 1 becomes UINT32_MAX (integer underflow), causing out-of-bounds access. Network-triggered via RDMA packet processing.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite.c:593-597`)

```c
lite_wc->wr_id = lite_wq->wrid[lite_wq->tail & (lite_wq->wqe_cnt - 1)];
```

**达成路径**

Network RDMA packet -> poll_cq -> poll_one -> poll_one_set_wc -> wrid array access

**验证说明**: Verified: wrid array access uses tail & (wqe_cnt-1) mask. If wqe_cnt is 0 from device config, mask becomes UINT32_MAX causing OOB. No explicit validation that wqe_cnt > 0. Network-triggered via poll_cq processing.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: d | 29: i | 30: r | 31: e | 32: c | 33: t | 34: _ | 35: e | 36: x | 37: t | 38: e | 39: r | 40: n | 41: a | 42: l | 43: , | 44: r | 45: e | 46: a | 47: c | 48: h | 49: a | 50: b | 51: i | 52: l | 53: i | 54: t | 55: y | 56: _ | 57: s | 58: c | 59: o | 60: r | 61: e | 62: : | 63: 3 | 64: 0 | 65: , | 66: c | 67: o | 68: n | 69: t | 70: r | 71: o | 72: l | 73: l | 74: a | 75: b | 76: i | 77: l | 78: i | 79: t | 80: y | 81: : | 82: p | 83: a | 84: r | 85: t | 86: i | 87: a | 88: l | 89: , | 90: c | 91: o | 92: n | 93: t | 94: r | 95: o | 96: l | 97: l | 98: a | 99: b | 100: i | 101: l | 102: i | 103: t | 104: y | 105: _ | 106: s | 107: c | 108: o | 109: r | 110: e | 111: : | 112: 1 | 113: 5 | 114: , | 115: m | 116: i | 117: t | 118: i | 119: g | 120: a | 121: t | 122: i | 123: o | 124: n | 125: s | 126: : | 127: [ | 128: ] | 129: , | 130: m | 131: i | 132: t | 133: i | 134: g | 135: a | 136: t | 137: i | 138: o | 139: n | 140: _ | 141: s | 142: c | 143: o | 144: r | 145: e | 146: : | 147: 0 | 148: , | 149: f | 150: i | 151: n | 152: a | 153: l | 154: _ | 155: s | 156: c | 157: o | 158: r | 159: e | 160: : | 161: 7 | 162: 5 | 163: }

---

### [VULN-CROSS-CONTAINER-001] container_isolation_bypass - devdrv_manager_container_logical_id_to_physical_id

**严重性**: High | **CWE**: CWE-285 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/sdk_driver/dms/devmng/drv_devmng/drv_devmng_host/ascend910/devdrv_manager_container.c:1-150` @ `devdrv_manager_container_logical_id_to_physical_id`
**模块**: cross_module
**跨模块**: ioctl_handlers → svm_memory → sdk_driver

**描述**: 跨模块容器隔离绕过：ioctl_handlers的devdrv_manager_container_logical_id_to_physical_id转换设备ID，svm_memory模块缺少namespace隔离检查，container进程可跨容器边界访问其他容器的设备资源或共享内存。

**达成路径**

[ioctl_handlers] devdrv_manager_ioctl → devdrv_manager_container_logical_id_to_physical_id → 物理设备ID
[svm_memory] svm_ioctl → 无namespace检查 → 跨容器内存共享

**验证说明**: 调用链验证完成：devdrv_manager_ioctl→devdrv_manager_container_logical_id_to_physical_id→SVM模块。ioctl_handlers有设备ID转换检查，但SVM模块缺少namespace隔离检查。代码证据：devmm_proc_info.c line 2175-2217设置docker_id但无namespace验证。

**评分明细**: base_score: 70 | chain_complete: true | cross_file_verified: true | semi_trusted_boundary: 5 | mitigations_found: true

---

### [VULN-CROSS-RDMA-001] untrusted_network_data_flow - hns_roce_lite_poll_cq

**严重性**: High | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite.c:645-801` @ `hns_roce_lite_poll_cq`
**模块**: cross_module
**跨模块**: roce_network → nda_ibv_extend → ascend_hal

**描述**: 跨模块RDMA网络数据未验证：roce_network模块从CQE提取byte_len/qpn/wqe_ctr等字段直接使用，数据传递到nda_ibv_extend模块和应用层。恶意网络数据可导致缓冲区溢出、数组越界或应用层内存安全问题。

**达成路径**

[roce_network] CQE[network] → byte_len → lite_wc → [nda_ibv_extend] ibv扩展 → 应用层
[roce_network] qpn → qp_table → QP操作 → 设备

**验证说明**: 调用链验证完成：CQE[network]→byte_len→lite_wc→应用层。代码证据：hns_roce_lite.c line 645，byte_len直接从CQE提取使用，无范围验证。qpn在line 795-801使用查找QP，但验证不完整。安全措施：有QP状态检查但无数据范围验证。

**评分明细**: base_score: 75 | chain_complete: true | cross_file_verified: true | mitigations_found: true

---

### [VULN-CROSS-HDC-001] device_firmware_data_validation - hdcdrv_ctrl_msg_recv

**严重性**: High | **CWE**: CWE-347 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `src/sdk_driver/hdc/pcie/common/hdcdrv_core.c:4151-4200` @ `hdcdrv_ctrl_msg_recv`
**模块**: cross_module
**跨模块**: hdc_communication → ascend_hal → sdk_driver

**描述**: 跨模块设备固件数据验证缺失：hdc_communication模块从设备固件接收控制消息，消息解析后的数据流出到session_management和memory_management模块。设备固件被视为semi_trusted，恶意固件可发送构造消息导致内核内存安全问题。

**达成路径**

[设备固件] PCIe DMA → [hdc_communication] hdcdrv_ctrl_msg_recv → 消息解析 → [session_management] 会话状态
[hdc_communication] → [memory_management] 内存块操作

**验证说明**: 调用链验证完成：设备固件→PCIe DMA→hdcdrv_ctrl_msg_recv→session/memory模块。代码证据：hdcdrv_core.c line 4151-4213处理设备消息，有长度检查但缺少数据内容验证。设备固件为semi_trusted，存在固件恶意构造消息风险。安全措施：有参数检查但无消息数据验证。

**评分明细**: base_score: 65 | chain_complete: true | cross_file_verified: true | semi_trusted_boundary: 5 | mitigations_found: true

---

### [ROCE-006-NULL-PTR-WRITE] Memory Corruption - hns_roce_lite_poll_cq

**严重性**: High | **CWE**: CWE-787 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite.c:858-861` @ `hns_roce_lite_poll_cq`
**模块**: roce_network

**描述**: Direct memory write through potentially invalid pointer. Code writes to cq->swdb_buf.hva and qp->sdb_buf.hva without NULL validation after mmap operations. If mmap fails but error handling is incomplete, NULL pointer dereference leads to crash or memory corruption.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite.c:858-861`)

```c
*(u32 *)cq->swdb_buf.hva = cq->cons_index & RECORD_DB_CI_MASK;
```

**达成路径**

mmap could fail -> hva could be NULL -> direct write -> memory corruption

**验证说明**: LIKELY: poll_cq writes to cq->swdb_buf.hva (line 858) without NULL check. Init validates mmap success (line 251-254), but poll_cq does NOT revalidate. If mmap partially failed or memory corrupted, NULL write possible.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: d | 29: i | 30: r | 31: e | 32: c | 33: t | 34: _ | 35: e | 36: x | 37: t | 38: e | 39: r | 40: n | 41: a | 42: l | 43: , | 44: r | 45: e | 46: a | 47: c | 48: h | 49: a | 50: b | 51: i | 52: l | 53: i | 54: t | 55: y | 56: _ | 57: s | 58: c | 59: o | 60: r | 61: e | 62: : | 63: 3 | 64: 0 | 65: , | 66: c | 67: o | 68: n | 69: t | 70: r | 71: o | 72: l | 73: l | 74: a | 75: b | 76: i | 77: l | 78: i | 79: t | 80: y | 81: : | 82: p | 83: a | 84: r | 85: t | 86: i | 87: a | 88: l | 89: , | 90: c | 91: o | 92: n | 93: t | 94: r | 95: o | 96: l | 97: l | 98: a | 99: b | 100: i | 101: l | 102: i | 103: t | 104: y | 105: _ | 106: s | 107: c | 108: o | 109: r | 110: e | 111: : | 112: 1 | 113: 5 | 114: , | 115: m | 116: i | 117: t | 118: i | 119: g | 120: a | 121: t | 122: i | 123: o | 124: n | 125: s | 126: : | 127: [ | 128: n | 129: u | 130: l | 131: l | 132: _ | 133: c | 134: h | 135: e | 136: c | 137: k | 138: _ | 139: i | 140: n | 141: i | 142: t | 143: ] | 144: , | 145: m | 146: i | 147: t | 148: i | 149: g | 150: a | 151: t | 152: i | 153: o | 154: n | 155: _ | 156: s | 157: c | 158: o | 159: r | 160: e | 161: : | 162: - | 163: 1 | 164: 0 | 165: , | 166: f | 167: i | 168: n | 169: a | 170: l | 171: _ | 172: s | 173: c | 174: o | 175: r | 176: e | 177: : | 178: 6 | 179: 5 | 180: }

---

### [VULN_IOCTL_CONTAINER_BYPASS_001] container_isolation_bypass - devdrv_manager_get_container_devids

**严重性**: High | **CWE**: CWE-668 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/sdk_driver/dms/devmng/drv_devmng/drv_devmng_host/ascend910/devdrv_manager_ioctl.c:114-150` @ `devdrv_manager_get_container_devids`
**模块**: ioctl_handlers
**跨模块**: devdrv_manager_container,ioctl_handlers

**描述**: Container isolation bypass via ioctl handler: devdrv_manager_get_container_devids checks for container/host system at line 119-121, but the check depends on current->nsproxy which could be manipulated by a crafted namespace. The function returns host device IDs to user space, potentially allowing a container process to enumerate devices outside its namespace.

**漏洞代码** (`src/sdk_driver/dms/devmng/drv_devmng/drv_devmng_host/ascend910/devdrv_manager_ioctl.c:114-150`)

```c
if ((current->nsproxy == NULL) || (!devdrv_manager_container_is_host_system(ka_task_get_current_mnt_ns()))) { return -EPERM; }
```

**达成路径**

copy_to_user_safe@140 -> hccl_devinfo -> user_space

**验证说明**: LIKELY: devdrv_manager_get_container_devids checks current->nsproxy and mnt_ns. Check is kernel-controlled but potentially bypassable in specific container configurations.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -15

---

### [VULN-LQDRV-003] user_pointer_validation - lq_get_fault_event_head_info

**严重性**: High | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/custom/lqdrv/kernel/ioctl_comm.c:77-111` @ `lq_get_fault_event_head_info`
**模块**: lqdrv_custom

**描述**: IOCTL_CMD_S.out_addr is user-provided pointer used directly in copy_to_user without validation. Malicious user could provide invalid pointer causing kernel to write to arbitrary user space addresses or trigger kernel crash.

**漏洞代码** (`src/custom/lqdrv/kernel/ioctl_comm.c:77-111`)

```c
ret = copy_to_user(ioctl_cmd->out_addr, &info_pipe, sizeof(SramDescCtlHeader));
```

**达成路径**

ka_base_copy_from_user -> ioctl_cmd.out_addr -> copy_to_user

**验证说明**: LIKELY: ioctl_cmd->out_addr is user-provided pointer used in copy_to_user (line 77). While copy_to_user handles invalid pointers by returning EFAULT, there is no explicit access_ok() validation before use. The kernel relies on copy_to_user internal safety checks.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 10 | final: 60

---

### [VULN_IOCTL_PARENT_CHILD_001] privilege_escalation - check_parent_child_relationship

**严重性**: High | **CWE**: CWE-269 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/sdk_driver/dms/devmng/drv_devmng/drv_devmng_host/ascend910/devdrv_manager_pid_map.c:685-742` @ `check_parent_child_relationship`
**模块**: ioctl_handlers
**跨模块**: ioctl_handlers,pid_map

**描述**: Parent-child relationship check bypass: check_parent_child_relationship verifies slave process is child of current process, but relies on tsk->real_parent->tgid comparison. A process in different namespace could potentially bypass this check to bind unauthorized processes.

**漏洞代码** (`src/sdk_driver/dms/devmng/drv_devmng/drv_devmng_host/ascend910/devdrv_manager_pid_map.c:685-742`)

```c
if (tsk->real_parent->tgid != cur_tgid) { return -EINVAL; }
```

**达成路径**

copy_from_user_safe@384 -> para_info.host_pid -> check_parent_child_relationship@861

**验证说明**: POSSIBLE: check_parent_child_relationship verifies tsk->real_parent->tgid. Check is reasonable within same namespace, but bypass potential exists if namespace isolation fails.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -20

---

### [VULN-IOCTL-002] Insufficient Authorization Check - devdrv_fop_bind_host_pid

**严重性**: High | **CWE**: CWE-639 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/dms/devmng/drv_devmng/drv_devmng_host/ascend910/devdrv_manager_ioctl.c:373-422` @ `devdrv_fop_bind_host_pid`
**模块**: ioctl_handlers
**跨模块**: ioctl_handlers,devdrv_manager_pid_map

**描述**: [CREDENTIAL_FLOW] The devdrv_fop_bind_host_pid() function allows binding host processes to devices using user-provided host_pid and sign fields. While check_parent_child_relationship() validates parent-child relationship, the authorization check (devdrv_is_master_pid) only verifies the master process exists in the sign list, not that the caller has authorization to bind that specific process. Attack vector: Local attacker can bind arbitrary processes by manipulating the sign field or exploiting race conditions in process creation.

**达成路径**

ioctl -> copy_from_user(host_pid,sign) -> devdrv_bind_hostpid -> devdrv_is_master_pid -> process_sign lookup

**验证说明**: LIKELY: devdrv_fop_bind_host_pid relies on sign list membership for authorization, not proper capability checks. Sign manipulation could allow unauthorized process binding.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -20

---

## 4. Medium 漏洞 (37)

### [ROCE-VULN-007] untrusted_data_use - hns_roce_lite_mark_recv_opcode

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite.c:652-667` @ `hns_roce_lite_mark_recv_opcode`
**模块**: roce_network
**跨模块**: [roce_network,nda_ibv_extend]

**描述**: Remote key (rkey) and immediate data (immtdata) from untrusted CQE stored without validation. These values from network packets could be used in subsequent memory operations without proper validation.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite.c:652-667`)

```c
ext->imm_data = le32toh(cqe->immtdata); ext->invalidated_rkey = le32toh(cqe->rkey);
```

**达成路径**

CQE[network] -> immtdata/rkey -> le32toh() -> ext structure

**验证说明**: LIKELY: immtdata and rkey from CQE stored without validation. These values from network could be used in subsequent operations. Cross-module impact to nda_ibv_extend.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: d | 29: i | 30: r | 31: e | 32: c | 33: t | 34: _ | 35: e | 36: x | 37: t | 38: e | 39: r | 40: n | 41: a | 42: l | 43: , | 44: r | 45: e | 46: a | 47: c | 48: h | 49: a | 50: b | 51: i | 52: l | 53: i | 54: t | 55: y | 56: _ | 57: s | 58: c | 59: o | 60: r | 61: e | 62: : | 63: 3 | 64: 0 | 65: , | 66: c | 67: o | 68: n | 69: t | 70: r | 71: o | 72: l | 73: l | 74: a | 75: b | 76: i | 77: l | 78: i | 79: t | 80: y | 81: : | 82: p | 83: a | 84: r | 85: t | 86: i | 87: a | 88: l | 89: , | 90: c | 91: o | 92: n | 93: t | 94: r | 95: o | 96: l | 97: l | 98: a | 99: b | 100: i | 101: l | 102: i | 103: t | 104: y | 105: _ | 106: s | 107: c | 108: o | 109: r | 110: e | 111: : | 112: 1 | 113: 5 | 114: , | 115: m | 116: i | 117: t | 118: i | 119: g | 120: a | 121: t | 122: i | 123: o | 124: n | 125: s | 126: : | 127: [ | 128: ] | 129: , | 130: m | 131: i | 132: t | 133: i | 134: g | 135: a | 136: t | 137: i | 138: o | 139: n | 140: _ | 141: s | 142: c | 143: o | 144: r | 145: e | 146: : | 147: 0 | 148: , | 149: f | 150: i | 151: n | 152: a | 153: l | 154: _ | 155: s | 156: c | 157: o | 158: r | 159: e | 160: : | 161: 7 | 162: 5 | 163: }

---

### [ROCE-007-RESOURCE-EXHAUST] Denial of Service - hns_roce_lite_wq_overflow

**严重性**: Medium | **CWE**: CWE-400 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite.c:923-937` @ `hns_roce_lite_wq_overflow`
**模块**: roce_network

**描述**: Resource exhaustion vulnerability in work queue overflow check. hns_roce_lite_wq_overflow() checks against max_post but the check can be bypassed by rapid posting of work requests before the CQ polling catches up. No rate limiting on post_send/post_recv.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite.c:923-937`)

```c
cur = wq->head - wq->tail; if (cur + nreq < wq->max_post) { return 0; }
```

**达成路径**

Rapid RDMA requests -> queue overflow -> resource exhaustion

**验证说明**: LIKELY: wq_overflow() has TOCTOU race. First check at line 928 without lock, then re-check at line 933 with lock. Race window between checks. Rapid posting could bypass limit.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: d | 29: i | 30: r | 31: e | 32: c | 33: t | 34: _ | 35: e | 36: x | 37: t | 38: e | 39: r | 40: n | 41: a | 42: l | 43: , | 44: r | 45: e | 46: a | 47: c | 48: h | 49: a | 50: b | 51: i | 52: l | 53: i | 54: t | 55: y | 56: _ | 57: s | 58: c | 59: o | 60: r | 61: e | 62: : | 63: 3 | 64: 0 | 65: , | 66: c | 67: o | 68: n | 69: t | 70: r | 71: o | 72: l | 73: l | 74: a | 75: b | 76: i | 77: l | 78: i | 79: t | 80: y | 81: : | 82: f | 83: u | 84: l | 85: l | 86: , | 87: c | 88: o | 89: n | 90: t | 91: r | 92: o | 93: l | 94: l | 95: a | 96: b | 97: i | 98: l | 99: i | 100: t | 101: y | 102: _ | 103: s | 104: c | 105: o | 106: r | 107: e | 108: : | 109: 2 | 110: 5 | 111: , | 112: m | 113: i | 114: t | 115: i | 116: g | 117: a | 118: t | 119: i | 120: o | 121: n | 122: s | 123: : | 124: [ | 125: o | 126: v | 127: e | 128: r | 129: f | 130: l | 131: o | 132: w | 133: _ | 134: c | 135: h | 136: e | 137: c | 138: k | 139: ] | 140: , | 141: m | 142: i | 143: t | 144: i | 145: g | 146: a | 147: t | 148: i | 149: o | 150: n | 151: _ | 152: s | 153: c | 154: o | 155: r | 156: e | 157: : | 158: - | 159: 1 | 160: 0 | 161: , | 162: f | 163: i | 164: n | 165: a | 166: l | 167: _ | 168: s | 169: c | 170: o | 171: r | 172: e | 173: : | 174: 7 | 175: 5 | 176: }

---

### [SVM-007] Integer Overflow in Memory Allocation - devmm_phy_addr_blk_create

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/svm/v2/common/svm_phy_addr_blk_mng.c:143-198` @ `devmm_phy_addr_blk_create`
**模块**: svm_memory

**描述**: Multiple allocation functions use pg_num * sizeof() without overflow checks. Large pg_num values could cause integer overflow leading to undersized allocations and subsequent buffer overflows.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/svm/v2/common/svm_phy_addr_blk_mng.c:143-198`)

```c
struct devmm_phy_addr_blk *devmm_phy_addr_blk_create(...) { pages = devmm_kvzalloc_ex(sizeof(ka_page_t *) * pg_num, ...); dma_blks = devmm_kvzalloc_ex(sizeof(struct devmm_dma_blk) * pg_num, ...); target_addr = devmm_kvzalloc_ex(sizeof(u64) * pg_num, ...); }
```

**达成路径**

User pg_num -> allocation size calculation -> potential overflow -> undersized buffer

**验证说明**: Lines 157-169 in svm_phy_addr_blk_mng.c: sizeof(ka_page_t*) * pg_num without overflow check. Large pg_num could overflow causing undersized allocation.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: i | 23: o | 24: c | 25: t | 26: l | 27: _ | 28: a | 29: l | 30: l | 31: o | 32: c | 33: + | 34: 2 | 35: 5 | 36: , | 37:   | 38: c | 39: o | 40: n | 41: t | 42: r | 43: o | 44: l | 45: l | 46: a | 47: b | 48: i | 49: l | 50: i | 51: t | 52: y | 53: = | 54: f | 55: u | 56: l | 57: l | 58: + | 59: 2 | 60: 0 | 61: , | 62:   | 63: m | 64: i | 65: t | 66: i | 67: g | 68: a | 69: t | 70: i | 71: o | 72: n | 73: s | 74: = | 75: s | 76: i | 77: z | 78: e | 79: _ | 80: c | 81: h | 82: e | 83: c | 84: k | 85: - | 86: 1 | 87: 0 | 88: ( | 89: p | 90: a | 91: r | 92: t | 93: i | 94: a | 95: l | 96: )

---

### [HDC-004] memory_corruption - hdcdrv_mem_block_head_check

**严重性**: Medium | **CWE**: CWE-787 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/hdc/pcie/common/hdcdrv_mem_com.c:211-234` @ `hdcdrv_mem_block_head_check`
**模块**: hdc_communication
**跨模块**: hdc_communication:memory_allocator

**描述**: Memory block head CRC validation exists but corrupted blocks may still be processed in some error paths. Memory corruption from device could bypass checks or cause memory safety issues. The block_head->magic and CRC checks may fail but error handling may be incomplete.

**达成路径**

device_firmware@DMA -> hdcdrv_mem_block_head_check -> memory_pool_operations

**验证说明**: CRC32 validation exists for block_head magic and integrity. However, error handling paths may not properly clean up in all scenarios. Corrupted blocks from device may bypass checks in certain error paths.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: : | 6: 3 | 7: 0 | 8: , | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: : | 22: 2 | 23: 0 | 24: , | 25: c | 26: o | 27: n | 28: t | 29: r | 30: o | 31: l | 32: l | 33: a | 34: b | 35: i | 36: l | 37: i | 38: t | 39: y | 40: : | 41: 1 | 42: 5 | 43: , | 44: m | 45: i | 46: t | 47: i | 48: g | 49: a | 50: t | 51: i | 52: o | 53: n | 54: s | 55: : | 56: 1 | 57: 0 | 58: , | 59: f | 60: i | 61: n | 62: a | 63: l | 64: : | 65: 5 | 66: 5 | 67: }

---

### [ROCE-VULN-002] out_of_bounds_access - hns_roce_lite_poll_one

**严重性**: Medium（原评估: HIGH → 验证后: Medium） | **CWE**: CWE-125 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite.c:795-806` @ `hns_roce_lite_poll_one`
**模块**: roce_network

**描述**: QPN (Queue Pair Number) extracted from untrusted CQE used for QP table lookup without proper bounds validation. QPN is masked with 0xffffff allowing 24-bit values, but the qp_table array may not cover this full range, potentially leading to out-of-bounds read in hns_roce_lite_find_qp.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite.c:795-806`)

```c
qpn = roce_get_field(cqe->byte_16, ...); *cur_qp = hns_roce_lite_find_qp(..., qpn & 0xffffff);
```

**达成路径**

CQE[network] -> byte_16 -> qpn extraction -> QP lookup

**验证说明**: POSSIBLE: QPN from CQE masked with 0xffffff. find_qp checks tind < HNS_ROCE_LITE_QP_TABLE_SIZE. Mitigation present but mask allows 24-bit values while table may be smaller.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: d | 29: i | 30: r | 31: e | 32: c | 33: t | 34: _ | 35: e | 36: x | 37: t | 38: e | 39: r | 40: n | 41: a | 42: l | 43: , | 44: r | 45: e | 46: a | 47: c | 48: h | 49: a | 50: b | 51: i | 52: l | 53: i | 54: t | 55: y | 56: _ | 57: s | 58: c | 59: o | 60: r | 61: e | 62: : | 63: 3 | 64: 0 | 65: , | 66: c | 67: o | 68: n | 69: t | 70: r | 71: o | 72: l | 73: l | 74: a | 75: b | 76: i | 77: l | 78: i | 79: t | 80: y | 81: : | 82: p | 83: a | 84: r | 85: t | 86: i | 87: a | 88: l | 89: , | 90: c | 91: o | 92: n | 93: t | 94: r | 95: o | 96: l | 97: l | 98: a | 99: b | 100: i | 101: l | 102: i | 103: t | 104: y | 105: _ | 106: s | 107: c | 108: o | 109: r | 110: e | 111: : | 112: 1 | 113: 5 | 114: , | 115: m | 116: i | 117: t | 118: i | 119: g | 120: a | 121: t | 122: i | 123: o | 124: n | 125: s | 126: : | 127: [ | 128: b | 129: o | 130: u | 131: n | 132: d | 133: s | 134: _ | 135: c | 136: h | 137: e | 138: c | 139: k | 140: _ | 141: t | 142: i | 143: n | 144: d | 145: ] | 146: , | 147: m | 148: i | 149: t | 150: i | 151: g | 152: a | 153: t | 154: i | 155: o | 156: n | 157: _ | 158: s | 159: c | 160: o | 161: r | 162: e | 163: : | 164: - | 165: 1 | 166: 0 | 167: , | 168: f | 169: i | 170: n | 171: a | 172: l | 173: _ | 174: s | 175: c | 176: o | 177: r | 178: e | 179: : | 180: 6 | 181: 5 | 182: }

---

### [VULN_IOCTL_ERROR_LEAK_001] information_disclosure - devdrv_get_error_code

**严重性**: Medium | **CWE**: CWE-200 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/sdk_driver/dms/devmng/drv_devmng/drv_devmng_host/ascend910/devdrv_manager_ioctl.c:455-461` @ `devdrv_get_error_code`
**模块**: ioctl_handlers

**描述**: Error code info disclosure: devdrv_get_error_code copies error codes from shm_status to user space without sanitization. Error_cnt and error_code array are directly exposed, potentially leaking sensitive info to unprivileged users.

**漏洞代码** (`src/sdk_driver/dms/devmng/drv_devmng/drv_devmng_host/ascend910/devdrv_manager_ioctl.c:455-461`)

```c
user_arg.error_code_count = dev_info->shm_status->error_cnt; for (i=0; i<LEN; i++) { user_arg.error_code[i] = dev_info->shm_status->error_code[i]; }
```

**达成路径**

copy_from_user_safe@431 -> shm_status -> copy_to_user_safe@461

**验证说明**: LIKELY: devdrv_get_error_code copies error_cnt and error_code array directly from shm_status to userspace. May leak internal device status.

**评分明细**: base: 30 | reachability: 30 | controllability: 5 | mitigations: 0

---

### [ROCE-VULN-014] improper_validation - hns_roce_lite_find_qp

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite.c:557-568` @ `hns_roce_lite_find_qp`
**模块**: roce_network

**描述**: Insufficient bounds check in hns_roce_lite_find_qp. The tind calculation uses num_qps and qp_table_shift but does not validate the resulting table index before accessing qp_table array.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite.c:557-568`)

```c
u32 tind = (qpn & (ctx->num_qps - 1)) >> ctx->qp_table_shift; if (tind < HNS_ROCE_LITE_QP_TABLE_SIZE) ...
```

**达成路径**

qpn -> tind calculation -> qp_table access

**验证说明**: POSSIBLE: find_qp has bounds check: tind < HNS_ROCE_LITE_QP_TABLE_SIZE at line 561. Mitigation present for table access.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: d | 29: i | 30: r | 31: e | 32: c | 33: t | 34: _ | 35: e | 36: x | 37: t | 38: e | 39: r | 40: n | 41: a | 42: l | 43: , | 44: r | 45: e | 46: a | 47: c | 48: h | 49: a | 50: b | 51: i | 52: l | 53: i | 54: t | 55: y | 56: _ | 57: s | 58: c | 59: o | 60: r | 61: e | 62: : | 63: 3 | 64: 0 | 65: , | 66: c | 67: o | 68: n | 69: t | 70: r | 71: o | 72: l | 73: l | 74: a | 75: b | 76: i | 77: l | 78: i | 79: t | 80: y | 81: : | 82: p | 83: a | 84: r | 85: t | 86: i | 87: a | 88: l | 89: , | 90: c | 91: o | 92: n | 93: t | 94: r | 95: o | 96: l | 97: l | 98: a | 99: b | 100: i | 101: l | 102: i | 103: t | 104: y | 105: _ | 106: s | 107: c | 108: o | 109: r | 110: e | 111: : | 112: 1 | 113: 5 | 114: , | 115: m | 116: i | 117: t | 118: i | 119: g | 120: a | 121: t | 122: i | 123: o | 124: n | 125: s | 126: : | 127: [ | 128: b | 129: o | 130: u | 131: n | 132: d | 133: s | 134: _ | 135: c | 136: h | 137: e | 138: c | 139: k | 140: _ | 141: t | 142: i | 143: n | 144: d | 145: ] | 146: , | 147: m | 148: i | 149: t | 150: i | 151: g | 152: a | 153: t | 154: i | 155: o | 156: n | 157: _ | 158: s | 159: c | 160: o | 161: r | 162: e | 163: : | 164: - | 165: 1 | 166: 0 | 167: , | 168: f | 169: i | 170: n | 171: a | 172: l | 173: _ | 174: s | 175: c | 176: o | 177: r | 178: e | 179: : | 180: 6 | 181: 5 | 182: }

---

### [HDC-006] buffer_overflow - hdcdrv_copy_from_user

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/hdc/pcie/common/hdcdrv_core.c:755-781` @ `hdcdrv_copy_from_user`
**模块**: hdc_communication

**描述**: copy_from_user operation with cmd->len parameter from user input. While block_head checks exist, the length parameter needs additional validation against allocation size. Could cause buffer overflow if len exceeds allocation.

**达成路径**

user_space@ioctl -> hdcdrv_copy_from_user -> block_head_dma_buf

**验证说明**: copy_from_user uses cmd->len from user input. Basic parameter validation exists but length needs verification against allocation size to prevent buffer overflow.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: : | 6: 3 | 7: 0 | 8: , | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: : | 22: 2 | 23: 0 | 24: , | 25: c | 26: o | 27: n | 28: t | 29: r | 30: o | 31: l | 32: l | 33: a | 34: b | 35: i | 36: l | 37: i | 38: t | 39: y | 40: : | 41: 1 | 42: 5 | 43: , | 44: m | 45: i | 46: t | 47: i | 48: g | 49: a | 50: t | 51: i | 52: o | 53: n | 54: s | 55: : | 56: 1 | 57: 0 | 58: , | 59: f | 60: i | 61: n | 62: a | 63: l | 64: : | 65: 5 | 66: 5 | 67: }

---

### [SVM-002] Insufficient Memory Range Validation - devmm_mmap_vma_check

**严重性**: Medium | **CWE**: CWE-119 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/svm/v2/common/svm_module_ops.c:112-132` @ `devmm_mmap_vma_check`
**模块**: svm_memory

**描述**: devmm_mmap_vma_check validates VMA addresses against hardcoded mmap_para.segs but does not validate against actual allocated memory ranges. An attacker could potentially map memory outside valid process bounds through crafted VMA manipulation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/svm/v2/common/svm_module_ops.c:112-132`)

```c
static int devmm_mmap_vma_check(u32 seg_id, ka_vm_area_struct_t *vma) { mmap_va = devmm_svm->mmap_para.segs[seg_id].va; mmap_size = devmm_svm->mmap_para.segs[seg_id].size; if ((ka_mm_get_vm_start(vma) != mmap_va) ... return -EINVAL; }
```

**达成路径**

VMA address -> devmm_mmap_vma_check -> devmm_svm_mmap -> memory mapping

**验证说明**: VMA validation against hardcoded mmap_para.segs, not actual allocation. Exploitation path unclear due to existing bounds checks, but design flaw exists.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: d | 23: i | 24: r | 25: e | 26: c | 27: t | 28: _ | 29: e | 30: x | 31: t | 32: e | 33: r | 34: n | 35: a | 36: l | 37: + | 38: 3 | 39: 0 | 40: ( | 41: m | 42: m | 43: a | 44: p | 45: ) | 46: , | 47:   | 48: c | 49: o | 50: n | 51: t | 52: r | 53: o | 54: l | 55: l | 56: a | 57: b | 58: i | 59: l | 60: i | 61: t | 62: y | 63: = | 64: p | 65: a | 66: r | 67: t | 68: i | 69: a | 70: l | 71: + | 72: 1 | 73: 5 | 74: , | 75:   | 76: m | 77: i | 78: t | 79: i | 80: g | 81: a | 82: t | 83: i | 84: o | 85: n | 86: s | 87: = | 88: b | 89: o | 90: u | 91: n | 92: d | 93: s | 94: _ | 95: c | 96: h | 97: e | 98: c | 99: k | 100: - | 101: 1 | 102: 0

---

### [ASCEND_HAL-006] buffer_overread - dsmi_msg_recev

**严重性**: Medium | **CWE**: CWE-126 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/ascend_hal/dmc/dsmi/dsmi_common/dsmi_common.c:203` @ `dsmi_msg_recev`
**模块**: ascend_hal

**描述**: Buffer Overread in Message Copy - memcpy_s uses dmp_cmd->recv_msg.data_len or recv->msg.data_len but both could be manipulated by malicious device response

**验证说明**: Buffer overread risk: data_len values from device response used directly in memcpy_s without validation. Malicious device could manipulate data_len.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: -10 | veto: false

---

### [SDK-KVMDT-001] Buffer_Overflow - hw_vdavinci_ioctl

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-120 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/vascend/kvmdt.c:1022-1035` @ `hw_vdavinci_ioctl`
**模块**: sdk_driver

**描述**: kvmdt.c uses copy_from_user/copy_to_user without proper size validation in multiple ioctl handlers. data_size is computed from user header without bounds checking.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/vascend/kvmdt.c:1022-1035`)

```c
if (copy_from_user(&hdr, (void __user *)arg, minsz) != 0) { ... data = memdup_user((void __user *)(arg + minsz), data_size); }
```

**达成路径**

user_ioctl -> copy_from_user -> memdup_user

**验证说明**: LIKELY: Relies on vfio_set_irqs_validate_and_prepare for bounds validation. While VFIO framework provides some protection, the driver-specific validation may have gaps. Standard VFIO validation may not cover all driver-specific constraints.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7: , | 8: r | 9: e | 10: a | 11: c | 12: h | 13: a | 14: b | 15: i | 16: l | 17: i | 18: t | 19: y | 20: : | 21: + | 22: 3 | 23: 0 | 24: ( | 25: i | 26: o | 27: c | 28: t | 29: l | 30: ) | 31: , | 32: c | 33: o | 34: n | 35: t | 36: r | 37: o | 38: l | 39: l | 40: a | 41: b | 42: i | 43: l | 44: i | 45: t | 46: y | 47: : | 48: + | 49: 1 | 50: 5 | 51: , | 52: m | 53: i | 54: t | 55: i | 56: g | 57: a | 58: t | 59: i | 60: o | 61: n | 62: s | 63: : | 64: - | 65: 1 | 66: 0 | 67: ( | 68: v | 69: f | 70: i | 71: o | 72: _ | 73: v | 74: a | 75: l | 76: i | 77: d | 78: a | 79: t | 80: i | 81: o | 82: n | 83: )

---

### [SVM-PID-LIST-008] PID List Time Check Insufficient - devmm_pid_set_share_status

**严重性**: Medium | **CWE**: CWE-287 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/sdk_driver/svm/v2/master/comm/svm_master_mem_share.c:199-203` @ `devmm_pid_set_share_status`
**模块**: svm_memory

**描述**: 共享内存PID白名单的启动时间验证可能失效。devmm_pid_set_share_status通过list_node->set_time < start_time检查进程是否为新进程，但start_time来自devmm_get_tgid_start_time，在进程快速重启或fork场景可能被绕过。恶意进程可利用PID重用时间窗口访问共享内存。

**漏洞代码** (`src/sdk_driver/svm/v2/master/comm/svm_master_mem_share.c:199-203`)

```c
if (list_node->set_time < start_time) { ka_task_up_write(&mng->rw_sem); devmm_drv_err(...); return -EACCES; }
```

**达成路径**

Old PID set_time recorded -> Process exits -> New process with same PID -> start_time < set_time -> bypass denied

**验证说明**: Time check at lines 199-203 can be bypassed via PID reuse. devmm_get_tgid_start_time may not be accurate in fork/restart scenarios.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: i | 23: o | 24: c | 25: t | 26: l | 27: _ | 28: i | 29: m | 30: p | 31: o | 32: r | 33: t | 34: + | 35: 2 | 36: 5 | 37: , | 38:   | 39: c | 40: o | 41: n | 42: t | 43: r | 44: o | 45: l | 46: l | 47: a | 48: b | 49: i | 50: l | 51: i | 52: t | 53: y | 54: = | 55: p | 56: a | 57: r | 58: t | 59: i | 60: a | 61: l | 62: + | 63: 1 | 64: 5 | 65: , | 66:   | 67: m | 68: i | 69: t | 70: i | 71: g | 72: a | 73: t | 74: i | 75: o | 76: n | 77: s | 78: = | 79: t | 80: i | 81: m | 82: e | 83: _ | 84: c | 85: h | 86: e | 87: c | 88: k | 89: - | 90: 1 | 91: 0 | 92: ( | 93: b | 94: y | 95: p | 96: a | 97: s | 98: s | 99: a | 100: b | 101: l | 102: e | 103: )

---

### [ROCE-VULN-003] array_index_validation - hns_roce_lite_poll_one_set_wc

**严重性**: Medium（原评估: HIGH → 验证后: Medium） | **CWE**: CWE-129 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite.c:585-594` @ `hns_roce_lite_poll_one_set_wc`
**模块**: roce_network

**描述**: WQE index (wqe_ctr) extracted from untrusted CQE used for wrid array access without validation. The 16-bit WQE index from CQE is used in arithmetic operations and could cause out-of-bounds access if the index exceeds wqe_cnt.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite.c:585-594`)

```c
wqe_ctr = roce_get_field(cqe->byte_4, CQE_BYTE_4_WQE_IDX_M, CQE_BYTE_4_WQE_IDX_S); lite_wq->tail += (wqe_ctr - lite_wq->tail) & ...;
```

**达成路径**

CQE[network] -> byte_4 -> wqe_ctr -> tail update -> wrid[] access

**验证说明**: POSSIBLE: WQE index from CQE used for wrid array access. Mask (wqe_cnt-1) provides bounds. But same issue as ROCE-001 if wqe_cnt is 0.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: d | 29: i | 30: r | 31: e | 32: c | 33: t | 34: _ | 35: e | 36: x | 37: t | 38: e | 39: r | 40: n | 41: a | 42: l | 43: , | 44: r | 45: e | 46: a | 47: c | 48: h | 49: a | 50: b | 51: i | 52: l | 53: i | 54: t | 55: y | 56: _ | 57: s | 58: c | 59: o | 60: r | 61: e | 62: : | 63: 3 | 64: 0 | 65: , | 66: c | 67: o | 68: n | 69: t | 70: r | 71: o | 72: l | 73: l | 74: a | 75: b | 76: i | 77: l | 78: i | 79: t | 80: y | 81: : | 82: l | 83: e | 84: n | 85: g | 86: t | 87: h | 88: _ | 89: o | 90: n | 91: l | 92: y | 93: , | 94: c | 95: o | 96: n | 97: t | 98: r | 99: o | 100: l | 101: l | 102: a | 103: b | 104: i | 105: l | 106: i | 107: t | 108: y | 109: _ | 110: s | 111: c | 112: o | 113: r | 114: e | 115: : | 116: 1 | 117: 0 | 118: , | 119: m | 120: i | 121: t | 122: i | 123: g | 124: a | 125: t | 126: i | 127: o | 128: n | 129: s | 130: : | 131: [ | 132: m | 133: a | 134: s | 135: k | 136: _ | 137: b | 138: o | 139: u | 140: n | 141: d | 142: s | 143: ] | 144: , | 145: m | 146: i | 147: t | 148: i | 149: g | 150: a | 151: t | 152: i | 153: o | 154: n | 155: _ | 156: s | 157: c | 158: o | 159: r | 160: e | 161: : | 162: - | 163: 1 | 164: 0 | 165: , | 166: f | 167: i | 168: n | 169: a | 170: l | 171: _ | 172: s | 173: c | 174: o | 175: r | 176: e | 177: : | 178: 6 | 179: 0 | 180: }

---

### [ROCE-VULN-005] integer_overflow - get_cqe

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite.c:540-543` @ `get_cqe`
**模块**: roce_network

**描述**: Potential integer overflow in CQE pointer calculation. Entry value multiplied by cqe_size for CQE buffer access. If entry * cqe_size exceeds buffer bounds, could cause out-of-bounds read of CQE data.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite.c:540-543`)

```c
return (struct hns_roce_lite_cqe *)((char *)cq->cq_buf.hva + (u32)(entry * cq->cqe_size));
```

**达成路径**

entry -> entry * cqe_size -> cq_buf.hva offset

**验证说明**: POSSIBLE: Same as ROCE-002. CQE pointer calculation uses mask via depth-1. Mitigation present.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: d | 29: i | 30: r | 31: e | 32: c | 33: t | 34: _ | 35: e | 36: x | 37: t | 38: e | 39: r | 40: n | 41: a | 42: l | 43: , | 44: r | 45: e | 46: a | 47: c | 48: h | 49: a | 50: b | 51: i | 52: l | 53: i | 54: t | 55: y | 56: _ | 57: s | 58: c | 59: o | 60: r | 61: e | 62: : | 63: 3 | 64: 0 | 65: , | 66: c | 67: o | 68: n | 69: t | 70: r | 71: o | 72: l | 73: l | 74: a | 75: b | 76: i | 77: l | 78: i | 79: t | 80: y | 81: : | 82: l | 83: e | 84: n | 85: g | 86: t | 87: h | 88: _ | 89: o | 90: n | 91: l | 92: y | 93: , | 94: c | 95: o | 96: n | 97: t | 98: r | 99: o | 100: l | 101: l | 102: a | 103: b | 104: i | 105: l | 106: i | 107: t | 108: y | 109: _ | 110: s | 111: c | 112: o | 113: r | 114: e | 115: : | 116: 1 | 117: 0 | 118: , | 119: m | 120: i | 121: t | 122: i | 123: g | 124: a | 125: t | 126: i | 127: o | 128: n | 129: s | 130: : | 131: [ | 132: m | 133: a | 134: s | 135: k | 136: _ | 137: b | 138: o | 139: u | 140: n | 141: d | 142: s | 143: ] | 144: , | 145: m | 146: i | 147: t | 148: i | 149: g | 150: a | 151: t | 152: i | 153: o | 154: n | 155: _ | 156: s | 157: c | 158: o | 159: r | 160: e | 161: : | 162: - | 163: 1 | 164: 0 | 165: , | 166: f | 167: i | 168: n | 169: a | 170: l | 171: _ | 172: s | 173: c | 174: o | 175: r | 176: e | 177: : | 178: 6 | 179: 0 | 180: }

---

### [HDC-005] privilege_escalation - hdcdrv_check_session_owner

**严重性**: Medium | **CWE**: CWE-287 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/hdc/pcie/common/hdcdrv_core.c:436-449` @ `hdcdrv_check_session_owner`
**模块**: hdc_communication
**跨模块**: hdc_communication:process_management

**描述**: Session ownership check relies on PID and task_start_time comparison which may be insufficient in containerized environments. Container ID verification added but may not cover all isolation scenarios. Could allow unauthorized session access.

**达成路径**

user_process@ioctl -> hdcdrv_check_session_owner -> session_operations

**验证说明**: Session ownership uses PID + task_start_time comparison which is reasonable for traditional environments. However, containerized environments may have PID namespace isolation issues. Container ID verification added but may not cover all isolation scenarios.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: : | 6: 3 | 7: 0 | 8: , | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: : | 22: 2 | 23: 0 | 24: , | 25: c | 26: o | 27: n | 28: t | 29: r | 30: o | 31: l | 32: l | 33: a | 34: b | 35: i | 36: l | 37: i | 38: t | 39: y | 40: : | 41: 1 | 42: 5 | 43: , | 44: m | 45: i | 46: t | 47: i | 48: g | 49: a | 50: t | 51: i | 52: o | 53: n | 54: s | 55: : | 56: 1 | 57: 5 | 58: , | 59: f | 60: i | 61: n | 62: a | 63: l | 64: : | 65: 5 | 66: 0 | 67: }

---

### [ROCE-002-OOB-READ-CQE] Memory Corruption - get_cqe

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite.c:540-542` @ `get_cqe`
**模块**: roce_network

**描述**: Out-of-bounds read in CQE processing. get_cqe() calculates CQE address using entry * cq->cqe_size without validating that entry is within cq->depth bounds. Malformed network packets could trigger this.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite.c:540-542`)

```c
return (struct hns_roce_lite_cqe *)((char *)cq->cq_buf.hva + (u32)(entry * cq->cqe_size));
```

**达成路径**

Network CQE hardware entry -> get_cqe -> memory access without bounds check

**验证说明**: Verified: get_cqe() calculates CQE address via entry*cqe_size. Mitigation present: get_sw_cqe uses n&(depth-1) mask for bounds. However, requires depth to be non-zero power of 2.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: d | 29: i | 30: r | 31: e | 32: c | 33: t | 34: _ | 35: e | 36: x | 37: t | 38: e | 39: r | 40: n | 41: a | 42: l | 43: , | 44: r | 45: e | 46: a | 47: c | 48: h | 49: a | 50: b | 51: i | 52: l | 53: i | 54: t | 55: y | 56: _ | 57: s | 58: c | 59: o | 60: r | 61: e | 62: : | 63: 3 | 64: 0 | 65: , | 66: c | 67: o | 68: n | 69: t | 70: r | 71: o | 72: l | 73: l | 74: a | 75: b | 76: i | 77: l | 78: i | 79: t | 80: y | 81: : | 82: p | 83: a | 84: r | 85: t | 86: i | 87: a | 88: l | 89: , | 90: c | 91: o | 92: n | 93: t | 94: r | 95: o | 96: l | 97: l | 98: a | 99: b | 100: i | 101: l | 102: i | 103: t | 104: y | 105: _ | 106: s | 107: c | 108: o | 109: r | 110: e | 111: : | 112: 1 | 113: 5 | 114: , | 115: m | 116: i | 117: t | 118: i | 119: g | 120: a | 121: t | 122: i | 123: o | 124: n | 125: s | 126: : | 127: [ | 128: b | 129: o | 130: u | 131: n | 132: d | 133: s | 134: _ | 135: c | 136: h | 137: e | 138: c | 139: k | 140: _ | 141: v | 142: i | 143: a | 144: _ | 145: m | 146: a | 147: s | 148: k | 149: ] | 150: , | 151: m | 152: i | 153: t | 154: i | 155: g | 156: a | 157: t | 158: i | 159: o | 160: n | 161: _ | 162: s | 163: c | 164: o | 165: r | 166: e | 167: : | 168: - | 169: 1 | 170: 5 | 171: , | 172: f | 173: i | 174: n | 175: a | 176: l | 177: _ | 178: s | 179: c | 180: o | 181: r | 182: e | 183: : | 184: 6 | 185: 0 | 186: }

---

### [ROCE-009-ATOMIC-WRITE-VALID] Input Validation - set_atom_write_seg

**严重性**: Medium | **CWE**: CWE-680 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite.c:1066-1081` @ `set_atom_write_seg`
**模块**: roce_network

**描述**: Incomplete validation in atomic write segment. set_atom_write_seg() only checks total_len > sizeof(uint32_t) but does not validate minimum size or that the data actually exists. Could allow processing of invalid atomic operations.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite.c:1066-1081`)

```c
if (sge_info->total_len > sizeof(uint32_t)) { return -EINVAL; }
```

**达成路径**

RDMA atomic write request -> incomplete validation -> potential hardware issue

**验证说明**: POSSIBLE: set_atom_write_seg() checks total_len > sizeof(uint32_t) but does not validate minimum size or data existence. Network-triggered atomic write could pass incomplete validation.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: d | 29: i | 30: r | 31: e | 32: c | 33: t | 34: _ | 35: e | 36: x | 37: t | 38: e | 39: r | 40: n | 41: a | 42: l | 43: , | 44: r | 45: e | 46: a | 47: c | 48: h | 49: a | 50: b | 51: i | 52: l | 53: i | 54: t | 55: y | 56: _ | 57: s | 58: c | 59: o | 60: r | 61: e | 62: : | 63: 3 | 64: 0 | 65: , | 66: c | 67: o | 68: n | 69: t | 70: r | 71: o | 72: l | 73: l | 74: a | 75: b | 76: i | 77: l | 78: i | 79: t | 80: y | 81: : | 82: p | 83: a | 84: r | 85: t | 86: i | 87: a | 88: l | 89: , | 90: c | 91: o | 92: n | 93: t | 94: r | 95: o | 96: l | 97: l | 98: a | 99: b | 100: i | 101: l | 102: i | 103: t | 104: y | 105: _ | 106: s | 107: c | 108: o | 109: r | 110: e | 111: : | 112: 1 | 113: 5 | 114: , | 115: m | 116: i | 117: t | 118: i | 119: g | 120: a | 121: t | 122: i | 123: o | 124: n | 125: s | 126: : | 127: [ | 128: s | 129: i | 130: z | 131: e | 132: _ | 133: c | 134: h | 135: e | 136: c | 137: k | 138: ] | 139: , | 140: m | 141: i | 142: t | 143: i | 144: g | 145: a | 146: t | 147: i | 148: o | 149: n | 150: _ | 151: s | 152: c | 153: o | 154: r | 155: e | 156: : | 157: - | 158: 1 | 159: 5 | 160: , | 161: f | 162: i | 163: n | 164: a | 165: l | 166: _ | 167: s | 168: c | 169: o | 170: r | 171: e | 172: : | 173: 6 | 174: 0 | 175: }

---

### [SVM-005] Potential Race Condition in Memory Operations - devmm_ioctl_mem_unmap

**严重性**: Medium | **CWE**: CWE-367 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/svm/v2/master/comm/svm_master_mem_map.c:513-581` @ `devmm_ioctl_mem_unmap`
**模块**: svm_memory

**描述**: TOCTOU race condition possible between vmma_get and vmma_exclusive_set in devmm_ioctl_mem_unmap. The vmma structure is obtained, validated, then locked - potentially allowing concurrent modification between get and lock operations.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/svm/v2/master/comm/svm_master_mem_map.c:513-581`)

```c
int devmm_ioctl_mem_unmap(...) { vmma = devmm_vmma_get(&heap->vmma_mng, para->va); ... ret = devmm_vmma_exclusive_set(vmma); ... devmm_access_munmap_all(svm_proc, vmma); }
```

**达成路径**

Thread A: vmma_get -> Thread B: vmma_modify -> Thread A: exclusive_set

**验证说明**: TOCTOU window between devmm_vmma_get(line 534) and devmm_vmma_exclusive_set(line 547). Exploitation requires precise timing and impact limited.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: = | 5: 3 | 6: 0 | 7: , | 8:   | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: = | 22: d | 23: i | 24: r | 25: e | 26: c | 27: t | 28: _ | 29: e | 30: x | 31: t | 32: e | 33: r | 34: n | 35: a | 36: l | 37: + | 38: 3 | 39: 0 | 40: ( | 41: i | 42: o | 43: c | 44: t | 45: l | 46: ) | 47: , | 48:   | 49: c | 50: o | 51: n | 52: t | 53: r | 54: o | 55: l | 56: l | 57: a | 58: b | 59: i | 60: l | 61: i | 62: t | 63: y | 64: = | 65: p | 66: a | 67: r | 68: t | 69: i | 70: a | 71: l | 72: + | 73: 1 | 74: 5 | 75: , | 76:   | 77: m | 78: i | 79: t | 80: i | 81: g | 82: a | 83: t | 84: i | 85: o | 86: n | 87: s | 88: = | 89: l | 90: o | 91: c | 92: k | 93: i | 94: n | 95: g | 96: - | 97: 1 | 98: 5 | 99: ( | 100: p | 101: a | 102: r | 103: t | 104: i | 105: a | 106: l | 107: )

---

### [ASCEND_HAL-004] improper_input_validation - halSqTaskArgsAsyncCopy

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/ascend_hal/trs/core/trs_interface.c:417` @ `halSqTaskArgsAsyncCopy`
**模块**: ascend_hal

**描述**: Missing Size Validation for DMA Copy - halSqTaskArgsAsyncCopy checks src/dst/size but does not validate size bounds against actual buffer capacity

**验证说明**: Missing upper bound validation for DMA copy size. src/dst/size checked for non-zero but no maximum size limit. Could lead to excessive memory operations.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: -10 | veto: false

---

### [SDK-TRSFOPS-001] Missing_Access_Control - trs_ioctl

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-287 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/trsdrv/trs/trs_core/trs_fops.c:1211-1256` @ `trs_ioctl`
**模块**: sdk_driver
**跨模块**: sdk_driver,pbl

**描述**: trs_ioctl function lacks comprehensive privilege validation before processing ioctl commands. The trs_ioctl_cmd_is_support only checks device existence and feature mode, but does not validate caller capabilities.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/trsdrv/trs/trs_core/trs_fops.c:1211-1256`)

```c
static long trs_ioctl(ka_file_t *file, unsigned int cmd, unsigned long arg) { ... return (long)trs_ioctl_handles[cmd_nr](proc_ctx, cmd, arg); }
```

**达成路径**

user_space -> trs_ioctl -> trs_ioctl_handles

**验证说明**: LIKELY: Has partial validation (trs_proc_support_cmd_check, trs_ioctl_cmd_is_support) but missing explicit capability check. Device existence check provides partial mitigation but not sufficient for privilege-sensitive operations.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7: , | 8: r | 9: e | 10: a | 11: c | 12: h | 13: a | 14: b | 15: i | 16: l | 17: i | 18: t | 19: y | 20: : | 21: + | 22: 3 | 23: 0 | 24: ( | 25: i | 26: o | 27: c | 28: t | 29: l | 30: ) | 31: , | 32: c | 33: o | 34: n | 35: t | 36: r | 37: o | 38: l | 39: l | 40: a | 41: b | 42: i | 43: l | 44: i | 45: t | 46: y | 47: : | 48: + | 49: 1 | 50: 5 | 51: , | 52: m | 53: i | 54: t | 55: i | 56: g | 57: a | 58: t | 59: i | 60: o | 61: n | 62: s | 63: : | 64: - | 65: 1 | 66: 5 | 67: ( | 68: p | 69: a | 70: r | 71: t | 72: i | 73: a | 74: l | 75: _ | 76: v | 77: a | 78: l | 79: i | 80: d | 81: a | 82: t | 83: i | 84: o | 85: n | 86: )

---

### [SDK-VNIC-001] Buffer_Overflow - pcivnic_dma_map_single

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/vnic/host/pcivnic_host.c:358-392` @ `pcivnic_dma_map_single`
**模块**: sdk_driver
**跨模块**: sdk_driver,vnic

**描述**: pcivnic_skb_data_buff_init allocates PCIVNIC_MAX_SKB_BUFF_SIZE buffers without proper bounds checking. DMA buffers are mapped without verifying skb->len fits within allocated size.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/vnic/host/pcivnic_host.c:358-392`)

```c
dma_addr = hal_kernel_devdrv_dma_map_single(pcidev->dev, skb->data, len, dma_dir);
```

**达成路径**

skb_data -> dma_map_single -> device

**验证说明**: LIKELY: DMA mapping uses skb->len for TX without explicit validation against PCIVNIC_MAX_SKB_BUFF_SIZE. For RX, fixed PCIVNIC_MAX_PKT_SIZE used. Potential for buffer overflow if skb->len exceeds allocated buffer, though SKB allocation typically bounds size.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7: , | 8: r | 9: e | 10: a | 11: c | 12: h | 13: a | 14: b | 15: i | 16: l | 17: i | 18: t | 19: y | 20: : | 21: + | 22: 3 | 23: 0 | 24: ( | 25: d | 26: m | 27: a | 28: _ | 29: m | 30: a | 31: p | 32: ) | 33: , | 34: c | 35: o | 36: n | 37: t | 38: r | 39: o | 40: l | 41: l | 42: a | 43: b | 44: i | 45: l | 46: i | 47: t | 48: y | 49: : | 50: + | 51: 1 | 52: 0 | 53: , | 54: m | 55: i | 56: t | 57: i | 58: g | 59: a | 60: t | 61: i | 62: o | 63: n | 64: s | 65: : | 66: - | 67: 1 | 68: 0 | 69: ( | 70: s | 71: k | 72: b | 73: _ | 74: l | 75: e | 76: n | 77: _ | 78: c | 79: h | 80: e | 81: c | 82: k | 83: : | 84: p | 85: a | 86: r | 87: t | 88: i | 89: a | 90: l | 91: )

---

### [SDK-MMAP-001] Missing_Access_Control - trs_mmap

**严重性**: Medium | **CWE**: CWE-287 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/trsdrv/trs/trs_core/trs_fops.c:1485-1497` @ `trs_mmap`
**模块**: sdk_driver

**描述**: Multiple mmap handlers (trs_mmap, rmo_mmap) expose kernel memory to user space without proper access control checks. VM flags are set but caller permissions not validated.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/trsdrv/trs/trs_core/trs_fops.c:1485-1497`)

```c
ka_mm_set_vm_flags(vma, ... | KA_VM_LOCKED | KA_VM_DONTEXPAND | KA_VM_DONTDUMP | KA_VM_DONTCOPY | KA_VM_IO | KA_VM_PFNMAP)
```

**达成路径**

user_mmap -> vm_flags -> kernel_memory

**验证说明**: LIKELY: trs_mmap sets VM_IO, VM_PFNMAP, VM_DONTCOPY flags but lacks explicit capability check. However, trs_mmap_open checks uda_can_access_udevid() providing device-level access control. mmap path may bypass this check in some configurations.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7: , | 8: r | 9: e | 10: a | 11: c | 12: h | 13: a | 14: b | 15: i | 16: l | 17: i | 18: t | 19: y | 20: : | 21: + | 22: 3 | 23: 0 | 24: ( | 25: m | 26: m | 27: a | 28: p | 29: ) | 30: , | 31: c | 32: o | 33: n | 34: t | 35: r | 36: o | 37: l | 38: l | 39: a | 40: b | 41: i | 42: l | 43: i | 44: t | 45: y | 46: : | 47: + | 48: 1 | 49: 5 | 50: , | 51: m | 52: i | 53: t | 54: i | 55: g | 56: a | 57: t | 58: i | 59: o | 60: n | 61: s | 62: : | 63: - | 64: 1 | 65: 5 | 66: ( | 67: v | 68: m | 69: _ | 70: f | 71: l | 72: a | 73: g | 74: s | 75: )

---

### [HDC-009] privilege_escalation - hdcdrv_uid_privilege_get

**严重性**: Medium | **CWE**: CWE-269 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/hdc/pcie/common/hdcdrv_core.c:4782-4793` @ `hdcdrv_uid_privilege_get`
**模块**: hdc_communication
**跨模块**: hdc_communication:session_management

**描述**: UID privilege check for connect messages may not properly handle virtualization scenarios. VF devices and container environments may have different privilege requirements. Could allow unauthorized privilege escalation in virtualized environments.

**达成路径**

user_process@connect_msg -> hdcdrv_uid_privilege_get -> session_privilege

**验证说明**: UID privilege check handles VF devices with special case. Virtualization scenarios are complex and may have different privilege requirements. May not cover all virtualization isolation scenarios.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: : | 6: 3 | 7: 0 | 8: , | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: : | 22: 2 | 23: 0 | 24: , | 25: c | 26: o | 27: n | 28: t | 29: r | 30: o | 31: l | 32: l | 33: a | 34: b | 35: i | 36: l | 37: i | 38: t | 39: y | 40: : | 41: 1 | 42: 5 | 43: , | 44: m | 45: i | 46: t | 47: i | 48: g | 49: a | 50: t | 51: i | 52: o | 53: n | 54: s | 55: : | 56: 1 | 57: 5 | 58: , | 59: f | 60: i | 61: n | 62: a | 63: l | 64: : | 65: 5 | 66: 0 | 67: }

---

### [VULN-LQDRV-004] buffer_size_validation - lq_get_fault_event_head_info

**严重性**: Medium | **CWE**: CWE-130 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/custom/lqdrv/kernel/ioctl_comm.c:65-84` @ `lq_get_fault_event_head_info`
**模块**: lqdrv_custom

**描述**: lq_get_fault_event_head_info does not validate user-provided out_size before copy_to_user. While IOCTL_GET_NODE_INFO has size check at line 92, IOCTL_GET_HEAD_INFO copies sizeof(SramDescCtlHeader) without verifying user buffer capacity.

**漏洞代码** (`src/custom/lqdrv/kernel/ioctl_comm.c:65-84`)

```c
ret = copy_to_user(ioctl_cmd->out_addr, &info_pipe, sizeof(SramDescCtlHeader));
```

**达成路径**

ioctl_cmd(from_user) -> lq_get_fault_event_head_info -> copy_to_user

**验证说明**: LIKELY: lq_get_fault_event_head_info does not validate out_size against sizeof(SramDescCtlHeader) before copy_to_user. IOCTL_GET_NODE_INFO has size check at line 92, but IOCTL_GET_HEAD_INFO lacks equivalent validation. Could overflow user buffer if smaller than expected.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 5 | final: 55

---

### [VULN-LQDRV-007] memory_operation - get_all_fault_by_pci

**严重性**: Medium | **CWE**: CWE-787 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/custom/lqdrv/kernel/ioctl_comm.c:86-122` @ `get_all_fault_by_pci`
**模块**: lqdrv_custom

**描述**: memcpy_s at line 103 copies g_kernel_event_table to temp_table using table_size derived from CAPACITY constant. While size check exists at line 92, the check uses user-provided out_size which could be manipulated.

**漏洞代码** (`src/custom/lqdrv/kernel/ioctl_comm.c:86-122`)

```c
ret = memcpy_s(temp_table, table_size, g_kernel_event_table, table_size);
```

**达成路径**

ka_base_copy_from_user -> ioctl_cmd.out_size -> size_check -> memcpy_s -> copy_to_user

**验证说明**: LIKELY: memcpy_s at line 103 uses table_size from CAPACITY constant. While size check exists at line 92 (ioctl_cmd->out_size < table_size), the check uses user-provided out_size which could theoretically be manipulated. However, the memcpy itself uses safe constant-derived size.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 10 | final: 55

---

### [SDK-XSMEM-001] TOCTOU - ioctl_xsmem_pool_register

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-367 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/buff/dc/buff_host/xsmem_framework.c:1050-1067` @ `ioctl_xsmem_pool_register`
**模块**: sdk_driver

**描述**: xsmem_framework ioctl handlers copy user data twice without atomic validation. copy_from_user_safe copies struct then copies embedded pointers, creating TOCTOU window between validations.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/buff/dc/buff_host/xsmem_framework.c:1050-1067`)

```c
if (copy_from_user_safe(&reg_arg, ...) != 0) { ... if (copy_from_user_safe(key, ...) != 0) }
```

**达成路径**

user_input -> copy_from_user_safe -> validation -> copy_from_user_safe(key)

**验证说明**: LIKELY: Has xsmem_confirm_user() check for authorized user validation. However, two separate copy_from_user calls for embedded pointer create potential TOCTOU window. Key validation happens after second copy, mitigating immediate exploitation.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7: , | 8: r | 9: e | 10: a | 11: c | 12: h | 13: a | 14: b | 15: i | 16: l | 17: i | 18: t | 19: y | 20: : | 21: + | 22: 3 | 23: 0 | 24: ( | 25: i | 26: o | 27: c | 28: t | 29: l | 30: ) | 31: , | 32: c | 33: o | 34: n | 35: t | 36: r | 37: o | 38: l | 39: l | 40: a | 41: b | 42: i | 43: l | 44: i | 45: t | 46: y | 47: : | 48: + | 49: 1 | 50: 5 | 51: , | 52: m | 53: i | 54: t | 55: i | 56: g | 57: a | 58: t | 59: i | 60: o | 61: n | 62: s | 63: : | 64: - | 65: 2 | 66: 0 | 67: ( | 68: x | 69: s | 70: m | 71: e | 72: m | 73: _ | 74: c | 75: o | 76: n | 77: f | 78: i | 79: r | 80: m | 81: _ | 82: u | 83: s | 84: e | 85: r | 86: : | 87: p | 88: r | 89: e | 90: s | 91: e | 92: n | 93: t | 94: )

---

### [SDK-QUEUE-001] Unvalidated_User_Input - queue_get_vector

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/queue/host/queue_fops.c:179-206` @ `queue_get_vector`
**模块**: sdk_driver
**跨模块**: sdk_driver,queue

**描述**: queue_fop_enqueue copies user iovec data without sufficient bounds validation. iovec_count is checked against QUEUE_MAX_IOVEC_NUM but individual iovec lengths are not validated.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/queue/host/queue_fops.c:179-206`)

```c
vector_len = sizeof(struct buff_iovec) + para->iovec_count * sizeof(struct iovec_info); ... ka_base_copy_from_user(vector, para->vector, vector_len)
```

**达成路径**

user_iovec -> copy_from_user -> queue_chan

**验证说明**: LIKELY: queue_check_vector validates iovec_base!=NULL and len!=0, and checks count match. However, individual iovec lengths not validated against QUEUE_MAX_IOVEC_NUM or max buffer size. Potential for excessive memory allocation via large iovec structures.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7: , | 8: r | 9: e | 10: a | 11: c | 12: h | 13: a | 14: b | 15: i | 16: l | 17: i | 18: t | 19: y | 20: : | 21: + | 22: 3 | 23: 0 | 24: ( | 25: i | 26: o | 27: c | 28: t | 29: l | 30: ) | 31: , | 32: c | 33: o | 34: n | 35: t | 36: r | 37: o | 38: l | 39: l | 40: a | 41: b | 42: i | 43: l | 44: i | 45: t | 46: y | 47: : | 48: + | 49: 1 | 50: 0 | 51: , | 52: m | 53: i | 54: t | 55: i | 56: g | 57: a | 58: t | 59: i | 60: o | 61: n | 62: s | 63: : | 64: - | 65: 1 | 66: 5 | 67: ( | 68: q | 69: u | 70: e | 71: u | 72: e | 73: _ | 74: c | 75: h | 76: e | 77: c | 78: k | 79: _ | 80: v | 81: e | 82: c | 83: t | 84: o | 85: r | 86: )

---

### [SDK-ESCHED-001] Missing_Access_Control - sched_fop_query_sync_msg_trace

**严重性**: Medium | **CWE**: CWE-287 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/esched/dc/host_adapt/esched_adapt.c:31-53` @ `sched_fop_query_sync_msg_trace`
**模块**: sdk_driver

**描述**: sched_fop_query_sync_msg_trace copies user data directly without capability check. Only copy_from_user_safe is used, missing privilege validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/esched/dc/host_adapt/esched_adapt.c:31-53`)

```c
if (copy_from_user_safe(para, (void *)(uintptr_t)arg, sizeof(struct sched_trace_input)) != 0)
```

**达成路径**

user_space -> copy_from_user_safe -> sched_query

**验证说明**: LIKELY: Direct copy_from_user_safe without privilege check. Data copied from user space without capability validation. No apparent access control mechanism for trace query operations. Moderate risk for information disclosure.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7: , | 8: r | 9: e | 10: a | 11: c | 12: h | 13: a | 14: b | 15: i | 16: l | 17: i | 18: t | 19: y | 20: : | 21: + | 22: 3 | 23: 0 | 24: ( | 25: i | 26: o | 27: c | 28: t | 29: l | 30: ) | 31: , | 32: c | 33: o | 34: n | 35: t | 36: r | 37: o | 38: l | 39: l | 40: a | 41: b | 42: i | 43: l | 44: i | 45: t | 46: y | 47: : | 48: + | 49: 1 | 50: 5 | 51: , | 52: m | 53: i | 54: t | 55: i | 56: g | 57: a | 58: t | 59: i | 60: o | 61: n | 62: s | 63: : | 64: - | 65: 1 | 66: 5 | 67: ( | 68: c | 69: o | 70: p | 71: y | 72: _ | 73: f | 74: r | 75: o | 76: m | 77: _ | 78: u | 79: s | 80: e | 81: r | 82: _ | 83: s | 84: a | 85: f | 86: e | 87: )

---

### [lqdrv_custom-V004] Missing Buffer Size Check - lq_get_fault_event_head_info

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/custom/lqdrv/kernel/ioctl_comm.c:65-84` @ `lq_get_fault_event_head_info`
**模块**: lqdrv_custom

**描述**: lq_get_fault_event_head_info copy_to_user without validating out_size.

**漏洞代码** (`src/custom/lqdrv/kernel/ioctl_comm.c:65-84`)

```c
copy_to_user(ioctl_cmd->out_addr, &info_pipe, sizeof(SramDescCtlHeader));
```

**达成路径**

No out_size validation

**验证说明**: LIKELY: lq_get_fault_event_head_info copies sizeof(SramDescCtlHeader) to user without validating out_size buffer capacity. IOCTL_GET_NODE_INFO has size validation but IOCTL_GET_HEAD_INFO lacks equivalent protection.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 5 | final: 55

---

### [ROCE-VULN-008] type_confusion - hns_roce_lite_mark_recv_opcode

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-843 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite.c:668-671` @ `hns_roce_lite_mark_recv_opcode`
**模块**: roce_network

**描述**: Potential type confusion in opcode handling. Unknown/unrecognized opcode from CQE sets status to RDMA_LITE_WC_GENERAL_ERR but execution continues. The lite_wc structure may have inconsistent fields for unrecognized opcodes.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite.c:668-671`)

```c
default: lite_wc->status = RDMA_LITE_WC_GENERAL_ERR; roce_err("unknown opcode: 0x%08x", opcode);
```

**达成路径**

CQE[network] -> opcode -> default case -> incomplete wc fields

**验证说明**: POSSIBLE: Unknown opcode sets RDMA_LITE_WC_GENERAL_ERR and logs error. Execution continues but lite_wc may have incomplete fields. Not a security issue per se, but could cause application confusion.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: d | 29: i | 30: r | 31: e | 32: c | 33: t | 34: _ | 35: e | 36: x | 37: t | 38: e | 39: r | 40: n | 41: a | 42: l | 43: , | 44: r | 45: e | 46: a | 47: c | 48: h | 49: a | 50: b | 51: i | 52: l | 53: i | 54: t | 55: y | 56: _ | 57: s | 58: c | 59: o | 60: r | 61: e | 62: : | 63: 3 | 64: 0 | 65: , | 66: c | 67: o | 68: n | 69: t | 70: r | 71: o | 72: l | 73: l | 74: a | 75: b | 76: i | 77: l | 78: i | 79: t | 80: y | 81: : | 82: p | 83: a | 84: r | 85: t | 86: i | 87: a | 88: l | 89: , | 90: c | 91: o | 92: n | 93: t | 94: r | 95: o | 96: l | 97: l | 98: a | 99: b | 100: i | 101: l | 102: i | 103: t | 104: y | 105: _ | 106: s | 107: c | 108: o | 109: r | 110: e | 111: : | 112: 1 | 113: 5 | 114: , | 115: m | 116: i | 117: t | 118: i | 119: g | 120: a | 121: t | 122: i | 123: o | 124: n | 125: s | 126: : | 127: [ | 128: e | 129: r | 130: r | 131: o | 132: r | 133: _ | 134: h | 135: a | 136: n | 137: d | 138: l | 139: i | 140: n | 141: g | 142: ] | 143: , | 144: m | 145: i | 146: t | 147: i | 148: g | 149: a | 150: t | 151: i | 152: o | 153: n | 154: _ | 155: s | 156: c | 157: o | 158: r | 159: e | 160: : | 161: - | 162: 1 | 163: 5 | 164: , | 165: f | 166: i | 167: n | 168: a | 169: l | 170: _ | 171: s | 172: c | 173: o | 174: r | 175: e | 176: : | 177: 5 | 178: 0 | 179: }

---

### [ROCE-VULN-013] integer_overflow - hns_roce_lite_mmap_hva

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite_stdio.c:279-286` @ `hns_roce_lite_mmap_hva`
**模块**: roce_network
**跨模块**: roce_network,ascend_hal

**描述**: Integer overflow in mmap offset calculation. In hns_roce_lite_mmap_hva, offset is incremented by alloc_size without overflow checking. Accumulated offsets could exceed host_buf.length leading to out-of-bounds memory mapping.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite_stdio.c:279-286`)

```c
alloc_size = align_up(host_buf->length, PAGE_ALIGN_4KB); mem_pool->offset += alloc_size;
```

**达成路径**

alloc_size -> offset accumulation -> potential overflow

**验证说明**: POSSIBLE: mmap offset accumulation in mem_pool->offset. Bounds check present at line 280: if (mem_pool->offset + alloc_size > mem_pool->host_buf.length). Overflow prevented.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: i | 29: n | 30: t | 31: e | 32: r | 33: n | 34: a | 35: l | 36: _ | 37: o | 38: n | 39: l | 40: y | 41: , | 42: r | 43: e | 44: a | 45: c | 46: h | 47: a | 48: b | 49: i | 50: l | 51: i | 52: t | 53: y | 54: _ | 55: s | 56: c | 57: o | 58: r | 59: e | 60: : | 61: 5 | 62: , | 63: c | 64: o | 65: n | 66: t | 67: r | 68: o | 69: l | 70: l | 71: a | 72: b | 73: i | 74: l | 75: i | 76: t | 77: y | 78: : | 79: l | 80: e | 81: n | 82: g | 83: t | 84: h | 85: _ | 86: o | 87: n | 88: l | 89: y | 90: , | 91: c | 92: o | 93: n | 94: t | 95: r | 96: o | 97: l | 98: l | 99: a | 100: b | 101: i | 102: l | 103: i | 104: t | 105: y | 106: _ | 107: s | 108: c | 109: o | 110: r | 111: e | 112: : | 113: 1 | 114: 0 | 115: , | 116: m | 117: i | 118: t | 119: i | 120: g | 121: a | 122: t | 123: i | 124: o | 125: n | 126: s | 127: : | 128: [ | 129: b | 130: o | 131: u | 132: n | 133: d | 134: s | 135: _ | 136: c | 137: h | 138: e | 139: c | 140: k | 141: ] | 142: , | 143: m | 144: i | 145: t | 146: i | 147: g | 148: a | 149: t | 150: i | 151: o | 152: n | 153: _ | 154: s | 155: c | 156: o | 157: r | 158: e | 159: : | 160: - | 161: 1 | 162: 5 | 163: , | 164: f | 165: i | 166: n | 167: a | 168: l | 169: _ | 170: s | 171: c | 172: o | 173: r | 174: e | 175: : | 176: 3 | 177: 0 | 178: }

---

### [VULN-IOCTL-005] TOCTOU Vulnerability - devdrv_bind_hostpid

**严重性**: Medium | **CWE**: CWE-367 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/dms/devmng/drv_devmng/drv_devmng_host/ascend910/devdrv_manager_pid_map.c:856-866` @ `devdrv_bind_hostpid`
**模块**: ioctl_handlers
**跨模块**: ioctl_handlers,devdrv_manager_pid_map

**描述**: In devdrv_bind_hostpid(), the master PID existence check (devdrv_is_master_pid) at line 856 is performed before the parent-child relationship check (check_parent_child_relationship) at line 861. Between these checks, the master process could terminate or the parent-child relationship could change, leading to binding an invalid or unauthorized process. Attack vector: Race condition exploitation during process binding.

**达成路径**

Check master_pid exists -> [race window] -> Check parent-child -> [race window] -> Bind operation

**验证说明**: POSSIBLE: TOCTOU window exists between devdrv_is_master_pid check (line 856) and check_parent_child_relationship (line 861). No locking visible. Race exploitation possible but difficult.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -20

---

### [VULN_QUEUE_008] information_disclosure - queue_check_vector

**严重性**: Medium | **CWE**: CWE-200 | **置信度**: 50/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/queue/host/queue_fops.c:156-170` @ `queue_check_vector`
**模块**: queue_operations

**描述**: 内核地址信息泄露 - 多处日志输出使用%pK格式打印内核地址，在某些内核配置下可能泄露敏感地址信息。

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/queue/host/queue_fops.c:156-170`)

```c
queue_err("ctx_addr(0x%pK) not match ctx_addr_len(%llu).\n", (void *)(uintptr_t)vector->context_base, vector->context_len);
```

**达成路径**

kernel pointer -> log output

**验证说明**: %pK format prints kernel addresses. Visibility depends on kptr_restrict sysctl (0=all visible, 1=restricted, 2=root only). Potential info disclosure if kptr_restrict=0.

**评分明细**: 0: b | 1: a | 2: s | 3: e | 4: : | 5: 3 | 6: 0 | 7:   | 8: + | 9:   | 10: r | 11: e | 12: a | 13: c | 14: h | 15: a | 16: b | 17: i | 18: l | 19: i | 20: t | 21: y | 22: : | 23: i | 24: n | 25: d | 26: i | 27: r | 28: e | 29: c | 30: t | 31: : | 32: 2 | 33: 0 | 34:   | 35: = | 36:   | 37: 5 | 38: 0 | 39:   | 40: ( | 41: c | 42: o | 43: n | 44: f | 45: i | 46: g | 47: _ | 48: d | 49: e | 50: p | 51: e | 52: n | 53: d | 54: e | 55: n | 56: t | 57: )

---

### [VULN-LQDRV-005] hardware_memory_exposure - tc_pci_map

**严重性**: Medium | **CWE**: CWE-732 | **置信度**: 50/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/custom/lqdrv/kernel/pci-dev.c:640-660` @ `tc_pci_map`
**模块**: lqdrv_custom

**描述**: PCIe BAR space is ioremaped and stored in global variables (g_bmc_pci_mem, g_exist_fault_mem, g_bar_flag_mem). These kernel-mapped hardware memory regions could potentially be exposed through mmap interface if proper isolation is not maintained.

**漏洞代码** (`src/custom/lqdrv/kernel/pci-dev.c:640-660`)

```c
g_bmc_pci_mem.pmap_addr = (unsigned long *)ka_mm_ioremap(bar_cpu_base_add, bar_cpu_add_len);
```

**达成路径**

pci_resource_start -> ioremap -> global_pmap_addr -> potential_mmap_exposure

**验证说明**: LIKELY: PCIe BAR space ioremaped at lines 640-660 stored in global variables g_bmc_pci_mem, g_exist_fault_mem, g_bar_flag_mem. While not directly exposed via mmap, the global storage without strict isolation could be leveraged through other interfaces. Requires additional context to confirm exposure path.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | final: 50

---

### [lqdrv_custom-V005] Unvalidated Index in BAR Access - get_node_info

**严重性**: Medium | **CWE**: CWE-119 | **置信度**: 50/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `src/custom/lqdrv/kernel/pci-dev.c:758-802` @ `get_node_info`
**模块**: lqdrv_custom

**描述**: get_node_info uses index parameter directly for BAR memory access without bounds validation. If g_fault_event_head.nodeNum is corrupted (from PCIe BAR read), index % g_fault_event_head.nodeNum can still cause out-of-bounds read from BAR mapped memory.

**漏洞代码** (`src/custom/lqdrv/kernel/pci-dev.c:758-802`)

```c
STATIC int get_node_info(SramFaultEventData *node_info, unsigned int index) {\n    // NO validation that index < g_fault_event_head.nodeNum!\n    node_info->head.msgId = ka_mm_readl(g_tcpci_info->bar_mem_addr + sizeof(SramDescCtlHeader) + sizeof(SramFaultEventData) * index);\n}
```

**达成路径**

Corrupted nodeNum from PCIe BAR -> update_mem_by_map reads corrupted values -> get_node_info uses corrupted bounds -> OOB read

**验证说明**: LIKELY: get_node_info uses index directly for BAR memory access. Callers use % g_fault_event_head.nodeNum for bounds, but nodeNum itself is read from BAR memory (line 750) and could be corrupted by hardware fault, causing unexpected bounds bypass.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | final: 50

---

### [ROCE-VULN-006] improper_validation - hns_roce_lite_init_cq

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite.c:237-542` @ `hns_roce_lite_init_cq`
**模块**: roce_network
**跨模块**: roce_network,ascend_hal

**描述**: cqe_size from device configuration used without validation. The cqe_size is set from lite_cq_attr->device_cq_attr.cqe_size without bounds checking. Malicious or malformed device configuration could set an invalid cqe_size leading to buffer access issues.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite.c:237-542`)

```c
cq->cqe_size = lite_cq_attr->device_cq_attr.cqe_size;
```

**达成路径**

device_cq_attr -> cqe_size -> CQE pointer arithmetic

**验证说明**: POSSIBLE: cqe_size from device_cq_attr configuration. Internal path, not directly network-triggered. Requires malformed device configuration.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: i | 29: n | 30: t | 31: e | 32: r | 33: n | 34: a | 35: l | 36: _ | 37: o | 38: n | 39: l | 40: y | 41: , | 42: r | 43: e | 44: a | 45: c | 46: h | 47: a | 48: b | 49: i | 50: l | 51: i | 52: t | 53: y | 54: _ | 55: s | 56: c | 57: o | 58: r | 59: e | 60: : | 61: 5 | 62: , | 63: c | 64: o | 65: n | 66: t | 67: r | 68: o | 69: l | 70: l | 71: a | 72: b | 73: i | 74: l | 75: i | 76: t | 77: y | 78: : | 79: n | 80: o | 81: n | 82: e | 83: , | 84: c | 85: o | 86: n | 87: t | 88: r | 89: o | 90: l | 91: l | 92: a | 93: b | 94: i | 95: l | 96: i | 97: t | 98: y | 99: _ | 100: s | 101: c | 102: o | 103: r | 104: e | 105: : | 106: 0 | 107: , | 108: m | 109: i | 110: t | 111: i | 112: g | 113: a | 114: t | 115: i | 116: o | 117: n | 118: s | 119: : | 120: [ | 121: ] | 122: , | 123: m | 124: i | 125: t | 126: i | 127: g | 128: a | 129: t | 130: i | 131: o | 132: n | 133: _ | 134: s | 135: c | 136: o | 137: r | 138: e | 139: : | 140: 0 | 141: , | 142: f | 143: i | 144: n | 145: a | 146: l | 147: _ | 148: s | 149: c | 150: o | 151: r | 152: e | 153: : | 154: 3 | 155: 5 | 156: }

---

### [ROCE-008-DB-NODE-OVERFLOW] Memory Corruption - hns_roce_lite_mmap_db

**严重性**: Medium | **CWE**: CWE-119 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/ascend_hal/roce/host_lite/hns_roce_lite_stdio.c:183-223` @ `hns_roce_lite_mmap_db`
**模块**: roce_network

**描述**: Potential buffer overflow in doorbell node management. hns_roce_lite_mmap_db() allocates db_dva_node and manages db_list without proper validation of the device_va alignment. Malicious device VA could lead to incorrect list manipulation.

**漏洞代码** (`src/ascend_hal/roce/host_lite/hns_roce_lite_stdio.c:183-223`)

```c
db_node->db_align_dva = align_va; db_node->hva = host_va;
```

**达成路径**

Malicious device VA -> incorrect db_node -> list corruption

**验证说明**: POSSIBLE: mmap_db() manages db_list nodes. Alignment calculation present but relies on device_va being valid. Internal device config path, not directly network-triggered.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: _ | 6: s | 7: c | 8: o | 9: r | 10: e | 11: : | 12: 3 | 13: 0 | 14: , | 15: r | 16: e | 17: a | 18: c | 19: h | 20: a | 21: b | 22: i | 23: l | 24: i | 25: t | 26: y | 27: : | 28: i | 29: n | 30: t | 31: e | 32: r | 33: n | 34: a | 35: l | 36: _ | 37: o | 38: n | 39: l | 40: y | 41: , | 42: r | 43: e | 44: a | 45: c | 46: h | 47: a | 48: b | 49: i | 50: l | 51: i | 52: t | 53: y | 54: _ | 55: s | 56: c | 57: o | 58: r | 59: e | 60: : | 61: 5 | 62: , | 63: c | 64: o | 65: n | 66: t | 67: r | 68: o | 69: l | 70: l | 71: a | 72: b | 73: i | 74: l | 75: i | 76: t | 77: y | 78: : | 79: p | 80: a | 81: r | 82: t | 83: i | 84: a | 85: l | 86: , | 87: c | 88: o | 89: n | 90: t | 91: r | 92: o | 93: l | 94: l | 95: a | 96: b | 97: i | 98: l | 99: i | 100: t | 101: y | 102: _ | 103: s | 104: c | 105: o | 106: r | 107: e | 108: : | 109: 1 | 110: 5 | 111: , | 112: m | 113: i | 114: t | 115: i | 116: g | 117: a | 118: t | 119: i | 120: o | 121: n | 122: s | 123: : | 124: [ | 125: a | 126: l | 127: i | 128: g | 129: n | 130: m | 131: e | 132: n | 133: t | 134: _ | 135: c | 136: a | 137: l | 138: c | 139: ] | 140: , | 141: m | 142: i | 143: t | 144: i | 145: g | 146: a | 147: t | 148: i | 149: o | 150: n | 151: _ | 152: s | 153: c | 154: o | 155: r | 156: e | 157: : | 158: - | 159: 1 | 160: 0 | 161: , | 162: f | 163: i | 164: n | 165: a | 166: l | 167: _ | 168: s | 169: c | 170: o | 171: r | 172: e | 173: : | 174: 4 | 175: 0 | 176: }

---

## 5. Low 漏洞 (2)

### [HDC-010] hardware_interface - hdcdrv_copy_sq_desc_to_remote

**严重性**: Low | **CWE**: CWE-667 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/cann/driver/src/sdk_driver/hdc/pcie/host/hdcdrv_host.c:235-251` @ `hdcdrv_copy_sq_desc_to_remote`
**模块**: hdc_communication
**跨模块**: hdc_communication:device_firmware

**描述**: Doorbell notification to device via PCIe may not properly validate device state before triggering. Malicious or faulty device could exploit timing issues. Missing device state validation before devdrv_msg_ring_doorbell call.

**达成路径**

host_driver@doorbell -> devdrv_msg_ring_doorbell -> PCIe_device

**验证说明**: Doorbell notification triggers device without explicit device state validation. Malicious or faulty device could exploit timing issues. Missing device state validation before devdrv_msg_ring_doorbell.

**评分明细**: 0: { | 1: b | 2: a | 3: s | 4: e | 5: : | 6: 3 | 7: 0 | 8: , | 9: r | 10: e | 11: a | 12: c | 13: h | 14: a | 15: b | 16: i | 17: l | 18: i | 19: t | 20: y | 21: : | 22: 2 | 23: 0 | 24: , | 25: c | 26: o | 27: n | 28: t | 29: r | 30: o | 31: l | 32: l | 33: a | 34: b | 35: i | 36: l | 37: i | 38: t | 39: y | 40: : | 41: 1 | 42: 5 | 43: , | 44: m | 45: i | 46: t | 47: i | 48: g | 49: a | 50: t | 51: i | 52: o | 53: n | 54: s | 55: : | 56: 1 | 57: 5 | 58: , | 59: f | 60: i | 61: n | 62: a | 63: l | 64: : | 65: 5 | 66: 0 | 67: }

---

### [HAL-HDC-ATOI-002] unsafe_function - hdc_cfg_parse_line

**严重性**: Low | **CWE**: CWE-676 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `src/ascend_hal/hdc/common/hdc_core.c:213-221` @ `hdc_cfg_parse_line`
**模块**: ascend_hal

**描述**: Use of atoi() for segment size configuration without bounds validation. Could result in zero or unexpected segment sizes if input is malformed.

**漏洞代码** (`src/ascend_hal/hdc/common/hdc_core.c:213-221`)

```c
config->socket_segment = atoi(value[0]); config->pcie_segment = atoi(value[0]);
```

**达成路径**

config_file -> atoi -> segment_size -> buffer allocation

**验证说明**: atoi() used for segment size without bounds validation. Could result in zero or unexpectedly large segment sizes if config file is malformed.

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -5 | veto: false

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| ascend_hal | 0 | 0 | 2 | 1 | 3 |
| cross_module | 0 | 3 | 0 | 0 | 3 |
| custom | 0 | 0 | 0 | 0 | 0 |
| hdc_communication | 0 | 0 | 4 | 1 | 5 |
| ioctl_handlers | 0 | 3 | 2 | 0 | 5 |
| lqdrv_custom | 0 | 1 | 5 | 0 | 6 |
| queue_operations | 0 | 0 | 1 | 0 | 1 |
| roce_network | 0 | 3 | 12 | 0 | 15 |
| sdk_driver | 0 | 0 | 7 | 0 | 7 |
| svm_memory | 0 | 1 | 4 | 0 | 5 |
| **合计** | **0** | **11** | **37** | **2** | **50** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 8 | 15.4% |
| CWE-287 | 5 | 9.6% |
| CWE-787 | 4 | 7.7% |
| CWE-367 | 3 | 5.8% |
| CWE-269 | 3 | 5.8% |
| CWE-190 | 3 | 5.8% |
| CWE-125 | 3 | 5.8% |
| CWE-120 | 3 | 5.8% |
| CWE-119 | 3 | 5.8% |
| CWE-732 | 2 | 3.8% |
| CWE-200 | 2 | 3.8% |
| CWE-843 | 1 | 1.9% |
| CWE-680 | 1 | 1.9% |
| CWE-676 | 1 | 1.9% |
| CWE-668 | 1 | 1.9% |
| CWE-667 | 1 | 1.9% |
| CWE-639 | 1 | 1.9% |
| CWE-401 | 1 | 1.9% |
| CWE-400 | 1 | 1.9% |
| CWE-347 | 1 | 1.9% |
| CWE-285 | 1 | 1.9% |
| CWE-130 | 1 | 1.9% |
| CWE-129 | 1 | 1.9% |
| CWE-126 | 1 | 1.9% |
