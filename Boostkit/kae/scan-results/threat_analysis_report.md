# KAE Kunpeng Accelerator Engine 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析由 AI 自主完成，基于对源代码的全面扫描和架构理解。

## 项目架构概览

KAE（Kunpeng Accelerator Engine）是基于鲲鹏处理器内置硬件加速单元提供的硬件加速解决方案。项目包含以下核心组件：

### 软件架构分层

```
┌─────────────────────────────────────────────────────────────┐
│  应用层 (TLS Server, Storage, Database)                      │
├─────────────────────────────────────────────────────────────┤
│  OpenSSL Engine / 压缩库 (KAEOpensslEngine, KAEZlib, etc.)   │
├─────────────────────────────────────────────────────────────┤
│  UADK 用户态框架 (wd_cipher, wd_rsa, wd_comp, etc.)          │
├─────────────────────────────────────────────────────────────┤
│  UACCE 内核框架 (uacce.c, qm.c, vfio)                        │
├─────────────────────────────────────────────────────────────┤
│  硬件加速器驱动 (sec2, hpre, zip)                            │
├─────────────────────────────────────────────────────────────┤
│  硬件加速器 (kSEC, kHPRE, kZIP)                              │
└─────────────────────────────────────────────────────────────┘
```

### 核心模块

| 模块 | 功能 | 文件数 | 代码行数 |
|------|------|--------|----------|
| KAEKernelDriver | 内核驱动（支持4个内核版本） | ~120 | ~80,000 |
| KAEOpensslEngine | OpenSSL加密引擎 | ~60 | ~25,000 |
| uadk | 用户态加速器框架 | ~100 | ~60,000 |
| KAEZlib | Zlib压缩加速 | ~30 | ~15,000 |
| KAEZstd/KAELz4/KAESnappy | 其他压缩加速 | ~30 | ~10,000 |

## 模块风险评估

### Critical 级别模块

#### 1. UACCE 内核框架 (uacce.c)

**风险描述**：
- ioctl 接口暴露给用户态，接受用户控制的命令和数据
- mmap 接口允许用户态直接映射内核 DMA 缓冲区和硬件 MMIO 空间
- 缺乏细粒度的权限检查，任意进程可打开设备文件

**关键攻击路径**：
- `UACCE_CMD_GET_SS_DMA`: 用户可获取 DMA 地址信息
- `UACCE_CMD_START_Q/PUT_Q`: 用户控制硬件队列启停
- mmap MMIO/DUS/SS 区域: 用户可直接读写硬件寄存器

#### 2. QM 队列管理器 (qm.c)

**风险描述**：
- 长达 6335 行的复杂代码，包含大量硬件交互逻辑
- Mailbox 通信机制可能被恶意请求滥用
- VF/PF 通信接口存在潜在攻击面

**关键攻击路径**：
- `UACCE_CMD_QM_SET_QP_CTX`: 设置 QP 上下文，可能触发内存破坏
- `UACCE_CMD_QM_SET_QP_INFO`: 设置 QP 深度和 BD 大小
- VF/PF mailbox 命令注入

#### 3. SEC2 加密引擎驱动 (sec_crypto.c)

**风险描述**：
- 处理用户提供的密钥、IV 和加密数据
- DMA 映射和缓冲区管理复杂
- 硬件队列深度和 BD 格式验证可能不充分

**关键攻击路径**：
- 密钥设置 (`sec_skcipher_setkey`): 用户密钥直接写入 DMA 内存
- IV 处理 (`sec_skcipher_copy_iv`): 用户 IV 直接复制
- 数据映射 (`sec_cipher_map`): 用户 scatterlist 直接映射

#### 4. VFIO 直通接口 (hisi_acc_vfio_pci.c)

**风险描述**：
- 虚拟机可通过 VFIO 直接访问硬件加速器
- 状态迁移接口可能泄露硬件状态或触发异常
- Precopy ioctl 暴露大量迁移数据

**关键攻击路径**：
- `hisi_acc_vfio_pci_ioctl`: VFIO ioctl 处理
- `hisi_acc_vf_precopy_ioctl`: 迁移数据复制
- 设备状态保存/加载

### High 级别模块

#### 5. OpenSSL Engine (e_uadk.c, sec_ciphers.c, hpre_rsa.c)

**风险描述**：
- 通过 OpenSSL API 接收用户密钥和数据
- 异步模式下的缓冲区管理复杂
- 算法回退机制可能被恶意触发

**关键攻击路径**：
- Engine ctrl 命令可禁用安全功能
- 密钥设置缺少完整验证
- 大数据块处理可能触发边界条件

#### 6. UADK 框架 (wd_cipher.c, wd_rsa.c)

**风险描述**：
- 用户态框架直接向硬件发送请求
- 参数验证依赖应用层输入
- 异步模式下的消息池管理存在竞态风险

**关键攻击路径**：
- `wd_do_cipher_sync/async`: 用户数据直接发送到硬件
- `wd_cipher_set_key`: 用户密钥存储到 session
- 数据格式验证可能不充分

### Medium 级别模块

#### 7. 压缩库 (KAEZlib, KAEZstd, KAELz4, KAESnappy)

**风险描述**：
- 接收用户提供的数据流进行压缩/解压
- 解压操作可能受到"解压炸弹"攻击
- 输入长度验证依赖 zlib/zstd 标准接口

**关键攻击路径**：
- `kz_deflate/kz_inflate`: 用户数据流处理
- 硬件队列资源耗尽攻击
- 恶意构造的压缩数据触发异常

## 攻击面分析

### 内核态攻击面

| 接口类型 | 入口点 | 攻击向量 | 信任等级 |
|---------|--------|----------|----------|
| ioctl | uacce_fops_unl_ioctl | 恶意命令参数、整数溢出、权限绕过 | untrusted_local |
| ioctl | hisi_qm_uacce_ioctl | QP 上下文注入、深度溢出 | untrusted_local |
| ioctl | hisi_acc_vfio_pci_ioctl | VFIO 迁移数据篡改 | semi_trusted |
| mmap | uacce_fops_mmap | DMA 缓冲区越界读写、硬件寄存器攻击 | untrusted_local |
| open | uacce_fops_open | 设备资源耗尽、权限绕过 | untrusted_local |

### 用户态攻击面

| 接口类型 | 入口点 | 攻击向量 | 信任等级 |
|---------|--------|----------|----------|
| OpenSSL API | sec_engine_ciphers | 恶意密钥、边界条件触发 | untrusted_local |
| OpenSSL API | hpre_rsa_methods | RSA 参数攻击、整数溢出 | untrusted_local |
| UADK API | wd_do_cipher_* | 数据长度溢出、IV 篡改 | untrusted_local |
| UADK API | wd_cipher_set_key | 密钥验证绕过 | untrusted_local |
| zlib API | kz_deflate/kz_inflate | 解压炸弹、资源耗尽 | untrusted_local |

### 硬件接口攻击面

| 接口类型 | 入口点 | 攻击向量 | 信任等级 |
|---------|--------|----------|----------|
| MMIO 寄存器 | mmap 映射区域 | 寄存器篡改、硬件配置攻击 | untrusted_local |
| DMA 缓冲区 | SS 区域映射 | DMA 地址欺骗、数据篡改 | untrusted_local |
| 硬件队列 | BD 提交 | BD 格式注入、队列耗尽 | untrusted_local |

## STRIDE 威胁建模

### Spoofing (欺骗)

| 威胁场景 | 彄件 | 描述 | 风险等级 |
|---------|------|------|----------|
| 设备身份欺骗 | uacce | 恶意进程可伪装合法用户打开设备 | Medium |
| VF 身份欺骗 | vfio | VM guest 可伪造 PF 消息 | High |
| Engine 身份欺骗 | OpenSSL Engine | 恶意应用可声称使用硬件加密但实际用软件 | Medium |

### Tampering (篡改)

| 威胁场景 | 彄件 | 描述 | 风险等级 |
|---------|------|------|----------|
| ioctl 参数篡改 | uacce/qm | 恶意 ioctl 参数触发内核漏洞 | Critical |
| DMA 数据篡改 | mmap | 用户态可修改 DMA 缓冲区数据 | Critical |
| 密钥篡改 | wd_cipher | 用户密钥在传输过程中可能被篡改 | High |
| BD 数据篡改 | sec_crypto | 硬件 BD 格式可能被用户态篡改 | High |
| VFIO 迁移数据篡改 | vfio | 迁移过程中的状态数据可能被篡改 | High |

### Repudiation (抵赖)

| 威胁场景 | 彄件 | 描述 | 风险等级 |
|---------|------|------|----------|
| 操作无日志 | uacce | ioctl 操作缺少审计日志 | Medium |
| 硬件操作无记录 | drv | 硬件队列操作难以追踪 | Medium |

### Information Disclosure (信息泄露)

| 威胁场景 | 彄件 | 描述 | 风险等级 |
|---------|------|------|----------|
| DMA 地址泄露 | uacce_get_ss_dma | ioctl 返回 DMA 地址信息 | High |
| 密钥内存泄露 | sec_cipher/hpre_rsa | DMA 内存中的密钥可能泄露 | Critical |
| 硬件状态泄露 | vfio | VFIO 迁移可能泄露硬件内部状态 | High |
| MMIO 寄存器泄露 | mmap | 用户态可读取硬件寄存器 | High |

### Denial of Service (拒绝服务)

| 威胁场景 | 彄件 | 描述 | 风险等级 |
|---------|------|------|----------|
| 队列资源耗尽 | qm | 恶意进程耗尽所有队列实例 | High |
| 硬件队列阻塞 | drv | 恶意 BD 提交阻塞硬件处理 | High |
| mmap 区域耗尽 | uacce | 大量 mmap 占用内存资源 | Medium |
| 异步请求池耗尽 | uadk | 异步模式下消息池耗尽 | Medium |

### Elevation of Privilege (权限提升)

| 威胁场景 | 彄件 | 描述 | 风险等级 |
|---------|------|------|----------|
| 内核漏洞利用 | uacce/qm | ioctl/mmap 漏洞可能提权到 root | Critical |
| 硬件控制权获取 | mmap | MMIO 访问可控制硬件行为 | Critical |
| VF 权限提升 | vfio | VM guest 可能攻击宿主机内核 | Critical |

## 安全加固建议

### 内核驱动层面

1. **ioctl 接口加固**
   - 增加严格的参数验证，包括长度、范围、格式检查
   - 对 `copy_from_user` 返回值进行完整检查
   - 添加速率限制防止滥用

2. **mmap 接口加固**
   - 限制 mmap 区域大小和数量
   - 增加对映射权限的细粒度控制
   - 对 MMIO 区域写入进行白名单过滤

3. **权限控制增强**
   - 添加设备文件访问权限检查
   - 限制每用户/每进程的队列数量
   - 添加 audit 日志记录关键操作

4. **DMA 缓冲区保护**
   - 使用 `dma_alloc_coherent` 时添加边界检查
   - 清零释放前的密钥数据 (`memzero_explicit`)
   - 验证 DMA 地址范围合法性

5. **VFIO 安全加固**
   - 验证迁移数据的完整性
   - 防止 VM guest 发送恶意命令
   - 增加状态保存/恢复的错误处理

### 用户态框架层面

1. **密钥处理加固**
   - 验证密钥长度和格式（AES/SM4/DES）
   - 检查 DES 弱密钥
   - 使用安全内存存储密钥

2. **数据验证增强**
   - 验证输入数据长度与硬件限制匹配
   - 检查 scatterlist 的完整性
   - IV 长度和格式验证

3. **异步模式加固**
   - 增加消息池容量检查
   - 处理竞态条件
   - 完善错误恢复机制

4. **压缩库加固**
   - 添加解压输出大小限制防止解压炸弹
   - 验证压缩数据格式完整性
   - 资源使用限制

### OpenSSL Engine 层面

1. **Engine 控制加固**
   - 限制可通过 ctrl 命令禁用的功能
   - 验证算法启用/禁用请求来源

2. **密钥管理加固**
   - 验证 RSA 密钥参数（模数长度、公钥指数）
   - 检查密钥数学属性
   - 使用硬件安全存储密钥

3. **回退机制加固**
   - 明确记录回退条件
   - 防止恶意触发回退

---

**报告生成时间**: 2026-04-21
**分析工具**: Architecture Agent
**项目版本**: KAE 2.0 (支持 OLK 4.19/5.4/5.10/6.6)