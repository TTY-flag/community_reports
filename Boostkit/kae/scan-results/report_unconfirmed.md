# 漏洞扫描报告 — 待确认漏洞

**项目**: KAE Kunpeng Accelerator Engine
**扫描时间**: 2026-04-21T18:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 43 | 45.3% |
| LIKELY | 26 | 27.4% |
| CONFIRMED | 26 | 27.4% |
| **总计** | **95** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 8 | 11.6% |
| Medium | 41 | 59.4% |
| Low | 20 | 29.0% |
| **有效漏洞总计** | **69** | - |
| 误报 (FALSE_POSITIVE) | 0 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-KERNEL-006]** missing_permission_check (High) - `uacce/uacce.c:765` @ `isolate_strategy_store` | 置信度: 80
2. **[VULN-SEC-ZLIB-002]** Buffer Overflow Risk in Format Header Write (High) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEZlib/src/v1/kaezip_deflate.c:179` @ `kaezip_deflate_set_fmt_header` | 置信度: 80
3. **[VULN-SEC-LZ4-006]** Improper Input Validation (High) - `KAELz4/src/kaelz4_adapter.c:722` @ `kaelz4_check_param_valid` | 置信度: 80
4. **[DF-001]** Improper Validation of Array Index (High) - `KAEKernelDriver/KAEKernelDriver-OLK-6.6/uacce/uacce.c:82` @ `uacce_get_ss_dma` | 置信度: 75
5. **[DF-007]** Improper Validation of Array Index (High) - `KAEKernelDriver/KAEKernelDriver-OLK-6.6/hisilicon/hpre/hpre_crypto.c:890` @ `hpre_rsa_setkey` | 置信度: 75
6. **[VULN-SEC-UADK-002]** Insecure Driver Loading Path (High) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_cipher.c:110` @ `wd_cipher_open_driver` | 置信度: 75
7. **[VULN-SEC-ZLIB-007]** Missing Buffer Size Validation Before memcpy in Decompress Output (High) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEZlib/src/v1/kaezip_ctx.c:417` @ `kaezip_get_decomp_output_data` | 置信度: 75
8. **[DF-003]** Buffer Copy without Checking Size of Input (High) - `KAEKernelDriver/KAEKernelDriver-OLK-6.6/hisilicon/sec2/sec_crypto.c:896` @ `sec_skcipher_setkey` | 置信度: 70
9. **[VULN-SEC-UADK-003]** Missing Session Access Control (Medium) - `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_cipher.c:280` @ `wd_cipher_alloc_sess` | 置信度: 85
10. **[DF-004]** Integer Overflow or Wraparound (Medium) - `KAEKernelDriver/KAEKernelDriver-OLK-6.6/uacce/uacce.c:457` @ `uacce_alloc_dma_buffers` | 置信度: 80

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `uacce_fops_unl_ioctl@KAEKernelDriver/KAEKernelDriver-OLK-6.6/uacce/uacce.c` | ioctl | untrusted_local | ioctl接口允许用户态程序控制硬件加速器队列。攻击者可以通过恶意ioctl命令触发内核漏洞，包括队列管理、DMA地址获取、QP上下文设置等操作。 | UACCE ioctl接口：UACCE_CMD_START_Q, UACCE_CMD_PUT_Q, UACCE_CMD_GET_SS_DMA |
| `hisi_qm_uacce_ioctl@KAEKernelDriver/KAEKernelDriver-OLK-6.6/hisilicon/qm.c` | ioctl | untrusted_local | QM ioctl接口允许用户态设置QP上下文和深度信息。攻击者可通过恶意参数触发缓冲区溢出或内存破坏。 | QM ioctl接口：UACCE_CMD_QM_SET_QP_CTX, UACCE_CMD_QM_SET_QP_INFO |
| `uacce_fops_mmap@KAEKernelDriver/KAEKernelDriver-OLK-6.6/uacce/uacce.c` | mmap | untrusted_local | mmap接口允许用户态程序直接映射内核DMA缓冲区和硬件MMIO空间。攻击者可能利用映射关系进行越界读写或硬件攻击。 | UACCE mmap接口：映射MMIO、DUS、SS内存区域 |
| `uacce_fops_open@KAEKernelDriver/KAEKernelDriver-OLK-6.6/uacce/uacce.c` | file | untrusted_local | 设备文件open操作允许任意用户态进程获取加速器队列。未授权进程可能耗尽队列资源或利用队列进行攻击。 | UACCE设备文件打开：/dev/uacce-* |
| `hisi_acc_vfio_pci_ioctl@KAEKernelDriver/KAEKernelDriver-OLK-6.6/hisilicon/vfio/hisi_acc_vfio_pci.c` | ioctl | semi_trusted | VFIO ioctl接口用于虚拟机直通场景。虚拟机guest可能通过VFIO接口攻击宿主机内核或窃取硬件资源。 | VFIO ioctl接口：用于VM pass-through |
| `uadk_engine_ctrl@KAEOpensslEngine/src/e_uadk.c` | decorator | untrusted_local | OpenSSL Engine控制接口允许应用启用/禁用加密算法。恶意应用可能禁用关键安全功能或触发回退到软件实现。 | OpenSSL Engine控制命令：UADK_CMD_ENABLE_* |
| `sec_engine_ciphers@KAEOpensslEngine/src/v1/alg/ciphers/sec_ciphers.c` | decorator | untrusted_local | 对称加密接口接收用户密钥和数据进行硬件加密。攻击者可能通过恶意密钥或数据触发硬件边界条件漏洞。 | 对称加密接口：AES/SM4/DES加密 |
| `hpre_get_rsa_methods@KAEOpensslEngine/src/v1/alg/pkey/hpre_rsa.c` | decorator | untrusted_local | RSA非对称加密接口处理用户提供的密钥和消息。攻击者可能通过特殊构造的密钥或消息触发整数溢出或硬件异常。 | RSA非对称加密接口：密钥生成/加密/解密/签名 |
| `wd_do_cipher_sync@uadk/wd_cipher.c` | rpc | untrusted_local | UADK同步加密接口接收用户数据。用户可控的输入长度、IV、密钥可能触发内存越界或硬件异常。 | UADK同步加密接口：wd_do_cipher_sync |
| `wd_do_cipher_async@uadk/wd_cipher.c` | rpc | untrusted_local | UADK异步加密接口接收用户数据。异步模式下数据缓冲区管理更复杂，可能存在竞态条件或缓冲区管理漏洞。 | UADK异步加密接口：wd_do_cipher_async |
| `kz_deflate@KAEZlib/src/kaezip_adapter.c` | rpc | untrusted_local | 压缩接口接收用户提供的数据流。用户可控的输入长度和flush参数可能触发缓冲区溢出或硬件队列耗尽。 | KAE压缩接口：deflate压缩 |
| `kz_inflate@KAEZlib/src/kaezip_adapter.c` | rpc | untrusted_local | 解压接口接收用户提供的数据流。恶意构造的压缩数据可能触发解压炸弹攻击或内存分配异常。 | KAE解压接口：inflate解压 |

**其他攻击面**:
- ioctl接口：UACCE_CMD_START_Q, UACCE_CMD_PUT_Q, UACCE_CMD_GET_SS_DMA, UACCE_CMD_QM_SET_QP_CTX, UACCE_CMD_QM_SET_QP_INFO
- mmap接口：用户态映射MMIO、DUS、SS内存区域
- VFIO接口：虚拟机直通加速器设备
- OpenSSL Engine接口：cipher/digest/rsa/dh/ecc算法
- UADK框架接口：wd_do_cipher_sync/async, wd_do_digest_sync/async
- 压缩库接口：deflate/inflate压缩解压
- 设备文件：/dev/uacce-hisi_sec2, /dev/uacce-hisi_hpre, /dev/uacce-hisi_zip

---

## 3. High 漏洞 (8)

### [VULN-SEC-KERNEL-006] missing_permission_check - isolate_strategy_store

**严重性**: High | **CWE**: CWE-732 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `uacce/uacce.c:765-783` @ `isolate_strategy_store`
**模块**: KAEKernelDriver-OLK-6.6

**描述**: isolate_strategy sysfs attribute writable without capability check. The isolate_strategy_store function allows any user with write access to sysfs to modify the error isolation threshold. This could allow unprivileged users to disable or manipulate device isolation behavior, potentially affecting system reliability.

**漏洞代码** (`uacce/uacce.c:765-783`)

```c
static ssize_t isolate_strategy_store(struct device *dev, struct device_attribute *attr,
                                   const char *buf, size_t count)
{
    struct uacce_device *uacce = to_uacce_device(dev);
    unsigned long val;
    int ret;

    if (kstrtoul(buf, 0, &val) < 0)
        return -EINVAL;

    if (val > UACCE_MAX_ERR_THRESHOLD)
        return -EINVAL;

    // No CAP_SYS_ADMIN or similar check before modifying isolation threshold
    ret = uacce->ops->isolate_err_threshold_write(uacce, val);
    ...
}
```

**达成路径**

sysfs write -> isolate_strategy_store -> isolate_err_threshold_write (modifies device behavior)

**验证说明**: 代码确认：isolate_strategy_store函数允许任何有sysfs写权限的用户修改错误隔离阈值，无CAP_SYS_ADMIN检查。可能影响系统可靠性。

---

### [VULN-SEC-ZLIB-002] Buffer Overflow Risk in Format Header Write - kaezip_deflate_set_fmt_header

**严重性**: High | **CWE**: CWE-120 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEZlib/src/v1/kaezip_deflate.c:179-195` @ `kaezip_deflate_set_fmt_header`
**模块**: KAEZlib

**描述**: In kaezip_deflate_set_fmt_header(), memcpy copies format header to strm->next_out without verifying strm->avail_out is sufficient for entire header. Partial check exists but final memcpy assumes buffer has enough space.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEZlib/src/v1/kaezip_deflate.c:179-195`)

```c
memcpy(strm->next_out, fmt_header, fmt_header_sz);
```

**达成路径**

fmt_header -> memcpy -> strm->next_out

**验证说明**: 格式头复制无完整缓冲区大小验证。可能溢出用户提供的输出缓冲区。

---

### [VULN-SEC-LZ4-006] Improper Input Validation - kaelz4_check_param_valid

**严重性**: High | **CWE**: CWE-20 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `KAELz4/src/kaelz4_adapter.c:722-743` @ `kaelz4_check_param_valid`
**模块**: KAELz4

**描述**: Insufficient validation of user-supplied buffer parameters in async compression APIs. The kaelz4_check_param_valid function checks for NULL pointers and zero-length buffers but does not validate that buf_len values are within reasonable bounds or that buf_num does not exceed internal buffer limits (REQ_BUFFER_MAX). Large buf_len or buf_num values could cause integer overflow in subsequent size calculations.

**漏洞代码** (`KAELz4/src/kaelz4_adapter.c:722-743`)

```c
static int kaelz4_check_param_valid(const struct kaelz4_buffer_list *src, struct kaelz4_buffer_list *dst,
                                    lz4_async_callback callback, struct kaelz4_result *result) {
    // Only checks for NULL and buf_len == 0, no upper bound validation
    result->src_size = 0;
    for (unsigned int i = 0; i < src->buf_num; i++) {
        if (unlikely(src->buf[i].data == NULL || src->buf[i].buf_len == 0)) {
            return KAE_LZ4_INVAL_PARA;
        }
        result->src_size += src->buf[i].buf_len;  // Potential overflow
    }
}
```

**验证说明**: 异步API参数验证不完整。累加src_size可能溢出，buf_num无上限检查。

---

### [DF-001] Improper Validation of Array Index - uacce_get_ss_dma

**严重性**: High | **CWE**: CWE-129 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `KAEKernelDriver/KAEKernelDriver-OLK-6.6/uacce/uacce.c:82-137` @ `uacce_get_ss_dma`
**模块**: KAEKernelDriver-OLK-6.6

**描述**: uacce_get_ss_dma 函数中 slice_idx 边界检查存在整数溢出风险。当 slice[0].total_num 为 0 时，`slice[0].total_num - 1` 会导致整数溢出（对于 unsigned 类型变成很大的正值），从而绕过边界检查 `slice[0].total_num - 1 < slice_idx`。攻击者可以通过 ioctl UACCE_CMD_GET_SS_DMA 命令提供恶意的 slice_idx 值，在边界检查被绕过后越界访问 slice 数组。

**漏洞代码** (`KAEKernelDriver/KAEKernelDriver-OLK-6.6/uacce/uacce.c:82-137`)

```c
if (slice[0].total_num - 1 < slice_idx) { /* 边界检查可能被整数溢出绕过 */ }
dma = slice[slice_idx].dma; /* 越界访问风险 */
size = slice[slice_idx].size;
```

**达成路径**

ioctl arg (用户输入) → copy_from_user(&slice_idx, arg, sizeof(unsigned long)) [Line 91] → slice_idx [Line 86] → 边界检查 slice[0].total_num - 1 < slice_idx [Line 108] → slice[slice_idx].dma/slice[slice_idx].size 越界访问 [Lines 114-115]

**验证说明**: 代码确认：uacce_get_ss_dma函数Line 108的边界检查`slice[0].total_num - 1 < slice_idx`存在整数溢出风险。当total_num为0时，unsigned类型减1会变成很大正值，绕过边界检查。但需要确认slice数组创建流程是否会产生total_num=0的情况。

---

### [DF-007] Improper Validation of Array Index - hpre_rsa_setkey

**严重性**: High | **CWE**: CWE-129 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `KAEKernelDriver/KAEKernelDriver-OLK-6.6/hisilicon/hpre/hpre_crypto.c:890-950` @ `hpre_rsa_setkey`
**模块**: KAEKernelDriver-OLK-6.6

**描述**: hpre_crypto.c 中 RSA/DH 密钥处理使用 ctx->key_sz - vlen 计算偏移量进行 memcpy。如果 vlen 大于 ctx->key_sz，偏移量会变成负数（对于 size_t 类型变成很大的正值），导致越界写入。密钥参数来自用户的 setkey 操作。

**漏洞代码** (`KAEKernelDriver/KAEKernelDriver-OLK-6.6/hisilicon/hpre/hpre_crypto.c:890-950`)

```c
memcpy(ctx->rsa.prikey + ctx->key_sz - vlen, ptr, vlen); /* ctx->key_sz - vlen 可能溢出 */
memcpy(ctx->rsa.pubkey + ctx->key_sz - vlen, ptr, vlen);
```

**达成路径**

用户 RSA setkey 操作 → 密钥参数 → ASN.1 解析 → vlen (密钥长度) → ctx->key_sz - vlen 偏移计算 → memcpy(ctx->rsa.prikey/pubkey + offset, ptr, vlen) → DMA buffer

**验证说明**: 代码分析：hpre_crypto.c中RSA/DH密钥处理使用ctx->key_sz - vlen计算偏移量。如果vlen > ctx->key_sz，对于size_t类型会产生很大的正值，导致越界写入。需要验证vlen的上限检查。

---

### [VULN-SEC-UADK-002] Insecure Driver Loading Path - wd_cipher_open_driver

**严重性**: High | **CWE**: CWE-426 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_cipher.c:110-111` @ `wd_cipher_open_driver`
**模块**: uadk

**描述**: Dynamic driver library loading from paths determined by environment variables without signature verification. wd_dlopen_drv(NULL) allows arbitrary driver loading from filesystem paths that could be manipulated by attackers to load malicious drivers.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_cipher.c:110-111`)

```c
wd_cipher_setting.dlh_list = wd_dlopen_drv(NULL);
```

**验证说明**: wd_dlopen_drv(NULL)允许从环境变量确定的路径动态加载驱动库，无签名验证。攻击者可能通过篡改路径加载恶意驱动。但需要确认库加载路径的安全限制。

---

### [VULN-SEC-ZLIB-007] Missing Buffer Size Validation Before memcpy in Decompress Output - kaezip_get_decomp_output_data

**严重性**: High | **CWE**: CWE-120 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEZlib/src/v1/kaezip_ctx.c:417-446` @ `kaezip_get_decomp_output_data`
**模块**: KAEZlib

**描述**: In kaezip_get_decomp_output_data(), memcpy copies to kz_ctx->out without explicit validation of destination buffer allocated size. While avail_out is checked, kz_ctx->out comes from user input strm->next_out.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEZlib/src/v1/kaezip_ctx.c:417-446`)

```c
memcpy(kz_ctx->out, op_data.out, produced);
```

**达成路径**

Hardware output -> memcpy -> user buffer

**验证说明**: 硬件输出复制到用户缓冲区。虽然有avail_out检查，但需确认缓冲区实际大小。

---

### [DF-003] Buffer Copy without Checking Size of Input - sec_skcipher_setkey

**严重性**: High | **CWE**: CWE-120 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `KAEKernelDriver/KAEKernelDriver-OLK-6.6/hisilicon/sec2/sec_crypto.c:896-947` @ `sec_skcipher_setkey`
**模块**: KAEKernelDriver-OLK-6.6

**描述**: sec_skcipher_setkey 函数中 memcpy 复制用户密钥到固定大小的 DMA 缓冲区时，keylen 来自用户输入但未充分验证是否超过 SEC_MAX_KEY_SIZE 缓冲区大小。虽然有密钥长度验证（如 AES 密钥长度检查），但这些检查分散在不同分支中，且 fallback 软件密钥设置路径 `crypto_sync_skcipher_setkey` 可能使用不同的长度限制。

**漏洞代码** (`KAEKernelDriver/KAEKernelDriver-OLK-6.6/hisilicon/sec2/sec_crypto.c:896-947`)

```c
memcpy(c_ctx->c_key, key, keylen); /* keylen来自用户，复制到固定大小缓冲区 */
```

**达成路径**

用户加密请求 → setkey callback → key/keylen 参数 → switch(c_alg) 密钥类型验证 → memcpy(c_ctx->c_key, key, keylen) [Line 937] → DMA coherent buffer (SEC_MAX_KEY_SIZE)

**验证说明**: 代码分析：sec_skcipher_setkey函数中memcpy复制密钥到固定大小DMA缓冲区。虽然有算法特定的密钥长度验证，但验证分散在不同分支中，fallback路径可能使用不同限制。需要进一步验证fallback路径的安全性。

---

## 4. Medium 漏洞 (41)

### [VULN-SEC-UADK-003] Missing Session Access Control - wd_cipher_alloc_sess

**严重性**: Medium | **CWE**: CWE-284 | **置信度**: 85/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_cipher.c:280-331` @ `wd_cipher_alloc_sess`
**模块**: uadk

**描述**: No authentication or authorization checks for session allocation and operations. wd_cipher_alloc_sess allocates cryptographic sessions without validating caller permissions, allowing any process to use cryptographic resources.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_cipher.c:280-331`)

```c
sess = malloc(sizeof(struct wd_cipher_sess)); memset(sess, 0, sizeof(struct wd_cipher_sess));
```

**验证说明**: 会话分配无认证检查，任何进程可使用加密资源。但这是用户态库，权限检查应在内核层实现。

---

### [DF-004] Integer Overflow or Wraparound - uacce_alloc_dma_buffers

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `KAEKernelDriver/KAEKernelDriver-OLK-6.6/uacce/uacce.c:457-519` @ `uacce_alloc_dma_buffers`
**模块**: KAEKernelDriver-OLK-6.6

**描述**: uacce_alloc_dma_buffers 函数中 mmap 区域大小计算存在整数溢出风险。size = vma->vm_end - vma->vm_start 来自用户 mmap 参数，ss_num = size / max_size + (size % max_size ? 1 : 0) 的计算可能导致 ss_num 溢出（如果 size 非常大）。后续 kcalloc(ss_num + 1, ...) 分配可能因整数溢出分配过小缓冲区。

**漏洞代码** (`KAEKernelDriver/KAEKernelDriver-OLK-6.6/uacce/uacce.c:457-519`)

```c
unsigned long size = vma->vm_end - vma->vm_start; /* 用户mmap参数 */
ss_num = size / max_size + (size % max_size ? 1 : 0); /* 可能溢出 */
slice = kcalloc(ss_num + 1, sizeof(*slice), GFP_KERNEL); /* 分配大小依赖ss_num */
```

**达成路径**

mmap syscall → vma 结构 → vma->vm_end - vma->vm_start [Line 461] → size → ss_num 计算 [Line 479] → kcalloc(ss_num + 1) [Line 480] → slice 数组

**验证说明**: 代码分析：mmap区域大小来自用户参数vma->vm_end - vma->vm_start。ss_num计算可能溢出，导致kcalloc分配过小缓冲区。但内核mmap有大小限制，需要确认实际溢出可能性。

---

### [VULN-SEC-UADK-001] Key Exposure in Logs - dump_sec_msg

**严重性**: Medium | **CWE**: CWE-532 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/drv/hisi_sec.c:825-856` @ `dump_sec_msg`
**模块**: uadk

**描述**: Sensitive key information exposed in error logs. The dump_sec_msg function logs key_bytes, iv_bytes and other sensitive cryptographic parameters in error cases, potentially leaking operational details to attackers who can access log files.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/drv/hisi_sec.c:825-856`)

```c
WD_ERR("key_bytes:%u iv_bytes:%u in_bytes:%u out_bytes:%u\n", cmsg->key_bytes, cmsg->iv_bytes, cmsg->in_bytes, cmsg->out_bytes);
```

**验证说明**: 错误日志暴露密钥和IV大小信息。虽然不直接输出密钥内容，但元数据泄露可辅助攻击分析。

---

### [VULN-SEC-ENGINE-001] Key Exposure - sec_ciphers_init

**严重性**: Medium | **CWE**: CWE-200 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v1/alg/ciphers/sec_ciphers.c:288-291` @ `sec_ciphers_init`
**模块**: KAEOpensslEngine

**描述**: Debug mode exposes cryptographic key and IV material in logs. When KAE_DEBUG_KEY_ENABLE is defined, the dump_data function logs key and IV values, potentially exposing sensitive cryptographic material to unauthorized observers or log files.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v1/alg/ciphers/sec_ciphers.c:288-291`)

```c
#ifdef KAE_DEBUG_KEY_ENABLE\n\tdump_data("key", priv_ctx->key, priv_ctx->key_len);\n\tdump_data("iv", priv_ctx->iv, priv_ctx->iv_len);\n#endif
```

**验证说明**: Debug模式(KAE_DEBUG_KEY_ENABLE)下dump_data函数暴露密钥和IV到日志。生产环境不应启用此调试宏，但需要确认默认配置。

---

### [VULN-SEC-KERNEL510-005] Error Handling - qm_check_dev_error

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-754 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEKernelDriver/KAEKernelDriver-OLK-5.10/hisilicon/qm.c:460-475` @ `qm_check_dev_error`
**模块**: KAEKernelDriver-OLK-5.10

**描述**: Incomplete shutdown mask handling in qm_check_dev_error. OLK-5.10 uses qm->err_info.qm_shutdown_mask and dev_shutdown_mask for error checking, but OLK-6.6 introduced a unified qm_err.shutdown_mask field with improved error handling flow in qm_hw_error_handle_v2.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEKernelDriver/KAEKernelDriver-OLK-5.10/hisilicon/qm.c:460-475`)

```c
OLK-5.10:
val = qm_get_hw_error_status(qm) & qm->err_info.qm_shutdown_mask;
dev_val = qm_get_dev_err_status(qm) & qm->err_info.dev_shutdown_mask;

OLK-6.6:
struct hisi_qm_err_mask *qm_err = &qm->err_info.qm_err;
error_status = qm_get_hw_error_status(qm);
if (error_status & qm->error_mask) { ... }
```

**达成路径**

Hardware error status read -> mask applied -> incomplete error categorization

**验证说明**: OLK-5.10错误掩码处理不完整。OLK-6.6引入统一shutdown_mask字段。

---

### [VULN-SEC-ZSTD-003] Integer Overflow - kaezstd_data_parsing

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `KAEZstd/src/v2/kaezstd_compress.c:41` @ `kaezstd_data_parsing`
**模块**: KAEZstd

**描述**: Integer overflow risk in seqnum*sizeof(seqDef) calculation. If seqnum is large, the multiplication could overflow resulting in smaller copy size.

**漏洞代码** (`KAEZstd/src/v2/kaezstd_compress.c:41`)

```c
config->tuple.seqnum*sizeof(seqDef)
```

**验证说明**: seqnum*sizeof(seqDef)乘法可能溢出。如果seqnum接近UINT_MAX，乘法结果溢出导致复制大小变小。

---

### [VULN-SEC-UADK-006] RSA Key Material in Session Structure - wd_rsa_sess

**严重性**: Medium | **CWE**: CWE-312 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_rsa.c:63-72` @ `wd_rsa_sess`
**模块**: uadk

**描述**: RSA private key material is stored in session structures without additional protection. Private key data is kept in wd_rsa_sess structure and could potentially be accessed or leaked if session memory is compromised.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_rsa.c:63-72`)

```c
struct wd_rsa_sess { ... struct wd_rsa_pubkey *pubkey; struct wd_rsa_prikey *prikey; ... };
```

**验证说明**: RSA私钥在会话结构中明文存储。如果会话内存被其他进程访问或泄露，密钥暴露。需要确认内存隔离机制。

---

### [VULN-SEC-ENGINE-002] Key Management - sec_ciphers_priv_ctx_cleanup

**严重性**: Medium | **CWE**: CWE-311 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v1/alg/ciphers/sec_ciphers.c:613-616` @ `sec_ciphers_priv_ctx_cleanup`
**模块**: KAEOpensslEngine

**描述**: Key material not zeroized before memory deallocation. The cipher cleanup function frees key and IV memory without first clearing sensitive data.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v1/alg/ciphers/sec_ciphers.c:613-616`)

```c
kae_free(priv_ctx->iv); kae_free(priv_ctx->key); kae_free(priv_ctx->next_iv);
```

**验证说明**: 密钥内存释放前未清零。内存可能被后续分配重用，密钥残留泄露风险。应使用OPENSSL_cleanse。

---

### [VULN-SEC-ENGINE-003] Authorization - uadk_engine_ctrl

**严重性**: Medium | **CWE**: CWE-863 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/e_uadk.c:231-320` @ `uadk_engine_ctrl`
**模块**: KAEOpensslEngine

**描述**: Engine control commands lack authorization checks. uadk_engine_ctrl allows unprivileged callers to disable cryptographic hardware acceleration without authentication.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/e_uadk.c:231-320`)

```c
switch (cmd) { case UADK_CMD_ENABLE_CIPHER_ENV: uadk_e_set_env_enabled("cipher", i); break; }
```

**验证说明**: uadk_engine_ctrl函数允许禁用硬件加速，无权限检查。但这是用户态库，调用者已经是应用进程，权限检查应在更高层实现。

---

### [VULN-SEC-KERNEL54-003] missing_security_check - unknown

**严重性**: Medium | **CWE**: CWE-732 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `uacce/uacce.c:919` @ `?`
**模块**: KAEKernelDriver-OLK-5.4

**描述**: OLK-5.4 lacks uacce_enable_sva/disable_sva functions present in OLK-6.6. Missing SVA lifecycle management.

**验证说明**: OLK-5.4缺失SVA生命周期管理函数。可能导致SVA状态不一致。

---

### [VULN-SEC-KERNEL54-007] missing_fallback_handling - unknown

**严重性**: Medium | **CWE**: CWE-770 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `hisilicon/hpre/hpre_crypto.c:795` @ `?`
**模块**: KAEKernelDriver-OLK-5.4

**描述**: OLK-5.4 lacks ctx->fallback flag setting for unsupported key sizes. OLK-6.6 properly sets fallback flag.

**验证说明**: OLK-5.4缺失unsupported key size fallback标志设置。可能导致意外软件回退。

---

### [VULN-SEC-KERNEL419-003] Buffer Overflow - sec_skcipher_setkey

**严重性**: Medium | **CWE**: CWE-119 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `hisilicon/sec2/sec_crypto.c:850` @ `sec_skcipher_setkey`
**模块**: KAEKernelDriver-OLK-4.19

**描述**: Key buffer operations use memcpy without explicit bounds validation beyond algorithm-specific checks. DMA memory exposure during key operations. Impact: 1) Cryptographic keys stored in DMA coherent memory visible to device; 2) Keys not scrubbed immediately after use; 3) Potential for key extraction through DMA attacks.

**漏洞代码** (`hisilicon/sec2/sec_crypto.c:850`)

```c
memcpy(c_ctx->c_key, key, keylen) - While keylen is validated per algorithm, DMA memory exposure is concerning
```

**验证说明**: OLK-4.19密钥存储在DMA coherent内存。无IOMMU保护时设备可读取密钥。与VULN-SEC-KERNEL419-002相关。

---

### [VULN-SEC-ZLIB-004] Large Memory Allocation Without Size Limits - kz_outbuffer_init

**严重性**: Medium | **CWE**: CWE-789 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEZlib/src/v2/kaezip_buffer.c:15-33` @ `kz_outbuffer_init`
**模块**: KAEZlib

**描述**: kz_outbuffer_init allocates OUTPUT_CHUNK_V2 (8MB) per stream without configurable limit. Multiple concurrent streams could exhaust system memory. Size is hardcoded as INPUT_CHUNK_V2 << 3 = 8MB.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEZlib/src/v2/kaezip_buffer.c:15-33`)

```c
malloc(OUTPUT_CHUNK_V2)
```

**达成路径**

malloc(8MB) -> out_buffer

**验证说明**: 每个stream分配8MB输出缓冲区。多个并发stream可能耗尽内存。

---

### [VULN-SEC-GZIP-001] Integer Overflow - kae_unzip

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `KAEGzip/open_source/gzip.c (patched):315-320` @ `kae_unzip`
**模块**: KAEGzip

**描述**: In kae_unzip function, the lseek operation uses negative offset based on bytes_in variable. If bytes_in approaches the maximum value of off_t type (typically 2^63-1 or 2^31-1), negating it could cause integer overflow, leading to unexpected file position or potential security issues. The patched code in kae_unzip() performs: lseek(ifd, -bytes_in, SEEK_CUR). This is problematic because bytes_in can be controlled by the size of input data read from the compressed file.

**漏洞代码** (`KAEGzip/open_source/gzip.c (patched):315-320`)

```c
off_t new_pos = lseek(ifd, -bytes_in, SEEK_CUR);
```

**达成路径**

Input file size -> bytes_in -> lseek offset calculation

**验证说明**: 整数溢出风险。bytes_in接近off_t最大值时，取负导致溢出。但需要确认实际文件大小范围。

---

### [VULN-SEC-GZIP-004] Improper Privilege Management - copy_stat

**严重性**: Medium | **CWE**: CWE-281 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `KAEGzip/open_source/gzip.c:1915-1959` @ `copy_stat`
**模块**: KAEGzip

**描述**: The copy_stat function preserves file ownership and permissions from input file to output file. While the code correctly filters out setuid/setgid files before processing, after compression/decompression it preserves the original file permissions and ownership using fchown. This could potentially reintroduce dangerous permissions or allow privilege escalation if an attacker can manipulate the input file metadata.

**漏洞代码** (`KAEGzip/open_source/gzip.c:1915-1959`)

```c
do_chown (ofd, ofname, -1, ifstat->st_gid); r = fchmod (ofd, mode); do_chown (ofd, ofname, ifstat->st_uid, -1);
```

**达成路径**

Input file stat -> output file ownership/permissions

**验证说明**: 复制文件保留原始权限和所有权。可能导致危险权限重新引入。

---

### [VULN-SEC-UADK-005] Async Pool Race Condition - wd_cipher_poll_ctx

**严重性**: Medium | **CWE**: CWE-362 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_cipher.c:857-862` @ `wd_cipher_poll_ctx`
**模块**: uadk

**描述**: Potential race condition in async message pool operations. wd_find_msg_in_pool retrieves messages by tag without verification that the message belongs to the current context, allowing potential message confusion between different async operations.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_cipher.c:857-862`)

```c
msg = wd_find_msg_in_pool(&wd_cipher_setting.pool, idx, resp_msg.tag); if (!msg) { WD_ERR("failed to find msg from pool!\n"); return -WD_EINVAL; }
```

**验证说明**: 异步消息池中按tag查找消息，无验证消息属于当前上下文。可能导致消息混淆，但需要确认tag生成机制和进程隔离。

---

### [VULN-SEC-UADK-007] Missing Zero Key Check - wd_cipher_set_key

**严重性**: Medium | **CWE**: CWE-322 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_cipher.c:229-253` @ `wd_cipher_set_key`
**模块**: uadk

**描述**: wd_cipher_set_key and wd_digest_set_key do not check for all-zero keys which could indicate weak or uninitialized key material. An all-zero key provides no cryptographic protection and should be rejected.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_cipher.c:229-253`)

```c
sess->key_bytes = key_len; memcpy(sess->key, key, key_len);
```

**验证说明**: 全零密钥检查缺失。零密钥无安全价值，应被拒绝。但实际应用很少使用零密钥，威胁有限。

---

### [VULN-SEC-KERNEL-005] key_management - hpre_rsa_clear_ctx

**严重性**: Medium | **CWE**: CWE-316 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `hisilicon/hpre/hpre_crypto.c:1005-1035` @ `hpre_rsa_clear_ctx`
**模块**: KAEKernelDriver-OLK-6.6

**描述**: RSA public key memory not properly cleared during cleanup in hpre_rsa_clear_ctx. While private keys (prikey, crt_prikey) are cleared with memzero_explicit, the pubkey buffer is freed without explicit clearing. This could leave public key data in DMA coherent memory after driver cleanup, potentially exposing key material through memory remanence.

**漏洞代码** (`hisilicon/hpre/hpre_crypto.c:1005-1035`)

```c
static void hpre_rsa_clear_ctx(struct hpre_ctx *ctx, bool is_clear_all)
{
    ...
    if (ctx->rsa.pubkey) {
        // pubkey not cleared with memzero_explicit before free
        dma_free_coherent(dev, ctx->key_sz << 1,
                          ctx->rsa.pubkey, ctx->rsa.dma_pubkey);
        ctx->rsa.pubkey = NULL;
    }

    if (ctx->rsa.crt_prikey) {
        memzero_explicit(ctx->rsa.crt_prikey, ...);  // Private key properly cleared
        dma_free_coherent(...);
    }

    if (ctx->rsa.prikey) {
        memzero_explicit(ctx->rsa.prikey, ctx->key_sz);  // Private key properly cleared
        dma_free_coherent(...);
    }
}
```

**达成路径**

RSA key set -> pubkey DMA allocation -> driver cleanup -> pubkey freed without memzero_explicit

**验证说明**: RSA公钥释放前未清零。内存残留可能泄露公钥数据。

---

### [VULN-SEC-ENGINE-004] Key Validation - change_rsa_method

**严重性**: Medium | **CWE**: CWE-347 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v1/alg/pkey/hpre_rsa.c:641-670` @ `change_rsa_method`
**模块**: KAEOpensslEngine

**描述**: RSA key import lacks cryptographic validation. The change_rsa_method function copies RSA key components (n, e, d, p, q, dmp1, dmq1, iqmp) from an incoming RSA structure to a new hardware-bound RSA key without validating key integrity, proper CRT parameter relationships, or checking for weak primes.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v1/alg/pkey/hpre_rsa.c:641-670`)

```c
static RSA *change_rsa_method(RSA *rsa_default)\n{\n    RSA_METHOD* hw_rsa = hpre_get_rsa_methods();\n    RSA *rsa = RSA_new();\n\n    const BIGNUM *e, *p, *q, *n, *d, *dmp1, *dmq1, *iqmp;\n    RSA_get0_key(rsa_default, &n, &e, &d);\n    RSA_get0_factors(rsa_default, &p, &q);\n    RSA_get0_crt_params(rsa_default, &dmp1, &dmq1, &iqmp);
```

**验证说明**: RSA密钥导入无完整验证。缺乏CRT参数关系检查和弱素数检测。

---

### [VULN-SEC-KERNEL510-007] Improper Privilege Assignment - hisi_qm_uacce_ioctl

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-266 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEKernelDriver/KAEKernelDriver-OLK-5.10/hisilicon/qm.c:2467-2500` @ `hisi_qm_uacce_ioctl`
**模块**: KAEKernelDriver-OLK-5.10

**描述**: Missing capability check for privileged ioctl operations. The uacce_fops_unl_ioctl and hisi_qm_uacce_ioctl functions handle various commands without checking for root/capable privileges for sensitive operations like UACCE_CMD_QM_SET_QP_CTX.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEKernelDriver/KAEKernelDriver-OLK-5.10/hisilicon/qm.c:2467-2500`)

```c
static long hisi_qm_uacce_ioctl(struct uacce_queue *q, unsigned int cmd, unsigned long arg) {
    struct hisi_qp *qp = q->priv;
    ...
    if (cmd == UACCE_CMD_QM_SET_QP_CTX) {
        if (copy_from_user(&qp_ctx, ...)) // No capability check
            return -EFAULT;
        qm_set_sqctype(q, qp_ctx.qc_type);
    }
}
```

**达成路径**

User ioctl -> copy_from_user -> direct qp configuration without privilege check

**验证说明**: ioctl操作无CAP_SYS_ADMIN检查。但这是内核驱动，设备文件权限提供基础隔离。

---

### [VULN-SEC-KERNEL510-008] Missing Authentication - uacce_fops_mmap

**严重性**: Medium（原评估: MEDIUM → 验证后: Medium） | **CWE**: CWE-306 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEKernelDriver/KAEKernelDriver-OLK-5.10/uacce/uacce.c:622-692` @ `uacce_fops_mmap`
**模块**: KAEKernelDriver-OLK-5.10

**描述**: Missing device state validation in mmap operations. The uacce_fops_mmap function maps DMA buffers to user space without checking device isolation state, potentially allowing access to device memory in unsafe configurations.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEKernelDriver/KAEKernelDriver-OLK-5.10/uacce/uacce.c:622-692`)

```c
static int uacce_fops_mmap(struct file *filep, struct vm_area_struct *vma) {
    ...
    qfr = kzalloc(sizeof(*qfr), GFP_KERNEL);
    // No UACCE_DEV_NOIOMMU safety check before DMA mapping
    case UACCE_QFRT_SS:
        ret = uacce_create_region(q, vma, qfr);
}
```

**达成路径**

User mmap request -> queue region allocation -> DMA mapping without isolation validation

**验证说明**: mmap操作未检查设备隔离状态。可能在不安全配置下映射DMA缓冲区。

---

### [VULN-SEC-ENGINE-006] Key Storage - cipher_priv_ctx

**严重性**: Medium | **CWE**: CWE-312 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v2/alg/ciphers/uadk_cipher.c:60-72` @ `cipher_priv_ctx`
**模块**: KAEOpensslEngine

**描述**: Cryptographic key stored in plaintext in context structure. cipher_priv_ctx stores key in plaintext array accessible to memory inspection.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v2/alg/ciphers/uadk_cipher.c:60-72`)

```c
unsigned char iv[IV_LEN]; unsigned char key[MAX_KEY_LEN];
```

**验证说明**: 密钥在结构体中明文存储。如果进程内存可被dump（如通过gdb或coredump），密钥暴露。

---

### [VULN-SEC-KERNEL54-002] deprecated_api - unknown

**严重性**: Medium | **CWE**: CWE-669 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `uacce/uacce.c:265` @ `?`
**模块**: KAEKernelDriver-OLK-5.4

**描述**: OLK-5.4 uses deprecated iommu_sva_bind_device() with NULL parameter. OLK-6.6 updated API. Version-specific: kernel 5.4 IOMMU SVA API differs.

**验证说明**: OLK-5.4使用deprecated IOMMU SVA API。OLK-6.6更新为新API。兼容性问题，安全威胁有限。

---

### [VULN-SEC-KERNEL54-006] deprecated_api - unknown

**严重性**: Medium | **CWE**: CWE-667 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `hisilicon/hpre/hpre_crypto.c:1184` @ `?`
**模块**: KAEKernelDriver-OLK-5.4

**描述**: OLK-5.4 uses deprecated struct field reqsize. OLK-6.6 uses kpp_set_reqsize() API.

**验证说明**: deprecated struct字段。OLK-6.6使用新API设置请求大小。

---

### [VULN-SEC-ZLIB-003] Missing Input Validation in V2 Compression Stream - kz_zlib_do_request_v2

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEZlib/src/v2/kaezip_comp.c:150-210` @ `kz_zlib_do_request_v2`
**模块**: KAEZlib

**描述**: In kz_zlib_do_request_v2(), the function accepts z_streamp strm from untrusted input but performs minimal validation. While NULL checks exist for out_buffer, the validation of strm->avail_in, strm->avail_out, strm->next_in, strm->next_out values is incomplete. Malicious values could lead to unexpected behavior. The function does not validate that strm pointers and sizes are within acceptable bounds before processing.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEZlib/src/v2/kaezip_comp.c:150-210`)

```c
if (unlikely(flush != Z_SYNC_FLUSH && flush != Z_NO_FLUSH && flush != Z_FINISH)) { return Z_STREAM_ERROR; } outbuffer_ptr out_buffer = (outbuffer_ptr)strm->adler; if (!out_buffer) { return Z_BUF_ERROR; }
```

**达成路径**

User strm parameters -> kz_zlib_do_request_v2() -> wd_do_comp_strm()

**验证说明**: V2压缩流参数验证不完整。 strm指针和大小需要更严格验证。

---

### [VULN-SEC-ZLIB-006] Unbounded Loop in Inflate Processing - kz_inflate_v1

**严重性**: Medium | **CWE**: CWE-834 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEZlib/src/v1/kaezip_inflate.c:107-125` @ `kz_inflate_v1`
**模块**: KAEZlib

**描述**: In kz_inflate_v1(), the do-while loop continues processing as long as avail_out != 0 and avail_in != 0, without a maximum iteration limit. A malicious input stream could cause excessive iterations, leading to CPU exhaustion or denial of service. The loop condition also includes kaezip_inflate_need_append_loop() which can extend iterations based on internal state.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEZlib/src/v1/kaezip_inflate.c:107-125`)

```c
do { ret = kaezip_do_inflate(strm, flush); } while ((strm->avail_out != 0 && strm->avail_in != 0) || kaezip_inflate_need_append_loop(...));
```

**达成路径**

Malicious compressed input -> unbounded do-while loop -> CPU exhaustion

**验证说明**: 解压循环无迭代限制。恶意输入可能导致CPU耗尽。

---

### [VULN-SEC-LZ4-002] Buffer Overread/Overwrite - LZ4_wildCopy16

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `KAELz4/src/v1/kaelz4_comp.h:187-203` @ `LZ4_wildCopy16`
**模块**: KAELz4

**描述**: LZ4_wildCopy8 and LZ4_wildCopy16 functions perform unbounded memory copies that can write up to 8-16 bytes beyond the intended destination boundary. These functions are designed for speed optimization but lack proper bounds checking, potentially causing buffer overflow when the destination buffer is tightly sized.

**漏洞代码** (`KAELz4/src/v1/kaelz4_comp.h:187-203`)

```c
static inline void LZ4_wildCopy16(void* dstPtr, const void* srcPtr, void* dstEnd) {
    BYTE* d = (BYTE*)dstPtr;
    const BYTE* s = (const BYTE*)srcPtr;
    BYTE* const e = (BYTE*)dstEnd;
    do { KZL_MEMCPY_16(d, s, 16); d += 16; s += 16; } while (d < e);
}
```

**验证说明**: wildCopy函数设计为速度优化，可能写越界8-16字节。需要确认调用方缓冲区大小。

---

### [VULN-SEC-LZ4-005] Buffer Overflow - kaelz4_set_input_data

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `KAELz4/src/v1/kaelz4_ctx.c:454-467` @ `kaelz4_set_input_data`
**模块**: KAELz4

**描述**: Unsafe memcpy in kaelz4_set_input_data function. The function copies input data using do_comp_len without validating that the destination buffer (op_data.in) has sufficient capacity. While COMP_BLOCK_SIZE is used as allocation size, the do_comp_len value should be validated against actual buffer size before memcpy.

**漏洞代码** (`KAELz4/src/v1/kaelz4_ctx.c:454-467`)

```c
void kaelz4_set_input_data(kaelz4_ctx_t *kz_ctx) {
    kz_ctx->op_data.in_len = 0;
    memcpy((uint8_t *)kz_ctx->op_data.in, kz_ctx->in, kz_ctx->do_comp_len);
    kz_ctx->op_data.in_len += kz_ctx->do_comp_len;
}
```

**验证说明**: 输入复制使用do_comp_len，虽然缓冲区分配COMP_BLOCK_SIZE，但应验证输入大小上限。

---

### [DF-006] Buffer Copy without Checking Size of Input - sec_skcipher_copy_iv

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `KAEKernelDriver/KAEKernelDriver-OLK-6.6/hisilicon/sec2/sec_crypto.c:1513-1520` @ `sec_skcipher_copy_iv`
**模块**: KAEKernelDriver-OLK-6.6

**描述**: sec_request_transfer 路径中 IV（初始化向量）复制使用 memcpy 复制用户 IV 到固定大小缓冲区。ctx->c_ctx.ivsize 来自加密算法的 IV 大小，但 sk_req->iv 来自用户请求，复制到 c_req->c_ivin（SEC_IV_SIZE 固定大小）时，如果 ivsize > SEC_IV_SIZE 可能导致缓冲区溢出。

**漏洞代码** (`KAEKernelDriver/KAEKernelDriver-OLK-6.6/hisilicon/sec2/sec_crypto.c:1513-1520`)

```c
memcpy(c_req->c_ivin, sk_req->iv, ctx->c_ctx.ivsize); /* ivsize可能超过SEC_IV_SIZE */
```

**达成路径**

用户加密请求 → skcipher_request → sk_req->iv → ctx->c_ctx.ivsize (来自crypto API) → memcpy(c_req->c_ivin, sk_req->iv, ivsize) → DMA coherent buffer

**验证说明**: IV复制使用ctx->c_ctx.ivsize作为长度，ivsize来自加密算法标准定义(AES=16字节)，但需确认SEC_IV_SIZE是否匹配ivsize上限。

---

### [VULN-SEC-UADK-008] IV Validation Gap for CTR Mode - cipher_iv_len_check

**严重性**: Medium | **CWE**: CWE-325 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_cipher.c:586-623` @ `cipher_iv_len_check`
**模块**: uadk

**描述**: CTR mode IV validation is incomplete. The code does not prevent IV reuse, which is catastrophic for CTR mode as reusing IV with same key reveals plaintext XOR of two messages.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_cipher.c:586-623`)

```c
switch (sess->alg) { case WD_CIPHER_AES: case WD_CIPHER_SM4: if (req->iv_bytes != AES_BLOCK_SIZE) { ... } break; }
```

**验证说明**: CTR模式IV长度检查存在，但无IV重用防护。IV重用会导致明文XOR泄露。需要确认应用层是否保证IV唯一性。

---

### [VULN-SEC-UADK-009] Callback Function Pointer Injection - wd_cipher_poll_ctx

**严重性**: Medium | **CWE**: CWE-94 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_cipher.c:868` @ `wd_cipher_poll_ctx`
**模块**: uadk

**描述**: Async mode allows arbitrary callback function pointers to be set via req->cb without validation. A malicious process could potentially inject callback pointers to hijack execution flow when async operations complete.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/wd_cipher.c:868`)

```c
req->cb(req, req->cb_param);
```

**验证说明**: 异步模式下req->cb回调函数指针未验证。恶意进程可能注入回调指针劫持执行流。但需要确认req来源和进程隔离机制。

---

### [VULN-SEC-ENGINE-005] Memory Security - sec_digests_init

**严重性**: Medium | **CWE**: CWE-14 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v1/alg/digests/sec_digests.c:139` @ `sec_digests_init`
**模块**: KAEOpensslEngine

**描述**: Sensitive digest context cleared with memset instead of secure clearing. The memset call to clear digest context can be optimized away by compilers, potentially leaving sensitive intermediate hash state data in memory. Should use OPENSSL_cleanse or similar secure clearing function.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v1/alg/digests/sec_digests.c:139`)

```c
    memset((void *)md_ctx, 0, sizeof(sec_digest_priv_t));
```

**验证说明**: 使用memset而非OPENSSL_cleanse清除敏感digest状态。编译器可能优化掉memset。

---

### [DF-011] Buffer Copy without Checking Size of Input - wd_cipher_set_key

**严重性**: Medium | **CWE**: CWE-120 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `uadk/wd_cipher.c:229-253` @ `wd_cipher_set_key`
**模块**: uadk

**描述**: wd_cipher_set_key 函数中使用 memcpy 复制用户密钥到会话缓冲区。虽然 cipher_key_len_check 函数有密钥长度验证，但 sess->key 是通过 sess->mm_ops.alloc 分配的 MAX_CIPHER_KEY_SIZE 固定大小缓冲区。如果密钥长度检查逻辑存在遗漏（如新算法类型），可能导致溢出。

**漏洞代码** (`uadk/wd_cipher.c:229-253`)

```c
ret = cipher_key_len_check(sess, key_len);
sess->key_bytes = key_len;
memcpy(sess->key, key, key_len); // 复制到固定大小缓冲区
```

**达成路径**

应用调用 wd_cipher_set_key → key/key_len 参数 → cipher_key_len_check 验证 → sess->key_bytes = key_len → memcpy(sess->key, key, key_len) → sess 缓冲区 (MAX_CIPHER_KEY_SIZE)

**验证说明**: 密钥复制到固定大小缓冲区(MAX_CIPHER_KEY_SIZE)，有长度检查。威胁有限。

---

### [VULN-SEC-ENGINE-008] Integer Overflow - ctr_iv_inc

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v2/alg/ciphers/uadk_cipher.c:580-598` @ `ctr_iv_inc`
**模块**: KAEOpensslEngine

**描述**: CTR mode counter increment may overflow. ctr_iv_inc does not check for overflow, leading to key/nonce reuse risk.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v2/alg/ciphers/uadk_cipher.c:580-598`)

```c
static void ctr_iv_inc(uint8_t *counter, __u32 c) { do { --n; c_value += counter1[n]; counter1[n] = (uint8_t)c_value; } while (n); }
```

**验证说明**: CTR模式计数器增量无溢出检查。溢出后key/nonce重用导致安全问题。需要确认计数器范围限制。

---

### [VULN-SEC-ZLIB-005] Integer Overflow Risk in Chunk Size Calculation - kz_zlib_do_comp_implement

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEZlib/src/v2/kaezip_comp.c:45-105` @ `kz_zlib_do_comp_implement`
**模块**: KAEZlib

**描述**: In kz_zlib_do_comp_implement(), chunk sizes use __u32 which can overflow with large inputs. Accumulated values are __u64 but strm_req sizes are __u32, potentially truncating large values.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEZlib/src/v2/kaezip_comp.c:45-105`)

```c
__u32 total_avail_in = req->src_len;
```

**达成路径**

Large input -> __u32 truncation

**验证说明**: 使用__u32存储输入大小，大值输入可能截断。需要确认上游大小限制。

---

### [VULN-SEC-LZ4-003] Integer Overflow - kaelz4_triples_rebuild

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `KAELz4/src/v1/kaelz4_comp.c:407-410` @ `kaelz4_triples_rebuild`
**模块**: KAELz4

**描述**: Integer overflow risk in destination buffer size calculation. The expression src_size + src_size / 255 + 16 can overflow when src_size is large (e.g., near SIZE_MAX). This overflow would result in a smaller computed buffer requirement than actually needed, potentially leading to buffer overflow during compression output.

**漏洞代码** (`KAELz4/src/v1/kaelz4_comp.c:407-410`)

```c
if (req->src_size + req->src_size / 255 + 16 >= save_info->dstCapacity - save_info->dst_len) {
    *save_info->status = KAE_LZ4_DST_BUF_OVERFLOW;
    return 0;
}
```

**验证说明**: 缓冲区大小计算存在溢出风险表达式。大src_size可能导致计算溢出。

---

### [VULN-SEC-SNAPPY-004] Integer Overflow - kaesnappy_data_parsing

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAESnappy/src/v2/kaesnappy_compress.c:42-43` @ `kaesnappy_data_parsing`
**模块**: KAESnappy

**描述**: Potential integer overflow in memcpy size calculation: The expression config->tuple.seqnum*sizeof(seqDef) could overflow if seqnum is very large (e.g., near UINT_MAX). This would result in a smaller-than-expected copy size due to wrap-around, potentially leading to incomplete data copying or buffer access issues.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAESnappy/src/v2/kaesnappy_compress.c:42-43`)

```c
memcpy((unsigned char*)zc->seqStore.sequencesStart, config->tuple.sequencesStart, config->tuple.seqnum*sizeof(seqDef));
```

**验证说明**: 乘法溢出风险。seqnum接近UINT_MAX时结果溢出。

---

### [VULN-SEC-SNAPPY-005] Improper Input Validation - kaesnappy_data_parsing

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAESnappy/src/v1/kaesnappy_comp.c:26-38` @ `kaesnappy_data_parsing`
**模块**: KAESnappy

**描述**: Unvalidated hardware output values: kaesnappy_data_parsing trusts hardware-returned pointers (literals_start, sequences_start) and values (lit_num, seq_num) without proper validation. Malfunctioning hardware, corrupted DMA output, or malicious hardware input could lead to buffer overflow or out-of-bounds access. The values lit_num and seq_num are used directly without bounds checking.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAESnappy/src/v1/kaesnappy_comp.c:26-38`)

```c
zc->seqStore.lit += config->snappy_data.lit_num; zc->seqStore.sequences += config->snappy_data.seq_num;
```

**验证说明**: V1数据解析使用硬件返回值累加指针。故障硬件可能导致指针越界。

---

### [VULN-SEC-ZSTD-004] Input Validation - kaezstd_compress_v1

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `KAEZstd/src/v1/kaezstd_comp.c:51-54` @ `kaezstd_compress_v1`
**模块**: KAEZstd

**描述**: Missing input validation for srcSize in kaezstd_compress. Only checks for NULL and zero, not for maximum allowed size.

**漏洞代码** (`KAEZstd/src/v1/kaezstd_comp.c:51-54`)

```c
if (kaezstd_ctx == NULL || src == NULL || srcSize == 0) { return KAE_ZSTD_INVAL_PARA; }
```

**验证说明**: 输入大小无上限验证。超大输入可能导致资源耗尽，但有基本NULL检查。

---

### [VULN-SEC-UADK-010] Missing Hardware Queue Access Control - hpre_init_qm_priv

**严重性**: Medium | **CWE**: CWE-668 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/drv/hisi_hpre.c:646-681` @ `hpre_init_qm_priv`
**模块**: uadk

**描述**: No access control for hardware queue operations. hisi_qm_alloc_qp allocates hardware queues without validating caller permissions, potentially allowing unauthorized processes to access cryptographic hardware resources.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/uadk/drv/hisi_hpre.c:646-681`)

```c
h_qp = hisi_qm_alloc_qp(qm_priv, h_ctx); if (!h_qp) { WD_ERR("failed to alloc qp!\n"); goto out; }
```

**验证说明**: 硬件队列分配无访问控制验证。但这是驱动层，进程隔离通过uacce设备文件权限实现。

---

### [VULN-SEC-SNAPPY-007] Buffer Overflow - kaesnappy_create_session

**严重性**: Medium | **CWE**: CWE-787 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAESnappy/src/v2/kaesnappy_config.c:167-168` @ `kaesnappy_create_session`
**模块**: KAESnappy

**描述**: Potential buffer overflow in V2 session creation: kaesnappy_create_session allocates REQ_DSTBUFF_LEN (1.28MB) for config->req.dst but does not validate that subsequent compression operations will not exceed this buffer. The req.dst_len is set to REQ_DSTBUFF_LEN but there is no runtime check against actual output size from wd_do_comp_strm.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAESnappy/src/v2/kaesnappy_config.c:167-168`)

```c
config->req.dst = malloc(REQ_DSTBUFF_LEN); config->req.dst_len = REQ_DSTBUFF_LEN;
```

**验证说明**: 会话创建分配固定大小输出缓冲区，但无运行时输出大小检查。

---

## 5. Low 漏洞 (20)

### [DF-005] Improper Input Validation - hisi_qm_uacce_ioctl

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 70/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `KAEKernelDriver/KAEKernelDriver-OLK-6.6/hisilicon/qm.c:2704-2744` @ `hisi_qm_uacce_ioctl`
**模块**: KAEKernelDriver-OLK-6.6

**描述**: hisi_qm_uacce_ioctl 函数处理 UACCE_CMD_QM_SET_QP_CTX 命令时，qp_ctx 结构体来自用户空间 copy_from_user，虽然 qc_type 有范围检查 `qp_ctx.qc_type > QM_MAX_QC_TYPE`，但 qp_ctx 结构体中的其他字段（如 id）可能被用户篡改，直接用于内核操作。

**漏洞代码** (`KAEKernelDriver/KAEKernelDriver-OLK-6.6/hisilicon/qm.c:2704-2744`)

```c
if (copy_from_user(&qp_ctx, (void __user *)arg, sizeof(struct hisi_qp_ctx)))
    return -EFAULT;
if (qp_ctx.qc_type > QM_MAX_QC_TYPE)
    return -EINVAL;
qm_set_sqctype(q, qp_ctx.qc_type);
qp_ctx.id = qp->qp_id; /* 用户可能篡改id字段 */
```

**达成路径**

ioctl UACCE_CMD_QM_SET_QP_CTX → copy_from_user(&qp_ctx, arg) [Line 2712] → qp_ctx 结构体 → qc_type 验证 [Line 2716] → qm_set_sqctype → copy_to_user 返回

**验证说明**: qp_ctx结构体来自用户空间，qc_type有范围检查，但id字段被内核覆盖(qp_ctx.id = qp->qp_id)，实际上用户篡改id字段影响有限。

---

### [VULN-SEC-ENGINE-007] IV Validation - uadk_e_cipher_init

**严重性**: Low | **CWE**: CWE-329 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v2/alg/ciphers/uadk_cipher.c:517-518` @ `uadk_e_cipher_init`
**模块**: KAEOpensslEngine

**描述**: IV copied without proper length validation. memcpy of IV without checking IV length matches expected algorithm requirements.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v2/alg/ciphers/uadk_cipher.c:517-518`)

```c
if (iv) memcpy(priv->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
```

**验证说明**: IV复制无长度验证。但iv_length由OpenSSL API保证正确，威胁有限。

---

### [VULN-SEC-GZIP-006] Path Traversal Potential - treat_dir

**严重性**: Low | **CWE**: CWE-22 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `KAEGzip/open_source/gzip.c:1991-2007` @ `treat_dir`
**模块**: KAEGzip

**描述**: The treat_dir function recursively processes directories when -r option is used. While there are checks for . and .. entries, the path construction using strcpy and strcat without full validation could potentially lead to path traversal if a malicious directory structure is created.

**漏洞代码** (`KAEGzip/open_source/gzip.c:1991-2007`)

```c
if (strequ (entry, .) || strequ (entry, ..)) continue; strcpy(nbuf,dir); strcpy (nbuf + len, entry);
```

**达成路径**

Directory entry -> path construction -> file processing

**验证说明**: -r递归处理时路径构造可能路径遍历。但有./..检查，威胁有限。

---

### [DF-008] Improper Neutralization of Input During Web Page Generation - hisi_acc_vf_precopy_ioctl

**严重性**: Low | **CWE**: CWE-79 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `KAEKernelDriver/KAEKernelDriver-OLK-6.6/hisilicon/vfio/hisi_acc_vfio_pci.c:828-876` @ `hisi_acc_vf_precopy_ioctl`
**模块**: KAEKernelDriver-OLK-6.6

**描述**: VFIO pre-copy ioctl 中 info 结构体通过 copy_to_user 返回给用户空间，info.initial_bytes 计算基于 migf->total_length - *pos，如果 pos 大于 total_length 可能返回负值（对于 unsigned 类型变成很大的值），虽然不直接导致安全问题，但可能导致信息泄露或状态不一致。

**漏洞代码** (`KAEKernelDriver/KAEKernelDriver-OLK-6.6/hisilicon/vfio/hisi_acc_vfio_pci.c:828-876`)

```c
info.initial_bytes = migf->total_length - *pos; /* pos可能大于total_length */
return copy_to_user((void __user *)arg, &info, minsz) ? -EFAULT : 0;
```

**达成路径**

VFIO ioctl VFIO_MIG_GET_PRECOPY_INFO → copy_from_user(&info, arg) → migf->total_length - *pos 计算 → copy_to_user 返回 info → VM guest

**验证说明**: info.initial_bytes = migf->total_length - *pos计算，如果pos > total_length会产生大正值(无符号溢出)。但这是信息返回，不直接导致安全问题。

---

### [DF-009] Stack-based Buffer Overflow - sec_ciphers_update_priv_ctx

**严重性**: Low | **CWE**: CWE-121 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `KAEOpensslEngine/src/v1/alg/ciphers/sec_ciphers.c:298-350` @ `sec_ciphers_update_priv_ctx`
**模块**: KAEOpensslEngine

**描述**: sec_ciphers_update_priv_ctx 函数中使用可变长度数组（VLA）`unsigned char K[iv_bytes]`，其中 iv_bytes 来自 priv_ctx->e_cipher_ctx->op_data.iv_bytes（默认值为16）。虽然此处 iv_bytes 是固定值，但 VLA 使用模式在类似代码中可能引入栈溢出风险，特别是如果 iv_bytes 来自用户输入或未充分验证的参数。

**漏洞代码** (`KAEOpensslEngine/src/v1/alg/ciphers/sec_ciphers.c:298-350`)

```c
int iv_bytes = priv_ctx->e_cipher_ctx->op_data.iv_bytes;
unsigned char K[iv_bytes]; // VLA 潜在栈溢出风险
```

**达成路径**

加密操作回调 → sec_ciphers_update_priv_ctx → priv_ctx→e_cipher_ctx→op_data.iv_bytes → VLA unsigned char K[iv_bytes] → 栈内存

**验证说明**: VLA使用模式。虽然当前iv_bytes来自固定值，但VLA模式在其他类似代码中可能有风险。

---

### [DF-010] Buffer Copy without Checking Size of Input - sec_ciphers_init_priv_ctx

**严重性**: Low | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `KAEOpensslEngine/src/v1/alg/ciphers/sec_ciphers.c:164-260` @ `sec_ciphers_init_priv_ctx`
**模块**: KAEOpensslEngine

**描述**: sec_ciphers_init_priv_ctx 函数中使用 kae_memcpy 复制用户密钥和 IV。key_len 和 iv_len 来自 EVP_CIPHER_CTX_key_length/iv_length，这些值虽然由 OpenSSL API 提供，但需要确保分配的缓冲区大小足够（priv_ctx->key/iv 通过 kae_malloc 分配）。如果 OpenSSL 返回异常值，可能导致缓冲区溢出。

**漏洞代码** (`KAEOpensslEngine/src/v1/alg/ciphers/sec_ciphers.c:164-260`)

```c
kae_memcpy(priv_ctx->key, key, EVP_CIPHER_CTX_key_length(ctx));
kae_memcpy(priv_ctx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
```

**达成路径**

OpenSSL cipher init → EVP_CIPHER_CTX → key/iv 参数 → kae_malloc 分配缓冲区 → kae_memcpy 复制 → priv_ctx 结构

**验证说明**: 密钥复制依赖OpenSSL API提供长度，如果API返回异常值可能溢出。但OpenSSL实现可靠。

---

### [DF-012] Buffer Copy without Checking Size of Input - wd_digest_set_key

**严重性**: Low | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `uadk/wd_digest.c:180-190` @ `wd_digest_set_key`
**模块**: uadk

**描述**: wd_digest.c 中 wd_digest_set_key 函数类似 wd_cipher_set_key，使用 memcpy 复制用户密钥。密钥长度检查可能不够全面，特别是对于不同摘要算法的密钥长度限制。

**漏洞代码** (`uadk/wd_digest.c:180-190`)

```c
memcpy(sess->key, key, key_len); // 密钥复制
```

**达成路径**

应用调用 → wd_digest_set_key → key/key_len → memcpy(sess->key) → sess 缓冲区

**验证说明**: Digest密钥复制，有长度检查。威胁有限。

---

### [VULN-SEC-ENGINE-009] Error Handling - rsa_fill_prikey

**严重性**: Low | **CWE**: CWE-392 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v2/alg/rsa/uadk_rsa.c:989-1046` @ `rsa_fill_prikey`
**模块**: KAEOpensslEngine

**描述**: RSA private key filling continues despite missing parameters. rsa_fill_prikey returns failure but does not clean up partially initialized key material.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v2/alg/rsa/uadk_rsa.c:989-1046`)

```c
if (!wd_dq || !wd_dp || !wd_qinv || !wd_q || !wd_p) return UADK_E_FAIL;
```

**验证说明**: RSA私钥填充失败时未清理部分初始化数据。内存残留泄露风险。

---

### [VULN-SEC-ENGINE-010] State Management - sec_digests_copy

**严重性**: Low | **CWE**: CWE-374 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v1/alg/digests/sec_digests.c:478-531` @ `sec_digests_copy`
**模块**: KAEOpensslEngine

**描述**: Digest copy exposes sensitive intermediate state. sec_digests_copy copies internal digest buffers without validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v1/alg/digests/sec_digests.c:478-531`)

```c
memcpy(tp->in, fp->in, from_ctx->last_update_bufflen); memcpy(tp->out, fp->out, fp->out_bytes);
```

**验证说明**: Digest内部状态复制无验证。暴露敏感中间数据，但主要用于context copy操作。

---

### [VULN-SEC-KERNEL54-005] deprecated_api - unknown

**严重性**: Low | **CWE**: CWE-727 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `hisilicon/sec2/sec_crypto.c:1064` @ `?`
**模块**: KAEKernelDriver-OLK-5.4

**描述**: OLK-5.4 uses deprecated SHASH_DESC_ON_STACK. OLK-6.6 uses crypto_shash_tfm_digest().

**验证说明**: deprecated SHASH_DESC_ON_STACK宏。栈上分配可能导致栈溢出风险。

---

### [VULN-SEC-KERNEL54-008] missing_error_check - unknown

**严重性**: Low | **CWE**: CWE-391 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `hisilicon/qm.c:450` @ `?`
**模块**: KAEKernelDriver-OLK-5.4

**描述**: OLK-5.4 missing dev_is_abnormal callback check present in OLK-6.6 for device error detection.

**验证说明**: OLK-5.4缺失设备错误检测回调检查。可能导致错误状态下操作设备。

---

### [VULN-SEC-KERNEL419-004] Information Disclosure - qm_log_hw_error

**严重性**: Low | **CWE**: CWE-200 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `hisilicon/qm.c:1488` @ `qm_log_hw_error`
**模块**: KAEKernelDriver-OLK-4.19

**描述**: Error messages throughout the codebase expose detailed internal addresses, queue IDs, device state, and hardware information that could aid attackers. Impact: 1) Attackers can learn device internals from error messages; 2) Queue ID exposure helps identify attack targets; 3) Hardware state information aids exploitation development.

**漏洞代码** (`hisilicon/qm.c:1488`)

```c
Error messages like "qm %s fifo overflow in function %u qp %u" expose internal device state
```

**验证说明**: 错误日志暴露内部设备状态信息。攻击者可学习设备内部结构。

---

### [VULN-SEC-GZIP-002] Improper Input Validation - main

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `KAEGzip/open_source/gzip.c:512-520` @ `main`
**模块**: KAEGzip

**描述**: The -b (bits) option uses atoi(optarg) to convert the argument to maxbits without proper bounds checking. While there is validation for numeric characters, there is no validation for the range of values. atoi can return negative values or values outside the expected range (typically 9-16 for LZW compression). This could lead to unexpected behavior or memory allocation issues.

**漏洞代码** (`KAEGzip/open_source/gzip.c:512-520`)

```c
maxbits = atoi(optarg);
```

**达成路径**

Command line argument -> atoi -> maxbits

**验证说明**: -b选项参数无范围验证。atoi可返回负值或超范围值。威胁有限，需命令行参数控制。

---

### [VULN-SEC-ENGINE-012] Session Management - uadk_e_cipher_cleanup

**严重性**: Low | **CWE**: CWE-401 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v2/alg/ciphers/uadk_cipher.c:543-556` @ `uadk_e_cipher_cleanup`
**模块**: KAEOpensslEngine

**描述**: Cipher session cleanup does not zeroize key material. The uadk_e_cipher_cleanup function frees the cipher session but does not explicitly clear the key material stored in the private context structure before the session is freed.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v2/alg/ciphers/uadk_cipher.c:543-556`)

```c
static int uadk_e_cipher_cleanup(EVP_CIPHER_CTX *ctx)\n{\n\tstruct cipher_priv_ctx *priv =\n\t\t(struct cipher_priv_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);\n\n\tuadk_e_cipher_sw_cleanup(ctx);\n\n\tif (priv && priv->sess) {\n\t\twd_cipher_free_sess(priv->sess);\n\t\tpriv->sess = 0;\n\t}\n\n\treturn 1;\n}
```

**验证说明**: 会话清理不清零密钥材料。与VULN-SEC-ENGINE-002类似问题。

---

### [DF-013] Improper Input Validation - wd_cipher_check_params

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `uadk/wd_cipher.c:661-711` @ `wd_cipher_check_params`
**模块**: uadk

**描述**: wd_cipher_check_params 函数验证加密请求参数，但 req->in_bytes 和 req->out_bytes 来自用户输入。虽然有 req->out_buf_bytes < req->in_bytes 的检查，但对于大数值输入（接近 UINT_MAX），可能导致整数溢出或资源耗尽。

**漏洞代码** (`uadk/wd_cipher.c:661-711`)

```c
if (unlikely(req->out_buf_bytes < req->in_bytes))
    return -WD_EINVAL;
```

**达成路径**

应用调用 wd_do_cipher_sync/async → wd_cipher_req 结构 → req→in_bytes/out_bytes → wd_cipher_check_params → wd_check_datalist → 硬件队列

**验证说明**: 参数检查存在但可能不完整。大值输入可能导致资源耗尽，但有基本检查。

---

### [VULN-SEC-ENGINE-011] Insecure Fallback - sec_ciphers_do_cipher

**严重性**: Low | **CWE**: CWE-470 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v1/alg/ciphers/sec_ciphers.c:589-601` @ `sec_ciphers_do_cipher`
**模块**: KAEOpensslEngine

**描述**: Automatic fallback to software may weaken security. Functions fall back to OpenSSL software without explicit user consent.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAEOpensslEngine/src/v1/alg/ciphers/sec_ciphers.c:589-601`)

```c
do_soft_cipher: wd_ciphers_put_engine_ctx(priv_ctx->e_cipher_ctx); sec_ciphers_software_encrypt(ctx, priv_ctx);
```

**验证说明**: 硬件失败时自动回退软件实现，无用户确认。可能导致性能下降或使用较弱实现。

---

### [VULN-SEC-KERNEL419-005] Deprecated API - uacce_init

**严重性**: Low | **CWE**: CWE-477 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `uacce/uacce.c:16` @ `uacce_init`
**模块**: KAEKernelDriver-OLK-4.19

**描述**: The code uses DEFINE_IDR instead of the recommended DEFINE_XARRAY_ALLOC. IDR is deprecated in newer kernels with known limitations. Impact: 1) IDR has fixed-size limitations; 2) Memory allocation efficiency issues; 3) Compatibility problems with newer kernels; 4) Missing features compared to XArray.

**漏洞代码** (`uacce/uacce.c:16`)

```c
Line 15 shows commented XARRAY: "// static DEFINE_XARRAY_ALLOC(uacce_xa);" while Line 16 uses legacy: "static DEFINE_IDR(uacce_idr);"
```

**验证说明**: 使用deprecated IDR而非XArray。IDR有固定大小限制和效率问题。

---

### [VULN-SEC-SNAPPY-006] Improper Input Validation - kaesnappy_get_comp_lv

**严重性**: Low | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAESnappy/src/v1/kaesnappy_ctx.c:35-86` @ `kaesnappy_get_comp_lv`
**模块**: KAESnappy

**描述**: Environment variable parsing without bounds validation: The function kaesnappy_get_comp_lv uses getenv() and atoi() to parse KAE_SNAPPY_COMP_TYPE without validating the input format. A maliciously crafted environment variable containing non-numeric characters could cause atoi() to return unexpected values. Similarly, kaesnappy_get_win_size parses KAE_SNAPPY_WINTYPE without robust validation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/kae/KAESnappy/src/v1/kaesnappy_ctx.c:35-86`)

```c
char *snappy_str = getenv("KAE_SNAPPY_COMP_TYPE"); int snappy_val = atoi(snappy_str);
```

**验证说明**: 环境变量解析无边界验证。恶意环境变量导致意外值。威胁有限。

---

### [VULN-SEC-GZIP-003] Hardcoded API Version - kae_zip

**严重性**: Low | **CWE**: CWE-749 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `KAEGzip/open_source/gzip.c (patched):465-466` @ `kae_zip`
**模块**: KAEGzip

**描述**: Both kae_zip and kae_unzip functions use hardcoded zlib version string 1.2.11 when calling deflateInit2_ and inflateInit2_. This hardcoded version may mismatch with the actual installed zlib version, potentially causing undefined behavior or compatibility issues.

**漏洞代码** (`KAEGzip/open_source/gzip.c (patched):465-466`)

```c
ret = deflateInit2_(&stream, level, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY, 1.2.11, sizeof(z_stream));
```

**达成路径**

Hardcoded version string -> zlib init function

**验证说明**: 硬编码zlib版本字符串可能不匹配安装版本。可能导致兼容性问题，安全威胁有限。

---

### [VULN-SEC-GZIP-007] KAE Hardware Fallback Logic - main

**严重性**: Low | **CWE**: CWE-754 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `KAEGzip/open_source/gzip.c (patched):432-454` @ `main`
**模块**: KAEGzip

**描述**: The patched code adds uadk_get_accel_platform() check at program start. If KAE hardware is not available, it falls back to software implementation. The work function pointer is changed from zip to kae_zip by default, but get_method() switches back to unzip for unsupported format features.

**漏洞代码** (`KAEGzip/open_source/gzip.c (patched):432-454`)

```c
static int (*work) (int infile, int outfile) = kae_zip; ... if (!uadk_get_accel_platform()) { ... }
```

**达成路径**

Hardware availability check -> work function selection

**验证说明**: 硬件可用性检查后选择工作函数。fallback逻辑可能导致意外行为。

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| KAEGzip | 0 | 0 | 2 | 4 | 6 |
| KAEKernelDriver-OLK-4.19 | 0 | 0 | 1 | 2 | 3 |
| KAEKernelDriver-OLK-5.10 | 0 | 0 | 3 | 0 | 3 |
| KAEKernelDriver-OLK-5.4 | 0 | 0 | 4 | 2 | 6 |
| KAEKernelDriver-OLK-6.6 | 0 | 4 | 3 | 2 | 9 |
| KAELz4 | 0 | 1 | 3 | 0 | 4 |
| KAEOpensslEngine | 0 | 0 | 7 | 7 | 14 |
| KAESnappy | 0 | 0 | 3 | 1 | 4 |
| KAEZlib | 0 | 2 | 4 | 0 | 6 |
| KAEZstd | 0 | 0 | 2 | 0 | 2 |
| uadk | 0 | 1 | 9 | 2 | 12 |
| **合计** | **0** | **8** | **41** | **20** | **69** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-120 | 8 | 11.6% |
| CWE-20 | 7 | 10.1% |
| CWE-190 | 7 | 10.1% |
| CWE-754 | 2 | 2.9% |
| CWE-732 | 2 | 2.9% |
| CWE-312 | 2 | 2.9% |
| CWE-200 | 2 | 2.9% |
| CWE-129 | 2 | 2.9% |
| CWE-94 | 1 | 1.4% |
| CWE-863 | 1 | 1.4% |
| CWE-834 | 1 | 1.4% |
| CWE-79 | 1 | 1.4% |
| CWE-789 | 1 | 1.4% |
| CWE-787 | 1 | 1.4% |
| CWE-78 | 1 | 1.4% |
| CWE-770 | 1 | 1.4% |
| CWE-749 | 1 | 1.4% |
| CWE-727 | 1 | 1.4% |
| CWE-669 | 1 | 1.4% |
| CWE-668 | 1 | 1.4% |
| CWE-667 | 1 | 1.4% |
| CWE-532 | 1 | 1.4% |
| CWE-477 | 1 | 1.4% |
| CWE-470 | 1 | 1.4% |
| CWE-426 | 1 | 1.4% |
| CWE-401 | 1 | 1.4% |
| CWE-392 | 1 | 1.4% |
| CWE-391 | 1 | 1.4% |
| CWE-374 | 1 | 1.4% |
| CWE-362 | 1 | 1.4% |
| CWE-347 | 1 | 1.4% |
| CWE-329 | 1 | 1.4% |
| CWE-325 | 1 | 1.4% |
| CWE-322 | 1 | 1.4% |
| CWE-316 | 1 | 1.4% |
| CWE-311 | 1 | 1.4% |
| CWE-306 | 1 | 1.4% |
| CWE-284 | 1 | 1.4% |
| CWE-281 | 1 | 1.4% |
| CWE-266 | 1 | 1.4% |
| CWE-22 | 1 | 1.4% |
| CWE-14 | 1 | 1.4% |
| CWE-125 | 1 | 1.4% |
| CWE-121 | 1 | 1.4% |
| CWE-119 | 1 | 1.4% |
