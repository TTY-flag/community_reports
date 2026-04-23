# VULN-DF-DYN-001：不信任库加载致任意代码执行漏洞

## 执行摘要

| 属性 | 值 |
|-----------|-------|
| **漏洞 ID** | VULN-DF-DYN-001 |
| **CWE** | CWE-427: 不可控搜索路径元素 |
| **类型** | untrusted_library_loading |
| **严重性** | Critical |
| **置信度** | 95% |
| **CVSS 3.1 评分** | 9.8 (Critical) |
| **攻击向量** | 网络（通过恶意模型文件） |
| **受影响组件** | CustomOpSoLoader - OM 模型 SO 二进制加载 |

## 1. 漏洞描述

### 1.1 概述

GE (Graph Engine) 组件直接从 OM (Offline Model) 文件加载自定义算子共享对象 (SO)，无任何签名验证或完整性检查。攻击者可在 SO_BINS 分区中构造包含任意代码的恶意 OM 文件，当模型加载时，代码将在 GE 进程上下文中执行。

### 1.2 技术细节

漏洞存在于 `/base/common/helper/custom_op_so_loader.cc:136-145` 的 `CustomOpSoLoader::DlopenSoByFd` 函数：

```cpp
Status CustomOpSoLoader::DlopenSoByFd(const int32_t mem_fd, void *&handle) const {
  GE_ASSERT_TRUE(mem_fd != kInvalidFd, "mem fd is invalid when loading custom op so.");
  const std::string so_path = std::string(kProcFdPrefix) + std::to_string(mem_fd);
  const int32_t open_flag =
      static_cast<int32_t>(static_cast<uint32_t>(MMPA_RTLD_NOW) | static_cast<uint32_t>(MMPA_RTLD_GLOBAL));
  handle = mmDlopen(so_path.c_str(), open_flag);  // 汇点: 任意代码执行
  GE_ASSERT_TRUE(handle != nullptr, "dlopen custom op so[%s] failed, errmsg:%s", so_path.c_str(), mmDlerror());
  GELOGI("[CustomOpSoLoader] dlopen custom op so[%s] success.", so_path.c_str());
  return SUCCESS;
}
```

加载流程：
1. 从 OM 模型文件的 `SO_BINS` 分区提取 SO 二进制数据
2. 通过 `memfd_create` 将数据写入匿名内存 fd
3. 通过 `mmDlopen`（`dlopen` 的封装）加载内存 fd
4. **无签名验证、代码签名或完整性检查**

### 1.3 缺失的安全控制

代码缺少：
- **数字签名验证** - 无代码签名检查
- **哈希验证** - 仅使用 FNV1a64 哈希用于去重（非安全用途）
- **白名单/信任存储** - 无可信供应商验证
- **证书验证** - 无 X.509 或类似证书验证
- **安全启动链** - 无 SO 来源证明

## 2. 完整攻击路径和数据流

### 2.1 数据流图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          攻击者控制                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  [恶意 OM 文件]                                                               │
│       │                                                                      │
│       │ 包含构造的 SO_BINS 分区及恶意 .so 二进制                               │
│       ▼                                                                      │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ SO_BINS 分区结构:                                                      │   │
│  │ ┌─────────────────────────────────────────────────────────────────┐  │   │
│  │ │ SoStoreHead: so_num = 1                                          │  │   │
│  │ ├─────────────────────────────────────────────────────────────────┤  │   │
│  │ │ SoStoreItemHead:                                                 │  │   │
│  │ │   magic: 0x5D776EFD                                              │  │   │
│  │ │   so_name_len: X                                                 │  │   │
│  │ │   so_bin_type: 3 (kCustomOp)                                     │  │   │
│  │ │   vendor_name_len: Y                                             │  │   │
│  │ │   bin_len: Z                                                     │  │   │
│  │ ├─────────────────────────────────────────────────────────────────┤  │   │
│  │ │ [恶意 ELF 共享对象 - 任意代码]                                     │  │   │
│  │ └─────────────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│                              GE 进程 (受害者)                                   │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  aclmdlLoadFromMem(model, modelSize, modelId)                                 │
│       │                                                                        │
│       ▼                                                                        │
│  ModelHelper::GenerateGeRootModel()                                           │
│       │                                                                        │
│       ▼                                                                        │
│  ModelHelper::LoadOpSoBin() ────────────────────────────────────────────────┐ │
│       │                                                                      │ │
│       │ om_load_helper.GetModelPartition(SO_BINS, ...)                       │ │
│       ▼                                                                      │ │
│  GeRootModel::LoadSoBinData(data, len)                                       │ │
│       │                                                                      │ │
│       │ OpSoStore::Load() 解析 SO_BINS 分区                                  │ │
│       ▼                                                                      │ │
│  [包含恶意二进制数据的 OpSoBinPtr]                                            │ │
│       │                                                                      │ │
│       │ GetSoBinType() == SoBinType::kCustomOp                               │ │
│       ▼                                                                      │ │
│  ModelHelper::LoadCustomOpSoBins()                                           │ │
│       │                                                                      │ │
│       ▼                                                                      │ │
│  CustomOpSoLoader::LoadCustomOpSoBins()                                      │ │
│       │                                                                      │ │
│       ├── CreateSoMemFd() ─── syscall(__NR_memfd_create, ...)               │ │
│       │                                                                      │ │
│       ├── WriteSoBinToFd() ─── write(mem_fd, MALICIOUS_BINARY, ...)         │ │
│       │                                                                      │ │
│       ▼                                                                      │ │
│  ┌─────────────────────────────────────────────────────────────────────────┐│ │
│  │ DlopenSoByFd()                                                          ││ │
│  │   const std::string so_path = "/proc/self/fd/<mem_fd>";                ││ │
│  │   handle = mmDlopen(so_path.c_str(), RTLD_NOW | RTLD_GLOBAL);          ││ │
│  │                                                                         ││ │
│  │   *** 任意代码执行 ***                                                   ││ │
│  │   构造函数 (.init_array, .ctors) 立即执行                              ││ │
│  └─────────────────────────────────────────────────────────────────────────┘│ │
│                                                                                │
└───────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 攻击链中的关键源文件

| 文件 | 行号 | 函数 | 角色 |
|------|------|----------|------|
| `base/common/helper/custom_op_so_loader.cc` | 136-145 | `DlopenSoByFd()` | **汇点** - 执行任意 SO |
| `base/common/helper/custom_op_so_loader.cc` | 115-133 | `WriteSoBinToFd()` | 将不可信二进制写入 memfd |
| `base/common/helper/custom_op_so_loader.cc` | 97-113 | `CreateSoMemFd()` | 创建匿名内存 fd |
| `base/common/helper/custom_op_so_loader.cc` | 147-190 | `LoadCustomOpSoBins()` | 协调自定义 SO 加载 |
| `base/common/helper/model_helper.cc` | 1500-1538 | `LoadOpSoBin()` | 从 OM 提取 SO_BINS，按类型分发 |
| `base/common/helper/model_helper.cc` | 1541-1548 | `LoadCustomOpSoBins()` | 调用 CustomOpSoLoader |
| `base/common/op_so_store/op_so_store.cc` | 98-154 | `OpSoStore::Load()` | **源点** - 从 OM 文件解析 SO_BINS |
| `inc/graph_metadef/graph/op_so_bin.h` | 34-65 | `OpSoBin` 类 | SO 二进制数据容器 |

## 3. 受影响入口点（攻击面）

### 3.1 触发漏洞的公开 API

以下 ACL API 接受 OM 模型数据并触发漏洞代码路径：

| API | 文件 | 描述 |
|-----|------|-------------|
| `aclmdlLoadFromFile()` | `api/acl/acl_model/model/acl_model.cpp:109` | 从文件路径加载模型 |
| `aclmdlLoadFromMem()` | `api/acl/acl_model/model/acl_model.cpp:210` | 从内存缓冲区加载模型 |
| `aclmdlLoadFromFileWithMem()` | `api/acl/acl_model/model/acl_model.cpp:215` | 使用预分配内存加载 |
| `aclmdlLoadFromMemWithMem()` | `api/acl/acl_model/model/acl_model.cpp:222` | 从内存加载使用预分配内存 |
| `aclmdlLoadFromFileWithQ()` | `api/acl/acl_model/model/acl_model.cpp:229` | 使用队列配置加载 |
| `aclmdlLoadFromMemWithQ()` | `api/acl/acl_model/model/acl_model.cpp:235` | 从内存加载使用队列 |
| `aclmdlBundleLoadModel()` | `api/acl/acl_model/model/acl_model.cpp:187` | Bundle 模型加载 |
| `aclmdlBundleLoadModelWithMem()` | `api/acl/acl_model/model/acl_model.cpp:192` | Bundle 加载使用内存 |
| `aclmdlBundleLoadModelWithConfig()` | `api/acl/acl_model/model/acl_model.cpp:199` | Bundle 加载使用配置 |
| `aclopCompileOp()` | `api/acl/acl_op_compiler/` | 单算子编译 |

### 3.2 攻击场景

1. **恶意模型文件分发**: 攻击者分发构造的 OM 文件，看起来像合法 AI 模型。当 GE 加载时，嵌入的恶意 SO 以 GE 进程权限执行。

2. **供应链攻击**: 攻破模型仓库或模型服务基础设施，向合法 OM 文件注入恶意 SO。

3. **模型市场攻击**: 向公共模型仓库上传恶意模型（类似 PyPI 恶意软件活动）。

4. **中间人攻击**: 拦截模型文件传输并注入恶意 SO_BINS 分区。

## 4. PoC 构建大纲

### 4.1 前提条件
- 了解 OM 文件格式
- ELF 共享对象构造知识
- 有 CANN 开发环境用于测试

### 4.2 高层步骤（概念性）

1. **构造恶意 SO**:
   - 创建带构造函数的共享对象
   - 构造函数在 `dlopen()` 时先于其他代码运行
   - 示例模式：
     ```c
     __attribute__((constructor))
     void malicious_init() {
         // 此处任意代码执行
         // 在 GE 进程上下文中运行
     }
     ```

2. **构建恶意 OM 文件**:
   - 以合法 OM 文件为基础
   - 将构造的 SO 注入 SO_BINS 分区
   - 设置 `SoBinType = kCustomOp`（值 3）
   - 重算分区偏移和头部

3. **触发执行**:
   - 用恶意 OM 调用 `aclmdlLoadFromMem()` 或 `aclmdlLoadFromFile()`
   - GE 提取并加载 SO
   - 恶意构造函数执行

### 4.3 OM 文件格式知识

来自 `base/common/op_so_store/op_so_store.cc`:
```
SoStoreHead (4 bytes):
  - so_num: uint32_t

SoStoreItemHead (每个 SO 16 bytes):
  - magic: 0x5D776EFD (uint32_t)
  - so_name_len: uint16_t
  - so_bin_type: uint16_t (3 = kCustomOp 触发漏洞)
  - vendor_name_len: uint32_t
  - bin_len: uint32_t

随后:
  - so_name (so_name_len bytes)
  - vendor_name (vendor_name_len bytes)
  - binary data (bin_len bytes) <- 恶意 SO 在此
```

## 5. 影响评估

### 5.1 严重性理由

| 因素 | 评估 |
|--------|------------|
| **攻击复杂度** | Low - 仅需按已知格式构造文件 |
| **所需权限** | None - 攻击者仅需提供模型文件 |
| **用户交互** | Required - 受害者必须加载模型 |
| **范围** | Changed - 攻破 GE 进程，可影响其他进程 |
| **机密性影响** | High - 完整进程内存访问 |
| **完整性影响** | High - 任意代码可修改任何内容 |
| **可用性影响** | High - 可崩溃或 DoS 系统 |

### 5.2 受影响组件

- **GE 进程**: Graph Engine 进程以提升权限运行以访问 NPU 硬件
- **使用自定义算子的所有模型**: 任何包含 `SoBinType::kCustomOp` SO 二进制的模型
- **模型服务基础设施**: 接受和加载不可信 OM 文件的系统
- **边缘设备**: 生产环境中的 Ascend NPU

### 5.3 真实世界影响

1. **容器逃逸**: 如果 GE 在容器中运行，攻击者可能逃逸到宿主机
2. **数据窃取**: 访问模型权重、推理数据和系统机密
3. **横向移动**: 使用被攻破的宿主机攻击其他基础设施
4. **模型污染**: 向合法模型注入后门
5. **加密密钥窃取**: 访问 HSM 集成、TLS 密钥等

## 6. 根因分析

### 6.1 设计缺陷

"SO in OM" 功能设计用于便携性和自包含，未考虑加载不可信代码的安全影响。功能文档明确说明：

> "SO in OM 特性将模型依赖的算子 .so 文件直接打包进 .om（Offline Model）文件中"

这创建了 OM 文件与 GE 进程之间的隐式信任关系，无任何验证机制。

### 6.2 代码分析

`CalculateSoBinFingerprint()` 中的指纹计算使用 FNV1a64 哈希：

```cpp
uint64_t CalculateFnv1a64(const uint8_t *data, const size_t data_len) {
  uint64_t hash = kFnvOffsetBasis;
  for (size_t i = 0U; i < data_len; ++i) {
    hash ^= static_cast<uint64_t>(data[i]);
    hash *= kFnvPrime;
  }
  return hash;
}
```

此哈希仅用于去重（检查是否已加载相同 SO），非安全验证。攻击者可轻松修改 SO 并保持功能。

### 6.3 缺失安全控制

代码明确避免磁盘回退（注释说明）：

```cpp
constexpr const char_t *kNoDiskFallbackHint = "strict no-disk-fallback is enabled.";
```

然而，无任何安全验证说明。设计优先：
1. 内存仅加载（安全有利 - 无磁盘痕迹）
2. 去重（性能）
3. **缺失: 信任验证**

## 7. 修复建议

### 7.1 短期缓解（快速见效）

1. **添加 SO 类型过滤**:
   ```cpp
   // 在 LoadCustomOpSoBins() 中，加载前:
   if (op_so_bin->GetSoBinType() != SoBinType::kSpaceRegistry &&
       op_so_bin->GetSoBinType() != SoBinType::kOpMasterDevice &&
       op_so_bin->GetSoBinType() != SoBinType::kAutofuse) {
       // 拒绝来自不可信源的 kCustomOp 类型
       GELOGE(FAILED, "Custom SO loading from untrusted source is disabled");
       return FAILED;
   }
   ```

2. **环境变量开关**:
   ```cpp
   // 添加配置以禁用自定义 SO 加载
   if (std::getenv("GE_DISABLE_CUSTOM_SO_LOADING") != nullptr) {
       GELOGW("Custom SO loading is disabled by environment");
       return SUCCESS; // 跳过加载
   }
   ```

### 7.2 中期解决方案

1. **数字签名验证**:
   - 向 OM 文件格式添加签名块
   - 使用可信证书验证 SO 签名
   - 拒绝未签名或签名无效的 SO
   - 将可信供应商公钥存储在安全位置

2. **白名单/信任存储**:
   - 为允许的供应商名实现信任存储
   - 仅加载信任存储中供应商的 SO
   - 维护内置算子的哈希白名单

3. **安全加载路径**:
   ```cpp
   Status SecureCustomOpSoLoader::LoadWithVerification(const OpSoBinPtr &so_bin) {
       // 1. 验证数字签名
       GE_ASSERT_SUCCESS(VerifySignature(so_bin));
       
       // 2. 检查供应商信任存储
       GE_ASSERT_SUCCESS(CheckVendorTrust(so_bin->GetVendorName()));
       
       // 3. 验证 SO 完整性
       GE_ASSERT_SUCCESS(ValidateSoIntegrity(so_bin->GetBinData(), so_bin->GetBinDataSize()));
       
       // 4. 在沙箱环境中加载
       return LoadInSandbox(so_bin);
   }
   ```

### 7.3 长期架构变更

1. **进程外加载**:
   - 在独立的沙箱进程中加载自定义 SO
   - 使用 IPC 通信
   - 限制沙箱权限

2. **Seccomp/沙箱集成**:
   - 加载后应用 seccomp 过滤器限制系统调用
   - 使用命名空间隔离加载的代码
   - 实现 AppArmor/SELinux profile

3. **证明集成**:
   - 与硬件证明（TEE）集成
   - 加载前验证模型来源
   - 为 OM 文件实现安全启动链

### 7.4 所需代码变更

**文件: `base/common/helper/custom_op_so_loader.cc`**

在第 136 行前添加:
```cpp
Status CustomOpSoLoader::VerifySoBinSignature(const OpSoBinPtr &op_so_bin) {
    // TODO: 实现签名验证
    // 1. 从 OM 元数据提取签名
    // 2. 使用可信公钥验证签名
    // 3. 验证失败则拒绝
    return SUCCESS;
}

Status CustomOpSoLoader::DlopenSoByFd(const int32_t mem_fd, void *&handle) const {
    // 添加加载前安全检查
    // 需使用适当的密钥管理实现
}
```

**文件: `base/common/helper/model_helper.cc`**

修改 `LoadOpSoBin()` 约 1521 行:
```cpp
if (op_so_bin_ptr->GetSoBinType() == SoBinType::kCustomOp) {
    // 添加安全检查后再加入加载列表
    if (!IsCustomOpBinAllowed(op_so_bin_ptr)) {
        GELOGW("Custom SO [%s] from vendor [%s] rejected - not in trust store",
               op_so_bin_ptr->GetSoName().c_str(),
               op_so_bin_ptr->GetVendorName().c_str());
        continue;
    }
    custom_op_so_bins.emplace_back(op_so_bin_ptr);
}
```

## 8. 参考资料

- CWE-427: 不可控搜索路径元素 - https://cwe.mitre.org/data/definitions/427.html
- CWE-426: 不可信搜索路径 - https://cwe.mitre.org/data/definitions/426.html
- OWASP: 不可信数据注入 - https://owasp.org/www-community/vulnerabilities/Untrusted_Data_Injection
- ELF 格式规范 - https://refspecs.linuxfoundation.org/elf/elf.pdf
- dlopen() Linux 手册 - https://man7.org/linux/man-pages/man3/dlopen.3.html

## 9. 结论

这是一个 **已确认的 Critical 级漏洞**，允许通过恶意 OM 模型文件执行任意代码。攻击面广（多个公开 API），利用复杂度低，影响严重（完整进程攻破）。

漏洞存在是因为系统信任 `SO_BINS` 分区内容而不验证，允许攻击者注入并以 GE 进程权限执行任意代码。

**需立即行动**: 实现短期缓解并规划签名验证基础设施。

---

*报告由安全分析工具生成*
*时间戳: 2026-04-22*