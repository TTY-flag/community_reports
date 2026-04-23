# 漏洞扫描报告 — 已确认漏洞

**项目**: metadef  
**扫描时间**: 2026-04-22T00:00:00Z  
**报告范围**: 仅包含 CONFIRMED 状态的漏洞  

---

## 执行摘要

本次扫描针对华为 CANN 框架的基础库 metadef 进行了安全审计，发现了 **2 个已确认的 Critical 级别漏洞**。这两个漏洞均为动态库注入类型，攻击者可通过控制环境变量实现任意代码执行，严重影响整个 CANN 软件栈的安全性。

### 核心发现

metadef 作为 CANN 平台的算子管理核心库，其动态库加载机制存在严重安全缺陷：

1. **环境变量完全控制加载路径**：`ASCEND_OPP_PATH` 和 `ASCEND_CUSTOM_OPP_PATH` 环境变量直接决定动态库加载路径，无白名单验证
2. **版本验证存在多种绕过方式**：路径包含 `opp_latest` 或缺失版本文件均可跳过验证
3. **无签名或完整性验证**：`mmDlopen()` 直接加载库文件，未进行任何安全校验
4. **跨模块攻击链完整可达**：从环境变量读取（plugin 模块）到库加载执行（registry 模块）形成完整攻击路径

### 安全风险评估

| 风险维度 | 评估结果 |
|---------|---------|
| 代码执行 | Critical - 完全控制目标进程 |
| 权限提升 | High - 在进程权限范围内执行任意操作 |
| 供应链攻击 | Critical - 可影响所有依赖 CANN 的应用 |
| 数据窃取 | High - 可访问进程内存中的敏感数据 |

### 建议优先级

这两个漏洞需要 **立即修复**。建议的实施顺序：
- P0：实现签名验证机制
- P0：移除 `opp_latest` 自动绕过逻辑
- P1：添加可信路径白名单
- P1：在 `AddSoToRegistry` 中调用 `ValidateSo`

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 9 | 64.3% |
| POSSIBLE | 2 | 14.3% |
| CONFIRMED | 2 | 14.3% |
| FALSE_POSITIVE | 1 | 7.1% |
| **总计** | **14** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| Critical | 2 | 100.0% |
| **有效漏洞总计** | **2** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-DF-CROSS-001]** cross_module_library_injection (Critical) - `base/registry/op_impl_space_registry_v2_impl.cc:79` @ `AddSoToRegistry` | 置信度: 85
2. **[VULN-SEC-DYN-003]** dynamic_library_injection (Critical) - `base/registry/op_impl_space_registry_v2_impl.cc:79` @ `AddSoToRegistry` | 置信度: 80

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `LoadSo@base/common/plugin/plugin_manager.cc` | file | untrusted_local | 通过环境变量 ASCEND_OPP_PATH、ASCEND_CUSTOM_OPP_PATH 等指定的路径加载第三方算子动态库（.so 文件），路径可能被用户控制 | 加载指定路径的共享库（.so 文件） |
| `Load@base/common/plugin/plugin_manager.cc` | file | untrusted_local | 扫描目录并加载所有 .so 文件，目录路径可能来自环境变量 | 扫描目录并加载所有 .so 文件 |
| `GetOppPath@base/common/plugin/plugin_manager.cc` | env | untrusted_local | 读取环境变量 MM_ENV_ASCEND_OPP_PATH 确定算子包路径 | 获取算子包路径（从环境变量或默认路径） |
| `GetPluginPathFromCustomOppPath@base/common/plugin/plugin_manager.cc` | env | untrusted_local | 读取环境变量 MM_ENV_ASCEND_CUSTOM_OPP_PATH 确定自定义算子路径 | 从自定义算子路径获取插件路径 |
| `LoadSoAndInitDefault@base/registry/opp_so_manager.cc` | file | untrusted_local | 加载算子库并注册到默认空间，算子库路径来自环境变量或配置 | 加载算子库并初始化默认注册空间 |
| `LoadOpsProtoPackage@base/registry/opp_so_manager.cc` | file | untrusted_local | 加载算子原型包，路径由环境变量控制 | 加载算子原型包（.so 文件） |
| `ParseJsonFile@error_manager/error_manager.cc` | file | semi_trusted | 解析 JSON 配置文件，文件路径来自库目录相对路径 | 解析 JSON 配置文件（error_code.json） |
| `ReadJsonFile@error_manager/error_manager.cc` | file | semi_trusted | 读取 JSON 文件并解析，文件路径参数可能来自外部 | 读取 JSON 文件 |
| `GetBinFromFile@base/utils/file_utils.cc` | file | semi_trusted | 读取二进制文件内容，路径参数来自外部调用 | 读取二进制文件 |
| `WriteBinToFile@base/utils/file_utils.cc` | file | semi_trusted | 写入二进制文件，路径参数来自外部调用 | 写入二进制文件 |
| `SaveBinToFile@base/utils/file_utils.cc` | file | semi_trusted | 保存二进制数据到文件，路径参数来自外部调用 | 保存二进制数据到文件 |
| `GetAscendWorkPath@base/utils/file_utils.cc` | env | untrusted_local | 读取环境变量 MM_ENV_ASCEND_WORK_PATH 确定工作路径 | 获取 Ascend 工作路径 |

**其他攻击面**:
- 动态库加载: plugin_manager.cc 通过 mmDlopen 加载第三方算子库，路径由环境变量控制
- 环境变量处理: 多个环境变量（ASCEND_OPP_PATH、ASCEND_CUSTOM_OPP_PATH、ASCEND_WORK_PATH）控制库加载路径
- 文件路径处理: realpath、mmRealPath 等函数处理外部传入的文件路径
- JSON 解析: error_manager.cc 使用 nlohmann::json 解析配置文件
- 共享库符号查找: mmDlsym 动态查找库函数符号
- 目录扫描: mmScandir 扫算目录查找 .so 文件

---

## 3. Critical 漏洞 (2)

### [VULN-DF-CROSS-001] cross_module_library_injection - AddSoToRegistry

**严重性**: Critical | **CWE**: CWE-426 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: dataflow-scanner

**位置**: `base/registry/op_impl_space_registry_v2_impl.cc:79-129` @ `AddSoToRegistry`
**模块**: cross_module
**跨模块**: plugin → registry → utils

#### 漏洞描述

跨模块数据流漏洞：环境变量控制的数据从 plugin 模块流向 registry 模块，最终在 registry 模块触发 mmDlopen。攻击者可通过设置 ASCEND_OPP_PATH 环境变量控制 plugin 模块中的路径获取，该路径被传递到 registry 模块的 AddSoToRegistry 函数，导致恶意库被加载。这是跨三个模块（plugin → registry → utils）的完整攻击链。

#### 深度分析

**跨模块攻击链特点**：
- **SOURCE (plugin模块)**: 环境变量读取点，位于 `base/common/plugin/plugin_manager.cc`
- **FLOW (utils模块)**: 路径规范化处理，位于 `base/utils/file_utils.cc`
- **SINK (registry模块)**: 动态库加载执行点，位于 `base/registry/op_impl_space_registry_v2_impl.cc`

**关键发现**：RealPath(mmRealPath→realpath) 仅规范化路径，不阻止恶意路径。且 plugin_manager.cc:162-170 逻辑显示即使 RealPath 失败，原始 opp_path 仍被继续使用。攻击者可通过设置 ASCEND_OPP_PATH 环境变量指向恶意库路径，触发 mmDlopen 加载恶意代码。

**缓解措施绕过分析**：

代码中存在版本验证函数 `IsVendorVersionValid()`，但有**多种绕过方式**：

1. **使用 "opp_latest" 路径绕过**：路径包含 "opp_latest" 字符串即可完全跳过版本验证
   ```cpp
   if (vendor_path.find(kOppLatest) != std::string::npos) {
       return true;  // 直接返回 true，跳过所有验证
   }
   ```

2. **空版本信息绕过**：在恶意目录中不放置版本信息文件 (`version.info`)
   ```cpp
   if (opp_version.empty() && compiler_version.empty()) {
       return true;  // 版本文件不存在时跳过验证
   }
   ```

3. **空版本范围要求绕过**：在特定部署环境中，版本要求可能未配置

**漏洞代码** (`base/registry/op_impl_space_registry_v2_impl.cc:79-129`)

```c
void *const handle = mmDlopen(
    so_path,
    static_cast<int32_t>(static_cast<uint32_t>(MMPA_RTLD_NOW) | static_cast<uint32_t>(MMPA_RTLD_GLOBAL)));
```

**达成路径**

```
[SOURCE] MM_SYS_GET_ENV@base/common/plugin/plugin_manager.cc:159 (plugin模块)
    ↓ 读取 ASCEND_OPP_PATH 环境变量
[PROCESS] GetOppPath()@plugin_manager.cc:156 (plugin模块)
    ↓ 获取 OPP 路径字符串
[SANITIZE] RealPath()@base/utils/file_utils.cc:30 (utils模块)
    ↓ 路径规范化（仅解析符号链接，不验证安全性）
[PROPAGATE] LoadOpsProtoSo()@opp_so_manager.cc:168 (registry模块)
    ↓ 构建 .so 文件路径列表
[PROPAGATE] LoadSoAndInitDefault()@opp_so_manager.cc:111 (registry模块)
    ↓ 准备加载动态库
[SINK] AddSoToRegistry()@op_impl_space_registry_v2_impl.cc:79 (registry模块)
    ↓ 调用 mmDlopen 加载动态库
[EXECUTE] mmDlopen()@op_impl_space_registry_v2_impl.cc:91 (registry模块)
    ↓ 执行恶意代码
```

**攻击场景示例**：

```bash
# 步骤1: 创建恶意目录结构（使用 opp_latest 绕过版本验证）
mkdir -p /tmp/attack_opp_latest/built-in/op_impl/ai_core/tbe/op_tiling/lib/linux/x86_64/

# 步骤2: 放置恶意库（恶意代码将在库加载时自动执行）
# 编译恶意库，包含 __attribute__((constructor)) 初始化函数
gcc -shared -fPIC -o malicious_op.so malicious_op.c

# 步骤3: 设置恶意环境变量
export ASCEND_OPP_PATH=/tmp/attack_opp_latest/

# 步骤4: 运行使用 CANN 框架的应用程序
./victim_cann_application  # 恶意库被自动加载并执行
```

**验证说明**: 跨模块调用链完整验证通过：

1. [SOURCE] MM_SYS_GET_ENV@plugin_manager.cc:159 获取 ASCEND_OPP_PATH 环境变量
2. GetOppPath()@plugin_manager.cc:156 将环境变量值传递给 opp_path
3. RealPath()@file_utils.cc:30 仅执行路径规范化，非安全缓解
4. GetOpsProtoPath()@plugin_manager.cc:608 调用 GetOppPath 并构建 so 列表
5. LoadOpsProtoSo()@opp_so_manager.cc:168 通过函数映射表调用 GetOpsProtoPath
6. LoadSoAndInitDefault()@opp_so_manager.cc:111 调用 AddSoToRegistry
7. [SINK] mmDlopen()@op_impl_space_registry_v2_impl.cc:91 加载攻击者控制的库

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-DYN-003] dynamic_library_injection - AddSoToRegistry

**严重性**: Critical | **CWE**: CWE-427 | **置信度**: 80/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `base/registry/op_impl_space_registry_v2_impl.cc:79-129` @ `AddSoToRegistry`
**模块**: registry
**跨模块**: plugin → registry

#### 漏洞描述

LoadSoAndInitDefault() 直接传递库路径到注册系统，路径最终来自环境变量。AddSoToRegistry() 使用 mmDlopen 加载库，无签名或来源验证。攻击者可通过控制环境变量使系统加载伪造的算子库。

#### 深度分析

**核心问题分析**：

该漏洞属于 **CWE-427: Uncontrolled Search Path Element**，即"不受控制的搜索路径元素"漏洞。核心问题在于：

1. **环境变量直接控制库路径**：系统直接从环境变量获取算子库路径，未进行白名单验证
2. **版本验证可被绕过**：`opp_latest` 关键字或缺失版本文件可绕过版本兼容性检查
3. **无签名验证**：`mmDlopen()` 直接加载库文件，无任何完整性或真实性验证
4. **ValidateSo 未在关键路径调用**：文件大小检查仅在部分流程生效，关键加载路径未调用

**关键代码节点分析**：

**入口点 - 环境变量读取**：
```cpp
// plugin_manager.cc:159-161
MM_SYS_GET_ENV(MM_ENV_ASCEND_OPP_PATH, path_env);
if ((path_env != nullptr) && (strlen(path_env) > 0U)) {
    opp_path = path_env;  // 直接使用环境变量值
}
```

**Sink 点 - 无验证的库加载**：
```cpp
// op_impl_space_registry_v2_impl.cc:91-93
void *const handle = mmDlopen(
    so_path,  // 直接使用路径，无签名验证
    static_cast<int32_t>(static_cast<uint32_t>(MMPA_RTLD_NOW) | 
                         static_cast<uint32_t>(MMPA_RTLD_GLOBAL)));
```

**缺失的安全措施**：
- 无数字签名验证
- 无哈希校验
- 无白名单机制
- 无代码完整性检查

**漏洞代码** (`base/registry/op_impl_space_registry_v2_impl.cc:79-129`)

```c
void *const handle = mmDlopen(
    so_path,
    static_cast<int32_t>(static_cast<uint32_t>(MMPA_RTLD_NOW) | static_cast<uint32_t>(MMPA_RTLD_GLOBAL)));
```

**达成路径**

```
MM_SYS_GET_ENV@plugin_manager.cc:159 → GetOppPath@plugin_manager.cc:156 → LoadOpsProtoSo@opp_so_manager.cc:168 → AddSoToRegistry@op_impl_space_registry_v2_impl.cc:79 → mmDlopen@op_impl_space_registry_v2_impl.cc:91
```

**验证说明**: Cross-module data flow verified: ASCEND_OPP_PATH environment variable directly controls library loading path through GetOppPath() → GetOpsProtoPath() → LoadOpsProtoSo() → AddSoToRegistry() → mmDlopen(). No signature or whitelist verification exists before mmDlopen(). mmRealPath() only checks path existence, not library authenticity. Version validation exists in IsVendorVersionValid() but is bypassable: (1) paths containing 'opp_latest' skip version check entirely, (2) missing version.info files also skip verification. Attacker with control of ASCEND_OPP_PATH can inject arbitrary .so libraries that will be loaded and executed.

**CVSS 评估建议**: 8.8 (High) - CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -5 | context: 0 | cross_file: 0

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cross_module | 1 | 0 | 0 | 0 | 1 |
| registry | 1 | 0 | 0 | 0 | 1 |
| **合计** | **2** | **0** | **0** | **0** | **2** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-427 | 1 | 50.0% |
| CWE-426 | 1 | 50.0% |

---

## 6. 修复建议

### 6.1 高优先级修复措施 (P0)

#### 修复措施 1: 实现签名验证机制

**修改文件**: `base/registry/op_impl_space_registry_v2_impl.cc`

为所有动态库实现数字签名验证，确保加载的库来自可信来源。

```cpp
// 建议新增签名验证函数
bool VerifySoSignature(const std::string &so_path) {
    // 读取签名文件 (如 .sig 或内嵌签名)
    std::string sig_path = so_path + ".sig";
    
    // 使用公钥验证签名
    // 仅华为官方签名或授权签名有效
    if (!VerifyDigitalSignature(so_path, sig_path, trusted_public_key)) {
        GELOGE("Signature verification failed for %s", so_path.c_str());
        return false;
    }
    return true;
}

// 在 AddSoToRegistry 中添加验证
ge::graphStatus OpImplSpaceRegistryImpl::AddSoToRegistry(const OppSoDesc &so_desc) {
    for (const auto &so_path : so_desc.GetSoPaths()) {
        // 新增：签名验证
        if (!VerifySoSignature(std::string(so_path.GetString()))) {
            GELOGE("Rejected unsigned library: %s", so_path.GetString());
            continue;  // 拒绝未签名库
        }
        
        void *const handle = mmDlopen(so_path.GetString(), ...);
        // ...
    }
}
```

#### 修复措施 2: 移除 opp_latest 自动绕过逻辑

**修改文件**: `base/common/plugin/plugin_manager.cc`

移除 `opp_latest` 路径的自动验证绕过，即使是 opp_kernel 包也需要进行安全验证。

```cpp
// plugin_manager.cc:380-396 修改建议
bool PluginManager::IsVendorVersionValid(const std::string &vendor_path) {
  // 移除 opp_latest 自动绕过逻辑
  // 即使是 opp_kernel 包，也应验证签名或使用白名单
  
  std::string opp_version;
  std::string compiler_version;
  GetOppAndCompilerVersion(vendor_path, opp_version, compiler_version);
  
  // 强制要求版本信息或签名验证
  if (opp_version.empty() && compiler_version.empty()) {
    GELOGE("[Security] Rejected path without version info: %s", vendor_path.c_str());
    return false;  // 改为拒绝而非跳过
  }
  return IsVendorVersionValid(opp_version, compiler_version);
}
```

### 6.2 高优先级修复措施 (P1)

#### 修复措施 3: 添加可信路径白名单

**修改文件**: `base/common/plugin/plugin_manager.cc`

实现环境变量路径白名单验证，限制可接受的算子库来源路径。

```cpp
// 新增可信路径验证函数
bool PluginManager::IsTrustedOppPath(const std::string &path) {
  // 定义可信路径白名单
  const std::vector<std::string> trusted_paths = {
    "/usr/local/Ascend/",
    "/opt/Ascend/",
    "/home/ascend/",  // 根据实际部署配置
    GetModelPath()    // 程序自身安装路径
  };
  
  std::string real_path = RealPath(path.c_str());
  if (real_path.empty()) {
    return false;
  }
  
  for (const auto &trusted : trusted_paths) {
    std::string trusted_real = RealPath(trusted.c_str());
    if (!trusted_real.empty() && 
        real_path.find(trusted_real) == 0) {
      return true;
    }
  }
  
  GELOGE(ge::FAILED, "[Security] OPP path [%s] is not in trusted whitelist!", path.c_str());
  return false;
}

// 在 GetOppPath 中添加验证
ge::Status PluginManager::GetOppPath(std::string &opp_path) {
  const ge::char_t *path_env = nullptr;
  MM_SYS_GET_ENV(MM_ENV_ASCEND_OPP_PATH, path_env);
  if ((path_env != nullptr) && (strlen(path_env) > 0U)) {
    opp_path = path_env;
    // [新增] 验证路径可信性
    if (!IsTrustedOppPath(opp_path)) {
      GELOGE(ge::FAILED, "[Security] Rejected untrusted OPP path from environment: %s", opp_path.c_str());
      opp_path.clear();
      return ge::FAILED;  // 拒绝不可信路径
    }
    // ...
  }
  // ...
}
```

#### 修复措施 4: 在关键路径添加 ValidateSo

**修改文件**: `base/registry/opp_so_manager.cc`

在 `LoadSoAndInitDefault()` 中添加 `ValidateSo` 调用，确保关键加载路径也执行文件大小验证。

```cpp
// opp_so_manager.cc:111-124 修改建议
void OppSoManager::LoadSoAndInitDefault(const std::vector<AscendString> &so_list, ...) const {
    int64_t size_of_loaded_so = 0;
    for (const auto &so_path_ascend : so_list) {
        auto so_path = so_path_ascend.GetString();
        
        // 新增：调用 ValidateSo
        int64_t file_size = 0;
        if (ValidateSo(std::string(so_path), size_of_loaded_so, file_size) != ge::SUCCESS) {
            GELOGW("Rejected library after validation: %s", so_path);
            continue;
        }
        
        // 新增：签名验证（配合修复措施 1）
        if (!VerifySoSignature(std::string(so_path))) {
            continue;
        }
        
        // 加载库
        gert::OppSoDesc opp_so_desc(so_list, ...);
        // ...
    }
}
```

### 6.3 配置层面加固建议

#### 1. 环境变量安全配置

```bash
# 在系统配置中锁定环境变量
export ASCEND_OPP_PATH=/usr/local/Ascend/opp

# 通过权限控制禁止用户覆盖
chmod 755 /usr/local/Ascend/opp
chown root:ascend /usr/local/Ascend/opp
```

#### 2. 启用审计日志

- 添加对环境变量来源的审计日志
- 记录所有动态库加载操作
- 监控异常路径访问

```cpp
// 建议添加审计日志
GELOG_SECURITY("Loading library from path: %s, source: %s", 
               so_path.c_str(), 
               path_env ? "ENV" : "DEFAULT");
```

#### 3. 权限隔离

- 使用专用用户运行 CANN 应用
- 限制算子库目录的写入权限
- 实施最小权限原则

### 6.4 修复优先级总结

| 优先级 | 修复措施 | 预估工作量 | 影响范围 |
|-------|---------|-----------|---------|
| P0 | 签名验证机制 | 中 | 所有动态库加载 |
| P0 | 移除 opp_latest 绕过 | 低 | 版本验证逻辑 |
| P1 | 可信路径白名单 | 低 | 环境变量处理 |
| P1 | 关键路径 ValidateSo | 低 | 库加载流程 |
| P2 | 审计日志增强 | 低 | 全系统 |

---

## 7. 附录

### 7.1 相关文件位置

| 文件 | 路径 | 关键行号 |
|-----|------|---------|
| op_impl_space_registry_v2_impl.cc | base/registry/ | 79-159 (AddSoToRegistry) |
| opp_so_manager.cc | base/registry/ | 111-124, 168-222 |
| plugin_manager.cc | base/common/plugin/ | 156-179, 380-396, 775-802 |
| file_utils.cc | base/utils/ | 30-49 (RealPath) |

### 7.2 环境变量定义

| 变量名 | 作用 | 安全风险 |
|-------|------|---------|
| `ASCEND_OPP_PATH` | 算子包根目录 | 高 - 可注入任意库路径 |
| `ASCEND_CUSTOM_OPP_PATH` | 自定义算子路径 | 高 - 可注入自定义算子库 |
| `ASCEND_HOME_PATH` | Ascend 安装目录 | 中 - 用于 opp_latest 路径构造 |
| `ASCEND_WORK_PATH` | 工作路径目录 | 中 - 可控制工作目录位置 |

### 7.3 参考资料

- CWE-426: Untrusted Search Path: https://cwe.mitre.org/data/definitions/426.html
- CWE-427: Uncontrolled Search Path Element: https://cwe.mitre.org/data/definitions/427.html
- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- SEI CERT C Coding Standard: SEC06-C. Handle library loading securely

---

*报告生成时间: 2026-04-22*  
*分析工具: OpenCode Vulnerability Scanner*  
*深度分析报告: scan-results/details/VULN-DF-CROSS-001.md, VULN-SEC-DYN-003.md*
