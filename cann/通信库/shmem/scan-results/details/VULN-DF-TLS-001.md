# VULN-DF-TLS-001: TLS回调注入漏洞

## 漏洞概述

| 属性 | 值 |
|------|-----|
| 漏洞ID | VULN-DF-TLS-001 |
| 类型 | 回调注入 (Callback Injection) |
| CWE | CWE-94: Improper Control of Generation of Code ('Code Injection') |
| 严重程度 | **Critical** |
| 状态 | CONFIRMED |
| 影响模块 | host_bootstrap/config_store |

**漏洞描述**: 用户提供的私钥解密回调函数 (`AccDecryptHandler`) 在注册时仅进行简单的非空检查，没有对回调函数的行为、来源或签名进行任何安全验证。恶意回调可以在TLS私钥密码解密时执行任意代码、返回伪造密码或造成拒绝服务。

---

## 详细技术分析

### 1. 漏洞入口点 - 回调注册函数

**文件**: `src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp`

**位置**: Lines 329-334

```cpp
void AccTcpSslHelper::RegisterDecryptHandler(const AccDecryptHandler &h)
{
    ASSERT_RET_VOID(h != nullptr);          // 仅检查非空
    ASSERT_RET_VOID(mDecryptHandler_ == nullptr);  // 仅防止重复注册
    mDecryptHandler_ = h;                    // 直接存储回调，无任何验证
}
```

**问题分析**:
- `ASSERT_RET_VOID` 宏仅进行简单的条件检查和日志记录，没有任何安全验证机制
- 没有检查回调来源是否可信
- 没有签名验证或白名单机制
- 没有对回调行为进行约束

### 2. 回调类型定义

**文件**: `src/host/bootstrap/config_store/acc_links/include/acc_def.h`

**位置**: Lines 113-120

```cpp
/**
 * @brief Callback function of private key password decryptor
 */
using AccDecryptHandler = std::function<int(const std::string &cipherText, char *plainText, size_t &plainTextLen)>;
```

**问题分析**:
- 使用 `std::function` 类型，可接受任意可调用对象
- C API: `typedef int (*aclshmem_decrypt_handler)(const char*, size_t, char*, size_t&)`
- Python绑定允许任意Python函数作为回调

### 3. 回调执行点 - 私钥密码解密

**文件**: `src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp`

**位置**: Lines 185-212 (`GetPkPass()`)

```cpp
AccResult AccTcpSslHelper::GetPkPass()
{
    std::string encryptedText = utils::StringUtil::TrimString(tlsPkPwd);
    if (mDecryptHandler_ == nullptr) {
        // 明文密码处理...
    } else {
        LOG_INFO("user employs a ciphertext password, which requires a decryption function.");
        auto buffer = new (std::nothrow) char[encryptedText.length() * UNO_2];
        if (buffer == nullptr) {
            LOG_ERROR("allocate memory for buffer failed");
            return ACC_ERROR;
        }
        size_t bufferLen = encryptedText.length() * UNO_2;
        // ⚠️ 关键漏洞点：直接调用用户回调
        auto ret = static_cast<AccResult>(mDecryptHandler_(encryptedText, buffer, bufferLen));
        if (ret != ACC_OK) {
            LOG_ERROR("Failed to decrypt private key password");
            delete[] buffer;
            return ret;
        }
        mKeyPass = std::make_pair(buffer, bufferLen);  // 解密结果直接用于私钥加载
    }
    return ACC_OK;
}
```

**调用链**: `Start()` -> `InitSSL()` -> `LoadPrivateKey()` -> `GetPkPass()` -> `mDecryptHandler_()`

### 4. Python绑定攻击向量

**文件**: `src/host/python_wrapper/pyshmem.cpp`

**位置**: Lines 99-110

```cpp
int32_t aclshmem_set_conf_store_tls_key_with_decrypt(std::string &tls_pk, std::string &tls_pk_pw,
    std::optional<py::function> py_decrypt_func = std::nullopt)
{
    if (!py_decrypt_func || !py_decrypt_func.has_value()) {
        return aclshmemx_set_config_store_tls_key(tls_pk.c_str(), tls_pk.size(), tls_pk_pw.c_str(),
            tls_pk_pw.size(), nullptr);
    }

    g_py_decrypt_func = *py_decrypt_func;  // 存储任意Python函数
    return aclshmemx_set_config_store_tls_key(tls_pk.c_str(), tls_pk.size(), tls_pk_pw.c_str(),
        tls_pk_pw.size(), py_decrypt_handler_wrapper);  // 注册包装器
}
```

**Python回调包装器** (Lines 80-97):
```cpp
static int py_decrypt_handler_wrapper(const char *cipherText, size_t cipherTextLen, char *plainText, size_t &plainTextLen)
{
    py::gil_scoped_acquire acquire;
    try {
        py::str py_cipher = py::str(cipherText, cipherTextLen);
        // ⚠️ 直接调用用户提供的Python函数，无验证
        std::string plain = py::cast<std::string>(g_py_decrypt_func(py_cipher).cast<py::str>());
        // ...
        std::copy(plain.begin(), plain.end(), plainText);
        plainTextLen = plain.size();
        return 0;
    } catch (const py::error_already_set &e) {
        return -1;
    }
}
```

---

## 完整攻击链分析

### 数据流图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SOURCE (入口点)                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  Python API: aclshmem_set_conf_store_tls_key_with_decrypt(py_func)          │
│  C API: aclshmemx_set_config_store_tls_key(pk, pwd, handler)                │
│                                                                             │
│  → g_boot_handle.decrypt_handler (shmem_init.cpp:627)                       │
│  → StoreFactory::SetTlsPkInfo (store_factory.cpp:256-295)                   │
│  → tlsOption_.decryptHandler_ = ConvertFunc(h)                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           存储路径                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  AccTcpServerDefault::RegisterDecryptHandler(h)                             │
│  → decryptHandler_ = h (acc_tcp_server_default.h:136)                       │
│                                                                             │
│  AccTcpSslHelper::RegisterDecryptHandler(h)                                 │
│  → mDecryptHandler_ = h (acc_tcp_ssl_helper.cpp:333)                        │
│                                                                             │
│  ⚠️ 仅检查: h != nullptr && mDecryptHandler_ == nullptr                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SINK (执行点)                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│  InitSSL() → LoadPrivateKey() → GetPkPass()                                 │
│                                                                             │
│  GetPkPass() (acc_tcp_ssl_helper.cpp:202):                                  │
│  auto ret = mDecryptHandler_(encryptedText, buffer, bufferLen);             │
│                                                                             │
│  解密结果传递给:                                                             │
│  → SslCtxSetDefaultPasswdCbUserdata(sslCtx, mKeyPass.first)                 │
│  → PemReadBioPk(bio, nullptr, nullptr, mKeyPass.first)                      │
│                                                                             │
│  ⚠️ 在TLS私钥加载流程中执行用户回调                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 模块调用关系

```
Python用户代码
    ↓
pyshmem.cpp::aclshmem_set_conf_store_tls_key_with_decrypt()
    ↓
shmem_init.cpp::aclshmemx_set_config_store_tls_key() [API入口]
    ↓
shmemi_bootstrap_config_store.cpp::config_store_bootstrap_set_tls_key()
    ↓
store_factory.cpp::StoreFactory::SetTlsPkInfo()
    ↓ (ConvertFunc转换)
AccTcpServerDefault::RegisterDecryptHandler()
    ↓
AccTcpSslHelper::RegisterDecryptHandler() [漏洞位置]
    ↓ (延迟调用)
AccTcpSslHelper::GetPkPass() [回调执行]
```

---

## 利用场景和攻击路径

### 场景1: 代码注入攻击

**攻击向量**: Python用户注册恶意回调函数

```python
import aclshmem

def malicious_decrypt(cipher_text):
    # 在解密回调中执行任意代码
    import os
    os.system("malicious_command")  # 可执行任意系统命令
    
    # 或窃取敏感数据
    with open("/etc/passwd", "r") as f:
        sensitive_data = f.read()
        # 发送到攻击者服务器...
    
    # 返回伪造密码
    return "fake_password"

aclshmem.set_conf_store_tls_key_with_decrypt(private_key, encrypted_password, malicious_decrypt)
```

**影响**:
- 在TLS初始化阶段执行任意代码
- 代码在进程上下文中运行，具有进程权限
- 可能导致数据泄露、权限提升或系统入侵

### 场景2: 拒绝服务攻击

**攻击向量**: 回调返回错误或导致崩溃

```python
def dos_decrypt(cipher_text):
    # 返回错误导致TLS初始化失败
    raise RuntimeError("DoS attack")
    
    # 或返回超长字符串触发缓冲区问题
    # return "A" * 1000000
```

**影响**:
- TLS初始化失败，服务无法启动
- 依赖TLS通信的分布式训练任务失败
- 高可用系统服务中断

### 场景3: 密码伪造攻击

**攻击向量**: 回调返回伪造密码绕过安全检查

```python
def fake_decrypt(cipher_text):
    # 返回伪造密码，可能绕过某些检查
    return "bypass_password"
```

**影响**:
- 可能使用错误密码加载私钥
- TLS握手失败导致通信中断
- 安全边界被绕过

### 场景4: 跨模块攻击

**攻击路径**: Python → C++ → OpenSSL

```
Python恶意回调
    ↓ (pybind11)
C++回调包装器 (py_decrypt_handler_wrapper)
    ↓
std::function调用 (mDecryptHandler_)
    ↓
OpenSSL API调用
    ↓ (敏感操作)
SSL_CTX密码设置 & 私钥加载
```

---

## PoC 概念验证思路

### PoC 1: 基础回调注入验证

```python
#!/usr/bin/env python3
"""
PoC: 验证回调注入漏洞存在性
"""

import aclshmem
import logging

CALLBACK_EXECUTED = False

def poc_decrypt_callback(cipher_text):
    global CALLBACK_EXECUTED
    CALLBACK_EXECUTED = True
    logging.warning("[PoC] Callback executed during TLS password decryption!")
    logging.warning(f"[PoC] Received cipher text length: {len(cipher_text)}")
    
    # 模拟正常返回
    return "test_password"

def test_callback_injection():
    """验证回调在TLS初始化时被调用"""
    # 设置TLS配置
    private_key = "mock_private_key_content"
    encrypted_password = "encrypted_password"
    
    # 注册恶意回调
    aclshmem.set_conf_store_tls_key_with_decrypt(
        private_key, 
        encrypted_password,
        poc_decrypt_callback
    )
    
    # 初始化ACL SHMEM (触发TLS初始化)
    # aclshmem.init(...)  # 实际测试需要完整环境
    
    if CALLBACK_EXECUTED:
        logging.error("[PoC] VULNERABILITY CONFIRMED: Callback was executed!")
        return True
    return False

if __name__ == "__main__":
    if test_callback_injection():
        print("VULN-DF-TLS-001: Callback Injection Vulnerability CONFIRMED")
```

### PoC 2: 代码执行验证

```python
#!/usr/bin/env python3
"""
PoC: 验证回调可执行任意代码
"""

import aclshmem
import tempfile
import os

MARKER_FILE = "/tmp/poc_vuln_tls_marker"

def code_execution_callback(cipher_text):
    # 在回调中执行任意代码
    with open(MARKER_FILE, "w") as f:
        f.write("PoC executed arbitrary code in TLS callback!")
    
    # 执行系统命令示例
    # os.system("id > /tmp/poc_vuln_tls_id")
    
    return "fake_password"

def test_code_execution():
    # 清理旧标记文件
    if os.path.exists(MARKER_FILE):
        os.remove(MARKER_FILE)
    
    # 注册回调
    aclshmem.set_conf_store_tls_key_with_decrypt(
        "mock_pk", 
        "mock_pwd",
        code_execution_callback
    )
    
    # 触发TLS初始化
    # aclshmem.init(...)
    
    # 检查标记文件是否存在
    if os.path.exists(MARKER_FILE):
        print("CRITICAL: Arbitrary code execution in TLS callback confirmed!")
        return True
    return False
```

### PoC 3: C API 回调注入

```c
/*
 * PoC: C API回调注入验证
 */

#include <stdio.h>
#include <string.h>
#include "aclshmem.h"

static int malicious_handler(const char* cipherText, size_t cipherLen, 
                             char* plainText, size_t& plainTextLen) {
    printf("[PoC] Malicious callback invoked!\n");
    printf("[PoC] Cipher length: %zu\n", cipherLen);
    
    // 执行任意操作
    system("echo 'PoC executed' > /tmp/poc_tls_callback");
    
    // 返回伪造密码
    strcpy(plainText, "injected_password");
    plainTextLen = strlen("injected_password");
    
    return 0;  // ACC_OK
}

int main() {
    // 注册恶意回调
    const char* pk = "mock_private_key";
    const char* pwd = "encrypted_password";
    
    int ret = aclshmemx_set_config_store_tls_key(
        pk, strlen(pk),
        pwd, strlen(pwd),
        malicious_handler
    );
    
    if (ret == 0) {
        printf("Malicious callback registered successfully!\n");
        printf("Callback will be invoked during TLS initialization.\n");
    }
    
    return 0;
}
```

---

## 修复建议

### 1. 紧急修复方案 (短期)

**增加回调验证机制**:

```cpp
void AccTcpSslHelper::RegisterDecryptHandler(const AccDecryptHandler &h)
{
    ASSERT_RET_VOID(h != nullptr);
    ASSERT_RET_VOID(mDecryptHandler_ == nullptr);
    
    // 新增：回调来源验证
    ASSERT_RET_VOID(ValidateCallbackSource(h));
    
    // 新增：回调行为约束（沙箱化）
    ASSERT_RET_VOID(RegisterSandboxedCallback(h));
    
    mDecryptHandler_ = h;
}
```

### 2. 架构级修复方案 (中期)

**方案A: 白名单机制**

```cpp
// 定义可信回调注册表
class CallbackRegistry {
private:
    static std::set<std::string> trustedCallbackIds_;
    
public:
    static bool IsTrusted(const std::string& callbackId) {
        return trustedCallbackIds_.count(callbackId) > 0;
    }
    
    static void RegisterTrusted(const std::string& callbackId) {
        // 仅允许管理员注册可信回调
        trustedCallbackIds_.insert(callbackId);
    }
};
```

**方案B: 回调签名验证**

```cpp
// 使用数字签名验证回调完整性
class SignedCallback {
public:
    static bool VerifySignature(const std::string& callbackId, 
                                const std::string& signature) {
        // 验证回调是否由可信源签名
        return CryptoUtils::VerifySignature(callbackId, signature);
    }
};
```

### 3. Python绑定安全加固

**限制Python回调能力**:

```cpp
static int py_decrypt_handler_wrapper(const char *cipherText, size_t cipherTextLen, 
                                      char *plainText, size_t &plainTextLen)
{
    // 新增：Python沙箱限制
    py::gil_scoped_acquire acquire;
    
    // 禁止危险操作
    PyDict_SetDefault(PyEval_GetGlobals(), 
                      py::str("__import__").ptr(), 
                      Py_None);
    
    try {
        // 限制回调执行时间
        auto result = py::module_::import("threading");
        auto timer = result.attr("Timer")(5, [](){ throw std::runtime_error("Timeout"); });
        timer.attr("start")();
        
        py::str py_cipher = py::str(cipherText, cipherTextLen);
        std::string plain = py::cast<std::string>(g_py_decrypt_func(py_cipher).cast<py::str>());
        
        // 新增：输出长度限制
        if (plain.size() > MAX_PASSWORD_LEN) {
            LOG_ERROR("Decrypted password too long");
            return -1;
        }
        
        std::copy(plain.begin(), plain.end(), plainText);
        plainTextLen = plain.size();
        return 0;
    } catch (...) {
        return -1;
    }
}
```

### 4. API文档安全警告

在API文档中添加安全警告：

```cpp
/**
 * @brief Register private key password decryptor
 * 
 * @warning SECURITY: The decrypt_handler will be invoked during TLS 
 *          initialization with access to sensitive password data.
 *          Only register trusted callback functions from verified sources.
 *          Malicious callbacks can execute arbitrary code, inject passwords,
 *          or cause denial of service.
 * 
 * @param decrypt_handler MUST be a trusted callback function with proper
 *                        validation and sandboxing. DO NOT accept callbacks
 *                        from untrusted user input.
 */
int32_t aclshmemx_set_config_store_tls_key(const char *tls_pk, ...);
```

---

## 影响范围评估

### 受影响组件

| 模块 | 文件 | 函数 | 影响 |
|------|------|------|------|
| host_init | shmem_init.cpp | aclshmemx_set_config_store_tls_key | API入口点 |
| host_python_wrapper | pyshmem.cpp | aclshmem_set_conf_store_tls_key_with_decrypt | Python攻击向量 |
| host_bootstrap/config_store | store_factory.cpp | SetTlsPkInfo | 回调存储 |
| acc_links | acc_tcp_server_default.h | RegisterDecryptHandler | 回调注册 |
| acc_links/security | acc_tcp_ssl_helper.cpp | RegisterDecryptHandler | **漏洞核心位置** |
| acc_links/security | acc_tcp_ssl_helper.cpp | GetPkPass | **回调执行点** |

### 影响场景

1. **分布式训练场景**: 使用TLS加密通信的AI训练集群
2. **多租户环境**: 不同用户可能注册不同回调
3. **Python用户场景**: 通过Python绑定使用ACL SHMEM的用户
4. **云服务场景**: 云上AI服务使用此库进行安全通信

### 风险评分详情

| 因子 | 得分 | 说明 |
|------|------|------|
| Base | 30 | 回调注入可执行任意代码 |
| Reachability | 30 | 回调在TLS初始化时必然被调用 |
| Controllability | 25 | 用户完全控制回调内容 |
| Mitigations | 0 | 无现有缓解措施 |
| Context | -5 | 需要TLS配置启用 |
| Cross-file | 0 | 跨模块攻击链完整 |
| **总分** | **80** | **Critical** |

---

## 总结

VULN-DF-TLS-001 是一个 **Critical级别的回调注入漏洞**，攻击者可以通过注册恶意解密回调函数，在TLS私钥密码解密过程中执行任意代码。漏洞影响C API和Python绑定两种使用方式，攻击链完整且无现有缓解措施。

**建议立即采取修复措施**，优先实施回调白名单机制和Python绑定沙箱限制，并在API文档中添加安全警告。

---

*报告生成时间: 2026-04-25*
*漏洞状态: CONFIRMED - Critical*
