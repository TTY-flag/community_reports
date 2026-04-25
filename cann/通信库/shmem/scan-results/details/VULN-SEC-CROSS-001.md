# VULN-SEC-CROSS-001: 跨模块TLS凭证泄露攻击链

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-SEC-CROSS-001 |
| **类型** | credential_exposure_chain |
| **CWE** | CWE-798 (硬编码凭证) |
| **严重性** | Critical |
| **状态** | CONFIRMED |
| **涉及模块** | Python绑定模块、TLS安全模块、初始化模块 |

**核心问题**: 这是一个完整的跨模块安全漏洞链，从Python回调注入到全局凭证存储，形成可被利用的完整攻击路径。攻击者可以通过Python API注入恶意回调函数，绕过TLS密码验证，最终获取TLS私钥密码并使其暴露在全局内存中。

## 详细技术分析

### 漏洞链路

```
Python层 → C++绑定层 → TLS安全层 → 初始化层 → 全局凭证存储
```

#### 第一层: Python回调注入 (无验证)

**文件**: `/src/host/python_wrapper/pyshmem.cpp`

**问题代码**:
```cpp
// 第26行: 全局存储Python回调函数
static py::function g_py_decrypt_func;

// 第99-110行: 接受任意Python回调，无签名验证
int32_t aclshmem_set_conf_store_tls_key_with_decrypt(std::string &tls_pk, std::string &tls_pk_pw,
    std::optional<py::function> py_decrypt_func = std::nullopt)
{
    if (!py_decrypt_func || !py_decrypt_func.has_value()) {
        return aclshmemx_set_config_store_tls_key(..., nullptr);
    }

    g_py_decrypt_func = *py_decrypt_func;  // 第107行: 无验证地存储到全局
    return aclshmemx_set_config_store_tls_key(..., py_decrypt_handler_wrapper);
}
```

**安全问题**:
- 用户可以传入任意Python函数作为解密回调
- 无函数签名验证、无类型检查、无沙箱限制
- 存储在全局静态变量中，所有代码可访问

#### 第二层: GIL竞态条件 (线程安全问题)

**文件**: `/src/host/python_wrapper/pyshmem.cpp`

**问题代码**:
```cpp
// 第72-97行: C++回调包装器 - 缺少GIL保护
static int py_decrypt_handler_wrapper(const char *cipherText, size_t cipherTextLen, char *plainText,
                                       size_t &plainTextLen)
{
    // 注意: 这里没有 py::gil_scoped_acquire!
    try {
        py::str py_cipher = py::str(cipherText, cipherTextLen);
        std::string plain = py::cast<std::string>(
            g_py_decrypt_func(py_cipher).cast<py::str>());  // 直接调用Python函数
        ...
    }
}
```

**对比正确实现** (第115-116行的 `bridge_logger`):
```cpp
static void bridge_logger(int level, const char *msg)
{
    if (g_py_logger_func) {
        py::gil_scoped_acquire acquire;  // 正确: 获取GIL
        g_py_logger_func(level, msg);
    }
}
```

**安全问题**:
- 从C++线程调用Python回调时，没有获取GIL
- 导致竞态条件、潜在的内存损坏、程序崩溃
- 可能导致Python解释器内部状态不一致

#### 第三层: TLS密码解密调用

**文件**: `/src/host/bootstrap/config_store/acc_links/csrc/security/acc_tcp_ssl_helper.cpp`

**问题代码**:
```cpp
// 第185-212行: GetPkPass() 函数
AccResult AccTcpSslHelper::GetPkPass()
{
    std::string encryptedText = utils::StringUtil::TrimString(tlsPkPwd);
    if (mDecryptHandler_ == nullptr) {
        // 使用明文密码
        mKeyPass = std::make_pair(new char[len + 1], len);
        std::copy(encryptedText.begin(), encryptedText.end(), mKeyPass.first);
    } else {
        // 第202行: 调用解密回调 (可能是恶意注入的Python函数)
        auto buffer = new (std::nothrow) char[encryptedText.length() * UNO_2];
        auto ret = static_cast<AccResult>(
            mDecryptHandler_(encryptedText, buffer, bufferLen));  // 调用回调
        mKeyPass = std::make_pair(buffer, bufferLen);  // 存储解密结果
    }
    return ACC_OK;
}
```

**安全问题**:
- `mDecryptHandler_` 可能是用户注入的恶意回调
- 解密后的密码存储在 `mKeyPass` 成员变量中
- 这个回调在TLS初始化期间被调用

#### 第四层: 全局凭证存储 (凭证泄露)

**文件**: `/src/host/init/shmem_init.cpp` 和 `/src/host/utils/shmemi_host_types.h`

**问题代码**:
```cpp
// shmemi_host_types.h 第32-60行: 全局结构体定义
typedef struct aclshmemi_bootstrap_handle {
    const char  *tls_pk;       // 第36行: TLS私钥
    const char  *tls_pk_pw;    // 第37行: TLS密码
    aclshmem_decrypt_handler decrypt_handler;  // 第44行: 解密回调
    ...
} aclshmemi_bootstrap_handle_t;

// shmem_init.cpp 第78行: 全局变量声明
aclshmemi_bootstrap_handle_t g_boot_handle;

// 第620-630行: 设置TLS密钥和密码
int32_t aclshmemx_set_config_store_tls_key(const char *tls_pk, const uint32_t tls_pk_len,
    const char *tls_pk_pw, const uint32_t tls_pk_pw_len, const aclshmem_decrypt_handler decrypt_handler)
{
    g_boot_handle.tls_pk = tls_pk;
    g_boot_handle.tls_pk_len = tls_pk_len;
    g_boot_handle.tls_pk_pw = tls_pk_pw;          // 第625行: 密码存入全局
    g_boot_handle.tls_pk_pw_len = tls_pk_pw_len;
    g_boot_handle.decrypt_handler = decrypt_handler;
    return ACLSHMEM_SUCCESS;
}
```

**安全问题**:
- TLS私钥和密码被存储在全局变量 `g_boot_handle` 中
- 所有进程代码都可以访问这些敏感信息
- 没有访问控制、没有加密存储、没有生命周期管理

## 利用场景和攻击路径

### 攻击场景1: 恶意回调注入

**攻击者视角**:
```python
import _pyshmem

# 创建恶意回调函数
def malicious_decrypt(cipher_text):
    # 返回任意密码，绕过TLS验证
    return "attacker_known_password"
    # 或者:
    # 1. 记录原始密码到日志
    # 2. 返回弱密码
    # 3. 执行任意代码

# 注入恶意回调
_pyshmem.set_conf_store_tls_key(
    tls_pk="fake_private_key",
    tls_pk_pw="encrypted_password",
    py_decrypt_func=malicious_decrypt
)
```

**后果**:
- 绕过TLS证书验证
- 可能导致中间人攻击
- 破坏集群安全通信

### 攻击场景2: 信息泄露

**攻击者视角**:
```python
# 通过其他模块访问全局变量
# g_boot_handle.tls_pk_pw 可被任意代码读取
# 敏感密码暴露给所有进程代码
```

**后果**:
- TLS私钥密码泄露
- 可能被用于伪造证书
- 破坏整个集群的安全基础

### 攻击场景3: GIL竞态导致崩溃

**攻击者视角**:
```python
import threading

# 多线程场景下触发回调
def race_condition_decrypt(cipher):
    # 在没有GIL的情况下被调用
    # 可能导致Python解释器崩溃
    return "password"

# 启动多个线程触发初始化
# 每个线程都可能导致竞态条件
```

**后果**:
- 程序崩溃
- 数据损坏
- 服务拒绝

### 完整攻击链路图

```
┌─────────────────────────────────────────────────────────────────────┐
│                        攻击入口点                                    │
│  Python API: set_conf_store_tls_key(tls_pk, tls_pk_pw, callback)   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     漏洞点1: 回调注入                                │
│  pyshmem.cpp:107                                                    │
│  g_py_decrypt_func = *py_decrypt_func                              │
│  (无验证，任意函数可存储)                                            │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     漏洞点2: GIL缺失                                │
│  pyshmem.cpp:82                                                     │
│  g_py_decrypt_func(py_cipher)                                      │
│  (从C++线程调用Python，缺少GIL)                                      │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     漏洞点3: TLS解密                                │
│  acc_tcp_ssl_helper.cpp:202                                        │
│  mDecryptHandler_(encryptedText, buffer, bufferLen)                │
│  (调用可能被污染的回调)                                              │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     漏洞点4: 全局存储                                │
│  shmem_init.cpp:625                                                │
│  g_boot_handle.tls_pk_pw = tls_pk_pw                              │
│  (敏感密码存入全局变量)                                              │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        最终后果                                     │
│  • TLS凭证泄露给所有进程代码                                         │
│  • 恶意回调可绕过TLS验证                                             │
│  • GIL竞态可导致崩溃                                                 │
└─────────────────────────────────────────────────────────────────────┘
```

## PoC 概念验证思路

### PoC 1: 回调注入验证

```python
#!/usr/bin/env python3
"""
概念验证: 验证回调可以被注入且无验证
"""
import _pyshmem

def injected_callback(cipher_text):
    # 验证回调被执行
    print(f"[PoC] Callback executed with: {cipher_text}")
    # 返回测试密码
    return "poc_password"

# 测试注入
result = _pyshmem.set_conf_store_tls_key(
    "test_private_key",
    "encrypted_test_password",
    injected_callback
)
print(f"[PoC] Injection result: {result}")
# 预期: 函数被接受，无任何验证警告
```

### PoC 2: GIL问题验证

```python
#!/usr/bin/env python3
"""
概念验证: 验证GIL缺失导致的线程安全问题
"""
import _pyshmem
import threading
import time

call_count = 0
crash_detected = False

def unsafe_callback(cipher):
    global call_count, crash_detected
    call_count += 1
    # 尝试访问Python对象 (在没有GIL的情况下)
    try:
        # 可能触发Python内部状态问题
        return str(call_count)
    except Exception as e:
        crash_detected = True
        return ""

# 多线程测试
threads = []
for i in range(10):
    t = threading.Thread(target=lambda: _pyshmem.set_conf_store_tls_key(
        "key", "pw", unsafe_callback
    ))
    threads.append(t)

for t in threads:
    t.start()
for t in threads:
    t.join()

print(f"[PoC] Calls: {call_count}, Crash: {crash_detected}")
# 预期: 在某些情况下可能触发崩溃或异常
```

### PoC 3: 信息泄露验证

```python
#!/usr/bin/env python3
"""
概念验证: 验证全局变量可被访问
"""
# 通过C扩展或其他方式访问 g_boot_handle
# 在实际场景中，攻击者可能:
# 1. 使用调试器读取全局变量
# 2. 通过内存扫描获取密码
# 3. 通过其他模块的API间接访问
```

## 修复建议

### 立即修复 (Critical优先级)

#### 修复点1: 添加GIL保护

**文件**: `src/host/python_wrapper/pyshmem.cpp`

```cpp
static int py_decrypt_handler_wrapper(const char *cipherText, size_t cipherTextLen, char *plainText,
                                       size_t &plainTextLen)
{
    if (cipherTextLen > MAX_CIPHER_LEN || !g_py_decrypt_func || g_py_decrypt_func.is_none()) {
        std::cerr << "input cipher len is too long or decrypt func invalid." << std::endl;
        return -1;
    }

    try {
        // 修复: 添加GIL获取
        py::gil_scoped_acquire acquire;  // 关键修复
        
        py::str py_cipher = py::str(cipherText, cipherTextLen);
        std::string plain = py::cast<std::string>(g_py_decrypt_func(py_cipher).cast<py::str>());
        ...
    }
}
```

#### 修复点2: 回调签名验证

**文件**: `src/host/python_wrapper/pyshmem.cpp`

```cpp
int32_t aclshmem_set_conf_store_tls_key_with_decrypt(std::string &tls_pk, std::string &tls_pk_pw,
    std::optional<py::function> py_decrypt_func = std::nullopt)
{
    if (!py_decrypt_func || !py_decrypt_func.has_value()) {
        return aclshmemx_set_config_store_tls_key(..., nullptr);
    }

    // 修复: 验证函数签名
    py::function func = *py_decrypt_func;
    if (!py::hasattr(func, "__call__")) {
        std::cerr << "Invalid decrypt function: not callable" << std::endl;
        return -1;
    }
    
    // 可选: 测试回调一次，验证返回类型
    try {
        py::gil_scoped_acquire acquire;
        auto test_result = func(py::str("test"));
        if (!py::isinstance<py::str>(test_result)) {
            std::cerr << "Invalid decrypt function: must return str" << std::endl;
            return -1;
        }
    } catch (...) {
        std::cerr << "Invalid decrypt function: test call failed" << std::endl;
        return -1;
    }

    g_py_decrypt_func = func;
    return aclshmemx_set_config_store_tls_key(..., py_decrypt_handler_wrapper);
}
```

#### 修复点3: 避免全局存储敏感信息

**文件**: `src/host/init/shmem_init.cpp`

```cpp
// 修复: 使用加密存储或限制访问
int32_t aclshmemx_set_config_store_tls_key(const char *tls_pk, const uint32_t tls_pk_len,
    const char *tls_pk_pw, const uint32_t tls_pk_pw_len, const aclshmem_decrypt_handler decrypt_handler)
{
    // 修复: 加密存储密码
    // 或者使用进程级私有存储
    // 或者在使用后立即清除
    
    // 建议: 使用临时存储，在TLS初始化完成后清除
    static std::string encrypted_pk_pw;
    if (tls_pk_pw && tls_pk_pw_len > 0) {
        encrypted_pk_pw.assign(tls_pk_pw, tls_pk_pw_len);
        g_boot_handle.tls_pk_pw = encrypted_pk_pw.c_str();
    }
    
    // 设置回调后，标记需要清除
    g_boot_handle.decrypt_handler = decrypt_handler;
    g_boot_handle.credentials_need_cleanup = true;
    
    return ACLSHMEM_SUCCESS;
}
```

### 长期改进建议

1. **沙箱机制**: 为Python回调实现沙箱限制
2. **安全审计**: 添加所有敏感操作的审计日志
3. **内存清理**: 在TLS初始化完成后立即清除密码内存
4. **访问控制**: 实现基于角色的凭证访问控制
5. **加密存储**: 对存储在内存中的密码进行加密

## 影响范围评估

### 直接影响

| 影项范围 | 描述 | 严重程度 |
|---------|------|---------|
| **TLS通信安全** | 可能被绕过，导致中间人攻击 | Critical |
| **集群认证** | 凭证泄露可能导致集群被入侵 | Critical |
| **服务稳定性** | GIL问题可能导致服务崩溃 | High |
| **数据安全** | 通信内容可能被窃取 | Critical |

### 受影响代码模块

| 模块 | 文件 | 行号 | 漏洞类型 |
|------|------|------|---------|
| Python绑定 | pyshmem.cpp | 26, 72-97, 99-110 | 回调注入、GIL缺失 |
| TLS安全 | acc_tcp_ssl_helper.cpp | 185-212 | 回调执行 |
| 初始化 | shmem_init.cpp | 620-630, 78 | 全局存储 |
| 类型定义 | shmemi_host_types.h | 32-60 | 结构体定义 |

### 攻击复杂度

| 因素 | 评估 |
|------|------|
| **攻击入口** | 低 - 公开Python API |
| **利用难度** | 低 - 直接注入回调 |
| **所需权限** | 低 - 用户级权限 |
| **影响范围** | 高 - 整个集群 |

## 结论

这是一个**真实且严重的跨模块安全漏洞链**，涉及多个关键安全问题：

1. **Python回调注入漏洞**: 用户可以注入任意Python回调函数，无任何验证
2. **GIL竞态条件**: 从C++线程调用Python回调时缺少GIL保护
3. **TLS密码泄露**: 解密后的密码存储在全局变量中
4. **凭证暴露**: 所有进程代码可以访问敏感凭证

**漏洞链完整性**: 多个漏洞点串联形成完整的攻击路径，从Python层注入到全局凭证存储，形成可被直接利用的安全漏洞链。

**建议立即修复**: 这是Critical级别的安全漏洞，应立即进行修复，优先处理GIL问题和回调验证。

---
**报告生成时间**: 2026-04-25
**分析者**: security-auditor
**状态**: CONFIRMED
