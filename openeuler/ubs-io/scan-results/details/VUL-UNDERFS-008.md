# VUL-UNDERFS-008: Inconsistent Input Validation Across FileSystem Implementations

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VUL-UNDERFS-008 |
| **类型** | Inconsistent Validation (验证不一致) |
| **CWE** | CWE-697: Incorrect Comparison |
| **严重性** | MEDIUM → **HIGH (重新评估)** |
| **置信度** | 95% (原报告80%) |
| **影响范围** | LocalSystem (高危), CephSystem (中等), HdfsSystem (安全) |

## 漏洞详情

### 验证机制对比

| 组件 | KeyValid() | 验证内容 |
|------|------------|----------|
| **SDK (bio.cpp)** | ✅ 有 | 阻止 `/` 开头、`..` 路径遍历 |
| **HdfsSystem** | ✅ 有 | 阻止 `/` 开头、`..` 路径遍历 |
| **LocalSystem** | ❌ **无** | 无任何验证 - **高危** |
| **CephSystem** | ❌ **无** | 无验证 - 行为不一致 |

### 代码分析

**SDK KeyValid() (bio.cpp:123-144)**:
```cpp
inline static bool KeyValid(const char *key)
{
    if (UNLIKELY(key == nullptr)) return false;
    // ... 长度检查 ...
    if ((keyStr[0] == '/') || keyStr.find("..") != std::string::npos) {
        return false;  // 阻止路径遍历攻击
    }
    return true;
}
```

**HdfsSystem KeyValid() (hdfs_system.cpp:29-36)**:
```cpp
inline static bool KeyValid(const char *key)
{
    if (UNLIKELY(key == nullptr || strlen(key) == 0 || strlen(key) >= UFS_KEY_MAX_SIZE) || 
        (key[0] == '/') || std::strstr(key, "..")) {
        return false;  // 与SDK一致的安全检查
    }
    return true;
}
```

**LocalSystem (local_system.cpp) - 无验证**:
```cpp
BResult LocalSystem::Put(const char *key, const char *value, const size_t len)
{
    std::string keyPath = mEmulationCephPath;  // "./ceph/"
    keyPath += key;  // 直接拼接，无验证！
    // keyPath 可能变成 "./ceph/../../../etc/passwd"
    // ...
    fstream file;
    file.open(keyPath.c_str(), ios::out | ios::binary);  // 路径遍历漏洞
}
```

## 漏洞触发条件

### 条件1: 直接访问 FileSystem 实例

如果攻击者能够绕过 SDK 层直接访问 FileSystem 实例:

```cpp
// 潜在攻击路径 - 通过 FileSystemFactory 直接创建实例
std::shared_ptr<FileSystem> fs = FileSystemFactory::CreateFileSystem(LOCAL_SYSTEM);
fs->Put("../../../etc/passwd", malicious_value, len);  // 路径遍历攻击
```

### 条件2: 内部代码路径绕过

当前架构中存在多个直接调用 `UnderFs::Instance()` 的代码路径:

| 调用位置 | 文件 | 行号 | 风险评估 |
|----------|------|------|----------|
| `BioClient::Put` fallback | bio_client.h | 84 | **低风险** - key来自SDK验证后的输入 |
| `Cache::GetFromUnderFS` | cache.cpp | 191 | **低风险** - key为内部生成 |
| `Cache::GetValueLengthFromUnderFS` | cache.cpp | 218 | **低风险** - key为内部生成 |
| `RCache::Stat` | rcache.cpp | 504 | **低风险** - key为内部生成 |
| 测试代码 | test_underfs.cpp | 46-47 | **需审查** - 测试用例使用的key |

### 条件3: DEBUG_UT 模式

在测试模式下 (DEBUG_UT)，LocalSystem 作为默认 UnderFs:

```cpp
static std::string GetUnderFsType()
{
#ifdef DEBUG_UT
    return LOCAL_SYSTEM;  // 测试模式默认使用无验证的LocalSystem
#else
    return instance->GetUnderFsConfig().underFsType;
#endif
}
```

## PoC 构造思路

### PoC 1: 路径遍历攻击 (LocalSystem)

```cpp
#include "file_system_factory.h"
#include "local_system.h"

using namespace ock::bio;

int main() {
    // 直接创建 LocalSystem 实例，绕过 SDK 验证
    auto fs = FileSystemFactory::CreateFileSystem(LOCAL_SYSTEM);
    fs->Init();
    
    // 路径遍历攻击: 写入任意文件
    const char* malicious_key = "../../../tmp/malicious_file";
    const char* payload = "exploit_payload";
    fs->Put(malicious_key, payload, strlen(payload));
    
    // 路径遍历攻击: 读取敏感文件
    const char* read_key = "../../../etc/passwd";
    char buffer[1024];
    fs->Get(read_key, buffer, sizeof(buffer), 0);
    
    // 路径遍历攻击: 删除任意文件
    fs->Delete("../../../tmp/target_file");
    
    return 0;
}
```

**预期效果**:
- `Put`: 文件写入到 `/tmp/malicious_file` 而非 `./ceph/`
- `Get`: 读取 `/etc/passwd` 内容
- `Delete`: 删除 `/tmp/target_file`

### PoC 2: 行为不一致测试

```cpp
// 同一个key在不同FileSystem实现中的行为差异
const char* test_key = "valid_key/../../escape";

// SDK 会拒绝此key
Bio::Put(test_key, value, len);  // 返回 RET_CACHE_EPERM

// HdfsSystem 会拒绝此key
hdfs_fs->Put(test_key, value, len);  // 返回 BIO_UFS_IOERR

// LocalSystem/CephSystem 会接受此key
local_fs->Put(test_key, value, len);  // 返回 BIO_OK - 安全漏洞！
ceph_fs->Put(test_key, value, len);   // 返回 BIO_OK - 行为不一致
```

## 实际可利用性评估

### 高风险场景

| 场景 | 可能性 | 影响 | 描述 |
|------|--------|------|------|
| 测试代码注入恶意key | 中等 | 高 | test_underfs.cpp 直接创建 FileSystem 实例 |
| DEBUG_UT 模式部署 | 低 | 高 | 生产环境不应使用测试模式 |
| 未来代码修改绕过验证 | 低 | 高 | 新代码可能直接调用 UnderFs |

### 中风险场景

| 场景 | 可能性 | 影响 | 描述 |
|------|--------|------|------|
| CephSystem 行为不一致 | 高 | 低 | RADOS对象无路径遍历风险，但行为不一致 |
| 运维工具直接调用UnderFs | 低 | 中 | 内部运维工具可能绕过SDK |

### 低风险场景 (有保护)

| 场景 | 可能性 | 影响 | 描述 |
|------|--------|------|------|
| SDK API 直接调用 | - | 无 | SDK层KeyValid()提供保护 |
| Cache内部key生成 | - | 无 | 内部生成的key不含恶意字符 |

## 影响范围

### LocalSystem (高危)
- **路径遍历**: 可读写任意本地文件
- **信息泄露**: 读取敏感文件如 `/etc/passwd`
- **数据破坏**: 删除任意文件
- **权限提升**: 在特定配置下可能写入特权文件

### CephSystem (中等)
- **行为不一致**: 同一key在SDK/HdfsSystem被拒绝，在CephSystem被接受
- **安全边界模糊**: 破坏统一的验证模型
- **无直接路径遍历**: RADOS使用对象名而非文件路径

### HdfsSystem (安全)
- 有完整的 KeyValid() 验证
- 与SDK验证逻辑一致

## 修复建议

### 方案1: 统一验证函数 (推荐)

在 `file_system.h` 基类中添加验证虚函数:

```cpp
class FileSystem {
public:
    // 新增: 统一的key验证方法
    static bool KeyValid(const char *key) {
        if (key == nullptr || strlen(key) == 0) return false;
        if (strlen(key) >= UFS_KEY_MAX_SIZE) return false;
        if (key[0] == '/') return false;  // 阻止绝对路径
        if (strstr(key, "..") != nullptr) return false;  // 阻止路径遍历
        return true;
    }
    
protected:
    // 内部使用基类验证
    bool ValidateKey(const char *key) {
        return FileSystem::KeyValid(key);
    }
};
```

### 方案2: LocalSystem 具体实现

在 `local_system.cpp` 所有方法中添加验证:

```cpp
BResult LocalSystem::Put(const char *key, const char *value, const size_t len)
{
    // 新增验证
    if (!FileSystem::KeyValid(key)) {
        LOG_ERROR("Invalid key, contains path traversal: " << key);
        return BIO_UFS_IOERR;
    }
    
    // 原有逻辑...
}

// 同样修改 Get, Delete, Stat, List 方法
```

### 方案3: CephSystem 具体实现

```cpp
BResult CephSystem::Put(const char *key, const char *value, const size_t len)
{
    // 新增验证
    if (!FileSystem::KeyValid(key)) {
        LOG_ERROR("Invalid key: " << key);
        return BIO_UFS_IOERR;
    }
    
    // 原有逻辑...
}
```

### 方案4: 验证配置化

在 UnderFsConfig 中添加验证策略:

```cpp
struct UnderFsConfig {
    std::string underFsType;
    bool enableKeyValidation = true;  // 新增: 强制启用验证
    // ...
};
```

## 安全最佳实践

1. **防御性编程**: 所有 FileSystem 实现必须验证输入
2. **验证一致性**: 基类定义验证逻辑，子类继承使用
3. **路径规范化**: LocalSystem 应使用 `realpath()` 并检查结果是否在允许目录内
4. **审计日志**: 记录验证失败的key用于安全审计

## 结论

**漏洞状态**: ✅ **真实漏洞**

**严重性重评**: MEDIUM → **HIGH**
- LocalSystem 存在明确的路径遍历漏洞
- CephSystem 存在验证不一致问题
- 测试代码直接创建 FileSystem 实例可能被利用

**修复优先级**: 高
- LocalSystem 需立即修复
- 建议统一所有 FileSystem 实现的验证逻辑

---

*分析日期: 2026-04-20*
*分析工具: 静态代码分析 + 手动审计*
