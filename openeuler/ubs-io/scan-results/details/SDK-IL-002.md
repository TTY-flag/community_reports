# SDK-IL-002: AddDisk函数日志输出磁盘路径信息致敏感路径泄露

## 1. 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | SDK-IL-002 |
| **类型** | Information Leakage (信息泄露) |
| **CWE** | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor |
| **严重性** | LOW (实际评估，原始报告为 MEDIUM) |
| **置信度** | 90% |
| **文件** | `ubsio-boostio/src/sdk/mirror_client.cpp`, `ubsio-boostio/src/sdk/bio.cpp` |
| **行号** | 886-893 (mirror_client.cpp), 1104, 1114, 1118 (bio.cpp) |
| **函数** | `AddDiskImpl`, `BioAddDisk` |

## 2. 漏洞详情

### 2.1 受影响代码

**mirror_client.cpp:886-893**
```cpp
BResult MirrorClient::AddDiskImpl(const char *diskPath)
{
    AddDiskRequest req{};
    req.comm = { MESSAGE_MAGIC, 0, 0, mLocalNid.VNodeId(), getpid() };
    auto pathLen = strlen(diskPath);
    BResult ret = memcpy_s(req.diskPath, FILE_PATH_MAX_LEN, diskPath, pathLen);
    if (ret != BIO_OK) {
        LOG_ERROR("Req copy disk path failed, ret:" << ret << ", path:" << diskPath << ".");
        //                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ 泄露点1
        return ret;
    }
    req.diskPath[pathLen] = '\0';

    ret = SendAddDiskRequest(req);
    if (UNLIKELY(ret != BIO_OK)) {
        CLIENT_LOG_ERROR("Send add disk request failed, ret:" << ret << ", diskPath:" << req.diskPath << ".");
        //                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ 泄露点2
    }
    return ret;
}
```

**bio.cpp:1101-1119**
```cpp
CResult BioAddDisk(const char *diskPath)
{
    if (UNLIKELY(diskPath == nullptr || strlen(diskPath) >= FILE_PATH_MAX_LEN)) {
        CLIENT_LOG_ERROR("Invalid input parameter, diskPath: " << diskPath << ".");
        //              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ 泄露点3
        return RET_CACHE_EPERM;
    }

    if (UNLIKELY(!gClient->Ready())) {
        return RET_CACHE_NOT_READY;
    }

    auto ret = gClient->GetMirror()->AddDisk(diskPath);
    if (ret != BIO_OK) {
        CLIENT_LOG_ERROR("Failed to add disk, ret:" << ret << ", diskPath:"<< diskPath << ".");
        //              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ 泄露点4
        return ToCResult(ret);
    }

    CLIENT_LOG_INFO("Add disk sucess! disk path: " << diskPath << ".");
    //            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ 泄露点5 (成功时也记录)
    return RET_CACHE_OK;
}
```

### 2.2 数据流分析

```
用户输入(diskPath) 
    ↓
BioAddDisk() [bio.cpp:1101]
    ↓
MirrorClient::AddDisk() [mirror_client.cpp:850]
    ↓
MirrorClient::AddDiskImpl() [mirror_client.cpp:879]
    ↓
日志输出 (LOG_ERROR / CLIENT_LOG_ERROR)
```

### 2.3 日志机制分析

**日志输出位置：**
1. **文件日志** (`logType = FILE_TYPE`):
   - 路径: `{logFilePath}/bio_sdk_{pid}.log`
   - 权限: `S_IRUSR | S_IWUSR | S_IRGRP` (仅所有者和组可读)
   
2. **标准输出** (`logType = STDOUT_TYPE`):
   - 输出到 stdout，可能被重定向到文件或日志收集系统

3. **标准错误** (`logType = STDERR_TYPE`):
   - 输出到 stderr

**日志配置代码 (bio_log.cpp:136-139):**
```cpp
handlers.after_open = [](const spdlog::filename_t &filename, std::FILE *fstream) {
    chmod(filename.c_str(), S_IRUSR | S_IWUSR | S_IRGRP);  // 仅 owner 和 group 可读写
};
```

## 3. 漏洞触发条件

### 3.1 前提条件

| 条件 | 说明 |
|------|------|
| C1 | 攻击者需要能够触发 `BioAddDisk()` API 调用 |
| C2 | 攻击者需要访问日志文件（组权限或日志收集系统） |
| C3 | `diskPath` 参数需包含敏感路径信息 |
| C4 | API 调用需产生错误条件以触发错误日志 |

### 3.2 触发场景

**场景1: 本地权限提升**
```
1. 低权限用户与应用程序同属一个组
2. 应用程序以高权限运行并调用 BioAddDisk()
3. 低权限用户读取日志文件获取敏感路径信息
```

**场景2: 日志注入攻击**
```
1. 攻击者控制 diskPath 参数内容
2. 注入包含换行符的路径名
3. 伪造日志条目或隐藏恶意活动
```

**场景3: 信息侦察**
```
1. 攻击者已获得初始访问权限
2. 通过日志收集内部存储架构信息
3. 用于后续攻击规划
```

## 4. PoC 构造思路

### 4.1 信息泄露 PoC

```cpp
// 攻击者控制的应用程序代码
#include "bio_c.h"

int main() {
    // 1. 初始化 SDK (需要有效配置)
    ClientOptionsConfig config = {};
    config.logType = FILE_TYPE;
    strcpy(config.logFilePath, "/tmp/logs");
    config.enable = true;
    
    BioInitialize(WORKER_MODE, &config);
    
    // 2. 构造包含敏感信息的路径触发错误
    const char* sensitive_path = "/dev/mapper/top_secret_encrypted_volume";
    BioAddDisk(sensitive_path);  // 触发错误日志
    
    // 3. 低权限用户读取日志
    // cat /tmp/logs/bio_sdk_*.log
    // 输出: Send add disk request failed, ret:xxx, diskPath:/dev/mapper/top_secret_encrypted_volume.
    
    return 0;
}
```

### 4.2 日志注入 PoC

```cpp
// 注入换行符伪造日志条目
const char* malicious_path = "/dev/sda\n[FAKE] 2024-01-01 00:00:00.000000 1234 ERROR Fake log entry";
BioAddDisk(malicious_path);
// 日志中将出现伪造条目，可用于掩盖真实攻击或混淆日志分析
```

## 5. 可利用性评估

### 5.1 利用难度分析

| 因素 | 评估 | 说明 |
|------|------|------|
| API 访问控制 | **高门槛** | 需要调用 SDK 初始化，通常由可信应用调用 |
| 日志访问权限 | **中等** | 文件权限限制为 owner+group，非世界可读 |
| 敏感路径暴露 | **低概率** | 大多数磁盘路径为标准设备路径 `/dev/sdX` |
| 错误触发条件 | **可控** | 攻击者可通过无效路径触发错误 |

### 5.2 实际影响评估

**低影响场景 (常见):**
- 标准磁盘路径: `/dev/sda`, `/dev/nvme0n1`
- 无敏感信息泄露

**中等影响场景:**
- LVM 卷路径: `/dev/mapper/encrypted_data`
- 特殊挂载点: `/mnt/backup/confidential`
- 用户标识路径: `/data/user_john_private`

**高影响场景 (罕见):**
- 泄露加密卷名称揭示受保护数据位置
- 路径模式暴露系统架构
- 配合其他漏洞实现提权

### 5.3 CVSS v3.1 评分

```
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N
```

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector | Local | 需要本地访问 |
| Attack Complexity | Low | 无特殊条件 |
| Privileges Required | Low | 需要用户权限 |
| User Interaction | None | 无需交互 |
| Scope | Unchanged | 影响范围不变 |
| Confidentiality | Low | 泄露有限信息 |
| Integrity | None | 无完整性影响 |
| Availability | None | 无可用性影响 |

**基础分数: 3.3 (LOW)**

## 6. 修复建议

### 6.1 推荐修复方案

**方案1: 路径脱敏 (推荐)**

```cpp
// 创建脱敏函数
static std::string SanitizePath(const char* path) {
    if (path == nullptr) return "<null>";
    
    std::string sanitized = path;
    // 仅保留文件名，隐藏目录路径
    size_t lastSlash = sanitized.find_last_of("/\\");
    if (lastSlash != std::string::npos) {
        return "/***" + sanitized.substr(lastSlash);
    }
    return "***";
}

// 应用修复
LOG_ERROR("Req copy disk path failed, ret:" << ret << ", path:" << SanitizePath(diskPath) << ".");
CLIENT_LOG_ERROR("Send add disk request failed, ret:" << ret << ", diskPath:" << SanitizePath(req.diskPath) << ".");
```

**方案2: 移除敏感参数日志**

```cpp
// 仅记录操作结果，不暴露参数值
LOG_ERROR("Req copy disk path failed, ret:" << ret << ".");
CLIENT_LOG_ERROR("Send add disk request failed, ret:" << ret << ".");
```

**方案3: 使用错误码代替详细错误信息**

```cpp
// 定义专门的错误码
enum AddDiskError {
    ADD_DISK_PATH_COPY_FAILED = 1,
    ADD_DISK_REQUEST_FAILED = 2,
};

LOG_ERROR("AddDisk failed, error_code:" << ADD_DISK_PATH_COPY_FAILED << ", ret:" << ret << ".");
```

### 6.2 缓解措施

| 措施 | 实施方法 | 效果 |
|------|---------|------|
| 限制日志访问 | 设置日志文件权限为 0600 | 阻止组内用户读取 |
| 日志脱敏 | 在日志收集系统中过滤敏感字段 | 防止集中存储泄露 |
| 审计监控 | 监控异常的 AddDisk 调用 | 检测潜在攻击尝试 |
| 输入验证 | 验证路径格式和字符 | 防止日志注入 |

## 7. 相关代码位置

| 文件 | 行号 | 说明 |
|------|------|------|
| `/ubsio-boostio/src/sdk/mirror_client.cpp` | 886 | 错误日志泄露点1 |
| `/ubsio-boostio/src/sdk/mirror_client.cpp` | 893 | 错误日志泄露点2 |
| `/ubsio-boostio/src/sdk/bio.cpp` | 1104 | 错误日志泄露点3 |
| `/ubsio-boostio/src/sdk/bio.cpp` | 1114 | 错误日志泄露点4 |
| `/ubsio-boostio/src/sdk/bio.cpp` | 1118 | 成功日志泄露点 |
| `/ubsio-boostio/src/common/bio_log.cpp` | 136-139 | 日志文件权限设置 |
| `/ubsio-boostio/src/sdk/bio_client_log.h` | 142-149 | 日志宏定义 |

## 8. 结论

### 8.1 漏洞判定

**判定结果: 真实漏洞 (LOW 严重性)**

虽然存在信息泄露，但实际利用场景有限：
1. API 访问需要可信应用上下文
2. 日志文件权限已做基本限制
3. 大多数磁盘路径不包含敏感信息
4. 攻击者收益相对有限

### 8.2 修复优先级

| 优先级 | 说明 |
|--------|------|
| P3 - 低优先级 | 建议在下一个版本中修复 |

### 8.3 相关漏洞

建议同时检查以下类似位置：
- 其他 SDK API 中的路径/参数日志
- 认证凭据日志 (certificationPath, privateKeyPath)
- 用户数据日志 (Put/Get 操作中的 key/value)

---

**报告生成时间**: 2026-04-20  
**分析工具版本**: opencode-vul-scanner v1.0  
**分析人员**: AI Security Analyzer
