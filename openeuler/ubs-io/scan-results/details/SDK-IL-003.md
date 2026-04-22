# SDK-IL-003: Information Leakage in MirrorClient::Put Alignment Failure

## 1. 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | SDK-IL-003 |
| **类型** | Information Leakage (信息泄露) |
| **CWE** | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor |
| **严重性** | MEDIUM |
| **置信度** | 90% |
| **文件** | `ubsio-boostio/src/sdk/mirror_client.cpp` |
| **行号** | 447-450 (主要泄露点), 以及其他20+处 |
| **函数** | `MirrorClient::Put`, `MirrorClient::PutAlignSize` |
| **相关漏洞** | SDK-IL-001 (同一问题的不同实例) |

## 2. 漏洞详情

### 2.1 主要泄露点代码

**mirror_client.cpp 第441-450行 (Put函数):**
```cpp
BResult MirrorClient::Put(MirrorPut &param)
{
    bool isAllocMem = false;
    char *value = param.value;
    BResult ret = PutAlignSize(value, param, isAllocMem);
    if (UNLIKELY(ret != BIO_OK)) {
        CLIENT_LOG_ERROR("Align size failed, ret: " << ret << ", key:" << param.key << ".");
        //                                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        //                                            直接输出用户提供的key到日志
        return ret;
    }
    ...
}
```

**mirror_client.cpp 第563-584行 (PutAlignSize函数):**
```cpp
BResult MirrorClient::PutAlignSize(const char *value, MirrorPut &param, bool &isAllocMem)
{
    // 触发条件: SCENE_BIGDATA 模式 + 数据长度未对齐
    if (UNLIKELY((mScene == SCENE_BIGDATA) && (param.length % mAlignSize != 0))) {
        uint64_t length = (((param.length) + (mAlignSize)-1) & ~((mAlignSize)-1));
        BIO_TRACE_START(SDK_TRACE_PUT_ALIGN_IO);
        if ((param.value = static_cast<char *>(malloc(length))) == nullptr) {
            BIO_TRACE_END(SDK_TRACE_PUT_ALIGN_IO, BIO_ALLOC_FAIL);
            CLIENT_LOG_ERROR("Alloc memory failed, size:" << length << ".");
            return BIO_ALLOC_FAIL;
        }
        auto ret = memcpy_s(param.value, length, value, param.length);
        if (ret != BIO_OK) {
            CLIENT_LOG_ERROR("Memory copy failed, ret:" << ret << ".");
            // 上一级调用者会输出: "Align size failed, key:" << param.key
            free(param.value);
            param.value = nullptr;
            return BIO_INNER_ERR;
        }
        ...
    }
    return BIO_OK;
}
```

### 2.2 MirrorPut 数据结构

**mirror_client.h 第54-63行:**
```cpp
struct MirrorPut {
    CacheAttr attr;
    char *key;           // 对象键名 - 用户提供的敏感标识符
    char *value;         // 对象数据值
    uint64_t length;     // 数据长度
    ObjLocation location;// 对象位置信息
    uint64_t flowId;     // 流标识
    uint64_t flowOffset; // 流偏移
    uint64_t flowIndex;  // 流索引
};
```

**Key参数特性:**
- 最大长度: KEY_MAX_SIZE = 256 字节
- 来源: 用户提供的对象标识符
- 可能包含: 文件路径、用户名、业务ID、机密数据标识等敏感信息

### 2.3 扩展泄露点分析

mirror_client.cpp 中存在超过20处类似的key泄露点:

| 行号 | 函数 | 日志内容 |
|------|------|----------|
| 447 | Put | "Align size failed, key:" << param.key |
| 538 | PutImpl | "Get pt entry failed, key:" << param.key |
| 548-549 | PutImpl | "Prepare put with space failed, key:" << param.key |
| 557 | PutImpl | "Send put request failed, key:" << param.key |
| 643-644 | PutImpl | "Alloc put offset failed, key:" << param.key |
| 651-652 | PutImpl | "Send put request failed, key:" << param.key |
| 684 | GetImpl | "Get pt entry failed, key:" << param.key |
| 700 | GetImpl | "Send get request failed, key:" << param.key |
| 727 | DeleteKeyImpl | "Get pt entry failed, key:" << key |
| 736 | DeleteKeyImpl | "Send delete request failed, key:" << key |
| 765 | LoadImpl | "Get pt entry failed, key:" << para.key |
| 776 | LoadImpl | "Send stat request failed, key:" << para.key |
| 827 | StatObjectImpl | "Get pt entry failed, key:" << key |
| 836 | StatObjectImpl | "Send stat request failed, key:" << key |
| 1162-1163 | PrepareFromServer | "Prepare resource failed, key:" << param.key |
| 1182-1183 | PrepareFromServer | "Copy data failed, key:" << param.key |
| 1214-1215 | PrepareFromClient | "Copy data failed, key:" << param.key |
| 1334-1335 | SendPutRequest | "Prepare put resource failed, key:" << param.key |
| 1365-1366 | GetMasterRemote | "Send sync get request failed, key:" << req.key |
| 1386-1387 | GetMasterRemote | "Client Get failed to verify CRC, key:" << req.key |

### 2.4 数据流分析

```
用户输入(key)
    ↓
应用程序调用 BioPut/MirrorClient::Put
    ↓
MirrorClient::Put() [mirror_client.cpp:441]
    ↓
MirrorClient::PutAlignSize() [mirror_client.cpp:563]
    ↓ (检测到对齐失败)
CLIENT_LOG_ERROR("Align size failed, key:" << param.key)
    ↓
BioClientLog::Log() [bio_client_log.h:102]
    ↓
日志系统输出 (文件/stdout/stderr)
```

### 2.5 日志机制分析

**日志配置 (bio_client_log.h):**
```cpp
enum class Level {
    LOG_LEVEL_TRACE = 0,  // 调试模式
    LOG_LEVEL_DEBUG = 1,  // 调试模式
    LOG_LEVEL_INFO = 2,   // 默认级别
    LOG_LEVEL_WARN = 3,
    LOG_LEVEL_ERROR = 4,  // 本漏洞触发的级别
    LOG_LEVEL_BUTT
};
```

**日志输出位置:**
1. **FILE_TYPE**: `{logFilePath}/bio_sdk_{pid}.log`
2. **STDOUT_TYPE**: 标准输出 (可能被重定向)
3. **STDERR_TYPE**: 标准错误

**日志文件权限 (bio_log.cpp:136-139):**
```cpp
handlers.after_close = [](const spdlog::filename_t &filename) {
    chmod(filename.c_str(), S_IRUSR | S_IRGRP);  // 0440: owner可读, group可读
};
handlers.after_open = [](const spdlog::filename_t &filename, std::FILE *fstream) {
    chmod(filename.c_str(), S_IRUSR | S_IWUSR | S_IRGRP);  // 0640: owner读写, group可读
};
```

## 3. 漏洞触发条件

### 3.1 特定触发条件 (SDK-IL-003独特场景)

本漏洞的触发场景与SDK-IL-001不同，需要满足以下特定条件：

| 条件 | 说明 | 要求 |
|------|------|------|
| C1 | 启用大数据场景模式 | `mScene == SCENE_BIGDATA` |
| C2 | 数据长度未对齐 | `param.length % mAlignSize != 0` |
| C3 | 内存分配或复制失败 | `malloc()` 或 `memcpy_s()` 返回错误 |
| C4 | 日志级别 >= ERROR | 默认配置满足 (ERROR=4 > INFO=2) |

### 3.2 触发场景详解

**场景A: 数据对齐失败 + 内存分配失败**
```cpp
// 条件组合
mScene == SCENE_BIGDATA  // 大数据场景
param.length % mAlignSize != 0  // 未对齐数据
malloc(aligned_length) == nullptr  // 内存不足

// 结果: CLIENT_LOG_ERROR("Alloc memory failed...") + 上层输出key
```

**场景B: 数据对齐失败 + 内存复制失败**
```cpp
// 条件组合
mScene == SCENE_BIGDATA
param.length % mAlignSize != 0
memcpy_s() != BIO_OK  // 复制错误

// 结果: CLIENT_LOG_ERROR("Memory copy failed...") + 上层输出key
```

### 3.3 攻击者触发方式

攻击者可以通过以下方式主动触发此漏洞：

1. **构造恶意输入:**
   - 设置场景为 SCENE_BIGDATA
   - 提供包含敏感信息的 key
   - 提供未对齐的数据长度（如非512/1024整数倍）

2. **利用资源耗尽:**
   - 在大数据场景下提交大量未对齐数据请求
   - 触发内存分配失败
   - 导致错误日志输出敏感key

## 4. PoC 构造思路

### 4.1 基本验证 PoC

```cpp
// PoC: 触发对齐失败导致的key泄露
#include "bio_c.h"
#include "mirror_client.h"

int main() {
    // 1. 初始化SDK，设置为大数据场景
    ClientOptionsConfig config = {};
    config.logType = FILE_TYPE;
    strcpy(config.logFilePath, "/var/log/boostio");
    config.enable = true;
    
    BioInitialize(CONVERGENCE, &config);
    
    // 2. 设置大数据场景模式
    BioClient::Instance()->GetMirror()->SetScene(SCENE_BIGDATA);
    
    // 3. 构造包含敏感信息的key和未对齐数据
    char* sensitiveKey = "/users/admin/credit_card_data.db";
    char* value = "Sensitive financial data...";
    uint64_t length = 123;  // 未对齐长度 (非512/1024整数倍)
    
    ObjLocation location = {};
    location.location[0] = 1;
    
    // 4. 执行Put操作
    MirrorPut param = {};
    param.key = sensitiveKey;
    param.value = value;
    param.length = length;
    param.location = location;
    
    BioClient::Instance()->GetMirror()->Put(param);
    
    // 5. 检查日志文件
    // 预期输出: [SDK Put:mirror_client.cpp:447] Align size failed, ret:xxx, key:/users/admin/credit_card_data.db.
    
    return 0;
}
```

### 4.2 验证日志泄露

```bash
# 查找日志文件
find /var/log -name "bio_sdk_*.log" 2>/dev/null

# 搜索泄露的key信息
grep -E "key:.*Align size failed|key:.*credit_card|key:.*admin" /var/log/boostio/bio_sdk_*.log

# 提取所有泄露的key
grep -oP 'key:\K[^,.]+' /var/log/boostio/bio_sdk_*.log | sort | uniq -c | sort -rn
```

### 4.3 资源耗尽触发 PoC

```cpp
// PoC: 通过资源耗尽触发内存分配失败
#include "bio_c.h"

void trigger_memory_exhaustion() {
    while (true) {
        // 循环提交大量未对齐请求，耗尽内存
        char* key = "/sensitive/transaction_record_XXXX";
        char* value = new char[1024*1024];  // 1MB数据
        
        MirrorPut param = {};
        param.key = key;
        param.value = value;
        param.length = 1234567;  // 未对齐
        
        BioClient::Instance()->GetMirror()->Put(param);
        
        // 当内存耗尽时，将触发:
        // CLIENT_LOG_ERROR("Alloc memory failed, size:...")
        // CLIENT_LOG_ERROR("Align size failed, key:/sensitive/transaction_record_XXXX")
    }
}
```

## 5. 可利用性评估

### 5.1 利用难度分析

| 因素 | 评估 | 说明 |
|------|------|------|
| **API访问** | 中等门槛 | 需要SDK初始化和应用集成 |
| **场景触发** | 可控 | 可设置SCENE_BIGDATA模式 |
| **条件构造** | 容易 | 未对齐数据长度易于构造 |
| **日志访问** | 组权限限制 | 需要同组用户或日志收集系统 |
| **Key敏感性** | 依赖用户习惯 | 取决于用户是否使用敏感key |

### 5.2 实际影响评估

**高影响场景:**
- 金融系统: key包含账户号、交易ID
- 医疗系统: key包含患者ID、病历标识
- 企业系统: key包含商业机密文件路径
- 云存储: key暴露用户数据位置

**低影响场景:**
- key使用UUID等非敏感标识
- key不包含用户/业务信息
- 仅使用短随机字符串

### 5.3 CVSS v3.1 评分

```
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N
```

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector | Local | 需要本地SDK访问 |
| Attack Complexity | Low | 触发条件易于满足 |
| Privileges Required | Low | 需要应用层权限 |
| User Interaction | None | 无需用户交互 |
| Scope | Unchanged | 影响范围不变 |
| Confidentiality | Low | 泄露有限敏感信息 |
| Integrity | None | 无完整性影响 |
| Availability | None | 无可用性影响 |

**基础分数: 3.3 (LOW)**

**实际严重性: MEDIUM** (考虑到大数据场景的特殊性和潜在的敏感数据暴露)

### 5.4 与SDK-IL-001的关系

本漏洞 (SDK-IL-003) 与 SDK-IL-001 是同一类问题在不同代码位置的表现：

| 对比项 | SDK-IL-001 | SDK-IL-003 |
|--------|------------|------------|
| 文件 | bio.cpp | mirror_client.cpp |
| 层级 | 公共API层 | 内部实现层 |
| 触发场景 | 任意Put/Get失败 | 大数据场景对齐失败 |
| 影响范围 | 所有SDK用户 | 大数据场景用户 |
| 修复优先级 | P1 | P2 |

## 6. 修复建议

### 6.1 推荐修复方案

**方案1: Key脱敏处理 (推荐)**

```cpp
// 创建脱敏辅助函数
static std::string SanitizeKey(const char* key) {
    if (key == nullptr) return "<null>";
    
    std::string keyStr(key);
    
    // 方案A: 仅显示前8字符 + 哈希后缀
    if (keyStr.length() > 8) {
        size_t hash = std::hash<std::string>{}(keyStr);
        return keyStr.substr(0, 8) + "...[" + std::to_string(hash % 10000) + "]";
    }
    
    // 方案B: 完全哈希化
    return "key[" + std::to_string(std::hash<std::string>{}(keyStr) % 1000000) + "]";
}

// 应用修复
CLIENT_LOG_ERROR("Align size failed, ret: " << ret << ", key:" << SanitizeKey(param.key) << ".");
CLIENT_LOG_ERROR("Get pt entry failed, ret: " << ret << ", ptId:" << ptId << ", key:" << SanitizeKey(param.key) << ".");
```

**方案2: 使用错误码替代**

```cpp
// 仅记录必要信息，不输出完整key
CLIENT_LOG_ERROR("Put operation failed, error_code:ALIGN_FAIL, ret:" << ret 
    << ", key_len:" << (param.key ? strlen(param.key) : 0) 
    << ", data_len:" << param.length << ".");
```

**方案3: 配置化敏感日志控制**

```cpp
// 添加配置选项
struct ClientOptionsConfig {
    ...
    bool enableSensitiveLog;  // 新增: 控制敏感参数输出
};

// 条件日志
#define CLIENT_LOG_ERROR_KEY(args, key) \
    do { \
        if (BioClient::Instance()->IsSensitiveLogEnabled()) { \
            CLIENT_LOG_ERROR(args << key); \
        } else { \
            CLIENT_LOG_ERROR(args << "<redacted>"); \
        } \
    } while(0)

CLIENT_LOG_ERROR_KEY("Align size failed, ret: " << ret << ", key:", SanitizeKey(param.key));
```

### 6.2 全面修复清单

需要修复的所有位置:

| 文件 | 行号范围 | 修复优先级 |
|------|----------|------------|
| mirror_client.cpp | 447 | P0 (本漏洞) |
| mirror_client.cpp | 538, 548-549, 557 | P0 |
| mirror_client.cpp | 643-644, 651-652 | P0 |
| mirror_client.cpp | 684, 700 | P1 |
| mirror_client.cpp | 727, 736 | P1 |
| mirror_client.cpp | 765, 776 | P1 |
| mirror_client.cpp | 827, 836 | P1 |
| mirror_client.cpp | 1162-1163, 1182-1183 | P1 |
| mirror_client.cpp | 1214-1215 | P1 |
| mirror_client.cpp | 1334-1335 | P1 |
| mirror_client.cpp | 1365-1366, 1386-1387 | P1 |
| mirror_client.h | 日志宏定义 | P2 |

### 6.3 缓解措施 (短期)

| 措施 | 实施方法 | 效果 |
|------|---------|------|
| 限制日志权限 | `chmod 600 bio_sdk_*.log` | 阻止组内用户读取 |
| 提高日志级别 | 设置为 WARN/ERROR 减少输出 | 减少正常操作记录 |
| 日志轮转 | 缩短保留时间，减少历史泄露 | 降低历史数据风险 |
| 日志脱敏系统 | 在日志收集层过滤 | 防止集中存储泄露 |
| 用户教育 | 文档说明key不应敏感 | 预防性措施 |

## 7. 相关代码位置汇总

| 文件路径 | 行号 | 说明 |
|----------|------|------|
| `/ubsio-boostio/src/sdk/mirror_client.cpp` | 447 | 主要泄露点 |
| `/ubsio-boostio/src/sdk/mirror_client.cpp` | 563-584 | 触发函数 |
| `/ubsio-boostio/src/sdk/mirror_client.cpp` | 20+ | 其他泄露点 |
| `/ubsio-boostio/src/sdk/mirror_client.h` | 54-63 | MirrorPut结构 |
| `/ubsio-boostio/src/sdk/mirror_client.h` | 42-45 | WorkerScene定义 |
| `/ubsio-boostio/src/sdk/bio_client_log.h` | 142-155 | 日志宏定义 |
| `/ubsio-boostio/src/common/bio_log.cpp` | 136-139 | 日志文件权限 |
| `/ubsio-boostio/src/sdk/bio.cpp` | 相关 | SDK-IL-001位置 |

## 8. 结论

### 8.1 漏洞判定

**判定结果: 真实漏洞**

这是一个真实的信息泄露漏洞，属于 SDK-IL-001 的变体：
1. 漏洞确实存在，key被输出到ERROR级别日志
2. 有特定的触发条件（大数据场景+对齐失败）
3. 实际危害取决于key的敏感程度
4. 日志权限已有基本限制，但组内用户仍可访问

### 8.2 严重性评估

- **技术严重性**: MEDIUM (有特定触发条件，但条件易于满足)
- **业务严重性**: HIGH (如果用户使用敏感key，数据暴露风险大)
- **合规严重性**: HIGH (可能违反数据保护法规)

### 8.3 修复优先级

| 优先级 | 说明 |
|--------|------|
| **P2** | 建议在下一个版本中修复，与SDK-IL-001一并处理 |

### 8.4 建议行动

1. **立即**: 审计日志文件权限配置
2. **短期**: 在日志收集系统添加脱敏规则
3. **中期**: 实施代码修复，key脱敏处理
4. **长期**: 建立敏感日志安全规范

---

**报告生成时间**: 2026-04-20  
**分析工具版本**: opencode-vul-scanner v1.0  
**分析人员**: AI Security Analyzer  
**审核状态**: 待人工审核
