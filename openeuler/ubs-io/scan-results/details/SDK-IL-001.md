# SDK-IL-001: SDK日志中直接输出用户Key等敏感信息致信息泄露

## 基本信息

| 属性 | 值 |
|------|-----|
| 漏洞ID | SDK-IL-001 |
| 类型 | Information Leakage (信息泄露) |
| CWE | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor |
| 严重性 | MEDIUM |
| 置信度 | 90% |
| 发现文件 | ubsio-boostio/src/sdk/bio.cpp |
| 影响行号 | 173-178 (及其他多处) |
| 影响函数 | Bio::Put, Bio::Get, Bio::Delete, Bio::Load, Bio::ListAll |

## 漏洞详情

### 1. 漏洞代码分析

在SDK模块中，多个核心函数在日志输出中直接暴露用户提供的`key`参数：

**bio.cpp 第173-178行 (Bio::Put函数):**
```cpp
if (UNLIKELY(ret != BIO_OK)) {
    CLIENT_LOG_ERROR("Put value failed, ret:" << ret << ", key:" << key << ", length:" << length <<
        ", location0:" << location.location[0] << ", location1:" << location.location[1] << ".");
} else {
    CLIENT_LOG_DEBUG("Put value success, key:" << key << ", length:" << length << ", location0:" <<
        location.location[0] << ", location1:" << location.location[1] << ".");
}
```

**其他受影响位置:**
- 第210-214行: `Bio::Put` (copy free variant) 成功/失败日志
- 第252-257行: `Bio::Get` 成功/失败日志  
- 第277-280行: `Bio::Delete` 成功/失败日志
- 第299-303行: `Bio::Load` 成功/失败日志
- 第335-337行: `Bio::ListAll` 成功/失败日志

### 2. Key参数分析

根据代码定义 (`message.h`):
```cpp
const uint32_t KEY_MAX_SIZE = 256;
```

Key是用户提供的对象标识符，最大256字节，用于：
- 对象存储系统的唯一标识
- 缓存系统中的数据索引
- 文件系统中的文件名映射

**Key的潜在敏感性:**
- 可能包含用户名、用户ID等身份信息
- 可能包含文件路径或文件名（可能暴露业务敏感文件）
- 可能包含业务数据标识符（如订单号、交易ID等）
- 用户误用时可能包含密码、密钥等凭证信息

### 3. 日志系统配置分析

根据 `bio_client_log.h` 和 `bio_client.cpp`:

**日志级别定义:**
```cpp
enum class Level {
    LOG_LEVEL_TRACE = 0,
    LOG_LEVEL_DEBUG = 1,
    LOG_LEVEL_INFO = 2,
    LOG_LEVEL_WARN = 3,
    LOG_LEVEL_ERROR = 4
};
```

**默认配置:**
```cpp
// bio_client.cpp 第49行
auto defaultLogLevel = static_cast<int32_t>(BioClientLog::Level::LOG_LEVEL_INFO);
```

**日志输出方式:**
- STDOUT_TYPE: 输出到标准输出
- FILE_TYPE: 输出到文件 `/logDir/bio_sdk_<pid>.log`
- STDERR_TYPE: 输出到标准错误

**关键发现:**
- ERROR级别日志(级别4)总是会被输出（大于默认INFO级别2）
- DEBUG级别日志(级别1)在调试模式下会输出
- 日志文件默认持久化保存

### 4. 影响范围扩展分析

通过代码搜索，发现类似问题存在于其他SDK模块：

**bio_qos.cpp:** 多处暴露key
```cpp
CLIENT_LOG_DEBUG("IO wake, put retry, nodeSet:" << nodeSet << ", key:" << entry->key << ".");
CLIENT_LOG_DEBUG("Put go on, nodeSet:" << nodeSet << ", key:" << entry->key << ", size:" << ...);
```

**mirror_client.cpp:** 多处暴露key
```cpp
CLIENT_LOG_ERROR("Send sync get request failed, ret:" << ret << ", key:" << req.key << ...);
CLIENT_LOG_ERROR("Get pt entry failed, ret: " << ret << ", ptId:" << ptId << ", key:" << param.key << ".");
```

**bio_client_agent.cpp:** 多处暴露key
```cpp
CLIENT_LOG_ERROR("Client get failed to verify the CRC, << key:" << req.key << ...);
```

**总计: 在SDK模块中发现230处CLIENT_LOG_*调用，其中多处直接暴露用户提供的key。**

## 漏洞触发条件

### 基本触发条件
1. 应用程序调用SDK API（Put/Get/Delete等）
2. 提供包含敏感信息的key参数
3. 操作失败触发ERROR日志，或成功操作在DEBUG模式下触发DEBUG日志

### 触发路径
```
用户调用 BioPut(tenantId, key, value, length, location)
    → Bio::Put(key, value, length, location)
        → gClient->Put(param)
            → 操作失败或成功
                → CLIENT_LOG_ERROR/CLIENT_LOG_DEBUG 输出包含key的日志
                    → 日志写入文件或输出到标准输出/错误
```

## 攻击场景分析

### 场景1: 日志文件持久化泄露
**攻击步骤:**
1. 攻击者获取系统日志访问权限（如：系统管理员权限、日志服务器访问、容器日志聚合系统）
2. 搜索包含`key=`关键字的日志条目
3. 提取敏感key信息，如：
   - 用户标识符 → 用户行为分析
   - 文件名 → 敏感文件定位
   - 业务数据标识 → 业务流程推断
4. 利用泄露信息进行进一步攻击

**示例日志内容:**
```
[SDK Put:bio.cpp:173] Put value failed, ret:BIO_ERR, key:/users/admin/credentials.conf, length:1024, location0:123, location1:0.
```

### 场景2: 多租户环境信息泄露
**攻击步骤:**
1. 多租户环境中，不同租户的日志可能混合存储
2. 低权限租户通过日志聚合系统或共享日志存储
3. 查看其他租户的操作日志，获取其key信息
4. 推断其他租户的数据结构和业务模式

### 场景3: 调试模式意外启用
**攻击步骤:**
1. 生产环境意外启用DEBUG日志级别
2. 所有成功的Put/Get操作都输出包含key的日志
3. 日志量剧增，包含大量敏感key信息
4. 攻击者通过大规模日志分析获取完整数据图谱

### 场景4: 日志传输链路泄露
**攻击步骤:**
1. 日志通过网络传输到远程日志服务器
2. 网络传输未加密或加密强度不足
3. 中间人攻击者截获日志数据包
4. 提取包含敏感key的日志内容

## PoC思路 (概念验证)

### 基本验证步骤

**步骤1: 确认日志输出机制**
```cpp
// 创建测试程序调用SDK
BioInitialize(CONVERGENCE, nullptr);
BioCreateCache({ tenantId, LOCAL_AFFINITY, WRITE_BACK });

// 使用敏感key调用Put
char sensitiveKey[] = "/secret/user_credentials.txt";
char value[] = "sensitive data";
BioPut(tenantId, sensitiveKey, value, strlen(value), location);
```

**步骤2: 检查日志输出**
```bash
# 查找日志文件
find /var/log -name "bio_sdk_*.log" 2>/dev/null

# 搜索包含key的日志
grep -r "key:" /var/log/bio_sdk_*.log
grep -r "key:/secret" /var/log/bio_sdk_*.log
```

**步骤3: 验证敏感信息泄露**
```bash
# 提取包含特定敏感key的日志
grep "key:/secret/user_credentials.txt" /var/log/bio_sdk_*.log

# 大规模提取所有key
grep -oP 'key:\K[^,]+' /var/log/bio_sdk_*.log | sort | uniq
```

### 高级验证场景

**多租户场景验证:**
```bash
# 模拟不同租户操作
Tenant A: BioPut(tenantId_A, "A_secret_data", ...)
Tenant B: BioPut(tenantId_B, "B_secret_data", ...)

# 检查Tenant B是否能看到Tenant A的key
grep "A_secret_data" /shared_logs/bio_sdk_*.log
```

**网络传输验证:**
```bash
# 在日志传输链路抓包
tcpdump -i eth0 -w log_traffic.pcap port 514

# 分析抓包数据，查找key信息
wireshark log_traffic.pcap | grep "key:"
```

## 实际可利用性评估

### 高可利用性条件
1. **日志持久化存储**: FILE_TYPE模式启用，日志保存到磁盘
2. **宽松的日志访问权限**: 日志文件权限设置不当，非管理员可读
3. **日志聚合系统**: 使用ELK/Splunk等系统，日志集中存储
4. **DEBUG模式启用**: 调试日志级别降低，大量操作被记录
5. **敏感key使用习惯**: 用户习惯使用包含敏感信息的key

### 低可利用性条件  
1. **仅STDOUT输出**: 日志输出到标准输出，不持久化
2. **严格日志权限**: 日志文件仅限管理员访问
3. **短key使用**: key不含敏感信息（如UUID）
4. **INFO日志级别**: 仅ERROR日志输出，正常操作不记录

### 风险等级评估矩阵

| 条件组合 | 风险等级 | 说明 |
|---------|---------|------|
| FILE持久化 + 敏感key + ERROR日志 | **HIGH** | 失败操作必定记录，敏感key泄露 |
| FILE持久化 + 敏感key + DEBUG日志 | **HIGH** | 所有操作记录，大规模泄露 |
| FILE持久化 + 非敏感key + ERROR日志 | **MEDIUM** | 仅失败操作记录，泄露风险较低 |
| STDOUT输出 + 敏感key + ERROR日志 | **LOW** | 不持久化，泄露窗口短 |

## 影响范围

### 技术影响
1. **信息泄露**: 用户数据标识、业务逻辑暴露
2. **隐私侵犯**: 用户身份、文件名等隐私信息泄露
3. **安全态势暴露**: 数据结构、访问模式暴露
4. **合规风险**: 可能违反数据保护法规（如GDPR、个人信息保护法）

### 业务影响
1. **用户信任损害**: 用户隐私数据泄露
2. **竞争劣势**: 业务数据结构暴露给竞争对手
3. **监管处罚**: 数据保护合规违规
4. **攻击助攻**: 为后续攻击提供情报

### 受影响的系统组件
- **ubsio-boostio SDK**: 所有使用SDK的应用程序
- **依赖应用**: 使用boostio作为缓存层的上层应用
- **日志系统**: 所有处理boostio日志的系统

## 修复建议

### 建议1: Key脱敏处理 (推荐)

**实施方式:**
```cpp
// 创建脱敏函数
static std::string SanitizeKey(const char* key) {
    if (key == nullptr) return "<null>";
    
    // 方案A: 仅显示前8字符 + 哈希
    std::string keyStr(key);
    if (keyStr.length() > 8) {
        size_t hash = std::hash<std::string>{}(keyStr);
        return keyStr.substr(0, 8) + "_" + std::to_string(hash);
    }
    return keyStr;
}

// 应用到日志
CLIENT_LOG_ERROR("Put value failed, ret:" << ret << ", key:" << SanitizeKey(key) << ", length:" << length);
```

**优点:**
- 保留足够调试信息（前缀+唯一标识）
- 完全隐藏敏感部分
- 兼容性好，不影响现有日志解析工具

### 建议2: 分离敏感日志 (可选)

**实施方式:**
```cpp
// 定义敏感日志宏，可配置开关
#ifdef ENABLE_SENSITIVE_LOG
#define SENSITIVE_KEY(key) key
#else
#define SENSITIVE_KEY(key) "<redacted>"
#endif

CLIENT_LOG_ERROR("Put value failed, ret:" << ret << ", key:" << SENSITIVE_KEY(key) << ", length:" << length);
```

**优点:**
- 开发环境可启用完整日志
- 生产环境自动脱敏
- 配置灵活

### 建议3: 错误码替代详细日志 (激进方案)

**实施方式:**
```cpp
// 仅记录错误码和基本统计信息
CLIENT_LOG_ERROR("Put operation failed, error_code:" << static_cast<int>(ret) << 
                 ", tenantId:" << tenantId << ", key_length:" << strlen(key));

// 成功操作不记录key
CLIENT_LOG_INFO("Put operation completed successfully, tenantId:" << tenantId);
```

**优点:**
- 最小化敏感信息泄露
- 保留必要调试信息（错误码）

**缺点:**
- 调试信息不够详细
- 需要调整日志分析流程

### 建议4: 日志级别配置增强

**实施方式:**
```cpp
// 在ClientOptionsConfig中添加敏感日志控制
typedef struct {
    LogType logType;
    char logFilePath[PATH_MAX];
    uint8_t enable;
    uint8_t enableSensitiveLog;  // 新增：敏感日志开关
    // ...其他字段
} ClientOptionsConfig;

// 在日志输出时检查
if (enableSensitiveLog) {
    CLIENT_LOG_ERROR("Put failed, key:" << key << ...);
} else {
    CLIENT_LOG_ERROR("Put failed, key_hash:" << HashKey(key) << ...);
}
```

**优点:**
- 用户可控制敏感信息输出
- 兼顾调试需求和生产安全

### 建议5: 全面扫描修复 (必要步骤)

**修复范围:**
1. 修复 `bio.cpp` 中所有暴露key的位置
2. 修复 `bio_qos.cpp` 中的key暴露
3. 修复 `mirror_client.cpp` 中的key暴露  
4. 修复 `bio_client_agent.cpp` 中的key暴露
5. 检查其他可能暴露用户数据的位置（prefix, diskPath等）

**修复优先级:**
- **P0**: ERROR级别日志（必定输出）
- **P1**: DEBUG级别日志（调试模式输出）
- **P2**: INFO/WARN级别日志（较低概率输出）

## 缓解措施 (短期)

### 系统层面
1. **日志权限加固:**
   ```bash
   chmod 640 /var/log/bio_sdk_*.log
   chown root:adm /var/log/bio_sdk_*.log
   ```

2. **日志级别调整:**
   ```cpp
   // 将默认日志级别调整为WARN
   auto defaultLogLevel = static_cast<int32_t>(BioClientLog::Level::LOG_LEVEL_WARN);
   ```

3. **日志轮转配置:**
   ```bash
   # 减少日志保留时间
   /var/log/bio_sdk_*.log {
       daily
       rotate 3
       compress
       missingok
       notifempty
   }
   ```

### 应用层面
1. **用户教育:**
   - 文档明确说明key不应包含敏感信息
   - 提供key命名最佳实践指南
   - 示例代码使用非敏感key

2. **运行时检查:**
   ```cpp
   // 添加key敏感性检查
   bool IsKeySensitive(const char* key) {
       // 检查是否包含敏感关键词
       std::string keyStr(key);
       std::vector<std::string> sensitivePatterns = {
           "password", "secret", "credential", "key", "token"
       };
       for (const auto& pattern : sensitivePatterns) {
           if (keyStr.find(pattern) != std::string::npos) {
               return true;
           }
       }
       return false;
   }
   
   // 在KeyValid中添加警告
   if (IsKeySensitive(key)) {
       CLIENT_LOG_WARN("Warning: key appears to contain sensitive information. Consider using non-sensitive identifiers.");
   }
   ```

## 验证修复效果

### 测试步骤
1. 应用修复补丁
2. 运行测试程序，使用敏感key
3. 检查日志输出：
   ```bash
   grep "key:" /var/log/bio_sdk_*.log
   # 应输出脱敏后的key，如: "key:secret_12345678_hash"
   # 不应输出完整key，如: "key:/secret/user_credentials.txt"
   ```
4. 确认功能不受影响：
   - API调用成功
   - 错误处理正常
   - 调试信息足够

### 回归测试
- 运行单元测试套件
- 运行集成测试
- 验证性能无显著下降

## 总结

### 漏洞确认
**这是一个真实的信息泄露漏洞**，符合CWE-200定义。在ubsio-boostio SDK中，多处日志语句直接输出用户提供的key参数，可能导致敏感信息泄露。

### 严重性评估
- **技术严重性**: MEDIUM（存在多种触发条件，但取决于实际使用场景）
- **业务严重性**: 可能升级为HIGH（如果用户习惯使用敏感key）
- **合规严重性**: HIGH（涉及隐私数据保护法规）

### 修复紧迫性
- **建议修复**: 是，应尽快实施修复
- **优先级**: P1（建议在下一版本发布前修复）
- **工作量**: 中等（涉及多处代码修改，但修改模式一致）

### 遗留问题
1. 其他SDK模块的类似问题需要一并修复
2. 日志系统的整体安全策略需要评估
3. 用户教育文档需要更新

## 参考信息

- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- GDPR Article 32: Security of processing

---
**报告生成时间**: 2026-04-20  
**分析者**: Security Scanner AI  
**审核状态**: 待人工审核
