# 漏洞扫描报告 — 待确认漏洞

**项目**: OmniAdaptor  
**扫描时间**: 2026-04-22T15:30:00+08:00  
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞  
**代码规模**: 28 文件, 8631 行  
**语言组成**: C/C++ + Python 混合

---

## 执行摘要

本次漏洞扫描的待确认漏洞（LIKELY/POSSIBLE）共 16 个，涉及指针安全、SSRF、环境变量注入、整数溢出和内存耗尽等多个安全类别。这些漏洞需要进一步人工审查以确定其真实性和实际风险。

### 待确认漏洞分布

| 类别 | 数量 | 主要分布模块 |
|------|------|-------------|
| NULL Pointer Dereference | 5 | JNI Interface |
| SSRF | 2 | Python Main |
| Environment Variable Injection | 2 | JNI Interface |
| Path Traversal (下游) | 2 | IO Module |
| Integer Overflow | 2 | Shuffle Module |
| Memory Exhaustion | 1 | Shuffle Module |
| Unsafe Pointer Use | 1 | JNI Interface |
| Buffer Overflow | 1 | Shuffle Module |

### 风险特征

**LIKELY 漏洞 (12 个)**：
- 置信度 65-75%，数据流完整但利用条件受限
- 多数与 JNI 边界的输入验证不足相关
- Python SSRF 漏洞具有实际利用可能性

**POSSIBLE 漏洞 (4 个)**：
- 置信度 45-50%，需要进一步验证利用路径
- 主要涉及内存操作的安全边界问题
- 在正常运行条件下难以触发

### 重点关注

1. **SSRF 漏洞 (VULN-DF-SSRF-001)** - Python Flink 日志解析工具的 URL 验证不足，可能被用于探测内网服务
2. **Unsafe Pointer Use (VULN-DF-MEM-001)** - JNI 指针转换缺乏有效性验证，可能导致内存损坏
3. **Integer Overflow (VULN-DF-INT-001)** - 内存分配计算存在溢出风险，可能导致缓冲区溢出

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 12 | 38.7% |
| FALSE_POSITIVE | 12 | 38.7% |
| POSSIBLE | 4 | 12.9% |
| CONFIRMED | 3 | 9.7% |
| **总计** | **31** | 100% |

### 1.2 严重性分布（待确认漏洞）

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 6 | 37.5% |
| Medium | 10 | 62.5% |
| **有效漏洞总计** | **16** | - |

### 1.3 Top 10 关键待确认漏洞

| 序号 | ID | 类型 | 严重性 | 位置 | 置信度 | 状态 |
|------|-----|------|--------|------|--------|------|
| 1 | VULN-DF-SSRF-001 | ssrf | High | `flink_log_parser.py:56` | 75 | LIKELY |
| 2 | SEC-021 | SSRF | High | `flink_log_parser.py:56` | 75 | LIKELY |
| 3 | VULN-DF-MEM-001 | unsafe_pointer_use | High | `SparkJniWrapper.cpp:137` | 65 | LIKELY |
| 4 | VULN-DF-ENV-001 | env_injection | High | `SparkJniWrapper.cpp:103` | 65 | LIKELY |
| 5 | SEC-008 | ENV_INJECTION | High | `SparkJniWrapper.cpp:103` | 65 | LIKELY |
| 6 | SEC-022 | NULL_POINTER | High | `SparkJniWrapper.cpp:144` | 65 | LIKELY |
| 7 | SEC-001 | NULL_POINTER | Medium | `SparkJniWrapper.cpp:51` | 60 | LIKELY |
| 8 | SEC-002 | NULL_POINTER | Medium | `SparkJniWrapper.cpp:83` | 60 | LIKELY |
| 9 | SEC-003 | NULL_POINTER | Medium | `SparkJniWrapper.cpp:99` | 60 | LIKELY |
| 10 | SEC-004 | NULL_POINTER | Medium | `SparkJniWrapper.cpp:103` | 60 | LIKELY |

---

## 2. 攻击面分析

### 2.1 入口点与待确认漏洞关联

| 入口点 | 关联漏洞 | 说明 |
|--------|----------|------|
| `Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_nativeMake` | VULN-DF-ENV-001, SEC-001~008 | JNI 字符串转换无 NULL 检查，环境变量注入 |
| `Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_split` | VULN-DF-MEM-001, SEC-022 | 指针地址直接转换无有效性验证 |
| `analyze_flink_logs@flink_log_parser.py` | VULN-DF-SSRF-001, SEC-021 | URL 验证不足，可能 SSRF |
| `FileInputStream::FileInputStream` | SEC-009 | 下游路径遍历风险 |
| `FileOutputStream::FileOutputStream` | SEC-010 | 下游路径遍历风险 |
| `Splitter::AllocatePartitionBuffers` | VULN-DF-INT-001, SEC-013, SEC-014 | 整数溢出和内存耗尽风险 |

### 2.2 数据流风险模式

| 模式 | 源 | 目标 | 风险等级 | 关联漏洞 |
|------|-----|------|----------|----------|
| **URL to HTTP Request** | CLI args.url | Flink Dashboard API | High | VULN-DF-SSRF-001 |
| **JNI jlong to Pointer** | Java jlong addresses | reinterpret_cast | High | VULN-DF-MEM-001 |
| **JNI String to Environment** | JNI local_dirs | setenv() | High | VULN-DF-ENV-001 |
| JNI String to C++ String | Java jstring | GetStringUTFChars | Medium | SEC-001~004 |
| Partition Count to Allocation | partition_id_cnt_cur | Allocator::Alloc() | Medium | VULN-DF-INT-001 |
| VectorBatch Data to memcpy | VCLocation data | memcpy_s | Medium | VULN-DF-MEM-003 |

---

## 3. High 级别漏洞深度分析

### 3.1 [VULN-DF-SSRF-001] Flink Dashboard URL SSRF

**严重性**: High | **CWE**: CWE-918 | **置信度**: 75 | **状态**: LIKELY

#### 漏洞概述

Python Flink 日志解析工具 `FlinkLogParser` 从 CLI 参数接收 URL 并用于连接 Flink Dashboard API。URL 验证仅检查协议（http/https）和端口范围（1-65535），但未阻止对内网地址、localhost 或云元数据端点的访问。

#### 漏洞代码

```python
# flink_log_parser.py:56-90
def _validate_url(self):
    """校验 URL 参数"""
    url = self.args.url
    try:
        parsed_url = urllib.parse.urlparse(url)
        
        # 仅校验协议 - 未验证目标地址
        if parsed_url.scheme not in ['http', 'https']:
            print(f"Error: Invalid URL scheme...")
            return False
        
        # 仅校验端口范围 - 未阻止内网地址
        if self.args.port < 1 or self.args.port > 65535:
            print(f"Error: Invalid port...")
            return False
        
        # 缺失的安全检查:
        # - 127.0.0.1, localhost
        # - 10.x.x.x, 172.16-31.x.x, 192.168.x.x
        # - 云元数据端点 169.254.169.254
        return True
```

#### 攻击场景

| 场景 | 输入 URL | 可能访问的目标 |
|------|----------|---------------|
| 内网服务探测 | `http://10.0.0.1:8080/` | 内部管理界面、API |
| Localhost 访问 | `http://127.0.0.1:6379/` | Redis、数据库等本地服务 |
| 云元数据读取 | `http://169.254.169.254/latest/meta-data/` | AWS/Azure 云凭证信息 |
| DNS 重绑定绕过 | `http://internal.corp.com:80/` | 解析为内网 IP |

#### 风险评估

- **可控性**: 管理员运行 CLI 工具，输入 URL 完全可控
- **利用条件**: 需要管理员执行该工具并传入恶意 URL
- **实际影响**: 
  - 内网服务信息泄露
  - 云凭证窃取（如果在云环境运行）
  - 绕过防火墙访问受限服务

#### 修复建议

```python
# 推荐 URL 验证增强
import ipaddress

def _validate_url(self):
    url = self.args.url
    parsed_url = urllib.parse.urlparse(url)
    
    # 1. 解析目标 IP
    hostname = parsed_url.hostname
    try:
        # 处理域名解析
        import socket
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        print(f"Error: Cannot resolve hostname: {hostname}")
        return False
    
    # 2. 验证不在私有 IP 范围内
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            print(f"Error: Cannot access private/internal IP: {ip}")
            return False
        
        # 3. 阻止云元数据 IP
        if ip == "169.254.169.254":
            print(f"Error: Cannot access cloud metadata endpoint")
            return False
    except ValueError:
        pass
    
    return True
```

---

### 3.2 [VULN-DF-MEM-001] Unsafe JNI Pointer Conversion

**严重性**: High | **CWE**: CWE-119 | **置信度**: 65 | **状态**: LIKELY

#### 漏洞概述

JNI 函数 `Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_split` 接收来自 Java 的 `splitter_addr` 和 `jVecBatchAddress` jlong 参数，直接使用 `reinterpret_cast` 转换为指针并使用，仅在 `splitter_addr` 上有 NULL 检查，但 `vecBatch` 指针完全未验证。

#### 漏洞代码

```cpp
// SparkJniWrapper.cpp:137-147
JNIEXPORT jlong JNICALL Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_split(
    JNIEnv *env, jobject jObj, jlong splitter_addr, jlong jVecBatchAddress)
{
    // 仅 NULL 检查，不验证地址有效性
    auto splitter = reinterpret_cast<Splitter *>(splitter_addr);
    if (!splitter) {
        std::string error_message = "Invalid splitter id " + std::to_string(splitter_addr);
        env->ThrowNew(runtimeExceptionClass, error_message.c_str());
        return -1;
    }

    // 无任何验证！直接转换使用
    auto vecBatch = (VectorBatch *) jVecBatchAddress;
    splitter->SetInputVecBatch(vecBatch);
    splitter->Split(*vecBatch);  // 解引用可能导致崩溃
    return 0L;
}
```

#### 数据流路径

```
JNI splitter_addr (jlong) [SOURCE]
    ↓ reinterpret_cast<Splitter*> [SparkJniWrapper.cpp:137]
    ↓ NULL check (不完整) [SparkJniWrapper.cpp:138]
    ↓ splitter dereference [SINK]

JNI jVecBatchAddress (jlong) [SOURCE]
    ↓ (VectorBatch*) cast [SparkJniWrapper.cpp:144]  ← 无验证
    ↓ splitter->Split(*vecBatch) [SINK]  ← 解引用
```

#### 风险评估

- **NULL 检查存在**: `splitter_addr` 有 NULL 检查，但无法检测无效地址
- **VectorBatch 无验证**: `jVecBatchAddress` 完全未检查
- **实际风险**: 
  - 恶意/错误的 Java 代码传入无效地址可能导致 C++ 进程崩溃
  - 无法直接用于攻击（攻击者需控制 Java 侧）
  - 主要影响稳定性而非安全性

#### 修复建议

```cpp
// 建议增强指针验证
// 1. 维护 splitter 实例注册表
static std::unordered_map<jlong, std::weak_ptr<Splitter>> splitter_registry;

// 2. 验证 splitter_addr 在注册表中
JNIEXPORT jlong JNICALL Java_com_huawei_boostkit_spark_jni_SparkJniWrapper_split(...)
{
    auto it = splitter_registry.find(splitter_addr);
    if (it == splitter_registry.end() || it->second.expired()) {
        env->ThrowNew(runtimeExceptionClass, "Invalid or expired splitter handle");
        return -1;
    }
    
    auto splitter = it->second.lock();
    
    // 3. VectorBatch 地址验证（通过 Splitter 内部机制）
    if (splitter->ValidateVecBatchAddress(jVecBatchAddress)) {
        auto vecBatch = reinterpret_cast<VectorBatch*>(jVecBatchAddress);
        splitter->Split(*vecBatch);
    } else {
        env->ThrowNew(runtimeExceptionClass, "Invalid VectorBatch address");
        return -1;
    }
    return 0L;
}
```

---

### 3.3 [VULN-DF-ENV-001] Environment Variable Injection

**严重性**: High | **CWE**: CWE-78 | **置信度**: 65 | **状态**: LIKELY

#### 漏洞概述

此漏洞与已确认的 VULN-DF-PTH-001 共享同一代码位置。通过 `setenv()` 设置的环境变量 `NATIVESQL_SPARK_LOCAL_DIRS` 会影响后续所有文件操作的路径基础。虽然环境变量注入本身不直接导致漏洞，但它为路径遍历攻击提供了攻击向量。

#### 漏洞代码

```cpp
// SparkJniWrapper.cpp:103-105
auto local_dirs = env->GetStringUTFChars(local_dirs_jstr, JNI_FALSE);
setenv("NATIVESQL_SPARK_LOCAL_DIRS", local_dirs, 1);  // 直接设置环境变量
env->ReleaseStringUTFChars(local_dirs_jstr, local_dirs);
```

#### 风险评估

- **依赖关系**: 此漏洞是 VULN-DF-PTH-001 的前置条件
- **独立影响**: 环境变量污染可能影响同一进程中的其他模块
- **组合攻击**: 与路径遍历漏洞组合可实现任意文件写入

#### 修复建议

与 VULN-DF-PTH-001 的修复方案相同：在设置环境变量前进行路径验证，或改用进程内部变量存储配置。

---

### 3.4 [SEC-008] ENV_INJECTION (与 VULN-DF-ENV-001 相同)

由 Security Auditor 独立发现，位于相同代码位置，共享相同漏洞根因。

---

### 3.5 [SEC-022] NULL Pointer Dereference in VectorBatch

**严重性**: High | **CWE**: CWE-476 | **置信度**: 65 | **状态**: LIKELY

#### 漏洞概述

VectorBatch 指针从 jlong 参数转换后直接使用，无有效性验证。与 VULN-DF-MEM-001 相关。

#### 漏洞代码

```cpp
// SparkJniWrapper.cpp:144-147
auto vecBatch = (VectorBatch *) jVecBatchAddress;  // 无验证
splitter->SetInputVecBatch(vecBatch);
splitter->Split(*vecBatch);  // 解引用
```

#### 风险评估

- **触发条件**: Java 传入无效地址（0 或垃圾值）
- **实际影响**: 进程崩溃，DoS
- **缓解因素**: NULL 检查在部分场景存在

---

## 4. Medium 级别漏洞

### 4.1 [SEC-001~004] GetStringUTFChars NULL Check Missing

**位置**: SparkJniWrapper.cpp 多处  
**类型**: NULL Pointer Dereference (CWE-476)  
**置信度**: 60 | **状态**: LIKELY

#### 漏洞概述

JNI `GetStringUTFChars()` 在内存分配失败时可能返回 NULL，代码将其结果直接用于构造 `std::string` 或传递给其他函数，无 NULL 检查。

#### 漏洞代码位置

| ID | 位置 | 参数 |
|----|------|------|
| SEC-001 | Line 51-53 | `jInputType` |
| SEC-002 | Line 83-85 | `partitioning_name_jstr` |
| SEC-003 | Line 99-101 | `data_file_jstr` |
| SEC-004 | Line 103-105 | `local_dirs_jstr` |

#### 修复建议

```cpp
// 标准修复模式
const char* str = env->GetStringUTFChars(jstr, JNI_FALSE);
if (str == nullptr) {
    env->ThrowNew(runtimeExceptionClass, "GetStringUTFChars returned NULL - allocation failure");
    return 0;
}
std::string result(str);
env->ReleaseStringUTFChars(jstr, str);
```

---

### 4.2 [SEC-009/010] File I/O Path Traversal (下游)

**位置**: SparkFile.cc  
**类型**: Path Traversal (CWE-22)  
**置信度**: 60 | **状态**: LIKELY

#### 漏洞概述

FileInputStream 和 FileOutputStream 构造函数接收文件路径参数直接用于 `open()` 调用，无路径规范化。这些是已确认路径遍历漏洞的下游 Sink 点。

#### 漏洞代码

```cpp
// SparkFile.cc:49-54
FileInputStream(std::string _filename) {
    filename = _filename;
    file = open(filename.c_str(), O_BINARY | O_RDONLY);  // 无验证
}

// SparkFile.cc:117-128
FileOutputStream(std::string _filename) {
    filename = _filename;
    file = open(filename.c_str(), O_BINARY | O_CREAT | O_WRONLY | O_TRUNC, ...);  // 无验证
}
```

#### 修复建议

与上游路径遍历漏洞一同修复。在文件操作层添加路径验证作为防御层。

---

### 4.3 [VULN-DF-INT-001] Integer Overflow in Allocation

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50 | **状态**: POSSIBLE

#### 漏洞概述

内存分配大小计算使用乘法 `new_size * (1 << column_type_id_[i])`。当 `new_size` 很大（来自分区数据计数）且 `column_type_id_[i] >= 3` 时，乘法可能溢出 int32，导致分配缓冲区小于预期，后续写入造成溢出。

#### 漏洞代码

```cpp
// splitter.cpp:77-82
void *ptr_tmp = static_cast<void *>(options_.allocator->Alloc(
    new_size * (1 << column_type_id_[i])));  // 潜在溢出点
fixed_valueBuffer_size_[partition_id] += new_size * (1 << column_type_id_[i]);
```

#### 风险评估

- **触发条件**: `new_size` 大于 2^29 且 `column_type_id` >= 3
- **实际可能性**: Spark batch row count 通常受内存限制，不易达到此规模
- **影响**: 缓冲区溢出导致内存损坏

#### 修复建议

```cpp
// 使用 size_t 并添加溢出检查
size_t alloc_size = static_cast<size_t>(new_size) * (1 << column_type_id_[i]);
if (alloc_size > MAX_ALLOC_SIZE || alloc_size < new_size) {  // 检测溢出
    throw std::runtime_error("Allocation size overflow detected");
}
void* ptr_tmp = options_.allocator->Alloc(alloc_size);
```

---

### 4.4 [SEC-013] Integer Overflow (与 VULN-DF-INT-001 相同)

由 Security Auditor 独立发现。

---

### 4.5 [SEC-014] Memory Exhaustion DoS

**严重性**: Medium | **CWE**: CWE-789 | **置信度**: 50 | **状态**: POSSIBLE

#### 漏洞概述

内存分配基于数据派生的大小，无上限检查。恶意 VectorBatch 可能触发大量内存分配导致进程耗尽内存。

#### 风险评估

- **触发条件**: 极大的 VectorBatch 数据
- **缓解因素**: Spark Executor 通常有内存限制
- **影响**: DoS，进程被 OOM Killer 终止

#### 修复建议

添加分配大小上限和内存使用监控。

---

### 4.6 [VULN-DF-MEM-003] Buffer Overflow in BytesGen

**严重性**: Medium | **CWE**: CWE-119 | **置信度**: 45 | **状态**: POSSIBLE

#### 漏洞概述

`memcpy_s` 操作使用来自 VCLocation 数据的长度和偏移量。需要验证偏移量是否在分配的 values buffer 范围内。

#### 漏洞代码

```cpp
// common.h:69-72
if (len != 0) {
    memcpy_s((char *) (values + offsets[i]), len, addr, len);  // 偏移量验证？
}
```

#### 修复建议

添加 buffer bounds 检查：确保 `offsets[i] + len <= buffer_size`。

---

## 5. 模块漏洞分布

| 模块 | High | Medium | Low | 合计 | 说明 |
|------|------|--------|-----|------|------|
| **jni-interface** | 4 | 4 | 0 | 8 | 主要风险集中在 JNI 边界 |
| **python-main** | 2 | 0 | 0 | 2 | SSRF 需关注 |
| **shuffle-module** | 0 | 4 | 0 | 4 | 内存操作安全边界 |
| **io-module** | 0 | 2 | 0 | 2 | 下游路径遍历 |
| **合计** | **6** | **10** | **0** | **16** | |

---

## 6. CWE 分布

| CWE | 数量 | 占比 | 描述 |
|-----|------|------|------|
| CWE-476 | 5 | 31.3% | NULL Pointer Dereference |
| CWE-918 | 2 | 12.5% | Server-Side Request Forgery (SSRF) |
| CWE-78 | 2 | 12.5% | OS Command Injection (env variant) |
| CWE-22 | 2 | 12.5% | Path Traversal (下游) |
| CWE-190 | 2 | 12.5% | Integer Overflow or Wraparound |
| CWE-119 | 2 | 12.5% | Buffer Overflow |
| CWE-789 | 1 | 6.3% | Memory Exhaustion |

---

## 7. 综合修复建议

### 7.1 JNI 边界安全加固

| 问题 | 修复方案 | 优先级 |
|------|----------|--------|
| GetStringUTFChars 无 NULL 检查 | 添加标准 NULL 检查模式 | P1 |
| 指针地址无有效性验证 | 实现实例注册表验证机制 | P2 |
| 环境变量直接设置 | 改用内部变量存储或前置验证 | P0 |

### 7.2 Python 工具安全增强

| 问题 | 修复方案 | 优先级 |
|------|----------|--------|
| URL 验证不足 | 添加私有 IP/云元数据 IP 阻止 | P1 |

### 7.3 内存操作安全边界

| 问题 | 修复方案 | 优先级 |
|------|----------|--------|
| 整数溢出风险 | 使用 size_t 并添加溢出检测 | P2 |
| 内存无上限 | 添加最大分配限制 | P2 |
| Buffer bounds | 验证 offset + len <= buffer_size | P3 |

### 7.4 分层防御策略

```
Layer 1: Java 端预验证（Spark Executor 层）
    ↓
Layer 2: JNI 边界验证（入口点）
    ↓  
Layer 3: 内部函数验证（下游操作）
    ↓
Layer 4: 系统级限制（SELinux/AppArmor）
```

---

## 8. 人工审查建议

### 8.1 需人工验证的漏洞

| ID | 审查重点 | 预期时间 |
|----|----------|----------|
| VULN-DF-SSRF-001 | URL 验证在部署环境中的实际风险 | 30 分钟 |
| VULN-DF-MEM-001 | Java 侧指针传递机制是否可控 | 1 小时 |
| VULN-DF-INT-001 | 最大 batch size 和实际触发可能性 | 30 分钟 |

### 8.2 建议验证方法

1. **SSRF**: 在隔离环境测试 URL 验证是否可被绕过
2. **指针安全**: 分析 Java Spark Executor 对 native 函数的调用控制
3. **整数溢出**: 统计生产环境最大 VectorBatch 规模
4. **Buffer overflow**: 追踪 offsets 数组的来源和边界控制

---

## 9. 参考资源

- [CWE-918: SSRF](https://cwe.mitre.org/data/definitions/918.html)
- [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
- [CWE-190: Integer Overflow](https://cwe.mitre.org/data/definitions/190.html)
- [OWASP SSRF Prevention](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)