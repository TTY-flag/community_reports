# 漏洞扫描报告 — 已确认漏洞

**项目**: IndexSDK
**扫描时间**: 2026-04-20T00:20:00Z
**报告范围**: 仅包含 CONFIRMED 状态的漏洞

---

## 执行摘要

本次漏洞扫描针对 IndexSDK 项目进行了深度安全分析。IndexSDK 是一个向量检索 SDK 库，部署在昇腾 NPU 服务器环境中，供应用程序调用。扫描覆盖了 5 个核心模块，共计 434 个源文件，发现 **1 个已确认的高危漏洞**。

**核心风险发现**：跨模块文件 I/O 安全措施不对称漏洞（CWE-73）被确认为高危级别。该漏洞涉及 `ivfsp_utils`、`vstar_great_impl` 和 `feature_retrieval` 三个模块的文件读取操作。写入操作（FSPIOWriter/VstarIOWriter）具有完整的安全防护栈（路径长度限制 255 字符、字符白名单验证、父目录符号链接递归检查、文件属主校验、文件大小限制 56GB），但读取操作（FSPIOReader/VstarIOReader）仅使用 `O_NOFOLLOW` 标志，缺乏上述关键安全检查。此外，`feature_retrieval` 模块的 `addCodeBook`、`loadAllData`、`saveAllData` API 直接接收用户路径参数，未应用任何验证。

**业务影响**：攻击者可利用该漏洞通过路径遍历或符号链接攻击读取系统中的敏感文件。在共享服务器环境中，恶意用户可能读取其他用户的索引数据或配置文件，导致数据泄露或隐私侵犯。写入路径的缺失验证可能导致数据被写入敏感系统位置。

**建议优先修复方向**：
1. **立即修复**：为 FSPIOReader 和 VstarIOReader 补充完整的安全验证逻辑，复用 initializeFileDescription 函数的安全栈
2. **短期修复**：为 feature_retrieval 模块的文件 I/O API 添加路径规范化、白名单验证和符号链接检查
3. **架构改进**：统一所有模块的文件 I/O 安全策略，建立中央安全验证模块

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| POSSIBLE | 24 | 54.5% |
| LIKELY | 11 | 25.0% |
| FALSE_POSITIVE | 8 | 18.2% |
| CONFIRMED | 1 | 2.3% |
| **总计** | **44** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 1 | 100.0% |
| **有效漏洞总计** | **1** | - |
| 误报 (FALSE_POSITIVE) | 8 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-CROSS-002]** File I/O Security Measure Asymmetry (High) - `multiple files:1` @ `FSPIOReader, VstarIOReader, addCodeBook, loadAllData, saveAllData` | 置信度: 85

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `add@feature_retrieval/src/ascendfaiss/ascend/AscendIndex.h` | api | untrusted_local | 用户应用程序调用此API传入向量数据，数据内容完全由调用方控制 | 向索引中添加向量数据 |
| `search@feature_retrieval/src/ascendfaiss/ascend/AscendIndex.h` | api | untrusted_local | 用户应用程序调用此API传入查询向量，数据内容完全由调用方控制 | 执行向量检索搜索 |
| `addCodeBook@feature_retrieval/src/ascendfaiss/ascend/ivfsp/AscendIndexIVFSP.h` | file | untrusted_local | 用户指定码本文件路径，文件路径完全由调用方控制，可能被用于路径遍历攻击 | 从指定路径加载码本文件 |
| `initializeFileDescription@ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp` | file | untrusted_local | 用户指定文件路径进行读写操作，虽有安全检查但路径仍由用户控制 | 初始化文件描述符并校验路径安全性 |
| `initializeFileDescription@vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp` | file | untrusted_local | 用户指定文件路径进行读写操作，路径由用户控制 | 初始化文件描述符并校验路径安全性 |
| `AscendIndex@feature_retrieval/src/ascendfaiss/ascend/AscendIndex.h` | api | semi_trusted | 构造函数接收设备列表和资源配置，需要一定权限才能正确配置 | SDK索引对象构造函数 |

**其他攻击面**:
- API接口: add(), search(), add_with_ids() 等向量数据输入
- 文件I/O: 码本加载、索引保存/加载等用户可控文件路径
- 配置参数: 设备列表、资源大小等初始化配置

---

## 3. High 漏洞 (1)

### [VULN-CROSS-002] File I/O Security Measure Asymmetry - FSPIOReader, VstarIOReader, addCodeBook, loadAllData, saveAllData

**严重性**: High | **CWE**: CWE-73 | **置信度**: 85/100 | **状态**: CONFIRMED | **来源**: security-auditor

**位置**: `multiple files:1` @ `FSPIOReader, VstarIOReader, addCodeBook, loadAllData, saveAllData`
**模块**: cross_module
**跨模块**: ivfsp_utils → vstar_great_impl → feature_retrieval

**描述**: [CREDENTIAL_FLOW] 多模块文件I/O安全措施不对称：FSPIOWriter/initializeFileDescription 有完整安全栈（路径长度255、字符白名单、软链接递归检查、属主校验、大小限制56GB、O_NOFOLLOW），但 FSPIOReader/VstarIOReader 仅使用 O_NOFOLLOW。feature_retrieval 模块的 addCodeBook/loadAllData/saveAllData 未应用任何验证。攻击者可通过读取路径绕过安全检查，实现路径遍历或符号链接攻击。

**漏洞代码** (`multiple files:1`)

```c
FSPIOReader(fd, name) only uses O_NOFOLLOW; VstarIOReader lacks validation; addCodeBook passes path directly
```

**达成路径**

用户路径 → ivfsp_utils/IoUtil.cpp(FSPIOReader:131) → open(仅O_NOFOLLOW); vstar_great_impl/VstarIoUtil.cpp(VstarIOReader:228) → open; feature_retrieval/AscendIndexIVFSPImpl.cpp(addCodeBook:102) → pIVFSPSQ

**验证说明**: 跨模块文件I/O安全措施不对称验证确认。FSPIOWriter/VstarIOWriter调用initializeFileDescription有完整安全栈（路径长度255、字符白名单、O_NOFOLLOW、父目录软链接检查checkLinkRec、文件属主检查、大小限制56GB、普通文件类型检查）。FSPIOReader/VstarIOReader仅使用O_NOFOLLOW。addCodeBook/loadAllData/saveAllData路径直接传递给pIVFSPSQ无验证。调用链完整：addCodeBook→FSPIOReader→open。评分：base30+reachability30+controllability25+mitigations0+context0+cross_file0=85

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

**深度分析**

### 根因分析

该漏洞的根因在于 **安全设计的不一致性** —— 同一模块中写入操作和读取操作采用了不同的安全策略。

**代码对比分析**：

**FSPIOWriter（写入）- 完整安全栈** (`ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:121-124`)
```cpp
FSPIOWriter::FSPIOWriter(const std::string &fname) : name(fname)
{
    initializeFileDescription(fd, name);  // 调用完整安全验证
}
```

`initializeFileDescription` 函数（第 28-81 行）实现了完整的安全检查栈：
- 路径长度校验（第 34 行）：限制 255 字符
- 字符白名单验证（第 36-40 行）：`isValidCode()` + `isInWhiteList()`
- 父目录符号链接递归检查（第 83-97 行 `checkLinkRec`）：逐级检查各级父目录是否为符号链接
- 文件属主校验（第 69-72 行）：`st.st_uid != geteuid()`
- 文件大小限制（第 65-68 行）：MAX_DATAFILE_SIZE = 56GB
- 普通文件类型检查（第 61-64 行）：`S_ISREG(st.st_mode)`

**FSPIOReader（读取）- 仅有 O_NOFOLLOW** (`ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:131-136`)
```cpp
FSPIOReader::FSPIOReader(const std::string &fname) : name(fname)
{
    fd = open(name.c_str(), O_NOFOLLOW | O_RDONLY);  // 仅使用 O_NOFOLLOW
    ASCEND_THROW_IF_NOT_MSG(fd >= 0, ...);
}
```

**关键缺失**：
1. **无路径长度检查** - 可能导致缓冲区溢出或路径截断
2. **无字符白名单验证** - 允许 `../` 等路径遍历字符
3. **无父目录符号链接检查** - `O_NOFOLLOW` 仅防护最终目标，不防护路径中间的符号链接
4. **无文件属主检查** - 可读取任意用户的文件
5. **无文件大小限制** - 可能触发资源耗尽

**VstarIOReader（vstar_great_impl 模块）** (`vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp:138-143`)
```cpp
VstarIOReader::VstarIOReader(const std::string &fname) : name(fname)
{
    fd = open(name.c_str(), O_NOFOLLOW | O_RDONLY);  // 同样仅有 O_NOFOLLOW
    ASCEND_THROW_IF_NOT_MSG(fd >= 0, ...);
}
```

**feature_retrieval 模块的 API 路径传递** (`feature_retrieval/src/ascendfaiss/ascend/ivfsp/AscendIndexIVFSPImpl.cpp:102-111`)
```cpp
void AscendIndexIVFSPImpl::addCodeBook(const char *codeBookPath)
{
    FAISS_THROW_IF_NOT_MSG((codeBookPath != nullptr), "codeBookPath can not be nullptr");
    std::string cdbkFilePath(codeBookPath);
    pIVFSPSQ->addCodeBook(cdbkFilePath);  // 路径直接传递，无验证
}
```

以及 `loadAllData` 和 `saveAllData`（第 177-192 行）：
```cpp
void AscendIndexIVFSPImpl::loadAllData(const char *dataPath)
{
    pIVFSPSQ->loadAllData(dataPath);  // 路径直接传递
}

void AscendIndexIVFSPImpl::saveAllData(const char *dataPath)
{
    pIVFSPSQ->saveAllData(dataPath);  // 路径直接传递
}
```

### 潜在利用场景

**场景 1：父目录符号链接绕过**
```
攻击者构造：/home/user/legitimate_dir -> /etc/passwd
调用路径：/home/user/legitimate_dir/shadow_data

FSPIOReader 使用 O_NOFOLLOW 打开：
- open("/home/user/legitimate_dir/shadow_data", O_NOFOLLOW)
- 由于 legitimate_dir 是符号链接，O_NOFOLLOW 无法防护
- 最终读取到 /etc/shadow_data（如果存在）
```

**场景 2：路径遍历攻击**
```
攻击者传入路径：/home/user/data/../../../../etc/passwd

FSPIOReader 缺少路径规范化检查：
- 直接 open() 调用，路径遍历字符未过滤
- 可读取系统敏感文件
```

**场景 3：跨用户数据访问**
```
在多用户共享服务器环境中：
- 用户 A 的进程调用 addCodeBook("/home/userB/sensitive_index")
- 缺少属主检查，可读取用户 B 的索引数据
- 导致隐私数据泄露
```

### 建议修复方式

**方案 1：复用 initializeFileDescription 的安全栈**

为 Reader 添加完整验证，与 Writer 保持一致：
```cpp
FSPIOReader::FSPIOReader(const std::string &fname) : name(fname)
{
    initializeFileDescription(fd, name);  // 复用完整安全栈
    // 或创建 initializeFileDescriptionForRead 变体
}
```

**方案 2：创建统一的安全文件打开函数**

```cpp
enum FileIOMode { READ, WRITE };

void secureFileOpen(int &fd, const std::string &fname, FileIOMode mode) {
    // 通用安全检查
    validatePathLength(fname);          // 255 字符限制
    validatePathCharacters(fname);      // 白名单验证
    validateNoSymlinkInPath(fname);     // 父目录符号链接检查
    validateFileOwner(fname);           // 属主检查
    validateFileSize(fname, mode);      // 大小限制
    
    int flags = (mode == READ) ? O_RDONLY : O_WRONLY;
    if (mode == WRITE) flags |= O_CREAT;
    fd = open(fname.c_str(), O_NOFOLLOW | flags);
}
```

**方案 3：为 feature_retrieval API 添加路径验证**

```cpp
void AscendIndexIVFSPImpl::addCodeBook(const char *codeBookPath)
{
    FAISS_THROW_IF_NOT_MSG((codeBookPath != nullptr), "codeBookPath can not be nullptr");
    
    // 新增安全验证
    std::string validatedPath = validateAndCanonicalizePath(codeBookPath);
    FAISS_THROW_IF_NOT_MSG(isPathWithinAllowedDirectory(validatedPath), 
                           "Path must be within allowed directories");
    
    pIVFSPSQ->addCodeBook(validatedPath);
}
```

---

## 4. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cross_module | 0 | 1 | 0 | 0 | 1 |
| **合计** | **0** | **1** | **0** | **0** | **1** |

## 5. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-73 | 1 | 100.0% |

---

## 6. 修复建议

### 优先级 1: 立即修复 (Critical/High 漏洞)

**[VULN-CROSS-002] File I/O Security Measure Asymmetry - 跨模块文件 I/O 安全措施不对称**

**修复策略**：

1. **统一 FSPIOReader 和 VstarIOReader 的安全验证**
   - 为 Reader 类添加与 Writer 相同的 `initializeFileDescription` 安全栈调用
   - 或创建专用的 `initializeFileDescriptionForRead` 函数，包含路径长度、字符白名单、父目录符号链接检查、文件属主校验

2. **修复位置及代码改动**：
   
   `ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:131-136`:
   ```cpp
   FSPIOReader::FSPIOReader(const std::string &fname) : name(fname)
   {
       // 当前: fd = open(name.c_str(), O_NOFOLLOW | O_RDONLY);
       // 建议: 调用 initializeFileDescription 或专用的读取安全函数
       int flags = O_NOFOLLOW | O_RDONLY;
       initializeFileDescriptionForRead(fd, name, flags);
   }
   ```
   
   `vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp:138-143`:
   ```cpp
   VstarIOReader::VstarIOReader(const std::string &fname) : name(fname)
   {
       // 当前: fd = open(name.c_str(), O_NOFOLLOW | O_RDONLY);
       // 建议: 调用 initializeFileDescription 或专用的读取安全函数
       initializeFileDescriptionForRead(fd, name);
   }
   ```

3. **为 feature_retrieval API 添加路径安全验证**
   
   `feature_retrieval/src/ascendfaiss/ascend/ivfsp/AscendIndexIVFSPImpl.cpp`:
   - 在 `addCodeBook` (第 102-111 行) 添加路径规范化、白名单验证
   - 在 `loadAllData` (第 177-186 行) 添加路径验证
   - 在 `saveAllData` (第 188-192 行) 添加路径验证
   
   ```cpp
   void AscendIndexIVFSPImpl::addCodeBook(const char *codeBookPath)
   {
       FAISS_THROW_IF_NOT_MSG((codeBookPath != nullptr), "codeBookPath can not be nullptr");
       
       // 新增安全验证
       std::string canonicalPath = RealPath(codeBookPath);
       FAISS_THROW_IF_NOT_MSG(CheckPathValid(canonicalPath), 
                              "Path validation failed");
       FAISS_THROW_IF_NOT_MSG(!CheckSymLink(canonicalPath), 
                              "Symlink not allowed in path");
       
       std::string cdbkFilePath(canonicalPath);
       pIVFSPSQ->addCodeBook(cdbkFilePath);
   }
   ```

4. **测试验证**：
   - 创建符号链接测试用例，验证父目录符号链接检查是否生效
   - 创建路径遍历测试用例（`../`），验证白名单是否过滤
   - 创建跨用户访问测试用例，验证属主检查是否生效

### 优先级 2: 短期修复 (High 级别的待确认漏洞)

根据待确认报告中的高危漏洞，建议同步处理：

1. **[VULN-001-VSTAR-READER] Path Traversal** - 与已确认漏洞同一根因，修复 FSPIOReader 后同步修复
2. **[VULN-IVFSP-CBT-001/002] Integer Overflow** - 添加整数溢出检查，使用 size_t 类型替代 int
3. **[SEC-IVFSP-001] Security Measure Bypass** - 与已确认漏洞同一问题，统一修复方案

### 优先级 3: 计划修复 (Medium/Low 级别漏洞)

1. **TOCTOU 竞态条件** - 使用 `openat2()` 或文件描述符操作避免竞态
2. **环境变量信任链** - 为 MX_INDEX_MODELPATH 等环境变量添加更严格的验证
3. **整数溢出** - 在内存分配前添加溢出检查宏或使用安全算术库
4. **信息泄露** - 评估生产环境日志级别配置，过滤敏感路径信息

### 架构改进建议

1. **建立中央文件 I/O 安全模块**
   - 创建统一的 `SecureFileIO` 类，封装所有安全检查
   - 所有模块通过该类进行文件操作，避免不一致

2. **建立安全配置策略文件**
   - 定义允许的文件路径范围（如 `/home/`, `/data/` 等）
   - 定义文件大小限制、字符白名单等可配置参数

3. **安全代码审计流程**
   - 在 CI/CD 中集成安全扫描工具
   - 定期进行跨模块安全一致性审计
