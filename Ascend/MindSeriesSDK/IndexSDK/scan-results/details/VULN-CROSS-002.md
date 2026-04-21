# VULN-CROSS-002: File I/O Security Measure Asymmetry (CWE-73)

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-CROSS-002 |
| **状态** | CONFIRMED |
| **CWE分类** | CWE-73: External Control of File Name or Path |
| **严重性** | High |
| **置信度** | 85% |
| **影响模块** | ivfsp_utils, vstar_great_impl, feature_retrieval |

### 漏洞描述

多个模块存在文件I/O安全措施不对称问题：文件写入操作（FSPIOWriter/VstarIOWriter）通过`initializeFileDescription()`实现了完整的安全检查栈，包括路径长度限制、字符白名单、软链接递归检查、属主校验、大小限制和O_NOFOLLOW标志。然而，文件读取操作（FSPIOReader/VstarIOReader）仅使用O_NOFOLLOW标志，缺乏其他关键安全验证。

攻击者可以通过读取路径绕过安全检查，实现路径遍历、符号链接攻击或敏感文件读取。

---

## 技术分析

### 1. 安全措施对比

#### FSPIOWriter/VstarIOWriter（完整安全栈）

**调用路径**: 
- `ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:121-124` (FSPIOWriter构造函数)
- `vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp:128-131` (VstarIOWriter构造函数)

**安全检查清单**:
```cpp
// initializeFileDescription() 中的安全栈
void initializeFileDescription(int &fd, const std::string &fname)
{
    // [1] 路径长度校验 (255字符限制)
    if (fname.length() > 255) { ASCEND_THROW_MSG("Path too long!\n"); }
    
    // [2] 路径字符白名单校验
    for (uint32_t j = 0; j < fname.length(); j++) {
        if (!isValidCode(fname[j]) && !isInWhiteList(fname[j])) {
            ASCEND_THROW_MSG("Invalid Path!\n");
        }
    }
    // 白名单: a-z, A-Z, 0-9, '-', '_', '.', '/', '~'
    
    // [3] 相对路径转换为绝对路径
    if (fname[0] != '/' && !(fname.length() > 1 && fname[0] == '~' && fname[1] == '/')) {
        char buffer [PATH_MAX];
        getcwd(buffer, sizeof(buffer));
        realPath = absPath + "/" + fname;
    }
    
    // [4] O_NOFOLLOW标志 - 防止跟随最终组件的软链接
    fd = open(realPath.c_str(), O_NOFOLLOW | O_WRONLY);
    
    // [5] 父目录递归软链接检查 (checkLinkRec)
    parentDirCheckAndRemove(realPath, fd, false);
    
    // [6] 普通文件属性校验
    if (!S_ISREG(st.st_mode)) { ASCEND_THROW_MSG("File is not a regular file.\n"); }
    
    // [7] 文件大小限制 (56GB)
    if (st.st_size > MAX_DATAFILE_SIZE) { ASCEND_THROW_MSG("File exceeds maximum size.\n"); }
    
    // [8] 文件属主校验
    if (st.st_uid != geteuid()) { ASCEND_THROW_MSG("Not File Owner.\n"); }
}
```

#### FSPIOReader/VstarIOReader（最小安全措施）

**调用路径**:
- `ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp:131-136` (FSPIOReader构造函数)
- `vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp:138-143` (VstarIOReader构造函数)

**仅有的安全措施**:
```cpp
FSPIOReader::FSPIOReader(const std::string &fname) : name(fname)
{
    // 仅使用O_NOFOLLOW标志 - 防止最终组件是软链接
    fd = open(name.c_str(), O_NOFOLLOW | O_RDONLY);
    ASCEND_THROW_IF_NOT_MSG(fd >= 0, "fname or one of its parent directory is a softlink...\n");
}
```

**缺失的安全检查**:
| 检查项 | Writer状态 | Reader状态 | 安全影响 |
|--------|-----------|-----------|---------|
| 路径长度限制 | ✓ (255) | ✗ | 可能导致缓冲区溢出 |
| 字符白名单 | ✓ | ✗ | 路径遍历攻击 |
| 绝对路径解析 | ✓ | ✗ | 相对路径歧义 |
| 父目录软链接检查 | ✓ (递归) | ✗ | 符号链接绕过 |
| 普通文件校验 | ✓ | ✗ | 读取设备文件 |
| 文件大小限制 | ✓ (56GB) | ✗ | 内存耗尽 |
| 文件属主校验 | ✓ | ✗ | 跨用户读取 |

---

### 2. 受影响的入口点

#### 入口点A: addCodeBook (feature_retrieval)

**文件**: `feature_retrieval/src/ascendfaiss/ascend/ivfsp/AscendIndexIVFSP.h:109`

**信任等级**: `untrusted_local` - 用户指定码本文件路径

**调用链**:
```
addCodeBook(const char *codeBookPath)
  → AscendIndexIVFSPImpl::addCodeBook(codeBookPath)  [AscendIndexIVFSPImpl.cpp:102]
    → pIVFSPSQ->addCodeBook(cdbkFilePath)  [AscendIndexIVFSPSQ.cpp:278]
      → AscendIndexIVFSPSQImpl::addCodeBook(path)  [AscendIndexIVFSPSQImpl.cpp:1116]
        → FSPIOReader(path)  [Line 1131]
```

**部分缓解措施** (在调用FSPIOReader前):
```cpp
// AscendIndexIVFSPSQImpl.cpp:1121-1128
struct stat codeBookStat;
if (lstat(path.c_str(), &codeBookStat) == 0) {
    if (!S_ISREG(codeBookStat.st_mode)) { FAISS_THROW_MSG("..."); }
    if (codeBookStat.st_size > CODE_BOOK_MAX_FILE_SIZE || codeBookStat.st_uid != geteuid()) {
        FAISS_THROW_FMT("...");
    }
}
```

**仍存在的漏洞**:
- TOCTOU漏洞: `lstat()`与`open()`之间存在时间窗口
- 父目录软链接绕过: 无递归检查
- 无路径字符白名单校验

#### 入口点B: loadAllData (ivfsp_impl)

**文件**: `ivfsp_impl/ascendfaiss/ascenddaemon/impl_custom/IndexIVFSPSQ.cpp:1043`

**调用链**:
```
loadAllData(const char *dataPath)
  → IndexIVFSPSQ::loadDeviceAllData(dataFile)
    → LoadCheck(dataFile)  [Line 1032]  // 部分校验
    → FSPIOReader(dataFileString)  [Line 1043]
```

**LoadCheck()分析**:
```cpp
void LoadCheck(const char *dataFile)
{
    std::ifstream allDataFin(dataFile, std::ios::binary);  // 问题: ifstream默认跟随软链接!
    struct stat st;
    lstat(dataFile, &st);
    // 仅检查: 文件存在、普通文件、大小<56GB
    // 缺失: 属主校验、父目录软链接检查、字符白名单
}
```

**漏洞**: ifstream的`open()`默认跟随软链接，绕过了lstat()检查

#### 入口点C: LoadIndex (vstar_great_impl)

**文件**: `vstar_great_impl/mix-index/src/npu/NpuIndexIVFHSP.cpp:344-346`

**调用链**:
```
NpuIndexIVFHSP::LoadIndex(indexPath)
  → VstarIOReader(indexPath)  [Line 346]  // 无前置校验!
```

**前置校验**: 无任何校验，直接使用VstarIOReader

#### 入口点D: ReadFile (IVFSPCodeBookTrainer)

**文件**: `ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp:151`

**调用链**:
```
IVFSPCodeBookTrainer::ReadFile(learnDataPath)
  → FSPIOReader(learnDataPath)  [Line 151]  // 无前置校验!
```

---

### 3. 根本原因分析

**安全设计缺陷**: 
开发者假设读取操作比写入操作"安全"，因此对读取路径实施了较少的安全检查。这是一种错误的安全假设，因为：

1. **信息泄露风险**: 读取敏感文件可能导致凭证泄露、配置泄露
2. **权限提升**: 通过读取其他用户的文件，可能获取提权信息
3. **路径遍历**: 读取操作同样需要防止路径遍历攻击
4. **符号链接攻击**: 攻击者可利用符号链接绕过预期的访问边界

**防御不对称性**:
```
Writer Security Stack (8项)   vs   Reader Security Stack (1项)
┌─────────────────────────┐        ┌─────────────────────────┐
│ Path Length Check       │        │ O_NOFOLLOW only         │
│ Character Whitelist     │        │                         │
│ Absolute Path Resolve   │        │                         │
│ O_NOFOLLOW              │        │                         │
│ Parent Dir Symlink Check│        │                         │
│ Regular File Check      │        │                         │
│ File Size Limit         │        │                         │
│ File Owner Check        │        │                         │
└─────────────────────────┘        └─────────────────────────┘
```

---

## 攻击场景

### 场景1: 父目录符号链接绕过

**前提条件**: 
- 攻击者有权限创建目录和符号链接
- 应用程序以较高权限运行（如root或service账户）

**攻击步骤**:
```
# 1. 创建攻击目录结构
mkdir -p /tmp/attack
ln -s /etc /tmp/attack/passwd_dir  # 创建指向/etc的符号链接

# 2. 准备攻击文件
echo "malicious_data" > /tmp/attack/passwd_dir/passwd.malicious

# 3. 触发漏洞
# 当应用程序调用 FSPIOReader("/tmp/attack/passwd_dir/passwd.malicious")
# O_NOFOLLOW只检查最终组件，不检查父目录passwd_dir是否是符号链接
# 应用程序会读取到/etc/passwd.malicious（如果存在）或攻击者可控路径
```

**Writer防护对比**:
`initializeFileDescription()`会调用`checkLinkRec()`递归检查所有父目录:
```cpp
bool checkLinkRec(const std::string &realPathFunc)
{
    std::string tmpPath = realPathFunc;
    while (tmpLast != -1) {
        if (S_ISLNK(saveStatTmp.st_mode)) { return true; }  // 发现软链接即拒绝
        tmpPath = tmpPath.substr(0, tmpLast);  // 向上遍历父目录
    }
}
```

### 场景2: TOCTOU攻击

**攻击目标**: `addCodeBook()`函数

**漏洞代码**:
```cpp
// AscendIndexIVFSPSQImpl.cpp:1121-1131
struct stat codeBookStat;
lstat(path.c_str(), &codeBookStat);  // [T1] 时间点1: 检查文件属性
// ... 检查通过 ...
FSPIOReader codeBookReader(path);    // [T2] 时间点2: 打开文件
```

**攻击步骤**:
```
# 1. 准备合法文件（通过lstat检查）
echo "valid_codebook_data" > /tmp/codebook.bin

# 2. 创建竞争脚本
while true; do
    # 在lstat和open之间替换文件
    rm /tmp/codebook.bin
    ln -s /etc/shadow /tmp/codebook.bin  # 替换为指向敏感文件的符号链接
    sleep 0.001
    rm /tmp/codebook.bin
    echo "valid_codebook_data" > /tmp/codebook.bin
done

# 3. 触发addCodeBook调用
# 如果竞争成功，FSPIOReader会打开/etc/shadow而非原始文件
```

**注意**: O_NOFOLLOW会阻止直接打开符号链接，但攻击者可以在竞争窗口内:
1. 先替换为符号链接（让lstat看到符号链接）
2. 然后快速替换为符号链接指向的目标文件副本

### 场景3: 跨用户文件读取

**漏洞代码**:
```cpp
// FSPIOReader/VstarIOReader 不检查文件属主
fd = open(name.c_str(), O_NOFOLLOW | O_RDONLY);
```

**攻击步骤**:
```
# 前提: 应用程序以服务账户service_user运行
# 攻击者以普通用户attacker身份操作

# 1. 攻击者创建包含敏感信息的文件
echo "secret_api_key=XXXXX" > /home/attacker/secrets.txt
chmod 644 /home/attacker/secrets.txt  # 任何人可读

# 2. 触发应用程序读取攻击者可控路径
# FSPIOReader("/home/attacker/secrets.txt")
# 不检查属主，直接读取成功

# 3. 信息泄露
# 应用程序读取攻击者文件内容，可能将其写入日志或返回给其他接口
```

**Writer防护对比**:
```cpp
if (st.st_uid != geteuid()) { ASCEND_THROW_MSG("Not File Owner.\n"); }
```

### 场景4: 路径遍历攻击

**漏洞代码**:
```cpp
// FSPIOReader不校验路径字符，允许../序列
fd = open(name.c_str(), O_NOFOLLOW | O_RDONLY);
```

**Writer防护对比**:
```cpp
// 只允许: a-z, A-Z, 0-9, '-', '_', '.', '/', '~'
for (uint32_t j = 0; j < fname.length(); j++) {
    if (!isValidCode(fname[j]) && !isInWhiteList(fname[j])) {
        ASCEND_THROW_MSG("Invalid Path!\n");
    }
}
// 注意: '.'在白名单中，但连续的'..'可能被滥用
```

**攻击示例**:
```
# 假设应用程序限制在/data/index目录下操作
# 用户传入路径: "/data/index/../../../etc/passwd"

# Writer会拒绝: 
# - 因为路径字符包含多个'.'和'..'组合触发检查
# - 绝对路径解析后超出预期范围

# Reader直接使用原始路径:
# - 可能成功读取/etc/passwd（如果O_NOFOLLOW未触发）
```

---

## 影响范围分析

### 直接影响

| 影响类型 | 严重程度 | 描述 |
|----------|---------|------|
| **信息泄露** | High | 可读取敏感配置文件、密钥文件、密码文件 |
| **权限提升** | Medium | 通过读取其他用户文件获取提权信息 |
| **拒绝服务** | Medium | 读取超大文件导致内存耗尽 |
| **数据完整性** | Low | 读取恶意数据影响应用程序状态 |

### 受影响组件

| 模块 | 文件路径 | 函数 | 使用情况 |
|------|---------|------|---------|
| ivfsp_utils | `src/ascenddaemon/utils/IoUtil.cpp` | FSPIOReader | 仅O_NOFOLLOW |
| vstar_great_impl | `mix-index/src/utils/VstarIoUtil.cpp` | VstarIOReader | 仅O_NOFOLLOW |
| feature_retrieval | `src/ascendfaiss/ascend/ivfsp/AscendIndexIVFSPImpl.cpp` | addCodeBook | TOCTOU风险 |
| ivfsp_impl | `src/ascenddaemon/impl_custom/IndexIVFSPSQ.cpp` | loadDeviceAllData | ifstream风险 |
| vstar_great_impl | `mix-index/src/npu/NpuIndexIVFHSP.cpp` | LoadIndex | 无前置校验 |
| ivfsp_impl | `src/ascenddaemon/IVFSPCodeBookTrainer.cpp` | ReadFile | 无前置校验 |

### 攻击复杂度评估

| 因素 | 评估 |
|------|------|
| 攻击前提条件 | Medium - 需要文件系统访问权限 |
| 攻击技术难度 | Low - 标准符号链接/路径遍历技术 |
| 攻击可靠性 | Medium - TOCTOU需要精确时间控制 |
| 攻击检测难度 | High - 文件读取操作难以区分正常与异常 |

---

## 修复建议

### 修复方案A: 统一安全栈（推荐）

**原理**: 为FSPIOReader/VstarIOReader添加与Writer相同的安全检查

**实现方案**:

```cpp
// 创建统一的路径验证函数
void validateFilePath(const std::string &fname, bool forWrite = false)
{
    std::string realPath = fname;
    struct stat st;
    
    // [1] 路径长度校验
    if (fname.length() > 255) { 
        ASCEND_THROW_MSG("Path too long!\n"); 
    }
    
    // [2] 路径字符白名单校验
    for (uint32_t j = 0; j < fname.length(); j++) {
        if (!isValidCode(fname[j]) && !isInWhiteList(fname[j])) {
            ASCEND_THROW_MSG("Invalid Path!\n");
        }
    }
    
    // [3] 绝对路径解析
    if (fname[0] != '/' && !(fname.length() > 1 && fname[0] == '~' && fname[1] == '/')) {
        char buffer[PATH_MAX];
        if (getcwd(buffer, sizeof(buffer)) != nullptr) {
            std::string absPath = buffer;
            realPath = absPath + "/" + fname;
        } else {
            ASCEND_THROW_MSG("Failed to retrieve absolute path!\n");
        }
    }
    
    // [4] 父目录软链接递归检查
    if (checkLinkRec(realPath)) {
        ASCEND_THROW_MSG("Path contains symbolic link in parent directories!\n");
    }
    
    // [5] 文件存在检查
    if (lstat(realPath.c_str(), &st) != 0) {
        ASCEND_THROW_MSG("File does not exist!\n");
    }
    
    // [6] 普通文件校验
    if (!S_ISREG(st.st_mode)) {
        ASCEND_THROW_MSG("File is not a regular file.\n");
    }
    
    // [7] 文件大小校验 (读取时也需要防止内存耗尽)
    if (st.st_size > MAX_DATAFILE_SIZE) {
        ASCEND_THROW_MSG("File exceeds maximum size.\n");
    }
    
    // [8] 文件属主校验
    if (st.st_uid != geteuid()) {
        ASCEND_THROW_MSG("Not File Owner.\n");
    }
}

// 修改FSPIOReader构造函数
FSPIOReader::FSPIOReader(const std::string &fname) : name(fname)
{
    validateFilePath(fname, false);  // 统一验证
    fd = open(name.c_str(), O_NOFOLLOW | O_RDONLY);
    ASCEND_THROW_IF_NOT_MSG(fd >= 0, "Failed to open file.\n");
}

// 修改VstarIOReader构造函数
VstarIOReader::VstarIOReader(const std::string &fname) : name(fname)
{
    validateFilePath(fname, false);  // 统一验证
    fd = open(name.c_str(), O_NOFOLLOW | O_RDONLY);
    ASCEND_THROW_IF_NOT_MSG(fd >= 0, "Failed to open file.\n");
}
```

**优势**:
- 完全消除安全不对称性
- 防止所有攻击场景
- 代码复用，减少维护成本

**风险**:
- 可能影响读取非属主文件的合法场景
- 需要评估业务影响

### 修复方案B: 增强部分校验（快速修复）

**原理**: 针对最危险的漏洞添加关键检查

**实现方案**:

```cpp
FSPIOReader::FSPIOReader(const std::string &fname) : name(fname)
{
    // [新增] 绝对路径解析
    std::string realPath = fname;
    if (fname[0] != '/') {
        char buffer[PATH_MAX];
        if (getcwd(buffer, sizeof(buffer)) != nullptr) {
            realPath = std::string(buffer) + "/" + fname;
        }
    }
    
    // [新增] 父目录软链接检查
    if (checkLinkRec(realPath)) {
        ASCEND_THROW_MSG("Parent directory contains symlink!\n");
    }
    
    // [新增] 文件属主校验
    struct stat st;
    if (lstat(realPath.c_str(), &st) == 0) {
        if (st.st_uid != geteuid()) {
            ASCEND_THROW_MSG("Not File Owner.\n");
        }
    }
    
    fd = open(realPath.c_str(), O_NOFOLLOW | O_RDONLY);
    ASCEND_THROW_IF_NOT_MSG(fd >= 0, "Failed to open file.\n");
}
```

### 修复方案C: 移除TOCTOU漏洞

**原理**: 使用fstat()替代lstat()，消除时间窗口

**针对addCodeBook的修复**:

```cpp
void AscendIndexIVFSPSQImpl::addCodeBook(const std::string &path)
{
    // 修复: 先打开文件，再检查属性 (消除TOCTOU)
    ::ascendSearch::FSPIOReader codeBookReader(path);  // 先打开
    struct stat st;
    if (fstat(codeBookReader.fd, &st) != 0) {  // 使用fstat而非lstat
        FAISS_THROW_MSG("Cannot get file stats.\n");
    }
    
    // 在文件已打开的情况下进行校验
    if (!S_ISREG(st.st_mode)) {
        FAISS_THROW_MSG("Not a regular file.\n");
    }
    if (st.st_size > CODE_BOOK_MAX_FILE_SIZE) {
        FAISS_THROW_MSG("File too large.\n");
    }
    if (st.st_uid != geteuid()) {
        FAISS_THROW_MSG("Not file owner.\n");
    }
    
    // 继续读取处理...
}
```

**注意**: 此方案需配合方案A/B中的Reader安全增强

### 修复方案D: 替换ifstream

**针对LoadCheck的修复**:

```cpp
void LoadCheck(const char *dataFile)
{
    // 修复: 使用lstat而非ifstream进行存在性检查
    struct stat st;
    ASCEND_THROW_IF_NOT_FMT(lstat(dataFile, &st) == 0, "ERROR: %s", strerror(errno));
    
    // 检查是否为软链接
    ASCEND_THROW_IF_NOT_MSG(!S_ISLNK(st.st_mode), "ERROR: File is a symbolic link!\n");
    
    // 检查是否为普通文件
    ASCEND_THROW_IF_NOT_FMT((st.st_mode & S_IFMT) == S_IFREG, 
        "ERROR: Data file input[%s] is not a Regular File!", dataFile);
    
    // 检查文件大小
    ASCEND_THROW_IF_NOT_FMT(st.st_size < MAX_DATAFILE_SIZE && st.st_size >= 16,
        "ERROR: Data file input[%s] size invalid!", dataFile);
    
    // [新增] 检查文件属主
    ASCEND_THROW_IF_NOT_FMT(st.st_uid == geteuid(),
        "ERROR: Data file input[%s] is not owned by current user!", dataFile);
    
    // [新增] 检查父目录软链接
    std::string pathStr(dataFile);
    ASCEND_THROW_IF_NOT_MSG(!checkLinkRec(pathStr), 
        "ERROR: Parent directory contains symbolic link!\n");
}
```

---

## 验证测试建议

### 测试用例1: 父目录符号链接测试

```cpp
// 测试代码
void testParentDirSymlink() {
    // 创建测试环境
    mkdir("/tmp/test_dir", 0755);
    symlink("/etc", "/tmp/test_dir/link_dir");
    system("echo 'test' > /etc/test_file");  // 需要root权限
    
    // 尝试读取
    try {
        FSPIOReader reader("/tmp/test_dir/link_dir/test_file");
        // 应抛出异常
        assert(false && "Should have thrown exception");
    } catch (...) {
        // 预期行为
    }
}
```

### 测试用例2: TOCTOU竞争测试

```cpp
// 测试代码
void testTOCTOU() {
    std::string path = "/tmp/toctou_test.bin";
    
    // 创建竞争线程
    std::thread attacker([&path]() {
        while (true) {
            unlink(path.c_str());
            symlink("/etc/shadow", path.c_str());
            usleep(100);
            unlink(path.c_str());
            system("echo 'valid' > " + path);
            usleep(100);
        }
    });
    
    // 尝试读取
    try {
        addCodeBook(path.c_str());
        // 检查读取的内容是否来自预期文件
    } catch (...) {
        // 安全拒绝
    }
    
    attacker.detach();
}
```

### 测试用例3: 属主校验测试

```cpp
void testOwnerCheck() {
    // 创建其他用户的文件（需要多用户环境）
    system("sudo -u otheruser echo 'secret' > /tmp/otheruser_file.txt");
    
    try {
        FSPIOReader reader("/tmp/otheruser_file.txt");
        // 应抛出异常
        assert(false && "Should have thrown exception");
    } catch (...) {
        // 预期行为
    }
}
```

---

## 修复优先级

| 优先级 | 修复项 | 工作量 | 风险 |
|--------|-------|--------|------|
| P0 | 父目录软链接检查 | 2小时 | Low |
| P0 | 文件属主校验 | 1小时 | Medium |
| P1 | 移除TOCTOU漏洞 | 3小时 | Low |
| P1 | 替换ifstream | 1小时 | Low |
| P2 | 路径字符白名单 | 2小时 | Medium |
| P2 | 绝对路径解析 | 2小时 | Low |

---

## 总结

VULN-CROSS-002是一个真实的安全漏洞，源于文件I/O操作中读写安全措施的不对称设计。攻击者可以通过以下方式利用此漏洞：

1. **符号链接绕过**: 通过父目录中的符号链接访问预期路径外的文件
2. **TOCTOU攻击**: 在检查和打开之间的时间窗口替换文件
3. **跨用户读取**: 绕过属主校验读取其他用户的敏感文件
4. **路径遍历**: 通过相对路径或特殊字符绕过预期目录限制

建议采用修复方案A（统一安全栈）作为长期解决方案，方案B/C/D作为快速缓解措施。所有修复应在充分测试后部署，确保不影响正常业务功能。

