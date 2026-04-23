# Zstandard (zstd) 压缩库威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析为 AI 自主识别，未使用 threat.md 约束文件。

## 1. 项目架构概览

### 1.1 项目定位

**Zstandard (zstd)** 是 Facebook/Meta 开发的高性能无损压缩算法，定位为：
- **核心类型**：C 语言压缩/解压缩库（library）
- **次要类型**：CLI 命令行工具（用于文件压缩/解压缩）
- **部署场景**：
  - 作为静态/动态库嵌入应用程序
  - 作为 CLI 工具在本地执行文件压缩
  - 作为 Linux 内核模块提供压缩服务
  - 作为 zlib/gzip 兼容层替代原有实现

### 1.2 模块结构

| 模块 | 目录 | 语言 | 行数 | 主要功能 | 风险等级 |
|------|------|------|------|----------|----------|
| **lib_decompress** | lib/decompress | C | ~5,200 | 核心解压缩逻辑 | **Critical** |
| **lib_legacy** | lib/legacy | C | ~16,000 | 旧版本格式解压缩 | **High** |
| **lib_common** | lib/common | C | ~3,500 | 公共基础设施（熵解码） | **High** |
| **lib_compress** | lib/compress | C | ~7,000 | 压缩逻辑 | Low |
| **programs_cli** | programs | C | ~12,000 | CLI 工具 | Medium |
| **zlib_wrapper** | zlibWrapper | C | ~3,400 | zlib 兼容层 | High |
| **contrib_linux_kernel** | contrib/linux-kernel | C | ~1,500 | 内核模块 | **Critical** |
| **contrib_seekable** | contrib/seekable_format | C | ~800 | 可寻址格式 | High |

### 1.3 源代码统计

- **总文件数**：142 个 C/C++ 文件 + 4 个 Python 文件
- **总代码行数**：~102,906 行
- **核心库代码**：~79,928 行
- **CLI 工具代码**：~12,284 行
- **兼容层代码**：~3,470 行

## 2. 攻击面分析

### 2.1 信任边界

| 边界名称 | 可信一侧 | 不可信一侧 | 风险等级 | 说明 |
|----------|----------|------------|----------|------|
| **压缩数据输入** | 应用逻辑（压缩） | 网络/文件数据（解压缩） | Critical | 解压缩处理用户提供的数据，是最主要的攻击面 |
| **文件系统接口** | 应用控制的路径 | CLI 用户指定的路径 | Medium | CLI 模式下用户可指定任意文件路径 |
| **字典加载** | 应用提供的字典 | 外部字典文件 | High | 字典数据影响解压缩行为 |
| **内核接口** | 内核代码 | 用户空间数据 | Critical | 内核模块接收用户空间的压缩数据 |

### 2.2 入口点分类

#### Critical 级别入口点

| 入口点 | 文件 | 函数 | 说明 |
|--------|------|------|------|
| 核心解压缩 API | lib/zstd.h | ZSTD_decompress() | 处理任意压缩数据缓冲区 |
| 流式解压缩 | lib/decompress/zstd_decompress.c | ZSTD_decompressStream() | 持续接收数据流 |
| 块解码 | lib/decompress/zstd_decompress_block.c | ZSTD_decompressBlock() | 解码单个压缩块 |
| Huffman 解码 | lib/decompress/huf_decompress.c | HUF_decompress() | 熵解码表可能被恶意构造 |

#### High 级别入口点

| 入口点 | 文件 | 函数 | 说明 |
|--------|------|------|------|
| Legacy v0.1 | lib/legacy/zstd_v01.c | ZSTDv01_decompress() | 早期格式可能缺乏安全检查 |
| Legacy v0.2-v0.7 | lib/legacy/*.c | ZSTDvXX_decompress() | 旧格式解压缩 |
| FSE 熵解码 | lib/common/fse_decompress.c | FSE_decompress() | 有限状态熵解码 |
| zlib 兼容层 | zlibWrapper/gzread.c | gzread() | gzip 格式处理 |

#### Medium 级别入口点

| 入口点 | 文件 | 函数 | 说明 |
|--------|------|------|------|
| CLI 入口 | programs/zstdcli.c | main(argc, argv) | 命令行参数处理 |
| 文件 I/O | programs/fileio.c | FIO_decompressFilename() | 文件路径处理 |
| 字典训练 | lib/dictBuilder/zdict.c | ZDICT_trainFromBuffer() | 样本数据处理 |

### 2.3 数据流路径

**关键攻击路径：CLI 解压缩 → 熵解码 → 内存拷贝**

```
用户文件路径 (argv)
    ↓
FIO_openSrcFile (fopen)
    ↓
fread (读取压缩数据)
    ↓
ZSTD_decompress
    ↓
ZSTD_decompressBlock
    ↓
ZSTD_decodeLiteralsBlock → HUF_decompress → ZSTD_memcpy
    ↓
ZSTD_decompressSequences → ZSTD_memcpy
```

## 3. 模块风险评估

### 3.1 lib/decompress 模块（Critical）

**风险描述**：解压缩模块是处理不可信数据的核心模块。恶意构造的压缩数据可触发：
- **缓冲区溢出**：解码表大小计算错误导致越界写入
- **整数溢出**：帧大小/块大小参数溢出
- **内存破坏**：序列解码时的 match/literal 操作越界
- **拒绝服务**：恶意帧头声明超大解压缩大小

**关键文件**：
- `zstd_decompress.c`：帧级解压缩，窗口大小验证
- `zstd_decompress_block.c`：块解码，序列执行
- `huf_decompress.c`：Huffman 熵解码，表构建

### 3.2 lib/legacy 模块（High）

**风险描述**：旧版本格式（v0.1-v0.7）解压缩代码可能缺乏现代安全检查：
- 早期代码可能未实施完整的边界检查
- 魔数识别后直接调用旧版解码器
- 旧格式可能有不同的帧结构，缺乏文档

**关键文件**：
- `zstd_v01.c` ~ `zstd_v07.c`：7 个旧版本解码器

### 3.3 lib/common 模块（High）

**风险描述**：公共模块包含熵解码基础设施：
- FSE 解码表构建依赖用户提供的数据
- bitstream 操作依赖正确的边界检查

**关键文件**：
- `fse_decompress.c`：有限状态熵解码
- `entropy_common.c`：熵编码公共函数
- `mem.h`：内存读取辅助函数

### 3.4 contrib/linux-kernel 模块（Critical）

**风险描述**：内核模块在更高权限下运行，安全漏洞影响更严重：
- 内核空间内存破坏可能导致系统崩溃
- 用户空间数据通过系统调用进入内核

**关键文件**：
- `zstd_decompress_module.c`：内核解压缩接口

### 3.5 zlibWrapper 模块（High）

**风险描述**：zlib 兼容层处理 gzip 格式：
- 应用可能通过 gzread() 处理外部文件
- 兼容层需要正确处理 zlib/zstd 格式切换

## 4. STRIDE 威胁建模

### 4.1 Spoofing（身份伪造）

| 威胁 | 可能性 | 影响 | 说明 |
|------|--------|------|------|
| 伪造帧魔数 | Medium | Low | 恶意数据伪装为 zstd 格式，但会被魔数检查拒绝 |
| 伪造字典 ID | Low | Medium | 可能导致错误的字典被加载 |

**缓解措施**：魔数验证、帧头完整性检查已实施。

### 4.2 Tampering（数据篡改）

| 威胁 | 可能性 | 影响 | 说明 |
|------|--------|------|------|
| 恶意压缩数据触发内存破坏 | **High** | **Critical** | 恶意构造的帧可触发缓冲区溢出 |
| 熵解码表篡改 | Medium | High | 恶意 Huffman/FSE 表可能导致越界访问 |
| 块大小篡改 | Medium | Critical | 声明超大块大小可能导致内存分配失败或溢出 |

**缓解措施**：需要严格的边界检查和大小验证。

### 4.3 Repudiation（抵赖）

| 威虑 | 可能性 | 影响 | 说明 |
|------|--------|------|------|
| 无日志记录 | Low | Low | CLI 工具和库 API 不记录操作日志 |

**缓解措施**：依赖应用层日志。

### 4.4 Information Disclosure（信息泄露）

| 威胁 | 可能性 | 影响 | 说明 |
|------|--------|------|------|
| 解压缩过程中内存内容泄露 | Low | Medium | 未初始化内存可能被写入输出 |
| 错误消息泄露内部状态 | Low | Low | 错误代码不泄露敏感信息 |

**缓解措施**：内存初始化、错误消息抽象。

### 4.5 Denial of Service（拒绝服务）

| 威胁 | 可能性 | 影响 | 说明 |
|------|--------|------|------|
| 恶意帧头声明超大大小 | **High** | **High** | 导致内存分配失败或长时间运行 |
| 循环压缩数据 | Medium | Medium | 导致无限循环解压缩 |
| 资源耗尽 | Medium | Medium | 多线程/流式解压缩资源消耗 |

**缓解措施**：窗口大小限制（ZSTD_MAXWINDOWSIZE_DEFAULT）、前进进度检查。

### 4.6 Elevation of Privilege（权限提升）

| 威胁 | 可能性 | 影响 | 说明 |
|------|--------|------|------|
| 内存破坏后代码执行 | **Medium** | **Critical** | 解压缩漏洞可被利用执行任意代码 |
| 内核模块漏洞 | Low | **Critical** | 内核空间漏洞导致 root 权限 |

**缓解措施**：需要完整的内存安全检查。

## 5. 安全加固建议

### 5.1 架构层面建议

1. **分离压缩和解压缩信任域**
   - 解压缩模块应被视为不可信数据处理模块
   - 建议在沙箱环境中运行解压缩操作

2. **输入验证强化**
   - 所有帧头参数应在处理前进行完整性验证
   - 块大小/帧大小应与实际数据长度对比

3. **资源限制**
   - 强制实施最大窗口大小限制
   - 实施解压缩进度检查防止循环攻击
   - 内存分配应有上限

4. **Legacy 格式处理**
   - 建议禁用不必要的旧版本支持
   - 对旧格式实施与当前格式相同的安全检查

5. **内核模块安全**
   - 内核模块应实施最严格的输入验证
   - 建议限制可解压缩的数据大小

### 5.2 代码层面建议

1. **熵解码表验证**
   - HUF_readDTable/FSE_buildDTable 应验证表大小
   - 符号值应在合法范围内

2. **序列解码边界检查**
   - match 拷贝操作应检查目标缓冲区边界
   - literal 拷贝应验证长度

3. **整数溢出防护**
   - 所有大小计算应使用安全算术
   - 检查 size_t 溢出

4. **内存初始化**
   - 分配的缓冲区应初始化为零
   - 防止未初始化内存泄露

## 6. 扫描重点建议

基于以上威胁分析，建议后续漏洞扫描重点关注：

### 6.1 高优先级扫描目标

| 优先级 | 文件 | 函数/区域 | 漏洞类型 |
|--------|------|-----------|----------|
| 1 | zstd_decompress_block.c | ZSTD_execSequence() | Buffer Overflow |
| 2 | huf_decompress.c | HUF_readDTable() | Out-of-bounds |
| 3 | zstd_decompress.c | ZSTD_decompressFrame() | Integer Overflow |
| 4 | zstd_v01.c ~ zstd_v07.c | 各 decodeFrame() | Legacy Vulnerabilities |
| 5 | fse_decompress.c | FSE_buildDTable() | Table Overflow |

### 6.2 重点关注的污点路径

- **数据源**：`ZSTD_decompress()` 的 `src` 参数
- **数据传递**：帧头解析 → 块解码 → 熵解码 → 序列解码
- **敏感操作**：`ZSTD_memcpy`、`ZSTD_malloc`、边界计算

---

**报告生成时间**：2026-04-21
**分析工具**：Architecture Agent（自主分析模式）