# IndexSDK 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析为 AI 自主识别，无 `threat.md` 约束文件。

## 项目架构概览

### 项目基本信息

| 属性 | 值 |
|------|------|
| 项目名称 | IndexSDK |
| 项目类型 | SDK/库 (library) |
| 主要语言 | C/C++ + Python (混合项目) |
| 源文件数 | 434个 (排除测试/构建/第三方) |
| 代码行数 | 179,780行 |
| 主要功能 | 基于 Faiss 开发的昇腾 NPU 异构检索加速框架 |

### 目录结构

```
IndexSDK/
├── feature_retrieval/     # 特征检索核心模块 (C++ + Python TBE算子)
├── ivfsp_impl/           # IVFSP 索引实现 (C++)
├── ivfsp_utils/          # IVFSP 工具 (Python训练脚本 + C++)
├── vsa_hpp/              # VSA HPP 索引实现 (C++)
├── vstar_great_impl/     # VSTAR Great 实现 (C++)
├── build/                # 构建目录
└── docs/                 # 文档目录
```

### 模块划分

| 模块 | 语言 | 功能描述 | 风险等级 |
|------|------|----------|----------|
| feature_retrieval | mixed | 特征检索核心：AscendIndex基类、IVF索引、Flat索引等 | High |
| ivfsp_impl | c_cpp | IVFSP索引实现：IVFSPSQ索引、码本训练 | High |
| ivfsp_utils | mixed | IVFSP工具：文件I/O、CPU算子、训练脚本 | High |
| vsa_hpp | c_cpp | VSA HPP索引：邻居检索、HPP内核 | Medium |
| vstar_great_impl | c_cpp | VSTAR/Great实现：磁盘索引、NPU索引 | High |

## 项目定位分析

### 项目类型判定

本项目为 **SDK/库** 类型，判断依据：
- 无 `main()` 入口函数，不作为独立程序运行
- 提供 C++ API 接口供应用程序调用
- 基于 Faiss 框架，继承 `faiss::Index` 类
- 构建目标为 `.so/.a` 动态库/静态库

### 信任边界模型

| 信任等级 | 边界位置 | 说明 |
|---------|----------|------|
| untrusted_local | API接口 | 调用方应用程序传入的向量数据、查询参数完全可控 |
| untrusted_local | 文件I/O | 用户指定的索引文件路径、码本文件路径由调用方控制 |
| semi_trusted | 设备配置 | 设备列表、资源配置需要一定权限才能正确配置 |
| internal | SDK内部 | 内部生成的数据结构、硬编码常量 |

## 攻击面分析

### 主要攻击面

#### 1. API 接口攻击面 (风险等级: Medium)

用户应用程序调用 SDK API 时传入的数据：

| 入口点 | 函数 | 数据类型 | 安全措施 |
|--------|------|----------|----------|
| AscendIndex.h:70 | add(idx_t n, const float *x) | 向量数据指针 | 无输入校验 |
| AscendIndex.h:81 | search(idx_t n, const float *x, idx_t k, ...) | 查询向量指针 | 有长度限制 (MAX_K=4096) |
| AscendIndex.h:74 | add_with_ids(idx_t n, const float *x, const idx_t *ids) | 向量+ID | 无输入校验 |

**潜在风险**：
- 缓冲区溢出：传入的 `n` 值与实际数据长度不匹配
- 内存越界：传入的指针指向无效内存区域
- 整数溢出：`idx_t` 参数可能导致内存分配计算错误

#### 2. 文件 I/O 攻击面 (风险等级: High)

用户指定文件路径进行索引加载/保存：

| 入口点 | 函数 | 文件类型 | 安全措施 |
|--------|------|----------|----------|
| AscendIndexIVFSP.h:109 | addCodeBook(const char *codeBookPath) | 码本文件 | 软链接检查、路径校验 |
| IoUtil.cpp:28 | initializeFileDescription(int &fd, const std::string &fname) | 任意文件 | 全面安全检查 |

**已实施的安全检查**（IoUtil.cpp）：
- ✅ 软链接检查 (`checkSoftLink`, `checkLinkRec`)
- ✅ 路径长度限制 (255字符)
- ✅ 路径字符白名单 (`isValidCode`, `isInWhiteList`)
- ✅ 文件属主检查 (`st.st_uid == geteuid()`)
- ✅ 文件大小限制 (56GB)
- ✅ 普通文件类型检查 (`S_ISREG`)
- ✅ 使用 `O_NOFOLLOW` 标志打开文件

**潜在风险**：
- 虽有安全检查，但路径仍由用户控制
- `FSPIOReader` 构造函数中直接调用 `open()`，未调用完整的 `initializeFileDescription`
- 路径拼接逻辑可能存在边界条件问题

#### 3. 配置参数攻击面 (风险等级: Medium)

SDK 初始化时的配置参数：

| 入口点 | 参数 | 限制 |
|--------|------|------|
| AscendIndexConfig | deviceList | 设备ID列表，无校验 |
| AscendIndexConfig | resourceSize | 内存池大小，32MB~4096MB范围 |
| AscendIndexConfig | blockSize | 块大小，默认16384*16 |

**潜在风险**：
- 无效设备ID可能导致运行时错误
- 资源大小配置可能导致内存耗尽

### 高风险文件列表

| 优先级 | 文件路径 | 风险等级 | 风险类型 |
|--------|----------|----------|----------|
| 1 | ivfsp_utils/src/ascenddaemon/utils/IoUtil.cpp | High | 文件I/O、路径遍历 |
| 2 | vstar_great_impl/mix-index/src/utils/VstarIoUtil.cpp | High | 文件I/O、路径遍历 |
| 3 | feature_retrieval/src/ascendfaiss/ascend/ivfsp/AscendIndexIVFSP.cpp | High | 码本加载、文件输入 |
| 4 | feature_retrieval/src/ascendfaiss/ascenddaemon/utils/AscendMemory.cpp | High | 内存分配、缓冲区操作 |
| 5 | ivfsp_impl/ascendfaiss/ascenddaemon/IVFSPCodeBookTrainer.cpp | High | 码本训练、内存操作 |
| 6 | vstar_great_impl/mix-index/src/npu/common/utils/AscendMemory.cpp | High | 内存分配 |
| 7 | feature_retrieval/src/ascendfaiss/ascend/impl/AscendIndexImpl.cpp | High | 向量数据处理、memcpy |
| 8 | vstar_great_impl/DiskIndex/src/Adapter/OpenGaussAdapter.cpp | High | 数据库接口 |

## STRIDE 威胁建模

### Spoofing (欺骗)

| 威胁场景 | 可能性 | 影响 | 缓解措施 |
|----------|--------|------|----------|
| 恶意调用方伪装为合法应用调用API | Low | Medium | SDK无身份验证机制，依赖调用方可信 |
| 文件属主欺骗（符号链接指向恶意文件） | Low | High | 已有软链接检查和属主验证 |

### Tampering (篡改)

| 威胁场景 | 可能性 | 影响 | 缓解措施 |
|----------|--------|------|----------|
| 索引文件被篡改导致检索结果错误 | Medium | High | 文件属主检查、普通文件类型检查 |
| 输入向量数据被篡改导致内存越界 | Medium | High | 无输入校验，依赖调用方正确性 |
| 码本文件被篡改导致模型数据错误 | Medium | Medium | 文件完整性检查有限 |

### Repudiation (抵赖)

| 威胁场景 | 可能性 | 影响 | 缓解措施 |
|----------|--------|------|----------|
| 无法追溯哪个调用方导致了错误 | High | Low | 无日志记录机制 |

### Information Disclosure (信息泄露)

| 威胁场景 | 可能性 | 影响 | 缓解措施 |
|----------|--------|------|----------|
| 索引文件泄露敏感向量数据 | Medium | High | 文件权限设置为640，仅owner可读写 |
| 内存未清零导致数据残留 | Medium | Medium | 需审查内存释放逻辑 |

### Denial of Service (拒绝服务)

| 威胁场景 | 可能性 | 影响 | 缓解措施 |
|----------|--------|------|----------|
| 大量无效请求消耗NPU资源 | Medium | High | 有长度限制(MAX_K=4096) |
| 资源配置过大导致内存耗尽 | Low | High | 有资源大小上限(4096MB) |
| 文件过大导致读取超时 | Low | Medium | 有文件大小限制(56GB) |

### Elevation of Privilege (权限提升)

| 威胁场景 | 可能性 | 影响 | 缓解措施 |
|----------|--------|------|----------|
| 符号链接攻击读取非授权文件 | Low | Critical | 已有软链接检查 |
| 路径遍历读取系统敏感文件 | Low | Critical | 已有路径白名单校验 |

## 安全加固建议（架构层面）

### 1. 文件I/O安全增强

- [ ] **建议**：统一 `FSPIOReader` 和 `VstarIOReader` 的安全检查流程，确保读取操作也调用 `initializeFileDescription`
- [ ] **建议**：增加文件内容完整性校验（如校验码本文件的Magic Number）
- [ ] **建议**：对读取的索引数据进行边界校验，防止恶意构造的索引文件导致内存越界

### 2. API 输入校验增强

- [ ] **建议**：在 `add()` 和 `search()` 函数中增加向量数据指针的空指针检查
- [ ] **建议**：增加 `n` 参数的合理性校验（如不超过某个上限）
- [ ] **建议**：增加返回值的错误码机制，而非仅抛出异常

### 3. 内存安全增强

- [ ] **建议**：审查所有 `memcpy`、`malloc` 调用，确保有边界检查
- [ ] **建议**：在释放内存前清零敏感数据
- [ ] **建议**：使用 RAII 模式管理所有动态内存（已部分实现）

### 4. 配置安全增强

- [ ] **建议**：增加设备ID有效性校验
- [ ] **建议**：限制资源配置的取值范围，防止极端配置

### 5. 日志与审计

- [ ] **建议**：增加关键操作的日志记录（如文件加载、索引构建）
- [ ] **建议**：增加错误追踪机制，便于定位问题

---

**报告生成时间**: 2026-04-20T00:20:00Z
**分析工具**: Architecture Agent
**LSP可用性**: 是