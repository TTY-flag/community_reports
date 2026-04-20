# RAGSDK 威胁分析报告

> **分析模式：自主分析模式**
> 本次攻击面分析未基于 threat.md 约束，由 AI 自主识别所有潜在攻击面和高风险模块。

## 项目架构概览

### 项目基本信息
- **项目名称**: RAGSDK (昇腾 RAG SDK)
- **项目类型**: Python 库/SDK
- **语言组成**: Python 157 文件 + C/C++ 75 文件
- **主要功能**: 知识增强开发套件，为解决大模型知识更新缓慢以及垂直领域知识回答弱的问题，提供知识库管理、向量检索、GraphRAG 等能力

### 架构分层

```
┌─────────────────────────────────────────────────────────────┐
│                   调用方应用 (External)                      │
└─────────────────────────────────────────────────────────────┘
                              ↓ API 调用
┌─────────────────────────────────────────────────────────────┐
│                    mx_rag (Python SDK)                       │
│  ┌─────────────┬──────────────┬──────────────┬───────────┐  │
│  │ document/   │ storage/     │ graphrag/    │ llm/      │  │
│  │ loader      │ vectorstore  │              │           │  │
│  │             │ docstore     │              │           │  │
│  └─────────────┴──────────────┴──────────────┴───────────┘  │
│  ┌─────────────┬──────────────┬──────────────┬───────────┐  │
│  │ knowledge/  │ retrievers/  │ embedding/   │ utils/    │  │
│  │             │              │              │           │  │
│  └─────────────┴──────────────┴──────────────┴───────────┘  │
└─────────────────────────────────────────────────────────────┘
                              ↓ NPU 加速调用
┌─────────────────────────────────────────────────────────────┐
│                    ops (C/C++ 加速算子)                       │
│  ┌─────────────┬──────────────┬──────────────┐              │
│  │ models/     │ operations/  │ adapter/     │              │
│  │             │ plugin_op    │ workspace    │              │
│  └─────────────┴──────────────┴──────────────┘              │
└─────────────────────────────────────────────────────────────┘
                              ↓ 外部服务调用
┌─────────────────────────────────────────────────────────────┐
│              外部 LLM 服务 / OpenGauss 数据库                 │
└─────────────────────────────────────────────────────────────┘
```

### 信任边界

| 边界 | 可信一侧 | 不可信一侧 | 风险等级 |
|------|---------|-----------|----------|
| API Interface | SDK 内部代码 | 调用方应用代码 | High |
| File Input | SDK 文件处理模块 | 用户提供的文件路径和内容 | High |
| LLM Service | SDK HTTP 客户端 | 远程 LLM 服务响应 | Medium |
| Database Storage | SDK 存储模块 | 数据库数据 | Medium |
| NPU Acceleration | Python SDK | C/C++ ops 模块 | Low |

## 模块风险评估

### 高风险模块

| 模块 | 文件 | STRIDE 威胁 | 风险等级 | 说明 |
|------|------|-------------|----------|------|
| 文件加载 | pdf_loader.py | T, I, D | Critical | 解析用户提供的 PDF 文件，fitz.open() 可能存在解析漏洞 |
| 文件加载 | excel_loader.py | T, I, D | Critical | 解析用户提供的 Excel 文件，xlrd/openpyxl 可能存在 ZIP bomb 或解析漏洞 |
| 数据库操作 | opengauss_storage.py | T, I, E | High | BM25 搜索使用 text() 构造 SQL，存在 SQL 注入风险 |
| 知识管理 | knowledge.py | T, I, E | High | SQLite 数据库操作，知识库文件路径传入 |
| GraphRAG | graphrag_pipeline.py | T, I, D | High | 图数据库 Cypher 查询构造，工作目录路径传入 |
| 图数据库 | opengauss_graph.py | T, I | High | Cypher 查询执行，可能存在注入风险 |

### 中风险模块

| 模块 | 文件 | STRIDE 威胁 | 风险等级 | 说明 |
|------|------|-------------|----------|------|
| HTTP 客户端 | url.py | T, I | Medium | HTTP POST 请求，外部服务响应解析 |
| LLM 客户端 | text2text.py | T, I | Medium | JSON 解析外部服务响应 |
| 向量检索 | retriever.py | I | Medium | 用户查询字符串传入 |
| 模型加载 | text_embedding.py | T, I | Medium | 模型路径传入 transformers |
| 文件检查 | file_check.py | - | Medium | 安全检查模块，是防护而非风险点 |
| C++ 文件操作 | filesystem.cpp | T, I | Medium | 文件路径验证和读取 |

### 低风险模块

| 模块 | 文件 | STRIDE 威胁 | 风险等级 | 说明 |
|------|------|-------------|----------|------|
| 配置处理 | config.cpp | - | Low | 仅内部配置，不接收外部输入 |
| 工作空间 | workspace.cpp | - | Low | 内存操作，无外部输入 |
| 日志模块 | log/*.cpp | I | Low | 日志输出，信息泄露风险较低 |

## 攻击面分析

### 1. 文件输入攻击面 (High Risk)

**位置**: `mx_rag/document/loader/*.py`

**攻击向量**:
- **路径遍历**: 用户传入的 `file_path` 参数可能包含 `../` 或符号链接，导致读取敏感文件
- **ZIP Bomb**: Excel (xlsx) 文件本质是 ZIP 格式，可能存在 ZIP bomb 攻击
- **解析漏洞**: PDF/Excel 解析库 (fitz, xlrd, openpyxl) 可能存在解析漏洞，导致内存溢出或代码执行

**已存在的防护**:
- `file_check.py` 包含路径黑名单检查 (`/etc/`, `/usr/bin/` 等)
- `FileCheck.check_input_path_valid()` 检查 `..` 和符号链接
- `_is_zip_bomb()` 检测 ZIP bomb
- `SecFileCheck` 检查文件大小、属主、权限

**潜在漏洞**:
- 黑名单可能不完整，遗漏敏感路径
- PDF 解析库 `fitz` 的安全性依赖外部库版本
- 大文件处理可能导致内存耗尽

### 2. SQL/Cypher 注入攻击面 (High Risk)

**位置**: 
- `mx_rag/storage/document_store/opengauss_storage.py:134`
- `mx_rag/graphrag/graphs/opengauss_graph.py`

**攻击向量**:
- BM25 全文搜索使用 `text(":question_query")` 构造 SQL
- Cypher 查询使用字符串拼接构造节点/边属性
- 用户查询字符串直接传入查询构造

**已存在的防护**:
- SQLAlchemy ORM 提供基础保护
- `bindparam` 用于参数绑定
- `validate_params` 装饰器进行参数验证

**潜在漏洞**:
- `text()` 函数内的动态 SQL 可能存在注入点
- Cypher 查询的字符串拼接未完全参数化

### 3. HTTP 响应处理攻击面 (Medium Risk)

**位置**: `mx_rag/utils/url.py`, `mx_rag/llm/text2text.py`

**攻击向量**:
- 外部 LLM 服务返回恶意 JSON 数据
- HTTP 响应大小控制不当导致内存耗尽
- SSL/TLS 配置不当导致中间人攻击

**已存在的防护**:
- `response_limit_size` 限制响应大小
- TLS 配置和证书验证 (`TlsConfig`, `CertContentsChecker`)
- CRL 检查 (`CRLChecker`)
- URL 验证 (`HttpUrlChecker`, `HttpsUrlChecker`)

**潜在漏洞**:
- JSON 解析失败时仅返回空字符串，可能丢失错误信息
- HTTP 模式 (`use_http=True`) 无加密保护

### 4. 模型加载攻击面 (Medium Risk)

**位置**: `mx_rag/embedding/local/*.py`

**攻击向量**:
- 用户传入 `model_path` 指向恶意模型文件
- transformers 库加载模型时的 pickle 反序列化风险
- safetensors 格式验证不足

**已存在的防护**:
- `SecDirCheck` 检查模型目录
- `safetensors_check` 验证 safetensors 格式
- `local_files_only=True` 限制本地加载

**潜在漏洞**:
- transformers 内部可能仍使用 pickle
- 模型文件验证不够严格

### 5. 图数据库操作攻击面 (High Risk)

**位置**: `mx_rag/graphrag/graphs/opengauss_graph.py`

**攻击向量**:
- Cypher 查询字符串拼接可能导致注入
- 图数据属性包含恶意内容
- 节点 ID 使用哈希值，可能存在哈希碰撞

**已存在的防护**:
- `CypherQueryBuilder` 提供结构化查询构建
- 属性使用 `cypher_value()` 转义

**潜在漏洞**:
- 复杂查询场景可能存在注入点
- 属性转义可能不完整

## STRIDE 威胁建模

### Spoofing (欺骗)

| 威胁 | 位置 | 影响 | 防护措施 |
|------|------|------|----------|
| 伪造 LLM 服务响应 | url.py | 恶意数据注入 | TLS 证书验证 |
| 伪造知识库数据 | knowledge.py | 数据完整性破坏 | 数据库权限检查 |

### Tampering (篡改)

| 威胁 | 位置 | 影响 | 防护措施 |
|------|------|------|----------|
| 文件内容篡改 | document/loader/*.py | 解析漏洞利用 | 文件属主检查 |
| SQL/Cypher 注入 | opengauss_storage.py, opengauss_graph.py | 数据库篡改 | ORM 保护 |
| 向量数据篡改 | storage/vectorstore.py | 检索结果污染 | 参数验证 |

### Repudiation (抵赖)

| 威胁 | 位置 | 影响 | 防护措施 |
|------|------|------|----------|
| 操作日志缺失 | 全项目 | 无法追溯攻击 | loguru 日志 |

### Information Disclosure (信息泄露)

| 威胁 | 位置 | 影响 | 防护措施 |
|------|------|------|----------|
| 文件路径泄露 | file_check.py | 敏感路径暴露 | 黑名单限制 |
| 查询内容泄露 | retriever.py | 用户隐私泄露 | 无加密存储 |
| 日志信息泄露 | log/*.cpp | 内部信息暴露 | 日志级别控制 |

### Denial of Service (拒绝服务)

| 威胁 | 位置 | 影响 | 防护措施 |
|------|------|------|----------|
| ZIP Bomb | excel_loader.py | 磁盘耗尽 | _is_zip_bomb() |
| 大文件处理 | pdf_loader.py | 内存耗尽 | MAX_SIZE 限制 |
| 大响应处理 | url.py | 内存耗尽 | response_limit_size |
| 高维向量处理 | vectorstore.py | 内存耗尽 | MAX_VEC_DIM 限制 |

### Elevation of Privilege (权限提升)

| 威胁 | 位置 | 影响 | 防护措施 |
|------|------|------|----------|
| 符号链接攻击 | filesystem.cpp | 读取任意文件 | IsPathValid() |
| 文件权限绕过 | file_check.py | 写入敏感文件 | check_mode() |

## 安全加固建议

### 架构层面

1. **输入验证增强**
   - 扩展文件路径黑名单，覆盖更多敏感路径
   - 对所有用户输入进行统一的白名单验证
   - 添加 MIME 类型验证，防止文件伪装

2. **数据库安全**
   - 完全使用 SQLAlchemy ORM，避免 `text()` 动态 SQL
   - 对 Cypher 查询使用完整参数化
   - 添加数据库访问审计日志

3. **加密存储**
   - 对用户查询内容添加可选加密存储
   - 对知识库数据添加敏感字段加密
   - 使用 `encrypt_fn`/`decrypt_fn` 回调统一加密策略

4. **依赖安全**
   - 定期更新 fitz (PyMuPDF), xlrd, openpyxl 等解析库
   - 扫描依赖库的已知漏洞 (CVE)
   - 使用 safetensors 格式而非 pickle 格式模型

5. **日志审计**
   - 记录所有 API 调用的关键参数
   - 记录文件访问、数据库操作的审计日志
   - 添加异常操作的告警机制

6. **NPU 加速模块安全**
   - C/C++ 代码添加完整的路径验证
   - 避免使用危险的 C 函数 (strcpy, sprintf 等)
   - 添加内存操作边界检查

### 运行时保护

1. **容器部署安全**
   - 使用非 root 用户运行
   - 限制容器文件系统访问
   - 设置资源使用限制 (CPU, 内存)

2. **网络安全**
   - 强制使用 HTTPS 连接 LLM 服务
   - 配置证书双向验证
   - 添加请求速率限制

3. **文件系统安全**
   - 使用独立的数据存储分区
   - 设置文件系统访问权限
   - 定期清理临时文件

## 总结

RAGSDK 作为知识增强开发套件，主要风险集中在文件解析和数据库操作两个攻击面。项目已包含较为完善的安全防护机制（文件路径验证、大小限制、ZIP bomb 检测），但仍存在潜在的注入风险和解析漏洞。建议重点关注以下改进：

1. 增强 SQL/Cypher 查询的参数化处理
2. 完善文件解析库的安全更新机制
3. 扩展输入验证的覆盖范围
4. 添加完整的审计日志功能

=== Architecture 分析完成 ===