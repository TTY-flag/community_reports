# 漏洞扫描报告 — 待确认漏洞

**项目**: RAGSDK
**扫描时间**: 2026-04-20T12:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 22 | 33.8% |
| POSSIBLE | 20 | 30.8% |
| LIKELY | 14 | 21.5% |
| CONFIRMED | 9 | 13.8% |
| **总计** | **65** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 2 | 6.3% |
| Medium | 23 | 71.9% |
| Low | 4 | 12.5% |
| **有效漏洞总计** | **32** | - |
| 误报 (FALSE_POSITIVE) | 22 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-EMB-001]** ssrf (High) - `mx_rag/embedding/service/tei_embedding.py:49` @ `TEIEmbedding.__init__` | 置信度: 75
2. **[CROSS-MODULE-002]** Cross-Module SSRF Attack Chain (High) - `mx_rag/utils/url.py → mx_rag/llm/text2text.py, mx_rag/embedding/service/tei_embedding.py:49` @ `is_url_valid → RequestUtils.post → LLM.chat/TEIEmbedding.embed` | 置信度: 70
3. **[VULN-SEC-DL-001]** path_blacklist_disabled (Medium) - `mx_rag/utils/file_check.py:49` @ `SecFileCheck.check` | 置信度: 80
4. **[VULN-SEC-GRAPH-002]** cypher_injection (Medium) - `mx_rag/graphrag/graphs/opengauss_graph.py:911` @ `_find_weakly_connected_components` | 置信度: 70
5. **[CROSS-MODULE-005]** Cross-Module Blacklist Bypass Chain (Medium) - `mx_rag/utils/file_check.py → mx_rag/document/loader/*, mx_rag/graphrag/graphrag_pipeline.py:49` @ `SecFileCheck.check → check_path_is_exist_and_valid` | 置信度: 70
6. **[VULN-SEC-DL-002]** symbolic_link_reread (Medium) - `mx_rag/document/loader/pdf_loader.py:112` @ `PdfLoader._parser/_plain_parser` | 置信度: 65
7. **[VULN-SEC-DL-003]** symbolic_link_reread (Medium) - `mx_rag/document/loader/excel_loader.py:310` @ `ExcelLoader._load_xls/_load_xlsx` | 置信度: 65
8. **[VULN-OPS-001]** integer_overflow (Medium) - `ops/operations/plugin_op/utils.cpp:30` @ `GetCopyTensorStride` | 置信度: 65
9. **[VULN-OPS-004]** out_of_bounds_read (Medium) - `ops/operations/plugin_op/aclnn_addmm.cpp:42` @ `AclnnAddmm::InferShape` | 置信度: 65
10. **[VULN-SEC-OPS-003]** size_mismatch (Medium) - `ops/operations/plugin_op/acl_nn_operation_cache.cpp:73` @ `AclNNOpCache::UpdateAclNNVariantPack` | 置信度: 65

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `PdfLoader.__init__@mx_rag/document/loader/pdf_loader.py` | file | untrusted_local | 用户通过 API 调用传入 file_path 参数，该路径指向用户可控制的文件。SDK 作为库被调用方应用使用，调用方应用的用户可能是本地非特权用户。 | PDF 文件加载入口，接收用户提供的文件路径 |
| `ExcelLoader.__init__@mx_rag/document/loader/excel_loader.py` | file | untrusted_local | 用户通过 API 调用传入 file_path 参数，该路径指向用户可控制的文件。Excel 文件包含复杂的解析逻辑，可能存在解析漏洞风险。 | Excel 文件加载入口，接收用户提供的文件路径 |
| `BaseLoader.__init__@mx_rag/document/loader/base_loader.py` | file | untrusted_local | 基类构造函数接收 file_path 参数，所有文档加载器继承此类。文件路径由调用方应用传入，可能来自用户输入。 | 文档加载器基类入口 |
| `RequestUtils.post@mx_rag/utils/url.py` | network | semi_trusted | HTTP POST 请求发送到外部 LLM 服务，URL 由调用方应用配置传入。响应数据来自远程服务，但调用方应用通常控制服务端。 | HTTP 请求入口，用于调用外部 LLM 服务 |
| `OpenGaussDocstore.full_text_search@mx_rag/storage/document_store/opengauss_storage.py` | file | untrusted_local | BM25 全文搜索接收用户提供的 query 参数，该参数用于构建 SQL 查询。虽然使用 SQLAlchemy ORM，但 query 参数直接传入 text() 函数。 | 全文搜索入口，接收用户查询字符串 |
| `KnowledgeStore.__init__@mx_rag/knowledge/knowledge.py` | file | untrusted_local | 知识库存储初始化接收 db_path 参数，由调用方应用传入。SQLite 数据库路径可能来自用户配置。 | 知识库存储入口 |
| `GraphRAGPipeline.__init__@mx_rag/graphrag/graphrag_pipeline.py` | file | untrusted_local | GraphRAG 流程初始化接收 work_dir 参数，用于存储图数据和向量索引。工作目录路径由调用方应用传入。 | GraphRAG 流程入口 |
| `Retriever._get_relevant_documents@mx_rag/retrievers/retriever.py` | file | untrusted_local | 检索器接收用户查询字符串 query 参数，用于向量搜索和文档检索。查询内容可能包含恶意构造。 | 文档检索入口 |
| `EmbeddingFactory.create_embedding@mx_rag/embedding/embedding_factory.py` | decorator | semi_trusted | 工厂方法根据 embedding_type 参数创建 embedding 实例，参数由调用方应用传入。embedding_type 控制实例化哪个类。 | Embedding 工厂入口 |

**其他攻击面**:
- API 文件路径输入: mx_rag/document/loader/*.py - 用户可传入任意文件路径
- HTTP 客户端响应: mx_rag/utils/url.py - 外部 LLM 服务响应数据
- SQL 查询构造: mx_rag/storage/document_store/opengauss_storage.py - BM25 搜索 query 参数
- 模型加载路径: mx_rag/embedding/local/*.py - model_path 参数传入 transformers
- 工作目录路径: mx_rag/graphrag/graphrag_pipeline.py - work_dir 参数
- 知识库数据库路径: mx_rag/knowledge/knowledge.py - db_path 参数
- Cypher 查询构造: mx_rag/graphrag/graphs/opengauss_graph.py - 图数据库查询

---

## 3. High 漏洞 (2)

### [VULN-SEC-EMB-001] ssrf - TEIEmbedding.__init__

**严重性**: High | **CWE**: CWE-918 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `mx_rag/embedding/service/tei_embedding.py:49-145` @ `TEIEmbedding.__init__`
**模块**: embedding
**跨模块**: embedding → utils

**描述**: Server-Side Request Forgery (SSRF) in TEIEmbedding. URL validation via HttpUrlChecker/HttpsUrlChecker only validates URL format but does not block internal IP addresses (127.0.0.1, 10.x.x.x, 172.16-31.x.x, 192.168.x.x) or cloud metadata endpoints (169.254.169.254). In semi_trusted context, if SDK is integrated into web service where URL comes from HTTP request, attacker can access internal services or cloud metadata.

**漏洞代码** (`mx_rag/embedding/service/tei_embedding.py:49-145`)

```c
def __init__(self, url: str, client_param=ClientParam(), embed_mode: str = 'dense'):
    self.url = url.rstrip("/")
    ...
    resp = self.client.post(self.url, json.dumps(request_body), headers=self.headers)
```

**达成路径**

tei_embedding.py:49 TEIEmbedding.__init__(url) [SOURCE - semi_trusted]
↓ url.rstrip("/") → self.url
↓ tei_embedding.py:145 self.client.post(self.url, ...) [SINK]
↓ url.py:111 is_url_valid(url, self.use_http) - format validation only
↓ url.py:116 self.pool.request(method='POST', url=url, ...) [HTTP request to arbitrary destination]

Cross-module: mx_rag/utils/url.py (RequestUtils) + mx_rag/utils/url_checker.py (regex validation without SSRF filtering)

**验证说明**: SSRF vulnerability confirmed. HttpUrlChecker/HttpsUrlChecker only validates URL format (regex matching), does not filter internal IP addresses (127.0.0.1, 10.x.x.x, 172.16-31.x.x, 192.168.x.x) or cloud metadata endpoints (169.254.169.254). In semi_trusted context, if SDK is integrated into web service where URL comes from HTTP request, attacker can probe internal services or steal cloud credentials.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CROSS-MODULE-002] Cross-Module SSRF Attack Chain - is_url_valid → RequestUtils.post → LLM.chat/TEIEmbedding.embed

**严重性**: High | **CWE**: CWE-918 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mx_rag/utils/url.py → mx_rag/llm/text2text.py, mx_rag/embedding/service/tei_embedding.py:49-145` @ `is_url_valid → RequestUtils.post → LLM.chat/TEIEmbedding.embed`
**模块**: cross_module
**跨模块**: utils → llm_client → embedding

**描述**: 完整跨模块 SSRF 链: utils 模块 URL 验证缺陷 → llm_client/embedding 模块 HTTP 请求。URL 验证仅检查格式，不阻止内网 IP 和云元数据端点。所有依赖 RequestUtils 的模块均受影响。

**达成路径**

[SOURCE] utils/url.py:49 is_url_valid(url) → [WEAK: regex only, no IP filter] → [OUT] RequestUtils.post → [SINK] llm/text2text.py:87 pool.request(url) OR tei_embedding.py:145 client.post(url)

**验证说明**: SSRF chain via URL validation bypass. Affects llm_client and embedding modules.

**评分明细**: base: 30 | reachability: 20 | controllability: 20 | mitigations: -5 | context: 0 | cross_file: 5

---

## 4. Medium 漏洞 (23)

### [VULN-SEC-DL-001] path_blacklist_disabled - SecFileCheck.check

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 80/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `mx_rag/utils/file_check.py:49-57` @ `SecFileCheck.check`
**模块**: document_loader
**跨模块**: document_loader → utils

**描述**: SecFileCheck.check() 调用 check_path_is_exist_and_valid() 时默认不启用黑名单检查(check_blacklist=False)，允许访问系统敏感路径如 /etc/, /usr/bin/, /sys/, /dev/ 等。黑名单保护机制在所有文档加载器中均被绕过。

**漏洞代码** (`mx_rag/utils/file_check.py:49-57`)

```c
def check(self):
    FileCheck.check_path_is_exist_and_valid(self.file_path)
    # check_blacklist 默认为 False，黑名单检查被禁用
```

**达成路径**

pdf_loader.py:53 PdfLoader.__init__ [SOURCE]
  → base_loader.py:50 SecFileCheck.check() [检查点]
  → file_check.py:49 check() [黑名单检查禁用]
  → pdf_loader.py:112 fitz.open(self.file_path) [SINK]

excel_loader.py:43 ExcelLoader.__init__ [SOURCE]
  → base_loader.py:50 SecFileCheck.check()
  → excel_loader.py:310 xlrd.open_workbook() [SINK]
  → excel_loader.py:341 load_workbook() [SINK]

**验证说明**: Blacklist disabled by default in SecFileCheck.check(). System paths accessible.

---

### [VULN-SEC-GRAPH-002] cypher_injection - _find_weakly_connected_components

**严重性**: Medium | **CWE**: CWE-943 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `mx_rag/graphrag/graphs/opengauss_graph.py:911-928` @ `_find_weakly_connected_components`
**模块**: graphrag
**跨模块**: graphrag → document_loader

**描述**: Potential Cypher injection via unsanitized node labels in _find_weakly_connected_components. The method retrieves node 'text' values and uses them directly in query without validation. Node text originates from LLM-generated content via graph_merger.py, which could contain malicious payloads designed to manipulate Cypher queries.

**漏洞代码** (`mx_rag/graphrag/graphs/opengauss_graph.py:911-928`)

```c
all_nodes = list(dict.fromkeys(self.get_nodes(with_data=False)))
visited = set()
components = []
for node in all_nodes:
    if node in visited:
        continue
    query = (f"MATCH (start:Node {{id: \"{node}\"}}) " ...)
```

**达成路径**

[Source: LLM responses via graph_merger.py]
→ merge_relations_into_graph [graph_merger.py:270] → graph.add_node(raw_text)
→ [Stored in database with text field]
→ get_nodes(with_data=False) [opengauss_graph.py:911]
→ _find_weakly_connected_components query [SINK]

**验证说明**: Cypher injection via LLM-generated node text in get_nodes().

**评分明细**: base: 30 | reachability: 30 | controllability: 20 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CROSS-MODULE-005] Cross-Module Blacklist Bypass Chain - SecFileCheck.check → check_path_is_exist_and_valid

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mx_rag/utils/file_check.py → mx_rag/document/loader/*, mx_rag/graphrag/graphrag_pipeline.py:49-57` @ `SecFileCheck.check → check_path_is_exist_and_valid`
**模块**: cross_module
**跨模块**: utils → document_loader → graphrag → knowledge → embedding

**描述**: 完整跨模块黑名单绕过链: utils FileCheck 黑名单默认禁用 → 所有使用 SecFileCheck 的模块。check_blacklist=False 是默认值，允许访问敏感系统路径。

**达成路径**

[SOURCE] file_check.py:49 SecFileCheck.check() → check_path_is_exist_and_valid(check_blacklist=False) → [WEAK] → 所有文档加载器、GraphRAG、knowledge 模块的文件操作

**验证说明**: Blacklist bypass chain affecting all file loading modules.

---

### [VULN-SEC-DL-002] symbolic_link_reread - PdfLoader._parser/_plain_parser

**严重性**: Medium | **CWE**: CWE-59 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `mx_rag/document/loader/pdf_loader.py:112-143` @ `PdfLoader._parser/_plain_parser`
**模块**: document_loader

**描述**: SecFileCheck 检查后使用 fitz.open() 再次打开文件，存在时间窗口(Time-of-Check to Time-of-Use)攻击风险。攻击者可能在检查通过后替换文件内容或符号链接目标。

**漏洞代码** (`mx_rag/document/loader/pdf_loader.py:112-143`)

```c
# _parser() 行112
with fitz.open(self.file_path) as pdf_document:

# _plain_parser() 行143
pdf_document = fitz.open(self.file_path)
```

**达成路径**

pdf_loader.py:53 PdfLoader.__init__ [SOURCE]
  → pdf_loader.py:202 SecFileCheck.check() [TOCTOU 检查点1]
  → pdf_loader.py:112 fitz.open() [TOCTOU 使用点]
  → 时间窗口内文件可被替换

**验证说明**: TOCTOU race condition between SecFileCheck and fitz.open(). Window exists but exploit complexity high.

---

### [VULN-SEC-DL-003] symbolic_link_reread - ExcelLoader._load_xls/_load_xlsx

**严重性**: Medium | **CWE**: CWE-59 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `mx_rag/document/loader/excel_loader.py:310-341` @ `ExcelLoader._load_xls/_load_xlsx`
**模块**: document_loader

**描述**: SecFileCheck 检查后使用 xlrd.open_workbook() 和 load_workbook() 再次打开文件，存在 TOCTOU 时间窗口攻击风险。

**漏洞代码** (`mx_rag/document/loader/excel_loader.py:310-341`)

```c
# _load_xls() 行310
wb = xlrd.open_workbook(self.file_path, formatting_info=True)

# _load_xlsx() 行341
wb = load_workbook(self.file_path, data_only=True, keep_links=False)
```

**达成路径**

excel_loader.py:43 ExcelLoader.__init__ [SOURCE]
  → base_loader.py:50 SecFileCheck.check() [TOCTOU 检查点]
  → excel_loader.py:310 xlrd.open_workbook() [TOCTOU 使用点]
  → excel_loader.py:341 load_workbook() [TOCTOU 使用点]

**验证说明**: TOCTOU in Excel loader. Same pattern as PDF loader.

---

### [VULN-OPS-001] integer_overflow - GetCopyTensorStride

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ops/operations/plugin_op/utils.cpp:30-32` @ `GetCopyTensorStride`
**模块**: ops_operations

**描述**: Stride calculation in GetCopyTensorStride() uses multiplication of tensor dimensions which could overflow for large tensors. The multiplication tmpStrides[i] = tensorDims.dims[i + 1] * tmpStrides[i + 1] could result in integer overflow if dimensions are very large, leading to incorrect stride values and potential memory corruption.

**漏洞代码** (`ops/operations/plugin_op/utils.cpp:30-32`)

```c
tmpStrides[i] = tensorDims.dims[i + 1] * tmpStrides[i + 1];
```

**达成路径**

utils.cpp:27 GetCopyTensorStride(tensorDims) [SOURCE]
  → utils.cpp:31 tmpStrides[i] = dims[i+1] * tmpStrides[i+1] [POTENTIAL OVERFLOW]
  → [OUT] aclnn_addmm.cpp:90 aclCreateTensor(...strides...) [SINK]

**验证说明**: GetCopyTensorStride() multiplies tensor dimensions without overflow bounds checking. Tensor dimensions from external input flow through stride calculation to aclCreateTensor. Attack surface: malformed tensor descriptors could trigger overflow. No mitigation found.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-OPS-004] out_of_bounds_read - AclnnAddmm::InferShape

**严重性**: Medium | **CWE**: CWE-125 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `ops/operations/plugin_op/aclnn_addmm.cpp:42-46` @ `AclnnAddmm::InferShape`
**模块**: ops_operations

**描述**: InferShape accesses tensor descriptors without bounds checking.

**漏洞代码** (`ops/operations/plugin_op/aclnn_addmm.cpp:42-46`)

```c
inTensorDescs.at(DIM1).shape.dims[DIM1];
```

**达成路径**

aclnn_addmm.cpp:46 [POTENTIAL OOB]

**验证说明**: InferShape accesses dims[DIM1] without checking shape.dimNum >= 2. If tensor has fewer than 2 dimensions, this reads uninitialized memory (CWE-125). .at() provides bounds check for vector but not for dims array. Attack surface: malformed input tensor with dimNum < 2.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-OPS-003] size_mismatch - AclNNOpCache::UpdateAclNNVariantPack

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `ops/operations/plugin_op/acl_nn_operation_cache.cpp:73-95` @ `AclNNOpCache::UpdateAclNNVariantPack`
**模块**: ops_operations
**跨模块**: ops_operations → ops_adapter

**描述**: UpdateAclNNVariantPack loops based on internal aclnnVariantPack size (aclInTensors.size()) but accesses external variantPack.inTensors.at(i). If variantPack has fewer tensors than cache expects, .at() throws uncaught exception causing crash.

**漏洞代码** (`ops/operations/plugin_op/acl_nn_operation_cache.cpp:73-95`)

```c
for (size_t i = 0; i < this->aclnnVariantPack.aclInTensors.size(); ++i) {
    this->aclnnVariantPack.aclInTensors[i]->atbTensor = variantPack.inTensors.at(i);
```

**达成路径**

Internal cache tensor count → loop iteration → external variantPack.inTensors.at(i) → potential exception

**验证说明**: UpdateAclNNVariantPack loops using internal aclInTensors.size() but accesses external variantPack.inTensors.at(i). Size mismatch causes std::out_of_range exception leading to crash. Attack surface: caller provides variantPack with fewer tensors than cache expects.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-OPS-004] size_mismatch - AclnnAddmm::InferShape

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `ops/operations/plugin_op/aclnn_addmm.cpp:42-46` @ `AclnnAddmm::InferShape`
**模块**: ops_operations
**跨模块**: ops_operations → ops_adapter

**描述**: InferShape functions access outTensorDescs.at(0) and iterate input dimensions without validating that inTensorDescs has sufficient elements. If called with empty or insufficient input tensor descriptors, .at() throws uncaught exception.

**漏洞代码** (`ops/operations/plugin_op/aclnn_addmm.cpp:42-46`)

```c
outTensorDescs.at(DIM0).format = inTensorDescs.at(DIM0).format;
outTensorDescs.at(DIM0).dtype = inTensorDescs.at(DIM0).dtype;
```

**达成路径**

External inTensorDescs parameter → at(DIM0) access → potential out_of_range exception

**验证说明**: InferShape accesses inTensorDescs.at(DIM0/DIM1) without validating vector size. If inTensorDescs has fewer than 2 elements, .at() throws std::out_of_range causing crash. Same vulnerability as VULN-OPS-004 but reported separately by security scanner.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-OPS-005] integer_overflow - GetCopyTensorStride

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `ops/operations/plugin_op/utils.cpp:27-34` @ `GetCopyTensorStride`
**模块**: ops_operations

**描述**: GetCopyTensorStride multiplies tensor dimension values to compute strides without overflow bounds checking. For tensors with large dimensions (e.g., batch=1M, seq=8K), stride multiplication could overflow int64_t leading to incorrect memory offsets.

**漏洞代码** (`ops/operations/plugin_op/utils.cpp:27-34`)

```c
for (int64_t i = static_cast<int64_t>(tensorDims.dimNum) - 2; i >= 0; i--) {
    tmpStrides[i] = tensorDims.dims[i + 1] * tmpStrides[i + 1];
```

**达成路径**

tensorDims.dims[] from external tensor → multiplication chain → potential overflow → stride values

**验证说明**: Same as VULN-OPS-001: GetCopyTensorStride multiplies dimensions without overflow checking. For large tensors, stride calculation could overflow int64_t. Duplicate detection from security scanner.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-OPS-006] size_mismatch - AclnnAddmm::CreateAclNNInTensorVariantPack

**严重性**: Medium | **CWE**: CWE-129 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `ops/operations/plugin_op/aclnn_addmm.cpp:78-106` @ `AclnnAddmm::CreateAclNNInTensorVariantPack`
**模块**: ops_operations
**跨模块**: ops_operations → ops_adapter

**描述**: CreateAclNNInTensorVariantPack resizes vector to GetInputNum() then loops accessing variantPack.inTensors.at(i). If variantPack contains fewer tensors than GetInputNum() expects, .at() throws exception not caught by caller.

**漏洞代码** (`ops/operations/plugin_op/aclnn_addmm.cpp:78-106`)

```c
aclnnVariantPack.aclInTensors.resize(GetInputNum());
for (size_t i = 0; i < aclnnVariantPack.aclInTensors.size(); ++i) {
    aclnnTensor->atbTensor = variantPack.inTensors.at(i);
```

**达成路径**

GetInputNum() (hardcoded DIM3) → resize → variantPack.inTensors.at(i) → potential exception

**验证说明**: CreateAclNNInTensorVariantPack resizes to GetInputNum() (hardcoded 3) then accesses variantPack.inTensors.at(i). If variantPack has fewer than 3 tensors, exception thrown. Attack surface: caller provides insufficient input tensors.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-STV-001] sql_injection_pattern - _drop_each_indexes

**严重性**: Medium | **CWE**: CWE-89 | **置信度**: 65/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `mx_rag/storage/vectorstore/opengauss.py:262-272` @ `_drop_each_indexes`
**模块**: storage_vectorstore

**描述**: SQL injection pattern using f-string interpolation in index deletion. While mitigated by isidentifier() validation, the pattern text(f"DROP INDEX IF EXISTS {index_name} CASCADE") is a risky code smell that could be exploited if the pg_indexes metadata source is compromised.

**漏洞代码** (`mx_rag/storage/vectorstore/opengauss.py:262-272`)

```c
for idx in indexes:
    index_name = idx[0]
    if index_name.isidentifier():
        session.execute(text(f"DROP INDEX IF EXISTS {index_name} CASCADE"))
    else:
        raise ValueError(f"Invalid index name: '{index_name}'")
```

**达成路径**

pg_indexes query → index_name validation → f-string SQL execution

**验证说明**: f-string SQL pattern. isidentifier() validation mitigates injection.

---

### [vuln-graphrag-004] callback-risk - build_graph

**严重性**: Medium | **CWE**: CWE-749 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `mx_rag/graphrag/graphs/graphrag_pipeline.py:189` @ `build_graph`
**模块**: graphrag

**描述**: User-provided encrypt_fn/decrypt_fn callbacks are executed without sandboxing. While run_and_check_callback validates return type and length, the callback function itself could perform malicious operations if attacker controls the callback.

**漏洞代码** (`mx_rag/graphrag/graphs/graphrag_pipeline.py:189`)

```c
write_to_json(self.relations_save_path, relations, self.encrypt_fn)
```

**达成路径**

encrypt_fn[IN, user callback] -> run_and_check_callback[validated type/length] -> file write[OUT]

**验证说明**: Callback risk. POSSIBLE via scanner confidence 40. Type validation exists.

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-OPS-001] memory_leak - AclnnAddmm class

**严重性**: Medium | **CWE**: CWE-401 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `ops/operations/plugin_op/aclnn_addmm.h:47-48` @ `AclnnAddmm class`
**模块**: ops_operations

**描述**: aclScalar objects created via aclCreateScalar() in class member initialization but never explicitly destroyed via aclDestroyScalar(). Resource leak on repeated instantiation.

**漏洞代码** (`ops/operations/plugin_op/aclnn_addmm.h:47-48`)

```c
aclScalar* alpha = aclCreateScalar(&alphaValue, ACL_BOOL);
    aclScalar* beta = aclCreateScalar(&betaValue, ACL_BOOL);
```

**达成路径**

aclCreateScalar() allocates ACL resource at class definition → No corresponding aclDestroyScalar() in destructor or DestroyOperation()

**验证说明**: aclScalar* alpha/beta created via aclCreateScalar() in class member initialization but never destroyed. Destructor ~AclnnAddmm() is empty, no aclDestroyScalar() calls. ACL resources leak on repeated instantiation. Each AclnnAddmm instance leaks 2 aclScalar handles.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [vuln-graphrag-001] cypher-injection - update_node_attributes_batch

**严重性**: Medium | **CWE**: CWE-89 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mx_rag/graphrag/graphs/opengauss_graph.py:279-284` @ `update_node_attributes_batch`
**模块**: graphrag

**描述**: Potential Cypher query injection in batch update methods: update_node_attributes_batch and update_edge_attributes_batch use json.dumps() instead of cypher_value() for value encoding. While node IDs are hashed with SHA256, attribute values bypass the dedicated Cypher escaping function. Cypher-specific characters like single quotes may not be properly escaped.

**漏洞代码** (`mx_rag/graphrag/graphs/opengauss_graph.py:279-284`)

```c
query = f"UNWIND {cypher_list} AS item MATCH (n:Node) WHERE n.id = item.id SET {set_clause}"
```

**达成路径**

work_dir[IN] -> graph_name[validated] -> relations[LLM-derived] -> attributes[user+LLM] -> json.dumps(attributes) -> Cypher query

**验证说明**: Cypher injection pattern. POSSIBLE via scanner confidence 60.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [vuln-graphrag-002] cypher-injection - update_edge_attributes_batch

**严重性**: Medium | **CWE**: CWE-89 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mx_rag/graphrag/graphs/opengauss_graph.py:356-366` @ `update_edge_attributes_batch`
**模块**: graphrag

**描述**: Similar Cypher injection risk in update_edge_attributes_batch: uses json.dumps() for edge attribute values instead of cypher_value(). Edge source/target IDs are hashed, but attribute values could contain unescaped Cypher characters.

**漏洞代码** (`mx_rag/graphrag/graphs/opengauss_graph.py:356-366`)

```c
query = f"UNWIND {cypher_list} AS item MATCH (a:Node)-[r]->(b:Node) WHERE a.id = item.start_id AND b.id = item.end_id SET {set_clause}"
```

**达成路径**

relations[LLM-derived] -> edge_updates[user] -> json.dumps(values) -> Cypher query

**验证说明**: Cypher injection pattern. POSSIBLE via scanner confidence 60.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [OPS-MODELS-001] path_traversal_bypass - FileSystem::IsPathValid

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ops/models/src/utils/filesystem.cpp:136-179` @ `FileSystem::IsPathValid`
**模块**: ops_models

**描述**: IsPathValid function can be bypassed via TOCTOU race condition. When lstat fails (line 145), the function returns TRUE (valid), allowing an attacker to create a symlink after validation but before use. Additionally, the path validation only checks if existing path components are symlinks, but does not prevent creation of symlinks in the path after validation passes.

**漏洞代码** (`ops/models/src/utils/filesystem.cpp:136-179`)

```c
if (lstat(path.c_str(), &buf) == -1) { return true; }
```

**达成路径**

External Input → IsPathValid() [VALIDATION_BYPASS] → ReadFile() [SINK]

**验证说明**: IsPathValid 存在 TOCTOU 窗口（lstat 失败返回 true），但 IsOwnerSame 检查会在路径不存在时阻止攻击。实际利用需攻击者替换自己拥有的文件为 symlink，仅造成信息泄露而非特权提升。利用难度高，属设计缺陷而非严重漏洞。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [OPS-MODELS-005] missing_path_validation - FileSystem::DeleteFile/Rename/MakeDir/Makedirs

**严重性**: Medium | **CWE**: CWE-73 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ops/models/src/utils/filesystem.cpp:197-226` @ `FileSystem::DeleteFile/Rename/MakeDir/Makedirs`
**模块**: ops_models

**描述**: DeleteFile, Rename, MakeDir, Makedirs functions do not call IsPathValid before performing file system operations. These functions accept arbitrary paths without any validation, allowing path traversal attacks.

**漏洞代码** (`ops/models/src/utils/filesystem.cpp:197-226`)

```c
void FileSystem::DeleteFile(const std::string &filePath) { remove(filePath.c_str()); }
```

**达成路径**

External path input → DeleteFile/Rename/MakeDir/Makedirs [SINK, NO_VALIDATION]

**验证说明**: DeleteFile/Rename/MakeDir/Makedirs 不调用 IsPathValid，参数可被外部传入。但当前代码中这些函数仅在内部使用（无外部调用点）。漏洞真实存在但当前无攻击路径，作为公共 API 存在潜在风险。

**评分明细**: base: 30 | reachability: 5 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: -10

---

### [OPS-MODELS-006] directory_traversal - FileSystem::GetDirChildItemsImpl

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ops/models/src/utils/filesystem.cpp:228-255` @ `FileSystem::GetDirChildItemsImpl`
**模块**: ops_models

**描述**: GetDirChildItemsImpl does not validate the dirPath parameter for path traversal. An attacker could provide paths like "../../../etc" to enumerate sensitive directories.

**漏洞代码** (`ops/models/src/utils/filesystem.cpp:228-255`)

```c
DIR *dirHandle = opendir(dirPath.c_str());
```

**达成路径**

External dirPath → GetDirChildItems/Files/Dirs → GetDirChildItemsImpl → opendir() [SINK]

**验证说明**: GetDirChildItemsImpl 不验证 dirPath，理论上可通过 Python API 传入 ../../../etc 等风险路径。但当前无实际外部调用证据。作为公共 API 存在潜在路径遍历风险。

**评分明细**: base: 30 | reachability: 5 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: -10

---

### [VULN-OPS-002] race_condition - ExecutorManager::IncreaseReference

**严重性**: Medium | **CWE**: CWE-362 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ops/operations/plugin_op/executor_manager.cpp:26-40` @ `ExecutorManager::IncreaseReference`
**模块**: ops_operations
**跨模块**: ops_operations,executor

**描述**: ExecutorManager uses std::map without mutex protection for reference counting operations. Multiple threads calling IncreaseReference/DecreaseReference concurrently could cause race conditions leading to incorrect reference counts, use-after-free, or memory corruption. The singleton pattern itself is thread-safe (C++11 static), but ExecutorManager class operations are not.

**漏洞代码** (`ops/operations/plugin_op/executor_manager.cpp:26-40`)

```c
std::map<aclOpExecutor *, int>::iterator it = this->executorCount_.find(executor);
```

**达成路径**

executor_manager.cpp:26 IncreaseReference() [NO MUTEX] -> [OUT] executor_manager.cpp:31 executorCount_[executor] = 1 [CONCURRENT WRITE]

**验证说明**: ExecutorManager uses std::map without mutex protection. In multi-threaded inference scenarios, concurrent IncreaseReference/DecreaseReference could cause race conditions. However, attack controllability is low - attacker cannot directly trigger race. Singleton pattern is thread-safe for creation but operations are not.

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: -15 | cross_file: 0

---

### [VULN-SEC-EMB-002] path_traversal - TextEmbedding.__init__

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `mx_rag/embedding/local/text_embedding.py:57-68` @ `TextEmbedding.__init__`
**模块**: embedding
**跨模块**: embedding → utils

**描述**: Model path blacklist bypass in TextEmbedding. SecDirCheck validates path (blocks '..' traversal, requires absolute path, checks owner/permissions) but does NOT enforce the BLACKLIST_PATH (/etc/, /usr/bin/, /tmp, etc.) by default. User could load models from sensitive directories if they own the files. Mitigated by owner check (files must be owned by current user) and permission check (≤0o755). In semi_trusted context with owner enforcement, risk is reduced.

**漏洞代码** (`mx_rag/embedding/local/text_embedding.py:57-68`)

```c
def __init__(self, model_path: str, ...):
    self.model_path = model_path
    SecDirCheck(self.model_path, 10 * GB).check()  # blacklist not enforced
    safetensors_check(model_path)
    self.tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True, use_safetensors=True)
    self.model = AutoModel.from_pretrained(model_path, local_files_only=True)
```

**达成路径**

text_embedding.py:57 TextEmbedding.__init__(model_path) [SOURCE - semi_trusted]
↓ text_embedding.py:64 SecDirCheck(model_path, 10*GB).check()
↓ file_check.py:81-87 _recursive_listdir → FileCheck.dir_check(path)
↓ file_check.py:172 check_input_path_valid(path, True) → check_blacklist=False [MISSING]
↓ text_embedding.py:67-68 AutoModel.from_pretrained(model_path) [SINK - model loading]

Cross-module: mx_rag/utils/file_check.py (SecDirCheck - blacklist NOT enforced)
Mitigations: local_files_only=True, use_safetensors=True, owner check, permission check ≤0o755

**验证说明**: BLACKLIST_PATH (/etc/, /usr/bin/, /tmp, etc.) not enforced by default in SecDirCheck. check_input_path_valid() has check_blacklist=False parameter, allowing model loading from sensitive directories. However, strong mitigations exist: owner check (files must belong to current user), permission check (≤0o755), path traversal '..' blocked, absolute path required. Attack requires creating malicious model files in sensitive directories and satisfying owner/permission constraints.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: -5

---

### [VULN-SEC-EMB-003] path_traversal - ImageEmbedding.__init__

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `mx_rag/embedding/local/img_embedding.py:79-85` @ `ImageEmbedding.__init__`
**模块**: embedding
**跨模块**: embedding → utils

**描述**: Same path blacklist bypass in ImageEmbedding. SecDirCheck and SecFileCheck used but blacklist not enforced. Same mitigations apply (owner/permission checks).

**漏洞代码** (`mx_rag/embedding/local/img_embedding.py:79-85`)

```c
def __init__(self, model_name: str, model_path: str, dev_id: int = 0):
    SecDirCheck(self.model_path, 10 * GB).check()  # blacklist not enforced
    safetensors_check(model_path)
    SecFileCheck(os.path.join(self.model_path, checkpoint), 10 * GB).check()
```

**达成路径**

img_embedding.py:79 ImageEmbedding.__init__(model_path) [SOURCE - semi_trusted]
↓ img_embedding.py:82 SecDirCheck(model_path).check() → blacklist not enforced
↓ img_embedding.py:85 SecFileCheck(checkpoint_path).check()
↓ file_check.py:49-57 SecFileCheck.check() → check_path_is_exist_and_valid → check_blacklist=False

Cross-module: mx_rag/utils/file_check.py
Mitigations: owner check, permission check ≤0o755, size limit 10GB

**验证说明**: Same BLACKLIST_PATH bypass as VULN-SEC-EMB-002. SecDirCheck and SecFileCheck used but blacklist not enforced by default. Same mitigations apply: owner check, permission check ≤0o755, size limit 10GB.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -20 | context: 0 | cross_file: -5

---

### [VULN-SEC-EMB-004] path_traversal - SparseEmbedding.__init__

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `mx_rag/embedding/local/sparse_embedding.py:52-78` @ `SparseEmbedding.__init__`
**模块**: embedding
**跨模块**: embedding → utils

**描述**: Same path blacklist bypass in SparseEmbedding. SecDirCheck used but blacklist not enforced. Additional risk: torch.load at line 77, but weights_only=True mitigates deserialization risk (CWE-502).

**漏洞代码** (`mx_rag/embedding/local/sparse_embedding.py:52-78`)

```c
def __init__(self, model_path: str, ...):
    SecDirCheck(self.model_path, 10 * GB).check()  # blacklist not enforced
    ...
    sparse_state_dict = torch.load(sparse_model_path, ..., weights_only=True)  # CWE-502 mitigated
```

**达成路径**

sparse_embedding.py:52 SparseEmbedding.__init__(model_path) [SOURCE - semi_trusted]
↓ sparse_embedding.py:57 SecDirCheck(model_path).check() → blacklist not enforced
↓ sparse_embedding.py:77 torch.load(sparse_model_path, weights_only=True) [CWE-502 MITIGATED]

Cross-module: mx_rag/utils/file_check.py
Mitigations: owner check, permission check, weights_only=True for torch.load

**验证说明**: Same BLACKLIST_PATH bypass as VULN-SEC-EMB-002. SecDirCheck used but blacklist not enforced. Additional mitigation: torch.load with weights_only=True prevents CWE-502 deserialization attack.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -25 | context: 0 | cross_file: -5

---

## 5. Low 漏洞 (4)

### [VULN-OPS-005] exception_resource_leak - GeluOperation::CreateAclNNVariantPack

**严重性**: Low | **CWE**: CWE-401 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ops/operations/plugin_op/aclnn_gelu_operation.cpp:88-96` @ `GeluOperation::CreateAclNNVariantPack`
**模块**: ops_operations

**描述**: GeluOperation throws runtime_error without cleanup of allocated tensors.

**漏洞代码** (`ops/operations/plugin_op/aclnn_gelu_operation.cpp:88-96`)

```c
throw std::runtime_error(ss.str());
```

**达成路径**

Exception thrown without cleanup

**验证说明**: CreateAclNNVariantPack throws runtime_error after partial tensor creation. If CreateAclNNInTensorVariantPack succeeds but CreateAclNNOutTensorVariantPack fails, InTensors are created but exception prevents executor creation. Destory() returns early if aclExecutor is null, leaving tensors unreleased. Limited impact: RAII destructor eventually called but may not clean partial state.

**评分明细**: base: 30 | reachability: 5 | controllability: 10 | mitigations: 0 | context: -15 | cross_file: 0

---

### [vuln-graphrag-005] llm-output-taint - query

**严重性**: Low | **CWE**: CWE-915 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mx_rag/graphrag/relation_extraction.py:207-245` @ `query`
**模块**: graphrag
**跨模块**: graphrag, llm

**描述**: LLM-generated JSON output flows directly into graph construction without strict content validation. Malformed or maliciously crafted LLM responses could inject unexpected data into relations, potentially affecting downstream Cypher queries.

**漏洞代码** (`mx_rag/graphrag/relation_extraction.py:207-245`)

```c
relations.append(_parse_and_repair_json(llm, text, "", repair_function, True, True))
```

**达成路径**

docs[IN, user files] -> LLM.chat[OUT, untrusted] -> json.loads[partial validation] -> relations[flows to graph] -> Cypher queries

**验证说明**: LLM output taint. POSSIBLE via scanner confidence 50.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [OPS-MODELS-002] buffer_overread - FileSystem::ReadFile

**严重性**: Low | **CWE**: CWE-125 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ops/models/src/utils/filesystem.cpp:182-195` @ `FileSystem::ReadFile`
**模块**: ops_models

**描述**: ReadFile function does not verify actual file size against bufferSize. If the file is larger than bufferSize, ifstream.read() will read exactly bufferSize bytes but the caller cannot determine if the read was complete or truncated. No null-termination is guaranteed. Buffer pointer is not validated for null.

**漏洞代码** (`ops/models/src/utils/filesystem.cpp:182-195`)

```c
fd.read(buffer, bufferSize); return true;
```

**达成路径**

ReadFile(filePath, buffer, bufferSize) [SOURCE] → fd.read(buffer, bufferSize) [SINK, potential out-of-bounds read if file > bufferSize]

**验证说明**: ReadFile 不返回实际读取字节数，调用者无法判断截断。buffer 无 null 指针检查。属 API 设计缺陷而非安全漏洞，需调用者配合不当使用才能触发。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: -15 | cross_file: 0

---

### [OPS-MODELS-007] path_validation_order_flaw - LogSinkFile::LogImpl

**严重性**: Low | **CWE**: CWE-362 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ops/models/src/log/log_sink_file.cpp:68-112` @ `LogSinkFile::LogImpl`
**模块**: ops_models

**描述**: In LogSinkFile::LogImpl, IsPathValid check occurs AFTER files have already been created and written. The validation at line 92 only happens during file rotation, not during initial file creation. This is a race condition (TOCTOU) vulnerability.

**漏洞代码** (`ops/models/src/log/log_sink_file.cpp:68-112`)

```c
if (!FileSystem::IsPathValid(fileDir_)) { return; } // AFTER file already opened
```

**达成路径**

LogImpl → fileHandle_.open() [FIRST_OPEN] → IsPathValid check [TOO_LATE]

**验证说明**: IsPathValid 在文件轮换时才检查（第92行），而非初始创建时。检查时机错误但 fileDir_ 是硬编码值，无外部可控性。无实际攻击向量。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: 0 | context: -20 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cross_module | 0 | 1 | 1 | 0 | 2 |
| document_loader | 0 | 0 | 3 | 0 | 3 |
| embedding | 0 | 1 | 3 | 0 | 4 |
| graphrag | 0 | 0 | 4 | 1 | 5 |
| mx_rag/utils | 0 | 0 | 0 | 0 | 0 |
| ops_models | 0 | 0 | 3 | 2 | 5 |
| ops_operations | 0 | 0 | 8 | 1 | 9 |
| storage_vectorstore | 0 | 0 | 1 | 0 | 1 |
| **合计** | **0** | **2** | **23** | **4** | **29** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-22 | 8 | 25.0% |
| CWE-89 | 3 | 9.4% |
| CWE-129 | 3 | 9.4% |
| CWE-918 | 2 | 6.3% |
| CWE-59 | 2 | 6.3% |
| CWE-401 | 2 | 6.3% |
| CWE-362 | 2 | 6.3% |
| CWE-190 | 2 | 6.3% |
| CWE-125 | 2 | 6.3% |
| CWE-943 | 1 | 3.1% |
| CWE-915 | 1 | 3.1% |
| CWE-749 | 1 | 3.1% |
| CWE-73 | 1 | 3.1% |
| CWE-295 | 1 | 3.1% |
| CWE-117 | 1 | 3.1% |
