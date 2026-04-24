# 漏洞扫描报告 — 待确认漏洞

**项目**: MindSpore
**扫描时间**: 2026-04-23T18:00:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| LIKELY | 10 | 52.6% |
| CONFIRMED | 6 | 31.6% |
| POSSIBLE | 2 | 10.5% |
| FALSE_POSITIVE | 1 | 5.3% |
| **总计** | **19** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 8 | 66.7% |
| Medium | 4 | 33.3% |
| **有效漏洞总计** | **12** | - |
| 误报 (FALSE_POSITIVE) | 1 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-PROTO-001]** unvalidated_input (High) - `mindspore/ccsrc/cluster/rpc/core/collective_ops_impl.cc:149` @ `RunRingAllReduce` | 置信度: 75
2. **[VULN-SEC-DATA-002]** json_injection (High) - `mindspore/ccsrc/minddata/dataset/data_source/coco_op.cc:102` @ `LoadTensorRow` | 置信度: 75
3. **[VULN-DF-NET-002]** improper_input_validation (High) - `mindspore/ccsrc/cluster/rpc/tcp/tcp_socket_operation.cc:26` @ `Receive` | 置信度: 75
4. **[VULN-PY-INJECT-001]** deserialization_untrusted_data (High) - `mindspore/python/mindspore/mint/distributed/distributed.py:2334` @ `broadcast_obj` | 置信度: 75
5. **[VULN-DF-MEM-002]** buffer_overflow (High) - `mindspore/core/load_mindir/load_model.cc:1125` @ `GetTensorDataFromExternal` | 置信度: 70
6. **[VULN-DF-MEM-003]** buffer_overflow (High) - `mindspore/core/load_mindir/load_model.cc:656` @ `GenerateTensorPtrFromTensorProto` | 置信度: 70
7. **[VULN-SEC-AUTH-001]** missing_authentication (High) - `mindspore/ccsrc/cluster/rpc/core/ps_context.cc:51` @ `PSContext` | 置信度: 65
8. **[VULN-SEC-CRYPTO-002]** unauthenticated_encryption (High) - `mindspore/core/utils/crypto.cc:175` @ `InitCipherCtxAES` | 置信度: 65
9. **[VULN-DF-NET-001]** buffer_overflow (Medium) - `mindspore/ccsrc/cluster/rpc/core/collective_ops_impl.cc:195` @ `RunRingAllReduce` | 置信度: 60
10. **[VULN-PY-CODE-001]** code_injection (Medium) - `mindspore/python/mindspore/graph/_parse/parser.py:810` @ `eval_script` | 置信度: 60

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `LoadMindIR@mindspore/core/load_mindir/load_model.cc` | file | untrusted_local | Users load external model files (.mindir) for inference or training. Model files may come from untrusted third parties. Per SECURITY.md: 'Model files are stored in binary mode... malicious code may be written into the model files, the code are loaded and executed.' | Load MindIR model file from disk or buffer. Parses protobuf format and constructs computational graph. |
| `LoadMindIR@mindspore/core/load_mindir/load_model.cc` | file | untrusted_local | Users can load model from memory buffer. Buffer contents may originate from untrusted sources (downloaded model, received from network). | Load MindIR model from memory buffer (for in-memory deserialization). |
| `connect@mindspore/ccsrc/cluster/rpc/tcp/socket_operation.cc` | network | semi_trusted | Distributed training nodes connect to each other. GPU clusters lack authentication per SECURITY.md: 'If GPUs or other clusters are used for training, identity authentication and secure transmission are not provided.' | TCP client connects to remote server for distributed training. |
| `accept4@mindspore/ccsrc/cluster/rpc/tcp/socket_operation.cc` | network | semi_trusted | TCP server accepts connections from other nodes. GPU cluster connections lack authentication. | TCP server accepts incoming connection from distributed training node. |
| `Receive@mindspore/ccsrc/cluster/rpc/tcp/tcp_socket_operation.cc` | network | semi_trusted | Receives data from connected nodes via recv(). Data may include gradients, model parameters, etc. from potentially untrusted nodes. | Receive data from network socket for distributed communication. |
| `AllReduce@mindspore/ccsrc/cluster/rpc/core/collective_ops_impl.cc` | rpc | semi_trusted | Collective operation receives data buffers from other nodes. Uses recvbuff which may contain malicious data in GPU clusters without authentication. | AllReduce collective operation - receives and processes data from all nodes. |
| `TFReaderOp@mindspore/ccsrc/minddata/dataset/data_source/tf_reader_op.cc` | file | untrusted_local | Users load TFRecord files containing training data. Files may come from untrusted sources. | Parse TFRecord format dataset files. |
| `CsvOp@mindspore/ccsrc/minddata/dataset/data_source/csv_op.cc` | file | untrusted_local | Users load CSV files containing dataset. CSV files are user-provided and may contain malicious content. | Parse CSV format dataset files. |
| `MindRecordOp@mindspore/ccsrc/minddata/dataset/data_source/mindrecord_op.cc` | file | untrusted_local | Users load MindRecord format files. MindRecord is a custom binary format that may come from untrusted sources. | Parse MindRecord format dataset files. |
| `CocoOp@mindspore/ccsrc/minddata/dataset/data_source/coco_op.cc` | file | untrusted_local | COCO dataset loader parses JSON annotation files and images. User-provided annotation files may contain malicious JSON. | Parse COCO dataset format (JSON + images). |
| `InitMindSpore@mindspore/ccsrc/pybind_api/init.cc` | decorator | untrusted_local | Python binding entry point. User Python code calls C++ functions through this layer. Per SECURITY.md: 'user-defined computational graph structure... malicious code may exist.' | Python-C++ binding initialization. Exposes C++ APIs to Python users. |
| `import@mindspore/python/mindspore/__init__.py` | stdin | untrusted_local | User imports MindSpore and writes Python code to define neural networks. Malicious Python code may be executed. | Python package entry point. Users write Python code that calls MindSpore APIs. |

**其他攻击面**:
- MindIR Model File Loading: load_model.cc uses protobuf ParseFromArray/ParseFromIstream to deserialize external .mindir files. Malicious model files could trigger deserialization vulnerabilities or cause memory corruption in memcpy_s operations.
- Checkpoint Loading: checkpoint.proto defines serialization format for model weights. Checkpoint files may contain malicious data.
- Distributed Training RPC: cluster/rpc module implements TCP communication. GPU clusters lack authentication. Nodes send/receive gradients and parameters. Malicious nodes could inject malicious data.
- TFRecord Parsing: tf_reader_op.cc parses TensorFlow example format. External TFRecord files may contain malicious serialized examples.
- CSV Parsing: csv_op.cc parses CSV files. CSV parsing may be vulnerable to CSV injection or malformed data.
- MindRecord Parsing: mindrecord_op.cc and mindspore/ccsrc/minddata/mindrecord/ parse custom binary format. Malformed MindRecord files could trigger parsing vulnerabilities.
- COCO JSON Parsing: coco_op.cc parses JSON annotation files. JSON parsing may be vulnerable to malformed JSON attacks.
- Image File Loading: Various image dataset ops (image_folder_op.cc, etc.) load and decode image files. Image decoding libraries may have vulnerabilities.
- Python Code Execution: User Python code defines computational graphs. Per SECURITY.md, malicious code may exist in user-defined network structures.
- Memory Operations: Multiple memcpy_s and huge_memcpy calls in load_model.cc and collective_ops_impl.cc. Buffer overflow potential if size calculations are incorrect.
- Protobuf Deserialization: All protobuf-based formats (mind_ir.proto, checkpoint.proto, comm.proto, etc.) rely on protobuf library. Malformed protobuf messages could trigger parsing vulnerabilities.

---

## 3. High 漏洞 (8)

### [VULN-SEC-PROTO-001] unvalidated_input - RunRingAllReduce

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `mindspore/ccsrc/cluster/rpc/core/collective_ops_impl.cc:149-159` @ `RunRingAllReduce`
**模块**: cluster_rpc

**描述**: Network data from CollectiveReceiveAsync is processed without validation before Memcpy. Received data (rec_ptr) is directly cast and processed. If received data size exceeds expected size, or if data is malformed, this could cause memory corruption or buffer overflow.

**漏洞代码** (`mindspore/ccsrc/cluster/rpc/core/collective_ops_impl.cc:149-159`)

```c
std::shared_ptr<std::vector<unsigned char>> rec_ptr = nullptr;
auto rec_req_id = node_->CollectiveReceiveAsync(node_role_, group_to_global_ranks[recv_from_rank], &rec_ptr);
MS_EXCEPTION_IF_NULL(rec_ptr);
auto tmp_recv_chunk = reinterpret_cast<T *>(rec_ptr->data());
calculate(recv_chunk, tmp_recv_chunk, recv_chunk_count, reduce_op);
```

**达成路径**

Network node sends data → CollectiveReceiveAsync receives → rec_ptr->data() directly cast → calculate() processes without size validation

**验证说明**: CollectiveReceiveAsync接收的网络数据直接reinterpret_cast使用，无大小验证。恶意节点在无认证集群中可发送恶意数据导致内存破坏。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-DATA-002] json_injection - LoadTensorRow

**严重性**: High（原评估: Medium → 验证后: High） | **CWE**: CWE-943 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `mindspore/ccsrc/minddata/dataset/data_source/coco_op.cc:102-168` @ `LoadTensorRow`
**模块**: minddata_dataset

**描述**: COCO dataset loader parses JSON annotation files without strict schema validation. The JSON structure is assumed to follow COCO format but malformed or malicious JSON could cause unexpected behavior or data corruption. Image paths from JSON are directly used without sanitization.

**漏洞代码** (`mindspore/ccsrc/minddata/dataset/data_source/coco_op.cc:102-168`)

```c
std::string image_id = image_ids_[row_id];
Path kImageFile = image_folder / image_id;
RETURN_IF_NOT_OK(ReadImageToTensor(kImageFile.ToString(), &image));
```

**达成路径**

External JSON annotation → Parse structure → Use image_id for file path → No path sanitization → Potential path traversal

**验证说明**: COCO JSON解析后image_id直接用于构建路径，无路径清理。恶意JSON可包含路径遍历字符(../)读取非预期文件。但有GetRealPath验证文件存在性。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-NET-002] improper_input_validation - Receive

**严重性**: High | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mindspore/ccsrc/cluster/rpc/tcp/tcp_socket_operation.cc:26-63` @ `Receive`
**模块**: cluster_rpc

**描述**: recv() receives network data into buffer with size recvLen which is passed as parameter. In distributed training context (GPU clusters without authentication), malicious nodes could send arbitrary data. The received data is then used in subsequent operations without validation.

**漏洞代码** (`mindspore/ccsrc/cluster/rpc/tcp/tcp_socket_operation.cc:26-63`)

```c
ssize_t TCPSocketOperation::ReceivePeek(Connection *connection, char *recvBuf, uint32_t recvLen) {
  return recv(connection->socket_fd, recvBuf, recvLen, MSG_PEEK);
}
...
ssize_t retval = recv(fd, curRecvBuf, totalRecvLen - *recvLen, static_cast<int>(0));
```

**达成路径**

Network socket recv() [SOURCE] → recvBuf → Connection handling → Memcpy operations

**验证说明**: recv()直接从网络接收数据，无内容验证。数据后续用于连接处理和Memcpy操作。在无认证集群中恶意节点可发送任意数据。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-PY-INJECT-001] deserialization_untrusted_data - broadcast_obj

**严重性**: High | **CWE**: CWE-502 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mindspore/python/mindspore/mint/distributed/distributed.py:2334-2336` @ `broadcast_obj`
**模块**: python_api

**描述**: pickle.loads() is used for deserialization in distributed communication. The code explicitly warns 'deserialization can execute arbitrary code, and attackers can trigger system command execution by constructing malicious objects'. In GPU clusters without authentication, malicious nodes could send crafted pickle payloads.

**漏洞代码** (`mindspore/python/mindspore/mint/distributed/distributed.py:2334-2336`)

```c
# WARNING: The fundamental risk of using pickle...
# is that deserialization can execute arbitrary code...
```

**达成路径**

Network receive from distributed node [SOURCE] → pickle data → pickle.loads() [SINK] → arbitrary code execution

**验证说明**: pickle.loads()用于分布式对象传输。代码有明确warning说明风险：反序列化可执行任意代码。在无认证集群中恶意节点可发送恶意pickle payload。用户需自保证安全。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-MEM-002] buffer_overflow - GetTensorDataFromExternal

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-120 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mindspore/core/load_mindir/load_model.cc:1125-1131` @ `GetTensorDataFromExternal`
**模块**: load_mindir

**描述**: huge_memcpy uses offset and length values from protobuf external_data field which comes from external model files. If a malicious model file contains incorrect offset/length values, this could cause out-of-bounds read from the weight buffer or buffer overflow when copying to tensor.

**漏洞代码** (`mindspore/core/load_mindir/load_model.cc:1125-1131`)

```c
auto ret = common::huge_memcpy(tensor_data_buf, tensor_info->DataNBytes(), data + tensor_proto.external_data().offset(), LongToSize(tensor_proto.external_data().length()));
```

**达成路径**

External .mindir file → TensorProto.external_data() [SOURCE] → offset/length from protobuf → huge_memcpy() [SINK]

**验证说明**: huge_memcpy使用protobuf external_data的offset/length，有DataNBytes()边界检查。恶意模型可尝试触发溢出但检查会阻止。错误数据可导致解析失败。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-MEM-003] buffer_overflow - GenerateTensorPtrFromTensorProto

**严重性**: High | **CWE**: CWE-120 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mindspore/core/load_mindir/load_model.cc:656-662` @ `GenerateTensorPtrFromTensorProto`
**模块**: load_mindir

**描述**: memcpy_s copies tensor data from protobuf raw_data field. While memcpy_s is a safe function, the sizes come from protobuf tensor_buf.size() which is from external model file. If protobuf claims a larger size than the allocated tensor buffer (tensor->DataNBytes()), the copy could fail, but data integrity is not validated before copy.

**漏洞代码** (`mindspore/core/load_mindir/load_model.cc:656-662`)

```c
errno_t ret = memcpy_s(tensor_data_buf, tensor->DataNBytes(), tensor_buf.data(), tensor_buf.size());
```

**达成路径**

External .mindir file → TensorProto.raw_data() [SOURCE] → tensor_buf.size() from protobuf → memcpy_s() [SINK]

**验证说明**: memcpy_s有tensor->DataNBytes()vs tensor_buf.size()边界检查。恶意模型文件可提供异常大小但检查会阻止实际溢出。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-AUTH-001] missing_authentication - PSContext

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-306 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `mindspore/ccsrc/cluster/rpc/core/ps_context.cc:51-55` @ `PSContext`
**模块**: cluster_rpc

**描述**: SSL/TLS encryption is OPTIONAL for distributed training. The enable_ssl_ flag defaults to false, meaning network communication between nodes is unencrypted by default. Per SECURITY.md: 'If GPUs or other clusters are used for training, identity authentication and secure transmission are not provided.' This allows man-in-the-middle attacks, data interception, and malicious node injection in GPU clusters.

**漏洞代码** (`mindspore/ccsrc/cluster/rpc/core/ps_context.cc:51-55`)

```c
enable_ssl_(false),
client_password_(),
server_password_(),
```

**达成路径**

User sets enable_ssl=false (default) → TCP connections established without SSL → Data transmitted in plaintext → Network traffic interceptable

**验证说明**: SSL/TLS默认禁用(enable_ssl=false)，GPU集群分布式训练通信未加密。根据SECURITY.md和project_model.json，这是已知的安全缺陷。攻击者可进行MITM攻击拦截梯度数据。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CRYPTO-002] unauthenticated_encryption - InitCipherCtxAES

**严重性**: High | **CWE**: CWE-327 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-auditor

**位置**: `mindspore/core/utils/crypto.cc:175-195` @ `InitCipherCtxAES`
**模块**: core_utils

**描述**: AES-CBC and SM4-CBC encryption modes are supported without authentication tag. CBC mode alone is vulnerable to padding oracle attacks and does not provide integrity verification. An attacker could modify encrypted model files without detection.

**漏洞代码** (`mindspore/core/utils/crypto.cc:175-195`)

```c
} else if (work_mode == "CBC") {
  if (is_encrypt) {
    ret = EVP_EncryptInit_ex(ctx, funcPtr(), nullptr, key, iv);
  } else {
    ret = EVP_DecryptInit_ex(ctx, funcPtr(), nullptr, key, iv);
  }
```

**达成路径**

Model file encrypted with AES-CBC → No authentication tag → Modified ciphertext decrypts to different plaintext → Integrity not verified

**验证说明**: AES-CBC/SM4-CBC无authentication tag，密文可被修改不被检测。但系统也支持AES-GCM(有认证)。用户选择CBC模式时存在padding oracle风险。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (4)

### [VULN-DF-NET-001] buffer_overflow - RunRingAllReduce

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-120 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mindspore/ccsrc/cluster/rpc/core/collective_ops_impl.cc:195-200` @ `RunRingAllReduce`
**模块**: cluster_rpc

**描述**: Memcpy copies data received from network (recv_str->data()) to local buffer (recv_chunk). The size comes from recv_str->size() which is received from remote nodes. In GPU clusters without authentication (per SECURITY.md), malicious nodes could send oversized data causing buffer overflow or memory corruption.

**漏洞代码** (`mindspore/ccsrc/cluster/rpc/core/collective_ops_impl.cc:195-200`)

```c
auto ret = Memcpy(recv_chunk, expect_size, rec_ptr->data(), rec_ptr->size());
```

**达成路径**

Network recv from distributed node [SOURCE] → rec_ptr->size() from network → Memcpy() [SINK]

**验证说明**: Memcpy使用expect_size(本地预期大小)vs rec_ptr->size()检查，有边界检查缓解。但恶意节点仍可发送异常数据触发错误处理。

**评分明细**: base: 30 | reachability: 20 | controllability: 25 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-PY-CODE-001] code_injection - eval_script

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-95 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mindspore/python/mindspore/graph/_parse/parser.py:810-830` @ `eval_script`
**模块**: python_api

**描述**: eval() is used to evaluate expression strings during JIT fallback. While this appears to be for legitimate JIT compilation purposes, the expression string (exp_str) could potentially be controlled through user-defined network structures. Per SECURITY.md: 'malicious code may exist in user-defined computational graph structure'.

**漏洞代码** (`mindspore/python/mindspore/graph/_parse/parser.py:810-830`)

```c
def eval_script(exp_str, params):
  ...
  res = eval(exp_str, global_params, local_params)
```

**达成路径**

User Python code defining network [SOURCE] → exp_str parameter → eval() [SINK]

**验证说明**: eval()用于JIT fallback。根据代码注释，exp_str来源为用户原始Python代码(用户自己保证安全)或内部生成的安全表达式。非外部攻击者可控。代码执行风险由用户承担。

**评分明细**: base: 30 | reachability: 30 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-AUTH-002] missing_authentication - Accept

**严重性**: Medium（原评估: Critical → 验证后: Medium） | **CWE**: CWE-287 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `mindspore/ccsrc/cluster/rpc/tcp/socket_operation.cc:477-513` @ `Accept`
**模块**: cluster_rpc

**描述**: TCP server accepts connections without any authentication or identity verification. The Accept() function accepts incoming connections from any source without validating the connecting node's identity. In GPU clusters, malicious nodes can connect and inject malicious gradients or model parameters.

**漏洞代码** (`mindspore/ccsrc/cluster/rpc/tcp/socket_operation.cc:477-513`)

```c
auto acceptFd =
  ::accept4(sock_fd, reinterpret_cast<struct sockaddr *>(&storage), &length, SOCK_NONBLOCK | SOCK_CLOEXEC);
if (acceptFd < 0) {
  MS_LOG(ERROR) << "Failed to call accept, errno: " << errno << ", server: " << sock_fd;
  return acceptFd;
}
```

**达成路径**

External node connects → Accept() accepts connection without validation → Connection added to cluster → Malicious node can send/receive data

**验证说明**: accept4()接受任意节点连接无身份验证。但攻击者无法控制连接内容(仅能连接)。在启用SSL时可缓解，但默认未启用。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-CRYPTO-001] cleartext_password_storage - set_client_password

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-256 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `mindspore/ccsrc/cluster/rpc/core/ps_context.cc:236-248` @ `set_client_password`
**模块**: cluster_rpc

**描述**: Client and server passwords stored in plaintext char arrays without encryption or hashing. Passwords are copied directly into memory using Memcpy without any cryptographic protection. This exposes credentials to memory dumps or inspection.

**漏洞代码** (`mindspore/ccsrc/cluster/rpc/core/ps_context.cc:236-248`)

```c
char *PSContext::client_password() { return client_password_; }
void PSContext::set_client_password(const char *password) {
  int ret = Memcpy(client_password_, kMaxPasswordLen, password, strlen(password));
```

**达成路径**

User provides password → Memcpy to client_password_ array → Stored in plaintext → Vulnerable to memory inspection

**验证说明**: 密码以明文存储在char数组。攻击者无法直接控制密码内容，但内存泄露可暴露凭证。有memset_s清除机制但存储时无加密。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

## 5. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| cluster_rpc | 0 | 3 | 3 | 0 | 6 |
| core_utils | 0 | 1 | 0 | 0 | 1 |
| load_mindir | 0 | 2 | 0 | 0 | 2 |
| minddata_dataset | 0 | 1 | 0 | 0 | 1 |
| python_api | 0 | 1 | 1 | 0 | 2 |
| **合计** | **0** | **8** | **4** | **0** | **12** |

## 6. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-120 | 3 | 25.0% |
| CWE-20 | 2 | 16.7% |
| CWE-95 | 1 | 8.3% |
| CWE-943 | 1 | 8.3% |
| CWE-502 | 1 | 8.3% |
| CWE-327 | 1 | 8.3% |
| CWE-306 | 1 | 8.3% |
| CWE-287 | 1 | 8.3% |
| CWE-256 | 1 | 8.3% |
