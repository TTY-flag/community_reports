# VULN-SEC-MODEL-001: Missing Integrity Check in MindIR Model Loading

## Executive Summary

**Severity:** Critical  
**CWE:** CWE-354 (Improper Validation of Integrity Check Value)  
**Confidence:** 85%  
**Status:** Confirmed Vulnerability  

MindIR model files are deserialized without cryptographic signature verification, allowing malicious model files to be loaded and executed. This vulnerability is explicitly acknowledged in the project's SECURITY.md documentation.

---

## 1. Vulnerability Details

### 1.1 Affected Code Location

**Primary File:** `/mindspore/core/load_mindir/load_model.cc`

**Affected Functions:**

| Function | Line Range | Description |
|----------|------------|-------------|
| `LoadMindIR(const void *buffer, const size_t &size)` | 3000-3018 | Direct buffer deserialization without integrity check |
| `LoadMindIR(const void *buffer, const size_t &size, const std::string &mindir_path, FuncGraphPtr *func_graph, std::string *user_info_string)` | 3098-3127 | Buffer deserialization variant |
| `LoadMindIR(const void *buffer, const size_t &size, const std::string &mindir_path)` | 3129-3145 | Buffer deserialization variant |
| `LoadMindIR(const void *buffer, ..., const CryptoInfo &cryptoInfo, ...)` | 3180-3213 | Even with crypto info, no signature verification |
| `LoadMindIR(const void *model_buffer, const size_t &model_size, const void *weight_buffer, ...)` | 3215-3251 | Multi-buffer deserialization |
| `ParseModelProto` | 2876-2897 | File-based parsing (uses decryption but not signature verification) |

### 1.2 Missing Security Check

The vulnerable code pattern is repeated across multiple functions:

```cpp
// load_model.cc:3000-3018 - Buffer-based loading (no integrity check)
FuncGraphPtr MindIRLoader::LoadMindIR(const void *buffer, const size_t &size) {
  mind_ir::ModelProto model;
  auto ret = model.ParseFromArray(buffer, SizeToInt(size));  // NO SIGNATURE VERIFICATION
  if (!ret) {
    MS_LOG(ERROR) << "ParseFromArray failed.";
    return nullptr;
  }
  // CheckModelConfigureInfo only validates metadata, NOT integrity
  if (!CheckModelConfigureInfo(model)) {
    MS_LOG(ERROR) << "Check configuration info for pb file failed!";
    return nullptr;
  }
  MSANFModelParser model_parser;
  InitModelParser(&model_parser, this);
  FuncGraphPtr func_graph = model_parser.Parse(model);  // Executes parsed model
  return func_graph;
}
```

**What `CheckModelConfigureInfo` actually validates (lines 340-370):**
- `producer_name` - metadata field
- `model_version` - version number
- `mind_ir_version` - format version compatibility
- `little_endian` - byte order compatibility

**NOT validated:**
- Cryptographic signature
- Hash verification
- Source authenticity
- Model integrity against tampering

### 1.3 Encryption Does Not Equal Integrity

The `ParseModelProto` function (lines 2876-2897) supports AES-GCM encryption:

```cpp
bool ParseModelProto(mind_ir::ModelProto *model, const std::string &path, const MindIRLoader *loader) {
  if (loader->dec_key() != nullptr) {
    size_t plain_len;
    auto plain_data = Decrypt(&plain_len, path, loader->dec_key(), loader->key_len(), loader->dec_mode());
    // Decryption provides confidentiality, NOT source authentication
    if (plain_data == nullptr) {
      MS_LOG(ERROR) << "Decrypt MindIR file failed, please check the correctness of the dec_key or dec_mode or the "
                       "file integrity.";  // "file integrity" is misleading - this is decryption failure
      return false;
    }
    if (!model->ParseFromArray(reinterpret_cast<char *>(plain_data.get()), SizeToInt(plain_len))) {
      // Still no signature verification after decryption
      ...
    }
  } else {
    // No encryption - direct file read without any protection
    std::fstream input_graph(path, std::ios::in | std::ios::binary);
    if (!input_graph || !model->ParseFromIstream(&input_graph)) {
      ...
    }
  }
  return true;
}
```

**Key issue:** AES-GCM provides authenticated encryption, meaning decryption will fail if the ciphertext is modified. However:
1. Anyone with the encryption key can create a "valid" encrypted malicious model
2. The buffer-based LoadMindIR functions bypass decryption entirely
3. No digital signature verifies the **source** or **authenticity** of the model

---

## 2. Official Acknowledgment

The project's SECURITY.md (lines 5-6) explicitly acknowledges this vulnerability:

```
Model files are stored in binary mode. When MindSpore is used to optimize or infer AI models 
and the model files are loaded in deserialization mode, once malicious code is written into 
the model files, the code are loaded and executed, causing attacks on the system.
```

The recommended mitigations in SECURITY.md are:
- Run MindSpore in sandbox
- Run as non-root user
- Ensure model source is trustworthy

**These are defensive mitigations, not code-level fixes.**

---

## 3. Attack Vector Analysis

### 3.1 Threat Model

| Attribute | Value |
|-----------|-------|
| Trust Level | `untrusted_local` |
| Attack Surface | Model file loading from memory buffer |
| Attack Complexity | Low |
| Privileges Required | User-level access to load model |
| User Interaction | Required (user must load malicious model) |

### 3.2 Attack Scenarios

**Scenario 1: Supply Chain Attack**
- Attacker distributes compromised model on model marketplace (e.g., HuggingFace, GitHub)
- User downloads and loads the model
- Malicious code embedded in model protobuf executes

**Scenario 2: Man-in-the-Middle Attack**
- Attacker intercepts model download from network
- Modifies protobuf content to inject malicious primitives
- User loads "legitimate" model that now contains payload

**Scenario 3: Local Tampering**
- Attacker with local access modifies cached/stored model files
- Model integrity not verified on subsequent loads

**Scenario 4: Memory Buffer Injection**
- Application receives model buffer from external source (API response, network socket)
- Buffer passed directly to `LoadMindIR(buffer, size)`
- No integrity verification occurs

---

## 4. Exploitation Steps (Conceptual)

### 4.1 Protobuf Manipulation Attack

1. **Obtain legitimate MindIR model file** (.mindir format)
2. **Parse protobuf structure** - MindIR uses protobuf format with defined schema
3. **Inject malicious primitive** - Add custom operation node with embedded payload:
   - Embed arbitrary code in primitive attributes
   - Use custom operator definitions to execute arbitrary code
   - Reference: SECURITY.md mentions "malicious code may be written into the model files"
4. **Serialize modified model** - Re-serialize protobuf with malicious content
5. **Distribute/Deploy** - User loads modified model via `mindspore.load_mindir()`

### 4.2 Technical Details

MindIR protobuf schema includes:
- `GraphProto` - computational graph structure
- `NodeProto` - individual operations (can define custom primitives)
- `AttributeProto` - operation attributes (can contain arbitrary data)
- `TensorProto` - weight tensors

**Attack vector:** The `PrimitiveProto` within `NodeProto` can define:
- Custom operator types
- Arbitrary attribute values
- Embedded function graphs

When `MSANFModelParser::Parse()` processes these nodes, it constructs the computational graph and can execute embedded malicious code during:
- Graph compilation
- Operator instantiation
- Custom operator registration

---

## 5. Impact Scope

### 5.1 Affected Components

- **Core Framework:** All model loading functionality
- **Python API:** `mindspore.load_mindir()`, `mindspore.train.serialization.load()`
- **C++ API:** `MindIRLoader::LoadMindIR()` and all buffer-based variants
- **MindSpore Lite:** Also vulnerable (lite mode path)

### 5.2 Affected Entry Points

| Entry Point | Location | Risk Level |
|-------------|----------|------------|
| Python `load_mindir()` | `python/mindspore/train/serialization.py:1111-1114` | High |
| C++ buffer loading | `core/load_mindir/load_model.cc:3000-3018` | Critical |
| Pipeline interface | `ccsrc/frontend/jit/ps/pipeline_interface.cc:188-283` | High |
| Compile cache manager | `ccsrc/frontend/jit/ps/compile_cache_manager.cc:197` | Medium |
| Kernel graph manager | `ccsrc/backend/common/kernel_graph/kernel_graph_mgr.cc:2923,3085,3211` | High |

### 5.3 Impact Assessment

- **Confidentiality:** Medium - Malicious model could exfiltrate data
- **Integrity:** Critical - Arbitrary code execution can modify any data
- **Availability:** High - Malicious model can crash or hang system
- **Scope:** Changed - Attack can affect other processes beyond MindSpore

---

## 6. Mitigation Recommendations

### 6.1 Recommended Solution: Digital Signature Verification

**Implement cryptographic signature verification for model files:**

```cpp
// Proposed architecture
class ModelSignatureVerifier {
public:
  bool VerifySignature(const void* buffer, size_t size, const SignatureInfo& sig);
private:
  // Use Ed25519 or ECDSA-P256 for signature verification
  // Signature embedded in model protobuf or separate .sig file
};

// Modified LoadMindIR with signature verification
FuncGraphPtr MindIRLoader::LoadMindIR(const void *buffer, const size_t &size) {
  // NEW: Verify signature before parsing
  if (!VerifyModelSignature(buffer, size)) {
    MS_LOG(ERROR) << "Model signature verification failed. Rejecting untrusted model.";
    return nullptr;
  }
  
  mind_ir::ModelProto model;
  auto ret = model.ParseFromArray(buffer, SizeToInt(size));
  // ... rest of loading logic
}
```

### 6.2 Signature Scheme Options

| Scheme | Advantages | Considerations |
|--------|------------|----------------|
| **Ed25519** | Fast, small signatures, no timing attacks | Requires key management |
| **ECDSA-P256** | Widely supported, FIPS compliant | Slower than Ed25519 |
| **RSA-PSS** | Compatible with existing PKI | Large signature size |

### 6.3 Implementation Steps

1. **Define signature protobuf extension:**
   ```protobuf
   message ModelSignature {
     string algorithm = 1;  // "Ed25519", "ECDSA-P256", etc.
     bytes signature = 2;   // Signature over model hash
     bytes public_key = 3;  // Optional embedded public key
     string key_id = 4;     // Key identifier for key store lookup
   }
   ```

2. **Add signature to MindIR export:**
   - Sign model during export (`mindspore.export()`)
   - Embed signature in protobuf or create companion `.mindir.sig` file

3. **Add signature verification to load:**
   - Compute hash of model content
   - Verify signature against trusted public keys
   - Reject unsigned or invalid models (with opt-out option)

4. **Key management:**
   - Provide trusted key store mechanism
   - Allow users to add/remove trusted signers
   - Support organization-specific signing keys

### 6.4 Short-Term Mitigations

For users unable to implement signatures immediately:

1. **Enable sandbox mode** (per SECURITY.md recommendation)
2. **Verify model hash** before loading:
   ```python
   import hashlib
   expected_hash = "sha256:abc123..."
   actual_hash = hashlib.sha256(open(model_path, 'rb').read()).hexdigest()
   if actual_hash != expected_hash:
       raise SecurityError("Model integrity check failed")
   ```
3. **Use encrypted models with known keys** (AES-GCM provides authenticated encryption)
4. **Restrict model sources** to trusted repositories only

---

## 7. References

- **CWE-354:** https://cwe.mitre.org/data/definitions/354.html
- **SECURITY.md:** `/mindspore/SECURITY.md` (lines 5-6)
- **Code Location:** `/mindspore/core/load_mindir/load_model.cc`
- **Header File:** `/mindspore/core/include/load_mindir/load_model.h`
- **Python API:** `/mindspore/python/mindspore/train/serialization.py`

---

## 8. Verification Evidence

### Code Analysis Summary

| Check | Finding | Risk |
|-------|---------|------|
| Signature verification call | NOT FOUND | Critical |
| Hash verification call | NOT FOUND | High |
| Certificate validation | NOT FOUND | High |
| Decryption-only integrity | AES-GCM auth tag | Medium (key holders can create valid models) |
| Buffer bypass | All buffer LoadMindIR skip decryption | Critical |

### Keywords Searched

- `ParseFromArray` - Found 17 occurrences, all without signature verification
- `signature` - Found in context of type signatures (not cryptographic)
- `verify` - No cryptographic verification found
- `integrity` - Only in error messages for decryption failure
- `decrypt`/`encrypt` - Encryption exists but for confidentiality only

---

## 9. Conclusion

This is a **confirmed vulnerability** per CWE-354. The MindSpore framework loads and executes model files without cryptographic integrity verification, allowing malicious models to be loaded and arbitrary code to be executed. The project acknowledges this risk in SECURITY.md but does not implement code-level mitigations.

**Recommended action:** Implement digital signature verification for all model loading pathways.
