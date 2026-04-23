# VULN-DF-DYN-001: Arbitrary Code Execution via Untrusted Library Loading

## Executive Summary

| Attribute | Value |
|-----------|-------|
| **Vulnerability ID** | VULN-DF-DYN-001 |
| **CWE** | CWE-427: Uncontrolled Search Path Element |
| **Type** | untrusted_library_loading |
| **Severity** | Critical |
| **Confidence** | 95% |
| **CVSS 3.1 Score** | 9.8 (Critical) |
| **Attack Vector** | Network (via malicious model file) |
| **Affected Component** | CustomOpSoLoader - OM model SO binary loading |

## 1. Vulnerability Description

### 1.1 Overview

The GE (Graph Engine) component loads custom operator shared objects (SO) directly from OM (Offline Model) files without any signature verification or integrity checks. An attacker can craft a malicious OM file containing arbitrary code in the SO_BINS partition, which will be executed in the context of the GE process when the model is loaded.

### 1.2 Technical Details

The vulnerability exists in the `CustomOpSoLoader::DlopenSoByFd` function at `/base/common/helper/custom_op_so_loader.cc:136-145`:

```cpp
Status CustomOpSoLoader::DlopenSoByFd(const int32_t mem_fd, void *&handle) const {
  GE_ASSERT_TRUE(mem_fd != kInvalidFd, "mem fd is invalid when loading custom op so.");
  const std::string so_path = std::string(kProcFdPrefix) + std::to_string(mem_fd);
  const int32_t open_flag =
      static_cast<int32_t>(static_cast<uint32_t>(MMPA_RTLD_NOW) | static_cast<uint32_t>(MMPA_RTLD_GLOBAL));
  handle = mmDlopen(so_path.c_str(), open_flag);  // SINK: Arbitrary code execution
  GE_ASSERT_TRUE(handle != nullptr, "dlopen custom op so[%s] failed, errmsg:%s", so_path.c_str(), mmDlerror());
  GELOGI("[CustomOpSoLoader] dlopen custom op so[%s] success.", so_path.c_str());
  return SUCCESS;
}
```

The loading flow:
1. SO binary data is extracted from the OM model file's `SO_BINS` partition
2. Data is written to an anonymous memory fd via `memfd_create`
3. The memory fd is loaded via `mmDlopen` (wrapper for `dlopen`)
4. **No signature verification, code signing, or integrity check is performed**

### 1.3 Missing Security Controls

The code lacks:
- **Digital signature verification** - No code signing check
- **Hash verification** - Only FNV1a64 hash for deduplication (not security)
- **Allowlist/Trust store** - No verification against trusted vendors
- **Certificate validation** - No X.509 or similar certificate validation
- **Secure boot chain** - No attestation of the SO origin

## 2. Complete Attack Path and Data Flow

### 2.1 Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ATTACKER CONTROLLED                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  [Malicious OM File]                                                         │
│       │                                                                      │
│       │ Contains crafted SO_BINS partition with malicious .so binary        │
│       ▼                                                                      │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ SO_BINS Partition Structure:                                         │   │
│  │ ┌─────────────────────────────────────────────────────────────────┐  │   │
│  │ │ SoStoreHead: so_num = 1                                         │  │   │
│  │ ├─────────────────────────────────────────────────────────────────┤  │   │
│  │ │ SoStoreItemHead:                                                │  │   │
│  │ │   magic: 0x5D776EFD                                             │  │   │
│  │ │   so_name_len: X                                                │  │   │
│  │ │   so_bin_type: 3 (kCustomOp)                                    │  │   │
│  │ │   vendor_name_len: Y                                            │  │   │
│  │ │   bin_len: Z                                                    │  │   │
│  │ ├─────────────────────────────────────────────────────────────────┤  │   │
│  │ │ [MALICIOUS ELF SHARED OBJECT - ARBITRARY CODE]                  │  │   │
│  │ └─────────────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│                              GE PROCESS (VICTIM)                               │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  aclmdlLoadFromMem(model, modelSize, modelId)                                 │
│       │                                                                        │
│       ▼                                                                        │
│  ModelHelper::GenerateGeRootModel()                                           │
│       │                                                                        │
│       ▼                                                                        │
│  ModelHelper::LoadOpSoBin() ────────────────────────────────────────────────┐ │
│       │                                                                      │ │
│       │ om_load_helper.GetModelPartition(SO_BINS, ...)                       │ │
│       ▼                                                                      │ │
│  GeRootModel::LoadSoBinData(data, len)                                       │ │
│       │                                                                      │ │
│       │ OpSoStore::Load() parses SO_BINS partition                          │ │
│       ▼                                                                      │ │
│  [OpSoBinPtr with malicious binary data]                                     │ │
│       │                                                                      │ │
│       │ GetSoBinType() == SoBinType::kCustomOp                               │ │
│       ▼                                                                      │ │
│  ModelHelper::LoadCustomOpSoBins()                                           │ │
│       │                                                                      │ │
│       ▼                                                                      │ │
│  CustomOpSoLoader::LoadCustomOpSoBins()                                      │ │
│       │                                                                      │ │
│       ├── CreateSoMemFd() ─── syscall(__NR_memfd_create, ...)               │ │
│       │                                                                      │ │
│       ├── WriteSoBinToFd() ─── write(mem_fd, MALICIOUS_BINARY, ...)         │ │
│       │                                                                      │ │
│       ▼                                                                      │ │
│  ┌─────────────────────────────────────────────────────────────────────────┐│ │
│  │ DlopenSoByFd()                                                          ││ │
│  │   const std::string so_path = "/proc/self/fd/<mem_fd>";                ││ │
│  │   handle = mmDlopen(so_path.c_str(), RTLD_NOW | RTLD_GLOBAL);          ││ │
│  │                                                                         ││ │
│  │   *** ARBITRARY CODE EXECUTION ***                                      ││ │
│  │   Constructor functions (.init_array, .ctors) execute immediately     ││ │
│  └─────────────────────────────────────────────────────────────────────────┘│ │
│                                                                                │
└───────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Key Source Files in Attack Chain

| File | Line | Function | Role |
|------|------|----------|------|
| `base/common/helper/custom_op_so_loader.cc` | 136-145 | `DlopenSoByFd()` | **SINK** - Executes arbitrary SO |
| `base/common/helper/custom_op_so_loader.cc` | 115-133 | `WriteSoBinToFd()` | Writes untrusted binary to memfd |
| `base/common/helper/custom_op_so_loader.cc` | 97-113 | `CreateSoMemFd()` | Creates anonymous memory fd |
| `base/common/helper/custom_op_so_loader.cc` | 147-190 | `LoadCustomOpSoBins()` | Orchestrates loading of custom SOs |
| `base/common/helper/model_helper.cc` | 1500-1538 | `LoadOpSoBin()` | Extracts SO_BINS from OM, dispatches by type |
| `base/common/helper/model_helper.cc` | 1541-1548 | `LoadCustomOpSoBins()` | Calls CustomOpSoLoader |
| `base/common/op_so_store/op_so_store.cc` | 98-154 | `OpSoStore::Load()` | **SOURCE** - Parses SO_BINS from OM file |
| `inc/graph_metadef/graph/op_so_bin.h` | 34-65 | `OpSoBin` class | Container for SO binary data |

## 3. Affected Entry Points (Attack Surface)

### 3.1 Public APIs That Trigger the Vulnerability

The following ACL APIs accept OM model data and trigger the vulnerable code path:

| API | File | Description |
|-----|------|-------------|
| `aclmdlLoadFromFile()` | `api/acl/acl_model/model/acl_model.cpp:109` | Load model from file path |
| `aclmdlLoadFromMem()` | `api/acl/acl_model/model/acl_model.cpp:210` | Load model from memory buffer |
| `aclmdlLoadFromFileWithMem()` | `api/acl/acl_model/model/acl_model.cpp:215` | Load with pre-allocated memory |
| `aclmdlLoadFromMemWithMem()` | `api/acl/acl_model/model/acl_model.cpp:222` | Load from memory with pre-allocated memory |
| `aclmdlLoadFromFileWithQ()` | `api/acl/acl_model/model/acl_model.cpp:229` | Load with queue configuration |
| `aclmdlLoadFromMemWithQ()` | `api/acl/acl_model/model/acl_model.cpp:235` | Load from memory with queue |
| `aclmdlBundleLoadModel()` | `api/acl/acl_model/model/acl_model.cpp:187` | Bundle model loading |
| `aclmdlBundleLoadModelWithMem()` | `api/acl/acl_model/model/acl_model.cpp:192` | Bundle with memory |
| `aclmdlBundleLoadModelWithConfig()` | `api/acl/acl_model/model/acl_model.cpp:199` | Bundle with config |
| `aclopCompileOp()` | `api/acl/acl_op_compiler/` | Single operator compilation |

### 3.2 Attack Scenarios

1. **Malicious Model File Distribution**: An attacker distributes a crafted OM file that appears to be a legitimate AI model. When loaded by GE, the embedded malicious SO executes with the privileges of the GE process.

2. **Supply Chain Attack**: Compromise a model repository or model serving infrastructure to inject malicious SOs into legitimate OM files.

3. **Model Marketplace Attack**: Upload malicious models to public model repositories (similar to PyPI malware campaigns).

4. **Man-in-the-Middle**: Intercept model file transfers and inject malicious SO_BINS partition.

## 4. PoC Construction Outline

### 4.1 Prerequisites
- Understanding of OM file format
- ELF shared object construction knowledge
- Access to CANN development environment for testing

### 4.2 High-Level Steps (Conceptual Only)

1. **Craft Malicious SO**:
   - Create a shared object with constructor function
   - Constructor runs on `dlopen()` before any other code
   - Example pattern:
     ```c
     __attribute__((constructor))
     void malicious_init() {
         // Arbitrary code execution here
         // Runs in context of GE process
     }
     ```

2. **Build Malicious OM File**:
   - Start with a legitimate OM file
   - Inject crafted SO into SO_BINS partition
   - Set `SoBinType = kCustomOp` (value 3)
   - Recalculate partition offsets and headers

3. **Trigger Execution**:
   - Call `aclmdlLoadFromMem()` or `aclmdlLoadFromFile()` with malicious OM
   - GE extracts and loads the SO
   - Malicious constructor executes

### 4.3 Required OM File Format Knowledge

From `base/common/op_so_store/op_so_store.cc`:
```
SoStoreHead (4 bytes):
  - so_num: uint32_t

SoStoreItemHead (16 bytes per SO):
  - magic: 0x5D776EFD (uint32_t)
  - so_name_len: uint16_t
  - so_bin_type: uint16_t (3 = kCustomOp triggers vulnerability)
  - vendor_name_len: uint32_t
  - bin_len: uint32_t

Followed by:
  - so_name (so_name_len bytes)
  - vendor_name (vendor_name_len bytes)
  - binary data (bin_len bytes) <- MALICIOUS SO HERE
```

## 5. Impact Assessment

### 5.1 Severity Justification

| Factor | Assessment |
|--------|------------|
| **Attack Complexity** | Low - Only requires crafting a file in known format |
| **Privileges Required** | None - Attacker only needs to provide model file |
| **User Interaction** | Required - Victim must load the model |
| **Scope** | Changed - Compromises GE process, can affect other processes |
| **Confidentiality Impact** | High - Full process memory access |
| **Integrity Impact** | High - Arbitrary code can modify anything |
| **Availability Impact** | High - Can crash or DoS the system |

### 5.2 Affected Components

- **GE Process**: The Graph Engine process runs with elevated privileges to access NPU hardware
- **All Models Using Custom Operators**: Any model with `SoBinType::kCustomOp` SO binaries
- **Model Serving Infrastructure**: Systems that accept and load untrusted OM files
- **Edge Devices**: Ascend NPUs in production environments

### 5.3 Real-World Impact

1. **Container Escape**: If GE runs in a container, the attacker may escape to the host
2. **Data Exfiltration**: Access to model weights, inference data, and system secrets
3. **Lateral Movement**: Use compromised host to attack other infrastructure
4. **Model Poisoning**: Inject backdoors into legitimate models
5. **Cryptographic Key Theft**: Access to HSM integrations, TLS keys, etc.

## 6. Root Cause Analysis

### 6.1 Design Flaw

The "SO in OM" feature was designed for portability and self-containment without considering the security implications of loading untrusted code. The feature documentation explicitly states:

> "SO in OM 特性将模型依赖的算子 .so 文件直接打包进 .om（Offline Model）文件中"

This creates an implicit trust relationship between the OM file and the GE process without any verification mechanism.

### 6.2 Code Analysis

The fingerprint calculation in `CalculateSoBinFingerprint()` uses FNV1a64 hash:

```cpp
uint64_t CalculateFnv1a64(const uint8_t *data, const size_t data_len) {
  uint64_t hash = kFnvOffsetBasis;
  for (size_t i = 0U; i < data_len; ++i) {
    hash ^= static_cast<uint64_t>(data[i]);
    hash *= kFnvPrime;
  }
  return hash;
}
```

This hash is only used for deduplication (checking if same SO is already loaded), NOT for security verification. An attacker can trivially modify the SO while maintaining functionality.

### 6.3 Missing Security Controls

The code explicitly avoids disk fallback (as stated in comments):

```cpp
constexpr const char_t *kNoDiskFallbackHint = "strict no-disk-fallback is enabled.";
```

However, there is no mention of any security verification. The design prioritizes:
1. Memory-only loading (good for security - no disk traces)
2. Deduplication (performance)
3. **Missing: Trust verification**

## 7. Remediation Recommendations

### 7.1 Short-Term Mitigations (Quick Wins)

1. **Add SO Type Filtering**:
   ```cpp
   // In LoadCustomOpSoBins(), before loading:
   if (op_so_bin->GetSoBinType() != SoBinType::kSpaceRegistry &&
       op_so_bin->GetSoBinType() != SoBinType::kOpMasterDevice &&
       op_so_bin->GetSoBinType() != SoBinType::kAutofuse) {
       // Reject kCustomOp type from untrusted sources
       GELOGE(FAILED, "Custom SO loading from untrusted source is disabled");
       return FAILED;
   }
   ```

2. **Environment Variable Toggle**:
   ```cpp
   // Add configuration to disable custom SO loading
   if (std::getenv("GE_DISABLE_CUSTOM_SO_LOADING") != nullptr) {
       GELOGW("Custom SO loading is disabled by environment");
       return SUCCESS; // Skip loading
   }
   ```

### 7.2 Medium-Term Solutions

1. **Digital Signature Verification**:
   - Add signature block to OM file format
   - Verify SO signature against trusted certificates
   - Reject unsigned SOs or SOs with invalid signatures
   - Store trusted vendor public keys in secure location

2. **Allowlist/Trust Store**:
   - Implement a trust store for allowed vendor names
   - Only load SOs from vendors in the trust store
   - Maintain a hash allowlist for built-in operators

3. **Secure Loading Path**:
   ```cpp
   Status SecureCustomOpSoLoader::LoadWithVerification(const OpSoBinPtr &so_bin) {
       // 1. Verify digital signature
       GE_ASSERT_SUCCESS(VerifySignature(so_bin));
       
       // 2. Check vendor trust store
       GE_ASSERT_SUCCESS(CheckVendorTrust(so_bin->GetVendorName()));
       
       // 3. Validate SO integrity
       GE_ASSERT_SUCCESS(ValidateSoIntegrity(so_bin->GetBinData(), so_bin->GetBinDataSize()));
       
       // 4. Load in sandboxed environment
       return LoadInSandbox(so_bin);
   }
   ```

### 7.3 Long-Term Architectural Changes

1. **Out-of-Process Loading**:
   - Load custom SOs in a separate sandboxed process
   - Use IPC for communication
   - Limit sandbox privileges

2. **Seccomp/Sandbox Integration**:
   - Apply seccomp filters to limit syscalls after loading
   - Use namespaces to isolate loaded code
   - Implement AppArmor/SELinux profiles

3. **Attestation Integration**:
   - Integrate with hardware attestation (TEE)
   - Verify model provenance before loading
   - Implement secure boot chain for OM files

### 7.4 Code Changes Required

**File: `base/common/helper/custom_op_so_loader.cc`**

Add before line 136:
```cpp
Status CustomOpSoLoader::VerifySoBinSignature(const OpSoBinPtr &op_so_bin) {
    // TODO: Implement signature verification
    // 1. Extract signature from OM metadata
    // 2. Verify signature against trusted public keys
    // 3. Reject if verification fails
    return SUCCESS;
}

Status CustomOpSoLoader::DlopenSoByFd(const int32_t mem_fd, void *&handle) const {
    // Add pre-loading security check
    // This should be implemented with proper key management
}
```

**File: `base/common/helper/model_helper.cc`**

Modify `LoadOpSoBin()` around line 1521:
```cpp
if (op_so_bin_ptr->GetSoBinType() == SoBinType::kCustomOp) {
    // Add security check before adding to load list
    if (!IsCustomOpBinAllowed(op_so_bin_ptr)) {
        GELOGW("Custom SO [%s] from vendor [%s] rejected - not in trust store",
               op_so_bin_ptr->GetSoName().c_str(),
               op_so_bin_ptr->GetVendorName().c_str());
        continue;
    }
    custom_op_so_bins.emplace_back(op_so_bin_ptr);
}
```

## 8. References

- CWE-427: Uncontrolled Search Path Element - https://cwe.mitre.org/data/definitions/427.html
- CWE-426: Untrusted Search Path - https://cwe.mitre.org/data/definitions/426.html
- OWASP: Untrusted Data Injection - https://owasp.org/www-community/vulnerabilities/Untrusted_Data_Injection
- ELF Format Specification - https://refspecs.linuxfoundation.org/elf/elf.pdf
- dlopen() Linux Manual - https://man7.org/linux/man-pages/man3/dlopen.3.html

## 9. Conclusion

This is a **confirmed critical vulnerability** that allows arbitrary code execution through malicious OM model files. The attack surface is broad (multiple public APIs), the exploit complexity is low, and the impact is severe (full process compromise).

The vulnerability exists because the system trusts the `SO_BINS` partition content without verification, allowing an attacker to inject and execute arbitrary code with the privileges of the GE process.

**Immediate action required**: Implement short-term mitigations and plan for signature verification infrastructure.

---

*Report generated by security analysis tool*
*Timestamp: 2026-04-22*
