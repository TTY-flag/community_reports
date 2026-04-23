# 漏洞扫描报告 — 待确认漏洞

**项目**: SIP (Signal Processing)
**扫描时间**: 2026-04-21T15:30:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 23 | 41.8% |
| POSSIBLE | 15 | 27.3% |
| LIKELY | 13 | 23.6% |
| CONFIRMED | 4 | 7.3% |
| **总计** | **55** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 7 | 25.0% |
| Medium | 8 | 28.6% |
| Low | 3 | 10.7% |
| **有效漏洞总计** | **28** | - |
| 误报 (FALSE_POSITIVE) | 23 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-sip_pta_python-002]** Missing dtype Validation (High) - `sip_pta/torch_sip/__init__.py:55` @ `asd_blas_cgemm` | 置信度: 75
2. **[VULN-sip_pta_python-004]** Missing Shape Validation (High) - `sip_pta/torch_sip/__init__.py:55` @ `asd_blas_cgemm` | 置信度: 75
3. **[DF-007]** Integer Overflow (High) - `core/fft/utils/workspace.cpp:44` @ `Workspace::allocate` | 置信度: 75
4. **[CORE-OPS-BASE-001]** Critical Dispatcher Vulnerability (High) - `core/utils/ops_base.cpp:263` @ `RunAsdOpsV2` | 置信度: 75
5. **[CORE-MEM-COPY-001]** Unchecked Memory Copy (High) - `core/utils/ops_base.cpp:184` @ `MkiRtMemCopy` | 置信度: 75
6. **[DF-004]** Buffer Overflow (High) - `core/utils/ops_base.cpp:184` @ `MallocTensorInDevice` | 置信度: 70
7. **[DF-003]** Integer Overflow (High) - `core/utils/ops_base.cpp:50` @ `MallocOutTensor` | 置信度: 65
8. **[VULN-sip_pta_python-001]** Missing Input Validation (Medium) - `sip_pta/torch_sip/__init__.py:18` @ `asd_mul` | 置信度: 65
9. **[CORE-WORKSPACE-001]** Integer Overflow in Workspace (Medium) - `core/fft/utils/workspace.cpp:39` @ `Workspace::allocate` | 置信度: 60
10. **[SIP_PTA_CSRC-001]** Missing NPU Device Validation (Medium) - `sip_pta/csrc/pytorch_npu_helper.hpp:307` @ `CreateAclTensorFromAtTensor` | 置信度: 55

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `asdBlasCreate@include/blas_api.h` | rpc | semi_trusted | API entry for handle creation, called by trusted application code through Ascend CL framework | Create BLAS handle for subsequent operations |
| `asdBlasCgemm@include/blas_api.h` | rpc | untrusted_local | Receives aclTensor pointers containing user-provided matrix data, tensors populated by external ML framework | Complex matrix multiplication with external tensor data |
| `asdBlasCgemv@include/blas_api.h` | rpc | untrusted_local | Receives aclTensor pointers containing user-provided matrix/vector data | Complex matrix-vector multiplication |
| `asdBlasCgemmBatched@include/blas_api.h` | rpc | untrusted_local | Batched operation with multiple tensors, higher risk due to dimension calculations | Batched complex matrix multiplication |
| `asdBlasCmatinvBatched@include/blas_api.h` | rpc | untrusted_local | Batched matrix inversion, complex dimension validation required | Batched complex matrix inversion |
| `asdFftMakePlan1D@include/fft_api.h` | rpc | semi_trusted | Plan creation with user-specified FFT size parameters | Create 1D FFT execution plan with size parameters |
| `asdFftExecC2C@include/fft_api.h` | rpc | untrusted_local | Executes FFT transform on user-provided tensor data | Execute complex-to-complex FFT transform |
| `asdFftExecC2R@include/fft_api.h` | rpc | untrusted_local | Transform with different input/output sizes, potential validation gap | Execute complex-to-real FFT transform |
| `asdFftExecR2C@include/fft_api.h` | rpc | untrusted_local | Transform with different input/output sizes | Execute real-to-complex FFT transform |
| `asdConvolve@include/filter_api.h` | rpc | untrusted_local | Convolution operation on user-provided signal and kernel tensors | Signal convolution operation |
| `asdInterpWithCoeff@include/interp_api.h` | rpc | untrusted_local | Interpolation with coefficient tensor from user | Interpolation using provided coefficients |
| `torch_sip_cgemm@sip_pta/csrc/blas/asd_blas_cgemm.cpp` | rpc | untrusted_local | PyTorch adapter converting PyTorch tensors to aclTensor without deep validation | PyTorch wrapper for BLAS Cgemm operation |

**其他攻击面**:
- aclTensor API Interface: All BLAS/FFT/Filter operations receive external tensor data
- PyTorch Adapter Layer: sip_pta converts Python tensors to Ascend format
- Dimension Parameters: User-provided m, n, k, lda, ldb, ldc, fftSize, batchSize values
- Workspace Memory: Internal buffer allocations based on calculated sizes
- Device Memory Copy: aclrtMemcpy and MkiRtMemCopy operations on tensor data
- Tiling Data: memcpy_s operations in kernel tiling without return value checks

---

## 3. High 漏洞 (7)

### [VULN-sip_pta_python-002] Missing dtype Validation - asd_blas_cgemm

**严重性**: High | **CWE**: CWE-664 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `sip_pta/torch_sip/__init__.py:55-78` @ `asd_blas_cgemm`
**模块**: sip_pta_python

**描述**: BLAS operations like asd_blas_cgemm require complex64 tensors but no dtype validation is performed. Passing incompatible dtypes (float32, int64) could cause memory corruption or incorrect results in the underlying C++ implementation.

**漏洞代码** (`sip_pta/torch_sip/__init__.py:55-78`)

```c
def asd_blas_cgemm(\n        mat_a: torch.Tensor,\n        mat_b: torch.Tensor,\n        mat_c: torch.Tensor,\n        ...):\n    return torch.ops.torch_sip.asd_blas_cgemm(mat_a, mat_b, mat_c, alpha_c, beta_c, t_a, t_b)
```

**达成路径**

Python tensors -> C++ BLAS kernel (dtype assumptions violated)

**验证说明**: CGEMM (complex matrix multiplication) requires complex64 tensors but no dtype validation exists. Passing float32/int64 tensors directly to C++ BLAS kernel could cause type confusion or memory corruption. Note: trans_a/trans_b parameters ARE validated via _get_trans_enum() (raises ValueError), and alpha/beta are converted to complex - but tensor dtype validation is completely missing.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-sip_pta_python-004] Missing Shape Validation - asd_blas_cgemm

**严重性**: High | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `sip_pta/torch_sip/__init__.py:55-78` @ `asd_blas_cgemm`
**模块**: sip_pta_python

**描述**: Matrix operations like asd_blas_cgemm accept tensor inputs without validating shape compatibility. For CGEMM, mat_a (M,K), mat_b (K,N), mat_c (M,N) shapes must match, but no validation occurs before passing to C++. Mismatched shapes could cause buffer overflows in the NPU kernel.

**漏洞代码** (`sip_pta/torch_sip/__init__.py:55-78`)

```c
def asd_blas_cgemm(mat_a, mat_b, mat_c, ...):\n    # No shape validation\n    return torch.ops.torch_sip.asd_blas_cgemm(mat_a, mat_b, mat_c, ...)
```

**达成路径**

User tensors -> No shape check -> C++ kernel (potential buffer overflow)

**验证说明**: No shape validation for CGEMM matrix dimensions. Required shape compatibility (mat_a: MxK, mat_b: KxN, mat_c: MxN considering transpose flags) is not checked before passing to C++ kernel. Mismatched shapes could cause buffer overflow in NPU backend. This is a critical vulnerability for matrix operations where dimension errors can lead to out-of-bounds memory access.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -10 | context: 0 | cross_file: 0

---

### [DF-007] Integer Overflow - Workspace::allocate

**严重性**: High | **CWE**: CWE-190 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `core/fft/utils/workspace.cpp:44` @ `Workspace::allocate`
**模块**: core
**跨模块**: core → fft

**描述**: Integer overflow in workspace offset calculation. offset + dataSize in allocate() could overflow if dataSize is very large or tainted, leading to invalid pointer return and potential buffer overflow.

**漏洞代码** (`core/fft/utils/workspace.cpp:44`)

```c
offsets_.push_back(offset + dataSize);
```

**达成路径**

dataSize@external -> offset calculation -> pointer return

**验证说明**: Integer overflow in workspace offset calculation. size_t offset + dataSize addition (line 44) without overflow check. If dataSize from external FFT tensor dimensions is very large, overflow wraps around causing invalid pointer return from (uint8_t*)dataPtr_ + offset. Called from FFT execution path with untrusted_local entry points.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CORE-OPS-BASE-001] Critical Dispatcher Vulnerability - RunAsdOpsV2

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-20 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `core/utils/ops_base.cpp:263-300` @ `RunAsdOpsV2`
**模块**: core
**跨模块**: core → ops → include

**描述**: RunAsdOpsV2 (ops_base.cpp:263) is the central dispatcher for all SIP operations. Receives external tensor data and parameters without comprehensive validation before launching NPU kernels. Missing bounds checks on tensor dimensions could lead to NPU memory corruption.

**达成路径**

aclTensor -> aclGetStorageShape -> tensor dims -> InferShape -> kernel launch

**验证说明**: RunAsdOpsV2 is a public API entry point receiving external aclTensor pointers without comprehensive validation. While stream null-check and operation lookup exist, tensor dimensions from untrusted_local input flow directly to InferShape and kernel execution. No bounds validation on input tensor dimensions. Risk: NPU memory corruption from malformed tensor parameters. Severity reduced from Critical to High due to partial internal validation (InferShape computes outputs).

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [CORE-MEM-COPY-001] Unchecked Memory Copy - MkiRtMemCopy

**严重性**: High（原评估: Critical → 验证后: High） | **CWE**: CWE-119 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `core/utils/ops_base.cpp:184-200` @ `MkiRtMemCopy`
**模块**: core
**跨模块**: core → ops

**描述**: MkiRtMemCopy (ops_base.cpp:184) copies tensor data to NPU device memory without validating dataSize bounds. Trusts tensor.dataSize from external input potentially leading to buffer overflow on NPU.

**达成路径**

tensor.dataSize -> malloc -> MkiRtMemCopy (device memory)

**验证说明**: MallocTensorInDevice allocates and copies tensor.dataSize bytes without bounds validation. Called directly from 17+ BLAS operations. Primary risk is memory exhaustion (huge dataSize) and potential read overflow if hostData lacks dataSize bytes. NOT a destination buffer overflow since allocation and copy sizes match. Severity reduced from Critical to High - actual vulnerability type is memory exhaustion/CWE-400 rather than classic buffer overflow.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [DF-004] Buffer Overflow - MallocTensorInDevice

**严重性**: High | **CWE**: CWE-119 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `core/utils/ops_base.cpp:184` @ `MallocTensorInDevice`
**模块**: core

**描述**: Memory copy operations use potentially overflowed dataSize. MkiRtMemCopy uses dataSize that could be corrupted by integer overflow, leading to buffer overflow or incorrect memory operations.

**漏洞代码** (`core/utils/ops_base.cpp:184`)

```c
st = MkiRtMemCopy(tensor.data, tensor.dataSize, tensor.hostData, tensor.dataSize, MKIRT_MEMCOPY_HOST_TO_DEVICE);
```

**达成路径**

dataSize@overflowed -> MkiRtMemCopy -> device memory

**验证说明**: Buffer overflow/downstream effect of DF-003. If dataSize is corrupted by upstream overflow, MkiRtMemCopy uses wrong size leading to undersized allocation and potential data corruption. Directly dependent on DF-003 overflow occurring. MallocTensorInDevice allocates then copies with same potentially-overflowed dataSize.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [DF-003] Integer Overflow - MallocOutTensor

**严重性**: High | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `core/utils/ops_base.cpp:50-51` @ `MallocOutTensor`
**模块**: core
**跨模块**: core → ops

**描述**: Potential integer overflow in dataSize calculation. tensor.Numel() multiplied by element size without overflow check. If Numel() is very large, dataSize could overflow, leading to undersized memory allocation.

**漏洞代码** (`core/utils/ops_base.cpp:50-51`)

```c
tensor.dataSize = static_cast<size_t>(tensor.Numel()) * static_cast<size_t>(GetTensorElementSize(tensor.desc.dtype));
```

**达成路径**

tensor.desc.dims@aclTensor -> Numel() -> dataSize -> MkiRtMemMallocDevice/MkiRtMemCopy

**验证说明**: Integer overflow possible in dataSize calculation. size_t casting on both operands mitigates overflow at multiplication point (sizeof(std::complex<float>) * Numel()), but upstream overflow in Numel() internal calculation remains possible if tensor dimensions from aclTensor are extremely large. Entry point untrusted_local via asdBlasCgemm/asdBlasCgemv. No explicit upper bound check on Numel() result.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (8)

### [VULN-sip_pta_python-001] Missing Input Validation - asd_mul

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `sip_pta/torch_sip/__init__.py:18-19` @ `asd_mul`
**模块**: sip_pta_python

**描述**: Function asd_mul() accepts arbitrary parameters without validating they are torch.Tensor types. Type hints are not enforced at runtime, allowing non-tensor inputs to be passed directly to C++ backend via torch.ops.torch_sip.asd_mul, potentially causing undefined behavior or crashes.

**漏洞代码** (`sip_pta/torch_sip/__init__.py:18-19`)

```c
def asd_mul(x: torch.Tensor, y: torch.Tensor) -> torch.Tensor:\n    return torch.ops.torch_sip.asd_mul(x, y)
```

**达成路径**

Python API -> torch.ops.torch_sip.asd_mul(x, y) -> C++ backend (no validation)

**验证说明**: PyTorch's dispatcher catches non-tensor inputs at runtime, making the 'non-tensor' claim in the description inaccurate. The actual vulnerability is missing shape/dtype validation for tensor parameters. For asd_mul (element-wise multiplication), shape mismatch would cause a runtime error rather than memory corruption. Severity downgraded to Medium as this is less critical than matrix operations like GEMM.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [CORE-WORKSPACE-001] Integer Overflow in Workspace - Workspace::allocate

**严重性**: Medium（原评估: Critical → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `core/fft/utils/workspace.cpp:39-55` @ `Workspace::allocate`
**模块**: core

**描述**: Workspace::allocate (workspace.cpp:39) performs linear allocation without overflow checking. Offset accumulation could exceed dataSize_ causing buffer overflow in FFT workspace.

**达成路径**

FFT params -> size calculation -> allocate(offset) -> heap overflow

**验证说明**: Workspace::allocate performs linear allocation without bounds checking. getAlignedSize() (workspace.h:43-45) validates input size overflow but NO check on accumulated offset+dataSize or against dataSize_ buffer capacity. Multiple allocations could cause: (1) size_t overflow from accumulated offsets, (2) returned pointer exceeding allocated buffer. Reachable via FFT API with external tensor parameters controlling allocation sizes. Severity reduced from Critical to Medium due to partial input validation and indirect controllability.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [SIP_PTA_CSRC-001] Missing NPU Device Validation - CreateAclTensorFromAtTensor

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `sip_pta/csrc/pytorch_npu_helper.hpp:307-339` @ `CreateAclTensorFromAtTensor`
**模块**: sip_pta_csrc
**跨模块**: sip_pta_csrc → sip_pta_python

**描述**: CreateAclTensorFromAtTensor (pytorch_npu_helper.hpp:307) does not validate tensor is on NPU device before creating aclTensor. CPU tensors passed to NPU operations cause undefined behavior.

**达成路径**

PyTorch tensor -> aclTensor (no device check) -> NPU kernel

**验证说明**: Partially mitigated. NPUGuard (line 28) validates signal.device(), and output inherits device via empty_like(signal). However, kernel tensor lacks explicit device check - CreateAclTensorFromAtTensor does not validate NPU device unlike ConvertType(MkiConvertInput) which has explicit TORCH_CHECK(torch_npu::utils::is_npu()). A CPU kernel tensor passed with NPU signal would cause undefined behavior. Reduced severity to Medium due to partial mitigation.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [OPS-IAMAX-002] Integer Truncation - IamaxTiling

**严重性**: Medium | **CWE**: CWE-197 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ops/blas/iamax/iamax/tiling/iamax_tiling.cpp:66-73` @ `IamaxTiling`
**模块**: ops

**描述**: Unsafe integer truncation via static_cast<uint32_t> on param.n, param.incx, and tensor dimensions. If input param.n is INT64_MAX or negative, static_cast truncates/wraps, causing incorrect element counts and potential buffer underallocation. The tensorLen calculation uses dims[sizeNum-1] without bounds checking sizeNum.

**漏洞代码** (`ops/blas/iamax/iamax/tiling/iamax_tiling.cpp:66-73`)

```c
uint32_t numberElements = static_cast<uint32_t>(param.n);\nuint32_t incx = static_cast<uint32_t>(param.incx);\nuint32_t tensorLen = static_cast<uint32_t>(launchParam.GetInTensor(0).desc.dims[sizeNum - 1]);
```

**达成路径**

API params (n, incx, tensor dims) -> static_cast -> element calculations -> buffer sizes

**验证说明**: Integer truncation via static_cast<uint32_t> on int64_t param.n/param.incx. Upstream validation in core/blas/iamax.cpp checks n<=0 but does NOT validate against UINT32_MAX. Truncation possible for large positive int64_t values. Mitigated by tensor shape check requiring n to match actual tensor size, reducing practical exploitability.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [OPS-CAXPY-001] Integer Overflow - CaxpyTiling

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ops/blas/caxpy/caxpy/tiling/caxpy_tiling.cpp:102` @ `CaxpyTiling`
**模块**: ops

**描述**: Integer overflow in element count multiplication. Line 102: n * COMPLEX_NUM can overflow uint32_t when n > ~2 billion. This overflowed value is stored in tilingDataPtr->n and used for device memory calculations, potentially causing buffer underallocation on NPU.

**漏洞代码** (`ops/blas/caxpy/caxpy/tiling/caxpy_tiling.cpp:102`)

```c
tilingDataPtr->n = n * COMPLEX_NUM;  // num of FP32 elements
```

**达成路径**

param.n -> n -> n * COMPLEX_NUM -> tilingDataPtr->n (device kernel uses this for memory ops)

**验证说明**: Integer overflow in n * COMPLEX_NUM multiplication. Upstream validation in core/blas/caxpy.cpp checks n <= UINT32_MAX but allows values in overflow range (2.1B to 4.2B). COMPLEX_NUM=2 multiplication overflows uint32_t when n > UINT32_MAX/2. Triggering requires tensor allocation of >2 billion elements, which is impractical for memory constraints.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [DF-005] Integer Overflow - SetyInTensor

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `core/blas/blasplan/BlasCgemvPlan.cpp:107-110` @ `SetyInTensor`
**模块**: core

**描述**: Integer overflow in ySize calculation. ySize is calculated as sizeof(std::complex<float>) multiplied by storageDims values. If storageDims contain large values from external aclTensor, ySize could overflow.

**漏洞代码** (`core/blas/blasplan/BlasCgemvPlan.cpp:107-110`)

```c
int64_t ySize = sizeof(std::complex<float>); for (uint64_t i = 0; i < storageDimsNum; i++) { ySize *= storageDims[i]; }
```

**达成路径**

aclTensor y -> aclGetStorageShape -> storageDims -> ySize -> aclrtMalloc/aclrtMemcpy

**验证说明**: Integer overflow in ySize loop multiplication (line 107-110). int64_t ySize multiplied by storageDims[i] without upper bound check. aclGetStorageShape provides dimensions from external aclTensor. Lower bound check exists (*storageDims <= 0) but no overflow prevention. Overflow would cause negative/wrapped ySize passed to aclrtMalloc/aclrtMemcpy.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -10 | context: -15 | cross_file: 0

---

### [SIP_PTA_CSRC-003] Null Pointer Dereference - asdConvolve

**严重性**: Medium | **CWE**: CWE-476 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `sip_pta/csrc/filter/asd_convolve.cpp:86-92` @ `asdConvolve`
**模块**: sip_pta_csrc

**描述**: CreateAclTensorFromAtTensor can return nullptr when aclCreateTensor fails. Callers use returned pointer without null checks leading to crashes.

**验证说明**: Theoretical null pointer risk. CreateAclTensorFromAtTensor returns nullptr if aclCreateTensorFunc is null (line 323). Callers in asd_convolve.cpp do not check for nullptr. HOWEVER, EXEC_FUNC macro wraps call in OpCommand with TORCH_CHECK that would throw before passing nullptr to ACL API. The null would be caught by PyTorch exception layer rather than causing silent dereference. Reduced to POSSIBLE because crash path is through exception, not silent null pointer usage.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-sip_pta_python-006] Missing Input Validation - asd_blas_caxpy

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `sip_pta/torch_sip/__init__.py:38-43` @ `asd_blas_caxpy`
**模块**: sip_pta_python

**描述**: Function asd_blas_caxpy() only validates alpha is complex type but does not validate x, y tensor parameters. Non-tensor inputs will cause unclear errors from the C++ layer.

**漏洞代码** (`sip_pta/torch_sip/__init__.py:38-43`)

```c
def asd_blas_caxpy(\n        x: torch.Tensor, y: torch.Tensor, alpha: Union[float, complex, int]\n) -> torch.Tensor:\n    if not isinstance(alpha, complex):\n        alpha = complex(alpha)\n    return torch.ops.torch_sip.asd_blas_caxpy(x, y, alpha)
```

**达成路径**

Python API (x, y not validated) -> C++ backend

**验证说明**: Description inaccurately claims 'non-tensor inputs' - PyTorch's torch.ops dispatcher validates Tensor type before calling C++. Alpha parameter IS validated (converted to complex if not already). Real vulnerability is missing shape validation for x and y tensors (CAXPY requires same shape vectors). Less severe than GEMM operations as shape mismatch would cause runtime error rather than buffer overflow. Severity downgraded from High to Medium.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -30 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (3)

### [DF-002] Missing Input Validation - asdBlasHCgemmBatched

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: dataflow-scanner

**位置**: `core/blas/gemm_batched.cpp:132` @ `asdBlasHCgemmBatched`
**模块**: core

**描述**: batchCount parameter not validated in asdBlasCgemmBatched/asdBlasHCgemmBatched functions. While m,n,k are validated (lines 100-105), batchCount is passed directly to RunAsdOpsV2 without bounds checking.

**漏洞代码** (`core/blas/gemm_batched.cpp:132`)

```c
param = {m, k, n, batchCount}; // batchCount not validated
```

**达成路径**

batchCount@external_input -> param -> RunAsdOpsV2

**验证说明**: batchCount lacks explicit bounds validation, but implicit bounds exist through tensor storage checks (lines 81-98). If batchCount mismatches tensor dimensions, the operation would fail. Impact is primarily correctness/resource exhaustion rather than memory corruption. Reduced severity to Low.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [OPS-CGETRI-001] Missing Validation - CgetriBatchedTiling

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `ops/blas/cgetri_batched/cgetri_batched/tiling/cgetri_batched_tiling.cpp:35-45` @ `CgetriBatchedTiling`
**模块**: ops

**描述**: Missing input validation for batchSize and n parameters. uint32_t batchSize and n are directly cast from param without bounds checking. No validation ensures these values are within acceptable limits before being used in device kernel operations.

**漏洞代码** (`ops/blas/cgetri_batched/cgetri_batched/tiling/cgetri_batched_tiling.cpp:35-45`)

```c
uint32_t batchSize = static_cast<uint32_t>(param.batchSize);\ntilingDataPtr->batchSize = batchSize;
```

**达成路径**

param.batchSize -> batchSize -> tilingDataPtr (device kernel)

**验证说明**: POSSIBLE: No explicit bounds validation on batchSize and n parameters before casting to uint32_t and passing to device kernel. However, this is standard BLAS library practice - parameters are assumed valid by caller. Implicit constraints from matrix dimensions (n and batchSize must fit in GPU memory) provide practical limits. Low severity as malformed input would likely fail elsewhere.

**评分明细**: base: 30 | reachability: 5 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0 | total: 50

---

### [SIP_PTA_CSRC-005] Reference Modification Issue - asdBlasCaxpy

**严重性**: Low | **CWE**: CWE-374 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `sip_pta/csrc/blas/asd_blas_caxpy.cpp:32-33` @ `asdBlasCaxpy`
**模块**: sip_pta_csrc

**描述**: asdBlasCaxpy uses y=y.contiguous() creating new tensor instead of modifying input in-place. In-place modification lost when function returns.

**验证说明**: Functional bug with limited security impact. Line 33: y = y.contiguous() creates NEW tensor and reassigns local reference. For non-contiguous y: (1) new contiguous tensor created, (2) in-place operation on new tensor, (3) original y unchanged, (4) caller expects in-place modification but gets wrong result. Functional correctness issue. CWE-374 inappropriate - better fit is data integrity concern. Severity lowered to Low since impact is computation correctness, not security compromise. Recommend fix: use y.set_data(y.contiguous()) or explicit error for non-contiguous y.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: -10 | context: 0 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| core | 0 | 5 | 2 | 1 | 8 |
| include | 0 | 0 | 0 | 0 | 0 |
| ops | 0 | 0 | 2 | 1 | 3 |
| sip_pta_csrc | 0 | 0 | 2 | 1 | 3 |
| sip_pta_python | 0 | 2 | 2 | 0 | 4 |
| **合计** | **0** | **7** | **8** | **3** | **18** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 7 | 25.0% |
| CWE-190 | 7 | 25.0% |
| CWE-628 | 5 | 17.9% |
| CWE-476 | 2 | 7.1% |
| CWE-119 | 2 | 7.1% |
| CWE-787 | 1 | 3.6% |
| CWE-664 | 1 | 3.6% |
| CWE-416 | 1 | 3.6% |
| CWE-374 | 1 | 3.6% |
| CWE-197 | 1 | 3.6% |
