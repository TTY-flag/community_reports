# VULN-SEC-TENSOR-001: Buffer Over-read in Tensor Constructor and Clone Method

## Vulnerability Summary

| Attribute | Value |
|-----------|-------|
| **CWE ID** | CWE-125: Out-of-bounds Read |
| **Severity** | High |
| **Trust Level** | untrusted_external |
| **Affected Module** | tensor |
| **Primary Location** | `AccSDK/source/tensor/Tensor.cpp:83` |
| **Secondary Locations** | `AccSDK/source/tensor/Tensor.cpp:121`, `AccSDK/source/py/module/PyTensor.cpp:102`, `AccSDK/source/py/module/PyUtil.cpp:84` |

## Vulnerability Description

The `Tensor` constructor accepts a user-provided buffer pointer (`void* data`) and shape vector without validating that the actual buffer size matches the expected size calculated from the shape. When the `Clone()` method is subsequently called, it reads `totalBytes` bytes from the buffer, potentially reading beyond the actual allocated memory if the user-provided shape is larger than the actual data.

This is a **CWE-125: Out-of-bounds Read** vulnerability that can lead to:
1. **Information Disclosure**: Reading sensitive data from adjacent memory
2. **Denial of Service**: Application crash when reading unmapped memory
3. **Memory Corruption**: Potential for exploitation depending on what data is read

## Call Chain Analysis

```
Python Layer                    C++ Binding Layer                    Core C++ Layer
─────────────────────────────────────────────────────────────────────────────────────────
PyTensor.from_numpy()     →     PyUtil.cpp: GetNumpyData()      →    Tensor.cpp:83 Tensor()
     │                               │                                    │
     │ PyObject* numpy array         │ Extract dataPtr, shape             │ CheckTensorParams()
     │                               │ from __array_interface__            │ (null check only)
     │                               │ NO SIZE VALIDATION                 │
     │                               │                                    ▼
     │                               │                          FillAuxInfo()
     │                               │                          (calculate totalBytes)
     │                               │                                    │
     └───────────────────────────────┴────────────────────────────────────┘
                                                                          │
                                          Clone() called ──────────────────┘
                                               │
                                               ▼
                                    memcpy_s(..., totalBytes)  [SINK - over-read]
```

### Layer 1: Python Entry Point (`PyTensor.cpp:99-106`)

```cpp
Tensor Tensor::from_numpy(PyObject* pyObj)
{
    NumpyData numpyData = GetNumpyData(pyObj);
    // VULNERABILITY: numpyData.dataPtr and numpyData.shape come from user input
    // No validation that the actual buffer size matches shape
    Acc::Tensor accTensor(numpyData.dataPtr, numpyData.shape, numpyData.dataType, Acc::TensorFormat::ND, "cpu");
    Tensor tensor;
    tensor.SetTensor(accTensor);
    return tensor;
}
```

**Security Control**: None - user-controlled numpy array is passed directly.

### Layer 2: Numpy Data Extraction (`PyUtil.cpp:47-137`)

```cpp
NumpyData GetNumpyData(PyObject* pyObj)
{
    // ...
    // Get data pointer from __array_interface__
    PyObject *dataPtrObj = PyTuple_GetItem(dataTuple, 0);
    numpyData.dataPtr = reinterpret_cast<void*>(PyLong_AsVoidPtr(dataPtrObj));
    if (PyErr_Occurred() || !numpyData.dataPtr) {
        throw std::runtime_error("Failed to get valid data pointer...");
    }
    // VULNERABILITY: Only checks that pointer is non-null, NOT that buffer is large enough
    
    // Get shape from __array_interface__
    for (Py_ssize_t i = 0; i < PyTuple_Size(shapeTuple); i++) {
        PyObject *dim = PyTuple_GetItem(shapeTuple, i);
        size_t dimSize = PyLong_AsSize_t(dim);  // User-controlled value
        numpyData.shape.push_back(dimSize);
    }
    // VULNERABILITY: Shape is user-controlled and not validated against actual buffer size
    // ...
}
```

**Security Control**: Only validates non-null pointer, does not validate buffer size against shape.

### Layer 3: Tensor Constructor (`Tensor.cpp:83-93`)

```cpp
Tensor::Tensor(void* data, const std::vector<size_t>& shape, DataType dataType, TensorFormat format, const char* device)
    : deviceId_(DEVICE_CPU),
      shape_(shape),
      dataType_(dataType),
      format_(format),
      dataPtr_(std::shared_ptr<void>(data, [](void*) {})),  // Takes ownership without size info
      device_(device ? device : "")
{
    CheckTensorParams();  // Only validates: dataPtr != nullptr, shape.size() > 0, format constraints
    FillAuxInfo();        // Calculates: totalBytes = product(shape) * elementSize
}
```

**Critical Vulnerability**: 
- `dataPtr_` stores the pointer without any size information
- `CheckTensorParams()` does NOT validate buffer size
- `FillAuxInfo()` calculates `totalBytes` based solely on user-provided `shape`

### Layer 4: AuxInfo Calculation (`Tensor.cpp:37-60`)

```cpp
void Tensor::FillAuxInfo()
{
    // Calculate caches
    auxInfo_.elementNums =
        std::accumulate(shape_.begin(), shape_.end(), static_cast<size_t>(1), std::multiplies<size_t>());
    auxInfo_.perElementBytes = GetByteSize(dataType_);
    auxInfo_.totalBytes = auxInfo_.elementNums * auxInfo_.perElementBytes;  // Based on user-provided shape!
    // ...
}
```

**Vulnerability**: `totalBytes` is calculated from user-controlled `shape_` without validation against actual buffer size.

### Layer 5: Clone Method - SINK (`Tensor.cpp:108-129`)

```cpp
ErrorCode Tensor::Clone(Tensor& tensor) const
{
    if (dataPtr_ == nullptr || auxInfo_.totalBytes == 0) {
        LogWarn << "Current tensor is empty, the clone operation is invalid.";
        return SUCCESS;
    }
    // Allocate based on totalBytes calculated from user-provided shape
    char* data = new(std::nothrow) char[auxInfo_.totalBytes];
    if (data == nullptr) {
        LogError << "Failed to malloc for tensor." << GetErrorInfo(ERR_BAD_ALLOC);
        return ERR_BAD_ALLOC;
    }
    std::shared_ptr<void> dstPtr(static_cast<void*>(data), [](void* ptr) { delete[] static_cast<char*>(ptr); });
    // VULNERABILITY: Reads totalBytes from user buffer without knowing actual size
    auto ret = memcpy_s(dstPtr.get(), auxInfo_.totalBytes, dataPtr_.get(), auxInfo_.totalBytes);
    // If actual buffer < totalBytes → OUT-OF-BOUNDS READ
    if (ret != SUCCESS) {
        LogError << "Tensor clone failed..." << GetErrorInfo(ERR_BAD_COPY);
        return ERR_BAD_COPY;
    }
    tensor = Tensor(dstPtr, shape_, dataType_, format_, this->Device().get());
    return SUCCESS;
}
```

**VULNERABILITY SINK**: `memcpy_s()` reads `totalBytes` bytes from `dataPtr_` without knowing the actual allocated size of the buffer.

## Proof of Concept

### Attack Vector 1: Python API Direct Exploitation

```python
import numpy as np
from mm.acc.wrapper.tensor_wrapper import Tensor

# Create a small buffer (100 bytes)
small_array = np.zeros((100,), dtype=np.uint8)
tensor = Tensor.from_numpy(small_array)

# Maliciously modify the internal shape (simulating a crafted input)
# In a real attack, this would be done by crafting a malicious numpy array
# with manipulated __array_interface__ metadata

# Alternative attack vector: Direct C++ manipulation
# The attacker creates a malicious object with __array_interface__:
class MaliciousArray:
    @property
    def __array_interface__(self):
        return {
            'version': 3,
            'data': (actual_buffer_address, False),  # Small buffer
            'shape': (1000000, 1000000),  # Huge shape
            'typestr': '<f4'  # float32 = 4 bytes per element
        }

# This would cause the Tensor to calculate totalBytes = 1000000 * 1000000 * 4 = 4TB
# And Clone() would attempt to read 4TB from the small buffer
```

### Attack Vector 2: Image Processing Pipeline

```python
# Image data flows through the pipeline:
# Image file → Decode → Tensor → Model inference
# 
# If image decoding produces a buffer smaller than expected shape:
# (e.g., truncated image file, corrupted header)
#
# The Tensor constructor has no way to verify the actual buffer size
# Subsequent Clone() or tensor operations will read out-of-bounds
```

## Impact Assessment

| Factor | Assessment |
|--------|-------------|
| **Attack Complexity** | Low - Straightforward exploitation via Python API |
| **Privileges Required** | None - Any user with SDK access |
| **User Interaction** | None - Can be triggered programmatically |
| **Scope** | Unchanged - Affects only the vulnerable process |
| **Confidentiality Impact** | High - Can read arbitrary process memory |
| **Integrity Impact** | None - Read-only vulnerability |
| **Availability Impact** | High - Can cause crash via SIGSEGV |

**CVSS v3.1 Score**: 8.6 (High) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H

## Root Cause Analysis

The vulnerability stems from a fundamental design issue:

1. **Missing Size Parameter**: The `Tensor` constructor accepts `void* data` but no `size_t bufferSize` parameter to validate against the calculated `totalBytes`.

2. **Trust Without Verification**: The code trusts that the caller provides a buffer of the correct size but has no way to verify this.

3. **Inconsistent Information Flow**: Shape information flows from user input through the entire pipeline, but actual buffer size information is lost at the Python-C++ boundary.

**Vulnerable Design Pattern**:
```
User Input (shape) → Trust → Calculate totalBytes → Read that many bytes
                                        ↑
                                   No validation against actual buffer
```

## Recommendations

### Immediate (High Priority)

1. **Add Buffer Size Parameter to Constructor**:

```cpp
// Modify Tensor constructor signature
Tensor::Tensor(void* data, size_t bufferSize, const std::vector<size_t>& shape, 
               DataType dataType, TensorFormat format, const char* device)
{
    CheckTensorParams();
    FillAuxInfo();
    // Validate buffer size
    if (auxInfo_.totalBytes > bufferSize) {
        LogError << "Buffer size mismatch: shape requires " << auxInfo_.totalBytes 
                 << " bytes but only " << bufferSize << " provided.";
        throw std::runtime_error("Buffer size mismatch");
    }
}
```

2. **Validate in Python Binding Layer**:

```cpp
// In PyUtil.cpp: GetNumpyData()
NumpyData GetNumpyData(PyObject* pyObj)
{
    // ... existing code ...
    
    // Add: Get strides information to validate buffer
    PyObject *stridesTuple = PyDict_GetItemString(arrayInterface, "strides");
    // Calculate actual buffer size from shape and strides
    
    // Add: Validate buffer is large enough
    size_t requiredSize = CalculateRequiredSize(numpyData.shape, numpyData.dataType);
    // Note: This still doesn't fully solve the problem since we can't know actual buffer size
    // from __array_interface__ alone - need to add explicit size parameter
}
```

### Short-term (Medium Priority)

3. **Add Safe Clone Method with Bounds Checking**:

```cpp
ErrorCode Tensor::CloneWithValidation(Tensor& tensor, size_t knownBufferSize) const
{
    if (auxInfo_.totalBytes > knownBufferSize) {
        LogError << "Clone rejected: buffer undersized";
        return ERR_INVALID_PARAM;
    }
    return Clone(tensor);
}
```

4. **Add Python-level Validation**:

```python
# In tensor_wrapper.py
@staticmethod
def from_numpy(array: np.ndarray) -> "Tensor":
    # Validate that array is contiguous and owns its data
    if not array.flags['C_CONTIGUOUS']:
        array = np.ascontiguousarray(array)
    
    # Calculate expected size
    expected_size = array.nbytes
    
    # Pass size to C++ for validation
    return _acc.Tensor.from_numpy_with_size(array, expected_size)
```

### Long-term (Low Priority)

5. **Redesign Memory Ownership Model**:

Consider using a RAII-based buffer wrapper that includes size information:

```cpp
class TensorBuffer {
    void* data_;
    size_t size_;
public:
    TensorBuffer(size_t size) : size_(size) {
        data_ = new char[size];
    }
    size_t size() const { return size_; }
    // ...
};

// Tensor takes ownership of TensorBuffer, not raw void*
Tensor::Tensor(TensorBuffer&& buffer, const std::vector<size_t>& shape, ...);
```

## Related Vulnerabilities

None directly related in this codebase, but similar patterns may exist in:
- Image module (Image::Image with buffer pointers)
- Video module (video frame buffers)

## References

- CWE-125: Out-of-bounds Read
- [OWASP Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
- [NIST CWE-125](https://cwe.mitre.org/data/definitions/125.html)

## Appendix: File References

| File | Lines | Purpose |
|------|-------|---------|
| `AccSDK/source/tensor/Tensor.cpp` | 83-93 | Tensor constructor (vulnerable) |
| `AccSDK/source/tensor/Tensor.cpp` | 108-129 | Clone method (sink) |
| `AccSDK/source/tensor/Tensor.cpp` | 37-60 | FillAuxInfo (size calculation) |
| `AccSDK/source/tensor/Tensor.cpp` | 62-81 | CheckTensorParams (missing size check) |
| `AccSDK/source/py/module/PyTensor.cpp` | 99-106 | Python binding entry point |
| `AccSDK/source/py/module/PyUtil.cpp` | 47-137 | Numpy data extraction |
| `AccSDK/source/py/module/PyImage.cpp` | 158-203 | Image::from_numpy (similar pattern) |
| `AccSDK/include/acc/tensor/Tensor.h` | 96-97 | Constructor declaration |
