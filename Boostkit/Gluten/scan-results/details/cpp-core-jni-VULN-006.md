# Vulnerability Report: cpp-core-jni-VULN-006

## Summary

| Field | Value |
|-------|-------|
| **Vulnerability ID** | cpp-core-jni-VULN-006 |
| **Type** | Improper Input Validation (CWE-20) |
| **Severity** | High |
| **Confidence** | 85% (Confirmed) |
| **File** | `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp/core/jni/JniWrapper.cc` |
| **Lines** | 680-705 |
| **Function** | `Java_org_apache_gluten_vectorized_NativeRowToColumnarJniWrapper_nativeConvertRowToColumnar` |
| **Trust Boundary** | JNI Interface (High Risk) |

## Description

Unsafe pointer casting in JNI boundary functions. Memory addresses (`memoryAddress`, `cSchema`) from JVM are directly cast to pointers without validation. Arbitrary memory addresses passed by malicious code or corrupted data could lead to memory corruption, information disclosure, or arbitrary code execution.

## Affected Code Locations

### Primary Vulnerability (Lines 684-705)

```cpp
JNIEXPORT jlong JNICALL
Java_org_apache_gluten_vectorized_NativeRowToColumnarJniWrapper_nativeConvertRowToColumnar(
    JNIEnv* env,
    jobject wrapper,
    jlong r2cHandle,
    jlongArray rowLength,
    jlong memoryAddress) {
  JNI_METHOD_START
  auto ctx = getRuntime(env, wrapper);

  if (rowLength == nullptr) {
    throw GlutenException("Native convert row to columnar: buf_addrs can't be null");
  }
  int numRows = env->GetArrayLength(rowLength);
  auto safeArray = getLongArrayElementsSafe(env, rowLength);
  // VULNERABLE: memoryAddress cast without validation
  uint8_t* address = reinterpret_cast<uint8_t*>(memoryAddress);

  auto converter = ObjectStore::retrieve<RowToColumnarConverter>(r2cHandle);
  auto cb = converter->convert(numRows, safeArray.elems(), address);
  return ctx->saveObject(cb);
  JNI_METHOD_END(kInvalidObjectHandle)
}
```

### Secondary Vulnerability (Lines 673-682)

```cpp
JNIEXPORT jlong JNICALL Java_org_apache_gluten_vectorized_NativeRowToColumnarJniWrapper_init(
    JNIEnv* env,
    jobject wrapper,
    jlong cSchema) {
  JNI_METHOD_START
  auto ctx = getRuntime(env, wrapper);
  // VULNERABLE: cSchema cast without validation
  return ctx->saveObject(ctx->createRow2ColumnarConverter(reinterpret_cast<struct ArrowSchema*>(cSchema)));
  JNI_METHOD_END(kInvalidObjectHandle)
}
```

## Additional Affected Locations

The same pattern exists in multiple other JNI functions in this file:

| Location | Function | Parameter |
|----------|----------|-----------|
| Line 766 | `exportToArrow` | `cSchema`, `cArray` |
| Line 790 | `createWithArrowArray` | `cSchema`, `cArray` |
| Line 1095 | `ShuffleReaderJniWrapper::make` | `cSchema` |
| Line 1182 | `ColumnarBatchSerializerJniWrapper::init` | `cSchema` |

## Data Flow Analysis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TRUST BOUNDARY: JVM → Native                        │
└─────────────────────────────────────────────────────────────────────────────┘

Java Layer:
  NativeRowToColumnarJniWrapper.java
    native long nativeConvertRowToColumnar(long r2cHandle, long[] rowLength, long bufferAddress)
    native long init(long cSchema)

Scala Caller:
  RowToVeloxColumnarExec.scala:223
    jniWrapper.nativeConvertRowToColumnar(r2cHandle, rowLength.toArray, arrowBuf.memoryAddress())

JNI Interface:
  JniWrapper.cc:699
    uint8_t* address = reinterpret_cast<uint8_t*>(memoryAddress);  ← NO VALIDATION
    converter->convert(numRows, safeArray.elems(), address);

Internal Processing:
  VeloxRowToColumnarConverter.cc:275
    data.emplace_back(std::string_view(reinterpret_cast<const char*>(memoryAddress + offset), rowLength[i]));
  VeloxRowToColumnarConverter.cc:299
    VELOX_DYNAMIC_SCALAR_TYPE_DISPATCH_ALL(createFlatVector, ..., memoryAddress, pool_.get());
```

## Control Flow

```
JVM (cSchema, memoryAddress as jlong)
    │
    ▼
JNI Entry: nativeConvertRowToColumnar / init
    │
    ▼
reinterpret_cast<ArrowSchema*>(cSchema)  ← Direct cast, no validation
reinterpret_cast<uint8_t*>(memoryAddress) ← Direct cast, no validation
    │
    ▼
ObjectStore::retrieve<RowToColumnarConverter>(r2cHandle)
    │
    ▼
converter->convert(numRows, rowLength, address)
    │
    ▼
VeloxRowToColumnarConverter::convert() → Memory Access
```

## Vulnerability Details

### Missing Validation Checks

1. **Null Pointer Check**: No check that `memoryAddress` or `cSchema` are non-zero before casting
2. **Bounds Validation**: No validation that the memory region at `memoryAddress` contains valid data
3. **Schema Validation**: No validation that `cSchema` points to a valid ArrowSchema structure
4. **Size Validation**: No validation that the memory region size matches expected row data
5. **Alignment Check**: No check for proper memory alignment

### Attack Vector

A malicious or compromised JVM could:
1. Pass `memoryAddress = 0` (null pointer) → Causes segmentation fault
2. Pass arbitrary address → Read/write arbitrary memory
3. Pass address pointing to sensitive data → Information disclosure
4. Pass address pointing to code regions → Potential code execution

### Impact Assessment

| Impact | Severity |
|--------|----------|
| Memory Corruption | Critical |
| Information Disclosure | High |
| Denial of Service | High |
| Arbitrary Code Execution | Medium (requires precise address knowledge) |

## Proof of Concept

### Scenario 1: Null Pointer Dereference

```java
// Malicious Java code
jniWrapper.nativeConvertRowToColumnar(handle, lengths, 0L);  // Pass 0 as memoryAddress
// Native code: uint8_t* address = reinterpret_cast<uint8_t*>(0);
// → Segmentation fault when accessing address
```

### Scenario 2: Arbitrary Memory Read

```java
// Malicious Java code
long arbitraryAddress = 0x7fff12345678L;  // Known kernel/user space address
jniWrapper.nativeConvertRowToColumnar(handle, lengths, arbitraryAddress);
// → Reads arbitrary memory, potentially exposing secrets
```

## Existing Mitigations

| Mitigation | Status | Details |
|------------|--------|---------|
| JNI_METHOD_START/END | Partial | Exception handling exists but doesn't prevent invalid access |
| rowLength null check | Present | Only checks rowLength array, not memoryAddress |
| GLUTEN_CHECK/GLUTEN_DCHECK | Available | Not applied to pointer validation |
| jniCastOrThrow | Available | Used for handles but not for memory addresses |

**No validation exists for `memoryAddress` or `cSchema` pointer parameters.**

## Recommended Remediation

### Immediate Fix (High Priority)

```cpp
JNIEXPORT jlong JNICALL
Java_org_apache_gluten_vectorized_NativeRowToColumnarJniWrapper_nativeConvertRowToColumnar(
    JNIEnv* env,
    jobject wrapper,
    jlong r2cHandle,
    jlongArray rowLength,
    jlong memoryAddress) {
  JNI_METHOD_START
  auto ctx = getRuntime(env, wrapper);

  // Add null/zero address validation
  GLUTEN_CHECK(memoryAddress != 0, "memoryAddress cannot be null or zero");
  
  if (rowLength == nullptr) {
    throw GlutenException("Native convert row to columnar: buf_addrs can't be null");
  }
  int numRows = env->GetArrayLength(rowLength);
  
  // Validate numRows is reasonable
  GLUTEN_CHECK(numRows > 0 && numRows < INT_MAX, "Invalid numRows value");
  
  auto safeArray = getLongArrayElementsSafe(env, rowLength);
  
  // Validate rowLength values
  int64_t totalSize = 0;
  for (int i = 0; i < numRows; i++) {
    GLUTEN_CHECK(safeArray.elems()[i] >= 0, "Invalid row length at index " + std::to_string(i));
    totalSize += safeArray.elems()[i];
  }
  
  // Additional: could validate address is within expected memory region
  // This requires tracking allocated buffers in the Java side
  
  uint8_t* address = reinterpret_cast<uint8_t*>(memoryAddress);

  auto converter = ObjectStore::retrieve<RowToColumnarConverter>(r2cHandle);
  auto cb = converter->convert(numRows, safeArray.elems(), address);
  return ctx->saveObject(cb);
  JNI_METHOD_END(kInvalidObjectHandle)
}
```

### Schema Validation Fix

```cpp
JNIEXPORT jlong JNICALL Java_org_apache_gluten_vectorized_NativeRowToColumnarJniWrapper_init(
    JNIEnv* env,
    jobject wrapper,
    jlong cSchema) {
  JNI_METHOD_START
  auto ctx = getRuntime(env, wrapper);

  // Validate cSchema is non-null
  GLUTEN_CHECK(cSchema != 0, "cSchema address cannot be null or zero");
  
  auto* schemaPtr = reinterpret_cast<struct ArrowSchema*>(cSchema);
  
  // Validate ArrowSchema structure
  GLUTEN_CHECK(schemaPtr->release != nullptr, "ArrowSchema must have a valid release function");
  // Optionally validate schema structure integrity
  
  return ctx->saveObject(ctx->createRow2ColumnarConverter(schemaPtr));
  JNI_METHOD_END(kInvalidObjectHandle)
}
```

### Long-term Security Architecture

1. **Token-based Address Verification**: Maintain a registry of valid memory addresses allocated through controlled APIs
2. **Memory Pool Tracking**: Track all memory allocations and validate addresses against known pools
3. **Bounds Checking**: Pass size information alongside addresses and validate before access
4. **Secure JNI Wrapper Class**: Create a validated wrapper for all pointer-style JNI parameters

## References

- **CWE-20**: Improper Input Validation - https://cwe.mitre.org/data/definitions/20.html
- **CWE-119**: Improper Restriction of Operations within the Bounds of a Memory Buffer
- **JNI Best Practices**: https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/design.html
- **Arrow C Data Interface**: https://arrow.apache.org/docs/format/CDataInterface.html

## Related Files

| File | Role |
|------|------|
| `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp/core/jni/JniWrapper.cc` | Primary vulnerable file |
| `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp/core/jni/JniCommon.h` | JNI helper functions |
| `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp/velox/operators/serializer/VeloxRowToColumnarConverter.cc` | Memory consumer |
| `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/gluten-arrow/src/main/java/org/apache/gluten/vectorized/NativeRowToColumnarJniWrapper.java` | Java JNI declaration |
| `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/backends-velox/src/main/scala/org/apache/gluten/execution/RowToVeloxColumnarExec.scala` | Scala caller |

## Verification Checklist

- [x] Confirmed vulnerable code exists at specified lines
- [x] Verified no existing validation for `memoryAddress` parameter
- [x] Verified no existing validation for `cSchema` parameter  
- [x] Traced data flow from JVM to native memory access
- [x] Identified additional affected functions with same pattern
- [x] Assessed attack vectors and impact
- [x] Provided concrete remediation recommendations

---

**Report Generated**: 2026-04-23  
**Scanner Version**: OpenCode Security Scanner  
**Analysis Type**: Static Code Analysis + Data Flow Tracing
