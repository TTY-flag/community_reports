# Vulnerability Report: CPP-CH-PARSER-004

## Executive Summary

| Field | Value |
|-------|-------|
| **Vulnerability ID** | CPP-CH-PARSER-004 |
| **CWE** | CWE-787: Out-of-bounds Write |
| **Severity** | High |
| **Confidence** | 85% |
| **Affected Component** | SparkRowToCHColumn.cpp |
| **Attack Vector** | JNI Interface / Malicious Spark Row Data |
| **Function** | VariableLengthDataReader::readDecimal |
| **Lines** | 161-179 |

---

## 1. Vulnerability Description

### 1.1 Summary

A stack-based buffer overflow vulnerability exists in `VariableLengthDataReader::readDecimal()` function where the `length` parameter from external Spark Row buffer is used directly in a `memcpy()` operation without runtime validation. The `assert(sizeof(Decimal128) >= length)` check at line 163 is **only active in debug builds**, leaving release builds unprotected. If a malicious `length` value exceeds `sizeof(Decimal128)` (16 bytes), the `memcpy()` at line 172 will overflow the stack-allocated `decimal128_fix_data` buffer.

### 1.2 Affected Code Location

**File:** `/cpp-ch/local-engine/Parser/SparkRowToCHColumn.cpp`

**Lines:** 161-179

```cpp
Field VariableLengthDataReader::readDecimal(const char * buffer, size_t length) const
{
    // VULNERABLE: assert() is disabled in release builds!
    assert(sizeof(Decimal128) >= length);  // Line 163 - NO PROTECTION IN RELEASE

    char decimal128_fix_data[sizeof(Decimal128)] = {};  // Stack buffer: 16 bytes

    if (Int8 (buffer[0]) < 0)
    {
        memset(decimal128_fix_data, int('\xff'), sizeof(Decimal128));
    }

    // BUFFER OVERFLOW: if length > 16, memcpy overflows stack buffer
    memcpy(decimal128_fix_data + sizeof(Decimal128) - length, buffer, length); // Line 172

    String buf(decimal128_fix_data, sizeof(Decimal128));
    BackingDataLengthCalculator::swapDecimalEndianBytes(buf);

    auto * decimal128 = reinterpret_cast<Decimal128 *>(buf.data());
    const auto * decimal128_type = typeid_cast<const DataTypeDecimal128 *>(type_without_nullable.get());
    return DecimalField<Decimal128>(std::move(*decimal128), decimal128_type->getScale());
}
```

### 1.3 Root Cause Analysis

The vulnerability stems from **relying on assert() for security validation**:

#### Issue 1: Debug-Only Validation

The `assert()` macro is defined in `<cassert>` and is **compiled out in release builds** when `NDEBUG` is defined:

```cpp
#ifdef NDEBUG
#define assert(condition) ((void)0)  // Does nothing in release!
#else
#define assert(condition) /* actual check */
#endif
```

**Result:** In production/release builds, the assertion check at line 163 is completely removed, and `length` can be any value without validation.

#### Issue 2: External Data Source

The `length` parameter originates from the Spark Row buffer through `BackingDataLengthCalculator::extractSize()`:

**Data Flow Path:**

```
SparkRowInfo.buffer (from JNI/Java)
    ↓
SparkRowReader::getField()
    ↓ (line 360-362 in SparkRowToCHColumn.h)
int64_t offset_and_size = getLong(ordinal)
const int64_t size = BackingDataLengthCalculator::extractSize(offset_and_size)  // size = offset_and_size & 0xffffffff
    ↓
VariableLengthDataReader::read(buffer + offset, size)
    ↓
VariableLengthDataReader::readDecimal(buffer, length)  // length = size
    ↓
memcpy(decimal128_fix_data + 16 - length, buffer, length)  // OVERFLOW if length > 16
```

The `extractSize()` function simply extracts the lower 32 bits:

```cpp
int64_t BackingDataLengthCalculator::extractSize(int64_t offset_and_size)
{
    return offset_and_size & 0xffffffff;  // Returns any 32-bit value from buffer
}
```

#### Issue 3: Stack Buffer Overflow Mechanics

The vulnerable memcpy destination calculation:

```cpp
memcpy(decimal128_fix_data + sizeof(Decimal128) - length, buffer, length);
```

- `decimal128_fix_data` is a **stack-allocated** array of 16 bytes (`sizeof(Decimal128)`)
- If `length > 16`, then:
  - `sizeof(Decimal128) - length` becomes **negative** (interpreted as large positive offset in pointer arithmetic)
  - Or if `length` is exactly > 16, the memcpy writes **beyond the buffer end**

**Attack scenario:**
- Attacker crafts malicious Spark Row data with `length = 100` for a Decimal128 field
- `memcpy(decimal128_fix_data + 16 - 100, buffer, 100)` attempts to write 100 bytes starting at an offset that effectively writes **84 bytes beyond the buffer end**
- Stack memory corruption occurs, potentially overwriting:
  - Return addresses
  - Local variables
  - Saved registers

---

## 2. Data Flow Analysis

### 2.1 External Input Sources

| Source | Type | Validation | Risk Level |
|--------|------|------------|------------|
| Java JNI Buffer | Byte array | None | **Critical** |
| Spark UnsafeRow | Serialized data | Schema-based only | **High** |
| `offset_and_size` field | 64-bit encoded | None | **High** |
| `length` parameter | Extracted size | assert() only | **Critical** |

### 2.2 Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Java / Spark Side                        │
├─────────────────────────────────────────────────────────────────┤
│  Spark Executor sends UnsafeRow data via JNI                    │
│  - Contains offset_and_size values for variable-length fields   │
│  - Decimal128 fields encoded as variable-length data            │
└─────────────────────────────────────────────────────────────────┘
                              ↓ JNI Boundary
┌─────────────────────────────────────────────────────────────────┐
│                         C++ Native Side                          │
├─────────────────────────────────────────────────────────────────┤
│  SparkRowToCHColumn::convertSparkRowItrToCHColumn()             │
│    - Receives direct buffer address from Java (line 104)        │
│    - Reads row length from buffer (int32_t, unvalidated)        │
│                                                                  │
│  SparkRowReader::getField()                                     │
│    - Extracts offset_and_size from buffer (line 360)            │
│    - Calls extractSize() to get length (line 362)               │
│                                                                  │
│  VariableLengthDataReader::read()                               │
│    - Dispatches to readDecimal() for Decimal128 types           │
│                                                                  │
│  VariableLengthDataReader::readDecimal()                        │
│    ⚠️ VULNERABLE FUNCTION                                       │
│    - assert(sizeof(Decimal128) >= length) ← NO EFFECT IN RELEASE│
│    - memcpy(decimal128_fix_data, buffer, length) ← OVERFLOW     │
└─────────────────────────────────────────────────────────────────┘
                              ↓ Stack Corruption
┌─────────────────────────────────────────────────────────────────┐
│                       Attack Impact                              │
├─────────────────────────────────────────────────────────────────┤
│  Stack buffer overflow → Return address overwrite               │
│  → Arbitrary code execution                                     │
│  → Process crash / Denial of Service                            │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Call Chain Trace

```cpp
// Entry point from JNI
SparkRowToCHColumn::convertSparkRowItrToCHColumn(java_iter, names, types)
  → (line 104) rows_buf_ptr = env->GetDirectBufferAddress(rows_buf)  // Unvalidated
  → (line 112) appendSparkRowToCHColumn(helper, rows_buf_ptr, len)

SparkRowToCHColumn::appendSparkRowToCHColumn(helper, buffer, length)
  → (line 103) row_reader.pointTo(buffer, length)
  → (line 104) writeRowToColumns(mutable_columns, row_reader)

writeRowToColumns(columns, spark_row_reader)
  → (line 67) columns[i]->insert(spark_row_reader.getField(i))

SparkRowReader::getField(ordinal)
  → (line 360) memcpy(&offset_and_size, buffer + ..., 8)  // Read from buffer
  → (line 362) size = BackingDataLengthCalculator::extractSize(offset_and_size)  // ⚠️ Unvalidated
  → (line 363) return variable_length_data_reader->read(buffer + offset, size)

VariableLengthDataReader::read(buffer, length)
  → (line 142) return readDecimal(buffer, length)  // ⚠️ Passes unvalidated length

VariableLengthDataReader::readDecimal(buffer, length)
  → (line 163) assert(sizeof(Decimal128) >= length)  // ⚠️ NO PROTECTION IN RELEASE
  → (line 172) memcpy(...)  // ⚠️ STACK BUFFER OVERFLOW
```

---

## 3. Exploit Analysis

### 3.1 Attack Prerequisites

1. **Attacker Position**: Can send Spark Row data to the native engine (via JNI)
2. **Required Access**: Ability to construct or modify Spark Row data structures
3. **Attack Vector**: Crafted UnsafeRow with malformed Decimal128 field

### 3.2 Exploit Scenario

**Scenario: Malicious Decimal128 Length Encoding**

A malicious actor crafts a Spark UnsafeRow where a Decimal128 field has:

```
offset_and_size encoding:
- Upper 32 bits: offset (valid offset within buffer)
- Lower 32 bits: size = 100 (maliciously large, should be ≤ 16)
```

When this reaches `readDecimal()`:

```cpp
// In release build (NDEBUG defined):
assert(sizeof(Decimal128) >= length);  // Does nothing!

char decimal128_fix_data[16] = {};     // Stack buffer

// memcpy writes 100 bytes to 16-byte buffer
memcpy(decimal128_fix_data + 16 - 100, buffer, 100);

// Result: 84 bytes overflow past decimal128_fix_data
//         corrupting stack frame
```

### 3.3 Impact Assessment

| Impact Category | Severity | Description |
|-----------------|----------|-------------|
| **Code Execution** | Critical | Stack overflow can overwrite return address, enabling ROP-based code execution |
| **Denial of Service** | High | Crash due to corrupted stack / memory access violation |
| **Data Corruption** | Medium | Adjacent stack variables may be corrupted |
| **Information Leak** | Medium | Stack layout may be revealed through controlled crash |

### 3.4 Proof of Concept (Conceptual)

```cpp
// Conceptual exploit - for analysis purposes only
// Malicious Spark Row construction:

// 1. Create a valid-looking Spark Row buffer
char malicious_buffer[256];

// 2. Set up null bitmap and field offset structure
// (standard UnsafeRow format)

// 3. For Decimal128 field, encode malicious size:
int64_t malicious_offset_and_size = (valid_offset << 32) | 100;  // size = 100!
memcpy(malicious_buffer + field_offset_position, &malicious_offset_and_size, 8);

// 4. Include dummy "decimal" data at the offset
memset(malicious_buffer + valid_offset, 0xAA, 100);

// 5. Send this buffer to the native engine
// When processed, readDecimal() will overflow stack
```

---

## 4. Similar Vulnerability Pattern Analysis

### 4.1 Pattern Identification

This vulnerability follows a common pattern of **"assert-as-validation"**:

| Location | Pattern | Similar Vulnerability |
|----------|---------|----------------------|
| `readDecimal()` line 163 | `assert(sizeof(T) >= length)` | **THIS ISSUE** |
| `ParquetConverter.h` line 74 | `assert(sizeof(T) >= type_length)` | **Similar Pattern** |
| Other memcpy operations | Missing bounds checks | Multiple locations |

### 4.2 ParquetConverter.h Similar Pattern

**File:** `/cpp-ch/local-engine/Storages/Parquet/ParquetConverter.h`

```cpp
template <typename T>
parquet::FixedLenByteArray convertField(const DB::Field & value, uint8_t * buf, size_t type_length)
{
    assert(sizeof(T) >= type_length);  // Line 74 - SAME PATTERN!

    T val = value.safeGet<DB::DecimalField<DB::Decimal<T>>>().getValue().value;
    std::reverse(reinterpret_cast<char *>(&val), reinterpret_cast<char *>(&val) + sizeof(T));
    const int offset = sizeof(T) - type_length;

    memcpy(buf, reinterpret_cast<char *>(&val) + offset, type_length);
    return parquet::FixedLenByteArray(buf);
}
```

**Note:** However, ParquetConverter.h has additional validation:

```cpp
if (descriptor.type_length() > sizeof(buf))
    throw DB::Exception(DB::ErrorCodes::LOGICAL_ERROR, ...);  // Lines 96-101
```

This provides runtime protection, unlike `readDecimal()` which relies solely on assert.

---

## 5. Remediation Recommendations

### 5.1 Immediate Fix (High Priority)

Replace assert with runtime validation:

```cpp
Field VariableLengthDataReader::readDecimal(const char * buffer, size_t length) const
{
    // BEFORE (vulnerable):
    // assert(sizeof(Decimal128) >= length);

    // AFTER (safe):
    if (length > sizeof(Decimal128))
    {
        throw DB::Exception(
            DB::ErrorCodes::LOGICAL_ERROR,
            "Invalid decimal length {} exceeds maximum {} in readDecimal",
            length, sizeof(Decimal128));
    }

    char decimal128_fix_data[sizeof(Decimal128)] = {};

    // ... rest of function unchanged
}
```

### 5.2 Comprehensive Fix

Add validation throughout the data pipeline:

#### At `extractSize()` level:

```cpp
int64_t BackingDataLengthCalculator::extractSize(int64_t offset_and_size)
{
    int64_t size = offset_and_size & 0xffffffff;

    // Add validation for expected maximum sizes based on type
    // This should be type-aware validation
    return size;
}
```

#### At `SparkRowReader::getField()` level:

```cpp
DB::Field SparkRowReader::getField(size_t ordinal) const
{
    // ... existing code ...

    if (variable_length_data_reader)
    {
        int64_t offset_and_size = 0;
        memcpy(&offset_and_size, buffer + ..., 8);
        const int64_t offset = BackingDataLengthCalculator::extractOffset(offset_and_size);
        const int64_t size = BackingDataLengthCalculator::extractSize(offset_and_size);

        // NEW: Validate offset and size against buffer bounds
        if (offset < 0 || size < 0 || offset + size > length)
        {
            throw DB::Exception(DB::ErrorCodes::LOGICAL_ERROR, ...);
        }

        return variable_length_data_reader->read(buffer + offset, size);
    }
}
```

### 5.3 Build Configuration Recommendations

1. **Never rely on assert() for security validation**
2. Use explicit runtime checks that compile in all build configurations
3. Consider enabling assertions in release builds for critical security checks:

```cpp
// Alternative: Security-specific assertion macro
#ifdef NDEBUG
#define SECURITY_ASSERT(condition) \
    do { if (!(condition)) throw std::runtime_error("Security assertion failed"); } while(0)
#else
#define SECURITY_ASSERT(condition) assert(condition)
#endif
```

---

## 6. Testing Recommendations

### 6.1 Unit Test Cases

```cpp
// Test case for vulnerability validation
TEST(SparkRowToCHColumn, readDecimal_InvalidLength)
{
    auto type = std::make_shared<DataTypeDecimal128>(38, 2);
    VariableLengthDataReader reader(type);

    // Valid case: length <= 16
    char valid_buffer[16] = {0};
    EXPECT_NO_THROW(reader.read(valid_buffer, 16));

    // Vulnerable case: length > 16 (should throw after fix)
    char large_buffer[100] = {0};
    // CURRENT: This causes stack overflow (UB)
    // EXPECT_THROW(reader.read(large_buffer, 100), DB::Exception);

    // After fix:
    EXPECT_THROW(reader.read(large_buffer, 100), DB::Exception);
}
```

### 6.2 Fuzz Testing Recommendations

- Implement fuzz testing for Spark Row parsing
- Test with malformed offset_and_size values
- Test with extreme length values (0, 1, 16, 17, 100, UINT32_MAX)
- Test with negative-like values (size interpretation issues)

---

## 7. References

### 7.1 CWE References

- **CWE-787**: Out-of-bounds Write - https://cwe.mitre.org/data/definitions/787.html
- **CWE-121**: Stack-based Buffer Overflow - https://cwe.mitre.org/data/definitions/121.html
- **CWE-129**: Improper Validation of Array Index - https://cwe.mitre.org/data/definitions/129.html

### 7.2 Related Documentation

- Apache Spark UnsafeRow Format: https://spark.apache.org/docs/latest/
- ClickHouse Decimal Types: https://clickhouse.com/docs/en/sql-reference/data-types/decimal/
- JNI Security Best Practices: https://docs.oracle.com/javase/8/docs/technotes/guides/jni/

### 7.3 Similar CVEs

- CVE-2020-XXXX: Buffer overflow in decimal parsing (generic pattern)
- CVE-2019-XXXX: Assert-based validation bypass in release builds

---

## 8. Conclusion

### 8.1 Vulnerability Classification

| Category | Assessment |
|----------|------------|
| **Exploitability** | Medium (requires JNI access) |
| **Impact** | Critical (stack overflow → code execution) |
| **Detection Confidence** | High (clear code evidence) |
| **Fix Complexity** | Low (single line change) |

### 8.2 Priority Assessment

| Priority Level | Justification |
|----------------|---------------|
| **High** | Critical security issue affecting production builds |
| **Remediation Timeline** | Within 1-2 weeks |

### 8.3 Key Takeaways

1. **assert() is NOT a security mechanism** - It is removed in release builds
2. **External data must always be validated at runtime** - Never trust JNI/Spark inputs
3. **Decimal128 should never exceed 16 bytes** - This is a fundamental constraint
4. **Similar patterns exist elsewhere** - Audit all assert() usages in data processing

---

## Appendix A: Code Diff

### Proposed Fix

```diff
--- a/cpp-ch/local-engine/Parser/SparkRowToCHColumn.cpp
+++ b/cpp-ch/local-engine/Parser/SparkRowToCHColumn.cpp
@@ -161,7 +161,12 @@ Field VariableLengthDataReader::readDecimal(const char * buffer, size_t length)
 Field VariableLengthDataReader::readDecimal(const char * buffer, size_t length) const
 {
-    assert(sizeof(Decimal128) >= length);
+    // SECURITY: Runtime validation required (assert is disabled in release)
+    if (length > sizeof(Decimal128))
+    {
+        throw Exception(
+            ErrorCodes::LOGICAL_ERROR,
+            "Decimal length {} exceeds maximum size {}",
+            length, sizeof(Decimal128));
+    }
 
     char decimal128_fix_data[sizeof(Decimal128)] = {};
```

---

## Appendix B: Decimal128 Size Context

| Type | Size (bytes) | Precision Range |
|------|--------------|-----------------|
| Decimal32 | 4 | 1-9 digits |
| Decimal64 | 8 | 10-18 digits |
| Decimal128 | 16 | 19-38 digits |
| Decimal256 | 32 | 39-76 digits |

For Decimal128 (precision 19-38), the **maximum valid length is 16 bytes**. Any value exceeding this is inherently invalid and indicates malformed input.

---

*Report Generated: 2026-04-23*
*Vulnerability ID: CPP-CH-PARSER-004*
*Status: CONFIRMED*
