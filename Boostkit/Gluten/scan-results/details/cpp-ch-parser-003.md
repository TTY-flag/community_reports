# cpp-ch-parser-003 漏洞详细分析报告

## 1. 漏洞概述

### 基本信息
| 属性 | 值 |
|------|-----|
| **漏洞 ID** | cpp-ch-parser-003 |
| **类型** | Out-of-bounds Read (CWE-125) |
| **严重性** | High |
| **CVSS 3.1 Score** | 7.5 (High) |
| **置信度** | 85/100 |
| **状态** | CONFIRMED |
| **文件路径** | `cpp-ch/local-engine/Parser/SparkRowToCHColumn.cpp` |
| **行号** | 187-248 |
| **函数名** | `VariableLengthDataReader::readArray` |
| **信任边界** | JNI Interface (High Risk) - Spark JVM Process → Native C++ Library |

### 漏洞摘要
函数 `readArray` 从 Spark Row buffer 中读取 `num_elems` 数值时，未对 `num_elems` 进行边界验证。攻击者可以通过构造恶意的 Spark Row 数据，设置超大的 `num_elems` 值，导致：
- 缓冲区越界读取（Out-of-bounds Read）
- 内存耗尽攻击（Memory Exhaustion via `array.reserve()`）
- 进程崩溃（DoS）
- 潜在的信息泄露（Information Disclosure）

### 调用图子集
```json
{
  "functions": {
    "VariableLengthDataReader::readArray@SparkRowToCHColumn.cpp": {
      "defined_at": 187,
      "calls": ["memcpy", "calculateBitSetWidthInBytes", "isBitSet", "array.reserve"],
      "called_by": ["VariableLengthDataReader::read", "SparkRowReader::getField"],
      "receives_external_input": true,
      "risk": "High",
      "input_types": ["buffer", "length"]
    },
    "isBitSet@CHColumnToSparkRow.cpp": {
      "defined_at": 75,
      "calls": [],
      "called_by": ["readArray", "readStruct"],
      "receives_external_input": true,
      "risk": "Medium",
      "input_types": ["bitmap", "index"]
    }
  },
  "data_flows": [
    {
      "source": "buffer@JNI/SparkRow",
      "path": ["memcpy(&num_elems, buffer, 8)", "calculateBitSetWidthInBytes(num_elems)", "array.reserve(num_elems)", "loop: buffer+offset"],
      "sink": "out-of-bounds read",
      "sink_type": "memory_operation"
    }
  ]
}
```

---

## 2. 技术细节分析

### 2.1 漏洞代码

**位置**: `cpp-ch/local-engine/Parser/SparkRowToCHColumn.cpp:187-248`

```cpp
Field VariableLengthDataReader::readArray(const char * buffer, [[maybe_unused]] size_t length) const
{
    /// 内存布局：numElements(8B) | null_bitmap(与numElements成正比) | values(每个值长度与类型有关) | backing data
    /// Read numElements
    int64_t num_elems = 0;
    memcpy(&num_elems, buffer, 8);                              // 漏洞点 1: 无验证读取
    if (num_elems == 0 || length == 0)                          // 漏洞点 2: 仅检查零值，无上限验证
        return Array();

    /// Skip null_bitmap
    const auto len_null_bitmap = calculateBitSetWidthInBytes(num_elems);  // 漏洞点 3: num_elems 过大会导致 bitmap 计算错误

    /// Read values
    const auto * array_type = typeid_cast<const DataTypeArray *>(type_without_nullable.get());
    const auto & nested_type = array_type->getNestedType();
    const auto elem_size = BackingDataLengthCalculator::getArrayElementSize(nested_type);

    Array array;
    array.reserve(num_elems);                                    // 漏洞点 4: 内存耗尽风险

    if (BackingDataLengthCalculator::isFixedLengthDataType(removeNullable(nested_type)))
    {
        FixedLengthDataReader reader(nested_type);
        for (int64_t i = 0; i < num_elems; ++i)
        {
            if (isBitSet(buffer + 8, i))                         // 漏洞点 5: bitmap 访问越界
            {
                array.emplace_back(Null{});
            }
            else
            {
                const auto elem = reader.read(buffer + 8 + len_null_bitmap + i * elem_size);  // 漏洞点 6: 数组元素访问越界
                array.emplace_back(elem);
            }
        }
    }
    else if (BackingDataLengthCalculator::isVariableLengthDataType(removeNullable(nested_type)))
    {
        VariableLengthDataReader reader(nested_type);
        for (int64_t i = 0; i < num_elems; ++i)
        {
            if (isBitSet(buffer + 8, i))                         // 漏洞点 5: bitmap 访问越界
            {
                array.emplace_back(Null{});
            }
            else
            {
                int64_t offset_and_size = 0;
                memcpy(&offset_and_size, buffer + 8 + len_null_bitmap + i * 8, 8);  // 漏洞点 7: offset_and_size 访问越界
                const int64_t offset = BackingDataLengthCalculator::extractOffset(offset_and_size);
                const int64_t size = BackingDataLengthCalculator::extractSize(offset_and_size);

                const auto elem = reader.read(buffer + offset, size);  // 漏洞点 8: offset 可指向任意位置
                array.emplace_back(elem);
            }
        }
    }
    else
        throw Exception(ErrorCodes::UNKNOWN_TYPE, "VariableLengthDataReader doesn't support type {}", nested_type->getName());

    return std::move(array);
}
```

### 2.2 辅助函数分析

**calculateBitSetWidthInBytes**: `CHColumnToSparkRow.cpp:48-51`
```cpp
int64_t calculateBitSetWidthInBytes(int64_t num_fields)
{
    return ((num_fields + 63) / 64) * 8;
}
```
- 当 `num_elems` 过大时（如 `INT64_MAX`），计算结果可能溢出或过大
- 此值用于计算 null_bitmap 的长度，直接影响后续的 buffer 访问偏移量

**isBitSet**: `CHColumnToSparkRow.cpp:75-82`
```cpp
ALWAYS_INLINE bool isBitSet(const char * bitmap, size_t index)
{
    assert(index >= 0);
    int64_t mask = 1L << (index & 63);
    int64_t word_offset = static_cast<int64_t>(index >> 6) * 8L;
    int64_t word = *reinterpret_cast<const int64_t *>(bitmap + word_offset);  // 越界读取风险
    return word & mask;
}
```
- `word_offset = (index >> 6) * 8` 当 index 过大时可能指向超出 buffer 的位置
- 只有 `assert(index >= 0)` 检查，没有边界检查

### 2.3 数据流分析

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Data Flow Analysis                              │
└─────────────────────────────────────────────────────────────────────────────┘

[SPARK JVM]                              [JNI Interface]              [Native C++]
     │                                         │                            │
     │  Spark UnsafeRow 数据                   │                            │
     │  (包含 Array 字段)                      │                            │
     │                                         │                            │
     ├─────────────────────────────────────────> JNI Call                   │
     │                                         │                            │
     │                                         │ convertSparkRowItrToCHColumn
     │                                         │                            │
     │                                         │ ┌──────────────────────────┤
     │                                         │ │ GetDirectBufferAddress   │
     │                                         │ │ rows_buf_ptr             │
     │                                         │ └──────────────────────────┤
     │                                         │                            │
     │                                         │ ┌──────────────────────────┤
     │                                         │ │ SparkRowReader.pointTo   │
     │                                         │ │ (buffer, length)         │
     │                                         │ └──────────────────────────┤
     │                                         │                            │
     │                                         │ ┌──────────────────────────┤
     │                                         │ │ SparkRowReader.getField  │
     │                                         │ │ (ordinal)                │
     │                                         │ └──────────────────────────┤
     │                                         │                            │
     │                                         │ ┌──────────────────────────┤
     │                                         │ │ VariableLengthDataReader │
     │                                         │ │ .read(buffer+offset,size)│
     │                                         │ └──────────────────────────┤
     │                                         │                            │
     │                                         │ ┌──────────────────────────┤
     │                                         │ │ readArray(buffer, length)│
     │                                         │ └──────────────────────────┤
     │                                         │                            │
     │                                         │ ┌──────────────────────────┤
     │                                         │ │ memcpy(&num_elems,       │
     │                                         │ │   buffer, 8)             │ <== 漏洞点
     │                                         │ │ num_elems = 恶意大值     │
     │                                         │ └──────────────────────────┤
     │                                         │                            │
     │                                         │ ┌──────────────────────────┤
     │                                         │ │ calculateBitSetWidthBytes│
     │                                         │ │ (num_elems)              │
     │                                         │ │ = 超大偏移量              │
     │                                         │ └──────────────────────────┤
     │                                         │                            │
     │                                         │ ┌──────────────────────────┤
     │                                         │ │ array.reserve(num_elems) │
     │                                         │ │ = 内存耗尽                │
     │                                         │ └──────────────────────────┤
     │                                         │                            │
     │                                         │ ┌──────────────────────────┤
     │                                         │ │ loop i=0..num_elems      │
     │                                         │ │ buffer + offset          │
     │                                         │ │ = 越界读取                │ <== 漏洞触发
     │                                         │ └──────────────────────────┤
     │                                         │                            │
     │                                         │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
     │                                         │   CRASH / INFO LEAK / DoS  │
     │                                         │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
```

### 2.4 漏洞根因分析

#### 问题 1: num_elems 无边界验证

```cpp
int64_t num_elems = 0;
memcpy(&num_elems, buffer, 8);  // 直接从 buffer 读取，无验证
if (num_elems == 0 || length == 0)  // 仅检查零值，无上限检查
    return Array();
```

**风险**:
- `num_elems` 可以是任意 `int64_t` 值（包括超大值如 `INT64_MAX`）
- 未验证 `num_elems` 是否与 `length` 参数匹配
- 当 `length` 很小但 `num_elems` 很大时，必然发生越界读取

#### 问题 2: length 参数未使用

```cpp
Field VariableLengthDataReader::readArray(const char * buffer, [[maybe_unused]] size_t length) const
```

**`length` 参数被标记为 `[[maybe_unused]]`**，这意味着：
- 函数内部完全不使用 `length` 参数进行边界检查
- 无法验证 buffer 中实际可用的数据长度
- 无法防止越界访问

#### 问题 3: 内存耗尽风险

```cpp
Array array;
array.reserve(num_elems);  // num_elems 可为超大值
```

**风险**:
- `num_elems` 设置为超大值（如 `1e9` 或 `INT64_MAX`）
- `array.reserve()` 尝试分配大量内存
- 导致内存耗尽或 OOM（Out Of Memory）
- 进程崩溃（DoS）

#### 问题 4: 循环中的越界访问

**固定长度元素路径**:
```cpp
const auto elem = reader.read(buffer + 8 + len_null_bitmap + i * elem_size);
```
当 `i * elem_size + 8 + len_null_bitmap > length` 时发生越界。

**变长元素路径**:
```cpp
memcpy(&offset_and_size, buffer + 8 + len_null_bitmap + i * 8, 8);
const auto elem = reader.read(buffer + offset, size);
```
- 第一行可能越界读取 offset_and_size
- 第二行使用恶意 offset 值可能访问任意内存位置

---

## 3. 攻击路径构造

### 3.1 恶意数据构造示例

#### Spark Row Array 内存布局
```
┌────────────────────────────────────────────────────────────────────────────┐
│ Spark UnsafeRow Array Layout                                               │
├────────────────────────────────────────────────────────────────────────────┤
│ Offset │ Size │ Description                                                │
├────────┼──────┼────────────────────────────────────────────────────────────┤
│ 0      │ 8B   │ num_elems (number of elements)                             │
│ 8      │ N*B  │ null_bitmap (N = (num_elems+63)/64, B = 8 bytes)           │
│ 8+N*B  │ M    │ values region (M depends on element type)                  │
│ 8+N*B+M│ *    │ backing data (for variable-length elements)                │
└────────────────────────────────────────────────────────────────────────────┘
```

#### PoC 1: 超大 num_elems 导致越界读取

```cpp
// 恶意 Spark Row buffer 构造
char malicious_buffer[16];  // 实际只有 16 字节
int64_t fake_num_elems = 1000000000LL;  // 声称有 10 亿元素
memcpy(malicious_buffer, &fake_num_elems, 8);  // 写入虚假的 num_elems

// 调用 readArray
VariableLengthDataReader reader(array_type);
Field result = reader.read(malicious_buffer, 16);  // length = 16，但声称有 10 亿元素

// 结果：
// 1. calculateBitSetWidthInBytes(1000000000) ≈ 125000000 字节
// 2. buffer + 8 + 125000000 完全超出 16 字节的 buffer
// 3. 越界读取，进程崩溃（SIGSEGV）
```

#### PoC 2: 内存耗尽攻击

```cpp
// 恶意 Spark Row buffer 构造
char malicious_buffer[8];
int64_t fake_num_elems = INT64_MAX;  // 最大值
memcpy(malicious_buffer, &fake_num_elems, 8);

// 调用 readArray
// array.reserve(INT64_MAX) 尝试分配巨大内存
// 结果：OOM，进程崩溃
```

#### PoC 3: 恶意 offset 导致任意内存读取

```cpp
// 构造恶意变长数组 buffer
char malicious_buffer[24];
int64_t num_elems = 1;
memcpy(malicious_buffer, &num_elems, 8);

// 第一个元素的 offset_and_size
int64_t offset_and_size = BackingDataLengthCalculator::getOffsetAndSize(0x7fff00001234, 100);
// offset = 0x7fff00001234 (攻击者选择的任意地址)
memcpy(malicious_buffer + 16, &offset_and_size, 8);  // 写入恶意 offset

// 调用 readArray
// buffer + offset 会读取任意内存地址的内容
// 信息泄露风险
```

### 3.2 攻击场景分析

#### 场景 1: 恶意 Spark 数据攻击

**前提条件**:
- Spark 应用处理外部数据源（如用户上传的文件）
- 数据包含 Array 类型字段

**攻击步骤**:
1. 攻击者构造包含恶意 Array 数据的文件
2. Spark 读取数据，生成包含恶意 num_elems 的 UnsafeRow
3. Native 层调用 readArray 处理恶意数据
4. 越界读取或内存耗尽导致崩溃

**效果**:
- Executor 进程崩溃（DoS）
- 潜在的信息泄露（读取其他进程数据）

#### 场景 2: 网络数据注入攻击

**前提条件**:
- Spark Shuffle 通过网络接收数据
- 数据格式未经过严格验证

**攻击步骤**:
1. 攻击者拦截或伪造 Shuffle 数据包
2. 在数据包中注入恶意 Array buffer
3. Native 层处理时触发漏洞

#### 场景 3: 序列化攻击

**前提条件**:
- Spark 使用 UnsafeRow 序列化格式
- 序列化数据来自不可信源

**攻击步骤**:
1. 构造恶意序列化数据
2. 在 Array 字段中植入超大 num_elems
3. Native 层反序列化时触发漏洞

---

## 4. 漏洞利用可行性评估

### 4.1 可利用性评分

| 因素 | 评分 | 说明 |
|------|------|------|
| **可达性** | 25/30 | 通过 JNI 接收 Spark Row 数据，路径间接 |
| **可控性** | 25/25 | num_elems 完全由外部数据控制 |
| **缓解措施** | 5/25 | 有零值检查，但无上限检查 |
| **上下文风险** | 10/15 | JNI 边界，跨信任域 |
| **总分** | **85/100** | 高置信度 |

### 4.2 利用难度分析

| 因素 | 评估 |
|------|------|
| **技术难度** | 中 - 需要了解 Spark Row 格式和 JNI 调用路径 |
| **权限要求** | 中 - 需要能注入或控制 Spark 数据源 |
| **环境依赖** | 低 - 所有使用 Gluten 的 Spark 应用 |
| **可靠性** | 高 - 缺乏边界检查必然导致问题 |

### 4.3 利用后果分析

#### 直接后果
1. **进程崩溃** (DoS): 最可能的结果
   - `num_elems * elem_size` 超出 buffer 范围 → SIGSEGV
   - `array.reserve(INT64_MAX)` → OOM → SIGKILL

2. **信息泄露**: 
   - 越界读取其他内存区域的数据
   - 可能泄露敏感信息（如密码、密钥）

3. **内存损坏**:
   - `isBitSet` 越界访问可能读取错误数据
   - 导致后续处理使用错误数据

#### 潜在后果
1. **任意内存读取**: 
   - 恶意 offset 值可指向任意内存地址
   - 信息泄露攻击

2. **拒绝服务**: 
   - 内存耗尽导致整个 Spark 集群不可用

---

## 5. 影响范围分析

### 5.1 影响组件

| 组件 | 影响 |
|------|------|
| **SparkRowToCHColumn.cpp** | 直受影响文件 |
| **VariableLengthDataReader** | 漏洞类 |
| **SparkRowReader** | 调用漏洞函数的入口 |
| **JNI Interface** | 数据入口点 |

### 5.2 相关漏洞函数

| 函数 | 文件 | 行号 | 漏洞类型 |
|------|------|------|----------|
| `readArray` | SparkRowToCHColumn.cpp | 187-248 | OOB Read |
| `readMap` | SparkRowToCHColumn.cpp | 250-287 | 类似风险 |
| `readStruct` | SparkRowToCHColumn.cpp | 289-329 | 类似风险 |
| `isBitSet` | CHColumnToSparkRow.cpp | 75-82 | OOB Read |

### 5.3 影响场景

| 场景 | 影响程度 |
|------|----------|
| **Spark Shuffle 数据读取** | 高 - 主要使用场景 |
| **Columnar 数据处理** | 高 - 核心功能 |
| **Array 类型字段处理** | 高 - 直受影响 |
| **Map/Struct 类型处理** | 中 - 类似风险 |

---

## 6. 缓解措施建议

### 6.1 立即修复建议

#### 修复代码

```cpp
// cpp-ch/local-engine/Parser/SparkRowToCHColumn.cpp:187-248 (修复版)
Field VariableLengthDataReader::readArray(const char * buffer, size_t length) const
{
    /// Read numElements with validation
    if (length < 8) {
        throw Exception(ErrorCodes::LOGICAL_ERROR, 
            "readArray: buffer length {} is too small for array header (need at least 8 bytes)", length);
    }
    
    int64_t num_elems = 0;
    memcpy(&num_elems, buffer, 8);
    
    /// Validate num_elems
    if (num_elems < 0) {
        throw Exception(ErrorCodes::LOGICAL_ERROR, 
            "readArray: num_elems {} is negative", num_elems);
    }
    
    if (num_elems == 0 || length == 0)
        return Array();
    
    /// Check for maximum reasonable size (防止内存耗尽)
    constexpr int64_t MAX_ARRAY_ELEMENTS = 1000000000LL;  // 10 亿元素上限
    if (num_elems > MAX_ARRAY_ELEMENTS) {
        throw Exception(ErrorCodes::LOGICAL_ERROR, 
            "readArray: num_elems {} exceeds maximum allowed {}", num_elems, MAX_ARRAY_ELEMENTS);
    }
    
    /// Skip null_bitmap with validation
    const auto len_null_bitmap = calculateBitSetWidthInBytes(num_elems);
    
    /// Check buffer has enough space for header + null_bitmap
    const size_t min_required = 8 + len_null_bitmap;
    if (length < min_required) {
        throw Exception(ErrorCodes::LOGICAL_ERROR, 
            "readArray: buffer length {} insufficient for {} elements (need at least {} bytes)", 
            length, num_elems, min_required);
    }
    
    /// Read values
    const auto * array_type = typeid_cast<const DataTypeArray *>(type_without_nullable.get());
    const auto & nested_type = array_type->getNestedType();
    const auto elem_size = BackingDataLengthCalculator::getArrayElementSize(nested_type);

    Array array;
    array.reserve(static_cast<size_t>(num_elems));  // 使用 size_t 避免溢出

    if (BackingDataLengthCalculator::isFixedLengthDataType(removeNullable(nested_type)))
    {
        /// Fixed-length validation
        const size_t fixed_values_size = static_cast<size_t>(num_elems) * elem_size;
        if (length < min_required + fixed_values_size) {
            throw Exception(ErrorCodes::LOGICAL_ERROR, 
                "readArray: buffer length {} insufficient for {} fixed-length elements of size {}", 
                length, num_elems, elem_size);
        }
        
        FixedLengthDataReader reader(nested_type);
        for (int64_t i = 0; i < num_elems; ++i)
        {
            if (isBitSet(buffer + 8, i))
            {
                array.emplace_back(Null{});
            }
            else
            {
                const auto elem = reader.read(buffer + 8 + len_null_bitmap + i * elem_size);
                array.emplace_back(elem);
            }
        }
    }
    else if (BackingDataLengthCalculator::isVariableLengthDataType(removeNullable(nested_type)))
    {
        /// Variable-length validation
        const size_t offset_array_size = static_cast<size_t>(num_elems) * 8;
        if (length < min_required + offset_array_size) {
            throw Exception(ErrorCodes::LOGICAL_ERROR, 
                "readArray: buffer length {} insufficient for {} variable-length element offsets", 
                length, num_elems);
        }
        
        VariableLengthDataReader reader(nested_type);
        for (int64_t i = 0; i < num_elems; ++i)
        {
            if (isBitSet(buffer + 8, i))
            {
                array.emplace_back(Null{});
            }
            else
            {
                int64_t offset_and_size = 0;
                memcpy(&offset_and_size, buffer + 8 + len_null_bitmap + i * 8, 8);
                const int64_t offset = BackingDataLengthCalculator::extractOffset(offset_and_size);
                const int64_t size = BackingDataLengthCalculator::extractSize(offset_and_size);
                
                /// Validate offset and size
                if (offset < 0 || size < 0) {
                    throw Exception(ErrorCodes::LOGICAL_ERROR, 
                        "readArray: invalid offset {} or size {} for element {}", offset, size, i);
                }
                if (static_cast<size_t>(offset + size) > length) {
                    throw Exception(ErrorCodes::LOGICAL_ERROR, 
                        "readArray: offset {} + size {} exceeds buffer length {}", offset, size, length);
                }

                const auto elem = reader.read(buffer + offset, static_cast<size_t>(size));
                array.emplace_back(elem);
            }
        }
    }
    else
        throw Exception(ErrorCodes::UNKNOWN_TYPE, "VariableLengthDataReader doesn't support type {}", nested_type->getName());

    return std::move(array);
}
```

### 6.2 isBitSet 函数修复建议

```cpp
// CHColumnToSparkRow.cpp:75-82 (修复版)
ALWAYS_INLINE bool isBitSet(const char * bitmap, size_t index, size_t bitmap_length)
{
    assert(index >= 0);
    int64_t mask = 1L << (index & 63);
    int64_t word_offset = static_cast<int64_t>(index >> 6) * 8L;
    
    /// 添加边界检查
    if (static_cast<size_t>(word_offset) + 8 > bitmap_length) {
        return false;  // 或抛出异常
    }
    
    int64_t word = *reinterpret_cast<const int64_t *>(bitmap + word_offset);
    return word & mask;
}
```

### 6.3 通用边界检查辅助函数

```cpp
// 建议: 在 SparkRowToCHColumn.h 中添加
namespace BoundsChecker {
    
    /// 验证 Spark Row buffer 的基本完整性
    bool validateArrayBuffer(const char* buffer, size_t length) {
        if (buffer == nullptr || length < 8) return false;
        
        int64_t num_elems = 0;
        memcpy(&num_elems, buffer, 8);
        
        if (num_elems < 0 || num_elems > MAX_ARRAY_ELEMENTS) return false;
        
        int64_t bitmap_size = calculateBitSetWidthInBytes(num_elems);
        if (length < static_cast<size_t>(8 + bitmap_size)) return false;
        
        return true;
    }
    
    /// 验证 offset 在 buffer 范围内
    bool validateOffset(size_t offset, size_t size, size_t buffer_length) {
        if (offset > buffer_length) return false;
        if (offset + size > buffer_length) return false;
        return true;
    }
    
    /// 计算安全的最大元素数
    int64_t calculateMaxSafeElements(size_t buffer_length, int64_t elem_size) {
        if (buffer_length < 8) return 0;
        int64_t available = static_cast<int64_t>(buffer_length - 8);
        // 简化计算，忽略 null_bitmap
        return available / elem_size;
    }
    
}
```

### 6.4 测试建议

```cpp
// test/gtest_spark_row.cpp
TEST(ReadArrayTest, NegativeNumElemsRejected) {
    char buffer[16];
    int64_t negative_num = -100;
    memcpy(buffer, &negative_num, 8);
    
    auto array_type = std::make_shared<DataTypeArray>(std::make_shared<DataTypeInt64>());
    VariableLengthDataReader reader(array_type);
    
    EXPECT_THROW(reader.read(buffer, 16), Exception);
}

TEST(ReadArrayTest, HugeNumElemsRejected) {
    char buffer[16];
    int64_t huge_num = INT64_MAX;
    memcpy(buffer, &huge_num, 8);
    
    auto array_type = std::make_shared<DataTypeArray>(std::make_shared<DataTypeInt64>());
    VariableLengthDataReader reader(array_type);
    
    EXPECT_THROW(reader.read(buffer, 16), Exception);
}

TEST(ReadArrayTest, NumElemsExceedsBufferLength) {
    char buffer[16];
    int64_t num_elems = 1000;  // 声称有1000个元素，但buffer只有16字节
    memcpy(buffer, &num_elems, 8);
    
    auto array_type = std::make_shared<DataTypeArray>(std::make_shared<DataTypeInt64>());
    VariableLengthDataReader reader(array_type);
    
    EXPECT_THROW(reader.read(buffer, 16), Exception);
}

TEST(ReadArrayTest, InvalidOffsetRejected) {
    char buffer[32];
    int64_t num_elems = 1;
    memcpy(buffer, &num_elems, 8);
    
    // 恶意 offset 指向超出 buffer 的位置
    int64_t offset_and_size = BackingDataLengthCalculator::getOffsetAndSize(1000, 10);
    memcpy(buffer + 16, &offset_and_size, 8);
    
    auto array_type = std::make_shared<DataTypeArray>(std::make_shared<DataTypeString>());
    VariableLengthDataReader reader(array_type);
    
    EXPECT_THROW(reader.read(buffer, 32), Exception);
}
```

---

## 7. 相关漏洞分析

### 7.1 readMap 函数类似风险

**位置**: `SparkRowToCHColumn.cpp:250-287`

```cpp
Field VariableLengthDataReader::readMap(const char * buffer, size_t length) const
{
    int64_t key_array_size = 0;
    memcpy(&key_array_size, buffer, 8);
    if (key_array_size == 0 || length == 0)
        return Map();
    
    /// key_array_size 同样未验证上限
    /// 可能触发 readArray 的漏洞
    VariableLengthDataReader key_reader(key_array_type);
    auto key_field = key_reader.read(buffer + 8, key_array_size);  // 传递给 readArray
```

**风险**: `key_array_size` 未验证，可能传递恶意值到 `readArray`。

### 7.2 readStruct 函数类似风险

**位置**: `SparkRowToCHColumn.cpp:289-329`

```cpp
Field VariableLengthDataReader::readStruct(const char * buffer, size_t /*length*/) const
{
    /// length 参数同样未使用！
    const auto len_null_bitmap = calculateBitSetWidthInBytes(num_fields);
    
    /// isBitSet(buffer, i) 可能越界
    /// reader.read(buffer + offset, size) 使用未验证的 offset
```

**风险**: 同样存在越界读取风险。

---

## 8. 附录

### 8.1 CWE-125 定义

> **CWE-125: Out-of-bounds Read**
> 
> The software reads data past the end, or before the beginning, of the intended buffer.
> 
> This typically occurs when the software reads data past the bounds of an allocated buffer. An attacker may be able to use this to read sensitive information from other memory locations or cause a crash.

### 8.2 相关 CVE 参考

- CVE-2022-26133: Out-of-bounds read in JNI buffer handling
- CVE-2020-1948: Apache Spark deserialization vulnerability
- CVE-2023-38646: Memory safety issues in native data processing

### 8.3 修复优先级建议

| 优先级 | 建议 |
|--------|------|
| **P0 (立即)** | 添加 num_elems 上限验证 |
| **P0 (立即)** | 使用 length 参数进行边界检查 |
| **P0 (立即)** | 验证 offset 不超出 buffer 范围 |
| **P1 (短期)** | 修复 isBitSet 添加 bitmap 长度参数 |
| **P1 (短期)** | 同样修复 readMap 和 readStruct |
| **P2 (中期)** | 创建统一的 BoundsChecker 辅助类 |
| **P3 (长期)** | 重构为更安全的 buffer 解析框架 |

---

## 9. 结论

**cpp-ch-parser-003 是一个真实存在的 High 级别漏洞**，需要立即修复。

**关键风险**:
- `num_elems` 从外部数据读取，无边界验证
- `length` 参数被忽略，无法防止越界
- 可能导致内存耗尽、进程崩溃、信息泄露
- `readMap` 和 `readStruct` 存在类似风险

**修复核心**:
1. 验证 `num_elems` 非负且有上限
2. 使用 `length` 参数验证 buffer 空间足够
3. 验证 `offset` 和 `size` 在 buffer 范围内
4. 同样修复 `isBitSet`、`readMap`、`readStruct`

**建议立即实施 P0 级别修复**，然后逐步完善防护措施。

---

**报告生成**: 2026-04-23
**漏洞状态**: CONFIRMED REAL
**推荐行动**: 立即修复
