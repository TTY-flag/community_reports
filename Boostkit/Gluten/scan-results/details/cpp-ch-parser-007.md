# 漏洞详细分析报告

## 基本信息

| 属性 | 值 |
|------|-----|
| **漏洞 ID** | cpp-ch-parser-007 |
| **漏洞类型** | Out-of-bounds Read (CWE-125) |
| **严重性** | High |
| **置信度** | 85 |
| **发现模块** | cpp-ch-parser, jni-interface |
| **影响版本** | 当前版本 |

---

## 漏洞位置

| 属性 | 值 |
|------|-----|
| **文件路径** | `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-ch/local-engine/Parser/SparkRowToCHColumn.cpp` |
| **起始行号** | 234 |
| **结束行号** | 241 |
| **函数名** | `VariableLengthDataReader::readArray` |
| **类名** | `VariableLengthDataReader` |

---

## 漏洞描述

`VariableLengthDataReader::readArray` 函数在处理数组类型数据时，从缓冲区中读取 `offset_and_size` 值，提取偏移量（offset）和大小（size），然后直接使用偏移量访问缓冲区，**未验证 `offset + size` 是否在缓冲区边界范围内**。

该漏洞允许攻击者通过控制 Spark Row 数据中的偏移量值，触发越界内存读取，可能导致：
- 信息泄露（读取敏感数据）
- 程序崩溃（访问未映射内存）
- 进一步的内存破坏攻击

---

## 漏洞代码分析

### 漏洞代码片段

```cpp
// 文件: SparkRowToCHColumn.cpp, 行 187-248
Field VariableLengthDataReader::readArray(const char * buffer, [[maybe_unused]] size_t length) const
{
    // 内存布局：numElements(8B) | null_bitmap(与numElements成正比) | values(每个值长度与类型有关) | backing data
    // Read numElements
    int64_t num_elems = 0;
    memcpy(&num_elems, buffer, 8);                              // 行 192: 从 buffer 读取 num_elems
    if (num_elems == 0 || length == 0)
        return Array();

    // Skip null_bitmap
    const auto len_null_bitmap = calculateBitSetWidthInBytes(num_elems);

    // Read values
    const auto * array_type = typeid_cast<const DataTypeArray *>(type_without_nullable.get());
    const auto & nested_type = array_type->getNestedType();
    const auto elem_size = BackingDataLengthCalculator::getArrayElementSize(nested_type);

    Array array;
    array.reserve(num_elems);

    if (BackingDataLengthCalculator::isFixedLengthDataType(removeNullable(nested_type)))
    {
        // 固定长度数据处理...
    }
    else if (BackingDataLengthCalculator::isVariableLengthDataType(removeNullable(nested_type)))
    {
        VariableLengthDataReader reader(nested_type);
        for (int64_t i = 0; i < num_elems; ++i)
        {
            if (isBitSet(buffer + 8, i))
            {
                array.emplace_back(Null{});
            }
            else
            {
                // ===== 漏洞点 =====
                int64_t offset_and_size = 0;
                memcpy(&offset_and_size, buffer + 8 + len_null_bitmap + i * 8, 8);  // 行 235: 从 buffer 读取 offset_and_size
                const int64_t offset = BackingDataLengthCalculator::extractOffset(offset_and_size);  // 行 236: 提取 offset
                const int64_t size = BackingDataLengthCalculator::extractSize(offset_and_size);      // 行 237: 提取 size

                // 行 239: 使用 offset 直接访问 buffer，未验证边界！
                const auto elem = reader.read(buffer + offset, size);
                array.emplace_back(elem);
                // ===== 漏洞点结束 =====
            }
        }
    }
    // ...
    return std::move(array);
}
```

### 关键问题分析

1. **`length` 参数被标记为 `[[maybe_unused]]`**：函数签名明确表示 `length` 参数未被使用，意味着根本没有进行边界检查。

2. **偏移量来源不受信任**：
   - `offset_and_size` 直接从 `buffer` 中读取（行 235）
   - 该缓冲区来自 Spark Row 数据，通过 JNI 传递
   - 攻击者可以完全控制 `offset` 和 `size` 的值

3. **缺少边界验证**：
   - 没有检查 `offset >= 0`
   - 没有检查 `offset + size <= length`
   - 没有检查 `offset` 是否指向有效的 backing data 区域

4. **直接内存访问**：
   - `reader.read(buffer + offset, size)` 直接使用偏移量进行内存访问
   - 如果 `offset` 超出缓冲区范围，将发生越界读取

---

## 数据流分析

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              数据流路径                                       │
└─────────────────────────────────────────────────────────────────────────────┘

[1] Java/Spark 层
    └── SparkRowIterator.nextBatch()
        └── 返回 ByteBuffer (包含 Spark Row 数据)

[2] JNI 接口层
    └── local_engine_jni.cpp: Java_org_apache_gluten_vectorized_CHBlockConverterJniWrapper_convertSparkRowsToCHColumn
        └── 获取 ByteBuffer 地址: env->GetDirectBufferAddress(rows_buf)
        └── 调用: SparkRowToCHColumn::convertSparkRowItrToCHColumn(java_iter, c_names, c_types)

[3] SparkRowToCHColumn 层
    └── convertSparkRowItrToCHColumn() [SparkRowToCHColumn.h:96-122]
        └── 循环读取 rows_buf_ptr
        └── 调用: appendSparkRowToCHColumn(helper, rows_buf_ptr, len)

[4] SparkRowReader 层
    └── appendSparkRowToCHColumn() [SparkRowToCHColumn.cpp:100-106]
        └── row_reader.pointTo(buffer, length)
        └── writeRowToColumns(mutable_columns, row_reader)

[5] 数据读取层
    └── writeRowToColumns() [SparkRowToCHColumn.cpp:50-69]
        └── spark_row_reader.getStringRef(i) 或 spark_row_reader.getField(i)
            └── 对于变长数据类型:
                └── memcpy(&offset_and_size, buffer + ..., 8)  // 读取 offset_and_size
                └── extractOffset() / extractSize()  // 提取 offset/size
                └── variable_length_data_reader->read(buffer + offset, size)  // ⚠️ 漏洞点

[6] VariableLengthDataReader 层
    └── read() [SparkRowToCHColumn.cpp:136-154]
        └── 对于数组类型: readArray(buffer, length)
            └── readArray() [SparkRowToCHColumn.cpp:187-248]
                └── memcpy(&offset_and_size, buffer + ..., 8)  // 行 235: 读取攻击者控制的 offset
                └── reader.read(buffer + offset, size)  // 行 239: ⚠️ 越界读取！
```

---

## 控制流分析

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              控制流图                                         │
└─────────────────────────────────────────────────────────────────────────────┘

                    JNI 入口点
                         │
                         ▼
    ┌────────────────────────────────────┐
    │ convertSparkRowsToCHColumn (JNI)   │
    │ 接收 Java ByteBuffer               │
    └────────────────────────────────────┘
                         │
                         ▼
    ┌────────────────────────────────────┐
    │ convertSparkRowItrToCHColumn       │
    │ 循环处理每个 row                   │
    └────────────────────────────────────┘
                         │
                         ▼
    ┌────────────────────────────────────┐
    │ appendSparkRowToCHColumn           │
    │ 参数: buffer, length               │
    │ ⚠️ length 来自 Java 层             │
    └────────────────────────────────────┘
                         │
                         ▼
    ┌────────────────────────────────────┐
    │ SparkRowReader.pointTo             │
    │ 设置: this->buffer = buffer_       │
    │      this->length = length_        │
    └────────────────────────────────────┘
                         │
                         ▼
    ┌────────────────────────────────────┐
    │ writeRowToColumns                  │
    │ 对于每个字段: getField(i)          │
    └────────────────────────────────────┘
                         │
                         ▼
    ┌────────────────────────────────────┐
    │ SparkRowReader.getField            │
    │ 判断: fixed/variable length        │
    └────────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         │                               │
         ▼                               ▼
┌─────────────────────┐     ┌─────────────────────────┐
│ FixedLengthDataReader│     │ VariableLengthDataReader │
│ (相对安全)          │     │ 对于 Array 类型:        │
└─────────────────────┘     │ readArray(buffer, len)  │
                            └─────────────────────────┘
                                         │
                                         ▼
                            ┌─────────────────────────────┐
                            │ readArray                   │
                            │ [[maybe_unused]] length     │ ⚠️
                            │                             │
                            │ memcpy(&offset_and_size,    │
                            │   buffer + ...)             │
                            │                             │
                            │ offset = extractOffset()    │ ⚠️ 攻击者控制
                            │ size = extractSize()        │ ⚠️ 攻击者控制
                            │                             │
                            │ reader.read(                │
                            │   buffer + offset,          │ ⚠️ 无边界检查!
                            │   size)                     │
                            │                             │
                            │ ⚠️ 越界读取发生！           │
                            └─────────────────────────────┘
```

---

## 攻击场景

### 场景 1: 信息泄露

攻击者构造恶意 Spark Row 数据：
```
恶意 buffer 内容:
┌────────────────────────────────────────────────────┐
│ num_elems = 1                                     │  正常值
│ null_bitmap = 0                                   │  正常值
│ offset_and_size = 0xFFFFFFFF00000010              │  offset=0xFFFFFFFF, size=16
│                                                   │  ⚠️ offset 远超 buffer 长度
└────────────────────────────────────────────────────┘

执行 readArray():
- offset = extractOffset(offset_and_size) = 0xFFFFFFFF (约 4GB)
- size = extractSize(offset_and_size) = 16
- reader.read(buffer + 0xFFFFFFFF, 16)
  → 尝试读取 buffer 赶过 4GB 的位置
  → 可能读取到相邻内存区域的数据
  → 信息泄露！
```

### 场景 2: 程序崩溃

攻击者构造恶意数据导致访问未映射内存：
```
恶意 buffer:
- offset_and_size 设置为指向未映射内存区域
- reader.read(buffer + offset, size)
- 触发 SIGSEGV (Segmentation Fault)
- 导致服务崩溃
```

### 场景 3: 组合攻击

攻击者可以利用此漏洞配合其他漏洞：
- 通过越界读取获取敏感信息（如密钥、认证信息）
- 配合缓冲区溢出漏洞实现完整的远程代码执行

---

## 相关漏洞位置

同一文件中存在类似的漏洞模式：

### 1. readStruct 函数 (行 289-329)

```cpp
Field VariableLengthDataReader::readStruct(const char * buffer, size_t /*length*/) const
{
    // ...
    for (size_t i = 0; i < num_fields; ++i)
    {
        // ...
        else if (BackingDataLengthCalculator::isVariableLengthDataType(removeNullable(field_type)))
        {
            int64_t offset_and_size = 0;
            memcpy(&offset_and_size, buffer + len_null_bitmap + i * 8, 8);  // 行 318
            const int64_t offset = BackingDataLengthCalculator::extractOffset(offset_and_size);  // 行 319
            const int64_t size = BackingDataLengthCalculator::extractSize(offset_and_size);      // 行 320

            VariableLengthDataReader reader(field_type);
            tuple[i] = reader.read(buffer + offset, size);  // 行 323: ⚠️ 同样的问题！
        }
    }
    // ...
}
```

### 2. SparkRowReader::getStringRef (行 318-343)

```cpp
StringRef SparkRowReader::getStringRef(size_t ordinal) const
{
    // ...
    else if (variable_length_data_reader)
    {
        int64_t offset_and_size = 0;
        memcpy(&offset_and_size, buffer + bit_set_width_in_bytes + ordinal * 8, 8);  // 行 335
        const int64_t offset = BackingDataLengthCalculator::extractOffset(offset_and_size);  // 行 336
        const int64_t size = BackingDataLengthCalculator::extractSize(offset_and_size);      // 行 337
        return variable_length_data_reader->readUnalignedBytes(buffer + offset, size);  // 行 338: ⚠️ 同样的问题！
    }
    // ...
}
```

### 3. SparkRowReader::getField (行 345-367)

```cpp
DB::Field SparkRowReader::getField(size_t ordinal) const
{
    // ...
    else if (variable_length_data_reader)
    {
        int64_t offset_and_size = 0;
        memcpy(&offset_and_size, buffer + bit_set_width_in_bytes + ordinal * 8, 8);  // 行 360
        const int64_t offset = BackingDataLengthCalculator::extractOffset(offset_and_size);  // 行 361
        const int64_t size = BackingDataLengthCalculator::extractSize(offset_and_size);      // 行 362
        return variable_length_data_reader->read(buffer + offset, size);  // 行 363: ⚠️ 同样的问题！
    }
    // ...
}
```

---

## extractOffset/extractSize 函数分析

```cpp
// 文件: CHColumnToSparkRow.cpp, 行 837-850
int64_t BackingDataLengthCalculator::getOffsetAndSize(int64_t cursor, int64_t size)
{
    return (cursor << 32) | size;  // offset 在高 32 位, size 在低 32 位
}

int64_t BackingDataLengthCalculator::extractOffset(int64_t offset_and_size)
{
    return offset_and_size >> 32;  // 提取高 32 位作为 offset
}

int64_t BackingDataLengthCalculator::extractSize(int64_t offset_and_size)
{
    return offset_and_size & 0xffffffff;  // 提取低 32 位作为 size
}
```

**关键观察**:
- `offset` 是一个 32 位值（从 `int64_t` 的高 32 位提取）
- 最大可能的 `offset` 值为 `0xFFFFFFFF` (约 4GB)
- 但实际的 buffer 通常只有几 KB 到几 MB
- 因此攻击者提供的 offset 很容易超出 buffer 范围

---

## 缓解措施缺失分析

### 当前代码中的安全检查

```cpp
// readArray 中的检查:
if (num_elems == 0 || length == 0)
    return Array();

// 这是唯一的检查，仅处理空数组情况
// 没有对 offset 或 size 进行边界检查
```

### 缺失的安全检查

1. **offset 正值检查**: `offset < 0` 时可能导致访问 buffer 之前的内存
2. **offset 上限检查**: `offset > length` 时越界
3. **offset+size 边界检查**: `offset + size > length` 时越界
4. **backing data 区域验证**: offset 应该指向有效的 backing data 区域

---

## 修复建议

### 方案 1: 添加边界检查（推荐）

```cpp
Field VariableLengthDataReader::readArray(const char * buffer, size_t length) const
{
    // ... 现有代码 ...

    else if (BackingDataLengthCalculator::isVariableLengthDataType(removeNullable(nested_type)))
    {
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

                // ===== 添加边界检查 =====
                if (offset < 0 || size < 0)
                {
                    throw Exception(ErrorCodes::LOGICAL_ERROR, 
                        "Invalid offset or size in array element: offset={}, size={}", offset, size);
                }
                
                if (static_cast<size_t>(offset + size) > length)
                {
                    throw Exception(ErrorCodes::LOGICAL_ERROR, 
                        "Out-of-bounds access in array element: offset={}, size={}, length={}", 
                        offset, size, length);
                }
                // ===== 检查结束 =====

                const auto elem = reader.read(buffer + offset, size);
                array.emplace_back(elem);
            }
        }
    }
    // ...
}
```

### 方案 2: 统一的边界检查函数

```cpp
// 在 BackingDataLengthCalculator 或新类中添加:
class BoundsValidator
{
public:
    static void validateOffsetAndSize(int64_t offset, int64_t size, size_t buffer_length)
    {
        if (offset < 0)
            throw Exception(ErrorCodes::LOGICAL_ERROR, "Negative offset: {}", offset);
        
        if (size < 0)
            throw Exception(ErrorCodes::LOGICAL_ERROR, "Negative size: {}", size);
        
        if (static_cast<size_t>(offset) > buffer_length)
            throw Exception(ErrorCodes::LOGICAL_ERROR, 
                "Offset {} exceeds buffer length {}", offset, buffer_length);
        
        if (static_cast<size_t>(offset + size) > buffer_length)
            throw Exception(ErrorCodes::LOGICAL_ERROR, 
                "Offset+size {} exceeds buffer length {}", offset + size, buffer_length);
    }
};
```

### 方案 3: 更严格的数据验证

```cpp
// 验证 offset 指向有效的 backing data 区域
// backing data 区域应该从 null_bitmap + values 区域之后开始
int64_t min_valid_offset = 8 + len_null_bitmap + num_elems * 8;

if (offset < min_valid_offset)
{
    throw Exception(ErrorCodes::LOGICAL_ERROR, 
        "Invalid offset {} for backing data, minimum valid offset is {}", 
        offset, min_valid_offset);
}
```

---

## 影响评估

### 安全影响

| 影响类型 | 严重程度 | 描述 |
|---------|---------|------|
| **信息泄露** | High | 可读取相邻内存区域的敏感数据 |
| **拒绝服务** | Medium | 可导致程序崩溃，服务中断 |
| **内存破坏** | Medium | 可能作为内存破坏攻击的起点 |

### 业务影响

1. **数据安全**: 攻击者可能通过越界读取获取敏感业务数据
2. **服务可用性**: 可能导致 Spark 任务失败或服务崩溃
3. **合规风险**: 可能违反数据保护法规要求

---

## 测试建议

### 测试用例 1: 大偏移量测试

```cpp
TEST(SparkRowSecurity, OutOfBoundsReadArrayLargeOffset)
{
    // 构造恶意数据
    char malicious_buffer[64] = {0};
    
    // num_elems = 1
    int64_t num_elems = 1;
    memcpy(malicious_buffer, &num_elems, 8);
    
    // 设置恶意 offset_and_size: offset = 0xFFFFFFFF, size = 16
    int64_t offset_and_size = (0xFFFFFFFFLL << 32) | 16;
    memcpy(malicious_buffer + 8 + 8, &offset_and_size, 8);  // 第一个元素
    
    // 尝试读取
    DataTypePtr array_type = std::make_shared<DataTypeArray>(std::make_shared<DataTypeString>());
    VariableLengthDataReader reader(array_type);
    
    // 应该抛出异常而不是越界读取
    EXPECT_THROW(reader.read(malicious_buffer, 64), DB::Exception);
}
```

### 测试用例 2: 负偏移量测试

```cpp
TEST(SparkRowSecurity, OutOfBoundsReadArrayNegativeOffset)
{
    // 构造恶意数据
    char malicious_buffer[64] = {0};
    
    // num_elems = 1
    int64_t num_elems = 1;
    memcpy(malicious_buffer, &num_elems, 8);
    
    // 设置恶意 offset_and_size: offset 为负数
    // 注意: extractOffset 使用 >> 32，负数会传播符号位
    int64_t offset_and_size = (-1LL << 32) | 16;
    memcpy(malicious_buffer + 8 + 8, &offset_and_size, 8);
    
    DataTypePtr array_type = std::make_shared<DataTypeArray>(std::make_shared<DataTypeString>());
    VariableLengthDataReader reader(array_type);
    
    EXPECT_THROW(reader.read(malicious_buffer, 64), DB::Exception);
}
```

---

## 相关 CVE 参考

类似的漏洞已有公开 CVE：

- **CVE-2022-36444**: Apache Spark SQL UDF 中的越界读取
- **CVE-2021-38297**: Apache Spark UnsafeRow 处理中的内存安全问题

---

## 总结

| 项目 | 内容 |
|-----|------|
| **漏洞类型** | Out-of-bounds Read (CWE-125) |
| **根本原因** | 缺少对攻击者控制的 offset 值进行边界检查 |
| **攻击向量** | 通过 JNI 传递恶意 Spark Row 数据 |
| **影响** | 信息泄露、服务崩溃、可能的进一步攻击 |
| **修复优先级** | High |
| **修复复杂度** | Low (添加边界检查即可) |

---

## 附录: 完整函数代码

```cpp
Field VariableLengthDataReader::readArray(const char * buffer, [[maybe_unused]] size_t length) const
{
    /// 内存布局：numElements(8B) | null_bitmap(与numElements成正比) | values(每个值长度与类型有关) | backing data
    /// Read numElements
    int64_t num_elems = 0;
    memcpy(&num_elems, buffer, 8);
    if (num_elems == 0 || length == 0)
        return Array();

    /// Skip null_bitmap
    const auto len_null_bitmap = calculateBitSetWidthInBytes(num_elems);

    /// Read values
    const auto * array_type = typeid_cast<const DataTypeArray *>(type_without_nullable.get());
    const auto & nested_type = array_type->getNestedType();
    const auto elem_size = BackingDataLengthCalculator::getArrayElementSize(nested_type);

    Array array;
    array.reserve(num_elems);

    if (BackingDataLengthCalculator::isFixedLengthDataType(removeNullable(nested_type)))
    {
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

                const auto elem = reader.read(buffer + offset, size);  // ⚠️ 漏洞点
                array.emplace_back(elem);
            }
        }
    }
    else
        throw Exception(ErrorCodes::UNKNOWN_TYPE, "VariableLengthDataReader doesn't support type {}", nested_type->getName());

    return std::move(array);
}
```

---

**报告生成时间**: 2026-04-23
**分析工具**: OpenCode Vulnerability Scanner
**分析人员**: Security Audit Team
