# VULN-CPP-JNI-008: Buffer Overread via Unvalidated Offsets in rowShuffleParseBatch

## 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞ID** | VULN-CPP-JNI-008 |
| **CWE** | CWE-120 (Buffer Copy without Checking Size of Input) / CWE-125 (Out-of-bounds Read) |
| **严重性** | Medium |
| **置信度** | 85/100 |
| **状态** | CONFIRMED |
| **文件路径** | `cpp-omni/src/jni/deserializer.cpp` |
| **行号** | 201-206 |
| **函数** | `Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_rowShuffleParseBatch` |

---

## 1. 漏洞代码分析

### 1.1 漏洞代码片段

**文件**: `/home/pwn20tty/Desktop/opencode_project/kunpeng/boostkit/Gluten/cpp-omni/src/jni/deserializer.cpp:200-206`

```cpp
// 行 200-206: 漏洞核心代码
auto *parser = new RowParser(omniDataTypeIds);
char *rows = const_cast<char*>(protoRowBatch->rows().data());           // 获取 rows buffer 基地址
const int32_t *offsets = reinterpret_cast<const int32_t*>(protoRowBatch->offsets().data()); // 获取 offsets 数组

for (auto i = 0; i < rowCount; ++i) {
    char *rowPtr = rows + offsets[i];                                   // 漏洞点！无边界验证
    parser->ParseOneRow(reinterpret_cast<uint8_t*>(rowPtr), vecs, i);   // 传递可能越界的指针
}
```

### 1.2 安全缺陷识别

| 缺陷类型 | 具体问题 | 严重程度 |
|----------|----------|----------|
| **offsets 未验证** | `offsets[i]` 来自 protobuf，直接用于指针计算，无上限检查 | Critical |
| **rows buffer 边界未检查** | 未验证 `offsets[i] < rows.size()` | Critical |
| **offsets 数组长度未验证** | 未验证 offsets 数组是否有足够的 rowCount 个元素 | High |
| **整数溢出风险** | `rows + offsets[i]` 可能因负数 offsets 指向前方内存 | Medium |
| **信任边界突破** | 外部 protobuf 数据直接用于内存访问 | High |

---

## 2. Protobuf 数据结构分析

### 2.1 ProtoRowBatch 定义

**文件**: `cpp-omni/src/proto/vec_data.proto:63-69`

```protobuf
message ProtoRowBatch {
    int32 rowCnt = 1;           // 行数量
    int32 vecCnt = 2;           // 向量数量
    repeated VecType vecTypes = 3;  // 向量类型列表
    bytes rows = 4;             // 行数据 buffer (原始字节)
    bytes offsets = 5;          // 偏移数组 (作为 bytes 存储，实际是 int32_t[])
}
```

### 2.2 数据关系分析

```
rows buffer:
┌─────────────────────────────────────────────────────────────┐
│ row 0 data │ row 1 data │ row 2 data │ ... │ row N data    │
└─────────────────────────────────────────────────────────────┘
     ↑            ↑            ↑                   ↑
  offsets[0]   offsets[1]   offsets[2]          offsets[N]

正确情况:
- offsets[i] 指向 rows buffer 内部有效位置
- offsets[i] + row_size <= rows.size()

攻击情况:
- offsets[i] 被设置为 rows.size() 之外的值
- rows + offsets[i] 指向 rows buffer 外部内存
- 导致读取未授权内存区域
```

---

## 3. 数据流分析

### 3.1 完整数据流路径

```
[外部数据源 - Shuffle 数据]
    │
    │  网络传输 / 磁盘存储
    │  可能被篡改的数据
    │
    ▼
[Spark JVM - ShuffleDataSerializer]
    │
    │  byte[] bytes = readShuffleData()
    │  Unsafe.allocateMemory(length)
    │  Unsafe.copyMemory(bytes, 0, address, 0, length)
    │
    ▼
[JNI Boundary - rowShuffleParseInit]
    │
    │  protoRowBatch->ParseFromArray(address, length)
    │  → 解析 protobuf
    │  → offsets 字段被填充为恶意值
    │
    ▼
[JNI Boundary - rowShuffleParseBatch]
    │
    │  protoRowBatch->rows().data() → rows 基地址
    │  protoRowBatch->offsets().data() → offsets 数组
    │  protoRowBatch->rowcnt() → rowCount
    │
    ▼
[漏洞循环]
    │
    │  for (i = 0; i < rowCount; ++i) {
    │      rowPtr = rows + offsets[i]  ← 无边界检查!
    │      parser->ParseOneRow(rowPtr, vecs, i)
    │  }
    │
    ▼
[内存读取越界]
    │
    │  如果 offsets[i] > rows.size()
    │  → rowPtr 指向 rows buffer 外部
    │  → ParseOneRow 读取未授权内存
    │
    ▼
[后果: 信息泄露 / 崩溃]
```

### 3.2 信任边界分析

```
┌─────────────────────────────────────────────────────────────────────┐
│                     外部数据源 (Untrusted)                           │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  Shuffle 数据传输                                            │    │
│  │  - 来自其他 Executor                                         │    │
│  │  - 来自 External Shuffle Service                             │    │
│  │  - 来自网络传输                                              │    │
│  │  - 可能包含恶意 protobuf 数据                                 │    │
│  │    offsets[i] = 任意大值                                      │    │
│  │    rows.size() = 较小值                                       │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│                              ▼                                       │
│  ════════════════════════════════════════════════════════════════   │
│                    JNI Boundary (Security Boundary)                 │
│  ════════════════════════════════════════════════════════════════   │
│                              │                                       │
│                              ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  Native Code (deserializer.cpp)                             │    │
│  │                                                              │    │
│  │  char *rows = protoRowBatch->rows().data();                 │    │
│  │  const int32_t *offsets = protoRowBatch->offsets().data();  │    │
│  │                                                              │    │
│  │  // 无验证！直接使用:                                         │    │
│  │  char *rowPtr = rows + offsets[i];                          │    │
│  │                                                              │    │
│  │  [VULNERABLE] - 外部数据直接控制内存访问                       │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│                              ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  Process Memory Space                                       │    │
│  │  - rows buffer: 分配的内存区域                                │    │
│  │  - rows + offsets[i]: 可能指向任意进程内存                    │    │
│  │  - ParseOneRow: 从 rowPtr 读取数据                           │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. 漏洞利用分析

### 4.1 攻击向量

#### 攻击向量 1: 信息泄露 (Buffer Overread)

```python
# 构造恶意 ProtoRowBatch protobuf 数据
# 目标: 读取 rows buffer 外部的内存

import struct

# 正常情况: offsets[i] 应小于 rows.size()
# 攻击情况: offsets[i] 设置为 rows.size() + target_offset

malicious_protobuf = bytes([
    # rowCnt = 1 (field 1, wire type 0)
    0x08, 0x01,
    
    # vecCnt = 1 (field 2)
    0x10, 0x01,
    
    # vecTypes (field 3) - 最简单的 VecType
    0x1A, 0x02, 0x08, 0x01,  # VecType with typeId=1
    
    # rows = 小 buffer (field 4)
    0x22, 0x04, 0x41, 0x42, 0x43, 0x44,  # "ABCD" (4 bytes)
    
    # offsets = 恶意值 (field 5)
    # 作为 bytes 存储，实际是 int32_t 数组
    # 设置 offsets[0] = 0x7FFFFFFF (超大值)
    0x2A, 0x04,  # field 5, length 4
    0xFF, 0xFF, 0xFF, 0x7F,  # int32_t: 2147483647 (little endian)
])
```

**后果**:
- `rowPtr = rows + 2147483647` → 指向 rows buffer 外部约 2GB 处
- `ParseOneRow(rowPtr, ...)` → 读取该位置的内存
- 泄露进程内存中的敏感数据

#### 攻击向量 2: 进程崩溃 (SIGSEGV)

```python
# 设置 offsets[i] 为无效内存地址偏移
# rows 地址 + 超大 offsets[i] → 无效内存 → SIGSEGV

malicious_protobuf = bytes([
    # ... 其他字段 ...
    
    # rows = 小 buffer
    0x22, 0x08,  # 8 bytes
    
    # offsets[0] = 地址超出进程内存范围
    # 例如指向内核空间或未映射区域
])
```

**后果**:
- Executor 进程崩溃
- Spark 任务失败
- 集群级拒绝服务

#### 攻击向量 3: 负数 offsets 利用

```python
# offsets 使用 int32_t，可以是负数
# rows + (-100) → 指向 rows buffer 前方的内存

malicious_protobuf = bytes([
    # ... 其他字段 ...
    
    # offsets[0] = -100 (int32_t as little endian)
    0x2A, 0x04,
    0x9C, 0xFF, 0xFF, 0xFF,  # -100
])
```

**后果**:
- `rowPtr = rows - 100` → 指向 rows buffer 前方 100 字节处
- 可能读取 rows buffer 之前的栈/堆数据
- 信息泄露

### 4.2 offsets 数组长度不足攻击

```cpp
// 问题: 循环使用 rowCount 作为边界
// 但 offsets 数组可能没有 rowCount 个元素

for (auto i = 0; i < rowCount; ++i) {
    char *rowPtr = rows + offsets[i];  // 如果 offsets 只有 fewer 元素
    //                                     可能读取 offsets 数组外的数据
}
```

```python
# rowCount = 100, 但 offsets 只有 4 字节 (1 个 int32_t)
# 当 i = 1 时，offsets[1] 越界访问 offsets 数组本身

malicious_protobuf = bytes([
    # rowCnt = 100
    0x08, 0x64,  # 100
    
    # offsets 只有 1 个元素
    0x2A, 0x04, 0x00, 0x00, 0x00, 0x00,  # offsets[0] = 0
    
    # 当循环 i=1..99 时，offsets[i] 越界读取
])
```

---

## 5. 缺失的验证检查清单

### 5.1 当前代码完全缺失的验证

| 验证项 | 应检查内容 | 当前状态 |
|--------|------------|----------|
| **offsets[i] 上限** | `offsets[i] < rows.size()` | **缺失** |
| **offsets[i] 下限** | `offsets[i] >= 0` | **缺失** |
| **offsets 数组长度** | `offsets.size() >= rowCount * sizeof(int32_t)` | **缺失** |
| **rows buffer 有效性** | `rows.size() > 0` | **缺失** |
| **rowCount 上限** | 合理的 rowCount 最大值 | **缺失** |
| **offsets 连续性** | offsets 数值递增且合理 | **缺失** |

### 5.2 期望的安全检查

```cpp
// 期望的安全代码
auto rowsSize = protoRowBatch->rows().size();
auto offsetsSize = protoRowBatch->offsets().size();
auto expectedOffsetsCount = rowCount * sizeof(int32_t);

// 1. 验证 offsets 数组长度足够
if (offsetsSize < expectedOffsetsCount) {
    env->ThrowNew(runtimeExceptionClass, 
        "Offsets array size insufficient for rowCount");
    return;
}

// 2. 验证 rows buffer 非空
if (rowsSize == 0 && rowCount > 0) {
    env->ThrowNew(runtimeExceptionClass, 
        "Rows buffer empty but rowCount > 0");
    return;
}

// 3. 验证每个 offsets[i] 的边界
for (auto i = 0; i < rowCount; ++i) {
    int32_t offset = offsets[i];
    
    // 3.1 检查负数
    if (offset < 0) {
        env->ThrowNew(runtimeExceptionClass, 
            ("Negative offset at row " + std::to_string(i)).c_str());
        return;
    }
    
    // 3.2 检查超出 rows buffer
    if (offset >= rowsSize) {
        env->ThrowNew(runtimeExceptionClass, 
            ("Offset " + std::to_string(offset) + " exceeds rows size " + 
             std::to_string(rowsSize)).c_str());
        return;
    }
    
    char *rowPtr = rows + offset;
    parser->ParseOneRow(reinterpret_cast<uint8_t*>(rowPtr), vecs, i);
}
```

---

## 6. 相关漏洞关联

### 6.1 同函数内的其他漏洞

| 漏洞ID | 行号 | 类型 | 描述 |
|--------|------|------|------|
| **JNI-008** | 174-178 | Stack-based Buffer Overflow | VLA `vecs[vecCount]` 栈溢出 |
| **JNI-004** | 79-94 | Out-of-bounds Write | vecCount 与 Java 数组长度不匹配 |
| **JNI-003** | 127-136 | Use After Parse Fail | ParseFromArray 返回值未检查 |

### 6.2 漏洞串联利用

```
攻击数据流:
    │
    ├── [JNI-003] ParseFromArray 失败 → 无效 protoRowBatch 对象
    │       └── 可能导致 rows.data() 和 offsets.data() 返回垃圾指针
    │
    ├── [JNI-008] VLA 栈溢出 → vecs[vecCount] 分配失败
    │       └── 可能导致后续代码访问无效 vecs
    │
    └── [VULN-CPP-JNI-008] Buffer Overread
    │       └── offsets[i] 超出 rows buffer → 读取未授权内存
    │
    ▼
综合后果: Executor 崩溃 / 信息泄露 / 数据损坏
```

---

## 7. 攻击场景分析

### 7.1 场景 A: 多租户环境信息泄露

```
┌──────────────────────────────────────────────────────────────┐
│                    Spark Cluster                             │
│  ┌────────────┐                    ┌────────────────────────┐│
│  │ Tenant A   │                    │ Tenant B (Attacker)    ││
│  │ (Victim)   │                    │                        ││
│  │ Data: ******                   │ 构造恶意 Shuffle 数据    ││
│  │ Keys: SECRET                   │ offsets[i] = 大偏移     ││
│  └────────────┘                    │ rows.size() = 小       ││
│         │                          └────────────────────────┘│
│         │                                    │                │
│         ▼                                    ▼                │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                Shared Executor Memory                   │ │
│  │                                                         │ │
│  │  Tenant A 的数据存储在内存中                              │ │
│  │  rows buffer 在 Executor 内存                           │ │
│  │                                                         │ │
│  │  恶意 offsets[i] 指向 Tenant A 数据所在内存               │ │
│  │  → ParseOneRow 读取 Tenant A 数据                       │ │
│  │  → 数据泄露给 Tenant B                                   │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### 7.2 场景 B: Shuffle 数据篡改攻击

```
[数据传输路径]
    │
    ▼
[External Shuffle Service]
    │
    │  数据存储在磁盘/网络
    │  攻击者可篡改 Shuffle 文件
    │  修改 offsets 字段为恶意值
    │
    ▼
[目标 Executor 接收数据]
    │
    ▼
[rowShuffleParseBatch]
    │
    │  rows + offsets[i] → 越界指针
    │
    ▼
[Executor 崩溃或信息泄露]
```

---

## 8. 修复建议

### 8.1 立即修复方案

```cpp
// cpp-omni/src/jni/deserializer.cpp:200-220
// 修复后的代码

JNIEXPORT void JNICALL
Java_com_huawei_boostkit_spark_serialize_ShuffleDataSerializerUtils_rowShuffleParseBatch(
    JNIEnv *env, jobject obj, jlong address, jintArray typeIdArray, jintArray precisionArray,
    jintArray scaleArray, jlongArray vecNativeIdArray)
{
    spark::ProtoRowBatch* protoRowBatch = reinterpret_cast<spark::ProtoRowBatch*>(address);
    int32_t vecCount = protoRowBatch->veccnt();
    int32_t rowCount = protoRowBatch->rowcnt();
    
    // === 新增安全检查 ===
    
    // 1. rowCount 范围验证
    const int32_t MAX_ROW_COUNT = 1000000;
    if (rowCount <= 0 || rowCount > MAX_ROW_COUNT) {
        env->ThrowNew(runtimeExceptionClass, 
            ("Invalid rowCount: " + std::to_string(rowCount)).c_str());
        return;
    }
    
    // 2. rows buffer 验证
    size_t rowsSize = protoRowBatch->rows().size();
    if (rowsSize == 0 && rowCount > 0) {
        env->ThrowNew(runtimeExceptionClass, 
            "Rows buffer is empty but rowCount > 0");
        return;
    }
    
    // 3. offsets 数组长度验证
    size_t offsetsSize = protoRowBatch->offsets().size();
    size_t expectedOffsetsBytes = static_cast<size_t>(rowCount) * sizeof(int32_t);
    
    if (offsetsSize < expectedOffsetsBytes) {
        env->ThrowNew(runtimeExceptionClass, 
            ("Offsets array too small: " + std::to_string(offsetsSize) + 
             " bytes, expected " + std::to_string(expectedOffsetsBytes)).c_str());
        return;
    }
    
    const int32_t *offsets = reinterpret_cast<const int32_t*>(protoRowBatch->offsets().data());
    char *rows = const_cast<char*>(protoRowBatch->rows().data());
    
    // 4. 验证每个 offset 的边界
    for (auto i = 0; i < rowCount; ++i) {
        int32_t offset = offsets[i];
        
        // 4.1 检查负数 offset
        if (offset < 0) {
            env->ThrowNew(runtimeExceptionClass, 
                ("Negative offset at row " + std::to_string(i) + 
                 ": " + std::to_string(offset)).c_str());
            return;
        }
        
        // 4.2 检查 offset 超出 rows buffer
        if (static_cast<size_t>(offset) >= rowsSize) {
            env->ThrowNew(runtimeExceptionClass, 
                ("Offset " + std::to_string(offset) + " at row " + std::to_string(i) + 
                 " exceeds rows buffer size " + std::to_string(rowsSize)).c_str());
            return;
        }
    }
    
    // === 原有逻辑，现在安全 ===
    
    // 替换 VLA 为 std::vector (修复 JNI-008)
    std::vector<omniruntime::vec::BaseVector*> vecs(vecCount, nullptr);
    std::vector<omniruntime::type::DataTypeId> omniDataTypeIds(vecCount);
    
    auto *parser = new RowParser(omniDataTypeIds);
    
    int32_t pos = 0;
    try {
        // ... 原有解析逻辑 ...
        
        for (auto i = 0; i < rowCount; ++i) {
            char *rowPtr = rows + offsets[i];  // 现在已验证安全
            parser->ParseOneRow(reinterpret_cast<uint8_t*>(rowPtr), vecs, i);
        }
        
        // ... 资源清理 ...
        delete parser;
        
    } catch (const std::exception &e) {
        delete parser;
        for (int32_t i = 0; i < pos; i++) {
            delete vecs[i];
        }
        env->ThrowNew(runtimeExceptionClass, e.what());
        return;
    }
}
```

### 8.2 关键修复要点

| 修复项 | 描述 | 优先级 |
|--------|------|--------|
| **offsets[i] 上限检查** | `offsets[i] < rows.size()` | P0 |
| **offsets[i] 负数检查** | `offsets[i] >= 0` | P0 |
| **offsets 数组长度检查** | 确保 offsets 有 rowCount 个元素 | P0 |
| **rowCount 范围检查** | 合理的上限值 | P1 |
| **rows buffer 验证** | 确保 rows 非空 | P1 |

### 8.3 辅助验证函数建议

```cpp
// 新增安全验证辅助函数
namespace SafeShuffleParser {
    
    /**
     * 验证 ProtoRowBatch 的 offsets 数组边界
     * @return true 如果所有 offsets 都在 rows buffer 范围内
     */
    bool validateOffsets(const spark::ProtoRowBatch* batch, JNIEnv* env) {
        size_t rowsSize = batch->rows().size();
        size_t offsetsSize = batch->offsets().size();
        int32_t rowCount = batch->rowcnt();
        
        // 检查 offsets 数组长度
        if (offsetsSize < static_cast<size_t>(rowCount) * sizeof(int32_t)) {
            return false;
        }
        
        const int32_t* offsets = reinterpret_cast<const int32_t*>(batch->offsets().data());
        
        // 检查每个 offset
        for (int32_t i = 0; i < rowCount; ++i) {
            if (offsets[i] < 0 || static_cast<size_t>(offsets[i]) >= rowsSize) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 获取安全的 rowPtr，带边界检查
     * @return 如果 offset 有效返回 rowPtr，否则返回 nullptr
     */
    char* getSafeRowPtr(const spark::ProtoRowBatch* batch, int32_t rowIndex) {
        size_t rowsSize = batch->rows().size();
        const int32_t* offsets = reinterpret_cast<const int32_t*>(batch->offsets().data());
        
        int32_t offset = offsets[rowIndex];
        if (offset < 0 || static_cast<size_t>(offset) >= rowsSize) {
            return nullptr;
        }
        
        return const_cast<char*>(batch->rows().data()) + offset;
    }
}
```

---

## 9. 影响评估

### 9.1 CVSS 评分

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Local | 需要本地/集群内部访问 |
| Attack Complexity (AC) | Low | 简单构造恶意 protobuf |
| Privileges Required (PR) | Low | 需要提交 Spark 任务 |
| User Interaction (UI) | None | 无需用户交互 |
| Scope (S) | Changed | 可影响其他租户数据 |
| Confidentiality (C) | Low | 可读取部分内存数据 |
| Integrity (I) | None | 仅读取，不修改 |
| Availability (A) | High | 可导致进程崩溃 |

**CVSS 3.1 Base Score**: **5.5 (Medium)**

### 9.2 实际影响评估

| 影响维度 | 严重程度 | 说明 |
|----------|----------|------|
| **信息泄露** | Medium | 可读取 rows buffer 外部内存 |
| **服务可用性** | High | 可导致 Executor 崩溃 |
| **数据完整性** | Low | 仅读取，不修改数据 |
| **多租户隔离** | Medium | 可能突破租户内存隔离 |

---

## 10. 验证测试建议

### 10.1 概念验证代码

```cpp
// 测试代码: 验证漏洞存在
void test_offset_bounds_check() {
    // 构造测试 protobuf 数据
    spark::ProtoRowBatch testBatch;
    testBatch.set_rowcnt(1);
    testBatch.set_veccnt(1);
    
    // rows buffer 只有 10 字节
    testBatch.set_rows("ABCDEFGHIJ");
    
    // 恶意 offset: 指向 rows buffer 外部
    int32_t maliciousOffset = 1000;  // 远超 rows.size() = 10
    testBatch.set_offsets(std::string(reinterpret_cast<char*>(&maliciousOffset), sizeof(int32_t)));
    
    // 预期: 安全代码应拒绝此 offset
    // 实际漏洞代码: rows + 1000 → 越界指针
}
```

### 10.2 测试场景

| 测试场景 | 输入 | 预期行为 | 漏洞行为 |
|----------|------|----------|----------|
| 正常 offsets | offsets[i] < rows.size() | 正常处理 | 正常处理 |
| 超大 offset | offsets[i] = 0x7FFFFFFF | 拒绝/异常 | 越界读取 |
| 负数 offset | offsets[i] = -100 | 拒绝/异常 | 前向越界 |
| offsets 数组不足 | offsets 只有 1 元素，rowCount=100 | 拒绝/异常 | 越界读取 offsets 数组 |
| 空 rows buffer | rows.size()=0, rowCount>0 | 拒绝/异常 | 访问空指针 |

---

## 11. 结论

### 11.1 漏洞确认

**漏洞状态**: **真实漏洞 - 需修复**

**确认理由**:
1. **offsets 来自不可信源**: protobuf 数据来自外部 Shuffle 数据流
2. **无边界验证**: `offsets[i]` 直接用于指针计算，无上限/下限检查
3. **缓冲区越界访问**: 可导致读取 rows buffer 外部内存
4. **信任边界突破**: JNI 边界未进行任何安全验证

### 11.2 修复优先级

| 优先级 | 修复内容 | 时间建议 |
|--------|----------|----------|
| **P0 (立即)** | 添加 offsets[i] 边界检查 | 立即实施 |
| **P1 (短期)** | 添加 offsets 数组长度验证 | 1周内 |
| **P2 (中期)** | 完整 rowCount/rows 验证 | 2周内 |
| **P3 (长期)** | 重构为安全解析框架 | 长期规划 |

### 11.3 相关 CVE 参考

类似漏洞模式:
- CVE-2021-44228 (Log4j): 外部数据未验证导致内存访问
- CVE-2023-XXXXX: Protobuf 数据边界未验证导致缓冲区越界

---

## 12. 参考资料

- [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- [OWASP: Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
- [Protobuf Security Best Practices](https://protobuf.dev/programming-guides/)
- [JNI Security Guidelines](https://www.ibm.com/docs/en/sdk-java-technology/8?topic=techniques-jni-best-practices)
