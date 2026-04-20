# OmniStateStore 威胁分析报告

## 项目概述

| 属性 | 值 |
|------|-----|
| 项目名称 | OmniStateStore |
| 语言 | C++14 + Java |
| 代码规模 | ~57,209 行核心代码，380 个源文件 |
| 用途 | Apache Flink 高性能状态存储引擎 |
| 架构 | LSM-tree 多层级内存管理架构 |

---

## 1. 攻击面分析

### 1.1 外部输入入口点

OmniStateStore 作为 Flink 状态后端，主要暴露以下攻击面：

| 入口点类型 | 描述 | 数据来源 | 风险等级 |
|-----------|------|----------|---------|
| **JNI 调用** | Java Native Interface 接口 | Flink 应用配置、用户数据 | **Critical** |
| **Checkpoint 文件** | 外部检查点文件 | HDFS/本地文件系统 | **Critical** |
| **配置参数** | 路径、内存限制、并行度 | Java BoostConfig 对象 | **High** |
| **序列化数据** | 二进制 KV 数据 | SST 文件、Slice 文件 | **High** |

### 1.2 JNI 接口攻击面 (Critical)

**JNI 入口点统计**: 21 个实现文件，~50 个导出函数

**主要安全风险函数**:

| 函数 | 文件 | 风险描述 |
|------|------|----------|
| `BoostStateDB_restore()` | BoostStateDB.cpp:64-131 | 外部路径传递，路径遍历风险 |
| `KVTableImpl_put/get()` | KVTableImpl.cpp | 原始指针传递，无句柄验证 |
| `DirectBuffer_nativeFreeDirectBuffer()` | DirectBuffer.cpp:89-90 | Use-after-free 风险 |
| `PQKeyIterator_open()` | PQKeyIterator.cpp | ByteArray 无边界检查 |

**数据流风险**:
- Java 传递 `jlong` 类型的原生指针直接用于 `reinterpret_cast`
- 原生内存地址暴露给 Java (通过 `SetLongField`)
- 无句柄有效性验证机制

---

## 2. 高危漏洞风险分析

### 2.1 路径遍历风险 (High → Critical)

**影响范围**: 状态恢复操作

**代码路径**:
```
JNI BoostStateDB_restore()
  → CheckPathValid() [kv_helper.h:327-381]
  → RestoreOperator::Restore()
  → CreateHardLinkForRestoredLocalFile() [restore_operator.cpp:152-165]
  → link(srcFile->GetPath(), targetFile->GetPath())
```

**漏洞分析**:
- `fileName` 来自检查点元数据文件 (`restoredFileInfo->GetFileName()`)
- `CheckPathValid()` 使用 `realpath()` 验证，但：
  - `realpath()` 需要路径存在才能完全验证
  - `allowPathNotExist` 标志可绕过存在性检查
  - **无显式 '..' 序列检查**
- 硬链接创建使用外部派生的路径组件

**缓解措施 (已存在)**:
- Java 层使用 `Path.normalize()` (BoostStateDownloader.java:95)
- Java 层检查 `Files.isSymbolicLink()` (EmbeddedOckStateBackend.java:847)

**建议增强**:
- 在 C++ 层添加显式 `'..'` 检查
- 验证解析后的路径在预期基础目录内
- 在 `link()` 操作前验证文件类型

### 2.2 内存安全风险 (Critical)

#### 2.2.1 Use-after-free

**位置**: `jni/DirectBuffer.cpp:89-90`

```cpp
void *addr = reinterpret_cast<void *>(data);
free(addr);
```

**问题**:
- 无所有权追踪
- 如果 Java 在 `nativeFreeDirectBuffer()` 后继续使用缓冲区，存在 UAF
- 无验证缓冲区是否真正由本模块分配

**攻击场景**:
1. Java 创建直接缓冲区
2. Native 调用 `nativeFreeDirectBuffer()`
3. Java 继续访问缓冲区 → UAF → 内存损坏/信息泄露

#### 2.2.2 原生指针暴露

**位置**: `jni/kv_helper.h:687-728`

```cpp
env->SetLongField(javaItem, keyFiled, reinterpret_cast<jlong>(cppItem->mKey));
env->SetIntField(javaItem, keyLenFiled, cppItem->mKeyLength);
```

**问题**:
- 原生内存地址直接暴露给 Java
- Java 可通过 DirectByteBuffer 访问任意原生内存
- 如果地址被篡改或泄露，可能导致内存损坏

### 2.3 反序列化风险 (High)

#### 2.3.1 长度控制的内存分配

**位置**: `common/io/file_input_view.h:64-88` (ReadUTF)

```cpp
uint64_t utfLen = 0;
if (UNLIKELY(Read(utfLen) != BSS_OK)) { return BSS_IO_ERR; }
if (UNLIKELY(utfLen > IO_SIZE_128K)) { return BSS_IO_ERR; }
auto *tempBuf = new (std::nothrow)uint8_t[utfLen];
```

**缓解**:
- 限制 `utfLen` ≤ 128KB ✓
- 但攻击者仍可控制分配 0-128KB

**位置**: `lsm_store/key/full_key_util.cpp:184-213` (ReadPrimary)

```cpp
uint32_t keyLen = 0;
RETURN_AS_NOT_OK_NO_LOG(inputView->Read(keyLen));
auto addr = FileMemAllocator::Alloc(memManager, holder, keyLen, __FUNCTION__);
```

**问题**:
- **无 keyLen 上限检查**
- 潜在内存耗尽攻击
- 可从恶意检查点文件触发

#### 2.3.2 无边界检查的 reinterpret_cast

**位置**: `binary/slice_binary.h:46-67` (SliceKey::Unpack)

```cpp
uint8_t *data = buffer->Data() + bufferOffset;
uint16_t stateId = *reinterpret_cast<const uint16_t *>(data);
```

**问题**:
- 无 `bufferOffset + sizeof(uint16_t) < bufferLen` 验证
- 如果 `bufferOffset` 无效，可能读取超出缓冲区边界

---

## 3. 中危漏洞分析

### 3.1 整数溢出风险

**位置**: `common/io/output_view.h:206-217` (Grow)

**已存在缓解**:
- 整数回绕检测 ✓
- `newCapacity << 1 < newCapacity` 检查

**潜在问题**:
- 如果初始大小较大，可能绕过某些检查

**位置**: `jni/KVTableImpl.cpp` 各函数

- `jint/jlong` 长度参数直接转换为 `uint32_t`
- 负值已检查，但大 `jlong` 值可能溢出 `uint32_t`

### 3.2 JNI 异常处理缺失

**位置**: 多处 JNI 调用

- 大多数 JNI 方法调用后未检查 Java 异常
- 例如 `kv_helper.h:161`: `env->CallObjectMethod()` 无异常检查

### 3.3 静态全局引用缓存

**位置**: `jni/kv_helper.h:40-53`

```cpp
static jclass stateTypeClass = nullptr;
static jmethodID stateTypeOfMethod = nullptr;
// ... 多个静态缓存
```

**风险**:
- 如果类被卸载/重载，过期引用可能导致崩溃
- JVM 崩溃时全局引用可能泄露

---

## 4. 已实施的安全控制

### 4.1 路径验证

| 机制 | 位置 | 描述 |
|------|------|------|
| `CheckPathValid()` | kv_helper.h:327-381 | realpath, access, lstat |
| `validateFilePath()` | EmbeddedOckStateBackend.java | Files.isSymbolicLink 检查 |
| `Path.normalize()` | BoostStateDownloader.java | 解析 '..' 序列 |

### 4.2 内存限制

| 机制 | 限制 | 位置 |
|------|------|------|
| UTF 长度限制 | 128KB | file_input_view.h |
| 整数回绕检测 | UINT32_MAX | output_view.h |
| ByteBuffer 边界检查 | pos + len ≤ mCapacity | byte_buffer.h |

### 4.3 版本验证

| 检查点 | 版本限制 | 验证位置 |
|--------|---------|----------|
| Snapshot 版本 | ≤ 5 | snapshot_restore_utils.cpp |
| Primary File Status 版本 | ≤ PRIMARY_FILE_STATUS_VERSION | version_meta_serializer.h |
| Java 元数据版本 | ≤ 3 | AbstractBoostSnapshotStrategy.java |
| Magic Number | -42 | version_meta_serializer.h |

### 4.4 安全函数使用

- 全项目使用 `memcpy_s` (secure memcpy)
- 集成 `libboundscheck` 安全库

### 4.5 编译安全选项

```
-fstack-protector-all
-fstack-protector-strong
-Wl,-z,relro,-z,now,-z,noexecstack
-D_FORTIFY_SOURCE=2
-fPIC
```

---

## 5. 漏洞严重性评估

### 严重性矩阵

| 漏洞类型 | 严重性 | 可利用性 | 影响范围 |
|----------|--------|----------|----------|
| Use-after-free (DirectBuffer) | **Critical** | High | 内存损坏、RCE 潜在 |
| 路径遍历 (Restore) | **High** | Medium | 文件系统访问 |
| 内存耗尽 (ReadPrimary keyLen) | **High** | Medium | 服务拒绝 |
| 原生指针暴露 | **High** | Medium | 内存损坏 |
| 缓冲区边界 (SliceKey::Unpack) | **Medium** | Low | 信息泄露 |
| 整数溢出 | **Medium** | Low | 内存损坏 |
| JNI 异常处理缺失 | **Low** | Low | 稳定性问题 |

---

## 6. 建议修复优先级

### P0 - 紧急修复

1. **DirectBuffer 所有权追踪**
   - 实现引用计数或所有权标志
   - 验证 `nativeFreeDirectBuffer()` 调用者拥有缓冲区
   - 防止 Use-after-free

2. **ReadPrimary keyLen 上限**
   - 添加最大 key 长度检查 (建议 1MB)
   - 防止恶意检查点导致内存耗尽

### P1 - 高优先级

3. **路径遍历增强**
   - 在 C++ `CheckPathValid()` 添加显式 '..' 检查
   - 验证解析路径在预期基础目录内
   - 在 `link()` 前验证文件类型

4. **句柄验证层**
   - 创建句柄注册表验证 `jlong` 句柄
   - 在 `reinterpret_cast` 前验证句柄有效性

### P2 - 中优先级

5. **SliceKey::Unpack 边界检查**
   - 添加显式边界验证: `bufferOffset + sizeof(T) < bufferLen`

6. **JNI 异常处理**
   - 在所有 JNI 方法调用后添加异常检查

### P3 - 低优先级

7. **原生地址保护**
   - 考虑混淆或验证传递给 Java 的内存地址

---

## 7. 模块风险评估

| 模块 | 风险等级 | 主要风险点 |
|------|----------|------------|
| **jni** | Critical | 原生指针暴露、UAF、无句柄验证 |
| **snapshot** | Critical | 外部路径、恢复操作、硬链接创建 |
| **common/io** | High | 反序列化长度控制、边界检查 |
| **lsm_store/key** | High | 无上限 keyLen、内存分配 |
| **binary** | Medium | reinterpret_cast 无边界验证 |
| **db** | High | 协调所有高风险操作 |
| **slice_table** | Medium | 数据处理、索引操作 |
| **fresh_table** | Medium | 内存管理、SkipList 操作 |
| **memory** | Medium | 分配器、淘汰管理 |
| **compress** | Low | LZ4 压缩/解压 |
| **plugin_java** | Critical | Unsafe 内存操作、路径处理 |

---

## 8. 攻击场景示例

### 场景 1: 恶意检查点恢复

**攻击向量**: 构造恶意检查点文件

1. 修改检查点元数据，插入 `../../../etc/passwd` 作为文件名
2. 触发恢复操作 `BoostStateDB_restore()`
3. 路径验证可能通过 (取决于 `allowPathNotExist` 配置)
4. 硬链接创建可能导致敏感文件链接

**缓解**: 增强 `CheckPathValid()`，添加基础目录验证

### 场景 2: 内存耗尽

**攻击向量**: 构造大 keyLen 的检查点文件

1. 修改 SST 文件，设置 `keyLen = 0xFFFFFFFF`
2. 触发读取操作 `FullKeyUtil::ReadPrimary()`
3. 尝试分配 ~4GB 内存
4. 服务拒绝或 OOM

**缓解**: 添加 keyLen 上限检查

### 场景 3: UAF 利用

**攻击向量**: DirectBuffer 生命周期攻击

1. Java 创建直接缓冲区
2. 开始迭代操作
3. 触发 `nativeFreeDirectBuffer()`
4. 继续迭代 → UAF → 潜在代码执行

**缓解**: 实现所有权追踪

---

## 9. 总结

OmniStateStore 作为 Flink 状态存储引擎，暴露了广泛的 JNI 接口攻击面。主要安全风险集中在：

1. **JNI 边界**: 原生指针暴露、句柄验证缺失、DirectBuffer UAF
2. **恢复操作**: 外部路径传递、硬链接创建使用外部文件名
3. **反序列化**: 长度控制内存分配、边界检查缺失

已存在的安全控制（路径验证、版本检查、安全编译选项）提供了基础防护，但建议增强：

- C++ 层路径遍历检查
- DirectBuffer 所有权机制
- 反序列化长度上限
- 句柄验证层

---

## 附录: 关键文件清单

| 类别 | 文件 | 安全相关性 |
|------|------|------------|
| JNI 核心 | jni/jni_common.cpp | JNI 生命周期 |
| JNI DB | jni/BoostStateDB.cpp | 恢复路径 |
| JNI 辅助 | jni/kv_helper.h | 路径验证、指针暴露 |
| JNI 内存 | jni/DirectBuffer.cpp | UAF 风险 |
| 恢复 | snapshot/restore_operator.cpp | 硬链接创建 |
| 序列化 | common/io/file_input_view.h | UTF 长度限制 |
| Key 读取 | lsm_store/key/full_key_util.cpp | keyLen 无上限 |
| Binary | binary/slice_binary.h | 边界检查缺失 |
| Java 路径 | EmbeddedOckStateBackend.java | symlink 检查 |

---

**报告生成时间**: 2026-04-20  
**分析范围**: 核心代码 57,209 行，380 源文件  
**分析方法**: 多 Agent 并行深度分析