# VEC-001-MEMLEAK: 内存泄漏漏洞

## 漏洞概述

**漏洞类型**: 内存泄漏 (CWE-401)  
**严重级别**: High  
**置信度**: 90%  
**影响模块**: vector, jni_bindings

OmniOperator 的 `VectorBatch::FreeAllVectors()` 函数存在内存泄漏缺陷。当所有向量通过 `AppendFlat` 添加时，`flatSize` 等于 `vectors.size()`，导致计算出的 `vectorSize` 为 0，没有任何向量被释放。

## 漏洞触发条件

1. 使用 `AppendFlat` 方法添加所有向量
2. 调用析构函数或 `FreeAllVectors()`
3. 长时间运行导致内存持续增长

## 关键代码分析

### vector_batch.cpp:65-73

```cpp
void VectorBatch::FreeAllVectors()
{
    // ⚠️ 计算逻辑缺陷
    int32_t vectorSize = static_cast<int32_t>(vectors.size()) - flatSize;
    
    // 如果所有向量通过 AppendFlat 添加
    // flatSize == vectors.size()
    // vectorSize == 0
    // ⚠️ 循环不执行，没有向量被释放
    
    for (int32_t vecIndex = 0; vecIndex < vectorSize; ++vecIndex) {
        delete vectors[vecIndex];
        vectors[vecIndex] = nullptr;
    }
}
```

## 问题分析

```
场景: 所有向量通过 AppendFlat 添加

初始状态:
- vectors.size() = 0
- flatSize = 0

添加第一个向量 (AppendFlat):
- vectors.size() = 1
- flatSize = 1

添加第二个向量 (AppendFlat):
- vectors.size() = 2
- flatSize = 2

...

最终状态:
- vectors.size() = N
- flatSize = N

FreeAllVectors 计算:
- vectorSize = vectors.size() - flatSize = N - N = 0

结果:
- 循环不执行
- 所有向量内存泄漏
```

## 危害评估

### 影响
- **内存泄漏**: 长时间运行的 Worker 进程内存持续增长
- **资源耗尽**: 最终导致内存不足，进程被 OOM Killer 杀死
- **性能下降**: 内存压力大时系统性能下降

### CVSS 评分

内存泄漏通常不视为可利用漏洞，危害评估：
- **攻击向量**: 不适用（代码缺陷，非攻击）
- **影响**: Medium (资源耗尽)

**危害级别**: Medium (资源耗尽风险，非安全漏洞)

## 修复建议

### 1. 修改 FreeAllVectors 逻辑（优先级：高）

```cpp
void VectorBatch::FreeAllVectors()
{
    // 修复: 释放所有向量，不管如何添加
    for (int32_t vecIndex = 0; vecIndex < static_cast<int32_t>(vectors.size()); ++vecIndex) {
        if (vectors[vecIndex] != nullptr) {
            delete vectors[vecIndex];
            vectors[vecIndex] = nullptr;
        }
    }
    vectors.clear();
    flatSize = 0;
}
```

### 2. 添加追踪机制（优先级：中）

```cpp
// 追踪哪些向量需要释放
std::set<Vector*> ownedVectors;

void AppendFlat(Vector* vec) {
    vectors.push_back(vec);
    flatSize++;
    // 记录需要释放的向量
    ownedVectors.insert(vec);
}

void FreeAllVectors() {
    for (auto* vec : ownedVectors) {
        delete vec;
    }
    ownedVectors.clear();
    vectors.clear();
    flatSize = 0;
}
```

### 3. 使用智能指针（优先级：中）

```cpp
// 使用 unique_ptr 自动管理内存
std::vector<std::unique_ptr<Vector>> vectors;
```

## 参考信息

- CWE-401: Missing Release of Memory after Effective Lifetime
- C++ Memory Management Best Practices