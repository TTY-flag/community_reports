# llm_datadist_cache_mgr-V007 - 参数校验缺失漏洞深度分析报告

## 漏洞概要

| 字段 | 值 |
|------|-----|
| 漏洞ID | llm_datadist_cache_mgr-V007 |
| 漏洞类型 | Missing Validation (参数校验缺失) |
| CWE分类 | CWE-129: Improper Validation of Array Index |
| 严重性 | High (高) |
| 置信度 | 80 |
| 影响文件 | `src/llm_datadist/cache_mgr/data_cache_engine.cc` |
| 漏洞位置 | 第 368-379 行 |
| 受影响函数 | `CheckParam` |
| 涉及模块 | llm_datadist_cache_mgr, data_transfer |

## 漏洞详情

### 漏洞描述

在 `data_cache_engine.cc` 的 `CheckParam` 函数中，对 `PullCacheParam` 参数进行验证时：

- **decoder_blocks（本地块索引）**：有完整的边界检查（验证 `block_index < cache_entry.num_blocks`）
- **prompt_blocks（远程块索引）**：**仅检查数组大小匹配，没有边界检查**

这导致恶意远程集群可以发送超出实际缓存块数量的索引，造成远程内存越界读取。

### 代码分析

漏洞代码位置：

```cpp
// data_cache_engine.cc 行 349-386
ge::Status DataCacheEngine::CheckParam(const CacheEntry &cache_entry, 
                                        const PullCacheParam &pull_cache_param) {
  // ... 其他检查 ...
  
  // 行 367-379：块索引检查
  if ((cache_entry.placement == CachePlacement::HOST) && 
      (cache_entry.cache_mem_type == CacheMemType::BLOCKS)) {
    // decoder_blocks 有边界检查 ✓
    for (const auto block_index : pull_cache_param.decoder_blocks) {
      LLM_CHK_BOOL_RET_STATUS(block_index < cache_entry.num_blocks,
                             ge::LLM_PARAM_INVALID,
                             "local block index out of bound, index = %lu, num_blocks = %lu", 
                             block_index, cache_entry.num_blocks);
    }
    
    // prompt_blocks 仅检查大小匹配，无边界检查 ✗
    LLM_CHK_BOOL_RET_STATUS(pull_cache_param.prompt_blocks.empty() ||
                               (pull_cache_param.decoder_blocks.size() == pull_cache_param.prompt_blocks.size()),
                           ge::LLM_PARAM_INVALID,
                           "check failed, src_block_index.size() = %zu, dst_block_index.size() = %zu",
                           pull_cache_param.prompt_blocks.size(),
                           pull_cache_param.decoder_blocks.size());
    // ↑ 仅检查数组大小相等，未检查 prompt_blocks 内容是否在合法范围内
  }
}
```

### 数据流分析

**prompt_blocks 数据流**：

```
[远程集群节点]
    ↓ 网络传输 (PullCache 请求)
[pull_cache_param.prompt_blocks] ← 污点源（来自远程）
    ↓ CheckParam (仅大小匹配检查，无边界验证)
[DataTransferClient::SetBufferInfo] (data_transfer_client.cc 行 97)
    ↓ 使用未验证的块索引
[PullCacheByGet]
    ↓ 远程内存访问
[远程缓存越界读取]
```

### 根本原因

漏洞的根本原因：

1. **不对称的验证策略**：本地块索引有完整边界检查，远程块索引被忽略
2. **错误的安全假设**：假设远程集群是可信的，不验证其发送的数据
3. **跨信任边界数据缺乏验证**：`prompt_blocks` 来自远程集群（不信任侧），却被当作可信数据处理

### PullCacheParam 结构

```cpp
struct PullCacheParam {
  std::vector<uint64_t> decoder_blocks;   // 本地块索引 - 有边界检查
  std::vector<uint64_t> prompt_blocks;    // 远程块索引 - 无边界检查 ✗
  int64_t size;
  uint32_t batch_index;
  size_t tensor_num_per_layer;
  std::vector<uint64_t> src_tensor_indices;
  std::vector<uint64_t> dst_tensor_indices;
};
```

## 攻击路径分析

### 攻击场景

**攻击前提条件**：
- 攻击者控制集群中的一个远程节点（或伪造为远程节点）
- 远程节点与目标节点已通过 `LinkLlmClusters` 建立连接

**攻击步骤**：

1. 攻击者控制的远程节点发起 `PullCache` 请求
2. 在 `pull_cache_param.prompt_blocks` 中包含超出范围的块索引
   - 例如：真实缓存只有 100 个块，发送索引值 1000 或更大的值
3. 目标节点的 `CheckParam` 函数：
   - 检查 `decoder_blocks` 边界（通过）
   - 仅检查 `prompt_blocks.size() == decoder_blocks.size()`（通过）
   - **不检查 prompt_blocks 的内容边界** ✗
4. 请求继续执行，`DataTransferClient` 使用未验证的索引访问远程缓存
5. 远程缓存越界读取，可能导致：
   - 读取敏感数据（信息泄露）
   - 访问无效内存（崩溃）
   - 数据损坏

### 攻击链路图

```
[恶意远程集群节点]
    ↓ LinkLlmClusters 已建立连接
    ↓ 发送 PullCache 请求
    ↓ prompt_blocks = [超大索引值]
[DataCacheEngine::PullCache] (行 113-161)
    ↓
[CheckParam] (行 349-386)
    ↓ decoder_blocks 边界检查 ✓
    ↓ prompt_blocks 大小检查 ✓（仅检查大小）
    ↓ prompt_blocks 边界检查 ✗（缺失）
    ↓ 验证"通过"
[DataTransferClient::SetBufferInfo]
    ↓ 使用未验证的 prompt_blocks 索引
[PullCacheByGet]
    ↓ 远程内存访问
[远程缓存越界读取 OOB]
    ↓
┌───────────────────────────────────┐
│ 信息泄露 │ 崩溃 │ 数据损坏     │
└───────────────────────────────────┘
```

### 攻击可行性评估

| 因素 | 评估 |
|------|------|
| 攻击复杂度 | 中 - 需控制远程节点 |
| 前置条件 | 中 - 需集群内节点身份 |
| 攻击成功率 | 高 - 无防护措施 |
| 影响范围 | 中 - 影响缓存数据 |

## 潜在影响分析

### 直接影响

1. **信息泄露**：
   - 越界读取可能获取其他缓存块的数据
   - 可能读取敏感推理数据（如 KV Cache 内容）

2. **内存访问异常**：
   - 访问超出缓存范围的地址可能导致崩溃
   - 可能触发远程节点的内存保护机制

3. **数据完整性问题**：
   - 获取错误数据可能导致推理结果错误

### 间接影响

1. **推理质量下降**：错误缓存数据导致模型推理输出异常
2. **集群信任问题**：节点间信任机制可能失效
3. **横向攻击**：获取的数据可用于进一步攻击

### 影响矩阵

| 影响维度 | 严重程度 | 说明 |
|----------|----------|------|
| 机密性 | Medium | 可能泄露缓存数据 |
| 完整性 | Medium | 可能返回错误数据 |
| 可用性 | Low | 可能导致节点崩溃 |

## 利用难度评估

### 利用难度：中

**理由**：
- 需要控制集群内一个节点（或伪造身份）
- 攻击代码简单，但前置条件较高
- 需要理解 PullCache 协议格式

### 攻击者能力要求

- 需要成为集群内节点（或入侵已有节点）
- 理解 LLM-DataDist 协议
- 能够构造恶意 PullCache 请求

## 修复建议

### 优先级：High (重要修复)

### 修复方案

#### 方案 1：添加 prompt_blocks 边界验证（推荐）

在 `CheckParam` 函数中添加对 `prompt_blocks` 的边界检查：

```cpp
ge::Status DataCacheEngine::CheckParam(const CacheEntry &cache_entry, 
                                        const PullCacheParam &pull_cache_param) {
  // ... 现有检查 ...
  
  if ((cache_entry.placement == CachePlacement::HOST) && 
      (cache_entry.cache_mem_type == CacheMemType::BLOCKS)) {
    // decoder_blocks 边界检查
    for (const auto block_index : pull_cache_param.decoder_blocks) {
      LLM_CHK_BOOL_RET_STATUS(block_index < cache_entry.num_blocks, ...);
    }
    
    // 新增：prompt_blocks 边界检查
    // 需要从远程获取或预先知道远程缓存的块数量
    uint64_t remote_max_blocks = GetRemoteCacheMaxBlocks(cache_key.prompt_cluster_id);
    for (const auto block_index : pull_cache_param.prompt_blocks) {
      LLM_CHK_BOOL_RET_STATUS(block_index < remote_max_blocks,
                             ge::LLM_PARAM_INVALID,
                             "remote block index out of bound, index = %lu, max_blocks = %lu",
                             block_index, remote_max_blocks);
    }
    
    // 大小匹配检查
    LLM_CHK_BOOL_RET_STATUS(pull_cache_param.prompt_blocks.empty() ||
                               (pull_cache_param.decoder_blocks.size() == pull_cache_param.prompt_blocks.size()),
                           ...);
  }
}
```

#### 方案 2：远程块数量协商

在建立连接时协商远程缓存的块数量信息：

```cpp
// 在 LinkLlmClusters 或初始握手时交换缓存元数据
struct CacheMetadata {
  uint64_t max_blocks;
  uint64_t stride;
  // ...
};

// 使用协商的元数据进行验证
```

#### 方案 3：信任边界明确标注

添加安全注释，明确标注跨信任边界的数据需要验证：

```cpp
// 安全注释：prompt_blocks 来自远程集群（不信任侧）
// 必须验证边界后才能使用
SECURITY_CHECK_BOUNDARY(pull_cache_param.prompt_blocks, remote_max_blocks);
```

### 修复验证

修复后应确保：
1. prompt_blocks 所有索引都有边界验证
2. 验证失败有明确的错误处理
3. 添加测试用例验证恶意索引被拒绝
4. 性能影响评估（不应显著影响正常缓存拉取）

## 缓解措施（临时）

在修复实施前，可采取以下临时缓解措施：

1. **集群成员验证**：加强节点加入集群的身份验证
2. **资源监控**：监控异常的缓存访问模式
3. **限制块数量**：设置硬性的最大块数量限制
4. **日志审计**：记录所有 PullCache 请求参数

## 参考信息

- **CWE-129**: https://cwe.mitre.org/data/definitions/129.html
- **CWE-129**: Improper Validation of Array Index

---

**报告生成时间**: 2026-04-21
**分析工具**: details-analyzer Agent