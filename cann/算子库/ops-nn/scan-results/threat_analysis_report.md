# 威胁分析报告 - ops-nn 项目

## 项目概述

| 属性 | 值 |
|-----|-----|
| **项目名称** | ops-nn (华为 CANN 神经网络算子库) |
| **项目类型** | C/C++ + Python 混合项目 |
| **规模** | 6795 个 C/C++ 文件 + 60 个 Python 文件 |
| **主要功能** | AI 神经网络算子实现（卷积、矩阵乘法、激活函数、哈希表、优化器等） |
| **生成时间** | 2026-04-21 |
| **分析模式** | 自主分析（无 threat.md 约束） |

---

## 模块统计

| 模块 | 文件数 | 风险等级 | 优先级 |
|-----|-------|---------|-------|
| hash | 38 | **Critical** | 1 |
| common | 181 | **High** | 2 |
| conv | 414 | **High** | 2 |
| matmul | 852 | **High** | 2 |
| rnn | 68 | **High** | 3 |
| index | 1008 | Medium | 4 |
| quant | 392 | Medium | 4 |
| norm | 962 | Medium | 5 |
| activation | 856 | Medium | 3 |
| optim | 150 | Medium | 4 |
| pooling | 564 | Low | 5 |
| loss | 367 | Low | 5 |
| foreach | 363 | Low | 6 |
| control | 24 | Low | 6 |

---

## 一、攻击面分析

### 1.1 外部输入入口点

| 入口点类型 | 函数模式 | 数据来源 | 风险等级 | 潜在威胁 |
|-----------|---------|---------|---------|---------|
| **API 入口** | `aclnn*_GetWorkspaceSize` | 用户张量形状参数 | 高 | 输入验证、缓冲区溢出、整数溢出 |
| **API 执行** | `aclnn*()` | 用户张量数据指针 | 高 | 内存操作、越界访问 |
| **内核函数** | `*_apt.cpp` | Tiling 参数 | 高 | 直接内存访问、原子操作 |
| **Tiling 函数** | `*_tiling.cpp` | 张量形状推导 | 中 | 整数溢出（块大小计算） |
| **ONNX 插件** | `*_onnx_plugin.cpp` | 外部 ONNX 模型文件 | 中 | 模型属性解析、格式验证 |
| **Python 脚本** | `scripts/*.py` | 配置文件、命令参数 | 中 | 命令执行、文件操作 |

### 1.2 信任边界

| 边界 | 描述 | 跨边界数据 | 安全要求 |
|-----|-----|-----------|---------|
| **用户 API → 内部处理** | 用户提供的张量和参数进入内部处理管道 | 张量形状、数据指针、工作空间大小 | 输入验证、形状检查 |
| **Host CPU → Device NPU** | Tiling 参数和内核数据从主机传输到设备 | Tiling 配置、内核参数 | 参数验证、边界检查 |
| **外部 ONNX 模型 → 内部算子** | ONNX 插件解析来自外部模型文件的属性 | 算子属性、参数值 | 模型格式验证、属性范围检查 |
| **共享内存池 → 张量数据** | 张量数据存储在共享工作空间内存 | 张量数据、中间结果 | 内存隔离、访问控制 |

---

## 二、高风险模块详细分析

### 2.1 Hash 模块 (Critical)

**风险原因**: 嵌入哈希表操作涉及直接内存分配和读写，使用原子操作进行并发控制。

#### 关键文件

| 文件路径 | 行数 | 风险描述 |
|---------|-----|---------|
| `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/kernel_lookup_or_insert_general.h` | 169 | 原子 CAS 操作，直接内存指针操作 `pCurrBucket = pTable + currIdx * bucketSize` |
| `hash/embedding_hash_table_lookup_or_insert/op_kernel/embedding_hash_table_lookup_or_insert.cpp` | 48 | 内核入口点，GM_ADDR 内存参数 |
| `hash/init_embedding_hash_table/op_kernel/init_embedding_hash_table_apt.cpp` | 28 | 哈希表初始化，bucketSize/embeddingDim 参数 |

#### 漏洞类型

| CWE | 漏洞类型 | 具体代码位置 | 触发条件 |
|-----|---------|-------------|---------|
| CWE-119 | 缓冲区溢出 | `pCurrBucket = pTable + currIdx * bucketSize` | bucketSize 计算错误、currIdx 模运算失败 |
| CWE-787 | 越界写入 | `*reinterpret_cast<__gm__ int64_t*>(pCurrBucket) = insertKey` | bucket 指针计算越界 |
| CWE-125 | 越界读取 | `pValues[i * embeddingDim + j] = *pCurrValue` | embeddingDim 参数错误 |
| CWE-190 | 整数溢出 | `currIdx * bucketSize` | 大哈希表容量导致乘法溢出 |
| CWE-362 | 竞争条件 | `AtomicCas` 操作 | 并发插入时的竞争处理 |

#### 高风险调用链

```
aclnnEmbeddingHashTableLookupOrInsert
  → embedding_hash_table_lookup_or_insert (内核)
    → ComputeLookupOrInsert
      → AtomicCas(pCurrBucket + TABLE_FLAG_OFFSET)
      → pCurrBucket = pTable + currIdx * bucketSize
      → *reinterpret_cast<__gm__ int64_t*>(pCurrBucket) = insertKey
```

---

### 2.2 Common 模块 (High)

**风险原因**: 包含 ONNX 插件框架（解析外部模型数据）、动态符号加载、哈希工具函数。

#### ONNX 插件文件

| 文件路径 | 行数 | 功能 |
|---------|-----|-----|
| `common/src/framework/resize_onnx_plugin.cpp` | 390 | 解析 resize 算子属性 |
| `common/src/framework/lstm_onnx_plugin.cpp` | ~120 | 解析 LSTM 配置 |
| `common/src/framework/gru_onnx_plugin.cpp` | ~94 | 解析 GRU 配置 |
| `common/src/framework/matmul_onnx_plugin.cpp` | 64 | 解析 MatMul transA/transB 属性 |
| `common/src/framework/batch_matmul_onnx_plugin.cpp` | ~80 | 解析 BatchMatMul 配置 |

#### 关键风险点

1. **ParseParams 函数**: 从外部 ONNX 模型文件提取算子属性
   - `node->attribute()` 迭代遍历
   - `dynamic_cast<const NodeProto*>(op_src)` 类型转换
   - 无边界检查的属性值提取

2. **动态符号加载** (`tbe_tiling_api.cpp`):
   ```cpp
   static FuncType func = Ops::NN::LegacyCommonMgr::GetInstance().GetFunc<FuncType>(symbolName);
   ```
   - 符号名称来自字符串常量
   - 函数指针动态获取

3. **MurmurHash** (`hash.cpp`):
   ```cpp
   uint32_t MurmurHash(const void* src, uint32_t len, uint32_t seed)
   ```
   - void 指针转换，内存读取操作

---

### 2.3 Conv 模块 (High)

**风险原因**: 卷积算子有复杂的张量形状验证，大文件（5000+ 行）代码复杂度高。

#### 关键文件

| 文件路径 | 行数 | 风险描述 |
|---------|-----|---------|
| `conv/convolution_forward/op_host/op_api/aclnn_convolution.cpp` | 5462 | 形状验证、工作空间计算 |
| `conv/convolution_backward/op_api/aclnn_convolution_backward.cpp` | 3205 | 梯度张量处理 |

#### 漏洞类型

| CWE | 漏洞类型 | 触发条件 |
|-----|---------|---------|
| CWE-190 | 整数溢出 | 工作空间大小 = batch * channels * height * width 计算溢出 |
| CWE-129 | 数组索引验证不当 | 卷积核位置索引计算 |

---

### 2.4 Matmul 模块 (High)

**风险原因**: Tiling 块大小计算中的整数溢出风险，量化参数处理。

#### 关键文件

| 文件路径 | 行数 | 风险描述 |
|---------|-----|---------|
| `matmul/mat_mul_v3/op_host/op_tiling/matmul_v3_base_tiling.cpp` | 2839 | 块大小计算 `blockM = CeilDiv(M, factor)` |
| `matmul/quant_batch_matmul_v3/op_api/aclnn_quant_matmul_v4.cpp` | 2124 | 量化参数验证 |
| `matmul/sparse4to2quant_matmul/op_host/op_tiling/sparse4to2quant_matmul_tiling.cpp` | ~1500 | 稀疏矩阵索引处理 |

#### 漏洞类型

| CWE | 漏洞类型 | 具体位置 |
|-----|---------|---------|
| CWE-190 | 整数溢出 | `CeilDiv(M, factor)` 对于超大矩阵维度 |
| CWE-129 | 索引验证不当 | 稀疏矩阵索引计算 |

---

### 2.5 RNN 模块 (High)

**风险原因**: LSTM/RNN 实现涉及复杂的状态管理和内存操作。

#### 关键文件

| 文件路径 | 行数 | 风险描述 |
|---------|-----|---------|
| `rnn/bidirection_lstm/op_kernel/lstm_bidir_fp16.cpp` | 1579 | 双向 LSTM 状态处理 |
| `rnn/single_layer_lstm_grad/op_host/op_api/aclnn_lstm_backward.cpp` | 1837 | 梯度反向传播 |

---

## 三、潜在漏洞类型汇总

| CWE | 漏洞类型 | 出现位置 | 触发条件 | 检测方法 |
|-----|---------|---------|---------|---------|
| CWE-119 | 缓冲区溢出 | hash 模块、memcpy 操作 | bucketSize/tableSize 计算错误 | 数据流分析、边界检查验证 |
| CWE-787 | 越界写入 | 张量数据写入、哈希表插入 | 索引计算错误、指针偏移错误 | 索引范围分析 |
| CWE-190 | 整数溢出 | Tiling 块大小计算、工作空间大小 | 大张量维度参数 (M/N/K > 2^31) | 整数运算审计 |
| CWE-129 | 数组索引验证不当 | gather/index_put/scatter | 索引范围检查缺失 | 输入验证分析 |
| CWE-125 | 越界读取 | 张量读取操作 | 形状推断错误、索引越界 | 形状验证分析 |
| CWE-362 | 竞争条件 | hash 模块原子操作 | 并发哈希表操作 | 并发安全分析 |
| CWE-20 | 输入验证不当 | ONNX 插件 ParseParams | 模型属性值异常 | 外部输入审计 |
| CWE-78 | OS 命令注入 | Python 脚本 subprocess | 参数未正确过滤 | 命令执行审计 |

---

## 四、数据流分析重点

### 4.1 高风险数据流路径

#### 路径 1: 用户张量 → API → 内核执行

```
[用户输入] 张量形状参数 (batch, channels, height, width, dtype)
    ↓ aclnn*_GetWorkspaceSize
[验证层] 形状参数检查、dtype 验证
    ↓ GetWorkspaceSize
[计算层] 工作空间大小 = 产品(维度) × sizeof(dtype)
    ↓ (整数溢出风险点)
[分配层] 工作空间内存分配
    ↓ aclnn*()
[执行层] Tiling 参数传递 → 内核启动
    ↓ Kernel
[内存层] GM_ADDR 直接内存操作
```

**关键验证点**:
- 形状参数乘法溢出检查
- 工作空间大小上限验证
- dtype 类型有效性检查

#### 路径 2: 哈希表初始化 → 内存分配 → 数据读写

```
[用户输入] tableSize, embeddingDim, bucketLength
    ↓ aclnnInitEmbeddingHashTable
[计算层] bucketSize = embeddingDim * sizeof(float) + overhead
    ↓ (整数溢出风险点)
[分配层] totalSize = bucketSize * tableSize
    ↓ MemoryAlloc
[初始化层] 哈希表桶初始化
    ↓ aclnnEmbeddingHashTableLookupOrInsert
[查找层] MurmurHash3(key) → currIdx = hash % tableSize
    ↓ (模运算风险点)
[访问层] pCurrBucket = pTable + currIdx * bucketSize
    ↓ (指针偏移风险点)
[写入层] AtomicCas → 数据写入
```

**关键验证点**:
- embeddingDim * sizeof(float) 溢出检查
- tableSize 上限验证
- currIdx 模运算结果范围检查
- 哈希碰撞循环终止条件

#### 路径 3: ONNX 模型 → 插件解析 → 算子构建

```
[外部文件] ONNX 模型 (.onnx)
    ↓ ONNX Parser
[解析层] NodeProto 解析
    ↓ ParseParamsFn
[属性层] node->attribute() 遍历
    ↓ (属性验证风险点)
[转换层] op_dest.SetAttr()
    ↓ 图构建
[执行层] 算子调度执行
```

**关键验证点**:
- 属性类型验证
- 属性值范围检查
- 模型格式验证

---

## 五、Python 脚本安全分析

### 5.1 高风险脚本

| 脚本路径 | 行数 | 风险函数 | 潜在威胁 |
|---------|-----|---------|---------|
| `scripts/package/package.py` | 813 | `subprocess.run(['chmod', ...])`, `subprocess.run(['rm', ...])`, `os.symlink()` | 命令执行、文件操作 |
| `scripts/tools/third_lib_download.py` | 50 | `subprocess.run(['git', 'clone', url, ...])` | 外部 URL 处理、git 命令执行 |
| `scripts/torch_extension/setup.py` | 150 | `subprocess.check_call(cmake_config_command)` | cmake 命令执行 |
| `scripts/util/dependency_parser.py` | 200 | `subprocess.run(['cmake', ...])` | cmake 命令执行 |

### 5.2 安全措施分析

**package.py 安全措施**:
- ✅ 使用列表形式传递命令参数（而非 shell=True）
- ✅ 使用 `capture_output=True` 捕获输出
- ✅ 路径通过 `os.path.abspath()` 规范化
- ⚠️ chmod 权限参数来自配置文件
- ⚠️ rm -f 操作删除目标文件

**third_lib_download.py 安全措施**:
- ✅ git 命令使用列表参数
- ⚠️ URL 来自配置或参数

---

## 六、扫描策略建议

### 6.1 大项目分批扫描策略

由于项目规模巨大（6795+ 文件），建议采用以下策略：

| 批次 | 模块 | 扫描深度 | 预计文件数 | 重点关注 |
|-----|-----|---------|----------|---------|
| 1 | hash | 深度扫描 | ~50 | 内存操作、原子操作、指针运算 |
| 2 | common (framework) | 深度扫描 | ~60 | ONNX 插件 ParseParams 函数 |
| 3 | conv | 中等扫描 | ~100 | 大文件（>3000 行）、tiling 计算 |
| 4 | matmul | 中等扫描 | ~100 | tiling 计算、量化参数 |
| 5 | rnn | 中等扫描 | ~50 | 状态管理、内存操作 |
| 6 | index | 快速扫描 | ~50 | 索引验证函数 |
| 7 | quant | 快速扫描 | ~50 | 类型转换 |
| 8 | scripts (Python) | 快速扫描 | ~15 | subprocess 调用 |

### 6.2 污点追踪规则

#### C/C++ 污点源 (Taint Sources)

| 污点源类型 | 函数/参数 | 数据类型 |
|-----------|---------|---------|
| API 输入 | `aclnn*_GetWorkspaceSize` 参数 | 张量形状 (int64_t) |
| API 输入 | 张量数据指针 `GM_ADDR` | 内存地址 |
| Tiling 输入 | tiling_data 结构体字段 | 块大小参数 (int64_t) |
| ONNX 输入 | `node->attribute()` | 算子属性值 |

#### C/C++ 污点汇 (Taint Sinks)

| 污点汇类型 | 函数/操作 | 危险等级 |
|-----------|---------|---------|
| 内存写入 | `memcpy`, `memset`, 指针赋值 | 高 |
| 数组访问 | `array[index]`, `pValues[i * dim + j]` | 高 |
| 内存分配 | `malloc`, 工作空间分配 | 中 |
| 整数运算 | `size = a * b * c` | 中 (溢出风险) |
| 原子操作 | `AtomicCas`, `AtomicAdd` | 高 |

#### Python 污点源

| 污点源类型 | 函数/参数 |
|-----------|---------|
| 配置输入 | XML 配置文件解析 |
| 命令参数 | `argparse` 参数 |

#### Python 污点汇

| 污点汇类型 | 函数 |
|-----------|-----|
| 命令执行 | `subprocess.run`, `subprocess.check_call` |
| 文件操作 | `os.symlink`, `os.chmod` |

---

## 七、安全加固建议

### 7.1 输入验证

1. **张量形状验证**: 所有 API 入口点进行张量形状乘法溢出检查
2. **索引范围验证**: gather/scatter 操作前进行索引边界检查
3. **参数范围验证**: ONNX 插件属性值进行范围验证

### 7.2 内存安全

1. **边界检查**: 内存操作前进行 `offset < buffer_size` 检查
2. **安全的指针运算**: 使用带边界检查的辅助函数替代直接指针运算
3. **工作空间上限**: 设置工作空间大小上限防止资源耗尽

### 7.3 整数溢出防护

1. **安全的乘法**: 使用 `SafeMultiply(a, b)` 替代直接 `a * b`
2. **安全的除法**: 使用 `CeilDivSafe(a, b)` 防止除法溢出
3. **上限检查**: 张量维度参数设置上限（如 2^30）

### 7.4 并发安全

1. **原子操作边界**: AtomicCas 操作前验证目标地址有效性
2. **循环终止**: 哈希碰撞检测循环必须有确定终止条件
3. **锁释放**: 确保原子锁操作后正确释放

---

## 八、附录

### A. 文件统计详情

| 类别 | 文件数 | 比例 |
|-----|-------|-----|
| op_kernel (内核实现) | ~2500 | 36% |
| op_host (主机端处理) | ~2000 | 29% |
| op_api (API 接口) | ~1500 | 22% |
| op_graph (图构建) | ~300 | 4% |
| common (通用代码) | ~180 | 3% |
| scripts (Python 脚本) | ~60 | 1% |
| 其他 | ~700 | 10% |

### B. 高风险文件列表 (Top 20)

| 排名 | 文件路径 | 行数 | 风险等级 |
|-----|---------|-----|---------|
| 1 | `conv/convolution_forward/op_host/op_api/aclnn_convolution.cpp` | 5462 | Critical |
| 2 | `conv/convolution_backward/op_api/aclnn_convolution_backward.cpp` | 3205 | High |
| 3 | `matmul/mat_mul_v3/op_host/op_tiling/matmul_v3_base_tiling.cpp` | 2839 | High |
| 4 | `index/unsorted_segment_sum/op_host/arch35/unsorted_segment_sum_tiling_arch35.cpp` | 2369 | Medium |
| 5 | `matmul/quant_batch_matmul_v3/op_api/aclnn_quant_matmul_v4.cpp` | 2124 | High |
| 6 | `rnn/single_layer_lstm_grad/op_host/op_api/aclnn_lstm_backward.cpp` | 1837 | High |
| 7 | `norm/deep_norm/op_kernel/deep_norm.cpp` | 1799 | Medium |
| 8 | `rnn/bidirection_lstm/op_kernel/lstm_bidir_fp16.cpp` | 1579 | High |
| 9 | `index/index_put_v2/op_api/aclnn_index_put_impl.cpp` | 1406 | Medium |
| 10 | `quant/dequant_swiglu_quant/op_kernel/dequant_swiglu_quant_apt.cpp` | 1411 | Medium |
| 11 | `common/src/framework/resize_onnx_plugin.cpp` | 390 | Medium |
| 12 | `hash/embedding_hash_table_lookup_or_insert/op_kernel/arch35/kernel_lookup_or_insert_general.h` | 169 | Critical |
| 13 | `scripts/package/package.py` | 813 | Medium |
| 14 | `scripts/util/parse_ini_to_json.py` | 344 | Low |

---

**报告结束**

*生成时间: 2026-04-21*
*分析工具: OpenCode 架构分析*