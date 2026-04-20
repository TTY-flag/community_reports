# 漏洞扫描报告 — 待确认漏洞

**项目**: MindSpeed
**扫描时间**: 2025-04-20T01:15:00Z
**报告范围**: 包含 LIKELY / POSSIBLE 状态的漏洞

---

## 1. 扫描摘要

### 1.1 验证状态分布

| 状态 | 数量 | 占比 |
|------|------|------|
| FALSE_POSITIVE | 38 | 46.3% |
| LIKELY | 18 | 22.0% |
| POSSIBLE | 14 | 17.1% |
| CONFIRMED | 12 | 14.6% |
| **总计** | **82** | 100% |

### 1.2 严重性分布

| 严重性 | 数量 | 占比 |
|--------|------|------|
| High | 2 | 6.5% |
| Medium | 18 | 58.1% |
| Low | 11 | 35.5% |
| **有效漏洞总计** | **31** | - |
| 误报 (FALSE_POSITIVE) | 38 | - |

### 1.3 Top 10 关键漏洞

1. **[VULN-SEC-PA-007]** null_pointer_dereference (High) - `mindspeed/ops/csrc/pluggable_allocator/smart_swap/DeviceCachingAllocator.cpp:1085` @ `DeviceCachingAllocator::release_block` | 置信度: 65
2. **[VULN-CROSS-MEM-001]** singleton_race_condition (High) - `mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:268` @ `NPUSwapManager::GetInstance/Init/DeInit` | 置信度: 55
3. **[VULN-SEC-TOOLS-001]** path_traversal (Medium) - `tools/data_handler.py:110` @ `serialize_to_disk` | 置信度: 75
4. **[VULN-SEC-TOOLS-002]** ssrf (Medium) - `tools/data_handler.py:510` @ `build_dataset` | 置信度: 75
5. **[VULN-tools-load_dataset-002]** Untrusted Dataset Loading (Medium) - `tools/data_handler.py:546` @ `build_dataset` | 置信度: 75
6. **[VULN-tools-load_dataset-004]** Path Traversal (Medium) - `tools/data_handler.py:528` @ `build_dataset` | 置信度: 75
7. **[cann_ops-005-3d91e21f]** Integer Overflow (Medium) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/cann/fusion_attention_v2.cpp:405` @ `npu_fusion_attention_v2` | 置信度: 70
8. **[VULN-DF-CPP-INT-001]** integer_overflow (Medium) - `mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:299` @ `ExecutorTensorInfo::convertShapeToInt64` | 置信度: 65
9. **[VULN-DF-CPP-INT-006]** integer_overflow (Medium) - `mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:326` @ `ExecutorTensorInfo::updateCallsStack` | 置信度: 65
10. **[cann_ops-002-898671c5]** Integer Overflow (Medium) - `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/cann/fusion_attention_v2.cpp:74` @ `dropout_gen_mask` | 置信度: 65

---

## 2. 攻击面分析

| 入口点 | 类型 | 信任等级 | 可达性理由 | 说明 |
|--------|------|----------|-----------|------|
| `main@mindspeed/run/run.py` | cmdline | untrusted_local | CLI 入口点，本地用户通过命令行参数控制 patch 文件路径，可指定 --patch 或 --reverse 选项 | 处理 git patch 文件的主入口 |
| `_load_base_checkpoint@mindspeed/checkpointing.py` | file | semi_trusted | 从 load_dir 加载 checkpoint 文件，路径来源于命令行参数 args.load 或 args.save，checkpoint 文件可能来自外部下载 | 加载模型 checkpoint 文件 |
| `_load_base_checkpoint@mindspeed/checkpointing.py` | file | semi_trusted | 加载 EMA checkpoint 文件，路径基于 checkpoint_name + '.ema' | 加载 EMA checkpoint 文件 |
| `load_layerzero_checkpoint@mindspeed/core/distributed/layerzero/state/mga_checkpoint.py` | file | semi_trusted | 从 ckpt_dir 加载 checkpoint 文件，路径来源于函数参数，可能来自外部 | 加载 layerzero checkpoint 文件 |
| `_AutoTokenizer.__init__@mindspeed/tokenizer/tokenizer.py` | file | semi_trusted | 从 tokenizer_name_or_path 加载 HuggingFace tokenizer，路径来源于 args.tokenizer_name_or_path | 加载预训练 tokenizer |
| `restricted_read@mindspeed/auto_settings/utils/file_utils.py` | file | trusted_admin | 读取 pickle 文件，但使用受限 Unpickler，仅允许 mindspeed.auto_settings 模块的类，降低了风险 | 受限的 pickle 文件读取 |
| `main@tools/preprocess_data.py` | cmdline | untrusted_local | 数据预处理 CLI 工具，本地用户通过命令行参数指定输入文件路径 | 数据预处理工具入口 |
| `patch_features@mindspeed/megatron_adaptor.py` | decorator | trusted_admin | 库入口点，导入时自动执行，修改 Megatron-LM 的行为。攻击者难以控制导入过程 | 库的主入口点，导入时自动 patch |
| `patch_from_args@mindspeed/run/run.py` | cmdline | untrusted_local | 执行 git apply 命令处理 patch 文件，patch 文件路径来自扫描目录，命令行参数控制行为 | 执行 git patch 命令 |
| `MindSpeedRunner.run@mindspeed/auto_settings/mindspeed_adaptor/mindspeed_runner.py` | cmdline | semi_trusted | 执行 torchrun 命令启动分布式训练，参数来源于配置 args，路径可能受外部配置影响 | 执行分布式训练命令 |
| `Qos.__init__@mindspeed/core/qos/qos.py` | env | trusted_admin | 从环境变量读取 QOS 配置参数（QOS_SDMA_LOW, QOS_ROCE_LOW 等），环境变量由部署者控制 | 读取环境变量配置 QoS |
| `process_args@mindspeed/arguments.py` | cmdline | untrusted_local | 解析命令行参数，定义训练参数，参数来自本地用户输入 | 命令行参数解析 |

**其他攻击面**:
- Checkpoint 文件加载：torch.load 用于加载 .pt checkpoint 文件
- Tokenizer 加载：AutoTokenizer.from_pretrained 加载外部 tokenizer
- Patch 文件处理：通过 git apply 命令处理 .patch 文件
- 数据集加载：datasets.load_dataset 加载外部数据集
- 命令行参数：CLI 工具接受本地用户输入
- 环境变量：从环境变量读取配置参数
- YAML 配置文件：yaml.safe_load 加载配置文件
- 进程执行：subprocess.Popen 执行 torchrun 命令

---

## 3. High 漏洞 (2)

### [VULN-SEC-PA-007] null_pointer_dereference - DeviceCachingAllocator::release_block

**严重性**: High | **CWE**: CWE-476 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `mindspeed/ops/csrc/pluggable_allocator/smart_swap/DeviceCachingAllocator.cpp:1085-1086` @ `DeviceCachingAllocator::release_block`
**模块**: pluggable_allocator

**描述**: release_block 函数直接访问 block->vmm_segment->fused 而无 null 检查。当 vmm_segment 为 nullptr 时（如 small_block 或未启用 VMM 分割），将触发空指针解引用崩溃。

**漏洞代码** (`mindspeed/ops/csrc/pluggable_allocator/smart_swap/DeviceCachingAllocator.cpp:1085-1086`)

```c
if (block->pool->is_small || !block->vmm_segment->fused) {
    total_allocated_memory -= block->size;
```

**达成路径**

block->vmm_segment [potential null] -> fused access -> crash

**验证说明**: 真实漏洞！release_block(Line1085)无条件访问block->vmm_segment->fused。当pool->is_small=false且vmmDefragment<=0时，vmm_segment为nullptr导致崩溃。用户可通过环境变量控制vmmDefragment。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CROSS-MEM-001] singleton_race_condition - NPUSwapManager::GetInstance/Init/DeInit

**严重性**: High | **CWE**: CWE-362 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: security-auditor

**位置**: `mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:268-1048` @ `NPUSwapManager::GetInstance/Init/DeInit`
**模块**: cross_module
**跨模块**: pluggable_allocator → torch_npu → DeviceCachingAllocator

**描述**: NPUSwapManager 单例跨模块共享竞态条件：NPUSwapManager::GetInstance() 返回全局单例，Init/DeInit 无线程同步（仅 isInit 标志）。tensorPtrCountMap 和 tensorPtrWeakPtrMap 被跨模块访问（DeviceCachingAllocator、NPUSwapManager）。多线程并发调用可能导致内存管理崩溃或数据损坏。

**漏洞代码** (`mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:268-1048`)

```c
static NPUSwapManager &GetInstance() { static NPUSwapManager instance; return instance; }
tensorPtrCountMap[tensor_ptr] = ...
```

**达成路径**

DeviceCachingAllocator::malloc → NPUSwapManager::GetInstance().ProcessMallocEvent → tensorPtrCountMap[ptr] → concurrent access → race condition

**验证说明**: NPUSwapManager单例竞态条件验证通过。Init/DeInit函数仅使用isInit标志检查，无mutex/lock保护。tensorPtrCountMap和tensorPtrWeakPtrMap被DeviceCachingAllocator和NPUSwapManager并发访问。在多线程训练场景下可能触发数据竞争，但这是内部实现问题而非外部攻击面。

**评分明细**: base: 30 | reachability: 5 | controllability: 0 | mitigations: -10 | context: 0 | cross_file: 0

---

## 4. Medium 漏洞 (18)

### [VULN-SEC-TOOLS-001] path_traversal - serialize_to_disk

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `tools/data_handler.py:110-113` @ `serialize_to_disk`
**模块**: tools
**跨模块**: tools → megatron.core.datasets

**描述**: 输出文件路径由命令行参数 output_prefix 直接控制，缺少路径规范化验证。用户可通过构造包含 ../ 的路径写入任意目录，在管理员权限下可能覆盖系统敏感文件。

**漏洞代码** (`tools/data_handler.py:110-113`)

```c
output_bin_files[key] = f"{self.args.output_prefix}_{key}_{level}.bin"
output_idx_files[key] = f"{self.args.output_prefix}_{key}_{level}.idx"
builders[key] = indexed_dataset.IndexedDatasetBuilder(output_bin_files[key])
```

**达成路径**

argv → args.output_prefix (preprocess_data.py:138) → serialize_to_disk (data_handler.py:95) → indexed_dataset.IndexedDatasetBuilder(output_bin_files[key]) [SINK]

**验证说明**: 数据流完整：argv → args.output_prefix → IndexedDatasetBuilder()。无路径规范化验证(os.path.realpath/abspath)。用户可构造../路径写入任意目录。CLI工具场景下，取决于执行权限。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: -10 | cross_file: 0

---

### [VULN-SEC-TOOLS-002] ssrf - build_dataset

**严重性**: Medium | **CWE**: CWE-918 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `tools/data_handler.py:510-513` @ `build_dataset`
**模块**: tools

**描述**: 通过 hf_datasets_params 参数加载外部 JSON 配置，其内容直接传递给 load_dataset 函数。恶意配置可能指定内部网络 URL 或恶意远程数据集，导致 SSRF 或加载不可信数据。CLI 工具场景下风险较低但需警惕配置文件来源。

**漏洞代码** (`tools/data_handler.py:510-513`)

```c
with open(args.hf_datasets_params, 'r') as fin:
    param_dict = json.load(fin)
return load_dataset(**param_dict)
```

**达成路径**

argv → args.hf_datasets_params → json.load (data_handler.py:512) → load_dataset(**param_dict) [SINK]

**验证说明**: 与VULN-tools-load_dataset-001相同代码位置但风险类型不同。JSON文件可注入包含URL或data_dir的参数，触发SSRF。用户可控制部分参数但非完全可控。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-tools-load_dataset-002] Untrusted Dataset Loading - build_dataset

**严重性**: Medium | **CWE**: CWE-918 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `tools/data_handler.py:546-553` @ `build_dataset`
**模块**: tools
**跨模块**: tools/preprocess_data.py,tools/data_handler.py

**描述**: Command-line argument --input is passed directly to load_dataset() without validation of dataset source legitimacy. This allows loading arbitrary remote HuggingFace datasets which may contain malicious data or trigger unexpected network requests.

**漏洞代码** (`tools/data_handler.py:546-553`)

```c
logger.info("loading data from remote huggingface")\nraw_datasets = load_dataset(\n    args.input,\n    split=split_flag,\n    num_proc=None if args.streaming else args.workers,\n    cache_dir=cache_dir,\n    streaming=args.streaming\n)
```

**达成路径**

argv -> argparse.parse_args() -> args.input -> load_dataset(args.input)

**验证说明**: 数据流完整：argv → args.input → load_dataset()。当args.input非本地路径时，作为远程HuggingFace数据集名称加载。SSRF风险：可加载任意远程数据集，但数据集内容由提供者控制。

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-tools-load_dataset-004] Path Traversal - build_dataset

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 75/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `tools/data_handler.py:528-542` @ `build_dataset`
**模块**: tools
**跨模块**: tools/preprocess_data.py,tools/data_handler.py

**描述**: The --input argument accepts arbitrary file paths that are passed to load_dataset() without path traversal validation. While the code checks if the path exists, there is no sanitization against directory traversal sequences or validation that the path is within expected boundaries.

**漏洞代码** (`tools/data_handler.py:528-542`)

```c
data_files = [args.input] if os.path.isfile(args.input) else \\n    glob.glob(os.path.join(args.input, '*'))\next, data_format = _get_data_format(data_files)\nfiltered_data_files = list(filter(lambda x: x.split('.')[-1] == ext, data_files))\nif filtered_data_files:\n    raw_datasets = load_dataset(\n        data_format,\n        split=split_flag,\n        data_files=filtered_data_files,
```

**达成路径**

argv -> argparse.parse_args() -> args.input -> os.path.isfile/glob.glob -> load_dataset()

**验证说明**: 数据流完整：argv → args.input → os.path.isfile/glob.glob → load_dataset()。无路径遍历验证(os.path.realpath/abspath)或边界检查。用户可访问任意路径，但CLI工具场景下需用户主动选择输入路径。

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: 0 | context: -10 | cross_file: 0

---

### [cann_ops-005-3d91e21f] Integer Overflow - npu_fusion_attention_v2

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 70/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/cann/fusion_attention_v2.cpp:405-410` @ `npu_fusion_attention_v2`
**模块**: cann_ops

**描述**: Potential integer overflow in accum accumulation for TND layout. The loop multiplies and accumulates sequence lengths without overflow checks. Large sequence lengths (even within the 1M limit per element) could cause accum to overflow when multiplied by N.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/cann/fusion_attention_v2.cpp:405-410`)

```c
accum += ((ac_seq_qlen_tmp[i] - ac_seq_qlen_tmp[i - 1]) * (ac_seq_kvlen_tmp[i] - ac_seq_kvlen_tmp[i - 1]));
```

**达成路径**

ac_seq_qlen/kvlen (user input) -> accum -> numels -> dropout mask

**验证说明**: Per-element limit (1M) exists but accum sum has no cap. With sufficient batch count (e.g., 10K+ batches of 1M*1M), accum could overflow int64_t (9.2E18). Direct external input via actual_seq_qlen/kvlen parameters.

**评分明细**: base: 30 | reachability: 30 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-DF-CPP-INT-001] integer_overflow - ExecutorTensorInfo::convertShapeToInt64

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:299-315` @ `ExecutorTensorInfo::convertShapeToInt64`
**模块**: pluggable_allocator

**描述**: Integer overflow in shape conversion: res = (res << 16) + s iteratively accumulates tensor dimensions. If tensor has large dimensions (>65535) or many dimensions, the left shift and addition can overflow size_t, causing incorrect hash values and potential memory corruption downstream.

**漏洞代码** (`mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:299-315`)

```c
res = (res << 16) + s;
```

**达成路径**

tensor dimensions -> convertShapeToInt64() -> shape hash -> ExecutorTensorInfo matching -> incorrect swap decisions

**验证说明**: shape hash溢出真实存在，但64位系统触发条件苛刻（需要大维度tensor多次迭代）。tensor shape由模型结构决定，用户可通过batch_size间接影响。建议：添加溢出检查或使用更安全的hash算法。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CPP-INT-006] integer_overflow - ExecutorTensorInfo::updateCallsStack

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:326-332` @ `ExecutorTensorInfo::updateCallsStack`
**模块**: pluggable_allocator

**描述**: Integer overflow in call stack tracking: opCallsStack shifts left by 8 bits per operation. With many operations overflow occurs.

**漏洞代码** (`mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:326-332`)

```c
opCallsStack = (opCallsStack << 8) + opIndex;
```

**达成路径**

updateCallsStack -> tensor matching -> swap decisions

**验证说明**: updateCallsStack中opCallsStack每次左移8位。tensor在复杂模型中可能被多次使用，约8次操作后溢出。溢出导致错误的calls stack hash，影响tensor匹配逻辑（功能性bug，非内存安全）。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cann_ops-002-898671c5] Integer Overflow - dropout_gen_mask

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/cann/fusion_attention_v2.cpp:74-83` @ `dropout_gen_mask`
**模块**: cann_ops

**描述**: Potential integer overflow in numels calculation for dropout mask generation. Multiplication of multiple tensor dimensions (B*N*S*S pattern) without overflow validation. A malicious or extremely large input tensor could cause numels to overflow, leading to insufficient dropout mask allocation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/cann/fusion_attention_v2.cpp:74-83`)

```c
numels = query.size(0) * head_num * query.size(1) * key.size(1);
```

**达成路径**

query/key tensor sizes -> numels -> dropout mask allocation

**验证说明**: Direct external API with tensor size multiplication. Practical overflow unlikely in normal ML use (B*N*S*S typically <1B), but malicious tensor construction could trigger overflow. PyTorch memory limits provide implicit mitigation.

**评分明细**: base: 30 | reachability: 30 | controllability: 10 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-ATB-002] Missing Input Validation - matmul_all_reduce

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/atb/lcal_coc.cpp:39-72` @ `matmul_all_reduce`
**模块**: atb_ops

**描述**: lcal_coc.cpp: Missing rank/rankSize validation. Parameters rank and rankSize are used for distributed communication without bounds checking. Negative rank or rankSize <= 0 could cause undefined behavior in communication operations.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/atb/lcal_coc.cpp:39-72`)

```c
param.rank = rank; param.rankSize = rankSize;
```

**验证说明**: rank/rankSize passed to distributed communication without bounds check. Negative values could cause undefined behavior in HCCL operations.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-ATB-005] Missing Input Validation - matmul_add_fp32

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/atb/matmul_add.cpp:39-65` @ `matmul_add_fp32`
**模块**: atb_ops

**描述**: matmul_add.cpp: No input validation in matmul_add_fp32. Function accepts x, weight, and C tensors without any validation of dimensions, shapes, dtypes, or device placement. Matmul shape compatibility is not verified before operation.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/atb/matmul_add.cpp:39-65`)

```c
void matmul_add_fp32(const at::Tensor &x, const at::Tensor &weight, at::Tensor & C)
```

**验证说明**: matmul_add_fp32 has no validation for dimensions, shapes, dtypes, or device placement. Shape incompatibility could cause crashes or data corruption.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-ATB-006] Missing Input Validation - groupmatmul_add_fp32

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/atb/groupmatmul_add.cpp:39-64` @ `groupmatmul_add_fp32`
**模块**: atb_ops

**描述**: groupmatmul_add.cpp: No input validation in groupmatmul_add_fp32. Function accepts x, weight, group_list, and grad tensors without any validation of dimensions, shapes, dtypes, device placement, or group_list contents. Critical for grouped operations where shape compatibility is essential.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/atb/groupmatmul_add.cpp:39-64`)

```c
void groupmatmul_add_fp32(const at::Tensor &x, const at::Tensor &weight, const at::Tensor &group_list, at::Tensor & grad)
```

**验证说明**: groupmatmul_add_fp32 lacks validation for dimensions, shapes, dtypes, device, and group_list contents. Critical for grouped matmul correctness.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-SEC-PA-001] integer_overflow - ExecutorTensorInfo::convertShapeToInt64

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-190 | **置信度**: 65/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:303-306` @ `ExecutorTensorInfo::convertShapeToInt64`
**模块**: pluggable_allocator

**描述**: convertShapeToInt64 函数在将 tensor shape 转换为 int64 时，执行左移和加法操作 (res = (res << 16) + s) 缺乏溢出检查。当 tensor 维度较大时（如 >65535），连续左移16位会导致整数溢出，可能产生错误的 shape hash 值，影响后续内存匹配逻辑。

**漏洞代码** (`mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:303-306`)

```c
size_t res = 0;
for (auto s : tensor.sizes()) {
    res = (res << 16) + s;
}
```

**达成路径**

tensor.sizes() [SOURCE] -> convertShapeToInt64() -> res (potential overflow) -> shape field

**验证说明**: 与VULN-DF-CPP-INT-001相同位置相同漏洞。convertShapeToInt64的左移加法操作无溢出检查，64位系统触发需要极端条件。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-DF-CPP-INT-005] integer_overflow - DeviceCachingAllocator::get_fused_fragmented_blocks

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `mindspeed/ops/csrc/pluggable_allocator/smart_swap/DeviceCachingAllocator.cpp:1356-1357` @ `DeviceCachingAllocator::get_fused_fragmented_blocks`
**模块**: pluggable_allocator

**描述**: Potential underflow in fuse size calculation: remain_size = (fuse_size - p.search_key.size). No bounds validation.

**漏洞代码** (`mindspeed/ops/csrc/pluggable_allocator/smart_swap/DeviceCachingAllocator.cpp:1356-1357`)

```c
size_t remain_size = (fuse_size - p.search_key.size); size_t keep_size = original_size - remain_size;
```

**达成路径**

block fusion -> split_large_block -> memory corruption

**验证说明**: get_fused_fragmented_blocks中remain_size和keep_size计算潜在underflow。当fuse_size远大于p.search_key.size时，remain_size可能超过last_block->size，导致keep_size为负值(wrap)。split_large_block接收错误size可能破坏内存。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-ATB-007] Missing Tensor Dtype Validation - matmul_all_reduce

**严重性**: Medium | **CWE**: CWE-20 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/atb/lcal_coc.cpp:39-266` @ `matmul_all_reduce`
**模块**: atb_ops

**描述**: lcal_coc.cpp: All LCOC functions (matmul_all_reduce, all_gather_matmul, etc.) lack dtype validation for input tensors. Unlike swiglu.cpp and rms_norm.cpp which check for Half/BFloat16/Float, these functions accept any dtype which could cause precision loss or runtime errors.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/atb/lcal_coc.cpp:39-266`)

```c
void matmul_all_reduce(const at::Tensor &input1, const at::Tensor &input2, ...)
```

**验证说明**: LCOC functions lack dtype validation unlike swiglu/rms_norm which check Half/BFloat16/Float. Accepting any dtype could cause precision loss or runtime errors.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [TOKENIZER-PATH-TRAVERSAL-001] Path Traversal - _AutoTokenizer.__init__

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-22 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: python-dataflow-module-scanner, python-security-module-scanner

**位置**: `mindspeed/tokenizer/tokenizer.py:77` @ `_AutoTokenizer.__init__`
**模块**: tokenizer
**跨模块**: tokenizer → features_manager

**描述**: Arbitrary tokenizer path loading via AutoTokenizer.from_pretrained without path validation. User-controlled tokenizer_name_or_path parameter flows directly to AutoTokenizer.from_pretrained without sanitization, allowing loading of arbitrary tokenizer files from any filesystem location. This could lead to arbitrary code execution through pickle deserialization in malicious tokenizer files.

**漏洞代码** (`mindspeed/tokenizer/tokenizer.py:77`)

```c
self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_name_or_path, **hf_tokenizer_kwargs)
```

**达成路径**

[{"source":"args.tokenizer_name_or_path","source_type":"external_input","source_location":"CLI/YAML config parameter --tokenizer-name-or-path","sink":"AutoTokenizer.from_pretrained","sink_location":"mindspeed/tokenizer/tokenizer.py:77","taint_path":["build_tokenizer_wrapper() -> _AutoTokenizer.__init__() -> AutoTokenizer.from_pretrained()"],"validation":"NONE in tokenizer.py (validation exists in features_manager/tokenizer/build_tokenizer.py and build_tokenizer/adaptor.py but requires feature registration)"}]

**验证说明**: LIKELY Path Traversal vulnerability (CWE-22, not deserialization). AutoTokenizer.from_pretrained() with user-controlled tokenizer_name_or_path allows loading tokenizer from arbitrary local paths. Strong mitigations present: trust_remote_code=False (line 75) prevents remote code execution from tokenizer config, local_files_only=True (line 76) prevents remote URL loading. Risk reduced to unintended tokenizer loading, not arbitrary code execution.

**评分明细**: base: 30 | reachability: 30 | controllability: 25 | mitigations: -25 | context: 0 | cross_file: 0

---

### [VULN-SEC-PA-004] memory_leak - SwapExecutor::initStanderdSwapOutVec

**严重性**: Medium | **CWE**: CWE-401 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: security-module-scanner

**位置**: `mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:591-612` @ `SwapExecutor::initStanderdSwapOutVec`
**模块**: pluggable_allocator

**描述**: initStanderdSwapOutVec 函数使用裸指针 new ExecutorTensorInfo 分配内存并存入 standerdSwapOutVec。若后续操作抛出异常或流程中断，clearStanderdSwapOutVec() 可能未被调用，导致内存泄漏。建议使用 unique_ptr 或 RAII 管理。

**漏洞代码** (`mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:591-612`)

```c
ExecutorTensorInfo *eti = new ExecutorTensorInfo(policyInfo.swapOutStage, policyInfo.swapInStage);
// ... loop processing ...
standerdSwapOutVec.push_back(eti);
```

**达成路径**

new ExecutorTensorInfo -> standerdSwapOutVec.push_back -> potential leak on exception

**验证说明**: initStanderdSwapOutVec使用裸指针new ExecutorTensorInfo存入vector。若循环中抛异常，部分分配的内存无法被clearStanderdSwapOutVec清理导致泄漏。正常流程有清理函数，但异常路径未覆盖。建议使用unique_ptr或RAII。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: 0 | context: 0 | cross_file: 0

---

### [VULN-CROSS-TOKENIZER-VALIDATION-001] inconsistent_validation - _AutoTokenizer.__init__ + validate_args

**严重性**: Medium | **CWE**: CWE-697 | **置信度**: 60/100 | **状态**: LIKELY | **来源**: dataflow-scanner

**位置**: `mindspeed/tokenizer/tokenizer.py + mindspeed/features_manager/tokenizer/build_tokenizer.py:77-31` @ `_AutoTokenizer.__init__ + validate_args`
**模块**: cross_module
**跨模块**: tokenizer → features_manager

**描述**: tokenizer 模块路径验证不一致: tokenizer.py 的 _AutoTokenizer.__init__ 直接调用 AutoTokenizer.from_pretrained 无路径验证，但 features_manager/tokenizer/build_tokenizer.py 和 build_tokenizer/adaptor.py 包含完整的路径验证逻辑。验证仅在 feature 注册后生效，直接调用路径存在漏洞。

**漏洞代码** (`mindspeed/tokenizer/tokenizer.py + mindspeed/features_manager/tokenizer/build_tokenizer.py:77-31`)

```c
AutoTokenizer.from_pretrained(tokenizer_name_or_path) [无验证]
vs os.path.exists() + os.path.realpath() [有验证]
```

**达成路径**

[tokenizer] args.tokenizer_name_or_path → _AutoTokenizer → AutoTokenizer.from_pretrained [无验证]
[features_manager] validate_args → path validation → safe call

**验证说明**: tokenizer路径验证不一致验证通过。tokenizer.py的_AutoTokenizer直接调用AutoTokenizer.from_pretrained无验证，而features_manager路径有完整验证(os.path.exists+realpath)。验证仅在feature注册后生效，直接导入tokenizer模块可绕过验证。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -5 | context: 0 | cross_file: 0

---

### [VULN-SEC-PA-006] use_after_free - DeviceCachingAllocator::try_merge_blocks

**严重性**: Medium（原评估: High → 验证后: Medium） | **CWE**: CWE-416 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `mindspeed/ops/csrc/pluggable_allocator/smart_swap/DeviceCachingAllocator.cpp:622-644` @ `DeviceCachingAllocator::try_merge_blocks`
**模块**: pluggable_allocator

**描述**: try_merge_blocks 函数在合并 Block 后 delete src (Line 643)。但 src 可能仍被 vmm_segment->phy_chunks 的 mapped_blocks 引用。后续 activate_large_block/deactivate_large_block 访问这些引用时，可能导致 Use After Free。

**漏洞代码** (`mindspeed/ops/csrc/pluggable_allocator/smart_swap/DeviceCachingAllocator.cpp:622-644`)

```c
dst->size += subsumed_size;
auto erased = pool.blocks.erase(src);
// ...
delete src;
```

**达成路径**

src block -> mapped_blocks reference -> delete src -> mapped_blocks still holds invalid pointer -> UAF

**验证说明**: try_merge_blocks中delete src潜在UAF风险。代码有mapped_blocks.size()>1前置检查阻止合并，但需验证remerge实现是否正确清理引用。用户通过内存压力可间接触发合并逻辑。

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

## 5. Low 漏洞 (11)

### [VULN-CMD-001] command_injection - MindSpeedRunner.run

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindspeed/auto_settings/mindspeed_adaptor/mindspeed_runner.py:29-53` @ `MindSpeedRunner.run`
**模块**: auto_settings

**描述**: Parameter injection risk in torchrun command execution. While subprocess.Popen uses list form (preventing shell injection), modified_argv is derived from sys.argv.copy() without validation. Attacker with control over command-line arguments could inject malicious parameters like --profile-save-path to write to arbitrary locations.

**漏洞代码** (`mindspeed/auto_settings/mindspeed_adaptor/mindspeed_runner.py:29-53`)

```c
subprocess.Popen(cmd, preexec_fn=os.setpgrp, env=modified_env) where cmd = ["torchrun", ...] + modified_argv
```

**达成路径**

Source: args@__init__:13 (semi_trusted cmdline) -> set_system_config@system_config.py:98 -> MindSpeedRunner(args) -> run(modified_argv) -> subprocess.Popen

**验证说明**: Parameter injection to torchrun via modified_argv. List-based subprocess prevents shell injection (-15). semi_trusted cmdline origin limits attack scope. Attacker could inject torchrun parameters like --log-dir but cannot execute arbitrary commands.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-CMD-002] command_injection - Runner.run

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-78 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindspeed/auto_settings/profile/runner.py:28-52` @ `Runner.run`
**模块**: auto_settings

**描述**: Second instance of parameter injection in Runner class. Same vulnerability pattern as mindspeed_runner.py. Command parameters derived from system_config which originates from command-line arguments without strict validation.

**漏洞代码** (`mindspeed/auto_settings/profile/runner.py:28-52`)

```c
subprocess.Popen(cmd, preexec_fn=os.setpgrp, env=modified_env) where cmd = ["torchrun", ...] + modified_argv
```

**达成路径**

Source: system_config (from cmdline args) -> Runner.__init__ -> run(modified_argv) -> subprocess.Popen

**验证说明**: Same pattern as VULN-CMD-001 in Runner class. Parameter injection to torchrun with list-based subprocess mitigating shell injection.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-DF-CPP-INPUT-001] missing_input_validation - SwapExecutor::SwapOut

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:389-390` @ `SwapExecutor::SwapOut`
**模块**: pluggable_allocator

**描述**: Tensor size used directly for memory allocation without validation: size_t size = storageImplPtr->nbytes(). No upper bound check.

**漏洞代码** (`mindspeed/ops/csrc/pluggable_allocator/smart_swap/NPUSwapManager.cpp:389-390`)

```c
size_t size = storageImplPtr->nbytes(); at::DataPtr dataPtrCpu = allocatorCPU->allocate(size);
```

**达成路径**

tensor storage -> SwapOut -> allocatorCPU->allocate(size)

**验证说明**: tensor size直接用于allocate无上限检查。但allocatorCPU->allocate会检查可用内存并抛OOM异常拒绝过大请求。用户可通过batch_size间接影响，但allocate层有防护。更多是资源管理问题而非安全漏洞。

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -10 | context: 0 | cross_file: 0

---

### [VULN-ATB-004] Missing Tensor Shape Validation - InferShapeRmsNorm

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 55/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/atb/rms_norm.cpp:41-54` @ `InferShapeRmsNorm`
**模块**: atb_ops

**描述**: rms_norm.cpp: Missing gamma tensor dimension validation against input tensor. InferShapeRmsNorm computes rstd_dim without validating gamma dimensions are compatible with x. No check that gamma dimensions match trailing dimensions of x tensor.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/atb/rms_norm.cpp:41-54`)

```c
int64_t rstd_dim = self.dim(); rstd_dim -= gamma.dim();
```

**验证说明**: Missing gamma size validation against self trailing dimensions. TORCH_CHECK only validates dimension count, not size values. Primarily correctness issue.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cann_ops-004-073ea7a2] Missing Input Validation - _check_dims

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/cann/gmm.cpp:39-46` @ `_check_dims`
**模块**: cann_ops

**描述**: Incomplete dimension validation in _check_dims function. Variables dim_num_w and dim_0_w are declared but never used for validation. The function only checks num_x > 0 && num_w > 0 but does not validate weight tensor dimensions, potentially leading to out-of-bounds access or incorrect operations.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/cann/gmm.cpp:39-46`)

```c
size_t dim_num_w = weight[0].sizes().size(); size_t dim_0_w = weight[0].sizes()[0];
```

**达成路径**

weight tensor dimensions -> unused validation -> ACLNN operation

**验证说明**: Incomplete validation: dim_num_w/dim_0_w declared but unused. Forward npu_gmm could receive 1D weight tensor causing weight[0].sizes()[dim_num_w-1] potential issues. ML framework typically validates upstream.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: -15 | cross_file: 0

---

### [VULN-ATB-001] Missing Tensor Dimension Validation - matmul_all_reduce

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/atb/lcal_coc.cpp:39-72` @ `matmul_all_reduce`
**模块**: atb_ops

**描述**: lcal_coc.cpp: Missing tensor dimension validation before matmul operations. Functions (matmul_all_reduce, all_gather_matmul, etc.) access input1.size(1) and input2.size(0) without verifying tensors have at least 2 dimensions. This can cause out-of-bounds access or undefined behavior.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/atb/lcal_coc.cpp:39-72`)

```c
bool transB = input1.size(1) != input2.size(0);
```

**验证说明**: Missing dimension validation exists, but PyTorch size() throws exception for invalid dim access - mitigates exploitation.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -10 | context: 0 | cross_file: 0

---

### [core-runner-subprocess-torchrun-44] command_execution - MindSpeedRunner.run

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-78 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindspeed/auto_settings/mindspeed_adaptor/mindspeed_runner.py:44-48` @ `MindSpeedRunner.run`
**模块**: core
**跨模块**: core,auto_settings

**描述**: subprocess.Popen executes torchrun command constructed from args parameters. While individual parameters are type-validated (nnodes as str, nproc_per_node as str, node_rank as int, master_addr as str, master_port as int), the modified_argv list is passed directly without validation. A malicious argv entry could inject additional torchrun options or arguments. The use of preexec_fn=os.setpgrp creates a process group but does not prevent command injection.

**漏洞代码** (`mindspeed/auto_settings/mindspeed_adaptor/mindspeed_runner.py:44-48`)

```c
process = subprocess.Popen(\n    cmd,\n    preexec_fn=os.setpgrp,\n    env=modified_env\n)
```

**达成路径**

args -> nnodes, nproc_per_node, node_rank, master_addr, master_port (line 14-18) -> cmd (line 34-41) + modified_argv -> subprocess.Popen (line 44)

**验证说明**: Parameter injection risk (not shell injection). List-based subprocess.Popen prevents shell injection but modified_argv from sys.argv could inject torchrun parameters like --log-dir. Limited attack surface due to torchrun's constrained options.

**评分明细**: base: 30 | reachability: 20 | controllability: 15 | mitigations: -15 | context: 0 | cross_file: 0

---

### [VULN-SEC-PA-005] memory_leak - DeviceCachingAllocator::malloc

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-401 | **置信度**: 50/100 | **状态**: POSSIBLE | **来源**: security-module-scanner

**位置**: `mindspeed/ops/csrc/pluggable_allocator/smart_swap/DeviceCachingAllocator.cpp:214-225` @ `DeviceCachingAllocator::malloc`
**模块**: pluggable_allocator

**描述**: malloc 函数中 new Block 创建后，若 pool.blocks.insert 失败或后续 split 操作异常，Block 内存可能泄漏。当前代码依赖 TORCH_INTERNAL_ASSERT 检查，但在异常路径下仍存在泄漏风险。

**漏洞代码** (`mindspeed/ops/csrc/pluggable_allocator/smart_swap/DeviceCachingAllocator.cpp:214-225`)

```c
Block *block = new Block(device, stream, size, &pool, block->ptr);
// ... setup ...
bool inserted = pool.blocks.insert(remaining).second;
```

**达成路径**

new Block -> pool.blocks.insert failure -> potential leak

**验证说明**: malloc中new Block后pool.blocks.insert(remaining)失败可能导致remaining泄漏。但insert失败概率极低（仅重复key时失败），且remaining是原始block而非新分配。实际风险较低。

**评分明细**: base: 30 | reachability: 20 | controllability: 0 | mitigations: 0 | context: 0 | cross_file: 0

---

### [cann_ops-006-d5e421e7] Integer Overflow - check_npu_mm_all_reduce_add_rms_norm_params

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-190 | **置信度**: 45/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/cann/inc/mc2_utils.h:38-43` @ `check_npu_mm_all_reduce_add_rms_norm_params`
**模块**: cann_ops

**描述**: Potential integer overflow in x1_bs calculation for mm_all_reduce_add_rms_norm. Multiplication x1.size(0) * x1.size(1) without overflow validation. Large batch and sequence sizes could overflow the comparison with residual dimensions.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/cann/inc/mc2_utils.h:38-43`)

```c
x1_bs *= x1.size(1);
```

**达成路径**

x1 tensor sizes -> x1_bs -> dimension comparison

**验证说明**: size_t multiplication of batch*sequence. Overflow theoretically possible with extreme tensor sizes (>9.2E18), but typical ML tensors (1M-10M elements) are safe. Internal validation function called from external API.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: -15 | cross_file: 0

---

### [VULN-PICKLE-001] insecure_deserialization - restricted_read

**严重性**: Low（原评估: Medium → 验证后: Low） | **CWE**: CWE-502 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `mindspeed/auto_settings/utils/file_utils.py:12-39` @ `restricted_read`
**模块**: auto_settings

**描述**: RestrictedUnpickler has incomplete security restrictions. While it limits module to mindspeed.auto_settings prefix, the find_class method uses getattr(module, global_name) which can access any module attribute, not just classes. The isinstance(class_, type) check happens AFTER import and getattr, potentially allowing exploitation if a malicious class exists in the allowed package.

**漏洞代码** (`mindspeed/auto_settings/utils/file_utils.py:12-39`)

```c
class _RestrictedUnpickler(pickle.Unpickler):\n    def find_class(self, module_name: str, global_name: str):\n        if module_name.startswith("mindspeed.auto_settings"):\n            module = import_module(module_name)\n            class_ = getattr(module, global_name)\n            if isinstance(class_, type):\n                return class_
```

**达成路径**

Source: file_path@restricted_read:28 (trusted_admin) -> check_file_size -> _RestrictedUnpickler.load

**验证说明**: RestrictedUnpickler provides significant protection: module whitelist (mindspeed.auto_settings.*) and isinstance type check. Attack requires: (1) controlling work_dir via cmdline, (2) placing malicious pickle file, (3) having matching malicious class in allowed package. Complex attack chain with limited exploitability.

**评分明细**: base: 30 | reachability: 20 | controllability: 10 | mitigations: -20 | context: 0 | cross_file: 0

---

### [cann_ops-007-a5a54846] Missing Input Validation - npu_mm_all_reduce_add_rms_norm

**严重性**: Low | **CWE**: CWE-20 | **置信度**: 40/100 | **状态**: POSSIBLE | **来源**: unknown

**位置**: `/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/cann/npu_mm_all_reduce_add_rms_norm.cpp:41-50` @ `npu_mm_all_reduce_add_rms_norm`
**模块**: cann_ops

**描述**: Missing validation for epsilon parameter in npu_mm_all_reduce_add_rms_norm. Epsilon should be positive non-zero value for RMS normalization, but no validation is performed. Negative or zero epsilon could cause division by zero or incorrect normalization.

**漏洞代码** (`/home/pwn20tty/Desktop/opencode_project/shenteng/MindSpeed/MindSpeed/mindspeed/ops/csrc/cann/npu_mm_all_reduce_add_rms_norm.cpp:41-50`)

```c
double epsilon,
```

**达成路径**

epsilon (user input) -> ACLNN RMS normalization operation

**验证说明**: epsilon missing validation for RMS norm. Zero/negative epsilon causes numerical anomalies (NaN in sqrt), but this is a SEMANTIC CORRECTNESS issue not a security vulnerability. Model code typically sets epsilon.

**评分明细**: base: 30 | reachability: 20 | controllability: 5 | mitigations: 0 | context: -15 | cross_file: 0

---

## 6. 模块漏洞分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| atb_ops | 0 | 0 | 4 | 2 | 6 |
| auto_settings | 0 | 0 | 0 | 3 | 3 |
| cann_ops | 0 | 0 | 2 | 3 | 5 |
| core | 0 | 0 | 0 | 1 | 1 |
| cross_module | 0 | 1 | 1 | 0 | 2 |
| pluggable_allocator | 0 | 1 | 6 | 2 | 9 |
| tokenizer | 0 | 0 | 1 | 0 | 1 |
| tools | 0 | 0 | 4 | 0 | 4 |
| **合计** | **0** | **2** | **18** | **11** | **31** |

## 7. CWE 分布

| CWE | 数量 | 占比 |
|-----|------|------|
| CWE-20 | 9 | 29.0% |
| CWE-190 | 7 | 22.6% |
| CWE-78 | 3 | 9.7% |
| CWE-22 | 3 | 9.7% |
| CWE-918 | 2 | 6.5% |
| CWE-401 | 2 | 6.5% |
| CWE-697 | 1 | 3.2% |
| CWE-502 | 1 | 3.2% |
| CWE-476 | 1 | 3.2% |
| CWE-416 | 1 | 3.2% |
| CWE-362 | 1 | 3.2% |
